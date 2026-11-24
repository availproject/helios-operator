use alloy_sol_types::SolValue;
use anyhow::Result;
use clap::Parser;
use helios_consensus_core::types::LightClientHeader;
use helios_ethereum::rpc::ConsensusRpc;
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_helios_script::{
    exit_code, fetch_execution_block_header, get_checkpoint, get_client, get_updates,
    install_panic_hook,
};
use sp1_sdk::{utils::setup_logger, Prover, ProverClient, SP1Stdin};
use std::process::ExitCode;
use std::time::Duration;

const SLOTS_PER_EPOCH: u64 = 32;

/// How many epochs behind the finalized epoch the test starts when `--slot` is not given. The gap
/// leaves a newer head to prove, also when the finality update of the node is an epoch or two
/// behind its finalized header.
const START_LAG_EPOCHS: u64 = 8;

/// How many older epochs are tried when the first slot of an epoch has no block.
const MAX_SKIPPED_EPOCHS: u64 = 8;

/// Timeout for one beacon header request.
const HEADER_TIMEOUT: Duration = Duration::from_secs(2 * 60);

#[derive(Parser, Debug, Clone)]
#[command(about = "Execute the SP1 Helios program on live data from a checkpoint slot. No proof.")]
pub struct TestArgs {
    /// Checkpoint slot to start from. Default: a recent finalized checkpoint.
    #[arg(long)]
    pub slot: Option<u64>,
}

const ELF: &[u8] = include_bytes!("../../elf/sp1-helios-elf");

#[tokio::main]
async fn main() -> ExitCode {
    install_panic_hook();
    // The error goes through `exit_code`, because Rust prints an error returned from `main`
    // without redaction.
    exit_code(run().await)
}

#[allow(unused)]
async fn run() -> Result<()> {
    dotenv::dotenv().ok();
    setup_logger();
    // Without `--slot` the test starts from a recent finalized checkpoint. A fixed slot stops
    // working, because a beacon node serves a light-client bootstrap only for some days.
    let slot = match TestArgs::parse().slot {
        Some(slot) => slot,
        None => {
            let consensus_rpc = std::env::var("SOURCE_CONSENSUS_RPC_URL").unwrap();
            recent_checkpoint_slot(&consensus_rpc).await
        }
    };
    println!("Start slot: {slot}");
    let checkpoint = get_checkpoint(slot).await;

    // Setup client.
    let helios_client = get_client(checkpoint).await;
    let sync_committee_updates = get_updates(&helios_client).await;
    let finality_update = helios_client.rpc.get_finality_update().await.unwrap();

    // From Gloas the finalized header only commits to the execution block hash; the program needs
    // the block header itself (same as the operator).
    let execution_block_header = match finality_update.finalized_header() {
        LightClientHeader::Gloas(header) => {
            let execution_rpc = std::env::var("SOURCE_EXECUTION_RPC_URL")
                .expect("SOURCE_EXECUTION_RPC_URL is required for a Gloas finalized header");
            Some(fetch_execution_block_header(&execution_rpc, header.execution_block_hash).await?)
        }
        _ => None,
    };

    let expected_current_slot = helios_client.expected_current_slot();
    let inputs = ProofInputs {
        sync_committee_updates,
        finality_update,
        expected_current_slot,
        store: helios_client.store.clone(),
        genesis_root: helios_client.config.chain.genesis_root,
        forks: helios_client.config.forks.clone(),
        execution_block_header,
    };

    // Write the inputs to the VM
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&serde_cbor::to_vec(&inputs)?);

    let prover_client = ProverClient::builder().cpu().build().await;
    let (public_values, report) = prover_client.execute(ELF.into(), stdin).await?;
    println!("Execution Report: {report:?}");

    let outputs = ProofOutputs::abi_decode(public_values.as_slice())?;
    println!(
        "ProofOutputs: prevHead {} -> newHead {}, executionStateRoot {}, newHeader {}",
        outputs.prevHead, outputs.newHead, outputs.executionStateRoot, outputs.newHeader
    );

    Ok(())
}

/// Returns the slot of a recent finalized checkpoint: the first slot of the epoch that lies
/// `START_LAG_EPOCHS` epochs behind the finalized epoch.
///
/// A beacon node serves the light-client bootstrap of a checkpoint only for some days, so a fixed
/// slot stops working. A missed slot has no block and no bootstrap, so when the first slot of an
/// epoch was missed, the epoch before it is taken.
async fn recent_checkpoint_slot(consensus_rpc: &str) -> u64 {
    let finalized_slot = beacon_header_slot(consensus_rpc, "finalized")
        .await
        .expect("The beacon node has no finalized header");

    let finalized_epoch_start = finalized_slot - finalized_slot % SLOTS_PER_EPOCH;
    let newest_slot = finalized_epoch_start.saturating_sub(START_LAG_EPOCHS * SLOTS_PER_EPOCH);
    for skipped_epochs in 0..=MAX_SKIPPED_EPOCHS {
        let slot = newest_slot.saturating_sub(skipped_epochs * SLOTS_PER_EPOCH);
        if beacon_header_slot(consensus_rpc, &slot.to_string())
            .await
            .is_some()
        {
            return slot;
        }
    }

    panic!(
        "No block in the first slot of the {} epochs that end at slot {newest_slot}",
        MAX_SKIPPED_EPOCHS + 1
    );
}

/// Returns the slot of the beacon header `block_id` (a slot number or `finalized`), or `None` when
/// the node has no block there.
async fn beacon_header_slot(consensus_rpc: &str, block_id: &str) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct HeaderResponse {
        data: HeaderData,
    }
    #[derive(serde::Deserialize)]
    struct HeaderData {
        header: SignedHeader,
    }
    #[derive(serde::Deserialize)]
    struct SignedHeader {
        message: HeaderMessage,
    }
    #[derive(serde::Deserialize)]
    struct HeaderMessage {
        // The beacon API sends numbers as strings.
        slot: String,
    }

    let url = format!(
        "{}/eth/v1/beacon/headers/{}",
        consensus_rpc.trim_end_matches('/'),
        block_id
    );
    let response = reqwest::Client::builder()
        .timeout(HEADER_TIMEOUT)
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        // The reqwest error text ends with the request URL, which holds the API key.
        .unwrap_or_else(|e| panic!("Cannot get beacon header {block_id}: {}", e.without_url()));
    let status = response.status();
    let body = response.text().await.unwrap();
    if status == reqwest::StatusCode::NOT_FOUND {
        return None;
    }
    if !status.is_success() {
        panic!("Cannot get beacon header {block_id}: HTTP {status}: {body}");
    }
    let header: HeaderResponse = serde_json::from_str(&body).unwrap();

    Some(header.data.header.message.slot.parse().unwrap())
}

#[cfg(test)]
mod tests {
    use super::recent_checkpoint_slot;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Starts a stand-in for a beacon node and returns its URL.
    ///
    /// It serves the header of `finalized_slot` for `finalized`, and a header for every slot in
    /// `slots_with_block`. Every other slot answers 404, like a missed slot does.
    fn serve_headers(finalized_slot: u64, slots_with_block: &'static [u64]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = [0u8; 1024];
                let read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..read]);

                // The request line is "GET /eth/v1/beacon/headers/{block_id} HTTP/1.1".
                let block_id = request
                    .split_whitespace()
                    .nth(1)
                    .and_then(|path| path.rsplit('/').next())
                    .unwrap_or_default();
                let slot = if block_id == "finalized" {
                    Some(finalized_slot)
                } else {
                    block_id
                        .parse()
                        .ok()
                        .filter(|slot| slots_with_block.contains(slot))
                };
                let (status, body) = match slot {
                    Some(slot) => (
                        "200 OK",
                        format!(r#"{{"data":{{"header":{{"message":{{"slot":"{slot}"}}}}}}}}"#),
                    ),
                    None => (
                        "404 Not Found",
                        r#"{"code":404,"message":"Block not found"}"#.to_string(),
                    ),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });

        url
    }

    #[tokio::test]
    async fn starts_eight_epochs_behind_the_finalized_checkpoint() {
        let consensus_rpc = serve_headers(32_000, &[31_744]);

        assert_eq!(recent_checkpoint_slot(&consensus_rpc).await, 31_744);
    }

    #[tokio::test]
    async fn counts_the_epochs_from_the_start_of_the_finalized_epoch() {
        // The first slot of epoch 1000 was missed, so the finalized block is the last block of
        // epoch 999. Epoch 999 starts at slot 31968.
        let consensus_rpc = serve_headers(31_999, &[31_712]);

        assert_eq!(recent_checkpoint_slot(&consensus_rpc).await, 31_712);
    }

    #[tokio::test]
    async fn skips_an_epoch_whose_first_slot_has_no_block() {
        // Slots 31744 and 31712 were missed.
        let consensus_rpc = serve_headers(32_000, &[31_680]);

        assert_eq!(recent_checkpoint_slot(&consensus_rpc).await, 31_680);
    }
}
