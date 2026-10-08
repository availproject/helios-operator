use alloy::sol_types::SolValue;
use anyhow::Result;
use clap::Parser;
use helios_consensus_core::types::LightClientHeader;
use helios_ethereum::rpc::ConsensusRpc;
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_helios_script::{fetch_execution_block_header, get_checkpoint, get_client, get_updates};
use sp1_sdk::{utils::setup_logger, Prover, ProverClient, SP1Stdin};

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long)]
    pub slot: Option<u64>,
}

const ELF: &[u8] = include_bytes!("../../elf/sp1-helios-elf");
#[allow(unused)]
#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    setup_logger();
    // Test checkpoint slot: a post-Gloas Sepolia checkpoint (epoch 353462). The beacon node must
    // still serve its light-client bootstrap and updates, so move it forward when it ages out.
    let slot = GenesisArgs::parse().slot.unwrap_or(11310784);
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
