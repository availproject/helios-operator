use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use helios_consensus_core::{
    calc_sync_period, consensus_spec::MainnetConsensusSpec, types::Update,
};
use helios_ethereum::rpc::ConsensusRpc;
use helios_ethereum::{
    config::{checkpoints, networks::Network, Config},
    consensus::Inner,
    rpc::http_rpc::HttpRpc,
};

use jsonrpsee::tracing::info;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc::channel, watch};
use url::Url;

pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u8 = 128;

/// Timeout for the beacon and execution RPC calls made here, so a stalled provider fails the
/// job instead of hanging the operator.
const RPC_TIMEOUT: Duration = Duration::from_secs(2 * 60);

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(RPC_TIMEOUT).build()?)
}

/// Fetch updates for client
pub async fn get_updates(
    client: &Inner<MainnetConsensusSpec, HttpRpc>,
) -> Vec<Update<MainnetConsensusSpec>> {
    let period =
        calc_sync_period::<MainnetConsensusSpec>(client.store.finalized_header.beacon().slot);

    let mut updates = client
        .rpc
        .get_updates(period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .unwrap();

    updates.retain(|u| {
        calc_sync_period::<MainnetConsensusSpec>(u.attested_header().beacon().slot) >= period
    });
    updates.sort_by_key(|u| u.attested_header().beacon().slot);

    updates
}

/// Fetch latest checkpoint from chain to bootstrap client to the latest state.
pub async fn get_latest_checkpoint() -> B256 {
    let cf = checkpoints::CheckpointFallback::new()
        .build()
        .await
        .unwrap();

    let chain_id = std::env::var("SOURCE_CHAIN_ID").expect("SOURCE_CHAIN_ID not set");
    let network = Network::from_chain_id(chain_id.parse().unwrap()).unwrap();

    cf.fetch_latest_checkpoint(&network).await.unwrap()
}

/// Fetch checkpoint from a slot number.
///
/// Reads the block root from the standard beacon API (`/eth/v1/beacon/headers/{slot}`), so it does
/// not depend on decoding the block body, which changes with every fork (Gloas moved the execution
/// payload out of the block).
pub async fn get_checkpoint(slot: u64) -> B256 {
    #[derive(serde::Deserialize)]
    struct HeaderResponse {
        data: HeaderData,
    }
    #[derive(serde::Deserialize)]
    struct HeaderData {
        root: B256,
    }

    let consensus_rpc = std::env::var("SOURCE_CONSENSUS_RPC_URL").unwrap();
    let url = format!(
        "{}/eth/v1/beacon/headers/{}",
        consensus_rpc.trim_end_matches('/'),
        slot
    );
    let response = http_client()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("Cannot get beacon header at slot {slot}: {e}"));
    let status = response.status();
    let body = response.text().await.unwrap();
    if !status.is_success() {
        panic!("Cannot get beacon header at slot {slot}: HTTP {status}: {body}");
    }
    let header: HeaderResponse = serde_json::from_str(&body).unwrap();

    header.data.root
}

/// Fetches the execution block `block_hash` and returns its RLP-encoded header.
///
/// The execution RPC is not trusted: the header is rebuilt from `eth_getBlockByHash`, encoded, and
/// only returned if it hashes to `block_hash`. The program checks the same again in-proof.
pub async fn fetch_execution_block_header(
    execution_rpc: &str,
    block_hash: B256,
) -> Result<Vec<u8>> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBlockByHash",
        "params": [block_hash, false],
    });
    let response: serde_json::Value = http_client()?
        .post(execution_rpc)
        .json(&request)
        .send()
        .await
        .map_err(|e| anyhow!("Cannot get execution block {block_hash}: {e}"))?
        .json()
        .await?;
    let block = response
        .get("result")
        .filter(|b| !b.is_null())
        .ok_or_else(|| {
            anyhow!(
                "Execution block {block_hash} not found. Is SOURCE_EXECUTION_RPC_URL on the chain Helios tracks? Response: {response}"
            )
        })?;

    encode_execution_block_header(block, block_hash)
}

/// RLP-encodes the header of an `eth_getBlockByHash` result and checks it hashes to `block_hash`.
fn encode_execution_block_header(block: &serde_json::Value, block_hash: B256) -> Result<Vec<u8>> {
    let header: alloy_consensus_v2::Header = serde_json::from_value(block.clone())?;
    let rlp = alloy_rlp::encode(&header);
    let hash = alloy_primitives::keccak256(&rlp);
    if hash != block_hash {
        return Err(anyhow!(
            "Execution header for {block_hash} re-encodes to {hash}; unknown header fields?"
        ));
    }

    Ok(rlp)
}

/// Setup a client from a checkpoint.
pub async fn get_client(checkpoint: B256) -> Inner<MainnetConsensusSpec, HttpRpc> {
    let consensus_rpc = std::env::var("SOURCE_CONSENSUS_RPC_URL").unwrap();
    let chain_id = std::env::var("SOURCE_CHAIN_ID").unwrap();
    let network = Network::from_chain_id(chain_id.parse().unwrap()).unwrap();
    let base_config = network.to_base_config();
    let url = Url::parse(&consensus_rpc).unwrap();

    let config = Config {
        consensus_rpc: url,
        execution_rpc: None,
        chain: base_config.chain,
        forks: base_config.forks,
        strict_checkpoint_age: false,
        ..Default::default()
    };

    let (block_send, _) = channel(256);
    let (finalized_block_send, _) = watch::channel(None);
    let (channel_send, _) = watch::channel(None);

    let mut client = Inner::new(
        &consensus_rpc,
        block_send,
        finalized_block_send,
        channel_send,
        Arc::new(config),
    );

    info!(target: "rpc", "checkpoint {:x}", checkpoint);

    client.bootstrap(checkpoint).await.unwrap();
    client
}

#[cfg(test)]
mod execution_header_tests {
    use super::*;

    /// `eth_getBlockByHash` result for Sepolia block 11869333 (after Gloas/Glamsterdam).
    const BLOCK_JSON: &str = include_str!("../testdata/sepolia-block-11869333.json");
    const BLOCK_HASH: &str = "0x227b1ede5189c4171dbc80bb4d8ba3933c8f5be244cc3764ab6fbbb80099cc2a";

    #[test]
    fn encodes_post_fork_header_to_its_hash() {
        let block: serde_json::Value = serde_json::from_str(BLOCK_JSON).unwrap();
        let hash: B256 = BLOCK_HASH.parse().unwrap();
        let rlp = encode_execution_block_header(&block, hash).unwrap();
        assert_eq!(alloy_primitives::keccak256(&rlp), hash);
    }

    #[test]
    fn rejects_header_for_another_hash() {
        let block: serde_json::Value = serde_json::from_str(BLOCK_JSON).unwrap();
        assert!(encode_execution_block_header(&block, B256::repeat_byte(1)).is_err());
    }
}
