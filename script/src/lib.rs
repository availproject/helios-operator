use alloy_primitives::B256;
use clap::Parser;
use helios::{
    config::networks::Network,
    consensus::{
        constants,
        rpc::{nimbus_rpc::NimbusRpc, ConsensusRpc},
        Inner,
    },
    consensus_core::calc_sync_period,
    prelude::*,
    types::Update,
};
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use sp1_helios_primitives::types::ExecutionStateProof;
use ssz_rs::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc::channel, watch};
use tracing::info;
use tree_hash::TreeHash;

/// Fetch updates for client
pub async fn get_updates(client: &Inner<NimbusRpc>) -> Vec<Update> {
    let period = calc_sync_period(client.store.finalized_header.beacon.slot);

    let updates = client
        .rpc
        .get_updates(period, constants::MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .unwrap();

    updates.clone()
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
pub async fn get_checkpoint(slot: u64) -> B256 {
    let rpc_url =
        std::env::var("SOURCE_CONSENSUS_RPC_URL").expect("SOURCE_CONSENSUS_RPC_URL not set");
    let rpc: NimbusRpc = NimbusRpc::new(&rpc_url);

    let block = rpc.get_block(slot).await.unwrap();

    B256::from_slice(block.tree_hash_root().as_ref())
}

#[derive(Deserialize)]
struct ApiResponse {
    success: bool,
    result: ExecutionStateProof,
}

/// Fetch merkle proof for the execution state root of a specific slot.
pub async fn get_execution_state_root_proof(
    slot: u64,
) -> Result<ExecutionStateProof, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let chain_id = std::env::var("SOURCE_CHAIN_ID").expect("SOURCE_CHAIN_ID not set");
    let url_suffix = match chain_id.as_str() {
        "11155111" => "-sepolia", // Sepolia chain ID
        "17000" => "-holesky",    // Holesky chain ID
        "1" => "",                // Mainnet chain ID
        _ => return Err(format!("Unsupported chain ID: {}", chain_id).into()),
    };

    let url = format!(
        "https://beaconapi{}.succinct.xyz/api/beacon/proof/executionStateRoot/{}",
        url_suffix, slot
    );

    let response: ApiResponse = client.get(url).send().await?.json().await?;

    if response.success {
        Ok(response.result)
    } else {
        Err("API request was not successful".into())
    }
}

/// Setup a client from a checkpoint.
pub async fn get_client(checkpoint: B256) -> Inner<NimbusRpc> {
    let consensus_rpc = std::env::var("SOURCE_CONSENSUS_RPC_URL").unwrap();
    let chain_id = std::env::var("SOURCE_CHAIN_ID").unwrap();

    info!(
        "chain_id" = chain_id,
        "checkpoint" = format!("{:?}", checkpoint),
        "Getting client"
    );

    let network = Network::from_chain_id(chain_id.parse().unwrap()).unwrap();
    let base_config = network.to_base_config();

    let config = Config {
        consensus_rpc: consensus_rpc.to_string(),
        execution_rpc: String::new(),
        chain: base_config.chain,
        forks: base_config.forks,
        strict_checkpoint_age: false,
        ..Default::default()
    };

    let (block_send, _) = channel(256);
    let (finalized_block_send, _) = watch::channel(None);
    let (channel_send, _) = watch::channel(None);

    let mut client = Inner::<NimbusRpc>::new(
        &consensus_rpc,
        block_send,
        finalized_block_send,
        channel_send,
        Arc::new(config),
    );

    client.bootstrap(checkpoint).await.unwrap();
    client
}

// Genesis config
pub const HELIOS_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long)]
    pub slot: Option<u64>,
    #[arg(long, default_value = ".env")]
    pub env_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisConfig {
    pub execution_state_root: String,
    pub genesis_time: u64,
    pub genesis_validators_root: String,
    pub guardian: String,
    pub head: u64,
    pub header: String,
    pub helios_program_vkey: String,
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    pub slots_per_period: u64,
    pub source_chain_id: u64,
    pub sync_committee_hash: String,
    pub verifier: String,
}

pub fn find_project_root() -> Option<PathBuf> {
    let mut path = std::env::current_dir().ok()?;
    while !path.join(".git").exists() {
        if !path.pop() {
            return None;
        }
    }
    Some(path)
}

/// Get the existing genesis config from the contracts directory.
pub fn get_existing_genesis_config(workspace_root: &Path) -> anyhow::Result<GenesisConfig> {
    let genesis_config_path = workspace_root.join("contracts").join("genesis.json");
    let genesis_config_content = std::fs::read_to_string(genesis_config_path)?;
    let genesis_config: GenesisConfig = serde_json::from_str(&genesis_config_content)?;
    Ok(genesis_config)
}

/// Write the genesis config to the contracts directory.
pub fn write_genesis_config(
    workspace_root: &Path,
    genesis_config: &GenesisConfig,
) -> anyhow::Result<()> {
    let genesis_config_path = workspace_root.join("contracts").join("genesis.json");
    info!("Writing genesis config to {:?}", &genesis_config_path);
    info!("Writing genesis data {:?}", &genesis_config);
    fs::write(
        genesis_config_path,
        serde_json::to_string_pretty(&genesis_config)?,
    )?;
    Ok(())
}
