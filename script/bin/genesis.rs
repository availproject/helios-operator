
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
use anyhow::Result;
/// Generate genesis parameters for light client contract
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_helios_script::{
    get_checkpoint, get_client, get_execution_state_root_proof, get_latest_checkpoint,
};
use sp1_sdk::{utils, HashableKey, ProverClient};
use ssz_rs::prelude::*;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use alloy::hex;
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use sp_core::H256;
use tree_hash::TreeHash;
use tracing::info;

const HELIOS_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

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

#[tokio::main]
pub async fn main() -> Result<()> {
    utils::setup_logger();

    let args = GenesisArgs::parse();

    // This fetches the .env file from the project root. If the command is invoked in the contracts/ directory,
    // the .env file in the root of the repo is used.
    if let Some(root) = find_project_root() {
        dotenv::from_path(root.join(args.env_file)).ok();
    } else {
        eprintln!(
            "Warning: Could not find project root. {} file not loaded.",
            args.env_file
        );
    }

    let client = ProverClient::new();
    let (_pk, vk) = client.setup(HELIOS_ELF);

    let checkpoint;
    if let Some(temp_slot) = args.slot {
        checkpoint = get_checkpoint(temp_slot).await;
    } else {
        checkpoint = get_latest_checkpoint().await;
    }
    let sp1_prover = env::var("SP1_PROVER").unwrap();

    let mut verifier = Address::ZERO;
    if sp1_prover != "mock" {
        verifier = env::var("SP1_VERIFIER_ADDRESS").unwrap().parse().unwrap();
    }

    let helios_client = get_client(checkpoint).await;
    let finalized_header = helios_client
        .store
        .finalized_header
        .clone()
        .beacon
        .tree_hash_root();
    let head = helios_client.store.finalized_header.clone().beacon.slot;
    let sync_committee_hash = helios_client
        .store
        .current_sync_committee
        .clone()
        .tree_hash_root();
    let genesis_time = helios_client.config.chain.genesis_time;
    let execution_state_root_proof = get_execution_state_root_proof(head).await.unwrap();
    let genesis_root = helios_client.config.chain.genesis_root;
    const SECONDS_PER_SLOT: u64 = 12;
    const SLOTS_PER_EPOCH: u64 = 32;
    const SLOTS_PER_PERIOD: u64 = SLOTS_PER_EPOCH * 256;
    let source_chain_id: u64 = match env::var("SOURCE_CHAIN_ID") {
        Ok(val) => val.parse().unwrap(),
        Err(_) => {
            info!("SOURCE_CHAIN_ID not set, defaulting to mainnet");
            1 // Mainnet chain ID
        }
    };

    // Get the workspace root with cargo metadata to make the paths.
    let workspace_root = PathBuf::from(
        cargo_metadata::MetadataCommand::new()
            .exec()
            .unwrap()
            .workspace_root,
    );

    // Read the Genesis config from the contracts directory.
    let mut genesis_config = get_existing_genesis_config(&workspace_root)?;

    genesis_config.genesis_validators_root = format!("0x{:x}", genesis_root);
    genesis_config.genesis_time = genesis_time;
    genesis_config.seconds_per_slot = SECONDS_PER_SLOT;
    genesis_config.slots_per_period = SLOTS_PER_PERIOD;
    genesis_config.slots_per_epoch = SLOTS_PER_EPOCH;
    genesis_config.source_chain_id = source_chain_id;
    genesis_config.sync_committee_hash = format!("0x{:x}", sync_committee_hash);
    genesis_config.header = format!("0x{:x}", finalized_header);
    genesis_config.execution_state_root =
        format!("0x{:x}", execution_state_root_proof.execution_state_root);
    genesis_config.head = head;
    genesis_config.helios_program_vkey = vk.bytes32();
    genesis_config.verifier = format!("0x{:x}", verifier);

    // Get the account associated with the private key.
    let private_key = env::var("PRIVATE_KEY").unwrap();
    let signer: PrivateKeySigner = private_key.parse().expect("Failed to parse private key");
    let deployer_address = signer.address();

    // Attempt using the GUARDIAN_ADDRESS, otherwise default to the address derived from the private key.
    // If the GUARDIAN_ADDRESS is not set, or is empty, the deployer address is used as the guardian address.
    let guardian = match env::var("GUARDIAN_ADDRESS") {
        Ok(guardian_addr) if !guardian_addr.is_empty() => guardian_addr,
        _ => format!("0x{:x}", deployer_address),
    };

    genesis_config.guardian = guardian;

    write_genesis_config(&workspace_root, &genesis_config)?;

    Ok(())
}

fn find_project_root() -> Option<PathBuf> {
    let mut path = std::env::current_dir().ok()?;
    while !path.join(".git").exists() {
        if !path.pop() {
            return None;
        }
    }
    Some(path)
}

/// Get the existing genesis config from the contracts directory.
fn get_existing_genesis_config(workspace_root: &Path) -> Result<GenesisConfig> {
    let genesis_config_path = workspace_root.join("contracts").join("genesis.json");
    let genesis_config_content = std::fs::read_to_string(genesis_config_path)?;
    let genesis_config: GenesisConfig = serde_json::from_str(&genesis_config_content)?;
    Ok(genesis_config)
}

/// Write the genesis config to the contracts directory.
fn write_genesis_config(workspace_root: &Path, genesis_config: &GenesisConfig) -> Result<()> {
    let genesis_config_path = workspace_root.join("contracts").join("genesis.json");
    info!("Writing genesis config to {:?}", &genesis_config_path);
    info!("Writing genesis data {:?}", &genesis_config);
    fs::write(
        genesis_config_path,
        serde_json::to_string_pretty(&genesis_config)?,
    )?;
    Ok(())
}

// #[test]
// fn test() {
//
//     let proof = hex!("54bdcae31025fd6c8688cf79b70e14b05cf7007e27026c89c1d5d3b0dda40377d5546f3c2d2765971de51abd287716903ced3c070ba0d6d802b1148556f5fdbdea066cc229069d586f3b20ace1c1a99e26b2bf71be719acc7c08b84546d7d5b008b2c6cf0f14569e909ac9277f549d7ca4d720666ad29d7ab09c1d03441579f193e85239003946b1b41b934389edf6e9adaf8cf17697dcdf1b1027a8ca9256aa7e0fc55208843ae9d5ffd4d20bed13fba53d909ccbb43e8786459fd83e811d8cd96e3f4804ec2089cfe173c31177b9211d1773b1c268e303a960346bda14000044c475d4129d82bf2c2dd059979aa97869854c62644bbaa1d161aafe854ce39ad81a37232f6124e1ca56cb7ef137e3a41b53dd967cf5f2395607ea2a6b78e3a265006fed0d6567ce82850901453b16e2c518f3e549992c5105a3bfc1469aef47613cb22606856d5b13511c3eee659f47bae5055125ff747cfd3e87cf21ecfb59e4d9447d1f6e246774dfd58f9156b04895db4570dbe559f0fa93687fed4b0a677662595910f7fcea2489385130910125dac2cc2e2b78d2549ad558a53cb3e165ef83922d19d175c6b36aeea79189a3aac060249cd9b8495a5acc608d37645018412e64881792fba8cfa3f80872791f03b69c33aa4c9faba3c87a4d188a9df380aaf2cdb02120a1de22c1479a8c672e25f5729f294898963259229a25cba0bdeff4559e471ab19c673239c09b1bd9d2fdd6dbc4de1691f33aba4e3b8e5c01ea3023ab5b83232ffd4755ef3aab0255e6154319f86b9fa4b466b1e0ef7dae4e64dd02833f6102621f70dcec5ee9d07f5ad4fa60449817b6b7707ff5ba76e68c4a3d0c553e590936c5aeb5d3f211f124e630cdc7cbd63d180a92925c26af2bf5e24a9db4cb63065183e4395dadf4c01316c7528ea2183a20c61eeded15201bd5bf53e013f3832629e92742e7d960eecbced22072afe527fab03ea7ae3bb249ae8c402d91e4dc19dc32b95e438ea78f951bd2b6f460f0329dde72d61954535da935f8f6a99d2b273ee4eb2a4bdc8fcbbfefe5ac8ed1cd861cac2a8f0028f02f09a721ec69b13a1af7c1768cf253b97a82ea15422c33e872e3b26a4d60a08164bf863df68e1cbe1351ca1afa1b7e489e003bda9cb38ef14e88b6689106652a9a046723442c06402f0964aeb1c130db176c333c5e02979ee3b94788e54dd3569a039769ec9a0059");
//     let public_values = hex!("3fe51638d5b621f8dcb074a4c63b6cde73f56352c38fb6c823fecfb4c79523b2e61d2f6dc52e667a9b82eb45aa1c2166b9e9b84125acff4b4c46f7d212efe9bf36210ad5953e264b9c0aac29ecefb9dfffc47abd1412d1693a5f180192755de4000000000000000000000000000000000000000000000000000000000062c400c926aeca0419adf05de4a1e021ef998ce26825f53ed69de261d316386f717f8b00000000000000000000000000000000000000000000000000000000006288202878a739ddb11dbd60027f964a92efc6549937d5ddffeffa314f93855313ae22");
//     let sp1_vk = hex!("0064fa3309d8e8f9c1cc6b0b776c593578f3820cdd13e54eac1d93efb972a7bc");
//
//     let is_valid = Groth16Verifier::verify(
//         &proof,
//         &public_values,
//         &format!("{:?}", sp1_vk),
//         &GROTH16_VK_BYTES,
//     );
//
//
//     println!("{:#?}", is_valid);
//
//
// }