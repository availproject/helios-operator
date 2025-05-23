use anyhow::Result;
use clap::{command, Parser};
use helios_ethereum::rpc::ConsensusRpc;
use sp1_helios_primitives::types::ProofInputs;
use sp1_helios_script::{get_checkpoint, get_client, get_updates};
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};

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
    let args = GenesisArgs::parse();

    // Get the current slot from the contract or fetch the latest checkpoint
    let checkpoint = if let Some(slot) = args.slot {
        get_checkpoint(slot).await
    } else {
        // test slot
        get_checkpoint(7121216).await
    };

    // Setup client.
    let helios_client = get_client(checkpoint).await;
    let sync_committee_updates = get_updates(&helios_client).await;
    let finality_update = helios_client.rpc.get_finality_update().await.unwrap();

    let expected_current_slot = helios_client.expected_current_slot();
    let inputs = ProofInputs {
        sync_committee_updates,
        finality_update,
        expected_current_slot,
        store: helios_client.store.clone(),
        genesis_root: helios_client.config.chain.genesis_root,
        forks: helios_client.config.forks.clone(),
    };

    // Write the inputs to the VM
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&serde_cbor::to_vec(&inputs)?);

    let prover_client = ProverClient::builder().cpu().build();
    let (_, report) = prover_client.execute(ELF, &stdin).run()?;
    println!("Execution Report: {:?}", report);

    Ok(())
}
