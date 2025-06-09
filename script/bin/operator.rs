mod test;

use alloy::sol;
use anyhow::{anyhow, Context, Result};
use avail::vector::events as VectorEvent;
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_ethereum::consensus::Inner;
use helios_ethereum::rpc::http_rpc::HttpRpc;
use helios_ethereum::rpc::ConsensusRpc;

use alloy::sol_types::SolValue;
use alloy_primitives::hex;
use alloy_primitives::hex::ToHexExt;
use avail_rust::avail::babe::storage::types::current_slot::CurrentSlot;
use avail_rust::avail::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use avail_rust::avail_core::currency::AVAIL;
use avail_rust::sp_core::{twox_128, Decode};
use avail_rust::{avail, Keypair, Options, SecretUri, H256, SDK};
use jsonrpsee::tracing::{error, info};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_helios_script::*;
use sp1_sdk::{
    NetworkProver, Prover, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
};
use std::env;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tree_hash::TreeHash;

const ELF: &[u8] = include_bytes!("../../elf/sp1-helios-elf");
// Skip problematic slot
struct SP1AvailLightClientOperator {
    client: NetworkProver,
    avail_client: HttpClient,
    pk: SP1ProvingKey,
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Helios {
        bytes32 public immutable GENESIS_VALIDATORS_ROOT;
        uint256 public immutable GENESIS_TIME;
        uint256 public immutable SECONDS_PER_SLOT;
        uint256 public immutable SLOTS_PER_PERIOD;
        uint32 public immutable SOURCE_CHAIN_ID;
        uint256 public head;
        mapping(uint256 => bytes32) public syncCommittees;
        mapping(uint256 => bytes32) public executionStateRoots;
        mapping(uint256 => bytes32) public headers;
        bytes32 public heliosProgramVkey;
        address public verifier;

        struct ProofOutputs {
            bytes32 executionStateRoot;
            bytes32 newHeader;
            bytes32 nextSyncCommitteeHash;
            uint256 newHead;
            bytes32 prevHeader;
            uint256 prevHead;
            bytes32 syncCommitteeHash;
        }

        event HeadUpdate(uint256 indexed slot, bytes32 indexed root);
        event SyncCommitteeUpdate(uint256 indexed period, bytes32 indexed root);

        function update(bytes calldata proof, bytes calldata publicValues) external;
        function getSyncCommitteePeriod(uint256 slot) internal view returns (uint256);
        function getCurrentSlot() internal view returns (uint256);
        function getCurrentEpoch() internal view returns (uint256);
    }
}

/// Implementation of the avail light clien operator that relays transactions to the Avail
impl SP1AvailLightClientOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let avail_rpc = env::var("AVAIL_RPC").expect("AVAIL_RPC env var not set");

        let client = ProverClient::builder().network().build();
        let (pk, _) = client.setup(ELF);

        let avail_client = HttpClientBuilder::default()
            .max_concurrent_requests(1024)
            .build(avail_rpc)
            .expect("Could not create RPC client");

        Self {
            client,
            avail_client,
            pk,
        }
    }

    /// Fetch values and generate an 'update' proof for the SP1 Helios contract.
    async fn request_update(
        &mut self,
        mut client: Inner<MainnetConsensusSpec, HttpRpc>,
    ) -> Result<Option<SP1ProofWithPublicValues>> {
        // head is initialised
        let head = self.get_head().await?;

        let slot_per_period = env::var("SLOTS_PER_PERIOD")
            .unwrap_or("8192".to_string())
            .parse::<u64>()?;

        info!("Head/Slot {}", head);

        let period = head / slot_per_period;
        let contract_next_sync_committee = self.get_sync_committee(period + 1).await?;

        let mut stdin = SP1Stdin::new();

        // Setup client.
        let mut sync_committee_updates = get_updates(&client).await;
        let finality_update = client
            .rpc
            .get_finality_update()
            .await
            .expect("RPC get_finality_update failed");

        // Check if contract is up to date
        let latest_block = finality_update.finalized_header().beacon().slot;
        if latest_block <= head {
            info!("Contract is up to date. Nothing to update.");
            return Ok(None);
        }

        // Optimization:
        // Skip processing update inside program if next_sync_committee is already stored in contract.
        // We must still apply the update locally to "sync" the helios client, this is due to
        // next_sync_committee not being stored when the helios client is bootstrapped.
        if !sync_committee_updates.is_empty() {
            let next_sync_committee = H256::from_slice(
                sync_committee_updates[0]
                    .next_sync_committee()
                    .tree_hash_root()
                    .as_ref(),
            );

            if contract_next_sync_committee == next_sync_committee {
                println!("Applying optimization, skipping update");
                let temp_update = sync_committee_updates.remove(0);

                client
                    .verify_update(&temp_update)
                    .expect("Verify update validation error!");
                client.apply_update(&temp_update);
            }
        }

        // Create program inputs
        let expected_current_slot = client.expected_current_slot();
        let inputs = ProofInputs {
            sync_committee_updates,
            finality_update,
            expected_current_slot,
            store: client.store.clone(),
            genesis_root: client.config.chain.genesis_root,
            forks: client.config.forks.clone(),
        };
        let encoded_proof_inputs = serde_cbor::to_vec(&inputs)?;
        stdin.write_slice(&encoded_proof_inputs);

        info!("Generate proof start");
        // Generate proof.
        let mock = env::var("SP1_PROVER")?.to_lowercase() == "mock";
        if mock {
            info!("Using mock prover");
            let prover_client = ProverClient::builder().mock().build();
            let proof = prover_client.prove(&self.pk, &stdin).groth16().run()?;
            Ok(Some(proof))
        } else {
            let proof = self
                .client
                .prove(&self.pk, &stdin)
                .groth16()
                .timeout(Duration::from_secs(900))
                .run()?;
            info!("Generate proof end");

            let proof_outputs: ProofOutputs =
                SolValue::abi_decode(&proof.public_values.as_slice(), true)
                    .context("Cannot decode public values")?;
            let new_slot = proof_outputs.newHead.to();
            if new_slot <= head {
                tracing::warn!(
                    message = "New slot slot is <= from the current, skipping update",
                    current_slot = head,
                    new_slot = new_slot
                );
                return Ok(None);
            }

            info!("Attempting to update to new head block: {:?}", latest_block);
            Ok(Some(proof))
        }
    }

    /// Relay the proof to Avail
    async fn relay_vector_update(&self, proof: SP1ProofWithPublicValues) -> Result<()> {
        let mock = env::var("SP1_PROVER")?.to_lowercase() == "mock";

        let proof_as_bytes = if mock { vec![] } else { proof.bytes() };

        let secret = env::var("AVAIL_SECRET").expect("AVAIL_SECRET env var not set");
        let avail_rpc = env::var("AVAIL_WS_RPC").expect("AVAIL_WS_RPC env var not set");
        let secret_uri = SecretUri::from_str(secret.as_str())?;
        let account = Keypair::from_uri(&secret_uri)?;

        let proof_vec: BoundedVec<u8> = BoundedVec(proof_as_bytes);
        let pub_values_vec: BoundedVec<u8> = BoundedVec(proof.public_values.to_vec());

        let sdk = SDK::new(avail_rpc.as_str())
            .await
            .expect("Could not create SDK!");

        let account_id = account.public_key().to_account_id();
        let storage_query = avail::storage().system().account(account_id);
        let best_block_hash = &sdk
            .client
            .best_block_hash()
            .await
            .expect("Must fetch fetch_best_block_hash!");
        let storage = sdk.client.storage().at(*best_block_hash);
        let result = storage.fetch(&storage_query).await?;
        if let Some(account) = result {
            info!(
                "token_amount" = account.data.free.checked_div(AVAIL),
                "nonce" = account.nonce,
                "Account info."
            );
        }

        let result = if mock {
            info!("Using mocked proof (mock_fulfill)!");
            let tx = sdk.tx.vector.mock_fulfill(pub_values_vec.0);
            tx.execute_and_watch_finalization(&account, Options::new())
                .await
                .expect("Transaction must be executed!")
        } else {
            info!("Using real proof (fulfill)!");
            let tx = sdk.tx.vector.fulfill(proof_vec.0, pub_values_vec.0);
            tx.execute_and_watch_finalization(&account, Options::new())
                .await
                .expect("Transaction must be executed!")
        };

        // if tx failed throw an error and retry
        if !result.is_successful().unwrap_or(false) {
            error!(
                "block_number" = result.block_number,
                "block_hash" = format!("{:?}", result.block_hash),
                "tx_hash" = format!("{:?}", result.tx_hash),
                "Transaction send failed!"
            );
            return Err(anyhow!("Tx failed!"));
        }

        let Some(events) = &result.events else {
            error!("No events received!");
            return Err(anyhow!("No events received!"));
        };

        let head_updated = events.find::<VectorEvent::HeadUpdated>();
        info!(
            "block_number" = result.block_number,
            "block_hash" = format!("{:?}", result.block_hash),
            "tx_hash" = format!("{:?}", result.tx_hash),
            "Transaction sent"
        );

        if !head_updated.is_empty() {
            info!(
                "slot" = head_updated[0].slot,
                "finalization_root" = format!("{:?}", head_updated[0].finalization_root),
                "execution_state_root" = format!("{:?}", head_updated[0].execution_state_root),
                "Head updated"
            );
        } else {
            error!(
                "block_number" = result.block_number,
                "block_hash" = format!("{:?}", result.block_hash),
                "tx_hash" = format!("{:?}", result.tx_hash),
                "No head updated"
            );
        }

        Ok(())
    }

    /// Start the operator.
    async fn run(&mut self, loop_delay_mins: u64) -> Result<()> {
        info!("Starting SP1 Helios operator for Avail");

        loop {
            // Get the current slot from the contract
            let start = Instant::now();
            let slot = self.get_head().await?;
            info!("Current slot: {}", slot);

            // Fetch the checkpoint at that slot
            let checkpoint = get_checkpoint(slot).await;

            // Get the client from the checkpoint
            let client = get_client(checkpoint).await;

            // Request an update
            match self.request_update(client).await {
                Ok(Some(proof)) => {
                    self.relay_vector_update(proof).await?;
                }
                Ok(None) => {
                    // Contract is up to date. Nothing to update.
                }
                Err(e) => {
                    error!("Request for update failed: {}", e);
                    info!("Retrying...");
                    continue;
                }
            };
            let duration = start.elapsed();

            info!("duration" = duration.as_secs(), "Loop finished");

            info!("Sleeping for {:?} minutes", loop_delay_mins);
            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_delay_mins)).await;
        }
    }

    /// get_head reads head from the Avail chain
    async fn get_head(&mut self) -> Result<u64> {
        let pallet = "Vector";
        let head = "Head";

        let finalized_block_hash_str: String = self
            .avail_client
            .request("chain_getFinalizedHead", rpc_params![])
            .await
            .expect("finalized head");

        let head_key = format!(
            "0x{}{}",
            hex::encode(twox_128(pallet.as_bytes())),
            hex::encode(twox_128(head.as_bytes()))
        );

        let head_str: String = self
            .avail_client
            .request(
                "state_getStorage",
                rpc_params![head_key, finalized_block_hash_str.clone()],
            )
            .await
            .context("Cannot parse head from Avail chain")
            .expect("Head must exist");

        // head cannot be zero on a chain as it is already populated
        let slot_from_hex =
            sp_core::bytes::from_hex(head_str.as_str()).expect("Must read slot from hex!");
        let slot: u64 =
            Decode::decode(&mut slot_from_hex.as_slice()).expect("Must decode slot from hex!");
        Ok(slot)
    }

    /// get_sync_committee reads sync committee hash from a chain so it can use later to apply updates
    async fn get_sync_committee(&mut self, period: u64) -> Result<H256> {
        let pallet = "Vector";
        let sync_committee_hash = "SyncCommitteeHashes";

        let finalized_block_hash_str: String = self
            .avail_client
            .request("chain_getFinalizedHead", rpc_params![])
            .await
            .expect("finalized head");

        info!("Finalized head: {}", finalized_block_hash_str);

        let sync_committee_key = format!(
            "0x{}{}{}",
            hex::encode(twox_128(pallet.as_bytes())),
            hex::encode(twox_128(sync_committee_hash.as_bytes())),
            hex::encode(period.to_le_bytes())
        );

        info!("Next period (current_period + 1) {}", period);

        let sync_committee_hash: String = self
            .avail_client
            .request(
                "state_getStorage",
                rpc_params![sync_committee_key, finalized_block_hash_str.clone()],
            )
            .await
            .unwrap_or(H256::zero().encode_hex());

        // sync committee must be initialized for the start period
        let sync_committee_hash = sp_core::bytes::from_hex(sync_committee_hash.as_str())
            .context("parse sync_committee_hash")?;
        let hash: H256 = Decode::decode(&mut sync_committee_hash.as_slice())
            .context("Decode sync_committee_hash")?;

        info!("Sync committee hash: {}", hash);

        Ok(H256(hash.into()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    let log_level = env::var("LOG_LEVEL").unwrap_or("info".to_string());

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_line_number(true)
                .with_target(true),
        )
        .with(LevelFilter::from_str(&log_level)?)
        .init();

    let loop_delay_mins = env::var("LOOP_DELAY_MINS")
        .unwrap_or("5".to_string())
        .parse()?;

    let mut operator = SP1AvailLightClientOperator::new().await;
    loop {
        if let Err(e) = operator.run(loop_delay_mins).await {
            error!("Error running operator: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ELF;
    use sp1_sdk::Prover;
    use sp1_sdk::{HashableKey, ProverClient};

    #[test]
    fn test_program_verification_key() {
        let client = ProverClient::builder().cpu().build();
        let (_pk, vk) = client.setup(ELF);

        assert_eq!(
            "0x003ef077b6a82831a994a12a673901221ca1752080605189930748d0772d5c68",
            vk.bytes32()
        );
    }
}
