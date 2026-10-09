use alloy::sol;
use anyhow::{anyhow, Context, Result};
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_consensus_core::types::LightClientHeader;
use helios_ethereum::consensus::Inner;
use helios_ethereum::rpc::http_rpc::HttpRpc;
use helios_ethereum::rpc::ConsensusRpc;

use avail_rust_client::codec::Decode;
use avail_rust_client::{
    avail, Client, HasHeader, Keypair, KeypairExt, Options, StorageValue, H256, ONE_AVAIL,
};
use jsonrpsee::tracing::{error, info, warn};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use sp1_helios_primitives::types::ProofInputs;
use sp1_helios_script::*;
use sp1_sdk::network::FulfillmentStrategy;
use sp1_sdk::{
    env::{EnvProver, EnvProvingKey},
    ProveRequest, Prover, ProverClient, SP1ProofWithPublicValues, SP1Stdin,
};
use std::env;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const ELF: &[u8] = include_bytes!("../../elf/sp1-helios-elf");
// A transaction stops being valid 32 blocks (~11 min) after it is signed. The receipt search then
// ends on its own; this bounds it when finality stalls.
const FINALIZATION_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Vector pallet event emitted when a proof updates the head. avail-rust ships no binding for it.
#[derive(Decode)]
#[codec(crate = avail_rust_client::codec)]
struct HeadUpdated {
    slot: u64,
    finalization_root: H256,
    execution_state_root: H256,
}

impl HasHeader for HeadUpdated {
    // (Vector pallet index, HeadUpdated event index)
    const HEADER_INDEX: (u8, u8) = (39, 0);
}

/// Vector pallet storage value holding the latest updated slot.
struct VectorHead;

impl StorageValue for VectorHead {
    const PALLET_NAME: &str = "Vector";
    const STORAGE_NAME: &str = "Head";
    type VALUE = u64;
}
// Skip problematic slot
struct SP1AvailLightClientOperator {
    env_prover: EnvProver,
    avail_client: HttpClient,
    pk: EnvProvingKey,
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

        let env_prover = ProverClient::from_env().await;

        let pk = env_prover
            .setup(ELF.into())
            .await
            .expect("Failed to setup proving key");

        let avail_client = HttpClientBuilder::default()
            .max_concurrent_requests(1024)
            .build(avail_rpc)
            .expect("Could not create RPC client");

        Self {
            env_prover,
            avail_client,
            pk,
        }
    }

    /// Fetch values and generate an 'update' proof for the SP1 Helios contract.
    async fn request_update(
        &mut self,
        client: Inner<MainnetConsensusSpec, HttpRpc>,
    ) -> Result<Option<SP1ProofWithPublicValues>> {
        // head is initialised
        let head = self.get_head().await?;

        info!("Head/Slot {}", head);

        let mut stdin = SP1Stdin::new();

        // Setup client.
        let sync_committee_updates = get_updates(&client).await;

        // Retry configuration for non-checkpoint slots
        let retry_threshold_mins: u64 = env::var("RETRY_THRESHOLD")
            .unwrap_or("5".to_string())
            .parse()?;
        let max_retries: u32 = env::var("MAX_RETRIES").unwrap_or("3".to_string()).parse()?;

        // Retry loop for getting a valid checkpoint slot
        let mut retry_count: u32 = 0;
        let finality_update = loop {
            let finality_update = client
                .rpc
                .get_finality_update()
                .await
                .expect("RPC get_finality_update failed");

            let latest_block = finality_update.finalized_header().beacon().slot;

            // Check if contract is up to date - this is expected, no retry needed
            if latest_block <= head {
                info!("Contract is up to date. Nothing to update.");
                return Ok(None);
            }

            // Check if it's a checkpoint slot (multiple of 32)
            if latest_block.is_multiple_of(32) {
                break finality_update;
            }

            // Non-checkpoint slot - apply retry logic
            retry_count += 1;
            if retry_count > max_retries {
                warn!(
                    "Max retries ({}) exceeded for non-checkpoint slot: {}. Giving up.",
                    max_retries, latest_block
                );
                return Ok(None);
            }

            warn!(
                "Attempted to commit to a non-checkpoint slot: {}. Retry {}/{}. Waiting {} minutes...",
                latest_block, retry_count, max_retries, retry_threshold_mins
            );
            tokio::time::sleep(Duration::from_secs(retry_threshold_mins * 60)).await;
        };

        let latest_block = finality_update.finalized_header().beacon().slot;

        info!(
            "New head to update Slot: {:?} from Head: {:?}",
            latest_block, head
        );

        // From Gloas the finalized header only commits to the execution block hash; the program
        // needs the block header itself to read the execution state root.
        let execution_block_header = match finality_update.finalized_header() {
            LightClientHeader::Gloas(header) => {
                let execution_rpc = env::var("SOURCE_EXECUTION_RPC_URL")
                    .context("SOURCE_EXECUTION_RPC_URL is required from the Gloas fork")?;
                Some(
                    fetch_execution_block_header(&execution_rpc, header.execution_block_hash)
                        .await?,
                )
            }
            _ => None,
        };

        // Create program inputs
        let expected_current_slot = client.expected_current_slot();
        let inputs = ProofInputs {
            sync_committee_updates,
            finality_update,
            expected_current_slot,
            store: client.store.clone(),
            genesis_root: client.config.chain.genesis_root,
            forks: client.config.forks.clone(),
            execution_block_header,
        };
        let encoded_proof_inputs = serde_cbor::to_vec(&inputs)?;
        stdin.write_slice(&encoded_proof_inputs);

        info!("Generate proof start");
        let mock = env::var("SP1_PROVER")?.to_lowercase() == "mock";
        if mock {
            info!("Using mock prover");
            let prover_client = ProverClient::builder().mock().build().await;
            let pk = prover_client.setup(ELF.into()).await?;
            let proof = prover_client.prove(&pk, stdin).groth16().await?;
            Ok(Some(proof))
        } else {
            let spn = env::var("SP1_PROVER")?.to_lowercase() == "network";

            let proof = if spn {
                info!("Using spn network prover");
                let spn_client = ProverClient::builder().network().build().await;
                let pk = spn_client.setup(ELF.into()).await?;
                let balance = spn_client.get_balance().await?;
                info!(message = "Available balance", balance = balance.to_string());
                let proof = spn_client
                    .prove(&pk, stdin)
                    .groth16()
                    .strategy(FulfillmentStrategy::Auction)
                    .min_auction_period(10)
                    .timeout(Duration::from_secs(900))
                    .await?;
                Ok(Some(proof))
            } else {
                info!("Using predefined prover");

                let proof = self.env_prover.prove(&self.pk, stdin).groth16().await?;
                Ok(Some(proof))
            };
            info!("Generate proof end");
            info!("Attempting to update to new head block: {:?}", latest_block);

            proof
        }
    }

    /// Relay the proof to Avail
    async fn relay_vector_update(&self, proof: SP1ProofWithPublicValues) -> Result<()> {
        let mock = env::var("SP1_PROVER")?.to_lowercase() == "mock";

        let proof_as_bytes = if mock { vec![] } else { proof.bytes() };
        let secret = env::var("AVAIL_SECRET").expect("AVAIL_SECRET env var not set");
        let avail_rpc = env::var("AVAIL_RPC").expect("AVAIL_RPC env var not set");
        let account = Keypair::from_str(secret.as_str())?;

        // A new client per relay: the client caches the runtime version when it connects.
        let client = Client::new(avail_rpc.as_str())
            .await
            .expect("Could not create Avail client!");

        let account_info = client.best().account_info(account.account_id()).await?;
        info!(
            "token_amount" = account_info.data.free.checked_div(ONE_AVAIL),
            "nonce" = account_info.nonce,
            "Account info."
        );

        let tx = if mock {
            info!("Using mocked proof (mock_fulfill)!");
            client
                .tx()
                .vector()
                .mock_fulfill(proof.public_values.to_vec())
        } else {
            info!("Using real proof (fulfill)!");
            client
                .tx()
                .vector()
                .fulfill(proof_as_bytes, proof.public_values.to_vec())
        };
        let submitted = tx
            .sign_and_submit(&account, Options::default())
            .await
            .expect("Transaction must be executed!");

        // receipt(false) searches finalized blocks only.
        let Ok(receipt) =
            tokio::time::timeout(FINALIZATION_TIMEOUT, submitted.receipt(false)).await
        else {
            error!(
                "tx_hash" = format!("{:?}", submitted.ext_hash),
                "Transaction not finalized within {:?}!", FINALIZATION_TIMEOUT
            );
            return Err(anyhow!("Tx not finalized!"));
        };
        let Some(receipt) = receipt.expect("Transaction must be executed!") else {
            error!(
                "tx_hash" = format!("{:?}", submitted.ext_hash),
                "Transaction not found in a finalized block before it expired!"
            );
            return Err(anyhow!("Tx not found!"));
        };

        let Ok(events) = receipt.events().await else {
            error!("No events received!");
            return Err(anyhow!("No events received!"));
        };

        if !events.is_extrinsic_success_present() {
            let dispatch_error = events
                .first::<avail::system::events::ExtrinsicFailed>()
                .map(|failed| format!("{:?}", failed.dispatch_error));
            error!(
                "block_number" = receipt.block_height,
                "block_hash" = format!("{:?}", receipt.block_hash),
                "tx_hash" = format!("{:?}", receipt.ext_hash),
                "dispatch_error" = dispatch_error,
                "Transaction send failed!"
            );
            return Err(anyhow!("Tx failed!"));
        }

        let head_updated = events.first::<HeadUpdated>();
        info!(
            "block_number" = receipt.block_height,
            "block_hash" = format!("{:?}", receipt.block_hash),
            "tx_hash" = format!("{:?}", receipt.ext_hash),
            "Transaction sent"
        );

        if let Some(head_updated) = head_updated {
            info!(
                "slot" = head_updated.slot,
                "finalization_root" = format!("{:?}", head_updated.finalization_root),
                "execution_state_root" = format!("{:?}", head_updated.execution_state_root),
                "Head updated"
            );
        } else {
            error!(
                "block_number" = receipt.block_height,
                "block_hash" = format!("{:?}", receipt.block_hash),
                "tx_hash" = format!("{:?}", receipt.ext_hash),
                "No head updated"
            );
        }

        Ok(())
    }

    /// Start the operator.
    async fn run(&mut self, job_delay: u64) -> Result<()> {
        info!("Starting SP1 Helios operator for Avail");

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
                return Err(e);
            }
        };
        let duration = start.elapsed();

        info!("duration" = duration.as_secs(), "Job finished");

        info!("Sleeping for {:?} minutes", job_delay);
        Ok(())
    }

    /// get_head reads head from the Avail chain
    async fn get_head(&mut self) -> Result<u64> {
        let finalized_block_hash_str: String = self
            .avail_client
            .request("chain_getFinalizedHead", rpc_params![])
            .await
            .expect("finalized head");

        let head_key = VectorHead::hex_encode_storage_key();

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
        let slot = VectorHead::decode_hex_storage_value(head_str.as_str())
            .expect("Must decode slot from hex!");
        Ok(slot)
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

    let job_delay_mins = env::var("LOOP_DELAY_MINS")
        .unwrap_or("5".to_string())
        .parse()?;

    let mut operator = SP1AvailLightClientOperator::new().await;
    if let Err(e) = operator.run(job_delay_mins).await {
        error!("Error running operator: {}", e);
        return Err(anyhow!("Error running operator: {}", e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{HeadUpdated, VectorHead, ELF};
    use avail_rust_client::avail_rust_core::decoded_extrinsics::TransactionEncodable;
    use avail_rust_client::{avail, StorageValue, TransactionEventDecodable};
    use sp1_sdk::Prover;
    use sp1_sdk::{HashableKey, ProverClient, ProvingKey};

    #[test]
    fn vector_head_key_matches_twox_128_layout() {
        // twox_128("Vector") ++ twox_128("Head"), the key the operator built before avail-rust 0.5.
        assert_eq!(
            "0xd86645c10ec3a857c1f5d453ad1c130c05fe52c2045750c3c492ccdcf62e2b9c",
            VectorHead::hex_encode_storage_key()
        );
        assert_eq!(
            15392032,
            VectorHead::decode_hex_storage_value("0x20ddea0000000000").unwrap()
        );
    }

    #[test]
    fn fulfill_calls_encode_for_vector_pallet() {
        let fulfill = avail::vector::tx::Fulfill {
            proof: vec![1, 2, 3],
            public_values: vec![9],
        };
        // pallet 39, call 13, then the SCALE-encoded byte vectors
        assert_eq!(vec![39, 13, 12, 1, 2, 3, 4, 9], fulfill.to_call());

        let mock_fulfill = avail::vector::tx::MockFulfill {
            public_values: vec![9],
        };
        assert_eq!(vec![39, 17, 4, 9], mock_fulfill.to_call());
    }

    #[test]
    fn head_updated_decodes_mainnet_event() {
        // HeadUpdated emitted by the fulfill in Avail mainnet block 3567692.
        let event = "0x270020ddea00000000005dd6b2872bc7d935a4e8e57628afe782a72890425fb50afac130ac8a7028a2d79bb0f826eb1c50b63a331425cb336163823f156b600511e90080a1e7c6172d38";
        let head_updated = HeadUpdated::from_event(event).unwrap();

        assert_eq!(15392032, head_updated.slot);
        assert_eq!(
            "0x5dd6b2872bc7d935a4e8e57628afe782a72890425fb50afac130ac8a7028a2d7",
            format!("{:?}", head_updated.finalization_root)
        );
        assert_eq!(
            "0x9bb0f826eb1c50b63a331425cb336163823f156b600511e90080a1e7c6172d38",
            format!("{:?}", head_updated.execution_state_root)
        );
    }

    #[tokio::test]
    async fn test_program_verification_key() {
        let client = ProverClient::builder().cpu().build().await;
        let pk = client.setup(ELF.into()).await.unwrap();
        let vk = pk.verifying_key();

        assert_eq!(
            "0x00a45c84e8f97c5e821aaff9cf2fb0531fc1ecdaedc1e3228e473e8bf1bc9f0f",
            vk.bytes32()
        );
    }
}
