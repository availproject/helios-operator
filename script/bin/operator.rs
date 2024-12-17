mod genesis;

use alloy::hex::ToHex;
/// Continuously generate proofs & keep light client updated with chain
use alloy::{hex, sol};
use anyhow::Result;
use avail::vector::events as VectorEvent;
use avail_rust::avail::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use avail_rust::sp_core::{twox_128, Decode};
use avail_rust::Block;
use avail_rust::{Keypair, SecretUri, H256, SDK};
use helios::consensus::rpc::ConsensusRpc;
use helios::consensus::{rpc::nimbus_rpc::NimbusRpc, Inner};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use sp1_helios_primitives::types::ProofInputs;
use sp1_helios_script::*;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin};
use ssz_rs::prelude::*;
use std::env;
use std::str::FromStr;
use tree_hash::TreeHash;

use anyhow::Context;
use tracing::info;

use avail_rust::avail_core::currency::AVAIL;
use avail_rust::{avail, transactions::Transaction, Nonce::BestBlockAndTxPool, Options};
use jsonrpsee::tracing::error;

const ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

struct SP1AvailLightClientOperator {
    client: ProverClient,
    avail_client: HttpClient,
    pk: SP1ProvingKey,
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1LightClient {
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

impl SP1AvailLightClientOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let avail_rpc = env::var("AVAIL_RPC").unwrap_or("http://127.0.0.1:9944/api".to_string());

        let client = ProverClient::new();
        let avail_client = HttpClientBuilder::default()
            .max_concurrent_requests(1024)
            .build(avail_rpc)
            .unwrap();
        let (pk, _) = client.setup(ELF);

        Self {
            client,
            avail_client,
            pk,
        }
    }

    /// Fetch values and generate an 'update' proof for the SP1 LightClient contract.
    async fn request_update(
        &mut self,
        mut client: Inner<NimbusRpc>,
    ) -> Result<Option<SP1ProofWithPublicValues>> {
        let head: u64 = self.get_head().await?;
        let slot_per_period = env::var("SLOTS_PER_PERIOD")
            .unwrap_or("8192".to_string())
            .parse::<u64>()?;
        info!("Head/Slot {}", head);

        let period = head / slot_per_period;
        let contract_next_sync_committee = self.get_sync_committee(period + 1).await?;

        let mut stdin = SP1Stdin::new();

        // Setup client.
        let mut updates = get_updates(&client).await;
        let finality_update = client.rpc.get_finality_update().await.unwrap();

        // Check if contract is up to date
        let latest_block = finality_update.finalized_header.beacon.slot;
        if latest_block <= head {
            info!("Contract is up to date. Nothing to update.");
            return Ok(None);
        }

        // Optimization:
        // Skip processing update inside program if next_sync_committee is already stored in contract.
        // We must still apply the update locally to "sync" the helios client, this is due to
        // next_sync_committee not being stored when the helios client is bootstrapped.
        if !updates.is_empty() {
            let next_sync_committee =
                H256::from_slice(updates[0].next_sync_committee.tree_hash_root().as_ref());

            if contract_next_sync_committee == next_sync_committee {
                info!("Applying optimization, skipping update");
                let temp_update = updates.remove(0);

                client.verify_update(&temp_update).unwrap(); // Panics if not valid
                client.apply_update(&temp_update);
            }
        }

        // Fetch execution state proof
        let execution_state_proof = get_execution_state_root_proof(latest_block).await.unwrap();

        // Create program inputs
        let expected_current_slot = client.expected_current_slot();
        let inputs = ProofInputs {
            updates,
            finality_update,
            expected_current_slot,
            store: client.store.clone(),
            genesis_root: client.config.chain.genesis_root,
            forks: client.config.forks.clone(),
            execution_state_proof,
        };
        let encoded_proof_inputs = serde_cbor::to_vec(&inputs)?;
        stdin.write_slice(&encoded_proof_inputs);

        // Generate proof.
        let proof = self.client.prove(&self.pk, stdin).groth16().run()?;

        info!("Attempting to update to new head block: {:?}", latest_block);
        Ok(Some(proof))
    }

    /// Relay the proof to Avail
    async fn relay_vector_update(&self, proof: SP1ProofWithPublicValues) -> Result<()> {
        let proof_as_bytes = if env::var("SP1_PROVER")?.to_lowercase() == "mock" {
            vec![]
        } else {
            proof.bytes()
        };

        let secret = env::var("AVAIL_SECRET").unwrap_or("//Alice".to_string());
        let avail_rpc = env::var("AVAIL_WS_RPC").unwrap_or("ws://127.0.0.1:9944".to_string());
        let secret_uri = SecretUri::from_str(secret.as_str())?;
        let account = Keypair::from_uri(&secret_uri)?;

        let proof_vec: BoundedVec<u8> = BoundedVec(proof_as_bytes);
        let pub_values_vec: BoundedVec<u8> = BoundedVec(proof.public_values.to_vec());

        let fulfill_call = avail::tx().vector().fulfill(proof_vec, pub_values_vec);
        let sdk = SDK::new(avail_rpc.as_str()).await.unwrap();

        let account_id = account.public_key().to_account_id();
        let storage_query = avail::storage().system().account(account_id);
        let best_block_hash = Block::fetch_best_block_hash(&sdk.rpc_client)
            .await
            .expect("Must fetch fetch_best_block_hash!");
        let storage = sdk.online_client.storage().at(best_block_hash);
        let result = storage.fetch(&storage_query).await?;
        if let Some(account) = result {
            info!(
                "token_amount" = account.data.free.checked_div(AVAIL),
                "nonce" = account.nonce,
                "Account info."
            );
        }

        let tx = Transaction::new(
            sdk.online_client.clone(),
            sdk.rpc_client.clone(),
            fulfill_call,
        );
        let options = Some(Options::new().nonce(BestBlockAndTxPool));
        let result = tx
            .execute_wait_for_finalization(&account, options)
            .await
            .expect("Transaction must be executed!");

        let head_updated = result.find_event::<VectorEvent::HeadUpdated>();

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
                    error!("Header range request failed: {}", e);
                }
            };

            info!("Sleeping for {:?} minutes", loop_delay_mins);
            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_delay_mins)).await;
        }
    }

    // Reads head from the Avail chain
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
            .context("Cannot parse head from Avail chain")?;

        let slot_from_hex = sp_core::bytes::from_hex(head_str.as_str()).context("decode slot")?;
        let slot: u64 = Decode::decode(&mut slot_from_hex.as_slice()).context("slot decode 2")?;
        Ok(slot)
    }

    async fn get_sync_committee(&mut self, period: u64) -> Result<H256> {
        let pallet = "Vector";
        let sync_committee_hash = "SyncCommitteeHashes";

        let finalized_block_hash_str: String = self
            .avail_client
            .request("chain_getFinalizedHead", rpc_params![])
            .await
            .expect("finalized head");

        let head_key = format!(
            "0x{}{}{}",
            hex::encode(twox_128(pallet.as_bytes())),
            hex::encode(twox_128(sync_committee_hash.as_bytes())),
            hex::encode(period.to_le_bytes())
        );

        info!("Period {}", period);

        let sync_committee_hash: String = self
            .avail_client
            .request(
                "state_getStorage",
                rpc_params![head_key, finalized_block_hash_str.clone()],
            )
            .await
            .unwrap_or(H256::zero().encode_hex());

        let sync_committee_hash = sp_core::bytes::from_hex(sync_committee_hash.as_str())
            .context("parse sync_committee_hash")?;
        let hash: H256 = Decode::decode(&mut sync_committee_hash.as_slice())
            .context("Decode sync_committee_hash")?;

        Ok(H256(hash.into()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let loop_delay_mins = env::var("LOOP_DELAY_MINS")
        .unwrap_or("5".to_string())
        .parse()?;

    let mut operator = SP1AvailLightClientOperator::new().await;
    loop {
        if let Err(e) = operator.run(loop_delay_mins).await {
            error!("Error running operator: {}", e);
            error!("Retrying: {}", e);
        }
    }
}
