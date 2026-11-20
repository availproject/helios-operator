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
use std::backtrace::{Backtrace, BacktraceStatus};
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

/// Returns `text` with every URL cut down to its scheme and host.
///
/// A provider URL holds the API key in the path, in the query or in `user:password@`. `reqwest`
/// adds the request URL to its error text, and helios and avail-rust copy that text into their
/// own errors. So an error must pass through this function before it is logged or printed.
pub fn redact_urls(text: &str) -> String {
    const SCHEME_END: &str = "://";

    let mut redacted = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(SCHEME_END) {
        let (head, tail) = rest.split_at(index + SCHEME_END.len());
        redacted.push_str(head);
        rest = tail;

        // "://" with no scheme in front of it is not a URL.
        if !head[..index].ends_with(|c: char| c.is_ascii_alphanumeric()) {
            continue;
        }

        let url_len = rest.find(ends_url).unwrap_or(rest.len());
        let (url, tail) = rest.split_at(url_len);
        let authority_len = url.find(['/', '?', '#']).unwrap_or(url.len());
        let (authority, path) = url.split_at(authority_len);
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);

        redacted.push_str(host);
        redacted.push_str(if path.is_empty() || path == "/" {
            path
        } else {
            "/<redacted>"
        });
        rest = tail;
    }
    redacted.push_str(rest);

    redacted
}

/// Inside an error message a URL ends at whitespace, at a quote or at a closing bracket.
fn ends_url(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | '`')
}

/// Prints a panic the way the standard hook does, but with the URLs in its message redacted.
///
/// Many RPC failures end in `unwrap` or `expect`, and their messages can hold the provider URL.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        eprintln!("thread '{name}' {}", redact_urls(&panic_info.to_string()));

        // The backtrace is captured only when RUST_BACKTRACE asks for it.
        let backtrace = Backtrace::capture();
        if backtrace.status() == BacktraceStatus::Captured {
            eprintln!("stack backtrace:\n{backtrace}");
        }
    }));
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
        // The reqwest error text ends with the request URL, which holds the API key.
        .unwrap_or_else(|e| {
            panic!(
                "Cannot get beacon header at slot {slot}: {}",
                e.without_url()
            )
        });
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
        // The reqwest error text ends with the request URL, which holds the API key.
        .map_err(|e| {
            anyhow!(
                "Cannot get execution block {block_hash}: {}",
                e.without_url()
            )
        })?
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
mod redact_urls_tests {
    use super::redact_urls;

    #[test]
    fn removes_the_path_that_holds_the_api_key() {
        assert_eq!(
            redact_urls(
                "error sending request for url (https://lb.example.com/eth/SECRET/eth/v1/beacon/headers/7)"
            ),
            "error sending request for url (https://lb.example.com/<redacted>)"
        );
    }

    #[test]
    fn removes_the_query_and_the_credentials() {
        let cases = [
            (
                "https://rpc.example.com?apikey=SECRET",
                "https://rpc.example.com/<redacted>",
            ),
            (
                "https://rpc.example.com/v2?apikey=SECRET#top",
                "https://rpc.example.com/<redacted>",
            ),
            (
                "wss://user:SECRET@node.example.com:443/ws",
                "wss://node.example.com:443/<redacted>",
            ),
            ("http://user:SECRET@10.0.0.1:8545", "http://10.0.0.1:8545"),
            ("http://[::1]:8545/SECRET", "http://[::1]:8545/<redacted>"),
        ];
        for (text, want) in cases {
            assert_eq!(redact_urls(text), want, "input: {text}");
        }
    }

    #[test]
    fn keeps_the_text_around_every_url() {
        let cases = [
            (
                "first https://a.example.com/SECRET1 then http://b.example.com/SECRET2 → end",
                "first https://a.example.com/<redacted> then http://b.example.com/<redacted> → end",
            ),
            (
                r#"Error { url: "https://a.example.com/SECRET", kind: Request }"#,
                r#"Error { url: "https://a.example.com/<redacted>", kind: Request }"#,
            ),
            (
                "failed for 'https://a.example.com/SECRET'",
                "failed for 'https://a.example.com/<redacted>'",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(redact_urls(text), want, "input: {text}");
        }
    }

    #[test]
    fn leaves_text_without_a_secret_unchanged() {
        let cases = [
            "",
            "Head must exist",
            "status: 404, raw response: b\"NOT_FOUND\"",
            "connecting to https://rpc.example.com failed",
            "connecting to https://rpc.example.com/ failed",
            "not a url: a :// b and ://c",
        ];
        for text in cases {
            assert_eq!(redact_urls(text), text);
        }
    }
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
