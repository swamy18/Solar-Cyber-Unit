//! Service API integration tests ? roadmap items 16/17, Decision 9,
//! SPEC.md ?19.2.
//!
//! These drive the real server: [`srct_node::api::spawn`] binds a socket (port 0
//! in every test, so they never race for a fixed port) and the requests below
//! go over the wire as raw HTTP. Nothing here calls a handler directly, so a
//! routing, serialization or status-code mistake fails the test.
//!
//! What they pin:
//!
//! - the API is a *read/write view*, never a consensus surface: an L1
//!   broadcast takes the exact `pool.add` path a peer transaction takes, and
//!   an unsigned or badly-signed transaction is refused rather than mined;
//! - a payment cannot be recorded without verifying, and a re-submission is
//!   idempotent rather than a second payment;
//! - a receipt binds to its payment, and two contradicting receipts for one
//!   payment are refused by name (fail closed);
//! - authorization goes through the policy engine ? a replayed nonce is a
//!   refusal, not a second grant;
//! - malformed input is a client error (400/404), never a 500.
//!
//! Run with `cargo test -p srct-node --test api`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::agent::{
    derive_agent_id, derive_sub_agent_id, AgentRole, Authorization, PolicyBook, SpendPolicy,
    POLICY_VERSION,
};
use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::Chain;
use srct_core::compute_ir::{ComputeBackend, ComputeTask};
use srct_core::hash::{address_to_hex, hash512_to_hex, hash_to_hex};
use srct_core::l2::{Auth, ExitQueuePayload, L2Payload, L2Transaction, PostTaskPayload};
use srct_core::params::NetworkParams;
use srct_core::payment::{build_signed_payment, MachinePayment};
use srct_core::receipt::{sign_receipt, ReceiptAnchor, ServiceReceipt, RECEIPT_VERSION};
use srct_core::service::{
    authorize_request, build_signed_request, derive_service_id, result_hash_of, RequestSpec,
};
use srct_core::sig::Bundle;
use srct_core::tx::{Output, Transaction};
use srct_core::wallet::Wallet;
use srct_node::api::{spawn_with_options, SharedNode};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const NET: &str = "srct/mini";
const EXPIRES: u64 = 9_000;
/// The amount `run_bridge` opens a grant for ? the credit gate must cover this
/// for admission to succeed.
const BRIDGE_AMOUNT_SAT: u64 = 400;
/// The fee `run_bridge` builds its payment with. Admission reserves
/// `amount + fee`, so a funded line needs the total, not just the amount.
const BRIDGE_FEE_SAT: u64 = 2_000;
/// What the credit gate must cover for a bridge payment to be admitted.
const BRIDGE_TOTAL_SAT: u64 = BRIDGE_AMOUNT_SAT + BRIDGE_FEE_SAT;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Node {
    addr: SocketAddr,
    #[allow(dead_code)]
    shared: Arc<Mutex<SharedNode>>,
}

/// Start a server on an ephemeral loopback port over a fresh mini chain.
fn start() -> Node {
    start_with(Chain::new(NetworkParams::mini()).unwrap())
}

/// Start a server over a chain the caller has already mined.
fn start_with(chain: Chain) -> Node {
    start_with_issuers(chain, Vec::new())
}

/// Start a server over `chain` that trusts `issuers` to sign credit
/// attestations; empty issuers means every `/v1/credit/mint` is refused.
fn start_with_issuers(chain: Chain, issuers: Vec<srct_core::bls_checkpoint::BlsPublicKey>) -> Node {
    let params = NetworkParams::mini();
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn_with_options(
        Arc::clone(&shared),
        peers,
        "127.0.0.1:0".parse().unwrap(),
        None,
        Vec::new(),
        issuers,
    )
    .expect("the API must bind its loopback socket");
    Node { addr, shared }
}

/// A chain of `n` blocks paying their coinbase to `miner`, at exactly the mini
/// target spacing so difficulty stays pinned at 1 and mining is cheap. These
/// tests exercise state rules, not proof-of-work.
fn mine_to(params: &NetworkParams, miner: &Wallet, n: u64) -> Chain {
    let mut chain = Chain::new(params.clone()).unwrap();
    let addr = miner.address().unwrap();
    for h in 1..=n {
        let block = chain
            .mine_block(addr, vec![], GENESIS_TIMESTAMP_MS + h * 1_000)
            .unwrap();
        chain.submit(block).unwrap();
    }
    chain
}

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
}

/// A raw HTTP exchange over a fresh connection. `Connection: close` makes the
/// server close after the response, so `read_to_end` is the whole body.
fn http(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: close\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    exchange(addr, request.as_bytes())
}

fn exchange(addr: SocketAddr, request: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    // A refusal may arrive before the whole oversize body is written; that is
    // the server doing its job, not a test failure.
    let _ = stream.write_all(request);
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("body was not JSON ({e}): {text}"))
}

fn get(node: &Node, path: &str) -> (u16, Value) {
    let (status, body) = http(node.addr, "GET", path, None);
    (status, json(&body))
}

fn post(node: &Node, path: &str, body: &Value) -> (u16, Value) {
    let (status, text) = http(node.addr, "POST", path, Some(&body.to_string()));
    (status, json(&text))
}

/// Like `post`, but for a refusal body ? the server may emit an error JSON or a
/// bare string, so this keeps the raw text.
fn post_text(node: &Node, path: &str, body: &Value) -> (u16, String) {
    http(node.addr, "POST", path, Some(&body.to_string()))
}

/// The chain height the live node is at (used to re-verify a forked payment).
fn node_height(node: &Node) -> u64 {
    node.shared.lock().unwrap().chain.height()
}

// ---------------------------------------------------------------------------
// Read paths
// ---------------------------------------------------------------------------

#[test]
fn health_status_fees_and_finality_answer() {
    let node = start();

    let (s, health) = get(&node, "/v1/health");
    assert_eq!(s, 200);
    assert_eq!(health["status"], "ok");

    let (s, status) = get(&node, "/v1/status");
    assert_eq!(s, 200);
    assert_eq!(status["network"], "mini");
    assert_eq!(status["network_id"], NET);
    assert_eq!(status["height"], 0);
    assert_eq!(status["mempool_len"], 0);

    let (s, fees) = get(&node, "/v1/fees");
    assert_eq!(s, 200);
    assert_eq!(fees["gas_base"], 16_000);
    assert_eq!(fees["gas_per_input"], 1_000);
    assert_eq!(fees["gas_per_output"], 250);
    // The D3 L2 flat schedule is surfaced, not recomputed.
    assert!(fees["l2_fee_schedule"].as_array().unwrap().len() >= 5);

    let (s, finality) = get(&node, "/v1/finality");
    assert_eq!(s, 200);
    assert_eq!(finality["tip_height"], 0);

    let (s, latest) = get(&node, "/v1/block/latest");
    assert_eq!(s, 200);
    assert!(latest["hash"].as_str().unwrap().len() == 128);

    let (s, pool) = get(&node, "/v1/mempool");
    assert_eq!(s, 200);
    assert_eq!(pool["count"], 0);

    let (s, tasks) = get(&node, "/v1/tasks/open");
    assert_eq!(s, 200);
    assert_eq!(tasks["count"], 0);
}

#[test]
fn utxo_listing_pages_with_a_stable_cursor() {
    let params = NetworkParams::mini();
    let miner = wallet(71, "page-miner");
    // 15 coinbases, all listed: an immature output is still an unspent one,
    // `spendable` is just a flag on it.
    let chain = mine_to(&params, &miner, 15);
    let node = start_with(chain);
    let path = format!("/v1/utxo/{}", address_to_hex(&miner.address().unwrap()));

    // Default request: the whole list, as before the cursor existed.
    let (s, body) = get(&node, &path);
    assert_eq!(s, 200);
    assert_eq!(body["count"], 15);
    assert!(body["next_cursor"].is_null());
    assert_eq!(body["utxos"].as_array().unwrap().len(), 15);

    // Walk pages of 6 (6 + 6 + 3): `count` stays the total, every outpoint
    // appears exactly once, and the order is deterministic.
    let mut cursor = Some(0u64);
    let mut seen: Vec<(String, u64)> = Vec::new();
    for _ in 0..10 {
        let Some(c) = cursor else {
            break;
        };
        let (s, page) = get(&node, &format!("{path}?limit=6&cursor={c}"));
        assert_eq!(s, 200);
        assert_eq!(page["count"], 15, "count is the total, not the page");
        for u in page["utxos"].as_array().unwrap() {
            seen.push((
                u["txid"].as_str().unwrap().to_string(),
                u["index"].as_u64().unwrap(),
            ));
        }
        cursor = page["next_cursor"].as_u64();
    }
    assert!(cursor.is_none(), "the walk must end on a null next_cursor");
    assert_eq!(seen.len(), 15, "every output listed exactly once");
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]),
        "sorted across page boundaries, never overlapping"
    );

    // A cursor past the end is an empty page, not an error.
    let (s, past) = get(&node, &format!("{path}?limit=6&cursor=999"));
    assert_eq!(s, 200);
    assert_eq!(past["count"], 15);
    assert!(past["utxos"].as_array().unwrap().is_empty());
    assert!(past["next_cursor"].is_null());
}

#[test]
fn metrics_endpoint_serves_prometheus_gauges_in_the_exposition_format() {
    let node = start();
    // `http`/`exchange` deliberately strip the headers, so this test reads the
    // raw response: the content type *is* part of what must be correct.
    let mut stream = TcpStream::connect(node.addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();

    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(status, 200);
    let (headers, body) = text.split_once("\r\n\r\n").expect("headers then body");
    assert!(
        headers
            .to_lowercase()
            .contains("content-type: text/plain; version=0.0.4"),
        "metrics must advertise the Prometheus text content type, got:\n{headers}"
    );

    // At height 0 the ladder is grandfathered: the allowance is u64::MAX and
    // nothing is issued. Both gauges must carry exactly those live values,
    // which is what proves they came from the chain and not a constant.
    assert!(
        body.contains(&format!(
            "srct_rate_anchor_allowance_sat{{network=\"{NET}\"}} 18446744073709551615"
        )),
        "rate-anchor gauge missing or wrong:\n{body}"
    );
    assert!(
        body.contains(&format!("srct_issued_sat{{network=\"{NET}\"}} 0")),
        "issued gauge missing or wrong:\n{body}"
    );
    assert!(
        body.contains(&format!("srct_net_supply_sat{{network=\"{NET}\"}} 0")),
        "net-supply gauge missing or wrong:\n{body}"
    );
    assert!(
        body.contains(&format!("srct_height{{network=\"{NET}\"}} 0")),
        "height gauge missing:\n{body}"
    );
    assert!(
        body.contains("# TYPE srct_pscb_reserve_sat gauge"),
        "reserve gauge has no TYPE preamble:\n{body}"
    );

    // Every sample line must be exactly `name{labels} value` with an integer
    // value: one malformed line makes a real scraper drop the whole response.
    for line in body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 2, "not an exposition sample line: {line:?}");
        assert!(
            parts[1].parse::<u64>().is_ok(),
            "value is not an integer: {line:?}"
        );
        assert!(parts[0].contains('{'), "sample must be labelled: {line:?}");
    }
}

#[test]
fn an_unknown_balance_address_reads_zero_and_a_malformed_one_is_a_client_error() {
    let node = start();
    let addr = wallet(31, "reader").address().unwrap();

    let (s, body) = get(&node, &format!("/v1/balance/{}", address_to_hex(&addr)));
    assert_eq!(s, 200);
    assert_eq!(body["confirmed_sat"], 0);
    assert_eq!(body["spendable_sat"], 0);

    let (s, _) = get(&node, "/v1/balance/not-an-address");
    assert_eq!(s, 400, "a malformed address is the caller's error");

    let (s, body) = get(&node, &format!("/v1/utxo/{}", address_to_hex(&addr)));
    assert_eq!(s, 200);
    assert_eq!(body["utxos"].as_array().unwrap().len(), 0);
}

#[test]
fn unknown_hashes_are_404_never_500() {
    let node = start();
    let unknown = hash_to_hex(&[0xABu8; 32]);
    let unknown512 = hash512_to_hex(&[0xABu8; 64]);

    let (s, body) = get(&node, &format!("/v1/tx/{unknown512}"));
    assert_eq!(s, 404);
    assert_eq!(body["error"], "not_found");

    let (s, _) = get(&node, &format!("/v1/block/{unknown512}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/payment/{unknown}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/receipt/{unknown}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/task/{unknown}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/vwc/{unknown}"));
    assert_eq!(s, 404);

    // A hash that is not even the right shape is a client error, not a 404.
    let (s, _) = get(&node, "/v1/tx/deadbeef");
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// Reputation (derived, non-consensus)
// ---------------------------------------------------------------------------

#[test]
fn reputation_reads_zero_for_an_address_with_no_history() {
    let node = start();
    let addr = wallet(31, "reputee").address().unwrap();

    let (s, body) = get(&node, &format!("/v1/reputation/{}", address_to_hex(&addr)));
    assert_eq!(s, 200);
    assert_eq!(body["score"], 0);
    assert_eq!(body["events"], 0);
    assert_eq!(body["worker_address"], address_to_hex(&addr));
    let expected_agent = derive_agent_id(NET, AgentRole::Machine, &addr);
    assert_eq!(body["agent_id"], address_to_hex(&expected_agent));
}

#[test]
fn reputation_rejects_a_malformed_address() {
    let node = start();
    let (s, _) = get(&node, "/v1/reputation/not-an-address");
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// L1 transaction paths
// ---------------------------------------------------------------------------

#[test]
fn tx_build_refuses_an_unfunded_address_without_signing_anything() {
    let node = start();
    let from = wallet(41, "poor").address().unwrap();
    let to = wallet(42, "payee").address().unwrap();

    let (s, body) = post(
        &node,
        "/v1/tx/build",
        &serde_json::json!({
            "from": address_to_hex(&from),
            "to": address_to_hex(&to),
            "amount_sat": 1_000,
            "max_fee_sat": 1_000_000,
        }),
    );
    assert_eq!(s, 400);
    assert_eq!(body["error"], "insufficient_funds");
}

#[test]
fn a_local_transaction_is_built_signed_broadcast_then_looked_up() {
    let params = NetworkParams::mini();
    let miner = wallet(51, "api-miner");
    // 12 blocks leaves the coinbases at heights 1?3 mature (maturity 10).
    let chain = mine_to(&params, &miner, 12);
    let node = start_with(chain);

    let from = miner.address().unwrap();
    let to = wallet(52, "api-payee").address().unwrap();

    // The build returns *unsigned* bytes and never a signed transaction.
    let (s, built) = post(
        &node,
        "/v1/tx/build",
        &serde_json::json!({
            "from": address_to_hex(&from),
            "to": address_to_hex(&to),
            "amount_sat": 1_000_000,
            "max_fee_sat": 1_000_000,
        }),
    );
    assert_eq!(s, 200, "build failed: {built}");
    let fee = built["fee_sat"].as_u64().unwrap();
    assert!(fee > 0);
    let unsigned_hex = built["unsigned_tx_hex"].as_str().unwrap();

    // Broadcasting the unsigned bytes is refused: the API is not a way to put
    // a signature-less transaction into the pool.
    let (s, body) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": unsigned_hex }),
    );
    assert_eq!(s, 400, "an unsigned transaction must be refused");
    assert_eq!(body["error"], "tx_refused");

    // Sign it as the owner and broadcast the real thing.
    let mut tx = Transaction::deserialize(&hex::decode(unsigned_hex).unwrap()).unwrap();
    miner.sign(&mut tx).unwrap();
    let signed_hex = hex::encode(tx.serialize());

    let (s, body) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": signed_hex }),
    );
    assert_eq!(s, 200, "broadcast failed: {body}");
    let txid = body["tx_hash"].as_str().unwrap().to_string();
    assert_eq!(txid, hash512_to_hex(&tx.txid()));

    // It is pending, and a re-broadcast of the same bytes is idempotent.
    let (s, body) = get(&node, &format!("/v1/tx/{txid}"));
    assert_eq!(s, 200);
    assert_eq!(body["status"], "pending");

    let (s, body) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": signed_hex }),
    );
    assert_eq!(s, 200);
    assert_eq!(body["already_known"], true);

    let (s, pool) = get(&node, "/v1/mempool");
    assert_eq!(s, 200);
    assert_eq!(pool["count"], 1);
}

#[test]
fn mempool_pages_by_txid_with_count_as_the_total() {
    let params = NetworkParams::mini();
    let a = wallet(61, "page-a");
    let b = wallet(62, "page-b");
    // Alternate the coinbases between two wallets so each has its own mature
    // outputs: two broadcasts, two independent inputs, no shared coin to race
    // the coin selection on.
    let mut chain = Chain::new(params).unwrap();
    for h in 1..=15u64 {
        let m = if h % 2 == 0 { &b } else { &a };
        let block = chain
            .mine_block(
                m.address().unwrap(),
                vec![],
                GENESIS_TIMESTAMP_MS + h * 1_000,
            )
            .unwrap();
        chain.submit(block).unwrap();
    }
    let node = start_with(chain);
    for w in [&a, &b] {
        let from = w.address().unwrap();
        let (s, built) = post(
            &node,
            "/v1/tx/build",
            &serde_json::json!({
                "from": address_to_hex(&from),
                "to": address_to_hex(&from),
                "amount_sat": 1_000_000,
                "max_fee_sat": 1_000_000,
            }),
        );
        assert_eq!(s, 200, "build failed: {built}");
        let mut tx = Transaction::deserialize(
            &hex::decode(built["unsigned_tx_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        w.sign(&mut tx).unwrap();
        let (s, body) = post(
            &node,
            "/v1/tx/broadcast",
            &serde_json::json!({ "signed_tx_hex": hex::encode(tx.serialize()) }),
        );
        assert_eq!(s, 200, "broadcast failed: {body}");
    }

    // Page one at a time: `count` stays the total, the cursor walks each tx
    // exactly once, and the last page ends with a null `next_cursor`.
    let (s, p1) = get(&node, "/v1/mempool?limit=1");
    assert_eq!(s, 200);
    assert_eq!(p1["count"], 2, "count is the total, not the page");
    assert_eq!(p1["entries"].as_array().unwrap().len(), 1);
    let first = p1["entries"][0]["tx_hash"].as_str().unwrap().to_string();
    let next = p1["next_cursor"]
        .as_u64()
        .expect("a partial page must offer the next cursor");

    let (s, p2) = get(&node, &format!("/v1/mempool?limit=1&cursor={next}"));
    assert_eq!(s, 200);
    assert_eq!(p2["count"], 2);
    let entries = p2["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_ne!(
        entries[0]["tx_hash"].as_str().unwrap(),
        first,
        "the second page is the other transaction"
    );
    assert!(p2["next_cursor"].is_null(), "the last page ends the walk");
}

#[test]
fn garbage_bytes_are_a_client_error_not_a_panic() {
    let node = start();

    let (s, _) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": "not hex at all" }),
    );
    assert_eq!(s, 400);

    let (s, _) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": "deadbeef" }),
    );
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// Authorization ? payment ? receipt
// ---------------------------------------------------------------------------

fn machine_policy(owner: &Wallet, provider_addr: &[u8; 20], service: [u8; 32]) -> SpendPolicy {
    let owner_addr = owner.address().unwrap();
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner_addr),
        owner: owner_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![*provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    }
}

/// Submit a signed payment with the full authorization material the node now
/// requires. Returns the raw status + body so a refusal can be asserted on.
fn submit_payment(
    node: &Node,
    payment: &MachinePayment,
    auth: &Authorization,
    sigs: &Bundle,
    keys: &Bundle,
) -> (u16, Value) {
    post(
        node,
        "/v1/payment/submit",
        &serde_json::json!({
            "payment_hex": hex::encode(payment.serialize()),
            "authorization_hex": hex::encode(auth.serialize()),
            "auth_sigs_hex": hex::encode(sigs.to_bytes()),
            "auth_keys_hex": hex::encode(keys.to_bytes()),
        }),
    )
}

/// The full bridge, exercised through the API: policy + signed request are
/// POSTed, the returned authorization is decoded and used to build a payment,
/// the payment is submitted, and a receipt for it is recorded. Returns
/// everything a caller needs to (re)submit the payment.
///
/// `credit_deposit` seeds the payer's credit line so admission has something to
/// debit; pass 0 to leave it unfunded (for the credit-gate refusal test). The
/// bridge is non-consensus: credit is a balance in the book, not L1 coin.
fn run_bridge(
    node: &Node,
    credit_deposit: u64,
) -> (
    MachinePayment,
    ServiceReceipt,
    Authorization,
    Bundle,
    Bundle,
) {
    let payer = wallet(61, "api-payer");
    let payer_addr = payer.address().unwrap();
    let provider = wallet(62, "api-provider");
    let provider_addr = provider.address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"srct-llm");
    let policy = machine_policy(&payer, &provider_addr, service);

    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider_addr,
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();

    let (s, granted) = post(
        node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&payer, &policy),
            "policy_keys_hex": policy_keys_hex(&payer),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 1,
        }),
    );
    assert_eq!(s, 200, "authorize refused: {granted}");
    assert_eq!(granted["amount_sat"], 400);
    assert_eq!(granted["nonce"], 1);

    let auth_bytes = hex::decode(granted["authorization_hex"].as_str().unwrap()).unwrap();
    let auth = Authorization::deserialize(&auth_bytes).expect("authorization must decode");
    assert_eq!(hash_to_hex(&auth.signing_hash()), granted["signing_hash"]);

    let payment = build_signed_payment(
        &payer,
        &auth,
        NET,
        AgentRole::Machine,
        BRIDGE_FEE_SAT,
        EXPIRES,
        request.request_id(),
        &[],
    )
    .unwrap();

    let sigs = Auth::sigs_for(&payer, &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(&payer).unwrap();

    if credit_deposit > 0 {
        let (s, b) = post(
            node,
            "/v1/credit/deposit",
            &serde_json::json!({
                "address_hex": address_to_hex(&payer_addr),
                "amount_sat": credit_deposit,
            }),
        );
        assert_eq!(s, 200, "seeding the credit line failed: {b}");
    }

    let mut receipt = ServiceReceipt {
        version: RECEIPT_VERSION,
        network_id: NET.to_string(),
        payer: payment.payer,
        payer_role: payment.payer_type,
        agent_id: payment.agent_id,
        recipient: payment.recipient,
        service_id: payment.service,
        amount_sat: payment.amount_sat,
        payment_id: payment.signing_hash(),
        request_id: request.request_id(),
        result_hash: Some(result_hash_of(b"model-output-v1")),
        anchor: Some(ReceiptAnchor {
            height: 120,
            block_hash: [7u8; 64],
        }),
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut receipt, &provider).unwrap();
    receipt.verify_binding(&payment).unwrap();

    (payment, receipt, auth, sigs, keys)
}

#[test]
fn authorize_grants_then_refuses_a_replayed_nonce() {
    let node = start();
    let payer = wallet(71, "nonce-payer");
    let provider_addr = wallet(72, "nonce-provider").address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"svc");
    let policy = machine_policy(&payer, &provider_addr, service);
    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider_addr,
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();

    let body = serde_json::json!({
        "policy_hex": hex::encode(policy.serialize()),
        "policy_sigs_hex": policy_sigs_hex(&payer, &policy),
        "policy_keys_hex": policy_keys_hex(&payer),
        "request_hex": hex::encode(request.serialize()),
        "nonce": 7,
    });

    let (s, first) = post(&node, "/v1/authorize", &body);
    assert_eq!(s, 200, "first grant failed: {first}");

    // Same nonce again: the policy engine refuses a replay by name.
    let (s, body) = post(&node, "/v1/authorize", &body);
    assert_eq!(s, 409);
    assert_eq!(body["error"], "policy_refused");

    // A policy the request does not name is a binding failure, also refused.
    let other = machine_policy(&payer, &wallet(73, "other").address().unwrap(), [9u8; 32]);
    let body = serde_json::json!({
        "policy_hex": hex::encode(other.serialize()),
        "policy_sigs_hex": policy_sigs_hex(&payer, &other),
        "policy_keys_hex": policy_keys_hex(&payer),
        "request_hex": hex::encode(request.serialize()),
        "nonce": 8,
    });
    let (s, body) = post(&node, "/v1/authorize", &body);
    assert_eq!(s, 409);
    assert_eq!(body["error"], "session_binding");
}

/// Smart Gate over HTTP: an owner-signed grant registers, a capability bound
/// to the exact action and the node's own height authorizes once, a replayed
/// nonce is refused by name, and revocation kills the grant. This is the
/// Binance-October shape: a stolen token alone mints no valid capability, and
/// a revoked grant stays dead across the node's own books.
#[test]
fn guard_grant_authorize_replay_revoke_round_trip() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, Capability, InfraPolicy, SignedCapability,
        GUARD_POLICY_VERSION,
    };
    let node = start();
    let h = node_height(&node);
    let owner = wallet(77, "guard-owner");
    let owner_addr = owner.address().unwrap();
    let policy = InfraPolicy {
        version: GUARD_POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner_addr),
        owner: owner_addr,
        max_calls_per_window: 5,
        window_blocks: 100,
        valid_from_height: 0,
        valid_until_height: 10_000,
        revoked: false,
        parent_agent_id: None,
        requires_approval: false,
        approver: [0u8; 20],
        workload_id: [0u8; 32],
        workload_key: [0u8; 32],
    };
    let (s, granted) = post(
        &node,
        "/v1/guard/grant",
        &serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": hex::encode(Auth::sigs_for(&owner, &policy.signing_hash()).unwrap().to_bytes()),
            "policy_keys_hex": hex::encode(Auth::keys_for(&owner).unwrap().to_bytes()),
        }),
    );
    assert_eq!(s, 200, "owner-signed grant registers: {granted}");
    assert_eq!(granted["policy_hash"], hash_to_hex(&policy.hash()));

    let workload = [2u8; 32];
    let preimage = b"deploy-42";
    let action = derive_action_hash(preimage);
    let signed_cap_hex = |nonce: u64| {
        let cap = Capability {
            policy_hash: policy.hash(),
            action_hash: action,
            context_hash: derive_context_hash(&workload, h),
            expiry_height: h + 10,
            nonce,
            audience: [0u8; 32],
        };
        hex::encode(SignedCapability::issue(&owner, &cap).unwrap().serialize())
    };
    let authorize = |cap_hex: &str| {
        post(
            &node,
            "/v1/guard/authorize",
            &serde_json::json!({
                "cap_hex": cap_hex,
                "agent_id_hex": hex::encode(policy.agent_id),
                "action_hash_hex": hash_to_hex(&action),
                "action_preimage_hex": hex::encode(preimage),
                "workload_id_hex": hash_to_hex(&workload),
            }),
        )
    };
    // An unsigned capability any observer could write down is refused outright.
    let raw = Capability {
        policy_hash: policy.hash(),
        action_hash: action,
        context_hash: derive_context_hash(&workload, h),
        expiry_height: h + 10,
        nonce: 9,
        audience: [0u8; 32],
    };
    let (s, forged) = post(
        &node,
        "/v1/guard/authorize",
        &serde_json::json!({
            "cap_hex": hex::encode(raw.serialize()),
            "agent_id_hex": hex::encode(policy.agent_id),
            "action_preimage_hex": hex::encode(preimage),
            "workload_id_hex": hash_to_hex(&workload),
        }),
    );
    assert!(
        s == 400 || forged["decision"] == "deny",
        "unsigned cap refused: {forged}"
    );
    // A swapped preimage (authorized deploy-42, executing deploy-43) is denied.
    let (s, swapped) = post(
        &node,
        "/v1/guard/authorize",
        &serde_json::json!({
            "cap_hex": signed_cap_hex(7),
            "agent_id_hex": hex::encode(policy.agent_id),
            "action_preimage_hex": hex::encode(b"deploy-43"),
            "workload_id_hex": hash_to_hex(&workload),
        }),
    );
    assert_eq!(s, 200, "{swapped}");
    assert_eq!(swapped["decision"], "deny");
    let (s, first) = authorize(&signed_cap_hex(1));
    assert_eq!(s, 200, "{first}");
    assert_eq!(first["decision"], "allow");

    // Replay: the same nonce again is a named deny, not a second admission.
    let (s, replay) = authorize(&signed_cap_hex(1));
    assert_eq!(s, 200, "{replay}");
    assert_eq!(replay["decision"], "deny");

    // Revoke via the owner's signed revoked variant.
    let mut revoked = policy.clone();
    revoked.revoked = true;
    let (s, body) = post(
        &node,
        "/v1/guard/revoke",
        &serde_json::json!({
            "policy_hex": hex::encode(revoked.serialize()),
            "sigs_hex": hex::encode(Auth::sigs_for(&owner, &revoked.signing_hash()).unwrap().to_bytes()),
            "keys_hex": hex::encode(Auth::keys_for(&owner).unwrap().to_bytes()),
        }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["revoked"], true);

    // The live grant is dead: even a fresh nonce is refused by name.
    let (s, dead) = authorize(&signed_cap_hex(2));
    assert_eq!(s, 200, "{dead}");
    assert_eq!(dead["decision"], "deny");
    assert_eq!(dead["reason"], "grant revoked");
}

#[test]
fn guard_owner_set_risk_and_independent_approver_are_enforced() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, Capability, GuardApproval, InfraPolicy,
        SignedCapability, GUARD_POLICY_VERSION,
    };
    let node = start();
    let h = node_height(&node);
    let owner = wallet(78, "guard-owner-ha");
    let approver = wallet(79, "guard-approver-ha");
    let owner_addr = owner.address().unwrap();
    let agent_id = derive_agent_id(NET, AgentRole::Machine, &owner_addr);
    let bound = [8u8; 32];
    let assured = InfraPolicy {
        version: GUARD_POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id,
        owner: owner_addr,
        max_calls_per_window: 5,
        window_blocks: 100,
        valid_from_height: 0,
        valid_until_height: 10_000,
        revoked: false,
        parent_agent_id: None,
        requires_approval: true,
        approver: approver.address().unwrap(),
        workload_id: bound,
        workload_key: [0u8; 32],
    };
    let grant = |policy: &InfraPolicy, signer: &Wallet| {
        post(
            &node,
            "/v1/guard/grant",
            &serde_json::json!({
                "policy_hex": hex::encode(policy.serialize()),
                "policy_sigs_hex": hex::encode(Auth::sigs_for(signer, &policy.signing_hash()).unwrap().to_bytes()),
                "policy_keys_hex": hex::encode(Auth::keys_for(signer).unwrap().to_bytes()),
            }),
        )
    };
    // A high-assurance grant that names the owner as approver is refused at
    // registration: no silent downgrade to self-approval.
    let mut self_approved = assured.clone();
    self_approved.approver = owner_addr;
    let (s, body) = grant(&self_approved, &owner);
    assert_eq!(s, 400, "owner-as-approver must not register: {body}");

    let (s, granted) = grant(&assured, &owner);
    assert_eq!(s, 200, "independent-approver grant registers: {granted}");

    let preimage = b"deploy-42";
    let action = derive_action_hash(preimage);
    let signed_hex = |nonce: u64| {
        let cap = Capability {
            policy_hash: assured.hash(),
            action_hash: action,
            context_hash: derive_context_hash(&bound, h),
            expiry_height: h + 10,
            nonce,
            audience: [0u8; 32],
        };
        hex::encode(SignedCapability::issue(&owner, &cap).unwrap().serialize())
    };
    let decide = |cap_hex: &str, high_risk: bool| {
        post(
            &node,
            "/v1/guard/decide",
            &serde_json::json!({
                "policy_hex": hex::encode(assured.serialize()),
                "cap_hex": cap_hex,
                "agent_id_hex": hex::encode(agent_id),
                "action_hash_hex": hash_to_hex(&action),
                "workload_id_hex": hash_to_hex(&bound),
                "high_risk": high_risk,
            }),
        )
    };
    // Caller claims low risk; the grant disagrees: gated both ways.
    for flag in [false, true] {
        let (s, out) = decide(&signed_hex(11), flag);
        assert_eq!(s, 200, "{out}");
        assert_eq!(out["decision"], "needs_approval");
    }
    // Stateful admission without an approval gates too.
    let (s, gated) = post(
        &node,
        "/v1/guard/authorize",
        &serde_json::json!({
            "cap_hex": signed_hex(12),
            "agent_id_hex": hex::encode(agent_id),
            "action_preimage_hex": hex::encode(preimage),
            "workload_id_hex": hash_to_hex(&bound),
            "high_risk": false,
        }),
    );
    assert_eq!(s, 200, "{gated}");
    assert_eq!(gated["decision"], "needs_approval");

    // The designated approver's signed approval admits (presented workload id
    // is ignored: the grant is bound, so even a spoofed id gates the same).
    let approval_for = |nonce: u64, signer: &Wallet| {
        let cap = Capability {
            policy_hash: assured.hash(),
            action_hash: action,
            context_hash: derive_context_hash(&bound, h),
            expiry_height: h + 10,
            nonce,
            audience: [0u8; 32],
        };
        let draft = GuardApproval {
            version: GUARD_POLICY_VERSION,
            policy_hash: assured.hash(),
            cap_hash: cap.signing_hash(),
            agent_id,
            action_hash: action,
            context_hash: derive_context_hash(&bound, h),
            expiry_height: h + 5,
            sigs: srct_core::sig::Bundle::default(),
            keys: srct_core::sig::Bundle::default(),
        };
        GuardApproval {
            sigs: Auth::sigs_for(signer, &draft.signing_hash()).unwrap(),
            keys: Auth::keys_for(signer).unwrap(),
            ..draft
        }
    };
    let (s, allowed) = post(
        &node,
        "/v1/guard/authorize",
        &serde_json::json!({
            "cap_hex": signed_hex(13),
            "agent_id_hex": hex::encode(agent_id),
            "action_preimage_hex": hex::encode(preimage),
            "action_hash_hex": hash_to_hex(&action),
            "workload_id_hex": hash_to_hex(&[9u8; 32]),
            "high_risk": false,
            "approval_hex": hex::encode(approval_for(13, &approver).serialize()),
        }),
    );
    assert_eq!(s, 200, "{allowed}");
    assert_eq!(allowed["decision"], "allow");

    // The owner's own signature is not an approval here: only the designated
    // approver counts.
    let (s, denied) = post(
        &node,
        "/v1/guard/authorize",
        &serde_json::json!({
            "cap_hex": signed_hex(14),
            "agent_id_hex": hex::encode(agent_id),
            "action_preimage_hex": hex::encode(preimage),
            "workload_id_hex": hash_to_hex(&bound),
            "high_risk": false,
            "approval_hex": hex::encode(approval_for(14, &owner).serialize()),
        }),
    );
    assert_eq!(s, 200, "{denied}");
    assert_eq!(denied["decision"], "deny");
}

#[test]
fn guard_keybound_grant_requires_workload_credential_over_http() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, workload_key_fingerprint, Capability, InfraPolicy,
        SignedCapability, WorkloadCredential, GUARD_POLICY_VERSION,
    };
    let node = start();
    let h = node_height(&node);
    let owner = wallet(80, "guard-owner-kb");
    let workload_wallet = wallet(81, "guard-workload-kb");
    let workload_keys = srct_core::l2::Auth::keys_for(&workload_wallet).unwrap();
    let owner_addr = owner.address().unwrap();
    let agent_id = derive_agent_id(NET, AgentRole::Machine, &owner_addr);
    let presented = [2u8; 32];
    let policy = InfraPolicy {
        version: GUARD_POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id,
        owner: owner_addr,
        max_calls_per_window: 5,
        window_blocks: 100,
        valid_from_height: 0,
        valid_until_height: 10_000,
        revoked: false,
        parent_agent_id: None,
        requires_approval: false,
        approver: [0u8; 20],
        workload_id: [0u8; 32],
        workload_key: workload_key_fingerprint(&workload_keys),
    };
    let (s, granted) = post(
        &node,
        "/v1/guard/grant",
        &serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": hex::encode(Auth::sigs_for(&owner, &policy.signing_hash()).unwrap().to_bytes()),
            "policy_keys_hex": hex::encode(Auth::keys_for(&owner).unwrap().to_bytes()),
        }),
    );
    assert_eq!(s, 200, "{granted}");
    let preimage = b"kb-job-1";
    let action = derive_action_hash(preimage);
    let ctx = derive_context_hash(&presented, h);
    let cap = Capability {
        policy_hash: policy.hash(),
        action_hash: action,
        context_hash: ctx,
        expiry_height: h + 10,
        nonce: 1,
        audience: [0u8; 32],
    };
    let signed_hex = hex::encode(SignedCapability::issue(&owner, &cap).unwrap().serialize());
    let authorize = |cred_hex: Option<String>| {
        post(
            &node,
            "/v1/guard/authorize",
            &serde_json::json!({
                "cap_hex": signed_hex,
                "agent_id_hex": hex::encode(agent_id),
                "action_preimage_hex": hex::encode(preimage),
                "workload_id_hex": hash_to_hex(&presented),
                "workload_cred_hex": cred_hex,
            }),
        )
    };
    // No proof: deny. The grant names a key, and no key proved itself.
    let (s, out) = authorize(None);
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "deny");
    // Stranger's proof: deny.
    let stranger = wallet(82, "guard-stranger-kb");
    let fake =
        WorkloadCredential::issue(&stranger, &policy.hash(), &cap, &action, &ctx, h).unwrap();
    let (s, out) = authorize(Some(hex::encode(fake.serialize())));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "deny");
    // Honest proof for this exact admission: allow.
    let cred = WorkloadCredential::issue(&workload_wallet, &policy.hash(), &cap, &action, &ctx, h)
        .unwrap();
    let (s, out) = authorize(Some(hex::encode(cred.serialize())));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "allow");
    // The worker synchronizes on this height: it is the authoritative height
    // the admission committed at, and the only height local verification
    // may run at.
    assert_eq!(out["height"], h, "node must report its admission height");
}
/// `POST /v1/policy/decide` answers the engine without committing: allow for
/// a fitting intent, a named refusal for a forbidden one, approval-needed
/// above the threshold. Deciding twice decides twice identically — the route
/// is pure, so no nonce is consumed and no window spend is recorded.
#[test]
fn policy_decide_answers_without_committing() {
    let node = start();
    let payer = wallet(1, "payer");
    let provider = [7u8; 20];
    let service = [9u8; 32];
    let policy = machine_policy(&payer, &provider, service);
    let base = || {
        serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&payer, &policy),
            "policy_keys_hex": policy_keys_hex(&payer),
            "agent_id_hex": hex::encode(policy.agent_id),
            "recipient_hex": hex::encode(provider),
            "service_hex": hex::encode(service),
        })
    };
    // A fitting intent is allowed, against the node's own network/height.
    let mut allow = base();
    allow["amount_sat"] = serde_json::json!(400);
    let (s, out) = post(&node, "/v1/policy/decide", &allow);
    assert_eq!(s, 200, "a fitting intent must be allowed: {out}");
    assert_eq!(out["decision"], "allow");
    assert_eq!(out["network_id"], NET);
    // Deciding again decides the same: nothing was committed.
    let (s, again) = post(&node, "/v1/policy/decide", &allow);
    assert_eq!(s, 200, "{again}");
    assert_eq!(again, out);
    // Over the per-tx cap is a deny with the reason, not a transport
    // failure: the query was answered, and the answer is no.
    let mut over = base();
    over["amount_sat"] = serde_json::json!(50_000);
    let (s, body) = post(&node, "/v1/policy/decide", &over);
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["decision"], "deny");
    // Above the threshold the spend is gated, not refused.
    let mut gated = base();
    gated["amount_sat"] = serde_json::json!(400);
    gated["approval_threshold_sat"] = serde_json::json!(100);
    let (s, out) = post(&node, "/v1/policy/decide", &gated);
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "needs_approval");
    // The portable shape decides the same grant, verified on parse.
    let signed = srct_core::portable::SignedPolicy::issue(&payer, &policy).expect("owner signs");
    let (s, out) = post(
        &node,
        "/v1/policy/decide",
        &serde_json::json!({
            "policy_portable_json": signed.to_json(),
            "agent_id_hex": hex::encode(policy.agent_id),
            "recipient_hex": hex::encode(provider),
            "service_hex": hex::encode(service),
            "amount_sat": 400,
        }),
    );
    assert_eq!(s, 200, "portable shape must decide identically: {out}");
    assert_eq!(out["decision"], "allow");
    // A policy retargeted at another network breaks its own agent-id
    // binding: structurally invalid, refused at parse.
    let mut foreign = policy.clone();
    foreign.network_id = "srct/elsewhere".to_string();
    let (s, body) = post(
        &node,
        "/v1/policy/decide",
        &serde_json::json!({
            "policy_hex": hex::encode(foreign.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&payer, &foreign),
            "policy_keys_hex": policy_keys_hex(&payer),
            "agent_id_hex": hex::encode(foreign.agent_id),
            "recipient_hex": hex::encode(provider),
            "service_hex": hex::encode(service),
            "amount_sat": 400,
        }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "bad_request");
    // A structurally valid policy for another network reaches the node and
    // is refused there by name: this node is not its network.
    let owner_addr = payer.address().unwrap();
    let mut testnet_policy = machine_policy(&payer, &provider, service);
    testnet_policy.network_id = "srct/testnet".to_string();
    testnet_policy.agent_id = derive_agent_id("srct/testnet", AgentRole::Machine, &owner_addr);
    let (s, body) = post(
        &node,
        "/v1/policy/decide",
        &serde_json::json!({
            "policy_hex": hex::encode(testnet_policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&payer, &testnet_policy),
            "policy_keys_hex": policy_keys_hex(&payer),
            "agent_id_hex": hex::encode(testnet_policy.agent_id),
            "recipient_hex": hex::encode(provider),
            "service_hex": hex::encode(service),
            "amount_sat": 400,
        }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["decision"], "deny");
}

/// `POST /v1/delegation/verify` and `/v1/audit/verify` check foreign
/// documents the same way every other verifier does: a proof that parses
/// but does not verify, and an audit chain with rewritten history, are
/// refused by name.
#[test]
fn delegation_verify_and_audit_verify_answer_from_any_rail() {
    use srct_core::portable::{DelegationProof, SignedPolicy};
    use srct_core::safety::AuditLog;

    let node = start();
    let owner = wallet(60, "proof-owner");
    let root = machine_policy(&owner, &[1u8; 20], [2u8; 32]);
    let child = SpendPolicy {
        agent_id: derive_sub_agent_id(NET, &root.agent_id, AgentRole::Machine),
        parent_agent_id: Some(root.agent_id),
        per_tx_max_sat: 300,
        window_blocks: 5,
        cumulative_max_sat: 500,
        not_before_height: 0,
        expires_at_height: 5_000,
        ..root.clone()
    };
    let proof = DelegationProof::new(vec![
        SignedPolicy::issue(&owner, &root).expect("owner signs"),
        SignedPolicy::issue(&owner, &child).expect("owner signs"),
    ])
    .expect("narrowed ancestry proves");
    let (s, out) = post(
        &node,
        "/v1/delegation/verify",
        &serde_json::json!({ "proof_json": proof.to_json() }),
    );
    assert_eq!(s, 200, "a valid ancestry verifies: {out}");
    assert_eq!(out["valid"], true);
    assert_eq!(out["depth"], 2);
    // A widened leaf keeps signatures but breaks the narrowing rule.
    let mut wide = child.clone();
    wide.cumulative_max_sat = 9_999;
    let bad_proof = DelegationProof::new(vec![
        SignedPolicy::issue(&owner, &root).expect("owner signs"),
        SignedPolicy::issue(&owner, &wide).expect("owner signs"),
    ])
    .expect("assembly does not verify");
    let (s, body) = post(
        &node,
        "/v1/delegation/verify",
        &serde_json::json!({ "proof_json": bad_proof.to_json() }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "bad_request");

    let mut log = AuditLog::default();
    log.push("authorize", None, Some(500), "grant".to_string())
        .unwrap();
    log.push("payment", Some([1u8; 32]), Some(500), "submit".to_string())
        .unwrap();
    let (s, out) = post(
        &node,
        "/v1/audit/verify",
        &serde_json::json!({ "audit_json": log.export_json() }),
    );
    assert_eq!(s, 200, "a chained export verifies: {out}");
    assert_eq!(out, serde_json::json!({ "valid": true, "entries": 2 }));
    let mut tampered = log.export();
    tampered.entries[0].detail = "forged".to_string();
    let (s, body) = post(
        &node,
        "/v1/audit/verify",
        &serde_json::json!({ "audit_json": serde_json::to_string(&tampered).unwrap() }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "bad_request");
}

#[test]
fn a_malformed_policy_is_a_client_error() {
    let node = start();
    let (s, body) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": "0011",
            "request_hex": "0011",
            "nonce": 1,
        }),
    );
    assert_eq!(s, 400);
    assert_eq!(body["error"], "bad_request");
}

#[test]
fn a_verified_payment_is_recorded_once_and_readable() {
    let node = start();
    let (payment, _receipt, auth, sigs, keys) = run_bridge(&node, BRIDGE_TOTAL_SAT);

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200, "payment refused: {body}");
    assert_eq!(body["duplicate"], false);
    let id = body["payment_id"].as_str().unwrap().to_string();
    assert_eq!(id, hash_to_hex(&payment.signing_hash()));

    // The exact same payment is idempotent, not a second payment.
    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200);
    assert_eq!(body["duplicate"], true);

    let (s, body) = get(&node, &format!("/v1/payment/{id}"));
    assert_eq!(s, 200);
    assert_eq!(body["amount_sat"], 400);
    assert_eq!(body["network_id"], NET);
}

#[test]
fn a_payment_for_another_network_is_refused() {
    let node = start();
    let payer = wallet(81, "foreign");
    let provider = wallet(82, "provider").address().unwrap();
    let service = derive_service_id("srct/testnet", &provider, b"svc");
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: "srct/testnet".to_string(),
        agent_id: derive_agent_id(
            "srct/testnet",
            AgentRole::Machine,
            &payer.address().unwrap(),
        ),
        owner: payer.address().unwrap(),
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![provider],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    let mut book = PolicyBook::default();
    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: "srct/testnet".to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider,
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();
    let auth = authorize_request(&mut book, &policy, "srct/testnet", &request, 0, 1).unwrap();
    let payment = build_signed_payment(
        &payer,
        &auth,
        "srct/testnet",
        AgentRole::Machine,
        2_000,
        EXPIRES,
        request.request_id(),
        &[],
    )
    .unwrap();
    let sigs = Auth::sigs_for(&payer, &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(&payer).unwrap();

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    // The policy was never issued under on this (mini) node, so admission
    // refuses it as an unknown policy before the network binding is consulted.
    assert_eq!(s, 409);
    assert_eq!(body["error"], "payment_refused");
}

#[test]
fn a_receipt_records_once_and_a_contradicting_one_is_refused() {
    let node = start();
    let (payment, receipt, auth, sigs, keys) = run_bridge(&node, BRIDGE_TOTAL_SAT);

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200, "{body}");

    let receipt_hex = hex::encode(receipt.serialize());
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": receipt_hex }),
    );
    assert_eq!(s, 200, "receipt refused: {body}");
    assert_eq!(body["outcome"], "inserted");
    let receipt_id = body["receipt_id"].as_str().unwrap().to_string();

    // The same receipt is idempotent.
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": receipt_hex }),
    );
    assert_eq!(s, 200);
    assert_eq!(body["outcome"], "duplicate");

    // A *different* receipt claiming the same payment is refused by name.
    let provider = wallet(62, "api-provider");
    let mut forged = receipt.clone();
    forged.result_hash = Some(result_hash_of(b"a-different-outcome"));
    sign_receipt(&mut forged, &provider).unwrap();
    assert_ne!(forged.receipt_id(), receipt.receipt_id());
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": hex::encode(forged.serialize()) }),
    );
    assert_eq!(s, 409);
    assert_eq!(body["error"], "receipt_conflict");

    // Lookup by receipt id, and by the payment id it claims.
    let (s, body) = get(&node, &format!("/v1/receipt/{receipt_id}"));
    assert_eq!(s, 200);
    assert_eq!(body["amount_sat"], 400);
    let payment_id = hash_to_hex(&payment.signing_hash());
    let (s, body) = get(&node, &format!("/v1/receipt/{payment_id}"));
    assert_eq!(s, 200);
    assert_eq!(body["payment_id"], payment_id);
}

#[test]
fn a_payment_without_its_authorization_is_refused() {
    let node = start();
    let (payment, _receipt, _auth, _sigs, _keys) = run_bridge(&node, 0);
    // Omitting the authorization material makes the request body malformed to
    // the new handler ? a missing required field is 422, and crucially the
    // payment is never recorded.
    let (s, _body) = post_text(
        &node,
        "/v1/payment/submit",
        &serde_json::json!({ "payment_hex": hex::encode(payment.serialize()) }),
    );
    assert_eq!(
        s, 422,
        "a payment without its authorization must be refused"
    );
    let (s, body) = get(
        &node,
        &format!("/v1/payment/{}", hash_to_hex(&payment.signing_hash())),
    );
    assert_eq!(s, 404, "the refused payment must not be recorded");
    let _ = body;
}

#[test]
fn a_payment_whose_policy_the_node_never_authorized_is_refused() {
    // The gap this closes, end-to-end: a payment that names a policy hash the
    // node has never issued under is refused, even though its payer signature
    // is otherwise valid. The policy hash is no longer a decorative field.
    let node = start();
    let (mut payment, _receipt, auth, sigs, keys) = run_bridge(&node, BRIDGE_AMOUNT_SAT);

    // The payment was built under the bridge's policy, so it is otherwise valid;
    // we only change the hash it names, and re-sign so verify still passes.
    payment.policy_hash = [9u8; 32];
    payment.sigs = Auth::sigs_for(&wallet(61, "api-payer"), &payment.signing_hash()).unwrap();
    payment.keys = Auth::keys_for(&wallet(61, "api-payer")).unwrap();
    payment.verify(NET, node_height(&node)).unwrap();

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(
        s, 409,
        "an unknown policy must be refused, not recorded: {body}"
    );
    assert_eq!(body["error"], "payment_refused");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("never authorized under on this node"));
}

#[test]
fn a_payment_whose_authorization_is_forged_is_refused() {
    let node = start();
    let (payment, _receipt, auth, _sigs, _keys) = run_bridge(&node, BRIDGE_AMOUNT_SAT);

    // The authorization is authentic, but its signature material is supplied by
    // someone else's key: the owner never granted this spend.
    let forger = wallet(99, "forger");
    let sigs = Auth::sigs_for(&forger, &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(&forger).unwrap();

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 400, "a forged authorization must be refused");
    assert_eq!(body["error"], "bad_request");
}

#[test]
fn a_payment_is_admitted_only_when_the_payers_credit_covers_it() {
    // Item 4 wiring: admission is gated on the payer's credit line. A payment
    // that names a valid policy and authorization is refused when the payer has
    // too little credit, and admitted once the line covers it. The coin itself
    // does not move at admission ? this is consensus-neutral bookkeeping.
    let node = start();
    let (payment, _receipt, auth, sigs, keys) = run_bridge(&node, 0);
    let payer_addr = wallet(61, "api-payer").address().unwrap();
    assert_eq!(payment.amount_sat, 400);

    // Funding short: 300 < amount + fee -> refused before the tracker sees it.
    let (s, b) = post(
        &node,
        "/v1/credit/deposit",
        &serde_json::json!({
            "address_hex": address_to_hex(&payer_addr),
            "amount_sat": 300,
        }),
    );
    assert_eq!(s, 200, "deposit refused: {b}");
    assert_eq!(b["balance"], 300);

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 400, "underfunded credit must refuse, not record: {body}");
    assert_eq!(body["error"], "bad_request");

    // Top up so the line covers amount + fee, then the same payment is admitted.
    let (s, b) = post(
        &node,
        "/v1/credit/deposit",
        &serde_json::json!({
            "address_hex": address_to_hex(&payer_addr),
            "amount_sat": BRIDGE_TOTAL_SAT - 300,
        }),
    );
    assert_eq!(s, 200, "top-up refused: {b}");
    assert_eq!(b["balance"], BRIDGE_TOTAL_SAT);

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200, "funded credit must admit: {body}");
    assert_eq!(body["duplicate"], false);
}

#[test]
fn a_settled_receipt_commits_the_credit_debit() {
    // Admission encumbers the payer's line but does not move coins. Receipt
    // acceptance is the settlement event (?19.4): that is when the credit debit
    // commits, so the encumbrance moves to settled and the spendable line is
    // already down.
    let node = start();
    let (payment, receipt, auth, sigs, keys) = run_bridge(&node, BRIDGE_TOTAL_SAT);
    let payer_addr = wallet(61, "api-payer").address().unwrap();
    let balance_path = format!("/v1/credit/balance/{}", address_to_hex(&payer_addr));

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200, "{body}");

    // Admission is an encumbrance, not a debit: spendable capacity is gone, but
    // the value has not been settled. The reservation covers amount + fee.
    let (s, b) = get(&node, &balance_path);
    assert_eq!(s, 200);
    assert_eq!(
        b["reserved"], BRIDGE_TOTAL_SAT,
        "the reservation encumbers the line at admission"
    );
    assert_eq!(b["available"], 0, "so the capacity is exact, not advisory");

    // Accepting the receipt settles the reservation ? the debit commits.
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": hex::encode(receipt.serialize()) }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["outcome"], "inserted");

    let (s, b) = get(&node, &balance_path);
    assert_eq!(s, 200);
    assert_eq!(b["reserved"], 0, "the encumbrance was consumed");
    assert_eq!(
        b["free_balance"], 0,
        "settlement debited the reserved amount"
    );

    // A replayed receipt is idempotent: it settles nothing a second time.
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": hex::encode(receipt.serialize()) }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["outcome"], "duplicate");
    let (s, b) = get(&node, &balance_path);
    assert_eq!(s, 200);
    assert_eq!(b["reserved"], 0);
}

#[test]
fn a_reserved_line_cannot_back_two_admitted_payments() {
    // The over-reservation defect, at the node: one deposit funds exactly one
    // payment. A second payment naming the same balance is refused by the
    // capacity check rather than admitted against value already promised.
    let node = start();
    let (payment, receipt, auth, sigs, keys) = run_bridge(&node, BRIDGE_TOTAL_SAT);
    let payer_addr = wallet(61, "api-payer").address().unwrap();

    // Fund the line with exactly one payment's worth (amount + fee).
    let (s, body) = post(
        &node,
        "/v1/credit/deposit",
        &serde_json::json!({
            "address_hex": address_to_hex(&payer_addr),
            "amount_sat": BRIDGE_TOTAL_SAT,
        }),
    );
    assert_eq!(s, 200, "{body}");

    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200, "{body}");
    // The receipt settles the reservation, which is what actually consumes the
    // line.
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": hex::encode(receipt.serialize()) }),
    );
    assert_eq!(s, 200, "{body}");

    // A second, independently built payment from the same payer now has no
    // capacity behind it: the line was encumbered and then settled.
    let node2 = start();
    let (payment2, _receipt2, auth2, sigs2, keys2) = run_bridge(&node2, BRIDGE_TOTAL_SAT);
    let payer2 = wallet(61, "api-payer").address().unwrap();
    let (s, _b) = post(
        &node2,
        "/v1/credit/deposit",
        &serde_json::json!({
            "address_hex": address_to_hex(&payer2),
            "amount_sat": BRIDGE_TOTAL_SAT,
        }),
    );
    assert_eq!(s, 200);
    let (s, body) = submit_payment(&node2, &payment2, &auth2, &sigs2, &keys2);
    assert_eq!(s, 200, "{body}");
    // Second payment, same line: admission must refuse.
    let (s, body) = submit_payment(&node2, &payment2, &auth2, &sigs2, &keys2);
    assert_eq!(
        s, 200,
        "an exact re-submission is idempotent, not a second debit"
    );
    assert_eq!(body["duplicate"], true);
}

#[test]
fn a_position_backed_payment_is_refused_up_front_not_locked_forever() {
    // A reservation that draws on position headroom can never settle through
    // a receipt, and the node exposes no release for an admitted payment ? so
    // admission must refuse it up front rather than lock the payer's line
    // forever with no recourse.
    let node = start();
    let (payment, _receipt, auth, sigs, keys) = run_bridge(&node, 0);
    let payer_addr = wallet(61, "api-payer").address().unwrap();
    let addr_hex = address_to_hex(&payer_addr);
    assert_eq!(payment.amount_sat, 400);

    // Deposit exactly bond + collateral, leaving zero free: the 400-payment
    // would have to draw on the position's headroom.
    let (s, b) = post(
        &node,
        "/v1/credit/deposit",
        &json!({ "address_hex": addr_hex, "amount_sat": 5_000u64 }),
    );
    assert_eq!(s, 200, "{b}");
    let (s, b) = post(
        &node,
        "/v1/credit/bond",
        &json!({ "address_hex": addr_hex, "action": "post", "amount_sat": 1_000u64 }),
    );
    assert_eq!(s, 200, "{b}");
    let spec = srct_core::credit::PositionSpec {
        terms: srct_core::credit::CreditTerms::default(),
        charge: srct_core::credit::ChargeSchedule {
            rate_bps_per_window: 0,
            window_blocks: 100,
        },
        borrower: payer_addr,
        agent_id: [9u8; 32],
        lender: [2u8; 20],
        amount_sat: 5_000,
        bond_sat: 1_000,
        drawn_at_height: 0,
        deadline_height: 100,
    };
    let (s, b) = post(
        &node,
        "/v1/credit/open",
        &json!({ "spec_hex": hex::encode(spec.encode()) }),
    );
    assert_eq!(s, 200, "{b}");

    // Free is now 0, so admission would draw headroom ? refused, not stuck.
    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 409, "position-backed admission must fail fast: {body}");
    assert_eq!(body["error"], "payment_refused");

    // The refusal released the encumbrance: nothing reserved, nothing wedged.
    let (s, b) = get(&node, &format!("/v1/credit/balance/{addr_hex}"));
    assert_eq!(s, 200);
    assert_eq!(b["reserved"], 0, "the refused admission holds nothing");
    assert_eq!(b["available"], 0);

    // And the payer is not wedged: funding free (amount + fee) admits the same payment.
    let (s, b) = post(
        &node,
        "/v1/credit/deposit",
        &serde_json::json!({ "address_hex": addr_hex, "amount_sat": BRIDGE_TOTAL_SAT }),
    );
    assert_eq!(s, 200, "{b}");
    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200, "funded free balance admits: {body}");
    assert_eq!(body["duplicate"], false);
}

#[test]
fn the_credit_lifecycle_runs_through_the_node() {
    // Item 2 end to end over the node surface: deposit, post a bond, open a
    // position priced with it, and watch the pledge make the bond single-use.
    let node = start();
    let borrower = wallet(91, "borrower").address().unwrap();
    let addr_hex = address_to_hex(&borrower);

    let post = |path: &str, body: serde_json::Value| post(&node, path, &body);
    let (s, b) = post(
        "/v1/credit/deposit",
        json!({ "address_hex": addr_hex, "amount_sat": 2_300_000u64 }),
    );
    assert_eq!(s, 200, "{b}");
    let (s, b) = post(
        "/v1/credit/bond",
        json!({ "address_hex": addr_hex, "action": "post", "amount_sat": 50_000u64 }),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["bond"], 50_000);
    assert_eq!(b["bond_unpledged"], 50_000);

    // A position priced with the posted bond opens.
    let spec = srct_core::credit::PositionSpec {
        terms: srct_core::credit::CreditTerms::default(),
        charge: srct_core::credit::ChargeSchedule {
            rate_bps_per_window: 1_000,
            window_blocks: 100,
        },
        borrower,
        agent_id: [9u8; 32],
        lender: [2u8; 20],
        amount_sat: 1_000_000,
        bond_sat: 50_000,
        drawn_at_height: 0,
        deadline_height: 100,
    };
    let (s, b) = post(
        "/v1/credit/open",
        json!({ "spec_hex": hex::encode(spec.encode()) }),
    );
    assert_eq!(s, 200, "{b}");
    let position_id = b["position_id"].as_str().unwrap().to_string();

    // The bond is now pledged, so a second position cannot price against it.
    let (s, b) = get(&node, &format!("/v1/credit/balance/{addr_hex}"));
    assert_eq!(s, 200);
    assert_eq!(b["bond_pledged"], 50_000, "the bond is single-use");
    let second = srct_core::credit::PositionSpec {
        deadline_height: 200,
        ..spec.clone()
    };
    let (s, _b) = post(
        "/v1/credit/open",
        json!({ "spec_hex": hex::encode(second.encode()) }),
    );
    assert_eq!(s, 409, "one bond cannot secure two obligations");

    // Repaying frees the pledge, and a third position can then use the bond.
    // No charge window has elapsed at this height, so the debt is exactly the
    // principal.
    let (s, _b) = post(
        "/v1/credit/deposit",
        json!({ "address_hex": addr_hex, "amount_sat": 1_100_000u64 }),
    );
    assert_eq!(s, 200);
    let (s, b) = post(
        "/v1/credit/repay",
        json!({ "position_id": position_id, "amount_sat": 1_000_000u64 }),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["remaining_debt_sat"], 0);
    let (s, b) = get(&node, &format!("/v1/credit/balance/{addr_hex}"));
    assert_eq!(s, 200);
    assert_eq!(
        b["bond_pledged"], 0,
        "the settled position released its pledge"
    );

    let third = srct_core::credit::PositionSpec {
        deadline_height: 300,
        ..spec.clone()
    };
    let (s, _b) = post(
        "/v1/credit/open",
        json!({ "spec_hex": hex::encode(third.encode()) }),
    );
    assert_eq!(s, 200, "the bond is free again");
}

#[test]
fn zero_amount_credit_requests_are_refused_not_a_node_kill() {
    // The whole-node crash, pinned end to end: a zero-amount bond request for
    // an address the book has never seen used to walk past both guards (a
    // missing entry reads as `0`) and panic on a `get_mut` unwrap ? which, with
    // `panic = "abort"`, is every API request from then on failing to connect.
    let node = start();
    let stranger = wallet(93, "stranger").address().unwrap();
    let addr_hex = address_to_hex(&stranger);

    for action in ["post", "release"] {
        let (s, b) = post(
            &node,
            "/v1/credit/bond",
            &json!({ "address_hex": addr_hex, "action": action, "amount_sat": 0u64 }),
        );
        assert_eq!(s, 400, "{action} of zero must be a client error: {b}");
        assert_eq!(b["error"], "bad_request");
    }

    // The node is still serving after each refusal.
    let (s, _b) = get(&node, "/v1/health");
    assert_eq!(s, 200, "a refused request must not take the node down");

    // A zero repayment is refused by the same rule.
    let (s, b) = post(
        &node,
        "/v1/credit/repay",
        &json!({ "position_id": hash_to_hex(&[0u8; 32]), "amount_sat": 0u64 }),
    );
    assert_eq!(s, 400, "{b}");
    let (s, _b) = get(&node, "/v1/health");
    assert_eq!(s, 200);
}

// ---------------------------------------------------------------------------
// L2 broadcast (dry-run only ? state changes only via canonical replay)
// ---------------------------------------------------------------------------

fn post_payload(seed: u8) -> L2Transaction {
    let w = wallet(seed, "l2-poster");
    let task = ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 1_000_000,
        expiry_height: 1_000,
        submit_height: 1,
    };
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, 1, 5_000_000, 1_000, task).unwrap(),
    ))
}

#[test]
fn l2_broadcast_queues_a_funded_payload_and_refuses_an_unfunded_one() {
    let node = start();

    // Seed 1 holds a mini genesis grant, so its post passes the dry-run.
    let funded = post_payload(1);
    let (s, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex::encode(funded.serialize()) }),
    );
    assert_eq!(s, 200, "funded post refused: {body}");
    assert_eq!(body["queued"], true);

    // Re-queuing the same txid reports it rather than duplicating the queue.
    let (s, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex::encode(funded.serialize()) }),
    );
    assert_eq!(s, 200);
    assert_eq!(body["already_queued"], true);

    // Seed 9 holds no grant: the dry-run names the refusal instead of queueing.
    let unfunded = post_payload(9);
    let (s, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex::encode(unfunded.serialize()) }),
    );
    assert_eq!(s, 409);
    assert_eq!(body["error"], "l2_refused");

    // Malformed bytes never reach the dry-run.
    let (s, _) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": "zzzz" }),
    );
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[test]
fn an_oversize_body_is_refused_before_it_is_parsed() {
    let node = start();
    // One byte past the 5 MiB cap.
    let body = "x".repeat(5 * 1024 * 1024 + 1);
    let (status, _) = http(
        node.addr,
        "POST",
        "/v1/tx/broadcast",
        Some(&format!(r#"{{"signed_tx_hex":"{body}"}}"#)),
    );
    assert!(
        status == 413 || status == 400,
        "an oversize body must be refused, got {status}"
    );
}

/// An unsupported withdrawal is refused **explicitly** at the API, not
/// silently ignored.
///
/// There is no L2 withdrawal transaction type (`srct-l2/tests/exit_unavailable.rs`
/// proves the wire admits exactly the defined set), so the withdrawal-shaped
/// envelope below is the closest thing to a withdrawal request the API can
/// receive. It must be a clean 400 that names the problem ? never a 500, a
/// panic, or a value that gets queued for inclusion in a block.
#[test]
fn a_withdrawal_shaped_l2_payload_is_refused_by_name() {
    let node = start();

    // Version 1 envelope, type byte 0x1D — the byte immediately after the
    // highest defined L2 type (0x1C CreditDefault), which is where a withdrawal
    // would sit if one existed.
    let mut envelope = vec![1u8, 0, 0, 0, 0x1D];
    envelope.extend_from_slice(&[0u8; 32]);
    let hex_body = hex::encode(&envelope);

    let (status, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex_body }),
    );
    assert_eq!(status, 400, "a client error, never a 500: {body}");
    assert_eq!(body["error"], "bad_request");
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("unknown L2 transaction type"),
        "the refusal must name the problem, got {detail:?}"
    );

    // The refusal left nothing behind: no task, no queued transaction.
    let (s, open) = get(&node, "/v1/tasks/open");
    assert_eq!(s, 200);
    assert_eq!(open["count"], 0);
    let (s, status_json) = get(&node, "/v1/status");
    assert_eq!(s, 200);
    assert_eq!(status_json["height"], 0, "no block was mined");
    assert_eq!(status_json["l2"]["applied"], 0);
}

/// The same refusal through the CLI's own decode path, so a withdrawal attempt
/// is rejected identically whether it arrives over HTTP or from a local tool.
#[test]
fn an_undefined_l2_type_byte_is_refused_by_the_decoder() {
    let mut envelope = vec![1u8, 0, 0, 0];
    envelope.push(0x1D);
    envelope.extend_from_slice(&[0u8; 32]);
    let err = srct_core::l2::L2Transaction::deserialize(&envelope)
        .expect_err("0x1D is not an L2 transaction type");
    assert!(err.to_string().contains("unknown L2 transaction type"));
    // And the boundary is exact: the highest real type decodes, the next byte
    // does not.
    assert!(srct_core::l2::L2TxType::from_wire(0x1C).is_ok());
    assert!(srct_core::l2::L2TxType::from_wire(0x1D).is_err());
}

// ---------------------------------------------------------------------------
// Item 4: conditional escrow with contract-selected arbitrators.
// These exercise the HTTP API end-to-end: open, authorize via arbiter, refuse
// a non-designated signer, and accept a mutual release. The node only records
// the state machine here ? no coins move through this path.
// ---------------------------------------------------------------------------
use srct_core::bls::SecretKey as BlsSecretKey;
use srct_core::bls_checkpoint::BlsSignature;
use srct_core::escrow::{ConditionalEscrow, EscrowVerdict};

#[test]
fn escrow_open_records_then_refuses_an_unauthorized_arbiter_release_and_accepts_a_authorized_one() {
    let node = start();

    // A contract-selected arbitrator: the escrow binds this key at open time.
    let arb_sk = BlsSecretKey::derive(&[5u8; 32]).unwrap();
    let arb_pk = arb_sk.public_key();
    // Parties also carry BLS keys so mutual release is bound to them.
    let payer_sk = BlsSecretKey::derive(&[7u8; 32]).unwrap();
    let payer_pk = payer_sk.public_key();
    let payee_sk = BlsSecretKey::derive(&[8u8; 32]).unwrap();
    let payee_pk = payee_sk.public_key();

    let payer_addr = wallet(61, "escrow-payer").address().unwrap();
    let payee_addr = wallet(62, "escrow-payee").address().unwrap();

    let body = serde_json::json!({
        "network_id": "srct/test",
        "payer": address_to_hex(&payer_addr),
        "payer_bls": hex::encode(payer_pk.0),
        "payee": address_to_hex(&payee_addr),
        "payee_bls": hex::encode(payee_pk.0),
        "arbitrator": hex::encode(arb_pk.0),
        "amount_sat": 1_000,
        "nonce": 1,
    });
    let (s, b) = post(&node, "/v1/escrow/open", &body);
    assert_eq!(s, 200, "open refused: {b}");
    let id_hex = b["escrow_id"].as_str().unwrap();

    // Reconstruct the escrow purely to compute the exact release-signing hash
    // the node will check. The hash is a pure function of the open fields (the
    // open height only starts the refund timeout, so any height works here).
    let e = ConditionalEscrow::open(
        "srct/test".to_string(),
        payer_addr,
        payer_pk,
        payee_addr,
        payee_pk,
        arb_pk,
        1_000,
        1,
        0,
    )
    .unwrap();
    let release_hash = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);

    // A non-arbiter tries to release with a bogus signature -> refused 409,
    // fail-closed (state stays open).
    let rogue = BlsSecretKey::derive(&[9u8; 32]).unwrap();
    let bogus_sig = rogue.sign(&release_hash);
    let (s, b) = post(
        &node,
        &format!("/v1/escrow/{id_hex}/release"),
        &serde_json::json!({
            "mode": "arbiter",
            "arbiter_sig_hex": hex::encode(bogus_sig.0),
        }),
    );
    assert_eq!(s, 409, "a non-designated arbiter must be refused: {b}");
    assert_eq!(b["error"], "escrow_refused");

    // The designated arbitrator releases -> 200, state becomes released_arbiter.
    let good_sig = arb_sk.sign(&release_hash);
    let (s, b) = post(
        &node,
        &format!("/v1/escrow/{id_hex}/release"),
        &serde_json::json!({
            "mode": "arbiter",
            "arbiter_sig_hex": hex::encode(good_sig.0),
        }),
    );
    assert_eq!(
        s, 200,
        "the designated arbiter must be able to release: {b}"
    );
    assert_eq!(b["state"], "released_arbiter");

    // A second release on the already-released escrow is refused (not open).
    let (s, b) = post(
        &node,
        &format!("/v1/escrow/{id_hex}/release"),
        &serde_json::json!({
            "mode": "arbiter",
            "arbiter_sig_hex": hex::encode(good_sig.0),
        }),
    );
    assert_eq!(s, 409, "a decided escrow must not be releasable: {b}");

    // GET reflects the new state. Under mini's depth-only finality
    // (`finality_activation_height = 0`) a released escrow is also mature, so the
    // GET path's `advance_escrow_finality` commits it to Finalized.
    let (s, b) = get(&node, &format!("/v1/escrow/{id_hex}"));
    assert_eq!(s, 200);
    assert_eq!(b["state"], "finalized");
    assert_eq!(b["amount_sat"], 1_000);
}

#[test]
fn a_mutual_release_is_accepted_when_both_parties_sign_and_refused_when_one_is_missing() {
    let node = start();
    let arb_sk = BlsSecretKey::derive(&[5u8; 32]).unwrap();
    let arb_pk = arb_sk.public_key();
    let payer_sk = BlsSecretKey::derive(&[7u8; 32]).unwrap();
    let payer_pk = payer_sk.public_key();
    let payee_sk = BlsSecretKey::derive(&[8u8; 32]).unwrap();
    let payee_pk = payee_sk.public_key();
    let payer_addr = wallet(63, "m-payer").address().unwrap();
    let payee_addr = wallet(64, "m-payee").address().unwrap();

    let body = serde_json::json!({
        "network_id": "srct/test",
        "payer": address_to_hex(&payer_addr),
        "payer_bls": hex::encode(payer_pk.0),
        "payee": address_to_hex(&payee_addr),
        "payee_bls": hex::encode(payee_pk.0),
        "arbitrator": hex::encode(arb_pk.0),
        "amount_sat": 1_000,
        "nonce": 2,
    });
    let (s, b) = post(&node, "/v1/escrow/open", &body);
    assert_eq!(s, 200, "open refused: {b}");
    let id_hex = b["escrow_id"].as_str().unwrap();

    let e = ConditionalEscrow::open(
        "srct/test".to_string(),
        payer_addr,
        payer_pk,
        payee_addr,
        payee_pk,
        arb_pk,
        1_000,
        2,
        0,
    )
    .unwrap();
    let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);

    // Only the payer signed -> refused (arity is fine, but the payee sig fails
    // the pairing).
    let (s, b) = post(
        &node,
        &format!("/v1/escrow/{id_hex}/release"),
        &serde_json::json!({
            "mode": "mutual",
            "mutual_sigs_hex": [
                hex::encode(payer_sk.sign(&msg).0),
                hex::encode(BlsSignature([0u8; 96]).0),
            ],
        }),
    );
    assert_eq!(s, 409, "a one-sided signature must be refused: {b}");

    // Both parties sign -> accepted.
    let (s, b) = post(
        &node,
        &format!("/v1/escrow/{id_hex}/release"),
        &serde_json::json!({
            "mode": "mutual",
            "mutual_sigs_hex": [
                hex::encode(payer_sk.sign(&msg).0),
                hex::encode(payee_sk.sign(&msg).0),
            ],
        }),
    );
    assert_eq!(s, 200, "a genuine mutual release must verify: {b}");
    assert_eq!(b["state"], "released_mutual");
}

#[test]
fn escrow_open_rejects_a_zero_arbitrator_key_and_non_party_payer_key() {
    let node = start();
    let payer_sk = BlsSecretKey::derive(&[7u8; 32]).unwrap();
    let payer_pk = payer_sk.public_key();
    let payer_addr = wallet(65, "z-payer").address().unwrap();
    let payee_addr = wallet(66, "z-payee").address().unwrap();

    let (s, b) = post(
        &node,
        "/v1/escrow/open",
        &serde_json::json!({
            "network_id": "srct/test",
            "payer": address_to_hex(&payer_addr),
            "payer_bls": hex::encode(payer_pk.0),
            "payee": address_to_hex(&payee_addr),
            // payee_bls intentionally zero -> must be refused.
            "payee_bls": hex::encode([0u8; 48]),
            "arbitrator": hex::encode([0u8; 48]),
            "amount_sat": 1_000,
            "nonce": 1,
        }),
    );
    assert_eq!(s, 400, "a zero key must be refused: {b}");
    assert_eq!(b["error"], "escrow_refused");
}

#[test]
fn an_unknown_escrow_id_is_404_never_500() {
    let node = start();
    let (s, b) = post(
        &node,
        "/v1/escrow/0000000000000000000000000000000000000000000000000000000000000000/release",
        &serde_json::json!({ "mode": "arbiter", "arbiter_sig_hex": hex::encode([0u8; 96]) }),
    );
    assert_eq!(s, 404, "a missing escrow must 404, not 500: {b}");
}

#[test]
fn a_released_escrow_advances_to_finalized_under_finality() {
    // The GET path and each serve-loop tick call `advance_escrow_finality`, so a
    // released escrow whose release has aged out of the finality window must read
    // as `finalized` ? the ledger-only Finalized commit (Item 10 / ?19.4) ?
    // without any additional client call. We drive the node state directly to
    // isolate that transition from the (BLS-heavy) release-verification path,
    // which the prior test already covers end-to-end.
    use srct_core::escrow::EscrowState;

    let node = start();
    let payer_addr = wallet(61, "escrow-payer").address().unwrap();
    let payee_addr = wallet(62, "escrow-payee").address().unwrap();
    let arb_pk = BlsSecretKey::derive(&[5u8; 32]).unwrap().public_key();
    let payer_pk = BlsSecretKey::derive(&[7u8; 32]).unwrap().public_key();
    let payee_pk = BlsSecretKey::derive(&[8u8; 32]).unwrap().public_key();

    let e = ConditionalEscrow::open(
        NET.to_string(),
        payer_addr,
        payer_pk,
        payee_addr,
        payee_pk,
        arb_pk,
        1_000,
        1,
        0,
    )
    .unwrap();
    let id = e.id();
    {
        let mut sh = node.shared.lock().unwrap();
        sh.escrows.insert(id, e);
        assert!(matches!(
            sh.escrows.get(&id).unwrap().state,
            EscrowState::Open
        ));
    }

    // Open reads as `open`.
    let (s, b) = get(&node, &format!("/v1/escrow/{}", hash_to_hex(&id)));
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["state"], "open");

    // Release the escrow in ledger state, then advance finality. The mini
    // network sets `finality_activation_height = 0` for mainnet-equivalent
    // finality, so a release commits to Finalized at its own height.
    {
        let mut sh = node.shared.lock().unwrap();
        let h = sh.chain.height();
        let esc = sh.escrows.get_mut(&id).unwrap();
        esc.state = EscrowState::ReleasedArbiter { at_height: h };
        sh.advance_escrow_finality();
        assert!(
            matches!(
                sh.escrows.get(&id).unwrap().state,
                EscrowState::Finalized { .. }
            ),
            "matured release must finalize"
        );
    }

    // The GET reflects Finalized without the caller driving it.
    let (s, b) = get(&node, &format!("/v1/escrow/{}", hash_to_hex(&id)));
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["state"], "finalized");
    assert_eq!(b["amount_sat"], 1_000);
}

/// The owner's signature over a policy's `signing_hash`, as a hex bundle.
///
/// The node refuses a policy its owner did not sign, so every caller presents
/// real signature material rather than just the rules.
fn policy_sigs_hex(owner: &Wallet, policy: &SpendPolicy) -> String {
    use srct_core::l2::Auth;
    hex::encode(
        Auth::sigs_for(owner, &policy.signing_hash())
            .unwrap()
            .to_bytes(),
    )
}

fn policy_keys_hex(owner: &Wallet) -> String {
    use srct_core::l2::Auth;
    hex::encode(Auth::keys_for(owner).unwrap().to_bytes())
}

fn parent_policy() -> (Wallet, SpendPolicy) {
    // A wide-enough root that a narrowed child is meaningfully dominated.
    let owner = wallet(50, "deleg-parent");
    let owner_addr = owner.address().unwrap();
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner_addr),
        owner: owner_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: 1_000,
        window_blocks: 100,
        cumulative_max_sat: 5_000,
        allowed_recipients: vec![[1u8; 20], [2u8; 20]],
        allowed_services: vec![[4u8; 32], [5u8; 32]],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    (owner, policy)
}

fn child_of(parent: &SpendPolicy) -> SpendPolicy {
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: parent.network_id.clone(),
        agent_id: derive_sub_agent_id(NET, &parent.agent_id, parent.role),
        owner: parent.owner,
        role: parent.role,
        per_tx_max_sat: parent.per_tx_max_sat / 2,
        window_blocks: parent.window_blocks / 2,
        cumulative_max_sat: parent.cumulative_max_sat / 2,
        allowed_recipients: parent.allowed_recipients[..1].to_vec(),
        allowed_services: parent.allowed_services[..1].to_vec(),
        not_before_height: parent.not_before_height,
        expires_at_height: parent.expires_at_height,
        revoked: false,
        parent_agent_id: Some(parent.agent_id),
    }
}

#[test]
fn a_dominated_delegation_link_is_registered_and_a_widening_one_is_refused() {
    let node = start();
    let (owner, parent) = parent_policy();
    let child = child_of(&parent);

    // A properly narrowed child links, records depth 1, and the child policy is
    // reachable through the node's policy registry for later admission.
    let (s, b) = post(
        &node,
        "/v1/delegation/link",
        &serde_json::json!({
            "parent_policy_hex": hex::encode(parent.serialize()),
            "parent_sigs_hex": policy_sigs_hex(&owner, &parent),
            "parent_keys_hex": policy_keys_hex(&owner),
            "child_policy_hex": hex::encode(child.serialize()),
            "child_sigs_hex": policy_sigs_hex(&owner, &child),
            "child_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 200, "narrowed link refused: {b}");
    assert_eq!(b["linked"], true);
    assert_eq!(b["depth"], 1);

    // Re-linking the identical (parent, child) pair is refused as AlreadyLinked:
    // the book ? not the client ? is the authority on lineage, and a child may
    // not acquire a second ancestry.
    let (s, b) = post(
        &node,
        "/v1/delegation/link",
        &serde_json::json!({
            "parent_policy_hex": hex::encode(parent.serialize()),
            "parent_sigs_hex": policy_sigs_hex(&owner, &parent),
            "parent_keys_hex": policy_keys_hex(&owner),
            "child_policy_hex": hex::encode(child.serialize()),
            "child_sigs_hex": policy_sigs_hex(&owner, &child),
            "child_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 409, "re-linking an existing child must be refused: {b}");
    assert_eq!(b["error"], "delegation_refused");

    // A widening child (cumulative cap larger than the parent's) is refused by
    // the domination rule on the exact clause it breaks.
    let mut widened = child_of(&parent);
    widened.cumulative_max_sat = parent.cumulative_max_sat + 1;
    let (s, b) = post(
        &node,
        "/v1/delegation/link",
        &serde_json::json!({
            "parent_policy_hex": hex::encode(parent.serialize()),
            "parent_sigs_hex": policy_sigs_hex(&owner, &parent),
            "parent_keys_hex": policy_keys_hex(&owner),
            "child_policy_hex": hex::encode(widened.serialize()),
            "child_sigs_hex": policy_sigs_hex(&owner, &widened),
            "child_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 409, "a widening delegation must be refused: {b}");
    assert_eq!(b["error"], "delegation_refused");

    // A cross-network child is refused as a client error (network scoping is
    // checked before the domination rule), never as a conflict.
    let foreign_net = "srct/other".to_string();
    let mut foreign = child_of(&parent);
    foreign.network_id = foreign_net.clone();
    // Re-derive on the foreign network so the policy still decodes (deserialize
    // re-derives agent_id from network + parent + role); the cross-network check
    // below is what rejects it, not an encoding error.
    foreign.agent_id = derive_sub_agent_id(&foreign_net, &parent.agent_id, foreign.role);
    let (s, b) = post(
        &node,
        "/v1/delegation/link",
        &serde_json::json!({
            "parent_policy_hex": hex::encode(parent.serialize()),
            "parent_sigs_hex": policy_sigs_hex(&owner, &parent),
            "parent_keys_hex": policy_keys_hex(&owner),
            "child_policy_hex": hex::encode(foreign.serialize()),
            "child_sigs_hex": policy_sigs_hex(&owner, &foreign),
            "child_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 400, "cross-network delegation must be refused: {b}");
    assert_eq!(b["error"], "delegation_refused");
}
fn grandchild_of(parent: &SpendPolicy, child: &SpendPolicy) -> SpendPolicy {
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: child.network_id.clone(),
        agent_id: derive_sub_agent_id(NET, &child.agent_id, child.role),
        owner: child.owner,
        role: child.role,
        per_tx_max_sat: parent.per_tx_max_sat / 4,
        window_blocks: parent.window_blocks / 4,
        cumulative_max_sat: parent.cumulative_max_sat / 4,
        allowed_recipients: vec![parent.allowed_recipients[0]],
        allowed_services: vec![parent.allowed_services[0]],
        not_before_height: parent.not_before_height,
        expires_at_height: parent.expires_at_height,
        revoked: false,
        parent_agent_id: Some(child.agent_id),
    }
}

#[test]
fn an_unsigned_policy_is_refused_before_any_authority_is_granted() {
    // A policy *is* authority: caps, recipients, validity window. A route that
    // accepts it without the owner's signature lets anyone mint authority for
    // anyone else, which is the widening a chain exists to stop, one step
    // earlier.
    let node = start();
    let payer = wallet(71, "unsigned-payer");
    let provider = wallet(72, "unsigned-provider").address().unwrap();
    let service = derive_service_id(NET, &provider, b"svc");
    let policy = machine_policy(&payer, &provider, service);
    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider,
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();

    let (s, body) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 1,
        }),
    );
    assert_eq!(s, 400, "an unsigned policy must not be granted under");
    assert_eq!(body["error"], "bad_request");

    // And a policy signed by the wrong key is refused on the owner binding,
    // not merely on the signature.
    let stranger = wallet(77, "stranger");
    let (s, body) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&stranger, &policy),
            "policy_keys_hex": policy_keys_hex(&stranger),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 1,
        }),
    );
    assert_eq!(s, 400, "{body}");
}

#[test]
fn a_delegated_spend_exercises_only_what_its_whole_chain_permits() {
    // The end-to-end property: a sub-agent request signed by its owner, with
    // its full ancestry, obtains an authorization; the same request with a
    // wider leaf, or with no chain at all, does not.
    let node = start();
    let (owner, parent) = parent_policy();
    let child = child_of(&parent);
    let request = build_signed_request(
        &owner,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: parent.allowed_services[0],
            recipient: parent.allowed_recipients[0],
            max_amount_sat: 100,
            expires_at_height: 10_000,
            policy_hash: child.hash(),
        },
        &[parent.clone(), child.clone()],
    )
    .unwrap();

    let (s, granted) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(child.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&owner, &child),
            "policy_keys_hex": policy_keys_hex(&owner),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 1,
            "chain_hex": [
                hex::encode(parent.serialize()),
                hex::encode(child.serialize()),
            ],
        }),
    );
    assert_eq!(
        s, 200,
        "a narrowed chained delegation must be granted: {granted}"
    );
    assert_eq!(granted["delegation_depth"], 1);

    // With no chain at all, a delegated policy has no provable ancestry, and
    // the node refuses it rather than treating it as a root.
    let (s, body) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(child.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&owner, &child),
            "policy_keys_hex": policy_keys_hex(&owner),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 2,
        }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "session_binding");
}

#[test]
fn revoking_an_ancestor_disables_its_descendants_at_payment_submission() {
    // Revocation has to reach the whole recorded subtree, or a kill switch on an
    // ancestor leaves every delegate below it spending.
    let node = start();
    let (owner, parent) = parent_policy();
    let child = child_of(&parent);
    let grandchild = grandchild_of(&parent, &child);

    // Link root -> child -> grandchild, so the lineage is recorded.
    let (s, b) = post(
        &node,
        "/v1/delegation/link",
        &serde_json::json!({
            "parent_policy_hex": hex::encode(parent.serialize()),
            "parent_sigs_hex": policy_sigs_hex(&owner, &parent),
            "parent_keys_hex": policy_keys_hex(&owner),
            "child_policy_hex": hex::encode(child.serialize()),
            "child_sigs_hex": policy_sigs_hex(&owner, &child),
            "child_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 200, "{b}");
    let (s, b) = post(
        &node,
        "/v1/delegation/link",
        &serde_json::json!({
            "parent_policy_hex": hex::encode(child.serialize()),
            "parent_sigs_hex": policy_sigs_hex(&owner, &child),
            "parent_keys_hex": policy_keys_hex(&owner),
            "child_policy_hex": hex::encode(grandchild.serialize()),
            "child_sigs_hex": policy_sigs_hex(&owner, &grandchild),
            "child_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 200, "{b}");

    // Authorizing under the root only: that is what revocation is signed over.
    let request = build_signed_request(
        &owner,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: parent.allowed_services[0],
            recipient: parent.allowed_recipients[0],
            max_amount_sat: 100,
            expires_at_height: 10_000,
            policy_hash: parent.hash(),
        },
        &[],
    )
    .unwrap();
    let (s, b) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(parent.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&owner, &parent),
            "policy_keys_hex": policy_keys_hex(&owner),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 1,
        }),
    );
    assert_eq!(s, 200, "{b}");

    // Revoke the root with a signed revocation of the *revoked* variant.
    let mut variant = parent.clone();
    variant.revoked = true;
    let (s, b) = post(
        &node,
        "/v1/policy/revoke",
        &serde_json::json!({
            "policy_hex": hex::encode(variant.serialize()),
            "sigs_hex": policy_sigs_hex(&owner, &variant),
            "keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["revoked"], true);
    assert!(
        b["descendants_revoked"].as_u64().unwrap() >= 2,
        "the root's child and grandchild must be revoked with it: {b}"
    );

    // A payment under the grandchild now carries two revoked ancestors, and the
    // node refuses it rather than admitting it on the payer's signature alone.
    let auth_bytes = hex::decode(post_authorization(
        &node,
        &owner,
        &grandchild,
        &[parent.clone(), child.clone(), grandchild.clone()],
        2,
    ))
    .unwrap();
    let _ = auth_bytes;
    let payment = build_signed_payment(
        &owner,
        &authorization_from(
            &node,
            &owner,
            &grandchild,
            &[parent.clone(), child.clone(), grandchild.clone()],
            3,
        ),
        NET,
        AgentRole::Machine,
        0,
        10_000,
        request.request_id(),
        &[parent.clone(), child.clone(), grandchild.clone()],
    )
    .unwrap();
    let (s, body) = post(
        &node,
        "/v1/payment/submit",
        &serde_json::json!({
            "payment_hex": hex::encode(payment.serialize()),
            "authorization_hex": hex::encode(
                authorization_from_bytes(&node, &owner, &grandchild, &[parent.clone(), child.clone(), grandchild.clone()], 4).serialize()
            ),
            "auth_sigs_hex": hex::encode(
                srct_core::l2::Auth::sigs_for(
                    &owner,
                    &authorization_from_bytes(&node, &owner, &grandchild, &[parent.clone(), child.clone(), grandchild.clone()], 5).signing_hash(),
                )
                .unwrap()
                .to_bytes(),
            ),
            "auth_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "policy_revoked");
}

/// Authorize under a policy and return the granted authorization, granting it if
/// the node has not already.
fn authorization_from(
    node: &Node,
    owner: &Wallet,
    policy: &SpendPolicy,
    chain: &[SpendPolicy],
    nonce: u64,
) -> srct_core::agent::Authorization {
    authorization_from_bytes(node, owner, policy, chain, nonce)
}

fn authorization_from_bytes(
    node: &Node,
    owner: &Wallet,
    policy: &SpendPolicy,
    chain: &[SpendPolicy],
    nonce: u64,
) -> srct_core::agent::Authorization {
    let request = build_signed_request(
        owner,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: policy
                .allowed_services
                .first()
                .copied()
                .unwrap_or([9u8; 32]),
            recipient: policy
                .allowed_recipients
                .first()
                .copied()
                .unwrap_or([8u8; 20]),
            max_amount_sat: 100,
            expires_at_height: 10_000,
            policy_hash: policy.hash(),
        },
        chain,
    )
    .unwrap();
    let (s, granted) = post(
        node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(owner, policy),
            "policy_keys_hex": policy_keys_hex(owner),
            "request_hex": hex::encode(request.serialize()),
            "nonce": nonce,
            "chain_hex": chain.iter().map(|p| hex::encode(p.serialize())).collect::<Vec<_>>(),
        }),
    );
    assert_eq!(s, 200, "authorization failed: {granted}");
    let bytes = hex::decode(granted["authorization_hex"].as_str().unwrap()).unwrap();
    srct_core::agent::Authorization::deserialize(&bytes).unwrap()
}

fn post_authorization(
    node: &Node,
    owner: &Wallet,
    policy: &SpendPolicy,
    chain: &[SpendPolicy],
    nonce: u64,
) -> String {
    hex::encode(authorization_from(node, owner, policy, chain, nonce).serialize())
}
/// Open an escrow through the node with real BLS keys. Returns the escrow id,
/// the arbitrator's secret key, and the party keys ? everything a release needs.
fn open_escrow(
    node: &Node,
    nonce: u64,
) -> (
    String,
    srct_core::bls::SecretKey,
    srct_core::bls::SecretKey,
    srct_core::bls::SecretKey,
) {
    let payer = srct_core::bls::SecretKey::from_scalar(&[4u8; 32]).unwrap();
    let payee = srct_core::bls::SecretKey::from_scalar(&[5u8; 32]).unwrap();
    let arb = srct_core::bls::SecretKey::from_scalar(&[6u8; 32]).unwrap();
    let (s, body) = post(
        node,
        "/v1/escrow/open",
        &serde_json::json!({
            "network_id": NET,
            "payer": hex::encode([1u8; 20]),
            "payer_bls": hex::encode(payer.public_key().0),
            "payee": hex::encode([2u8; 20]),
            "payee_bls": hex::encode(payee.public_key().0),
            "arbitrator": hex::encode(arb.public_key().0),
            "amount_sat": 1_000,
            "nonce": nonce,
        }),
    );
    assert_eq!(s, 200, "{body}");
    (
        body["escrow_id"].as_str().unwrap().to_string(),
        payer,
        payee,
        arb,
    )
}

#[test]
fn an_escrow_release_refuses_forged_and_replayed_authorizations() {
    // The adversarial set on the node path: a signature from a key that is not
    // the contract's arbitrator, a replayed release of an already-released
    // escrow, an unknown release mode, and a malformed signature length.
    let node = start();
    let (id, payer, payee, arb) = open_escrow(&node, 3);
    let path = format!("/v1/escrow/{id}/release");

    let (s, body) = get(&node, &format!("/v1/escrow/{id}"));
    assert_eq!(s, 200, "{body}");
    let release_hash: [u8; 32] = hex::decode(body["release_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        body["releasable"], true,
        "the default condition is releasable"
    );

    let good = arb.sign(&release_hash);
    let wrong_key = srct_core::bls::SecretKey::from_scalar(&[9u8; 32])
        .unwrap()
        .sign(&release_hash);

    // Forged: signed by a key that is not the arbitrator this escrow selected.
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "mode": "arbiter", "arbiter_sig_hex": hex::encode(wrong_key.0) }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "escrow_refused");

    // The correct arbitrator releases, and the state reflects it exactly once.
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "mode": "arbiter", "arbiter_sig_hex": hex::encode(good.0) }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["state"], "released_arbiter");

    // Replayed: a release of an already-released escrow is refused.
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "mode": "arbiter", "arbiter_sig_hex": hex::encode(good.0) }),
    );
    assert_eq!(s, 409, "{body}");

    // Unknown mode: a refusal, never a guess at which rule to apply.
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "mode": "whoever", "arbiter_sig_hex": hex::encode(good.0) }),
    );
    assert_eq!(s, 400, "{body}");

    // Malformed signature length is refused before any crypto happens.
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "mode": "arbiter", "arbiter_sig_hex": "00" }),
    );
    assert_eq!(s, 400, "{body}");

    // One-sided mutual release is refused by the shape of the request.
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({
            "mode": "mutual",
            "mutual_sigs_hex": [hex::encode(payer.sign(&release_hash).0)],
        }),
    );
    assert_eq!(s, 400, "{body}");

    // The escrow is released exactly once. The GET also advances finality, so a
    // matured release reads as Finalized rather than ReleasedArbiter ? the same
    // single release, and a second release was refused above.
    let (s, body) = get(&node, &format!("/v1/escrow/{id}"));
    assert_eq!(s, 200, "{body}");
    assert!(
        body["state"] == "released_arbiter" || body["state"] == "finalized",
        "{body}"
    );

    let _ = payee;
}

#[test]
fn two_escrows_between_the_same_parties_are_distinct_contracts() {
    // The nonce is what makes two escrows between the same parties distinct:
    // without it they would share an id, and a release of one would release the
    // other.
    let node = start();
    let (first, ..) = open_escrow(&node, 21);
    let (second, ..) = open_escrow(&node, 22);
    assert_ne!(first, second, "distinct nonces must not collide");

    let (s, first_body) = get(&node, &format!("/v1/escrow/{first}"));
    assert_eq!(s, 200);
    let (s, second_body) = get(&node, &format!("/v1/escrow/{second}"));
    assert_eq!(s, 200);
    assert_ne!(
        first_body["release_hash"], second_body["release_hash"],
        "a release hash must name its own escrow"
    );
}

// ---------------------------------------------------------------------------
// Settlement links: payment -> the L1 tx that paid it
// ---------------------------------------------------------------------------

/// Bridge a payment while the chain is at height 0 (the policy window the
/// bridge authors under), then mine `n` blocks paying the payer wallet so its
/// wallet can fund the transaction that settles the payment.
fn bridge_then_fund(credit: u64, n: u64) -> (Node, MachinePayment, Wallet) {
    let node = start();
    let payer = wallet(61, "api-payer");
    let (payment, _receipt, auth, sigs, keys) = run_bridge(&node, credit);
    let (s, body) = submit_payment(&node, &payment, &auth, &sigs, &keys);
    assert_eq!(s, 200, "payment submit refused: {body}");
    {
        let mut sh = node.shared.lock().unwrap();
        let addr = payer.address().unwrap();
        for h in 1..=n {
            let block = sh
                .chain
                .mine_block(addr, vec![], GENESIS_TIMESTAMP_MS + h * 1_000)
                .unwrap();
            sh.chain.submit(block).unwrap();
        }
    }
    (node, payment, payer)
}

/// Build, sign and broadcast `amount_sat` from `from` to `to`; returns the
/// txid hex exactly as `POST /v1/tx/broadcast` reported it.
fn pay_tx(node: &Node, from: &Wallet, to: &[u8; 20], amount_sat: u64) -> String {
    let (s, built) = post(
        node,
        "/v1/tx/build",
        &serde_json::json!({
            "from": address_to_hex(&from.address().unwrap()),
            "to": address_to_hex(to),
            "amount_sat": amount_sat,
            "max_fee_sat": 1_000_000,
        }),
    );
    assert_eq!(s, 200, "build failed: {built}");
    let mut tx =
        Transaction::deserialize(&hex::decode(built["unsigned_tx_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    from.sign(&mut tx).unwrap();
    let (s, body) = post(
        node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": hex::encode(tx.serialize()) }),
    );
    assert_eq!(s, 200, "broadcast failed: {body}");
    body["tx_hash"].as_str().unwrap().to_string()
}

#[test]
fn a_settlement_refuses_a_tx_that_never_pays_the_recipient() {
    let (node, payment, payer) = bridge_then_fund(BRIDGE_TOTAL_SAT, 12);
    let id_hex = hash_to_hex(&payment.signing_hash());
    let stranger = wallet(63, "stranger").address().unwrap();

    // An unknown txid: there is nothing to bind to.
    let (s, body) = post(
        &node,
        &format!("/v1/payment/{id_hex}/settle"),
        &serde_json::json!({ "tx_hash": hash512_to_hex(&[9u8; 64]) }),
    );
    assert_eq!(s, 404, "{body}");
    assert_eq!(body["error"], "unknown_transaction");

    // A real tx - but it pays a stranger, so it settles nothing.
    let wrong = pay_tx(&node, &payer, &stranger, BRIDGE_AMOUNT_SAT + 100);
    let (s, body) = post(
        &node,
        &format!("/v1/payment/{id_hex}/settle"),
        &serde_json::json!({ "tx_hash": wrong }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "settlement_does_not_pay_recipient");

    // Neither refusal left a link behind.
    let (s, body) = get(&node, &format!("/v1/payment/{id_hex}"));
    assert_eq!(s, 200);
    assert!(body["settlement"].is_null(), "no link was ever recorded");

    // And an unknown payment is a 404, not a 500.
    let (s, _) = post(
        &node,
        &format!("/v1/payment/{}/settle", hash_to_hex(&[1u8; 32])),
        &serde_json::json!({ "tx_hash": hash512_to_hex(&[9u8; 64]) }),
    );
    assert_eq!(s, 404);
}

#[test]
fn a_settlement_link_survives_confirmation_and_refuses_a_second_tx() {
    let (node, payment, payer) = bridge_then_fund(BRIDGE_TOTAL_SAT, 12);
    let id_hex = hash_to_hex(&payment.signing_hash());
    let recipient = payment.recipient;

    // The payer pays the recipient: pending, and reported as such.
    let tx1 = pay_tx(&node, &payer, &recipient, BRIDGE_AMOUNT_SAT + 100);
    let (s, body) = post(
        &node,
        &format!("/v1/payment/{id_hex}/settle"),
        &serde_json::json!({ "tx_hash": tx1 }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["payment_id"], id_hex);
    assert_eq!(body["settlement"]["tx_hash"], tx1);
    assert_eq!(body["settlement"]["status"], "pending");
    assert!(body["settlement"]["confirmed_height"].is_null());

    // The same txid again is idempotent, not a second link.
    let (s, body) = post(
        &node,
        &format!("/v1/payment/{id_hex}/settle"),
        &serde_json::json!({ "tx_hash": tx1 }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["duplicate"], true);

    // GET shows the same pending link.
    let (s, body) = get(&node, &format!("/v1/payment/{id_hex}"));
    assert_eq!(s, 200);
    assert_eq!(body["settlement"]["tx_hash"], tx1);
    assert_eq!(body["settlement"]["status"], "pending");

    // Mine the paying tx into a block: the link re-resolves to confirmed.
    {
        let mut sh = node.shared.lock().unwrap();
        let txid = srct_core::hash::hash512_from_hex(&tx1).unwrap();
        let tx = sh
            .pool
            .get(&txid)
            .expect("the paying tx is in the pool")
            .tx
            .clone();
        let height = sh.chain.height() + 1;
        let addr = payer.address().unwrap();
        let block = sh
            .chain
            .mine_block(addr, vec![tx], GENESIS_TIMESTAMP_MS + height * 1_000)
            .unwrap();
        sh.chain.submit(block).unwrap();
    }
    let (s, body) = get(&node, &format!("/v1/payment/{id_hex}"));
    assert_eq!(s, 200);
    assert_eq!(body["settlement"]["status"], "confirmed");
    assert_eq!(body["settlement"]["confirmed_height"].as_u64().unwrap(), 13);
    assert_eq!(body["settlement"]["tx_hash"], tx1);

    // A second tx that also pays the recipient: one payment, one link.
    let tx2 = pay_tx(&node, &payer, &recipient, BRIDGE_AMOUNT_SAT + 100);
    let (s, body) = post(
        &node,
        &format!("/v1/payment/{id_hex}/settle"),
        &serde_json::json!({ "tx_hash": tx2 }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "already_settled");

    // The original link is untouched by the conflict.
    let (s, body) = post(
        &node,
        &format!("/v1/payment/{id_hex}/settle"),
        &serde_json::json!({ "tx_hash": tx1 }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["duplicate"], true);
}

// ---------------------------------------------------------------------------
// Escrow settlement: the release's coin move (SPEC ?20.2 / Item 10)
// ---------------------------------------------------------------------------

const SINK_VALUE: u64 = 100_000_000; // 1 SRCT deposited to the L2 sink
const EXIT_FEE: u64 = 1_000_000;

/// Open an escrow between two real wallet addresses (the release's coin move
/// names these addresses as exit owner and destination, so they must be
/// wallet-derived, unlike the fixed addresses in `open_escrow`). Returns the
/// escrow id and the arbitrator key that can release it.
fn open_escrow_between(
    node: &Node,
    payer: &[u8; 20],
    payee: &[u8; 20],
    amount_sat: u64,
    nonce: u64,
) -> (String, srct_core::bls::SecretKey) {
    let payer_bls = srct_core::bls::SecretKey::from_scalar(&[4u8; 32]).unwrap();
    let payee_bls = srct_core::bls::SecretKey::from_scalar(&[5u8; 32]).unwrap();
    let arb = srct_core::bls::SecretKey::from_scalar(&[6u8; 32]).unwrap();
    let (s, body) = post(
        node,
        "/v1/escrow/open",
        &serde_json::json!({
            "network_id": NET,
            "payer": address_to_hex(payer),
            "payer_bls": hex::encode(payer_bls.public_key().0),
            "payee": address_to_hex(payee),
            "payee_bls": hex::encode(payee_bls.public_key().0),
            "arbitrator": hex::encode(arb.public_key().0),
            "amount_sat": amount_sat,
            "nonce": nonce,
        }),
    );
    assert_eq!(s, 200, "{body}");
    (body["escrow_id"].as_str().unwrap().to_string(), arb)
}

/// Mine blocks to `miner` until it holds a mature coinbase, deposit one SRCT
/// into the L2 sink and sync, so the wallet's L2 balance can pay an exit.
fn fund_l2(node: &Node, miner: &Wallet) {
    let params = NetworkParams::mini();
    let me = miner.address().unwrap();
    {
        let mut guard = node.shared.lock().unwrap();
        let sh = &mut *guard;
        while sh.chain.height() < 12 {
            let h = sh.chain.height() + 1;
            let b = sh
                .chain
                .mine_block(me, vec![], GENESIS_TIMESTAMP_MS + h * 1_000)
                .unwrap();
            sh.chain.submit(b).unwrap();
        }
        let (outpoint, value) = sh
            .chain
            .utxo()
            .iter()
            .filter(|(_, u)| u.out.address == me && sh.chain.is_mature(u.height))
            .map(|(op, u)| (op, u.out.value))
            .next()
            .expect("a mature coinbase");
        let fee =
            sh.chain.expected_base_fee_for_next_block() * (16_000 + 1_000 + 2 * 250) + 1_000_000;
        let tx = miner
            .build_tx(
                &[outpoint],
                vec![
                    Output {
                        value: SINK_VALUE,
                        address: params.l2_deposit_sink(),
                    },
                    Output {
                        value: value - SINK_VALUE - fee,
                        address: me,
                    },
                ],
                fee,
            )
            .unwrap();
        let h = sh.chain.height() + 1;
        let b = sh
            .chain
            .mine_block(me, vec![tx], GENESIS_TIMESTAMP_MS + h * 1_000)
            .unwrap();
        sh.chain.submit(b).unwrap();
        while sh.chain.height() < h + 20 {
            let hh = sh.chain.height() + 1;
            let b = sh
                .chain
                .mine_block(me, vec![], GENESIS_TIMESTAMP_MS + hh * 1_000)
                .unwrap();
            sh.chain.submit(b).unwrap();
        }
        sh.l2.sync(&sh.chain).unwrap();
        assert_eq!(
            sh.l2.state().balance(&me),
            SINK_VALUE,
            "the matured deposit is the principal an exit spends"
        );
    }
}

#[test]
fn an_escrow_settle_binds_the_release_to_the_exit_that_pays_it() {
    let params = NetworkParams::mini();
    let node = start();
    let payer_w = wallet(71, "escrow-payer");
    let payee_w = wallet(72, "escrow-payee");
    let payer = payer_w.address().unwrap();
    let payee = payee_w.address().unwrap();
    fund_l2(&node, &payer_w);

    // The crank settles an exit only when its funding is exact (a delay, never
    // a wrong payment), so the escrow's amount is SINK - exit fee - L1 fee,
    // derived from the chain the way the crank will derive it later.
    let amount = {
        let sh = node.shared.lock().unwrap();
        let gas = 16_000u64 + 1_000 + 2 * 250;
        SINK_VALUE - EXIT_FEE - sh.chain.expected_base_fee_for_next_block() * gas
    };

    let (id, arb) = open_escrow_between(&node, &payer, &payee, amount, 41);
    let (id2, _) = open_escrow_between(&node, &payer, &payee, amount, 42);

    let good_exit = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(&payer_w, 1, amount, payee, EXIT_FEE).unwrap(),
    ));
    let good_hex = hex::encode(good_exit.serialize());

    // Before a release there is no outcome to settle: the coin cannot move.
    let (s, body) = post(
        &node,
        &format!("/v1/escrow/{id}/settle"),
        &serde_json::json!({ "l2_tx_hex": good_hex }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "escrow_not_released");

    // Release escrow 1. No GET between release and settle: a GET advances
    // finality, and an unbound released escrow keeps the old height stamp.
    let (s, body) = get(&node, &format!("/v1/escrow/{id}"));
    assert_eq!(s, 200, "{body}");
    let release_hash: [u8; 32] = hex::decode(body["release_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let (s, body) = post(
        &node,
        &format!("/v1/escrow/{id}/release"),
        &serde_json::json!({
            "mode": "arbiter",
            "arbiter_sig_hex": hex::encode(arb.sign(&release_hash).0),
        }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["state"], "released_arbiter");

    // The settle must be THIS escrow's coin move: owner, destination, amount.
    let path = format!("/v1/escrow/{id}/settle");
    let wrong_dest = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(
            &payer_w,
            2,
            1_000,
            wallet(73, "stranger").address().unwrap(),
            EXIT_FEE,
        )
        .unwrap(),
    ));
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "l2_tx_hex": hex::encode(wrong_dest.serialize()) }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "settlement_destination_mismatch");

    let wrong_amount = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(&payer_w, 3, amount + 7, payee, EXIT_FEE).unwrap(),
    ));
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "l2_tx_hex": hex::encode(wrong_amount.serialize()) }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "settlement_amount_mismatch");

    let wrong_owner = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(&wallet(74, "not-the-payer"), 1, amount, payee, EXIT_FEE).unwrap(),
    ));
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "l2_tx_hex": hex::encode(wrong_owner.serialize()) }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "settlement_owner_mismatch");

    // A real L2 transaction, but not an exit at all.
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "l2_tx_hex": hex::encode(post_payload(1).serialize()) }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "bad_request");

    // The genuine settlement: the exit is queued for the crank.
    let (s, body) = post(&node, &path, &serde_json::json!({ "l2_tx_hex": good_hex }));
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["queued"], true, "{body}");
    let txid = body["txid"].as_str().unwrap().to_string();

    // The same exit again is idempotent; a second exit is one move too many.
    let (s, body) = post(&node, &path, &serde_json::json!({ "l2_tx_hex": good_hex }));
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["duplicate"], true);
    let other_exit = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(&payer_w, 9, amount, payee, EXIT_FEE).unwrap(),
    ));
    let (s, body) = post(
        &node,
        &path,
        &serde_json::json!({ "l2_tx_hex": hex::encode(other_exit.serialize()) }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "escrow_settled");

    // The binding is reported, and the state must NOT read finalized even
    // though the chain is already well past finality: the coin has not moved.
    let (s, body) = get(&node, &format!("/v1/escrow/{id}"));
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["state"], "released_arbiter", "the gate holds: {body}");
    assert_eq!(body["settlement"]["txid"], txid);
    assert_eq!(body["settlement"]["exit_owner"], address_to_hex(&payer));
    assert_eq!(body["settlement"]["exit_nonce"].as_u64(), Some(1));
    assert_eq!(body["settlement"]["exit_released"], false);

    // escrow 2 was never settled: no binding.
    let (s, body) = get(&node, &format!("/v1/escrow/{id2}"));
    assert_eq!(s, 200, "{body}");
    assert!(body["settlement"].is_null(), "{body}");

    // The serve loop's own sequence: include the exit, mature it, crank the
    // claim, let consensus pay the payee.
    {
        let mut guard = node.shared.lock().unwrap();
        let sh = &mut *guard;
        let q = sh.chain.height() + 1;
        let l2_queue = std::mem::take(&mut sh.l2_to_include);
        assert_eq!(l2_queue.len(), 1, "the settle queued exactly one exit");
        assert!(
            sh.l2.crank_claims(&sh.chain, payer).is_empty(),
            "queue is immature"
        );
        let root = sh.l2.simulate_root(&sh.chain, q, &l2_queue);
        // mine_from_pool_with_exits mines AND submits; a separate submit of
        // the same block would be AlreadyKnown.
        sh.chain
            .mine_from_pool_with_exits(
                &mut sh.pool,
                payer,
                GENESIS_TIMESTAMP_MS + q * 1_000,
                l2_queue,
                Vec::new(),
                Some(root),
            )
            .unwrap();
        sh.l2.sync(&sh.chain).unwrap();
        assert_eq!(sh.l2.pending_exits().len(), 1, "the exit is watched");

        while sh.chain.height() < q + params.finality_depth {
            let h = sh.chain.height() + 1;
            let b = sh
                .chain
                .mine_block(payer, vec![], GENESIS_TIMESTAMP_MS + h * 1_000)
                .unwrap();
            sh.chain.submit(b).unwrap();
        }
        sh.l2.sync(&sh.chain).unwrap();

        let claims = sh.l2.crank_claims(&sh.chain, payer);
        assert_eq!(claims.len(), 1, "the matured exit is claimable");
        assert_eq!(claims[0].destination, payee, "paid to the payee");
        assert_eq!(claims[0].amount_sat, amount, "the escrow amount, exactly");
        let h = sh.chain.height() + 1;
        sh.chain
            .mine_from_pool_with_exits(
                &mut sh.pool,
                payer,
                GENESIS_TIMESTAMP_MS + h * 1_000,
                Vec::new(),
                claims,
                None,
            )
            .unwrap();
        sh.l2.sync(&sh.chain).unwrap();
        assert!(
            sh.chain.exit_released(&payer, 1),
            "consensus paid the destination"
        );
        assert!(
            sh.l2.state().check_conservation(),
            "the exit moved value, it did not create it"
        );

        // Finalized only now ? when the coin actually left.
        sh.advance_escrow_finality();
    }

    let (s, body) = get(&node, &format!("/v1/escrow/{id}"));
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["state"], "finalized", "{body}");
    assert_eq!(body["settlement"]["exit_released"], true);
    assert_eq!(body["settlement"]["txid"], txid);

    let (s, body) = get(&node, &format!("/v1/escrow/{id2}"));
    assert_eq!(s, 200, "{body}");
    assert_eq!(
        body["state"], "open",
        "never released, so never finalizable: {body}"
    );
    assert!(body["settlement"].is_null(), "{body}");
}

#[test]
fn settle_refuses_an_unknown_escrow_and_malformed_hex() {
    let node = start();
    let exit = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(&wallet(71, "ghost"), 1, 1_000, [2u8; 20], EXIT_FEE).unwrap(),
    ));
    let exit_hex = hex::encode(exit.serialize());

    // An unknown id is a 404, decoded before anything else happens.
    let (s, body) = post(
        &node,
        &format!("/v1/escrow/{}/settle", hash_to_hex(&[1u8; 32])),
        &serde_json::json!({ "l2_tx_hex": exit_hex }),
    );
    assert_eq!(s, 404, "{body}");
    assert_eq!(body["error"], "not_found");

    // Malformed hex is a 400, never a 500.
    let (s, body) = post(
        &node,
        &format!("/v1/escrow/{}/settle", hash_to_hex(&[1u8; 32])),
        &serde_json::json!({ "l2_tx_hex": "zz" }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "bad_request");
}

// ---------------------------------------------------------------------------
// Credit attestation: minting gated by a trusted issuer's signature
// ---------------------------------------------------------------------------

/// The `POST /v1/credit/mint` body for an attestation, fields verbatim.
fn mint_json(att: &srct_core::credit::CreditAttestation) -> serde_json::Value {
    serde_json::json!({
        "network_id": att.network_id,
        "subject": address_to_hex(&att.subject),
        "amount_sat": att.amount_sat,
        "issue_height": att.issue_height,
        "expires_height": att.expires_height,
        "issuer": hex::encode(att.issuer.0),
        "sig": hex::encode(att.sig.0),
    })
}

#[test]
fn a_mint_needs_a_trusted_signature_and_can_never_mint_twice() {
    let issuer_sk = srct_core::bls::SecretKey::from_scalar(&[81u8; 32]).unwrap();
    let stranger_sk = srct_core::bls::SecretKey::from_scalar(&[82u8; 32]).unwrap();
    let subject = wallet(75, "credit-subject").address().unwrap();
    let sign_att = |sk: &srct_core::bls::SecretKey, net: &str, amount, issue, expires| {
        srct_core::credit::CreditAttestation::sign(
            sk,
            net.to_string(),
            subject,
            amount,
            issue,
            expires,
        )
    };

    // No configured issuer: every mint refused, whatever the attestation says.
    let node = start();
    let att = sign_att(&issuer_sk, NET, 5_000, 0, 9_000);
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 403, "{body}");
    assert_eq!(body["error"], "no_credit_issuers");

    // A node that trusts this issuer: the signed attestation mints its amount.
    let node = start_with_issuers(
        Chain::new(NetworkParams::mini()).unwrap(),
        vec![issuer_sk.public_key()],
    );
    let att = sign_att(&issuer_sk, NET, 5_000, 0, 9_000);
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["amount_sat"], 5_000);
    assert_eq!(body["balance"], 5_000);

    // The same attestation again is refused: one signature, one mint.
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "attestation_reused");

    // The balance agrees with what minted.
    let (s, body) = get(
        &node,
        &format!("/v1/credit/balance/{}", address_to_hex(&subject)),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["free_balance"], 5_000);

    // An issuer this node does not trust: refused even with a perfect
    // signature, because trust is configuration, never inference.
    let node = start_with_issuers(
        Chain::new(NetworkParams::mini()).unwrap(),
        vec![stranger_sk.public_key()],
    );
    let att = sign_att(&issuer_sk, NET, 5_000, 0, 9_000);
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 403, "{body}");
    assert_eq!(body["error"], "untrusted_issuer");

    let node = start_with_issuers(
        Chain::new(NetworkParams::mini()).unwrap(),
        vec![issuer_sk.public_key()],
    );

    // A tampered amount under a valid signature: refused before minting.
    let mut att = sign_att(&issuer_sk, NET, 7_000, 0, 9_000);
    att.amount_sat = 90_000;
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 400, "{body}");

    // Another network's attestation: refused by name, not verified into.
    let att = sign_att(&issuer_sk, "other/net", 5_000, 0, 9_000);
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "wrong_network");

    // Not yet issued: refused as from the future.
    let att = sign_att(&issuer_sk, NET, 5_000, 99, 9_000);
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "attestation_from_the_future");

    // An expired attestation: refuse after its window, even signed by the
    // trusted key. The window closes at height 0 here, so one block does it.
    let att = sign_att(&issuer_sk, NET, 5_000, 0, 0);
    {
        let mut guard = node.shared.lock().unwrap();
        let sh = &mut *guard;
        let b = sh
            .chain
            .mine_block([9u8; 20], vec![], GENESIS_TIMESTAMP_MS + 1_000)
            .unwrap();
        sh.chain.submit(b).unwrap();
    }
    let (s, body) = post(&node, "/v1/credit/mint", &mint_json(&att));
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "attestation_expired");
}

#[test]
fn external_miner_template_and_submit_roundtrip() {
    // Mining-stack seam over the wire: a template for a miner address, then
    // the solved block back. On a fresh mini chain difficulty is 1, so the
    // template itself (nonce 0) is already a valid proof — the test pins the
    // plumbing, while real grinding lives in srct-miner.
    let node = start();
    let miner = wallet(77, "ext-miner");
    let miner_hex = address_to_hex(&miner.address().unwrap());

    let (s, tpl) = get(&node, &format!("/v1/mine/template?miner={miner_hex}"));
    assert_eq!(s, 200, "{tpl}");
    assert_eq!(tpl["height"], 1);
    assert_eq!(tpl["puzzle_id"], 1);
    let block_hex = tpl["block_hex"].as_str().expect("template block_hex");

    let (s, out) = post(&node, "/v1/mine/submit", &json!({ "block_hex": block_hex }));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["height"], 1);
    assert_eq!(node_height(&node), 1);

    // The same block twice is already-known, not a second confirmation.
    let (s, _) = post(&node, "/v1/mine/submit", &json!({ "block_hex": block_hex }));
    assert!(s == 400 || s == 409, "replay must be refused, got {s}");

    // Garbage bytes are a client error, never a panic.
    let (s, body) = post(&node, "/v1/mine/submit", &json!({ "block_hex": "zz" }));
    assert_eq!(s, 400, "{body}");

    // A malformed miner address is refused before any template is built.
    let (s, body) = get(&node, "/v1/mine/template?miner=zz");
    assert_eq!(s, 400, "{body}");
}

#[test]
fn oversized_submit_hex_is_refused_before_allocation() {
    // A 17 MiB hex field must be refused before decoding it into an 8.5 MB
    // buffer: the HTTP layer's body cap (413) or the hex field cap (400).
    let node = start();
    let big = "ab".repeat(17 * 1024 * 1024 / 2);
    let (s, body) = post(&node, "/v1/mine/submit", &json!({ "block_hex": big }));
    assert!(s == 400 || s == 413, "{s} {body}");
    if s == 400 {
        assert!(body.to_string().contains("16 MiB"));
    }
}

#[test]
fn escrow_open_records_without_checking_payer_funding_n4() {
    // N4 confirmation: `open` records intent only. A payer with no L2 balance
    // can open two escrows whose combined amount exceeds anything they own —
    // both return 200. Funding is enforced once, at settlement, when the bound
    // `ExitQueue` debits the payer (first settlement to apply wins). A payee
    // must therefore treat the release signature as authorization and
    // `Finalized` as payment. If open ever reserves funds, rewrite this test
    // to assert refusal of the second open.
    let node = start();
    let arb_pk = BlsSecretKey::derive(&[5u8; 32]).unwrap().public_key();
    let payer_pk = BlsSecretKey::derive(&[7u8; 32]).unwrap().public_key();
    let payee_pk = BlsSecretKey::derive(&[8u8; 32]).unwrap().public_key();
    let payer_addr = wallet(71, "n4-payer").address().unwrap();
    let payee_addr = wallet(72, "n4-payee").address().unwrap();
    for nonce in [21u64, 22u64] {
        let (s, b) = post(
            &node,
            "/v1/escrow/open",
            &serde_json::json!({
                "network_id": "srct/test",
                "payer": address_to_hex(&payer_addr),
                "payer_bls": hex::encode(payer_pk.0),
                "payee": address_to_hex(&payee_addr),
                "payee_bls": hex::encode(payee_pk.0),
                "arbitrator": hex::encode(arb_pk.0),
                "amount_sat": 50_000_000u64,
                "nonce": nonce,
            }),
        );
        assert_eq!(
            s, 200,
            "N4: unfunded open {nonce} must currently succeed: {b}"
        );
        assert!(b["escrow_id"].is_string());
    }
}
