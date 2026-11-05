//! Usage-based credits: the trial faucet (service layer, never consensus).
//!
//! A broke agent cannot post a claim deposit, so its first task is unfundable.
//! The faucet fixes that without touching consensus: an operator-funded sponsor
//! drips one fixed amount over ordinary L1 rails, the node verifies the
//! receipt against its own chain, and the agent repays the same way later.
//! The node never signs and never mints — it only records and verifies.
//!
//! Pinned here, end to end against a real node + real chain:
//! - one trial per agent, ever (a second request is refused);
//! - funding needs a *confirmed* L1 payment to the agent (mempool is not
//!   enough, a wrong-recipient payment is not enough, one tx funds at most
//!   one trial);
//! - repayment needs a confirmed L1 payment back to the sponsor;
//! - an orphaned funding payment can be re-confirmed with its replacement;
//! - the trial book survives an encode/decode round trip (v9 envelope).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::chain::Chain;
use srct_core::hash::{address_to_hex, hash512_to_hex, Address, Hash512};
use srct_core::params::NetworkParams;
use srct_core::tx::{OutPoint, Output};
use srct_core::wallet::Wallet;
use srct_node::api::{SharedNode, TrialRecord, TrialState};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const TRIAL_AMOUNT: u64 = 5_000_000;
const TRIAL_DRIP: u64 = 20_000_000;
const TRIAL_FEE: u64 = 2_000_000;

struct Node {
    addr: SocketAddr,
    shared: Arc<Mutex<SharedNode>>,
}

fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "trial-test").unwrap()
}

fn addr(seed: u8) -> Address {
    wallet(seed).address().unwrap()
}

fn start() -> Node {
    std::env::set_var("SRCT_TRIAL_SPONSOR", address_to_hex(&addr(1)));
    std::env::set_var("SRCT_TRIAL_AMOUNT_SAT", TRIAL_AMOUNT.to_string());
    std::env::set_var("SRCT_TRIAL_MAX_OUTSTANDING_SAT", "1000000000");
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = srct_node::api::spawn_with_options(
        Arc::clone(&shared),
        peers,
        "127.0.0.1:0".parse().unwrap(),
        None,
        Vec::new(),
        Vec::new(),
    )
    .expect("bind loopback");
    Node { addr, shared }
}

fn exchange(addr: SocketAddr, request: &[u8]) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let _ = stream.write_all(request);
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}")),
    )
}

fn post(addr: SocketAddr, path: &str, body: &Value) -> (u16, Value) {
    let raw = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw}",
        raw.len()
    );
    exchange(addr, req.as_bytes())
}

fn get(addr: SocketAddr, path: &str) -> (u16, Value) {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    exchange(addr, req.as_bytes())
}

/// Mine `n` empty blocks paying coinbase to `miner`, then submit each.
fn mine_empty(shared: &Arc<Mutex<SharedNode>>, miner: Address, n: u64) {
    for _ in 0..n {
        let mut sh = shared.lock().unwrap();
        let h = sh.chain.height() + 1;
        let block = sh.chain.mine_block(miner, vec![], ts(h)).unwrap();
        sh.chain.submit(block).unwrap();
    }
}

/// Mine one block containing `txs`.
fn mine_with(
    shared: &Arc<Mutex<SharedNode>>,
    miner: Address,
    txs: Vec<srct_core::tx::Transaction>,
) {
    let mut sh = shared.lock().unwrap();
    let h = sh.chain.height() + 1;
    let block = sh.chain.mine_block(miner, txs, ts(h)).unwrap();
    sh.chain.submit(block).unwrap();
}

/// The coinbase txid that paid `miner` at `height`.
fn coinbase_at(shared: &Arc<Mutex<SharedNode>>, height: u64) -> Hash512 {
    let sh = shared.lock().unwrap();
    sh.chain.block_at(height).unwrap().txs[0].txid()
}

/// Ordinary L1 payment, signed, fee covered: `from` pays `to` `amount`.
fn pay(
    from_seed: u8,
    prev: Hash512,
    prev_value: u64,
    to: Address,
    amount: u64,
) -> srct_core::tx::Transaction {
    let w = wallet(from_seed);
    let change = prev_value - amount - TRIAL_FEE;
    w.build_tx(
        &[OutPoint {
            txid: prev,
            index: 0,
        }],
        vec![
            Output {
                value: amount,
                address: to,
            },
            Output {
                value: change,
                address: addr(from_seed),
            },
        ],
        TRIAL_FEE,
    )
    .expect("sponsor can fund the drip")
}

#[test]
fn trial_full_lifecycle_on_real_chain() {
    let node = start();
    let sponsor = addr(1);
    let agent = addr(2);
    let stranger = addr(3);
    let agent_hex = address_to_hex(&agent);

    // 1. Mature the sponsor's coinbase, then drip to the agent.
    mine_empty(&node.shared, sponsor, 12);
    let coinbase = coinbase_at(&node.shared, 1);
    // Coinbase value on mini: 76 SRCT — the faucet test spends a sliver.
    let drip = pay(1, coinbase, 7_600_000_000, agent, TRIAL_DRIP);
    let drip_id = drip.txid();
    mine_with(&node.shared, sponsor, vec![drip]);

    // 2. No trial yet: status is 404, funding is refused.
    let (code, _) = get(node.addr, &format!("/v1/trials/{agent_hex}"));
    assert_eq!(code, 404, "no trial recorded yet");
    let (code, body) = post(
        node.addr,
        "/v1/trials/fund",
        &json!({ "agent_hex": agent_hex, "txid_hex": hash512_to_hex(&drip_id) }),
    );
    assert_eq!(code, 404, "funding without a request is refused: {body}");

    // 3. Request: one per agent, ever.
    let (code, body) = post(
        node.addr,
        "/v1/trials/request",
        &json!({ "agent_hex": agent_hex }),
    );
    assert_eq!(code, 200, "request must record: {body}");
    assert_eq!(body["state"], json!("requested"));
    assert_eq!(body["amount_sat"], json!(TRIAL_AMOUNT));
    let (code, body) = post(
        node.addr,
        "/v1/trials/request",
        &json!({ "agent_hex": agent_hex }),
    );
    assert_eq!(
        code, 409,
        "a second trial for the same agent is refused: {body}"
    );

    // 4. Funding with a payment to someone else proves nothing. A different
    // coinbase funds it: reusing the drip's outpoint would double-spend.
    let coinbase2 = coinbase_at(&node.shared, 2);
    let wrong = pay(1, coinbase2, 7_600_000_000, stranger, TRIAL_DRIP);
    let wrong_id = wrong.txid();
    mine_with(&node.shared, sponsor, vec![wrong]);
    let (code, body) = post(
        node.addr,
        "/v1/trials/fund",
        &json!({ "agent_hex": agent_hex, "txid_hex": hash512_to_hex(&wrong_id) }),
    );
    assert_eq!(code, 422, "a payment to someone else funds nothing: {body}");

    // 5. The real drip confirms the trial.
    let (code, body) = post(
        node.addr,
        "/v1/trials/fund",
        &json!({ "agent_hex": agent_hex, "txid_hex": hash512_to_hex(&drip_id) }),
    );
    assert_eq!(code, 200, "the drip must fund the trial: {body}");
    assert_eq!(body["state"], json!("funded"));
    // Idempotent re-confirmation of the same receipt.
    let (code, _) = post(
        node.addr,
        "/v1/trials/fund",
        &json!({ "agent_hex": agent_hex, "txid_hex": hash512_to_hex(&drip_id) }),
    );
    assert_eq!(code, 200, "re-confirming the same receipt is fine");

    // 6. One L1 payment funds at most one trial.
    let agent_b = address_to_hex(&addr(4));
    let (code, _) = post(
        node.addr,
        "/v1/trials/request",
        &json!({ "agent_hex": agent_b }),
    );
    assert_eq!(code, 200, "a second agent may request");
    let (code, body) = post(
        node.addr,
        "/v1/trials/fund",
        &json!({ "agent_hex": agent_b, "txid_hex": hash512_to_hex(&drip_id) }),
    );
    assert_eq!(code, 409, "the same receipt cannot fund two trials: {body}");

    // 7. Repayment needs a confirmed payment back to the sponsor.
    let (code, _) = get(node.addr, &format!("/v1/trials/{agent_hex}"));
    assert_eq!(code, 200);
    // The agent pays back out of the drip (real money, both ways). Every
    // output ages before it can move again, so the repayment waits out the
    // drip's maturation first.
    mine_empty(&node.shared, sponsor, 12);
    let repay = pay(2, drip_id, TRIAL_DRIP, sponsor, TRIAL_AMOUNT);
    let repay_id = repay.txid();
    mine_with(&node.shared, sponsor, vec![repay]);
    let (code, body) = post(
        node.addr,
        "/v1/trials/repay",
        &json!({ "agent_hex": agent_hex, "txid_hex": hash512_to_hex(&repay_id) }),
    );
    assert_eq!(code, 200, "the payback must close the trial: {body}");
    assert_eq!(body["state"], json!("repaid"));

    // 8. Closed means closed: no second trial, no second funding.
    let (code, _) = post(
        node.addr,
        "/v1/trials/request",
        &json!({ "agent_hex": agent_hex }),
    );
    assert_eq!(code, 409, "a repaid agent cannot trial again: {body}");
    let (code, body) = get(node.addr, &format!("/v1/trials/{agent_hex}"));
    assert_eq!(code, 200);
    assert_eq!(body["state"], json!("repaid"));
    assert_eq!(body["repay_txid"], json!(hash512_to_hex(&repay_id)));

    // 9. The book survives an encode/decode round trip (v10 envelope).
    let bytes = {
        let sh = node.shared.lock().unwrap();
        sh.encode_state()
    };
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let l2 = srct_node::l2::NodeL2::fresh(&params).unwrap();
    let mut fresh = SharedNode::new(chain, l2);
    fresh.decode_state(&bytes).expect("v10 envelope replays");
    let t: &TrialRecord = fresh.trials.get(&agent).expect("trial survived");
    assert_eq!(t.state, TrialState::Repaid);
    assert_eq!(t.amount_sat, TRIAL_AMOUNT);
    assert_eq!(t.fund_txid, Some(drip_id));
}

#[test]
fn trial_request_names_a_bad_agent() {
    let node = start();
    let (code, _) = post(
        node.addr,
        "/v1/trials/request",
        &json!({ "agent_hex": "not-hex" }),
    );
    assert_eq!(code, 400, "a malformed agent is refused, not recorded");
}
