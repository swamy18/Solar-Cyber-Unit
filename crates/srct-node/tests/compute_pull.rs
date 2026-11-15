//! Pull-model integration tests: open ticket board, atomic claims,
//! capacity-gated offers, and pre-authorized payouts that fire exactly once.
//!
//! Drives the real server over raw HTTP like the other node suites.
//! Run with `cargo test -p srct-node --test compute_pull`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::chain::Chain;
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_node::api::{spawn_with_options, SharedNode};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const NET: &str = "srct/mini";
const EXIT_FEE: u64 = 1_000_000;

struct Node {
    addr: SocketAddr,
    #[allow(dead_code)]
    shared: Arc<Mutex<SharedNode>>,
}

fn start() -> Node {
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn_with_options(
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

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
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

fn post(node: &Node, path: &str, body: &Value) -> (u16, Value) {
    let raw = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        node.addr, raw.len(), raw
    );
    exchange(node.addr, req.as_bytes())
}

fn get(node: &Node, path: &str) -> (u16, Value) {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        node.addr
    );
    exchange(node.addr, req.as_bytes())
}

fn requester() -> Wallet {
    wallet(11, "pull-requester")
}
fn provider() -> Wallet {
    wallet(12, "pull-provider")
}

fn register_bond(node: &Node, provider: &Wallet, amount: u64, nonce: u64) {
    let bond = srct_compute::ProviderBond {
        version: srct_compute::BOND_VERSION,
        network_id: NET.to_string(),
        provider: provider.address().unwrap(),
        amount_sat: amount,
        registered_height: 0,
        nonce,
    };
    let signed = srct_compute::SignedBond::sign(bond, provider).unwrap();
    let (s, body) = post(
        node,
        "/v1/compute/bonds/register",
        &json!({ "bond_hex": hex::encode(signed.encode()) }),
    );
    assert_eq!(s, 200, "bond register failed: {body}");
}

fn post_offer(node: &Node, provider: &Wallet, nonce: u64, max_units: u32, price: u64) -> String {
    let profile = srct_compute::DeviceProfile::new(
        srct_compute::DeviceClass::Cpu,
        srct_compute::Determinism::Reproducible,
        16_384,
        8,
        1_000,
        100_000,
        2_000,
        [0u8; 32],
    );
    let offer = srct_compute::ComputeOffer {
        version: srct_compute::OFFER_VERSION,
        network_id: NET.to_string(),
        provider: provider.address().unwrap(),
        service: "ai/inference".to_string(),
        profile,
        unit_price_sat: price,
        min_units: 1,
        max_units_per_job: max_units,
        privacy: false,
        verification: srct_compute::Verification::Receipt,
        available_from: 0,
        available_until: 10_000,
        nonce,
    };
    let signed = srct_compute::SignedOffer::sign(offer, provider).unwrap();
    let (s, body) = post(
        node,
        "/v1/compute/offers",
        &json!({ "offer_hex": hex::encode(signed.encode()) }),
    );
    assert_eq!(s, 200, "offer post failed: {body}");
    body["offer_hash"].as_str().unwrap().to_string()
}

fn post_job(node: &Node, requester: &Wallet, units: u32, max_total: u64) -> String {
    let job = srct_compute::ComputeJob {
        version: srct_compute::JOB_VERSION,
        network_id: NET.to_string(),
        requester: requester.address().unwrap(),
        service: "ai/inference".to_string(),
        units,
        max_unit_price_sat: 250,
        max_total_sat: max_total,
        class_mask: srct_compute::DeviceClass::ALL_MASK,
        min_ram_mib: 512,
        min_units_per_sec: 100,
        min_bandwidth_kbps: 0,
        determinism: srct_compute::Determinism::Reproducible,
        required_kernel: [0u8; 32],
        min_verification: srct_compute::Verification::Receipt,
        sealed_input: false,
        input: [42u8; 32],
        deadline: 9_000,
        nonce: 100,
    };
    let signed = srct_compute::SignedJob::sign(job, requester).unwrap();
    let hash = hex::encode(signed.hash());
    let (s, body) = post(node, "/v1/compute/jobs", &json!({ "job_hex": hex::encode(signed.encode()) }));
    assert_eq!(s, 200, "job post failed: {body}");
    hash
}

fn fund_job(node: &Node, requester: &Wallet, job_hash: &str, amount: u64) {
    let funding = srct_compute::EscrowFunding {
        version: srct_compute::ESCROW_VERSION,
        network_id: NET.to_string(),
        job: hex::decode(job_hash)
            .unwrap()
            .try_into()
            .map_err(|_| "bad job hash")
            .unwrap(),
        requester: requester.address().unwrap(),
        amount_sat: amount,
        deadline: 9_000,
        nonce: 7,
    };
    let signed = srct_compute::SignedFunding::sign(funding, requester).unwrap();
    let (s, body) = post(
        node,
        "/v1/compute/escrow/fund",
        &json!({ "funding_hex": hex::encode(signed.encode()) }),
    );
    assert_eq!(s, 200, "fund failed: {body}");
}

fn fund_l2_requester(node: &Node, requester: &Wallet, amount: u64) {
    use srct_core::block::GENESIS_TIMESTAMP_MS;
    use srct_core::tx::Output;
    // Real L2 money: an L1 payment to the sink, matured, then synced into
    // the node's L2 view — the same burn-to-sink path production uses.
    let params = NetworkParams::mini();
    let me = requester.address().unwrap();
    let mut sh = node.shared.lock().unwrap();
    for h in 1..=12u64 {
        let b = sh
            .chain
            .mine_block(me, vec![], GENESIS_TIMESTAMP_MS + h * 1_000)
            .unwrap();
        sh.chain.submit(b).unwrap();
    }
    let sink = params.l2_deposit_sink();
    let (outpoint, value) = sh
        .chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == me && sh.chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase");
    let fee = sh.chain.expected_base_fee_for_next_block() * (16_000 + 1_000 + 2 * 250) + 1_000_000;
    let change = value - amount - fee;
    let tx = requester
        .build_tx(
            &[outpoint],
            vec![
                Output {
                    value: amount,
                    address: sink,
                },
                Output {
                    value: change,
                    address: me,
                },
            ],
            fee,
        )
        .unwrap();
    let h = sh.chain.height() + 1;
    let deposit = sh
        .chain
        .mine_block(me, vec![tx], GENESIS_TIMESTAMP_MS + h * 1_000)
        .unwrap();
    sh.chain.submit(deposit).unwrap();
    for _ in 0..20 {
        let h = sh.chain.height() + 1;
        let b = sh
            .chain
            .mine_block(me, vec![], GENESIS_TIMESTAMP_MS + h * 1_000)
            .unwrap();
        sh.chain.submit(b).unwrap();
    }
    let snapshot = sh.chain.clone();
    sh.l2.sync(&snapshot).unwrap();
    assert_eq!(sh.l2.state().balance(&me), amount, "deposit matured");
}

#[allow(clippy::too_many_arguments)]
fn post_ticket(
    node: &Node,
    requester: &Wallet,
    job_hash: &str,
    units: u32,
    price: u64,
    nonce: u64,
    designated: Option<srct_core::hash::Address>,
    exit_hex: Option<String>,
) -> Value {
    let ticket = srct_compute::ClaimTicket {
        version: srct_compute::ticket::TICKET_VERSION,
        network_id: NET.to_string(),
        requester: requester.address().unwrap(),
        job: hex::decode(job_hash)
            .unwrap()
            .try_into()
            .map_err(|_| "bad job hash")
            .unwrap(),
        shard: 0,
        units,
        unit_price_sat: price,
        total_sat: units as u64 * price,
        min_ram_mib: 512,
        min_units_per_sec: 100,
        min_bandwidth_kbps: 0,
        determinism: srct_compute::Determinism::Reproducible,
        required_kernel: [0u8; 32],
        min_verification: srct_compute::Verification::Receipt,
        sealed_input: false,
        input: [42u8; 32],
        deadline: 9_000,
        nonce,
        provider: designated,
    };
    let signed = srct_compute::SignedTicket::sign(ticket, requester).unwrap();
    let mut req = json!({ "ticket_hex": hex::encode(signed.encode()) });
    if let Some(exit) = exit_hex {
        req["exit_tx_hex"] = json!(exit);
    }
    let (s, body) = post(node, "/v1/compute/tickets", &req);
    assert_eq!(s, 200, "ticket post failed: {body}");
    body
}

fn build_exit(requester: &Wallet, nonce: u64, amount: u64, dest: &srct_core::hash::Address) -> String {
    let payload =
        srct_core::l2::ExitQueuePayload::build(requester, nonce, amount, *dest, EXIT_FEE).unwrap();
    let tx = srct_core::l2::L2Transaction::new(srct_core::l2::L2Payload::ExitQueue(payload));
    hex::encode(tx.serialize())
}

fn claim(node: &Node, provider: &Wallet, ticket_hash: &str, units: u32, nonce: u64) -> Value {
    let ticket_bytes = hex::decode(ticket_hash).unwrap();
    let ticket_id: [u8; 32] = ticket_bytes.try_into().map_err(|_| "bad hash").unwrap();
    let c = srct_compute::ShardClaim {
        version: srct_compute::ticket::CLAIM_VERSION,
        network_id: NET.to_string(),
        ticket: ticket_id,
        provider: provider.address().unwrap(),
        units,
        nonce,
    };
    let signed = srct_compute::SignedClaim::sign(c, provider).unwrap();
    let (s, body) = post(
        node,
        "/v1/compute/claims",
        &json!({ "claim_hex": hex::encode(signed.encode()) }),
    );
    assert_eq!(s, 200, "claim failed: {body}");
    body
}

fn settle_claim(
    node: &Node,
    provider: &Wallet,
    ticket_hash: &str,
    claim_hash: &str,
    units: u32,
    height: u64,
) -> Value {
    let t: [u8; 32] = hex::decode(ticket_hash).unwrap().try_into().map_err(|_| "x").unwrap();
    let c: [u8; 32] = hex::decode(claim_hash).unwrap().try_into().map_err(|_| "x").unwrap();
    let t_full = node
        .shared
        .lock()
        .unwrap()
        .compute_claims
        .ticket(&t)
        .cloned()
        .expect("ticket stored");
    let c_full = node
        .shared
        .lock()
        .unwrap()
        .compute_claims
        .all_claims()
        .find(|x| x.hash() == c)
        .cloned()
        .expect("claim stored");
    let r = srct_compute::ComputeReceipt::for_claim(&t_full, &c_full, units, [4u8; 32], 500, height, 7)
        .unwrap();
    let signed = srct_compute::SignedReceipt::sign(r, provider).unwrap();
    let (s, body) = post(
        node,
        "/v1/compute/receipt",
        &json!({ "receipt_hex": hex::encode(signed.encode()) }),
    );
    assert_eq!(s, 200, "settle failed: {body}");
    body
}

/// Many offers at once, nonce-distinct, all live: the pull model never had a
/// one-offer-at-a-time rule, and capacity is the only gate.
#[test]
fn provider_holds_many_offers_at_once() {
    let node = start();
    let p = provider();
    register_bond(&node, &p, 50_000, 1);
    let h1 = post_offer(&node, &p, 1, 10, 100);
    let h2 = post_offer(&node, &p, 2, 10, 100);
    let h3 = post_offer(&node, &p, 3, 10, 100);
    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    let (s, list) = get(&node, "/v1/compute/offers/list?service=ai/inference");
    assert_eq!(s, 200);
    assert_eq!(list["count"], 3, "{list}");
    // Same nonce twice is the same offer: idempotent, not a second listing.
    let h1b = post_offer(&node, &p, 1, 10, 100);
    assert_eq!(h1, h1b);
    let (s, list) = get(&node, "/v1/compute/offers/list?service=ai/inference");
    assert_eq!(s, 200);
    assert_eq!(list["count"], 3, "{list}");
}

/// An unbonded provider has zero capacity: the first offer is refused, not
/// filed. Small bond, small capacity — and the error says how to fix it.
#[test]
fn unbonded_offers_are_refused_by_capacity() {
    let node = start();
    let p = provider();
    let profile = srct_compute::DeviceProfile::new(
        srct_compute::DeviceClass::Cpu,
        srct_compute::Determinism::Reproducible,
        16_384,
        8,
        1_000,
        100_000,
        2_000,
        [0u8; 32],
    );
    let offer = srct_compute::ComputeOffer {
        version: srct_compute::OFFER_VERSION,
        network_id: NET.to_string(),
        provider: p.address().unwrap(),
        service: "ai/inference".to_string(),
        profile,
        unit_price_sat: 200,
        min_units: 1,
        max_units_per_job: 100,
        privacy: false,
        verification: srct_compute::Verification::Receipt,
        available_from: 0,
        available_until: 10_000,
        nonce: 1,
    };
    let signed = srct_compute::SignedOffer::sign(offer, &p).unwrap();
    let (s, body) = post(
        &node,
        "/v1/compute/offers",
        &json!({ "offer_hex": hex::encode(signed.encode()) }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "capacity_exceeded");
}

/// First valid claim wins; a second claim for the same ticket refuses even
/// though it is otherwise valid. No waiting, no queue-jumping.
#[test]
fn first_claim_wins_and_second_refuses() {
    let node = start();
    let r = requester();
    let fast = provider();
    let slow = wallet(13, "slow");
    register_bond(&node, &fast, 5_000, 1);
    register_bond(&node, &slow, 5_000, 2);
    let job = post_job(&node, &r, 10, 25_000);
    fund_job(&node, &r, &job, 5_000);
    let t = post_ticket(&node, &r, &job, 10, 200, 1, None, None);
    let th = t["ticket_hash"].as_str().unwrap().to_string();

    let won = claim(&node, &slow, &th, 10, 1);
    assert_eq!(won["status"], "claimed");

    // Fast provider's later claim for the same ticket: valid signature,
    // capable, funded — still refused. First wins.
    let c = srct_compute::ShardClaim {
        version: srct_compute::ticket::CLAIM_VERSION,
        network_id: NET.to_string(),
        ticket: hex::decode(&th).unwrap().try_into().map_err(|_| "x").unwrap(),
        provider: fast.address().unwrap(),
        units: 10,
        nonce: 1,
    };
    let signed = srct_compute::SignedClaim::sign(c, &fast).unwrap();
    let (s, body) = post(
        &node,
        "/v1/compute/claims",
        &json!({ "claim_hex": hex::encode(signed.encode()) }),
    );
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "claim_rejected");
}

/// A pre-signed exit fires only after a verified receipt settles, pays
/// exactly once, and cannot be redirected.
#[test]
fn preauth_exit_fires_once_after_settlement_and_never_redirects() {
    let node = start();
    let r = requester();
    let p = provider();
    register_bond(&node, &p, 5_000, 1);
    let job = post_job(&node, &r, 10, 25_000);
    fund_job(&node, &r, &job, 5_000);
    fund_l2_requester(&node, &r, 5_000_000);

    // Designated ticket with a pre-signed exit for the exact total.
    let exit = build_exit(&r, 1, 2_000, &p.address().unwrap());
    let t = post_ticket(&node, &r, &job, 10, 200, 1, Some(p.address().unwrap()), Some(exit));
    assert_eq!(t["preauth"], true);
    let th = t["ticket_hash"].as_str().unwrap().to_string();

    // Before any receipt, nothing is queued: the preauth alone moves nothing.
    let (s, payouts) = get(&node, "/v1/compute/payouts");
    assert_eq!(s, 200);
    assert_eq!(payouts["count"], 0);

    let c = claim(&node, &p, &th, 10, 1);
    let ch = c["claim_hash"].as_str().unwrap().to_string();
    let settled = settle_claim(&node, &p, &th, &ch, 10, 0);
    assert_eq!(settled["status"], "settled");
    assert_eq!(settled["auto_queued"], true, "{settled}");

    // The payout is bound: the manual claim path reports it as claimed.
    let rh = settled["receipt_hash"].as_str().unwrap().to_string();
    let (s, payouts) = get(&node, "/v1/compute/payouts");
    assert_eq!(s, 200);
    assert_eq!(payouts["payouts"][0]["claimed"], true);

    // Replaying the receipt settles nothing twice: already_settled, and the
    // preauth was consumed with the first queue, so no second exit exists.
    // Rebuild the identical receipt and post it again.
    let t_full = node
        .shared
        .lock()
        .unwrap()
        .compute_claims
        .ticket(&hex::decode(&th).unwrap().try_into().unwrap())
        .cloned()
        .expect("ticket stored");
    let claim_id: [u8; 32] = hex::decode(&ch).unwrap().try_into().unwrap();
    let c_full = node
        .shared
        .lock()
        .unwrap()
        .compute_claims
        .all_claims()
        .find(|x| x.hash() == claim_id)
        .cloned()
        .expect("claim stored");
    let r2 = srct_compute::ComputeReceipt::for_claim(&t_full, &c_full, 10, [4u8; 32], 500, 0, 7)
        .unwrap();
    let s2 = srct_compute::SignedReceipt::sign(r2, &p).unwrap();
    let (s, body) = post(
        &node,
        "/v1/compute/receipt",
        &json!({ "receipt_hex": hex::encode(s2.encode()) }),
    );
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["duplicate"], true);
    let (s, payouts2) = get(&node, "/v1/compute/payouts");
    assert_eq!(s, 200);
    assert_eq!(payouts2["count"], 1, "no duplicate payout was recorded");

    // A preauth naming the wrong destination is refused at store time —
    // it can never become a queued payment.
    let job2 = post_job(&node, &r, 10, 25_000);
    let wrong = build_exit(&r, 2, 2_000, &wallet(99, "stranger").address().unwrap());
    let ticket = srct_compute::ClaimTicket {
        version: srct_compute::ticket::TICKET_VERSION,
        network_id: NET.to_string(),
        requester: r.address().unwrap(),
        job: hex::decode(&job2).unwrap().try_into().map_err(|_| "x").unwrap(),
        shard: 0,
        units: 10,
        unit_price_sat: 200,
        total_sat: 2_000,
        min_ram_mib: 512,
        min_units_per_sec: 100,
        min_bandwidth_kbps: 0,
        determinism: srct_compute::Determinism::Reproducible,
        required_kernel: [0u8; 32],
        min_verification: srct_compute::Verification::Receipt,
        sealed_input: false,
        input: [42u8; 32],
        deadline: 9_000,
        nonce: 3,
        provider: Some(p.address().unwrap()),
    };
    let signed = srct_compute::SignedTicket::sign(ticket, &r).unwrap();
    let (s, body) = post(
        &node,
        "/v1/compute/tickets",
        &json!({ "ticket_hex": hex::encode(signed.encode()), "exit_tx_hex": wrong }),
    );
    assert_eq!(s, 400, "{body}");
    assert_eq!(body["error"], "preauth_destination_mismatch");
    let _ = rh;
}

/// Settling one shard never blocks the next: claim, settle, repeat with no
/// cooldown and no one-claim-at-a-time rule.
#[test]
fn settle_then_claim_again_without_waiting() {
    let node = start();
    let r = requester();
    let p = provider();
    register_bond(&node, &p, 50_000, 1);
    let job = post_job(&node, &r, 20, 25_000);
    fund_job(&node, &r, &job, 20_000);

    for (i, shard) in (0..2u64).enumerate() {
        let ticket = post_ticket(&node, &r, &job, 10, 200, (i + 1) as u64, None, None);
        let th = ticket["ticket_hash"].as_str().unwrap().to_string();
        let c = claim(&node, &p, &th, 10, shard + 1);
        let settled = settle_claim(&node, &p, &th, c["claim_hash"].as_str().unwrap(), 10, 0);
        assert_eq!(settled["status"], "settled");
        assert_eq!(settled["auto_queued"], false, "no preauth attached");
    }
    let (s, payouts) = get(&node, "/v1/compute/payouts");
    assert_eq!(s, 200);
    assert_eq!(payouts["count"], 2);
}
