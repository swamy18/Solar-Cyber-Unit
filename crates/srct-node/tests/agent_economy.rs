//! Agent-economy integration tests: reputation, tiers, jobs, FX, ramps, lending.
//!
//! Drives the real server over raw HTTP. Each test is an end-to-end slice:
//! - wallet tiers narrow a funded parent (max-spend / min-spend sub-wallets);
//! - a research agent hires a data agent, delivers, disputes (funds lock),
//!   and the arbitrator resolves;
//! - an issuer-signed reputation batch scores a recorded payment;
//! - a USD rate prices an exact SRCT quote and records a stablecoin-in swap;
//! - a ramp provider quotes, a user accepts, the provider settles;
//! - a lender publishes standard terms, a borrower accepts, repays, earns a
//!   limit, and auto-repays from revenue; receipt status tracks every step.
//!
//! Run with `cargo test -p srct-node --test agent_economy`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::agent::{derive_agent_id, AgentRole, Authorization, SpendPolicy, POLICY_VERSION};
use srct_core::bls::SecretKey as BlsSecretKey;
use srct_core::chain::Chain;
use srct_core::hash::address_to_hex;
use srct_core::l2::Auth;
use srct_core::params::NetworkParams;
use srct_core::payment::{build_signed_payment, MachinePayment};
use srct_core::receipt::{sign_receipt, ReceiptAnchor, ServiceReceipt, RECEIPT_VERSION};
use srct_core::service::{build_signed_request, derive_service_id, result_hash_of, RequestSpec};
use srct_core::sig::Bundle;
use srct_core::wallet::Wallet;
use srct_node::api::{spawn_with_options, SharedNode};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const NET: &str = "srct/mini";
const EXPIRES: u64 = 9_000;

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

fn policy_sigs_hex(owner: &Wallet, policy: &SpendPolicy) -> String {
    hex::encode(
        Auth::sigs_for(owner, &policy.signing_hash())
            .unwrap()
            .to_bytes(),
    )
}

fn policy_keys_hex(owner: &Wallet) -> String {
    hex::encode(Auth::keys_for(owner).unwrap().to_bytes())
}

fn credit_signed_fields(wallet: &Wallet, hash: &[u8; 32]) -> Value {
    let auth = Auth::sign(wallet, hash).unwrap();
    json!({
        "sigs_hex": hex::encode(auth.sigs.to_bytes()),
        "keys_hex": hex::encode(auth.keys.to_bytes()),
    })
}

fn credit_bond_body(wallet: &Wallet, address: &[u8; 20], amount: u64) -> Value {
    let hash = srct_core::hash::sha256_dom(
        b"srct/node-credit-bond/v1",
        &[NET.as_bytes(), address, b"post", &amount.to_le_bytes()],
    );
    let mut body = json!({
        "address_hex": address_to_hex(address),
        "action": "post",
        "amount_sat": amount,
    });
    body.as_object_mut().unwrap().extend(
        credit_signed_fields(wallet, &hash)
            .as_object()
            .unwrap()
            .clone(),
    );
    body
}

fn credit_repay_body(wallet: &Wallet, position_id: &str, amount: u64) -> Value {
    let id: [u8; 32] = hex::decode(position_id).unwrap().try_into().unwrap();
    let hash = srct_core::hash::sha256_dom(
        b"srct/node-credit-repay/v1",
        &[NET.as_bytes(), &id, &amount.to_le_bytes()],
    );
    let mut body = json!({ "position_id": position_id, "amount_sat": amount });
    body.as_object_mut().unwrap().extend(
        credit_signed_fields(wallet, &hash)
            .as_object()
            .unwrap()
            .clone(),
    );
    body
}

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
        cumulative_max_sat: 100_000,
        allowed_recipients: vec![*provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    }
}

/// Authorize + submit one payment through the API. Returns the payment + auth.
fn bridge(
    node: &Node,
    payer: &Wallet,
    policy: &SpendPolicy,
    provider_addr: &[u8; 20],
    service: [u8; 32],
    amount: u64,
    nonce: u64,
) -> (
    String,
    MachinePayment,
    Authorization,
    Bundle,
    Bundle,
    srct_core::service::PaymentRequest,
) {
    let request = build_signed_request(
        payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: *provider_addr,
            max_amount_sat: amount,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();
    let (s, granted) = post(
        node,
        "/v1/authorize",
        &json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(payer, policy),
            "policy_keys_hex": policy_keys_hex(payer),
            "request_hex": hex::encode(request.serialize()),
            "nonce": nonce,
        }),
    );
    assert_eq!(s, 200, "authorize refused: {granted}");
    let auth = Authorization::deserialize(
        &hex::decode(granted["authorization_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let payment = build_signed_payment(
        payer,
        &auth,
        NET,
        AgentRole::Machine,
        0,
        EXPIRES,
        request.request_id(),
        &[],
    )
    .unwrap();
    let sigs = Auth::sigs_for(payer, &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(payer).unwrap();
    let (s, submitted) = post(
        node,
        "/v1/payment/submit",
        &json!({
            "payment_hex": hex::encode(payment.serialize()),
            "authorization_hex": hex::encode(auth.serialize()),
            "auth_sigs_hex": hex::encode(sigs.to_bytes()),
            "auth_keys_hex": hex::encode(keys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "submit refused: {submitted}");
    (
        submitted["payment_id"].as_str().unwrap().to_string(),
        payment,
        auth,
        sigs,
        keys,
        request,
    )
}

#[test]
fn wallet_tiers_narrow_a_funded_parent() {
    let node = start();
    let owner = wallet(11, "tier-owner");
    let provider_addr = wallet(12, "tier-provider").address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"tier-svc");
    let parent = SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner.address().unwrap()),
        owner: owner.address().unwrap(),
        role: AgentRole::Machine,
        per_tx_max_sat: 20,
        window_blocks: 100,
        cumulative_max_sat: 500,
        allowed_recipients: vec![provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    let max = srct_core::tiers::build_tier(
        &parent,
        &srct_core::tiers::TierSpec {
            network_id: NET.to_string(),
            label: "max-spend".to_string(),
            per_tx_max_sat: 20,
            window_blocks: 100,
            cumulative_max_sat: 500,
            allowed_recipients: vec![provider_addr],
            allowed_services: vec![service],
            not_before_height: 0,
            expires_at_height: 5_000,
        },
    )
    .unwrap();
    let min = srct_core::tiers::build_tier(
        &max,
        &srct_core::tiers::TierSpec {
            network_id: NET.to_string(),
            label: "min-spend".to_string(),
            per_tx_max_sat: 1,
            window_blocks: 100,
            cumulative_max_sat: 50,
            allowed_recipients: vec![provider_addr],
            allowed_services: vec![service],
            not_before_height: 0,
            expires_at_height: 500,
        },
    )
    .unwrap();
    // Tiers nest: max under the parent, min under max (one child identity per
    // parent, so the min tier narrows the max tier transitively).
    for (par, tier) in [(&parent, &max), (&max, &min)] {
        let (s, b) = post(
            &node,
            "/v1/wallet/tier",
            &json!({
                "parent_policy_hex": hex::encode(par.serialize()),
                "parent_sigs_hex": policy_sigs_hex(&owner, par),
                "parent_keys_hex": policy_keys_hex(&owner),
                "tier_policy_hex": hex::encode(tier.serialize()),
                "tier_sigs_hex": policy_sigs_hex(&owner, tier),
                "tier_keys_hex": policy_keys_hex(&owner),
            }),
        );
        assert_eq!(s, 200, "tier register refused: {b}");
    }
    // A tier that widens the parent is refused.
    let mut wide = min.clone();
    wide.per_tx_max_sat = 21;
    let (s, _) = post(
        &node,
        "/v1/wallet/tier",
        &json!({
            "parent_policy_hex": hex::encode(parent.serialize()),
            "parent_sigs_hex": policy_sigs_hex(&owner, &parent),
            "parent_keys_hex": policy_keys_hex(&owner),
            "tier_policy_hex": hex::encode(wide.serialize()),
            "tier_sigs_hex": policy_sigs_hex(&owner, &wide),
            "tier_keys_hex": policy_keys_hex(&owner),
        }),
    );
    assert_eq!(s, 409);
    let (s, tiers) = get(
        &node,
        &format!("/v1/wallet/tiers/{}", hex::encode(parent.agent_id)),
    );
    assert_eq!(s, 200);
    assert_eq!(tiers["count"], 1);
    let (s, nested) = get(
        &node,
        &format!("/v1/wallet/tiers/{}", hex::encode(max.agent_id)),
    );
    assert_eq!(s, 200);
    assert_eq!(nested["count"], 1);
}

#[test]
fn job_hire_deliver_dispute_and_resolve() {
    let node = start();
    let hirer = wallet(21, "hirer");
    let worker = wallet(22, "worker");
    let hirer_addr = hirer.address().unwrap();
    let worker_addr = worker.address().unwrap();
    let payer_sk = BlsSecretKey::derive(&[23u8; 32]).unwrap();
    let payee_sk = BlsSecretKey::derive(&[24u8; 32]).unwrap();
    let arb_sk = BlsSecretKey::derive(&[25u8; 32]).unwrap();
    // The open commits the hirer's funds: the hirer authorizes every term.
    let open_msg = srct_core::jobs::open_hash(
        &hirer_addr,
        &worker_addr,
        &arb_sk.public_key(),
        &[9u8; 32],
        500,
        9_000,
        1,
    );
    let (s, opened) = post(
        &node,
        "/v1/jobs/open",
        &json!({
            "hirer_hex": address_to_hex(&hirer_addr),
            "worker_hex": address_to_hex(&worker_addr),
            "payer_bls": hex::encode(payer_sk.public_key().0),
            "payee_bls": hex::encode(payee_sk.public_key().0),
            "arbitrator": hex::encode(arb_sk.public_key().0),
            "service_hex": hex::encode([9u8; 32]),
            "amount_sat": 500,
            "deadline_height": 9_000,
            "nonce": 1,
            "hirer_sig_hex": hex::encode(payer_sk.sign(&open_msg).0),
        }),
    );
    assert_eq!(s, 200, "job open refused: {opened}");
    let job_id = opened["job_id"].as_str().unwrap().to_string();
    let escrow_id = opened["escrow_id"].as_str().unwrap().to_string();

    // Worker commits with a signature over the job id.
    let job_bytes = hex::decode(&job_id).unwrap();
    let mut job_hash = [0u8; 32];
    job_hash.copy_from_slice(&job_bytes);
    let wsigs = Auth::sigs_for(&worker, &job_hash).unwrap();
    let wkeys = Auth::keys_for(&worker).unwrap();
    let (s, b) = post(
        &node,
        &format!("/v1/jobs/{job_id}/accept"),
        &json!({
            "worker_sigs_hex": hex::encode(wsigs.to_bytes()),
            "worker_keys_hex": hex::encode(wkeys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "accept refused: {b}");

    // Deliver the dataset hash, authorized by the worker's signature over
    // the (job, result) pair.
    let result = [7u8; 32];
    let deliver_msg = srct_core::jobs::deliver_hash(&job_hash, &result);
    let dsigs = Auth::sigs_for(&worker, &deliver_msg).unwrap();
    let dkeys = Auth::keys_for(&worker).unwrap();
    let (s, b) = post(
        &node,
        &format!("/v1/jobs/{job_id}/deliver"),
        &json!({
            "result_hash_hex": hex::encode(result),
            "worker_sigs_hex": hex::encode(dsigs.to_bytes()),
            "worker_keys_hex": hex::encode(dkeys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "deliver refused: {b}");

    // Hirer disputes: funds lock.
    let dispute_sig = payer_sk.sign(&srct_core::jobs::dispute_hash(
        &job_hash,
        "dataset incomplete",
    ));
    let (s, b) = post(
        &node,
        &format!("/v1/jobs/{job_id}/dispute"),
        &json!({ "by": "hirer", "reason": "dataset incomplete", "sig_hex": hex::encode(dispute_sig.0) }),
    );
    assert_eq!(s, 200, "dispute refused: {b}");
    assert_eq!(b["held"], true);

    // Release while held is refused, even with a valid arbitrator signature.
    let (s, b) = post(
        &node,
        &format!("/v1/escrow/{escrow_id}/release"),
        &json!({ "mode": "arbiter", "arbiter_sig_hex": hex::encode([0u8; 96]) }),
    );
    assert_eq!(s, 409, "held escrow must refuse release: {b}");
    assert_eq!(b["error"], "escrow_held");

    // Arbitrator resolves to pay the worker; the hold lifts.
    let resolve_sig = arb_sk.sign(&srct_core::jobs::resolve_hash(&job_hash, true, &result));
    let (s, b) = post(
        &node,
        &format!("/v1/jobs/{job_id}/resolve"),
        &json!({
            "pay_worker": true,
            "result_hash_hex": hex::encode(result),
            "arbitrator_sig_hex": hex::encode(resolve_sig.0),
        }),
    );
    assert_eq!(s, 200, "resolve refused: {b}");
    let (s, state) = get(&node, &format!("/v1/jobs/{job_id}"));
    assert_eq!(s, 200);
    assert_eq!(state["state"], "ResolvedRelease");
    assert_eq!(state["held"], false);
}

#[test]
fn passport_scores_a_recorded_payment() {
    let node = start();
    let payer = wallet(31, "rep-payer");
    let payer_addr = payer.address().unwrap();
    let provider = wallet(32, "rep-provider");
    let provider_addr = provider.address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"rep-svc");
    let policy = machine_policy(&payer, &provider_addr, service);
    let (s, b) = post(
        &node,
        "/v1/credit/deposit",
        &json!({ "address_hex": address_to_hex(&payer_addr), "amount_sat": 100_000 }),
    );
    assert_eq!(s, 200, "deposit refused: {b}");
    let (payment_id, payment, _, _, _, signed_request) =
        bridge(&node, &payer, &policy, &provider_addr, service, 400, 1);
    // A signed receipt for the payment: the verifiable event the passport cites.
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
        request_id: signed_request.request_id(),
        result_hash: Some(result_hash_of(b"rep-output")),
        anchor: Some(ReceiptAnchor {
            height: 120,
            block_hash: [7u8; 64],
        }),
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut receipt, &provider).unwrap();
    let (s, b) = post(
        &node,
        "/v1/receipt",
        &json!({ "receipt_hex": hex::encode(receipt.serialize()) }),
    );
    assert_eq!(s, 200, "receipt refused: {b}");

    // Assemble the subject's events from node books.
    let (s, attested) = post(
        &node,
        "/v1/reputation/passport/attest",
        &json!({ "address_hex": address_to_hex(&payer_addr), "role": "machine" }),
    );
    assert_eq!(s, 200, "attest refused: {attested}");
    assert!(!attested["events"].as_array().unwrap().is_empty());

    // An issuer signs the batch; the node re-verifies every source.
    let issuer_sk = BlsSecretKey::derive(&[33u8; 32]).unwrap();
    let subject = derive_agent_id(NET, AgentRole::Machine, &payer_addr);
    let batch = srct_core::passport::PassportBatch {
        network_id: NET.to_string(),
        subject,
        events: vec![srct_core::passport::PassportEvent {
            kind: srct_core::passport::PassportEventKind::PaymentCompleted,
            height: 0,
            source: hex::decode(&payment_id)
                .unwrap()
                .try_into()
                .map(|b: [u8; 32]| b)
                .unwrap(),
            counterparty: provider_addr,
            amount_sat: 400,
        }],
        issuer: issuer_sk.public_key(),
        issued_height: 0,
        expires_height: 9_000,
        sig: srct_core::bls_checkpoint::BlsSignature([0u8; 96]),
    };
    let mut batch = batch;
    batch.sig = issuer_sk.sign(&batch.signing_hash());
    let (s, registered) = post(
        &node,
        "/v1/reputation/batch",
        &json!({
            "network_id": NET,
            "subject_hex": hex::encode(subject),
            "events": [{
                "kind": "PaymentCompleted",
                "height": 0,
                "source_hex": payment_id,
                "counterparty_hex": address_to_hex(&provider_addr),
                "amount_sat": 400,
            }],
            "issuer_hex": hex::encode(issuer_sk.public_key().0),
            "issued_height": 0,
            "expires_height": 9000,
            "sig_hex": hex::encode(batch.sig.0),
        }),
    );
    assert_eq!(s, 200, "batch refused: {registered}");
    assert!(registered["score"].as_i64().unwrap() > 0);

    // A batch pointing at nothing recorded is refused.
    let (s, _) = post(
        &node,
        "/v1/reputation/batch",
        &json!({
            "network_id": NET,
            "subject_hex": hex::encode(subject),
            "events": [{
                "kind": "PaymentCompleted",
                "height": 0,
                "source_hex": hex::encode([99u8; 32]),
                "counterparty_hex": address_to_hex(&provider_addr),
                "amount_sat": 400,
            }],
            "issuer_hex": hex::encode(issuer_sk.public_key().0),
            "issued_height": 0,
            "expires_height": 9000,
            "sig_hex": hex::encode(batch.sig.0),
        }),
    );
    assert_ne!(s, 200);

    let (s, score) = get(
        &node,
        &format!(
            "/v1/reputation/score/{}?role=machine",
            address_to_hex(&payer_addr)
        ),
    );
    assert_eq!(s, 200);
    assert!(score["score"].as_i64().unwrap() > 0);
}

#[test]
fn usd_quote_settles_in_srct_with_transparent_fees() {
    let node = start();
    let issuer_sk = BlsSecretKey::derive(&[41u8; 32]).unwrap();
    std::env::set_var("SRCT_FX_ISSUERS", hex::encode(issuer_sk.public_key().0));
    let rate = srct_core::fx::FxRate {
        base: "USDC".to_string(),
        sat_per_minor: 1_000,
        valid_from_height: 0,
        valid_until_height: 9_000,
        source: "test-oracle".to_string(),
        issuer: issuer_sk.public_key(),
        sig: srct_core::bls_checkpoint::BlsSignature([0u8; 96]),
    };
    let mut rate = rate;
    rate.sig = issuer_sk.sign(&rate.signing_hash());
    let (s, b) = post(
        &node,
        "/v1/fx/rates",
        &json!({
            "base": "USDC",
            "sat_per_minor": 1_000,
            "valid_from_height": 0,
            "valid_until_height": 9000,
            "source": "test-oracle",
            "issuer_hex": hex::encode(issuer_sk.public_key().0),
            "sig_hex": hex::encode(rate.sig.0),
        }),
    );
    assert_eq!(s, 200, "rate refused: {b}");

    // $1.00 at 1000 sat/cent, 1% fee, 0.5% slippage → 101_500 due.
    let (s, quote) = post(
        &node,
        "/v1/fx/quote",
        &json!({ "base": "USDC", "amount_minor": 100, "fee_bps": 100, "slippage_bps": 50, "ttl_blocks": 60 }),
    );
    assert_eq!(s, 200, "quote refused: {quote}");
    assert_eq!(quote["sat_due"], 101_500);
    assert_eq!(quote["fee_sat"], 1_000);

    // Stablecoin-in: the agent holds USDC off-protocol, settles SRCT on market.
    // `fee_sat` is the all-in surcharge the node binds: sat_due must equal
    // gross-at-live-rate plus fee (100*1000 + 1500), so the quote's slippage
    // headroom rides inside the declared fee rather than beside it.
    let payer_addr = wallet(42, "fx-payer").address().unwrap();
    let (s, swap) = post(
        &node,
        "/v1/fx/swap",
        &json!({
            "payer_hex": address_to_hex(&payer_addr),
            "role": "machine",
            "stable_asset": "USDC",
            "stable_minor": 100,
            "sat_due": 101_500,
            "fee_sat": 1_500,
            "rate_sat_per_minor": 1_000,
            "expires_height": 60,
            "stable_ref": "usdc-tx-abc",
            "nonce": 1,
        }),
    );
    assert_eq!(s, 200, "swap refused: {swap}");
    assert!(swap["swap_id"].as_str().unwrap().len() == 64);
    std::env::remove_var("SRCT_FX_ISSUERS");
}

#[test]
fn ramp_quote_intent_and_provider_settle() {
    let node = start();
    let provider = wallet(51, "ramp-provider");
    let provider_addr = provider.address().unwrap();
    let quote = srct_core::ramp::RampQuote {
        network_id: NET.to_string(),
        provider: provider_addr,
        direction: srct_core::ramp::RampDirection::StableToSrct,
        asset: "USDC".to_string(),
        asset_minor: 100,
        sat_amount: 101_500,
        fee_sat: 1_000,
        expires_height: 9_000,
        nonce: 1,
    };
    let (sigs, keys) = srct_core::ramp::sign_quote(&provider, &quote).unwrap();
    let (s, b) = post(
        &node,
        "/v1/ramp/quote",
        &json!({
            "network_id": NET,
            "provider_hex": address_to_hex(&provider_addr),
            "direction": "stable_to_srct",
            "asset": "USDC",
            "asset_minor": 100,
            "sat_amount": 101_500,
            "fee_sat": 1_000,
            "expires_height": 9000,
            "nonce": 1,
            "provider_sigs_hex": hex::encode(sigs.to_bytes()),
            "provider_keys_hex": hex::encode(keys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "ramp quote refused: {b}");
    let quote_id = b["quote_id"].as_str().unwrap().to_string();

    let (s, quotes) = get(&node, "/v1/ramp/quotes?direction=stable_to_srct");
    assert_eq!(s, 200);
    assert_eq!(quotes["count"], 1);

    let user_addr = wallet(52, "ramp-user").address().unwrap();
    let (s, intent) = post(
        &node,
        "/v1/ramp/intent",
        &json!({ "quote_id": quote_id, "user_hex": address_to_hex(&user_addr), "fill_ref": "bank-ref-1" }),
    );
    assert_eq!(s, 200, "intent refused: {intent}");
    let intent_id = intent["intent_id"].as_str().unwrap().to_string();

    // Provider closes as filled, signed over
    // (intent id + outcome + fill ref): the receipt reference is covered.
    let id_bytes = hex::decode(&intent_id).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&id_bytes);
    msg.extend_from_slice(b"filled");
    msg.extend_from_slice(&("bank-ref-1-done".len() as u64).to_le_bytes());
    msg.extend_from_slice(b"bank-ref-1-done");
    let digest = srct_core::hash::sha256_dom(b"srct/ramp-settle/v1", &[&msg]);
    let fsigs = Auth::sigs_for(&provider, &digest).unwrap();
    let fkeys = Auth::keys_for(&provider).unwrap();
    let (s, settled) = post(
        &node,
        &format!("/v1/ramp/intent/{intent_id}/settle"),
        &json!({
            "outcome": "filled",
            "fill_ref": "bank-ref-1-done",
            "provider_sigs_hex": hex::encode(fsigs.to_bytes()),
            "provider_keys_hex": hex::encode(fkeys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "settle refused: {settled}");
    let (s, intents) = get(&node, "/v1/ramp/intents");
    assert_eq!(s, 200);
    assert_eq!(intents["intents"][0]["filled"], true);
}

#[test]
fn ramp_lists_page_deterministically() {
    let node = start();
    let provider = wallet(53, "ramp-pager");
    let provider_addr = provider.address().unwrap();
    // Three live quotes; distinct nonces give distinct ids.
    for nonce in 1..=3u64 {
        let quote = srct_core::ramp::RampQuote {
            network_id: NET.to_string(),
            provider: provider_addr,
            direction: srct_core::ramp::RampDirection::StableToSrct,
            asset: "USDC".to_string(),
            asset_minor: 100,
            sat_amount: 101_500,
            fee_sat: 1_000 * nonce,
            expires_height: 9_000,
            nonce,
        };
        let (sigs, keys) = srct_core::ramp::sign_quote(&provider, &quote).unwrap();
        let (s, b) = post(
            &node,
            "/v1/ramp/quote",
            &json!({
                "network_id": NET,
                "provider_hex": address_to_hex(&provider_addr),
                "direction": "stable_to_srct",
                "asset": "USDC",
                "asset_minor": 100,
                "sat_amount": 101_500,
                "fee_sat": 1_000 * nonce,
                "expires_height": 9000,
                "nonce": nonce,
                "provider_sigs_hex": hex::encode(sigs.to_bytes()),
                "provider_keys_hex": hex::encode(keys.to_bytes()),
            }),
        );
        assert_eq!(s, 200, "ramp quote refused: {b}");
    }

    // Page 1 of 2.
    let (s, p1) = get(&node, "/v1/ramp/quotes?direction=stable_to_srct&limit=2");
    assert_eq!(s, 200);
    assert_eq!(p1["total"], 3);
    assert_eq!(p1["quotes"].as_array().unwrap().len(), 2);
    let cursor = p1["next_cursor"]
        .as_u64()
        .expect("a non-final page must carry next_cursor");
    // Same page twice: identical order (quote-id order, not HashMap order).
    let (s, p1b) = get(&node, "/v1/ramp/quotes?direction=stable_to_srct&limit=2");
    assert_eq!(s, 200);
    assert_eq!(p1["quotes"], p1b["quotes"], "pages must be deterministic");
    // Page 2: the remaining quote, cursor closed at the end.
    let (s, p2) = get(
        &node,
        &format!("/v1/ramp/quotes?direction=stable_to_srct&limit=2&cursor={cursor}"),
    );
    assert_eq!(s, 200);
    assert_eq!(p2["quotes"].as_array().unwrap().len(), 1);
    assert!(
        p2["next_cursor"].is_null(),
        "last page must close the cursor"
    );
    // Union covers all three, disjoint.
    let mut ids: Vec<String> = p1["quotes"]
        .as_array()
        .unwrap()
        .iter()
        .chain(p2["quotes"].as_array().unwrap().iter())
        .map(|q| q["quote_id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3, "pages must partition the registry");

    // Intents page the same way: two intents on the first quote.
    let first_quote = &ids[0];
    for (n, seed) in [(54u8, "ramp-intent-a"), (55u8, "ramp-intent-b")] {
        let user = wallet(n, seed).address().unwrap();
        let (s, intent) = post(
            &node,
            "/v1/ramp/intent",
            &json!({ "quote_id": first_quote, "user_hex": address_to_hex(&user), "fill_ref": seed }),
        );
        assert_eq!(s, 200, "intent refused: {intent}");
    }
    let (s, i1) = get(&node, "/v1/ramp/intents?limit=1");
    assert_eq!(s, 200);
    assert_eq!(i1["total"], 2);
    let icursor = i1["next_cursor"]
        .as_u64()
        .expect("a non-final page must carry next_cursor");
    let (s, i2) = get(&node, &format!("/v1/ramp/intents?limit=1&cursor={icursor}"));
    assert_eq!(s, 200);
    assert!(
        i2["next_cursor"].is_null(),
        "last page must close the cursor"
    );
    assert_ne!(
        i1["intents"][0]["intent_id"], i2["intents"][0]["intent_id"],
        "pages must not repeat"
    );
}

#[test]
fn productive_lending_from_offer_to_autorepay() {
    let node = start();
    let lender = wallet(61, "lender");
    let lender_addr = lender.address().unwrap();
    let offer = srct_core::lending::LoanOffer {
        network_id: NET.to_string(),
        lender: lender_addr,
        min_principal_sat: 100,
        max_principal_sat: 10_000,
        rate_bps_per_window: 500,
        window_blocks: 100,
        base_collateral_bps: 10_000,
        max_discount_bps: 2_000,
        bond_ratio_bps: 2_000,
        min_collateral_bps: 8_000,
        expires_height: 9_000,
        nonce: 1,
    };
    let osigs = Auth::sigs_for(&lender, &offer.id()).unwrap();
    let okeys = Auth::keys_for(&lender).unwrap();
    let (s, b) = post(
        &node,
        "/v1/loans/offers",
        &json!({
            "network_id": NET,
            "lender_hex": address_to_hex(&lender_addr),
            "min_principal_sat": 100,
            "max_principal_sat": 10000,
            "rate_bps_per_window": 500,
            "window_blocks": 100,
            "base_collateral_bps": 10000,
            "max_discount_bps": 2000,
            "bond_ratio_bps": 2000,
            "min_collateral_bps": 8000,
            "expires_height": 9000,
            "nonce": 1,
            "lender_sigs_hex": hex::encode(osigs.to_bytes()),
            "lender_keys_hex": hex::encode(okeys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "offer refused: {b}");
    let offer_id = b["offer_id"].as_str().unwrap().to_string();

    let (s, offers) = get(&node, "/v1/loans/offers/list?principal=1000");
    assert_eq!(s, 200);
    assert_eq!(offers["count"], 1);

    // Borrower funds bond + collateral, then takes the standard terms.
    let borrower = wallet(62, "borrower");
    let borrower_addr = borrower.address().unwrap();
    for (path, body) in [
        (
            "/v1/credit/deposit",
            json!({ "address_hex": address_to_hex(&borrower_addr), "amount_sat": 5_000 }),
        ),
        (
            "/v1/credit/bond",
            credit_bond_body(&borrower, &borrower_addr, 200),
        ),
    ] {
        let (s, b) = post(&node, path, &body);
        assert_eq!(s, 200, "{path} refused: {b}");
    }
    let accept_msg = |amount: u64| {
        srct_core::lending::accept_hash(
            &hex::decode(&offer_id)
                .unwrap()
                .try_into()
                .map(|b: [u8; 32]| b)
                .unwrap(),
            &borrower_addr,
            amount,
            200,
            9000,
        )
    };
    let asigs = Auth::sigs_for(&borrower, &accept_msg(1000)).unwrap();
    let akeys = Auth::keys_for(&borrower).unwrap();
    let (s, accepted) = post(
        &node,
        "/v1/loans/accept",
        &json!({
            "offer_id": offer_id,
            "borrower_hex": address_to_hex(&borrower_addr),
            "bond_sat": 200,
            "amount_sat": 1000,
            "deadline_height": 9000,
            "borrower_sigs_hex": hex::encode(asigs.to_bytes()),
            "borrower_keys_hex": hex::encode(akeys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "accept refused: {accepted}");
    assert_eq!(accepted["required_collateral_sat"], 800);
    let position_id = accepted["position_id"].as_str().unwrap().to_string();

    // Dashboard prices the exposure; collateral covers the debt.
    let (s, dash) = get(&node, "/v1/lending/dashboard");
    assert_eq!(s, 200);
    assert_eq!(dash["open_positions"], 1);
    let (s, col) = get(&node, &format!("/v1/lending/collateral/{position_id}"));
    assert_eq!(s, 200);
    assert_eq!(col["debt_sat"], 1_000);

    // Repay in full: history records it, the limit becomes nonzero.
    let (s, b) = post(
        &node,
        "/v1/credit/repay",
        &credit_repay_body(&borrower, &position_id, 1000),
    );
    assert_eq!(s, 200, "repay refused: {b}");
    let (s, history) = get(
        &node,
        &format!("/v1/lending/borrower/{}", address_to_hex(&borrower_addr)),
    );
    assert_eq!(s, 200);
    assert_eq!(history["repaid_positions"], 1);
    assert!(history["suggested_max_principal_sat"].as_u64().unwrap() > 0);
    let (s, limit) = get(
        &node,
        &format!("/v1/lending/limit/{}", address_to_hex(&borrower_addr)),
    );
    assert_eq!(s, 200);
    assert!(limit["suggested_max_principal_sat"].as_u64().unwrap() > 0);

    // Second loan + standing auto-repay: revenue pays the loan down by itself.
    let asigs2 = Auth::sigs_for(&borrower, &accept_msg(1500)).unwrap();
    let akeys2 = Auth::keys_for(&borrower).unwrap();
    let (s, accepted2) = post(
        &node,
        "/v1/loans/accept",
        &json!({
            "offer_id": offer_id,
            "borrower_hex": address_to_hex(&borrower_addr),
            "bond_sat": 200,
            "amount_sat": 1500,
            "deadline_height": 9000,
            "borrower_sigs_hex": hex::encode(asigs2.to_bytes()),
            "borrower_keys_hex": hex::encode(akeys2.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "second accept refused: {accepted2}");
    let position2 = accepted2["position_id"].as_str().unwrap().to_string();
    let (instr, isigs, ikeys) = srct_core::lending::sign_standing_repay(
        &borrower,
        NET,
        hex::decode(&position2)
            .unwrap()
            .try_into()
            .map(|b: [u8; 32]| b)
            .unwrap(),
        5_000,
        10_000,
        9_000,
        1,
    )
    .unwrap();
    let (s, b) = post(
        &node,
        "/v1/lending/autorepay",
        &json!({
            "borrower_hex": address_to_hex(&borrower_addr),
            "position_id": position2,
            "pct_bps": instr.pct_bps,
            "cap_sat": instr.cap_sat,
            "expires_height": instr.expires_height,
            "nonce": instr.nonce,
            "sigs_hex": hex::encode(isigs.to_bytes()),
            "keys_hex": hex::encode(ikeys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "autorepay register refused: {b}");
    let (s, deposited) = post(
        &node,
        "/v1/credit/deposit",
        &json!({ "address_hex": address_to_hex(&borrower_addr), "amount_sat": 1000 }),
    );
    assert_eq!(s, 200, "deposit refused: {deposited}");
    assert_eq!(deposited["autorepay"]["repaid_sat"], 500);

    // Receipt status tracks a payment end to end.
    let payer = wallet(63, "status-payer");
    let payer_addr = payer.address().unwrap();
    let provider_addr = wallet(64, "status-provider").address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"status-svc");
    let policy = machine_policy(&payer, &provider_addr, service);
    let (s, deposited) = post(
        &node,
        "/v1/credit/deposit",
        &json!({ "address_hex": address_to_hex(&payer_addr), "amount_sat": 100_000 }),
    );
    assert_eq!(s, 200, "deposit refused: {deposited}");
    let (payment_id, payment, _, _, _, signed_request) =
        bridge(&node, &payer, &policy, &provider_addr, service, 400, 1);
    let (s, status) = get(&node, &format!("/v1/payments/{payment_id}/receipt_status"));
    assert_eq!(s, 200);
    assert_eq!(status["recorded"], true);
    assert_eq!(status["receipt_present"], false);
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
        request_id: signed_request.request_id(),
        result_hash: Some(result_hash_of(b"status-output")),
        anchor: Some(ReceiptAnchor {
            height: 120,
            block_hash: [7u8; 64],
        }),
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut receipt, &wallet(64, "status-provider")).unwrap();
    let (s, b) = post(
        &node,
        "/v1/receipt",
        &json!({ "receipt_hex": hex::encode(receipt.serialize()) }),
    );
    assert_eq!(s, 200, "receipt refused: {b}");
    let (s, status) = get(&node, &format!("/v1/payments/{payment_id}/receipt_status"));
    assert_eq!(s, 200);
    assert_eq!(status["receipt_present"], true);
}
