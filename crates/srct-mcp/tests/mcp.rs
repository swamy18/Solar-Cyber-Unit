//! `srct-mcp` tests — roadmap §10.
//!
//! The properties under test are the ones that make an MCP surface safe in
//! front of an autonomous agent:
//!
//! 1. it cannot mint authority — every authorization goes through the same
//!    `PolicyBook` the protocol uses, and a replayed nonce is refused;
//! 2. it cannot fabricate or launder a receipt — a receipt that verifies but
//!    does not bind to the presented payment is refused by name;
//! 3. malformed input is a named refusal, never a partial action or a panic;
//! 4. it holds no key material — the signing hash is returned for the caller
//!    to sign, and nothing here can produce a signature.
//!
//! Run with `cargo test -p srct-mcp`.

use serde_json::json;

use srct_core::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
use srct_core::hash::hash_to_hex;
use srct_core::payment::build_signed_payment;
use srct_core::receipt::{sign_receipt, ServiceReceipt, RECEIPT_VERSION};
use srct_core::service::{build_signed_request, derive_service_id, result_hash_of, RequestSpec};
use srct_core::wallet::Wallet;
use srct_mcp::SolarCyberUnitMcp;

const NET: &str = "srct/mini";
const HEIGHT: u64 = 50;
const EXPIRES: u64 = 9_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "mcp-test").unwrap()
}

fn policy(service: [u8; 32], provider: [u8; 20]) -> SpendPolicy {
    let owner = wallet(1).address().unwrap();
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
        owner,
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
    }
}

/// The pieces a caller would assemble before talking to the surface.
struct Fixture {
    policy: SpendPolicy,
    request: srct_core::service::PaymentRequest,
}

fn fixture() -> Fixture {
    let payer = wallet(1);
    let provider = wallet(2).address().unwrap();
    let service = derive_service_id(NET, &provider, b"srct-llm");
    let policy = policy(service, provider);
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
    Fixture { policy, request }
}

fn authorize_request_json(f: &Fixture, nonce: u64) -> serde_json::Value {
    json!({
        "op": "authorize",
        "network_id": NET,
        "height": HEIGHT,
        "nonce": nonce,
        "policy_hex": hex::encode(f.policy.serialize()),
        "request_hex": hex::encode(f.request.serialize()),
    })
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[test]
fn capabilities_are_advertised_and_unknown_ops_are_refused() {
    let mcp = SolarCyberUnitMcp::new();
    let caps = mcp.capabilities();
    assert!(caps.contains(&"authorize"));
    assert!(caps.contains(&"inspect.receipt"));
    assert!(caps.contains(&"node.status"));

    let mut mcp = SolarCyberUnitMcp::new();
    let err = mcp
        .handle(&json!({ "op": "no.such.thing" }))
        .expect_err("an unknown op must be refused");
    assert_eq!(err.code, "bad_request");

    let err = mcp
        .handle(&json!({ "not_op": true }))
        .expect_err("a missing op must be refused");
    assert_eq!(err.code, "bad_request");
}

#[test]
fn authorize_returns_bytes_and_a_signing_hash_without_a_key() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();

    let out = mcp.handle(&authorize_request_json(&f, 1)).expect("grant");
    assert_eq!(out["amount_sat"], 400);
    assert_eq!(out["nonce"], 1);
    assert_eq!(out["height"], HEIGHT);

    // The returned bytes decode, and the signing hash matches the bytes —
    // i.e. the caller really can sign what it was handed.
    let bytes = hex::decode(out["authorization_hex"].as_str().unwrap()).unwrap();
    let auth = srct_core::agent::Authorization::deserialize(&bytes).unwrap();
    assert_eq!(hash_to_hex(&auth.signing_hash()), out["signing_hash"]);
}

#[test]
fn a_replayed_nonce_is_refused_by_the_policy_engine() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();

    mcp.handle(&authorize_request_json(&f, 4)).expect("grant");
    let err = mcp
        .handle(&authorize_request_json(&f, 4))
        .expect_err("a replayed nonce must be refused");
    assert_eq!(err.code, "policy_refused");

    // A policy the request does not name is a binding failure.
    let other = policy([9u8; 32], wallet(3).address().unwrap());
    let err = mcp
        .handle(&json!({
            "op": "authorize",
            "network_id": NET,
            "height": HEIGHT,
            "nonce": 5,
            "policy_hex": hex::encode(other.serialize()),
            "request_hex": hex::encode(f.request.serialize()),
        }))
        .expect_err("a mismatched policy must be refused");
    assert_eq!(err.code, "session_binding");
}

#[test]
fn malformed_authorization_input_is_refused_not_panicked() {
    let mut mcp = SolarCyberUnitMcp::new();
    let err = mcp
        .handle(&json!({
            "op": "authorize",
            "network_id": NET,
            "height": HEIGHT,
            "nonce": 1,
            "policy_hex": "zz",
            "request_hex": "zz",
        }))
        .expect_err("bad hex must be refused");
    assert_eq!(err.code, "bad_request");

    // Missing required fields are named.
    let err = mcp
        .handle(&json!({ "op": "authorize", "network_id": NET }))
        .expect_err("missing fields must be refused");
    assert_eq!(err.code, "bad_request");
}

// ---------------------------------------------------------------------------
// Offline verification
// ---------------------------------------------------------------------------

fn authorize_and_pay(f: &Fixture) -> (srct_core::payment::MachinePayment, ServiceReceipt) {
    let mut book = srct_core::agent::PolicyBook::default();
    let auth =
        srct_core::service::authorize_request(&mut book, &f.policy, NET, &f.request, HEIGHT, 1)
            .unwrap();
    let payment = build_signed_payment(
        &wallet(1),
        &auth,
        NET,
        AgentRole::Machine,
        2_000,
        EXPIRES,
        f.request.request_id(),
        &[],
    )
    .unwrap();
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
        request_id: f.request.request_id(),
        result_hash: Some(result_hash_of(b"output")),
        anchor: None,
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut receipt, &wallet(2)).unwrap();
    (payment, receipt)
}

#[test]
fn inspect_request_payment_and_receipt_verify_offline() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    let (payment, receipt) = authorize_and_pay(&f);

    let out = mcp
        .handle(&json!({
            "op": "inspect.request",
            "network_id": NET,
            "height": HEIGHT,
            "request_hex": hex::encode(f.request.serialize()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);
    assert_eq!(out["amount_sat"], serde_json::Value::Null);
    assert_eq!(out["max_amount_sat"], 400);
    assert_eq!(out["request_id"], hash_to_hex(&f.request.request_id()));

    let out = mcp
        .handle(&json!({
            "op": "inspect.payment",
            "network_id": NET,
            "height": HEIGHT,
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);
    assert_eq!(out["payment_id"], hash_to_hex(&payment.signing_hash()));

    let out = mcp
        .handle(&json!({
            "op": "inspect.receipt",
            "network_id": NET,
            "receipt_hex": hex::encode(receipt.serialize()),
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);
    assert_eq!(out["bound_to_payment"], true);
    assert_eq!(out["receipt_id"], hash_to_hex(&receipt.receipt_id()));
}

#[test]
fn a_receipt_for_another_payment_is_refused_not_merely_verified() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    let (payment, receipt) = authorize_and_pay(&f);

    // A second, independently valid receipt for a *different* payment.
    let other_payer = wallet(5);
    let mut other = receipt.clone();
    other.payer = other_payer.address().unwrap();
    other.agent_id = derive_agent_id(NET, AgentRole::Machine, &other.payer);
    other.payment_id = [0x77u8; 32];
    other.request_id = [0x88u8; 32];
    sign_receipt(&mut other, &wallet(2)).unwrap();

    // Presenting `other` alongside the first payment must fail the binding
    // check even though `other` verifies on its own.
    let err = mcp
        .handle(&json!({
            "op": "inspect.receipt",
            "network_id": NET,
            "receipt_hex": hex::encode(other.serialize()),
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .expect_err("a receipt must not verify against an unrelated payment");
    assert_eq!(err.code, "receipt_not_bound");
}

#[test]
fn a_payment_on_another_network_is_refused() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    let (payment, _) = authorize_and_pay(&f);
    let err = mcp
        .handle(&json!({
            "op": "inspect.payment",
            "network_id": "srct/testnet",
            "height": HEIGHT,
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .expect_err("network binding must hold");
    assert_eq!(err.code, "payment_invalid");
}

#[test]
fn verify_authorization_uses_the_shared_owner_binding() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    let mut book = srct_core::agent::PolicyBook::default();
    let auth =
        srct_core::service::authorize_request(&mut book, &f.policy, NET, &f.request, HEIGHT, 1)
            .unwrap();
    let sigs = srct_core::l2::Auth::sigs_for(&wallet(1), &auth.signing_hash()).unwrap();
    let keys = srct_core::l2::Auth::keys_for(&wallet(1)).unwrap();

    let out = mcp
        .handle(&json!({
            "op": "verify.authorization",
            "authorization_hex": hex::encode(auth.serialize()),
            "sigs_hex": hex::encode(sigs.to_bytes()),
            "keys_hex": hex::encode(keys.to_bytes()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);

    // The same bundle presented by a *different* key must be refused: the
    // verification binds the keys to the owner before looking at signatures.
    let attacker_keys = srct_core::l2::Auth::keys_for(&wallet(9)).unwrap();
    let err = mcp
        .handle(&json!({
            "op": "verify.authorization",
            "authorization_hex": hex::encode(auth.serialize()),
            "sigs_hex": hex::encode(sigs.to_bytes()),
            "keys_hex": hex::encode(attacker_keys.to_bytes()),
        }))
        .expect_err("a third-party key bundle must not authenticate another owner's grant");
    assert_eq!(err.code, "authorization_invalid");
}

// ---------------------------------------------------------------------------
// Node transport
// ---------------------------------------------------------------------------

#[test]
fn a_bad_endpoint_is_a_transport_error_not_a_panic() {
    let mut mcp = SolarCyberUnitMcp::new();
    let err = mcp
        .handle(&json!({ "op": "node.status", "endpoint": "not-an-endpoint" }))
        .expect_err("a malformed endpoint must be refused");
    assert_eq!(err.code, "bad_request");

    // A well-formed but closed port is transport trouble, clearly labelled.
    let err = mcp
        .handle(&json!({ "op": "node.status", "endpoint": "127.0.0.1:1" }))
        .expect_err("an unreachable node is a transport error");
    assert_eq!(err.code, "transport");
}

// ---------------------------------------------------------------------------
// Agent authority and credit, read side
// ---------------------------------------------------------------------------

/// The surface can read a published-grant payload: the terms, the spender
/// the grant names, and the hash the owner signs. It cannot sign it.
#[test]
fn it_reads_a_published_grant_without_signing_it() {
    let mut mcp = SolarCyberUnitMcp::new();
    let owner = wallet(1);
    let agent = wallet(2);
    let grant = policy([0x11u8; 32], wallet(3).address().unwrap());
    let payload =
        srct_core::l2::PolicyPayload::build_from_policy(&owner, &grant, agent.address().unwrap())
            .unwrap();
    let out = mcp
        .handle(&json!({
            "op": "inspect.policy",
            "payload_hex": hex::encode(payload.serialize()),
        }))
        .expect("the grant is readable");
    assert_eq!(out["owner"], hex::encode(owner.address().unwrap()));
    assert_eq!(out["spender"], hex::encode(agent.address().unwrap()));
    assert_eq!(out["per_tx_max_sat"], 600);
    assert_eq!(out["cumulative_max_sat"], 1_000);
    assert!(!out["signing_hash"].as_str().unwrap_or_default().is_empty());
    // The hash is the owner's to sign, not the surface's.
    assert!(out.get("signature").is_none());
}

/// The surface can read a spend under a grant, and a credit opening: the
/// terms, the derived position id, and the hash the lender signs.
#[test]
fn it_reads_a_spend_and_a_credit_opening() {
    let mut mcp = SolarCyberUnitMcp::new();
    let agent = wallet(2);
    let spend = srct_core::l2::AgentSpendPayload::build(
        &agent,
        [0x33u8; 32],
        7,
        wallet(3).address().unwrap(),
        400,
        None,
    )
    .unwrap();
    let out = mcp
        .handle(&json!({
            "op": "inspect.agent_spend",
            "payload_hex": hex::encode(spend.serialize()),
        }))
        .expect("the spend is readable");
    assert_eq!(out["agent"], hex::encode(agent.address().unwrap()));
    assert_eq!(out["amount_sat"], 400);
    assert_eq!(out["nonce"], 7);

    let lender = wallet(1);
    let credit = srct_core::l2::CreditOpenPayload::build(
        &lender,
        wallet(2).address().unwrap(),
        1_000,
        1_000,
        100,
        100,
        9_000,
        1,
    )
    .unwrap();
    let out = mcp
        .handle(&json!({
            "op": "inspect.credit",
            "payload_hex": hex::encode(credit.serialize()),
        }))
        .expect("the credit opening is readable");
    assert_eq!(out["lender"], hex::encode(lender.address().unwrap()));
    assert_eq!(out["amount_sat"], 1_000);
    assert_eq!(out["collateral_sat"], 1_000);
    assert_eq!(
        out["position_id"],
        hash_to_hex(&credit.derived_position_id())
    );
}

/// The new operations are advertised, so an agent never guesses a name.
#[test]
fn the_authority_operations_are_advertised() {
    let mcp = SolarCyberUnitMcp::new();
    let caps = mcp.capabilities();
    for expected in ["inspect.policy", "inspect.agent_spend", "inspect.credit"] {
        assert!(caps.contains(&expected), "{expected} must be advertised");
    }
}

/// Malformed input is a named refusal, never a panic and never a partial
/// action - the same discipline every other operation follows.
#[test]
fn a_malformed_grant_is_refused_by_name() {
    let mut mcp = SolarCyberUnitMcp::new();
    let err = mcp
        .handle(&json!({ "op": "inspect.policy", "payload_hex": "00ff" }))
        .expect_err("garbage is refused");
    assert_eq!(err.code, "bad_request");
}

// ---------------------------------------------------------------------------
// Wallet guard + portable policy surface
// ---------------------------------------------------------------------------

fn guard_json(f: &Fixture, amount: u64, height: u64, expires: u64) -> serde_json::Value {
    json!({
        "op": "wallet.guard",
        "max_amount_sat": 600,
        "allowed_recipients_hex": [hex::encode(f.policy.allowed_recipients[0])],
        "allowed_services_hex": [hex::encode(f.policy.allowed_services[0])],
        "amount_sat": amount,
        "recipient_hex": hex::encode(f.policy.allowed_recipients[0]),
        "service_hex": hex::encode(f.policy.allowed_services[0]),
        "height": height,
        "expires_at_height": expires,
    })
}

#[test]
fn the_guard_ops_are_advertised() {
    let mcp = SolarCyberUnitMcp::new();
    for expected in [
        "wallet.guard",
        "policy.decide",
        "policy.export",
        "policy.verify",
        "delegation.prove",
        "delegation.verify",
        "auth.bind",
        "auth.verify_bound",
        "audit.verify",
    ] {
        assert!(
            mcp.capabilities().contains(&expected),
            "{expected} must be advertised"
        );
    }
}

#[test]
fn the_guard_allows_denies_and_gates_approval() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    // Inside the budget and the window: allow.
    let out = mcp
        .handle(&guard_json(&f, 400, HEIGHT, HEIGHT + 10))
        .expect("fits the budget");
    assert_eq!(out["decision"], "allow");
    // Over budget: refused by name, nothing signed.
    let mut over = guard_json(&f, 700, HEIGHT, HEIGHT + 10);
    over["approval_threshold_sat"] = json!(10_000);
    let err = mcp.handle(&over).expect_err("over budget");
    assert_eq!(err.code, "guard_refused");
    // Inside the budget but above the approval threshold: gated, not refused.
    let mut gated = guard_json(&f, 400, HEIGHT, HEIGHT + 10);
    gated["approval_threshold_sat"] = json!(100);
    let out = mcp.handle(&gated).expect("gated, not refused");
    assert_eq!(out["decision"], "needs_approval");
    // A stale window refuses even when the budget fits.
    let err = mcp
        .handle(&guard_json(&f, 400, HEIGHT + 10, HEIGHT + 10))
        .expect_err("past expiry");
    assert_eq!(err.code, "guard_refused");
}

#[test]
fn policy_decide_matches_the_engine_without_committing() {
    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    let base = json!({
        "op": "policy.decide",
        "network_id": NET,
        "height": HEIGHT,
        "policy_hex": hex::encode(f.policy.serialize()),
        "agent_id_hex": hex::encode(f.policy.agent_id),
        "recipient_hex": hex::encode(f.policy.allowed_recipients[0]),
        "service_hex": hex::encode(f.policy.allowed_services[0]),
    });
    let mut allow = base.clone();
    allow["amount_sat"] = json!(400);
    assert_eq!(mcp.handle(&allow).unwrap()["decision"], "allow");
    // A spend the policy forbids is denied by name.
    let mut deny = base.clone();
    deny["amount_sat"] = json!(50_000);
    let err = mcp.handle(&deny).expect_err("over per-tx");
    assert_eq!(err.code, "policy_refused");
    // The decide path commits nothing: the same authorization still works.
    mcp.handle(&authorize_request_json(&f, 1))
        .expect("decide must not consume the nonce");
    mcp.handle(&authorize_request_json(&f, 1))
        .expect_err("the nonce is still fresh, so a replay refuses");
}

#[test]
fn policy_export_verify_and_delegation_prove_round_trip() {
    use srct_core::agent::{derive_sub_agent_id, AgentRole};
    use srct_core::l2::Auth;

    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    let owner = wallet(1);
    let keys_hex = hex::encode(Auth::keys_for(&owner).unwrap().to_bytes());
    let sigs_hex = hex::encode(
        Auth::sigs_for(&owner, &f.policy.signing_hash())
            .unwrap()
            .to_bytes(),
    );
    let exported = mcp
        .handle(&json!({
            "op": "policy.export",
            "policy_hex": hex::encode(f.policy.serialize()),
            "sigs_hex": sigs_hex,
            "keys_hex": keys_hex,
        }))
        .expect("a signed grant exports");
    assert_eq!(
        exported["owner"],
        srct_core::hash::address_to_hex(&owner.address().unwrap())
    );

    let verified = mcp
        .handle(&json!({
            "op": "policy.verify",
            "portable_json": exported.to_string(),
        }))
        .expect("the export verifies anywhere");
    assert_eq!(verified["valid"], true);

    // A narrowed child under the same owner proves as one ancestry.
    let child = SpendPolicy {
        agent_id: derive_sub_agent_id(NET, &f.policy.agent_id, AgentRole::Machine),
        parent_agent_id: Some(f.policy.agent_id),
        per_tx_max_sat: 300,
        window_blocks: 5,
        cumulative_max_sat: 500,
        not_before_height: 0,
        expires_at_height: 5_000,
        ..f.policy.clone()
    };
    let child_sigs = hex::encode(
        Auth::sigs_for(&owner, &child.signing_hash())
            .unwrap()
            .to_bytes(),
    );
    let proof = mcp
        .handle(&json!({
            "op": "delegation.prove",
            "policies_hex": [hex::encode(f.policy.serialize()), hex::encode(child.serialize())],
            "sigs_hex": [sigs_hex, child_sigs],
            "keys_hex": [keys_hex.clone(), keys_hex],
        }))
        .expect("the ancestry proves");
    let checked = mcp
        .handle(&json!({
            "op": "delegation.verify",
            "proof_json": proof.to_string(),
        }))
        .expect("the proof verifies");
    assert_eq!(checked["valid"], true);
    assert_eq!(checked["depth"], 2);
}

#[test]
fn auth_bind_and_verify_bound_enforce_expiry_and_tx() {
    use srct_core::agent::PolicyBook;
    use srct_core::l2::Auth;
    use srct_core::service::authorize_request;

    let mut mcp = SolarCyberUnitMcp::new();
    let f = fixture();
    let payer = wallet(1);
    let mut book = PolicyBook::default();
    let auth = authorize_request(&mut book, &f.policy, NET, &f.request, HEIGHT, 1).expect("grant");
    let payment = build_signed_payment(
        &payer,
        &auth,
        NET,
        AgentRole::Machine,
        0,
        EXPIRES,
        f.request.request_id(),
        &[],
    )
    .unwrap();
    let auth_sigs = Auth::sigs_for(&payer, &auth.signing_hash()).unwrap();
    let auth_keys = Auth::keys_for(&payer).unwrap();
    let bound = srct_core::portable::BoundAuthorization::issue(
        &payer,
        &auth,
        &auth_sigs,
        &auth_keys,
        HEIGHT + 10,
        payment.signing_hash(),
    )
    .unwrap();

    // The keyless bind step names the exact hash the owner must sign.
    let bind_out = mcp
        .handle(&json!({
            "op": "auth.bind",
            "authorization_hex": hex::encode(auth.serialize()),
            "expires_at_height": HEIGHT + 10,
            "tx_hash_hex": hash_to_hex(&payment.signing_hash()),
        }))
        .expect("bind names the hash");
    assert_eq!(bind_out["binding_hash"], hash_to_hex(&bound.signing_hash()));

    // The bound grant verifies against the exact payment inside its window.
    let ok = mcp
        .handle(&json!({
            "op": "auth.verify_bound",
            "bound_json": bound.to_json(),
            "policy_hex": hex::encode(f.policy.serialize()),
            "payment_hex": hex::encode(payment.serialize()),
            "height": HEIGHT,
        }))
        .expect("live binding verifies");
    assert_eq!(ok["valid"], true);

    // Past expiry, or against another transaction, it refuses by name.
    for height in [HEIGHT + 10, HEIGHT + 11] {
        let err = mcp
            .handle(&json!({
                "op": "auth.verify_bound",
                "bound_json": bound.to_json(),
                "policy_hex": hex::encode(f.policy.serialize()),
                "payment_hex": hex::encode(payment.serialize()),
                "height": height,
            }))
            .expect_err("expired bindings refuse");
        assert_eq!(err.code, "bound_invalid");
    }
    let mut other = payment.clone();
    other.amount_sat = 399;
    let err = mcp
        .handle(&json!({
            "op": "auth.verify_bound",
            "bound_json": bound.to_json(),
            "policy_hex": hex::encode(f.policy.serialize()),
            "payment_hex": hex::encode(other.serialize()),
            "height": HEIGHT,
        }))
        .expect_err("another transaction refuses");
    assert_eq!(err.code, "bound_invalid");
}

#[test]
fn guard_check_requires_a_signed_capability() {
    use srct_core::guard::{
        derive_context_hash, Capability, InfraPolicy, SignedCapability, GUARD_POLICY_VERSION,
    };
    let owner = wallet(11);
    let owner_addr = owner.address().unwrap();
    let agent_id = derive_agent_id(NET, AgentRole::Machine, &owner_addr);
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
        workload_key: [0u8; 32],
    };
    let workload = [2u8; 32];
    let action = [1u8; 32];
    let ctx = derive_context_hash(&workload, HEIGHT);
    let mut mcp = SolarCyberUnitMcp::new();

    // Unsigned bytes any observer could write down: refused, never allowed.
    let raw = Capability {
        policy_hash: policy.hash(),
        action_hash: action,
        context_hash: ctx,
        expiry_height: HEIGHT + 10,
        nonce: 1,
        audience: [0u8; 32],
    };
    let err = mcp
        .handle(&json!({
            "op": "guard.check",
            "network_id": NET,
            "height": HEIGHT,
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(raw.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_hash_hex": hash_to_hex(&action),
            "workload_id_hex": hash_to_hex(&workload),
        }))
        .expect_err("an unsigned capability must be refused");
    assert_eq!(err.code, "unsigned_capability");

    // Signed by a stranger: same bytes, no authority.
    let stranger = wallet(12);
    let forged = SignedCapability::issue(&stranger, &raw).unwrap();
    let err = mcp
        .handle(&json!({
            "op": "guard.check",
            "network_id": NET,
            "height": HEIGHT,
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(forged.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_hash_hex": hash_to_hex(&action),
            "workload_id_hex": hash_to_hex(&workload),
        }))
        .expect_err("a forged capability must be refused");
    assert_eq!(err.code, "guard_refused");

    // Honest owner signature: allowed.
    let signed = SignedCapability::issue(&owner, &raw).unwrap();
    let out = mcp
        .handle(&json!({
            "op": "guard.check",
            "network_id": NET,
            "height": HEIGHT,
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(signed.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_hash_hex": hash_to_hex(&action),
            "workload_id_hex": hash_to_hex(&workload),
        }))
        .expect("an owner-signed capability passes the pre-check");
    assert_eq!(out["decision"], "allow");
}

#[test]
fn guard_authorize_recomputes_the_action_and_rejects_boolean_approval() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, Capability, GuardApproval, InfraPolicy,
        SignedCapability, GUARD_POLICY_VERSION,
    };
    let owner = wallet(21);
    let owner_addr = owner.address().unwrap();
    let agent_id = derive_agent_id(NET, AgentRole::Machine, &owner_addr);
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
        workload_key: [0u8; 32],
    };
    let workload = [4u8; 32];
    let preimage = b"deploy-42";
    let action = derive_action_hash(preimage);
    let ctx = derive_context_hash(&workload, HEIGHT);
    let cap = Capability {
        policy_hash: policy.hash(),
        action_hash: action,
        context_hash: ctx,
        expiry_height: HEIGHT + 10,
        nonce: 1,
        audience: [0u8; 32],
    };
    let signed = SignedCapability::issue(&owner, &cap).unwrap();
    let base = || {
        json!({
            "op": "guard.authorize",
            "network_id": NET,
            "height": HEIGHT,
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(signed.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_preimage_hex": hex::encode(preimage),
            "workload_id_hex": hex::encode(workload),
        })
    };
    let mut mcp = SolarCyberUnitMcp::new();
    let out = mcp.handle(&base()).expect("exact preimage authorizes");
    assert_eq!(out["decision"], "allow");

    // Action swap: authorized deploy-42, executing deploy-43.
    let mut mcp2 = SolarCyberUnitMcp::new();
    let mut swapped = base();
    swapped["action_preimage_hex"] = json!(hex::encode(b"deploy-43"));
    swapped["cap_hex"] = json!(hex::encode(
        SignedCapability::issue(&owner, &cap).unwrap().serialize()
    ));
    let err = mcp2
        .handle(&swapped)
        .expect_err("a swapped action must be refused");
    assert_eq!(err.code, "guard_refused");

    // Boolean approval is dead: high-risk + approved:true refuses.
    let mut mcp3 = SolarCyberUnitMcp::new();
    let mut boolean = base();
    boolean["high_risk"] = json!(true);
    boolean["approved"] = json!(true);
    let err = mcp3
        .handle(&boolean)
        .expect_err("boolean approval must be refused");
    assert_eq!(err.code, "approval_invalid");

    // High-risk without any approval gates instead of allowing.
    let mut mcp4 = SolarCyberUnitMcp::new();
    let mut gated = base();
    gated["high_risk"] = json!(true);
    let out = mcp4.handle(&gated).expect("missing approval gates");
    assert_eq!(out["decision"], "needs_approval");

    // Signed approval from a stranger denies.
    let stranger = wallet(22);
    let draft = GuardApproval {
        version: GUARD_POLICY_VERSION,
        policy_hash: policy.hash(),
        cap_hash: cap.signing_hash(),
        agent_id,
        action_hash: action,
        context_hash: ctx,
        expiry_height: HEIGHT + 5,
        sigs: srct_core::sig::Bundle::default(),
        keys: srct_core::sig::Bundle::default(),
    };
    let fake = GuardApproval {
        sigs: srct_core::l2::Auth::sigs_for(&stranger, &draft.signing_hash()).unwrap(),
        keys: srct_core::l2::Auth::keys_for(&stranger).unwrap(),
        ..draft.clone()
    };
    let mut mcp5 = SolarCyberUnitMcp::new();
    let mut forged = base();
    forged["high_risk"] = json!(true);
    forged["approval_hex"] = json!(hex::encode(fake.serialize()));
    let err = mcp5.handle(&forged).expect_err("a fake approval must deny");
    assert_eq!(err.code, "guard_refused");

    // Honest owner approval allows.
    let honest = GuardApproval {
        sigs: srct_core::l2::Auth::sigs_for(&owner, &draft.signing_hash()).unwrap(),
        keys: srct_core::l2::Auth::keys_for(&owner).unwrap(),
        ..draft
    };
    let mut mcp6 = SolarCyberUnitMcp::new();
    let mut ok = base();
    ok["high_risk"] = json!(true);
    ok["approval_hex"] = json!(hex::encode(honest.serialize()));
    let out = mcp6.handle(&ok).expect("an owner-signed approval allows");
    assert_eq!(out["decision"], "allow");
}

#[test]
fn mcp_transport_refuses_untrusted_endpoints() {
    let mut mcp = SolarCyberUnitMcp::new();
    // A caller-supplied public URL must not receive the bearer token: refused
    // before any socket opens (no SRCT_MCP_ALLOW_REMOTE in this test env).
    let err = mcp
        .handle(&json!({
            "op": "node.status",
            "endpoint": "203.0.113.7:8080",
        }))
        .expect_err("a public endpoint must be refused");
    assert_eq!(err.code, "untrusted_endpoint");
    // Scheme/userinfo/path shapes are refused, never parsed into a dial.
    for endpoint in [
        "http://127.0.0.1:8080",
        "user:pass@127.0.0.1:8080",
        "127.0.0.1:8080/v1/status",
    ] {
        let err = mcp
            .handle(&json!({ "op": "node.status", "endpoint": endpoint }))
            .expect_err("a non host:port endpoint must be refused");
        assert!(
            err.code == "untrusted_endpoint" || err.code == "bad_request",
            "unexpected code for {endpoint}: {}",
            err.code
        );
    }
}

#[test]
fn guard_check_enforces_owner_set_risk_and_scoped_caps_refuse_locally() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, Capability, InfraPolicy, SignedCapability,
        GUARD_POLICY_VERSION,
    };
    let owner = wallet(31);
    let owner_addr = owner.address().unwrap();
    let approver = wallet(32);
    let agent_id = derive_agent_id(NET, AgentRole::Machine, &owner_addr);
    // High-assurance grant: owner-named independent approver, bound workload.
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
        requires_approval: true,
        approver: approver.address().unwrap(),
        workload_id: [6u8; 32],
        workload_key: [0u8; 32],
    };
    let preimage = b"deploy-42";
    let cap = Capability {
        policy_hash: policy.hash(),
        action_hash: derive_action_hash(preimage),
        context_hash: derive_context_hash(&[6u8; 32], HEIGHT),
        expiry_height: HEIGHT + 10,
        nonce: 1,
        audience: [0u8; 32],
    };
    let signed = SignedCapability::issue(&owner, &cap).unwrap();
    let mut mcp = SolarCyberUnitMcp::new();
    // Caller claims low risk; the grant disagrees: gated, not allowed.
    let out = mcp
        .handle(&json!({
            "op": "guard.check",
            "network_id": NET,
            "height": HEIGHT,
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(signed.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_hash_hex": hash_to_hex(&cap.action_hash),
            "workload_id_hex": hash_to_hex(&[6u8; 32]),
            "high_risk": false,
        }))
        .expect("owner-set risk must answer");
    assert_eq!(out["decision"], "needs_approval");
    // An audience-scoped capability cannot be admitted by the unscoped local
    // book: it belongs to its node.
    let mut scoped = cap.clone();
    scoped.audience = [0xAAu8; 32];
    let scoped_signed = SignedCapability::issue(&owner, &scoped).unwrap();
    let mut mcp2 = SolarCyberUnitMcp::new();
    let err = mcp2
        .handle(&json!({
            "op": "guard.authorize",
            "network_id": NET,
            "height": HEIGHT,
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(scoped_signed.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_preimage_hex": hex::encode(preimage),
            "workload_id_hex": hash_to_hex(&[6u8; 32]),
        }))
        .expect_err("a scoped capability must not admit locally");
    assert_eq!(err.code, "guard_refused");
}

#[test]
fn guard_credential_proves_possession_over_mcp() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, workload_key_fingerprint, Capability, InfraPolicy,
        SignedCapability, WorkloadCredential, GUARD_POLICY_VERSION,
    };
    let owner = wallet(41);
    let owner_addr = owner.address().unwrap();
    let workload_wallet = wallet(42);
    let workload_keys = srct_core::l2::Auth::keys_for(&workload_wallet).unwrap();
    let agent_id = derive_agent_id(NET, AgentRole::Machine, &owner_addr);
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
    let workload = [4u8; 32];
    let preimage = b"mcp-job-9";
    let action = derive_action_hash(preimage);
    let ctx = derive_context_hash(&workload, HEIGHT);
    let cap = Capability {
        policy_hash: policy.hash(),
        action_hash: action,
        context_hash: ctx,
        expiry_height: HEIGHT + 10,
        nonce: 1,
        audience: [0u8; 32],
    };
    let signed = SignedCapability::issue(&owner, &cap).unwrap();
    let base = || {
        json!({
            "op": "guard.authorize",
            "network_id": NET,
            "height": HEIGHT,
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(signed.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_preimage_hex": hex::encode(preimage),
            "workload_id_hex": hex::encode(workload),
        })
    };
    // No proof: the bound grant denies.
    let mut mcp = SolarCyberUnitMcp::new();
    let err = mcp
        .handle(&base())
        .expect_err("a key-bound grant must deny without proof");
    assert_eq!(err.code, "guard_refused");
    // Impersonation: a stranger's key denies.
    let stranger = wallet(43);
    let fake =
        WorkloadCredential::issue(&stranger, &policy.hash(), &cap, &action, &ctx, HEIGHT).unwrap();
    let mut mcp2 = SolarCyberUnitMcp::new();
    let mut forged = base();
    forged["workload_cred_hex"] = json!(hex::encode(fake.serialize()));
    let err = mcp2.handle(&forged).expect_err("impersonation must deny");
    assert_eq!(err.code, "guard_refused");
    // Honest proof of possession: allow.
    let cred = WorkloadCredential::issue(
        &workload_wallet,
        &policy.hash(),
        &cap,
        &action,
        &ctx,
        HEIGHT,
    )
    .unwrap();
    let mut mcp3 = SolarCyberUnitMcp::new();
    let mut ok = base();
    ok["workload_cred_hex"] = json!(hex::encode(cred.serialize()));
    let out = mcp3.handle(&ok).expect("possession proof admits");
    assert_eq!(out["decision"], "allow");
}

#[test]
fn audit_verify_checks_the_exported_chain() {
    use srct_core::safety::AuditLog;

    let mut mcp = SolarCyberUnitMcp::new();
    let mut log = AuditLog::default();
    log.push("authorize", None, Some(500), "grant".to_string())
        .unwrap();
    log.push("payment", Some([1u8; 32]), Some(500), "submit".to_string())
        .unwrap();
    let out = mcp
        .handle(&json!({ "op": "audit.verify", "audit_json": log.export_json() }))
        .expect("the chain verifies");
    assert_eq!(out, json!({ "valid": true, "entries": 2 }));

    let mut tampered = log.export();
    tampered.entries[0].detail = "forged".to_string();
    let err = mcp
        .handle(&json!({
            "op": "audit.verify",
            "audit_json": serde_json::to_string(&tampered).unwrap(),
        }))
        .expect_err("rewritten history refuses");
    assert_eq!(err.code, "audit_invalid");
}
