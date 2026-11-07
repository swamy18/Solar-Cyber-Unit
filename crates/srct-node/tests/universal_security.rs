//! Universal security V1 lock-in: finance gate over the hosted API.
//!
//! What this pins (nothing here touches consensus):
//! - `POST /v1/policy/decide` answers from the node's own network/height,
//!   with named deny reasons and `needs_approval` treated as gated, never
//!   allow. Deciding twice decides identically (no nonce consumed).
//! - `POST /v1/guard/decide` fails closed on hash mismatch, expiry,
//!   over-long lifetime, zero nonce and cross-principal capabilities.
//! - `POST /v1/guard/authorize` never consumes window budget on deny, and a
//!   replayed nonce is a named deny, not a second admission.
//!
//! Run with `cargo test -p srct-node --test universal_security`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
use srct_core::chain::Chain;
use srct_core::hash::{hash_to_hex, to_hex};
use srct_core::l2::Auth;
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_node::api::{spawn_with_options, SharedNode};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const NET: &str = "srct/mini";

struct Node {
    addr: SocketAddr,
    #[allow(dead_code)]
    shared: Arc<Mutex<SharedNode>>,
}

fn start() -> Node {
    let chain = Chain::new(NetworkParams::mini()).unwrap();
    let l2 = NodeL2::fresh(&NetworkParams::mini()).unwrap();
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
    .expect("the API must bind its loopback socket");
    Node { addr, shared }
}

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
}

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
    let mut stream = TcpStream::connect(addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let _ = stream.write_all(request.as_bytes());
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

fn post(node: &Node, path: &str, body: &Value) -> (u16, Value) {
    let (status, text) = http(node.addr, "POST", path, Some(&body.to_string()));
    (status, json(&text))
}

fn node_height(node: &Node) -> u64 {
    node.shared.lock().unwrap().chain.height()
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
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![*provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    }
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

/// Finance gate V1: allow fits, over-cap and zero-amount deny by name,
/// threshold gates without refusing, and deciding twice is identical.
#[test]
fn policy_decide_finance_gate_v1() {
    let node = start();
    let payer = wallet(61, "fin-payer");
    let provider = [7u8; 20];
    let service = [9u8; 32];
    let policy = machine_policy(&payer, &provider, service);
    let base = || {
        json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(&payer, &policy),
            "policy_keys_hex": policy_keys_hex(&payer),
            "agent_id_hex": hex::encode(policy.agent_id),
            "recipient_hex": hex::encode(provider),
            "service_hex": hex::encode(service),
        })
    };

    let mut allow = base();
    allow["amount_sat"] = json!(400);
    let (s, out) = post(&node, "/v1/policy/decide", &allow);
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "allow");
    assert_eq!(out["network_id"], NET);

    // Read-only: deciding again decides identically, nothing committed.
    let (s, again) = post(&node, "/v1/policy/decide", &allow);
    assert_eq!(s, 200, "{again}");
    assert_eq!(again, out);

    let mut over = base();
    over["amount_sat"] = json!(50_000);
    let (s, body) = post(&node, "/v1/policy/decide", &over);
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("per-tx limit"));

    let mut zero = base();
    zero["amount_sat"] = json!(0);
    let (s, body) = post(&node, "/v1/policy/decide", &zero);
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["reason"], "amount is zero");

    let mut stranger = base();
    stranger["amount_sat"] = json!(400);
    stranger["recipient_hex"] = json!(hex::encode([0xFFu8; 20]));
    let (s, body) = post(&node, "/v1/policy/decide", &stranger);
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["reason"], "recipient is not allowed");

    // Above the threshold the spend is gated, never silently allowed.
    let mut gated = base();
    gated["amount_sat"] = json!(400);
    gated["approval_threshold_sat"] = json!(100);
    let (s, out) = post(&node, "/v1/policy/decide", &gated);
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "needs_approval");

    // A grant for another network is refused at parse, never answered as allow.
    let mut foreign = policy.clone();
    foreign.network_id = "srct/elsewhere".to_string();
    let (s, body) = post(
        &node,
        "/v1/policy/decide",
        &json!({
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
}

/// Smart Gate decide fails closed on every forged or stale capability shape.
#[test]
fn guard_decide_fail_closed_v1() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, Capability, InfraPolicy, SignedCapability,
        GUARD_POLICY_VERSION,
    };
    let node = start();
    let h = node_height(&node);
    let owner = wallet(77, "guard-owner");
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
    let preimage = b"pay-400-sat";
    let action = derive_action_hash(preimage);
    let cap_hex =
        |cap: &Capability| hex::encode(SignedCapability::issue(&owner, cap).unwrap().serialize());
    let decide = |cap_hex: &str, action_hash_hex: String| {
        post(
            &node,
            "/v1/guard/decide",
            &json!({
                "policy_hex": hex::encode(policy.serialize()),
                "cap_hex": cap_hex,
                "agent_id_hex": hex::encode(agent_id),
                "action_hash_hex": action_hash_hex,
                "workload_id_hex": hash_to_hex(&workload),
            }),
        )
    };
    let good = Capability {
        policy_hash: policy.hash(),
        action_hash: action,
        context_hash: derive_context_hash(&workload, h),
        expiry_height: h + 10,
        nonce: 1,
        audience: [0u8; 32],
    };
    let (s, out) = decide(&cap_hex(&good), hash_to_hex(&action));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "allow");

    // Wrong action hash: the executed bytes do not match the grant.
    let (s, out) = decide(
        &cap_hex(&good),
        hash_to_hex(&derive_action_hash(b"pay-401-sat")),
    );
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "deny");
    assert_eq!(out["reason"], "action hash mismatch");

    // Expired capability.
    let expired = Capability {
        expiry_height: h,
        nonce: 2,
        ..good.clone()
    };
    let (s, out) = decide(&cap_hex(&expired), hash_to_hex(&action));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "deny");
    assert_eq!(out["reason"], "capability expired");

    // Lifetime over the 30-height cap.
    let long = Capability {
        expiry_height: h + 31,
        nonce: 3,
        ..good.clone()
    };
    let (s, out) = decide(&cap_hex(&long), hash_to_hex(&action));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "deny");
    assert_eq!(out["reason"], "capability lifetime exceeds cap");

    // Zero nonce: never admissible.
    let zero = Capability {
        nonce: 0,
        ..good.clone()
    };
    let (s, out) = decide(&cap_hex(&zero), hash_to_hex(&action));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "deny");

    // Cross-principal: the capability names this grant but another agent asks.
    let stranger_id = derive_agent_id(NET, AgentRole::Machine, &[9u8; 20]);
    let (s, out) = post(
        &node,
        "/v1/guard/decide",
        &json!({
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": cap_hex(&good),
            "agent_id_hex": hex::encode(stranger_id),
            "action_hash_hex": to_hex(&action),
            "workload_id_hex": hash_to_hex(&workload),
        }),
    );
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["decision"], "deny");
}

/// Deny consumes nothing: a swapped preimage and a replay leave budget intact.
#[test]
fn guard_authorize_deny_consumes_no_budget_v1() {
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, Capability, InfraPolicy, SignedCapability,
        GUARD_POLICY_VERSION,
    };
    let node = start();
    let h = node_height(&node);
    let owner = wallet(91, "budget-owner");
    let owner_addr = owner.address().unwrap();
    let agent_id = derive_agent_id(NET, AgentRole::Machine, &owner_addr);
    let policy = InfraPolicy {
        version: GUARD_POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id,
        owner: owner_addr,
        max_calls_per_window: 2,
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
        &json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": hex::encode(Auth::sigs_for(&owner, &policy.signing_hash()).unwrap().to_bytes()),
            "policy_keys_hex": hex::encode(Auth::keys_for(&owner).unwrap().to_bytes()),
        }),
    );
    assert_eq!(s, 200, "{granted}");

    let workload = [2u8; 32];
    let preimage = b"pay-400-sat";
    let action = derive_action_hash(preimage);
    let cap_hex = |nonce: u64| {
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
    let authorize = |nonce: u64, preimage_hex: String| {
        post(
            &node,
            "/v1/guard/authorize",
            &json!({
                "cap_hex": cap_hex(nonce),
                "agent_id_hex": hex::encode(agent_id),
                "action_hash_hex": hash_to_hex(&action),
                "action_preimage_hex": preimage_hex,
                "workload_id_hex": hash_to_hex(&workload),
            }),
        )
    };

    // Swapped preimage denies and must not consume budget.
    let (s, swapped) = authorize(7, hex::encode(b"pay-999-sat"));
    assert_eq!(s, 200, "{swapped}");
    assert_eq!(swapped["decision"], "deny");

    // First real admission.
    let (s, first) = authorize(1, hex::encode(preimage));
    assert_eq!(s, 200, "{first}");
    assert_eq!(first["decision"], "allow");

    // Replay of the same nonce denies and must not consume budget either.
    let (s, replay) = authorize(1, hex::encode(preimage));
    assert_eq!(s, 200, "{replay}");
    assert_eq!(replay["decision"], "deny");

    // Second real admission still fits in a window of 2: neither deny consumed.
    let (s, second) = authorize(2, hex::encode(preimage));
    assert_eq!(s, 200, "{second}");
    assert_eq!(second["decision"], "allow");
}
