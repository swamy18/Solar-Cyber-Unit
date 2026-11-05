//! Worker `GuardGate` against the real node over real HTTP: admission goes
//! through `NodeGateAuthority` → `POST /v1/guard/authorize`, the node's book
//! is the single commit point, and local verification runs at the returned
//! authoritative height.
//!
//! What this file proves over the wire (not against fakes):
//!
//! - Key-bound capabilities execute end to end when the worker is in sync.
//! - A worker behind the node self-heals: first attempt denies stale with the
//!   node's height, the bounded retry rebuilds the proof there and admits.
//! - A worker ahead of the node self-heals the same way.
//! - Replays and impersonations deny by name; nothing executes on refusal.
//! - Approval-gated grants gate and then admit with the designated approval.
//! - The authorize answer carries the height local verification must use.
//!
//! Run with `cargo test -p srct-node --test guard_worker_http`.

use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use srct_core::agent::{derive_agent_id, AgentRole};
use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::Chain;
use srct_core::compute_ir::ComputeBackend;
use srct_core::guard::{
    derive_action_hash, derive_context_hash, workload_key_fingerprint, Capability, GuardApproval,
    GuardBook, InfraPolicy, SignedCapability, GUARD_POLICY_VERSION,
};
use srct_core::hash::Hash;
use srct_core::l2::Auth;
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_node::api::{spawn, SharedNode};
use srct_node::l2::NodeL2;
use srct_worker::executor::{CpuExecutor, ExecutionWork};
use srct_worker::{GuardGate, HttpNode, NodeGateAuthority, WorkerError};

const NET: &str = "srct/mini";

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
}

fn spawn_node() -> (SocketAddr, Arc<Mutex<SharedNode>>) {
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let mut l2 = NodeL2::fresh(&params).unwrap();
    l2.sync(&chain).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let addr = spawn(
        Arc::clone(&shared),
        Arc::new(AtomicUsize::new(0)),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .expect("the API must bind its loopback socket");
    (addr, shared)
}

fn node_height(shared: &Arc<Mutex<SharedNode>>) -> u64 {
    shared.lock().unwrap().chain.height()
}

/// Advance the live chain by one empty block, so the test can put the worker
/// behind the node on purpose.
fn mine_empty(shared: &Arc<Mutex<SharedNode>>) {
    let mut sh = shared.lock().unwrap();
    let SharedNode { chain, l2, .. } = &mut *sh;
    let h = chain.height() + 1;
    let root = l2.simulate_root(chain, h, &[]);
    let block = chain
        .mine_block_with_l2_root(
            [9u8; 20],
            Vec::new(),
            Vec::new(),
            root,
            GENESIS_TIMESTAMP_MS + h * 1_000,
            None,
            4_000_000,
        )
        .expect("an empty block must build");
    chain.submit(block).expect("it must be accepted");
    l2.sync(chain).unwrap();
}

fn http(addr: SocketAddr) -> HttpNode {
    HttpNode::new(format!("http://{addr}")).expect("a loopback URL parses")
}

fn test_work() -> ExecutionWork {
    ExecutionWork {
        task_id: [0x51u8; 32],
        ir_hash: [0x52u8; 32],
        input_hash: [0x53u8; 32],
        required_memory_bytes: 1024,
        backend_hint: ComputeBackend::Cpu,
        current_height: 10,
    }
}

fn keybound_policy(owner_addr: [u8; 20], workload: &Wallet) -> InfraPolicy {
    let keys = Auth::keys_for(workload).unwrap();
    InfraPolicy {
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
        workload_key: workload_key_fingerprint(&keys),
    }
}

/// Register an owner-signed grant over HTTP; returns the decoded answer.
fn register_grant(http: &HttpNode, policy: &InfraPolicy, owner: &Wallet) -> Value {
    let body = json!({
        "policy_hex": hex::encode(policy.serialize()),
        "policy_sigs_hex": hex::encode(Auth::sigs_for(owner, &policy.signing_hash()).unwrap().to_bytes()),
        "policy_keys_hex": hex::encode(Auth::keys_for(owner).unwrap().to_bytes()),
    });
    http.post_json("/v1/guard/grant", &body)
        .expect("grant registration must succeed")
}

fn signed_cap(
    owner: &Wallet,
    policy: &InfraPolicy,
    action: &Hash,
    workload: &Hash,
    h: u64,
    nonce: u64,
) -> SignedCapability {
    let cap = Capability {
        policy_hash: policy.hash(),
        action_hash: *action,
        context_hash: derive_context_hash(workload, h),
        expiry_height: h + 10,
        nonce,
        audience: [0u8; 32],
    };
    SignedCapability::issue(owner, &cap).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn gate_for(
    http: HttpNode,
    policy: &InfraPolicy,
    signed: SignedCapability,
    approval: Option<GuardApproval>,
    workload_wallet: Option<Wallet>,
    height: u64,
    workload: Hash,
) -> GuardGate {
    GuardGate {
        policy: policy.clone(),
        signed,
        approval,
        book: GuardBook::default(),
        authority: Box::new(NodeGateAuthority::new(http)),
        workload_wallet,
        agent_id: policy.agent_id,
        network_id: NET.to_string(),
        height,
        workload_id: workload,
        node_audience: [0u8; 32],
        escalate_to_approval: false,
    }
}

#[test]
fn keybound_executes_end_to_end_over_http() {
    let (addr, shared) = spawn_node();
    let h = node_height(&shared);
    let owner = wallet(61, "http-guard-owner");
    let owner_addr = owner.address().unwrap();
    let workload_wallet = wallet(62, "http-workload");
    let workload = [4u8; 32];
    let policy = keybound_policy(owner_addr, &workload_wallet);
    let granted = register_grant(&http(addr), &policy, &owner);
    assert_eq!(granted["policy_hash"], hex::encode(policy.hash()));

    let work = test_work();
    let preimage = srct_worker::guard_action_preimage(&work);
    let action = derive_action_hash(&preimage);
    let signed = signed_cap(&owner, &policy, &action, &workload, h, 1);
    let mut gate = gate_for(
        http(addr),
        &policy,
        signed,
        None,
        Some(workload_wallet),
        h,
        workload,
    );
    let out = gate
        .execute(&CpuExecutor::default(), &work)
        .expect("an in-sync key-bound execution admits over HTTP");
    assert!(!out.output.is_empty(), "the executor ran");
    assert_eq!(
        gate.book.state(&policy.hash()).map(|s| s.last_nonce),
        Some(1),
        "the local mirror committed the admitted nonce"
    );

    // The authorize answer carries the height local verification must use.
    let raw = http(addr)
        .post_json(
            "/v1/guard/authorize",
            &json!({
                "cap_hex": hex::encode(gate.signed.serialize()),
                "agent_id_hex": hex::encode(policy.agent_id),
                "action_preimage_hex": hex::encode(preimage),
                "workload_id_hex": hex::encode(workload),
            }),
        )
        .expect("raw authorize answers over HTTP");
    assert_eq!(raw["height"], h, "the node reports its admission height");
}

#[test]
fn worker_behind_node_self_heals_over_http() {
    let (addr, shared) = spawn_node();
    mine_empty(&shared);
    let h = node_height(&shared);
    assert!(h >= 1, "the test needs the node ahead of genesis");
    let owner = wallet(63, "http-guard-owner-2");
    let owner_addr = owner.address().unwrap();
    let workload_wallet = wallet(64, "http-workload-2");
    let workload = [4u8; 32];
    let policy = keybound_policy(owner_addr, &workload_wallet);
    register_grant(&http(addr), &policy, &owner);

    // The owner built the capability for the live height; the worker still
    // believes the previous one. First attempt denies stale with the node's
    // height, the bounded retry rebuilds there and admits — over the wire.
    let work = test_work();
    let preimage = srct_worker::guard_action_preimage(&work);
    let action = derive_action_hash(&preimage);
    let signed = signed_cap(&owner, &policy, &action, &workload, h, 1);
    let mut gate = gate_for(
        http(addr),
        &policy,
        signed,
        None,
        Some(workload_wallet),
        h - 1,
        workload,
    );
    gate.execute(&CpuExecutor::default(), &work)
        .expect("a behind worker heals within the retry bound");
}

#[test]
fn worker_ahead_of_node_self_heals_over_http() {
    let (addr, shared) = spawn_node();
    let h = node_height(&shared);
    let owner = wallet(65, "http-guard-owner-3");
    let owner_addr = owner.address().unwrap();
    let workload_wallet = wallet(66, "http-workload-3");
    let workload = [4u8; 32];
    let policy = keybound_policy(owner_addr, &workload_wallet);
    register_grant(&http(addr), &policy, &owner);

    let work = test_work();
    let preimage = srct_worker::guard_action_preimage(&work);
    let action = derive_action_hash(&preimage);
    let signed = signed_cap(&owner, &policy, &action, &workload, h, 1);
    let mut gate = gate_for(
        http(addr),
        &policy,
        signed,
        None,
        Some(workload_wallet),
        h + 1,
        workload,
    );
    gate.execute(&CpuExecutor::default(), &work)
        .expect("an ahead worker heals within the retry bound");
}

#[test]
fn replay_and_impersonation_denied_over_http() {
    let (addr, shared) = spawn_node();
    let h = node_height(&shared);
    let owner = wallet(67, "http-guard-owner-4");
    let owner_addr = owner.address().unwrap();
    let workload_wallet = wallet(68, "http-workload-4");
    let workload = [4u8; 32];
    let policy = keybound_policy(owner_addr, &workload_wallet);
    register_grant(&http(addr), &policy, &owner);

    let work = test_work();
    let preimage = srct_worker::guard_action_preimage(&work);
    let action = derive_action_hash(&preimage);
    let signed = signed_cap(&owner, &policy, &action, &workload, h, 1);
    let mut gate = gate_for(
        http(addr),
        &policy,
        signed,
        None,
        Some(workload_wallet),
        h,
        workload,
    );
    gate.execute(&CpuExecutor::default(), &work)
        .expect("first execution admits");

    // Same capability again: the authority denies the replayed nonce, and
    // nothing executes a second time.
    let err = gate
        .execute(&CpuExecutor::default(), &work)
        .expect_err("a replayed nonce must not execute");
    assert!(
        matches!(err, WorkerError::GuardDenied(_)),
        "unexpected: {err}"
    );

    // Impersonation: a stranger's key cannot prove possession, even with a
    // fresh capability envelope naming it.
    let stranger = wallet(69, "http-stranger");
    let signed2 = signed_cap(&owner, &policy, &action, &workload, h, 2);
    let mut impostor = gate_for(
        http(addr),
        &policy,
        signed2,
        None,
        Some(stranger),
        h,
        workload,
    );
    let err = impostor
        .execute(&CpuExecutor::default(), &work)
        .expect_err("impersonation must not execute");
    assert!(
        matches!(err, WorkerError::GuardDenied(_)),
        "unexpected: {err}"
    );
    assert!(
        impostor.book.is_empty(),
        "a refused admission commits no local state"
    );
}

#[test]
fn approval_gated_grant_executes_over_http() {
    use srct_core::guard::GUARD_POLICY_VERSION;
    let (addr, shared) = spawn_node();
    let h = node_height(&shared);
    let owner = wallet(70, "http-guard-owner-5");
    let approver = wallet(71, "http-approver-5");
    let owner_addr = owner.address().unwrap();
    let workload = [4u8; 32];
    let mut policy = keybound_policy(owner_addr, &wallet(72, "unused"));
    policy.requires_approval = true;
    policy.approver = approver.address().unwrap();
    policy.workload_key = [0u8; 32];
    register_grant(&http(addr), &policy, &owner);

    let work = test_work();
    let preimage = srct_worker::guard_action_preimage(&work);
    let action = derive_action_hash(&preimage);
    let ctx = derive_context_hash(&workload, h);
    let cap = Capability {
        policy_hash: policy.hash(),
        action_hash: action,
        context_hash: ctx,
        expiry_height: h + 10,
        nonce: 1,
        audience: [0u8; 32],
    };
    let signed = SignedCapability::issue(&owner, &cap).unwrap();

    // Without the designated approval: gated, never executed.
    let mut gated = gate_for(http(addr), &policy, signed.clone(), None, None, h, workload);
    assert_eq!(
        gated.execute(&CpuExecutor::default(), &work),
        Err(WorkerError::GuardApprovalNeeded)
    );

    // With it: the same admission executes.
    let draft = GuardApproval {
        version: GUARD_POLICY_VERSION,
        policy_hash: policy.hash(),
        cap_hash: cap.signing_hash(),
        agent_id: policy.agent_id,
        action_hash: action,
        context_hash: ctx,
        expiry_height: h + 5,
        sigs: srct_core::sig::Bundle::default(),
        keys: srct_core::sig::Bundle::default(),
    };
    let approval = GuardApproval {
        sigs: Auth::sigs_for(&approver, &draft.signing_hash()).unwrap(),
        keys: Auth::keys_for(&approver).unwrap(),
        ..draft
    };
    let mut admitted = gate_for(
        http(addr),
        &policy,
        signed,
        Some(approval),
        None,
        h,
        workload,
    );
    admitted
        .execute(&CpuExecutor::default(), &work)
        .expect("a designated approval admits over HTTP");
}
