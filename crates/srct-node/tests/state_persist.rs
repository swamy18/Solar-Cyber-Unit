//! Node-local state persistence: the books a node owns beside the chain
//! (receipts, replay tracker, payments, reservations, policy accounting,
//! credit, delegations, issued policies, revocations) survive a restart.
//!
//! Chain, mempool and L2 are deliberately out of scope: the chain is durable,
//! L2 replays from it, and the rest is derived. What is pinned here:
//!
//! - `SharedNode::encode_state` / `decode_state` round-trips a populated node
//!   byte for byte, so a restart restores the same books;
//! - a refused load (wrong version, truncated bytes, trailing bytes) changes
//!   nothing - a failed decode is never a half-loaded state;
//! - the real `srct_store::StateFile` path (atomic save, digest-checked load)
//!   carries the envelope end to end.
//!
//! Integrity of the *bytes* is the state file's checksum, not the envelope's:
//! that is pinned in `srct-store`'s own tests, and the startup path always
//! reads through it.

use srct_core::agent::{
    derive_agent_id, AgentRole, AuthorizationRequest, SpendPolicy, POLICY_VERSION,
};
use srct_core::chain::Chain;
use srct_core::credit::Reservation;
use srct_core::guard::{
    derive_context_hash, Capability, Decision as GuardDecision, InfraPolicy, GUARD_POLICY_VERSION,
};
use srct_core::hash::Hash;
use srct_core::params::NetworkParams;
use srct_core::payment::{MachinePayment, PAYMENT_VERSION};
use srct_core::receipt::{sign_receipt, ReceiptAnchor, ServiceReceipt, RECEIPT_VERSION};
use srct_core::sig::Bundle;
use srct_core::wallet::Wallet;
use srct_node::api::SharedNode;
use srct_node::l2::NodeL2;

const NET: &str = "srct/mini";

fn fresh() -> SharedNode {
    let chain = Chain::new(NetworkParams::mini()).expect("chain");
    let l2 = NodeL2::fresh(&NetworkParams::mini()).expect("l2");
    SharedNode::new(chain, l2)
}

fn policy() -> SpendPolicy {
    let owner = [7u8; 20];
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.into(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
        owner,
        role: AgentRole::Machine,
        per_tx_max_sat: 1_000,
        window_blocks: 100,
        cumulative_max_sat: 5_000,
        allowed_recipients: vec![[1u8; 20]],
        allowed_services: vec![[9u8; 32]],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    }
}

fn guard_policy() -> InfraPolicy {
    let owner = [7u8; 20];
    InfraPolicy {
        version: GUARD_POLICY_VERSION,
        network_id: NET.into(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
        owner,
        max_calls_per_window: 10,
        window_blocks: 100,
        valid_from_height: 0,
        valid_until_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    }
}

fn machine_payment() -> MachinePayment {
    MachinePayment {
        version: PAYMENT_VERSION,
        network_id: NET.into(),
        payer_type: AgentRole::Machine,
        payer: [7u8; 20],
        agent_id: derive_agent_id(NET, AgentRole::Machine, &[7u8; 20]),
        recipient: [1u8; 20],
        service: Some([9u8; 32]),
        amount_sat: 500,
        fee_sat: 2_000,
        nonce: 4,
        policy_hash: [3u8; 32],
        expires_at_height: 900,
        reference: [4u8; 32],
        chain: Vec::new(),
        keys: Bundle::default(),
        sigs: Bundle::default(),
    }
}

fn signed_receipt() -> ServiceReceipt {
    let issuer = Wallet::from_private_key_bytes(&[11u8; 32], "state-persist").expect("key");
    let mut r = ServiceReceipt {
        version: RECEIPT_VERSION,
        network_id: NET.into(),
        payer: [7u8; 20],
        payer_role: AgentRole::Machine,
        agent_id: derive_agent_id(NET, AgentRole::Machine, &[7u8; 20]),
        recipient: issuer.address().expect("address"),
        service_id: Some([9u8; 32]),
        amount_sat: 500,
        payment_id: [1u8; 32],
        request_id: [2u8; 32],
        result_hash: Some([6u8; 32]),
        anchor: Some(ReceiptAnchor {
            height: 42,
            block_hash: [8u8; 64],
        }),
        keys: Bundle::default(),
        sigs: Bundle::default(),
    };
    sign_receipt(&mut r, &issuer).expect("issuer signs");
    r
}

/// Populate every book the envelope carries, so no section is round-tripped
/// only in its empty state.
fn populate(node: &mut SharedNode) {
    node.payment_tracker
        .observe(&[1u8; 32], 900)
        .expect("observe");

    let debtor = [7u8; 20];
    node.credit.deposit(debtor, 5_000).expect("deposit");
    let reservation = Reservation {
        id: [9u8; 32],
        debtor,
        amount_sat: 500,
        from_free_sat: 500,
        position_draws: Vec::new(),
        position_id: None,
    };
    node.reservations.insert(reservation.id, reservation);

    let p = policy();
    let req = AuthorizationRequest {
        agent_id: p.agent_id,
        recipient: [1u8; 20],
        amount_sat: 400,
        service: Some([9u8; 32]),
        height: 10,
        nonce: 1,
    };
    node.policies.authorize(&p, NET, &req).expect("grant");
    node.policy_registry.insert(p.hash(), p.clone());
    node.revoked_policies.insert([3u8; 32]);
    node.delegations.record_root(&p);

    let pay = machine_payment();
    let payment_id: Hash = pay.signing_hash();
    node.payment_store.insert(payment_id, pay);
    // One settlement link: a payment bound to the tx that paid its recipient.
    node.payment_tx.insert(payment_id, [7u8; 64]);

    let receipt = signed_receipt();
    node.receipts
        .accept(&receipt, NET)
        .expect("receipt accepted");

    // A released escrow bound to the exit that pays it (Gap 3 settlement).
    // The escrow itself is stored too: since the orphan prune, a restart
    // drops exit bindings whose escrow is not in the book, so a dangling
    // binding would not round-trip.
    let escrow = srct_core::escrow::ConditionalEscrow::open(
        NET.into(),
        [7u8; 20],
        srct_core::bls_checkpoint::BlsPublicKey([1u8; 48]),
        [1u8; 20],
        srct_core::bls_checkpoint::BlsPublicKey([2u8; 48]),
        srct_core::bls_checkpoint::BlsPublicKey([3u8; 48]),
        500,
        5,
        0,
    )
    .expect("open escrow");
    let escrow_id = escrow.id();
    node.escrows.insert(escrow_id, escrow);
    node.escrow_exit.insert(
        escrow_id,
        srct_node::api::EscrowExitBinding {
            txid: [7u8; 64],
            owner: [1u8; 20],
            nonce: 5,
        },
    );

    // A minted attestation that must never mint again, across a restart.
    node.attestations_used.insert([6u8; 32], 500);

    // A Smart Gate grant the node enforces, plus one consumed capability:
    // the window count and nonce must survive the restart, or a replay
    // would look fresh.
    let gp = guard_policy();
    node.guard_registry.insert(gp.hash(), gp.clone());
    node.guard_revoked.insert([5u8; 32]);
    let workload = [2u8; 32];
    let ctx = derive_context_hash(&workload, 10);
    let action = [1u8; 32];
    let cap = Capability {
        policy_hash: gp.hash(),
        action_hash: action,
        context_hash: ctx,
        expiry_height: 40,
        nonce: 1,
    };
    match node.guards.authorize(
        &gp,
        &cap,
        &gp.agent_id,
        NET,
        10,
        &action,
        &ctx,
        false,
        false,
    ) {
        GuardDecision::Allow => {}
        other => panic!("guard allow: {other:?}"),
    }
}

#[test]
fn node_books_survive_an_encode_decode_round_trip() {
    let mut a = fresh();
    populate(&mut a);

    let bytes = a.encode_state();
    let mut b = fresh();
    b.decode_state(&bytes).expect("state decodes");
    assert_eq!(
        b.encode_state(),
        bytes,
        "a decoded node re-encodes to the same bytes"
    );

    // Spot-check the lookups that matter, not just the re-encode.
    assert!(b.payment_tracker.contains(&[1u8; 32]));
    assert_eq!(b.credit.total_deposited(), 5_000);
    assert_eq!(b.reservations.len(), 1);
    assert_eq!(
        b.receipts.by_payment_id(&[1u8; 32]).map(|r| r.serialize()),
        a.receipts.by_payment_id(&[1u8; 32]).map(|r| r.serialize())
    );
    assert_eq!(b.payment_store.len(), 1);
    assert_eq!(b.payment_tx, a.payment_tx, "settlement links round-trip");
    assert_eq!(
        b.escrow_exit, a.escrow_exit,
        "escrow exit bindings round-trip"
    );
    assert_eq!(
        b.attestations_used, a.attestations_used,
        "used attestations round-trip"
    );
    assert!(b.policy_registry.contains_key(&policy().hash()));
    assert!(b.revoked_policies.contains(&[3u8; 32]));
    assert_eq!(
        b.escrow_exit.len(),
        1,
        "the exit binding survives because its escrow is stored"
    );
    assert!(b.guard_registry.contains_key(&guard_policy().hash()));
    assert!(b.guard_revoked.contains(&[5u8; 32]));
    assert_eq!(
        b.guards.state(&guard_policy().hash()).map(|s| s.last_nonce),
        Some(1),
        "guard nonce survives the restart"
    );
    assert_eq!(b.delegations.recorded().count(), 1);
    assert_eq!(
        b.policies.state(&policy().hash()).map(|s| s.last_nonce),
        Some(1)
    );
}

#[test]
fn a_refused_load_changes_nothing() {
    let mut a = fresh();
    populate(&mut a);
    let bytes = a.encode_state();
    let pristine = fresh().encode_state();

    // A version this build does not know.
    let mut c = fresh();
    let err = c.decode_state(&[99u8]).expect_err("wrong version refused");
    assert!(err.contains("version"), "unhelpful error: {err}");
    assert_eq!(c.encode_state(), pristine, "refused version loaded nothing");

    // Truncated bytes: the last section's length no longer matches the file.
    let mut d = fresh();
    assert!(d.decode_state(&bytes[..bytes.len() - 6]).is_err());
    assert_eq!(d.encode_state(), pristine, "truncation loaded nothing");

    // Trailing bytes after the last section.
    let mut over = bytes.clone();
    over.push(0);
    let mut e = fresh();
    assert!(e.decode_state(&over).is_err());
    assert_eq!(e.encode_state(), pristine, "trailing bytes loaded nothing");

    // And a successful load is still exact: nothing partial happened anywhere.
    let mut ok = fresh();
    ok.decode_state(&bytes).expect("clean load");
    assert_eq!(ok.encode_state(), bytes);
}

#[test]
fn the_state_file_round_trips_through_the_store() {
    let dir = std::env::temp_dir().join(format!("srct-node-state-{}", std::process::id()));
    let file = srct_store::StateFile::new(dir.join("state.bin"));
    let _ = std::fs::remove_dir_all(&dir);

    let mut a = fresh();
    populate(&mut a);
    let bytes = a.encode_state();
    file.save(&bytes).expect("save");

    let loaded = file.load().expect("loadable").expect("file present");
    let mut b = fresh();
    b.decode_state(&loaded).expect("state decodes");
    assert_eq!(b.encode_state(), bytes);

    // A missing file is a fresh node, not an error.
    let absent = srct_store::StateFile::new(dir.join("absent.bin"));
    assert!(absent.load().unwrap().is_none());

    let _ = std::fs::remove_dir_all(&dir);
}
