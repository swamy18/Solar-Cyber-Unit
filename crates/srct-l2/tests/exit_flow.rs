//! L2 → L1 exits, L2 side (approved P1, E-1…E-3).
//!
//! Queueing is an L2 transaction (`ExitQueue`, type byte `0x15`); release is an
//! L1 operation the replay layer observes. This file pins the L2 half: the
//! wire type, the queue debit-and-record, the nonce replay rule, the maturity
//! predicate, the committed-root proofs, and the release accounting. The L1
//! release rule itself is tested where it lives (`srct-core` chain tests).
//!
//! Supersedes `exit_unavailable.rs`: exits exist now, so the "exactly five
//! types" and "value never leaves" pins below are rewritten as the six-type
//! wire and the queue → release lifecycle.

use srct_core::agent::{derive_agent_id, AgentRole, SpendPolicy};
use srct_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use srct_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use srct_core::error::Error;
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    ClaimTaskPayload, CreditOpenPayload, ExitQueuePayload, L2Payload, L2Transaction, L2TxType,
    PolicyPayload, PostTaskPayload, SettlePayload, SubmitResultPayload, Verdict, L2_TX_AGENT_SPEND,
    L2_TX_AUDIT_ANCHOR, L2_TX_CLAIM, L2_TX_CREDIT_COLLATERAL, L2_TX_CREDIT_DEFAULT,
    L2_TX_CREDIT_OPEN, L2_TX_CREDIT_OPEN_V2, L2_TX_CREDIT_REPAY, L2_TX_DISPUTE, L2_TX_EXIT_QUEUE,
    L2_TX_GUARDED_CANCEL, L2_TX_GUARDED_FREEZE, L2_TX_GUARDED_OPTIN, L2_TX_POLICY,
    L2_TX_POLICY_REVOKE, L2_TX_POST, L2_TX_SETTLE, L2_TX_SUBMIT, MIN_EXIT_FEE_SAT,
};
use srct_core::state_root::verify_inclusion;
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2Error, L2State};

// ---------------------------------------------------------------------------
// 1. The wire format admits six types and nothing else
// ---------------------------------------------------------------------------

/// Exhaustive over every possible type byte: exactly the thirteen known values
/// are accepted, and every other byte is refused **by name**.
#[test]
fn thirteen_l2_transaction_types_exist_with_the_credit_types_last() {
    let known = [
        L2_TX_POST,
        L2_TX_CLAIM,
        L2_TX_SUBMIT,
        L2_TX_DISPUTE,
        L2_TX_SETTLE,
        L2_TX_EXIT_QUEUE,
        L2_TX_POLICY,
        L2_TX_POLICY_REVOKE,
        L2_TX_AGENT_SPEND,
        L2_TX_CREDIT_OPEN,
        L2_TX_CREDIT_COLLATERAL,
        L2_TX_CREDIT_REPAY,
        L2_TX_CREDIT_DEFAULT,
        L2_TX_CREDIT_OPEN_V2,
        L2_TX_GUARDED_OPTIN,
        L2_TX_GUARDED_CANCEL,
        L2_TX_GUARDED_FREEZE,
        L2_TX_AUDIT_ANCHOR,
    ];
    let mut accepted = Vec::new();
    for byte in 0u8..=255 {
        match L2TxType::from_wire(byte) {
            Ok(t) => accepted.push(t),
            Err(e) => {
                // Refused *by name*, not with a generic decode failure.
                assert!(
                    matches!(&e, Error::Malformed(m) if *m == "unknown L2 transaction type"),
                    "byte {byte:#04x} must be refused by name, got {e:?}"
                );
            }
        }
    }
    assert_eq!(
        accepted.len(),
        18,
        "exactly eighteen L2 transaction types exist (13 original + CreditOpenV2 + 4 guarded/audit)"
    );
    assert_eq!(
        accepted,
        vec![
            L2TxType::PostTask,
            L2TxType::ClaimTask,
            L2TxType::SubmitResult,
            L2TxType::Dispute,
            L2TxType::Settle,
            L2TxType::ExitQueue,
            L2TxType::Policy,
            L2TxType::PolicyRevoke,
            L2TxType::AgentSpend,
            L2TxType::CreditOpen,
            L2TxType::CreditCollateral,
            L2TxType::CreditRepay,
            L2TxType::CreditDefault,
            L2TxType::CreditOpenV2,
            L2TxType::GuardedOptIn,
            L2TxType::GuardedCancel,
            L2TxType::GuardedFreeze,
            L2TxType::AuditAnchor,
        ]
    );
    assert_eq!(L2TxType::ExitQueue.fee_sat(), 2_000);
    assert_eq!(known.len(), 18);
}

/// An exit-queue payload round-trips through the envelope and its signature
/// covers every consensus field: owner, nonce, amount, destination and fee.
#[test]
fn exit_queue_payload_round_trips_and_signs_every_field() {
    let w = wallet(1);
    let owner = addr(&w);
    let dest = [0xCCu8; 20];
    let base =
        ExitQueuePayload::build(&w, 7, 50_000, dest, 1_000).expect("owner funds irrelevant here");
    assert_eq!(base.owner, owner);
    base.verify_auth().unwrap();
    let tx = L2Transaction::new(L2Payload::ExitQueue(base.clone()));
    let back = L2Transaction::deserialize(&tx.serialize()).unwrap();
    assert_eq!(back, tx);
    assert_eq!(back.tx_type(), L2TxType::ExitQueue);

    // Mutating any consensus field breaks the authorization.
    for mutate in [
        "nonce",
        "amount_sat",
        "destination",
        "exit_fee_sat",
        "owner",
    ] {
        let mut changed = base.clone();
        match mutate {
            "nonce" => changed.nonce += 1,
            "amount_sat" => changed.amount_sat += 1,
            "destination" => changed.destination = [0xDDu8; 20],
            "exit_fee_sat" => changed.exit_fee_sat += 1,
            _ => changed.owner = [0xDDu8; 20],
        }
        assert!(
            changed.verify_auth().is_err(),
            "{mutate} must be covered by the signing hash"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Queue → release on the L2 side
// ---------------------------------------------------------------------------

const DEADLINE: u64 = 100;
/// `world()` credits two accounts (submitter and worker) at 10 SRCT each.
const CREDITED: u64 = 20_000_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "exit-flow").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn task() -> ComputeTask {
    ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 0,
        expiry_height: DEADLINE,
        submit_height: 0,
    }
}

fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::new((1..=n).map(|i| BlsPublicKey([i; 48])).collect())
}

fn settle_payload(
    task_id: Hash,
    verdict: Verdict,
    vwc_hash: Hash,
    signed: usize,
    total: usize,
    height: u64,
) -> SettlePayload {
    let n_bytes = total.div_ceil(8).max(1);
    let mut bitmap = vec![0u8; n_bytes];
    for i in 0..signed {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    SettlePayload {
        task_id,
        verdict,
        vwc_hash,
        network_id: "srct/mini".to_string(),
        height,
        bls_sig: [0xAAu8; 96],
        signer_bitmap: bitmap,
        signer_count: signed as u32,
        pq_sidecar: Vec::new(),
    }
}

fn attestation(w: &Wallet, task_id: Hash, result: Hash) -> ComputeAttestation {
    let mut a = ComputeAttestation {
        task_id,
        result_hash: result,
        backend: ComputeBackend::Gpu,
        worker_address: addr(w),
        attest_height: 0,
        signature: vec![],
    };
    a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
    a
}

/// `L2Config::mini` never activates exits (`0`); tests that queue use this.
fn exits_on() -> L2Config {
    let mut c = L2Config::mini();
    c.exit_activation_height = 1;
    c
}

struct World {
    state: L2State,
    submitter: Wallet,
    worker: Wallet,
    validators: ValidatorSet,
    verifier: MockBls,
}

fn world() -> World {
    world_with(L2Config::mini())
}

fn world_with(config: L2Config) -> World {
    let submitter = wallet(1);
    let worker = wallet(2);
    let mut state = L2State::new(config);
    state.credit(addr(&submitter), 10_000_000).unwrap();
    state.credit(addr(&worker), 10_000_000).unwrap();
    World {
        state,
        submitter,
        worker,
        validators: validators(4),
        verifier: MockBls,
    }
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) {
        self.state
            .apply(tx, height, &self.validators, &self.verifier)
            .expect("a well-formed step of the lifecycle");
    }

    fn assert_conserved(&self, step: &str) {
        assert!(
            self.state.check_conservation(),
            "{step}: conservation broken (conservation_total {} != funded_total {})",
            self.state.conservation_total(),
            self.state.funded_total()
        );
    }
}

fn queue_tx(w: &World, nonce: u64, amount: u64, fee: u64) -> L2Transaction {
    let dest = addr(&w.worker);
    let p = ExitQueuePayload::build(&w.submitter, nonce, amount, dest, fee).unwrap();
    L2Transaction::new(L2Payload::ExitQueue(p))
}

/// Queueing debits `amount + exit_fee + queue fee`, records the exit, and
/// release removes the record while moving its value out of L2 entirely.
/// Conservation holds at every step; `funded_total` drops by exactly the
/// released value, never more, never less.
#[test]
fn exit_queue_then_release_moves_value_out_exactly_once() {
    let mut w = world_with(exits_on());
    let funded = w.state.funded_total();
    assert_eq!(funded, CREDITED);

    let before = w.state.balance(&addr(&w.submitter));
    w.apply(&queue_tx(&w, 1, 1_000_000, 1_000), 5);
    // Debit is amount + prepaid release fee + the flat queue fee (2,000).
    assert_eq!(
        w.state.balance(&addr(&w.submitter)),
        before - 1_000_000 - 1_000 - 2_000
    );
    // The value sits encumbered, still inside L2: conservation is unchanged.
    assert_eq!(w.state.exits_locked_total(), 1_001_000);
    assert_eq!(w.state.funded_total(), funded);
    w.assert_conserved("queue");
    let record = w
        .state
        .exit(&addr(&w.submitter), 1)
        .expect("the queue record must exist")
        .clone();
    assert_eq!(record.queued_height, 5);
    assert_eq!(record.destination, addr(&w.worker));

    // Release (what replay does when it observes the L1 claim): the record is
    // gone and its value left L2 — funded drops by exactly amount + fee.
    let released = w.state.note_release(&addr(&w.submitter), 1).unwrap();
    assert_eq!(released, record);
    assert!(w.state.exit(&addr(&w.submitter), 1).is_none());
    assert_eq!(w.state.exits_locked_total(), 0);
    assert_eq!(w.state.exited_total(), 1_001_000);
    assert_eq!(w.state.funded_total(), funded - 1_001_000);
    w.assert_conserved("release");
}

/// Below the activation height queueing is refused: funds must never be
/// encumbered with no release. `L2Config::mini` never activates (`0`).
#[test]
fn queue_before_activation_is_refused() {
    let mut w = world();
    let tx = queue_tx(&w, 1, 1_000_000, 500);
    let err = w
        .state
        .apply(&tx, 5, &w.validators, &w.verifier)
        .expect_err("queueing must be refused while exits are inactive");
    assert_eq!(err, L2Error::ExitNotActive);
    assert_eq!(w.state.exit_count(), 0);
    w.assert_conserved("refused queue");
}

/// Nonces are strictly increasing per owner: a repeat or a rewind is refused,
/// a higher nonce is a new exit. Separate owners have separate sequences.
#[test]
fn queue_nonce_replay_and_rewind_are_refused() {
    let mut w = world_with(exits_on());
    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    w.apply(&queue_tx(&w, 2, 100_000, 1_000), 6);
    // A repeated nonce in *new* bytes (different amount, so a different txid
    // that clears the replay set) is refused by the nonce rule, not the txid
    // rule. A byte-identical resubmission would fail earlier as `Replay` —
    // both layers hold, and this test pins the nonce one specifically.
    for bad in [1, 2] {
        let dest = addr(&w.worker);
        let p = ExitQueuePayload::build(&w.submitter, bad, 200_000, dest, 1_000).unwrap();
        let err = w
            .state
            .apply(
                &L2Transaction::new(L2Payload::ExitQueue(p)),
                7,
                &w.validators,
                &w.verifier,
            )
            .expect_err("a repeated nonce must be refused");
        assert_eq!(err, L2Error::BadExitNonce);
    }
    w.apply(&queue_tx(&w, 3, 100_000, 1_000), 7);
    assert_eq!(w.state.exit_count(), 3);
    w.assert_conserved("nonces");
}

/// A queue the account cannot cover is refused with nothing written: no
/// record, no debit, no nonce consumed (a retry with funds is a new attempt,
/// not a replay).
#[test]
fn queue_without_funds_and_zero_amount_are_refused() {
    let mut w = world_with(exits_on());
    let poor = wallet(9);
    let dest = addr(&w.worker);
    let p = ExitQueuePayload::build(&poor, 1, 1_000_000, dest, 1_000).unwrap();
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::ExitQueue(p)),
            5,
            &w.validators,
            &w.verifier,
        )
        .expect_err("an unfunded queue must be refused");
    assert!(matches!(err, L2Error::InsufficientBalance { .. }));
    assert_eq!(w.state.exit_count(), 0);

    let p = ExitQueuePayload::build(&w.submitter, 1, 0, dest, 0).unwrap();
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::ExitQueue(p)),
            5,
            &w.validators,
            &w.verifier,
        )
        .expect_err("a zero-amount queue must be refused");
    assert!(matches!(err, L2Error::ZeroAmount(_)));
    w.assert_conserved("refused queues");
}

/// The prepaid release fee must clear `MIN_EXIT_FEE_SAT`: zero (or dust) pays
/// nobody to file the L1 release, so the exit would sit unclaimed forever.
/// Refused before any state moves; exactly the minimum queues.
#[test]
fn queue_below_the_minimum_exit_fee_is_refused() {
    let mut w = world_with(exits_on());
    let dest = addr(&w.worker);
    for fee in [0, MIN_EXIT_FEE_SAT - 1] {
        let p = ExitQueuePayload::build(&w.submitter, 1, 100_000, dest, fee).unwrap();
        let err = w
            .state
            .apply(
                &L2Transaction::new(L2Payload::ExitQueue(p)),
                5,
                &w.validators,
                &w.verifier,
            )
            .expect_err("a sub-minimum exit fee must be refused");
        assert_eq!(err, L2Error::ExitFeeBelowMinimum);
    }
    assert_eq!(w.state.exit_count(), 0);
    w.assert_conserved("refused fee");
    w.apply(&queue_tx(&w, 1, 100_000, MIN_EXIT_FEE_SAT), 6);
    assert_eq!(w.state.exit_count(), 1);
}

/// Releasing an unknown exit — never queued, or already released and therefore
/// removed — is refused by name. There is no second release.
#[test]
fn release_of_unknown_or_released_exit_is_refused() {
    let mut w = world_with(exits_on());
    let owner = addr(&w.submitter);
    assert_eq!(
        w.state.note_release(&owner, 1).expect_err("unknown exit"),
        L2Error::UnknownExit
    );
    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    w.state.note_release(&owner, 1).unwrap();
    assert_eq!(
        w.state.note_release(&owner, 1).expect_err("second release"),
        L2Error::UnknownExit
    );
    w.assert_conserved("releases");
}

/// Maturity is the deposit rule, never weaker: depth `maturity_depth` **and**
/// the binding checkpoint height once binding finality is active.
#[test]
fn exit_maturity_needs_depth_and_binding_finality() {
    use srct_l2::L2State as S;
    // Depth only (binding inactive): mature at Q + depth, not before.
    assert!(!S::exit_is_mature(10, 29, 0, 20));
    assert!(S::exit_is_mature(10, 30, 0, 20));
    // Binding active: the queue block must also sit under the checkpoint.
    assert!(!S::exit_is_mature(10, 300, 9, 20));
    assert!(S::exit_is_mature(10, 300, 10, 20));
    assert!(S::exit_is_mature(10, 300, 50, 20));
}

/// With no queued exits the committed root is the account root: a pre-exit
/// state commits identically under both functions.
#[test]
fn committed_root_matches_state_root_without_exits() {
    let w = world_with(exits_on());
    assert_eq!(w.state.committed_root(), w.state.state_root());
}

/// A queued exit record proves against the committed root, and only as
/// queued: any field changed, and the proof fails. After release the record
/// has no leaf and no proof.
#[test]
fn exit_record_proves_against_the_committed_root_until_release() {
    let mut w = world_with(exits_on());
    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    let owner = addr(&w.submitter);
    let root = w.state.committed_root();
    assert_ne!(root, w.state.state_root(), "the exit must move the root");
    let proof = w.state.exit_proof(&owner, 1).expect("queued exit proves");
    let record = w.state.exit(&owner, 1).unwrap().clone();
    assert!(verify_inclusion(root, record.leaf(), &proof));
    // The proof binds every record field: amount, destination, fee, height.
    let mut forged = record.clone();
    forged.amount_sat += 1;
    assert!(!verify_inclusion(root, forged.leaf(), &proof));
    // Unknown owner/nonce has no proof.
    assert!(w.state.exit_proof(&addr(&w.worker), 1).is_none());
    assert!(w.state.exit_proof(&owner, 2).is_none());
    // After release the leaf is gone: no proof, and the root moves back.
    w.state.note_release(&owner, 1).unwrap();
    assert!(w.state.exit_proof(&owner, 1).is_none());
}

/// The wire blob round-trips with exits inside it, and a decoded state still
/// conserves — an observer that decodes this blob sees the same queue.
#[test]
fn state_wire_round_trips_with_queued_exits() {
    let mut w = world_with(exits_on());
    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    let bytes = w.state.encode();
    let back = L2State::decode(&bytes).expect("a fresh encode must decode");
    assert_eq!(back, w.state);
    assert!(back.check_conservation());
    assert!(back.exit(&addr(&w.submitter), 1).is_some());
}

/// Restart from the same blocks reaches the same exits: replay, not
/// persistence, is what reconstructs the queue (reorg safety by
/// construction).
#[test]
fn replay_rebuilds_identical_exit_state() {
    use srct_core::params::NetworkParams;
    use srct_l2::{ChainL2, DepositParams, L2Genesis};
    let params = NetworkParams::mini();
    let mut config = exits_on();
    config.exit_activation_height = params.exit_activation_height;
    let genesis = L2Genesis::for_params(&params);
    let deposits = DepositParams::for_params(&params);
    let mut first = ChainL2::empty(config.clone(), &genesis, deposits).unwrap();
    let mut second = ChainL2::empty(config, &genesis, deposits).unwrap();
    // Fund both identically outside genesis (unit-test seam, like `world`).
    for l2 in [&mut first, &mut second] {
        l2.state_mut().credit(addr(&wallet(1)), 10_000_000).unwrap();
    }
    let tx = {
        let w = wallet(1);
        let p = ExitQueuePayload::build(&w, 1, 100_000, addr(&wallet(2)), 1_000).unwrap();
        L2Transaction::new(L2Payload::ExitQueue(p))
    };
    for l2 in [&mut first, &mut second] {
        l2.state_mut()
            .apply(&tx, 5, &validators(4), &MockBls)
            .unwrap();
    }
    assert_eq!(first.state(), second.state());
    assert_eq!(first.state().exit_count(), 1);
}

// ---------------------------------------------------------------------------
// 3. The settlement lifecycle still closes without exits
// ---------------------------------------------------------------------------

/// A complete lifecycle — funded post, claim, submit, explicit quorum settle —
/// moves value between L2 buckets and never out of L2 unless an exit is
/// queued and released (tested above).
#[test]
fn value_stays_in_l2_across_a_full_settlement_lifecycle() {
    let mut w = world_with(exits_on());
    let funded = w.state.funded_total();
    assert_eq!(funded, CREDITED);

    let post = PostTaskPayload::build(&w.submitter, 1, 1_000_000, DEADLINE, task()).unwrap();
    let id = post.task_id;
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 1);

    let claim = ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Gpu, 50_000).unwrap();
    w.apply(&L2Transaction::new(L2Payload::Claim(claim)), 2);

    let result = [0xAAu8; 32];
    let submit =
        SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, result)).unwrap();
    w.apply(&L2Transaction::new(L2Payload::Submit(submit)), 3);

    let settle = settle_payload(id, Verdict::Correct, result, 3, w.validators.len(), 9);
    w.apply(&L2Transaction::new(L2Payload::Settle(settle)), 9);

    assert_eq!(w.state.funded_total(), funded);
    w.assert_conserved("settle");
    assert!(w.state.total_locked() == 0, "escrow must be fully released");
    assert!(
        w.state.balance(&addr(&w.worker)) > 10_000_000,
        "the worker must have been paid"
    );
    assert_eq!(w.state.conservation_total(), funded);
}

/// The accumulated L2 fees are burned or parked in PSCB, never moved to L1.
#[test]
fn l2_fees_reduce_l2_buckets_and_never_reach_l1() {
    let mut w = world_with(exits_on());
    let funded = w.state.funded_total();
    let post = PostTaskPayload::build(&w.submitter, 1, 1_000_000, DEADLINE, task()).unwrap();
    let id = post.task_id;
    let fee = L2Transaction::new(L2Payload::Post(post.clone())).fee_sat();
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 1);

    assert_eq!(w.state.pscb, fee / 2, "half the post fee accrues to PSCB");
    assert_eq!(w.state.burned, fee - fee / 2, "the rest is burned in L2");
    assert_eq!(w.state.funded_total(), funded);
    w.assert_conserved("post fee");
    assert!(w.state.task(&id).is_some());
}

/// The protocol escrow identity holds an L2 balance and has no key — the same
/// structural fact as the L1 sink, on the L2 side. Nobody can authorize an
/// exit from it, so its balance never queues.
#[test]
fn the_l2_escrow_identity_has_no_key() {
    use srct_core::params::{NetworkParams, SAT_PER_SRCT};
    use srct_l2::{L2Genesis, L2State};

    let params = NetworkParams::mini();
    let mut state = L2State::new(exits_on());
    state
        .apply_genesis(&L2Genesis::for_params(&params))
        .unwrap();

    let escrow = params.l2_escrow_address();
    assert!(state.balance(&escrow) > 0);
    assert_eq!(
        state.balance(&escrow),
        params.l2_genesis_escrow_sat - 3 * SAT_PER_SRCT
    );
    for seed in 1..=8u8 {
        assert_ne!(addr(&wallet(seed)), escrow);
    }
    assert!(state.check_conservation());
}

// ---------------------------------------------------------------------------
// 8. Exit proof against the committed root when policies/positions exist
//    (regression for the divergent-leaf-set bug: exit_proof used to build
//    only accounts+exits, but committed_root commits accounts+exits+policies+
//    positions — so the proof index landed on the wrong leaf and the proof
//    never verified once a single policy or position existed.)
// ---------------------------------------------------------------------------

fn network_id() -> String {
    L2Config::mini().network_id
}

/// Publish a grant signed by `owner` for `agent` spending `recipient`'s funds.
fn publish_policy(
    state: &mut L2State,
    validators: &ValidatorSet,
    owner: &Wallet,
    agent: &Wallet,
    recipient: &Wallet,
) -> Hash {
    let agent_id = derive_agent_id(&network_id(), AgentRole::Machine, &owner.address().unwrap());
    let policy = SpendPolicy {
        version: srct_core::agent::POLICY_VERSION,
        network_id: network_id(),
        agent_id,
        owner: owner.address().unwrap(),
        role: AgentRole::Machine,
        per_tx_max_sat: 10_000,
        window_blocks: 100,
        cumulative_max_sat: 100_000,
        allowed_recipients: vec![recipient.address().unwrap()],
        allowed_services: vec![],
        not_before_height: 0,
        expires_at_height: 1_000_000,
        revoked: false,
        parent_agent_id: None,
    };
    let payload =
        PolicyPayload::build_from_policy(owner, &policy, agent.address().unwrap()).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    state
        .apply(&tx, 10, validators, &MockBls)
        .expect("the grant publishes");
    policy.hash()
}

/// Open a credit position: lender funds borrower's account, collateral locks.
fn open_credit(
    state: &mut L2State,
    validators: &ValidatorSet,
    lender: &Wallet,
    borrower: Address,
    amount: u64,
    collateral: u64,
) {
    let payload =
        CreditOpenPayload::build(lender, borrower, amount, collateral, 100, 100, 1_000, 1).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    state
        .apply(&tx, 10, validators, &MockBls)
        .expect("the credit position opens");
}

/// An exit queued into a state that already holds a published policy still
/// proves against `committed_root()` — the proof index must account for the
/// policy leaf that now sits after the exit leaves.
#[test]
fn exit_proof_verifies_with_a_policy_already_published() {
    let mut w = world_with(exits_on());
    // Insert a policy leaf before queueing so the exit is *not* the last leaf.
    let policy_hash = publish_policy(
        &mut w.state,
        &w.validators,
        &w.submitter,
        &wallet(3),
        &w.worker,
    );
    assert!(
        w.state.policy(&policy_hash).is_some(),
        "policy was published"
    );

    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    let owner = addr(&w.submitter);
    let root = w.state.committed_root();
    let proof = w.state.exit_proof(&owner, 1).expect("queued exit proves");
    let record = w.state.exit(&owner, 1).unwrap().clone();
    assert!(
        verify_inclusion(root, record.leaf(), &proof),
        "exit proof must verify against committed_root even with policies present"
    );
    w.assert_conserved("policy + exit");
}

/// An exit queued into a state that already holds a credit position still
/// proves against `committed_root()` — the index must skip position leaves.
#[test]
fn exit_proof_verifies_with_a_credit_position_already_open() {
    let mut w = world_with(exits_on());
    // Open a credit position to add a position leaf before queueing.
    // Use `worker` (wallet 2, already credited) as borrower so collateral is funded.
    open_credit(
        &mut w.state,
        &w.validators,
        &w.submitter,
        addr(&w.worker),
        100_000,
        100_000,
    );
    assert!(
        !w.state.credit_positions().is_empty(),
        "position was opened"
    );

    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    let owner = addr(&w.submitter);
    let root = w.state.committed_root();
    let proof = w.state.exit_proof(&owner, 1).expect("queued exit proves");
    let record = w.state.exit(&owner, 1).unwrap().clone();
    assert!(
        verify_inclusion(root, record.leaf(), &proof),
        "exit proof must verify against committed_root even with positions present"
    );
    w.assert_conserved("credit + exit");
}

/// An exit queued into a state with both policies and credit positions proves
/// against `committed_root()` — every leaf category shifts the index.
#[test]
fn exit_proof_verifies_with_policies_and_positions_present() {
    let mut w = world_with(exits_on());
    let ph = publish_policy(
        &mut w.state,
        &w.validators,
        &w.submitter,
        &wallet(3),
        &w.worker,
    );
    assert!(w.state.policy(&ph).is_some());
    // Use `worker` (already credited) as borrower.
    open_credit(
        &mut w.state,
        &w.validators,
        &w.submitter,
        addr(&w.worker),
        100_000,
        100_000,
    );

    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    let owner = addr(&w.submitter);
    let root = w.state.committed_root();
    let proof = w.state.exit_proof(&owner, 1).expect("queued exit proves");
    let record = w.state.exit(&owner, 1).unwrap().clone();
    assert!(
        verify_inclusion(root, record.leaf(), &proof),
        "exit proof must verify against committed_root with policies + positions"
    );
    w.assert_conserved("policy + credit + exit");
}

/// A proof built against a root that does **not** include the policy leaf
/// must fail — this pins that `exit_proof` really uses `committed_root`, not
/// a stale accounts+exits root.
#[test]
fn exit_proof_fails_against_a_root_built_without_policies() {
    let mut w = world_with(exits_on());
    // Queue an exit *before* the policy, so the pre-policy root is a real one.
    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    let owner = addr(&w.submitter);

    // Capture the root before policies are added (accounts + exits only).
    let stale_root = w.state.committed_root();
    let proof = w.state.exit_proof(&owner, 1).expect("queued exit proves");
    let record = w.state.exit(&owner, 1).unwrap().clone();
    assert!(
        verify_inclusion(stale_root, record.leaf(), &proof),
        "proof verifies against the pre-policy root"
    );

    // Now publish a policy — this changes `committed_root` but not the proof.
    publish_policy(
        &mut w.state,
        &w.validators,
        &w.submitter,
        &wallet(3),
        &w.worker,
    );
    let new_root = w.state.committed_root();
    assert_ne!(new_root, stale_root, "policy changes the committed root");
    assert!(
        !verify_inclusion(new_root, record.leaf(), &proof),
        "proof from before the policy must not verify against the post-policy root"
    );
}

/// A throttled config refuses the queue that would overflow the window, keeps
/// funds untouched, and admits it again once the window rolls over.
#[test]
fn exit_window_cap_refuses_then_reopens() {
    let mut cfg = exits_on();
    cfg.max_exit_window_sat = 1_500_000;
    cfg.exit_window_blocks = 10;
    let mut w = world_with(cfg);
    // First queue (1M) fits; second (1M) would total 2M over a 1.5M cap.
    w.apply(&queue_tx(&w, 1, 1_000_000, 1_000), 5);
    let before = w.state.balance(&addr(&w.submitter));
    let over = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(&w.submitter, 2, 1_000_000, addr(&w.worker), 1_000).unwrap(),
    ));
    let err = w
        .state
        .apply(&over, 5, &w.validators, &w.verifier)
        .expect_err("window overflow must be refused");
    assert!(
        matches!(err, L2Error::ExitWindowFull { .. }),
        "the refusal names the window: {err:?}"
    );
    // Nothing moved: balance, locked total and nonce are exactly as before.
    assert_eq!(w.state.balance(&addr(&w.submitter)), before);
    assert_eq!(w.state.exits_locked_total(), 1_001_000);
    // Next window: the same queue is admitted.
    w.apply(&queue_tx(&w, 2, 1_000_000, 1_000), 15);
    assert_eq!(w.state.exits_locked_total(), 2_002_000);
    w.assert_conserved("window rollover");
}

/// One actor may not fill the window alone: the per-owner sub-cap refuses
/// the filler by name while a different owner still queues in the same
/// window. This is the fairness bound — without it, a filler holding the
/// global cap open starves every other owner until rollover, at fee cost.
#[test]
fn exit_per_owner_subcap_refuses_filler_but_admits_others() {
    let mut cfg = exits_on();
    cfg.max_exit_window_sat = 1_500_000;
    cfg.exit_window_blocks = 10;
    cfg.max_exit_per_owner_window_sat = 600_000;
    let mut w = world_with(cfg);
    // The attacker queues 500k: fits both caps.
    w.apply(&queue_tx(&w, 1, 500_000, 1_000), 5);
    // Another 500k of their own would be 1M against a 600k share: refused
    // by name, even though the 1.5M global cap still has room.
    let dest = addr(&w.worker);
    let p = ExitQueuePayload::build(&w.submitter, 2, 500_000, dest, 1_000).unwrap();
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::ExitQueue(p)),
            5,
            &w.validators,
            &w.verifier,
        )
        .expect_err("own share overflow must be refused");
    assert!(
        matches!(
            err,
            L2Error::ExitOwnerWindowFull {
                owner_total: 1_000_000,
                owner_cap: 600_000,
                ..
            }
        ),
        "the refusal names the owner share: {err:?}"
    );
    // Nothing moved for the refused queue: no record, no debit, no nonce.
    assert_eq!(w.state.exit_count(), 1);
    assert_eq!(w.state.exit_window_total(), 500_000);
    // A different owner still queues inside the same window: the filler
    // holds nobody else out.
    let victim = ExitQueuePayload::build(&w.worker, 1, 400_000, addr(&w.submitter), 1_000).unwrap();
    w.state
        .apply(
            &L2Transaction::new(L2Payload::ExitQueue(victim)),
            5,
            &w.validators,
            &w.verifier,
        )
        .expect("other owners are unaffected by one owner's share");
    assert_eq!(w.state.exit_count(), 2);
    assert_eq!(w.state.exit_window_total(), 900_000);
    w.assert_conserved("per-owner sub-cap");
}

/// The per-owner share resets when the window rolls, exactly like the
/// global total: last window's filler queues again in the next one.
#[test]
fn exit_per_owner_share_resets_when_the_window_rolls() {
    let mut cfg = exits_on();
    cfg.max_exit_window_sat = 1_500_000;
    cfg.exit_window_blocks = 10;
    cfg.max_exit_per_owner_window_sat = 600_000;
    let mut w = world_with(cfg);
    w.apply(&queue_tx(&w, 1, 500_000, 1_000), 5);
    let dest = addr(&w.worker);
    let p = ExitQueuePayload::build(&w.submitter, 2, 500_000, dest, 1_000).unwrap();
    assert!(matches!(
        w.state.apply(
            &L2Transaction::new(L2Payload::ExitQueue(p)),
            5,
            &w.validators,
            &w.verifier,
        ),
        Err(L2Error::ExitOwnerWindowFull { .. })
    ));
    // Next window: the share is fresh, the same queue is admitted.
    w.apply(&queue_tx(&w, 2, 500_000, 1_000), 15);
    assert_eq!(w.state.exit_count(), 2);
    assert_eq!(w.state.exit_window_total(), 500_000);
    w.assert_conserved("owner share rollover");
}

/// The owner shares travel on the wire with the window they break down: a
/// fresh encode decodes to the identical state, and conservation holds.
#[test]
fn exit_window_owner_shares_round_trip_on_the_wire() {
    let mut cfg = exits_on();
    cfg.max_exit_window_sat = 1_500_000;
    cfg.exit_window_blocks = 10;
    cfg.max_exit_per_owner_window_sat = 600_000;
    let mut w = world_with(cfg);
    w.apply(&queue_tx(&w, 1, 500_000, 1_000), 5);
    let victim = ExitQueuePayload::build(&w.worker, 1, 400_000, addr(&w.submitter), 1_000).unwrap();
    w.state
        .apply(
            &L2Transaction::new(L2Payload::ExitQueue(victim)),
            5,
            &w.validators,
            &w.verifier,
        )
        .unwrap();
    let bytes = w.state.encode();
    let back = L2State::decode(&bytes).expect("a fresh encode must decode");
    assert_eq!(back, w.state);
    assert!(back.check_conservation());
}

/// A blob whose owner shares do not add up to the window total is tampered
/// with, not merely odd: the breakdown is re-checked at decode.
#[test]
fn exit_window_owner_shares_must_agree_with_the_total() {
    let mut cfg = exits_on();
    cfg.max_exit_window_sat = 1_500_000;
    cfg.exit_window_blocks = 10;
    cfg.max_exit_per_owner_window_sat = 600_000;
    let mut w = world_with(cfg);
    w.apply(&queue_tx(&w, 1, 500_000, 1_000), 5);
    let bytes = w.state.encode();
    // The owner map is the last place the owner's address appears on the
    // wire (accounts, exit records and the nonce map all come first; only
    // empty maps and the vault follow in this fixture), so the final
    // occurrence is the map entry and the 8 bytes after it are its total.
    let owner = addr(&w.submitter);
    let at = bytes
        .windows(20)
        .rposition(|s| s == owner.as_slice())
        .expect("the owner is on the wire");
    let mut forged = bytes.clone();
    let total = u64::from_le_bytes(forged[at + 20..at + 28].try_into().unwrap());
    forged[at + 20..at + 28].copy_from_slice(&(total + 1).to_le_bytes());
    let err = L2State::decode(&forged).expect_err("a forged share must be refused");
    assert!(
        err.to_string().contains("disagree with the window total"),
        "the refusal names the breakdown: {err}"
    );
}

/// A large exit waits the extra delay on top of base maturity — same rule on
/// the L2 queue side and (via chain params) on the L1 release side.
#[test]
fn large_exit_waits_extra_maturity() {
    assert_eq!(
        L2State::exit_maturity_depth_for(99, 20, 100, 144),
        20,
        "below the threshold the bare depth governs"
    );
    assert_eq!(
        L2State::exit_maturity_depth_for(100, 20, 100, 144),
        164,
        "at the threshold the extra delay applies (inclusive)"
    );
    // Disabled profiles add nothing regardless of size.
    assert_eq!(L2State::exit_maturity_depth_for(u64::MAX, 20, 0, 0), 20);
}

/// After release, the exit leaf is gone and adding a policy does not resurrect
/// it — proves against the *current* tree even when the tree shrinks.
#[test]
fn exit_proof_after_release_and_policy_is_none() {
    let mut w = world_with(exits_on());
    publish_policy(
        &mut w.state,
        &w.validators,
        &w.submitter,
        &wallet(3),
        &w.worker,
    );

    w.apply(&queue_tx(&w, 1, 100_000, 1_000), 5);
    let owner = addr(&w.submitter);

    // Publish a second policy (by `worker`, who is also credited) after the exit.
    publish_policy(
        &mut w.state,
        &w.validators,
        &w.worker,
        &wallet(4),
        &w.submitter,
    );

    w.state.note_release(&owner, 1).unwrap();
    assert!(
        w.state.exit_proof(&owner, 1).is_none(),
        "released exit has no leaf even with policies in the tree"
    );
}
