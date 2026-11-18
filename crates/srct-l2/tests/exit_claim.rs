//! L2 → L1 exit claims, L1 side (approved P1, E-1…E-3).
//!
//! These tests drive a real [`Chain`] through the whole loop the design
//! requires: deposit to the sink, queue on L2, mature under the depth rule,
//! release by a permissionless claim, and the joint accounting after. The L2
//! queue half is pinned in `exit_flow.rs`; what is under test here is the
//! consensus release rule — proof against the committed root, exact funding,
//! idempotency, reorg unwind — and that a block carrying any of it is still a
//! valid block by every pre-exit rule.
//!
//! Profile: `mini` (exit activation at 1, depth-only finality, 20-block
//! finality depth). Binding finality is covered by the L2-side maturity unit
//! test; these tests pin the depth half on a live chain.

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::{Chain, DEFAULT_MAX_ATTEMPTS};
use srct_core::exit::ExitClaim;
use srct_core::hash::Address;
use srct_core::l2::{ExitQueuePayload, L2Payload, L2Transaction};
use srct_core::mempool::Mempool;
use srct_core::params::NetworkParams;
use srct_core::tx::{OutPoint, Output};
use srct_core::wallet::Wallet;
use srct_l2::{ChainL2, DepositParams, L2Config, L2Genesis, L2State};
use srct_l2::L2Error;

use srct_core::bls_checkpoint::{MockBls, ValidatorSet};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const SINK_VALUE: u64 = 100_000_000; // 1 SRCT deposit
const EXIT_FEE: u64 = 1_000_000;
const QUEUE_FLAT_FEE: u64 = 2_000; // FEE_TX_EXIT_QUEUE_SAT

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "exit-claim").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn ts(h: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + h * 1_000
}

fn l2config() -> L2Config {
    let mut c = L2Config::mini();
    c.exit_activation_height = 1;
    c
}

fn l2view(chain: &Chain) -> ChainL2 {
    let params = NetworkParams::mini();
    // Authority resolves per height inside replay now.
    ChainL2::replay(
        chain,
        l2config(),
        &L2Genesis::for_params(&params),
        DepositParams::for_params(&params),
        &MockBls,
    )
    .unwrap()
}

fn mine_empty_to(chain: &mut Chain, miner: Address, to: u64) {
    while chain.height() < to {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

/// A mature miner coinbase outpoint (mini maturity is 10).
fn mature_outpoint(chain: &Chain, miner: Address) -> (OutPoint, u64) {
    chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == miner && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase")
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    let gas = 16_000 + 1_000 * n_in as u64 + 250 * n_out as u64;
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000)
}

/// The world an exit test needs: a chain with a matured 1-SRCT deposit and the
/// L2 view that credited it. Returns `(chain, miner, deposit_height)`.
fn deposited_world() -> (Chain, Wallet, u64) {
    let params = NetworkParams::mini();
    let miner = wallet(9);
    let me = addr(&miner);
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, me, 12);
    // Deposit: miner pays the sink; miner is the single input owner, so the
    // L2 recipient is the miner (Decision 10 item 2).
    let (op, value) = mature_outpoint(&chain, me);
    let fee = fee_for(&chain, 1, 2);
    let tx = miner
        .build_tx(
            &[op],
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
    let d = chain.height() + 1;
    let b = chain.mine_block(me, vec![tx], ts(d)).unwrap();
    chain.submit(b).unwrap();
    // Mature the deposit: spendable at D + finality_depth (20 on mini).
    mine_empty_to(&mut chain, me, d + 20);
    (chain, miner, d)
}

/// The sink outpoint holding the deposit.
fn sink_outpoint(chain: &Chain) -> (OutPoint, u64) {
    let sink = NetworkParams::mini().l2_deposit_sink();
    chain
        .utxo()
        .outputs_for_address(&sink)
        .into_iter()
        .next()
        .expect("the deposit sink output")
}

/// Queue an exit at the tip+1 and return `(queue_height, queue_txid_state)`.
/// Mines the queue block with the correctly computed committed root and
/// returns the L2 state right after it (for building the claim proof).
fn queue_exit(
    chain: &mut Chain,
    l2: &mut ChainL2,
    owner: &Wallet,
    nonce: u64,
    amount: u64,
    dest: Address,
) -> (u64, srct_l2::L2State) {
    let q = chain.height() + 1;
    let me = addr(owner);
    let p = ExitQueuePayload::build(owner, nonce, amount, dest, EXIT_FEE).unwrap();
    let tx = L2Transaction::new(L2Payload::ExitQueue(p));
    // Simulate Q's L2 transitions to commit the exact root the block claims:
    // the trailer transaction at Q, no deposits in Q's (empty) body.
    let mut sim = l2.state().clone();
    sim.advance_block(q);
    sim.apply(&tx, q, &ValidatorSet::new(vec![]), &MockBls)
        .expect("the queue must apply: balance was credited by the deposit");
    let root = sim.committed_root();
    let b = chain
        .mine_block_with_l2_root(
            me,
            vec![],
            vec![tx],
            root,
            ts(q),
            None,
            DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(b).unwrap();
    assert_eq!(
        chain.block_at(q).unwrap().l2_state_root,
        Some(root),
        "the queue block must commit the simulated root"
    );
    // Bring the caller's view forward past the queue block it just mined:
    // the simulation above ran on a clone, so without this the view would
    // stay stale at the pre-queue height and its balances would lie.
    *l2 = l2view(chain);
    (q, sim)
}

/// Build the release claim for a queued exit against the Q-state.
#[allow(clippy::too_many_arguments)]
fn build_claim(
    chain: &Chain,
    sim_q: &srct_l2::L2State,
    owner: Address,
    nonce: u64,
    amount: u64,
    dest: Address,
    claimant: Address,
    q: u64,
) -> ExitClaim {
    let proof = sim_q
        .exit_proof(&owner, nonce)
        .expect("the queued exit must prove against its own root");
    let (sink_op, sink_value) = sink_outpoint(chain);
    assert_eq!(sink_value, SINK_VALUE);
    // Exact funding: sink == amount + prepaid fee + required L1 fee.
    let gas = 16_000 + 1_000 + 2 * 250;
    let l1_fee = chain.expected_base_fee_for_next_block() * gas;
    assert_eq!(
        SINK_VALUE,
        amount + EXIT_FEE + l1_fee,
        "the test setup must fund the claim exactly"
    );
    ExitClaim {
        owner,
        nonce,
        amount_sat: amount,
        destination: dest,
        claimant,
        exit_fee_sat: EXIT_FEE,
        queued_height: q,
        inputs: vec![sink_op],
        proof,
        proof_height: None,
    }
}

// ---------------------------------------------------------------------------
// 1. The full loop
// ---------------------------------------------------------------------------

/// Deposit → queue → mature → release: the destination gets exactly the
/// principal, the crank (here the miner) gets exactly the prepaid fee, the
/// sink output is consumed, the identity is marked, and the chain still
/// verifies. L2 `note_release` mirrors what replay will do once the absorb
/// hook lands; conservation holds on both sides.
#[test]
fn exit_claim_releases_exactly_once_and_conserves() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    assert_eq!(l2.state().balance(&me), SINK_VALUE);

    // The base fee must sit at its floor before queueing: the claim amount is
    // committed in the queue record, so the L1 fee it implies has to be
    // stable from here to the claim block. Empty blocks pin it at the floor.
    assert_eq!(chain.expected_base_fee_for_next_block(), 10);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    // The queue debit is amount + prepaid fee + the flat queue fee: pin it,
    // so a silent fee change breaks this test rather than the accounting.
    let before = l2.state().balance(&me);
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    assert_eq!(
        l2.state().balance(&me),
        before - amount - EXIT_FEE - QUEUE_FLAT_FEE
    );
    // Mature: tip must reach Q + 20.
    mine_empty_to(&mut chain, me, q + 20);
    assert_eq!(chain.expected_base_fee_for_next_block(), 10);

    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    assert!(claim.verify_proof(&chain.block_at(q).unwrap().l2_state_root.unwrap()));
    let h = chain.height() + 1;
    chain
        .mine_from_pool_with_exits(
            &mut Mempool::new(1 << 20),
            me,
            ts(h),
            vec![],
            vec![claim.clone()],
            None,
        )
        .unwrap();
    assert_eq!(chain.height(), h);

    // Principal and fee land exactly where the record says.
    let dest_got: u64 = chain
        .utxo()
        .outputs_for_address(&dest)
        .iter()
        .map(|(_, v)| v)
        .sum();
    assert_eq!(dest_got, amount);
    let fee_got: u64 = chain
        .utxo()
        .outputs_for_address(&me)
        .iter()
        .filter(|(op, _)| op.txid == claim.claim_id())
        .map(|(_, v)| v)
        .sum();
    assert_eq!(fee_got, EXIT_FEE);
    // The sink output is consumed, not copied.
    assert!(chain
        .utxo()
        .outputs_for_address(&NetworkParams::mini().l2_deposit_sink())
        .is_empty());
    assert!(chain.exit_released(&me, 1));
    chain.verify_canonical_chain().unwrap();

    // L2 side: replay observed the release itself, so the record is already gone
    // and the books need no manual nudge.
    let l2_after = l2view(&chain);
    assert!(
        l2_after.state().exit(&me, 1).is_none(),
        "replay absorbed the release: a released exit cannot be proven again"
    );
    assert!(l2_after.state().check_conservation());
    assert_eq!(
        l2_after.state().funded_total(),
        l2.state().funded_total() - (amount + EXIT_FEE)
    );
}

// ---------------------------------------------------------------------------
// 2. Refusals, each by name
// ---------------------------------------------------------------------------

/// A claim before depth maturity is refused — the queue block is not final.
#[test]
fn exit_before_finality_is_refused_by_name() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    assert_eq!(chain.expected_base_fee_for_next_block(), 10);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);

    // One block later: Q + 1 < Q + 20, not mature.
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("not yet mature")),
        "immature claim must be refused by name, got {res:?}"
    );
    assert_eq!(chain.height(), h - 1, "the refused block must not land");
    assert!(!chain.exit_released(&me, 1));
}

/// The same claim in a second block is refused: one release per identity.
#[test]
fn exit_replay_is_refused_by_name() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    chain
        .mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim.clone()], None)
        .unwrap();
    // Mine one more block carrying the identical claim: consensus refuses it.
    let h2 = chain.height() + 1;
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h2), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("already released")),
        "replayed claim must be refused by name, got {res:?}"
    );
}

/// A proof that does not match the record — here a tampered amount — verifies
/// against nothing and the claim is refused before any value moves.
#[test]
fn exit_with_forged_proof_is_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let mut claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    claim.amount_sat += 1; // the proof no longer matches the record
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("does not verify")),
        "forged proof must be refused by name, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}

/// A claim whose inputs are not sink outputs is refused: the release rule
/// moves sink value only, never an ordinary coin.
#[test]
fn exit_consuming_a_non_sink_input_is_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let mut claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    // Swap the sink input for an ordinary miner coinbase of equal value...
    // there is none of exactly SINK_VALUE, so fund exactly: the point is the
    // address check fires, not the funding check. Use the sink output but
    // re-point a copy at a normal address is impossible — instead spend a
    // normal output and let the address rule fire first.
    let (normal_op, _) = mature_outpoint(&chain, me);
    claim.inputs = vec![normal_op];
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("not a sink output")
            || e.to_string().contains("must total exactly")),
        "non-sink input must be refused by name, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}

/// A queue for less than the sink output leaves the claim underfunded: inputs
/// must total *exactly* principal + fee + L1 fee, so the claim is refused and
/// nothing moves.
#[test]
fn exit_with_inexact_funding_is_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    // Queue 1,000 sat short of exact: the proof is valid for this record, but
    // the sink output overpays it, so funding is inexact.
    let amount = SINK_VALUE - EXIT_FEE - l1_fee - 1_000;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    // Build the claim by hand: build_claim's exactness assert would fire, so
    // replicate it with the short amount (proof matches this record).
    let proof = sim_q.exit_proof(&me, 1).unwrap();
    let (sink_op, _) = sink_outpoint(&chain);
    let claim = ExitClaim {
        owner: me,
        nonce: 1,
        amount_sat: amount,
        destination: dest,
        claimant: me,
        exit_fee_sat: EXIT_FEE,
        queued_height: q,
        inputs: vec![sink_op],
        proof,
        proof_height: None,
    };
    assert!(claim.verify_proof(&chain.block_at(q).unwrap().l2_state_root.unwrap()));
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("must total exactly")),
        "inexact funding must be refused by name, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}

// ---------------------------------------------------------------------------
// 3. Activation gating
// ---------------------------------------------------------------------------

/// Below activation (a profile carrying `0`) a claim is refused before any proof
/// is read — and an L2 section without a root is still fine there, because
/// the root rule only exists at and after activation.
#[test]
fn pre_activation_claim_is_refused() {
    let mut params = NetworkParams::mainnet();
    params.exit_activation_height = 0;
    assert_eq!(params.exit_activation_height, 0);
    let miner = wallet(9);
    let me = addr(&miner);
    let mut chain = Chain::new(params).unwrap();
    mine_empty_to(&mut chain, me, 3);
    // The proof field is never read: activation fires first. Any bytes decode
    // here; what matters is the refusal names activation, not the proof.
    let claim = ExitClaim {
        owner: me,
        nonce: 1,
        amount_sat: 100,
        destination: dest_of(),
        claimant: me,
        exit_fee_sat: 0,
        queued_height: 1,
        inputs: vec![OutPoint {
            txid: [0x55u8; 64],
            index: 0,
        }],
        proof: srct_core::state_root::InclusionProof {
            index: 0,
            leaf_count: 1,
            siblings: vec![],
        },
        proof_height: None,
    };
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("before activation")),
        "pre-activation claim must be refused by name, got {res:?}"
    );
}

fn dest_of() -> Address {
    addr(&wallet(8))
}

/// At and after activation, L2 transactions without a committed root are
/// refused: a queue in such a block could never be proven.
#[test]
fn post_activation_l2_without_root_is_refused() {
    let miner = wallet(9);
    let me = addr(&miner);
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_empty_to(&mut chain, me, 2);
    // A bare L2 transaction (no signature check at L1: validity is L2's job).
    let tx = L2Transaction::new(L2Payload::ExitQueue(srct_core::l2::ExitQueuePayload {
        owner: me,
        auth: Default::default(),
        nonce: 1,
        amount_sat: 1,
        destination: dest_of(),
        exit_fee_sat: 0,
    }));
    let h = chain.height() + 1;
    let b = chain
        .mine_block_with_l2(me, vec![], vec![tx], ts(h), None, DEFAULT_MAX_ATTEMPTS)
        .unwrap();
    let res = chain.submit(b);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("must commit a root")),
        "rootless post-activation L2 must be refused by name, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Reorg unwinds a release
// ---------------------------------------------------------------------------

/// A reorg that drops the claim block unmarks the identity, restores the sink
/// output and removes the release outputs: the winning branch never contained
/// the release, so no trace of it may remain. `verify` still passes — the
/// unwind is exact, not approximate.
#[test]
fn reorg_of_the_claim_block_unwinds_the_release() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let claim_id = claim.claim_id();
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    chain
        .mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None)
        .unwrap();
    assert!(chain.exit_released(&me, 1));
    let before_tip = chain.tip_hash();

    // Rival shares everything through H-1 and mines two empties: heavier, so
    // it wins. Fork point H-1 is above the finality floor (tip H, depth 20).
    assert!(h - 1 > h.saturating_sub(20));
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    for x in 1..h {
        rival.submit(chain.block_at(x).unwrap().clone()).unwrap();
    }
    for x in h..=h + 1 {
        let b = rival.mine_block(me, vec![], ts(x)).unwrap();
        rival.submit(b).unwrap();
    }
    assert!(rival.total_work() > chain.total_work());
    chain.submit(rival.block_at(h).unwrap().clone()).unwrap();
    chain
        .submit(rival.block_at(h + 1).unwrap().clone())
        .unwrap();
    assert_ne!(chain.tip_hash(), before_tip);

    // No trace of the release remains on the winning branch.
    assert!(!chain.exit_released(&me, 1));
    let (sink_op, sink_value) = sink_outpoint(&chain);
    assert_eq!(sink_value, SINK_VALUE);
    let _ = sink_op;
    assert!(
        chain
            .utxo()
            .get(&OutPoint {
                txid: claim_id,
                index: 0
            })
            .is_none(),
        "the destination output must be gone with its block"
    );
    chain.verify_canonical_chain().unwrap();
}

/// Two identical claims in one block spend the same sink output twice: the
/// miner's probe admits the first and the second finds its input gone — the
/// same double-spend refusal two L1 transactions spending one input get
/// (`UnknownOutPoint`), not a second release.
#[test]
fn duplicate_claims_in_one_block_are_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(
        &mut pool,
        me,
        ts(h),
        vec![],
        vec![claim.clone(), claim],
        None,
    );
    assert!(
        matches!(&res, Err(srct_core::error::Error::UnknownOutPoint)),
        "duplicate claims must be refused as a double-spend, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}

// ---------------------------------------------------------------------------
// Phase 3: guarded exit cancel/claim ordering
// ---------------------------------------------------------------------------
//
// The cancel/claim race: a guarded exit cancelled inside the delay window has
// no spendable L1 proof afterwards (no post-delay block commits the record),
// and cancelling at/after the window is refused outright. Both directions are
// decided by block order alone.

use srct_core::l2::{GuardedCancelPayload, GuardedOptInPayload};

const GUARDED_D: u64 = 10;

fn guarded_params() -> NetworkParams {
    let mut p = NetworkParams::mini();
    p.guarded_activation_height = 1;
    p.guarded_exit_delay_blocks = GUARDED_D;
    p
}

fn guarded_l2config() -> L2Config {
    let mut c = L2Config::mini();
    c.exit_activation_height = 1;
    c.guarded_activation_height = 1;
    c.guarded_exit_delay_blocks = GUARDED_D;
    c.guarded_grant_delay_blocks = 10;
    c.guarded_max_grant_lifetime_blocks = 100_000;
    c.guarded_outflow_cap_bps = 10_000;
    c.guarded_outflow_window_blocks = 1_000_000;
    c
}

fn guarded_view(chain: &Chain) -> ChainL2 {
    let params = guarded_params();
    ChainL2::replay(
        chain,
        guarded_l2config(),
        &L2Genesis::for_params(&params),
        DepositParams::for_params(&params),
        &MockBls,
    )
    .unwrap()
}

/// Apply L2 transactions in a fresh block carrying the correctly computed
/// post-state root, then resync the caller's L2 view to the new tip.
fn mine_l2_block(chain: &mut Chain, l2: &mut ChainL2, miner: Address, txs: Vec<L2Transaction>) -> u64 {
    let h = chain.height() + 1;
    let vals = ValidatorSet::new(vec![]);
    let mut sim = l2.state().clone();
    sim.advance_block(h);
    for tx in &txs {
        sim.apply(tx, h, &vals, &MockBls)
            .unwrap_or_else(|e| panic!("guarded test L2 tx must apply, got {e:?}"));
    }
    let root = sim.committed_root();
    let b = chain
        .mine_block_with_l2_root(miner, vec![], txs, root, ts(h), None, DEFAULT_MAX_ATTEMPTS)
        .unwrap();
    chain.submit(b).unwrap();
    *l2 = guarded_view(chain);
    h
}

/// A guarded world: owner holds a matured deposit and is opted into guarded
/// mode with `guardian` watching and `dest` allow-listed.
struct GuardedWorld {
    chain: Chain,
    l2: ChainL2,
    owner: Wallet,
    guardian: Wallet,
    dest: Address,
    params: NetworkParams,
}

fn guarded_world() -> GuardedWorld {
    let params = guarded_params();
    let owner = wallet(21);
    let guardian = wallet(22);
    let dest = addr(&wallet(23));
    let me = addr(&owner);
    let mut chain = Chain::new(params.clone()).unwrap();
    for h in 1..=12u64 {
        let b = chain.mine_block(me, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    let (op, value) = chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == me && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase");
    let fee = fee_for(&chain, 1, 2);
    let tx = owner
        .build_tx(
            &[op],
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
    let d = chain.height() + 1;
    let b = chain.mine_block(me, vec![tx], ts(d)).unwrap();
    chain.submit(b).unwrap();
    // Mature the deposit (mini finality depth 20).
    while chain.height() < d + 20 {
        let h = chain.height() + 1;
        let b = chain.mine_block(me, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    let mut l2 = guarded_view(&chain);
    // Opt in: owner guarded, guardian watching, dest allow-listed.
    // Cap is 100% here so the integration flow (cancel/claim ordering) is
    // what is under test; the cap itself is pinned by the vectors suite and
    // the allow-list unit test below.
    let opt = GuardedOptInPayload::build(&owner, addr(&guardian), vec![dest], 10, 100_000, 10_000, 1_000_000, 1)
        .unwrap();
    let h_opt = mine_l2_block(
        &mut chain,
        &mut l2,
        me,
        vec![L2Transaction::new(L2Payload::GuardedOptIn(opt))],
    );
    // Advance past the allow-list activation delay (D = 10): guarded exits
    // queued before the list is active are refused by name.
    while chain.height() < h_opt + GUARDED_D {
        let h = chain.height() + 1;
        let b = chain.mine_block(me, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    l2 = guarded_view(&chain);
    GuardedWorld {
        chain,
        l2,
        owner,
        guardian,
        dest,
        params,
    }
}

/// A guarded exit queued before its allow-list is active is refused outright.
#[test]
fn guarded_exit_before_allowlist_activation_is_refused() {
    let cfg = guarded_l2config();
    let mut s = L2State::new(cfg);
    let owner = wallet(41);
    let guardian = wallet(42);
    let dest = addr(&wallet(43));
    s.credit(addr(&owner), 10_000_000_000).unwrap();
    // Opt in at height 1 with a 10-block activation delay.
    let opt = GuardedOptInPayload::build(&owner, addr(&guardian), vec![dest], 10, 100_000, 1_000, 1_000_000, 1)
        .unwrap();
    let vals = ValidatorSet::new(vec![]);
    s.apply(&L2Transaction::new(L2Payload::GuardedOptIn(opt)), 1, &vals, &MockBls)
        .unwrap();
    // Immediate queue (height 2 < 1 + 10) is refused by name.
    let q = L2Transaction::new(L2Payload::ExitQueue(
        ExitQueuePayload::build(&owner, 1, 1_000_000, dest, EXIT_FEE).unwrap(),
    ));
    assert!(matches!(
        s.apply(&q, 2, &vals, &MockBls),
        Err(L2Error::GuardedDestinationNotAllowed)
    ));
    // After the delay the same queue applies.
    assert!(s.apply(&q, 12, &vals, &MockBls).is_ok());
}

fn guarded_queue(w: &mut GuardedWorld, nonce: u64, amount: u64) -> u64 {
    let tx = L2Transaction::new(L2Payload::ExitQueue(
        srct_core::l2::ExitQueuePayload::build(&w.owner, nonce, amount, w.dest, EXIT_FEE).unwrap(),
    ));
    let me = addr(&w.owner);
    mine_l2_block(&mut w.chain, &mut w.l2, me, vec![tx])
}

fn guarded_cancel(w: &mut GuardedWorld, nonce: u64) -> Result<(), String> {
    let mut target = [0u8; 32];
    target[..8].copy_from_slice(&nonce.to_le_bytes());
    let tx = L2Transaction::new(L2Payload::GuardedCancel(
        GuardedCancelPayload::build(&w.guardian, addr(&w.owner), 0, target, nonce).unwrap(),
    ));
    let me = addr(&w.owner);
    let h = w.chain.height() + 1;
    let vals = ValidatorSet::new(vec![]);
    let mut sim = w.l2.state().clone();
    sim.advance_block(h);
    match sim.apply(&tx, h, &vals, &MockBls) {
        Ok(_) => {
            let root = sim.committed_root();
            let b = w
                .chain
                .mine_block_with_l2_root(me, vec![], vec![tx], root, ts(h), None, DEFAULT_MAX_ATTEMPTS)
                .unwrap();
            w.chain.submit(b).map_err(|e| e.to_string())?;
            w.l2 = guarded_view(&w.chain);
            Ok(())
        }
        Err(e) => Err(format!("{e:?}")),
    }
}

/// A guarded exit cancelled inside the delay window cannot be claimed with a
/// post-delay proof: no block at or after the window commits the record, so
/// no valid guarded proof exists. Cancelling at or after the window is
/// refused by name instead.
#[test]
fn guarded_cancel_inside_window_blocks_later_claims() {
    let mut w = guarded_world();
    let me = addr(&w.owner);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let q = guarded_queue(&mut w, 1, amount);
    // Cancel inside the window: queued + D is still in the future.
    assert!(q + GUARDED_D > w.chain.height() + 1);
    guarded_cancel(&mut w, 1).expect("in-window cancel must apply");
    // The record is gone from L2: no proof can be built against any root.
    let l2h = guarded_view(&w.chain);
    assert!(
        l2h.state().exit_proof(&me, 1).is_none(),
        "a cancelled exit must have no spendable proof"
    );
    // A cancel at/after the delay window is refused outright.
    let q2 = guarded_queue(&mut w, 2, amount);
    while w.chain.height() < q2 + GUARDED_D {
        let h = w.chain.height() + 1;
        let b = w.chain.mine_block(me, vec![], ts(h)).unwrap();
        w.chain.submit(b).unwrap();
        w.l2 = guarded_view(&w.chain);
    }
    let late = guarded_cancel(&mut w, 2);
    assert!(
        matches!(late, Err(ref e) if e.contains("GuardedCancelWindowClosed")),
        "late cancel must be refused by name, got {late:?}"
    );
}

/// A guarded exit that was never cancelled IS claimable — with a proof
/// against a block at or after `queued + D`. A queue-block-only claim
/// (no `proof_height`) is refused for a guarded exit: the guarded leaf does
/// not match the legacy proof.
#[test]
fn guarded_exit_claimable_with_post_delay_proof() {
    let mut w = guarded_world();
    let me = addr(&w.owner);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let q = guarded_queue(&mut w, 1, amount);
    // Advance past BOTH the guard delay and L2 maturity (mini depth 20),
    // committing the L2 root in every block so post-delay proofs exist.
    while w.chain.height() < q + 25 {
        mine_l2_block(&mut w.chain, &mut w.l2, me, vec![]);
    }
    let sink_op = w
        .chain
        .utxo()
        .outputs_for_address(&w.params.l2_deposit_sink())
        .into_iter()
        .next()
        .expect("a sink output funds the claim")
        .0;
    // Legacy shape first: no proof height. The proof below is built against
    // the queue block's own committed root (the exact root check_claim will
    // verify against), so the ONLY reason it can fail is the leaf format:
    // the committed record is guarded, the legacy proof is not.
    let sim_q = ChainL2::replay_to(
        &w.chain,
        guarded_l2config(),
        &L2Genesis::for_params(&w.params),
        DepositParams::for_params(&w.params),
        &MockBls,
        q,
    )
    .expect("replay to the queue block works");
    let legacy_proof = sim_q
        .state()
        .exit_proof(&me, 1)
        .expect("a proof builds while the record is pending");
    let legacy = ExitClaim {
        owner: me,
        nonce: 1,
        amount_sat: amount,
        destination: w.dest,
        claimant: me,
        exit_fee_sat: EXIT_FEE,
        queued_height: q,
        inputs: vec![sink_op],
        proof: legacy_proof,
        proof_height: None,
    };
    let h = w.chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let refused = w.chain.mine_from_pool_with_exits(
        &mut pool,
        me,
        ts(h),
        vec![],
        vec![legacy],
        None,
    );
    assert!(
        matches!(refused, Err(ref e) if e.to_string().contains("exit proof does not verify")),
        "guarded exit without a guarded proof must be refused, got {refused:?}"
    );
    // Guarded shape: prove against a post-delay block that still commits it.
    let h_proof = w.chain.height();
    assert!(
        h_proof >= q + GUARDED_D,
        "the proof block must clear the delay window"
    );
    assert!(w.chain.block_at(h_proof).unwrap().l2_state_root.is_some());
    let tip2 = guarded_view(&w.chain);
    let proof = tip2
        .state()
        .exit_proof(&me, 1)
        .expect("the pending guarded exit must prove against a post-delay root");
    // The refused legacy claim spent nothing: the sink output is still there.
    let sink_op2 = w
        .chain
        .utxo()
        .outputs_for_address(&w.params.l2_deposit_sink())
        .into_iter()
        .next()
        .expect("the failed claim spent nothing")
        .0;
    let claim = ExitClaim {
        owner: me,
        nonce: 1,
        amount_sat: amount,
        destination: w.dest,
        claimant: me,
        exit_fee_sat: EXIT_FEE,
        queued_height: q,
        inputs: vec![sink_op2],
        proof,
        proof_height: Some(h_proof),
    };
    let h2 = w.chain.height() + 1;
    let mut pool2 = Mempool::new(1 << 20);
    let res = w.chain.mine_from_pool_with_exits(
        &mut pool2,
        me,
        ts(h2),
        vec![],
        vec![claim],
        None,
    );
    assert!(
        res.is_ok(),
        "guarded claim with a post-delay proof must be accepted, got {res:?}"
    );
    assert!(w.chain.exit_released(&me, 1));
}
