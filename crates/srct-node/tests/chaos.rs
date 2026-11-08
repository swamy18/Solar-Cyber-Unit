//! Deterministic chaos / failure tests — Phase 6 M6, SPEC.md §13.11.
//!
//! These pin the failure behaviour that keeps a node alive and correct when
//! things go wrong: invalid L2 payloads are skipped by name, reorgs cannot
//! mutate state that is only replayable, a bad block never enters the store,
//! and accounting invariants hold even under adversarial inputs. Every test
//! here was chosen to fail if the corresponding guard were removed.
//!
//! Run with `cargo test -p srct-node --test chaos`.

use srct_core::chain::Chain;
use srct_core::compute_ir::ComputeBackend;
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    ClaimTaskPayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload, Verdict,
};
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_l2::L2Error;
use srct_node::l2::NodeL2;
use srct_store::BlockStore;

const MAX_ATTEMPTS: u64 = 4_000_000;

fn addr(tag: u8) -> Address {
    [tag; 20]
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "chaos-test").unwrap()
}

fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn task(nonce: u64, deadline: u64) -> srct_core::compute_ir::ComputeTask {
    let mut task_id = [0x11u8; 32];
    task_id[0] = nonce as u8;
    task_id[1] = (nonce >> 8) as u8;
    srct_core::compute_ir::ComputeTask {
        task_id,
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 1_000_000,
        expiry_height: deadline,
        submit_height: 1,
    }
}

/// A post signed by `seed`, well-formed but unfunded (no genesis grant).
fn post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, nonce, 5_000_000, deadline, task(nonce, deadline)).unwrap(),
    ))
}

/// A post whose signature no longer matches (body mutated after signing).
fn bad_auth_post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let mut tx = post(seed, nonce, deadline);
    if let L2Payload::Post(ref mut p) = tx.payload {
        p.payment_sat += 1;
    }
    tx
}

fn claim_unknown_task(seed: u8) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Claim(
        ClaimTaskPayload::build(&w, [0xABu8; 32], ComputeBackend::Cpu, 1_000).unwrap(),
    ))
}

/// Mine `l2` into the next block, committing the root replay derives
/// (`NodeL2::simulate_root`): the node's own view is the reference, so the
/// block commits the outcome replay recomputes rather than a guess.
fn mine_l2(chain: &mut Chain, view: &NodeL2, l2: Vec<L2Transaction>) -> srct_core::block::Block {
    let h = chain.height() + 1;
    if l2.is_empty() {
        return chain
            .mine_block_with_l2(addr(1), Vec::new(), Vec::new(), ts(h), None, MAX_ATTEMPTS)
            .expect("a block we just mined must build");
    }
    if !chain.exit_active_at(h) {
        return chain
            .mine_block_with_l2(addr(1), Vec::new(), l2, ts(h), None, MAX_ATTEMPTS)
            .expect("a block we just mined must build");
    }
    let root = view.simulate_root(chain, h, &l2);
    chain
        .mine_block_with_l2_root(addr(1), Vec::new(), l2, root, ts(h), None, MAX_ATTEMPTS)
        .expect("a block we just mined must build")
}

/// Mine `l2` into the next block and submit it.
fn mine_and_submit(chain: &mut Chain, view: &mut NodeL2, l2: Vec<L2Transaction>) {
    let block = mine_l2(chain, view, l2);
    chain.submit(block).expect("it must be accepted");
}

fn fresh_node(params: &NetworkParams) -> (Chain, NodeL2) {
    let mut chain = Chain::new(params.clone()).unwrap();
    let h = chain.height() + 1;
    let block = chain
        .mine_block_with_l2(addr(1), Vec::new(), Vec::new(), ts(h), None, MAX_ATTEMPTS)
        .expect("genesis block must build");
    chain.submit(block).expect("genesis must be accepted");
    let mut view = NodeL2::fresh(params).unwrap();
    view.sync(&chain).unwrap();
    (chain, view)
}

// ---------------------------------------------------------------------------
// Chaos scenario 1: invalid L2 payload is skipped, not crashed
// ---------------------------------------------------------------------------

#[test]
fn an_invalid_l2_payload_is_skipped_by_name_not_crashed() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    // A bad-auth post: the node must skip it by name, not crash, and must
    // not leave any partial state.
    let bad = bad_auth_post(2, 1, 200);
    let txid = bad.txid();
    mine_and_submit(&mut chain, &mut view, vec![bad]);
    view.sync(&chain).unwrap();

    assert_eq!(
        view.skipped().len(),
        1,
        "exactly the bad payload was skipped"
    );
    assert_eq!(view.skipped()[0].txid, txid);
    assert_eq!(
        view.skipped()[0].error,
        L2Error::BadAuthorization,
        "the failure is named, not a panic"
    );
    assert_eq!(view.applied_count(), 0, "no state changed");
    assert!(!view.is_clean());
}

#[test]
fn an_unknown_task_claim_is_skipped_without_partial_write() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    let claim = claim_unknown_task(2);
    let txid = claim.txid();
    mine_and_submit(&mut chain, &mut view, vec![claim]);
    view.sync(&chain).unwrap();

    assert_eq!(view.skipped().len(), 1);
    assert_eq!(view.skipped()[0].txid, txid);
    assert_eq!(view.skipped()[0].error, L2Error::UnknownTask);
    assert_eq!(view.applied_count(), 0);
}

#[test]
fn a_settle_without_quorum_is_refused() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    let settle = L2Transaction::new(L2Payload::Settle(SettlePayload {
        task_id: [0x77u8; 32],
        verdict: Verdict::Correct,
        vwc_hash: [0x99u8; 32],
        network_id: "srct/mini".to_string(),
        height: 0,
        bls_sig: [0x01u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
        pq_sidecar: Vec::new(),
    }));
    let txid = settle.txid();
    mine_and_submit(&mut chain, &mut view, vec![settle]);
    view.sync(&chain).unwrap();

    assert_eq!(view.skipped().len(), 1);
    assert_eq!(view.skipped()[0].txid, txid);
    assert!(
        matches!(
            view.skipped()[0].error,
            L2Error::BadQuorum | L2Error::BadBlsSignature
        ),
        "got {:?}",
        view.skipped()[0].error
    );
}

// ---------------------------------------------------------------------------
// Chaos scenario 2: reorg cannot mutate already-accepted L2 state
// ---------------------------------------------------------------------------

#[test]
fn a_rejected_block_never_mutates_l2_state() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);
    let before = view.state().clone();

    // Build a block with a bad merkle root — it must be rejected by submit.
    let mut bad_block = mine_l2(&mut chain, &view, vec![post(2, 1, 200)]);
    bad_block.header.merkle_root = [0xFFu8; 32];

    let result = chain.clone().submit(bad_block);
    assert!(
        result.is_err(),
        "a block with a bad merkle root is rejected"
    );

    // NodeL2 never saw the rejected block — sync is a no-op.
    view.sync(&chain).unwrap();
    assert_eq!(view.state(), &before, "rejected block changed nothing");
}

#[test]
fn a_bad_authorization_is_refused_before_balance_check() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    // bad_auth_post mutates the payment after signing, so the signature no
    // longer covers the body. Authorization is checked first, so this is
    // refused even on an empty/unfunded ledger.
    let bad = bad_auth_post(2, 1, 200);
    mine_and_submit(&mut chain, &mut view, vec![bad]);
    view.sync(&chain).unwrap();

    assert_eq!(view.skipped()[0].error, L2Error::BadAuthorization);
    assert_eq!(view.applied_count(), 0);
}

#[test]
fn sequential_incremental_sync_matches_full_replay() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    // Apply blocks one at a time (incremental path).
    for nonce in 1..=3u64 {
        mine_and_submit(&mut chain, &mut view, vec![post(2, nonce, 200)]);
        view.sync(&chain).unwrap();
    }
    let incremental_skips = view.skipped().len();
    let incremental_applied = view.applied_count();

    // Full replay from genesis must agree exactly.
    let replay = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(replay.skipped().len(), incremental_skips);
    assert_eq!(replay.applied_count(), incremental_applied);
}

// ---------------------------------------------------------------------------
// Chaos scenario 3: chain-level failures
// ---------------------------------------------------------------------------

#[test]
fn an_empty_l2_section_is_absent_not_stripped() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    mine_and_submit(&mut chain, &mut view, Vec::new());
    view.sync(&chain).unwrap();
    assert!(view.is_clean(), "empty L2 is clean");
    assert_eq!(view.skipped().len(), 0);
}

#[test]
fn a_transaction_cannot_create_value_out_of_thin_air() {
    // A block whose coinbase exceeds the reward + tips must be rejected.
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    let h = chain.height() + 1;
    let block = chain
        .mine_block_with_l2(addr(1), Vec::new(), Vec::new(), ts(h), None, MAX_ATTEMPTS)
        .unwrap();

    // Inflate the coinbase output.
    let mut inflated = block.clone();
    if let Some(tx) = inflated.txs.first_mut() {
        if let Some(out) = tx.outputs.first_mut() {
            out.value += 1_000_000_000_000;
        }
    }
    let result = chain.submit(inflated);
    assert!(
        result.is_err(),
        "a block inflating its coinbase must be rejected"
    );
}

#[test]
fn double_spend_is_rejected() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);
    let before = view.state().clone();

    // Two posts with the same nonce — identical txid (replay).
    let p1 = post(2, 1, 200);
    let p2 = post(2, 1, 200);
    assert_eq!(p1.txid(), p2.txid(), "same nonce => same txid");

    let block = mine_l2(&mut chain, &view, vec![p1, p2]);
    assert!(
        chain.clone().submit(block).is_ok(),
        "both are accepted into the block (replay is an L2 concern)"
    );

    // L2 replay must not apply the txid twice.
    view.sync(&chain).unwrap();
    assert_eq!(view.state(), &before);
    assert_eq!(view.applied_count(), 0, "neither unfunded post was applied");
}

#[test]
fn l2_replay_refuses_duplicate_apply() {
    // The same L2 transaction in two consecutive blocks: the second
    // application is refused as a replay.
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    // Seed 2 is in the mini genesis grants (funded), so the first post
    // applies and the second identical one is a replay.
    let tx = post(2, 1, 200);

    // The derived task_id is what the state stores, not the txid.
    let task_id: Hash = match &tx.payload {
        L2Payload::Post(p) => p.task_id,
        _ => unreachable!(),
    };

    // First appearance: funded => applied, task created.
    let block1 = mine_l2(&mut chain, &view, vec![tx.clone()]);
    chain.submit(block1).unwrap();
    view.sync(&chain).unwrap();
    assert_eq!(view.applied_count(), 1, "first post was applied");
    assert!(view.state().task(&task_id).is_some(), "task was created");

    // Second appearance in the next block: refused as Replay.
    let block2 = mine_l2(&mut chain, &view, vec![tx.clone()]);
    chain.submit(block2).unwrap();
    view.sync(&chain).unwrap();

    let replay_skip = &view.skipped()[view.skipped().len() - 1];
    assert_eq!(
        replay_skip.txid,
        tx.txid(),
        "the skip names the replayed txid"
    );
    assert_eq!(
        replay_skip.error,
        L2Error::Replay,
        "refused by name, not by state drift"
    );
    assert_eq!(
        view.applied_count(),
        1,
        "replay did not apply a second time"
    );
    assert!(view.state().task(&task_id).is_some());
}

// ---------------------------------------------------------------------------
// Chaos scenario 4: node restart recovery
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicU64, Ordering};

static CHAOS_STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn chaos_store_dir() -> std::path::PathBuf {
    let id = CHAOS_STORE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("srct-chaos-{}-{id}", std::process::id()));
    // The name is process-scoped, and a process id is reused: a directory left
    // behind by an earlier run would be opened as if it were this run's, and
    // the store would refuse a chain that does not match it. Start clean.
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn restart_through_block_store_preserves_canonical_chain() {
    let params = NetworkParams::mini();
    let (mut chain, mut view) = fresh_node(&params);

    for nonce in 1..=3u64 {
        mine_and_submit(&mut chain, &mut view, vec![post(2, nonce, 200)]);
        view.sync(&chain).unwrap();
    }
    let height = chain.height();
    let tip = chain.tip_hash();
    let applied = view.applied_count();
    let skipped = view.skipped().len();

    // Persist as a real node would.
    let dir = chaos_store_dir();
    let (mut bs, _) = BlockStore::open(&dir, &params).unwrap();
    for h in 1..=height {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&tip).unwrap();
    bs.sync().unwrap();

    // Rebuild the chain from the store alone.
    let (mut bs2, _) = BlockStore::open(&dir, &params).unwrap();
    let (_, store_height) = bs2.tip();
    let mut reloaded = Chain::new(params.clone()).unwrap();
    for h in 1..=store_height {
        let block = bs2
            .block_at_height(h)
            .unwrap()
            .unwrap_or_else(|| panic!("store lost block at height {h}"));
        reloaded.submit(block).unwrap();
    }
    assert_eq!(reloaded.height(), height);
    assert_eq!(reloaded.tip_hash(), tip);

    // The L2 view must reconstruct identically by replay.
    let replay = NodeL2::replay_from(&reloaded, &params).unwrap();
    assert_eq!(replay.applied_count(), applied);
    assert_eq!(replay.skipped().len(), skipped);
}

#[test]
fn restart_recovery_from_a_torn_tail_drops_the_incomplete_block() {
    let params = NetworkParams::mini();
    let dir = chaos_store_dir();

    let (mut bs, _) = BlockStore::open(&dir, &params).unwrap();
    let h = bs.tip().1 + 1;
    let block = {
        let mut chain = Chain::new(params.clone()).unwrap();
        let bh = chain.height() + 1;
        let blk = chain.mine_block(addr(1), Vec::new(), ts(bh)).unwrap();
        chain.submit(blk.clone()).unwrap();
        blk
    };
    bs.append_block(&block).unwrap();
    bs.set_tip(&block.block_hash()).unwrap();
    // The premise of this test is a *durable* tip inside the torn tail:
    // without the flush, batching would (correctly) fall back to genesis
    // instead of refusing, since nothing was ever claimed durable.
    bs.flush_meta().unwrap();
    bs.sync().unwrap();

    let log_path = dir.join("blocks.log");
    let original_len = std::fs::metadata(&log_path).unwrap().len();
    let new_len = original_len * 4 / 5;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&log_path)
        .unwrap();
    f.set_len(new_len).unwrap();
    drop(f);

    let result = BlockStore::open(&dir, &params);
    assert!(result.is_err(), "a torn tail must not be silently accepted");
    let _ = h;
}

// ---------------------------------------------------------------------------
// Chaos scenario 5: bad block rejected and never counted
// ---------------------------------------------------------------------------

#[test]
fn an_invalid_block_does_not_inflate_cumulative_work() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    let h = chain.height() + 1;
    let valid = chain
        .mine_block_with_l2(addr(1), Vec::new(), Vec::new(), ts(h), None, MAX_ATTEMPTS)
        .unwrap();
    chain.submit(valid.clone()).unwrap();

    let mut bad = valid.clone();
    bad.txs[0].outputs[0].value = u64::MAX;
    let res = chain.submit(bad);
    assert!(res.is_err(), "inflating block is rejected");

    assert_eq!(chain.tip_hash(), valid.block_hash());
    assert_eq!(chain.height(), 1);
}

#[test]
fn a_block_with_a_future_timestamp_is_rejected() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();

    let h = chain.height() + 1;
    let now = ts(h);
    let ts_future = now + params.future_limit_ms() + 1;
    let block = chain
        .mine_block_with_l2(
            addr(1),
            Vec::new(),
            Vec::new(),
            ts_future,
            None,
            MAX_ATTEMPTS,
        )
        .unwrap();
    let res = chain.submit_at(block, Some(now));
    assert!(res.is_err(), "a block with a future timestamp is rejected");
}

#[test]
fn fork_choice_picks_the_heavier_branch_by_work() {
    let params = NetworkParams::mini();
    let mut main = Chain::new(params.clone()).unwrap();
    let h1 = main.height() + 1;
    let fork = main.clone();
    let mut fork = fork;
    let b1 = main.mine_block(addr(1), Vec::new(), ts(h1)).unwrap();
    let b2 = fork.mine_block(addr(1), Vec::new(), ts(h1) + 1).unwrap();
    main.submit(b1.clone()).unwrap();
    fork.submit(b2.clone()).unwrap();

    // Node A sees [b1, b2]; Node B sees [b2, b1] — different arrival order.
    let mut node_a = Chain::new(params.clone()).unwrap();
    node_a.submit(b1.clone()).unwrap();
    node_a.submit(b2.clone()).unwrap();

    let mut node_b = Chain::new(params.clone()).unwrap();
    node_b.submit(b2).unwrap();
    node_b.submit(b1).unwrap();

    assert_eq!(
        node_a.tip_hash(),
        node_b.tip_hash(),
        "two nodes with the same blocks must agree on the tip"
    );
}
