//! Phase B crash-safety: batched metadata durability (Decision 3).
//!
//! `set_tip` no longer rewrites `meta.json` on every call: linear extensions
//! only move the in-memory tip and count toward `META_FLUSH_INTERVAL`, while
//! reorgs, finality and shutdown flush synchronously. A crash between
//! flushes must therefore never lose committed history and never adopt a
//! fork the node did not choose. These tests simulate the crash by dropping
//! the store *without* flushing (no graceful shutdown path runs), then
//! reopening:
//!
//! - unflushed linear extensions are re-adopted from the log;
//! - torn tails fall back to the last complete block;
//! - a fork inside the lag window keeps the recorded tip (no guessing);
//! - reorgs and finality stay synchronous (meta file updated immediately);
//! - batching actually batches (meta file untouched until the interval).
//!
//! Run with `cargo test -p srct-store --test persist_crash`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::Chain;
use srct_core::hash::Hash512;
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_store::blocks::META_FLUSH_INTERVAL;
use srct_store::BlockStore;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_dir(name: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "srct-store-crash-{name}-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

fn miner() -> srct_core::hash::Address {
    Wallet::from_private_key_bytes(&[4u8; 32], "persist-crash")
        .unwrap()
        .address()
        .unwrap()
}

fn chain_to(to: u64) -> Chain {
    let me = miner();
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=to {
        let b = chain.mine_block(me, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    chain
}

/// Append `1..=to` from `chain` and move the tip — without flushing, exactly
/// like a node that crashes before its next batched flush.
fn stage_unflushed(dir: &Path, chain: &Chain, to: u64) {
    // Mirrors the production save path: append each block, then tip at it
    // (one journal entry per advance), but never flush — `bs` is dropped
    // here, simulating a crash before the next batched flush.
    let params = chain.params().clone();
    let (mut bs, _) = BlockStore::open(dir, &params).unwrap();
    for h in 1..=to {
        let block = chain.block_at(h).unwrap();
        bs.append_block(block).unwrap();
        bs.set_tip(&block.block_hash()).unwrap();
    }
}

fn meta_height(dir: &Path) -> u64 {
    // Read through the real loader: a torn meta.json must fail here, never
    // parse as a stale-but-valid height.
    let file = srct_store::meta::MetaFile::new(dir.join("meta.json"));
    file.load().unwrap().expect("meta.json must exist").height
}

#[test]
fn fast_path_matches_slow_path_state() {
    // Identical chains persisted two ways must reopen identically: per-block
    // set_tip (all fast paths) vs one set_tip at the end, both flushed.
    let dir_a = tmp_dir("fast-a");
    let dir_b = tmp_dir("fast-b");
    let chain = chain_to(20);
    let params = chain.params().clone();
    for (dir, per_block) in [(&dir_a, true), (&dir_b, false)] {
        let (mut bs, _) = BlockStore::open(dir.clone(), &params).unwrap();
        for h in 1..=20u64 {
            let b = chain.block_at(h).unwrap();
            bs.append_block(b).unwrap();
            if per_block {
                bs.set_tip(&b.block_hash()).unwrap();
            }
        }
        if !per_block {
            bs.set_tip(&chain.tip_hash()).unwrap();
        }
        bs.flush_meta().unwrap();
        assert_eq!(bs.tip(), (chain.tip_hash(), 20));
        for h in 1..=20u64 {
            assert_eq!(
                bs.hash_at_height(h),
                Some(chain.block_at(h).unwrap().block_hash())
            );
        }
    }
    // Same bytes on disk for both strategies (order-independent log layout
    // is append order here, so compare reopened views instead).
    for dir in [&dir_a, &dir_b] {
        let (bs, _) = BlockStore::open(dir.clone(), &params).unwrap();
        assert_eq!(bs.tip(), (chain.tip_hash(), 20));
    }
}

#[test]
fn unflushed_writes_batch_the_meta_file() {
    // Advancing below the flush interval must not touch meta.json; the
    // in-memory tip still moves (the node keeps serving from it).
    let dir = tmp_dir("batching");
    let chain = chain_to(5);
    let params = chain.params().clone();
    let unflushed = 5u64;
    assert!(unflushed < META_FLUSH_INTERVAL);
    let (mut bs, _) = BlockStore::open(dir.clone(), &params).unwrap();
    for h in 1..=5u64 {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
        bs.set_tip(&chain.block_at(h).unwrap().block_hash())
            .unwrap();
    }
    assert_eq!(bs.tip(), (chain.tip_hash(), 5));
    assert_eq!(meta_height(&dir), 0, "meta file must lag the in-memory tip");
    assert!(bs.tip_writes_since_flush() > 0);
    bs.flush_meta().unwrap();
    assert_eq!(meta_height(&dir), 5);
    assert_eq!(bs.tip_writes_since_flush(), 0);
}

#[test]
fn simulated_crash_adopts_the_unflushed_linear_tip() {
    // Crash with 7 unflushed blocks on top of genesis: reopen must adopt
    // all 7, since each has exactly one parent chaining to the recorded tip.
    let dir = tmp_dir("crash-adopt");
    let chain = chain_to(7);
    stage_unflushed(&dir, &chain, 7);
    assert_eq!(meta_height(&dir), 0, "nothing was flushed before the crash");
    let (mut bs, _) = BlockStore::open(dir.clone(), chain.params()).unwrap();
    assert_eq!(bs.tip(), (chain.tip_hash(), 7));
    for h in 1..=7u64 {
        let got = bs
            .block_at_height(h)
            .unwrap()
            .expect("adopted height readable");
        assert_eq!(got.block_hash(), chain.block_at(h).unwrap().block_hash());
    }
}

#[test]
fn torn_tail_in_the_lag_window_falls_back_to_the_last_complete_block() {
    // 5 blocks staged, then the file is truncated mid-record to simulate a
    // torn tail exactly where a crash mid-append would leave it.
    let dir = tmp_dir("torn-tail");
    let chain = chain_to(5);
    stage_unflushed(&dir, &chain, 5);
    let log_path = dir.join("blocks.log");
    let len = std::fs::metadata(&log_path).unwrap().len();
    // Cut into the last record's payload: any power loss inside a record
    // must read as a torn tail, never as a committed block.
    let mut buf = std::fs::read(&log_path).unwrap();
    buf.truncate((len - 24) as usize);
    std::fs::write(&log_path, &buf).unwrap();
    let (mut bs, recovery) = BlockStore::open(dir.clone(), chain.params()).unwrap();
    assert!(
        recovery.truncated,
        "the torn tail must be reported, not hidden"
    );
    let (tip, height) = bs.tip();
    assert_eq!(height, 4, "tip falls back to the last complete block");
    assert_eq!(tip, chain.block_at(4).unwrap().block_hash());
    assert!(bs.block_at_height(5).unwrap().is_none());
}

#[test]
fn fork_in_the_lag_window_adopts_the_journaled_choice() {
    // Two children of the same parent inside the unflushed window: adoption
    // replays the journaled decision (block 6 was explicitly tipped), it does
    // not guess — and the unchosen sibling stays in the log for the node.
    let dir = tmp_dir("fork-ambiguous");
    let chain = chain_to(6);
    let params = chain.params().clone();
    // A sibling of block 6 on the same parent (different timestamp).
    let me = miner();
    let mut forked = chain_to(5);
    let side = {
        let b = forked.mine_block(me, vec![], ts(6) + 7).unwrap();
        forked.submit(b.clone()).unwrap();
        b
    };
    assert_ne!(
        side.block_hash(),
        chain.block_at(6).unwrap().block_hash(),
        "sibling must differ"
    );
    // Flush at height 5 first: the recorded tip is durable, the fork is not.
    let (mut bs, _) = BlockStore::open(dir.clone(), &params).unwrap();
    for h in 1..=5u64 {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&chain.block_at(5).unwrap().block_hash())
        .unwrap();
    bs.flush_meta().unwrap();
    assert_eq!(meta_height(&dir), 5);
    // Now stage both children of block 5 and tip at the main one — no flush.
    bs.append_block(chain.block_at(6).unwrap()).unwrap();
    bs.append_block(&side).unwrap();
    bs.set_tip(&chain.block_at(6).unwrap().block_hash())
        .unwrap();
    drop(bs); // crash: no flush
    let (mut bs2, _) = BlockStore::open(dir.clone(), &params).unwrap();
    let (tip, height) = bs2.tip();
    assert_eq!(
        (tip, height),
        (chain.block_at(6).unwrap().block_hash(), 6),
        "recovery must adopt the journaled choice, not guess"
    );
    // The unchosen sibling survived in the log for the node to see.
    assert!(bs2.block_by_hash(&side.block_hash()).unwrap().is_some());
}

#[test]
fn missing_journal_falls_back_to_the_recorded_tip() {
    // No journal at all (old datadir, or the operator deleted it): recovery
    // behaves exactly like before batching — the recorded tip stands, and
    // unflushed-looking blocks stay side branches until the node re-tips
    // them explicitly.
    let dir = tmp_dir("no-journal");
    let chain = chain_to(6);
    let params = chain.params().clone();
    let (mut bs, _) = BlockStore::open(dir.clone(), &params).unwrap();
    for h in 1..=5u64 {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&chain.block_at(5).unwrap().block_hash())
        .unwrap();
    bs.flush_meta().unwrap();
    bs.append_block(chain.block_at(6).unwrap()).unwrap();
    bs.set_tip(&chain.block_at(6).unwrap().block_hash())
        .unwrap();
    drop(bs); // crash: no flush
    std::fs::remove_file(dir.join("tip.journal")).unwrap();
    let (bs2, _) = BlockStore::open(dir.clone(), &params).unwrap();
    assert_eq!(
        bs2.tip(),
        (chain.block_at(5).unwrap().block_hash(), 5),
        "without a journal the recorded tip stands"
    );
}

#[test]
fn reorg_still_saves_synchronously() {
    // A fork decision is always durable immediately: no flush call needed.
    let dir = tmp_dir("reorg-sync");
    let chain = chain_to(6);
    let params = chain.params().clone();
    let (mut bs, _) = BlockStore::open(dir.clone(), &params).unwrap();
    for h in 1..=6u64 {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&chain.tip_hash()).unwrap();
    bs.flush_meta().unwrap();
    assert_eq!(meta_height(&dir), 6);

    // Reorg onto a fork of height 5 (sibling of block 6's parent chain).
    let mut forked = chain_to(4);
    let me = miner();
    let mut fhash: Hash512 = [0u8; 64];
    for h in 5..=6u64 {
        let b = forked.mine_block(me, vec![], ts(h) + 13).unwrap();
        fhash = b.block_hash();
        forked.submit(b.clone()).unwrap();
        bs.append_block(&b).unwrap();
    }
    bs.set_tip(&fhash).unwrap();
    // No flush_meta call — the slow path must have saved synchronously.
    assert_eq!(meta_height(&dir), 6);
    let text = std::fs::read_to_string(dir.join("meta.json")).unwrap();
    let hexof: String = fhash.iter().map(|b| format!("{b:02x}")).collect();
    assert!(text.contains(&hexof));
}

#[test]
fn idempotent_retip_writes_nothing_and_counts_nothing() {
    let dir = tmp_dir("idempotent");
    let chain = chain_to(3);
    let params = chain.params().clone();
    let (mut bs, _) = BlockStore::open(dir.clone(), &params).unwrap();
    for h in 1..=3u64 {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
        bs.set_tip(&chain.block_at(h).unwrap().block_hash())
            .unwrap();
    }
    let before = bs.tip_writes_since_flush();
    assert!(before > 0);
    bs.set_tip(&chain.tip_hash()).unwrap();
    assert_eq!(
        bs.tip_writes_since_flush(),
        before,
        "re-marking the tip is a no-op"
    );
}

fn genesis_hash(chain: &Chain) -> srct_core::hash::Hash512 {
    chain.block_hash_at(0).unwrap()
}

#[test]
fn torn_journal_tail_falls_back_to_previous_entry() {
    // Crash mid-journal-append: the last line is partial. Recovery drops it
    // and adopts the newest *complete* entry instead of falling all the way
    // back to the recorded tip.
    let dir = tmp_dir("journal-torn");
    let chain = chain_to(5);
    stage_unflushed(&dir, &chain, 5);
    let jp = dir.join("tip.journal");
    let mut buf = std::fs::read(&jp).unwrap();
    buf.truncate(buf.len() - 7); // cut inside the last "height hex" line
    std::fs::write(&jp, &buf).unwrap();
    let (bs, _) = BlockStore::open(&dir, chain.params()).unwrap();
    assert_eq!(bs.tip(), (chain.block_at(4).unwrap().block_hash(), 4));
}

#[test]
fn garbage_journal_is_ignored_not_trusted() {
    // A journal that does not parse at all must not move the tip anywhere:
    // fall back to the recorded tip, which is always valid history.
    let dir = tmp_dir("journal-garbage");
    let chain = chain_to(5);
    stage_unflushed(&dir, &chain, 5);
    std::fs::write(dir.join("tip.journal"), b"not a journal at all").unwrap();
    let (bs, _) = BlockStore::open(&dir, chain.params()).unwrap();
    assert_eq!(bs.tip(), (genesis_hash(&chain), 0));
}

#[test]
fn missing_meta_json_starts_from_genesis_despite_journal() {
    // Deleted metadata = unknown history: the fresh path ignores even a
    // perfectly good journal and starts at genesis rather than adopting
    // blocks no metadata vouches for.
    let dir = tmp_dir("journal-no-meta");
    let chain = chain_to(5);
    stage_unflushed(&dir, &chain, 5);
    std::fs::remove_file(dir.join("meta.json")).unwrap();
    let (bs, _) = BlockStore::open(&dir, chain.params()).unwrap();
    assert_eq!(bs.tip(), (genesis_hash(&chain), 0));
}

#[test]
fn finalized_point_is_durable_without_any_further_flush() {
    // set_finalized must sync the log itself: finality frequently lands on a
    // tip whose blocks have only been appended since the last batched flush,
    // and a meta file naming not-yet-stable blocks would brick the store on
    // power loss (recorded tip missing from the log).
    let dir = tmp_dir("finality-durable");
    let chain = chain_to(10);
    let (mut bs, _) = BlockStore::open(&dir, chain.params()).unwrap();
    for h in 1..=7u64 {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
        bs.set_tip(&chain.block_at(h).unwrap().block_hash())
            .unwrap();
    }
    bs.set_finalized(3, chain.block_at(3).unwrap().block_hash())
        .unwrap();
    drop(bs); // crash: no explicit flush_meta / sync anywhere after appends
    let (bs, _) = BlockStore::open(&dir, chain.params()).unwrap();
    assert_eq!(bs.tip(), (chain.block_at(7).unwrap().block_hash(), 7));
    assert_eq!(
        bs.finalized(),
        Some((3, chain.block_at(3).unwrap().block_hash()))
    );
}

#[test]
fn journal_stays_bounded_by_flush_truncation() {
    // The journal must not grow with history: every flush rewrites it down,
    // so its size is bounded by the batch window no matter how tall the
    // chain gets.
    let dir = tmp_dir("journal-bounded");
    let chain = chain_to(30);
    let (mut bs, _) = BlockStore::open(&dir, chain.params()).unwrap();
    for h in 1..=30u64 {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
        bs.set_tip(&chain.block_at(h).unwrap().block_hash())
            .unwrap();
        bs.flush_meta_if_due().unwrap();
    }
    let len = std::fs::metadata(dir.join("tip.journal")).unwrap().len();
    assert!(len < 4096, "journal must stay tiny, got {len} bytes");
}
