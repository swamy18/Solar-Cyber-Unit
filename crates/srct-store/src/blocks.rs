//! The block store: the append-only log, dressed as a blockchain.
//!
//! Every block this node ever hears about — canonical or side branch — is one
//! record in one log. "Which chain is canonical" is not a layout question; it is
//! one metadata row naming a tip hash and height, and the canonical chain is
//! found by walking parent hashes backward from that tip. A reorg moves that
//! metadata row and nothing else.
//!
//! **The store holds no consensus rules.** Whether a block is valid is
//! `srct-core`'s question; the store stores bytes and hands the node whatever it
//! asks for by hash. The worst failure a store bug can cause is a block not
//! found, never a block changed.

use std::collections::HashMap;
use std::path::Path;

use srct_core::block::Block;
use srct_core::hash::Hash512;
use srct_core::params::NetworkParams;

use crate::log::{RecordLog, RecordRef};
use crate::meta::{Meta, MetaFile};
use crate::{Recovery, StoreError};

/// The first byte of a record payload distinguishes record kinds.
///
/// `0x00` (or any absent tag, for the first format) is a block; `0x01` is a UTXO
/// snapshot. Blocks never start with a `0x01` byte in a position the decoder
/// accepts, so the tag is unambiguous — but it is checked anyway, so a payload
/// is never guessed at.
pub const TAG_BLOCK: u8 = 0x00;
pub const TAG_UTXO: u8 = 0x01;

/// Blocks of tip advancement between durable metadata flushes. The tip moves
/// in memory on every `set_tip`; the `meta.json` file (plus the log fsync
/// that must precede it) is rewritten at most this often, on finality
/// changes, on reorgs, and on shutdown — never less often than the node
/// needs to restart without replaying more than this many blocks past the
/// recorded tip. Crash recovery re-adopts the logged extension (see
/// `BlockStore::open`), so a deferred flush loses no decisions, only
/// re-derives them.
pub const META_FLUSH_INTERVAL: u64 = 10;

/// The directory holding `blocks.log` and `meta.json`.
#[derive(Debug)]
pub struct BlockStore {
    log: RecordLog,
    meta_file: MetaFile,
    meta: Meta,
    /// Block hash → record ref. Rebuilt from the log at open.
    by_hash: HashMap<Hash512, RecordRef>,
    /// Canonical height → block hash. Rebuilt from the tip at open; extended by
    /// `set_tip`.
    by_height: HashMap<u64, Hash512>,
    /// Blocks whose parent is not in the store, waiting for it. Bounded by the
    /// store itself: the log bytes stay (append-only), but list membership is
    /// capped — a peer feeding unconnectable side branches must not grow RAM
    /// without bound.
    orphans: Vec<Hash512>,
    /// Tip advances since the last durable metadata flush. Only the fast
    /// (linear-extension) path defers; reorgs, finality and shutdown flush
    /// synchronously, so this counter only ever covers a short linear tail
    /// that open-time recovery re-derives deterministically.
    tip_writes_since_flush: u64,
    /// Append-only record of every tip decision (`"<height> <hexhash>\\n"`
    /// per line). `meta.json` only catches up on flush; the journal lets a
    /// restart re-adopt exactly the recorded choice instead of guessing.
    /// Never fsync'd per write — durability comes from `flush_meta`, and a
    /// torn tail line is dropped on read.
    journal_path: std::path::PathBuf,
}

/// List-only cap for [`BlockStore::orphans`]. The block bytes stay in the log;
/// only the waiting-list entry is evicted, oldest first.
pub const MAX_ORPHANS: usize = 1024;

/// What appending a block did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// Stored as a new block whose parent is known.
    Stored,
    /// Already present, verified by hash. Stored once; both callers share it.
    Duplicate,
    /// Stored, but its parent is not in the store (yet).
    Orphaned,
}

/// Summary of what a store holds, for logging and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreInfo {
    pub blocks: u64,
    pub canonical_height: u64,
    pub log_bytes: u64,
    pub orphans: u64,
}

impl BlockStore {
    /// Open (creating if absent) and recover.
    ///
    /// The index is rebuilt by scanning the log, so there is no separate index
    /// file to go stale — the only copy of the data is the data. Recovery is
    /// reported, not hidden.
    pub fn open(
        dir: impl AsRef<Path>,
        params: &NetworkParams,
    ) -> Result<(Self, Recovery), StoreError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(|e| StoreError::io(dir, e))?;

        let log_path = dir.join("blocks.log");
        let (mut log, recovery) = RecordLog::open(&log_path)?;

        let meta_file = MetaFile::new(dir.join("meta.json"));
        // Whether the metadata file existed and parsed. A missing file means
        // a fresh store (or operator-deleted metadata): the tip journal is
        // ignored and the chain honestly starts at genesis rather than
        // adopting history no metadata vouches for. The journal only ever
        // fast-forwards a *loaded* tip.
        let (mut meta, loaded_meta) = match meta_file.load()? {
            Some(m) => {
                // A store opened against another network's data would feed this
                // node a foreign chain's blocks, so it is refused by name.
                if m.network != params.network_id {
                    return Err(StoreError::BadMeta {
                        detail: format!(
                            "store belongs to network \"{}\", this node is \"{}\"",
                            m.network, params.network_id
                        ),
                    });
                }
                (m, true)
            }
            None => {
                // Fresh store: genesis is implied, not stored. The canonical
                // chain at open is height 0, tip = genesis — computed from the
                // same params the node uses, never read back from a file that
                // could disagree with it.
                let genesis = srct_core::block::genesis_block(params.genesis_difficulty);
                let m = Meta::new(&params.network_id, genesis.block_hash());
                meta_file.save(&m)?;
                (m, false)
            }
        };

        // Rebuild the hash index by decoding every block record. A committed
        // block that no longer decodes is damage, not a crash: refuse, because
        // silently holding less than it did is the failure this store exists to
        // make impossible.
        let mut by_hash: HashMap<Hash512, RecordRef> = HashMap::with_capacity(log.len());
        for r in log.refs().to_vec() {
            let bytes = log.read(r)?;
            if payload_is_utxo(&bytes) {
                continue; // snapshot records are scanned, not indexed here
            }
            let payload = block_payload(&bytes);
            let block = Block::deserialize(payload).map_err(|e| StoreError::Corrupt {
                path: log_path.clone(),
                offset: r.offset,
                detail: format!("stored block does not decode: {e}"),
            })?;
            let h = block.block_hash();
            match by_hash.get(&h) {
                // Same hash must mean the same bytes; anything else is someone
                // using a hash to swap payloads, which is corruption of the
                // worst kind.
                Some(&existing) => {
                    if log.read(existing)? != bytes {
                        return Err(StoreError::Corrupt {
                            path: log_path.clone(),
                            offset: r.offset,
                            detail: "a block hash appears with two different payloads".into(),
                        });
                    }
                }
                None => {
                    by_hash.insert(h, r);
                }
            }
        }

        // The recorded tip must exist in the log, or the metadata is lying.
        if meta.height > 0 && !by_hash.contains_key(&meta.tip) {
            return Err(StoreError::MissingBlock { hash: meta.tip });
        }

        // Height index: walk from the tip to genesis via parent hashes. Only
        // this walk reaches `by_height`, so "canonical" means exactly "provable
        // from the recorded tip", not whatever the log happens to contain.
        let mut by_height = rebuild_height_index(&mut log, &log_path, &by_hash, &meta)?;
        // Genesis is height 0 of every chain: index it explicitly so the
        // fast-tip path's induction hypothesis (`by_height[tip] == tip`)
        // holds from a fresh store, instead of forcing one slow walk.
        // `rebuild_height_index` returns empty for a height-0 store because
        // there is nothing to walk; the entry below states the same fact the
        // walk would prove for the degenerate chain.
        by_height.entry(0).or_insert(meta.genesis);
        // Adopt an unflushed tip extension: `set_tip` batches durability (the
        // journal in `tip.journal` records every tip decision; `meta.json`
        // only catches up on flush), so after a crash the log can hold
        // canonical blocks above the recorded tip. Adoption replays the
        // journal newest-first and takes the first entry that provably
        // extends the recorded tip — a decision the node already made, never
        // a guess: a missing journal, a torn tail, garbage, or an entry that
        // does not chain contiguously from the recorded tip all fall back to
        // the recorded tip, which is always valid canonical history.
        // In-memory only; the next `flush_meta` persists it. Runs before the
        // orphan computation so adopted blocks count as canonical.
        // Skipped entirely for fresh stores: with no loaded metadata there is
        // nothing to fast-forward, and history starts honestly at genesis.
        // Adopted-but-unflushed heights count toward the batch budget, exactly
        // like fast-path advances made live: the bytes are durable in the log
        // but `meta.json` does not name them yet, so the first flush must not
        // wait a full interval.
        let mut adopted_unflushed = 0u64;
        if loaded_meta {
            // Newest journal entry first: a torn tip (power loss mid-append)
            // falls back to the newest complete decision, not all the way to
            // metadata. Entries at or below the recorded height, or entries
            // that do not chain contiguously down to it, are skipped.
            if let Some(entries) = read_journal(&dir.join("tip.journal")) {
                for (jh, jhash) in entries.iter().rev() {
                    let (jh, jhash) = (*jh, *jhash);
                    if jh <= meta.height {
                        continue;
                    }
                    // Walk down from the journaled tip. The recorded tip
                    // itself needs no lookup — it is already proven, and
                    // genesis is implied rather than stored, so the check
                    // comes first and the log is only read for the suffix.
                    let mut chain: Vec<(u64, Hash512)> = Vec::new();
                    let mut cur = jhash;
                    let mut h = jh;
                    let mut ok = false;
                    let mut guard = 0usize;
                    loop {
                        if cur == meta.tip && h == meta.height {
                            ok = true;
                            break;
                        }
                        guard += 1;
                        if guard > by_hash.len() + 1 {
                            break;
                        }
                        let &r = match by_hash.get(&cur) {
                            Some(r) => r,
                            None => break,
                        };
                        let bytes = match log.read(r) {
                            Ok(b) => b,
                            Err(_) => break,
                        };
                        let block = match Block::deserialize(block_payload(&bytes)) {
                            Ok(b) => b,
                            Err(_) => break,
                        };
                        if block.header.height != h {
                            break;
                        }
                        chain.push((h, cur));
                        if h == 0 {
                            break;
                        }
                        cur = block.header.prev_hash;
                        h -= 1;
                    }
                    if ok {
                        // Count the adoption toward the batch budget: these
                        // heights are durable in the log but not yet in
                        // `meta.json`, exactly like unflushed fast-path
                        // advances, so the next flush must account for them.
                        let adopted = chain.len() as u64;
                        for (height, hash) in chain {
                            by_height.insert(height, hash);
                        }
                        meta.tip = jhash;
                        meta.height = jh;
                        adopted_unflushed = adopted;
                        break;
                    }
                }
            }
        }
        // A side branch that forked at genesis has no parent in common with the
        // canonical walk; anything whose parent is unknown is an orphan.
        // The canonical set is built once: scanning it per candidate is
        // O(n^2) in the size of the log.
        let canonical: std::collections::HashSet<&Hash512> = by_height.values().collect();
        let mut orphans: Vec<Hash512> = by_hash
            .keys()
            .filter(|h| !canonical.contains(*h) && **h != meta.genesis)
            .copied()
            .collect();
        // The same bound `append_block` enforces live. Order here is hash
        // order, not append order — bounded is the property; the live path
        // keeps newest-first from here on.
        orphans.sort();
        if orphans.len() > MAX_ORPHANS {
            orphans.drain(..orphans.len() - MAX_ORPHANS);
        }

        let journal_path = dir.join("tip.journal");
        let store = BlockStore {
            log,
            meta_file,
            meta,
            by_hash,
            by_height,
            orphans,
            tip_writes_since_flush: adopted_unflushed,
            journal_path,
        };
        Ok((store, recovery))
    }

    /// What recovery found and did at open.
    pub fn recovery(&self) -> Recovery {
        self.log.recovery()
    }

    /// Store accounting, for logging.
    pub fn info(&self) -> StoreInfo {
        StoreInfo {
            blocks: self.by_hash.len() as u64,
            canonical_height: self.meta.height,
            log_bytes: self.log.file_len().unwrap_or(0),
            orphans: self.orphans.len() as u64,
        }
    }

    /// Current canonical tip hash and height.
    pub fn tip(&self) -> (Hash512, u64) {
        (self.meta.tip, self.meta.height)
    }

    /// The persisted binding-finalized point, or `None` when no checkpoint has
    /// ever finalized (Decision 12).
    pub fn finalized(&self) -> Option<(u64, Hash512)> {
        if self.meta.finalized_height == 0 {
            None
        } else {
            Some((self.meta.finalized_height, self.meta.finalized_hash))
        }
    }

    /// Persist the binding-finalized point (Decision 12), fail-closed.
    ///
    /// Refused unless the store itself proves the claim: the height must be at
    /// or below the stored tip and the stored canonical block at that height
    /// must hash to `hash`. A finalized height can never move backwards or to a
    /// different hash — that would "un-finalize" history the node already
    /// committed to, which is precisely the transition this exists to prevent.
    pub fn set_finalized(&mut self, height: u64, hash: Hash512) -> Result<(), StoreError> {
        if height == 0 || height > self.meta.height {
            return Err(StoreError::BadMeta {
                detail: "finalized height must be within the stored chain".into(),
            });
        }
        if self.hash_at_height(height) != Some(hash) {
            return Err(StoreError::BadMeta {
                detail: "finalized hash is not the stored canonical block".into(),
            });
        }
        if height < self.meta.finalized_height {
            return Err(StoreError::BadMeta {
                detail: "finalized height cannot move backwards".into(),
            });
        }
        if self.meta.finalized_height == height && self.meta.finalized_hash != hash {
            return Err(StoreError::BadMeta {
                detail: "conflicting finalized hash at an already-final height".into(),
            });
        }
        self.meta.finalized_height = height;
        self.meta.finalized_hash = hash;
        // Synchronous, like a reorg save: finality is always durable
        // immediately, and it carries the current tip with it. The full
        // flush (log sync first) is required, not just the metadata write:
        // finality frequently lands on a tip whose blocks have only been
        // appended since the last batched flush, and a meta file naming
        // not-yet-stable blocks turns a power loss into an unopenable store
        // (recorded tip missing from the log). Order is the guarantee.
        // (`flush_meta` also resets the batch counter.)
        self.flush_meta()
    }

    /// Look up a block by its hash.
    ///
    /// Reads are bounded by the record's own length, which was itself bounded at
    /// append time; no lookup can allocate beyond what this node once stored.
    pub fn block_by_hash(&mut self, h: &Hash512) -> Result<Option<Block>, StoreError> {
        let Some(&r) = self.by_hash.get(h) else {
            return Ok(None);
        };
        let bytes = self.log.read(r)?;
        Block::deserialize(block_payload(&bytes))
            .map(Some)
            .map_err(|e| StoreError::BadBlock {
                detail: format!("stored block {}: {e}", crate::hex(h)),
            })
    }

    /// Look up a block by canonical height.
    pub fn block_at_height(&mut self, height: u64) -> Result<Option<Block>, StoreError> {
        match self.hash_at_height(height) {
            Some(h) => self.block_by_hash(&h),
            None => Ok(None),
        }
    }

    /// The hash recorded for a canonical height, without decoding the block.
    pub fn hash_at_height(&self, height: u64) -> Option<Hash512> {
        self.by_height.get(&height).copied()
    }

    /// Append a block and classify it as new, duplicate, or orphaned.
    ///
    /// Appending decides *storage*; [`BlockStore::set_tip`] decides
    /// *canonicality*. A block that is stored but never set as (an ancestor of)
    /// the tip is simply a side branch or an orphan, and survives a restart.
    pub fn append_block(&mut self, block: &Block) -> Result<AppendOutcome, StoreError> {
        let h = block.block_hash();
        if self.by_hash.contains_key(&h) {
            return Ok(AppendOutcome::Duplicate);
        }

        let mut bytes = Vec::with_capacity(1 + block.serialize().len());
        bytes.push(TAG_BLOCK);
        bytes.extend_from_slice(&block.serialize());
        let r = self.log.append(&bytes)?;
        self.by_hash.insert(h, r);

        // Genesis is implied rather than stored, so a parent equal to it is as
        // known as a parent in the log.
        let parent_known = self.by_hash.contains_key(&block.header.prev_hash)
            || block.header.prev_hash == self.meta.genesis;
        if parent_known {
            Ok(AppendOutcome::Stored)
        } else {
            // Cap list membership, not storage: the bytes are already in the
            // log, and dropping the oldest waiter cannot lose a block the
            // node can still connect by hash.
            if self.orphans.len() >= MAX_ORPHANS {
                self.orphans.remove(0);
            }
            self.orphans.push(h);
            Ok(AppendOutcome::Orphaned)
        }
    }

    /// Mark a block as the canonical tip. A reorg is this call and nothing else.
    ///
    /// Two paths, one guarantee: the metadata file is only ever replaced
    /// atomically, and only after the new tip's ancestry is proven.
    ///
    /// Fast path: the new tip extends the recorded tip directly, possibly
    /// across several heights at once (batched appends). It walks back only
    /// until the recorded tip, checking prev-links *and* height continuity,
    /// so reaching it proves exactly the ancestry the full walk would prove
    /// for the new suffix — O(batch), not O(history). The metadata file is
    /// *not* rewritten here; it follows at the next [`BlockStore::flush_meta`]
    /// (or on reorg/finality/shutdown, which flush synchronously).
    ///
    /// Slow path: anything else (reorg, gap, unknown block) takes the full
    /// walk to genesis exactly as before, then saves synchronously: a fork
    /// decision is always durable immediately.
    pub fn set_tip(&mut self, new_tip: &Hash512) -> Result<(), StoreError> {
        if *new_tip == self.meta.genesis {
            // Resetting to genesis is a legal decision the node can make after
            // a total invalidation; it needs no walk.
            self.meta.tip = *new_tip;
            self.meta.height = 0;
            self.by_height.clear();
            self.append_journal(0, &self.meta.genesis)?;
            self.flush_meta()?;
            return Ok(());
        }
        if *new_tip == self.meta.tip {
            // Idempotent re-mark: the index already covers this tip and the
            // journal already names it (the first call recorded the
            // decision). No walk, no write — the batched flush will persist
            // it with the rest of the window.
            return Ok(());
        }

        // Fast-path induction hypothesis: the recorded tip is indexed. After
        // a genesis reset `by_height` is empty, so that path always takes
        // the slow walk below; after a full walk or a fast advance the
        // hypothesis holds by construction.
        if self.by_height.get(&self.meta.height) == Some(&self.meta.tip) {
            if let Some(suffix) = self.direct_extension(new_tip)? {
                // Suffix is tip-first with contiguous heights
                // meta.height+1 ..= new tip height (checked inside).
                for (height, h) in suffix.iter().rev() {
                    self.by_height.insert(*height, *h);
                }
                let advanced = suffix.len() as u64;
                let &(tip_height, tip_hash) = &suffix[0];
                self.meta.tip = tip_hash;
                self.meta.height = tip_height;
                // Journal first: the decision is recorded even though the
                // metadata file waits for the next flush (see `flush_meta`).
                // A crash before the flush replays this exact entry on open.
                self.append_journal(tip_height, &tip_hash)?;
                self.tip_writes_since_flush = self.tip_writes_since_flush.saturating_add(advanced);
                return Ok(());
            }
        }

        // Walk the candidate's ancestry to genesis, collecting the heights.
        // Cycle-guarded: two stored blocks can point at each other (a
        // corrupt or hostile log), and an unguarded walk would loop forever
        // instead of refusing the tip. A genuine chain visits every hash at
        // most once and cannot be longer than the store itself.
        let mut chain: Vec<(u64, Hash512)> = Vec::new();
        let mut seen: std::collections::HashSet<Hash512> = std::collections::HashSet::new();
        let mut cur = *new_tip;
        let mut at_tip = true;
        loop {
            if !seen.insert(cur) {
                return Err(StoreError::MissingParent { hash: cur });
            }
            if chain.len() > self.by_hash.len() {
                return Err(StoreError::MissingParent { hash: cur });
            }
            let &r = self.by_hash.get(&cur).ok_or({
                if at_tip {
                    StoreError::MissingBlock { hash: cur }
                } else {
                    StoreError::MissingParent { hash: cur }
                }
            })?;
            at_tip = false;
            let bytes = self.log.read(r)?;
            let block =
                Block::deserialize(block_payload(&bytes)).map_err(|e| StoreError::BadBlock {
                    detail: e.to_string(),
                })?;
            chain.push((block.header.height, cur));
            if block.header.prev_hash == self.meta.genesis {
                chain.push((0, self.meta.genesis));
                break;
            }
            if block.header.height == 0 {
                break;
            }
            cur = block.header.prev_hash;
        }
        // The walk must land on genesis exactly once, at height 0. `chain` runs
        // tip-first, so the tip's height is the first entry, not the last — the
        // first version of this read the genesis entry and recorded height 0
        // for a chain that was never genesis.
        let tip_height = match chain.first() {
            Some(&(height, _)) => height,
            None => return Err(StoreError::MissingParent { hash: *new_tip }),
        };
        if chain.last().map(|&(h, _)| h) != Some(0) {
            return Err(StoreError::MissingParent { hash: *new_tip });
        }

        // Commit: in-memory index first, then metadata. If the metadata write
        // fails, the in-memory state is stale but the file is not half-written
        // (rename is atomic); the error propagates so the caller decides.
        // Synchronous flush: fork decisions are durable immediately, journal
        // entry included, so reopening never has to guess which branch won.
        self.by_height.clear();
        for (height, h) in &chain {
            self.by_height.insert(*height, *h);
        }
        self.meta.tip = *new_tip;
        self.meta.height = tip_height;
        self.append_journal(tip_height, new_tip)?;
        self.flush_meta()?;
        Ok(())
    }

    /// Walk back from `new_tip` toward the recorded tip. Returns the suffix
    /// (tip-first) when every step prev-links to its parent with contiguous
    /// heights ending exactly at the recorded tip — i.e. a direct linear
    /// extension. Returns `Ok(None)` for anything else (gap, fork, unknown
    /// block, height jump, cycle); the caller then takes the slow path,
    /// which produces the legacy errors for those cases.
    ///
    /// Only fully decoded block headers are trusted for height/prev; the
    /// walk is bounded by the store size exactly like the full walk.
    fn direct_extension(
        &mut self,
        new_tip: &Hash512,
    ) -> Result<Option<Vec<(u64, Hash512)>>, StoreError> {
        let mut suffix: Vec<(u64, Hash512)> = Vec::new();
        let mut seen: std::collections::HashSet<Hash512> = std::collections::HashSet::new();
        let mut cur = *new_tip;
        loop {
            if cur == self.meta.tip {
                break;
            }
            if !seen.insert(cur) {
                return Ok(None);
            }
            if suffix.len() > self.by_hash.len() {
                return Ok(None);
            }
            let &r = match self.by_hash.get(&cur) {
                Some(r) => r,
                None => return Ok(None),
            };
            let bytes = self.log.read(r)?;
            let block =
                Block::deserialize(block_payload(&bytes)).map_err(|e| StoreError::BadBlock {
                    detail: format!("stored block {}: {e}", crate::hex(&cur)),
                })?;
            suffix.push((block.header.height, cur));
            if block.header.prev_hash == self.meta.genesis && self.meta.height != 0 {
                // Reached genesis without passing through the recorded tip:
                // a different history, not an extension of ours.
                return Ok(None);
            }
            cur = block.header.prev_hash;
        }
        if suffix.is_empty() {
            // `new_tip == meta.tip` is handled before this is called; an
            // empty suffix here would mean advancing zero blocks.
            return Ok(None);
        }
        // Contiguity: tip-first suffix must read tip_height, tip_height-1,
        // ..., exactly down to meta.height + 1.
        let tip_height = suffix[0].0;
        if tip_height != self.meta.height + suffix.len() as u64 {
            return Ok(None);
        }
        for (i, (height, _)) in suffix.iter().enumerate() {
            if *height + i as u64 != tip_height {
                return Ok(None);
            }
        }
        Ok(Some(suffix))
    }

    /// Make the recorded tip durable: fsync the log, then the journal, then
    /// atomically replace `meta.json`. The order is the guarantee — the
    /// metadata file can never name blocks whose bytes are not already on
    /// stable storage, and a crash can only lose the unflushed tail, which
    /// the torn-tail scan drops and the open-time journal replay re-derives.
    /// Flushes happen at most every [`META_FLUSH_INTERVAL`] tip advances
    /// (plus reorgs, finality and shutdown, which flush synchronously).
    pub fn flush_meta(&mut self) -> Result<(), StoreError> {
        self.log.sync()?;
        self.sync_journal()?;
        self.meta_file.save(&self.meta)?;
        // The flushed tip is durable in meta.json now, so the journal entries
        // that led to it are redundant: truncate to keep the file O(lag
        // window) instead of O(history). Any crash order stays consistent —
        // truncation only ever discards decisions meta.json already records.
        self.truncate_journal()?;
        self.tip_writes_since_flush = 0;
        Ok(())
    }

    /// Flush only when [`META_FLUSH_INTERVAL`] tip advances have accumulated
    /// since the last flush. Returns whether a flush happened. A failed
    /// flush propagates with the counter untouched, so the next call retries.
    pub fn flush_meta_if_due(&mut self) -> Result<bool, StoreError> {
        if self.tip_writes_since_flush < META_FLUSH_INTERVAL {
            return Ok(false);
        }
        self.flush_meta()?;
        Ok(true)
    }

    /// Tip advances since the last durable flush. The node uses it (with
    /// [`BlockStore::flush_meta_if_due`]) to bound how far the file can lag
    /// the in-memory tip; crash-recovery tests use it to assert batching
    /// actually batches.
    pub fn tip_writes_since_flush(&self) -> u64 {
        self.tip_writes_since_flush
    }

    /// Record a tip decision in `tip.journal`, one `"<height> <hexhash>\\n"`
    /// line per call. Unflushed and unfsync'd by design: the entry only has
    /// to survive a *process* crash (OS page cache), because a *power* loss
    /// that tears the journal tail also tears the unflushed log tail it
    /// describes — and then the torn-tail scan plus the older journal/meta
    /// consistently describe the older prefix. A torn final line is dropped
    /// on read; anything else malformed fails the whole journal (fail closed
    /// to the recorded metadata tip).
    fn append_journal(&self, height: u64, hash: &Hash512) -> Result<(), StoreError> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .map_err(|e| StoreError::io(&self.journal_path, e))?;
        writeln!(f, "{height} {}", crate::hex(hash))
            .map_err(|e| StoreError::io(&self.journal_path, e))?;
        Ok(())
    }

    /// Fsync the journal file. Runs inside [`BlockStore::flush_meta`], after
    /// the log sync and before the metadata save — the same ordering that
    /// makes power loss consistent.
    fn sync_journal(&self) -> Result<(), StoreError> {
        // Missing journal (old datadir, or no tip ever set) is fine: there is
        // nothing to make durable yet.
        if !self.journal_path.exists() {
            return Ok(());
        }
        // Write access is required: on Windows, flushing a read-only handle
        // fails with Access Denied instead of syncing.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&self.journal_path)
            .and_then(|f| f.sync_all())
            .map_err(|e| StoreError::io(&self.journal_path, e))
    }

    /// Truncate the journal after a successful flush: every decision in it
    /// is now recorded in `meta.json`, so the file restarts empty and stays
    /// bounded by the batch window instead of growing with history. Crash
    /// order is safe either way — losing the truncation only leaves
    /// already-recorded decisions to be skipped on open (`jh <= height`),
    /// and losing part of the truncation itself is impossible (a file size
    /// change is atomic; there is no partial new content to misread).
    fn truncate_journal(&self) -> Result<(), StoreError> {
        if !self.journal_path.exists() {
            return Ok(());
        }
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.journal_path)
            .and_then(|f| f.sync_all())
            .map_err(|e| StoreError::io(&self.journal_path, e))?;
        Ok(())
    }

    /// Blocks accepted whose parent was unknown at the time.
    pub fn orphans(&self) -> &[Hash512] {
        &self.orphans
    }

    /// Remove an orphan from the waiting list once its parent has landed.
    ///
    /// The block itself stays in the log: storage is append-only, and the node
    /// may still connect it later.
    pub fn resolve_orphan(&mut self, h: &Hash512) {
        self.orphans.retain(|x| x != h);
    }

    /// Append a UTXO snapshot record.
    ///
    /// Snapshots live in the same log as blocks, tagged, so there is one file,
    /// one recovery story, and no way for a snapshot and a block to disagree
    /// about which of them survived a crash.
    pub fn append_utxo_snapshot(&mut self, payload: &[u8]) -> Result<(), StoreError> {
        let mut rec = Vec::with_capacity(1 + payload.len());
        rec.push(TAG_UTXO);
        rec.extend_from_slice(payload);
        self.log.append(&rec)?;
        Ok(())
    }

    /// Read the most recent UTXO snapshot, if any. Deterministic replay input.
    pub fn latest_utxo_snapshot(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        let refs: Vec<RecordRef> = self.log.refs().to_vec();
        for r in refs.iter().rev() {
            let bytes = self.log.read(*r)?;
            if payload_is_utxo(&bytes) {
                // `payload_is_utxo` is true only for a non-empty record, but
                // slice by length rather than trust that: an empty record
                // must skip, never panic the open path.
                if bytes.len() < 2 {
                    continue;
                }
                return Ok(Some(bytes[1..].to_vec()));
            }
        }
        Ok(None)
    }

    /// Flush the log to the OS (not durable storage).
    pub fn flush(&mut self) -> Result<(), StoreError> {
        self.log.flush()
    }

    /// Make everything appended so far durable. The commit point for batches.
    pub fn sync(&mut self) -> Result<(), StoreError> {
        self.log.sync()
    }

    /// Total blocks held: canonical chain, side branches, everything.
    pub fn block_count(&self) -> u64 {
        self.by_hash.len() as u64
    }

    /// Every block hash in the store, in append order.
    pub fn all_hashes(&self) -> Vec<Hash512> {
        self.by_hash.keys().copied().collect()
    }
}

/// Strip the kind tag. **Every** record the store writes is tagged — assuming
/// an untagged block format was a real bug: a block's first serialized byte is
/// its version (currently 1), which is byte-identical to [`TAG_UTXO`], so an
/// untagged block was silently misread as a UTXO snapshot and vanished from
/// the index. The tag is one byte and ambiguity is not free.
fn block_payload(bytes: &[u8]) -> &[u8] {
    &bytes[1..]
}

fn payload_is_utxo(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TAG_UTXO)
}

/// Read the tip journal, newest entry last: `Some(entries)`, or `None` when
/// the file is missing (old datadir, or no tip ever set — legacy behavior,
/// no adoption), torn beyond a single tail line, or malformed anywhere else
/// (fail closed to the recorded metadata tip: a corrupt journal must never
/// promote a guess).
///
/// A power loss mid-append leaves a partial last line, which is dropped —
/// the previous line is still a complete, valid decision. Callers walk the
/// entries newest-first so a torn tip falls back to the newest complete
/// decision, not all the way to metadata.
fn read_journal(path: &Path) -> Option<Vec<(u64, Hash512)>> {
    let bytes = std::fs::read(path).ok()?;
    let mut text = String::from_utf8(bytes).ok()?;
    if !text.ends_with('\n') {
        let pos = text.rfind('\n')?;
        text.truncate(pos + 1);
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (h, hh) = match (parts.next(), parts.next()) {
            (Some(h), Some(hex)) if parts.next().is_none() => (h, hex),
            _ => return None,
        };
        let height: u64 = h.parse().ok()?;
        if hh.len() != 128 {
            return None;
        }
        let raw = hh.as_bytes();
        let mut hash = [0u8; 64];
        for (i, chunk) in raw.chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            hash[i] = u8::from_str_radix(s, 16).ok()?;
        }
        out.push((height, hash));
    }
    Some(out)
}

fn rebuild_height_index(
    log: &mut RecordLog,
    log_path: &Path,
    by_hash: &HashMap<Hash512, RecordRef>,
    meta: &Meta,
) -> Result<HashMap<u64, Hash512>, StoreError> {
    let mut by_height = HashMap::new();
    if meta.height == 0 {
        return Ok(by_height);
    }
    // Same cycle guard as `set_tip`: a corrupt log must fail the open,
    // never hang it.
    let mut seen: std::collections::HashSet<Hash512> = std::collections::HashSet::new();
    let mut walked = 0usize;
    let mut cur = meta.tip;
    loop {
        if !seen.insert(cur) {
            return Err(StoreError::MissingParent { hash: cur });
        }
        walked += 1;
        if walked > by_hash.len() + 1 {
            return Err(StoreError::MissingParent { hash: cur });
        }
        let &r = by_hash
            .get(&cur)
            .ok_or(StoreError::MissingBlock { hash: cur })?;
        let bytes = log.read(r)?;
        let block = Block::deserialize(block_payload(&bytes)).map_err(|e| StoreError::Corrupt {
            path: log_path.to_path_buf(),
            offset: r.offset,
            detail: format!("stored block does not decode while rebuilding the height index: {e}"),
        })?;
        let existing = by_height.insert(block.header.height, cur);
        if existing.is_some() {
            return Err(StoreError::Corrupt {
                path: log_path.to_path_buf(),
                offset: r.offset,
                detail: "two canonical blocks claim the same height".into(),
            });
        }
        if block.header.prev_hash == meta.genesis {
            by_height.insert(0, meta.genesis);
            break;
        }
        if block.header.height == 0 {
            break;
        }
        cur = block.header.prev_hash;
    }
    if by_height.get(&0) != Some(&meta.genesis) {
        return Err(StoreError::MissingParent { hash: meta.genesis });
    }
    Ok(by_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::hash::Hash512;
    use std::path::PathBuf;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("srct-store-blocks-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn mini_params() -> NetworkParams {
        NetworkParams::mini()
    }

    /// Timestamps at the mini target spacing, so difficulty stays pinned at 1
    /// and mining is instant. These tests attack storage, not proof-of-work.
    fn ts(height: u64) -> u64 {
        srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
    }

    fn miner() -> srct_core::hash::Address {
        [9; 20]
    }

    /// Build a small honest chain on top of genesis, mining each block so the
    /// hashes and signatures are the real thing the store will see in prod.
    fn mined_chain(n: u64) -> Vec<(Hash512, Vec<u8>)> {
        use srct_core::chain::Chain;
        let mut chain = Chain::new(mini_params()).unwrap();
        let mut blocks = Vec::new();
        for h in 1..=n {
            let b = chain.mine_block(miner(), vec![], ts(h)).unwrap();
            let hash = b.block_hash();
            blocks.push((hash, b.serialize()));
            chain.submit(b).unwrap();
        }
        blocks
    }

    /// Two rival blocks at the SAME height on the same parent. They are mined
    /// from an unsubmitted genesis with different timestamps, because mining,
    /// submitting and then mining again produces height 2, not a rival — the
    /// first version of this helper built a straight chain and called it a fork.
    fn rival_blocks() -> (Vec<u8>, Vec<u8>) {
        use srct_core::chain::Chain;
        let mut chain = Chain::new(mini_params()).unwrap();
        // Neither is submitted, so both are mined on genesis at height 1; the
        // differing timestamps make them different blocks.
        let b1 = chain.mine_block(miner(), vec![], ts(1)).unwrap();
        let b2 = chain.mine_block(miner(), vec![], ts(1) + 500).unwrap();
        (b1.serialize(), b2.serialize())
    }

    #[test]
    fn a_fresh_store_opens_at_genesis_and_stays_there_after_reopen() {
        let dir = tmp_dir("fresh");
        let params = mini_params();
        let genesis = srct_core::block::genesis_block(params.genesis_difficulty);
        let gh = genesis.block_hash();
        {
            let (store, rec) = BlockStore::open(&dir, &params).unwrap();
            assert_eq!(store.tip(), (gh, 0));
            assert_eq!(rec.discarded_tail_bytes, 0);
        }
        let (store, _) = BlockStore::open(&dir, &params).unwrap();
        assert_eq!(store.tip(), (gh, 0));
    }

    #[test]
    fn blocks_round_trip_by_hash_and_height_across_a_restart() {
        let dir = tmp_dir("roundtrip");
        let params = mini_params();
        let blocks = mined_chain(5);
        {
            let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
            for (h, bytes) in &blocks {
                let b = Block::deserialize(bytes).unwrap();
                let out = store.append_block(&b).unwrap();
                assert_eq!(out, AppendOutcome::Stored);
                store.set_tip(h).unwrap();
            }
            store.sync().unwrap();
        }
        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        assert_eq!(store.info().canonical_height, 5);
        for (i, (h, bytes)) in blocks.iter().enumerate() {
            let want = Block::deserialize(bytes).unwrap();
            let got = store.block_by_hash(h).unwrap().expect("block present");
            assert_eq!(got.serialize(), want.serialize(), "height {i} by hash");
            let got = store
                .block_at_height(i as u64 + 1)
                .unwrap()
                .expect("by height");
            assert_eq!(got.block_hash(), *h, "height index matches after reopen");
        }
    }

    #[test]
    fn a_duplicate_append_stores_once_and_reports_duplicate() {
        let dir = tmp_dir("dup");
        let params = mini_params();
        let blocks = mined_chain(2);
        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        let b = Block::deserialize(&blocks[0].1).unwrap();
        assert_eq!(store.append_block(&b).unwrap(), AppendOutcome::Stored);
        assert_eq!(store.append_block(&b).unwrap(), AppendOutcome::Duplicate);
        assert_eq!(store.block_count(), 1);
    }

    #[test]
    fn a_side_branch_is_stored_and_survives_a_restart_without_becoming_canonical() {
        let dir = tmp_dir("sidebranch");
        let params = mini_params();
        // Two competing blocks at the same height on the same parent: one
        // becomes the tip, the other is a side branch the node may revisit.
        let (raw1, raw2) = rival_blocks();
        let b1 = Block::deserialize(&raw1).unwrap();
        let b2 = Block::deserialize(&raw2).unwrap();
        let h1 = b1.block_hash();
        let h2 = b2.block_hash();

        {
            let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
            store.append_block(&b1).unwrap();
            store.append_block(&b2).unwrap();
            store.set_tip(&h1).unwrap();
            store.sync().unwrap();
        }
        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        assert_eq!(store.tip(), (h1, 1), "the recorded tip survives");
        assert_eq!(store.block_count(), 2, "both branches are held");
        assert!(
            store.block_by_hash(&h2).unwrap().is_some(),
            "the side branch is retrievable"
        );
        assert!(
            store.hash_at_height(1) == Some(h1),
            "canonical height 1 is b1"
        );
    }

    #[test]
    fn a_reorg_moves_the_tip_and_survives_a_restart() {
        let dir = tmp_dir("reorg");
        let params = mini_params();
        let (raw1, raw2) = rival_blocks();
        let b1 = Block::deserialize(&raw1).unwrap();
        let b2 = Block::deserialize(&raw2).unwrap();
        let h1 = b1.block_hash();
        let h2 = b2.block_hash();

        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        store.append_block(&b1).unwrap();
        store.append_block(&b2).unwrap();
        store.set_tip(&h1).unwrap();
        assert_eq!(store.tip(), (h1, 1));
        // Reorg to the competing block.
        store.set_tip(&h2).unwrap();
        assert_eq!(store.tip(), (h2, 1));
        assert_eq!(store.hash_at_height(1), Some(h2));
        store.sync().unwrap();

        let (store, _) = BlockStore::open(&dir, &params).unwrap();
        assert_eq!(store.tip(), (h2, 1), "the reorged tip is what reopen sees");
    }

    #[test]
    fn an_orphan_is_reported_and_survives_a_restart() {
        let dir = tmp_dir("orphan");
        let params = mini_params();
        let blocks = mined_chain(1);
        // Hand the store a block whose parent is not genesis and not in the
        // store: a block for a chain the node has not seen the start of.
        let mut fake = Block::deserialize(&blocks[0].1).unwrap();
        fake.header.height = 99;
        fake.header.prev_hash = [0xEE; 64];
        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        let out = store.append_block(&fake).unwrap();
        assert_eq!(out, AppendOutcome::Orphaned);
        assert_eq!(store.orphans().len(), 1);
        store.sync().unwrap();
        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        assert_eq!(store.orphans().len(), 1, "orphans are not forgotten");
        assert!(store.block_by_hash(&fake.block_hash()).unwrap().is_some());
        store.resolve_orphan(&fake.block_hash());
        assert!(store.orphans().is_empty());
    }

    #[test]
    fn setting_a_tip_the_store_cannot_prove_is_refused_and_changes_nothing() {
        let dir = tmp_dir("badtip");
        let params = mini_params();
        let blocks = mined_chain(2);
        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        let b1 = Block::deserialize(&blocks[0].1).unwrap();
        let h1 = b1.block_hash();
        store.append_block(&b1).unwrap();
        store.set_tip(&h1).unwrap();
        let before = store.tip();

        // A hash that is not in the store at all.
        let ghost = [0x5A; 64];
        assert!(matches!(
            store.set_tip(&ghost),
            Err(StoreError::MissingBlock { .. })
        ));
        assert_eq!(store.tip(), before, "a failed reorg changes nothing");

        // A block in the store whose ancestry does not reach genesis (the
        // height-99 orphan from the other test's trick).
        let mut fake = Block::deserialize(&blocks[1].1).unwrap();
        fake.header.height = 99;
        fake.header.prev_hash = [0xEE; 64];
        let fh = fake.block_hash();
        store.append_block(&fake).unwrap();
        assert!(matches!(
            store.set_tip(&fh),
            Err(StoreError::MissingParent { .. })
        ));
        assert_eq!(store.tip(), before, "an unprovable tip changes nothing");
    }

    #[test]
    fn a_store_from_another_network_is_refused() {
        let dir = tmp_dir("foreign-net");
        let params = mini_params();
        {
            let (_store, _) = BlockStore::open(&dir, &params).unwrap();
        }
        let mainnet = NetworkParams::mainnet();
        match BlockStore::open(&dir, &mainnet) {
            Err(StoreError::BadMeta { .. }) => {}
            other => panic!("expected BadMeta, got {other:?}"),
        }
    }

    #[test]
    fn metadata_lost_falls_back_to_genesis_not_to_a_guess() {
        let dir = tmp_dir("metalost");
        let params = mini_params();
        let blocks = mined_chain(3);
        {
            let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
            for (h, bytes) in &blocks {
                let b = Block::deserialize(bytes).unwrap();
                store.append_block(&b).unwrap();
                store.set_tip(h).unwrap();
            }
            store.sync().unwrap();
        }
        std::fs::remove_file(dir.join("meta.json")).unwrap();
        let (store, _) = BlockStore::open(&dir, &params).unwrap();
        // The blocks are still there; the canonical chain is honestly unknown,
        // so the store reports genesis rather than guessing a fork.
        assert_eq!(store.tip().1, 0);
        assert_eq!(store.block_count(), 3);
    }

    /// **Damage with committed data after it refuses to open.** The damaged
    /// record is deliberately not the last one: a damaged *last* record is a
    /// torn tail by definition and is dropped (that is recovery, and it is
    /// tested separately). Damage *inside* the chain, with good data after it,
    /// is corruption and the store must refuse.
    #[test]
    fn a_stored_block_that_no_longer_decodes_refuses_to_open() {
        let dir = tmp_dir("badblock");
        let params = mini_params();
        let blocks = mined_chain(2);
        {
            let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
            for (h, raw) in &blocks {
                let b = Block::deserialize(raw).unwrap();
                store.append_block(&b).unwrap();
                store.set_tip(h).unwrap();
            }
            store.sync().unwrap();
        }
        // Flip a payload byte inside the FIRST record. Layout: file header (8)
        // + record header (8) + kind tag (1), then the block's own bytes start
        // with its version, so aim past that into the header fields.
        let mut bytes = std::fs::read(dir.join("blocks.log")).unwrap();
        let victim = 8 + 8 + 1 + 40;
        bytes[victim] ^= 0xFF;
        std::fs::write(dir.join("blocks.log"), &bytes).unwrap();

        match BlockStore::open(&dir, &params) {
            Err(StoreError::Corrupt { .. }) => {}
            Err(e) => panic!("expected Corrupt, got {e:?}"),
            Ok(_) => panic!("a store with an undecodable block must refuse to open"),
        }
    }

    /// The tail rule and the metadata interact honestly: if recovery drops a
    /// tail, and the metadata's tip was inside that tail, the store refuses
    /// rather than silently reopening at a tip it cannot prove.
    ///
    /// The explicit flush is the test's premise, not boilerplate: only a
    /// flushed tip makes the metadata file name the block, and only a named
    /// block can be missed. Unflushed tips live in the journal and fall back
    /// to the recorded tip instead (see the `persist_crash` suite).
    #[test]
    fn a_dropped_tail_that_held_the_tip_refuses_to_open() {
        let dir = tmp_dir("tailtip");
        let params = mini_params();
        let blocks = mined_chain(1);
        {
            let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
            let b = Block::deserialize(&blocks[0].1).unwrap();
            store.append_block(&b).unwrap();
            store.set_tip(&blocks[0].0).unwrap();
            store.flush_meta().unwrap();
        }
        // Damage the only record — the tip is inside what recovery will drop.
        let mut bytes = std::fs::read(dir.join("blocks.log")).unwrap();
        let last = bytes.len() - 3;
        bytes[last] ^= 0xFF;
        std::fs::write(dir.join("blocks.log"), &bytes).unwrap();

        match BlockStore::open(&dir, &params) {
            Err(StoreError::MissingBlock { .. }) => {}
            other => panic!("expected MissingBlock, got {other:?}"),
        }
    }

    #[test]
    fn a_torn_tail_costs_only_the_tail() {
        let dir = tmp_dir("torn");
        let params = mini_params();
        let blocks = mined_chain(3);
        {
            let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
            for (h, bytes) in &blocks {
                let b = Block::deserialize(bytes).unwrap();
                store.append_block(&b).unwrap();
                store.set_tip(h).unwrap();
            }
            store.sync().unwrap();
        }
        // A crash mid-append: half of a fourth record reaches the file.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join("blocks.log"))
                .unwrap();
            f.write_all(&4096u32.to_le_bytes()).unwrap();
            f.write_all(&[0u8; 4]).unwrap();
            f.write_all(&[0u8; 10]).unwrap();
            f.sync_all().unwrap();
        }
        let (mut store, rec) = BlockStore::open(&dir, &params).unwrap();
        assert!(rec.truncated);
        assert!(rec.discarded_tail_bytes > 0);
        assert_eq!(store.block_count(), 3);
        assert_eq!(store.tip().1, 3);
        // And the store keeps working.
        let b = Block::deserialize(&blocks[2].1).unwrap();
        assert_eq!(store.append_block(&b).unwrap(), AppendOutcome::Duplicate);
    }

    #[test]
    fn utxo_snapshots_round_trip_and_are_distinguished_from_blocks() {
        let dir = tmp_dir("utxo");
        let params = mini_params();
        let blocks = mined_chain(1);
        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        let b = Block::deserialize(&blocks[0].1).unwrap();
        store.append_block(&b).unwrap();
        store.append_utxo_snapshot(b"snapshot-one").unwrap();
        store.append_utxo_snapshot(b"snapshot-two").unwrap();
        store.sync().unwrap();

        let (mut store, _) = BlockStore::open(&dir, &params).unwrap();
        assert_eq!(
            store.latest_utxo_snapshot().unwrap(),
            Some(b"snapshot-two".to_vec()),
            "the newest snapshot wins"
        );
        assert_eq!(
            store.block_count(),
            1,
            "snapshots are not counted as blocks"
        );
    }
}
