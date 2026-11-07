//! Stratum-lite v1: minimal JSON-lines job server for pool operators.
//!
//! The node serves one miner via `GET /v1/mine/template`; a pool serves many.
//! This module is that pool side: it hands out jobs (unsolved templates),
//! validates submitted shares, and forwards full-difficulty blocks through a
//! caller-provided submit callback (normally `POST /v1/mine/submit`).
//!
//! Protocol: newline-delimited JSON over TCP.
//!
//! ```text
//! miner -> {"method":"getjob","miner":"<20-byte hex>"}
//! pool  -> {"job_id":7,"height":123,"difficulty":"1000","puzzle_id":1,"block_hex":"..."}
//! miner -> {"method":"submit","job_id":7,"miner":"<20-byte hex>","block_hex":"..."}
//! pool  -> {"accepted":true,"share":true,"block":false}
//! ```
//!
//! Anti-theft rule: the submitted block must match the job's `prev_hash`,
//! `height`, `difficulty`, `puzzle_id` and `merkle_root` exactly — only
//! `nonce`, `extra_nonce` and `timestamp` may differ. A miner that swaps the
//! coinbase (or any transaction) changes the merkle root and the share is
//! refused. Proof validity is re-checked by the pool with the same rule the
//! node uses; the node re-checks again at submit.
//!
//! Share difficulty: the pool accepts proofs meeting a weaker `share_difficulty`
//! as shares for accounting, and forwards only proofs that also meet the
//! job's network difficulty as blocks. Found blocks close a PPLNS round over
//! the trailing window (see [`crate::payout`]): pool hopping has no timing
//! edge because every share in the window is worth the same. Share and payout
//! accounting is in-memory; moving actual coin on chain stays the operator's
//! job (`mark_paid` records it).
//!
//! Known non-fixable: block withholding. A miner who finds a full-difficulty
//! proof and never submits it is indistinguishable from an unlucky one — no
//! pool protocol can tell them apart. The damage is bounded by construction:
//! a withheld block earns no share (nothing was submitted) and the round it
//! would have closed stays open, so the withholder dilutes their own window
//! weight along with everyone else's.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use srct_core::block::{Block, Header};
use srct_core::error::{Error, Result};
use srct_core::hash::Address;
use srct_core::hbm_pow::HbmConfig;
#[cfg(test)]
use srct_core::puzzle::PuzzleSolver;
use srct_core::puzzle::PuzzleSpec;

use crate::payout::{FinalizedRound, PaymentReceipt, RoundTracker, PPLNS_MAX_WINDOW};

/// A job handed to one miner: an unsolved template plus its id.
#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: u64,
    pub block: Block,
}

/// Per-miner accounting kept by the pool.
#[derive(Debug, Clone, Default)]
pub struct ShareStats {
    /// Shares accepted at share difficulty (includes blocks).
    pub shares: u64,
    /// Shares that also met network difficulty and were forwarded.
    pub blocks_found: u64,
}

/// Outcome of a validated submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitOutcome {
    pub share: bool,
    pub block: bool,
}

/// In-memory pool: job store plus share accounting.
///
/// `template_fn` supplies a fresh unsolved template on every `getjob`
/// (a pool fetches this from its node); `submit_fn` receives solved blocks
/// that meet network difficulty and returns whether the node accepted them.
pub struct Pool {
    inner: Mutex<PoolInner>,
    payouts: Mutex<RoundTracker>,
    template_fn: Box<dyn Fn() -> Result<Block> + Send + Sync>,
    // `Arc`, not `Box`: block submits run under a wall-clock deadline on a
    // helper thread, and the closure must move there.
    submit_fn: Arc<dyn Fn(Block) -> Result<bool> + Send + Sync>,
    share_difficulty: u128,
    spec: PuzzleSpec,
    hbm: Option<HbmConfig>,
    submit_timeout: std::time::Duration,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("share_difficulty", &self.share_difficulty)
            .field("spec_id", &self.spec.id)
            .field("has_hbm", &self.hbm.is_some())
            .finish_non_exhaustive()
    }
}

struct PoolInner {
    next_job_id: u64,
    jobs: HashMap<u64, Block>,
    stats: HashMap<Address, ShareStats>,
    max_miners: usize,
    /// Block hashes of accepted solutions, oldest-first. One proof, one
    /// share: without this, a miner hands the same solved header in under two
    /// job ids (the pool serves the same template twice) and gets paid twice
    /// for one grind, diluting every honest miner.
    seen: HashSet<srct_core::hash::Hash512>,
    seen_order: VecDeque<srct_core::hash::Hash512>,
}

/// How many accepted solutions the duplicate filter remembers. Past that,
/// the oldest is forgotten — a forgotten hash colliding with a fresh proof
/// would need the same 512-bit block hash twice, i.e. the same proof.
const SEEN_CAP: usize = 4096;

/// Hard ceiling on miners with accounting state. A valid share can add a new
/// miner address, so without this a flood of unique addresses grows `stats`,
/// `pending`, `lifetime_shares` and the share log's key space without bound.
/// Full pools refuse new miners instead of growing: fail closed, not OOM.
pub const MAX_MINERS: usize = 100_000;

/// Floor for the share bar on Internet-facing pools. Share difficulty 1
/// means every hash is a payable share — fine for a private test pool, but
/// an open pool must price shares so that accounting entries cost real work.
/// `Pool::new` keeps accepting 1 for tests and private pools;
/// [`Pool::new_with_config`] enforces the configured floor.
pub const MIN_OPERATIONAL_SHARE_DIFFICULTY: u128 = 1_000;

/// Connection-level DoS posture for [`serve`]. One thread per connection
/// means threads are the bound, not memory — but only when the count itself
/// is bounded. These caps shed floods at accept time instead of spawning
/// without limit; the per-connection guards (lifetime, request rate,
/// request count, read/write deadlines) bound what one admitted connection
/// can ever cost.
#[derive(Debug, Clone, Copy)]
pub struct ServeLimits {
    /// Total concurrent connections across all source addresses.
    pub max_connections: usize,
    /// Concurrent connections from one IP address.
    pub max_per_ip: usize,
    /// Requests (lines) served per connection before it is closed. Bounds
    /// how much work one connection can ever extract.
    pub max_lines_per_conn: u64,
    /// Read deadline per line: a peer that never finishes a line holds one
    /// handler thread only until this fires.
    pub read_timeout_secs: u64,
    /// Write deadline per reply: a peer that stops reading while still
    /// sending requests cannot pin a thread in `write_all` past this.
    pub write_timeout_secs: u64,
    /// Total lifetime of one connection. Long-lived miner sessions
    /// reconnect; an immortal connection is a leak, not a feature.
    pub max_connection_secs: u64,
    /// Token-bucket burst: how many requests a connection may fire at once.
    pub rate_burst: u32,
    /// Token-bucket refill: sustained requests per second per connection.
    /// With the per-IP connection cap, this also caps per-IP request rate.
    pub rate_per_sec: f64,
}

impl Default for ServeLimits {
    fn default() -> Self {
        ServeLimits {
            max_connections: 512,
            max_per_ip: 32,
            max_lines_per_conn: 50_000,
            read_timeout_secs: 60,
            write_timeout_secs: 30,
            max_connection_secs: 900,
            rate_burst: 32,
            rate_per_sec: 20.0,
        }
    }
}

/// Token-bucket request throttle: `burst` immediate requests, then
/// `per_sec` sustained. Refusals are cheap local arithmetic — no clocks
/// beyond `Instant`, no shared state — so the throttle itself cannot be
/// turned into an allocation or contention attack.
#[derive(Debug, Clone)]
struct RateLimiter {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    fn new(burst: u32, per_sec: f64) -> Self {
        let capacity = burst.max(1) as f64;
        RateLimiter {
            capacity,
            tokens: capacity,
            refill_per_sec: per_sec.max(0.0),
            last: std::time::Instant::now(),
        }
    }

    /// Spend one token if any is available.
    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Pool construction knobs. `Pool::new` uses the permissive defaults
/// (any non-zero share difficulty, [`MAX_MINERS`] accounting cap);
/// Internet-facing operators use `new_with_config` with a real share
/// floor so that each accounting entry costs proven work.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Largest number of miners with accounting state.
    pub max_miners: usize,
    /// Minimum accepted `share_difficulty`.
    pub min_share_difficulty: u128,
    /// Wall-clock deadline for the node-submit callback per found block.
    /// A node that never answers must time out the share, not pin the
    /// handler thread (and the miner's payout) forever.
    pub submit_timeout_secs: u64,
    /// Blocks a round waits before its earnings become payable (100
    /// mainnet, 10 mini/testnet): the coinbase is unspendable until then,
    /// so payable-before-maturity would pay orphanable money.
    pub coinbase_maturity: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            max_miners: MAX_MINERS,
            min_share_difficulty: 1,
            submit_timeout_secs: 120,
            coinbase_maturity: 100,
        }
    }
}

/// Run `f` with a wall-clock deadline on a helper thread. The orphaned
/// thread on timeout completes into a dropped channel and exits; orphans
/// only exist while the callback itself hangs, so they are bounded by the
/// block rate, not by attacker input.
fn call_with_timeout<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
    timeout: std::time::Duration,
) -> std::result::Result<T, ()> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(timeout).map_err(|_| ())
}

impl Pool {
    /// `share_difficulty` must be non-zero and no harder than any template
    /// the pool will serve (a share can never beat a harder bar it was not
    /// ground against — here the bar only filters, so an unreachable bar
    /// would refuse every share). `fee_bps` is the pool fee in basis points.
    ///
    /// Accounting state (per-miner stats, payout balances, round history)
    /// is bounded: the miner table refuses newcomers past [`MAX_MINERS`],
    /// the job store evicts past 1024 entries, the duplicate filter holds
    /// 4096 digests, and finalized rounds/receipts are pruned by the
    /// payout ledger. The payout ledger itself persists via
    /// [`Pool::save_state`]/[`Pool::load_state`]: restart without loading
    /// starts with empty balances, which would silently drop debt.
    pub fn new(
        spec: PuzzleSpec,
        hbm: Option<HbmConfig>,
        share_difficulty: u128,
        fee_bps: u32,
        template_fn: impl Fn() -> Result<Block> + Send + Sync + 'static,
        submit_fn: impl Fn(Block) -> Result<bool> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::new_with_config(
            spec,
            hbm,
            share_difficulty,
            fee_bps,
            PoolConfig::default(),
            template_fn,
            submit_fn,
        )
    }

    /// Like [`Pool::new`] with explicit limits. `config.min_share_difficulty`
    /// refuses unreachable-cheap pools for open operation: a share bar below
    /// the floor is a configuration error, not a share.
    pub fn new_with_config(
        spec: PuzzleSpec,
        hbm: Option<HbmConfig>,
        share_difficulty: u128,
        fee_bps: u32,
        config: PoolConfig,
        template_fn: impl Fn() -> Result<Block> + Send + Sync + 'static,
        submit_fn: impl Fn(Block) -> Result<bool> + Send + Sync + 'static,
    ) -> Result<Self> {
        if share_difficulty == 0 {
            return Err(Error::InvalidDifficulty(0));
        }
        if share_difficulty < config.min_share_difficulty {
            return Err(Error::BadPuzzleSpec(format!(
                "share difficulty {share_difficulty} below the pool minimum {}",
                config.min_share_difficulty
            )));
        }
        if config.max_miners == 0 {
            return Err(Error::Malformed("pool miner cap must be non-zero"));
        }
        spec.validate()?;
        if let Some(cfg) = &hbm {
            cfg.validate()?;
        }
        Ok(Pool {
            inner: Mutex::new(PoolInner {
                next_job_id: 1,
                jobs: HashMap::new(),
                stats: HashMap::new(),
                seen: HashSet::new(),
                seen_order: VecDeque::new(),
                max_miners: config.max_miners,
            }),
            payouts: Mutex::new(RoundTracker::with_maturity(
                fee_bps,
                config.coinbase_maturity,
            )?),
            template_fn: Box::new(template_fn),
            submit_fn: Arc::new(submit_fn),
            share_difficulty,
            spec,
            hbm,
            submit_timeout: std::time::Duration::from_secs(config.submit_timeout_secs.max(1)),
        })
    }

    /// Hand out a job. The template is stored under its id so `submit_job`
    /// can pin the submission to it.
    pub fn get_job(&self) -> Result<Job> {
        let block = (self.template_fn)()?;
        // The pool serves hybrid (puzzle 1) when its spec is hybrid, and HBM
        // (puzzle 2) only when an HBM config is present. A puzzle-2 template
        // with no config must be refused here, not handed out to fail at
        // share validation.
        let serves_hybrid = self.spec.id == 1 && block.header.puzzle_id == 1;
        let serves_hbm = self.hbm.is_some() && block.header.puzzle_id == 2;
        if !(serves_hybrid || serves_hbm) {
            return Err(Error::BadPuzzleSpec(format!(
                "template names puzzle {} but the pool serves {}",
                block.header.puzzle_id, self.spec.id
            )));
        }
        // A share bar above the network difficulty collapses the PPLNS
        // window to 1 (winner-takes-all on a lucky share) and refuses every
        // honest share below it: fail the job here, not at submission.
        if self.share_difficulty > block.header.difficulty {
            return Err(Error::BadPuzzleSpec(format!(
                "share difficulty {} above template difficulty {}",
                self.share_difficulty, block.header.difficulty
            )));
        }
        // Fail fast on an unusable template difficulty: 0 can never be met
        // and an overflow difficulty burns miner CPU on an unsatisfiable bar.
        // `proof_meets` maps overflow to Ok(false); refuse here with a name.
        if block.header.difficulty == 0 {
            return Err(Error::BadPuzzleSpec(
                "template difficulty is zero".to_string(),
            ));
        }
        if srct_core::u256::target_for_difficulty(block.header.difficulty).is_err() {
            return Err(Error::BadPuzzleSpec(format!(
                "template difficulty {} overflows the target",
                block.header.difficulty
            )));
        }
        // The template names the current height: unlock whatever matured.
        // Without this a round's earnings would sit in `immature` forever.
        if let Ok(mut payouts) = self.payouts.lock() {
            payouts.mature(block.header.height);
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::Malformed("pool lock"))?;
        let job_id = inner.next_job_id;
        inner.next_job_id = inner.next_job_id.wrapping_add(1).max(1);
        inner.jobs.insert(job_id, block.clone());
        // Jobs are single-use: a submission consumes its job, so a replayed
        // share cannot be counted twice and a stale template cannot linger.
        // (The store only grows by jobs never submitted; pools rotate
        // templates every block, so this is bounded by submission rate.)
        if inner.jobs.len() > 1024 {
            let oldest = *inner.jobs.keys().min().unwrap();
            inner.jobs.remove(&oldest);
        }
        Ok(Job { job_id, block })
    }

    /// Validate a submission against `job_id`'s template and account it.
    pub fn submit_job(&self, job_id: u64, miner: Address, block: Block) -> Result<SubmitOutcome> {
        let template = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            inner
                .jobs
                .remove(&job_id)
                .ok_or(Error::Malformed("unknown job"))?
        };
        // Anti-theft: everything but the proof fields and timestamp must be
        // byte-identical to the issued template. `base_fee_sat`, `version`
        // and `sig_scheme` are pinned too: all three feed the hashed
        // preimage, so a mutated one is a different puzzle instance that
        // could still pass the share bar and earn PPLNS weight for an
        // invalid-fee header the node would refuse.
        let a = &template.header;
        let b = &block.header;
        if a.prev_hash != b.prev_hash
            || a.merkle_root != b.merkle_root
            || a.height != b.height
            || a.difficulty != b.difficulty
            || a.puzzle_id != b.puzzle_id
            || a.epoch_id != b.epoch_id
            || a.base_fee_sat != b.base_fee_sat
            || a.version != b.version
            || a.sig_scheme != b.sig_scheme
        {
            return Err(Error::Malformed("share does not match its job"));
        }
        if block.txs != template.txs {
            return Err(Error::Malformed("share transactions differ from its job"));
        }
        // The body is consensus: l2 payload, exit claims and the block
        // signature all feed the merkle root / chain validation. A share
        // with a valid PoW but a mutated body would earn PPLNS weight for
        // a block the node must refuse, diluting honest miners.
        if block.l2_txs != template.l2_txs
            || block.l2_state_root != template.l2_state_root
            || block.exit_claims != template.exit_claims
            || block.signature != template.signature
            || block.signer_pubkey != template.signer_pubkey
        {
            return Err(Error::Malformed("share body differs from its job"));
        }
        // Timestamp is a proof field (miners grind it), but an unbounded one
        // is a dilution primitive: a far-future/ancient share passes the
        // share bar yet the node would refuse it by median/future rules.
        // Bound drift from the issued template to one day either way.
        {
            let t = template.header.timestamp_ms;
            let bts = block.header.timestamp_ms;
            const DAY_MS: u64 = 86_400_000;
            if bts.saturating_sub(t) > DAY_MS || t.saturating_sub(bts) > DAY_MS {
                return Err(Error::Malformed("share timestamp drifts too far"));
            }
        }
        // Miner-table bound before any accounting or forwarding: a fresh
        // address per share would otherwise grow `stats`, the payout
        // tracker's lifetime map and pending balances without bound. New
        // miners past the cap are refused up front, so a full pool neither
        // records debt it cannot track nor forwards work it will not pay.
        {
            // One lock at a time, always: `inner` then `payouts` nested here
            // would deadlock against any future `payouts` -> `inner` path.
            // (Same rule as the `encode_state` copy-under-each-lock pattern.)
            let (known_in_stats, table_full) = {
                let inner = self
                    .inner
                    .lock()
                    .map_err(|_| Error::Malformed("pool lock"))?;
                (
                    inner.stats.contains_key(&miner),
                    inner.stats.len() >= inner.max_miners,
                )
            };
            if !known_in_stats {
                let tracked = self
                    .payouts
                    .lock()
                    .map_err(|_| Error::Malformed("pool lock"))?
                    .is_tracked(&miner);
                if !tracked && table_full {
                    return Err(Error::Malformed("miner table full"));
                }
            }
        }
        // The solution identity, computed before the block moves into the
        // submit callback below: one proof, one share (see the duplicate
        // check ahead of accounting).
        let digest = block.block_hash();

        // Share bar first: the proof must meet `share_difficulty`.
        if !self.proof_meets(&block.header, self.share_difficulty)? {
            return Err(Error::Malformed("share below pool difficulty"));
        }
        let is_block = self.proof_meets(&block.header, b.difficulty)?;
        // One proof, one share: the same solved header handed in under two
        // job ids (or replayed twice) counts once. Checked before the node
        // submit, so a duplicate neither pays nor forwards a second copy of
        // the block to the node.
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            if !inner.seen.insert(digest) {
                return Err(Error::Malformed("duplicate solution"));
            }
            inner.seen_order.push_back(digest);
            if inner.seen_order.len() > SEEN_CAP {
                if let Some(oldest) = inner.seen_order.pop_front() {
                    inner.seen.remove(&oldest);
                }
            }
        }
        let coinbase_sat = template
            .txs
            .first()
            .and_then(|tx| tx.outputs.first())
            .map(|o| o.value)
            .unwrap_or(0);
        // The template's coinbase is real-money accounting: refuse absurd
        // values before they enter the payout ledger. Zero pays nobody and
        // a value above 1000 BTC is never a real mainnet/mini reward.
        if coinbase_sat == 0 || coinbase_sat > 100_000_000_000 {
            return Err(Error::Malformed("template coinbase out of range"));
        }
        let block_height = b.height;
        // Copied before `block` moves into the submit callback below.
        let template_difficulty = b.difficulty;
        if is_block {
            // Total request deadline: the node callback runs on a helper
            // thread with a wall-clock timeout, so a hung node times out
            // the share instead of pinning this handler thread forever.
            let submit = self.submit_fn.clone();
            let timeout = self.submit_timeout;
            let submitted = call_with_timeout(move || submit(block), timeout);
            let accepted = match submitted {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    // The block never reached the node: forget the proof so a
                    // retry of the same solution is not misreported as a
                    // duplicate.
                    let mut inner = self
                        .inner
                        .lock()
                        .map_err(|_| Error::Malformed("pool lock"))?;
                    inner.seen.remove(&digest);
                    inner.seen_order.retain(|d| *d != digest);
                    return Err(e);
                }
                Err(()) => {
                    let mut inner = self
                        .inner
                        .lock()
                        .map_err(|_| Error::Malformed("pool lock"))?;
                    inner.seen.remove(&digest);
                    inner.seen_order.retain(|d| *d != digest);
                    return Err(Error::Malformed("node submit timed out"));
                }
            };
            if !accepted {
                let mut inner = self
                    .inner
                    .lock()
                    .map_err(|_| Error::Malformed("pool lock"))?;
                inner.seen.remove(&digest);
                inner.seen_order.retain(|d| *d != digest);
                return Err(Error::Malformed("node refused the block"));
            }
        }
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            let stats = inner.stats.entry(miner).or_default();
            stats.shares += 1;
            if is_block {
                stats.blocks_found += 1;
            }
        }
        // Payout accounting mirrors the share stats exactly: every accepted
        // share (blocks included) earns window weight, and a found block
        // closes the round on its coinbase value over the trailing PPLNS
        // window (twice the expected shares per block, so every share is
        // worth the same no matter when it landed — pool hopping has no
        // timing edge). This runs after the node accepted, so a refused
        // block never pays anyone.
        {
            let mut payouts = self
                .payouts
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            payouts.record_share(&miner);
            // Unlock first (a share at height H matures older rounds), then
            // finalize the new round into `immature`.
            payouts.mature(block_height);
            if is_block {
                // Twice the expected shares per block at the template's own
                // difficulty: a share-difficulty bar above the network bar
                // would admit no shares at all, so the quotient is ≥ 2 in
                // every reachable state and the clamp is pure belt-and-braces.
                let window = (template_difficulty
                    .saturating_mul(2)
                    .checked_div(self.share_difficulty)
                    .unwrap_or(0))
                .clamp(1, PPLNS_MAX_WINDOW as u128) as usize;
                payouts.finalize_block(block_height, coinbase_sat, window);
            }
        }
        Ok(SubmitOutcome {
            share: true,
            block: is_block,
        })
    }

    /// Copy of one miner's accounting (zeroes when the miner has no shares).
    pub fn stats_for(&self, miner: &Address) -> ShareStats {
        self.inner
            .lock()
            .map(|inner| inner.stats.get(miner).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// Pending (unpaid) earnings for `miner` in sats.
    pub fn pending_payout(&self, miner: &Address) -> u64 {
        self.payouts.lock().map(|p| p.pending(miner)).unwrap_or(0)
    }

    /// Unlock matured rounds at `current_height` (coinbase maturity, not
    /// wall time). Called automatically on every job and share; exposed so
    /// tests and operators can advance a pool without traffic.
    pub fn mature_at(&self, current_height: u64) {
        if let Ok(mut payouts) = self.payouts.lock() {
            payouts.mature(current_height);
        }
    }

    /// The pool operator's earned fees in sats.
    pub fn operator_earned(&self) -> u64 {
        self.payouts
            .lock()
            .map(|p| p.operator_earned())
            .unwrap_or(0)
    }

    /// Most recently finalized round, if the pool has found a block yet.
    pub fn last_round(&self) -> Option<FinalizedRound> {
        self.payouts.lock().ok()?.rounds().last().cloned()
    }

    /// Record an on-chain payment to a miner against their pending balance.
    /// Returns the atomic receipt (unique id, bound to the latest round).
    /// Prefer [`Pool::mark_paid_with_txid`] with the settling transaction:
    /// a receipt that names its txid is provably paid, one without is only
    /// recorded intent.
    pub fn mark_paid(&self, miner: &Address, amount_sat: u64) -> Result<PaymentReceipt> {
        self.payouts
            .lock()
            .map_err(|_| Error::Malformed("pool lock"))?
            .mark_paid(miner, amount_sat)
    }

    /// Like [`Pool::mark_paid`], bound to the on-chain transaction that paid
    /// it — the evidence that reconciles this record against the chain.
    pub fn mark_paid_with_txid(
        &self,
        miner: &Address,
        amount_sat: u64,
        txid: srct_core::hash::Hash512,
    ) -> Result<PaymentReceipt> {
        self.payouts
            .lock()
            .map_err(|_| Error::Malformed("pool lock"))?
            .mark_paid_with_txid(miner, amount_sat, Some(txid))
    }

    /// Kept payment receipts, oldest-first (capped by the ledger).
    pub fn receipts(&self) -> Vec<PaymentReceipt> {
        self.payouts
            .lock()
            .map(|p| p.receipts().cloned().collect())
            .unwrap_or_default()
    }

    /// Lifetime paid to `miner` across all receipts, pruned or not.
    pub fn paid_total(&self, miner: &Address) -> u64 {
        self.payouts
            .lock()
            .map(|p| p.paid_total(miner))
            .unwrap_or(0)
    }

    /// Number of miners with accounting state.
    pub fn miner_count(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.stats.len())
            .unwrap_or(0)
    }

    /// Encode the pool's accounting state (miner stats, duplicate filter,
    /// payout ledger) into one versioned blob. The job store is
    /// deliberately excluded: jobs are single-use live state, and a
    /// restarted pool reissues them.
    pub fn encode_state(&self) -> Result<Vec<u8>> {
        use srct_core::ser::Writer;
        // Lock discipline: `inner` before `payouts`, matching the miner-cap
        // check in `submit_job`. The reverse order (taken here before this
        // fix) deadlocks against a concurrent share submission: one thread
        // holds `inner` and wants `payouts` while the encoder holds
        // `payouts` and wants `inner`. Sections are copied under each lock
        // in turn instead of nesting, so no thread ever holds both.
        let (next_job_id, stats, seen_order) = {
            let inner = self
                .inner
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            (
                inner.next_job_id,
                inner.stats.clone(),
                inner.seen_order.clone(),
            )
        };
        let ledger = {
            let payouts = self
                .payouts
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            payouts.encode()
        };
        let mut w = Writer::with_capacity(4096);
        w.u8(1);
        w.u64le(next_job_id);
        w.u32le(stats.len() as u32);
        for (miner, s) in stats.iter() {
            w.fixed(miner).u64le(s.shares).u64le(s.blocks_found);
        }
        w.u32le(seen_order.len() as u32);
        for d in seen_order.iter() {
            w.fixed(d);
        }
        w.u32le(ledger.len() as u32).raw(&ledger);
        Ok(w.into_vec())
    }

    /// Inverse of [`Pool::encode_state`]: decodes into locals and commits
    /// only on full success, so a refused blob never leaves half-loaded
    /// accounting. Outstanding jobs are left untouched (live single-use
    /// state the file never contained).
    pub fn decode_state(&self, bytes: &[u8]) -> Result<()> {
        use srct_core::ser::Reader;
        use std::collections::{HashMap, HashSet};
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| Error::Malformed("pool state version"))?;
        if version != 1 {
            return Err(Error::Malformed("pool state version"));
        }
        let next_job_id = r.u64le().map_err(|_| Error::Malformed("pool state"))?;
        if next_job_id == 0 {
            return Err(Error::Malformed("pool state job counter"));
        }
        let n_stats = r.u32le().map_err(|_| Error::Malformed("pool state"))? as usize;
        if n_stats > MAX_MINERS {
            return Err(Error::Malformed("pool state miners over the cap"));
        }
        let mut stats = HashMap::with_capacity(n_stats);
        for _ in 0..n_stats {
            let miner: Address = r.fixed().map_err(|_| Error::Malformed("pool state"))?;
            let shares = r.u64le().map_err(|_| Error::Malformed("pool state"))?;
            let blocks_found = r.u64le().map_err(|_| Error::Malformed("pool state"))?;
            if stats
                .insert(
                    miner,
                    ShareStats {
                        shares,
                        blocks_found,
                    },
                )
                .is_some()
            {
                return Err(Error::Malformed("pool state duplicate miner"));
            }
        }
        let n_seen = r.u32le().map_err(|_| Error::Malformed("pool state"))? as usize;
        if n_seen > SEEN_CAP {
            return Err(Error::Malformed("pool state seen over the cap"));
        }
        let mut seen = HashSet::with_capacity(n_seen);
        let mut seen_order = VecDeque::with_capacity(n_seen);
        for _ in 0..n_seen {
            let d: srct_core::hash::Hash512 =
                r.fixed().map_err(|_| Error::Malformed("pool state"))?;
            if !seen.insert(d) {
                return Err(Error::Malformed("pool state duplicate digest"));
            }
            seen_order.push_back(d);
        }
        let ledger_len = r.u32le().map_err(|_| Error::Malformed("pool state"))? as usize;
        if ledger_len > 64 * 1024 * 1024 {
            return Err(Error::Malformed("pool state ledger over the cap"));
        }
        let ledger_bytes = r
            .fixed_slice(ledger_len)
            .map_err(|_| Error::Malformed("pool state"))?;
        let ledger =
            RoundTracker::decode(ledger_bytes).map_err(|_| Error::Malformed("pool ledger"))?;
        r.expect_end()
            .map_err(|_| Error::Malformed("pool state trailing"))?;
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            if stats.len() > inner.max_miners {
                return Err(Error::Malformed("pool state miners over pool cap"));
            }
            inner.stats = stats;
            inner.seen = seen;
            inner.seen_order = seen_order;
            inner.next_job_id = next_job_id.max(1);
        }
        {
            let mut payouts = self
                .payouts
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            *payouts = ledger;
        }
        Ok(())
    }

    /// Atomically persist accounting state (temp file + rename, so a crash
    /// leaves the old file or the new one, never a torn half). Call after
    /// every finalized round and every payment.
    pub fn save_state(&self, path: &std::path::Path) -> Result<()> {
        let bytes = self.encode_state()?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes).map_err(|_| Error::Malformed("pool state write"))?;
        std::fs::rename(&tmp, path).map_err(|_| Error::Malformed("pool state commit"))?;
        Ok(())
    }

    /// Load state written by [`Pool::save_state`]. Fail-closed: any error
    /// refuses without touching live accounting.
    ///
    /// Startup-only: this *replaces* the ledger, the miner table and the
    /// duplicate filter. Loading over a pool that already accepted shares
    /// would orphan their accounting — load once before serving, then only
    /// [`Pool::save_state`].
    pub fn load_state(&self, path: &std::path::Path) -> Result<()> {
        let bytes = std::fs::read(path).map_err(|_| Error::Malformed("pool state read"))?;
        self.decode_state(&bytes)
    }

    /// Check the header's proof against an arbitrary share bar.
    ///
    /// The header is evaluated **as-is**: the share bar only selects the
    /// target the resulting hash is compared against. The header's own
    /// difficulty field is part of the hashed preimage (`stage1_seed` /
    /// `memory_hash` both serialize it), so swapping it would evaluate a
    /// different puzzle instance — valid shares refused, invalid ones
    /// accepted. This never weakens what `submit` enforces.
    ///
    /// Dispatch is on the *header's* puzzle id, not the pool's spec: a pool
    /// serving both puzzles (hybrid spec + HBM config) must verify an HBM
    /// template with the HBM rule. Dispatching on the pool spec instead
    /// refused every valid HBM share as below-difficulty.
    fn proof_meets(&self, header: &Header, difficulty: u128) -> Result<bool> {
        if difficulty == 0 {
            return Err(Error::InvalidDifficulty(0));
        }
        // A bar harder than the representable target (u128::MAX) can never
        // be met by any proof: that is a refused share, not an error.
        let target = match srct_core::u256::target_for_difficulty(difficulty) {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };
        match header.puzzle_id {
            1 => {
                let run = srct_core::puzzle::run_puzzle(&self.spec, header);
                Ok(srct_core::u256::U256::from_be_bytes(run.final_hash) <= target)
            }
            2 => {
                let cfg = self.hbm.as_ref().ok_or_else(|| {
                    Error::BadPuzzleSpec("hbm proof without an hbm config".into())
                })?;
                cfg.validate()?;
                let Some(mh) = srct_core::hbm_pow::memory_hash(header, cfg.lanes, cfg.accesses)
                else {
                    return Ok(false);
                };
                Ok(srct_core::u256::U256::from_be_bytes(mh) <= target)
            }
            other => Err(Error::BadPuzzleSpec(format!(
                "pool cannot verify puzzle {other}"
            ))),
        }
    }
}

/// Serve the JSON-lines protocol on `listener` until the process exits.
/// Each connection is handled on its own thread; a malformed line gets a
/// `{"accepted":false,"reason":"..."}` reply and the connection continues.
///
/// DoS posture: connections are capped ([`ServeLimits`], enforced at accept
/// time both globally and per source IP, so a flood is shed instead of
/// spawning threads without limit). Each admitted connection is bounded in
/// every dimension: request count, total lifetime, request rate (token
/// bucket), per-line read deadline, per-reply write deadline (a peer that
/// stops reading cannot pin the thread in `write_all`), and a 9 MiB line
/// cap against allocation attacks — a failed write closes the connection
/// instead of looping. Block submits additionally run under the pool's
/// submit deadline, so a hung node times out the share. Accounting itself
/// is bounded — the miner table refuses newcomers past [`MAX_MINERS`], the
/// job store evicts past 1024 entries, and the payout ledger prunes rounds
/// and receipts. An operator facing the open internet still wants a firewall
/// in front — this is pool software, not a hardened edge daemon.
pub fn serve(listener: TcpListener, pool: Arc<Pool>) -> ! {
    serve_limited(listener, pool, ServeLimits::default())
}

/// Like [`serve`] with explicit connection limits.
pub fn serve_limited(listener: TcpListener, pool: Arc<Pool>, limits: ServeLimits) -> ! {
    use std::collections::HashMap;
    use std::net::IpAddr;
    let total = Arc::new(Mutex::new(0usize));
    let per_ip = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
        let admitted = {
            let mut t = total.lock().unwrap_or_else(|e| e.into_inner());
            let mut ips = per_ip.lock().unwrap_or_else(|e| e.into_inner());
            let ip_count = peer_ip
                .map(|ip| ips.get(&ip).copied().unwrap_or(0))
                .unwrap_or(0);
            if *t >= limits.max_connections.max(1) || ip_count >= limits.max_per_ip.max(1) {
                false
            } else {
                *t += 1;
                if let Some(ip) = peer_ip {
                    ips.insert(ip, ip_count + 1);
                }
                true
            }
        };
        if !admitted {
            drop(stream);
            continue;
        }
        let pool = pool.clone();
        let total = total.clone();
        let per_ip = per_ip.clone();
        std::thread::spawn(move || {
            handle_conn(stream, &pool, limits);
            let mut t = total.lock().unwrap_or_else(|e| e.into_inner());
            *t = t.saturating_sub(1);
            if let Some(ip) = peer_ip {
                let mut ips = per_ip.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(c) = ips.get_mut(&ip) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        ips.remove(&ip);
                    }
                }
            }
        });
    }
    unreachable!("listener.incoming never returns None");
}

/// Largest single protocol line the pool will buffer (9 MiB): a `submit`
/// carries `block_hex` for a block of at most `max_block_bytes` (4 MiB on
/// every profile, i.e. 8M hex chars) plus a small JSON envelope, so 9 MiB
/// leaves ~1.4 MiB of headroom while cutting the worst-case per-connection
/// buffer from 16 MiB. Anything larger without a newline is an allocation
/// attack, not a share.
const MAX_LINE_BYTES: u64 = 9 * 1024 * 1024;

fn handle_conn(stream: TcpStream, pool: &Pool, limits: ServeLimits) {
    let started = std::time::Instant::now();
    let max_lines = limits.max_lines_per_conn.max(1);
    let lifetime = std::time::Duration::from_secs(limits.max_connection_secs.max(1));
    let mut throttle = RateLimiter::new(limits.rate_burst, limits.rate_per_sec);
    // Timeouts are per-handle on some platforms (notably Windows): set the
    // read deadline on the cloned reader handle and the write deadline on
    // the writer, never once on the pre-clone socket and never again.
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    if reader_stream
        .set_read_timeout(Some(std::time::Duration::from_secs(
            limits.read_timeout_secs.max(1),
        )))
        .is_err()
    {
        return;
    }
    let mut writer = stream;
    if writer
        .set_write_timeout(Some(std::time::Duration::from_secs(
            limits.write_timeout_secs.max(1),
        )))
        .is_err()
    {
        return;
    }
    let mut reader = BufReader::new(reader_stream);
    // `send` reports a dead peer: every call site returns right after a
    // `false`, so a peer that stops reading cannot pin this thread in
    // `write_all` past the write deadline above.
    let mut send = |value: serde_json::Value| -> bool {
        let mut out = value.to_string();
        out.push('\n');
        writer.write_all(out.as_bytes()).is_ok()
    };
    let mut line = String::new();
    let mut served: u64 = 0;
    loop {
        // Lifetime + request-count caps: even a well-formed chatterbox
        // eventually reconnects; an immortal connection is a leak, and a
        // peer that never finishes a line holds one handler thread only
        // until the read deadline fires.
        if served >= max_lines || started.elapsed() >= lifetime {
            return;
        }
        served += 1;
        line.clear();
        // Line cap: block_hex rides inside one JSON line (up to 8M hex chars
        // for a 4 MiB block plus envelope) — anything past 9 MiB without a
        // newline is an allocation attack, not a share.
        let mut capped = reader.by_ref().take(MAX_LINE_BYTES);
        let n = match capped.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => return,
        };
        if n == 0 {
            return;
        }
        if n as u64 >= MAX_LINE_BYTES && !line.ends_with('\n') {
            send(serde_json::json!({"accepted": false, "reason": "line too long"}));
            return;
        }
        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                if !send(serde_json::json!({"accepted": false, "reason": format!("bad json: {e}")}))
                {
                    return;
                }
                continue;
            }
        };
        // Per-connection request rate: bursts pass, sustained floods get a
        // refusal instead of proof verification and pool work.
        if !throttle.allow() {
            if !send(serde_json::json!({"accepted": false, "reason": "rate limited"})) {
                return;
            }
            continue;
        }
        match req.get("method").and_then(|m| m.as_str()) {
            Some("getjob") => {
                let Some(miner_hex) = req.get("miner").and_then(|m| m.as_str()) else {
                    if !send(serde_json::json!({"accepted": false, "reason": "missing miner"})) {
                        return;
                    }
                    continue;
                };
                if srct_core::hash::address_from_hex(miner_hex).is_err() {
                    if !send(serde_json::json!({"accepted": false, "reason": "bad miner address"}))
                    {
                        return;
                    }
                    continue;
                }
                match pool.get_job() {
                    Ok(job) => {
                        if !send(serde_json::json!({
                            "job_id": job.job_id,
                            "height": job.block.header.height,
                            "difficulty": job.block.header.difficulty.to_string(),
                            "puzzle_id": job.block.header.puzzle_id,
                            "block_hex": hex::encode(job.block.serialize()),
                        })) {
                            return;
                        }
                    }
                    Err(e) => {
                        if !send(serde_json::json!({"accepted": false, "reason": e.to_string()})) {
                            return;
                        }
                    }
                }
            }
            Some("submit") => {
                let job_id = req.get("job_id").and_then(|j| j.as_u64());
                let miner_hex = req.get("miner").and_then(|m| m.as_str());
                let block_hex = req.get("block_hex").and_then(|b| b.as_str());
                let (Some(job_id), Some(miner_hex), Some(block_hex)) =
                    (job_id, miner_hex, block_hex)
                else {
                    if !send(
                        serde_json::json!({"accepted": false, "reason": "missing job_id/miner/block_hex"}),
                    ) {
                        return;
                    }
                    continue;
                };
                let miner = match srct_core::hash::address_from_hex(miner_hex) {
                    Ok(a) => a,
                    Err(e) => {
                        if !send(
                            serde_json::json!({"accepted": false, "reason": format!("bad miner address: {e}")}),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                let raw = match hex::decode(block_hex.trim().trim_start_matches("0x")) {
                    Ok(raw) => raw,
                    Err(e) => {
                        if !send(
                            serde_json::json!({"accepted": false, "reason": format!("bad block hex: {e}")}),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                let block = match Block::deserialize(&raw) {
                    Ok(b) => b,
                    Err(e) => {
                        if !send(
                            serde_json::json!({"accepted": false, "reason": format!("block decode: {e}")}),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                match pool.submit_job(job_id, miner, block) {
                    Ok(out) => {
                        if !send(
                            serde_json::json!({"accepted": true, "share": out.share, "block": out.block}),
                        ) {
                            return;
                        }
                    }
                    Err(e) => {
                        if !send(serde_json::json!({"accepted": false, "reason": e.to_string()})) {
                            return;
                        }
                    }
                }
            }
            _ => {
                if !send(
                    serde_json::json!({"accepted": false, "reason": "unknown method (getjob/submit)"}),
                ) {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::chain::Chain;
    use srct_core::params::NetworkParams;

    fn test_pool(share_difficulty: u128, submitted: Arc<Mutex<Vec<Block>>>) -> (Pool, Address) {
        let miner = [7u8; 20];
        let chain = Arc::new(Mutex::new(Chain::new(NetworkParams::mini()).unwrap()));
        let pool = Pool::new(
            PuzzleSpec::hybrid_v1(),
            None,
            share_difficulty,
            0,
            {
                let chain = chain.clone();
                move || {
                    chain.lock().unwrap().build_template_with(
                        miner,
                        vec![],
                        1_767_225_601_000,
                        Some(1),
                    )
                }
            },
            move |block| {
                submitted.lock().unwrap().push(block);
                Ok(true)
            },
        )
        .unwrap();
        (pool, miner)
    }

    #[test]
    fn job_solve_submit_counts_share_and_block() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted.clone());

        let job = pool.get_job().unwrap();
        assert_eq!(job.block.header.height, 1);
        // Difficulty 1: nonce 0 is already a valid proof.
        let out = pool.submit_job(job.job_id, miner, job.block).unwrap();
        assert_eq!(
            out,
            SubmitOutcome {
                share: true,
                block: true
            }
        );
        assert_eq!(submitted.lock().unwrap().len(), 1);
        let stats = pool.stats_for(&miner);
        assert_eq!(stats.shares, 1);
        assert_eq!(stats.blocks_found, 1);
    }

    #[test]
    fn replay_of_a_consumed_job_is_refused() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted);

        let job = pool.get_job().unwrap();
        pool.submit_job(job.job_id, miner, job.block.clone())
            .unwrap();
        let err = pool.submit_job(job.job_id, miner, job.block).unwrap_err();
        assert_eq!(err, Error::Malformed("unknown job"));
    }

    #[test]
    fn coinbase_swap_is_refused() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted.clone());

        let job = pool.get_job().unwrap();
        // Steal the reward: change the coinbase value, keep the old header.
        // The header merkle still matches the job, but the transactions don't.
        let mut stolen = job.block.clone();
        stolen.txs[0].outputs[0].value += 1;
        let err = pool.submit_job(job.job_id, miner, stolen).unwrap_err();
        assert_eq!(
            err,
            Error::Malformed("share transactions differ from its job")
        );

        // Or rewrite the header merkle to match the stolen body: now the
        // header diverges from the issued job instead.
        let job2 = pool.get_job().unwrap();
        let mut forged = job2.block.clone();
        forged.txs[0].outputs[0].value += 1;
        forged.header.merkle_root = forged.merkle_root();
        let err = pool.submit_job(job2.job_id, miner, forged).unwrap_err();
        assert_eq!(err, Error::Malformed("share does not match its job"));
        assert_eq!(submitted.lock().unwrap().len(), 0);
    }

    #[test]
    fn below_share_difficulty_is_refused() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(u128::MAX, submitted.clone());

        // Unreachable bar, refused at job time: a share difficulty above the
        // template's network difficulty admits no shares at all, so the job
        // is never issued instead of failing every submission.
        let err = pool.get_job().unwrap_err();
        assert!(matches!(err, Error::BadPuzzleSpec(_)));
        assert!(submitted.lock().unwrap().is_empty());
        let _ = miner;
    }

    /// An HBM template must verify under the HBM rule, not the pool's hybrid
    /// spec: a proof that passes HBM at network difficulty but fails hybrid
    /// is a block, and the pool must forward it. (Dispatching on the pool
    /// spec instead counted it as a mere share and never submitted.)
    #[test]
    fn hbm_template_verifies_under_the_hbm_rule() {
        use srct_core::hbm_pow::{hbm_satisfies_cfg, HbmConfig};

        const DIFFICULTY: u128 = 64;
        let miner = [7u8; 20];
        let chain = Arc::new(Mutex::new(Chain::new(NetworkParams::mini()).unwrap()));
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let submitted_clone = submitted.clone();
        let pool = Pool::new(
            PuzzleSpec::hybrid_v1(),
            Some(HbmConfig::test()),
            1,
            0,
            {
                let chain = chain.clone();
                move || {
                    let mut template = chain.lock().unwrap().build_template_with(
                        miner,
                        vec![],
                        1_767_225_601_000,
                        Some(DIFFICULTY),
                    )?;
                    // The node would only serve puzzle 2 under an HBM-active
                    // profile; here we re-tag the header to exercise the
                    // pool's dispatch without forking consensus params.
                    template.header.puzzle_id = 2;
                    Ok(template)
                }
            },
            move |block| {
                submitted_clone.lock().unwrap().push(block);
                Ok(true)
            },
        )
        .unwrap();

        let job = pool.get_job().unwrap();
        assert_eq!(job.block.header.puzzle_id, 2);
        let cfg = HbmConfig::test();
        let mut hybrid = PuzzleSolver::new(PuzzleSpec::hybrid_v1());
        // Grind for a nonce that passes HBM but fails hybrid at the same
        // difficulty: at difficulty 64 the first HBM pass almost surely
        // fails hybrid (2^-256-ish collision either way).
        let mut winner = None;
        for nonce in 0..50_000u64 {
            let mut header = job.block.header.clone();
            header.nonce = nonce;
            let hbm_ok = hbm_satisfies_cfg(&header, DIFFICULTY, &cfg).unwrap();
            if hbm_ok && !hybrid.satisfies(&header).unwrap() {
                winner = Some(header);
                break;
            }
        }
        let header = winner.expect("difficulty 64 must solve in 50k tries");
        let mut block = job.block.clone();
        block.header = header;
        let out = pool.submit_job(job.job_id, miner, block).unwrap();
        assert_eq!(
            out,
            SubmitOutcome {
                share: true,
                block: true
            }
        );
        assert_eq!(submitted.lock().unwrap().len(), 1);
    }

    #[test]
    fn same_proof_under_two_jobs_counts_once() {
        // Attack: the pool serves the same template twice (same tip, two
        // job ids). A miner solves once and submits the identical solved
        // block under both ids, billing two shares for one grind.
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted.clone());

        let job_a = pool.get_job().unwrap();
        let job_b = pool.get_job().unwrap();
        assert_ne!(job_a.job_id, job_b.job_id);
        // Difficulty 1: nonce 0 is already a valid proof.
        let out = pool
            .submit_job(job_a.job_id, miner, job_a.block.clone())
            .unwrap();
        assert_eq!(
            out,
            SubmitOutcome {
                share: true,
                block: true
            }
        );
        let err = pool
            .submit_job(job_b.job_id, miner, job_a.block)
            .unwrap_err();
        assert_eq!(err, Error::Malformed("duplicate solution"));
        let stats = pool.stats_for(&miner);
        assert_eq!(stats.shares, 1);
        assert_eq!(stats.blocks_found, 1);
        // The duplicate must not have been forwarded a second time: one
        // proof, one submit.
        assert_eq!(submitted.lock().unwrap().len(), 1);
        // Held until the coinbase matures (default 100 in tests): one
        // share's pay, unlocked a hundred blocks later.
        assert_eq!(pool.pending_payout(&miner), 0);
        pool.mature_at(101);
        assert_eq!(pool.pending_payout(&miner), {
            let coinbase: u64 = submitted.lock().unwrap()[0].txs[0].outputs[0].value;
            coinbase
        });
    }

    #[test]
    fn block_find_pays_miner_minus_fee() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let submitted_clone = submitted.clone();
        let chain = Arc::new(Mutex::new(Chain::new(NetworkParams::mini()).unwrap()));
        let miner = [7u8; 20];
        let pool = Pool::new(
            PuzzleSpec::hybrid_v1(),
            None,
            1,
            1_000, // 10% pool fee
            {
                let chain = chain.clone();
                move || {
                    chain.lock().unwrap().build_template_with(
                        miner,
                        vec![],
                        1_767_225_601_000,
                        Some(1),
                    )
                }
            },
            move |block| {
                submitted_clone.lock().unwrap().push(block);
                Ok(true)
            },
        )
        .unwrap();

        let job = pool.get_job().unwrap();
        let coinbase: u64 = job.block.txs[0].outputs[0].value;
        pool.submit_job(job.job_id, miner, job.block).unwrap();

        let fee = coinbase * 1_000 / 10_000;
        // Held until the coinbase matures (100 blocks here): not payable yet.
        assert_eq!(pool.pending_payout(&miner), 0);
        pool.mature_at(101);
        assert_eq!(pool.pending_payout(&miner), coinbase - fee);
        assert_eq!(pool.operator_earned(), fee);
        let round = pool.last_round().expect("a found block finalizes a round");
        assert_eq!(round.block_height, 1);
        assert_eq!(round.payouts, vec![(miner, coinbase - fee)]);

        // Operator pays out; double-pay is refused.
        pool.mark_paid(&miner, coinbase - fee).unwrap();
        assert_eq!(pool.pending_payout(&miner), 0);
        assert!(pool.mark_paid(&miner, 1).is_err());
    }

    #[test]
    fn wire_getjob_submit_roundtrip() {
        use std::io::{BufRead, BufReader, Write};

        let submitted = Arc::new(Mutex::new(Vec::new()));
        let submitted_clone = submitted.clone();
        let pool = Arc::new(test_pool(1, submitted_clone).0);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve(listener, pool));

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let miner_hex = "07".repeat(20);
        let mut line = String::new();
        writeln!(
            stream,
            "{{\"method\":\"getjob\",\"miner\":\"{miner_hex}\"}}"
        )
        .unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let job: serde_json::Value = serde_json::from_str(&line).unwrap();
        let job_id = job["job_id"].as_u64().expect("job_id");
        let block_hex = job["block_hex"].as_str().expect("block_hex").to_string();
        assert_eq!(job["height"], 1);

        writeln!(
            stream,
            "{{\"method\":\"submit\",\"job_id\":{job_id},\"miner\":\"{miner_hex}\",\"block_hex\":\"{block_hex}\"}}"
        )
        .unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let out: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(out["accepted"], true);
        assert_eq!(out["share"], true);
        assert_eq!(out["block"], true);
        assert_eq!(submitted.lock().unwrap().len(), 1);

        // Unknown method gets a named refusal, connection stays alive.
        writeln!(stream, "{{\"method\":\"bogus\"}}").unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let out: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(out["accepted"], false);
    }

    fn capped_pool(max_miners: usize) -> (Pool, Address) {
        let miner = [7u8; 20];
        let chain = Arc::new(Mutex::new(Chain::new(NetworkParams::mini()).unwrap()));
        let pool = Pool::new_with_config(
            PuzzleSpec::hybrid_v1(),
            None,
            1,
            0,
            PoolConfig {
                max_miners,
                min_share_difficulty: 1,
                submit_timeout_secs: 120,
                coinbase_maturity: 10,
            },
            {
                let chain = chain.clone();
                move || {
                    chain.lock().unwrap().build_template_with(
                        miner,
                        vec![],
                        1_767_225_601_000,
                        Some(1),
                    )
                }
            },
            |_| Ok(true),
        )
        .unwrap();
        (pool, miner)
    }

    #[test]
    fn share_floor_below_minimum_is_a_config_error() {
        let chain = Arc::new(Mutex::new(Chain::new(NetworkParams::mini()).unwrap()));
        let err = Pool::new_with_config(
            PuzzleSpec::hybrid_v1(),
            None,
            1,
            0,
            PoolConfig {
                max_miners: MAX_MINERS,
                min_share_difficulty: MIN_OPERATIONAL_SHARE_DIFFICULTY,
                submit_timeout_secs: 120,
                coinbase_maturity: 10,
            },
            {
                let chain = chain.clone();
                move || {
                    chain.lock().unwrap().build_template_with(
                        [7u8; 20],
                        vec![],
                        1_767_225_601_000,
                        Some(1),
                    )
                }
            },
            |_| Ok(true),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadPuzzleSpec(_)));
    }

    #[test]
    fn full_miner_table_refuses_newcomers_but_keeps_regulars() {
        // Attack: a fresh address per share would grow accounting without
        // bound. Past the cap, unknown miners are refused before anything
        // is recorded or forwarded, while known miners keep working.
        let (pool, miner) = capped_pool(1);
        let job_a = pool.get_job().unwrap();
        pool.submit_job(job_a.job_id, miner, job_a.block).unwrap();
        assert_eq!(pool.miner_count(), 1);

        let newcomer = [9u8; 20];
        let job_b = pool.get_job().unwrap();
        // A distinct proof (nonce 1 also solves at difficulty 1) from a
        // fresh address: refused as full, not counted, not forwarded.
        let mut other = job_b.block.clone();
        other.header.nonce = 1;
        let err = pool.submit_job(job_b.job_id, newcomer, other).unwrap_err();
        assert_eq!(err, Error::Malformed("miner table full"));
        assert_eq!(pool.stats_for(&newcomer).shares, 0);
        assert_eq!(pool.pending_payout(&newcomer), 0);

        // The regular's next share still works (fresh nonce: the pool
        // serves the same template twice, and replaying the first proof
        // would be a duplicate, not a second share).
        let job_c = pool.get_job().unwrap();
        let mut again = job_c.block.clone();
        again.header.nonce = 2;
        pool.submit_job(job_c.job_id, miner, again).unwrap();
        assert_eq!(pool.stats_for(&miner).shares, 2);
    }

    #[test]
    fn pool_state_survives_a_restart() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted.clone());
        let job = pool.get_job().unwrap();
        let coinbase: u64 = job.block.txs[0].outputs[0].value;
        pool.submit_job(job.job_id, miner, job.block).unwrap();
        // Payable only after maturity (default 100): mark_paid refuses the
        // immature balance, then succeeds once unlocked.
        let txid = [0xEEu8; 64];
        assert!(pool.mark_paid_with_txid(&miner, 10, txid).is_err());
        pool.mature_at(101);
        let r = pool.mark_paid_with_txid(&miner, 10, txid).unwrap();
        assert_eq!(r.receipt_id, 1);

        let dir = std::env::temp_dir();
        let path = dir.join(format!("pool-state-test-{}.bin", std::process::id()));
        pool.save_state(&path).unwrap();
        assert!(!path.with_extension("tmp").exists());

        // A fresh pool with no template/submit history loads the accounting.
        let (fresh, _) = test_pool(1, Arc::new(Mutex::new(Vec::new())));
        fresh.load_state(&path).unwrap();
        assert_eq!(fresh.pending_payout(&miner), coinbase - 10);
        assert_eq!(fresh.paid_total(&miner), 10);
        assert_eq!(fresh.stats_for(&miner).shares, 1);
        let receipts = fresh.receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].txid, Some(txid));
        // The receipt counter survives: no id is ever reused.
        let r2 = fresh.mark_paid(&miner, 1).unwrap();
        assert_eq!(r2.receipt_id, 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn pool_state_decode_is_fail_closed() {
        let (pool, _) = test_pool(1, Arc::new(Mutex::new(Vec::new())));
        assert!(pool.decode_state(&[]).is_err());
        let mut bytes = pool.encode_state().unwrap();
        bytes.push(0xFF);
        // Live accounting untouched by the refusal.
        assert!(pool.decode_state(&bytes).is_err());
        assert_eq!(pool.miner_count(), 0);
    }

    #[test]
    fn rate_limiter_bursts_then_refuses_without_refill() {
        let mut rl = RateLimiter::new(3, 0.0);
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(!rl.allow());
        assert!(!rl.allow());
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut rl = RateLimiter::new(1, 1_000.0);
        assert!(rl.allow());
        assert!(!rl.allow());
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(rl.allow(), "10ms at 1000/s must refill");
    }

    #[test]
    fn serve_limits_default_to_finite_bounds() {
        let l = ServeLimits::default();
        assert!(l.max_connections > 0 && l.max_per_ip > 0 && l.max_lines_per_conn > 0);
        assert!(l.read_timeout_secs > 0 && l.write_timeout_secs > 0);
        assert!(l.max_connection_secs > 0);
        assert!(l.rate_burst > 0 && l.rate_per_sec > 0.0);
    }

    #[test]
    fn hung_node_submit_times_out_without_poisoning_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // A hung node must time out the share, not pin the handler: the
        // timed-out proof is forgotten, so the retry is a resubmit rather
        // than a duplicate, and nothing is accounted until the node accepts.
        let miner = [7u8; 20];
        let chain = Arc::new(Mutex::new(Chain::new(NetworkParams::mini()).unwrap()));
        let calls = Arc::new(AtomicUsize::new(0));
        let pool = Pool::new_with_config(
            PuzzleSpec::hybrid_v1(),
            None,
            1,
            0,
            PoolConfig {
                max_miners: MAX_MINERS,
                min_share_difficulty: 1,
                submit_timeout_secs: 1,
                coinbase_maturity: 10,
            },
            {
                let chain = chain.clone();
                move || {
                    chain.lock().unwrap().build_template_with(
                        miner,
                        vec![],
                        1_767_225_601_000,
                        Some(1),
                    )
                }
            },
            {
                let calls = calls.clone();
                move |_| {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        Ok(false)
                    } else {
                        Ok(true)
                    }
                }
            },
        )
        .unwrap();

        let job_a = pool.get_job().unwrap();
        let err = pool
            .submit_job(job_a.job_id, miner, job_a.block)
            .unwrap_err();
        assert_eq!(err, Error::Malformed("node submit timed out"));
        assert_eq!(pool.stats_for(&miner).shares, 0);
        assert_eq!(pool.pending_payout(&miner), 0);

        let job_b = pool.get_job().unwrap();
        let out = pool.submit_job(job_b.job_id, miner, job_b.block).unwrap();
        assert!(out.block);
        assert_eq!(pool.stats_for(&miner).shares, 1);
    }

    #[test]
    fn line_cap_fits_largest_block_but_rejects_allocation_attack() {
        // Largest real line: 4 MiB block as 8M hex chars plus a small JSON
        // envelope. The cap must clear that with headroom, and must stay well
        // below the old 16 MiB that let one connection pin 16 MiB (512 conns
        // = 8 GiB, 32 per-IP = 512 MiB).
        let cap = MAX_LINE_BYTES;
        assert!(cap >= 8 * 1024 * 1024 + 1024 * 1024);
        assert!(cap < 16 * 1024 * 1024);
        assert_eq!(cap, 9 * 1024 * 1024);
    }

    #[test]
    fn oversized_line_without_newline_is_refused() {
        use std::io::{BufRead, BufReader, Write};
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let pool = Arc::new(test_pool(1, submitted).0);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve(listener, pool));
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();
        // One byte past the cap, no newline: the server must refuse without
        // buffering unbounded input.
        let flood = vec![b'x'; (MAX_LINE_BYTES + 1) as usize];
        stream.write_all(&flood).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let out: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(out["accepted"], false);
        assert_eq!(out["reason"], "line too long");
    }

    #[test]
    fn concurrent_encode_and_submit_do_not_deadlock() {
        use std::sync::mpsc;
        // Lock-ordering regression test: `submit_job` takes `inner` then
        // `payouts` (miner-cap check) while `encode_state` used to take them
        // in the reverse order — a classic ABBA deadlock under load. Hammer
        // both paths from several threads; a watchdog bounds the run so a
        // regression fails the test instead of hanging the suite.
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted);
        let pool = Arc::new(pool);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn({
            let pool = pool.clone();
            move || {
                let mut handles = Vec::new();
                for t in 0..4u64 {
                    let pool = pool.clone();
                    handles.push(std::thread::spawn(move || {
                        for i in 0..25u64 {
                            let job = pool.get_job().unwrap();
                            let mut block = job.block.clone();
                            // Distinct proof per iteration: the pool serves
                            // the same template repeatedly, and difficulty 1
                            // solves every nonce.
                            block.header.nonce = t * 1_000_000 + i + 1;
                            pool.submit_job(job.job_id, miner, block).unwrap();
                        }
                    }));
                }
                for _ in 0..100 {
                    pool.encode_state().unwrap();
                }
                for h in handles {
                    h.join().unwrap();
                }
                tx.send(pool.stats_for(&miner).shares).unwrap();
            }
        });
        match rx.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(shares) => assert_eq!(shares, 100),
            Err(_) => panic!("encode/submit workload did not finish: lock ordering regressed"),
        }
    }
}
