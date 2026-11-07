//! Pool payout ledger: PPLNS (pay-per-last-N-shares) round accounting.
//!
//! A *round* is the shares standing between two blocks the pool finds (or
//! between startup and the first block). When the pool finds a block paying
//! `coinbase_sat` to the pool address, [`RoundTracker::finalize_block`]
//! splits the reward across the **last `window` shares**, not the round:
//!
//! - the pool takes `fee_bps` basis points off the top (tracked as
//!   `operator_earned`, never mixed with miner money),
//! - the rest plus carried dust is split proportionally to shares **inside
//!   the window**, floored to whole sats,
//! - the flooring remainder (dust) is **not** kept by the operator: it
//!   carries into the next round's pot, so miners lose nothing to rounding.
//!
//! Why a window and not the round (PROP): under proportional-per-round
//! accounting a share submitted early in a long round is worth less than one
//! submitted late, so a miner who only mines fresh rounds earns more per hash
//! than a loyal one — pool hopping. Under PPLNS every share in the window is
//! worth exactly the same no matter when it landed, so there is no timing
//! edge to exploit. The window is `2 × network_difficulty /
//! share_difficulty` (≈ two blocks' worth of shares), bounded by
//! [`PPLNS_MAX_WINDOW`] so the share log is bounded memory.
//!
//! A round with no shares in the window pays the whole pot to the carry
//! (minus the fee): there is nobody to pay, and the dust rule keeps it miner
//! money.
//!
//! This ledger is accounting only. Moving actual coin is the operator's
//! on-chain transfer; [`RoundTracker::mark_paid`] records it so a miner is
//! never paid twice. All iteration is over ordered structures, so identical
//! share sequences produce byte-identical round records on every machine.

use std::collections::{BTreeMap, VecDeque};

use srct_core::error::{Error, Result};
use srct_core::hash::{Address, Hash512};
use srct_core::ser::{Reader, Writer};

/// Upper bound on the PPLNS window (and hence on the share log): one million
/// shares ≈ 20 MB of addresses. Windows are derived as twice the expected
/// shares per block, so an operator whose rounds routinely exceed this should
/// raise share difficulty, not memory.
pub const PPLNS_MAX_WINDOW: usize = 1_000_000;

/// How many finalized rounds the ledger keeps in memory. Older rounds are
/// pruned: the per-miner `pending` balances already carry what is owed, and
/// an unbounded round history would let a long-lived pool grow without
/// bound. The prune point is well past any operator reconciliation window.
pub const MAX_ROUNDS_KEPT: usize = 1024;

/// How many payment receipts the ledger keeps. Receipt ids stay monotonic
/// across the prune (only the oldest records are dropped), so uniqueness is
/// never reused.
pub const MAX_RECEIPTS_KEPT: usize = 10_000;

/// Version byte of the [`RoundTracker`] persistence encoding. A build that
/// writes a different layout writes a different value, so an old file is
/// refused by version instead of misread field by field.
pub const LEDGER_VERSION: u8 = 2;

/// One finalized round: who earned what, deterministically ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRound {
    pub round_id: u64,
    pub block_height: u64,
    pub coinbase_sat: u64,
    pub fee_sat: u64,
    /// The PPLNS window this round paid over.
    pub window: usize,
    /// `(miner, sats)` sorted by address bytes.
    pub payouts: Vec<(Address, u64)>,
    /// Flooring remainder carried into the next round's pot.
    pub dust_sat: u64,
}

/// One recorded on-chain payment: a unique, monotonic `receipt_id`, the
/// miner, the amount, the latest finalized round at payment time (0 when no
/// round exists yet), and the settling transaction when the operator binds
/// one. The `txid` is what reconciles this record against the chain: a
/// receipt without a bound transaction is "recorded, not yet proven paid",
/// and `mark_paid_with_txid` is how it becomes proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentReceipt {
    pub receipt_id: u64,
    pub round_id: u64,
    pub miner: Address,
    pub amount_sat: u64,
    pub txid: Option<Hash512>,
}

fn encode_addr_u64(w: &mut Writer, map: &BTreeMap<Address, u64>) {
    w.u32le(map.len() as u32);
    for (addr, v) in map {
        w.fixed(addr).u64le(*v);
    }
}

fn decode_addr_u64(
    r: &mut Reader<'_>,
    what: &str,
    cap: usize,
) -> std::result::Result<BTreeMap<Address, u64>, String> {
    let n = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
    if n > cap {
        return Err(format!("{what}: {n} entries over the {cap} cap"));
    }
    let mut map = BTreeMap::new();
    for _ in 0..n {
        let addr: Address = r.fixed().map_err(|e| format!("{what}: {e}"))?;
        let v = r.u64le().map_err(|e| format!("{what}: {e}"))?;
        if map.insert(addr, v).is_some() {
            return Err(format!("{what}: duplicate key"));
        }
    }
    Ok(map)
}

#[derive(Debug, Clone)]
pub struct RoundTracker {
    fee_bps: u32,
    round_id: u64,
    /// Every accepted share in arrival order. Never cleared on finalize —
    /// PPLNS pays the trailing window, so a share stays eligible across
    /// blocks until it ages out past the window or the memory cap.
    log: VecDeque<Address>,
    lifetime_shares: BTreeMap<Address, u64>,
    pending: BTreeMap<Address, u64>,
    /// Round earnings not yet spendable: `(release_height, miner -> sats)`.
    /// A found block's coinbase cannot be spent until `coinbase_maturity`
    /// blocks bury it, so crediting it straight to `pending` let the
    /// operator pay real funds for a round a reorg can still orphan. Entries
    /// move to `pending` only via [`Self::mature`].
    immature: Vec<(u64, BTreeMap<Address, u64>)>,
    /// Blocks a coinbase must wait before its round matures (100 mainnet,
    /// 10 mini/testnet — set from [`PoolConfig`](super::PoolConfig)).
    coinbase_maturity: u64,
    /// Miner money carried across rounds (rounding dust + shareless pots).
    carry_sat: u64,
    /// Pool operator's earned fees, separate from miner money.
    operator_earned_sat: u64,
    rounds: Vec<FinalizedRound>,
    /// Monotonic receipt counter: never reused, never rewound by pruning.
    next_receipt_id: u64,
    /// Atomic payout records, oldest-first, capped at [`MAX_RECEIPTS_KEPT`].
    receipts: VecDeque<PaymentReceipt>,
    /// Lifetime paid per miner (sums every receipt, pruned or not).
    paid_total: BTreeMap<Address, u64>,
}

impl RoundTracker {
    /// `fee_bps` is the pool fee in basis points (250 = 2.5%).
    pub fn new(fee_bps: u32) -> Result<Self> {
        Self::with_maturity(fee_bps, 100)
    }

    /// Like [`Self::new`] with an explicit coinbase maturity (100 mainnet,
    /// 10 on mini/testnet): a round's earnings unlock that many blocks after
    /// its height.
    pub fn with_maturity(fee_bps: u32, coinbase_maturity: u64) -> Result<Self> {
        if fee_bps > 10_000 {
            return Err(Error::Malformed("pool fee exceeds 100%"));
        }
        Ok(RoundTracker {
            fee_bps,
            round_id: 0,
            log: VecDeque::new(),
            lifetime_shares: BTreeMap::new(),
            pending: BTreeMap::new(),
            immature: Vec::new(),
            coinbase_maturity,
            carry_sat: 0,
            operator_earned_sat: 0,
            rounds: Vec::new(),
            next_receipt_id: 1,
            receipts: VecDeque::new(),
            paid_total: BTreeMap::new(),
        })
    }

    /// Move matured round earnings into `pending`. Call with the current
    /// chain height whenever the pool observes it (job issue, share
    /// submit): without this nothing ever unlocks.
    pub fn mature(&mut self, current_height: u64) {
        let mut i = 0;
        while i < self.immature.len() {
            if self.immature[i].0 <= current_height {
                let (_, map) = self.immature.remove(i);
                for (miner, pay) in map {
                    *self.pending.entry(miner).or_insert(0) = self
                        .pending
                        .get(&miner)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(pay);
                }
            } else {
                i += 1;
            }
        }
    }

    /// Drop immature earnings for `block_height`: the reorg hook. A round
    /// whose block left canon pays nobody — keeping it would unlock orphan
    /// money at maturity. Entries are keyed by release height
    /// (`finalize_height + maturity`), so the orphaned one is exact.
    /// The operator fee for the voided round is reversed too, and dust
    /// carried from exactly that round is returned (when no later round
    /// has consumed it).
    pub fn void_round(&mut self, block_height: u64) {
        let mut void_fee = 0u64;
        let mut void_dust = 0u64;
        let mut void_count = 0usize;
        let mut was_latest = false;
        if let Some(last) = self.rounds.last() {
            was_latest = last.block_height == block_height;
        }
        for r in self
            .rounds
            .iter()
            .filter(|r| r.block_height == block_height)
        {
            void_fee = void_fee.saturating_add(r.fee_sat);
            void_dust = void_dust.saturating_add(r.dust_sat);
            void_count += 1;
        }
        self.rounds.retain(|r| r.block_height != block_height);
        let release = block_height.saturating_add(self.coinbase_maturity);
        self.immature.retain(|(r, _)| *r != release);
        self.operator_earned_sat = self.operator_earned_sat.saturating_sub(void_fee);
        // Only the latest round's dust is still sitting in `carry_sat`:
        // later rounds would have consumed it into their own pots.
        if void_count == 1 && was_latest && self.carry_sat == void_dust {
            self.carry_sat = 0;
        }
    }

    /// Record one accepted share for `miner` at the tail of the window.
    pub fn record_share(&mut self, miner: &Address) {
        self.log.push_back(*miner);
        if self.log.len() > PPLNS_MAX_WINDOW {
            self.log.pop_front();
        }
        // Saturating: a wrapping counter would eventually credit a miner
        // with fewer shares than earned; clamping keeps the ledger monotonic.
        // `Pool` additionally bounds the miner table at `MAX_MINERS`.
        *self.lifetime_shares.entry(*miner).or_insert(0) = self
            .lifetime_shares
            .get(miner)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
    }

    /// Close the open round on a found block: split `coinbase_sat`
    /// proportionally to the last `window` shares. The log is kept — PPLNS
    /// pays the trailing window, so a share stays eligible across blocks
    /// until it ages out. `window == 0` (or an empty log) means nobody is
    /// payable and the whole pot carries; oversized windows simply pay the
    /// whole log.
    ///
    /// Earnings land in `immature`, not `pending`: the coinbase is
    /// unspendable until `coinbase_maturity` buries the block, and paying
    /// out of `mark_paid` before that would spend money a reorg can still
    /// take back. [`Self::mature`] unlocks them; [`Self::void_round`]
    /// cancels them.
    pub fn finalize_block(
        &mut self,
        block_height: u64,
        coinbase_sat: u64,
        window: usize,
    ) -> FinalizedRound {
        self.round_id += 1;
        // u128 throughout: a u64 coinbase times basis points overflows u64
        // long before it looks large, and a wrapped fee would silently become
        // the operator's — or the miners' — money.
        let fee_sat = (coinbase_sat as u128)
            .saturating_mul(self.fee_bps as u128)
            .saturating_div(10_000) as u64;
        self.operator_earned_sat = self.operator_earned_sat.saturating_add(fee_sat);
        let pot = coinbase_sat
            .saturating_sub(fee_sat)
            .saturating_add(self.carry_sat);
        self.carry_sat = 0;

        let window = window.min(PPLNS_MAX_WINDOW).min(self.log.len());
        let mut counts: BTreeMap<Address, u64> = BTreeMap::new();
        for miner in self.log.iter().skip(self.log.len() - window) {
            *counts.entry(*miner).or_insert(0) += 1;
        }
        let total_shares = window as u64;
        let mut payouts = Vec::new();
        let mut immature_map: BTreeMap<Address, u64> = BTreeMap::new();
        if total_shares > 0 {
            let mut distributed = 0u64;
            for (miner, shares) in &counts {
                let pay = (*shares as u128)
                    .saturating_mul(pot as u128)
                    .saturating_div(total_shares as u128) as u64;
                distributed = distributed.saturating_add(pay);
                if pay > 0 {
                    *immature_map.entry(*miner).or_insert(0) = immature_map
                        .get(miner)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(pay);
                    payouts.push((*miner, pay));
                }
            }
            self.carry_sat = pot.saturating_sub(distributed);
        } else {
            // Nobody payable: the whole pot carries, miner money stays miner
            // money instead of silently becoming operator revenue.
            self.carry_sat = pot;
        }
        let round = FinalizedRound {
            round_id: self.round_id,
            block_height,
            coinbase_sat,
            fee_sat,
            window,
            payouts,
            dust_sat: self.carry_sat,
        };
        // Held, not payable: unlocks at `mature(block_height + maturity)`,
        // cancels at `void_round(block_height)`.
        if !immature_map.is_empty() {
            let release = block_height.saturating_add(self.coinbase_maturity);
            self.immature.push((release, immature_map));
        }
        self.rounds.push(round.clone());
        // Bound the history: pending balances already carry what is owed, so
        // dropping the oldest finalized records bounds memory without
        // forgiving any debt. Round ids stay monotonic regardless.
        while self.rounds.len() > MAX_ROUNDS_KEPT {
            self.rounds.remove(0);
        }
        round
    }

    /// Record a payment of `amount_sat` to `miner` against their pending
    /// balance. Overpaying (more than pending) is refused: it would hide an
    /// accounting bug as generosity. Returns the atomic receipt: its
    /// `receipt_id` is unique across the ledger's lifetime, and the receipt
    /// is stored before returning so a crash after this call cannot lose it
    /// once the operator persists the ledger (see [`Self::save_to_file`]).
    pub fn mark_paid(&mut self, miner: &Address, amount_sat: u64) -> Result<PaymentReceipt> {
        self.mark_paid_with_txid(miner, amount_sat, None)
    }

    /// Like [`Self::mark_paid`], binding the record to the on-chain
    /// transaction that paid it. Reconciling receipts against the chain is
    /// how an operator proves "paid": a receipt with `txid: None` is
    /// recorded intent, one with `Some` names the evidence.
    ///
    /// Crash-safe order is send-on-chain first, then record with the
    /// resulting txid, then [`Self::save_to_file`] immediately: recording
    /// first and crashing before the save loses the receipt while the
    /// coin is gone, and the retry double-pays. Never re-record the same
    /// payment — a second record debits pending twice.
    pub fn mark_paid_with_txid(
        &mut self,
        miner: &Address,
        amount_sat: u64,
        txid: Option<Hash512>,
    ) -> Result<PaymentReceipt> {
        // Zero-amount "payments" create receipt noise and can mask a caller
        // that lost the real amount: refuse them instead of recording them.
        if amount_sat == 0 {
            return Err(Error::Malformed("zero payout"));
        }
        let pending = self.pending.get(miner).copied().unwrap_or(0);
        if amount_sat > pending {
            return Err(Error::Malformed("payout exceeds pending balance"));
        }
        self.pending.insert(*miner, pending - amount_sat);
        let receipt = PaymentReceipt {
            receipt_id: self.next_receipt_id,
            round_id: self.round_id,
            miner: *miner,
            amount_sat,
            txid,
        };
        self.next_receipt_id = self.next_receipt_id.wrapping_add(1).max(1);
        self.receipts.push_back(receipt.clone());
        while self.receipts.len() > MAX_RECEIPTS_KEPT {
            self.receipts.pop_front();
        }
        *self.paid_total.entry(*miner).or_insert(0) = self
            .paid_total
            .get(miner)
            .copied()
            .unwrap_or(0)
            .saturating_add(amount_sat);
        Ok(receipt)
    }

    /// Kept payment receipts, oldest-first.
    pub fn receipts(&self) -> impl Iterator<Item = &PaymentReceipt> {
        self.receipts.iter()
    }

    /// Lifetime paid to `miner` across all receipts, pruned or not.
    pub fn paid_total(&self, miner: &Address) -> u64 {
        self.paid_total.get(miner).copied().unwrap_or(0)
    }

    /// Encode the whole ledger — shares, balances, carry, rounds, receipts —
    /// into one versioned blob. A pool restart restores from this instead of
    /// starting with empty balances: without it, unpaid earnings and share
    /// history die with the process and `mark_paid` guards a balance that
    /// no longer exists.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4096);
        w.u8(LEDGER_VERSION);
        w.u32le(self.fee_bps).u64le(self.round_id);
        w.u32le(self.log.len() as u32);
        for miner in &self.log {
            w.fixed(miner);
        }
        encode_addr_u64(&mut w, &self.lifetime_shares);
        encode_addr_u64(&mut w, &self.pending);
        w.u64le(self.carry_sat).u64le(self.operator_earned_sat);
        w.u32le(self.rounds.len() as u32);
        for r in &self.rounds {
            w.u64le(r.round_id)
                .u64le(r.block_height)
                .u64le(r.coinbase_sat)
                .u64le(r.fee_sat)
                .u64le(r.window as u64);
            w.u32le(r.payouts.len() as u32);
            for (miner, pay) in &r.payouts {
                w.fixed(miner).u64le(*pay);
            }
            w.u64le(r.dust_sat);
        }
        w.u64le(self.next_receipt_id);
        w.u32le(self.receipts.len() as u32);
        for rc in &self.receipts {
            w.u64le(rc.receipt_id)
                .u64le(rc.round_id)
                .fixed(&rc.miner)
                .u64le(rc.amount_sat);
            match &rc.txid {
                Some(t) => {
                    w.u8(1).fixed(t);
                }
                None => {
                    w.u8(0);
                }
            }
        }
        encode_addr_u64(&mut w, &self.paid_total);
        // v2: immature round earnings plus the maturity they unlock under.
        w.u64le(self.coinbase_maturity);
        w.u32le(self.immature.len() as u32);
        for (release, map) in &self.immature {
            w.u64le(*release);
            encode_addr_u64(&mut w, map);
        }
        w.into_vec()
    }

    /// Inverse of [`Self::encode`]. Every section decodes into locals and
    /// only commits on full success, so a refused blob never leaves a
    /// half-loaded ledger. Count guards precede every allocation, so a lying
    /// length cannot force a huge allocation before the codec trips.
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("ledger: {e}"))?;
        if version != LEDGER_VERSION {
            return Err(format!(
                "ledger version {version}, this build reads {LEDGER_VERSION}"
            ));
        }
        let fee_bps = r.u32le().map_err(|e| format!("ledger: {e}"))?;
        if fee_bps > 10_000 {
            return Err("ledger: fee exceeds 100%".into());
        }
        let round_id = r.u64le().map_err(|e| format!("ledger: {e}"))?;
        let log_len = r.u32le().map_err(|e| format!("ledger: {e}"))? as usize;
        if log_len > PPLNS_MAX_WINDOW {
            return Err(format!("ledger: {log_len} log entries over the cap"));
        }
        let mut log = VecDeque::with_capacity(log_len);
        for _ in 0..log_len {
            log.push_back(r.fixed::<20>().map_err(|e| format!("ledger: {e}"))?);
        }
        let lifetime_shares = decode_addr_u64(&mut r, "lifetime_shares", 1_000_000)?;
        let pending = decode_addr_u64(&mut r, "pending", 1_000_000)?;
        let carry_sat = r.u64le().map_err(|e| format!("ledger: {e}"))?;
        let operator_earned_sat = r.u64le().map_err(|e| format!("ledger: {e}"))?;
        let rounds_len = r.u32le().map_err(|e| format!("ledger: {e}"))? as usize;
        if rounds_len > MAX_ROUNDS_KEPT {
            return Err(format!("ledger: {rounds_len} rounds over the cap"));
        }
        let mut rounds = Vec::with_capacity(rounds_len);
        for _ in 0..rounds_len {
            let rid = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let block_height = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let coinbase_sat = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let fee_sat = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let window = r.u64le().map_err(|e| format!("ledger: {e}"))? as usize;
            if window > PPLNS_MAX_WINDOW {
                return Err("ledger: round window over the cap".into());
            }
            let n = r.u32le().map_err(|e| format!("ledger: {e}"))? as usize;
            if n > 1_000_000 {
                return Err("ledger: round payouts over the cap".into());
            }
            let mut payouts = Vec::with_capacity(n);
            for _ in 0..n {
                let miner: Address = r.fixed().map_err(|e| format!("ledger: {e}"))?;
                let pay = r.u64le().map_err(|e| format!("ledger: {e}"))?;
                payouts.push((miner, pay));
            }
            let dust_sat = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            rounds.push(FinalizedRound {
                round_id: rid,
                block_height,
                coinbase_sat,
                fee_sat,
                window,
                payouts,
                dust_sat,
            });
        }
        let next_receipt_id = r.u64le().map_err(|e| format!("ledger: {e}"))?;
        if next_receipt_id == 0 {
            return Err("ledger: receipt counter must not be zero".into());
        }
        let rc_len = r.u32le().map_err(|e| format!("ledger: {e}"))? as usize;
        if rc_len > MAX_RECEIPTS_KEPT {
            return Err(format!("ledger: {rc_len} receipts over the cap"));
        }
        let mut receipts = VecDeque::with_capacity(rc_len);
        for _ in 0..rc_len {
            let receipt_id = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let round_id = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let miner: Address = r.fixed().map_err(|e| format!("ledger: {e}"))?;
            let amount_sat = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let has_txid = r.u8().map_err(|e| format!("ledger: {e}"))?;
            let txid = match has_txid {
                0 => None,
                1 => Some(r.fixed::<64>().map_err(|e| format!("ledger: {e}"))?),
                _ => return Err("ledger: bad txid flag".into()),
            };
            receipts.push_back(PaymentReceipt {
                receipt_id,
                round_id,
                miner,
                amount_sat,
                txid,
            });
        }
        let paid_total = decode_addr_u64(&mut r, "paid_total", 1_000_000)?;
        let coinbase_maturity = r.u64le().map_err(|e| format!("ledger: {e}"))?;
        let im_len = r.u32le().map_err(|e| format!("ledger: {e}"))? as usize;
        if im_len > MAX_ROUNDS_KEPT {
            return Err(format!("ledger: {im_len} immature rounds over the cap"));
        }
        let mut immature = Vec::with_capacity(im_len);
        for _ in 0..im_len {
            let release = r.u64le().map_err(|e| format!("ledger: {e}"))?;
            let map = decode_addr_u64(&mut r, "immature", 1_000_000)?;
            immature.push((release, map));
        }
        r.expect_end()
            .map_err(|e| format!("ledger: trailing bytes ({e})"))?;
        // Receipt ids must be unique and below the counter: a file that pays
        // the same receipt twice (or rewinds the counter) is corrupt.
        {
            let mut last = 0u64;
            for rc in &receipts {
                if rc.receipt_id == 0 || rc.receipt_id >= next_receipt_id {
                    return Err("ledger: receipt id outside the counter range".into());
                }
                if rc.receipt_id <= last {
                    return Err("ledger: receipts out of order".into());
                }
                last = rc.receipt_id;
            }
        }
        Ok(RoundTracker {
            fee_bps,
            round_id,
            log,
            lifetime_shares,
            pending,
            immature,
            coinbase_maturity,
            carry_sat,
            operator_earned_sat,
            rounds,
            next_receipt_id,
            receipts,
            paid_total,
        })
    }

    /// Atomically persist the ledger: write to a sibling temp file and
    /// rename over the target, so a crash mid-write leaves either the old
    /// file or the new one, never a torn half. Call after every finalized
    /// round and every payment; the file is the durable payment ledger.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let bytes = self.encode();
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes).map_err(|_| Error::Malformed("ledger write failed"))?;
        std::fs::rename(&tmp, path).map_err(|_| Error::Malformed("ledger commit failed"))?;
        Ok(())
    }

    /// Load a ledger written by [`Self::save_to_file`]. Any failure — missing
    /// file, bad version, trailing bytes — is a refusal, never a partial
    /// best effort: the caller must not run payouts on a ledger it cannot
    /// prove is complete.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|_| Error::Malformed("ledger read failed"))?;
        Self::decode(&bytes).map_err(|_| Error::Malformed("ledger decode failed"))
    }

    pub fn pending(&self, miner: &Address) -> u64 {
        self.pending.get(miner).copied().unwrap_or(0)
    }

    pub fn operator_earned(&self) -> u64 {
        self.operator_earned_sat
    }

    pub fn carry(&self) -> u64 {
        self.carry_sat
    }

    pub fn lifetime_shares(&self, miner: &Address) -> u64 {
        self.lifetime_shares.get(miner).copied().unwrap_or(0)
    }

    /// Whether `miner` already has ledger state (share history or a
    /// balance). Used by the pool's miner-table bound: only unknown miners
    /// count against the cap.
    pub fn is_tracked(&self, miner: &Address) -> bool {
        self.lifetime_shares.contains_key(miner) || self.pending.contains_key(miner)
    }

    pub fn rounds(&self) -> &[FinalizedRound] {
        &self.rounds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    #[test]
    fn proportional_split_with_fee_and_dust_carry() {
        // 3:1 shares, 10% fee, 101-sat coinbase: fee 10, pot 91.
        // A: 91*3/4 = 68, B: 91*1/4 = 22, dust 1 carries.
        let mut t = RoundTracker::new(1_000).unwrap();
        for _ in 0..3 {
            t.record_share(&addr(1));
        }
        t.record_share(&addr(2));
        let r = t.finalize_block(100, 101, 1_000_000);
        assert_eq!(r.fee_sat, 10);
        assert_eq!(r.payouts, vec![(addr(1), 68), (addr(2), 22)]);
        assert_eq!(r.dust_sat, 1);
        // Not yet payable: the round matures 100 blocks after its height.
        assert_eq!(t.pending(&addr(1)), 0);
        t.mature(200);
        assert_eq!(t.pending(&addr(1)), 68);
        assert_eq!(t.pending(&addr(2)), 22);
        assert_eq!(t.operator_earned(), 10);
        assert_eq!(t.carry(), 1);

        // Next round: dust joins the pot, and — PPLNS, not PROP — the first
        // round's shares are still inside the window, so they earn again.
        // Log: A,A,A,B (old) + B (new); pot 9 + 1 dust = 10 over 5 shares:
        // A: 10*3/5 = 6, B: 10*2/5 = 4, dust 0.
        t.record_share(&addr(2));
        let r2 = t.finalize_block(101, 10, 1_000_000);
        assert_eq!(r2.payouts, vec![(addr(1), 6), (addr(2), 4)]);
        assert_eq!(r2.dust_sat, 0);
        t.mature(201);
        assert_eq!(t.pending(&addr(1)), 74);
        assert_eq!(t.pending(&addr(2)), 26);
    }

    #[test]
    fn window_excludes_stale_shares() {
        // The anti-hopping property: only the last `window` shares are paid.
        // A hopper's 90 ancient shares earn nothing once 10 loyal shares
        // arrived after them and the window is 10.
        let mut t = RoundTracker::new(0).unwrap();
        for _ in 0..90 {
            t.record_share(&addr(9));
        }
        for _ in 0..10 {
            t.record_share(&addr(1));
        }
        let r = t.finalize_block(100, 100, 10);
        assert_eq!(r.window, 10);
        assert_eq!(r.payouts, vec![(addr(1), 100)]);
        t.mature(200);
        assert_eq!(t.pending(&addr(9)), 0);
        assert_eq!(t.pending(&addr(1)), 100);
    }

    #[test]
    fn shares_survive_across_blocks_until_they_age_out() {
        // PPLNS, not PROP: a share unpaid in one block stays eligible for the
        // next while it is still inside the window.
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        let r1 = t.finalize_block(100, 60, 10);
        assert_eq!(r1.payouts, vec![(addr(1), 60)]);
        // No new shares, same window: the old share is still the whole
        // window, so a second block pays it again.
        let r2 = t.finalize_block(101, 40, 10);
        assert_eq!(r2.payouts, vec![(addr(1), 40)]);
        t.mature(201);
        assert_eq!(t.pending(&addr(1)), 100);
    }

    #[test]
    fn shareless_round_carries_the_pot() {
        let mut t = RoundTracker::new(0).unwrap();
        let r = t.finalize_block(100, 50, 1_000_000);
        assert!(r.payouts.is_empty());
        assert_eq!(r.dust_sat, 50);
        assert_eq!(t.carry(), 50);
        assert_eq!(t.operator_earned(), 0);
    }

    #[test]
    fn overpay_is_refused_and_exact_pay_clears() {
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.finalize_block(100, 100, 1_000_000);
        // Nothing payable before maturity, so even the exact amount refuses.
        assert!(t.mark_paid(&addr(1), 100).is_err());
        t.mature(200);
        assert!(t.mark_paid(&addr(1), 101).is_err());
        t.mark_paid(&addr(1), 100).unwrap();
        assert_eq!(t.pending(&addr(1)), 0);
    }

    #[test]
    fn fee_above_100_percent_is_refused() {
        assert!(RoundTracker::new(10_001).is_err());
    }

    #[test]
    fn extreme_coinbase_values_do_not_wrap() {
        // u64::MAX coinbase at 100% fee and at 0%: the fee and every share
        // must be exact, never wrapped. (u64 arithmetic wrapped here before
        // the u128 fix — a wrapped fee silently moved money.)
        let mut t = RoundTracker::new(10_000).unwrap();
        t.record_share(&addr(1));
        let r = t.finalize_block(1, u64::MAX, 1_000_000);
        assert_eq!(r.fee_sat, u64::MAX);
        assert!(r.payouts.is_empty());
        assert_eq!(t.operator_earned(), u64::MAX);

        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.record_share(&addr(2));
        let r = t.finalize_block(1, u64::MAX, 1_000_000);
        // Odd value split two ways: 2^64-1 = 2*(2^63-1) + 1, dust 1 carries.
        let half = u64::MAX / 2;
        assert_eq!(r.payouts, vec![(addr(1), half), (addr(2), half)]);
        assert_eq!(r.dust_sat, 1);
        assert_eq!(t.carry(), 1);
    }

    #[test]
    fn rounds_are_deterministic_and_ordered() {
        let mut t = RoundTracker::new(0).unwrap();
        // Insert out of order; payouts must still sort by address.
        t.record_share(&addr(1));
        t.record_share(&addr(9));
        let r = t.finalize_block(100, 100, 1_000_000);
        assert_eq!(r.payouts, vec![(addr(1), 50), (addr(9), 50)]);
        assert_eq!(t.rounds().len(), 1);
        assert_eq!(t.rounds()[0].round_id, 1);
    }

    #[test]
    fn receipts_are_unique_monotonic_and_bound_to_txid() {
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.finalize_block(100, 100, 1_000_000);
        t.mature(200);
        let r1 = t.mark_paid(&addr(1), 40).unwrap();
        let txid = [0xABu8; 64];
        let r2 = t.mark_paid_with_txid(&addr(1), 60, Some(txid)).unwrap();
        assert_eq!((r1.receipt_id, r2.receipt_id), (1, 2));
        assert_eq!(r1.txid, None);
        assert_eq!(r2.txid, Some(txid));
        assert_eq!(t.paid_total(&addr(1)), 100);
        assert_eq!(t.pending(&addr(1)), 0);
        let ids: Vec<u64> = t.receipts().map(|r| r.receipt_id).collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn finalized_history_is_bounded() {
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        for h in 0..(MAX_ROUNDS_KEPT as u64 + 10) {
            t.finalize_block(h, 10, 1_000_000);
        }
        assert_eq!(t.rounds().len(), MAX_ROUNDS_KEPT);
        // Ids stay monotonic across the prune: no round is ever renumbered.
        assert_eq!(
            t.rounds().last().unwrap().round_id,
            MAX_ROUNDS_KEPT as u64 + 10
        );
        assert_eq!(t.rounds().first().unwrap().round_id, 11);
    }

    #[test]
    fn ledger_survives_a_restart_through_encode_decode() {
        let mut t = RoundTracker::new(250).unwrap();
        t.record_share(&addr(1));
        t.record_share(&addr(2));
        t.finalize_block(100, 101, 1_000_000);
        t.mature(200);
        let txid = [0xCDu8; 64];
        let r = t.mark_paid_with_txid(&addr(1), 10, Some(txid)).unwrap();
        assert_eq!(r.receipt_id, 1);
        let bytes = t.encode();
        let u = RoundTracker::decode(&bytes).unwrap();
        assert_eq!(u.pending(&addr(1)), t.pending(&addr(1)));
        assert_eq!(u.pending(&addr(2)), t.pending(&addr(2)));
        assert_eq!(u.carry(), t.carry());
        assert_eq!(u.operator_earned(), t.operator_earned());
        assert_eq!(u.rounds(), t.rounds());
        let receipts: Vec<_> = u.receipts().cloned().collect();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].txid, Some(txid));
        assert_eq!(u.paid_total(&addr(1)), 10);
        // The counter survives too: the next receipt is 2, never reused.
        let mut u = u;
        u.record_share(&addr(1));
        u.finalize_block(101, 50, 1_000_000);
        u.mature(201);
        let r2 = u.mark_paid(&addr(1), 1).unwrap();
        assert_eq!(r2.receipt_id, 2);
    }

    #[test]
    fn earnings_unlock_only_at_maturity_and_void_cancels() {
        // A found block's coinbase is unspendable until maturity: payable
        // only at height + maturity, never before.
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.finalize_block(100, 100, 1_000_000);
        assert_eq!(t.pending(&addr(1)), 0);
        t.mature(199);
        assert_eq!(t.pending(&addr(1)), 0);
        t.mature(200);
        assert_eq!(t.pending(&addr(1)), 100);
        // A reorg that orphans the block cancels the unlock: void first,
        // then even maturity pays nothing.
        let mut u = RoundTracker::new(0).unwrap();
        u.record_share(&addr(1));
        u.finalize_block(100, 100, 1_000_000);
        u.void_round(100);
        u.mature(200);
        assert_eq!(u.pending(&addr(1)), 0);
    }

    #[test]
    fn ledger_decode_is_fail_closed() {
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.finalize_block(100, 50, 1_000_000);
        let mut bytes = t.encode();
        // Trailing bytes: refused.
        bytes.push(0xFF);
        assert!(RoundTracker::decode(&bytes).is_err());
        // Bad version: refused, never misread.
        let mut bad = t.encode();
        bad[0] = 0x7F;
        assert!(RoundTracker::decode(&bad).is_err());
        // Empty: refused.
        assert!(RoundTracker::decode(&[]).is_err());
    }

    #[test]
    fn ledger_save_and_load_is_atomic() {
        let mut t = RoundTracker::new(100).unwrap();
        t.record_share(&addr(3));
        t.finalize_block(7, 90, 1_000_000);
        t.mature(107);
        t.mark_paid(&addr(3), 5).unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("pplns-ledger-test-{}.bin", std::process::id()));
        t.save_to_file(&path).unwrap();
        // No temp file lingers after the atomic rename.
        assert!(!path.with_extension("tmp").exists());
        let u = RoundTracker::load_from_file(&path).unwrap();
        assert_eq!(u.pending(&addr(3)), t.pending(&addr(3)));
        assert_eq!(u.rounds(), t.rounds());
        assert_eq!(u.paid_total(&addr(3)), 5);
        std::fs::remove_file(&path).ok();
        // Missing file is a refusal, not an empty ledger: running payouts on
        // an unprovable ledger would silently drop debt.
        assert!(RoundTracker::load_from_file(&path).is_err());
    }
}
