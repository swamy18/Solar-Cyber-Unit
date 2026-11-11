//! SRCT Treats: reward claims for agents, machines and robots.
//!
//! A third value component alongside liquid SRCT (UTXO) and committed SRCT
//! (L2 escrow): transferable incentive claims backed by a sub-ledger of the
//! PSCB fee reserve. Treats are never spendable as UTXOs — value leaves the
//! system only as satoshis, when Treats are burned and the backing reserve
//! pays out.
//!
//! # Design rules (locked)
//!
//! - **Two acquisition paths, both verified.** Fee-based Treats mint only
//!   from verified settlement artifacts the node itself observed (an accepted
//!   receipt, a VWC the L2 state holds) — never from caller-supplied claims.
//!   Free Treats move only under an owner-signed gift certificate. There is
//!   no open mint: `commit`/`event_for` build from ledger state, and the API
//!   exposes no generic mint.
//! - **Fixed weight table in code.** An event carries no amount and no weight.
//! - **Source counted once** per subject (bounded ring), accumulator-chained
//!   like reputation, so history cannot be rewritten or replayed.
//! - **Storable, capped — no decay.** Balances accumulate for later use;
//!   growth is bounded by a per-agent cap and a global outstanding cap.
//! - **Service layer.** Balances live in a node-local [`TreatLedger`].
//!   Consensus only tracks the backing sat reserve
//!   (`Chain::treat_reserve`); transfers move claims, redemption burns them.
//! - **Integer-only.** No floats anywhere.

use crate::agent::AgentId;
use crate::hash::{sha256_dom, Address, Hash};
use crate::ser::{Reader, Writer};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// v3 adds the per-account last event kind (novelty damping input); v4 adds
/// persisted redemption nonces. Older blobs decode with nonce state empty.
pub const TREATS_VERSION: u8 = 4;
pub const DOM_TREAT_EVENT: &[u8] = b"srct/treat-event/v1";
pub const DOM_TREAT_ACC: &[u8] = b"srct/treat-acc/v1";
pub const DOM_TREAT_GIFT: &[u8] = b"srct/treat-gift/v1";
pub const DOM_TREAT_TRANSFER: &[u8] = b"srct/treat-transfer/v1";
pub const DOM_TREAT_VOUCHER: &[u8] = b"srct/treat-voucher/v1";
pub const MAX_TREAT_NETWORK_ID_LEN: usize = 64;
pub const NOVELTY_STEP_BPS: u64 = 1_500;
pub const STREAK_STEP_BPS: u64 = 500;
pub const STREAK_MAX_BPS: u64 = 5_000;
pub const MAX_TRACKED_SOURCES: usize = 128;
pub const DEFAULT_MAX_SUBJECTS: usize = 8192;
pub const BPS_DENOM: u32 = 10_000;

/// Share of each block's PSCB leg routed to the Treat reserve, in bps.
/// 1000 = 10% of the PSCB leg; cap 2000 = 20%.
pub const TREAT_BPS: u32 = 1_000;
pub const TREAT_MAX_BPS: u32 = 2_000;

/// Storable balance ceiling per holder, in Treats.
pub const MAX_TREAT_BALANCE_PER_AGENT: u64 = 1_000_000;
/// Global ceiling on all outstanding Treats.
pub const MAX_TREAT_OUTSTANDING: u64 = 500_000_000;
/// Largest single owner-signed gift, in Treats.
pub const MAX_GIFT_AMOUNT: u64 = 10_000;
/// Largest single agent-to-agent transfer, in Treats.
pub const MAX_TRANSFER_AMOUNT: u64 = 100_000;
/// Fee sats that earn one bonus Treat, and the per-event bonus cap.
pub const FEE_SAT_PER_TREAT: u64 = 1_000;
pub const FEE_BONUS_CAP: u64 = 50;
/// Certificates must expire within this many blocks of the current height.
pub const TREAT_CERT_MAX_LIFETIME: u64 = 10_000;
/// Fresh redemption vouchers stay usable this many blocks.
pub const VOUCHER_LIFETIME_BLOCKS: u64 = 1_440;
/// Bound retained voucher and consumed-id state so redemptions cannot grow
/// state.bin without limit. Expired vouchers remain auditable until pruning is
/// implemented, so refuse new issuance at this cap.
pub const MAX_VOUCHERS: usize = 8_192;

/// Treat cut carved from an already-computed PSCB amount.
/// `None` when `bps` exceeds [`TREAT_MAX_BPS`]: refuse, never clamp.
pub fn treat_cut(pscb_sat: u64, bps: u32) -> Option<u64> {
    if bps > TREAT_MAX_BPS {
        return None;
    }
    Some((pscb_sat as u128 * bps as u128 / BPS_DENOM as u128) as u64)
}

/// Default cut (10% of the PSCB leg). Infallible: default is within cap.
pub fn treat_cut_default(pscb_sat: u64) -> u64 {
    treat_cut(pscb_sat, TREAT_BPS).expect("default bps is within cap")
}

/// Split a PSCB leg into `(retained, treat)`. Invariant: sum == pscb.
pub fn split_pscb_for_treats(pscb_sat: u64) -> (u64, u64) {
    let t = treat_cut_default(pscb_sat);
    (pscb_sat.saturating_sub(t), t)
}

/// Redemption quote: satoshis for burning `treats` given
/// `reserve_sat` backing `outstanding` treats. Floored, checked.
pub fn redeem_quote(treats: u64, reserve_sat: u64, outstanding: u64) -> Option<u64> {
    if treats == 0 || outstanding == 0 || reserve_sat == 0 {
        return Some(0);
    }
    let v = (treats as u128)
        .checked_mul(reserve_sat as u128)?
        .checked_div(outstanding as u128)?;
    u64::try_from(v).ok()
}

/// Capped fee-proportional bonus, in Treats, for `fee_sat` of verified spend.
pub fn fee_bonus(fee_sat: u64) -> u64 {
    (fee_sat / FEE_SAT_PER_TREAT).min(FEE_BONUS_CAP)
}

/// What earned the Treats. Discriminant is part of the event id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TreatKind {
    VerifiedWork = 0,
    ServiceCompleted = 1,
    PaymentCompleted = 2,
    DisputeWon = 3,
    DisputeLost = 4,
    /// Owner-signed free gift (applied via [`TreatLedger::apply_gift`]).
    Gift = 5,
}

impl TreatKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TreatKind::VerifiedWork),
            1 => Some(TreatKind::ServiceCompleted),
            2 => Some(TreatKind::PaymentCompleted),
            3 => Some(TreatKind::DisputeWon),
            4 => Some(TreatKind::DisputeLost),
            5 => Some(TreatKind::Gift),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Fixed base Treats. Not a field of any event: cannot be self-declared.
    pub fn base(self) -> u64 {
        match self {
            TreatKind::VerifiedWork => 20,
            TreatKind::ServiceCompleted => 5,
            TreatKind::PaymentCompleted => 5,
            TreatKind::DisputeWon => 10,
            // Losing a dispute mints nothing; the ledger slashes instead.
            TreatKind::DisputeLost => 0,
            // Gifts carry their signed amount, not a table weight.
            TreatKind::Gift => 0,
        }
    }
}

/// What a redemption voucher pays toward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoucherKind {
    FeeCredit = 0,
    Discount = 1,
    Trial = 2,
    ServiceCredit = 3,
}

impl VoucherKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(VoucherKind::FeeCredit),
            1 => Some(VoucherKind::Discount),
            2 => Some(VoucherKind::Trial),
            3 => Some(VoucherKind::ServiceCredit),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn parse_kind(s: &str) -> Option<Self> {
        match s {
            "fee_credit" => Some(VoucherKind::FeeCredit),
            "discount" => Some(VoucherKind::Discount),
            "trial" => Some(VoucherKind::Trial),
            "service_credit" => Some(VoucherKind::ServiceCredit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreatError {
    Malformed(&'static str),
    UnsupportedVersion(u8),
    WrongNetwork { expected: String, got: String },
    BadNetworkId(usize),
    ChainBroken { subject: AgentId },
    DuplicateSource { source: Hash },
    SubjectLimit { cap: usize },
    Overflow,
    InsufficientBalance { have: u64, want: u64 },
    BadAmount,
    CapExceeded,
    NonceReuse,
    Expired,
    BadSignature(&'static str),
    UnknownVoucher,
    VoucherConsumed,
    VoucherExpired,
    KindMismatch,
    WrongRecipient,
    AlreadyClaimed,
}

impl fmt::Display for TreatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreatError::Malformed(w) => write!(f, "malformed treat record: {w}"),
            TreatError::UnsupportedVersion(v) => write!(f, "unsupported treats version {v}"),
            TreatError::WrongNetwork { expected, got } => {
                write!(f, "treats ledger is {expected}, record is {got}")
            }
            TreatError::BadNetworkId(n) => write!(f, "treats network id length {n} invalid"),
            TreatError::ChainBroken { .. } => write!(f, "event does not chain onto accumulator"),
            TreatError::DuplicateSource { source } => {
                write!(f, "source {} already counted", hex::encode(source))
            }
            TreatError::SubjectLimit { cap } => {
                write!(f, "treats ledger is at its subject cap ({cap})")
            }
            TreatError::Overflow => write!(f, "arithmetic overflow in treats accounting"),
            TreatError::InsufficientBalance { have, want } => {
                write!(f, "insufficient treats: have {have}, want {want}")
            }
            TreatError::BadAmount => write!(f, "treat amount is zero or over its per-record cap"),
            TreatError::CapExceeded => write!(
                f,
                "treat cap exceeded: balance or outstanding would overflow its ceiling"
            ),
            TreatError::NonceReuse => write!(f, "certificate nonce already used or not increasing"),
            TreatError::Expired => {
                write!(f, "certificate is expired or lives past its max lifetime")
            }
            TreatError::BadSignature(w) => write!(f, "certificate signature invalid: {w}"),
            TreatError::UnknownVoucher => write!(f, "unknown treat voucher"),
            TreatError::VoucherConsumed => write!(f, "treat voucher already consumed"),
            TreatError::VoucherExpired => write!(f, "treat voucher expired"),
            TreatError::KindMismatch => write!(f, "voucher kind does not match this use"),
            TreatError::WrongRecipient => write!(f, "treat voucher names another recipient"),
            TreatError::AlreadyClaimed => write!(f, "work already claimed for treats"),
        }
    }
}

impl std::error::Error for TreatError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreatEvent {
    pub version: u8,
    pub network_id: String,
    pub subject: AgentId,
    pub kind: TreatKind,
    pub height: u64,
    pub source: Hash,
    pub prev: Hash,
    /// Consecutive repeats of [`TreatAccount::last_kind`] so far (novelty
    /// damping input): same kind again increments, anything else resets.
    pub repeats: u32,
    /// Consecutive verified epochs (streak bonus input).
    pub streak: u32,
}

impl TreatEvent {
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(170);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.subject)
            .u8(self.kind.as_u8())
            .u64le(self.height)
            .fixed(&self.source)
            .fixed(&self.prev)
            .u32le(self.repeats)
            .u32le(self.streak);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TreatError> {
        let mut r = Reader::new(bytes);
        let event = Self::decode_reader(&mut r)?;
        r.expect_end()
            .map_err(|_| TreatError::Malformed("trailing bytes"))?;
        Ok(event)
    }

    fn decode_reader(r: &mut Reader) -> Result<Self, TreatError> {
        let version = r.u8().map_err(|_| TreatError::Malformed("version"))?;
        if version != 1 && version != 2 {
            // Event encoding is version 1; ledger envelope is versioned
            // separately. Accept both ledger generations' event shape.
            return Err(TreatError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| TreatError::Malformed("network len"))? as usize;
        if net_len == 0 || net_len > MAX_TREAT_NETWORK_ID_LEN {
            return Err(TreatError::BadNetworkId(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| TreatError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| TreatError::Malformed("network id is not utf-8"))?
            .to_string();
        let subject = r
            .fixed::<20>()
            .map_err(|_| TreatError::Malformed("subject"))?;
        let kind_raw = r.u8().map_err(|_| TreatError::Malformed("kind"))?;
        // Gifts never travel as events; refuse them here so a hand-built
        // event cannot mint an arbitrary gift amount.
        let kind = match TreatKind::from_u8(kind_raw) {
            Some(TreatKind::Gift) | None => {
                return Err(TreatError::Malformed("kind out of range"));
            }
            Some(k) => k,
        };
        let height = r.u64le().map_err(|_| TreatError::Malformed("height"))?;
        let source = r
            .fixed::<32>()
            .map_err(|_| TreatError::Malformed("source"))?;
        let prev = r.fixed::<32>().map_err(|_| TreatError::Malformed("prev"))?;
        let repeats = r.u32le().map_err(|_| TreatError::Malformed("repeats"))?;
        let streak = r.u32le().map_err(|_| TreatError::Malformed("streak"))?;
        Ok(TreatEvent {
            version,
            network_id,
            subject,
            kind,
            height,
            source,
            prev,
            repeats,
            streak,
        })
    }

    pub fn event_id(&self) -> Hash {
        sha256_dom(DOM_TREAT_EVENT, &[&self.serialize()])
    }

    /// Dopamine-shaped mint amount: base * novelty * (1 + streak bonus).
    pub fn mint_amount(&self) -> u64 {
        let base = self.kind.base() as u128;
        if base == 0 {
            return 0;
        }
        let novelty_bps = (BPS_DENOM as u64)
            .saturating_sub((self.repeats as u64).saturating_mul(NOVELTY_STEP_BPS));
        // Floor novelty at 10% so long-running pairs still earn something.
        let novelty_bps = novelty_bps.max(1_000);
        let streak_bps = ((self.streak as u64).saturating_mul(STREAK_STEP_BPS)).min(STREAK_MAX_BPS);
        let v = base * novelty_bps as u128 * (BPS_DENOM as u128 + streak_bps as u128)
            / (BPS_DENOM as u128 * BPS_DENOM as u128);
        v as u64
    }
}

/// Owner-signed free gift: the human signs the exact recipient, amount,
/// nonce and expiry. The node verifies; there is no open mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GiftCertificate {
    pub network_id: String,
    pub giver: Address,
    pub recipient: AgentId,
    pub amount: u64,
    pub nonce: u64,
    pub expiry_height: u64,
}

impl GiftCertificate {
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(
            DOM_TREAT_GIFT,
            &[
                self.network_id.as_bytes(),
                &self.giver,
                &self.recipient,
                &self.amount.to_le_bytes(),
                &self.nonce.to_le_bytes(),
                &self.expiry_height.to_le_bytes(),
            ],
        )
    }
}

/// Agent-to-agent transfer: the sender signs the exact recipient, amount,
/// nonce and expiry. Verifiable anywhere, applied on this node's ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCertificate {
    pub network_id: String,
    pub sender: Address,
    pub sender_subject: AgentId,
    pub recipient: AgentId,
    pub amount: u64,
    pub nonce: u64,
    pub expiry_height: u64,
}

impl TransferCertificate {
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(
            DOM_TREAT_TRANSFER,
            &[
                self.network_id.as_bytes(),
                &self.sender,
                &self.sender_subject,
                &self.recipient,
                &self.amount.to_le_bytes(),
                &self.nonce.to_le_bytes(),
                &self.expiry_height.to_le_bytes(),
            ],
        )
    }
}

/// Single-use redemption voucher: burned Treats become a spendable credit
/// toward one benefit kind. Consumed exactly once, then dead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreatVoucher {
    pub id: Hash,
    pub network_id: String,
    pub recipient: AgentId,
    pub value_sat: u64,
    pub kind: VoucherKind,
    pub expiry_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreatAccount {
    pub accumulator: Hash,
    pub balance: u64,
    pub lifetime_earned: u64,
    pub lifetime_redeemed: u64,
    pub streak: u32,
    pub repeats: u32,
    /// Kind of the most recent committed event. Novelty damping counts
    /// *consecutive* repeats of one kind: without remembering what the
    /// last event was, `repeats` could never advance and every repeat
    /// paid full novelty.
    pub last_kind: Option<TreatKind>,
    pub last_height: u64,
    pub events: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTreat {
    pub event: TreatEvent,
    pub event_id: Hash,
    pub minted: u64,
    pub balance: u64,
}

#[derive(Debug, Clone)]
pub struct TreatLedger {
    network_id: String,
    accounts: BTreeMap<AgentId, TreatAccount>,
    /// Runtime-only replay guard (bounded ring per subject). Restart resets
    /// it; receipt acceptance (persisted `ReceiptBook`) and the persisted
    /// `claimed_tasks` set below are the restart-safe replay guards for the
    /// two mint paths.
    sources: BTreeMap<AgentId, VecDeque<Hash>>,
    max_subjects: usize,
    pub outstanding: u64,
    giver_nonces: BTreeMap<Address, u64>,
    sender_nonces: BTreeMap<Address, u64>,
    redeem_nonces: BTreeMap<AgentId, u64>,
    claimed_tasks: BTreeSet<Hash>,
    vouchers: BTreeMap<Hash, TreatVoucher>,
    consumed: BTreeSet<Hash>,
    voucher_seq: u64,
}

impl TreatLedger {
    pub fn new(network_id: impl Into<String>) -> Self {
        Self::with_capacity(network_id, DEFAULT_MAX_SUBJECTS)
    }

    pub fn with_capacity(network_id: impl Into<String>, max_subjects: usize) -> Self {
        TreatLedger {
            network_id: network_id.into(),
            accounts: BTreeMap::new(),
            sources: BTreeMap::new(),
            max_subjects,
            outstanding: 0,
            giver_nonces: BTreeMap::new(),
            sender_nonces: BTreeMap::new(),
            redeem_nonces: BTreeMap::new(),
            claimed_tasks: BTreeSet::new(),
            vouchers: BTreeMap::new(),
            consumed: BTreeSet::new(),
            voucher_seq: 0,
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn subjects(&self) -> usize {
        self.accounts.len()
    }

    pub fn balance(&self, subject: &AgentId) -> u64 {
        self.accounts.get(subject).map(|a| a.balance).unwrap_or(0)
    }

    pub fn account(&self, subject: &AgentId) -> Option<&TreatAccount> {
        self.accounts.get(subject)
    }

    pub fn outstanding(&self) -> u64 {
        self.outstanding
    }

    /// Unconsumed, unexpired voucher liability in sats.
    pub fn voucher_liability(&self, height: u64) -> u64 {
        self.vouchers
            .values()
            .filter(|v| !self.consumed.contains(&v.id) && height <= v.expiry_height)
            .fold(0u64, |a, v| a.saturating_add(v.value_sat))
    }

    pub fn event_for(
        &self,
        subject: AgentId,
        kind: TreatKind,
        height: u64,
        source: Hash,
    ) -> Result<TreatEvent, TreatError> {
        if kind == TreatKind::Gift {
            return Err(TreatError::Malformed("gifts are not events"));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_TREAT_NETWORK_ID_LEN {
            return Err(TreatError::BadNetworkId(self.network_id.len()));
        }
        let acc = self.accounts.get(&subject);
        let prev = acc.map(|a| a.accumulator).unwrap_or([0u8; 32]);
        // Novelty damping counts *consecutive* repeats of one kind: same
        // kind again increments, anything else (or a fresh account) resets.
        let repeats = match acc {
            Some(a) if a.last_kind == Some(kind) => a.repeats.saturating_add(1),
            _ => 0,
        };
        let streak = match kind {
            TreatKind::VerifiedWork | TreatKind::ServiceCompleted | TreatKind::DisputeWon => {
                acc.map(|a| a.streak.saturating_add(1)).unwrap_or(1)
            }
            _ => acc.map(|a| a.streak).unwrap_or(0),
        };
        Ok(TreatEvent {
            version: 1,
            network_id: self.network_id.clone(),
            subject,
            kind,
            height,
            source,
            prev,
            repeats,
            streak,
        })
    }

    fn check_caps(&self, subject: &AgentId, add: u64) -> Result<(), TreatError> {
        let have = self.balance(subject);
        if have
            .checked_add(add)
            .map(|b| b > MAX_TREAT_BALANCE_PER_AGENT)
            .unwrap_or(true)
        {
            return Err(TreatError::CapExceeded);
        }
        if self
            .outstanding
            .checked_add(add)
            .map(|o| o > MAX_TREAT_OUTSTANDING)
            .unwrap_or(true)
        {
            return Err(TreatError::CapExceeded);
        }
        Ok(())
    }

    fn apply_mint(&mut self, event: &TreatEvent, extra: u64) -> Result<AppliedTreat, TreatError> {
        if event.version != 1 && event.version != 2 {
            return Err(TreatError::UnsupportedVersion(event.version));
        }
        if event.network_id != self.network_id {
            return Err(TreatError::WrongNetwork {
                expected: self.network_id.clone(),
                got: event.network_id.clone(),
            });
        }
        let known = self.accounts.contains_key(&event.subject);
        if !known && self.accounts.len() >= self.max_subjects {
            return Err(TreatError::SubjectLimit {
                cap: self.max_subjects,
            });
        }
        let current = self
            .accounts
            .get(&event.subject)
            .cloned()
            .unwrap_or_default();
        if event.prev != current.accumulator {
            return Err(TreatError::ChainBroken {
                subject: event.subject,
            });
        }
        let minted = event
            .mint_amount()
            .checked_add(extra)
            .ok_or(TreatError::Overflow)?;
        self.check_caps(&event.subject, minted)?;
        {
            let ring = self.sources.entry(event.subject).or_default();
            if ring.contains(&event.source) {
                return Err(TreatError::DuplicateSource {
                    source: event.source,
                });
            }
            if ring.len() >= MAX_TRACKED_SOURCES {
                ring.pop_front();
            }
            ring.push_back(event.source);
        }

        let event_id = event.event_id();
        let acc = {
            let mut w = Writer::with_capacity(64);
            w.raw(&current.accumulator).fixed(&event_id);
            sha256_dom(DOM_TREAT_ACC, &[w.as_slice()])
        };
        let (balance, lifetime_earned, streak, repeats, events) = match event.kind {
            TreatKind::DisputeLost => {
                // Slash to zero: fraud forfeits Treats.
                (
                    0,
                    current.lifetime_earned,
                    0,
                    current.repeats,
                    current.events.checked_add(1).ok_or(TreatError::Overflow)?,
                )
            }
            _ => {
                let balance = current
                    .balance
                    .checked_add(minted)
                    .ok_or(TreatError::Overflow)?;
                let lifetime_earned = current
                    .lifetime_earned
                    .checked_add(minted)
                    .ok_or(TreatError::Overflow)?;
                let events = current.events.checked_add(1).ok_or(TreatError::Overflow)?;
                (
                    balance,
                    lifetime_earned,
                    event.streak,
                    current.repeats,
                    events,
                )
            }
        };
        if event.kind == TreatKind::DisputeLost {
            self.outstanding = self.outstanding.saturating_sub(current.balance);
        } else {
            self.outstanding = self
                .outstanding
                .checked_add(minted)
                .ok_or(TreatError::Overflow)?;
        }
        let next = TreatAccount {
            accumulator: acc,
            balance,
            lifetime_earned,
            lifetime_redeemed: current.lifetime_redeemed,
            streak,
            repeats,
            last_kind: Some(event.kind),
            last_height: event.height.max(current.last_height),
            events,
        };
        self.accounts.insert(event.subject, next.clone());
        Ok(AppliedTreat {
            event: event.clone(),
            event_id,
            minted,
            balance: next.balance,
        })
    }

    /// Commit a ledger-built event. Refusals mutate nothing.
    /// Only the node's verified-artifact paths may call this; there is no
    /// API route that accepts caller-built events.
    pub fn commit(&mut self, event: &TreatEvent) -> Result<AppliedTreat, TreatError> {
        self.apply_mint(event, 0)
    }

    /// Commit with a capped fee-proportional bonus for verified spend.
    pub fn commit_with_fee(
        &mut self,
        event: &TreatEvent,
        fee_sat: u64,
    ) -> Result<AppliedTreat, TreatError> {
        self.apply_mint(event, fee_bonus(fee_sat))
    }

    /// Claim VerifiedWork Treats for a settled task whose VWC the node
    /// holds. `cert_id` is the VWC id (source-once); `payment_sat` prices
    /// the fee bonus. Refusals mutate nothing.
    pub fn claim_verified_work(
        &mut self,
        task_id: Hash,
        cert_id: Hash,
        worker: AgentId,
        payment_sat: u64,
        height: u64,
    ) -> Result<AppliedTreat, TreatError> {
        if self.claimed_tasks.contains(&task_id) {
            return Err(TreatError::AlreadyClaimed);
        }
        let event = self.event_for(worker, TreatKind::VerifiedWork, height, cert_id)?;
        let applied = self.apply_mint(&event, fee_bonus(payment_sat))?;
        self.claimed_tasks.insert(task_id);
        Ok(applied)
    }

    /// Verify a signature bundle against the key bundle for `actor` over `msg`.
    pub fn verify_cert_sig(
        keys: &crate::sig::Bundle,
        sigs: &crate::sig::Bundle,
        actor: &Address,
        msg: &Hash,
    ) -> Result<(), TreatError> {
        let addr = keys
            .address()
            .map_err(|_| TreatError::BadSignature("bad key bundle"))?;
        if &addr != actor {
            return Err(TreatError::BadSignature("signer is not the named actor"));
        }
        crate::sig::verify_bundle(sigs, keys, msg)
            .map_err(|_| TreatError::BadSignature("bundle verify failed"))
    }

    fn check_cert_window(&self, expiry_height: u64, height: u64) -> Result<(), TreatError> {
        if expiry_height <= height {
            return Err(TreatError::Expired);
        }
        if expiry_height > height.saturating_add(TREAT_CERT_MAX_LIFETIME) {
            return Err(TreatError::Expired);
        }
        Ok(())
    }

    /// Apply an owner-signed gift. The giver's key signs; anyone may relay.
    pub fn apply_gift(
        &mut self,
        cert: &GiftCertificate,
        keys: &crate::sig::Bundle,
        sigs: &crate::sig::Bundle,
        height: u64,
    ) -> Result<u64, TreatError> {
        if cert.network_id != self.network_id {
            return Err(TreatError::WrongNetwork {
                expected: self.network_id.clone(),
                got: cert.network_id.clone(),
            });
        }
        if cert.amount == 0 || cert.amount > MAX_GIFT_AMOUNT {
            return Err(TreatError::BadAmount);
        }
        if cert.nonce == 0 {
            return Err(TreatError::NonceReuse);
        }
        self.check_cert_window(cert.expiry_height, height)?;
        Self::verify_cert_sig(keys, sigs, &cert.giver, &cert.signing_hash())?;
        let last = self.giver_nonces.get(&cert.giver).copied().unwrap_or(0);
        if cert.nonce <= last {
            return Err(TreatError::NonceReuse);
        }
        let known = self.accounts.contains_key(&cert.recipient);
        if !known && self.accounts.len() >= self.max_subjects {
            return Err(TreatError::SubjectLimit {
                cap: self.max_subjects,
            });
        }
        self.check_caps(&cert.recipient, cert.amount)?;
        self.giver_nonces.insert(cert.giver, cert.nonce);
        let mut acc = self
            .accounts
            .get(&cert.recipient)
            .cloned()
            .unwrap_or_default();
        acc.balance = acc
            .balance
            .checked_add(cert.amount)
            .ok_or(TreatError::Overflow)?;
        acc.lifetime_earned = acc
            .lifetime_earned
            .checked_add(cert.amount)
            .ok_or(TreatError::Overflow)?;
        acc.last_height = height.max(acc.last_height);
        acc.events = acc.events.checked_add(1).ok_or(TreatError::Overflow)?;
        self.accounts.insert(cert.recipient, acc);
        self.outstanding = self
            .outstanding
            .checked_add(cert.amount)
            .ok_or(TreatError::Overflow)?;
        Ok(self.balance(&cert.recipient))
    }

    /// Apply a sender-signed transfer between holders.
    pub fn apply_transfer(
        &mut self,
        cert: &TransferCertificate,
        keys: &crate::sig::Bundle,
        sigs: &crate::sig::Bundle,
        height: u64,
    ) -> Result<(u64, u64), TreatError> {
        if cert.network_id != self.network_id {
            return Err(TreatError::WrongNetwork {
                expected: self.network_id.clone(),
                got: cert.network_id.clone(),
            });
        }
        if cert.amount == 0 || cert.amount > MAX_TRANSFER_AMOUNT {
            return Err(TreatError::BadAmount);
        }
        if cert.nonce == 0 {
            return Err(TreatError::NonceReuse);
        }
        self.check_cert_window(cert.expiry_height, height)?;
        Self::verify_cert_sig(keys, sigs, &cert.sender, &cert.signing_hash())?;
        let last = self.sender_nonces.get(&cert.sender).copied().unwrap_or(0);
        if cert.nonce <= last {
            return Err(TreatError::NonceReuse);
        }
        let sender_bal = self.balance(&cert.sender_subject);
        if sender_bal < cert.amount {
            return Err(TreatError::InsufficientBalance {
                have: sender_bal,
                want: cert.amount,
            });
        }
        let recipient_known = self.accounts.contains_key(&cert.recipient);
        if !recipient_known && self.accounts.len() >= self.max_subjects {
            return Err(TreatError::SubjectLimit {
                cap: self.max_subjects,
            });
        }
        // Cap check on the recipient before mutating anything.
        let r_have = self.balance(&cert.recipient);
        if r_have
            .checked_add(cert.amount)
            .map(|b| b > MAX_TREAT_BALANCE_PER_AGENT)
            .unwrap_or(true)
        {
            // Self-transfer only needs the balance to already fit, which it
            // does by construction — skip the cap trip for that case.
            if cert.sender_subject != cert.recipient {
                return Err(TreatError::CapExceeded);
            }
        }
        self.sender_nonces.insert(cert.sender, cert.nonce);
        if cert.sender_subject != cert.recipient {
            {
                let mut s = self
                    .accounts
                    .get(&cert.sender_subject)
                    .cloned()
                    .unwrap_or_default();
                s.balance -= cert.amount;
                s.last_height = height.max(s.last_height);
                self.accounts.insert(cert.sender_subject, s);
            }
            {
                let mut r = self
                    .accounts
                    .get(&cert.recipient)
                    .cloned()
                    .unwrap_or_default();
                r.balance = r
                    .balance
                    .checked_add(cert.amount)
                    .ok_or(TreatError::Overflow)?;
                r.lifetime_earned = r
                    .lifetime_earned
                    .checked_add(cert.amount)
                    .ok_or(TreatError::Overflow)?;
                r.last_height = height.max(r.last_height);
                self.accounts.insert(cert.recipient, r);
            }
        }
        Ok((
            self.balance(&cert.sender_subject),
            self.balance(&cert.recipient),
        ))
    }

    /// Whether another voucher can be safely issued without mutating state.
    pub fn can_issue_voucher(&self) -> bool {
        self.vouchers.len() < MAX_VOUCHERS && self.voucher_seq < u64::MAX
    }

    /// Last accepted redemption nonce for a Treats subject.
    pub fn redeem_nonce(&self, subject: &AgentId) -> u64 {
        self.redeem_nonces.get(subject).copied().unwrap_or(0)
    }

    /// Record a redemption nonce after the burn and voucher have committed.
    /// Nonces are strictly increasing and persist across restarts.
    pub fn record_redeem_nonce(&mut self, subject: AgentId, nonce: u64) -> Result<(), TreatError> {
        if nonce == 0 || nonce <= self.redeem_nonce(&subject) {
            return Err(TreatError::NonceReuse);
        }
        self.redeem_nonces.insert(subject, nonce);
        Ok(())
    }

    /// Burn `treats` from `subject` for redemption. Returns the burned amount.
    pub fn burn_for_redeem(&mut self, subject: &AgentId, treats: u64) -> Result<u64, TreatError> {
        if treats == 0 {
            return Err(TreatError::BadAmount);
        }
        let mut acc = self.accounts.get(subject).cloned().unwrap_or_default();
        if acc.balance < treats {
            return Err(TreatError::InsufficientBalance {
                have: acc.balance,
                want: treats,
            });
        }
        acc.balance -= treats;
        acc.lifetime_redeemed = acc
            .lifetime_redeemed
            .checked_add(treats)
            .ok_or(TreatError::Overflow)?;
        self.accounts.insert(*subject, acc);
        self.outstanding = self.outstanding.saturating_sub(treats);
        Ok(treats)
    }

    /// Mint a single-use redemption voucher after the burn + reserve debit.
    pub fn issue_voucher(
        &mut self,
        network_id: &str,
        recipient: AgentId,
        value_sat: u64,
        kind: VoucherKind,
        height: u64,
    ) -> Result<TreatVoucher, TreatError> {
        if value_sat == 0 {
            return Err(TreatError::BadAmount);
        }
        if self.vouchers.len() >= MAX_VOUCHERS {
            return Err(TreatError::Malformed("voucher book is full"));
        }
        let seq = self.voucher_seq;
        let next_seq = self
            .voucher_seq
            .checked_add(1)
            .ok_or(TreatError::Overflow)?;
        let expiry_height = height.saturating_add(VOUCHER_LIFETIME_BLOCKS);
        let mut w = Writer::with_capacity(128);
        w.raw(network_id.as_bytes())
            .fixed(&recipient)
            .u64le(value_sat)
            .u8(kind.as_u8())
            .u64le(expiry_height)
            .u64le(seq);
        let id = sha256_dom(DOM_TREAT_VOUCHER, &[w.as_slice()]);
        let v = TreatVoucher {
            id,
            network_id: network_id.to_string(),
            recipient,
            value_sat,
            kind,
            expiry_height,
        };
        self.voucher_seq = next_seq;
        self.vouchers.insert(id, v.clone());
        Ok(v)
    }

    /// Consume a voucher exactly once. Returns its sat value.
    /// Read-only voucher validation shared by preview and burn, so the two
    /// can never disagree about what counts as usable.
    fn voucher_valid(
        &self,
        id: &Hash,
        height: u64,
        want: Option<VoucherKind>,
    ) -> Result<TreatVoucher, TreatError> {
        let v = self
            .vouchers
            .get(id)
            .cloned()
            .ok_or(TreatError::UnknownVoucher)?;
        if self.consumed.contains(id) {
            return Err(TreatError::VoucherConsumed);
        }
        if height > v.expiry_height {
            return Err(TreatError::VoucherExpired);
        }
        if let Some(k) = want {
            if v.kind != k {
                return Err(TreatError::KindMismatch);
            }
        }
        Ok(v)
    }

    /// What a voucher would cover, without burning it. The recipient is
    /// part of the check: a voucher names its beneficiary, and naming
    /// someone else's voucher id must not spend their discount.
    pub fn voucher_cover(
        &self,
        id: &Hash,
        height: u64,
        want: Option<VoucherKind>,
        recipient: &AgentId,
    ) -> Result<u64, TreatError> {
        let v = self.voucher_valid(id, height, want)?;
        if v.recipient != *recipient {
            return Err(TreatError::WrongRecipient);
        }
        Ok(v.value_sat)
    }

    pub fn consume_voucher(
        &mut self,
        id: &Hash,
        height: u64,
        want: Option<VoucherKind>,
        recipient: &AgentId,
    ) -> Result<u64, TreatError> {
        let voucher = self.voucher_valid(id, height, want)?;
        if voucher.recipient != *recipient {
            return Err(TreatError::WrongRecipient);
        }
        self.consumed.insert(*id);
        Ok(voucher.value_sat)
    }

    /// Encode for `state.bin` persistence (trailing section, versioned v2).
    /// The per-subject source ring stays runtime-only; receipt acceptance
    /// (persisted `ReceiptBook`) and `claimed_tasks` are the restart-safe
    /// replay guards for the two mint paths.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128 + self.accounts.len() * 80);
        w.u8(TREATS_VERSION);
        w.u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes());
        w.u64le(self.outstanding);
        w.u32le(self.accounts.len() as u32);
        for (id, a) in &self.accounts {
            w.fixed(id)
                .fixed(&a.accumulator)
                .u64le(a.balance)
                .u64le(a.lifetime_earned)
                .u64le(a.lifetime_redeemed)
                .u32le(a.streak)
                .u32le(a.repeats)
                .u8(a.last_kind.map(|k| k.as_u8()).unwrap_or(255))
                .u64le(a.last_height)
                .u64le(a.events);
        }
        w.u32le(self.giver_nonces.len() as u32);
        for (addr, n) in &self.giver_nonces {
            w.fixed(addr).u64le(*n);
        }
        w.u32le(self.sender_nonces.len() as u32);
        for (addr, n) in &self.sender_nonces {
            w.fixed(addr).u64le(*n);
        }
        w.u32le(self.redeem_nonces.len() as u32);
        for (agent, n) in &self.redeem_nonces {
            w.fixed(agent).u64le(*n);
        }
        w.u32le(self.claimed_tasks.len() as u32);
        for h in &self.claimed_tasks {
            w.fixed(h);
        }
        w.u64le(self.voucher_seq);
        w.u32le(self.vouchers.len() as u32);
        for v in self.vouchers.values() {
            w.fixed(&v.id)
                .u16le(v.network_id.len() as u16)
                .raw(v.network_id.as_bytes())
                .fixed(&v.recipient)
                .u64le(v.value_sat)
                .u8(v.kind.as_u8())
                .u64le(v.expiry_height);
        }
        w.u32le(self.consumed.len() as u32);
        for h in &self.consumed {
            w.fixed(h);
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreatError> {
        let mut r = Reader::new(bytes);
        let l = Self::decode_reader(&mut r)?;
        r.expect_end()
            .map_err(|_| TreatError::Malformed("trailing"))?;
        Ok(l)
    }

    pub fn decode_reader(r: &mut Reader) -> Result<Self, TreatError> {
        let v = r.u8().map_err(|_| TreatError::Malformed("version"))?;
        // v1 (accounts only), v2 (full book), v3 (last-kind), v4 (redemption nonces).
        if !(1..=TREATS_VERSION).contains(&v) {
            return Err(TreatError::UnsupportedVersion(v));
        }
        let n = r
            .u16le()
            .map_err(|_| TreatError::Malformed("network len"))? as usize;
        if n == 0 || n > MAX_TREAT_NETWORK_ID_LEN {
            return Err(TreatError::BadNetworkId(n));
        }
        let nb = r
            .fixed_slice(n)
            .map_err(|_| TreatError::Malformed("network"))?;
        let network_id = std::str::from_utf8(nb)
            .map_err(|_| TreatError::Malformed("network utf8"))?
            .to_string();
        let outstanding = r
            .u64le()
            .map_err(|_| TreatError::Malformed("outstanding"))?;
        let count = r.u32le().map_err(|_| TreatError::Malformed("count"))? as usize;
        if count > DEFAULT_MAX_SUBJECTS {
            return Err(TreatError::SubjectLimit {
                cap: DEFAULT_MAX_SUBJECTS,
            });
        }
        if outstanding > MAX_TREAT_OUTSTANDING {
            return Err(TreatError::Malformed("outstanding over cap"));
        }
        let mut ledger = TreatLedger::with_capacity(network_id, DEFAULT_MAX_SUBJECTS);
        ledger.outstanding = outstanding;
        // Every mint/gift path credits `outstanding` alongside the balance
        // it creates, and every burn/slash debits both together, so the
        // outstanding supply always covers the account balances. A blob
        // claiming less (crafted small to inflate `redeem_quote` payouts
        // against the chain reserve) or more than the cap refuses here
        // instead of poisoning the node that loads it.
        let mut balance_sum = 0u64;
        for _ in 0..count {
            let id = r.fixed::<20>().map_err(|_| TreatError::Malformed("id"))?;
            let accumulator = r.fixed::<32>().map_err(|_| TreatError::Malformed("acc"))?;
            let balance = r.u64le().map_err(|_| TreatError::Malformed("balance"))?;
            let lifetime_earned = r.u64le().map_err(|_| TreatError::Malformed("earned"))?;
            let lifetime_redeemed = r.u64le().map_err(|_| TreatError::Malformed("redeemed"))?;
            let streak = r.u32le().map_err(|_| TreatError::Malformed("streak"))?;
            let repeats = r.u32le().map_err(|_| TreatError::Malformed("repeats"))?;
            // v3+ carries the last event kind; older blobs predate novelty
            // tracking and decode with it unset (full novelty — the safe
            // direction, never a surprise penalty).
            let last_kind = if v >= 3 {
                match r.u8().map_err(|_| TreatError::Malformed("last_kind"))? {
                    255 => None,
                    b => Some(TreatKind::from_u8(b).ok_or(TreatError::Malformed("last_kind"))?),
                }
            } else {
                None
            };
            let last_height = r.u64le().map_err(|_| TreatError::Malformed("height"))?;
            let events = r.u64le().map_err(|_| TreatError::Malformed("events"))?;
            balance_sum = balance_sum
                .checked_add(balance)
                .ok_or(TreatError::Malformed("balances overflow"))?;
            if balance_sum > outstanding {
                return Err(TreatError::Malformed("outstanding below account balances"));
            }
            ledger.accounts.insert(
                id,
                TreatAccount {
                    accumulator,
                    balance,
                    lifetime_earned,
                    lifetime_redeemed,
                    streak,
                    repeats,
                    last_kind,
                    last_height,
                    events,
                },
            );
        }
        if v == 1 {
            // Legacy envelope: no nonce guards, claims, or vouchers.
            r.expect_end()
                .map_err(|_| TreatError::Malformed("trailing"))?;
            return Ok(ledger);
        }
        let g = r
            .u32le()
            .map_err(|_| TreatError::Malformed("giver nonces"))? as usize;
        if g > DEFAULT_MAX_SUBJECTS {
            return Err(TreatError::SubjectLimit {
                cap: DEFAULT_MAX_SUBJECTS,
            });
        }
        for _ in 0..g {
            let addr = r
                .fixed::<20>()
                .map_err(|_| TreatError::Malformed("giver"))?;
            let nonce = r
                .u64le()
                .map_err(|_| TreatError::Malformed("giver nonce"))?;
            ledger.giver_nonces.insert(addr, nonce);
        }
        let s = r
            .u32le()
            .map_err(|_| TreatError::Malformed("sender nonces"))? as usize;
        if s > DEFAULT_MAX_SUBJECTS {
            return Err(TreatError::SubjectLimit {
                cap: DEFAULT_MAX_SUBJECTS,
            });
        }
        for _ in 0..s {
            let addr = r
                .fixed::<20>()
                .map_err(|_| TreatError::Malformed("sender"))?;
            let nonce = r
                .u64le()
                .map_err(|_| TreatError::Malformed("sender nonce"))?;
            ledger.sender_nonces.insert(addr, nonce);
        }
        if v == 2 || v == 3 {
            let c = r.u32le().map_err(|_| TreatError::Malformed("claimed"))? as usize;
            if c > 1 << 20 {
                return Err(TreatError::Malformed("claimed over cap"));
            }
            for _ in 0..c {
                let h = r
                    .fixed::<32>()
                    .map_err(|_| TreatError::Malformed("claimed id"))?;
                ledger.claimed_tasks.insert(h);
            }
            ledger.voucher_seq = r
                .u64le()
                .map_err(|_| TreatError::Malformed("voucher seq"))?;
            let vc = r.u32le().map_err(|_| TreatError::Malformed("vouchers"))? as usize;
            if vc > MAX_VOUCHERS {
                return Err(TreatError::Malformed("vouchers over cap"));
            }
            for _ in 0..vc {
                let id = r
                    .fixed::<32>()
                    .map_err(|_| TreatError::Malformed("voucher id"))?;
                let nl = r
                    .u16le()
                    .map_err(|_| TreatError::Malformed("voucher net len"))?
                    as usize;
                if nl == 0 || nl > MAX_TREAT_NETWORK_ID_LEN {
                    return Err(TreatError::BadNetworkId(nl));
                }
                let network_id = std::str::from_utf8(
                    r.fixed_slice(nl)
                        .map_err(|_| TreatError::Malformed("voucher net"))?,
                )
                .map_err(|_| TreatError::Malformed("voucher net utf8"))?
                .to_string();
                let recipient = r
                    .fixed::<20>()
                    .map_err(|_| TreatError::Malformed("voucher recipient"))?;
                let value_sat = r
                    .u64le()
                    .map_err(|_| TreatError::Malformed("voucher value"))?;
                let kind = VoucherKind::from_u8(
                    r.u8().map_err(|_| TreatError::Malformed("voucher kind"))?,
                )
                .ok_or(TreatError::Malformed("voucher kind range"))?;
                let expiry_height = r
                    .u64le()
                    .map_err(|_| TreatError::Malformed("voucher expiry"))?;
                ledger.vouchers.insert(
                    id,
                    TreatVoucher {
                        id,
                        network_id,
                        recipient,
                        value_sat,
                        kind,
                        expiry_height,
                    },
                );
            }
            let cc = r.u32le().map_err(|_| TreatError::Malformed("consumed"))? as usize;
            if cc > MAX_VOUCHERS {
                return Err(TreatError::Malformed("consumed over cap"));
            }
            for _ in 0..cc {
                let h = r
                    .fixed::<32>()
                    .map_err(|_| TreatError::Malformed("consumed id"))?;
                ledger.consumed.insert(h);
            }
            r.expect_end()
                .map_err(|_| TreatError::Malformed("trailing"))?;
            return Ok(ledger);
        }
        if v >= 4 {
            let rn = r
                .u32le()
                .map_err(|_| TreatError::Malformed("redeem nonces"))? as usize;
            if rn > DEFAULT_MAX_SUBJECTS {
                return Err(TreatError::SubjectLimit {
                    cap: DEFAULT_MAX_SUBJECTS,
                });
            }
            for _ in 0..rn {
                let agent = r
                    .fixed::<20>()
                    .map_err(|_| TreatError::Malformed("redeem agent"))?;
                let nonce = r
                    .u64le()
                    .map_err(|_| TreatError::Malformed("redeem nonce"))?;
                if nonce == 0 || ledger.redeem_nonces.insert(agent, nonce).is_some() {
                    return Err(TreatError::Malformed("duplicate or zero redeem nonce"));
                }
            }
        }
        let c = r.u32le().map_err(|_| TreatError::Malformed("claimed"))? as usize;
        if c > 1 << 20 {
            return Err(TreatError::Malformed("claimed over cap"));
        }
        for _ in 0..c {
            let h = r
                .fixed::<32>()
                .map_err(|_| TreatError::Malformed("claimed id"))?;
            ledger.claimed_tasks.insert(h);
        }
        ledger.voucher_seq = r
            .u64le()
            .map_err(|_| TreatError::Malformed("voucher seq"))?;
        let vc = r.u32le().map_err(|_| TreatError::Malformed("vouchers"))? as usize;
        if vc > MAX_VOUCHERS {
            return Err(TreatError::Malformed("vouchers over cap"));
        }
        for _ in 0..vc {
            let id = r
                .fixed::<32>()
                .map_err(|_| TreatError::Malformed("voucher id"))?;
            let nl = r
                .u16le()
                .map_err(|_| TreatError::Malformed("voucher net len"))?
                as usize;
            if nl == 0 || nl > MAX_TREAT_NETWORK_ID_LEN {
                return Err(TreatError::BadNetworkId(nl));
            }
            let nb = r
                .fixed_slice(nl)
                .map_err(|_| TreatError::Malformed("voucher net"))?;
            let network_id = std::str::from_utf8(nb)
                .map_err(|_| TreatError::Malformed("voucher net utf8"))?
                .to_string();
            let recipient = r
                .fixed::<20>()
                .map_err(|_| TreatError::Malformed("voucher recipient"))?;
            let value_sat = r
                .u64le()
                .map_err(|_| TreatError::Malformed("voucher value"))?;
            let kind =
                VoucherKind::from_u8(r.u8().map_err(|_| TreatError::Malformed("voucher kind"))?)
                    .ok_or(TreatError::Malformed("voucher kind range"))?;
            let expiry_height = r
                .u64le()
                .map_err(|_| TreatError::Malformed("voucher expiry"))?;
            ledger.vouchers.insert(
                id,
                TreatVoucher {
                    id,
                    network_id,
                    recipient,
                    value_sat,
                    kind,
                    expiry_height,
                },
            );
        }
        let cc = r.u32le().map_err(|_| TreatError::Malformed("consumed"))? as usize;
        if cc > MAX_VOUCHERS {
            return Err(TreatError::Malformed("consumed over cap"));
        }
        for _ in 0..cc {
            let h = r
                .fixed::<32>()
                .map_err(|_| TreatError::Malformed("consumed id"))?;
            ledger.consumed.insert(h);
        }
        r.expect_end()
            .map_err(|_| TreatError::Malformed("trailing"))?;
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2::Auth;
    use crate::wallet::Wallet;

    const NET: &str = "srct/testnet";

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_private_key_bytes(&[seed; 32], "treats-test").expect("key")
    }

    #[test]
    fn weights_are_fixed_and_loss_slashes() {
        assert_eq!(TreatKind::VerifiedWork.base(), 20);
        assert_eq!(TreatKind::ServiceCompleted.base(), 5);
        assert_eq!(TreatKind::DisputeWon.base(), 10);
        assert_eq!(TreatKind::DisputeLost.base(), 0);
    }

    #[test]
    fn treat_cut_is_ten_percent_of_pscb_with_cap() {
        assert_eq!(treat_cut_default(1_000), 100);
        assert_eq!(treat_cut_default(1), 0);
        assert!(treat_cut(1_000, 2_001).is_none());
        let (retained, t) = split_pscb_for_treats(1_000);
        assert_eq!(retained + t, 1_000);
    }

    #[test]
    fn redeem_quote_is_proportional_and_floored() {
        assert_eq!(redeem_quote(10, 1_000, 100), Some(100));
        assert_eq!(redeem_quote(0, 1_000, 100), Some(0));
        assert_eq!(redeem_quote(10, 0, 100), Some(0));
        assert_eq!(redeem_quote(10, 1_000, 0), Some(0));
    }

    #[test]
    fn fee_bonus_is_capped() {
        assert_eq!(fee_bonus(0), 0);
        assert_eq!(fee_bonus(999), 0);
        assert_eq!(fee_bonus(5_000), 5);
        assert_eq!(fee_bonus(1_000_000), FEE_BONUS_CAP);
    }

    #[test]
    fn commit_applies_caps_and_fee_bonus() {
        let mut l = TreatLedger::new(NET);
        let ev = l
            .event_for([1u8; 20], TreatKind::VerifiedWork, 10, [2u8; 32])
            .unwrap();
        let base = ev.mint_amount();
        let applied = l.commit_with_fee(&ev, 5_000).unwrap();
        assert_eq!(applied.minted, base + 5);
        // Source replay refused.
        assert!(matches!(
            l.commit(&ev),
            Err(TreatError::ChainBroken { .. } | TreatError::DuplicateSource { .. })
        ));
    }

    #[test]
    fn per_agent_and_global_caps_refuse() {
        let mut l = TreatLedger::with_capacity(NET, 8);
        // Fill one holder to its ceiling via gifts.
        let giver = wallet(40);
        let giver_addr = giver.address().unwrap();
        let mut nonce = 1u64;
        let recipient = [9u8; 20];
        let mut total = 0u64;
        while total + MAX_GIFT_AMOUNT <= MAX_TREAT_BALANCE_PER_AGENT {
            let cert = GiftCertificate {
                network_id: NET.into(),
                giver: giver_addr,
                recipient,
                amount: MAX_GIFT_AMOUNT,
                nonce,
                expiry_height: 5_000,
            };
            let auth = Auth::sign(&giver, &cert.signing_hash()).unwrap();
            l.apply_gift(&cert, &auth.keys, &auth.sigs, 10).unwrap();
            total += MAX_GIFT_AMOUNT;
            nonce += 1;
        }
        assert_eq!(l.balance(&recipient), total);
        let cert = GiftCertificate {
            network_id: NET.into(),
            giver: giver_addr,
            recipient,
            amount: 1,
            nonce,
            expiry_height: 5_000,
        };
        let auth = Auth::sign(&giver, &cert.signing_hash()).unwrap();
        assert_eq!(
            l.apply_gift(&cert, &auth.keys, &auth.sigs, 10),
            Err(TreatError::CapExceeded)
        );
    }

    #[test]
    fn gifts_need_owner_signature_fresh_nonce_and_window() {
        let mut l = TreatLedger::new(NET);
        let giver = wallet(41);
        let other = wallet(42);
        let giver_addr = giver.address().unwrap();
        let cert = GiftCertificate {
            network_id: NET.into(),
            giver: giver_addr,
            recipient: [3u8; 20],
            amount: 100,
            nonce: 1,
            expiry_height: 500,
        };
        // Wrong signer refused.
        let bad = Auth::sign(&other, &cert.signing_hash()).unwrap();
        assert!(matches!(
            l.apply_gift(&cert, &bad.keys, &bad.sigs, 10),
            Err(TreatError::BadSignature(_))
        ));
        let auth = Auth::sign(&giver, &cert.signing_hash()).unwrap();
        // Expired refused.
        assert_eq!(
            l.apply_gift(&cert, &auth.keys, &auth.sigs, 600),
            Err(TreatError::Expired)
        );
        // Past max lifetime refused.
        let far = GiftCertificate {
            expiry_height: 10 + TREAT_CERT_MAX_LIFETIME + 1,
            ..cert.clone()
        };
        let far_auth = Auth::sign(&giver, &far.signing_hash()).unwrap();
        assert_eq!(
            l.apply_gift(&far, &far_auth.keys, &far_auth.sigs, 10),
            Err(TreatError::Expired)
        );
        // Good gift applies.
        assert_eq!(
            l.apply_gift(&cert, &auth.keys, &auth.sigs, 10).unwrap(),
            100
        );
        // Replay refused.
        assert_eq!(
            l.apply_gift(&cert, &auth.keys, &auth.sigs, 11),
            Err(TreatError::NonceReuse)
        );
        // Over-cap gift refused.
        let big = GiftCertificate {
            amount: MAX_GIFT_AMOUNT + 1,
            nonce: 2,
            ..cert.clone()
        };
        let big_auth = Auth::sign(&giver, &big.signing_hash()).unwrap();
        assert_eq!(
            l.apply_gift(&big, &big_auth.keys, &big_auth.sigs, 11),
            Err(TreatError::BadAmount)
        );
    }

    #[test]
    fn transfers_move_claims_with_sender_signature() {
        let mut l = TreatLedger::new(NET);
        let sender_w = wallet(43);
        let sender_addr = sender_w.address().unwrap();
        let sender_sub =
            crate::agent::derive_agent_id(NET, crate::agent::AgentRole::Machine, &sender_addr);
        // Fund the sender via gift.
        let giver = wallet(44);
        let giver_addr = giver.address().unwrap();
        let fund = GiftCertificate {
            network_id: NET.into(),
            giver: giver_addr,
            recipient: sender_sub,
            amount: 500,
            nonce: 1,
            expiry_height: 5_000,
        };
        let fa = Auth::sign(&giver, &fund.signing_hash()).unwrap();
        l.apply_gift(&fund, &fa.keys, &fa.sigs, 10).unwrap();
        let recipient = [8u8; 20];
        let cert = TransferCertificate {
            network_id: NET.into(),
            sender: sender_addr,
            sender_subject: sender_sub,
            recipient,
            amount: 200,
            nonce: 1,
            expiry_height: 5_000,
        };
        let auth = Auth::sign(&sender_w, &cert.signing_hash()).unwrap();
        let (s, r) = l.apply_transfer(&cert, &auth.keys, &auth.sigs, 11).unwrap();
        assert_eq!((s, r), (300, 200));
        // Replay refused; overspend refused.
        assert_eq!(
            l.apply_transfer(&cert, &auth.keys, &auth.sigs, 12),
            Err(TreatError::NonceReuse)
        );
        let over = TransferCertificate {
            amount: 10_000,
            nonce: 2,
            ..cert.clone()
        };
        let oa = Auth::sign(&sender_w, &over.signing_hash()).unwrap();
        assert!(matches!(
            l.apply_transfer(&over, &oa.keys, &oa.sigs, 12),
            Err(TreatError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn claim_work_needs_a_fresh_task() {
        let mut l = TreatLedger::new(NET);
        let worker = [6u8; 20];
        let a = l
            .claim_verified_work([1u8; 32], [2u8; 32], worker, 3_000, 20)
            .unwrap();
        assert!(a.minted >= TreatKind::VerifiedWork.base());
        assert_eq!(
            l.claim_verified_work([1u8; 32], [2u8; 32], worker, 3_000, 21),
            Err(TreatError::AlreadyClaimed)
        );
    }

    #[test]
    fn vouchers_are_single_use_and_expire() {
        let mut l = TreatLedger::new(NET);
        let v = l
            .issue_voucher(NET, [7u8; 20], 900, VoucherKind::Trial, 100)
            .unwrap();
        assert_eq!(l.voucher_liability(100), 900);
        assert_eq!(
            l.consume_voucher(&v.id, 101, Some(VoucherKind::Trial), &[8u8; 20]),
            Err(TreatError::WrongRecipient)
        );
        assert_eq!(l.voucher_liability(101), 900);
        assert_eq!(
            l.consume_voucher(&v.id, 101, Some(VoucherKind::Trial), &[7u8; 20])
                .unwrap(),
            900
        );
        assert_eq!(
            l.consume_voucher(&v.id, 102, Some(VoucherKind::Trial), &[7u8; 20]),
            Err(TreatError::VoucherConsumed)
        );
        assert_eq!(l.voucher_liability(102), 0);
        let v2 = l
            .issue_voucher(NET, [7u8; 20], 100, VoucherKind::Trial, 100)
            .unwrap();
        assert_eq!(
            l.consume_voucher(&v2.id, 101, Some(VoucherKind::FeeCredit), &[7u8; 20]),
            Err(TreatError::KindMismatch)
        );
        assert_eq!(
            l.consume_voucher(&v2.id, 10_000, None, &[7u8; 20]),
            Err(TreatError::VoucherExpired)
        );
    }

    #[test]
    fn redemption_nonce_survives_a_round_trip_and_replay_is_refused() {
        let mut ledger = TreatLedger::new(NET);
        ledger.record_redeem_nonce([7u8; 20], 3).unwrap();
        assert_eq!(
            ledger.record_redeem_nonce([7u8; 20], 3),
            Err(TreatError::NonceReuse)
        );
        assert_eq!(
            ledger.record_redeem_nonce([7u8; 20], 2),
            Err(TreatError::NonceReuse)
        );
        let bytes = ledger.encode();
        let restored = TreatLedger::decode(&bytes).unwrap();
        assert_eq!(restored.redeem_nonce(&[7u8; 20]), 3);
        assert_eq!(restored.encode(), bytes);
    }

    #[test]
    fn voucher_preview_binds_recipient_and_burns_nothing() {
        // A voucher names its beneficiary: previewing for anyone else
        // refuses, and previewing never consumes — a failed payment must
        // not destroy the discount.
        let mut l = TreatLedger::new(NET);
        let v = l
            .issue_voucher(NET, [7u8; 20], 900, VoucherKind::Trial, 100)
            .unwrap();
        assert_eq!(
            l.voucher_cover(&v.id, 50, Some(VoucherKind::Trial), &[9u8; 20]),
            Err(TreatError::WrongRecipient)
        );
        assert_eq!(
            l.voucher_cover(&v.id, 50, Some(VoucherKind::Trial), &[7u8; 20]),
            Ok(900)
        );
        // Still unconsumed after two previews: the burn happens only in
        // `consume_voucher`, which the node calls after payment verifies.
        assert_eq!(
            l.voucher_cover(&v.id, 50, Some(VoucherKind::Trial), &[7u8; 20]),
            Ok(900)
        );
    }

    #[test]
    fn novelty_damps_consecutive_repeats_and_resets_on_change() {
        // Same kind twice: the second mint pays damped novelty.
        let mut l = TreatLedger::new(NET);
        let e1 = l
            .event_for([3u8; 20], TreatKind::ServiceCompleted, 5, [4u8; 32])
            .unwrap();
        assert_eq!(e1.repeats, 0);
        let m1 = e1.mint_amount();
        l.commit(&e1).unwrap();
        let e2 = l
            .event_for([3u8; 20], TreatKind::ServiceCompleted, 6, [5u8; 32])
            .unwrap();
        assert_eq!(e2.repeats, 1, "same kind again increments");
        assert!(e2.mint_amount() < m1, "novelty damps the repeat");
        l.commit(&e2).unwrap();
        // A different kind resets the run: full novelty again, so the
        // reset mint beats the damped repeat mint.
        let e3 = l
            .event_for([3u8; 20], TreatKind::PaymentCompleted, 7, [6u8; 32])
            .unwrap();
        assert_eq!(e3.repeats, 0, "kind change resets");
        assert!(
            e3.mint_amount() >= e2.mint_amount(),
            "reset restores novelty"
        );
    }

    #[test]
    fn encode_decode_round_trip_v2_and_legacy_v1() {
        let mut l = TreatLedger::new(NET);
        let ev = l
            .event_for([3u8; 20], TreatKind::ServiceCompleted, 5, [4u8; 32])
            .unwrap();
        l.commit(&ev).unwrap();
        let giver = wallet(45);
        let giver_addr = giver.address().unwrap();
        let gift = GiftCertificate {
            network_id: NET.into(),
            giver: giver_addr,
            recipient: [3u8; 20],
            amount: 50,
            nonce: 1,
            expiry_height: 5_000,
        };
        let ga = Auth::sign(&giver, &gift.signing_hash()).unwrap();
        l.apply_gift(&gift, &ga.keys, &ga.sigs, 6).unwrap();
        let v = l
            .issue_voucher(NET, [3u8; 20], 10, VoucherKind::FeeCredit, 6)
            .unwrap();
        let _ = (v,);
        let bytes = l.encode();
        let back = TreatLedger::decode(&bytes).unwrap();
        assert_eq!(back.balance(&[3u8; 20]), l.balance(&[3u8; 20]));
        assert_eq!(back.outstanding(), l.outstanding());
        assert_eq!(back.voucher_liability(6), l.voucher_liability(6));
        // Legacy v1 bytes (accounts only) still decode with empty new stores.
        let mut w = Writer::with_capacity(64);
        w.u8(1);
        w.u16le(NET.len() as u16).raw(NET.as_bytes());
        w.u64le(l.outstanding());
        w.u32le(0);
        let legacy = TreatLedger::decode(&w.into_vec()).unwrap();
        assert_eq!(legacy.outstanding(), l.outstanding());
        assert_eq!(legacy.voucher_liability(6), 0);

        // A v2 blob (accounts without the last-kind byte) decodes with
        // novelty unset: full novelty going forward, never a surprise
        // penalty for pre-tracking balances.
        let mut v2 = Writer::with_capacity(128);
        v2.u8(2);
        v2.u16le(NET.len() as u16).raw(NET.as_bytes());
        v2.u64le(1000);
        v2.u32le(1);
        v2.fixed(&[3u8; 20])
            .fixed(&[9u8; 32])
            .u64le(500)
            .u64le(500)
            .u64le(0)
            .u32le(2)
            .u32le(4)
            .u64le(7)
            .u64le(3);
        v2.u32le(0).u32le(0).u32le(0);
        v2.u64le(0).u32le(0).u32le(0);
        let old = TreatLedger::decode(&v2.into_vec()).unwrap();
        assert_eq!(old.balance(&[3u8; 20]), 500);
        // Full novelty: repeats reset on the next event of any kind.
        let next = old
            .event_for([3u8; 20], TreatKind::ServiceCompleted, 8, [7u8; 32])
            .unwrap();
        assert_eq!(next.repeats, 0, "legacy accounts restart novelty");

        // A forged blob whose outstanding cannot cover its balances
        // refuses instead of loading a drain-ready ledger.
        let mut bad = Writer::with_capacity(128);
        bad.u8(3);
        bad.u16le(NET.len() as u16).raw(NET.as_bytes());
        bad.u64le(10);
        bad.u32le(1);
        bad.fixed(&[3u8; 20])
            .fixed(&[9u8; 32])
            .u64le(500)
            .u64le(500)
            .u64le(0)
            .u32le(0)
            .u32le(0)
            .u8(255)
            .u64le(7)
            .u64le(3);
        bad.u32le(0).u32le(0).u32le(0);
        bad.u64le(0).u32le(0).u32le(0);
        assert!(TreatLedger::decode(&bad.into_vec()).is_err());
    }
}
