//! SRCT Treats: dopamine-inspired reward claims for agents, machines, robots.
//!
//! A third value component alongside liquid SRCT (UTXO) and committed SRCT
//! (L2 escrow): non-transferable incentive claims backed by a sub-ledger of
//! the PSCB fee reserve. Treats are never spendable as UTXOs, never
//! transferable, and mint only from verified work artifacts.
//!
//! Design rules (locked):
//! - **No second currency.** Balances live in a node-local [`TreatLedger`],
//!   like reputation. Consensus only tracks the backing sat reserve
//!   (`Chain::treat_reserve`); redemption burns Treats and pays from it.
//! - **Fixed weight table in code.** An event carries no amount and no weight.
//! - **Source counted once** per subject (bounded ring), accumulator-chained
//!   like reputation, so history cannot be rewritten or replayed.
//! - **Decay.** Balances decay with inactivity so hoarding is pointless and
//!   continued useful work is rewarded (dopamine shaping).
//! - **Integer-only.** No floats anywhere.

use crate::agent::AgentId;
use crate::hash::{sha256_dom, Hash};
use crate::ser::{Reader, Writer};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub const TREATS_VERSION: u8 = 1;
pub const DOM_TREAT_EVENT: &[u8] = b"srct/treat-event/v1";
pub const DOM_TREAT_ACC: &[u8] = b"srct/treat-acc/v1";
pub const MAX_TREAT_NETWORK_ID_LEN: usize = 64;
pub const MAX_TRACKED_SOURCES: usize = 128;
pub const DEFAULT_MAX_SUBJECTS: usize = 8192;
pub const BPS_DENOM: u32 = 10_000;

/// Share of each block's PSCB leg routed to the Treat reserve, in bps.
/// 1000 = 10% of the PSCB half; cap 2000 = 20%.
pub const TREAT_BPS: u32 = 1_000;
pub const TREAT_MAX_BPS: u32 = 2_000;

/// Decay applied on explicit `apply_decay`: `balance * DECAY_BPS / DENOM`
/// per `DECAY_BLOCKS` of inactivity.
pub const TREAT_DECAY_BPS: u64 = 100; // 1%
pub const TREAT_DECAY_BLOCKS: u64 = 1_000;

/// Novelty damping per repeat with the same counterparty: repeats pay less.
pub const NOVELTY_STEP_BPS: u64 = 1_500;
/// Streak bonus per consecutive verified epoch, capped.
pub const STREAK_STEP_BPS: u64 = 500;
pub const STREAK_MAX_BPS: u64 = 5_000;

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

/// What earned the Treats. Discriminant is part of the event id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TreatKind {
    VerifiedWork = 0,
    ServiceCompleted = 1,
    PaymentCompleted = 2,
    DisputeWon = 3,
    DisputeLost = 4,
}

impl TreatKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TreatKind::VerifiedWork),
            1 => Some(TreatKind::ServiceCompleted),
            2 => Some(TreatKind::PaymentCompleted),
            3 => Some(TreatKind::DisputeWon),
            4 => Some(TreatKind::DisputeLost),
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
}

impl fmt::Display for TreatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreatError::Malformed(w) => write!(f, "malformed treat event: {w}"),
            TreatError::UnsupportedVersion(v) => write!(f, "unsupported treats version {v}"),
            TreatError::WrongNetwork { expected, got } => {
                write!(f, "treats ledger is {expected}, event is {got}")
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
    /// Repeats with the same counterparty so far (novelty damping input).
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
        let version = r.u8().map_err(|_| TreatError::Malformed("version"))?;
        if version != TREATS_VERSION {
            return Err(TreatError::UnsupportedVersion(version));
        }
        let net_len = r.u16le().map_err(|_| TreatError::Malformed("network len"))? as usize;
        if net_len == 0 || net_len > MAX_TREAT_NETWORK_ID_LEN {
            return Err(TreatError::BadNetworkId(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| TreatError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| TreatError::Malformed("network id is not utf-8"))?
            .to_string();
        let subject = r.fixed::<20>().map_err(|_| TreatError::Malformed("subject"))?;
        let kind_raw = r.u8().map_err(|_| TreatError::Malformed("kind"))?;
        let kind = TreatKind::from_u8(kind_raw).ok_or(TreatError::Malformed("kind out of range"))?;
        let height = r.u64le().map_err(|_| TreatError::Malformed("height"))?;
        let source = r.fixed::<32>().map_err(|_| TreatError::Malformed("source"))?;
        let prev = r.fixed::<32>().map_err(|_| TreatError::Malformed("prev"))?;
        let repeats = r.u32le().map_err(|_| TreatError::Malformed("repeats"))?;
        let streak = r.u32le().map_err(|_| TreatError::Malformed("streak"))?;
        r.expect_end().map_err(|_| TreatError::Malformed("trailing bytes"))?;
        Ok(TreatEvent { version, network_id, subject, kind, height, source, prev, repeats, streak })
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
        let novelty_bps = (BPS_DENOM as u64).saturating_sub(
            (self.repeats as u64).saturating_mul(NOVELTY_STEP_BPS),
        );
        // Floor novelty at 10% so long-running pairs still earn something.
        let novelty_bps = novelty_bps.max(1_000);
        let streak_bps = ((self.streak as u64).saturating_mul(STREAK_STEP_BPS)).min(STREAK_MAX_BPS);
        let v = base * novelty_bps as u128 * (BPS_DENOM as u128 + streak_bps as u128)
            / (BPS_DENOM as u128 * BPS_DENOM as u128);
        v as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreatAccount {
    pub accumulator: Hash,
    pub balance: u64,
    pub lifetime_earned: u64,
    pub lifetime_redeemed: u64,
    pub streak: u32,
    pub repeats: u32,
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
    sources: BTreeMap<AgentId, VecDeque<Hash>>,
    max_subjects: usize,
    pub outstanding: u64,
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

    pub fn event_for(
        &self,
        subject: AgentId,
        kind: TreatKind,
        height: u64,
        source: Hash,
    ) -> Result<TreatEvent, TreatError> {
        if self.network_id.is_empty() || self.network_id.len() > MAX_TREAT_NETWORK_ID_LEN {
            return Err(TreatError::BadNetworkId(self.network_id.len()));
        }
        let acc = self.accounts.get(&subject);
        let prev = acc.map(|a| a.accumulator).unwrap_or([0u8; 32]);
        let repeats = acc.map(|a| a.repeats).unwrap_or(0);
        let streak = match kind {
            TreatKind::VerifiedWork | TreatKind::ServiceCompleted | TreatKind::DisputeWon => {
                acc.map(|a| a.streak.saturating_add(1)).unwrap_or(1)
            }
            _ => acc.map(|a| a.streak).unwrap_or(0),
        };
        Ok(TreatEvent {
            version: TREATS_VERSION,
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

    /// Commit a ledger-built event. Refusals mutate nothing.
    pub fn commit(&mut self, event: &TreatEvent) -> Result<AppliedTreat, TreatError> {
        if event.version != TREATS_VERSION {
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
            return Err(TreatError::SubjectLimit { cap: self.max_subjects });
        }
        let current = self.accounts.get(&event.subject).cloned().unwrap_or_default();
        if event.prev != current.accumulator {
            return Err(TreatError::ChainBroken { subject: event.subject });
        }
        let ring = self.sources.entry(event.subject).or_default();
        if ring.contains(&event.source) {
            return Err(TreatError::DuplicateSource { source: event.source });
        }
        if ring.len() >= MAX_TRACKED_SOURCES {
            ring.pop_front();
        }
        ring.push_back(event.source);

        let event_id = event.event_id();
        let acc = {
            let mut w = Writer::with_capacity(64);
            w.raw(&current.accumulator).fixed(&event_id);
            sha256_dom(DOM_TREAT_ACC, &[w.as_slice()])
        };
        let minted = event.mint_amount();
        let (balance, lifetime_earned, streak, repeats, events) =
            match event.kind {
                TreatKind::DisputeLost => {
                    // Slash to zero + cooldown: fraud forfeits Treats.
                    (0, current.lifetime_earned, 0, current.repeats, current.events.checked_add(1).ok_or(TreatError::Overflow)?)
                }
                _ => {
                    let balance = current.balance.checked_add(minted).ok_or(TreatError::Overflow)?;
                    let lifetime_earned = current.lifetime_earned.checked_add(minted).ok_or(TreatError::Overflow)?;
                    let events = current.events.checked_add(1).ok_or(TreatError::Overflow)?;
                    (balance, lifetime_earned, event.streak, current.repeats, events)
                }
            };
        // Losing slashes outstanding; minting grows it.
        if event.kind == TreatKind::DisputeLost {
            self.outstanding = self.outstanding.saturating_sub(current.balance);
        } else {
            self.outstanding = self.outstanding.checked_add(minted).ok_or(TreatError::Overflow)?;
        }
        let next = TreatAccount {
            accumulator: acc,
            balance,
            lifetime_earned,
            lifetime_redeemed: current.lifetime_redeemed,
            streak,
            repeats,
            last_height: event.height.max(current.last_height),
            events,
        };
        self.accounts.insert(event.subject, next.clone());
        Ok(AppliedTreat { event: event.clone(), event_id, minted, balance: next.balance })
    }

    /// Burn `treats` from `subject` for redemption. Returns the burned amount.
    pub fn burn_for_redeem(&mut self, subject: &AgentId, treats: u64) -> Result<u64, TreatError> {
        let mut acc = self.accounts.get(subject).cloned().unwrap_or_default();
        if acc.balance < treats {
            return Err(TreatError::InsufficientBalance { have: acc.balance, want: treats });
        }
        acc.balance -= treats;
        acc.lifetime_redeemed = acc.lifetime_redeemed.checked_add(treats).ok_or(TreatError::Overflow)?;
        self.accounts.insert(*subject, acc);
        self.outstanding = self.outstanding.saturating_sub(treats);
        Ok(treats)
    }

    /// Apply inactivity decay at `height`. Returns decayed amount.
    pub fn apply_decay(&mut self, subject: &AgentId, height: u64) -> u64 {
        let Some(mut acc) = self.accounts.get(subject).cloned() else { return 0 };
        if height.saturating_sub(acc.last_height) < TREAT_DECAY_BLOCKS || acc.balance == 0 {
            return 0;
        }
        let decay = (acc.balance as u128 * TREAT_DECAY_BPS as u128 / BPS_DENOM as u128) as u64;
        let decay = decay.max(1).min(acc.balance);
        acc.balance -= decay;
        acc.last_height = height;
        self.accounts.insert(*subject, acc);
        self.outstanding = self.outstanding.saturating_sub(decay);
        decay
    }

    /// Encode for `state.bin` persistence (trailing section, versioned).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.accounts.len() * 80);
        w.u8(TREATS_VERSION);
        w.u16le(self.network_id.len() as u16).raw(self.network_id.as_bytes());
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
                .u64le(a.last_height)
                .u64le(a.events);
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreatError> {
        let mut r = Reader::new(bytes);
        Self::decode_reader(&mut r).and_then(|l| { r.expect_end().map_err(|_| TreatError::Malformed("trailing"))?; Ok(l) })
    }

    pub fn decode_reader(r: &mut Reader) -> Result<Self, TreatError> {
        let v = r.u8().map_err(|_| TreatError::Malformed("version"))?;
        if v != TREATS_VERSION {
            return Err(TreatError::UnsupportedVersion(v));
        }
        let n = r.u16le().map_err(|_| TreatError::Malformed("network len"))? as usize;
        if n == 0 || n > MAX_TREAT_NETWORK_ID_LEN {
            return Err(TreatError::BadNetworkId(n));
        }
        let nb = r.fixed_slice(n).map_err(|_| TreatError::Malformed("network"))?;
        let network_id = std::str::from_utf8(nb)
            .map_err(|_| TreatError::Malformed("network utf8"))?
            .to_string();
        let outstanding = r.u64le().map_err(|_| TreatError::Malformed("outstanding"))?;
        let count = r.u32le().map_err(|_| TreatError::Malformed("count"))? as usize;
        if count > DEFAULT_MAX_SUBJECTS {
            return Err(TreatError::SubjectLimit { cap: DEFAULT_MAX_SUBJECTS });
        }
        let mut ledger = TreatLedger::with_capacity(network_id, DEFAULT_MAX_SUBJECTS);
        ledger.outstanding = outstanding;
        for _ in 0..count {
            let id = r.fixed::<20>().map_err(|_| TreatError::Malformed("id"))?;
            let accumulator = r.fixed::<32>().map_err(|_| TreatError::Malformed("acc"))?;
            let balance = r.u64le().map_err(|_| TreatError::Malformed("balance"))?;
            let lifetime_earned = r.u64le().map_err(|_| TreatError::Malformed("earned"))?;
            let lifetime_redeemed = r.u64le().map_err(|_| TreatError::Malformed("redeemed"))?;
            let streak = r.u32le().map_err(|_| TreatError::Malformed("streak"))?;
            let repeats = r.u32le().map_err(|_| TreatError::Malformed("repeats"))?;
            let last_height = r.u64le().map_err(|_| TreatError::Malformed("height"))?;
            let events = r.u64le().map_err(|_| TreatError::Malformed("events"))?;
            ledger.accounts.insert(id, TreatAccount {
                accumulator, balance, lifetime_earned, lifetime_redeemed,
                streak, repeats, last_height, events,
            });
        }
        r.expect_end().map_err(|_| TreatError::Malformed("trailing"))?;
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "srct/testnet";

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
    fn mint_redeem_decay_round_trip() {
        let mut l = TreatLedger::new(NET);
        let ev = l.event_for([1u8; 20], TreatKind::VerifiedWork, 10, [2u8; 32]).unwrap();
        assert!(ev.mint_amount() > 0);
        let applied = l.commit(&ev).unwrap();
        assert_eq!(l.balance(&[1u8; 20]), applied.minted);
        let out = l.outstanding();
        assert_eq!(out, applied.minted);
        // Replay refused.
        let ev2 = l.event_for([1u8; 20], TreatKind::VerifiedWork, 11, [5u8; 32]).unwrap();
        assert!(l.commit(&ev2).is_ok()); // different source ok
        // Duplicate source refused.
        assert!(matches!(
            l.commit(&ev),
            Err(TreatError::ChainBroken { .. } | TreatError::DuplicateSource { .. })
        ));
        // Redeem.
        let bal = l.balance(&[1u8; 20]);
        l.burn_for_redeem(&[1u8; 20], 1).unwrap();
        assert_eq!(l.balance(&[1u8; 20]), bal - 1);
        // Decay after inactivity window.
        let before = l.balance(&[1u8; 20]);
        let d = l.apply_decay(&[1u8; 20], 10 + TREAT_DECAY_BLOCKS + 1);
        assert!(d > 0);
        assert_eq!(l.balance(&[1u8; 20]), before - d);
        // Dispute loss slashes to zero.
        let evl = l.event_for([1u8; 20], TreatKind::DisputeLost, 50_000, [9u8; 32]).unwrap();
        l.commit(&evl).unwrap();
        assert_eq!(l.balance(&[1u8; 20]), 0);
    }

    #[test]
    fn encode_decode_round_trip() {
        let mut l = TreatLedger::new(NET);
        let ev = l.event_for([3u8; 20], TreatKind::ServiceCompleted, 5, [4u8; 32]).unwrap();
        l.commit(&ev).unwrap();
        let bytes = l.encode();
        let back = TreatLedger::decode(&bytes).unwrap();
        assert_eq!(back.balance(&[3u8; 20]), l.balance(&[3u8; 20]));
        assert_eq!(back.outstanding(), l.outstanding());
    }
}
