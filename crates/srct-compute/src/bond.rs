//! Bonded provider registration and reputation.
//!
//! Identity in [`crate::market`] is an ordinary SRCT address, so a provider
//! can create as many as it likes and each one advertises capacity for free.
//! This module makes capacity claims cost something:
//!
//! - a provider registers a **bond** — a signed commitment to stake SRCT
//!   against its offers. The bond is an instruction for the escrow or payment
//!   layer; this crate never moves coin itself.
//! - a requester can **slash** a bond with a signed dispute bound to a real
//!   assignment: `NoShow` after the deadline takes 10% of the bond,
//!   `Overclaim`/`Impostor` (fraud) take 50%.
//! - settlements raise and timeouts lower a **reputation score**; a provider
//!   whose score falls below the ban threshold, or whose bond falls below the
//!   minimum, is refused by [`BondBook::admit_offer`].
//!
//! Failure behaviour is fail-closed: an unbonded, under-bonded or banned
//! provider's offers are never scheduled, a bond cannot be withdrawn during
//! its lockup, and the same dispute or registration cannot be replayed to
//! double its effect.
//!
//! What this does **not** do: verify the evidence behind a dispute (the
//! requester signs its claim; arbitration is the escrow layer's job), prove
//! hardware truth, or move coin. Slashes and bonds are instructions only.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::market::SignedOffer;
use crate::settle::SignedReceipt;
use crate::{market::SignedAssignment, ComputeError};

pub const BOND_VERSION: u8 = 1;
/// The smallest bond an offer may stand behind.
pub const MIN_BOND_SAT: u64 = 10_000;
/// `NoShow` penalty, in basis points of the bond.
pub const SLASH_NOSHOW_BPS: u64 = 1_000;
/// Fraud (`Overclaim`, `Impostor`) penalty, in basis points of the bond.
pub const SLASH_FRAUD_BPS: u64 = 5_000;
/// A bond cannot be withdrawn until this many heights after registration.
pub const LOCKUP_HEIGHTS: u64 = 144;
/// Reputation at or below which a provider's offers are refused.
pub const BAN_SCORE: i64 = -100;
/// Reputation cost of one timed-out assignment.
pub const TIMEOUT_PENALTY: i64 = 10;
/// Reputation cost of one slash.
pub const SLASH_PENALTY: i64 = 100;

const DOM_BOND: &[u8] = b"srct/compute/bond/v1";
const DOM_WITHDRAW: &[u8] = b"srct/compute/withdraw/v1";
const DOM_DISPUTE: &[u8] = b"srct/compute/dispute/v1";

/// Why a requester is slashing a provider's bond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisputeReason {
    /// The assignment expired without an acceptable receipt.
    NoShow = 0,
    /// The provider claimed more units than the assignment granted.
    Overclaim = 1,
    /// The receipt's signer was not the assigned provider.
    Impostor = 2,
    /// Re-execution produced a different result: the receipt is fabricated.
    WrongResult = 3,
}

impl DisputeReason {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DisputeReason::NoShow),
            1 => Some(DisputeReason::Overclaim),
            2 => Some(DisputeReason::Impostor),
            3 => Some(DisputeReason::WrongResult),
            _ => None,
        }
    }

    /// The penalty this reason takes, in basis points.
    pub fn penalty_bps(self) -> u64 {
        match self {
            DisputeReason::NoShow => SLASH_NOSHOW_BPS,
            DisputeReason::Overclaim | DisputeReason::Impostor | DisputeReason::WrongResult => {
                SLASH_FRAUD_BPS
            }
        }
    }
}

/// A provider's signed stake commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderBond {
    pub version: u8,
    pub network_id: String,
    /// Address that signs offers and receipts, and that must match the
    /// bundler.
    pub provider: Address,
    /// Satoshis committed by this registration. Registrations top the bond
    /// up; a withdraw releases part of it.
    pub amount_sat: u64,
    pub registered_height: u64,
    pub nonce: u64,
}

impl ProviderBond {
    fn validate(&self) -> Result<(), ComputeError> {
        if self.version != BOND_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported bond version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("bond network id length".into()));
        }
        if self.amount_sat == 0 {
            return Err(ComputeError::Malformed(
                "bond amount must be positive".into(),
            ));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("bond nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(96 + self.network_id.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.provider)
            .u64le(self.amount_sat)
            .u64le(self.registered_height)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_BOND, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("bond network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("bond network is not utf-8".into()))?
            .to_string();
        let provider = r.fixed().map_err(malformed)?;
        let amount_sat = r.u64le().map_err(malformed)?;
        let registered_height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let bond = ProviderBond {
            version,
            network_id,
            provider,
            amount_sat,
            registered_height,
            nonce,
        };
        bond.validate()?;
        Ok(bond)
    }

    /// The height at which a full or partial withdraw becomes possible.
    pub fn lockup_until(&self) -> u64 {
        self.registered_height.saturating_add(LOCKUP_HEIGHTS)
    }
}

/// A provider-signed bond registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBond {
    pub bond: ProviderBond,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedBond {
    pub fn sign(bond: ProviderBond, wallet: &Wallet) -> Result<Self, ComputeError> {
        bond.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != bond.provider {
            return Err(ComputeError::WrongProvider);
        }
        let auth = Auth::sign(wallet, &bond.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedBond {
            bond,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.bond.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.bond.provider {
            return Err(ComputeError::WrongProvider);
        }
        verify_bundle(&self.sigs, &self.keys, &self.bond.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.bond.hash()
    }
}

/// A provider's signed request to release part of its bond.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondWithdrawal {
    pub version: u8,
    pub network_id: String,
    pub provider: Address,
    pub amount_sat: u64,
    pub nonce: u64,
}

impl BondWithdrawal {
    fn validate(&self) -> Result<(), ComputeError> {
        if self.version != BOND_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported withdrawal version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed(
                "withdrawal network id length".into(),
            ));
        }
        if self.amount_sat == 0 {
            return Err(ComputeError::Malformed(
                "withdrawal amount must be positive".into(),
            ));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("withdrawal nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(80 + self.network_id.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.provider)
            .u64le(self.amount_sat)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_WITHDRAW, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed(
                "withdrawal network id length".into(),
            ));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("withdrawal network is not utf-8".into()))?
            .to_string();
        let provider = r.fixed().map_err(malformed)?;
        let amount_sat = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let withdrawal = BondWithdrawal {
            version,
            network_id,
            provider,
            amount_sat,
            nonce,
        };
        withdrawal.validate()?;
        Ok(withdrawal)
    }
}

/// A provider-signed withdrawal request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedWithdrawal {
    pub withdrawal: BondWithdrawal,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedWithdrawal {
    pub fn sign(withdrawal: BondWithdrawal, wallet: &Wallet) -> Result<Self, ComputeError> {
        withdrawal.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != withdrawal.provider {
            return Err(ComputeError::WrongProvider);
        }
        let auth = Auth::sign(wallet, &withdrawal.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedWithdrawal {
            withdrawal,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.withdrawal.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.withdrawal.provider {
            return Err(ComputeError::WrongProvider);
        }
        verify_bundle(&self.sigs, &self.keys, &self.withdrawal.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }
}

/// A requester's signed accusation, bound to one assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondDispute {
    pub version: u8,
    pub network_id: String,
    /// The requester that signed the assignment and pays for the work.
    pub requester: Address,
    pub provider: Address,
    /// The exact assignment the claim is about.
    pub assignment: Hash,
    pub reason: DisputeReason,
    /// Commitment to off-protocol evidence. Not verified by this crate.
    pub evidence: Hash,
    pub nonce: u64,
}

impl BondDispute {
    fn validate(&self) -> Result<(), ComputeError> {
        if self.version != BOND_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported dispute version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("dispute network id length".into()));
        }
        if self.assignment == [0u8; 32] {
            return Err(ComputeError::Malformed(
                "dispute names no assignment".into(),
            ));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("dispute nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(120 + self.network_id.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.requester)
            .fixed(&self.provider)
            .fixed(&self.assignment)
            .u8(self.reason.as_u8())
            .fixed(&self.evidence)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_DISPUTE, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("dispute network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("dispute network is not utf-8".into()))?
            .to_string();
        let requester = r.fixed().map_err(malformed)?;
        let provider = r.fixed().map_err(malformed)?;
        let assignment = r.fixed().map_err(malformed)?;
        let reason = DisputeReason::from_u8(r.u8().map_err(malformed)?)
            .ok_or_else(|| ComputeError::Malformed("dispute reason".into()))?;
        let evidence = r.fixed().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let dispute = BondDispute {
            version,
            network_id,
            requester,
            provider,
            assignment,
            reason,
            evidence,
            nonce,
        };
        dispute.validate()?;
        Ok(dispute)
    }
}

/// A requester-signed dispute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDispute {
    pub dispute: BondDispute,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedDispute {
    pub fn sign(dispute: BondDispute, wallet: &Wallet) -> Result<Self, ComputeError> {
        dispute.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != dispute.requester {
            return Err(ComputeError::WrongRequester);
        }
        let auth = Auth::sign(wallet, &dispute.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedDispute {
            dispute,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.dispute.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.dispute.requester {
            return Err(ComputeError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.dispute.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }
}

/// What the book knows about one provider's behaviour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reputation {
    pub settled_units: u64,
    pub settled_count: u64,
    pub timeouts: u64,
    pub slashes: u64,
}

impl Reputation {
    /// `settled_units - 10 * timeouts - 100 * slashes`, saturating.
    pub fn score(&self) -> i64 {
        let units = self.settled_units.min(i64::MAX as u64) as i64;
        units
            .saturating_sub(
                TIMEOUT_PENALTY.saturating_mul(self.timeouts.min(i64::MAX as u64) as i64),
            )
            .saturating_sub(SLASH_PENALTY.saturating_mul(self.slashes.min(i64::MAX as u64) as i64))
    }
}

/// Bond and reputation book for one network.
///
/// The book stores signed instructions only. Registering a bond does not lock
/// coin; slashing does not burn it. The payment or escrow layer executes both.
#[derive(Clone, Debug, Default)]
pub struct BondBook {
    network_id: String,
    bonds: BTreeMap<Address, ProviderBond>,
    reputation: BTreeMap<Address, Reputation>,
    registrations: BTreeSet<Hash>,
    disputes: BTreeSet<Hash>,
    withdrawals: BTreeSet<Hash>,
}

impl BondBook {
    pub fn new(network_id: impl Into<String>) -> Self {
        BondBook {
            network_id: network_id.into(),
            ..Default::default()
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// A provider's current bond, if any.
    pub fn bond(&self, provider: &Address) -> Option<&ProviderBond> {
        self.bonds.get(provider)
    }

    /// A provider's reputation record (all zeros when never seen).
    pub fn reputation(&self, provider: &Address) -> Reputation {
        self.reputation.get(provider).copied().unwrap_or_default()
    }

    /// A provider's reputation score.
    pub fn score(&self, provider: &Address) -> i64 {
        self.reputation(provider).score()
    }

    /// Stake a signed bond. Re-registering tops the bond up and clears
    /// accumulated timeouts: fresh stake is skin in the game.
    ///
    /// Returns the provider's total bonded amount.
    pub fn register(&mut self, bond: &SignedBond, height: u64) -> Result<u64, ComputeError> {
        bond.verify()?;
        if bond.bond.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if bond.bond.registered_height > height {
            return Err(ComputeError::Malformed(
                "bond registered at a future height".into(),
            ));
        }
        if !self.registrations.insert(bond.hash()) {
            return Err(ComputeError::Replay);
        }
        let provider = bond.bond.provider;
        let entry = self.bonds.entry(provider).or_insert(ProviderBond {
            version: bond.bond.version,
            network_id: self.network_id.clone(),
            provider,
            amount_sat: 0,
            registered_height: bond.bond.registered_height,
            nonce: bond.bond.nonce,
        });
        entry.amount_sat = entry
            .amount_sat
            .checked_add(bond.bond.amount_sat)
            .ok_or_else(|| ComputeError::Malformed("bond amount overflows".into()))?;
        if bond.bond.registered_height > entry.registered_height {
            entry.registered_height = bond.bond.registered_height;
        }
        let rep = self.reputation.entry(provider).or_default();
        rep.timeouts = 0;
        Ok(entry.amount_sat)
    }

    /// Release part of a bond. Refused during lockup and beyond the stake.
    ///
    /// Returns the remaining bonded amount.
    pub fn withdraw(
        &mut self,
        withdrawal: &SignedWithdrawal,
        height: u64,
    ) -> Result<u64, ComputeError> {
        withdrawal.verify()?;
        if withdrawal.withdrawal.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        let provider = withdrawal.withdrawal.provider;
        let bond = self
            .bonds
            .get_mut(&provider)
            .ok_or(ComputeError::NotBonded)?;
        if height < bond.lockup_until() {
            return Err(ComputeError::LockupActive);
        }
        if withdrawal.withdrawal.amount_sat > bond.amount_sat {
            return Err(ComputeError::InsufficientBond);
        }
        // Mark the withdrawal consumed only now: a refused request is not a
        // used instruction and the same signed request may be retried later.
        if !self.withdrawals.insert(withdrawal.withdrawal.hash()) {
            return Err(ComputeError::Replay);
        }
        bond.amount_sat -= withdrawal.withdrawal.amount_sat;
        Ok(bond.amount_sat)
    }

    /// Slash a bond with a requester-signed dispute bound to an assignment.
    ///
    /// `NoShow` disputes require the assignment to be past its deadline;
    /// fraud disputes are valid at any height. Returns the remaining bond.
    pub fn slash(
        &mut self,
        dispute: &SignedDispute,
        assignment: &SignedAssignment,
        height: u64,
    ) -> Result<u64, ComputeError> {
        dispute.verify()?;
        assignment.verify()?;
        let d = &dispute.dispute;
        let a = &assignment.assignment;
        if d.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if d.assignment != assignment.hash()
            || d.provider != a.provider
            || d.requester != a.requester
        {
            return Err(ComputeError::BindingMismatch);
        }
        if d.reason == DisputeReason::NoShow && height <= a.deadline {
            return Err(ComputeError::NotExpired);
        }
        if !self.disputes.insert(dispute.dispute.hash()) {
            return Err(ComputeError::AlreadySlashed);
        }
        let bond = self
            .bonds
            .get_mut(&d.provider)
            .ok_or(ComputeError::NotBonded)?;
        let penalty = bond.amount_sat / 10_000 * d.reason.penalty_bps();
        bond.amount_sat -= penalty;
        self.reputation.entry(d.provider).or_default().slashes += 1;
        Ok(bond.amount_sat)
    }

    /// Count settled units toward a provider's reputation.
    pub fn record_settlement(
        &mut self,
        receipt: &SignedReceipt,
        assignment: &SignedAssignment,
    ) -> Result<(), ComputeError> {
        receipt.verify()?;
        assignment.verify()?;
        let r = &receipt.receipt;
        let a = &assignment.assignment;
        if r.job != a.job || r.assignment != assignment.hash() || r.provider != a.provider {
            return Err(ComputeError::BindingMismatch);
        }
        if r.unit_price_sat != a.unit_price_sat {
            return Err(ComputeError::PriceMismatch);
        }
        if r.units_done > a.units {
            return Err(ComputeError::Overclaim);
        }
        let rep = self.reputation.entry(a.provider).or_default();
        rep.settled_units = rep
            .settled_units
            .checked_add(r.units_done as u64)
            .ok_or_else(|| ComputeError::Malformed("reputation units overflow".into()))?;
        rep.settled_count += 1;
        Ok(())
    }

    /// Count one timed-out assignment against a provider.
    pub fn record_timeout(
        &mut self,
        assignment: &SignedAssignment,
        height: u64,
    ) -> Result<(), ComputeError> {
        assignment.verify()?;
        if height <= assignment.assignment.deadline {
            return Err(ComputeError::NotExpired);
        }
        self.reputation
            .entry(assignment.assignment.provider)
            .or_default()
            .timeouts += 1;
        Ok(())
    }

    /// Whether an offer may be scheduled: signature, network, an active bond
    /// at or above the minimum, and a reputation score above the ban.
    pub fn admit_offer(&self, offer: &SignedOffer, height: u64) -> Result<(), ComputeError> {
        offer.verify()?;
        if offer.offer.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        let provider = offer.offer.provider;
        let bond = self.bonds.get(&provider).ok_or(ComputeError::NotBonded)?;
        if bond.registered_height > height {
            return Err(ComputeError::NotBonded);
        }
        if bond.amount_sat < MIN_BOND_SAT {
            return Err(ComputeError::InsufficientBond);
        }
        if self.score(&provider) <= BAN_SCORE {
            return Err(ComputeError::Banned);
        }
        Ok(())
    }
}

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}
