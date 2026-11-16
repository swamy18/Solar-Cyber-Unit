//! Job escrow: fund once, release per settled receipt, refund the remainder.
//!
//! [`crate::settle`] decides *whether* a receipt may be paid; this module
//! decides *whether the money is there*. A requester funds a job once with a
//! signed commitment, each settled receipt releases exactly its own total from
//! that pot, and after the job deadline the unspent remainder is refunded
//! exactly once.
//!
//! Failure behaviour is fail-closed:
//!
//! - a job cannot be funded twice, after its deadline, or by a stranger;
//! - a release must bind to the funded job, requester and deadline, and the
//!   sum of all releases can never exceed the funded amount
//!   ([`ComputeError::BudgetExceeded`]);
//! - the same assignment cannot release twice, and a late receipt cannot
//!   release at all;
//! - a refund is only possible after the deadline, only once, and never after
//!   the pot was already refunded; a release after a refund is refused.
//!
//! What this does **not** do: move coin. A [`PayoutInstruction`] and a
//! [`RefundInstruction`] are instructions for the payment or escrow rail; this
//! crate never holds or transfers funds itself.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::market::SignedAssignment;
use crate::settle::{decode_signed, encode_signed, PayoutInstruction, SignedReceipt};
use crate::ComputeError;

pub const ESCROW_VERSION: u8 = 1;
const DOM_FUNDING: &[u8] = b"srct/compute/escrow/v1";

/// Default payout delay (in chain blocks) per network profile.
///
/// Mainnet blocks are ~10 minutes, so a short 2-block delay gives the
/// consumer time to dispute. Testnet and mini use 180 blocks to keep the
/// window long enough to observe on fast chains.
pub fn default_payout_delay_blocks(network_id: &str) -> u64 {
    match network_id {
        "srct/mainnet" => 2,
        "srct/testnet" | "srct/mini" => 180,
        _ => 0,
    }
}

/// A requester's signed commitment to lock a job budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowFunding {
    pub version: u8,
    pub network_id: String,
    /// The job this pot pays for.
    pub job: Hash,
    /// The requester that pays and signs assignments for the job.
    pub requester: Address,
    /// Total satoshis locked for the job.
    pub amount_sat: u64,
    /// The job deadline; no release or funding is possible after it.
    pub deadline: u64,
    pub nonce: u64,
}

impl EscrowFunding {
    fn validate(&self) -> Result<(), ComputeError> {
        if self.version != ESCROW_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported escrow version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("escrow network id length".into()));
        }
        if self.job == [0u8; 32] {
            return Err(ComputeError::Malformed("escrow names no job".into()));
        }
        if self.amount_sat == 0 {
            return Err(ComputeError::Malformed(
                "escrow amount must be positive".into(),
            ));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("escrow nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(96 + self.network_id.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.job)
            .fixed(&self.requester)
            .u64le(self.amount_sat)
            .u64le(self.deadline)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_FUNDING, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("escrow network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("escrow network is not utf-8".into()))?
            .to_string();
        let funding = EscrowFunding {
            version,
            network_id,
            job: r.fixed().map_err(malformed)?,
            requester: r.fixed().map_err(malformed)?,
            amount_sat: r.u64le().map_err(malformed)?,
            deadline: r.u64le().map_err(malformed)?,
            nonce: r.u64le().map_err(malformed)?,
        };
        r.expect_end().map_err(malformed)?;
        funding.validate()?;
        Ok(funding)
    }
}

/// A requester-signed escrow funding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFunding {
    pub funding: EscrowFunding,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedFunding {
    pub fn sign(funding: EscrowFunding, wallet: &Wallet) -> Result<Self, ComputeError> {
        funding.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != funding.requester {
            return Err(ComputeError::WrongRequester);
        }
        let auth = Auth::sign(wallet, &funding.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedFunding {
            funding,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.funding.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.funding.requester {
            return Err(ComputeError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.funding.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.funding.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.funding.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let (body, sigs, keys) = decode_signed(bytes, "escrow funding")?;
        let funding = EscrowFunding::decode(&body)?;
        let signed = SignedFunding {
            funding,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// The exact transfer that returns an unspent remainder to the requester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundInstruction {
    pub to: Address,
    pub amount_sat: u64,
    pub job: Hash,
}

/// One funded job's escrow state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowAccount {
    pub job: Hash,
    pub requester: Address,
    pub funded_sat: u64,
    pub released_sat: u64,
    pub refunded_sat: u64,
    pub deadline: u64,
    pub refunded: bool,
}

impl EscrowAccount {
    /// Satoshis still available for release or refund.
    pub fn remaining_sat(&self) -> u64 {
        self.funded_sat
            .saturating_sub(self.released_sat)
            .saturating_sub(self.refunded_sat)
    }
}

/// A payout recorded by the escrow book: the job it pays from, the amount,
/// and the height at which it becomes payable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledPayout {
    pub job: Hash,
    pub amount_sat: u64,
    pub payable_at: u64,
}

/// Escrow book for one network.
///
/// The book stores signed instructions and accounting only. Funding does not
/// lock coin and a release does not move it; the payment or escrow rail
/// executes both.
///
/// Releases can be immediate (`payable_at = 0`) or scheduled (`payable_at`
/// in the future). During the delay window a slice can be disputed; a held
/// payout never pays out and its funds return to the pot.
#[derive(Clone, Debug, Default)]
pub struct EscrowBook {
    network_id: String,
    accounts: BTreeMap<Hash, EscrowAccount>,
    fundings: BTreeSet<Hash>,
    releases: BTreeSet<Hash>,
    /// Assignment hash -> scheduled payout record.
    scheduled: BTreeMap<Hash, ScheduledPayout>,
    /// Assignment hashes whose payout has been paid out.
    paid: BTreeSet<Hash>,
    /// Assignment hashes whose payout is held (disputed/slashed).
    held: BTreeSet<Hash>,
}

/// Cap for persisted escrow accounts and single-use sets. Bounds the worst-case
/// allocation when decoding an untrusted `state.bin` section.
pub const MAX_ESCROW_ACCOUNTS: usize = 100_000;

impl EscrowBook {
    pub fn new(network_id: impl Into<String>) -> Self {
        EscrowBook {
            network_id: network_id.into(),
            ..Default::default()
        }
    }

    /// Encode the whole book for `state.bin`. Accounts first (they carry the
    /// money state), then the single-use funding and release sets.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.accounts.len() * 120);
        w.u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes());
        w.u32le(self.accounts.len() as u32);
        for (job, a) in &self.accounts {
            w.fixed(job)
                .fixed(&a.requester)
                .u64le(a.funded_sat)
                .u64le(a.released_sat)
                .u64le(a.refunded_sat)
                .u64le(a.deadline)
                .u8(u8::from(a.refunded));
        }
        w.u32le(self.fundings.len() as u32);
        for h in &self.fundings {
            w.fixed(h);
        }
        w.u32le(self.releases.len() as u32);
        for h in &self.releases {
            w.fixed(h);
        }
        w.u32le(self.scheduled.len() as u32);
        for (h, sp) in &self.scheduled {
            w.fixed(h)
                .fixed(&sp.job)
                .u64le(sp.amount_sat)
                .u64le(sp.payable_at);
        }
        w.u32le(self.paid.len() as u32);
        for h in &self.paid {
            w.fixed(h);
        }
        w.u32le(self.held.len() as u32);
        for h in &self.held {
            w.fixed(h);
        }
        w.into_vec()
    }

    /// Decode a book written by [`EscrowBook::encode`]. Fail-closed: any
    /// truncation, trailing garbage, over-cap count, duplicate id, network
    /// mismatch or internally inconsistent account (released + refunded above
    /// funded) refuses the whole blob.
    pub fn decode(bytes: &[u8], network_id: &str) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("escrow network id length".into()));
        }
        let net_bytes = r.fixed_slice(net_len).map_err(malformed)?;
        let stored = std::str::from_utf8(net_bytes)
            .map_err(|_| ComputeError::Malformed("escrow network is not utf-8".into()))?;
        if stored != network_id {
            return Err(ComputeError::WrongNetwork);
        }
        let n_accounts = r.u32le().map_err(malformed)? as usize;
        if n_accounts > MAX_ESCROW_ACCOUNTS {
            return Err(ComputeError::Malformed("escrow accounts over cap".into()));
        }
        let mut accounts = BTreeMap::new();
        for _ in 0..n_accounts {
            let job: Hash = r.fixed().map_err(malformed)?;
            let account = EscrowAccount {
                job,
                requester: r.fixed().map_err(malformed)?,
                funded_sat: r.u64le().map_err(malformed)?,
                released_sat: r.u64le().map_err(malformed)?,
                refunded_sat: r.u64le().map_err(malformed)?,
                deadline: r.u64le().map_err(malformed)?,
                refunded: match r.u8().map_err(malformed)? {
                    0 => false,
                    1 => true,
                    _ => return Err(ComputeError::Malformed("escrow refund flag".into())),
                },
            };
            if account.released_sat.saturating_add(account.refunded_sat) > account.funded_sat {
                return Err(ComputeError::Malformed("escrow account over-spent".into()));
            }
            if accounts.insert(job, account).is_some() {
                return Err(ComputeError::Malformed("duplicate escrow account".into()));
            }
        }
        let n_fundings = r.u32le().map_err(malformed)? as usize;
        if n_fundings > MAX_ESCROW_ACCOUNTS {
            return Err(ComputeError::Malformed("escrow fundings over cap".into()));
        }
        let mut fundings = BTreeSet::new();
        for _ in 0..n_fundings {
            let h: Hash = r.fixed().map_err(malformed)?;
            if !fundings.insert(h) {
                return Err(ComputeError::Malformed("duplicate escrow funding".into()));
            }
        }
        let n_releases = r.u32le().map_err(malformed)? as usize;
        if n_releases > MAX_ESCROW_ACCOUNTS {
            return Err(ComputeError::Malformed("escrow releases over cap".into()));
        }
        let mut releases = BTreeSet::new();
        for _ in 0..n_releases {
            let h: Hash = r.fixed().map_err(malformed)?;
            if !releases.insert(h) {
                return Err(ComputeError::Malformed("duplicate escrow release".into()));
            }
        }
        let n_scheduled = r.u32le().map_err(malformed)? as usize;
        if n_scheduled > MAX_ESCROW_ACCOUNTS {
            return Err(ComputeError::Malformed("escrow scheduled entries over cap".into()));
        }
        let mut scheduled = BTreeMap::new();
        for _ in 0..n_scheduled {
            let h: Hash = r.fixed().map_err(malformed)?;
            let job: Hash = r.fixed().map_err(malformed)?;
            let amount_sat = r.u64le().map_err(malformed)?;
            let payable_at = r.u64le().map_err(malformed)?;
            if scheduled
                .insert(
                    h,
                    ScheduledPayout {
                        job,
                        amount_sat,
                        payable_at,
                    },
                )
                .is_some()
            {
                return Err(ComputeError::Malformed("duplicate escrow scheduled entry".into()));
            }
        }
        let n_paid = r.u32le().map_err(malformed)? as usize;
        if n_paid > MAX_ESCROW_ACCOUNTS {
            return Err(ComputeError::Malformed("escrow paid entries over cap".into()));
        }
        let mut paid = BTreeSet::new();
        for _ in 0..n_paid {
            let h: Hash = r.fixed().map_err(malformed)?;
            if !paid.insert(h) {
                return Err(ComputeError::Malformed("duplicate escrow paid entry".into()));
            }
        }
        let n_held = r.u32le().map_err(malformed)? as usize;
        if n_held > MAX_ESCROW_ACCOUNTS {
            return Err(ComputeError::Malformed("escrow held entries over cap".into()));
        }
        let mut held = BTreeSet::new();
        for _ in 0..n_held {
            let h: Hash = r.fixed().map_err(malformed)?;
            if !held.insert(h) {
                return Err(ComputeError::Malformed("duplicate escrow held entry".into()));
            }
        }
        r.expect_end().map_err(malformed)?;
        Ok(EscrowBook {
            network_id: network_id.into(),
            accounts,
            fundings,
            releases,
            scheduled,
            paid,
            held,
        })
    }
}

impl EscrowBook {
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// A job's escrow account, if it was funded.
    pub fn account(&self, job: &Hash) -> Option<&EscrowAccount> {
        self.accounts.get(job)
    }

    /// Satoshis still available for a job, or zero when it was never funded.
    pub fn remaining_sat(&self, job: &Hash) -> u64 {
        self.accounts
            .get(job)
            .map(EscrowAccount::remaining_sat)
            .unwrap_or(0)
    }

    /// Lock a job budget. A job can be funded exactly once, before its
    /// deadline, by the requester that signs its assignments.
    ///
    /// Returns the funded amount.
    pub fn fund(&mut self, funding: &SignedFunding, height: u64) -> Result<u64, ComputeError> {
        funding.verify()?;
        if funding.funding.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if height > funding.funding.deadline {
            return Err(ComputeError::Expired);
        }
        self.insert_funding(funding)
    }

    /// Restore a journaled funding on restart.
    ///
    /// The append-time height check already passed when the entry was first
    /// verified, so replay does not re-apply it; signature, network and
    /// single-use checks still run.
    pub fn restore(&mut self, funding: &SignedFunding) -> Result<u64, ComputeError> {
        funding.verify()?;
        if funding.funding.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        self.insert_funding(funding)
    }

    fn insert_funding(&mut self, funding: &SignedFunding) -> Result<u64, ComputeError> {
        let f = &funding.funding;
        if self.accounts.contains_key(&f.job) {
            return Err(ComputeError::Replay);
        }
        if !self.fundings.insert(funding.hash()) {
            return Err(ComputeError::Replay);
        }
        self.accounts.insert(
            f.job,
            EscrowAccount {
                job: f.job,
                requester: f.requester,
                funded_sat: f.amount_sat,
                released_sat: 0,
                refunded_sat: 0,
                deadline: f.deadline,
                refunded: false,
            },
        );
        Ok(f.amount_sat)
    }

    /// Release exactly one settled receipt's total from the job pot.
    ///
    /// The receipt and assignment are re-verified here, so a caller cannot
    /// skip [`crate::settle`]'s checks by handing over a raw instruction.
    pub fn release(
        &mut self,
        receipt: &SignedReceipt,
        assignment: &SignedAssignment,
        height: u64,
    ) -> Result<PayoutInstruction, ComputeError> {
        receipt.verify()?;
        assignment.verify()?;
        let a = &assignment.assignment;
        let r = &receipt.receipt;
        if r.job != a.job || r.assignment != assignment.hash() || r.provider != a.provider {
            return Err(ComputeError::BindingMismatch);
        }
        if r.units_done > a.units {
            return Err(ComputeError::Overclaim);
        }
        if r.unit_price_sat != a.unit_price_sat {
            return Err(ComputeError::PriceMismatch);
        }
        if height > a.deadline || r.height > a.deadline {
            return Err(ComputeError::Expired);
        }
        let account = self
            .accounts
            .get_mut(&a.job)
            .ok_or(ComputeError::NotFunded)?;
        if account.requester != a.requester || account.deadline != a.deadline {
            return Err(ComputeError::BindingMismatch);
        }
        if account.refunded {
            return Err(ComputeError::AlreadyRefunded);
        }
        if self.releases.contains(&assignment.hash()) {
            return Err(ComputeError::AlreadySettled);
        }
        let released = account
            .released_sat
            .checked_add(r.total_sat)
            .ok_or_else(|| ComputeError::Malformed("escrow release overflows".into()))?;
        if released > account.funded_sat {
            return Err(ComputeError::BudgetExceeded);
        }
        self.releases.insert(assignment.hash());
        account.released_sat = released;
        Ok(PayoutInstruction {
            from: a.requester,
            to: a.provider,
            amount_sat: r.total_sat,
            job: a.job,
            assignment: assignment.hash(),
            receipt: receipt.hash(),
            payable_at: 0,
        })
    }

    /// Release a settled receipt on a schedule: the payout becomes payable at
    /// `height + payout_delay_blocks`. Until then the slice can be disputed.
    /// A disputed or slashed slice never pays out (`hold`). `payable_at = 0`
    /// means immediately payable.
    pub fn release_scheduled(
        &mut self,
        receipt: &SignedReceipt,
        assignment: &SignedAssignment,
        height: u64,
        payout_delay_blocks: u64,
    ) -> Result<PayoutInstruction, ComputeError> {
        receipt.verify()?;
        assignment.verify()?;
        let a = &assignment.assignment;
        let r = &receipt.receipt;
        if r.job != a.job || r.assignment != assignment.hash() || r.provider != a.provider {
            return Err(ComputeError::BindingMismatch);
        }
        if r.units_done > a.units {
            return Err(ComputeError::Overclaim);
        }
        if r.unit_price_sat != a.unit_price_sat {
            return Err(ComputeError::PriceMismatch);
        }
        if height > a.deadline || r.height > a.deadline {
            return Err(ComputeError::Expired);
        }
        let account = self
            .accounts
            .get_mut(&a.job)
            .ok_or(ComputeError::NotFunded)?;
        if account.requester != a.requester || account.deadline != a.deadline {
            return Err(ComputeError::BindingMismatch);
        }
        if account.refunded {
            return Err(ComputeError::AlreadyRefunded);
        }
        if self.releases.contains(&assignment.hash()) {
            return Err(ComputeError::AlreadySettled);
        }
        let released = account
            .released_sat
            .checked_add(r.total_sat)
            .ok_or_else(|| ComputeError::Malformed("escrow release overflows".into()))?;
        if released > account.funded_sat {
            return Err(ComputeError::BudgetExceeded);
        }
        let payable_at = if payout_delay_blocks > 0 {
            height.saturating_add(payout_delay_blocks)
        } else {
            0
        };
        self.releases.insert(assignment.hash());
        self.scheduled.insert(
            assignment.hash(),
            ScheduledPayout {
                job: a.job,
                amount_sat: r.total_sat,
                payable_at,
            },
        );
        account.released_sat = released;
        Ok(PayoutInstruction {
            from: a.requester,
            to: a.provider,
            amount_sat: r.total_sat,
            job: a.job,
            assignment: assignment.hash(),
            receipt: receipt.hash(),
            payable_at,
        })
    }

    /// Release exactly one settled receipt's total for a ticket claim.
    ///
    /// Mirrors [`EscrowBook::release`]: both signatures plus the claim are
    /// re-verified, the funded job pot pays exactly the receipt's total, and
    /// the claim hash enters the once-only release set. A claim against an
    /// unfunded job settles nothing.
    pub fn release_for_claim(
        &mut self,
        receipt: &SignedReceipt,
        ticket: &crate::ticket::SignedTicket,
        claim: &crate::ticket::SignedClaim,
        height: u64,
    ) -> Result<PayoutInstruction, ComputeError> {
        receipt.verify()?;
        ticket.verify()?;
        claim.verify()?;
        let t = &ticket.ticket;
        let c = &claim.claim;
        let r = &receipt.receipt;
        let claim_id = claim.hash();
        if c.ticket != ticket.hash() {
            return Err(ComputeError::BindingMismatch);
        }
        if r.job != t.job || r.assignment != claim_id || r.provider != c.provider {
            return Err(ComputeError::BindingMismatch);
        }
        if r.units_done > t.units {
            return Err(ComputeError::Overclaim);
        }
        if r.unit_price_sat != t.unit_price_sat {
            return Err(ComputeError::PriceMismatch);
        }
        if height > t.deadline || r.height > t.deadline {
            return Err(ComputeError::Expired);
        }
        let account = self
            .accounts
            .get_mut(&t.job)
            .ok_or(ComputeError::NotFunded)?;
        if account.requester != t.requester || account.deadline != t.deadline {
            return Err(ComputeError::BindingMismatch);
        }
        if account.refunded {
            return Err(ComputeError::AlreadyRefunded);
        }
        if self.releases.contains(&claim_id) {
            return Err(ComputeError::AlreadySettled);
        }
        let released = account
            .released_sat
            .checked_add(r.total_sat)
            .ok_or_else(|| ComputeError::Malformed("escrow release overflows".into()))?;
        if released > account.funded_sat {
            return Err(ComputeError::BudgetExceeded);
        }
        self.releases.insert(claim_id);
        account.released_sat = released;
        Ok(PayoutInstruction {
            from: t.requester,
            to: c.provider,
            amount_sat: r.total_sat,
            job: t.job,
            assignment: claim_id,
            receipt: receipt.hash(),
            payable_at: 0,
        })
    }

    /// Scheduled variant of [`release_for_claim`] with a payout delay.
    pub fn release_for_claim_scheduled(
        &mut self,
        receipt: &SignedReceipt,
        ticket: &crate::ticket::SignedTicket,
        claim: &crate::ticket::SignedClaim,
        height: u64,
        payout_delay_blocks: u64,
    ) -> Result<PayoutInstruction, ComputeError> {
        receipt.verify()?;
        ticket.verify()?;
        claim.verify()?;
        let t = &ticket.ticket;
        let c = &claim.claim;
        let r = &receipt.receipt;
        let claim_id = claim.hash();
        if c.ticket != ticket.hash() {
            return Err(ComputeError::BindingMismatch);
        }
        if r.job != t.job || r.assignment != claim_id || r.provider != c.provider {
            return Err(ComputeError::BindingMismatch);
        }
        if r.units_done > t.units {
            return Err(ComputeError::Overclaim);
        }
        if r.unit_price_sat != t.unit_price_sat {
            return Err(ComputeError::PriceMismatch);
        }
        if height > t.deadline || r.height > t.deadline {
            return Err(ComputeError::Expired);
        }
        let account = self
            .accounts
            .get_mut(&t.job)
            .ok_or(ComputeError::NotFunded)?;
        if account.requester != t.requester || account.deadline != t.deadline {
            return Err(ComputeError::BindingMismatch);
        }
        if account.refunded {
            return Err(ComputeError::AlreadyRefunded);
        }
        if self.releases.contains(&claim_id) {
            return Err(ComputeError::AlreadySettled);
        }
        let released = account
            .released_sat
            .checked_add(r.total_sat)
            .ok_or_else(|| ComputeError::Malformed("escrow release overflows".into()))?;
        if released > account.funded_sat {
            return Err(ComputeError::BudgetExceeded);
        }
        let payable_at = if payout_delay_blocks > 0 {
            height.saturating_add(payout_delay_blocks)
        } else {
            0
        };
        self.releases.insert(claim_id);
        self.scheduled.insert(
            claim_id,
            ScheduledPayout {
                job: t.job,
                amount_sat: r.total_sat,
                payable_at,
            },
        );
        account.released_sat = released;
        Ok(PayoutInstruction {
            from: t.requester,
            to: c.provider,
            amount_sat: r.total_sat,
            job: t.job,
            assignment: claim_id,
            receipt: receipt.hash(),
            payable_at,
        })
    }

    /// Assignment hashes whose scheduled payouts are due at `height`
    /// (`payable_at <= height`, not yet paid, not held). Immediate payouts
    /// (`payable_at = 0`) are not returned here — they are payable at release
    /// time.
    pub fn due_payouts(&self, height: u64) -> Vec<Hash> {
        self.scheduled
            .iter()
            .filter(|(_, sp)| sp.payable_at > 0 && sp.payable_at <= height)
            .filter(|(h, _)| !self.paid.contains(*h) && !self.held.contains(*h))
            .map(|(h, _)| *h)
            .collect()
    }

    /// Mark a scheduled payout as paid. No-op if unknown or already paid.
    pub fn mark_paid(&mut self, assignment: &Hash) {
        self.paid.insert(*assignment);
    }

    /// Hold a scheduled payout (disputed or slashed). It never pays out and
    /// its funds return to the pot, increasing the refundable remainder.
    /// Returns `true` when the payout was found and held.
    pub fn hold(&mut self, assignment: &Hash) -> bool {
        if let Some(sp) = self.scheduled.get(assignment) {
            if sp.payable_at == 0 || self.paid.contains(assignment) || self.held.contains(assignment)
            {
                return false;
            }
            self.held.insert(*assignment);
            // Return funds to the pot: reduce released_sat on the job's account.
            if let Some(account) = self.accounts.get_mut(&sp.job) {
                account.released_sat = account.released_sat.saturating_sub(sp.amount_sat);
            }
            true
        } else {
            false
        }
    }
    /// Refund the unspent remainder after the job deadline, exactly once.
    ///
    /// A fully released pot refunds zero and still closes, so a later release
    /// cannot reopen it.
    pub fn refund(&mut self, job: &Hash, height: u64) -> Result<RefundInstruction, ComputeError> {
        let account = self.accounts.get_mut(job).ok_or(ComputeError::NotFunded)?;
        if height <= account.deadline {
            return Err(ComputeError::NotExpired);
        }
        if account.refunded {
            return Err(ComputeError::AlreadyRefunded);
        }
        let amount_sat = account.funded_sat - account.released_sat;
        account.refunded = true;
        account.refunded_sat = amount_sat;
        Ok(RefundInstruction {
            to: account.requester,
            amount_sat,
            job: *job,
        })
    }
}

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}
