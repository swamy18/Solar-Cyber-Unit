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

/// Escrow book for one network.
///
/// The book stores signed instructions and accounting only. Funding does not
/// lock coin and a release does not move it; the payment or escrow rail
/// executes both.
#[derive(Clone, Debug, Default)]
pub struct EscrowBook {
    network_id: String,
    accounts: BTreeMap<Hash, EscrowAccount>,
    fundings: BTreeSet<Hash>,
    releases: BTreeSet<Hash>,
}

impl EscrowBook {
    pub fn new(network_id: impl Into<String>) -> Self {
        EscrowBook {
            network_id: network_id.into(),
            ..Default::default()
        }
    }

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
        let f = &funding.funding;
        if f.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if height > f.deadline {
            return Err(ComputeError::Expired);
        }
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
        })
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
