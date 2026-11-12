//! Provider receipts and exact settlement.
//!
//! A receipt is the provider's signed statement that it finished `units_done`
//! of an assignment. Settlement is a pure check of the verified receipt against
//! the requester-signed assignment: same job, same assignment, same provider,
//! same unit price, no overclaim, before the deadline, and only once.
//!
//! What a receipt proves: *this provider claims these units for this assignment*.
//! It does not prove the output is correct or that the device is what its offer
//! said. Re-execution, ZK proofs and TEE attestation are separate verification
//! milestones; this crate only implements the receipt level honestly.
//!
//! The ledger also records timeouts. Once an assignment is expired it can never
//! settle, so a late receipt cannot resurrect work that was already reassigned.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::market::{SignedAssignment, MAX_JOB_UNITS};
use crate::ComputeError;

pub const RECEIPT_VERSION: u8 = 1;
const DOM_RECEIPT: &[u8] = b"srct/compute/receipt/v1";

/// A provider's signed proof of completed units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeReceipt {
    pub version: u8,
    pub job: Hash,
    pub assignment: Hash,
    pub provider: Address,
    /// Units actually completed. Must not exceed the assignment.
    pub units_done: u32,
    pub unit_price_sat: u64,
    pub total_sat: u64,
    /// Commitment to the produced output. The payload moves off-protocol.
    pub output: Hash,
    pub elapsed_ms: u64,
    /// Height the provider claims it finished at.
    pub height: u64,
    pub nonce: u64,
}

impl ComputeReceipt {
    pub fn new(
        assignment: &SignedAssignment,
        units_done: u32,
        output: Hash,
        elapsed_ms: u64,
        height: u64,
        nonce: u64,
    ) -> Result<Self, ComputeError> {
        if units_done == 0 || units_done > assignment.assignment.units {
            return Err(ComputeError::Overclaim);
        }
        let total = (units_done as u64)
            .checked_mul(assignment.assignment.unit_price_sat)
            .ok_or_else(|| ComputeError::Malformed("receipt total overflows".into()))?;
        Ok(ComputeReceipt {
            version: RECEIPT_VERSION,
            job: assignment.assignment.job,
            assignment: assignment.hash(),
            provider: assignment.assignment.provider,
            units_done,
            unit_price_sat: assignment.assignment.unit_price_sat,
            total_sat: total,
            output,
            elapsed_ms,
            height,
            nonce,
        })
    }

    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != RECEIPT_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported receipt version {}",
                self.version
            )));
        }
        if self.job == [0u8; 32] || self.assignment == [0u8; 32] {
            return Err(ComputeError::Malformed(
                "receipt names an empty job or assignment".into(),
            ));
        }
        if self.units_done == 0 || self.units_done > MAX_JOB_UNITS {
            return Err(ComputeError::Malformed("receipt units out of range".into()));
        }
        if self.unit_price_sat == 0 {
            return Err(ComputeError::Malformed(
                "receipt unit price must be positive".into(),
            ));
        }
        let expected = (self.units_done as u64)
            .checked_mul(self.unit_price_sat)
            .ok_or_else(|| ComputeError::Malformed("receipt total overflows".into()))?;
        if expected != self.total_sat {
            return Err(ComputeError::Malformed(
                "receipt total does not equal units times price".into(),
            ));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("receipt nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .fixed(&self.job)
            .fixed(&self.assignment)
            .fixed(&self.provider)
            .u32le(self.units_done)
            .u64le(self.unit_price_sat)
            .u64le(self.total_sat)
            .fixed(&self.output)
            .u64le(self.elapsed_ms)
            .u64le(self.height)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_RECEIPT, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let receipt = ComputeReceipt {
            version: r.u8().map_err(|e| ComputeError::Malformed(e.to_string()))?,
            job: r.fixed().map_err(malformed)?,
            assignment: r.fixed().map_err(malformed)?,
            provider: r.fixed().map_err(malformed)?,
            units_done: r.u32le().map_err(malformed)?,
            unit_price_sat: r.u64le().map_err(malformed)?,
            total_sat: r.u64le().map_err(malformed)?,
            output: r.fixed().map_err(malformed)?,
            elapsed_ms: r.u64le().map_err(malformed)?,
            height: r.u64le().map_err(malformed)?,
            nonce: r.u64le().map_err(malformed)?,
        };
        r.expect_end().map_err(malformed)?;
        receipt.validate()?;
        Ok(receipt)
    }
}

/// A provider-signed receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReceipt {
    pub receipt: ComputeReceipt,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedReceipt {
    pub fn sign(receipt: ComputeReceipt, wallet: &Wallet) -> Result<Self, ComputeError> {
        receipt.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != receipt.provider {
            return Err(ComputeError::WrongProvider);
        }
        let auth = Auth::sign(wallet, &receipt.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedReceipt {
            receipt,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.receipt.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.receipt.provider {
            return Err(ComputeError::WrongProvider);
        }
        verify_bundle(&self.sigs, &self.keys, &self.receipt.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.receipt.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.receipt.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let (body, sigs, keys) = decode_signed(bytes, "receipt")?;
        let receipt = ComputeReceipt::decode(&body)?;
        let signed = SignedReceipt {
            receipt,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// The exact transfer the payment or escrow layer should execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutInstruction {
    pub from: Address,
    pub to: Address,
    pub amount_sat: u64,
    pub job: Hash,
    pub assignment: Hash,
    pub receipt: Hash,
}

/// Settlement state of one assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementStatus {
    Pending,
    Settled(PayoutInstruction),
    Expired,
}

/// Replay- and timeout-safe settlement book for one node or coordinator.
#[derive(Clone, Debug, Default)]
pub struct ComputeLedger {
    settled: BTreeMap<Hash, PayoutInstruction>,
    expired: BTreeSet<Hash>,
}

impl ComputeLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status(&self, assignment: &Hash) -> SettlementStatus {
        if let Some(payout) = self.settled.get(assignment) {
            return SettlementStatus::Settled(payout.clone());
        }
        if self.expired.contains(assignment) {
            return SettlementStatus::Expired;
        }
        SettlementStatus::Pending
    }

    pub fn is_settled(&self, assignment: &Hash) -> bool {
        self.settled.contains_key(assignment)
    }

    pub fn payouts(&self) -> impl Iterator<Item = &PayoutInstruction> {
        self.settled.values()
    }

    pub fn settled_total_sat(&self) -> u64 {
        self.settled.values().map(|p| p.amount_sat).sum()
    }

    /// Verify a receipt against its assignment and record the payout.
    ///
    /// The returned instruction moves no coin; the caller executes it.
    pub fn settle(
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
        if self.settled.contains_key(&assignment.hash()) {
            return Err(ComputeError::AlreadySettled);
        }
        if self.expired.contains(&assignment.hash()) {
            return Err(ComputeError::AssignmentExpired);
        }

        let payout = PayoutInstruction {
            from: a.requester,
            to: a.provider,
            amount_sat: r.total_sat,
            job: a.job,
            assignment: assignment.hash(),
            receipt: receipt.hash(),
        };
        self.settled.insert(assignment.hash(), payout.clone());
        Ok(payout)
    }

    /// Mark a timed-out assignment expired. Returns `true` when this call was
    /// the one that expired it.
    ///
    /// An expired assignment can never settle, which is what makes rescheduling
    /// safe: the old provider cannot come back after the work moved.
    pub fn expire(
        &mut self,
        assignment: &SignedAssignment,
        height: u64,
    ) -> Result<bool, ComputeError> {
        assignment.verify()?;
        let id = assignment.hash();
        if self.settled.contains_key(&id) {
            return Err(ComputeError::AlreadySettled);
        }
        if height <= assignment.assignment.deadline {
            return Err(ComputeError::NotExpired);
        }
        Ok(self.expired.insert(id))
    }
}

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}

pub(crate) fn encode_signed(body: &[u8], sigs: &Bundle, keys: &Bundle) -> Vec<u8> {
    let sigs = sigs.to_bytes();
    let keys = keys.to_bytes();
    let mut w = Writer::with_capacity(body.len() + sigs.len() + keys.len() + 16);
    w.u32le(body.len() as u32)
        .raw(body)
        .u32le(sigs.len() as u32)
        .raw(&sigs)
        .u32le(keys.len() as u32)
        .raw(&keys);
    w.into_vec()
}

pub(crate) fn decode_signed(
    bytes: &[u8],
    what: &str,
) -> Result<(Vec<u8>, Bundle, Bundle), ComputeError> {
    let err = |detail: String| ComputeError::Malformed(format!("{what}: {detail}"));
    let mut r = Reader::new(bytes);
    let body_len = r.u32le().map_err(malformed)? as usize;
    if body_len > 64 * 1024 {
        return Err(err("body over cap".into()));
    }
    let body = r.fixed_slice(body_len).map_err(malformed)?.to_vec();
    let sigs_len = r.u32le().map_err(malformed)? as usize;
    if sigs_len > 8 * 1024 {
        return Err(err("signature bundle over cap".into()));
    }
    let sigs = Bundle::deserialize(r.fixed_slice(sigs_len).map_err(malformed)?)
        .map_err(|e| err(e.to_string()))?;
    let keys_len = r.u32le().map_err(malformed)? as usize;
    if keys_len > 8 * 1024 {
        return Err(err("key bundle over cap".into()));
    }
    let keys = Bundle::deserialize(r.fixed_slice(keys_len).map_err(malformed)?)
        .map_err(|e| err(e.to_string()))?;
    r.expect_end().map_err(malformed)?;
    Ok((body, sigs, keys))
}
