//! Challenge re-execution: enforcing `Verification::Challenge`.
//!
//! A receipt proves who claims the work, not that the output is correct. A
//! challenge forces an independent re-run: the requester names a second
//! bonded provider (the challenger), the challenger submits its own receipt
//! for the same assignment, and the two result hashes are compared.
//!
//! - Match: the original receipt stands; nobody is slashed.
//! - Mismatch: the original result is fabricated. The verdict carries
//!   everything needed for a `WrongResult` bond dispute, which takes the
//!   fraud penalty (50%) through the existing [`crate::bond`] slash path.
//!
//! What this is not: a scheduler. Assigning the challenger, funding the
//! re-execution and paying the challenger are the escrow rail's job. This
//! book checks bindings and compares commitments; it never moves coin. The
//! rail authenticates callers (the book trusts the requester check, not the
//! network).

use std::collections::{BTreeMap, BTreeSet};

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::bond::BondDispute;
use crate::market::SignedAssignment;
use crate::settle::SignedReceipt;
use crate::{ComputeError, DisputeReason};

pub const CHALLENGE_VERSION: u8 = 1;

const DOM_CHALLENGE: &[u8] = b"srct/compute/challenge/v1";

/// A requester-signed demand to re-execute one assignment independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub version: u8,
    pub network_id: String,
    /// The requester that signed the assignment and pays for the work.
    pub requester: Address,
    /// The provider whose receipt is challenged.
    pub provider: Address,
    /// The independent provider that must re-run the assignment.
    pub challenger: Address,
    /// The exact assignment being re-executed.
    pub assignment: Hash,
    /// Height by which the second receipt must arrive.
    pub deadline_height: u64,
    pub nonce: u64,
}

impl Challenge {
    fn validate(&self) -> Result<(), ComputeError> {
        if self.version != CHALLENGE_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported challenge version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed(
                "challenge network id length".into(),
            ));
        }
        if self.challenger == self.provider {
            return Err(ComputeError::Malformed(
                "challenger must differ from the challenged provider".into(),
            ));
        }
        if self.assignment == [0u8; 32] {
            return Err(ComputeError::Malformed(
                "challenge names no assignment".into(),
            ));
        }
        if self.deadline_height == 0 {
            return Err(ComputeError::Malformed("challenge deadline is zero".into()));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("challenge nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160 + self.network_id.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.requester)
            .fixed(&self.provider)
            .fixed(&self.challenger)
            .fixed(&self.assignment)
            .u64le(self.deadline_height)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_CHALLENGE, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed(
                "challenge network id length".into(),
            ));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("challenge network is not utf-8".into()))?
            .to_string();
        let requester = r.fixed().map_err(malformed)?;
        let provider = r.fixed().map_err(malformed)?;
        let challenger = r.fixed().map_err(malformed)?;
        let assignment = r.fixed().map_err(malformed)?;
        let deadline_height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let challenge = Challenge {
            version,
            network_id,
            requester,
            provider,
            challenger,
            assignment,
            deadline_height,
            nonce,
        };
        challenge.validate()?;
        Ok(challenge)
    }
}

/// A requester-signed challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedChallenge {
    pub challenge: Challenge,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedChallenge {
    pub fn sign(challenge: Challenge, requester: &Wallet) -> Result<Self, ComputeError> {
        challenge.validate()?;
        let address = requester
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != challenge.requester {
            return Err(ComputeError::WrongRequester);
        }
        let auth = Auth::sign(requester, &challenge.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedChallenge {
            challenge,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.challenge.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.challenge.requester {
            return Err(ComputeError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.challenge.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.challenge.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.challenge.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let (body, sigs, keys) = decode_signed(bytes, "challenge")?;
        let challenge = Challenge::decode(&body)?;
        let signed = SignedChallenge {
            challenge,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// The outcome of comparing the two receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeVerdict {
    /// Both receipts commit to the same result. The original stands.
    Match { assignment: Hash },
    /// The results differ: the original receipt is fabricated.
    Mismatch {
        provider: Address,
        requester: Address,
        assignment: Hash,
        /// The challenger's result commitment (the contradicting evidence).
        evidence: Hash,
    },
}

impl ChallengeVerdict {
    /// The bond dispute a mismatch justifies. The requester signs it and the
    /// existing [`crate::bond::BondBook::slash`] takes the fraud penalty.
    /// `None` on a match: nothing to slash.
    pub fn fraud_dispute(&self, network_id: &str, nonce: u64) -> Option<BondDispute> {
        match self {
            ChallengeVerdict::Match { .. } => None,
            ChallengeVerdict::Mismatch {
                provider,
                requester,
                assignment,
                evidence,
            } => Some(BondDispute {
                version: crate::bond::BOND_VERSION,
                network_id: network_id.into(),
                requester: *requester,
                provider: *provider,
                assignment: *assignment,
                reason: DisputeReason::WrongResult,
                evidence: *evidence,
                nonce,
            }),
        }
    }
}

#[derive(Clone, Debug)]
struct ChallengeRecord {
    challenge: SignedChallenge,
    second: Option<SignedReceipt>,
}

/// One node's challenge book: which assignments are being re-executed, whose
/// second receipt arrived, and what the comparison said.
#[derive(Clone, Debug, Default)]
pub struct ChallengeBook {
    network_id: String,
    records: BTreeMap<Hash, ChallengeRecord>,
    seen: BTreeSet<Hash>,
}

impl ChallengeBook {
    pub fn new(network_id: impl Into<String>) -> Self {
        ChallengeBook {
            network_id: network_id.into(),
            records: BTreeMap::new(),
            seen: BTreeSet::new(),
        }
    }

    /// Open a challenge against a settled assignment. The requester must own
    /// the assignment, the challenger must be independent, and the deadline
    /// must be in the future.
    pub fn open(
        &mut self,
        challenge: &SignedChallenge,
        assignment: &SignedAssignment,
        height: u64,
    ) -> Result<(), ComputeError> {
        challenge.verify()?;
        assignment.verify()?;
        let c = &challenge.challenge;
        if c.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if c.requester != assignment.assignment.requester {
            return Err(ComputeError::WrongRequester);
        }
        if c.provider != assignment.assignment.provider {
            return Err(ComputeError::BindingMismatch);
        }
        if c.assignment != assignment.hash() {
            return Err(ComputeError::BindingMismatch);
        }
        if height >= c.deadline_height {
            return Err(ComputeError::Expired);
        }
        // One challenge per assignment, ever: a failed challenge does not
        // clear the provider, and a second attempt would fork the audit trail.
        if self.records.contains_key(&c.assignment) {
            return Err(ComputeError::Replay);
        }
        if !self.seen.insert(challenge.hash()) {
            return Err(ComputeError::Replay);
        }
        self.records.insert(
            c.assignment,
            ChallengeRecord {
                challenge: challenge.clone(),
                second: None,
            },
        );
        Ok(())
    }

    /// Submit the challenger's re-execution receipt. Exactly once, before the
    /// deadline, signed by the challenger and bound to the same assignment.
    pub fn submit_second(
        &mut self,
        receipt: &SignedReceipt,
        height: u64,
    ) -> Result<(), ComputeError> {
        receipt.verify()?;
        let record = self
            .records
            .get_mut(&receipt.receipt.assignment)
            .ok_or(ComputeError::BindingMismatch)?;
        if record.second.is_some() {
            return Err(ComputeError::Replay);
        }
        if receipt.receipt.provider != record.challenge.challenge.challenger {
            return Err(ComputeError::WrongProvider);
        }
        if height > record.challenge.challenge.deadline_height {
            return Err(ComputeError::Expired);
        }
        record.second = Some(receipt.clone());
        Ok(())
    }

    /// Compare the original receipt against the submitted re-execution.
    pub fn verdict(
        &self,
        assignment: &Hash,
        first: &SignedReceipt,
    ) -> Result<ChallengeVerdict, ComputeError> {
        first.verify()?;
        let record = self
            .records
            .get(assignment)
            .ok_or(ComputeError::BindingMismatch)?;
        let second = record
            .second
            .as_ref()
            .ok_or_else(|| ComputeError::Malformed("challenge has no second receipt yet".into()))?;
        if first.receipt.assignment != *assignment || second.receipt.assignment != *assignment {
            return Err(ComputeError::BindingMismatch);
        }
        if first.receipt.output == second.receipt.output {
            Ok(ChallengeVerdict::Match {
                assignment: *assignment,
            })
        } else {
            Ok(ChallengeVerdict::Mismatch {
                provider: first.receipt.provider,
                requester: record.challenge.challenge.requester,
                assignment: *assignment,
                evidence: second.receipt.output,
            })
        }
    }
}

fn encode_signed(body: &[u8], sigs: &Bundle, keys: &Bundle) -> Vec<u8> {
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

fn decode_signed(bytes: &[u8], what: &str) -> Result<(Vec<u8>, Bundle, Bundle), ComputeError> {
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

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}
