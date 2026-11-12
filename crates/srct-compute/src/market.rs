//! Offers, jobs, capacity-aware sharding and signed assignments.
//!
//! The scheduler is a pure function: given a signed job, a set of signed offers
//! and a height, it returns the cheapest complete plan it can build. Every
//! selection is deterministic, so two callers holding the same offers reach the
//! same shard layout and the same total price.
//!
//! Planning rules are fail-closed:
//!
//! - an offer with an invalid signature, wrong network, wrong service, expired
//!   window, insufficient verification level or an ineligible device profile is
//!   simply not a candidate;
//! - a device never receives a shard larger than its advertised per-shard cap,
//!   nor more than the offer's per-job cap across all of its shards;
//! - a shard never falls below the offer's minimum, so a device is not asked to
//!   run an unprofitable fragment;
//! - an empty class mask or an empty candidate set covers nothing;
//! - a plan that cannot cover every requested unit, needs too many shards, or
//!   exceeds the job's total budget is refused, never truncated.

use std::collections::BTreeMap;

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::device::{
    Determinism, DeviceClass, DeviceProfile, DeviceRequirement, MAX_RAM_MIB, MIN_RAM_MIB,
};
use crate::ComputeError;

pub const OFFER_VERSION: u8 = 1;
pub const JOB_VERSION: u8 = 1;
pub const ASSIGNMENT_VERSION: u8 = 1;
/// Longest accepted service tag.
pub const MAX_SERVICE_LEN: usize = 64;
/// Most units one job may request.
pub const MAX_JOB_UNITS: u32 = 1_000_000;
/// Most times an assignment may be rescheduled after a timeout.
pub const MAX_ATTEMPTS: u16 = 3;
/// Most shards one plan may contain.
pub const MAX_SHARDS: usize = 4_096;

const DOM_OFFER: &[u8] = b"srct/compute/offer/v1";
const DOM_JOB: &[u8] = b"srct/compute/job/v1";
const DOM_ASSIGNMENT: &[u8] = b"srct/compute/assignment/v1";

/// How much independent evidence a job accepts.
///
/// [`Verification::Receipt`] is enforced by [`crate::settle`];
/// [`Verification::Attested`] is enforced by [`crate::tee`] (signed
/// attestation quotes against the requester's SLA). `Challenge` re-execution
/// is still a discovery/requirements field only; an offer advertising it is
/// self-declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verification {
    Receipt = 0,
    Challenge = 1,
    Attested = 2,
}

impl Verification {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Verification::Receipt),
            1 => Some(Verification::Challenge),
            2 => Some(Verification::Attested),
            _ => None,
        }
    }
}

/// A provider's signed advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeOffer {
    pub version: u8,
    pub network_id: String,
    /// Address that will sign receipts and receive payment.
    pub provider: Address,
    pub service: String,
    pub profile: DeviceProfile,
    pub unit_price_sat: u64,
    pub min_units: u32,
    pub max_units_per_job: u32,
    /// Whether this provider accepts a sealed (privately delivered) input.
    pub privacy: bool,
    pub verification: Verification,
    pub available_from: u64,
    pub available_until: u64,
    pub nonce: u64,
}

impl ComputeOffer {
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != OFFER_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported offer version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("offer network id length".into()));
        }
        if self.service.is_empty() || self.service.len() > MAX_SERVICE_LEN {
            return Err(ComputeError::Malformed("offer service length".into()));
        }
        self.profile.validate()?;
        if self.unit_price_sat == 0 {
            return Err(ComputeError::Malformed(
                "offer unit price must be positive".into(),
            ));
        }
        if self.min_units == 0 || self.max_units_per_job < self.min_units {
            return Err(ComputeError::Malformed(
                "offer unit range is empty or inverted".into(),
            ));
        }
        if self.max_units_per_job > MAX_JOB_UNITS {
            return Err(ComputeError::Malformed(
                "offer per-job cap above the job bound".into(),
            ));
        }
        if self.available_until < self.available_from {
            return Err(ComputeError::Malformed(
                "offer availability window is inverted".into(),
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let profile = self.profile.encode();
        let mut w = Writer::with_capacity(160 + self.network_id.len() + self.service.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.provider)
            .u16le(self.service.len() as u16)
            .raw(self.service.as_bytes())
            .u16le(profile.len() as u16)
            .raw(&profile)
            .u64le(self.unit_price_sat)
            .u32le(self.min_units)
            .u32le(self.max_units_per_job)
            .u8(self.privacy as u8)
            .u8(self.verification.as_u8())
            .u64le(self.available_from)
            .u64le(self.available_until)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_OFFER, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("offer network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("offer network is not utf-8".into()))?
            .to_string();
        let provider = r.fixed().map_err(malformed)?;
        let svc_len = r.u16le().map_err(malformed)? as usize;
        if svc_len == 0 || svc_len > MAX_SERVICE_LEN {
            return Err(ComputeError::Malformed("offer service length".into()));
        }
        let service = std::str::from_utf8(r.fixed_slice(svc_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("offer service is not utf-8".into()))?
            .to_string();
        let profile_len = r.u16le().map_err(malformed)? as usize;
        if profile_len == 0 || profile_len > 256 {
            return Err(ComputeError::Malformed("offer profile length".into()));
        }
        let profile = DeviceProfile::decode(r.fixed_slice(profile_len).map_err(malformed)?)?;
        let unit_price_sat = r.u64le().map_err(malformed)?;
        let min_units = r.u32le().map_err(malformed)?;
        let max_units_per_job = r.u32le().map_err(malformed)?;
        let privacy = r.u8().map_err(malformed)?;
        if privacy > 1 {
            return Err(ComputeError::Malformed("offer privacy flag".into()));
        }
        let verification = Verification::from_u8(r.u8().map_err(malformed)?)
            .ok_or_else(|| ComputeError::Malformed("offer verification level".into()))?;
        let offer = ComputeOffer {
            version,
            network_id,
            provider,
            service,
            profile,
            unit_price_sat,
            min_units,
            max_units_per_job,
            privacy: privacy == 1,
            verification,
            available_from: r.u64le().map_err(malformed)?,
            available_until: r.u64le().map_err(malformed)?,
            nonce: r.u64le().map_err(malformed)?,
        };
        r.expect_end().map_err(malformed)?;
        offer.validate()?;
        Ok(offer)
    }
}

/// A provider-signed offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOffer {
    pub offer: ComputeOffer,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedOffer {
    pub fn sign(offer: ComputeOffer, wallet: &Wallet) -> Result<Self, ComputeError> {
        offer.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != offer.provider {
            return Err(ComputeError::WrongProvider);
        }
        let auth = Auth::sign(wallet, &offer.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedOffer {
            offer,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.offer.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.offer.provider {
            return Err(ComputeError::WrongProvider);
        }
        verify_bundle(&self.sigs, &self.keys, &self.offer.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.offer.hash()
    }
}

/// What a requester needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeJob {
    pub version: u8,
    pub network_id: String,
    /// Address that pays, and that signs assignments.
    pub requester: Address,
    pub service: String,
    pub units: u32,
    pub max_unit_price_sat: u64,
    /// Hard ceiling for the whole plan, so a cheap-looking unit price cannot
    /// turn into unbounded spend through many shards.
    pub max_total_sat: u64,
    pub class_mask: u8,
    pub min_ram_mib: u32,
    pub determinism: Determinism,
    /// Exact kernel hash required, or zero for any.
    pub required_kernel: Hash,
    pub min_verification: Verification,
    /// Require a provider that accepts sealed inputs.
    pub sealed_input: bool,
    /// Commitment to the input data. The payload moves off-protocol.
    pub input: Hash,
    pub deadline: u64,
    pub nonce: u64,
}

impl ComputeJob {
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != JOB_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported job version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("job network id length".into()));
        }
        if self.service.is_empty() || self.service.len() > MAX_SERVICE_LEN {
            return Err(ComputeError::Malformed("job service length".into()));
        }
        if self.units == 0 || self.units > MAX_JOB_UNITS {
            return Err(ComputeError::Malformed("job units out of range".into()));
        }
        if self.max_unit_price_sat == 0 || self.max_total_sat == 0 {
            return Err(ComputeError::Malformed(
                "job price bounds must be positive".into(),
            ));
        }
        if self.class_mask == 0 || self.class_mask & !DeviceClass::ALL_MASK != 0 {
            return Err(ComputeError::Malformed(
                "job device class mask is empty or unknown".into(),
            ));
        }
        if !(MIN_RAM_MIB..=MAX_RAM_MIB).contains(&self.min_ram_mib) {
            return Err(ComputeError::Malformed("job ram requirement".into()));
        }
        if self.deadline == 0 {
            return Err(ComputeError::Malformed("job deadline is zero".into()));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("job nonce is zero".into()));
        }
        Ok(())
    }

    pub fn requirement(&self) -> DeviceRequirement {
        DeviceRequirement {
            class_mask: self.class_mask,
            min_ram_mib: self.min_ram_mib,
            determinism: self.determinism,
            kernel: self.required_kernel,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(180 + self.network_id.len() + self.service.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.requester)
            .u16le(self.service.len() as u16)
            .raw(self.service.as_bytes())
            .u32le(self.units)
            .u64le(self.max_unit_price_sat)
            .u64le(self.max_total_sat)
            .u8(self.class_mask)
            .u32le(self.min_ram_mib)
            .u8(self.determinism.as_u8())
            .fixed(&self.required_kernel)
            .u8(self.min_verification.as_u8())
            .u8(self.sealed_input as u8)
            .fixed(&self.input)
            .u64le(self.deadline)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_JOB, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("job network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("job network is not utf-8".into()))?
            .to_string();
        let requester = r.fixed().map_err(malformed)?;
        let svc_len = r.u16le().map_err(malformed)? as usize;
        if svc_len == 0 || svc_len > MAX_SERVICE_LEN {
            return Err(ComputeError::Malformed("job service length".into()));
        }
        let service = std::str::from_utf8(r.fixed_slice(svc_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("job service is not utf-8".into()))?
            .to_string();
        let units = r.u32le().map_err(malformed)?;
        let max_unit_price_sat = r.u64le().map_err(malformed)?;
        let max_total_sat = r.u64le().map_err(malformed)?;
        let class_mask = r.u8().map_err(malformed)?;
        let min_ram_mib = r.u32le().map_err(malformed)?;
        let determinism = Determinism::from_u8(r.u8().map_err(malformed)?)
            .ok_or_else(|| ComputeError::Malformed("job determinism class".into()))?;
        let required_kernel = r.fixed().map_err(malformed)?;
        let min_verification = Verification::from_u8(r.u8().map_err(malformed)?)
            .ok_or_else(|| ComputeError::Malformed("job verification level".into()))?;
        let sealed_input = r.u8().map_err(malformed)?;
        if sealed_input > 1 {
            return Err(ComputeError::Malformed("job sealed-input flag".into()));
        }
        let job = ComputeJob {
            version,
            network_id,
            requester,
            service,
            units,
            max_unit_price_sat,
            max_total_sat,
            class_mask,
            min_ram_mib,
            determinism,
            required_kernel,
            min_verification,
            sealed_input: sealed_input == 1,
            input: r.fixed().map_err(malformed)?,
            deadline: r.u64le().map_err(malformed)?,
            nonce: r.u64le().map_err(malformed)?,
        };
        r.expect_end().map_err(malformed)?;
        job.validate()?;
        Ok(job)
    }
}

/// A requester-signed job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedJob {
    pub job: ComputeJob,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedJob {
    pub fn sign(job: ComputeJob, wallet: &Wallet) -> Result<Self, ComputeError> {
        job.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != job.requester {
            return Err(ComputeError::WrongRequester);
        }
        let auth = Auth::sign(wallet, &job.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedJob {
            job,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.job.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.job.requester {
            return Err(ComputeError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.job.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.job.hash()
    }
}

/// One shard of a job assigned to one provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub version: u8,
    pub job: Hash,
    pub offer: Hash,
    pub requester: Address,
    pub provider: Address,
    /// Dense shard index inside the plan.
    pub shard: u16,
    pub units: u32,
    pub unit_price_sat: u64,
    pub total_sat: u64,
    pub deadline: u64,
    pub attempt: u16,
}

impl Assignment {
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != ASSIGNMENT_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported assignment version {}",
                self.version
            )));
        }
        if self.job == [0u8; 32] || self.offer == [0u8; 32] {
            return Err(ComputeError::Malformed(
                "assignment names an empty job or offer".into(),
            ));
        }
        if self.units == 0 || self.units > MAX_JOB_UNITS {
            return Err(ComputeError::Malformed(
                "assignment units out of range".into(),
            ));
        }
        if self.unit_price_sat == 0 {
            return Err(ComputeError::Malformed(
                "assignment unit price must be positive".into(),
            ));
        }
        let expected = (self.units as u64)
            .checked_mul(self.unit_price_sat)
            .ok_or_else(|| ComputeError::Malformed("assignment total overflows".into()))?;
        if expected != self.total_sat {
            return Err(ComputeError::Malformed(
                "assignment total does not equal units times price".into(),
            ));
        }
        if self.attempt > MAX_ATTEMPTS {
            return Err(ComputeError::TooManyAttempts);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .fixed(&self.job)
            .fixed(&self.offer)
            .fixed(&self.requester)
            .fixed(&self.provider)
            .u16le(self.shard)
            .u32le(self.units)
            .u64le(self.unit_price_sat)
            .u64le(self.total_sat)
            .u64le(self.deadline)
            .u16le(self.attempt);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_ASSIGNMENT, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let assignment = Assignment {
            version: r.u8().map_err(malformed)?,
            job: r.fixed().map_err(malformed)?,
            offer: r.fixed().map_err(malformed)?,
            requester: r.fixed().map_err(malformed)?,
            provider: r.fixed().map_err(malformed)?,
            shard: r.u16le().map_err(malformed)?,
            units: r.u32le().map_err(malformed)?,
            unit_price_sat: r.u64le().map_err(malformed)?,
            total_sat: r.u64le().map_err(malformed)?,
            deadline: r.u64le().map_err(malformed)?,
            attempt: r.u16le().map_err(malformed)?,
        };
        r.expect_end().map_err(malformed)?;
        assignment.validate()?;
        Ok(assignment)
    }
}

/// An assignment signed by the requester, which authorizes the payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAssignment {
    pub assignment: Assignment,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedAssignment {
    pub fn sign(assignment: Assignment, wallet: &Wallet) -> Result<Self, ComputeError> {
        assignment.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != assignment.requester {
            return Err(ComputeError::WrongRequester);
        }
        let auth = Auth::sign(wallet, &assignment.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedAssignment {
            assignment,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.assignment.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.assignment.requester {
            return Err(ComputeError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.assignment.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.assignment.hash()
    }
}

/// A deterministic, fully priced shard layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub job: Hash,
    pub requester: Address,
    pub attempt: u16,
    pub assignments: Vec<Assignment>,
    pub total_sat: u64,
}

impl Plan {
    pub fn units(&self) -> u32 {
        self.assignments.iter().map(|a| a.units).sum()
    }

    /// Sign every shard with the requester's wallet.
    pub fn sign(&self, wallet: &Wallet) -> Result<SignedPlan, ComputeError> {
        let mut signed = Vec::with_capacity(self.assignments.len());
        for assignment in &self.assignments {
            signed.push(SignedAssignment::sign(assignment.clone(), wallet)?);
        }
        let plan = SignedPlan {
            job: self.job,
            requester: self.requester,
            attempt: self.attempt,
            assignments: signed,
            total_sat: self.total_sat,
        };
        plan.verify()?;
        Ok(plan)
    }
}

/// A plan whose every shard carries the requester's authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPlan {
    pub job: Hash,
    pub requester: Address,
    pub attempt: u16,
    pub assignments: Vec<SignedAssignment>,
    pub total_sat: u64,
}

impl SignedPlan {
    pub fn verify(&self) -> Result<(), ComputeError> {
        if self.assignments.is_empty() {
            return Err(ComputeError::Malformed("plan has no assignments".into()));
        }
        let mut total = 0u64;
        for assignment in &self.assignments {
            assignment.verify()?;
            if assignment.assignment.job != self.job
                || assignment.assignment.requester != self.requester
                || assignment.assignment.attempt != self.attempt
            {
                return Err(ComputeError::BindingMismatch);
            }
            total = total
                .checked_add(assignment.assignment.total_sat)
                .ok_or_else(|| ComputeError::Malformed("plan total overflows".into()))?;
        }
        if total != self.total_sat {
            return Err(ComputeError::Malformed(
                "plan total does not equal its shards".into(),
            ));
        }
        Ok(())
    }

    pub fn units(&self) -> u32 {
        self.assignments.iter().map(|a| a.assignment.units).sum()
    }

    pub fn for_provider(&self, provider: &Address) -> Vec<&SignedAssignment> {
        self.assignments
            .iter()
            .filter(|a| a.assignment.provider == *provider)
            .collect()
    }
}

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}

/// Build the cheapest complete plan for `job`.
///
/// `height` is the planning height; offers whose window excludes it and jobs
/// whose deadline has passed are refused. `attempt` is the rescheduling round
/// and is capped at [`MAX_ATTEMPTS`].
pub fn plan_assignments(
    job: &SignedJob,
    offers: &[SignedOffer],
    height: u64,
    attempt: u16,
) -> Result<Plan, ComputeError> {
    job.verify()?;
    if attempt > MAX_ATTEMPTS {
        return Err(ComputeError::TooManyAttempts);
    }
    if height > job.job.deadline {
        return Err(ComputeError::Expired);
    }
    let requirement = job.job.requirement();

    let mut candidates: Vec<&SignedOffer> = offers
        .iter()
        .filter(|offer| {
            offer.verify().is_ok()
                && offer.offer.network_id == job.job.network_id
                && offer.offer.service == job.job.service
                && offer.offer.unit_price_sat <= job.job.max_unit_price_sat
                && offer.offer.available_from <= height
                && height <= offer.offer.available_until
                && offer.offer.verification >= job.job.min_verification
                && (!job.job.sealed_input || offer.offer.privacy)
                && offer.offer.profile.meets(&requirement)
        })
        .collect();
    if candidates.is_empty() {
        return Err(ComputeError::NoEligibleOffer);
    }
    candidates.sort_by_key(|offer| {
        (
            offer.offer.unit_price_sat,
            offer.offer.provider,
            offer.hash(),
        )
    });

    let mut remaining = job.job.units;
    let mut total_sat = 0u64;
    let mut assignments = Vec::new();
    let mut assigned_per_offer: BTreeMap<Hash, u32> = BTreeMap::new();

    for offer in candidates {
        // One offer can own several shards: a phone with a 4-unit shard cap and
        // an 8-unit per-job cap must still be able to take all 8 units. The
        // loop stops at the per-job cap, so an offer is never over-assigned.
        loop {
            if remaining == 0 {
                break;
            }
            let already = assigned_per_offer.get(&offer.hash()).copied().unwrap_or(0);
            let per_job_left = offer.offer.max_units_per_job.saturating_sub(already);
            let take = remaining
                .min(per_job_left)
                .min(offer.offer.profile.max_units_per_shard);
            if take < offer.offer.min_units || take == 0 {
                break;
            }
            if assignments.len() >= MAX_SHARDS {
                return Err(ComputeError::TooManyShards);
            }
            let cost = (take as u64)
                .checked_mul(offer.offer.unit_price_sat)
                .ok_or_else(|| ComputeError::Malformed("assignment total overflows".into()))?;
            let new_total = total_sat
                .checked_add(cost)
                .ok_or_else(|| ComputeError::Malformed("plan total overflows".into()))?;
            if new_total > job.job.max_total_sat {
                return Err(ComputeError::BudgetExceeded);
            }
            assignments.push(Assignment {
                version: ASSIGNMENT_VERSION,
                job: job.hash(),
                offer: offer.hash(),
                requester: job.job.requester,
                provider: offer.offer.provider,
                shard: assignments.len() as u16,
                units: take,
                unit_price_sat: offer.offer.unit_price_sat,
                total_sat: cost,
                deadline: job.job.deadline,
                attempt,
            });
            *assigned_per_offer.entry(offer.hash()).or_insert(0) += take;
            remaining -= take;
            total_sat = new_total;
        }
    }

    if remaining > 0 {
        return Err(ComputeError::InsufficientCapacity);
    }
    Ok(Plan {
        job: job.hash(),
        requester: job.job.requester,
        attempt,
        assignments,
        total_sat,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_encodings_are_refused() {
        assert!(Verification::from_u8(7).is_none());
        assert_eq!(Verification::from_u8(2), Some(Verification::Attested));
    }

    #[test]
    fn assignment_arithmetic_is_checked() {
        let a = Assignment {
            version: ASSIGNMENT_VERSION,
            job: [1u8; 32],
            offer: [2u8; 32],
            requester: [3u8; 20],
            provider: [4u8; 20],
            shard: 0,
            units: 3,
            unit_price_sat: 10,
            total_sat: 31,
            deadline: 100,
            attempt: 1,
        };
        assert!(matches!(a.validate(), Err(ComputeError::Malformed(_))));
        let decoded = Assignment::decode(&Assignment { total_sat: 30, ..a }.encode()).unwrap();
        assert_eq!(decoded.total_sat, 30);
    }
}
