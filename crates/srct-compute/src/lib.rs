//! Decentralized compute sharing for heterogeneous devices (non-consensus).
//!
//! A device advertises what it can run and at what unit price, a requester
//! describes the work it needs, the scheduler splits that work into shards that
//! fit each device, and a provider's signed receipt settles exactly the units
//! it finished. The same protocol covers a 2 GB phone, a 64 GB workstation, a
//! GPU, an NPU and a future photonic device: the differences live in a
//! [`device::DeviceProfile`], not in separate job or settlement code.
//!
//! # Scope
//!
//! - [`device`]: device class, determinism class, memory/core limits, kernel
//!   hash and capability matching.
//! - [`market`]: signed offers, signed jobs, deterministic capacity-aware
//!   sharding and requester-signed assignments.
//! - [`settle`]: provider-signed receipts, overclaim/price/deadline checks and
//!   an exact [`settle::PayoutInstruction`] the existing payment or escrow
//!   layer should execute.
//!
//! # What this is not
//!
//! - **Not consensus.** Nothing here can mint, move, slash or finalize a coin.
//!   A payout is an instruction; the caller decides which rail executes it.
//! - **Not a verifier.** A receipt proves *who claims* units were done, not that
//!   the computation was correct. `Verification::Receipt` is the only level this
//!   crate enforces; challenge re-execution, ZK proofs and TEE attestation are
//!   later milestones.
//! - **Not a scheduler daemon.** Planning is a pure function of offers, job and
//!   height. Availability gossip, leases, retries on a timer and provider
//!   liveness are the operator's job.
//! - **Not Sybil-resistant.** Identity is a normal SRCT address; a provider can
//!   create many. Bonding and reputation are prerequisites for production.
//! - **Not a trusted benchmark.** RAM, cores, bandwidth and kernel hash are
//!   self-declared. They bound what a job is assigned, not what the device
//!   actually has.

pub mod device;
pub mod market;
pub mod settle;

pub use device::{Determinism, DeviceClass, DeviceProfile, DeviceRequirement};
pub use market::{
    plan_assignments, Assignment, ComputeJob, ComputeOffer, Plan, SignedAssignment, SignedJob,
    SignedOffer, SignedPlan, MAX_ATTEMPTS, MAX_JOB_UNITS, MAX_SERVICE_LEN,
};
pub use settle::{
    ComputeLedger, ComputeReceipt, PayoutInstruction, SettlementStatus, SignedReceipt,
};

/// Why a compute-sharing operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComputeError {
    /// A field is missing, out of range or inconsistent.
    Malformed(String),
    /// A signature or key bundle does not verify.
    BadSignature(String),
    /// The offer, job, assignment or receipt names another network.
    WrongNetwork,
    /// The key bundle does not own the claimed provider address.
    WrongProvider,
    /// The key bundle does not own the claimed requester address.
    WrongRequester,
    /// No offer is eligible for this job.
    NoEligibleOffer,
    /// Eligible offers cannot cover the requested units.
    InsufficientCapacity,
    /// The cheapest complete plan costs more than the job's total budget.
    BudgetExceeded,
    /// The plan would need more shards than the protocol allows.
    TooManyShards,
    /// The assignment has been rescheduled too many times.
    TooManyAttempts,
    /// The assignment's availability window has not started or has ended.
    NotAvailable,
    /// The work's deadline has passed.
    Expired,
    /// The assignment is not past its deadline yet.
    NotExpired,
    /// A receipt claims more units than the assignment granted.
    Overclaim,
    /// A receipt's unit price does not match the assignment.
    PriceMismatch,
    /// A receipt or assignment refers to another job or assignment.
    BindingMismatch,
    /// The assignment was already settled.
    AlreadySettled,
    /// The assignment is expired and can no longer settle.
    AssignmentExpired,
}

impl std::fmt::Display for ComputeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComputeError::Malformed(detail) => write!(f, "malformed compute data: {detail}"),
            ComputeError::BadSignature(detail) => write!(f, "invalid signature: {detail}"),
            ComputeError::WrongNetwork => write!(f, "compute object is for another network"),
            ComputeError::WrongProvider => write!(f, "key bundle does not own the provider"),
            ComputeError::WrongRequester => write!(f, "key bundle does not own the requester"),
            ComputeError::NoEligibleOffer => write!(f, "no eligible offer"),
            ComputeError::InsufficientCapacity => write!(f, "offers cannot cover the job"),
            ComputeError::BudgetExceeded => write!(f, "plan exceeds the job budget"),
            ComputeError::TooManyShards => write!(f, "plan needs too many shards"),
            ComputeError::TooManyAttempts => write!(f, "assignment attempt cap reached"),
            ComputeError::NotAvailable => write!(f, "offer is outside its availability window"),
            ComputeError::Expired => write!(f, "deadline has passed"),
            ComputeError::NotExpired => write!(f, "deadline has not passed"),
            ComputeError::Overclaim => write!(f, "receipt claims more units than assigned"),
            ComputeError::PriceMismatch => write!(f, "receipt price does not match the assignment"),
            ComputeError::BindingMismatch => write!(f, "job, offer or assignment does not match"),
            ComputeError::AlreadySettled => write!(f, "assignment is already settled"),
            ComputeError::AssignmentExpired => write!(f, "assignment expired before settlement"),
        }
    }
}

impl std::error::Error for ComputeError {}
