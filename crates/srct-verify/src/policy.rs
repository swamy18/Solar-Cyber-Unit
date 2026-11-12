//! Verification policy: which evidence a task needs.
//!
//! Section 7 of the brief distinguishes three claims:
//!
//! - **Proof of execution** — the workload ran in an approved environment
//!   (TEE attestation).
//! - **Proof of correctness** — the result equals the specified computation
//!   on the committed inputs (FHE homomorphic recomputation, ZK proof).
//! - **Proof of resource consumption** — the agreed resources were provided
//!   (metered receipts; enforced by `srct-compute::settle` and dispatched
//!   through `UnifiedVerifier` as `Evidence::Compute`).
//!
//! [`select_proofs`] maps a task profile to the required proof set. It is
//! advisory: the [`crate::verify::UnifiedVerifier`] enforces whatever evidence
//! it is given, and the escrow rail decides what to require.

/// What kind of work is being verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskKind {
    /// Plain inference or training step; correctness matters when valuable.
    Inference,
    /// Inputs must stay encrypted; correctness via homomorphic recomputation.
    EncryptedCompute,
    /// Execution must be hardware-attested.
    AttestedExecution,
    /// Correctness must be proven in zero knowledge.
    ProvenCompute,
}

/// How much is at stake. Higher levels add proofs, never remove them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Standard = 0,
    High = 1,
    Critical = 2,
}

/// Which claim the evidence must establish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Execution,
    Correctness,
}

/// The task profile the policy decides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskProfile {
    pub kind: TaskKind,
    pub security: SecurityLevel,
    /// Settlement value in satoshis. High-value plain inference additionally
    /// requires correctness (a ZK proof), because re-execution is cheap for
    /// the verifier but fabrication is cheap for the worker.
    pub value_sat: u64,
}

/// Value at or above which plain inference also requires a correctness proof.
pub const HIGH_VALUE_SAT: u64 = 1_000_000;

/// Required proofs for a profile, in verification order. Execution first
/// (cheap reject on wrong environment), correctness second.
pub fn select_proofs(profile: &TaskProfile) -> Vec<ProofKind> {
    match profile.kind {
        TaskKind::EncryptedCompute => {
            let mut proofs = vec![ProofKind::Correctness];
            if profile.security >= SecurityLevel::High {
                proofs.insert(0, ProofKind::Execution);
            }
            proofs
        }
        TaskKind::AttestedExecution => {
            let mut proofs = vec![ProofKind::Execution];
            if profile.security >= SecurityLevel::Critical {
                proofs.push(ProofKind::Correctness);
            }
            proofs
        }
        TaskKind::ProvenCompute => vec![ProofKind::Correctness],
        TaskKind::Inference => {
            if profile.value_sat >= HIGH_VALUE_SAT || profile.security >= SecurityLevel::High {
                vec![ProofKind::Correctness]
            } else {
                vec![]
            }
        }
    }
}
