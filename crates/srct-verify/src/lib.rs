//! Unified execution-verification policy and dispatch (non-consensus).
//!
//! Section 7 of the brief separates proof of execution (TEE), proof of
//! correctness (FHE recomputation, ZK proofs) and proof of resource use
//! (metered receipts). This crate selects the required proofs per task
//! ([`policy`]) and verifies every proof type through one fail-closed
//! verifier ([`verify`]) holding all replay books.

pub mod policy;
pub mod verify;

pub use policy::{select_proofs, ProofKind, SecurityLevel, TaskKind, TaskProfile, HIGH_VALUE_SAT};
pub use verify::{Evidence, EvidenceKind, UnifiedVerifier, VerifiedOutput, VerifyError};
