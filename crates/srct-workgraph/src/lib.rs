//! AI Work Graph: reusable verifiable-compute artifacts (non-consensus).
//!
//! Artifacts record what was computed, who owns it, what it derives from and
//! under what license it may be reused. Registering a derivation is a use:
//! revenue on the child flows upstream as royalties automatically.
//!
//! # Scope
//!
//! - [`artifact`]: content hashes, owner, lineage, license, evidence binding,
//!   owner signatures and wire codecs.
//! - [`graph`]: provenance book (signature/network/parent/license/cycle/
//!   replay checks) and exact recursive royalty settlement.
//!
//! # What this is not
//!
//! - **Not a proof checker.** Evidence hashes point at the issuing crates'
//!   proofs (VWC, TEE quote, FHE receipt, ZK proof). Those crates verify
//!   their own proofs; this crate enforces lineage integrity.
//! - **Not storage.** Content lives with its owner; the graph holds hashes.
//! - **Not consensus.** Settlements are instructions; the payment or escrow
//!   rail executes them.

pub mod artifact;
pub mod graph;

pub use artifact::{
    Artifact, ArtifactKind, License, SignedArtifact, ARTIFACT_VERSION, MAX_PARENTS,
    MAX_ROYALTY_BPS, MAX_ROYALTY_DEPTH,
};
pub use graph::WorkGraph;

/// Why a work-graph operation was refused. Fail-closed: any variant means no
/// registration and no payout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkError {
    Malformed(String),
    BadSignature(String),
    WrongOwner,
    WrongNetwork,
    UnknownParent,
    UnknownArtifact,
    NotReusable,
    Replay,
}

impl std::fmt::Display for WorkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkError::Malformed(detail) => write!(f, "malformed artifact data: {detail}"),
            WorkError::BadSignature(detail) => write!(f, "invalid signature: {detail}"),
            WorkError::WrongOwner => write!(f, "key bundle is not the owner"),
            WorkError::WrongNetwork => write!(f, "artifact is for another network"),
            WorkError::UnknownParent => write!(f, "parent artifact is not registered"),
            WorkError::UnknownArtifact => write!(f, "artifact is not registered"),
            WorkError::NotReusable => write!(f, "parent license forbids reuse"),
            WorkError::Replay => write!(f, "artifact was already registered"),
        }
    }
}

impl std::error::Error for WorkError {}
