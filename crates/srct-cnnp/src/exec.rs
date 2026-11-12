//! Execution-evidence gate for discovered capabilities.
//!
//! Discovery (`registry::discover`) filters on `min_privacy` and
//! `min_verification`, but filtering is routing, not proof. When a plan
//! stage selects a capability that promises private execution (`Tee`, `Fhe`)
//! or proven execution (`Tee`, `Zk`), this gate requires the matching
//! evidence and checks it through `srct-verify` before the stage settles.
//!
//! The rail supplies the evidence (SLA-bound quotes, signed tasks and
//! receipts); the gate checks provider binding, cryptographic validity and
//! coverage of the required set. Replay protection comes from the inner
//! verifiers. Plain and sealed stages need no evidence beyond the metering
//! receipt (`metering::settle_receipt`).

use srct_verify::{
    AttestationRoots, Evidence, EvidenceKind, UnifiedVerifier, VerifiedOutput, VerifyError,
};

use crate::registry::{Privacy, SignedCapability, Verification};

/// Why a plan stage was refused execution evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageError {
    Malformed(String),
    BadCapability(String),
    WrongProvider,
    MissingEvidence(EvidenceKind),
    EvidenceRefused(String),
}

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageError::Malformed(detail) => write!(f, "malformed stage data: {detail}"),
            StageError::BadCapability(detail) => write!(f, "invalid capability: {detail}"),
            StageError::WrongProvider => write!(f, "evidence is not from the stage provider"),
            StageError::MissingEvidence(kind) => write!(f, "missing {kind:?} evidence"),
            StageError::EvidenceRefused(detail) => write!(f, "evidence refused: {detail}"),
        }
    }
}

impl std::error::Error for StageError {}

/// Evidence a capability's levels require. Empty for plain/sealed stages.
pub fn required_evidence(privacy: Privacy, verification: Verification) -> Vec<EvidenceKind> {
    let mut required = Vec::with_capacity(2);
    if privacy == Privacy::Tee || verification == Verification::Tee {
        required.push(EvidenceKind::Tee);
    }
    if privacy == Privacy::Fhe {
        required.push(EvidenceKind::Fhe);
    }
    if verification == Verification::Zk {
        required.push(EvidenceKind::Zk);
    }
    required
}

fn evidence_providers(evidence: &Evidence) -> Vec<srct_core::hash::Address> {
    match evidence {
        Evidence::Tee { sla, quote } => vec![sla.provider, quote.quote.provider],
        Evidence::Fhe { task, receipt } => vec![task.task.provider, receipt.receipt.worker],
        Evidence::Zk { task, receipt } => vec![task.task.provider, receipt.receipt.worker],
    }
}

fn evidence_kind(evidence: &Evidence) -> EvidenceKind {
    match evidence {
        Evidence::Tee { .. } => EvidenceKind::Tee,
        Evidence::Fhe { .. } => EvidenceKind::Fhe,
        Evidence::Zk { .. } => EvidenceKind::Zk,
    }
}

/// Fail-closed gate for one plan stage.
#[derive(Clone, Debug, Default)]
pub struct StageGate {
    verifier: UnifiedVerifier,
}

impl StageGate {
    pub fn new() -> Self {
        Self {
            verifier: UnifiedVerifier::new(),
        }
    }

    /// Verify a stage: the capability must be signed and live, every evidence
    /// must come from the stage provider and verify cryptographically, and
    /// the required kinds must all be covered. Returns the verified outputs
    /// in evidence order for the settlement rail.
    pub fn verify_stage(
        &mut self,
        capability: &SignedCapability,
        evidences: &[Evidence],
        roots: &AttestationRoots,
        height: u64,
    ) -> Result<Vec<VerifiedOutput>, StageError> {
        capability
            .verify()
            .map_err(|e| StageError::BadCapability(e.to_string()))?;
        let cap = &capability.capability;
        let required = required_evidence(cap.privacy, cap.verification);
        let mut outputs = Vec::with_capacity(evidences.len());
        let mut covered = Vec::with_capacity(evidences.len());
        for evidence in evidences {
            // Every address the evidence mentions (context and proof) must be
            // the stage provider: substitution anywhere fails here, before any
            // cryptography runs.
            if evidence_providers(evidence)
                .iter()
                .any(|a| *a != cap.provider)
            {
                return Err(StageError::WrongProvider);
            }
            let output = self
                .verifier
                .verify(evidence, roots, height)
                .map_err(|e| StageError::EvidenceRefused(map_verify_error(e)))?;
            covered.push(evidence_kind(evidence));
            outputs.push(output);
        }
        for kind in required {
            if !covered.contains(&kind) {
                return Err(StageError::MissingEvidence(kind));
            }
        }
        Ok(outputs)
    }
}

fn map_verify_error(e: VerifyError) -> String {
    e.to_string()
}
