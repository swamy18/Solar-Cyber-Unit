//! One fail-closed verifier for every proof type.
//!
//! The inner verifiers own their replay books, so the same evidence can never
//! verify twice even across mixed workloads. Error types are preserved
//! transparently — no information is lost by unifying.

use crate::policy::{select_proofs, ProofKind, TaskProfile};
use srct_compute::tee::{AttestationRoots, SignedTeeQuote, TeeError, TeeSla, TeeVerifier};
use srct_compute::{ComputeError, ComputeLedger, SignedAssignment, SignedReceipt};
use srct_fhe::{FheError, SignedFheReceipt, SignedFheTask};
use srct_zkml::{SignedZkReceipt, SignedZkTask, ZkError};

/// Why unified verification refused evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Tee(TeeError),
    Fhe(FheError),
    Zk(ZkError),
    Compute(ComputeError),
    Policy(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Tee(e) => write!(f, "tee evidence refused: {e}"),
            VerifyError::Fhe(e) => write!(f, "fhe evidence refused: {e}"),
            VerifyError::Zk(e) => write!(f, "zk evidence refused: {e}"),
            VerifyError::Compute(e) => write!(f, "compute receipt refused: {e}"),
            VerifyError::Policy(detail) => write!(f, "policy not satisfied: {detail}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Evidence for one verification. Each variant carries everything its inner
/// verifier needs: the signed proof plus its public context.
#[derive(Clone, Debug)]
pub enum Evidence {
    /// TEE execution proof: the requester's SLA plus the worker's quote.
    Tee { sla: TeeSla, quote: SignedTeeQuote },
    /// Encrypted-compute correctness: the signed task plus the worker receipt.
    Fhe {
        task: SignedFheTask,
        receipt: SignedFheReceipt,
    },
    /// Zero-knowledge correctness: the signed task plus the worker receipt.
    Zk {
        task: SignedZkTask,
        receipt: SignedZkReceipt,
    },
    /// Resource-use proof: the requester-signed assignment plus the
    /// provider-signed receipt. Verifies exact metered settlement.
    Compute {
        assignment: SignedAssignment,
        receipt: SignedReceipt,
    },
}

/// What an accepted evidence proves: the output commitment for the
/// escrow rail to settle against. The bytes are type-specific (TEE output
/// hash, FHE ciphertext, ZK commitment); the rail interprets them per kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOutput {
    pub kind: EvidenceKind,
    pub output: Vec<u8>,
}

/// Which evidence verified, without the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Tee,
    Fhe,
    Zk,
    Compute,
}

/// One verifier for all proof types, holding every replay book.
#[derive(Clone, Debug, Default)]
pub struct UnifiedVerifier {
    tee: TeeVerifier,
    fhe: srct_fhe::task::FheVerifier,
    zk: srct_zkml::task::ZkVerifier,
    compute: ComputeLedger,
}

impl UnifiedVerifier {
    pub fn new() -> Self {
        Self {
            tee: TeeVerifier::new(),
            fhe: srct_fhe::task::FheVerifier::new(),
            zk: srct_zkml::task::ZkVerifier::new(),
            compute: ComputeLedger::new(),
        }
    }

    /// Verify one evidence against its context. `roots` authorizes TEE
    /// attestations; `current_height` enforces freshness everywhere.
    pub fn verify(
        &mut self,
        evidence: &Evidence,
        roots: &AttestationRoots,
        current_height: u64,
    ) -> Result<VerifiedOutput, VerifyError> {
        match evidence {
            Evidence::Tee { sla, quote } => {
                let output = self
                    .tee
                    .verify(sla, quote, roots, current_height)
                    .map_err(VerifyError::Tee)?;
                Ok(VerifiedOutput {
                    kind: EvidenceKind::Tee,
                    output: output.to_vec(),
                })
            }
            Evidence::Fhe { task, receipt } => {
                let output = self
                    .fhe
                    .verify(task, receipt, current_height)
                    .map_err(VerifyError::Fhe)?;
                Ok(VerifiedOutput {
                    kind: EvidenceKind::Fhe,
                    output: output.encode().to_vec(),
                })
            }
            Evidence::Zk { task, receipt } => {
                let output = self
                    .zk
                    .verify(task, receipt, current_height)
                    .map_err(VerifyError::Zk)?;
                Ok(VerifiedOutput {
                    kind: EvidenceKind::Zk,
                    output: output.to_vec(),
                })
            }
            Evidence::Compute {
                assignment,
                receipt,
            } => {
                let payout = self
                    .compute
                    .settle(receipt, assignment, current_height)
                    .map_err(VerifyError::Compute)?;
                Ok(VerifiedOutput {
                    kind: EvidenceKind::Compute,
                    output: payout.amount_sat.to_le_bytes().to_vec(),
                })
            }
        }
    }

    /// Verify every evidence and refuse unless the task profile's proof set
    /// is covered. This is the escrow-rail gate: the rail calls this before
    /// release instead of trusting any single proof.
    pub fn verify_for_profile(
        &mut self,
        profile: &TaskProfile,
        evidences: &[Evidence],
        roots: &AttestationRoots,
        current_height: u64,
    ) -> Result<Vec<VerifiedOutput>, VerifyError> {
        let mut outputs = Vec::with_capacity(evidences.len());
        let mut kinds = Vec::with_capacity(evidences.len());
        for evidence in evidences {
            let out = self.verify(evidence, roots, current_height)?;
            kinds.push(out.kind);
            outputs.push(out);
        }
        let missing: Vec<ProofKind> = select_proofs(profile)
            .into_iter()
            .filter(|p| match p {
                ProofKind::Execution => !kinds.contains(&EvidenceKind::Tee),
                ProofKind::Correctness => {
                    !kinds.contains(&EvidenceKind::Fhe) && !kinds.contains(&EvidenceKind::Zk)
                }
            })
            .collect();
        if !missing.is_empty() {
            return Err(VerifyError::Policy(format!("missing proofs: {missing:?}")));
        }
        Ok(outputs)
    }

    /// Verify the policy gate and, only on success, run the rail's release.
    /// One call instead of two, so a rail cannot release first and check
    /// proofs after. The closure runs exactly when the gate passes and never
    /// when it fails — the test pins both directions.
    pub fn gated_release<T>(
        &mut self,
        profile: &TaskProfile,
        evidences: &[Evidence],
        roots: &AttestationRoots,
        current_height: u64,
        release: impl FnOnce(Vec<VerifiedOutput>) -> T,
    ) -> Result<T, VerifyError> {
        let outputs = self.verify_for_profile(profile, evidences, roots, current_height)?;
        Ok(release(outputs))
    }
}
