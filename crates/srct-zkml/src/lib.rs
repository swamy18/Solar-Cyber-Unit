//! Native ZKML verification prototype (non-consensus).
//!
//! A worker proves in zero knowledge that a committed output equals a
//! public-weight linear function of committed private inputs. The verifier
//! learns nothing about the inputs — only that the computation was correct.
//!
//! # Scope
//!
//! - [`circuit`]: Sigma-protocol proofs (Pedersen commitments, CDS OR
//!   bit-proofs, Fiat-Shamir) for one quantized linear layer with 16-bit
//!   range checks, plus threshold assertions (`value >= bound`) as the
//!   non-linear gate primitive.
//! - [`task`]: signed tasks, worker receipts carrying the proofs, and a
//!   fail-closed verifier whose `Ok` is the escrow rail's release signal.
//!
//! # What this is not
//!
//! - **Not general ZKML.** One linear layer, at most 8 inputs of 16 bits, plus
//!   a threshold-assertion gate. No folding/recursion (Nova-style systems are
//!   future), and threshold assertions are not yet bound to task envelopes
//!   (that binding is a wire-version decision).
//! - **Not a usefulness proof.** The proof shows the specified computation
//!   ran, not that the output is factually correct or useful.
//! - **Not consensus.** Nothing here moves coin. Verification returns the
//!   accepted output commitment; the escrow or payment layer settles it.

pub mod circuit;
pub mod task;

pub use circuit::{
    eval_plaintext, prove_linear, prove_threshold, verify_linear, verify_threshold, BitProof,
    LinearProof, ThresholdProof, BIT_WIDTH, MAX_INPUTS, MAX_WEIGHT_ABS, POINT_LEN,
};
pub use task::{
    SignedZkReceipt, SignedZkTask, ZkReceipt, ZkTask, ZkVerifier, BIT_PROOF_LEN, ZK_VERSION,
};

/// Why a ZKML operation was refused. Fail-closed: any variant means no payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkError {
    Malformed(String),
    BadSignature(String),
    WrongRequester,
    WrongWorker,
    BindingMismatch,
    InvalidProof,
    Expired,
    FutureHeight,
    Replay,
}

impl std::fmt::Display for ZkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkError::Malformed(detail) => write!(f, "malformed zk data: {detail}"),
            ZkError::BadSignature(detail) => write!(f, "invalid signature: {detail}"),
            ZkError::WrongRequester => write!(f, "key bundle is not the requester"),
            ZkError::WrongWorker => write!(f, "key bundle is not the worker"),
            ZkError::BindingMismatch => write!(f, "task, worker or network does not match"),
            ZkError::InvalidProof => write!(f, "zero-knowledge proof is invalid"),
            ZkError::Expired => write!(f, "receipt arrived after the deadline"),
            ZkError::FutureHeight => write!(f, "receipt claims a future height"),
            ZkError::Replay => write!(f, "task was already settled"),
        }
    }
}

impl std::error::Error for ZkError {}
