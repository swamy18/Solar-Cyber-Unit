//! Encrypted-compute prototype for SRCT (non-consensus).
//!
//! Agent A encrypts its inputs, worker B evaluates a weighted sum over the
//! ciphertexts, and any verifier re-runs the public operation to check the
//! result — the worker never sees plaintext. The requester's secret key never
//! leaves its owner; the signed task binds inputs, weights, provider and
//! deadline.
//!
//! # Scope
//!
//! - [`elgamal`]: exponential ElGamal over secp256k1 with baby-step
//!   giant-step decryption. Additive homomorphism + scalar multiplication.
//! - [`task`]: signed tasks, worker receipts and a fail-closed verifier whose
//!   `Ok` is the escrow rail's release signal.
//!
//! # What this is not
//!
//! - **Not general FHE.** One operation only: `bias + Σ w·x`. No encrypted
//!   non-linearities, no bootstrapping, no TFHE. Weights and bias are public.
//! - **Not consensus.** Nothing here moves coin. The verifier returns the
//!   accepted output ciphertext; the escrow or payment layer settles it.
//! - **Not a range proof.** Arithmetic is modulo the curve order. Values must
//!   stay inside the caller's decode bound; overflow wraps silently.

pub mod elgamal;
pub mod task;

pub use elgamal::{Ciphertext, FheKeys, CIPHERTEXT_LEN, POINT_LEN};
pub use task::{
    eval, FheReceipt, FheTask, FheVerifier, SignedFheReceipt, SignedFheTask, WeightedSum,
    FHE_VERSION, MAX_INPUTS, MAX_WEIGHT_ABS,
};

/// Why an encrypted-compute operation was refused. Fail-closed: any variant
/// means no payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FheError {
    Malformed(String),
    BadSignature(String),
    WrongRequester,
    WrongWorker,
    BindingMismatch,
    FraudulentOutput,
    Expired,
    FutureHeight,
    Replay,
}

impl std::fmt::Display for FheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FheError::Malformed(detail) => write!(f, "malformed fhe data: {detail}"),
            FheError::BadSignature(detail) => write!(f, "invalid signature: {detail}"),
            FheError::WrongRequester => write!(f, "key bundle is not the requester"),
            FheError::WrongWorker => write!(f, "key bundle is not the worker"),
            FheError::BindingMismatch => write!(f, "task, worker or network does not match"),
            FheError::FraudulentOutput => write!(f, "output does not match the homomorphic result"),
            FheError::Expired => write!(f, "receipt arrived after the deadline"),
            FheError::FutureHeight => write!(f, "receipt claims a future height"),
            FheError::Replay => write!(f, "task was already settled"),
        }
    }
}

impl std::error::Error for FheError {}
