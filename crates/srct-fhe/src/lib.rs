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
//! - [`cost`]: operation-count pricing and worst-case bound analysis, so the
//!   rail refuses evaluation that cannot decrypt correctly.
//! - [`registry`]: operator-curated encryption keys with rotation and
//!   revocation, so workers encrypt under the right key.
//! - [`escrow`]: one-shot per-task funding with release on verified receipt
//!   and refund after the deadline, as settlement instructions.
//! - [`tfhe`]: toy gate-bootstrapping engine (LWE, blind rotation, NAND and
//!   derived gates, one-bootstrap lookup tables). Correctness-tested;
//!   explicitly not production parameters.
//!
//! # What this is not
//!
//! - **Not general FHE.** The ElGamal core does one operation only:
//!   `bias + Σ w·x`. Non-linear work goes through the [`tfhe`] bootstrapped
//!   gates instead. Weights and bias are public in both paths.
//! - **Not consensus.** Nothing here moves coin. The verifier returns the
//!   accepted output ciphertext; the escrow or payment layer settles it.
//! - **Not a zero-knowledge range proof.** Arithmetic is modulo the curve
//!   order. Static bound analysis ([`cost::eval_bounded`]) refuses an
//!   evaluation whose worst case exceeds the decryption bound, but ciphertext
//!   inputs carry no proof of their own range.

pub mod cost;
pub mod elgamal;
pub mod escrow;
pub mod registry;
pub mod task;
pub mod tfhe;

pub use cost::{
    eval_bounded, max_output, price_task, task_cost, COST_ADD, COST_BASE, COST_SCALAR_MUL,
};
pub use elgamal::{Ciphertext, FheKeys, CIPHERTEXT_LEN, POINT_LEN};
pub use escrow::{FheEscrow, Payout, Refund};
pub use registry::{KeyRecord, KeyRegistry, KeyStatus, MAX_RETIRED_KEYS, REGISTRY_VERSION};
pub use task::{
    eval, FheReceipt, FheTask, FheVerifier, SignedFheReceipt, SignedFheTask, WeightedSum,
    FHE_VERSION, MAX_INPUTS, MAX_WEIGHT_ABS,
};
pub use tfhe::{
    and_gate, bootstrap, lwe_decrypt, lwe_decrypt_answer, lwe_encrypt, mux_gate, nand_gate,
    not_gate, or_gate, phase, relu2_gate, tfhe_keygen, xor_gate, LweCipher, LweSecret, TfheKeys,
    AND_TABLE, NAND_TABLE, OR_TABLE, TFHE_LWE_N, TFHE_N, XOR_TABLE,
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
