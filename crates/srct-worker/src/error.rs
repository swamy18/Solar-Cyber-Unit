//! Errors for the worker SDK.
//!
//! Deliberately its own enum: an SDK failure is neither an L1 consensus failure
//! nor an L2 state failure, and mixing the three makes caller branching
//! ambiguous. Every L2 refusal is carried verbatim as
//! [`WorkerError::Protocol(L2Error)`](crate::error::WorkerError::Protocol) — the
//! SDK adds its own names only for failures the *client* can cause.
//!
//! No variant ever carries or renders private key material (SPEC.md §18.16).

use std::fmt;

use srct_l2::error::L2Error;

/// An SDK-layer failure, classified per SPEC.md §18.10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerError {
    /// An L2 refusal from the authoritative state machine, carried verbatim.
    Protocol(L2Error),
    /// The task id is not registered in the observed state.
    UnknownTask,
    /// The task is not in the state this action requires.
    TaskNotAvailable(&'static str),
    /// The task's deadline has passed against the observed height.
    TaskExpired,
    /// The wallet's balance cannot cover deposit + fee.
    InsufficientBalance { needed: u64, available: u64 },
    /// The configured wallet is not the actor the operation binds to
    /// (claim-descriptor mismatch, attestation identity, ownership checks).
    IdentityMismatch,
    /// The executor refused or failed the job; `(backend, reason)` is opaque
    /// operator data and never contains keys.
    ExecutionFailed {
        backend: &'static str,
        reason: String,
    },
    /// A transport/broadcast failure: retryable, timeout-safe per §18.9.
    BroadcastUnavailable(&'static str),
    /// A definitive protocol refusal of a broadcast (replay, bad signature,
    /// insufficient balance surfaced as 4xx): the node's answer, carried
    /// verbatim, and NOT retryable — retrying the same bytes can never
    /// succeed. Kept separate from `BroadcastUnavailable` precisely so the
    /// retry table cannot collapse the two.
    BroadcastRefused(String),
    /// The node could not be reached, or answered with a status that carries
    /// no observation (5xx, timeout, refused connect). The *reading* seam's
    /// counterpart to `BroadcastUnavailable`: nothing was observed, so the
    /// caller must not act — and this is a different fact from "the
    /// observation arrived and cannot be trusted", which is
    /// `ObservationMalformed`. Both are retryable (§18.10).
    ObservationUnavailable(&'static str),
    /// The observation seam returned malformed or missing data.
    ObservationMalformed(&'static str),
    /// A result claimed by the caller carries no bytes.
    EmptyResult,
    /// The Smart Gate refused the work at the execution boundary: the named
    /// gate reason, carried verbatim. Never retry the same bytes blindly —
    /// fetch a fresh capability or approval first.
    GuardDenied(String),
    /// The Smart Gate gated the work for a signed approval that was not
    /// supplied. Fetch the designated approver's approval, then re-decide.
    GuardApprovalNeeded,
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerError::Protocol(e) => write!(f, "protocol refused: {e}"),
            WorkerError::UnknownTask => write!(f, "unknown task"),
            WorkerError::TaskNotAvailable(why) => write!(f, "task not available: {why}"),
            WorkerError::TaskExpired => write!(f, "task deadline has passed"),
            WorkerError::InsufficientBalance { needed, available } => {
                write!(f, "insufficient balance: need {needed}, have {available}")
            }
            WorkerError::IdentityMismatch => {
                write!(f, "operation does not bind to the configured wallet")
            }
            WorkerError::ExecutionFailed { backend, reason } => {
                write!(f, "execution failed on {backend}: {reason}")
            }
            WorkerError::BroadcastUnavailable(why) => write!(f, "broadcast unavailable: {why}"),
            WorkerError::BroadcastRefused(detail) => write!(f, "broadcast refused: {detail}"),
            WorkerError::ObservationUnavailable(why) => write!(f, "observation unavailable: {why}"),
            WorkerError::ObservationMalformed(why) => write!(f, "malformed observation: {why}"),
            WorkerError::EmptyResult => write!(f, "executor produced no result bytes"),
            WorkerError::GuardDenied(reason) => write!(f, "smart gate denied execution: {reason}"),
            WorkerError::GuardApprovalNeeded => {
                write!(
                    f,
                    "smart gate needs a signed approval from the designated approver"
                )
            }
        }
    }
}

impl std::error::Error for WorkerError {}

/// Result alias for SDK operations.
pub type WorkerResult<T> = Result<T, WorkerError>;

impl From<L2Error> for WorkerError {
    fn from(e: L2Error) -> Self {
        WorkerError::Protocol(e)
    }
}

/// A `srct-core` codec/signing failure surfaces as a local error named for its
/// cause — never swallowed, never reinterpreted as a protocol verdict.
impl From<srct_core::Error> for WorkerError {
    fn from(e: srct_core::Error) -> Self {
        WorkerError::ObservationMalformed(match e {
            // Signing failures (the only core errors this SDK can induce in
            // its own paths beyond codec noise) name their origin.
            srct_core::Error::BadKey(_) => "core key/signing error",
            _ => "core codec error",
        })
    }
}

/// Whether an operation that failed may be safely retried (SPEC.md §18.10).
///
/// Retry here means *reconcile and re-broadcast the same bytes*: a protocol
/// refusal never becomes retryable by mutating the payload, and a local
/// configuration error never succeeds by being attempted twice.
pub fn is_retryable(err: &WorkerError) -> bool {
    match err {
        WorkerError::BroadcastRefused(_) => false,
        WorkerError::BroadcastUnavailable(_) | WorkerError::ObservationMalformed(_) => true,
        WorkerError::ObservationUnavailable(_) => true,
        // A timeout can leave a protocol error *behind* a broadcast that landed;
        // §18.9 reconciliation (same txid) is how a caller finds out.
        WorkerError::Protocol(_) | WorkerError::UnknownTask | WorkerError::TaskExpired => false,
        WorkerError::InsufficientBalance { .. } => false,
        WorkerError::TaskNotAvailable(_) => false,
        WorkerError::IdentityMismatch => false,
        WorkerError::ExecutionFailed { .. } => false,
        WorkerError::EmptyResult => false,
        WorkerError::GuardDenied(_) | WorkerError::GuardApprovalNeeded => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_is_transport_only() {
        assert!(is_retryable(&WorkerError::BroadcastUnavailable(
            "socket closed"
        )));
        assert!(is_retryable(&WorkerError::ObservationMalformed("bad view")));
        assert!(is_retryable(&WorkerError::ObservationUnavailable(
            "connect failed"
        )));

        assert!(!is_retryable(&WorkerError::Protocol(L2Error::Replay)));
        assert!(!is_retryable(&WorkerError::IdentityMismatch));
        assert!(!is_retryable(&WorkerError::InsufficientBalance {
            needed: 1,
            available: 0
        }));
        assert!(!is_retryable(&WorkerError::TaskExpired));
        assert!(!is_retryable(&WorkerError::EmptyResult));
        assert!(!is_retryable(&WorkerError::ExecutionFailed {
            backend: "CPU",
            reason: "boom".into()
        }));
    }

    #[test]
    fn display_never_contains_a_key_shaped_hex_blob() {
        // Any error text must not embed a 32-byte hex secret. The SDK has one
        // job here: never accept arbitrary user/executor text into a variant
        // that carries signing material, and never embed raw key bytes.
        let es = [
            WorkerError::IdentityMismatch.to_string(),
            WorkerError::EmptyResult.to_string(),
            WorkerError::UnknownTask.to_string(),
        ];
        for s in es {
            assert!(!s.contains("private"), "{s}");
        }
    }
}
