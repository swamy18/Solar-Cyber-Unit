//! DiLoCo proof-of-useful-work prototype for SRCT (non-consensus).
//!
//! This crate implements the *useful-work* half of a future dual-mining
//! design as a standalone, testable subsystem. It does not touch consensus:
//! SRCT's hybrid-v1 hash PoW remains the only block-security mechanism, and
//! nothing here can mint a coin or alter a block. The purpose is to build and
//! measure the mechanisms a consensus integration would need, with real
//! training and adversarial tests rather than a simulated hash-shaped workload.
//!
//! # What is implemented
//!
//! - A small but real MLP (2-8-1, tanh hidden, sigmoid output) trained with
//!   mini-batch SGD on a deterministic two-moons classification set.
//! - DiLoCo-style rounds: every worker starts from the same global parameters,
//!   takes `inner_steps` local SGD steps on its own shard, and submits a
//!   pseudo-gradient `delta = theta_local - theta_global`.
//! - Cryptographic update envelopes: a worker signs the round id, model
//!   version, base model hash, sample/step counts and a commitment to the
//!   delta bytes. A signature over metadata without the delta is worthless, so
//!   the commitment is part of the signed preimage and is recomputed from the
//!   bytes on arrival.
//! - Byzantine filtering: finite-value checks, update-norm bounds, duplicate
//!   worker/commitment rejection, and a coordinate-wise median reference with
//!   a cosine-similarity floor. The median is robust to a minority of
//!   moderate outliers; the norm cap bounds the damage a single submission can
//!   do before filtering.
//! - Round coordination with an explicit quorum, failure state and recovery
//!   semantics: a round finalizes only with `min_quorum` accepted updates and
//!   fails closed otherwise, so a disconnected worker stalls neither the model
//!   nor the reward accounting.
//! - Contribution-weighted reward settlement in satoshis. Weights combine
//!   accepted samples and measured cosine quality; stake is eligibility-only
//!   until it is bonded and verifiable on chain. The split is exact
//!   (largest-remainder), so the sum equals the pot.
//! - Deterministic checkpoint encoding and hashing, so two coordinators that
//!   accepted the same updates derive the same model bytes.
//!
//! # What is deliberately not claimed
//!
//! - This is **not** consensus-active. It does not change block validation,
//!   difficulty, rewards or finality. A consensus integration needs a fork
//!   schedule, a migration plan and an economic analysis, none of which is
//!   invented here.
//! - A valid update is not automatically a *useful* update. The checks here
//!   reject fabricated, duplicated, non-finite and outlier updates, and score
//!   accepted work; they cannot prove that a gradient descends the loss of the
//!   intended objective. `inner_loss` is reported but never trusted for
//!   rewards.
//! - `f32` training is reproducible on one implementation but not bit-exact
//!   across every compiler/CPU combination. A consensus version would need a
//!   fixed-point or integer training kernel, or verification by re-execution
//!   under a pinned toolchain. The checkpoint hash is a commitment, not a
//!   cross-platform consensus guarantee.
//! - Sybil resistance here is stake-capped accounting, not a complete identity
//!   system. A production design must bind worker keys to bonded stake and to
//!   the L2 authority/escrow layer.
//! - **Hardware:** a `TrainBackend` seam wraps the compute path. Two backends
//!   are implemented: the CPU `f32` reference (`Reproducible`) and a
//!   block-partitioned executor (`Statistical`) that proves heterogeneous
//!   execution strategies pass the same conformance suite. GPU, TPU, NPU,
//!   Apple-silicon and photonic backends are not implemented. Adding one
//!   means implementing the trait and passing `backend::check_backend`; the
//!   round, validation and reward code does not change.
//!   Neither implemented backend is `BitExact`, so both are refused by the
//!   consensus gate; see `docs/dual-mining.md` section 8.

pub mod backend;
pub mod data;
pub mod fixed;
pub mod model;
pub mod round;
pub mod update;

pub use backend::{
    check_backend, local_update_with, require_determinism, BackendCapabilities, BackendError,
    BlockedBackend, ConformanceReport, CpuBackend, DeterminismClass, DeviceClass,
    FixedPointBackend, LocalUpdate, TrainBackend,
};
pub use data::{accuracy, mean_loss, shards, two_moons, Sample};
pub use fixed::{quantize_samples, FixedMlp};
pub use model::{Mlp, MODEL_VERSION};
pub use round::{Contribution, FinalizedRound, Rejection, RoundConfig, RoundOutcome, RoundState};
pub use update::{SignedUpdate, UpdateClaim};
