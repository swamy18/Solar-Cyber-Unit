//! # srct-l2
//!
//! Layer 2 of Solar Cyber Unit: the verified-work task marketplace.
//!
//! This crate is the state machine that turns the six L2 transaction types in
//! `srct_core::l2` into a task lifecycle — post, claim, submit, dispute, settle,
//! exit — and moves SRCT against it deterministically.
//!
//! What is here:
//! - [`TaskContract`] and [`ContractState`]: the transitions, with no economic
//!   state and no cryptography.
//! - [`L2State`]: accounts, escrow, the M2 slash vault, D3 flat fees, replay
//!   protection, exit queue/release accounting, and a conservation invariant.
//! - [`L2Config`]: the network-wide parameters (dispute window, vesting period,
//!   whistleblower bounty, exit activation height).
//!
//! What is deliberately *not* here, and why:
//! - **L1 block validity.** L2 transactions are carried in L1 blocks and
//!   committed by each block's merkle root (Decision 6), and L2 state is rebuilt
//!   from that chain by [`replay::ChainL2`]. What is *not* here is any rule that
//!   makes an L1 block invalid because of its L2 content: an L2 payload that
//!   fails to apply is recorded by the replayer and skipped deterministically,
//!   never turned into a consensus rule. That separation is what keeps this
//!   integration from touching `Chain::submit`.
//! - **BLS finality activation.** `Settle` verifies a validator-quorum aggregate
//!   through the existing `BlsVerifier` trait, but nothing here finalizes an L1
//!   block. L2 consumes the L1 finality layer's binding answer through the same
//!   `Chain`; it never grows one of its own.
//!
//! What arrived with the certificate milestone:
//! - **Verified Work Certificates** ([`vwc`], SPEC.md §17): the protocol's
//!   receipt for verified correct work, issued automatically at settlement —
//!   `Quorum`-verified for an explicit `Settle`, `WindowElapsed` for an implicit
//!   one. Certificates hold no value and sit outside the conservation sum.
//!
//! Everything here is deterministic: no wall clock, no floating point, no
//! iteration-order dependence. `L2State::advance_block` sorts task ids before it
//! touches them, and a `HashMap` never decides an outcome.

pub mod deposits;
pub mod dispute;
pub mod error;
pub mod genesis;
pub mod replay;
pub mod reputation;
pub mod state;
pub mod task_contract;
pub mod tee_evidence;
pub mod vwc;

pub use deposits::{
    DepositIgnoreReason, DepositParams, DetectedDeposit, IgnoredDeposit, PendingDeposit,
};
pub use dispute::{Arbiter, DisputeEngine, DisputeEvidence, DisputeVerdict};
pub use error::{L2Error, L2Result};
pub use genesis::L2Genesis;
pub use replay::{ChainL2, ExitWatch, SkippedL2, UnbackedClaim};
pub use state::{CreditPosition, CreditPositionState, ExitRecord, L2Effect, L2State};
pub use task_contract::{
    ContractState, DisputeChallenge, ExpiryOutcome, L2Config, ServiceContract, SettlementOutcome,
    TaskContract,
};
pub use tee_evidence::{TeeBackedAttestation, TEE_EVIDENCE_VERSION};
pub use vwc::{VerifiedWorkCertificate, VwcVerification, VWC_VERSION};
