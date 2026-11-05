//! Worker SDK for the Solar Cyber Unit L2 task marketplace (SPEC.md §18).
//!
//! `srct-worker` is a **client** crate: it builds already-specified L2 payloads,
//! signs them with the existing wallet, submits them through an injected
//! broadcaster, and derives discovery/earnings/dispute views from the
//! authoritative state the protocol produces. It implements no consensus rule:
//! `TaskContract` transitions, dispute arbitration, VWC validation, settlement
//! economics and fee routing are reused from `srct-core` and `srct-l2` verbatim
//! (§18.1).
//!
//! Module map:
//! - [`node`] — the `L2NodeView`/`L2Broadcaster` seams (§18.3)
//! - [`http`] — the node transport over the §19.2 REST API (§18.3)
//! - [`discovery`] — task discovery and filtering over authoritative state (§18.4)
//! - [`claim`] / [`submit`] — the two worker-side transaction flows (§18.5, §18.7)
//! - [`executor`] — the execution seam the operator plugs its engine into (§18.6)
//! - [`guard`] — the Smart Gate execution boundary: exact-work admission
//!   before any executor runs
//! - [`dispute`] — dispute observation and challenger participation (§18.14)
//! - [`vwc`] — certificate observation/validation (§18.13, reusing §17)
//! - [`client`] — the `WorkerClient` facade and `Earnings` (§18.9, §18.13)
//! - [`config`] — operator-supplied configuration (§18.12)
//! - [`error`] — the error taxonomy and its retry classification (§18.10)

pub mod authority;
pub mod claim;
pub mod client;
pub mod config;
pub mod discovery;
pub mod dispute;
pub mod error;
pub mod executor;
pub mod exit;
pub mod guard;
pub mod http;
pub mod node;
pub mod submit;
pub mod vwc;

pub use authority::{
    add_credit_collateral, add_credit_collateral_plan, agent_spend, agent_spend_plan,
    default_credit, default_credit_plan, open_credit, open_credit_plan, publish_policy,
    publish_policy_plan, repay_credit, repay_credit_plan, revoke_policy, revoke_policy_plan,
    AgentSpendPlan, CreditCollateralPlan, CreditDefaultPlan, CreditOpenPlan, CreditRepayPlan,
    PolicyPlan,
};
pub use claim::{claim_plan, claim_task, reconcile_claimed, ClaimPlan, ClaimedState};
pub use client::{earnings_of, Earnings, WorkerClient};
pub use config::{Filter, WorkerConfig};
pub use discovery::{discover_tasks, TaskRef};
pub use dispute::{
    dispute_of_task, dispute_plan, dispute_resolution, file_dispute, DisputePlan,
    DisputeResolution, DisputeView,
};
pub use error::{is_retryable, WorkerError, WorkerResult};
pub use executor::{
    execute_task, result_hash_of, CpuExecutor, ExecError, ExecutionOutput, ExecutionWork, Executor,
    ExecutorCapabilities,
};
pub use exit::{queue_exit, queue_exit_plan, ExitPlan};
pub use guard::{
    guard_action_hash, guard_action_preimage, parse_authorize_answer, Admission, AdmissionRequest,
    GateAuthority, GuardGate, NodeGateAuthority,
};
pub use http::{ConservationReport, HttpNode};
pub use node::{BroadcastError, L2Broadcaster, L2NodeView};
pub use submit::{reconcile_submitted, submit_plan, submit_result, SubmitPlan, SubmittedState};
pub use vwc::{certificates_for_worker, is_offline_verifiable, observe_certificate};
