//! `TaskContract`: the L2 task lifecycle state machine.
//!
//! ```text
//!   Open ──claim──▶ InProgress ──submit──▶ ResultSubmitted ──dispute──▶ Disputed
//!    │                 │                        │                         │
//!    │                 │                        └─ window elapses ─▶ auto-settle Correct
//!    │                 │
//!    └─ deadline ─▶ Expired ◀─ deadline ────────┘
//! ```
//!
//! This module holds the *transitions only*: no balances, no fees, no BLS. Every
//! method either refuses an illegal transition with a named error or changes the
//! state, and nothing here can move value. The economy lives in
//! [`crate::state::L2State`], which is the only thing that debits an account and
//! the only thing that consults a validator set. That split is deliberate: it is
//! what lets the transitions be tested exhaustively without a wallet, and what
//! keeps "who pays" from being tangled with "may this happen".
//!
//! The dispute window is a protocol parameter ([`crate::L2Config`]), not a field
//! an actor chooses. A submitter who could pick their own window could pick a
//! zero-length one; a worker who could pick it could make challenges impossible.

use srct_core::compute_ir::ComputeAttestation;
use srct_core::deliverable::{Attestation, ComputeDeliverable, Deliverable};
use srct_core::fees::split_flat_fee;
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    ClaimTaskPayload, DisputePayload, PostTaskPayload, SubmitResultPayload, Verdict,
    VWC_HASH_EXPIRED,
};
use srct_core::slash::VESTING_BLOCKS_MAINNET;

use srct_core::ser::{Reader, Writer};

use crate::error::{L2Error, L2Result};

/// Protocol parameters for the L2 task layer.
///
/// All three are network-wide rather than per-task, because a value an actor
/// chooses is a value an actor can choose badly (a zero challenge window is not
/// a challenge window). `dispute_window` is how long a submitted result can be
/// challenged, and also how long a filed dispute has to be resolved;
/// `vesting_period` is the M2 vesting horizon for a fraud slash, taken from
/// `srct_core::slash` so L2 slashing and M2 cannot drift apart;
/// `whistleblower_bounty_percent` is the share of a slashed deposit paid to a
/// successful challenger out of the PSCB reserve (SPEC.md §15.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Config {
    /// Chain this config (and the state built from it) belongs to. The
    /// expected network for `Settle` verification: a settle aggregate signs
    /// its network, and `apply` refuses one naming another. Wired from
    /// `NetworkParams::network_id` by the node, like the exit height below.
    pub network_id: String,
    pub dispute_window: u64,
    pub vesting_period: u64,
    /// Whole percent, 0..=100. Not a basis-point value because the bounty is a
    /// coarse incentive, not a fee split that has to reconcile to the satoshi.
    pub whistleblower_bounty_percent: u64,
    /// First L1 height at which an exit may be queued (approved P1). `0`
    /// means the profile never activates exits — queueing is refused rather
    /// than encumbering funds with no release. Wired from
    /// `NetworkParams::exit_activation_height` by the node; the constructors
    /// below carry `0` and the node overrides per profile.
    pub exit_activation_height: u64,
    /// Maximum total exit principal per `exit_window_blocks` window. Wired
    /// from `NetworkParams::max_exit_window_sat`; `0` disables. A refused
    /// queue keeps its funds — the owner retries in the next window.
    pub max_exit_window_sat: u64,
    /// Length of the exit window in blocks. Wired from
    /// `NetworkParams::exit_window_blocks`.
    pub exit_window_blocks: u64,
    /// Maximum exit principal one owner may queue per window. Wired from
    /// `NetworkParams::max_exit_per_owner_window_sat`; `0` disables the
    /// sub-cap, leaving the global cap as the only bound. Bounds one owner's
    /// share of the window so a filler cannot starve every other owner.
    pub max_exit_per_owner_window_sat: u64,
    /// Exits at or above this principal wait an additional
    /// `large_exit_extra_delay_blocks`. Wired from
    /// `NetworkParams::large_exit_threshold_sat`; `0` disables.
    pub large_exit_threshold_sat: u64,
    /// Extra maturity blocks for large exits. Wired from
    /// `NetworkParams::large_exit_extra_delay_blocks`.
    pub large_exit_extra_delay_blocks: u64,
    /// First L1 height at which CreditOpenV2 (borrower-consented) is required.
    /// `0` means never. Wired from `NetworkParams::credit_consent_activation_height`.
    pub credit_consent_activation_height: u64,
    /// Maximum collateral as a multiple of required collateral (e.g. 2 = max 2x).
    /// `0` means no cap (pre-activation behavior).
    pub credit_max_collateral_multiple: u64,
    /// Maximum term in blocks (deadline_height - height). `0` means no cap.
    pub credit_max_term_blocks: u64,
    /// Minimum window_blocks. `0` means no minimum (pre-activation behavior).
    pub credit_min_window_blocks: u64,
    /// First L1 height at which guarded accounts may be created (Phase 3).
    /// `0` means never.
    pub guarded_activation_height: u64,
    /// Grant-activation delay D for guarded accounts (blocks).
    pub guarded_grant_delay_blocks: u64,
    /// Maximum grant lifetime for guarded accounts (blocks).
    pub guarded_max_grant_lifetime_blocks: u64,
    /// Balance-relative outflow cap in basis points per window.
    pub guarded_outflow_cap_bps: u64,
    /// Outflow window length in blocks.
    pub guarded_outflow_window_blocks: u64,
    /// Guarded-exit delay D (blocks), shared with L1 consensus. A guarded
    /// exit may only be cancelled while `tip < queued_height + D`, and a
    /// guarded L1 claim must prove the record against a block at or after
    /// `queued_height + D`. Must equal
    /// `NetworkParams::guarded_exit_delay_blocks` (wired by the node); the
    /// two sides sharing one constant is what makes the cancel/claim race
    /// decide deterministically by block order.
    pub guarded_exit_delay_blocks: u64,
    /// Single-spend amount above which a guarded account needs the guardian's
    /// co-signature on the spend. `0` means never required (tier disabled).
    pub guarded_approval_threshold_sat: u64,
}

impl L2Config {
    /// Check the documented ranges: the bounty is a whole percent
    /// (`0..=100`, see the field doc), and a zero dispute window is not a
    /// window — nothing could ever be challenged inside it.
    pub fn validate(&self) -> L2Result<()> {
        if self.whistleblower_bounty_percent > 100 {
            return Err(L2Error::BadConfig("whistleblower bounty over 100 percent"));
        }
        if self.dispute_window == 0 {
            return Err(L2Error::BadConfig("dispute window must be nonzero"));
        }
        // Exit throttle pairing mirrors `NetworkParams::validate`: a cap
        // without a window (or a threshold without its delay) is a half-rule.
        if (self.max_exit_window_sat == 0) != (self.exit_window_blocks == 0) {
            return Err(L2Error::BadConfig(
                "exit window cap and length must be set together",
            ));
        }
        // Per-owner sub-cap mirrors `NetworkParams::validate`: a share
        // bigger than the whole is nonsense, and a share of a window that
        // does not exist is a half-rule.
        if self.max_exit_per_owner_window_sat > self.max_exit_window_sat {
            return Err(L2Error::BadConfig(
                "exit per-owner cap must not exceed the window cap",
            ));
        }
        if self.max_exit_per_owner_window_sat > 0 && self.exit_window_blocks == 0 {
            return Err(L2Error::BadConfig(
                "exit per-owner cap needs a window length",
            ));
        }
        if (self.large_exit_threshold_sat == 0) != (self.large_exit_extra_delay_blocks == 0) {
            return Err(L2Error::BadConfig(
                "large exit threshold and delay must be set together",
            ));
        }
        // Guarded caps: basis points are a fraction of 10_000; anything above
        // is nonsense. Zero disables each guarded feature (pre-activation).
        if self.guarded_outflow_cap_bps > 10_000 {
            return Err(L2Error::BadConfig(
                "guarded outflow cap exceeds 100 percent",
            ));
        }
        // Cap/window pairing: a cap with no window (or vice versa) is a half-rule.
        if (self.guarded_outflow_cap_bps == 0) != (self.guarded_outflow_window_blocks == 0) {
            return Err(L2Error::BadConfig(
                "guarded outflow cap and window must be set together",
            ));
        }
        Ok(())
    }

    /// Production values: a ~100-block (~17 hour) challenge window and the
    /// one-year M2 vesting period.
    pub fn mainnet() -> Self {
        L2Config {
            network_id: "srct/mainnet".to_string(),
            dispute_window: 100,
            vesting_period: VESTING_BLOCKS_MAINNET,
            whistleblower_bounty_percent: 25,
            exit_activation_height: 0,
            max_exit_window_sat: 0,
            exit_window_blocks: 0,
            max_exit_per_owner_window_sat: 0,
            large_exit_threshold_sat: 0,
            large_exit_extra_delay_blocks: 0,
            credit_consent_activation_height: 0,
            credit_max_collateral_multiple: 0,
            credit_max_term_blocks: 0,
            credit_min_window_blocks: 0,
            guarded_activation_height: 0,
            guarded_grant_delay_blocks: 0,
            guarded_max_grant_lifetime_blocks: 0,
            guarded_outflow_cap_bps: 0,
            guarded_outflow_window_blocks: 0,
        guarded_exit_delay_blocks: 0,
        guarded_approval_threshold_sat: 0,
        }
    }

    /// The `mini` profile's shortened window, so a dispute can be resolved inside
    /// a test run. The bounty share is identical to mainnet: it is an incentive,
    /// not a timing parameter, and a test that used a different share would be
    /// testing a different rule.
    pub fn mini() -> Self {
        L2Config {
            network_id: "srct/mini".to_string(),
            dispute_window: 5,
            vesting_period: srct_core::slash::VESTING_BLOCKS_MINI,
            whistleblower_bounty_percent: 25,
            exit_activation_height: 0,
            max_exit_window_sat: 0,
            exit_window_blocks: 0,
            max_exit_per_owner_window_sat: 0,
            large_exit_threshold_sat: 0,
            large_exit_extra_delay_blocks: 0,
            credit_consent_activation_height: 0,
            credit_max_collateral_multiple: 0,
            credit_max_term_blocks: 0,
            credit_min_window_blocks: 0,
            guarded_activation_height: 0,
            guarded_grant_delay_blocks: 0,
            guarded_max_grant_lifetime_blocks: 0,
            guarded_outflow_cap_bps: 0,
            guarded_outflow_window_blocks: 0,
        guarded_exit_delay_blocks: 0,
        guarded_approval_threshold_sat: 0,
        }
    }
}

/// A task's lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractState<A = ComputeAttestation> {
    Open,
    InProgress {
        claimed_at: u64,
    },
    ResultSubmitted {
        result_hash: Hash,
        submitted_at: u64,
        attestation: A,
    },
    Disputed(DisputeChallenge<A>),
    Settled(SettlementOutcome),
    Expired(ExpiryOutcome),
}

impl<A> ContractState<A> {
    pub fn name(&self) -> &'static str {
        match self {
            ContractState::Open => "Open",
            ContractState::InProgress { .. } => "InProgress",
            ContractState::ResultSubmitted { .. } => "ResultSubmitted",
            ContractState::Disputed(_) => "Disputed",
            ContractState::Settled(_) => "Settled",
            ContractState::Expired(_) => "Expired",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, ContractState::Settled(_) | ContractState::Expired(_))
    }
}

/// A filed challenge.
///
/// Both sides of the dispute are kept: `against_result` and `against_attestation`
/// are the challenged submission, and `counter_result` /
/// `counter_attestation` the challenger's answer. That makes a `Disputed`
/// contract self-describing, so the arbitration engine can read complete
/// evidence from the contract alone rather than reaching back into a prior
/// state the contract no longer carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeChallenge<A = ComputeAttestation> {
    pub challenger: Address,
    pub against_result: Hash,
    pub against_attestation: A,
    pub counter_result: Hash,
    pub counter_attestation: A,
    pub deposit_sat: u64,
    pub filed_at: u64,
}

/// The value movements a settlement implies.
///
/// Named fields rather than a netted number on purpose: a caller (or an auditor)
/// has to be able to see *why* value moved. Every field is applied by
/// `L2State::apply_settle`; none of them are applied here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SettlementOutcome {
    pub verdict: Verdict,
    /// Escrow paid to the worker minus the settle fee.
    pub worker_paid: u64,
    /// Deposit returned to the worker (only when the worker was right).
    pub worker_deposit_returned: u64,
    /// Deposit routed to the M2 slash vault (fraud).
    pub worker_deposit_slashed: u64,
    /// Escrow returned to the submitter (fraud or expiry).
    pub submitter_refunded: u64,
    /// Deposit returned to the challenger (challenge upheld).
    pub challenger_refunded: u64,
    /// Deposit destroyed because the challenge failed.
    pub challenger_deposit_burned: u64,
    /// Deposit destroyed in full (expiry, no vest).
    pub worker_deposit_burned: u64,
    pub fee_burned: u64,
    pub fee_pscb: u64,
    pub at_height: u64,
}

/// The value movements of an implicit expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExpiryOutcome {
    pub submitter_refunded: u64,
    pub worker_deposit_burned: u64,
    pub at_height: u64,
}

/// The general escrowed-service contract.
///
/// `D` is the deliverable being adjudicated and `A` the worker's signed claim
/// about it. Everything above them - escrow, bonding, the dispute window, the
/// settlement arithmetic - is identical for every `D`, which is the point: the
/// trust primitive is general and only the *predicate* varies.
///
/// [`TaskContract`] is the compute instantiation, and it is a type alias rather
/// than a wrapper, so there is exactly one settlement path in the tree
/// (`docs/roadmap-agent-economy.md` D3). A second implementation sitting beside
/// this one would make the abstraction cosmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContract<D = ComputeDeliverable, A = ComputeAttestation> {
    pub task_id: Hash,
    pub submitter: Address,
    pub worker: Option<Address>,
    pub deliverable: D,
    pub payment_sat: u64,
    pub worker_deposit_sat: u64,
    pub deadline_height: u64,
    pub dispute_window: u64,
    pub nonce: u64,
    pub state: ContractState<A>,
}

/// The compute instantiation of [`ServiceContract`]: escrow against a
/// `ComputeTask`, adjudicated by the canonical CPU reference.
pub type TaskContract = ServiceContract<ComputeDeliverable, ComputeAttestation>;

/// Everything a *general* service contract is opened with.
///
/// The same fields `TaskContract::new` takes from a compute `PostTaskPayload`,
/// but without the compute payload, so a non-compute service (a translation, a
/// review, a delivery) is opened through the same validated path rather than by
/// struct-literal assembly in a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContractSpec<D> {
    /// The service's identity: derived from submitter, service and nonce.
    pub task_id: Hash,
    /// Who funds the escrow.
    pub submitter: Address,
    /// The deliverable the contract is judged against.
    pub deliverable: D,
    /// Escrow amount. Zero is refused: an escrow for nothing is not a contract.
    pub payment_sat: u64,
    /// Bond the worker posts when claiming.
    pub worker_deposit_sat: u64,
    /// Last height at which the work may be delivered.
    pub deadline_height: u64,
    /// Heights after delivery in which a challenge may be raised.
    pub dispute_window: u64,
    /// Per-contract nonce, so two contracts with otherwise identical fields
    /// are distinct.
    pub nonce: u64,
}

impl<D, A> ServiceContract<D, A> {
    /// Open a **general** service contract under any deliverable type.
    ///
    /// This is the constructor a non-compute deliverable goes through, and it
    /// validates exactly what the compute path validates: a positive escrow, a
    /// real deadline, a dispute window that fits before the deadline, and a
    /// distinct id. A caller that cannot be bothered with those is not opening a
    /// contract, it is assembling a struct.
    ///
    /// Invalid specs are refused by name ([`L2Error::InvalidContractSpec`])
    /// rather than panicked: malformed input is a deterministic rejection, not
    /// a crash, in the L2 consensus layer.
    pub fn open(spec: ServiceContractSpec<D>) -> L2Result<Self> {
        if spec.payment_sat == 0 {
            return Err(L2Error::ZeroAmount("payment_sat"));
        }
        if spec.deadline_height == 0 {
            return Err(L2Error::InvalidContractSpec("deadline_height is zero"));
        }
        if spec.dispute_window >= spec.deadline_height {
            return Err(L2Error::InvalidContractSpec(
                "dispute_window reaches the deadline",
            ));
        }
        Ok(ServiceContract {
            task_id: spec.task_id,
            submitter: spec.submitter,
            worker: None,
            deliverable: spec.deliverable,
            payment_sat: spec.payment_sat,
            worker_deposit_sat: spec.worker_deposit_sat,
            deadline_height: spec.deadline_height,
            dispute_window: spec.dispute_window,
            nonce: spec.nonce,
            state: ContractState::Open,
        })
    }
}

impl<D, A> ServiceContract<D, A> {
    /// The canonical result this contract's deliverable must produce.
    ///
    /// Rule 3 of the predicate discipline: computed from the contract's own
    /// committed fields, never taken from a caller. The id passed is the
    /// *contract's*, not the deliverable's own - see
    /// `Deliverable::reference` for why that distinction is load-bearing.
    pub fn reference(&self) -> Hash
    where
        D: Deliverable,
    {
        self.deliverable.reference(&self.task_id)
    }
}

/// The compute wire entry points.
///
/// These forward to the generic transitions, so the L2 payload types stay
/// concrete while the logic exists exactly once.
impl TaskContract {
    /// Record the worker's result from a `SubmitResult` payload.
    ///
    /// The attestation must bind to this task, to the signing worker, and to the
    /// result hash in the same payload. Its own `signature` field is not
    /// independently verifiable (an attestation carries an address, not a key);
    /// the authoritative authentication is the enclosing `SubmitResult` payload's
    /// signature, which covers the attestation bytes.
    pub fn submit_result(
        &mut self,
        actor: Address,
        submit: &SubmitResultPayload,
        current_height: u64,
    ) -> L2Result<()> {
        if submit.task_id != self.task_id {
            return Err(L2Error::BadAttestation("task_id"));
        }
        self.submit(
            actor,
            submit.result_hash,
            submit.attestation.clone(),
            current_height,
        )
    }

    /// File a challenge against a submitted result from a `Dispute` payload.
    pub fn file_dispute(
        &mut self,
        actor: Address,
        dispute: &DisputePayload,
        current_height: u64,
    ) -> L2Result<()> {
        if dispute.task_id != self.task_id || actor != dispute.challenger {
            return Err(L2Error::BadAuthorization);
        }
        self.dispute(
            actor,
            dispute.counter_result,
            dispute.counter_attestation.clone(),
            dispute.challenge_deposit_sat,
            current_height,
        )
    }
}

/// Construction from a compute post is the only compute-specific step.
///
/// Everything below is deliverable-agnostic: this is the one place a concrete
/// type has to be named, and it is here rather than in the state machine so that
/// the transitions themselves work for any `Deliverable`.
impl TaskContract {
    /// Create an `Open` contract from a post.
    ///
    /// Rejects a task id that is not the derivable one, a deadline that is
    /// already in the past, a deadline that disagrees with the M3 envelope's own
    /// expiry (two deadlines for one task is an ambiguity, not a feature), and a
    /// zero payment.
    pub fn new(post: &PostTaskPayload, current_height: u64, dispute_window: u64) -> L2Result<Self> {
        if post.task_id != post.derived_task_id() {
            return Err(L2Error::BadAttestation("task_id is not the derived id"));
        }
        if post.payment_sat == 0 {
            return Err(L2Error::ZeroAmount("payment_sat"));
        }
        // No dust escrows: an explicit `Correct`/`Expired` settlement
        // refuses when the escrow cannot cover the settle fee floor, so a
        // task posted below it could never settle explicitly and would rely
        // on implicit paths. Refuse the post instead.
        let fee_floor = srct_core::l2::settle_fee_sat(post.payment_sat);
        if post.payment_sat < fee_floor {
            return Err(L2Error::AmountTooSmallForFee {
                available: post.payment_sat,
                fee: fee_floor,
            });
        }
        if post.deadline_height != post.compute_task.expiry_height {
            return Err(L2Error::DeadlineMismatch);
        }
        if post.deadline_height <= current_height {
            return Err(L2Error::TaskExpired);
        }
        if !post.compute_task.is_active(current_height) {
            return Err(L2Error::TaskExpired);
        }
        Ok(TaskContract {
            task_id: post.task_id,
            submitter: post.submitter,
            worker: None,
            deliverable: ComputeDeliverable(post.compute_task.clone()),
            payment_sat: post.payment_sat,
            worker_deposit_sat: 0,
            deadline_height: post.deadline_height,
            dispute_window,
            nonce: post.nonce,
            state: ContractState::Open,
        })
    }
}

/// The state machine, deliverable-agnostic.
///
/// The transitions below are shared by every `Deliverable`. They were written
/// against `ComputeAttestation` until this impl block was made generic, which is
/// why the compute path is a type alias rather than a parallel implementation:
/// there is one set of transitions, and a second deliverable drives the same ones
/// (`docs/roadmap-agent-economy.md` D3).
impl<D, A> ServiceContract<D, A>
where
    D: Deliverable,
    A: Attestation,
{
    /// Reserve the task for `actor`.
    pub fn claim(
        &mut self,
        actor: Address,
        claim: &ClaimTaskPayload,
        current_height: u64,
    ) -> L2Result<()> {
        if !matches!(self.state, ContractState::Open) {
            return Err(self.illegal("claim"));
        }
        if claim.task_id != self.task_id || actor != claim.worker {
            return Err(L2Error::BadAuthorization);
        }
        if current_height > self.deadline_height {
            return Err(L2Error::TaskExpired);
        }
        if claim.worker_deposit_sat == 0 {
            return Err(L2Error::ZeroAmount("worker_deposit_sat"));
        }
        // The deposit is the *entire* penalty available for a fraud verdict, so
        // it must always be able to cover the settle fee. If it were not, a
        // worker could claim with a dust deposit, submit a wrong result, and
        // then be structurally unslashable: the `Fraudulent` arm of
        // `settle_inner` refuses when `deposit < fee`, and once a result is
        // submitted `Expired` is no longer reachable either, leaving
        // auto-settle `Correct` as the only settlement left. The worker would
        // collect the whole escrow for work that is provably wrong, and the
        // penalty would be a number they chose in advance.
        //
        // `settle_fee_sat` is the same function `apply_settle` charges from, and
        // `payment_sat` is fixed at post time, so the floor is stable for the
        // life of the contract and this check cannot be dodged later.
        let min_deposit = srct_core::l2::settle_fee_sat(self.payment_sat);
        if claim.worker_deposit_sat < min_deposit {
            return Err(L2Error::AmountTooSmallForFee {
                available: claim.worker_deposit_sat,
                fee: min_deposit,
            });
        }
        self.worker = Some(actor);
        self.worker_deposit_sat = claim.worker_deposit_sat;
        self.state = ContractState::InProgress {
            claimed_at: current_height,
        };
        Ok(())
    }

    /// Record a result with an already-validated attestation of any kind.
    ///
    /// The generic step of the transition. [`TaskContract::submit_result`] is
    /// the compute wire form; this is what a second deliverable drives, so the
    /// validation below exists once rather than twice.
    pub fn submit(
        &mut self,
        actor: Address,
        result_hash: Hash,
        attestation: A,
        current_height: u64,
    ) -> L2Result<()> {
        if !matches!(self.state, ContractState::InProgress { .. }) {
            return Err(self.illegal("submit a result"));
        }
        if Some(actor) != self.worker {
            return Err(L2Error::BadAuthorization);
        }
        if attestation.worker_address() != actor {
            return Err(L2Error::BadAttestation("attestation worker_address"));
        }
        if current_height > self.deadline_height {
            return Err(L2Error::TaskExpired);
        }
        if attestation.task_id() != self.task_id {
            return Err(L2Error::BadAttestation("attestation task_id"));
        }
        if attestation.result_hash() != result_hash {
            return Err(L2Error::BadAttestation("attestation result_hash"));
        }
        // An all-zero result hash is the expired placeholder, not a commitment.
        // Allowing it would make a certified-correct settlement and an expired
        // one indistinguishable in the settle record, which is exactly the
        // collision Phase 4's certificates must not have (SPEC.md §17.6).
        if result_hash == VWC_HASH_EXPIRED {
            return Err(L2Error::BadAttestation(
                "result_hash is the expired placeholder; a result must commit to real output",
            ));
        }
        if !attestation.is_signed() {
            return Err(L2Error::BadAttestation("attestation is unsigned"));
        }
        self.state = ContractState::ResultSubmitted {
            result_hash,
            submitted_at: current_height,
            attestation,
        };
        Ok(())
    }

    /// File a challenge with attestations of any kind - the generic step of the
    /// transition. [`TaskContract::file_dispute`] is the compute wire form.
    pub fn dispute(
        &mut self,
        actor: Address,
        counter_result: Hash,
        counter_attestation: A,
        challenge_deposit_sat: u64,
        current_height: u64,
    ) -> L2Result<()> {
        let (result_hash, submitted_at, against_attestation) = match &self.state {
            ContractState::ResultSubmitted {
                result_hash,
                submitted_at,
                attestation,
            } => (*result_hash, *submitted_at, attestation.clone()),
            _ => return Err(self.illegal("file a dispute")),
        };
        if counter_attestation.task_id() != self.task_id {
            return Err(L2Error::BadAttestation("counter attestation task_id"));
        }
        if counter_attestation.result_hash() != counter_result {
            return Err(L2Error::BadAttestation("counter attestation result_hash"));
        }
        if current_height > submitted_at.saturating_add(self.dispute_window) {
            return Err(L2Error::DisputeWindowClosed);
        }
        if counter_result == result_hash {
            return Err(L2Error::DisputeAgreesWithResult);
        }
        if challenge_deposit_sat == 0 {
            return Err(L2Error::ZeroAmount("challenge_deposit_sat"));
        }
        // The counter-attestation belongs to the challenger: without this
        // binding anyone could file a dispute quoting someone else's
        // attestation, and the bounty would accrue to the filer rather than
        // the attester who did the work.
        if counter_attestation.worker_address() != actor {
            return Err(L2Error::BadAttestation(
                "counter attestation worker_address",
            ));
        }
        if !counter_attestation.is_signed() {
            return Err(L2Error::BadAttestation("counter attestation is unsigned"));
        }
        self.state = ContractState::Disputed(DisputeChallenge {
            challenger: actor,
            against_result: result_hash,
            against_attestation,
            counter_result,
            counter_attestation,
            deposit_sat: challenge_deposit_sat,
            filed_at: current_height,
        });
        Ok(())
    }

    /// The result hash that a `Correct` verdict must name, if this contract is
    /// currently settleable as correct.
    pub fn correct_settlement_hash(&self, current_height: u64) -> Option<Hash> {
        match &self.state {
            ContractState::ResultSubmitted {
                result_hash,
                submitted_at,
                ..
            } if current_height > submitted_at.saturating_add(self.dispute_window) => {
                Some(*result_hash)
            }
            ContractState::Disputed(c) => Some(c.against_result),
            _ => None,
        }
    }

    /// True when the dispute window has elapsed with no challenge, so the
    /// contract settles itself.
    pub fn due_for_auto_settle(&self, current_height: u64) -> bool {
        self.correct_settlement_hash(current_height).is_some()
            && matches!(self.state, ContractState::ResultSubmitted { .. })
    }

    /// Settle a `Correct` verdict with no fee. Only the implicit path (the
    /// dispute window closing) uses this; an explicit `Settle` transaction pays
    /// the D3 fee through [`TaskContract::settle`].
    pub fn auto_settle_correct(&mut self, current_height: u64) -> L2Result<SettlementOutcome> {
        let hash = self
            .correct_settlement_hash(current_height)
            .filter(|_| matches!(self.state, ContractState::ResultSubmitted { .. }))
            .ok_or_else(|| self.illegal("auto-settle"))?;
        self.settle_inner(Verdict::Correct, hash, current_height, 0)
    }

    /// True when a filed dispute has gone unresolved past its resolution window.
    ///
    /// The window is the same length as the filing window, measured from
    /// `filed_at`. A challenge that is filed and then abandoned does not stall
    /// the task forever, and it is not free: lapsing burns the challenger's
    /// deposit exactly as a lost challenge would.
    pub fn due_for_dispute_lapse(&self, current_height: u64) -> bool {
        match &self.state {
            ContractState::Disputed(c) => {
                current_height > c.filed_at.saturating_add(self.dispute_window)
            }
            _ => false,
        }
    }

    /// Apply the implicit settlement of a lapsed dispute: the submitted result
    /// stands, the challenger's deposit is burned, and no fee is charged because
    /// nothing was transacted.
    pub fn lapse_dispute(&mut self, current_height: u64) -> L2Result<SettlementOutcome> {
        let hash = match &self.state {
            ContractState::Disputed(c) if self.due_for_dispute_lapse(current_height) => {
                c.against_result
            }
            ContractState::Disputed(_) => return Err(L2Error::DisputeWindowClosed),
            _ => return Err(self.illegal("lapse a dispute")),
        };
        self.settle_inner(Verdict::Correct, hash, current_height, 0)
    }

    /// Apply a validator verdict, returning the value movements it implies.
    pub fn settle(
        &mut self,
        verdict: Verdict,
        vwc_hash: Hash,
        current_height: u64,
        fee: u64,
    ) -> L2Result<SettlementOutcome> {
        self.settle_inner(verdict, vwc_hash, current_height, fee)
    }

    fn settle_inner(
        &mut self,
        verdict: Verdict,
        vwc_hash: Hash,
        current_height: u64,
        fee: u64,
    ) -> L2Result<SettlementOutcome> {
        let escrow = self.payment_sat;
        let deposit = self.worker_deposit_sat;
        let challenge_deposit = match &self.state {
            ContractState::Disputed(c) => c.deposit_sat,
            _ => 0,
        };
        let split = split_flat_fee(fee);

        let mut outcome = SettlementOutcome {
            verdict,
            fee_burned: split.burned,
            fee_pscb: split.pscb,
            at_height: current_height,
            ..Default::default()
        };

        match verdict {
            Verdict::Correct => {
                let expected = match &self.state {
                    ContractState::ResultSubmitted { .. } => self
                        .correct_settlement_hash(current_height)
                        .ok_or(L2Error::DisputeWindowClosed)?,
                    ContractState::Disputed(c) => c.against_result,
                    _ => return Err(self.illegal("settle as Correct")),
                };
                if vwc_hash != expected {
                    return Err(L2Error::BadVwcHash);
                }
                if escrow < fee {
                    return Err(L2Error::AmountTooSmallForFee {
                        available: escrow,
                        fee,
                    });
                }
                outcome.worker_paid = escrow - fee;
                outcome.worker_deposit_returned = deposit;
                if matches!(self.state, ContractState::Disputed(_)) {
                    // The challenger was wrong: their deposit is destroyed in
                    // full, which is what makes a baseless challenge costly.
                    outcome.challenger_deposit_burned = challenge_deposit;
                }
            }
            Verdict::Fraudulent => {
                let challenge = match &self.state {
                    ContractState::Disputed(c) => c,
                    _ => return Err(self.illegal("settle as Fraudulent")),
                };
                if vwc_hash != challenge.counter_result {
                    return Err(L2Error::BadVwcHash);
                }
                if deposit < fee {
                    return Err(L2Error::AmountTooSmallForFee {
                        available: deposit,
                        fee,
                    });
                }
                outcome.submitter_refunded = escrow;
                outcome.challenger_refunded = challenge_deposit;
                // Fee comes out of the worker's deposit first: the submitter was
                // defrauded and deserves a whole refund, and the losing worker is
                // the party whose conduct created the cost.
                outcome.worker_deposit_slashed = deposit - fee;
            }
            Verdict::Expired => {
                // Expiry is normally implicit and free (`try_expire`). An explicit
                // Expired verdict exists so the arbitrator set can close a task a
                // vanished worker never delivered, and it pays the settle fee like
                // any other explicit settlement. The deadline guard matches
                // `try_expire`: a quorum cannot kill a live task early,
                // refunding the submitter and burning the worker's deposit
                // while the worker still had time to deliver.
                match &self.state {
                    ContractState::Open | ContractState::InProgress { .. } => {}
                    _ => return Err(self.illegal("settle as Expired")),
                }
                if current_height <= self.deadline_height {
                    // Same variant `try_expire`-adjacent paths use for "not
                    // yet open": the window for expiry has not opened.
                    return Err(L2Error::DisputeWindowClosed);
                }
                if vwc_hash != VWC_HASH_EXPIRED {
                    return Err(L2Error::BadVwcHash);
                }
                if deposit == 0 {
                    if escrow < fee {
                        return Err(L2Error::AmountTooSmallForFee {
                            available: escrow,
                            fee,
                        });
                    }
                    outcome.submitter_refunded = escrow - fee;
                } else {
                    if deposit < fee {
                        return Err(L2Error::AmountTooSmallForFee {
                            available: deposit,
                            fee,
                        });
                    }
                    outcome.submitter_refunded = escrow;
                    // No vest for an expiry: a smaller penalty than a fraud slash.
                    outcome.worker_deposit_burned = deposit - fee;
                }
            }
        }

        self.state = ContractState::Settled(outcome);
        Ok(outcome)
    }

    /// Implicit expiry: the deadline passed with no result submitted.
    ///
    /// Returns the movements when the transition happened, `None` otherwise.
    /// No fee is charged — nothing was transacted, the clock simply ran out.
    pub fn try_expire(&mut self, current_height: u64) -> Option<ExpiryOutcome> {
        let outcome = match &self.state {
            ContractState::Open if current_height > self.deadline_height => ExpiryOutcome {
                submitter_refunded: self.payment_sat,
                worker_deposit_burned: 0,
                at_height: current_height,
            },
            ContractState::InProgress { .. } if current_height > self.deadline_height => {
                ExpiryOutcome {
                    submitter_refunded: self.payment_sat,
                    worker_deposit_burned: self.worker_deposit_sat,
                    at_height: current_height,
                }
            }
            _ => return None,
        };
        self.state = ContractState::Expired(outcome);
        Some(outcome)
    }

    /// The challenger, if one is on file. Read before settling, because a
    /// settled contract no longer carries the challenge.
    pub fn challenger(&self) -> Option<Address> {
        match &self.state {
            ContractState::Disputed(c) => Some(c.challenger),
            _ => None,
        }
    }

    /// Value still held by this contract, in satoshis.
    ///
    /// This is the contract's side of the conservation invariant: everything an
    /// account paid in and the contract has not yet released.
    pub fn locked_total(&self) -> u64 {
        match &self.state {
            ContractState::Open => self.payment_sat,
            ContractState::InProgress { .. } | ContractState::ResultSubmitted { .. } => {
                self.payment_sat.saturating_add(self.worker_deposit_sat)
            }
            ContractState::Disputed(c) => self
                .payment_sat
                .saturating_add(self.worker_deposit_sat)
                .saturating_add(c.deposit_sat),
            ContractState::Settled(_) | ContractState::Expired(_) => 0,
        }
    }

    fn illegal(&self, action: &'static str) -> L2Error {
        L2Error::IllegalTransition {
            state: self.state.name(),
            action,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire encoding (SPEC.md §19.2): what a node hands a remote observer
// ---------------------------------------------------------------------------

/// `ContractState` tags on the wire. Total: a byte outside this range is
/// refused rather than coerced into some other state.
const WIRE_OPEN: u8 = 0;
const WIRE_IN_PROGRESS: u8 = 1;
const WIRE_RESULT_SUBMITTED: u8 = 2;
const WIRE_DISPUTED: u8 = 3;
const WIRE_SETTLED: u8 = 4;
const WIRE_EXPIRED: u8 = 5;

impl DisputeChallenge {
    pub(crate) fn encode(&self, w: &mut Writer) {
        w.fixed(&self.challenger)
            .fixed(&self.against_result)
            .raw(&self.against_attestation.encode())
            .fixed(&self.counter_result)
            .raw(&self.counter_attestation.encode())
            .u64le(self.deposit_sat)
            .u64le(self.filed_at);
    }

    pub(crate) fn decode(r: &mut Reader<'_>, task_id: &Hash) -> L2Result<Self> {
        let challenger = r.fixed().map_err(L2Error::Codec)?;
        let against_result: Hash = r.fixed().map_err(L2Error::Codec)?;
        let against_attestation = ComputeAttestation::from_reader(r).map_err(L2Error::Codec)?;
        let counter_result: Hash = r.fixed().map_err(L2Error::Codec)?;
        let counter_attestation = ComputeAttestation::from_reader(r).map_err(L2Error::Codec)?;
        let deposit_sat = r.u64le().map_err(L2Error::Codec)?;
        let filed_at = r.u64le().map_err(L2Error::Codec)?;
        // The protocol only ever writes a challenge whose evidence names this
        // task (both attestations are checked at filing), so a blob that
        // disagrees was not produced by a node.
        if against_attestation.task_id() != *task_id {
            return Err(L2Error::BadAttestation(
                "wire: challenged attestation names another task",
            ));
        }
        if counter_attestation.task_id() != *task_id {
            return Err(L2Error::BadAttestation(
                "wire: counter attestation names another task",
            ));
        }
        Ok(DisputeChallenge {
            challenger,
            against_result,
            against_attestation,
            counter_result,
            counter_attestation,
            deposit_sat,
            filed_at,
        })
    }
}

impl SettlementOutcome {
    pub(crate) fn encode(&self, w: &mut Writer) {
        w.u8(self.verdict.to_wire())
            .u64le(self.worker_paid)
            .u64le(self.worker_deposit_returned)
            .u64le(self.worker_deposit_slashed)
            .u64le(self.submitter_refunded)
            .u64le(self.challenger_refunded)
            .u64le(self.challenger_deposit_burned)
            .u64le(self.worker_deposit_burned)
            .u64le(self.fee_burned)
            .u64le(self.fee_pscb)
            .u64le(self.at_height);
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> L2Result<Self> {
        let verdict =
            Verdict::from_wire(r.u8().map_err(L2Error::Codec)?).map_err(L2Error::Codec)?;
        Ok(SettlementOutcome {
            verdict,
            worker_paid: r.u64le().map_err(L2Error::Codec)?,
            worker_deposit_returned: r.u64le().map_err(L2Error::Codec)?,
            worker_deposit_slashed: r.u64le().map_err(L2Error::Codec)?,
            submitter_refunded: r.u64le().map_err(L2Error::Codec)?,
            challenger_refunded: r.u64le().map_err(L2Error::Codec)?,
            challenger_deposit_burned: r.u64le().map_err(L2Error::Codec)?,
            worker_deposit_burned: r.u64le().map_err(L2Error::Codec)?,
            fee_burned: r.u64le().map_err(L2Error::Codec)?,
            fee_pscb: r.u64le().map_err(L2Error::Codec)?,
            at_height: r.u64le().map_err(L2Error::Codec)?,
        })
    }
}

impl ExpiryOutcome {
    pub(crate) fn encode(&self, w: &mut Writer) {
        w.u64le(self.submitter_refunded)
            .u64le(self.worker_deposit_burned)
            .u64le(self.at_height);
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> L2Result<Self> {
        Ok(ExpiryOutcome {
            submitter_refunded: r.u64le().map_err(L2Error::Codec)?,
            worker_deposit_burned: r.u64le().map_err(L2Error::Codec)?,
            at_height: r.u64le().map_err(L2Error::Codec)?,
        })
    }
}

impl TaskContract {
    /// Canonical wire encoding of a whole contract.
    ///
    /// Self-delimiting: every nested piece is either fixed-size or written by
    /// its own decoder (`ComputeAttestation`), so `decode` never has to guess
    /// where a field ends. This is the transport a node serves a remote worker
    /// (SPEC.md §19.2); it carries no signature material of its own — a
    /// contract is state, not an actor's claim, so nothing here is signed.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256);
        w.fixed(&self.task_id).fixed(&self.submitter);
        match self.worker {
            Some(a) => {
                w.u8(1).fixed(&a);
            }
            None => {
                w.u8(0);
            }
        }
        w.raw(&self.deliverable.encode())
            .u64le(self.payment_sat)
            .u64le(self.worker_deposit_sat)
            .u64le(self.deadline_height)
            .u64le(self.dispute_window)
            .u64le(self.nonce);
        match &self.state {
            ContractState::Open => {
                w.u8(WIRE_OPEN);
            }
            ContractState::InProgress { claimed_at } => {
                w.u8(WIRE_IN_PROGRESS).u64le(*claimed_at);
            }
            ContractState::ResultSubmitted {
                result_hash,
                submitted_at,
                attestation,
            } => {
                w.u8(WIRE_RESULT_SUBMITTED)
                    .fixed(result_hash)
                    .u64le(*submitted_at)
                    .raw(&attestation.encode());
            }
            ContractState::Disputed(c) => {
                w.u8(WIRE_DISPUTED);
                c.encode(&mut w);
            }
            ContractState::Settled(o) => {
                w.u8(WIRE_SETTLED);
                o.encode(&mut w);
            }
            ContractState::Expired(o) => {
                w.u8(WIRE_EXPIRED);
                o.encode(&mut w);
            }
        }
        w.into_vec()
    }

    /// Decode [`TaskContract::encode`]. Bounded and fail-closed: an unknown
    /// state tag, a truncated field, trailing bytes, or an invariant the
    /// protocol itself enforces on every path that *writes* a contract (the
    /// attestation must name this task and this worker) is refused by name.
    /// A refusal produces no contract at all.
    pub fn decode(r: &mut Reader<'_>) -> L2Result<Self> {
        let task_id: Hash = r.fixed().map_err(L2Error::Codec)?;
        let submitter: Address = r.fixed().map_err(L2Error::Codec)?;
        let worker = match r.u8().map_err(L2Error::Codec)? {
            0 => None,
            1 => Some(r.fixed().map_err(L2Error::Codec)?),
            _ => return Err(L2Error::Codec(srct_core::Error::Malformed("worker flag"))),
        };
        let deliverable = ComputeDeliverable::decode(r)?;
        let payment_sat = r.u64le().map_err(L2Error::Codec)?;
        let worker_deposit_sat = r.u64le().map_err(L2Error::Codec)?;
        let deadline_height = r.u64le().map_err(L2Error::Codec)?;
        let dispute_window = r.u64le().map_err(L2Error::Codec)?;
        let nonce = r.u64le().map_err(L2Error::Codec)?;

        let tag = r.u8().map_err(L2Error::Codec)?;
        let state = match tag {
            WIRE_OPEN => ContractState::Open,
            WIRE_IN_PROGRESS => ContractState::InProgress {
                claimed_at: r.u64le().map_err(L2Error::Codec)?,
            },
            WIRE_RESULT_SUBMITTED => {
                let result_hash: Hash = r.fixed().map_err(L2Error::Codec)?;
                let submitted_at = r.u64le().map_err(L2Error::Codec)?;
                let attestation = ComputeAttestation::decode(r).map_err(L2Error::Codec)?;
                if attestation.task_id() != task_id {
                    return Err(L2Error::BadAttestation(
                        "wire: submitted attestation names another task",
                    ));
                }
                ContractState::ResultSubmitted {
                    result_hash,
                    submitted_at,
                    attestation,
                }
            }
            WIRE_DISPUTED => ContractState::Disputed(DisputeChallenge::decode(r, &task_id)?),
            WIRE_SETTLED => ContractState::Settled(SettlementOutcome::decode(r)?),
            WIRE_EXPIRED => ContractState::Expired(ExpiryOutcome::decode(r)?),
            other => {
                return Err(L2Error::Codec(srct_core::Error::Malformed(
                    if other <= WIRE_EXPIRED {
                        "unknown contract state tag"
                    } else {
                        "contract state tag out of range"
                    },
                )))
            }
        };

        // The invariant every write path holds: only `Open` has no worker, and
        // a submitted result is always attested by the contract's own worker.
        if matches!(state, ContractState::Open) && worker.is_some() {
            return Err(L2Error::Codec(srct_core::Error::Malformed(
                "wire: an open contract names a worker",
            )));
        }
        if matches!(
            state,
            ContractState::InProgress { .. } | ContractState::ResultSubmitted { .. }
        ) && worker.is_none()
        {
            return Err(L2Error::Codec(srct_core::Error::Malformed(
                "wire: a claimed contract names no worker",
            )));
        }
        if let ContractState::ResultSubmitted {
            result_hash,
            attestation,
            ..
        } = &state
        {
            let expected = worker.ok_or(L2Error::Codec(srct_core::Error::Malformed(
                "wire: unattested submission",
            )))?;
            if attestation.worker_address() != expected {
                return Err(L2Error::BadAttestation(
                    "wire: attestation is by someone other than the worker",
                ));
            }
            if attestation.result_hash() != *result_hash {
                return Err(L2Error::BadAttestation(
                    "wire: attestation disagrees with the submitted result",
                ));
            }
        }

        Ok(TaskContract {
            task_id,
            submitter,
            worker,
            deliverable,
            payment_sat,
            worker_deposit_sat,
            deadline_height,
            dispute_window,
            nonce,
            state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::compute_ir::{ComputeBackend, ComputeTask};
    use srct_core::l2::{derive_task_id, Auth};

    fn addr(n: u8) -> Address {
        [n; 20]
    }

    fn task_for(deadline: u64) -> ComputeTask {
        ComputeTask {
            task_id: [0x11u8; 32],
            ir_hash: [0x22u8; 32],
            input_hash: [0x33u8; 32],
            required_memory_bytes: 0,
            backend_hint: ComputeBackend::Cpu,
            reward_sat: 0,
            expiry_height: deadline,
            submit_height: 0,
        }
    }

    /// A post with an empty (unverified) authorization. Transitions never check
    /// signatures — that is `L2State`'s job — so these double as a statement of
    /// where the boundary is.
    fn post(submitter: Address, nonce: u64, payment: u64, deadline: u64) -> PostTaskPayload {
        let compute_task = task_for(deadline);
        let task_id = derive_task_id(&submitter, nonce, &compute_task.task_hash());
        PostTaskPayload {
            submitter,
            auth: Auth::default(),
            task_id,
            payment_sat: payment,
            nonce,
            deadline_height: deadline,
            compute_task,
        }
    }

    fn claim(worker: Address, task_id: Hash, deposit: u64) -> ClaimTaskPayload {
        ClaimTaskPayload {
            worker,
            auth: Auth::default(),
            task_id,
            backend: ComputeBackend::Cpu,
            worker_deposit_sat: deposit,
        }
    }

    fn attestation(worker: Address, task_id: Hash, result: Hash) -> ComputeAttestation {
        ComputeAttestation {
            task_id,
            result_hash: result,
            backend: ComputeBackend::Cpu,
            worker_address: worker,
            attest_height: 0,
            signature: vec![0x01],
        }
    }

    fn submit(worker: Address, task_id: Hash, result: Hash) -> SubmitResultPayload {
        SubmitResultPayload {
            worker,
            auth: Auth::default(),
            task_id,
            result_hash: result,
            attestation: attestation(worker, task_id, result),
        }
    }

    fn dispute(challenger: Address, task_id: Hash, counter: Hash, deposit: u64) -> DisputePayload {
        DisputePayload {
            challenger,
            auth: Auth::default(),
            task_id,
            counter_result: counter,
            counter_attestation: attestation(challenger, task_id, counter),
            challenge_deposit_sat: deposit,
        }
    }

    fn open_contract() -> TaskContract {
        let p = post(addr(1), 1, 5_000_000, 100);
        TaskContract::new(&p, 1, 5).unwrap()
    }

    #[test]
    fn a_new_contract_rejects_a_mismatched_deadline() {
        // Only the L2 deadline moves, so the derived task id is still valid and
        // the refusal must come from the deadline rule rather than the id rule.
        let mut p = post(addr(1), 1, 1_000, 100);
        p.deadline_height = 101;
        assert_eq!(
            p.task_id,
            p.derived_task_id(),
            "the setup must keep the id valid"
        );
        assert!(matches!(
            TaskContract::new(&p, 1, 5),
            Err(L2Error::DeadlineMismatch)
        ));
    }

    #[test]
    fn a_new_contract_rejects_a_borrowed_task_id_and_zero_payment() {
        let mut p = post(addr(1), 1, 1_000, 100);
        p.task_id = [0xEEu8; 32];
        assert!(matches!(
            TaskContract::new(&p, 1, 5),
            Err(L2Error::BadAttestation(_))
        ));

        let p = post(addr(1), 1, 0, 100);
        assert!(matches!(
            TaskContract::new(&p, 1, 5),
            Err(L2Error::ZeroAmount(_))
        ));

        let p = post(addr(1), 1, 1_000, 100);
        assert!(matches!(
            TaskContract::new(&p, 100, 5),
            Err(L2Error::TaskExpired)
        ));
    }

    #[test]
    fn happy_path_open_to_settled() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        assert!(matches!(c.state, ContractState::InProgress { .. }));
        assert_eq!(c.worker, Some(addr(2)));

        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(c.state, ContractState::ResultSubmitted { .. }));

        // Window is 5 blocks, submitted at 3, so height 9 is the first settled one.
        assert!(!c.due_for_auto_settle(8));
        assert!(c.due_for_auto_settle(9));

        let outcome = c.settle(Verdict::Correct, [0xAAu8; 32], 9, 20_000).unwrap();
        assert_eq!(outcome.worker_paid, 5_000_000 - 20_000);
        assert_eq!(outcome.worker_deposit_returned, 10_000);
        assert_eq!(outcome.fee_burned + outcome.fee_pscb, 20_000);
        assert!(matches!(c.state, ContractState::Settled(_)));
        assert_eq!(c.locked_total(), 0);
    }

    #[test]
    fn a_double_claim_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        assert!(matches!(
            c.claim(addr(3), &claim(addr(3), id, 10_000), 3),
            Err(L2Error::IllegalTransition { .. })
        ));
        assert_eq!(c.worker, Some(addr(2)));
    }

    #[test]
    fn a_claim_after_the_deadline_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        assert!(matches!(
            c.claim(addr(2), &claim(addr(2), id, 10_000), 101),
            Err(L2Error::TaskExpired)
        ));
    }

    #[test]
    fn only_the_claiming_worker_may_submit() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        assert!(matches!(
            c.submit_result(addr(3), &submit(addr(3), id, [1u8; 32]), 3),
            Err(L2Error::BadAuthorization)
        ));
        // And a submission whose attestation names someone else is refused too.
        let mut s = submit(addr(2), id, [1u8; 32]);
        s.attestation.worker_address = addr(9);
        assert!(matches!(
            c.submit_result(addr(2), &s, 3),
            Err(L2Error::BadAttestation(_))
        ));
    }

    #[test]
    fn a_result_after_the_deadline_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        assert!(matches!(
            c.submit_result(addr(2), &submit(addr(2), id, [1u8; 32]), 101),
            Err(L2Error::TaskExpired)
        ));
    }

    #[test]
    fn a_dispute_after_the_window_is_refused_but_inside_it_is_accepted() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();

        assert!(matches!(
            c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 9),
            Err(L2Error::DisputeWindowClosed)
        ));
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 8)
            .unwrap();
        assert!(matches!(c.state, ContractState::Disputed(_)));
    }

    #[test]
    fn a_dispute_that_agrees_with_the_result_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(
            c.file_dispute(addr(4), &dispute(addr(4), id, [0xAAu8; 32], 500), 4),
            Err(L2Error::DisputeAgreesWithResult)
        ));
    }

    #[test]
    fn settling_before_the_window_closes_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(
            c.settle(Verdict::Correct, [0xAAu8; 32], 7, 20_000),
            Err(L2Error::DisputeWindowClosed)
        ));
    }

    #[test]
    fn a_settle_hash_that_does_not_match_the_verdict_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(
            c.settle(Verdict::Correct, [0xCCu8; 32], 9, 0),
            Err(L2Error::BadVwcHash)
        ));
    }

    #[test]
    fn a_fraud_verdict_is_refused_when_the_deposit_cannot_cover_the_fee() {
        // The settle fee comes out of the losing worker's deposit, so a deposit
        // smaller than the fee leaves no honest way to charge it. The settle must
        // fail closed rather than collect a partial fee or dip into the escrow
        // the defrauded submitter is owed.
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();

        assert_eq!(
            c.settle(Verdict::Fraudulent, [0xBBu8; 32], 5, 20_000),
            Err(L2Error::AmountTooSmallForFee {
                available: 10_000,
                fee: 20_000
            })
        );
        assert!(
            matches!(c.state, ContractState::Disputed(_)),
            "a refused settle must leave the contract untouched"
        );
    }

    #[test]
    fn a_fraud_verdict_with_a_deposit_larger_than_the_fee_slashes_the_remainder() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 100_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();

        let outcome = c
            .settle(Verdict::Fraudulent, [0xBBu8; 32], 5, 20_000)
            .unwrap();
        assert_eq!(outcome.worker_deposit_slashed, 80_000);
        assert_eq!(outcome.submitter_refunded, 5_000_000);
        assert_eq!(outcome.challenger_refunded, 500);
    }

    #[test]
    fn a_failed_challenge_burns_the_challenger_deposit() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();

        // No fee, so the arithmetic is unambiguous about what was burned.
        let outcome = c.settle(Verdict::Correct, [0xAAu8; 32], 5, 0).unwrap();
        assert_eq!(outcome.challenger_deposit_burned, 500);
        assert_eq!(outcome.challenger_refunded, 0);
        assert_eq!(outcome.worker_paid, 5_000_000);
        assert_eq!(outcome.worker_deposit_returned, 10_000);
    }

    #[test]
    fn an_open_task_expires_and_refunds_the_submitter() {
        let mut c = open_contract();
        assert!(c.try_expire(100).is_none(), "deadline is 100, not passed");
        let outcome = c.try_expire(101).expect("expires the block after");
        assert_eq!(outcome.submitter_refunded, 5_000_000);
        assert_eq!(outcome.worker_deposit_burned, 0);
        assert!(matches!(c.state, ContractState::Expired(_)));
        assert_eq!(c.locked_total(), 0);
    }

    #[test]
    fn an_in_progress_task_that_lapses_burns_the_worker_deposit() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        let outcome = c.try_expire(101).expect("expires the block after");
        assert_eq!(outcome.submitter_refunded, 5_000_000);
        assert_eq!(outcome.worker_deposit_burned, 10_000);
    }

    #[test]
    fn a_terminal_contract_cannot_be_settled_twice() {
        let mut c = open_contract();
        c.try_expire(101).unwrap();
        assert!(matches!(
            c.settle(Verdict::Correct, [0u8; 32], 102, 0),
            Err(L2Error::IllegalTransition { .. })
        ));
        assert!(!c.due_for_auto_settle(200));
    }

    /// A claim deposit below the settle fee is refused at claim time.
    ///
    /// Without this rule the worker picks its own penalty. A dust deposit makes
    /// the `Fraudulent` arm of `settle_inner` unreachable (`deposit < fee`), and
    /// once a result is submitted `Expired` is unreachable too — so the only
    /// settlement left is the free auto-settle `Correct`. The worker then keeps
    /// the entire escrow for work that is provably wrong, and the penalty is a
    /// number they chose before doing anything.
    #[test]
    fn a_claim_deposit_that_cannot_cover_the_settle_fee_is_refused() {
        let mut c = open_contract(); // payment 5_000_000 -> settle fee 5_000
        let id = c.task_id;
        assert_eq!(srct_core::l2::settle_fee_sat(c.payment_sat), 5_000);

        // One satoshi under the fee: enough to post, not enough to be slashed.
        assert_eq!(
            c.claim(addr(2), &claim(addr(2), id, 4_999), 2),
            Err(L2Error::AmountTooSmallForFee {
                available: 4_999,
                fee: 5_000,
            })
        );
        assert!(
            matches!(c.state, ContractState::Open),
            "a refused claim must leave the task claimable"
        );

        // Exactly the fee is the floor, and a fraud verdict against it now works
        // rather than being structurally impossible.
        c.claim(addr(2), &claim(addr(2), id, 5_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();
        let outcome = c
            .settle(Verdict::Fraudulent, [0xBBu8; 32], 5, 5_000)
            .unwrap();
        assert_eq!(outcome.submitter_refunded, 5_000_000);
        assert_eq!(outcome.worker_deposit_slashed, 0);
    }

    /// The floor tracks the escrow, so a large task demands a real stake.
    #[test]
    fn the_deposit_floor_scales_with_the_escrow() {
        // payment 500_000_000 -> 0.1% = 500_000 sat, well above the 1_000 floor.
        let p = post(addr(1), 1, 500_000_000, 100);
        let mut c = TaskContract::new(&p, 1, 5).unwrap();
        let id = c.task_id;
        assert_eq!(
            c.claim(addr(2), &claim(addr(2), id, 499_999), 2),
            Err(L2Error::AmountTooSmallForFee {
                available: 499_999,
                fee: 500_000,
            })
        );
        c.claim(addr(2), &claim(addr(2), id, 500_000), 2).unwrap();
    }

    #[test]
    fn exit_per_owner_subcap_pairing_is_enforced() {
        // The constructors carry no throttle: valid by construction.
        L2Config::mini().validate().unwrap();
        L2Config::mainnet().validate().unwrap();
        // A share bigger than the whole is nonsense.
        let mut bad = L2Config::mini();
        bad.max_exit_window_sat = 1_000;
        bad.exit_window_blocks = 10;
        bad.max_exit_per_owner_window_sat = 1_001;
        assert!(bad.validate().is_err());
        // A share of a window that does not exist is a half-rule.
        let mut bad = L2Config::mini();
        bad.max_exit_per_owner_window_sat = 100;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn locked_total_tracks_every_held_leg() {
        let mut c = open_contract();
        let id = c.task_id;
        assert_eq!(c.locked_total(), 5_000_000);
        c.claim(addr(2), &claim(addr(2), id, 10_000), 2).unwrap();
        assert_eq!(c.locked_total(), 5_010_000);
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert_eq!(c.locked_total(), 5_010_000);
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();
        assert_eq!(c.locked_total(), 5_010_500);
        c.settle(Verdict::Fraudulent, [0xBBu8; 32], 5, 0).unwrap();
        assert_eq!(c.locked_total(), 0);
    }
}
