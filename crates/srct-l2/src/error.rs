//! Errors for the L2 task-contract layer.
//!
//! Deliberately its own enum rather than a reuse of `srct_core::Error`: an L2
//! failure is not a consensus failure, and folding the two together is how an
//! L2 bug becomes indistinguishable from an L1 one. Codec failures from
//! `srct-core` are carried through as [`L2Error::Codec`] so a malformed payload
//! still names its origin.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Error {
    /// A payload's signature did not verify, or it acted as a different address
    /// than it claimed.
    BadAuthorization,
    /// The referenced task id is not registered.
    UnknownTask,
    /// A task with this id already exists (post replay, or an id collision).
    TaskAlreadyExists,
    /// This exact transaction was already applied.
    Replay,
    /// The requested transition is illegal from the task's current state.
    IllegalTransition {
        state: &'static str,
        action: &'static str,
    },
    /// The task deadline has passed.
    TaskExpired,
    /// The dispute window has closed (or has not yet opened, for settlement).
    DisputeWindowClosed,
    /// A dispute that agrees with the submitted result is pointless and refused.
    DisputeAgreesWithResult,
    /// A field that must be positive was zero.
    ZeroAmount(&'static str),
    /// The L2 deadline and the M3 envelope expiry disagree.
    DeadlineMismatch,
    /// An attestation does not bind to the task, worker or result it is filed
    /// with.
    BadAttestation(&'static str),
    /// The settle evidence did not meet quorum, or the bitmap disagrees with the
    /// declared signer count.
    BadQuorum,
    /// The settle BLS aggregate did not verify.
    BadBlsSignature,
    /// The settle payload names a network this state does not belong to. The
    /// aggregate is bound to its network, so a cross-chain replay fails here
    /// by name rather than by a pairing mismatch.
    BadSettleNetwork,
    /// The settle payload claims a vote height above the applying height. A
    /// quorum formed at `H` may settle at `H+1`, but never from the future.
    BadSettleHeight,
    /// The settle lattice sidecar failed clause-7-shape verification: the
    /// detail names the signer index and the rule. See `validators::check_sidecar`.
    BadPqSidecar(String),
    /// The settle hash does not match the verdict it settles.
    BadVwcHash,
    /// Arbitration evidence is missing a required part (for example an
    /// unsigned attestation).
    EvidenceIncomplete,
    /// An attestation does not bind to the task or result it is filed with.
    EvidenceMismatch(&'static str),
    /// The reference re-execution reproduced neither claim, so no verdict can be
    /// reached and nothing is slashed.
    InconclusiveDispute,
    /// A certificate already exists for this task; a task settles once, so a
    /// second issuance is a protocol violation, never an update.
    VwcAlreadyIssued,
    /// A certificate was refused: the reason is stated, and validation always
    /// fails closed (SPEC.md §17.6).
    VwcInvalid(&'static str),
    /// An account cannot cover the required fee, deposit or escrow.
    InsufficientBalance { needed: u64, available: u64 },
    /// The held amount cannot cover the settle fee.
    AmountTooSmallForFee { available: u64, fee: u64 },
    /// A numeric total did not fit.
    Overflow,
    /// The L2 genesis allocation was applied twice. Genesis funding happens
    /// exactly once per state construction (SPEC.md §19.4); a second
    /// application would duplicate every grant, so it is refused by name.
    GenesisAlreadyApplied,
    /// A genesis allocation is structurally invalid (duplicate grantee, grant
    /// to the escrow identity). The reason is stated.
    InvalidGenesis(&'static str),
    /// A deposit `(txid, output_index)` already credited. The same L1 bytes in
    /// a later block pay once; the second occurrence is refused by name
    /// (Decision 10 item 5).
    DuplicateDeposit,
    /// Exits are not active on this state: the profile never activates them
    /// (`exit_activation_height == 0`) or the queue height predates
    /// activation. Queueing would encumber funds with no release.
    ExitNotActive,
    /// The exit's prepaid release fee is below `MIN_EXIT_FEE_SAT`. A zero or
    /// dust fee pays nobody to file the L1 release, so the exit would never be
    /// claimed — refused at queue time instead.
    ExitFeeBelowMinimum,
    /// An exit nonce that repeats or rewinds the owner's last queue nonce.
    /// Nonces are strictly increasing per owner (approved P1 replay rule).
    BadExitNonce,
    /// No queued exit for this `(owner, nonce)` — never queued, or already
    /// released (release removes the record, so a spent exit has no leaf and
    /// no second release).
    UnknownExit,
    /// The exit window is full: this queue would push the window's total
    /// principal over `max_exit_window_sat`. Funds are untouched — the owner
    /// retries once `window_ends_at` passes.
    ExitWindowFull {
        window_total: u64,
        window_cap: u64,
        window_ends_at: u64,
    },
    /// This owner's share of the window is full: the queue would push their
    /// window principal over `max_exit_per_owner_window_sat`. Other owners
    /// are unaffected — this is the fairness bound, and a filler hitting it
    /// is exactly the attack it stops. Funds are untouched; the owner
    /// retries once `window_ends_at` passes.
    ExitOwnerWindowFull {
        owner_total: u64,
        owner_cap: u64,
        window_ends_at: u64,
    },
    /// The exit names an unspendable destination (for example the deposit
    /// sink): value in, never out. The reason is stated.
    BadExitDestination(&'static str),
    /// A configuration value is outside its documented range (for example a
    /// whistleblower bounty over 100 percent, or a zero dispute window).
    BadConfig(&'static str),
    /// A codec failure raised by `srct-core`.
    Codec(srct_core::Error),
    /// A reputation derivation refused a canonical artifact (roadmap item 9).
    /// The reason is the underlying ledger clause, stated.
    Reputation(String),
    /// A spending-policy rule refused the transaction. The reason is stated, so
    /// a caller learns *which* clause bound it rather than only that it did not.
    Policy(String),
    /// The transaction names the wrong grant, the wrong spender or the wrong
    /// agent: a binding mismatch rather than a limit.
    PolicyBinding(&'static str),
    /// No published grant with this hash, or none for this agent.
    UnknownPolicy,
    /// The agent already has a live grant. An agent has exactly one grant at a
    /// time, so a second one cannot be used to double the caps the first one
    /// grants.
    PolicyAlreadyPublished,
    /// The grant is revoked, or it descends from a revoked grant. The owner's
    /// kill switch reaches every descendant without a separate revocation per
    /// link.
    PolicyRevoked,
    /// A cap bound the spend: per transaction, or cumulative inside the window.
    PolicyLimit(&'static str),
    /// The recipient is not on the grant's allow-list. An empty allow-list
    /// allows nothing, which is the safe reading of an empty list.
    PolicyRecipient,
    /// The service tag is not on the grant's allow-list, or the grant names
    /// services and the spend named none.
    PolicyService,
    /// The nonce repeats or rewinds the grant's last nonce. Nonces are strictly
    /// increasing per grant.
    PolicyNonce,
    /// The grant is not usable at this height: not yet valid, expired, or the
    /// height ran backwards inside the grant.
    PolicyWindow(&'static str),
    /// A credit term is out of range: a zero window, a rate above the cap, a
    /// deadline in the past.
    CreditTerms(&'static str),
    /// The collateral posted does not meet the requirement. The requirement and
    /// the amount posted are both stated, so a caller knows the gap.
    CreditUndercollateralised { required: u64, posted: u64 },
    /// A position with this id already exists.
    CreditPositionExists,
    /// No position with this id.
    UnknownCreditPosition,
    /// The position is not open: it was already repaid or already defaulted.
    CreditPositionClosed,
    /// The transaction names a position that belongs to somebody else.
    CreditBinding(&'static str),
    /// The position is not yet due, so it cannot be defaulted.
    CreditNotDue,
    /// The interest charged on a position overflowed the arithmetic the charge
    /// schedule permits. Refused rather than wrapped: a wrapped charge would
    /// under-charge the lender.
    CreditInterestOverflow,
    /// A repayment larger than the debt owed. Refused rather than trimmed: the
    /// lender is paid the debt and not a satoshi more, and the borrower's
    /// excess is not silently taken. The node-local credit book refuses the
    /// same shape (SPEC.md §22.5).
    CreditRepaymentExceedsDebt { debt: u64 },
    /// A service-contract spec named an impossible contract: zero payment, no
    /// deadline, or a dispute window that reaches the deadline. Refused by
    /// name at construction rather than panicked.
    InvalidContractSpec(&'static str),
    /// A guarded account is frozen: all outflows are halted pending guardian
    /// review or unfreeze.
    AccountFrozen,
    /// A guarded-account grant was published before its activation delay
    /// elapsed (`not_before_height < publish_height + D`).
    GrantDelayNotSatisfied,
    /// A guarded-account grant exceeds the maximum lifetime
    /// (`expires_at - not_before > max_grant_lifetime`).
    GrantLifetimeExceeded,
    /// An exit or AgentSpend from a guarded account names a destination that
    /// is not in the active allow-list.
    GuardedDestinationNotAllowed,
    /// Guarded opt-in names the owner itself as guardian. The guardian must
    /// be independent of the owner, or the guard is theatre.
    GuardedGuardianMustDiffer,
    /// This account already opted into guarded mode.
    GuardedAlreadyOptedIn,
    /// This account is not in guarded mode.
    GuardedNotOptedIn,
    /// The signer is not the account's registered guardian.
    GuardedGuardianMismatch,
    /// GuardedCancel names an unknown target kind (only 0 = exit, 1 = grant).
    GuardedUnknownTarget,
    /// A guarded exit cancel arrived at or after the delay window: the exit
    /// is claimable now, and cancelling would race an L1 proof against a
    /// post-delay root.
    GuardedCancelWindowClosed,
    /// A guarded spend at or above the human-approval tier lacks the
    /// guardian's co-signature on the identical terms.
    GuardedApprovalRequired,
    /// A guarded-account outflow would exceed the balance-relative window cap.
    GuardedOutflowCapped { allowed: u64, requested: u64 },
}

impl fmt::Display for L2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L2Error::BadAuthorization => write!(f, "L2 authorization failed"),
            L2Error::UnknownTask => write!(f, "unknown task"),
            L2Error::TaskAlreadyExists => write!(f, "task already exists"),
            L2Error::Replay => write!(f, "transaction already applied"),
            L2Error::IllegalTransition { state, action } => {
                write!(f, "cannot {action} while the task is {state}")
            }
            L2Error::TaskExpired => write!(f, "task deadline has passed"),
            L2Error::DisputeWindowClosed => write!(f, "dispute window is closed"),
            L2Error::DisputeAgreesWithResult => {
                write!(f, "dispute agrees with the submitted result")
            }
            L2Error::ZeroAmount(w) => write!(f, "{w} must be non-zero"),
            L2Error::DeadlineMismatch => {
                write!(f, "L2 deadline and M3 envelope expiry disagree")
            }
            L2Error::BadAttestation(w) => write!(f, "bad attestation: {w}"),
            L2Error::BadQuorum => write!(f, "settle evidence does not meet quorum"),
            L2Error::BadBlsSignature => write!(f, "settle BLS aggregate did not verify"),
            L2Error::BadSettleNetwork => {
                write!(f, "settle payload is for another network")
            }
            L2Error::BadSettleHeight => {
                write!(f, "settle vote height is above the applying height")
            }
            L2Error::BadPqSidecar(why) => write!(f, "settle lattice sidecar refused: {why}"),
            L2Error::BadVwcHash => write!(f, "settle hash does not match the verdict"),
            L2Error::EvidenceIncomplete => write!(f, "dispute evidence is incomplete"),
            L2Error::EvidenceMismatch(w) => write!(f, "dispute evidence mismatch: {w}"),
            L2Error::InconclusiveDispute => {
                write!(f, "arbitration was inconclusive; nothing to settle")
            }
            L2Error::VwcAlreadyIssued => {
                write!(
                    f,
                    "a verified-work certificate already exists for this task"
                )
            }
            L2Error::VwcInvalid(why) => write!(f, "certificate refused: {why}"),
            L2Error::InsufficientBalance { needed, available } => {
                write!(f, "insufficient balance: need {needed}, have {available}")
            }
            L2Error::AmountTooSmallForFee { available, fee } => write!(
                f,
                "held amount {available} cannot cover the {fee} sat settle fee"
            ),
            L2Error::Overflow => write!(f, "arithmetic overflow"),
            L2Error::GenesisAlreadyApplied => {
                write!(f, "l2 genesis allocation already applied")
            }
            L2Error::InvalidGenesis(why) => write!(f, "invalid l2 genesis: {why}"),
            L2Error::DuplicateDeposit => write!(f, "deposit already credited"),
            L2Error::ExitNotActive => write!(f, "exits are not active at this height"),
            L2Error::ExitFeeBelowMinimum => {
                write!(f, "exit fee is below the protocol minimum")
            }
            L2Error::BadExitNonce => write!(f, "exit nonce repeats or rewinds"),
            L2Error::UnknownExit => write!(f, "no such queued exit"),
            L2Error::ExitWindowFull {
                window_total,
                window_cap,
                window_ends_at,
            } => write!(
                f,
                "exit window full: {window_total} of {window_cap} sat used, retry after height {window_ends_at}"
            ),
            L2Error::ExitOwnerWindowFull {
                owner_total,
                owner_cap,
                window_ends_at,
            } => write!(
                f,
                "owner exit share full: {owner_total} of {owner_cap} sat used, retry after height {window_ends_at}"
            ),
            L2Error::BadExitDestination(why) => write!(f, "bad exit destination: {why}"),
            L2Error::BadConfig(why) => write!(f, "bad l2 config: {why}"),
            L2Error::Codec(e) => write!(f, "codec: {e}"),
            L2Error::Reputation(w) => write!(f, "reputation: {w}"),
            L2Error::Policy(w) => write!(f, "policy refused: {w}"),
            L2Error::PolicyBinding(w) => write!(f, "policy binding: {w}"),
            L2Error::UnknownPolicy => write!(f, "no such published policy"),
            L2Error::PolicyAlreadyPublished => {
                write!(f, "the agent already has a live published policy")
            }
            L2Error::PolicyRevoked => write!(f, "the policy is revoked"),
            L2Error::PolicyLimit(w) => write!(f, "policy limit: {w}"),
            L2Error::PolicyRecipient => write!(f, "recipient is not on the policy allow-list"),
            L2Error::PolicyService => write!(f, "service is not on the policy allow-list"),
            L2Error::PolicyNonce => write!(f, "policy nonce repeats or rewinds"),
            L2Error::PolicyWindow(w) => write!(f, "policy window: {w}"),
            L2Error::CreditTerms(w) => write!(f, "credit terms refused: {w}"),
            L2Error::CreditUndercollateralised { required, posted } => {
                write!(f, "collateral {posted} is below the required {required}")
            }
            L2Error::CreditPositionExists => write!(f, "the credit position already exists"),
            L2Error::UnknownCreditPosition => write!(f, "no such credit position"),
            L2Error::CreditPositionClosed => write!(f, "the credit position is closed"),
            L2Error::CreditBinding(w) => write!(f, "credit binding: {w}"),
            L2Error::CreditNotDue => write!(f, "the credit position is not yet due"),
            L2Error::CreditInterestOverflow => write!(f, "credit interest overflowed"),
            L2Error::CreditRepaymentExceedsDebt { debt } => {
                write!(f, "the repayment exceeds the debt owed ({debt} sat)")
            }
            L2Error::InvalidContractSpec(why) => {
                write!(f, "invalid service-contract spec: {why}")
            }
            L2Error::AccountFrozen => write!(f, "guarded account is frozen"),
            L2Error::GrantDelayNotSatisfied => {
                write!(f, "guarded grant activation delay not satisfied")
            }
            L2Error::GrantLifetimeExceeded => {
                write!(f, "guarded grant exceeds maximum lifetime")
            }
            L2Error::GuardedDestinationNotAllowed => {
                write!(f, "destination not in guarded allow-list")
            }
            L2Error::GuardedGuardianMustDiffer => {
                write!(f, "guardian must differ from the owner")
            }
            L2Error::GuardedAlreadyOptedIn => {
                write!(f, "account already opted into guarded mode")
            }
            L2Error::GuardedNotOptedIn => write!(f, "account is not guarded"),
            L2Error::GuardedGuardianMismatch => {
                write!(f, "signer is not the account guardian")
            }
            L2Error::GuardedUnknownTarget => {
                write!(f, "guarded cancel names an unknown target kind")
            }
            L2Error::GuardedCancelWindowClosed => {
                write!(f, "guarded exit cancel arrived after the delay window")
            }
            L2Error::GuardedApprovalRequired => {
                write!(f, "guarded spend needs guardian co-signature")
            }
            L2Error::GuardedOutflowCapped { allowed, requested } => write!(
                f,
                "guarded outflow capped: {requested} requested, {allowed} allowed this window"
            ),
        }
    }
}

impl std::error::Error for L2Error {}

impl From<srct_core::Error> for L2Error {
    fn from(e: srct_core::Error) -> Self {
        L2Error::Codec(e)
    }
}

pub type L2Result<T> = std::result::Result<T, L2Error>;
