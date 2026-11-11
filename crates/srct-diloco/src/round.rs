//! DiLoCo round coordination, Byzantine filtering and reward settlement.
//!
//! A round is a small state machine:
//!
//! ```text
//! Open --submit*--> (quorum reached) --> finalize --> Finalized
//!   \-- finalize with too few updates -----------> Failed
//! ```
//!
//! Finalization is deterministic given the accepted submissions: the
//! coordinate-wise median defines a reference pseudo-gradient, submissions
//! whose cosine similarity to that reference is below `min_cosine` are
//! rejected, and the mean of the survivors is applied through a momentum
//! outer optimizer. Rewards are paid from a fixed pot by validated work
//! (samples x quality x capped stake), split exactly.
//!
//! The coordinator is deliberately conservative:
//!
//! - one submission per registered worker per round, and one commitment
//!   globally, so a replay or a copied update cannot be counted twice;
//! - a norm cap is checked *before* the median, so a single submission cannot
//!   dominate the reference even if it is the first one seen;
//! - a round with too few accepted updates fails instead of producing a
//!   low-confidence model step;
//! - the outer velocity is retained across rounds, so a failed round does not
//!   silently reset the optimizer state.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{Address, Hash};

use crate::model::{Mlp, MODEL_VERSION};
use crate::update::{SignedUpdate, UPDATE_VERSION};

/// Round configuration. Values are explicit rather than hidden defaults so a
/// coordinator's policy is auditable.
#[derive(Clone, Debug)]
pub struct RoundConfig {
    pub round_id: u64,
    /// Minimum number of accepted updates required to finalize.
    pub min_quorum: usize,
    /// Maximum registered workers in this round.
    pub max_workers: usize,
    /// Largest L2 norm a pseudo-gradient may have.
    pub max_update_norm: f32,
    /// Minimum cosine similarity to the coordinate-wise median.
    pub min_cosine: f32,
    /// Samples beyond this count earn no extra reward weight.
    pub max_samples_per_update: u64,
    /// Stake beyond this value is not recorded in full. Stake does not price
    /// work in this prototype; the cap exists for the bonded integration.
    pub max_effective_stake_sat: u64,
    /// Total reward pot for the round, in satoshis.
    pub reward_pot_sat: u64,
    /// Outer-optimizer momentum.
    pub momentum: f32,
    /// Outer-optimizer learning rate.
    pub outer_lr: f32,
}

impl RoundConfig {
    pub fn new(round_id: u64, min_quorum: usize) -> Self {
        RoundConfig {
            round_id,
            min_quorum: min_quorum.max(1),
            max_workers: 64,
            max_update_norm: 5.0,
            min_cosine: 0.0,
            max_samples_per_update: 4_096,
            max_effective_stake_sat: 1_000_000,
            reward_pot_sat: 1_000_000,
            momentum: 0.5,
            outer_lr: 1.0,
        }
    }
}

/// Why an update or a round was refused. Named rather than a string so tests
/// can assert the exact rule and operators can alert on the reason.
#[derive(Clone, Debug, PartialEq)]
pub enum Rejection {
    RoundClosed,
    UnsupportedVersion(u8),
    WrongRound { expected: u64, got: u64 },
    WrongModel { expected: u32, got: u32 },
    BaseMismatch,
    NotRegistered,
    StakeZero,
    BadSignature(String),
    NonFinite,
    UpdateTooLarge { norm: f32, cap: f32 },
    NoWork,
    SamplesExceedAssignment { claimed: u64, assigned: u64 },
    DuplicateWorker,
    DuplicateCommitment,
    TooManyWorkers { cap: usize },
    NotEnoughUpdates { got: usize, need: usize },
    LowQuality { cosine: f32, floor: f32 },
    ZeroAggregate,
    ZeroAccepted,
    ModelOverflow,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::RoundClosed => write!(f, "round is closed"),
            Rejection::UnsupportedVersion(v) => write!(f, "unsupported update version {v}"),
            Rejection::WrongRound { expected, got } => {
                write!(f, "update names round {got}, this round is {expected}")
            }
            Rejection::WrongModel { expected, got } => {
                write!(f, "update names model {got}, expected {expected}")
            }
            Rejection::BaseMismatch => write!(f, "update base is not this round's model"),
            Rejection::NotRegistered => write!(f, "worker is not registered for this round"),
            Rejection::StakeZero => write!(f, "worker stake must be positive"),
            Rejection::BadSignature(detail) => write!(f, "invalid update: {detail}"),
            Rejection::NonFinite => write!(f, "update contains non-finite values"),
            Rejection::UpdateTooLarge { norm, cap } => {
                write!(f, "update norm {norm} exceeds cap {cap}")
            }
            Rejection::NoWork => write!(f, "update claims no samples or no steps"),
            Rejection::SamplesExceedAssignment { claimed, assigned } => write!(
                f,
                "update claims {claimed} samples but the worker was assigned {assigned}"
            ),
            Rejection::DuplicateWorker => write!(f, "worker already submitted this round"),
            Rejection::DuplicateCommitment => write!(f, "identical update already submitted"),
            Rejection::TooManyWorkers { cap } => write!(f, "worker cap {cap} reached"),
            Rejection::NotEnoughUpdates { got, need } => {
                write!(f, "round has {got} updates, quorum is {need}")
            }
            Rejection::LowQuality { cosine, floor } => {
                write!(f, "update cosine {cosine:.4} is below the floor {floor:.4}")
            }
            Rejection::ZeroAggregate => write!(f, "median update is zero"),
            Rejection::ZeroAccepted => write!(f, "no update passed the similarity filter"),
            Rejection::ModelOverflow => write!(f, "aggregated model is not finite"),
        }
    }
}

impl std::error::Error for Rejection {}

/// One accepted contribution and the inputs to its reward weight.
#[derive(Clone, Debug, PartialEq)]
pub struct Contribution {
    pub worker: Address,
    pub samples: u64,
    pub steps: u32,
    /// Cosine similarity to the median reference, in `[-1, 1]`.
    pub cosine: f32,
    /// Registered stake, recorded for observability. It does not price work
    /// until worker keys are bound to bonded stake by consensus.
    pub stake_sat: u64,
    /// Integer reward weight (`samples * quality_bps`).
    pub weight: u128,
}

/// The result of a finalized round.
#[derive(Clone, Debug)]
pub struct FinalizedRound {
    pub round_id: u64,
    pub model: Mlp,
    pub model_hash: Hash,
    pub accepted: Vec<Contribution>,
    pub rejected: Vec<(Address, Rejection)>,
    pub rewards: BTreeMap<Address, u64>,
    pub reward_pot_sat: u64,
    pub median_norm: f32,
    pub aggregate_norm: f32,
}

impl FinalizedRound {
    /// True when the reward split sums to the pot exactly.
    pub fn rewards_are_exact(&self) -> bool {
        self.rewards.values().sum::<u64>() == self.reward_pot_sat
    }
}

/// Outcome of finalizing a round.
#[derive(Clone, Debug)]
pub enum RoundOutcome {
    Finalized(FinalizedRound),
    Failed {
        round_id: u64,
        reason: Rejection,
        received: usize,
    },
}

/// What the coordinator assigned to a worker for this round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerRegistration {
    pub stake_sat: u64,
    /// Samples in the shard the coordinator assigned. A worker cannot claim
    /// more than this, so reward weight cannot be inflated by inventing work.
    pub assigned_samples: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoundStatus {
    Open,
    Finalized,
    Failed,
}

/// Coordinator state for one training round.
#[derive(Clone, Debug)]
pub struct RoundState {
    config: RoundConfig,
    base: Mlp,
    base_hash: Hash,
    velocity: Mlp,
    workers: BTreeMap<Address, WorkerRegistration>,
    submissions: BTreeMap<Address, SignedUpdate>,
    seen: BTreeSet<Hash>,
    status: RoundStatus,
}

impl RoundState {
    /// Start a round on top of `base`, carrying the outer-optimizer velocity
    /// from the previous round.
    ///
    /// Refuses a configuration that could not produce a meaningful round
    /// (zero quorum, quorum above the worker cap, non-finite optimizer
    /// constants, a cosine floor outside `[-1, 1]`).
    pub fn new(config: RoundConfig, base: Mlp, velocity: Mlp) -> Result<Self, String> {
        if config.min_quorum == 0 {
            return Err("quorum must be at least 1".into());
        }
        if config.max_workers < config.min_quorum {
            return Err("worker cap is below the quorum".into());
        }
        if !config.max_update_norm.is_finite() || config.max_update_norm <= 0.0 {
            return Err("max_update_norm must be finite and positive".into());
        }
        if !config.min_cosine.is_finite() || !(-1.0..=1.0).contains(&config.min_cosine) {
            return Err("min_cosine must be finite and within [-1, 1]".into());
        }
        if !config.outer_lr.is_finite() || config.outer_lr <= 0.0 {
            return Err("outer_lr must be finite and positive".into());
        }
        if !config.momentum.is_finite() || !(0.0..1.0).contains(&config.momentum) {
            return Err("momentum must be finite and within [0, 1)".into());
        }
        if !base.is_finite() || !velocity.is_finite() {
            return Err("base model and velocity must be finite".into());
        }
        let base_hash = base.hash();
        Ok(RoundState {
            config,
            base,
            base_hash,
            velocity,
            workers: BTreeMap::new(),
            submissions: BTreeMap::new(),
            seen: BTreeSet::new(),
            status: RoundStatus::Open,
        })
    }

    pub fn config(&self) -> &RoundConfig {
        &self.config
    }

    pub fn base(&self) -> &Mlp {
        &self.base
    }

    pub fn base_hash(&self) -> Hash {
        self.base_hash
    }

    pub fn velocity(&self) -> &Mlp {
        &self.velocity
    }

    pub fn received(&self) -> usize {
        self.submissions.len()
    }

    pub fn is_open(&self) -> bool {
        self.status == RoundStatus::Open
    }

    /// Register a worker with a stake and its assigned shard size.
    ///
    /// The assignment is what makes the sample count checkable: the
    /// coordinator knows how many examples the worker was given, and a claim
    /// above that number is refused. Re-registering the same address updates
    /// the assignment; the address still gets one submission in the round.
    pub fn register_worker(
        &mut self,
        worker: Address,
        stake_sat: u64,
        assigned_samples: u64,
    ) -> Result<(), Rejection> {
        if self.status != RoundStatus::Open {
            return Err(Rejection::RoundClosed);
        }
        if stake_sat == 0 {
            return Err(Rejection::StakeZero);
        }
        if assigned_samples == 0 {
            return Err(Rejection::NoWork);
        }
        if !self.workers.contains_key(&worker) && self.workers.len() >= self.config.max_workers {
            return Err(Rejection::TooManyWorkers {
                cap: self.config.max_workers,
            });
        }
        self.workers.insert(
            worker,
            WorkerRegistration {
                stake_sat,
                assigned_samples,
            },
        );
        Ok(())
    }

    /// Validate and store one signed update.
    ///
    /// Every refusal leaves the round exactly as it was: nothing is inserted
    /// until all checks pass.
    pub fn submit(&mut self, update: SignedUpdate) -> Result<(), Rejection> {
        if self.status != RoundStatus::Open {
            return Err(Rejection::RoundClosed);
        }
        if update.version != UPDATE_VERSION {
            return Err(Rejection::UnsupportedVersion(update.version));
        }
        if update.claim.round_id != self.config.round_id {
            return Err(Rejection::WrongRound {
                expected: self.config.round_id,
                got: update.claim.round_id,
            });
        }
        if update.claim.model_version != MODEL_VERSION {
            return Err(Rejection::WrongModel {
                expected: MODEL_VERSION,
                got: update.claim.model_version,
            });
        }
        if update.claim.base != self.base_hash {
            return Err(Rejection::BaseMismatch);
        }
        if !self.workers.contains_key(&update.claim.worker) {
            return Err(Rejection::NotRegistered);
        }
        update.verify().map_err(Rejection::BadSignature)?;
        if update.claim.samples == 0 || update.claim.steps == 0 {
            return Err(Rejection::NoWork);
        }
        let assigned = self
            .workers
            .get(&update.claim.worker)
            .map(|w| w.assigned_samples)
            .unwrap_or(0);
        if update.claim.samples > assigned {
            return Err(Rejection::SamplesExceedAssignment {
                claimed: update.claim.samples,
                assigned,
            });
        }
        if !update.claim.inner_loss.is_finite() {
            return Err(Rejection::NonFinite);
        }
        if !update.claim.delta.is_finite() {
            return Err(Rejection::NonFinite);
        }
        let norm = update.claim.delta.l2_norm();
        if !norm.is_finite() || norm > self.config.max_update_norm {
            return Err(Rejection::UpdateTooLarge {
                norm,
                cap: self.config.max_update_norm,
            });
        }
        if self.seen.contains(&update.claim.commitment) {
            return Err(Rejection::DuplicateCommitment);
        }
        if self.submissions.contains_key(&update.claim.worker) {
            return Err(Rejection::DuplicateWorker);
        }
        self.seen.insert(update.claim.commitment);
        self.submissions.insert(update.claim.worker, update);
        Ok(())
    }

    /// Close the round and, with quorum, apply the robust aggregate.
    ///
    /// The velocity is advanced only on success; a failed round returns the
    /// unchanged optimizer state for the next attempt.
    pub fn finalize(&mut self) -> RoundOutcome {
        if self.status != RoundStatus::Open {
            return RoundOutcome::Failed {
                round_id: self.config.round_id,
                reason: Rejection::RoundClosed,
                received: self.submissions.len(),
            };
        }
        if self.submissions.len() < self.config.min_quorum {
            self.status = RoundStatus::Failed;
            return RoundOutcome::Failed {
                round_id: self.config.round_id,
                reason: Rejection::NotEnoughUpdates {
                    got: self.submissions.len(),
                    need: self.config.min_quorum,
                },
                received: self.submissions.len(),
            };
        }

        let deltas: Vec<&Mlp> = self.submissions.values().map(|u| &u.claim.delta).collect();
        let median = coordinate_median(&deltas);
        let median_norm = median.l2_norm();
        if median_norm == 0.0 || !median_norm.is_finite() {
            self.status = RoundStatus::Failed;
            return RoundOutcome::Failed {
                round_id: self.config.round_id,
                reason: Rejection::ZeroAggregate,
                received: self.submissions.len(),
            };
        }

        let mut accepted: Vec<Contribution> = Vec::new();
        let mut accepted_deltas: Vec<Mlp> = Vec::new();
        let mut rejected: Vec<(Address, Rejection)> = Vec::new();
        for (worker, update) in &self.submissions {
            let cosine = cosine(&update.claim.delta, &median);
            if !cosine.is_finite() || cosine < self.config.min_cosine {
                rejected.push((
                    *worker,
                    Rejection::LowQuality {
                        cosine,
                        floor: self.config.min_cosine,
                    },
                ));
                continue;
            }
            let stake = self.workers.get(worker).map(|w| w.stake_sat).unwrap_or(0);
            let stake_capped = stake.min(self.config.max_effective_stake_sat);
            let samples_capped = update.claim.samples.min(self.config.max_samples_per_update);
            let quality_bps = (cosine.clamp(0.0, 1.0) * 10_000.0).round() as u128;
            // Stake is deliberately not a multiplier until it is bonded and
            // verifiable on chain. Self-declared stake would be free weight.
            let weight = samples_capped as u128 * quality_bps;
            accepted.push(Contribution {
                worker: *worker,
                samples: update.claim.samples,
                steps: update.claim.steps,
                cosine,
                stake_sat: stake_capped,
                weight,
            });
            accepted_deltas.push(update.claim.delta.clone());
        }

        if accepted_deltas.is_empty() {
            self.status = RoundStatus::Failed;
            return RoundOutcome::Failed {
                round_id: self.config.round_id,
                reason: Rejection::ZeroAccepted,
                received: self.submissions.len(),
            };
        }

        let aggregate = coordinate_mean(&accepted_deltas);
        let aggregate_norm = aggregate.l2_norm();
        // v = momentum * v + delta
        let velocity = coordinate_combine(&self.velocity, self.config.momentum, &aggregate, 1.0);
        // theta = theta + lr * v. The pseudo-gradient is `local - global`, and
        // local training moved in the descent direction, so the aggregate is
        // added. Subtracting it would move the global model in the opposite
        // direction (the bug this prototype's first convergence test caught).
        let model = coordinate_combine(&self.base, 1.0, &velocity, self.config.outer_lr);
        if !model.is_finite() || !velocity.is_finite() {
            self.status = RoundStatus::Failed;
            return RoundOutcome::Failed {
                round_id: self.config.round_id,
                reason: Rejection::ModelOverflow,
                received: self.submissions.len(),
            };
        }

        let rewards = split_rewards(self.config.reward_pot_sat, &accepted);
        let model_hash = model.hash();
        self.velocity = velocity;
        self.status = RoundStatus::Finalized;
        RoundOutcome::Finalized(FinalizedRound {
            round_id: self.config.round_id,
            model,
            model_hash,
            accepted,
            rejected,
            rewards,
            reward_pot_sat: self.config.reward_pot_sat,
            median_norm,
            aggregate_norm,
        })
    }
}

/// Coordinate-wise median of the submitted pseudo-gradients.
fn coordinate_median(deltas: &[&Mlp]) -> Mlp {
    let mut params = vec![0.0f32; crate::model::PARAM_COUNT];
    let mut column: Vec<f32> = Vec::with_capacity(deltas.len());
    for (i, slot) in params.iter_mut().enumerate() {
        column.clear();
        for d in deltas {
            column.push(d.params()[i]);
        }
        column.sort_by(|a, b| a.total_cmp(b));
        let n = column.len();
        *slot = if n % 2 == 1 {
            column[n / 2]
        } else {
            (column[n / 2 - 1] + column[n / 2]) * 0.5
        };
    }
    Mlp::from_params(&params).expect("median of finite updates is finite")
}

/// Coordinate-wise mean of the accepted pseudo-gradients.
fn coordinate_mean(deltas: &[Mlp]) -> Mlp {
    let mut params = vec![0.0f32; crate::model::PARAM_COUNT];
    for d in deltas {
        for (slot, value) in params.iter_mut().zip(d.params().iter()) {
            *slot += *value;
        }
    }
    let inv = 1.0 / deltas.len() as f32;
    for slot in params.iter_mut() {
        *slot *= inv;
    }
    Mlp::from_params(&params).expect("mean of finite updates is finite")
}

/// `a * scale_a + b * scale_b`, coordinate-wise.
fn coordinate_combine(a: &Mlp, scale_a: f32, b: &Mlp, scale_b: f32) -> Mlp {
    let pa = a.params();
    let pb = b.params();
    let out: Vec<f32> = pa
        .iter()
        .zip(pb.iter())
        .map(|(x, y)| x * scale_a + y * scale_b)
        .collect();
    Mlp::from_params(&out).expect("combine of finite models is finite")
}

/// Cosine similarity in `[-1, 1]`; zero when either vector is zero.
fn cosine(a: &Mlp, b: &Mlp) -> f32 {
    let na = a.l2_norm();
    let nb = b.l2_norm();
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    (a.dot(b) / (na * nb)).clamp(-1.0, 1.0)
}

/// Split `pot` by weight with an exact largest-remainder distribution.
///
/// Ties are broken by address order, so two coordinators with the same
/// accepted set produce the same reward map.
fn split_rewards(pot: u64, accepted: &[Contribution]) -> BTreeMap<Address, u64> {
    let mut rewards: BTreeMap<Address, u64> = BTreeMap::new();
    if accepted.is_empty() {
        return rewards;
    }
    let total: u128 = accepted.iter().map(|c| c.weight).sum();
    if total == 0 {
        // Accepted work with no measurable quality still gets an equal share;
        // the alternative is silently withholding the pot.
        let each = pot / accepted.len() as u64;
        let mut remainder = pot - each * accepted.len() as u64;
        for c in accepted {
            let extra = if remainder > 0 {
                remainder -= 1;
                1
            } else {
                0
            };
            rewards.insert(c.worker, each + extra);
        }
        return rewards;
    }
    let mut assigned = 0u64;
    let mut fractions: Vec<(u128, Address)> = Vec::with_capacity(accepted.len());
    for c in accepted {
        let exact = (pot as u128) * c.weight;
        let share = (exact / total) as u64;
        let rem = exact % total;
        assigned += share;
        rewards.insert(c.worker, share);
        fractions.push((rem, c.worker));
    }
    // Largest remainder first; address ascending on ties.
    fractions.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut leftover = pot - assigned;
    for (_, worker) in fractions {
        if leftover == 0 {
            break;
        }
        if let Some(slot) = rewards.get_mut(&worker) {
            *slot += 1;
            leftover -= 1;
        }
    }
    rewards
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{shards, two_moons};
    use crate::update::UpdateClaim;
    use srct_core::wallet::Wallet;

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_private_key_bytes(&[seed; 32], "diloco-test").unwrap()
    }

    fn update(
        round_id: u64,
        base: &Mlp,
        worker: &Wallet,
        local: &Mlp,
        samples: u64,
        steps: u32,
    ) -> SignedUpdate {
        let claim = UpdateClaim::new(
            round_id,
            base,
            worker.address().unwrap(),
            local,
            samples,
            steps,
            0.5,
        );
        SignedUpdate::sign(worker, claim).unwrap()
    }

    #[test]
    fn a_signed_update_round_trips_and_verifies() {
        let base = Mlp::new(1);
        let worker = wallet(2);
        let mut local = base.clone();
        local.b2[0] += 0.1;
        let signed = update(1, &base, &worker, &local, 32, 10);
        signed.verify().unwrap();
        let bytes = signed.encode();
        let back = SignedUpdate::decode(&bytes).unwrap();
        assert_eq!(back, signed);
        back.verify().unwrap();
    }

    #[test]
    fn a_tampered_delta_breaks_the_commitment() {
        let base = Mlp::new(1);
        let worker = wallet(3);
        let mut local = base.clone();
        local.b2[0] += 0.1;
        let mut signed = update(1, &base, &worker, &local, 32, 10);
        signed.claim.delta.b2[0] += 0.2;
        assert!(signed.verify().is_err());
    }

    #[test]
    fn a_round_needs_quorum_and_splits_the_pot_exactly() {
        let data = two_moons(32, 5);
        let parts = shards(&data, 3);
        let base = Mlp::new(5);
        let mut cfg = RoundConfig::new(1, 2);
        cfg.reward_pot_sat = 1_000_003;
        let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
        for (i, seed) in [11u8, 12, 13].iter().enumerate() {
            let worker = wallet(*seed);
            round
                .register_worker(worker.address().unwrap(), 10_000, 64)
                .unwrap();
            let mut local = base.clone();
            let (_, grad) = local.loss_and_grad(&parts[i]);
            local.sgd_step(&grad, 0.3);
            round
                .submit(update(1, &base, &worker, &local, 32, 1))
                .unwrap();
        }
        match round.finalize() {
            RoundOutcome::Finalized(done) => {
                assert!(done.rewards_are_exact());
                assert_eq!(done.accepted.len(), 3);
                assert_ne!(done.model_hash, base.hash());
            }
            other => panic!("expected finalization, got {other:?}"),
        }
    }

    #[test]
    fn too_few_updates_fails_closed() {
        let base = Mlp::new(6);
        let mut cfg = RoundConfig::new(2, 2);
        cfg.reward_pot_sat = 500;
        let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
        let worker = wallet(21);
        round
            .register_worker(worker.address().unwrap(), 10_000, 64)
            .unwrap();
        let mut local = base.clone();
        local.b2[0] += 0.1;
        round
            .submit(update(2, &base, &worker, &local, 32, 1))
            .unwrap();
        match round.finalize() {
            RoundOutcome::Failed { reason, .. } => {
                assert!(matches!(reason, Rejection::NotEnoughUpdates { .. }));
            }
            other => panic!("expected failure, got {other:?}"),
        }
    }
}
