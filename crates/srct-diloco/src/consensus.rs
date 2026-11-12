//! Staged proof-of-useful-work consensus package (inactive by default).
//!
//! Hash mining remains the only block-security mechanism on every profile:
//! `pouw_activation_height` is `0` (off) everywhere, the same convention as
//! `pq_activation_height`. Nothing here executes unless a profile activates
//! it, and activation with `0` changes no block-validity rule, mints no coin
//! and alters no schedule. What this module *does* complete, as pure
//! mechanism with exact tests, is every item §7 of `docs/dual-mining.md`
//! demands before any fork:
//!
//! 1. **Deterministic training kernel** — done elsewhere (`FixedMlp`,
//!    `BitExact` tier); the challenge path below pins its determinism class.
//! 2. **Round anchoring** — [`RoundAnchor`]: round id, base-model hash,
//!    accepted worker set commitment and aggregate commitment, with a bounded
//!    canonical encoding. A fork would commit this object in a block or in L2
//!    state; the object and its refusal rules exist now.
//! 3. **Reward schedule** — [`pouw_mint_sat`]: the PoUW portion shares the
//!    existing schedule. Coinbase plus PoUW mint is validated through the real
//!    [`check_mint_at_height`](srct_core::supply::check_mint_at_height) gate,
//!    so PoUW issuance can never exceed the issuance integral or the rate
//!    anchor. The ladder era is exact, so an active PoUW mint requires the
//!    coinbase to yield headroom — pinned by test.
//! 4. **Eligibility and Sybil resistance** — [`worker_eligible`]: posted bond
//!    at or above a positive floor, no fraud slash. The floor must be
//!    positive: a zero floor admits every Sybil for free and is refused.
//!    Post-fork the bond figure comes from the L1 bond ledger; the predicate
//!    does not change.
//! 5. **Challenge path** — [`reexecute_check`]: a bonded challenger re-runs
//!    the worker's local steps on the dispute-context shard and compares the
//!    recomputed delta against the claimed one within the backend's
//!    determinism tolerance ([`tolerance_for`]). A mismatch is `Fraud`.
//!    Post-fork the claim envelope must commit to the shard and the
//!    hyperparameters (wire v2); the re-execution comparison does not change.
//! 6. **Fork schedule and migration** — the switch exists
//!    (`pouw_activation_height`, default off on every profile) and
//!    [`pouw_active`] is its single reader. Activation heights, test vectors
//!    and the economic review remain governance steps, not code.
//! 7. **Low-participation rule** — [`pouw_mint_for_round`]: without quorum no
//!    PoUW reward is minted for the period and hash mining continues
//!    unchanged.

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::params::NetworkParams;
use srct_core::ser::{Reader, Writer};
use srct_core::supply::{block_reward_sat, check_mint_at_height};

use crate::backend::{local_update_with, DeterminismClass, TrainBackend};
use crate::data::Sample;
use crate::model::{Mlp, MODEL_VERSION};

pub const ROUND_ANCHOR_VERSION: u8 = 1;
/// Most workers one anchor may name.
pub const MAX_ANCHOR_WORKERS: usize = 1024;
const DOM_ROUND_ANCHOR: &[u8] = b"srct/diloco/round-anchor/v1";

/// Why staged PoUW verification refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PouwError {
    Malformed(String),
    NotActive,
    ExceedsSchedule(String),
    Ineligible,
    Fraud,
    QuorumNotMet,
}

impl std::fmt::Display for PouwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PouwError::Malformed(detail) => write!(f, "malformed pouw object: {detail}"),
            PouwError::NotActive => write!(f, "proof-of-useful-work is not active"),
            PouwError::ExceedsSchedule(detail) => {
                write!(f, "pouw mint exceeds the issuance schedule: {detail}")
            }
            PouwError::Ineligible => write!(f, "worker is not eligible for pouw rewards"),
            PouwError::Fraud => write!(f, "re-execution does not match the claimed update"),
            PouwError::QuorumNotMet => write!(f, "round did not reach quorum"),
        }
    }
}

impl std::error::Error for PouwError {}

/// Whether PoUW minting and anchoring apply at `height`. `0` means never —
/// the same convention as `pq_activation_height`.
pub fn pouw_active(params: &NetworkParams, height: u64) -> bool {
    params.pouw_activation_height != 0 && height >= params.pouw_activation_height
}

/// The consensus object a fork would commit: which round, trained from what
/// base, by which accepted workers, to what aggregate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundAnchor {
    pub version: u8,
    pub network_id: String,
    pub round_id: u64,
    pub base_model: Hash,
    /// Accepted worker addresses, sorted and unique.
    pub workers: Vec<Address>,
    /// Commitment to the finalized aggregate model bytes.
    pub aggregate: Hash,
    /// Height the round finalized at.
    pub height: u64,
}

impl RoundAnchor {
    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_ROUND_ANCHOR, &[&self.encode()])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128 + self.network_id.len() + self.workers.len() * 20);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .u64le(self.round_id)
            .fixed(&self.base_model);
        w.u16le(self.workers.len() as u16);
        for worker in &self.workers {
            w.fixed(worker);
        }
        w.fixed(&self.aggregate).u64le(self.height);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PouwError> {
        let bad = |detail: &str| PouwError::Malformed(format!("round anchor {detail}"));
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| bad("version is missing"))?;
        if version != ROUND_ANCHOR_VERSION {
            return Err(bad("version is unknown"));
        }
        let net_len = r.u16le().map_err(|_| bad("network is missing"))? as usize;
        if net_len == 0 || net_len > 128 {
            return Err(bad("network id length is bad"));
        }
        let network_id = std::str::from_utf8(
            r.fixed_slice(net_len)
                .map_err(|_| bad("network bytes are missing"))?,
        )
        .map_err(|_| bad("network is not utf-8"))?
        .to_string();
        let round_id = r.u64le().map_err(|_| bad("round id is missing"))?;
        let base_model: Hash = r.fixed().map_err(|_| bad("base model is missing"))?;
        let count = r.u16le().map_err(|_| bad("worker count is missing"))? as usize;
        if count == 0 || count > MAX_ANCHOR_WORKERS {
            return Err(bad("worker set is empty or over cap"));
        }
        let mut workers = Vec::with_capacity(count);
        for _ in 0..count {
            workers.push(r.fixed().map_err(|_| bad("worker bytes are missing"))?);
        }
        let sorted = {
            let mut s = workers.clone();
            s.sort();
            s
        };
        if workers != sorted {
            return Err(bad("worker set is not sorted"));
        }
        {
            let mut dedup = sorted.clone();
            dedup.dedup();
            if dedup.len() != workers.len() {
                return Err(bad("worker set holds a duplicate"));
            }
        }
        let aggregate: Hash = r.fixed().map_err(|_| bad("aggregate is missing"))?;
        let height = r.u64le().map_err(|_| bad("height is missing"))?;
        r.expect_end().map_err(|_| bad("has trailing bytes"))?;
        let anchor = RoundAnchor {
            version,
            network_id,
            round_id,
            base_model,
            workers,
            aggregate,
            height,
        };
        anchor.verify()?;
        Ok(anchor)
    }

    /// Refuse anything that must never anchor: empty or zero hashes, a zero
    /// round with no height, an empty worker set (also refused at decode).
    pub fn verify(&self) -> Result<(), PouwError> {
        if self.version != ROUND_ANCHOR_VERSION {
            return Err(PouwError::Malformed(
                "round anchor version is unknown".into(),
            ));
        }
        if self.network_id.is_empty() || self.network_id.len() > 128 {
            return Err(PouwError::Malformed(
                "round anchor network id is bad".into(),
            ));
        }
        if self.base_model == [0u8; 32] {
            return Err(PouwError::Malformed(
                "round anchor base model is zero".into(),
            ));
        }
        if self.aggregate == [0u8; 32] {
            return Err(PouwError::Malformed(
                "round anchor aggregate is zero".into(),
            ));
        }
        if self.workers.is_empty() || self.workers.len() > MAX_ANCHOR_WORKERS {
            return Err(PouwError::Malformed(
                "round anchor worker set is bad".into(),
            ));
        }
        if self.height == 0 {
            return Err(PouwError::Malformed("round anchor height is zero".into()));
        }
        Ok(())
    }
}

/// Admissibility of a PoUW mint at `height`, sharing the existing schedule.
///
/// Coinbase plus PoUW mint passes through the real issuance gate, so the sum
/// can never exceed the issuance integral or the rate anchor. Before
/// activation any nonzero PoUW claim is refused and the layer has no opinion
/// on the coinbase. Returns the new issued total.
pub fn pouw_mint_sat(
    params: &NetworkParams,
    issued_so_far: u64,
    coinbase_reward: u64,
    pouw_requested: u64,
    height: u64,
) -> Result<u64, PouwError> {
    if !pouw_active(params, height) {
        if pouw_requested > 0 {
            return Err(PouwError::NotActive);
        }
        return Ok(issued_so_far);
    }
    let total = coinbase_reward
        .checked_add(pouw_requested)
        .ok_or_else(|| PouwError::ExceedsSchedule("pouw mint overflows".into()))?;
    check_mint_at_height(params, issued_so_far, total, height)
        .map_err(|e| PouwError::ExceedsSchedule(e.to_string()))
}

/// PoUW reward for one round: zero without quorum. Hash mining continues
/// unchanged — this function only gates the PoUW portion.
pub fn pouw_mint_for_round(accepted: usize, min_quorum: usize, requested_sat: u64) -> u64 {
    if accepted >= min_quorum.max(1) {
        requested_sat
    } else {
        0
    }
}

/// Worker eligibility for PoUW rewards: bonded at or above a positive floor,
/// never slashed. A zero floor admits every Sybil for free and is refused.
pub fn worker_eligible(posted_bond_sat: u64, slashed: bool, min_bond_sat: u64) -> bool {
    min_bond_sat > 0 && !slashed && posted_bond_sat >= min_bond_sat
}

/// Determinism tolerance for challenge re-execution, in absolute parameter
/// units. Bit-exact kernels must reproduce byte-identically.
pub fn tolerance_for(class: DeterminismClass) -> f32 {
    match class {
        DeterminismClass::BitExact => 0.0,
        DeterminismClass::Reproducible => 1e-5,
        DeterminismClass::Statistical => 1e-3,
    }
}

/// Challenge re-execution: re-run the worker's local steps and compare the
/// recomputed delta against the claimed one.
///
/// `shard`, `steps` and `lr` come from the dispute context; post-fork the
/// claim envelope must commit to them (wire v2) — the comparison does not
/// change. A mismatch beyond the backend's tolerance is `Fraud`.
pub fn reexecute_check(
    backend: &dyn TrainBackend,
    base: &Mlp,
    shard: &[Sample],
    steps: u32,
    lr: f32,
    claimed_delta: &Mlp,
    tolerance: f32,
) -> Result<(), PouwError> {
    if shard.is_empty() || steps == 0 {
        return Err(PouwError::Malformed(
            "challenge shard or steps are empty".into(),
        ));
    }
    let local = local_update_with(backend, base, shard, steps, lr)
        .map_err(|e| PouwError::Malformed(e.to_string()))?;
    let expected = local.model.sub(base);
    let mut worst = 0.0f32;
    for (a, b) in expected.params().iter().zip(claimed_delta.params().iter()) {
        worst = worst.max((a - b).abs());
    }
    if !worst.is_finite() || worst > tolerance {
        return Err(PouwError::Fraud);
    }
    Ok(())
}

/// Convenience: block reward of the profile at `height`, for mint tests.
pub fn profile_reward(params: &NetworkParams, height: u64) -> u64 {
    block_reward_sat(params, height)
}

/// Model-format version this consensus package pins. A fork must not mix
/// delta bytes across model versions.
pub fn pinned_model_version() -> u32 {
    MODEL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CpuBackend;
    use crate::data::two_moons;

    fn mini() -> NetworkParams {
        NetworkParams::mini()
    }

    #[test]
    fn pouw_is_inactive_on_every_shipped_profile() {
        for params in [
            NetworkParams::mainnet(),
            NetworkParams::testnet(),
            NetworkParams::mini(),
        ] {
            assert_eq!(params.pouw_activation_height, 0);
            assert!(!pouw_active(&params, u64::MAX));
            // Inactive: a nonzero claim is refused, zero mint is a no-op.
            assert_eq!(
                pouw_mint_sat(&params, 1_000, 50, 1, 1_000_000),
                Err(PouwError::NotActive)
            );
            assert_eq!(pouw_mint_sat(&params, 1_000, 50, 0, 1_000_000), Ok(1_000));
        }
    }

    #[test]
    fn active_pouw_mint_shares_the_schedule_exactly() {
        let mut params = mini();
        params.pouw_activation_height = 1;
        let height = 6u64;
        let issued = srct_core::supply::cumulative_issuance_sat(&params, height - 1);
        let coinbase = block_reward_sat(&params, height);
        // The ladder-era integral is exact: a full coinbase plus any PoUW
        // mint exceeds it.
        assert!(matches!(
            pouw_mint_sat(&params, issued, coinbase, 1, height),
            Err(PouwError::ExceedsSchedule(_))
        ));
        // The coinbase yielding one satoshi of headroom admits one satoshi.
        let total = pouw_mint_sat(&params, issued, coinbase - 1, 1, height).unwrap();
        assert_eq!(total, issued + coinbase);
    }

    #[test]
    fn low_participation_mints_nothing() {
        assert_eq!(pouw_mint_for_round(1, 2, 1_000), 0);
        assert_eq!(pouw_mint_for_round(2, 2, 1_000), 1_000);
        assert_eq!(pouw_mint_for_round(0, 1, 1_000), 0);
    }

    #[test]
    fn eligibility_needs_a_positive_bonded_floor() {
        assert!(worker_eligible(10_000, false, 10_000));
        assert!(!worker_eligible(9_999, false, 10_000));
        assert!(!worker_eligible(10_000, true, 10_000));
        // A zero floor admits every Sybil: refused, not open participation.
        assert!(!worker_eligible(u64::MAX, false, 0));
    }

    #[test]
    fn round_anchor_round_trips_and_refuses_misbinding() {
        let anchor = RoundAnchor {
            version: ROUND_ANCHOR_VERSION,
            network_id: "srct/mini".into(),
            round_id: 7,
            base_model: [11u8; 32],
            workers: vec![[1u8; 20], [2u8; 20]],
            aggregate: [13u8; 32],
            height: 100,
        };
        assert_eq!(RoundAnchor::decode(&anchor.encode()).unwrap(), anchor);
        // Unsorted workers are refused at decode.
        let mut bad = anchor.clone();
        bad.workers.reverse();
        assert!(RoundAnchor::decode(&bad.encode()).is_err());
        // Empty and zero fields are refused.
        let mut bad = anchor.clone();
        bad.workers.clear();
        assert!(bad.verify().is_err());
        let mut bad = anchor.clone();
        bad.aggregate = [0u8; 32];
        assert!(bad.verify().is_err());
        // Truncation and version corruption fail closed.
        let bytes = anchor.encode();
        assert!(RoundAnchor::decode(&bytes[..bytes.len() - 4]).is_err());
        let mut bad = bytes.clone();
        bad[0] = 99;
        assert!(RoundAnchor::decode(&bad).is_err());
    }

    #[test]
    fn challenge_catches_a_fabricated_delta() {
        let backend = CpuBackend;
        let base = Mlp::new(3);
        let shard = two_moons(4, 11);
        let local = crate::backend::local_update_with(&backend, &base, &shard, 2, 0.05).unwrap();
        let delta = local.model.sub(&base);
        // Honest delta passes well inside the reproducible tolerance.
        reexecute_check(
            &backend,
            &base,
            &shard,
            2,
            0.05,
            &delta,
            tolerance_for(DeterminismClass::Reproducible),
        )
        .unwrap();
        // A fabricated delta fails even at the statistical tolerance.
        let mut fake = delta.clone();
        fake.w1[0] += 1.0;
        assert_eq!(
            reexecute_check(
                &backend,
                &base,
                &shard,
                2,
                0.05,
                &fake,
                tolerance_for(DeterminismClass::Statistical)
            ),
            Err(PouwError::Fraud)
        );
        // Empty shard is malformed, not fraud.
        assert!(matches!(
            reexecute_check(&backend, &base, &[], 2, 0.05, &delta, 1.0),
            Err(PouwError::Malformed(_))
        ));
    }
}
