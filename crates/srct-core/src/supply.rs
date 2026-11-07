//! Halving-ladder supply schedule with the approved tail. SPEC.md §7.
//!
//! Design doc Section 16: 76 SRCT per block, halving every 262 800 blocks
//! (5 years) over an 8-rung whole-SRCT ladder. The ladder is followed by the
//! tail approved 2026-10-09 (`docs/decisions.md` M-A..M-C): mainnet decays
//! 0.50 → 0.25 → 0.125 SRCT to a permanent 0.1 SRCT floor; fast profiles pay a
//! constant 1-sat token tail. The load-bearing mint bound is the issuance
//! integral `cumulative_issuance_sat(height)`. After the approved relocation of
//! the conservation-anchor and escrow-backing jobs (M-D/M-E, shipped 2026-10-09)
//! and Stage SA-1 (Decision 18), `supply_cap_sat` is gone from the mint bound and
//! the report; the rate anchor (Stage SA-3) is the only cap left.

use crate::error::{Error, Result};
use crate::params::NetworkParams;

/// Number of halvings already elapsed at `height`.
///
/// Clamped rather than truncated by `as u32`: past ~1.1e15 blocks the quotient
/// exceeds `u32::MAX` and a silent wrap would make the reported halving count
/// disagree with the reward actually paid.
pub fn halvings(params: &NetworkParams, height: u64) -> u32 {
    (height / params.halving_period).min(u32::MAX as u64) as u32
}

/// Block reward in satoshis for the halving epoch at `period`.
///
/// The ladder is halved in **whole SRCT**, not by shifting satoshis, so the
/// schedule is exactly the design doc's 76, 38, 19, 9, 4, 2, 1, 0 (Section 16).
/// Shifting satoshis instead would give 76, 38, 19, 9.5, 4.75 ... and break the
/// arithmetic.
pub fn period_reward_sat(params: &NetworkParams, period: u32) -> u64 {
    if period >= 64 {
        return 0;
    }
    let start_srct = params.start_reward_sat / crate::params::SAT_PER_SRCT;
    (start_srct >> period) * crate::params::SAT_PER_SRCT
}

/// First period whose ladder rung is zero (7 for mainnet's 76-SRCT start).
///
/// The tail phase begins here; activation is implicit and exact because
/// `reward(height)` is a pure function of height and every height below this
/// keeps its ladder rung — historical blocks validate byte-identically
/// (monetary-redesign §5.4).
pub fn exhaustion_period(params: &NetworkParams) -> u32 {
    let start_srct = params.start_reward_sat / crate::params::SAT_PER_SRCT;
    for p in 0..64u32 {
        if (start_srct >> p) == 0 {
            return p;
        }
    }
    64
}

/// Block reward in satoshis: the ladder rung while a rung is non-zero, then
/// the profile's tail (approved M-A, 2026-10-09).
///
/// Mainnet ladder 76, 38, 19, 9, 4, 2, 1 SRCT, then Policy E decay
/// 0.50 → 0.25 → 0.125 → the permanent 0.1 SRCT floor — every step at most a
/// halving, the step into the floor the smallest of the series. Fast
/// profiles pay their constant token tail from the first tail period.
pub fn block_reward_sat(params: &NetworkParams, height: u64) -> u64 {
    let period = halvings(params, height);
    let rung = period_reward_sat(params, period);
    if rung > 0 {
        return rung;
    }
    match params.tail {
        crate::params::TailEmission::None => 0,
        crate::params::TailEmission::Constant { per_block_sat } => per_block_sat,
        crate::params::TailEmission::DecayToFloor { floor_sat } => {
            // k = 1 at the first tail period (0.5 SRCT), halved in satoshis
            // each period: 1.00 (ladder) → 0.50 → 0.25 → 0.125 → floor.
            let k = period.saturating_sub(exhaustion_period(params).saturating_sub(1));
            let decay = if k >= 64 {
                0
            } else {
                crate::params::SAT_PER_SRCT >> k
            };
            decay.max(floor_sat)
        }
    }
}

/// Total issuance after `mined_blocks` blocks have been mined **on top of
/// genesis**.
///
/// Genesis mints nothing (Section 16: 0% premine), so heights run `1..=N`.
/// Getting this off-by-one wrong makes a node over-report issuance by a full
/// block reward, which is exactly the number someone would publish as
/// "coins mined".
///
/// Overflow posture: the accumulation saturates rather than wraps or traps.
/// That is deliberate — consensus must never halt on arithmetic of a
/// configured schedule — but it means a profile whose schedule integral
/// reaches `u64::MAX` stops bounding (bound == MAX admits everything).
/// Profile authors own schedule sanity: every decided profile's millennium
/// issuance is pinned by test below `u64::MAX / 2`, so saturation is
/// unreachable there. Do not raise `start_reward_sat` orders of magnitude
/// without re-pinning those tests.
pub fn cumulative_supply_sat(params: &NetworkParams, mined_blocks: u64) -> u64 {
    let mut total: u64 = 0;
    let mut start = 1u64;
    // A tail never reaches a zero reward, so the loop is bounded by
    // `mined_blocks / halving_period`, not by 64 periods.
    while start <= mined_blocks {
        let period = halvings(params, start);
        // Period p covers heights `p·H ..= (p+1)·H − 1`: block `(p+1)·H`
        // already pays the *next* rung, so including it here would count one
        // block at the wrong reward at every boundary.
        let period_end =
            ((period as u64 + 1).saturating_mul(params.halving_period)).saturating_sub(1);
        let end = mined_blocks.min(period_end);
        let reward = block_reward_sat(params, start);
        if reward == 0 {
            // `TailEmission::None`: issuance has stopped for good.
            break;
        }
        total = total.saturating_add(reward.saturating_mul(end - start + 1));
        start = end + 1;
    }
    total
}

/// The load-bearing mint bound (monetary-redesign §5.1 rule 1, approved
/// 2026-10-09): the most value the chain may hold at `height` is the
/// integral of the reward function through that height. Non-decreasing in
/// `height` by construction — every term is non-negative.
pub fn cumulative_issuance_sat(params: &NetworkParams, height: u64) -> u64 {
    cumulative_supply_sat(params, height)
}

/// First height at which the reward is the tail rather than a ladder rung.
pub fn exhaustion_height(params: &NetworkParams) -> u64 {
    exhaustion_period(params) as u64 * params.halving_period
}

/// The ladder-era integral: what the schedule can actually issue through the
/// last ladder block. This is the figure the supply report quotes; it is not a
/// bound (the bound is per-height and is the issuance integral itself).
///
/// It is the exact integral through the last ladder block, not
/// `Σ rung(p) · halving_period`: genesis occupies a rung-0 height without
/// minting anything (0 % premine), so the first rung is paid by
/// `H − 1` blocks rather than `H`. Mainnet's exact figure is therefore
/// 39,157,124 SRCT, 76 SRCT below the geometric-shortcut 39,157,200 the design
/// doc quotes — the figure this function reports is the one the chain can
/// reach.
pub fn max_issuance_sat(params: &NetworkParams) -> u64 {
    cumulative_supply_sat(params, exhaustion_height(params) - 1)
}

/// After Stage SA-3, the only bound on growth of the issuance integral per
/// period is the rate anchor: gross issuance in any `halving_period` window
/// ending at `height` must not exceed 1 % of the issuance integral at the
/// window's start (Decision 18 §4.3 — ≤ 0.2 %/yr across the window).
/// Before ladder exhaustion there is no period window to anchor, so the
/// ladder is grandfathered and bounded by its own constants.
pub fn rate_anchor_allowance(params: &NetworkParams, height: u64) -> u64 {
    // Before exhaustion the ladder is grandfathered: the integral is bounded
    // by its own (much smaller) ladder constants, so no ceiling applies.
    if height < exhaustion_height(params) {
        return u64::MAX;
    }
    let window_start = (height / params.halving_period) * params.halving_period;
    let issued_start = cumulative_issuance_sat(params, window_start.saturating_sub(1));
    // 1 % of the supply issued at the window's start, in satoshis.
    (issued_start / 100).max(1)
}

/// Gross issuance already paid inside `height`'s period window
/// (`floor(height / H) · H ..= height - 1`). The rate anchor bounds this
/// quantity plus the next reward; the mint gate is the only caller.
pub fn period_issued_sat(params: &NetworkParams, issued_so_far: u64, height: u64) -> u64 {
    if height < exhaustion_height(params) {
        return 0;
    }
    let window_start = (height / params.halving_period) * params.halving_period;
    let issued_start = cumulative_issuance_sat(params, window_start.saturating_sub(1));
    issued_so_far.saturating_sub(issued_start)
}

/// The mint gate the chain applies, at a height.
///
/// Two bounds, both pure functions of chain state (Decision 18):
///
/// 1. **Issuance integral** (monetary-redesign §5.1 rule 1, approved
///    2026-10-09): the most value the chain may hold at `height` is the
///    integral of the reward function through that height. There is no stock
///    cap any more — the `.min(supply_cap_sat)` is gone (Stage SA-2).
/// 2. **Rate anchor** (§4.3): after ladder exhaustion, gross issuance inside
///    the current `halving_period` window plus `reward` must not exceed 1 % of
///    the supply issued at the window's start. The ladder era is grandfathered.
///
/// `Chain::apply_block` calls exactly this, so the miner, the validator and the
/// node report cannot disagree about how much is mintable at a height.
///
/// Returns the new issued total. A `u64` overflow is refused rather than
/// wrapped: a wrapped sum would compare small and pass the bound.
pub fn check_mint_at_height(
    params: &NetworkParams,
    issued_so_far: u64,
    reward: u64,
    height: u64,
) -> Result<u64> {
    let want = issued_so_far
        .checked_add(reward)
        .ok_or(Error::SupplyRateExceeded {
            already: issued_so_far,
            requested: reward,
            allowed_in_period: rate_anchor_allowance(params, height),
        })?;
    let bound = cumulative_issuance_sat(params, height);
    if want > bound {
        return Err(Error::SupplyRateExceeded {
            already: issued_so_far,
            requested: reward,
            allowed_in_period: bound.saturating_sub(issued_so_far),
        });
    }
    // Rate anchor: the period's gross issuance plus this reward must fit in
    // 1 % of the supply issued at the window's start. The approved schedule
    // sits ~3x under this ceiling, so it never binds in normal operation; it
    // exists to refuse a future schedule that would dilute far faster.
    let allowed_in_period = rate_anchor_allowance(params, height);
    let period_after = period_issued_sat(params, issued_so_far, height).saturating_add(reward);
    if period_after > allowed_in_period {
        return Err(Error::SupplyRateExceeded {
            already: issued_so_far,
            requested: reward,
            allowed_in_period,
        });
    }
    Ok(want)
}

/// A height-oblivious legacy mint check, kept only so call sites that do not
/// carry a block height can still refuse a freshly-written value being attached
/// to an old chain. The consensus gate is [`check_mint_at_height`].
///
/// After Stage SA-1 there is no stock ceiling; a height-oblivious caller
/// cannot be checked against the rate anchor except by refusing any single mint
/// at all, which would be wrong, so the only refusal this keeps is overflow.
pub fn check_mint(_params: &NetworkParams, issued_so_far: u64, reward: u64) -> Result<u64> {
    issued_so_far
        .checked_add(reward)
        .ok_or(Error::SupplyRateExceeded {
            already: issued_so_far,
            requested: reward,
            allowed_in_period: u64::MAX,
        })?;
    Ok(issued_so_far + reward)
}

/// True when adding `reward` to `issued` would swamp the `u64` space, so a
/// saturating-add path must not be used.
pub fn reward_exceeds_remaining(_params: &NetworkParams, issued: u64, reward: u64) -> bool {
    issued.saturating_add(reward) < issued || issued.saturating_add(reward) < reward
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SAT_PER_SRCT;
    #[test]
    fn mainnet_reward_ladder() {
        let p = NetworkParams::mainnet();
        let expect = [76u64, 38, 19, 9, 4, 2, 1];
        for (i, srct) in expect.iter().enumerate() {
            let h = (i as u64) * p.halving_period;
            assert_eq!(block_reward_sat(&p, h) / SAT_PER_SRCT, *srct, "halving {i}");
        }
        // Tail phase (approved Policy E): 0.50, 0.25, 0.125 SRCT, then the
        // 0.1 floor held forever — the last step is the -20 % clamp into
        // the floor, the smallest step of the series.
        let floor = 10_000_000u64;
        let tail = [
            (7u32, 50_000_000u64),
            (8, 25_000_000),
            (9, 12_500_000),
            (10, floor),
            (11, floor),
            (63, floor),
        ];
        for (period, want) in tail {
            assert_eq!(
                block_reward_sat(&p, period as u64 * p.halving_period),
                want,
                "tail period {period}"
            );
        }
    }
    #[test]
    fn historical_heights_keep_their_ladder_rungs_under_the_tail() {
        // Activation at exhaustion (§5.4): every height below it pays exactly
        // its ladder rung, so every historical block validates identically.
        for params in [
            NetworkParams::mainnet(),
            NetworkParams::mini(),
            NetworkParams::testnet(),
        ] {
            for period in 0..exhaustion_period(&params) {
                for off in [0u64, 1, params.halving_period - 1] {
                    let h = period as u64 * params.halving_period + off;
                    assert_eq!(
                        block_reward_sat(&params, h),
                        period_reward_sat(&params, period),
                        "{} height {h}",
                        params.name
                    );
                }
            }
        }
    }
    #[test]
    fn every_tail_step_is_at_most_a_halving_and_reaches_the_floor() {
        let p = NetworkParams::mainnet();
        let mut prev = period_reward_sat(&p, exhaustion_period(&p) - 1); // 1 SRCT
        for period in exhaustion_period(&p)..exhaustion_period(&p) + 8 {
            let now = block_reward_sat(&p, period as u64 * p.halving_period);
            // A step is at most a halving (drop <= 50 %): the reward never
            // falls below half the previous one, and it never rises.
            assert!(
                now <= prev && now * 2 >= prev,
                "period {period}: {now} is not a step of at most a halving from {prev}"
            );
            prev = now;
        }
        assert_eq!(prev, 10_000_000, "the floor is reached and held");
    }
    #[test]
    fn fast_profile_tails_are_token_tails() {
        // F5: a mainnet-sized tail on 1-second blocks would mint >1000 %/yr
        // against the fast cap. The fast profiles pay 1 sat/block forever.
        for p in [NetworkParams::mini(), NetworkParams::testnet()] {
            assert_eq!(block_reward_sat(&p, 14_000), 1, "{}", p.name);
            assert_eq!(block_reward_sat(&p, 100_000), 1, "{}", p.name);
            // From the first tail block on, the integral grows by exactly
            // one sat per block.
            assert_eq!(
                cumulative_supply_sat(&p, 40_000) - cumulative_supply_sat(&p, 14_000),
                26_000,
                "{}",
                p.name
            );
        }
        // Mainnet at the same height is still on its ladder.
        assert_eq!(
            block_reward_sat(&NetworkParams::mainnet(), 14_000),
            76 * SAT_PER_SRCT
        );
    }
    #[test]
    fn cumulative_issuance_is_monotonic_and_matches_the_reward_integral() {
        let p = NetworkParams::mini();
        let checkpoints = [
            0u64, 1, 2, 1_999, 2_000, 2_001, 13_999, 14_000, 14_001, 40_000,
        ];
        let mut prev = 0u64;
        for &h in &checkpoints {
            let now = cumulative_issuance_sat(&p, h);
            assert!(now >= prev, "bound decreased at height {h}");
            prev = now;
        }
        let mut running = 0u64;
        for h in 1..=40_000u64 {
            running = running.saturating_add(block_reward_sat(&p, h));
            if checkpoints.contains(&h) {
                assert_eq!(cumulative_issuance_sat(&p, h), running, "height {h}");
            }
        }
    }
    #[test]
    fn u64_overflow_unreachable_for_the_decided_tail() {
        // A century of 1-second blocks under the token tail, and a millennium
        // of 10-minute blocks under the mainnet floor, both stay far below
        // u64 — saturating arithmetic is defence, never the boundary.
        let mini = NetworkParams::mini();
        let century = 100 * 365 * 86_400u64; // 3.15e9 blocks
                                             // Ladder first (297,924 SRCT over mini's first 13,999 blocks), then
                                             // one sat per remaining block forever.
        assert_eq!(
            cumulative_supply_sat(&mini, century),
            297_924 * SAT_PER_SRCT + (century - 13_999)
        );
        let main = NetworkParams::mainnet();
        let millennium = 1_000 * 52_596u64; // ~1000 years of 10-min blocks
        let total = cumulative_supply_sat(&main, millennium);
        assert!(
            total < u64::MAX / 2,
            "issuance {total} must not approach the overflow"
        );
    }
    #[test]
    fn reward_is_constant_within_a_period() {
        let p = NetworkParams::mini();
        for off in 0..p.halving_period {
            assert_eq!(
                block_reward_sat(&p, off),
                p.start_reward_sat,
                "reward changed at offset {off} of the first period"
            );
        }
        assert_eq!(
            block_reward_sat(&p, p.halving_period),
            38 * crate::params::SAT_PER_SRCT
        );
    }
    #[test]
    fn genesis_mints_nothing() {
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            assert_eq!(cumulative_supply_sat(&p, 0), 0);
            assert_eq!(
                cumulative_supply_sat(&p, 1),
                p.start_reward_sat,
                "one mined block pays exactly one reward"
            );
            assert_eq!(cumulative_supply_sat(&p, 5), p.start_reward_sat * 5);
        }
    }
    #[test]
    fn cumulative_supply_matches_design_doc() {
        let p = NetworkParams::mainnet();
        // Design doc Section 16: 2 x 262,800 x 76 = 39,945,600 was the old
        // stock cap (removed by Decision 18).
        // Actual issuance is the floor-divided geometric sum: 149 x 262,800.
        // Ladder-era issuance through exhaustion, with exact block-reward
        // semantics: block h pays `block_reward_sat(h)`, so each period's
        // last block already pays the next rung (the old integral counted
        // it one period early — a reporting off-by-one, never load-bearing,
        // now pinned exactly). Through height 1,839,600 = 7 x halving_period
        // — the first tail block, at 0.5 SRCT — that is 39,157,124.5 SRCT.
        let issued = cumulative_supply_sat(&p, 7 * p.halving_period);
        assert_eq!(issued, 39_157_124 * SAT_PER_SRCT + 50_000_000);
    }
    #[test]
    fn max_issuance_is_the_ladder_era_integral() {
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            let max = max_issuance_sat(&p);
            // It equals the exact ladder-only integral through the last ladder
            // block — the figure the supply report quotes, not a bound (the
            // bound is per-height).
            assert!(max > 0);
            assert_eq!(max, cumulative_supply_sat(&p, exhaustion_height(&p) - 1));
            // And it is exactly one genesis slot short of the geometric
            // shortcut `Σ rung(p) · H` that the design doc quotes: height 0
            // pays no reward, so the first rung is paid by `H - 1` blocks.
            let mut shortcut = 0u64;
            for period in 0..exhaustion_period(&p) {
                shortcut = shortcut
                    .saturating_add(period_reward_sat(&p, period).saturating_mul(p.halving_period));
            }
            assert_eq!(max, shortcut - period_reward_sat(&p, 0));
        }
        // The pinned mainnet and mini figures, so a refactor of the integral
        // cannot quietly move the number the docs publish.
        assert_eq!(
            max_issuance_sat(&NetworkParams::mainnet()),
            39_157_124 * SAT_PER_SRCT
        );
        assert_eq!(
            max_issuance_sat(&NetworkParams::mini()),
            297_924 * SAT_PER_SRCT
        );
    }
    #[test]
    fn cumulative_supply_is_monotonic_and_partial_periods_count() {
        let p = NetworkParams::mini();
        let mut prev = 0;
        for n in [
            0u64,
            1,
            2,
            p.halving_period,
            p.halving_period + 1,
            3 * p.halving_period,
        ] {
            let s = cumulative_supply_sat(&p, n);
            assert!(s >= prev, "supply must not decrease at {n} mined blocks");
            prev = s;
        }
        // Blocks 1..=H−1 pay the starting reward; block H and H+1 already
        // pay the halved one — exact block-reward semantics, boundary
        // included.
        assert_eq!(
            cumulative_supply_sat(&p, p.halving_period + 1),
            p.start_reward_sat * (p.halving_period - 1) + 2 * 38 * crate::params::SAT_PER_SRCT
        );
    }
    #[test]
    fn rate_anchor_allowance_at_exhaustion_is_sensible_for_the_decided_tail() {
        let main = NetworkParams::mainnet();
        // At the first tail block the integral is already huge (39.16M SRCT),
        // so the 0.2 % allowance across one 262,800-block period is far larger
        // than the period's actual issuance under the floor (5,259,600 sat).
        let allowance_at_tail = rate_anchor_allowance(&main, exhaustion_height(&main));
        let floor_period_issuance = 52_596 * 10_000_000u64; // 0.1 SRCT/block
        assert!(
            floor_period_issuance <= allowance_at_tail,
            "the decided tail {floor_period_issuance} must fit under the rate anchor {allowance_at_tail}"
        );
    }
    #[test]
    fn rate_anchor_still_allows_the_ladder() {
        // Through exhaustion the allowance is u64::MAX, so every ladder reward
        // trivially passes. Heights 1..=H-1 are the ladder era; H itself is
        // already the first tail block.
        let main = NetworkParams::mainnet();
        let mut issued = 0u64;
        for h in 1..exhaustion_height(&main) {
            issued = check_mint_at_height(&main, issued, block_reward_sat(&main, h), h).unwrap();
        }
        assert_eq!(issued, max_issuance_sat(&main));
    }
    #[test]
    fn rate_anchor_refuses_a_schedule_that_over_issues_a_window() {
        // The anchor's whole job (Decision 18 §4.3): a *schedule* far more
        // generous than the approved one must be refused by name. A synthetic
        // 50-SRCT tail would issue 13.1M SRCT in one window against a 391,571
        // SRCT (1 %) allowance, so once the window has used its allowance the
        // next reward is refused — it does not matter that the integral of
        // that synthetic schedule would still "have room".
        let mut p = NetworkParams::mainnet();
        p.tail = crate::params::TailEmission::Constant {
            per_block_sat: 50 * SAT_PER_SRCT,
        };
        let window_start = exhaustion_height(&p);
        let h = window_start + p.halving_period - 1; // last block of the window
        let issued_start = max_issuance_sat(&p);
        let allowance = rate_anchor_allowance(&p, h);
        assert!(allowance > 0);
        // As if earlier blocks in this window had already issued the full
        // 1 %: one more 50-SRCT reward must be refused by the anchor, with the
        // anchor's own allowance named in the error.
        assert!(matches!(
            check_mint_at_height(&p, issued_start + allowance, 50 * SAT_PER_SRCT, h),
            Err(Error::SupplyRateExceeded { allowed_in_period, .. }) if allowed_in_period == allowance
        ));
        // And the same window *inside* its allowance is accepted.
        assert!(
            check_mint_at_height(&p, issued_start + allowance - SAT_PER_SRCT, SAT_PER_SRCT, h)
                .is_ok()
        );
    }
    #[test]
    fn the_whole_schedule_matches_the_simulated_issuance() {
        let p = NetworkParams::mainnet();
        // Mint every block's actual reward through one full period past
        // exhaustion and compare with the integral: the mint gate and the
        // bound must never disagree at any height.
        let horizon = 9 * p.halving_period;
        let mut issued = 0u64;
        for h in 1..=horizon {
            issued = check_mint_at_height(&p, issued, block_reward_sat(&p, h), h).unwrap();
        }
        assert_eq!(issued, cumulative_supply_sat(&p, horizon));
    }
    #[test]
    fn no_block_can_mint_beyond_cumulative_issuance() {
        // §6.1 #4, stated as the property the chain enforces: at every height
        // the scheduled reward lands exactly on the integral, a single extra
        // satoshi is refused, and a saturating sum can never be mistaken for
        // one that fits.
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            let mut issued = 0u64;
            for h in 1..=40_000u64 {
                let reward = block_reward_sat(&p, h);
                let after = check_mint_at_height(&p, issued, reward, h)
                    .unwrap_or_else(|e| panic!("{}: height {h} refused the schedule: {e}", p.name));
                assert_eq!(
                    after,
                    cumulative_issuance_sat(&p, h),
                    "{}: at height {h} the gate and the integral must agree",
                    p.name
                );
                assert!(
                    check_mint_at_height(&p, issued, reward + 1, h).is_err(),
                    "{}: one satoshi over the integral at {h} must be refused",
                    p.name
                );
                issued = after;
            }
            // Overflow is refused, not wrapped into a small number the bound
            // would happily accept.
            assert!(matches!(
                check_mint_at_height(&p, u64::MAX, 1, 1),
                Err(Error::SupplyRateExceeded { .. })
            ));
        }
    }
    #[test]
    fn derived_supply_bound_holds_at_every_height() {
        // §6.1 #5: the bound is the integral of the reward function at every
        // height, not just at period boundaries, and it never decreases.
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            let mut running = 0u64;
            let mut prev = 0u64;
            for h in 1..=100_000u64 {
                running = running.saturating_add(block_reward_sat(&p, h));
                if running == u64::MAX {
                    break;
                }
                let bound = cumulative_issuance_sat(&p, h);
                assert_eq!(running, bound, "{} at height {h}", p.name);
                assert!(bound >= prev, "{}: the bound fell at {h}", p.name);
                prev = bound;
            }
        }
    }
    #[test]
    fn mini_and_mainnet_tails_are_independent() {
        // §6.1 #11 / proposal F5: the mainnet floor on a 1-second profile
        // would mint a four-digit percentage a year against its cap, so the
        // two tails are set independently and neither schedule consults the
        // other's value. After SA-1 the numeric cap is completely gone and the
        // M-C guard becomes a rate-guard on the period, checked by the rate
        // anchor.
        let main = NetworkParams::mainnet();
        let mini = NetworkParams::mini();

        // Height 14,000 is past mini's exhaustion but far below mainnet's
        // (1,839,600): one profile pays its tail while the other is still on
        // its ladder, and the two schedules never consult each other's value.
        assert_eq!(block_reward_sat(&main, 14_000), 76 * SAT_PER_SRCT);
        assert_eq!(block_reward_sat(&mini, 14_000), 1);
        assert_eq!(exhaustion_height(&main), 1_839_600);
        assert_eq!(exhaustion_height(&mini), 14_000);
    }
    #[test]
    fn supply_vectors_agree_with_the_implementation() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vectors/supply_vectors.json");
        let raw = std::fs::read_to_string(&path).expect("supply_vectors.json must exist");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("must be valid JSON");
        assert_eq!(v["sat_per_srct"], 100_000_000u64, "SPEC.md section 0");

        for (name, p) in [
            ("mainnet", NetworkParams::mainnet()),
            ("mini", NetworkParams::mini()),
        ] {
            let sec = &v[name];

            // The reward ladder, checked through block_reward_sat so the
            // halving arithmetic in supply.rs is what is under test.
            let listed: Vec<u64> = sec["ladder_srct"]
                .as_array()
                .unwrap_or_else(|| panic!("{name}: ladder_srct missing"))
                .iter()
                .map(|x| x.as_u64().unwrap())
                .collect();
            assert_eq!(listed, vec![76, 38, 19, 9, 4, 2, 1, 0], "{name}: ladder");
            for (period, want) in listed.iter().enumerate() {
                let h = period as u64 * p.halving_period;
                assert_eq!(
                    block_reward_sat(&p, h) / SAT_PER_SRCT,
                    *want,
                    "{name}: period {period} reward"
                );
            }

            // The currently-published reachable figure must agree with the
            // implementation; the vector's ceiling fields are the rate anchor
            // (`rate_anchor_max_pct_per_period`, `largest_tail_window_pct...`),
            // never a stock cap (Decision 18, regenerated in SA-4).
            let reachable_sat = max_issuance_sat(&p);
            let listed_reachable = sec["max_reachable_srct"].as_u64().unwrap() * SAT_PER_SRCT;
            assert_eq!(
                reachable_sat, listed_reachable,
                "{name}: reachable issuance disagrees with the schedule sim"
            );

            // Self-consistency of the schedule sim, unqualified by any cap:
            // the file's own period-by-period issuance must match the
            // implementation's integral through the same points.
            let cum1 = sec["issued_after_first_period_srct"].as_u64().unwrap();
            assert_eq!(
                cum1 * SAT_PER_SRCT,
                cumulative_supply_sat(&p, p.halving_period),
                "{name}: issuance after one period"
            );
            let cum2 = sec["issued_after_two_periods_srct"].as_u64().unwrap();
            assert_eq!(
                cum2 * SAT_PER_SRCT,
                cumulative_supply_sat(&p, 2 * p.halving_period),
                "{name}: issuance after two periods"
            );
        }
    }
}
