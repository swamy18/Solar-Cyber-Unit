//! LWMA difficulty retarget and tamper-resistant timestamp rules.
//! SPEC.md §6.
//!
//! Design doc Section 28.2/28.10: use a *proven* algorithm (Zawy-style linearly
//! weighted moving average), a per-block change limit, and a short future
//! timestamp allowance. The 2-hour allowance Bitcoin uses was measured in
//! `verification/sim/difficulty_attack_sim.py` to let a 40% attacker drag difficulty down;
//! one block time does not.

use crate::error::{Error, Result};
use crate::params::NetworkParams;

/// Number of previous timestamps the median-time rule looks at.
pub const MEDIAN_LOOKBACK: usize = 11;

/// Clamp applied to each individual solve time (fraction of target spacing).
pub const MIN_SOLVE_TIME_NUM: u64 = 1; // /4
pub const MIN_SOLVE_TIME_DEN: u64 = 4;
pub const MAX_SOLVE_TIME_NUM: u64 = 5; // *1

pub fn clamp_solve_time(t: i64, target_ms: u64) -> u64 {
    let lo = (target_ms / MIN_SOLVE_TIME_DEN).max(1);
    let hi = target_ms.saturating_mul(MAX_SOLVE_TIME_NUM).max(lo);
    let t = t.max(0) as u64;
    t.clamp(lo, hi)
}

fn weight_sum(window: u32) -> u128 {
    let w = window as u128;
    w * (w + 1) * (2 * w + 1) / 6
}

/// Difficulty for the block *after* the supplied history.
///
/// `history_newest_first[i]` is the timestamp of the block `i` blocks back from
/// the tip; index 0 is the tip.
///
/// While the chain is shorter than `difficulty_window + 1`, the *available*
/// window is used rather than falling back to the genesis difficulty. Pinning
/// difficulty for the first hour of a new chain would hand that hour to
/// whoever shows up first. The weighted sum uses the same weight formula over
/// however many solve times exist, which is standard Zawy ramp-up behaviour.
pub fn next_difficulty(
    params: &NetworkParams,
    prev_difficulty: u128,
    history_newest_first: &[u64],
) -> u128 {
    // Clamp the genesis shortcuts into the profile bounds: `validate()`
    // pins sane profiles, but an out-of-range genesis must not persist
    // forever on a chain that short-circuits here.
    let max_window = params.difficulty_window.max(1) as usize;
    if history_newest_first.len() < 2 {
        return params.genesis_difficulty.clamp(
            params.min_difficulty,
            params.max_difficulty.max(params.min_difficulty),
        );
    }
    let window = (history_newest_first.len() - 1).min(max_window);
    let t = params.target_block_time_ms as u128;
    let w_sum = weight_sum(window as u32);

    let mut s: u128 = 0;
    for i in 0..window {
        let raw = history_newest_first[i] as i128 - history_newest_first[i + 1] as i128;
        let clamped = clamp_solve_time(raw as i64, params.target_block_time_ms);
        // Zawy LWMA weights the *newest* solve time most. `i` counts back
        // from the tip, so the block `i` blocks back carries weight
        // (window - i)^2: the tip's own solve time weighs window^2 and the
        // oldest in the window weighs 1. Weighting the oldest most instead
        // would make the retarget sluggish and is not the proven algorithm
        // the design doc (28.2/28.10) asks for.
        let depth = (window - i) as u128;
        let weight = depth * depth;
        s += weight * clamped as u128;
    }

    // Retarget multiplicatively from the previous difficulty:
    //
    //     d_new = d_prev * T / avg_solve
    //
    // This restoring force is the whole point. Dividing the weighted
    // average solve time by T instead (`avg_solve / T`) yields a
    // scale-invariant number that is a fixed point at *every* difficulty,
    // so a chain whose hashrate halves would never correct itself.
    //
    // `avg_solve` is at least T/4 (every solve time is clamped, and the
    // clamp floor is at least 1 ms), so the division below is safe and
    // the result is at most 4 * d_prev, well inside u128.
    // `w_sum` is nonzero: `window >= 1` (guaranteed above), and
    // `weight_sum` is a sum of positive squares.
    let avg_solve = s / w_sum.max(1);
    let raw = if avg_solve == 0 {
        prev_difficulty.clamp(
            params.min_difficulty,
            params.max_difficulty.max(params.min_difficulty),
        )
    } else {
        prev_difficulty.saturating_mul(t).saturating_div(avg_solve)
    };
    let mut d = if raw == 0 { 1 } else { raw };

    // Per-block change limit: +/- change_limit_bps. The upper bound always
    // admits at least +1, otherwise a chain starting at difficulty 1 could
    // never bootstrap upwards.
    let bps = params.change_limit_bps.min(10_000) as u128;
    let lo = prev_difficulty
        .saturating_mul(10_000 - bps)
        .saturating_div(10_000)
        .max(1);
    let hi = prev_difficulty
        .saturating_mul(10_000 + bps)
        .saturating_div(10_000)
        .max(prev_difficulty.saturating_add(1))
        .min(params.max_difficulty);
    d = d.clamp(lo, hi.max(lo));

    d.clamp(params.min_difficulty, params.max_difficulty)
}

/// Median of the previous `MEDIAN_LOOKBACK` timestamps, oldest-first subset.
pub fn median_previous_timestamp(history_newest_first: &[u64]) -> Option<u64> {
    let n = MEDIAN_LOOKBACK.min(history_newest_first.len());
    if n == 0 {
        return None;
    }
    let mut v: Vec<u64> = history_newest_first[..n].to_vec();
    v.sort_unstable();
    Some(v[n / 2])
}

/// Consensus timestamp rule (SPEC.md §6.1): a block may not be older than the
/// median of the previous `MEDIAN_LOOKBACK` timestamps.
///
/// There is deliberately **no** consensus upper bound. An upper bound needs a
/// reference that advances with wall time, and the only such thing is the local
/// clock — which would make validity depend on machine skew. Instead the upper
/// bound is a node policy, [`validate_local_clock`], applied when a block enters
/// the chain. See `docs/status.md`: a node that skips that check can be talked
/// into a higher-difficulty branch, which is the same tradeoff Bitcoin makes with
/// a two-hour allowance rather than one block time.
pub fn validate_timestamp(
    _params: &NetworkParams,
    timestamp_ms: u64,
    history_newest_first: &[u64],
) -> Result<()> {
    let Some(median) = median_previous_timestamp(history_newest_first) else {
        return Ok(()); // the block right after genesis
    };
    if timestamp_ms < median {
        return Err(Error::TimestampTooOld {
            median,
            got: timestamp_ms,
        });
    }
    Ok(())
}

/// Node policy: reject timestamps ahead of the local clock.
///
/// This is the rule `verification/sim/difficulty_attack_sim.py` measures. One block time is
/// tight enough that a 40% attacker cannot manufacture median progress; the same
/// simulation shows a two-hour allowance lets it drag difficulty down.
pub fn validate_local_clock(timestamp_ms: u64, now_ms: u64, params: &NetworkParams) -> Result<()> {
    let limit = now_ms.saturating_add(params.future_limit_ms());
    if timestamp_ms > limit {
        return Err(Error::TimestampTooFuture {
            limit,
            got: timestamp_ms,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: usize = 60;

    fn history(times_newest_first: &[u64]) -> Vec<u64> {
        times_newest_first.to_vec()
    }

    /// History whose block `i` solve time (newest first) is `solve[i]`.
    fn history_with(solve: &[u64]) -> Vec<u64> {
        let mut h = vec![100_000_000_000u64; solve.len() + 1];
        for i in 0..solve.len() {
            h[i + 1] = h[i].saturating_sub(solve[i]);
        }
        h
    }

    #[test]
    fn perfect_spacing_is_a_fixed_point_at_every_difficulty() {
        // The defining property: if blocks arrive exactly T apart, difficulty
        // must not drift. Under the multiplicative retarget this holds at any
        // starting value, not just 1.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let h: Vec<u64> = (0..=WINDOW)
            .map(|i| 100_000_000_000 - (i as u64) * t)
            .collect();
        for start in [1u128, 2, 17, 1_000, 999_999] {
            assert_eq!(
                next_difficulty(&p, start, &history(&h)),
                start,
                "difficulty {start} drifted under perfect spacing"
            );
        }
    }

    #[test]
    fn halved_hashrate_lowers_difficulty_to_restore_target_spacing() {
        // Blocks taking 2T means half the hash rate. The chain must lower
        // difficulty by half, not raise it. This is the restoring force: the
        // old `avg_solve / T` formula returned 2 here and ran away to 4T.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let h: Vec<u64> = (0..=WINDOW)
            .map(|i| 100_000_000_000 - (i as u64) * 2 * t)
            .collect();
        // Exact value is 0.5, floored to 0, so the per-block change limit
        // from prev=1000 gives floor(1000 * 0.9) = 900.
        assert_eq!(next_difficulty(&p, 1_000, &history(&h)), 900);
        // From 100 the 10% step is the binding constraint.
        assert_eq!(next_difficulty(&p, 100, &history(&h)), 90);
    }

    #[test]
    fn doubled_hashrate_raises_difficulty_to_restore_target_spacing() {
        // Blocks taking T/2 means double the hash rate; difficulty must rise.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let h: Vec<u64> = (0..=WINDOW)
            .map(|i| 100_000_000_000 - (i as u64) * t / 2)
            .collect();
        assert_eq!(next_difficulty(&p, 1_000, &history(&h)), 1_100);
        assert_eq!(next_difficulty(&p, 1_000_000, &history(&h)), 1_100_000);
    }

    #[test]
    fn solve_time_clamp_bounds_a_single_step_to_a_factor_of_four() {
        // Solve times clamp to [t/4, 5t], so one retarget can multiply
        // difficulty by at most 4 (down) or 5 (up) before the change limit.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        // Absurdly fast blocks, but the clamp floors them at t/4 => 4x up.
        let fast: Vec<u64> = (0..=WINDOW).map(|i| 100_000_000_000 - i as u64).collect();
        assert_eq!(next_difficulty(&p, 1_000, &history(&fast)), 1_100);
        // Absurdly slow blocks, clamped at 5t => 5x down, but the 10% step
        // from 1000 binds first and gives 900.
        let slow: Vec<u64> = (0..=WINDOW)
            .map(|i| 100_000_000_000 - (i as u64) * t * 50)
            .collect();
        assert_eq!(next_difficulty(&p, 1_000, &history(&slow)), 900);
    }

    #[test]
    fn change_limit_admits_at_least_plus_one() {
        // Without the +1 floor on the upper bound, a chain starting at
        // difficulty 1 could never bootstrap upwards: 1 * 1.1 floors to 1.
        let p = NetworkParams::mainnet();
        let fast: Vec<u64> = (0..=WINDOW).map(|i| 100_000_000_000 - i as u64).collect();
        assert_eq!(next_difficulty(&p, 1, &history(&fast)), 2);
        assert_eq!(next_difficulty(&p, 2, &history(&fast)), 3);
        assert_eq!(next_difficulty(&p, 3, &history(&fast)), 4);
    }

    #[test]
    fn one_pathological_block_cannot_move_difficulty() {
        // A single timestamp far in the past is clamped, not trusted, so it
        // must not drag difficulty by more than one change-limit step.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let mut h: Vec<u64> = (0..=WINDOW)
            .map(|i| 100_000_000_000 - (i as u64) * t)
            .collect();
        h[3] = 100_000_000_000 - 3 * t - 100 * t;
        // Perfect spacing everywhere except two clamped solve times that
        // cancel, so the weighted mean is still ~T and difficulty holds.
        let d = next_difficulty(&p, 1_000, &history(&h));
        assert!((900..=1_100).contains(&d), "difficulty moved too far: {d}");
    }

    #[test]
    fn slow_blocks_that_the_clock_policy_would_reject_do_not_move_difficulty() {
        // An attacker can only claim to be ahead by `future_limit_ms`, so the
        // timestamps reaching the retarget can never jump a whole window
        // forward. This is the property the attack simulation measures.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        assert!(p.future_limit_ms() < t * 2);
        let h: Vec<u64> = (0..=WINDOW)
            .map(|i| 100_000_000_000 - (i as u64) * t)
            .collect();
        assert_eq!(next_difficulty(&p, 1_000, &h), 1_000);
    }

    #[test]
    fn newest_solve_times_weigh_more_than_old_ones() {
        // Zawy LWMA weights the newest block most. Two histories holding the
        // same solve times in opposite orders must retarget differently.
        // Uniform solve-time tests cannot catch a weighting bug, so mix them.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let w = p.difficulty_window as usize;

        // Half the window fast (t/4), half slow (5t).
        let mut fast_then_slow = vec![t / 4; w];
        fast_then_slow[w / 2..].copy_from_slice(&vec![5 * t; w - w / 2]);
        let mut slow_then_fast = vec![5 * t; w];
        slow_then_fast[w / 2..].copy_from_slice(&vec![t / 4; w - w / 2]);

        // `a` puts the fast blocks at the tip, so its weighted mean solve time
        // is the lower of the two. Blocks arriving early mean the network is
        // too easy on itself, so difficulty must go UP: `a > b`. Weighting the
        // oldest solve times most instead would flip this to `a < b`.
        let a = next_difficulty(&p, 1_000_000, &history_with(&fast_then_slow));
        let b = next_difficulty(&p, 1_000_000, &history_with(&slow_then_fast));
        assert!(a > b, "newest weights must dominate: a={a} b={b}");

        // Both sit inside one change-limit step of 1,000,000: the change
        // limit dominates the raw value at this scale.
        assert!((900_000..=1_100_000).contains(&a), "a={a}");
        assert!((900_000..=1_100_000).contains(&b), "b={b}");
    }

    #[test]
    fn difficulty_adapts_from_the_first_block() {
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;

        // Only the genesis timestamp is known: nothing to measure yet.
        assert_eq!(
            next_difficulty(&p, 1, &history(&[100_000_000_000])),
            p.genesis_difficulty
        );

        // Perfect spacing holds, and a partial window behaves identically:
        // no fallback to a fixed value, no "hold genesis for an hour" hole.
        let h2: Vec<u64> = (0..=WINDOW)
            .map(|i| 100_000_000_000 - (i as u64) * t)
            .collect();
        assert_eq!(next_difficulty(&p, 1, &history(&h2)), 1);
        let short: Vec<u64> = (0..5).map(|i| 100_000_000_000 - (i as u64) * t).collect();
        assert_eq!(next_difficulty(&p, 1, &history(&short)), 1);
    }

    #[test]
    fn a_chain_that_lost_half_its_hashrate_converges_back_to_target() {
        // End-to-end restoring force: 400 blocks at 2T spacing must walk
        // difficulty back down toward the target rather than running away.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let mut d = 1_000_000u128;
        let mut ts = 100_000_000_000u64;
        let mut hist: Vec<u64> = vec![ts];
        for _ in 0..400 {
            // Timestamps must increase: history is newest-first, so each new
            // block goes to the front and is 2T *after* its parent.
            ts += 2 * t;
            hist.insert(0, ts);
            hist.truncate(WINDOW + 2);
            d = next_difficulty(&p, d, &hist);
        }
        // 10% per block downward from 1e6 needs ~66 blocks to reach 1e3 and
        // ~450 to reach ~1; assert it fell by orders of magnitude.
        assert!(
            d <= 1_000_000 / 100,
            "difficulty failed to recover, still at {d}"
        );
    }

    #[test]
    fn solve_time_is_clamped_both_ways() {
        let t = 600_000u64;
        assert_eq!(clamp_solve_time(-5, t), t / 4);
        assert_eq!(clamp_solve_time(0, t), t / 4);
        assert_eq!(clamp_solve_time(t as i64, t), t);
        assert_eq!(clamp_solve_time(100 * t as i64, t), 5 * t);
    }

    #[test]
    fn median_timestamp_rule_blocks_time_warps() {
        let p = NetworkParams::mainnet();
        let h = vec![100u64, 200, 300, 400, 500];
        assert_eq!(median_previous_timestamp(&h), Some(300));
        assert_eq!(median_previous_timestamp(&[]), None);

        assert!(matches!(
            validate_timestamp(&p, 299, &h),
            Err(Error::TimestampTooOld { .. })
        ));
        validate_timestamp(&p, 300, &h).unwrap();

        // No history (the block right after genesis) has no constraint.
        validate_timestamp(&p, u64::MAX, &[]).unwrap();
    }

    #[test]
    fn a_chain_at_exactly_target_spacing_is_never_rejected() {
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            let t = p.target_block_time_ms;
            let mut history: Vec<u64> = Vec::new();
            let mut ts = crate::block::GENESIS_TIMESTAMP_MS;
            for _ in 0..500 {
                ts += t;
                validate_timestamp(&p, ts, &history).unwrap();
                history.insert(0, ts);
                history.truncate(12);
            }
        }
    }

    #[test]
    fn slow_blocks_are_still_minable() {
        // Blocks arriving five target-times apart must be accepted. An upper
        // bound anchored on the median would have rejected these during the
        // ramp-up window, which is why there is no consensus ceiling.
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let mut history: Vec<u64> = vec![crate::block::GENESIS_TIMESTAMP_MS];
        let mut ts = history[0];
        for _ in 0..200 {
            ts += 5 * t;
            validate_timestamp(&p, ts, &history).unwrap();
            history.insert(0, ts);
            history.truncate(12);
        }
    }

    #[test]
    fn local_clock_policy_bounds_a_future_timestamp_attacker() {
        let p = NetworkParams::mainnet();
        assert_eq!(p.future_limit_ms(), 600_000, "one block time");
        let now = 1_700_000_000_000u64;
        validate_local_clock(now, now, &p).unwrap();
        validate_local_clock(now + 599_999, now, &p).unwrap();
        assert!(matches!(
            validate_local_clock(now + 600_001, now, &p),
            Err(Error::TimestampTooFuture { .. })
        ));

        // The comparison the design doc's Section 28.9 turns on: one block time
        // versus Bitcoin's two hours.
        let bitcoin_allowance_ms = 2 * 60 * 60 * 1000u64;
        assert!(
            p.future_limit_ms() * 12 <= bitcoin_allowance_ms,
            "our allowance must be far tighter than two hours"
        );
    }

    /// Named cases pinned in `verification/tests/vectors/difficulty_vectors.json`.
    ///
    /// These exist because the retarget is easy to "fix" in a way that still
    /// passes a hand-written test: the multiplicative form and the
    /// direction of the Zawy weights both have to be reproduced exactly by
    /// any other implementation. A second implementation that disagrees
    /// here is a consensus split, not a rounding difference.
    fn vector_cases() -> Vec<(&'static str, u128, Vec<u64>, u128)> {
        let p = NetworkParams::mainnet();
        let t = p.target_block_time_ms;
        let w = p.difficulty_window as usize;
        let mut cases: Vec<(&'static str, u128, Vec<u64>, u128)> = Vec::new();

        // Perfect spacing must not move difficulty at all.
        let perfect: Vec<u64> = vec![t; w];
        for start in [1u128, 7, 1_000] {
            cases.push((
                "perfect_spacing_fixed_point",
                start,
                history_with(&perfect),
                next_difficulty(&p, start, &history_with(&perfect)),
            ));
        }

        // Halved hashrate -> 2T spacing -> difficulty must fall.
        let half: Vec<u64> = vec![2 * t; w];
        cases.push((
            "halved_hashrate_lowers",
            1_000,
            history_with(&half),
            next_difficulty(&p, 1_000, &history_with(&half)),
        ));

        // Doubled hashrate -> T/2 spacing -> difficulty must rise.
        let double: Vec<u64> = vec![t / 2; w];
        cases.push((
            "doubled_hashrate_raises",
            1_000,
            history_with(&double),
            next_difficulty(&p, 1_000, &history_with(&double)),
        ));

        // Mixed spacing, newest-weighted: a fast tip outranks a fast tail.
        let mut fast_tip = vec![5 * t; w];
        fast_tip[..w / 2].fill(t / 4);
        cases.push((
            "newest_solve_times_weigh_most",
            1_000_000,
            history_with(&fast_tip),
            next_difficulty(&p, 1_000_000, &history_with(&fast_tip)),
        ));

        cases
    }

    #[test]
    fn difficulty_vectors_are_stable() {
        // Regenerate with: UPDATE_DIFFICULTY_VECTORS=1 cargo test -p srct-core
        let cases = vector_cases();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../verification/tests/vectors/difficulty_vectors.json");

        if std::env::var("UPDATE_DIFFICULTY_VECTORS").is_ok() {
            let mut json = String::from("{\n");
            json.push_str("  \"_comment\": \"Generated from srct-core by difficulty_vectors_are_stable. Do not hand-edit.\",\n");
            json.push_str("  \"target_block_time_ms\": 600000,\n");
            json.push_str("  \"difficulty_window\": 60,\n");
            json.push_str("  \"change_limit_bps\": 1000,\n");
            json.push_str("  \"cases\": [\n");
            for (i, (name, prev, hist, got)) in cases.iter().enumerate() {
                json.push_str("    {\n");
                json.push_str(&format!("      \"name\": \"{name}\",\n"));
                json.push_str(&format!("      \"prev_difficulty\": {prev},\n"));
                let ts: Vec<String> = hist.iter().map(|v| format!("\"{v}\"")).collect();
                json.push_str(&format!(
                    "      \"history_newest_first\": [{}],\n",
                    ts.join(", ")
                ));
                json.push_str(&format!("      \"expected_difficulty\": {got}\n"));
                json.push_str(if i + 1 == cases.len() {
                    "    }\n"
                } else {
                    "    },\n"
                });
            }
            json.push_str("  ]\n}\n");
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, json).unwrap();
            eprintln!("wrote {}", path.display());
            return;
        }

        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["target_block_time_ms"], 600_000u64);
        assert_eq!(v["difficulty_window"], 60u64);

        let listed = v["cases"].as_array().expect("cases must be an array");
        assert_eq!(
            listed.len(),
            cases.len(),
            "vector file is stale: regenerate with UPDATE_DIFFICULTY_VECTORS=1"
        );

        let p = NetworkParams::mainnet();
        for (entry, (name, prev, hist, expected)) in listed.iter().zip(cases.iter()) {
            assert_eq!(entry["name"], *name, "vector order changed");
            assert_eq!(
                entry["prev_difficulty"].as_u64().unwrap(),
                *prev as u64,
                "vector {name}: prev_difficulty changed"
            );
            assert_eq!(
                entry["expected_difficulty"].as_u64().unwrap(),
                *expected as u64,
                "vector {name}: retarget output changed -- this is a consensus change"
            );
            // And the vector must still describe the behaviour it claims.
            let from_vector = next_difficulty(&p, *prev, hist);
            assert_eq!(
                from_vector, *expected,
                "vector {name}: recomputing from the stored history disagrees"
            );
        }
    }
}
