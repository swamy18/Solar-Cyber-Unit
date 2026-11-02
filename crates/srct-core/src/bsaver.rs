//! B-Saver: minimal exogenous floor for SRCT (no dilution).
//!
//! Idea: keep 90%+ of the economics untouched. B-Saver is a *sub-ledger* of
//! the existing PSCB share, never a new mint and never a cut from burn or
//! miner tip:
//!
//! ```text
//! full_base fee -> burn (ceil 50%, unchanged) + PSCB (floor 50%, unchanged)
//! PSCB -> pscb_retained + bsaver_reserve (5%, cap 10%)
//! ```
//!
//! Consensus: `Chain` credits `bsaver_cut_default(split.pscb)` per block into
//! `bsaver_reserve` and keeps `burned + pscb + bsaver == full_base`. Old data
//! replays under the new rule on restart (pre-launch governance activation).
//!
//! The other two legs need no share at all:
//! - burn-to-compute redeemability: burning SRCT buys a `ComputeClaim`
//!   (exogenous $/FLOP anchor, supply shrinks on use).
//! - large-loan haircut: big positions need extra SRCT cover, small ones unchanged.

/// B-Saver cut in basis points over the PSCB leg only. 500 = 5%.
pub const BSAVER_BPS: u32 = 500;
/// Hard cap: B-Saver never takes more than 10% of PSCB.
pub const BSAVER_MAX_BPS: u32 = 1_000;
/// Basis-point denominator.
pub const BPS_DENOM: u32 = 10_000;

/// Large-loan gate: at or above this principal the extra cover applies.
/// 10 SRCT keeps everyday agent jobs untouched.
pub const LARGE_LOAN_THRESHOLD_SAT: u64 = 1_000_000_000;
/// Extra cover for large loans, in bps of principal (120% = 12_000).
pub const LARGE_LOAN_COVER_BPS: u32 = 12_000;

/// Integer FLOPs granted per burned sat (protocol price table placeholder).
/// Kept integer-only: no floats anywhere near consensus.
pub const FLOPS_PER_SAT: u64 = 1_000;

/// B-Saver's share carved from an already-computed PSCB amount.
///
/// `pscb * bps / 10_000`, floored. `bps` above [`BSAVER_MAX_BPS`] is refused
/// (returns `None`) rather than clamped: a silent clamp would hide a
/// governance overreach as a normal number.
pub fn bsaver_cut(pscb_sat: u64, bps: u32) -> Option<u64> {
    if bps > BSAVER_MAX_BPS {
        return None;
    }
    Some((pscb_sat as u128 * bps as u128 / BPS_DENOM as u128) as u64)
}

/// Default cut (5%) over a PSCB amount. Infallible: default bps <= max.
pub fn bsaver_cut_default(pscb_sat: u64) -> u64 {
    bsaver_cut(pscb_sat, BSAVER_BPS).expect("default bps is within cap")
}

/// Split a PSCB leg into `(retained, bsaver)`. Invariant: sum == pscb.
pub fn split_pscb(pscb_sat: u64) -> (u64, u64) {
    let b = bsaver_cut_default(pscb_sat);
    (pscb_sat.saturating_sub(b), b)
}

/// Burn-to-compute quote: FLOPs for burning `burn_sat`. Checked, never wraps.
pub fn redeem_quote(burn_sat: u64) -> Option<u64> {
    (burn_sat as u128)
        .checked_mul(FLOPS_PER_SAT as u128)
        .and_then(|v| u64::try_from(v).ok())
}

/// Whether a loan principal needs the large-loan cover.
pub fn requires_extra_cover(principal_sat: u64) -> bool {
    principal_sat >= LARGE_LOAN_THRESHOLD_SAT
}

/// Required SRCT collateral for a principal: 100% below threshold,
/// 120% at/above. Pure integer math, rounds up.
pub fn required_collateral_sat(principal_sat: u64) -> Option<u64> {
    let bps = if requires_extra_cover(principal_sat) {
        LARGE_LOAN_COVER_BPS
    } else {
        BPS_DENOM
    };
    let v = principal_sat as u128 * bps as u128;
    let up = v.saturating_add(BPS_DENOM as u128 - 1) / BPS_DENOM as u128;
    u64::try_from(up).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cut_is_five_percent_of_pscb_only() {
        assert_eq!(bsaver_cut_default(1_000), 50);
        assert_eq!(bsaver_cut_default(1), 0); // floor, never rounds up
        let (retained, b) = split_pscb(1_000);
        assert_eq!(retained + b, 1_000);
        assert_eq!(b, 50);
    }

    #[test]
    fn cut_never_exceeds_ten_percent() {
        assert!(bsaver_cut(1_000_000, 1_001).is_none());
        assert_eq!(bsaver_cut(1_000_000, 1_000), Some(100_000));
    }

    #[test]
    fn burn_and_tip_untouched_shape() {
        // 50/50 base split stays: B-Saver only subdivides the PSCB half.
        let full_base = 9u64;
        let pscb = full_base / 2; // 4, matches fees::split_fees
        let burned = full_base - pscb; // 5, odd sat to burn
        let (retained, b) = split_pscb(pscb);
        assert_eq!(burned, 5);
        assert_eq!(retained + b, pscb);
    }

    #[test]
    fn redeem_quote_is_integer_and_checked() {
        assert_eq!(redeem_quote(1), Some(1_000));
        assert_eq!(redeem_quote(0), Some(0));
        assert!(redeem_quote(u64::MAX).is_none());
    }

    #[test]
    fn small_loans_unchanged_large_loans_need_120() {
        assert!(!requires_extra_cover(100));
        assert!(!requires_extra_cover(LARGE_LOAN_THRESHOLD_SAT - 1));
        assert!(requires_extra_cover(LARGE_LOAN_THRESHOLD_SAT));
        assert_eq!(required_collateral_sat(1_000).unwrap(), 1_000);
        assert_eq!(
            required_collateral_sat(LARGE_LOAN_THRESHOLD_SAT).unwrap(),
            1_200_000_000
        );
    }
}
