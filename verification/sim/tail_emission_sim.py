"""Monetary policy simulation + self-test (DESIGN ANALYSIS ONLY).

NOT consensus code. Nothing here is imported by any Rust crate, and nothing
here changes a reward, a fee, a cap or an invariant. It exists so every number
quoted in `docs/monetary-redesign.md` is reproducible with one command.

    python verification/sim/tail_emission_sim.py            # full comparative analysis
    python verification/sim/tail_emission_sim.py --selftest # assertions + vector cross-check

`--selftest` exits non-zero if any hand-computed value, committed supply vector,
monotonicity property, continuity property or overflow bound does not hold.

Modeled assumptions are labelled in the output. Price figures are *sensitivity
parameters*, never forecasts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SAT_PER_SRCT = 100_000_000
SECONDS_PER_YEAR = 86_400 * 365.25

# --- existing profiles (verified against crates/srct-core/src/params.rs) -----
MAINNET = {
    "name": "mainnet",
    "halving_period": 262_800,
    "start_reward_srct": 76,
    "ladder_srct": 39_157_124,
    "block_time_s": 600,
    "base_fee_initial_sat": 1_000,
    "base_fee_min_sat": 100,
    "gas_cap": 2_000_000,
    "gas_tx_base": 16_000,
}
MINI = {**MAINNET, "name": "mini", "halving_period": 2_000, "ladder_srct": 297_924,
        "block_time_s": 1, "base_fee_initial_sat": 100, "base_fee_min_sat": 10}
TESTNET = {**MINI, "name": "testnet"}
PROFILES = [MAINNET, MINI, TESTNET]

# --- candidates (the VALUE is a protocol decision, not chosen by this file) --
TAIL_FLOOR_CANDIDATES = [1.0, 0.5, 0.25, 0.1, 0.05]
APPROVED_FLOOR_SRCT = 0.1             # approved 2026-10-09 (M-B), implemented
APPROVED_TESTNET_TAIL_SAT = 1        # approved 2026-10-09 (M-C), implemented


def ladder_rung_srct(p: dict, period: int) -> int:
    """Whole-SRCT halving, exactly as `supply::period_reward_sat`."""
    return 0 if period >= 64 else p["start_reward_srct"] >> period


def exhaustion_period(p: dict) -> int:
    k = 0
    while ladder_rung_srct(p, k) > 0:
        k += 1
    return k          # first period whose rung is zero (7 for start 76)


def exhaustion_height(p: dict) -> int:
    return exhaustion_period(p) * p["halving_period"]


def reward_srct(p: dict, height: int, policy: str, floor_srct: float = 0.0) -> float:
    """Block subsidy in SRCT under a named policy.

    A         : ladder only, then zero (the pre-M-A schedule, superseded by the tail)
    FLAT      : max(ladder, floor)  -> flat tail from exhaustion
    DECAY     : ladder, then halve in satoshis each period down to `floor`
    SAT_TAIL  : ladder, then a constant 1-sat tail (fast profiles only)
    """
    period = height // p["halving_period"]
    rung = float(ladder_rung_srct(p, period))
    if policy == "A":
        return rung
    if policy == "FLAT":
        return max(rung, floor_srct)
    if policy == "DECAY":
        if period <= exhaustion_period(p) - 1:
            return rung
        k = period - (exhaustion_period(p) - 1)      # 1 at the first tail period
        return max(floor_srct, 1.0 / (2 ** k))
    if policy == "SAT_TAIL":
        return rung if rung > 0 else 1.0 / SAT_PER_SRCT
    raise ValueError(policy)


def cumulative_srct(p: dict, blocks: int, policy: str, floor_srct: float = 0.0) -> float:
    """Gross issuance after `blocks` blocks mined on top of genesis (height>=1)."""
    if blocks <= 0:
        return 0.0
    total = 0.0
    # Exact block-reward semantics: block `h` pays `reward(h)`, and `halvings()`
    # is constant over `p*H ..= (p+1)*H - 1`, so period p is that closed range —
    # block `(p+1)*H` already pays the next rung. Walking the range by height
    # (not by period index offset from 1) is what keeps the boundary block from
    # being skipped or counted twice: an earlier revision did both, and the two
    # errors cancelled only at the rounding this file prints.
    h = 1
    while h <= blocks:
        period = h // p["halving_period"]
        end = min(blocks, (period + 1) * p["halving_period"] - 1)
        r = reward_srct(p, h, policy, floor_srct)
        total += r * (end - h + 1)
        h = end + 1
    return total


def blocks_per_year(p: dict) -> float:
    return SECONDS_PER_YEAR / p["block_time_s"]


def years_at(p: dict, blocks: float) -> float:
    return blocks * p["block_time_s"] / SECONDS_PER_YEAR


def supply_removed_srct_per_block(p: dict, activity: float, base_fee_sat: int) -> float:
    """Live supply removed per block = the ENTIRE base fee, not half of it.

    `split_fees` removes `burned` (50%) and `pscb` (50%) from the UTXO set; the
    coinbase may claim only `reward + tip` (chain.rs:479), so value leaves live
    supply by `full_base`. `pscb_reserve` is a counter on `Chain`, never an
    output, and no path converts it back into UTXOs (verified 2026-10-09).

    Earlier revisions of this file used `0.5 * base_fee * gas`, which
    understated the removal by 2x. Corrected.
    """
    return base_fee_sat * (p["gas_cap"] * activity) / SAT_PER_SRCT


def burned_half_srct_per_block(p: dict, activity: float, base_fee_sat: int) -> float:
    """The M1 `burned` half alone (the other half accrues to PSCB)."""
    return 0.5 * supply_removed_srct_per_block(p, activity, base_fee_sat)


def fee_revenue_srct_per_block(p: dict, activity: float, base_fee_sat: int) -> float:
    return base_fee_sat * (p["gas_cap"] * activity) / SAT_PER_SRCT


ACTIVITY = {"idle": 0.0, "low": 0.05, "normal": 0.25, "high": 1.0}


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
def selftest() -> int:
    fails: list[str] = []

    def check(name: str, got, want, tol=1e-9):
        ok = (abs(got - want) <= tol) if isinstance(want, (int, float)) else (got == want)
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}: got {got!r} want {want!r}")
        if not ok:
            fails.append(name)

    print("== hand-computed values ==")
    # Exact block-reward semantics (see `cumulative_srct`): the ladder issues
    # `149H - 76` SRCT, the first rung paid by `H - 1` blocks because genesis
    # mints nothing. The geometric shortcut `149H` over-states it by 76 SRCT.
    check("mainnet first block reward (SRCT)", reward_srct(MAINNET, 1, "A"), 76.0)
    check("mainnet after 1 period", cumulative_srct(MAINNET, 262_800, "A"), 19_972_762.0)
    check("mainnet +1 block into period 2",
          cumulative_srct(MAINNET, 262_801, "A"), 19_972_800.0)
    check("mainnet after 2 periods", cumulative_srct(MAINNET, 525_600, "A"), 29_959_143.0)
    check("mainnet exhaustion height", exhaustion_height(MAINNET), 1_839_600)
    check("mainnet exhausted issuance", cumulative_srct(MAINNET, 1_839_600, "A"), 39_157_124.0)
    check("ladder sum x period less the genesis slot (149H - 76)",
          sum(ladder_rung_srct(MAINNET, k) for k in range(7)) * 262_800 - 76, 39_157_124.0)
    check("mini exhausted issuance", cumulative_srct(MINI, 14_000, "A"), 297_924.0)
    check("mini exhaustion height", exhaustion_height(MINI), 14_000)

    print("== continuity ==")
    for floor in TAIL_FLOOR_CANDIDATES:
        h = exhaustion_height(MAINNET)
        before = reward_srct(MAINNET, h - 1, "FLAT", floor)
        after = reward_srct(MAINNET, h, "FLAT", floor)
        step = after - before
        if floor == 1.0 and abs(step) > 1e-9:
            fails.append("flat-1.0 must be continuous")
            print(f"  FAIL  flat {floor}: step {step:+.2f} (expected 0)")
        else:
            print(f"  ok    flat {floor:<5}: {before:>5.2f} -> {after:>5.2f} (step {step:+.2f})")
    # E is NOT literally continuous: 0.125 -> 0.10 is a -20% clamp. The claim the
    # design actually makes (doc section 2.5) is "no step greater than a
    # halving", so assert that instead. Step period by period: an earlier
    # revision of this check stepped `h + k*period`, which skips the first tail
    # period and reported a bogus -75% step.
    period_blocks = MAINNET["halving_period"]
    first_tail = exhaustion_height(MAINNET) // period_blocks      # 7
    prev = reward_srct(MAINNET, (first_tail - 1) * period_blocks, "DECAY",
                      APPROVED_FLOOR_SRCT)
    worst_drop, clamp_drop = 0.0, None
    print("  tail steps (period by period):")
    for per in range(first_tail, first_tail + 6):
        now = reward_srct(MAINNET, per * period_blocks, "DECAY",
                         APPROVED_FLOOR_SRCT)
        drop = (prev - now) / prev if prev else 0.0
        if now > prev + 1e-9:
            fails.append("decay tail must be non-increasing")
        print(f"    ok    period {per:2d}  {prev:>6.4f} -> {now:<6.4f} SRCT"
              f"  ({-100 * drop:+.1f}%)")
        worst_drop = max(worst_drop, drop)
        if clamp_drop is None and now == APPROVED_FLOOR_SRCT and prev > now:
            clamp_drop = drop
        prev = now
    check("no decay tail step exceeds a halving (50%)",
          round(worst_drop, 9) <= 0.5, True)
    check("largest tail step is exactly a halving (50%)", round(worst_drop, 9), 0.5)
    check("the clamp into the floor is -20%",
          round(clamp_drop, 9), 0.2)
    check("decay tail reaches and holds the floor",
          reward_srct(MAINNET, 50 * period_blocks, "DECAY", APPROVED_FLOOR_SRCT),
          APPROVED_FLOOR_SRCT)

    print("== supply-removal accounting (regression guard) ==")
    rem = supply_removed_srct_per_block(MAINNET, 1.0, 1_000)
    check("full base fee removed at 100% activity, fee 1000 (SRCT/block)", rem, 20.0)
    check("the M1 'burned' half is half the removal",
          burned_half_srct_per_block(MAINNET, 1.0, 1_000), rem / 2)
    check("removal is NOT half the base fee (old bug: would be 10.0)",
          rem == 10.0, False)
    floor_fee = MAINNET["base_fee_min_sat"]
    net_tail = APPROVED_FLOOR_SRCT - supply_removed_srct_per_block(MAINNET, 0.25, floor_fee)
    check("tail-era net per block @fee floor, normal activity", net_tail, -0.4)

    print("== monotonicity / bounds ==")
    for policy in ("A", "FLAT", "DECAY"):
        prev = -1.0
        for h in (1, 100_000, 262_800, 1_000_000, 1_839_600, 5_000_000, 50_000_000):
            cum = cumulative_srct(MAINNET, h, policy, APPROVED_FLOOR_SRCT)
            if cum < prev:
                fails.append(f"{policy}: cumulative decreased at {h}")
            prev = cum
    print("  ok    cumulative issuance is non-decreasing (per policy) over 50M blocks")
    if cumulative_srct(MAINNET, 10**9, "A") != 39_157_124.0:
        fails.append("policy A must stop at 39,157,124")
    print("  ok    policy A is bounded at 39,157,124 SRCT")

    print("== rate anchor headroom (Decision 18) ==")
    # The 1 % per-halving-period ceiling must never bind the approved DECAY
    # tail: each of the first tail windows' gross issuance is measured against
    # the supply issued at that window's start.
    H = MAINNET["halving_period"]
    start_h = exhaustion_height(MAINNET)
    worst = 0.0
    for k in range(6):
        ws = start_h + k * H
        base = cumulative_srct(MAINNET, ws - 1, "DECAY", APPROVED_FLOOR_SRCT)
        gross = cumulative_srct(MAINNET, ws + H - 1, "DECAY", APPROVED_FLOOR_SRCT) - base
        worst = max(worst, gross / base)
        print(f"  ok    tail window {k}: {gross:>12,.0f} SRCT on {base:>12,.0f} "
              f"issued ({100 * gross / base:.4f}%)")
    check("no approved tail window reaches the 1 % anchor", worst < 0.01, True)

    print("== overflow headroom ==")
    for tail_sat, profile in [(int(APPROVED_FLOOR_SRCT * SAT_PER_SRCT), MAINNET),
                              (1, MINI)]:
        blocks = 2**64 / tail_sat
        yrs = blocks * profile["block_time_s"] / SECONDS_PER_YEAR
        print(f"  ok    {profile['name']} tail {tail_sat} sat/block: "
              f"u64 sat overflow in {yrs:,.0f} years")
        if yrs < 1_000:
            fails.append(f"{profile['name']} overflow horizon too small")

    print("== committed supply vectors cross-check ==")
    path = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "supply_vectors.json"
    try:
        v = json.loads(path.read_text(encoding="utf-8"))
        check("vectors sat_per_srct", v["sat_per_srct"], SAT_PER_SRCT)
        for key, prof, policy in (("mainnet", MAINNET, "A"), ("mini", MINI, "A")):
            sec = v[key]
            check(f"{key} rate_anchor_max_pct_per_period",
                  sec["rate_anchor_max_pct_per_period"], 1.0)
            reach = int(cumulative_srct(prof, 64 * prof["halving_period"], policy))
            check(f"{key} max_reachable_srct", sec["max_reachable_srct"], reach)
            check(f"{key} issued_after_first_period_srct",
                  sec["issued_after_first_period_srct"],
                  int(cumulative_srct(prof, prof["halving_period"], policy)))
            check(f"{key} issued_after_two_periods_srct",
                  sec["issued_after_two_periods_srct"],
                  int(cumulative_srct(prof, 2 * prof["halving_period"], policy)))
            check(f"{key} halving_period_blocks", sec["halving_period_blocks"],
                  prof["halving_period"])
            check(f"{key} ladder_srct", sec["ladder_srct"],
                  [ladder_rung_srct(prof, k) for k in range(8)])
    except FileNotFoundError:
        print("  FAIL  supply_vectors.json missing")
        fails.append("vectors file")

    print("== determinism ==")
    a = [cumulative_srct(MAINNET, h, "DECAY", APPROVED_FLOOR_SRCT) for h in
         (1, 500_000, 1_900_000, 4_000_000)]
    b = [cumulative_srct(MAINNET, h, "DECAY", APPROVED_FLOOR_SRCT) for h in
         (1, 500_000, 1_900_000, 4_000_000)]
    check("identical inputs give identical outputs", a == b, True)

    print()
    if fails:
        print(f"SELFTEST FAILED ({len(fails)}): {fails}")
        return 1
    print("SELFTEST PASSED")
    return 0


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------
def policy_table(p: dict) -> None:
    bpy = blocks_per_year(p)
    print(f"  annual blocks: {bpy:,.0f}")
    print(f"  {'policy':<28} {'annual SRCT':>12} {'dilution @39.16M':>17} "
          f"{'@20M':>9} {'@10M':>9}")
    print("  " + "-" * 80)
    rows = [("A  ladder only, no tail (pre-M-A)", "A", 0.0),
            ("B  tail 1.00 SRCT", "FLAT", 1.0),
            ("C  tail 0.50 SRCT", "FLAT", 0.5),
            ("D  tail 0.10 SRCT", "FLAT", 0.1),
            ("E  decay->0.10 SRCT (rec.)", "DECAY", APPROVED_FLOOR_SRCT)]
    for label, policy, floor in rows:
        h = 100 * bpy
        annual = cumulative_srct(p, h, policy, floor) - cumulative_srct(p, h - bpy, policy, floor)
        if policy == "A" and h > exhaustion_height(p):
            annual = 0.0
        def dil(s: float) -> str:
            return f"{100 * annual / s:.4f}%" if annual else "0.0000%"
        # Denominators: the ladder payout (not a cap - the tail keeps issuing),
        # and two illustrative "what if supply had been capped at 20M / 10M"
        # sensitivity reads.
        print(f"  {label:<28} {annual:>12,.0f} {dil(MAINNET['ladder_srct']):>17} "
              f"{dil(20_000_000):>9} {dil(10_000_000):>9}")


def horizon_table(p: dict) -> None:
    bpy = blocks_per_year(p)
    horizons = [10, 25, 50, 100]
    print(f"  {'policy':<28}" + "".join(f"{'y'+str(y):>15}" for y in horizons))
    print("  " + "-" * 88)
    for label, policy, floor in [("A  ladder only, no tail (pre-M-A)", "A", 0.0),
                                 ("B  tail 1.00", "FLAT", 1.0),
                                 ("C  tail 0.50", "FLAT", 0.5),
                                 ("D  tail 0.10", "FLAT", 0.1),
                                 ("E  decay->0.10 (rec.)", "DECAY", APPROVED_FLOOR_SRCT)]:
        cells = "".join(f"{cumulative_srct(p, int(y * bpy), policy, floor):>15,.0f}"
                        for y in horizons)
        print(f"  {label:<28}{cells}")


def net_supply_table(p: dict) -> None:
    """Net supply by year with the M1 burn applied (policy E vs A)."""
    bpy = int(blocks_per_year(p))
    print("  (live supply = cumulative issuance - cumulative base fee removed)")
    print(f"  {'policy':<10} {'activity':<8} {'base fee':>9} "
          f"{'net y10':>14} {'net y25':>14} {'net y50':>14} {'net y100':>15}")
    print("  " + "-" * 92)
    for label, policy, floor in [("A", "A", 0.0),
                                 ("E(rec)", "DECAY", APPROVED_FLOOR_SRCT)]:
        for act_name, activity in ACTIVITY.items():
            for fee in (p["base_fee_min_sat"], p["base_fee_initial_sat"]):
                burn = supply_removed_srct_per_block(p, activity, fee) * bpy
                cells = []
                for y in (10, 25, 50, 100):
                    gross = cumulative_srct(p, y * bpy, policy, floor)
                    cells.append(f"{max(0.0, gross - burn * y):>14,.0f}")
                print(f"  {label:<10} {act_name:<8} {fee:>9,} " + " ".join(cells))


def security_budget_table(p: dict) -> None:
    bpy = blocks_per_year(p)
    print("  subsidy + full fee revenue, SRCT/block and SRCT/year "
          "(policy E at its 0.10 SRCT floor):")
    print(f"  {'activity':<9}{'base fee':>10}{'SRCT/block':>12}{'SRCT/year':>15}"
          f"{'USD/yr @ $0.10':>17}{'@ $1':>12}{'@ $10':>12}{'@ $100':>12}")
    print("  " + "-" * 100)
    for act_name, activity in ACTIVITY.items():
        for fee in (p["base_fee_min_sat"], p["base_fee_initial_sat"],
                    p["base_fee_initial_sat"] * 10):
            fees = fee_revenue_srct_per_block(p, activity, fee)
            subsidy = APPROVED_FLOOR_SRCT
            per_year = (subsidy + fees) * bpy
            usd = "".join(f"{per_year * px:>12,.0f}" for px in (0.10, 1, 10, 100))
            print(f"  {act_name:<9}{fee:>10,}{subsidy + fees:>12,.2f}"
                  f"{per_year:>15,.0f}{usd:>17}")


def micropayment_table(p: dict) -> None:
    l1_min = p["base_fee_min_sat"] * p["gas_tx_base"]
    print(f"  L1 minimum on-chain fee (base_fee_min x GAS_TX_BASE): "
          f"{l1_min:,} sat = {l1_min / SAT_PER_SRCT:.8f} SRCT")
    print(f"  L2 flat fees: post 5,000 / claim 2,000 / submit 2,000 / "
          f"dispute 10,000 / settle 20,000 / exit-queue 2,000 sat")
    print(f"  L2 settle vs L1 floor: {l1_min / 20_000:.1f}x cheaper on L2")
    print(f"  L2 deposit minimum per sink output: 1,000,000 sat = "
          f"{1_000_000 / SAT_PER_SRCT:.2f} SRCT")


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    print("MONETARY POLICY SIMULATION — design analysis only, no consensus effect")
    print("Assumptions: 365.25-day years; the ENTIRE base fee leaves live")
    print("supply (M1 destroys 50%, the other 50% accrues to the non-spendable")
    print("pscb_reserve counter, which no code path converts back to UTXOs);")
    print("fee revenue scales with (base fee x gas used); price rows are")
    print("sensitivity parameters, NOT forecasts.\n")

    for p in PROFILES:
        print(f"===== {p['name']} ({p['block_time_s']}s blocks) =====")
        print(f"  ladder exhausts at height {exhaustion_height(p):,} "
              f"(~{years_at(p, exhaustion_height(p)):.2f} years); "
              f"ladder payout {p['ladder_srct']:,} SRCT; reachable "
              f"{cumulative_srct(p, exhaustion_height(p), 'A'):,.0f} SRCT")
        if p["name"] == "mainnet":
            print("\n  [annual issuance & dilution]")
            policy_table(p)
            print("\n  [cumulative gross issuance]")
            horizon_table(p)
            print("\n  [net supply after burns]")
            net_supply_table(p)
            print("\n  [security budget]")
            security_budget_table(p)
            print("\n  [steady state: is the tail inflationary?]")
            print("  The base-fee retarget RISES whenever usage >= gas_cap and FALLS")
            print("  below it, so sustained full blocks are not a steady state; the")
            print("  long-run base fee converges to the floor. Live-supply change per")
            print("  block = reward - (base fee x gas used); positive = inflation.")
            print(f"  {'activity':>9}{'removed/block':>15}{'net E tail':>12}{'net A tail':>12}")
            for act_name, activity in ACTIVITY.items():
                r = supply_removed_srct_per_block(p, activity, p["base_fee_min_sat"])
                print(f"  {act_name:>9}{r:>15,.2f}"
                      f"{APPROVED_FLOOR_SRCT - r:>12,.2f}{0.0 - r:>12,.2f}")
            print("\n  [micropayment floors]")
            micropayment_table(p)
        else:
            tail = 1.0 / SAT_PER_SRCT
            annual = tail * blocks_per_year(p)
            print(f"  1-sat tail -> {annual:,.4f} SRCT/year "
                  f"({100 * annual / p['ladder_srct']:.6f}% of the {p['ladder_srct']:,} ladder payout)")
            print("  no tail -> mining stops permanently at "
                  f"{years_at(p, exhaustion_height(p)):.2f} years")
        print()

    print("Run `python verification/sim/tail_emission_sim.py --selftest` for the assertions")
    print("and the committed-vector cross-check.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
