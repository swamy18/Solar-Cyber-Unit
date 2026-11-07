"""Supply schedule simulation (SPEC.md section 7; design doc section 16).

Regenerates the numbers the design doc commits to and checks them against the
Rust implementation. Run directly to print the whole schedule:

    python verification/sim/supply_schedule_sim.py

Independent of `tail_emission_sim.py`, which owns the tail *comparison*; this
script owns the committed vectors. Both must agree with `supply.rs` to the
satoshi, which is the cross-check that makes a disagreement a defect rather
than a formatting difference.

The approved tail (`docs/decisions.md` M-A..M-G, 2026-10-09) is modelled here:
mainnet decays to a 0.1 SRCT floor, mini/testnet pay a constant 1 sat/block.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SAT_PER_SRCT = 100_000_000

# Tail emission, approved 2026-10-09 (M-A decay tail, M-B 0.1 SRCT floor,
# M-C 1 sat/block on the fast profiles). `decay_to_floor` is the mainnet rule:
# the first tail period pays 0.5 SRCT and each later period halves in satoshis
# until the floor clamps it; `constant_sat` is the fast-profile rule.
MAINNET = {
    "name": "mainnet",
    "halving_period": 262_800,
    "start_reward_srct": 76,
    "block_time_s": 600,
    "tail_decay_to_floor_sat": 10_000_000,
}
MINI = {
    "name": "mini",
    "halving_period": 2_000,
    "start_reward_srct": 76,
    "block_time_s": 1,
    "tail_constant_sat": 1,
}

# Decision 18 (2026-10-09): no stock cap. The replacement is the rate anchor —
# gross issuance in any halving period after ladder exhaustion may not exceed
# this share of the supply issued at that window's start.
RATE_ANCHOR_MAX_PCT_PER_PERIOD = 1.0


def exhaustion_period(params: dict) -> int:
    """First period whose ladder rung is zero, i.e. where the tail begins."""
    start = params["start_reward_srct"]
    for p in range(64):
        if (start >> p) == 0:
            return p
    return 64


def tail_reward_sat(params: dict, period: int) -> int:
    """The tail rule, mirroring `supply::block_reward_sat` exactly."""
    if "tail_constant_sat" in params:
        return params["tail_constant_sat"]
    floor = params["tail_decay_to_floor_sat"]
    k = max(0, period - (exhaustion_period(params) - 1))
    if k >= 64:
        return floor
    return max(floor, SAT_PER_SRCT >> k)


def halvings(params: dict, height: int) -> int:
    return height // params["halving_period"]


def reward_srct(params: dict, height: int) -> int:
    """Halved in whole SRCT, never in satoshis (see supply.rs for why)."""
    return params["start_reward_srct"] >> halvings(params, height)


def reward_sat(params: dict, height: int) -> int:
    """The shipped reward function, in satoshis: ladder rung, then tail."""
    rung = reward_srct(params, height)
    if rung > 0:
        return rung * SAT_PER_SRCT
    return tail_reward_sat(params, halvings(params, height))


def reward_ladder(params: dict) -> list[int]:
    return [reward_srct(params, p * params["halving_period"]) for p in range(8)]


def cumulative_sat(params: dict, mined_blocks: int) -> int:
    """Issuance after `mined_blocks` blocks mined on top of genesis, satoshis.

    Exact block-reward semantics: block `h` pays `reward_sat(h)`, so period p
    covers heights `p*H ..= (p+1)*H - 1` and block `(p+1)*H` already pays the
    next rung. Counting that block in the previous period is an off-by-one
    that a mirrored Rust bug would otherwise hide.
    """
    total = 0
    start = 1
    while start <= mined_blocks:
        period = halvings(params, start)
        period_end = (period + 1) * params["halving_period"] - 1
        end = min(mined_blocks, period_end)
        total += reward_sat(params, start) * (end - start + 1)
        start = end + 1
    return total


def max_issuance_srct(params: dict) -> int:
    """The ladder-era integral: the reporting figure, not a bound (long-run
    issuance is unbounded by design, so the bound is per-height).

    Genesis occupies a rung-0 height without minting, so the first rung is paid
    by `H - 1` blocks: the exact figure is `149H - 76` SRCT, 76 SRCT below the
    `149H` geometric shortcut the design doc quotes.
    """
    return (
        cumulative_sat(params, exhaustion_period(params) * params["halving_period"] - 1)
        // SAT_PER_SRCT
    )


def largest_tail_window_pct(params: dict, windows: int = 6) -> float:
    """The most any post-exhaustion window issues, as a percent of the supply
    issued at that window's start.

    This is the figure the rate anchor must sit above: with the approved tail
    it is ~0.34 % on mainnet (the 0.5-SRCT first tail period), so the 1 %
    ceiling never binds in normal operation.
    """
    start_period = exhaustion_period(params)
    worst = 0.0
    for k in range(windows):
        per = start_period + k
        window_start = per * params["halving_period"]
        issued_start = cumulative_sat(params, window_start - 1)
        if issued_start == 0:
            continue
        gross = cumulative_sat(params, window_start + params["halving_period"] - 1) - issued_start
        worst = max(worst, 100.0 * gross / issued_start)
    return worst


def year_of(height: int, params: dict) -> float:
    """Elapsed years for `height` blocks (365.25-day years)."""
    return height * params["block_time_s"] / (86_400 * 365.25)


def report(params: dict) -> dict:
    ladder = reward_ladder(params)
    reachable = max_issuance_srct(params)
    periods = params["halving_period"]
    return {
        "network": params["name"],
        "ladder_srct": ladder,
        "halving_period_blocks": periods,
        "halving_period_years": round(year_of(periods, params), 3),
        "issued_after_first_period_srct": whole_srct(
            params, cumulative_sat(params, periods), "one period"
        ),
        "issued_after_two_periods_srct": whole_srct(
            params, cumulative_sat(params, 2 * periods), "two periods"
        ),
        "max_reachable_srct": reachable,
        # Decision 18: no stock cap. The anchor is the only ceiling: at most
        # 1 % of issued supply per halving period, and the approved schedule
        # sits ~3x under it (see `largest_tail_window_pct_of_issued`).
        "rate_anchor_max_pct_per_period": RATE_ANCHOR_MAX_PCT_PER_PERIOD,
        "largest_tail_window_pct_of_issued": largest_tail_window_pct(params),
        "final_reward_srct": next((r for r in ladder if r == 0), None),
        # The approved tail (M-A..M-G). `tail_activation_height` is where the
        # ladder gives way to it; the floor is what the decay clamps to. Both
        # units are carried deliberately: satoshis are what the code uses, and
        # SRCT is what a reader checks.
        "tail_activation_height": exhaustion_period(params) * periods,
        "tail_floor_sat": tail_reward_sat(params, exhaustion_period(params)),
        "tail_floor_srct": tail_reward_sat(params, exhaustion_period(params)) / SAT_PER_SRCT,
        "tail_reward_at_exhaustion_sat": tail_reward_sat(
            params, exhaustion_period(params)
        ),
        "tail_is_constant": "tail_constant_sat" in params,
    }


def whole_srct(params: dict, sat: int, what: str) -> int:
    """Convert an issuance figure to SRCT, refusing a fraction.

    Both reported horizons are pre-tail (the ladder pays whole SRCT), so a
    remainder means the schedule changed shape and the vector would silently
    carry a truncated number.
    """
    if sat % SAT_PER_SRCT:
        raise AssertionError(f"{params['name']}: {what} is not a whole number of SRCT")
    return sat // SAT_PER_SRCT


def check_design_doc_claims() -> list[str]:
    """The numbers the design doc asserts, verified rather than repeated."""
    problems: list[str] = []
    m = report(MAINNET)

    # Section 16: the ladder start and shape (no stock cap since Decision 18).
    if m["ladder_srct"] != [76, 38, 19, 9, 4, 2, 1, 0]:
        problems.append(f"reward ladder is {m['ladder_srct']}, expected [76,38,19,9,4,2,1,0]")
    if abs(m["halving_period_years"] - 5.0) > 0.01:
        problems.append(f"halving period is {m['halving_period_years']}y, expected 5y")

    # The geometric-series shortcut over-states issuance: floor division means
    # the ladder issues 149H - 76 SRCT (genesis eats a rung-0 height without
    # minting).
    if m["max_reachable_srct"] != 149 * 262_800 - 76:
        problems.append(
            f"reachable issuance is {m['max_reachable_srct']}, expected {149 * 262_800 - 76}"
        )
    # Decision 18: the rate anchor replaces the stock cap. The approved
    # schedule must fit under it with headroom (~3x on mainnet), never bind.
    if m["rate_anchor_max_pct_per_period"] != 1.0:
        problems.append("the rate anchor must be 1 % per halving period")
    if not 0.0 < m["largest_tail_window_pct_of_issued"] < 1.0:
        problems.append(
            f"largest tail window {m['largest_tail_window_pct_of_issued']}% must sit under the 1 % anchor"
        )

    # The tail (M-A/M-B): 0.5 SRCT at activation, then 0.25, 0.125, then the
    # 0.1 SRCT floor held forever — every step at most a halving, the step into
    # the floor the smallest of the series.
    if m["tail_activation_height"] != 1_839_600:
        problems.append(
            f"mainnet tail activates at {m['tail_activation_height']}, expected 1,839,600"
        )
    first_tail = exhaustion_period(MAINNET)
    path = [
        tail_reward_sat(MAINNET, first_tail + i) / SAT_PER_SRCT for i in range(4)
    ]
    if path != [0.5, 0.25, 0.125, 0.1]:
        problems.append(f"mainnet tail path is {path}, expected [0.5, 0.25, 0.125, 0.1]")
    if tail_reward_sat(MAINNET, first_tail + 40) != 10_000_000:
        problems.append("the mainnet floor is not held forever")
    prev = reward_sat(MAINNET, m["tail_activation_height"] - 1)
    for period in range(first_tail, first_tail + 10):
        now = tail_reward_sat(MAINNET, period)
        if now > prev or now * 2 < prev:
            problems.append(f"tail step at period {period} is more than a halving: {prev} -> {now}")
        prev = now

    # Issuance keeps growing forever under a tail — the whole point of M-A.
    late = cumulative_sat(MAINNET, 64 * 262_800)
    if late <= m["max_reachable_srct"] * SAT_PER_SRCT:
        problems.append("the tail did not add any issuance past the ladder era")
    # …and it stays a trickle: the mainnet floor mints ~0.013 %/yr of the
    # supply issued at exhaustion, far under the 0.2 %/yr the anchor implies.
    tail_year = 52_596 * 10_000_000
    issued_at_tail_start = cumulative_sat(MAINNET, m["tail_activation_height"] - 1)
    if tail_year * 500 >= issued_at_tail_start:
        problems.append("the mainnet floor mints more than 0.2 %/yr of issued supply")

    mi = report(MINI)
    if mi["tail_activation_height"] != 14_000 or mi["tail_floor_sat"] != 1:
        problems.append("mini tail is not the approved 1 sat/block from height 14,000")
    # Mini's own 1-sat tail is a trickle of its issued supply: under the
    # 0.2 %/yr the anchor implies. (F5's >1000 %/yr warning was about a
    # mainnet-sized floor on 1-second blocks — which is why the profiles'
    # tails are set independently.)
    mini_issued = cumulative_sat(MINI, mi["tail_activation_height"] - 1)
    mini_year = 31_536_000 * mi["tail_reward_at_exhaustion_sat"]
    if mini_year * 500 >= mini_issued:
        problems.append("mini's tail mints more than 0.2 %/yr of issued supply")
    if mi["largest_tail_window_pct_of_issued"] >= 1.0:
        problems.append("mini's tail must sit under the 1 % anchor")
    return problems


def main() -> int:
    for params in (MAINNET, MINI):
        print(f"=== {params['name']} ===")
        for key, value in report(params).items():
            print(f"  {key:32} {value}")
        print()

    problems = check_design_doc_claims()
    print("design-doc cross-check:", "OK" if not problems else "FAILED")
    for p in problems:
        print("  -", p)

    out = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "supply_vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "sat_per_srct": SAT_PER_SRCT,
                "mainnet": report(MAINNET),
                "mini": report(MINI),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {out}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())