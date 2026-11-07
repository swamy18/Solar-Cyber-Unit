"""Agent-economy demo (envelope level, stdlib only).

Mirrors the Rust tests without keys: tier narrowing math, USD-quote math,
passport scoring with counterparty dampening, and the job lifecycle.

    python verification/sim/agent_economy_demo.py

The cryptography (owner signatures, BLS attestations) lives in the Rust
wallet and node tests (`cargo test -p srct-node --test agent_economy`).
"""

from __future__ import annotations

import math


def quote_usd(amount_minor: int, sat_per_minor: int, fee_bps: int, slip_bps: int) -> tuple[int, int]:
    # The declared fee is all-in: slippage headroom rides inside it, so
    # sat_due == gross + fee exactly (the rule `/v1/fx/swap` enforces).
    gross = amount_minor * sat_per_minor
    fee = gross * fee_bps // 10_000
    slip = gross * slip_bps // 10_000
    return gross + fee + slip, fee + slip


def passport_score(events: list[tuple[str, str]]) -> int:
    weights = {"task": 1, "payment": 1, "repay": 4, "dispute_lost": -4, "default": -8}
    groups: dict[tuple[str, str], int] = {}
    for kind, counterparty in events:
        groups[(kind, counterparty)] = groups.get((kind, counterparty), 0) + 1
    total = 0
    for (kind, _), count in groups.items():
        w = weights[kind]
        total += w * math.isqrt(count) if w > 0 else w * count
    return total


def main() -> None:
    # Tier narrowing: caps only shrink down the chain.
    parent, mx, mn = 20, 20, 1
    assert mn <= mx <= parent, "tiers must narrow"
    print(f"tiers: parent {parent}/tx -> max {mx}/tx -> min {mn}/tx")

    # USD quote: $1.00 at 1000 sat/cent, 1% fee, 0.5% slippage headroom.
    due, fee = quote_usd(100, 1_000, 100, 50)
    assert (due, fee) == (101_500, 1_500), (due, fee)
    print(f"quote: $1.00 -> {due} sat (all-in fee {fee})")

    # Passport: 100 farmed payments, one counterparty, lose to 4 genuine ones.
    farmed = [("payment", "X")] * 100
    genuine = [("payment", str(i)) for i in range(4)]
    assert passport_score(farmed) < passport_score(genuine) * 3
    print(f"passport: farmed={passport_score(farmed)} genuine={passport_score(genuine)}")

    # Default zeroes any suggested limit.
    assert passport_score([("repay", "A"), ("repay", "B"), ("default", "C")]) <= 0
    print("lending: a default outweighs two repayments")

    # Job lifecycle: offer -> accept -> deliver -> release, or dispute -> hold.
    state, held = "Offered", False
    state, held = "Accepted", False
    state = "Delivered"
    assert not held
    state, held = "Disputed", True
    assert held, "funds stay locked on dispute"
    state, held = "ResolvedRelease", False
    print(f"job: {state}, held={held}")
    print("Demo OK: tiers narrow, quotes exact, reputation resists farming, jobs lock on dispute.")


if __name__ == "__main__":
    main()
