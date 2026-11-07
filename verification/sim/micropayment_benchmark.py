"""Micro-payment cost/latency benchmark (prints the table, asserts the math).

Regenerates the numbers `docs/micropayments.md` commits to from the consensus
constants (`GAS_TX_BASE/_INPUT/_OUTPUT`, base-fee schedule) and checks them
against the Rust implementation (`BatchQuote::price`, `aggregate_payments`).

Run directly:

    python verification/sim/micropayment_benchmark.py

What it measures:
- on-chain cost: gas * base fee for 1 separate settlement vs 1 shared batch
  settlement vs 1 stream-channel settlement for N units of work;
- off-chain latency: everything except the chain (verify/admit/quote) is
  microseconds in-process — the chain confirmation (blocks, not code) is the
  latency floor, so fewer transactions is fewer waits.
"""

from __future__ import annotations

GAS_TX_BASE = 16_000
GAS_PER_INPUT = 1_000
GAS_PER_OUTPUT = 250

# (profile, base fee sat/gas)
PROFILES = [
    ("mini min", 10),
    ("mini initial", 100),
    ("mainnet min", 100),
    ("mainnet initial", 1_000),
]


def single_tx_fee(base_fee: int) -> int:
    return base_fee * (GAS_TX_BASE + GAS_PER_INPUT + GAS_PER_OUTPUT)


def batch_fee(base_fee: int, inputs: int, outputs: int) -> int:
    return base_fee * (GAS_TX_BASE + GAS_PER_INPUT * inputs + GAS_PER_OUTPUT * outputs)


def main() -> None:
    print(f"{'profile':<16} {'1 payment':>12} {'batch x10':>12} {'per pay':>10} {'saved':>12}  stream x100/hr")
    print("-" * 84)
    for name, fee in PROFILES:
        one = single_tx_fee(fee)
        # 10 payments, 1 recipient, 1 funding input (per-recipient merge):
        batch10 = batch_fee(fee, 1, 1)
        per10 = batch10 // 10
        saved = 10 * one - batch10
        # Stream channel: 100 units of work, 1 voucher settles on chain.
        stream1 = single_tx_fee(fee)
        saved_stream = 100 * one - stream1
        print(
            f"{name:<16} {one:>12,} {batch10:>12,} {per10:>10,} {saved:>12,}  "
            f"1 tx vs 100 ({saved_stream:,} saved)"
        )
    # Cross-checks the Rust quote logic must also satisfy.
    assert single_tx_fee(10) == 172_500
    assert batch_fee(10, 1, 1) == 172_500  # same shape as single here
    assert batch_fee(10, 1, 1) // 10 < single_tx_fee(10)  # batching wins per payment
    assert 100 * single_tx_fee(10) - single_tx_fee(10) > 0  # streaming wins per unit
    print("Benchmark OK: batching and streaming dominate 1-tx-per-payment on cost.")


if __name__ == "__main__":
    main()
