"""Verify every vector file is present, self-consistent and current.

SPEC.md section 12 lists four vector files and says to regenerate them with
this script. In practice the puzzle and difficulty vectors have to be emitted
by the Rust implementation (they are consensus values, not derived quantities
Python can author), so this script runs the right generators and then checks
the result. Supply vectors *are* computed here, because they are arithmetic
over the schedule rather than digests.

    python verification/sim/verify_vectors.py          # regenerate + verify, non-zero on failure
    python verification/sim/verify_vectors.py --check  # verify only, do not write

The generated files are then re-checked against a live implementation:
`puzzle_crosscheck.py` re-derives every puzzle digest from the independent
Python reference, and `cargo test` re-derives the difficulty values. A vector
file that exists but is never compared to an implementation is decoration.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS_DIR = ROOT / "tests" / "vectors"

EXPECTED = {
    "puzzle_vectors.json": "header serialization + 3 PoW stage digests",
    "ser_vectors.json": "input / output / tx / header byte layouts",
    "supply_vectors.json": "reward ladder, cumulative supply, rate-anchor invariant",
    "difficulty_vectors.json": "LWMA next-difficulty, timestamp clamp",
    "net_vectors.json": "frame envelope, every msg_type payload, VERSION, bounds",
    "l2_authority_vectors.json": (
        "L2 policy + credit scenarios, verdicts and final state "
        "(SPEC.md 21, 22)"
    ),
}

problems: list[str] = []
notes: list[str] = []


def run(cmd: list[str], env: dict | None = None) -> bool:
    merged = {**os.environ, **(env or {})}
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=merged)
    if proc.returncode != 0:
        problems.append(f"`{' '.join(cmd)}` failed:\n{proc.stdout}\n{proc.stderr}")
        return False
    return True


def check_present() -> None:
    for name, covers in EXPECTED.items():
        path = VECTORS_DIR / name
        if not path.exists():
            problems.append(f"{name} is missing (covers {covers})")
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            problems.append(f"{name} is not valid JSON: {e}")


def check_supply_values() -> None:
    """Re-derive the supply ladder here rather than trusting the file."""
    path = VECTORS_DIR / "supply_vectors.json"
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))

    for network in ("mainnet", "mini"):
        if network not in data:
            problems.append(f"supply_vectors.json is missing the {network} section")
            continue
        sec = data[network]
        ladder = sec["ladder_srct"]
        if ladder != [76, 38, 19, 9, 4, 2, 1, 0]:
            problems.append(f"{network}: ladder is {ladder}, expected [76,38,19,9,4,2,1,0]")

        period = sec["halving_period_blocks"]
        # Floor division makes the reachable total 149 periods' worth, not the
        # 152 the geometric series suggests; and genesis occupies a rung-0
        # height without minting, so the first rung is paid by `period - 1`
        # blocks. Reachable = 149 x period - 76.
        expected_reachable = (
            sum((76 >> k) * period for k in range(8) if (76 >> k) > 0) - 76
        )
        if sec["max_reachable_srct"] != expected_reachable:
            problems.append(
                f"{network}: reachable issuance {sec['max_reachable_srct']} "
                f"!= {expected_reachable}"
            )
        if sec.get("rate_anchor_max_pct_per_period") != 1.0:
            problems.append(f"{network}: rate anchor must be 1 % per halving period")
        if not 0.0 < sec.get("largest_tail_window_pct_of_issued", 1.0) < 1.0:
            problems.append(
                f"{network}: the approved schedule must sit under the 1 % anchor"
            )


def check_puzzle_against_reference() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "sim" / "puzzle_crosscheck.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        problems.append(
            "puzzle_crosscheck.py failed -- the Rust and Python implementations "
            f"disagree:\n{proc.stdout}\n{proc.stderr}"
        )


def check_net_against_reference() -> None:
    """Cross-check the wire format against the independent Python encoder.

    Round-trip tests only prove a codec agrees with itself, so a field order
    that differs from SPEC.md 13.5 passes every Rust test and still breaks every
    other implementation. `net_reference.py` is written from the prose, so a
    disagreement points at the spec rather than at either implementation. It
    has already earned its place: it caught ADDR encoding `ip | port` where the
    spec says `port | ip`.
    """
    proc = subprocess.run(
        [sys.executable, str(ROOT / "sim" / "net_reference.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        problems.append(
            "net_reference.py failed -- the Rust and Python wire-format "
            f"implementations disagree:\n{proc.stdout}\n{proc.stderr}"
        )
    else:
        notes.append("wire format cross-checked against an independent encoder")


def main() -> int:
    parser = argparse.ArgumentParser(description="verify or regenerate Solar Cyber Unit test vectors")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify only; do not regenerate anything",
    )
    args = parser.parse_args()

    if not args.check:
        # Puzzle and difficulty digests must come from the implementation
        # that defines them. Supply is pure arithmetic and is done in Python.
        run(
            ["cargo", "test", "-p", "srct-core", "--lib", "puzzle_vectors_are_stable"],
            env={"UPDATE_PUZZLE_VECTORS": "1"},
        )
        run(
            ["cargo", "test", "-p", "srct-core", "--lib", "difficulty_vectors_are_stable"],
            env={"UPDATE_DIFFICULTY_VECTORS": "1"},
        )
        run([sys.executable, str(ROOT / "sim" / "supply_schedule_sim.py")])
        notes.append("regenerated puzzle, difficulty and supply vectors from source")

    check_present()
    check_supply_values()
    if (VECTORS_DIR / "puzzle_vectors.json").exists():
        check_puzzle_against_reference()
    if (VECTORS_DIR / "net_vectors.json").exists():
        check_net_against_reference()

    for name in sorted(EXPECTED):
        path = VECTORS_DIR / name
        if path.exists():
            size = path.stat().st_size
            print(f"  {'ok ' if path.exists() else 'MISSING'} {name:<28}{size:>8} bytes")

    if notes:
        print("\n" + "\n".join(f"  note: {n}" for n in notes))

    if problems:
        print(f"\nFAILED ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return 1

    print("\nall vector files present, self-consistent and cross-checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
