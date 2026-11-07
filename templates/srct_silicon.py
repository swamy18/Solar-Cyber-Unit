#!/usr/bin/env python3
"""Photonic & custom-silicon PoW: benchmark attestation, not bonus yield.

The network already runs integer-only math on every chip (CPU, GPU, NPU,
TPU, photonic, domestic accelerators all compute bit-identical results)
and `srct-miner` exposes one `ComputeBackend` contract with two in-tree
backends (`CpuBackend`, `PortableBackend`) — a new chip joins by
implementing the contract and passing the differential test, never by
forking consensus. This file is the process around that port:

- `attest(...)` records a vendor's measured numbers (device class,
  puzzle + dims, candidates/sec, watts) into a canonical attestation.
- `efficiency(att)` derives candidates/joule and an efficiency class.
- `verify_attestation(att)` re-checks schema, known puzzle dims, and
  internal arithmetic, so a port PR carries a checkable claim.
- `port_checklist(device)` prints the exact steps from claim to merged
  backend.

What this file does NOT do: mining multipliers or bonus yield for
next-gen hardware. The coinbase is a consensus rule — paying photonic
miners more per block is monetary policy, changes what every node
accepts, and hands an advantage to whoever buys the newest fab first
(the centralization this network exists to resist). Hardware innovation
is incentivized the other way: the attestation below is the admission
ticket, and the fastest truthful chip wins blocks the honest way — by
evaluating more candidates per joule.

Puzzle dims mirrored from `PuzzleSpec` (`crates/srct-core/src/puzzle.rs`):
hybrid-v1/vwc-v1 share stage 2 (16 rounds input chain, 16-wide, 3
layers, 16x16); hbm-v1 is the memory-hard route. Claims against other
dims refuse.

Stdlib only: json + time. No new dependencies.
"""

import json
import sys
import time

# Device classes the network's integer-only PoW already admits.
DEVICES = ("cpu", "gpu", "npu", "tpu", "photonic", "neuromorphic",
           "fpga", "asic", "edge", "solar-edge", "domestic-accelerator")

# (puzzle_id, hash_rounds, nn_input_dim, nn_hidden_dim, nn_layers)
KNOWN_PUZZLES = {
    1: {"name": "hybrid-v1", "hash_rounds": 16, "nn_input_dim": 16,
        "nn_hidden_dim": 16, "nn_layers": 3},
    3: {"name": "vwc-v1", "hash_rounds": 16, "nn_input_dim": 16,
        "nn_hidden_dim": 16, "nn_layers": 3},
    # puzzle_id 2 (hbm-v1) is memory-hard: scratchpad params live in
    # HbmConfig, not here; attestations against it name puzzle_id 2
    # with the config hash in `notes`.
    2: {"name": "hbm-v1", "hash_rounds": 0, "nn_input_dim": 0,
        "nn_hidden_dim": 0, "nn_layers": 0},
}

# Efficiency classes, candidates per joule. Class A is the bar a new
# fab process should clear to matter; anything below D is a space
# heater with extra steps.
CLASSES = ((1_000_000, "A"), (100_000, "B"), (10_000, "C"), (1_000, "D"))


class SrctError(Exception):
    """Anything that stops the attestation from validating."""


def attest(device, puzzle_id, candidates_per_sec, watts,
           vendor="", model="", notes="", backend=""):
    """Build a benchmark attestation. Numbers are operator-measured.

    `candidates_per_sec` and `watts` must be measured on the same run
    over the same candidate set; the attestation records the claim and
    `verify_attestation` re-checks everything re-checkable. What it
    cannot re-check — that the vendor really ran the benchmark — is why
    the differential test against the reference backend stays mandatory
    (see `port_checklist`).
    """
    if device not in DEVICES:
        raise SrctError(f"unknown device {device!r}; one of {DEVICES}")
    spec = KNOWN_PUZZLES.get(puzzle_id)
    if spec is None:
        raise SrctError(f"unknown puzzle_id {puzzle_id}; "
                        f"one of {sorted(KNOWN_PUZZLES)}")
    if candidates_per_sec <= 0:
        raise SrctError("candidates_per_sec must be > 0")
    if watts <= 0:
        raise SrctError("watts must be > 0 (wall power, same run)")
    return {
        "device": device,
        "vendor": vendor or "",
        "model": model or "",
        "puzzle_id": puzzle_id,
        "puzzle_name": spec["name"],
        "hash_rounds": spec["hash_rounds"],
        "nn_input_dim": spec["nn_input_dim"],
        "nn_hidden_dim": spec["nn_hidden_dim"],
        "nn_layers": spec["nn_layers"],
        "candidates_per_sec": candidates_per_sec,
        "watts": watts,
        "backend": backend or "",
        "notes": notes or "",
        "measured_at": int(time.time()),
    }


def efficiency(att):
    """Candidates/joule plus class. Pure arithmetic over the claim."""
    per_joule = att["candidates_per_sec"] / att["watts"]
    cls = "E"
    for bar, name in CLASSES:
        if per_joule >= bar:
            cls = name
            break
    return {"candidates_per_joule": per_joule, "class": cls}


def verify_attestation(att):
    """Re-check everything re-checkable. Returns the attestation + class.

    Schema, known device, known puzzle with matching dims, positive
    measurements, sane magnitudes (faster than light refuses: no
    candidate evaluation exceeds 1e15/s on any physics we know).
    Trust in the *measurement* still comes from the differential test,
    not from this function.
    """
    if not isinstance(att, dict):
        raise SrctError("attestation must be an object")
    for key in ("device", "puzzle_id", "candidates_per_sec", "watts"):
        if key not in att:
            raise SrctError(f"attestation missing {key!r}")
    if att["device"] not in DEVICES:
        raise SrctError(f"unknown device {att['device']!r}")
    spec = KNOWN_PUZZLES.get(att["puzzle_id"])
    if spec is None:
        raise SrctError(f"unknown puzzle_id {att['puzzle_id']!r}")
    for dim in ("hash_rounds", "nn_input_dim", "nn_hidden_dim", "nn_layers"):
        if att.get(dim) != spec[dim]:
            raise SrctError(f"{dim} {att.get(dim)!r} != {spec['name']} "
                            f"spec {spec[dim]!r}")
    cps, watts = att["candidates_per_sec"], att["watts"]
    if not (0 < cps <= 1e15):
        raise SrctError("candidates_per_sec outside physical plausibility")
    if not (0 < watts <= 1e7):
        raise SrctError("watts outside physical plausibility")
    out = dict(att)
    out["efficiency"] = efficiency(att)
    return out


def port_checklist(device):
    """The exact path from attestation to merged backend."""
    return [
        f"1. Implement ComputeBackend for {device} "
        "(crates/srct-miner/src/accel.rs: same kernels, bit-identical).",
        "2. Pass the differential test: every candidate, every epoch, "
        "equal to CpuBackend (see accel.rs tests).",
        "3. Attach this file's verified attestation "
        "(device, puzzle, candidates/sec, watts, efficiency class).",
        "4. No consensus change, no multiplier, no fork: the fastest "
        "truthful chip wins blocks by evaluating more candidates.",
    ]


def _selftest():
    """Offline self-test: attest, verify, rank, refuse.

    Run:  python templates/srct_silicon.py --selftest
    """
    # A photonic prototype at 2M candidates/sec on 1W: class A.
    att = attest("photonic", 1, 2_000_000, 1.0, vendor="acme",
                 model="ph-1", backend="PhotonicBackend")
    checked = verify_attestation(att)
    assert checked["efficiency"]["class"] == "A", checked
    assert checked["puzzle_name"] == "hybrid-v1", checked

    # vwc-v1 shares the NN dims; hbm-v1 is the memory route.
    assert verify_attestation(
        attest("neuromorphic", 3, 50_000, 1.0))["efficiency"]["class"] == "C"
    assert verify_attestation(
        attest("gpu", 2, 5_000, 50.0))["puzzle_name"] == "hbm-v1"

    # Efficiency ordering is arithmetic, not marketing.
    slow = efficiency(attest("cpu", 1, 500, 65.0))
    assert slow["class"] == "E", slow

    # Unknown device, puzzle, bad numbers, dim mismatch: all refuse.
    for bad in (dict(device="warp-drive", puzzle_id=1,
                     candidates_per_sec=1, watts=1.0),
                dict(device="gpu", puzzle_id=99,
                     candidates_per_sec=1, watts=1.0),
                dict(device="gpu", puzzle_id=1,
                     candidates_per_sec=0, watts=1.0),
                dict(device="gpu", puzzle_id=1,
                     candidates_per_sec=1, watts=-5.0)):
        try:
            attest(**bad)
            raise AssertionError(f"bad attestation accepted: {bad}")
        except SrctError:
            pass
    tampered = attest("gpu", 1, 100_000, 100.0)
    tampered["nn_layers"] = 4
    try:
        verify_attestation(tampered)
        raise AssertionError("dim mismatch must refuse")
    except SrctError:
        pass
    for key in ("device", "watts"):
        short = attest("gpu", 1, 100_000, 100.0)
        del short[key]
        try:
            verify_attestation(short)
            raise AssertionError(f"missing {key} must refuse")
        except SrctError:
            pass

    steps = port_checklist("photonic")
    assert len(steps) == 4 and "no multiplier" in steps[3].lower(), steps
    print("srct_silicon selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
