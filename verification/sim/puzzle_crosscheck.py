"""Cross-check the Rust PoW puzzle against the independent Python reference.

SPEC.md section 12 states that `verification/tests/vectors/*.json` are consumed by both the
Rust test suite and this script, and that a language implementation is correct
only if it reproduces them byte for byte.

That second half is the point. `verification/sim/srct_reference.py` is a second
implementation written from the prose of SPEC.md, not from the Rust source. If
the two agree on every vector, that is real evidence the spec is unambiguous --
if they disagree, the disagreement is in the spec, not in either
implementation.

    python verification/sim/puzzle_crosscheck.py          # check, non-zero exit on mismatch

Regenerate the vectors from Rust with:

    UPDATE_PUZZLE_VECTORS=1 cargo test -p srct-core --lib puzzle_vectors
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from srct_reference import (  # noqa: E402
    PuzzleSpec,
    genesis_header,
    run_puzzle,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "puzzle_vectors.json"

# The vector generator builds headers from the genesis block with these
# overrides. They are part of the fixture, so they are restated here rather
# than imported: the reference implementation must not depend on the Rust
# code that produced the numbers it is checking.
BASE_TIMESTAMP_MS = 1_700_000_000_000


def reference_header(height: int, nonce: int, epoch_id: int):
    """Rebuild the exact header the Rust vector generator used.

    SPEC.md section 11 defines the genesis header, so this is derivable from
    the spec: extra_nonce is "srct-genesis" padded to 16 bytes, the
    merkle root is the single-transaction coinbase root, and difficulty is 1.
    """
    # Leaf hash of the one-transaction genesis coinbase: SHA256(0x00 || tx).
    # Recomputed rather than hardcoded so the reference stays independent.
    import hashlib

    def u32le(v: int) -> bytes:
        return v.to_bytes(4, "little")

    def u64le(v: int) -> bytes:
        return v.to_bytes(8, "little")

    coinbase = (
        u32le(1)  # version
        + bytes([1])  # tx_type = coinbase
        + u64le(0)  # lock_time
        + u32le(1)  # input_count
        + (b"\x00" * 64)  # prevout_hash
        + (0).to_bytes(4, "little")  # prevout_index
        # SPEC.md 3.5: signature and key bundles. A coinbase spends
        # nothing, so both are empty -- two zero counts. These replaced
        # the old fixed 64-byte signature + 33-byte pubkey.
        + bytes([0])
        + bytes([0])
        + u32le(1)  # output_count
        + u64le(0)  # value
        + b"One Consciousness.\x00\x00"  # address (genesis inscription, SPEC.md \u00a72.3)
    )
    merkle_root = hashlib.sha256(b"\x00" + coinbase).digest()

    header = genesis_header(merkle_root, difficulty=1)
    return type(header)(
        version=header.version,
        height=height,
        prev_hash=header.prev_hash,
        merkle_root=merkle_root,
        timestamp_ms=BASE_TIMESTAMP_MS,
        base_fee_sat=header.base_fee_sat,
        difficulty=header.difficulty,
        nonce=nonce,
        puzzle_id=header.puzzle_id,
        epoch_id=epoch_id,
        extra_nonce=header.extra_nonce,
    )


def main() -> int:
    if not VECTORS.exists():
        print(f"missing {VECTORS}")
        print("regenerate with: UPDATE_PUZZLE_VECTORS=1 cargo test -p srct-core")
        return 2

    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    spec = PuzzleSpec.hybrid_v1()

    spec_json = data.get("spec", {})
    mismatches: list[str] = []
    for key, got in (
        ("hash_rounds", spec.hash_rounds),
        ("nn_input_dim", spec.nn_input_dim),
        ("nn_hidden_dim", spec.nn_hidden_dim),
        ("nn_layers", spec.nn_layers),
        ("nn_share_bps", spec.nn_share_bps()),
    ):
        want = spec_json.get(key)
        if want is not None and want != got:
            mismatches.append(f"spec.{key}: rust={want} reference={got}")

    print("=== puzzle cross-check: srct-core vs independent Python reference ===")
    print(f"{'case':<22}{'stage':<12}{'result':<8}detail")
    print("-" * 72)

    checked = 0
    for case in data["cases"]:
        height = case["height"]
        nonce = case["nonce"]
        epoch = case["epoch_id"]
        name = f"h{height}_n{nonce}_e{epoch}"

        header = reference_header(height, nonce, epoch)
        if len(header.serialize()) != case["header_len"]:
            mismatches.append(
                f"{name}: header length {len(header.serialize())} "
                f"!= rust {case['header_len']}"
            )

        run = run_puzzle(spec, header)
        for field in ("seed", "activation_digest", "final_hash"):
            want = case[field]
            got = run[field].hex()
            checked += 1
            if got == want:
                print(f"{name:<22}{field:<12}{'ok':<8}{got[:24]}...")
            else:
                mismatches.append(f"{name}: {field}\n    rust      {want}\n    reference {got}")
                print(f"{name:<22}{field:<12}{'FAIL':<8}{got[:24]}...")

    print()
    if mismatches:
        print(f"MISMATCH ({len(mismatches)}):")
        for m in mismatches:
            print(f"  - {m}")
        print(
            "\nThe Rust and the reference implementation disagree. One of them\n"
            "is wrong, or SPEC.md is ambiguous -- do not paper over it by\n"
            "regenerating the vectors until they match."
        )
        return 1

    print(f"OK: {checked} digests agree across {len(data['cases'])} vectors")
    print(
        "The spec is unambiguous on header layout and the three PoW stages,\n"
        "as far as these cases exercise it."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
