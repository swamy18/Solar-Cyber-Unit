"""Solar Cyber Unit puzzle: independent Python reference implementation of SPEC.md section 5.

This exists to answer one question: is the Rust implementation the only
implementation? A second implementation written from the spec, in a different
language, that produces identical digests is the cheapest evidence that SPEC.md
is unambiguous.

It is deliberately a *reference*, not a fast one: weights are re-derived from
the hash chain on every call, exactly as the spec describes them, so a reader can
follow every line against the document.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

# --- Domain tags (SPEC.md section 0) ---------------------------------------
DOM_BLOCK = b"srct/blockhash/v1"
DOM_TX = b"srct/txid/v1"
DOM_BLOCK512 = b"srct/blockhash512/v1"
DOM_TX512 = b"srct/txid512/v1"
DOM_TXBODY = b"srct/txbody/v1"
DOM_SIG = b"srct/sig/v1"
DOM_ADDR = b"srct/addr/v2"
DOM_S1 = b"srct/puzzle/stage1/v1"
DOM_S2 = b"srct/puzzle/stage2/v1"
DOM_S3 = b"srct/puzzle/stage3/v1"
DOM_W = b"srct/puzzle/weights/v1"

SIG_SCHEME_SECP256K1_ECDSA = 1

HEADER_LEN = 177
BIAS_INDEX_OFFSET = 1_000_000
ACTIVATION_SHIFT = 2


def sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def sha_dom(dom: bytes, *parts: bytes) -> bytes:
    return sha(dom, *parts)


def sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def sha512_dom(dom: bytes, *parts: bytes) -> bytes:
    return sha512(dom, *parts)


def i32le(value: int) -> bytes:
    return struct.pack("<i", value)


def u32le(value: int) -> bytes:
    return struct.pack("<I", value)


def u64le(value: int) -> bytes:
    return struct.pack("<Q", value)


# --- Header (SPEC.md section 3.4) -------------------------------------------


@dataclass(frozen=True)
class Header:
    version: int
    height: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp_ms: int
    base_fee_sat: int
    difficulty: int
    nonce: int
    puzzle_id: int
    epoch_id: int
    extra_nonce: bytes
    sig_scheme: int = SIG_SCHEME_SECP256K1_ECDSA

    def serialize(self) -> bytes:
        return b"".join(
            [
                u32le(self.version),
                u64le(self.height),
                self.prev_hash,
                self.merkle_root,
                u64le(self.timestamp_ms),
                u64le(self.base_fee_sat),
                self.difficulty.to_bytes(16, "little"),
                u64le(self.nonce),
                u64le(self.puzzle_id),
                u32le(self.epoch_id),
                self.extra_nonce,
                bytes([self.sig_scheme]),
            ]
        )

    def block_hash(self) -> bytes:
        return sha512_dom(DOM_BLOCK512, self.serialize())


def genesis_header(merkle_root: bytes, difficulty: int) -> Header:
    return Header(
        version=1,
        height=0,
        prev_hash=b"\x00" * 64,
        merkle_root=merkle_root,
        timestamp_ms=1_767_225_600_000,  # 2026-01-01T00:00:00Z
        base_fee_sat=0,
        difficulty=difficulty,
        nonce=0,
        puzzle_id=1,
        epoch_id=0,
        extra_nonce=b"srct-genesis" + b"\x00\x00\x00\x00",
    )


# --- Puzzle spec (SPEC.md section 5.1) --------------------------------------


@dataclass(frozen=True)
class PuzzleSpec:
    id: int
    name: str
    hash_rounds: int
    nn_input_dim: int
    nn_hidden_dim: int
    nn_layers: int
    min_nn_share_bps: int
    max_nn_share_bps: int

    @staticmethod
    def hybrid_v1() -> "PuzzleSpec":
        return PuzzleSpec(
            id=1,
            name="hybrid-v1",
            hash_rounds=16,
            nn_input_dim=16,
            nn_hidden_dim=16,
            nn_layers=3,
            min_nn_share_bps=3_000,
            max_nn_share_bps=5_000,
        )

    def in_dim(self, layer: int) -> int:
        return self.nn_input_dim if layer == 0 else self.nn_hidden_dim

    def nn_macs(self) -> int:
        return self.nn_layers * self.nn_hidden_dim * self.nn_hidden_dim

    def hash_invocations(self) -> int:
        return 1 + self.hash_rounds + 1

    def nn_share_bps(self) -> int:
        """Cost-model share of mining work done by the network (section 5.6)."""
        macs = self.nn_macs()
        hash_cost = self.hash_invocations() * 64
        return (macs * 10_000 + hash_cost // 2) // (macs + hash_cost)

    def validate(self) -> None:
        if min(self.nn_input_dim, self.nn_hidden_dim, self.nn_layers) == 0:
            raise ValueError("network dimensions must be non-zero")
        if self.hash_rounds == 0:
            raise ValueError("at least one hash round is required")
        share = self.nn_share_bps()
        if not (self.min_nn_share_bps <= share <= self.max_nn_share_bps):
            raise ValueError(f"nn_share_bps {share} outside the audit band")


# --- Weight derivation (SPEC.md section 5.3) -------------------------------


def _epoch_seed(epoch_id: int) -> bytes:
    return sha_dom(DOM_W, u32le(epoch_id))


def _weight_stream(k: int, epoch_id: int) -> bytes:
    return sha_dom(DOM_W, _epoch_seed(epoch_id), u32le(k))


def weight(spec: PuzzleSpec, layer: int, out: int, inp: int, epoch_id: int) -> int:
    k = (layer * spec.nn_hidden_dim + out) * spec.in_dim(layer) + inp
    b = _weight_stream(k, epoch_id)[0]
    return b - 255 if b > 127 else b


def bias(spec: PuzzleSpec, layer: int, out: int, epoch_id: int) -> int:
    k = BIAS_INDEX_OFFSET + layer * spec.nn_hidden_dim + out
    return _weight_stream(k, epoch_id)[0] % 63


def fold32(value: int) -> int:
    """Wrap a 64-bit accumulator into a signed 32-bit value."""
    u = value & 0xFFFF_FFFF
    return u - 0x1_0000_0000 if u >= 0x8000_0000 else u


# --- The three stages (SPEC.md sections 5.2 - 5.4) --------------------------


def stage1_seed(spec: PuzzleSpec, header: Header) -> bytes:
    v = sha_dom(DOM_S1, header.serialize(), u64le(header.nonce))
    for r in range(spec.hash_rounds):
        v = sha_dom(DOM_S1, v, bytes([r]))
    return v


def stage2_activation_digest(spec: PuzzleSpec, seed: bytes, epoch_id: int) -> bytes:
    x = [seed[j] - 128 for j in range(spec.nn_input_dim)]
    acts = bytearray(DOM_S2)
    for layer in range(spec.nn_layers):
        in_dim = spec.in_dim(layer)
        z = []
        for out in range(spec.nn_hidden_dim):
            acc = bias(spec, layer, out, epoch_id)
            for inp in range(in_dim):
                acc += x[inp] * weight(spec, layer, out, inp, epoch_id)
            z.append(fold32(acc))
        for value in z:
            acts += i32le(value)
        x = [max(value >> ACTIVATION_SHIFT, 0) for value in z]
    return sha(bytes(acts))


def stage3_final(
    spec: PuzzleSpec, seed: bytes, act_digest: bytes, nonce: int, epoch_id: int
) -> bytes:
    return sha_dom(DOM_S3, seed, act_digest, u64le(nonce), u32le(epoch_id))


def run_puzzle(spec: PuzzleSpec, header: Header) -> dict[str, bytes]:
    seed = stage1_seed(spec, header)
    act = stage2_activation_digest(spec, seed, header.epoch_id)
    final = stage3_final(spec, seed, act, header.nonce, header.epoch_id)
    return {"seed": seed, "activation_digest": act, "final_hash": final}


def target_for_difficulty(difficulty: int) -> int:
    """target(d) = floor((2^256 - 1) / d), exact integer arithmetic."""
    if difficulty <= 0:
        raise ValueError("difficulty must be positive")
    if difficulty > 1 << 96:
        raise ValueError("difficulty above the 2^96 ceiling")
    return ((1 << 256) - 1) // difficulty


def satisfies(spec: PuzzleSpec, header: Header) -> bool:
    return int.from_bytes(run_puzzle(spec, header)["final_hash"], "big") <= target_for_difficulty(
        header.difficulty
    )


def address_from_pubkey(pubkey: bytes) -> bytes:
    return sha_dom(DOM_ADDR, pubkey)[:20]