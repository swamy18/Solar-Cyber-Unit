"""Independent Python implementation of the Solar Cyber Unit wire format (SPEC.md section 13).

This is the same discipline as ``verification/sim/srct_reference.py`` for the PoW puzzle:
a second implementation written from the *prose* of the specification rather
than from the Rust source, so that a disagreement points at the spec instead of
at either implementation.

Why it matters here. A round-trip test only proves a codec agrees with itself.
If ``VERSION`` encoded ``user_agent`` before ``protocol_version`` and the decoder
read them in the same wrong order, every round-trip test in the crate passes and
two implementations of section 13.5 silently desync -- which looks exactly like a
consensus split. ``verification/tests/vectors/net_vectors.json`` pins the bytes, but that file
is generated *from* the Rust, so it cannot catch a bug that is in both.

    python verification/sim/net_reference.py            # cross-check against the vectors
    python verification/sim/net_reference.py --show     # print the derived bytes

What this can and cannot check. Everything the wire format defines from a spec
constant: the frame envelope, every ``msg_type`` payload, ``VERSION`` for both
profiles, and the section 13.8 bounds. It cannot check ``block1`` or the locator
entries, because those values come from mining blocks on a real chain -- that
needs a Rust node, not a second implementation. Those are named in
``SKIPPED`` so the gap is stated rather than glossed over.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "net_vectors.json"

# --- SPEC.md section 13.5: frozen message numbers -------------------------
MSG_VERSION = 1
MSG_VERACK = 2
MSG_PING = 3
MSG_PONG = 4
MSG_INV = 5
MSG_GETDATA = 6
MSG_BLOCK = 7
MSG_GETBLOCKS = 8
MSG_ADDR = 9
MSG_TX = 10
MSG_CHECKPOINT = 11

# --- SPEC.md section 13.3: per-profile identity ---------------------------
# A new profile MUST pick a magic no existing profile uses.
NETWORK_MAGIC = {
    "mainnet": bytes([0x6A, 0x4E, 0x54, 0x02]),
    "mini": bytes([0x6A, 0x4E, 0x54, 0x03]),
}
NETWORK_ID = {
    "mainnet": b"srct/mainnet",
    "mini": b"srct/mini",
}

# --- SPEC.md section 13.8: resource bounds --------------------------------
MAX_FRAME_BYTES = 4_100_000
MAX_INV_PER_MSG = 500
MAX_ADDR_PER_MSG = 100
MAX_LOCATOR_LEN = 500
MAX_PEERS = 125
MAX_INBOUND = 32
HANDSHAKE_TIMEOUT_S = 20
BAN_SCORE_THRESHOLD = 100
ORPHAN_POOL_MAX = 64
# section 13.14, all from the section 13.8 table.
MAX_RELAY_IN_FLIGHT = 128
MAX_RELAY_PENDING = 1_024
MAX_RELAY_KNOWN = 4_096
MAX_TX_INV_BATCH = 64
TX_RELAY_PER_PEER_PER_MIN = 600
TX_REQUEST_TIMEOUT_MS = 30_000

# section 13.5: kind 1 = block; kind 0 = transaction (section 13.14).
# 0 was reserved for transactions before they existed, so that announcement could
# be added without changing the shape of INV/GETDATA.
INV_TYPE_BLOCK = 1
INV_TYPE_TX = 0
PROTOCOL_VERSION = 1

# section 3.5: 1 <= len <= 4096 per bundle component, and at most 4 components.
BUNDLE_MAX_COMPONENTS = 4
BUNDLE_COMPONENT_MAX = 4096


# --- encoders, written from the field tables in section 13 ----------------


def u16le(n: int) -> bytes:
    return n.to_bytes(2, "little")


def u32le(n: int) -> bytes:
    return n.to_bytes(4, "little")


def u64le(n: int) -> bytes:
    return n.to_bytes(8, "little")


def frame(magic: bytes, msg_type: int, payload: bytes) -> bytes:
    """frame = magic(4) | msg_type(1) | payload_len(4 LE) | payload"""
    if len(magic) != 4:
        raise ValueError("magic must be 4 bytes")
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError(f"payload {len(payload)} exceeds max_frame_bytes")
    return magic + bytes([msg_type]) + u32le(len(payload)) + payload


def version_payload(
    network: str,
    height: int,
    tip_hash: bytes,
    user_agent: bytes = b"/srct-net:0.2",
    nonce: int = 0x0123_4567_89AB_CDEF,
    services: int = 1,
) -> bytes:
    """VERSION -- SPEC.md section 13.4, in the order the table lists."""
    network_id = NETWORK_ID[network]
    if len(network_id) > 255:
        raise ValueError("network_id does not fit a 1-byte length prefix")
    if len(user_agent) > 255:
        raise ValueError("user_agent does not fit a 1-byte length prefix")
    if len(tip_hash) != 64:
        raise ValueError("tip_hash must be 64 bytes")
    out = NETWORK_MAGIC[network]
    out += bytes([len(network_id)]) + network_id
    out += u32le(PROTOCOL_VERSION)
    out += u64le(services)
    out += u64le(height)
    out += tip_hash
    out += bytes([len(user_agent)]) + user_agent
    out += u64le(nonce)
    return out


def nonce_payload(nonce: int) -> bytes:
    """VERACK / PING / PONG all carry a bare echoed nonce."""
    return u64le(nonce)


def inv_payload(entries: list[tuple[int, bytes]]) -> bytes:
    """INV / GETDATA: count(2 LE) | count x (kind(1) | hash(64))."""
    if len(entries) > MAX_INV_PER_MSG:
        raise ValueError(f"inv count {len(entries)} exceeds max_inv_per_msg")
    out = u16le(len(entries))
    for kind, h in entries:
        if len(h) != 64:
            raise ValueError("inv hash must be 64 bytes")
        out += bytes([kind]) + h
    return out


def getblocks_payload(locator: list[bytes], stop: bytes) -> bytes:
    """GETBLOCKS: count(2 LE) | count x locator(64) | stop_hash(64)."""
    if len(locator) > MAX_LOCATOR_LEN:
        raise ValueError(f"locator count {len(locator)} exceeds max_locator_len")
    if len(stop) != 64:
        raise ValueError("stop_hash must be 64 bytes")
    return u16le(len(locator)) + b"".join(locator) + stop


def addr_payload(addrs: list[tuple[bytes, int]]) -> bytes:
    """ADDR: count(2 LE) | count x (port(2 LE) | ip(16))."""
    if len(addrs) > MAX_ADDR_PER_MSG:
        raise ValueError(f"addr count {len(addrs)} exceeds max_addr_per_msg")
    out = u16le(len(addrs))
    for ip, port in addrs:
        if len(ip) != 16:
            raise ValueError("addr ip must be 16 bytes (IPv6-mapped IPv4)")
        out += u16le(port) + ip
    return out


def ipv4_mapped(a: str, b: str, c: str, d: str) -> bytes:
    """::ffff:a.b.c.d -- the representation section 13.5 requires."""
    return bytes(10) + bytes([0xFF, 0xFF]) + bytes([a, b, c, d])


def bundle(components: list[tuple[int, bytes]]) -> bytes:
    """Signature / key bundle -- SPEC.md section 3.5.

    count(1) | count x (scheme(1) | len(2 LE) | bytes)

    ``count = 0`` is legal and is what an unsigned or coinbase input carries.
    """
    if len(components) > BUNDLE_MAX_COMPONENTS and components:
        raise ValueError(f"bundle has {len(components)} components (max 4)")
    out = bytes([len(components)])
    seen: set[int] = set()
    for scheme, blob in components:
        if not 1 <= len(blob) <= BUNDLE_COMPONENT_MAX:
            raise ValueError(f"component length {len(blob)} outside 1..4096")
        if scheme in seen:
            raise ValueError(f"scheme {scheme} repeats within one bundle")
        seen.add(scheme)
        out += bytes([scheme]) + u16le(len(blob)) + blob
    return out


def tx_payload(
    inputs: list[tuple[bytes, int, list[tuple[int, bytes]], list[tuple[int, bytes]]]],
    outputs: list[tuple[int, bytes]],
    version: int = 1,
    tx_type: int = 0,
    lock_time: int = 0,
) -> bytes:
    """Transaction -- SPEC.md section 3.3.

    version(4 LE) | tx_type(1) | lock_time(8 LE) |
    input_count(4 LE)  | inputs  (64 | index(4 LE) | sigs | keys)
    output_count(4 LE) | outputs (value(8 LE) | address(20))
    """
    out = u32le(version) + bytes([tx_type]) + u64le(lock_time)
    out += u32le(len(inputs))
    for prev_hash, prev_index, sigs, keys in inputs:
        if len(prev_hash) != 64:
            raise ValueError("prevout hash must be 64 bytes")
        out += prev_hash + u32le(prev_index) + bundle(sigs) + bundle(keys)
    out += u32le(len(outputs))
    for value, address in outputs:
        if len(address) != 20:
            raise ValueError("address must be 20 bytes")
        out += u64le(value) + address
    return out


def checkpoint_payload(
    height: int, block_hash: bytes, network_id: bytes, epoch: int
) -> bytes:
    """CheckpointPayload -- SPEC.md section 14 / M5.

    height(8 LE) | block_hash(64) | id_len(4 LE) | network_id | epoch(8 LE)
    """
    if len(block_hash) != 64:
        raise ValueError("block_hash must be 64 bytes")
    return (
        u64le(height)
        + block_hash
        + u32le(len(network_id))
        + network_id
        + u64le(epoch)
    )


def checkpoint_payload_wire(
    payload: bytes,
    aggregate_sig: bytes,
    bitmap: bytes,
    signer_count: int,
    sidecar: list = [],
) -> bytes:
    """CHECKPOINT -- SPEC.md section 13.5, msg_type = 11.

    payload_len(4 LE) | payload | aggregate_sig(96) |
    bitmap_len(4 LE) | bitmap | signer_count(4 LE) |
    sidecar_count(4 LE) | sidecar_count x (signer_index(4 LE) | sig(3309))
    """
    if len(aggregate_sig) != 96:
        raise ValueError("aggregate_sig must be 96 bytes")
    wire = (
        u32le(len(payload))
        + payload
        + aggregate_sig
        + u32le(len(bitmap))
        + bitmap
        + u32le(signer_count)
        + u32le(len(sidecar))
    )
    for index, sig in sidecar:
        if len(sig) != 3309:
            raise ValueError("sidecar signatures must be 3309 bytes")
        wire += u32le(index) + sig
    return wire


# --- the values net_vectors.json pins -------------------------------------

TIP = bytes([0x5A]) * 64


def derived_items() -> dict[str, str]:
    mini = NETWORK_MAGIC["mini"]
    items: dict[str, str] = {}
    items["frame_inv_type7_len4"] = frame(mini, MSG_BLOCK, b"srct").hex()
    for net in ("mainnet", "mini"):
        items[f"version_{net}"] = version_payload(net, 42, TIP).hex()
    items["msg_verack"] = nonce_payload(0xDEAD).hex()
    items["msg_ping"] = nonce_payload(0xBEEF).hex()
    items["msg_pong"] = nonce_payload(0xFEED).hex()
    items["msg_inv"] = inv_payload(
        [(INV_TYPE_BLOCK, bytes([0x11]) * 64), (INV_TYPE_BLOCK, bytes([0x22]) * 64)]
    ).hex()
    items["msg_getdata"] = inv_payload([(INV_TYPE_BLOCK, bytes([0x33]) * 64)]).hex()
    items["msg_getblocks"] = getblocks_payload(
        [bytes([0x44]) * 64, bytes([0x55]) * 64], bytes([0x66]) * 64
    ).hex()
    items["msg_addr"] = addr_payload([(ipv4_mapped(127, 0, 0, 1), 8333)]).hex()
    # section 13.14: an unsigned transaction, so the payload follows from section
    # 3 prose alone -- both bundles are `count = 0` and no key material is needed.
    items["msg_inv_tx"] = inv_payload([(INV_TYPE_TX, bytes([0x99]) * 64)]).hex()
    items["msg_tx"] = tx_payload(
        inputs=[(bytes([0x77]) * 64, 1, [], [])],
        outputs=[(12_345, bytes([0x88]) * 20)],
    ).hex()
    # section 13.5 msg_type = 11 (M4). A structural certificate: the payload is
    # deterministic from the field table, and the aggregate/bitmap are fixed
    # byte patterns so a second encoder can rebuild the whole message without a
    # pairing library. Real BLS aggregation is pinned by the Rust M4 tests.
    cp_payload = checkpoint_payload(
        100, bytes([0x21]) * 64, NETWORK_ID["mini"], 10
    )
    items["msg_checkpoint"] = checkpoint_payload_wire(
        cp_payload, bytes([0x37]) * 96, bytes([0b0000_0111]), 3
    ).hex()
    return items


def derived_facts() -> dict[str, int]:
    mini = NETWORK_MAGIC["mini"]
    return {
        "version_mainnet_len": len(version_payload("mainnet", 42, TIP)),
        "version_mini_len": len(version_payload("mini", 42, TIP)),
        "verack_len": len(nonce_payload(0xDEAD)),
        "ping_len": len(nonce_payload(0xBEEF)),
        "pong_len": len(nonce_payload(0xFEED)),
        "inv_len": len(
            inv_payload([(INV_TYPE_BLOCK, bytes([0x11]) * 64), (INV_TYPE_BLOCK, bytes([0x22]) * 64)])
        ),
        "getdata_len": len(inv_payload([(INV_TYPE_BLOCK, bytes([0x33]) * 64)])),
        "getblocks_len": len(
            getblocks_payload([bytes([0x44]) * 64, bytes([0x55]) * 64], bytes([0x66]) * 64)
        ),
        "addr_len": len(addr_payload([(ipv4_mapped(127, 0, 0, 1), 8333)])),
        "inv_tx_len": len(inv_payload([(INV_TYPE_TX, bytes([0x99]) * 64)])),
        "tx_len": len(
            tx_payload(inputs=[(bytes([0x77]) * 64, 1, [], [])], outputs=[(12_345, bytes([0x88]) * 20)])
        ),
        "checkpoint_len": len(
            checkpoint_payload_wire(
                checkpoint_payload(100, bytes([0x21]) * 64, NETWORK_ID["mini"], 10),
                bytes([0x37]) * 96,
                bytes([0b0000_0111]),
                3,
            )
        ),
        "checkpoint_type_number": MSG_CHECKPOINT,
        "max_frame_payload": MAX_FRAME_BYTES,
        "max_inv_per_msg": MAX_INV_PER_MSG,
        "max_addr_per_msg": MAX_ADDR_PER_MSG,
        "max_locator_len": MAX_LOCATOR_LEN,
        "max_relay_in_flight": MAX_RELAY_IN_FLIGHT,
        "max_relay_pending": MAX_RELAY_PENDING,
        "max_relay_known": MAX_RELAY_KNOWN,
        "max_tx_inv_batch": MAX_TX_INV_BATCH,
        "tx_relay_per_peer_per_min": TX_RELAY_PER_PEER_PER_MIN,
        "tx_request_timeout_ms": TX_REQUEST_TIMEOUT_MS,
    }


# Chain-derived values: a second implementation cannot produce these without
# mining a real chain, so they are reported as skipped rather than passed over.
SKIPPED = {
    "block1": "a mined block -- needs the Rust puzzle, not a second encoder",
    "locator_N": "derived from a 200-block chain",
    "locator_len_200": "derived from a 200-block chain",
    "inv_from_genesis_first": "derived from a 200-block chain",
    "inv_from_genesis_len": "derived from a 200-block chain",
}


def crosscheck() -> int:
    if not VECTORS.exists():
        print(f"missing {VECTORS}\nregenerate with UPDATE_NET_VECTORS=1 cargo test -p srct-net")
        return 1
    doc = json.loads(VECTORS.read_text())
    pinned = {e["name"]: e["hex"] for e in doc["items"]}
    pinned_facts = {f["name"]: f["value"] for f in doc["facts"]}

    problems: list[str] = []
    checked = 0

    for name, want in derived_items().items():
        if name not in pinned:
            problems.append(f"{name}: pinned file has no such entry")
            continue
        if pinned[name] != want:
            problems.append(
                f"{name}:\n    rust   {pinned[name]}\n    python {want}"
            )
        else:
            checked += 1

    for name, want in derived_facts().items():
        if name not in pinned_facts:
            problems.append(f"fact {name}: pinned file has no such entry")
            continue
        if pinned_facts[name] != want:
            problems.append(f"fact {name}: rust {pinned_facts[name]} != python {want}")
        else:
            checked += 1

    # section 13.3: the two live profiles MUST differ in both discriminators.
    if NETWORK_MAGIC["mainnet"] == NETWORK_MAGIC["mini"]:
        problems.append("mainnet and mini share a network_magic (13.3)")
    if NETWORK_ID["mainnet"] == NETWORK_ID["mini"]:
        problems.append("mainnet and mini share a network_id (13.3)")
    if NETWORK_MAGIC["mainnet"] == bytes(4) or NETWORK_MAGIC["mini"] == bytes(4):
        problems.append("a profile declares an all-zero magic (13.3)")

    print(f"cross-checked {checked} wire-format values against the Rust vectors")
    print(f"skipped {len(SKIPPED)} chain-derived values (need a real node):")
    for name, why in sorted(SKIPPED.items()):
        if name in pinned or any(k.startswith(name.split("_")[0]) for k in pinned):
            print(f"    - {name}: {why}")

    if problems:
        print(f"\nFAILED ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nwire format agrees byte-for-byte with the Rust implementation")
    return 0


def show() -> None:
    for name, h in derived_items().items():
        print(f"{name:<24}{h}")
    print()
    for name, v in derived_facts().items():
        print(f"{name:<24}{v}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--show", action="store_true", help="print derived values and exit")
    args = ap.parse_args()
    if args.show:
        show()
        return 0
    return crosscheck()


if __name__ == "__main__":
    sys.exit(main())
