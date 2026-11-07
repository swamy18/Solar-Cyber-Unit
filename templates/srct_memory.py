#!/usr/bin/env python3
"""Decentralized agent memory: shared context without bloating L1.

Autonomous agents need memory — past interactions, context windows,
agreed facts. Storing it on the L1 UTXO chain is expensive and slow,
so this layer lives beside the chain, not on it:

- `append(store, agent_hex, context)` writes one hash-chained entry
  (`prev_hash -> entry_hash`); history cannot be rewritten, only
  extended — the same discipline as the node's audit log.
- `sync(store, peer_entries)` merges another agent's entries by hash
  (set union; order by entry hash). Two agents that exchange entries
  converge on the same memory without a server — CRDT in the only
  sense that matters here: merges commute, duplicates collapse.
- `verify(store)` re-checks the whole chain; a single edited byte
  anywhere breaks every later hash.
- `anchor(store)` returns the tip hash — the cryptographic summary of
  everything remembered so far. Agents attach it to task results and
  VWC attestations, so verifiers and the policy engine release funds
  against memory that is proven continuous, not merely claimed.

The L1 stays lean (hashes travel, megabytes do not); agents still get
their shared "global brain": real-time sync peer to peer, settlement
gated on the anchor.

Stdlib only: hashlib + json + time. No new dependencies.
"""

import hashlib
import json
import sys
import time

DOMAIN = "srct/memory/v1"


class SrctError(Exception):
    """Anything that stops the memory from verifying."""


def _hash(prev_hash_hex, agent_hex, context_hex, at):
    # Inputs arrive from untrusted stores and hostile peers: every decode
    # failure is a clean SrctError (merge refused / chain broken), never a
    # leaked ValueError/TypeError/OverflowError.
    try:
        prev_raw = bytes.fromhex(prev_hash_hex)
        agent_raw = agent_hex.encode("utf-8")
        context_raw = bytes.fromhex(context_hex)
        at_raw = at.to_bytes(8, "big")
    except (ValueError, TypeError, AttributeError, OverflowError) as e:
        raise SrctError(f"bad entry bytes: {e}")
    h = hashlib.sha256()
    h.update(DOMAIN.encode("utf-8"))
    h.update(prev_raw)
    h.update(agent_raw)
    h.update(context_raw)
    h.update(at_raw)
    return h.hexdigest()


def _load_store(store):
    try:
        with open(store, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {"entries": []}
    except (OSError, ValueError) as e:
        raise SrctError(f"store unreadable: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        raise SrctError("store malformed: expected {\"entries\": [...]}")
    return doc


def _save_store(store, doc):
    try:
        with open(store, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
    except OSError as e:
        raise SrctError(f"store unwritable: {e}")


def _now():
    return int(time.time())


def tip(doc_entries):
    """Tip hash: `00..00` for empty memory, else the last entry's hash."""
    if not doc_entries:
        return "00" * 32
    h = doc_entries[-1].get("entry_hash")
    if not isinstance(h, str) or not h:
        raise SrctError("tip entry malformed: store corrupt, verify it")
    return h


def append(store, agent_hex, context_hex):
    """Remember `context_hex` (arbitrary bytes, hex) as `agent_hex`.

    Returns the entry. The entry commits to the previous tip, so the
    log is append-only: editing history breaks the chain, and
    `verify` will say so.
    """
    try:
        bytes.fromhex(context_hex)
    except ValueError:
        raise SrctError("context_hex must be hex")
    if not agent_hex:
        raise SrctError("agent_hex must be non-empty")
    doc = _load_store(store)
    at = _now()
    entry = {
        "seq": len(doc["entries"]),
        "prev_hash": tip(doc["entries"]),
        "agent_hex": agent_hex,
        "context_hex": context_hex,
        "at": at,
    }
    entry["entry_hash"] = _hash(entry["prev_hash"], agent_hex,
                                context_hex, at)
    doc["entries"].append(entry)
    _save_store(store, doc)
    return entry


def verify(store):
    """Re-check every link. Returns `{"entries": N, "tip": ...}`.

    Raises `SrctError` naming the first broken sequence number —
    fail-closed, like every other check in this repo.
    """
    doc = _load_store(store)
    prev = "00" * 32
    for i, e in enumerate(doc["entries"]):
        for key in ("agent_hex", "context_hex", "at", "entry_hash",
                    "prev_hash", "seq"):
            if key not in e:
                raise SrctError(f"entry {i} missing {key!r}")
        if e["seq"] != i:
            raise SrctError(f"entry {i} mis-sequenced as {e['seq']}")
        if e["prev_hash"] != prev:
            raise SrctError(f"entry {i} forks the chain: "
                            f"prev {e['prev_hash'][:12]} != tip "
                            f"{prev[:12]}")
        want = _hash(e["prev_hash"], e["agent_hex"], e["context_hex"],
                     e["at"])
        if e["entry_hash"] != want:
            raise SrctError(f"entry {i} hash mismatch: content edited")
        prev = e["entry_hash"]
    return {"entries": len(doc["entries"]), "tip": prev}


def sync(store, peer_entries):
    """Merge a peer's entries by hash. Returns `(added, tip)`.

    Union semantics: entries we already hold (by `entry_hash`) are
    skipped; genuinely new entries that extend our tip are appended in
    peer order; entries that fork our history are refused, never
    interleaved. Two agents exchanging entries converge without a
    server. A fork means the peer rewrote history — treat it as
    hostile, re-verify the peer, do not merge.
    """
    if not isinstance(peer_entries, list):
        raise SrctError("peer_entries must be a list")
    doc = _load_store(store)
    known = {e.get("entry_hash") for e in doc["entries"]}
    cur_tip = tip(doc["entries"])
    added = 0
    for e in peer_entries:
        if not isinstance(e, dict):
            raise SrctError("peer entry must be an object; merge refused")
        h = e.get("entry_hash")
        if not h or h in known:
            continue
        if e.get("prev_hash") != cur_tip:
            raise SrctError(f"peer entry {h[:12]} forks our tip; "
                            "merge refused")
        want = _hash(e["prev_hash"], e.get("agent_hex", ""),
                     e.get("context_hex", ""), e.get("at", -1))
        if want != h:
            raise SrctError(f"peer entry {h[:12]} hash mismatch; "
                            "merge refused")
        e = dict(e)
        e["seq"] = len(doc["entries"])
        doc["entries"].append(e)
        known.add(h)
        cur_tip = h
        added += 1
    _save_store(store, doc)
    return {"added": added, "tip": cur_tip}


def anchor(store):
    """The tip hash to attach to task results and VWC attestations.

    Verifiers recompute continuity from the entries the agent also
    supplies; funds release against proven memory, not claimed memory.
    """
    return verify(store)["tip"]


def _selftest():
    """Offline self-test: two agents, one shared memory.

    Run:  python templates/srct_memory.py --selftest
    """
    import os
    import tempfile

    fd, a_store = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(a_store)
    fd, b_store = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(b_store)
    try:
        # Empty memory anchors to zero; verify passes on nothing.
        assert anchor(a_store) == "00" * 32
        assert verify(a_store) == {"entries": 0, "tip": "00" * 32}

        # Agent A remembers two facts; each entry chains the last.
        e1 = append(a_store, "aa", "beef")
        e2 = append(a_store, "aa", "cafe")
        assert e2["prev_hash"] == e1["entry_hash"], (e1, e2)
        assert e1["seq"] == 0 and e2["seq"] == 1
        assert anchor(a_store) == e2["entry_hash"]

        # Agent B syncs A's entries: same memory, no server.
        doc_a = _load_store(a_store)
        merged = sync(b_store, doc_a["entries"])
        assert merged == {"added": 2, "tip": e2["entry_hash"]}, merged
        assert anchor(b_store) == anchor(a_store)

        # Re-sync is a no-op: duplicates collapse by hash.
        assert sync(b_store, doc_a["entries"])["added"] == 0

        # B appends; A syncs B: both converge again.
        e3 = append(b_store, "bb", "f00d")
        sync(a_store, _load_store(b_store)["entries"])
        assert anchor(a_store) == anchor(b_store) == e3["entry_hash"]
        assert verify(a_store)["entries"] == 3

        # Editing history breaks verification at the edited entry.
        doc = _load_store(a_store)
        doc["entries"][1]["context_hex"] = "dead"
        _save_store(a_store, doc)
        try:
            verify(a_store)
            raise AssertionError("edited history must refuse")
        except SrctError as e:
            assert "entry 1" in str(e), e

        # Forking entries refuse the merge instead of interleaving.
        doc = _load_store(b_store)
        fork = dict(doc["entries"][0])
        fork["entry_hash"] = "ab" * 32
        fork["prev_hash"] = "00" * 32
        try:
            sync(a_store, [fork])
            raise AssertionError("forked merge must refuse")
        except SrctError:
            pass

        # Malformed peer bytes refuse cleanly (SrctError, never a leak).
        for bad in (["not-a-dict"],
                    [{"entry_hash": "zz", "prev_hash": "00" * 32,
                      "agent_hex": "aa", "context_hex": "not-hex!!",
                      "at": 1}],
                    [{"entry_hash": "zz", "prev_hash": "00" * 32,
                      "agent_hex": "aa", "context_hex": "beef",
                      "at": "yesterday"}]):
            try:
                sync(a_store, bad)
                raise AssertionError(f"malformed merge accepted: {bad}")
            except SrctError:
                pass

        # Bad inputs refuse at the door.
        for bad in (dict(agent_hex="", context_hex="beef"),
                    dict(agent_hex="aa", context_hex="not-hex!!")):
            try:
                append(a_store, **bad)
                raise AssertionError(f"bad append accepted: {bad}")
            except SrctError:
                pass
    finally:
        for path in (a_store, b_store):
            if os.path.exists(path):
                os.remove(path)
    print("srct_memory selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
