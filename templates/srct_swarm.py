#!/usr/bin/env python3
"""Agentic swarm consensus: dynamic multi-agent approval, no static multisig.

Static multisigs (M-of-N human addresses) assume the signer set never
changes. AI swarms are dynamic — agents spawn for a micro-task and
terminate when it completes — so the approval set must be assembled per
decision, not per wallet. A swarm round does that:

    from srct_swarm import open_round, vote, authorize

    rid = open_round(store="swarm.json", tx_hash="<hex>",
                     required_roles=("auditor", "budget", "compliance"))
    vote(store, rid, role="auditor", agent_hex="...",
         decision="approve", reason="code reviewed, no exfil")
    vote(store, rid, role="budget", agent_hex="...",
         decision="approve", reason="under 400 sat policy cap")
    vote(store, rid, role="compliance", agent_hex="...",
         decision="approve", reason="recipient allow-listed")
    authorize(store, rid)   # {"go": True, ...} — spend may proceed

Rules, fail-closed throughout:

- Every required role must approve at least once; one agent fills one
  role, never two (Sybil-by-hat-switching is refused).
- Any `deny` from a required role blocks the round — a single
  independent objection stops the spend.
- Rounds are ephemeral: `ttl_hours` expiry, and a decided round never
  re-opens. The store is a local JSON trail of what was asked, who
  answered, and what was decided.

Honest boundary: this gates the *template-driven* spend — the operator
only invokes `srct-worker pay` / releases the `GuardApproval` after
`authorize()` says go. On-chain N-of-M enforcement would need a
consensus change (`GuardApproval` names one designated approver today),
so a round's votes are audit evidence, not chain proof. `sig_hex` on a
vote carries the verifier's own signature for that trail.

Stdlib only: hashlib + json + time. No new dependencies.
"""

import hashlib
import json
import sys
import time

APPROVE = "approve"
DENY = "deny"


class SrctError(Exception):
    """Anything that stops the round from progressing."""


def _now():
    return int(time.time())


def _load_store(store):
    try:
        with open(store, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {"rounds": []}
    except (OSError, ValueError) as e:
        raise SrctError(f"store unreadable: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("rounds"), list):
        raise SrctError("store malformed: expected {\"rounds\": [...]}")
    return doc


def _save_store(store, doc):
    try:
        with open(store, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
    except OSError as e:
        raise SrctError(f"store unwritable: {e}")


def _get_round(doc, round_id):
    for r in doc["rounds"]:
        if r.get("round_id") == round_id:
            return r
    raise SrctError(f"round {round_id[:12]} unknown in this store")


def open_round(store, tx_hash, required_roles=("auditor", "budget",
                                               "compliance"), ttl_hours=24,
               note=""):
    """Open an ephemeral voting round for one high-value transaction."""
    roles = list(dict.fromkeys(required_roles))
    if len(roles) < 2:
        raise SrctError("swarm needs at least 2 distinct required roles")
    if not roles or any(not isinstance(r, str) or not r for r in roles):
        raise SrctError("roles must be non-empty strings")
    if ttl_hours <= 0:
        raise SrctError("ttl_hours must be > 0")
    now = _now()
    doc = _load_store(store)
    taken = {r.get("round_id") for r in doc["rounds"]}
    salt = 0
    while True:
        seed = f"{tx_hash}|{'/'.join(roles)}|{now}|{salt}".encode("utf-8")
        round_id = hashlib.sha256(seed).hexdigest()[:32]
        if round_id not in taken:
            break
        salt += 1
    rnd = {
        "round_id": round_id,
        "tx_hash": tx_hash,
        "required_roles": roles,
        "votes": [],
        "note": note or "",
        "opened_at": now,
        "expires_at": now + int(ttl_hours * 3600),
        "decided": None,
    }
    doc["rounds"].append(rnd)
    _save_store(store, doc)
    return round_id


def vote(store, round_id, role, agent_hex, decision, reason="",
         sig_hex=""):
    """Cast one verifier's vote. Returns the updated tally."""
    if decision not in (APPROVE, DENY):
        raise SrctError(f"decision must be {APPROVE!r} or {DENY!r}")
    doc = _load_store(store)
    rnd = _get_round(doc, round_id)
    now = _now()
    if rnd.get("decided") is not None:
        raise SrctError("round already decided; open a fresh round")
    if now >= rnd["expires_at"]:
        raise SrctError("round expired; open a fresh round")
    if role not in rnd["required_roles"]:
        raise SrctError(f"role {role!r} not required by this round")
    agents = {v.get("agent_hex") for v in rnd["votes"]}
    if agent_hex in agents:
        raise SrctError("one agent fills one role: already voted")
    roles = {v.get("role") for v in rnd["votes"]}
    if role in roles:
        raise SrctError(f"role {role!r} already has its vote")
    rnd["votes"].append({
        "role": role,
        "agent_hex": agent_hex,
        "decision": decision,
        "reason": reason or "",
        "sig_hex": sig_hex or "",
        "at": now,
    })
    _save_store(store, doc)
    return tally(store, round_id)


def tally(store, round_id):
    """Current standing: per-role decisions plus what is still missing."""
    doc = _load_store(store)
    rnd = _get_round(doc, round_id)
    by_role = {v["role"]: v["decision"] for v in rnd["votes"]}
    missing = [r for r in rnd["required_roles"] if r not in by_role]
    denied = sorted(r for r, d in by_role.items() if d == DENY)
    return {
        "round_id": round_id,
        "tx_hash": rnd["tx_hash"],
        "by_role": by_role,
        "missing": missing,
        "denied": denied,
        "expired": _now() >= rnd["expires_at"],
        "decided": rnd.get("decided"),
    }


def authorize(store, round_id):
    """Go/no-go for the spend. Locks the decision into the round.

    `{"go": True}` only when every required role approved, none denied,
    and the round is live. Anything else is `{"go": False, reason}` —
    and a go/no-go, once written, is final for that round.
    """
    doc = _load_store(store)
    rnd = _get_round(doc, round_id)
    if rnd.get("decided") is not None:
        decided = rnd["decided"]
        return {"go": decided == "go", "round_id": round_id,
                "reason": "already decided: " + decided}
    t = tally(store, round_id)
    if t["expired"]:
        rnd["decided"] = "no-go (expired)"
        _save_store(store, doc)
        return {"go": False, "round_id": round_id, "reason": "round expired"}
    if t["denied"]:
        rnd["decided"] = "no-go (denied by: %s)" % ", ".join(t["denied"])
        _save_store(store, doc)
        return {"go": False, "round_id": round_id,
                "reason": rnd["decided"], "denied": t["denied"]}
    if t["missing"]:
        return {"go": False, "round_id": round_id,
                "reason": "waiting for roles: " + ", ".join(t["missing"]),
                "missing": t["missing"]}
    rnd["decided"] = "go"
    _save_store(store, doc)
    return {"go": True, "round_id": round_id, "tx_hash": rnd["tx_hash"]}


def _selftest():
    """Offline self-test: temp store, real round rules.

    Run:  python templates/srct_swarm.py --selftest
    """
    import os
    import tempfile

    fd, store = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(store)
    try:
        # A single role is not a swarm.
        try:
            open_round(store, "tx", required_roles=("auditor",))
            raise AssertionError("single role must refuse")
        except SrctError:
            pass

        rid = open_round(store, "tx-1", note="pay worker")
        assert tally(store, rid)["missing"] == ["auditor", "budget",
                                               "compliance"], rid

        vote(store, rid, "auditor", "aa", APPROVE, reason="clean")
        t = vote(store, rid, "budget", "bb", APPROVE, reason="under cap")
        assert t["missing"] == ["compliance"], t

        # Waiting is not a go.
        pending = authorize(store, rid)
        assert pending == {"go": False, "round_id": rid,
                           "reason": "waiting for roles: compliance",
                           "missing": ["compliance"]}, pending

        # Same agent cannot wear two hats.
        try:
            vote(store, rid, "compliance", "aa", APPROVE)
            raise AssertionError("double vote must refuse")
        except SrctError as e:
            assert "one role" in str(e), e

        # Filled role cannot vote twice.
        try:
            vote(store, rid, "auditor", "cc", APPROVE)
            raise AssertionError("second vote for role must refuse")
        except SrctError:
            pass

        # Full approval: go, and the decision locks.
        vote(store, rid, "compliance", "cc", APPROVE, reason="allow-listed")
        go = authorize(store, rid)
        assert go == {"go": True, "round_id": rid, "tx_hash": "tx-1"}, go
        again = authorize(store, rid)
        assert again["go"] is True and "already decided" in again["reason"], again
        try:
            vote(store, rid, "compliance", "dd", APPROVE)
            raise AssertionError("vote after decision must refuse")
        except SrctError:
            pass

        # One deny blocks the whole round.
        rid2 = open_round(store, "tx-2")
        vote(store, rid2, "auditor", "aa", APPROVE)
        vote(store, rid2, "budget", "bb", DENY, reason="over cap")
        no = authorize(store, rid2)
        assert no["go"] is False and no["denied"] == ["budget"], no
        # Missing role after a deny still reports the deny, not the wait.
        assert "denied by" in no["reason"], no

        # Bad decisions and unknown roles refuse at the door.
        rid3 = open_round(store, "tx-3")
        for kw in (dict(role="janitor", agent_hex="zz", decision=APPROVE),
                   dict(role="auditor", agent_hex="zz", decision="maybe")):
            try:
                vote(store, rid3, **kw)
                raise AssertionError(f"bad vote accepted: {kw}")
            except SrctError:
                pass
    finally:
        if os.path.exists(store):
            os.remove(store)
    print("srct_swarm selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
