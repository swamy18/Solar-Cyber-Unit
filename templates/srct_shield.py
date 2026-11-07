#!/usr/bin/env python3
"""Agent Shield: sub-agents never die mid-workflow at 0 SRCT.

In Web3 a drained wallet just fails its transaction and the workflow
breaks. In a cross-agent system a critical agent going insolvent
mid-workflow crashes everything downstream. The Shield is liquidity
self-healing in two halves:

1. **Credit delegation lines (live today).** A parent registers a line
   for its sub-agent anchored to its own on-chain `LoanOffer`
   (`register_line` checks the offer's principal range covers the cap).
   When the sub-agent's spendable balance drops under the floor, `check`
   trips and returns the exact `POST /v1/loans/accept` payload — terms
   from the parent's signed offer, borrower fields filled, signatures
   left for the sub-agent's own key (keys never enter Python). The loan
   funds the active task; the task's earnings repay it, optionally via a
   standing auto-repay instruction.

2. **PSCB-backed emergency micro-loans (NOT live).** The fallback pool
   half needs a consensus change — who may draw, per-draw caps, and how
   repayment is enforced are chain-state rules, not a template. `check`
   reports `fallback: {"available": False, ...}` openly instead of
   pretending. When that decision lands, it plugs in here.

Every trip is appended to the board's `trips` trail — the audit of who
ran dry, when, and what rescued them.

Stdlib only: urllib + json + time. No new dependencies.
"""

import json
import sys
import time
import urllib.request

_BALANCE = "/v1/balance"
_OFFERS = "/v1/loans/offers"
_ACCEPT_PATH = "/v1/loans/accept"


class SrctError(Exception):
    """Anything that stops the Shield from answering."""


# -- transport (reads only; signatures are the signatory's business) ----


def _http_get(node, path):
    import urllib.error
    req = urllib.request.Request(node.rstrip("/") + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8")
            doc = json.loads(body) if body else {}
        except Exception:
            doc = {}
        return e.code, doc
    except Exception as e:
        raise SrctError(f"node unreachable for {path}: {e}")


# -- board --------------------------------------------------------------


def _load_board(board):
    try:
        with open(board, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {"lines": [], "trips": []}
    except (OSError, ValueError) as e:
        raise SrctError(f"board unreadable: {e}")
    if not isinstance(doc, dict):
        raise SrctError("board malformed: expected an object")
    doc.setdefault("lines", [])
    doc.setdefault("trips", [])
    return doc


def _save_board(board, doc):
    try:
        with open(board, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
    except OSError as e:
        raise SrctError(f"board unwritable: {e}")


def _now():
    return int(time.time())


# -- half 1: credit delegation lines ------------------------------------


def register_line(board, parent_hex, sub_agent_hex, offer_id, cap_sat,
                  ttl_hours=720, node=None):
    """Register a parent's credit line for its sub-agent.

    Anchored to the parent's on-chain `LoanOffer`: when `node` is given,
    the offer is fetched and the cap must fit its principal range, so the
    line cannot promise what the offer cannot lend. Without `node` the
    line stores `"verified": False` — usable for planning, never trusted
    for execution.
    """
    if cap_sat <= 0:
        raise SrctError("cap_sat must be > 0")
    if ttl_hours <= 0:
        raise SrctError("ttl_hours must be > 0")
    verified = False
    if node is not None:
        status, body = _http_get(node, _OFFERS + "?principal=0&limit=1000")
        if status != 200:
            raise SrctError(f"node answered {status} for loan offers")
        offers = {o.get("offer_id"): o for o in body.get("offers", [])}
        offer = offers.get(offer_id)
        if offer is None:
            raise SrctError(f"offer {offer_id[:12]} not live on this node")
        if not (offer.get("min_principal_sat", 1) <= cap_sat
                <= offer.get("max_principal_sat", 0)):
            raise SrctError(f"cap {cap_sat} outside offer range "
                            f"[{offer.get('min_principal_sat')}, "
                            f"{offer.get('max_principal_sat')}]")
        verified = True
    now = _now()
    line = {
        "parent": parent_hex,
        "sub_agent": sub_agent_hex,
        "offer_id": offer_id,
        "cap_sat": cap_sat,
        "registered_at": now,
        "expires_at": now + int(ttl_hours * 3600),
        "verified": verified,
    }
    doc = _load_board(board)
    doc["lines"].append(line)
    _save_board(board, doc)
    return line


def _live_lines(doc, sub_agent_hex, now):
    return [l for l in doc["lines"]
            if l.get("sub_agent") == sub_agent_hex
            and l.get("expires_at", 0) > now]


def spendable_sat(node, address_hex):
    """Spendable (mature, unspent) balance for one address."""
    status, body = _http_get(node, f"{_BALANCE}/{address_hex}")
    if status != 200:
        raise SrctError(f"node answered {status} for balance")
    return int(body.get("spendable_sat", 0))


def check(node, board, sub_agent_hex, floor_sat, need_sat,
          deadline_height):
    """Tripwire: `{"ok": True}` while funded, rescue plan at 0.

    When `spendable_sat < floor_sat`, returns `{"ok": False, ...}` with
    the first live covering line rendered as an accept payload (terms
    from the parent's signed offer; `borrower_sigs_hex` /
    `borrower_keys_hex` left empty for the sub-agent's own key), plus a
    standing-repay hint and `fallback: {"available": False}` — the
    PSCB-backed emergency-loan half, honestly marked as needing a
    consensus change. The trip is appended to the board trail.
    """
    balance = spendable_sat(node, sub_agent_hex)
    if balance >= floor_sat:
        return {"ok": True, "spendable_sat": balance, "floor_sat": floor_sat}
    doc = _load_board(board)
    now = _now()
    lines = [l for l in _live_lines(doc, sub_agent_hex, now)
             if l.get("verified") and l.get("cap_sat", 0) >= need_sat]
    trip = {
        "at": now,
        "sub_agent": sub_agent_hex,
        "spendable_sat": balance,
        "floor_sat": floor_sat,
        "need_sat": need_sat,
        "rescued_by": None,
        "fallback": {
            "available": False,
            "reason": "PSCB-backed emergency micro-loans need a "
                      "consensus change (who may draw, per-draw caps, "
                      "repayment enforcement); not faked here",
        },
    }
    if lines:
        line = min(lines, key=lambda l: l.get("cap_sat", 0))
        trip["rescued_by"] = {
            "parent": line["parent"],
            "offer_id": line["offer_id"],
            "accept_payload": {
                "offer_id": line["offer_id"],
                "borrower_hex": sub_agent_hex,
                "bond_sat": 0,
                "amount_sat": need_sat,
                "deadline_height": deadline_height,
                "borrower_sigs_hex": "",
                "borrower_keys_hex": "",
                "_note": "terms come from the parent's signed offer; "
                         "the sub-agent signs with its own key",
            },
            "repay_hint": "fund the active task, settle it, repay from "
                          "earnings (or register POST "
                          "/v1/lending/autorepay for standing repay)",
        }
    doc["trips"].append(trip)
    _save_board(board, doc)
    out = {"ok": False, "spendable_sat": balance, "floor_sat": floor_sat,
           "need_sat": need_sat}
    out.update(trip)
    del out["at"]
    return out


def _selftest():
    """Offline self-test: fake node + temp board, real trip logic.

    Run:  python templates/srct_shield.py --selftest
    """
    import os
    import tempfile

    mod = sys.modules[__name__]
    real_get = mod._http_get
    try:
        balances = {"sub-broke": 0, "sub-rich": 10_000}
        offers = [{"offer_id": "oo-parent", "lender": "pp",
                   "min_principal_sat": 100, "max_principal_sat": 50_000,
                   "rate_bps_per_window": 200, "window_blocks": 144,
                   "expires_height": 9000}]

        def fake_get(node, path):
            if path.startswith(_BALANCE + "/"):
                addr = path.rsplit("/", 1)[1]
                return 200, {"address": addr,
                             "confirmed_sat": balances.get(addr, 0),
                             "spendable_sat": balances.get(addr, 0),
                             "pending_sat": 0, "next_height": 10}
            if path.startswith(_OFFERS):
                return 200, {"offers": list(offers)}
            raise AssertionError(path)

        mod._http_get = fake_get

        fd, board = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(board)
        try:
            # Funded agent: no trip, no trail written.
            ok = check("http://fake", board, "sub-rich", 1_000, 5_000, 9000)
            assert ok == {"ok": True, "spendable_sat": 10_000,
                          "floor_sat": 1_000}, ok

            # Broke agent, no line: trip with honest fallback=False.
            trip = check("http://fake", board, "sub-broke", 1_000, 5_000, 9000)
            assert trip["ok"] is False, trip
            assert trip["rescued_by"] is None, trip
            assert trip["fallback"]["available"] is False, trip

            # Register the parent's line (verified against the offer)...
            line = register_line(board, "pp", "sub-broke", "oo-parent",
                                 20_000, ttl_hours=72, node="http://fake")
            assert line["verified"] is True, line
            # ...and the trip now carries the accept payload.
            trip = check("http://fake", board, "sub-broke", 1_000, 5_000, 9000)
            plan = trip["rescued_by"]
            assert plan["parent"] == "pp", plan
            payload = plan["accept_payload"]
            assert payload["offer_id"] == "oo-parent", payload
            assert payload["borrower_hex"] == "sub-broke", payload
            assert payload["amount_sat"] == 5_000, payload
            assert payload["deadline_height"] == 9000, payload

            # Cap below need: line exists but cannot cover — no rescue.
            trip = check("http://fake", board, "sub-broke", 1_000, 40_000, 9000)
            assert trip["rescued_by"] is None, trip

            # Unknown offer refuses at registration, not at trip time.
            try:
                register_line(board, "pp", "sub-broke", "no-such-offer",
                              1_000, node="http://fake")
                raise AssertionError("unknown offer must refuse")
            except SrctError:
                pass

            # Cap outside the offer range refuses too.
            try:
                register_line(board, "pp", "sub-broke", "oo-parent",
                              99_000_000, node="http://fake")
                raise AssertionError("over-range cap must refuse")
            except SrctError:
                pass

            # Trail recorded both trips.
            trail = _load_board(board)["trips"]
            assert len(trail) == 3, trail
        finally:
            if os.path.exists(board):
                os.remove(board)
    finally:
        mod._http_get = real_get
    print("srct_shield selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
