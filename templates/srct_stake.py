#!/usr/bin/env python3
"""Staking & yield tracker: lock tokens, strengthen the network, earn.

Two locking legs exist today, both enforced by consensus — this file tracks
them and projects yield without touching chain internals:

1. **Validator bonds** (`bond.rs`): stake locks in a bond output; the
   committee is always the 21 highest-staked bonds (TopN); unbonding takes
   1008 blocks; equivocation slashes the full bond into the vault. Locking
   stake is how operators strengthen consensus and shrink circulating
   supply. No tracker endpoint exists yet, so this file reports the
   consensus facts (`bond_facts()`) for operators planning a bond.

2. **Productive lending** (`lending.rs`): lenders publish signed offers
   (rate capped on chain at 10% per window, simple interest); borrowers
   post collateral + bond; interest accrues to the lender. This is the
   live yield leg: locked principal earns protocol-enforced interest.
   `best_offer_for(...)` + `position_summary(...)` project it;
   `dashboard(...)` reads live exposure from the node.

What this file does NOT do: invent protocol-revenue yield for stakers.
Fees pay the block producer and slash vesting feeds the PSCB reserve today;
redirecting a revenue leg to stakers is a monetary-policy decision that
needs a consensus change, not a template. When that decision lands, this
is where the tracker plugs in.

Stdlib only: urllib + json. No new dependencies.
"""

import json
import sys
import urllib.request

_OFFERS = "/v1/loans/offers"
_DASHBOARD = "/v1/lending/dashboard"
_AUTOREPAY = "/v1/lending/autorepay"

# Consensus facts, mirrored from crates/srct-core/src/bond.rs.
COMMITTEE_SIZE = 21
UNBONDING_PERIOD_BLOCKS = 1008
# Rate cap mirrored from lending.rs: 10% per window, simple interest.
MAX_RATE_BPS_PER_WINDOW = 1000
BPS = 10_000


class SrctError(Exception):
    """Anything that stops the tracker from answering."""


# -- transport (reads only; nothing here signs or locks) ----------------


def _http_get(node, path):
    import urllib.error
    req = urllib.request.Request(node.rstrip("/") + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 404, {}
        try:
            body = e.read().decode("utf-8")
            doc = json.loads(body) if body else {}
        except Exception:
            doc = {}
        return e.code, doc
    except Exception as e:
        raise SrctError(f"node unreachable for {path}: {e}")


# -- leg 1: validator bonds (consensus facts) ---------------------------


def bond_facts():
    """What locking stake as a validator bond buys, per consensus."""
    return {
        "committee": f"top {COMMITTEE_SIZE} bonds by stake (TopN)",
        "unbonding_blocks": UNBONDING_PERIOD_BLOCKS,
        "slash": "equivocation deletes the full bond into the slash vault",
        "min_bond_sat": "per-profile NetworkParams::min_bond_sat "
                        "(0 on mini/testnet)",
        "yield_today": "none from protocol revenue — bonds secure, "
                       "they do not yet earn; see module docstring",
    }


# -- leg 2: productive lending (live yield) ------------------------------


def live_offers(node, principal_sat=0):
    """Signed loan offers fitting `principal_sat`, cheapest rate first.

    Follows `next_cursor` until the registry is exhausted: picking the
    cheapest rate from a truncated first page would lock the operator
    into worse terms on a busy node.
    """
    offers = []
    cursor = None
    while True:
        path = _OFFERS + f"?principal={principal_sat}&limit=1000"
        if cursor is not None:
            path += f"&cursor={cursor}"
        status, body = _http_get(node, path)
        if status != 200:
            raise SrctError(f"node answered {status} for loan offers")
        offers.extend(body.get("offers", []))
        cursor = body.get("next_cursor")
        if cursor is None:
            break
    return offers


def best_offer_for(offers, principal_sat):
    """Cheapest rate among offers whose range covers `principal_sat`."""
    cands = [o for o in offers
             if o.get("min_principal_sat", 1) <= principal_sat
             <= o.get("max_principal_sat", 0)]
    if not cands:
        raise SrctError(f"no live offer covers {principal_sat} sat")
    return min(cands, key=lambda o: (o.get("rate_bps_per_window", 0),
                                     o.get("window_blocks", 0)))


def estimate_yield(principal_sat, rate_bps_per_window, windows):
    """Simple-interest projection under the 10%-per-window chain cap.

    Pure arithmetic — matches `accrued_interest` semantics: each window
    pays `principal * rate_bps / 10000`, no compounding.
    """
    if rate_bps_per_window > MAX_RATE_BPS_PER_WINDOW:
        raise SrctError(f"rate {rate_bps_per_window} bps over the "
                        f"{MAX_RATE_BPS_PER_WINDOW} bps chain cap")
    if principal_sat <= 0 or windows <= 0:
        raise SrctError("principal and windows must be > 0")
    per_window = principal_sat * rate_bps_per_window // BPS
    return {
        "principal_sat": principal_sat,
        "rate_bps_per_window": rate_bps_per_window,
        "windows": windows,
        "interest_per_window_sat": per_window,
        "total_interest_sat": per_window * windows,
        "total_return_sat": principal_sat + per_window * windows,
    }


def position_summary(node, principal_sat, windows):
    """One call: cheapest live offer + yield projection for `principal_sat`.

    Returns `{"offer": ..., "projection": ...}`. Refuses when nothing
    covers the principal — the operator waits for a fresh offer instead
    of locking into bad terms.
    """
    offer = best_offer_for(live_offers(node, principal_sat), principal_sat)
    return {
        "offer": offer,
        "projection": estimate_yield(principal_sat,
                                     offer["rate_bps_per_window"], windows),
    }


def dashboard(node):
    """Lender risk dashboard: exposure, due-soon, expected interest."""
    status, body = _http_get(node, _DASHBOARD)
    if status != 200:
        raise SrctError(f"node answered {status} for lending dashboard")
    return body


def autorepay_status(node, borrower_hex):
    """The borrower's live standing auto-repay instruction, if any."""
    status, body = _http_get(node, f"{_AUTOREPAY}/{borrower_hex}")
    if status == 404:
        return None
    if status != 200:
        raise SrctError(f"node answered {status} for autorepay status")
    return body


def _selftest():
    """Offline self-test: fake node books, real selection + arithmetic.

    Run:  python templates/srct_stake.py --selftest
    """
    mod = sys.modules[__name__]
    real_get = mod._http_get
    try:
        offers = [
            {"offer_id": "oo-cheap", "lender": "ll",
             "min_principal_sat": 100, "max_principal_sat": 10_000,
             "rate_bps_per_window": 200, "window_blocks": 144,
             "expires_height": 9000},
            {"offer_id": "oo-pricey", "lender": "ll",
             "min_principal_sat": 100, "max_principal_sat": 50_000,
             "rate_bps_per_window": 800, "window_blocks": 144,
             "expires_height": 9000},
        ]

        def fake_get(node, path):
            if path.startswith(_OFFERS):
                # Two pages: the cheapest offer sits on page 2, so only
                # cursor-following selection finds it.
                if "cursor=" in path:
                    return 200, {"count": 1, "total": 2,
                                 "truncated": False, "next_cursor": None,
                                 "offers": [offers[0]]}
                return 200, {"count": 1, "total": 2,
                             "truncated": True, "next_cursor": 1,
                             "offers": [offers[1]]}
            if path == _DASHBOARD:
                return 200, {"exposure_by_lender": {"ll": 5_000},
                             "due_soon": [], "expected_interest_sat": 100}
            if path.startswith(_AUTOREPAY):
                if path.endswith("/known"):
                    return 200, {"borrower": "known", "active": True}
                return 404, {}
            raise AssertionError(path)

        mod._http_get = fake_get

        facts = bond_facts()
        assert "21" in facts["committee"] and facts["unbonding_blocks"] == 1008, facts

        got = live_offers("http://fake", 5_000)
        assert len(got) == 2, got
        # Cheapest rate wins, not the biggest range.
        assert best_offer_for(got, 5_000)["offer_id"] == "oo-cheap", got
        try:
            best_offer_for(got, 99_000_000)
            raise AssertionError("uncovered principal must refuse")
        except SrctError:
            pass

        # 5,000 sat at 200 bps for 3 windows: 100/window, 300 total.
        proj = estimate_yield(5_000, 200, 3)
        assert proj["interest_per_window_sat"] == 100, proj
        assert proj["total_interest_sat"] == 300, proj
        assert proj["total_return_sat"] == 5_300, proj

        try:
            estimate_yield(5_000, 1001, 1)
            raise AssertionError("over-cap rate must refuse")
        except SrctError:
            pass

        summary = position_summary("http://fake", 5_000, 3)
        assert summary["offer"]["offer_id"] == "oo-cheap", summary
        assert summary["projection"]["total_interest_sat"] == 300, summary

        dash = dashboard("http://fake")
        assert dash["expected_interest_sat"] == 100, dash
        assert autorepay_status("http://fake", "known")["active"] is True
        assert autorepay_status("http://fake", "nobody") is None
    finally:
        mod._http_get = real_get
    print("srct_stake selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
