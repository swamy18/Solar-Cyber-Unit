#!/usr/bin/env python3
"""Frictionless SRCT funding over the ramp registry.

Non-crypto-native companies fund agent micro-payments without touching
chain internals: pick the cheapest live stable/fiat quote, open an intent,
and wait for the provider's out-of-band fill:

    from srct_fund import ensure_funded

    intent = ensure_funded(node="http://127.0.0.1:8080",
                           user_hex="<agent address>",
                           min_sat=1_000_000, asset="USDC")

Custody never touches this file or the node: the provider fills out of
band (bank transfer, stablecoin payment) and closes the intent with its own
signature. The node only records the signed trail
(quote -> intent -> filled/refunded), so a lying provider leaves signed
evidence. Two nodes can hold different registries — verify against your
own node. Full flow: `docs/ramps.md`.

Polling, not webhooks: the provider settles on its own schedule, so this
SDK waits on the registry trail (`GET /v1/ramp/intents`) until the intent
is `filled`, `refunded`, or the timeout expires.

Stdlib only: urllib + json + time. No new dependencies.
"""

import json
import os
import sys
import time
import urllib.request

_QUOTES = "/v1/ramp/quotes"
_INTENTS = "/v1/ramp/intents"
_INTENT = "/v1/ramp/intent"


class SrctError(Exception):
    """Anything that stops funding from completing."""


class SrctExpiredQuote(SrctError):
    """The picked quote expired between listing and intent; re-quote."""


# -- transport (no keys anywhere near here) -----------------------------


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


def _http_post(node, path, payload):
    import urllib.error
    req = urllib.request.Request(
        node.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
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


# -- registry reads ----------------------------------------------------


def live_quotes(node, direction="stable_to_srct", asset=None):
    """Live (unexpired) quotes for one direction, optionally one asset.

    Follows `next_cursor` until the registry is exhausted: picking the
    cheapest fee from a truncated first page would silently overpay on a
    busy node.
    """
    quotes = []
    cursor = None
    while True:
        path = _QUOTES + f"?direction={direction}&limit=1000"
        if cursor is not None:
            path += f"&cursor={cursor}"
        status, body = _http_get(node, path)
        if status != 200:
            raise SrctError(f"node answered {status} for ramp quotes")
        quotes.extend(body.get("quotes", []))
        cursor = body.get("next_cursor")
        if cursor is None:
            break
    if asset is not None:
        quotes = [q for q in quotes if q.get("asset") == asset]
    return quotes


def pick_quote(quotes, min_sat, asset=None):
    """Cheapest fee among quotes covering at least `min_sat`.

    Raises `SrctError` when nothing covers the target — the caller tops
    up through two smaller intents or waits for a fresh provider quote.
    """
    cands = [q for q in quotes
             if q.get("sat_amount", 0) >= min_sat
             and (asset is None or q.get("asset") == asset)]
    if not cands:
        raise SrctError(f"no live quote covers {min_sat} sat"
                        + (f" in {asset}" if asset else ""))
    return min(cands, key=lambda q: (q.get("fee_sat", 0),
                                     q.get("sat_amount", 0)))


def open_intent(node, quote_id, user_hex, fill_ref):
    """Accept a live quote. Returns the intent id (existing or new)."""
    status, body = _http_post(node, _INTENT, {
        "quote_id": quote_id,
        "user_hex": user_hex,
        "fill_ref": fill_ref,
    })
    detail = str(body.get("detail", ""))
    if status == 409 and "expired" in detail:
        raise SrctExpiredQuote("quote expired before the intent landed")
    if status != 200:
        raise SrctError(f"node answered {status} for ramp intent: "
                        f"{body.get('detail', body)}")
    return body["intent_id"]


def intent_status(node, intent_id):
    """Current registry state for one intent. Raises if unknown.

    Follows `next_cursor` until the registry is exhausted: stopping at
    the first page would misreport a live intent as missing on a busy
    node.
    """
    cursor = None
    while True:
        path = _INTENTS + "?limit=1000"
        if cursor is not None:
            path += f"&cursor={cursor}"
        status, body = _http_get(node, path)
        if status != 200:
            raise SrctError(f"node answered {status} for ramp intents")
        for intent in body.get("intents", []):
            if intent.get("intent_id") == intent_id:
                return intent
        cursor = body.get("next_cursor")
        if cursor is None:
            break
    raise SrctError(f"intent {intent_id[:12]} not on this node; "
                    "verify against your own node")


def wait_settled(node, intent_id, poll_secs=5, timeout_secs=600):
    """Wait until the provider fills or refunds. Returns the intent dict.

    `filled=True` means the provider closed the intent with its own
    signature — the SRCT side is funded. `refunded=True` raises: the
    money never moved, re-quote instead of retrying a dead intent.
    """
    deadline = time.time() + timeout_secs
    while True:
        intent = intent_status(node, intent_id)
        if intent.get("filled"):
            return intent
        if intent.get("refunded"):
            raise SrctError(f"intent {intent_id[:12]} refunded by provider; "
                            "re-quote instead of retrying")
        if time.time() >= deadline:
            raise SrctError(f"intent {intent_id[:12]} unsettled after "
                            f"{timeout_secs}s; the provider has not filled yet")
        time.sleep(poll_secs)


def ensure_funded(node, user_hex, min_sat, asset="USDC",
                  direction="stable_to_srct", fill_ref=None,
                  poll_secs=5, timeout_secs=600):
    """One call: cheapest live quote -> intent -> wait for the fill.

    Returns the settled intent dict. `fill_ref` defaults to a timestamped
    reference with 64 random bits, which the operator matches against the
    provider's out-of-band receipt (bank reference, stablecoin tx hash).
    Uniqueness matters, not just readability: intent ids bind
    (quote, user, provider, fill_ref), and anyone can pre-squat a
    guessable reference on the open registry — randomness makes the
    squat miss. A quote that expires between listing and intent is
    re-quoted once automatically — the retry lists fresh quotes and
    skips the dead one, so no intent is ever opened twice for the same
    fill.
    """
    ref = fill_ref or f"srct-fund-{int(time.time())}-{os.urandom(8).hex()}"
    dead = set()
    for _ in range(2):
        quotes = [q for q in live_quotes(node, direction=direction,
                                         asset=asset)
                  if q.get("quote_id") not in dead]
        quote = pick_quote(quotes, min_sat, asset=asset)
        try:
            intent_id = open_intent(node, quote["quote_id"], user_hex, ref)
        except SrctExpiredQuote:
            dead.add(quote["quote_id"])
            continue
        return wait_settled(node, intent_id, poll_secs=poll_secs,
                            timeout_secs=timeout_secs)
    raise SrctError("two quotes expired in a row; the provider feed is "
                    "moving faster than intents land — retry shortly")


def _selftest():
    """Offline self-test: fake node registry, real selection + polling.

    Run:  python templates/srct_fund.py --selftest
    """
    mod = sys.modules[__name__]
    real_get, real_post = mod._http_get, mod._http_post
    try:
        quotes = [
            {"quote_id": "qq-cheap", "provider": "pp", "asset": "USDC",
             "asset_minor": 100, "sat_amount": 2_000_000, "fee_sat": 500,
             "expires_height": 9000},
            {"quote_id": "qq-pricey", "provider": "pp", "asset": "USDC",
             "asset_minor": 100, "sat_amount": 5_000_000, "fee_sat": 9000,
             "expires_height": 9000},
            {"quote_id": "qq-small", "provider": "pp", "asset": "USDC",
             "asset_minor": 100, "sat_amount": 100, "fee_sat": 1,
             "expires_height": 9000},
        ]
        state = {"posted": [], "polls": 0, "refund": False,
                 "expire_first": False}

        def fake_get(node, path):
            if path.startswith(_QUOTES):
                # Two pages: cursor paging must be followed, and the
                # cheapest quote sits on page 2.
                if "cursor=" in path:
                    return 200, {"count": 1, "total": 3,
                                 "truncated": False, "next_cursor": None,
                                 "quotes": [quotes[2]]}
                return 200, {"count": 2, "total": 3,
                             "truncated": True, "next_cursor": 2,
                             "quotes": [quotes[0], quotes[1]]}
            if path.startswith(_INTENTS):
                state["polls"] += 1
                if state["refund"]:
                    return 200, {"next_cursor": None, "intents": [{
                        "intent_id": "ii-1", "quote_id": "qq-cheap",
                        "user": "uu", "provider": "pp", "fill_ref": "r",
                        "filled": False, "refunded": True}]}
                filled = state["polls"] >= 2
                return 200, {"next_cursor": None, "intents": [{
                    "intent_id": "ii-1", "quote_id": "qq-cheap",
                    "user": "uu", "provider": "pp", "fill_ref": "r",
                    "filled": filled, "refunded": False}]}
            raise AssertionError(path)

        def fake_post(node, path, payload):
            assert path == _INTENT, path
            state["posted"].append(payload)
            if state["expire_first"]:
                state["expire_first"] = False
                # Real node envelope: {"error": ..., "detail": ...}.
                return 409, {"error": "ramp_refused",
                             "detail": "quote expired"}
            return 200, {"intent_id": "ii-1", "duplicate": False}

        mod._http_get, mod._http_post = fake_get, fake_post

        # Pages followed: all 3 quotes seen though page 1 held 2.
        got = live_quotes("http://fake", asset="USDC")
        assert len(got) == 3, got
        # Cheapest fee among quotes covering the target — not the biggest.
        assert pick_quote(got, 1_000_000)["quote_id"] == "qq-cheap", got
        try:
            pick_quote(got, 99_000_000)
            raise AssertionError("uncovered target must refuse")
        except SrctError:
            pass
        assert open_intent("http://fake", "qq-cheap", "uu", "r") == "ii-1"
        assert state["posted"][0]["fill_ref"] == "r", state["posted"]
        settled = wait_settled("http://fake", "ii-1", poll_secs=0,
                               timeout_secs=30)
        assert settled["filled"] and state["polls"] >= 2, settled

        # Expired quote between list and intent: re-quoted once, same
        # fill_ref, exactly one intent opened per quote.
        state["expire_first"] = True
        state["polls"] = 0
        before = len(state["posted"])
        settled = ensure_funded("http://fake", "uu", 1_000_000,
                                poll_secs=0, timeout_secs=30)
        assert settled["filled"], settled
        fresh_posts = state["posted"][before:]
        assert len(fresh_posts) == 2, fresh_posts
        assert fresh_posts[0]["quote_id"] != fresh_posts[1]["quote_id"], \
            "retry must skip the dead quote"
        assert fresh_posts[0]["fill_ref"] == fresh_posts[1]["fill_ref"], \
            "retry keeps the operator's reference"

        # Refunded intents refuse instead of hanging.
        state["polls"] = 0
        state["refund"] = True
        try:
            wait_settled("http://fake", "ii-1", poll_secs=0, timeout_secs=30)
            raise AssertionError("refunded intent must refuse")
        except SrctError as e:
            assert "refunded" in str(e), e

        # Unknown intents refuse with a clear message.
        state["refund"] = False
        try:
            intent_status("http://fake", "no-such-intent")
            raise AssertionError("unknown intent must refuse")
        except SrctError as e:
            assert "not on this node" in str(e), e

        # Timeout instead of hanging forever.
        state["polls"] = -10_000  # never reaches the fill threshold
        try:
            wait_settled("http://fake", "ii-1", poll_secs=0, timeout_secs=0)
            raise AssertionError("stale intent must time out")
        except SrctError as e:
            assert "unsettled" in str(e), e
    finally:
        mod._http_get, mod._http_post = real_get, real_post
    print("srct_fund selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
