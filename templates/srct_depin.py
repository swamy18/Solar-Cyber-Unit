#!/usr/bin/env python3
"""DePIN capacity board: surplus compute earns SRCT.

Crypto coins usually run on speculation. This board gives SRCT real demand
one advertisement at a time: any machine — datacenter GPU, home CPU, NPU
box, or a solar-powered edge device — publishes what it can spare, at what
price, and consumers discover it and pay for it through the L2 task economy
(`payment_sat` locked on chain until the work settles or expires).

The board itself is a local JSON registry — discovery commits nothing, and
custody never touches this file. Money moves only through L2 tasks and
their verified-work certificates, which the chain already settles
trustlessly (dispute -> committee verdict -> slash):

    from srct_depin import advertise, discover, match

    advertise(board="depin.json", provider_hex="<addr>", device="solar-edge",
              compute_units=8, unit="gpu-hour", price_sat_per_unit=500,
              endpoint="http://edge-1:8080", renewable=True, ttl_hours=72)
    offers = discover(board="depin.json", unit="gpu-hour", min_units=4,
                      max_price_sat=600, renewable_only=True)
    job = match(board="depin.json", unit="gpu-hour", min_units=4,
                max_price_sat=600)   # cheapest fitting offer + task shape

Offer fields are metadata — the chain verifies delivered work, not the
advertisement. An offer that cannot deliver simply never earns: no
certificate, no payment.

Stdlib only: json + time. No new dependencies.
"""

import json
import sys
import time

# Device classes the board understands. `solar-edge` is a power story, not
# a chip story: a low-draw device on renewable power. The chain does not
# verify the power source — the price does the talking.
DEVICES = ("gpu", "cpu", "npu", "tpu", "edge", "solar-edge", "fpga", "asic")


class SrctError(Exception):
    """Anything that stops the board from making progress."""


def _now():
    return int(time.time())


def _load_board(board):
    try:
        with open(board, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {"offers": []}
    except (OSError, ValueError) as e:
        raise SrctError(f"board unreadable: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("offers"), list):
        raise SrctError("board malformed: expected {\"offers\": [...]}")
    return doc


def _save_board(board, doc):
    try:
        with open(board, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
    except OSError as e:
        raise SrctError(f"board unwritable: {e}")


def _live(offers, now):
    return [o for o in offers if o.get("expires_at", 0) > now]


def advertise(board, provider_hex, device, compute_units, unit,
              price_sat_per_unit, endpoint=None, renewable=False,
              ttl_hours=72, note=""):
    """Publish surplus compute. Returns the offer dict that was stored.

    `compute_units` is what the provider can spare right now (e.g. 8
    gpu-hours); `price_sat_per_unit` is the ask. Expired offers are
    ignored by `discover`, never deleted — the trail is the audit.
    """
    if device not in DEVICES:
        raise SrctError(f"unknown device {device!r}; one of {DEVICES}")
    if compute_units <= 0:
        raise SrctError("compute_units must be > 0")
    if price_sat_per_unit < 0:
        raise SrctError("price_sat_per_unit must be >= 0")
    if ttl_hours <= 0:
        raise SrctError("ttl_hours must be > 0")
    now = _now()
    offer = {
        "provider": provider_hex,
        "device": device,
        "compute_units": compute_units,
        "unit": unit,
        "price_sat_per_unit": price_sat_per_unit,
        "endpoint": endpoint or "",
        "renewable": bool(renewable),
        "note": note or "",
        "advertised_at": now,
        "expires_at": now + int(ttl_hours * 3600),
    }
    doc = _load_board(board)
    doc["offers"].append(offer)
    _save_board(board, doc)
    return offer


def discover(board, unit=None, min_units=0, max_price_sat=None,
             device=None, renewable_only=False):
    """Live offers, cheapest unit price first. Discovery commits nothing."""
    doc = _load_board(board)
    out = []
    for o in _live(doc["offers"], _now()):
        if unit is not None and o.get("unit") != unit:
            continue
        if o.get("compute_units", 0) < min_units:
            continue
        if max_price_sat is not None \
                and o.get("price_sat_per_unit", 0) > max_price_sat:
            continue
        if device is not None and o.get("device") != device:
            continue
        if renewable_only and not o.get("renewable"):
            continue
        out.append(o)
    out.sort(key=lambda o: (o.get("price_sat_per_unit", 0),
                            -o.get("compute_units", 0)))
    return out


def match(board, unit, min_units, max_price_sat=None, **filters):
    """Cheapest fitting offer plus the L2 task shape to pay for it.

    Returns `{"offer": ..., "suggested_task": {...}}` where the suggested
    task locks `min_units * price_sat_per_unit` sat for the provider — the
    shape the consumer posts to the L2 task economy. Raises `SrctError`
    when nothing fits.
    """
    offers = discover(board, unit=unit, min_units=min_units,
                      max_price_sat=max_price_sat, **filters)
    if not offers:
        raise SrctError(f"no live offer fits {min_units}x {unit}"
                        + (f" under {max_price_sat} sat/u"
                           if max_price_sat is not None else ""))
    offer = offers[0]
    total = min_units * offer["price_sat_per_unit"]
    return {
        "offer": offer,
        "suggested_task": {
            "provider": offer["provider"],
            "unit": unit,
            "units": min_units,
            "payment_sat": total,
            "note": "post as an L2 task; settles on verified work only",
        },
    }


def _selftest():
    """Offline self-test: temp board, real advertise/discover/match.

    Run:  python templates/srct_depin.py --selftest
    """
    import os
    import tempfile

    fd, board = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(board)  # start missing: _load_board treats it as empty
    try:
        assert discover(board) == [], "empty board discovers nothing"

        advertise(board, "pp-datacenter", "gpu", 16, "gpu-hour", 800,
                  endpoint="http://gpu-1:8080", ttl_hours=72)
        advertise(board, "pp-solar", "solar-edge", 8, "gpu-hour", 500,
                  endpoint="http://edge-1:8080", renewable=True,
                  ttl_hours=72, note="daylight only")
        advertise(board, "pp-home", "cpu", 32, "cpu-hour", 50, ttl_hours=72)

        # Cheapest unit price first.
        offers = discover(board, unit="gpu-hour", min_units=4)
        assert [o["provider"] for o in offers] == ["pp-solar", "pp-datacenter"], offers

        # Renewable filter keeps only the solar edge device.
        green = discover(board, unit="gpu-hour", min_units=4, renewable_only=True)
        assert [o["provider"] for o in green] == ["pp-solar"], green

        # Price cap excludes the datacenter GPU.
        cheap = discover(board, unit="gpu-hour", min_units=4, max_price_sat=600)
        assert [o["provider"] for o in cheap] == ["pp-solar"], cheap

        # Match returns the offer plus the payable task shape.
        job = match(board, "gpu-hour", 4, max_price_sat=600)
        assert job["offer"]["provider"] == "pp-solar", job
        assert job["suggested_task"]["payment_sat"] == 4 * 500, job

        # Nothing fits: clear refusal, no partial match.
        try:
            match(board, "gpu-hour", 4, max_price_sat=100)
            raise AssertionError("unfittable match must refuse")
        except SrctError:
            pass

        # Bad inputs refuse at advertise time, not at match time.
        for bad in (dict(device="quantum"), dict(compute_units=0),
                    dict(price_sat_per_unit=-1), dict(ttl_hours=0)):
            kw = dict(board=board, provider_hex="pp", device="gpu",
                      compute_units=1, unit="x", price_sat_per_unit=1)
            kw.update(bad)
            try:
                advertise(**kw)
                raise AssertionError(f"bad advertise accepted: {bad}")
            except SrctError:
                pass

        # Expired offers are invisible, never deleted.
        doc = _load_board(board)
        doc["offers"][0]["expires_at"] = _now() - 1
        _save_board(board, doc)
        assert len(_load_board(board)["offers"]) == 3, "trail preserved"
        assert all(o["provider"] != "pp-datacenter"
                   for o in discover(board, unit="gpu-hour")), "expired hidden"
    finally:
        if os.path.exists(board):
            os.remove(board)
    print("srct_depin selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
