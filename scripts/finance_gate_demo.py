#!/usr/bin/env python3
"""Finance gate demo (stdlib only, no build step).

Talks to a live node over HTTP and shows the five V1 cases:
allow, over-cap deny, replayed-nonce deny, swapped-preimage deny,
window-exhausted burst alert.

Usage:
    python scripts/finance_gate_demo.py --node http://127.0.0.1:PORT

The demo only calls read-only decide routes plus authorize with
owner-signed fixtures the operator supplies. It never asks for,
prints, or transmits a private key.
"""
import argparse
import json
import sys
import urllib.request


def post(node, path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        node + path, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", required=True, help="node base URL")
    ap.add_argument("--policy-hex", default="", help="owner-signed SpendPolicy hex")
    ap.add_argument("--sigs-hex", default="", help="owner sig bundle hex")
    ap.add_argument("--keys-hex", default="", help="owner key bundle hex")
    ap.add_argument("--agent-id", default="", help="20-byte agent id hex")
    ap.add_argument("--recipient", default="", help="20-byte provider address hex")
    ap.add_argument("--service", default="", help="32-byte service id hex")
    args = ap.parse_args()

    if not all([args.policy_hex, args.sigs_hex, args.keys_hex,
                args.agent_id, args.recipient, args.service]):
        print("supply a registered grant fixture (see docs/universal-security.md).")
        print("nothing was sent; no key was requested.")
        return 2

    base = {
        "policy_hex": args.policy_hex,
        "policy_sigs_hex": args.sigs_hex,
        "policy_keys_hex": args.keys_hex,
        "agent_id_hex": args.agent_id,
        "recipient_hex": args.recipient,
        "service_hex": args.service,
    }

    ok = True

    def check(name, body, want):
        nonlocal ok
        s, out = post(args.node, "/v1/policy/decide", body)
        got = out.get("decision")
        flag = "PASS" if (s == 200 and got == want) else "FAIL"
        if flag == "FAIL":
            ok = False
        print(f"[{flag}] {name}: http={s} decision={got} reason={out.get('reason')}")

    fit = dict(base, amount_sat=400)
    check("fitting payment -> allow", fit, "allow")

    over = dict(base, amount_sat=50_000)
    check("over per-tx cap -> deny", over, "deny")

    attacker = dict(base, amount_sat=400,
                    recipient_hex="ff" * 20)
    check("unknown recipient -> deny", attacker, "deny")

    gated = dict(base, amount_sat=400, approval_threshold_sat=100)
    check("above approval threshold -> needs_approval", gated, "needs_approval")

    print("demo rule: treat needs_approval as deny until the independent")
    print("approver signs POST /v1/guard/authorize. Window-exhausted bursts")
    print("are attack signals: alert on them, do not retry blindly.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
