"""x402 paid-API demo (envelope level).

Simulates the agent loop the task asks for without needing keys:

    agent calls paid API -> 402 + PAYMENT-REQUIRED -> budget check ->
    (wallet signs: see crates/srct-core/tests/x402.rs) -> retry with
    PAYMENT-SIGNATURE -> 200 + PAYMENT-RESPONSE + resource.

Run directly to print the whole loop:

    python verification/sim/x402_paid_api_demo.py

The crypto (request/authorize/pay) lives in Rust (`cargo test -p srct-core
--test x402`, `cargo test -p srct-node --test x402`); this script mirrors the
envelope logic in stdlib so the flow is auditable in Python too.
"""

from __future__ import annotations

import base64
import json

X402_VERSION = 2
SCHEME = "exact"
NETWORK = "srct:mini"
PRICE_SAT = 500
RESOURCE = "/v1/paid/weather"
PAY_TO = "42" * 20


def b64e(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def b64d(header: str) -> dict:
    return json.loads(base64.b64decode(header))


def server_challenge() -> tuple[int, dict[str, str], dict]:
    required = {
        "x402Version": X402_VERSION,
        "accepts": [
            {
                "scheme": SCHEME,
                "network": NETWORK,
                "amount": str(PRICE_SAT),
                "payTo": PAY_TO,
                "description": "Demo paid weather (x402 exact, 500 sat)",
                "mimeType": "application/json",
                "resource": RESOURCE,
                "maxTimeoutSecs": 60,
            }
        ],
        "resource": RESOURCE,
        "description": "Demo paid weather (x402 exact, 500 sat)",
        "error": "payment required",
    }
    return 402, {"PAYMENT-REQUIRED": b64e(required)}, required


def agent_select(required: dict, budget_max: int) -> dict:
    options = [a for a in required["accepts"] if a["scheme"] == SCHEME]
    options = [a for a in options if a["network"].startswith("srct:")]
    affordable = [a for a in options if int(a["amount"]) <= budget_max]
    if not affordable:
        raise RuntimeError("no compatible accept inside budget")
    return min(affordable, key=lambda a: int(a["amount"]))


def server_verify(signature: dict) -> tuple[int, dict[str, str], dict]:
    payload = signature.get("payload", {})
    if signature.get("x402Version") != X402_VERSION or signature.get("scheme") != SCHEME:
        return 400, {}, {"error": "unsupported scheme/version"}
    if signature.get("network") != NETWORK:
        return 409, {}, {"error": "unknown network"}
    if not payload.get("payment_hex"):
        return 400, {}, {"error": "empty payload"}
    # Real node: MachinePayment.verify + linked_to + admit_payment + credit gate.
    response = {"success": True, "paymentId": "demo-payment-id"}
    body = {"report": {"weather": "sunny", "temperature": 70}, "payment_id": "demo-payment-id"}
    return 200, {"PAYMENT-RESPONSE": b64e(response)}, body


def main() -> None:
    print("1. Agent: GET", RESOURCE)
    status, headers, required = server_challenge()
    print(f"   Server: {status} + PAYMENT-REQUIRED ({len(headers['PAYMENT-REQUIRED'])} b64 chars)")
    assert b64d(headers["PAYMENT-REQUIRED"]) == required

    print("2. Agent: budget check (max 600 sat, recipient/service allow-list)")
    accept = agent_select(required, budget_max=600)
    print(f"   Selected: scheme={accept['scheme']} network={accept['network']} amount={accept['amount']}")
    try:
        agent_select(required, budget_max=100)
        raise AssertionError("greedy budget should have refused")
    except RuntimeError as exc:
        print(f"   Greedy server refused locally: {exc}")

    print("3. Agent: wallet signs (Rust: build_signed_request -> authorize_request -> build_signed_payment)")
    signature = {
        "x402Version": X402_VERSION,
        "scheme": SCHEME,
        "network": NETWORK,
        "payload": {
            "payment_hex": "aa",
            "authorization_hex": "bb",
            "auth_sigs_hex": "cc",
            "auth_keys_hex": "dd",
        },
    }
    sig_header = b64e(signature)
    assert b64d(sig_header) == signature

    print("4. Agent: GET + PAYMENT-SIGNATURE -> server verifies + settles")
    status, out_headers, body = server_verify(signature)
    print(f"   Server: {status} + PAYMENT-RESPONSE ({len(out_headers['PAYMENT-RESPONSE'])} b64 chars)")
    print(f"   Body: {body}")
    assert status == 200 and body["report"]["weather"] == "sunny"
    print("Demo OK: 402 -> authorize bounded spend -> pay -> 200.")


if __name__ == "__main__":
    main()
