"""Portable policy decide demo (binding level).

Shows the agent wallet-guard loop a developer gets from `pip install`-style
use — stdlib only, no Rust toolchain: a portable policy (exported once via
the keyless MCP `policy.export`), a payment intent, and a node that decides.

Run the offline self-test (no node needed):

    python sim/policy_decide_demo.py --self-test

Decide against a local node (needs a portable policy JSON file — export one
with the MCP `policy.export` op, or copy the `policy_json` from a Rust test
fixture):

    python sim/policy_decide_demo.py --node http://127.0.0.1:8080 \
        --policy policy.json --agent-id <hex> --recipient <hex> \
        --amount-sat 400 --threshold-sat 100

The crypto (sign/verify/narrow/bind) lives in Rust (`cargo test -p
srct-policy`, `cargo test -p srct-node --test api policy_decide`); this
script mirrors the codec logic in stdlib so the flow is auditable in
Python too.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "crates" / "srct-policy" / "bindings" / "python"))

from srct_policy import (  # noqa: E402
    NodeHttpBackend,
    PaymentIntent,
    PolicyClient,
    PolicyDecision,
    parse_delegation_proof,
    parse_portable_policy,
)


def self_test() -> None:
    """Offline codec checks: intents, decisions, and document shapes."""
    intent = PaymentIntent(
        agent_id="ab" * 20,
        recipient="cd" * 20,
        amount_sat=400,
        service=None,
        height=50,
        nonce=1,
        network_id="srct/mini",
    )
    decoded = json.loads(intent.to_json())
    assert decoded["amount_sat"] == 400, decoded
    assert PolicyDecision.parse('{"decision": "allow"}').is_allow()
    gated = PolicyDecision.parse('{"decision": "needs_approval", "reason": "x"}')
    assert gated.decision == "needs_approval" and gated.reason == "x"
    assert PolicyDecision.parse('{"decision": "deny", "reason": "y"}').decision == "deny"
    for bad in ('{"decision": "maybe"}', '{"decision": "deny"}', "not json"):
        try:
            PolicyDecision.parse(bad)
        except (ValueError, KeyError):
            pass
        else:
            raise AssertionError(f"malformed decision accepted: {bad}")
    doc = {
        "version": 1,
        "policy_hex": "00",
        "sigs_hex": "00",
        "keys_hex": "00",
        "policy_hash": "ab" * 32,
        "owner": "owner",
        "agent_id": "ab" * 20,
        "network_id": "srct/mini",
    }
    assert parse_portable_policy(json.dumps(doc))["owner"] == "owner"
    proof = {
        "version": 1,
        "links": ["{}"],
        "root_owner": "o",
        "leaf_agent": "a",
        "leaf_policy_hash": "h",
    }
    assert parse_delegation_proof(json.dumps(proof))["links"] == ["{}"]
    print("self-test: intents, decisions and document shapes all codec clean")


def decide_live(args: argparse.Namespace) -> int:
    """The guard loop: intent in, allow/deny/approval-needed out."""
    policy_json = Path(args.policy).read_text(encoding="utf-8")
    # Structural read first (routing without trusting); the node verifies.
    parse_portable_policy(policy_json)
    client = PolicyClient.for_node(args.node)
    # Rail identity for the call shape; the node backend ignores it on the
    # wire and frames the intent in its own network.
    rail_network = "srct/mini"
    intent = PaymentIntent(
        agent_id=args.agent_id,
        recipient=args.recipient,
        amount_sat=args.amount_sat,
        service=args.service,
        height=0,  # the node decides at its own height
        nonce=0,  # decide commits nothing, so no nonce is consumed
        network_id=rail_network,
    )
    try:
        decision = client.decide(rail_network, policy_json, intent, args.threshold_sat)
    except RuntimeError as e:
        print(f"node refused: {e}")
        return 1
    print(f"decision: {decision.decision}")
    if decision.reason:
        print(f"reason: {decision.reason}")
    return 0 if decision.is_allow() else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SRCT portable policy decide demo")
    parser.add_argument("--self-test", action="store_true", help="offline codec checks")
    parser.add_argument("--node", default="http://127.0.0.1:8080")
    parser.add_argument("--policy", help="portable policy JSON file (MCP policy.export)")
    parser.add_argument("--agent-id", default="")
    parser.add_argument("--recipient", default="")
    parser.add_argument("--amount-sat", type=int, default=0)
    parser.add_argument("--service", default=None)
    parser.add_argument("--threshold-sat", type=int, default=None)
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.policy:
        parser.error("--policy is required without --self-test")
    return decide_live(args)


if __name__ == "__main__":
    raise SystemExit(main())
