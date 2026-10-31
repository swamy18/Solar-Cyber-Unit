"""srct_policy — Python binding for the chain-agnostic SRCT policy engine.

The engine itself stays in Rust (one implementation of every rule, in
``crates/srct-policy``): this module is the JSON codec + client seam. It builds
payment intents, parses decisions, and structurally reads portable documents —
it never re-implements a budget, narrowing, or signature rule. Verification
that matters (signatures, chains, bindings) runs in Rust: either behind the
injected backend (a callable, a subprocess, or node HTTP) or on any node
speaking ``POST /v1/policy/decide``, ``/v1/delegation/verify`` and
``/v1/audit/verify`` (see :class:`NodeHttpBackend` — no Rust toolchain needed,
just a node URL, stdlib only).

Quick start against a local node::

    from srct_policy import NodeHttpBackend, PaymentIntent, PolicyClient

    guard = PolicyClient.for_node("http://127.0.0.1:8080")
    decision = guard.decide("srct/testnet", portable_policy_json, PaymentIntent(...), 100)
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class PaymentIntent:
    """What an agent wants to do — mirrors ``portable::PaymentIntent``."""

    agent_id: str  # 20-byte agent id, hex (0x optional)
    recipient: str  # 20-byte recipient, hex
    amount_sat: int
    service: Optional[str]  # 32-byte service tag hex, or None
    height: int
    nonce: int
    network_id: str

    def to_json(self) -> str:
        if self.amount_sat < 0:
            raise ValueError("amount_sat must be non-negative")
        return json.dumps(
            {
                "agent_id": self.agent_id,
                "recipient": self.recipient,
                "amount_sat": self.amount_sat,
                "service": self.service,
                "height": self.height,
                "nonce": self.nonce,
                "network_id": self.network_id,
            }
        )


@dataclass(frozen=True)
class PolicyDecision:
    """The engine's answer: allow, deny, or approval-needed."""

    decision: str  # "allow" | "deny" | "needs_approval"
    reason: str = ""

    @staticmethod
    def parse(raw: str) -> "PolicyDecision":
        doc = json.loads(raw)
        decision = doc.get("decision")
        if decision == "allow":
            return PolicyDecision(decision="allow")
        if decision in ("deny", "needs_approval") and isinstance(doc.get("reason"), str):
            return PolicyDecision(decision=decision, reason=doc["reason"])
        raise ValueError("malformed policy decision")

    def is_allow(self) -> bool:
        return self.decision == "allow"


def parse_portable_policy(raw: str) -> dict:
    """Structurally read a portable policy (routing without trusting)."""
    doc = json.loads(raw)
    for field in ("policy_hex", "policy_hash", "owner", "network_id"):
        if not isinstance(doc.get(field), str):
            raise ValueError(f"malformed portable policy: {field}")
    if doc.get("version") != 1:
        raise ValueError("unsupported portable version")
    return doc


def parse_delegation_proof(raw: str) -> dict:
    """Structurally read a delegation proof (routing without trusting)."""
    doc = json.loads(raw)
    if doc.get("version") != 1 or not isinstance(doc.get("links"), list) or not doc["links"]:
        raise ValueError("malformed delegation proof")
    return doc


class PolicyClient:
    """The agent wallet guard: allow, deny, or approval-needed, via a backend.

    ``decide`` is any callable
    ``(network_id, policy_json, intent_json, threshold) -> str`` backed by the
    Rust engine (FFI, subprocess, or node HTTP). ``network_id`` is the rail
    asking the question — the caller's own network, never a field copied from
    agent-supplied JSON. The node backend ignores it on the wire (the node
    frames the intent in its own network) but still requires it so a direct
    Rust backend and the node backend share one call shape.
    """

    def __init__(
        self,
        decide: Callable[[str, str, str, Optional[int]], str],
        verify_proof: Optional[Callable[[str], str]] = None,
        verify_audit: Optional[Callable[[str], int]] = None,
    ) -> None:
        self._decide = decide
        self._verify_proof = verify_proof
        self._verify_audit = verify_audit

    @staticmethod
    def for_node(base_url: str) -> "PolicyClient":
        """A client verified by any node — no Rust toolchain, just a URL."""
        backend = NodeHttpBackend(base_url)
        return PolicyClient(backend.decide, backend.verify_proof, backend.verify_audit)

    def decide(
        self,
        network_id: str,
        policy_portable_json: str,
        intent: PaymentIntent,
        approval_threshold_sat: Optional[int] = None,
    ) -> PolicyDecision:
        out = self._decide(
            network_id, policy_portable_json, intent.to_json(), approval_threshold_sat
        )
        return PolicyDecision.parse(out)

    def verify_proof(self, proof_json: str) -> str:
        if self._verify_proof is None:
            raise NotImplementedError("no proof backend wired")
        return self._verify_proof(proof_json)

    def verify_audit(self, audit_json: str) -> int:
        if self._verify_audit is None:
            raise NotImplementedError("no audit backend wired")
        return self._verify_audit(audit_json)


class NodeHttpBackend:
    """A backend that speaks to any node over HTTP — stdlib only.

    Verification runs on the node (the same engine that admits payments);
    this module only codecs the JSON. Non-2xx answers raise RuntimeError
    with the node's named refusal, so a deny is never mistaken for an
    allow.
    """

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")

    def _post(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self._base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                doc = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                doc = json.loads(e.read().decode("utf-8"))
            except ValueError:
                doc = {"error": "http_error", "detail": e.reason}
            raise RuntimeError(
                f"node refused ({e.code} {doc.get('error', 'error')}): "
                f"{doc.get('detail', doc.get('reason', doc))}"
            ) from e
        if not isinstance(doc, dict):
            raise RuntimeError("node answered outside JSON")
        return doc

    def decide(
        self,
        network_id: str,
        policy_portable_json: str,
        intent_json: str,
        approval_threshold_sat: Optional[int] = None,
    ) -> str:
        # The node frames the intent in its own network and height, so the
        # caller's network_id never travels: it exists so direct-Rust backends
        # and this backend share one call shape, and the rail cannot forget
        # to name itself.
        _ = network_id
        intent = json.loads(intent_json)
        doc = self._post(
            "/v1/policy/decide",
            {
                "policy_portable_json": policy_portable_json,
                "agent_id_hex": intent["agent_id"],
                "recipient_hex": intent["recipient"],
                "amount_sat": intent["amount_sat"],
                "service_hex": intent.get("service"),
                "approval_threshold_sat": approval_threshold_sat,
            },
        )
        return json.dumps(
            {"decision": doc["decision"], "reason": doc.get("reason", "")}
        )

    def verify_proof(self, proof_json: str) -> str:
        doc = self._post("/v1/delegation/verify", {"proof_json": proof_json})
        if doc.get("valid") is not True:
            raise RuntimeError("node did not verify the proof")
        return f"{doc['leaf_agent']}/{doc['leaf_policy_hash']}"

    def verify_audit(self, audit_json: str) -> int:
        doc = self._post("/v1/audit/verify", {"audit_json": audit_json})
        if doc.get("valid") is not True or not isinstance(doc.get("entries"), int):
            raise RuntimeError("node did not verify the audit chain")
        return int(doc["entries"])
