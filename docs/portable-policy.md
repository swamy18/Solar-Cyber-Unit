# Portable agent policy

The policy layer is the one place that answers *may this agent spend?* — and
it travels. A grant signed once by the owner verifies on any chain or rail
without the issuing node, without chain state, and without any private key.
This document specifies the interface (`srct-core::portable`,
`srct-policy`, and the `srct-mcp` wallet-guard ops).

## Objects

All portable documents are JSON with hex fields, version `1`. The canonical
byte codecs (`serialize`/`deserialize`) are the same bytes the owner signed.

### `SignedPolicy` — the grant that travels

`policy_hex` (a `SpendPolicy`: caps, allow-lists, window, parent link,
revocation flag) + `sigs_hex`/`keys_hex` (the owner's signature over
`policy.signing_hash()`). Denormalized `policy_hash`/`owner`/`agent_id`/
`network_id` let a rail route before it decodes — and parsing re-checks them,
so a document that routes one way and verifies another is refused. The
network binding is clause one of `evaluate_policy` itself, so no caller of
the seam can forget it.

```bash
# MCP: export a signed grant (verified on the way out)
{"op":"policy.export","policy_hex":"...","sigs_hex":"...","keys_hex":"..."}
# MCP: verify one from any rail
{"op":"policy.verify","portable_json":"{...}"}
```

### `DelegationProof` — the verifiable tree

Root-first `links[]` of `SignedPolicy` JSON. Verification is three layers:
every link verifies, the inner policies narrow link-by-link
(`delegation::assert_chain`), and the chain starts at a root. The leaf is
what spends; everything above it is why it may.

```bash
# MCP: prove an ancestry (parallel root-first arrays)
{"op":"delegation.prove","policies_hex":[...],"sigs_hex":[...],"keys_hex":[...]}
# MCP: verify one from any rail
{"op":"delegation.verify","proof_json":"{...}"}
```

### `BoundAuthorization` — short-lived, exact-transaction, enforced

The advisory approval becomes a rule: the owner signs the grant hash, the
expiry, and the **exact transaction hash** together
(`srct/bound-auth/v1`), with a lifetime cap of 30 blocks
(`MAX_BOUND_LIFETIME_BLOCKS`). A stolen authorization re-aimed at another
payment, or replayed past its window, refuses by name. The node admits it via
`service::admit_bound_payment` (same checks as `admit_payment`, after the
binding verifies).

```bash
# MCP (keyless): name the hash the owner must sign
{"op":"auth.bind","authorization_hex":"...","expires_at_height":110,"tx_hash_hex":"..."}
# MCP: verify a bound grant against its policy, payment and height
{"op":"auth.verify_bound","bound_json":"{...}","policy_hex":"...","payment_hex":"...","height":105}
```

### `PaymentIntent` → `PolicyDecision` — the engine seam

Input a payment intent (agent, recipient, amount, service, height, nonce,
network); get back `allow`, `deny` (named reason), or `needs_approval`
(high-value gating without refusal). Stateless pre-check only — nonces and
window spend still commit in `PolicyBook::authorize`. This is the exact shape
the `srct-policy` crate (`decide`) and its TypeScript/Python bindings speak,
so every rail decides what the node decides.

```bash
# MCP: stateless decide (commits nothing)
{"op":"policy.decide","network_id":"srct/testnet","height":50,"policy_hex":"...",
 "agent_id_hex":"...","recipient_hex":"...","amount_sat":400,"service_hex":"..."}
```

### Audit export — auditor/insurer readable

`AuditLog::export_json()` emits the hash-chained entries with hex hashes;
`verify_export_json` re-checks links, entry hashes, order from genesis, and
the tip. An auditor verifies rather than trusts. A `dropped` count travels
alongside (the ring's own admission of partiality — reported, not proven);
`GET /v1/audit` reports it too.

```bash
{"op":"audit.verify","audit_json":"{...}"}   # → {"valid": true, "entries": N}
```

## Wallet guard (x402 + any rail)

`X402Budget::check_guarded` runs the budget (amount, allow-lists) plus the
short window (challenge height precedes expiry, window ≤ 30 blocks) *before*
any key is used, and returns the exact grant the agent may sign. MCP:

```bash
{"op":"wallet.guard","max_amount_sat":600,"allowed_recipients_hex":[...],
 "amount_sat":400,"recipient_hex":"...","height":50,"expires_at_height":60,
 "approval_threshold_sat":100}
# → {"decision":"allow"|"needs_approval",...} or guard_refused
```

On x402 the same guard fronts signing; challenges may advertise Base beside
SRCT (`build_required_with_evm`, `eip155:8453`/`eip155:84532`) while the node
settles SRCT options only — EVM settlement stays the external facilitator's
job, under the same budget.

## HTTP backends (bindings without Rust)

The TypeScript/Python bindings codec the JSON; verification runs in Rust.
The Rust can be any node — no toolchain, no vendoring, just a URL:

- `POST /v1/policy/decide` — policy (portable JSON, or hex + owner
  signatures) + payment intent → `{"decision": "allow" | "deny" |
  "needs_approval", "reason", "network_id", "height"}`. Read-only: nothing
  is committed, so deciding twice decides twice. A deny is a 200 with the
  reason — the query was answered, and the answer is no; only malformed
  input is an error.
- `POST /v1/delegation/verify` — a proof from any rail →
  `{valid, depth, root_owner, leaf_agent, leaf_policy_hash}`.
- `POST /v1/audit/verify` — an exported chain from any rail →
  `{valid, entries}`.

`NodeHttpBackend` (both bindings, stdlib only) speaks these three; the
agent loop is then `PolicyClient.for_node(url)` in Python or
`new PolicyClient(new NodeHttpBackend(url))` in TypeScript. Demo (offline
self-test, then live against a node):

```bash
python sim/policy_decide_demo.py --self-test
python sim/policy_decide_demo.py --node http://127.0.0.1:8080 \
  --policy policy.json --agent-id <hex> --recipient <hex> \
  --amount-sat 400 --threshold-sat 100
```

(The portable policy comes from the keyless MCP `policy.export`, or any
owner-signed grant.) Vendoring the `srct-policy` Rust crate instead still
compiles all of `srct-core` (BLS, ML-DSA and all) — see the crate docs for
the honest weight note. For outsiders, HTTP or the bindings are the way in.

## Smart Gate (companion surface)

Spend policies govern *payments*; the Smart Gate governs *any exact action*
(deploys, signing-service use, container execution) under the same
owner-signs-once discipline. The shapes rhyme on purpose: an owner-signed
`InfraPolicy` grant, a signed capability (`SignedCapability`, the only form
`cap_hex` takes — raw capabilities are refused as unsigned), a short lifetime
(30 heights), strictly increasing nonzero nonces, and a signed high-risk
approval (`GuardApproval`) instead of a boolean. The execution boundary
recomputes the canonical action hash from the preimage it observes
(`action_preimage_hex` is required at `guard.authorize` /
`POST /v1/guard/authorize`); a caller-supplied hash alone is never trusted.
Full architecture, threat model, and the authoritative-state rule (node
registry + revocation set authoritative per node; MCP-local gate state a
non-authoritative cache): [`smart-gate-architecture.md`](smart-gate-architecture.md).

## Rules the interface keeps

- One engine: `PolicyBook` commits, `dominates` narrows, `verify_*` checks.
  Nothing here re-implements them — not in Rust, not in the bindings.
- Keyless: no op accepts or returns a private key. Signing hashes go out,
  signatures come in.
- Fail-closed and named: every refusal names its clause; hostile bytes are
  refused before any allocation they dictate.
- Signed authority: grants, capabilities and high-risk approvals are
  owner-signed envelopes; booleans never stand in for signatures.
- Boundary recomputation: the exact action is re-derived from observed bytes
  at admission, not accepted as a caller claim.
