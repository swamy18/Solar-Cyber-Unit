# Solar Smart Gate — Architecture (Implemented)

Status: implemented and enforced by the node. No consensus change. `guard.rs`
(core capability book, signed capabilities, signed approvals) +
`srct-policy::guard_verify` (stateless pre-check) + MCP `guard.check` /
`guard.authorize` + node `POST /v1/guard/decide` (stateless pre-check),
`POST /v1/guard/grant` (owner-signed registration),
`POST /v1/guard/revoke` (owner-signed kill switch with descendant propagation),
`POST /v1/guard/authorize` (stateful execution-boundary admission with audit).
Grants, revocations and the capability book persist in `state.bin`
(envelope v10; v8/v9 migrate with empty gate state). Worker k8s/cloud shims
are follow-up.

## 1. Goal

One universal gate inside Solar Cyber Units. Coin stays coin. Gate answers one question for any platform: `may this workload do this exact action at this exact moment under this grant?` Answer is `allow / deny / needs_approval`. Enforcement is exact-equality, fail-closed.

Prevents Binance Oct 2026 pattern: stolen laptop token used outside normal flow to deploy container and force signing service to sign.

## 2. Threat model

- Attacker owns 1-2 engineer laptops via trojanized installer (June) and fake-interview repo (Sept).
- Attacker reaches internal AI tool, moves laterally B -> A/C (Oct 20).
- Attacker steals long-lived deploy token, triggers signing outside withdrawal process with pre-signed batch (Oct 29).
- No private key break. System tricked into signing.

Assumptions: endpoint can be owned. Network can be observed. Long-lived secrets on laptops are considered compromised. Chain tip, validator quorum, and owner offline keys are trusted.

Five concrete holes this design closes (each with a named regression test):

1. **Forged capability** — a bare capability (policy hash + action + context + expiry + nonce) is public bytes anyone can write down. Fixed by owner-signed capabilities (§3).
2. **Fake approval** — a caller-supplied `approved: true` boolean claims authorization without proof. Fixed by signed approvals (§4).
3. **Action swap** — authorizing a caller-supplied hash proves nothing about what executes. Fixed by preimage recomputation at the boundary (§5).
4. **Replay and revocation drift** — zero/reused nonces, unchecked revocation sets, restart resurrection. Fixed by strict nonces, authoritative revocation, persisted books (§6).
5. **MCP token theft** — a caller-controlled endpoint plus a bearer header is credential delivery to the attacker. Fixed by the endpoint trust gate (§7).

## 3. Primitive: signed, context-bound capability

```
cap      = H(DOM_G || policy_hash || action_hash || context_hash || expiry || nonce)
action   = H(DOM_A || preimage)          // recomputed at the boundary, never trusted in
context  = H(DOM_C || workload_id || height)
signed   = version || cap || sigs || keys // owner's signature over cap.signing_hash()
approval = H(DOM_P || policy || cap || agent || action || context || expiry) + owner sigs
```

- `policy_hash`: owner-signed narrow grant, network-bound, revocable. Empty allows nothing.
- `action_hash`: SHA-256 over the domain tag and the **exact preimage bytes** about to execute (deploy digest or payment payload). The boundary recomputes it (§5).
- `context_hash`: workload attestation id + height, recomputed by the verifier.
- `expiry`: short, max 30 heights from the check height (`MAX_CAP_LIFETIME`). Enforced by verifier, re-checked at admission. Heights, not wall-clock: `guard.rs` is pure and deterministic — no clock, no I/O.
- `nonce`: strictly increasing per grant, **nonzero** (`ZeroNonce` refusal). `PaymentTracker` pattern reused.
- `sigs`/`keys`: the owner's hybrid signature bundle (`1+2+3` accepted) over the capability hash, with the keys binding to the grant's `owner` address. The signature covers all five fields together, so none of policy, action, context, expiry or nonce can be swapped after signing.

Verify is stateless exact match plus signature. Commit is stateful nonce + window spend in `GuardBook`.

Three exacts must coincide: prior intent, present bytes, present moment. Missing one denies. No fuzzy match, no learning bypass.

### What `SignedCapability::verify` checks, in order

Version, owner binding (`keys.address() == policy.owner`), bundle signature over the capability hash, then that the capability names this grant. Unsigned envelopes, stranger signatures, and tampered fields all refuse as `UnsignedCapability` / `PolicyMismatch` — never as allow.

## 4. Protocol

1. Enroll: owner signs narrow grant offline, registers via `POST /v1/guard/grant` (owner signature mandatory — no signature, no authority). Revoke via `POST /v1/guard/revoke` kills the grant **and every registered descendant** (§6).
2. Guard: workload calls `guard.check` (stateless) before any key is used. Budget + allow-list + window checked. Returns allow or refusal; unsigned/forged capabilities refused by name.
3. Issue: owner signs a capability bound to the exact action preimage. Long-term token never leaves vault.
4. Verify: runtime / cloud broker / wallet service verifies offline via `srct-policy` crate (`guard_verify` checks the owner signature + all equalities). No node needed.
5. Settle: receipt + hash-chained audit entry on the enforcing node (`guard_allow`, `guard_needs_approval`, `guard_refused`, `guard_grant`, `guard_revoke`). The audit log is node-local, bounded, and export-verifiable (`audit.verify`); it is **not** anchored to the chain — see §8.
6. Escalate: high-risk calls return `needs_approval` until a signed `GuardApproval` from the grant owner, bound to the exact capability instance (grant + capability hash + agent + action + context + expiry), is presented. A missing approval gates; a forged one denies. The old boolean is rejected everywhere.

## 5. Data structures

- `InfraPolicy`: caps, validity heights, parent link, revocation flag. Same narrowing shape as `SpendPolicy`, domain tag `srct/guard-policy/v1`. Grants live in the node's registry (cap `MAX_GUARD_REGISTRY = 1024`, refusal when full).
- `Capability`: policy_hash, action_hash, context_hash, expiry, **nonzero** nonce.
- `SignedCapability`: version + capability + owner `sigs`/`keys` bundles. This is the only form `cap_hex` takes on every boundary (node, MCP, `srct-policy`): raw capabilities are refused as "not signed".
- `GuardApproval`: policy_hash, cap_hash (= capability signing hash), agent_id, action_hash, context_hash, expiry + owner `sigs`/`keys` over `srct/guard-approval/v1`. Lifetime cap 30 heights. Authority is the grant owner; the independence is the second signature over the exact instance, not a second boolean.
- `Decision`: allow / needs_approval (missing approval) / deny(reason). Reasons named: `hash_mismatch`, `expired`, `nonce_reuse`, `zero_nonce`, `unsigned_capability`, `bad_approval`, `action_mismatch`, `context_mismatch`, `cross_principal`, `velocity_exceeded` (`window_exhausted`), `session_cap`.
- `Receipt`: audit entries per decision on the enforcing node. Duplicate receipt for same cap is `duplicate` semantics at the payment layer; conflicting receipt is `receipt_conflict`.

All LE encoding, JSON portable form version 1 with hex fields. Canonical bytes equal signed bytes.

## 6. Replay, revocation, and authoritative state

- **Nonce discipline.** Nonce 0 is refused. Every admission requires `nonce > last_nonce` (strictly increasing from a `last_nonce = 0` start). Consumed nonces live in the persisted `GuardBook`; a replayed nonce is a named deny, and a refused call commits nothing (no budget consumed, no nonce stored).
- **Overflow safety.** Window-end arithmetic uses `checked_add` (overflow denies instead of wrapping); spend counters use `checked_add`; time-window and lifetime math uses `saturating_sub` with explicit caps. Codec paths are bounded before allocation (`MAX_GUARD_BOOK_READ`, registry cap, per-field hex caps).
- **Revocation.** Two sets, one authority: the node's `guard_registry` (grants it enforces) and `guard_revoked` (hashes it has killed). `guard_decide` (stateless) consults the node's revocation set even though it commits nothing. `guard_authorize` (stateful) requires the capability to name a registered, unrevoked grant. Revocation propagates to registered descendants via the parent-agent walk, and each killed grant's book state is forgotten so a restart can neither resurrect spent nonces nor replay them — the revocation set itself persists in `state.bin`.
- **Restart and multi-node.** Grants, revocations and the capability book persist in `state.bin` (v10 sections; decode is bounded and fail-closed). The node's registry + revocation set + book is **authoritative per node**. Local MCP `GuardBook` state is a non-authoritative cache for keyless pre-checks — never present it as global. Multiple nodes reach the same answer by (a) publishing the grant on the L2 `Policy`/`PolicyRevoke` path and registering the same owner-signed bytes on each enforcing node, and (b) replicating revocations the same way. There is no cross-node nonce lock: the same capability must not be aimed at two enforcing nodes.
- **Delegation.** A grant's `parent_agent_id` names its parent; narrowing follows the same attenuation rule as spend policies, and revocation of an ancestor kills every registered descendant (see the walk in `guard_revoke`). Cycle safety comes from one-way agent derivation; the walk itself is hop-bounded and fail-closed.

## 7. Trust boundaries

- **Stateless pre-check vs stateful admission.** `guard.check`, `srct-policy::guard_verify` and `POST /v1/guard/decide` verify signatures and equalities and commit nothing. `guard.authorize` / `POST /v1/guard/authorize` additionally recompute the action hash from the supplied preimage, enforce the tumbling-window budget and the strictly increasing nonce, and commit on allow. Final authorization is the execution boundary (`GuardBook::authorize_signed` on the enforcing node or the runtime that recomputes), never an API pre-check.
- **MCP credential protection.** The MCP HTTP client dials `host:port` only (no scheme, userinfo, or path). Loopback is trusted by default and is the **only** target that ever receives the `SRCT_API_TOKEN` bearer. Anything else is refused as `untrusted_endpoint` unless the exact `host:port` is listed in `SRCT_MCP_TRUSTED_ENDPOINTS` **and** `SRCT_MCP_ALLOW_REMOTE=1` is set — and even then the bearer is never sent over this plaintext transport. Mixed loopback/non-loopback DNS answers (rebinding shape) are refused; redirects (3xx) are errors, never followed; endpoint values and tokens never appear in error strings or logs. Remote operators must terminate TLS in front of the node; this client does not do HTTPS.
- **Audit.** Every grant, allow, needs-approval, refusal and revocation appends to the node's bounded hash-chained `AuditLog` (`chain_valid`; `GET /v1/risk/policy` exports the live envelope). The chain exports as auditor/insurer-readable JSON (`AuditLog::export_json`, re-checked by `verify_export_json`, MCP `audit.verify`). Audit is node-local persistence, not consensus and not chain-anchored.

## 8. What is implemented, partial, and planned

- **Implemented:** owner-signed grants and registration; signed capabilities end to end (core, `srct-policy`, MCP, node); signed high-risk approvals with missing-vs-forged distinction; execution-boundary action recomputation; strict nonzero monotonic nonces with persisted books; revocation with descendant propagation and restart-safe persistence; registry/book capacity caps with refusal; overflow-safe window arithmetic; stateless/stateful separation; MCP endpoint trust gate with no-token-to-untrusted rule and no-redirect rule; audit logging of every gate decision with verifiable export; negative tests for forgery, fake approval, action swap, replay, revocation, and untrusted endpoints.
- **Partial:** grant ancestry is a parent link plus revocation propagation, not a full portable delegation-proof chain like spend policies; multi-node consistency is replication-by-operator (publish + register everywhere), not a consensus lock; MCP remote operation is dial-but-unauthenticated by design (plaintext client) — production remote use needs a TLS-terminating proxy, at which point the bearer model must be revisited.
- **Planned (not implemented):** worker k8s/cloud broker shims; TLS in the MCP/worker HTTP clients; any chain anchoring of audit receipts; cross-node capability locks.

## 9. Code map

- `crates/srct-core/src/guard.rs`: `InfraPolicy`, `Capability`, `SignedCapability`, `GuardApproval`, `derive_action_hash` / `derive_context_hash`, `GuardBook::authorize` + `authorize_signed`, tests for forgery/fake-approval/swap/zero-nonce.
- `crates/srct-policy` (`guard_verify`): stateless signature + equality pre-check; denies unsigned envelopes.
- `crates/srct-mcp` (`guard.check` / `guard.authorize`, `http_json` trust gate): signed pre-check; preimage-recomputing admission; `approved:true` rejected; loopback-only bearer.
- `crates/srct-node/src/api.rs`: `POST /v1/guard/decide` (pre-check + revocation-set consult), `POST /v1/guard/grant` (owner-signed registration, registry cap), `POST /v1/guard/revoke` (owner-signed, descendant propagation), `POST /v1/guard/authorize` (signed + preimage + approval, audit).
- `crates/srct-worker` + `templates/`: k8s admission shim, cloud broker shim, EVM facilitator shim (follow-up).
- Tests: core `guard` unit tests, `srct-policy` verify tests, `srct-mcp` guard + transport tests, node `api` round-trip (grant → signed authorize → replay deny → revoke → dead), `state_persist` book round-trip.

## 10. Quantum and AI-agent resistance

No new hardness assumption. Hash equality + short-lived high-entropy nonce + domain separation + owner signatures over all bound fields. Hybrid bundles `1+2+3` already in consensus reused, so Shor break of secp256k1 alone does not forge. Learning does not help: past caps do not predict future nonce/context, windows are short, cross-principal moves denied by ancestry check.

## 11. Universal use and anti-copy

Verify is free and offline. Trust is not copyable: network_id binding, validator TopN BLS quorum, canonical audit tip, burn/PSCB accounting, accumulated history. Fork gets new magic/id, old grants fail, no quorum, no insurer acceptance. Use is cheaper than rebuild.

## 12. Binance prevention mapping

- Fake Homebrew hash denies at the gate before any deploy token exists.
- Assignment repo setup execution hash mismatch denies (recomputed, not claimed).
- B -> A/C lateral via AI tool -> cross_principal deny, delegation ancestry fails.
- Stolen deploy token alone -> no valid capability without owner signature + fresh context + nonce.
- 50 pre-signed burst -> velocity + per-owner window cap refuse by name, high-value needs signed second approval.
