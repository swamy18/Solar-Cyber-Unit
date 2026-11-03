# Solar Smart Gate — Architecture (Phase 1 Design)

Status: Phase 1-3 implemented. No consensus change. `guard.rs` + `srct-policy::guard_verify` + MCP `guard.check` / `guard.authorize` + `POST /v1/guard/decide` live. Worker k8s/cloud shims are follow-up.

## 1. Goal

One universal gate inside Solar Cyber Units. Coin stays coin. Gate answers one question for any platform: `may this workload do this exact action at this moment?` Answer is `allow / deny / needs_approval`. Enforcement is exact-equality, fail-closed.

Prevents Binance Oct 2026 pattern: stolen laptop token used outside normal flow to deploy container and force signing service to sign.

## 2. Threat model

- Attacker owns 1-2 engineer laptops via trojanized installer (June) and fake-interview repo (Sept).
- Attacker reaches internal AI tool, moves laterally B -> A/C (Oct 20).
- Attacker steals long-lived deploy token, triggers signing outside withdrawal process with pre-signed batch (Oct 29).
- No private key break. System tricked into signing.

Assumptions: endpoint can be owned. Network can be observed. Long-lived secrets on laptops are considered compromised. Chain tip, validator quorum, and owner offline keys are trusted.

## 3. Primitive: context-bound capability

```
cap = H(DOM_G || policy_hash || action_hash || context_hash || expiry || nonce)
```

- `policy_hash`: owner-signed narrow grant, network-bound, revocable. Empty allows nothing.
- `action_hash`: SHA-256 of exact bytes to execute (deploy digest or payment payload hash).
- `context_hash`: workload attestation id + height + window id.
- `expiry`: short, max 120s wall time or 2-block equivalent. Enforced by verifier, re-checked at admission.
- `nonce`: strictly increasing per grantor, single-use. `PaymentTracker` pattern reused.

Verify is stateless exact match. Commit is stateful nonce + window spend in `PolicyBook` / `SessionBook`.

Three exacts must coincide: prior intent, present bytes, present moment. Missing one denies. No fuzzy match, no learning bypass.

## 4. Protocol

1. Enroll: owner signs narrow grant offline, publishes via `Policy` L2 tx. Revoke kills descendants.
2. Guard: workload calls `guard.check` before any key use. Budget + allow-list + window checked. Returns exact grant to sign or refusal.
3. Issue: broker mints 2-min capability bound to exact `action_hash`. Long-term token never leaves vault.
4. Verify: runtime / cloud broker / wallet service verifies offline via `srct-policy` crate. No node needed.
5. Settle: receipt + hash-chained audit entry anchored to Solar tip. Export verifiable via `audit.verify`.
6. Escalate: at or above high-value threshold, `human_approval_required` from second-channel approver key. Payer key does not count.

## 5. Data structures

- `InfraPolicy`: caps, service allow-list, validity heights, parent link, revocation flag. Same shape as `SpendPolicy`, new domain tag `srct/cap-policy/v1`.
- `Capability`: policy_hash, action_hash, context_hash, expiry, nonce, sigs/keys bundles (hybrid 1+2+3 accepted).
- `Decision`: allow / deny(reason) / needs_approval. Reasons named: `hash_mismatch`, `expired`, `nonce_reuse`, `cross_principal`, `velocity_exceeded`, `session_cap`.
- `Receipt`: cap hash + executor + height + result hash. Duplicate receipt for same cap is `duplicate`, conflicting receipt is `receipt_conflict`.

All LE encoding, JSON portable form version 1 with hex fields, canonical bytes equal signed bytes.

## 6. Code map

- `crates/srct-core/src/guard.rs` (new): policy check, capability verify, session + velocity enforcement.
- `crates/srct-core/src/portable.rs` (extend): `SignedGrant`, `BoundCapability` JSON.
- `crates/srct-policy` (extend): `decide(intent, context)` same allow/deny seam.
- `crates/srct-mcp` (extend): `guard.check`, `cap.issue`, `cap.verify`, `audit.verify`.
- `crates/srct-node/src/api.rs` (extend): `POST /v1/guard/decide`, `POST /v1/cap/issue`, `POST /v1/cap/verify`.
- `crates/srct-worker` + `templates/` (extend): k8s admission shim, cloud broker shim, EVM facilitator shim.
- Tests: `escrow`-style unit subsets + `api` integration, vectors in `tests/vectors/cap_vectors.json`.

## 7. Quantum and AI-agent resistance

No new hardness assumption. Hash equality + short-lived high-entropy nonce + domain separation. Hybrid bundles `1+2+3` already in consensus reused, so Shor break of secp256k1 alone does not forge. Learning does not help: past caps do not predict future nonce/context, windows are 60-120s, cross-principal moves denied by ancestry check.

## 8. Universal use and anti-copy

Verify is free and offline. Trust is not copyable: network_id binding, validator TopN BLS quorum, canonical audit tip, burn/PSCB accounting, accumulated history. Fork gets new magic/id, old grants fail, no quorum, no insurer acceptance. Use is cheaper than rebuild.

## 9. Binance prevention mapping

- Fake Homebrew hash not in allow-list -> deny at guard, before deploy token exists.
- Assignment repo setup execution hash mismatch -> deny.
- B -> A/C lateral via AI tool -> cross_principal deny, delegation ancestry fails.
- Stolen deploy token alone -> no valid capability without fresh context + nonce.
- 50 pre-signed burst -> velocity + per-owner window cap refuse by name, high-value needs second approver.

## 10. Phase plan

- Phase 1 (this file): design lock.
- Phase 2: core `guard.rs` + portable + policy decide, unit tests.
- Phase 3: node API + MCP + worker shims, api integration tests, clippy + build + full workspace tests per AGENTS.md.
- Phase 4: operator guides (`wallet-safety.md` pattern), vectors, final report update.
