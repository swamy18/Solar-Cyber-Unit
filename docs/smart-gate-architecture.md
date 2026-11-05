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
policy   = H(DOM_GP || ... || requires_approval || approver || workload_id || workload_key)
cap      = H(DOM_G || policy_hash || action_hash || context_hash || expiry || nonce || audience)
action   = H(DOM_A || preimage)          // recomputed at the boundary, never trusted in
context  = H(DOM_C || effective_workload || height)
signed   = version || cap || sigs || keys // owner's signature over cap.signing_hash()
approval = H(DOM_P || policy || cap || agent || action || context || expiry) + approver sigs
cred     = H(DOM_W || policy || cap || action || context || nonce || height) + workload sigs
```

- `policy_hash`: owner-signed narrow grant, network-bound, revocable. Empty allows nothing. The grant carries the risk model: `requires_approval` (high-assurance bit), `approver` (independent second-channel address), `workload_id` (bound workload, zero = unbound). All three are covered by the grant signature, so they cannot be added or stripped after issuance.
- `action_hash`: SHA-256 over the domain tag and the **exact preimage bytes** about to execute (deploy digest or payment payload). The boundary recomputes it (§5).
- `context_hash`: workload id + height, recomputed by the verifier from the *effective* workload — the grant-bound id when the grant names one, so a caller-supplied id is ignored for bound grants.
- `expiry`: short, max 30 heights from the check height (`MAX_CAP_LIFETIME`). Enforced by verifier, re-checked at admission. Heights, not wall-clock: `guard.rs` is pure and deterministic — no clock, no I/O.
- `nonce`: strictly increasing per grant, **nonzero** (`ZeroNonce` refusal). `PaymentTracker` pattern reused.
- `audience`: enforcing-node scope. Zero means unscoped (admittable anywhere — the documented multi-node caveat); non-zero means only the node configured with that audience admits it.
- `sigs`/`keys`: the owner's hybrid signature bundle (`1+2+3` accepted) over the capability hash, with the keys binding to the grant's `owner` address. The signature covers all six fields together, so none of policy, action, context, expiry, nonce or audience can be swapped after signing.

Verify is stateless exact match plus signature plus grant risk-model validity. Commit is stateful nonce + window spend in `GuardBook`.

Three exacts must coincide: prior intent, present bytes, present moment. Missing one denies. No fuzzy match, no learning bypass.

### What `SignedCapability::verify` checks, in order

Version, owner binding (`keys.address() == policy.owner`), bundle signature over the capability hash, then that the capability names this grant. Unsigned envelopes, stranger signatures, and tampered fields all refuse as `UnsignedCapability` / `PolicyMismatch` — never as allow.

### Workload possession, not just workload binding

Binding a `workload_id` stops the caller from swapping ids, but it does not
authenticate the process. `workload_key` is the fingerprint of a workload
identity key the owner pins in the grant
(`workload_key_fingerprint(keys)`); the executing process proves possession
with a `WorkloadCredential` — a fresh signature over the exact admission
transcript (grant, capability, action, context, nonce, height), built at
execution time and valid only at that height. Verification lives inside
`authorize_signed` through the single shared rule
(`check_workload_credential`), so possession is part of the decision, not an
adjacent check. Missing, forged, mismatched or stale credentials deny before
any nonce is consumed. Legacy zero-key grants require no proof (documented as
unauthenticated). The rule is enforced identically by the portable pre-check,
the node routes, MCP, and the worker execution boundary.

### Risk classification is owner-set, never caller-set

The request's `high_risk` flag can only escalate a low-assurance grant into `needs_approval`; a `false` from the caller never de-escalates a high-assurance grant, because every boundary ORs the grant's `requires_approval` bit with the caller's flag. An attacker submitting `high_risk: false` for a dangerous operation still gates. Misconfigured high-assurance grants (no approver, owner as approver, agent as approver) fail closed with `SelfApproval` on every admission path and at grant registration.

## 4. Protocol

1. Enroll: owner signs narrow grant offline, registers via `POST /v1/guard/grant` (owner signature mandatory — no signature, no authority; misconfigured high-assurance grants refused at registration). Revoke via `POST /v1/guard/revoke` kills the grant **and every registered descendant** (§6).
2. Guard: workload calls `guard.check` (stateless) before any key is used. Budget + allow-list + window checked. Returns allow or refusal; unsigned/forged capabilities refused by name.
3. Issue: owner signs a capability bound to the exact action preimage. Long-term token never leaves vault. The workload identity key (when bound) stays with the executing process.
4. Verify: runtime / cloud broker / wallet service verifies offline via `srct-policy` crate (`guard_verify` checks the owner signature + all equalities). No node needed.
5. Settle: receipt + hash-chained audit entry on the enforcing node (`guard_allow`, `guard_needs_approval`, `guard_refused`, `guard_grant`, `guard_revoke`). The audit log is node-local, bounded, and export-verifiable (`audit.verify`); it is **not** anchored to the chain — see §8.
6. Escalate: high-risk calls return `needs_approval` until a signed `GuardApproval` from the grant's *designated approver* — an address the owner named at issuance, independent of the owner — bound to the exact capability instance (grant + capability hash + agent + action + context + expiry), is presented. A missing approval gates; a forged one denies; an owner-signed approval on a grant that names someone else denies. The old boolean is rejected everywhere. Legacy grants that name no approver fall back to the owner (self-managed, documented as weaker — not second-channel).

## 5. Data structures

- `InfraPolicy`: caps, validity heights, parent link, revocation flag, plus the owner-set risk model (`requires_approval`, `approver`, `workload_id`, `workload_key`). Current layout version 2; v1 bytes still decode with legacy defaults (no mandated approval, owner approves, unbound workload, no key proof) and re-serialize byte-identically, so v1 hashes and signatures stay stable. `validate()` refuses a v1-marked grant carrying v2 fields rather than silently dropping them. Same narrowing shape as `SpendPolicy`, domain tag `srct/guard-policy/v1`. Grants live in the node's registry (cap `MAX_GUARD_REGISTRY = 1024`, refusal when full).
- `Capability`: policy_hash, action_hash, context_hash, expiry, **nonzero** nonce, `audience` (zero = unscoped).
- `SignedCapability`: version + capability + owner `sigs`/`keys` bundles. This is the only form `cap_hex` takes on every boundary (node, MCP, `srct-policy`): raw capabilities are refused as "not signed". Only the current envelope version decodes.
- `GuardApproval`: policy_hash, cap_hash (= capability signing hash), agent_id, action_hash, context_hash, expiry + **designated-approver** `sigs`/`keys` over `srct/guard-approval/v1`. Lifetime cap 30 heights. Authority is the grant's approver address (owner-named, enforced distinct); legacy zero-approver grants fall back to the owner.
- `WorkloadCredential`: policy_hash, cap_hash, action_hash, context_hash, nonce, height + workload-identity `sigs`/`keys` over `srct/guard-workload/v1`. Proves possession of the grant's `workload_key` for this exact admission at this exact height; stale (other-height), mismatched, or forged credentials deny. Only the current envelope version decodes.
- `Decision`: allow / needs_approval (missing approval) / deny(reason). Reasons named: `hash_mismatch`, `expired`, `nonce_reuse`, `zero_nonce`, `unsigned_capability`, `bad_approval`, `bad_credential`, `self_approval`, `wrong_audience`, `action_mismatch`, `context_mismatch`, `cross_principal`, `velocity_exceeded` (`window_exhausted`), `session_cap`.
- `Receipt`: audit entries per decision on the enforcing node. Duplicate receipt for same cap is `duplicate` semantics at the payment layer; conflicting receipt is `receipt_conflict`.

All LE encoding, JSON portable form version 1 with hex fields. Canonical bytes equal signed bytes. The raw unsigned admission path (`GuardBook::authorize`) was deleted: the only authorization entry point is `authorize_signed`, so no integration can bypass signature verification.

## 6. Replay, revocation, and authoritative state

- **Nonce discipline.** Nonce 0 is refused. Every admission requires `nonce > last_nonce` (strictly increasing from a `last_nonce = 0` start). Consumed nonces live in the persisted `GuardBook`; a replayed nonce is a named deny, and a refused call commits nothing (no budget consumed, no nonce stored).
- **Overflow safety.** Window-end arithmetic uses `checked_add` (overflow denies instead of wrapping); spend counters use `checked_add`; time-window and lifetime math uses `saturating_sub` with explicit caps. Codec paths are bounded before allocation (`MAX_GUARD_BOOK_READ`, registry cap, per-field hex caps).
- **Revocation.** Two sets, one authority: the node's `guard_registry` (grants it enforces) and `guard_revoked` (hashes it has killed). `guard_decide` (stateless) consults the node's revocation set even though it commits nothing. `guard_authorize` (stateful) requires the capability to name a registered, unrevoked grant. Revocation propagates to registered descendants via the parent-agent walk, and each killed grant's book state is forgotten so a restart can neither resurrect spent nonces nor replay them — the revocation set itself persists in `state.bin`.
- **Restart and multi-node.** Grants, revocations and the capability book persist in `state.bin` (v10 sections; decode is bounded and fail-closed; v1 grant bytes decode with legacy risk defaults). The node's registry + revocation set + book is **authoritative per node**. Local MCP `GuardBook` state is a non-authoritative cache for keyless pre-checks — never present it as global. Multiple nodes reach the same answer by (a) publishing the grant on the L2 `Policy`/`PolicyRevoke` path and registering the same owner-signed bytes on each enforcing node, and (b) replicating revocations the same way. There is no cross-node nonce lock; the mitigation is owner-set audience scoping: a capability scoped to node A denies on node B by name (`WrongAudience`), while unscoped (legacy) capabilities remain independently admittable everywhere — which is why high-value capabilities should be scoped.
- **Workload binding.** When a grant names a `workload_id`, every boundary recomputes the context from the bound id and ignores any caller-supplied id — a spoofed presented id can neither help nor hurt. Unbound (legacy) grants trust the presented id, documented as weaker: bind the workload for anything that matters.
- **Delegation.** A grant's `parent_agent_id` names its parent; narrowing follows the same attenuation rule as spend policies, and revocation of an ancestor kills every registered descendant (see the walk in `guard_revoke`). Cycle safety comes from one-way agent derivation; the walk itself is hop-bounded and fail-closed.

## 7. Trust boundaries

- **Stateless pre-check vs stateful admission.** `guard.check`, `srct-policy::guard_verify` and `POST /v1/guard/decide` verify signatures, grant risk-model validity, workload possession (when the grant binds a key), and equalities and commit nothing; risk is owner-set OR caller-escalated, and bound grants recompute context from the bound workload. `guard.authorize` / `POST /v1/guard/authorize` additionally recompute the action hash from the supplied preimage, enforce audience scoping, the tumbling-window budget and the strictly increasing nonce, and commit on allow. Final authorization is the execution boundary (`GuardBook::authorize_signed` on the enforcing node or the runtime that recomputes), never an API pre-check. The in-process reference boundary is the worker SDK's `GuardGate::execute` (`srct-worker/src/guard.rs`): it recomputes the canonical preimage from the exact work about to run, admits through the gate, and only then invokes the inner executor. Managed-cluster admission webhooks remain planned, not implemented.
- **Authority before execution.** `GuardGate::execute` asks its `RevocationAuthority` on every run, before the local book and before the executor (`NodeDecideAuthority` replays node `POST /v1/guard/decide` against the authority's live state). A stale answer forgets the grant's local accounting (mirroring node revoke semantics) and denies; an unreachable authority denies without touching local state. There is no offline fallback and no cached-allow: a worker cut off from its authority stops executing gated work. TOCTOU residual: a revocation landing between the authority check and execution stops the *next* execution, not this one — documented, no cross-node lock claimed.
- **MCP credential protection.** The MCP HTTP client dials `host:port` only (no scheme, userinfo, or path). Loopback is trusted by default and is the **only** target that ever receives the `SRCT_API_TOKEN` bearer. Anything else is refused as `untrusted_endpoint` unless the exact `host:port` is listed in `SRCT_MCP_TRUSTED_ENDPOINTS` **and** `SRCT_MCP_ALLOW_REMOTE=1` is set — and even then the bearer is never sent over this plaintext transport. Mixed loopback/non-loopback DNS answers (rebinding shape) are refused; redirects (3xx) are errors, never followed; endpoint values and tokens never appear in error strings or logs. Remote operators must terminate TLS in front of the node; this client does not do HTTPS.
- **Audit.** Every grant, allow, needs-approval, refusal and revocation appends to the node's bounded hash-chained `AuditLog` (`chain_valid`; `GET /v1/risk/policy` exports the live envelope). The chain exports as auditor/insurer-readable JSON (`AuditLog::export_json`, re-checked by `verify_export_json`, MCP `audit.verify`). Audit is node-local persistence, not consensus and not chain-anchored.

## 8. What is implemented, partial, and planned

- **Implemented:** owner-signed grants and registration; signed capabilities end to end (core, `srct-policy`, MCP, node, worker); owner-set risk classification (caller escalates, never de-escalates); independent-approver model with self-approval refused at registration and admission; signed high-risk approvals with missing-vs-forged-vs-wrong-approver distinction; workload proof-of-possession credentials verified inside admission on every boundary; authority-before-execution in the worker (`NodeDecideAuthority`, no offline fallback, forget-on-revoke); execution-boundary action recomputation (node, MCP, worker `GuardGate`); workload binding with caller-supplied ids ignored for bound grants; audience scoping (`SRCT_GUARD_AUDIENCE`, enforced at node admission); strict nonzero monotonic nonces with persisted books; revocation with descendant propagation and restart-safe persistence; explicit v1/v2 compatibility (v1 decodes, authorizes with legacy semantics, re-serializes byte-identically; unknown versions refuse loudly); registry/book capacity caps with refusal; overflow-safe window arithmetic; stateless/stateful separation; MCP endpoint trust gate with no-token-to-untrusted rule and no-redirect rule; audit logging of every gate decision with verifiable export; negative tests for forgery, fake approval, wrong approver, de-escalation, impersonation, stale credentials, missing proof, revocation-at-authority, unreachable authority, action swap, workload spoofing, wrong audience, replay, revocation, unsupported versions, malformed envelopes, and untrusted endpoints. The raw unsigned `GuardBook::authorize` no longer exists.
- **Partial:** grant ancestry is a parent link plus revocation propagation, not a full portable delegation-proof chain like spend policies; multi-node consistency is replication-by-operator plus owner-set audience scoping (publish + register everywhere; scope a capability to one node to deny its replay on others), not a consensus lock — unscoped capabilities remain independently admittable everywhere, stated honestly; the authority check and execution are two steps (a revocation landing between them stops the next execution, not the current one); MCP remote operation is dial-but-unauthenticated by design (plaintext client) — production remote use needs a TLS-terminating proxy, at which point the bearer model must be revisited.
- **Planned (not implemented):** managed-cluster (k8s) admission webhooks and cloud-broker shims; TLS in the MCP/worker HTTP clients; any chain anchoring of audit receipts; cross-node capability locks; hardware-backed workload identity (TPM/TEE quotes instead of software keys).

## 9. Code map

- `crates/srct-core/src/guard.rs`: `InfraPolicy` (v2 risk model + `workload_key`), `Capability` (+ audience), `SignedCapability`, `GuardApproval` (designated approver), `WorkloadCredential` + `check_workload_credential` (single possession rule), `derive_action_hash` / `derive_context_hash`, `GuardBook::authorize_signed` (the only entry point; raw `authorize` deleted), tests for forgery/fake-approval/wrong-approver/de-escalation/impersonation/stale-credential/swap/spoofed-workload/wrong-audience/zero-nonce/v1-authorize/v1-stability/unsupported-versions/malformed-envelopes.
- `crates/srct-policy` (`guard_verify` / `guard_verify_full`): stateless signature + risk-model + binding + possession pre-check; denies unsigned envelopes and self-approval grants.
- `crates/srct-mcp` (`guard.check` / `guard.authorize`, `http_json` trust gate): signed pre-check with owner-set risk + optional `workload_cred_hex`; preimage-recomputing admission with credential passthrough; `approved:true` rejected; scoped caps refused locally; loopback-only bearer.
- `crates/srct-node/src/api.rs`: `POST /v1/guard/decide` (pre-check + revocation-set consult + audience + optional credential), `POST /v1/guard/grant` (owner-signed registration, risk-model validation, registry cap), `POST /v1/guard/revoke` (owner-signed, descendant propagation), `POST /v1/guard/authorize` (signed + preimage + designated approval + optional credential, `SRCT_GUARD_AUDIENCE` scoping, audit).
- `crates/srct-worker/src/guard.rs`: `GuardGate::execute` — authority-first (`RevocationAuthority`, `NodeDecideAuthority`), possession auto-proof from the provisioned workload key, then local admission, then executor; forget-on-revoke, no offline fallback. `templates/`: k8s admission shim, cloud broker shim, EVM facilitator shim (follow-up).
- Tests: core `guard` unit tests, `srct-policy` verify tests, `srct-mcp` guard + credential + transport tests, node `api` round-trips (grant → signed authorize → replay deny → revoke → dead; owner-set-risk/independent-approver; key-bound credential over HTTP), worker `guard` execution tests (revocation-at-authority, unreachable authority, possession), `state_persist` book round-trip via the signed boundary.

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
