# A safer agent wallet

The agent wallet is safer than a normal crypto wallet by construction: every
spend is policy-governed, every grant is owner-signed, every payment is
replay-safe, and every event is auditable. This page is the operator and
developer guide to the safety layer.

## Layers

1. **Spend policy** (`agent::SpendPolicy` + `PolicyBook`): per-transaction
   cap, tumbling window + cumulative cap, recipient and service allow-lists
   (empty allows nothing), validity heights, strict nonce increase, owner
   revocation, delegation narrowing. Fail-closed and ordered; nothing mutates
   on refusal.
2. **Session budget** (`safety::SessionBook`): the per-agent aggregate across
   rotated policies. A policy rotation starts a fresh policy window by design;
   the session book stops spend being split across N policies. Enforced in
   `POST /v1/payment/submit` and the x402 settle path when configured:
   `SRCT_SESSION_WINDOW_BLOCKS` + `SRCT_SESSION_CAP_SAT` (both zero =
   gate off, policy windows only).
3. **Risk checks** (`safety::RiskPolicy`): high-value human approval
   (`SRCT_HIGH_VALUE_THRESHOLD_SAT`), per-payer velocity cap
   (`SRCT_MAX_PAYMENTS_PER_PAYER`), mainnet guard in test mode
   (`SRCT_TEST_MODE=1` refuses `srct/mainnet` spends). At or above the
   threshold the payment is **refused** (`403 human_approval_required`)
   until a key listed in `SRCT_HIGH_VALUE_APPROVERS` co-signs the payment
   hash (`approval_sigs_hex` + `approval_keys_hex` on submit and x402
   settle; the payer's own key does not count). `0` disables the threshold
   entirely — in that shape the response flag never fires either.
4. **Idempotency**: `PaymentTracker` (exact replay → `duplicate: true` before
   admission, so a retry never double-reserves), `ReceiptBook` (same receipt
   → `duplicate`; different receipt for the same payment → `receipt_conflict`
   409), strictly increasing policy nonces. A network timeout can be retried,
   never rebuilt: check `GET /v1/payments/unsettled` first.
5. **Pre-sign wallet guard** (`x402::X402Budget::check_guarded`): the budget
   (amount, recipient/service allow-lists) *plus a short window* — the spend
   must land before its expiry, and the window is capped at 30 blocks
   (`MAX_GUARD_LIFETIME_BLOCKS`). Runs before any key is used and returns the
   exact grant the agent may sign; over-budget, stale or over-long windows
   refuse before signing, never after. MCP: `wallet.guard`
   (allow / deny / approval-needed).
5. **Receipts + reconciliation**: every admission holds a credit reservation
   until its receipt settles it; reservations release on any failure path.
   `GET /v1/payments/unsettled` lists recorded-but-unbound payments (retry
   these, do not rebuild); `GET /v1/receipts/orphans` lists receipts claiming
   unrecorded payments (investigate, never auto-settle).

## Test mode

Set `SRCT_TEST_MODE=1` on a dev node: `srct/mainnet` spends are refused with
`test_mode` while `mini`/`testnet` work unchanged. No separate binary, no
flag that can leak into prod config unnoticed — the env var is read per
request and exported in `GET /v1/risk/policy`.

## Monitoring (alert on these)

Conservation passing does not mean nothing was stolen — a thief's exit
conserves perfectly. Watch the flows, not just the invariant:

- `GET /v1/conservation`: `exit_window_total_sat` vs `exit_window_cap_sat`
  (a window filling fast is the drain in progress), `pending_exit_sat`
  (queued but unreleased), `joint_overflow` (a clamped sum reads as
  headroom — it refuses instead), and `ok` (any conservation breach stops
  the node from writing).
- `GET /v1/exit/crankable`: `pending` entries carry `reason`s —
  `no_exact_funding_subset_at_current_fee` after a fee spike is normal,
  a sudden wall of crankable large exits is not.
- `GET /v1/metrics`: joint-supply gauges for dashboards; pair with an
  outflow spike alert on the fields above. The node exports the numbers —
  paging is the operator's job, because only the operator knows their
  legitimate exit cadence.

## Audit trail

Every grant, admission, duplicate, refusal, revocation, stream open/settle
and receipt appends to a bounded, hash-chained `AuditLog` (each entry commits
to the previous hash; `GET /v1/audit` reports `chain_valid`). The ring is
in-memory by design — full history lives in the payment/receipt stores it
references. Export:

```bash
curl "$NODE/v1/audit?limit=200"   # newest last, hash chain verified
curl "$NODE/v1/risk/policy"       # thresholds, velocity, test mode, session envelope
curl "$NODE/v1/payments/unsettled"
curl "$NODE/v1/receipts/orphans"
```

For auditors and insurers the chain exports as self-verifying JSON
(`AuditLog::export_json` — entries with hex hashes plus the tip;
`verify_export_json` re-checks links, entry hashes, order from genesis, and
the tip; MCP `audit.verify`). An export that parses but does not verify is
refused — verification travels with the data, not with trust in the node.

## Short-lived enforced grants

High-value approval (`human_approval_required`) gates the amount. Bound
grants gate the *grant itself*: `BoundAuthorization` has the owner sign the
grant hash, the expiry and the exact transaction hash together
(`srct/bound-auth/v1`), with a 30-block lifetime cap. The agent builds the
payment, the owner signs the binding for that payment's hash with a near
expiry, and admission (`service::admit_bound_payment`, MCP
`auth.bind` / `auth.verify_bound`) refuses anything re-aimed at another
transaction or replayed past its window. A stolen authorization settles
nothing.

## High-risk flow (recommended)

1. Set `SRCT_HIGH_VALUE_THRESHOLD_SAT` to the amount that needs a human, and
   list approver keys in `SRCT_HIGH_VALUE_APPROVERS` (comma-separated hex
   owner addresses — hardware or second-channel keys, never the hot key).
   With no env set, mainnet still gates at 10 SRCT
   (`MAINNET_DEFAULT_HIGH_VALUE_THRESHOLD_SAT`): the gate is on unless the
   operator turns it off on purpose (`0` is the documented opt-out).
2. The agent submits up to the threshold freely; at or above it the node
   answers `403 human_approval_required` — the advisory flag is gone as a
   bypass, and the payment is not recorded, reserved or settled.
3. The operator co-signs the payment's `signing_hash` with an approver key;
   the agent re-submits with `approval_sigs_hex` + `approval_keys_hex` and
   the admission records a `payment_approved` audit entry.
4. Velocity and session caps stay on as the backstop for compromised keys.

## Hot wallet caps (recommended)

Keep the hot key small by construction, so one compromise cannot empty
anything that matters:

- One policy per purpose (`purpose: payroll`, `purpose: fees`), each with a
  tight `per_tx_max_sat` and an allow-list naming only its recipients.
- Tumbling windows short (`window_blocks` ~ dozens, not thousands) and
  cumulative caps at a daily loss budget you can state out loud.
- Session caps on (`SRCT_SESSION_WINDOW_BLOCKS` +
  `SRCT_SESSION_CAP_SAT`) so N rotated policies do not multiply the budget.
- The high-value threshold at or below the hot key's loss budget: anything
  bigger needs an approver key that never lives on the agent host.

## Key custody

`wallets.json` is Argon2id + ChaCha20-Poly1305, 0600, atomic write; plaintext
only with explicit `--allow-plaintext-wallet`; the API never signs and never
sees a key. One seed derives every chain (`srct-core/src/hd.rs`: SRCT `jt1`
+ EVM `0x` + BTC bech32; `srct-worker hd-address/evm-sign`) — the same
scalar, per-chain addresses, no new backup to lose. Full flow:
[`docs/xchain.md`](xchain.md). No HSM/seed-phrase import yet for operator
wallets — that is future work, and the policy/session/approval layers above
are what make a file key survivable until then.

Separation that matters operationally, HSM or not:

- Agent hot keys, human approver keys (`SRCT_HIGH_VALUE_APPROVERS`), FX
  issuer keys (`SRCT_FX_ISSUERS`), ramp provider keys and seed/bootnode keys
  must all be different keys, ideally on different machines. One key in two
  roles is how a single compromise becomes a total one.
- FX issuers and ramp providers hold customer funds off-protocol: their keys
  deserve the strongest custody available (hardware signer or threshold
  signing), because a signature from them moves other people's money.
- Approver keys sign rarely and from a second channel — that infrequency is
  what makes an offline or hardware key practical for them.
