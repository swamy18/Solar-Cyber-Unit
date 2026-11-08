# SRCT Treats — Complete Integration Plan

Decisions locked with user: full transferability between agents; owner-signed
gifts for free issuance; fee-based auto-mint as base + capped fee bonus on
verified settlement; decay removed, replaced by per-agent + global caps;
service-layer signed transfer certificates (no consensus change); scope is
Treats completion + integration, global-financial-system work out of scope.

Recorded consequence: transferable + redeemable Treats are a second
spendable value, which retires the old "no second currency / never
transferable" invariant in `README.md`, `docs/treats.md`, and
`srct-core/src/agent.rs` docs. The plan updates those statements instead of
leaving them contradictory.

## Goal

- Disable open Treats mint through any API.
- Exactly two acquisition paths: (1) fee-based auto-mint on verified work /
  fees paid, (2) owner-signed human/system gifts (free).
- Treats are storable, capped, transferable agent-to-agent via signed
  certificates, and redeemable for fee-credit sats (sell path), discounts,
  trial access, and service credits.

## Non-goals (explicitly out of scope)

- No new consensus transaction type; no L1/L2 fork.
- No custody, compliance/KYC, fiat liquidity, or governance redesign.
- No changes to issuance integral, rate anchor, halving, or tail.

## Architecture

- `srct-core/src/treats.rs` stays the ledger authority: balances, nonces,
  source-once ring, fixed weight table, caps, quotes, encode/decode. Add:
  `GiftCertificate` (owner-signed exact gift), `TransferCertificate`
  (sender-signed exact transfer), replay guards, per-agent cap +
  `MAX_OUTSTANDING` global cap, fee-bonus mint calculator, removal of
  `apply_decay` (or leave dead code deleted, not deprecated).
- `Chain::treat_reserve` unchanged (10% PSCB leg, reorg-rewound). Reserve
  only moves on redemption debit (`spend_treat_reserve`) and per-block
  credit. Transfers and gifts never touch the reserve directly; gifts dilute
  the proportional redemption quote automatically.
- Node service layer (`crates/srct-node/src/api.rs`, `SharedNode`):
  auto-mint hooks, gift/transfer verification + application, single-use
  redemption vouchers consumed by fee paths, persistence, metrics.
- Surfaces: `srct-worker` + `templates/srct_agent.py` show balance and
  redeem; MCP exposes `treats.balance` / `treats.redeem` (no mint); x402
  responses and job/trial flows surface Treats earned and accept vouchers.

## Data flow

1. Fee-based: receipt accepted (`receipt_submit` → `ReceiptBook::accept`)
   or VWC/settle observed → node builds `TreatEvent` (source = receipt_id /
   VWC id, never caller-supplied) → `TreatLedger::commit` with
   `mint = base + min(fee_units, FEE_BONUS_CAP)` → balance up, outstanding
   up. Duplicate source refused. Dispute loss slashes to zero.
2. Gift: human signs `gift(recipient, amount, nonce, expiry, network)` →
   `POST /v1/treats/gift` verifies owner signature, expiry, nonce freshness,
   cap headroom → mint to recipient, record nonce in persisted replay guard.
3. Transfer: sender signs `transfer(recipient, amount, sender_nonce,
   expiry, network)` → `POST /v1/treats/transfer` verifies, checks balance,
   applies debit/credit atomically, records nonce. Certificates verify
   offline anywhere (portable, like `portable-policy.md`).
4. Redeem/sell/spend: `POST /v1/treats/redeem {agent, treats, kind}` burns
   Treats, debits reserve by `redeem_quote`, and issues a single-use
   voucher `{voucher_id, value_sat, kind, expiry}` for `fee_credit` /
   `discount` / `trial` / `service_credit`. Fee paths (`payment_submit`,
   stream settle, trial repay, aggregate quotes) accept + consume the voucher
   id exactly once (persisted consumed-voucher set).

## Security

- Every mint/transfer/gift path verifies signatures against the claimed
  owner/sender key bundle; stranger signatures refused before state checks.
- Strictly increasing nonzero nonces per sender/giver + persisted replay
  guards (survive restart); duplicate source per subject refused.
- Network binding on every certificate; wrong-network refused.
- Fee-bonus capped per event; wash-trade farming bounded by real fees paid
  + caps + dispute slash. Gift amounts bounded by per-gift cap + giver
  window cap.
- Checked arithmetic everywhere; reserve exhaustion refuses (never mints).
- State growth bounded: subject cap, source ring, nonce/guard caps, voucher
  set pruned on expiry. `state.bin` grows by bounded sections only.

## Tokenomics (unchanged funding, new sinks)

- Funding: 10% of each block's PSCB leg → `treat_reserve` (cap 20%).
  Invariant `burned + pscb_retained + bsaver + treat == full_base` holds.
- Sinks: redemptions debit the reserve; transfers/gifts move claims, not
  sats. Redemption quote `treats * reserve / outstanding` (floored) means
  free gifts dilute value per Treat rather than draining fixed value.

## Integration strategy (ordered tasks)

1. Core ledger (`treats.rs`): gift + transfer certificate types with
   sign/verify, nonce + replay-guard stores with encode/decode, per-agent
   cap + global outstanding cap enforced in `commit`/gift apply, fee-bonus
   calculator, delete `apply_decay` and decay constants, unit tests
   (round-trip, replay, cap refusal, slash, quote).
2. Disable open mint: remove `POST /v1/treats/mint` route (or return 410
   gone); keep handler compiled out via removal, not a flag. Add
   `POST /v1/treats/gift`, `POST /v1/treats/transfer`, extend
   `POST /v1/treats/redeem` with voucher kinds.
3. Auto-mint hooks: receipt-accept path and VWC/settle observation path
   construct events internally (no caller kind/source). Keep kinds
   `verified_work`, `service_completed`, `payment_completed`,
   `dispute_won`, `dispute_lost`.
4. Voucher consumption: single-use voucher store (persisted, pruned);
   wire into `payment_submit`, stream settle, trial repay, aggregate-quote
   discount. One voucher → one consumption, double-spend refused by id.
5. Persistence: `state.bin` v12 (ledger + nonce guards + voucher set);
   migrate v11 with empty new stores; network-mismatch refuses.
6. Surfaces: worker balance/redeem commands, template polling, MCP
   `treats.balance`/`treats.redeem`, x402/job/trial response fields.
7. Reporting: `status` / `conservation` / `/metrics` add outstanding,
   subjects, voucher liability (reserved sats).
8. Docs: rewrite `docs/treats.md` (transferable design, two acquisition
   paths, caps, vouchers), update `README.md`, `SPEC.md` §8 note, and the
   retired "never transferable" statements.

## Failure modes

- Reorg: reserve rewinds; ledger/vouchers are node-local and unaffected —
  document per-node divergence; certificates stay verifiable.
- Restart: all guards/vouchers persist; no replay resurrection.
- Reserve empty / cap hit / voucher expired or reused: refuse by name,
  mutate nothing.
- Cross-node balance disagreement: expected (service layer); reserve and
  UTXO set remain the cross-node truth.

## Validation

- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo build --workspace`
- `cargo test -p srct-core --lib treats` plus receipt/VWC-adjacent suites
- `cargo test -p srct-node --test api` (full file)
- New tests required: gift/transfer round-trip + forgery refusal, nonce
  replay across restart (encode/decode), cap refusals, voucher
  double-spend refusal, auto-mint on receipt fixture without caller input,
  v11→v12 migration with populated ledger.
- `python sim/agent_economy_demo.py` extended to show earn → transfer →
  redeem in one loop.

## Open risks

- Transferability invites farming rings; fee caps + dispute slash + gift
  giver caps mitigate but do not eliminate collusion. Monitor
  outstanding-to-reserve ratio and per-subject velocity.
- Proportional quote means early Treats are worth more per unit when gifts
  expand outstanding; communicate redemption value as floating, not fixed.
