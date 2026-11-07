# SRCT Treats

Transferable reward claims for AI agents, machines and robots. Third value
component next to liquid SRCT (UTXO) and committed SRCT (L2 escrow): Treats
never live in the UTXO set and are never spendable as coin. Value leaves the
system only as satoshis, when Treats are burned and the backing Treat
reserve pays out.

## Acquisition: exactly two paths, both verified

There is no generic mint route. The old `POST /v1/treats/mint` was removed,
so no API can print Treats from nothing.

1. **Fee-based auto-mint.** The node mints by itself when it observes
   verified settlement:
   - an accepted service receipt mints `ServiceCompleted` to the service
     and `PaymentCompleted` to the payer (source = receipt id);
   - `POST /v1/treats/claim-work {task_id}` mints `VerifiedWork` once per
     task when the node's own L2 state holds the VWC (source = VWC id).

   Each mint is base weight plus a capped fee bonus:
   `mint = base + min(fee_sat / 1000, 50)`. Wash trading is bounded by
   real fees paid, per-event caps, and dispute slashing.
2. **Owner-signed gifts.** `POST /v1/treats/gift` applies a gift only with
   the giver's signature over the exact recipient, amount, nonce and
   expiry. Replay (same or lower nonce), forgery, expiry, and cap
   violations all refuse before anything mutates.

Fixed base weights: VerifiedWork 20, ServiceCompleted/PaymentCompleted 5,
DisputeWon 10, DisputeLost slashes the holder to zero.

Request fields for gifts and transfers: `{*_hex, recipient_hex, role?,
amount, nonce, expiry_height, sigs_hex, keys_hex}` with `role` one of
`machine` (default), `human`, `service`. Limits: one gift at most 10,000
Treats, one transfer at most 100,000, holder ceiling 1,000,000, global
outstanding ceiling 500,000,000. Certificates expire within 10,000 blocks.

## Storage and transfers

Treats are storable and accumulate for later use. Growth is bounded, not
decayed: the per-holder and global ceilings above refuse further mints.

Holders move claims with `POST /v1/treats/transfer`: the sender signs the
exact recipient, amount, nonce and expiry. Nonce-per-sender replay guards
persist across restarts, so a transfer certificate spends exactly once and
verifies anywhere.

## Redemption: sell, discounts, trials, credits

`POST /v1/treats/redeem {agent_hex, role?, treats, kind?}` burns Treats,
debits the Treat reserve at the proportional quote
(`payout_sat = treats * reserve / outstanding`, floored), and issues a
single-use voucher toward one benefit kind: `fee_credit` (default),
`discount`, `trial`, or `service_credit`. Vouchers live 1,440 blocks and
spend exactly once: directly via
`POST /v1/treats/voucher/consume {voucher_id, kind?}`, or internally by
trial repay — `POST /v1/trials/repay` accepts an optional `voucher_id` and
a Trial-kind voucher covers part of the L1 repayment.

Free gifts dilute the quote rather than draining fixed value: new claims
raise `outstanding` against the same reserve, so each Treat redeems for
fewer sats. The reserve is never minted into and an empty reserve refuses.

Read the balance with `GET /v1/treats/balance/{agent}?role=` (also in
`status`, `conservation`, `/metrics`, and `srct-worker treats-balance`).

## Money rules

- Funding: 10% of each block's PSCB leg → `treat_reserve` (cap 20%).
  Invariant: `burned + pscb_retained + bsaver + treat == full_base`.
- `Chain::treat_reserve` is credited and rewound per block and re-derived
  by `verify_canonical_chain`. Transfers and gifts never touch it.
- Balances are this node's view (persisted in `state.bin` v12); the
  reserve and the UTXO set are the cross-node truth.
