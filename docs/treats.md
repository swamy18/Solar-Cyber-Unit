# SRCT Treats

Non-transferable dopamine reward claims for AI agents, machines and robots.
Third value component next to liquid SRCT (UTXO) and committed SRCT (L2
escrow): Treats never live in the UTXO set, are never transferable, and are
never spendable as coin.

## Funding

Each block's base-fee portion splits 50/50 into burn and the PSCB leg. The
leg subdivides, all integer-floored:

```text
full_base -> burn (ceil 50%) + PSCB leg (floor 50%)
PSCB leg  -> retained PSCB + B-Saver (5%, cap 10%) + Treats (10%, cap 20%)
```

Invariant: `burned + pscb_retained + bsaver + treat == full_base`.
`Chain::treat_reserve` is credited per canonical block and rewound per
rolled-back block, checked by `verify_canonical_chain`, and counted in
`base_removed_total` (net-supply reporting). Redemption never mints: an
empty reserve refuses.

## Mint (service layer, `srct-core::treats`)

`TreatLedger` is node-local, keyed by `AgentId`, accumulator-chained with a
bounded per-subject source ring (one source counts once). Weights are a
fixed table in code — an event carries no amount and no weight:

| Event | Base Treats |
|---|---|
| VerifiedWork | 20 |
| ServiceCompleted | 5 |
| PaymentCompleted | 5 |
| DisputeWon | 10 |
| DisputeLost | 0 + balance slashed to zero |

Dopamine shaping, integer-only: novelty damps repeats with the same
counterparty (floor 10%), streak adds up to +50% for consecutive verified
epochs, and balances decay 1% per 1,000 blocks of inactivity.

## Redemption

Burn Treats, receive fee-credit sats at the proportional quote:

```text
payout_sat = treats * treat_reserve_sat / outstanding_treats (floored)
```

`payout_sat == 0` or above the reserve is refused. No transfer endpoint
exists by design.

## API

- `GET /v1/treats/balance/{agent}` — balance, lifetime earned/redeemed, streak, outstanding, reserve.
- `POST /v1/treats/mint` — `{agent_hex, kind, source_hex, height?}`; kinds `verified_work`, `service_completed`, `payment_completed`, `dispute_won`, `dispute_lost`.
- `POST /v1/treats/redeem` — `{agent_hex, treats}`; burns and pays from the reserve.
- `GET /v1/treats/reserve` — reserve, outstanding, subjects.
- `status`, `conservation`, `/metrics` also report `treat_reserve_sat`.

## What Treats are not

Not a currency, not a UTXO asset, not consensus money. Consensus tracks
only the backing sat reserve; balances are this node's view (persisted in
`state.bin` v11) like reputation. A fork or another node may disagree on a
balance; no node can disagree on the reserve.
