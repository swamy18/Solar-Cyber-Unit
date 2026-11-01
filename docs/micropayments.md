# Economical micro-payments

A service should charge an agent per API call, per computation, per dataset
query or per unit of robot work without a separate manual transaction each
time. Three primitives make that economical. None changes consensus; all reuse
`MachinePayment`, `SpendPolicy` and the credit path.

## Benchmark: total cost, not just the fee

Regenerate with `python sim/micropayment_benchmark.py`. Gas constants are
`GAS_TX_BASE=16_000`, `GAS_PER_INPUT=1_000`, `GAS_PER_OUTPUT=250`; fee is
`base_fee * gas` (50% burn / 50% PSCB, tip = excess).

| profile | 1 payment | batch of 10 (1 recipient) | per payment | saved | stream: 100 units |
|---|---|---|---|---|---|
| mini min (10) | 172,500 | 172,500 | 17,250 | 1,552,500 | 1 tx instead of 100 |
| mini initial (100) | 1,725,000 | 1,725,000 | 172,500 | 15,525,000 | 1 tx instead of 100 |
| mainnet min (100) | 1,725,000 | 1,725,000 | 172,500 | 15,525,000 | 1 tx instead of 100 |
| mainnet initial (1,000) | 17,250,000 | 17,250,000 | 1,725,000 | 155,250,000 | 1 tx instead of 100 |

All values in satoshis. Batching merges per-recipient outputs
(`service::aggregate_payments`), so 10 payments to one provider cost one
base fee, not ten. Streaming goes further: N units of work accrue off-chain,
one voucher settles on chain.

Latency follows the same curve: off-chain verify/admit/quote is microseconds
in-process — the confirmation wait (blocks, not code) is the floor, so fewer
transactions is fewer waits. A batched settlement confirms once for N
payments; a stream confirms once for N units of work.

## 1. Batching — `POST /v1/payments/aggregate`

Same payer, N recorded payments → one `PaymentBatch` (per-recipient merged
outputs, shared `GAS_TX_BASE`) → `BatchQuote` prices gas, required fee,
per-payment cost and savings vs N separate transactions at the current base
fee. Read-only: the quote is not a settlement; the operator builds and
broadcasts the batch transaction out of band.

```bash
curl -X POST $NODE/v1/payments/aggregate \
  -H 'Content-Type: application/json' \
  -d '{"payment_ids": ["<hex>", "..."]}'
# → {payer, payments, outputs, total_amount_sat, gas_used,
#    required_fee_sat, fee_per_payment_sat, separate_total_fee_sat, savings_sat}
```

Library: `srct_core::micro::quote_batch` (refuses empty batches, mixed
payers, overflow). Tested in `srct-core --lib micro::` and
`srct-node --test micro_safety`.

## 2. Stream channels — `POST /v1/streams/open|settle`, `GET /v1/streams/{id}`

Open a `PaymentStream` once (rate per block, expiry, hard cap). Each unit of
work mints an off-chain voucher (`micro::voucher_spec` sizes it at exactly
the newly accrued amount; `build_settlement` signs it). Only the last voucher
needs the chain: a `MachinePayment` with `reference` = stream id carries the
final amount through the ordinary submit/receipt path, and the submit binds
the recipient — a stream-bound payment must pay the stream's recipient, so
the voucher accounting and the coin cannot diverge. The `StreamBook`
(single writer: the node) enforces exact, ordered, in-cap settlement —
over/ under-claims and replays are refused by name, and accounting persists
in `state.bin` (currently envelope v9) so a restart cannot double-withdraw.

```bash
curl -X POST $NODE/v1/streams/open   -d '{"stream_hex":"..."}'
curl -X POST $NODE/v1/streams/settle -d '{"stream_hex":"...","settlement_hex":"..."}'
curl $NODE/v1/streams/<stream_id>   # settled_sat, claimable_sat, height
```

## 3. Sponsored transactions — `micro::SponsoredIntent`

A sponsor (faucet, employer, service operator) signs coverage of one batch's
fee: `sign_sponsor_intent(wallet, network, batch, fee_sat, expiry)` binds
sponsor + batch hash + fee + expiry under `srct/sponsor-intent/v1`;
`verify_sponsor_intent` checks network, expiry, batch identity, fee coverage
and signer==sponsor. The coin still moves through the ordinary transaction;
the intent is the auditable fee-attribution record the settler checks before
building. No delegated fee-payer exists at consensus — deliberately, so a
sponsor can never mint authority, only cover a priced quote.

## When to use what

- One-off or rare payments: `POST /v1/payment/submit` as before.
- Many payments, one payer (payouts, per-call billing runs): aggregate first,
  settle once.
- Repeated metered use (API calls, compute, queries, robot work): open a
  stream, voucher per unit, settle the final voucher on chain.
- Onboarding / subsidized use: sponsor signs the batch intent, settler builds.
