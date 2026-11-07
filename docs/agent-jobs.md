# Agent-to-agent job escrow

A research agent hires a data agent: payment locks in escrow, work is
verified on delivery, release pays exactly that result. On dispute the funds
stay locked until the arbitrator decides.

## Flow

```
POST /v1/jobs/open                 hirer locks payment + posts the job
                                   (hirer BLS-signs every term: open_hash)
POST /v1/jobs/{id}/accept          worker commits (signature over the job id)
POST /v1/jobs/{id}/deliver         worker posts result hash, worker-signed
                                   over (job id, result) + optional receipt
POST /v1/jobs/{id}/resolve|release hirer/arbitrator releases against the result
— or —
POST /v1/jobs/{id}/dispute         hirer, worker or arbitrator freezes funds
POST /v1/escrow/{id}/release       refused while held (escrow_held)
POST /v1/escrow/{id}/settle        refused while held; no auto-refund either
POST /v1/jobs/{id}/resolve         arbitrator signs (job, pay|refund, result);
                                   hold lifts; coin moves via escrow release/settle
GET  /v1/jobs/{id}                 record + escrow state + held flag
```

Result binding is the point: `release` against a delivered job refuses a
mismatched hash — the release pays for *this* dataset, not any dataset. The
resolve signature binds (job id, direction, result hash) to the arbitrator
key the escrow named at open, so no other key can decide. The same binding
runs at every step: `open` needs the hirer's signature over all terms (no
one can open escrow-backed jobs in someone else's name), `deliver` needs the
worker's signature over (job id, result) — the `accept` signature over the
bare job id is not accepted as delivery authorization — and a receipt naming
a different result is refused rather than filed alongside.

Dispute locks are node-enforced (`held_escrows`, persisted in `state.bin` —
currently envelope v7): release, settlement binding and the timeout
auto-refund all refuse while
a job is disputed. An unresponsive arbitrator cannot be distinguished from a
slow one by the machine — expiry policy says the hirer should pick
arbitrators with live tooling, and jobs carry deadlines regardless. Job
identity includes the funding nonce, so two opens with identical terms but
different funding are different jobs.

## Receipts on every payment

Machine-verifiable receipts already exist (`ServiceReceipt`: issuer-signed,
bound to payment id, recipient, amount, service). The node cannot sign for a
provider, so the guarantee is structural: `GET /v1/payments/{id}/receipt_status`
reports `{recorded, receipt_present, settlement_tx}` and agents poll it —
treating a payment as complete before its receipt appears is a client bug,
and the endpoint makes that check one call.

## Capacity discovery (DePIN)

Jobs assume the hirer already knows a worker. `templates/srct_depin.py`
closes that gap: providers advertise surplus compute — datacenter GPU,
home CPU, NPU box, or a solar-powered edge device — with units, unit
price, and expiry on a local JSON board (`advertise`); consumers filter
by unit, price, device class, or renewable-only (`discover`, cheapest
first) and take the best fit plus the payable L2 task shape (`match`).
Discovery commits nothing and custody never enters the picture — money
moves only through the task economy's verified-work certificates, so an
offer that cannot deliver simply never earns. This is the intrinsic-demand
story: real compute buys and sells for SRCT, not speculation.
`python templates/srct_depin.py --selftest` exercises it offline.

## Shared memory without bloating L1

Agents need memory — past interactions, context windows, agreed facts —
and L1 UTXOs are the wrong place for it. `templates/srct_memory.py`
keeps a hash-chained log beside the chain: `append` writes one entry
committing to the previous tip, `sync` merges a peer's entries by hash
(union semantics — two agents exchanging entries converge with no
server, forks refused, duplicates collapsed), `verify` re-checks every
link fail-closed, and `anchor` returns the tip hash. Agents attach the
tip to task results and VWC attestations, so verifiers and the policy
engine release funds against memory proven continuous, not merely
claimed. Hashes travel, megabytes do not — the shared brain without the
chain bloat. `python templates/srct_memory.py --selftest` exercises it
offline.
