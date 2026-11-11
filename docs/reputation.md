# Portable agent reputation

An agent's verifiable history — tasks done, payments made, disputes,
refunds, loans repaid or defaulted — travels with the agent, and any service
can price or gate access from it.

Scope: passport batches and scores are per-node books, not consensus — two
honest nodes can score the same agent differently (different books, different
issuers seen). A score is that node's opinion, never a chain fact. Services
that gate on scores should read them from a node they operate.

## How it works

1. The agent works: receipts record task completions and payments, credit
   positions record repayments and defaults (`GET /v1/reputation/passport/attest`
   assembles the subject's events from node books).
2. An issuer (marketplace, service, lender) that verified the events signs a
   `PassportBatch` (`POST /v1/reputation/batch`). The node re-verifies every
   payment and loan source against its own books before storing it — and
   binds each event to it: the subject must be the payment's agent (or the
   loan's borrower), the counterparty the other side, and the amounts must
   match, so real-but-unrelated history cannot inflate anyone's score;
   task/dispute/refund kinds are issuer-attested. On an exposed API, the node
   refuses registration unless `SRCT_PASSPORT_ISSUERS` contains a trusted
   issuer key. Loopback-only development nodes may accept any valid signer.
   The node-local batch book is capped at 4,096 entries; a duplicate batch is
   idempotent.
3. Any service combines live batches into one score + tier
   (`GET /v1/reputation/score/{agent}?role=machine` → `Deny | Throttled |
   Standard | Preferred`).

## Why it resists sybils

- History costs money: every positive event is backed by a real payment, a
  settled receipt, posted collateral or a repaid loan. Minting N fresh
  identities means funding N histories.
- Repeat business dampens: events with one counterparty count as the integer
  square root of their count. Two colluding parties farming receipts between
  fresh ids gain ~10x less than genuine diverse work (see
  `passport::tests::farming_one_counterparty_dampens`).
- Stake-backed events weigh more: a repaid collateralized loan (+4) outweighs
  a bare task completion (+1).
- Negatives are sticky and never dampen: dispute lost (−4), default (−8). One
  default zeroes any suggested credit limit.

Deliberately not used: wallet age and raw transaction count — both are free
to fake. `credit` never reads a score (positions stay collateralized); the
score prices risk, it never guarantees repayment.

## Tiered wallets (max-spend / min-spend)

A user funds one agent (say 500 SRCT) and splits spend power: a max-spend
tier (20/tx for trusted services) and a min-spend tier (1/tx for
experiments). Tiers are narrowed child policies (`tiers::build_tier_pair`),
so a tier can never exceed its parent — caps, recipients, services, window.
They nest (min under max under the root) because delegation names one child
per parent; revoking the root stops the whole tree, and a short expiry makes
a temporary spending key without any revocation round-trip.

The ancestry itself travels: `DelegationProof` is the root-first chain of
signed policies any service verifies (`delegation.verify`), so a tiered
agent proves its whole lineage to whoever it pays. Interface:
[`portable-policy.md`](portable-policy.md).

```bash
curl -X POST $NODE/v1/wallet/tier -d '{"parent_policy_hex":"...","parent_sigs_hex":"...","parent_keys_hex":"...","tier_policy_hex":"...","tier_sigs_hex":"...","tier_keys_hex":"..."}'
curl $NODE/v1/wallet/tiers/<agent_hex>   # tiers under an agent id
```
