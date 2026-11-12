# Universal cross-network intent settlement

Status: **working non-consensus prototype** in `crates/srct-intent`. It defines
signed intents, competitive quotes, cross-asset conversion routes, delivery
receipts, a lifecycle state machine with timeouts and disputes, and the exact
settlement/refund instructions the existing SRCT payment and escrow layer should
execute. It does not move coins and does not verify another chain.

```bash
cargo test -p srct-intent
cargo run --release -p srct-intent --example intent_demo
```

## 1. The problem

An agent on one network wants work from a provider on another:

- what service and input (hashes),
- a price ceiling and a latency ceiling,
- required verification and privacy,
- accepted settlement assets,
- a deadline and a dispute authority.

Today each network has its own quote/escrow vocabulary. This crate makes the
intent a portable signed object, so SRCT can coordinate the lifecycle while the
actual value stays on the network that holds it.

## 2. Lifecycle

```text
Open --quote*--> accept --> Accepted --delivery--> Fulfilled --settle--> Settled
  |                              |                       |
  |                              |                       +--dispute--> Disputed
  |                              |                                      |
  |                              +--deadline passed--> Refunded         +--resolve--> Settled / Refunded
  +--intent deadline passed--> Refunded
```

Every transition is guarded:

| Transition | Guards |
|---|---|
| `open` | creator signature, valid fields, accepted assets include the max-price asset, deadline not passed, no duplicate intent id |
| `quote` | solver signature, intent is open, one quote per solver, asset accepted, price inside the converted cap, latency/verification/privacy floors, quote unexpired and no later than the intent deadline |
| `accept` | best valid quote or a named solver's valid quote, still within the quote/intent deadline |
| `fulfill` | accepted state, solver signature, matching intent and quote, delivery height not in the future and not past `delivery_by`, non-zero result |
| `settle` | fulfilled state; one settlement only |
| `refund` | open past the intent deadline, or accepted past the delivery deadline |
| `dispute` | fulfilled state, creator-signed challenge, non-zero evidence |
| `resolve` | disputed state, signature from the intent's arbiter, matching evidence; releases to the solver or refunds the creator |

A second delivery, settlement, refund or resolution is refused by state, not by
a flag, so replays cannot pay twice.

## 3. Wire formats and signatures

All objects use canonical little-endian encodings and domain-separated hashes:

```
intent      = creator || service || input || arbiter || max_price ||
              latency || verification || privacy || accepted_assets ||
              deadline || nonce
quote       = intent_hash || solver || price || route? || latency ||
              verification || privacy || valid_until || nonce
route       = router || from || to || numerator || denominator ||
              fee_bps || valid_until || nonce
delivery    = intent || quote_hash || solver || result || height || nonce
dispute     = intent || creator || evidence || nonce
resolution  = intent || arbiter || release_to_solver || evidence || nonce
```

Each is signed with the existing hybrid key bundle and verified against the
named actor's address. A signature over metadata alone is not enough: the
signed hash covers every field, and a delivery names both the intent and the
accepted quote.

## 4. Cross-asset quotes

A quote in the intent's max-price asset needs no route. A quote in another
accepted asset must carry a router-signed route:

```text
affordable = floor(max_price * numerator / denominator * (10000 - fee_bps) / 10000)
quote is valid when price <= affordable and the route is unexpired
```

Concrete example: 1,000 USDC max, route 2 SRCT per USDC with a 10% fee gives
`1,000 * 2 * 0.9 = 1,800 SRCT`; an 1,800 SRCT quote is valid, 1,801 is refused.

Discovery ranking uses the inverse estimate (rounded up) to compare a
cross-asset quote against the intent's max-price asset:

```
cost_in_max = ceil(price * denominator * 10000 / (numerator * (10000 - fee_bps)))
```

That estimate is only for ordering. Settlement uses the quote's actual asset
and amount, never the estimate.

## 5. Settlement and refund instructions

Settlement returns:

```
SettlementInstruction { from: creator, to: solver, amount: quote.price,
                        intent, reference: delivery_hash }
```

Refund returns:

```
RefundInstruction { to: creator, amount: intent.max_price,
                    intent, reason: Expired | Resolved }
```

The existing SRCT payment/x402/escrow path executes these. This crate does not
hold custody and cannot release funds by itself.

## 6. Threat model

**Stopped by the implementation**

- Tampered intents, quotes, routes, deliveries, disputes and resolutions
  (signature and hash coverage).
- A quote over the price cap, over the latency cap, below the verification or
  privacy floor, in an unaccepted asset, or after its expiry.
- A cross-asset quote with a missing, wrong-direction, expired or
  value-insufficient route.
- Two quotes from one solver for one intent.
- A delivery from a solver other than the accepted one, a delivery naming
  another quote or intent, a future delivery, a late delivery or a zero result.
- Double settlement, double refund, or settlement after a refund.
- A dispute from anyone other than the creator, and a resolution from anyone
  other than the intent's arbiter or with mismatched evidence.

**Not provided**

- Actual cross-chain execution. Chain adapters, light clients, proof relayers
  and asset custody are out of scope.
- Atomicity across chains. The design is escrow + instruction; a chain that
  cannot escrow must provide its own adapter guarantees.
- Arbiter selection, staking or accountability. The arbiter is a named address.
- Privacy. Service, input, result and amounts are visible; sealed/FHE
  execution belongs to the CNNP and FHE milestones.
- Partial fills, streaming and multi-provider sharding of one stage.
- Dispute evidence evaluation. The arbiter decides; this crate records the
  decision and enforces the state transition.

## 7. SRCT integration

- `Intent.max_price.asset` and `Quote.price.asset` are opaque `AssetId`s. SRCT
  is one asset id; a stablecoin or a wrapped token is another.
- The returned `SettlementInstruction` is the authorization the existing
  payment/escrow layer consumes; the settlement adapter maps `AssetId` to its
  rail.
- `Verification::{None, ProviderSigned, Optimistic, Tee, Zk}` is enforced at
  settlement: `Tee`/`Zk` intents require verified evidence. The creator or
  arbiter pins expectations (`expect_evidence`: the TEE SLA or the ZK task);
  the solver attaches its proof (`attach_evidence`); the book checks kind,
  worker binding and cryptographic validity through `srct-verify`, then
  `settle` releases. Dispute/resolve stays available as the arbitration
  fallback.
- `Privacy::{Public, Sealed, Tee, Fhe}` is the same seam as CNNP. Only the
  label is enforced here; actual privacy must come from the execution layer.

## 8. Roadmap

1. Persist and replicate the book (state encoding + restart tests).
2. Chain adapters: SRCT escrow binding, external settlement adapters, asset
   route registry.
3. Solver discovery and quote gossip (HTTP/MCP transport).
4. Partial fills, streaming settlement and multi-solver stages.
5. Bonded arbitration and slashing for proven misbehaviour.
6. Verification-level enforcement — **done** (`expect_evidence` /
   `attach_evidence` / settle gate for `Tee`/`Zk` via `srct-verify`).
   FHE-privacy enforcement on delivery is next.
7. End-to-end test with two independent node processes and a real escrow lock.
