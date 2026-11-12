# AI Work Graph

`srct-workgraph` turns useful AI computation into reusable, attributable,
revenue-sharing artifacts. An artifact records content hashes, its owner, its
lineage (parents) and its license; deriving from an artifact is a use, and
revenue on the child flows upstream as royalties automatically.

## What it is

```
Artifact = version || network || kind || owner || model || input ||
           runtime || result || evidence || parents || license ||
           created_height || nonce
```

- **Kinds:** training updates, inference results, adapter weights, encrypted
  results, attested executions, ZK-proven results. The `evidence` hash
  points at the issuing crate's proof (VWC id, TEE quote, FHE receipt, ZK
  proof).
- **Licenses:** `reusable` gates derivation; `royalty_bps` (capped at 50%)
  sets the upstream share of each revenue event.
- **Registration** checks signatures, network, existing and reusable
  parents, parents no newer than the child, and replays. Cycles are
  impossible by construction: parents must already be registered and hashes
  commit to the parent list.
- **Settlement** (`settle_revenue`) walks upstream recursively: each artifact
  keeps its share minus its royalty, the pool splits equally among direct
  parents, dust stays with the child owner, and the walk stops after
  `MAX_ROYALTY_DEPTH` (8). Payouts merge per owner, sort by address, and sum
  exactly to the revenue.

## Honest limits

- **Proofs are referenced, not rechecked.** VWC/TEE/FHE/ZK validity belongs
  to the issuing crates; the graph enforces lineage integrity.
- **Content lives elsewhere.** The graph holds hashes; owners store data.
- **Instructions, not coin.** Settlements tell the payment/escrow rail what
  to move; nothing here moves value.
- **Depth-capped.** Ancestors deeper than 8 hops earn nothing from a use.

## Verified behavior

`cargo test -p srct-workgraph` passes 10 acceptance tests: registration and
transitive descendants, signature/owner/network/parent/license checks,
parent-newer-than-child refusal, replay refusal, an exact 3-level royalty
chain (95,000 / 4,000 / 1,000 of 100,000), a 3-parent split with dust kept by
the owner, depth-cap cutoff with exact sums, zero-royalty passthrough, and
wire round-trips with truncation/unknown-kind/over-cap refusals.

## Next milestones

1. Cross-crate evidence verification: check referenced VWC/TEE/FHE/ZK proofs
   at registration instead of trusting the issuer.
2. Content-addressed artifact store with the same caps.
3. Usage oracles: meter real downstream reuse (CNNP metering feeds this).
4. Escrow-rail integration: lock revenue, release per settlement, refund
   leftovers.
