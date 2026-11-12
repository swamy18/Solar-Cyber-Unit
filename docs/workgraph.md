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

- **Proofs are referenced by default, rechecked on request.** Plain
  `register` trusts the issuing crates; `register_with_evidence` re-verifies
  through `srct-verify` and binds the output to the artifact.
- **Content lives with its owner, cached beside the graph.** The graph holds
  hashes; `ArtifactStore` is the bounded key-is-hash cache next to it.
- **Instructions, not coin.** Settlements tell the payment/escrow rail what
  to move; nothing here moves value. `RevenueEscrow` locks, releases and
  refunds as instructions.
- **Depth-capped.** Ancestors deeper than 8 hops earn nothing from a use.

## Verified behavior

`cargo test -p srct-workgraph` passes 16 acceptance tests: registration and
transitive descendants, signature/owner/network/parent/license checks,
parent-newer-than-child refusal, replay refusal, an exact 3-level royalty
chain (95,000 / 4,000 / 1,000 of 100,000), a 3-parent split with dust kept by
the owner, depth-cap cutoff with exact sums, zero-royalty passthrough,
wire round-trips with truncation/unknown-kind/over-cap refusals, cross-crate
evidence checks (mismatch and fraud refused), a content-addressed store
(key-is-hash, caps, snapshot replay), a metered-reuse oracle counting
verified CNNP receipts exactly once, and a revenue escrow with
per-payout release and exactly-once refund.

## Next milestones

1. Cross-crate evidence verification — **done** (`register_with_evidence`:
   verifies the proof through `srct-verify` and binds the verified output to
   the artifact's evidence hash before lineage checks run).
2. Content-addressed artifact store — **done** (`ArtifactStore`: bounded,
   key-is-hash-of-bytes cache beside the graph with snapshot replay).
3. Usage oracles — **record side done** (`UsageLedger`: verified CNNP
   metering receipts counted exactly once per receipt hash, with per-capability
   and per-provider totals).
4. Escrow-rail integration — **instruction layer done** (`RevenueEscrow`:
   lock revenue once, release per computed payout without ever exceeding the
   locked total, refund the remainder exactly once). Payment-rail execution
   of the payout/refund instructions is next.
