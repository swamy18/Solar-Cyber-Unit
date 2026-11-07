# Mining guide

The three ways to mine (in-node, standalone miner, pool) and where rewards
go are in the [README](../README.md#mining). This guide holds the detail:
seed boxes, the pool protocol, hardware backends, and the upgrade route.

## Seed node on a small box (24×7)

A seed node keeps the network alive while mining happens elsewhere. It needs
almost nothing — 512 MB RAM and a few GB of persistent disk are enough —
because it relays and validates but never grinds. Run it relay-only:

```sh
./target/release/srct-node serve --network mainnet --data-dir ./chain \
  --no-mine --listen 0.0.0.0:9833
```

Three things matter here: `--no-mine` (no CPU burn), `--data-dir` on a disk
that survives restarts (lose it and the node resyncs from genesis), and port
`9833` reachable from the internet so other nodes can dial in. Point
`srct-miner --node` at this box's API port and your laptop keeps mining while
the box keeps the chain.

## Option C — mine through a pool

Pools speak stratum-lite JSON-lines over TCP: `getjob` hands each miner an
unsolved template, `submit` returns shares. Jobs are single-use, one solved
proof counts as one share pool-wide (no double-billing across jobs),
submissions are pinned to the job (same transactions, difficulty and history
— swapping the coinbase invalidates the share), weak proofs count as shares
for accounting while only full-difficulty proofs go to the chain as blocks.
Rewards split over the last N shares (PPLNS, N ≈ two blocks' worth — every
share is worth the same no matter when it landed, so pool hopping has no
timing edge) minus the pool fee, rounding dust
carries to the next round instead of leaking to the operator, and every payout
is recorded before it is paid. Pool accounting never mints: only the consensus
coinbase creates coins.

## What hardware mines

Anything. The PoW is integer-only — no floats anywhere — so CPU, GPU, NPU,
TPU, photonic chips and domestic accelerators all compute bit-identical
results, and the three stages pull in different directions (hash throughput,
matrix-vector units, memory bandwidth), so no single exotic chip dominates.
`srct-miner` exposes one `ComputeBackend` contract with two in-tree backends:

| Flag | Backend | Meaning |
|---|---|---|
| `--backend cpu` | `CpuBackend` | Reference implementation. Default. |
| `--backend portable` | `PortableBackend` | Independently written implementation; differential-tested equal to the reference on every candidate. The template silicon vendors port. |
| `--backend auto` | — | Same as `cpu` today; picks the best available backend. Also via `SRCT_MINER_BACKEND`. |

A new chip joins by implementing the same contract and passing the
differential test — never by forking consensus. (SPEC §5.3 names the exact
kernel surface; SPEC §13.1/§19.2 specify the template and pool protocols.)

## Puzzle registry

The chain ships three registered puzzles. `puzzle_id` lives in the block
header and the active one is `NetworkParams::puzzle_id`; profiles default to
`hybrid-v1`.

| id | Name | Kind | Stage 3 input | Notes |
|---|---|---|---|---|
| 1 | `hybrid-v1` | hash + integer NN | block fields only | Default active puzzle on every profile. SPEC §5. |
| 2 | `hbm-v1` | memory-hard scratchpad | memory hash | Staged upgrade route for ASIC pressure. Not live. SPEC §M4. |
| 3 | `vwc-v1` | hash + integer NN + VWC id | block fields + verified-work-certificate id | `extra_nonce` carries the latest VWC id, so mining anchors useful L2 compute. Opt-in: set `puzzle_id: 3` on a profile. No cap, no bond, no identity. |

### VWC-linked mining (`vwc-v1`, puzzle_id = 3)

`vwc-v1` reuses `hybrid-v1`'s stage 1 (hash chain) and stage 2 (integer NN)
and changes only stage 3: the final hash additionally commits to the latest
verified-work-certificate id from a settled L2 task, carried in
`header.extra_nonce` (first 16 bytes of the VWC id). A distinct domain tag
(`srct/puzzle/stage3-vwc/v1`) keeps the output disjoint from `hybrid-v1`.

The effect: mining is no longer pure brute force. A block's proof binds the
chain to a real, verified piece of compute that the L2 task economy already
settled. The node tracks the latest VWC id after applying each block and the
template builder writes it into `extra_nonce`, so an external miner grinds
only `nonce` and never needs to touch the commitment.

Why this is fair:
- **No cap.** Every miner runs the same puzzle; no per-address win limit.
- **No bond.** A fresh laptop can mine full rewards instantly, same as `hybrid-v1`.
- **No identity.** Mining stays permissionless; the VWC commitment is data, not a gate.
- **Useful work.** Electricity spent mining also anchors L2 compute rather than being discarded.

A profile opts in by setting `puzzle_id: 3` (and ensuring at least one VWC
has settled, or `extra_nonce` stays zero — which is still a valid proof).
`hbm-v1` remains the fallback upgrade route if ASIC pressure ever appears.

## Photonic & custom silicon (attestation, not multipliers)

The PoW is integer-only so every chip computes bit-identical results,
and `srct-miner` exposes one `ComputeBackend` contract: a new chip
(photonic, neuromorphic, custom ASIC) joins by implementing the contract
and passing the differential test against `CpuBackend` on every
candidate — never by forking consensus. `templates/srct_silicon.py` is
the process around a port: `attest` records measured candidates/sec and
wall watts per puzzle, `efficiency` derives candidates/joule plus a
class, `verify_attestation` re-checks schema, spec dims and physical
plausibility, and `port_checklist` prints the exact path to a merged
backend. There is deliberately no mining multiplier or bonus yield for
new hardware: the coinbase is a consensus rule, and paying newest-fab
first would centralize on whoever buys silicon fastest. The fastest
truthful chip wins blocks the honest way — more candidates per joule.

## Auto-tuning boundary

Consensus parameters (target spacing, fee base, epoch length and
weights, difficulty clamp) are profile constants every node enforces
identically — no node auto-tunes them, gradient-free or otherwise,
because two nodes that tune differently are two chains. What operators
do tune locally: miner `--threads` / `--batch` / `--backend` (same
blocks, different speed), pool fee and PPLNS window (same payouts,
different accounting), seed-box relay flags. Self-tuning ends where
consensus begins.

## Upgrade route: hbm-v1

A second puzzle, `hbm-v1` (`puzzle_id = 2`), is designed and registered in
code but is **not** the active mining puzzle — the chain rests on §5 alone
(Decision 22). The memory-hard HBM path is the upgrade route for when ASIC
pressure appears, not a second live puzzle.
