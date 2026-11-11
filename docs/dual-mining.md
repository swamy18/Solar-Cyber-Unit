# Dual mining: hash PoW + DiLoCo proof-of-useful-work

Status: **hash mining is consensus-active; DiLoCo PoUW is a working
non-consensus prototype.** The prototype trains a real model, validates signed
updates, filters Byzantine work, and settles exact rewards in satoshis. It does
not mint coins, change block validity, or alter difficulty. An activation
requires the fork/migration work listed at the end of this page.

Run the measured demo:

```bash
cargo run --release -p srct-diloco --example train_demo
cargo test -p srct-diloco
```

## 1. Audit: what exists today

| Component | State | Consensus? |
|---|---|---|
| `hybrid-v1` hash + integer-NN-shaped puzzle | Active on every profile | **Yes** — block validity |
| HBM puzzle (`puzzle_id = 2`) | Registered, not active | No (activation is a profile decision) |
| VWC-linked puzzle (`puzzle_id = 3`) | Implemented, opt-in by profile | Would be, if a profile selects it |
| Block reward, fee split, rate anchor | Active | **Yes** |
| L2 task escrow, VWC, disputes, exits | Active | **Yes** (L2 state root) |
| Node-local credit, reputation, FX, ramps | Service layer | No |
| AI training in mining | **Absent** | — |

The README and `docs/status.md` already say plainly that the current neural
stage is ML-shaped integer work, not training. This crate is the first actual
training workload in the repository. It is deliberately separate from
`srct-core` so no consensus rule changed while the mechanism is proven.

## 2. Why DiLoCo

DiLoCo (Douillard et al., DeepMind, 2023) trains across poorly connected nodes
by running many local SGD steps between rare synchronization rounds. Only the
pseudo-gradient has to cross the network:

```text
worker i:   theta_i = local_sgd(theta_global, shard_i, H steps)
            delta_i = theta_i - theta_global
coordinator: delta_bar = aggregate(delta_1 ... delta_n)
              v       = momentum * v + delta_bar
              theta   = theta_global + outer_lr * v
```

The sign matters. `delta_i` points in the descent direction because local
training reduced the loss, so the coordinator **adds** the aggregate. The first
version of this prototype subtracted it and a real convergence test caught the
result immediately (loss 1.01 -> 14.11). The fixed implementation reaches
0.2695, which is why the test exists.

## 3. What the prototype implements

`crates/srct-diloco`:

- **Real model and data.** A 2-8-1 tanh/sigmoid MLP, 33 parameters, trained by
  mini-batch SGD on a deterministic two-moons set (192 samples, 96 per class,
  seeded noise). No hash-shaped simulation.
- **Local training.** `H = 20` full-shard SGD steps at `lr = 0.05` per worker
  per round; the worker may run this on its own data and hardware.
- **Signed update envelope.**
  - The signed preimage is domain-separated (`srct/diloco/claim/v1`) and
    covers round id, model version, worker address, base-model hash, sample
    and step counts, and a commitment to the delta.
  - The commitment is `SHA256("srct/diloco/update/v1" || round || worker ||
    base || delta_bytes)`, so a signature over metadata cannot be reused with a
    swapped delta.
  - The hybrid key bundle must derive to the registered worker address.
- **Validation before storage.** Version, round, model version, base hash,
  registration, signature, finite values, non-zero work, update-norm cap,
  duplicate worker, duplicate commitment. A refusal mutates nothing.
- **Byzantine filtering.** Coordinate-wise median of the submitted deltas
  defines a reference; every delta's cosine similarity to it must meet
  `min_cosine`. Survivors are averaged and applied through the momentum outer
  optimizer.
- **Quorum and failure semantics.** `min_quorum` accepted updates are
  required. A short round fails closed and leaves the optimizer velocity
  unchanged, so a disconnected worker causes a retry, not a bad model step.
- **Contribution pricing and exact reward split.** A worker is registered
  with an assigned shard size and cannot claim more samples than that. Weight
  is `samples * quality_bps`, with `quality_bps` from the measured cosine.
  Stake is recorded for eligibility but is **not** a reward multiplier until
  it is bonded and verifiable on chain; self-declared stake would be free
  weight. The pot is split by largest remainder, tie-broken by address, so the
  sum equals the pot exactly.
- **Deterministic checkpoints.** Canonical little-endian parameter encoding and
  a versioned model hash.

## 4. Measured results

Environment: the repository's Windows development machine, release profile,
24 rounds, 3 workers, 2 shards needed for quorum.

| Metric | Initial | Final |
|---|---|---|
| Training loss (BCE) | 1.0144 | 0.2695 |
| Accuracy (two moons) | 17.2% | 88.5% |
| Round latency (release) | — | 6.4-8.5 ms/round across runs |
| Round latency (debug) | — | 175.5 ms/round |
| Checkpoint hash | — | `5de030b090da1e8d1fb98f4792ac9b72…` |

The debug and release runs produced the same checkpoint hash on this host.
That is useful evidence of determinism for one implementation, **not** a
cross-platform consensus guarantee.

## 5. Adversarial tests

`cargo test -p srct-diloco` covers:

- a forged worker key is refused;
- a tampered delta invalidates its commitment;
- a replayed or duplicate update is refused before it can be counted twice;
- wrong round, wrong model version and wrong base model are refused;
- non-finite and oversized updates are refused before aggregation;
- a low-quality outlier (opposite direction) is excluded from the aggregate
  and receives no reward, while the round still reaches quorum;
- a round below quorum fails closed and leaves velocity unchanged;
- two coordinators replaying identical inputs derive the same checkpoint hash
  and the same reward map;
- truncated wire encodings are refused.

## 6. Threat model and limits

**What the prototype does stop**

- Fabricated metadata without a matching signature.
- A signature reused with a different delta.
- Duplicate counting of one proof.
- NaNs, infinities and updates above the norm cap.
- A minority of moderate outliers (median + cosine filter).
- Rewards paid to rejected work.

**What it does not prove**

- A gradient that passes the checks can still be useless or harmful for the
  intended objective. `inner_loss` is worker-reported and never trusted.
- A well-resourced adversary with many identities can Sybil the round. The
  assigned-sample check stops a worker inventing extra work, but not creating
  extra workers. Consensus activation must bind worker keys to bonded stake
  (existing `bond.rs`) and to the L2 authority/escrow layer, and must price
  stake only after that binding exists.
- `f32` training is not bit-exact across all compilers and CPUs. A consensus
  version needs a fixed-point/integer kernel or verified re-execution under a
  pinned toolchain.
- The data set is public and tiny. That is appropriate for a correctness
  prototype, not for a production training incentive.
- Model averaging is not a proof that the global model improves on held-out
  data; the test measures the training objective on the same deterministic set.

## 7. Consensus activation: required work before any fork

Nothing below has been done, and none of it should be improvised:

1. **Training kernel determinism.** Fixed-point or integer forward/backward
   passes, with cross-platform vectors. Without this, two validators can
   disagree on the same update.
2. **Round anchoring.** A new consensus object (round id, base model hash,
   accepted worker set, aggregate commitment) committed in a block or in L2
   state, with replay rules.
3. **Reward schedule.** A bounded PoUW emission split that preserves the
   existing issuance integral and rate anchor. It must not create coins outside
   `chain.rs`'s supply checks. Hash mining must remain fully funded and
   independently able to produce blocks.
4. **Eligibility and Sybil resistance.** Bonded worker registration, one
   submission per bond per round, stake-weighted caps, and slashing for
   proven-equivocation (two different signed updates in one round).
5. **Challenge path.** A bonded challenge that re-runs a worker's local steps
   on the committed shard and slashes a mismatch, so the optimistic filter is
   not the only defense.
6. **Fork schedule and migration.** Activation height per profile, old-node
   rejection semantics, state/wire version bump, reproducible test vectors and
   an economic review.
7. **Low-participation rule.** If the PoUW track has no quorum, hash mining
   continues unchanged and no PoUW reward is minted for that period. This is
   the default the prototype already enforces at the round level.

## 8. Remaining programme

The wider brief (CNNP representation exchange, FHE, TEE-backed SLAs, ZKML,
cross-chain intents, AI work graph) is **not implemented by this change**. The
audit above is the base those milestones build on. The ordered plan is:

1. DiLoCo PoUW prototype — **done, non-consensus** (this crate).
2. Deterministic training kernel + consensus round object — next.
3. TEE execution attestation as an L2 evidence type, with an explicit
   approved-execution vs correctness distinction.
4. FHE encrypted-compute adapter with real TFHE-style operations and measured
   costs; start with narrow supported op sets, not neural inference claims.
5. Unified verification policy (execution, correctness, resource metering).
6. CNNP representation envelopes and cross-architecture adapters, priced and
   settled through the existing payment/escrow surfaces.
7. Cross-chain intent lifecycle (quote, execute, verify, settle, refund).
8. Work-graph attribution and reuse compensation.
9. SDK adapters (Rust/Python/TypeScript/MCP) and production hardening.

Each milestone must ship with working code, adversarial tests, measured
limitations, and a commit. Interfaces or simulations alone do not count.
