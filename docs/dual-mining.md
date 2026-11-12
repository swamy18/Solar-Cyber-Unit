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

## 8. Heterogeneous training hardware (requirement)

DiLoCo must be useful for training and running AI models, not only for PoUW.
The same protocol must accept CPU, GPU, TPU, NPU, Apple silicon and future
photonic accelerators without rewriting the round logic, validation or reward
accounting every time hardware changes.

The separation is mandatory:

- **Hardware-independent:** model graph, optimizer, DiLoCo round state, update
  envelopes, Byzantine filtering, contribution scoring and rewards.
- **Hardware-specific:** kernel implementations, device memory, collectives,
  device discovery and resource measurement.

A planned `TrainBackend` seam (not implemented yet) carries:

```text
Capabilities {
  device_class: Cpu | Gpu | Tpu | Npu | AppleSoc | Photonic | Other,
  supported_dtypes, max_batch, memory_bytes,
  deterministic: BitExact | Reproducible | Statistical,
  fused_ops, collective_ops,
}
load(kernel_set) -> KernelHandle { kernel_hash, capabilities }
upload/download(buffer)
forward/backward/optimizer_step(device_buffer)
all_reduce_sum(device_buffers)   // or coordinator-mediated exchange
measure() -> ResourceEvidence
```

Determinism is a first-class property, not an assumption:

| Class | Meaning | Consensus use |
|---|---|---|
| `BitExact` | Pinned integer/fixed-point kernel, identical bytes everywhere | Required for direct consensus verification |
| `Reproducible` | Same backend + driver + shapes reproduce; other backends may differ | Re-execution challenge or TEE/ZK evidence |
| `Statistical` | Numerically close, not reproducible | Non-consensus training only, or proof-backed |

A backend that is not `BitExact` must never be the sole authority for a
consensus finalization. Consensus would pin the kernel hash and the determinism
class; adding a backend would not change the protocol, only the set of approved
kernel hashes.

Extension rule: adding a device means implementing the trait and passing the
same conformance suite, never forking consensus:

1. forward and backward parity against the CPU reference on fixed vectors;
2. gradient and optimizer-step parity within the backend's determinism class;
3. a full DiLoCo round producing the same checkpoint under `BitExact`, or a
   documented divergence under the other classes;
4. device-loss and out-of-memory recovery without corrupting the round;
5. memory and resource-measurement bounds;
6. unavailable backend fails closed and falls back to CPU, never silently
   changing the math.

The existing mining `ComputeBackend` in `crates/srct-miner/src/accel.rs` is the
precedent for the conformance-test style, but training needs backward passes,
optimizer state, device memory and collectives, so it is a separate seam.

Implemented milestone (H1): the CPU reference now sits behind
`srct_diloco::backend::TrainBackend`, with `check_backend` running fixed-vector
forward/loss/gradient/optimizer/round parity and `require_determinism` gating
consensus use. `CpuBackend` is classified `Reproducible`, so it is explicitly
refused for `BitExact` consensus finalization. The suite also proves a
perturbed kernel fails, a `Statistical` kernel can pass tolerance but not the
consensus gate, and an unavailable device fails closed.

Milestones:

1. Extract the CPU reference behind `TrainBackend` — **done** (7 conformance
   tests; no behavioural change to rounds).
2. GPU backend through a vendor-neutral shim (CUDA/ROCm), parity-tested.
3. Apple Metal/ANE and NPU adapters.
4. TPU and photonic experiments with an explicit determinism class and a
   verification policy; useful for non-consensus training first.
5. Capability-aware scheduler: discovery, price/latency/memory placement,
   device failure and re-shard.

## 9. Remaining programme

The wider brief is only partially implemented. The CNNP core, the intent
lifecycle exist, TEE-backed execution evidence (`srct-compute::tee`), an
additive-homomorphic encrypted-compute prototype (`srct-fhe`) and a
zero-knowledge linear-evaluation prototype (`srct-zkml`) as non-consensus
prototypes; SDK adapters are **not implemented**. The audit above is the base those milestones build on.
The ordered plan is:

1. DiLoCo PoUW prototype — **done, non-consensus** (this crate).
2. Heterogeneous `TrainBackend` seam + CPU reference conformance — **done**
   (H1, 7 conformance tests).
3. GPU, Apple/NPU, TPU and photonic backends under the determinism policy —
   partially done: a second (`Statistical`, block-partitioned) backend passes
   the same conformance suite, proving the seam takes heterogeneous execution.
   Real silicon backends still next.
4. Deterministic training kernel + consensus round object.
5. TEE execution attestation as an L2 evidence type — **done, non-consensus**
   (`srct-l2::tee_evidence`: `TeeBackedAttestation` implementing the generic
   `Attestation` trait, verified through `srct-verify`, flowing through the
   real `ServiceContract::submit` path). Consensus-state activation (`L2State`)
   needs the formal consensus-change process and is explicitly next.
6. FHE encrypted-compute adapter — **prototype done, non-consensus**
   (`srct-fhe`: exponential-ElGamal weighted sums, exact recomputation
   checks). TFHE-style non-linear ops and measured-cost expansion are next.
7. Unified verification policy (execution, correctness, resource metering)
   — **done, non-consensus** (`srct-verify`: policy table + one verifier
   for TEE/FHE/ZKML). Escrow/intent wiring is next.
8. Native ZKML — **prototype done, non-consensus** (`srct-zkml`:
   Sigma-protocol proofs for one quantized linear layer with range checks;
   Bulletproofs R1CS evaluated but its published crate does not compile).
   Non-linear gates and folding are next.
8. CNNP nonlinear/tokenizer adapters and transport — the representation,
   linear-adapter, discovery and metering core is done (non-consensus).
9. Intent persistence, chain adapters and solver discovery — the lifecycle
   state machine is done (non-consensus).
10. Work-graph attribution and reuse compensation — **done, non-consensus**
    (`srct-workgraph`: lineage, licenses, exact royalty settlement).
    Cross-crate evidence checks are next.
11. SDK adapters (Rust/Python/TypeScript/MCP) and production hardening.

Each milestone must ship with working code, adversarial tests, measured
limitations, and a commit. Interfaces or simulations alone do not count.
