# Solar Cyber Unit (SRCT)

<img src="docs/assets/Solar_Cyber_unit.png" alt="Solar Cyber Unit coin logo" width="200">

**An AI-native Layer 1 cryptocurrency whose roadmap replaces hash-only mining with
proof of useful work — currently secured by hash PoW while the AI, compute, and
verification layers mature as tested prototypes.**

Status as of **2026-11-13**: pre-launch. No external security audit has been
performed. All claims below are verified against the implementation in this
repository; every subsystem is labeled with its maturity so prototypes are never
mistaken for production.

**Author:** Swamy Gadila. Open source — see [License](#license).

---

## Contents

- [What Solar Cyber Unit is](#what-solar-cyber-unit-is)
- [Architecture at a glance](#architecture-at-a-glance)
- [Layer 1 blockchain](#layer-1-blockchain)
- [Mining and issuance](#mining-and-issuance)
- [Hash mining vs staged proof of useful work](#hash-mining-vs-staged-proof-of-useful-work)
- [DiLoCo and AI compute](#diloco-and-ai-compute)
- [Decentralized compute](#decentralized-compute)
- [Verification: TEE, FHE, ZKML](#verification-tee-fhe-zkml)
- [CNNP: connecting neural networks](#cnnp-connecting-neural-networks)
- [AI Work Graph: artifacts and royalties](#ai-work-graph-artifacts-and-royalties)
- [Agents: identity, messaging, payments](#agents-identity-messaging-payments)
- [Programmable credits and Smart Gate](#programmable-credits-and-smart-gate)
- [Escrow and economic settlement](#escrow-and-economic-settlement)
- [Repository layout](#repository-layout)
- [Installation and build](#installation-and-build)
- [Running a node](#running-a-node)
- [Running a miner](#running-a-miner)
- [Running a compute participant](#running-a-compute-participant)
- [Running tests and examples](#running-tests-and-examples)
- [Security model and threat assumptions](#security-model-and-threat-assumptions)
- [Current limitations](#current-limitations)
- [Development roadmap](#development-roadmap)
- [Mainnet readiness and deployment](#mainnet-readiness-and-deployment)
- [License](#license)

---

## What Solar Cyber Unit is

SRCT is a Layer 1 coin with one reference chain and one currency. It does four
jobs that settle in the same coin:

1. **Native cryptocurrency** — UTXO transfers, EIP-1559-style fees, bonded
   validators, binding finality. This is live consensus code and the only thing
   securing the chain today.
2. **Agent authorization** — owner-signed spending policies enforced at
   transaction admission, portable across chains and rails.
3. **Machine payments** — batched micro-payments, usage streams, x402
   pay-per-call, and a Smart Gate safety layer.
4. **Verifiable work economy** — escrow for compute, intents across networks,
   royalties for AI artifacts. Largely prototype libraries, not consensus.

The purpose of SRCT is to become an AI-native currency: mining that trains
models instead of burning hashes, compute markets with cryptographic proof of
execution, and royalty graphs for AI artifacts — all settling in one coin. The
chain is designed so each layer can be used without the others.

Full protocol specification: [`docs/SPEC.md`](docs/SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).
Development log: [`docs/status.md`](docs/status.md).

---

## Architecture at a glance

Two layers, kept strictly separate:

- **Layer 1 (consensus).** `srct-core`, `srct-net`, `srct-store`, `srct-node`,
  `srct-miner`, `srct-worker`, `srct-l2`, `srct-policy`, `srct-mcp`,
  `srct-bench`. Blocks, transactions, mining, fees, P2P sync, storage, wallet,
  REST API. L2 entries ride inside L1 blocks but **no L2 failure can ever
  invalidate an L1 block** — L2 payloads that fail validation are skipped
  deterministically.
- **Layer 2 / off-chain (non-consensus).** `srct-diloco`, `srct-compute`,
  `srct-fhe`, `srct-zkml`, `srct-verify`, `srct-cnnp`, `srct-workgraph`,
  `srct-intent`, `srct-agentnet`. Training, compute markets, encrypted
  computation, proofs, interop, intents, messaging. These are libraries and
  verifiers; their outputs become consensus-relevant only through explicitly
  activated paths (all currently inactive).

Maturity legend used throughout this document:

| Label | Meaning |
|---|---|
| `[L1 ACTIVE]` | Consensus code, tested, securing the chain today |
| `[STAGED · DISABLED]` | Mechanism implemented, activation height `0` (never active) |
| `[PROTOTYPE]` | Working, tested library; not wired to consensus or payments |
| `[EMULATED]` | Hardware interface exists; execution falls back to CPU |
| `[INSTRUCTIONS]` | Off-chain process documented; no on-chain settlement by the node |
| `[PLANNED]` | Design only |

---

## Layer 1 blockchain

`[L1 ACTIVE]`

- **Blocks.** `srct-core/src/block.rs`. Header (`BLOCK_VERSION = 1`,
  `HEADER_SERIALIZED_LEN = 177`): version, height, `prev_hash` (SHA-512),
  Merkle root (SHA-256), timestamp, base fee, difficulty (`u128`), `puzzle_id`,
  `epoch_id`, `extra_nonce[16]`, signature scheme. Transactions list starts with
  the coinbase; L2 entries travel in the block trailer.
- **Transactions.** Types `0 = STANDARD, 1 = COINBASE, 2 = BOND, 3 = UNBOND,
  4 = SLASH`. Validation (`ledger.rs::check_tx`) rejects unknown types, empty
  or duplicate inputs, zero-value outputs, value overflow, future lock-times,
  missing UTXOs, immature coinbase spends, and underpaid fees. Gas schedule:
  `GAS_TX_BASE = 16000`, `GAS_PER_INPUT = 1000`, `GAS_PER_OUTPUT = 250`.
- **Cryptography.** Addresses are hybrid bundles (secp256k1 ECDSA/Schnorr by
  default). ML-DSA-65 post-quantum signatures are age-gated by
  `pq_activation_height` (currently `0`, inactive) and never required
  (`require_hybrid_signatures = false` on all profiles).
- **P2P networking** (`srct-net`). Framed transport
  (`magic | type | len`, `MAX_FRAME = 4.1 MiB`), 12 frozen message types,
  magic-plus-network-id handshake, block-first `Inv`/`GetData` sync with
  bounded in-flight state, peer address book, relay manager.
- **Storage and recovery** (`srct-store`). Append-only `RecordLog` plus
  `meta.json` (atomic rename) plus journal. Reopens rebuild the index; a torn
  tail append is dropped and reported; damage-with-data refuses to open.
- **Fork and versioning.** `BLOCK_VERSION = 1`, `PROTOCOL_VERSION = 1`, unknown
  message numbers are ignored (forward-compatible freeze). The chain refuses to
  adopt forks at or below the binding-finality height.
- **Finality and committee.** Binding-finality depth `100 / 20 / 20`
  (mainnet/mini/testnet). Genesis committees: 21 keys mainnet (quorum 15),
  4 keys mini/testnet. Bonded stake derives a `TopN` committee (max 21) that
  replaces the bootstrap set. Equivocation evidence is recorded but
  **detect-only** — no automatic slashing burn. Checkpoint interval
  `100 / 10 / 10`.
- **Network profiles.** `mainnet` (600 s block target), `mini`, `testnet`
  (1 s targets for local testing). Magic bytes and network IDs differ per
  profile; `mini` is the CLI default.

Details: [`docs/SPEC.md`](docs/SPEC.md) §§1–13,
[`docs/mining.md`](docs/mining.md).

---

## Mining and issuance

`[L1 ACTIVE]`

- **Puzzle.** `hybrid-v1` (`puzzle_id = 1`) is the active puzzle on every
  profile: a SHA-256 hash chain (carries the security), an integer-only
  neural-network-shaped stage (epoch-derived weights — **no training, no
  inference**; it buys hardware diversity, not AI output), and a final hash
  binding both into the value compared against the target. No floating point
  anywhere in the hot path. `hbm-v1` (`puzzle_id = 2`) is registered but
  inactive; `vwc-v1` (`puzzle_id = 3`) is an opt-in commit path.
- **Difficulty.** Zawy LWMA, window 60, ±1000 bps change cap, median-11
  timestamps, future-time limit at the block target. Range clamped between
  genesis-minimum and `2^96`.
- **Issuance.** First block pays **76 SRCT**. Halving every 262,800 blocks
  (mainnet; 2,000 on mini/testnet) down a whole-coin ladder
  `76 → 38 → 19 → 9 → 4 → 2 → 1`, then a tail (`0.5 → 0.25 → 0.125 → 0.1`
  SRCT floor on mainnet). Genesis mints **zero**. There is **no fixed supply
  cap** (decision D18): a 1%-per-period rate anchor bounds cumulative issuance
  instead. Approximate maximum issuance: ~39.2M SRCT (mainnet), ~298k (mini).
- **Fees.** EIP-1559 base fee; each block splits the base take 50/50 between a
  burn sink and the PSCB pool, miner keeps the tip. Flat L2 fees
  (5000/2000/2000/10000/1000 sat by entry type) split the same way.

Details: [`docs/monetary-policy.md`](docs/monetary-policy.md),
[`docs/SPEC.md`](docs/SPEC.md) §§4–8.

---

## Hash mining vs staged proof of useful work

This is the distinction most readers get wrong, so it is stated plainly:

- **Today the chain is secured by hash mining alone.** `pouw_activation_height
  = 0` on every profile, and `0` means *never*: DiLoCo/PoUW code cannot mint,
  cannot set difficulty, and cannot affect fork choice.
- **Staged PoUW is implemented but disabled** `[STAGED · DISABLED]`. The
  mechanism exists in `srct-diloco/src/consensus.rs`: a bounded `RoundAnchor`
  (sorted unique workers 1–1024, versioned encoding), mint checked against the
  real issuance integral, worker eligibility requiring a positive bond floor,
  re-execution checks on disputed shards, and a low-participation rule that
  mints nothing below quorum. What remains before any activation is a fork
  schedule, a migration plan, and wire-format v2 shard/hyperparameter
  commitments.
- **What the neural stage in mining is.** Cost-model diversity, not useful AI.
  Real training lives in `srct-diloco` and is currently non-consensus.

Details: [`docs/dual-mining.md`](docs/dual-mining.md).

---

## DiLoCo and AI compute

`[PROTOTYPE]` — real training, tested, non-consensus.

- **Model and data.** `Mlp` 2-8-1 (tanh hidden, sigmoid output, 33 params),
  LCG-seeded Xavier init, BCE loss, SGD steps, canonical little-endian
  encoding hashed under `srct/diloco/model/v1`. Demo workload: two-moons,
  192 samples across 3 shards.
- **Round lifecycle.** Workers register, submit `UpdateClaim`s
  (`delta = local − base`, SHA-256 commitment, hybrid signature bound to the
  worker). Admission is fail-closed: bad version/round/model, unregistered
  worker, bad signature, non-finite or oversized deltas, duplicate submissions
  are all refused. Finalization needs `submissions ≥ min_quorum` or the round
  fails with velocity unchanged.
- **Byzantine filtering.** Reference = coordinate-wise median; workers with
  `cosine(delta, reference) < min_cosine` are rejected as low quality.
  Survivors are mean-averaged with outer momentum. Robust to minority moderate
  outliers; **not** a Sybil defense (see limitations).
- **Fixed-point arithmetic.** `FixedMlp` implements Q16.16 (`Q = 1<<16`,
  saturating, non-finite → 0, ±32768 range). `tanh`/`sigmoid` are polynomial
  approximations; the objective is MSE (a close cousin of BCE, not the
  identical function). Integer-only and byte-identical across reruns.
- **Determinism classes.** `Statistical(0) < Reproducible(1) < BitExact(2)`.
  `CpuBackend` is `Reproducible`; `BlockedBackend` is `Statistical`;
  `FixedPointBackend` is `BitExact`. Conformance (`check_backend`) enforces
  tolerances per class (`0.0`, `1e-6`, `1e-3`) and refuses f32 backends at the
  `BitExact` gate.
- **Hardware backends** `[EMULATED]`. `Cuda / Rocm / Tpu / Npu / AppleSoc /
  Photonic` interfaces exist with declared capabilities (batch sizes, memory
  budgets), but `probe()` always returns false — no vendor SDK is linked — and
  every method returns `Err(Unavailable)` fail-closed. `emulated()` runs CPU
  kernels under a hardware device class with a distinct kernel hash, so
  emulated runs are distinguishable from (future) silicon runs.
- **Rewards.** Exact pot conservation: `weight = min(samples, 4096) ×
  quality_bps` where `quality_bps = round(clamp(cosine,0,1) × 10000)`; shares
  are floored with the remainder dealt by largest remainder (ties by address).
  Declared stake is recorded but is **not** a reward multiplier.
- **Measured.** Reference run (24 rounds, 3 workers): loss 1.01 → 0.27,
  accuracy 17% → 89%, ~7 ms/round in release. Debug and release agree on the
  same host (not cross-platform for f32).

Details: [`docs/dual-mining.md`](docs/dual-mining.md).

---

## Decentralized compute

`[PROTOTYPE]` — pure non-consensus library. **Nothing here moves coins.**
Every payout, refund, slash, and withdrawal is a `PayoutInstruction` for an
off-chain rail to execute. No `srct-node` code path calls into these books.

- **Market.** Self-declared `DeviceProfile`s (class bitmask, RAM 512–1M MiB,
  determinism floor, kernel hash), signed offers and jobs
  (`srct/compute/{offer,job,assignment}/v1`), deterministic greedy planner:
  filter (network, service, window, price, verification floor, sealed ⇒
  privacy), sort by `(price, provider, hash)`, fill greedily. Bounded
  (`MAX_JOB_UNITS = 10⁶`, 4096 shards, 3 attempts).
- **Receipts and settlement.** `receipt.total = units_done × price`, checked
  exactly; once-only settlement; late settlement refused after the deadline.
- **Bonds and reputation.** Minimum bond 10,000 sat, 144-block lockup.
  Slash: 10% no-show (past deadline), 50% fraud
  (`WrongResult`/`Overclaim`/`Impostor`), with integer-division truncation.
  Score = `settled_units − 10 × timeouts − 100 × slashes` (saturating);
  score ≤ −100 bans. A high-volume provider can survive one fraud event —
  the ban is conditional, not automatic.
- **Challenge re-execution.** One challenge per assignment, ever. A second
  receipt from the challenger before the deadline decides `Match`/`Mismatch`;
  mismatches become `WrongResult` disputes for the requester to slash on.
- **TEE evidence.** `SignedTeeQuote` bound to an SLA and checked against an
  operator-configured attestation-roots registry (add/revoke), with model /
  runtime / config / input hash binding, freshness window, and replay
  protection. A quote proves *execution under a key*, not correctness.
- **Job escrow.** Fund-once by the requester, per-receipt release with
  `Σ released ≤ funded` conservation, single post-deadline refund. Prototype
  pot only — **a different state machine from the L1 job escrow** in
  `agent-jobs.md`; same verbs, disjoint books.
- **Persistence and gossip.** `FlowJournal` (4096 entries, 8 KiB each,
  verify-everything replay; timeouts are not journaled and restore from an
  unsigned `TimeoutCheckpoint` floor) and `GossipSet` (signed batches, dedup
  by hash, deterministic sort-merge; no sockets, no timers — transport is the
  operator's job).

Details: [`docs/compute-sharing.md`](docs/compute-sharing.md),
[`docs/agent-jobs.md`](docs/agent-jobs.md),
[`docs/reputation.md`](docs/reputation.md).

---

## Verification: TEE, FHE, ZKML

`[PROTOTYPE]` throughout. Nothing in this section is production cryptography.

- **Unified policy** (`srct-verify`). A task profile
  (`kind × security × value`) selects required proofs: encrypted compute needs
  correctness (+ execution above `High`); attested execution needs execution
  (+ correctness at `Critical`); high-value inference needs correctness. The
  table is **advisory** — a rail is only gated if it calls
  `verify_for_profile` / `gated_release`. One `UnifiedVerifier` owns all
  replay books so mixed-evidence replays stay independent.
- **FHE** (`srct-fhe`). Exponential ElGamal on secp256k1, `Enc(m) = (rG, mG +
  rP)`: homomorphic add, scalar multiply (negation wraps mod n), 66-byte
  encodings. Decryption is BSGS in `[0, bound)` — `O(√bound)`, owner-chosen
  bound, `None` outside it. Linear weighted sums only (`MAX_INPUTS = 64`,
  `|weight| ≤ 10⁶`); weights and bias are public; no range proofs, only static
  `eval_bounded` guards. The TFHE gate module is an explicitly labeled
  **toy**: `N = 128`, coarse torus grid, large sigma, `O(N²)` multiply,
  non-constant-time Gaussian, and `rebind` needs the secret (no third-party
  composability). It is not wired to tasks. A `KeyRegistry`
  (rotation/revocation) exists.
- **ZKML** (`srct-zkml`). Sigma-protocol proofs, **not SNARKs**: Pedersen
  commitments (`H` is a SHA-256-derived NUMS point, one line to replace),
  per-bit CDS OR-proofs, Fiat–Shamir challenges, range verification, threshold
  assertions (`value ≥ threshold`). Limits: ≤ 8 inputs × 16 bits, public
  weights, correctness ≠ usefulness. Batch folding is **linear batch
  verification, not recursive Nova folding**: each OR-proof is still verified
  individually; only the linear recomposition check is folded via
  transcript randomness (soundness `1/p` per fold, not amortized).
- **L2 TEE evidence** (`srct-l2/src/tee_evidence.rs`). `TeeBackedAttestation`
  (`sla` + `quote`) verifies through the unified verifier with strict codecs.
  It is exercised as a generic `ServiceContract` path in tests; L2 consensus
  settlement still uses plain `ComputeAttestation` — promoting the TEE path
  needs a formal consensus change.

Details: [`docs/fhe.md`](docs/fhe.md), [`docs/zkml.md`](docs/zkml.md),
[`docs/verify.md`](docs/verify.md).

---

## CNNP: connecting neural networks

`[PROTOTYPE]` — byte formats and math, no transport, no availability, no DoS
resistance beyond caps.

- **Spaces and envelopes.** `ModelSpace` hashed under
  `srct/cnnp/space/v1`. `RepresentationEnvelope`s commit to
  `(space, owner, payload)`; sealed variants use XChaCha20-Poly1305 with the
  space/owner/nonce as AAD. Only representations are sealed — adapter and
  tokenizer weights are public, and metadata (space, owner, size, timing) is
  visible.
- **Adapters.** Ridge-regression affine fits (`(XᵀX + λI)W = XᵀY`, bias
  unregularized, Gauss–Jordan partial pivot in f64, stored f32) and quadratic
  lifts (source dim ≤ 16). Tokenizer maps by positional vote with coverage
  scores and unknown-token refusal. Held-out reports compare against a
  baseline; low MSE is a fit claim, not a semantic-equivalence claim.
- **Discovery and metering.** Signed capabilities with price/latency/privacy/
  verification floors; `discover` ranks by `(price, latency, provider, nonce)`
  skipping bad signatures and expiries. Usage receipts settle exactly
  (`units × price`, checked); `ReceiptBook` settles once per request.
  Multi-stage plans (≤ 8 stages) are quoted with continuity, cap, floor, and
  budget checks.
- **Execution gate.** `required_evidence(privacy, verification)` maps each
  stage to required `Tee`/`Fhe`/`Zk` evidence; the gate verifies the
  capability signature, provider binding, evidence validity, and coverage.
  `Optimistic` stages require no evidence and fall back to L2 escrow/dispute.

Details: [`docs/cnnp.md`](docs/cnnp.md).

---

## AI Work Graph: artifacts and royalties

`[PROTOTYPE]` — exact accounting, no coin movement.

- **Artifacts.** Content-hashed (`srct/workgraph/artifact/v1`), owner-signed,
  ≤ 16 parents, license with `royalty_bps ≤ 5000` (50%). Parents must pre-exist
  and be reusable, children cannot predate parents, cycles are impossible by
  construction. Optional evidence binding re-verifies through the unified
  verifier and requires the artifact's evidence hash to match (or hash to) the
  verifier output.
- **Royalty settlement.** Recursive: each royalty-bearing node keeps
  `amt − pool`, splits `pool = amt × bps / 10000` across parents, recurses to
  depth 8 (deeper ancestors collect nothing further). Dust from integer
  division stays with the child owner. Every settlement sums **exactly** to
  the revenue. `UsageLedger` records CNNP receipts once each;
  `RevenueEscrow` locks cumulative releases against the locked amount with a
  single refund.
- **Store.** Content-keyed blobs, 1024 × 256 KiB, idempotent puts.

Details: [`docs/workgraph.md`](docs/workgraph.md).

---

## Agents: identity, messaging, payments

Messaging `[PROTOTYPE]` (in-memory transport); identity and payments
`[L1 ACTIVE]` where noted. Wire formats and state machines:
[`docs/agentnet.md`](docs/agentnet.md).

- **Identity** `[L1 ACTIVE]`. `derive_agent_id(network, role, address)` binds a
  20-byte id to a hybrid-bundle address; roles are `Human` / `Machine` /
  `Service`; ids are network-bound. Recipients enforce bundle→address binding.
- **Pairwise E2E.** Ephemeral ECDH + HKDF-SHA256 + XChaCha20-Poly1305, AAD
  covering version/network/thread/sequence/identities. 64 KiB messages.
- **Double ratchet.** Per-direction DH rotation with strict in-order delivery —
  gaps and reorders are refused, not buffered.
- **Sealed sender.** Sender identity and signature travel inside the AEAD;
  the wire exposes recipient, thread, sequence, and expiry only. Verification
  is recipient-side.
- **Groups.** Sender-key groups with epoch-bump reseed on member removal, and
  an MLS-*style* protocol (proposals, commits, epoch keys) that is explicitly
  **not RFC 9420** (no ratchet tree, no path secrets, no intra-epoch forward
  secrecy).
- **Presence and delivery.** Heartbeats, fanout targets, ack sets, padded
  framing (opt-in, up to 64 KiB), and a verify-before-store mailbox (4096
  messages, 8192 sender guards that are never evicted — a full guard table
  refuses new pairs rather than dropping old ones).
- **Transport.** `LoopbackTransport` (in-memory) plus wire codecs only.
  Sockets, relays, and multi-node agent delivery are operator work. The
  "live 3-node E2E" test (`srct-node/tests/e2e_multi_node.rs`) proves **L1
  payment relay and tip agreement**, not agent messaging over the network.
- **Agent payments.** Programmable credits (streams, x402 pay-per-call,
  portable grants, trial faucet), documented in
  [`docs/agent-credits.md`](docs/agent-credits.md),
  [`docs/micropayments.md`](docs/micropayments.md),
  [`docs/x402.md`](docs/x402.md). x402 is `exact`-only; EVM chains are
  advertised formats the node never settles.

---

## Programmable credits and Smart Gate

- **Credits.** Streams open/settle against `StreamBook` (last-voucher-only);
  portable grants carry `SpendPolicy`/`PolicyBook` decisions off-chain with the
  same allow/deny/approval-needed answers as admission; the trial faucet is
  sponsor-funded and env-configured (`SRCT_TRIAL_*`).
- **Smart Gate.** Owner-signed `InfraPolicy` / `Capability` / `Approval` /
  `WorkloadCredential`, exact-equality matching, strictly increasing nonces,
  30-block credential lifetime, audience scoping, revocation with descendant
  propagation, hash-chained node-local audit log (not chain-anchored).
  Enforcement point: `GuardGate::execute` in the worker plus
  `POST /v1/guard/*` in the node API.

Details: [`docs/smart-gate-architecture.md`](docs/smart-gate-architecture.md),
[`docs/portable-policy.md`](docs/portable-policy.md).

---

## Escrow and economic settlement

Three different escrows exist — similar verbs, disjoint state machines:

1. **L1 conditional escrow** `[L1 ACTIVE]` (`srct-core/src/escrow.rs`).
   Contract-selected BLS arbitrator, `Open → Released → Finalized/Refunded`,
   expiry at the unbonding window, settled over `POST /v1/escrow/*`. The node
   job board (`docs/agent-jobs.md`) holds funds in `held_escrows`.
2. **L2 task escrow** `[L1 ACTIVE]` (`srct-l2`). Locked credits with
   `check_conservation` (`conservation_total == funded_total`) asserted after
   every operation; exits active from height 1 with throttling.
3. **Prototype rails** `[PROTOTYPE]`. `srct-compute` job escrow, `srct-intent`
   `MemRail`, `srct-workgraph` revenue escrow — instructions and test rails,
   never touching the UTXO set.

Related `[INSTRUCTIONS]` material — documented processes the node does not
settle: cross-network intents (signed intents/quotes/routes, one-quote-per-
solver, exact-once settle/refund, named-arbiter disputes, TEE/ZK evidence
gates against operator-configured roots — a prototype, not a trustless
bridge), USD/fiat conversion (whitelisted FX issuers, off-protocol custody),
ramps, on-chain lending types (`0x19–0x1C`, 100%-collateral default,
≤ 10% per window), and Treats (no mint endpoint; fee auto-mint plus owner
gifts; redemption burns to a reserve-ratio voucher).

Details: [`docs/intents.md`](docs/intents.md),
[`docs/usd-settlement.md`](docs/usd-settlement.md),
[`docs/ramps.md`](docs/ramps.md), [`docs/lending.md`](docs/lending.md),
[`docs/treats.md`](docs/treats.md), [`docs/agent-jobs.md`](docs/agent-jobs.md).

---

## Repository layout

19 workspace crates (`Cargo.toml`, edition 2021, version `0.1.0`):

| Crate | Role | Maturity |
|---|---|---|
| `srct-core` | Blocks, tx, ledger, supply, fees, difficulty, agents, escrow, x402 | `[L1 ACTIVE]` |
| `srct-net` | P2P frames, messages, sync, relay, peers | `[L1 ACTIVE]` |
| `srct-store` | Append-only log, meta.json, journal | `[L1 ACTIVE]` |
| `srct-node` | CLI, REST API, wallet store, L2 glue, mediation | `[L1 ACTIVE]` |
| `srct-miner` | Solver, stratum pool, PPLNS payouts, accel backends | `[L1 ACTIVE]` |
| `srct-worker` | Off-chain worker client SDK (node/http/discovery/claim/submit) | `[L1 ACTIVE]` client |
| `srct-l2` | Task contracts, deposits, disputes, VWC, TEE evidence type | `[L1 ACTIVE]` core / `[PROTOTYPE]` TEE path |
| `srct-policy` | Chain-agnostic policy decisions + TypeScript/Python bindings | `[L1 ACTIVE]` |
| `srct-mcp` | Keyless wallet-guard dispatcher | `[L1 ACTIVE]` |
| `srct-bench` | Measurement harness over `Chain::submit` | tooling |
| `srct-diloco` | DiLoCo training, Q16.16, backends, staged consensus | `[PROTOTYPE]` / `[STAGED · DISABLED]` consensus |
| `srct-compute` | Compute market, bonds, challenges, escrow, gossip | `[PROTOTYPE]` |
| `srct-fhe` | Exponential ElGamal tasks + toy TFHE gates | `[PROTOTYPE]` |
| `srct-zkml` | Sigma-protocol ZKML + linear batch folding | `[PROTOTYPE]` |
| `srct-verify` | Unified verification policy + verifier | `[PROTOTYPE]` |
| `srct-cnnp` | Representation spaces, adapters, discovery, metering | `[PROTOTYPE]` |
| `srct-workgraph` | Artifact lineage + exact royalty settlement | `[PROTOTYPE]` |
| `srct-intent` | Cross-network intents, quotes, routes, disputes | `[PROTOTYPE]` |
| `srct-agentnet` | Encrypted messaging, ratchet, groups | `[PROTOTYPE]` |

Supporting trees: `templates/` (10 `srct_*.py` participant templates),
`verification/sim/` + `verification/tests/vectors/` (second-implementation
cross-checks), `sdk-js/` (dependency-free JS REST client),
`scripts/` (network start/stop/reset, test counting),
`.github/workflows/` (`ci.yml`, `audit.yml`, `release.yml`), `fuzz/`
(17 cargo-fuzz targets), `paper/`, `chain/` (local data, gitignored).

---

## Installation and build

Requires **Rust 1.75+** (developed against 1.99) and **Python 3.11+** for the
simulations. Node.js for `sdk-js` only.

```sh
git clone https://github.com/swamy18/Solar-Cyber-Unit.git
cd Solar-Cyber-Unit
cargo build --release
```

Lint and type-check (must stay clean):

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo fmt --all --check
```

---

## Running a node

```sh
export SRCT_WALLET_PASSPHRASE=change-me   # or pass --allow-plaintext-wallet to init

./target/release/srct-node init   --network mini --data-dir ./chain
./target/release/srct-node mine   --network mini --data-dir ./chain --blocks 25
./target/release/srct-node status --network mini --data-dir ./chain
./target/release/srct-node verify --network mini --data-dir ./chain

# Run a P2P node (mines by default, so it settles matured exits).
./target/release/srct-node serve --network mini --data-dir ./chain \
                                 --listen 127.0.0.1:8333
```

`verify` replays the whole chain from genesis and diffs the UTXO set, supply,
bond ledger, and binding-finalized point against stored state — run it after
any change. `srct-node help` (or any command with `--help`) prints the full
command list: `init`, `mine`, `send`, `status`, `verify`, `show-block`,
`balance`, `wallet`, `policy`, `agent-spend`, `credit`, `l2`, `export`,
`serve`, `validator`.

Multi-node local network (deterministic genesis, node 1 as seed):

```sh
scripts/start-network --nodes 3
scripts/stop-network
scripts/reset-network
```

Ask the policy engine before spending (no wallet or chain state needed):

```sh
python verification/sim/policy_decide_demo.py --self-test
```

---

## Running a miner

Two options, both against the active `hybrid-v1` puzzle:

- **In-node** (`[L1 ACTIVE]`): `srct-node mine --blocks N` mines directly into
  the local chain directory.
- **Standalone** (`[L1 ACTIVE]`): `srct-miner` solves headers
  (`solve_header` over `nonce` + `extra_nonce`), serves stratum work to pooled
  miners with PPLNS accounting (accounting only — it never mints), and submits
  templates over HTTP (`cargo test -p srct-node --test api external_miner`
  covers the roundtrip).

External-miner and template/submit flows are integration-tested; measured
local stratum throughput is ~114 kH/s (recorded in
[`docs/mainnet-readiness.md`](docs/mainnet-readiness.md)).

---

## Running a compute participant

`[PROTOTYPE]` — off-chain only. No coins move; participation is local
execution plus signed messages.

- Advertise capacity: build a `DeviceProfile`, sign a `SignedOffer`
  (`templates/srct_node.py` is a resource-capped participant resource node;
  `templates/srct_depin.py` sketches a JSON board for discovery).
- Plan and execute: `plan_assignments` matches a `SignedJob` to offers;
  `TeeVerifier` checks execution quotes against the SLA and attestation roots.
- Settle off-chain: receipts, `EscrowBook` fund/release/refund, and challenge
  flows are demonstrated in `crates/srct-compute` tests and the e2e
  escrow/challenge test — run those, not a chain, to exercise the flow.

---

## Running tests and examples

Last recorded full run (2026-11-13 working tree, `docs/status.md`): **1924
passed, 0 failed, 4 ignored** across 155 suites, plus `npm --prefix sdk-js
test` 8/8. Counts move with the tree — `scripts/test_count.sh` is the single
source of truth; do not trust a stale number in prose.

```sh
cargo test --workspace
npm --prefix sdk-js test
python verification/sim/verify_vectors.py --check
```

Fast loops per subsystem:

```sh
cargo test -p srct-core --lib
cargo test -p srct-node --test api
cargo test -p srct-miner
cargo test -p srct-diloco
cargo test -p srct-cnnp
cargo test -p srct-intent
cargo test -p srct-agentnet
cargo test -p srct-compute
cargo test -p srct-fhe
cargo test -p srct-zkml
cargo test -p srct-workgraph
cargo test -p srct-verify
cargo test -p srct-l2 --test tee_evidence
cargo test -p srct-core --test committee_rotation
```

Examples: `crates/srct-diloco/examples/train_demo.rs` (24-round training),
`crates/srct-cnnp/examples/cnnp_demo.rs`,
`crates/srct-agentnet/examples/agentnet_demo.rs`,
`crates/srct-intent/examples/intent_demo.rs`,
`verification/sim/policy_decide_demo.py --self-test`.

---

## Security model and threat assumptions

What the chain assumes, honestly stated:

- **Hash-majority honesty** for PoW confirmation; bootstrap keys are public
  test vectors until bonded stake rotates the committee.
- **BLS quorum trust pre-slash**: checkpoint and arbitration votes are
  evidence first — equivocation is detected, not automatically punished.
- **Fail-closed everywhere**: unknown tx types, unregistered workers, bad
  signatures, non-finite deltas, over-budget plans, expired quotes, and
  out-of-order ratchet messages are refused, never defaulted open.
- **Integer-only consensus paths**: no floating point in mining, difficulty,
  supply, fees, or settlement; Q16.16 saturates instead of wrapping.
- **Conservation checked in code**: L1/L2 conservation endpoints and fuzz
  targets assert `conservation_total == funded_total` after every operation;
  escrow books enforce `Σ released ≤ funded`; royalty splits sum exactly.
- **Replay protection**: nonces strictly increase (policies, credentials),
  receipts and artifacts are once-only by hash, quotes carry heights and
  expiries, mailbox guards never evict.
- **Wallet at rest**: Argon2id (19 MiB, t=2, p=1) + ChaCha20-Poly1305, 0600
  files, atomic tmp+rename writes, in-memory keys zeroized. Plaintext wallets
  require an explicit opt-out flag. No HSM, no seed phrase (documented future
  work in [`docs/wallet-safety.md`](docs/wallet-safety.md)).
- **What is NOT assumed**: no network privacy (ids, roles, sizes, timing are
  visible; sealed sender hides the sender only); no TEE trust without a
  correct roots registry and freshness windows; no FHE/ZK soundness beyond
  stated prototype parameters; no bridge trustlessness for intents (named
  arbiters, operator roots); no fiat settlement by the node.

Disclosure policy: [`docs/SECURITY.md`](docs/SECURITY.md) (90-day window,
GitHub Security Advisory intake). **A passing test suite is not an audit** —
see below.

---

## Current limitations

- PoUW consensus is implemented but **disabled** (`pouw_activation_height =
  0`); the chain is hash-secured and AI training earns no issuance.
- GPU/TPU/NPU/Apple/photonic backends are **interfaces with CPU fallback**;
  no silicon kernels, no collectives, no power/thermal modeling.
- TFHE is a **labeled toy** (`N = 128`, non-constant-time); FHE handles linear
  functions with public weights only.
- ZKML is **Sigma protocols, not SNARKs**; ≤ 8 inputs × 16 bits; batch folding
  is linear batching, not recursion; weights public.
- Compute/CNNP/workgraph/intent payouts are **instructions, not coin
  transfers**; the prototype books are not wired to L1 UTXOs.
- Two escrows (L1 job hold vs compute pot), two reputations (passport tiers vs
  compute score), two discovery mechanisms (JSON board vs gossip set) share
  names but not state — operators must not mix them.
- Messaging runs on **in-memory transport**; no relay daemon, no group
  consensus transport, full guard tables refuse rather than rotate.
- No external audit, no published PGP release key, no log-shipping/OTLP
  observability, no HSM/seed-phrase wallet support.

---

## Development roadmap

Ordered, with entry criteria:

1. **Harden L1 operations.** Publish PGP key, add log-shipping/OTLP, backup
   runbooks for `chain.json`/`wallets.json`/policy dir, release tagging.
2. **External audit.** Independent review of consensus, cryptography, and
   wallet handling before any value-bearing mainnet.
3. **PoUW activation path.** Fork schedule, migration plan, wire v2
   shard/hyperparameter commitments; only then a nonzero activation height.
4. **Real hardware.** Vendor kernels behind the `TrainBackend` seam with
   conformance gates; silicon proofs before any "runs on X" claim.
5. **Production cryptography.** Replace toy TFHE parameters (or integrate a
   real TFHE/FHE library), NUMS ceremony for the ZKML basis point, larger
   circuits, range proofs over hidden weights.
6. **Rail integration.** Execute prototype settlement instructions against
   real UTXOs with conservation proofs; unify or clearly separate the
   duplicate escrow/reputation/discovery mechanisms.
7. **Agent transport.** Relay daemon, group delivery semantics, guard rotation
   policy, then multi-node agentnet E2E.

---

## Mainnet readiness and deployment

Evidence-based status lives in
[`docs/mainnet-readiness.md`](docs/mainnet-readiness.md) — five separate
columns per item: implemented, tested, audited, operationally deployed, still
required. Headline: L1 mechanics are implemented and tested (including BLS
adversarial suites, L2 end-to-end plus chaos, 3-node TCP sync, external miner
roundtrips); **nothing is audited, nothing is operationally deployed**, and
release tagging, PGP publication, and observability are still required. Do not
treat green test columns as a launch decision.

---

## License

**Copyright © 2026 The Solar Cyber Unit developers.**

**Code: MIT** — the same permissive licence Bitcoin Core uses. Full text at
the repo root (`LICENSE-MIT`). You may use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the software.

---

*Document status: rewritten 2026-11-13 against the implementation at `main`.
Supersedes all prior README development summaries. Per-subsystem detail lives
in `docs/`; where this file and a subsystem doc disagree, the subsystem doc's
math and the code win — file an issue.*
