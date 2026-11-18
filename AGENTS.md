# AGENTS.md

This is the source of truth for the checks to run during a session, so they are not
re-derived each turn.

## Lint and type-check

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
```

## Tests

Fast inner loop (iteration; same assertions, smaller build/test surface —
use while editing a single crate; the full suite below remains the gate):
```bash
# Unit tests only for the crate being edited (no integration binaries, no doc tests).
cargo test -p srct-core --lib
# Integration tests for one crate only, one binary at a time.
cargo test -p srct-core --test api
# Skip doc tests during iteration (each doc example is a separate rustc invocation).
cargo test -p srct-core --lib --tests
```

Full verification gate (unchanged semantics — run before reporting done):
```bash
# Run everything.
cargo test --workspace
# Core escrow + service unit tests.
cargo test -p srct-core --lib
# Node HTTP API integration tests (roadmap items 2 and 4).
cargo test -p srct-node --test api
# Mining stack: solver/stratum/payouts/backends, template/submit roundtrips.
cargo test -p srct-miner
# CNNP representation/adapter/discovery/metering core.
cargo test -p srct-cnnp
# Decentralized E2E agent messaging (envelopes, double ratchet, mailbox).
cargo test -p srct-agentnet
# Decentralized compute sharing (offers, sharding, receipts, settlement, bonds, TEE).
cargo test -p srct-compute
# Encrypted-compute prototype (ElGamal tasks, receipts, verifier).
cargo test -p srct-fhe
# ZKML verification prototype (Sigma proofs, tasks, receipts, verifier).
cargo test -p srct-zkml
# AI Work Graph (artifacts, lineage, royalty settlement).
cargo test -p srct-workgraph
# Unified verification policy (policy table, TEE/FHE/ZK verifier).
cargo test -p srct-verify
# L2 TEE evidence type (attestation, verification, contract path).
cargo test -p srct-l2 --test tee_evidence
# JS SDK (mock-transport REST client tests).
npm --prefix sdk-js test
# Proof-system benchmarks (release mode, ignored by default).
cargo test --release -p srct-compute --test tee bench_ -- --ignored --nocapture
# Cross-network intent lifecycle, quotes, routes and disputes.
cargo test -p srct-intent
cargo test -p srct-core --test committee_rotation
cargo test -p srct-node --test api external_miner
# Escrow-specific subsets.
cargo test -p srct-core --lib escrow
cargo test -p srct-node --test api escrow
```

## Style notes

- Edition 2021; code uses 4-space indentation, no emojis.
- Prefer editing existing files; do not add doc files unless asked.
- Do not commit unless explicitly requested.
