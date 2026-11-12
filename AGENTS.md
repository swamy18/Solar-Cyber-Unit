# AGENTS.md

This is the source of truth for the checks to run during a session, so they are not
re-derived each turn.

## Lint and type-check

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
```

## Tests

```bash
# Run everything.
cargo test --workspace
# Core escrow + service unit tests.
cargo test -p srct-core --lib
# Node HTTP API integration tests (roadmap items 2 and 4).
cargo test -p srct-node --test api
# Mining stack: solver/stratum/payouts/backends, template/submit roundtrips.
cargo test -p srct-miner
# DiLoCo proof-of-useful-work prototype (real training + adversarial rounds).
cargo test -p srct-diloco
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
