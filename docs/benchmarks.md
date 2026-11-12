# Benchmarks

Measured on this machine (Windows, release mode unless noted). Each number
reproduces via the ignored bench test named beside it:

```bash
cargo test --release -p srct-compute --test tee bench_ -- --ignored --nocapture
cargo test --release -p srct-fhe --test fhe bench_ -- --ignored --nocapture
cargo test --release -p srct-zkml --test zkml bench_ -- --ignored --nocapture
```

## Proof systems (release)

| Operation | Latency | Notes |
|---|---|---|
| TEE quote sign + verify | 1.02 ms | `bench_tee_quote_verify`, 200 ops |
| FHE keygen | 0.17 ms | `bench_fhe_ops` |
| FHE encrypt | 0.27 ms/ct | secp256k1 ElGamal |
| FHE weighted-sum eval (4 inputs) | 1.18 ms | homomorphic only |
| FHE decrypt (bound 2^20) | 12.5 ms | BSGS table ~1k entries; bound 2^32 ≈ 42 s suite time (debug) |
| ZK prove (4-input linear) | 45.2 ms | 64 OR-proofs, `bench_zk_prove_verify` |
| ZK verify | 25.9 ms | same |

Takeaways: verification is cheap everywhere (TEE ~1 ms, ZK ~26 ms);
decryption cost is caller-controlled via the decode bound; proving is the
only expensive step and stays interactive for small statements.

## Training and interop (debug, from module docs)

| Operation | Latency |
|---|---|
| DiLoCo release round (3 workers) | 6.4–8.5 ms/round |
| CNNP ridge adapter fit (128 pairs) | 1.9–3.4 ms |
| CNNP two-stage plan quote | 30 sat, 100 ms |
| Workgraph royalty settlement | sub-ms (integer arithmetic, depth-capped) |
| Intent attach + settle (TEE/ZK) | dominated by the proof checks above |

## What is not benchmarked yet

Throughput under load, gossip propagation latency, journal replay at cap
(4,096 entries), multi-round DiLoCo convergence at scale, and live-network
latencies. Those need a running network, not a unit harness.
