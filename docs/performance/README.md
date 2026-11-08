# SRCT Performance Benchmarking — Method

Phase A is measurement only. Nothing here changes consensus, storage formats,
validation, mining, cryptography, or the wire protocol. The harness
(`crates/srct-bench`) builds deterministic chains with the production
`Chain::submit` path and times each pipeline stage separately.

## Harness

- Location: `crates/srct-bench` (binary crate, isolated: no consensus crate
  depends on it; adding it changes no existing build graph).
- Run: `cargo run --release -p srct-bench -- run --workload <w> --blocks <n>
  --dir <scratch> [--json out.json] [--markdown out.md]`.
  Always `--release`: validation is signature-hashing dominated and debug
  builds measure the wrong thing (empty-800 replay: 5.1 s debug vs 0.57 s
  release on the reference box).
- Determinism: mini profile, fixed wallet seeds, `GENESIS + h*1000`
  timestamps. Same flags ⇒ same chain, same numbers (modulo machine noise).

## Workloads

| Workload | Shape | What it measures |
|---|---|---|
| `empty` | Coinbase-only blocks | Floor cost: headers, indexing, replay, mempool admission of plain spends |
| `realistic` | 14 spends/block, 1-in-2-out (≈245 k gas, near the 250 k gas target) so EIP-1559 fees stay flat | Validation + UTXO/store growth at steady state |
| `adversarial` | Gas-cap-full blocks (~110 1-in-2-out, ~1.9 M of the 2 M cap) with 6 interleaved empty blocks per full block | Worst-case validation CPU inside protocol limits |

Fee note (measured, not assumed): sustained above-target blocks raise the base
fee ~+31–84 %/block, so an uninterrupted full-block run measures fee
explosion, not validation. The interleaved empties (~−12 %/block) keep the fee
oscillating instead — documented in the harness, not hidden.

A universal chain rule the harness obeys (and benchmarks depend on):
**every output, not just coinbases, must age `coinbase_maturity` blocks
before it may be spent** (`ledger.rs::check_tx`). The pool therefore carries
a 10-block pipeline of ripening outputs; a run that ignores this fails
closed at block build time.

## Stages (per run)

1. `build_and_validate` — mine + `submit` (production validation), incl. signing time.
2. `store_persist` — append + tip + sync to a fresh `BlockStore`.
3. `store_reopen_index_rebuild` — cold open: RecordLog recovery, full index rebuild, height walk.
4. `chain_replay_validate` — fresh `Chain`, full canonical re-submit (what every boot does).
5. `l2_replay` — `NodeL2::replay_from` over the replayed chain (floor cost on empty L2 state).
6. `mempool_admit_2000` — up to 2000 correctly-signed spends admitted against the tip UTXO set.
7. `totals` — roll-up incl. `utxo_entries`, `log_bytes`, peak RSS.

## Output schema (`results/*.json`)

```json
{
  "tool": "srct-bench",
  "workload": "realistic", "blocks": 200,
  "note": "mini profile, deterministic seeds; no consensus/storage/wire changes",
  "stages": [
    {"workload": "...", "blocks": 200, "stage": "build_and_validate",
     "wall_ms": 11149, "detail": {"chain_height": 234, "utxo_entries": 3201, "...": "..."}}
  ]
}
```

Each run also writes a same-name `.md` table. Both live under
`docs/performance/results/` — never under `crates/`.

## Reproducing

```text
cargo run --release -p srct-bench -- run --workload empty --blocks 800 --dir ./target/bench-empty
cargo run --release -p srct-bench -- run --workload realistic --blocks 200 --dir ./target/bench-realistic
cargo run --release -p srct-bench -- run --workload adversarial --blocks 10 --dir ./target/bench-adversarial
```

Record with every result file: OS + arch, CPU model, total RAM, rustc
version, profile (`--release`), and peak RSS. RSS comes from
`/proc/self/status` (`VmHWM`) on Linux; on other OSes the harness emits
`null` instead of inventing a number. **A result without machine specs is
not a baseline.**

## Environment matrix (required before any support claim)

Run the matrix on 1 GB, 2 GB and 4 GB Linux boxes and record whether the
run is CPU- or memory-constrained (OOM-killer hits, swap activity, iowait).
**Do not claim a configuration is supported without a passing run on it.**
The reference runs in this repo were taken on an 8 GB Windows dev box —
relative comparisons only, not a qualification of any VPS tier.

## Regression tests required

- CI gate: `store_reopen_index_rebuild` and `chain_replay_validate` wall
  times on `empty × 800` must not regress beyond noise (catches accidental
  O(n²) in open/replay paths).
- `mempool_admit_2000` admission count must stay at the faucet limit and
  never regress to mass rejection (catches fee/maturity rule drift in the
  harness's assumptions).
- JSON schema stability: `results/*.json` must keep the keys above so
  reports stay comparable across runs.
