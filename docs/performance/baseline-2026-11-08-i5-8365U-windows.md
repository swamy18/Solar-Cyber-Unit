# Baseline report — 2026-11-08, reference dev box

Machine: Windows 11 64-bit, Intel i5-8365U (4C/8T, 1.6 GHz base), 8 GB RAM,
rustc 1.99.1, `--release` (opt-level 3, thin LTO). Mini profile, deterministic
seeds. Peak RSS: `null` — Windows has no `/proc`; RSS must come from the
Linux 1/2/4 GB runs. **These numbers are relative baselines only and do not
qualify any VPS tier.**

Raw JSON: `results/baseline-2026-11-08-i5-8365U-windows-*.json` (same directory).

## Results (release)

### empty × 800 (812 blocks on disk incl. 12 setup)

| stage | wall_ms | detail |
|---|---|---|
| build_and_validate | 544 | 812 blocks, 812 UTXOs |
| store_persist | 6435 | log 330,270 B |
| store_reopen_index_rebuild | 34 | 812 records indexed |
| chain_replay_validate | 572 | 0.7 ms/block |
| l2_replay | 9 | empty L2 state (floor) |
| mempool_admit_2000 | 2884 | 803 admitted (~3.6 ms each) |
| totals | 10478 | — |

### realistic × 200, 14 spends/block (234 blocks, +14 net UTXO/block)

| stage | wall_ms | detail |
|---|---|---|
| build_and_validate | 11149 | ~55 ms/block, ~3.9 ms/spend incl. signing |
| store_persist | 1834 | log 1,086,202 B |
| store_reopen_index_rebuild | 43 | — |
| chain_replay_validate | 1308 | ~5.6 ms/block with txs |
| l2_replay | 6 | floor |
| mempool_admit_2000 | 694 | 242 admitted (faucet-limited) |
| totals | 15034 | 3,201 UTXO entries |

### adversarial × 10 gas-cap-full + 60 pacing empties (109 blocks)

| stage | wall_ms | detail |
|---|---|---|
| build_and_validate | 3687 | ~370 ms/full block, ~3.3 ms/spend |
| store_persist | 597 | log 470,788 B |
| store_reopen_index_rebuild | 26 | — |
| chain_replay_validate | 555 | — |
| l2_replay | 4 | floor |
| mempool_admit_2000 | 264 | 111 admitted (faucet-limited) |
| totals | 5133 | 2,523 UTXO entries |

## Analysis

1. **Persist cost is per block, not per byte.** 6.4 s for 812 empty blocks
   vs 1.8 s for 234 realistic blocks ≈ 8 ms/block in both: `meta.json`
   rewrite + fsync on every tip advance dominates. Batching tip advances
   is the obvious Phase B disk win (crash-safety design required).
2. **Validation is signature-bound.** ~3–4 ms/spend end-to-end (sign +
   verify) on this box; replay of tx-bearing blocks costs ~8× empty replay
   per block. No superlinear behaviour observed over these heights.
3. **Reopen is cheap at small history** (26–43 ms: full scan + decode +
   index of ≤1 MB). The O(history) shape is what matters — re-measure at
   100 k+ blocks on the 1/2/4 GB boxes.
4. **L2 replay on empty L2 state is noise** (4–9 ms). This is the floor,
   not the cost: L2-state replay with real positions/tasks is unmeasured
   and must be benchmarked before any L2 pruning claim.
5. **Mempool admission ≈ one signature verification each** (~3.6 ms).
   The 32 MB cap bounds count, not CPU: a full pool under flood still
   pays verify-per-tx on churn.
6. **Fee dynamics bound sustained throughput, not validation.**
   Above-target blocks raise base fee ~+31–84 %/block (measured rule,
   `fees.rs::next_base_fee`); the harness paces adversarial blocks with
   empties to measure validation instead of fee explosion.
7. **RSS unmeasured here** (`null`). The Linux runs must record VmHWM;
   the confirmed RAM risks from the Phase 0 audit (full canonical
   `Chain.blocks` + per-block undo + full L2 maps in heap) need numbers,
   not estimates.

## Phase B recommendations (from these numbers + Phase 0)

1. Batch tip persistence (fewer meta fsyncs per block) with the same
   crash guarantees — biggest measured per-block cost.
2. Make peer/inbound/stratum caps configurable with 1 GB defaults
   (thread-per-peer + 9 MB pool buffers dominate small-box RSS before any
   chain data does).
3. Stream the legacy `blocks.json` migration (today: whole file into RAM).
4. Keep canonical pruning blocked on audited snapshots (Phase 0 §9):
   nothing here changes that dependency.
5. Add the §7 Linux matrix (1/2/4 GB) with VmHWM + iowait recorded; gate
   any "supported" claim on it.
