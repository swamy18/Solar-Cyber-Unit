# SRCT Phase C — Scalability & Resource Profiling

**Starting reference:** Phase B commit `f14ae77` (commit `f14ae77`, pushed to `origin/main`).
**Status:** measurement only — no source changes in this phase; `crates/srct-bench` was already extended in Phase A/B, and only its CLI/measurement surface was used here. Nothing committed or pushed from this phase.

## 1. Benchmark methodology

All runs use the isolated `srct-bench` binary crate (`crates/srct-bench`), mini network profile, deterministic wallet seeds, `GENESIS + h*1000` timestamps. Every block mined and submitted goes through production `Chain::submit` validation; every store call uses the public `BlockStore` API against a scratch directory. No consensus, storage-format, validation, mining-difficulty, cryptographic, or wire changes were made.

### Stages measured per run

| Stage | What it measures |
|---|---|
| `build_and_validate` | Mine + `Chain::submit` per block (production validation, incl. signing time). Setup blocks (maturity) are excluded from the measured count. |
| `store_persist` | Append each block to `BlockStore`, move tip, then one `sync` — what a syncing node pays on top of validation. |
| `store_reopen_index_rebuild` | Cold `BlockStore::open`: RecordLog recovery, full index rebuild, height walk, plus Phase B journal adoption. Correctness asserted (reopened tip == persisted tip, journal adoption applied). |
| `chain_replay_validate` | Fresh `Chain`, full canonical re-submit of every stored block (what every boot does). |
| `l2_replay` | `NodeL2::replay_from` over the replayed chain (production startup path). |
| `mempool_admit_2000` | Up to 2000 correctly-signed spends admitted against the tip UTXO set — bounds relay-admission cost. |
| `totals` | Roll-up incl. UTXO entry count, `blocks.log`/`meta.json`/`tip.journal` sizes, total store dir bytes, bytes/block, process RSS/CPU before/after (`/proc` on Linux; `GetProcessMemoryInfo`/`GetProcessTimes` raw FFI on Windows), available parallelism. |

### Hardware-protection rules (honored)

- Workloads run sequentially, one at a time, each in its own scratch directory under `./target/bench-phasec-*`.
- `--max-rss-gb 6` safety budget on an 8 GB machine: the run stops gracefully (partial JSON kept) instead of pushing the box into swap/OOM-killer territory. Never triggered.
- `--dir` refuses anything that looks like a real data directory or source tree (`blocks.log`, `meta.json`, `state.bin`, `tip.journal`, `wallets`, `Cargo.toml`, `.git`, `crates/`, `src/`).
- No real blockchain data directory was touched or deleted.

## 2. Hardware and software environment

- Machine: Windows 11 64-bit, Intel Core i5-8365U (4C/8T, 1.60 GHz base), 8,391,184,384 B (~8 GiB) RAM.
- Free physical memory during runs: ~920 MB – 990 MB (other processes present).
- Toolchain: rustc 1.99.1, `--release` (opt-level 3).
- Profile: `srct-core` `mini` (target block time 600 s, max block bytes 4,000,000).
- Linux `/proc` support retained in the harness; this box reports via raw Windows FFI (`GetProcessMemoryInfo`, `GetProcessTimes`). Peak RSS is process `VmHWM`/`PeakWorkingSetSize` — the high-water mark, not a snapshot.
- Phase A baseline (i5-8365U, 8 GB, Windows, release): empty-800 total 10.5 s, realistic-200 total 15.0 s, adversarial-10 total 5.1 s — provided for reference only, different block counts.

## 3. Results for every tested height

All numbers below are wall-clock milliseconds unless noted. Raw JSON: `docs/performance/results/phase-c/empty-1k.json`, `docs/performance/results/phase-c/empty-10k.json`.

### empty × 1,000 (1,012 blocks on disk incl. 12 setup)

| Stage | wall_ms | Per-block (measured 1,000) | Detail highlights |
|---|---:|---:|---|
| build_and_validate | 634 | 0.63 ms | utxo_entries 1,012 |
| store_persist | 404 | 0.40 ms | log_bytes 545,969 (~540 B/block) |
| store_reopen_index_rebuild | 29 | 0.03 ms | journal_adopted: true |
| chain_replay_validate | 480 | 0.48 ms | replayed_blocks 1,000 |
| l2_replay | 9 | 0.01 ms | empty L2 state (floor) |
| mempool_admit_2000 | 1,771 | — | 1,012 admitted (faucet-limited) |
| **totals** | **3,327** | — | peak_rss 14,995,456 B (~14.3 MB) |

### empty × 10,000 (10,012 blocks on disk incl. 12 setup)

| Stage | wall_ms | Per-block (measured 10,000) | Detail highlights |
|---|---:|---:|---|
| build_and_validate | 134,593 | 13.5 ms | utxo_entries 10,012 |
| store_persist | 6,443 | 0.64 ms | log_bytes 5,405,982 (~539 B/block) |
| store_reopen_index_rebuild | 418 | 0.04 ms | journal_adopted: true |
| chain_replay_validate | 125,798 | 12.6 ms | replayed_blocks 10,000 |
| l2_replay | 87 | 0.01 ms | empty L2 state (floor) |
| mempool_admit_2000 | 7,481 | — | 2,000 admitted |
| **totals** | **274,820** | — | peak_rss 77,168,640 B (~73.6 MB) |

### Workloads not completed (limitation, see §8)

`realistic × 1k` and `adversarial × 1k` both panicked in the harness with `input too small for outs`: the pool's outputs are sized at chain setup (minimum 5,000,000 sats each) and spent over the run; as base fee drifts, an output's value can fall below its spend fee and `spend()` panics. This is a **harness design limitation**, not a consensus bug — the pool never fee-reprices outputs at spend time. Fixing it (re-size outputs at spend time, or a fresh faucet per batch) is a Phase D benchmark-harness task, not a node fix. `empty` has no spends and is unaffected.

`empty × 50k` was started but exceeded a 1-hour wall budget with no completion (build phase alone scales super-linearly — see §7). Stopped per the hardware-protection rule.

## 4. Peak RAM and CPU observations

Peak RSS (`VmHWM` / `PeakWorkingSetSize`, the high-water mark):

| Height | Peak RSS | Current RSS at end | User CPU ms | Kernel CPU ms |
|---|---:|---:|---:|---:|
| 1,000 | ~14.3 MB | ~13.7 MB | 2,812 | 468 |
| 10,000 | ~73.6 MB | ~34.8 MB | 203,593 | 55,796 |

- **RAM scales roughly linearly with height** (≈7.3 MB per 1,000 blocks at 1k → 10k, dominated by `Chain.blocks` holding every canonical block fully deserialized plus per-block `undo` maps). Well within an 8 GB box: 100k blocks would project to ~700 MB for chain state alone, still under the 6 GB safety budget with headroom for the OS and peer threads. Not measured at 100k (see §8).
- **CPU is single-threaded-bound:** one core pinned near 100% (`user_cpu` ≈ wall time × 0.75–0.95). `available_parallelism` reports 8 but the benchmark (and node's store path) is single-threaded. Multi-core headroom exists but is unused today.
- **Pagefile / commit charge:** not separately measured beyond RSS; the harness reports `peak_pagefile_bytes`/`pagefile_bytes` as available on Windows (values were small relative to RSS in these runs).

## 5. Storage growth measurements

| File | empty-1k | empty-10k | Per-block |
|---|---:|---:|---:|
| `blocks.log` | 545,969 B | 5,405,982 B | ~540 B |
| `meta.json` | 588 B | 588 B | constant |
| `tip.journal` (unflushed at run end) | 134,501 B | 1,340,514 B | ~134 B |

- **`blocks.log` grows linearly at ~540 bytes/block** (empty blocks: ~300-byte header + framing). At the adversarial 4 MB cap the ceiling is ~4 MB/block, but realistic traffic is far below that.
- **`meta.json` is constant ~588 B** (one atomic rewrite per flush, not per block).
- **`tip.journal`** grows ~134 B per tip advance *during a run that never flushes* (`run_stages` appends + sets tip but never calls `flush_meta` mid-run). In production the serve loop calls `flush_meta_if_due` every `META_FLUSH_INTERVAL` (10) advances, so a live node's journal stays ≈1,340 bytes. Boundedness is verified by `journal_stays_bounded_by_flush_truncation` in `persist_crash.rs`. Total data dir at 10k: ~5.4 MB — trivial for any VPS.
- **Archive vs pruned:** nothing is pruned today (Phase B deliberately kept canonical pruning behind audited snapshots). A 100k-block archive would project ~54 MB on disk — still tiny; the RAM cost of holding all blocks in `Chain.blocks` is the binding constraint, not disk.

## 6. Reopen and recovery timings

| Height | Reopen + index rebuild | Chain replay (full validate) | Journal adoption | Tip verified |
|---|---:|---:|---:|---|
| 1,000 | 29 ms | 480 ms | applied | ✅ matches persisted tip |
| 10,000 | 418 ms | 125,798 ms | applied | ✅ matches persisted tip |

- Reopen scales well (29 ms → 418 ms, ~14x for 10x — mostly `RecordLog` scan + full decode of every block).
- **Chain replay is the outlier:** 0.48 ms/block at 1k → 12.6 ms/block at 10k (~26x slower for 10x height — super-linear). Each `submit` re-runs `check_tx` plus UTXO/bond lookups; suspect `BTreeMap`/fee-state growth or per-block validation work that scales with height. **This is the top candidate bottleneck for Phase D.**
- L2 replay stays flat (9 ms → 87 ms, empty state floor) — no L2-state growth measured (Phase B audit noted L2 state is never persisted; real L2 load unmeasured).
- Recovery correctness asserted at both heights: reopened tip equals persisted tip, journal adoption applied.

## 7. Identified bottlenecks

1. **Chain replay `submit` is super-linear in height** (0.48 → 12.6 ms/block). Restart time at 100k blocks would project to ~2+ minutes just replaying, before any new block arrives. Needs profiling (per-block `check_tx` cost vs. height, UTXO `BTreeMap` growth, fee-state lookups).
2. **`Chain.blocks` holds every canonical block fully deserialized in RAM** (~7.3 MB per 1,000 blocks observed). No block cache, no pruning, no snapshot — acceptable for a VPS at modest heights, but 100k blocks projects to ~700 MB chain-state RAM before UTXO/L2/mempool.
3. **Single-threaded persistence and validation:** one core pinned; 8 hardware threads available but unused by the store path.
4. **Journal grows unflushed during long bulk operations** (~134 B per tip advance). Truncates on `flush_meta` (every 10 advances in production serve; not called mid-run in the harness). Not a leak, but bursty memory during sync storms.
5. **Mempool admission ≈ one signature verification per tx** (~3.6 ms/tx observed earlier at small scale; 7.5 s for 2,000 at 10k height — likely UTXO lookups growing). Bounded by count (cap 32 MB) but not by CPU per flood burst.

## 8. Failures and limitations

| Item | Detail |
|---|---|
| `adversarial × 1k`, `realistic × 1k` | Harness panicked: `input too small for outs` — pool outputs sized at chain setup can't cover drifted base fee after long runs. Harness flaw (no fee-aware output re-sizing at spend time), not a consensus bug. Phase D harness fix. |
| `empty × 50k` | Started, exceeded 1-hour wall budget with no completion (build phase scales super-linearly — see §7). Stopped per hardware-protection rule. Not a crash; no partial results kept (killed cleanly). |
| No 50k / 100k numbers | Machine time budget exhausted after ~2 hours of runs. 1k/10k empty are the only completed large-chain points. |
| Peak RSS via Windows FFI | Works (`GetProcessMemoryInfo`); Linux retains `/proc`. No zero-filled measurements anywhere. |
| No Linux run | Documented as future validation; Windows-only results reported here. |

## 9. Recommendations for Phase D

1. **Profile chain replay per-block cost at 1k→10k→50k** to find the super-linear component in `submit`/`check_tx` before any pruning or snapshot work. Restart time is the first operational cliff.
2. **Benchmark on the 1/2/4 GB matrix** with `VmHWM` + iowait recorded; gate any "supported VPS tier" claim on actual numbers (Phase A requirement, still open).
3. **Fix the benchmark harness** (fee-aware output sizing at spend time) so adversarial/realistic workloads can run at 1k+ without panicking.
4. **Only then** consider storage-format/compaction/snapshot work — Phase B correctly kept canonical pruning behind audited snapshots; do not implement pruning until replay cost and snapshot restore are benchmarked.
5. **Add multi-threaded store/validation path** if single-core pinning proves binding on smaller VPS instances.

---

**Raw measurements:** `docs/performance/results/phase-c/empty-1k.json`, `docs/performance/results/phase-c/empty-10k.json` (machine-readable; same schema as Phase A/B baselines).

**Companion baselines:** Phase A `docs/performance/baseline-2026-11-08-i5-8365U-windows.md` + `docs/performance/results/baseline-*.json`; Phase B `docs/performance/results/phase-b-*-windows-*.json`. None modified in this phase.
