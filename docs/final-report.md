# Final Verification Report — 2026-10-09

> **Historical snapshot.** Later decisions supersede parts of this report:
> Decisions 25–26 moved policy and credit on chain, and Decision 27 added the
> 21-key mainnet bootstrap committee while keeping L2 settlement fail-closed.
> Current status lives in `docs/status.md`.

Scope: finish the genuinely remaining work, resolve or isolate the documented
protocol blockers, verify everything, and leave the repository in a defensible
public-testnet / mainnet-candidate state — **without** inventing protocol
economics, changing consensus, or faking verification. No code was changed; all
changes are documentation truthfulness plus new design/audit records.

## 1. Current HEAD commit

`dd2e1da782197303254111a53b825a14c158a221` ("fix: update worker_flows fuzz target
to L2NodeView fallible interface"), branch `main`. Working tree has uncommitted
documentation changes (see §13/§15); no commits were created.

## 2. Tests passed / failed

```
cargo test --workspace     → 870 passed, 0 failed, 1 ignored (vwc_perf_probe)   # historical snapshot as of dd2e1da, 2026-10-09; current counts come from scripts/test_count.sh
cargo fmt --all --check    → clean
cargo clippy --workspace --all-targets --all-features -- -D warnings → clean
cargo build --workspace --release → succeeded
```

This supersedes the 755-test figure in `docs/sprint-status.md` (recorded then);
`docs/sprint-status.md` now carries a 2026-10-09 addendum with these numbers.

## 3. Fuzz targets — actual executions / crashes

Fourteen targets, WSL2 Ubuntu nightly + **ASan** (confirmed in logs), 30 s each,
2026-10-09, over committed corpora plus a seedless start. All `rc=0`.

| target | execs | target | execs |
|---|---:|---|---:|
| tx_decode | 1,157,972 | l2_payload_decode | 969,970 |
| block_decode | 594,510 | m3_readers | 581,483 |
| wire_msg_decode | 1,158,948 | dispute_arbitrate | 1,682,553 |
| mempool_admit | 1,688 | l2_state_apply | 1,478 |
| storage_recover | 1,369 | vwc_decode | 1,417,179 |
| checkpoint_validate | 16,584 | worker_flows | 3,299 |
| meta_parse | 194,412 | checkpoint_codec | 1,570,716 |

**Total 9,352,161 executions, 0 crashes, 0 sanitizer findings, 0 timeouts.** The
low-count targets are capability-bound (real fsync / real chain / real BLS per
iteration), documented as such in `docs/fuzz.md`. The previous `docs/fuzz.md`
table was fabricated (impossible test-isolate counts, duplicated rows) and has
been replaced with this measured run.

## 4. Security findings

No new vulnerability was found this session. The security document overstated
itself ("No critical or high-severity issues") and cited wrong decision numbers;
`docs/security_audit.md` now says "none found by the methods used", names the
self-review limitation, and points at the four real pre-mainnet items (exit
path, M2 rule, M4 registration, and the unbonded committee). No open
high-severity issue in the reviewed surfaces stands.

## 5. Benchmark results (real, measured)

Intel Core i5-8365U (8 logical), Windows, release build, 2026-10-09:

| Path | Measured |
|---|---|
| Mine 300 mini blocks (PoW included) | 225,824 ms (~753 ms/block, PoW-bound — **not** validation) |
| `srct-node verify` (replay+validate 301 blocks) | 304 ms (~1.0 ms/block, incl. process start) |
| `srct-node status` (storage reopen) | 193 ms |
| VWC encode / decode / validate | 4.16 µs / 3.21 µs / 2,630.15 µs (real BLS) |
| `GET /v1/health` / `/v1/status` / `/v1/fees` | 9.1 ms / 2.0–3.0 ms / 2.4 ms |

The previous `docs/benchmarks.md` attributed numbers to an "M2 MacBook Air" and
reported storage/block/API figures with no probe behind them; those are deleted,
and the paths still unmeasured (isolated block validation, L2 apply rate,
storage append, transport throughput, large-chain replay, multi-node sync) are
now explicitly listed as **not measured**.

## 6. Chaos / network results

- `crates/srct-node/tests/chaos.rs` — 15 adversarial tests (invalid L2 payload
  skipped by name, unknown-task claim with no partial write, settle without
  quorum refused, rejected block never mutates L2 state, restart through the
  store, torn-tail recovery, invalid block not counted as work, future
  timestamp, fork choice by work, conservation). **Pass.**
- `crates/srct-node/tests/e2e_two_process.rs` — spawns a real `srct-node serve`
  subprocess and drives a real `WorkerClient` over HTTP/TCP through the whole L2
  lifecycle. **Pass** (true multi-process, not mocked).
- `crates/srct-net/tests/tx_relay.rs` — 10 real-socket relay tests. **Pass.**

## 7. SPEC / code mismatches found

1. **Supply arithmetic error in SPEC §7:** the unmintable remainder was written
   `787 400 SRCT`. The figure went through two corrections: first to **788 400**
   (39,945,600 − 39,157,200), then — once the approved tail forced the exact
   block-by-block semantics — to **788 476** (39,945,600 − 39,157,124), because
   genesis occupies a rung-0 height without minting. `supply::tests`,
   `verification/sim/supply_schedule_sim.py` and `verification/tests/vectors/supply_vectors.json` now pin
   the exact figure.
2. **SPEC reward formula matched nothing in code:** SPEC said
   `start_reward_sat >> halvings`, but `supply::period_reward_sat` halves
   **whole SRCT** (`(start_reward_srct >> period) * SAT_PER_SRCT`). Fixed to match
   the implementation, with the reason (sat-shifting pays 9.5 SRCT at epoch 3).
3. **SPEC §8 capped the fee at a `BASE_FEE_MAX` name that does not exist** and
   omitted the floor values. Corrected to `base_fee_min_sat`/`base_fee_max_sat`
   and their per-profile values (100/50,000,000 mainnet; 10/1,000,000 mini/testnet).
4. **`docs/monetary-policy.md` described a schedule that exists nowhere** (a
   10,000,000 SRCT cap, 1 SRCT initial reward, 210,000-block halving,
   `TARGET_SUPPLY_SAT`/`MAX_HALVINGS`). Rewritten from the code.
5. **`docs/l2-exit-design.md` cited a non-existent "Decision 21"** and further
   assumed the deposit sink could release funds — it cannot (no key). Rewritten.
6. **Readiness docs documented things that do not exist**: a `config.toml`, a
   `/metrics` endpoint, a `/health` route (it is `/v1/health`), a `--bootnode`
   flag (the plural `--bootnodes` flag was added later and now exists),
   `serve --sync`, a worker run command. All corrected to the real CLI/API.
7. **`docs/security_audit.md` and `docs/status.md` cited wrong decision numbers
   / a non-existent `SPEC.md §15` node-API section** (it is §19.2). Corrected.
8. **`docs/fuzz.md` and `docs/benchmarks.md` contained fabricated numbers.**
   Replaced with measured runs.

No code-vs-SPEC *consensus* mismatch remains: every item above was a document
that disagreed with code that is itself correct and test-pinned.

## 8. Protocol decisions still required

Recorded as blockers (not choices) in `docs/decisions.md` → *Pending*:

- **P1 — L2 → L1 exit primitive.** ~~The sink is unspendable; an exit needs a
  new L1 release rule.~~ **Resolved by Decision 19** (see §11.1): exits are
  implemented.
- **P2 — Bonded stake / mainnet committee.** ~~Stake transaction, bond ledger,
  unbonding, mainnet bootstrap committee, and the equivocation-slashing
  path.~~ **Resolved by Decision 20 + Decision 27** (bond ledger, TopN,
  unbonding, full-bond burn, 21-key bootstrap), **hardened 2026-10-28**
  (seed snapshots, per-epoch slash verification, fail-closed expiry).
- **P3 — M2 activation rule** ~~(what proves a compute result fraudulent)~~.
  **Resolved:** canonical CPU reference + fraud slashing through the M2 vault
  (see mainnet-readiness §7).
- **P4 — M4 registration** ~~(does the HBM puzzle replace or compose with
  §5)~~. **Partly resolved:** registered in code as `puzzle_id = 2` with a
  miner solver arm, but **not active** on any profile; activation still needs
  its decision (parameter defect + panic guard still open per the 2026-10-12
  HBM review).
- **P5 — settle-fee vs small-task interaction** ~~(`AmountTooSmallForFee`)~~.
  **Resolved by Decision 23:** 0.1% proportional fee, 1 000-sat floor.

## 9. Implementation work still remaining

None of it was authorised, so none was started: L2 exits, stake/bond ledger,
M2/M4 activation rules, a `srct-worker` run daemon verb, and the unmeasured
benchmark harnesses. **No line of product code changed this session.**

## 10. Operational work still remaining

`/metrics` (Prometheus) export, a node config file, structured log shipping, a
release/tagging pipeline, a `CHANGELOG.md`, a published PGP disclosure key, and
reproducible-build tooling.

## 11. Exact blockers preventing public testnet

1. ~~**L2 deposits are one-way** (P1).~~ **Resolved by Decision 19:** exits are
   implemented (SPEC.md §19.6), so testnet value is withdrawable wherever
   `exit_activation_height > 0`. Operators should still confirm that value before
   assuming it.
2. ~~**No worker daemon binary**~~ — `srct-worker run` ships the daemon loop over
   the node's REST API, gated on `/v1/conservation`.
3. **API is unauthenticated** — loopback/tunnel only.
4. **No metrics/log shipping** — monitoring is `/v1/status` polling.

Items 2–4 are operational and can be accepted for a first testnet; item 1 is a
design property, documented, not a defect. The L1 testnet itself (profile,
committee, binding finality at height 20, sync, relay, L2 task flow) is
implemented and verified.

## 12. Exact blockers preventing mainnet

1. ~~**P1 — exits undefined** (fund-safety).~~ **Resolved by Decision 19.**
2. ~~**P2 — no stake ledger and no mainnet committee** (`mainnet` committee is
   empty → finality fails closed and is untestable there).~~ **Resolved by
   Decisions 20 + 27**, hardened 2026-10-28 (seed snapshots, per-epoch slash
   verification).
3. **P3/P4 — M2 and M4 activation rules unspecified.** P3 resolved (M2
   closed); P4 still open — registered but inactive.
4. **§10 operational gaps** and **no third-party security audit**.

Mainnet readiness is **not claimed**.

## 13. Files changed

Modified: `SPEC.md`, `docs/monetary-policy.md`, `docs/l2-exit-design.md`,
`docs/mainnet-readiness.md`, `docs/testnet-readiness.md`, `docs/security_audit.md`,
`docs/fuzz.md`, `docs/benchmarks.md`, `docs/decisions.md`, `docs/status.md`,
`docs/roadmap.md`, `docs/sprint-status.md`.
Added: `docs/validator-economics.md`, `docs/final-report.md`.
All are documentation. No source, test, vector, CI or config file was touched.

## 14. Commits created

None. The changes are left uncommitted for review (the task did not request a
commit, and the repository uses small reviewable commits).

## 15. Is the git tree clean?

**No** — intentionally. `git status` shows 12 modified docs and 1 new doc
(+ this report). No code is dirty. The tree is clean of any code change; the
doc edits are the deliverable and are ready to review and commit.

## 16. Honest overall status

Classification of the work:

| Bucket | Contents |
|---|---|
| **DONE** | L1 core, P2P + tx relay, L2 (contract, six payloads, dispute, VWC), deposits + maturity, M5 binding finality on `testnet`, machine/agent identity + authorization, payments, receipts, reputation, bridge, MCP, worker SDK + HTTP transport + run daemon, two-process E2E, chaos suite, 14 fuzz targets (executed clean), vector cross-checks, monetary reconciliation, exit **rule (Decision 19)** |
| **NEEDS VERIFICATION** | Multi-node sync at real testnet scale; a third-party security audit; long fuzz campaigns on the capability-bound targets |
| **BLOCKED BY DECISION** | Stake ledger + mainnet committee (P2); M2 rule (P3); M4 registration (P4); settle-fee interaction (P5). *(P1 — the exit rule — is implemented; what remains for mainnet is the `exit_activation_height` configuration.)* |
| **IMPLEMENTATION REQUIRED** | Stake/bond ledger, M2/M4 rules, the mainnet exit activation height, worker `queue_exit` polish, benchmark harnesses — gated on the decisions above |
| **OPERATIONAL REQUIRED** | Metrics, config file, log shipping, release pipeline, PGP key, reproducible builds |

**Bottom line: this is a defensible public-testnet candidate for the L1/L2 task
and payment flow, and it is not mainnet-ready.** The core is implemented and
now honestly verified — 773 tests (historical snapshot as of 2026-10-09; current
counts come from scripts/test_count.sh), a real 9.35M-execution fuzz campaign with no
crashes, and real performance numbers. The remaining work is not "polish": it is
five protocol decisions that must not be guessed, and the exit decision is the
one that gates mainnet value safety. Nothing here is claimed complete that is
not; every fabricate-able number was replaced with a measurement or a labelled
"not measured".

## 17. Addendum — later sessions, 2026-10-09

Three statements above are superseded by work landed after this report was
written, and are recorded here rather than edited silently:

- **§9/§11: the `srct-worker run` daemon verb shipped** (discover → claim →
  execute → submit over the node's REST API, covered by `crates/srct-worker/
tests/cli_run.rs` and the two-process E2E), and **`/metrics` shipped**
  (Prometheus text gauges, §10's first item).
- **The conservation-enforcement gap closed.** `GET /v1/conservation` serves
  the three-check verdict live from the one implementation
  (`srct_node::conservation::conservation_report`) that `srct-node verify`
  prints from; `/metrics` exports `Solar Cyber Unit_joint_supply_sat` and
  `Solar Cyber Unit_conservation_ok`; and `srct-worker run` gates on that report before
  its first pass — a breach or unreadable numbers are refused with a
  non-zero exit naming the terms, an unreachable or non-reporting node warns
  and continues. The worker recomputes the verdict from the report's own
  terms (`ConservationReport::holds`), never the node's `ok` flag. Tests:
  `crates/srct-node/tests/conservation_api.rs` (3), http.rs unit tests (2),
  `cli_run.rs` fake-node gate tests (3), `ConservationReport` ordering test.
- **What this does not do:** detection is on-demand (endpoint, scrape,
  worker startup), not a serve-loop halt. What a node that detects value
  creation should *do* — halt, freeze L2, or alarm-only — is an undecided
  policy, as is the exit rule itself (P1 in `docs/decisions.md`). Mainnet
  readiness remains **NO-GO** on the same blockers §12 lists.
