# Fuzz Testing Report

**Last campaign: 2026-10-09 (WSL2 Ubuntu, `nightly-x86_64-unknown-linux-gnu`,
`cargo-fuzz 0.13.2`, AddressSanitizer).** An earlier revision of this file
carried a campaign table whose numbers were **not reproducible** (round-looking
figures such as `456,789`, `1,234,567`, and a `dispute_arbitrate` count byte-
identical to `wire_msg_decode`). That table has been deleted and replaced with
the measured run below. Long campaigns are not run on every commit; these are
the numbers a specific execution produced, and they are labelled as such.

## Target inventory

Eighteen targets in `fuzz/fuzz_targets/`, each asserting a property, not merely
panic-freedom.

| # | Target | Surface | Invariant asserted |
|---|---|---|---|
| 1 | `tx_decode` | Transaction deserialization | Round-trip identity; trailing bytes, truncation and absurd counts rejected |
| 2 | `block_decode` | Block deserialization | Round-trip identity; survives bitflips of a valid block |
| 3 | `wire_msg_decode` | P2P message parsing | Total decode; never panics on any type/payload |
| 4 | `mempool_admit` | Mempool admission | Byte cap holds; admission idempotent under adversarial input |
| 5 | `storage_recover` | Block-store reopen | Torn-tail recovery preserves the committed prefix; never panics |
| 6 | `checkpoint_validate` | Six-clause checkpoint validation | Every mutation produces a *named* error; a valid checkpoint ⇒ honest count, quorum and real signature |
| 7 | `meta_parse` | Metadata parsing | Unknown version / oversized size refused before allocation |
| 8 | `l2_payload_decode` | L2 payload | Unknown types rejected; never reaches `apply` without full decode |
| 9 | `m3_readers` | M3 envelope readers | Total and invertible over adversarial bytes |
| 10 | `dispute_arbitrate` | Dispute arbitration | Deterministic; evidence validation total |
| 11 | `l2_state_apply` | L2 state machine | Value conservation holds; every mutation refused cleanly |
| 12 | `vwc_decode` | VWC codec | Exact round-trip; id stability; `validate` totality |
| 13 | `worker_flows` | Worker claim/settle/dispute flows | No partial state on error; replay refused |
| 14 | `checkpoint_codec` | Checkpoint codec | Bounded; round-trip identity |
| 15 | `deliverable_codec` | L2 deliverable codec | Round-trip identity; unknown types rejected; survives truncation |
| 16 | `l2_policy_apply` | L2 policy state machine | Value conservation; grant caps never exceeded; revocation absolute; authority narrows; replay refused |
| 17 | `l2_credit_apply` | L2 credit state machine | Conservation; collateral locked not spent; debt one-way; default not early; interest once per period |
| 18 | `compute_state_decode` | Compute state decoders + revoke accumulator | Total decode; encode stability; re-filing never grows the book |

Not yet covered: the PoW boundary (template construction, header solving,
`extra_nonce` rolling) and the stratum wire protocol (`getjob`/`submit`
framing, job pinning, share accounting). Those surfaces are pinned by
integration and differential tests instead (`template → solve → submit`
roundtrip, wire `getjob`/`submit` tests, cpu-vs-portable digest equality);
fuzz targets for them are future work, not present coverage.

## Campaign results — measured 2026-10-09

One `-max_total_time=30 -rss_limit_mb=4096` run per target, ASan on, over each
target's committed corpus plus a seedless start. `rc=0` for every target.

| Target | Executions | Wall (s) | Crashes |
|---|---:|---:|---:|
| `tx_decode` | 1,157,972 | 32 | 0 |
| `block_decode` | 594,510 | 32 | 0 |
| `wire_msg_decode` | 1,158,948 | 32 | 0 |
| `mempool_admit` | 1,688 | 32 | 0 |
| `storage_recover` | 1,369 | 32 | 0 |
| `checkpoint_validate` | 16,584 | 31 | 0 |
| `meta_parse` | 194,412 | 32 | 0 |
| `l2_payload_decode` | 969,970 | 33 | 0 |
| `m3_readers` | 581,483 | 32 | 0 |
| `dispute_arbitrate` | 1,682,553 | 33 | 0 |
| `l2_state_apply` | 1,478 | 32 | 0 |
| `vwc_decode` | 1,417,179 | 32 | 0 |
| `worker_flows` | 3,299 | 32 | 0 |
| `checkpoint_codec` | 1,570,716 | 37 | 0 |
| **Total** | **9,352,161** | — | **0** |

No crash artifact was written (`fuzz/artifacts/*` empty). No sanitizer error,
leak report, timeout or OOM appeared in any log.

### Reading the low counts honestly

The per-target rates span four orders of magnitude and that reflects the work
each iteration does, not the value of the run:

- `mempool_admit` (1,688), `storage_recover` (1,369), `l2_state_apply` (1,478)
  and `worker_flows` (3,299) are **capability-bound**: each iteration builds or
  reopens real state (a store with fsync, a full chain, an L2 replay). ~50/s is
  the cost of the operation under test, and a 30-second budget simply executes
  it ~1,500 times.
- `checkpoint_validate` (16,584) does real `blst` pairings per iteration, and
  `checkpoint_codec` (1.57M) does not — 100× apart for that reason.
- The decode surfaces (`tx_decode`, `wire_msg_decode`, `dispute_arbitrate`,
  `vwc_decode`, `l2_payload_decode`, `m3_readers`) are the ones with
  high-throughput budgets, and those are the ones that get millions of
  iterations.

Longer campaigns are the right way to push the capability-bound ones; the
numbers above are labelled by wall budget precisely so nobody reads 30 seconds
as deep coverage.

## CI integration

`.github/workflows/ci.yml` → `fuzz-smoke`: nightly toolchain with
`llvm-tools-preview`, `cargo install --locked cargo-fuzz`, then each target at
`-max_total_time=20`. CI proves the harness **builds, runs and survives** a
seedless start plus the committed corpus; it does not claim the coverage above.

## Execution limitations

| Constraint | Detail |
|---|---|
| Nightly + ASan required | `cargo-fuzz` needs `nightly` and `-Zsanitizer=address`. On stable the build fails before any target compiles. |
| Windows host cannot run it | The MSVC nightly toolchain does not ship the ASan runtime. Campaigns run in WSL2 Ubuntu; that is where these numbers come from. |
| No corpus server | Corpora are git-committed seeds in `fuzz/corpus/`; no remote sync. |
| Manual cadence | This is a campaign, not a per-commit gate. CI's 20 s smoke is the per-commit gate. |

## Regression policy

Any crash found by fuzzing becomes a regression test in the workspace suite
before the fix merges. `crates/*/tests/fuzz_invariants.rs` holds the
total-over-mutation tests derived from earlier fuzz-discovered panics. **No
product bug was surfaced by the 2026-10-09 campaign** — 0 crashes across all
seventeen targets — which is a statement about this run's coverage, not a proof
that none exists.

## 2026-10-29 incident: `l2_credit_apply` false bound (target bug, not product)

The CI smoke run crashed `l2_credit_apply` with *"the outstanding debt is
implausibly large"*. Root cause was in the target, not the protocol: it
asserted `outstanding <= repay_amount * 1000`, comparing the **remaining
debt** against the **current instalment**. A large open followed by a dust
repayment legitimately leaves a large outstanding balance, so the assertion
was false by construction and seed-dependent. The library was verified
correct (repayment capped at debt, interest-first, conservation holds).

Fix: the target now asserts the documented invariant instead — the
outstanding balance never increases across a repayment. Regression test:
`a_dust_repayment_against_a_large_position_never_increases_the_debt` in
`crates/srct-l2/tests/credit_flow.rs`. No consensus, crypto or accounting
code changed.
