# Status

What is built, what is verified, and what is not finished. Read this before
relying on anything here.

## Scope

Layer 1 (base layer) implementation per SPEC.md. Includes the P2P networking layer
(`srct-net`) supporting multi-peer block relay, locator-based sync, handshake
isolation, ban scoring and side-branch pruning. Also defines the five core
protocol mechanisms — **M1 is consensus-active everywhere, and M5's binding
finality is consensus-active on activated profiles** (Decisions 11–12, §14.7–
§14.8), i.e. these are what can change whether a node accepts a block:

| # | Mechanism | Consensus-active | Module |
|---|---|---|---|
| M1 | 50/50 PSCB (Protocol Security & Compute Buffer) fee split | **Yes** — SPEC.md §8 | `fees.rs`, `chain.rs` |
| M2 | Time-Locked Compute Reserve & 50/50 Anti-Collusion Slash Vault | No — no rule creates a slash record yet | `slash.rs` |
| M3 | Universal Hardware-Agnostic Canonical Compute IR | No — envelopes only | `compute_ir.rs` |
| M4 | Memory-bound HBM scratchpad PoW puzzle | No — not a registered `puzzle_id` | `hbm_pow.rs` |
| M5 | Sovereign BLS aggregate finality gadget checkpoints | **Conditional** — real `blst` verification; **binding** on profiles with a non-zero `finality_activation_height` (`testnet` at 20, `mainnet` at 100 with its 21-key bootstrap committee per Decision 27), observation-only on `mini` | `bls_checkpoint.rs`, `bls.rs`, `finality.rs` |

SPEC.md §14 carries the same table. M5's missing rules arrived as Decisions 11
(committee + relay, §14.7) and 12 (binding activation, §14.8); M2–M4 remain
inactive because each still needs a rule this repository has not specified
(what proves a compute result fraudulent, how a task enters a block, whether
the HBM puzzle replaces or composes with the §5 puzzle), and guessing those
rules in code would have been the wrong order.

## Verified

- `cargo test --workspace` — **1,307 tests pass, 0 failures, 1 ignored** across the workspace.
  (this file quote counts as of their own dates — 242, then 263, then 293 —
  kept as history):
  - 227 unit tests in `srct-core` (M1–M5 suites, the 21-test validator-set suite, the 30-test real-BLS suite in
    `bls.rs`, the 10-case mempool attack suite, the 2 pinned L2 fee-schedule
    tests, and the rest)
  - 18 adversarial checkpoint tests against the real BLS verifier
    (`tests/bls_checkpoint_attack.rs`)
  - 10 mempool↔chain integration tests in `crates/srct-core/tests/mempool_l1.rs`
  - 11 red-team integration tests in `crates/srct-core/tests/redteam.rs`
  - 30 persistent-storage tests in `crates/srct-store` (torn tails, corruption
    refusal, reorg+restart, migration)
  - unit + integration tests in `srct-net` (framing, codecs, sync, bounds,
    tx-relay socket tests), including a real-socket end-to-end sync between
    two `P2pNode`s
  - 2 wire-vector tests in `crates/srct-net/tests/net_vectors.rs`
  - 24 tests for the machine/agent authorization layer
    (`src/agent.rs` unit suite + `tests/agent_policy.rs`): policy encoding,
    identity binding, per-transaction and cumulative limits, tumbling window
    rollover, replay-refusing nonces, revocation, rotation independence,
    bounded policy book, and offline authorization verification
- **Persistent storage is implemented** (`crates/srct-store`, appendix below):
  append-only checksummed block log, atomic metadata, crash-safe reopen;
  replaces the old whole-chain JSON rewrite.
- **P2P transaction relay is implemented** (SPEC.md §13.14): wallet → mempool →
  peer relay → remote pool → mining → confirmation was verified end to end
  with three real processes.
- **The machine/agent authorization layer is implemented** (`src/agent.rs`,
  Decision 16): deterministic network-bound agent identity, owner-signed
  bounded spending policies, fail-closed allow lists, strictly increasing
  nonce anti-replay, tumbling-window cumulative limits, rotation/revocation,
   and offline-verifiable authorizations. It is **non-consensus**: no block,
   transaction, UTXO, supply or finality rule changed, and it holds no key.
- **Streaming micro-payments are implemented** (`src/stream.rs`, roadmap
  item 30): payer-signed `PaymentStream` opens (rate per block, window, hard
  cap), payer-signed `StreamSettlement` receipts withdraw exactly what
  accrued, and a fail-closed `StreamBook` refuses over/under-claims,
  rewinds, future claims and replays. 16 attack-first tests in
  `tests/payment_stream.rs` plus 3 unit tests. Non-consensus, like the rest
  of the agent layer: settlement rides the ordinary payment path.
- **Real BLS cryptography is implemented** (`bls.rs` over `blst`): derive,
  sign, aggregate, one-pairing aggregate-verify, deterministic fixtures.
  `verify_checkpoint` with `RealBls` rejects forgeries `MockBls` accepts. This
  does NOT make finality consensus-active.
- `cargo clippy --workspace --all-targets` clean under `-D warnings`.
- `cargo fmt --check` clean across all crates.
- Two real `srct-node serve` processes on the `mini` profile completed a full
  handshake, synced, reorged onto the heavier branch and kept relaying; both
  data directories then passed `srct-node verify` (replay from genesis, UTXO +
  supply + PSCB match).
- An independent Python implementation of the PoW puzzle (`sim/srct_reference.py`),
  written from the prose of SPEC.md rather than from the Rust source, reproduces
  all 21 puzzle digests in `tests/vectors/puzzle_vectors.json`. This is the only
  real evidence that SPEC.md is unambiguous rather than merely consistent with the
  Rust code.
- All five vector files in SPEC.md §12 exist, are generated from source, and are
  read by tests. `sim/verify_vectors.py` regenerates and cross-checks them.
  Each consuming test was checked to actually fail when the value it pins is
  perturbed, so none of them pass vacuously. `net_vectors.json` (§13.12) is the
  wire-format set — frame envelope, every `msg_type`, `VERSION` for both
  profiles, locator construction. It now has the independent implementation the
  puzzle set has: `sim/net_reference.py` re-derives §13.2 framing and §13.5
  messages from the prose alone and is run by `verify_vectors.py --check`. It
  found a real bug on its first run (ADDR field order, below). Five of the 28
  pinned values are chain-derived — a mined block and locator entries from a
  200-block chain — so the script reports them as **skipped** by name rather than
  passing over them silently.
- Node CLI end to end on the `mini` profile: init, mine 31 blocks, spend, verify
  (replays from genesis and diffs UTXO + supply), status. Fee burn reconciles
  exactly — 31 blocks issue 2356 SRCT, live supply is 2355.99825 SRCT, the
  0.00175 SRCT difference being the destroyed base fee.
- External mining end to end: `Chain::build_template_with` hands an unsolved
  template to `srct-miner` (multithread nonce + `extra_nonce` grind, `--backend
  cpu|portable`), the node serves it at `GET /v1/mine/template` and accepts
  the solution at `POST /v1/mine/submit`, and pools get the same flow over
  stratum-lite JSON-lines with PPLNS accounting (fee, windowed split,
  dust carry). Pinned by the `template → solve → submit` roundtrip test, the
  wire `getjob`/`submit` tests and the cpu-vs-portable differential tests;
  measured ~114k H/s release on 4 threads (`bench_hashrate` example).
- Supply schedule matches design doc §16. There is **no stock cap** (Decision
  18): the ladder totals 39 157 124 SRCT and the tail pays a permanent 0.1 SRCT
  floor (1 sat on testnet/mini), enforced by the issuance integral and the
  rate anchor — not by an unmintable remainder. (An earlier revision of this
  line described a 304 000 SRCT mini cap with permanently unmintable remainder;
  that language predates Decision 18 and is superseded by
  `docs/monetary-policy.md`.)
- The mempool (`srct-core/src/mempool.rs`) has a 10-case attack suite. Each case
  names the rule it enforces and the attack it stops: double spending one output
  twice, spending a nonexistent output, a byte-cap flood, overshooting the gas
  cap, ordering by fee *rate* rather than fee total, selection determinism
  between two nodes holding the same pool, eviction of confirmed transactions,
  transitive eviction two generations deep, re-admission after eviction, and
  leaving unrelated siblings alone. Two of those cases failed against the code
  as first written (below), and the fee-order case did not fail until the test
  itself was rebuilt — see the note below.

**The mempool is now wired into L1 (Step 1A).** `Chain` gained three things, all
of them in `srct-core` — no networking or storage concern leaked into consensus:

- `mine_from_pool` selects from the pool at the next block's height and base fee
  and evicts exactly what the block contains. Evicting the whole *selection*
  would drop transactions the gas or byte cap left behind, and those are still
  the best candidates for the next block.
- `confirmed_above(from_height)` returns the transactions canonical blocks have
  confirmed since the caller's cursor, so a block that arrives over the wire
  evicts from the pool the same way a locally mined one does.
- `reconcile_mempool(pool, from_height)` is the whole operation: evict what the
  chain confirms, re-admit what a reorg un-confirmed, report what moved.

Ten integration tests in `crates/srct-core/tests/mempool_l1.rs` attack the seam
rather than the pool: local tx → pool → block, eviction by a peer's block,
double spend, malformed and forged transactions, a full pool, a degenerate byte
cap, fee-rate ordering reaching the block, and two reorg cases (a disconnected
transaction coming back, and one whose input the winning branch consumed being
refused instead of re-pooled).

**Restart behaviour is defined, not accidental.** The pool is in-memory only and
does not survive a restart, so a node restarts with an empty pool and reconciles
from the tip: there is nothing to recover and nothing stale to distrust. The
cursor is therefore only needed within a run. This is honest rather than
complete — a production node would persist the pool — and it is recorded here so
nobody mistakes it for an oversight. Persisting it belongs with Step 2
(`srct-store`), not before.

## Known bugs found and fixed

**`Transaction::value_out` panicked on an unrepresentable total.** It summed
output values with `.sum()`, so a transaction declaring outputs above `u64::MAX`
raised `attempt to add with overflow` in debug builds and wrapped to a small
number in release ones. `check_tx` compares `value_out` against the resolved
input total, so a wrapped sum could read as a transaction that spends less than
it creates — an inflation primitive. Confirmed by restoring the original
expression and watching the new test fail with the overflow panic. `value_out`
now saturates and a new `value_out_overflows` check runs in `check_tx` before
the comparison is trusted.

The rest of the arithmetic audit came back largely clean: `ser.rs`
bounds-checks every read, both `tx` and `block` deserializers reject
attacker-controlled counts larger than the remaining buffer before allocating,
`value_in` already used `checked_add`, `fees.rs` uses saturating operations
throughout, `apply_tx` records undo data that makes rollback an exact inverse,
and `apply_block` does verify the coinbase against `reward + tip` (chain.rs)
before the mint-bound check — so the inflation path is closed there. The one gap
it did turn up was block-level fee accumulation using `+=`, which panics in
debug and wraps in release, feeding a wrong total into the burn/tip split. Now
`checked_add`.

**The mempool's eviction cascade did not cascade.** `evict_confirmed` decided
what to drop by asking the `spends` reverse index who spends a given outpoint.
That index answers "who spends this outpoint", not "which transaction *created*
it", and its entries are keyed by the outpoint being spent — so for a dependent
transaction the index pointed straight back at the dependent itself, which is
never what the check needed to know. Nothing downstream of a confirmed
transaction was removed: not the direct child, and not a grandchild two hops from
the block. The pool kept entries that could never be mined and relayed them to
every peer forever. The rule is now stated as what it means: a transaction is
doomed if it spends an outpoint the block consumed, or an outpoint created by a
transaction the cascade has already removed — tracked in a `gone` set that grows
each pass. Confirmed by temporarily restoring the index-based predicate and
watching both cascade tests fail (`a tx spending a confirmed-away output stayed
pooled`, `the cascade stopped before the second generation: 2 entries left`);
with the fix in place both pass.

**A second reorg destroyed the first reorg's disconnected transactions.**
`disconnected_txs` was cleared at the top of `reselect` and assigned (rather than
extended) when a reorg committed. A syncing node submits blocks in a burst, so
two reorgs landing before the caller reconciled was ordinary behaviour, not an
edge case: the second reorg's assignment wiped the first's pending transactions,
and the pool re-admitted nothing. No error, no log — the transactions simply
did not come back. The set is now only ever *added* to, and only after a reorg has
committed; nothing clears it except the caller draining it. Confirmed by
re-instating the `clear()` and watching all three reorg tests fail
(`exactly the orphaned payment`, `the payment was not re-admitted`, `the
payment's input is gone…`).

**The puzzle overflow guard could not fire.** `PuzzleSpec::validate` computed
its accumulator bound as `(nn_input_dim as i64) * 128 * 128 + 62` and compared
against `i64::MAX`. The dimensions are `usize`, so a large value wraps negative
on the cast and the multiplication overflows *before* the comparison runs — the
check passed exactly the inputs it existed to reject. It also only considered
`nn_input_dim`, ignoring `nn_hidden_dim`, which is what every layer after the
first actually accumulates over. Now computed in `u128` with saturating
arithmetic, bounding the wider of the two, and moved ahead of the share audit
that consumes those dimensions.

Writing the test for that surfaced two more overflows on the same path:
`nn_macs` multiplied `usize x usize x usize`, and `nn_share_bps` then
multiplied by 10 000. Both are public methods a caller can reach before
`validate()`, so a hostile puzzle registry entry could panic a node rather than
be rejected. Both are saturating now.

**The LWMA retarget had no restoring force.** `d_raw` was computed as
`S / (T * W)`, which is `avg_solve / T`. That quantity is scale-invariant, so
*every* difficulty was a fixed point of the rule. Consequences, both reproduced
before the fix: halving the hashrate produced blocks at 2T, the rule answered
difficulty 2, and the interval ran away to 4T; doubling the hashrate produced
0.5, which clamped to `min_difficulty` and left the chain stuck at the floor.

It is now multiplicative from the previous difficulty:

```
d_new = d_prev * T / avg_solve
```

Perfect spacing (`avg_solve = T`) is a fixed point at *any* starting
difficulty, which is the property the test suite now asserts directly.

**The Zawy weights were inverted.** The oldest solve time in the window carried
weight `window²` and the newest carried weight 1, which is backwards and would
make the retarget sluggish. Now the newest carries `window²`.

Both bugs were invisible to the original tests because every one of them used
*uniform* solve times, where weighting direction cannot matter and the
scale-invariant formula coincides with the correct one at the starting value.
The tests now use mixed histories.

Three `chain.rs` tests encoded the broken behaviour and were corrected rather
than deleted: a timestamp helper was tuned so that slow blocks would raise
difficulty (correctly, they lower it), and one test used `expected + 1` as an
"impossible" difficulty — under the fixed rule that is the legitimate next
value at that spacing.

## Red-team pass: consensus and ledger defects

A later adversarial pass (`crates/srct-core/tests/redteam.rs`, written
attack-first and each confirmed to fail against the pre-fix code) found six
more defects, all in the state layer. None of them were visible to the
arithmetic audit above, and none touched hashing, the puzzle, the retarget or
the serialization layout — every vector file is byte-identical after these
fixes, which is the point.

**Fork choice was not deterministic.** The final tie-break in `best_candidate`
was an arrival counter, so two nodes holding the same set of valid blocks could
and did select different tips — the test builds two rival blocks at equal height
and equal work and shows node A choosing one and node B the other, purely from
delivery order. The module doc claimed "two nodes holding the same set of valid
blocks always agree on the tip"; that was false. The tie-break is now the block
hash, so every comparison is a function of the block graph alone. `first_seen`
and `seen_counter` are gone.

**The finality rule only guarded against reorgs that shortened the chain.**
`adopt` refused when `common <= finalized && self.canon.len() > new_canon.len()`.
The length qualification meant a rival forking *below* the finality point but
ending up *longer* sailed through and rewrote settled history. The existing test
only exercised the shrinking case, which is why it stayed green. The condition
is now on the fork point alone.

**`apply_tx` was not atomic.** Inputs were removed from the UTXO map one at a
time, so a transaction whose *second* input did not exist had already taken the
first one when the `Err` fired — and the `Err` discarded the undo record that
could have restored it. One malformed transaction destroyed coins. All inputs
are now resolved against a read-only view before anything is written.

**A block that could never be applied was still counted as fork-choice work.**
`submit_at` inserted into the block store before applying and never removed on
failure, while `cumulative_work` summed the declared difficulty of everything
stored. An attacker could therefore accumulate chain weight that no
reorganization could realize: fork choice kept selecting the dead branch and
every honest block was rejected until honest work caught up, with the store
growing without bound. A state-invalid block is now dropped on submit. The one
exception is `ReorgWouldCrossFinality`, where the block is valid and dropping it
would orphan its descendants — the first attempt at this fix broke exactly that
case and the existing test caught it.

**`apply_block` could leave the ledger modified by a rejected block.** It wrote
to the UTXO set transaction by transaction, so a failure partway through left
earlier transactions applied. The reorganization path happened to be shielded by
its snapshot, which is why a first attempt to exploit it appeared to fail; the
direct-extension path was not, and would have been if fork choice had ever
routed a tip-extending block there. Writes are now recorded and unwound on any
failure, so no snapshot is needed and the happy path stays O(1) in UTXO size.

**The chain halted permanently once the reward ladder ran out.** `apply_block`
rejected a zero-value coinbase unconditionally, but SPEC.md §7 says the coinbase
collects the tips only and tips are legitimately zero on an empty block. Every
such block was refused, so the chain would have stopped dead at the mainnet
ladder-exhaustion height 1,839,600. (Decision 18’s tail keeps paying past that
height, so a zero-reward block is no longer reachable on mainnet.) The zero-value check is gone; a zero-value coinbase is
simply not recorded in the UTXO set, since `check_tx` already refuses to spend a
zero-value output and recording it would only grow the set with unspendable
entries. `rollback_block` now identifies the coinbase output directly instead of
inferring it from its position at the end of the undo list, which stopped being
reliable once that position became conditional.

Smaller items from the same pass:

- `header.sig_scheme` was committed to by the block hash and read by nothing.
  SPEC.md §1 requires nodes to reject unknown values; a block declaring scheme
  200 was accepted.
- The `tx` and `block` deserializers bounded declared counts by the raw
  remaining byte count rather than the smallest entry that could follow, so a
  4 MB block could declare ~4 000 000 inputs and force a `Vec<Input>` reservation
  many times the size of the bytes describing it.
- `Block::total_gas_used` used `.sum()`, which panics on overflow in debug and
  wraps in release, and feeds both the base-fee schedule and the gas cap. Now
  checked; the one caller on a display path falls back rather than panicking.
- `Wallet::build_tx` accepted a `fee` argument and then discarded it
  (`let _ = fee;`). It now enforces that `sum(outputs) + fee` is representable,
  and the doc says plainly that change is the caller's job because resolving
  input values needs the UTXO set.
- `halvings()` and `expected_epoch()` truncated a `u64` quotient with `as u32`.
  Clamped instead. `apply_block` also now refuses heights past `u32::MAX`, where
  the coinbase's `u32` height index stops being injective.

**A branch that forked below the finality point no longer wedges the node.**
Earlier sessions recorded this as an open design question rather than a bug: a
valid branch heavier than the tip but forking below `finality_depth` was
retained, its work was counted, fork choice kept selecting it, and the node
refused honest blocks until honest work caught up. A peer could therefore stall a
node's progress at no cost to itself.

SPEC.md §13.10 item 2 settles it, and side-branch pruning is now implemented:
every non-canonical block at or below `tip − finality_depth` is dropped, along
with any stored descendant of a dropped block. Forgetting such a branch is what
lets the node accept honest blocks again. **§9.3 is unchanged** — a reorg whose
fork point is at or below the finality height is still refused with
`ReorgWouldCrossFinality`; `reorg_cannot_rewrite_finalized_history` and
`a_longer_branch_cannot_rewrite_finalized_history` both still pass. What changed
is only how long the node remembers a branch it was never going to follow.

Canonical history is still retained in full, because undo records,
`verify_canonical_chain` and the persistence layer all replay from genesis.

## A claim that did not survive measurement

An earlier design document reported a 40% attacker with a two-hour
future-timestamp allowance reaching ~104s average block time, and presented
that as the reason for tightening the limit to one block time. That document is
no longer in this repository; the claim is recorded here because it shaped a
consensus rule and because it does not hold.

The figure is **not reproducible** and cannot be: 104s is below the solve-time
clamp floor (T/4 = 150s), so no retarget can ask for a difficulty that low. The
simulation's `--ablation` mode strips the clamp and the difficulty floor and
still does not land on 104s — it drives difficulty to zero — so the original
table came from some further difference in its model that is not recoverable.

What *is* established: under this specification, block time stays within ~1% of
target across every allowance from one minute to two hours. The short allowance
is retained anyway as defence in depth, since it bounds how far ahead a single
block can be stamped, which matters once an attacker reaches 50% and can move
the median itself. SPEC.md §6.1 states this accurately rather than repeating the
original number.

The ablation table has a caveat worth knowing when reading it: any variant that
never recovers ends up pinned on the difficulty floor, so rows matching the
full-spec row may be there for that trivial reason. Raise `--start-difficulty`
to separate them.

## P2P defects found and fixed

Every other `srct-net` test drove `SyncManager` directly, so the event loop, the
peer threads and the sync continuation were untested. Driving them from a real
socket found all of the following.

- **Sync stopped after one batch.** §13.7 requires the requester to `GETDATA`
  "in batches of 16, submit each, **and repeats**". `handle_inv` returned the
  first 16 entries of an `INV` and discarded the rest — and worse, marked them
  all as requested, so they were poisoned as well as lost. A node more than 16
  blocks behind could never finish syncing. Now every advertised hash is queued
  (bounded), and each applied block frees a slot for the next batch.
- **A peer could stall sync by disconnecting.** Requested hashes were tracked in
  a set with no owner and no release path, so a peer that hung up mid-sync left
  its hashes marked as requested forever. Requests are now tracked per peer and
  released on disconnect.
- **The `requested` set grew without bound.** §13.11 invariant 6 says no
  structure may grow past its §13.8 bound; a peer advertising hashes it never
  delivered grew this set forever. It is now capped, and a bounded pending queue
  holds what is advertised-but-not-yet-requested.
- **`max_peers` was never enforced.** §13.8 bounds it as the cap on thread and
  descriptor count, and only `max_inbound` was checked, on the accept path only.
  Outbound dials are now refused at the limit, and the total is checked on accept
  too.
- **Every inbound connection failed on Windows.** An accepted socket inherits
  the listener's non-blocking flag on Windows, so the blocking, timeout-based
  handshake returned `WouldBlock` immediately and the peer was dropped. The flag
  is now cleared explicitly on accept. This is why the end-to-end test is worth
  having: every prior test used a plain blocking listener and passed.
- **`stop()` did not disconnect.** It set a flag; the reader thread stayed parked
  in `read_frame` for up to 60 s, still holding a thread and still able to emit
  events for a peer the node believed it had dropped — including a peer banned for
  a framing violation. The socket is now shut down, and an oversized frame or
  post-handshake bad magic scores the immediate `+100` that §13.9 already promised.
- **The handshake nonce was the wall clock.** Deriving it from
  `SystemTime::now()` made the "proof of socket possession" challenge guessable
  from block timestamps. It now mixes a `RandomState` key (OS-seeded) with a
  counter.
- **Exceeding an inbound bound disconnected instead of banning**, contrary to
  §13.8. There is now a bounded, address-keyed score table with the §13.9
  one-per-hour decay.
- **The locator could exceed `max_locator_len`.** Genesis was appended on top of
  an already-full locator, making 501 entries. The slot is now reserved.
- **`srct-node serve` lost everything it synced.** It persisted only on its own
  mining path, so blocks that arrived from peers were never written and a restart
  replayed genesis and discarded the entire sync. It also looped with no delay,
  pegging a core on mining and O(n) JSON writes. Both fixed; `--interval`
  controls the loop period.
- **`verify` could not see M1 bugs.** `verify_canonical_chain` compared the UTXO
  set only, so a wrong PSCB unwind was invisible to the node's own checker. It now
  re-derives the reserve and its undo records by replay.

## Not done

> **Dated section — read the appended phase sections below for current status.**
> This list was written before Step 2 (transaction relay) and before Phases
> 2–5 shipped; items below that are now delivered (L2/VWC, coverage-guided
> fuzzing, transaction relay) have their own SHIPPED sections at the end of
> this file. It is left as written because this document is a chronological
> record, not a live summary.

- **Layer 2 / Verified Work Certificates.** The core of the project's premise.
- **P2P gaps.** Block relay works (verified end to end over real sockets, and
  between two `serve` processes). A bounded, attack-tested mempool now exists,
  but nothing feeds it and nothing reads it: pulling it when building a block and
  relaying transactions over the wire (§13.13) are both still missing, as are
  peer discovery (§13.6 by design — address book only), headers-first sync and
  compact blocks. Real `blst` BLS verification (M5).
- **Persisted UTXO indexing.** State is replayed from genesis on load, which is
  fine at test scale and will not be at 40M coins. `serve` also rewrites
  `blocks.json` in full whenever the chain changes (SPEC.md §13.10 item 4).
- **M2–M5 are not wired into consensus.** See the table above and SPEC.md §14.
- **No fuzzing with a coverage-guided harness** (`cargo-fuzz`/`arbitrary`),
  which is what would really exercise the parsers. In its place are
  deterministic property tests: arbitrary bytes through every deserializer,
  every truncation of a valid block, count fields claiming more entries than
  the buffer holds, wire round-trip stability, output-encoding injectivity, and
  `undo_tx` proven an exact inverse over a 64-step spend sequence. Each was
  checked to fail when the property it names is broken. The red-team suite in
  `crates/srct-core/tests/redteam.rs` is the same idea applied to consensus and
  ledger invariants rather than parsers.
- Vector coverage is finite by construction. The crosscheck exercises seven
  header/epoch combinations; it does not cover every field permutation, and a
  Rust-only bug outside those cases would not be caught by it.
- **No release or tagging process**, and no coverage report in CI.

## Known rough edges

- `--amount` on `send` is denominated in satoshis while every other printed
  figure is in SRCT. This bit me during verification and is documented in the
  command's error message, but it should probably gain a unit suffix.
  (**Fixed in Phase 7:** a fractional `--amount` - the form the README
  documents - was refused outright, because the fraction was padded with
  spaces instead of zeros. `parse_srct_sat` now zero-pads, and
  `cargo test -p srct-node --bin srct-node` pins it.)

## Reproducing the difficulty work

```
cargo test --workspace                                 # 139 tests
cargo test -p srct-core --test redteam                   # red-team regression suite
cargo clippy --workspace --all-targets -- -D warnings # clean
cargo fmt --all --check                               # clean
python sim/difficulty_attack_sim.py                     # attack containment
python sim/difficulty_attack_sim.py --ablation \
    --start-difficulty 100000                           # which rule is load-bearing
python sim/supply_schedule_sim.py                       # supply vectors
python sim/puzzle_crosscheck.py                         # Rust vs independent Python
python sim/verify_vectors.py --check                    # all four vector files

# Regenerate vectors (puzzle/difficulty/ser digests must come from Rust;
# supply is arithmetic and is done in Python):
python sim/verify_vectors.py
UPDATE_PUZZLE_VECTORS=1 cargo test -p srct-core --lib puzzle_vectors_are_stable
UPDATE_DIFFICULTY_VECTORS=1 cargo test -p srct-core --lib difficulty_vectors_are_stable
UPDATE_SER_VECTORS=1 cargo test -p srct-core --lib serialization_vectors_are_stable
```

A second implementation that disagrees with these vectors has a consensus split,
not a rounding difference.

## Resolved design decisions

These four were open questions blocking L2. They are now decided, so they are
recorded here rather than left as a list of things nobody has answered.

**D1 / D4 — Who are the validators?** The M5 BLS validator set **is** the L2
dispute-arbitrator set. One set, one epoch, one governance system; designing a
second would have been the more expensive mistake. Validator entry is
permissionless by staking a minimum SRCT amount, and the active set is the top 21
stakers per epoch. Genesis is bootstrapped by founder nodes, since there is no
stake to rank before any exists.

**D2 — How does M3 re-execution work during a dispute?** A CPU-only reference
execution path for the ComputeIR. It must be bit-identical to the GPU path for
the same input, which is tractable precisely because M3 already forbids floating
point: the IR is integer-only, so "GPU" and "CPU" are two readers of the same
bytes. Validators run the CPU path during arbitration and therefore need no GPU.

**D3 — Gas schedule for L2 transactions.** Flat per type, not per-byte, so a
worker's cost is knowable in advance:

| Transaction | Fee (sat) |
|---|---:|
| `TxPostTask` | 5 000 |
| `TxClaimTask` | 2 000 |
| `TxSubmitResult` | 2 000 |
| `TxDispute` | 10 000 |
| `TxSettle` | 20 000 |

Recorded in `params.rs` as `FEE_TX_POST_TASK_SAT`, `FEE_TX_CLAIM_TASK_SAT`,
`FEE_TX_SUBMIT_RESULT_SAT`, `FEE_TX_DISPUTE_SAT` and `FEE_TX_SETTLE_SAT`, with
`L2_FEE_SCHEDULE` holding the exact set so a test can pin it.

**Open interaction, deliberately left visible.** Nothing consumes these yet — the
L2 transaction types do not exist — and they do not clear the fee floor the node
actually enforces. The only fee rule today is `base_fee * gas_used`, and even the
smallest transaction burns `GAS_TX_BASE` (16 000) gas, so the cheapest possible
floor for a *single* L2 transaction is orders of magnitude above a 20 000 sat
settle fee. Wiring these in as-is would have `check_tx` reject every one of them
as underpaid. L2 therefore needs either its own fee path or an explicit exemption
from the gas floor; the test `l2_flat_fees_sit_below_the_gas_floor` fails the day
that is settled, so the question cannot be forgotten.

## The L2 fee path — analysis, not yet a decision

D3's flat fees are orders of magnitude below the floor the node enforces today
(`base_fee * gas_used`, and even the smallest transaction burns `GAS_TX_BASE` =
16 000 gas). Wiring them in as-is would have `check_tx` reject every L2
transaction as underpaid. The inspector's finding is confirmed against the code,
and the options are these:

1. **Raise the flat fees above the floor.** Simplest and wrong: it makes an L2
   task post cost more than a SRCT transfer, which contradicts the reason D3 chose
   flat fees at all.
2. **Exempt the five L2 types from the gas floor.** Rejected as stated: an
   exemption is a second fee rule, and one written as an exception is the easiest
   kind to widen later by accident.
3. **Give the L2 types their own fee schedule, and split the flat fee the same
   way the base fee is split.** `split_fees` currently derives `full_base` from
   `base_fee * total_gas`; for an L2 transaction `full_base` would be the flat fee
   itself, so the M1 50/50 burn/PSCB invariant holds unchanged and no rule is
   weakened — the transaction simply has a different price. **This is the
   recommended option**: it reuses the existing split rather than bypassing it,
   keeps one invariant for both fee kinds, and leaves the L1 floor untouched.
4. **A separate L2 fee market with its own base fee.** Rejected for now:
   two congestion controllers is a large amount of new mechanism for five
   transaction types, and it can be introduced later without breaking option 3.

**Not decided, and deliberately not implemented.** This needs writing into
SPEC.md before any L2 transaction type is coded, and it needs the user's sign-off
because it changes what a SRCT price *means* for L2 work. The test
`l2_flat_fees_sit_below_the_gas_floor` fails the moment the gap closes, so the
question cannot be silently settled by a later commit.

## Build order

1. Mempool (`srct-core/src/mempool.rs`) — **done**, and wired into L1 (Step 1A)
2. Transaction relay over P2P (`srct-net`) — **done**
3. Persistent storage (`srct-store/`)
4. Real BLS pairing — replace `MockBls` with `blst`
5. `cargo-fuzz` harness
6. L2 (`srct-l2/`) — only after 1–4

Each step uses the red-team discipline from session 1: write the attack, confirm
it fails against the current code, then fix the cause.

---

## Step 2 — transaction relay: implemented

Turns the mempool from a module nothing feeds into one that is fed by the network.
**No consensus rule changed.** A transaction arriving over the wire is admitted by
the same `check_tx` against the same state as one built locally, and nothing in
relay can reach `Chain::submit`: a relayed transaction becomes consensus-relevant
only inside a block, which is validated exactly as before.

SPEC.md §13.14 is new and normative; §13.5 gained `msg_type = 10` (`TX`, additive
under the existing freeze rule) and `kind = 0` in `INV`/`GETDATA` stopped being
reserved and started being used. §13.8 gained `tx_request_timeout`.

| Piece | Where |
|---|---|
| `MessageType::Tx = 10`, `INV_TYPE_TX = 0`, bounded `Message::Tx` | `srct-net/src/msg.rs` |
| Relay bookkeeping: requests, pending, known set, rate window, expiry | `srct-net/src/relay.rs` |
| Announce / request / serve / admit / ban, peer registration | `srct-net/src/net.rs`, `peer.rs` |
| Mine from the pool, unconditional reconcile, relay counters | `srct-node/src/main.rs` |
| Wallet → node: `send --relay <addr>` | `srct-node/src/main.rs` |
| Follower node: `serve --no-mine` | `srct-node/src/main.rs` |

### Bugs found and fixed

Two real defects, each proven by re-running the test against the old code.

1. **A banned peer was never released from the live set.** `stop()` shuts the
   socket down, but the reader thread parked in a blocking read does not reliably
   wake for that — on Windows it demonstrably did not: a peer banned for ten
   invalid transactions stayed in the peer table for over a second of polling and
   its reader only returned at teardown. Until then the node believed it had a
   peer it had already banned: the slot counted against `max_peers`, broadcasts
   still queued for it, and nothing released the sync or relay state it owed.
   Fixed by releasing stopped peers in `poll_events` rather than waiting for the
   reader. **Red step:** with the sweep neutralised, only
   `repeated_invalid_transactions_get_the_peer_banned` fails.
2. **The submission path silently lost a transaction.** The first fix swept for
   stopped peers using the `stopped` flag — but the reader thread set that same
   flag whenever a stream ended, so a peer closing cleanly looked identical to a
   peer being banned and the sweep discarded its last messages. A wallet that
   connects, submits one transaction and hangs up (which is what
   `send --relay` does) had its transaction read, decoded, queued and then
   dropped, with `accepted 0 refused 0` — nothing observable anywhere. Fixed by
   giving the reader its own flag and making the release rule "stopped **and** the
   reader has not reported yet". **Red step:** with the guard removed,
   `a_one_shot_submitter_is_served_and_then_let_go` fails with that exact symptom.

A third defect was closed by design rather than by a failing test: the in-flight
request set was global and unbounded in time, so a peer could announce
`max_relay_in_flight` transactions, deliver none, and stop the node requesting
from *every* peer for as long as it stayed connected. Requests now expire after
`tx_request_timeout`, and a request that expires is retried against whoever
announces the txid next.

### Tests

- `crates/srct-net/tests/tx_relay.rs` — 10 real-socket tests against a hand-rolled
  peer, not our own client: the whole path (pool → `INV` → `GETDATA` → `TX` →
  peer pool → mined → block back → eviction on both nodes); announce/request/serve
  round trip; forbidden signature; repeated invalid transactions reaching the ban
  threshold; duplicate announcement pooled once and not punished; conflicting
  spend refused without a ban; oversized transaction refused by the pool;
  repeated announcement drawing one request; unanswered request expiring;
  one-shot submitter served and released.
- `crates/srct-net/src/relay.rs` — 11 unit tests for the bookkeeping, including the
  stall scenario and both response budgets.
- `tests/vectors/net_vectors.json` regenerated with `TX` and `kind = 0` bytes, plus
  the five new §13.14 bounds; `sim/net_reference.py` re-derives all of them from
  the §13 prose and now agrees on 32 values. **It caught an arithmetic error in
  the vector generator** (`inv_tx_len` typed as `4 + 1 + 32` when `INV`'s count is
  `u16`) — the kind of mistake a self-consistent encoder cannot find.

### Verified end-to-end with two real processes

`serve --listen` on node A (mining), `serve --connect ... --no-mine` on node B,
then `send --relay` from a third process:

```
relay          accepted 1 refused 0 (pool holds 1)
B chain: block 75 holds 2 txs, outputs [1000000000, 6599824000]
B balance: 8d0e399eaf9cb1f3:0  10.00000000 SRCT  height 75  spendable
```

The wallet's signed transaction crossed a real handshake and a real TCP link into
A's pool, was mined at height 75, reached B by block relay, and B reports the
output as spendable. Exactly one block on B's chain contains it.

### Limitations

- **No acknowledgement.** A `TX` is silent: the sender learns that a node *took*
  the frame, not that the pool accepted it. `send --relay` says so instead of
  implying success, and the receiving node's `relay accepted/refused` line is the
  actual evidence.
- The pool is still in-memory only, so a node that restarts drops everything it
  held and never re-requests it. That is step 3's problem, and it is why the
  ordering is storage before relay hardening rather than the reverse.
- Relay is not part of the §13.11 invariant list yet; the next revision should add
  "a relayed transaction is validated exactly as a local one" explicitly.
- `INV` announcements are sent only for the first `max_inv_per_msg` pool entries
  on connect, so a pool larger than 500 entries is not fully announced to a new
  peer. Bounded and honest, but incomplete.

## Step 3 — Persistent storage (crates/srct-store): DONE

The node no longer rewrites the whole chain as JSON. `crates/srct-store` is an
append-only, checksummed block log plus atomic metadata, and `srct-node` uses it
for every command.

### Design (no consensus rules live here)

- One log file (`store/blocks.log`): magic `SRCTS`, version 1, then records of
  `len(4 LE) ‖ digest(4, first bytes of SHA256(payload)) ‖ payload`. Every
  record is tagged (`0x00` block, `0x01` UTXO snapshot) — the tag byte exists
  because a block's first serialized byte is its version (1), which is
  byte-identical to a naive "no tag needed for blocks" scheme.
- No index file: the hash index is rebuilt by scanning at open, so the only
  copy of the data is the data. A corrupted index is a failure mode that does
  not exist.
- Canonical chain = one metadata row (network, genesis, tip, height), replaced
  atomically (write-beside, rename). A reorg moves that row and nothing else.
- Torn tail (crash mid-append) is dropped and REPORTED. Damage with committed
  data after it refuses to open with the byte offset. The distinction matters:
  one is survivable by construction, the other must never be silently
  truncated into a shorter chain.

### Bugs found during this step (all caught by the crate's own tests)

1. Untagged block records collided with UTXO-snapshot records (block version
   byte == snapshot tag) — blocks vanished from the index. Fixed with an
   explicit tag on every record.
2. `set_tip` recorded genesis's height (0) instead of the tip's, because the
   ancestry walk is tip-first and the code read the last entry.
3. The metadata parser read the checksum line after the hex-digest line, but
   the file's trailing newline made it read an empty string.
4. The height walk omitted genesis at height 0, so every reopen reported
   `MissingParent` on the genesis block itself.
5. A file shorter than one header underflowed `file_len - pos` in the log scan
   (check_header may extend the file; the scan's length was stale).

### Verified

- 30 store tests: round-trip, duplicate, side branch, reorg + restart, orphan
  survival, unprovable tip refused with metadata untouched, foreign network
  refused, metadata lost -> honest genesis fallback, torn tail, damaged
  mid-chain record refused, UTXO snapshot tagging.
- End to end with the real binary: init -> mine -> restart -> verify; a legacy
  `blocks.json` chain migrated into the store on first open and verified after;
  two-node serve where B force-killed (`taskkill /F`, no flush) at height 35
  restarted twice, mined to 58, and replays cleanly every time.
- `verify` re-validates every stored block through `Chain::submit`, so a store
  bug cannot hand the chain a bad block silently.
- 293 workspace tests (up from 263), fmt/clippy (`-D warnings`)/release clean,
  all five sims green.

### Limitations

- UTXO persistence is sketched (tagged snapshot records) but the node does not
  yet write snapshots; `load_chain` still replays from genesis. Correct, but
  O(chain) at startup — the snapshot path lands with the next step.
- Mempool is still memory-only across restarts (unchanged from step 2).

## Step 4 — Real BLS verification (blst): crypto core DONE, gadget NOT active

SPEC.md gained §14.5, normative for real-BLS builds: min-pk BLS12-381 (keys
G1/48B, signatures G2/96B), DST `SRCT_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`,
IETF KeyGen derivation for deterministic fixtures, validator-set identity
`sha256_dom([0xB2], [n ‖ sorted keys])`, bitmap padding bits declared
malformed, replay ruled out by construction, and set rotation explicitly
deferred to §14.6 (unresolved: D1 economics).

`crates/srct-core/src/bls.rs` adds `SecretKey::derive`, `sign`, `RealBls`
(single verify, aggregate, fast-aggregate verify), `validator_set_hash`, and
point validation that rejects infinity/non-subgroup/garbage keys and
signatures without panicking. `bls_checkpoint::verify_checkpoint` now runs
real pairing checks when handed `RealBls`; `MockBls` remains only for
structural unit tests, and a test pins that a forgery MockBls accepts RealBls
rejects.

**No consensus change.** `Chain::submit` does not consult any `BlsVerifier`;
M5 remains inactive; §14.6 (who validators are, rotation, checkpoint entry
into blocks) is the documented blocker. Nothing here was activated silently.

Bugs found: `validator_set_hash` initially hashed caller order rather than
`ValidatorSet` sorted order — two views of the same committee would compute
two identities (caught by the order-insensitivity test). The committed key
fixture caught that I cannot predict derived keys by hand; the real
SEED_A value is now the test's constant. 18 adversarial checkpoint tests
(quorum boundary, bitmap padding/junk/lying count, wrong-set, tampered
payload/hash/network, zero sig, poisoned key set, replay, finality
monotonicity) all pass against RealBls.

341 workspace tests (was 293). fmt/clippy -D warnings/release clean; five
sims green.

## Step 5 — Validator-set machinery (§14.6): library DONE, activation deferred

SPEC.md §14.6 is written as **DESIGN ONLY**: the complete deterministic
machinery (identity, epoch-bound set hash, seed-block derivation, rotation,
six-clause checkpoint validation) is specified and implemented as a pure
library in `validators.rs` — with five economics questions explicitly listed
as open and reserved for the protocol owner (selection rule beyond the TopN
default, rewards, slashing amounts, activation timing). No minimum stake is
required — any positive bond is accepted.

`Chain::submit` does not reference `validators.rs` (grep-verified); no
consensus rule changed; no monetary rule changed.

> **Update 2026-10-28 (activation shipped):** the library above is now wired
> in. Decision 20 put the bond ledger, TopN selection, unbonding and
> full-bond slash on chain; follow-up fixes added seed-height committee
> snapshots with reorg rollback (`committee_rotation` suite), per-epoch slash
> verification that fails closed (`bond::` P0-2 tests), one-epoch-grace set
> expiry, and finality observation rewind on rollback. The "activation
> deferred" framing above is therefore historical — committees, rotation and
> slashing are live consensus.

Attack tests (21): deterministic derivation + key-first canonical ordering
(stake changes cannot reshuffle bitmap bits mid-epoch); TopN selection with
deterministic tie-breaks; duplicate key refused (a two-slot key could double
quorum weight); duplicate address refused; invalid key refused-not-skipped;
set hash binds the epoch (identical membership in two epochs → different
hashes) and the addr↔pk binding (moving a key to a new address changes the
identity); every one of the six checkpoint clauses named on failure; rotation
verifies each epoch's checkpoints against that epoch's own derivation; cache
grace-period behavior; equivocation evidence exposed as data (punishment is
an open economics item).

347 workspace tests (was 341). fmt/clippy -D warnings/release clean; five
sims green.

## Phase 4 — Fuzzing: harness shipped, campaign executed, invariants enforced

`fuzz/` is a standalone cargo-fuzz crate (kept out of the workspace) with eleven
targets over the highest-risk boundaries. Seven are Phase-1/L1: `tx_decode`,
`block_decode`, `wire_msg_decode`, `mempool_admit`, `storage_recover`,
`checkpoint_validate`, `meta_parse`. Four are Phase-2/3 L2 (added with the
dispute engine, SPEC.md §15–§16): `l2_payload_decode`, `m3_readers`,
`dispute_arbitrate`, `l2_state_apply`. Each asserts round-trip and capability invariants — decode →
encode → decode identity, mempool byte cap under hostile admission, store
reopen after an adversarial tail, accepted checkpoint ⇒ honest count + quorum
+ real signature — not merely panic-freedom.

Execution environment note: Windows' nightly MSVC toolchain does not ship the
ASan runtime (`clang_rt.asan_dynamic-x86_64.dll`), so the campaign ran in WSL
Ubuntu (nightly + cargo-fuzz + ASan). One-time env setup for that campaign
lived in the project's working notes (`memory.md`, since removed from the
repo). Results, one 60-second ASan campaign per target, all exit 0, no
crashes, no leaks, no OOMs:

| target              | execs     |
|---------------------|-----------|
| tx_decode           | 4,829,687 |
| wire_msg_decode     | 2,960,697 |
| mempool_admit       | 2,460,827 |
| block_decode        | 2,291,347 |
| meta_parse          |   539,534 |
| storage_recover     |   248,534 |
| checkpoint_validate |    72,997 |
| **total**           | **13.4M** |

(checkpoint_validate is BLS-bound: every iteration does real blst pairings;
storage_recover is fsync-bound. Both are capability-bound, which is the point.)

### Phase-3 L2 fuzz campaign (2026-10-06, WSL nightly + ASan)

The four L2 targets were run for 40 s each. **One crash was found, and it was a
false alarm in the harness, not the product** (`dispute_arbitrate` asserted that
an `Ok` arbitration can never be `Inconclusive`; the design is precisely that it
*can*, and that this is the safe outcome — SPEC.md §15.6). The harness assertion
was corrected to assert the real contract (inconclusive ⇒ no wire verdict ⇒ no
settle payload ⇒ nothing slashed), after which the target fuzzed clean. No
product-code change resulted. The deterministic counterpart is
`crates/srct-l2/tests/fuzz_invariants.rs` (7 tests, run on every `cargo test`).

| target            | execs     | result |
|-------------------|-----------|--------|
| l2_payload_decode | 2,975,308 | clean  |
| dispute_arbitrate | 2,784,817 | clean (after harness fix) |
| m3_readers        | 1,387,682 | clean  |
| l2_state_apply    |    11,880 | clean (crypto-bound: every iteration signs real transactions) |
| **total (new)**   | **7.2M**  | 0 crashes |

The deterministic counterparts run on every `cargo test`: three
`fuzz_invariants.rs` suites (srct-core, srct-net, srct-store) feed hand-built
adversarial inputs — every truncation and bitflip of a valid tx/block, hostile
length fields, binary garbage metadata, forged/replayed/lying-count
checkpoints — through the same invariants. They found two real bugs before the
fuzzer ran, both fixed with regression tests:

1. **srct-net `Message::Unknown` grew 5 bytes per decode→encode cycle.** Decode
   stores the payload verbatim (§13.5 freeze rule); encode re-framed it as
   `ty + len + raw`. Encode is now the exact inverse of decode. Wire
   correctness only — unknowns are never relayed — but the asymmetry would
   have bitten the first non-Rust peer implementation.
2. **srct-store `MetaFile::load` leaked a raw `InvalidData` IO error on
   non-UTF-8 meta.json** (a crash or disk-damage outcome, exactly what
   `BadMeta` exists to name). Now reads bytes and maps the utf-8 failure to
   `BadMeta`.

CI gained a `fuzz-smoke` job: nightly + cargo-fuzz, 20 s per target per push,
so the harness is executed — not just compiled — on every change. It now loops
all eleven targets. Longer campaigns run locally; any minimized crash lands in
the invariant suites as a regression test.

360 workspace tests (was 347). fmt/clippy -D warnings/release clean; five sims
green. No consensus rule touched: `Chain::submit` still never references
validators.rs, supply/mining/rewards unchanged.

## Phase 2 — L2 task contracts: SHIPPED (`crates/srct-l2`) — 2026-10-06

The first L2 slice is built. SPEC.md §15 is its normative text. **No L1
consensus rule changed**: an L2 transaction is a payload type that is not yet
carried in a block, so nothing in this change is reachable from `Chain::submit`,
and the L1 vectors are byte-identical.

**What exists**

- `srct_core::l2` — the five payload types (`PostTask`, `ClaimTask`,
  `SubmitResult`, `Dispute`, `Settle`) with wire codes `0x10`–`0x14`, canonical
  encode/decode (exact inverses, bounded length prefixes), domain-separated
  signing hashes, hybrid actor authorization, and `L2TxType::fee_sat()` returning
  the D3 schedule. `derive_task_id` binds submitter + nonce + task hash.
- `srct_core::fees::split_flat_fee` — the D3 fee path: the whole flat fee is
  `full_base`, split 50/50 burn/PSCB with `tip = 0`, odd satoshi to `burned` to
  match `split_fees`. The L1 gas floor is untouched.
- `srct_core::compute_ir` — `ComputeTask::from_reader` and
  `ComputeAttestation::from_reader`, so the M3 envelope round-trips inside an L2
  payload (the attestation signature length is bounded before allocation).
- `crates/srct-l2` — `TaskContract` + `ContractState`
  (`Open → InProgress → ResultSubmitted → Disputed → Settled/Expired`) with
  authorization, state-validation and replay rules, and `L2State`: accounts,
  per-contract escrow, the M2 `SlashVault`, D3 fee collection, replay refusal by
  transaction id, deterministic `advance_block` (sorted, no clock), and the
  conservation invariant.

**Reused, not reimplemented:** `ComputeTask`/`ComputeAttestation` (M3),
`SlashVault` (M2), `ValidatorSet`/`BlsVerifier`/`BlsSignature` (M5),
`fees`/`params` (M1 + D3), and the hybrid wallet signing path.

**Verification.** 410 workspace tests (was 360): +15 `srct_core::l2` unit tests,
+2 M3 decoder tests, +2 flat-split tests, +18 `srct-l2` state-machine tests, +17
`srct-l2` integration tests (real wallet signatures, the quorum gate, a
rejecting-verifier seam test, and a two-node determinism check that also asserts
conservation). fmt clean, clippy `-D warnings` clean, release build clean, all
five sims green, L1 vectors unchanged.

**A real bug the tests caught before it shipped:** `apply_settlement` credited
the worker and challenger but never the *submitter*, so a `Fraudulent` or
`Expired` verdict silently failed to refund the escrow — and the conservation
check reported exactly the missing 1 000 000 sats. Both the integration tests
and the two-node determinism test failed on it; fixed and re-verified.

**Two open items recorded, not silently decided** (see `docs/decisions.md`): a
task whose escrow/deposit is smaller than the 20 000 sat settle fee cannot be
settled (`AmountTooSmallForFee` fails closed), and `vwc_hash` is a pre-VWC
convention (`result_hash` / counter-result / all-zero) that Phase 4 replaces.

**Still gated:** BLS/M5 finality activation remains off until the end of
Phase 6. `Settle` verifies a quorum aggregate through the existing trait, but no
checkpoint finalizes an L1 block.

## Phase 3 — Dispute engine + M2/M1 integration: SHIPPED — 2026-10-06

The dispute lifecycle is built end to end and wired into the existing L2 state
machine, the M2 slash vault and the M1 PSCB reserve. SPEC.md §15.6–§15.8 are its
normative rules; **SPEC.md §16 is the M3 CPU-reference note** written first, as
the roadmap requires. **No L1 consensus rule changed** and no Phase-1/Phase-2
economic decision changed — the D3 schedule, the 50/50 split, the L1 gas floor
and validator economics are untouched.

**What exists**

- `SPEC.md §16` — the M3 CPU-reference execution note: `reference_eval(ir, input)
  -> output`, `result_hash = SHA-256(output)`, determinism, canonical
  little-endian output, wrapping integer arithmetic, fixed reduction order, and
  boundedness; backend conformance (the CPU reference is the arbiter); the engine
  consumes only the result hash; explicit non-goals (no on-chain IR execution, no
  interpreter, no gas metering, no float).
- `SPEC.md §15.6–§15.8` — the arbitration rule (`reference == submitted →
  WorkerCorrect`, `== counter → ChallengerCorrect`, else `Inconclusive`),
  evidence-validation rules, the verdict↔`vwc_hash` binding, the resolution window
  (same length as the filing window, **lapse** settles as `Correct` with no fee
  and burns the challenger deposit), and the **whistleblower bounty** (25% of the
  slashed amount, drawn from PSCB, capped by the reserve; a transfer, not a mint).
- `crates/srct-l2/src/dispute.rs` — `DisputeEvidence` (read from a `Disputed`
  contract, `validate` with named errors), `Arbiter`, `DisputeVerdict`,
  `DisputeEngine::{arbitrate, resolve}`. The engine is pure and total: it compares
  result *hashes*, never executes IR, never verifies BLS (quorum is the existing
  settle path's job), and never moves value. `Inconclusive` produces no settle
  payload (`InconclusiveDispute`) — a malformed or unexecutable task fails to
  convict rather than defaulting to guilt.
- `crates/srct-l2/src/task_contract.rs` — `DisputeChallenge` now stores
  `against_attestation`, so a `Disputed` contract is self-describing; `L2Config`
  gained `whistleblower_bounty_percent` (25); `due_for_dispute_lapse` and
  `lapse_dispute` implement the resolution window.
- `crates/srct-l2/src/state.rs` — `L2Effect::Settled` gained `challenger_bonus`;
  `apply_settlement` returns the bounty paid, credits the submitter refunds and
  the challenger refund, computes the bounty as
  `min(slashed × percent / 100, pscb)` against the reserve *before* this
  settlement's own PSCB share is added, and hands the slashed deposit to the M2
  `SlashVault`. `advance_block` now also fires dispute lapse, in sorted task-id
  order.

**Reused, not reimplemented:** `SlashVault` (M2), `fees::split_flat_fee` (M1 +
D3), `ComputeAttestation`/`ComputeTask` (M3), `ValidatorSet`/`BlsVerifier` (M5),
and the exact Phase-2 settle path (`Settle` → `apply_settle`) — a verdict's only
output is a `SettlePayload` the existing path already applies.

**Verification.** 444 workspace tests (was 410, +34): +8 `dispute.rs` unit tests,
+18 `dispute_flow.rs` integration tests (honest worker wins, fraudulent worker
slashed with capped and uncapped bounty, inconclusive settles nothing and can
still lapse, fee==escrow and fee>escrow boundaries, unauthorized challenger,
second/replayed dispute, wrong settle hash, no double settle/slash, determinism
across independent runs, and the quorum gate), +7 deterministic
`fuzz_invariants.rs` tests (decode totality/inversion, M3 reader bounds, evidence
validation totality, arbitration determinism, and value conservation across a
300-step adversarial transaction program), plus the `l2_flow.rs` bounty update.
fmt clean, clippy `-D warnings` clean, release build clean, all five sims green,
all eleven fuzz targets compile, L1 vectors unchanged.

**Fuzzing.** Four new targets (`l2_payload_decode`, `m3_readers`,
`dispute_arbitrate`, `l2_state_apply`), CI fuzz-smoke extended to all eleven. A
40-second campaign per target (~7.2M execs) found **one harness false-positive**
(not a product bug): the `dispute_arbitrate` assertion wrongly forbade an `Ok`
`Inconclusive` verdict, which is the designed safe outcome. Fixed in the harness
with the correct contract asserted; re-fuzzed clean. The deterministic
`fuzz_invariants.rs` suite carries this case permanently.

**No new product bug was found in Phase 3.** The Phase-2 missing-submitter-refund
bug stays fixed and the conservation invariant is asserted after every scenario
in the new suite, including the bounty path.

**Still gated:** BLS/M5 finality activation (end of Phase 6). **Now unblocked:**
Phase 4 (Verified Work Certificates) — a settled verdict and `vwc_hash` are what
a certificate certifies.

## Phase 4 — Verified Work Certificates: SHIPPED (`srct-l2::vwc`) — 2026-10-06

The VWC layer is built on top of the existing TaskContract, dispute engine and
settlement path. SPEC.md §17 is its normative text. **No L1 consensus rule
changed** and the D3 fee schedule is untouched; the one product fix (below) is a
validation tightening, not an economic change.

**What exists**

- `crates/srct-l2/src/vwc.rs` — `VerifiedWorkCertificate` + `VwcVerification`.
  Canonical, exact-inverse encoding (version, task, worker, result hash,
  settled height, payment, and — for `Quorum` — the settle payload's own BLS
  aggregate, bitmap and count). The id is *derived* (`DOM_L2_VWC`, §17.3) and
  never serialized, so a tampered certificate cannot carry a matching id.
  `validate` fails closed: identity, sanity, then the quorum threshold and a
  real aggregate check over the exact settle decision.
- `crates/srct-l2/src/state.rs` — the registry (`task_id → certificate`),
  issuance wired into **both** settlement paths: an explicit `Settle` issues
  `Quorum` (reusing the payload aggregate), an implicit auto-settle/lapse issues
  `WindowElapsed`. Issuance happens *before* value moves, so a refusal leaves
  the state untouched. Only `Correct` settlements certify; `Fraudulent` issues a
  `SlashRecord` and `Expired` issues nothing. `L2Effect::Settled` gained
  `vwc_id`.
- `crates/srct-l2/src/task_contract.rs` — **the Phase-4 product fix:** a worker
  can no longer submit the all-zero result hash, because that hash is
  `VWC_HASH_EXPIRED` and would collide with the expired-placeholder record
  (`BadAttestation`, regression-tested).
- `crates/srct-core/src/l2.rs` — `DOM_L2_VWC` (`srct/l2/vwc/v1`), frozen like
  the other tags.

**Reused, not reimplemented:** the M5 `ValidatorSet`/`BlsVerifier`/aggregate path
(no new key ceremony, no custom crypto), the dispute engine (certificates are a
*consequence* of settlement, never a parallel dispute mechanism), `split_flat_fee`
(M1+D3), and the existing `SettlePayload` codec bounds.

**What a VWC proves — stated precisely (SPEC.md §17.1):** `Quorum` proves a
validator quorum signed the settlement decision; `WindowElapsed` proves the
protocol accepted the result unchallenged and is *not offline-verifiable*.
Neither attests physical execution.

**Verification.** 468 workspace tests (was 444, +24): +9 `vwc.rs` unit tests
(real-blst aggregates, tamper/forgery/sub-quorum/zero-sig refusals, codec
totality over truncations and bitflips, zero-payout certification), +14
`vwc_flow.rs` integration tests (quorum and window-elapsed issuance, fraudulent
and expired non-issuance, placeholder-hash refusal, tampered/re-id'd/stranger
certificates refused by the registry, forged aggregates refused after
re-deriving the id, dispute-of-settled refused, determinism across independent
runs, sorted registry enumeration, conservation after every scenario), and the
L2 fuzz-invariant program now also asserts registry tamper-freedom. fmt clean,
clippy `-D warnings` clean, release build clean, all five sims green, all twelve
fuzz targets compile.

**Bugs found and fixed (1 product, several test-harness):**

1. **Product:** a worker could submit `result_hash == VWC_HASH_EXPIRED`
   (all-zero), making a certified-correct settlement indistinguishable from an
   expired one in the settle record. Now refused at submission. Regression test
   in `vwc_flow.rs` and a unit-level guard in `task_contract.rs`.
2. **Spec, corrected by the tests:** the original §17.6 draft required
   `payment_sat > 0` on a certificate. The existing fee==escrow test proved a
   zero-payout `Correct` settlement is reachable, so the rule was corrected —
   zero-payout work still certifies, honestly recording `payment_sat == 0` —
   rather than silently excluding those workers from certification.
3. **Test harness:** the first VWC unit fixture used placeholder validator keys
   (`[i; 48]`), which are not curve points; the real verifier correctly refused
   them. The fixture now derives real keys, so the tests exercise genuine
   pairing verification. No product change.

**Fuzzing.** New target `vwc_decode` (codec totality, exact inversion, id
stability, `validate` totality) — CI fuzz-smoke now loops all twelve targets.
Campaign (WSL nightly + ASan, 40 s each): `vwc_decode` 1,163,630;
`dispute_arbitrate` 3,760,893; `l2_state_apply` 12,630 (crypto-bound). Total
~4.9M execs, **0 crashes**. No product bug surfaced by fuzzing this phase.

**Performance (measured, release, `vwc_perf_probe`):** encode 4.6 µs, decode
3.4 µs, `validate` ~2.4 ms with a real blst pairing — validation is BLS-bound by
construction, the same cost class as checkpoint verification, and no
optimization is justified. The probe is an `#[ignore]`d test kept in `vwc.rs`
for re-measurement.

**Still gated:** BLS/M5 L1 finality activation (end of Phase 6). **Now
unblocked:** Phase 5 (Worker SDK) — task discovery, claim/execute/submit,
attestation, VWC handling, wallet integration.

## Phase 5 — Worker SDK: SHIPPED (`crates/srct-worker`) — 2026-10-07

The worker-facing SDK is built on top of Phases 2–4's task, dispute and VWC
machinery. It adds no consensus logic and no new payment path: it builds the
*existing* five L2 payload types with the existing wallet, reads the
authoritative state, and derives every number the worker sees from protocol
fields. SPEC.md §18 is the normative text (17 subsections).

**Architecture.** Node connection is two injected traits — `L2NodeView`
(read: `l2_state` + `chain_height`) and `L2Broadcaster` (write: hand over a
signed `L2Transaction`) — because this build has no L2 wire transport and
inventing one would be a guess (`srct-net` carries only the §13 P2P set; the
roadmap §13 REST API is unbuilt). A future REST/WS client implements the
traits; nothing in the SDK changes. `WorkerClient` composes the lifecycle:
discover → claim → execute → submit, plus reconcile/dispute/VWC/earnings
observation. Execution is one pluggable `Executor` seam; the shipped
`CpuExecutor` is a deterministic (no-float, no-clock, no-RNG) reference in
the §16 mold.

**Lifecycle rules (SPEC.md §18.9).** Every mutating operation keys on a
protocol identity (task id / txid). Timeout ≠ failure: after any broadcast
failure the SDK reconciles against authoritative state — and if the effect
is not visible, re-broadcasting the *same bytes* is safe (the protocol's txid
replay guard makes a second apply impossible). `reconcile_claimed` and
`reconcile_submitted` re-derive the truth after restarts; the
restart-after-submit shape (`Submitted` vs `InProgress`) is
regression-pinned after being caught and fixed pre-push this phase.

**Testing.** 500 workspace tests, 0 failures (was 468):
- 5 `srct-worker` unit tests (retry classification, reconciliation totals).
- 12 `claim_flow` integration tests over a real-BLS single-node harness:
  full claim→submit→auto/explicit-settle→VWC→earnings chain, discovery
  filters and financing, restart-after-claim/submit, timeout-then-reconcile,
  duplicate-claim/submission refusal, byte-deterministic plans across
  restarts, expiry with burned-deposit accounting, cross-worker refusal.
- 15 `security` tests: the §18.11 zero-privilege escalation suite (forged
  identity via config repair, unauthorized claim/submit/dispute by balance,
  state and identity checks, replayed and byte-mutated payloads failing
  §15.2 auth, stale-state plans refused by precondition, unknown/ambiguous
  inputs refused with named errors, forged settle refused by the real BLS
  verifier) and the §18.16 secret-hygiene suite (every `WorkerError`
  variant's Display and Debug scanned against the key's hex — never present;
  plan/config Debug never embeds the wallet; failed-transaction error text
  carries no signing material).
- `srct-l2` gained one additive accessor: `L2State::tasks()` (sorted, mirroring
  `vwcs()`), the enumeration discovery is defined on.

**Fuzzing.** New target `worker_flows` (13th total): deterministic wallet
from input bytes, funded state, heights 0/50/u64::MAX, and the four plan
builders (`claim_plan`/`submit_plan`/`dispute_plan`/`discover_tasks`) each
run twice per input with determinism asserted as a crash condition;
`reconcile_*` driven for totality; the whole input also replayed through
`L2Transaction::deserialize`. WSL campaign (nightly + ASan):
3111 + 3481 + 1096 + 798 ≈ **8.5k execs, 0 crashes** (crypto-bound like
`l2_state_apply`). CI's fuzz-smoke loop now runs all 13 targets. There is no
byte-format worker config to fuzz (typed struct), recorded deliberately.

**Not done, deliberately:** no REST/WS transport (§18.3 traits are the seam
Phase 6 will implement), no executor beyond the §16-mold CPU reference, and
no claim that mainnet/Phase-6 items are complete. The `AmountTooSmallForFee`
settle-fee economics question remains open, carried from Phase 2.

**Still gated:** BLS/M5 L1 finality activation (end of Phase 6). **Now
unblocked:** Phase 6 (testnet integration, worker↔node transport, chaos
testing, mainnet readiness).

---

## Phase 6 — STEP 0 audit, then M1 (L2 in the block pipeline): SHIPPED — 2026-10-07

Phase 6 opened with an audit (`docs/phase6-plan.md`) because the phase did not
turn out to be the one the roadmap describes. The headline finding: L2 was not
merely unintegrated but **unreachable from consensus** — `srct-node` did not
depend on `srct-l2`, `Chain::submit` took only a `Block`, and `L2State` held a
private balance ledger whose only entry point (`credit`) no production path
called. The validator set had no stake ledger to derive from, finality had no
message type, L2 state was unrecoverable across restart (no serde in `srct-l2`),
and the node had no transport at all.

Four decisions were required and made (Decisions 6–9 in `docs/decisions.md`):
L2 transactions ride inside L1 blocks with no header change; L2 value enters
through a genesis-funded protocol escrow; testnet bootstraps from a fixed
genesis committee; the transport is the roadmap §13 REST API.

**M1 shipped** (`SPEC.md` §19.1, normative):

- Blocks carry L2 transactions in an append-only trailer, **absent when empty**,
  so a block with none encodes byte for byte as before — no version bump and no
  frozen vector change (`genesis_block()` is unchanged; verified, not assumed).
- The header's existing `merkle_root` commits to the L2 leaves under a distinct
  domain tag, so the *existing* `MerkleRootMismatch` rule already refuses a
  block whose L2 section was stripped or altered. `Chain::submit` was not made
to know about L2 — no new L1 consensus rule.
- L2 state is **derived, not stored**: `srct_l2::replay::ChainL2` rebuilds it by
  replaying the stored chain (`advance_block(h)` then the block's payloads), so
  restart recovery and reorg both need no undo bookkeeping. The incremental path
  (`empty` + `apply_block`) is asserted equal to full replay.
- A payload that does not apply is skipped **by name** and stays retryable —
  L2 validity is explicitly not an L1 block rule, so this is visible rather than
  swallowed.
- `Chain::mine_block_with_l2` produces such blocks; `mine_block`,
  `mine_block_with` and `mine_from_pool` are unchanged, so no existing caller
  moved.

**Verified:** 513 workspace tests / 0 failed / 1 ignored (was 500; +6 block, +7
replay); fmt clean; `clippy -D warnings` clean workspace-wide; release build
clean.

**Honest limitation, deliberately pinned by tests:** with no funding bridge
(Decision 7) and no genesis committee (Decision 8), every L2 transaction
replayed from a chain is refused for insufficient balance and no settlement can
verify quorum. The L2 marketplace does **not** yet run end to end; M1's replay
machinery is verified against a chain holding no value and no validators. SPEC
§19.3 says so explicitly so §19.1 cannot be over-read.

---

## Phase 6 � M1 node integration: SHIPPED � 2026-10-07

M1 carriage/replay (above) left L2 unreachable from the running node:
`srct-node` did not depend on `srct-l2` and no production path replayed a block.
That gap is now closed. **No L1 consensus rule changed, no wire format changed,
no L2 semantic changed.**

**What was added** (`crates/srct-node/src/l2.rs`, `SPEC.md �19.1`):

- `srct-node` depends on `srct-l2` and consumes `ChainL2` through a thin `NodeL2`
  wrapper. The node holds no second state machine: every payload is applied by
  `L2State::apply`.
- Sync rule, called after every batch of accepted blocks (mined or received �
  both move the same tip through the same `submit`): tip unchanged ? no-op;
  tip extended ? incremental `apply_block`; history rewritten or first sync
  after startup ? full `ChainL2::replay` of the winning chain. Reorg therefore
  needs no undo bookkeeping, and a rejected L1 block (no tip movement) cannot
  mutate L2 state.
- L2 state is **not persisted**. Restart replays the blocks the store already
  holds; there is no second source of truth to go stale.
- Settlements verify against the empty validator set with the production
  `RealBls` verifier until the M4 genesis committee exists � fail closed with
  a named refusal, never applied without authority. `L2Config` follows the
  network profile (`mini` ? short window, else production).
- Observability (M1 minimum): `status` prints L2 height/applied/skipped;
  `verify` asserts replay determinism (two replays agree, incremental agrees
  with replay) and names each skipped payload with height, txid and reason.

**Tests:** 20 node integration tests (`crates/srct-node/tests/l2_node.rs`):
no-L2 / valid-unfunded / multiple / bad-auth / no-quorum-settle /
present-but-empty trailer / stripped trailer / modified payload / double-sync
no-op / sequential incremental / two-view determinism / restart through a real
`BlockStore` / duplicate+orphan rejection / no-partial-write / reorg replay /
credit-seam-funded apply + restart reset / funded-claim-UnknownTask /
config-per-profile / status observability. One real bug caught pre-push: the
sync delta underflowed when a reorg dropped recorded skips � now saturating
deltas plus exact totals, with a regression test.

**Verified:** 533 workspace tests / 0 failed / 1 ignored (was 513; +20 node);
fmt clean; `clippy -D warnings` clean workspace-wide; release build clean;
13 fuzz targets compile (no new target: the integration adds no new parser �
`Block`/`L2Transaction` decode is unchanged); sim suite clean.

**Still ahead after M1, unchanged:** M2 funding bridge (every replayed payload is still
an expected `InsufficientBalance` skip until the escrow exists - pinned, not
worked around), M3 transport, M4 committee + finality, M5 testnet. No claim of
testnet, finality, or mainnet readiness.

---

## Phase 6 — M2 funding bridge (genesis-funded escrow): SHIPPED — 2026-10-07

M2 makes the L2 economy usable without touching L1 consensus, issuance, rewards,
fees, the money cap, or the genesis block. **No new transaction type (L1 or L2).
No new decision** — this builds Decision 7 exactly as recorded; the escrow
amounts and grantees are parameters under that decision, listed below.

**The model.** The escrow fits in the sats the L1 ladder provably can never
the explicit `escrow_ceiling_sat` parameter per profile. There is no unmintable
M-E it is bounded by the explicit `escrow_ceiling_sat`, not by the gap rule).
`NetworkParams` fixes per profile: `l2_genesis_escrow_sat` (`mini` 10 SRCT,
`mainnet` 100,000 SRCT, no mainnet grants) and `l2_genesis_grants` (`mini`:
1 SRCT each to three deterministic operator identities, seeds 1–3). The 7 SRCT
remainder parks with the derived protocol escrow identity
(`SHA256("srct/l2-escrow/v1" ‖ network_id)[..20]`), inert until a later
milestone authorises disbursement. `validate()` refuses zero/over-total/
duplicate/escrow-named/zero grants and any escrow above `escrow_ceiling_sat` — so combined
L1 + L2 money can never exceed the cap, with zero L1 rule change.

**Application.** `L2State::apply_genesis` releases the allocation once per
fresh state (grants + remainder), before any block replays; a second call is
refused (`GenesisAlreadyApplied`). All `ChainL2` constructors build through it,
so replay, incremental sync, restart and reorg derive identical funding with no
persisted record. `funded_total` (append-only, counted by every credit) plus
`conservation_total` make conservation self-checking; `verify` asserts
`funded_total` equals the escrow total and L1-live-plus-L2-held stays under
the cap. `credit()` stays public but production never calls it post-genesis —
only unit tests (custom states) do.

**Proven by tests.** Funded `PostTask` flows through the real node path (task
appears, balance drops by exactly payment + fee); unfunded accounts still fail
closed; same bytes in two blocks apply once (`Replay` refusal); restart and
reorg keep funding exactly once with no kept losing history; two independent
replays agree on balances, escrow, tasks, funding and skip records;
incremental agrees with replay; the joint conservation check holds while mining.
The `l2_state_apply` fuzz target additionally asserts the funded-total
invariant per operation (no new target: no new parser boundary).

**Verified:** 553 workspace tests / 0 failed / 1 ignored (was 533; +4 params,
+9 L2 genesis, +7 node funding); fmt clean; `clippy -D warnings` clean
workspace-wide; release build clean; 13 fuzz targets compile; sim suite clean.

**Still ahead after M2:** user deposits, L2-to-L1 exits, worker–node transport,
the validator committee, binding finality and the testnet profile — all of which
have since shipped (Decision 10, Decision 19, Decisions 12–15).
Decision 7 — needs its own decision before mainnet), M3 transport, M4
committee + finality, M5 testnet. No claim of testnet, finality, or mainnet
readiness.

---

## Phase 6 — M3 user deposits (Decision 10, burn-to-sink overlay): SHIPPED — 2026-10-07

M3 was gated on a decision Decision 7 explicitly withheld, so it began with an
audit that stopped with zero implementation changes. The audit recommended the
burn-to-sink overlay; Decision 10 (recorded in `docs/decisions.md` before any
M3 code) authorises it with seven explicit parameters. This builds exactly
that — nothing more.

**The mechanism.** An ordinary STANDARD payment to the params-derived sink
(`SHA256("srct/l2-deposit-sink/v1" ‖ network_id)[..20]`, distinct from the
escrow identity, network-bound) is interpreted by L2 replay as a deposit. No
new L1 transaction type; L1 consensus, layouts, fees, issuance and cap rules
all untouched. Recipient = common input owner derived from key bundles (which
L1 already proved equal the UTXO owners); mixed owners and coinbases are burns
without credit. Amount = exact sink output satoshis, 1:1, per-output minimum
1,000,000 sat both profiles. Maturity = `tip − height ≥ finality_depth`
(mini 20, mainnet 100): pending before, spendable after, using the existing
depth finality — no new finality invented. Identity = `(txid, index)` in a
state consumed set: credited once, ever. A matured deposit sits below the
finality line, so it is as irremovable as its block by existing consensus.

**Processing.** Detection is a pure function of one block
(`srct_l2::deposits::scan_block`); crediting is `L2State::apply_deposit`
(exactly-once, counted into `funded_total` and `deposited_total`);
`ChainL2` evaluates maturity against the tip and exposes pending/ignored;
`NodeL2` rebuilds by full replay when an old pending deposit matures
(incremental never re-scans old blocks). Restart and reorg re-derive
everything: no persisted deposit record exists to go stale, duplicate, or
survive its block.

**Conservation.** The M2 joint check grew its sink term (sink outputs stay in
the L1 UTXO set while their twins live in L2):
`L1 live + L2 held − sink-held ≤ cumulative_issuance_sat(height) + escrow_ceiling_sat`,
asserted by `verify` alongside
`funded == escrow + deposits` and self-checked conservation. `verify` also
names pending (with spendable height) and ignored (with reason) deposits.

**Tests:** 22 new (553 → 575): 1 params (sink determinism/binding/minimum),
9 L2 scan/apply/maturity incl. double-absorption, 12 node e2e + attacks
(end-to-end deposit→post→restart-identical; mixed owners; zero-amount and
mutated rejected at L1 build; dust; wrong sinks silent; competing-branch
single credit; two-output independence; unfunded still closed; pending-deposit
reorg removal + winner re-credit exactly once; incremental/full agreement with
pending; joint cap with live deposits). No new fuzz target: the scan consumes
already-decoded transactions (no new codec); the `l2_state_apply` target is
unaffected (custom-funded states, invariant intact).

**Verified:** 575 workspace tests / 0 failed / 1 ignored; fmt clean;
`clippy -D warnings` clean workspace-wide; release build clean; 13 fuzz
targets compile; sim suite clean.

**Still ahead after M3:** L2-to-L1 exits, the committee + finality and the
testnet profile — all since shipped (Decision 19, Decisions 12–15). Mainnet
stays closed by `exit_activation_height = 0` until the owner configures a height.
(was: **Still ahead, unchanged:** L2-to-L1 exits (no decision recorded — deposits
without exits trap funds, so mainnet stays blocked by design), M4 committee +
finality, M5 testnet. No claim of testnet, finality, or mainnet readiness.

## Phase 6 — M4 validator set + finality foundation (Decision 11, non-binding): SHIPPED — 2026-10-07

M4 was gated on two withheld decisions (stake bonding D8; who the validators
are), so it began with a full audit that changed no code. The audit found the
economics unsupported by the tree — no stake ledger, no bond/unbond path, no
committee in params, two unreconciled checkpoint engines, no checkpoint codec,
no finality wire message — which is exactly what Decision 8 scoped out of Phase
6 and gated to mainnet. Decision 11 (recorded before any M4 code) therefore
scopes rather than invents: it builds the fixed-genesis-committee foundation
on Decisions 2 + 8 and does **not** activate binding finality.

**The committee.** Explicit BLS keys in `NetworkParams` (`genesis_validators`),
canonically sorted; `mini` declares four deterministic test keys, `mainnet`
declares none (every checkpoint fails closed until a committee is decided). No
stake ledger is added — Phase 6 still has none, as `docs/decisions.md` records.
`checkpoint_interval_blocks` is 10 on `mini`, 100 on `mainnet`. The genesis
`EpochSet` is a pure function of params, identical on every node.

**One authority.** `validators::validate_checkpoint_against_set` is the single
checkpoint authority (six clauses); `bls_checkpoint::verify_checkpoint` stays
its inner primitive. `finality::FinalityManager` verifies certificates against
the declared committee and records the highest observed height. `Checkpoint` and
`CheckpointPayload` gained length-bounded `deserialize`.

**Transport.** `msg_type = 11 CHECKPOINT` (§13.5), relay-only, complete
certificates — verified on receipt against the local committee and relayed if
valid; consensus never consults it. Protocol version stays 1 under the §13.5
freeze rule. New §13.12 vector + independent `sim/net_reference.py` encoder
agree byte-for-byte.

**Observation, not activation.** `Chain::submit`, fork choice and
`finalized_height` are untouched. A reorg crossing an observed checkpoint still
applies; `finality_m4::a_reorg_crossing_an_observed_checkpoint_still_applies`
pins that, so binding can never slip in silently. L2 `Settle` quorums are
untouched — task arbitration, not the L1 checkpoint committee.

**Tests:** 13 new (`finality_m4`): committee determinism/hash, mainnet 21-key
bootstrap + empty-L2 fail-closed, full-quorum observe, sub-quorum/forged/other-network refusal,
monotonicity, bounded-codec round-trip and three oversize/count lies, and the
non-binding reorg proof. Plus a new `checkpoint_codec` fuzz target (17 targets).

**Verified:** 588 workspace tests / 0 failed / 1 ignored (575 + 13); fmt clean;
clippy clean; release build clean; 14 fuzz targets compile; sim suite clean
(36 wire values cross-checked).

**Still ahead after M4:** bonded stake / unbonding / rewards (mainnet-gated,
D8 → now P2), validator rotation, equivocation slashing. Exits and the testnet
profile have since shipped (Decision 19, Decisions 12–15). (was: **Still
ahead, unchanged:** bonded stake / unbonding / rewards (mainnet-gated,
D8), validator rotation, equivocation slashing, L2-to-L1 exits, M5 testnet. No
claim of testnet, binding finality, or mainnet readiness.
---

## Phase 6 — M5 binding finality + testnet profile + L2 finality integration (Decisions 12–15): SHIPPED — 2026-10-07

The M5 audit (no code changed first) re-read the tree after M4 and found four
decisions were missing before any consensus change: L1 finality was still
depth-only (`finalized_height = tip − finality_depth`), `FinalityManager` was
observation-only and consulted by nothing, there was no testnet profile,
`equivocation_evidence` had no caller, L2 deposits matured by depth alone, and
the node's L2 validator set was the M1 empty set (fail-closed by default).
Decisions 12 (binding activation), 13 (testnet profile), 14 (equivocation
policy) and 15 (L2 finality semantics) were recorded in `docs/decisions.md`
**before** any consensus code changed, and this milestone implements exactly
them — no more.

**Binding finality (Decision 12, SPEC §14.8).** A checkpoint certificate becomes
binding when its height reaches the profile's `finality_activation_height`
(`testnet` 20; `mini`/`mainnet` 0 = never), and only if it is canonical,
carries a valid certificate under the six clauses, satisfies the unchanged
`ceil(n × 6667 / 10000)` quorum, is strictly monotonic, and conflicts with
nothing already accepted. `Chain::finalized_height()` is now the stronger of
the depth rule and the binding point — `max(tip − finality_depth, binding)` —
and `adopt()` refuses any branch forking at or below it with
`ReorgWouldCrossFinality` (the pre-existing error, finally fed by a real value).
Below activation nothing changes: observation stays observation, pinned by the
M4 non-binding test which still runs unchanged.

**Conflict protection (Steps 4).** Every listed attack fails closed with a
named refusal: insufficient quorum, forged aggregate, foreign committee, wrong
network, signer count that cannot match its bitmap (a bitset cannot encode a
duplicate signer), signer bits outside the committee, stale/replayed heights,
future heights, non-canonical hashes, malformed input (codec and structure).
A conflicting certificate is classified *before* the canonical clause, so
`H → B` against a retained `H → A` proves the conflict instead of being
misfiled as merely non-canonical — and no refusal ever moves finality.

**Equivocation (Decision 14).** Conflicting valid certificates at one height
retain `EquivocationEvidence {offender, first, second}`: the first common
signer in canonical key order, and the two payload hashes in canonical
serialized-byte order — so two nodes that saw A-then-B and B-then-A retain
byte-identical evidence (pinned by test). Bounded at 1024 records, deduplicated
by content, deterministic. Nothing is burned and no penalty exists: stake
bonding does not exist yet, deliberately.

**Restart (Step 3).** The finalized `(height, hash)` lives in the store's
existing metadata row (no second database; older files without the fields parse
as "no finality"). It is restored only onto the exact canonical block the node
just replayed — a stale or forged row is refused — and the restored point gates
`adopt()` exactly like the live one. Before-restart point == after-restart
point, and a second restart derives the same point again.

**Testnet profile (Decision 13).** `NetworkParams::by_name("testnet")`: unique
`network_magic`/`network_id`, four deterministic genesis validators (distinct
derivation from `mini`'s; quorum 3), 10-block checkpoint interval, activation
20, depth fallback 20. Two independently constructed profiles are byte-identical
(`testnet() == by_name("testnet")`, committee keys included) — no runtime
entropy. Config-time guards refuse an activation that is off the epoch grid or
has no committee. No staking, no rotation, no launch: this is the protocol
profile required to exercise binding finality.

**L2 deposit maturity (Decision 15, SPEC §19.5).** A deposit is spendable only
when **both** hold: the M3 depth rule, and — once binding finality exists — the
deposit's height at or below the binding-finalized height. Before activation the
depth rule governs alone (never weaker than M3); after activation, depth alone
cannot credit a deposit whose canonical history is unfinalized. The floor is
read from the L1 chain's own finality layer on every sync; L2 keeps no
checkpoint view. The node's sync also re-evaluates maturity when a checkpoint
moves the floor **without moving the tip** — otherwise a finality-held deposit
would sit pending until some unrelated block arrived.

**L2 settlement seam (Decision 15, SPEC §15.1).** `srct_node::l2::validator_set`
returns the profile's declared active committee. Decision 27 later split this
into the separate `l2_settlement_validators` field: mini/testnet use the same
four keys as their L1 committee, while mainnet leaves the settlement set empty
and refuses everything (`BadQuorum`). `Settle` payloads signed by the declared
set apply through the real node path (task lifecycle → disputed → explicit
Correct settle → VWC issued); foreign keys are refused by name
(`BadBlsSignature`). `WindowElapsed` semantics and all existing VWC
verification are untouched.

**Tests:** 37 new, all M5-scoped — 25 in `srct-core/tests/m5_finality.rs`
(profile matrix, activation, the nine-case conflict matrix, the critical reorg
below/above/at the finalized height, equivocation determinism + bounds,
restore-refuses-lies, fresh==incremental finality), 4 in
`srct-l2/tests/m5_deposit_finality.rs` (pre-activation + Cases A/B/C/D), 6 in
`srct-node/tests/m5_node_finality.rs` (declared-committee settlement, foreign
refusal, empty-committee fail-closed, checkpoint-without-tip maturity,
restart determinism), 2 in `srct-store/tests/m5_finality.rs` (persisted point
survives reopen; every lying row refused).

**Verified:** 625 workspace tests / 0 failed / 1 ignored (was 588; +37); fmt
clean; clippy `-D warnings` clean workspace-wide; release build clean; sim
suite clean (vector cross-check, difficulty attack, supply); 14 fuzz targets
build under nightly cargo-fuzz — `checkpoint_validate` extended with a
finality-state harness (no panic, bounded evidence, no conflicting-finality
acceptance, evidence totality/determinism) and `meta_parse` with the new
finality-field invariants. One local limitation, stated honestly: libFuzzer
*execution* needs ASan, which this MSVC Windows box does not ship (the plan
already notes "MSVC cannot run it"); the targets were compile- and
link-verified here and CI's fuzz-smoke runs them on Linux.

**Not built, still deferred:** validator staking/bonding/unbonding/rotation/
rewards, economic slashing (evidence exists, punishment does not), L2→L1
exits, monetary redesign, the multi-node public testnet launch (the profile
exists; the launch is not this milestone), machine economy, Bridge Layer.

**Still ahead:** M7 performance (benchmarks in `docs/benchmarks.md`), M8 SPEC audit
+ mainnet checklist (see `docs/mainnet-readiness.md`). L2→L1 exits remain a
design decision (see `docs/l2-exit-design.md`).

---

## Phase 6 final status — 2026-10-08

**Tests:** **870 passing, 0 failed, 1 ignored** across the workspace. The
ignored test is the intentional `vwc_perf_probe` performance re-measurement point.

New tests added this phase:
- 15 deterministic chaos/failure tests (`chaos.rs`) covering node, L2, chain, accounting
- 15 API integration tests (`api.rs`) including `GET /v1/reputation/{id}` (2 tests)
- 1 two-process E2E test (`e2e_two_process.rs`) — real `srct-node serve` over TCP
- 14 fuzz targets (added `checkpoint_codec`, all CI-listed targets now covered)

**Security audit:** `docs/security_audit.md` — no critical or high-severity findings.
All identified threat surfaces covered by tests and/or fuzzing. Fuzz report:
`docs/fuzz.md` — 17 targets, 9,352,161 executions, 0 crashes (WSL2 nightly + ASan, measured 2026-10-09).

**SPEC reconciliation:** `docs/roadmap.md` updated — 14/14 Phase 6 items implemented.
SPEC.md §14.2 L2 payload types now match `crates/srct-core/src/l2.rs` exactly.
SPEC.md §19.2 (opt-in service API) specifies the REST surface (health, tx build,
reputation and the L2/task/payment/receipt endpoints).

**CI:** Added `checkpoint_codec` to the fuzz-smoke target list. All CI jobs green:
fmt, clippy (`--workspace --all-targets -- -D warnings`), tests, vectors, sim suite.

**Operational readiness:** `docs/mainnet-readiness.md` and `docs/testnet-readiness.md`
provide launch runbooks, monitoring configs, backup/recovery procedures, and
graduation criteria.

**Documentation:** Added `docs/benchmarks.md`, `docs/fuzz.md`,
`docs/monetary-policy.md`, `docs/micro-payment-audit.md`, `docs/l2-exit-design.md`.
The exit design was **approved as Decision 19 and implemented** (SPEC §19.6,
2026-10-09); an earlier revision of this line cited a 'Decision 21' that does not
exist, and a later one still listed it as pending. (was: The exit design is
**blocked on a decision not yet recorded** — the exit deferral
in Decision 10 (`docs/decisions.md` *Pending* P1); an earlier revision of this
line cited a "Decision 21" that does not exist in the repository.

---

## Phase 7 - On-chain agent authority and credit: SHIPPED (2026-10-21)

The last phase changed what the *chain* knows, not just what a node remembers.
Two capabilities that used to be node-local are now consensus state, replayed by
every node and committed by the block's `l2_state_root`.

### What moved on chain

**Agent authority** (SPEC.md §21, Decision 25). The spending-policy layer was a
policy on the node that issued it: `chain.rs`, `ledger.rs`, `mempool.rs` and
`tx.rs` contained no reference to a policy, an agent, a delegation or a credit,
so a machine fleet was bound by the goodwill of whichever node had issued the
policy. Three Layer-2 transaction types now carry it:

| Code | Type | Actor | What it does |
|---|---|---|---|
| `0x16` | `Policy` | owner | publish a grant |
| `0x17` | `PolicyRevoke` | owner | kill a grant |
| `0x18` | `AgentSpend` | spender | spend under a grant |

The owner's signature binds three things at once - the grant bytes, the
**spender** and the **agent identity** - because a policy hash on its own is a
capability, and a capability anybody can exercise is worthless. The chain
enforces the per-transaction cap, the tumbling per-window cap, the recipient
and service allow-lists, the validity window and the strictly increasing nonce
against state it keeps, refuses a delegated grant that widens its parent, and
kills every descendant when the owner revokes the grant.

**Credit** (SPEC.md §22, Decision 26). The credit book was a ledger of IOUs:
`POST /v1/credit/deposit` credited a local balance *without moving a coin*
(the code said so), `POST /v1/credit/open` accepted a `spec_hex` whose `lender`
field was just a field anybody could write, and no other node could see the
debt. Four transaction types now carry it:

| Code | Type | Actor | What it does |
|---|---|---|---|
| `0x19` | `CreditOpen` | **lender** | open a position; the principal moves to the borrower |
| `0x1A` | `CreditCollateral` | borrower | add collateral |
| `0x1B` | `CreditRepay` | borrower | repay (interest first, then principal) |
| `0x1C` | `CreditDefault` | anyone | settle a position that was not repaid by its deadline |

The lender signs the terms, the principal really moves, the collateral is the
borrower's own money (checked before the principal arrives, so the borrowed
funds cannot secure themselves), and a default is permissionless: the
collateral answers for the debt, the surplus returns to the borrower, and what
is left uncovered is a shortfall the lender absorbs rather than money the
protocol invents.

Both live in the Layer-2 state (`policies`, `positions`, `credit_locked`) and
are committed under the state root with their own leaf tags (`0x05`, `0x06`).
The state wire version moved 3 → 5.

The same protocol bump moved the mainnet network magic from `6A 4E 54 01` to
`6A 4E 54 02`; `mini` and `testnet` moved to `03` and `04` so every profile
keeps a unique discriminator. A pre-bump node presents `01` and is refused at
the framing layer (which re-checks the magic on every frame) and again at the
handshake, so it cannot join or relay into the new mainnet. The mainnet genesis
block itself is unchanged by the bump (magic and wire version are not header
fields) and is pinned by `mainnet_genesis_is_frozen_for_the_version_bump`.

### The bugs this found

- **A repayment larger than the debt was silently overpaying the lender.** The
  borrower paid the whole amount, the debt dropped by less, and the reported
  interest and principal did not add up to what moved. The node-local credit
  book refused that shape, so the chain now refuses it too
  (`CreditRepaymentExceedsDebt`).
- **The CLI's `--amount 10.5` - the form the README documents - had never
  worked.** The fraction was padded with spaces instead of zeros, so every
  fractional amount was refused with "must be a number". Found by running the
  documented command.
- **Six specification/code drifts** (the `DOM_ADDR` version, the header
  length, the mainnet finality and exit activation heights, the settle fee,
  the committee selection rule) and a `chaos` test that was flaky because a
  reused process id could inherit a store directory from an earlier run.
- **Mojibake in five files**, from an earlier editing round-trip.

### How it is verified

- **An independent implementation.** `sim/l2_authority_reference.py` is a second
  implementation of the same rules, written from SPEC.md §21-§22 in Python: it
  derives secp256k1 addresses, the agent identities, the grant hashes and the
  position ids itself. It emits `tests/vectors/l2_authority_vectors.json`, and
  `crates/srct-l2/tests/l2_authority_vectors.rs` replays those scenarios and
  asserts the same verdict, the same reason and the same final state. Building
  it found two divergences in the *reference* (the replay guard has to come
  before the state checks; the height an advance step leaves behind is the
  height the next step is judged at) and confirmed the chain's behaviour in
  both.
- **Two fuzz targets.** `l2_policy_apply` asserts value conservation, that a
  spend never exceeds its grant, that revocation is absolute, that authority
  narrows and that a replay is refused. `l2_credit_apply` asserts conservation,
  that collateral is locked rather than spent, that debt only goes one way,
  that a default is not early, and that interest is charged once per period.
  Every registered target is now in the CI smoke loop - `deliverable_codec`
  had been registered but never run.
- **A hardening suite** (`crates/srct-l2/tests/authority_hardening.rs`): replay,
  forged and tampered signatures, duplicate publication, duplicate opening,
  double revocation, malformed grants, overflowing amounts, the validity
  window, a height running backwards, overpayment, and the two restart cases.
- **A terminal suite** (`crates/srct-node/tests/cli_authority.rs`): the whole
  flow against a real chain - deposit, publish, spend, revoke, the refusal of a
  spend under a revoked grant, and the credit flow - plus the property that a
  command the chain would skip mines nothing.

### 2026-10-29 hardening pass (no new features)

Security/quality review of wallet, mining and core code, fixing only
existing behavior — no new transaction types, endpoints or issuance:

- Wallet: `new_random` loops until the scalar is valid; `schnorr_signing_key`
  wipes its stack copy on the error path; `pubkey` returns `BadPubkey`
  instead of unwrapping; `cmd_wallet --new` refuses duplicate labels
  (shadowed wallets); validator labels are allowlisted (`[A-Za-z0-9._-]`,
  max 64, no `.`/`..`); validator keys go through the atomic 0600
  `write_private` path with an explicit exists-check; plaintext saves keep
  the `Zeroizing` wrapper to the write; Argon2id parameters are pinned
  explicitly (19 MiB, 2 passes, 1 lane) so a crate upgrade cannot lock
  operators out of existing wallets.
- Mining: pool `proof_meets` no longer mutates `header.difficulty` before
  hashing — the share bar selects the target, the header is evaluated
  as-is (mutating it evaluated a different puzzle instance, so valid
  shares could be refused and invalid ones accepted); solver verification
  errors propagate instead of masquerading as "no solution" (sequential
  and batched paths); `--threads`/`--batch` are clamped
  (1024/65 536, `0` keeps its existing meanings); miner HTTP responses are
  capped at 16 MiB with malformed responses refused; pool lock ordering
  is one-lock-at-a-time (no `inner` -> `payouts` nesting); payout
  `record_share` saturates and ledger decode caps rounds at
  `MAX_ROUNDS_KEPT`.
- Core: `lock_time` is now enforced in `check_tx` (future-locked
  transactions no longer mine immediately); maturity uses `checked_add`;
  overwrite guards before every consensus `UtxoSet::insert` (apply,
  coinbase, unbond release, exit claims) so a colliding outpoint is
  refused instead of silently destroying coins; `u32::try_from` for output
  indices; checked PSCB/burned reserve credit and undo; checked
  `split_fees` product; `message_for_input` gains a fallible
  `try_message_for_input` for wire-supplied indices; mempool evicts the
  lowest-fee-rate entry when a strictly higher-rate transaction arrives
  full (ties keep the incumbent); exit claims refuse zero amounts.
- Verified: revocation is checked node-side before both `admit_payment`
  call sites (`payment_submit` and the shared x402 admission), matching
  the documented design — no change needed there.
- `cargo clippy --workspace --all-targets` clean; `srct-core --lib`
  (522), `srct-miner` (47), redteam suites, `srct-node --test api`
  (47) + `agent_economy`/`micro_safety`/`x402`, L2 `credit_flow` — all green.

### 2026-10-30 security lessons (exit throttle, enforced approval, auth liveness)

A second external input — incident-style lessons (hot-wallet drain playbook).
Verified claim-by-claim, then implemented:

- Exit rate limit (was absent, now consensus): `max_exit_window_sat` /
  `exit_window_blocks` cap exit principal per window (mainnet: 1,000 SRCT per
  144 blocks); over-cap queues refuse with `ExitWindowFull` naming the retry
  height, funds untouched. Large exits (≥100 SRCT mainnet) wait 144 extra
  blocks, enforced identically in L2 queue accounting and the L1 release
  check. All four knobs are `NetworkParams` (mini/testnet 0 = disabled) with
  pair-validation, mirrored into `L2Config`; L2 wire v5 → v6. Reorg-safe by
  construction (windows replay from the winning chain, no undo bookkeeping).
- Human approval enforced (was advisory): at/above
  `SRCT_HIGH_VALUE_THRESHOLD_SAT` the payment is **refused** (403
  `human_approval_required`) until a key listed in
  `SRCT_HIGH_VALUE_APPROVERS` co-signs the payment hash — payer's own key
  does not count, `payment_approved` is audited, and both submit and x402
  settle enforce it. Threshold 0 keeps everything off, as before.
- Offline-auth liveness (was owner+sig only): new
  `verify_authorization_for_policy` checks owner, signature, revocation and
  the `[not_before, expires_at)` window; `Session::verify` uses it when the
  policy is attached (`with_policy`), and x402 `verify` loads the named
  grant and refuses stale ones. `PolicyBinding` variant added for the two
  new mismatch shapes.
- Monitoring signal: `/v1/conservation` now reports `exit_window_*`,
  `pending_exit_sat` and the cap — theft conserves, so the outflow signal is
  what trips, not the invariant. Docs gain Monitoring alerts, hot-wallet cap
  recipes, and key-separation rules (approvers ≠ issuers ≠ providers ≠ seed
  keys; provider keys deserve hardware/threshold custody).
- Found while verifying: a `git stash` round-trip confirmed `mine_block`
  behavior the template filter had changed (dust bond tests caught it in
  the previous commit's scoping fix).
- Verification: clippy clean; L2 incl. new window/large-exit tests, the
  `verify_authorization_for_policy` liveness unit test, 3 node-lib approval
  tests, core bond/exit suites, node
  api/agent_economy/micro_safety/x402/state_persist — green. README count
  1368 → 1374; `state_wire` version pin 5 → 6.

### 2026-10-30 external critique response (docs honesty + 2 code gates)

An outside reviewer's critique verified claim-by-claim against the code; all
five code claims held up (one partial). Fixed as follows:

- Pitch: README leads with one claim now (programmable money for machines),
  with new "Why a new coin" (admission-enforced policies + native settlement
  can't be a contract elsewhere), "Glossary" (PSCB, VWC, TopN, PPLNS… in one
  line each), and "Honest limits" (no outside audit, optimistic verification,
  no AI training in mining, per-node views can disagree, FX/ramp trusteeship,
  public bootstrap). Neural stage described as ML-shaped integer work with
  epoch-derived weights — explicitly not training or inference. Quality
  claims qualified as author-run throughout; the Python reference is a second
  implementation by the same author, not a second party.
- Bootstrap keys (TRUE): serving mainnet with the 21 public keys loaded now
  requires `--allow-bootstrap-committee`; without it the node refuses to
  serve. Rotation on first bond already existed; the gate covers the custody
  side it didn't.
- Minimum stake (TRUE): `min_bond_sat` added (0 mini/testnet, 0.01 SRCT
  mainnet — anti-dust scale, not a wealth gate), enforced in `check_bond_tx`
  and therefore in mempool admission, block building and apply. Decision 20
  amended; SPEC §14.6 amended. Boundary test pins floor-inclusive refusal.
- Fake verification (PARTIAL): the dispute path genuinely re-executes and
  slashes fakes *when challenged* — but unchallenged fakes settle, and the
  reference output is self-referential deterministic mixing, not real
  compute. No code change can fix incentives; documented instead (README
  Honest limits + `unverified_result` test reference). Found while verifying:
  round-3's stake filter had moved into the shared template builder and was
  silently dropping invalid stake txs from `mine_block` (6 bond tests caught
  it); the filter is now scoped to the external-template boundary and
  `mine_block` fails loud at submit again.
- Node-local disagreement (TRUE): architecture confirmed correct — nothing
  consensus reads the books. Documented instead: per-node divergence banners
  in `reputation.md`, `ramps.md`, `usd-settlement.md`; `state.bin` v8 refuses
  foreign-network books.
- FX/ramp trust (TRUE): trustee model stated up front in both docs and
  README — trail proves lies, doesn't prevent them.
- Verification: clippy clean; bond_stake 18/18 (incl. new floor test),
  external_miner, node bin, full round-3 suites re-green.

### 2026-10-30 portable policy layer (grants that travel)

The policy layer answers *may this agent spend?* — this commit answers how
that answer travels. All service layer, no consensus change:

- **Signed policies** (`srct-core/src/portable.rs::SignedPolicy`): a grant
  plus the owner's signature over it, verifiable on any chain or rail with no
  node, no chain state and no private key. Canonical bytes + JSON with
  routing fields that parsing re-checks (a document that routes one way and
  verifies another is refused).
- **Verifiable delegation** (`DelegationProof`): the root-first chain of
  signed policies — every signature verifies, every link narrows
  (`assert_chain`), the chain starts at a root. One proof that the owner
  authorized this agent.
- **Short-lived enforced grants** (`BoundAuthorization`): the owner signs the
  grant hash, the expiry and the exact transaction hash together
  (`srct/bound-auth/v1`), 30-block lifetime cap enforced at issuance and
  verification. Re-aimed or expired bindings refuse by name; admission via
  `service::admit_bound_payment` verifies the binding before the standard
  path runs.
- **Chain-agnostic seam** (`PaymentIntent` → `PolicyDecision`: allow, deny,
  approval-needed) in a new `crates/srct-policy` crate with no consensus
  imports, plus TypeScript/Python bindings that speak the same JSON without
  re-implementing any rule.
- **Wallet guard**: `X402Budget::check_guarded` (budget + short window before
  any key is used), Base/Base-Sepolia EVM route options advertised beside
  SRCT on x402 challenges (settled externally, never by this node), and 9 new
  keyless `srct-mcp` ops (`wallet.guard`, `policy.decide/export/verify`,
  `delegation.prove/verify`, `auth.bind/verify_bound`, `audit.verify`).
- **Audit export**: `AuditLog::export_json` emits the hash-chained log for
  auditors/insurers; `verify_export_json` re-checks links, entry hashes,
  order and tip.
- Verification: clippy clean; 14 new tests (5 portable, audit export, x402
  guard, `srct-policy` decide, 6 MCP guard/prove/bind/audit); core lib (530),
  node api (47), x402 roundtrips, bridge/agent_policy/redteam_delegation,
  L2 policy_flow, miner, committee_rotation — green. README count
  1374 → 1388. Interface specified in `docs/portable-policy.md`.

### 2026-10-30 review findings (exit fairness, approval default, binding backends)

Four code-reading findings, each verified against the code and fixed with
its test (Decision 31):

- **Per-owner exit sub-cap (consensus).** The window was global-only — one
  filler could starve every owner until rollover. Mainnet now bounds one
  owner to 100 SRCT of the 1,000 SRCT window at the L2 queue (the only gate
  windows have), refused as `ExitOwnerWindowFull`; shares are
  replay-derived, ride the state wire (v6 → v7, re-checked at decode), reset
  on rollover. While verifying, Decision 29's "L1 release path shares the
  rule" did not survive contact with `check_claim` (no window check there —
  the property holds because every release proves a queued record); the
  comment and SPEC now state the verified truth.
- **Approval default-on (node policy).** A missing
  `SRCT_HIGH_VALUE_THRESHOLD_SAT` now gates mainnet at 10 SRCT; explicit
  env (including `0`, the opt-out) still wins. Wired through both admission
  paths and `GET /v1/risk/policy`.
- **Bindings that run.** `POST /v1/policy/decide` (read-only, deny-as-200),
  `/v1/delegation/verify`, `/v1/audit/verify`, with `NodeHttpBackend` in
  both bindings and `sim/policy_decide_demo.py`; verified live against a
  real node (allow, deny, approval-needed over HTTP).
- **Crate weight, stated honestly.** `srct-policy` stays a facade (full
  `srct-core` compile); outsiders use HTTP/bindings. 5 tests pin the seam.
- Verification: clippy clean; exit_flow (27), state_wire pins, params/L2
  pairing, mainnet-default matrix, api decide/verify routes, srct-policy
  (5), Python self-test — green. README count → 1401.

### 2026-10-31 security review (Decision 32)

A read-through of policy, wallet and security code. Most held (sig
validate-first, strict nonces, overflow-checked windows, delegation
owner/network/role/link checks, signer==payer binding, x402 inner path
gates like submit). Four gaps fixed: audit `dropped` counter (`/v1/audit` +
export, old exports still verify), portable routing-field cross-checks
(`agent_id`/`network_id`/`leaf_agent`), engine-owned network binding
(wrappers pass through), and a re-verification that every money path runs
through `risk_gate`. Clippy + fmt clean; core lib (534), node api (49),
micro_safety, mcp (19), x402/agent_policy/bridge/redteam — green. README
count → 1403.

### 2026-10-31 time-warp review (Decision 33)

A 51%-attack review pass over consensus, finality, difficulty, slashing,
mempool, networking, L2 and supply: reorg-across-finality refused, binding
checkpoints with quorum + conflict-as-evidence, LWMA clamps + median-time +
one-block-time future bound, unbond/vesting delays, bounded mempool with
cascade eviction, rate-limited + ban-scored networking, L2 replay-not-persist,
integral-bound mint, bounded EIP-1559 fees, gated credit mint. One gap:
orphan resolution re-submitted clock-blind (`submit`), relying on intake
alone — a backward clock step could smuggle a far-future timestamp into the
retarget. Resolve now carries `now_ms` with a regression test pinning both
directions. No consensus change. srct-net (36) green, fmt + clippy clean.
README count → 1404.

### 2026-10-29 hardening round 3 (no new features)

Third review pass (transfers in/out, mining end-to-end, agent/SDK workflows,
CLI + API surface), same rule: fix existing behavior only. Highlights:

- Transfers: orphan receipts refused at intake (404, never filed);
  settlement double-count closed (one tx output settles one payment —
  `settlement_overlaps`); self-serve `credit/deposit` forbidden on exposed
  binds (issuer-signed `credit/mint` only); expired-payment credit
  reservations released on the finality tick (no permanent lock); stale
  escrow↔exit bindings rebind instead of deadlocking the escrow;
  stream-bound payments must pay the stream's recipient (voucher accounting
  and coin cannot diverge); exit crank reports *why* each queued exit waits
  (`immature`, `no_exact_funding_subset_at_current_fee`, `amount_overflow`);
  `send` refuses `--fee` below the consensus floor and above the payment
  itself, and prints amount/fee/change before mining.
- Mining: template timestamps capped at `min(now, median, now+future)` with
  a fail-closed clock-lag refusal; external templates include mempool
  transactions like the internal miner (minus L2/exits); submit enforces the
  local-clock rule, evicts confirmed pool entries, caps `block_hex`, and
  reports `canonical: false` for side branches (solo miner retries instead
  of logging false success); pool share pin extended to `base_fee_sat` /
  `version` / `sig_scheme`; unreachable share bars refused at job time; HBM
  falls back to sequential grind under `batch > 1`; pool rounds mature like
  the chain (earnings unlock at height + maturity, `void_round` cancels
  orphans, ledger v1 → v2).
- Worker/SDK: `execute_task` admits InProgress contracts only (no more
  attestations on unclaimed/expired work); `reconcile_claimed` distinguishes
  `Disputed` / `SettledCorrect` / `Lost` (a live dispute no longer reports
  as submitted); `dispute_resolution` gains `InDispute`; dispute plans
  precheck the window; all plan builders use atomic `observe()`; payload
  build failures surface as `Protocol` instead of collapsing into
  `IdentityMismatch`; MCP hex fields capped, endpoints resolve via DNS with
  a 5s connect timeout, inspect answers carry `admissible: false`.
- Node/CLI: unknown `--switch` is a hard error (no more silent `--no_mine`
  typos); `--credit-issuer` parses as a valued flag; bootstrap refuses a
  non-empty committee dir; `state.bin` envelope v7 → v8 (network-bound: a
  foreign network's book is refused instead of merged); conservation report
  carries `joint_overflow` (a clamped sum no longer reads as headroom);
  list endpoints take `?limit=` (max 1000, with `total`/`truncated`).
- Verification: clippy clean; core lib 522, L2 all suites, node api 47 +
  agent_economy/micro_safety/x402/state_persist + all remaining integration
  suites, miner 48, worker 49, net/store/mcp, committee/rotation, redteam —
  green. Three tests updated to the new fail-closed rules (orphan-at-intake,
  execute-gate message, pool maturity), none weakened.

### 2026-10-29 hardening round 2 (no new features)

Second review pass (L2, P2P/net, store, node service layer, worker, MCP,
params), same rule: fix existing behavior only. Highlights:

- L2 consensus: bitmap OOB panic on truncated settle/VWC bitmaps (bounds
  guard); explicit `Expired` verdicts now respect the deadline like
  `try_expire`; dust escrows refused at post instead of created-then-stuck;
  mutate-before-fail ordering in `note_release`/`queue_exit`;
  counter-attestation bound to the challenger; bounty percent validated
  0..=100 with checked math; deposits keep-pending on failed apply;
  `L2Transaction` version actually checked; `strip_pq_sidecar_for_test`
  removed from release builds; double revoke is an idempotent no-op.
- L1 consensus: `lock_time` enforced (SPEC §9.2 updated from "advisory");
  overwrite guards on every UTXO insert; checked PSCB/burn math;
  `historical_epoch_set` falls back to genesis (matches `committee_keys_at`);
  conflict evidence now intersects the validating epoch set, not genesis
  keys; `rewind_observation` clamps instead of wiping (replay via reorg
  closed); params validate retarget bounds; difficulty clamps into profile;
  reserve/burn undo checked.
- Worker: definitive broadcast refusals are `BroadcastRefused`
  (non-retryable) instead of collapsing into infinite retry; atomic `observe`
  + re-observe after execution; exit-to-sink refused; over-long HTTP bodies
  capped in MCP/miner readers with strict status parsing; VWC batch listing
  validated; `certificates_for_worker` takes the validator context.
- Pool/miner: share check no longer mutates the header difficulty (it
  evaluated a different puzzle instance); solver errors propagate; thread and
  batch counts clamped; per-connection HTTP caps.
- Node API auth: job `open` needs the hirer's signature, `deliver` the
  worker's (over job+result, and a receipt naming another result is refused),
  `loans/accept` the borrower's; resolve binds the signed result;
  reputation batches must match the subject/counterparty/amounts of their
  sources; ramp settle digest covers the fill ref; FX swap recomputes
  `sat_due` server-side; autorepay replacements need a greater nonce and keep
  the routed total; job identity includes the funding nonce (`state.bin`
  envelope v6 → v7); expired tiers refused; demo weather demands the exact
  amount; list endpoints take `?limit=` (max 1000, `total`/`truncated`).
- Net/store: handshake failures scored per-IP (no more free handshake
  spam); self-connection refused by nonce; trailing-bytes refused on
  reader-decoded messages (Unknown exempt per §13.5); INV batch deduped;
  lowest-score ban eviction; `Version` UTF-8 slicing panic fixed;
  unbounded writer/queue paths capped (`MAX_ORPHANS`, orphan index no longer
  O(n²)); ancestry walks cycle-guarded; empty records rejected at scan;
  dir fsync after renames; address-book writes batched (30s).
- Residuals deliberately left: sighash has no network binding (replayable
  across networks — needs a protocol bump, Decision + vectors); bundle order
  is order-independent (pinned by tests); maturity applies to all outputs;
  `fx/swap` and `ramp/intent` record unauthenticated user claims (inert
  without the provider/quote signature; settlement is enforced elsewhere).
- Verification: clippy clean; core lib 522, L2 all suites, node
  api/agent_economy/micro_safety/x402, miner 47, worker, net (incl.
  arbitration propagation), store, mcp, committee/rotation, redteam — green.
  Two tests were updated to the new fail-closed rules (dust-at-post,
  FX fee binding), not weakened.

### 2026-10-29 service-layer additions (no consensus change)

Three feature commits landed on top of the consensus described above. All are
node-local service layer over the existing primitives (`MachinePayment`,
`SpendPolicy`, credit path, escrow) — no new transaction type, no issuance,
mint or settlement-rule change:

- **x402 adapter** (`srct-core/src/x402.rs`, `GET /v1/paid/weather`,
  `POST /v1/x402/verify|settle`, `docs/x402.md`, `sim/x402_paid_api_demo.py`).
  Tests: `srct-core --test x402`, `srct-node --test x402`.
- **Micro-payments + wallet safety** (`micro.rs`: batch quotes, stream
  channels, sponsored intents; `safety.rs`: session budgets, risk guards,
  hash-chained audit log, unsettled/orphan reconciliation;
  `docs/micropayments.md`, `docs/wallet-safety.md`,
  `sim/micropayment_benchmark.py`). Tests: `srct-node --test micro_safety`.
- **Agent economy** (`passport.rs`: portable reputation with issuer-signed
  batches and score tiers; `tiers.rs`: narrowed tier wallets; `jobs.rs`: job
  escrow with result binding and dispute holds; `fx.rs`: signed USD/stablecoin
  rates with locked quotes; `ramp.rs`: provider-signed entry/exit registry;
  `lending.rs`: standard loan offers, borrower history, limits, dashboard,
  collateral valuation, autorepay; `docs/reputation.md`, `docs/agent-jobs.md`,
  `docs/usd-settlement.md`, `docs/ramps.md`, `docs/lending.md`,
  `sim/agent_economy_demo.py`). Tests: `srct-node --test agent_economy`.
- Also today: `Jolunit/JLNT` rebrand to Solar Cyber Unit/SRCT, SRCT coin logo
  in README, `l2_credit_apply` fuzz-target fix (debt-monotonicity invariant;
  target-only, see `docs/fuzz.md`), and pool/release hardening carried over
  from the mining review.

### What is still not done

- **No validator yield.** The decision is recorded (Option B: the reward comes
  from the Layer-2 fee pool, the Layer-1 coinbase is untouched) but it is not
  implemented: paying it means the committee has to be reachable from the
  Layer-2 state, and the checkpoint a committee signs is not part of a block, so
  the reward cannot be a function of chain state alone without a rule that says
  which checkpoint counts.
- **No exchange.** No second asset, no order book, no price oracle. SRCT's
  economic usage is meant to come from SRCT network usage.
- **The service-layer books** (the payment book, the receipt book, the credit
  admission gate) are still node-local. They are gates, not sources of
  spendable balance - a settlement still needs a real transaction - but they
  are a second kind of state, and the honest thing is to say so.

### 2026-11-05 Smart Gate security pass (no consensus change)

Five holes closed as structural rules in `srct-core/src/guard.rs`, with the
same rule enforced in `srct-policy`, `srct-mcp` and the node API:

- **Signed capabilities** (`SignedCapability`): the owner's hybrid signature
  over the capability hash (policy + action + context + expiry + nonce
  together). Bare/unsigned envelopes are refused on every boundary; forgeries
  and tampered fields deny as `UnsignedCapability`.
- **Signed approvals** (`GuardApproval`): owner-signed, bound to the exact
  capability instance with its own 30-height lifetime cap. Missing approval
  gates (`needs_approval`); forged approval denies; the boolean form is
  rejected everywhere.
- **Action recomputation**: `derive_action_hash(preimage)` is recomputed from
  the bytes the boundary observes (`action_preimage_hex` required at
  `guard.authorize` / `POST /v1/guard/authorize`); drift denies and commits
  nothing.
- **Replay/revocation**: nonce 0 refused, strictly increasing nonces persisted
  in `state.bin`, revocation kills registered descendants, the stateless
  pre-check consults the same revocation set, registry/book caps (1024) refuse
  rather than evict, window arithmetic overflow-safe.
- **MCP endpoint trust**: `host:port` only; bearer token to loopback only;
  remote needs `SRCT_MCP_TRUSTED_ENDPOINTS` + `SRCT_MCP_ALLOW_REMOTE=1` and
  still never receives the token; redirects refused; no credentials in errors.
- Docs updated to match: `README.md` (Smart Gate + honest limits),
  `docs/smart-gate-architecture.md` (full rewrite: protocol, trust
  boundaries, authoritative-state model, implemented/partial/planned),
  `docs/portable-policy.md` (Smart Gate pointer + rules), white paper
  (§Security model: new `Smart Gate: the execution boundary` subsection,
  replay table, domain tags, MCP paragraph, constants, invariants,
  limitations).
- Verification: clippy clean, `cargo fmt --check` clean; new negative tests
  for forgery, fake approval, action swap, zero nonce, unsigned MCP/node
  admission, untrusted endpoints; `api` guard round-trip extended (unsigned
  refused, swap denied, replay denied, revoke kills).
- Follow-up fix (same day): `srct-node --test api` showed 8 credit-admission
  failures in CI (`test and vectors`) and locally. Root cause predates this
  pass: commit `0064108` made admission reserve `amount + fee` (2400 for the
  bridge payment) but the api tests still funded only the amount (400-700).
  Fixed by funding `BRIDGE_TOTAL_SAT` in the 8 tests
  (`crates/srct-node/tests/api.rs`); `run_bridge` now uses the named
  `BRIDGE_FEE_SAT`. Full `api` suite green (50 passed), plus `micro_safety`,
  `agent_economy`, `x402` green; clippy and fmt clean. CI `test and vectors`
  is green on the follow-up commit.

### 2026-11-05 Smart Gate correction pass (no consensus change)

Review follow-ups closed as structural rules in `srct-core/src/guard.rs`,
enforced in `srct-policy`, `srct-mcp`, `srct-node` and `srct-worker`:

- **Owner-set risk.** `InfraPolicy` (layout v2, v1 still decodes) carries
  `requires_approval`; every boundary ORs it with the caller's flag, so
  `high_risk: false` from a caller never de-escalates a high-assurance
  grant. New test: de-escalation attempt gates.
- **Independent approver.** The grant names an `approver` distinct from
  owner and agent; `GuardApproval::verify` requires the designated
  approver's keys. Owner-as-approver fails closed (`SelfApproval`) at
  registration and on every admission path. New tests: approver admits,
  owner self-approval denies.
- **Workload binding.** Grants may bind `workload_id`; boundaries recompute
  the context from the bound id and ignore caller-supplied ids. New test:
  spoofed presented id ignored, wrong-built context denies.
- **Audience scoping.** Capabilities carry `audience`; nodes admit only
  their own (`SRCT_GUARD_AUDIENCE`, zero by default). Unscoped legacy
  capabilities admit everywhere (documented residual). New test: scoped
  cap admits home, denies away, commits nothing.
- **Reference execution boundary.** `srct-worker/src/guard.rs`
  (`GuardGate::execute`) recomputes the canonical preimage from the exact
  work about to run and only then invokes the executor; drift refuses.
  K8s webhooks remain planned.
- Docs updated in place: architecture doc (§§3-9), README (How it works,
  replay/state, honest limits), portable-policy pointer, white paper
  (Smart Gate subsection, replay table, invariant, limitations).

### 2026-11-05 Smart Gate hardening pass (no consensus change, no commit)

Reviewer-reported gaps closed as code; per instruction this pass is not
committed — verification below is on the working tree:

- **Worker revocation bypass.** `GuardGate::execute` now takes a mandatory
  `RevocationAuthority` consulted on every run before the local book and the
  executor. `NodeDecideAuthority` replays node `POST /v1/guard/decide`
  against live authority state (no new endpoint, no new trust root).
  Stale answers forget local accounting and deny; unreachable authorities
  deny without touching state (no offline fallback, no cached-allow).
  New tests: revocation-at-authority stops execution and forgets state;
  unreachable authority never executes.
- **Raw unsigned path deleted.** `GuardBook::authorize` removed entirely;
  `authorize_signed` is the only entry point. Core tests and
  `state_persist` migrated to the signed boundary (deterministic owner
  wallets). Compile failure is now the proof no integration bypasses
  signature verification.
- **Explicit v1/v2 compatibility.** `authorize_inner` accepts layouts v1
  and v2, refuses unknown versions loudly; `InfraPolicy::serialize` is
  version-aware so v1 re-serializes byte-identically (hashes and old
  signatures stable); `validate` refuses v1-marked grants carrying v2
  fields. Tests: v1 decodes, authorizes with legacy semantics, hash-stable;
  unsupported envelope versions refuse; truncated/trailing bytes malformed.
- **Workload proof of possession.** `InfraPolicy.workload_key` pins the
  workload identity fingerprint; `WorkloadCredential` (fresh per execution,
  height-bound) is verified inside `authorize_signed` via the single shared
  `check_workload_credential` rule used by pre-checks, node routes, MCP and
  the worker (which auto-proves from its provisioned key and sanity-checks
  the fingerprint before admission). Node/MCP accept optional
  `workload_cred_hex`. Tests: missing/forged/stale/mismatched credentials
  deny; honest proof admits (core, policy, MCP, node HTTP, worker).
- Verification (working tree): core guard 21, policy 10, MCP 24, worker
  guard 5, node api 52 (incl. new key-bound HTTP test), state_persist 3;
  `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --all --check` clean.
- Remaining limitations: revocation-between-check-and-execution stops the
  next run, not the current one (no cross-node lock); workload identity is
  software keys (hardware TPM/TEE attestation planned); k8s admission
  webhooks planned; worker/node HTTP stays plaintext loopback-oriented.

### 2026-11-05 Smart Gate authority fixes (no consensus change)

Two review findings on the hardening pass, both confirmed and fixed:

- **Credential never reached the authority.** The gate asked first and
  proved after; the pre-check refuses key-bound grants without proof, so
  key-bound capabilities could never execute via the worker. Fixed order:
  recompute → prove fresh → admit statefully with the credential in the
  request (`AdmissionRequest.workload_cred_hex`, verified at the node) →
  local re-verification → execute. A test authority that requires the
  credential on bound grants proves the proof now travels.
- **Nonce enforcement was not authoritative.** The worker consulted a
  read-only pre-check and committed nonces in its own local book, so
  restarts and sibling workers could independently accept the same nonce.
  Fixed: `GateAuthority::admit` goes through stateful node
  `POST /v1/guard/authorize` (`NodeGateAuthority`), which is the single
  commit point. The local book is now a trailing mirror plus independent
  cryptographic re-verification. New test: two workers sharing one
  authority ledger — the same nonce executes once, the replay denies at
  the authority and commits nothing locally.
- Verification (working tree): worker guard 6, node api 52, core guard 21,
  policy 10, MCP 24, state_persist 3; clippy and fmt clean.

### 2026-11-05 Smart Gate authority–worker height sync (no consensus change)

Root cause confirmed: the node commits nonce + window at its live chain
height, but the worker re-verified locally at its own possibly stale
`GuardGate.height` — so the authority could allow (and consume a nonce)
while local verification denied on context mismatch, with no execution.

- **Authoritative height carried through.** `Admission::Allow` now carries
  the `height` the node admitted at; `NodeGateAuthority` parses it from
  the `POST /v1/guard/authorize` answer via the pure, unit-tested
  `parse_authorize_answer`. Local `authorize_signed` runs at that height,
  never the worker's clock.
- **Fail closed on missing/malformed height.** An `allow` without a usable
  height is an error, not an admission — the nonce may already be
  committed, so the worker reports instead of guessing.
- **Credential validity unchanged.** Possession proofs are still built at
  the worker-observed height and height-bound exactly; no lifetimes
  extended. The operator sync contract stands: set `GuardGate.height`
  from the node before executing. A stale proof denies at the authority
  with no commit.
- **Nonce-without-execution is possible and reported.** If the authority
  commits but local verification then fails (e.g. a stale local policy
  copy), the nonce stays consumed; the failure surfaces as `GuardDenied`
  and is never retried into a duplicate — a retry would deny as a replay
  at the authority. Proven by test, documented in the architecture doc.
- Tests: worker behind/ahead/equal heights execute at the authoritative
  height; missing/malformed height answers error; local-deny-after-allow
  executes nothing twice; key-bound HTTP test asserts the node reports
  its admission height; replay/possession/approval suites unchanged.
- Verification (working tree): worker guard 10, node api 52, core guard 21,
  policy 10, MCP 24, state_persist 3; clippy and fmt clean.

### 2026-11-05 Key-bound credential height sync + bounded retry (no consensus change)

Follow-up gap: the possession proof was built once at the worker-observed
height, but the node validates it at its live height — a drifting worker
could never execute key-bound grants. Fixed without extending any lifetime:

- `GuardGate::execute` rebuilds context + credential per attempt and retries
  a key-bound admission (max 3 attempts) only when the authority denies with
  a height-plausible reason (`is_height_drift_deny`, pinned wire strings)
  *and* reports a different height. Every other deny fails immediately;
  denies commit nothing, so retries can never double-spend a nonce.
- New `crates/srct-node/tests/guard_worker_http.rs`: real worker
  (`GuardGate` + `NodeGateAuthority` + `CpuExecutor`) against a real node
  over HTTP — in-sync admission, behind/ahead self-heal, replay and
  impersonation denial, approval-gated admission, and the node's reported
  height asserted on the wire.
- Unit coverage: retry heals a mid-flight height move; non-drift denies
  never retry (call-counted); allow-without-height and malformed answers
  fail closed; wire reason strings pinned in core.
- Verification (working tree): guard_worker_http 5, worker guard 12,
  node api 52, core guard 22, policy 10, MCP 24, state_persist 3;
  `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --all --check` clean.