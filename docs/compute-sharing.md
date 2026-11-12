# Decentralized compute sharing

Status: **working non-consensus prototype** in `crates/srct-compute`. It lets
heterogeneous devices advertise compute behind a signed bond, lets a requester
shard work across them, and settles exactly the units each provider finished.
It moves no coin and does not change consensus.

```bash
cargo test -p srct-compute
cargo run --release -p srct-compute --example compute_demo
```

## 1. What problem it solves

A phone with 2 GB of RAM, a 64 GB laptop, a GPU box and a future NPU should all
be able to earn SRCT for spare compute without four separate protocols:

- a provider must describe its hardware, kernel and price in a signed offer;
- a requester must state units, device requirements, verification level, price
  cap and total budget;
- the scheduler must split the job into shards that actually fit each device;
- a provider must receive an authorization it can prove, and a requester must
  pay only for units that were assigned and claimed;
- a timed-out provider must not be able to settle after the work moved.

`srct-compute` answers those with signed data formats, a deterministic planner
and a settlement ledger. Running the work, gossiping offers and executing the
payout are the operator's layers.

## 2. Device profile

```
DeviceProfile = version || class || determinism || ram_mib || cores ||
                max_units_per_shard || bandwidth_kbps || kernel(32)
profile_hash = SHA256("srct/compute/device-profile/v1" || encode)
```

- `class`: CPU, GPU, TPU, NPU, Apple silicon, photonic. A new class is a new
  encoding value; an unknown byte is refused rather than coerced.
- `determinism`: `Statistical < Reproducible < BitExact`. A job requiring
  `BitExact` cannot be scheduled on a floating-point device.
- `max_units_per_shard` is a device-side cap, independent of the offer's
  per-job cap.
- `kernel` is the declared kernel-set hash; zero means "any kernel". A job that
  names a kernel binds reproducibility to that exact hash.

`DeviceRequirement` matching is fail-closed: an empty class mask matches nothing,
too little RAM refuses, a weaker determinism class refuses and a different kernel
refuses.

## 3. Signed offers

```
ComputeOffer = version || network || provider || service || profile ||
               unit_price_sat || min_units || max_units_per_job ||
               privacy || verification || available_from || available_until || nonce
offer_hash = SHA256("srct/compute/offer/v1" || encode)
```

`SignedOffer` carries the provider's hybrid key bundle and signature over
`offer_hash`. Verification requires the bundle to own `provider`. The scheduling
window is explicit, and the per-job cap bounds how many units one offer can take
across all of its shards.

`min_units` is the smallest profitable shard; a scheduler never asks a device to
run a fragment below it. `privacy` says the provider accepts a sealed input, and
`verification` is the advertised evidence level.

## 4. Signed jobs and planning

```
ComputeJob = version || network || requester || service || units ||
             max_unit_price_sat || max_total_sat || class_mask || min_ram_mib ||
             determinism || required_kernel || min_verification || sealed_input ||
             input_commitment || deadline || nonce
```

`SignedJob` is the requester's authorization. `max_total_sat` is a hard budget,
so many shards cannot turn a low unit price into unbounded spend.

`plan_assignments(job, offers, height, attempt)` is a pure, deterministic
function:

1. verify the job and every offer; drop any offer that fails;
2. keep offers on the same network and service, inside their availability
   window, at or below the price cap, at or above the verification floor, with a
   privacy mode that matches `sealed_input`, and with a device profile that meets
   every hard requirement;
3. sort by `(unit price, provider, offer hash)`;
4. greedily take `min(remaining, offer-per-job left, device per-shard cap)` from
   each offer, skipping any shard below `min_units`;
5. refuse when no candidate exists, capacity cannot cover every unit, the shard
   cap is exceeded, or the cheapest complete plan exceeds `max_total_sat`.

The result is a `Plan` of `Assignment`s. Each assignment names the job, offer,
requester, provider, shard index, units, unit price, exact total, deadline and
attempt, and is hashed under its own domain tag. `Plan::sign` turns every shard
into a requester-signed `SignedAssignment`; a `SignedPlan` verifies all shards
and that their totals add up exactly.

An offer may own several shards: its `max_units_per_job` is cumulative across
them, so a phone with a 4-unit shard cap and an 8-unit per-job cap takes two
shards, never more than 8 units.

Example from the demo (`fleet`: GPU 7 sat/unit, phone 10, laptop 12; 30 units,
total budget 1,000 sat):

```
plan: 30 units in 4 shards for 244 sat
  shard 0: 20 units -> GPU      at 7 sat/unit
  shard 1:  4 units -> phone    at 10 sat/unit
  shard 2:  4 units -> phone    at 10 sat/unit
  shard 3:  2 units -> laptop   at 12 sat/unit
```

The phone participates because its shard cap is 4 units, not because the
protocol has a phone-specific path.

## 5. Receipts and settlement

```
ComputeReceipt = version || job || assignment || provider ||
                 units_done || unit_price_sat || total_sat || output ||
                 elapsed_ms || height || nonce
```

The provider signs `receipt_hash`. `ComputeLedger::settle` then checks:

- both signatures verify, and the keys own the named provider/requester;
- receipt job, assignment id and provider match the assignment;
- `units_done <= assignment.units`, unit price matches, and
  `total_sat == units_done * unit_price_sat`;
- neither settlement height nor the claimed finish height is past the deadline;
- the assignment was not already settled and was not expired.

It records a `PayoutInstruction { from, to, amount_sat, job, assignment, receipt }`
and returns it. The instruction moves no coin; the existing payment or escrow
layer executes it. Duplicate settlement returns `AlreadySettled`.

`expire` marks an assignment as timed out only after its deadline. Expired
assignments can never settle, so a late receipt cannot resurrect work that was
already rescheduled. `attempt` is capped at `MAX_ATTEMPTS` (3), so a job cannot
be retried forever against the same budget.

## 6. Bonds and reputation

Sybil resistance starts here: identity is still an ordinary SRCT address, but a
capacity claim now costs stake and bad behaviour costs more.

```
ProviderBond    = version || network || provider || amount_sat || registered_height || nonce
BondWithdrawal  = version || network || provider || amount_sat || nonce
BondDispute     = version || network || requester || provider || assignment ||
                  reason || evidence || nonce
```

- **Registration** (`BondBook::register`): the provider signs a bond. It is an
  instruction for the escrow or payment layer; the book only records it. A
  re-registration tops the bond up and clears accumulated timeouts — fresh
  stake is skin in the game. The same signed bond cannot be registered twice.
- **Lockup**: a bond cannot be withdrawn until `LOCKUP_HEIGHTS` (144) heights
  after registration. A refused withdrawal is not consumed; the same signed
  request may be retried after lockup. An applied one cannot be replayed.
- **Disputes** (`BondBook::slash`): the assignment's requester signs a dispute
  bound to one assignment. `NoShow` requires the deadline to have passed and
  takes 10% of the bond; `Overclaim` and `Impostor` (fraud) take 50% at any
  height. The same dispute cannot slash twice, the dispute must name the exact
  assignment it slashes, and slashing an unbonded provider is refused.
- **Reputation**: `score = settled_units - 10 * timeouts - 100 * slashes`,
  saturating. `record_settlement` counts a verified receipt's units;
  `record_timeout` counts an assignment that passed its deadline unclaimed.
- **Admission** (`BondBook::admit_offer`): an offer is schedulable only if it
  verifies, belongs to the book's network, stands behind a bond of at least
  `MIN_BOND_SAT` (10,000 sat) registered before the current height, and its
  provider's score is above `BAN_SCORE` (−100). A fraud slash therefore bans a
  provider permanently — re-bonding restores the stake, not the score — and a
  provider that times out ten assignments without settling any units is also
  out until it settles work or re-bonds.

Honest limits: the book verifies *who* signed a dispute, not the evidence
behind it (arbitration belongs to the escrow layer); slashes and bonds are
instructions, not coin movement; and a provider that can afford many bonds can
still present many identities.

## 7. TEE-backed execution evidence

`Verification::Attested` is now enforced by `crate::tee`, not self-declared.
A worker that runs the workload inside an approved environment presents a
signed attestation quote; the verifier decides whether the escrow rail may
release payment.

```
TeeQuote = version || network || provider || tee || workload || model ||
           runtime || config || input || output || height || nonce
```

- **Quote** (`SignedTeeQuote::sign`): the attestation (quoting) key signs the
  body. The signer is the *attester*, not the provider — the provider address
  is bound inside the signed body, so a worker cannot forge evidence for
  another provider's SLA.
- **Roots** (`AttestationRoots`): the registry of trusted quoting keys, one
  entry per `(attester, tee family)`. `revoke` marks a compromised root;
  unknown and revoked attesters are refused.
- **SLA** (`TeeSla`): the requester's conditions — network, provider, workload
  binding, approved model/runtime/config measurements, input commitment,
  required TEE family, and `max_age_heights` freshness window.
- **Verify** (`TeeVerifier::verify`, fail-closed, cheap checks first):
  SLA/quote well-formed → signature valid → attester trusted and live →
  TEE family matches → provider/workload/network bind → measurements match →
  input matches → height not future and within the age window → quote hash
  unseen (replay book) → accept and return the output hash.

Any refusal means no payment. `TeeType::Software` is a test/simulator label,
accepted only when the SLA explicitly asks for it; production SLAs pin `Tdx`
or `SevSnp`.

Honest limit, stated in code: a quote proves the approved environment
*executed* the workload (proof of execution). It does not prove the output is
correct or useful — that is challenge re-execution / ZKML, still future.

## 8. What is not enforced

- **Correctness.** A receipt proves who claims units, and a TEE quote proves
  approved execution — neither proves the output is correct. `Challenge`
  re-execution and ZK proofs remain future milestones; `Challenge` is still a
  self-declared advertised field.
- **Hardware truth.** RAM, cores, bandwidth, kernel hash and device class are
  self-declared. They bound assignment, not reality.
- **Sybil resistance at the stake layer.** Bonds and reputation gate admission,
  but a slash is only as real as the escrow or payment rail that executes it,
  and dispute evidence is unverified here.
- **Liveness and leasing.** Planning is a pure function of offers, job and
  height. Offer gossip, heartbeats, lease renewal and retry timers are the
  operator's responsibility.
- **Confidential payloads.** `sealed_input` only requires a provider that accepts
  sealed input. Sealing itself is `srct-cnnp`'s envelope, keyed off-protocol.

## 9. Verified behavior

`cargo test -p srct-compute` passes 42 tests (5 unit, 37 acceptance):

- profile hash binds class, RAM, caps and kernel; unknown encodings refused;
- requirement matching refuses empty mask, low RAM, weak determinism and wrong
  kernel;
- offer and job wire codecs round-trip, tampered offers fail their signature;
- a 30-unit job splits across a GPU, a phone and a laptop deterministically,
  including with the offer list reversed;
- a small phone takes a small job alone, and takes several 4-unit shards up to
  its 8-unit per-job cap;
- ineligible offers (RAM, determinism, kernel, class, service, price, sealed
  input, verification, expired window) are never scheduled;
- capacity, per-shard minimum and total budget are enforced;
- only the requester can sign a plan; tampered shards fail;
- full lifecycle settles exactly once, with the exact payout;
- overclaim, price mismatch, wrong assignment binding, impostor provider and
  forged receipts are refused;
- late receipts and expired assignments cannot settle; expiry is idempotent;
- attempt cap and deadline are enforced;
- assignment arithmetic and wire decoding are checked;
- an unbonded or under-bonded provider's offer is refused; a bonded one is
  admitted;
- forged, tampered and replayed bond registrations are refused, and a
  different registration tops the bond up;
- a fraud dispute halves the bond, drops the score to the ban threshold, and
  the provider stays banned even after re-bonding;
- only the assignment's requester can slash: a stranger's dispute fails on the
  requester binding, a rewritten one fails the signature;
- a dispute must name the exact assignment it slashes; a duplicate dispute is
  refused;
- a `NoShow` dispute requires the deadline to pass and takes 10%;
- ten timeouts ban a provider; settled units raise the score back over the
  threshold; re-bonding clears timeouts but not fraud slashes;
- withdrawals are refused during lockup, cannot exceed the stake, cannot be
  replayed, and a drained bond no longer backs offers;
- bond, withdrawal and dispute wire codecs round-trip and refuse truncation;
- settlement credit binds the receipt to its assignment; overclaims never
  reach the book;
- a valid attestation quote verifies and returns the output hash;
- tampered quotes fail the signature; unknown and revoked attesters refused;
- model, runtime and config mismatches refused; wrong provider, workload,
  input or TEE family refused;
- stale (past the age window) and future-height quotes refused; the exact
  age limit is still fresh;
- the same quote bytes cannot verify twice; simulator quotes accepted only
  by simulator SLAs;
- quote wire codec round-trips, refuses unknown versions and truncation;
  zero output hash and zero nonce never sign;
- signed offers, assignments and receipts round-trip through wire codecs that
  refuse truncation and version corruption;
- the flow journal appends only verified objects, snapshots with bounded
  encoding, and restarts by re-verifying every entry — tampering fails the
  whole replay;
- gossip keeps only signed live offers, dedups, merges order-independently,
  prunes on expiry, and refuses forged/foreign/overflowed input;
- challenge re-execution clears matching receipts and slashes fabricated ones:
  same result verifies clean, a different result produces a `WrongResult`
  dispute that halves the bond and bans the provider through the existing
  slash path; self-challenges, stranger requesters, duplicate challenges and
  receipts, wrong-worker/late/misbound second receipts and tampered
  challenges are all refused; challenge wire codecs round-trip.

## 10. Next milestones

1. GPU / Apple / NPU / TPU / photonic backends behind the `srct-diloco`
   `TrainBackend` conformance suite; this crate only routes units.
2. Challenge re-execution — **done** (`challenge::ChallengeBook` with
   independent re-runs, result comparison and `WrongResult` fraud disputes).
3. Escrow integration: fund the job once, release per settled receipt, refund
   the remainder at the deadline; execute bond registrations, slashes and
   withdrawals on the same rail.
4. Persistent bond/reputation snapshots (offers, assignments and receipts
   already journal — bonds are the escrow rail's job).
5. Gossip transport binding: carry the gossip set over the agent messaging
   rail or HTTP/MCP (message rules done here).
