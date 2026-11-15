# Decentralized compute sharing

Status: **production money loop** with core in `crates/srct-compute` and endpoints in `crates/srct-node`. Any device advertises capability (RAM, measured throughput, bandwidth, determinism) behind a signed bond, requesters shard work across devices, and verified receipts settle completed units — via planned assignments or the open ticket board. Offers, jobs, assignments, tickets, claims, receipts, payouts, preauth exits, escrow and bond books, and challenges persist in `state.bin` (envelope v16).

```bash
cargo test -p srct-compute
cargo test -p srct-node --test agent_economy
python templates/srct_node.py --selftest
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
and a settlement ledger. `srct-node` runs the full money loop over REST:

- market: `POST /v1/compute/offers` & `GET /v1/compute/offers/list`
  (list reports each provider's bond, score, bonded state, capacity and open exposure;
  posting is capacity-gated)
- jobs: `POST /v1/compute/jobs` & `GET /v1/compute/jobs/list`
- planning: `POST /v1/compute/plan`
- authorization to pay (push): `POST /v1/compute/assign` (optional `exit_tx_hex`
  pre-signed payout) & `GET /v1/compute/assignments/list`
- authorization to pay (pull): `POST /v1/compute/tickets` (optional `exit_tx_hex`
  on designated tickets), `GET /v1/compute/tickets/list` (open board),
  `POST /v1/compute/claims` (first valid claim wins)
- money in: `POST /v1/compute/escrow/fund`, money back: `POST /v1/compute/escrow/refund`
- settlement: `POST /v1/compute/receipt` & `GET /v1/compute/receipts/list`
- money out: `GET /v1/compute/payouts`,
  `GET /v1/compute/payouts/{receipt}/exit-template`,
  `POST /v1/compute/payouts/{receipt}/claim`
- disputes: `POST /v1/compute/challenge/open`,
  `POST /v1/compute/challenge/second`,
  `GET /v1/compute/challenge/{assignment}`
- stake: `POST /v1/compute/bonds/register`, `POST /v1/compute/bonds/withdraw`,
  `POST /v1/compute/bonds/dispute`, `GET /v1/compute/bonds/{provider}`

The loop, end to end: the requester posts a job, funds its escrow, plans
shards and signs one assignment per shard — or posts open tickets on the
board and lets providers claim them. The provider runs the work
(`templates/srct_node.py` ships built-in CPU inference and training workers,
so a fresh box contributes real deterministic arithmetic out of the box) and
posts a receipt. Settlement verifies the receipt against the assignment or
the winning claim, releases exactly its total from the funded escrow, and
records the exact payout. A pre-signed exit attached to the assignment or
designated ticket queues automatically on settlement — no second signature.
Otherwise the requester signs an exit from the template; anyone submits the
claim; consensus pays the provider when the exit releases — the same
permissionless crank pattern as the L2 exit path. A pre-signed exit attached
to the assignment (`exit_tx_hex` on assign) or designated ticket fires here
instead: the node stored it at authorization time, re-verifies the exact
binding at settle time, dry-runs L2 admission, and queues it with no second
signature. It fires only after a verified receipt settles, exactly once
(the preauth is consumed whether the queue accepts it or not — settling
twice cannot pay twice), and never redirects (owner, destination and amount
must match the payout to the satoshi). Anything else leaves the payout
manual with the reason in the audit trail. Settling the receipt
immediately frees the provider for the next claim: no cooldown, no
one-offer-at-a-time rule.

### Dedicated Resource Modes and Consumer Dispatch

In `templates/srct_node.py`, participants operate under 100% dedicated allocation:
- **`mode="mine"`**: 100% of CPU/threads allocated to PoW mining.
- **`mode="ai_compute"`**: 100% of RAM/compute allocated to AI compute tasks.
- **Consumer Task Dispatch**: Incoming consumer requests dynamically dispatch between AI inference (`task["type"] == "inference"`) and AI training (`task["type"] == "training"`).

## 2. Device profile

```
DeviceProfile = version || class || determinism || ram_mib || cores ||
                max_units_per_shard || bandwidth_kbps ||
                claimed_units_per_sec || kernel(32)   // v2; v1 stops at bandwidth
profile_hash = SHA256("srct/compute/device-profile/v1" || encode)
```

- `class`: CPU, GPU, TPU, NPU, Apple silicon, photonic. **Display label
  only.** Matching never consults it: a new hardware family joins without
  any protocol change, and a job expresses "fast" as floors, not as a
  class gate. An unknown byte is still refused rather than coerced.
- `determinism`: `Statistical < Reproducible < BitExact`. A job requiring
  `BitExact` cannot be scheduled on a floating-point device.
- `claimed_units_per_sec`: self-declared sustained throughput measured with
  the canonical benchmark kernel (units per second). Spot-checked by receipt
  `elapsed_ms` and challenge re-execution, never trusted outright. Version
  1 profiles decode with 0, which satisfies only jobs that require none.
- `max_units_per_shard` is a device-side cap, independent of the offer's
  per-job cap.
- `kernel` is the declared kernel-set hash; zero means "any kernel". A job that
  names a kernel binds reproducibility to that exact hash.

`DeviceRequirement` matching is fail-closed on capabilities: too little RAM
refuses, throughput below the floor refuses, bandwidth below the floor
refuses, a weaker determinism class refuses and a different kernel refuses.
The class mask rides the wire for compatibility and is ignored.

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
             min_units_per_sec || min_bandwidth_kbps ||     // v2; v1 decodes both as 0
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

## 4b. Pull model: tickets and atomic claims

Planning picks the provider; tickets let the provider pick the work. A
requester posts a signed `ClaimTicket` per shard — job, shard index, units,
price, exact total, capability floors, deadline, nonce, and optionally a
designated provider — on the open board (`POST /v1/compute/tickets`,
`GET /v1/compute/tickets/list`). Any capable provider claims one with a
signed `ShardClaim` (`POST /v1/compute/claims`). The first valid claim wins:
the node's `ClaimBook` inserts atomically and refuses every later claim for
the same ticket by name, even a valid one.

Two signatures authorize the payout, same as the push path: the requester
signs the shard terms (ticket), the provider signs the take (claim).
Settlement (`settle_claim`), escrow release (`release_for_claim`) and
challenges (`open_for_claim`) mirror the assignment path check for check —
binding, price, deadline, once-only — keyed by the claim hash instead of the
assignment hash. Receipts for claims are built with
`ComputeReceipt::for_claim`. Expired tickets prune with their claims: a
claim past its ticket deadline can never settle, so dropping it loses
nothing settleable.

Designated tickets (`provider: Some`) name the winner up front. Only they
can carry a pre-signed payout exit (the destination must be known when the
requester signs); the node stores it and queues it automatically on
settlement. Open tickets settle into the manual claim path with an
auto-built exit template. Settling immediately frees the provider for the
next claim: no cooldown, no one-at-a-time rule, and many live offers can
coexist as long as they fit the provider's capacity.

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
and returns it. The node executes the instruction through the claim path:
the payout binds to a requester-signed L2 exit (`exit-template` then `claim`),
queues with the same admission gate as every other L2 write, and pays the
provider when consensus releases the exit. The crate itself never holds or
moves coin; the node moves it only through signed exits the requester
authorized. Duplicate settlement returns `AlreadySettled`.

`expire` marks an assignment as timed out only after its deadline. Expired
assignments can never settle, so a late receipt cannot resurrect work that was
already rescheduled. `attempt` is capped at `MAX_ATTEMPTS` (3), so a job cannot
be retried forever against the same budget.

### Job escrow

`ComputeLedger` decides whether a receipt may be paid; `escrow::EscrowBook`
decides whether the money is there. A requester signs one `EscrowFunding`
(`job`, `requester`, `amount_sat`, `deadline`, `nonce`) and the book locks that
budget for the job. Each settled receipt then releases exactly its own
`total_sat` from the pot, and after the deadline the unspent remainder is
refunded once.

- a job is funded exactly once, before its deadline, by the requester that
  signs its assignments; a second funding, a foreign network, a stranger's
  signature or a post-deadline funding is refused;
- `release` re-verifies the receipt and assignment, requires the funded job,
  requester and deadline to match, and refuses overclaim, price mismatch, a
  late receipt, a duplicate assignment and any release after a refund;
- the sum of all releases can never exceed the funded amount
  (`BudgetExceeded`), and a refused release consumes neither the assignment nor
  the pot;
- `refund` is only possible after the deadline, only once, and a fully released
  pot refunds zero and still closes so a later release cannot reopen it.

`PayoutInstruction` and `RefundInstruction` are instructions only; this crate
never holds or moves coin.

## 6. Bonds, capacity and reputation

Sybil resistance starts here: identity is still an ordinary SRCT address, but a
capacity claim now costs stake and bad behaviour costs more. A provider joins
with one command — `templates/srct_node.py --auto-capability` measures the box
(RAM + benchmarked throughput) and shells `srct-worker compute-join`, which
stakes the bond and posts the offer. No manual hardware description.

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
  takes 10% of the bond; `Overclaim`, `Impostor` and `WrongResult` (fraud) take
  50% at any height. The same dispute cannot slash twice, the dispute must name the exact
  assignment it slashes, and slashing an unbonded provider is refused.
- **Reputation**: `score = settled_units - 10 * timeouts - 100 * slashes`,
  saturating. `record_settlement` counts a verified receipt's units;
  `record_timeout` counts an assignment that passed its deadline unclaimed.
- **Minimum bond** is 1,000 sat (`MIN_BOND_SAT`): low enough that any
  device joins, high enough to price bond spam. Small bonds still slash
  meaningfully (NoShow 10% = 100 sat, fraud 50% = 500 sat — both non-dust)
  and the −100 score penalty bans on a single fraud.
- **Capacity** (`BondBook::capacity`): open exposure may not exceed
  `bond × 10 + effective_units × 100`. Posting an offer and claiming a
  ticket both check it, so a fresh 1,000-sat bond carries ~10,000 sat of
  open work and only settled receipts raise the limit. Unbonded providers
  have zero capacity: the first offer is refused, not filed.
- **Wash-trade dampening** (`effective_units`): settled volume counts per
  counterparty at its integer square root. Ten jobs with ten different
  requesters earn ~3× the capacity of the same volume with one — including
  yourself. Self-dealing buys sublinear headroom no matter the volume.
- **Admission** (`BondBook::admit_offer`): an offer is schedulable only if it
  verifies, belongs to the book's network, stands behind a bond of at least
  `MIN_BOND_SAT` (1,000 sat) registered before the current height, and its
  provider's score is above `BAN_SCORE` (−100). The node additionally gates
  posting and claiming on capacity (above), which is the live limit;
  admission is the static floor.

Honest limits: the book verifies *who* signed a dispute, not the evidence
behind it (arbitration belongs to the escrow layer); slashes and bonds are
instructions, not coin movement; and a provider that can afford many bonds can
still present many identities.

Node wiring: bonds, reputations and single-use ids persist in `state.bin`
(`BondBook::encode`/`decode`, fail-closed); the offers list reports each
provider's live `bonded` state, bond total and score; settled receipts feed
`record_settlement` automatically, so reputation follows real paid work.

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
  re-execution catches a result that does not reproduce, by comparison, but it
  cannot prove semantic correctness and ZK proofs remain future work.
- **Hardware truth.** RAM, throughput, bandwidth, kernel hash and device class are
  self-declared. They bound assignment, not reality; elapsed times and
  re-execution are the spot-checks, attestation is not claimed.
- **Sybil resistance at the stake layer.** Bonds and reputation gate admission,
  but a slash is only as real as the escrow or payment rail that executes it,
  and dispute evidence is unverified here.
- **Liveness and leasing.** Planning is a pure function of offers, job and
  height. Offer gossip, heartbeats, lease renewal and retry timers are the
  operator's responsibility.
- **Confidential payloads.** `sealed_input` only requires a provider that accepts
  sealed input. Sealing itself is `srct-cnnp`'s envelope, keyed off-protocol.

## 9. Verified behavior

`cargo test -p srct-compute` unit + acceptance suites (device, market,
escrow, settle, bond, challenge, ticket, TEE, journal, gossip):

- capability matching runs on RAM, throughput, bandwidth and determinism;
  class is a display label (a photonic mask still matches a CPU offer);
  v1 wire decodes with zero throughput; v2 throughput validates;
- a small phone takes a small job alone, and takes several 4-unit shards up to
  its 8-unit per-job cap;
- ineligible offers (RAM, throughput, bandwidth, determinism, kernel,
  service, price, sealed input, verification, expired window) are never
  scheduled;
- two-sig tickets post, first claim wins, replays and wrong-provider claims
  refuse, designated tickets enforce the named provider, expired boards
  prune to nothing settleable, ticket escrow releases exactly and only
  when funded;
- bond floor is 1,000 sat; slash math multiplies before dividing so small
  bonds slash for real (NoShow 100, fraud 500 on 1,000);
- capacity starts at bond x 10, grows with dampened settled volume, and
  wash volume with one counterparty earns strictly less than distributed
  volume; v1 bond books still decode;
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
- a fraud dispute halves the bond and subtracts 100 from the score, which
  bans the provider unless settled volume covers the penalty (ban iff
  `settled_units − 10 × timeouts − 100 × slashes ≤ −100`); fraud slashes
  survive re-bonding;
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
- the flow journal appends only verified offers, assignments, receipts, bonds,
  escrow fundings, withdrawals and disputes, snapshots with bounded encoding,
  and restarts by re-verifying every entry — tampering, truncation or a
  foreign-network entry fails the whole replay; an order-preserving rebuild
  replays registrations, releases, slashes and withdrawals to the same bond
  balance, escrow remainder and ledger total, and applying credits before
  disputes would visibly change the penalty; operator-observed timeout counts
  persist through a checkpoint that restores as a floor, never a rewind;
- gossip keeps only signed live offers, dedups, merges order-independently,
  prunes on expiry, refuses forged/foreign/overflowed input, ships as signed
  batches re-verified on decode, and rides the agent transport end to end;
- challenge re-execution clears matching receipts and slashes fabricated ones:
  same result verifies clean, a different result produces a `WrongResult`
  dispute that halves the bond and bans the provider through the existing
  slash path; self-challenges, stranger requesters, duplicate challenges and
  receipts, wrong-worker/late/misbound second receipts and tampered
  challenges are all refused; challenge wire codecs round-trip;
- escrow funds a job once, releases each settled receipt's exact total, refuses
  over-release beyond the pot, duplicate assignments, late/misbound/overclaiming
  receipts and any release after a refund, then refunds the remainder exactly
  once after the deadline; funding wire codecs round-trip and refuse tampering;
- claim-settlement and claim-slash mirror the assignment paths against the
  ticket two-sig binding; challenge opens against settled claims;
- pre-signed exits fire only after a verified receipt settles, queue exactly
  once (second settlement is already_settled; the preauth is consumed on
  first use), and refuse any owner/destination/amount redirect at store time;
- one end-to-end test runs a bonded two-shard job from bond admission and
  funding through settlement, challenge/slash, refund and journal replay;
- node pull-model tests cover many-offers-at-once, zero-capacity refusal,
  first-claim-wins, settle-then-claim-again, and the full preauth
  fire-once/no-redirect lifecycle against real L2 funding.

## 10. Next milestones

1. Capability profiles are self-declared and spot-checked (receipt
    `elapsed_ms`, challenge re-execution); attested hardware measurement is
    future work, not a claim. This crate routes units, nothing more.
2. Challenge re-execution — **done** (`challenge::ChallengeBook` with
   independent re-runs, result comparison and `WrongResult` fraud disputes).
3. Escrow integration — **done** (`escrow::EscrowBook`: fund once, release per
   settled receipt, refund the remainder at the deadline). Executing bond
   registrations, slashes and withdrawals on the same rail is still the
   payment layer's job.
4. Persistent bond/reputation snapshots — **done**: bond registrations,
   escrow fundings, withdrawals and disputes journal and rebuild in order,
   and operator-observed timeout counts persist through a
   `TimeoutCheckpoint` that restores as a floor (never rewinds observed
   timeouts).
5. Gossip transport binding — **seam done** (`encode_batch`/`decode_batch`:
   signed batch wire format, every offer re-verified on decode; the agent
   `LoopbackTransport` round-trip is pinned by test). Live P2P/HTTP/MCP
   rails and peer scoring stay the operator's job.
