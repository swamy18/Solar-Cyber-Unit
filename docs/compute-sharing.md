# Decentralized compute sharing

Status: **production money loop** with core in `crates/srct-compute` and endpoints in `crates/srct-node`. Any device advertises capability (RAM, measured throughput, bandwidth, determinism) behind a signed bond, requesters shard work across devices, and verified receipts settle completed units — via planned assignments or the open ticket board. Offers, jobs, assignments, tickets, claims, receipts, payouts, preauth exits, escrow and bond books, challenges, usage records, the metering ledger, and provider attestation records persist in `state.bin` (envelope v18; v8–v17 migrate).

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
- metering: `GET /v1/compute/ledger?from=&to=` (node-local usage ledger,
  indexed by slice end height)
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

## 2. Device profile and backend registry

```
DeviceProfile = version || class || backend || determinism || ram_mib || cores ||
                max_units_per_shard || bandwidth_kbps ||
                claimed_units_per_sec || kernel(32)   // v3; v2 lacks backend,
                                                      // v1 lacks backend+throughput
profile_hash = SHA256("srct/compute/device-profile/v1" || encode)
```

- `class`: CPU, GPU, TPU, NPU, Apple silicon, photonic. **Display label
  only.** Matching never consults it. An unknown class byte is still
  refused rather than coerced; an unknown *backend id* is accepted as
  generic (labels behave differently by design — see below).
- `backend`: open vendor/arch identifier (e.g. `"cpu/x86_64"`,
  `"apple/silicon"`, `"mobile/snapdragon-x"`), v3 on the wire (≤128 bytes,
  `[A-Za-z0-9/_.-]`). Unknown ids are accepted as `"generic"` and matched
  purely on capabilities — a new hardware family joins with no protocol
  change. Versions 1 and 2 still decode, with the legacy class mapping
  (`cpu/generic`, `gpu/generic`, `tpu/generic`, `npu/generic`,
  `apple/silicon`, `photonic/generic`) in place of the field.
- `determinism`: `Statistical < Reproducible < BitExact`. A job requiring
  `BitExact` cannot be scheduled on a floating-point device.
- `claimed_units_per_sec`: self-declared sustained throughput measured with
  the canonical benchmark kernel (units per second). Spot-checked by receipt
  `elapsed_ms` and challenge re-execution, never trusted outright. Versions
  1 and 2 decode as before (v1 throughput 0, satisfying only jobs that
  require none); v3 validates the backend id alongside throughput.
- `max_units_per_shard` is a device-side cap, independent of the offer's
  per-job cap.
- `kernel` is the declared kernel-set hash; zero means "any kernel". A job that
  names a kernel binds reproducibility to that exact hash.

`DeviceRequirement` matching is fail-closed on capabilities: too little RAM
refuses, throughput below the floor refuses, bandwidth below the floor
refuses, a weaker determinism class refuses and a different kernel refuses.
The class mask rides the wire for compatibility and is ignored; the backend
id is likewise not consulted — capability floors are the whole gate.

### Backend plugin interface (prototype)

Vendors (mobile, Apple NPU, discrete GPU, other accelerators) plug an
executor in without protocol changes through the `ComputeBackend` Rust
trait (`backend_id`, `describe`, `execute`) and the `register_backend`
hook in `templates/srct_node.py`. The `BackendRegistry` advertises known
ids; unknown ids stay unknown and match on capabilities only.

Shipped with working execution code: `CpuBackend` (`"cpu/generic"`,
deterministic mixing loop) and `LoopbackBackend` (`"ref/loopback"`,
deterministic hash chain — labelled as a reference, not a performance
claim). GPU/NPU support is **not** claimed: no `cuda/*`, `metal/*`,
`rocm/*` or NPU backend ships, and the template refuses to run a workload
on a named backend with no registered executor. A label without a working
executor is interface-only, never support.

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
function using max-min fair allocation (water-filling) across provider
identities:

1. verify the job and every offer; drop any offer that fails;
2. keep offers on the same network and service, inside their availability
   window, at or below the price cap, at or above the verification floor, with a
   privacy mode that matches `sealed_input`, and with a device profile that meets
   every hard requirement;
3. group eligible offers by provider identity; each provider's capacity is the
   sum of its offers' per-job caps;
4. water-fill: every active provider receives an equal share of the remaining
   units, capped at its remaining capacity; providers that hit capacity drop
   out and the remainder is redistributed; a sub-unit remainder is handed out
   one unit at a time. Price only breaks ties (shard order) and enforces the
   price cap — it never sizes a provider's share;
5. turn each provider's allocation into shards, drawing from its offers in
   price order, skipping any shard below `min_units`; a remainder that cannot
   form a valid shard is redistributed to providers with remaining capacity;
6. refuse when no candidate exists, capacity cannot cover every unit, the shard
   cap is exceeded, or the fair plan exceeds `max_total_sat`.

Fairness is per identity: a provider with 100 machines gets no more than its
equal share. Sybil resistance comes from the bond floor and the capacity rule
(`bond × 10 + dampened settled volume × 100`), not from allocation.

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
plan: 30 units in 5 shards for 284 sat
  shard 0: 11 units -> desktop   at  7 sat/unit
  shard 1:  4 units -> phone     at 10 sat/unit
  shard 2:  4 units -> phone     at 10 sat/unit
  shard 3: 10 units -> laptop    at 12 sat/unit
  shard 4:  1 unit  -> desktop   at  7 sat/unit
```

Desktop, phone and laptop each receive their equal share first (10 units);
the phone caps at 8, so its overflow redistributes. The laptop's 10-unit
per-shard cap means its 11-unit share lands as one 10-unit shard; the
unshardable unit redistributes to the next provider with room. Price only
ordered the shards — it never let the cheapest box take the whole job.

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

### Demand broadcast

A ticket posted on any node is gossiped over `srct-net` to all connected
nodes (`Message::Ticket`, type 14 — additive per the frozen-type rule, so
older nodes ignore it). Each relay re-verifies the requester's signature
and only forwards what its own node accepts; the flood gate
(`allow_control_from`) rate-limits control traffic per peer. The
`TicketGossipSet` keeps signed live tickets with TTL (the ticket deadline),
dedup, signature verification, per-peer insertion rate limits and a size
bound — the same rules as offer gossip, which stays transport-agnostic.

A provider node whose template limits and capabilities fit auto-claims
received tickets through the existing atomic claim path
(`try_auto_claim_ticket`): the node's provider wallet signs a `ShardClaim`,
capacity is checked, and the first valid claim wins — so no double claim
can succeed even when two providers race for the same ticket. Auto-claim is
ON when the provider template (wallet + matching offer) is active, OFF for
a bare node with no provider wallet.

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

It records a `PayoutInstruction { from, to, amount_sat, job, assignment, receipt, payable_at }`
and returns it. The node executes the instruction through the claim path:
the payout binds to a requester-signed L2 exit (`exit-template` then `claim`),
queues with the same admission gate as every other L2 write, and pays the
provider when consensus releases the exit. The crate itself never holds or
moves coin; the node moves it only through signed exits the requester
authorized. Duplicate settlement returns `AlreadySettled`.

### Delayed scheduled payout

Escrow releases each slice's payment only after `payout_delay_blocks` from
the slice's end (`payable_at = settle_height + delay`): mainnet 2 blocks
(~20 minutes at 10-minute blocks), testnet/mini 180 blocks. Release happens
automatically at the scheduled height — each serve-loop tick runs
`process_due_compute_payouts`, which binds stored pre-signed exits for due
slices and marks them paid. The consumer is charged per slice actually
consumed; unused escrow is refunded after the deadline. During the delay
window a slice can be disputed: a held (disputed or slashed) slice never
pays out, and its funds return to the pot, increasing the refundable
remainder. No payout happens before the delay, and the delay is a
per-network profile parameter, not a consensus rule.

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

### Metering: slices, usage records and the node-local ledger

Result correctness is **not** a goal. What the market verifies is metered
consumption: capacity delivered and used.

A *compute slice* is a fixed amount of units per fixed number of chain
blocks: 100 units per 1 block on mainnet, per 10 blocks on testnet/mini.
Per slice, both provider and consumer sign a `UsageRecord` (ticket,
provider, units, height range). A mismatch between the two sides' records
opens a dispute through the existing bond/challenge path.

Each node keeps a local ledger indexed by chain height — where compute came
from, how much each provider supplied, where it went — exposed at
`GET /v1/compute/ledger?from=&to=` and persisted in `state.bin` with a
fail-closed decode. There is **no** consensus change and no shared state
machine: every node tracks its own view. A consensus commitment (ledger
root) is a proposal only, not implemented.

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

## 7b. Provider template: percentage caps, hard limits, session sandbox

`templates/srct_node.py` resolves `--ram-pct`, `--cpu-pct`,
`--compute-pct` (optionally `--gpu-pct`) to absolute caps at start-up from
detected hardware (RAM, core count, measured benchmark, discovered GPU).
Percentages outside 0–100 refuse; a missing required flag refuses.

`enforce_limits()` applies hard OS-level limits, never to be exceeded:

- Linux: cgroups v2 (`memory.max` + `cpu.max`);
- Windows: Job Objects (memory limit + CPU hard-cap rate);
- anything else (or missing privilege): **refuses to start** unless
  `--best-effort` is passed, which runs in a clearly labelled BEST-EFFORT
  mode (in-process `ResourceGuard` only — token bucket + RAM ceilings).

The active mode prints at start-up and is covered by `--selftest`, which
reports the per-platform matrix (this repo's CI box: Windows enforces via
Job Objects; Linux needs the memory and cpu controllers plus write
access; macOS/others are best-effort only). A job that would exceed the
resolved caps is refused before admission — verified by selftest.

The backend registry hook (`register_backend` / `execute_with_backend`)
lets vendors plug executors in without protocol changes; `"cpu/generic"`
is pre-registered. Auto-capability (`--auto-capability`) reports the
detected `backend_id` and passes `--backend` to `compute-join`.

Each ticket runs in a `SessionSandbox`: workload artifacts stage into a
private temp dir for the session and are shredded at session end — success,
refusal or exception. See §8: this is lifecycle, not live-run
confidentiality.

## 8. What is not enforced

- **Correctness.** A receipt proves who claims units, a usage record proves
  how many were delivered and used, and a TEE quote proves approved
  execution — none proves the output is correct. `Challenge` re-execution
  catches a result that does not reproduce, by comparison, but it cannot
  prove semantic correctness and ZK proofs remain future work.
- **Hardware truth.** RAM, throughput, bandwidth, kernel hash, device class
  and backend id are self-declared. They bound assignment, not reality;
  elapsed times and re-execution are the spot-checks, attestation is not
  claimed. Unknown backend ids are accepted as generic: matching runs on
  capabilities, so an unknown id neither helps nor hurts a provider.
- **Workload confidentiality.** Say it plainly: **the provider can see the
  workload while it runs** — code, weights and data execute in the
  provider's process memory — unless sealed input or a TEE is used. The
  consumer keeps code, weights and data under its own control; the
  template stages them into the provider's sandbox only for the session
  and deletes them at session end (success, refusal or exception). That is
  a lifecycle guarantee, not confidentiality of a live run.
- **Sybil resistance at the stake layer.** Bonds and reputation gate admission,
  but a slash is only as real as the escrow or payment rail that executes it,
  and dispute evidence is unverified here. Fair allocation is per identity:
  nothing stops one operator running many bonded identities.
- **Liveness and leasing.** Planning is a pure function of offers, job and
  height. Heartbeats, lease renewal and retry timers are the operator's
  responsibility. Ticket gossip carries demand; offer gossip stays
  transport-agnostic.
- **Confidential payloads.** `sealed_input` only requires a provider that accepts
  sealed input. Sealing itself is `srct-cnnp`'s envelope, keyed off-protocol.
- **Ledger consensus.** The metering ledger is node-local and observational.
  No ledger root is committed to consensus; the commitment is a proposal
  only.

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
- the fair plan splits a 30-unit job across three providers as equal shares
  capped by capacity (desktop 12, phone 8, laptop 10), redistributes capped
  and unshardable remainders, prices only the shards, stays inside the
  budget, and reproduces exactly with the offer list reversed;
- a large provider and a small provider both receive shares; a provider with
  many offers (many "machines") gets no more than its single equal share;
  a capped provider's overflow redistributes; over-cap prices are excluded;
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
- payouts carry `payable_at`: nothing is due before
  `settle_height + payout_delay_blocks` (mainnet 2, testnet/mini 180),
  due slices release automatically at the height, a held (disputed) slice
  never pays and its funds return to the pot, unused escrow refunds after
  the deadline, and a zero delay stays immediately payable;
- usage records hash deterministically, slice windows follow the network
  slice length (1 block mainnet, 10 testnet/mini), the node-local ledger
  records and queries by height range, round-trips through `state.bin`,
  and refuses tampered, truncated and wrong-version blobs;
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
- ticket gossip (`TicketGossipSet`) keeps only signed live tickets, dedups,
  rate-limits per peer, merges order-independently, prunes on expiry and
  ships as signed batches; a ticket announced on one of three real-TCP
  nodes reaches all three with its signature intact, and when two holders
  race to claim, the first valid claim wins and the second is refused;
- device v3 profiles round-trip with backend ids, v1/v2 still decode with
  the legacy backend mapping, unknown backends match purely on capabilities,
  over-long and non-identifier backend ids refuse, and the CPU and loopback
  reference backends execute deterministically (GPU/NPU ids stay unclaimed);
- template `--selftest` pins percentage-cap resolution, over-limit refusal,
  strict-vs-best-effort enforcement, the backend plugin hook (register,
  execute, refuse-unclaimed), and session-sandbox deletion on success and
  on handler failure;

## 11. Confidential Tier — threat model and plan (simulator-tested only)

A consumer's data, model and keys stay under the consumer's control. The
compute provider must never see plaintext or hold any key. This covers
inference and training, is directly deployable with production-proven
technology, and uses no research approaches. **Nothing in this section is
validated on real hardware.** Every behaviour below is simulator-tested
only until the hardware-gated runs (TDX, SEV-SNP, NVIDIA CC hosts) pass;
the runbook for those runs is a deliverable of the later phases.

### Threat model (read first)

**Intended protection, conditional on real hardware and integration:**
- a malicious provider process (the guest/key-release design keeps plaintext
  in the approved guest image);
- the provider's OS and hypervisor admin (memory encryption and attested
  measurements);
- other tenants on the same machine (per-job keys);
- passive network observers (encrypted bundles and channel traffic).

These guarantees are architectural goals, not measured hardware assurances.
The current implementation is simulator-tested; production guest isolation
and an attested TLS transport are not established by that test coverage.

**NOT protected against — stated plainly, no unconditional privacy claimed:**
- hardware vendor compromise (Intel/AMD/NVIDIA roots are trust anchors;
  a compromised root breaks everything below it);
- microarchitectural side channels (cache, timing, power — no
  constant-time claim is made on ML kernels);
- denial of service (a malicious host can always refuse to compute);
- traffic metadata (message sizes, timing and endpoints are visible).

**Normal (non-TEE) providers keep working** but only get non-sensitive
jobs, labelled non-confidential at match time. The existing `privacy`
(sealed-input) flag is a delivery hint and **must never authorize a
confidential job** — only a verified attestation matching the job SLA
does. One test pins exactly this.

### 1. Confidential provider foundations (implemented; hardware integration pending)

- Confidential VMs: Intel TDX and AMD SEV-SNP, plus NVIDIA
  confidential-computing GPUs (H100/H200/Blackwell) with CC mode on. No
  SGX for ML workloads.
- Guest, inference and training helper modules and attestation-aware job
  fields exist. A production measured guest image and host isolation have not
  been demonstrated; the provider-visible workload caveat still applies.
- The node accepts provider-signed evidence and persists it. Evidence
  registration is node-local and does not itself make marketplace admission
  or execution confidential.

### 2. Remote attestation (implemented, simulator-tested only)

- Vendor evidence (`srct-compute/src/vendor.rs`): parsed Intel TDX DCAP
  quotes (v4 layout: 48-byte header, 584-byte TD body, 384-byte QE
  report, QE signature, auth data, concatenated DER PCK chain, plus a
  65-byte attestation-pubkey trailer that makes the QE binding checkable),
  AMD SEV-SNP reports (ABI offsets, 1184-byte report + 512-byte
  signature), NVIDIA JWT reports (ES256 over `header_b64.payload_b64`,
  claims-checked). All parsers are fail-closed and fuzzed
  (`tdx_quote_parse`, `snp_report_parse`, `nvidia_report_parse`,
  `vendor_chain_parse`).
- Chain verification with `p256` + `p384` + `x509-parser` (kept out of
  `srct-core`): exact-TBS DER splitting (no re-encoding), DN chaining,
  validity windows, CRL serials, pinned root SPKI hashes. P-384 covers AMD
  VCEK/VLEK chains and SNP report signatures; `TeeError::UnsupportedCurve`
  remains as the fail-closed path for any future family needing an
  unapproved curve.
- Policy checks: debug off unless the SLA explicitly opts in (setter and
  attester must agree — a mismatched quote header is a lying attester),
  TCB minimums per family, approved-measurement allowlist (TDX: mr_td +
  RTMRs; SNP: measurement; NVIDIA: sorted claims), nonce freshness, replay
  protection, expiry, revocation. The enclave's ephemeral public key is
  bound into `report_data` (`SHA256(pubkey || nonce_le)`); any mismatch
  returns `BadReportData` and the data key is never released.
- `TeeType::NvidiaCc` added; `TEE_VERSION` 2 with v1 still decoding
  (v1 SLA/quote paths unchanged). `TeeVerifier::verify_v2` runs the full
  confidential path; plain `verify` on a v2 quote fails closed. Software
  evidence is refused on mainnet in both paths, even when asked for.
- `srct-verify` routes new `Evidence::TeeV2` (mapped to `EvidenceKind::Tee`);
  `srct-l2/tee_evidence` decodes v1 and v2 but stays signature-check-only
  and out of `apply()` — no consensus change.
- Not done here: RIM/KDS/PCS fetchers (node-side, later phase),
  hardware-gated runs (runbook pending).

### 3. Key management (implemented, simulator-tested only)

- Per-job random data key (XChaCha20-Poly1305; AES-256-GCM also permitted
  by the format).
- Key release: the consumer verifies the attestation, then wraps the data
  key to the enclave's ephemeral public key with HPKE (RFC 9180,
  X25519, HKDF-SHA256, ChaCha20-Poly1305). **If attestation fails, the key
  is never sent** — pinned by negative tests for tampered quotes, wrong
  measurements, stale/replayed quotes, debug-enabled guests, revoked
  attesters and `report_data` mismatches.
- Separate result key and checkpoint key. Short TTL, rotation,
  revocation, zeroization after the session. No key material in logs,
  errors or crash dumps.
- Pluggable KMS adapter: local encrypted keystore by default (same format
  as `wallets.json`: Argon2id + ChaCha20-Poly1305, `0600`, atomic write);
  HashiCorp Vault and cloud KMS as trait stubs + docs only.
- New consumer-side crate `srct-confid` with its own CLI (`srct-confid`):
  keystore init/list/revoke, key wrap/open, and attestation-gated release.
  Key-release code never links into the provider-side `srct-worker`.

### 4. Shield bundle (implemented format and helpers; end-to-end deployment pending)

- Versioned shield bundle: manifest plus AEAD-encrypted chunks with unique
  nonces, integrity chain or Merkle tree, bound to job id, ticket and the
  approved measurement; streaming support for large datasets.
- Model weights encrypted the same way, or a public model pre-installed
  inside the measured image and referenced by service name.
- Consumer-to-enclave channel uses attested TLS. Results and checkpoints
  are encrypted to the consumer's key before they leave the enclave.
- The bundle parser has a fuzz target (`shield_bundle_parse`) in the current
  26-target inventory.

### 5. Guest runtime and attested metering (helpers implemented; production isolation pending)

- Runtime helpers encode the intended no-network, no-plaintext-persistence,
  wipe-on-exit lifecycle, and resource limits are applied by the host
  executor. Hardware-enforced isolation has not been verified.
- Attestation and key-release helpers exist, but a real enclave session
  lifecycle is not yet demonstrated end to end.
- The ordinary signed usage ledger exists; enclave-signed usage metering has
  not been shown on hardware.

### 6. Matching and policy (implemented with simulator evidence)

- Jobs declare a confidentiality level (new `ComputeJob` field:
  `JOB_VERSION` 2 → 3; v1/v2 decode as non-confidential). The planner
  only considers providers with a valid, fresh attestation matching the
  job SLA, then applies the existing fair allocation.
- Attestation expiry, freshness and revocation checks are implemented in the
  evidence-verification path. Session-level re-attestation on real hardware
  remains unverified. Bond, capacity and reputation rules are unchanged.

### 7. Inference helpers (implemented; confidential deployment pending)

- Interactive and batch inference inside attested enclaves with encrypted
  request/response streams. Batching, timeouts, and graceful failure
  (no plaintext fallback, ever).

### 8. Training helpers (implemented; confidential deployment pending)

- The repository has training helpers, including local CPU execution; the
  following production confidential workloads remain unverified:
- (a) Training and fine-tuning (including LoRA) on one provider's
  confidential GPU(s), with multi-GPU data parallelism inside that
  single machine.
- (b) Many independent parallel jobs (hyperparameter sweeps, per-dataset
  fine-tunes), each in its own attested enclave.
- (c) Encrypted checkpoints every N steps, resume after preemption or
  failure, and migration to another attested provider using the
  consumer's key.
- Out of scope this round, documented here and in code: synchronous
  training of one model across independent providers, split learning,
  MPC, FHE, DiLoCo-style methods.

### 9. Current integration boundary

- Consumer-side component: `srct-confid` CLI (job submit not yet wired to
  node endpoints; attestation verification, key broker, bundle creation,
  result decryption available as library + CLI). Key-release code never
  links into `srct-worker`.
- Node endpoints for attestation evidence submission and verification are
  implemented: `POST /v1/compute/attest/submit` verifies and persists a
  provider quote, and `POST /v1/compute/attest/verify` reports whether a
  provider has a fresh matching record. The v18 `state.bin` section is
  fail-closed and migrates v8–v17. These records are node-local; they do not
  change consensus.

### Validation gates (what counts as done)

- Simulator end-to-end tests for the full flow.
- Negative tests: tampered quote, wrong measurement, stale or replayed
  quote, debug-enabled guest, revoked attester, mismatched `report_data`
  — the key must never be released in any of these.
- Fuzz tests for bundle and quote parsing; hardware-gated tests behind
  an env var with a runbook for real TDX, SEV-SNP and NVIDIA CC hosts.
- No path is called "production-ready" until it has passed on real
  hardware. Until then, every confidential claim is labelled
  **simulator-tested only**.
- All existing tests (wash-trading, capacity, fairness) keep passing.
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
6. Fair, metered, continuously-running market — **done**: max-min fair
   allocation across provider identities (price only breaks ties); delayed
   scheduled payout (`payable_at`, per-network delay, auto-release tick,
   dispute hold, refund of unused escrow); node-local metering ledger
   (slices, dual-signed usage records, `GET /v1/compute/ledger`,
   `state.bin` v18); demand broadcast over `srct-net` (ticket gossip +
   capability/capacity-gated auto-claim); percentage template caps with
   hard OS enforcement; extensible backend registry (CPU + loopback
   reference backends, GPU/NPU interface-only); session sandbox with the
   provider-visibility caveat stated plainly.
7. Confidential tier — **in progress, simulator-tested only** (see §11):
   TDX/SEV-SNP/NVIDIA-CC providers, vendor attestation verification,
   consumer-side key broker with HPKE key release, shield bundle, attested
   metering, confidential matching. Nothing here is validated on real
   hardware; every claim below is marked simulator-only until the
   hardware-gated runs pass.
