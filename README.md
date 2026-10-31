# Solar Cyber Unit (SRCT)

<img src="Solar_Cyber_unit.png" alt="Solar Cyber Unit coin logo" width="200">

Programmable money for machines: spend policies enforced at admission, escrow for verifiable work, micro-payments with a safety-first wallet. Pre-launch — no outside audit yet.

**Author and copyright:** The project is open source — see [License](#license).

**Built by:** Swamy Gadila. The project is open for anyone to use
and redistribute.

---

## Contents

- [What this is](#what-this-is)
- [The four pieces](#the-four-pieces)
- [Why a new coin](#why-a-new-coin)
- [Glossary](#glossary)
- [Honest limits](#honest-limits)
- [Quick start](#quick-start)
- [Machines and agents](#machines-and-agents)
  - [Portable policy interface](docs/portable-policy.md)
- [Mining](#mining)
- [Supply](#supply)
- [What the chain is for](#what-the-chain-is-for)
- [Use cases](#use-cases)
- [Agent payments (x402)](#agent-payments-x402)
- [Micro-payments and wallet safety](#micro-payments-and-wallet-safety)
- [Agent economy](#agent-economy)
- [How fraud is detected](#how-fraud-is-detected)
- [How withdrawals work](#how-withdrawals-work)
- [Validators and finality](#validators-and-finality)
- [Credit and lending](#credit-and-lending)
- [Repository layout](#repository-layout)
- [Network profiles](#network-profiles)
- [Commands](#commands)
- [Testing](#testing)
- [License](#license)
- [Security](#security)

---

## What this is

The product is the policy engine; SRCT is its reference chain. A spend
policy answers exactly one question — *may this agent, at this height,
spend this much to this recipient?* — and the chain enforces the answer at
admission the way it refuses a double-spend: no policy-aware base layer, no
guarantee. The same engine decides identically anywhere: the grant travels
as a signed portable format any rail verifies, and `srct-policy` (plus
`POST /v1/policy/decide`) gives the same allow / deny / approval-needed off
chain as on it. A decision is not a settlement — spending SRCT still
requires SRCT admission. Start at [Machines and agents](#machines-and-agents).

Mining keeps the principle every blockchain shares — *solving is hard,
verifying is easy* — and changes the work. It runs three stages
(`hybrid-v1`, `puzzle_id = 1`, the active mining puzzle on every profile):
a SHA-256 hash chain (carries the security), an integer-only
neural-network-shaped stage (epoch-derived weights, no training and no
inference — what it buys is hardware diversity, not AI output), and a final
hash binding both into the value that must fall below the target. Capped
share (30–50% of modelled work) and no floating point anywhere keep the
neural stage a cost model rather than a liability. Full detail:
[Mining](#mining).

---

## The four pieces

SRCT is one coin doing four jobs. Each job is a separate layer — you can
use one without the others — but they settle in the same coin.

### 1. Native cryptocurrency

SRCT itself is an ordinary mined coin on a UTXO chain (Layer 1). Wallets,
transfers, blocks and P2P work like any Bitcoin-shaped chain: 1 SRCT =
100,000,000 sats, integer-only accounting, no floats anywhere. New coins
come only from mining (`hybrid-v1` proof of work); genesis minted nothing,
so the premine is 0%. There is no stock cap — a halving ladder issues
39,157,124 SRCT, then a small tail emission pays miners forever. Every
block's base fee splits 50/50 into a burn and the on-chain PSCB reserve,
so usage removes supply from the spendable set. Full detail:
[Supply](#supply), [Mining](#mining).

### 2. AI agent authorization

An owner writes a spending policy once — per-transaction cap, tumbling
window cap, named recipients, named services, validity heights, a strictly
increasing nonce — and signs it offline. From then on every spend by that
agent is checked against the policy at admission, the same way the chain
refuses a double-spend: a violating payment never enters a block, even
with the owner offline. A signed policy travels as a portable grant any
rail can verify without a node, delegations chain root-first with a
narrowing rule, and short-lived grants bind one exact transaction with a
30-block lifetime. The `srct-policy` crate (plus `POST /v1/policy/decide`
and the TypeScript/Python bindings) answers allow / deny /
approval-needed identically on every rail. Full detail:
[Machines and agents](#machines-and-agents),
[`docs/portable-policy.md`](docs/portable-policy.md).

### 3. Machine payments

Per-call billing without a transaction per call. Agents pay over the x402
challenge/response shape (`402 Payment Required` → `PAYMENT-SIGNATURE` →
`200` with receipt), batched quotes merge N payments into one transaction,
stream channels settle a whole usage window once, and sponsors can cover
fees without minting authority. None of this changes consensus — every
primitive reuses ordinary `MachinePayment`s under a spend policy — and the
wallet around them is gated by construction: session budgets, enforced
high-value human approval, idempotency, receipts with reconciliation, and
a hash-chained audit log. Full detail:
[Agent payments (x402)](#agent-payments-x402),
[Micro-payments and wallet safety](#micro-payments-and-wallet-safety).

### 4. Verifiable task economy

Layer 2 is where compute gets paid for without trusting either side. A
submitter locks escrow for a described task, a worker claims it and submits
a result hash, anyone may challenge with a counter-result, and a committee
settles: correct work is paid, fakes are slashed (half burned, half vested),
the challenger earns a bounty. Fraud is decided by a canonical CPU
reference over the task's own committed fields — nobody can dictate the
verdict, and an inconclusive arbitration settles nothing. Settled work
yields a verified-work certificate, and value exits back to Layer 1 through
a queue, maturity and a permissionless crank. Full detail:
[What the chain is for](#what-the-chain-is-for),
[How fraud is detected](#how-fraud-is-detected),
[How withdrawals work](#how-withdrawals-work).

---

## Why a new coin

The honest question: x402 payments, spend policies and escrow could live on an
existing chain or on stablecoin rails. Three reasons they don't here:

1. **Policies are enforced at admission, by consensus — on SRCT, the
   reference chain.** A spend policy on another chain is a contract the base
   layer does not know about — it can advise, not refuse. Here `check_tx`
   refuses a payment that violates its policy the same way it refuses a
   double-spend. The *decisions* travel: portable grants, the `srct-policy`
   engine and `POST /v1/policy/decide` let any rail ask the same question —
   but spending SRCT still requires SRCT admission. No policy-aware base
   layer, no guarantee.
2. **The task economy settles in the native coin.** Escrow, slashing, bonds and
   fee burns are chain state, not contract balances — a dispute payout cannot
   be frozen by a token issuer and does not depend on a bridge.
3. **One fee market, one audit trail.** Batch quotes, streams, receipts and
   reconciliation all price in the same unit the miners are paid in, so the
   cost model in [`docs/micropayments.md`](docs/micropayments.md) is exact
   rather than an oracle away from exact.

The trade is stated openly: a new chain must earn its security and its
liquidity from zero, and nothing here removes that cost.

---

## Glossary

Every piece of jargon, in one line each:

| Term | What it is |
|---|---|
| `PSCB` | Protocol-owned reserve: half of every fee accrues to it instead of the miner; it pays whistleblower bounties and vesting. |
| `VWC` | Verified-work certificate: a credential derived from a *settled* task — proof work was paid for, never a self-claim. |
| `TopN` | Committee rule: the N largest bonds form the validator set (N = 21). |
| `PPLNS` | Pool payout rule: pay per last N shares — rewards recent work, resists pool-hopping. |
| `VWB` / escrow | The locked funds behind a task or trade, released only by the rules both sides agreed to. |
| `sats` | Smallest unit: 1 SRCT = 100,000,000 sats. Integer-only accounting, no floats. |
| `state.bin` | One node's local books (payments, jobs, reputation…). Restarts survive; other nodes may disagree — see [Honest limits](#honest-limits). |
| `mini` / `testnet` / `mainnet` | Network profiles: same code, different parameters (fast local testing → real deployment). |

---

## Honest limits

What this project is not, and where trust actually lives. Read this before
trusting any number in it:

- **No outside audit.** Every test, red-team suite, simulation and the Python
  reference implementation were written and run by the author. Counts are
  real (`scripts/test_count.sh` reproduces them) but self-reported — treat
  them as diligence, not certification.
- **Verification is optimistic.** A submitted result settles as-is if nobody
  disputes it within the window — including a wrong one
  (`srct-l2/tests/unverified_result.rs` pins this rule). The dispute path
  re-executes and slashes fakes, but only if a challenger shows up. Running
  challengers is part of operating this network, not an optional extra.
- **Mining does not train AI.** The neural stage is ML-shaped integer work
  with epoch-derived weights — it keeps AI hardware competitive, it does not
  produce models or inference (see [What this is](#what-this-is)).
- **Reputation, jobs, FX and ramps are per-node views.** They live in each
  node's `state.bin`, not in consensus — two honest nodes can disagree on a
  score, a quote or a job state. Consensus money (UTXOs, bonds, L2 accounts)
  cannot disagree. Never treat another node's score or quote as fact; run
  your own node.
- **FX issuers and ramp providers are trusted.** Rates come from a configured
  whitelist, custody never touches the node — the chain stores the signed
  audit trail, not the dollars. If an issuer lies, the trail proves it; it
  does not prevent it.
- **Mainnet cold start is public.** The 21 bootstrap keys are deterministic in
  source — anyone can sign alongside a bootstrap validator until the first
  bond rotates authority. Serving mainnet with them requires the explicit
  `--allow-bootstrap-committee` flag, and replacing them with bonded keys is
  the operator's first job.
- **Bindings need a node.** The TypeScript/Python bindings are codecs, not
  verifiers — allow/deny answers come from a node (`/v1/policy/decide` and
  friends) or the Rust engine, never from the binding alone. No node, no
  decisions.
- **`srct-policy` is a facade, not a slim dependency.** Vendoring the crate
  still compiles all of `srct-core` (BLS, ML-DSA and all) — see the weight
  note in the crate docs. Outsiders wanting answers without Rust use HTTP
  or the bindings against a node URL.
- **The exit window is shared, and one share is capped.** Mainnet lets one
  owner queue 100 SRCT per 144-block window: a genuinely large exit waits
  across windows. Refusals delay, never destroy — but plan around it.

---

## Quick start

Requires **Rust 1.75+** (developed and tested against 1.99) and **Python 3.11+**
for the simulations.

```sh
git clone https://github.com/swamy18/Solar-Cyber-Unit.git
cd Solar-Cyber-Unit
cargo build --release
```

```sh
# Wallet keys are encrypted at rest: set a passphrase for this shell, or add
# --allow-plaintext-wallet to init if you deliberately want a plaintext file.
export SRCT_WALLET_PASSPHRASE=change-me

# Create a chain directory and a miner wallet.
./target/release/srct-node init   --network testnet --data-dir ./chain

# Mine blocks, then check the chain agrees with itself.
./target/release/srct-node mine   --network testnet --data-dir ./chain --blocks 25
./target/release/srct-node status --network testnet --data-dir ./chain
./target/release/srct-node verify --network testnet --data-dir ./chain

# Run a P2P node. It mines by default, so it settles matured exits.
./target/release/srct-node serve  --network testnet --data-dir ./chain \
                                  --listen 127.0.0.1:9833
```

`verify` replays the whole chain from genesis and diffs the resulting UTXO set,
supply, bond ledger and binding-finalized point against stored state. It is the
check worth running after any change.

Ask the engine before you spend — no wallet, no chain state needed:

```sh
# Offline: the codec self-test (intents, decisions, document shapes).
python sim/policy_decide_demo.py --self-test

# Against a node (serve with --api-listen first; policy.json via MCP policy.export).
python sim/policy_decide_demo.py --node http://127.0.0.1:8080 --policy policy.json \
  --agent-id <hex> --recipient <hex> --amount-sat 400 --threshold-sat 100
# → decision: allow | needs_approval | deny (with reason)
```

Run `srct-node help` for the full command list; every command accepts `--help`.

To stand up a local multi-node network (deterministic genesis, separate data
dirs, node 1 as seed, the rest dialing it via `--bootnodes`):

```sh
scripts/start-network --nodes 3          # init, serve, wait until all share a tip
scripts/stop-network                     # graceful stop via pid files
scripts/reset-network                    # stop and delete the data root
```

---

## Machines and agents

There is a full policy layer for software acting on someone's behalf. It lives in
`srct-core/src/agent.rs` and is **pure and deterministic** — no clock, no
randomness, no I/O — so a wallet and a service reaching the same inputs reach the
same answer.

**Agent identity.** `derive_agent_id(network_id, role, owner)` gives a stable
identifier for an actor. Three roles exist: `Human` (a wallet), `Machine` (a
device spending under a policy), and `Service` (an identity that *receives*
payments). The ID is network-bound, so the same device has different IDs on
different chains.

**Spending policies.** A `SpendPolicy` is owner-signed and answers exactly one
question: *may this agent, at this height, spend this much to this recipient?*
Every refusal is a named error, and the ambiguous cases all fail closed:

- **an empty recipient list** authorizes nothing — not "anything";
- **an empty service list** authorizes no service-tagged payment;
- **a nonce must strictly increase**, so an authorization cannot be replayed;
- a height below the policy's own window start refuses — time does not run
  backwards inside a policy;
- cumulative spend is bounded **per window**, and the window rolls over rather
  than accumulating forever.

**No second currency.** The `owner` field is an ordinary address, so machine and
human balances live in the same UTXO set under the same issuance schedule. There
is no separate "machine token".

**Portable grants.** A `SignedPolicy` is the policy plus the owner's signature
over it — the unit that travels. Anyone holding the bytes (another chain, an
x402 facilitator on Base, an insurer's auditor) verifies the grant with no
node, no chain state and no private key. A `DelegationProof` is the root-first
chain of signed policies, so a service sees one proof that the owner authorized
this agent, not a pile of claims. Full interface:
[`docs/portable-policy.md`](docs/portable-policy.md).

**Short-lived, exact-transaction grants.** `BoundAuthorization` turns the
advisory approval into an enforced one: the owner signs the grant hash, the
expiry and the *exact transaction hash* together, with a 30-block lifetime cap.
A stolen authorization re-aimed at another payment, or replayed past its
window, is refused by name — at verification and at admission
(`service::admit_bound_payment`).

**Chain-agnostic engine.** The `srct-policy` crate is the policy layer's
cross-chain face: input a `PaymentIntent`, get back `allow`, `deny` or
`approval-needed` — the same decision the node reaches, with no consensus
imports. TypeScript (`bindings/typescript/srct_policy.ts`) and Python
(`bindings/python/srct_policy.py`) bindings speak the same JSON. Honest
weight note: the crate still compiles all of `srct-core` — outsiders wanting
answers without Rust use HTTP (`POST /v1/policy/decide`) or the bindings
against a node URL.

**Payments.** `MachinePayment` is the canonical format. `ReceiptBook` records
deterministic service receipts and refuses a receipt that conflicts with an
existing one for the same payment. `PaymentTracker` is an exact-payment replay
guard. A settled payment also carries its proof: `POST /v1/payment/{id}/settle`
binds the Layer 1 transaction that paid it (a tx that does not pay the recipient
is refused), `GET /v1/payment/{id}` reports the link as `settlement`, and the
link persists across restarts.

**Reputation.** A bounded accumulator per identity, driven by a **fixed weight
table in code, not data**:

| Event | Weight |
|---|---|
| Service completed | +1 |
| Payment completed | +1 |
| Verified work | +2 |
| Dispute won | +1 |
| **Dispute lost** | **−3** |

An event carries no amount, no weight and no signature of its own — the weights
are not forgeable by producing a differently-shaped event. Losing a dispute costs
three times what winning one earns, so baseless challenges are expensive. It is
**not mintable**: nothing here creates a token.

**Streaming micro-payments.** `PaymentStream` is pay-as-you-use: a payer-signed
rate per block, a window, a hard cap, a recipient, and the governing policy for
non-human payers. Settlement receipts are payer-signed and the `StreamBook` is
fail-closed — exact amounts, strictly ordered, non-future settlements, accrual
checked for wraparound. Settlement rides the ordinary payment path with the
stream id as the reference, so there is no new transaction type.

**MCP.** `srct-mcp` is a keyless MCP surface over agent identity, payments,
receipts and reputation, over the agent authority and credit layer — and an
**agent wallet guard**: `wallet.guard` runs the budget plus a short expiry
before any key is used (allow / deny / approval-needed), `policy.decide`
answers the engine statelessly, `policy.export`/`policy.verify` and
`delegation.prove`/`delegation.verify` move portable grants across rails,
`auth.bind`/`auth.verify_bound` enforce the short-lived exact-transaction
grant, and `audit.verify` checks an exported audit chain. `inspect.policy`,
`inspect.agent_spend` and `inspect.credit` read the terms an agent is about
to sign and the hash to sign.

### Consensus state vs. service layer

The spending-policy layer is consensus state (SPEC.md §21). A grant is published
on chain, the owner's signature binds it to a named spender and a named agent,
the caps, allow-lists and nonce are enforced against state the chain keeps, and
revoking a grant kills every descendant of it. The same is true of credit
(SPEC.md §22): a loan is a chain fact with the lender's signature over its terms,
principal really moves, and the collateral answers for the debt.

The *service layer* surrounding them is still node-local: the payment book, the
receipt book, the credit gate used for admission and the authorisation helper the
API issues offline. Those are operational bookkeeping, not sources of spendable
balance — they persist to disk so they survive restart, but consensus never
depends on them.

---

## Mining

Three ways to mine, from simplest to pooled. All three produce the same blocks
and pay the same coinbase — the difference is only where the grinding happens.

**Where the reward goes.** Every block pays its coinbase to one address: the
node's miner wallet for in-node mining, or the `--miner` address you pass to
`srct-miner`. New coins are **immature** first — spendable after 100 blocks on
mainnet, 10 on testnet/mini — then they are ordinary UTXOs. Check them with
`srct-node balance --address <addr>` or `status`.

**Difficulty, honest numbers.** Every profile starts at difficulty 1 (trivially
mineable — a laptop mines block after block on a fresh chain) and retargets
every block toward its target spacing (10 minutes mainnet, 1 second
testnet/mini), at most ±10% per block. As miners join, difficulty rises and the
same hardware finds fewer blocks. Measured reference: ~114k H/s on 4 CPU
threads (release build, `hybrid-v1`), so one such machine holds ~10-minute
blocks alone until difficulty passes ~68M. Launch is CPU-fair by construction;
difficulty does the hardening, not special hardware.

### Option A — mine inside the node (simplest start)

```sh
export SRCT_WALLET_PASSPHRASE=change-me
./target/release/srct-node init --network testnet --data-dir ./chain
./target/release/srct-node serve --network testnet --data-dir ./chain \
  --listen 127.0.0.1:9833
```

`serve` mines by default into the wallet created by `init`. One command, no
other software. Good for: first launch, testing, solo mining while the network
is small.

### Option B — mine with the standalone miner (recommended)

Run the node relay-only and grind on any machine with the `srct-miner` binary:

```sh
# 1. Node side: no built-in mining, templates on loopback.
./target/release/srct-node serve --network testnet --data-dir ./chain \
  --no-mine --api-listen 127.0.0.1:8080

# 2. Miner side: fetch a template, solve it, submit the block — repeat forever.
./target/release/srct-miner --node 127.0.0.1:8080 \
  --miner <20-byte-hex-address> --threads 0 --backend auto
```

How it works: `GET /v1/mine/template?miner=<hex>` returns an unsolved block
(`block_hex` plus height/difficulty/puzzle_id); the miner grinds `nonce` and
`extra_nonce` until the proof passes, then `POST /v1/mine/submit
{"block_hex": ...}` hands it back. The node re-validates everything —
template, proof, tip, timestamp — so a stale or forged solution is refused,
never half-applied. Any HTTP client can do this loop; the binary just does it
well (multithreaded, `--threads N` with `0` = one per CPU and a cap of 1024,
`--batch N` for batched solving with a cap of 65536, automatic retry with backoff).

The `--miner` address need not belong to any wallet on the node — it is just
where the coinbase pays out.

Seed boxes, the pool protocol, hardware backends and the `hbm-v1` upgrade
route: [`docs/mining.md`](docs/mining.md).

---

## Supply

There is **no stock cap**. That is a deliberate change — see
[Decision 18](docs/decisions.md) — and the current bounds are different in kind.

**The ladder** halves in whole SRCT every 262 800 blocks (~5 years at a 10-minute
block):

```
76, 38, 19, 9, 4, 2, 1 SRCT
```

Whole SRCT, not shifted satoshis: halving 9.5 → 4.75 would break the arithmetic.

**Premine is 0%**, enforced in code rather than in prose. Genesis mints nothing.

**The ladder totals exactly 39 157 124 SRCT.** Not the 39 157 200 a geometric
shortcut suggests — genesis occupies a rung-0 height without minting, so the
first rung is paid by `H − 1` blocks rather than `H`. That 76 SRCT is the
difference between the design document's approximation and what the chain can
actually reach, and `supply::max_issuance_sat` reports the real figure.

**The tail** takes over after the ladder (height 1 839 600) and never stops:

```
0.50 → 0.25 → 0.125 SRCT, then a permanent 0.1 SRCT floor
```

So issuance continues forever, reaching the floor at height 2 628 000 (~50 years)
instead of terminating. Testnet and mini pay a constant 1 sat per block from their
first tail period.

**Two bounds enforce this**, both checked in `Chain::apply_block` so the miner,
validator and node cannot disagree about what is mintable at a height:

1. **The issuance integral.** A block may not mint past
   `cumulative_issuance_sat(height)`. Overflow is refused rather than wrapped — a
   wrapped sum would compare small and pass the bound.
2. **The rate anchor.** After ladder exhaustion, gross issuance inside the current
   halving window may not exceed **1% of the supply issued at that window's
   start**. The approved schedule sits ~3× under it, so the anchor never binds it
   today — it exists to refuse a *future* schedule that would dilute far faster.
   The ladder era is grandfathered.

**Net supply can fall.** The base fee splits 50/50 into a burn and an on-chain
reserve, so usage *removes* supply from the spendable set. Combined with a
declining tail reward, the simulation measures net supply falling below
break-even at ≈5% activity and being at 25% at the fee floor. This is a measured
consequence, not a bug — the analysis and sensitivity tables are in
[docs/monetary-policy.md](docs/monetary-policy.md).

Gross issuance, removal and net supply are reported by `status`,
`GET /v1/conservation` and the `/metrics` gauges. Conservation passing does
not mean nothing was stolen — a thief's exit conserves perfectly — so
`/v1/conservation` also reports the exit-outflow watch (`exit_window_total`
vs cap, `pending_exit_sat`): alert on a window filling fast, not on the
invariant staying green.

---

## What the chain is for

Two distinct layers, with different jobs:

**Layer 1** is a conventional UTXO chain — wallets, transfers, blocks, P2P. It
exists to be a durable settlement layer, and nothing about it is AI-specific.

**Layer 2** is the part that makes the compute work worth doing. It is a task
economy: a **submitter** posts an escrow for a described computation, a **worker**
claims it, runs it and submits a result hash, and anyone may **challenge** that
result. A committee then decides whether the work was correct, and settlement
moves the money accordingly.

The L2 transaction types are the whole vocabulary — six for the task economy and
the exit mechanism, seven for the authority and credit layers (thirteen total):

| Type | Value | Purpose |
|---|---|---|
| `PostTask` | `0x10` | Submitter: open a task, lock the escrow, publish the compute spec |
| `ClaimTask` | `0x11` | Worker: take the task, post a deposit |
| `SubmitResult` | `0x12` | Worker: submit the result hash with a signed attestation |
| `Dispute` | `0x13` | Anyone: challenge the result with a counter-result and a deposit |
| `Settle` | `0x14` | Committee: apply the decision — pay, refund, slash |
| `ExitQueue` | `0x15` | Owner: start withdrawing back to Layer 1 |
| `Policy` | `0x16` | Owner: publish a spending grant (agent authority) |
| `PolicyRevoke` | `0x17` | Owner: kill a grant — every descendant dies with it |
| `AgentSpend` | `0x18` | Spender: spend under a published grant |
| `CreditOpen` | `0x19` | Lender: open a loan; the principal moves to the borrower |
| `CreditCollateral` | `0x1A` | Borrower: add collateral to a position |
| `CreditRepay` | `0x1B` | Borrower: repay (interest first, then principal) |
| `CreditDefault` | `0x1C` | Anyone: settle a position that was not repaid by its deadline |

A task moves through six states: `Open → InProgress → ResultSubmitted →
Disputed? → Settled`, with `Expired` as the timeout branch.

---

## Use cases

These are the things a UTXO chain with a task economy on top of it can do that
the two layers alone cannot.

**Settlement for work nobody re-runs.** Someone pays for a result; someone else
checks it without re-doing it. The chain holds the escrow and decides the
outcome, so the two sides need no prior relationship and no arbitrator they both
trust.

**Machines spending under a written policy.** An owner authorizes once, offline,
and every later spend is checked against it with the owner offline — bounded per
transaction, bounded per window, to named recipients and named services, with a
nonce that makes an authorization unreplayable and a kill switch.

**Payment for what a machine produced, not what it claimed.** A verified-work
certificate is a derived consequence of a settled task, never a claim an actor
makes, so it can be shown to a third party as evidence.

**Reputation that travels with the identity and cannot be bought.** An event
carries no weight of its own, so a differently-shaped event cannot forge a
better score, and losing a dispute costs three times what winning one earns.

**Value that comes back.** Deposits are not one-way. An owner can bring value
back to Layer 1 through a queue, a maturity period and a proof-authorised release
that anyone can crank.

**What this is for, concretely.** If a machine can produce a result that anyone
else can check without re-running it, that machine can be paid for it without
both sides trusting each other. That is the economic claim: verifiable
delegation of computation, with the blockchain as the escrow and the arbiter.

---

## Agent payments (x402)

SRCT speaks the x402 challenge/response shape with no second payment system.
A client calls a paid resource, gets `402 Payment Required` plus a
`PAYMENT-REQUIRED` envelope, and retries with a `PAYMENT-SIGNATURE`. The node
verifies by reusing the ordinary payment admission path
(`service::admit_payment` + the node-local `CreditBook`), so there is no
consensus change.

```
Agent ──GET /v1/paid/weather──▶ 402 + PAYMENT-REQUIRED (exact, srct:mini, 500 sat)
Agent ──budget check (max, allow-lists)──▶ PaymentRequest → Authorization → MachinePayment
Agent ──GET + PAYMENT-SIGNATURE──▶ verify → admit → 200 + PAYMENT-RESPONSE + weather
```

- `GET /v1/paid/weather` — demo paid resource (500 sat, fixed recipient and
  service `x402-weather-v1`). Missing signature returns `402`; a valid
  signature admits the payment and returns `200` with the report.
- `POST /v1/x402/verify` — facilitator verify (offline checks, no state change).
- `POST /v1/x402/settle` — facilitator settle (same admission as
  `POST /v1/payment/submit`).
- Client budget (`X402Budget { max_amount_sat, allowed_recipients,
  allowed_services }`) is enforced *before* signing — a server asking for
  more is refused locally. `check_guarded` adds the short window: the spend
  must land before its expiry, and the window is capped at 30 blocks.
- `scheme` is `exact` only; `network` is CAIP-2 `srct:<reference>`
(`srct_core::x402::srct_network_caip2` / `parse_srct_network`) or, beside
SRCT, an EVM rail (`eip155:8453` Base, `eip155:84532` Base Sepolia —
advertised, never settled by this node); `amount` is a decimal satoshi string.

Full mapping, curl flow and limits: [`docs/x402.md`](docs/x402.md). Demo:
`python sim/x402_paid_api_demo.py`.

---

## Micro-payments and wallet safety

Per-call billing without a manual transaction per call. Three primitives,
none of which changes consensus — all reuse `MachinePayment`, `SpendPolicy`
and the credit path. Full guide: [`docs/micropayments.md`](docs/micropayments.md).

| Primitive | Endpoint | What it does |
|---|---|---|
| Batch quotes | `POST /v1/payments/aggregate` | Same payer, N recorded payments → one `PaymentBatch` with per-recipient merged outputs. Returns gas, required fee, per-payment cost and savings vs N separate transactions. Read-only quote. |
| Stream channels | `POST /v1/streams/open`, `POST /v1/streams/settle`, `GET /v1/streams/{id}` | Open once (rate per block, expiry, hard cap); each unit of work mints an off-chain voucher; only the final voucher settles on chain as a `MachinePayment` with `reference` = stream id, bound to the stream's recipient. `StreamBook` enforces exact, ordered, in-cap settlement; accounting persists in `state.bin` (v8). |
| Sponsored intents | library `srct_core::micro::SponsoredIntent` | A sponsor signs fee coverage (`sign_sponsor_intent` / `verify_sponsor_intent`, bound to sponsor + batch hash + fee + expiry). Auditable fee-attribution record — deliberately not a consensus fee-payer, so a sponsor can cover a priced quote but never mint authority. |

Benchmark (`python sim/micropayment_benchmark.py`): 10 payments to one
provider cost one base fee instead of ten; a 100-unit stream settles once
instead of 100 times. Latency follows the same curve — fewer transactions is
fewer confirmation waits.

The wallet around them is safer than a normal crypto wallet by construction
(full operator guide: [`docs/wallet-safety.md`](docs/wallet-safety.md)):

1. **Spend policy** — per-tx cap, tumbling window + cumulative cap,
   recipient/service allow-lists (empty allows nothing), validity heights,
   strict nonce increase, owner revocation. Fail-closed.
2. **Session budget** (`safety::SessionBook`) — per-agent aggregate across
   rotated policies, so spend cannot be split across N policies.
   `SRCT_SESSION_WINDOW_BLOCKS` + `SRCT_SESSION_CAP_SAT` (both zero = gate off).
3. **Risk checks** (`safety::RiskPolicy`) — high-value approval is *enforced*,
   not advisory: at or above `SRCT_HIGH_VALUE_THRESHOLD_SAT` the node answers
   `403 human_approval_required` until a key listed in
   `SRCT_HIGH_VALUE_APPROVERS` co-signs the payment (the payer's own key does
   not count). Threshold `0` disables the gate — but only if the operator
   sets it: with no env set, mainnet gates at 10 SRCT by default, so the
   drain playbook never depends on a forgotten variable. Plus per-payer velocity cap
   (`SRCT_MAX_PAYMENTS_PER_PAYER`) and a mainnet guard in test mode
   (`SRCT_TEST_MODE=1` refuses `srct/mainnet` spends). Full operator recipe:
   [`docs/wallet-safety.md`](docs/wallet-safety.md).
4. **Idempotency** — `PaymentTracker` (exact replay → `duplicate: true`
   before admission), `ReceiptBook` (same receipt → `duplicate`; conflicting
   receipt → `receipt_conflict` 409), strictly increasing policy nonces.
5. **Receipts + reconciliation** — every admission holds a credit reservation
   until its receipt settles it; `GET /v1/payments/unsettled` lists
   recorded-but-unbound payments (retry these, do not rebuild);
   `GET /v1/receipts/orphans` lists receipts claiming unrecorded payments.
6. **Audit trail** — every grant, admission, refusal, revocation, stream and
   receipt appends to a bounded hash-chained `AuditLog`
   (`GET /v1/audit` reports `chain_valid`; `GET /v1/risk/policy` exports the
   live envelope). The chain exports as auditor/insurer-readable JSON
   (`AuditLog::export_json`, re-checked by `verify_export_json`, MCP
   `audit.verify`).

---

## Agent economy

Portable reputation, tiered spend power, job escrow with result binding,
dollar pricing with SRCT settlement, auditable fiat ramps, and productive
lending. Service-layer (node-local books), not consensus — except the L2
credit positions in [`Credit and lending`](#credit-and-lending), which stay
the collateralized on-chain primitive underneath.

### Portable reputation + tiered wallets

[`docs/reputation.md`](docs/reputation.md).

- History travels with the agent: receipts record task completions and
  payments, credit positions record repayments and defaults
  (`POST /v1/reputation/passport/attest` assembles a subject's events from
  node books). An issuer that verified the events signs a `PassportBatch`
  (`POST /v1/reputation/batch`; the node re-verifies every payment and loan
  source against its own books). Any service scores it
  (`GET /v1/reputation/score/{agent}?role=machine` →
  `Deny | Throttled | Standard | Preferred`).
- Sybil resistance: every positive event is backed by a real payment, settled
  receipt, posted collateral or repaid loan; repeat business with one
  counterparty counts as its integer square root; stake-backed events weigh
  more (repaid collateralized loan +4 vs bare task +1); negatives are sticky
  and never dampen (dispute lost −4, default −8; any default zeroes the
  suggested credit limit). Wallet age and raw tx count are deliberately unused.
- Tiered wallets: one funding split into narrowed child policies
  (`tiers::build_tier_pair`) — e.g. 20/tx for trusted services, 1/tx for
  experiments. A tier can never exceed its parent; they nest; revoking the
  root stops the whole tree. `POST /v1/wallet/tier`,
  `GET /v1/wallet/tiers/{agent}`.

### Agent-to-agent job escrow

[`docs/agent-jobs.md`](docs/agent-jobs.md).

```
POST /v1/jobs/open → POST /v1/jobs/{id}/accept → POST /v1/jobs/{id}/deliver
→ POST /v1/jobs/{id}/resolve|release (against the delivered result hash)
— or — POST /v1/jobs/{id}/dispute (freezes funds until the arbitrator resolves)
```

Release binds the result hash — it pays for *this* dataset, not any dataset.
The resolve signature binds (job id, direction, result hash) to the
arbitrator key named at open. Every step is authorized: `open` needs the
hirer's signature over all terms, `deliver` the worker's over (job, result),
and `loans/accept` the borrower's over (offer, amount, bond, deadline) — no
one opens debt or jobs in someone else's name. Dispute locks are
node-enforced (`held_escrows`, persisted in `state.bin` v8): release,
settlement binding and the timeout auto-refund all refuse while disputed.
`GET /v1/jobs/{id}` reports the record plus escrow state and held flag.
`GET /v1/payments/{id}/receipt_status` reports
`{recorded, receipt_present, settlement_tx}` — treating a payment as complete
before its receipt appears is a client bug.

### Dollar prices, SRCT settlement

[`docs/usd-settlement.md`](docs/usd-settlement.md). SRCT is a mined coin, not
a peg — services quote in USD (or a supported stablecoin) and settle in SRCT
at a transparent locked rate. `POST /v1/fx/rates` (issuer must be in
`SRCT_FX_ISSUERS`), `GET /v1/fx/rates/list`,
`POST /v1/fx/quote` (amount, sat due, fee, slippage, rate, expiry stated up
front; stale or expired quotes refused), `POST /v1/fx/swap` (stablecoin-in
intent as audit trail — custody never touches the node).

### Entering and exiting SRCT

[`docs/ramps.md`](docs/ramps.md). The node is the auditable registry for
entry/exit; custody and compliance live with the ramp provider off-protocol.
`POST /v1/ramp/quote` (provider-signed, either direction),
`GET /v1/ramp/quotes`, `POST /v1/ramp/intent`,
`POST /v1/ramp/intent/{id}/settle` (only the quoted provider closes its own
intent; terminal: filled or refunded, never both), `GET /v1/ramp/intents`.

### Productive lending

[`docs/lending.md`](docs/lending.md). Credit for working capital on top of
the on-chain positions: lenders publish standard terms
(`POST /v1/loans/offers`, rate ≤ 10%/window, full-collateral terms),
borrowers discover (`GET /v1/loans/offers/list`, cheapest first) and accept
(`POST /v1/loans/accept` — terms come from the offer; bond and collateral
must already be funded). History prices risk
(`GET /v1/lending/borrower/{addr}`, `GET /v1/lending/limit/{borrower}` —
advisory only; any default zeroes it; no history means zero),
`GET /v1/lending/dashboard` (exposure, due-soon, shortfalls),
`GET /v1/lending/collateral/{position_id}` (live coverage in bps). Loss order:
collateral first, then the borrower's posted bond, then the lender absorbs
the shortfall — never minted. Borrowers can authorize automatic repayment
from revenue (`POST /v1/lending/autorepay`, revocable, capped, expiring;
`credit/deposit` routes the authorized share first).

Demo covering reputation, tiers, jobs, USD quotes, ramps and lending:
`python sim/agent_economy_demo.py`.

---

## How fraud is detected

The canonical CPU reference decides. Nothing else is authoritative, and no
caller can supply the answer.

### The reference

`compute_ir::reference_result_hash(task_id, ir_hash, input_hash, required_memory_bytes)`
is a fixed-round permutation over the task's own committed fields. It commits to
the *task*, never to a caller's claim about it.

Two properties make it authoritative:

- **It is not interpreted.** The reference is a permutation over commitments, not
  an interpreter for arbitrary IR. SPEC §16.4/§16.5 forbid an on-chain
  interpreter, and this is the shape that respects that: a fixed function, not a
  runtime.
- **It has no height, clock or RNG input.** Identical task fields produce
  identical bytes on every machine, every run.

### The lifecycle

```
worker submits R
      │
      ├─ nobody challenges inside the window
      │     → auto-settle Correct → paid → WindowElapsed VWC
      │                          (a receipt, NOT a verification)
      │
      ┤─ challenger files R' with a deposit
            → DisputeEngine::resolve computes the reference itself
                  reference == R   → WorkerCorrect     → Verdict::Correct
                  reference == R'  → ChallengerCorrect → Verdict::Fraudulent
                  reference == neither → Inconclusive  → settles nothing
```

`DisputeEngine::resolve` reads the evidence from the contract and computes the
reference from the contract's own fields. It never accepts the reference as a
parameter — taking it as an argument would let any caller dictate the verdict.

**"No match is not guilt."** An inconclusive arbitration settles nothing. A
malformed or unexecutable task cannot become a fraud conviction by accident.

### Vote binding and replay protection

Each committee member signs one vote per held key — four keys is four committee
members, not one member with four signatures, because a quorum counts *distinct*
signers.

A vote binds the task, the verdict, the reference result, the network, the
height and the signer, under its own domain separation tag. It signs exactly
`SettlePayload::signing_hash`, which is what lets a quorum of votes aggregate
into the aggregate the settlement transaction carries — and lets the settlement
path re-verify it from scratch with real BLS pairings.

Receiving nodes check a vote against **their own** committee and height, and relay
only what they accepted, so a bad vote travels at most one hop. One vote per
signer means a replay, a duplicate, or a relay loop cannot inflate quorum.

A **split committee** (two honest members disagreeing) is refused but *not*
recorded as equivocation — blaming an honest signer for the committee's
disagreement is exactly the kind of thing that gets turned into a slash. A genuine
double-sign is recorded as `ArbitrationEquivocation`.

The signed message includes the network and height: `SettlePayload` carries both,
`SettlePayload::signing_hash` covers them, and `apply` refuses a payload naming
another network or a vote from the future. The tally re-checks that every counted
vote names one network and one height, and the quorum certificate carries the same
chain context so it stays re-verifiable.

### What a fraud verdict does

| | |
|---|---|
| Worker | Deposit slashed through the M2 vault: 50% burned immediately, 50% vests linearly over a year |
| Submitter | Refunded whole |
| Challenger | Paid a bounty from the PSCB reserve; their deposit returns |
| Certificate | **None** — a fraud verdict is not evidence of correct work |

Settlement fees are proportional: 0.1% of task value, 1 000-sat minimum.

---

## How withdrawals work

Deposits are not one-way. An owner on Layer 2 can bring value back to Layer 1.

1. **Deposit.** An ordinary Layer 1 payment to the profile's derived sink
   address. No new transaction type. Credited 1:1 after finality depth.
2. **Queue.** The owner signs an `ExitQueue` transaction, which debits
   `amount + exit_fee + queue_fee` and records `(owner, nonce) → (amount,
   destination, height)`. Nonces are per-owner and strictly increasing.
3. **Mature.** After finality depth *and* binding finality, the exit is
   settleable. Exits use the same or a stronger rule than deposits, never weaker.
4. **Release.** A **permissionless crank** builds the claim: it consumes sink
   outputs and proves the exit record against the L2 state root committed at the
   queue block.

The claim is authorised by an **inclusion proof, not a signature**, because the
sink holds no key. Consensus pays only the destination the proven record names —
a caller cannot redirect it — and the claimant collects a fee the owner prepaid
at queue time, which is what makes a crank nobody wants to run a non-issue rather
than a griefing vector.

**Exact funding only.** A claim must consume sink outputs summing *exactly* to
`amount + exit_fee + required L1 fee`, with no change and no tip. An exit whose
funding is not sitting in a subset summing to that figure stays queued rather
than draining a stranger's deposit. The cost is a liveness edge: it can wait.

**Windowed, and fair within the window.** Mainnet caps exit principal at
1,000 SRCT per 144-block window — and at 100 SRCT per owner inside it. The
global cap alone is starvable (one filler holds everyone else out until
rollover, at fee cost); the per-owner sub-cap refuses the filler by name
(`ExitOwnerWindowFull`) while other owners still queue, and resets on
rollover. Refusals delay, never destroy.

**Anyone can crank.** Consensus is permissionless, and claims are not
miner-only: `GET /v1/exit/crankable?claimant=<address>` hands the settleable
claims to any third party, so a non-miner can build a block with them. An escrow settlement
rides this same path — `POST /v1/escrow/{id}/settle` queues the release's exit
and the crank pays it, with no separate escrow coin.

**Reorg-safe.** A release is an ordinary undoable Layer 1 operation: rollback
restores the sink outputs, clears the identity, and L2 replay regenerates the
watch.

**Conservation is unchanged.** The joint check needed no exit term at all — the
L1 payment and the L2 debit cancel while the sink term falls by the same amount.

> **Active on mainnet.** `mainnet.exit_activation_height` is `1`, which means
> exits work from genesis — same as Bitcoin spends. Testnet and mini activate
> at height 1.

---

## Validators and finality

**Bonded stake** (`bond.rs`, Decision 20). Three transaction types — `TX_BOND`,
`TX_UNBOND`, `TX_SLASH` — feed a bond ledger with a bond-order index. No wealth
gate — but an anti-dust floor (`min_bond_sat`: 0 on mini/testnet, 0.01 SRCT on
mainnet): below it a bond is refused, so 1-sat spam cannot permanently occupy
ledger entries on every node. Unbonding locks for `UNBONDING_PERIOD_BLOCKS` =
1 008 (seven days). Provable equivocation burns the full bond.

Bonds only admit keys whose holder proves they hold them: `TX_BOND` carries a
96-byte proof-of-possession signature bound to network, bonder and key, and a
payload without one does not decode.

**Finality.** Binding finality activates at `finality_activation_height = 100`
on mainnet from genesis. Depth-based finality (100 blocks) secures the chain
before that — the same Bitcoin-style rule. The 21-key bootstrap committee signs
until the first bond, then the stake-weighted TopN set replaces it. Those 21
keys are public (deterministic in source), so serving mainnet with them loaded
requires `--allow-bootstrap-committee` — cold start is explicit, never silent;
replace them with bonded keys.

**Fixed-epoch committees.** Each epoch's committee derives from the bond state
at its seed height and stays fixed for the whole epoch; a bond mid-epoch takes
effect only at the epoch its seed first sees. Reorgs across a seed height roll
the committee back exactly — snapshots travel with the chain state and the
finality observation frontier rewinds with them (`rewind_observation`), so a
certificate from a losing branch can never be replayed.

**Slash verification is per-epoch.** `check_slash_tx` verifies each checkpoint
against its own epoch's committee and fails closed when that set is
unavailable — an expired epoch or disjoint signer sets refuse rather than fall
back. A validator that drops out of TopN can still be slashed on evidence from
when it was bonded. Committee caches hold the current set plus the previous
one inside its grace, then expire; deriving a set that fails is a hard error,
and there is no genesis fallback once bonds exist.

---

## Credit and lending

Layer 2 supports agent-to-agent lending as on-chain state. The principal, the
collateral, and the debt are real coins in the UTXO set — consensus state, not
accounting entries. A loan is a four-step lifecycle: **open**, **repay**, and
either **repay-in-full** or **default**. Collateral may also be **added** to an
open position at any time before it settles. Full-collateral terms by default
(100%), interest capped at 10% per window and charged per whole window,
repayment applies interest first, overpayment is refused rather than clipped,
anyone may default an overdue position, and the loss order is collateral,
then bond, then lender — the protocol never mints to cover a shortfall.
Full mechanics (wire types, terms, fee split, interest arithmetic,
settlement order, position tracking, fund flow):
[`docs/lending.md`](docs/lending.md#the-consensus-primitive-underneath).

### CLI

```sh
# Open a loan: you are the lender, --to is the borrower.
# --collateral defaults to the principal amount (100% collateralization).
srct-node credit --to <borrower-address> --amount <SRCT> \
                --collateral <sat> --rate-bps <bps> \
                --window <blocks> --deadline <height> --nonce <n>

# Repay (interest first). Use --amount-sat for exact satoshis.
srct-node credit --repay --position <id> --amount <SRCT>

# Default a position at or after its deadline (permissionless).
srct-node credit --default --position <id>

# List all positions.
srct-node credit --list
```

The `credit` subcommand uses a wallet. The lender signs `CreditOpen`; the
borrower signs `CreditRepay`; any wallet can sign `CreditDefault` once the
deadline has passed. On a local node the CLI mines the transaction directly;
over the network, serialize the `L2Transaction` to hex and POST it to
`/v1/l2/broadcast`, which dry-runs against the current state and queues it for
the next block.

Adding collateral to an open position (`CreditCollateral`, `0x1A`) is available
via the same `/v1/l2/broadcast` endpoint — the CLI's `credit` subcommand does
not expose it directly, but the worker SDK does (`add_credit_collateral`).

> **On-chain positions vs the lending marketplace.** This section is the
> consensus primitive: collateralized loans as chain state. The loan offers,
> borrower history, credit limits, dashboard, collateral-valuation and
> auto-repay endpoints in [Agent economy](#agent-economy) are the node-local
> marketplace built on top of it — they price and discover loans, they never
> replace collateral. `credit` in the API never reads a reputation score.

---

## Repository layout

| Path | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | **Normative.** Where a disagreement exists, this wins. |
| [`AGENTS.md`](AGENTS.md) | Lint, type-check and test commands for this session. |
| `crates/srct-core/` | Protocol implementation. All consensus logic. |
| `crates/srct-net/` | P2P wire protocol, sync and relay. |
| `crates/srct-store/` | Append-only checksummed block log, crash recovery. |
| `crates/srct-l2/` | Layer 2: contracts, disputes, certificates, exits. |
| `crates/srct-node/` | CLI and node daemon. |
| `crates/srct-miner/` | Standalone CPU miner: template grinder, stratum-lite pool server with PPLNS payouts, universal compute backends. |
| `crates/srct-worker/` | Worker-side SDK. Client only, no consensus. |
| `crates/srct-mcp/` | Keyless MCP surface over agent identity, payments — and the agent wallet guard. |
| `crates/srct-policy/` | Chain-agnostic policy engine: portable grants, delegation proofs, bound grants, JSON decisions + TS/Python bindings. No consensus imports — but still compiles all of `srct-core` (see crate docs); outsiders use HTTP or the bindings. |
| `fuzz/` | 17 cargo-fuzz targets over the attacker-controlled boundaries. |
| `sim/` | Independent Python reference, attack simulations, and feature demos (`x402_paid_api_demo.py`, `micropayment_benchmark.py`, `agent_economy_demo.py`). |
| `tests/vectors/` | Consensus vectors. Generated from source, never hand-edited. |
| `docs/` | Design records, verification status and readiness reports — plus per-feature guides: `portable-policy.md`, `x402.md`, `micropayments.md`, `wallet-safety.md`, `reputation.md`, `agent-jobs.md`, `usd-settlement.md`, `ramps.md`, `lending.md`. |
| `paper/` | The Solar Cyber Unit protocol paper (LaTeX + PDF). |

Nine crates in one workspace. **All consensus logic lives in `srct-core`**, which
has no I/O, no clock and no network. The service-layer feature modules
live beside it without touching consensus: `x402.rs` (x402
adapter, budget guard, Base rail options), `micro.rs` (batch/stream/sponsored), `safety.rs` (session budgets,
risk guards, audit log + export), `portable.rs` (signed policies, delegation
proofs, short-lived bound grants, intent→decision seam),
`passport.rs` + `tiers.rs` (portable reputation,
tiered wallets), `jobs.rs` (agent job escrow), `fx.rs` (USD quotes),
`ramp.rs` (entry/exit registry), `lending.rs` (loan marketplace). The `mini`
profile is the same code with different parameters — never a second
implementation — so anything tested on `mini` is the production code path.

Key documents: [`docs/decisions.md`](docs/decisions.md) for design decisions,
[`docs/status.md`](docs/status.md) for the verification record,
[`docs/mainnet-readiness.md`](docs/mainnet-readiness.md) for what blocks launch,
[`docs/monetary-policy.md`](docs/monetary-policy.md) for the supply analysis,
and the feature guides listed in the `docs/` row above
([portable policy](docs/portable-policy.md),
[x402](docs/x402.md), [micro-payments](docs/micropayments.md),
[wallet safety](docs/wallet-safety.md), [reputation](docs/reputation.md),
[jobs](docs/agent-jobs.md), [USD settlement](docs/usd-settlement.md),
[ramps](docs/ramps.md), [lending](docs/lending.md)).

---

## Network profiles

Same code, different numbers.

| | `mainnet` | `testnet` | `mini` |
|---|---|---|---|
| Block time | 600 000 ms | 1 000 ms | 1 000 ms |
| Halving period | 262 800 | 2 000 | 2 000 |
| Start reward | 76 SRCT | 76 SRCT | 76 SRCT |
| Finality depth | 100 | 20 | 20 |
| Coinbase maturity | 100 | 10 | 10 |
| Genesis validators | 21 public bootstrap (quorum 15) | 4 deterministic | 4 deterministic |
| L2 settlement validators | **none** (fail closed) | 4 deterministic | 4 deterministic |
| Binding finality | on at height 100 | on at height 20 | off |
| Exits | on at height 1 | on at height 1 | on at height 1 |
| PQ spend requirement | **off** | off | off |
| Mining puzzle | `hybrid-v1` (`puzzle_id = 1`) | `hybrid-v1` (`puzzle_id = 1`) | `hybrid-v1` (`puzzle_id = 1`) |
| Retarget | LWMA every block, ±10% | LWMA every block, ±10% | LWMA every block, ±10% |
| Genesis difficulty | 1 | 1 | 1 |

`mainnet` ships with 21 public deterministic bootstrap keys (quorum 15) so
finality can bind before any stake exists; the first bond replaces them with
the stake-weighted TopN committee. Its separate L2 settlement set stays empty,
so settlements fail closed. Exits are active from height 1. The PQ row is the
`pq_activation_height` of Decision 24: `0` means no input is refused for
lacking an ML-DSA-65 component, and the rule is age-gated when it is flipped —
only outputs created at or after the height must carry the component, so
history is never stranded.

Network magic bytes (§13.3): `mainnet` = `6A4E5402`, `mini` = `6A4E5403`,
`testnet` = `6A4E5404`. These move with each protocol version that changes the
wire format or state root, so pre-bump peers are refused at framing before they
can join.

---

## Commands

```
srct-node <COMMAND> [OPTIONS]

  init        Create a chain directory, a miner wallet and the genesis block
  mine        Mine blocks and extend the chain
  send        Spend from a wallet address, local or over P2P
  status      Print chain tip, difficulty, supply, wallet balance, L2 pipeline
  verify      Replay the chain from genesis and diff it against stored state
  show-block  Print one block
  balance     List the unspent outputs of an address
  wallet      Create or list wallets
  policy      Publish, revoke or list spending grants (agent authority)
  agent-spend Spend under a published grant
  credit      Open, repay, default or list credit positions
  l2          Layer-2 summary, and the deposit address
  validator   Add or list checkpoint-signing keys
  export      Write the canonical chain to JSON
  serve       Run a P2P node: relay, sync, opt-in REST API, exit crank, signing
```

```
srct-miner --node 127.0.0.1:PORT --miner <20-byte-hex> [--threads N] [--batch N] [--backend cpu|portable|auto]
```

Full mining guide — three ways to mine, where rewards go, hardware backends,
pool protocol — is in [Mining](#mining) above; the node endpoints
(`GET /v1/mine/template`, `POST /v1/mine/submit`) are specified in SPEC §19.2.

### Agent authority and credit, from the terminal

A grant is the owner's signed authority for a named spender. It is published
on chain, so every node enforces it:

```sh
# The deposit address: an ordinary L1 payment to it credits your L2 balance.
srct-node l2 --deposit-address
srct-node send --to <deposit-address> --amount 5

# Publish a grant: this key may spend up to 0.01 SRCT per payment and
# 0.05 SRCT per window, to this recipient only.
srct-node policy --spender <spender> --per-tx 1000000 --cumulative 5000000 \
                --recipients <recipient>

# The agent spends under it.
srct-node agent-spend --policy <policy-hash> --to <recipient> --amount 0.002 --nonce 1

# The owner kills it; every descendant of the grant dies with it.
srct-node policy --revoke --agent-id <agent-id>
srct-node policy --list
```

Credit works the same way — the **lender** signs, the principal really moves,
and the collateral answers for the debt:

```sh
srct-node credit --to <borrower> --amount 1 --collateral 100000000
srct-node credit --repay --position <position-hash> --amount 1
srct-node credit --list
```

Every one of these commands checks the transaction against the state the chain
will replay and refuses with the chain's own reason, rather than mining a
block the replay would skip.

Common options: `--network <mainnet|testnet|mini>` (default `mini`) and
`--data-dir <path>` (default `./chain`).

`serve` also takes `--listen`, `--connect`, `--bootnodes`, `--peers`,
`--interval`, `--api-listen`, `--api-token`, `--api-allowed-host` and
`--no-mine`. `--bootnodes` dials peers at startup (SPEC §13.6: v0.2 has no
ADDR gossip, so bootnodes plus `peers.json` are the only peer sources).
`--credit-issuer` lists the BLS keys trusted to sign credit attestations for
`POST /v1/credit/mint` (comma-separated 48-byte hex keys; with none listed,
every mint is refused).
`send --amount` takes SRCT (`--amount-sat` takes satoshis); printed balances
are in SRCT.

The API defaults to loopback and needs no credentials. Binding anything
non-loopback is refused unless a token is supplied:

```sh
# Non-loopback: a bearer token is mandatory (§19.2). Pass it through the
# environment, not --api-token: flags are visible in `ps`.
export SRCT_API_TOKEN="..."
srct-node serve --network testnet --data-dir ./chain --api-listen 0.0.0.0:8080

# Loopback: unchanged, and unauthenticated.
srct-node serve --network testnet --data-dir ./chain --api-listen 127.0.0.1:8080
```

Every request to an exposed bind must carry `Authorization: Bearer <token>`
(compared in constant time). Every bind — loopback included — requires a
`Host` header (DNS-rebinding defense): a loopback bind accepts loopback names
only, while a non-loopback bind additionally accepts any IP literal, the bound
address, and hostnames listed via `--api-allowed-host` (comma-separated) or
`SRCT_API_ALLOWED_HOSTS`. A missing, unknown, or bracket-malformed `Host` is
403. Exposed binds also rate-limit per remote address, and every bind caps a
request at 10 seconds, 64 requests in flight, 128 open connections, and 30
seconds to finish sending request headers (the slowloris bound).

Credit, escrow and delegation state is node-local and never consensus, but it
is no longer lost on restart: the books beside the chain (receipts, replay
tracker, payments and their settlement links, reservations, policy accounting,
credit and the attestations already minted, delegations, issued policies,
revocations, escrows and their exit bindings) persist to `state.bin` — an atomic,
digest-checked file with a fail-closed load (a corrupt file refuses to start)
— flushed when their bytes change, plus once at shutdown.

---

## Testing

```sh
cargo test --workspace                                   # 1404 passed, 0 failed, 1 ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
python sim/verify_vectors.py --check                     # consensus vectors
```

The test count above is refreshed from `scripts/test_count.sh`, which is the
single source of truth — run it and paste the total rather than hand-editing.

Targeted suites for the fast loops:

```sh
cargo test -p srct-core --test x402           # x402 challenge/budget/authorize/pay/admit roundtrip
cargo test -p srct-node --test x402           # 402 → verify → settle → retry over real HTTP
cargo test -p srct-policy                     # chain-agnostic decide/verify JSON seam
cargo test -p srct-mcp                        # keyless wallet guard, portable prove/verify, bound grants
cargo test -p srct-node --test micro_safety   # batch quotes, streams, sponsor intents, session/risk/audit
cargo test -p srct-node --test agent_economy  # passport, tiers, jobs, FX quotes, ramps, lending marketplace
cargo test -p srct-core --lib arbitration::    # fraud-arbitration votes
cargo test -p srct-core --test cp_signing_nodes # quorum, conflicts, restart
cargo test -p srct-core --test bond_stake      # bonded-stake attacks
cargo test -p srct-core --test committee_rotation # seed-epoch committees + reorg rollback
cargo test -p srct-miner                       # solver, stratum, payouts, backends
cargo test -p srct-node --test api external_miner # template/submit over HTTP
cargo test -p srct-l2  --test unverified_result # the unchallenged-result rule
cargo test -p srct-node --test arbitration_path # full fraud lifecycle
cargo test -p srct-net  --test arbitration_votes # 3 nodes, real TCP
cargo test -p srct-node --test exit_crank_api   # withdrawal flow over HTTP
cargo test -p srct-node --test state_persist    # books survive restart
cargo test -p srct-node --test api escrow       # escrow open/settle over HTTP
cargo test -p srct-core --test redteam          # adversarial regressions
cargo test -p srct-core --test redteam_round2   # round-2 credit regressions
cargo test -p srct-core --test pq_signature     # post-quantum bundle attacks
```

CI (`.github/workflows/ci.yml`) runs format, clippy, the full suite, a release
build, the vector cross-checks, attack simulations, and all 17 fuzz targets
on nightly with ASan. `.github/workflows/release.yml` re-runs the same gate on a
tagged tree before publishing artifacts with checksums and a keyless
cosign/Sigstore bundle.

**Every action is pinned to a commit SHA**, with the tag it came from in a
trailing comment, so a compromised or retagged action cannot silently change
what CI runs. Job tokens are least-privilege: `contents: read` by default, and
only the two jobs that genuinely write (the signing job's `id-token: write` for
the OIDC identity, the publish job's `contents: write`) take more. Dependabot
keeps the pins honest but opens **no pull requests** — every update PR is a
branch, and this repository keeps `main` as its only branch, so applying a bump
is an owner step (`cargo update -p <crate>` plus `cargo audit`). Security
*alerts* are unaffected: those come from the advisory database, not from PRs.

**Vectors.** `tests/vectors/` holds the consensus byte layouts, generated only
from the implementation. `sim/srct_reference.py` is a second PoW implementation
written from `SPEC.md` rather than from the Rust (by the same author — a second
implementation, not a second party), and it reproduces all 21 puzzle digests —
that agreement is evidence the spec is unambiguous rather than merely
self-consistent.

**Fuzzing.** 17 cargo-fuzz targets over L1 wire, mempool, storage and
checkpoints; L2 codec, disputes, state and certificates; and the worker. They
assert capability invariants — decode/encode inversion, bounded allocation, value
conservation under adversarial transaction programs — not just panic-freedom.

**Red team.** `crates/srct-core/tests/redteam*.rs` holds 21 adversarial integration
tests across four files (`redteam`, `redteam_credit`, `redteam_delegation`,
`redteam_round2`), each confirmed to fail against the code it now guards. The full
record of defects found and fixed is in [docs/status.md](docs/status.md).
Author-run, like everything above — see [Honest limits](#honest-limits).

---

## License

**Copyright © 2026 The Solar Cyber Unit developers.**

**Code: MIT** — the same permissive licence Bitcoin Core uses. The full text
ships at the repo root (`LICENSE-MIT`). You may use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the software, and permit
persons to whom it is furnished to do so, including commercially.

---

## Security

[`SECURITY.md`](SECURITY.md) is the disclosure policy: what counts as a
vulnerability, the severity model, the 90-day window, and the intake channel
(GitHub Security Advisory, or `security@solarcyberunit.org`). Do not open a public
issue for a security defect.

---

Full protocol specification: [`SPEC.md`](SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).
