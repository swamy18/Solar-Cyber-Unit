# Solar Cyber Unit (SRCT)

<img src="docs/assets/Solar_Cyber_unit.png" alt="Solar Cyber Unit coin logo" width="200">

Programmable money for machines: spend policies enforced at admission, escrow for verifiable work, micro-payments with a safety-first wallet, and a Smart Gate security layer any platform can verify. Pre-launch — no outside audit yet.

**Author and copyright:** The project is open source — see [License](#license).

**Built by:** Swamy Gadila. The project is open for anyone to use
and redistribute.

---

## Contents

- [What SRCT is](#what-srct-is)
- [The main pillars](#the-main-pillars)
- [Why a new coin](#why-a-new-coin)
- [Glossary](#glossary)
- [Honest limits](#honest-limits)
- [Quick start](#quick-start)
- [Machines and agents](#machines-and-agents)
- [Mining and AI compute](#mining-and-ai-compute)
- [Supply](#supply)
- [Cryptography, quantum security and security layers](#cryptography-quantum-security-and-security-layers)
- [P2P and storage](#p2p-and-storage)
- [API index](#api-index)
- [Timestamps](#timestamps)
- [Performance and verification](#performance-and-verification)
- [What the chain is for](#what-the-chain-is-for)
- [Layer 1 and Layer 2](#layer-1-and-layer-2)
- [Use cases and features](#use-cases-and-features)
  - [Agent payments (x402)](#agent-payments-x402)
  - [Micro-payments and wallet safety](#micro-payments-and-wallet-safety)
  - [Smart Gate (device-grid security layer)](#smart-gate-device-grid-security-layer)
  - [Agent economy](#agent-economy)
  - [SRCT Treats (tradeable reward claims)](#srct-treats-tradeable-reward-claims)
  - [How fraud is detected](#how-fraud-is-detected)
  - [How withdrawals work](#how-withdrawals-work)
  - [Validators and finality](#validators-and-finality)
  - [Wallets, transfers and policies](#wallets-transfers-and-policies)
  - [Credit and lending](#credit-and-lending)
- [Network profiles](#network-profiles)
- [Commands](#commands)
  - [Agent authority and credit, from the terminal](#agent-authority-and-credit-from-the-terminal)
- [Testing](#testing)
- [License](#license)
- [Security](#security)

---

## What SRCT is

SRCT (Solar Cyber Unit) is a mined cryptocurrency on its own UTXO blockchain (Layer 1), with a task economy on top (Layer 2) where one machine can pay another for compute work without trusting it.

In one paragraph: an owner writes a spending policy once and signs it offline; from then on every spend by their agent or device is checked against that policy when the transaction reaches the network — a violating payment never enters a block, the same way a double-spend never does. Machines bill each other per API call or per job through the x402 payment shape and through escrowed tasks: money is locked first, work is submitted, anyone may challenge a result, and a committee settles who gets paid. New coins come only from mining; there was no premine. Fees are split between a burn and an on-chain reserve, so usage removes coins from circulation while paying for security.

What you can do with it today:

- **Hold and move coins** with ordinary wallets and transfers on a Bitcoin-shaped UTXO chain.
- **Mine** with a CPU from inside the node or with the standalone `srct-miner` (pools supported).
- **Authorize agents and devices** with signed spending policies enforced by every node at admission.
- **Sell or buy compute** through the compute marketplace (offers, jobs, receipts) and earn SRCT.
- **Accept per-call payments** as a service via x402, batch quotes and stream channels.
- **Run verifiable tasks** on Layer 2: escrow, challenge, committee settlement, verified-work certificates, withdrawals back to Layer 1.

How SRCT differs from other cryptocurrencies:

| | Most chains | SRCT |
|---|---|---|
| Agent spending rules | A smart contract that advises; the base layer does not know about it | Checked at admission by consensus — a violating spend is refused like a double-spend |
| Machine micro-billing | One transaction per call, or off-chain IOUs | x402 shape with batched quotes and stream channels that settle once |
| Buying compute | Trust the seller, or trust an escrow company | Escrow + challenge + committee settlement in the protocol, with slashing |
| Agent safety | Each app rolls its own permissions | Smart Gate: owner-signed capabilities bound to the exact action, verified everywhere |
| Money for AI work | Paid off-chain, unverifiable on-chain | Settled work yields a verified-work certificate the worker can show anyone |

Pre-launch, the codebase also contains labelled **non-consensus prototypes** (DiLoCo training, encrypted compute, ZKML proofs, cross-network intents and others). They are real, tested library code, but they do not move Layer 1 coins and are not consensus. Read [Honest limits](#honest-limits) before trusting any number in this file.

---

## The main pillars

SRCT is one coin doing six jobs. Each job is a separate layer — you can use one without the others — but they all settle in the same coin.

### 1. Native currency

SRCT itself is an ordinary mined coin on a UTXO chain (Layer 1). Wallets, transfers, blocks and P2P work like any Bitcoin-shaped chain: 1 SRCT = 100,000,000 sats, integer-only accounting, no floats anywhere. New coins come only from mining (`hybrid-v1` proof of work); genesis minted nothing, so the premine is 0%. There is no stock cap — a halving ladder issues 39,157,124 SRCT, then a small tail emission pays miners forever. Every block's base fee splits 50/50 into a burn and the on-chain PSCB leg (retained PSCB plus the 5% B-Saver floor and the 10% SRCT Treats backing), so usage removes supply from the spendable set. Full detail: [Supply](#supply), [Mining and AI compute](#mining-and-ai-compute).

### 2. Mining and selling AI compute power

Mining secures the chain with hash-based proof of work, and the same participant software lets a machine sell its compute instead: it advertises capacity, takes jobs from the marketplace, runs real inference or training work, and gets paid per settled receipt. One box runs in exactly one dedicated mode at a time — 100% mining or 100% AI compute — never a split share. Consumers dispatch incoming jobs between AI training and AI inference handlers. Full detail: [Mining and AI compute](#mining-and-ai-compute).

### 3. AI agent authorization

An owner writes a spending policy once — per-transaction cap, tumbling window cap, named recipients, named services, validity heights, a strictly increasing nonce — and signs it offline. From then on every spend by that agent is checked against the policy at admission, the same way the chain refuses a double-spend: a violating payment never enters a block, even with the owner offline. A signed policy travels as a portable grant any rail can verify without a node, delegations chain root-first with a narrowing rule, and short-lived grants bind one exact transaction with a 30-block lifetime. The `srct-policy` crate (plus `POST /v1/policy/decide` and the TypeScript/Python bindings) gives the same allow / deny / approval-needed answer off chain as on it. Full detail: [Machines and agents](#machines-and-agents).

### 4. Machine payments

Per-call billing without a transaction per call. Agents bill over the x402 challenge/response shape (`402 Payment Required` → `PAYMENT-SIGNATURE` → `200` with receipt), batched quotes merge N payments into one transaction, stream channels settle a whole usage window once, and sponsors can cover fees without minting authority. None of this changes consensus — every primitive reuses ordinary `MachinePayment`s under a spend policy — and the wallet around them is gated by construction: session budgets, enforced high-value human approval, idempotency, receipts with reconciliation, and a hash-chained audit log. Full detail: [Agent payments (x402)](#agent-payments-x402), [Micro-payments and wallet safety](#micro-payments-and-wallet-safety).

### 5. Wearable technology and everyday devices

There is no wearable-specific chain code, and this README does not claim otherwise. The device story is a usage pattern over the implemented machine layer: a watch, sensor hub, solar gateway or robot is a `Machine`-role identity (`derive_agent_id`) spending under an owner-signed policy with tight caps and named recipients. A wearable can therefore stream tiny payments for the data or actions it produces — each reading billed through a stream channel or batched quote — while the owner stays offline and the policy enforces the budget. If the device is compromised, the damage is bounded by the caps and the owner revokes the grant. Full detail: [Machines and agents](#machines-and-agents), [Wallets, transfers and policies](#wallets-transfers-and-policies).

### 6. Verifiable task economy

Layer 2 is where compute gets paid for without trusting either side. A submitter locks escrow for a described task, a worker claims it and submits a result hash, anyone may challenge with a counter-result, and a committee settles: correct work is paid, fakes are slashed (half burned, half vested), the challenger earns a bounty. Fraud is decided by a canonical CPU reference over the task's own committed fields — nobody can dictate the verdict, and an inconclusive arbitration settles nothing. Settled work yields a verified-work certificate, and value exits back to Layer 1 through a queue, maturity and a permissionless crank. Full detail: [What the chain is for](#what-the-chain-is-for), [How fraud is detected](#how-fraud-is-detected), [How withdrawals work](#how-withdrawals-work).

---

## Why a new coin

The honest question: x402 payments, spend policies and escrow could live on an existing chain or on stablecoin rails. Three reasons they don't here:

1. **Policies are enforced at admission, by consensus — on SRCT, the reference chain.** A spend policy on another chain is a contract the base layer does not know about — it can advise, not refuse. Here `check_tx` refuses a payment that violates its policy the same way it refuses a double-spend. The *decisions* travel: portable grants, the `srct-policy` engine and `POST /v1/policy/decide` let any rail ask the same question — but spending SRCT still requires SRCT admission. No policy-aware base layer, no guarantee.
2. **The task economy settles in the native coin.** Escrow, slashing, bonds and fee burns are chain state, not contract balances — a dispute payout cannot be frozen by a token issuer and does not depend on a bridge.
3. **One fee market, one audit trail.** Batch quotes, streams, receipts and reconciliation all price in the same unit the miners are paid in, so the cost model in [`docs/micropayments.md`](docs/micropayments.md) is exact rather than an oracle away from exact.

The trade is stated openly: a new chain must earn its security and its liquidity from zero, and nothing here removes that cost.

---

## Glossary

Every piece of jargon, in one line each:

| Term | What it is |
|---|---|
| `PSCB` | Protocol-owned leg: half of every base fee (retained PSCB plus the B-Saver floor and the Treats backing); pays whistleblower bounties and vesting. |
| `Treats` | Transferable reward claims for agents/machines/robots, backed by 10% of the PSCB leg and redeemable via single-use vouchers (fee credit, discount, trial, service credit). Never a UTXO, never spendable as coin. |
| `VWC` | Verified-work certificate: a credential derived from a *settled* task — proof work was paid for, never a self-claim. |
| `TopN` | Committee rule: the N largest bonds form the validator set (N = 21). |
| `PPLNS` | Pool payout rule: pay per last N shares — rewards recent work, resists pool-hopping. |
| `VWB` / escrow | The locked funds behind a task or trade, released only by the rules both sides agreed to. |
| `sats` | Smallest unit: 1 SRCT = 100,000,000 sats. Integer-only accounting, no floats. |
| `state.bin` | One node's local books (payments, jobs, reputation, Treats…). Restarts survive; other nodes may disagree — see [Honest limits](#honest-limits). |
| `mini` / `testnet` / `mainnet` | Network profiles: same code, different parameters (fast local testing → real deployment). |

---

## Honest limits

What this project is not, and where trust actually lives. Read this before trusting any number in it:

- **No outside audit.** Every test, red-team suite, simulation and the Python reference implementation were written and run by the author. Counts are real (`scripts/test_count.sh` reproduces them) but self-reported — treat them as diligence, not certification.
- **Verification is optimistic.** A submitted result settles as-is if nobody disputes it within the window — including a wrong one (`srct-l2/tests/unverified_result.rs` pins this rule). The dispute path re-executes and slashes fakes, but only if a challenger shows up. Running challengers is part of operating this network, not an optional extra.
- **Useful-work mining is staged, not live.** The neural-shaped `hybrid-v1` puzzle is hash proof of work. The separate DiLoCo proof-of-useful-work package trains a real model with signed updates and Byzantine filtering, but it is not consensus-active: it is enabled on `testnet` (height 1) while `mainnet` stays at height 0 awaiting on-chain governance activation. Hardware backends (CUDA, ROCm, TPU, NPU, Apple-silicon, photonic) fail closed with `Err(Unavailable)` where drivers are absent and fall back to CPU. See [`docs/dual-mining.md`](docs/dual-mining.md).
- **Compute settlement is instructions, not coin movement.** `srct-compute` plans capacity-aware shards, checks receipts and records exact settlement instructions (`PayoutInstruction { from, to, amount }`) — it does not itself move Layer 1 coins. The marketplace is wired into `srct-node` via REST (`POST /v1/compute/offers`, `GET /v1/compute/offers/list`, `POST /v1/compute/jobs`, `GET /v1/compute/jobs/list`, `POST /v1/compute/plan`, `POST /v1/compute/receipt`, `GET /v1/compute/receipts/list`) with persistence in `state.bin` (envelope v14). See [`docs/compute-sharing.md`](docs/compute-sharing.md).
- **The service crates are non-consensus prototypes or integration seams.** DiLoCo training, CNNP adapters, cross-network intents, agent messaging, compute sharing, FHE, ZKML, the unified verifier and the work graph are real tested libraries, but they do not activate useful-work mining and do not independently transfer Layer 1 funds. Intent settlement hands payment or refund instructions to the existing escrow layer; it verifies no foreign chain and holds no custody. A CNNP adapter proves who fitted it, not that two models mean the same thing. See [`docs/intents.md`](docs/intents.md), [`docs/cnnp.md`](docs/cnnp.md), [`docs/agentnet.md`](docs/agentnet.md).
- **Reputation, jobs, FX and ramps are per-node views.** They live in each node's `state.bin`, not in consensus — two honest nodes can disagree on a score, a quote or a job state. Consensus money (UTXOs, bonds, L2 accounts) cannot disagree. Never treat another node's score or quote as fact; run your own node.
- **FX issuers and ramp providers are trusted.** Rates come from a configured whitelist, custody never touches the node — the chain stores the signed audit trail, not the dollars. If an issuer lies, the trail proves it; it does not prevent it.
- **Mainnet cold start is public.** The 21 bootstrap keys are deterministic in source — anyone can sign alongside a bootstrap validator until the first bond rotates authority. Serving mainnet with them requires the explicit `--allow-bootstrap-committee` flag, and replacing them with bonded keys is the operator's first job.
- **Bindings need a node.** The TypeScript/Python bindings are codecs, not verifiers — allow/deny answers come from a node (`/v1/policy/decide` and friends) or the Rust engine, never from the binding alone. No node, no decisions.
- **`srct-policy` is a facade, not a slim dependency.** Vendoring the crate still compiles all of `srct-core` (BLS, ML-DSA and all). Outsiders wanting answers without Rust use HTTP or the bindings against a node URL.
- **The exit window is shared, and one share is capped.** Mainnet lets one owner queue 100 SRCT per 144-block window: a genuinely large exit waits across windows. Refusals delay, never destroy — but plan around it.
- **The Smart Gate is per-node authority over a plaintext loopback transport.** Gate decisions are enforced by whichever node or runtime observes the bytes — there is no cross-node capability lock, and multi-node deployments converge by registering the same owner-signed grants and replicating revocations, plus owner-set audience scoping for high-value capabilities. The worker/MCP HTTP clients are plaintext `host:port` transports: loopback is the supported shape. Gate audit receipts are node-local and export-verifiable, not chain-anchored; managed-cluster admission webhooks are designed but not implemented (the worker SDK's in-process `GuardGate::execute` is the implemented reference boundary).
- **Slash vault is empty by construction (for now).** M2 (`slash.rs`, 50% burn + 50% vest) is defined and tested, but nothing creates a slash record yet.
- **Mainnet L2 settlement is fail-closed.** Its validator set starts empty, so settlements refuse until configured; testnet/mini use deterministic keys.
- **HBM is staged, VWC mining is opt-in, PQ spend is off, PoUW is off on mainnet.** `hbm-v1` (`puzzle_id = 2`) is registered, never active; `vwc-v1` (`puzzle_id = 3`) mines only where a profile sets it; `pq_activation_height = 0` and `pouw_activation_height = 0` on mainnet (age-gated when flipped, testnet rehearsal first).

---

## Quick start

Requires **Rust 1.75+** (developed and tested against 1.99) and **Python 3.11+** for the simulations.

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

`verify` replays the whole chain from genesis and diffs the resulting UTXO set, supply, bond ledger and binding-finalized point against stored state. It is the check worth running after any change.

To stand up a local multi-node network (deterministic genesis, separate data dirs, node 1 as seed, the rest dialling it via `--bootnodes`):

```sh
scripts/start-network --nodes 3          # init, serve, wait until all share a tip
scripts/stop-network                     # graceful stop via pid files
scripts/reset-network                    # stop and delete the data root
```

Run `srct-node help` for the full command list; every command accepts `--help`.

---

## Machines and agents

One policy layer for software acting on someone else's behalf. It lives in `srct-core/src/agent.rs` and is **pure and deterministic** — no clock, no randomness, no I/O — so a wallet and a service reaching the same inputs reach the same answer.

- **Agent identity.** `derive_agent_id(network_id, role, owner)` gives a stable identifier. Three roles exist: `Human` (a wallet), `Machine` (a device spending under a policy), and `Service` (an identity that *receives* payments). The ID is network-bound, so the same device has different IDs on different chains.
- **Spending policies.** A `SpendPolicy` is owner-signed and answers exactly one question: *may this agent, at this height, spend this much to this recipient?* Every refusal is a named error, and the ambiguous cases all fail closed: an empty recipient list authorizes nothing, an empty service list authorizes no service-tagged payment, a nonce must strictly increase, cumulative spend is bounded per window, and validity is checked against heights, never wall-clock time.
- **No second currency.** The `owner` field is an ordinary address, so machine and human balances live in the same UTXO set under the same issuance schedule. There is no separate "machine token".
- **Portable grants.** A `SignedPolicy` is the policy plus the owner's signature — the unit that travels. Anyone holding the bytes (another chain, an x402 facilitator, an insurer's auditor) verifies the grant with no node, no chain state and no private key. A `DelegationProof` is the root-first chain of signed policies with a narrowing rule, capped at depth 8. Full interface: [`docs/portable-policy.md`](docs/portable-policy.md).
- **Short-lived, exact-transaction grants.** `BoundAuthorization` turns an advisory approval into an enforced one: the owner signs the grant hash, the expiry and the *exact transaction hash* together, with a 30-block lifetime cap. A stolen authorization re-aimed at another payment, or replayed past its window, is refused by name.
- **Chain-agnostic engine.** The `srct-policy` crate answers `allow`, `deny` or `approval-needed` for a `PaymentIntent` — the same decision the node reaches, with no consensus imports. TypeScript and Python bindings speak the same JSON over `POST /v1/policy/decide`. Honest weight note: the crate still compiles all of `srct-core` — outsiders wanting answers without Rust use HTTP or the bindings against a node URL.
- **Payments and receipts.** `MachinePayment` is the canonical format. `ReceiptBook` refuses a receipt that conflicts with an existing one for the same payment; `PaymentTracker` is an exact-payment replay guard. A settled payment carries its proof: `POST /v1/payment/{id}/settle` binds the Layer 1 transaction that paid it, `GET /v1/payment/{id}` reports the link, and the link persists across restarts.
- **Reputation.** A bounded accumulator per identity, driven by a **fixed weight table in code, not data**: service completed +1, payment completed +1, verified work +2, dispute won +1, **dispute lost −3**. An event carries no amount, weight or signature of its own, so weights are not forgeable. It is **not mintable**: nothing here creates a token.
- **Streaming micro-payments.** `PaymentStream` is pay-as-you-use: a payer-signed rate per block, a window, a hard cap, a recipient, and the governing policy for non-human payers. Settlement rides the ordinary payment path with the stream id as reference, so there is no new transaction type.
- **MCP surface.** `srct-mcp` is a keyless MCP surface over agent identity, payments, receipts and reputation — and an **agent wallet guard**: `wallet.guard` runs the budget plus a short expiry before any key is used (allow / deny / approval-needed), `policy.decide` answers the engine statelessly, `policy.export`/`policy.verify` and `delegation.prove`/`delegation.verify` move portable grants across rails, `auth.bind`/`auth.verify_bound` enforce the short-lived exact-transaction grant, and `audit.verify` checks an exported audit chain.

**Agent helpers (`srct-worker`).** Seven single-purpose commands over a node URL — no local chain data needed, no consensus touched: `verify-cert` (quorum-backed or merely unchallenged? exits `0` verified, `2` paid-not-verified, `3` no certificate), `grant` (owner key → bounded grant, prints `policy_hex`), `claim` / `submit-result` (the two signing steps a plug-and-play template drives), `pay` (x402 with a client-side budget), `stream-open` / `stream-voucher` / `stream-status`, `batch-quote` (price one shared settlement for N recorded payments, read-only), and `trial-request` / `trial-fund` / `trial-status` / `trial-repay` (one sponsored first task per agent, ever). `grant` → `pay` is the intended chain; `claim` → `submit-result` is the template chain (`templates/srct_agent.py`).

**Trial faucet (operator setup).** Trials stay disabled until a sponsor is configured — with no sponsor there is no money behind a trial, so every request is refused:

```sh
export SRCT_TRIAL_SPONSOR=<sponsor-address>   # pays real SRCT per trial
export SRCT_TRIAL_AMOUNT_SAT=1000000         # default: one L2 minimum deposit
export SRCT_TRIAL_MAX_OUTSTANDING_SAT=10000000  # sponsor exposure cap
```

### Consensus state vs. service layer

The spending-policy layer is consensus state (SPEC §21). A grant is published on chain, the owner's signature binds it to a named spender and a named agent, the caps, allow-lists and nonce are enforced against state the chain keeps, and revoking a grant kills every descendant of it. The same is true of credit (SPEC §22): a loan is a chain fact with the lender's signature over its terms, principal really moves, and the collateral answers for the debt.

The *service layer* around them is still node-local: the payment book, the receipt book, the credit gate used for admission and the authorisation helper the API issues offline. Those are operational bookkeeping, not sources of spendable balance — they persist to disk so they survive restart, but consensus never depends on them.

---

## Mining and AI compute

Three ways to mine, from simplest to pooled. All three produce the same blocks and pay the same coinbase — the difference is only where the grinding happens.

Hash mining is the only consensus mechanism today. The separate DiLoCo proof-of-useful-work prototype in `crates/srct-diloco` trains a real model and validates, scores and pays contributions, but it is **not consensus-active** (enabled on `testnet` at height 1; `mainnet` stays at height 0 awaiting governance). See [`docs/dual-mining.md`](docs/dual-mining.md) for the measured results, the threat model and the fork work still required.

**Where the reward goes.** Every block pays its coinbase to one address: the node's miner wallet for in-node mining, or the `--miner` address you pass to `srct-miner`. New coins are **immature** first — spendable after 100 blocks on mainnet, 10 on testnet/mini — then they are ordinary UTXOs. Check them with `srct-node balance --address <addr>` or `status`.

**Difficulty, honest numbers.** Every profile starts at difficulty 1 (trivially mineable — a laptop mines block after block on a fresh chain) and retargets every block toward its target spacing (10 minutes mainnet, 1 second testnet/mini), at most ±10% per block. As miners join, difficulty rises and the same hardware finds fewer blocks. Measured reference: ~114k H/s on 4 CPU threads (release build, `hybrid-v1`), so one such machine holds ~10-minute blocks alone until difficulty passes ~68M. Launch is CPU-fair by construction; difficulty does the hardening, not special hardware.

**The puzzle.** The registry ships three entries; only the first grinds today:

| Puzzle id | Name | Commits to | Active on |
|-----------|------|------------|-----------|
| 1 | `hybrid-v1` | block fields only | `mainnet` / `mini` / `testnet` (default) |
| 2 | `hbm-v1` | memory-hard scratchpad | staged, never active (ASIC-pressure route) |
| 3 | `vwc-v1` | block fields + latest verified-work-certificate id | opt-in (`puzzle_id: 3`) |

`hybrid-v1` runs three stages: a SHA-256 hash chain (carries the security), an integer-only neural-network-shaped stage with epoch-derived weights (no training, no inference — what it buys is hardware diversity, not AI output), and a final hash binding both into the value that must fall below the target. No floating point anywhere; a capped share (30–50% of modelled work) keeps the neural stage a cost model rather than a liability. `vwc-v1` binds mining to useful L2 compute: `header.extra_nonce` carries the latest verified-work-certificate id, and consensus enforces the commitment. No bond, no cap, no identity required. Full detail: [`docs/mining.md`](docs/mining.md).

### Option A — mine inside the node (simplest start)

```sh
export SRCT_WALLET_PASSPHRASE=change-me
./target/release/srct-node init --network testnet --data-dir ./chain
./target/release/srct-node serve --network testnet --data-dir ./chain \
  --listen 127.0.0.1:9833
```

`serve` mines by default into the wallet created by `init`. One command, no other software. Good for: first launch, testing, solo mining while the network is small.

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

How it works: `GET /v1/mine/template?miner=<hex>` returns an unsolved block (`block_hex` plus height/difficulty/puzzle id); the miner grinds `nonce` and `extra_nonce` until the proof passes, then `POST /v1/mine/submit {"block_hex": ...}` hands it back. The node re-validates everything — template, proof, tip, timestamp — so a stale or forged solution is refused, never half-applied. Any HTTP client can do this loop; the binary just does it well (multithreaded, `--threads N` with `0` = one per CPU capped at 1024, `--batch N` capped at 65536, `--backend cpu|portable|auto`, automatic retry with backoff).

The `--miner` address need not belong to any wallet on the node — it is just where the coinbase pays out. Pools speak stratum-lite JSON-lines (`getjob`/`submit`, single-use job ids, anti-theft template pinning, share vs network difficulty) with PPLNS over the last-N shares (N ≈ two blocks, `fee_bps`, dust carried, `mark_paid`, `PPLNS_MAX_WINDOW` = 1M).

### Selling compute instead of hashing

A participant runs `templates/srct_node.py` as a dedicated node. Resource-sharing is mutually exclusive and 100% dedicated — fractional splits are refused:

- **Mining mode (`mode="mine"`):** 100% of CPU and system threads go to proof-of-work mining via `srct-miner`. AI compute polling is completely disabled.
- **AI compute mode (`mode="ai_compute"`):** 100% of system RAM and compute capacity go to the AI marketplace. Proof-of-work mining is completely disabled.
- **Consumer dispatch (inference vs training):** incoming jobs route dynamically — jobs shaped as inference (`infer_fn`, `task["type"] == "inference"`) run the inference path; training jobs (`train_fn`, `task["type"] == "training"`) run the training path. Worker processes can execute real external programs (Python, ONNX, llama.cpp and others) through the `CommandExecutor` in `srct-worker`.
- **Marketplace integration:** the participant talks directly to the node's compute REST endpoints (`/v1/compute/offers`, `/v1/compute/jobs`, `/v1/compute/receipt`), so offers, assignments and receipts are the same objects the node stores.

How providers and consumers interact: a provider posts a signed offer (capacity, price, device profile); a consumer job is planned into deterministic cheapest-complete shard assignments; the worker claims and runs it, then posts a receipt; `ComputeLedger::settle` checks the binding, price, deadline and once-only rule and returns the exact payout instruction. Settlement instructions are exact — overclaims and double-settles are refused — but the compute crate itself moves no Layer 1 coins; the rail executes the instruction. Self-test: `python templates/srct_node.py --selftest`.

How SRCT technology supports AI training and AI inference:

| Workload | Where it runs | Status |
|---|---|---|
| Inference jobs | Compute marketplace → participant `infer_fn` / external model runtimes | Integrated via node REST + receipts |
| Training jobs | Compute marketplace → participant `train_fn` | Integrated via node REST + receipts |
| DiLoCo distributed training | `srct-diloco` prototype (real MLP, signed updates, Byzantine filtering) | Real tested code, **not consensus-active** |
| Hardware backends | CUDA/ROCm/TPU/NPU/Apple/photonic adapters | Probe-and-emulation; fail closed without drivers, CPU fallback |

---

## Supply

There is **no stock cap**. That is a deliberate change — see [Decision 18](docs/decisions.md).

**The ladder** halves in whole SRCT every 262,800 blocks (~5 years at a 10-minute block):

```
76, 38, 19, 9, 4, 2, 1 SRCT
```

Whole SRCT, not shifted satoshis.

**Premine is 0%**, enforced in code rather than in prose. Genesis mints nothing.

**The ladder totals exactly 39,157,124 SRCT.** Genesis occupies a rung-0 height without minting, so the first rung is paid by `H − 1` blocks rather than `H`. That 76 SRCT is the difference between the geometric shortcut (39,157,200) and what the chain can actually reach, and `supply::max_issuance_sat` reports the real figure.

**The tail** takes over after the ladder (height 1,839,600) and never stops:

```
0.50 → 0.25 → 0.125 SRCT, then a permanent 0.1 SRCT floor
```

Issuance continues forever, reaching the floor at height 2,628,000 (~50 years). Testnet and mini pay a constant 1 sat per block from their first tail period.

**Two bounds enforce this**, both checked in `Chain::apply_block` so the miner, validator and node cannot disagree about what is mintable at a height:

1. **The issuance integral.** A block may not mint past `cumulative_issuance_sat(height)`. Overflow is refused rather than wrapped.
2. **The rate anchor.** After ladder exhaustion, gross issuance inside the current halving window may not exceed **1% of the supply issued at that window's start**. The approved schedule sits ~3× under it, so the anchor never binds today — it exists to refuse a *future* schedule that would dilute far faster. The ladder era is grandfathered.

**Net supply can fall.** The base fee splits 50/50 into a burn and an on-chain reserve leg (retained PSCB + B-Saver + Treats backing), so usage *removes* supply from the spendable set. Combined with a declining tail reward, the simulation measures net supply falling below break-even at ≈5% activity and reaching 25% removal at the fee floor. This is a measured consequence, not a bug — the analysis and sensitivity tables are in [docs/monetary-policy.md](docs/monetary-policy.md).

Gross issuance, removal and net supply are reported by `status`, `GET /v1/conservation` and the `/metrics` gauges. Conservation passing does not mean nothing was stolen — a thief's exit conserves perfectly — so `/v1/conservation` also reports the exit-outflow watch (`exit_window_total` vs cap, `pending_exit_sat`): alert on a window filling fast, not on the invariant staying green.

Small consensus rules worth knowing: `lock_time` is enforced — a transaction with `lock_time > height` is refused, so a timelocked payment cannot mine early. A full mempool evicts the single lowest-fee-rate entry when a strictly higher-rate transaction arrives. Difficulty retargets every block (LWMA, ±10%, solve-time clamp `[T/4, 5T]`); the future-timestamp ceiling is policy at admission, never a consensus split. Exit claims need exact funding — sink outputs summing *exactly* to `amount + fees`, no change or tip — or the exit waits.

---

## Cryptography, quantum security and security layers

### What protects a coin today

| Primitive | What it is | Where |
|---|---|---|
| Hash | SHA-256 internal, SHA-512 64-byte `txid`/`block_hash` — ~128-bit Grover + ~85-bit BHT margin on the two ids attackers want most | `SPEC.md §0` |
| Signatures | `1` secp256k1 ECDSA (low-s), `2` Schnorr, `3` ML-DSA-65 FIPS-204 level 3; hybrid bundle `1+3` is quantum-safe (Shor on secp256k1 alone forges nothing) | SPEC §1.2, `sig.rs` |
| Domains | Every hash input carries a frozen ASCII tag (`DOM_BLOCK512`, `DOM_S1`, `DOM_S3_VWC`, …) — tags never change for a `/v1` suffix | `SPEC.md §0` |
| PQ migration | `verify_input_pq` refuses bundles without scheme 3; activation is age-gated (`pq_activation_height`, `0` = off) so history is never stranded | Decision 24, `pq_signature` / `pq_migrate` tests |
| Checkpoints | BLS12-381 min-pk via `blst` (G1 48B, G2 96B, DST) stays; ML-DSA-65 sidecar carries the same decision per signer, verified as clause-7 shape on checkpoints and VWC `Quorum` certs | `bls_checkpoint.rs`, `validators::check_sidecar`, `pq_checkpoint` / `pq_settle` tests |

Rejected, on record: BLS → ML-DSA multisig (3 KB × N explosion), SPHINCS+ in the checkpoint envelope (8–30 KB, unrelayable). SPHINCS+ stays an idea for cold evidence only.

### Designed to survive quantum computers

Quantum resistance comes from three implemented mechanisms, not from promises:

1. **Hash strength with margin.** Transaction and block ids are 64-byte SHA-512 digests. Even under Grover-accelerated search the work factor keeps roughly a 128-bit margin, with an ~85-bit margin against the best known preimage-plus-collision trade on the two identifiers an attacker wants most.
2. **Hybrid signatures, available now.** Every signature the gate, the policy engine and x402 payments verify travels as a hybrid bundle: scheme 1 (ECDSA) plus scheme 3 (ML-DSA-65, FIPS 204 level 3). Every component must verify, components match by scheme id rather than position, and the address commits to the whole key set — so breaking secp256k1 with Shor forges nothing while the lattice component stands. Wallets can already generate classical, hybrid or post-quantum keys. Network-wide enforcement is staged: `pq_activation_height = 0` (off) on every profile, age-gated when flipped so only outputs created at or after the height must carry the lattice component.
3. **Checkpoint quorum with lattice sidecar.** Binding-finality checkpoints aggregate BLS signatures at a 2/3 quorum (6667 bps) and carry a per-signer ML-DSA-65 sidecar list, so the long-range history anchor does not depend on elliptic-curve assumptions alone.

### The security layers, and how they interact

SRCT defends in four layers. Each layer answers a different question, and each inner layer holds even if an outer one is bypassed:

| # | Layer | Question it answers | How it works internally |
|---|---|---|---|
| 1 | **Admission policy** | *May this coin move under this grant?* | `SpendPolicy` checked in `check_tx` against chain state: window, per-tx cap, allow-lists, strictly increasing nonce, revocation set. Refusal happens before block inclusion — no gas is wasted on it. |
| 2 | **Smart Gate** | *May this workload do this exact action right now?* | Owner-signed `InfraPolicy` registered on the enforcing node; per execution the owner signs a capability bound to `policy_hash \|\| action_hash \|\| context_hash \|\| expiry \|\| nonce`. The boundary recomputes the hashes from the bytes it observes — one bit of drift denies. Tumbling window + strictly increasing nonce per grant, max 30-height lifetime, audience scoping to one node for high-value capabilities, revocation kills the grant and every descendant. Stateless pre-check (`guard.check`, `POST /v1/guard/decide`) commits nothing; stateful admission (`guard.authorize`, `POST /v1/guard/authorize`, `GuardGate::execute`) commits window + nonce. |
| 3 | **Wallet safety** | *May this key sign under current conditions?* | Session budgets cap aggregate spend across rotated policies; high-value spends are *enforced* to need a co-signer from an approver list (the payer's own key does not count; mainnet defaults to gating at 10 SRCT); velocity caps bound payments per payer; idempotency (`PaymentTracker`, `ReceiptBook`) refuses replays and conflicting receipts; every grant, admission, refusal, stream and receipt appends to a hash-chained audit log that exports as auditor-readable JSON. |
| 4 | **Settlement finality** | *Is this history what everyone agreed on?* | Depth-based finality plus binding checkpoints from the TopN bonded committee (BLS quorum + lattice sidecar); equivocation burns the full bond; slash vault splits 50% burn / 50% vest. |

How they combine: the wallet layer stops a stolen key from draining funds; the Smart Gate stops a compromised workload from turning a valid key toward an action the owner never approved; the admission layer stops a crafted transaction from entering a block even if both outer layers are bypassed; finality stops history itself from being rewritten after the fact. Audit receipts are node-local and export-verifiable rather than chain-anchored, so routine interactions are audited without paying a chain fee for each one — only final settlement settles on chain.

A note on naming: there is no separate "Smart Grid" crate in the codebase. The implemented layer that secures grids of devices, workloads and agents — capabilities, grants, revocation, audit — is the **Smart Gate** (`srct-core/src/guard.rs`, [`docs/smart-gate-architecture.md`](docs/smart-gate-architecture.md)). Any "grid" deployment is Smart Gate grants registered on each enforcing node with audience scoping.

---

## P2P and storage

**P2P (`crates/srct-net`).** Framing is `magic || type || length` with the magic re-checked on every frame; handshake exchanges magic + network id + protocol version + nonce (proof-of-socket, 20 s timeout). Network magic bytes (§13.3): `mainnet` = `6A4E5402`, `mini` = `6A4E5403`, `testnet` = `6A4E5404` — they move with each protocol version that changes the wire format or state root, so pre-bump peers are refused at framing before they can join. v0.2 has no ADDR gossip — bootnodes plus `peers.json` are the only peer sources. Relay is `INV -> GETDATA -> TX/BLOCK`; bad magic after handshake is an immediate ban, handshake failures score per IP, in-flight counts are capped. A handshake is never authentication.

**Storage (`crates/srct-store`).** Append-only checksummed block log plus atomic metadata and a canonical index — no consensus rules inside. `flush` vs `sync` is an explicit durability contract; a crash mid-append leaves a partial last line that recovery drops. Covered by 30 `persist_crash` tests.

---

## API index

112 `/v1/` routes. The guide sections above show the main flows; the full set:

- Node: `GET /v1/health`, `/v1/status`, `/v1/finality`, `/v1/fees`, `/v1/mempool`, `/v1/block/{hash}`, `/v1/block/latest`, `/v1/balance/{address}`, `/metrics`
- Money: `GET /v1/conservation`, `POST /v1/l2/broadcast`, `GET /v1/l2/state`, `POST /v1/credit/open|repay|default|deposit|bond|mint`, `GET /v1/credit/*`, `GET /v1/exit/crankable`. Node-local `credit/open` requires lender + borrower signatures; `credit/bond` and `credit/repay` require the named account's signature. These operations are separate from consensus L2 credit positions. `credit/deposit` is an unbacked local test/admin credit writer, not an L1 deposit; it is disabled on exposed API binds.
- Escrow: `POST /v1/escrow/open`, `GET /v1/escrow/{id}`, `POST /v1/escrow/{id}/release|settle` (release binds the delivered result hash; dispute freezes via `held_escrows`)
- Guard/policy: `POST /v1/policy/decide`, `/v1/policies*`, `/v1/guard/grant|decide|authorize|revoke`, `POST /v1/delegation/link|verify`, `POST /v1/authorize`
- Compute: `POST /v1/compute/offers`, `GET /v1/compute/offers/list`, `POST /v1/compute/jobs`, `GET /v1/compute/jobs/list`, `POST /v1/compute/plan`, `POST /v1/compute/receipt`, `GET /v1/compute/receipts/list`
- Full list is the router in `crates/srct-node/src/api.rs` — SPEC §19 is normative when they disagree.

---

## Timestamps

Heights order money; wall-clock time only advises. The rules:

- **Genesis time.** `GENESIS_TIMESTAMP_MS` is fixed in code (2026-01-01). Deterministic harnesses build chains at `GENESIS + h*1000`.
- **Block pacing.** Target spacing is 10 minutes on mainnet, 1 second on testnet/mini. Difficulty retargets every block (LWMA, ±10%, solve-time clamp `[T/4, 5T]`).
- **No future-drift splits.** Consensus enforces only a lower bound on block timestamps (median of the lookback window). The future ceiling (`timestamp > now + one block time`) is policy at admission (`validate_local_clock`) — a too-far-future block is refused by the receiving node, never a chain fork.
- **Money uses heights, not clocks.** `lock_time > height` refuses the transaction, so a timelocked payment cannot mine early. Policies, capabilities and stream windows all expire in heights (`not_before`, `expires_at`, 30-block grant lifetimes), so identical inputs decide identically on every machine with no clock to disagree about.

---

## Performance and verification

- **Bench:** `crates/srct-bench` builds deterministic chains — `run --workload empty|realistic|adversarial --blocks N`, mini profile, `GENESIS + h*1000` timestamps, RSS budgets. Production `Chain::submit` + public `BlockStore` API on a scratch dir.
- **Reports (measurement only):** `docs/performance/README.md`, `baseline-2026-11-08-i5-8365U-windows.md`, `phase-c-scalability-report.md` + `results/*.json`. Known harness limit: realistic/adversarial 1k runs can panic on fee-drifted outputs — a bench-harness sizing bug, not a consensus bug.
- **More reading:** `docs/final-report.md` (round summaries), `docs/fuzz.md` (17 cargo-fuzz targets over wire/mempool/store/L2/worker), `docs/security-review-hbm-2026-10-12.md` (HBM scope, sizing, `lanes==0` notes), `paper/srct-settlement-layer.tex` (protocol paper: hashes, PQ, domain separation, PoW diversity, settlement layers).
- **Vectors.** `verification/tests/vectors/` holds the consensus byte layouts, generated only from the implementation. `verification/sim/srct_reference.py` is a second PoW implementation written from `SPEC.md` rather than from the Rust (by the same author — a second implementation, not a second party), and it reproduces all 21 puzzle digests — evidence the spec is unambiguous rather than merely self-consistent.
- **Red team.** `crates/srct-core/tests/redteam*.rs` holds 21 adversarial integration tests across four files (`redteam`, `redteam_credit`, `redteam_delegation`, `redteam_round2`), each confirmed to fail against the code it now guards. The full record of defects found and fixed is in [docs/status.md](docs/status.md). Author-run, like everything above — see [Honest limits](#honest-limits).

---

## What the chain is for

Two distinct layers, with different jobs:

**Layer 1** is a conventional UTXO chain — wallets, transfers, blocks, P2P. It exists to be a durable settlement layer, and nothing about it is AI-specific.

**Layer 2** is the part that makes the compute work worth doing. It is a task economy: a **submitter** posts an escrow for a described computation, a **worker** claims it, runs it and submits a result hash, and anyone may **challenge** that result. A committee then decides whether the work was correct, and settlement moves the money accordingly.

The L2 transaction types are the whole vocabulary — six for the task economy and the exit mechanism, seven for the authority and credit layers (thirteen total):

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

A task moves through six states: `Open → InProgress → ResultSubmitted → Disputed? → Settled`, with `Expired` as the timeout branch.

---

## Layer 1 and Layer 2

**Layer 1 — settlement.** UTXO money with blocks, difficulty, fees and P2P relay. It holds no AI state and makes no AI decisions; its job is to keep the books exactly. Consensus rules (supply bounds, signature checks, lock_time, maturity, mempool discipline) are enforced identically by miner, validator and node on every block.

**Layer 2 — verifiable work.** Contracts, disputes, certificates and exits, defined by SPEC §§15–17 and implemented in `crates/srct-l2`:

- **Contracts** (`task_contract.rs`) move tasks through their states, credit deposits 1:1 from ordinary Layer 1 payments to the profile's derived sink address, auto-settle unchallenged results on expiry, and expire abandoned tasks.
- **Disputes** (`dispute.rs`) re-execute the canonical CPU reference over the task's own committed fields. The engine reads the evidence from the contract and computes the reference itself — it never accepts the reference as a parameter, so no caller can dictate the verdict. Inconclusive arbitration settles nothing.
- **Certificates** (`vwc.rs`) come in two kinds: `Quorum` (BLS aggregate + lattice sidecar, offline-verifiable — real evidence of correct work) and `WindowElapsed` (a receipt that nobody challenged in time — explicitly *not* verification).
- **Exits** (`state.rs`, `replay.rs`) mature after finality depth plus binding finality, release through a permissionless crank that proves the exit record against the L2 state root committed at the queue block, and require exact funding (sink outputs summing *exactly* to `amount + exit_fee + L1 fee`, no change, no tip). Mainnet caps exit principal at 1,000 SRCT per 144-block window with a 100 SRCT per-owner sub-cap so one filler cannot starve everyone else; refusals delay, never destroy. Active from height 1 on all profiles.

Value flows down (Layer 1 payment → L2 deposit credit) and back up (exit queue → mature → crank-built claim → Layer 1 payment) with conservation preserved across the joint check.

---

## Use cases and features

Things a UTXO chain with a task economy on top can do that the two layers alone cannot: settlement for work nobody re-runs, machines spending under a written policy, payment for what a machine produced rather than what it claimed, reputation that travels with the identity and cannot be bought, and value that comes back.

### Agent payments (x402)

SRCT speaks the x402 challenge/response shape with no second payment system. A client calls a paid resource, gets `402 Payment Required` plus a `PAYMENT-REQUIRED` envelope, and retries with a `PAYMENT-SIGNATURE`. The node verifies by reusing the ordinary payment admission path (`service::admit_payment` + the node-local `CreditBook`), so there is no consensus change.

```
Agent ──GET /v1/paid/weather──▶ 402 + PAYMENT-REQUIRED (exact, srct:mini, 500 sat)
Agent ──budget check (max, allow-lists)──▶ PaymentRequest → Authorization → MachinePayment
Agent ──GET + PAYMENT-SIGNATURE──▶ verify → admit → 200 + PAYMENT-RESPONSE + weather
```

- `GET /v1/paid/weather` — demo paid resource (500 sat, fixed recipient and service `x402-weather-v1`). Missing signature returns `402`; a valid signature admits the payment and returns `200` with the report.
- `POST /v1/x402/verify` — facilitator verify (offline checks, no state change).
- `POST /v1/x402/settle` — facilitator settle (same admission as `POST /v1/payment/submit`).
- Client budget (`X402Budget { max_amount_sat, allowed_recipients, allowed_services }`) is enforced *before* signing — a server asking for more is refused locally. Absent allow-lists mean unbounded; present ones are enforced exactly like `SpendPolicy` (empty present denies all). `check_guarded` adds the short window: the spend must land before its expiry, capped at 30 blocks.
- `scheme` is `exact` only; `network` is CAIP-2 `srct:<reference>` or, beside SRCT, an EVM rail (`eip155:8453` Base, `eip155:84532` Base Sepolia — advertised, never settled by this node); `amount` is a decimal satoshi string.

Full mapping, curl flow and limits: [`docs/x402.md`](docs/x402.md). Demo: `python verification/sim/x402_paid_api_demo.py`.

### Micro-payments and wallet safety

Per-call billing without a manual transaction per call. Three primitives, none of which changes consensus — all reuse `MachinePayment`, `SpendPolicy` and the credit path. Full guide: [`docs/micropayments.md`](docs/micropayments.md).

| Primitive | Endpoint | What it does |
|---|---|---|
| Batch quotes | `POST /v1/payments/aggregate` | Same payer, N recorded payments → one `PaymentBatch` with per-recipient merged outputs. Returns gas, required fee, per-payment cost and savings vs N separate transactions. Read-only quote. |
| Stream channels | `POST /v1/streams/open`, `POST /v1/streams/settle`, `GET /v1/streams/{id}` | Open once (rate per block, expiry, hard cap); each unit of work mints an off-chain voucher; only the final voucher settles on chain as a `MachinePayment` with `reference` = stream id, bound to the stream's recipient. `StreamBook` enforces exact, ordered, in-cap settlement; accounting persists in `state.bin`. |
| Sponsored intents | library `srct_core::micro::SponsoredIntent` | A sponsor signs fee coverage (`sign_sponsor_intent` / `verify_sponsor_intent`, bound to sponsor + batch hash + fee + expiry). Auditable fee-attribution record — deliberately not a consensus fee-payer, so a sponsor can cover a priced quote but never mint authority. |

Benchmark (`python verification/sim/micropayment_benchmark.py`): 10 payments to one provider cost one base fee instead of ten; a 100-unit stream settles once instead of 100 times. Latency follows the same curve — fewer transactions is fewer confirmation waits.

The wallet around them is safer than a normal crypto wallet by construction (full operator guide: [`docs/wallet-safety.md`](docs/wallet-safety.md)):

1. **Spend policy** — per-tx cap, tumbling window + cumulative cap, recipient/service allow-lists (empty allows nothing), validity heights, strict nonce increase, owner revocation. Fail-closed.
2. **Session budget** (`safety::SessionBook`) — per-agent aggregate across rotated policies, so spend cannot be split across N policies. `SRCT_SESSION_WINDOW_BLOCKS` + `SRCT_SESSION_CAP_SAT` (both zero = gate off).
3. **Risk checks** (`safety::RiskPolicy`) — high-value approval is *enforced*, not advisory: at or above `SRCT_HIGH_VALUE_THRESHOLD_SAT` the node answers `403 human_approval_required` until a key listed in `SRCT_HIGH_VALUE_APPROVERS` co-signs the payment (the payer's own key does not count). Threshold `0` disables the gate — but only if the operator sets it: with no env set, mainnet gates at 10 SRCT by default. Plus per-payer velocity cap (`SRCT_MAX_PAYMENTS_PER_PAYER`) and a mainnet guard in test mode (`SRCT_TEST_MODE=1` refuses `srct/mainnet` spends).
4. **Idempotency** — `PaymentTracker` (exact replay → `duplicate: true` before admission), `ReceiptBook` (same receipt → `duplicate`; conflicting receipt → `receipt_conflict` 409), strictly increasing policy nonces.
5. **Receipts + reconciliation** — every admission holds a credit reservation until its receipt settles it; `GET /v1/payments/unsettled` lists recorded-but-unbound payments (retry these, do not rebuild); `GET /v1/receipts/orphans` lists receipts claiming unrecorded payments.
6. **Audit trail** — every grant, admission, refusal, revocation, stream and receipt appends to a bounded hash-chained `AuditLog` (`GET /v1/audit` reports `chain_valid`; `GET /v1/risk/policy` exports the live envelope). The chain exports as auditor/insurer-readable JSON, re-checked on import, verified via MCP `audit.verify`. Audit receipts are node-local over loopback and export-verifiable, never chain-anchored — so routine interactions are audited without paying a chain fee each; only final settlement settles on chain.

### Smart Gate (device-grid security layer)

Universal security layer for the AI-agent era: one question — *may this workload do this exact action at this exact moment under this grant?* — answered as `allow / deny / needs_approval` anywhere, settled as trust on Solar.

- **What it is:** an owner-signed, context-bound capability (`SignedCapability`: owner signature over `policy_hash || action_hash || context_hash || expiry || nonce`, where `action_hash` is the canonical hash of the exact bytes about to execute). A bare capability is public bytes anyone can write down — only the owner's signature turns it into authority, and every boundary verifies it. The grant bounds rate and validity only and names no tools, images, or APIs. Exactness comes from recomputation: the execution boundary re-derives `action_hash` from the preimage it observes and `context_hash` from workload + height. One bit of drift denies. Short-lived by construction (max 30 heights, no wall-clock), nonzero strictly increasing nonce, tumbling window, cross-principal deny. Fail-closed, deterministic, integer-only.
- **How it works:** the owner signs a narrow `InfraPolicy` once (`srct-core::guard`) and registers it (`guard/grant`, signature mandatory). Risk lives in the grant: a high-assurance grant names an independent approver and mandates a signed approval for every admission — a caller reporting `high_risk: false` cannot switch that off (callers escalate, never de-escalate), and a grant that names its owner as approver is refused at registration. Before any key or long-lived token is used, the workload calls the gate. The runtime, container broker, cloud broker, or wallet signing service verifies the owner signature offline and executes only on `allow`. High-risk actions return `needs_approval` until a signed `GuardApproval` from the grant's designated approver — bound to the exact capability instance, agent, action, context and expiry — is presented; a missing approval gates, a forged one denies. Grants can bind a workload id and a workload identity key (only a fresh per-execution possession proof admits), and capabilities can scope to one enforcing node (`SRCT_GUARD_AUDIENCE`) so high-value actions are not independently admittable everywhere. The raw unsigned admission path was deleted: `authorize_signed` is the only entry point. Refusals consume no budget and are named (`action_mismatch`, `context_mismatch`, `expired`, `nonce_reuse`, `zero_nonce`, `unsigned_capability`, `bad_approval`, `wrong_audience`, `cross_principal`, `window_exhausted`).
- **Replay, revocation, state:** nonces are nonzero and strictly increasing per grant, persisted in the node's `GuardBook` across restarts (`state.bin`); revocation kills the grant and every registered descendant and persists in a revocation set the stateless pre-check also consults. The node's registry + revocation set + book is authoritative per node; MCP-local gate state is a non-authoritative cache. The worker execution boundary admits statefully through the authority on every run — revoked denies and forgets local state, unreachable denies without touching it. There is no cross-node nonce lock: scope high-value capabilities to one node via `audience`. Registry (1024 grants) and book (1024 grants) refuse when full rather than evicting.
- **Quantum-resistant by construction:** every signature the gate, the policy engine and x402 payments verify travels as a hybrid bundle (scheme 1 ECDSA + scheme 3 ML-DSA-65, FIPS 204 level 3). SPEC §1.2 is the reference.
- **How others use it:** free verify, paid trust. Any platform calls `srct-policy::guard_verify`, MCP `guard.check` / `guard.authorize`, or the node routes `POST /v1/guard/decide` (stateless pre-check), `POST /v1/guard/grant` (owner-signed registration), `POST /v1/guard/revoke` (owner-signed kill switch with descendant propagation), `POST /v1/guard/authorize` (stateful admission with audit). Verification needs no Solar node; enforcement and audit settle on the enforcing Solar node, which is what drives SRCT demand (fee burn + PSCB accounting). Full design: [`docs/smart-gate-architecture.md`](docs/smart-gate-architecture.md).
- **Finance-gate quick start (V1):** company payments behind the gate — frozen intent shape, five integration steps, and the sales demo: [`docs/universal-security.md`](docs/universal-security.md), `python scripts/finance_gate_demo.py --node http://127.0.0.1:PORT`. Lock-in tests: `cargo test -p srct-node --test universal_security`.
- **Why copy does not transfer trust:** verification code is open by design; the trust root is not copyable. Grants are network-bound, decisions anchor to the canonical tip, and audit receipts are accepted because of the validator quorum, bond ledger, and accumulated history behind them. A fork gets a new network id and magic, old grants fail binding, and no quorum or insurer accepts its proofs.

### Agent economy

Portable reputation, tiered spend power, job escrow with result binding, dollar pricing with SRCT settlement, auditable fiat ramps, and productive lending. Service-layer (node-local books), not consensus — except the L2 credit positions in [Credit and lending](#credit-and-lending), which stay the collateralized on-chain primitive underneath.

**Portable reputation + tiered wallets** ([`docs/reputation.md`](docs/reputation.md)). History travels with the agent: receipts record task completions and payments, credit positions record repayments and defaults (`POST /v1/reputation/passport/attest` assembles a subject's events from node books). An issuer that verified the events signs a `PassportBatch` (`POST /v1/reputation/batch`; the node re-verifies every payment and loan source against its own books). Any service scores it (`GET /v1/reputation/score/{agent}?role=machine` → `Deny | Throttled | Standard | Preferred`). Sybil resistance: every positive event is backed by a real payment, settled receipt, posted collateral or repaid loan; repeat business with one counterparty counts at its integer square root; stake-backed events weigh more (repaid collateralized loan +4 vs bare task +1); negatives are sticky and never dampen (dispute lost −4, default −8; any default zeroes the suggested credit limit). Wallet age and raw tx count are deliberately unused. Tiered wallets: one funding split into narrowed child policies (`tiers::build_tier_pair`) — e.g. 20/tx for trusted services, 1/tx for experiments. A tier can never exceed its parent; they nest; revoking the root stops the whole tree (`POST /v1/wallet/tier`, `GET /v1/wallet/tiers/{agent}`).

**Agent-to-agent job escrow** ([`docs/agent-jobs.md`](docs/agent-jobs.md)):

```
POST /v1/jobs/open → POST /v1/jobs/{id}/accept → POST /v1/jobs/{id}/deliver
→ POST /v1/jobs/{id}/resolve|release (against the delivered result hash)
— or — POST /v1/jobs/{id}/dispute (freezes funds until the arbitrator resolves)
```

Release binds the result hash — it pays for *this* dataset, not any dataset. The resolve signature binds (job id, direction, result hash) to the arbitrator key named at open. Every step is authorized: `open` needs the hirer's signature over all terms, `deliver` the worker's over (job, result), and `loans/accept` the borrower's over (offer, amount, bond, deadline) — no one opens debt or jobs in someone else's name. Dispute locks are node-enforced (`held_escrows`, persisted in `state.bin`): release, settlement binding and the timeout auto-refund all refuse while disputed. `GET /v1/jobs/{id}` reports the record plus escrow state and held flag.

**Dollar prices, SRCT settlement** ([`docs/usd-settlement.md`](docs/usd-settlement.md)). SRCT is a mined coin, not a peg — services quote in USD (or a supported stablecoin) and settle in SRCT at a transparent locked rate. `POST /v1/fx/rates` (issuer must be in `SRCT_FX_ISSUERS`), `GET /v1/fx/rates/list`, `POST /v1/fx/quote` (amount, sat due, fee, slippage, rate, expiry stated up front; stale or expired quotes refused), `POST /v1/fx/swap` (stablecoin-in intent as audit trail — custody never touches the node).

**Entering and exiting SRCT** ([`docs/ramps.md`](docs/ramps.md)). The node is the auditable registry for entry/exit; custody and compliance live with the ramp provider off-protocol. `POST /v1/ramp/quote` (provider-signed, either direction), `GET /v1/ramp/quotes`, `POST /v1/ramp/intent`, `POST /v1/ramp/intent/{id}/settle` (only the quoted provider closes its own intent; terminal: filled or refunded, never both), `GET /v1/ramp/intents`.

**Productive lending** ([`docs/lending.md`](docs/lending.md)). Credit for working capital on top of the on-chain positions: lenders publish standard terms (`POST /v1/loans/offers`, rate ≤ 10%/window, full-collateral terms), borrowers discover (`GET /v1/loans/offers/list`, cheapest first) and accept (`POST /v1/loans/accept` — terms come from the offer; bond and collateral must already be funded). History prices risk (`GET /v1/lending/borrower/{addr}`, `GET /v1/lending/limit/{borrower}` — advisory only; any default zeroes it; no history means zero), `GET /v1/lending/dashboard` (exposure, due-soon, shortfalls), `GET /v1/lending/collateral/{position_id}` (live coverage in bps). Loss order: collateral first, then the borrower's posted bond, then the lender absorbs the shortfall — never minted. Borrowers can authorize automatic repayment from revenue (`POST /v1/lending/autorepay`, revocable, capped, expiring).

Demo covering reputation, tiers, jobs, USD quotes, ramps and lending: `python verification/sim/agent_economy_demo.py`.

### SRCT Treats (tradeable reward claims)

[`docs/treats.md`](docs/treats.md). Transferable reward claims for agents, machines and robots — the third value component next to liquid SRCT and committed escrow. Backed by 10% of each block's PSCB leg (`Chain::treat_reserve`, reorg-rewound, reported in `status` / `conservation` / `/metrics`). No open mint: Treats accrue only from verified settlement (receipt auto-mint with base weight plus capped fee bonus, VWC claim) or from owner-signed gifts. Storable and capped (per-holder + global ceilings, no decay); agent-to-agent transfers move under sender signatures; redemption burns Treats for single-use vouchers (fee credit, discount, trial, service credit). `GET /v1/treats/balance/{agent}?role=`, `POST /v1/treats/gift`, `POST /v1/treats/transfer`, `POST /v1/treats/claim-work`, `POST /v1/treats/redeem`, `POST /v1/treats/voucher/consume` (beneficiary signature required), `GET /v1/treats/reserve`. A Trial-kind voucher covers part of `POST /v1/trials/repay`. `srct-worker treats-balance` shows the balance.

### How fraud is detected

The canonical CPU reference decides. Nothing else is authoritative, and no caller can supply the answer.

**The reference.** `compute_ir::reference_result_hash(task_id, ir_hash, input_hash, required_memory_bytes)` is a fixed-round permutation over the task's own committed fields. It commits to the *task*, never to a caller's claim about it. Two properties make it authoritative: it is not an interpreter for arbitrary IR (SPEC §16.4/§16.5 forbid an on-chain interpreter — a fixed function respects that), and it has no height, clock or RNG input, so identical task fields produce identical bytes on every machine, every run.

**The lifecycle:**

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

`DisputeEngine::resolve` reads the evidence from the contract and computes the reference from the contract's own fields. It never accepts the reference as a parameter — taking it as an argument would let any caller dictate the verdict.

**"No match is not guilt."** An inconclusive arbitration settles nothing. A malformed or unexecutable task cannot become a fraud conviction by accident.

**Vote binding and replay protection.** Each committee member signs one vote per held key — four keys is four committee members, not one member with four signatures, because a quorum counts *distinct* signers. A vote binds the task, the verdict, the reference result, the network, the height and the signer, under its own domain separation tag. It signs exactly `SettlePayload::signing_hash`, which is what lets a quorum of votes aggregate into the settlement transaction — and lets the settlement path re-verify it from scratch with real BLS pairings. Receiving nodes check a vote against **their own** committee and height, and relay only what they accepted, so a bad vote travels at most one hop. One vote per signer means a replay, a duplicate, or a relay loop cannot inflate quorum. A split committee (two honest members disagreeing) is refused but *not* recorded as equivocation; a genuine double-sign is recorded as `ArbitrationEquivocation`. The signed message includes the network and height, the tally re-checks that every counted vote names one network and one height, and the quorum certificate carries the same chain context so it stays re-verifiable.

**What a fraud verdict does:**

| | |
|---|---|
| Worker | Deposit slashed through the M2 vault: 50% burned immediately, 50% vests linearly over a year |
| Submitter | Refunded whole |
| Challenger | Paid a bounty from the PSCB reserve; their deposit returns |
| Certificate | **None** — a fraud verdict is not evidence of correct work |

Settlement fees are proportional: 0.1% of task value, 1,000-sat minimum.

### How withdrawals work

Deposits are not one-way. An owner on Layer 2 can bring value back to Layer 1.

1. **Deposit.** An ordinary Layer 1 payment to the profile's derived sink address. No new transaction type. Credited 1:1 after finality depth.
2. **Queue.** The owner signs an `ExitQueue` transaction, which debits `amount + exit_fee + queue_fee` and records `(owner, nonce) → (amount, destination, height)`. Nonces are per-owner and strictly increasing.
3. **Mature.** After finality depth *and* binding finality, the exit is settleable. Exits use the same or a stronger rule than deposits, never weaker.
4. **Release.** A **permissionless crank** builds the claim: it consumes sink outputs and proves the exit record against the L2 state root committed at the queue block.

The claim is authorised by an **inclusion proof, not a signature**, because the sink holds no key. Consensus pays only the destination the proven record names — a caller cannot redirect it — and the claimant collects a fee the owner prepaid at queue time, which is what makes a crank nobody wants to run a non-issue rather than a griefing vector.

**Exact funding only.** A claim must consume sink outputs summing *exactly* to `amount + exit_fee + required L1 fee`, with no change and no tip. An exit whose funding is not sitting in a subset summing to that figure stays queued rather than draining a stranger's deposit. The cost is a liveness edge: it can wait.

**Windowed, and fair within the window.** Mainnet caps exit principal at 1,000 SRCT per 144-block window — and at 100 SRCT per owner inside it. The global cap alone is starvable (one filler holds everyone else out until rollover, at fee cost); the per-owner sub-cap refuses the filler by name (`ExitOwnerWindowFull`) while other owners still queue, and resets on rollover. Refusals delay, never destroy.

**Anyone can crank.** Consensus is permissionless, and claims are not miner-only: `GET /v1/exit/crankable?claimant=<address>` hands the settleable claims to any third party, so a non-miner can build a block with them. An escrow settlement rides this same path — `POST /v1/escrow/{id}/settle` queues the release's exit and the crank pays it, with no separate escrow coin.

**Reorg-safe.** A release is an ordinary undoable Layer 1 operation: rollback restores the sink outputs, clears the identity, and L2 replay regenerates the watch.

**Conservation is unchanged.** The joint check needed no exit term at all — the L1 payment and the L2 debit cancel while the sink term falls by the same amount.

> **Active on mainnet.** `mainnet.exit_activation_height` is `1`, which means exits work from genesis — same as Bitcoin spends. Testnet and mini activate at height 1.

### Validators and finality

**Bonded stake** (`bond.rs`, Decision 20). Three transaction types — `TX_BOND`, `TX_UNBOND`, `TX_SLASH` — feed a bond ledger with a bond-order index. No wealth gate — but an anti-dust floor (`min_bond_sat`: 0 on mini/testnet, 0.01 SRCT on mainnet): below it a bond is refused, so 1-sat spam cannot permanently occupy ledger entries on every node. Unbonding locks for `UNBONDING_PERIOD_BLOCKS` = 1,008 (seven days). Provable equivocation burns the full bond.

Bonds only admit keys whose holder proves they hold them: `TX_BOND` carries a 96-byte proof-of-possession signature bound to network, bonder and key, and a payload without one does not decode.

**Finality.** Binding finality activates at `finality_activation_height = 100` on mainnet from genesis. Depth-based finality (100 blocks) secures the chain before that — the same Bitcoin-style rule. The 21-key bootstrap committee signs until the first bond, then the stake-weighted TopN set replaces it. Those 21 keys are public (deterministic in source), so serving mainnet with them loaded requires `--allow-bootstrap-committee` — cold start is explicit, never silent; replace them with bonded keys.

**Fixed-epoch committees.** Each epoch's committee derives from the bond state at its seed height and stays fixed for the whole epoch; a bond mid-epoch takes effect only at the epoch its seed first sees. Reorgs across a seed height roll the committee back exactly — snapshots travel with the chain state and the finality observation frontier rewinds with them (`rewind_observation`), so a certificate from a losing branch can never be replayed.

**Slash verification is per-epoch.** `check_slash_tx` verifies each checkpoint against its own epoch's committee and fails closed when that set is unavailable — an expired epoch or disjoint signer sets refuse rather than fall back. A validator that drops out of TopN can still be slashed on evidence from when it was bonded. Committee caches hold the current set plus the previous one inside its grace, then expire; deriving a set that fails is a hard error, and there is no genesis fallback once bonds exist.

### Wallets, transfers and policies

**Wallets.** Keys live in `wallets.json`, encrypted at rest with `SRCT_WALLET_PASSPHRASE` (Argon2id + ChaCha20-Poly1305, `0600` atomic write). Plaintext files are refused unless `--allow-plaintext-wallet` is passed deliberately. Addresses are 20-byte hex (`jt1` prefix); classical, hybrid and post-quantum addresses are distinct by construction. Scalars are redacted in debug output and zeroized on drop.

**Transfers.** A transfer spends confirmed UTXOs to a recipient address with an integer sat amount and a fee. `lock_time > height` refuses the transaction, so timelocked payments cannot mine early. Coinbase outputs are immature first (100 blocks mainnet, 10 testnet/mini). Balances split into confirmed / spendable / pending (`GET /v1/balance/{address}`).

**Policies and enforcement.** A grant is published on chain (`srct-node policy --spender …`), so every node enforces it — not just the owner's wallet. Spending under it (`srct-node agent-spend --policy … --nonce N`) is checked against chain state at admission: live grant, window, per-tx cap, allow-lists, strictly increasing nonce, unrevoked ancestry. The owner kills a grant with `srct-node policy --revoke`, and every descendant of it dies with it. Over the network the same operations go through `POST /v1/l2/broadcast` (dry-run against current state, queued for the next block) after `POST /v1/policy/decide` answers the advisory question with the chain's own reason — so a violating spend is refused before it mines rather than skipped after.

### Credit and lending

Layer 2 supports agent-to-agent lending as on-chain state. The principal, the collateral, and the debt are real coins in the UTXO set — consensus state, not accounting entries. A loan is a four-step lifecycle: **open**, **repay**, and either **repay-in-full** or **default**. Collateral may also be **added** to an open position at any time before it settles. Full-collateral terms by default (100%), interest capped at 10% per window and charged per whole window, repayment applies interest first, overpayment is refused rather than clipped, anyone may default an overdue position, and the loss order on chain is collateral, then lender — a marketplace bond, if the borrower posted one, sits in between at the service layer — the protocol never mints to cover a shortfall. Full mechanics (wire types, terms, fee split, interest arithmetic, settlement order, position tracking, fund flow): [`docs/lending.md`](docs/lending.md#the-consensus-primitive-underneath).

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

The `credit` subcommand uses a wallet. The lender signs `CreditOpen`; the borrower signs `CreditRepay`; any wallet can sign `CreditDefault` once the deadline has passed. On a local node the CLI mines the transaction directly; over the network, serialize the `L2Transaction` to hex and POST it to `/v1/l2/broadcast`, which dry-runs against the current state and queues it for the next block.

Adding collateral to an open position (`CreditCollateral`, `0x1A`) is available via the same `/v1/l2/broadcast` endpoint — the CLI's `credit` subcommand does not expose it directly, but the worker SDK does (`add_credit_collateral`).

> **On-chain positions vs the lending marketplace.** This section is the consensus primitive: collateralized loans as chain state. The loan offers, borrower history, credit limits, dashboard, collateral-valuation and auto-repay endpoints in [Agent economy](#agent-economy) are the node-local marketplace built on top of it — they price and discover loans, they never replace collateral. `credit` in the API never reads a reputation score.

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

`mainnet` ships with 21 public deterministic bootstrap keys (quorum 15) so finality can bind before any stake exists; the first bond replaces them with the stake-weighted TopN committee. Its separate L2 settlement set stays empty, so settlements fail closed. Exits are active from height 1. The PQ row is the `pq_activation_height` of Decision 24: `0` means no input is refused for lacking an ML-DSA-65 component, and the rule is age-gated when it is flipped — only outputs created at or after the height must carry the component, so history is never stranded.

Network magic bytes (§13.3): `mainnet` = `6A4E5402`, `mini` = `6A4E5403`, `testnet` = `6A4E5404`. These move with each protocol version that changes the wire format or state root, so pre-bump peers are refused at framing before they can join.

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

Full mining guide — three ways to mine, where rewards go, hardware backends, pool protocol — is in [Mining and AI compute](#mining-and-ai-compute) above; the node endpoints (`GET /v1/mine/template`, `POST /v1/mine/submit`) are specified in SPEC §19.2.

### Agent authority and credit, from the terminal

A grant is the owner's signed authority for a named spender. It is published on chain, so every node enforces it:

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

Credit works the same way — the **lender** signs, the principal really moves, and the collateral answers for the debt:

```sh
srct-node credit --to <borrower> --amount 1 --collateral 100000000
srct-node credit --repay --position <position-hash> --amount 1
srct-node credit --list
```

Every one of these commands checks the transaction against the state the chain will replay and refuses with the chain's own reason, rather than mining a block the replay would skip.

Common options: `--network <mainnet|testnet|mini>` (default `mini`) and `--data-dir <path>` (default `./chain`).

`serve` also takes `--listen`, `--connect`, `--bootnodes`, `--peers`, `--interval`, `--api-listen`, `--api-token`, `--api-allowed-host` and `--no-mine`. `--bootnodes` dials peers at startup (SPEC §13.6: v0.2 has no ADDR gossip, so bootnodes plus `peers.json` are the only peer sources). `--credit-issuer` lists the BLS keys trusted to sign credit attestations for `POST /v1/credit/mint` (comma-separated 48-byte hex keys; with none listed, every mint is refused). `send --amount` takes SRCT (`--amount-sat` takes satoshis); printed balances are in SRCT.

The API defaults to loopback and needs no credentials. Binding anything non-loopback is refused unless a token is supplied:

```sh
# Non-loopback: a bearer token is mandatory (§19.2). Pass it through the
# environment, not --api-token: flags are visible in `ps`.
export SRCT_API_TOKEN="..."
srct-node serve --network testnet --data-dir ./chain --api-listen 0.0.0.0:8080

# Loopback: unchanged, and unauthenticated.
srct-node serve --network testnet --data-dir ./chain --api-listen 127.0.0.1:8080
```

Every request to an exposed bind must carry `Authorization: Bearer <token>` (compared in constant time). Every bind — loopback included — requires a `Host` header (DNS-rebinding defense): a loopback bind accepts loopback names only, while a non-loopback bind additionally accepts any IP literal, the bound address, and hostnames listed via `--api-allowed-host` (comma-separated) or `SRCT_API_ALLOWED_HOSTS`. A missing, unknown, or bracket-malformed `Host` is 403. Exposed binds also rate-limit per remote address, and every bind caps a request at 10 seconds, 64 requests in flight, 128 open connections, and 30 seconds to finish sending request headers (the slowloris bound).

Credit, escrow and delegation state is node-local and never consensus, but it is no longer lost on restart: the books beside the chain (receipts, replay tracker, payments and their settlement links, reservations, policy accounting, credit and the attestations already minted, delegations, issued policies, revocations, escrows and their exit bindings) persist to `state.bin` — an atomic, digest-checked file with a fail-closed load (a corrupt file refuses to start) — flushed when their bytes change, plus once at shutdown.

---

## Testing

```sh
cargo test --workspace                                   # full suite (refresh counts with scripts/test_count.sh)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
python verification/sim/verify_vectors.py --check                     # consensus vectors
```

Targeted suites for the fast loops:

```sh
cargo test -p srct-core --test x402           # x402 challenge/budget/authorize/pay/admit roundtrip
cargo test -p srct-node --test x402           # 402 → verify → settle → retry over real HTTP
cargo test -p srct-policy                     # chain-agnostic decide/verify JSON seam
cargo test -p srct-mcp                        # keyless wallet guard, portable prove/verify, bound grants
cargo test -p srct-node --test micro_safety   # batch quotes, streams, sponsor intents, session/risk/audit
cargo test -p srct-node --test agent_economy  # passport, tiers, jobs, FX quotes, ramps, lending marketplace
cargo test -p srct-agentnet                   # pairwise, double ratchet, sealed sender, groups, MLS-style epochs
cargo test -p srct-compute                    # offers, sharding, TEE evidence, bonds, challenges, journal, escrow
cargo test -p srct-diloco                     # DiLoCo rounds, fixed-point backend and hardware conformance
cargo test -p srct-cnnp                       # representation adapters, metering and evidence gates
cargo test -p srct-intent                     # intent lifecycle, evidence, bonds and solver directory
cargo test -p srct-fhe                        # encrypted sums and toy TFHE gates
cargo test -p srct-zkml                       # Sigma proofs, threshold gate and batch folding
cargo test -p srct-workgraph                  # lineage, evidence, usage ledger and revenue escrow
cargo test -p srct-verify                     # unified TEE/FHE/ZKML/compute evidence policy
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
cargo test -p srct-node --test universal_security # finance-gate V1: decide/authorize fail-closed over HTTP
```

CI (`.github/workflows/ci.yml`) runs format, clippy, the full suite, a release build, the vector cross-checks, attack simulations, and all 17 fuzz targets on nightly with ASan. `.github/workflows/release.yml` re-runs the same gate on a tagged tree before publishing artifacts with checksums and a keyless cosign/Sigstore bundle.

**Every action is pinned to a commit SHA**, with the tag it came from in a trailing comment, so a compromised or retagged action cannot silently change what CI runs. Job tokens are least-privilege: `contents: read` by default, and only the two jobs that genuinely write (the signing job's `id-token: write` for the OIDC identity, the publish job's `contents: write`) take more. Dependabot keeps the pins honest but opens **no pull requests** — every update PR is a branch, and this repository keeps `main` as its only branch, so applying a bump is an owner step (`cargo update -p <crate>` plus `cargo audit`). Security *alerts* are unaffected: those come from the advisory database, not from PRs.

**Vectors.** `verification/tests/vectors/` holds the consensus byte layouts, generated only from the implementation. `verification/sim/srct_reference.py` is a second PoW implementation written from `SPEC.md` rather than from the Rust (by the same author — a second implementation, not a second party), and it reproduces all 21 puzzle digests — that agreement is evidence the spec is unambiguous rather than merely self-consistent.

**Fuzzing.** 17 cargo-fuzz targets over L1 wire, mempool, storage and checkpoints; L2 codec, disputes, state and certificates; and the worker. They assert capability invariants — decode/encode inversion, bounded allocation, value conservation under adversarial transaction programs — not just panic-freedom.

**Red team.** `crates/srct-core/tests/redteam*.rs` holds 21 adversarial integration tests across four files (`redteam`, `redteam_credit`, `redteam_delegation`, `redteam_round2`), each confirmed to fail against the code it now guards. The full record of defects found and fixed is in [docs/status.md](docs/status.md). Author-run, like everything above — see [Honest limits](#honest-limits).

---

## License

**Copyright © 2026 The Solar Cyber Unit developers.**

**Code: MIT** — the same permissive licence Bitcoin Core uses. The full text ships at the repo root (`LICENSE-MIT`). You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, and permit persons to whom it is furnished to do so, including commercially.

---

## Security

[`SECURITY.md`](docs/SECURITY.md) is the disclosure policy: what counts as a vulnerability, the severity model, the 90-day window, and the intake channel (GitHub Security Advisory, or `security@solarcyberunit.org`). Do not open a public issue for a security defect.

---

Full protocol specification: [`SPEC.md`](docs/SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).
