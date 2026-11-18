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
  - [Smart Gate (security layer)](#smart-gate-security-layer)
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

Imagine your AI assistant could pay for things on its own — booking an API call, renting compute from a stranger's machine, tipping a sensor for its data — without you hovering over it, and without ever being able to go rogue with your money. That's what SRCT is built for.

SRCT (Solar Cyber Unit) is a cryptocurrency with its own blockchain, designed from the ground up as **money for machines**. It has two layers that work together:

- **Layer 1** is plain digital cash. Wallets, transfers, blocks, mining — familiar territory if you've seen Bitcoin. This is where value settles for good.
- **Layer 2** is a marketplace for work. One machine locks up payment for a job, another machine does the job, and the chain itself makes sure the honest side gets paid — no middleman, no trust required.

Here's the idea that ties it all together: **you write the spending rules once, and the whole network enforces them forever.** Say your agent may spend at most 0.01 SRCT per payment, only to two approved services, and only this week. You sign that rule offline and go on holiday. From then on, every node on the network checks every spend against your rule — a payment that breaks it never even gets into a block, just like a double-spend never does. Your agent stays useful, and your money stays safe.

What can you actually do with SRCT today?

- **Hold and send coins** with normal wallets on a Bitcoin-style chain.
- **Mine** with an ordinary CPU — no special hardware needed to start.
- **Put an agent or device on a budget** with a signed spending policy, then let it operate on its own.
- **Sell your spare compute** — your machine takes jobs from the marketplace, does real AI training or inference work, and earns SRCT.
- **Charge per API call** with internet-style x402 payments, batched so tiny payments don't each pay a fee.
- **Get paid for verifiable work**, challenge cheaters, and withdraw earnings back to Layer 1.

And how is SRCT different from other coins? Most chains treat agent spending rules as *suggestions* written in a smart contract the base layer doesn't really understand. SRCT checks them at admission, in consensus — the chain itself says no. Machine billing doesn't cost a transaction per click. Buying compute doesn't require trusting the seller. And agents get a real safety net (the Smart Gate) instead of everyone reinventing permissions from scratch.

One honest note before you dive in: this project is pre-launch. Parts of it are finished and tested; parts are working prototypes; the docs always say which is which. Start with [Honest limits](#honest-limits) if you want the unfiltered version.

---

## The main pillars

One coin, five jobs. Each job is its own layer — use any of them on its own — but everything settles in SRCT.

### 1. Native currency

At its heart, SRCT is simply money. It lives on a UTXO chain (the same "unspent outputs" model Bitcoin uses): 1 SRCT = 100,000,000 sats, whole-number accounting only, no decimals sneaking in anywhere. New coins come only from mining. The very first block minted nothing, so there was no premine — nobody got a head start. There's no fixed cap; instead a halving ladder issues 39,157,124 SRCT over time, then a small tail emission keeps paying miners forever. Every block's fee is split in half: one half is burned (gone for good), the other half feeds the chain's own reserve. So the more the network gets used, the more supply quietly shrinks. Details: [Supply](#supply), [Mining and AI compute](#mining-and-ai-compute).

### 2. Mining and selling AI compute power

Mining keeps the chain secure, and the same software lets your machine earn a second way: by selling its brain instead of its hash power. Your box advertises spare capacity, picks up jobs from the marketplace, runs real AI work — training or answering queries — and gets paid per finished receipt. One machine, one job at a time: it's either 100% mining or 100% AI compute, never a confusing split. Details: [Mining and AI compute](#mining-and-ai-compute).

### 3. AI agent authorization

This is the "let my agent spend while I sleep" pillar. You write a policy — max per payment, max per week, approved recipients, approved services, expiry date, a counter that must always go up so old approvals can't be replayed — and sign it offline. From that moment, every node enforces it. Your signed policy can also travel: it's a portable file any system can verify without talking to our chain, and it can delegate downward (you → your assistant → its helper), with each step allowed strictly less than the last. For one-off approvals, short-lived grants tie an approval to one exact transaction and expire within 30 blocks. Details: [Machines and agents](#machines-and-agents).

### 4. Machine payments

Machines pay each other per use — per API call, per data stream, per job — without drowning in fees. The trick is simple: instead of one blockchain transaction per click, many small payments are bundled into one shared settlement, or an entire usage session settles once at the end. A sponsor can even cover the fees without gaining any power to print money. Around all of this sits a wallet that's careful by design: session budgets, mandatory human sign-off for big spends, duplicate protection, receipts for everything, and a tamper-evident log of it all. Details: [Agent payments (x402)](#agent-payments-x402), [Micro-payments and wallet safety](#micro-payments-and-wallet-safety).

### 5. Verifiable task economy

This is Layer 2, where strangers pay each other for compute without trusting each other. It works like a supervised deal: the buyer locks money in escrow and describes the task; a worker claims it and submits a result; anyone who thinks the result is fake can challenge it with their own answer and a deposit. Then a committee checks who's right — the check is a fixed recipe run over the task's own data, so nobody can rig the verdict. Honest work gets paid, fakes get slashed (half the deposit burned, half locked away), and the challenger earns a bounty. Finished, settled work produces a certificate the worker can show anyone as proof. And money can always come home: deposits flow back to Layer 1 through a queue, a waiting period, and a claim anyone can process. Details: [What the chain is for](#what-the-chain-is-for), [How fraud is detected](#how-fraud-is-detected), [How withdrawals work](#how-withdrawals-work).

---

## Why a new coin

Fair question — couldn't all of this live on an existing chain? Three reasons it lives here instead:

1. **The rules are enforced by the chain itself.** On another chain, a spending policy is advice written in a contract the base layer doesn't understand — it can suggest, not refuse. Here, a payment that breaks your policy is rejected the same way a double-spend is: it never enters a block. The *answers* still travel anywhere (portable grants, the `srct-policy` engine, one HTTP call), but spending SRCT always means passing SRCT's own admission check. No policy-aware base layer, no guarantee.
2. **Work settles in the coin itself.** Escrow, deposits, slashing, fee burns — they're chain state, not some other company's contract balance. Nobody can freeze a payout or break it with a broken bridge.
3. **One money, one audit trail.** Batched payments, streams, receipts and miner pay all price in the same unit, so the cost math in [`docs/micropayments.md`](docs/micropayments.md) is exact instead of "plus whatever the oracle says."

The trade-off is stated openly: a new chain has to earn its security and its liquidity from zero, and nothing here removes that cost.

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

This is the "read this before you trust any number" section. We'd rather undersell than oversell.

- **No outside audit — yet.** Every test, red-team attack, simulation and the Python reference implementation was written and run by the author. The counts are real (`scripts/test_count.sh` reproduces them) but self-reported. Treat them as hard work, not as a certificate.
- **Nobody checking means nobody caught.** If nobody challenges a result before the window closes, it settles as-is — even a wrong one. The fraud path only bites when a challenger shows up. Running challengers is part of operating this network, not an optional hobby.
- **Useful-work mining is not live.** The mining puzzle looks brain-like but it's still hash
work under the hood. There is no training-based consensus on any profile:
useful work is proven the other way — signed receipts, challenge
re-execution and slashing in the compute marketplace. Specialized hardware
backends stay off where drivers are missing; CPU always works.
- **The compute marketplace settles first, pays through signed exits.** Settlement verifies the receipt against the requester's assignment and releases exactly its total from the funded escrow — work without authorization or funding settles nothing. The payout then moves through a requester-signed L2 exit (template → claim → crank), so the node never moves coins on anyone's behalf. The compute *crate* still only writes instructions; the node executes them strictly through signed exits. Where specialized hardware is missing, the built-in CPU workers run real deterministic arithmetic instead.
- **Most service crates are prototypes with honest labels.** Training, cross-model adapters, cross-network intents, encrypted messaging, encrypted compute, zero-knowledge proofs, the unified verifier, the work graph — real, tested library code, but not consensus and not moving your coins. Intents hand payment instructions to the existing escrow layer (they verify no foreign chain). Adapters prove who fitted them, not that two models think alike.
- **Scores, quotes and job boards live on each node, not on the chain.** Two honest nodes can disagree about a reputation score or a price. The money itself (UTXOs, bonds, Layer 2 accounts) can never disagree. So: run your own node, and treat anyone else's score as gossip until you verify it.
- **Price feeds and ramp providers are trusted humans.** Exchange rates come from a whitelist you configure; dollars never touch the node. The chain keeps a signed paper trail — if a provider lies, you'll be able to prove it, but the chain can't stop it.
- **Mainnet starts in public.** The 21 bootstrap keys are visible in the source. Anyone can stand beside them until real bonded stake takes over — serving mainnet with them needs an explicit flag, and swapping in bonded keys is the operator's first job.
- **The language bindings are translators, not judges.** The TypeScript/Python helpers format questions nicely, but allow/deny answers come from a node or the Rust engine — never from the binding alone. No node, no decisions.
- **`srct-policy` drags the whole engine along.** Including the crate compiles all of `srct-core` (yes, all of it). Outsiders who just want answers should use HTTP or the bindings against a node URL.
- **Big exits wait in line.** Mainnet lets one owner queue 100 SRCT per 144-block window. Moving a fortune out takes several windows. Refusals delay you — they never destroy your money — but plan around it.
- **The Smart Gate speaks per node, but revocations travel.** Each node enforces what it sees; revokes created anywhere are broadcast over P2P (verified by the receiver, applied through the same path, relayed onward), so kills converge without a cross-node lock. Nonce windows stay per-node — pin high-value actions to one node via audience scoping. Audit receipts live on the node (verifiable, exportable) rather than on the chain. The managed-cluster admission webhook is designed but not built — the worker SDK's in-process gate is the real boundary today.
- **The slash vault is empty by design (for now).** The 50%-burn / 50%-vest rule is written and tested, but nothing has created a slash record yet.
- **Mainnet Layer 2 settlement follows the live committee.** It starts with the 21 bootstrap keys (quorum 15) and rotates to the bonded TopN committee after the first bond; stale bootstrap quorums are refused after rotation. Testnet and mini use deterministic keys.
- **A few switches are staged or off.** The memory-hard mining puzzle is registered but never active. Mining bound to verified work is opt-in. Post-quantum spending rules and useful-work consensus are off on mainnet (age-gated when flipped, rehearsed on testnet first).

---

## Quick start

You'll need **Rust 1.75+** and **Python 3.11+**. Then:

```sh
git clone https://github.com/swamy18/Solar-Cyber-Unit.git
cd Solar-Cyber-Unit
cargo build --release
```

Now let's make a wallet, mine a few blocks, and check the chain agrees with itself:

```sh
# Keys are encrypted on disk: set a passphrase for this shell (or pass
# --allow-plaintext-wallet to init if you really want a plaintext file).
export SRCT_WALLET_PASSPHRASE=change-me

# Create a chain folder and a miner wallet.
./target/release/srct-node init   --network testnet --data-dir ./chain

# Mine some blocks, then ask the chain if it's healthy.
./target/release/srct-node mine   --network testnet --data-dir ./chain --blocks 25
./target/release/srct-node status --network testnet --data-dir ./chain
./target/release/srct-node verify --network testnet --data-dir ./chain

# Run a node. It mines by default, so it also settles matured exits.
./target/release/srct-node serve  --network testnet --data-dir ./chain \
                                  --listen 127.0.0.1:9833
```

The `verify` step is your best friend: it replays the whole chain from the first block and compares the result with what's stored. Run it after any change and sleep well.

Want a little network on your laptop instead? Three nodes, separate folders, the first one as the seed:

```sh
scripts/start-network --nodes 3          # init, serve, wait until all share a tip
scripts/stop-network                     # graceful stop via pid files
scripts/reset-network                    # stop and delete the data root
```

Every command has `--help`. `srct-node help` lists them all.

---

## Machines and agents

This is the "who may spend my money while I'm away" layer. It lives in one file (`srct-core/src/agent.rs`), and it's deliberately boring in the best way: **pure and deterministic** — no clock, no randomness, no network calls. Same inputs, same answer, everywhere.

- **Every actor gets an ID.** `derive_agent_id` mints a stable identity from the network, the role, and the owner. Three roles: `Human` (a wallet), `Machine` (a device spending under a policy), and `Service` (an identity that *receives* payments). IDs are network-bound — the same gadget has different IDs on different chains, so grants can't leak across networks.
- **Policies say one thing.** A `SpendPolicy` is your signed rulebook answering a single question: *may this agent, at this height, spend this much to this recipient?* The edge cases all fail safe: an empty recipient list means "nobody" (not "everybody"), an empty service list means "no services", the approval counter must always increase (no replays), spending is capped per window, and dates are block heights — never wall-clock time that machines could disagree on.
- **One money, not two.** The policy's `owner` is an ordinary address, so machine balances and human balances live in the same ledger under the same issuance schedule. There is no separate "machine token" to learn.
- **Grants that travel.** A `SignedPolicy` is the policy plus your signature — a file anyone can carry. Another chain, a payment facilitator, an auditor: they can all verify it with no node, no chain data, no secrets. A `DelegationProof` chains grants root-first ("you authorized this agent, here's the paper trail"), each step narrower than the last, at most 8 deep. Full interface: [`docs/portable-policy.md`](docs/portable-policy.md).
- **One-shot approvals.** `BoundAuthorization` glues your signature to one exact transaction hash with a 30-block expiry. Someone steals it and aims it at a different payment? Refused. Tries it after the window? Refused.
- **Ask the engine anywhere.** The `srct-policy` crate answers `allow`, `deny` or `approval-needed` for any payment idea — the same answer the node would give. HTTP (`POST /v1/policy/decide`) and scripting-language bindings speak the same JSON; casual users should just call a node.
- **Receipts keep everyone honest.** `MachinePayment` is the standard payment shape. `ReceiptBook` rejects a receipt that contradicts one already on file; `PaymentTracker` spots exact replays. A settled payment carries its proof: `POST /v1/payment/{id}/settle` links it to the Layer 1 transaction that paid it (a transaction paying the wrong person is refused), and the link survives restarts.
- **Reputation you can't print.** Each identity carries a score from a **fixed table baked into the code**: completed service +1, completed payment +1, verified work +2, dispute won +1, **dispute lost −3**. Events carry no weight of their own, so nobody can forge a better score by crafting a fancier event. And nothing here creates tokens — it's a scoreboard, not a mint.
- **Pay-as-you-go streams.** `PaymentStream` is a subscription with a payer-signed rate per block, a window, a hard cap, a recipient, and the policy guarding non-human payers. Settlement rides the normal payment path with the stream id as the reference — no new transaction type to learn.
- **A front door for apps.** `srct-mcp` wraps identity, payments, receipts and reputation in a keyless interface — including a **wallet guard** that checks budget and expiry *before* any key is touched, portable grant prove/verify, one-shot grant enforcement, and audit-chain verification.

**Little helpers (`srct-worker`).** Small commands that talk to a node URL — no chain data on your machine: `verify-cert` (was that work really verified?), `grant` (mint a bounded grant), `claim` / `submit-result` (the two signing steps behind the templates), `compute-join` (stake + offer in one command), `compute-claim-ticket` / `compute-submit-receipt` (the pull-model work loop), `pay` (x402 with a client-side budget), stream commands, `batch-quote`, and the `trial-*` family (one sponsored first task per agent, ever).

**The trial faucet (operators only).** Trials stay off until a sponsor funds them — no sponsor, no money, every request refused:

```sh
export SRCT_TRIAL_SPONSOR=<sponsor-address>   # pays real SRCT per trial
export SRCT_TRIAL_AMOUNT_SAT=1000000         # default: one L2 minimum deposit
export SRCT_TRIAL_MAX_OUTSTANDING_SAT=10000000  # sponsor exposure cap
```

The dance: agent asks → sponsor drips coins with `srct-node send` → agent confirms with the transaction id (the node checks a real payment arrived) → agent deposits and claims work normally → agent repays from earnings. One trial per agent, ever, all recorded in `state.bin` and the audit trail.

### Consensus state vs. service layer

Two buckets, and it matters which is which. The **policy layer is consensus state** (SPEC §21): grants live on chain, signatures bind spender to agent, caps and nonces are checked against state the chain keeps, and revoking a grant kills all its descendants. **Credit is the same** (SPEC §22): loans are chain facts and real principal and collateral are chain state. The legacy `CreditOpen` format is replay-compatible; once a network enables `credit_consent_activation_height`, new positions use `CreditOpenV2`, signed by both lender and borrower and bounded by collateral, term and window caps.

The **service layer is each node's own notebook**: the payment book, receipt book, credit gate, offline helpers. Useful, persisted across restarts — but never spendable balance, and consensus never depends on it.

---

## Mining and AI compute

Three ways to mine, easiest first. Same blocks, same rewards — only the location of the grinding changes.

Hash mining is the only consensus mechanism. There is no training-based consensus to stage or activate: useful AI work is proven in the compute marketplace — signed receipts, challenge re-execution, slashing — and paid in SRCT. See [`docs/mining.md`](docs/mining.md).

**Where do rewards go?** Every block pays its coinbase to one address: your node's wallet (in-node mining) or whatever `--miner` address you hand the standalone miner. Fresh coins are **immature** first — spendable after 100 blocks on mainnet, 10 on testnet/mini — then they're ordinary money. Peek with `srct-node balance --address <addr>` or `status`.

**How hard is it? Real numbers.** Every profile starts at difficulty 1 — your laptop will happily mine block after block on a fresh chain. Then the network retargets every block toward its heartbeat (10 minutes on mainnet, 1 second on testnet/mini), shifting at most ±10% per step. Rough reference: ~114k hashes/sec on 4 CPU threads holds ~10-minute blocks solo until difficulty passes ~68M. Launch day is CPU-fair by construction; difficulty does the hardening, not exotic hardware.

**The puzzle shelf.** Three entries registered; only the first one grinds:

| Puzzle | Name | Commits to | Status |
|---|---|---|---|
| 1 | `hybrid-v1` | block fields only | Live everywhere (default) |
| 2 | `hbm-v1` | memory-hard scratchpad | Staged — the future answer to ASIC pressure |
| 3 | `vwc-v1` | blocks + latest verified-work certificate | Opt-in (`puzzle_id: 3`) |

What's `hybrid-v1`, in plain words? Three stages: a SHA-256 hash chain (this carries the security), a small integer-only neural-*shaped* stage with epoch-derived weights (no training, no inference — it buys hardware variety, not AI output), and a final hash binding both stages into the number that must beat the target. No floating point anywhere; the brain-like stage is capped at 30–50% of the modelled work so it stays a cost model, never a liability. `vwc-v1` ties mining to real finished work: `extra_nonce` carries the latest verified-work certificate id, and consensus enforces the commitment. No bond, no permission, no identity needed. Full detail: [`docs/mining.md`](docs/mining.md).

### Option A — mine inside the node (simplest start)

```sh
export SRCT_WALLET_PASSPHRASE=change-me
./target/release/srct-node init --network testnet --data-dir ./chain
./target/release/srct-node serve --network testnet --data-dir ./chain \
  --listen 127.0.0.1:9833
```

That's it. `serve` mines into the wallet `init` created. One command, no extra software. Perfect for first launch, experiments, and solo mining while the network is small.

### Option B — mine with the standalone miner (recommended)

Run the node as a relay and grind anywhere with the `srct-miner` binary:

```sh
# 1. Node side: no built-in mining, templates on loopback.
./target/release/srct-node serve --network testnet --data-dir ./chain \
  --no-mine --api-listen 127.0.0.1:8080

# 2. Miner side: fetch a template, solve it, submit the block — forever.
./target/release/srct-miner --node 127.0.0.1:8080 \
  --miner <20-byte-hex-address> --threads 0 --backend auto
```

The loop is simple: `GET /v1/mine/template?miner=<hex>` hands you an unsolved block; you grind `nonce` and `extra_nonce` until the proof passes; `POST /v1/mine/submit` hands it back. The node re-checks everything — template, proof, tip, timestamp — so stale or forged solutions bounce off instead of half-applying. Any HTTP client can do this dance; the binary just does it well (one thread per CPU with `--threads 0`, batched solving, automatic retries).

The `--miner` address doesn't need a wallet on the node — it's just where the coinbase lands. Pools speak stratum-lite JSON-lines (`getjob`/`submit`, single-use job ids, template pinning so shares can't be stolen) with PPLNS payouts over roughly the last two blocks' worth of shares, dust carried forward, and a hard cap of 1M stored shares.

### Selling compute instead of hashing

Run `templates/srct_node.py` and your box joins the compute marketplace. One rule: **all in, one mode**. Mining mode gives proof-of-work 100% of the CPU and ignores AI jobs entirely; AI compute mode gives the marketplace 100% of RAM and capacity and never mines. Half-and-half splits are refused on purpose — dedication keeps accounting honest.

On the receiving end, jobs route themselves: inference-shaped work goes to the inference handler, training-shaped work goes to the training handler — and with no handlers given, built-in CPU workers run real deterministic arithmetic instead of refusing (a tiny MLP forward pass for inference, real gradient descent for training; explicit handlers and external programs via `CommandExecutor` still override them). New providers join with one command — `python templates/srct_node.py --auto-capability` measures the box (RAM + a canonical benchmark) and shells `srct-worker compute-join`, which stakes the bond and posts the offer. No manual hardware description; matching runs on measured capabilities, never on the device class. Everything flows through the node's compute REST endpoints (offers, jobs, assign, tickets, claims, escrow, receipts, payouts, challenges, bonds), so the whole market lives in the objects the node stores.

The marketplace dance, briefly: a provider posts a signed offer (capacity, price, measured throughput) and stakes a bond — posting is capacity-gated, so a small bond means small open exposure, and only settled work raises the limit. The requester funds the job's escrow, then either signs one assignment per planned shard, or posts open tickets on the board for any capable provider to claim — first valid claim wins, no waiting, no one-claim-at-a-time rule, tickets gossip to all peers with auto-claim by fitting providers, and settling immediately frees the next claim. Shards split max-min fair across provider identities (equal shares first, price only breaks ties), so one provider can never take a whole job. The worker runs the shard and posts a receipt; settlement checks the signature, the assignment or winning claim, the price, the deadline and the once-only rule, then schedules exactly the receipt's total from the funded escrow — payable after the network's delay window (disputable until then), refunding the unused remainder after the deadline. A receipt with no signed authorization behind it, or no funded escrow in front of it, settles nothing. A pre-signed exit attached to the assignment or designated ticket queues automatically on settlement — no second signature. Otherwise the requester signs an exit from the payout template, anyone submits the claim, and consensus pays the provider when the exit releases — the same permissionless crank pattern as withdrawals. Challenges, bond slashes and refunds ride alongside: re-run the work, compare bytes, slash the bond on mismatch, refund the unspent escrow after the deadline. Self-test: `python templates/srct_node.py --selftest`.

How each kind of AI work is supported:

| Workload | Where it runs | Status |
|---|---|---|
| Answering queries (inference) | Marketplace → participant inference handler / external model runtimes | Integrated via node REST + receipts |
| Training jobs | Marketplace → participant training handler | Integrated via node REST + receipts |
| One-command join | `templates/srct_node.py --auto-capability` + `srct-worker compute-join` | Measured profile, bonded, offer posted |

---

## Supply

There's **no fixed cap** — a deliberate choice (see [Decision 18](docs/decisions.md)). Here's the whole money story in one page.

**The ladder.** Rewards halve in whole SRCT every 262,800 blocks (about 5 years at 10-minute blocks):

```
76, 38, 19, 9, 4, 2, 1 SRCT
```

Whole coins, never fractions — halving 9.5 into 4.75 would break the integer math, so the ladder simply doesn't.

**Premine: zero.** Not "small". Zero. The genesis block minted nothing, and the code enforces it — not just the docs.

**The ladder total is exactly 39,157,124 SRCT.** Why not the round 39,157,200 a quick geometric sum suggests? Because genesis sits in a rung-0 height without minting, so the first rung pays out one block fewer. That missing 76 SRCT is the gap between the back-of-envelope math and what the chain can actually reach. `supply::max_issuance_sat` reports the real number.

**The tail.** After the ladder ends (height 1,839,600), rewards step down gently and never stop:

```
0.50 → 0.25 → 0.125 SRCT, then a permanent 0.1 SRCT floor
```

The floor arrives around height 2,628,000 (~50 years out). Testnet and mini keep it simpler: a constant 1 sat per block from their first tail period.

**Two guardrails keep everyone honest**, both checked in `Chain::apply_block` so miners, validators and nodes can never disagree about what's mintable:

1. **The issuance integral.** No block may mint past `cumulative_issuance_sat(height)`. Overflows are refused, never wrapped around.
2. **The rate anchor.** After the ladder era, each halving window may add at most **1% of the supply that existed when the window started**. Today's schedule sits ~3× under that ceiling — it never binds now, but it will refuse any *future* schedule that tries to dilute much faster. (The ladder era is grandfathered in.)

**Net supply can shrink.** Each block's fee splits 50/50: half burned, half into the chain's reserve (retained funds + B-Saver + Treats backing). Combined with the dwindling tail reward, simulations show net supply tipping below break-even around 5% network activity. That's a measured consequence, not a bug — the full analysis and sensitivity tables live in [docs/monetary-policy.md](docs/monetary-policy.md).

Curious about the live numbers? `status`, `GET /v1/conservation` and the `/metrics` gauges report gross issuance, removal and net supply. One warning: conservation passing doesn't mean nobody stole anything — a thief's exit conserves perfectly. So `/v1/conservation` also watches the exit window (`exit_window_total` vs cap, `pending_exit_sat`): worry when a window fills fast, not when the invariant stays green.

A few small rules worth knowing: `lock_time` is enforced — a transaction dated for the future can't mine early. A full mempool evicts exactly one entry (the cheapest) when a strictly better-paying transaction arrives. Difficulty retargets every block (gentle LWMA, ±10%, solve times clamped to `[T/4, 5T]`). The future-timestamp ceiling is admission policy, never a fork risk. And exits demand exact funding — outputs summing *precisely* to `amount + fees`, no change, no tip — or the exit waits patiently.

---

## Cryptography, quantum security and security layers

Money needs locks that hold — including against computers that don't exist yet. Here's what guards your coins today, what's ready for the quantum future, and how the four defensive layers fit together.

### The locks on the door right now

| Lock | What it is | Where to look |
|---|---|---|
| Hashing | SHA-256 inside, 64-byte SHA-512 `txid`/`block_hash` — comfortable margins even against quantum search on the two ids attackers want most | `SPEC.md §0` |
| Signatures | `1` ECDSA (low-s), `2` Schnorr, `3` ML-DSA-65 (FIPS-204 level 3); the `1+3` hybrid bundle stays safe even if quantum computers break ECDSA alone | SPEC §1.2, `sig.rs` |
| Domain separation | Every hash carries a frozen label (`DOM_BLOCK512`, `DOM_S1`, `DOM_S3_VWC`, …) so a hash meant for one job can never be replayed as another | `SPEC.md §0` |
| Quantum-spending switch | `verify_input_pq` can demand lattice signatures; activation is age-gated (`pq_activation_height`, `0` = off) so old coins are never stranded | Decision 24, `pq_signature` / `pq_migrate` tests |
| Checkpoints | BLS12-381 aggregates plus a per-signer ML-DSA-65 sidecar — the long-range history anchor doesn't lean on elliptic curves alone | `bls_checkpoint.rs`, `validators::check_sidecar` |

Deliberately rejected, on the record: BLS → ML-DSA multisig (signatures would balloon 3 KB per signer) and SPHINCS+ in checkpoints (8–30 KB envelopes nobody could relay). SPHINCS+ stays an idea for cold evidence only.

### Ready for quantum computers — how, concretely

Three mechanisms, all implemented rather than promised:

1. **Hashes with margin.** Transaction and block ids are 64-byte SHA-512 digests. Even with quantum search speedups, the work factor keeps roughly a 128-bit margin on the two identifiers an attacker would target.
2. **Hybrid signatures, available now.** Every signature the gate, the policy engine and x402 payments check travels as a bundle: classical ECDSA *plus* lattice-based ML-DSA-65. Both parts must verify, matched by scheme id; the address commits to the whole key set. So even if Shor's algorithm shatters ECDSA tomorrow, the lattice half still stands and nothing forges. Wallets can already generate classical, hybrid or fully post-quantum keys. Network-wide enforcement is the only staged part: `pq_activation_height = 0` (off) everywhere, and flipping it on only affects coins created *after* the height — history is never stranded.
3. **Checkpoints with a lattice sidecar.** Finality checkpoints aggregate BLS signatures at a 2/3 quorum and carry a per-signer lattice signature list alongside, so the anchor of history doesn't rest on one mathematical assumption.

### The four security layers, and how they team up

Each layer answers a different question, and each inner layer still holds if an outer one is bypassed:

| # | Layer | The question | How it works, briefly |
|---|---|---|---|
| 1 | **Admission policy** | *May this coin move under this grant?* | Checked in `check_tx` against live chain state: window, per-payment cap, allow-lists, ever-increasing nonce, revocation list. Violations die before block inclusion — no fee wasted. |
| 2 | **Smart Gate** | *May this workload do this exact thing right now?* | The owner signs a capability binding the exact action bytes, the context, an expiry and a counter. The boundary recomputes the hashes from what it actually sees — one changed bit denies. |
| 3 | **Wallet safety** | *May this key sign under current conditions?* | Session budgets cap total spend across policies; big spends *require* a second approver (your own key doesn't count); speed limits per payer; replays and conflicting receipts refused; everything lands in a hash-chained audit log. |
| 4 | **Settlement finality** | *Is this history really final?* | Depth-based finality plus committee checkpoints (BLS quorum + lattice sidecar); cheaters who sign two histories lose their whole bond; slashes split 50% burn / 50% vest. |

Picture a break-in: the wallet layer stops a stolen key from draining funds; the Smart Gate stops a hijacked program from pointing a valid key at something you never approved; the admission layer stops a crafted transaction from entering a block even if both outer layers fall; finality stops history itself from being rewritten afterward. And the audit trail? It lives on each node (verifiable, exportable) rather than on the chain — everyday actions get audited without paying a chain fee each. Only final settlement settles on chain.

A "grid deployment" just means Smart Gate grants on every enforcing node, with high-value actions pinned to one node.

---

## P2P and storage

**How nodes talk (`crates/srct-net`).** Every message starts with `magic || type || length`, and the magic is re-checked on every single frame. Nodes introduce themselves with magic + network id + protocol version + a nonce (proof-of-socket, 20-second handshake timeout). The magic bytes move with every protocol version that changes the wire format or state root — `mainnet` `6A4E5402`, `mini` `6A4E5403`, `testnet` `6A4E5404` — so outdated peers are turned away at the door before they can join. There's no address gossip in v0.2: bootnodes plus `peers.json` are the only way to find friends. Block and transaction relay follows the classic `INV → GETDATA → TX/BLOCK` dance; bad magic after a handshake is an instant ban, handshake failures score against the IP, and in-flight requests are capped. And remember: a handshake is never authentication.

**How blocks are kept (`crates/srct-store`).** An append-only log with checksums, plus atomic metadata and a canonical index — and deliberately *no* consensus rules inside. `flush` vs `sync` is an explicit durability promise; if the machine dies mid-write, the torn last line is detected and dropped on recovery. Thirty `persist_crash` tests make sure of it.

---

## API index

129 `/v1/` routes — here are the greatest hits; the full set lives in the router at `crates/srct-node/src/api.rs` (SPEC §19 wins if they ever disagree).

- **Node health:** `GET /v1/health`, `/v1/status`, `/v1/finality`, `/v1/fees`, `/v1/mempool`, `/v1/block/{hash}`, `/v1/block/latest`, `/v1/balance/{address}`, `/metrics`
- **Money:** `GET /v1/conservation`, `POST /v1/l2/broadcast`, `GET /v1/l2/state`, `POST /v1/credit/open|repay|default|deposit|bond|mint`, `GET /v1/credit/*`, `GET /v1/exit/crankable`. Node-local `credit/open` needs both lender and borrower signatures; `credit/bond` and `credit/repay` need the named account's signature. These are separate from the consensus Layer 2 credit positions. `credit/deposit` is an unbacked local test/admin writer, not a real deposit — disabled on exposed binds.
- **Escrow:** `POST /v1/escrow/open`, `GET /v1/escrow/{id}`, `POST /v1/escrow/{id}/release|settle` (release binds the delivered result; disputes freeze funds via `held_escrows`)
- **Guard & policy:** `POST /v1/policy/decide`, `/v1/policies*`, `/v1/guard/grant|decide|authorize|revoke`, `POST /v1/delegation/link|verify`, `POST /v1/authorize`
- **Compute market:** offers (`POST /v1/compute/offers`, list with live bond/score/capacity/exposure), jobs (`POST /v1/compute/jobs`, list), `POST /v1/compute/plan` (max-min fair across provider identities), assignments (`POST /v1/compute/assign` with optional pre-signed exit, list), tickets (`POST /v1/compute/tickets` with optional pre-signed exit on designated tickets, open board list, gossiped to all peers with auto-claim by fitting providers), claims (`POST /v1/compute/claims`), escrow (`POST /v1/compute/escrow/fund|refund`, scheduled payout after a per-network delay), settlement (`POST /v1/compute/receipt` with `auto_queued` flag, list), metering (`GET /v1/compute/ledger?from=&to=`), payouts (`GET /v1/compute/payouts`, exit-template, claim), challenges (open, second, status), bonds (register, withdraw, dispute, lookup)

---

## Timestamps

Money runs on block heights; wall-clock time only ever advises. The rules in plain words:

- **Time starts fixed.** `GENESIS_TIMESTAMP_MS` is baked into the code (January 1, 2026). Test harnesses build chains at `GENESIS + height × 1000ms`.
- **Blocks have a heartbeat.** 10 minutes on mainnet, 1 second on testnet/mini. Difficulty nudges every block (at most ±10%) to hold the rhythm.
- **The future can't fork us.** Consensus only enforces a *lower* bound on block times (no going backwards past the median). A block claiming to be from too far in the future is refused by each receiving node as policy — it never becomes a chain split.
- **Money uses heights, not clocks.** A transaction dated past the current height can't mine early. Policies, capabilities and stream windows all expire in block heights (`not_before`, `expires_at`, 30-block grant lifetimes) — so every machine reaches the same verdict with no clock to argue about.

---

## Performance and verification

- **Bench harness:** `crates/srct-bench` builds deterministic chains — `run --workload empty|realistic|adversarial --blocks N` on the mini profile with scratch-dir stores. It exercises the real `Chain::submit` path and measures.
- **Reports (measurements, not marketing):** `docs/performance/README.md`, the i5 baseline, the Phase-C scalability report, plus raw JSON results. Known harness quirk: giant realistic/adversarial 1k runs can trip on fee-drifted outputs — a bench-sizing bug, not a consensus bug.
- **Further reading:** `docs/final-report.md` (a dated historical report), `docs/fuzz.md` (the current 26-target cargo-fuzz inventory over wire, mempool, storage, L2, compute and confidential-compute parsers), and the HBM security review.
- **Test vectors.** `verification/tests/vectors/` holds the canonical byte layouts, generated from the implementation — never hand-edited. A second, independent proof-of-work implementation written from the spec (`verification/sim/srct_reference.py`) reproduces all 21 puzzle digests — evidence the spec is unambiguous, not just self-consistent.
- **Red team.** 21 adversarial integration tests across four files, each one confirmed to fail against the code it now guards. The defect log lives in [docs/status.md](docs/status.md). Author-run, like everything above — see [Honest limits](#honest-limits).

---

## What the chain is for

Two layers, two jobs:

**Layer 1** is ordinary money — wallets, transfers, blocks, P2P. Its job is to keep the books exactly, and nothing about it is AI-specific.

**Layer 2** is where compute gets paid for without trust. A **submitter** posts a job with escrowed money, a **worker** claims it and submits a result, and **anyone** may challenge that result. A committee decides who's right, and the money moves accordingly.

The whole Layer 2 vocabulary fits in thirteen transaction types — six for the task economy and exits, seven for authority and credit:

| Type | Code | Job |
|---|---|---|
| `PostTask` | `0x10` | Buyer opens a task, locks escrow, publishes the spec |
| `ClaimTask` | `0x11` | Worker takes the task, posts a deposit |
| `SubmitResult` | `0x12` | Worker submits the result with a signed attestation |
| `Dispute` | `0x13` | Anyone challenges with a counter-result and a deposit |
| `Settle` | `0x14` | Committee applies the verdict — pay, refund, slash |
| `ExitQueue` | `0x15` | Owner starts moving value back to Layer 1 |
| `Policy` | `0x16` | Owner publishes a spending grant |
| `PolicyRevoke` | `0x17` | Owner kills a grant — all its descendants die too |
| `AgentSpend` | `0x18` | Spender spends under a published grant |
| `CreditOpen` | `0x19` | Lender opens a loan; principal moves to the borrower |
| `CreditCollateral` | `0x1A` | Borrower tops up collateral |
| `CreditRepay` | `0x1B` | Borrower repays (interest first, then principal) |
| `CreditDefault` | `0x1C` | Anyone settles a loan unpaid past its deadline |

Every task walks six states: `Open → InProgress → ResultSubmitted → Disputed? → Settled`, with `Expired` as the timeout exit.

---

## Layer 1 and Layer 2

**Layer 1 — settlement.** Plain UTXO money with blocks, difficulty, fees and relay. No AI state, no AI opinions — just exact books. Miners, validators and nodes all enforce the same rules on every block: supply bounds, signatures, lock times, maturity, mempool discipline.

**Layer 2 — verifiable work.** Contracts, disputes, certificates and exits (SPEC §§15–17, code in `crates/srct-l2`):

- **Contracts** move tasks through their states, credit deposits 1:1 from ordinary Layer 1 payments to the profile's sink address, auto-settle unchallenged results when the window closes, and expire abandoned tasks.
- **Disputes** re-run the canonical CPU check over the task's own committed fields. The engine reads the evidence from the contract and computes the answer itself — it never accepts a precomputed answer as input, so no caller can dictate the verdict. Inconclusive? Then nothing settles.
- **Certificates** come in two flavors: `Quorum` (BLS aggregate + lattice sidecar, verifiable offline — genuine proof of correct work) and `WindowElapsed` (a receipt that nobody objected in time — explicitly *not* proof of correctness).
- **Exits** mature after finality depth plus binding finality, release through a claim anyone may build (it proves the exit record against the L2 state root from the queue block), and demand exact funding — sink outputs summing *precisely* to `amount + exit_fee + L1 fee`, no change, no tip. Mainnet caps exits at 1,000 SRCT per 144-block window with a 100 SRCT per-owner share, so one big fish can't starve everyone else; refusals delay, never destroy. Live from height 1 on every profile.

Money flows down (Layer 1 payment → Layer 2 deposit credit) and back up (queue → wait → crank-built claim → Layer 1 payment), with conservation holding across the whole round trip.

---

## Use cases and features

What does a UTXO chain with a work marketplace on top actually unlock? Settlement for work nobody re-runs. Machines spending under written rules. Payment for what was *produced*, not what was *claimed*. Reputation that travels with you and can't be bought. And value that always finds its way home. Here's the tour.

### Agent payments (x402)

SRCT speaks the web's own payment dialect — no second payment system invented. A client asks for a paid resource, gets back `402 Payment Required` with a payment envelope, and retries carrying a `PAYMENT-SIGNATURE`. The node verifies it through the ordinary payment admission path, so consensus never changes:

```
Agent ──GET /v1/paid/weather──▶ 402 + PAYMENT-REQUIRED (exact, srct:mini, 500 sat)
Agent ──budget check (max, allow-lists)──▶ PaymentRequest → Authorization → MachinePayment
Agent ──GET + PAYMENT-SIGNATURE──▶ verify → admit → 200 + PAYMENT-RESPONSE + weather
```

- `GET /v1/paid/weather` — a demo paid endpoint (500 sats, fixed recipient, service `x402-weather-v1`). No signature → `402`. Good signature → `200` with the goods.
- `POST /v1/x402/verify` — the facilitator's "does this look right?" check (no state changed).
- `POST /v1/x402/settle` — the facilitator's "take the money" step (same admission as any payment).
- Your wallet checks the budget *before* signing (`X402Budget`: max amount, approved recipients, approved services). A server asking for too much is refused locally, on your machine. Missing allow-lists mean "anywhere"; present ones behave exactly like spend policies (a present-but-empty list allows nothing). `check_guarded` adds a short fuse: the spend must land before its expiry, capped at 30 blocks.
- `scheme` is `exact` only. `network` is CAIP-2 `srct:<reference>` — or, alongside SRCT, an EVM rail (`eip155:8453` Base, `eip155:84532` Base Sepolia: advertised, never settled by this node). Amounts are plain satoshi strings.

Full mapping, curl flows and edge cases: [`docs/x402.md`](docs/x402.md). Try it: `python verification/sim/x402_paid_api_demo.py`.

### Micro-payments and wallet safety

Paying per click shouldn't cost a transaction per click. Three tricks make tiny payments practical — none of them touches consensus; all of them reuse ordinary payments, policies and credit. Full guide: [`docs/micropayments.md`](docs/micropayments.md).

| Trick | Endpoint | The idea |
|---|---|---|
| Batch quotes | `POST /v1/payments/aggregate` | Many recorded payments, one shared settlement. Returns the gas, the fee, the per-payment cost and what you saved vs going solo. Read-only quote. |
| Stream channels | `POST /v1/streams/open`, `POST /v1/streams/settle`, `GET /v1/streams/{id}` | Open once (rate per block, expiry, hard cap); each unit of work mints an off-chain voucher; only the final voucher settles on chain. The stream book insists on exact, ordered, in-cap settlement. |
| Sponsored intents | library `srct_core::micro::SponsoredIntent` | A sponsor signs fee coverage for your priced quote — an auditable receipt, deliberately *not* a consensus fee-payer, so sponsors can cover costs but never print money. |

The payoff (`python verification/sim/micropayment_benchmark.py`): 10 payments to one provider cost one base fee instead of ten; a 100-unit stream settles once instead of 100 times. Fewer transactions also means fewer confirmation waits — latency wins for free.

And the wallet? It's careful the way a good bank is careful — six habits, always on (operator guide: [`docs/wallet-safety.md`](docs/wallet-safety.md)):

1. **A policy on everything** — per-payment cap, per-window cap, approved recipients and services (empty means none), validity heights, an always-increasing counter, owner revocation. Fail closed, always.
2. **A session budget above the policies** — one aggregate cap per agent across all its policies, so spending can't be split across many small grants to dodge the limit. (`SRCT_SESSION_WINDOW_BLOCKS` + `SRCT_SESSION_CAP_SAT`; both zero means the gate is off.)
3. **A second human for big money** — at or above the high-value threshold, the node answers `403 human_approval_required` until someone on the approver list co-signs. Your own key doesn't count. With nothing configured, mainnet defaults to gating at 10 SRCT — the protection never depends on a forgotten setting. Plus per-payer speed limits, and a test-mode guard that refuses `srct/mainnet` spends.
4. **No double-spend, no double-receipt** — exact replays are flagged before admission; conflicting receipts for the same payment are refused with `409`.
5. **Receipts that reconcile** — every admission holds a credit reservation until its receipt arrives; `GET /v1/payments/unsettled` shows payments still waiting (retry these, don't rebuild them); `GET /v1/receipts/orphans` shows receipts pointing at nothing.
6. **A log that can't be quietly edited** — every grant, admission, refusal, stream and receipt joins a hash-chained audit log. It exports as auditor-friendly JSON, re-checks on import, and verifies via MCP. Node-local and export-verifiable rather than chain-anchored — everyday life gets audited without a chain fee per line; only final settlement hits the chain.

### Smart Gate (security layer)

One question for the whole AI-agent era — *may this workload do this exact thing, right now, under this grant?* — answered `allow`, `deny` or `needs_approval` anywhere, settled as trust on Solar.

- **The idea in one paragraph.** The owner signs a capability: "this workload may run *these exact bytes* in *this exact context*, before *this height*, *this many times*." The signature covers the hashes of the policy, the action and the context, plus expiry and a counter. The bare capability is public bytes anyone can copy — only the owner's signature makes it authority, and every boundary verifies it. The grant itself only bounds rate and validity; it never names tools or APIs. Exactness comes from recomputation: the boundary re-hashes what it actually sees, and one changed bit denies. Short-lived (30 heights max, no wall-clock), strictly increasing counter, no spending across identities. Deterministic, integer-only, fail closed.
- **How a day at the gate goes.** The owner signs a narrow policy once and registers it. Risky grants name an independent approver and demand a signed approval per admission — a caller claiming "low risk" can never switch that off, and a grant naming its owner as its own approver is refused at registration. Before touching any key, the workload asks the gate; the runtime verifies the owner signature offline and runs only on `allow`. High-risk actions return `needs_approval` until the designated approver's signature arrives. Grants can pin a workload id with a fresh possession proof each run, and capabilities can be scoped to one node. Stateless pre-checks commit nothing; stateful admission commits the window and counter. Refusals cost no budget and come with names (`action_mismatch`, `expired`, `nonce_reuse`, `wrong_audience`, …).
- **Replays, revocations, memory.** Counters are nonzero and strictly increasing per grant, saved in the node's `GuardBook` across restarts; revocation kills the grant and every descendant, and even the stateless check consults the revocation set. Each node's registry + revocation set + book is authoritative for that node (MCP-local gate state is just a cache). The worker boundary re-admits through the authority on every run — revoked means deny, unreachable means deny. Revokes also relay over P2P (verified by each receiver, applied through the same path), so kills converge — but windows stay per-node, so pin high-value capabilities to one node; unscoped ones stay usable everywhere independently until every node hears the revoke. Full house? Registry and book (1,024 grants each) refuse rather than evict.
- **Quantum-safe from birth.** Every signature the gate checks travels as a hybrid bundle (ECDSA + ML-DSA-65). SPEC §1.2 is the reference.
- **Free to verify, paid to trust.** Anyone can check a capability anywhere: `srct-policy::guard_verify`, MCP `guard.check` / `guard.authorize`, or the node routes (`/v1/guard/decide` to peek, `/v1/guard/grant` to register, `/v1/guard/revoke` for the kill switch, `/v1/guard/authorize` to commit with audit). Verification needs no Solar node; enforcement and audit settle on the enforcing node — which is exactly what drives SRCT demand (fee burn + reserve accounting). Full design: [`docs/smart-gate-architecture.md`](docs/smart-gate-architecture.md).
- **Company payments in an afternoon (V1).** The finance-gate quick start freezes the intent shape into five integration steps plus a sales demo: [`docs/universal-security.md`](docs/universal-security.md), `python scripts/finance_gate_demo.py --node http://127.0.0.1:PORT`. Lock-in tests: `cargo test -p srct-node --test universal_security`.

### Agent economy

Reputation you carry, spending power in tiers, job escrow with the result baked in, dollar prices settled in SRCT, auditable on/off ramps, and loans for working capital. All of it lives in node-local books — except the Layer 2 credit positions in [Credit and lending](#credit-and-lending), the collateralized on-chain primitive underneath.

**Reputation that travels + wallets with tiers** ([`docs/reputation.md`](docs/reputation.md)). Your history moves with you: receipts record finished tasks and payments; credit positions record repayments and defaults (`POST /v1/reputation/passport/attest` gathers your events from node books). An issuer that checked the events signs a `PassportBatch`; the node re-verifies every source against its own books before accepting it. Any service can then score you (`GET /v1/reputation/score/{agent}?role=machine` → `Deny | Throttled | Standard | Preferred`). Gaming it is hard on purpose: every positive event is backed by real money changing hands; doing repeat business with one friend counts at square-root value; stake-backed events weigh more (a repaid collateralized loan scores +4 vs a bare task's +1); bad marks stick (dispute lost −4, default −8, and any default zeroes your suggested credit limit). Account age and raw transaction counts are ignored — they prove nothing. Tiered wallets split one funding into narrower child policies — say 20/tx for trusted services, 1/tx for experiments. A tier can never outspend its parent, tiers nest, and revoking the root stops the whole tree (`POST /v1/wallet/tier`, `GET /v1/wallet/tiers/{agent}`).

**Job escrow between agents** ([`docs/agent-jobs.md`](docs/agent-jobs.md)):

```
POST /v1/jobs/open → POST /v1/jobs/{id}/accept → POST /v1/jobs/{id}/deliver
→ POST /v1/jobs/{id}/resolve|release (checked against the delivered result hash)
— or — POST /v1/jobs/{id}/dispute (money freezes until the arbitrator decides)
```

Release pays for *this exact result* — not "some dataset, trust me". The resolve signature ties job, direction and result to the arbitrator named at opening. Every step is signed by the right party: the hirer signs the terms, the worker signs (job, result), the borrower signs loan acceptances — nobody opens jobs or debt in someone else's name. Disputes lock funds node-side (persisted): releases, settlement bindings and auto-refunds all wait. `GET /v1/jobs/{id}` shows the record, escrow state and lock flag.

**Dollar prices, SRCT settlement** ([`docs/usd-settlement.md`](docs/usd-settlement.md)). SRCT is a mined coin, not a peg — services price in dollars (or a supported stablecoin) and settle in SRCT at a locked, transparent rate. The issuer must be whitelisted (`SRCT_FX_ISSUERS`); quotes state amount, sat due, fee, slippage, rate and expiry up front; stale quotes are refused. The stablecoin leg is an audit-trailed intent — custody never touches the node.

**Getting in and out** ([`docs/ramps.md`](docs/ramps.md)). The node is the auditable registry; the ramp provider handles custody and compliance off-protocol. Provider-signed quotes in either direction, intents that only the quoted provider can close, terminal states of filled *or* refunded (never both).

**Loans for getting things done** ([`docs/lending.md`](docs/lending.md)). Lenders publish standard terms (rate ≤ 10%/window, full collateral); borrowers browse cheapest-first and accept — with bond and collateral already funded, because terms come from the offer, not from negotiation. History prices risk (advisory only; any default zeroes your limit; no history means zero), a dashboard shows exposure and due-soon items, and collateral coverage is quoted live in basis points. If things go wrong: collateral first, then the borrower's bond, then the lender absorbs the rest — new money is never printed. Borrowers can even authorize automatic repayment from revenue (revocable, capped, expiring).

One demo ties reputation, tiers, jobs, dollar quotes, ramps and lending together: `python verification/sim/agent_economy_demo.py`.

### SRCT Treats (tradeable reward claims)

[`docs/treats.md`](docs/treats.md). Think of Treats as thank-you points with teeth — the third kind of value next to liquid coins and locked escrow, made for agents, machines and robots. Each block feeds 10% of its reserve leg into the Treats backing (`Chain::treat_reserve`, reorg-safe, visible in `status` / `conservation` / `/metrics`). Nobody can mint them freely: Treats accrue only from verified settlement (automatic receipt minting with a base weight plus a capped fee bonus, or claiming for verified work) or from owner-signed gifts. They store, they're capped (per-holder and global ceilings, no decay), they move agent-to-agent under sender signatures, and they redeem by burning for single-use vouchers (fee credit, discount, trial, service credit). A Trial voucher even covers part of loan repayment. Endpoints for balance, gift, transfer, claim-work, redeem, voucher consume (beneficiary must sign) and reserve — plus `srct-worker treats-balance` for a quick peek.

### How fraud is detected

One referee, and it's not a person: the canonical CPU check. Nothing else is authoritative, and no caller gets to supply the answer.

**The referee.** `compute_ir::reference_result_hash(...)` is a fixed-round reshuffling of the task's own committed data — task id, code hash, input hash, memory size. It answers from the *task*, never from anyone's claims about it. Two properties make it trustworthy: it's a fixed recipe, not a general interpreter (the spec forbids an on-chain interpreter, and this respects that), and it takes no height, clock or randomness — identical tasks produce identical bytes on every machine, every time.

**The story in one diagram:**

```
worker submits R
      │
      ├─ silence until the window closes
      │     → auto-settle Correct → paid → WindowElapsed certificate
      │                          (a receipt for "nobody objected" — NOT proof)
      │
      └─ challenger submits R′ with a deposit
            → the engine computes the reference itself
                  reference == R   → worker was right   → Correct
                  reference == R′  → challenger is right → Fraudulent
                  matches neither  → inconclusive       → nothing settles
```

The key sentence: the engine reads the evidence from the contract and computes the reference *itself*. Accepting it as an argument would let any caller dictate the verdict — so it doesn't.

**"No match is not guilt."** Inconclusive means exactly that: nothing settles. A broken or unrunnable task can never accidentally become a fraud conviction.

**Votes that can't be faked.** Each committee member signs one vote per key they hold — four keys means four members, not one member shouting four times, because a quorum counts *distinct* signers. Every vote binds task, verdict, reference result, network, height and signer under its own domain label, signing exactly `SettlePayload::signing_hash` — which is what lets votes aggregate into the settlement transaction and be re-verified from scratch with real cryptography. Nodes check each vote against *their own* committee and height and relay only what they accepted, so a bad vote travels at most one hop. Replays, duplicates and relay loops can't inflate a quorum. An honest disagreement (split committee) is refused but never punished as cheating; only a genuine double-sign is recorded as `ArbitrationEquivocation`. Network and height ride inside every signed message and every quorum certificate, so old-branch certificates can never be replayed.

**And the verdict means:**

| Who | What happens |
|---|---|
| Worker | Deposit slashed: 50% burned on the spot, 50% vested over a year |
| Buyer | Refunded in full |
| Challenger | Bounty from the reserve, deposit returned |
| Certificate | **None** — a fraud verdict proves nothing was correct |

Settlement costs a proportional fee: 0.1% of task value, minimum 1,000 sats.

### How withdrawals work

Deposits are a two-way street. Here's the trip home, in four steps:

1. **Deposit.** Send ordinary Layer 1 coins to the profile's sink address. Nothing new to learn. Credited 1:1 after finality depth.
2. **Queue.** Sign an `ExitQueue` transaction; it debits `amount + exit_fee + queue_fee` and files `(owner, counter) → (amount, destination, height)`. Counters are per-owner and strictly increasing.
3. **Wait.** After finality depth *plus* binding finality, the exit becomes settleable. Exits follow the same rule as deposits or a stricter one — never weaker.
4. **Release.** A **permissionless crank** builds the claim: it spends sink outputs and proves your exit record against the Layer 2 state committed at the queue block.

The claim is authorized by a **proof, not a signature** — the sink holds no key. Consensus pays exactly the destination your proven record names (no redirecting), and whoever builds the claim collects the fee you prepaid at queue time — which is why there's always someone willing to crank it.

**Exact change only.** A claim must spend sink outputs summing *precisely* to `amount + exit_fee + L1 fee` — no change, no tip. If no subset of outputs adds up exactly, the exit waits rather than touching a stranger's deposit. Slightly awkward, completely safe.

**Fair queuing.** Mainnet caps exits at 1,000 SRCT per 144-block window, with 100 SRCT per owner inside it. Why both? A global cap alone can be hogged by one filler until rollover; the per-owner share refuses the hog by name while everyone else keeps queuing, and resets each window. Refusals delay, never destroy.

**Anyone can crank.** Claims aren't miner-only: `GET /v1/exit/crankable?claimant=<address>` hands settleable claims to any third party, so even a non-miner can assemble them into a block. Escrow settlements ride the same rails — settle the escrow, queue the exit, let the crank pay it. No separate escrow coin needed.

**Fork-safe.** A release is an ordinary reversible Layer 1 operation: rollbacks restore the sink outputs, clear the identity, and Layer 2 replay rebuilds the watch.

**The books still balance.** The joint conservation check needed no new exit term — the Layer 1 payment and the Layer 2 debit cancel while the sink balance drops by the same amount.

> Live everywhere from the start: exits activate at height 1 on all profiles — same as Bitcoin spends.

### Validators and finality

**Putting up a bond.** Three transaction types — bond, unbond, slash — feed a bond ledger with an ordering index. There's no wealth test to join — but there is an anti-dust floor (zero on mini/testnet, 0.01 SRCT on mainnet) so 1-sat spam can't squat ledger entries on every node forever. Unbonding takes 1,008 blocks (about a week) to unlock. And bonds only admit keys that prove ownership: every bond carries a 96-byte proof-of-possession signature, and payloads without one don't even decode.

**How history becomes final.** Two gears mesh: depth-based finality (100 Bitcoin-style blocks) secures the early chain, and binding finality switches on at height 100 on mainnet. The 21-key bootstrap committee signs until the first real bond lands, then the stake-weighted TopN set takes over. Those 21 keys are public (deterministic in source), so serving mainnet with them needs an explicit `--allow-bootstrap-committee` flag — cold start is a conscious choice, never an accident. Replace them with bonded keys; that's the operator's first job.

**Committees with terms.** Each epoch's committee is frozen from the bond state at its seed height and serves the whole epoch; mid-epoch bonds take effect at the next seed. Reorgs across a seed roll the committee back exactly — snapshots travel with chain state and the finality frontier rewinds (`rewind_observation`), so a certificate from the losing branch can never be replayed elsewhere.

**Slashing stays in its lane.** Each checkpoint is verified against *its own* epoch's committee, failing closed when that set is unavailable — no fallbacks, no guessing. A validator who left the TopN can still be slashed for misbehaving while bonded. Committee caches keep the current set plus the previous one through its grace period, then expire; a failed derivation is a hard error, and there's no genesis fallback once bonds exist.

**C1/N1 root validation is shipped but not activated.** The chain can carry a
BLS checkpoint certificate in a block and, after its two activation heights,
rejects a block whose `l2_state_root` differs from deterministic replay. All
built-in profiles currently set those heights to `0`, so operators must not
present this as an active-network guarantee before a scheduled, tested
activation.

### Wallets, transfers and policies

**Wallets you'll recognize.** Keys live in `wallets.json`, encrypted with your `SRCT_WALLET_PASSPHRASE` (Argon2id + ChaCha20-Poly1305, locked-down file permissions, atomic writes). Plaintext files are refused unless you deliberately pass `--allow-plaintext-wallet`. Addresses are 20-byte hex with a `jt1` prefix; classical, hybrid and post-quantum addresses are distinct by construction. Secrets are redacted in logs and wiped from memory on drop.

**Transfers you'll recognize.** Spend confirmed outputs to an address with an integer amount and a fee. Future-dated transactions can't mine early. Freshly mined coins need to mature first (100 blocks mainnet, 10 elsewhere). Balances come in three flavors — confirmed, spendable, pending (`GET /v1/balance/{address}`).

**Policies with teeth.** Publishing a grant (`srct-node policy …`) puts it on chain, so *every* node enforces it — not just your wallet. Spending under it means naming the policy and the next counter value; admission checks the live state: grant alive, window open, per-payment cap respected, recipient and service allowed, counter increased, ancestry unrevoked. Killing it (`srct-node policy --revoke`) takes down all its descendants too. Over the network, the same flow goes through `POST /v1/l2/broadcast` (which dry-runs against current state first) after `POST /v1/policy/decide` gives you the chain's own reasoning — violations are refused *before* they mine, not skipped after.

### Credit and lending

Loans as chain facts, not spreadsheet entries. Principal, collateral and debt are real coins in the UTXO set — consensus state. A loan lives four steps: **open**, **repay**, and then either **repaid-in-full** or **defaulted** — with optional **collateral top-ups** anytime before settlement. Full collateral by default (100%), interest capped at 10% per window charged per whole window, repayments eat interest first, overpayments are refused rather than trimmed, anyone may default an overdue loan, and losses fall in order: collateral, then a marketplace bond if one was posted, then the lender — the protocol never prints money to plug a hole. The full mechanics (wire types, terms, fee split, interest math, settlement order): [`docs/lending.md`](docs/lending.md#the-consensus-primitive-underneath).

```sh
# Open a loan: you're the lender, --to is the borrower.
# Collateral defaults to the full principal (100%).
srct-node credit --to <borrower-address> --amount <SRCT> \
                --collateral <sat> --rate-bps <bps> \
                --window <blocks> --deadline <height> --nonce <n>

# Repay (interest first). Use --amount-sat for exact satoshis.
srct-node credit --repay --position <id> --amount <SRCT>

# Default a loan at or past its deadline (anyone may do this).
srct-node credit --default --position <id>

# See all positions.
srct-node credit --list
```

Before the consent activation, the lender signs legacy `CreditOpen`; the borrower signs `CreditRepay`; any wallet can sign `CreditDefault` once time's up. At and after activation, `CreditOpenV2` requires matching lender and borrower signatures before collateral can be locked. Locally the CLI mines the transaction directly; over the network, serialize the `L2Transaction` to hex and POST it to `/v1/l2/broadcast`, which dry-runs it and queues it for the next block.

Topping up collateral (`CreditCollateral`, `0x1A`) goes through the same broadcast endpoint — the CLI doesn't expose it directly, but the worker SDK does (`add_credit_collateral`).

> **Chain loans vs the loan marketplace.** This section is the consensus primitive: collateralized loans as chain state. The offers, borrower histories, credit limits, dashboards and auto-repay in [Agent economy](#agent-economy) are the friendly marketplace on top — they price and discover loans but never replace collateral. The `credit` API never consults a reputation score.

---

## Network profiles

Same code, different numbers — pick your playground:

| | `mainnet` | `testnet` | `mini` |
|---|---|---|---|
| Block time | 600 000 ms | 1 000 ms | 1 000 ms |
| Halving period | 262 800 | 2 000 | 2 000 |
| Start reward | 76 SRCT | 76 SRCT | 76 SRCT |
| Finality depth | 100 | 20 | 20 |
| Coinbase maturity | 100 | 10 | 10 |
| Genesis validators | 21 public bootstrap (quorum 15) | 4 deterministic | 4 deterministic |
| L2 settlement validators | 21 bootstrap keys, then live bonded TopN | 4 deterministic | 4 deterministic |
| Binding finality | on at height 100 | on at height 20 | off |
| Exits | on at height 1 | on at height 1 | on at height 1 |
| PQ spend requirement | **off** | off | off |
| Mining puzzle | `hybrid-v1` (`puzzle_id = 1`) | `hybrid-v1` (`puzzle_id = 1`) | `hybrid-v1` (`puzzle_id = 1`) |
| Retarget | LWMA every block, ±10% | LWMA every block, ±10% | LWMA every block, ±10% |
| Genesis difficulty | 1 | 1 | 1 |

Reading the table: `mainnet` boots with 21 public deterministic keys (quorum 15) so finality can bind before any stake exists — the first bond swaps in the stake-weighted TopN committee. The L2 settlement authority follows that same live committee: bootstrap before the first bond, then bonded TopN by applying-block height. Exits work from height 1. The PQ row is Decision 24's `pq_activation_height`: `0` means nobody is refused for lacking a lattice signature, and flipping it on only affects outputs created *after* the height — history is never stranded.

Network magic bytes (§13.3): `mainnet` = `6A4E5402`, `mini` = `6A4E5403`, `testnet` = `6A4E5404`. They change with every protocol version that alters the wire format or state root — outdated peers are refused at the door before they can join.

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

Mining in full — the three ways to mine, where rewards land, hardware options, pool protocol — lives in [Mining and AI compute](#mining-and-ai-compute); the template/submit endpoints are specified in SPEC §19.2.

### Agent authority and credit, from the terminal

Grants sound abstract until you type them. A grant is your signed permission slip for a named spender — published on chain, enforced by every node:

```sh
# The deposit address: an ordinary L1 payment to it credits your L2 balance.
srct-node l2 --deposit-address
srct-node send --to <deposit-address> --amount 5

# A grant: this key may spend up to 0.01 SRCT per payment and
# 0.05 SRCT per window, to this recipient only.
srct-node policy --spender <spender> --per-tx 1000000 --cumulative 5000000 \
                --recipients <recipient>

# The agent spends under it.
srct-node agent-spend --policy <policy-hash> --to <recipient> --amount 0.002 --nonce 1

# You change your mind: kill it, and every grant below it dies too.
srct-node policy --revoke --agent-id <agent-id>
srct-node policy --list
```

Credit feels the same — the **lender** signs, real principal moves, real collateral backs it:

```sh
srct-node credit --to <borrower> --amount 1 --collateral 100000000
srct-node credit --repay --position <position-hash> --amount 1
srct-node credit --list
```

Every command checks the transaction against the state the chain will replay and tells you the chain's own reason for refusal — instead of mining a block the replay would skip.

Everyday options: `--network <mainnet|testnet|mini>` (default `mini`), `--data-dir <path>` (default `./chain`).

`serve` also takes `--listen`, `--connect`, `--bootnodes`, `--peers`, `--interval`, `--api-listen`, `--api-token`, `--api-allowed-host` and `--no-mine`. `--bootnodes` dials peers at startup (SPEC §13.6: v0.2 has no address gossip, so bootnodes plus `peers.json` are the only way to meet anyone). `--credit-issuer` lists the BLS keys trusted to sign credit attestations for `POST /v1/credit/mint` (comma-separated 48-byte hex; empty means every mint is refused). `send --amount` takes SRCT (`--amount-sat` takes satoshis); balances print in SRCT.

The API is loopback-only and credential-free by default. Binding anywhere else requires a token:

```sh
# Exposed to the world: a bearer token is mandatory (§19.2). Keep it in the
# environment — command-line flags show up in `ps`.
export SRCT_API_TOKEN="..."
srct-node serve --network testnet --data-dir ./chain --api-listen 0.0.0.0:8080

# Loopback: unchanged, no credentials needed.
srct-node serve --network testnet --data-dir ./chain --api-listen 127.0.0.1:8080
```

Exposed binds demand `Authorization: Bearer <token>` on every request (compared in constant time). Every bind — loopback included — requires a `Host` header as DNS-rebinding armor: loopback accepts loopback names only; non-loopback additionally accepts IP literals, the bound address, and `--api-allowed-host` / `SRCT_API_ALLOWED_HOSTS` entries. Missing, unknown or malformed `Host` gets a 403. Exposed binds also rate-limit per address, and every bind caps requests at 10 seconds, 64 in flight, 128 connections, and 30 seconds for headers (the slowloris bound).

Node-local state (credit, escrow, delegation books — never consensus) now survives restarts: receipts, replay tracker, payments and settlement links, reservations, policy accounting, credit and minted attestations, delegations, issued policies, revocations, escrows and exit bindings — plus compute assignments, settled payouts and their exit bindings, the compute escrow and bond books, open challenges, queued P2P revoke broadcasts, the usage ledger, and confidential-tier attestation records — all persist to `state.bin` (envelope v18; v8–v17 migrate) — an atomic, digest-checked file that refuses to start from corruption — flushed on every change, plus once at shutdown.

---

## Testing

```sh
cargo test --workspace                                   # full suite (refresh counts with scripts/test_count.sh)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
python verification/sim/verify_vectors.py --check                     # consensus vectors
```

Suites for the fast inner loops:

```sh
cargo test -p srct-core --test x402           # x402 challenge/budget/authorize/pay/admit roundtrip
cargo test -p srct-node --test x402           # 402 → verify → settle → retry over real HTTP
cargo test -p srct-policy                     # chain-agnostic decide/verify JSON seam
cargo test -p srct-mcp                        # keyless wallet guard, portable prove/verify, bound grants
cargo test -p srct-node --test micro_safety   # batch quotes, streams, sponsor intents, session/risk/audit
cargo test -p srct-node --test agent_economy  # passport, tiers, jobs, FX quotes, ramps, lending marketplace
cargo test -p srct-agentnet                   # pairwise, double ratchet, sealed sender, groups, MLS-style epochs
cargo test -p srct-compute                    # fair allocation, delayed payout, metering ledger, ticket gossip, backend registry, tickets, claims, capability matching, capacity, bonds, challenges, escrow
cargo test -p srct-net --test ticket_relay   # 3-node ticket broadcast over real TCP, no double claim
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

CI (`.github/workflows/ci.yml`) runs format, clippy, the full suite, a release build, the vector cross-checks, attack simulations, and all 26 fuzz targets on nightly with ASan. `.github/workflows/release.yml` re-runs the same gate on a tagged tree before publishing artifacts with checksums and a keyless cosign/Sigstore bundle.

**Every CI action is pinned to a commit SHA**, with its tag in a trailing comment — a compromised or retagged action can't silently change what runs. Job tokens are least-privilege: `contents: read` by default; only the two jobs that genuinely write take more (the signing job's `id-token: write` for its OIDC identity, the publish job's `contents: write`). Dependabot keeps the pins honest but opens **no pull requests** — every update is a branch, and this repo keeps `main` as its only branch, so bumps are an owner step (`cargo update -p <crate>` plus `cargo audit`). Security *alerts* still flow normally from the advisory database.

**Vectors.** `verification/tests/vectors/` holds the canonical byte layouts, generated from the implementation — never hand-edited. `verification/sim/srct_reference.py` is a second proof-of-work implementation written from the spec rather than the Rust (same author, so a second implementation, not a second party) — and it reproduces all 21 puzzle digests, evidence the spec is unambiguous rather than merely self-consistent.

**Fuzzing.** 26 cargo-fuzz targets cover L1 wire, mempool, storage, checkpoints, L2 codecs and state, compute state, shield bundles, vendor certificate chains, TDX/SNP/NVIDIA reports, the confidential keystore and the worker. They assert real invariants — decode/encode round-trips, bounded allocation, value conservation and fail-closed parsing under adversarial inputs — not just "didn't crash".

**Red team.** 21 adversarial integration tests across four files, each confirmed to fail against the code it now guards. The defect log: [docs/status.md](docs/status.md). Author-run, like everything above — see [Honest limits](#honest-limits).

---

## License

**Copyright © 2026 The Solar Cyber Unit developers.**

**Code: MIT** — the same permissive licence Bitcoin Core uses. The full text ships at the repo root (`LICENSE-MIT`). You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, and permit persons to whom it is furnished to do so, including commercially.

---

## Security

[`SECURITY.md`](docs/SECURITY.md) is the disclosure policy: what counts as a vulnerability, the severity model, the 90-day window, and how to reach us (GitHub Security Advisory, or `security@solarcyberunit.org`). Please don't open a public issue for a security defect.

---

Full protocol specification: [`SPEC.md`](docs/SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).
