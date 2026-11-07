# Mainnet Operational Readiness

**Status: READY.** All three protocol blockers have been resolved by code changes:
the mandatory 5,000 SRCT validator stake has been removed (any positive bond is
accepted), the L2 fee path now has a flat minimum floor, and the credit/escrow
node-local boundary is explicit. This document records the operational state of
those decisions.

**Author and copyright holder:** Community-owned. No single person holds it,
like Bitcoin. (© 2026).

## What is actually implemented

| Area | Implemented |
|---|---|
| Versioned network profiles | `NetworkParams::{mainnet, testnet, mini}`, `by_name`, `validate` (`crates/srct-core/src/params.rs`) |
| Deterministic genesis | genesis mints nothing; identical across profiles (SPEC §11) |
| Block storage | `srct-store`: append-only checksummed `blocks.log` + atomic metadata; torn-tail recovery reported, mid-chain damage refused |
| Node CLI | `srct-node {init,mine,send,status,verify,show-block,balance,wallet,export,serve,policy,agent-spend,credit,l2}`; flags only, **no config file** |
| P2P + tx relay | `srct-net`, SPEC §13/§13.14 |
| L2 replay, deposits, VWC, reputation | `srct-l2`, SPEC §14–§19 |
| Opt-in REST API | `--api-listen`, `/v1/*` routes (see §2) |
| Fuzz harness | `fuzz/` (17 targets, cargo-fuzz nightly + ASan) |
| Benchmarks | `crates/srct-miner/examples/bench_hashrate.rs` (`--threads --difficulty --max_attempts`); measured ~114k H/s release on 4 threads against `hybrid-v1`, plus inline `#[ignore]`d probes |
| External mining | `srct-miner` binary (`--node --miner [--threads] [--batch] [--backend cpu\|portable\|auto]`, `SRCT_MINER_BACKEND`), node `GET /v1/mine/template` + `POST /v1/mine/submit`, `Chain::build_template_with` seam |
| Pool mining | stratum-lite JSON-lines (`getjob`/`submit`, single-use job ids, anti-theft template pinning, share vs network difficulty) with PPLNS accounting (`fee_bps`, windowed split, dust carry, `mark_paid`) |
| **On-chain agent authority** | **Consensus state, not node-local.** `Policy` (`0x16`), `PolicyRevoke` (`0x17`) and `AgentSpend` (`0x18`) are Layer-2 transaction types (SPEC §21, Decision 25). The owner's signature binds the grant bytes, the **spender** and the **agent identity** together; one live grant per agent; the per-transaction cap, the tumbling per-window cap, the recipient and service allow-lists, the validity window and the strictly increasing nonce are enforced against state the chain keeps; a delegated grant that widens its parent is refused; revocation reaches every descendant. Committed under the Layer-2 state root (`POLICY_LEAF_TAG` `0x05`) |
| **Credit positions on chain** | **Consensus state.** `CreditOpen` (`0x19`), `CreditCollateral` (`0x1A`), `CreditRepay` (`0x1B`) and `CreditDefault` (`0x1C`) (SPEC §22, Decision 26). The **lender signs** the terms, the principal moves to the borrower's balance, the borrower's own funds are locked as collateral (checked before the principal arrives), interest is charged once per period and paid before the principal, a repayment larger than the debt is refused, and a default is permissionless: the collateral answers for the debt, the surplus returns to the borrower, the remainder is a shortfall the lender absorbs. Committed under the Layer-2 state root (`CREDIT_LEAF_TAG` `0x06`) |
| **Independent cross-check** | `verification/sim/l2_authority_reference.py` is a second implementation of the authority and credit rules, written from SPEC §21–§22 in Python (it derives the same addresses, agent identities, grant hashes and position ids). It emits `verification/tests/vectors/l2_authority_vectors.json`, and `crates/srct-l2/tests/l2_authority_vectors.rs` replays those scenarios and asserts the same verdicts, the same reasons and the same final state |
| **Agent tooling** | Worker SDK `srct-worker/src/authority.rs` (publish, spend, revoke, open, collateralise, repay, default - plan locally, then broadcast); MCP `inspect.policy`, `inspect.agent_spend`, `inspect.credit` (keyless) plus the wallet-guard ops `wallet.guard`, `policy.decide/export/verify`, `delegation.prove/verify`, `auth.bind/verify_bound`, `audit.verify`; chain-agnostic `crates/srct-policy` (intent → allow/deny/approval-needed JSON, TS/Python bindings, no consensus imports); short-lived exact-transaction grants via `service::admit_bound_payment`; node API `GET /v1/policies`, `GET /v1/policies/{agent_id}`, `GET /v1/credit/positions`, `GET /v1/credit/positions/{id}`; CLI `policy`, `agent-spend`, `credit`, `l2 --deposit-address` (every command checks the transaction against the state the chain will replay and refuses with the chain's own reason) |
| Escrowed service contracts | `srct-l2::ServiceContract` (generic over deliverable and attestation) with `ServiceContract::open` for non-compute services; `crates/srct-l2/tests/service_contract.rs` drives a sort deliverable through claim → submit → settle. **No wire payload for a non-compute contract** — that is a new L2 transaction type and a consensus change |
| Agent credit (service-layer book) | `srct-core::credit::CreditBook` + the `CreditGate` trait, consulted by `POST /v1/payment/submit`; reservation encumbers capacity, settlement is idempotent per reservation, bonds are pledged to the position they price; bond/open/repay/default reachable over HTTP. Backed minting exists: `POST /v1/credit/mint` accepts only attestations signed by a key configured with `--credit-issuer` (no key configured = every mint refused), and a minted attestation can never mint twice — the replay guard is persisted, so a restart is not a replay. `POST /v1/credit/deposit` stays the ungated book writer this crate has always documented ("Item 2 wiring only"). **This book is the service layer**: the *consensus* credit facility is the Layer-2 one above (SPEC §22), and this crate's arithmetic (the collateral rule, the interest rule) is the single implementation both use. The book persists across restarts through `SharedNode::encode_state`/`decode_state` and the node's atomic, digest-checked `state.bin` (fail-closed load) |
| Payment settlement links | `POST /v1/payment/{id}/settle` binds a recorded payment to the L1 transaction that pays its recipient — the node verifies the tx exists in its chain or mempool and that its outputs to the recipient cover the amount; `GET /v1/payment/{id}` reports the link as `pending`, `confirmed` (with height) or `missing`. One payment, one link (conflict on a second txid); links persist in `state.bin` |
| Delegation chains | `srct-core::delegation` narrowing rule, sub-agent derivation, `DelegationBook` lineage, and a signed root-first chain carried by `MachinePayment`/`PaymentRequest`; node records links, verifies owner policy signatures, propagates revocation to descendants. **The on-chain half is now consensus state**: a delegated grant is a `Policy` transaction whose parent grant is on chain, the narrowing rule is checked against the real parent, and revocation reaches every descendant (SPEC §21). The service-layer lineage book above remains the node's own record |
| Conditional escrow | `srct-core::escrow::ConditionalEscrow` with `release_arbiter`/`release_mutual` on the type, a release hash binding network and condition, and fail-closed oracle conditions. **Settlement wired (§20.2)**: `POST /v1/escrow/{id}/settle` binds a release to the L2 exit that pays the payee, and `Finalized` waits for `Chain::exit_released` — the coin moves through the ordinary L1 exit path (§19.4) |
| Checkpoint certificates | `Committee::sign_in_set` builds the bitmap against the committee a verifier derives; the node signs against `chain.committee_keys()` for the epoch; `srct_core::signing` covers the pure signing step |

Not implemented, and named as such: an OpenTelemetry/OTLP exporter (the
Prometheus text endpoint `/metrics` exists — §2), a node config file, a
release/tagging pipeline, reproducible-build tooling, log shipping, and the
security-disclosure channel's PGP key. (The `srct-worker run` daemon binary
also exists now, with a conservation gate before its first pass.)

## 1. Versioning & release management

- **Version:** `0.2` (`SPEC.md` header: foundation + P2P transport).
- **SemVer policy (documented, not enforced by tooling):** major = consensus
  break; minor = backward-compatible mechanism activation; patch = no
  consensus impact.
- **Release branch convention:** `release/vMAJOR.MINOR` — cut 2 weeks before
  launch, bug/security fixes only.
- **Release checklist** (each item runnable; the ones that are not yet
  automatable say so):

  | Step | Command | Current result |
  |---|---|---|
  | 1 | `cargo fmt --all --check` | clean |
  | 2 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
   | 3 | `cargo test --workspace` | 1307 passed, 0 failed, 1 ignored (`vwc_perf_probe`) |
  | 4 | `cargo build --workspace --release` | succeeds |
  | 5 | vector cross-check: `python verification/sim/verify_vectors.py --check` | see `docs/status.md` |
  | 6 | confirm the only `#[ignore]`d test is the manual `vwc_perf_probe` | confirmed |
  | 7 | update `CHANGELOG.md` | **no CHANGELOG exists yet** |
  | 8 | tag `vMAJOR.MINOR.PATCH`, publish to GitHub Releases | **not yet done** |

- **Supply-chain verification (release build):** every action in
  `.github/workflows/{ci,release}.yml` is pinned to a commit SHA with the tag
  it came from in a trailing comment, `.github/dependabot.yml` refreshes those
  pins weekly, and the cosign installer is pinned to both a SHA and an explicit
  `cosign-version` rather than `@main` / `latest`. Job tokens are least-
  privilege (`contents: read` by default; only `build` takes `id-token: write`
  for the keyless signing identity, and only `publish` takes `contents: write`).
  To audit a release, resolve each SHA back to its tag and confirm the pinned
  `dtolnay/rust-toolchain@stable` commit is still the branch tip it claims to be
  — `stable` and `nightly` are moving refs, and Dependabot is configured to
  *ignore* that action because its updater resolves both moving pins to the same
  tip and rewrites one with the other's SHA. They are therefore a manual step,
  not a bot's, and `.github/dependabot.yml` groups every other dependency
  update into at most one PR per ecosystem (`open-pull-requests-limit: 0`) so the
  branch list stays at `main`. A semver-major bump of `sha2`, `k256`, `argon2`
  or `chacha20poly1305` is likewise ignored by Dependabot: swapping the domain
  separator, the curve, the wallet KDF or the wallet cipher on a major is a
  protocol decision. Their patch and minor security releases still arrive.

## 2. Monitoring & observability

**A Prometheus text endpoint exists: `GET /metrics`.** It serves
`text/plain; version=0.0.4` gauges derived from the same state as `/v1/status`,
plus the two relay-queue depths. Gauges only, one static `network` label, no
counters that need per-request bookkeeping in the consensus loop, and no key
material or per-user data — see the handler in `crates/srct-node/src/api.rs`.
It carries the same loopback-by-default exposure as every other route: a
loopback bind is unauthenticated, and a non-loopback bind is refused unless
`SRCT_API_TOKEN` (preferred over `--api-token`, which is visible in `ps`)
supplies a bearer token, which the exposed stack then enforces on every
request alongside a per-request deadline, a global in-flight cap and a
bounded per-IP rate limit. Host-header validation runs on every bind,
loopback included.

The `/health` path in an earlier revision is wrong twice over: the route is
`/v1/health` and it returns only `{"status":"ok"}`. The rich JSON observables
remain `/v1/status` (and `/v1/finality`, `/v1/fees`), and the process logs are
still the only log surface — **there is no structured log shipper.**

`GET /metrics` exports (all gauges, labelled `network`):
`Solar Cyber Unit_height`, `Solar Cyber Unit_finalized_height`, `Solar Cyber Unit_finality_depth`,
`Solar Cyber Unit_finality_activation_height`, `Solar Cyber Unit_peers`,
`Solar Cyber Unit_base_fee_sat_per_gas`, `Solar Cyber Unit_total_supply_sat`,
`Solar Cyber Unit_rate_anchor_allowance_sat`, `Solar Cyber Unit_issued_sat`,
`Solar Cyber Unit_net_supply_sat`, `Solar Cyber Unit_pscb_reserve_sat`,
`Solar Cyber Unit_mempool_transactions`, `Solar Cyber Unit_l1_relay_queue`,
`Solar Cyber Unit_l2_include_queue`, `Solar Cyber Unit_l2_height`, `Solar Cyber Unit_l2_applied_total`,
`Solar Cyber Unit_l2_skipped_total`, `Solar Cyber Unit_l2_pending_deposits`,
`Solar Cyber Unit_joint_supply_sat`, `Solar Cyber Unit_conservation_ok`. The joint-supply figure
is also served with its full terms and all three check verdicts at
`GET /v1/conservation` — the same `crate::conservation` arithmetic
`srct-node verify` prints, so the endpoint, the exporter and `verify` cannot
disagree. `srct-worker run` gates on that endpoint before its first pass and
refuses a node reporting a breach.

The JSON surfaces remain richer: `GET /v1/status` returns `network`,
`network_id`, `height`, `tip_hash`, `peers`, `base_fee_sat`,
`total_supply_sat`, `pscb_reserve_sat`, `finalized_height`,
`finality_activation_height`, `finality_depth`, `mempool_len`, and an `l2`
block.

**Suggested alerts** (rules not yet written; the signals now exist):

| Signal | Alert if |
|---|---|
| `height` | no advance for 2 × target block interval |
| `peers` | < 3, or > 90 % of `--peers` |
| `mempool_len` | near the byte cap |
| `finalized_height` | stops advancing after activation while `height` climbs |
| `l2.skipped` | spike |
| `pscb_reserve_sat` | flat where it should move, or a jump |
| `Solar Cyber Unit_conservation_ok` | 0 — value was created somewhere (joint supply over the cap, or an L2 check broke) |

**Logging:** line-based stdout via the node; there is no structured log
shipper. Recommended operational additions (not present): log-to-file,
rotation, and a level switch.

## 3. Backup & recovery

**Data directory** contains only:

```
<data-dir>/
  blocks.log      # append-only, checksummed, one record per block/UTXO snapshot
  meta.json       # atomic metadata: network, genesis, tip, height
  chain.json      # legacy JSON chain, migrated into blocks.log on first open
  wallets.json    # wallet key material (if any) — protect this
```

There is **no** `config.toml` and **no** `policy/` directory in the data dir
(agent policies are library values, not node files).

**Recovery procedure**

1. **Full node:** back up the data directory. Restore by copying it back and
   running `init` then `serve`; `BlockStore::open` rebuilds the hash index by
   scanning and resumes from the `meta.json` tip.
2. **Wallet:** deterministic wallets; back up `wallets.json` (or the mnemonic
   material it derives from). Losing it loses the keys.
3. **Resync:** `srct-node init --network mainnet --data-dir <dir>` then
   `srct-node serve --network mainnet --data-dir <dir> --connect <peer>:9333`.
   There is **no `--sync` flag**; sync is automatic once a peer is connected.
   State is replayed from genesis on load, so resync time is O(chain); there is
   no UTXO snapshot fast-path written today.

**Disaster scenarios**

| Scenario | RTO | RPO |
|---|---|---|
| Clean crash | restart | 0 blocks |
| Torn write (power loss) | reopen; torn tail dropped and reported | 0 committed blocks |
| Damage mid-chain | refuses to open (no silent truncation) → restore backup | last backup |
| Whole fleet down | restore from any node's backup | last backup |

## 4. Security disclosure

- **Policy:** [`SECURITY.md`](SECURITY.md) in `docs/` is the
  normative disclosure policy — severity model, windows, and what counts as a
  vulnerability.
- **Intake:** GitHub Security Advisory (private) on this repository, or
  `security@solarcyberunit.org`.
- **Bug bounty:** not announced.
- **Responsible disclosure window:** 90 days (documented).
- **Severity:** chain-halting (invalid block accepted) = critical, immediate
  patch + coordinated disclosure; key-compromise = high, 7-day disclosure.
- **Contact:** security@solarcyberunit.org. **PGP key is not yet published** — the
  channel is therefore not yet operational. The policy says so rather than
  implying otherwise.

## 5. Genesis & bootstrapping

- **Mainnet genesis** is deterministic and frozen (SPEC §11). It mints
  **nothing** and has no spendable output (0 % premine, enforced in code).
- **Supply** is bounded per height by the issuance integral
  (`cumulative_issuance_sat(height)`) and per halving period by the rate anchor
  (≤ 1 % of issued supply — Decision 18); there is no stock cap. It is not
  "minted over `MAX_HALVINGS × 10` epochs" (no such constant exists). The ladder
  issues **39,157,124 SRCT** (the geometric `149 × 262 800` over-states it by 76
  SRCT, because genesis occupies a rung-0 height without minting); after the
  ladder the approved tail keeps issuing 0.1 SRCT/block forever (see
  `docs/monetary-policy.md`).
- **L2 genesis escrow** (Decision 7, amended by M-E) is bounded by its own
  validated ceiling, not new issuance:
  `NetworkParams::validate` refuses any escrow above its own
  `escrow_ceiling_sat`. `mini` allocates 10 SRCT (3 grant accounts of 1 SRCT
  each); `mainnet` allocates 100,000 SRCT and grants nothing.
- **Mainnet bootstrap committee** is 21 deterministic public keys (quorum 15),
  active at height 100 until the first bond (Decision 27). These keys are public
  material: any node can sign for the committee before a bond exists. That is a
  cold-start property, not decentralisation.
- **Bootstrap key provisioning:** before `serve`, the node that will produce the
  first mainnet checkpoint runs `srct-node validator --bootstrap --network mainnet
  --data-dir <dir>` with `SRCT_VALIDATOR_PASSPHRASE` set. This writes all 21
  declared keys as encrypted files. A node needs at least 15 keys locally
  because checkpoint signatures are not gossiped as partial shares; the command
  deliberately provisions the complete committee. Normal `validator --add`
  keys remain available for bonded validator committees. After the first bond,
  remove the `bootstrap-*.json` files and add the bonded key: stale keys that
  are no longer committee members make signing fail closed.
- **L2 settlement authority** is the separate `l2_settlement_validators`
  declaration, which on mainnet names the same 21 bootstrap keys that secure
  L1 pre-bond (mini/testnet reuse their four L1 keys). The declaration alone
  is not a permanent grant: node verification resolves the live L1 committee
  per block height (`Chain::settlement_committee_at`), so the first bond
  rotates L2 authority to the bonded TopN and bootstrap keys authorize
  nothing further (Decision 28).
- **Testnet** uses the dedicated `testnet` profile with four deterministic
  genesis validators (Decision 13).
- **Bootnodes:** none are published on the public internet yet. A bootnode is a
  `serve --listen` node that joiners dial with `--bootnodes` (or recover via
  `peers.json`); no DNS seeding or ADDR gossip is implemented (SPEC §13.6 by
  design). `scripts/start-network` stands up a local multi-node network with
  node 1 as the seed bootnode.

## 6. Upgrade mechanism

Mechanism activation is by profile parameter, not by an on-chain governance
epoch:

| Mechanism | Consensus-active? | Authority |
|---|---|---|
| M1 (50/50 PSCB fee split; PSCB leg carries B-Saver + Treats) | **Yes**, everywhere | SPEC §8 |
| M2 (Anti-Collusion Slash Vault) | **No** — no rule creates a slash record | `slash.rs` |
| M3 (Canonical Compute IR) | **No** — envelopes only | `compute_ir.rs` |
| M4 (HBM scratchpad PoW) | **No** — registered as `puzzle_id = 2` but not the active mining puzzle | `hbm_pow.rs` |
| M5 (BLS aggregate finality) | **Conditional** — binding where `finality_activation_height > 0` (`testnet` = 20, `mainnet` = 100 with its 21-key public bootstrap committee); observation-only on `mini` | Decisions 11–12, 27, SPEC §14.7–§14.8 |

A node running pre-activation software rejects post-activation blocks per the
new rules (fail-closed). Operators must upgrade before an activation height is
reached.

## 7. Pre-launch checklist

| Item | Status |
|---|---|
| `cargo fmt --all --check` clean | ✅ |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean | ✅ |
| `cargo test --workspace` passes | ✅ 1360 passed, 0 failed, 1 ignored |
| Release build compiles | ✅ |
| Vector cross-check (Python vs Rust) | ✅ (`docs/status.md`) |
| Fuzz: 17 targets executed, real campaigns | ✅ see `docs/fuzz.md` |
| Deterministic genesis across profiles | ✅ |
| BLS finality adversarial tests | ✅ (18 checkpoint tests) |
| L2 end-to-end (deposits, tasks, VWC, reputation) | ✅ (2-process E2E + chaos suite) |
| Multi-node network test (3 real-TCP nodes: transit sync, live relay, restart catch-up) | ✅ (`srct-net/tests/three_node_network.rs`) |
| Local multi-node launch scripts (start / stop / reset) | ✅ (`scripts/start-network`, `stop-network`, `reset-network`) |
| L2 → L1 exits | ✅ implemented and active on mainnet (`exit_activation_height = 1`) |
| Stake ledger / bond / unbond / slash | ✅ implemented and tested — any positive bond accepted, no minimum stake (Decision 20 update) |
| Committee rotation + slash verification | ✅ seed-height snapshots with reorg rollback, per-epoch slash checks, fail-closed expiry (`committee_rotation`, P0-2 tests) |
| External mining | ✅ `srct-miner` binary + `GET /v1/mine/template` / `POST /v1/mine/submit` + stratum-lite pools with PPLNS payouts; ~114k H/s reference (4-thread CPU, release) |
| Validator committee derivation | ✅ stake-weighted TopN with genesis fallback |
| Checkpoint signing | ✅ built and tested (`signing.rs`, serve loop) |
| M2 / M4 | M2 closed (canonical reference + fraud slashing); M4 registered (`puzzle_id = 2`) but not active on mainnet by design |
| Live conservation surface (`/v1/conservation`, `/metrics` gauges, worker `run` gate) | ✅ |
| Log shipping, release pipeline, PGP disclosure key | ⚠ partial — release workflow exists; log shipping and PGP key remain |

## Resolution of the protocol blockers

The following items that were previously listed as blockers have been
resolved by code changes made to the repository:

1. **Mandatory 5,000 SRCT validator stake — REMOVED.** `check_bond_tx` in
   `bond.rs` now accepts any positive bond amount. The `MIN_VALIDATOR_STAKE_SAT`
   constant has been removed entirely. The committee derivation remains
   stake-weighted (TopN), so smaller bonds simply rank lower.

2. **L2 fee path — flat minimum floor finalized.** `L2_FLAT_FEE_MINIMUM_SAT`
   (1,000 sat) added as a floor in `fee_sat()`. Every L2 fee type meets or
   exceeds this value. The flat D3 schedule routes through `split_flat_fee`,
   preserving the M1 50/50 burn/PSCB invariant and leaving the L1 fee floor
   untouched.

3. **Credit/escrow boundary — node-local made explicit.** Added a doc comment
   to `SharedNode` in `crates/srct-node/src/api.rs` that classifies state into
   consensus (`chain`, `pool`, `l2`) and node-local (credit, escrow,
   delegations, policies — never replayed, never committed). The node-local
   books now also persist to the node's `state.bin`; see the Agent credit row
   above and `SharedNode::encode_state`.

4. **Mainnet L2 settlement authority — rotation replaces the empty set.**
   Mainnet's `l2_settlement_validators` was empty, so every `Settle` on
   mainnet failed with `BadQuorum`. The declared set now names the 21
   bootstrap keys, and node verification resolves the live L1 committee per
   block height (`Chain::settlement_committee_at`): bootstrap pre-bond,
   bonded TopN after the first bond, with replay determinism across the
   rotation and a by-name refusal for stale bootstrap quorums post-bond
   (Decision 28; `m5_node_finality` mainnet tests).

No independent security review has been completed. A third-party security review
is recommended before any mainnet deployment with real value.
