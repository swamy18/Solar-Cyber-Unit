# Monetary Policy

**Reconciled against code and SPEC on 2026-10-09**, including the approved tail
(Decisions M-A…M-G in `docs/decisions.md`) and the approved supply anchor
(Decision 18: the stock cap replaced by a rate rule). This file previously
described a schedule that exists nowhere in the repository (a 10,000,000 SRCT
cap, a 1 SRCT initial reward, 210,000-block halvings, `TARGET_SUPPLY_SAT` /
`MAX_HALVINGS` constants). None of those names or numbers exist in the code.
The text below is what `crates/srct-core/src/supply.rs` and
`crates/srct-core/src/params.rs` actually implement, pinned by
`SPEC.md §7`/`§10`, `sim/supply_schedule_sim.py`, and
`tests/vectors/supply_vectors.json`. If any of the three ever disagree, the
tests (`supply::tests::*`, `params::tests::*`) fail first.

## Design

SRCT is a **rate-anchored, time-based issuance** cryptocurrency with **no premine**
and **no stock cap**: genesis mints nothing, and Decision 18 (2026-10-09)
removed the numerical supply ceiling entirely. Minting is bounded per height by
the issuance integral `cumulative_issuance_sat(height)` through the single gate
`supply::check_mint_at_height`, and per halving period by the rate anchor —
gross issuance in any post-ladder window may not exceed 1 % of the supply
issued at that window's start. After the ladder the approved tail (§Issuance
schedule) keeps a small, bounded issuance flowing forever, so long-run issuance
is unbounded by design and every bound consensus enforces is a rate, never a
total.

**Net supply** — gross issuance minus everything usage ever removed (the burned
half plus the PSCB leg of every block's base fee, i.e. retained PSCB + B-Saver + Treats backing) — is what holders
experience, and `status`, `GET /v1/conservation` and the `/metrics` gauges
report it (Decision 18 §4.5).

There is **no `TARGET_SUPPLY_SAT`** and **no `MAX_HALVINGS` constant** in the
code. Halvings are computed as `height / halving_period` (clamped), and the
ladder reaches its last non-zero rung after 7 halvings, where the tail takes
over; `period_reward_sat` returns 0 for any epoch ≥ 64 as a hard stop.

## Parameters (actual, from `params.rs`)

| Parameter | Mainnet | Testnet / Mini |
|---|---|---|
| Stock supply cap | **none** (Decision 18 — the rate anchor below replaced it) | none |
| Rate anchor | ≤ 1 % of issued supply per halving period (≤ 0.2 %/yr) | same rule |
| `start_reward_sat` | 76 SRCT (7,600,000,000 sat) per block | 76 SRCT |
| `halving_period` | 262,800 blocks (5 years at 10 min) | 2,000 blocks |
| Reward ladder | 76, 38, 19, 9, 4, 2, 1 SRCT (then the tail) | same ladder |
| Tail | 0.50 → 0.25 → 0.125 SRCT, then a permanent **0.1 SRCT** floor | constant **1 sat/block** |
| `GENESIS_MINT` | 0 (nothing pre-mined) | 0 |
| `SAT_PER_SRCT` | 100,000,000 | 100,000,000 |

The ladder halves in **whole SRCT**
(`period_reward_sat = (start_reward_srct >> epoch) * SAT_PER_SRCT`), not by
shifting satoshis — shifting would pay 9.5 SRCT at epoch 3 and break the
issuance arithmetic. Epochs ≥ 7 pay the tail, halved in **satoshis** and clamped by the
floor (`DecayToFloor`), never zero on any shipped profile.

## Issuance schedule (mainnet)

```
Epoch 0: 262,799 blocks × 76 SRCT = 19,972,724 SRCT   (genesis mints nothing)
Epoch 1: 262,800 blocks × 38 SRCT =  9,986,400 SRCT
Epoch 2: 262,800 blocks × 19 SRCT =  4,993,200 SRCT
Epoch 3: 262,800 blocks ×  9 SRCT =  2,365,200 SRCT
Epoch 4: 262,800 blocks ×  4 SRCT =  1,051,200 SRCT
Epoch 5: 262,800 blocks ×  2 SRCT =    525,600 SRCT
Epoch 6: 262,800 blocks ×  1 SRCT =    262,800 SRCT
Epoch 7 (1,839,600): tail begins at 0.50 SRCT, decays to the 0.1 SRCT floor
────────────────────────────────────────────────
Ladder-era issuance:  149 × 262,800 − 76 = 39,157,124 SRCT
Rate anchor (the only ceiling):  ≤ 1 % of issued per halving period
Tail (steady state):        0.1 SRCT/block ≈ 5,260 SRCT/yr ≈ 0.013 %/yr
```

The tail is the approved policy (Decisions M-A…M-C): the ladder's last rung is
followed by 0.50 → 0.25 → 0.125 SRCT and then a **permanent 0.1 SRCT floor**, so
issuance never stops. Long-run issuance is therefore unbounded by design; the
bounds consensus enforces are the per-height issuance integral and the
per-period rate anchor (Decision 18) — never a stock total.

On `mini`/`testnet` the same ladder over 2,000-block epochs issues **297,924
SRCT** through the ladder era. Their tail is a constant **1 sat/block** (M-C):
the mainnet value on a 1-second profile would mint a four-digit percentage per
year against its own issued supply, which is why the tails are set
independently. The largest tail window issues ~0.34 % of supply on mainnet —
about a third of the 1 % anchor, so the anchor never binds the approved
schedule (`sim/supply_schedule_sim.py` prints
`largest_tail_window_pct_of_issued`).

If a block reward would cross either bound, the block is refused
(`supply::check_mint_at_height` → `SupplyRateExceeded`) and the surplus is
never created.

## Fee model (M1 — 50/50 PSCB split)

SPEC.md §8, implemented in `fees::split_fees` / `fees::split_flat_fee`:

| Component | Destination |
|---|---|
| **Burn** | 50% of the base-fee portion (ceil — the odd satoshi goes here), removed from the UTXO set forever |
| **PSCB leg** | 50% of the base-fee portion (floor): retained PSCB + 5% B-Saver floor (cap 10%) + 10% SRCT Treats backing (cap 20%) |
| **Miner tip** | The full tip (`total_fees − base_fee × gas_used`) goes to the block producer |

Both L1 (`split_fees`) and L2 (`split_flat_fee`, Decision D3) round the same
way — `flat_split_puts_the_odd_satoshi_where_split_fees_does` pins it — so an
L1 fee and an L2 fee of the same size burn identical amounts. The PSCB is a
protocol-owned accounting claim on already-removed supply, not new issuance;
together with the burned half it is the removal term net-supply reporting
subtracts from gross issuance.

L1 has a gas floor (`min_tx_fee = base_fee × GAS_TX_BASE`, `GAS_TX_BASE =
16,000`); L2 transactions pay the flat D3 schedule
(post 5,000 / claim 2,000 / submit 2,000 / dispute 10,000 / settle 20,000
sat) and never consult the L1 floor (`l2_fees_do_not_use_the_l1_gas_floor`).

## Escrow and the L2 deposit sink (Decisions 7 and 10)

- **Genesis escrow (Decision 7, amended by M-E):** `l2_genesis_escrow_sat` is
  bounded by the explicit, validated `escrow_ceiling_sat` — mainnet 100,000
  SRCT, mini/testnet 10 SRCT. `params::validate` rejects any profile whose
  escrow exceeds its ceiling (`escrow_respects_the_new_ceiling`).
- **User deposits (Decision 10):** an ordinary L1 payment to the
  network-bound `l2_deposit_sink` address (unspendable, holds no key) is
  read by L2 replay as a deposit, credited 1:1 after
  `finality_depth` (mini/testnet 20, mainnet 100 blocks). Sink outputs stay
  in the L1 UTXO set forever.
- **Exits (Decision 19, SPEC.md §19.6): implemented.** An `ExitQueue` L2
  transaction debits the owner and records the exit; a block `exit_claim`
  consumes **sink outputs** authorised by an inclusion proof against the
  `l2_state_root` committed at the queue height — not a signature, because the
  sink holds no key. The crank is permissionless, and the owner prepays the
  claimant's fee at queue time so an unfunded crank cannot exist. Per exit the
  L2 debit equals the L1 release 1:1 and the joint check of §19.4 needs **no new
  term** (the L1 payment and the L2 debit cancel while the sink term falls by the
  same amount) — `tests/conservation.rs` passes unchanged, which is the evidence.
  Activation is `NetworkParams::exit_activation_height`: all three profiles
  (`mini`/`testnet`/`mainnet`) = 1, i.e. exits work from genesis. P2–P5 remain
  the remaining mainnet work.

## Conservation laws (tested)

1. No inflation beyond the integral: `supply::tests::no_block_can_mint_beyond_cumulative_issuance`
   and `supply::tests::derived_supply_bound_holds_at_every_height`
2. The rate anchor refuses a dilutive schedule: `supply::tests::rate_anchor_refuses_a_schedule_that_over_issues_a_window`
3. Net supply is issuance minus removal: `chain::tests::the_burn_counter_and_net_report_track_removal`
4. Value conservation in transactions: `ledger::tests::a_transaction_can_never_create_more_value_than_it_spends`
5. L1 + L2 supply never exceeds the joint bound: `srct-node` `tests/l2_funding.rs::joint_l1_plus_l2_supply_stays_under_the_joint_bound`
   and `GET /v1/conservation` (issuance integral + escrow ceiling)
6. Escrow respects its own ceiling: `params::tests::escrow_respects_the_new_ceiling`

## Policy decisions

- **Decision 3 (§16):** mainnet reward ladder shape — matches
  `supply::tests::mainnet_reward_ladder`.
- **Decision D3 / Decision 1:** L2 fee schedule — see
  `l2::tests::fee_mapping_is_the_decided_d3_schedule`. The settle fee is
  fixed; no fee was changed by any Phase-6 milestone.
- **Decisions M-A…M-G (2026-10-09):** tail shape (E, decay to a floor),
  0.1 SRCT mainnet floor, 1 sat/block on mini/testnet, an explicit
  `escrow_ceiling_sat`, no fee-burn target (deflation accepted), activation at
  each profile's ladder exhaustion. Implemented in `supply.rs`/`params.rs`/`chain.rs`,
  vectors regenerated, and pinned by `supply::tests::*`, `params::tests::*`,
  `sim/supply_schedule_sim.py --selftest` and `sim/tail_emission_sim.py --selftest`.
- **Decision 18 (2026-10-09):** the stock cap deleted and replaced by the rate
  anchor (≤ 1 % of issued per halving period), with net-supply reporting
  (issuance minus burns) on `status`, `/v1/conservation` and `/metrics`.
  Implemented in `supply.rs`/`chain.rs`/`conservation.rs`/`api.rs`, vectors
  regenerated with the anchor fields, pinned by the tests in §Conservation
  laws above.
- The issuance paths, block rewards, halving schedule, tail values, rate anchor
  and both fee schedules are **frozen** at the recorded decisions; changing any
  of them is a consensus monetary decision requiring explicit sign-off (roadmap
  item 19).

## References

- `SPEC.md` §5 (PoW), §7 (supply schedule), §8 (fees), §10 (profiles)
- `crates/srct-core/src/supply.rs` (implementation + tests)
- `crates/srct-core/src/fees.rs` (M1 fee split)
- `sim/supply_schedule_sim.py` (independent Python reference cross-check)
- `tests/vectors/supply_vectors.json` (pinned numbers)
