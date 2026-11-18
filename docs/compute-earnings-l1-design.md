# Phase 6 — Compute Earnings to L1 (Design First, No Code Until Approval)

**Status:** DESIGN ONLY (measurements done — see §2). No implementation, no throttle parameter change. Awaiting owner choice among options (a)/(b)/(c) before any code.

**Constraint (non-negotiable):** Exit throttle (`max_exit_window_sat = 1000 SRCT`, `max_exit_per_owner_window_sat = 100 SRCT` per 144 blocks on mainnet, plus +144 blocks for exits >= 100 SRCT) stays exactly as is. For compute payouts the exit owner is the REQUESTER. Do NOT change the throttle.

## 1. Flow map (verified from source — see final report for line refs)

**Node-level compute path (`srct-compute` + `EscrowBook` in `state.bin`):**
- `EscrowBook` accounts hold requester-funded escrow (node-local, not L1 UTXO, not L2 balance).
- Settlement records `PayoutInstruction { from: requester, to: provider, amount_sat }`. Money moves only through a requester-signed L2 exit (`exit-template` → `claim`), or a pre-signed exit attached via `exit_tx_hex`.
- Consensus pays the provider's L1 address when the exit releases. Compute earnings reach L1 ONLY via the L2 exit path.

**L2 task path (`srct-l2` PostTask/ClaimTask/Settle):**
- `PostTask` locks submitter funds; `ClaimTask` locks worker deposit; `Settle` pays worker's L2 balance (`pay(worker, worker_paid)`), refunds submitter, slashes/burns deposits.
- Worker earnings become L2 balances immediately. They become L1-owned only after a separate worker-signed ExitQueue + L1 release, subject to the same throttle.

**Conclusion:** Compute earnings are L2-owned at settlement, L1-owned only after exit release. The requester (node path) or worker (task path) must queue the exit. The throttle applies per owner per window.

## 2. Measured results (`srct-l2/tests/throttle_capacity.rs`, green)

Test uses mini profile with exit throttle set to mainnet values
(`max_exit_window_sat` = 1000 SRCT, `max_exit_per_owner_window_sat` = 100 SRCT
per 144 blocks), 10-SRCT exits, MockBls verifier:

- Single owner: **10 x 10-SRCT exits per 144-block window** (100 SRCT owner cap
  / 10 SRCT per exit = exactly 10; the 11th is refused with
  `ExitOwnerWindowFull`). Output: `single owner accepted 10 x 10-SRCT exits
  per 144-block window`.
- Network-wide: **100 x 10-SRCT exits per 144-block window** (1000 SRCT global
  cap / 10 SRCT per exit = exactly 100 across 10 owners x 10 exits each).
  Output: `network accepted 100 x 10-SRCT exits per 144-block window`.

Both are exact divisions, not estimates — the test asserts `accepted == 10`
and `accepted == 100` respectively. Larger payouts scale linearly down (e.g.
100-SRCT exits: 1 per owner, 10 network-wide, plus the +144-block maturity
rule for exits >= 100 SRCT).

## 3. Options (design only, no implementation)

### Option A: Pre-signed / designated exit by default
Make every settlement auto-queue its exit (no manual claim step). Unchanged throttle. When throttle is full (`ExitWindowFull` / `ExitOwnerWindowFull`): receipt waits, exit queued in next window, retry story is automatic re-queue by crank. Provider waits; receipt is not stuck (payout instruction persists); retry is idempotent via receipt hash.

Comparison: cheapest consensus touch (reuses the existing exit path, no new
money-movement rule). Throughput is the measured throttle: 10 x 10-SRCT
payouts per owner per window, 100 network-wide. Sustained compute revenue
above that queues into later windows — fine for periodic payouts, backpressures
bursty demand. No honeypot weakening (throttle untouched). Recommended default
unless payouts must bypass L2 ownership.

### Option B: Requester pays provider directly with ordinary L1 payment at settlement
Bypass L2 hop for compute revenue. Node-level escrow must hold or prove L1 funds. Conservation: L1 payment moves value directly (no L2 debit/credit); joint-supply check must account for the L1→L1 transfer without double-counting the escrowed amount. Requires escrow adaptation to prove L1 funds (hold UTXO or signed payment intent). Heavier consensus touch than (a).

Comparison: removes the throttle from the compute path entirely (L1 payment
has no exit-window cap), so throughput is mempool/block-size bound instead of
10/100-per-window. Cost is a new consensus money-movement rule plus escrow
proof-of-funds, joint-supply accounting changes, and a larger audit surface.
Only worth it if measured (a) throughput (10/owner, 100/network per 144
blocks at 10 SRCT) is proven insufficient for expected compute volume.

### Option C: Hybrid (if L1-owned without weakening throttle)
Any hybrid must keep compute earnings L1-owned without weakening the honeypot protection. Example: designated exits (a) for small payouts + direct L1 payment (b) for large payouts above a threshold, with the threshold itself consensus-gated. More complex; only if (a) and (b) alone are insufficient.

Comparison: keeps small-payout simplicity of (a) (measured 10/100 capacity
covers the bulk) while lifting large payouts out of the window. Adds
threshold consensus logic plus both (a) and (b) machinery — most complex,
two audit surfaces. Choose only if workload is bimodal (many small + few
large that cannot wait a window).

## 4. Throttle-full behavior (all options)

- `ExitWindowFull`: global cap hit. Provider/requester waits. Receipt persists. Crank retries next window. No funds lost (queue refusal keeps funds).
- `ExitOwnerWindowFull`: owner cap hit. Same, scoped to owner. Other owners unaffected.
- Receipt stuck? No — `PayoutInstruction` + `compute_payout_exit` binding persist in `state.bin`; re-queue is idempotent by receipt hash.
- Retry story: manual `claim` re-submission or automatic crank (`process_due_compute_payouts`). No dust, no loss.

## 5. Recommendation

Option (a) is the recommended default: smallest change, throttle intact,
measured capacity (10 x 10-SRCT per owner / 100 network-wide per 144-block
window) handles steady payout flow with automatic re-queue on full windows.
Escalate to (b) only on demonstrated throughput need; (c) only for bimodal
load. No implementation authorised here — owner decision required. Do NOT
alter exit throttle parameters.

*End of Phase 6 design — measurements done, awaiting owner decision.*
