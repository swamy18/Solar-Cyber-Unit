# Productive lending for agents

Credit for working capital — not merely moving already-owned funds. Lenders
publish standard terms, borrowers discover and accept them, history prices
risk, and revenue repays loans by itself where the borrower authorized it.

## Standard offers and discovery

```bash
curl -X POST $NODE/v1/loans/offers -d '{lender-signed terms...}'  # rate ≤10%/window, full collateral terms
curl "$NODE/v1/loans/offers/list?principal=1000"                  # live offers, cheapest first
curl -X POST $NODE/v1/loans/accept -d '{"offer_id":"...","borrower_hex":"...",
  "bond_sat":200,"amount_sat":1000,"deadline_height":9000}'       # terms come from the offer
```

Accepting opens a position on exactly the signed terms — amount and deadline
are the borrower's only choices. Bond and collateral must already be funded.
The accept carries the borrower's own signature over (offer, borrower,
amount, bond, deadline): the debt lands in the named borrower's book, so
only that borrower can authorize it.

## History, limits, dashboards

- `GET /v1/lending/borrower/{addr}` — verified repayments, on-time rate,
  defaults, total repaid/borrowed, reputation score, and a suggested ceiling.
- `GET /v1/lending/limit/{borrower}` — the ceiling plus its factors.
- `GET /v1/lending/dashboard` — exposure by lender, due-soon positions,
  defaulted positions with shortfalls, expected interest.
- `GET /v1/lending/collateral/{position_id}` — live collateral vs
  debt + accrued interest (coverage in bps).

The suggestion is advisory: any default zeroes it, no history means zero
(unproven is unpriced, not free), and the lender decides. Reputation is an
input to pricing, never a guarantee of repayment.

## Who bears losses

Collateral first, then the borrower's posted bond, then the lender absorbs
the shortfall. A vanished borrower or a revoked owner key changes nothing
about this order: the position still defaults at its deadline and settles by
these rules. Define this in the loan agreement, not in the score.

## Automatic repayment from revenue

```bash
curl -X POST $NODE/v1/lending/autorepay -d '{"borrower_hex":"...","position_id":"...",
  "pct_bps":5000,"cap_sat":10000,"expires_height":9000,"nonce":1,
  "sigs_hex":"...","keys_hex":"..."}'   # borrower-signed, revocable by replacement
curl $NODE/v1/lending/autorepay/<borrower>               # live instruction, if any
```

While live, each credit deposit routes the authorized share to the position
first (`credit/deposit` answers `autorepay: {position_id, repaid_sat, ...}`).
Only explicit borrower authorization, only while unexpired and under cap.
Replacing the instruction needs a strictly greater nonce (a stale signature
never unedits the live one), and the routed total carries over — editing the
cap or rate cannot silently reset what was already repaid through it.

## The consensus primitive underneath

The marketplace above prices and discovers loans; this section is the
collateralized on-chain primitive it stands on — real coins in the UTXO set,
consensus state, not accounting entries.

### Transaction types

| Type | Wire | Actor | Fee | Purpose |
|---|---|---|---|---|
| `CreditOpen` | `0x19` | Lender | 2 000 sat | Open a position |
| `CreditCollateral` | `0x1A` | Borrower | 2 000 sat | Add collateral |
| `CreditRepay` | `0x1B` | Borrower | 2 000 sat | Repay (interest first) |
| `CreditDefault` | `0x1C` | Anyone | 2 000 sat | Settle an overdue position |

Every credit transaction pays a flat 2 000 sat fee
(`FEE_TX_CREDIT_OPEN_SAT` / `_COLLATERAL_SAT` / `_REPAY_SAT` / `_DEFAULT_SAT` in
`params.rs`), the same tier as exit-queue transactions. The fee splits with `split_flat_fee`:
half is burned, half enters the PSCB reserve, and the miner tip is zero — an L2
fee is not paid to the block producer. Burnt gets the odd satoshi on ties
(`ceil(fee / 2)` → burn, `floor(fee / 2)` → PSCB).

### Terms and limits

- **Full collateralization.** The default `CreditTerms` require the collateral to
  equal the borrowed principal: `base_collateral_bps = 10 000` (100%),
  `max_discount_bps = 2_000`, `min_collateral_bps = 8_000`. With no bond posted
  the discount is zero, so `required = max(100% − 0%, 80%) = 100%`. The collateral
  must be the borrower's own money, checked **before** the principal arrives, so
  a position can never outrun its backing.
- **No zero-collateral term sets.** A `CreditTerms` with `min_collateral_bps ==
  0` is refused by name where the arithmetic lives (`required_collateral`),
  not left to callers to remember — there is no path to a zero-collateral
  line.
- **Interest rate cap.** A position may charge at most
  `MAX_CREDIT_RATE_BPS_PER_WINDOW = 1_000` (10%) per window. A rate above that is
  refused rather than clamped.
- **Position ID.** Derived as a domain-separated hash over the lender, borrower,
  principal, collateral, rate, window, deadline and nonce —
  `SHA256(DOM_L2_CREDIT_POSITION ‖ lender ‖ borrower ‖ amount ‖ collateral ‖
  rate ‖ window ‖ deadline ‖ nonce)` — so a lender cannot be shown terms they did
  not sign, and two identical loans become two distinct positions via the nonce.

### How a loan opens

1. The **lender** builds and signs a `CreditOpenPayload` with the borrower's
   address, principal amount, collateral amount, interest rate, window length,
   deadline height and per-lender nonce. The payload is sealed by a hybrid
   ECDSA + Schnorr `Auth` bundle (`CreditOpenPayload::build`).
2. The transaction is submitted (via `srct-node credit` on the CLI, or by
   serializing the `L2Transaction` to hex and POSTing it to
   `/v1/l2/broadcast`). Consensus checks: the lender has `principal + fee`, the
   borrower has `collateral`, the derived position ID is new, and the terms pass
   the rules above.
3. Funds move atomically inside `apply_credit_open` (`state.rs`):
    - Lender's balance decreases by `principal + fee`.
    - Borrower's balance increases by `principal`.
    - Borrower's `collateral` is locked into `credit_locked` (part of the
      conservation sum — spendable by no one until the position settles).
    - The fee splits into burn and PSCB.
4. A `CreditPosition` is created in on-chain L2 state:

    | Field | Set to |
    |---|---|
    | `lender` | the signing lender's address |
    | `borrower` | as specified in the payload |
    | `principal_sat` | the loan amount |
    | `outstanding_sat` | equals `principal_sat` |
    | `interest_paid_sat` | 0 |
    | `collateral_sat` | the posted collateral |
    | `rate_bps_per_window` | as specified (≤ 1 000) |
    | `window_blocks` | as specified |
    | `opened_height` | the block that applies it |
    | `deadline_height` | as specified (must be future) |
    | `interest_settled_height` | same as `opened_height` |
    | `state` | `Open` |

### Interest

Interest is **simple**, charged **once per whole window** on the **outstanding
principal**, computed by `ChargeSchedule::accrued_interest`
(`credit.rs`):

```
windows = (height − interest_settled_height) / window_blocks
interest = principal × rate_bps_per_window × windows / 10 000
```

- Fractional windows do not accrue — the total depends on whole elapsed windows,
  not on rounding order, so two nodes compute identical figures from identical
  heights.
- The triple product is checked in `u128`; a value that overflows `u128` is a
  refusal (`CreditInterestOverflow`), never a wrap or a silent clamp.
- `interest_settled_height` advances on each repayment, so two repayments in the
  same window charge for that window only once.
- **The lender receives all accrued interest.** The protocol never retains
  interest for itself; it flows to the lender together with principal
  repayments.

### How repayment works

The borrower repays against the debt, **interest first then principal**
(`apply_credit_repay`, `state.rs`):

1. Debt = `outstanding_sat + accrued_interest(outstanding_sat,
   interest_settled_height, height)`.
2. The repayment splits:
   `interest_paid = min(amount, interest_due)`,
   `principal_paid = amount − interest_paid`.
3. Funds move:
    - Borrower's balance decreases by `repayment + fee`.
    - **Lender's balance increases by `repayment`** — the full amount, interest and
      principal alike.
    - Fee splits into burn and PSCB.
4. The position updates: `outstanding_sat` decreases by `principal_paid`,
   `interest_paid_sat` increases by `interest_paid`, `interest_settled_height`
   advances to the current height.
5. **Overpayment is refused**, not clipped: if `repayment > debt`, the
   transaction returns `CreditRepaymentExceedsDebt` and changes nothing. Send
   exactly the right amount — the borrower may repay in multiple instalments
   across multiple transactions.
6. When `outstanding_sat` reaches zero:
    - `state` becomes `Repaid`.
    - The locked collateral is released: `credit_locked` decreases by the full
      collateral amount, and the **collateral returns to the borrower's balance**.
    - The position is closed and cannot be repaid or defaulted again
      (`CreditPositionClosed`).

Only the borrower named in the position may repay; a mismatched actor gets a
`CreditBinding` error.

### Adding collateral

`CreditCollateral` (`0x1A`) lets a borrower lock more collateral into an open
position, signed by the borrower. Consensus checks the position exists, is `Open`,
and that the borrower matches. The collateral leaves the borrower's balance and
enters `credit_locked`, increasing `position.collateral_sat`. This is useful when
rates or prices move unfavorably after a loan opens. A borrower may add collateral
any time before the position settles.

### How default works

Default is **permissionless** — any agent may trigger it — but only at or after the
deadline. `apply_credit_default` (`state.rs`) enforces `height >=
deadline_height`; defaulting sooner is refused with `CreditNotDue`. The steps:

1. The trigger pays the 2 000 sat fee (burn/PSCB split).
2. Debt is computed as above: `outstanding_sat + accrued_interest`.
3. The collateral is released from `credit_locked`.
4. Settlement:
    - `take = min(collateral, debt)` — the collateral covers as much of the debt
      as it can.
    - **Lender receives `take`** — principal and interest that the collateral
      covers.
    - **Borrower receives `excess = collateral − take`** — any surplus beyond the
      debt.
    - `shortfall = debt − take` — if collateral is insufficient, the **lender
      absorbs the shortfall**. The protocol never mints money to cover a loss.
5. `state` becomes `Defaulted`. A defaulted position cannot be defaulted or
   repaid again.

The settlement is deterministic: every node replays the same `accrued_interest`
and `min(collateral, debt)` arithmetic, so the split between lender and borrower
is identical on every node.

### Tracking positions

Each position is a committed entry in on-chain L2 state, included in the state
root with leaf tag `CREDIT_LEAF_TAG = 0x06` (`state_root.rs`). The fields exposed
via the API:

| Field | Meaning |
|---|---|
| `position_id` | Derived ID |
| `lender` | Lender's address (always the original counterparty) |
| `borrower` | Borrower's address |
| `principal_sat` | Original loan amount |
| `outstanding_sat` | Principal not yet repaid |
| `interest_paid_sat` | Total interest paid to the lender so far |
| `collateral_sat` | Collateral still locked |
| `rate_bps_per_window` | Interest rate per window |
| `window_blocks` | Window length in blocks |
| `opened_height` | Block the position was created |
| `deadline_height` | Block the debt is due by |
| `state` | `Open`, `Repaid`, or `Defaulted` |

```
GET /v1/credit/positions              # list all positions (paginated)
GET /v1/credit/positions/{id}       # one position by ID
```

The on-chain `outstanding_sat` is the source of truth for how much the borrower
still owes. At any height the debt is `outstanding_sat + accrued_interest(...)`;
`GET /v1/conservation` reports the `credit_locked` total so the whole collateral
pool can be audited.

### Wallet fund flow

Lending is built on the UTXO layer. The four operations move real coins between
wallet balances and the `credit_locked` pool:

| Operation | From | To | Amount |
|---|---|---|---|
| Open | Lender's wallet | Borrower's wallet | `principal` |
| Open | Borrower's wallet | `credit_locked` | `collateral` |
| Open | Lender's wallet | burn + PSCB | `fee` (2 000 sat) |
| Add collateral | Borrower's wallet | `credit_locked` | added collateral |
| Add collateral | Borrower's wallet | burn + PSCB | `fee` (2 000 sat) |
| Repay | Borrower's wallet | Lender's wallet | `repayment` (interest + principal) |
| Repay | Borrower's wallet | burn + PSCB | `fee` (2 000 sat) |
| Repay (full) | `credit_locked` | Borrower's wallet | `collateral` (returned) |
| Default | `credit_locked` | Lender's wallet | `take = min(collateral, debt)` |
| Default | `credit_locked` | Borrower's wallet | `excess = collateral − take` |
| Default | Trigger's wallet | burn + PSCB | `fee` (2 000 sat) |

The lender is always the original counterparty named in the position —
repayments and defaults always pay that address, never a pool or a different
lender.

## Staking & yield tracker

Locking has two legs. **Validator bonds** lock stake for consensus
security: the committee is always the 21 highest-staked bonds, unbonding
takes 1008 blocks, equivocation slashes the full bond into the vault —
`templates/srct_stake.py` reports these consensus facts (`bond_facts()`)
for operators planning a bond. **Productive lending** is the live yield
leg: locked principal earns chain-capped simple interest (10% per window)
from collateralized borrowers. The same template drives it end to end —
`live_offers` / `best_offer_for` (cheapest rate covering the principal),
`estimate_yield` (projection under the chain cap), `position_summary`
(one call: offer + projection), `dashboard` (live exposure and expected
interest), `autorepay_status` (the borrower's standing instruction).
`python templates/srct_stake.py --selftest` exercises it offline.
Redirecting protocol revenue (fees, slash vesting) to stakers is not
included: that is a monetary-policy decision needing a consensus change,
not a template.

## Agent Shield (insolvency tripwire)

A sub-agent at 0 SRCT mid-workflow crashes everything downstream.
`templates/srct_shield.py` heals the half that needs no consensus:
parents register credit delegation lines anchored to their live on-chain
`LoanOffer` (`register_line` refuses caps the offer cannot cover), and
`check` trips under the floor — returning the exact `POST
/v1/loans/accept` payload (terms from the parent's signed offer,
signatures left for the sub-agent's own key) plus a standing-repay hint,
and appending the trip to the board trail. The PSCB-backed emergency
micro-loan half is reported as unavailable, not faked: drawing rights on
the reserve need a consensus change. `python templates/srct_shield.py
--selftest` exercises it offline.
