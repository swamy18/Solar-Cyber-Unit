# Agent credits: pay-as-you-go money for machines

Prepaid API credits (OpenAI, Anthropic, Google) make every agent pre-fund a
balance, watch it expire, and keep it locked to one vendor. SRCT replaces all
three properties with protocol mechanics that already exist — plus one small
service-layer flow for first tasks. This page ties them together.

## Pay as you use, not prepaid

- **Stream channels** (`POST /v1/streams/open|settle`, `GET /v1/streams/{id}`):
  open once (rate per block, window, hard cap), mint an off-chain voucher per
  unit of work, settle only the final voucher on chain. N units of metered use
  cost one on-chain settlement instead of N prepaid top-ups.
- **x402 paid resources** (`GET /v1/paid/*`, `POST /v1/x402/verify|settle`):
  the client calls, gets `402 + PAYMENT-REQUIRED`, checks its own budget
  *before* any key is used (`X402Budget::check_guarded`: max amount,
  allow-lists, short expiry window), signs the exact payment, retries.
  The worker CLI wraps the whole round trip: `srct-worker pay --resource ...
  --max-amount ... --recipients ... --service-name ...` refuses an
  over-budget challenge without touching a key.

No company holds the funds in between: the stream payer's cap is enforced by
the `StreamBook`, the x402 budget is enforced client-side, and settlement is
an ordinary payment to the provider — never a custodial balance.

## No credit expiration

An SRCT balance never expires. There is no validity window on coins: a UTXO
holds value until it is spent, and an L2 balance until it is used. Time bounds
exist only where they limit *spending* — a grant's `not_before_height` /
`expires_at_height`, a stream's window, a quote's expiry — and a time-bound
that lapses never destroys the underlying coins. An agent holding SRCT keeps
it; only its authority to spend under a particular grant can run out, and the
owner re-issues that with one command (`srct-worker grant`).

## Credits circulate: inter-agent resale

A grant is a signed permission, not a vendor-locked balance, and it nests:
any agent holding a grant can issue a *narrower* sub-grant (`--parent`) to
another agent — smaller caps, fewer recipients, shorter window, never wider.
The chain enforces the narrowing; revoking the root kills the whole tree.
So credits bought once can flow machine-to-machine: agent A funds a task
budget, delegates a slice to agent B for a subtask, B pays C for data —
without any company's wallet in the middle and without new issuance. See
[`portable-policy.md`](portable-policy.md) for the proof format any rail can
verify, and [`reputation.md`](reputation.md) for how history prices that
trust.

## First tasks: usage-based credits (the trial faucet)

A new agent with no coins cannot post the claim deposit a task requires, and
an on-chain loan cannot help either — collateral must be the borrower's own
money. The trial faucet closes that gap without touching consensus:

```
agent:      srct-worker trial-request --node $NODE --agent <agent-id>
sponsor:    srct-node send --to <agent-address> --amount <drip>   # real SRCT
agent:      srct-worker trial-fund --node $NODE --agent <agent> --txid <txid>
agent:      # deposit to the L2 sink, then claim tasks normally
agent:      srct-worker trial-repay --node $NODE --agent <agent> --txid <txid>
```

- `POST /v1/trials/request` records one trial per agent, ever, against the
  operator-configured sponsor (`SRCT_TRIAL_SPONSOR`; unset means trials are
  closed) and a fixed drip (`SRCT_TRIAL_AMOUNT_SAT`, default 1 000 000 sat —
  enough to clear one minimum L2 deposit plus first-claim costs).
- `POST /v1/trials/fund` confirms a *confirmed* L1 payment to the agent (a
  mempool promise does not count; one tx funds at most one trial). A funding
  payment that orphans off the chain can be re-confirmed with its replacement.
- `POST /v1/trials/repay` confirms the payback to the sponsor the same way.
- Total unpaid trials are capped (`SRCT_TRIAL_MAX_OUTSTANDING_SAT`, default
  10 000 000 sat): the sponsor's exposure is bounded by construction.
- Every record persists in `state.bin` (envelope v9) and every step appends
  to the audit log (`trial_request` / `trial_fund` / `trial_repay`).

The trial is a free-trial entry point, but every trial is real SRCT the
sponsor spent — there is no points system wearing a currency's notation.

## Plug-and-play worker template

`templates/srct_agent.py` turns any Python function into an earning agent in
two lines (stdlib only — no crypto knowledge needed, the key never leaves
`srct-worker`):

```python
from srct_agent import SrctAgent
SrctAgent(node="http://127.0.0.1:8080", wallet="agent.json",
          policy_hex="...").serve(my_task_fn)
```

`my_task_fn(task_dict) -> bytes` is your framework call — LangChain, CrewAI,
OpenClaw (adapters documented at the bottom of the template). The template
polls open tasks, claims (`srct-worker claim`), runs your function, submits
the bytes (`srct-worker submit-result`), and can verify the certificate
afterwards (`srct-worker verify-cert`: quorum-backed or merely unchallenged).
`python templates/srct_agent.py --selftest` exercises the loop offline.
