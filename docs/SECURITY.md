# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security defect.** A public issue names the
defect, the code that carries it and the shape of the attack, and that is
enough to weaponise before a patch exists.

Use one of these channels, in this order:

1. **GitHub Security Advisory** — the "Report a vulnerability" button on this
   repository. This is the intended intake: it is private between you and the
   maintainers until a fix ships.
2. **Email** — `security@solarcyberunit.org`.

Include: the affected crate and file, the version or commit, a description of
the impact, and a reproduction (a failing test is ideal — the repository's
`fuzz/` and `verification/tests/vectors/` harnesses accept them directly).

### Encryption

`security@solarcyberunit.org` is currently served **without a published PGP key**. Until
a key is published here, encrypting the report is not possible, and the
maintainers acknowledge this as an open gap in the disclosure channel rather
than a settled part of it. Until a key exists:

- treat the GitHub Security Advisory channel as the confidential one;
- do not send a live exploit against a public network;
- ask for a key to be published if your report needs one.

## Disclosure window

| Severity | Meaning | Fix target | Disclosure |
|---|---|---|---|
| **Critical** | Chain-halting: an invalid block is accepted, or a consensus rule can be broken | Immediate, out of cycle | Coordinated, after a patch is published on the affected branch |
| **High** | Key compromise, forging of an authorization or a certificate, or theft of funds | 7 days | Coordinated, after the fix ships |
| **Medium** | A bounded denial of service, a resource limit that can be exhausted, or a bookkeeping defect that cannot move value | 30 days | Public on the fix date |
| **Low** | A hardening gap, an information leak with no key material, or a missing limit | Next release | Public on the fix date |

**Responsible disclosure window: 90 days.** If a fix is taking longer, tell us
before the window closes and we will agree a date with you. We will not pursue
an action against a reporter who stays inside the agreed window.

A report is a bug report, not an attack. Demonstrating the defect on a
`mini` or `testnet` network is fine; demonstrating it against a live network
with real value is not.

## What counts as a vulnerability

- Any path by which a node accepts a block or transaction that the
  specification forbids, or by which two nodes with the same valid history
  disagree on the resulting state.
- Any path by which value moves without the authority the protocol requires —
  including the node-local books (receipts, payments, credit, escrow,
  delegation), which must never be able to create spendable balance.
- Any path by which a private key, a wallet file, a validator key or a bearer
  token is disclosed, or by which an encrypted wallet file can be decrypted
  without the passphrase.
- Any path by which a policy, a credit line, a delegation chain, an escrow
  authorisation, or a Smart Gate capability can be forged, replayed, or bypassed.
  This includes `action_hash` / `context_hash` mismatch accepted as allow,
  expired or over-lifetime capabilities accepted, reused nonces accepted,
  cross-principal capabilities accepted, or window accounting mutated on deny.
- Any unbounded resource consumption reachable from the network boundary (API,
  peer-to-peer frame, block or transaction decoding, storage recovery).
- Any failure to fail closed: a refusal that is silently converted into a
  permissive path, or a missing-state case that produces an empty set where a
  populated one was meant.

## Smart Gate security model

The Smart Gate (`srct-core::guard`, `srct-policy::guard_verify`,
MCP `guard.check` / `guard.authorize`, `POST /v1/guard/decide`) is a
service-layer gate, not consensus. It answers `allow / deny /
needs_approval` and never moves value by itself.

- **Trusts:** the owner key that signed the grant, the verifier that
  re-derives `action_hash` and `context_hash` from what it is about to
  execute, and the Solar tip that anchors audit receipts. Endpoints are
  assumed compromisable: long-lived tokens on laptops are treated as already
  exposed.
- **Enforces:** exact hash equality on all three bindings, expiry and the
  30-height lifetime cap, strictly increasing nonces, tumbling-window budgets
  that never mutate on deny, cross-principal rejection, and second-channel
  approval for high-risk actions (the payer key never counts as approver).
- **Does not promise:** malware prevention on the endpoint, attestation of
  the workload binary itself, or network confidentiality. A forged
  `action_hash` at the verifier (lying about what will execute) is an
  integrator bug, not a gate bypass — report it as such with the adapter name.
- **Integrator rules:** verify with the same `srct-core` functions or
  `srct-policy` (do not re-implement the checks), recompute `action_hash`
  and `context_hash` locally (never accept them from the requester alone),
  treat `needs_approval` as deny until the approver signature lands, and
  alert on `window_exhausted` bursts the way exit-watch alerts on full
  windows. Forks are expected to verify but cannot inherit trust: network
  binding, quorum, and history stay with the canonical chain.

## What is out of scope

- A miner with more hash power than the honest majority: that is the
  documented security model of a proof-of-work chain, not a bug.
- A validator committee that exceeds two thirds of itself: that is the
  documented assumption behind quorum finality.
- An unchallenged but incorrect task result being paid. That is the documented
  optimistic settlement rule; the protocol distinguishes a quorum-backed
  certificate from an unchallenged one, and the weakness is structural and
  documented.
- Compile-time, dependency or linter findings with no reachable impact.
- Missing tests without an identified defect.

## Supported versions

The protocol is **pre-launch**. Security fixes land on `main` and on the
release branch of the current protocol version. There is no long-term-support
branch: the chain has not launched, so there is no deployed history to keep
compatible.

Any fix that changes a consensus rule, a serialization format or a fee
schedule is a **protocol version bump**: it changes the network magic, the
state format and, when the serialized genesis block changes, the genesis hash.
It is announced as such in the release notes before it ships.

## Scope of this policy

This policy covers the code in this repository: the protocol implementation, the
node, the standalone miner and pool server (`srct-miner`, including the
stratum-lite wire protocol and PPLNS payout accounting), the worker SDK, the
MCP surface, the fuzzing harnesses and the
simulation suite.

It does **not** cover a network operated by a third party, an exchange, a
custodian or a wallet provider, nor any service that reaches this code over
the network. Those are their own operators' responsibility. If a defect in
this repository is what makes a third-party service unsafe, report it here
anyway.
