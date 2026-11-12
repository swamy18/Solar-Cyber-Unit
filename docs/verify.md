# Unified Verification Policy

`srct-verify` answers Section 7 of the brief: which evidence a task needs,
and one verifier that checks it all.

## Policy

Three claims, three mechanisms:

| Claim | Mechanism | Crate |
|---|---|---|
| Proof of execution | TEE attestation | `srct-compute::tee` |
| Proof of correctness | FHE recomputation / ZK proof | `srct-fhe`, `srct-zkml` |
| Proof of resource use | Metered receipts | `srct-compute::settle` via `Evidence::Compute` |

`select_proofs` maps a task profile (kind, security level, value) to the
required proof set. Execution first (cheap reject), correctness second.
Rules: encrypted compute always proves correctness (high stakes add
execution); attested execution always proves execution (critical adds
correctness); proven compute is correctness only; plain inference needs
correctness only when high-value (≥ 1M sat) or high security.

The policy is advisory — the verifier enforces whatever evidence it gets,
and the escrow rail decides what to require.

## Unified verifier

`UnifiedVerifier` holds the TEE, FHE, ZKML and compute-ledger replay books and verifies any
`Evidence` (quote+SLA, task+receipt, task+receipt, assignment+receipt) through the inner
verifiers, preserving their error types transparently. The same evidence can
never verify twice, even across mixed workloads. Accepted evidence returns
the output commitment for the escrow rail to settle against (compute returns
the 8-byte LE payout amount).

## Verified behavior

`cargo test -p srct-verify` passes 9 acceptance tests: the full policy table
is pinned, TEE/FHE/ZKML/compute evidence each verify through the unified verifier
with the right kind tags, fraud, wrong-statement, expired and replayed evidence are refused
with transparent inner errors, one verifier handles mixed evidence independently,
the profile gate refuses release without its proof set, and the gated-release
seam runs the rail closure only on pass.

## Next milestones

1. Escrow-rail integration — **gate plus seam done** (`verify_for_profile`:
   verifies every evidence and refuses release unless the policy's proof set
   is covered; `gated_release` runs the rail's closure only on pass, never
   on failure). Node-side L1 escrow paths are intentionally unwired: the L1
   coin escrow is signature-gated, not proof-gated, and mixing the two would
   be a consensus-adjacent behaviour change.
