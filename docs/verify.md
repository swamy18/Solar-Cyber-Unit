# Unified Verification Policy

`srct-verify` answers Section 7 of the brief: which evidence a task needs,
and one verifier that checks it all.

## Policy

Three claims, three mechanisms:

| Claim | Mechanism | Crate |
|---|---|---|
| Proof of execution | TEE attestation | `srct-compute::tee` |
| Proof of correctness | FHE recomputation / ZK proof | `srct-fhe`, `srct-zkml` |
| Proof of resource use | Metered receipts | `srct-compute::settle` (enforced there) |

`select_proofs` maps a task profile (kind, security level, value) to the
required proof set. Execution first (cheap reject), correctness second.
Rules: encrypted compute always proves correctness (high stakes add
execution); attested execution always proves execution (critical adds
correctness); proven compute is correctness only; plain inference needs
correctness only when high-value (≥ 1M sat) or high security.

The policy is advisory — the verifier enforces whatever evidence it gets,
and the escrow rail decides what to require.

## Unified verifier

`UnifiedVerifier` holds the TEE, FHE and ZKML replay books and verifies any
`Evidence` (quote+SLA, task+receipt, task+receipt) through the inner
verifiers, preserving their error types transparently. The same evidence can
never verify twice, even across mixed workloads. Accepted evidence returns
the output commitment for the escrow rail to settle against.

## Verified behavior

`cargo test -p srct-verify` passes 5 acceptance tests: the full policy table
is pinned, TEE/FHE/ZKML evidence each verify through the unified verifier
with the right kind tags, fraud and wrong-statement evidence are refused
with transparent inner errors, replays are refused, and one verifier handles
mixed evidence independently.

## Next milestones

1. Resource-use proofs in the unified verifier (receipt settlement dispatch).
2. Escrow-rail integration: require the policy's proof set before release.
3. Intent lifecycle wiring: enforce `Verification::{Tee, Zk}` levels on
   delivery (roadmap item 6).
