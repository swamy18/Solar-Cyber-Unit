# Zero-Knowledge ML Verification (Prototype)

`srct-zkml` proves correct quantized linear evaluation in zero knowledge:
the worker commits to private inputs, proves `output = bias + Σ w·x`, and
the verifier learns nothing about the inputs — only that the computation
was correct.

## What it is

Sigma protocols over secp256k1 (Schnorr + CDS OR-composition + Fiat-Shamir),
no new dependencies:

- **Pedersen commitments** `Com(v, r) = vG + rH` hide each input and each
  bit. Perfectly hiding, computationally binding.
- **Bit-proofs:** every input is bit-decomposed; each bit commitment carries
  a CDS OR-proof that it opens to 0 or 1.
- **Homomorphic checks:** the verifier recomputes `X == Σ 2^i·B_i` (range)
  and `Y == Σ w_i·X_i + bias·G` (evaluation) on commitments. A worker that
  skips the work or fabricates the output fails here.
- **Fiat-Shamir:** every challenge hashes the statement (weights, bias,
  commitments) plus the prover's first messages, so proofs cannot be
  transplanted to another evaluation.

## Workflow

```
ZkTask    = version || network || requester || provider || weights ||
            bias || input_commitments || deadline || nonce
ZkReceipt = version || task_hash || worker || bit_proofs ||
            output_commitment || height || nonce
```

1. Worker commits to inputs and bits, proves each bit, signs a receipt.
2. `ZkVerifier::verify` checks signatures, bindings and deadline, then the
   OR-proofs and homomorphic equations, then the replay book. Returns the
   output commitment on `Ok`.
3. The escrow rail releases payment on `Ok`.

## Honest limits

- **One linear layer.** At most 8 inputs of 16 bits, no non-linearities, no
  folding/recursion (Nova-style systems are future).
- **Public model.** Weights and bias are public; only inputs/outputs are
  private. Model privacy is future.
- **Prototype generator.** `H` is derived from a fixed label, not a true
  nothing-up-my-sleeve ceremony. Replacing it is a one-line change with no
  protocol impact.
- **Correctness, not usefulness.** The proof shows the specified computation
  ran, not that the output is factually correct or useful.

## Evaluated and rejected

Bulletproofs R1CS (`bulletproofs 5.0.0` with `yoloproofs`): the published
crate does not compile — its `r1cs/proof.rs` calls `CtOption::ok_or`, which
exists in neither `subtle 2.5.0` nor `2.6.1`. Depending on it was not an
option, so this prototype uses only the workspace's existing `k256`.

## Verified behavior

`cargo test -p srct-zkml` passes 9 acceptance tests in ~3 s: circuit
prove/verify with a plaintext cross-check (68), a full task→receipt→verify
workflow, tampered output commitments and wrong-statement proofs refused as
`InvalidProof`, tampered commitments breaking the task signature, impostor
and wrong-worker refusals, late/future/replay refusals, malformed tasks
(over-cap weights, count mismatches, zero deadline/nonce) and receipts
(wrong bit shape) refused, and wire round-trips.

## Next milestones

1. Non-linear gates (ReLU/argmax range arguments) for real neural layers.
2. Folding/recursion (Nova-style) to aggregate many proofs cheaply.
3. Model-commitment privacy: prove over committed weights too.
4. Ceremonied NUMS generator to replace the prototype `H`.
5. Escrow-rail integration: fund on task, release on verified receipt, refund
   on deadline, slash on proven fraud.
