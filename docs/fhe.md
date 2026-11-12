# Encrypted Compute (FHE Prototype)

`srct-fhe` is a working encrypted-compute prototype, not general FHE. Agent A
encrypts its inputs, worker B evaluates a weighted sum over the ciphertexts,
and any verifier re-runs the public operation to check the result. The worker
never sees plaintext; the requester's secret never leaves its owner.

## What it is

Exponential ElGamal over secp256k1: `Enc(m) = (rG, mG + rP)`.

- **Additive homomorphism:** `Enc(a) + Enc(b) = Enc(a+b)`.
- **Scalar multiplication:** `k * Enc(a) = Enc(ka)` (negative `k` wraps mod n).
- **Decryption:** baby-step giant-step discrete log in `[0, bound)`. The
  caller picks `bound`; arithmetic is modulo the curve order.

The one supported operation is `output = bias + Σ weights[i] * inputs[i]`
over ciphertexts — the linear core of private-input neural inference.

## Workflow

```
FheTask = version || network || requester || provider || enc_pubkey ||
          weights || bias || inputs || deadline || nonce
FheReceipt = version || task_hash || worker || output || height || nonce
```

1. A generates a keypair, encrypts inputs, signs the task (signature covers
   inputs, weights, provider, deadline — none can be swapped).
2. B evaluates `eval` homomorphically and signs the receipt.
3. `FheVerifier::verify` checks: signatures, requester/worker bindings, task
   hash match, height not future, deadline not passed, **exact homomorphic
   recomputation** (a worker that skips work or fabricates output fails here),
   and a replay book. Returns the output ciphertext on `Ok`.
4. The escrow rail releases payment on `Ok`. A decrypts with its secret.

## Honest limits

- **One operation only.** No encrypted non-linearities, no bootstrapping, no
  TFHE. Weights and bias are public; only inputs/outputs are private.
- **Bounded values.** Decryption searches `[0, bound)`; arithmetic is modulo
  the curve order. `cost::eval_bounded` refuses an evaluation whose static
  worst case exceeds the decryption bound, so an over-bound sum never reaches
  a receipt — but there is still no zero-knowledge range proof on inputs.
- **No range proofs.** Ciphertexts are validated on-curve, not on-range.
- A requester's keypair is self-managed; there is no on-chain key registry.

## Verified behavior

`cargo test -p srct-fhe` passes 12 acceptance tests: encrypt/decrypt
round-trips (0 to 1,000,000), randomized encryption (same plaintext, different
bytes), homomorphic add/scale matching plaintext, a full task→receipt→verify
workflow decrypting to the exact expected value (59), tampered output refused
as `FraudulentOutput`, tampered inputs/weights breaking the task signature,
impostor and wrong-worker refusals, late/future receipts refused, double
settlement refused, malformed tasks (identity/off-curve keys, over-cap
weights, empty inputs, zero nonce/deadline) refused, wire round-trips —
plus exact operation-cost pricing (`task_cost`/`price_task`) with overflow
refusal.

Measured on this machine (debug build): full 11-test suite in ~42 s, dominated
by BSGS table builds at bound 2^32 (~65k entries). Production bounds should be
set per workload; smaller bounds decode proportionally faster.

## Next milestones

1. TFHE-style runtime for non-linear ops (ReLU, argmax) and bootstrapping —
   research work, explicitly out of scope for this prototype.
2. Encrypted-weight inference (both model and input private) — research work.
3. Range proofs on inputs so overflow fails closed instead of wrapping —
   partially covered by static bound analysis (`cost::eval_bounded`
   refuses over-bound evaluation before any ciphertext work); ZK range
   proofs remain research work.
4. On-chain encryption-key registry — **done** (`KeyRegistry`: operator-curated
   keys with rotation that keeps old keys resolvable and revocation that
   distrusts entirely).
5. Escrow-rail integration — **done** (`FheEscrow`: fund once, release exactly
   the funded task on a verified receipt, refund the remainder exactly once
   after the deadline). Payment-rail execution of the instructions is next.
