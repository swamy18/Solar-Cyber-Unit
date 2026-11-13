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

## Toy TFHE gates (`src/tfhe.rs`)

A weighted sum stays linear no matter how it is evaluated, so the ElGamal
core above cannot do non-linear work. `tfhe.rs` adds the missing piece the
other way — bootstrapped binary gates over LWE ciphertexts, from which any
boolean circuit (and, by lookup table, small quantized non-linearities like
ReLU) is built:

- **LWE** encrypts one bit as `b = <a, s> + e + m/8` on a coarse mask grid
  (`TFHE_MASK_STEP = 2^24`), so the blind rotation's phases are exact;
- **TGGSW external product**, **blind rotation** and **sample extract**
  compose into a **functional bootstrap** evaluating a lookup table;
- gates: **NAND, AND, OR, XOR, NOT, MUX, ReLU2** — every gate output is
  re-encrypted through `rebind`, so gates compose into circuits.

Toy parameters (`N = 128`), non-constant-time, naive `O(N^2)` arithmetic:
correctness is measured (every gate against its full truth table, plus
randomized trials), never claimed. Not production crypto; the TFHE envelope
is not wired into tasks (that binding is a protocol step).

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

- **One task operation only.** The task envelope carries the linear
  `bias + Σ w·x` evaluation; non-linearities exist only as the standalone
  toy TFHE engine above, not wired to tasks. Weights and bias are public;
  only inputs/outputs are private.
- **Bounded values.** Decryption searches `[0, bound)`; arithmetic is modulo
  the curve order. `cost::eval_bounded` refuses an evaluation whose static
  worst case exceeds the decryption bound, so an over-bound sum never reaches
  a receipt — but there is still no zero-knowledge range proof on inputs.
- **No range proofs.** Ciphertexts are validated on-curve, not on-range.
- A requester's keypair is self-managed; there is no on-chain key registry.

## Verified behavior

`cargo test -p srct-fhe` passes 27 tests — 16 acceptance tests: encrypt/decrypt
round-trips (0 to 1,000,000), randomized encryption (same plaintext, different
bytes), homomorphic add/scale matching plaintext, a full task→receipt→verify
workflow decrypting to the exact expected value (59), tampered output refused
as `FraudulentOutput`, tampered inputs/weights breaking the task signature,
impostor and wrong-worker refusals, late/future receipts refused, double
settlement refused, malformed tasks (identity/off-curve keys, over-cap
weights, empty inputs, zero nonce/deadline) refused, wire round-trips —
plus exact operation-cost pricing (`task_cost`/`price_task`) with overflow
refusal — and 11 TFHE unit tests: LWE round-trips, bit-exact gadget
decomposition, negacyclic wrap, external product scaling by the secret bit,
sample extraction, and full truth tables plus randomized trials for every
gate (NAND/AND/OR/XOR/NOT/MUX/ReLU2, including a chained MUX).

Measured on this machine (debug build): full 11-test suite in ~42 s, dominated
by BSGS table builds at bound 2^32 (~65k entries). Production bounds should be
set per workload; smaller bounds decode proportionally faster.

## Next milestones

1. TFHE-style runtime for non-linear ops: **toy engine done**
   (`src/tfhe.rs`, gates + rebind into circuits). What remains is
   productionizing it — standard parameters, NTT kernels, constant-time
   code, and wiring TFHE ciphertexts into task envelopes (wire v2).
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
