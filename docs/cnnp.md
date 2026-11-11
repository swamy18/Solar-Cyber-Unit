# Cross-Neural Network Protocol (CNNP) core

Status: **working non-consensus prototype** in `crates/srct-cnnp`. It defines
representation spaces, signed and sealed representation envelopes, real
cross-space adapters, signed capability discovery, and exact usage settlement.
It does not change consensus, and it does not move coins itself.

```bash
cargo test -p srct-cnnp
cargo run --release -p srct-cnnp --example cnnp_demo
```

## 1. What problem it solves

Independently built models cannot cooperate by default:

- the same 8 floats mean different things in different layers and tokenizers;
- a service cannot tell whether a vector came from the model it claims;
- a provider cannot price work per representation without a metering unit;
- a caller cannot discover a compatible provider or prove what was delivered.

The CNNP core answers those four questions with data formats and signatures.
It deliberately does not merge models or require a shared runtime.

## 2. Components

### Representation space (`space::ModelSpace`)

```
ModelSpace = model_id(32) || tokenizer(32) || architecture || layer ||
             dim(u32) || dtype(u8)
space_hash = SHA256("srct/cnnp/space/v1" || encode(ModelSpace))
```

Two spaces with the same dimension are still different spaces if their model,
tokenizer, architecture or layer differs. Adapters and envelopes bind to the
hash, not to the dimension alone.

### Signed and sealed envelopes

A plain envelope carries `f32` little-endian values. A sealed envelope carries
XChaCha20-Poly1305 ciphertext under a caller-supplied 32-byte key.

```
commitment = SHA256("srct/cnnp/envelope-commit/v1" ||
                    space_hash || owner || seal_flag || nonce? || payload)
signing_hash = SHA256("srct/cnnp/envelope/v1" ||
                      version || space_hash || owner || seal_flag || commitment)
AEAD AAD = space_hash || owner || nonce || version
```

Properties:

- the owner signs the exact payload through the commitment, so swapping values
  invalidates the signature;
- the AEAD binds ciphertext to space, owner and nonce, so a sealed payload
  cannot be re-homed to another space even if the attacker re-signs the
  envelope;
- a plain envelope refuses a decryption key and a sealed envelope refuses to
  decode without one, so the privacy mode is never ambiguous.

Metadata (space, owner, size, timing) stays visible. This is representation
confidentiality, not metadata privacy.

### Linear adapters (`adapter::LinearAdapter`)

An adapter is a signed affine map `target = W * source + b`, fitted by ridge
regression on paired activations:

```
min_W  ||X W - Y||^2 + lambda * ||W||^2
(X^T X + lambda I) W = X^T Y        (bias column not regularized)
```

The solver uses Gauss-Jordan elimination with partial pivoting in `f64`, then
stores `f32` weights. The adapter commits to the source hash, target hash,
weights, bias, sample count, training MSE and trainer, and the trainer signs
that hash. Applying it verifies the envelope's source space first.

This transfers a *representation*, not model weights: a provider can offer a
target-space capability without publishing its model.

### Capability discovery (`registry`)

A capability names the provider, source and target spaces, service, price per
unit, unit cap, latency, privacy level, verification level, expiry and nonce.
Discovery verifies every signature, skips expired offers, filters by the
query, and sorts by `(price, latency, provider, nonce)` so every caller sees
the same ranking.

### Metering and plans (`metering`)

A usage receipt binds:

```
capability_hash || payer || request_id || provider || units ||
unit_price || total || height || nonce
```

and is signed by the provider. Settlement checks the offer signature, the same
capability, provider, price, unit cap, expiry and arithmetic, then returns
`Settlement { from: payer, to: provider, amount_sat }`.

`ReceiptBook` is the economic nullifier: a payer-assigned `request_id` can be
settled once. A replay, or a second receipt for the same work under a different
nonce, is refused.

A plan chains capability hashes from an input space to an output space, with a
per-stage unit count. `quote_plan` checks that every offer is valid and
unexpired, that consecutive spaces match
(`stage[i].target == stage[i+1].source`), that each unit count is inside the
offer's cap, that privacy and verification floors hold, and that
`sum(units * price)` is under the cap.

## 3. Measured results

Environment: development machine, release profile, example `cnnp_demo`.

| Metric | Value |
|---|---|
| Adapter fit, 128 paired samples, 8 -> 16 dims | 1.9-3.4 ms |
| Adapter MSE on training pairs | 0.000032 |
| Mean-predictor baseline MSE | 0.464712 |
| Sealed envelope size, 8 floats | 436 bytes |
| Two-stage plan | 30 sat, 100 ms |

The training pairs are generated from a fixed linear map plus a small nonlinear
term. The adapter is expected to recover the linear part nearly exactly; the
residual is the nonlinear term. This is a correctness test for the fitting and
binding path, not a claim about semantic alignment between real foundation
models.

## 4. Threat model

**Stopped by the implementation**

- Tampered plaintext, wrong owner key, swapped signature bundle.
- A sealed envelope decoded without the key or with the wrong key.
- Ciphertext re-homed to another space (AAD mismatch) even with a fresh
  signature.
- Applying an adapter to the wrong source space or the wrong dimension.
- Tampered adapter weights or a signer that is not the named trainer.
- A capability signed by someone other than its provider.
- Expired offers in discovery or plans.
- Over-unit billing, a price that differs from the offer, a future receipt,
  arithmetic that does not match `units * price`.
- Replayed receipts and a second receipt for the same request id.
- Plan stages that do not chain, an output space that is not reached, a plan
  over budget, or a plan that violates the privacy/verification floor.

**Not provided**

- Semantic equivalence. A low training MSE does not prove that two models mean
  the same thing; the adapter can be overfitted or the paired data can be
  unrepresentative.
- Model-weight privacy. Envelopes protect representations and adapter weights
  are published; the model itself is never sent, but inference-side leakage is
  out of scope.
- Metadata privacy. Space, owner, timing and size are visible.
- Key exchange. Sealed envelopes take a raw 32-byte key; deriving it needs a
  KEM or an existing secure channel.
- Transport, gossip, availability and denial-of-service. Offers and envelopes
  are byte formats; the operator's rail carries them.
- Consensus settlement. `Settlement` is an authorization, not a payment. The
  existing SRCT payment/x402/escrow path must move value.
- A trustless model of adapter quality. The trainer's signature proves who
  fitted it, not that it is good.

## 5. Integration with SRCT

- **Payments.** `Settlement` and the offer's `price_sat_per_unit` feed the
  existing `payment.rs` / x402 metered path. No new coin or mint is created.
- **Verification levels.** `Verification::{None, ProviderSigned, Optimistic,
  Tee, Zk}` is the routing seam for the later TEE/ZKML milestones. Today only
  provider-signed receipts and discovery metadata are implemented.
- **Escrow.** A plan can be quoted first and settled per stage; the existing
  L2 escrow/dispute path remains the fallback for `Optimistic`.
- **Privacy levels.** `Privacy::{Public, Sealed, Tee, Fhe}` distinguishes what
  is actually protected. `Sealed` is implemented; `Tee` and `Fhe` are labels a
  provider may not advertise until the corresponding verification exists.

## 6. Roadmap

1. Nonlinear adapters (small MLP/attention) with a versioned format.
2. Tokenizer-level input adapters, not just layer activations.
3. Capability gossip and an HTTP/MCP transport binding.
4. Semantic evaluation harness: held-out probes, not just paired MSE.
5. Work-graph attribution: adapter reuse and downstream revenue sharing.
6. TEE/FHE verification levels wired to real attestation and FHE runtimes.
7. Cross-chain intent lifecycle on top of plans and receipts (quote, execute,
   verify, refund, dispute).

Interfaces alone do not count as completion; each item needs working code,
adversarial tests and measured limits.
