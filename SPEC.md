# SOLAR CYBER UNIT PROTOCOL SPECIFICATION

**Version:** 0.1.0 (the workspace version in `Cargo.toml`)
**Status:** Draft — §0–§12 normative for `srct-core`; §13 normative for `srct-net`; §14 records the M1–M5 protocol mechanisms and, for each, whether it is consensus-active today; §15–§17 normative for `srct-l2`; §18 for `srct-worker`; §19 for L1↔L2 integration. §19.1, §19.2, §19.4, §19.5 and §19.6 are implemented and tested. §20 (conditional escrow) is implemented as a non-consensus node-records-state surface in `srct-core::escrow` and `srct-node::api`; coin settlement runs via `POST /v1/escrow/{id}/settle` (§20.2).
**Scope:** Layer 1 (base layer, §0–§13), the M1–M5 protocol mechanisms (§14), Layer 2 and the worker SDK (§15–§18), and L1↔L2 integration including deposits and exits (§19). §13 covers block and transaction relay between nodes.

This document is the **normative reference**. Any implementation in any language must produce identical byte-level output for the vectors in `tests/vectors/`. Five vector files exist today — the four covering §0–§12, plus `net_vectors.json` (§13.12) for the wire format.

---

## 0. Conventions

| Rule | Value |
|---|---|
| Hash | SHA-256 (FIPS 180-4), 32 bytes — internal commitments, Merkle nodes, PoW evidence |
| Chain identity hash | SHA-512 (FIPS 180-4), 64 bytes — `txid` and `block_hash` only. A 256-bit digest keeps ~128 bits of preimage resistance against Grover and ~85 bits of collision resistance against a quantum (BHT) collision search; doubling the width of the two ids an attacker most wants to forge restores a full 256-bit margin. Nothing else widens: the PoW target comparison, Merkle nodes and addresses keep their widths |
| Signature | secp256k1, ECDSA, compact 64-byte `r‖s`, low-`s` enforced |
| Integer arithmetic | Signed/unsigned integers only. **No floating point anywhere in consensus.** |
| Byte order | Explicit `LE` (little-endian) or raw (byte sequence as written) on every field |
| Amounts | Satoshis (smallest unit). `1 SRCT = 100,000,000 sat` (8 decimals) |
| Difficulty | `u128`, always `≥ 1` |
| Difficulty ceiling | `MAX_DIFFICULTY = 2^96` (keeps target division overflow-free in any language) |
| U256 | Big-endian 32-byte unsigned integer; `U256_BE(bytes)` is the primary comparison form |

**Domain separation.** Every hash input is prefixed with an ASCII domain tag (raw bytes, no NUL terminator). Tags are frozen and MUST NOT change for a given version suffix `/v1`.

| Tag | Bytes |
|---|---|
| `DOM_BLOCK` | `srct/blockhash/v1` |
| `DOM_BLOCK512` | `srct/blockhash512/v1` |
| `DOM_TX` | `srct/txid/v1` |
| `DOM_TX512` | `srct/txid512/v1` |
| `DOM_TXBODY` | `srct/txbody/v1` |
| `DOM_SIG` | `srct/sig/v1` |
| `DOM_ADDR` | `srct/addr/v2` |
| `DOM_S1` | `srct/puzzle/stage1/v1` |
| `DOM_S2` | `srct/puzzle/stage2/v1` |
| `DOM_S3` | `srct/puzzle/stage3/v1` |
| `DOM_W` | `srct/puzzle/weights/v1` |
| `DOM_GENESIS` | `srct/genesis/v1` |
| `DOM_NET_HANDSHAKE` | `srct/net/handshake/v1` |

Single-byte tags for the M3/M5 envelopes (§14). They are one byte rather than an
ASCII string because they tag a fixed-shape payload, not a message family:

| Tag | Value | Covers |
|---|---|---|
| `DOM_COMPUTE_TASK` | `0xC0` | §14.2 compute task |
| `DOM_COMPUTE_ATTEST` | `0xC1` | §14.2 compute attestation |
| `DOM_BLS_CHECKPOINT` | `0xB1` | §14.4 BLS checkpoint payload |

---

## 1. Keys, addresses, signatures

```
pubkey  = 33 bytes, compressed secp256k1 point (0x02/0x03 prefix + 32-byte X)
address = U8(U8(SHA256(DOM_ADDR ‖ pubkey))[0..20])          // 20 bytes
```

Signatures are versioned by the header field `sig_scheme` (**signature agility**, Section 20.1):

| `sig_scheme` | Scheme |
|---|---|
| `1` | secp256k1 ECDSA over SHA-256 (v0.1 only) |
A future hybrid post-quantum scheme MUST use a new `sig_scheme` value and MUST NOT reuse `1`. Nodes MUST reject unknown `sig_scheme` values.

### 1.1 Signature message

The signature for input `k` commits to the entire transaction **except** the signatures themselves, so outputs cannot be swapped after signing:

```
sighash = SHA256( DOM_TXBODY ‖ serialize(tx with every input.signature = 64 zero bytes
                                            and every input.pubkey   = 33 zero bytes) )
msg_k   = SHA256( DOM_SIG ‖ U4LE(k) ‖ sighash ‖ U4LE(input[k].prevout_index) )
```

`msg_k` is what the private key of `input[k].prevout` signs.

---

## 2. Merkle root

Standard binary Merkle tree, Bitcoin-style, domain-separated:

```
leaf(i)      = SHA256( 0x00 ‖ serialize(tx_i) )
internal(l,r) = SHA256( 0x01 ‖ l ‖ r )
```

Construction: pair leaves left-to-right; if the level has an odd node count, **duplicate the last node** and continue. The root of a single-transaction block is `leaf(0)`.

---

## 3. Serialization

All lengths are implied by the field list. Integers marked `LE` are little-endian.

### 3.1 `Input` — variable

| Field | Size |
|---|---|
| `prevout_hash` | 64 raw |
| `prevout_index` | 4 LE |
| `sigs` | signature bundle (§3.5) |
| `keys` | public-key bundle (§3.5) |

Fixed prefix is 68 bytes. The two bundles are length-prefixed, so the input is
variable-length. This is deliberate: a post-quantum signature is ~2.4 KB
(ML-DSA-44) to 3.3 KB (ML-DSA-65), and no fixed field sized to today's 64-byte
ECDSA could ever hold one. A cap that admits a real post-quantum signature would
have to be at least 4096 bytes per component regardless.

### 3.2 `Output` — 28 bytes

| Field | Size |
|---|---|
| `value` | 8 LE |
| `address` | 20 raw |

### 3.3 `Transaction` — variable

| Field | Size |
|---|---|
| `version` | 4 LE |
| `tx_type` | 1 (`0` = standard, `1` = coinbase, `2` = bond, `3` = unbond, `4` = slash; anything else is refused, never interpreted as standard) |
| `lock_time` | 8 LE |
| `input_count` | 4 LE |
| `inputs` | `input_count × (variable)` |
| `output_count` | 4 LE |
| `outputs` | `output_count × 28` |
| `stake` | present only for types 2–4 (see below); standard and coinbase carry no byte here, so their txids are unchanged |

Stake payloads (Decision 20), positional by `tx_type`:

| Type | Payload |
|---|---|
| `2` (bond) | `bls_pk` (48) ‖ optional `0x01 ‖ mldsa_pk` (1952) — the BLS key the bond authorizes, plus the validator's lattice key when it registers one. A bare 48-byte payload is a bond with no lattice key; a `0x00` flag byte means the same. The lattice key never replaces the BLS key as the committee identity |
| `3` (unbond) | `bond_id` (64) — the txid of the `TX_BOND` that created the bond |
| `4` (slash) | `len_a` (4 LE) + checkpoint A + `len_b` (4 LE) + checkpoint B (each ≤ 262 144 bytes) — two conflicting checkpoints as equivocation evidence (sized for dual-signed certificates carrying up to 64 lattice signatures) |

### 3.5 Signature and key bundles

A bundle is an ordered, canonical list of components:

```
count          1        (0 permitted only for an unsigned or coinbase input)
per component: scheme   1
                len     2 LE
                bytes   len
```

Rules, all enforced:

- `1 ≤ count ≤ 4` for an input that claims to spend.
- `1 ≤ len ≤ 4096` per component. Checked against the *declared* length before
  any allocation, since the prefix is attacker-controlled.
- Total serialized size ≤ `2 × 4 × 4096 + 512`.
- Every `scheme` must be one this implementation can verify.
- A scheme may not repeat within one bundle — a duplicate adds bytes without
  adding independence, so it is not a hybrid.

An unsigned input and a coinbase input both carry two empty bundles
(`count = 0`), which is why `count = 0` parses. Non-emptiness is enforced by
validation, which only runs for inputs that actually claim to spend.

**Hybrid verification.** `sigs` and `keys` are parallel: `sigs[i]` is verified
by the key in `keys` declaring the same `scheme` id — matched by id, not by
position. **Every** component must verify. A one-of-N rule would not be a
hybrid: an adversary who breaks one primitive would forge that component and
strip the rest.

**Addresses commit to the whole key set.**
`address = SHA256(DOM_ADDR || serialize(keys))[0..20]`, with `DOM_ADDR` at
`/v2` because the preimage changed from a bare 33-byte pubkey to a serialized
bundle. An ECDSA-only key set and a hybrid one therefore cannot share an
address, and a hybrid key set cannot be quietly reduced.

**Schemes.** `1` = secp256k1 ECDSA (low-`s`, canonical). `2` = secp256k1
BIP-340 Schnorr. Scheme 2 exercises the multi-scheme path end to end; it is not
post-quantum and adds no quantum resistance on its own. A lattice scheme (3)
would slot in without changing any encoding, since the bundle is generic.

**Scheme `3` = ML-DSA-65 (FIPS 204), security level 3. Implemented.** A Shor
break of secp256k1 does not reach the lattice component, so a bundle carrying
`1 + 2 + 3` keeps a spend authorizable when the classical primitives fail and
vice versa: every component must verify, so breaking any single one does not
let an attacker through. Verifying keys are 1952 bytes and signatures 3309,
both inside the 4096-byte component cap that was sized for exactly this.
Verification is over the 32-byte digest with an empty ML-DSA context, since the
digest is already domain-separated upstream.

The three scheme sets a wallet can sign, and the address each one commits to:

| Mode | Schemes | Address |
|---|---|---|
| `Classical` | `1` | `ecdsa_address` |
| `Hybrid` (default) | `1 + 2` | `hybrid_address` |
| `PostQuantum` | `1 + 2 + 3` | `pq_address` |

All three addresses are distinct by construction — the address hashes the whole
serialized key bundle — so funds credited to one are not spendable under
another, and a hybrid output cannot be quietly reduced to its classical half.
`Transaction::verify_input` derives the address from the input's own key bundle
and compares it to the address that owns the spent output, so a bundle a
caller invents for an output it does not own is refused before any
cryptographic check.

Scheme `3` is accepted by consensus but **not required yet**:
`pq_activation_height` is `0` on every profile (§9.3, §10). Once a profile sets
it, an input spending an output created at or after that height must carry an
ML-DSA-65 component; outputs predating it are exempt, so the rule is age-gated
and never strands history. Turning it on is the PQ-activation decision recorded
in `docs/decisions.md` (Decision 24).

```
txid = SHA512( DOM_TX512 ‖ serialize(tx) )          // 64 bytes
```

### 3.4 `Header` — exactly 177 bytes

| Field | Size | Notes |
|---|---|---|
| `version` | 4 LE | block version |
| `height` | 8 LE | `0` for genesis |
| `prev_hash` | 64 raw | previous block hash (512-bit identity) |
| `merkle_root` | 32 raw | |
| `timestamp_ms` | 8 LE | Unix milliseconds |
| `base_fee_sat` | 8 LE | base fee for the *next* block (§8) |
| `difficulty` | 16 LE | `u128`, `≥ 1`, `≤ 2^96` |
| `nonce` | 8 LE | |
| `puzzle_id` | 8 LE | puzzle registry entry |
| `epoch_id` | 4 LE | NN weight epoch |
| `extra_nonce` | 16 raw | miner-controlled |
| `sig_scheme` | 1 | |

```
block_hash = SHA512( DOM_BLOCK512 ‖ serialize(header) )          // 64 bytes
```

### 3.5 `Block`

```
serialize(block) = serialize(header) ‖ signature(64 raw) ‖ signer_pubkey(33 raw)
                        ‖ U4LE(tx_count) ‖ serialize(tx_0) ‖ … ‖ serialize(tx_{n-1})
```

`signer_pubkey` is informational in v0.1 (no header-level signature requirement yet); it is committed to by the block hash so a re-signed block is a different block.

---

## 4. Difficulty → target

```
target(d) = floor( (2^256 − 1) / d )
```

Computed by 256-step binary long division (see `u256.rs`); never by floating point.

A block satisfies its own PoW iff:

```
U256_BE( block_hash ) ≤ target(header.difficulty)
```

`difficulty = 1` ⇒ `target = 2^256 − 1` ⇒ every hash is valid. This is the genesis setting (Section 16: starting difficulty must be low so the network can start).

---

## 5. Hybrid PoW puzzle (Stage 1 hash → Stage 2 NN → Stage 3 hash)

Per Section 29: security rests on the hash stages; the NN stage guarantees GPU/AI hardware participation and is an auditable fraction of mining work.

### 5.1 Puzzle parameters (`puzzle_id = 1`, "hybrid-v1")

| Constant | Value |
|---|---|
| `hash_rounds` | `16` |
| `nn_input_dim` | `16` |
| `nn_hidden_dim` | `16` |
| `nn_layers` | `3` |
| `nn_epoch_blocks` | height interval after which NN weights rotate |
| `min_nn_share_bps` | `3000` (30%) |
| `max_nn_share_bps` | `5000` (50%) |

These live in the versioned **puzzle registry**. Supply, halving and base rules are immutable; only puzzle parameters are upgradeable (Section 19.3 item 3), and only via the governance timelock (`docs/roadmap.md`).

`hbm-v1` is registered in code as `puzzle_id = 2` (`PuzzleSpec::hbm_v1`) but
is **not** the active mining puzzle on any profile: every profile mines
`puzzle_id = 1`, and the chain rests on §5 alone (Decision 22). The HBM
scratchpad is the designed upgrade route for ASIC pressure, not a second live
puzzle.

### 5.2 Stage 1 — memory-hard-ish hash chain

```
v = SHA256( DOM_S1 ‖ serialize(header) ‖ U8LE(nonce) )
repeat hash_rounds times:
    v = SHA256( DOM_S1 ‖ v ‖ U8(r) )          // r = 0 .. hash_rounds-1
seed = v
```

`serialize(header)` already contains `nonce`, `extra_nonce`, `prev_hash`, `merkle_root`, `timestamp_ms`, `height` — so the seed is bound to the full block, and the `nonce` argument in stage 1 is redundant-but-intentional (it makes the hash input visually match stage 3).

### 5.3 Stage 2 — integer-only neural network

**Weight derivation** (no floats, no platform-dependent libs). Weights come from the epoch id, so no miner can precompute them before an epoch starts:

```
epoch_seed = SHA256( DOM_W ‖ U4LE(epoch_id) )
wstream(k) = SHA256( DOM_W ‖ epoch_seed ‖ U4LE(k) )        // 32 bytes

in_dim(l)  = 16 if l == 0 else 16                          // = nn_input_dim / nn_hidden_dim
weight(l,o,i) = let b = wstream(((l * nn_hidden_dim + o) * in_dim(l) + i))[0]
                let w = b as i32; if w > 127 { w -= 255 }; w     // ∈ [-128, 127]
bias(l,o)     = wstream(1_000_000 + l * nn_hidden_dim + o)[0] % 63   // ∈ [0, 62]
```

**Forward pass:**

```
x[j] = seed[j] as i32 − 128                for j in 0..nn_input_dim
activations = empty byte string
for l in 0 .. nn_layers:
    for o in 0 .. nn_hidden_dim:
        s = bias(l, o)
        for i in 0 .. in_dim(l):
            s += x[i] * weight(l, o, i)          // i64 accumulator
        z[o] = fold32(s)                          // wrap to i32
    activations ‖= U4LE(z[o]) for all o          // ALL layers, pre-activation
    for o in 0 .. nn_hidden_dim:
        x[o] = max(z[o] >> ACTIVATION_SHIFT, 0)   // arithmetic shift, then ReLU
```

```
fold32(v) = let u = (v mod 2^32) as u32
            if u ≥ 2^31 then u − 2^32 else u      // returned as i32
```

Accumulator bound: `|s| ≤ 16 × 128 × 128 + 62 = 262 206 < 2^63`, so `i64` cannot overflow on any conforming implementation.

`>> ACTIVATION_SHIFT` is an **arithmetic** shift right (sign-extending),
`ACTIVATION_SHIFT = 2`. ReLU is applied *after* the shift.

`ACTIVATION_SHIFT`, `fold32` and `PuzzleSpec::in_dim` are the portable kernel
surface (`srct-core::puzzle`): every compute backend — CPU, GPU, NPU, TPU,
photonic, domestic accelerators — implements exactly these primitives, so all
substrates compute bit-identical digests. The `srct-miner` differential tests
pin a reference backend against an independently written one
candidate-for-candidate; a new substrate joins by passing that test, never by
renegotiating the math.

**Activation digest** — every layer, pre-activation, so no layer can be skipped or approximated:

```
act_digest = SHA256( DOM_S2 ‖ activations )
```

### 5.4 Stage 3 — final hash

```
final = SHA256( DOM_S3 ‖ seed ‖ act_digest ‖ U8LE(nonce) ‖ U4LE(epoch_id) )
```

`final` depends on the header (through `seed`), so no precomputation table can be reused across blocks.

### 5.5 PoW validity

```
solve(header) = ( U256_BE(final) ≤ target(header.difficulty) )
```

That predicate is the whole validity rule, and it is also the conformance
rule for miner backends: a batched or device implementation (`srct-miner`
`ComputeBackend`, §19.2) is conformant iff it returns this predicate's answer
on every header — byte-identical `final`, never a tolerance.

### 5.6 NN share of work (Section 29.3 audit rule)

The protocol cannot measure wall-clock, so the `30–50%` rule is enforced as an auditable **cost model** on the puzzle parameters:

```
nn_macs    = nn_layers × nn_hidden_dim × nn_hidden_dim        (default 3×16×16 = 768)
hash_cost  = (1 + hash_rounds + 1) × 64                        (1 hash ≡ 64 int32 MACs)
nn_share_bps = round( 10000 × nn_macs / (nn_macs + hash_cost) )
```

A puzzle registry entry is **valid** iff `min_nn_share_bps ≤ nn_share_bps ≤ max_nn_share_bps`.
Defaults give `nn_share_bps = 4000` (40%). Rejected at genesis otherwise. This is a proxy, not a stopwatch — stated plainly in `docs/status.md`.

---

## 6. Difficulty adjustment (LWMA)

Per Sections 28.2 / 28.10: a proven algorithm (linearly weighted moving average, Zawy-style), not a bespoke one.

Parameters: `difficulty_window = 60`, `change_limit_bps = 1000` (±10% per block), `min_difficulty`, `max_difficulty`.

Let `T = target_block_time_ms` and let `tip[i]` be the `i`-th block back from the tip (`tip[0]` = tip). For `i = 0 … window-1`:

```
t_i = clamp( tip[i].timestamp_ms − tip[i+1].timestamp_ms,  T/4,  5T )
W   = Σ_{k=1..window} k²                     // = window(window+1)(2window+1)/6
S   = Σ_{i=0..window-1} (window − i)² · t_i  // newest solve time weighs most
avg = floor( S / W )                         // weighted mean solve time, ms
d_raw = floor( d_prev · T / avg )            // MULTIPLICATIVE — see below
```

**The retarget must be multiplicative.** `d_new = d_prev · T / avg_solve`, not `avg_solve / T`. The latter is scale-invariant: it returns a number that is a fixed point at *every* difficulty, so the rule has no restoring force and cannot correct a hashrate change in either direction. Worked example at `T` and `d_prev = 1`: hashrate halves, blocks arrive at `2T`, and `avg_solve / T` yields difficulty `2`, which stretches the interval to `4T` — the chain runs away from the target instead of toward it. Symmetrically, doubled hashrate yields `0.5`, clamps to `min_difficulty = 1`, and the chain sticks at the floor.

With the multiplicative form the same case yields `1 · T / 2T = 0.5`, and the block interval returns to `T`. Perfect spacing (`avg_solve = T`) is a fixed point at every difficulty, which is the property the test suite asserts directly.

Because every `t_i` is clamped to `[T/4, 5T]`, `avg ≥ T/4`, so one step multiplies difficulty by at most `4` down or `5` up, and the result is at most `5 · d_prev` — comfortably inside `u128`.

Clamps:

```
d = clamp(d_raw,  max(1, d_prev · (10000 − change_limit_bps) / 10000),
                 min(MAX_DIFFICULTY, max(d_prev · (10000 + change_limit_bps) / 10000,
                                         d_prev + 1)) )
d = clamp(d, min_difficulty, max_difficulty)
```

The upper bound admits at least `+1`, otherwise a chain starting at difficulty `1` could never bootstrap upwards.

While the chain is shorter than `window + 1`, the *available* window is used with the same weight formula. Pinning difficulty for the first hour of a new chain would hand that hour to whoever shows up first; this is standard Zawy ramp-up behaviour.

### 6.1 Timestamp rules

**Consensus (deterministic, no local clock):**

```
M = median( timestamp_ms of the previous 11 blocks, or fewer if height < 11 )
timestamp_ms ≥ M
```

**Node policy (non-consensus):**

```
timestamp_ms ≤ local_now_ms + future_limit_ms
```

There is deliberately **no** consensus upper bound. An upper bound needs a reference that advances with wall time, and the only such thing is the local clock — which would make block validity depend on machine skew, so two honest nodes could disagree about the same block. The ceiling is therefore policy, applied when a block enters the chain (`validate_local_clock`), and `future_limit_ms = target_block_time_ms` — one block time, not Bitcoin's two hours.

A node that skips the local-clock check can be talked into accepting a higher-difficulty branch; that is the same tradeoff Bitcoin accepts, only with a wider window. See `docs/status.md`.

`sim/difficulty_attack_sim.py` measures this rule. Under the protocol as specified, a 40% attacker cannot make blocks arrive faster than the target spacing at any allowance: the median rule anchors honest timestamps at real time (a minority is outvoted six-to-five in the median), and the solve-time clamp bounds any single retarget to `[0.25, 5]`. The attacker's future stamps instead surface as `5T` solve times on the honest→attacker transitions, which the LWMA weights heavily, so the attack *raises* difficulty and slows the network down for the attacker as well.

Design doc §28.9 reports that a two-hour allowance let a 40% attacker reach ~104s average block time. That is not reproducible under this specification, and cannot be: 104s is below the solve-time clamp floor (`T/4` = 150s), so no retarget can ask for a difficulty that low. Those figures come from a model without the solve-time clamp, without a difficulty floor, and with honest miners copying the tip instead of anchoring on the median. `--design-doc-model` in the simulation reproduces the mechanism; the short allowance is retained regardless, as defence in depth for the case where an attacker reaches 50% and can move the median itself.

---

## 7. Supply schedule

Per Section 16. `SAT_PER_SRCT = 100_000_000`.

| Parameter | Value |
|---|---|
| `halving_period` | `262 800` blocks (5 years at 10 min) |
| `start_reward` | `76 SRCT` = `7_600_000_000 sat` |
| `supply_cap` | **none** — Decision 18 (2026-10-09) replaced the stock cap with the rate anchor below |
| `tail_emission` | **approved + implemented** — mainnet `0.50`, `0.25`, `0.125` SRCT then the permanent `0.1` SRCT floor; `mini`/`testnet` a constant `1 sat`/block (Decisions M-A…M-C) |

```
halvings  = height / halving_period
rung(p)   = start_reward_srct >> p                         // whole-SRCT halving
reward(h) = rung(halvings) * SAT_PER_SRCT                  // while rung > 0
tail(p)   = max(tail_floor_sat, 1 SRCT >> (p − exhaustion_period + 1))
reward(h) = tail(halvings)                                // once rung == 0

// The ladder is halved in **whole SRCT**, not by shifting satoshis:
// `start_reward_sat >> halvings` would pay 9.5 SRCT at halving 3 and
// contradict the ladder below. Shifting whole SRCT keeps every rung a
// whole number of SRCT and keeps the issuance arithmetic exact.
// The tail is halved in **satoshis** and clamped by its floor.
```

Reward ladder: `76, 38, 19, 9, 4, 2, 1`, then the approved tail (Decisions
M-A…M-C, `docs/decisions.md`): mainnet `0.50, 0.25, 0.125` SRCT and the
permanent `0.1 SRCT` floor; mini/testnet a constant `1 sat` per block. The tail
activates at each profile's ladder exhaustion (mainnet `1 839 600`, mini and
testnet `14 000`) and leaves **every historical block byte-identical** — the
reward stays a pure function of height.

**Mint bound (hard, enforced in code):** live UTXO value may never exceed the
issuance integral at the height — `cumulative_issuance_sat(height)`.
`supply::check_mint_at_height` is the only mint gate and `Chain::apply_block`
calls it. Because the first rung is paid by `halving_period − 1` blocks
(genesis occupies a height without minting), the ladder era issues
`149 × 262 800 − 76 = 39 157 124 SRCT`. There is no stock cap any more
(Decision 18): with a tail, long-run issuance is unbounded by design, so the
bound is per-height, never a single total. `sim/supply_schedule_sim.py`
regenerates these numbers and `tests/vectors/supply_vectors.json` pins them.

**Rate anchor (hard, enforced in code):** after ladder exhaustion, gross
issuance inside the current `halving_period` window plus the next reward must
not exceed **1 % of the supply issued at the window's start** (Decision 18 §4.3
— ≤ 0.2 %/yr). The ladder era is grandfathered and bounded by its own rungs.
The approved tail sits ~3× under this ceiling, so it never binds in normal
operation; it exists to refuse a future schedule that would dilute far faster.
A consensus-visible violation is refused with `SupplyRateExceeded`, which also
names the period allowance, so the refusal is auditable.

**Net supply (reported, not a bound):** gross issuance minus everything usage
ever removed — the burned half plus the PSCB half of every block's base fee
(`Chain::burned_fees_total` + `Chain::pscb_reserve`, both rewound on reorg).
`status`, `GET /v1/conservation` and the `/metrics` gauges report it; it is
the dilution holders experience, while gross issuance is what the two bounds
above constrain.

If a block reward would cross either bound, the block is refused by consensus
(`SupplyRateExceeded`); the surplus is unrecoverable rather than burned out of
circulation.

---

## 8. Fees, burn and the PSCB split

Per Sections 28.1 / 24.3: EIP-1559-shaped base fee. No new supply is minted from fees, so usage can never inflate issuance past the mint bound.

```
fee_total(block)   = Σ fee(tx)
base_fee_total     = base_fee × gas_used(block)
tip_total          = fee_total − base_fee_total
coinbase.value     = block_reward(height) + tip_total
```

**The base-fee portion is split 50/50 (M1, §14).** Half is burned — removed
from the UTXO set and never reissued — and half accrues to the on-chain
Protocol Security & Compute Buffer reserve:

```
pscb_credit(block) = base_fee_total / 2        // floor
burned(block)      = base_fee_total − pscb     // == ceil(base_fee_total / 2)
coinbase.value     = block_reward(height) + tip_total
```

The odd satoshi goes to `burned`, not to the reserve: a burn is irrecoverable,
so conservative rounding on that side is the safe direction. Only the tip is
paid to the miner, as before.

`pscb_credit` is **reorg-correct**: it is credited per canonical block and
subtracted again when that block is rolled back, so the reserve always equals
the sum over the canonical chain. The burned half is tracked the same way
(`Chain::burned_fees_total`, rewound per rolled-back block); together the two
halves are the removal term net-supply reporting subtracts from gross
issuance. `verify_canonical_chain`
re-derives both by replay and fails if either diverges.

The PSCB leg subdivides, all integer-floored: 5% to the B-Saver floor (cap
10%) and 10% to the SRCT Treats backing (cap 20%), the remainder retained as
PSCB. Invariant: `burned + pscb_retained + bsaver + treat == base_fee_total`.
`Chain::treat_reserve` and `Chain::bsaver_reserve` are credited and rewound
per block exactly like PSCB and are likewise re-derived by
`verify_canonical_chain`. Redemption from the Treat reserve never mints: an
empty reserve refuses.

```
gas_per_tx  = 16 000 + 1 000 × input_count + 250 × output_count
gas_cap     = 2 000 000 per block

base_fee_next = base_fee + base_fee × (gas_used − gas_cap) / (gas_cap × 8)
               // clamped to [base_fee_min_sat, base_fee_max_sat] (profile: 100/50_000_000 on
               // mainnet, 10/1_000_000 on mini and testnet — SPEC.md §10)
               // when gas_used == gas_cap the fee rises by 1/512 per block
```

A transaction must pay `fee ≥ base_fee × gas_used(tx)`.

---

## 9. Consensus validation rules

### 9.1 Block

1. `header.height == prev.height + 1` (genesis exempt)
2. `header.prev_hash == block_hash(prev)`
3. `U256_BE(block_hash) ≤ target(header.difficulty)` — PoW valid
4. `header.difficulty == expected_difficulty(tip_history)` (§6)
5. `merkle_root == computed_merkle_root(txs)`
6. Timestamp rules (§6.1)
7. `puzzle_id` exists in the registry and is active at this height; `epoch_id == height / nn_epoch_blocks`
8. `gas_used ≤ gas_cap`
9. Every transaction passes §9.2
10. Size limits: `tx_count ≤ 5 000`, block bytes `≤ 4 000 000`

### 9.2 Transaction

1. `tx_type == 0` (standard) except index 0, which MUST be a coinbase; types
   `2`/`3`/`4` are the bonded-stake operations (§14.6 amendment); anything
   else is refused (`unknown tx_type`), never interpreted as standard
2. Coinbase: exactly 1 input with `prevout_hash == prev_hash`, `prevout_index == height`; exactly 1 output
3. Coinbase txid MUST NOT collide with any other txid in the block (BIP30-style defence)
4. No duplicate inputs within a transaction; no inputs already spent in the UTXO set
5. `Σ inputs ≥ Σ outputs + fee` (no inflation)
6. Every input's `signature` verifies against `msg_k` (§1.1) for the address owning the spent output
7. Coinbase outputs referencing the same address accumulate — a single miner cannot claim two matured rewards in one block
8. `coinbase.value ≤ block_reward(height) + tip_total` — miners may **not** over-claim
9. Standard tx: `lock_time` is enforced — a transaction with `lock_time > height` is refused, so a timelocked transaction cannot mine early
10. Bond (`2`): inputs share exactly one signer (the bonder); BLS key valid
     and not already bonded; exactly one output pays the derived bond identity
     `SHA256("srct/bond-identity/v1" ‖ network_id ‖ bonder ‖ bls_pk)[..20]`
     with value at or above `min_bond_sat` (0.01 SRCT mainnet; 0 on
     `mini`/`testnet` — an anti-dust floor, not a wealth gate: Solar Cyber Unit
     stays permissionless while 1-sat bonds cannot permanently occupy ledger
     entries on every node);
     that output is consumed into the bond ledger by
    the applying block (it never rests in the UTXO set, so a later release
    cannot double-count it)
11. Unbond (`3`): bond exists; single signer is the bonder;
    `height ≥ bond_height + 1008` (7 days at mainnet block time, fixed); the
    record is deleted and the full amount is recreated as a spendable output
    to the bonder
12. Slash (`4`): two checkpoints naming the same height with different hashes,
    both verifying against the current bond-derived committee with `RealBls`,
    sharing a signer; permissionless (any fee-paying inputs); the bond is
    deleted into the M2 vault (half burned at once, half vested to PSCB —
    an equivocator earns nothing back)

### 9.3 Maturity, finality

| Parameter | Meaning |
|---|---|
| `coinbase_maturity` | blocks before coinbase value is spendable |
| `finality_depth` | `h ≤ tip − finality_depth` is immutable; a reorg crossing it is rejected as `ReorgWouldCrossFinality` |
| `finality_activation_height` | height from which a valid canonical checkpoint certificate becomes binding finality on top of the depth rule (§14.8); `0` = never |
| `pq_activation_height` | height from which a bundle without an ML-DSA-65 component is refused when spending outputs created at or after it (§1, Decision 24); `0` = never. Age-gated, so outputs predating the height stay spendable under their original bundle — history is never stranded |

Mainnet: maturity `100`, finality `100`, activation `100`. Mini: `10`, `20`,
`0`. Testnet: `10`, `20`, activation `20` (§14.8).

---

## 10. Network profiles (Section 17: mini version = same code, different config)

The mini version is **not** a second codebase. It is the same `srct-core` with a different `NetworkParams`. Non-consensus constants live in code; consensus constants live in `params.rs` and are mirrored by `sim/` cross-checks.

| Parameter | `mainnet` | `mini` | `testnet` |
|---|---|---|---|
| `target_block_time_ms` | `600 000` | `1 000` | `1 000` |
| `halving_period` | `262 800` | `2 000` | `2 000` |
| `start_reward_srct` | `76` | `76` | `76` |
| `rate_anchor_pct` | `1 %` of issued per `halving_period` (all profiles) | | |
| `difficulty_window` | `60` | `60` | `60` |
| `change_limit_bps` | `1000` | `1000` | `1000` |
| `genesis_difficulty` | `1` | `1` | `1` |
| `min_difficulty` | `1` | `1` | `1` |
| `max_difficulty` | `2^96` | `2^40` | `2^40` |
| `coinbase_maturity` | `100` | `10` | `10` |
| `finality_depth` | `100` | `20` | `20` |
| `gas_cap` | `2 000 000` | `2 000 000` | `2 000 000` |
| `base_fee_initial_sat` | `1 000` | `100` | `100` |
| `base_fee_min_sat` | `100` | `10` | `10` |
| `base_fee_max_sat` | `50 000 000` | `1 000 000` | `1 000 000` |
| `nn_epoch_blocks` | `50 000` | `2 000` | `2 000` |
| `puzzle_id` | `1` | `1` | `1` |
| `network_id` | `srct/mainnet` | `srct/mini` | `srct/testnet` |
| `network_magic` | `6A 4E 54 02` | `6A 4E 54 03` | `6A 4E 54 04` |
| `checkpoint_interval_blocks` | `100` | `10` | `10` |
| `finality_activation_height` | `100` | `0` | `20` |
| `pq_activation_height` | `0` (**never**) | `0` | `0` |
| `genesis_validators` | `21` (bootstrap, quorum 15) | `4` (quorum 3) | `4` (quorum 3) |
| `l2_settlement_validators` | `0` (fails closed) | `4` (quorum 3) | `4` (quorum 3) |
| `exit_activation_height` | `1` | `1` | `1` |
| `l2_genesis_escrow_sat` | `100 000 SRCT` | `10 SRCT` | `10 SRCT` |
| `escrow_ceiling_sat` | `100 000 SRCT` | `10 SRCT` | `10 SRCT` |
| `min_bond_sat` | `0.01 SRCT` | `0` | `0` |
| `max_exit_window_sat` | `1 000 SRCT` | `0` (disabled) | `0` (disabled) |
| `exit_window_blocks` | `144` | `0` | `0` |
| `max_exit_per_owner_window_sat` | `100 SRCT` | `0` (disabled) | `0` (disabled) |
| `large_exit_threshold_sat` | `100 SRCT` | `0` (disabled) | `0` (disabled) |
| `large_exit_extra_delay_blocks` | `144` | `0` | `0` |

`testnet` shares the mini ladder and block schedule but has its own magic/id,
its own deterministic committee (distinct derivation), and the §14.8
activation height. `mainnet` carries a 21-key public deterministic bootstrap
committee (Decision 27) so binding finality can activate at height 100 on a
fresh chain; the first bond replaces it under the TopN rule. Mainnet's separate
`l2_settlement_validators` set is empty, so L2 settlements stay fail-closed. No
profile carries a stock supply cap (Decision 18).

**`exit_activation_height` gates the whole exit rule of §19.6, and `0` means
*never*, not *from genesis*.** A profile on `0` accepts neither a committed
`l2_state_root` nor an exit claim, and an L2-bearing block on it must therefore
carry no root. All three shipped profiles activate at height `1`, so deposits
and exits are open from genesis on every profile: the rule is compiled,
tested and live, and a profile that wants it closed sets `0`.

**Exit throttle (mainnet only).** The deposit sink is a honeypot: at most
`max_exit_window_sat` of exit principal may queue per `exit_window_blocks`
(1 000 SRCT per 144 blocks), no more than `max_exit_per_owner_window_sat`
of it from any one owner (100 SRCT — the fairness bound, so one filler
cannot starve every other owner until rollover), and exits at or above
`large_exit_threshold_sat` wait `large_exit_extra_delay_blocks` on top of
base maturity (100 SRCT → +144 blocks). Over-cap queues are refused with the
retry height named (`ExitWindowFull`, or `ExitOwnerWindowFull` for a full
owner share); funds stay put and the owner retries in the next window —
a delay, never a taking. The throttle is enforced at the L2 queue, which is
the only gate windows have: every L1 release must prove a queued record
against a committed root, so capping queues caps the drain rate with no
second check needed. `mini`/`testnet` carry `0` for all five (disabled) so
tests exercise the bare rules.

---

## 11. Genesis block

```
header.version      = 1
header.height       = 0
header.prev_hash    = 64 zero bytes
header.merkle_root  = merkle_root([coinbase])
header.timestamp_ms = 0
header.difficulty   = params.genesis_difficulty        // 1 ⇒ any hash valid
header.nonce        = 0
header.puzzle_id    = 1
header.epoch_id     = 0
header.extra_nonce  = "srct-genesis" padded to 16 bytes
header.sig_scheme   = 1
coinbase            = version 1, tx_type 1, lock_time 0,
                      input { prev_hash = 64 zeros, index = 0, sig = 64 zeros, pubkey = 33 zeros },
                      output { value = 0, address = 20 zero bytes }
```

The genesis block is **not** a premine: it contains zero value and no spendable output (Section 16 — 0% founder premine is enforced in code, not just in prose).

---

## 12. Test vectors

`tests/vectors/*.json` are consumed by the Rust test suite. A language implementation is correct only if it reproduces them byte for byte.

| File | Covers | Generated by | Consumed by |
|---|---|---|---|
| `puzzle_vectors.json` | header serialization, stage 1 seed, stage 2 activation digest, stage 3 final, work-share accounting | `UPDATE_PUZZLE_VECTORS=1 cargo test -p srct-core` | `puzzle_vectors_are_stable`, `sim/puzzle_crosscheck.py` |
| `ser_vectors.json` | input / output / tx / header byte layouts | `UPDATE_SER_VECTORS=1 cargo test -p srct-core` | `serialization_vectors_are_stable` |
| `supply_vectors.json` | reward ladder, cumulative issuance integral, rate-anchor allowance | `sim/supply_schedule_sim.py` | `a_supply_vector_file_exists_to_show_the_pattern`, `sim/verify_vectors.py` |
| `difficulty_vectors.json` | LWMA next-difficulty, timestamp clamp behaviour | `UPDATE_DIFFICULTY_VECTORS=1 cargo test -p srct-core` | `difficulty_vectors_are_stable` |
| `net_vectors.json` | frame envelope, every `msg_type` payload, `VERSION` layout, locator construction (§13.12) | `UPDATE_NET_VECTORS=1 cargo test -p srct-net` | `net_vectors_are_stable` |

`sim/puzzle_crosscheck.py` is the important one: it re-derives every puzzle digest with `sim/srct_reference.py`, a second implementation written from the prose of this document rather than from the Rust source. If the two disagree, the disagreement is in the spec, not in either implementation.

Regenerate and verify everything with `python sim/verify_vectors.py` (`--check` to verify without writing).

---

## 13. Peer-to-peer layer (v0.2)

**Status: implemented in `srct-net`, with the two §13.10 MUSTs (incremental
cumulative work, side-branch pruning) and the §13.8 resource bounds in place.**
This section is normative for the network layer and describes what `srct-net`
MUST do. It was written before the code, per the same discipline as §5: where
the wire format is ambiguous, every implementation will disagree and the
disagreement will look like a consensus split.

### 13.0 What this section is, and is not

The P2P layer **relays data; it never decides anything.** Every rule that
determines whether a block is valid lives in §9 and is unchanged by anything here.
A node that receives a block MUST run the same `validate_standalone` +
`submit` path it runs for a block it mined itself. There is no "trusted peer"
fast path, no relaxed validation for relayed data, and no way for a peer to
influence a consensus decision.

Blocks relay as before; transactions relay per §13.14 and the mempool selects
them into blocks. External mining templates served over the §19.2 endpoints
are coinbase-only in v1 (pool transaction inclusion is the next step, not this
route), so relay and mining stay orthogonal: gossip moves data, templates move
work.

### 13.1 Design constraints inherited from §9

Three properties of the base layer constrain the network layer, and each one
rules out an otherwise reasonable design:

**Fork choice is deterministic (§9, `chain.rs`).** Selection depends only on the
block graph. This is *why* the P2P layer needs no consensus changes: nodes may
receive blocks in any order and still agree. It also means a peer cannot cause a
split by withholding or reordering data.

**Validation needs chain state.** `submit` checks difficulty against tip history
and reorgs against undo records, so a block cannot be validated in isolation and
then stored. Validation and application are one operation, and the network layer
MUST NOT split them.

**`Chain` is single-owner.** `submit`, `adopt`, `mine_block` and
`build_template_with` all take `&mut self`. The network layer therefore MUST NOT
hold `Arc<Mutex<Chain>>`: template construction and submission mutate the tip,
and a lock held across them would stall every peer thread. Instead
there is one **chain thread** owning the `Chain`, and peer threads exchange
messages with it over channels. The chain thread is the only writer. (The
unbounded solving loop lives outside it, in `srct-miner` or any pool speaking
the §19.2 mining endpoints.)

```
peer threads (N)                   chain thread (1)
  read socket                        own the Chain (sole writer)
  frame/deframe                      loop:
  validate framing bounds              - drain inbound channel -> submit() -> canon/utxo
  hand off Message ----------------->  - build template on request
  <--------------- outbound           - submit(winner) -> canon/utxo
                                       - fan out resulting INV to peers
```

Mining runs **beside** the chain thread, not on it. `Chain::build_template_with`
builds an unsolved block against the current tip — everything fixed except
`nonce`/`extra_nonce`, which both commit into the proof through the serialized
header — and an external miner (`srct-miner`, or any pool speaking the §19.2
mining endpoints) grinds the template and hands the solved block to `submit`,
which re-validates everything including the proof. The template path and the
in-process `mine_block` path share the same header construction, so a template
can never commit to a different block than the node would mine itself. Mining
against a stale tip is harmless: `submit` enforces the tip, the difficulty and
the timestamp rules, so a stale solution is refused, never half-applied.

### 13.2 Transport and framing

TCP. Every message is a length-prefixed frame:

```
frame = magic(4) ‖ msg_type(1) ‖ payload_len(4 LE) ‖ payload(payload_len)
```

- `magic` MUST be the 4-byte network magic (§13.3). It is re-checked on **every**
  frame, not only at connect, so a peer cannot hand a valid handshake then switch
  to garbage.
- `payload_len` MUST be `≤ max_frame_bytes` (§13.8) **checked before any
  allocation.** The length prefix is attacker-controlled; this is the same class of
  bug as the bundle-length and input-count issues already fixed in §3.1/§3.5, and
  it is the single most important bound in this section.
- A frame larger than the cap MUST close the connection, not be skipped. There is
  no resynchronisation point in a stream protocol, so skipping leaves the peer
  desynchronised and able to confuse every later message.

Framing is deliberately **not** domain-tagged or hashed. It is transport, not
consensus: a frame is never hashed, never committed to by a block, and never
compared across implementations. `DOM_NET_HANDSHAKE` (§0) exists for the one
place where a hash *is* needed — the handshake challenge (§13.4).

### 13.3 Network identity

**The genesis hash does NOT identify the network.** `genesis_block(difficulty)`
(`block.rs`) derives the genesis block from difficulty alone, and both profiles
set `genesis_difficulty = 1`, so `mainnet` and `mini` produce the **identical**
genesis block:

```
ccc9db9181e91c52bc4f9d7639a00add3f6b8c5a214a8d2319fdfcabe6276953
f1c392ea9aa6b308a357d360b49a2167893254f6ac85745818cd0a2299fa1a5a
```

A handshake that compared genesis hashes would consider a mainnet node and a mini
node the same network and would relay `mainnet` blocks into a `mini` chain. Every
block would then fail §9.1 rule 4 (wrong difficulty), so no state corruption
would occur — but the node would waste bandwidth and, worse, could not be trusted
to reject a cross-network peer at all. Discrimination MUST use an explicit
parameter instead.

Each profile therefore declares a `network_magic` and a `network_id` string.
`mainnet` and `mini` MUST differ in both.

| Parameter | `mainnet` | `mini` |
|---|---|---|
| `network_magic` | `0x6A 0x4E 0x54 0x02` | `0x6A 0x4E 0x54 0x03` |
| `network_id` | `srct/mainnet` | `srct/mini` |

A new profile MUST pick a magic no existing profile uses. Magic reuse across two
live networks is the failure this rule exists to prevent.

The protocol version bump moved mainnet from `6A 4E 54 01` to `6A 4E 54 02`;
`mini` and `testnet` moved to `6A 4E 54 03` and `6A 4E 54 04` so every live
profile still owns exactly one magic. A pre-bump node presents `01`, which does
not match the mainnet profile, so it is refused at framing and again at the
handshake. It cannot join or relay blocks into the new mainnet.

**Long-term fix, not in v0.2:** give the genesis coinbase an `extra_nonce`
derived from `network_id`, which would make the genesis hash discriminating and
let the handshake compare hashes as Bitcoin does. That is a **consensus-breaking
change to the genesis block** and therefore out of scope for a networking release.
It is recorded here so the option is not lost.

### 13.4 Handshake

The first frame on every connection MUST be `VERSION`; anything else closes the
connection.

| Field | Size | Notes |
|---|---|---|
| `network_magic` | 4 | §13.3 |
| `network_id` | `1 + n` | length-prefixed string |
| `protocol_version` | 4 LE | `1` in v0.2 |
| `services` | 8 LE | bit 0 = serves blocks; v0.2 all nodes set it |
| `height` | 8 LE | best height, `0` if at genesis |
| `tip_hash` | 64 raw | tip block hash (512-bit identity) |
| `user_agent` | `1 + n` | length-prefixed, `≤ 64` bytes |
| `nonce` | 8 LE | see below |

A responder MUST reject the connection if `network_magic` or `network_id` does
not match its own, if `protocol_version` is greater than it supports, or if
`height == 0` while `tip_hash` is not the genesis hash (an inconsistent claim,
and free to reject before doing any work).

`nonce` makes the handshake **proof of possession of the socket** and nothing
more. The responder echoes the initiator's nonce in `VERACK`; the initiator
requires the echo. This defeats a trivially replayed handshake, which is worth
having on an unauthenticated transport. It is **not** peer identity: there is no
node key, no certificate, and no authentication in v0.2. A node MUST NOT treat a
successful handshake as evidence of anything beyond "something answered on the
other end of this socket". Peer reputation is therefore per-connection and
lost on reconnect — an acknowledged v0.2 limitation, not a design choice.

Both directions send `VERSION`; both then send `VERACK`. A node MUST NOT relay
anything before its own handshake completes.

### 13.5 Messages

`msg_type` values in v0.2. Values are frozen; unknown types MUST be ignored
without disconnecting, so a later version can add messages safely.

| Type | Name | Payload |
|---:|---|---|
| `1` | `VERSION` | §13.4 |
| `2` | `VERACK` | echoed `nonce` (8) |
| `3` | `PING` | `nonce` (8) |
| `4` | `PONG` | `nonce` (8) |
| `5` | `INV` | `count(2 LE) ‖ count × (kind(1) ‖ hash(64))` |
| `6` | `GETDATA` | same shape as `INV` |
| `7` | `BLOCK` | `serialize(block)` (§3.5) |
| `8` | `GETBLOCKS` | `count(2 LE) ‖ locator(count × 64) ‖ stop_hash(64)` |
| `9` | `ADDR` | `count(2 LE) ‖ count × (port(2 LE) ‖ ip(16))` |
| `10` | `TX` | `serialize(transaction)` (§3.6) |
| `11` | `CHECKPOINT` | `payload_len(4 LE) ‖ payload ‖ aggregate_sig(96) ‖ bitmap_len(4 LE) ‖ bitmap ‖ signer_count(4 LE)` |

`kind` is `1` = block and `0` = transaction (§13.14). Transactions were reserved
here before they existed, precisely so the *announcement* could be added without
changing `INV`/`GETDATA`'s shape; only delivery needed a new message type.

`msg_type = 10` was added in v0.3. It is additive by construction: the freeze rule
above already requires an unknown type to be ignored without disconnecting, so a
v0.2 node drops `TX` and stays connected. Such a node does not relay transactions,
which is a peer's choice and not a protocol violation.

`msg_type = 11` was added in v0.4 (Decision 11, §14). It is additive under the
same rule: a node that predates it drops `CHECKPOINT` and stays connected. It
carries a complete checkpoint certificate, never a proposal or a vote — no BFT
round protocol exists in M4 to give those meaning. A receiver verifies the
certificate against its own local committee and relays it if valid; it then
applies it through the chain's finality layer (§14.8), which either records an
observation (profiles without activation) or, on an activated profile, moves
binding finality — the relay rule itself is unchanged: a bad or conflicting
certificate is not relayed. The payload is `CheckpointPayload.serialize()` (§14.5), and
every length field is bounded (`MAX_CHECKPOINT_PAYLOAD_BYTES`,
`MAX_SIGNER_BITMAP_BYTES`) before allocation, per the rule below.

Every `count` field MUST be bounded by the smallest entry that could follow,
checked before allocating — `INV` entries are 65 bytes, `ADDR` entries 18,
`GETBLOCKS` locators 64. Bounding by remaining bytes alone is the defect already
fixed in §3; the same bound applies here.

`count` MUST additionally be capped at `max_inv_per_msg` (§13.8).

**`ADDR` carries a 16-byte address, not 4.** IPv6-mapped IPv4 is the
representation, matching Bitcoin's historical choice. v0.2 listens on IPv4 only
and treats any address it cannot parse as a protocol violation rather than
guessing at a conversion.

### 13.6 Peer discovery

v0.2 has **no discovery protocol.** There is no `ADDR` gossip, no DNS seed, no
super-nodes. A node's peer set comes from its configured address book only.

This is a real limitation and the reason is worth stating: peer discovery needs a
sybil-resistance story that this protocol has not made yet. Gossiping addresses
from peers we cannot authenticate means one hostile node hands us its own
connections forever. That is acceptable for a small, operator-run network and is
not acceptable for an open one, so v0.2 does the former. `ADDR` is specced in §13.5
so the message exists, but a node MUST NOT populate its address book from it in
v0.2.

### 13.7 Relay and sync

**Relay (steady state).** On accepting a block that extends or reorgs the tip, a
node MUST `INV` it to every connected peer **except the one it came from**. On
receiving an `INV` for an unknown block, a node MUST send `GETDATA` for it.

**Invasion prevention.** A node MUST NOT relay a block it has not validated. This
is the rule that stops a cheap-PoW attacker (`difficulty = 1` on `mini` makes PoW
free) from using honest nodes as a bandwidth amplifier: an invalid block is
dropped at `submit` and never announced.

**Sync (initial).** Block-first, not headers-first. The requester sends `GETBLOCKS`
with a locator:

```
locator[0]      = tip_hash
locator[i]      = block_hash_at(height − 10ⁱ),   i = 1, 2, 3, …
locator         = capped at 500 entries; append genesis hash if absent
```

The responder walks its canonical chain back to the **first** locator hash it
recognises and `INV`s up to 500 hashes after it. The requester then `GETDATA`s
them in batches of 16, submits each, and repeats.

Headers-first would be faster and is what a mature node does, but it is
unnecessary here: a block's validity depends on tip history and undo records
(§13.1), so a header chain that cannot be applied buys nothing for a node that
must validate every block anyway. Recorded as a future optimisation.

**The requester MUST tolerate gaps.** A `BLOCK` whose parent is unknown MUST be
retained in a bounded orphan pool and re-offered when its parent arrives, not
discarded. `submit` returns `UnknownParent`, which is a normal outcome of racing
a peer's relay, not an error.

**The requester MUST NOT trust the responder's height.** A peer claiming height
`10⁹` is making the requester queue work it will never finish; the batch size
stays 16 and the requester advances only on blocks it has actually applied.

### 13.8 Resource bounds

Every bound here is attacker-controlled unless noted. A node that omits one has a
remotely triggerable failure, so these are requirements, not tuning.

| Bound | Value | Protects |
|---|---|---|
| `max_frame_bytes` | `4 100 000` | one `max_block_bytes` block + envelope |
| `max_inv_per_msg` | `500` | 500 × 65 = 32.5 KB per `INV` |
| `max_addr_per_msg` | `100` | 100 × 18 = 1.8 KB per `ADDR` |
| `max_locator_len` | `500` | 500 × 64 = 32 KB per `GETBLOCKS` |
| `max_peers` | `125` | thread count, fd count |
| `max_inbound` | `32` | inbound connection flood |
| `handshake_timeout` | `20 s` | half-open connection exhaustion |
| `ban_score_threshold` | `100` | misbehaviour (below) |
| `orphan_pool_max` | `64` | memory from parentless blocks |
| `max_relay_in_flight` | `128` | outstanding transaction requests (§13.14) |
| `max_relay_pending` | `1 024` | advertised-but-unrequested txids (32 KB) |
| `max_relay_known` | `4 096` | relay-loop suppression set (128 KB) |
| `max_tx_inv_batch` | `64` | txids requested per `GETDATA` |
| `tx_relay_per_peer_per_min` | `600` | transaction flood from one peer |
| `tx_request_timeout` | `30 s` | an unanswered transaction request is forgotten (§13.14) |

`max_frame_bytes` is `max_block_bytes + 100 000`, so a maximum-size block is
relayable with room for its envelope. `max_inbound < max_peers` because inbound
connections are the ones an attacker chooses; outbound are ours.

A peer exceeding any inbound bound is **banned** (§13.9), not merely
disconnected. `max_peers` alone is not a defence: an attacker who fills it stops
honest nodes connecting, which is why inbound is capped lower and why exceeding
inbound limits scores rather than merely closing.

### 13.9 Misbehaviour and bans

Each peer connection carries a ban score, starting at `0`, reset on reconnect.
Reaching `100` bans the address. Scores decay by `1` per hour.

| Misbehaviour | Score |
|---|---:|
| Frame over `max_frame_bytes` | `+100` (immediate ban) |
| Bad `magic` after handshake | `+100` (immediate ban) |
| Wrong `network_id` / `network_magic` | `+10`, disconnect |
| Oversized declared `count` in any message | `+20` |
| First frame not `VERSION` | `+20` |
| `BLOCK` failing §9 validation | `+10` |
| `BLOCK` whose parent is unknown, repeated | `+5` |
| Unresponsive to `PING` (60 s) | `+10` |
| `ADDR` ignored in v0.2, still sent | `+10` |
| `TX` failing deserialisation or `check_tx` | `+10` |

**A block failing validation is +10, not a ban.** Difficulty and PoW failures are
normal on a chain under hashrate churn, and an honest peer relaying a block during
a reorg race can easily send one the receiver has already applied differently. A
node that bans on this would disconnect honest peers precisely when the network is
busiest. Reaching a threshold of *repeated* invalid blocks is what bans.

**Invalid blocks MUST NOT enter the block store.** `submit_at` already drops a
block that cannot be applied (§9.1), and that behaviour is load-bearing here: a
stored block contributes its declared difficulty to `cumulative_work`, so retaining
an unusable one lets a peer accumulate fork-choice weight no reorganisation can
realise. `ReorgWouldCrossFinality` is the deliberate exception — the block is
valid, and dropping it would orphan its descendants.

### 13.10 Performance requirements

These are consensus-adjacent. A single node never hits them; a node accepting
relayed blocks does, and a peer can trigger them deliberately. **v0.2 MUST NOT ship
without the two marked items.**

**`cumulative_work` is O(chain length) and `best_candidate` calls it per stored
block** (`chain.rs`). One `submit` is therefore O(stored²), and side branches are
retained forever, so the cost only grows. A peer submitting blocks turns this into
a quadratic amplifier — the cheapest possible way to burn a node's CPU.

1. **MUST (blocking), implemented:** maintain cumulative work incrementally per
   stored block, computed once at insert as `parent_work + difficulty`. Fork
   choice becomes O(stored) to scan and O(1) per block to score. This changes no
   consensus outcome: the value is identical, since it is a sum along the same
   path.
2. **MUST (blocking), implemented:** prune side branches. Canonical history is
   retained in full — undo records, `verify_canonical_chain` and persistence all
   replay from genesis. Every **non-canonical** block at or below
   `tip − finality_depth` is dropped, together with any stored descendant of a
   dropped block (a block whose parent is gone cannot be walked to). Pruning runs
   when the store exceeds `canon_len + 4 × finality_depth`.

   This also settles a behaviour the rule was previously ambiguous about: a valid
   branch that forks *below* the finality point used to be retained with its work
   counted, so fork choice kept selecting it and the node refused honest blocks
   until honest work caught up. Such a branch is now forgotten, and honest blocks
   are accepted again. **§9.3 is unchanged** — a reorg whose fork point is at or
   below the finality height is still refused with `ReorgWouldCrossFinality`. What
   changes is only how long the node keeps a branch it was never going to follow.
3. **SHOULD:** `adopt()` snapshots the whole UTXO set per reorg — O(chain length).
   The incremental undo primitives already exist (`ledger.rs`), so a reorg should
   unwind block by block. Not a DoS vector on its own: a reorg crossing
   `finality_depth` is refused outright (§9.3), which bounds how often this runs.
4. ~~**SHOULD:** persist blocks append-only rather than rewriting the whole chain
   file per block.~~ **Resolved (v0.3).** `crates/srct-store` is an append-only,
   checksummed record log with atomically-replaced metadata; the node appends
   O(new blocks) per mined block and rebuilds its index by scanning at open.
   See the crate documentation for the crash semantics (torn tails are
   truncated and reported; damage to committed data refuses to open).

### 13.11 Invariants a node MUST preserve

The point of this section, and the tests that must assert them:

1. **Relay cannot change validity.** A block accepted via P2P MUST equal, byte for
   byte, the block accepted via `submit` locally. Tested by running the same block
   through both paths and comparing resulting state.
2. **Two nodes converge regardless of delivery order.** Node A and node B fed the
   same blocks in opposite orders MUST reach the same tip. This is the property
   §13.1 exists to protect; it is already tested for direct submission
   (`fork_choice_is_independent_of_block_arrival_order`) and MUST be extended to
   the P2P path.
3. **A node that has processed no blocks MUST equal a node that processed nothing.**
   A fresh node receiving a genesis-only `VERSION` MUST stay at genesis.
4. **Cross-network isolation.** A `mini` node MUST refuse a `mainnet` connection at
   handshake and MUST NOT relay a single block.
5. **Invalid blocks never enter the store.** After any sequence of invalid `BLOCK`
   messages, the block store and `cumulative_work` MUST be unchanged.
6. **No unbounded growth from hostile input.** A peer sending maximum-size frames,
   maximum `count` fields and orphan blocks MUST NOT grow any bounded structure
   past §13.8.
7. **Handshake is not authentication.** No code path may treat a completed
   handshake as authorisation for anything.

### 13.12 Test vectors

`net_vectors.json` covers the wire format, pinned the same way as the other
vector files (§12): generated from source, never hand-edited, and a second
implementation that disagrees has a bug, not a rounding difference.

| Covers | Note |
|---|---|
| Frame encode/decode round-trip at `max_frame_bytes` | the boundary that matters |
| Frame decode rejects `payload_len > max_frame_bytes` | must not allocate |
| Every `msg_type` payload round-trip | frozen values from §13.5 |
| `VERSION` field layout, all profiles | both networks |
| Locator construction from a 1 000-block chain | exponential spacing, 500 cap |
| `GETBLOCKS` response against 3 divergent chains | responder walk-back |

### 13.13 Unresolved, deliberately

Listed so these are decisions rather than oversights:

- **Peer identity.** No node keys. Reputation is per-connection (§13.4).
- **Discovery.** Address book only (§13.6). Sybil resistance unaddressed.
- ~~**Transaction relay.**~~ **Resolved in §13.14 (v0.3).** It was left unspecced
  on purpose — "better specified from a real implementation than guessed at now" —
  and the implementation is what settled the shape: the `kind = 0` reservation in
  §13.5 turned out to be sufficient for the announcement, so only delivery needed
  a new message type. Conflict sets, re-validation after reorg and fee ordering
  came from the mempool, not from the wire.
- **Headers-first sync.** Deferred with justification (§13.7).
- **Compact blocks / BIP-152.** Later; the 500-hash `INV` path is adequate first.
- **Genesis network discrimination.** Needs a consensus-breaking genesis change
  (§13.3); `network_magic` is the v0.2 workaround.

### 13.14 Transaction relay

**Transaction relay does not change consensus, and no rule here can.** A
transaction arriving over the wire is admitted by the same `check_tx` against the
same state as one built locally — §13.11 invariant 1 extended from blocks to
transactions. Nothing in this section may reach `Chain::submit`: a relayed
transaction becomes consensus-relevant only if a block containing it is mined or
received, and that block is validated exactly as §13.7 requires. The mempool is
not consensus state, so a peer cannot use this section to make an invalid
transaction valid.

**Announcement and request reuse the existing messages.** `INV` and `GETDATA`
carry `kind = 0` entries naming transaction ids, with the payload shape unchanged.
Delivery uses `TX` (§13.5).

**Flow.**

1. On a locally accepted transaction, announce its txid to every peer except the
   one it arrived from.
2. On `INV` with `kind = 0`, request the txids not already held or already
   requested, batched into `GETDATA` at `max_tx_inv_batch` per message.
3. On `GETDATA` with `kind = 0`, answer with the transactions the node's own pool
   holds, and answer nothing for the rest. A node is not obliged to serve a
   transaction it does not have, and serving one from anywhere but the pool would
   mean relaying something the node never validated.
4. On `TX`, deserialise, validate, admit to the pool; if admission succeeded and
   the transaction was not already known, announce it onward to the other peers.

**A peer may not make the node do unbounded work.**

- The relay request set is capped at `max_relay_in_flight`; the
  advertised-but-unrequested queue at `max_relay_pending` (§13.8).
- **An unanswered request is forgotten after `tx_request_timeout`.** A cap alone is
  not enough, because the request set is global rather than per-peer and the cap
  bounds how many requests can be held, not how long. Without a deadline a peer
  could announce `max_relay_in_flight` transactions, deliver none, and stop the
  node requesting transactions from *every* peer for as long as it stayed
  connected — and the withheld txids would be marked as already requested, so a
   peer that did hold them would be ignored too. Sixty-four bytes per announcement
   would buy a permanent, node-wide relay stall. Expiry bounds the worst case to a
  delay, and a request that expires is retried against whoever announces the txid
  next; the txid is never blacklisted.
- The set of txids remembered for relay-loop suppression is capped at
  `max_relay_known`, evicting oldest-first. **Eviction weakens suppression rather
  than breaking it:** a re-announced old transaction is requested at most once
  more, and every path that makes a node *do* work is separately bounded, so the
  worst case is a bounded amount of repeated work rather than growth.
- Per-peer transaction throughput is limited to `tx_relay_per_peer_per_min`.
  Exceeding it scores the peer, and the §13.8 rule applies: exceeding an inbound
  bound bans rather than merely disconnecting.
- A `TX` payload over `max_frame_bytes` is rejected by the frame layer before any
  allocation (§13.2 item 1), so no separate transaction size limit exists. There
  deliberately is not one: a relay cap tighter than `max_block_bytes` could make a
  transaction that consensus accepts permanently unrelayable, which is
  censorship. A transaction larger than a whole block is refused by the pool
  instead, where the reason is checkable against `max_block_bytes`.
- A transaction already present in the pool or already announced is not requested
  and not relayed again.

**Invalid transactions are misbehaviour, not noise.** A `TX` that fails
deserialisation or `check_tx` is charged `+10` (§13.9) and is never relayed
onward. **A node MUST NOT relay a transaction it did not itself admit** — that is
what stops a peer from using a node as an amplifier for data the node knows to be
invalid.

**Reorg re-admission is local.** A transaction the canonical chain un-confirmed is
re-admitted to the pool (§13.10) and, once re-admitted, announced like any other.
There is no wire message for un-confirmation: a peer that applied the same reorg
draws the same conclusion from the same blocks.

---

## 14. Protocol mechanisms (M1–M5)

These are the mechanisms the design calls for by name. The table below is the
authoritative statement of which are **consensus-active today** — meaning a
node's validation or state machine depends on them — and which are defined
data structures with no effect on consensus yet. The distinction is stated here
because the alternative, a document that lists all five as shipped, hides the
most important fact about them: **only M1 can change what an L1 node accepts.**
M5's binding finality is an exception worth naming precisely: on a profile with
`finality_activation_height > 0` (today `testnet`), a checkpoint that
`validators.rs` accepts does move `finalized_height`, and therefore does change
which reorgs `adopt()` refuses. That is the §14.8 activation, not a different
model.

| # | Mechanism | Module | Consensus-active | § |
|---|---|---|---|---|
| M1 | 50/50 PSCB base-fee split | `fees.rs`, `chain.rs` | **Yes** — changes the UTXO set and therefore supply accounting | §8 |
| M2 | Anti-collusion slash vault (50% burn + 50% linear vesting) | `slash.rs` | No — defined and tested, nothing creates a slash record yet | this section |
| M3 | Hardware-agnostic compute IR + attestation envelope | `compute_ir.rs` | No — serialization and signing hashes only | this section |
| M4 | Memory-bound HBM scratchpad PoW | `hbm_pow.rs` | No — registered in code as `puzzle_id = 2` (`PuzzleSpec::hbm_v1`) but not the active mining puzzle on any profile; the chain rests on the §5 puzzle (Decision 22) | this section |
| M5 | BLS12-381 aggregate finality gadget | `bls_checkpoint.rs`, `finality.rs` | **Conditional** — pairing-checked since §14.5; binding only on profiles with a non-zero `finality_activation_height` (Decision 12): active on `testnet` at 20 and on `mainnet` at 100 with its 21-key bootstrap committee (Decision 27), observation-only on `mini` | §14.5–§14.8 |

**Why M2–M4 are not wired in.** Each needs a rule that no spec currently
states: what evidence proves a compute result fraudulent (M2), who is allowed to
submit a compute task and how a result enters a block (M3), whether the HBM
puzzle replaces or composes with the §5 puzzle and how difficulty maps onto it
(M4). M2 and M4 in particular would change consensus: a slash moves coins and an HBM stage
changes what counts as valid work. Guessing those rules in code rather than in
this document would have been the wrong order, so the modules exist, are tested
against their stated invariants, and are documented as inactive.

**M5's missing rules arrived as Decisions 11 and 12, and the stake half later
as Decision 20.** Decision 11 (§14.7) named the committee — an explicit genesis
list of BLS keys — and the relay message; Decision 12 (§14.8) named the
activation condition under which a checkpoint stops being an observation and
starts being finality. Decision 20 then replaced the declared genesis list with
a bond-ledger-derived, stake-weighted committee (§14.6, §14.7): bonds, a bond
ledger, unbonding and equivocation slashing are all live. Rotation and rewards
are not.

### 14.1 M2 — Anti-collusion slash vault

On a proven-fraudulent compute result, a validator's stake splits:

```
burned     = stake / 2                        // destroyed, never reissued
vest_total = stake − burned                   // == ceil(stake / 2)
unlock     = slash_height + vesting_period
```

`vest_total` pays back to the *original* validator, `ceil(vest_total /
vesting_period)` per block. Two properties are enforced: the split is exact
(`burned + vest_total == stake`, no satoshi created or lost), and the final block
releases the remainder, so total vested over the period equals `vest_total`
exactly. Exhausted records are pruned, so the vault is bounded.

Mainnet `vesting_period` = 52 560 blocks (365 days at 10-minute blocks); the
mini profile uses 2 000.

The burn is the part that carries the security argument: a colluding validator
who slashes *themselves* recovers only the vesting half, and only by continuing
honest work for a year.

### 14.2 M3 — Compute IR and attestation

A `ComputeTask` commits, under domain tag `0xC0`, to `task_id`, `worker_address`,
`hardware_target`, `quantization_mode`, `input_hash`, `flop_count` and
`deadline_block`. A `ComputeAttestation` commits under `0xC1` to that task hash
plus a `result_hash`. Hardware targets (`Cuda`, `Rocm`, `Ane`, `Tpu`,
`Photonic`, `Generic`) and quantization modes (`Int8`, `Fp16`, `Fp32`,
`BFloat16`) are enumerated with explicit discriminants, so a future target is a
new variant rather than a change to an existing encoding.

### 14.3 M4 — Memory-bound HBM scratchpad PoW

A proof of work stage whose cost is memory *latency* rather than arithmetic: a
scratchpad of `lanes` cache lines (32 bytes each), seeded from the header hash,
followed by `accesses` pseudorandom hops where the next lane index is derived
from a SHA-256 output. Mainnet is 16 384 lanes (512 KiB) and 64 accesses.

The security claim is that the access sequence cannot be precomputed without the
header, so an ASIC cannot parallelise it and a cloud burst cannot amortise it.
It is registered in code as `puzzle_id = 2` (`PuzzleSpec::hbm_v1`) but is not
the active mining puzzle on any profile, so it validates nothing in consensus
today.

### 14.4 M5 — BLS aggregate finality

`BlsPublicKey` (48-byte compressed G1) and `BlsSignature` (96-byte compressed
G2) are typed wrappers, so a wrong-size key cannot be constructed. A
`CheckpointPayload` commits under domain tag `0xB1` to epoch, height, block hash
and validator-set hash. `ValidatorSet` sorts keys at construction, so its hash
does not depend on insertion order. Quorum is `ceil(n × 2/3)`, and a signer set
is carried as a bitmap of `n` bits. `BlsVerifier` is a trait so the pairing check
can be swapped for a real implementation (`blst`) without touching the chain.

**The pairing core is real, and the authority is now purchased.** Since §14.5, a
`blst`-backed `RealBls` verifier performs actual pairing checks, and
`verify_checkpoint` with `RealBls` rejects forgeries that `MockBls` (kept for
CI-only structural tests) would accept. Since Decision 20 (§14.6, §14.7) the
committee is derived from the bond ledger by stake-weighted TopN rather than
declared, and a proven equivocation burns the bond. Rotation and rewards are
still missing: a checkpoint signer is paid nothing, so the security budget is
currently entirely volunteer.

### 14.5 M5 — Real BLS signatures (blst): wire and protocol semantics

§14.4 specified the envelope with a mock verifier. This section specifies the
real cryptography and is **normative for any build that sets
`real-bls` on**. It does NOT activate M5 consensus; activation additionally
requires §14.6 (validator-set economics), which is unresolved.

**Curve and scheme.** BLS12-381, min-signature layout: public keys in G1
(48 bytes compressed), signatures in G2 (96 bytes compressed). Aggregation is
point addition in G2, so an aggregate is one 96-byte value regardless of the
number of signers. The `blst` library (Supranational; NCC Group-audited, the
implementation behind Ethereum consensus) performs all pairing checks.

**Domain separation tag (DST).** All hashing-to-curve uses the DST

    "SRCT_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"

— the IETF `BLS12381G2_XMD:SHA-256_SSWU_RO_` suite string prefixed with the
protocol namespace `SRCT_SIG_`. No other message type may sign under this DST;
future BLS-signed protocol messages get their own `SRCT_`-prefixed DST. The
`0xB1` domain tag in `signing_hash` (§14.4) remains as a pre-image domain tag:
the message presented to BLS is `sha256_dom([0xB1], [payload_bytes])`, and that
32-byte hash — not the raw payload — is hashed to curve under the DST.

**Key encoding.** A `BlsPublicKey` is the 48-byte compressed serialization of a
G1 point. Validation at deserialization: `blst_p1_deserialize` + membership
check. The all-zeros point, points not in the correct subgroup, and infinity
are all rejected — a key that fails validation cannot enter a `ValidatorSet`.

**Signature encoding.** A `BlsSignature` is the 96-byte compressed G2 point.
Validation at verification time, never trusted from the wire alone.

**Message format.** The signed message is exactly:

    msg = sha256_dom([0xB1], [CheckpointPayload.serialize()])

    CheckpointPayload = height(u64) ‖ block_hash(64) ‖ net_id_len(u32) ‖
                        net_id(bytes) ‖ epoch(u64)

All integers little-endian. The message handed to BLS is the 32-byte hash; two
payloads with the same serialization always produce the same message, and the
hash binds network_id, so mainnet signatures never verify on mini.

**Validator-set identity.** A validator set is identified by
`set_hash = sha256_dom([0xB2], [n(u32) ‖ pk_1 ‖ … ‖ pk_n])` with keys in the
sorted order `ValidatorSet` already imposes. A checkpoint does not carry the
set; verifiers compute the set they expect for (epoch, height) and reject a
checkpoint whose `signer_bitmap` does not decode against it. The payload's
epoch and the set used must agree — a signature from a different epoch's set
fails simply because its keys are not in the verifying set.

**Quorum and bitmap.** Quorum is `ceil(n × 6667 / 10000)` (§14.4). The bitmap
is `ceil(n/8)` bytes, bit `i` (LSB-first within each byte) set means validator
`i` in sorted order signed. Bitmap bytes beyond `ceil(n/8)` are rejected; bits
at or above `n` within the last byte must be zero, and a set bit there is
malformed, not "extra signers" — this prevents a peer from smuggling
significance into padding bits.

**Duplicates.** Aggregation is over the set of distinct signers decoded from
the bitmap; each validator contributes at most one key by construction, so a
"duplicate signer" cannot occur in a well-formed checkpoint, and a verifier
MUST reject any hand-aggregated signature claiming to represent a signer list
with repeats — the bitmap makes repeats unrepresentable, which is the point.

**Lattice sidecar (post-quantum dual signature).** ML-DSA has no
pairing-based aggregation, so the quantum half of a checkpoint is a list, not
an aggregate: one `PqSidecarEntry = signer_index(u32) ‖ signature(3309)` per
bitmap signer holding a registered lattice key, over the same 32-byte message
above with an empty ML-DSA context. Wire shape, riding last so its absence
costs four zero bytes:

    sidecar_count(u32) ‖ sidecar_count × entry, at most 64 entries

Certificates written before the sidecar existed end after `signer_count` and
decode to an empty sidecar. Verification is clause 7 of §14.6: the index names
the member, the verifier's own epoch set names the key, the caller names
neither — and a bitmap signer with a registered key and no entry fails,
including a sidecar stripped off in transit.

**Replay protection.** A checkpoint is replay-protected by construction:
(epoch, height, block_hash, network_id) is unique per signing event because
heights advance monotonically and `CheckpointChain::accept` refuses a height
at or below the finalized tip. A signature over an already-accepted checkpoint
is therefore a no-op, and a signature over a future height cannot be produced
without the block hash of a real block at that height.

**Set changes.** Validator-set rotation is out of scope until §14.6 resolves
who validators are (D1: the M5 set is the staked top-21 per epoch — economics
unresolved). Until rotation exists, the set is a fixed genesis parameter per
network. A build MUST NOT implement rotation silently; set changes are a
consensus decision requiring explicit activation.

**Activation boundary (unchanged from §14.4).** `RealBls` gives this repository
real pairing verification. It does NOT make checkpoints consensus-relevant:
nothing in `Chain::submit` consults a `BlsVerifier`, and the block-validation
rules of §4–§9 are unchanged. M5 remains not consensus-active; what changed is
that the cryptographic core is real, tested against malformed input, and
shared between the checkpoint machinery and any future message type.

**Test fixtures.** Deterministic tests derive keys from `KeyGen`-style seeds
(IETF BLS key generation: `sk = HKDF-Extract(ikm, "" ‖ I2OSP(48,))` per draft-
irtf-cfrg-bls-signature-05 §2.3) over fixed 32-byte IKM values committed in the
test source, so every CI run verifies the same keys and signatures byte for
byte.

### 14.6 M5 — Validator-set semantics (DESIGN ONLY — not consensus-active)

> **Amendment (Decision 20 — consensus-active):** the economics below are now
> decided and implemented. **Anti-dust bond floor, not a stake threshold** —
> `NetworkParams::min_bond_sat` (0 on `mini`/`testnet`, 1_000_000 sat =
> 0.01 SRCT on `mainnet`): a bond below the floor is refused at admission and
> in blocks. The permissionless principle stands (the floor is dust-scale,
> ~1/500,000th of the removed 5,000 SRCT minimum); what it stops is 1-sat
> bonds permanently occupying ledger, snapshot and committee-derivation
> entries on every node at only fee cost to the submitter. The committee
> is the **first 21 eligible bonds by `(bond_height, bond_index)`** (bond
> order, not stake weight; no genesis-fixed identities, no privileged seats);
> unbonding is **1008 blocks, fixed**; equivocation burns the **full bond**
> through the M2 vault; there are **no rewards and no fee share**. The bond
> ledger lives in chain state with per-block undo (reorg-safe like every other
> state); an empty ledger falls back to the profile's declared committee (the
> test bootstrap). The library text that follows is unchanged and still
> describes the pure derivation machinery; the candidate list it derives from
> is now the bond ledger, and the selection rule in force is bond order.

**As built (committee behavior the chain enforces).** The library derivation
above is the pure function; the chain wires it as follows. Each epoch's
committee derives from the bond state at its **seed height** and stays fixed
for the whole epoch — a bond placed mid-epoch takes effect only at the epoch
whose seed first sees it. Seed snapshots travel with chain state, so a reorg
across a seed height rolls the committee back exactly, and the finality
observation frontier rewinds with it: a checkpoint accepted on a losing branch
is forgotten, never replayed. The epoch-set cache holds the current set plus
the previous one inside a one-epoch grace (late previous-epoch checkpoints
still verify), then expires fail-closed; once bonds exist there is no genesis
fallback, and a committee that fails to derive is a hard block error, never a
silent empty set. Slash evidence is verified per epoch — each checkpoint
against its own epoch's committee via the seed snapshot, refusing when that
set is unavailable — so a validator that drops out of TopN is still slashable
on evidence from when it was bonded, while expired evidence and disjoint
signer sets are refused.

This section defines the validator-set machinery completely enough to
implement and attack-test as a **library**, so that the remaining open
questions are purely economic (who stakes, how much, what the rewards are).
Nothing here changes block validation: `Chain::submit` does not consult any of
it, and a build that ships this code ships it inert.

**The unresolved economics** are, explicitly, and they are decisions for the
protocol owner, not the implementer:

1. minimum stake to enter the set, and whether stake is bonded/withdrawable;
2. whether the top-N stakers (D1 suggested N=21) are the set, or stake-weighted
   sampling, or a fixed genesis committee for testnets;
3. validator rewards or fee shares, if any;
4. slashing for equivocation (double-signing checkpoints), amounts and
   evidence rules, and its interaction with M2;
5. when the set activates at all.

Everything else — identity, selection determinism, rotation, quorum,
checkpoint rules — is specified here and is safe to build, because it
prescribes no economics and touches no consensus path.

**Validator identity.** A validator is a pair `(stake_address, bls_pk)` where
`stake_address` is the 20-byte address (§1) that controls the stake and
`bls_pk` is a validated 48-byte G1 key (§14.5). A validator MAY additionally
register a 1952-byte ML-DSA-65 lattice key in its bond for checkpoint
sidecars; the lattice key is never the identity and never affects ordering —
bitmap bit `i` stays aligned with §14.4's bitmap semantics with or without it.
The binding is committed in
the set hash, so a key cannot be moved between addresses without changing the
set identity. A validator MUST NOT appear twice with the same `bls_pk` under
different addresses — a key that signs for two slots could double its quorum
weight; the derivation rules below make that construction fail closed. The
same holds for a lattice key under two BLS identities: one holder signing for
two stakes would make the sidecar ambiguous about whose stake each lattice
signature backs.

**Set representation and identity.** The validator set for epoch `e` is a
sorted vector of `(stake_address, bls_pk[, mldsa_pk])` triples, sorted by
`(bls_pk, stake_address)` — key first, because the key is what signatures
verify against, so bitmap bit `i` stays aligned with §14.4's bitmap semantics.
Identity is

    set_hash(e) = sha256_dom([0xB2], [ epoch(u64) ‖ n(u32) ‖
                                     for each validator sorted:
                                        addr(20) ‖ pk(48) ‖ (0x01 ‖ lattice(1952))? ])

A validator without a registered lattice key contributes nothing further, so
a set in which nobody registered hashes exactly as before.

Binding the epoch makes a set for epoch 5 unusable as the set for epoch 6 even
if membership is identical; a checkpoint for epoch `e` is only ever verifiable
against `set_hash(e)`.

**Set derivation (deterministic).** The set for epoch `e` is derived from
chain state at a fixed boundary:

    seed_block(e) = the canonical block at height
                    max(0, e * EPOCH_BLOCKS - EPOCH_LOOKBACK)

The full validator candidate list (stake table) at `seed_block`'s state, plus
nothing else, determines the set for epoch `e`. Derivation is a pure function
`f(stake_state_at_seed_block, epoch) -> ValidatorSet`, so two nodes at the
same height compute the same set byte for byte, and a reorg across the seed
boundary deterministically changes the set — no committee has a hidden
continuity advantage. `EPOCH_LOOKBACK` gives nodes the set before it takes
effect; a node learns epoch `e`'s validators while still in epoch `e-1`.

**Selection within an epoch (the abstract rule).** Given the candidate list,
the selection function selects at most `MAX_VALIDATORS` entries, deterministically,
by a rule the economics decision will parameterize (top-N by stake is the D1
default). The library exposes selection as a function of an explicit
`SelectionRule` enum; shipping `TopN` now does not presume the economics,
because the rule is a parameter, not a policy baked into consensus.

**Quorum.** Unchanged from §14.4: `ceil(n * 6667 / 10000)` of the CURRENT
epoch's set, computed over the set actually derived for the checkpoint's
epoch — never "the set the proposer liked".

**Checkpoint rules (validation, all of it, still inert).** A checkpoint for
epoch `e` at height `h` is valid iff:

1. `h` is within epoch `e` (`e == h / EPOCH_BLOCKS`);
2. the verifier derives `set(e)` from its own canonical chain and computes
   `set_hash(e)`;
3. the bitmap decodes against `set(e)`: exactly `ceil(n/8)` bytes, no set bits
   at or above `n`, and `signer_count` equals the popcount;
4. signer count meets quorum;
5. the aggregate verifies (§14.5) against the signers' keys under the
   checkpoint DST;
6. `h` is beyond the current finalized height.
7. the lattice sidecar verifies: for every bitmap signer holding a registered
   lattice key, exactly one sidecar entry with that bitmap index verifies over
   the same signing hash the aggregate covers. Signers without a registered
   key pass on the aggregate alone. An entry for a non-signer, a duplicate
   index, an entry for a keyless member, or a missing entry for a keyed
   signer is a refusal — including a sidecar stripped off in transit, which
   lands here as "missing", never as valid-without.

Failure of any clause is a rejection with the clause named; a checkpoint that
fails clause 2 (wrong set) MUST count toward the peer's ban score, because a
node that computes a different set is either out of sync or hostile, and the
receiver cannot tell — it treats both as garbage.

**Set changes (rotation).** Rotation happens only at epoch boundaries. Epoch
`e`'s set is fixed at `seed_block(e)` and cannot change during `e`, even if
stake moves — a validator whose stake is withdrawn mid-epoch still completes
the epoch (this is why bonded stake matters, and why it is an economics
question). Handover rules:

- The last checkpoint of epoch `e` and the first of epoch `e+1` are verified
  against their own epoch's sets respectively; there is no joint signature and
  no overlap requirement.
- A node tracks `set(e-1)` for one full epoch after handover, solely to
  validate late-arriving checkpoints from the previous epoch that are still
  higher than its finalized height. After that grace period the old set is
  dropped.
- Equivocation across a boundary (signing conflicting checkpoints for epochs
  `e` and `e+1`) is two separate evidence events against one key; the
  slashing economics are §14.6-open item 4, but the *evidence* (two
  valid-but-conflicting signed checkpoints, same key, both verifiable) is
  well-defined now and the library exposes it as data.

**What this section deliberately does NOT do:**

- It does not wire checkpoints into `Chain::submit`, fork choice, or
  `finalized_height` reporting.

**Implementation note.** `crates/srct-core/src/validators.rs` implements this
section as a pure library: `ValidatorRecord`, `SelectionRule::TopN`,
`derive_set`, `set_hash`, `EpochSetCache` (holds current + previous epoch,
with the grace-period drop), and the checkpoint clause checks as
`validate_checkpoint_against_set` returning the failed clause. Tests attack
every clause; none of it is reachable from consensus.

### 14.7 M5 — Validator set + finality foundation (Decision 11, non-binding)

Decision 11 resolves the §14.6 open items for Phase 6 by **scoping, not
inventing**: the economics (bonded stake, rewards, slashing) remain open and
mainnet-gated, exactly as Decision 8 set out, and M4 builds only what Decisions
2 (bootstrap mode) and 8 authorized. Binding finality activation is governed by
§14.8 (Decision 12): `testnet` at height 20, `mainnet` at height 100, and
`mini` observation-only.

- **Committee.** The genesis committee is an explicit list of BLS keys in
  `NetworkParams` (`genesis_validators`), canonically sorted by key bytes.
  `mini` and `testnet` declare four deterministic test keys; `mainnet` declares
  21 deterministic public bootstrap keys (Decision 27), quorum 15. Until a bond
  exists these keys carry authority by declaration; the first bond replaces
  them under Decision 20's TopN rule. `checkpoint_interval_blocks` is `10` on
  `mini`/`testnet` and `100` on `mainnet`.
- **One authority.** `validators::validate_checkpoint_against_set` is the single
  checkpoint authority (the six clauses above). `bls_checkpoint::verify_checkpoint`
  remains its inner signature primitive, not a rival authority.
  `CheckpointChain` is a monotonic observation log.
- **Transport.** `msg_type = 11 CHECKPOINT` (§13.5) carries complete
  certificates only. A receiver verifies against its local committee and relays
  if valid; consensus never consults it. `Checkpoint`/`CheckpointPayload`
  gained bounded `deserialize`.
- **Observation, before activation (Decision 11).** `srct_core::finality::FinalityManager`
  records what the committee signed and reports it, and at that stage
  `finalized_height` and fork choice did not consult it. **Superseded by §14.8:**
  once a profile's `finality_activation_height` is reached, `adopt()` refuses any
  branch forking at or below the binding-finalized height, and
  `Chain::finalized_height()` is the stronger of the depth and binding rules. On
  `testnet` (activation height 20) that is enforced; on `mini`/`mainnet` (0) it
  is not, and the observation-only behaviour above is what remains. L2 `Settle`
  quorums are untouched either way — they belong to task arbitration, not the L1
  checkpoint committee.

### 14.8 M5 — Binding finality, testnet profile, equivocation (Decisions 12–14)

M4 (§14.7) built the committee machinery and deliberately left it
observation-only. This section is the rule that makes it *binding* under an
explicit activation condition, the profile that exercises it, and the conflict
policy that bounds it. It is normative for `srct_core::finality`,
`Chain::{apply_checkpoint, restore_finality, finalized_height, adopt}`, the
store's finalized metadata fields, and the `testnet` profile.

**Activation condition (Decision 12).** Every profile carries
`finality_activation_height`: the height at which a valid certificate becomes
binding, or `0` for *never*. Below the activation height an accepted
certificate is an observation — it never gates `Chain::adopt()`, never
persists as finality, and never matures an L2 deposit (§19.5). The value must
be a multiple of `checkpoint_interval_blocks` and require a non-empty
committee, or `NetworkParams::validate` refuses the profile at config time —
a rule that could never fire is refused rather than silently inert. `mini`
carries `0` (observation only); `testnet` carries `20`; `mainnet` carries `100`
with its 21-key bootstrap committee (Decision 27).

**The finalized checkpoint.** A certificate over height `H` becomes the
binding finalized point only if all five hold:

1. its block hash is the **canonical** block this chain holds at `H`;
2. the certificate is valid — the seven clauses of §14.5/§14.6 (epoch, derived
   set, bitmap, count, quorum, aggregate signature, lattice sidecar), with the network id
   checked before any signature work;
3. it satisfies the existing quorum `ceil(n × 6667 / 10000)` — unchanged,
   never stake-weighted;
4. `H` is **strictly monotonic** above every previously accepted height (a
   replay or stale certificate is refused, not re-finalized);
5. it does **not conflict** with an already-accepted/finalized certificate at
   `H` (see below).

Every refusal fails closed: nothing is recorded, finality does not move, and
the error names its clause (`FinalityError::{InvalidCertificate, NotCanonical,
NotMonotonic, ConflictingFinality}`).

**Enforcement.** `Chain::finalized_height()` is the stronger of the two rules:
`max(tip − finality_depth, binding_finalized_height)`. `adopt()` refuses any
competing branch whose fork point is at or below it with
`ReorgWouldCrossFinality`. Before activation the first term is the whole rule,
exactly as before M5; after activation a branch forking at or below the
finalized height is refused no matter how much work it carries, and a branch
forking strictly above it is adopted when otherwise valid. Fork choice itself
is not redesigned.

**Conflict behavior and equivocation evidence (Decision 14).** Given two
otherwise-valid certificates at the same height, `H → A` and `H → B`:

- both are never accepted: the first retains the height, the second is refused
  as `ConflictingFinality` — so the system can never finalize two different
  block hashes at one height, before *or* after a restart;
- the conflict is classified **before** the canonical clause, so a certificate
  for a competing hash proves the conflict instead of being misfiled as merely
  non-canonical;
- `EquivocationEvidence { offender, first, second }` is retained: `offender` is
  the first common signer in canonical key order; `first`/`second` are payload
  hashes in canonical serialized-byte order, so two nodes that saw the
  certificates in opposite orders retain byte-identical evidence;
- retention is bounded (at most 1024 evidence records and 256 recent
  certificates), deduplicated by content, and refusals record nothing else;
- **no punishment**: stake bonding does not exist yet, nothing is burned, and
  no penalty is invented. The evidence is proof, not an execution.

**Restart.** The finalized `(height, hash)` is persisted in the store's existing
metadata row — not a second database — and restored after block replay only
onto the exact canonical block at that height; a stale or forged row is
refused. Finality before restart equals finality after restart, the restored
point enforces `adopt()` exactly as the live one did, and evidence itself is
in-memory (diagnostic until slashing exists).

**Testnet profile (Decision 13).** `NetworkParams::by_name("testnet")`:

| Property | Value |
|---|---|
| network id | `srct/testnet` (unique) |
| network magic | `6A 4E 54 04` (unique) |
| genesis validator committee | 4 deterministic keys (public test material, distinct derivation from `mini`'s), canonically sorted |
| quorum | `ceil(4 × 6667 / 10000) = 3` |
| `checkpoint_interval_blocks` | `10` (epoch = height / 10) |
| `finality_activation_height` | `20` |
| `finality_depth` (fallback) | `20` |
| staking / rotation | none — the committee is the fixed genesis list |

Determinism is a test-pinned property: two independently constructed
`testnet` profiles — by name or by constructor — are byte-identical, key
material included, with no runtime entropy anywhere. This is the protocol
profile required to test binding finality, **not** a public testnet launch;
validator staking, rotation, rewards and slashing remain deferred (§14.6 open
items).

**Mainnet bootstrap (Decision 27).** `NetworkParams::mainnet()` declares 21
deterministic public keys derived under
`srct/mainnet-validator-seed/v1`, canonically sorted, with quorum
`ceil(21 × 6667 / 10000) = 15`. Binding finality activates at height `100` on
the `100`-block grid. The keys are public material: any node can produce a
valid certificate before a bond exists. That is the accepted cold-start
property. With a non-empty bond ledger the existing stake-weighted TopN rule
selects the epoch committee and the bootstrap list is no longer used; with an
empty ledger it remains the fallback.

**L2 consumes this finality, it does not duplicate it.** Deposit maturity
requires both the depth rule and this binding rule (§19.5), read from the L1
chain's own finality layer; L2 settlement verifies against the separate
`l2_settlement_validators` declaration — never ad-hoc keys, and never the L1
bootstrap committee by convenience (§15.1). `mini` and `testnet` carry the same
four keys as their L1 committee; `mainnet` keeps this set empty and refuses
every settlement by name.

---

## 15. Layer 2: task contracts and the L2 transaction types

Layer 2 is the verified-work marketplace: a submitter posts a compute task with
a locked payment, a worker claims and runs it, and settlement releases the
payment against a verdict. A sixth payload type, `ExitQueue`, moves value the
other way — out of L2 and back to L1 (§19.6). This section specifies the payload
types, the task state machine, and the fee path. It is **normative for the
`srct-l2` crate and `srct_core::l2`**, and it deliberately stops short of L1
consensus:

- These payloads are carried inside L1 blocks as a length-prefixed trailer
  committed by the merkle root (§19.1 — implemented). An L2-free block still
  encodes byte-identically to the pre-§19.1 format, which is why the frozen L1
  vectors are untouched.
- Nothing here changes `Chain::submit`, fork choice, `finalized_height`, issuance,
  the L1 fee floor or the L1 gas model. An L2 payload that fails to apply is
  recorded by the replayer and skipped deterministically; it never turns an L1
  block invalid. That separation is what keeps this integration out of
  `Chain::submit`.

### 15.1 Transaction types and wire codes

Thirteen payload types, each with an explicit wire code. The `0x10` base is
deliberate: L1 uses `0` (`STANDARD`) and `1` (`COINBASE`), so an unknown L1 type
is refused as an L1 type rather than silently read as an L2 one.

| Type | Code | Fee (sat) | Actor |
|---|---:|---:|---|
| `PostTask` | `0x10` | 5 000 | submitter |
| `ClaimTask` | `0x11` | 2 000 | worker |
| `SubmitResult` | `0x12` | 2 000 | worker |
| `Dispute` | `0x13` | 10 000 | challenger |
| `Settle` | `0x14` | `max(0.1% of released value, 1 000)` | validator quorum |
| `ExitQueue` | `0x15` | 2 000 | exit owner (§19.6) |
| `Policy` | `0x16` | 2 000 | grant owner (§21.1) |
| `PolicyRevoke` | `0x17` | 2 000 | grant owner (§21.2) |
| `AgentSpend` | `0x18` | 2 000 | the grant's spender (§21.3) |
| `CreditOpen` | `0x19` | 2 000 | lender (§22.3) |
| `CreditCollateral` | `0x1A` | 2 000 | borrower (§22.4) |
| `CreditRepay` | `0x1B` | 2 000 | borrower (§22.5) |
| `CreditDefault` | `0x1C` | 2 000 | anyone, once due (§22.6) |

The first four carry an explicit actor address and a signature bundle over a
domain-separated signing hash. The signing hash covers the payload **including
the key bundle but excluding the signature bundle**, so re-signing does not
change the message and swapping keys does. This is the same discipline as the L1
`Transaction::sighash`. The seven types added by §21 and §22 follow the same
discipline: a domain-separated signing hash over the payload, the key bundle
included and the signature bundle excluded, and the actor's address checked
against the key bundle's own address.

`Settle` has no single signer. Its authorization is a validator-quorum
BLS12-381 aggregate (the M5 structure: bitmap + signer count + 96-byte
aggregate) **plus the lattice sidecar**: one ML-DSA-65 signature per bitmap
signer holding a registered lattice key, over the same decision hash, carried
in the payload and in the issued VWC. Both halves verify through the existing
`BlsVerifier` trait and the epoch set's registered keys **against the
profile's declared `l2_settlement_validators`** — separate from the L1
`genesis_validators` committee used at §14.8, never keys pulled from finality
machinery by convenience. Mainnet declares an empty settlement set, verifies
against nothing, and therefore refuses every settlement by name (`BadQuorum`)
— fail closed, never fail open. A bitmap
signer with a registered key and no valid sidecar entry is refused by name
(`BadPqSidecar`) — fail closed, never silently downgraded. The aggregate
message is the domain-separated hash of
`(task_id, verdict, vwc_hash, network_id, height)`, so a settle decision
cannot be replayed against another task, another verdict, another chain, or —
from the future — another height. `apply` refuses a payload naming another
network than the state's own config, and a vote height above the applying
height. A quorum formed at `H` may still settle at `H+1`: votes are signed as
the chain moves, so the height rule is "not from the future", with the
dispute lifecycle (a task settles once) closing the replay window.

Wire form of the settle payload (the sidecar rides last; a payload written
before it existed ends after `signer_count` and decodes to an empty sidecar —
but any payload written before the network/height binding is refused outright,
because its signature covers the decision alone and must no longer verify):

```
fixed  task_id        (32)
u8     verdict
fixed  vwc_hash       (32)
u32le  id_len         (<= 64)
raw    network_id                   // chain the quorum signed for
u64le  height                       // height the quorum signed at
raw    bls_sig        (96)
u32le  bitmap_len     (<= 64)
raw    signer_bitmap
u32le  signer_count
u32le  sidecar_count  (<= 64)       // absent in pre-sidecar encodings
sidecar_count × (u32le signer_index ‖ raw sig (3309))
```

Every payload is canonically encodable: `serialize` and `from_reader` are exact
inverses, and every length prefix (signature bundle components, attestation
signatures, signer bitmap) is bounded **before** it drives an allocation.

### 15.2 Task identity

```
task_id = SHA256(DOM_L2_POST ‖ submitter(20) ‖ nonce(8 LE) ‖ ComputeTask::task_hash())
```

The nonce makes two otherwise identical posts distinct; the submitter is bound
in so a third party cannot repost another actor's task under a colliding id. A
post whose `task_id` is not the derivable one is refused, so the id is a
commitment rather than a claim.

### 15.3 Lifecycle

```
  Open ──claim──▶ InProgress ──submit──▶ ResultSubmitted ──dispute──▶ Disputed
   │                 │                        │                          │
   │                 │                        └─ window elapses ─▶ auto-settle Correct
   │                 │
   └─ deadline ─▶ Expired ◀─ deadline ────────┘
```

The **dispute window is a protocol parameter**, not a field an actor chooses: a
submitter who could pick their own window could pick zero, and a worker who
could pick it could make challenges impossible. `L2Config` fixes it per network.

Opening is fail-closed with named errors, never panics: a contract with zero
payment, no deadline, or a dispute window reaching the deadline is refused at
construction (`L2Error::ZeroAmount` / `L2Error::InvalidContractSpec`). Malformed
input is a deterministic rejection in the L2 layer, not a crash.

The L2 `deadline_height` must equal the embedded M3 envelope's `expiry_height`.
Two deadlines for one task is an ambiguity, not a feature, and the mismatch is
rejected rather than resolved.

`Settle` verdicts:

- **Correct** — from `ResultSubmitted` after the window, or from `Disputed` when
the worker was right. Escrow minus the settle fee pays the worker; the worker's
deposit is returned; a losing challenger's deposit is burned in full.
- **Fraudulent** — from `Disputed`. The submitter is refunded the whole escrow,
the challenger's deposit is returned, and the worker's deposit — after the
settle fee — enters the M2 vault (50% burned, 50% vesting). The fee comes from
the losing worker's deposit, not from the escrow the defrauded submitter is owed.
- **Expired** — from `Open` or `InProgress`; submitter refunded, worker deposit
  burned in full (no vest). Expiry is normally implicit and free; this verdict
exists so the arbitrator set can close a task a vanished worker never delivered.

Implicit transitions — a deadline passing, a dispute window closing — charge
**no fee**, because nothing was transacted.

### 15.4 Fees

L2 fees ride a path of their own: `fees::split_flat_fee(fee)` treats the fee
as `full_base` and applies the unchanged M1 50/50 burn/PSCB rule, with the
odd satoshi going to `burned` exactly as `split_fees` does. The L1 gas floor
(`base_fee * gas_used`) is untouched and L2 never consults it. There is no
exemption and no second fee market.

Post/claim/submit/dispute/exit-queue fees are the flat D3 values. The settle
fee is proportional (Decision 23): **0.1% of the task's escrow value, minimum
1 000 sat** (`settle_fee_sat`). A task settles exactly when its escrow covers
this — below the 1 000-sat floor the fee exceeds the value (refused), at or
above it the fee is always payable. On `Fraudulent` the fee is computed from
the escrow but charged against the worker's deposit, so the defrauded
submitter is refunded whole.

### 15.5 Value conservation and replay

An L2 fee or a slashed deposit is **moved, never conjured**. For any sequence of
applied transactions:

```
Σ accounts + Σ locked + burned + PSCB + vault_remaining == Σ credited
```

`L2State::conservation_total` is that left-hand side, and the integration tests
assert it after every scenario. A transaction is refused by id if it was already
applied, and a *rejected* transaction is not marked applied — a transaction
refused on a precondition (a task not yet posted) may be retried once the
precondition holds, but it can never apply twice.

### 15.6 Dispute evidence and arbitration

A `Disputed` contract carries two competing results: the worker's submitted
`result_hash` and the challenger's `counter_result`. Arbitration turns those,
plus a reference re-execution (SPEC.md §16), into a verdict:

```
re_execution == submitted_result  and != counter_result  ->  WorkerCorrect
re_execution == counter_result    and != submitted_result ->  ChallengerCorrect
anything else (matches neither, or no reference result)   ->  Inconclusive
```

`counter_result == submitted_result` is refused at dispute-filing time, so the
two "and" clauses can never both hold. **`Inconclusive` is not a verdict**: it
settles nothing, slashes nothing and burns nothing. A task can only be settled
by `Correct` or `Fraudulent` (or implicitly `Expired`).

Evidence is validated before it is arbitrated, and every failure is named:
both attestations must bind to this task and to the result they claim, both must
carry a signature, and the two results must differ. Evidence is never executed —
the engine compares result *hashes* only (§16.4).

The verdict names the hash a settlement must carry: `submitted_result` for
`Correct`, `counter_result` for `Fraudulent`. A `Settle` transaction whose
`vwc_hash` does not match its verdict is refused (`BadVwcHash`), which is what
binds a settlement decision to the evidence it was derived from.

### 15.7 Dispute resolution window and lapse

A filed dispute must be resolved within the **same** window length as the filing
window, measured from `filed_at`. If it is not, the dispute **lapses**: the
worker's submitted result stands and the settlement is applied as `Correct` with
no fee, which burns the challenger's deposit. A challenge that is filed and then
abandoned is therefore not free — the same anti-spam rule as a challenge that
was filed and lost. Lapse is an implicit transition and is applied by
`L2State::advance_block` in deterministic, sorted task order.

### 15.8 Whistleblower bounty

When a challenge is **upheld** (`Fraudulent`), the challenger is refunded their
deposit and additionally receives a bounty of **25% of the slashed amount**,
paid from the M1 PSCB reserve and capped by the reserve's current balance. The
bounty is a transfer *out of* the reserve to the challenger, so it moves value
rather than minting it and the conservation invariant is unchanged. A failing
challenge earns nothing and burns the deposit.

### 15.9 What is not specified here

- *Nothing outstanding:* how an L2 transaction reaches a block is specified and
  implemented in §19.1.
- Verified Work Certificate issuance, representation and validation — now
  specified in §17. The `vwc_hash` field of a settlement remains the value that
  a certificate commits to: `result_hash` for `Correct`, the counter-result for
  `Fraudulent`, and all-zero (`VWC_HASH_EXPIRED`) for `Expired`; only a `Correct`
  settlement issues a certificate.
- The off-chain mechanics of producing `re_execution_result` (scheduling the
  arbitrator set, distributing the IR and input bytes) — the off-chain
  arbitration path, still unspecified.
- *Nothing outstanding:* §14.8 (Decision 12) defines the binding-finality
  activation rule. `testnet` activates at 20; `mainnet` activates at 100 with
  its 21-key bootstrap committee (Decision 27).

---

## 16. M3 CPU-reference execution (normative for dispute arbitration)

This section is the note §15.6 and `docs/roadmap.md` §11 (open question 2) call
for: how a validator decides which of two competing compute results is correct,
without owning the hardware the task was run on. **Dispute arbitration depends
on this section and on nothing else**, so it is written before the engine that
consumes it (Phase 3).

### 16.1 Why a reference is needed at all

M3 makes a task hardware-neutral on purpose: the same task may run on a GPU, an
NPU, a TPU, or a CPU. That is only a marketplace if the hardware does not change
the *answer*. The protocol therefore needs one execution path that is defined by
these bytes alone — no driver, no vendor library, no scheduler — and that path
is the CPU reference. Every other backend is measured against it.

This is tractable precisely because M3 already forbids floating point (decision
D2, `docs/decisions.md`). Integer-only IR means the GPU path and the CPU path
are two readers of the same bytes, not two rounding-error chains that were
never going to agree. Had M3 allowed FP, this section could not be written.

### 16.2 The reference execution function

```
reference_eval(ir_bytes, input_bytes) -> output_bytes
result_hash = SHA-256(output_bytes)          // the M3 result commitment
```

`reference_eval` MUST satisfy, for any inputs:

1. **Determinism.** Two runs on two machines, at two times, on two architectures
   produce byte-identical `output_bytes`. There is no wall clock, no RNG, no
   address-space dependence, no thread-count dependence, and no
   floating-point value anywhere in the evaluation.
2. **Canonical output.** `output_bytes` is the little-endian encoding of the
   task's output lanes. No padding, no platform endianness, no length prefix
   beyond what the task's IR declares.
3. **Total arithmetic.** Integer overflow is defined, not undefined: lane
   arithmetic is wrapping modulo the lane width (`u64` lanes mod 2^64, `u32`
   lanes mod 2^32). A backend that traps on overflow is non-conformant; a
   backend that saturates is non-conformant; only wrapping agrees with the
   reference.
4. **Fixed reduction order.** Any reduction over lanes fixes its order in the IR
   (ascending lane index). A backend may parallelise internally but MUST
   reproduce the specified order's result.
5. **Bounded.** Evaluation terminates on every input. An IR that cannot
   terminate is malformed and MUST be rejected before execution.

### 16.3 Backend conformance

A backend is **conformant** iff, for every task, its `result_hash` equals the
reference's `result_hash`. A disagreement is not "numeric noise" and MUST NOT be
tolerated by tolerance or rounding: it is a non-conformance, and the CPU
reference is the arbiter. This is what makes a challenge resolvable at all — a
challenger's counter-result can only be *correct* if it is what the reference
produces.

### 16.4 What the dispute engine consumes

Arbitration consumes only the **result hash** of the reference run. The engine
does not execute IR, does not parse IR, and does not carry a runtime: it is a
pure state machine over `(task_id, submitted_result, counter_result,
re_execution_result)`. Producing `re_execution_result` is the arbitrator set's
off-chain job, exactly as signing a checkpoint is. Keeping execution out of the
engine is what keeps the engine deterministic and reviewable.

Consequences, stated so they are not discovered later:

- The engine learns *which* result is right; it never learns *why*. A verdict is
  a comparison of hashes, not an evaluation.
- A task whose IR cannot be executed by the reference (malformed, non-terminating,
  out-of-memory) is arithmetically indistinguishable from an inconclusive
  dispute: the reference produces no `result_hash`, so no hash matches, and the
  engine returns `Inconclusive` rather than a verdict. The task is not slashed on
  an inconclusive outcome.
- The reference is a *tie-breaker*, not a re-miner. It is not required to be
  fast or to prove that the worker did the work; M4 is what proves hardware. The
  reference only answers "what is the correct output?".

### 16.5 Non-goals

- No on-chain IR execution, and no interpreter in `srct-core` or `srct-l2`.
- No gas metering of IR here — out of scope for the shipped worker SDK too.
- Floating point is never introduced, in the reference or any backend.
- The reference does not replace attestation or hardware proof; it determines
  correctness only after a result has been challenged.

### 16.6 The canonical reference (Decision 21 — implemented)

The reference function has exactly one definition:
`compute_ir::reference_output(task_id, ir_hash, input_hash,
required_memory_bytes)` (plus `reference_result_hash` over it) — a fixed
permutation satisfying §16.2, run by worker, challenger and arbitrator alike.
It takes commitments, not bytecode (the chain stores hashes so blocks stay
small), and deliberately **no height**: reproducibility demands identical
inputs across runs at different times, and a height is never identical.
Replay protection stays with task expiry and attestation heights.
`DisputeEngine::resolve` computes this itself from the disputed contract; a
caller-supplied reference hash is not accepted, so no party can dictate the
verdict it will be judged by.

---

## 17. Verified Work Certificates (VWC, Phase 4)

A Verified Work Certificate is the protocol's receipt for **verified correct
work**: a deterministic, canonical, off-chain-transferable record that task `T`
was settled as `Correct` with result `R`, that worker `W` was paid `P` sats for
it at height `H`, and — when the verification kind is quorum — a BLS aggregate
over exactly that decision, verifiable by anyone holding the validator set.

### 17.1 What a VWC proves, and what it does not

A VWC proves **digital verification**, not physical-world truth. Precisely:

- `Quorum` verification proves that a validator quorum signed a settlement
  decision naming `(task_id, Correct, result_hash)`. What the quorum signed is a
  decision; the strength of that decision is whatever produced the reference
  result (§16 for a challenged task, the unchallenged submission otherwise).
- `WindowElapsed` verification proves that the protocol settled the task as
  `Correct` after the dispute window closed with no challenge. It is *accepted*,
  not independently re-verified: its strength is the on-chain record, and it is
  not offline-verifiable. A relying party who needs stronger evidence MUST
  require the `Quorum` kind.

Nothing here attests that a human or machine physically executed anything. M4
proves hardware in mining; a VWC proves only that the protocol's verification
path accepted a result.

### 17.2 Representation

Canonical, little-endian, exact-inverse encoding (the same codec rules as §15.1):

```
u32le  version                      // 2; unknown versions are refused
fixed  task_id        (32)
fixed  worker         (20)
fixed  result_hash    (32)
u64le  settled_height
u64le  payment_sat                    // what the worker was paid
u8     verification_kind              // 1 = Quorum, 2 = WindowElapsed
if Quorum:
  raw    bls_sig        (96)          // aggregate over the SettlePayload signing hash
  u32le  bitmap_len     (<= 64)
  raw    signer_bitmap
  u32le  signer_count
  u32le  sidecar_count  (<= 64)      // lattice entries, absent in pre-sidecar encodings
  sidecar_count × (u32le signer_index ‖ raw sig (3309))
  u32le  id_len         (<= 64)
  raw    network_id                   // chain the quorum signed for
  u64le  vote_height                  // height the quorum signed at
```

The certificate id is *not* stored in the encoding — it is derived (§17.3), so a
tampered certificate cannot carry a matching id, and two encodings of the same
certificate are byte-identical.

### 17.3 Identity

```
vwc_id = SHA256("srct/l2/vwc/v1" ‖ body)
```

where `body` is the entire encoding above (version included). The id is a
function of the certificate's content alone: no wall clock, no randomness, no
iteration order. Two implementations encoding the same settlement MUST derive
the same id.

### 17.4 Issuance rule

A VWC is issued **by the protocol, automatically, at settlement**. There is no
issuance transaction and no actor who can request one, because a certificate is
a *derived consequence* of an already-authorized settlement, not a new claim.
The rules:

1. Only a settlement with `verdict == Correct` and `vwc_hash != VWC_HASH_EXPIRED`
   issues one. `Fraudulent` settlements issue none — a certificate of fraud is a
   `SlashRecord`, not a VWC. `Expired` settlements issue none — no work was
   verified.
2. Exactly **one** certificate exists per task, ever. The registry (§17.7) keys
   on `task_id`; a second issuance attempt for the same task is refused and
   fails closed.
3. The certificate is issued with the settlement, atomically: a settlement that
   cannot record its certificate is a programming error surfaced as an error on
   the explicit path, and the implicit path cannot produce one (a task settles
   once — see §17.8).
4. Issuance moves **no value**. The conservation invariant of §15.5 is
   unaffected by certificate creation.

The worker cannot forge a VWC by claiming work: issuance requires the settlement
path, which requires either a validator-quorum-signed `Settle` transaction or
the dispute window closing unchallenged. A worker's own attestation is necessary
but never sufficient.

### 17.5 Verification kinds

| Kind | Value | Evidence carried | Offline-verifiable | Strength |
|---|---|---|---|---|
| `Quorum` | 1 | BLS aggregate + signer bitmap + count + lattice sidecar | Yes, given the validator set | A quorum signed this exact decision, under both primitives |
| `WindowElapsed` | 2 | none | No | The on-chain record; unchallenged for one full window |

An explicit `Settle` transaction always yields `Quorum` — its payload already
carries the aggregate and the sidecar, and the certificate reuses both rather
than re-signing.
An implicit settlement (auto-settle or dispute lapse, §15.7) yields
`WindowElapsed`, because no aggregate exists for a transition no one transacted.

### 17.6 Validation

`validate` is total, deterministic and fails closed. It MUST check, in order:

1. **Identity.** `vwc_id == derived(body)` — any tampered field is caught here.
2. **Sanity.** `result_hash != VWC_HASH_EXPIRED`; `worker != 0^20`;
   `settled_height > 0`. `payment_sat` MAY be zero — an escrow that exactly
   covered the settle fee pays the worker nothing, but the work was still
   verified and still certifies.
3. **Kind-specific.** For `Quorum`: bitmap and count agree; count ≥ quorum
   threshold; the aggregate verifies over
   `SettlePayload { task_id, Correct, result_hash, network_id, vote_height }.signing_hash()`
   — rebuilt with the chain context the certificate carries — with the
   *same* verifier the settlement path uses; then the lattice sidecar verifies
   clause-7-shape against the set's registered keys (every bitmap signer
   holding one needs a valid entry — a relying party that stops at the
   aggregate accepts a decision whose quantum half is missing). For `WindowElapsed`: nothing
   further — its strength is the on-chain record (§17.5).
4. **Presence.** When checked against live state, the certificate MUST be in the
   registry under its own `task_id`, byte-identical. A certificate that is not
   in the registry was never issued; one that differs from the registry entry
   has been tampered with after issuance.

Validation never panics on any input; every failure is a named error.

### 17.7 Registry and replay

The L2 state keeps one registry entry per settled task (`task_id →
certificate`). This is the replay guard: a task settles once, so a second
certificate for the same task is impossible, and a decoded certificate claiming
a task that already settled differently is detected by comparison against the
registry entry. The registry stores full certificates so validation against
live state is a byte comparison, not a re-derivation from state the task no
longer carries (a settled contract keeps its outcome, but the evidence the
certificate binds to is the registry's job).

### 17.8 Lifecycle, and why there is no revocation

The lifecycle is exactly two states: **issued** and — from a relying party's
view — **validated** (or refused). There is no pending, accepted, revoked or
expired state, because:

- Issuance happens at settlement, so there is nothing before "issued".
- Settlement is terminal and one-way (§15.3): a task that reached `Settled`
  can never be disputed or re-settled. A `Correct` settlement therefore can
  never be overturned later, which is precisely the condition that would make
  revocation necessary. If a re-litigation mechanism is ever specified, it must
  come with a revocation rule as a separate, reviewable change.
- Certificates do not expire. A receipt for verified work does not become false
  with time; a relying party who cares about recency keys on `settled_height`
  itself.

### 17.9 Determinism

Id derivation, encoding, validation results and registry contents are pure
functions of settlement data. No clock, no RNG, no `HashMap` iteration order
(any enumeration of the registry is sorted by task id), no platform-dependent
behaviour.

### 17.10 Non-goals

- **No new transaction type.** Certificates are protocol outputs, not inputs;
  nothing authorizes one that the settlement did not already authorize. (This
  supersedes the roadmap's Step-6 note that VWC lands with new tx types; the
  reason is recorded in `docs/decisions.md`.)
- **No issuer key of its own.** The issuer is the protocol; `Quorum`
  authentication reuses the existing M5 aggregate and `BlsVerifier`. No custom
  cryptography, no new key ceremony.
- **No on-chain VWC transactions, no transfer semantics, no marketplace.** A
  certificate is a receipt; what third parties do with it is out of scope here.
- **No claim of physical execution.** See §17.1.

---

## 18. Worker SDK (Phase 6, `crates/srct-worker`)

A worker is any actor that claims tasks from the L2 marketplace, executes them,
and submits results: a human-operated process, an AI agent, an autonomous
machine. This section is **normative for the worker-facing crate** `srct-worker`.
It defines what the SDK MAY do on the protocol's behalf and what it MUST never
do. Unless stated, failure is always fail-closed: an SDK error never creates a
protocol effect that the L2 state machine did not authorize.

### 18.1 Boundary: what the SDK is, and is not

- **The SDK is a client, not a validator.** It contains no consensus logic. It
  does not apply, order or accept transactions; it constructs already-specified
  payloads ([`srct_core::l2`](§15)) and reads the authoritative state the
  protocol produces (§15.3, §17.7).
- **No second implementation.** TaskContract rules, dispute arbitration,
  VWC validation, wallet signing, settlement economics and fee routing are
  reused from `srct-core` and `srct-l2` verbatim. The SDK MUST NOT reimplement,
  re-derive or relax any of them.
- **No new transaction type, fee, or authorization path.** Every wire artifact
  the SDK produces is one of the L2 payloads of §15.1, signed by the
  §15.2 hybrid `Auth`.
- **Not a consensus participant.** The SDK never arbitrates, never settles
  (`Settle` has no single signer, §15.1) and never certifies (§17.4).

### 18.2 Worker identity

- A worker's identity is **its wallet address** (§15.2): the hybrid address of
  the same `Wallet` an L1 funding account uses. There is no separate worker
  registration and no worker registry.
- Authorization for claim, submit and dispute payloads is therefore exactly
  §15.2's `Auth::verify_as`: possession of the wallet's keys, nothing else.
- Identity conflict rule: an SDK instance deterministically derives an address
  from a single `Wallet`. A mismatch between the configured wallet and any
  external identity reference (attestation `worker_address`, registry account)
  is reported as `WorkerError::IdentityMismatch` and aborts the operation.

### 18.2.1 Delegated agent identities and policy chains (normative for `srct_core::agent` and `srct_core::delegation`)

**This section changes no consensus rule.** It amends the derivation scheme for
*agent policy identities* — an offline, non-consensus object (the owner-signed
`SpendPolicy`) that no block validity rule reads. The amendment is recorded here
because a new identity derivation is protocol-visible, not because blocks change.

**Sub-agent derivation.** An agent that spends under a delegated policy derives
its id from its **parent**, never from the funds it is trusted with:

```text
agent_id  = sha256_dom(DOM_AGENT_ID_SUB, network_id || parent_agent_id || role)[..20]
```

`DOM_AGENT_ID_SUB` is a new domain tag (`"srct/agent-id/sub/v1"`), the treatment
`DOM_ADDR/v2` received: two derivations over one tag are two meanings over one
byte string, and a collision between them would be an identity confusion, not a
bug. A root policy (no parent) derives as before, with `DOM_AGENT_ID` from
`(network_id, role, owner)`.

**The parent link lives in the signed bytes.** `SpendPolicy` carries
`parent_agent_id: Option<[u8; 20]>`; the canonical encoding gained a final
presence byte, and `POLICY_VERSION` moved from 1 to 2 so a version-1 policy is
refused rather than reinterpreted as a root. A link held in a separate table
could be attached to a policy that never had one — exactly the widening
delegation must refuse — so a child policy is a child because the bytes say so.

**The narrowing rule (the whole of item 3).** A child is refused unless it is
**dominated by its parent on every field**:

| Field | Rule |
|---|---|
| `version`, `network_id`, `owner`, `role` | equal — a delegate does not hop networks, does not add a co-spender, and does not change what kind of actor spends |
| `agent_id` | derives from the parent via the sub-agent derivation |
| `parent_agent_id` | names the policy above it |
| `window_blocks`, `per_tx_max_sat`, `cumulative_max_sat` | child ≤ parent |
| `not_before_height`, `expires_at_height` | child ≥ parent / child ≤ parent |
| `allowed_recipients`, `allowed_services` | child ⊆ parent |

Domination is checked field by field and each check is independent: "narrower on
average" is not a property, and a child with a tighter per-transaction cap but a
longer window can out-spend its parent. The safe configuration is the default, so
widening is impossible to do by omission.

**Chain rules.** A chain is a sequence of policies, root first. Every adjacent
pair is checked with the domination rule, so the rule composes; a chain longer
than `MAX_DELEGATION_DEPTH` is refused, because verification cost must not be the
caller's choice. A revoked policy anywhere in the chain refuses the whole chain —
an ancestor's kill switch must reach its leaves. A delegation registry
(`DelegationBook`) answers the questions a chain cannot: one agent id has one
lineage, and a link is not recorded twice.

**What remains unwired, deliberately.** The policy layer is a constraint, not an
enforced one, until something consults it (open finding, `docs/security-audit-2026-10-11.md`);
delegation inherits that status unchanged. Delegation decides no block's validity.

### 18.3 Node connection

- The SDK never decides what the chain is. It reads protocol state through an
  injected **state view** and hands signed payloads to an injected **broadcaster**:
  ```rust
  pub trait L2NodeView {          // read side
      fn l2_state(&self) -> L2State;   // the authoritative, replicated view
      fn chain_height(&self) -> u64;
  }
  pub trait L2Broadcaster {       // write side
      fn broadcast(&mut self, tx: &L2Transaction) -> Result<(), BroadcastError>;
  }
  ```
- Rationale: the seams keep the SDK transport-agnostic. `srct-net` carries only
  the §13 P2P message set, so the shipped transport is `srct_worker::HttpNode`
  over the node's opt-in REST API (§19.2). A local node or an embedded `L2State`
  can implement the same traits instead, without changing the SDK, which keeps
  every protocol rule testable without a socket.
- The SDK treats node responses as **untrusted data**: state views it cannot
  parse are errors, defaults are never guessed, and a malformed or stale view
  fails closed (§18.11).
- Connection failure, timeout after broadcast and transport outage are
  retryable; see §18.10.

### 18.4 Task discovery and filtering

- Discovery is a **pure function of authoritative state** plus the worker's
  filter configuration. Given the same `L2State` at the same height and the same
  filter, every call returns the same tasks in the same order (ascending
  `task_id`); a `HashMap` never decides an outcome (§15.9, §17.9).
- A task is **available** iff its contract is `Open` (§15.3), its deadline
  satisfies `current_height <= deadline_height` (§15.3 claim rule), and the
  worker's balance can cover `worker_deposit_sat + FEE_TX_CLAIM_TASK_SAT` when a
  deposit is required. Unavailable tasks (claimed, submitted, disputed,
  settled, expired) are never surfaced.
- The SDK MUST NOT evaluate task *desirability* (reward, hardware fit) by
  protocol rule; that is the operator's policy, expressed through the filter
  configuration (§18.12) or the application's own code over the returned
  `TaskRef`s.
- Payment information surfaced per task: `payment_sat` (escrow), the claiming
  worker's own `worker_deposit_sat` requirement, the D3 fees already fixed by
  `params.rs`, and `deadline_height`.

### 18.5 Task claiming

- A claim is a §15.1 `ClaimTask` payload built by
  `ClaimTaskPayload::build(wallet, task_id, backend, worker_deposit_sat)` and
  wrapped in `L2Transaction::new`. No other construction exists.
- Claim preconditions checked locally, before broadcast (all fail closed):
  the task exists; its state is `Open`; `current_height <= deadline_height`;
  the wallet's balance covers deposit + fee (§18.4); the caller's configured
  `backend` is recorded in the payload.
- The final authority is the protocol: a claim the L2 state machine rejects
  (already claimed, expired, insufficient funds) is reported as
  `WorkerError::Protocol(L2Error)` from the state view's next observation, never
  silently retried into a different shape (§18.10).
- Deposit policy: `worker_deposit_sat` is an economic decision (it is burned on
  never-delivering, §15.3/§15.4). The SDK proposes values the operator configures;
  it MUST NOT invent a nonzero deposit to satisfy a failing claim.

### 18.6 Task execution

- Execution is the **.Executor trait seam**:
  ```rust
  pub trait Executor {
      fn capabilities(&self) -> ExecutorCapabilities;
      fn execute(&self, work: &ExecutionWork) -> Result<ExecutionOutput, ExecError>;
  }
  ```
  with `capabilities()` describing the hardware the operator provisions
  (backends offered, max memory) and `execute()` producing the result bytes
  whose SHA-256 is the submission's `result_hash`. The SDK ships only the §16
  CPU-referencing shape needed by tests and dispute observation; every real
  executor (CPU, GPU, agent, external service) roots its own `Executor`.
- The SDK MUST NOT interpret `ir_hash`/`input_hash`: fetching the off-chain IR
  is the operator's transport (its hashes are the on-chain commitment, §15.1).
- Execution is isolated from consensus, wallet and settlement state by type: an
  `Executor` receives `ExecutionWork` (task id, IR/input hashes, backend hint,
  height) and holds no keys and no state handle.

### 18.7 Result submission

- The submission is a §15.1 `SubmitResult` payload: `result_hash` = SHA-256 of
  the executor output, attestation = `ComputeAttestation` (M3, §18.8) bound to
  the same task/worker/result, whole payload signed by the claim wallet's
  §15.2 `Auth`.
- Local preconditions, all fail closed: the task is `InProgress` **and claimed
  by this worker** (identity check §18.2); `current_height <= deadline_height`;
  `result_hash != [0u8;32]` (the expired placeholder — §17.6's submission rule);
  the attestation is signed.
- Duplicate submission is idempotent-by-state: after a successful broadcast the
  SDK records `task_id → submitted`, and a restart re-derives the same answer
  from authoritative state (§18.9) rather than rebroadcasting.

### 18.8 Attestation

- The attestation is the existing `ComputeAttestation` (M3), serialized
  canonically (§15.1/§17.2 rules unchanged). The SDK reuses the type and its
  codec; no parallel format exists.
- It signs over `task_id ‖ result_hash ‖ backend ‖ worker_address ‖ height`
  with the worker's wallet key. `worker_address` MUST be the configured
  wallet's address (§18.2 identity rule) and MUST equal the enclosing
  `SubmitResult` actor — the L2 layer already enforces this; the SDK enforces
  it too before broadcast for a clear, SDK-level error.

### 18.9 Lifecycle, idempotency and replay safety

- Canonical lifecycle (per task, monotonic, driven by observed state):
  `Discovered(Observable) → Claimed → Executed → Submitted → Settled`
  with only three exits on the way: `Expired`, `SettledCorrect(worker)`, and
  `SettledFraudulent(worker)`. The SDK's job is to *observe and act*, never to
  invent a transition the state machine did not make.
- **Idempotency rule:** every mutating SDK operation is keyed by an existing
  protocol identity (task_id, attestation hash, dispute id) so that an
  operation repeated after
restart or timeout either (a) finds its effect already recorded in
authoritative state — done, no second broadcast — or (b) re-broadcasts the
*same bytes* (same txid) if the effect is not yet visible. The node's replay
protection (§15.5) makes a duplicate apply impossible; reusing the same payload
is safe and MUST be preferred over building a variant with new bytes.
- **Timeout ≠ failure.** After any broadcast failure or timeout, the SDK MUST
  NOT assume the transaction failed. Reconcile by querying the authoritative
  view: if the effect is visible, it is done; if not, rebroadcasting the same
  bytes is safe.
- Restart-after-claim and restart-after-submit are the primary tested flows:
  a restarted SDK re-derives the task's state from the `L2NodeView` and either
  resumes (still `InProgress`/`ResultSubmitted`) or exits cleanly (`Expired`,
  lost to another claimant, already settled).

### 18.10 Retry, errors and failure classification

- Every SDK failure is one of:
  - **`Retryable`** — transport/connection failure, timeout, stale view. Safe to
    retry: the operation re-runs and either completes or observes completion.
  - **`Protocol`** — a named `L2Error` from the authoritative view (§15's error
    set). The SDK reports and surfaces; retrying with the same inputs must
    produce the same error, and the SDK MUST NOT mutate the payload to force a
    different outcome.
  - **`Local`** — configuration, identity mismatch (§18.2), executor error,
    unsupported capability. Never retried without operator input.
- No error is swallowed; no protocol rejection is converted into fake success;
  SDK errors name their cause (§18.16 hygiene rules for what must never leak).

### 18.11 Authorization and fail-closed rules (normative security properties)

An actor starting with **zero privilege** MUST NOT be able, through any SDK
path, to become an authorized worker, claimant, verifier, settler or payment
recipient. The SDK upholds this by construction; the test suite proves it by
attack:

- **Claim/submit/dispute authorization is §15.2 auth, full stop.** A wallet
  that never claimed a task cannot submit its result (`submit_result` actor ==
  contract worker, §15.3); a wallet that is not the challenger cannot file or
  read its dispute; a non-validator can never settle (no single-signer settle
  path exists).
- **The SDK refuses to construct a payload whose actor differs from its
  configured wallet** (`WorkerError::IdentityMismatch`), before any broadcast.
- **Unknown or forged node responses authorize nothing.** An `L2State` view is
  only an observation surface: crafting a fake view cannot make the SDK
  broadcast anything unsigned, and the protocol layer still verifies every
  authorization itself.
- **No escalation through retry:** every retry re-uses the same payload and
  identity; no retry path widens the set of actions the SDK will sign.
- **Fail closed on ambiguity:** unknown task, unknown state shape, zero values
  where the protocol demands nonzero, ambiguous identity — refuse and report,
  never guess.

### 18.12 Configuration

Configuration is data the **operator** supplies: worker wallet, backend offered,
worker deposit (for the next claim), filter (min payment, max deadline
distance, required memory, allowed backend class), and broadcaster/view wiring.
The SDK's configuration holds the wallet's private key material only by owning
the `Wallet`, and §18.16's hygiene rules apply to every place the configuration
or the SDK could print, log, Debug or serialize it.

### 18.13 Earnings

Earnings are **derived from authoritative state**, never accumulated in a side
ledger. For the configured wallet address the SDK reports:

- **available balance** — `L2State::balance` (payments credited by settlement
  §15.4, M2 vesting payouts returned to this address, and explicit credits);
- **locked/pending** — escrow locked in tasks this worker claimed and not yet
  settled: the payment owed on a future `Correct` settle, plus the worker's own
  deposit still at risk while `InProgress`/`ResultSubmitted`;
- **settled earnings** — for each task this worker claimed and which settled
  `Correct`: the certificate's `payment_sat` (§17.2), and the total credited
  (`SettlementOutcome::worker_paid + worker_deposit_returned`), referenced by
  `task_id`, `vwc_id` and — where one exists — the settle `txid`;
- **losses** — slashed or burned deposits (`Fraudulent`/`Expired`), by task.

No SDK value is invented: every number traces to a field of `L2State`
(`balance`, `task`, `vwc`, `SettlementOutcome`) or to a protocol fee constant.

### 18.14 Dispute participation

- **Observation.** The SDK observes a dispute over *its own* submitted result
  from the task's `Disputed` state (challenger, both results and
  attestations, deposits, `filed_at`), and watches it resolve through
  authoritative state: a settle `Settled` outcome or the §15.7 lapse rule.
- **Participation (the worker as challenger).** Building and broadcasting a
  §15.1 `Dispute` payload is supported for any task in `ResultSubmitted`, with
  the challenger's own deposit and counter-attestation.
- **The SDK cannot arbitrate and MUST NOT try.** Arbitration consumes a
  reference re-execution hash (§16.4) that only the arbitrator set produces;
  the SDK reads the resulting verdict from state and reports it.
- Repeat/dispute-replay protection is §15.5's txid rule (§18.9).

### 18.15 Determinism

Worker-side construction is deterministic wherever protocol encoding requires
it: payload construction, task-id invocation, attestation serialization, result
hashing, txid derivation and VWC handling are pure functions of (wallet, task,
result, heights). No wall clock, no RNG, no map-order dependence (§15.9,
§17.9). The SDK never introduces `HashMap` iteration anywhere a
protocol-visible result is produced.

### 18.16 Secret hygiene

The SDK MUST never include private key bytes in any `Debug`/`Display` output it
constructs, log them, include them in error messages or serialized worker
telemetry, or write them anywhere an operator did not explicitly configure.
The SDK's own error and debug output carries no signing material, and its
regression tests assert that over every public error and debug path.

### 18.17 Non-goals

- No REST/WS transport of its own. The shipped transport, `srct_worker::HttpNode`,
  is a *client* of the node's opt-in REST API (§19.2) and implements §18.3's
  traits; the SDK itself stays transport-agnostic, so a local node or an
  embedded `L2State` can implement the same traits instead.
- No executor implementations beyond the §16 CPU-reference shape used by
  tests and dispute observation; no scheduler, no ops UI.
- No worker reputation, scoring or registry beyond the protocol's.
- No move of consensus logic (task application, dispute resolution, fee
  accounting, settlement) into the SDK. The SDK is a client of an L2 the node
  already runs.

---

## 19. Phase 6: L1↔L2 integration (specified in six parts)

§19.1 specifies how an L2 transaction reaches a block — §15.9 left it
deliberately unspecified until the state machine underneath had been exercised.
**§19.1, §19.2, §19.4, §19.5 and §19.6 describe behaviour that is implemented
and tested.** §19.3 was specified but not built when this section was first
written; it has since been superseded, and is marked as such rather than being
folded in with the implemented parts.

### 19.1 L2 transactions in L1 blocks — IMPLEMENTED, normative

**Carriage.** A block MAY carry L2 transactions in a trailer after its L1
transaction list:

```
serialize(block) = header(177) ‖ signature(64) ‖ signer_pubkey(33)
                   ‖ U4LE(tx_count) ‖ tx_0 … tx_{n-1}
                   ‖ U4LE(l2_count) ‖ (U4LE(len) ‖ l2_tx_bytes(len)) × l2_count
```

1. The trailer is **absent when `l2_count` is zero**. A block whose trailer is
   present and empty is invalid (`Malformed`): one block has exactly one byte
   encoding, and a second encoding of a block is a second identity for it.
2. Consequently a block with no L2 transactions — which is every block that
   exists before this section — encodes byte for byte as it did in §3.5. No
   version bump, no frozen vector change, and `genesis_block()` is unchanged.
3. `l2_count` MUST be bounded by the remaining bytes before any allocation, and
   each entry's `len` MUST be within the remaining bytes. Both are checked; a
   count that passes one and fails the other is still rejected without
   allocating.
4. Each entry is length-prefixed so it is parsed independently: a malformed entry
   cannot desynchronise the parse of the entries after it.

**The commitment.** The header's `merkle_root` covers the L1 leaves first, then
the L2 leaves, in block order. L1 and L2 leaves use **distinct domain tags**
(`0x00` and `0x02`; internal nodes remain `0x01`), so an L2 payload can never be
presented as an L1 transaction leaf or vice versa.

This is the rule that makes the carriage safe, and it is worth being precise
about why: `block_hash = SHA512(DOM_BLOCK512 ‖ serialize(header))` (§3.4), so the
header binds the body *only* through `merkle_root`. Committing L2 leaves to that
same root means the existing `MerkleRootMismatch` rule (§9.1) already refuses a
block whose L2 section was stripped, reordered or altered — **no new L1 block
rule is introduced**, and `Chain::submit` is not made to know about L2 at all.

**Application.** L2 state is a pure function of the canonical chain:

    state = fold over heights h = 1..=tip of  ( advance_block(h) ; block(h).l2_txs in order )

The clock advances to the height **first**, then the block's own transactions
apply in block order. That order is normative because two nodes must agree on
whether a transaction landing on the same height as an expiry sees the task open
or expired.

**A failed L2 transaction is not a failed block.** L2 validity is explicitly
*not* an L1 block-validity rule. A payload that does not apply is refused by
`L2State::apply`, recorded by the replayer with its height, txid and named
error, and otherwise ignored: it is **not** marked applied (so the same bytes
remain retryable, §15.5) and it changes no state. Every node reaches the same
conclusion, because `apply` is a pure function of state and the rejection is
deterministic — so a miner that wastes block space on an unapplicable payload
causes no divergence. Making L2 validity a block rule is a separate change that
would require `Chain` to consult L2, which the dependency direction
(`srct-l2 → srct-core`) forbids by construction.

**Derivation, not storage.** L2 state is rebuilt by replaying the stored chain,
not persisted alongside it. A restart therefore cannot recover a *stale* L2
state — there is none to recover — and a reorg needs no undo bookkeeping: the
chain that won is replayed. `L2State`'s equality is derived over all of its
fields, so "two nodes agree" is a total comparison rather than a hand-picked
summary.

**Implementations.** `srct_core::block` (carriage, commitment),
`srct_core::chain::Chain::mine_block_with_l2` (producing a block that carries
L2), `srct_l2::replay::{ChainL2, SkippedL2}` (replay and the incremental path),
`srct_node::l2::NodeL2` (the node's view: replay on startup, incremental while
the tip extends, full replay when history is rewritten; settlements verified
against the profile's declared `l2_settlement_validators` committee with the
production BLS verifier — empty on `mainnet`, which therefore refuses every
settlement by name, see §15.1). `srct-node status` reports L2 height/applied/skipped;
`srct-node verify` asserts replay determinism (two replays agree, incremental
agrees with replay) and names the skipped payloads.

### 19.2 Worker↔node transport — IMPLEMENTED (reads + broadcast), loopback-bound

Decision 9 selects the roadmap §13 REST API. That document remains the authority
for its L1 endpoints; this subsection records the additive part the worker SDK
needs, so §13 itself is not edited.

- The server is `srct-node`, opt-in via `--api-listen`, disabled by default.
- The worker SDK's §18.3 seams are implemented as a client of it:
  `L2NodeView` reads, `L2Broadcaster` writes. The SDK is not modified to
  accommodate the transport.
- Endpoints the SDK requires beyond §13's list: L2 task state, open-task
  enumeration, L2 certificate lookup, and broadcast of an `L2Transaction`
  (§13's broadcast is L1-shaped).
- Authentication, replay protection, malformed-message rejection and
  idempotent retry are required (§18.9, §18.10, §18.11 apply to the transport
  exactly as they apply to the SDK's own state machines). Authentication is
  implemented as: Host-header validation on **every** bind (loopback
  included), bearer-token authentication (constant-time compare) with a
  per-IP token bucket on exposed binds, and a per-request deadline plus a
  global in-flight cap on every bind. The bearer token SHOULD come from the
  `SRCT_API_TOKEN` environment variable rather than `--api-token`, because
  command-line flags are visible in `ps`.
- Binding is loopback by default; exposing it beyond that is an operator
  decision, and the API is not a consensus surface: nothing it accepts may
  reach `Chain::submit` except a signed transaction, which is validated as
  §13.14 requires.

**Implemented (measured).** The node serves the L2 additions above at `GET
/v1/l2/state` (canonical state as `state_hex`), `GET /v1/task/{task_id}`,
`GET /v1/tasks/open`, `GET /v1/vwc/{task_id}` (the certificate plus its
`vwc_hex`) and `POST /v1/l2/broadcast`. `GET /v1/conservation` additionally
serves the live joint-supply report of §19.4–§19.5 (L1 live + L2 held −
deposit sink, against the joint bound (issuance integral + escrow ceiling), with all three check verdicts) — the same
arithmetic `srct-node verify` prints — and the `srct-worker run` verb gates on
it before its first pass, recomputing the verdict from the terms rather than
trusting the node's `ok` flag. `srct-worker::HttpNode` is a client of the API
that implements both §18.3 seams, `L2NodeView` (reads) and `L2Broadcaster`
(writes). The state a node hands a remote observer is a **versioned,
deterministic encoding** (`L2_STATE_WIRE_VERSION = 5`): sorted maps so two
nodes agree byte-for-byte, each declared count bounded by the bytes actually
remaining before anything is allocated, duplicate keys and trailing bytes
refused, and `check_conservation` re-run on decode, so a peer cannot hand the
SDK a state that does not balance. The SDK's read seam is **fallible**: an
unreachable or undecodable node is an error naming the reason
(`ObservationUnavailable` / `ObservationMalformed`), never an empty view — a
silently empty state would let a worker build a claim against nothing.
Client-side bounds are one response cap (16 MiB default), one header cap
(16 KiB), a connect timeout and a read timeout; plain `http://` only, with
HTTPS refused by name rather than downgraded.

**Implemented (measured).** Transport authentication. A non-loopback bind is
*refused* without a bearer token; loopback binds stay unauthenticated by
design. Host-header validation runs on every bind, bearer authentication
(constant-time compare) and a bounded per-IP token bucket run on exposed
binds, and a per-request deadline plus a global in-flight cap run on every
bind. Replay/idempotence for writes rests on the node's existing L2 dedup
and mempool rules rather than on a transport nonce or credential.

**Implemented (measured).** External mining. The node serves coinbase-only
templates at `GET /v1/mine/template?miner=<20-byte hex>` (unsolved block as
`block_hex` plus `height`/`difficulty`/`puzzle_id`/`prev_hash`, per the §13.1
template rule) and accepts solved blocks at `POST /v1/mine/submit
{"block_hex": ...}`, which runs the identical `submit` path — proof,
difficulty, tip and timestamp rules included — so external mining adds no
trust. Hex request fields are capped at 16 MiB (consensus caps blocks at 4
MB, so nothing legitimate approaches it); the pool wire caps lines at the
same 16 MiB with a read deadline, and duplicate solutions are refused, so one
proof counts as one share. The reference miner is `srct-miner --node ADDR:PORT --miner HEX
[--threads N] [--batch N] [--backend cpu|portable|auto]`, which loops
template → solve → submit; pool operators get the same flow as stratum-lite
JSON-lines (`getjob`/`submit` over TCP, single-use job ids, submissions
pinned to the job's `merkle_root`/`prev_hash`/`height`/`difficulty`/
`puzzle_id`/`epoch_id`, share difficulty vs network difficulty, per-miner
share stats). Pool reward splitting is off-chain PPLNS accounting (last-N-shares
window, so pool hopping has no timing edge; `fee_bps` off the top, flooring
dust carried forward,
`mark_paid` recorded) and never new issuance: only the consensus coinbase
rule mints, and only `submit` enforces it.

### 19.3 Superseded — genesis validator committee and checkpoints (Decisions 11–14)

This subsection once reserved the genesis validator committee and the
checkpoint machinery as "specified only when its decision lands". All three
parts are now decided, specified and built:

- **The fixed genesis set** — `NetworkParams::genesis_validators`, the declared
  committee, listed in the §10 profile table (§14.7).
- **The checkpoint message type** — `msg_type = 11 CHECKPOINT` on the §13.5 set.
- **The single authoritative validator** — `validators::validate_checkpoint_against_set`.

Binding finality is activated per §14.8: `testnet` carries
`finality_activation_height = 20`, and `mainnet` carries `100` with its 21-key
bootstrap committee (Decision 27). Nothing is outstanding here.

### 19.4 L2 genesis funding (Decision 7) — IMPLEMENTED, normative

L2 value enters through a genesis-funded protocol escrow. There is no deposit
There is no deposit transaction, no lock transaction, and no new L1 transaction
type for funding: user deposits ride an ordinary L1 payment to the derived sink
(§19.5), and L2→L1 exits ride `exit_claims` authorised by an inclusion proof
(§19.6). The one production **genesis** funding event is below.

**The allocation.** Two `NetworkParams` fields fix it per profile:

- `l2_genesis_escrow_sat`: the total L2 genesis allocation. `mini` allocates
  10 SRCT; `mainnet` allocates 100,000 SRCT and no grants.
- `l2_genesis_grants`: named `(address, amount)` balances released at genesis.
  `mini` grants 1 SRCT each to three deterministic operator identities; an
  empty list is legal (that is mainnet today).

The remainder (`escrow − grants`) parks with the protocol escrow identity:
`SHA256("srct/l2-escrow/v1" ‖ network_id)[..20]`, derived per network, holding
no key. It is inert in M2 — no disbursement rule exists for it yet — which is
stated so its balance cannot be misread as spendable supply.

**The backing rule.** The escrow is bounded by its own explicit, validated
parameter: `l2_genesis_escrow_sat ≤ escrow_ceiling_sat`, enforced by
`NetworkParams::validate` (Decision M-E). The shipped ceilings are exactly the
allocations (mini/testnet 10 SRCT; mainnet 100 000 SRCT) — tight, so the
parameter constrains rather than rubber-stamps. Because L1 can never hold more
than its issuance integral and L2 can never hold more than its escrow ceiling,
combined L1 + L2 money can never exceed `cumulative_issuance_sat(height) +
escrow_ceiling_sat` — the joint bound `GET /v1/conservation` reports and the
`srct-worker run` gate checks. `validate` additionally refuses a zero escrow,
zero grants, duplicate grantees, grants
naming the escrow identity, and grants summing above the total.

**Application.** `L2State::apply_genesis` releases the allocation once, to a
freshly constructed state, before any block is replayed: L2 height 0 holds the
funding and block 1 is the first that can spend it. A second application is
refused (`GenesisAlreadyApplied`) rather than double-funding. Every `ChainL2`
constructor applies it, so full replay, incremental sync, restart recovery and
reorg replay all derive identical funding with no persisted funding record and
no block-carried funding to replay twice.

**Conservation.** `L2State::funded_total` counts every satoshi ever released
(genesis, or a unit-test credit); `conservation_total` counts every satoshi
still in the system. Their equality is checked after every transition: fees,
burns, slashes, bounties and refunds move value between buckets but never
change the sum. `srct-node verify` additionally asserts `funded_total` equals the profile's
escrow total plus credited deposits minus `exited_total` (no unauthorized
funding happened) and that live L1 supply plus L2 held stays under
`cumulative_issuance_sat(height) + escrow_ceiling_sat`.

**Failure behaviour.** A payload from an unfunded account is still refused with
`InsufficientBalance`, recorded as skipped, and retryable — unchanged from M1.
A funded account's valid `PostTask` applies through the normal replay path. No
L2 validity rule became an L1 block rule: funding changes what applies, never
what is accepted.

**Implementations.** `NetworkParams::{l2_genesis_escrow_sat, l2_genesis_grants,
l2_escrow_address}` + `validate` (gap-fit and shape rules),
`srct_l2::genesis::L2Genesis` (allocation view), `L2State::{apply_genesis,
funded_total, check_conservation}`, `ChainL2::{empty, replay}` (genesis-first
construction), `srct-node verify` (joint conservation checks).

### 19.5 User L1 → L2 deposits (Decision 10) — IMPLEMENTED, normative

A STANDARD L1 payment carrying an output to the deposit sink is a deposit. L1
validates it as a payment like any other — no L1 rule changed, no new
transaction type — and L2 replay reads the deposit out of the accepted block.

**Sink.** `SHA256("srct/l2-deposit-sink/v1" ‖ network_id)[..20]`
(`NetworkParams::l2_deposit_sink`): deterministic per profile, distinct from
the escrow identity, holding no key. Another network's sink on this chain is
an ordinary burn.

**Recipient.** The common owner of the transaction's inputs, each read as its
input key bundle's address — which L1 consensus already proved equals the
spent UTXO's owner, so replay derives ownership without re-verifying
signatures and without UTXO history. Inputs with different owners, and
coinbase transactions, are not deposits: the value stays burned, nothing is
credited, and the refusal is recorded with its reason. There is no
third-party recipient in M3: the depositor funds only itself.

**Amount.** Exactly the sink output's satoshis, 1:1, no rate and no fee on the
credit itself. Each sink output is an independent deposit. Outputs below the
per-output minimum (1,000,000 sat both profiles,
`NetworkParams::l2_deposit_minimum_sat`) stay burned. A claimed amount is
never trusted: the credited value is read from the committed output.

**Replay identity.** `(txid, output_index)`, tracked in a consumed set in
`L2State`. The same bytes in a later block credit once; the second occurrence
is refused as a duplicate. Restart and reorg re-derive the set from the
winning chain.

**Maturity.** Detected at acceptance, spendable once **both** required safety
conditions hold (Decision 15):

1. **depth** — the §9.3 `finality_depth` rule, unchanged: `tip − deposit_height ≥ finality_depth`
   (20 on `mini`/`testnet`, 100 on `mainnet`); and
2. **binding finality** — once the chain has a binding checkpoint (§14.8), the
   deposit's own height must be at or below the binding-finalized height.

Before binding finality activates (finalized height `0`), the depth rule
governs alone — deposits are never less safe than M3, and no new finality
mechanism was invented. After activation, depth alone cannot make a deposit
spendable while the canonical history it sits in is not yet finalized.
Before maturity the deposit is pending (visible via
`pending_deposits`, not spendable). A consequence worth stating plainly: a
matured deposit sits below **both** finality lines, so consensus already makes
it as irremovable as its block — tying maturity to the stronger of the two
finality rules is what makes reorg-removal of credited deposits
unrepresentable except through a finality violation, which L1 refuses on its
own.

**Processing order.** Per block: clock, then L2 transactions in order, then
detected deposits in output order. Maturity is evaluated against the tip and
the L1 binding-finalized height together:
full replay evaluates every deposit at the final tip and the chain's current
finality point, while the incremental
path evaluates new blocks at the new tip and rebuilds by full replay when an
old pending deposit becomes spendable — whether by depth catching up **or** by
a checkpoint moving the binding floor (it never re-scans old blocks, so
extending would leave the deposit pending forever while a replay would credit
it). The binding floor is read from the L1 chain's own finality layer on every
sync; L2 keeps no checkpoint view of its own.

**Conservation.** Per deposit, L1 sink value equals L2 credited value, 1:1, no
rate and no fee on the credit itself. Globally the joint check of §19.4 grows a
sink term, because sink outputs remain in the L1 UTXO set while their twins live
in L2: `L1 live + L2 held − sink-held ≤ cumulative_issuance_sat(height) +
escrow_ceiling_sat`. Without the term every deposit would read as inflation;
with it the sum is constant across deposits and falls on burns. (§19.6 adds the
exit direction: the L1 payment and the L2 debit cancel, so the same check holds
with no new term.)

**Failure behaviour.** Ineligible sink outputs (mixed owners, dust) are burns
without credit, recorded with named reasons. Duplicates are refused by name.
Unfunded L2 accounts are still refused with `InsufficientBalance`. No deposit
rule is an L1 block rule: funding changes what applies, never what is
accepted.

**Exits.** Defined normatively in §19.6.

**Implementations.** `NetworkParams::{l2_deposit_sink, l2_deposit_minimum_sat}`
+ `validate`, `srct_l2::deposits::{DepositParams, scan_block, DetectedDeposit,
PendingDeposit, IgnoredDeposit}` (detection is a pure function of one block),
`L2State::{apply_deposit, deposited_total, deposit_credited}`,
`ChainL2::{pending_deposits, ignored_deposits, has_pending_matured}`,
`srct-node` sync (maturation-triggered replay) + `status`/`verify` (deposit
pipeline and sink-aware joint check).

---

### 19.6 L2 L1 exits (Decision 19) - IMPLEMENTED, normative

The return route §19.5 required. An owner debits an L2 account; the value
reaches an L1 address the owner chose, authorised by a proof rather than a
signature.

**Activation.** `NetworkParams::exit_activation_height` gates the whole rule.
`0` means **never**, not *from genesis* — a profile that has chosen no height
accepts neither a committed L2 root nor an exit claim (`Chain::exit_active_at`).
Below the activation height a block carrying either is refused structurally,
before any proof is read. At and after it, a block with L2 transactions **must**
commit an `l2_state_root`: an exit cannot be proven without one, so a
rootless block would silently disable exits.

**The two sides.**

*L2 side.* `L2TxType::ExitQueue` (`0x15`) carries `ExitQueuePayload`. It debits
`amount + exit_fee + queue_fee` from the owner and records
`(owner, nonce) → (amount, destination, exit_fee, queued_height)`. It is refused
by name on a zero amount, an exit fee below `MIN_EXIT_FEE_SAT` (1,000 sat), a
repeated or rewound per-owner nonce, an inactive profile, or an insufficient
balance — the record is written only after every check passes, so a refused
queue leaves no partial state. No cancellation:
a cancel/claim race needs its own ordering rule for no benefit, and the value is
encumbered for exactly one finality window.

*Exit throttle.* The deposit sink is a honeypot: at most
`max_exit_window_sat` of exit principal may queue per `exit_window_blocks`
(1 000 SRCT per 144 blocks on mainnet; `0` disables on `mini`/`testnet`), no
more than `max_exit_per_owner_window_sat` of it from any one owner
(100 SRCT on mainnet — one filler cannot starve the window). Over-cap
queues are refused with the retry height (`ExitWindowFull`, or
`ExitOwnerWindowFull` naming a full owner share) — funds stay put and the
owner retries in the next window. Exits at or above
`large_exit_threshold_sat` wait `large_exit_extra_delay_blocks` on top of
base maturity (100 SRCT → +144 blocks on mainnet). The per-owner shares are
replay-derived beside the window total (state wire v7) and re-checked at
decode, so a transported state cannot smuggle a broken-down window. Both
halves compute the same delay from the same inputs, so neither the L2 queue
accounting nor the L1 release check can release early. Windows are
replay-derived, so reorgs rebuild them from the winning chain with no undo
bookkeeping.

*L1 side.* A block carries `exit_claims: Vec<ExitClaim>` beside its L2 trailer.
A claim takes **sink outputs** as inputs and is authorised by an *inclusion
proof* of the exit record against the `l2_state_root` committed at
`queued_height` — not by a signature, because the sink holds no key. Consuming
the sink outputs rather than minting against them keeps the ordinary
`value_in >= value_out` rule in force everywhere; undo, reorg, fee and maturity
machinery are reused unchanged.

**Validation.** All fail closed.

1. Active profile, and `queued_height` final under the **stronger** of the two
   Decision 15 rules — depth `finality_depth` **and**, once binding finality is
   active, the binding checkpoint height. Exits are never less safe than
   deposits.
2. `amount_sat`, `destination` and `exit_fee_sat` equal the proven record
   exactly. No caller-supplied override is ever read.
3. Inputs resolve to real sink outputs totalling **exactly**
   `amount + exit_fee + required L1 fee`. No change output, no tip.
4. One release per `(owner, nonce)`, ever. Consensus keeps the consumed identity
   set, so replay is refused by consensus rather than by bookkeeping.
5. `queued_height < height`: the queue block must be final before the block that
   settles it.

**Who may settle it.** Permissionless (E-2). Anyone may build and submit a
claim; consensus pays only the recorded `destination` and the `claimant`'s
prepaid fee. No operator privilege and no second authorisation path to audit.
The fee is **prepaid by the owner at queue time** (E-3) — that is what makes an
unfunded crank impossible, and therefore what makes a permissionless crank safe.

**The proof is captured at the queue block.** `ChainL2` records an `ExitWatch`
(the record plus its `InclusionProof`) at the one moment the node's L2 root
equals the block's committed root. A crank therefore never replays back to
`queued_height` — the expensive alternative the design rejected. A block that
mixes an exit queue with a deposit moves the root after the queue applies, so it
yields no watch and the exit simply stays queued; nothing is proved against the
wrong root.

**Reorg.** A release is an ordinary undoable L1 operation. Rolling back the block
that settled it restores the sink outputs, clears the identity, and L2 replay
regenerates the watch, so a rolled-back exit is spendable again and one the
winner keeps is re-marked. A rolled-back release is not lost and a kept one is
not double-paid.

**Conservation.** Per exit, L2 debit equals L1 release, 1:1, no rate and no fee
on the principal. The §19.5 joint check is **unchanged and still holds**: the L1
payment `+a` and the L2 debit `−a` cancel, while the sink term falls by the same
`a`. `joint_sat` therefore needs no exit term — that is the strongest available
evidence the accounting was done right, and `tests/conservation.rs` keeps passing
untouched. `exited_sat` is reported (`/v1/status`, `/v1/conservation`,
`srct-node verify`) so an operator can confirm the two directions balanced.

**Implementations.** `srct_core::exit::ExitClaim` (+ codec, identity, gas,
proof verification), `srct_core::l2::ExitQueuePayload`, `L2State::{queue_exit,
exit_proof, exit_is_mature, note_release, exited_total, exit_queue_is_active}`,
`ChainL2::{pending_exits, ExitWatch}` (absorb releases and captures proofs),
`Chain::{exit_active_at, exit_released, mine_from_pool_with_exits}`,
`NodeL2::{pending_exits, crank_claims, simulate_root}`, `srct_worker::{queue_exit,
queue_exit_plan, ExitPlan}`.

---

## 20. Conditional Escrow with Contract-Selected Arbitrators (Item 4)

This section is non-consensus: the escrow is a *state machine recorded by the node*
(`srct-core::escrow::ConditionalEscrow`), and the actual coin move at release reuses the
ordinary L1 exit path (§19.4). It lets a payer lock value subject to a condition that is
resolved either by **both parties** signing (mutual release) or by a **single designated
arbitrator** signing (arbiter release).

### 20.1 Design

- The payer opens an escrow with `ConditionalEscrow::open(...)` naming an arbitrator's
  BLS public key **in the contract**. The arbitrator is *not* a Solar Cyber Unit key: the protocol
  never holds an "arbitrator key," and there is no committee. The contract selects one
  independently-operated BLS public key per escrow; a quorum of one is the point.
- Both parties also record a BLS public key (`payer_key`, `payee_key`), so a mutual
  release cannot be satisfied by an attacker naming their own key in the request.
- The escrow `id = H(network_id ‖ payer ‖ payer_key ‖ payee ‖ payee_key ‖ arbitrator ‖
  amount ‖ nonce)` (DOM_ESCROW). It is a pure function of the open fields, so the node can
  recompute the release-signing hash without storing extra state, and two escrows between
  the same parties differ by nonce.
- Release signing hash: `h = H(id ‖ verdict)` (DOM_ESCROW). For the standard pay-to-payee
  outcome `verdict = ReleasedToPayee (0)`.

### 20.2 State machine

```
Open
  --(arbiter sig over h)-->       ReleasedArbiter{at_height}
  --(both sigs over h)-->         ReleasedMutual{at_height}
Released{Arbiter,Mutual}
  --(ledger settlement, §19.4)--> Finalized{at_height}
```

- `Open` is the only live state. A release from any other state is refused (fail closed);
  a decided escrow cannot be re-released.
- The node records `ReleasedArbiter`/`ReleasedMutual`. `Finalized` is written by the
  settlement path when the coin actually leaves the escrow address on the base layer.

### 20.3 Verification rules

- **Arbiter release** (`verify_arbiter_release`): exactly one BLS signature, verified
  under the `arbitrator` key recorded in the escrow. Any other signer's signature fails the
  pairing — there is no fallback list.
- **Mutual release** (`verify_mutual_release`): exactly two BLS signatures, verified under
  `payer_key` then `payee_key` respectively, **and** the claimed keys must equal the
  escrow's bound `payer_key`/`payee_key` (so a non-party cannot release by naming a key).
- Signatures are raw BLS12-381 `min_pk` (48-byte public key, 96-byte signature,
  §16 signature scheme), verified via `RealBls` (`blst`), the same primitive used for
  validator signatures elsewhere — no bespoke signing logic is added to the contract.

### 20.4 API

- `POST /v1/escrow/open` — body `{network_id, payer, payer_bls, payee, payee_bls,
  arbitrator, amount_sat, nonce}`; returns `{escrow_id}`. A zero party/arbiter key or a
  zero amount is a `400 escrow_refused`.
- `POST /v1/escrow/{id}/release` — body `{mode:"arbiter", arbiter_sig_hex}` or
  `{mode:"mutual", mutual_sigs_hex:[sig0,sig1]}`; on success returns `{escrow_id, state}`.
  A bad signature is `409 escrow_refused`; a decided escrow is `409`; a missing escrow is
  `404`.
- `GET /v1/escrow/{id}` — `{escrow_id, payer, payee, amount_sat, state}`.

### 20.5 Rationale

- *Why contract-selected arbitrators, not a Solar Cyber Unit committee?* So Solar Cyber Unit holds no power of
  attorney over users' funds and cannot unilaterally release. The user picks the
  arbitrator they trust; the protocol only enforces the signature against the key the
  contract recorded. This corresponds to Decision 9 and ends the prior custody blocker.
- *Why BLS for the parties?* It is the only signature primitive the protocol already
  carries (§16), so mutual release reuses `blst` rather than introducing a secp256k1
  aggregation path that would need its own consensus rules and test vectors.
- *Why record `Finalized` here?* To keep the release signature check off consensus
  (§14.1) while still surfacing the settlement outcome that the L1 exit path produces in
  §19.4.

### 20.6 Implemented surface

`srct-core::escrow` (`ConditionalEscrow`, `EscrowState`, `EscrowVerdict`,
`release_signing_hash`, `verify_mutual_release`, `verify_arbiter_release`,
`BlsVerifier` trait + `RealBls`, encode/decode) is unit-tested including: non-designated
arbiter signature refused, non-party key refused for mutual, arity rule, round-trip
codec, zero-key/self-party refusal. The HTTP surface in `srct-node::api` is covered by
`crates/srct-node/tests/api.rs` (open, unauthorized arbiter refused, authorized arbiter
accept, replay of a decided escrow refused, mutual accept, one-sided sig refused,
unknown-id 404, zero-key open refused). Coin settlement runs through
`POST /v1/escrow/{id}/settle`: the call binds a released escrow to the L2 exit
that pays it (owner = payer, destination = payee, amount = escrow amount), and
§20.2's `Finalized` is written only when `Chain::exit_released` confirms
consensus actually paid that destination.

---

## 21. Agent authority on chain (Phase 7)

### 21.1 Why this section exists

The spending-policy layer of §18 was, until this section, a **node-local**
mechanism: a policy constrained a payment *on the node that issued it*, and
the chain never saw it. A machine fleet bound by policies was therefore bound
by the goodwill of whichever node issued them, not by the protocol. Two nodes
holding the same chain could disagree about whether a spend was permitted.

This section moves that authority onto the chain, where a rule that every node
replays is a rule and a rule that one node checks is advice. The three
transaction types below are the whole vocabulary:

| Type | Code | Actor | Purpose |
|---|---:|---|---|
| `Policy` | `0x16` | owner | publish a spending grant |
| `PolicyRevoke` | `0x17` | owner | kill a published grant |
| `AgentSpend` | `0x18` | spender | spend under a published grant |

They are Layer-2 transactions (§15, §19.1): they are carried in L1 blocks and
committed by the block's Merkle root, and the Layer-2 state they change is
committed by the block's `l2_state_root`. A grant and its counters are therefore
part of the state every node replays, and two nodes replaying the same chain
hold the same authority.

### 21.2 The grant

A grant is the owner's signed `SpendPolicy` (§18.2), exactly the object the
node-local engine already used - `per_tx_max_sat`, `window_blocks`,
`cumulative_max_sat`, `allowed_recipients`, `allowed_services`,
`not_before_height`, `expires_at_height`, `role`, `agent_id`, `owner`,
`parent_agent_id`. The policy encoding, its hash, and its structural validation
(`SpendPolicy::validate`) are unchanged.

What the publication adds is the **binding**:

```
PolicyPayload = owner(20) ‖ auth ‖ u32le(len) ‖ grant_bytes(len) ‖ spender(20) ‖ agent_id(20)
```

The owner's signature covers the grant bytes, the **spender** and the **agent
identity** together. That binding is the whole point: a policy hash on its own
is a capability, and a capability anyone can exercise is worthless. Here the
owner says *"this key may spend under these caps"*, and the chain remembers it.

`len` is bounded by `MAX_POLICY_BYTES` (4096) and checked against the
remaining buffer before any allocation.

### 21.3 Publication rules

A publication is refused unless **all** of the following hold:

1. the grant decodes and passes `SpendPolicy::validate`;
2. the grant's `owner` equals the signer's address;
3. the grant's `network_id` equals the state's network;
4. the grant is not itself revoked - a revoked grant is published by revoking,
   not by publishing;
5. the grant's `agent_id` equals the `agent_id` the transaction names;
6. the agent has **no live grant** - one grant per agent at a time, so a second
   grant cannot be used to double the first one's caps (a revoked grant may be
   replaced);
7. if the grant is delegated, its parent grant is on chain, is live, and
   **dominates** it (§18.2.1): the child's caps are not wider than the parent's,
   its allow-lists are not wider, and it does not outlive it.

The fee is charged from the owner's balance, like every other L2 fee (§15.1).

### 21.4 Revocation

```
PolicyRevokePayload = owner(20) ‖ auth ‖ agent_id(20)
```

The owner of the grant kills it. The grant stays in state with its `revoked`
flag set, and **every descendant of it dies with it**: a spend checks the whole
ancestry, so the kill switch reaches a delegated fleet without a revocation
transaction per link. The walk is bounded by the delegation depth cap
(`MAX_DELEGATION_DEPTH` = 8) and fails closed - a missing ancestor, a revoked
one, or a chain deeper than the cap all mean "not live".

### 21.5 Spending under a grant

```
AgentSpendPayload = agent(20) ‖ auth ‖ policy_hash(32) ‖ nonce(u64) ‖
                    recipient(20) ‖ amount_sat(u64) ‖ service_tag(u8)[+32]
```

The spend is signed by the **spender**, not by the owner: the owner signed once,
at publication, and the grant itself authorises every later spend. The chain
checks, in this order:

1. the grant is on chain, and the signer is the **spender** the grant names;
2. the grant is live: not revoked, and no revoked ancestor;
3. the grant is for this network;
4. the height is inside the grant's validity window
   (`not_before_height` inclusive, `expires_at_height` exclusive);
5. `amount_sat` is positive and at most `per_tx_max_sat`;
6. the recipient is on `allowed_recipients` - **an empty list allows nothing**;
7. the service tag follows the grant: a tagged request must name a tag on
   `allowed_services`, and a grant that names services authorises **no untagged
   spending**;
8. the nonce is **strictly greater** than the grant's last nonce;
9. the height has not run backwards inside the grant;
10. the spend inside the current tumbling window stays within
    `cumulative_max_sat`.

The money: the grant's **owner** balance pays the recipient the amount and the
fee on top. A grant is an allowance over the owner's own funds; the spender is
the key that exercises it.

The counters the chain keeps are `window_start_height`, `spent_in_window_sat`,
`total_spent_sat`, `last_nonce` and `spends`. Without them a per-window cap is
a suggestion and a nonce is a formality.

**Offline verifiers check liveness, not just the signature.** An
authorization carries no expiry itself — it borrows its window from the
grant it names. Any service that verifies offline (a receipt check, a
delivery handoff, an x402 retry) must run the grant check too:
owner match, signature valid, grant not revoked, height inside
`[not_before_height, expires_at_height)`. A stale grant verifies as bytes
and must not verify as authority (`verify_authorization_for_policy`).

### 21.6 Commitment

A published grant is a leaf under the Layer-2 state root, with its own domain
tag (`POLICY_LEAF_TAG` = `0x05`), committing to the grant hash, the spender, the
agent identity, the kill switch and the three counters that make a cap
enforceable. The leaf list is: account leaves (address order), exit leaves
(`(owner, nonce)` order), policy leaves (hash order).

### 21.7 Failure model

A malformed payload is skipped by the replayer, as any malformed Layer-2
payload is (§19.1). A payload that is well-formed but **unauthorised** - a
grant for another owner, a grant that widens its parent, a spend above a cap,
a spend under a revoked grant - is refused by the state machine by name
(`PolicyBinding`, `PolicyLimit`, `PolicyRecipient`, `PolicyService`,
`PolicyNonce`, `PolicyRevoked`, `PolicyWindow`, `PolicyAlreadyPublished`,
`UnknownPolicy`), and the refusal never moves value.

### 21.8 Fees

| Type | Code | Fee (sat) |
|---|---:|---:|
| `Policy` | `0x16` | 2 000 |
| `PolicyRevoke` | `0x17` | 2 000 |
| `AgentSpend` | `0x18` | 2 000 |

Same tier as `ClaimTask` / `ExitQueue`: a signed record, no arbitration.

### 21.9 Implemented surface

`srct-core::l2` carries the three payload types and their wire codes;
`srct-core::agent` carries `PolicyEntry` (the grant, the spender, the counters)
and its leaf; `srct-l2::state` applies them and commits them.
`crates/srct-l2/tests/policy_flow.rs` pins: publication changes the committed
root; a grant naming another owner is refused; an agent has one live grant at a
time; a spend moves value from the grant owner; the per-transaction cap binds;
the window cap binds and the window rolls over; an empty allow-list allows
nothing; a recipient outside the list is refused; the service rules refuse
both an unknown tag and an untagged spend under a tagged grant; a repeated
nonce is refused and the identical bytes are refused as a replay; only the
named spender may exercise a grant; a revoked grant authorises nothing; a
revoked parent kills its descendant; a widening grant is refused; the state
encoding round-trips the grants; and two nodes replaying the same transactions
agree on the root.

### 21.10 Portable policy surface (off-chain, non-consensus)

The grants of §21.5–§21.9 settle on this chain, but their *authority* is
portable and specified in `docs/portable-policy.md` (Decision 30), not here:
a `SignedPolicy` (grant + owner signature, verifiable with the bytes alone),
a `DelegationProof` (the root-first signed chain, every link verified and
every narrowing link checked), and a `BoundAuthorization` (the owner signs
grant + expiry + exact transaction hash, 30-block lifetime cap) admitted via
`service::admit_bound_payment`. The chain-agnostic engine crate
`crates/srct-policy` decides `PaymentIntent` → allow / deny /
approval-needed with no consensus imports. None of this moves a coin on its
own: settlement still requires a §21 spend the state machine admits.

---

## 22. Credit positions on chain (Phase 7)

### 22.1 Why this section exists

The credit facility of §18.4 was a **node-local** ledger of IOUs. Three
things were wrong with it, and each was a hole rather than a limitation:

1. **No coin moved.** `POST /v1/credit/deposit` credited a local balance and
   the code said so itself: *"This credits the local book only - no coin
   moves."* A credit line nobody can fund is a number.
2. **No lender signature.** `POST /v1/credit/open` accepted a `spec_hex` whose
   `lender` field was just a field. Anybody could open a position naming a
   lender who had never agreed to lend, and the record would say the lender
   owed the debt.
3. **Nobody else could see it.** The book lived in one node's `state.bin`, so
   a borrower with a line on one node had no line at all on another.

This section makes a loan a chain fact. The vocabulary is four transaction
types:

| Type | Code | Actor | Purpose |
|---|---:|---|---|
| `CreditOpen` | `0x19` | **lender** | open a position; the principal moves to the borrower |
| `CreditCollateral` | `0x1A` | borrower | add collateral to a position |
| `CreditRepay` | `0x1B` | borrower | repay (interest first, then principal) |
| `CreditDefault` | `0x1C` | anyone | settle a position that was not repaid by its deadline |

### 22.2 The position

```
CreditOpenPayload = lender(20) ‖ auth ‖ borrower(20) ‖ amount_sat(u64) ‖
                    collateral_sat(u64) ‖ rate_bps_per_window(u32) ‖
                    window_blocks(u64) ‖ deadline_height(u64) ‖ nonce(u64)
```

The **lender** signs, and the signature covers every term. That is the whole
difference between a loan and a claim: the lender agreed to these terms, and
the chain holds the agreement.

The position id is derived from the terms:

```
position_id = SHA256("srct/l2/credit-position/v1" ‖
                      lender ‖ borrower ‖ amount ‖ collateral ‖ rate ‖
                      window ‖ deadline ‖ nonce)
```

so two positions differing in any term are different positions, and one set of
terms is one position.

### 22.3 Opening

A position is refused unless **all** of the following hold:

1. the principal and the collateral are both positive;
2. the window is non-zero;
3. the rate is at most `MAX_CREDIT_RATE_BPS_PER_WINDOW` (1 000 bps, i.e. 10 %
   per window) - a rate above the cap is refused rather than clamped, because a
   silent clamp would hide what the lender asked for;
4. the deadline is above the current height;
5. the collateral meets the requirement, which without a bond is
    **full collateralisation** (`CreditTerms::default().required_collateral`,
    the same arithmetic the node-local book used, with a zero bond);
6. the term set itself is valid: `min_collateral_bps` must be non-zero — a
    zero collateral floor is refused where the arithmetic lives
    (`required_collateral`), so no caller can admit a zero-collateral line;
7. the position id is new;
8. the lender can fund the principal and the fee, and the borrower can fund
   the collateral **from its own balance** - the collateral is checked before
   the principal arrives, so the borrowed money cannot secure itself.

Then the value moves: the lender's balance pays the principal and the fee, the
borrower's balance receives the principal, the borrower's balance locks the
collateral, and the fee splits 50/50 into burn and reserve like every other L2
fee.

### 22.4 Repayment

Repayment is signed by the borrower. Interest is charged first, then principal
- the same order and the same reason as the node-local book. Interest is
simple interest per whole window on the outstanding principal:

```
interest = principal x rate_bps x windows / 10 000
windows  = (height - interest_settled_height) / window_blocks
```

The position remembers the height up to which interest has been charged, so
two instalments do not each pay for the whole elapsed time.

When the outstanding principal reaches zero the position is `Repaid` and the
collateral returns to the borrower.

### 22.5 Default

A default is **permissionless**: anyone may trigger the settlement of an
overdue position, because a default only the lender could trigger is a default
that could be delayed. The triggerer pays the fee.

At or after the deadline:

- the debt is the outstanding principal plus the interest accrued to this
  height;
- the collateral answers for it: the lender receives `min(collateral, debt)`;
- the surplus returns to the borrower - a default takes what is owed and no
  more;
- what the collateral does not cover is a **shortfall the lender absorbs**,
  not a loss the protocol invents money to cover.

The position becomes `Defaulted` and cannot be repaid or defaulted again.

### 22.6 Commitment and conservation

A position is a leaf under the Layer-2 state root with its own domain tag
(`CREDIT_LEAF_TAG` = `0x06`), committing to the id, the two parties, the
principal, the outstanding debt, the interest paid, the collateral, the charge
schedule, the opening height, the deadline and the state.

Collateral is held in a `credit_locked` bucket that is part of the
conservation sum: it is in the system, but not spendable. The invariant
`conservation_total() == funded_total()` holds after every credit transition.

### 22.7 Fees

| Type | Code | Fee (sat) |
|---|---:|---:|
| `CreditOpen` | `0x19` | 2 000 |
| `CreditCollateral` | `0x1A` | 2 000 |
| `CreditRepay` | `0x1B` | 2 000 |
| `CreditDefault` | `0x1C` | 2 000 |

### 22.8 Implemented surface

`srct-core::l2` carries the four payload types and their wire codes;
`srct-core::credit` keeps the arithmetic (the collateral rule and the interest
rule) so there is one implementation of each; `srct-l2::state` applies them,
holds the positions and commits them.
`crates/srct-l2/tests/credit_flow.rs` pins: the principal moves to the borrower
and the collateral locks; a loan the lender did not sign is refused; an
undercollateralised loan is refused; an unusable term is refused; a repayment
pays interest first and then principal; a fully repaid position returns the
collateral; only the borrower may repay; collateral can be posted after the
loan; a default before the deadline is refused; a default pays the lender from
the collateral and reports the shortfall; a default returns the surplus to the
borrower; a closed position cannot be settled twice; the state encoding
round-trips the positions; and two nodes replaying the same loan agree on the
root.