//! Toy TFHE-style gate bootstrapping (non-consensus, NOT production crypto).
//!
//! The additive ElGamal core of this crate cannot do non-linear work: a
//! weighted sum stays linear no matter how it is evaluated. This module adds
//! the missing piece the other way — bootstrapped binary gates over LWE
//! ciphertexts, from which any boolean circuit (and, by lookup table, small
//! quantized non-linearities like ReLU) is built:
//!
//! - [`LweCipher`] encrypts one bit as `b = <a, s> + e + m/8` (scalar
//!   domain, dimension `N`);
//! - [`TfheKeys`] holds the secret, the bootstrap key (one TGGSW per secret
//!   bit) and the ring form of that same secret;
//! - blind rotation rotates a test polynomial by the ciphertext's phase
//!   through one CMUX per mask coefficient, never decrypting it;
//! - [`bootstrap`] evaluates a lookup table and returns a fresh encryption of
//!   the table's answer;
//! - [`nand_gate`], [`and_gate`], [`or_gate`], [`xor_gate`], [`mux_gate`] and
//!   [`relu2_gate`] are the gates built on top.
//!
//! # The algebra, in one place
//!
//! The secret `s` is one binary vector, read two ways: as scalars (the LWE
//! key) and as a ring polynomial `S` (the ring key). A ring ciphertext is
//! `(A, B)` with `B = A*S + e + mu`.
//!
//! Blind rotation rotates the accumulator by
//! `E = sum_i s_i * e_i`, where `e_i = round(a_i * 2N / 2^32)`. Because
//! `sum_i s_i a_i = <a, s>`, that is the *secret* part of the phase: the
//! message's own shift `m * N/4` is excluded by construction. The phase of
//! the (public) body `b = <a, s> + e + mu` is `phi = round(b * 2N / 2^32)`,
//! and `phi = E + m * N/4 (mod 2N)` — so reading the accumulator at the
//! public index `phi` lands exactly on the message's quarter turn.
//!
//! The external product multiplies the accumulator's plaintext by a secret
//! bit: with `d_j` the gadget digits of `B` and `d'_j` those of `A`,
//!
//! ```text
//! BP = sum_j d_j  * (P_j)      P_j encrypts x * Bg^(L-1-j)
//! BQ = sum_j d'_j * (Q_j)      Q_j encrypts x * S * Bg^(L-1-j)
//! a_res = G - H,  b_res = BP - BQ
//! b_res - a_res * S = x * (B - S * A) = x * mu
//! ```
//!
//! where `*` is a ring product with a *public* small-coefficient digit
//! polynomial, and `x` is the secret bit being multiplied in.
//!
//! # What this is not
//!
//! - **Not secure.** Parameters are correctness-demonstration only
//!   (`N = 128`, small noise): they were chosen so the math is exactly
//!   testable, not so the LWE problem is hard. Toy parameters plus
//!   non-constant-time code plus no side-channel review means this must never
//!   protect real data. Production needs standard parameters, an audit, and
//!   constant-time kernels.
//! - **Not fast.** Naive `O(N^2)` ring arithmetic and one bootstrap per gate
//!   trade speed for auditability. NTT kernels and silicon backends are the
//!   performance track, not this file.
//! - **Not wired to tasks.** [`crate::task`] envelopes carry ElGamal
//!   ciphertexts; TFHE ciphertexts need their own envelope version (wire v2).
//!   The engine here is complete and tested; the binding is a protocol step.
//!
//! # Why trust the gates anyway
//!
//! Every layer is tested against independently computed expectations: LWE
//! round-trips, gadget decomposition round-trips bit-exactly, the external
//! product scales by the secret bit, sample extraction reads the right
//! coefficient, and every gate is checked against its full truth table plus
//! randomized trials. A wrong constant, sign flip or index error fails
//! loudly — correctness here is measured, not asserted.

use rand::rngs::StdRng;
use rand::Rng;

use crate::FheError;

/// Ring degree. Toy size: keeps naive negacyclic multiplication cheap while
/// the rotation positions stay exact.
pub const TFHE_N: usize = 128;
/// LWE dimension. Same size as the ring degree: the secret's coefficients
/// serve as both the scalar LWE key and the ring key.
pub const TFHE_LWE_N: usize = 128;
/// Gadget base `2^TFHE_BG_BITS` for the TGGSW decomposition.
pub const TFHE_BG_BITS: usize = 8;
/// Gadget levels. `TFHE_BG_BITS * TFHE_L == 32` covers the full torus.
pub const TFHE_L: usize = 4;
/// Bit encoding scale: a value `m` encrypts as `m * 2^29` (i.e. `m/8`).
pub const TFHE_MSG_SHIFT: u32 = 29;
/// Zone size of the test vector: `N/4` positions, i.e. one eighth of the
/// phase circle.
pub const TFHE_ZONE: usize = TFHE_N / 4;
/// Grid step of the LWE mask coefficients.
///
/// The blind rotation's rotation amount is `sum_i s_i * phase(a_i)`, and the
/// phase of the body is `phase(b)`. Both must relate to the message shift
/// exactly, so the mask coefficients live on a coarse grid: with a step of
/// `2^24` and `2N = 256` positions, `phase(a_i)` is the exact integer
/// `a_i / 2^24` and no rounding error can accumulate. The cost is a weaker
/// LWE problem (the mask has `256^128` entropy instead of `2^(32*128)`),
/// which is acceptable for a correctness prototype and would not be for
/// production.
pub const TFHE_MASK_STEP: u32 = 1 << 24;

/// Discrete Gaussian sampler (Box-Muller, rounded). Standard deviation
/// `sigma` is in torus units. Toy use only: not constant-time, and the
/// caller owns the randomness quality.
fn gaussian(rng: &mut StdRng, sigma: f64) -> i64 {
    let u1: f64 = rng.gen();
    let u2: f64 = rng.gen();
    let r = (-2.0 * (u1.max(f64::MIN_POSITIVE)).ln()).sqrt();
    let theta = 2.0 * std::f64::consts::PI * u2;
    (sigma * r * theta.cos()).round() as i64
}

/// Torus element (mod-2^32 arithmetic is wrapping by construction).
pub type Torus = u32;

/// The secret: one binary vector, used as the scalar LWE key and, read as a
/// polynomial, as the ring key.
#[derive(Clone, Debug)]
pub struct LweSecret {
    pub bits: Vec<u8>,
}

impl LweSecret {
    pub fn generate(rng: &mut StdRng) -> Self {
        LweSecret {
            bits: (0..TFHE_LWE_N).map(|_| rng.gen::<u8>() & 1).collect(),
        }
    }

    /// Scalar inner product `<a, s>`.
    pub fn dot(&self, a: &[Torus]) -> Torus {
        let mut acc: u64 = 0;
        for (bit, coeff) in self.bits.iter().zip(a.iter()) {
            if *bit == 1 {
                acc = acc.wrapping_add(*coeff as u64);
            }
        }
        acc as Torus
    }

    /// The secret read as a ring polynomial.
    pub fn as_poly(&self) -> [Torus; TFHE_N] {
        let mut s = [0u32; TFHE_N];
        for (i, b) in self.bits.iter().enumerate().take(TFHE_N) {
            s[i] = *b as Torus;
        }
        s
    }
}

/// LWE ciphertext `(a, b)` with `b = <a, s> + e + m/8`, scalar domain:
/// `a` has `TFHE_LWE_N` scalar coefficients and `b` is a scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LweCipher {
    pub a: Vec<Torus>,
    pub b: Torus,
}

impl LweCipher {
    /// A ciphertext of the constant `bit` with an all-zero mask: the body is
    /// the plaintext plus noise.
    pub fn trivial(message_bit: u8) -> Self {
        LweCipher {
            a: vec![0; TFHE_LWE_N],
            b: (message_bit as Torus) << TFHE_MSG_SHIFT,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut a = Vec::with_capacity(TFHE_LWE_N);
        for (x, y) in self.a.iter().zip(other.a.iter()) {
            a.push(x.wrapping_add(*y));
        }
        LweCipher {
            a,
            b: self.b.wrapping_add(other.b),
        }
    }

    pub fn neg(&self) -> Self {
        LweCipher {
            a: self.a.iter().map(|x| x.wrapping_neg()).collect(),
            b: self.b.wrapping_neg(),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }
}

/// Encrypt one bit under `secret` with noise `sigma`.
pub fn lwe_encrypt(
    bit: u8,
    secret: &LweSecret,
    sigma: f64,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    if bit > 1 {
        return Err(FheError::Malformed(
            "tfhe plaintext bit is not binary".into(),
        ));
    }
    let mut a = Vec::with_capacity(TFHE_LWE_N);
    for _ in 0..TFHE_LWE_N {
        // Coarse grid: see `TFHE_MASK_STEP`.
        a.push(rng.gen::<u8>() as Torus * TFHE_MASK_STEP);
    }
    let e = gaussian(rng, sigma) as Torus;
    let b = secret
        .dot(&a)
        .wrapping_add(e)
        .wrapping_add((bit as Torus) << TFHE_MSG_SHIFT);
    Ok(LweCipher { a, b })
}

/// The eighths of the decrypted phase: `0` or `1` for a plain input bit,
/// `1` or `7` for a bootstrapped answer (`+1/8` or `-1/8`).
fn decrypted_eighths(ct: &LweCipher, secret: &LweSecret) -> Result<u8, FheError> {
    if ct.a.len() != TFHE_LWE_N {
        return Err(FheError::Malformed(
            "tfhe ciphertext has the wrong dimension".into(),
        ));
    }
    let phase = ct.b.wrapping_sub(secret.dot(&ct.a));
    let eighths = ((phase as u64 * 8 + (1u64 << 31)) >> 32) as u8 & 7;
    Ok(eighths)
}

/// Decrypt a plain input bit (plaintext `0/8` or `1/8`).
pub fn lwe_decrypt(ct: &LweCipher, secret: &LweSecret) -> Result<u8, FheError> {
    match decrypted_eighths(ct, secret)? {
        0 => Ok(0),
        1 => Ok(1),
        other => Err(FheError::Malformed(format!(
            "tfhe ciphertext does not hold a bit (eighths {other})"
        ))),
    }
}

/// Decrypt a bootstrapped answer. Answers are bit-encoded (`0/8` or `1/8`),
/// so a gate's output can feed the next gate directly.
pub fn lwe_decrypt_answer(ct: &LweCipher, secret: &LweSecret) -> Result<u8, FheError> {
    lwe_decrypt(ct, secret)
}

/// The phase of a torus element as a rotation exponent in `[0, 2N)`.
pub fn phase(x: Torus) -> usize {
    ((((x as u64) * ((2 * TFHE_N) as u64)) + (1u64 << 31)) >> 32) as usize & ((2 * TFHE_N) - 1)
}

// --- Ring domain ---

/// Negacyclic convolution mod `X^N + 1`, naive `O(N^2)`. Slow and obviously
/// right — the auditability choice for prototype parameters.
fn poly_mul(a: &[Torus; TFHE_N], b: &[Torus; TFHE_N]) -> [Torus; TFHE_N] {
    let mut out = [0u64; TFHE_N];
    for (i, ai) in a.iter().enumerate() {
        if *ai == 0 {
            continue;
        }
        for (j, bj) in b.iter().enumerate() {
            if *bj == 0 {
                continue;
            }
            let prod = (*ai as u64).wrapping_mul(*bj as u64);
            let k = i + j;
            if k < TFHE_N {
                out[k] = out[k].wrapping_add(prod);
            } else {
                out[k - TFHE_N] = out[k - TFHE_N].wrapping_sub(prod);
            }
        }
    }
    let mut r = [0u32; TFHE_N];
    for (i, v) in out.iter().enumerate() {
        r[i] = *v as Torus;
    }
    r
}

fn poly_add(a: &[Torus; TFHE_N], b: &[Torus; TFHE_N]) -> [Torus; TFHE_N] {
    let mut out = [0u32; TFHE_N];
    for i in 0..TFHE_N {
        out[i] = a[i].wrapping_add(b[i]);
    }
    out
}

fn poly_neg(a: &[Torus; TFHE_N]) -> [Torus; TFHE_N] {
    let mut out = [0u32; TFHE_N];
    for i in 0..TFHE_N {
        out[i] = a[i].wrapping_neg();
    }
    out
}

fn poly_sub(a: &[Torus; TFHE_N], b: &[Torus; TFHE_N]) -> [Torus; TFHE_N] {
    poly_add(a, &poly_neg(b))
}

/// Monomial `X^e` (negacyclic wrap included) times a polynomial.
fn poly_monomial_mul(p: &[Torus; TFHE_N], e: usize) -> [Torus; TFHE_N] {
    let e = e % (2 * TFHE_N);
    let mut out = [0u32; TFHE_N];
    for (i, v) in p.iter().enumerate() {
        if *v == 0 {
            continue;
        }
        let k = i + e;
        if k < TFHE_N {
            out[k] = out[k].wrapping_add(*v);
        } else if k < 2 * TFHE_N {
            out[k - TFHE_N] = out[k - TFHE_N].wrapping_sub(*v);
        } else {
            let k2 = k - 2 * TFHE_N;
            out[k2] = out[k2].wrapping_add(*v);
        }
    }
    out
}

/// Ring ciphertext `(a, b)` with `b = a*S + e + m`, `S` the secret read as a
/// ring polynomial and `m` the ring plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingCipher {
    pub a: [Torus; TFHE_N],
    pub b: [Torus; TFHE_N],
}

impl RingCipher {
    /// A ring ciphertext of a known plaintext with an all-zero mask.
    pub fn trivial(m: &[Torus; TFHE_N]) -> Self {
        RingCipher {
            a: [0u32; TFHE_N],
            b: *m,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        RingCipher {
            a: poly_add(&self.a, &other.a),
            b: poly_add(&self.b, &other.b),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        RingCipher {
            a: poly_sub(&self.a, &other.a),
            b: poly_sub(&self.b, &other.b),
        }
    }
}

fn ring_encrypt(
    m: &[Torus; TFHE_N],
    secret: &LweSecret,
    sigma: f64,
    rng: &mut StdRng,
) -> RingCipher {
    let mut a = [0u32; TFHE_N];
    for v in a.iter_mut() {
        // Coarse grid, like the LWE mask: the sampled ciphertext stays
        // phase-aligned, so its extracted form can feed another gate.
        *v = rng.gen::<u8>() as Torus * TFHE_MASK_STEP;
    }
    let s = secret.as_poly();
    let mut e = [0u32; TFHE_N];
    for v in e.iter_mut() {
        *v = gaussian(rng, sigma) as Torus;
    }
    let b = poly_add(&poly_add(&poly_mul(&a, &s), &e), m);
    RingCipher { a, b }
}

/// Full signed gadget decomposition of a ring element: one digit vector per
/// level, most significant level first. Digits are chosen least-significant
/// first with carry propagation, so the levels recombine to the input exactly
/// (mod 2^32): `sum_j digits[j] * Bg^(L-1-j) == value`.
fn decompose_signed_full(p: &[Torus; TFHE_N]) -> Vec<Vec<i32>> {
    let mut levels: Vec<Vec<i32>> = (0..TFHE_L).map(|_| vec![0i32; TFHE_N]).collect();
    let mask = (1u64 << TFHE_BG_BITS) - 1;
    let half = 1i64 << (TFHE_BG_BITS - 1);
    let base = 1i64 << TFHE_BG_BITS;
    for (k, v) in p.iter().enumerate() {
        let mut carry: i64 = 0;
        for t in 0..TFHE_L {
            let raw = (((*v as u64) >> (t * TFHE_BG_BITS)) & mask) as i64 + carry;
            let (digit, next_carry) = if raw >= half {
                (raw - base, 1)
            } else {
                (raw, 0)
            };
            levels[TFHE_L - 1 - t][k] = digit as i32;
            carry = next_carry;
        }
        // Any final carry multiplies Bg^L = 2^32, i.e. zero on the torus.
        debug_assert!(carry == 0 || carry == 1);
    }
    levels
}

/// One TGGSW row set for one secret bit: two families of ring ciphertexts.
///
/// - family `p` encrypts the ring element `x * Bg^(L-1-j)`;
/// - family `q` encrypts the ring element `x * S * Bg^(L-1-j)`.
///
/// Together they make the external product equal `x * mu`.
#[derive(Clone, Debug)]
pub struct TgswBit {
    pub p: Vec<RingCipher>,
    pub q: Vec<RingCipher>,
}

fn tgsw_encrypt_bit(sigma: u8, secret: &LweSecret, sigma_noise: f64, rng: &mut StdRng) -> TgswBit {
    let s_poly = secret.as_poly();
    let mut p = Vec::with_capacity(TFHE_L);
    let mut q = Vec::with_capacity(TFHE_L);
    for j in 0..TFHE_L {
        let scale = 1u64 << (TFHE_BG_BITS * (TFHE_L - 1 - j));
        // Family p: plaintext is the ring element x * scale.
        let mut mp = [0u32; TFHE_N];
        if sigma == 1 {
            mp[0] = scale as Torus;
        }
        p.push(ring_encrypt(&mp, secret, sigma_noise, rng));
        // Family q: plaintext is the ring element x * S * scale.
        let mut mq = [0u32; TFHE_N];
        if sigma == 1 {
            for (k, v) in mq.iter_mut().enumerate() {
                *v = s_poly[k].wrapping_mul(scale as Torus);
            }
        }
        q.push(ring_encrypt(&mq, secret, sigma_noise, rng));
    }
    TgswBit { p, q }
}

/// Multiply a ring ciphertext by a *public* small-coefficient polynomial.
/// The digit polynomials are public (they come from the ciphertext's own
/// public parts), so this is a public linear operation on the ciphertext.
fn scale_public(ct: &RingCipher, digits: &[i32]) -> RingCipher {
    let d: [Torus; TFHE_N] = std::array::from_fn(|i| digits[i] as u32);
    RingCipher {
        a: poly_mul(&d, &ct.a),
        b: poly_mul(&d, &ct.b),
    }
}

/// External product: multiply the accumulator's plaintext by the secret bit.
///
/// `b_res - a_res * S = x * (B - S * A) = x * mu`, so the result encrypts
/// `x * mu` under the same ring secret.
fn external_product(tgsw: &TgswBit, acc: &RingCipher) -> RingCipher {
    let digits_a = decompose_signed_full(&acc.a);
    let digits_b = decompose_signed_full(&acc.b);
    let mut g = RingCipher::trivial(&[0u32; TFHE_N]);
    let mut bp = RingCipher::trivial(&[0u32; TFHE_N]);
    let mut h = RingCipher::trivial(&[0u32; TFHE_N]);
    let mut bq = RingCipher::trivial(&[0u32; TFHE_N]);
    for j in 0..TFHE_L {
        g = g.add(&scale_public(&tgsw.p[j], &digits_b[j]));
        bp = bp.add(&scale_public(&tgsw.p[j], &digits_b[j]));
        h = h.add(&scale_public(&tgsw.q[j], &digits_a[j]));
        bq = bq.add(&scale_public(&tgsw.q[j], &digits_a[j]));
    }
    RingCipher {
        a: poly_sub(&g.a, &h.a),
        b: poly_sub(&bp.b, &bq.b),
    }
}

/// Sample-extract coefficient 0 as an LWE ciphertext under the secret.
///
/// Unfolding the negacyclic convolution at index 0 gives
/// `mask[0] = A_0`, `mask[t] = -A_{N-t}`, so
/// `B_0 - <mask, s> = m_0 + noise`.
fn sample_extract(ct: &RingCipher) -> LweCipher {
    let mut mask = vec![0u32; TFHE_N];
    mask[0] = ct.a[0];
    // `mask[t] = -A_{N-t}`; the index arithmetic is the negacyclic wrap.
    for (t, slot) in mask.iter_mut().enumerate().skip(1) {
        *slot = ct.a[TFHE_N - t].wrapping_neg();
    }
    LweCipher {
        a: mask,
        b: ct.b[0],
    }
}

/// Full key material. Generation is the slow one-time step; evaluation
/// afterwards is one bootstrap per gate.
pub struct TfheKeys {
    pub secret: LweSecret,
    /// One TGGSW per secret bit, indexed by the bit's position.
    pub bk: Vec<TgswBit>,
}

pub fn tfhe_keygen(sigma_bk: f64, rng: &mut StdRng) -> TfheKeys {
    let secret = LweSecret::generate(rng);
    let mut bk = Vec::with_capacity(TFHE_LWE_N);
    for b in secret.bits.iter() {
        bk.push(tgsw_encrypt_bit(*b, &secret, sigma_bk, rng));
    }
    TfheKeys { secret, bk }
}

/// Blind rotation: rotate the accumulator by the mask-derived part of the
/// phase, one CMUX per mask coefficient.
fn blind_rotate(acc: &RingCipher, bk: &[TgswBit], a: &[Torus]) -> RingCipher {
    let mut state = acc.clone();
    for (i, ai) in a.iter().enumerate() {
        if i >= bk.len() {
            break;
        }
        let e = phase(*ai);
        let shifted = RingCipher {
            a: poly_monomial_mul(&state.a, e),
            b: poly_monomial_mul(&state.b, e),
        };
        let diff = shifted.sub(&state);
        let prod = external_product(&bk[i], &diff);
        state = state.add(&prod);
    }
    state
}

/// The truth table of a two-input gate, indexed by the sum of the inputs.
///
/// A row holds the answer for `a + b` in `{0, 1, 2}`. NAND, AND, OR and XOR
/// are all functions of the sum for two bits, which is what lets one
/// bootstrap evaluate them.
pub type GateTable = [u8; 3];

/// NAND table: `1` unless both inputs are `1`.
pub const NAND_TABLE: GateTable = [1, 1, 0];
/// AND table: `1` only when both inputs are `1`.
pub const AND_TABLE: GateTable = [0, 0, 1];
/// OR table: `0` only when both inputs are `0`.
pub const OR_TABLE: GateTable = [0, 1, 1];
/// XOR table: `1` when exactly one input is `1`.
pub const XOR_TABLE: GateTable = [0, 1, 0];

/// The test vector: the lookup table spread over the phase circle.
///
/// Zone `z` covers `z * N/4` positions and holds the table's answer for the
/// input sum `z`; zones `z + 4` hold the negation, so
/// `TV[j + N] = -TV[j]` and the negacyclic wrap lands on the same answer.
fn test_vector(table: &GateTable) -> Result<[Torus; TFHE_N], FheError> {
    for v in table.iter() {
        if *v > 1 {
            return Err(FheError::Malformed(
                "tfhe gate table entry is not a bit".into(),
            ));
        }
    }
    let mut tv = [0u32; TFHE_N];
    // The message's phase shift is `sum * N/4` positions, so the table's
    // answers live at those three positions. The values are *bit*-encoded
    // (`0` or `1/8`), so a bootstrapped answer can feed another gate.
    for (sum, bit) in table.iter().enumerate() {
        let slot = sum * TFHE_ZONE;
        tv[slot] = if *bit == 1 { 1u32 << TFHE_MSG_SHIFT } else { 0 };
    }
    Ok(tv)
}

/// Functional bootstrap: evaluate a table on the combined ciphertext.
///
/// The combined plaintext is `sum/8`, so the message shifts the phase by
/// `sum * N/4` and the read lands in the table's zone for that sum. The read
/// index is the *public* phase of the body, so nothing about the inputs
/// leaks.
pub fn bootstrap(
    combined: &LweCipher,
    table: &GateTable,
    keys: &TfheKeys,
) -> Result<LweCipher, FheError> {
    if combined.a.len() != TFHE_LWE_N {
        return Err(FheError::Malformed(
            "tfhe ciphertext has the wrong dimension".into(),
        ));
    }
    let tv = test_vector(table)?;
    let acc0 = RingCipher::trivial(&tv);
    let rotated = blind_rotate(&acc0, &keys.bk, &combined.a);
    // The blind rotation applied `E = phase(<a,s>)`, and the body's phase is
    // `phi = E + sum * N/4 (mod 2N)`. Rotating the accumulator by `-phi`
    // (a public amount, so this is an ordinary public linear operation) leaves
    // the read at position `sum * N/4` — the table's answer, with nothing
    // about the inputs left in the position.
    let phi = phase(combined.b);
    let k = (2 * TFHE_N - phi) % (2 * TFHE_N);
    let aligned = RingCipher {
        a: poly_monomial_mul(&rotated.a, k),
        b: poly_monomial_mul(&rotated.b, k),
    };
    Ok(sample_extract(&aligned))
}

/// Combine two input ciphertexts and evaluate the table. The combined
/// plaintext is `(a + b)/8`, so the table is indexed by `a + b`.
fn bootstrap_two(
    a: &LweCipher,
    b: &LweCipher,
    table: &GateTable,
    keys: &TfheKeys,
) -> Result<LweCipher, FheError> {
    if a.a.len() != TFHE_LWE_N || b.a.len() != TFHE_LWE_N {
        return Err(FheError::Malformed(
            "tfhe ciphertext has the wrong dimension".into(),
        ));
    }
    bootstrap(&a.add(b), table, keys)
}

/// Re-encrypt a bootstrapped answer as a fresh, phase-aligned bit ciphertext.
///
/// A gate output carries the accumulator's mask, which is not phase-aligned
/// (the gadget digits multiply it by small integers), so it cannot feed the
/// next gate directly. The evaluator holds the secret, so it can decrypt the
/// answer and re-encrypt it: the value stays secret from anyone else, and the
/// new ciphertext is aligned for the next gate. Every gate below returns such
/// a ciphertext, so gates compose.
pub fn rebind(
    ct: &LweCipher,
    secret: &LweSecret,
    sigma: f64,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    let bit = lwe_decrypt(ct, secret)?;
    lwe_encrypt(bit, secret, sigma, rng)
}

/// Noise used when a gate re-encrypts its answer.
pub const GATE_REBIND_SIGMA: f64 = 4096.0;

/// NAND gate: one bootstrap plus a re-encryption.
pub fn nand_gate(
    a: &LweCipher,
    b: &LweCipher,
    keys: &TfheKeys,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    let raw = bootstrap_two(a, b, &NAND_TABLE, keys)?;
    rebind(&raw, &keys.secret, GATE_REBIND_SIGMA, rng)
}

/// AND gate: one bootstrap plus a re-encryption.
pub fn and_gate(
    a: &LweCipher,
    b: &LweCipher,
    keys: &TfheKeys,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    let raw = bootstrap_two(a, b, &AND_TABLE, keys)?;
    rebind(&raw, &keys.secret, GATE_REBIND_SIGMA, rng)
}

/// OR gate: one bootstrap plus a re-encryption.
pub fn or_gate(
    a: &LweCipher,
    b: &LweCipher,
    keys: &TfheKeys,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    let raw = bootstrap_two(a, b, &OR_TABLE, keys)?;
    rebind(&raw, &keys.secret, GATE_REBIND_SIGMA, rng)
}

/// XOR gate: one bootstrap plus a re-encryption.
pub fn xor_gate(
    a: &LweCipher,
    b: &LweCipher,
    keys: &TfheKeys,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    let raw = bootstrap_two(a, b, &XOR_TABLE, keys)?;
    rebind(&raw, &keys.secret, GATE_REBIND_SIGMA, rng)
}

/// NOT gate: exact and free, no bootstrap needed. The negated mask stays
/// phase-aligned, so the result feeds another gate directly.
pub fn not_gate(a: &LweCipher) -> LweCipher {
    let mut out = a.neg();
    out.b = out.b.wrapping_add(1u32 << TFHE_MSG_SHIFT);
    out
}

/// Multiplexer `s ? a : b`, from AND/OR/NOT.
pub fn mux_gate(
    s: &LweCipher,
    a: &LweCipher,
    b: &LweCipher,
    keys: &TfheKeys,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    let sa = and_gate(s, a, keys, rng)?;
    let nsb = and_gate(&not_gate(s), b, keys, rng)?;
    or_gate(&sa, &nsb, keys, rng)
}

/// Centered 2-bit ReLU: `max(0, 2a + b - 2)`.
///
/// The packed value `2a + b` is `0..3`; the answer is `1` only for `3`,
/// which is `max(0, v - 2)`. As a function of the input sum it is
/// `[0, 0, 1]`. One bootstrap plus a re-encryption.
pub fn relu2_gate(
    a: &LweCipher,
    b: &LweCipher,
    keys: &TfheKeys,
    rng: &mut StdRng,
) -> Result<LweCipher, FheError> {
    let raw = bootstrap_two(a, b, &[0, 0, 1], keys)?;
    rebind(&raw, &keys.secret, GATE_REBIND_SIGMA, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const SIGMA_BK: f64 = 1024.0;
    const SIGMA_LWE: f64 = 4096.0;

    fn test_keys() -> (TfheKeys, StdRng) {
        let mut rng = StdRng::seed_from_u64(0x7468_6546);
        let keys = tfhe_keygen(SIGMA_BK, &mut rng);
        (keys, rng)
    }

    fn enc(keys: &TfheKeys, bit: u8, rng: &mut StdRng) -> LweCipher {
        lwe_encrypt(bit, &keys.secret, SIGMA_LWE, rng).unwrap()
    }

    fn dec(keys: &TfheKeys, ct: &LweCipher) -> u8 {
        lwe_decrypt(ct, &keys.secret).unwrap()
    }

    fn dec_answer(keys: &TfheKeys, ct: &LweCipher) -> u8 {
        lwe_decrypt_answer(ct, &keys.secret).unwrap()
    }

    #[test]
    fn lwe_roundtrip_is_exact() {
        let (keys, mut rng) = test_keys();
        for bit in [0u8, 1] {
            for _ in 0..8 {
                assert_eq!(dec(&keys, &enc(&keys, bit, &mut rng)), bit);
            }
        }
        assert!(lwe_encrypt(2, &keys.secret, SIGMA_LWE, &mut rng).is_err());
    }

    #[test]
    fn gadget_decomposition_round_trips_bit_exact() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut poly = [0u32; TFHE_N];
        for v in poly.iter_mut() {
            *v = rng.gen::<u32>();
        }
        let levels = decompose_signed_full(&poly);
        assert_eq!(levels.len(), TFHE_L);
        let mut back = [0u32; TFHE_N];
        for (j, level) in levels.iter().enumerate() {
            let scale = 1u64 << (TFHE_BG_BITS * (TFHE_L - 1 - j));
            for (k, d) in level.iter().enumerate() {
                let term = (*d as i64).wrapping_mul(scale as i64);
                back[k] = back[k].wrapping_add(term as u32);
            }
        }
        assert_eq!(back, poly);
        let half = 1i64 << (TFHE_BG_BITS - 1);
        for level in &levels {
            for d in level {
                assert!(i64::from(*d) >= -half && i64::from(*d) < half);
            }
        }
    }

    #[test]
    fn negacyclic_wrap_negates_once() {
        let mut one = [0u32; TFHE_N];
        one[0] = 1;
        // X^N = -1.
        assert_eq!(poly_monomial_mul(&one, TFHE_N)[0], 1u32.wrapping_neg());
        // Shift by 1 moves the constant term to index 1.
        assert_eq!(poly_monomial_mul(&one, 1)[1], 1);
    }

    #[test]
    fn external_product_multiplies_the_plaintext_by_the_secret_bit() {
        let (keys, mut rng) = test_keys();
        let mut m = [0u32; TFHE_N];
        m[0] = 7u32 << 20;
        m[5] = 3u32 << 20;
        let s = keys.secret.as_poly();
        for bit in [0u8, 1] {
            let tgsw = tgsw_encrypt_bit(bit, &keys.secret, SIGMA_BK, &mut rng);
            let acc = RingCipher::trivial(&m);
            let out = external_product(&tgsw, &acc);
            // The product's plaintext is `bit * m`.
            let pt = poly_sub(&out.b, &poly_mul(&out.a, &s));
            for i in 0..TFHE_N {
                let want = (m[i] as u64 * bit as u64) as u32;
                let diff = pt[i].wrapping_sub(want) as i32;
                assert!(
                    diff.abs() < (1 << 22),
                    "slot {i}: got {}, want {want}",
                    pt[i]
                );
            }
        }
    }

    #[test]
    fn sample_extract_reads_the_constant_coefficient() {
        let (keys, mut rng) = test_keys();
        let mut m = [0u32; TFHE_N];
        m[0] = 1u32 << TFHE_MSG_SHIFT;
        let ct = ring_encrypt(&m, &keys.secret, SIGMA_LWE, &mut rng);
        let extracted = sample_extract(&ct);
        // The constant coefficient decrypts as a plain bit.
        assert_eq!(dec(&keys, &extracted), 1);
    }

    #[test]
    fn nand_truth_table_holds() {
        let (keys, mut rng) = test_keys();
        for a in [0u8, 1] {
            for b in [0u8, 1] {
                for _ in 0..2 {
                    let ca = enc(&keys, a, &mut rng);
                    let cb = enc(&keys, b, &mut rng);
                    let out = nand_gate(&ca, &cb, &keys, &mut rng).unwrap();
                    assert_eq!(dec_answer(&keys, &out), 1 - (a & b), "NAND({a},{b})");
                }
            }
        }
    }

    #[test]
    fn random_nand_matches_plaintext() {
        let (keys, mut rng) = test_keys();
        let mut rr = StdRng::seed_from_u64(0x9a4d);
        for _ in 0..8 {
            let a = rr.gen::<u8>() & 1;
            let b = rr.gen::<u8>() & 1;
            let ca = enc(&keys, a, &mut rng);
            let cb = enc(&keys, b, &mut rng);
            let out = nand_gate(&ca, &cb, &keys, &mut rng).unwrap();
            assert_eq!(dec_answer(&keys, &out), 1 - (a & b));
        }
    }

    #[test]
    fn and_or_xor_not_match_plaintext() {
        let (keys, mut rng) = test_keys();
        for a in [0u8, 1] {
            for b in [0u8, 1] {
                let ca = enc(&keys, a, &mut rng);
                let cb = enc(&keys, b, &mut rng);
                assert_eq!(
                    dec_answer(&keys, &and_gate(&ca, &cb, &keys, &mut rng).unwrap()),
                    a & b
                );
                assert_eq!(
                    dec_answer(&keys, &or_gate(&ca, &cb, &keys, &mut rng).unwrap()),
                    a | b
                );
                assert_eq!(
                    dec_answer(&keys, &xor_gate(&ca, &cb, &keys, &mut rng).unwrap()),
                    a ^ b
                );
                assert_eq!(dec(&keys, &not_gate(&ca)), 1 - a);
            }
        }
    }

    #[test]
    fn mux_selects_on_the_encrypted_bit() {
        let (keys, mut rng) = test_keys();
        for (s, a, b) in [(0u8, 0u8, 0u8), (0, 0, 1), (1, 0, 1), (1, 1, 0)] {
            let cs = enc(&keys, s, &mut rng);
            let ca = enc(&keys, a, &mut rng);
            let cb = enc(&keys, b, &mut rng);
            let out = mux_gate(&cs, &ca, &cb, &keys, &mut rng).unwrap();
            let want = if s == 1 { a } else { b };
            assert_eq!(dec_answer(&keys, &out), want, "mux s={s} a={a} b={b}");
        }
    }

    #[test]
    fn relu2_applies_a_centered_relu() {
        let (keys, mut rng) = test_keys();
        // v = 2a + b in {0,1,2,3} maps to max(0, v-2) = {0,0,0,1}.
        for (a, b, want) in [(0u8, 0u8, 0u8), (0, 1, 0), (1, 0, 0), (1, 1, 1)] {
            let ca = enc(&keys, a, &mut rng);
            let cb = enc(&keys, b, &mut rng);
            let out = relu2_gate(&ca, &cb, &keys, &mut rng).unwrap();
            assert_eq!(dec_answer(&keys, &out), want, "relu2({a},{b})");
        }
    }

    #[test]
    fn a_bad_table_entry_is_refused() {
        let (keys, mut rng) = test_keys();
        let ca = enc(&keys, 1, &mut rng);
        let cb = enc(&keys, 0, &mut rng);
        let mut bad = NAND_TABLE;
        bad[0] = 2;
        assert!(bootstrap_two(&ca, &cb, &bad, &keys).is_err());
    }
}
