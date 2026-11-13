//! Zero-knowledge proofs of correct quantized linear evaluation, built from
//! Sigma protocols over secp256k1 — no new dependencies.
//!
//! The worker proves, in zero knowledge, that committed outputs equal a
//! public-weight linear function of committed private inputs:
//!
//! ```text
//! output = bias + Σ weights[i] * inputs[i],  inputs[i] in [0, 2^16)
//! ```
//!
//! Inputs stay hidden: the verifier sees only Pedersen commitments
//! (`Com(v, r) = vG + rH`), the public weights/bias and the proofs.
//!
//! How each link is enforced:
//!
//! - **Bits are bits.** Every input is bit-decomposed; each bit commitment
//!   carries a CDS OR-proof that it commits to 0 or 1. Forging one means
//!   breaking the proof's soundness or the discrete log.
//! - **Bits recompose.** The verifier checks `X == Σ 2^i * B_i`
//!   homomorphically — no proof needed, just curve arithmetic.
//! - **Linear evaluation.** The verifier checks
//!   `Y == Σ w_i * X_i + bias*G` homomorphically. A worker that skips the
//!   work or fabricates the output fails here.
//!
//! Proofs are non-interactive via Fiat-Shamir over the statement and the
//! prover's first messages. This is a prototype seam, not general ZKML: one
//! linear layer, at most [`MAX_INPUTS`] 16-bit inputs, no non-linearities.
//!
//! Evaluated and rejected: Bulletproofs R1CS (`bulletproofs 5.0.0`) — the
//! published crate does not compile (its `r1cs/proof.rs` calls
//! `CtOption::ok_or`, which exists in neither `subtle 2.5.0` nor `2.6.1`),
//! so depending on it was not an option.

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1, SecretKey};
use rand::rngs::StdRng;
use srct_core::hash::sha256_dom;

use crate::ZkError;

/// Bit width every private input is range-constrained to.
pub const BIT_WIDTH: usize = 16;
/// Maximum private inputs per proof: keeps proving time in milliseconds.
pub const MAX_INPUTS: usize = 8;
/// Plaintext weights stay small so evaluated sums stay in range.
pub const MAX_WEIGHT_ABS: i64 = 1_000_000;
/// Wire length of one compressed curve point.
pub const POINT_LEN: usize = 33;

const DOM_CHALLENGE: &[u8] = b"srct/zkml-or-challenge/v1";

/// Second generator for Pedersen commitments. `H = h*G` with `h` derived
/// from a fixed label — a prototype stand-in for a real nothing-up-my-sleeve
/// point (documented, not hidden).
pub(crate) fn h_generator() -> ProjectivePoint {
    let mut counter: u64 = 0;
    loop {
        let mut label = b"srct-zkml-H/".to_vec();
        label.extend_from_slice(&counter.to_be_bytes());
        let digest = sha256_dom(b"srct-zkml-H", &[&label]);
        if let Some(h) = Option::<Scalar>::from(Scalar::from_repr(digest.into())) {
            if h != Scalar::ZERO {
                return ProjectivePoint::GENERATOR * h;
            }
        }
        counter += 1;
    }
}

fn scalar_from_key(key: &SecretKey) -> Scalar {
    Option::<Scalar>::from(Scalar::from_repr(key.to_bytes()))
        .expect("secret-key bytes are a valid non-zero scalar")
}

pub(crate) fn scalar_of_weight(w: i64) -> Scalar {
    if w >= 0 {
        Scalar::from(w as u64)
    } else {
        -Scalar::from(w.unsigned_abs())
    }
}

pub(crate) fn encode_point(p: &ProjectivePoint) -> Result<[u8; POINT_LEN], ZkError> {
    let affine = p.to_affine();
    if affine == AffinePoint::IDENTITY {
        return Err(ZkError::Malformed("zk commitment is the identity".into()));
    }
    let enc = affine.to_encoded_point(true);
    let bytes = enc.as_bytes();
    let mut out = [0u8; POINT_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn decode_point(raw: &[u8; POINT_LEN]) -> Result<ProjectivePoint, ZkError> {
    let enc = EncodedPoint::from_bytes(raw.as_slice())
        .map_err(|_| ZkError::Malformed("zk point encoding is invalid".into()))?;
    Option::from(<ProjectivePoint as FromEncodedPoint<Secp256k1>>::from_encoded_point(&enc))
        .ok_or_else(|| ZkError::Malformed("zk point is not on the curve".into()))
}

/// Deterministic challenge scalar in `[1, n)`: hash the statement and first
/// messages, retrying with a counter on the negligible chance the digest is
/// not a valid non-zero scalar.
fn challenge(parts: &[&[u8]]) -> Scalar {
    let mut counter: u64 = 0;
    loop {
        let mut with_counter = Vec::with_capacity(parts.len() + 1);
        with_counter.extend_from_slice(parts);
        let counter_bytes = counter.to_be_bytes();
        with_counter.push(&counter_bytes);
        let digest = sha256_dom(DOM_CHALLENGE, &with_counter);
        if let Some(c) = Option::<Scalar>::from(Scalar::from_repr(digest.into())) {
            if c != Scalar::ZERO {
                return c;
            }
        }
        counter += 1;
    }
}

fn validate_dims(weights: &[i64], inputs: usize) -> Result<(), ZkError> {
    if weights.len() != inputs {
        return Err(ZkError::Malformed(
            "zk weights must match the input count".into(),
        ));
    }
    if weights.is_empty() || weights.len() > MAX_INPUTS {
        return Err(ZkError::Malformed("zk input count out of range".into()));
    }
    if weights.iter().any(|w| w.abs() > MAX_WEIGHT_ABS) {
        return Err(ZkError::Malformed("zk weight exceeds the cap".into()));
    }
    Ok(())
}

/// A CDS OR-proof that a bit commitment `B` opens to 0 or 1: knowledge of `r`
/// with `B = rH` (bit 0) or `B - G = rH` (bit 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitProof {
    /// The bit commitment `B`.
    pub commitment: [u8; POINT_LEN],
    /// First messages for the 0-branch and the 1-branch.
    pub a0: [u8; POINT_LEN],
    pub a1: [u8; POINT_LEN],
    /// Split challenges, `c0 + c1 == challenge`.
    pub c0: [u8; 32],
    pub c1: [u8; 32],
    /// Responses with `z_j * H == A_j + c_j * P_j`.
    pub z0: [u8; 32],
    pub z1: [u8; 32],
}

impl BitProof {
    pub(crate) fn encode(&self, w: &mut srct_core::ser::Writer) {
        w.raw(&self.commitment)
            .raw(&self.a0)
            .raw(&self.a1)
            .raw(&self.c0)
            .raw(&self.c1)
            .raw(&self.z0)
            .raw(&self.z1);
    }

    pub(crate) fn decode(r: &mut srct_core::ser::Reader) -> Result<Self, ZkError> {
        let mut commitment = [0u8; POINT_LEN];
        let mut a0 = [0u8; POINT_LEN];
        let mut a1 = [0u8; POINT_LEN];
        commitment.copy_from_slice(r.fixed_slice(POINT_LEN).map_err(malformed)?);
        a0.copy_from_slice(r.fixed_slice(POINT_LEN).map_err(malformed)?);
        a1.copy_from_slice(r.fixed_slice(POINT_LEN).map_err(malformed)?);
        let mut c0 = [0u8; 32];
        let mut c1 = [0u8; 32];
        let mut z0 = [0u8; 32];
        let mut z1 = [0u8; 32];
        c0.copy_from_slice(r.fixed_slice(32).map_err(malformed)?);
        c1.copy_from_slice(r.fixed_slice(32).map_err(malformed)?);
        z0.copy_from_slice(r.fixed_slice(32).map_err(malformed)?);
        z1.copy_from_slice(r.fixed_slice(32).map_err(malformed)?);
        // Every point must be on the curve; scalars must be canonical.
        decode_point(&commitment)?;
        decode_point(&a0)?;
        decode_point(&a1)?;
        for (name, raw) in [("c0", &c0), ("c1", &c1), ("z0", &z0), ("z1", &z1)] {
            if Option::<Scalar>::from(Scalar::from_repr((*raw).into())).is_none() {
                return Err(ZkError::Malformed(format!(
                    "zk bit-proof {name} is not canonical"
                )));
            }
        }
        Ok(BitProof {
            commitment,
            a0,
            a1,
            c0,
            c1,
            z0,
            z1,
        })
    }
}

/// A proven statement: input commitments, one OR-proof per bit, and the
/// output commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearProof {
    pub input_commitments: Vec<[u8; POINT_LEN]>,
    pub bit_proofs: Vec<Vec<BitProof>>,
    pub output_commitment: [u8; POINT_LEN],
}

/// Plaintext evaluation the commitments mirror. Callers keep values small.
pub fn eval_plaintext(weights: &[i64], bias: u64, inputs: &[u16]) -> u64 {
    let mut acc = bias as i128;
    for (w, x) in weights.iter().zip(inputs.iter()) {
        acc += (*w as i128) * (*x as i128);
    }
    acc as u64
}

fn commit_to(value: Scalar, rng: &mut StdRng) -> (ProjectivePoint, Scalar) {
    let r = scalar_from_key(&SecretKey::random(rng));
    (ProjectivePoint::GENERATOR * value + h_generator() * r, r)
}

/// Prove correct evaluation. The statement (weights, bias, commitments, first
/// messages) is hashed into every challenge, binding each bit-proof to this
/// exact evaluation.
pub fn prove_linear(
    weights: &[i64],
    bias: u64,
    inputs: &[u16],
    rng: &mut StdRng,
) -> Result<LinearProof, ZkError> {
    validate_dims(weights, inputs.len())?;
    struct Opening {
        bit_coms: Vec<ProjectivePoint>,
        bit_rands: Vec<Scalar>,
        bit_values: Vec<u64>,
    }
    // Phase 1: commit every bit. Each input commitment IS the recombined
    // bit commitments (so the verifier's homomorphic recomputation matches
    // by construction); knowledge of the bit randomness implies knowledge
    // of every opening.
    let mut input_coms = Vec::with_capacity(inputs.len());
    let mut openings = Vec::with_capacity(inputs.len());
    for value in inputs {
        let mut opening = Opening {
            bit_coms: Vec::with_capacity(BIT_WIDTH),
            bit_rands: Vec::with_capacity(BIT_WIDTH),
            bit_values: Vec::with_capacity(BIT_WIDTH),
        };
        let mut x_com = ProjectivePoint::IDENTITY;
        let mut power = Scalar::from(1u64);
        for i in 0..BIT_WIDTH {
            let bit = ((*value >> i) & 1) as u64;
            let (b_com, r) = commit_to(Scalar::from(bit), rng);
            encode_point(&b_com)?;
            x_com += b_com * power;
            power += power;
            opening.bit_coms.push(b_com);
            opening.bit_rands.push(r);
            opening.bit_values.push(bit);
        }
        input_coms.push(encode_point(&x_com)?);
        openings.push(opening);
    }
    // Phase 2: OR-prove every bit against the complete statement.
    let statement = statement_bytes(weights, bias, &input_coms);
    let mut bit_proofs_all = Vec::with_capacity(inputs.len());
    for opening in &openings {
        let mut bit_proofs = Vec::with_capacity(BIT_WIDTH);
        for (b_com, r, bit) in opening
            .bit_coms
            .iter()
            .zip(opening.bit_rands.iter())
            .zip(opening.bit_values.iter())
            .map(|((c, r), v)| (c, r, v))
        {
            bit_proofs.push(prove_bit_known(*bit, *b_com, *r, &statement, rng)?);
        }
        bit_proofs_all.push(bit_proofs);
    }
    // Output commitment reuses randomness homomorphically: knowledge of the
    // bit randomness implies knowledge of this opening.
    let mut y_com = ProjectivePoint::GENERATOR * Scalar::from(bias);
    for (idx, w) in weights.iter().enumerate() {
        y_com += decode_point(&input_coms[idx])? * scalar_of_weight(*w);
    }
    Ok(LinearProof {
        input_commitments: input_coms,
        bit_proofs: bit_proofs_all,
        output_commitment: encode_point(&y_com)?,
    })
}

pub(crate) fn statement_bytes(
    weights: &[i64],
    bias: u64,
    input_coms: &[[u8; POINT_LEN]],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&bias.to_be_bytes());
    bytes.extend_from_slice(&(weights.len() as u64).to_be_bytes());
    for w in weights {
        bytes.extend_from_slice(&w.to_be_bytes());
    }
    for com in input_coms {
        bytes.extend_from_slice(com);
    }
    bytes
}

/// CDS OR-proof for one bit commitment already made in phase 1. The
/// precomputed `statement` binds the proof to its exact evaluation, so a
/// bit-proof cannot be transplanted to another statement.
fn prove_bit_known(
    bit: u64,
    b_com: ProjectivePoint,
    r: Scalar,
    statement: &[u8],
    rng: &mut StdRng,
) -> Result<BitProof, ZkError> {
    debug_assert!(bit <= 1);
    let h = h_generator();
    let g = ProjectivePoint::GENERATOR;
    let b_com_bytes = encode_point(&b_com)?;
    // P0 = B (bit 0: B = rH), P1 = B - G (bit 1: B - G = rH).
    let p0 = b_com;
    let p1 = b_com - g;
    // Real branch is `bit`; fake the other with random challenge/response.
    let fake = 1 - bit as usize;
    let mut first = [ProjectivePoint::IDENTITY; 2];
    let mut challenges = [Scalar::ZERO; 2];
    let mut responses = [Scalar::ZERO; 2];
    let a_real = scalar_from_key(&SecretKey::random(rng));
    first[bit as usize] = h * a_real;
    challenges[fake] = scalar_from_key(&SecretKey::random(rng));
    responses[fake] = scalar_from_key(&SecretKey::random(rng));
    let p_fake = if fake == 0 { p0 } else { p1 };
    first[fake] = h * responses[fake] - p_fake * challenges[fake];
    let a0_bytes = encode_point(&first[0])?;
    let a1_bytes = encode_point(&first[1])?;
    let c = challenge(&[statement, &b_com_bytes, &a0_bytes, &a1_bytes]);
    challenges[bit as usize] = c - challenges[fake];
    responses[bit as usize] = a_real + challenges[bit as usize] * r;
    Ok(BitProof {
        commitment: b_com_bytes,
        a0: a0_bytes,
        a1: a1_bytes,
        c0: challenges[0].to_bytes().into(),
        c1: challenges[1].to_bytes().into(),
        z0: responses[0].to_bytes().into(),
        z1: responses[1].to_bytes().into(),
    })
}

/// Verify a proof package against public weights/bias. Learns nothing about
/// the inputs beyond the (public) bit-length bound.
pub fn verify_linear(weights: &[i64], bias: u64, package: &LinearProof) -> Result<(), ZkError> {
    validate_dims(weights, package.input_commitments.len())?;
    if package.bit_proofs.len() != package.input_commitments.len()
        || package
            .bit_proofs
            .iter()
            .any(|bits| bits.len() != BIT_WIDTH)
    {
        return Err(ZkError::Malformed("zk bit proof shape is wrong".into()));
    }
    let h = h_generator();
    let g = ProjectivePoint::GENERATOR;
    let mut input_pts = Vec::with_capacity(package.input_commitments.len());
    let statement = statement_bytes(weights, bias, &package.input_commitments);
    for (input_raw, bits) in package
        .input_commitments
        .iter()
        .zip(package.bit_proofs.iter())
    {
        let x_com = decode_point(input_raw)?;
        // Bits recompose to the input commitment.
        let mut recomposed = ProjectivePoint::IDENTITY;
        let mut power = Scalar::from(1u64);
        for proof in bits {
            verify_bit(&statement, proof, &h)?;
            let b_com = decode_point(&proof.commitment)?;
            recomposed += b_com * power;
            power += power;
        }
        if recomposed != x_com {
            return Err(ZkError::InvalidProof);
        }
        input_pts.push(x_com);
    }
    // Linear evaluation recomputes to the output commitment.
    let mut expected = g * Scalar::from(bias);
    for (x_com, w) in input_pts.iter().zip(weights.iter()) {
        expected += *x_com * scalar_of_weight(*w);
    }
    if encode_point(&expected)? != package.output_commitment {
        return Err(ZkError::InvalidProof);
    }
    let _ = decode_point(&package.output_commitment)?;
    Ok(())
}

pub(crate) fn verify_bit(
    statement: &[u8],
    proof: &BitProof,
    h: &ProjectivePoint,
) -> Result<(), ZkError> {
    let g = ProjectivePoint::GENERATOR;
    let b_com = decode_point(&proof.commitment)?;
    let a0 = decode_point(&proof.a0)?;
    let a1 = decode_point(&proof.a1)?;
    let c0 = Option::<Scalar>::from(Scalar::from_repr(proof.c0.into()))
        .ok_or_else(|| ZkError::Malformed("zk bit-proof c0 is not canonical".into()))?;
    let c1 = Option::<Scalar>::from(Scalar::from_repr(proof.c1.into()))
        .ok_or_else(|| ZkError::Malformed("zk bit-proof c1 is not canonical".into()))?;
    let z0 = Option::<Scalar>::from(Scalar::from_repr(proof.z0.into()))
        .ok_or_else(|| ZkError::Malformed("zk bit-proof z0 is not canonical".into()))?;
    let z1 = Option::<Scalar>::from(Scalar::from_repr(proof.z1.into()))
        .ok_or_else(|| ZkError::Malformed("zk bit-proof z1 is not canonical".into()))?;
    let c = challenge(&[statement, &proof.commitment, &proof.a0, &proof.a1]);
    if c0 + c1 != c {
        return Err(ZkError::InvalidProof);
    }
    if *h * z0 != a0 + b_com * c0 {
        return Err(ZkError::InvalidProof);
    }
    if *h * z1 != a1 + (b_com - g) * c1 {
        return Err(ZkError::InvalidProof);
    }
    Ok(())
}

/// A proven lower bound: the committed value opens to at least `threshold`.
///
/// The prover commits the value, bit-decomposes the difference `d = value -
/// threshold` with one CDS OR-proof per bit (same machinery as the linear
/// gate, under a distinct statement tag), and the verifier recomposes the
/// difference homomorphically and checks `X - threshold*G == D`. This is the
/// non-linear gate primitive thresholded activations are built from: a
/// clipped `max(x, c)` is a linear gate plus this assertion, and a step
/// gate is this assertion alone.
///
/// Task-envelope binding (which task commitment this assertion covers) is a
/// wire-version decision and is deliberately not smuggled in here: this
/// proof stands alone with its own domain separation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdProof {
    pub input_commitment: [u8; POINT_LEN],
    pub threshold: u16,
    pub bit_proofs: Vec<BitProof>,
}

fn threshold_statement_bytes(threshold: u16, input_com: &[u8; POINT_LEN]) -> Vec<u8> {
    let mut bytes = Vec::from(b"srct/zkml/threshold/v1");
    bytes.extend_from_slice(&threshold.to_be_bytes());
    bytes.extend_from_slice(input_com);
    bytes
}

/// Prove `value >= threshold` for a freshly committed value. A false
/// statement is refused at prove time — there is no proof of a lie to verify.
///
/// The bit commitments reuse the input's blinding by construction: blindings
/// `r_1..r_15` are fresh and `r_0` absorbs the slack so that
/// `Σ 2^i r_i` equals the input blinding. The verifier's homomorphic
/// recomposition then matches `X - threshold*G` exactly. This is the same
/// blinding discipline Bulletproof-style range proofs use.
pub fn prove_threshold(
    value: u16,
    threshold: u16,
    rng: &mut StdRng,
) -> Result<ThresholdProof, ZkError> {
    if value < threshold {
        return Err(ZkError::InvalidProof);
    }
    let h = h_generator();
    let g = ProjectivePoint::GENERATOR;
    let r_x = scalar_from_key(&SecretKey::random(rng));
    let x_com = g * Scalar::from(value as u64) + h * r_x;
    let input_commitment = encode_point(&x_com)?;
    let d = (value - threshold) as u64;
    let statement = threshold_statement_bytes(threshold, &input_commitment);
    let mut tail = Vec::with_capacity(BIT_WIDTH - 1);
    let mut acc = r_x;
    let mut pow = Scalar::from(2u64);
    for _ in 1..BIT_WIDTH {
        let r = scalar_from_key(&SecretKey::random(rng));
        tail.push(r);
        acc -= pow * r;
        pow = pow + pow;
    }
    let mut r_bits = Vec::with_capacity(BIT_WIDTH);
    r_bits.push(acc);
    r_bits.extend(tail);
    let mut bit_proofs = Vec::with_capacity(BIT_WIDTH);
    for (i, r) in r_bits.iter().enumerate().take(BIT_WIDTH) {
        let bit = (d >> i) & 1;
        let b_com = g * Scalar::from(bit) + h * *r;
        encode_point(&b_com)?;
        bit_proofs.push(prove_bit_known(bit, b_com, *r, &statement, rng)?);
    }
    Ok(ThresholdProof {
        input_commitment,
        threshold,
        bit_proofs,
    })
}

/// Verify a threshold assertion. Learns nothing about the value beyond the
/// bound and the 16-bit length.
pub fn verify_threshold(proof: &ThresholdProof) -> Result<(), ZkError> {
    if proof.bit_proofs.len() != BIT_WIDTH {
        return Err(ZkError::Malformed(
            "zk threshold bit proof shape is wrong".into(),
        ));
    }
    let x_com = decode_point(&proof.input_commitment)?;
    let statement = threshold_statement_bytes(proof.threshold, &proof.input_commitment);
    let h = h_generator();
    let g = ProjectivePoint::GENERATOR;
    let mut recomposed = ProjectivePoint::IDENTITY;
    let mut power = Scalar::from(1u64);
    for bp in &proof.bit_proofs {
        verify_bit(&statement, bp, &h)?;
        recomposed += decode_point(&bp.commitment)? * power;
        power += power;
    }
    if recomposed != x_com - g * Scalar::from(proof.threshold as u64) {
        return Err(ZkError::InvalidProof);
    }
    Ok(())
}

impl ThresholdProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = srct_core::ser::Writer::with_capacity(POINT_LEN + 2 + BIT_WIDTH * 256);
        w.raw(&self.input_commitment).u16le(self.threshold);
        for bp in &self.bit_proofs {
            bp.encode(&mut w);
        }
        w.into_vec()
    }

    /// Strict inverse of [`ThresholdProof::encode`]. Verifies the assertion,
    /// so tampered bytes fail here instead of loading a bad proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, ZkError> {
        let mut r = srct_core::ser::Reader::new(bytes);
        let mut input_commitment = [0u8; POINT_LEN];
        input_commitment.copy_from_slice(r.fixed_slice(POINT_LEN).map_err(malformed)?);
        let threshold = r.u16le().map_err(malformed)?;
        let mut bit_proofs = Vec::with_capacity(BIT_WIDTH);
        for _ in 0..BIT_WIDTH {
            bit_proofs.push(BitProof::decode(&mut r)?);
        }
        r.expect_end().map_err(malformed)?;
        let proof = ThresholdProof {
            input_commitment,
            threshold,
            bit_proofs,
        };
        verify_threshold(&proof)?;
        Ok(proof)
    }
}

fn malformed(e: srct_core::error::Error) -> ZkError {
    ZkError::Malformed(e.to_string())
}
