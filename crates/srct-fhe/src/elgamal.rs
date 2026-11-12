//! Additive-homomorphic encryption for the encrypted-compute prototype.
//!
//! Exponential ElGamal over secp256k1: `Enc(m) = (rG, mG + rP)` where `P` is
//! the requester's public key. Ciphertexts add (`Enc(a) + Enc(b) = Enc(a+b)`)
//! and scale (`k * Enc(a) = Enc(ka)`), so a worker can evaluate a weighted sum
//! — the linear core of neural inference — without ever seeing the inputs.
//!
//! Decryption needs the discrete log of `mG`, so it searches `[0, bound)` with
//! baby-step giant-step. The caller picks `bound` above the largest value it
//! expects; arithmetic itself is modulo the curve order. This is a prototype
//! seam, not general FHE: linear operations only, 64-bit-scale values, no
//! bootstrapping, no encrypted non-linearities.

use std::collections::HashMap;

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1, SecretKey};
use rand::rngs::StdRng;

use crate::FheError;

/// Compressed point on the wire. All-zero bytes mean the identity point;
/// `0x02/0x03`-prefixed bytes are an ordinary compressed encoding.
pub const POINT_LEN: usize = 33;
/// An ElGamal ciphertext is two wire points.
pub const CIPHERTEXT_LEN: usize = 2 * POINT_LEN;

fn encode_point(p: &ProjectivePoint) -> [u8; POINT_LEN] {
    let a = p.to_affine();
    if a == AffinePoint::IDENTITY {
        return [0u8; POINT_LEN];
    }
    let enc = a.to_encoded_point(true);
    let bytes = enc.as_bytes();
    let mut out = [0u8; POINT_LEN];
    out.copy_from_slice(bytes);
    out
}

fn decode_point(raw: &[u8; POINT_LEN]) -> Result<ProjectivePoint, FheError> {
    if *raw == [0u8; POINT_LEN] {
        return Ok(ProjectivePoint::IDENTITY);
    }
    let enc = EncodedPoint::from_bytes(raw.as_slice())
        .map_err(|_| FheError::Malformed("ciphertext point encoding is invalid".into()))?;
    // A 33-byte compressed encoding can never be the identity point.
    Option::from(<ProjectivePoint as FromEncodedPoint<Secp256k1>>::from_encoded_point(&enc))
        .ok_or_else(|| FheError::Malformed("ciphertext point is not on the curve".into()))
}

/// A requester's encryption keypair. The secret never leaves the requester;
///
/// [`PublicKey`] encrypts, [`FheKeys::decrypt`] (below) recovers values.
pub struct FheKeys {
    secret: Scalar,
    public: ProjectivePoint,
}

impl FheKeys {
    pub fn generate(rng: &mut StdRng) -> Self {
        let secret = scalar_from_key(&SecretKey::random(rng));
        let public = ProjectivePoint::GENERATOR * secret;
        FheKeys { secret, public }
    }

    pub fn public_point(&self) -> ProjectivePoint {
        self.public
    }

    /// Wire encoding of the public key (goes into the signed task).
    pub fn public_bytes(&self) -> [u8; POINT_LEN] {
        encode_point(&self.public)
    }

    pub fn encrypt(&self, m: u32, rng: &mut StdRng) -> Ciphertext {
        let r = scalar_from_key(&SecretKey::random(rng));
        Ciphertext::from_points(
            &(ProjectivePoint::GENERATOR * r),
            &(point_from_u64(m as u64) + self.public * r),
        )
    }

    /// Recover `m` in `[0, bound)`. Returns `None` when the value is outside
    /// the bound (or the ciphertext is not under this key).
    pub fn decrypt(&self, ct: &Ciphertext, bound: u64) -> Option<u64> {
        let c1 = ct.c1_point().ok()?;
        let c2 = ct.c2_point().ok()?;
        let m_point = (c2 - c1 * self.secret).to_affine();
        bsgs(&m_point, bound)
    }
}

fn scalar_from_key(key: &SecretKey) -> Scalar {
    Option::from(Scalar::from_repr(key.to_bytes()))
        .expect("secret-key bytes are a valid non-zero scalar")
}

fn point_from_u64(m: u64) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * Scalar::from(m)
}

/// Integer square root (floor) via Newton's method. `u64::isqrt` postdates
/// the workspace MSRV, so this avoids the `incompatible_msrv` lint.
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = 1u64 << (64 - n.leading_zeros()).div_ceil(2);
    loop {
        let y = (x + n / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// Baby-step giant-step discrete log in `[0, bound)`. `None` for `bound == 0`
/// or a value at or above the bound.
fn bsgs(target: &AffinePoint, bound: u64) -> Option<u64> {
    if bound == 0 {
        return None;
    }
    if *target == AffinePoint::IDENTITY {
        return Some(0);
    }
    let step = isqrt(bound) + 1;
    let mut table: HashMap<[u8; POINT_LEN], u64> = HashMap::new();
    let mut baby = ProjectivePoint::IDENTITY;
    let gen = ProjectivePoint::GENERATOR;
    for j in 0..step {
        let key = encode_point(&baby);
        table.entry(key).or_insert(j);
        baby += gen;
    }
    let factor = gen * Scalar::from(step);
    let mut cur = ProjectivePoint::from(*target);
    let mut i: u64 = 0;
    loop {
        if let Some(j) = table.get(&encode_point(&cur)) {
            let m = (i as u128) * (step as u128) + (*j as u128);
            if m < bound as u128 {
                return Some(m as u64);
            }
            return None;
        }
        if i == step {
            return None;
        }
        cur -= factor;
        i += 1;
    }
}

/// An ElGamal ciphertext: two curve points on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    c1: [u8; POINT_LEN],
    c2: [u8; POINT_LEN],
}

impl Ciphertext {
    pub fn from_points(c1: &ProjectivePoint, c2: &ProjectivePoint) -> Self {
        Ciphertext {
            c1: encode_point(c1),
            c2: encode_point(c2),
        }
    }

    /// A public deterministic encryption of `m` (randomness zero). Only for
    /// public biases the worker already knows, never for private inputs.
    pub fn trivial_plaintext(m: u64) -> Self {
        Ciphertext::from_points(&ProjectivePoint::IDENTITY, &point_from_u64(m))
    }

    pub fn c1_point(&self) -> Result<ProjectivePoint, FheError> {
        decode_point(&self.c1)
    }

    pub fn c2_point(&self) -> Result<ProjectivePoint, FheError> {
        decode_point(&self.c2)
    }

    /// `Enc(a) + Enc(b) = Enc(a+b)`. Both inputs are validated on the curve.
    pub fn add(&self, other: &Ciphertext) -> Result<Ciphertext, FheError> {
        Ok(Ciphertext::from_points(
            &(self.c1_point()? + other.c1_point()?),
            &(self.c2_point()? + other.c2_point()?),
        ))
    }

    /// `k * Enc(a) = Enc(ka)`. Negative scalars wrap modulo the curve order.
    pub fn scalar_mul(&self, k: i64) -> Result<Ciphertext, FheError> {
        let s = if k >= 0 {
            Scalar::from(k as u64)
        } else {
            -Scalar::from(k.unsigned_abs())
        };
        Ok(Ciphertext::from_points(
            &(self.c1_point()? * s),
            &(self.c2_point()? * s),
        ))
    }

    /// `ct + Enc(0)` under `public`: same plaintext, fresh randomness.
    pub fn rerandomize_under(
        &self,
        public: &ProjectivePoint,
        rng: &mut StdRng,
    ) -> Result<Ciphertext, FheError> {
        let r = scalar_from_key(&SecretKey::random(rng));
        let zero = Ciphertext::from_points(&(ProjectivePoint::GENERATOR * r), &(*public * r));
        self.add(&zero)
    }

    pub fn encode(&self) -> [u8; CIPHERTEXT_LEN] {
        let mut out = [0u8; CIPHERTEXT_LEN];
        out[..POINT_LEN].copy_from_slice(&self.c1);
        out[POINT_LEN..].copy_from_slice(&self.c2);
        out
    }

    pub fn decode(bytes: &[u8; CIPHERTEXT_LEN]) -> Result<Self, FheError> {
        let mut c1 = [0u8; POINT_LEN];
        let mut c2 = [0u8; POINT_LEN];
        c1.copy_from_slice(&bytes[..POINT_LEN]);
        c2.copy_from_slice(&bytes[POINT_LEN..]);
        let ct = Ciphertext { c1, c2 };
        ct.c1_point()?;
        ct.c2_point()?;
        Ok(ct)
    }
}
