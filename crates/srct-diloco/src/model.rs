//! A small real neural network: 2 inputs, 8 tanh hidden units, 1 sigmoid output.
//!
//! The model is intentionally tiny so a full DiLoCo round is cheap enough to
//! run in CI and in adversarial tests, while still being an actual
//! gradient-trained classifier (two-moons is not linearly separable, so a
//! hidden layer is required and the training signal is real).
//!
//! Parameters are stored as `f32` vectors. Canonical encoding is little-endian
//! IEEE-754 bit patterns; the checkpoint hash commits to those bytes. This is
//! deterministic for one build, not a cross-platform consensus guarantee (see
//! the crate docs).

use srct_core::hash::{sha256_dom, Hash};
use srct_core::ser::{Reader, Writer};

use crate::data::Sample;

pub const INPUT_DIM: usize = 2;
pub const HIDDEN_DIM: usize = 8;
pub const OUTPUT_DIM: usize = 1;
pub const PARAM_COUNT: usize =
    HIDDEN_DIM * INPUT_DIM + HIDDEN_DIM + OUTPUT_DIM * HIDDEN_DIM + OUTPUT_DIM;

/// Model format version. A change to the architecture or the parameter layout
/// must bump this value; a coordinator refuses updates that name another
/// version.
pub const MODEL_VERSION: u32 = 1;

const DOM_MODEL: &[u8] = b"srct/diloco/model/v1";

/// A deterministic 64-bit linear congruential generator.
///
/// Deliberately not `rand`: training data, initialisation and mini-batch order
/// must be reproducible from a seed alone, and a consensus-adjacent component
/// should not depend on an OS entropy source.
pub(crate) struct Lcg(u64);

impl Lcg {
    pub(crate) fn new(seed: u64) -> Self {
        Lcg(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    /// Uniform in `[0, 1)` with 24 bits of resolution.
    pub(crate) fn next_f32(&mut self) -> f32 {
        ((self.next_u64() >> 40) as f32) / ((1u32 << 24) as f32)
    }

    /// Uniform in `[-1, 1)`.
    pub(crate) fn signed(&mut self) -> f32 {
        self.next_f32() * 2.0 - 1.0
    }
}

/// A two-layer MLP classifier.
#[derive(Clone, Debug, PartialEq)]
pub struct Mlp {
    /// Hidden weights, `HIDDEN_DIM * INPUT_DIM`, row-major by hidden unit.
    pub w1: Vec<f32>,
    /// Hidden biases, `HIDDEN_DIM`.
    pub b1: Vec<f32>,
    /// Output weights, `OUTPUT_DIM * HIDDEN_DIM`, row-major by output unit.
    pub w2: Vec<f32>,
    /// Output biases, `OUTPUT_DIM`.
    pub b2: Vec<f32>,
}

impl Mlp {
    /// Deterministic Xavier-style initialisation from `seed`.
    pub fn new(seed: u64) -> Self {
        let mut rng = Lcg::new(seed);
        let mut w1 = vec![0.0f32; HIDDEN_DIM * INPUT_DIM];
        let mut b1 = vec![0.0f32; HIDDEN_DIM];
        let mut w2 = vec![0.0f32; OUTPUT_DIM * HIDDEN_DIM];
        let mut b2 = vec![0.0f32; OUTPUT_DIM];
        let limit1 = (6.0f32 / (INPUT_DIM + HIDDEN_DIM) as f32).sqrt();
        let limit2 = (6.0f32 / (HIDDEN_DIM + OUTPUT_DIM) as f32).sqrt();
        for w in w1.iter_mut() {
            *w = rng.signed() * limit1;
        }
        for w in w2.iter_mut() {
            *w = rng.signed() * limit2;
        }
        // Small non-zero biases break symmetry without dominating the input.
        for b in b1.iter_mut() {
            *b = rng.signed() * 0.05;
        }
        for b in b2.iter_mut() {
            *b = rng.signed() * 0.05;
        }
        Mlp { w1, b1, w2, b2 }
    }

    /// A zero model with the same shape.
    pub fn zeros() -> Self {
        Mlp {
            w1: vec![0.0; HIDDEN_DIM * INPUT_DIM],
            b1: vec![0.0; HIDDEN_DIM],
            w2: vec![0.0; OUTPUT_DIM * HIDDEN_DIM],
            b2: vec![0.0; OUTPUT_DIM],
        }
    }

    /// Flattened parameter vector in canonical order.
    pub fn params(&self) -> Vec<f32> {
        let mut out = Vec::with_capacity(PARAM_COUNT);
        out.extend_from_slice(&self.w1);
        out.extend_from_slice(&self.b1);
        out.extend_from_slice(&self.w2);
        out.extend_from_slice(&self.b2);
        out
    }

    /// Rebuild from a flattened vector. Refuses the wrong length or any
    /// non-finite value: a model that contains NaN can never be checkpointed.
    pub fn from_params(params: &[f32]) -> Result<Self, String> {
        if params.len() != PARAM_COUNT {
            return Err(format!(
                "model expects {PARAM_COUNT} parameters, got {}",
                params.len()
            ));
        }
        if params.iter().any(|v| !v.is_finite()) {
            return Err("model parameters must be finite".into());
        }
        let mut at = 0usize;
        let w1 = params[at..at + HIDDEN_DIM * INPUT_DIM].to_vec();
        at += HIDDEN_DIM * INPUT_DIM;
        let b1 = params[at..at + HIDDEN_DIM].to_vec();
        at += HIDDEN_DIM;
        let w2 = params[at..at + OUTPUT_DIM * HIDDEN_DIM].to_vec();
        at += OUTPUT_DIM * HIDDEN_DIM;
        let b2 = params[at..at + OUTPUT_DIM].to_vec();
        Ok(Mlp { w1, b1, w2, b2 })
    }

    /// Canonical encoding: parameter count, then each `f32` as its little-endian
    /// bit pattern.
    pub fn encode(&self) -> Vec<u8> {
        let params = self.params();
        let mut w = Writer::with_capacity(4 + params.len() * 4);
        w.u32le(params.len() as u32);
        for p in params {
            w.u32le(p.to_bits());
        }
        w.into_vec()
    }

    /// Inverse of [`Mlp::encode`], strict about length and finiteness.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let n = r.u32le().map_err(|e| format!("model: {e}"))? as usize;
        if n != PARAM_COUNT {
            return Err(format!("model: {n} parameters, expected {PARAM_COUNT}"));
        }
        let mut params = Vec::with_capacity(n);
        for _ in 0..n {
            let bits = r.u32le().map_err(|e| format!("model: {e}"))?;
            params.push(f32::from_bits(bits));
        }
        r.expect_end().map_err(|e| format!("model: {e}"))?;
        Self::from_params(&params)
    }

    /// Versioned commitment to the canonical encoding.
    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_MODEL, &[&MODEL_VERSION.to_le_bytes(), &self.encode()])
    }

    /// Forward pass: returns the hidden activations and the output probability.
    pub fn forward(&self, x: &[f32; INPUT_DIM]) -> ([f32; HIDDEN_DIM], f32) {
        let mut h = [0.0f32; HIDDEN_DIM];
        for (j, slot) in h.iter_mut().enumerate() {
            let mut z = self.b1[j];
            for (i, xi) in x.iter().enumerate() {
                z += self.w1[j * INPUT_DIM + i] * xi;
            }
            *slot = z.tanh();
        }
        let mut z2 = self.b2[0];
        for (j, hj) in h.iter().enumerate() {
            z2 += self.w2[j] * hj;
        }
        (h, sigmoid(z2))
    }

    /// Binary cross-entropy and its gradient over `samples`.
    ///
    /// Returns `(mean_loss, gradient)`. The loss is the objective the local
    /// worker descends; it is reported for observability, never used to price
    /// a contribution (a worker can lie about it).
    pub fn loss_and_grad(&self, samples: &[Sample]) -> (f32, Mlp) {
        let mut grad = Mlp::zeros();
        if samples.is_empty() {
            return (0.0, grad);
        }
        let mut loss = 0.0f32;
        for s in samples {
            let (h, p) = self.forward(&s.x);
            let p = p.clamp(1e-7, 1.0 - 1e-7);
            loss += -(s.y * p.ln() + (1.0 - s.y) * (1.0 - p).ln());
            let d2 = p - s.y;
            for (j, hj) in h.iter().enumerate() {
                let h_j = *hj;
                grad.w2[j] += d2 * h_j;
                let dh = d2 * self.w2[j];
                let dz1 = dh * (1.0 - h_j * h_j);
                grad.b1[j] += dz1;
                for (i, xi) in s.x.iter().enumerate() {
                    grad.w1[j * INPUT_DIM + i] += dz1 * xi;
                }
            }
            grad.b2[0] += d2;
        }
        let inv = 1.0 / samples.len() as f32;
        loss *= inv;
        for v in grad
            .w1
            .iter_mut()
            .chain(grad.b1.iter_mut())
            .chain(grad.w2.iter_mut())
            .chain(grad.b2.iter_mut())
        {
            *v *= inv;
        }
        (loss, grad)
    }

    /// One SGD step: `self -= lr * grad`.
    pub fn sgd_step(&mut self, grad: &Mlp, lr: f32) {
        for (p, g) in self
            .w1
            .iter_mut()
            .zip(grad.w1.iter())
            .chain(self.b1.iter_mut().zip(grad.b1.iter()))
            .chain(self.w2.iter_mut().zip(grad.w2.iter()))
            .chain(self.b2.iter_mut().zip(grad.b2.iter()))
        {
            *p -= lr * g;
        }
    }

    /// `self + other`.
    pub fn add(&self, other: &Mlp) -> Mlp {
        let a = self.params();
        let b = other.params();
        let sum: Vec<f32> = a.iter().zip(b.iter()).map(|(x, y)| x + y).collect();
        Mlp::from_params(&sum).expect("sum of finite models is finite")
    }

    /// `self - other`, computed in canonical parameter order.
    pub fn sub(&self, other: &Mlp) -> Mlp {
        let a = self.params();
        let b = other.params();
        let diff: Vec<f32> = a.iter().zip(b.iter()).map(|(x, y)| x - y).collect();
        Mlp::from_params(&diff).expect("difference of finite models is finite")
    }

    /// `self * scale`.
    pub fn scale(&self, scale: f32) -> Mlp {
        let scaled: Vec<f32> = self.params().iter().map(|v| v * scale).collect();
        Mlp::from_params(&scaled).expect("scaled finite model is finite")
    }

    /// L2 norm of the flattened parameters.
    pub fn l2_norm(&self) -> f32 {
        self.params().iter().map(|v| v * v).sum::<f32>().sqrt()
    }

    /// Dot product of two flattened parameter vectors.
    pub fn dot(&self, other: &Mlp) -> f32 {
        self.params()
            .iter()
            .zip(other.params().iter())
            .map(|(a, b)| a * b)
            .sum()
    }

    /// True when every parameter is finite.
    pub fn is_finite(&self) -> bool {
        self.params().iter().all(|v| v.is_finite())
    }
}

fn sigmoid(z: f32) -> f32 {
    1.0 / (1.0 + (-z).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips_and_binds_version() {
        let model = Mlp::new(7);
        let bytes = model.encode();
        let back = Mlp::decode(&bytes).unwrap();
        assert_eq!(back, model);
        assert_eq!(back.hash(), model.hash());
        let mut other = model.clone();
        other.b2[0] += 0.5;
        assert_ne!(other.hash(), model.hash());
    }

    #[test]
    fn non_finite_models_are_refused() {
        let mut params = Mlp::new(1).params();
        params[0] = f32::NAN;
        assert!(Mlp::from_params(&params).is_err());
        let mut model = Mlp::new(1);
        model.w1[0] = f32::INFINITY;
        assert!(!model.is_finite());
    }

    #[test]
    fn a_gradient_step_reduces_loss_on_a_simple_case() {
        let model = Mlp::new(3);
        let samples = crate::data::two_moons(32, 9);
        let (before, grad) = model.loss_and_grad(&samples);
        let mut next = model.clone();
        next.sgd_step(&grad, 0.5);
        let (after, _) = next.loss_and_grad(&samples);
        assert!(after < before, "loss {before} -> {after}");
    }
}
