//! Fixed-point (Q16.16) neural kernels: the BitExact tier.
//!
//! Every operation is integer arithmetic, so two hosts produce identical
//! bytes for identical inputs — no floating-point rounding, no libm
//! transcendentals, no NaN or infinity (overflow saturates). That is the
//! whole point: [`FixedPointBackend`] can be classified `BitExact` by
//! construction, which the `f32` backends cannot.
//!
//! Honest limits, stated up front:
//!
//! - The activations are integer Padé/tanh and integer sigmoid approximations,
//!   and the objective is mean-squared error, not the BCE of [`crate::model`].
//!   A fixed-point backend trains a *close cousin* of the reference model, not
//!   the identical function. Cross-dtype parity with `f32` is Statistical by
//!   design; BitExact means bit-identical *within* this dtype.
//! - Values live in ±32768 with 2^-16 resolution. Anything larger saturates;
//!   anything smaller than half a step rounds. Callers keep models in range.

use crate::data::Sample;
use crate::model::{Mlp, HIDDEN_DIM, INPUT_DIM};

/// Q16.16 scale factor.
const Q: i64 = 1 << 16;
/// `tanh` saturates past this magnitude (in Q16.16 units).
const TANH_LIM: i64 = 8 * Q;

fn sat_q(v: i64) -> i32 {
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

pub(crate) fn from_f32(x: f32) -> i32 {
    if !x.is_finite() {
        return 0;
    }
    sat_q((x as f64 * Q as f64).round() as i64)
}

pub(crate) fn to_f32(x: i32) -> f32 {
    x as f32 / Q as f32
}

/// Integer `tanh` via the Padé approximant `x(27+x²)/(27+9x²)`, all Q16.16.
/// Deterministic on every host; close to `tanh` on [-8, 8], saturated outside.
fn tanh_q(x: i32) -> i32 {
    let v = x as i64;
    if v >= TANH_LIM {
        return Q as i32;
    }
    if v <= -TANH_LIM {
        return -(Q as i32);
    }
    let x2 = (v * v) >> 16;
    let num = v * (27 * Q + x2);
    let den = 27 * Q + 9 * x2;
    sat_q(num / den)
}

/// Integer sigmoid via `sigmoid(x) = (tanh(x/2) + 1) / 2`.
fn sigmoid_q(x: i32) -> i32 {
    ((tanh_q(sat_q(x as i64 >> 1)) as i64 + Q) >> 1) as i32
}

/// An MLP with Q16.16 integer parameters. Same 2-8-1 shape as [`Mlp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedMlp {
    pub w1: Vec<i32>,
    pub b1: Vec<i32>,
    pub w2: Vec<i32>,
    pub b2: Vec<i32>,
}

impl FixedMlp {
    pub fn zeros() -> Self {
        FixedMlp {
            w1: vec![0; HIDDEN_DIM * INPUT_DIM],
            b1: vec![0; HIDDEN_DIM],
            w2: vec![0; HIDDEN_DIM],
            b2: vec![0; 1],
        }
    }

    /// Quantize an `f32` model. Non-finite entries become zero; out-of-range
    /// entries saturate. Both are deterministic.
    pub fn from_mlp(model: &Mlp) -> Self {
        let q = |v: &[f32]| v.iter().map(|x| from_f32(*x)).collect();
        FixedMlp {
            w1: q(&model.w1),
            b1: q(&model.b1),
            w2: q(&model.w2),
            b2: q(&model.b2),
        }
    }

    /// Back to `f32`. Integer→float conversion is IEEE-exact in operation
    /// (not in precision): identical bits in, identical bits out, everywhere.
    pub fn to_mlp(&self) -> Mlp {
        let mut flat =
            Vec::with_capacity(self.w1.len() + self.b1.len() + self.w2.len() + self.b2.len());
        for v in [&self.w1, &self.b1, &self.w2, &self.b2] {
            flat.extend(v.iter().map(|x| to_f32(*x)));
        }
        Mlp::from_params(&flat).expect("quantized values are always finite")
    }

    pub fn forward(&self, x: &[i32; INPUT_DIM]) -> ([i32; HIDDEN_DIM], i32) {
        let mut h = [0i32; HIDDEN_DIM];
        for (j, slot) in h.iter_mut().enumerate() {
            let mut z = self.b1[j] as i64;
            for (i, xi) in x.iter().enumerate() {
                z += (self.w1[j * INPUT_DIM + i] as i64 * *xi as i64) >> 16;
            }
            *slot = tanh_q(sat_q(z));
        }
        let mut z2 = self.b2[0] as i64;
        for (j, hj) in h.iter().enumerate() {
            z2 += (self.w2[j] as i64 * *hj as i64) >> 16;
        }
        (h, sigmoid_q(sat_q(z2)))
    }

    /// Mean-squared error and its gradient, mirroring `Mlp::loss_and_grad`'s
    /// structure with integer ops. MSE needs only +, −, ×: no logarithms, so
    /// no transcendentals anywhere in the backend.
    pub fn loss_and_grad(&self, samples: &[(i32, [i32; INPUT_DIM])]) -> (i32, FixedMlp) {
        let mut grad = FixedMlp::zeros();
        let mut gw1 = vec![0i64; HIDDEN_DIM * INPUT_DIM];
        let mut gb1 = vec![0i64; HIDDEN_DIM];
        let mut gw2 = vec![0i64; HIDDEN_DIM];
        let mut gb2 = vec![0i64; 1];
        let mut loss_sum = 0i64;
        for (y, x) in samples {
            let (h, p) = self.forward(x);
            let e = p as i64 - *y as i64;
            loss_sum += (e * e) >> 16;
            let d2 = 2 * e;
            // Output sigmoid derivative from the output itself: s(1−s).
            let ds = (p as i64 * (Q - p as i64)) >> 16;
            for (j, hj) in h.iter().enumerate() {
                let hj64 = *hj as i64;
                gw2[j] += (d2 * hj64) >> 16;
                // Hidden tanh derivative from the activation: 1−t².
                let dt = Q - ((hj64 * hj64) >> 16);
                let dw = (d2 * ((ds * self.w2[j] as i64) >> 16)) >> 16;
                let dz1 = (dw * dt) >> 16;
                gb1[j] += dz1;
                for (i, xi) in x.iter().enumerate() {
                    gw1[j * INPUT_DIM + i] += (dz1 * *xi as i64) >> 16;
                }
            }
            gb2[0] += (d2 * ds) >> 16;
        }
        let n = samples.len() as i64;
        let loss = sat_q(loss_sum / n);
        let mean = |acc: &[i64]| acc.iter().map(|v| sat_q(v / n)).collect();
        grad.w1 = mean(&gw1);
        grad.b1 = mean(&gb1);
        grad.w2 = mean(&gw2);
        grad.b2 = mean(&gb2);
        (loss, grad)
    }

    /// One SGD step: `self -= lr * grad`, all integer.
    pub fn sgd_step(&mut self, grad: &FixedMlp, lr: i32) {
        for (dst, parts) in [
            (&mut self.w1, &grad.w1),
            (&mut self.b1, &grad.b1),
            (&mut self.w2, &grad.w2),
            (&mut self.b2, &grad.b2),
        ] {
            for (p, g) in dst.iter_mut().zip(parts.iter()) {
                *p = sat_q(*p as i64 - ((lr as i64 * *g as i64) >> 16));
            }
        }
    }
}

/// Quantized samples for [`FixedMlp`]: labels as 0/1 in Q16.16.
pub fn quantize_samples(samples: &[Sample]) -> Vec<(i32, [i32; INPUT_DIM])> {
    samples
        .iter()
        .map(|s| {
            let y = if s.y >= 0.5 { Q as i32 } else { 0 };
            (y, [from_f32(s.x[0]), from_f32(s.x[1])])
        })
        .collect()
}
