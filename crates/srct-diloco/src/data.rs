//! Deterministic training data and sharding.
//!
//! The two-moons set is generated from a fixed seed, so a round can be
//! reproduced byte-for-byte by every coordinator. Workers train on disjoint
//! shards; this is the property that makes the local updates genuinely
//! different rather than three copies of one gradient.

use crate::model::{Lcg, Mlp, INPUT_DIM};

/// One labelled example.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    pub x: [f32; INPUT_DIM],
    pub y: f32,
}

/// Deterministic two-moons classification set.
///
/// Class 0 lies on the upper half circle, class 1 on the offset lower half
/// circle. Gaussian-ish noise comes from the same LCG, so `(per_class, seed)`
/// fully determines the data.
pub fn two_moons(per_class: usize, seed: u64) -> Vec<Sample> {
    let mut rng = Lcg::new(seed);
    let mut out = Vec::with_capacity(per_class * 2);
    let n = per_class.max(1);
    for i in 0..n {
        let t = std::f32::consts::PI * (i as f32) / (n as f32);
        let noise_x = rng.signed() * 0.08;
        let noise_y = rng.signed() * 0.08;
        out.push(Sample {
            x: [t.cos() + noise_x, t.sin() + noise_y],
            y: 0.0,
        });
    }
    for i in 0..n {
        let t = std::f32::consts::PI * (i as f32) / (n as f32);
        let noise_x = rng.signed() * 0.08;
        let noise_y = rng.signed() * 0.08;
        out.push(Sample {
            x: [1.0 - t.cos() + noise_x, 0.5 - t.sin() + noise_y],
            y: 1.0,
        });
    }
    out
}

/// Split `samples` into `workers` round-robin shards.
///
/// Every shard is non-empty when `samples.len() >= workers`; a caller that
/// asks for more workers than samples gets empty shards and the local-update
/// validation refuses zero-sample work.
pub fn shards(samples: &[Sample], workers: usize) -> Vec<Vec<Sample>> {
    let workers = workers.max(1);
    let mut out: Vec<Vec<Sample>> = vec![Vec::new(); workers];
    for (i, sample) in samples.iter().enumerate() {
        out[i % workers].push(*sample);
    }
    out
}

/// Mean binary cross-entropy over `samples`.
pub fn mean_loss(model: &Mlp, samples: &[Sample]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    samples
        .iter()
        .map(|s| {
            let (_, p) = model.forward(&s.x);
            let p = p.clamp(1e-7, 1.0 - 1e-7);
            -(s.y * p.ln() + (1.0 - s.y) * (1.0 - p).ln())
        })
        .sum::<f32>()
        / samples.len() as f32
}

/// Fraction of samples classified correctly at a 0.5 threshold.
pub fn accuracy(model: &Mlp, samples: &[Sample]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let correct = samples
        .iter()
        .filter(|s| {
            let (_, p) = model.forward(&s.x);
            ((p >= 0.5) as u8 as f32) == s.y
        })
        .count();
    correct as f32 / samples.len() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_is_deterministic_and_sharded_disjointly() {
        let a = two_moons(16, 4);
        let b = two_moons(16, 4);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        let parts = shards(&a, 3);
        assert_eq!(parts.iter().map(|p| p.len()).sum::<usize>(), a.len());
        assert!(parts.iter().all(|p| !p.is_empty()));
    }

    #[test]
    fn a_fresh_model_is_near_chance_not_perfect() {
        let data = two_moons(64, 11);
        let model = Mlp::new(11);
        let acc = accuracy(&model, &data);
        assert!(acc < 0.95, "a random model must not start solved: {acc}");
    }
}
