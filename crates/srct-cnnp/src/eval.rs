//! Held-out evaluation for fitted adapters (non-consensus).
//!
//! A training MSE is optimism: the adapter saw the data. [`evaluate`] scores
//! any fitted map on pairs it was not fitted on, against the mean-predictor
//! baseline over the same held-out targets. A map that cannot beat predicting
//! the mean is overfitted or fitted on noise — the report states both numbers
//! and lets the caller decide.

/// What a held-out run measured.
#[derive(Clone, Debug, PartialEq)]
pub struct HeldOutReport {
    pub pairs: usize,
    pub model_mse: f32,
    pub baseline_mse: f32,
}

impl HeldOutReport {
    /// Whether the map beats predicting the held-out mean.
    pub fn beats_baseline(&self) -> bool {
        self.model_mse < self.baseline_mse
    }
}

/// Score `apply` on held-out `(input, target)` pairs with `target_dim`
/// outputs. Fails closed on empty pairs, dimension mismatches and
/// non-finite values — never a silent zero.
pub fn evaluate(
    apply: impl Fn(&[f32]) -> Result<Vec<f32>, String>,
    target_dim: usize,
    pairs: &[(Vec<f32>, Vec<f32>)],
) -> Result<HeldOutReport, String> {
    if pairs.is_empty() {
        return Err("evaluation needs at least one pair".into());
    }
    if target_dim == 0 {
        return Err("evaluation target dimension is zero".into());
    }
    let mut mean = vec![0.0f64; target_dim];
    for (_, y) in pairs {
        if y.len() != target_dim {
            return Err("evaluation pair has the wrong target dimension".into());
        }
        if y.iter().any(|v| !v.is_finite()) {
            return Err("evaluation target is not finite".into());
        }
        for (m, v) in mean.iter_mut().zip(y.iter()) {
            *m += *v as f64;
        }
    }
    for m in mean.iter_mut() {
        *m /= pairs.len() as f64;
    }
    let mut model_total = 0.0f64;
    let mut base_total = 0.0f64;
    for (x, y) in pairs {
        let got = apply(x)?;
        if got.len() != target_dim {
            return Err("evaluation output has the wrong dimension".into());
        }
        for ((g, m), v) in got.iter().zip(mean.iter()).zip(y.iter()) {
            if !g.is_finite() {
                return Err("evaluation output is not finite".into());
            }
            let dm = *g as f64 - *v as f64;
            let db = *m - *v as f64;
            model_total += dm * dm;
            base_total += db * db;
        }
    }
    let n = (pairs.len() * target_dim) as f64;
    Ok(HeldOutReport {
        pairs: pairs.len(),
        model_mse: (model_total / n) as f32,
        baseline_mse: (base_total / n) as f32,
    })
}
