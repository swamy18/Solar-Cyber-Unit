//! Quadratic representation adapters.
//!
//! A [`QuadraticAdapter`] is a signed second-order map from one model space
//! to another: the input is expanded to `[x, x_i * x_j (i <= j)]` and a ridge
//! fit runs in the expanded space, reusing the exact solver behind
//! [`crate::adapter::LinearAdapter`]. It fits curves a linear projection
//! cannot (parabolas, saddles, XOR-like bends) while staying deterministic,
//! bounded and fully signed.
//!
//! Honest limits: this is still a fixed polynomial basis, not a learned
//! representation — no hidden layers, no attention, no tokenizer awareness.
//! Source dimensions are capped at [`MAX_QUAD_SOURCE_DIM`] so the expanded
//! design matrix stays small.

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::adapter::ridge_affine_solve;
use crate::space::{ModelSpace, RepresentationEnvelope};

pub const QUAD_ADAPTER_VERSION: u8 = 1;
/// Largest source dimension a quadratic fit accepts. The expanded space has
/// `d + d * (d + 1) / 2` features, so 16 expands to 152.
pub const MAX_QUAD_SOURCE_DIM: usize = 16;
const DOM_QUAD_ADAPTER: &[u8] = b"srct/cnnp/quad-adapter/v1";
const MAX_QUAD_BYTES: usize = 16 * 1024 * 1024;

/// Number of expanded features for a `dim`-dimensional input.
pub fn expanded_dim(dim: usize) -> usize {
    dim + dim * (dim + 1) / 2
}

/// Deterministic second-order expansion: linear terms in index order, then
/// `x[i] * x[j]` for `i <= j` in lexicographic order.
pub fn expand(input: &[f32]) -> Vec<f64> {
    let mut out = Vec::with_capacity(expanded_dim(input.len()));
    out.extend(input.iter().map(|v| *v as f64));
    for i in 0..input.len() {
        for j in i..input.len() {
            out.push(input[i] as f64 * input[j] as f64);
        }
    }
    out
}

/// A signed quadratic map `target = W * expand(source) + b`.
#[derive(Clone, Debug, PartialEq)]
pub struct QuadraticAdapter {
    pub version: u8,
    pub source: ModelSpace,
    pub target: ModelSpace,
    /// `target.dim * expanded_dim(source.dim)`, row-major by target unit.
    pub weight: Vec<f32>,
    /// `target.dim`.
    pub bias: Vec<f32>,
    /// Number of paired examples used to fit it.
    pub samples: u32,
    /// Training mean-squared error on the paired set, in target space.
    pub train_mse: f32,
    /// Address that fitted and signed the adapter. Attribution for reuse.
    pub trainer: Address,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl QuadraticAdapter {
    /// Fit and sign a quadratic adapter with ridge regression.
    ///
    /// The fit is deterministic: identical pairs, ridge and spaces produce
    /// the same bytes.
    pub fn fit(
        source: ModelSpace,
        target: ModelSpace,
        pairs: &[(Vec<f32>, Vec<f32>)],
        ridge: f32,
        trainer: &Wallet,
    ) -> Result<Self, String> {
        source.validate()?;
        target.validate()?;
        if source.dim as usize > MAX_QUAD_SOURCE_DIM {
            return Err(format!(
                "quadratic adapter supports at most {MAX_QUAD_SOURCE_DIM} source dims"
            ));
        }
        if pairs.len() < 2 {
            return Err("adapter fit needs at least two paired examples".into());
        }
        if !ridge.is_finite() || ridge < 0.0 {
            return Err("ridge must be finite and non-negative".into());
        }
        let d = source.dim as usize;
        let t = target.dim as usize;
        for (i, (x, y)) in pairs.iter().enumerate() {
            if x.len() != d || y.len() != t {
                return Err(format!(
                    "pair {i} has dimensions ({}, {}), expected ({d}, {t})",
                    x.len(),
                    y.len()
                ));
            }
            if x.iter().chain(y.iter()).any(|v| !v.is_finite()) {
                return Err(format!("pair {i} contains a non-finite value"));
            }
        }
        let features: Vec<Vec<f64>> = pairs.iter().map(|(x, _)| expand(x)).collect();
        let targets: Vec<Vec<f64>> = pairs
            .iter()
            .map(|(_, y)| y.iter().map(|v| *v as f64).collect())
            .collect();
        let (weight, bias) = ridge_affine_solve(&features, &targets, ridge as f64)?;

        let address = trainer.address().map_err(|e| e.to_string())?;
        let mut adapter = QuadraticAdapter {
            version: QUAD_ADAPTER_VERSION,
            source,
            target,
            weight,
            bias,
            samples: pairs.len() as u32,
            train_mse: 0.0,
            trainer: address,
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        adapter.train_mse = adapter.mse(pairs)?;
        let auth = Auth::sign(trainer, &adapter.hash()).map_err(|e| e.to_string())?;
        adapter.sigs = auth.sigs;
        adapter.keys = auth.keys;
        Ok(adapter)
    }

    /// Apply the map. Refuses a wrong input dimension or non-finite input.
    pub fn apply(&self, input: &[f32]) -> Result<Vec<f32>, String> {
        if input.len() != self.source.dim as usize {
            return Err(format!(
                "adapter expects {} inputs, got {}",
                self.source.dim,
                input.len()
            ));
        }
        if input.iter().any(|v| !v.is_finite()) {
            return Err("adapter input contains a non-finite value".into());
        }
        let expanded = expand(input);
        let d = expanded.len();
        let t = self.target.dim as usize;
        let mut out = vec![0.0f32; t];
        for (k, slot) in out.iter_mut().enumerate() {
            let mut acc = self.bias[k] as f64;
            for (i, xi) in expanded.iter().enumerate() {
                acc += self.weight[k * d + i] as f64 * xi;
            }
            let acc = acc as f32;
            if !acc.is_finite() {
                return Err("adapter output is not finite".into());
            }
            *slot = acc;
        }
        Ok(out)
    }

    /// Translate a signed representation from the adapter's source space.
    pub fn translate(
        &self,
        envelope: &RepresentationEnvelope,
        key: Option<&[u8; 32]>,
    ) -> Result<Vec<f32>, String> {
        if envelope.space.hash() != self.source.hash() {
            return Err("adapter source space does not match the envelope".into());
        }
        let values = envelope.values(key)?;
        self.apply(&values)
    }

    /// Mean-squared error over paired data.
    pub fn mse(&self, pairs: &[(Vec<f32>, Vec<f32>)]) -> Result<f32, String> {
        if pairs.is_empty() {
            return Err("mse needs at least one pair".into());
        }
        let mut total = 0.0f64;
        for (x, y) in pairs {
            let got = self.apply(x)?;
            if got.len() != y.len() {
                return Err("mse pair has the wrong target dimension".into());
            }
            for (a, b) in got.iter().zip(y.iter()) {
                let diff = *a as f64 - *b as f64;
                total += diff * diff;
            }
        }
        Ok((total / (pairs.len() as f64 * self.target.dim as f64)) as f32)
    }

    /// Identity of the adapter, including its trained weights and trainer.
    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_QUAD_ADAPTER, &[&self.encode_unsigned()])
    }

    /// Verify structure, dimensions, finiteness, trainer binding and signature.
    pub fn verify(&self) -> Result<(), String> {
        if self.version != QUAD_ADAPTER_VERSION {
            return Err(format!("unsupported adapter version {}", self.version));
        }
        self.source.validate()?;
        self.target.validate()?;
        let want = self.target.dim as usize * expanded_dim(self.source.dim as usize);
        if self.weight.len() != want {
            return Err("adapter weight length does not match its dimensions".into());
        }
        if self.bias.len() != self.target.dim as usize {
            return Err("adapter bias length does not match its target".into());
        }
        if self
            .weight
            .iter()
            .chain(self.bias.iter())
            .any(|v| !v.is_finite())
        {
            return Err("adapter contains a non-finite parameter".into());
        }
        if self.samples == 0 {
            return Err("adapter claims zero training samples".into());
        }
        if !self.train_mse.is_finite() || self.train_mse < 0.0 {
            return Err("adapter training MSE is invalid".into());
        }
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.trainer {
            return Err("adapter key bundle is not the trainer".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.hash())
            .map_err(|_| "adapter signature invalid".to_string())
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let source = self.source.encode();
        let target = self.target.encode();
        let mut w = Writer::with_capacity(64 + source.len() + target.len() + self.weight.len() * 4);
        w.u8(self.version)
            .u32le(source.len() as u32)
            .raw(&source)
            .u32le(target.len() as u32)
            .raw(&target)
            .u32le(self.samples)
            .u32le(self.train_mse.to_bits())
            .fixed(&self.trainer)
            .u32le(self.weight.len() as u32);
        for v in &self.weight {
            w.u32le(v.to_bits());
        }
        w.u32le(self.bias.len() as u32);
        for v in &self.bias {
            w.u32le(v.to_bits());
        }
        w.into_vec()
    }

    /// Canonical transport encoding including signature bundles.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.encode_unsigned();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(body.len() + sigs.len() + keys.len() + 16);
        w.u32le(body.len() as u32)
            .raw(&body)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    /// Strict inverse of [`QuadraticAdapter::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_QUAD_BYTES {
            return Err("adapter over the size cap".into());
        }
        let mut r = Reader::new(bytes);
        let body_len = r.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if body_len > MAX_QUAD_BYTES {
            return Err("adapter: body over cap".into());
        }
        let mut br = Reader::new(
            r.fixed_slice(body_len)
                .map_err(|e| format!("adapter: {e}"))?,
        );
        let version = br.u8().map_err(|e| format!("adapter: {e}"))?;
        let source_len = br.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if source_len > 4 * 1024 {
            return Err("adapter: source space over cap".into());
        }
        let mut sr = Reader::new(
            br.fixed_slice(source_len)
                .map_err(|e| format!("adapter: {e}"))?,
        );
        let source = ModelSpace::decode(&mut sr)?;
        sr.expect_end().map_err(|e| format!("adapter: {e}"))?;
        let target_len = br.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if target_len > 4 * 1024 {
            return Err("adapter: target space over cap".into());
        }
        let mut tr = Reader::new(
            br.fixed_slice(target_len)
                .map_err(|e| format!("adapter: {e}"))?,
        );
        let target = ModelSpace::decode(&mut tr)?;
        tr.expect_end().map_err(|e| format!("adapter: {e}"))?;
        let samples = br.u32le().map_err(|e| format!("adapter: {e}"))?;
        let train_mse = f32::from_bits(br.u32le().map_err(|e| format!("adapter: {e}"))?);
        let trainer = br.fixed().map_err(|e| format!("adapter: {e}"))?;
        let weight_len = br.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if weight_len > MAX_QUAD_BYTES / 4 {
            return Err("adapter: weight count over cap".into());
        }
        let mut weight = Vec::with_capacity(weight_len);
        for _ in 0..weight_len {
            weight.push(f32::from_bits(
                br.u32le().map_err(|e| format!("adapter: {e}"))?,
            ));
        }
        let bias_len = br.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if bias_len > MAX_QUAD_BYTES / 4 {
            return Err("adapter: bias count over cap".into());
        }
        let mut bias = Vec::with_capacity(bias_len);
        for _ in 0..bias_len {
            bias.push(f32::from_bits(
                br.u32le().map_err(|e| format!("adapter: {e}"))?,
            ));
        }
        br.expect_end().map_err(|e| format!("adapter: {e}"))?;
        let sigs_len = r.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err("adapter: signature bundle over cap".into());
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|e| format!("adapter: {e}"))?,
        )
        .map_err(|e| format!("adapter: {e}"))?;
        let keys_len = r.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if keys_len > 8 * 1024 {
            return Err("adapter: key bundle over cap".into());
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|e| format!("adapter: {e}"))?,
        )
        .map_err(|e| format!("adapter: {e}"))?;
        r.expect_end().map_err(|e| format!("adapter: {e}"))?;
        let adapter = QuadraticAdapter {
            version,
            source,
            target,
            weight,
            bias,
            samples,
            train_mse,
            trainer,
            sigs,
            keys,
        };
        adapter.verify()?;
        Ok(adapter)
    }
}
