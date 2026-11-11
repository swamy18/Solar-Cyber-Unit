//! Cross-architecture representation adapters.
//!
//! An adapter is a small, reusable, signed linear map from one model space to
//! another. It is trained by ridge regression on paired activations
//! `(source, target)` and never requires either model's weights. This is the
//! "reuse a capability without downloading the model" primitive: the owner of
//! the target space publishes a space descriptor and an adapter, and a caller
//! translates source representations locally before invoking the target model.
//!
//! A linear adapter is honest about what it can express: it is a projection,
//! not a semantic bridge. Nonlinear adapters (MLP/attention) are a later
//! milestone; the format carries a version so they can be added without
//! silently changing the meaning of existing bytes.

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::space::{ModelSpace, RepresentationEnvelope};

pub const ADAPTER_VERSION: u8 = 1;
const DOM_ADAPTER: &[u8] = b"srct/cnnp/adapter/v1";
const MAX_ADAPTER_BYTES: usize = 16 * 1024 * 1024;

/// A signed affine map `target = W * source + b`.
#[derive(Clone, Debug, PartialEq)]
pub struct LinearAdapter {
    pub version: u8,
    pub source: ModelSpace,
    pub target: ModelSpace,
    /// `target.dim * source.dim`, row-major by target unit.
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

impl LinearAdapter {
    // Matrix elimination is index-based by construction; naming the indices is
    // clearer and less error-prone than threading iterators through a pivot.
    #[allow(clippy::needless_range_loop)]
    /// Fit and sign an adapter with ridge regression.
    ///
    /// `ridge` regularizes the weights (the bias term is left unregularized).
    /// The fit is deterministic: identical pairs, ridge and spaces produce the
    /// same bytes, so two parties can reproduce and verify an adapter.
    pub fn fit(
        source: ModelSpace,
        target: ModelSpace,
        pairs: &[(Vec<f32>, Vec<f32>)],
        ridge: f32,
        trainer: &Wallet,
    ) -> Result<Self, String> {
        source.validate()?;
        target.validate()?;
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

        // Normal equations: (X^T X + lambda I) W = X^T Y, with a bias column.
        let n = d + 1;
        let mut a = vec![vec![0.0f64; n]; n];
        let mut b = vec![vec![0.0f64; t]; n];
        for (x, y) in pairs {
            let mut row = Vec::with_capacity(n);
            row.extend(x.iter().map(|v| *v as f64));
            row.push(1.0);
            for i in 0..n {
                for j in 0..n {
                    a[i][j] += row[i] * row[j];
                }
                for k in 0..t {
                    b[i][k] += row[i] * y[k] as f64;
                }
            }
        }
        for i in 0..d {
            a[i][i] += ridge as f64;
        }

        // Gauss-Jordan with partial pivoting on [A | B].
        for col in 0..n {
            let mut pivot = col;
            for row in col + 1..n {
                if a[row][col].abs() > a[pivot][col].abs() {
                    pivot = row;
                }
            }
            if a[pivot][col].abs() < 1e-12 {
                return Err("adapter fit is singular; add ridge or more data".into());
            }
            a.swap(col, pivot);
            b.swap(col, pivot);
            let inv = 1.0 / a[col][col];
            for j in col..n {
                a[col][j] *= inv;
            }
            for k in 0..t {
                b[col][k] *= inv;
            }
            for row in 0..n {
                if row == col {
                    continue;
                }
                let factor = a[row][col];
                if factor == 0.0 {
                    continue;
                }
                for j in col..n {
                    a[row][j] -= factor * a[col][j];
                }
                for k in 0..t {
                    b[row][k] -= factor * b[col][k];
                }
            }
        }

        let mut weight = vec![0.0f32; t * d];
        let mut bias = vec![0.0f32; t];
        for k in 0..t {
            for i in 0..d {
                let v = b[i][k];
                if !v.is_finite() || v.abs() > f32::MAX as f64 {
                    return Err("adapter weights are not representable as f32".into());
                }
                weight[k * d + i] = v as f32;
            }
            let v = b[d][k];
            if !v.is_finite() || v.abs() > f32::MAX as f64 {
                return Err("adapter bias is not representable as f32".into());
            }
            bias[k] = v as f32;
        }

        let address = trainer.address().map_err(|e| e.to_string())?;
        let mut adapter = LinearAdapter {
            version: ADAPTER_VERSION,
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
        let d = self.source.dim as usize;
        let t = self.target.dim as usize;
        let mut out = vec![0.0f32; t];
        for (k, slot) in out.iter_mut().enumerate() {
            let mut acc = self.bias[k];
            for (i, xi) in input.iter().enumerate() {
                acc += self.weight[k * d + i] * xi;
            }
            if !acc.is_finite() {
                return Err("adapter output is not finite".into());
            }
            *slot = acc;
        }
        Ok(out)
    }

    /// Translate a signed representation from the adapter's source space.
    ///
    /// The envelope must verify and name exactly the source space the adapter
    /// was fitted for. The returned vector is in the target space; signing it
    /// as a new envelope is the caller's (translator's) act.
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
        sha256_dom(DOM_ADAPTER, &[&self.encode_unsigned()])
    }

    /// Verify structure, dimensions, finiteness, trainer binding and signature.
    pub fn verify(&self) -> Result<(), String> {
        if self.version != ADAPTER_VERSION {
            return Err(format!("unsupported adapter version {}", self.version));
        }
        self.source.validate()?;
        self.target.validate()?;
        if self.weight.len() != self.target.dim as usize * self.source.dim as usize {
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

    /// Strict inverse of [`LinearAdapter::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_ADAPTER_BYTES {
            return Err("adapter over the size cap".into());
        }
        let mut r = Reader::new(bytes);
        let body_len = r.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if body_len > MAX_ADAPTER_BYTES {
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
        if weight_len > MAX_ADAPTER_BYTES / 4 {
            return Err("adapter: weight count over cap".into());
        }
        let mut weight = Vec::with_capacity(weight_len);
        for _ in 0..weight_len {
            weight.push(f32::from_bits(
                br.u32le().map_err(|e| format!("adapter: {e}"))?,
            ));
        }
        let bias_len = br.u32le().map_err(|e| format!("adapter: {e}"))? as usize;
        if bias_len > MAX_ADAPTER_BYTES / 4 {
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
        let adapter = LinearAdapter {
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
