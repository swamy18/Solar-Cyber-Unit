//! Hardware backend seam for DiLoCo training.
//!
//! The protocol -- rounds, signed updates, Byzantine filtering, scoring and
//! rewards -- is hardware-independent. Only the kernels that compute a forward
//! pass, a gradient and an optimizer step are device-specific. This module
//! defines the seam and the CPU reference implementation, plus a conformance
//! suite every future backend must pass before it can be selected.
//!
//! Determinism is explicit. `f32` kernels are **not** bit-exact across every
//! compiler and CPU, so the CPU reference is classified `Reproducible`, not
//! `BitExact`. A backend may only be used for consensus finalization when its
//! class is `BitExact`; `require_determinism` is the gate, not an assumption.
//!
//! Adding a GPU, TPU, NPU, Apple-silicon or photonic backend means implementing
//! [`TrainBackend`] and passing [`check_backend`] -- not editing the round,
//! validation or reward code.

use srct_core::hash::{sha256_dom, Hash};
use srct_core::ser::Writer;

use crate::data::{two_moons, Sample};
use crate::fixed::{from_f32, quantize_samples, to_f32, FixedMlp};
use crate::model::Mlp;

pub const BACKEND_VERSION: u8 = 1;
const DOM_BACKEND: &[u8] = b"srct/diloco/backend/v1";

/// Device family a backend targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceClass {
    Cpu = 0,
    Gpu = 1,
    Tpu = 2,
    Npu = 3,
    AppleSoc = 4,
    Photonic = 5,
    Other = 6,
}

impl DeviceClass {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DeviceClass::Cpu),
            1 => Some(DeviceClass::Gpu),
            2 => Some(DeviceClass::Tpu),
            3 => Some(DeviceClass::Npu),
            4 => Some(DeviceClass::AppleSoc),
            5 => Some(DeviceClass::Photonic),
            6 => Some(DeviceClass::Other),
            _ => None,
        }
    }
}

/// How reproducible a backend's numerics are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeterminismClass {
    /// Close numerically, not reproducible.
    Statistical = 0,
    /// Same backend/driver/shapes reproduce; other backends may differ.
    Reproducible = 1,
    /// Pinned integer/fixed-point kernels with identical bytes everywhere.
    BitExact = 2,
}

/// Declared capabilities of a backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub device: DeviceClass,
    pub determinism: DeterminismClass,
    /// Element type exposed by the seam. The protocol currently requires `f32`.
    pub dtype: &'static str,
    pub max_batch: u32,
    pub memory_bytes: u64,
}

/// A backend failure. `Unavailable` is a normal state: a device that is absent
/// or lost must fail closed and let the caller stay on the CPU reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    Unavailable(&'static str),
    Unsupported(String),
    Malformed(String),
    NonFinite,
    ConformanceFailed { check: &'static str, detail: String },
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unavailable(what) => write!(f, "backend unavailable: {what}"),
            BackendError::Unsupported(what) => write!(f, "backend unsupported: {what}"),
            BackendError::Malformed(what) => write!(f, "backend input malformed: {what}"),
            BackendError::NonFinite => write!(f, "backend produced a non-finite value"),
            BackendError::ConformanceFailed { check, detail } => {
                write!(f, "backend conformance failed at {check}: {detail}")
            }
        }
    }
}

impl std::error::Error for BackendError {}

/// The device-specific training seam.
///
/// The signatures deliberately operate on the canonical [`Mlp`] so a backend
/// can be swapped without changing round code. A future GPU backend uploads
/// the model, runs its kernels and downloads the result; device buffers are an
/// internal optimisation, not a protocol concern.
pub trait TrainBackend {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    fn forward(&self, model: &Mlp, x: &[f32; 2]) -> Result<f32, BackendError>;
    fn loss_and_grad(&self, model: &Mlp, samples: &[Sample]) -> Result<(f32, Mlp), BackendError>;
    fn sgd_step(&self, model: &Mlp, grad: &Mlp, lr: f32) -> Result<Mlp, BackendError>;

    /// Content identity of the kernel and capability set. Consensus would pin
    /// this hash rather than trusting a device name.
    fn kernel_hash(&self) -> Hash {
        let caps = self.capabilities();
        let name = self.name();
        let mut w = Writer::with_capacity(128 + name.len() + caps.dtype.len());
        w.u8(BACKEND_VERSION)
            .u16le(name.len() as u16)
            .raw(name.as_bytes())
            .u8(caps.device.as_u8())
            .u8(caps.determinism as u8)
            .u16le(caps.dtype.len() as u16)
            .raw(caps.dtype.as_bytes())
            .u32le(caps.max_batch)
            .u64le(caps.memory_bytes);
        sha256_dom(DOM_BACKEND, &[w.as_slice()])
    }
}

/// The CPU reference backend: one-shot f32 kernels over the whole batch.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuBackend;

impl TrainBackend for CpuBackend {
    fn name(&self) -> &'static str {
        "cpu-reference-f32"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            device: DeviceClass::Cpu,
            // Honest classification: f32 is reproducible for one build/host,
            // not bit-exact across every compiler and CPU.
            determinism: DeterminismClass::Reproducible,
            dtype: "f32",
            max_batch: 65_536,
            memory_bytes: 0,
        }
    }

    fn forward(&self, model: &Mlp, x: &[f32; 2]) -> Result<f32, BackendError> {
        let (_, p) = model.forward(x);
        if p.is_finite() {
            Ok(p)
        } else {
            Err(BackendError::NonFinite)
        }
    }

    fn loss_and_grad(&self, model: &Mlp, samples: &[Sample]) -> Result<(f32, Mlp), BackendError> {
        if samples.is_empty() {
            return Err(BackendError::Malformed("empty sample batch".into()));
        }
        let (loss, grad) = model.loss_and_grad(samples);
        if !loss.is_finite() || !grad.is_finite() {
            return Err(BackendError::NonFinite);
        }
        Ok((loss, grad))
    }

    fn sgd_step(&self, model: &Mlp, grad: &Mlp, lr: f32) -> Result<Mlp, BackendError> {
        if !lr.is_finite() || lr < 0.0 {
            return Err(BackendError::Malformed("learning rate is invalid".into()));
        }
        if !grad.is_finite() {
            return Err(BackendError::NonFinite);
        }
        let mut next = model.clone();
        next.sgd_step(grad, lr);
        if !next.is_finite() {
            return Err(BackendError::NonFinite);
        }
        Ok(next)
    }
}

/// A block-partitioned executor: the heterogeneity proof.
///
/// Real accelerators expose small fast memories and fixed transfer sizes;
/// this backend models that constraint honestly on CPU hardware: it never
/// holds more than `block` samples at once, chunking larger batches and
/// combining per-block means. Blocked summation rounds differently than the
/// one-shot CPU reference, so it is classified `Statistical` — close enough
/// to interoperate (tolerance 1e-3), never bit-identical. Device class is
/// `Other`: it proves the seam takes new execution strategies, not that this
/// machine grew an NPU.
///
/// A zero block size fails closed in `check_backend` (`max_batch` must be
/// positive), like a misconfigured device.
#[derive(Clone, Copy, Debug)]
pub struct BlockedBackend {
    block: usize,
}

impl BlockedBackend {
    pub fn new(block: usize) -> Self {
        BlockedBackend { block }
    }
}

impl TrainBackend for BlockedBackend {
    fn name(&self) -> &'static str {
        "blocked-executor-f32"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            device: DeviceClass::Other,
            determinism: DeterminismClass::Statistical,
            dtype: "f32",
            max_batch: self.block.min(u32::MAX as usize) as u32,
            // Simulated scratchpad: 64 KiB of fast memory.
            memory_bytes: 65_536,
        }
    }

    fn forward(&self, model: &Mlp, x: &[f32; 2]) -> Result<f32, BackendError> {
        let (_, p) = model.forward(x);
        if p.is_finite() {
            Ok(p)
        } else {
            Err(BackendError::NonFinite)
        }
    }

    fn loss_and_grad(&self, model: &Mlp, samples: &[Sample]) -> Result<(f32, Mlp), BackendError> {
        if samples.is_empty() {
            return Err(BackendError::Malformed("empty sample batch".into()));
        }
        if self.block == 0 {
            return Err(BackendError::Malformed("block size is zero".into()));
        }
        let mut loss_sum = 0.0f32;
        let mut acc = Mlp::zeros();
        for chunk in samples.chunks(self.block) {
            let (loss, grad) = model.loss_and_grad(chunk);
            if !loss.is_finite() || !grad.is_finite() {
                return Err(BackendError::NonFinite);
            }
            let n = chunk.len() as f32;
            loss_sum += loss * n;
            for (dst, src) in acc
                .w1
                .iter_mut()
                .zip(grad.w1.iter())
                .chain(acc.b1.iter_mut().zip(grad.b1.iter()))
                .chain(acc.w2.iter_mut().zip(grad.w2.iter()))
                .chain(acc.b2.iter_mut().zip(grad.b2.iter()))
            {
                *dst += *src * n;
            }
        }
        let inv = 1.0 / samples.len() as f32;
        loss_sum *= inv;
        for v in acc
            .w1
            .iter_mut()
            .chain(acc.b1.iter_mut())
            .chain(acc.w2.iter_mut())
            .chain(acc.b2.iter_mut())
        {
            *v *= inv;
        }
        if !loss_sum.is_finite() || !acc.is_finite() {
            return Err(BackendError::NonFinite);
        }
        Ok((loss_sum, acc))
    }

    fn sgd_step(&self, model: &Mlp, grad: &Mlp, lr: f32) -> Result<Mlp, BackendError> {
        CpuBackend.sgd_step(model, grad, lr)
    }
}

/// Fixed-point Q16.16 integer kernels: the BitExact tier.
///
/// All arithmetic is integer, so identical inputs produce identical bytes on
/// every host — the property the consensus gate requires. Activations are
/// integer Padé-tanh/sigmoid approximations and the objective is MSE (see
/// [`crate::fixed`]), so this trains a close cousin of the `f32` reference,
/// not the identical function. Cross-dtype parity is Statistical by design;
/// BitExact is claimed within this dtype only.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixedPointBackend;

impl TrainBackend for FixedPointBackend {
    fn name(&self) -> &'static str {
        "fixed-point-q16-16"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            device: DeviceClass::Cpu,
            determinism: DeterminismClass::BitExact,
            dtype: "q16.16",
            max_batch: 65_536,
            memory_bytes: 0,
        }
    }

    fn forward(&self, model: &Mlp, x: &[f32; 2]) -> Result<f32, BackendError> {
        if !model.is_finite() || !x.iter().all(|v| v.is_finite()) {
            return Err(BackendError::Malformed("non-finite model or input".into()));
        }
        let fixed = FixedMlp::from_mlp(model);
        let (_, p) = fixed.forward(&[from_f32(x[0]), from_f32(x[1])]);
        Ok(to_f32(p))
    }

    fn loss_and_grad(&self, model: &Mlp, samples: &[Sample]) -> Result<(f32, Mlp), BackendError> {
        if samples.is_empty() {
            return Err(BackendError::Malformed("empty sample batch".into()));
        }
        if !model.is_finite()
            || !samples
                .iter()
                .all(|s| s.x.iter().all(|v| v.is_finite()) && s.y.is_finite())
        {
            return Err(BackendError::Malformed(
                "non-finite model or samples".into(),
            ));
        }
        let fixed = FixedMlp::from_mlp(model);
        let (loss, grad) = fixed.loss_and_grad(&quantize_samples(samples));
        Ok((to_f32(loss), grad.to_mlp()))
    }

    fn sgd_step(&self, model: &Mlp, grad: &Mlp, lr: f32) -> Result<Mlp, BackendError> {
        if !lr.is_finite() || lr < 0.0 {
            return Err(BackendError::Malformed("learning rate is invalid".into()));
        }
        if !model.is_finite() || !grad.is_finite() {
            return Err(BackendError::NonFinite);
        }
        let mut fixed = FixedMlp::from_mlp(model);
        fixed.sgd_step(&FixedMlp::from_mlp(grad), from_f32(lr));
        Ok(fixed.to_mlp())
    }
}

/// Refuse a backend that cannot meet the required determinism class.
///
/// Consensus finalization requires `BitExact`. The CPU reference is
/// `Reproducible`, so this gate intentionally refuses to treat it as a
/// consensus kernel; that is the fixed-point milestone's job.
pub fn require_determinism(
    caps: &BackendCapabilities,
    required: DeterminismClass,
) -> Result<(), BackendError> {
    if caps.determinism < required {
        return Err(BackendError::Unsupported(format!(
            "{:?} backend is {:?}, requires {:?}",
            caps.device, caps.determinism, required
        )));
    }
    Ok(())
}

/// Result of one local training run through a backend.
#[derive(Clone, Debug, PartialEq)]
pub struct LocalUpdate {
    pub model: Mlp,
    pub loss_before: f32,
    pub loss_after: f32,
    pub samples: usize,
    pub steps: u32,
}

/// Run `steps` local SGD steps on `shard` through `backend`.
///
/// This is the function a worker uses. A GPU/NPU backend can replace the CPU
/// implementation without changing the caller.
pub fn local_update_with(
    backend: &dyn TrainBackend,
    global: &Mlp,
    shard: &[Sample],
    steps: u32,
    lr: f32,
) -> Result<LocalUpdate, BackendError> {
    if shard.is_empty() {
        return Err(BackendError::Malformed("empty shard".into()));
    }
    if steps == 0 {
        return Err(BackendError::Malformed("zero local steps".into()));
    }
    if !lr.is_finite() || lr <= 0.0 {
        return Err(BackendError::Malformed("learning rate is invalid".into()));
    }
    let (loss_before, _) = backend.loss_and_grad(global, shard)?;
    let mut model = global.clone();
    for _ in 0..steps {
        let (_, grad) = backend.loss_and_grad(&model, shard)?;
        model = backend.sgd_step(&model, &grad, lr)?;
    }
    let (loss_after, _) = backend.loss_and_grad(&model, shard)?;
    Ok(LocalUpdate {
        model,
        loss_before,
        loss_after,
        samples: shard.len(),
        steps,
    })
}

/// What a conformance run measured.
#[derive(Clone, Debug, PartialEq)]
pub struct ConformanceReport {
    pub backend: &'static str,
    pub kernel_hash: Hash,
    pub determinism: DeterminismClass,
    pub max_forward_delta: f32,
    pub max_loss_delta: f32,
    pub max_gradient_delta: f32,
    pub max_step_delta: f32,
    pub checkpoint_match: bool,
}

/// Run the conformance suite every backend must pass.
///
/// The suite compares the backend against the CPU reference on fixed vectors:
/// forward pass, loss and gradient, one optimizer step, and a five-step local
/// update. Tolerances follow the declared determinism class:
///
/// - `BitExact`: every delta must be exactly zero and the checkpoint must match;
/// - `Reproducible`: deltas <= 1e-6;
/// - `Statistical`: deltas <= 1e-3, and the backend still cannot finalize
///   consensus without a stronger evidence mode.
pub fn check_backend(backend: &dyn TrainBackend) -> Result<ConformanceReport, BackendError> {
    let caps = backend.capabilities();
    if caps.dtype != "f32" {
        return Err(BackendError::Unsupported(format!(
            "protocol requires f32 kernels, backend exposes {}",
            caps.dtype
        )));
    }
    if caps.max_batch == 0 {
        return Err(BackendError::Malformed("max_batch must be positive".into()));
    }
    if backend.name().is_empty() {
        return Err(BackendError::Malformed("backend name is empty".into()));
    }

    let reference = Mlp::new(123);
    let samples = two_moons(8, 99);

    let mut max_forward_delta = 0.0f32;
    for s in &samples {
        let reference_p = reference.forward(&s.x).1;
        let got = backend.forward(&reference, &s.x)?;
        max_forward_delta = max_forward_delta.max((got - reference_p).abs());
    }

    let (reference_loss, reference_grad) = reference.loss_and_grad(&samples);
    let (got_loss, got_grad) = backend.loss_and_grad(&reference, &samples)?;
    let max_loss_delta = (got_loss - reference_loss).abs();
    let max_gradient_delta = max_delta(&reference_grad.params(), &got_grad.params());

    let mut reference_step = reference.clone();
    reference_step.sgd_step(&reference_grad, 0.1);
    let got_step = backend.sgd_step(&reference, &reference_grad, 0.1)?;
    let max_step_delta = max_delta(&reference_step.params(), &got_step.params());

    let reference_local = local_update_reference(&reference, &samples, 5, 0.05)?;
    let got_local = local_update_with(backend, &reference, &samples, 5, 0.05)?;
    let checkpoint_match = reference_local.hash() == got_local.model.hash();
    let local_delta = max_delta(&reference_local.params(), &got_local.model.params());

    let tolerance = match caps.determinism {
        DeterminismClass::BitExact => 0.0,
        DeterminismClass::Reproducible => 1e-6,
        DeterminismClass::Statistical => 1e-3,
    };
    let worst = max_forward_delta
        .max(max_loss_delta)
        .max(max_gradient_delta)
        .max(max_step_delta)
        .max(local_delta);
    if worst > tolerance {
        return Err(BackendError::ConformanceFailed {
            check: "parity",
            detail: format!(
                "worst delta {worst} exceeds {tolerance} for {:?}",
                caps.determinism
            ),
        });
    }
    if caps.determinism == DeterminismClass::BitExact && !checkpoint_match {
        return Err(BackendError::ConformanceFailed {
            check: "checkpoint",
            detail: "BitExact backend produced a different checkpoint hash".into(),
        });
    }

    Ok(ConformanceReport {
        backend: backend.name(),
        kernel_hash: backend.kernel_hash(),
        determinism: caps.determinism,
        max_forward_delta,
        max_loss_delta,
        max_gradient_delta,
        max_step_delta,
        checkpoint_match,
    })
}

/// Direct CPU reference local update, used by conformance comparisons.
fn local_update_reference(
    global: &Mlp,
    shard: &[Sample],
    steps: u32,
    lr: f32,
) -> Result<Mlp, BackendError> {
    let mut model = global.clone();
    for _ in 0..steps {
        let (_, grad) = model.loss_and_grad(shard);
        if !grad.is_finite() {
            return Err(BackendError::NonFinite);
        }
        model.sgd_step(&grad, lr);
    }
    if !model.is_finite() {
        return Err(BackendError::NonFinite);
    }
    Ok(model)
}

fn max_delta(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).abs())
        .fold(0.0f32, f32::max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_backend_declares_reproducible_not_bit_exact() {
        let caps = CpuBackend.capabilities();
        assert_eq!(caps.device, DeviceClass::Cpu);
        assert_eq!(caps.determinism, DeterminismClass::Reproducible);
        assert_eq!(caps.dtype, "f32");
    }

    #[test]
    fn consensus_gate_refuses_a_non_bit_exact_backend() {
        let caps = CpuBackend.capabilities();
        assert!(require_determinism(&caps, DeterminismClass::Reproducible).is_ok());
        assert!(require_determinism(&caps, DeterminismClass::BitExact).is_err());
    }

    #[test]
    fn kernel_hash_binds_name_and_capabilities() {
        let a = CpuBackend.kernel_hash();
        let b = CpuBackend.kernel_hash();
        assert_eq!(a, b);
        struct Other;
        impl TrainBackend for Other {
            fn name(&self) -> &'static str {
                "other"
            }
            fn capabilities(&self) -> BackendCapabilities {
                BackendCapabilities {
                    device: DeviceClass::Gpu,
                    determinism: DeterminismClass::Statistical,
                    dtype: "f32",
                    max_batch: 1,
                    memory_bytes: 1,
                }
            }
            fn forward(&self, model: &Mlp, x: &[f32; 2]) -> Result<f32, BackendError> {
                CpuBackend.forward(model, x)
            }
            fn loss_and_grad(
                &self,
                model: &Mlp,
                samples: &[Sample],
            ) -> Result<(f32, Mlp), BackendError> {
                CpuBackend.loss_and_grad(model, samples)
            }
            fn sgd_step(&self, model: &Mlp, grad: &Mlp, lr: f32) -> Result<Mlp, BackendError> {
                CpuBackend.sgd_step(model, grad, lr)
            }
        }
        assert_ne!(a, Other.kernel_hash());
    }
}
