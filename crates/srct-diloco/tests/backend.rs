//! Backend conformance and fail-closed tests.
//!
//! These prove the hardware seam's policy, not just its interface: the CPU
//! reference passes, a perturbed kernel fails, a `Statistical` backend can
//! pass the tolerance but is still refused for consensus, and an unavailable
//! device fails closed.

use srct_diloco::backend::{
    check_backend, local_update_with, require_determinism, BackendCapabilities, BackendError,
    BlockedBackend, CpuBackend, DeterminismClass, DeviceClass, FixedPointBackend, TrainBackend,
};
use srct_diloco::data::two_moons;
use srct_diloco::model::Mlp;
use srct_diloco::Sample;

#[derive(Clone, Copy)]
struct Perturbed {
    name: &'static str,
    delta: f32,
    determinism: DeterminismClass,
}

impl TrainBackend for Perturbed {
    fn name(&self) -> &'static str {
        self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            device: DeviceClass::Other,
            determinism: self.determinism,
            dtype: "f32",
            max_batch: 1_024,
            memory_bytes: 1,
        }
    }

    fn forward(&self, model: &Mlp, x: &[f32; 2]) -> Result<f32, BackendError> {
        CpuBackend.forward(model, x)
    }

    fn loss_and_grad(&self, model: &Mlp, samples: &[Sample]) -> Result<(f32, Mlp), BackendError> {
        let (loss, mut grad) = CpuBackend.loss_and_grad(model, samples)?;
        for v in grad
            .w1
            .iter_mut()
            .chain(grad.b1.iter_mut())
            .chain(grad.w2.iter_mut())
            .chain(grad.b2.iter_mut())
        {
            *v += self.delta;
        }
        Ok((loss + self.delta, grad))
    }

    fn sgd_step(&self, model: &Mlp, grad: &Mlp, lr: f32) -> Result<Mlp, BackendError> {
        CpuBackend.sgd_step(model, grad, lr)
    }
}

#[derive(Clone, Copy)]
struct Unavailable;

impl TrainBackend for Unavailable {
    fn name(&self) -> &'static str {
        "unavailable-device"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            device: DeviceClass::Gpu,
            determinism: DeterminismClass::Reproducible,
            dtype: "f32",
            max_batch: 1,
            memory_bytes: 1,
        }
    }

    fn forward(&self, _model: &Mlp, _x: &[f32; 2]) -> Result<f32, BackendError> {
        Err(BackendError::Unavailable("device lost"))
    }

    fn loss_and_grad(&self, _model: &Mlp, _samples: &[Sample]) -> Result<(f32, Mlp), BackendError> {
        Err(BackendError::Unavailable("device lost"))
    }

    fn sgd_step(&self, _model: &Mlp, _grad: &Mlp, _lr: f32) -> Result<Mlp, BackendError> {
        Err(BackendError::Unavailable("device lost"))
    }
}

#[test]
fn the_cpu_reference_passes_conformance_and_is_reproducible() {
    let report = check_backend(&CpuBackend).unwrap();
    assert_eq!(report.determinism, DeterminismClass::Reproducible);
    assert_eq!(report.max_forward_delta, 0.0);
    assert_eq!(report.max_gradient_delta, 0.0);
    assert_eq!(report.max_step_delta, 0.0);
    assert!(report.checkpoint_match);
    assert_eq!(report.kernel_hash, CpuBackend.kernel_hash());
}

#[test]
fn the_cpu_reference_cannot_be_used_as_a_consensus_kernel() {
    let caps = CpuBackend.capabilities();
    assert!(require_determinism(&caps, DeterminismClass::Reproducible).is_ok());
    assert!(require_determinism(&caps, DeterminismClass::BitExact).is_err());
}

#[test]
fn a_perturbed_reproducible_backend_fails_conformance() {
    let bad = Perturbed {
        name: "perturbed",
        delta: 0.5,
        determinism: DeterminismClass::Reproducible,
    };
    assert!(matches!(
        check_backend(&bad),
        Err(BackendError::ConformanceFailed { .. })
    ));
}

#[test]
fn a_statistical_backend_can_pass_tolerance_but_not_consensus() {
    let noisy = Perturbed {
        name: "statistical",
        delta: 1e-4,
        determinism: DeterminismClass::Statistical,
    };
    let report = check_backend(&noisy).unwrap();
    assert_eq!(report.determinism, DeterminismClass::Statistical);
    assert!(require_determinism(&noisy.capabilities(), DeterminismClass::BitExact).is_err());
}

#[test]
fn a_bit_exact_backend_with_any_drift_is_refused() {
    let almost = Perturbed {
        name: "almost-bit-exact",
        delta: 1e-7,
        determinism: DeterminismClass::BitExact,
    };
    assert!(matches!(
        check_backend(&almost),
        Err(BackendError::ConformanceFailed { .. })
    ));
}

#[test]
fn an_unavailable_device_fails_closed() {
    assert!(matches!(
        check_backend(&Unavailable),
        Err(BackendError::Unavailable(_))
    ));
    let global = Mlp::new(5);
    let shard = two_moons(4, 5);
    assert!(matches!(
        local_update_with(&Unavailable, &global, &shard, 2, 0.1),
        Err(BackendError::Unavailable(_))
    ));
}

#[test]
fn local_update_through_the_backend_matches_direct_cpu_training() {
    let global = Mlp::new(7);
    let shard = two_moons(8, 7);
    let update = local_update_with(&CpuBackend, &global, &shard, 6, 0.05).unwrap();
    let mut direct = global.clone();
    for _ in 0..6 {
        let (_, grad) = direct.loss_and_grad(&shard);
        direct.sgd_step(&grad, 0.05);
    }
    assert_eq!(update.model.hash(), direct.hash());
    assert!(update.loss_after <= update.loss_before);
    assert_eq!(update.samples, shard.len());
    assert_eq!(update.steps, 6);
}

#[test]
fn the_blocked_executor_passes_conformance_as_statistical() {
    let backend = BlockedBackend::new(3);
    let caps = backend.capabilities();
    assert_eq!(caps.device, DeviceClass::Other);
    assert_eq!(caps.determinism, DeterminismClass::Statistical);
    assert_eq!(caps.dtype, "f32");
    assert_eq!(caps.max_batch, 3);
    let report = check_backend(&backend).unwrap();
    assert_eq!(report.determinism, DeterminismClass::Statistical);
    assert!(report.max_forward_delta <= 1e-3);
    assert!(report.max_loss_delta <= 1e-3);
    assert!(report.max_gradient_delta <= 1e-3);
    assert!(report.max_step_delta <= 1e-3);
    // A different execution strategy hashes differently: consensus pins the
    // hash, never the device name.
    assert_ne!(report.kernel_hash, CpuBackend.kernel_hash());
    assert_eq!(report.kernel_hash, backend.kernel_hash());
    // Statistical can interoperate but never finalize consensus.
    assert!(require_determinism(&caps, DeterminismClass::Statistical).is_ok());
    assert!(require_determinism(&caps, DeterminismClass::BitExact).is_err());
}

#[test]
fn blocked_chunking_matches_the_reference_within_rounding() {
    let model = Mlp::new(21);
    let samples = two_moons(8, 21);
    let (reference_loss, reference_grad) = CpuBackend.loss_and_grad(&model, &samples).unwrap();
    for block in [1, 2, 3, 5, 8, 64] {
        let backend = BlockedBackend::new(block);
        let (loss, grad) = backend.loss_and_grad(&model, &samples).unwrap();
        assert!(
            (loss - reference_loss).abs() < 1e-5,
            "block {block}: loss delta too large"
        );
        let worst = grad
            .w1
            .iter()
            .chain(grad.b1.iter())
            .chain(grad.w2.iter())
            .chain(grad.b2.iter())
            .zip(
                reference_grad
                    .w1
                    .iter()
                    .chain(reference_grad.b1.iter())
                    .chain(reference_grad.w2.iter())
                    .chain(reference_grad.b2.iter()),
            )
            .map(|(a, b)| (a - b).abs())
            .fold(0.0f32, f32::max);
        assert!(worst < 1e-5, "block {block}: gradient delta too large");
    }
}

#[test]
fn blocked_training_reduces_loss_like_the_reference() {
    let global = Mlp::new(7);
    let shard = two_moons(16, 7);
    let update = local_update_with(&BlockedBackend::new(5), &global, &shard, 6, 0.05).unwrap();
    assert!(update.loss_after <= update.loss_before);
    assert_eq!(update.samples, shard.len());
    let reference = local_update_with(&CpuBackend, &global, &shard, 6, 0.05).unwrap();
    assert!((update.loss_after - reference.loss_after).abs() < 1e-3);
}

#[test]
fn a_zero_block_and_empty_batches_fail_closed() {
    assert!(matches!(
        check_backend(&BlockedBackend::new(0)),
        Err(BackendError::Malformed(_))
    ));
    let model = Mlp::new(3);
    assert!(matches!(
        BlockedBackend::new(4).loss_and_grad(&model, &[]),
        Err(BackendError::Malformed(_))
    ));
    assert!(matches!(
        CpuBackend.loss_and_grad(&model, &[]),
        Err(BackendError::Malformed(_))
    ));
}

#[test]
fn the_fixed_point_backend_is_bit_exact_by_construction() {
    let caps = FixedPointBackend.capabilities();
    assert_eq!(caps.device, DeviceClass::Cpu);
    assert_eq!(caps.determinism, DeterminismClass::BitExact);
    assert_eq!(caps.dtype, "q16.16");
    // The consensus gate accepts the declared class.
    assert!(require_determinism(&caps, DeterminismClass::BitExact).is_ok());
}

#[test]
fn fixed_point_training_is_byte_identical_across_runs() {
    let global = Mlp::new(7);
    let shard = two_moons(16, 7);
    let first = local_update_with(&FixedPointBackend, &global, &shard, 6, 0.05).unwrap();
    let second = local_update_with(&FixedPointBackend, &global, &shard, 6, 0.05).unwrap();
    assert_eq!(first.model.hash(), second.model.hash());
    assert_eq!(first.loss_before.to_bits(), second.loss_before.to_bits());
    assert_eq!(first.loss_after.to_bits(), second.loss_after.to_bits());
    // And it actually learns: loss goes down on separable data.
    assert!(first.loss_after < first.loss_before);
    assert!(first.loss_after.is_finite());
}

#[test]
fn fixed_point_rejects_non_f32_kernels_and_bad_inputs() {
    // The f32-parity conformance suite only speaks f32: a q16.16 backend is
    // refused at the dtype gate, not silently compared.
    assert!(matches!(
        check_backend(&FixedPointBackend),
        Err(BackendError::Unsupported(_))
    ));
    let model = Mlp::new(3);
    assert!(matches!(
        FixedPointBackend.loss_and_grad(&model, &[]),
        Err(BackendError::Malformed(_))
    ));
    assert!(matches!(
        FixedPointBackend.sgd_step(&model, &model, -0.1),
        Err(BackendError::Malformed(_))
    ));
    let mut nan_model = Mlp::new(3);
    nan_model.w1[0] = f32::NAN;
    assert!(matches!(
        FixedPointBackend.forward(&nan_model, &[0.0, 0.0]),
        Err(BackendError::Malformed(_))
    ));
}

#[test]
fn fixed_point_forward_matches_sigmoid_shape() {
    // Zero input through a zero-bias unit: sigmoid(0) = 0.5 exactly.
    let model = Mlp::zeros();
    let p = FixedPointBackend.forward(&model, &[0.0, 0.0]).unwrap();
    assert!((p - 0.5).abs() < 1e-4, "sigmoid(0) should be 0.5, got {p}");
    assert!(p.is_finite());
}
