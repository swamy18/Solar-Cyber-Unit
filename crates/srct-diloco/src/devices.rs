//! Hardware training backends: GPU, TPU, NPU, Apple silicon, photonic.
//!
//! Each backend implements [`crate::backend::TrainBackend`] behind a hardware
//! probe. The execution contract is strict:
//!
//! - **No device, no math.** Without the hardware (or its driver linked into
//!   this build) every entry point fails closed with
//!   [`crate::backend::BackendError::Unavailable`] — never a panic, never a
//!   wrong number. `probe()` is where a silicon build links its detection
//!   (`dlopen("libcuda.so")`, IOKit matching, `/dev/accel`, ...); this build
//!   carries no vendor SDK, so it reports absent.
//! - **Emulation is plumbing only.** `emulated()` runs the CPU reference
//!   kernels under the hardware device class, so shapes, dtypes, batching,
//!   kernel-hash binding and determinism gating are testable on any machine.
//!   Emulated names carry an `-emulated` suffix, so an emulated kernel hash
//!   can never be mistaken for silicon when backends are approved.
//! - **Determinism is declared, not assumed.** `f32` accelerator kernels are
//!   `Reproducible` (same backend + driver reproduces); only pinned
//!   integer kernels are `BitExact`. Photonic analog execution is
//!   `Statistical`.
//!
//! What this is not: a driver. Real kernels, collectives, device memory
//! management and power/thermal policy plug in behind `execute_*` — the seam
//! (capabilities, kernel hash, conformance, fail-closed absence) does not move
//! when they land.

use crate::backend::{
    BackendCapabilities, BackendError, CpuBackend, DeterminismClass, DeviceClass, TrainBackend,
};
use crate::data::Sample;
use crate::model::Mlp;

/// How this backend instance executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackendMode {
    /// Real silicon, when the probe finds it.
    Hardware,
    /// CPU reference kernels under a hardware device class, for plumbing
    /// tests. Never approvable for consensus finalization under its own name.
    Emulated,
}

macro_rules! define_backend {
    ($name:ident, $human:expr, $device:expr, $determinism:expr, $batch:expr, $mem:expr) => {
        #[doc = concat!("`", $human, "` training backend (prototyped seam).")]
        ///
        /// See the module docs for the execution contract: absent hardware
        /// fails closed, `emulated()` runs CPU kernels for plumbing tests.
        #[derive(Clone, Copy, Debug)]
        pub struct $name {
            mode: BackendMode,
        }

        impl $name {
            /// Use real silicon. The probe reports absent in any build
            /// without the vendor driver linked; every method then fails
            /// closed with `Unavailable`.
            pub fn hardware() -> Self {
                $name {
                    mode: BackendMode::Hardware,
                }
            }

            /// Run CPU reference kernels under this hardware device class.
            /// Plumbing tests only; the `-emulated` name keeps its kernel
            /// hash distinct from silicon.
            pub fn emulated() -> Self {
                $name {
                    mode: BackendMode::Emulated,
                }
            }

            /// Whether this instance will execute instead of failing closed.
            pub fn is_available(&self) -> bool {
                match self.mode {
                    BackendMode::Emulated => true,
                    BackendMode::Hardware => Self::probe(),
                }
            }

            /// Hardware presence probe. Link point for silicon builds
            /// (driver handle, device enumeration); always absent here.
            pub fn probe() -> bool {
                false
            }

            fn check_available(&self) -> Result<(), BackendError> {
                if self.is_available() {
                    Ok(())
                } else {
                    Err(BackendError::Unavailable(concat!(
                        $human,
                        " device not present in this build"
                    )))
                }
            }
        }

        impl TrainBackend for $name {
            fn name(&self) -> &'static str {
                match self.mode {
                    BackendMode::Hardware => concat!($human, "-f32"),
                    BackendMode::Emulated => concat!($human, "-f32-emulated"),
                }
            }

            fn capabilities(&self) -> BackendCapabilities {
                BackendCapabilities {
                    device: $device,
                    determinism: $determinism,
                    dtype: "f32",
                    max_batch: $batch,
                    memory_bytes: $mem,
                }
            }

            fn forward(&self, model: &Mlp, x: &[f32; 2]) -> Result<f32, BackendError> {
                self.check_available()?;
                CpuBackend.forward(model, x)
            }

            fn loss_and_grad(
                &self,
                model: &Mlp,
                samples: &[Sample],
            ) -> Result<(f32, Mlp), BackendError> {
                self.check_available()?;
                CpuBackend.loss_and_grad(model, samples)
            }

            fn sgd_step(&self, model: &Mlp, grad: &Mlp, lr: f32) -> Result<Mlp, BackendError> {
                self.check_available()?;
                CpuBackend.sgd_step(model, grad, lr)
            }
        }
    };
}

define_backend!(
    CudaBackend,
    "cuda",
    DeviceClass::Gpu,
    DeterminismClass::Reproducible,
    1_048_576,
    8 << 30
);
define_backend!(
    RocmBackend,
    "rocm",
    DeviceClass::Gpu,
    DeterminismClass::Reproducible,
    1_048_576,
    8 << 30
);
define_backend!(
    TpuBackend,
    "tpu",
    DeviceClass::Tpu,
    DeterminismClass::Reproducible,
    4_194_304,
    16 << 30
);
define_backend!(
    NpuBackend,
    "npu",
    DeviceClass::Npu,
    DeterminismClass::Reproducible,
    262_144,
    4 << 30
);
define_backend!(
    AppleSocBackend,
    "apple-soc",
    DeviceClass::AppleSoc,
    DeterminismClass::Reproducible,
    524_288,
    0
);
define_backend!(
    PhotonicBackend,
    "photonic",
    DeviceClass::Photonic,
    DeterminismClass::Statistical,
    65_536,
    0
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{check_backend, require_determinism};

    #[test]
    fn hardware_backends_declare_their_device_class() {
        assert_eq!(
            CudaBackend::hardware().capabilities().device,
            DeviceClass::Gpu
        );
        assert_eq!(
            RocmBackend::hardware().capabilities().device,
            DeviceClass::Gpu
        );
        assert_eq!(
            TpuBackend::hardware().capabilities().device,
            DeviceClass::Tpu
        );
        assert_eq!(
            NpuBackend::hardware().capabilities().device,
            DeviceClass::Npu
        );
        assert_eq!(
            AppleSocBackend::hardware().capabilities().device,
            DeviceClass::AppleSoc
        );
        assert_eq!(
            PhotonicBackend::hardware().capabilities().device,
            DeviceClass::Photonic
        );
        for caps in [
            CudaBackend::hardware().capabilities(),
            TpuBackend::hardware().capabilities(),
            NpuBackend::hardware().capabilities(),
            AppleSocBackend::hardware().capabilities(),
        ] {
            assert_eq!(caps.determinism, DeterminismClass::Reproducible);
            assert_eq!(caps.dtype, "f32");
        }
        assert_eq!(
            PhotonicBackend::hardware().capabilities().determinism,
            DeterminismClass::Statistical
        );
    }

    #[test]
    fn absent_hardware_fails_closed_never_panics() {
        assert!(!CudaBackend::hardware().is_available());
        let model = Mlp::new(7);
        assert!(matches!(
            CudaBackend::hardware().forward(&model, &[0.0, 0.0]),
            Err(BackendError::Unavailable(_))
        ));
        assert!(matches!(
            TpuBackend::hardware().loss_and_grad(&model, &[]),
            Err(BackendError::Unavailable(_))
        ));
        // Empty input is refused as malformed even in emulated mode.
        assert!(matches!(
            CudaBackend::emulated().loss_and_grad(&model, &[]),
            Err(BackendError::Malformed(_))
        ));
    }

    #[test]
    fn emulated_kernel_hashes_are_distinct_from_each_other() {
        use std::collections::BTreeSet;
        let hashes: BTreeSet<_> = [
            CudaBackend::emulated().kernel_hash(),
            RocmBackend::emulated().kernel_hash(),
            TpuBackend::emulated().kernel_hash(),
            NpuBackend::emulated().kernel_hash(),
            AppleSocBackend::emulated().kernel_hash(),
            PhotonicBackend::emulated().kernel_hash(),
            CpuBackend.kernel_hash(),
        ]
        .into_iter()
        .collect();
        assert_eq!(hashes.len(), 7);
    }

    #[test]
    fn no_hardware_backend_passes_the_consensus_gate() {
        for caps in [
            CudaBackend::hardware().capabilities(),
            RocmBackend::hardware().capabilities(),
            TpuBackend::hardware().capabilities(),
            NpuBackend::hardware().capabilities(),
            AppleSocBackend::hardware().capabilities(),
            PhotonicBackend::hardware().capabilities(),
        ] {
            assert!(require_determinism(&caps, DeterminismClass::BitExact).is_err());
        }
    }

    #[test]
    fn emulated_backends_pass_plumbing_conformance() {
        use crate::backend::TrainBackend;
        // CPU-cheap: fixed vectors only, no training loop.
        let backends: [&dyn TrainBackend; 5] = [
            &CudaBackend::emulated(),
            &RocmBackend::emulated(),
            &TpuBackend::emulated(),
            &NpuBackend::emulated(),
            &AppleSocBackend::emulated(),
        ];
        for backend in backends {
            let report = check_backend(backend).unwrap();
            assert_eq!(report.determinism, DeterminismClass::Reproducible);
        }
        let report = check_backend(&PhotonicBackend::emulated()).unwrap();
        assert_eq!(report.determinism, DeterminismClass::Statistical);
    }
}
