//! Heterogeneous device descriptions.
//!
//! A profile is what a provider claims about its hardware. It is deliberately
//! small and fixed-size: adding a new device class (photonic, or whatever comes
//! next) adds an encoding value here and nothing else in the protocol changes.
//! A future format uses a new version rather than reinterpreting old bytes.

use srct_core::hash::{sha256_dom, Hash};
use srct_core::ser::{Reader, Writer};

use crate::ComputeError;

pub const PROFILE_VERSION: u8 = 1;
pub const MIN_RAM_MIB: u32 = 512;
pub const MAX_RAM_MIB: u32 = 1_048_576;
pub const MAX_CORES: u16 = 1_024;
pub const MAX_BANDWIDTH_KBPS: u32 = 100_000_000;
const DOM_PROFILE: &[u8] = b"srct/compute/device-profile/v1";

/// The broad hardware family a device belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceClass {
    Cpu = 0,
    Gpu = 1,
    Tpu = 2,
    Npu = 3,
    AppleSilicon = 4,
    Photonic = 5,
}

impl DeviceClass {
    /// Every class this version understands.
    pub const ALL_MASK: u8 = 0b0011_1111;

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Total conversion. An unknown byte is refused rather than coerced, so a
    /// future class cannot silently be read as today's fallback.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DeviceClass::Cpu),
            1 => Some(DeviceClass::Gpu),
            2 => Some(DeviceClass::Tpu),
            3 => Some(DeviceClass::Npu),
            4 => Some(DeviceClass::AppleSilicon),
            5 => Some(DeviceClass::Photonic),
            _ => None,
        }
    }

    pub fn mask(self) -> u8 {
        1u8 << self.as_u8()
    }
}

/// How reproducible this device's kernels are.
///
/// Ordered from least to most strict: `Statistical < Reproducible < BitExact`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Determinism {
    /// Floating-point or scheduling differences change the low bits.
    Statistical = 0,
    /// Same kernel and inputs reproduce the same result on the same class.
    Reproducible = 1,
    /// Exact integer/fixed-point kernel; the only class consensus could use.
    BitExact = 2,
}

impl Determinism {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Determinism::Statistical),
            1 => Some(Determinism::Reproducible),
            2 => Some(Determinism::BitExact),
            _ => None,
        }
    }
}

/// What a device can run and how much of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceProfile {
    pub version: u8,
    pub class: DeviceClass,
    pub determinism: Determinism,
    /// Usable memory in MiB; bounds what a shard may ask for.
    pub ram_mib: u32,
    pub cores: u16,
    /// Largest shard this device accepts, independent of the offer's per-job cap.
    pub max_units_per_shard: u32,
    /// Rough egress/ingress in kbit/s, used only for ranking tie-breaks.
    pub bandwidth_kbps: u32,
    /// Hash of the exact kernel set the provider will run. Zero means "any
    /// kernel this provider has", which a job binds explicitly when it needs
    /// reproducibility.
    pub kernel: Hash,
}

/// What a job requires from a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRequirement {
    pub class_mask: u8,
    pub min_ram_mib: u32,
    pub determinism: Determinism,
    /// Required kernel hash, or zero for any.
    pub kernel: Hash,
}

impl DeviceProfile {
    pub fn new(
        class: DeviceClass,
        determinism: Determinism,
        ram_mib: u32,
        cores: u16,
        max_units_per_shard: u32,
        bandwidth_kbps: u32,
        kernel: Hash,
    ) -> Self {
        DeviceProfile {
            version: PROFILE_VERSION,
            class,
            determinism,
            ram_mib,
            cores,
            max_units_per_shard,
            bandwidth_kbps,
            kernel,
        }
    }

    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != PROFILE_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported device profile version {}",
                self.version
            )));
        }
        if !(MIN_RAM_MIB..=MAX_RAM_MIB).contains(&self.ram_mib) {
            return Err(ComputeError::Malformed("device ram out of range".into()));
        }
        if self.cores == 0 || self.cores > MAX_CORES {
            return Err(ComputeError::Malformed("device cores out of range".into()));
        }
        if self.max_units_per_shard == 0 {
            return Err(ComputeError::Malformed(
                "device must accept at least one unit per shard".into(),
            ));
        }
        if self.bandwidth_kbps == 0 || self.bandwidth_kbps > MAX_BANDWIDTH_KBPS {
            return Err(ComputeError::Malformed(
                "device bandwidth out of range".into(),
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.u8(self.version)
            .u8(self.class.as_u8())
            .u8(self.determinism.as_u8())
            .u32le(self.ram_mib)
            .u16le(self.cores)
            .u32le(self.max_units_per_shard)
            .u32le(self.bandwidth_kbps)
            .fixed(&self.kernel);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_PROFILE, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| ComputeError::Malformed(e.to_string()))?;
        let class =
            DeviceClass::from_u8(r.u8().map_err(|e| ComputeError::Malformed(e.to_string()))?)
                .ok_or_else(|| ComputeError::Malformed("unknown device class".into()))?;
        let determinism =
            Determinism::from_u8(r.u8().map_err(|e| ComputeError::Malformed(e.to_string()))?)
                .ok_or_else(|| ComputeError::Malformed("unknown determinism class".into()))?;
        let profile = DeviceProfile {
            version,
            class,
            determinism,
            ram_mib: r
                .u32le()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?,
            cores: r
                .u16le()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?,
            max_units_per_shard: r
                .u32le()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?,
            bandwidth_kbps: r
                .u32le()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?,
            kernel: r
                .fixed()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?,
        };
        r.expect_end()
            .map_err(|e| ComputeError::Malformed(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Whether this device satisfies every hard requirement.
    pub fn meets(&self, requirement: &DeviceRequirement) -> bool {
        requirement.class_mask != 0
            && requirement.class_mask & self.class.mask() != 0
            && self.ram_mib >= requirement.min_ram_mib
            && self.determinism >= requirement.determinism
            && (requirement.kernel == [0u8; 32] || self.kernel == requirement.kernel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(class: DeviceClass, ram: u32, shard: u32, kernel: Hash) -> DeviceProfile {
        DeviceProfile::new(
            class,
            Determinism::Reproducible,
            ram,
            8,
            shard,
            50_000,
            kernel,
        )
    }

    #[test]
    fn profile_hash_binds_every_capability_field() {
        let base = profile(DeviceClass::Cpu, 2_048, 8, [1u8; 32]);
        let other = profile(DeviceClass::Gpu, 2_048, 8, [1u8; 32]);
        assert_ne!(base.hash(), other.hash());
        assert_eq!(
            base.hash(),
            profile(DeviceClass::Cpu, 2_048, 8, [1u8; 32]).hash()
        );
        let decoded = DeviceProfile::decode(&base.encode()).unwrap();
        assert_eq!(decoded, base);
    }

    #[test]
    fn requirement_matching_is_fail_closed() {
        let cpu = profile(DeviceClass::Cpu, 1_024, 4, [7u8; 32]);
        let req = DeviceRequirement {
            class_mask: DeviceClass::Cpu.mask(),
            min_ram_mib: 2_048,
            determinism: Determinism::Reproducible,
            kernel: [0u8; 32],
        };
        assert!(!cpu.meets(&req), "too little ram");
        assert!(!cpu.meets(&DeviceRequirement {
            class_mask: 0,
            ..req.clone()
        }));
        assert!(!cpu.meets(&DeviceRequirement {
            class_mask: DeviceClass::Gpu.mask(),
            min_ram_mib: 512,
            ..req.clone()
        }));
        assert!(!cpu.meets(&DeviceRequirement {
            class_mask: DeviceClass::Cpu.mask(),
            min_ram_mib: 512,
            determinism: Determinism::BitExact,
            kernel: [0u8; 32],
        }));
        assert!(!cpu.meets(&DeviceRequirement {
            class_mask: DeviceClass::Cpu.mask(),
            min_ram_mib: 512,
            determinism: Determinism::Reproducible,
            kernel: [9u8; 32],
        }));
        assert!(cpu.meets(&DeviceRequirement {
            class_mask: DeviceClass::Cpu.mask() | DeviceClass::Gpu.mask(),
            min_ram_mib: 1_024,
            determinism: Determinism::Statistical,
            kernel: [7u8; 32],
        }));
    }

    #[test]
    fn invalid_profiles_are_refused() {
        let mut p = profile(DeviceClass::Cpu, 2_048, 8, [0u8; 32]);
        p.max_units_per_shard = 0;
        assert!(p.validate().is_err());
        p.max_units_per_shard = 8;
        p.ram_mib = MIN_RAM_MIB - 1;
        assert!(p.validate().is_err());
        assert!(DeviceClass::from_u8(200).is_none());
        assert!(Determinism::from_u8(9).is_none());
    }
}
