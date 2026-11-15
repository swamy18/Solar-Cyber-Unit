//! Heterogeneous device descriptions.
//!
//! A profile is what a provider claims about its hardware: memory, measured
//! throughput, bandwidth and determinism. Matching runs on those capabilities,
//! never on the device class — `class` is a display label only, so a new
//! hardware family joins without any protocol change. Throughput and
//! bandwidth are self-declared (spot-checked by receipt `elapsed_ms` and
//! challenge re-execution, never attested here). Version 2 adds the
//! throughput field; version 1 profiles still decode, with throughput 0.

use srct_core::hash::{sha256_dom, Hash};
use srct_core::ser::{Reader, Writer};

use crate::ComputeError;

pub const PROFILE_VERSION: u8 = 2;
pub const MIN_RAM_MIB: u32 = 512;
pub const MAX_RAM_MIB: u32 = 1_048_576;
pub const MAX_CORES: u16 = 1_024;
pub const MAX_BANDWIDTH_KBPS: u32 = 100_000_000;
/// Largest claimable throughput in units per second. Bounds the field; the
/// claim itself is still self-reported and spot-checked, not trusted.
pub const MAX_UNITS_PER_SEC: u32 = 100_000_000;
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
    /// Display label only. Matching never consults it: a job that needs a
    /// fast CPU and a job that needs a GPU express that as throughput, RAM,
    /// bandwidth and determinism floors, not as a class gate.
    pub class: DeviceClass,
    pub determinism: Determinism,
    /// Usable memory in MiB; bounds what a shard may ask for.
    pub ram_mib: u32,
    pub cores: u16,
    /// Largest shard this device accepts, independent of the offer's per-job cap.
    pub max_units_per_shard: u32,
    /// Rough egress/ingress in kbit/s; a hard floor for matching, and a
    /// ranking tie-break in planning.
    pub bandwidth_kbps: u32,
    /// Self-declared sustained throughput in units per second, measured with
    /// the canonical benchmark kernel. Spot-checked by receipt `elapsed_ms`
    /// and challenge re-execution, never trusted outright. Version 1
    /// profiles decode with 0, which satisfies only jobs that require none.
    pub claimed_units_per_sec: u32,
    /// Hash of the exact kernel set the provider will run. Zero means "any
    /// kernel this provider has", which a job binds explicitly when it needs
    /// reproducibility.
    pub kernel: Hash,
}

/// What a job requires from a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRequirement {
    /// Kept on the wire for compatibility; ignored by matching.
    pub class_mask: u8,
    pub min_ram_mib: u32,
    /// Minimum sustained throughput in units per second.
    pub min_units_per_sec: u32,
    /// Minimum bandwidth in kbit/s.
    pub min_bandwidth_kbps: u32,
    pub determinism: Determinism,
    /// Required kernel hash, or zero for any.
    pub kernel: Hash,
}

impl DeviceProfile {
    /// Eight capability fields; the constructor takes them all rather than
    /// a builder because a profile with a missing floor is a malformed
    /// profile, and the type system should say so at the call site.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: DeviceClass,
        determinism: Determinism,
        ram_mib: u32,
        cores: u16,
        max_units_per_shard: u32,
        bandwidth_kbps: u32,
        claimed_units_per_sec: u32,
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
            claimed_units_per_sec,
            kernel,
        }
    }

    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != 1 && self.version != PROFILE_VERSION {
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
        if self.version == PROFILE_VERSION
            && (self.claimed_units_per_sec == 0 || self.claimed_units_per_sec > MAX_UNITS_PER_SEC)
        {
            return Err(ComputeError::Malformed(
                "device throughput out of range".into(),
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(68);
        w.u8(self.version)
            .u8(self.class.as_u8())
            .u8(self.determinism.as_u8())
            .u32le(self.ram_mib)
            .u16le(self.cores)
            .u32le(self.max_units_per_shard)
            .u32le(self.bandwidth_kbps);
        if self.version == PROFILE_VERSION {
            w.u32le(self.claimed_units_per_sec);
        }
        w.fixed(&self.kernel);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_PROFILE, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| ComputeError::Malformed(e.to_string()))?;
        if version != 1 && version != PROFILE_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported device profile version {version}"
            )));
        }
        let class =
            DeviceClass::from_u8(r.u8().map_err(|e| ComputeError::Malformed(e.to_string()))?)
                .ok_or_else(|| ComputeError::Malformed("unknown device class".into()))?;
        let determinism =
            Determinism::from_u8(r.u8().map_err(|e| ComputeError::Malformed(e.to_string()))?)
                .ok_or_else(|| ComputeError::Malformed("unknown determinism class".into()))?;
        let ram_mib = r
            .u32le()
            .map_err(|e| ComputeError::Malformed(e.to_string()))?;
        let cores = r
            .u16le()
            .map_err(|e| ComputeError::Malformed(e.to_string()))?;
        let max_units_per_shard = r
            .u32le()
            .map_err(|e| ComputeError::Malformed(e.to_string()))?;
        let bandwidth_kbps = r
            .u32le()
            .map_err(|e| ComputeError::Malformed(e.to_string()))?;
        // Version 2 appends throughput after bandwidth. Version 1 profiles
        // decode with 0, which only satisfies jobs that require none.
        let claimed_units_per_sec = if version == PROFILE_VERSION {
            r.u32le()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?
        } else {
            0
        };
        let profile = DeviceProfile {
            version,
            class,
            determinism,
            ram_mib,
            cores,
            max_units_per_shard,
            bandwidth_kbps,
            claimed_units_per_sec,
            kernel: r
                .fixed()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?,
        };
        r.expect_end()
            .map_err(|e| ComputeError::Malformed(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Whether this device satisfies every hard requirement. Capability
    /// floors only: RAM, throughput, bandwidth, determinism, kernel. The
    /// class mask is deliberately not consulted — it is a display label.
    pub fn meets(&self, requirement: &DeviceRequirement) -> bool {
        self.ram_mib >= requirement.min_ram_mib
            && self.claimed_units_per_sec >= requirement.min_units_per_sec
            && self.bandwidth_kbps >= requirement.min_bandwidth_kbps
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
            1_000,
            kernel,
        )
    }

    fn req() -> DeviceRequirement {
        DeviceRequirement {
            class_mask: DeviceClass::Cpu.mask(),
            min_ram_mib: 1_024,
            min_units_per_sec: 500,
            min_bandwidth_kbps: 10_000,
            determinism: Determinism::Statistical,
            kernel: [0u8; 32],
        }
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
    fn requirement_matching_is_capability_based_and_fail_closed() {
        let cpu = profile(DeviceClass::Cpu, 1_024, 4, [7u8; 32]);
        // Too little RAM fails even when every other floor passes.
        assert!(!cpu.meets(&DeviceRequirement {
            min_ram_mib: 2_048,
            ..req()
        }));
        // Class mismatch is ignored: a GPU-only mask still matches a CPU
        // device when the capability floors pass. Class is a display label.
        assert!(cpu.meets(&DeviceRequirement {
            class_mask: DeviceClass::Gpu.mask(),
            ..req()
        }));
        // An empty mask (previously malformed-as-never-match) also matches
        // when capabilities pass: the mask is not consulted at all.
        assert!(cpu.meets(&DeviceRequirement {
            class_mask: 0,
            ..req()
        }));
        // Throughput floor: 1,000 claimed < 2,000 required.
        assert!(!cpu.meets(&DeviceRequirement {
            min_units_per_sec: 2_000,
            ..req()
        }));
        // Bandwidth floor: 50,000 claimed < 60,000 required.
        assert!(!cpu.meets(&DeviceRequirement {
            min_bandwidth_kbps: 60_000,
            ..req()
        }));
        // Determinism still binds: BitExact required, Reproducible offered.
        assert!(!cpu.meets(&DeviceRequirement {
            determinism: Determinism::BitExact,
            ..req()
        }));
        // Kernel binds when the job names one.
        assert!(!cpu.meets(&DeviceRequirement {
            kernel: [9u8; 32],
            ..req()
        }));
        // Everything passing matches, including an explicit kernel pin.
        assert!(cpu.meets(&DeviceRequirement {
            kernel: [7u8; 32],
            ..req()
        }));
        assert!(cpu.meets(&req()));
    }

    #[test]
    fn version_1_profiles_decode_with_zero_throughput() {
        // Legacy bytes: version 1 layout has no throughput field.
        let mut legacy = vec![1u8, DeviceClass::Cpu.as_u8(), 1u8];
        legacy.extend_from_slice(&2_048u32.to_le_bytes());
        legacy.extend_from_slice(&8u16.to_le_bytes());
        legacy.extend_from_slice(&4u32.to_le_bytes());
        legacy.extend_from_slice(&50_000u32.to_le_bytes());
        legacy.extend_from_slice(&[7u8; 32]);
        let decoded = DeviceProfile::decode(&legacy).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.claimed_units_per_sec, 0);
        // Zero throughput satisfies only jobs that require none.
        assert!(decoded.meets(&DeviceRequirement {
            min_units_per_sec: 0,
            ..req()
        }));
        assert!(!decoded.meets(&req()));
        // Unknown versions still refuse.
        let mut bad = legacy.clone();
        bad[0] = 9;
        assert!(DeviceProfile::decode(&bad).is_err());
    }

    #[test]
    fn version_2_throughput_is_validated() {
        let mut p = profile(DeviceClass::Cpu, 2_048, 8, [0u8; 32]);
        p.claimed_units_per_sec = 0;
        assert!(p.validate().is_err(), "v2 must claim positive throughput");
        p.claimed_units_per_sec = MAX_UNITS_PER_SEC + 1;
        assert!(p.validate().is_err(), "throughput over cap");
        p.claimed_units_per_sec = 1_000;
        assert!(p.validate().is_ok());
        // v2 round-trips through its own encoding.
        let decoded = DeviceProfile::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
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
