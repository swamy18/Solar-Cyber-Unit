//! Heterogeneous device descriptions and the backend plugin interface.
//!
//! A profile is what a provider claims about its hardware: an open backend
//! identifier (vendor/arch string) plus capabilities — memory, measured
//! throughput, bandwidth and determinism. Matching runs on those
//! capabilities, never on the class or the backend id, so a new hardware
//! family joins without any protocol change: unknown backends are accepted
//! as `"generic"` and matched purely on capabilities. Throughput and
//! bandwidth are self-declared (spot-checked by receipt `elapsed_ms` and
//! challenge re-execution, never attested here).
//!
//! Wire history: version 1 profiles have no throughput field (decode with 0);
//! version 2 appends throughput; version 3 appends the backend id. Versions
//! 1 and 2 still decode, with the backend defaulting to the legacy mapping
//! for their class. The old `DeviceClass` list is kept as a display label
//! only and is never consulted by matching.
//!
//! Backends plug executors in without protocol changes through the
//! [`ComputeBackend`] trait (Rust) and the `register_backend` hook in
//! `templates/srct_node.py` (Python). Shipped backends with working
//! execution code: [`CpuBackend`] (canonical subtask loop) and
//! [`LoopbackBackend`] (deterministic reference transform, labelled as
//! such). Anything else — mobile, Apple NPU, discrete GPUs and other
//! accelerators — is interface-only until a vendor ships a working
//! executor: the trait is the contract, there are no stub claims.

use std::collections::BTreeMap;

use srct_core::hash::{sha256_dom, Hash};
use srct_core::ser::{Reader, Writer};

use crate::ComputeError;

pub const PROFILE_VERSION: u8 = 3;
pub const MIN_RAM_MIB: u32 = 512;
pub const MAX_RAM_MIB: u32 = 1_048_576;
pub const MAX_CORES: u16 = 1_024;
pub const MAX_BANDWIDTH_KBPS: u32 = 100_000_000;
/// Largest claimable throughput in units per second. Bounds the field; the
/// claim itself is still self-reported and spot-checked, not trusted.
pub const MAX_UNITS_PER_SEC: u32 = 100_000_000;
/// Longest backend identifier, in bytes. Bounds the field; it is a label.
pub const MAX_BACKEND_ID_LEN: usize = 128;
/// Backend id used when none is named: matched purely on capabilities.
pub const GENERIC_BACKEND: &str = "generic";
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
    /// Open backend identifier (vendor/arch string, e.g. `"cpu/x86_64"`,
    /// `"apple/silicon"`, `"mobile/snapdragon-x"`). Unknown ids are accepted
    /// as [`GENERIC_BACKEND`] and matched purely on capabilities. Version 3
    /// carries it on the wire; versions 1 and 2 decode with the legacy
    /// mapping for their class (see [`legacy_backend`]).
    pub backend: String,
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
        let class_backend = legacy_backend(class).to_string();
        DeviceProfile {
            version: PROFILE_VERSION,
            class,
            backend: class_backend,
            determinism,
            ram_mib,
            cores,
            max_units_per_shard,
            bandwidth_kbps,
            claimed_units_per_sec,
            kernel,
        }
    }

    /// Name an explicit backend id (vendor/arch string). The id is a label:
    /// matching never consults it, but relays and dashboards display it.
    pub fn with_backend(mut self, backend: impl Into<String>) -> Self {
        self.backend = backend.into();
        self
    }

    /// The effective backend id: the stored id for version 3 profiles, the
    /// legacy class mapping for versions 1 and 2.
    pub fn backend_id_or_legacy(&self) -> &str {
        if self.version >= 3 && !self.backend.is_empty() {
            &self.backend
        } else {
            legacy_backend(self.class)
        }
    }

    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != 1 && self.version != 2 && self.version != PROFILE_VERSION {
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
        if self.version >= 2
            && (self.claimed_units_per_sec == 0 || self.claimed_units_per_sec > MAX_UNITS_PER_SEC)
        {
            return Err(ComputeError::Malformed(
                "device throughput out of range".into(),
            ));
        }
        if self.backend.len() > MAX_BACKEND_ID_LEN {
            return Err(ComputeError::Malformed("device backend id over cap".into()));
        }
        if !self.backend.is_empty()
            && !self
                .backend
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
        {
            return Err(ComputeError::Malformed(
                "device backend id has illegal characters".into(),
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
            w.u16le(self.backend.len() as u16)
                .raw(self.backend.as_bytes());
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
        if version != 1 && version != 2 && version != PROFILE_VERSION {
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
        // Version 2 appends throughput after bandwidth, version 3 appends the
        // backend id after throughput. Versions 1 and 2 decode with a zero
        // throughput (satisfies only jobs that require none) and the legacy
        // backend mapping for their class.
        let claimed_units_per_sec = if version >= 2 {
            r.u32le()
                .map_err(|e| ComputeError::Malformed(e.to_string()))?
        } else {
            0
        };
        let backend = if version >= PROFILE_VERSION {
            let len =
                r.u16le()
                    .map_err(|e| ComputeError::Malformed(e.to_string()))? as usize;
            if len > MAX_BACKEND_ID_LEN {
                return Err(ComputeError::Malformed("device backend id over cap".into()));
            }
            let raw = r
                .fixed_slice(len)
                .map_err(|e| ComputeError::Malformed(e.to_string()))?;
            String::from_utf8(raw.to_vec())
                .map_err(|_| ComputeError::Malformed("device backend id is not utf-8".into()))?
        } else {
            String::new()
        };
        let profile = DeviceProfile {
            version,
            class,
            backend,
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
    /// class mask and the backend id are deliberately not consulted — both
    /// are display labels, so an unknown backend matches exactly like a
    /// known one when its capabilities pass.
    pub fn meets(&self, requirement: &DeviceRequirement) -> bool {
        self.ram_mib >= requirement.min_ram_mib
            && self.claimed_units_per_sec >= requirement.min_units_per_sec
            && self.bandwidth_kbps >= requirement.min_bandwidth_kbps
            && self.determinism >= requirement.determinism
            && (requirement.kernel == [0u8; 32] || self.kernel == requirement.kernel)
    }
}

/// Legacy backend label for a [`DeviceClass`], used when a version 1 or 2
/// profile (which carries no backend id) is read. Display only.
pub fn legacy_backend(class: DeviceClass) -> &'static str {
    match class {
        DeviceClass::Cpu => "cpu/generic",
        DeviceClass::Gpu => "gpu/generic",
        DeviceClass::Tpu => "tpu/generic",
        DeviceClass::Npu => "npu/generic",
        DeviceClass::AppleSilicon => "apple/silicon",
        DeviceClass::Photonic => "photonic/generic",
    }
}

/// Capabilities one backend executor advertises. Mirrors the capability
/// floors of [`DeviceProfile`] so a registry entry and a profile compare
/// with the same rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub backend_id: String,
    pub ram_mib: u32,
    pub units_per_sec: u32,
    pub bandwidth_kbps: u32,
    pub determinism: Determinism,
}

impl BackendCapabilities {
    /// Whether these capabilities satisfy a job's hard requirement.
    /// Unknown backend ids are fine — matching is purely on capabilities.
    pub fn meets(&self, requirement: &DeviceRequirement) -> bool {
        self.ram_mib >= requirement.min_ram_mib
            && self.units_per_sec >= requirement.min_units_per_sec
            && self.bandwidth_kbps >= requirement.min_bandwidth_kbps
            && self.determinism >= requirement.determinism
    }
}

/// Executor plugin interface. A vendor (mobile, Apple NPU, discrete GPU,
/// other accelerators) plugs an executor in by implementing this trait —
/// no protocol change, no new wire version. This is an interface: shipping
/// an implementation with working execution code is what turns a label
/// like `"cuda/sm_90"` into a supported backend.
pub trait ComputeBackend {
    /// Open backend identifier (vendor/arch string, e.g. `"cpu/x86_64"`).
    fn backend_id(&self) -> &str;
    /// Capabilities this executor actually delivers.
    fn describe(&self) -> BackendCapabilities;
    /// Run `units` units of the canonical subtask over `input`, returning
    /// the packed result bytes. Deterministic: same input and units produce
    /// the same bytes on every machine running this backend.
    fn execute(&self, input: &[u8], units: u32) -> Result<Vec<u8>, ComputeError>;
}

/// Open registry of backend executors. Unknown ids are accepted as
/// [`GENERIC_BACKEND`] and matched purely on capabilities — registering is
/// how a box advertises, never how the network gates.
#[derive(Clone, Debug, Default)]
pub struct BackendRegistry {
    backends: BTreeMap<String, BackendCapabilities>,
}

impl BackendRegistry {
    /// A registry with the CPU reference backend already registered.
    pub fn new() -> Self {
        let mut registry = BackendRegistry {
            backends: BTreeMap::new(),
        };
        registry.register(CpuBackend::default().describe());
        registry
    }

    /// Advertise one backend's capabilities. Re-registering the same id
    /// replaces the previous entry.
    pub fn register(&mut self, caps: BackendCapabilities) {
        self.backends.insert(caps.backend_id.clone(), caps);
    }

    /// Look up a backend id. Returns `None` for ids nobody registered —
    /// callers treat that as [`GENERIC_BACKEND`], matched purely on the
    /// profile's capabilities.
    pub fn lookup(&self, backend_id: &str) -> Option<&BackendCapabilities> {
        self.backends.get(backend_id)
    }

    /// Whether this exact id was registered.
    pub fn is_known(&self, backend_id: &str) -> bool {
        self.backends.contains_key(backend_id)
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }
}

/// CPU reference backend with working execution code (`"cpu/generic"`).
///
/// Runs the canonical mixing loop: `units` rounds of a small deterministic
/// arithmetic kernel over the input, returning the digest. Same input and
/// units produce the same bytes on every machine — a challenger re-running
/// the same task gets the same result.
pub struct CpuBackend {
    pub units_per_sec: u32,
}

impl Default for CpuBackend {
    fn default() -> Self {
        CpuBackend {
            units_per_sec: 1_000_000,
        }
    }
}

impl ComputeBackend for CpuBackend {
    fn backend_id(&self) -> &str {
        "cpu/generic"
    }

    fn describe(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_id: self.backend_id().to_string(),
            ram_mib: 1_024,
            units_per_sec: self.units_per_sec,
            bandwidth_kbps: 50_000,
            determinism: Determinism::Reproducible,
        }
    }

    fn execute(&self, input: &[u8], units: u32) -> Result<Vec<u8>, ComputeError> {
        if units == 0 {
            return Err(ComputeError::Malformed("backend units must be > 0".into()));
        }
        let mut acc = sha256_dom(b"srct/backend/cpu/v1", &[input]);
        for _ in 0..units {
            let mut w = Vec::with_capacity(64);
            w.extend_from_slice(&acc);
            w.extend_from_slice(input);
            acc = sha256_dom(b"srct/backend/cpu/v1", &[&w]);
        }
        Ok(acc.to_vec())
    }
}

/// Loopback reference backend (`"ref/loopback"`). Working execution code,
/// labelled as a reference: a pure deterministic transform (hash chain)
/// with no hardware behind it, for tests and for vendors to copy the
/// trait shape from. Not a performance claim.
pub struct LoopbackBackend;

impl ComputeBackend for LoopbackBackend {
    fn backend_id(&self) -> &str {
        "ref/loopback"
    }

    fn describe(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_id: self.backend_id().to_string(),
            ram_mib: 512,
            units_per_sec: 100_000,
            bandwidth_kbps: 10_000,
            determinism: Determinism::BitExact,
        }
    }

    fn execute(&self, input: &[u8], units: u32) -> Result<Vec<u8>, ComputeError> {
        if units == 0 {
            return Err(ComputeError::Malformed("backend units must be > 0".into()));
        }
        let mut acc = sha256_dom(b"srct/backend/loopback/v1", &[input]);
        for i in 0..units {
            let mut w = Vec::with_capacity(40);
            w.extend_from_slice(&acc);
            w.extend_from_slice(&i.to_le_bytes());
            acc = sha256_dom(b"srct/backend/loopback/v1", &[&w]);
        }
        Ok(acc.to_vec())
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
        // No backend id on the wire: the legacy mapping applies.
        assert_eq!(decoded.backend_id_or_legacy(), "cpu/generic");
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
    fn version_3_backend_roundtrips_and_old_encodings_stay_decodable() {
        let mut p = profile(DeviceClass::AppleSilicon, 16_384, 10, [0u8; 32]);
        p = p.with_backend("apple/silicon");
        assert_eq!(p.version, PROFILE_VERSION);
        let decoded = DeviceProfile::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.backend_id_or_legacy(), "apple/silicon");
        assert_eq!(decoded.hash(), p.hash());

        // Unknown backend ids are accepted as generic: matching is purely
        // on capabilities, so a mobile part joins with no protocol change.
        let mut unknown = profile(DeviceClass::Cpu, 2_048, 8, [0u8; 32]);
        unknown = unknown.with_backend("mobile/snapdragon-x");
        let decoded_unknown = DeviceProfile::decode(&unknown.encode()).unwrap();
        assert_eq!(
            decoded_unknown.backend_id_or_legacy(),
            "mobile/snapdragon-x"
        );
        assert!(decoded_unknown.meets(&req()));
        assert!(!decoded_unknown.meets(&DeviceRequirement {
            min_ram_mib: 4_096,
            ..req()
        }));

        // A hand-built version 2 encoding still decodes, with the legacy
        // backend mapping for its class.
        let mut v2 = vec![2u8, DeviceClass::Gpu.as_u8(), 1u8];
        v2.extend_from_slice(&65_536u32.to_le_bytes());
        v2.extend_from_slice(&25u16.to_le_bytes());
        v2.extend_from_slice(&20u32.to_le_bytes());
        v2.extend_from_slice(&50_000u32.to_le_bytes());
        v2.extend_from_slice(&5_000u32.to_le_bytes());
        v2.extend_from_slice(&[7u8; 32]);
        let decoded_v2 = DeviceProfile::decode(&v2).unwrap();
        assert_eq!(decoded_v2.version, 2);
        assert_eq!(decoded_v2.claimed_units_per_sec, 5_000);
        assert_eq!(decoded_v2.backend_id_or_legacy(), "gpu/generic");

        // Backend id bounds: over-long or non-identifier bytes refuse.
        let mut bad_len = profile(DeviceClass::Cpu, 2_048, 8, [0u8; 32]);
        bad_len = bad_len.with_backend("x".repeat(MAX_BACKEND_ID_LEN + 1));
        assert!(bad_len.validate().is_err());
        let bad_chars =
            profile(DeviceClass::Cpu, 2_048, 8, [0u8; 32]).with_backend("cpu; rm -rf /");
        assert!(bad_chars.validate().is_err());
        let mut bad_utf8 = profile(DeviceClass::Cpu, 2_048, 8, [0u8; 32]);
        bad_utf8.version = PROFILE_VERSION;
        let mut bytes = bad_utf8.encode();
        // Corrupt the backend length prefix to exceed the cap.
        let backend_len_pos = bytes.len() - 32 - 2;
        bytes[backend_len_pos] = 0xFF;
        bytes[backend_len_pos + 1] = 0xFF;
        assert!(DeviceProfile::decode(&bytes).is_err());
    }

    #[test]
    fn backend_registry_accepts_unknown_as_generic() {
        let mut registry = BackendRegistry::new();
        // CPU reference backend is pre-registered.
        assert!(registry.is_known("cpu/generic"));
        assert_eq!(registry.len(), 1);
        // Registering a vendor backend advertises it; unknown ids stay
        // unknown and are matched purely on capabilities.
        registry.register(BackendCapabilities {
            backend_id: "mobile/snapdragon-x".into(),
            ram_mib: 2_048,
            units_per_sec: 1_000,
            bandwidth_kbps: 50_000,
            determinism: Determinism::Reproducible,
        });
        assert!(registry.is_known("mobile/snapdragon-x"));
        assert!(!registry.is_known("npu/unreleased-9"));
        assert_eq!(registry.lookup("npu/unreleased-9"), None);
        // Capability gating is backend-blind.
        let caps = registry.lookup("mobile/snapdragon-x").unwrap();
        assert!(caps.meets(&req()));
        assert!(!caps.meets(&DeviceRequirement {
            min_ram_mib: 4_096,
            ..req()
        }));
    }

    #[test]
    fn shipped_backends_execute_deterministically() {
        let cpu = CpuBackend::default();
        assert_eq!(cpu.backend_id(), "cpu/generic");
        let a = cpu.execute(b"task-bytes", 10).unwrap();
        let b = cpu.execute(b"task-bytes", 10).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // Different units or input change the output.
        assert_ne!(a, cpu.execute(b"task-bytes", 11).unwrap());
        assert_ne!(a, cpu.execute(b"other-bytes", 10).unwrap());
        assert!(cpu.execute(b"task-bytes", 0).is_err());
        // describe() is consistent with execution being offered.
        assert_eq!(cpu.describe().backend_id, "cpu/generic");

        // Loopback reference backend: working code, labelled reference.
        let loopback = LoopbackBackend;
        assert_eq!(loopback.backend_id(), "ref/loopback");
        let x = loopback.execute(b"task-bytes", 10).unwrap();
        let y = loopback.execute(b"task-bytes", 10).unwrap();
        assert_eq!(x, y);
        assert_eq!(x.len(), 32);
        assert_ne!(x, a, "backends must not alias each other's outputs");
        assert!(loopback.execute(b"task-bytes", 0).is_err());
        // GPU/NPU support is NOT claimed: no backend named cuda/*, metal/*,
        // rocm/* or npu/* ships. The trait is the interface; these labels
        // would only appear once a vendor ships a working executor.
        let registry = BackendRegistry::new();
        for id in ["cuda/sm_90", "metal/m4", "rocm/mi300", "npu/unreleased-9"] {
            assert!(!registry.is_known(id), "{id} must not be claimed");
        }
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
