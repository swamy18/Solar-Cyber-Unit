//! Attestation-gated key release.
//!
//! The single invariant of the confidential tier: **a data key is sealed
//! to an enclave key if and only if full vendor attestation verifies.**
//! [`release_data_key`] loads the key only after checking expiry and
//! revocation, verifies the attestation, binds the presented ephemeral
//! key, and only then performs the HPKE seal. Every failure path returns
//! before any sealed bytes exist.

use srct_compute::tee::{AttestationRoots, SignedTeeQuote, TeeSla, TeeVerifier};
use srct_compute::vendor::{expected_report_binding, VendorEvidence, VendorInputs};

use crate::keywrap::{self, SealedKey, HPKE_INFO};
use crate::{ConfidError, KmsAdapter};

/// Which key is being released: separate keys for data, results and
/// checkpoints, each bound to its own info string so a sealed data key
/// can never be mistaken for a sealed result key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPurpose {
    Data,
    Result,
    Checkpoint,
}

impl KeyPurpose {
    fn label(&self) -> &'static str {
        match self {
            KeyPurpose::Data => "data",
            KeyPurpose::Result => "result",
            KeyPurpose::Checkpoint => "checkpoint",
        }
    }
}

/// Info string binding a release: domain, purpose, workload, session nonce.
/// The enclave checks nothing here — the binding protects the *consumer*
/// from misdelivered keys (a sealed blob for job A will not open in the
/// session for job B because the info differs and the AEAD fails).
pub fn release_info(purpose: KeyPurpose, workload: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(HPKE_INFO.len() + 32 + 32 + 8);
    info.extend_from_slice(HPKE_INFO);
    info.extend_from_slice(b":");
    info.extend_from_slice(purpose.label().as_bytes());
    info.extend_from_slice(b":");
    info.extend_from_slice(workload);
    info.extend_from_slice(b":");
    info.extend_from_slice(&nonce.to_le_bytes());
    info
}

/// Everything the gate needs, borrowed. All of it is public except the
/// keys themselves; the only secret is looked up from the KMS by id.
pub struct ReleasePolicy<'a> {
    /// Requested SLA: measurement, minimum TCB, network, workload binding.
    pub sla: &'a TeeSla,
    /// The worker's signed quote (v2 with vendor evidence).
    pub quote: &'a SignedTeeQuote,
    /// Trusted attester roots (pinned by the consumer, out of band).
    pub roots: &'a AttestationRoots,
    /// Vendor verification inputs: roots, CRLs, TCB minimums, times.
    pub vendor: &'a VendorInputs,
    /// Enclave ephemeral public key as presented over the attested channel.
    pub presented_pubkey: &'a [u8],
    /// Chain height the quote is verified against.
    pub current_height: u64,
}

/// A released key, ready to hand to the enclave channel. Contains only
/// ciphertext: the encapsulation and the sealed key bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRelease {
    pub sealed: SealedKey,
    /// The info string the seal is bound to (for the consumer's records).
    pub info: Vec<u8>,
}

/// Verify attestation, then seal the named data key to the enclave key.
///
/// Order matters and is load-bearing:
/// 1. the key loads (unknown / expired / revoked keys fail here, before
///    any crypto touches the network-facing side);
/// 2. the presented ephemeral key must equal the release target — a
///    mismatch means the channel and the request disagree, fail closed;
/// 3. full attestation verification (`verify_v2`); **any failure returns
///    here and no sealed bytes are ever constructed**;
/// 4. only then, HPKE-seal the key with the release binding as info.
///
/// The `aad` binds the release envelope (ticket id, height range); it is
/// authenticated alongside the key.
#[allow(clippy::too_many_arguments)]
pub fn release_data_key<K: KmsAdapter>(
    kms: &K,
    key_id: &str,
    enclave_pubkey: &[u8; 32],
    purpose: KeyPurpose,
    aad: &[u8],
    now_unix: u64,
    policy: &ReleasePolicy<'_>,
) -> Result<SealedRelease, ConfidError> {
    // 1. The key must exist, be unexpired and unrevoked.
    let key = kms.load(key_id, now_unix)?;
    // 2. The channel-presented key and the release target must agree.
    if policy.presented_pubkey != enclave_pubkey {
        return Err(ConfidError::AttestationFailed(
            "presented key does not match the release target".into(),
        ));
    }
    // 3. Full attestation verification. Nothing leaves on failure.
    let mut verifier = TeeVerifier::default();
    verifier
        .verify_v2(
            policy.sla,
            policy.quote,
            policy.roots,
            policy.vendor,
            policy.presented_pubkey,
            policy.current_height,
        )
        .map_err(ConfidError::from)?;
    // 4. Seal. The binding covers purpose + workload + session nonce.
    let info = release_info(purpose, &policy.sla.workload, policy.quote.quote.nonce);
    let sealed = keywrap::seal_to_enclave(enclave_pubkey, &key, &info, aad)?;
    Ok(SealedRelease { sealed, info })
}

/// Expected `report_data[..32]`, for callers that build evidence or
/// verify bindings without a full [`VendorInputs`].
pub fn expected_binding(ephem_pubkey: &[u8], nonce: u64) -> [u8; 32] {
    expected_report_binding(ephem_pubkey, nonce)
}

/// Measurement id of a vendor evidence value, for SLA construction.
pub fn measurement_id(evidence: &VendorEvidence) -> [u8; 32] {
    evidence.measurement_id()
}

/// Zero a stack or heap key buffer explicitly at the end of a scope.
/// (`Zeroizing` handles the common case on drop; this is for plain arrays
/// that briefly held derived bytes.)
pub fn zeroize_key(key: &mut [u8; 32]) {
    use zeroize::Zeroize as _;
    key.zeroize();
}
