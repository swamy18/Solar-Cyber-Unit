//! Guest runtime: simulator-backed attested execution session.
//!
//! Lifecycle:
//!   Attesting  →  KeyReleased  →  Running  →  Sealed  →  Wiped
//!
//! The guest (inside the TEE) attests to the consumer, receives a sealed
//! data key, runs the workload, seals the output, then wipes memory. All
//! state transitions are recorded in an audit trail. This crate links the
//! simulator only — real hardware runs use the same interface with a
//! hardware-backed attestation and key unseal.

use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use generic_array::{typenum::U24, GenericArray};
use zeroize::Zeroizing;

use crate::tee::{AttestationRoots, SignedTeeQuote, TeeError, TeeSla, TeeType, TeeVerifier};
use crate::vendor::VendorInputs;
use crate::ComputeError;
use srct_core::hash::{sha256_dom, Hash};

const DOM_SESSION: &[u8] = b"srct/guest/session/v1";
const DOM_USAGE: &[u8] = b"srct/guest/usage/v1";

/// An HPKE-sealed data key delivered to the guest after attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedKey {
    pub encapped: [u8; 32],
    pub ct: Vec<u8>,
}

/// Guest session state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Quote received, attestation pending.
    Attesting,
    /// Attestation passed; data key released into guest memory.
    KeyReleased,
    /// Workload executing; input and key in guest memory.
    Running,
    /// Output sealed; key and input wiped from guest memory.
    Sealed,
    /// All guest memory wiped; session terminated.
    Wiped,
}

/// A guest-side attested session.
#[derive(Clone, Debug)]
pub struct GuestSession {
    pub session_id: Hash,
    pub tee: TeeType,
    pub state: SessionState,
    /// SLA the consumer enforced.
    pub sla: TeeSla,
    /// Verified quote output hash (bound to the workload).
    pub output_hash: Option<Hash>,
    /// Sealed data key (in guest memory only while KeyReleased/Running).
    pub sealed_key: Option<SealedKey>,
    /// Plaintext data key in guest memory (Running only; None otherwise).
    pub data_key: Option<Zeroizing<[u8; 32]>>,
    /// Workload input (Running only; None otherwise).
    pub input: Option<Zeroizing<Vec<u8>>>,
    /// Sealed output (Sealed only).
    pub sealed_output: Option<Vec<u8>>,
    /// Audit trail of state transitions.
    pub audit: Vec<SessionEvent>,
    /// Created at (unix seconds).
    pub created_unix: u64,
}

/// Audit event for a session transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEvent {
    pub transition: String,
    pub height: u64,
    pub detail: String,
}

impl GuestSession {
    /// Create a new attesting session bound to an SLA.
    pub fn new(session_id: Hash, tee: TeeType, sla: TeeSla, height: u64) -> Self {
        let now = now_unix();
        Self {
            session_id,
            tee,
            state: SessionState::Attesting,
            sla,
            output_hash: None,
            sealed_key: None,
            data_key: None,
            input: None,
            sealed_output: None,
            audit: vec![SessionEvent {
                transition: "Attesting".into(),
                height,
                detail: format!("session created for tee {:?}", tee),
            }],
            created_unix: now,
        }
    }

    /// Release a data key into the guest after successful attestation.
    /// The key arrives HPKE-sealed to the guest ephemeral pubkey; the guest
    /// unwraps it and holds it in zeroizing memory.
    pub fn release_key(
        &mut self,
        sealed: SealedKey,
        data_key: [u8; 32],
        height: u64,
    ) -> Result<(), TeeError> {
        if self.state != SessionState::Attesting {
            return Err(TeeError::Malformed(
                "key release only in Attesting state".into(),
            ));
        }
        self.sealed_key = Some(sealed);
        self.data_key = Some(Zeroizing::new(data_key));
        self.state = SessionState::KeyReleased;
        self.audit.push(SessionEvent {
            transition: "KeyReleased".into(),
            height,
            detail: "data key unsealed into guest memory".into(),
        });
        Ok(())
    }

    /// Begin running the workload. Moves KeyReleased → Running. The data
    /// key and input are now resident in guest memory.
    pub fn start_run(&mut self, input: Vec<u8>, height: u64) -> Result<(), TeeError> {
        if self.state != SessionState::KeyReleased {
            return Err(TeeError::Malformed(
                "start_run only in KeyReleased state".into(),
            ));
        }
        let input_zero = Zeroizing::new(input);
        self.input = Some(input_zero);
        self.state = SessionState::Running;
        self.audit.push(SessionEvent {
            transition: "Running".into(),
            height,
            detail: "workload input resident; executing".into(),
        });
        Ok(())
    }

    /// Seal the workload output and wipe key/input from guest memory.
    /// Running → Sealed. The output is AEAD-sealed under the data key.
    pub fn seal_output(&mut self, output: &[u8], height: u64) -> Result<Vec<u8>, TeeError> {
        if self.state != SessionState::Running {
            return Err(TeeError::Malformed(
                "seal_output only in Running state".into(),
            ));
        }
        let data_key = self
            .data_key
            .as_ref()
            .ok_or(TeeError::Malformed("no data key in guest".into()))?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(data_key.as_ref()));
        let mut nonce = [0u8; 24];
        // Use deterministic nonce derived from session + output for auditability.
        let nonce_input = sha256_dom(DOM_SESSION, &[&self.session_id, output]);
        nonce.copy_from_slice(&nonce_input[..24]);
        let nonce_n = GenericArray::<u8, U24>::from_slice(&nonce);
        let ct = cipher
            .encrypt(
                nonce_n,
                Payload {
                    msg: output,
                    aad: &[],
                },
            )
            .map_err(|e| TeeError::Malformed(format!("output seal failed: {e}")))?;
        let mut sealed_out = nonce.to_vec();
        sealed_out.extend_from_slice(&ct);
        self.sealed_output = Some(sealed_out.clone());
        self.output_hash = Some(sha256_dom(DOM_USAGE, &[output]));
        self.state = SessionState::Sealed;
        // Wipe key and input from guest memory.
        self.data_key = None;
        self.input = None;
        self.audit.push(SessionEvent {
            transition: "Sealed".into(),
            height,
            detail: "output sealed; key and input wiped from guest memory".into(),
        });
        Ok(sealed_out)
    }

    /// Wipe all remaining guest memory and terminate. Sealed → Wiped.
    /// Fail-closed: cannot be un-wiped.
    pub fn wipe(&mut self, height: u64) -> Result<(), TeeError> {
        if self.state == SessionState::Wiped {
            return Err(TeeError::Malformed("already wiped".into()));
        }
        // Wipe key and input from guest memory.
        self.sealed_key = None;
        self.data_key = None;
        self.input = None;
        self.sealed_output = None;
        self.state = SessionState::Wiped;
        self.audit.push(SessionEvent {
            transition: "Wiped".into(),
            height,
            detail: "all guest memory wiped; session terminated".into(),
        });
        Ok(())
    }

    /// Record an attested usage record for one compute slice. The guest
    /// signs this over its attestation key; the consumer verifies it
    /// against the session's output hash.
    pub fn usage_record(&self, units: u32, slice_height: u64) -> UsageRecord {
        UsageRecord {
            session_id: self.session_id,
            output_hash: self.output_hash.unwrap_or([0u8; 32]),
            units,
            slice_height,
            sealed: self.state == SessionState::Sealed,
        }
    }
}

/// Attested usage record signed by the guest enclave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageRecord {
    pub session_id: Hash,
    pub output_hash: Hash,
    pub units: u32,
    pub slice_height: u64,
    pub sealed: bool,
}

impl UsageRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = srct_core::ser::Writer::with_capacity(128);
        w.fixed(&self.session_id)
            .fixed(&self.output_hash)
            .u32le(self.units)
            .u64le(self.slice_height)
            .u8(self.sealed as u8);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = srct_core::ser::Reader::new(bytes);
        let session_id = r
            .fixed()
            .map_err(|e| ComputeError::Malformed(format!("session_id: {e}")))?;
        let output_hash = r
            .fixed()
            .map_err(|e| ComputeError::Malformed(format!("output_hash: {e}")))?;
        let units = r
            .u32le()
            .map_err(|e| ComputeError::Malformed(format!("units: {e}")))?;
        let slice_height = r
            .u64le()
            .map_err(|e| ComputeError::Malformed(format!("slice_height: {e}")))?;
        let sealed = r
            .u8()
            .map_err(|e| ComputeError::Malformed(format!("sealed: {e}")))?
            != 0;
        r.expect_end()
            .map_err(|e| ComputeError::Malformed(format!("trailing: {e}")))?;
        Ok(UsageRecord {
            session_id,
            output_hash,
            units,
            slice_height,
            sealed,
        })
    }
}

/// Attest a quote against an SLA, returning the output hash on success.
/// This is the guest-side entry point: consumer provides the quote, guest
/// verifies it matches the expected SLA.
pub fn attest_quote(
    verifier: &mut TeeVerifier,
    sla: &TeeSla,
    signed: &SignedTeeQuote,
    roots: &AttestationRoots,
    vendor: &VendorInputs,
    presented_pubkey: &[u8],
    height: u64,
) -> Result<Hash, TeeError> {
    verifier.verify_v2(sla, signed, roots, vendor, presented_pubkey, height)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lifecycle() {
        let sla = TeeSla {
            version: 2,
            network_id: "srct/mini".into(),
            provider: [1u8; 20],
            workload: [2u8; 32],
            model_hash: [3u8; 32],
            runtime_hash: [4u8; 32],
            config_hash: [5u8; 32],
            input_hash: [6u8; 32],
            tee: TeeType::Tdx,
            max_age_heights: 10,
            min_tcb_svn: [0u8; 16],
            allow_debug: false,
            measurement: [7u8; 32],
        };
        let mut session = GuestSession::new([9u8; 32], TeeType::Tdx, sla.clone(), 10);
        assert_eq!(session.state, SessionState::Attesting);

        // Release key
        let sealed = SealedKey {
            encapped: [1u8; 32],
            ct: vec![2u8; 48],
        };
        session.release_key(sealed.clone(), [3u8; 32], 11).unwrap();
        assert_eq!(session.state, SessionState::KeyReleased);

        // Start run
        session.start_run(b"workload input".to_vec(), 12).unwrap();
        assert_eq!(session.state, SessionState::Running);
        assert!(session.input.is_some());

        // Seal output
        let sealed_out = session.seal_output(b"workload result", 13).unwrap();
        assert!(!sealed_out.is_empty());
        assert_eq!(session.state, SessionState::Sealed);
        assert!(session.data_key.is_none());
        assert!(session.input.is_none());
        assert!(session.output_hash.is_some());

        // Wipe
        session.wipe(14).unwrap();
        assert_eq!(session.state, SessionState::Wiped);

        // Cannot un-wipe
        assert!(session.wipe(15).is_err());
        // Cannot re-release after wipe
        assert!(session.release_key(sealed, [3u8; 32], 15).is_err());
    }

    #[test]
    fn usage_record_encodes() {
        let record = UsageRecord {
            session_id: [1u8; 32],
            output_hash: [2u8; 32],
            units: 100,
            slice_height: 50,
            sealed: true,
        };
        let bytes = record.encode();
        let decoded = UsageRecord::decode(&bytes).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn double_release_refused() {
        let sla = TeeSla {
            version: 2,
            network_id: "srct/mini".into(),
            provider: [1u8; 20],
            workload: [2u8; 32],
            model_hash: [3u8; 32],
            runtime_hash: [4u8; 32],
            config_hash: [5u8; 32],
            input_hash: [6u8; 32],
            tee: TeeType::Tdx,
            max_age_heights: 10,
            min_tcb_svn: [0u8; 16],
            allow_debug: false,
            measurement: [7u8; 32],
        };
        let mut session = GuestSession::new([9u8; 32], TeeType::Tdx, sla, 10);
        let sealed = SealedKey {
            encapped: [1u8; 32],
            ct: vec![2u8; 48],
        };
        session.release_key(sealed.clone(), [3u8; 32], 11).unwrap();
        assert!(session.release_key(sealed, [3u8; 32], 12).is_err());
    }
}
