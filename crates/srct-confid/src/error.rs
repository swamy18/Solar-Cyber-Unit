//! Error type for the consumer-side key broker.
//!
//! Display strings never include key material, passphrases, or sealed
//! plaintext: failures name the *check* that failed (unknown key, expired
//! key, revoked key, failed attestation), never the secret involved.

use std::fmt;

/// All failures of the confidential-tier key broker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfidError {
    /// Input bytes do not decode (keystore file, sealed bundle, hex, JSON).
    Malformed(String),
    /// A cryptographic operation failed (KDF, AEAD open, HPKE seal/open).
    /// The message names the step, never the key.
    Crypto(String),
    /// Key not found in the keystore.
    UnknownKey(String),
    /// Key past its TTL.
    Expired(String),
    /// Key was revoked by its owner.
    Revoked(String),
    /// Attestation did not verify, or was never run. The data key is not
    /// released on this path, by construction.
    AttestationFailed(String),
    /// The requested KMS backend is a documented stub, not an implementation.
    NotConfigured(String),
    /// Filesystem failure reading or writing the keystore.
    Io(String),
}

impl fmt::Display for ConfidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfidError::Malformed(d) => write!(f, "malformed confid data: {d}"),
            ConfidError::Crypto(d) => write!(f, "crypto operation failed: {d}"),
            ConfidError::UnknownKey(id) => write!(f, "unknown key id: {id}"),
            ConfidError::Expired(id) => write!(f, "key expired: {id}"),
            ConfidError::Revoked(id) => write!(f, "key revoked: {id}"),
            ConfidError::AttestationFailed(d) => write!(f, "attestation rejected: {d}"),
            ConfidError::NotConfigured(d) => write!(f, "kms backend not configured: {d}"),
            ConfidError::Io(d) => write!(f, "keystore io failed: {d}"),
        }
    }
}

impl std::error::Error for ConfidError {}

impl From<srct_compute::tee::TeeError> for ConfidError {
    fn from(e: srct_compute::tee::TeeError) -> Self {
        ConfidError::AttestationFailed(e.to_string())
    }
}
