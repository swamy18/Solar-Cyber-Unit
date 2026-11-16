//! Consumer-side confidential-tier key broker.
//!
//! Everything in this crate runs on the *consumer* side. It must never be
//! linked into the provider binary (`srct-worker`): the keystore holds data
//! keys, the release gate decides when they may leave, and neither may
//! exist on a machine the adversary administers.
//!
//! Pieces:
//!
//! - [`keywrap`]: HPKE (RFC 9180) seal/open with the single suite
//!   DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305.
//! - [`kms`]: pluggable key management. [`kms::LocalKeystore`] is the
//!   default (Argon2id + ChaCha20-Poly1305 file, `0600`, atomic write).
//!   [`kms::VaultKms`] and [`kms::CloudKms`] are documented stubs only.
//! - [`release`]: the attestation gate. A data key is sealed to an
//!   enclave key **iff** full vendor attestation verifies; otherwise the
//!   function returns an error and nothing leaves the broker.

pub mod error;
pub mod keywrap;
pub mod kms;
pub mod release;

pub use error::ConfidError;
pub use keywrap::{SealedKey, HPKE_INFO};
pub use kms::{KmsAdapter, LocalKeystore};
pub use release::{release_data_key, KeyPurpose, ReleasePolicy, SealedRelease};
