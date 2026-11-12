//! On-chain encryption-key registry (non-consensus).
//!
//! A worker that encrypts under the wrong requester key produces receipts no
//! verifier will accept, and a requester that loses its secret stalls every
//! open task. This registry is the operator-curated directory both sides
//! check: `add_key` publishes an owner's current public key, `rotate` moves
//! it to the retired set (old tasks still resolve), and `revoke` distrusts an
//! owner entirely. Like [`crate::task`] attestation roots, trust is configured
//! out of band — the registry records decisions, it does not make them.
//!
//! What this is not: a PKI. There are no certificates, no expiry and no
//! revocation lists over the wire; rotation history is bounded and archival
//! is the operator's job.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::Address;

use crate::elgamal::POINT_LEN;
use crate::task::decode_pubkey;
use crate::FheError;

pub const REGISTRY_VERSION: u8 = 1;
/// Most retired keys kept per owner. Past the cap the operator archives out
/// of band; rotation is refused rather than silently dropping audit history.
pub const MAX_RETIRED_KEYS: usize = 16;

/// The current encryption key of one requester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub owner: Address,
    pub pubkey: [u8; POINT_LEN],
    pub registered_height: u64,
}

/// Where a key stands. Retired keys still resolve so in-flight tasks keep
/// verifying; revoked owners resolve to nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Current,
    Retired,
    Unknown,
}

/// Operator-curated encryption keys per requester address.
#[derive(Clone, Debug, Default)]
pub struct KeyRegistry {
    network_id: String,
    current: BTreeMap<Address, KeyRecord>,
    retired: BTreeMap<Address, Vec<([u8; POINT_LEN], u64)>>,
    revoked: BTreeSet<Address>,
}

impl KeyRegistry {
    pub fn new(network_id: impl Into<String>) -> Self {
        KeyRegistry {
            network_id: network_id.into(),
            current: BTreeMap::new(),
            retired: BTreeMap::new(),
            revoked: BTreeSet::new(),
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn lookup(&self, owner: &Address) -> Option<&KeyRecord> {
        self.current.get(owner)
    }

    /// Whether `pubkey` ever belonged to `owner` and was rotated (not revoked).
    pub fn is_retired(&self, owner: &Address, pubkey: &[u8; POINT_LEN]) -> bool {
        self.retired
            .get(owner)
            .is_some_and(|v| v.iter().any(|(k, _)| k == pubkey))
    }

    pub fn status(&self, owner: &Address, pubkey: &[u8; POINT_LEN]) -> KeyStatus {
        if self.revoked.contains(owner) {
            return KeyStatus::Unknown;
        }
        if self.current.get(owner).is_some_and(|r| &r.pubkey == pubkey) {
            return KeyStatus::Current;
        }
        if self.is_retired(owner, pubkey) {
            return KeyStatus::Retired;
        }
        KeyStatus::Unknown
    }

    /// Publish an owner's first key. The bytes must decode to a curve point;
    /// a second current key needs `rotate`, not a second registration.
    pub fn add_key(
        &mut self,
        owner: Address,
        pubkey: [u8; POINT_LEN],
        height: u64,
    ) -> Result<(), FheError> {
        decode_pubkey(&pubkey)?;
        if self.revoked.contains(&owner) {
            return Err(FheError::Malformed("fhe owner is revoked".into()));
        }
        if self.current.contains_key(&owner) {
            return Err(FheError::Malformed("fhe owner already has a key".into()));
        }
        self.current.insert(
            owner,
            KeyRecord {
                owner,
                pubkey,
                registered_height: height,
            },
        );
        Ok(())
    }

    /// Replace an owner's key, keeping the old one resolvable for in-flight
    /// tasks. Rotating to the key already in use is refused.
    pub fn rotate(
        &mut self,
        owner: Address,
        pubkey: [u8; POINT_LEN],
        height: u64,
    ) -> Result<(), FheError> {
        decode_pubkey(&pubkey)?;
        if self.revoked.contains(&owner) {
            return Err(FheError::Malformed("fhe owner is revoked".into()));
        }
        let record = self
            .current
            .get(&owner)
            .ok_or_else(|| FheError::Malformed("fhe owner has no key".into()))?;
        if record.pubkey == pubkey {
            return Err(FheError::Malformed(
                "fhe rotation reuses the live key".into(),
            ));
        }
        let retired = self.retired.entry(owner).or_default();
        if retired.len() >= MAX_RETIRED_KEYS {
            return Err(FheError::Malformed("fhe retired keys are over cap".into()));
        }
        retired.push((record.pubkey, height));
        self.current.insert(
            owner,
            KeyRecord {
                owner,
                pubkey,
                registered_height: height,
            },
        );
        Ok(())
    }

    /// Distrust an owner entirely: current and retired keys stop resolving.
    /// The entries are kept for audit; trust is restored by re-adding a key
    /// after un-revoking out of band. Revocation itself is operator state
    /// here — there is no in-crate un-revoke, by design.
    pub fn revoke(&mut self, owner: Address) {
        self.current.remove(&owner);
        self.retired.remove(&owner);
        self.revoked.insert(owner);
    }

    pub fn is_revoked(&self, owner: &Address) -> bool {
        self.revoked.contains(owner)
    }
}
