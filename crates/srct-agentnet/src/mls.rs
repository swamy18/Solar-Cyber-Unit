//! MLS-style epoch-ratcheted group messaging (non-consensus).
//!
//! The sender-key groups in [`crate::groups`] re-key when a member leaves, but
//! every member keeps its own long-lived chain. MLS (RFC 9420) improves on
//! that: the group shares a *commitment* to its membership, and every commit
//! derives a fresh epoch key. This module implements that core:
//!
//! - a **key package** per member (leaf key plus the member's signature);
//! - **proposals** (add, remove) and a **commit** that carries the new epoch
//!   secret wrapped for each member's leaf key, so only members can unwrap it;
//! - an **epoch key** that every member holds, from which each sender's
//!   message key is derived — so any member can read any other member's
//!   messages, and a removed member cannot read the next epoch;
//! - **messages** signed by the sender and encrypted under the sender's
//!   epoch key, with a per-(epoch, sender) sequence that refuses replays.
//!
//! # What this is not
//!
//! - **Not RFC 9420.** The ratchet tree, path secrets, credential
//!   encryption and the ciphersuite negotiation are not implemented. This is
//!   the commitment-and-epoch structure that gives membership changes their
//!   teeth: a removal invalidates the next epoch's keys for everyone.
//! - **Not forward-secret inside an epoch.** MLS's tree ratchet gives
//!   per-message forward secrecy; here the epoch key covers every message of
//!   that epoch, so a compromise mid-epoch reads that epoch. A commit (which
//!   is cheap) closes the window.
//! - **Not consensus.** Nothing here mints, moves or finalizes anything.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use rand::rngs::StdRng;
use rand::RngCore;
use sha2::Sha256;
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::hash::{sha256_dom, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::message::MessageError;

pub const MLS_VERSION: u8 = 1;
/// Most members one group may hold.
pub const MAX_MLS_MEMBERS: usize = 128;
/// Most bytes one message body may hold.
pub const MAX_MLS_BODY: usize = 64 * 1024;
const NONCE_LEN: usize = 24;
const DOM_EPOCH: &[u8] = b"srct/agentnet/mls-epoch/v1";
const DOM_SENDER: &[u8] = b"srct/agentnet/mls-sender/v1";
const DOM_WRAP: &[u8] = b"srct/agentnet/mls-wrap/v1";

/// Why a group operation was refused. Fail-closed: any variant means no
/// membership change and no message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsError {
    Malformed(String),
    NotMember,
    UnknownMember,
    WrongGroup,
    WrongEpoch,
    BadSignature(String),
    BadKey(String),
    Replay,
    TooLarge,
}

impl std::fmt::Display for MlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsError::Malformed(detail) => write!(f, "malformed group message: {detail}"),
            MlsError::NotMember => write!(f, "sender is not a group member"),
            MlsError::UnknownMember => write!(f, "member is not in the group"),
            MlsError::WrongGroup => write!(f, "message is for another group"),
            MlsError::WrongEpoch => write!(f, "message is from a past epoch"),
            MlsError::BadSignature(detail) => write!(f, "invalid signature: {detail}"),
            MlsError::BadKey(detail) => write!(f, "invalid key: {detail}"),
            MlsError::Replay => write!(f, "group sequence was already consumed"),
            MlsError::TooLarge => write!(f, "group message exceeds its size cap"),
        }
    }
}

impl std::error::Error for MlsError {}

impl From<MessageError> for MlsError {
    fn from(e: MessageError) -> Self {
        MlsError::Malformed(e.to_string())
    }
}

/// A member's leaf key pair. The public half travels in the key package; the
/// private half never leaves its owner.
#[derive(Clone, Debug)]
pub struct LeafKey {
    pub secret: SecretKey,
}

impl LeafKey {
    pub fn generate(rng: &mut StdRng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let secret = SecretKey::from_slice(&bytes).expect("a random 32-byte scalar is a valid key");
        LeafKey { secret }
    }

    pub fn public_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out.copy_from_slice(self.secret.public_key().to_encoded_point(true).as_bytes());
        out
    }
}

/// A member's key package: the leaf public key plus the member's own
/// signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackage {
    pub member: AgentId,
    pub leaf_public: [u8; 33],
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl KeyPackage {
    /// Build a package for `member`, signed with the member's wallet.
    pub fn create(member: AgentId, leaf: &LeafKey, wallet: &Wallet) -> Result<Self, MlsError> {
        let body = package_body(&member, &leaf.public_bytes());
        let auth = Auth::sign(wallet, &body).map_err(|e| MlsError::BadSignature(e.to_string()))?;
        Ok(KeyPackage {
            member,
            leaf_public: leaf.public_bytes(),
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    /// Verify the member's signature over the package.
    pub fn verify(&self) -> Result<(), MlsError> {
        let body = package_body(&self.member, &self.leaf_public);
        verify_bundle(&self.sigs, &self.keys, &body)
            .map_err(|e| MlsError::BadSignature(e.to_string()))?;
        // The leaf key must be a curve point.
        PublicKey::from_sec1_bytes(&self.leaf_public)
            .map_err(|e| MlsError::BadKey(e.to_string()))?;
        Ok(())
    }
}

fn package_body(member: &AgentId, leaf_public: &[u8; 33]) -> Hash {
    let mut w = Writer::with_capacity(80);
    w.u8(MLS_VERSION).fixed(member).fixed(leaf_public);
    sha256_dom(b"srct/agentnet/mls-package/v1", &[w.as_slice()])
}

/// One membership change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposal {
    Add(KeyPackage),
    Remove(AgentId),
}

impl Proposal {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
        match self {
            Proposal::Add(pkg) => {
                w.u8(0).fixed(&pkg.member).fixed(&pkg.leaf_public);
                let sigs = pkg.sigs.to_bytes();
                let keys = pkg.keys.to_bytes();
                w.u32le(sigs.len() as u32).raw(&sigs);
                w.u32le(keys.len() as u32).raw(&keys);
            }
            Proposal::Remove(m) => {
                w.u8(1).fixed(m);
            }
        }
        w.into_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        let mut r = Reader::new(bytes);
        let bad = |d: &str| MlsError::Malformed(format!("proposal {d}"));
        match r.u8().map_err(|_| bad("is missing"))? {
            0 => {
                let member: AgentId = r.fixed().map_err(|_| bad("member is missing"))?;
                let leaf_public: [u8; 33] = r.fixed().map_err(|_| bad("leaf key is missing"))?;
                let sigs_len = r.u32le().map_err(|_| bad("sigs length is missing"))? as usize;
                if sigs_len > 8 * 1024 {
                    return Err(MlsError::TooLarge);
                }
                let sigs = Bundle::deserialize(
                    r.fixed_slice(sigs_len)
                        .map_err(|_| bad("sigs are missing"))?,
                )
                .map_err(|e| MlsError::BadSignature(e.to_string()))?;
                let keys_len = r.u32le().map_err(|_| bad("keys length is missing"))? as usize;
                if keys_len > 8 * 1024 {
                    return Err(MlsError::TooLarge);
                }
                let keys = Bundle::deserialize(
                    r.fixed_slice(keys_len)
                        .map_err(|_| bad("keys are missing"))?,
                )
                .map_err(|e| MlsError::BadSignature(e.to_string()))?;
                r.expect_end().map_err(|_| bad("has trailing bytes"))?;
                Ok(Proposal::Add(KeyPackage {
                    member,
                    leaf_public,
                    sigs,
                    keys,
                }))
            }
            1 => {
                let member: AgentId = r.fixed().map_err(|_| bad("member is missing"))?;
                r.expect_end().map_err(|_| bad("has trailing bytes"))?;
                Ok(Proposal::Remove(member))
            }
            _ => Err(bad("kind is unknown")),
        }
    }
}

/// A membership commit: proposals, the new epoch's keys wrapped for each
/// member, and the committer's signature over the whole thing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub version: u8,
    pub group: Hash,
    /// The epoch this commit moves the group *from*.
    pub epoch: u64,
    pub proposals: Vec<Proposal>,
    /// One wrapped epoch key per member of the *new* membership.
    pub wrapped: Vec<(AgentId, Vec<u8>)>,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl Commit {
    fn signing_body(&self) -> Hash {
        let mut w = Writer::with_capacity(256 + self.proposals.len() * 64);
        w.u8(self.version)
            .fixed(&self.group)
            .u64le(self.epoch)
            .u32le(self.proposals.len() as u32);
        for p in &self.proposals {
            let bytes = p.encode();
            w.u32le(bytes.len() as u32).raw(&bytes);
        }
        w.u32le(self.wrapped.len() as u32);
        for (member, blob) in &self.wrapped {
            w.fixed(member).u32le(blob.len() as u32).raw(blob);
        }
        sha256_dom(b"srct/agentnet/mls-commit/v1", &[w.as_slice()])
    }

    pub fn verify_signature(&self) -> Result<(), MlsError> {
        verify_bundle(&self.sigs, &self.keys, &self.signing_body())
            .map_err(|e| MlsError::BadSignature(e.to_string()))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(512);
        w.u8(self.version)
            .fixed(&self.group)
            .u64le(self.epoch)
            .u32le(self.proposals.len() as u32);
        for p in &self.proposals {
            let bytes = p.encode();
            w.u32le(bytes.len() as u32).raw(&bytes);
        }
        w.u32le(self.wrapped.len() as u32);
        for (member, blob) in &self.wrapped {
            w.fixed(member).u32le(blob.len() as u32).raw(blob);
        }
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        w.u32le(sigs.len() as u32).raw(&sigs);
        w.u32le(keys.len() as u32).raw(&keys);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        let mut r = Reader::new(bytes);
        let bad = |d: &str| MlsError::Malformed(format!("commit {d}"));
        let version = r.u8().map_err(|_| bad("is missing"))?;
        if version != MLS_VERSION {
            return Err(MlsError::Malformed("unsupported commit version".into()));
        }
        let group: Hash = r.fixed().map_err(|_| bad("group is missing"))?;
        let epoch = r.u64le().map_err(|_| bad("epoch is missing"))?;
        let count = r.u32le().map_err(|_| bad("proposal count is missing"))? as usize;
        if count > MAX_MLS_MEMBERS {
            return Err(MlsError::TooLarge);
        }
        let mut proposals = Vec::with_capacity(count);
        for _ in 0..count {
            let len = r.u32le().map_err(|_| bad("proposal length is missing"))? as usize;
            if len == 0 || len > 64 * 1024 {
                return Err(MlsError::TooLarge);
            }
            let blob = r
                .fixed_slice(len)
                .map_err(|_| bad("proposal bytes are missing"))?;
            proposals.push(Proposal::decode(blob)?);
        }
        let wcount = r.u32le().map_err(|_| bad("wrapped count is missing"))? as usize;
        if wcount > MAX_MLS_MEMBERS {
            return Err(MlsError::TooLarge);
        }
        let mut wrapped = Vec::with_capacity(wcount);
        for _ in 0..wcount {
            let member: AgentId = r.fixed().map_err(|_| bad("wrapped member is missing"))?;
            let len = r.u32le().map_err(|_| bad("wrapped length is missing"))? as usize;
            if len == 0 || len > 64 * 1024 {
                return Err(MlsError::TooLarge);
            }
            let blob = r
                .fixed_slice(len)
                .map_err(|_| bad("wrapped bytes are missing"))?
                .to_vec();
            wrapped.push((member, blob));
        }
        let sigs_len = r.u32le().map_err(|_| bad("sigs length is missing"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err(MlsError::TooLarge);
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|_| bad("sigs are missing"))?,
        )
        .map_err(|e| MlsError::BadSignature(e.to_string()))?;
        let keys_len = r.u32le().map_err(|_| bad("keys length is missing"))? as usize;
        if keys_len > 8 * 1024 {
            return Err(MlsError::TooLarge);
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|_| bad("keys are missing"))?,
        )
        .map_err(|e| MlsError::BadSignature(e.to_string()))?;
        r.expect_end().map_err(|_| bad("has trailing bytes"))?;
        let commit = Commit {
            version,
            group,
            epoch,
            proposals,
            wrapped,
            sigs,
            keys,
        };
        commit.verify_signature()?;
        Ok(commit)
    }
}

/// One member of the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub agent: AgentId,
    pub leaf_public: [u8; 33],
}

/// A member's view of the group: the membership, the epoch, and the epoch
/// key this member holds.
#[derive(Clone, Debug)]
pub struct MlsGroup {
    pub group: Hash,
    pub network_id: String,
    pub epoch: u64,
    pub members: Vec<Member>,
    /// The epoch key: every member holds the same one.
    pub epoch_key: [u8; 32],
    /// Highest consumed sequence per sender index, per epoch.
    last_seq: BTreeMap<usize, u64>,
}

/// The epoch key: one key shared by every member of the epoch. It is
/// derived from the epoch secret alone — including the member would give
/// each member a *different* key, and then no member could read another
/// member's messages.
fn derive_epoch_key(secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(secret), &[0u8; 32]);
    let mut out = [0u8; 32];
    hk.expand(DOM_EPOCH, &mut out).expect("epoch kdf expand");
    out
}

fn derive_sender_key(epoch_key: &[u8; 32], sender_index: usize) -> [u8; 32] {
    let idx = (sender_index as u64).to_le_bytes();
    let hk = Hkdf::<Sha256>::new(Some(epoch_key), &idx);
    let mut out = [0u8; 32];
    hk.expand(DOM_SENDER, &mut out).expect("sender kdf expand");
    out
}

/// Wrap an epoch key to one member's leaf key: ECDH then XChaCha20-Poly1305.
fn wrap_key(epoch_key: &[u8; 32], leaf_public: &[u8; 33]) -> Result<Vec<u8>, MlsError> {
    let peer =
        PublicKey::from_sec1_bytes(leaf_public).map_err(|e| MlsError::BadKey(e.to_string()))?;
    let ephemeral = SecretKey::random(&mut rand::rngs::OsRng);
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), peer.as_affine());
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &shared.raw_secret_bytes()[..]);
    let mut key = [0u8; 32];
    hk.expand(DOM_WRAP, &mut key)
        .map_err(|e| MlsError::BadKey(e.to_string()))?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| MlsError::BadKey(e.to_string()))?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ephemeral_pub = ephemeral.public_key().to_encoded_point(true);
    // Blob layout: ephemeral public key || nonce || sealed box. The epoch
    // key is the plaintext and never appears in the blob.
    let mut body = Vec::with_capacity(33 + NONCE_LEN + epoch_key.len() + 16);
    body.extend_from_slice(ephemeral_pub.as_bytes());
    body.extend_from_slice(&nonce);
    let aad = body.clone();
    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            AeadPayload {
                msg: epoch_key,
                aad: &aad,
            },
        )
        .map_err(|e| MlsError::BadKey(e.to_string()))?;
    body.extend_from_slice(&sealed);
    Ok(body)
}

/// Unwrap an epoch key with the member's leaf private key.
fn unwrap_key(blob: &[u8], leaf: &LeafKey) -> Result<[u8; 32], MlsError> {
    if blob.len() < 33 + NONCE_LEN + 16 {
        return Err(MlsError::Malformed("wrapped key is too short".into()));
    }
    let mut eph_bytes = [0u8; 33];
    eph_bytes.copy_from_slice(&blob[..33]);
    let eph =
        PublicKey::from_sec1_bytes(&eph_bytes).map_err(|e| MlsError::BadKey(e.to_string()))?;
    let shared = diffie_hellman(leaf.secret.to_nonzero_scalar(), eph.as_affine());
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &shared.raw_secret_bytes()[..]);
    let mut key = [0u8; 32];
    hk.expand(DOM_WRAP, &mut key)
        .map_err(|e| MlsError::BadKey(e.to_string()))?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| MlsError::BadKey(e.to_string()))?;
    let nonce: [u8; NONCE_LEN] = blob[33..33 + NONCE_LEN]
        .try_into()
        .map_err(|_| MlsError::Malformed("wrapped nonce is bad".into()))?;
    let sealed = &blob[33 + NONCE_LEN..];
    let plain = cipher
        .decrypt(
            &XNonce::from(nonce),
            AeadPayload {
                msg: sealed,
                aad: &blob[..33 + NONCE_LEN],
            },
        )
        .map_err(|_| MlsError::BadKey("wrapped key did not open".into()))?;
    if plain.len() != 32 {
        return Err(MlsError::Malformed(
            "unwrapped key is the wrong size".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plain);
    Ok(out)
}

/// A group message: signed by the sender, encrypted under the sender's
/// epoch key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsMessage {
    pub version: u8,
    pub group: Hash,
    pub epoch: u64,
    pub sender_index: usize,
    pub seq: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl MlsMessage {
    /// The wire and signing header: the routing fields plus the *ciphertext*
    /// length, so a decoder knows how many bytes to read.
    fn header(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(96);
        w.u8(self.version)
            .fixed(&self.group)
            .u64le(self.epoch)
            .u64le(self.sender_index as u64)
            .u64le(self.seq)
            .fixed(&self.nonce)
            .u32le(self.ciphertext.len() as u32);
        w.into_vec()
    }

    /// The AEAD associated data: the routing fields plus the *plaintext*
    /// length. It differs from the wire header by the 16-byte tag, so the
    /// two must be built separately -- the AEAD checks the plaintext length,
    /// the wire announces the ciphertext length.
    fn aad(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(96);
        w.u8(self.version)
            .fixed(&self.group)
            .u64le(self.epoch)
            .u64le(self.sender_index as u64)
            .u64le(self.seq)
            .fixed(&self.nonce)
            .u32le(self.ciphertext.len().saturating_sub(16) as u32);
        w.into_vec()
    }

    fn signing_hash(&self) -> Hash {
        let mut w = Writer::with_capacity(160 + self.ciphertext.len());
        w.raw(&self.header()).raw(&self.ciphertext);
        sha256_dom(b"srct/agentnet/mls-message/v1", &[w.as_slice()])
    }

    /// Verify the sender's signature over the header and the body.
    pub fn verify_signature(&self) -> Result<(), MlsError> {
        let body = self.signing_hash();
        verify_bundle(&self.sigs, &self.keys, &body)
            .map_err(|e| MlsError::BadSignature(e.to_string()))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256 + self.ciphertext.len());
        // The header carries the ciphertext length, so the body follows it.
        w.raw(&self.header());
        w.raw(&self.ciphertext);
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        w.u32le(sigs.len() as u32).raw(&sigs);
        w.u32le(keys.len() as u32).raw(&keys);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        let mut r = Reader::new(bytes);
        let bad = |d: &str| MlsError::Malformed(format!("message {d}"));
        let version = r.u8().map_err(|_| bad("is missing"))?;
        if version != MLS_VERSION {
            return Err(MlsError::Malformed("unsupported message version".into()));
        }
        let group: Hash = r.fixed().map_err(|_| bad("group is missing"))?;
        let epoch = r.u64le().map_err(|_| bad("epoch is missing"))?;
        let sender_index = r.u64le().map_err(|_| bad("sender index is missing"))? as usize;
        let seq = r.u64le().map_err(|_| bad("sequence is missing"))?;
        if seq == 0 {
            return Err(MlsError::Malformed("sequence is zero".into()));
        }
        let nonce: [u8; NONCE_LEN] = r.fixed().map_err(|_| bad("nonce is missing"))?;
        let ct_len = r.u32le().map_err(|_| bad("body length is missing"))? as usize;
        if ct_len == 0 || ct_len > MAX_MLS_BODY + 16 {
            return Err(MlsError::TooLarge);
        }
        let ciphertext = r
            .fixed_slice(ct_len)
            .map_err(|_| bad("body is missing"))?
            .to_vec();
        let sigs_len = r.u32le().map_err(|_| bad("sigs length is missing"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err(MlsError::TooLarge);
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|_| bad("sigs are missing"))?,
        )
        .map_err(|e| MlsError::BadSignature(e.to_string()))?;
        let keys_len = r.u32le().map_err(|_| bad("keys length is missing"))? as usize;
        if keys_len > 8 * 1024 {
            return Err(MlsError::TooLarge);
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|_| bad("keys are missing"))?,
        )
        .map_err(|e| MlsError::BadSignature(e.to_string()))?;
        r.expect_end().map_err(|_| bad("has trailing bytes"))?;
        let message = MlsMessage {
            version,
            group,
            epoch,
            sender_index,
            seq,
            nonce,
            ciphertext,
            sigs,
            keys,
        };
        message.verify_signature()?;
        Ok(message)
    }
}

impl MlsGroup {
    /// The group id for a network, creator and nonce. Deterministic, so
    /// every member derives the same id without a server.
    pub fn group_id(network_id: &str, creator: &AgentId, nonce: u64) -> Hash {
        sha256_dom(
            b"srct/agentnet/mls-group/v1",
            &[network_id.as_bytes(), creator, &nonce.to_le_bytes()],
        )
    }

    /// Create a group with one member (the creator).
    pub fn create(
        network_id: impl Into<String>,
        creator: AgentId,
        _role: AgentRole,
        leaf: &LeafKey,
        nonce: u64,
        rng: &mut StdRng,
    ) -> Self {
        let network_id = network_id.into();
        let group = Self::group_id(&network_id, &creator, nonce);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let epoch_key = derive_epoch_key(&secret);
        MlsGroup {
            group,
            network_id,
            epoch: 0,
            members: vec![Member {
                agent: creator,
                leaf_public: leaf.public_bytes(),
            }],
            epoch_key,
            last_seq: BTreeMap::new(),
        }
    }

    /// Join an existing group: the same group id, the membership and the
    /// epoch key the member received out of band (or unwrapped from a
    /// commit). A joining member starts at the given epoch.
    pub fn join(
        network_id: impl Into<String>,
        group: Hash,
        epoch: u64,
        members: Vec<Member>,
        epoch_key: [u8; 32],
    ) -> Self {
        MlsGroup {
            group,
            network_id: network_id.into(),
            epoch,
            members,
            epoch_key,
            last_seq: BTreeMap::new(),
        }
    }

    pub fn member_index(&self, agent: &AgentId) -> Option<usize> {
        self.members.iter().position(|m| &m.agent == agent)
    }

    pub fn is_member(&self, agent: &AgentId) -> bool {
        self.member_index(agent).is_some()
    }

    /// Build a commit for the given proposals. The committer must be a
    /// member; the new epoch key is wrapped for every member of the *new*
    /// membership.
    pub fn commit(
        &self,
        proposals: Vec<Proposal>,
        committer: &Wallet,
        rng: &mut StdRng,
    ) -> Result<Commit, MlsError> {
        let committer_agent = derive_agent_id(
            &self.network_id,
            AgentRole::Machine,
            &committer
                .address()
                .map_err(|e| MlsError::BadKey(e.to_string()))?,
        );
        if !self.is_member(&committer_agent) {
            return Err(MlsError::NotMember);
        }
        // Compute the new membership.
        let mut members = self.members.clone();
        for p in &proposals {
            match p {
                Proposal::Add(pkg) => {
                    pkg.verify()?;
                    if members.len() >= MAX_MLS_MEMBERS {
                        return Err(MlsError::TooLarge);
                    }
                    if members.iter().any(|m| m.agent == pkg.member) {
                        return Err(MlsError::Malformed("member is already present".into()));
                    }
                    members.push(Member {
                        agent: pkg.member,
                        leaf_public: pkg.leaf_public,
                    });
                }
                Proposal::Remove(agent) => {
                    if !members.iter().any(|m| &m.agent == agent) {
                        return Err(MlsError::UnknownMember);
                    }
                    if members.len() == 1 {
                        return Err(MlsError::Malformed(
                            "the last member cannot be removed".into(),
                        ));
                    }
                    members.retain(|m| &m.agent != agent);
                }
            }
        }
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let epoch_key = derive_epoch_key(&secret);
        let mut wrapped = Vec::with_capacity(members.len());
        for m in &members {
            let blob = wrap_key(&epoch_key, &m.leaf_public)?;
            wrapped.push((m.agent, blob));
        }
        let mut commit = Commit {
            version: MLS_VERSION,
            group: self.group,
            epoch: self.epoch,
            proposals,
            wrapped,
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        let body = commit.signing_body();
        let auth =
            Auth::sign(committer, &body).map_err(|e| MlsError::BadSignature(e.to_string()))?;
        commit.sigs = auth.sigs;
        commit.keys = auth.keys;
        Ok(commit)
    }

    /// Apply a commit: verify it, update the membership, and take the new
    /// epoch key from the wrapped blob addressed to this member.
    pub fn apply(&mut self, commit: &Commit, me: &AgentId, leaf: &LeafKey) -> Result<(), MlsError> {
        if commit.group != self.group {
            return Err(MlsError::WrongGroup);
        }
        if commit.epoch != self.epoch {
            return Err(MlsError::WrongEpoch);
        }
        commit.verify_signature()?;
        let mut members = self.members.clone();
        for p in &commit.proposals {
            match p {
                Proposal::Add(pkg) => {
                    pkg.verify()?;
                    if members.len() >= MAX_MLS_MEMBERS {
                        return Err(MlsError::TooLarge);
                    }
                    if members.iter().any(|m| m.agent == pkg.member) {
                        return Err(MlsError::Malformed("member is already present".into()));
                    }
                    members.push(Member {
                        agent: pkg.member,
                        leaf_public: pkg.leaf_public,
                    });
                }
                Proposal::Remove(agent) => {
                    if !members.iter().any(|m| &m.agent == agent) {
                        return Err(MlsError::UnknownMember);
                    }
                    if members.len() == 1 {
                        return Err(MlsError::Malformed(
                            "the last member cannot be removed".into(),
                        ));
                    }
                    members.retain(|m| &m.agent != agent);
                }
            }
        }
        if !members.iter().any(|m| &m.agent == me) {
            return Err(MlsError::NotMember);
        }
        let blob = commit
            .wrapped
            .iter()
            .find(|(m, _)| m == me)
            .map(|(_, b)| b.as_slice())
            .ok_or(MlsError::UnknownMember)?;
        let key = unwrap_key(blob, leaf)?;
        self.members = members;
        self.epoch += 1;
        self.epoch_key = key;
        self.last_seq.clear();
        Ok(())
    }

    /// Encrypt a message for the group.
    pub fn seal(
        &mut self,
        body: &[u8],
        sender: &Wallet,
        rng: &mut StdRng,
    ) -> Result<MlsMessage, MlsError> {
        if body.len() > MAX_MLS_BODY {
            return Err(MlsError::TooLarge);
        }
        let address = sender
            .address()
            .map_err(|e| MlsError::BadKey(e.to_string()))?;
        let agent = derive_agent_id(&self.network_id, AgentRole::Machine, &address);
        let index = self.member_index(&agent).ok_or(MlsError::NotMember)?;
        let seq = self.last_seq.get(&index).copied().unwrap_or(0) + 1;
        let key = derive_sender_key(&self.epoch_key, index);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let aad = {
            let mut w = Writer::with_capacity(96);
            w.u8(MLS_VERSION)
                .fixed(&self.group)
                .u64le(self.epoch)
                .u64le(index as u64)
                .u64le(seq)
                .fixed(&nonce)
                .u32le(body.len() as u32);
            w.into_vec()
        };
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).map_err(|e| MlsError::BadKey(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: body,
                    aad: &aad,
                },
            )
            .map_err(|e| MlsError::BadKey(e.to_string()))?;
        let mut message = MlsMessage {
            version: MLS_VERSION,
            group: self.group,
            epoch: self.epoch,
            sender_index: index,
            seq,
            nonce,
            ciphertext,
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        let body = message.signing_hash();
        let auth = Auth::sign(sender, &body).map_err(|e| MlsError::BadSignature(e.to_string()))?;
        message.sigs = auth.sigs;
        message.keys = auth.keys;
        self.last_seq.insert(index, seq);
        Ok(message)
    }

    /// Decrypt and verify a message from the group. Replays and stale
    /// epochs are refused.
    pub fn open(&mut self, message: &MlsMessage) -> Result<Vec<u8>, MlsError> {
        if message.group != self.group {
            return Err(MlsError::WrongGroup);
        }
        if message.epoch != self.epoch {
            return Err(MlsError::WrongEpoch);
        }
        if message.sender_index >= self.members.len() {
            return Err(MlsError::UnknownMember);
        }
        let body = message.signing_hash();
        verify_bundle(&message.sigs, &message.keys, &body)
            .map_err(|e| MlsError::BadSignature(e.to_string()))?;
        let last = self
            .last_seq
            .get(&message.sender_index)
            .copied()
            .unwrap_or(0);
        if message.seq <= last {
            return Err(MlsError::Replay);
        }
        let key = derive_sender_key(&self.epoch_key, message.sender_index);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).map_err(|e| MlsError::BadKey(e.to_string()))?;
        // The AEAD appends a 16-byte tag, so the plaintext length is the
        // ciphertext length minus the tag; `aad()` computes it the same way.
        let aad = message.aad();
        let plain = cipher
            .decrypt(
                &XNonce::from(message.nonce),
                AeadPayload {
                    msg: &message.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| MlsError::BadKey("group message did not open".into()))?;
        self.last_seq.insert(message.sender_index, message.seq);
        Ok(plain)
    }
}
