//! Sealed-sender messaging (non-consensus).
//!
//! A normal envelope names its sender in plaintext, so every relay learns the
//! conversation graph. A sealed envelope hides the sender from everyone
//! except the recipient: routing fields (network, thread, sequence,
//! recipient, expiry) stay plaintext, while the sender identity, the sender's
//! key bundle and signature, and the body travel inside one AEAD box keyed
//! off an ephemeral ECDH with the recipient.
//!
//! The price of hiding is verification placement. A relay cannot verify what
//! it cannot decrypt, so sealed envelopes are *never* relay-mailbox
//! compatible: [`SealedEnvelope::open`] and [`SealedMailboxAccept`] run on
//! the recipient side, where the wallet both decrypts and verifies the
//! sender signature. Sequence guards still apply — sealed and normal
//! messages share one `(thread, sender)` sequence space — but the guard can
//! only be checked after decryption, so replays are refused at open time,
//! not at relay time.
//!
//! Snapshot note: a sealed snapshot replays structure and guards only.
//! Authenticity re-checks on `open` (tampered ciphertext fails there), which
//! is exactly where it is checkable.

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use rand::RngCore;
use sha2::Sha256;
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::message::{MessageError, Recipient, MAX_NETWORK_LEN, MAX_PLAINTEXT};

pub const SEALED_VERSION: u8 = 1;
/// Most bytes one sealed box may hold: body plus sender identity, signature
/// bundle and AEAD overhead.
pub const MAX_SEALED_BLOB: usize = MAX_PLAINTEXT + 1024;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const DOM_SEALED_KDF: &[u8] = b"srct/agentnet/sealed-kdf/v1";
const DOM_SEALED_SIGN: &[u8] = b"srct/agentnet/sealed/v1";

/// A sender-hidden envelope. The wire names no sender: no agent id, no
/// address, no role, no key bundle.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedEnvelope {
    pub version: u8,
    pub network_id: String,
    pub thread: Hash,
    pub seq: u64,
    pub recipient_agent: AgentId,
    pub recipient_address: Address,
    pub recipient_role: AgentRole,
    pub ephemeral_pubkey: [u8; 33],
    pub nonce: [u8; NONCE_LEN],
    pub expires_height: u64,
    /// AEAD box: `sender_agent || sender_address || sender_role ||
    /// sigs_len || sigs || keys_len || keys || body`. One box, one nonce,
    /// no key reuse.
    pub sealed: Vec<u8>,
}

fn sealed_kdf(
    shared: &[u8],
    thread: &Hash,
    network: &str,
    recipient: &AgentId,
) -> Result<[u8; 32], MessageError> {
    let hk = Hkdf::<Sha256>::new(Some(thread), shared);
    let mut info = Vec::with_capacity(DOM_SEALED_KDF.len() + network.len() + 20);
    info.extend_from_slice(DOM_SEALED_KDF);
    info.extend_from_slice(network.as_bytes());
    info.extend_from_slice(recipient);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| MessageError::Crypto("hkdf expand".into()))?;
    Ok(key)
}

#[allow(clippy::too_many_arguments)]
fn sealed_aad(
    network: &str,
    thread: &Hash,
    seq: u64,
    recipient_agent: &AgentId,
    recipient_address: &Address,
    recipient_role: AgentRole,
    ephemeral: &[u8; 33],
    expires: u64,
) -> Vec<u8> {
    let mut w = Writer::with_capacity(128 + network.len());
    w.u8(SEALED_VERSION)
        .u16le(network.len() as u16)
        .raw(network.as_bytes())
        .fixed(thread)
        .u64le(seq)
        .fixed(recipient_agent)
        .fixed(recipient_address)
        .u8(recipient_role.as_u8())
        .fixed(ephemeral)
        .u64le(expires);
    w.into_vec()
}

#[allow(clippy::too_many_arguments)]
fn sealed_signing_hash(
    network: &str,
    thread: &Hash,
    seq: u64,
    recipient_agent: &AgentId,
    recipient_address: &Address,
    recipient_role: AgentRole,
    expires: u64,
    body: &[u8],
) -> Hash {
    let mut w = Writer::with_capacity(128 + network.len() + body.len());
    w.raw(DOM_SEALED_SIGN)
        .u16le(network.len() as u16)
        .raw(network.as_bytes())
        .fixed(thread)
        .u64le(seq)
        .fixed(recipient_agent)
        .fixed(recipient_address)
        .u8(recipient_role.as_u8())
        .u64le(expires)
        .u32le(body.len() as u32)
        .raw(body);
    sha256_dom(DOM_SEALED_SIGN, &[w.as_slice()])
}

impl SealedEnvelope {
    /// Seal a message, hiding the sender from relays.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        sender: &Wallet,
        sender_role: AgentRole,
        network_id: &str,
        thread: Hash,
        seq: u64,
        recipient: &Recipient,
        plaintext: &[u8],
        expires_height: u64,
    ) -> Result<Self, MessageError> {
        if network_id.is_empty() || network_id.len() > MAX_NETWORK_LEN {
            return Err(MessageError::Malformed("network id length".into()));
        }
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(MessageError::TooLarge);
        }
        if seq == 0 {
            return Err(MessageError::InvalidSequence);
        }
        recipient.validate()?;
        let sender_address = sender
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let sender_agent = derive_agent_id(network_id, sender_role, &sender_address);
        let recipient_address = recipient.address;
        let recipient_role = recipient.role;
        let recipient_agent = derive_agent_id(network_id, recipient_role, &recipient_address);
        let recipient_pubkey = recipient.ecdh_pubkey()?;
        let recipient_public = PublicKey::from_sec1_bytes(&recipient_pubkey)
            .map_err(|e| MessageError::BadKey(e.to_string()))?;

        let signing_hash = sealed_signing_hash(
            network_id,
            &thread,
            seq,
            &recipient_agent,
            &recipient_address,
            recipient_role,
            expires_height,
            plaintext,
        );
        let auth = Auth::sign(sender, &signing_hash)
            .map_err(|e| MessageError::BadSignature(e.to_string()))?;
        let sigs = auth.sigs.to_bytes();
        let keys = auth.keys.to_bytes();

        let (ephemeral, ephemeral_pubkey) = loop {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            match SecretKey::from_slice(&bytes) {
                Ok(key) => {
                    let encoded = key.public_key().to_encoded_point(true);
                    let mut public = [0u8; 33];
                    public.copy_from_slice(encoded.as_bytes());
                    break (key, public);
                }
                Err(_) => continue,
            }
        };
        let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient_public.as_affine());
        let key = sealed_kdf(
            &shared.raw_secret_bytes()[..],
            &thread,
            network_id,
            &recipient_agent,
        )?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let mut inner = Writer::with_capacity(128 + sigs.len() + keys.len() + plaintext.len());
        inner
            .fixed(&sender_agent)
            .fixed(&sender_address)
            .u8(sender_role.as_u8())
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys)
            .u32le(plaintext.len() as u32)
            .raw(plaintext);
        let inner = inner.into_vec();
        if inner.len() + TAG_LEN > MAX_SEALED_BLOB {
            return Err(MessageError::TooLarge);
        }
        let aad = sealed_aad(
            network_id,
            &thread,
            seq,
            &recipient_agent,
            &recipient_address,
            recipient_role,
            &ephemeral_pubkey,
            expires_height,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| MessageError::Crypto("cipher init".into()))?;
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: &inner,
                    aad: &aad,
                },
            )
            .map_err(|_| MessageError::Crypto("encrypt".into()))?;
        Ok(SealedEnvelope {
            version: SEALED_VERSION,
            network_id: network_id.to_string(),
            thread,
            seq,
            recipient_agent,
            recipient_address,
            recipient_role,
            ephemeral_pubkey,
            nonce,
            expires_height,
            sealed,
        })
    }

    /// Message identity for recipient-side replay guards.
    pub fn id(&self) -> Hash {
        sha256_dom(
            DOM_SEALED_SIGN,
            &[
                self.network_id.as_bytes(),
                &self.thread,
                &self.seq.to_le_bytes(),
                &self.recipient_agent,
                &self.ephemeral_pubkey,
                &self.nonce,
                &self.sealed,
            ],
        )
    }

    /// Decrypt and verify with the recipient's wallet. Returns the sender's
    /// agent id and the body. The sender signature covers the routing plus
    /// the body, so a relay that re-homes the envelope breaks verification.
    pub fn open(&self, recipient: &Wallet) -> Result<(AgentId, Vec<u8>), MessageError> {
        if self.version != SEALED_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_LEN {
            return Err(MessageError::Malformed("network id length".into()));
        }
        if self.seq == 0 {
            return Err(MessageError::InvalidSequence);
        }
        if self.sealed.len() > MAX_SEALED_BLOB || self.sealed.len() < TAG_LEN {
            return Err(MessageError::TooLarge);
        }
        let address = recipient
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        if address != self.recipient_address {
            return Err(MessageError::WrongRecipient);
        }
        let secret_bytes = recipient.private_key_bytes();
        let secret = SecretKey::from_slice(&secret_bytes[..])
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let ephemeral = PublicKey::from_sec1_bytes(&self.ephemeral_pubkey)
            .map_err(|_| MessageError::BadKey("ephemeral key is not a point".into()))?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
        let key = sealed_kdf(
            &shared.raw_secret_bytes()[..],
            &self.thread,
            &self.network_id,
            &self.recipient_agent,
        )?;
        let aad = sealed_aad(
            &self.network_id,
            &self.thread,
            self.seq,
            &self.recipient_agent,
            &self.recipient_address,
            self.recipient_role,
            &self.ephemeral_pubkey,
            self.expires_height,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| MessageError::Crypto("cipher init".into()))?;
        let inner = cipher
            .decrypt(
                &XNonce::from(self.nonce),
                AeadPayload {
                    msg: &self.sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                MessageError::Crypto("wrong key, wrong metadata or tampered box".into())
            })?;
        let mut r = Reader::new(&inner);
        let sender_agent: AgentId = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let sender_address: Address = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let sender_role =
            AgentRole::from_u8(r.u8().map_err(|e| MessageError::Malformed(e.to_string()))?)
                .ok_or_else(|| MessageError::Malformed("sender role".into()))?;
        let sigs_len = r
            .u32le()
            .map_err(|e| MessageError::Malformed(e.to_string()))? as usize;
        if sigs_len > 8 * 1024 {
            return Err(MessageError::TooLarge);
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|e| MessageError::Malformed(e.to_string()))?,
        )
        .map_err(|e| MessageError::BadSignature(e.to_string()))?;
        let keys_len = r
            .u32le()
            .map_err(|e| MessageError::Malformed(e.to_string()))? as usize;
        if keys_len > 8 * 1024 {
            return Err(MessageError::TooLarge);
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|e| MessageError::Malformed(e.to_string()))?,
        )
        .map_err(|e| MessageError::BadSignature(e.to_string()))?;
        let body_len = r
            .u32le()
            .map_err(|e| MessageError::Malformed(e.to_string()))? as usize;
        if body_len > MAX_PLAINTEXT {
            return Err(MessageError::TooLarge);
        }
        let body = r
            .fixed_slice(body_len)
            .map_err(|e| MessageError::Malformed(e.to_string()))?
            .to_vec();
        r.expect_end()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        // The decrypted keys must name the decrypted sender; the signature
        // must cover the routing plus the body.
        let signer = keys
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        if signer != sender_address {
            return Err(MessageError::BadSignature(
                "key bundle is not the sender".into(),
            ));
        }
        if derive_agent_id(&self.network_id, sender_role, &sender_address) != sender_agent {
            return Err(MessageError::BadSignature(
                "sender identity does not match its address".into(),
            ));
        }
        let signing_hash = sealed_signing_hash(
            &self.network_id,
            &self.thread,
            self.seq,
            &self.recipient_agent,
            &self.recipient_address,
            self.recipient_role,
            self.expires_height,
            &body,
        );
        verify_bundle(&sigs, &keys, &signing_hash)
            .map_err(|_| MessageError::BadSignature("signature does not verify".into()))?;
        Ok((sender_agent, body))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256 + self.network_id.len() + self.sealed.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.thread)
            .u64le(self.seq)
            .fixed(&self.recipient_agent)
            .fixed(&self.recipient_address)
            .u8(self.recipient_role.as_u8())
            .fixed(&self.ephemeral_pubkey)
            .fixed(&self.nonce)
            .u64le(self.expires_height)
            .u32le(self.sealed.len() as u32)
            .raw(&self.sealed);
        w.into_vec()
    }

    /// Structure-only decode. Authenticity checks on `open`, never here: the
    /// opener holds the only key that can check them.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > 128 + MAX_NETWORK_LEN + MAX_SEALED_BLOB {
            return Err(MessageError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| MessageError::Malformed(e.to_string()))?;
        if version != SEALED_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|e| MessageError::Malformed(e.to_string()))? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_LEN {
            return Err(MessageError::Malformed("network id length".into()));
        }
        let network_id = std::str::from_utf8(
            r.fixed_slice(net_len)
                .map_err(|e| MessageError::Malformed(e.to_string()))?,
        )
        .map_err(|_| MessageError::Malformed("network is not utf-8".into()))?
        .to_string();
        let thread = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let seq = r
            .u64le()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        if seq == 0 {
            return Err(MessageError::InvalidSequence);
        }
        let recipient_agent = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let recipient_address = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let recipient_role =
            AgentRole::from_u8(r.u8().map_err(|e| MessageError::Malformed(e.to_string()))?)
                .ok_or_else(|| MessageError::Malformed("recipient role".into()))?;
        let ephemeral_pubkey = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        PublicKey::from_sec1_bytes(&ephemeral_pubkey)
            .map_err(|_| MessageError::BadKey("ephemeral key is not a point".into()))?;
        let nonce: [u8; NONCE_LEN] = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let expires_height = r
            .u64le()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let sealed_len = r
            .u32le()
            .map_err(|e| MessageError::Malformed(e.to_string()))? as usize;
        if !(TAG_LEN..=MAX_SEALED_BLOB).contains(&sealed_len) {
            return Err(MessageError::TooLarge);
        }
        let sealed = r
            .fixed_slice(sealed_len)
            .map_err(|e| MessageError::Malformed(e.to_string()))?
            .to_vec();
        r.expect_end()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        Ok(SealedEnvelope {
            version,
            network_id,
            thread,
            seq,
            recipient_agent,
            recipient_address,
            recipient_role,
            ephemeral_pubkey,
            nonce,
            expires_height,
            sealed,
        })
    }
}
