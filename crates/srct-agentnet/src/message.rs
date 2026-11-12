//! End-to-end encrypted agent messages.
//!
//! A message is encrypted to the recipient's secp256k1 identity key with an
//! ephemeral ECDH key, a domain-separated HKDF-SHA256 derivation, and
//! XChaCha20-Poly1305. The sender signs the full envelope with the existing
//! hybrid key bundle, so the recipient learns *who* sent it while the content
//! stays confidential.
//!
//! What is hidden and what is not:
//!
//! - **Hidden:** the plaintext, from the network, the transport and every other
//!   participant. Only the recipient's wallet (the agent owner) can decrypt.
//! - **Visible:** the sender and recipient agent identities, the thread id,
//!   sequence number, expiry and ciphertext size. This is a metadata leak by
//!   design in this version; sealed-sender routing is a later milestone.
//! - **Not forward-secret across messages:** the recipient's static key plus a
//!   captured ephemeral key decrypts that message. A double ratchet is not
//!   implemented. Per-message ephemeral keys do prevent one message's key from
//!   decrypting another.
//!
//! The signature covers the AAD (network, thread, sequence, both identities and
//! addresses, ephemeral key) as well as the nonce, expiry and ciphertext, so a
//! relay cannot re-home a message to another thread or recipient.

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
use srct_core::sig::{verify_bundle, Bundle, SCHEME_SECP256K1_ECDSA};
use srct_core::wallet::Wallet;

pub const MESSAGE_VERSION: u8 = 1;
pub const MAX_NETWORK_LEN: usize = 64;
pub const MAX_PLAINTEXT: usize = 64 * 1024;
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 16;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const DOM_KDF: &[u8] = b"srct/agentnet/kdf/v1";
const DOM_SIGN: &[u8] = b"srct/agentnet/message/v1";
const DOM_THREAD: &[u8] = b"srct/agentnet/thread/v1";

/// Why a message was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageError {
    Malformed(String),
    UnsupportedVersion(u8),
    WrongNetwork,
    WrongRecipient,
    BadSignature(String),
    BadKey(String),
    Crypto(String),
    TooLarge,
    InvalidSequence,
    /// The envelope's thread does not match the session's thread.
    WrongThread,
    /// The envelope's sender is not the peer this session is bound to.
    WrongPeer,
    /// The session cannot send or receive in its current state.
    RatchetState(String),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::Malformed(detail) => write!(f, "malformed message: {detail}"),
            MessageError::UnsupportedVersion(v) => write!(f, "unsupported message version {v}"),
            MessageError::WrongNetwork => write!(f, "message is for another network"),
            MessageError::WrongRecipient => write!(f, "message is for another recipient"),
            MessageError::BadSignature(detail) => write!(f, "invalid sender signature: {detail}"),
            MessageError::BadKey(detail) => write!(f, "invalid key: {detail}"),
            MessageError::Crypto(detail) => write!(f, "decryption failed: {detail}"),
            MessageError::TooLarge => write!(f, "message exceeds its size cap"),
            MessageError::InvalidSequence => write!(f, "sequence number must be positive"),
            MessageError::WrongThread => write!(f, "message belongs to another thread"),
            MessageError::WrongPeer => write!(f, "message is not from this session's peer"),
            MessageError::RatchetState(detail) => write!(f, "ratchet state: {detail}"),
        }
    }
}

impl std::error::Error for MessageError {}

/// A deterministic conversation id for two agents.
///
/// The order of the two identities does not matter, so both sides derive the
/// same thread. `nonce` lets one pair run multiple independent conversations.
pub fn thread_id(a: &AgentId, b: &AgentId, nonce: u64) -> Hash {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    sha256_dom(DOM_THREAD, &[first, second, &nonce.to_le_bytes()])
}

/// The party a message is encrypted to.
///
/// The address is the recipient's **hybrid** address (the same address that
/// owns funds and names the agent identity), while the ECDH key is the ECDSA
/// component of that key bundle. Binding both together here means a sender
/// cannot encrypt to a key that does not control the named recipient, and a
/// relay cannot substitute a key without breaking the address binding.
#[derive(Clone, Debug, PartialEq)]
pub struct Recipient {
    pub address: Address,
    pub role: AgentRole,
    pub keys: Bundle,
}

impl Recipient {
    /// Build a recipient from a public key bundle and verify the bundle names
    /// an address before it is used.
    pub fn new(keys: Bundle, role: AgentRole) -> Result<Self, MessageError> {
        keys.validate()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let address = keys
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let recipient = Recipient {
            address,
            role,
            keys,
        };
        recipient.validate()?;
        Ok(recipient)
    }

    /// Re-check an already-built recipient, including one whose public fields
    /// were mutated. [`MessageEnvelope::seal`] calls this so a key bundle can
    /// never be paired with an address it does not control.
    pub fn validate(&self) -> Result<(), MessageError> {
        self.keys
            .validate()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let bound = self
            .keys
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        if bound != self.address {
            return Err(MessageError::BadKey(
                "recipient keys do not match recipient address".into(),
            ));
        }
        self.ecdh_pubkey()?;
        Ok(())
    }

    /// Convenience for the common case: the recipient's wallet owns both the
    /// address and the ECDH key.
    pub fn from_wallet(wallet: &Wallet, role: AgentRole) -> Result<Self, MessageError> {
        let keys = Auth::keys_for(wallet).map_err(|e| MessageError::BadKey(e.to_string()))?;
        Self::new(keys, role)
    }

    /// The compressed secp256k1 public key used for the ECDH agreement.
    pub fn ecdh_pubkey(&self) -> Result<[u8; 33], MessageError> {
        let component = self
            .keys
            .components
            .iter()
            .find(|c| c.scheme == SCHEME_SECP256K1_ECDSA)
            .ok_or_else(|| MessageError::BadKey("recipient has no ECDSA key".into()))?;
        let bytes: [u8; 33] =
            component.bytes.as_slice().try_into().map_err(|_| {
                MessageError::BadKey("recipient ECDSA key is not compressed".into())
            })?;
        PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| MessageError::BadKey("recipient ECDSA key is not a point".into()))?;
        Ok(bytes)
    }
}

/// One encrypted, signed message.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageEnvelope {
    pub version: u8,
    pub network_id: String,
    pub thread: Hash,
    /// Strictly positive, per `(thread, sender)` sequence.
    pub seq: u64,
    pub sender_agent: AgentId,
    pub sender_address: Address,
    pub sender_role: AgentRole,
    pub recipient_agent: AgentId,
    pub recipient_address: Address,
    pub recipient_role: AgentRole,
    /// Compressed ephemeral public key used only for this message.
    pub ephemeral_pubkey: [u8; 33],
    pub nonce: [u8; NONCE_LEN],
    /// XChaCha20-Poly1305 ciphertext including the tag.
    pub ciphertext: Vec<u8>,
    pub expires_height: u64,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl MessageEnvelope {
    /// Encrypt and sign a message.
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
        let recipient_address = recipient.address;
        let recipient_role = recipient.role;
        let sender_address = sender
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let sender_agent = derive_agent_id(network_id, sender_role, &sender_address);
        let recipient_agent = derive_agent_id(network_id, recipient_role, &recipient_address);
        let recipient_pubkey = recipient.ecdh_pubkey()?;
        let recipient_public = PublicKey::from_sec1_bytes(&recipient_pubkey)
            .map_err(|e| MessageError::BadKey(e.to_string()))?;

        // Ephemeral key: fresh for every message.
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
        let key = derive_key(
            &shared.raw_secret_bytes()[..],
            &thread,
            network_id,
            &sender_agent,
            &recipient_agent,
        )?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = aad_bytes(
            MESSAGE_VERSION,
            network_id,
            &thread,
            seq,
            &sender_agent,
            &sender_address,
            sender_role,
            &recipient_agent,
            &recipient_address,
            recipient_role,
            &ephemeral_pubkey,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| MessageError::Crypto("cipher init".into()))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| MessageError::Crypto("encrypt".into()))?;

        let mut envelope = MessageEnvelope {
            version: MESSAGE_VERSION,
            network_id: network_id.to_string(),
            thread,
            seq,
            sender_agent,
            sender_address,
            sender_role,
            recipient_agent,
            recipient_address,
            recipient_role,
            ephemeral_pubkey,
            nonce,
            ciphertext,
            expires_height,
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        let auth = Auth::sign(sender, &envelope.signing_hash())
            .map_err(|e| MessageError::BadSignature(e.to_string()))?;
        envelope.sigs = auth.sigs;
        envelope.keys = auth.keys;
        Ok(envelope)
    }

    /// Domain-separated hash over every field a participant relies on.
    pub fn signing_hash(&self) -> Hash {
        let aad = aad_bytes(
            self.version,
            &self.network_id,
            &self.thread,
            self.seq,
            &self.sender_agent,
            &self.sender_address,
            self.sender_role,
            &self.recipient_agent,
            &self.recipient_address,
            self.recipient_role,
            &self.ephemeral_pubkey,
        );
        let mut w = Writer::with_capacity(aad.len() + NONCE_LEN + 8 + 4 + self.ciphertext.len());
        w.raw(&aad)
            .fixed(&self.nonce)
            .u64le(self.expires_height)
            .u32le(self.ciphertext.len() as u32)
            .raw(&self.ciphertext);
        sha256_dom(DOM_SIGN, &[w.as_slice()])
    }

    /// Message identity, used by the replay guard.
    pub fn id(&self) -> Hash {
        self.signing_hash()
    }

    /// Verify structure, identity binding and sender signature.
    ///
    /// This does not decrypt. A mailbox can therefore store a message it cannot
    /// read, which is the correct division: only the recipient's wallet can
    /// open it.
    pub fn verify(&self) -> Result<(), MessageError> {
        if self.version != MESSAGE_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_LEN {
            return Err(MessageError::Malformed("network id length".into()));
        }
        if self.seq == 0 {
            return Err(MessageError::InvalidSequence);
        }
        if self.ciphertext.len() < TAG_LEN || self.ciphertext.len() > MAX_CIPHERTEXT {
            return Err(MessageError::TooLarge);
        }
        if derive_agent_id(&self.network_id, self.sender_role, &self.sender_address)
            != self.sender_agent
        {
            return Err(MessageError::Malformed(
                "sender identity does not match its address".into(),
            ));
        }
        if derive_agent_id(
            &self.network_id,
            self.recipient_role,
            &self.recipient_address,
        ) != self.recipient_agent
        {
            return Err(MessageError::Malformed(
                "recipient identity does not match its address".into(),
            ));
        }
        let signer = self
            .keys
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        if signer != self.sender_address {
            return Err(MessageError::BadSignature(
                "key bundle is not the sender".into(),
            ));
        }
        PublicKey::from_sec1_bytes(&self.ephemeral_pubkey)
            .map_err(|_| MessageError::BadKey("ephemeral key is not a point".into()))?;
        verify_bundle(&self.sigs, &self.keys, &self.signing_hash())
            .map_err(|_| MessageError::BadSignature("signature does not verify".into()))?;
        Ok(())
    }

    /// Decrypt with the recipient's wallet. The wallet must be the owner of the
    /// recipient address; the agent's owner and the agent share that key.
    pub fn open(&self, recipient: &Wallet) -> Result<Vec<u8>, MessageError> {
        self.verify()?;
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
        let key = derive_key(
            &shared.raw_secret_bytes()[..],
            &self.thread,
            &self.network_id,
            &self.sender_agent,
            &self.recipient_agent,
        )?;
        let aad = aad_bytes(
            self.version,
            &self.network_id,
            &self.thread,
            self.seq,
            &self.sender_agent,
            &self.sender_address,
            self.sender_role,
            &self.recipient_agent,
            &self.recipient_address,
            self.recipient_role,
            &self.ephemeral_pubkey,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| MessageError::Crypto("cipher init".into()))?;
        let plaintext = cipher
            .decrypt(
                &XNonce::from(self.nonce),
                AeadPayload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                MessageError::Crypto("wrong key, wrong metadata or tampered ciphertext".into())
            })?;
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(MessageError::TooLarge);
        }
        Ok(plaintext)
    }

    /// Canonical wire encoding.
    pub fn encode(&self) -> Vec<u8> {
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(256 + self.network_id.len() + self.ciphertext.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.thread)
            .u64le(self.seq)
            .fixed(&self.sender_agent)
            .fixed(&self.sender_address)
            .u8(self.sender_role.as_u8())
            .fixed(&self.recipient_agent)
            .fixed(&self.recipient_address)
            .u8(self.recipient_role.as_u8())
            .fixed(&self.ephemeral_pubkey)
            .fixed(&self.nonce)
            .u64le(self.expires_height)
            .u32le(self.ciphertext.len() as u32)
            .raw(&self.ciphertext)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    /// Strict inverse of [`MessageEnvelope::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| MessageError::Malformed(e.to_string()))?;
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
        let sender_agent = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let sender_address = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let sender_role =
            AgentRole::from_u8(r.u8().map_err(|e| MessageError::Malformed(e.to_string()))?)
                .ok_or_else(|| MessageError::Malformed("sender role".into()))?;
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
        let nonce = r
            .fixed()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let expires_height = r
            .u64le()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let ct_len = r
            .u32le()
            .map_err(|e| MessageError::Malformed(e.to_string()))? as usize;
        if !(TAG_LEN..=MAX_CIPHERTEXT).contains(&ct_len) {
            return Err(MessageError::TooLarge);
        }
        let ciphertext = r
            .fixed_slice(ct_len)
            .map_err(|e| MessageError::Malformed(e.to_string()))?
            .to_vec();
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
        r.expect_end()
            .map_err(|e| MessageError::Malformed(e.to_string()))?;
        let envelope = MessageEnvelope {
            version,
            network_id,
            thread,
            seq,
            sender_agent,
            sender_address,
            sender_role,
            recipient_agent,
            recipient_address,
            recipient_role,
            ephemeral_pubkey,
            nonce,
            ciphertext,
            expires_height,
            sigs,
            keys,
        };
        envelope.verify()?;
        Ok(envelope)
    }
}

fn derive_key(
    shared: &[u8],
    thread: &Hash,
    network: &str,
    sender: &AgentId,
    recipient: &AgentId,
) -> Result<[u8; 32], MessageError> {
    let hk = Hkdf::<Sha256>::new(Some(thread), shared);
    let mut info = Vec::with_capacity(DOM_KDF.len() + network.len() + 40);
    info.extend_from_slice(DOM_KDF);
    info.extend_from_slice(network.as_bytes());
    info.extend_from_slice(sender);
    info.extend_from_slice(recipient);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| MessageError::Crypto("hkdf expand".into()))?;
    Ok(key)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn aad_bytes(
    version: u8,
    network: &str,
    thread: &Hash,
    seq: u64,
    sender_agent: &AgentId,
    sender_address: &Address,
    sender_role: AgentRole,
    recipient_agent: &AgentId,
    recipient_address: &Address,
    recipient_role: AgentRole,
    ephemeral_pubkey: &[u8; 33],
) -> Vec<u8> {
    let mut w = Writer::with_capacity(160 + network.len());
    w.u8(version)
        .u16le(network.len() as u16)
        .raw(network.as_bytes())
        .fixed(thread)
        .u64le(seq)
        .fixed(sender_agent)
        .fixed(sender_address)
        .u8(sender_role.as_u8())
        .fixed(recipient_agent)
        .fixed(recipient_address)
        .u8(recipient_role.as_u8())
        .fixed(ephemeral_pubkey);
    w.into_vec()
}
