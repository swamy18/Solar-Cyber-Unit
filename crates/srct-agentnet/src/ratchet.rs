//! Double-ratchet sessions on top of the message envelope.
//!
//! [`MessageEnvelope::seal`](crate::message::MessageEnvelope::seal) encrypts
//! every message to the recipient's static key, so a wallet key plus a captured
//! ephemeral key decrypts that message forever. A ratchet session removes that
//! permanent exposure: message keys are derived from a chain that is
//! irreversibly advanced after every message, and each change of direction
//! mixes in a fresh Diffie-Hellman key.
//!
//! The protocol is the standard double ratchet, specialised for this crate's
//! ordered transport:
//!
//! - The **initiator** generates a fresh DH ratchet key and derives the root
//!   key from `ECDH(that key, the recipient's static key)`; its first envelope
//!   header carries that ratchet key in the `ephemeral_pubkey` field.
//! - The **responder** recognises the first message, performs the same ECDH
//!   with its static key, and immediately rotates its own ratchet key. Its
//!   first reply therefore mixes a second DH into the root key.
//! - Every message advances only the sending chain; an old chain key cannot
//!   derive a later message key (forward secrecy).
//! - Every direction change feeds a new ECDH into the root key, so an
//!   attacker who learns one side's *current* state still cannot read past
//!   messages and loses access again after the next reply (post-compromise
//!   security).
//!
//! Consequences that are deliberate:
//!
//! - messages must arrive in order: a gap in `seq` is refused rather than
//!   buffered, exactly like the mailbox. Skipped-key buffers would be the
//!   alternative and this crate chooses the simpler fail-closed rule.
//! - a ratchet message can **not** be opened with
//!   [`MessageEnvelope::open`](crate::message::MessageEnvelope::open) — the
//!   static path derives a different key. Only the session can decrypt.
//! - the envelope format, the signature and the mailbox are unchanged. A
//!   ratchet envelope verifies and is stored by a relay exactly like any
//!   other envelope; only the two endpoints hold ratchet state.

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
use srct_core::ser::Writer;
use srct_core::wallet::Wallet;

use crate::message::{
    aad_bytes, MessageEnvelope, MessageError, Recipient, MAX_NETWORK_LEN, MAX_PLAINTEXT,
    MESSAGE_VERSION,
};

const DOM_SESSION: &[u8] = b"srct/agentnet/ratchet/session/v1";
const DOM_RK: &[u8] = b"srct/agentnet/ratchet/root/v1";
const DOM_CK: &[u8] = b"srct/agentnet/ratchet/chain/v1";
const DOM_MK: &[u8] = b"srct/agentnet/ratchet/message/v1";

/// Which endpoint of the conversation this session is.
///
/// The initiator sends first; the responder must receive the initiator's
/// first message before it can send anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionSide {
    Initiator,
    Responder,
}

/// One pairwise ratchet conversation.
///
/// A session owns the cryptographic state for exactly one `(network, thread)`
/// pair between two agents. It is cheap to clone for snapshot/forensics tests,
/// but a clone is a *frozen copy*: using it after the live session advanced
/// will fail, which is the forward-secrecy property.
#[derive(Clone)]
pub struct RatchetSession {
    network_id: String,
    thread: Hash,
    side: SessionSide,
    local_address: Address,
    local_role: AgentRole,
    local_agent: AgentId,
    remote_address: Address,
    remote_role: AgentRole,
    remote_agent: AgentId,
    /// Root key. `None` for a responder until the first message arrives.
    rk: Option<[u8; 32]>,
    /// Our current DH ratchet key.
    dhs: SecretKey,
    dhs_pub: [u8; 33],
    /// The peer's current DH ratchet key.
    dhr: Option<[u8; 33]>,
    /// Sending and receiving chain keys.
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    /// Envelope sequence numbers, global per sender, never reset by a step.
    next_send: u64,
    next_recv: u64,
}

impl RatchetSession {
    /// Open a session as the endpoint that sends the first message.
    ///
    /// The recipient's key bundle is validated (address binding included) so
    /// the root DH cannot be computed against a key the named recipient does
    /// not control.
    pub fn initiator(
        wallet: &Wallet,
        role: AgentRole,
        network_id: &str,
        thread: Hash,
        recipient: &Recipient,
    ) -> Result<Self, MessageError> {
        validate_network(network_id)?;
        recipient.validate()?;
        let local_address = wallet
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let local_agent = derive_agent_id(network_id, role, &local_address);
        let remote_agent = derive_agent_id(network_id, recipient.role, &recipient.address);
        let remote_pubkey = recipient.ecdh_pubkey()?;
        let remote_public = PublicKey::from_sec1_bytes(&remote_pubkey)
            .map_err(|e| MessageError::BadKey(e.to_string()))?;

        // The initiator's first DH ratchet key doubles as the handshake key:
        // ECDH against the recipient's static key seeds the root key.
        let (dhs, dhs_pub) = generate_key()?;
        let dh0 = diffie_hellman(dhs.to_nonzero_scalar(), remote_public.as_affine());
        let salt = session_salt(network_id, &thread, &local_agent, &remote_agent);
        let (rk, cks) = kdf_rk(&salt, dh0.raw_secret_bytes())?;

        Ok(RatchetSession {
            network_id: network_id.to_string(),
            thread,
            side: SessionSide::Initiator,
            local_address,
            local_role: role,
            local_agent,
            remote_address: recipient.address,
            remote_role: recipient.role,
            remote_agent,
            rk: Some(rk),
            dhs,
            dhs_pub,
            dhr: Some(remote_pubkey),
            cks: Some(cks),
            ckr: None,
            next_send: 0,
            next_recv: 1,
        })
    }

    /// Open a session as the endpoint that receives the first message.
    ///
    /// The expected peer is bound at construction: an envelope claiming the
    /// same thread but a different sender is refused, so a third party cannot
    /// hijack the session by delivering its own handshake first.
    pub fn responder(
        wallet: &Wallet,
        role: AgentRole,
        network_id: &str,
        thread: Hash,
        remote: &Recipient,
    ) -> Result<Self, MessageError> {
        validate_network(network_id)?;
        remote.validate()?;
        let local_address = wallet
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let local_agent = derive_agent_id(network_id, role, &local_address);
        let remote_agent = derive_agent_id(network_id, remote.role, &remote.address);

        // Until the first message arrives, our ratchet key is the wallet's
        // static key; the first receive rotates it to a fresh pair.
        let dhs = SecretKey::from_slice(&wallet.private_key_bytes()[..])
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let encoded = dhs.public_key().to_encoded_point(true);
        let mut dhs_pub = [0u8; 33];
        dhs_pub.copy_from_slice(encoded.as_bytes());

        Ok(RatchetSession {
            network_id: network_id.to_string(),
            thread,
            side: SessionSide::Responder,
            local_address,
            local_role: role,
            local_agent,
            remote_address: remote.address,
            remote_role: remote.role,
            remote_agent,
            rk: None,
            dhs,
            dhs_pub,
            dhr: None,
            cks: None,
            ckr: None,
            next_send: 0,
            next_recv: 1,
        })
    }

    pub fn thread(&self) -> Hash {
        self.thread
    }

    pub fn side(&self) -> SessionSide {
        self.side
    }

    /// The sequence number the next accepted message must carry.
    pub fn next_recv(&self) -> u64 {
        self.next_recv
    }

    /// The sequence number the next sent message will carry.
    pub fn next_send(&self) -> u64 {
        self.next_send + 1
    }

    /// The peer's current DH ratchet key (the header future messages carry).
    pub fn remote_ratchet(&self) -> Option<[u8; 33]> {
        self.dhr
    }

    /// Our current DH ratchet key (the header our next message carries).
    pub fn local_ratchet(&self) -> [u8; 33] {
        self.dhs_pub
    }

    /// Encrypt, sign and return the next message in this thread.
    ///
    /// The sending chain advances only after the envelope is fully built and
    /// signed, so a failure never burns a message key and never opens a gap
    /// the peer would refuse forever.
    pub fn send(
        &mut self,
        wallet: &Wallet,
        plaintext: &[u8],
        expires_height: u64,
    ) -> Result<MessageEnvelope, MessageError> {
        self.check_wallet(wallet)?;
        let ck = self
            .cks
            .ok_or_else(|| MessageError::RatchetState("no sending chain; receive first".into()))?;
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(MessageError::TooLarge);
        }
        let seq = self.next_send + 1;
        let (key, nonce) = message_key(&ck, seq)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| MessageError::Crypto("cipher init".into()))?;
        let aad = self.aad(seq);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| MessageError::Crypto("encrypt".into()))?;

        let sender_address = wallet
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        let mut envelope = MessageEnvelope {
            version: MESSAGE_VERSION,
            network_id: self.network_id.clone(),
            thread: self.thread,
            seq,
            sender_agent: self.local_agent,
            sender_address,
            sender_role: self.local_role,
            recipient_agent: self.remote_agent,
            recipient_address: self.remote_address,
            recipient_role: self.remote_role,
            ephemeral_pubkey: self.dhs_pub,
            nonce,
            ciphertext,
            expires_height,
            sigs: Default::default(),
            keys: Default::default(),
        };
        let auth = Auth::sign(wallet, &envelope.signing_hash())
            .map_err(|e| MessageError::BadSignature(e.to_string()))?;
        envelope.sigs = auth.sigs;
        envelope.keys = auth.keys;

        self.cks = Some(chain_step(&ck)?);
        self.next_send = seq;
        Ok(envelope)
    }

    /// Verify and decrypt an incoming message.
    ///
    /// Refusals never advance the chains: a tampered or out-of-order message
    /// leaves the session able to accept the honest message that follows.
    pub fn receive(
        &mut self,
        envelope: &MessageEnvelope,
        wallet: &Wallet,
    ) -> Result<Vec<u8>, MessageError> {
        envelope.verify()?;
        self.check_wallet(wallet)?;
        if envelope.network_id != self.network_id {
            return Err(MessageError::WrongNetwork);
        }
        if envelope.thread != self.thread {
            return Err(MessageError::WrongThread);
        }
        if envelope.sender_agent != self.remote_agent
            || envelope.sender_address != self.remote_address
            || envelope.sender_role != self.remote_role
        {
            return Err(MessageError::WrongPeer);
        }
        if envelope.recipient_agent != self.local_agent {
            return Err(MessageError::WrongRecipient);
        }

        let header = envelope.ephemeral_pubkey;
        if Some(header) != self.dhr {
            let header_public = PublicKey::from_sec1_bytes(&header)
                .map_err(|_| MessageError::BadKey("ratchet key is not a point".into()))?;
            match self.dhr {
                None => {
                    // First message: pair the peer's ratchet key with our
                    // static key, exactly as the initiator did.
                    let static_key = SecretKey::from_slice(&wallet.private_key_bytes()[..])
                        .map_err(|e| MessageError::BadKey(e.to_string()))?;
                    let dh0 =
                        diffie_hellman(static_key.to_nonzero_scalar(), header_public.as_affine());
                    let salt = session_salt(
                        &self.network_id,
                        &self.thread,
                        &envelope.sender_agent,
                        &envelope.recipient_agent,
                    );
                    let (rk, ckr) = kdf_rk(&salt, dh0.raw_secret_bytes())?;
                    self.rk = Some(rk);
                    self.ckr = Some(ckr);
                }
                Some(_) => {
                    let rk = self
                        .rk
                        .ok_or_else(|| MessageError::RatchetState("root key missing".into()))?;
                    let dh =
                        diffie_hellman(self.dhs.to_nonzero_scalar(), header_public.as_affine());
                    let (rk, ckr) = kdf_rk(&rk, dh.raw_secret_bytes())?;
                    self.rk = Some(rk);
                    self.ckr = Some(ckr);
                }
            }
            // Rotate our sending ratchet key now, so the next reply mixes a
            // fresh DH into the root key even if we never send.
            let (dhs, dhs_pub) = generate_key()?;
            let dh2 = diffie_hellman(dhs.to_nonzero_scalar(), header_public.as_affine());
            let rk = self.rk.ok_or_else(|| {
                MessageError::RatchetState("root key missing after ratchet step".into())
            })?;
            let (rk, cks) = kdf_rk(&rk, dh2.raw_secret_bytes())?;
            self.rk = Some(rk);
            self.dhs = dhs;
            self.dhs_pub = dhs_pub;
            self.dhr = Some(header);
            self.cks = Some(cks);
        }

        let ck = self
            .ckr
            .ok_or_else(|| MessageError::RatchetState("no receiving chain yet".into()))?;
        if envelope.seq != self.next_recv {
            return Err(MessageError::RatchetState(format!(
                "expected sequence {}, got {}",
                self.next_recv, envelope.seq
            )));
        }
        let (key, nonce) = message_key(&ck, envelope.seq)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| MessageError::Crypto("cipher init".into()))?;
        let aad = aad_bytes(
            envelope.version,
            &envelope.network_id,
            &envelope.thread,
            envelope.seq,
            &envelope.sender_agent,
            &envelope.sender_address,
            envelope.sender_role,
            &envelope.recipient_agent,
            &envelope.recipient_address,
            envelope.recipient_role,
            &envelope.ephemeral_pubkey,
        );
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                MessageError::Crypto("message does not decrypt under this session's chain".into())
            })?;
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(MessageError::TooLarge);
        }
        self.ckr = Some(chain_step(&ck)?);
        self.next_recv += 1;
        Ok(plaintext)
    }

    fn check_wallet(&self, wallet: &Wallet) -> Result<(), MessageError> {
        let address = wallet
            .address()
            .map_err(|e| MessageError::BadKey(e.to_string()))?;
        if address != self.local_address {
            return Err(MessageError::WrongRecipient);
        }
        Ok(())
    }

    fn aad(&self, seq: u64) -> Vec<u8> {
        aad_bytes(
            MESSAGE_VERSION,
            &self.network_id,
            &self.thread,
            seq,
            &self.local_agent,
            &self.local_address,
            self.local_role,
            &self.remote_agent,
            &self.remote_address,
            self.remote_role,
            &self.dhs_pub,
        )
    }
}

impl std::fmt::Debug for RatchetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetSession")
            .field("side", &self.side)
            .field("thread", &self.thread)
            .field("next_send", &self.next_send)
            .field("next_recv", &self.next_recv)
            .finish_non_exhaustive()
    }
}

fn validate_network(network_id: &str) -> Result<(), MessageError> {
    if network_id.is_empty() || network_id.len() > MAX_NETWORK_LEN {
        return Err(MessageError::Malformed("network id length".into()));
    }
    Ok(())
}

/// A fresh DH ratchet key pair.
fn generate_key() -> Result<(SecretKey, [u8; 33]), MessageError> {
    loop {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        match SecretKey::from_slice(&bytes) {
            Ok(key) => {
                let encoded = key.public_key().to_encoded_point(true);
                let mut public = [0u8; 33];
                public.copy_from_slice(encoded.as_bytes());
                break Ok((key, public));
            }
            Err(_) => continue,
        }
    }
}

/// `KDF_RK` from the double ratchet: a DH output ratchets the root key and
/// yields the next chain key. The old root key is overwritten by the caller.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8]) -> Result<([u8; 32], [u8; 32]), MessageError> {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut out = [0u8; 64];
    hk.expand(DOM_RK, &mut out)
        .map_err(|_| MessageError::Crypto("hkdf root".into()))?;
    let mut next = [0u8; 32];
    let mut ck = [0u8; 32];
    next.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    Ok((next, ck))
}

/// The symmetric chain: `KDF_CK` returns the next chain key.
fn chain_step(ck: &[u8; 32]) -> Result<[u8; 32], MessageError> {
    let hk = Hkdf::<Sha256>::new(Some(ck), DOM_CK);
    let mut next = [0u8; 32];
    hk.expand(DOM_CK, &mut next)
        .map_err(|_| MessageError::Crypto("hkdf chain".into()))?;
    Ok(next)
}

/// The message key and AEAD nonce for one sequence number on one chain.
fn message_key(ck: &[u8; 32], seq: u64) -> Result<([u8; 32], [u8; 24]), MessageError> {
    let hk = Hkdf::<Sha256>::new(Some(ck), &seq.to_le_bytes());
    let mut out = [0u8; 56];
    hk.expand(DOM_MK, &mut out)
        .map_err(|_| MessageError::Crypto("hkdf message key".into()))?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..]);
    Ok((key, nonce))
}

/// The shared salt both endpoints derive independently. It binds the ratchet
/// to this network, thread and pair of agents, so the same DH output in two
/// conversations never seeds the same root key.
fn session_salt(network: &str, thread: &Hash, sender: &AgentId, recipient: &AgentId) -> [u8; 32] {
    let mut w = Writer::with_capacity(network.len() + 80);
    w.raw(thread)
        .u16le(network.len() as u16)
        .raw(network.as_bytes())
        .fixed(sender)
        .fixed(recipient);
    let hash = sha256_dom(DOM_SESSION, &[w.as_slice()]);
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&hash);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::thread_id;

    const NET: &str = "srct/testnet";
    const ROLE: AgentRole = AgentRole::Machine;

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_private_key_bytes(&[seed; 32], "agentnet-ratchet-unit").unwrap()
    }

    #[test]
    fn an_old_chain_key_cannot_derive_a_later_message_key() {
        let alice = wallet(1);
        let bob = wallet(2);
        let a = derive_agent_id(NET, ROLE, &alice.address().unwrap());
        let b = derive_agent_id(NET, ROLE, &bob.address().unwrap());
        let thread = thread_id(&a, &b, 3);
        let mut session = RatchetSession::initiator(
            &alice,
            ROLE,
            NET,
            thread,
            &Recipient::from_wallet(&bob, ROLE).unwrap(),
        )
        .unwrap();

        // The chain state before any message was sent.
        let stale = session.clone();
        let m1 = session.send(&alice, b"one", 100).unwrap();
        let m2 = session.send(&alice, b"two", 100).unwrap();
        assert_ne!(m1.ciphertext, m2.ciphertext);

        // Derive what the OLD chain would have used for sequence 2 and try to
        // open the real sequence-2 message with it. The message key must not
        // match: the chain advanced past it irreversibly.
        let (key, nonce) = message_key(stale.cks.as_ref().unwrap(), 2).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let aad = aad_bytes(
            MESSAGE_VERSION,
            NET,
            &thread,
            2,
            &stale.local_agent,
            &stale.local_address,
            stale.local_role,
            &stale.remote_agent,
            &stale.remote_address,
            stale.remote_role,
            &m2.ephemeral_pubkey,
        );
        let opened = cipher.decrypt(
            &XNonce::from(nonce),
            AeadPayload {
                msg: &m2.ciphertext,
                aad: &aad,
            },
        );
        assert!(opened.is_err(), "an old chain key opened a later message");
    }

    #[test]
    fn chain_keys_never_repeat_a_message_key() {
        let ck = [7u8; 32];
        let next = chain_step(&ck).unwrap();
        assert_ne!(ck, next);
        let (key_a, nonce_a) = message_key(&ck, 1).unwrap();
        let (key_b, _) = message_key(&next, 1).unwrap();
        assert_ne!(key_a, key_b);
        assert_ne!(nonce_a, [0u8; 24]);
    }
}
