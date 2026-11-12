//! Decentralized end-to-end encrypted messaging for SRCT agents (non-consensus).
//!
//! AI agents need a private channel that no relay, peer or chain observer can
//! read. This crate is the protocol core:
//!
//! - [`message`]: network/role-bound agent identities, per-message ephemeral
//!   ECDH, HKDF-SHA256 key derivation, XChaCha20-Poly1305 encryption, and a
//!   hybrid signature over the whole envelope.
//! - [`ratchet`]: double-ratchet sessions over the same envelope format,
//!   giving forward secrecy and post-compromise security for ordered
//!   conversation threads.
//! - [`mailbox`]: bounded, replay-safe storage that verifies envelopes without
//!   being able to decrypt them, so an untrusted relay can host it.
//!
//! # Threat model
//!
//! Hidden from everyone except the recipient's wallet:
//!
//! - the plaintext and the plaintext length (only the ciphertext length is
//!   visible, padded only by the caller);
//! - the per-message key: a fresh ephemeral key and nonce mean one message's
//!   key cannot decrypt another.
//!
//! Visible by design in this version:
//!
//! - sender and recipient agent identities, roles and addresses;
//! - thread id, sequence number, expiry height and ciphertext size.
//!
//! Not provided yet:
//!
//! - **sealed sender**: the sender identity is in the envelope, so a relay
//!   learns the conversation graph;
//! - **group messaging**: a thread is a pairwise conversation. Groups need a
//!   sender-key or MLS layer;
//! - **transport**: envelopes and mailboxes are byte formats. Moving them is
//!   the operator's P2P/HTTP/MCP rail;
//! - **online delivery**: a mailbox is passive storage. Push, presence and
//!   multi-device fan-out are not implemented.
//!
//! # Consensus
//!
//! Nothing here can mint, move, slash or finalize anything. The crate depends on
//! `srct-core` only for keys, signatures and hashing, and it changes no
//! consensus rule.

pub mod mailbox;
pub mod message;
pub mod ratchet;

pub use mailbox::{
    Mailbox, MailboxEntry, MailboxError, DEFAULT_MAX_MESSAGES, DEFAULT_MAX_PER_THREAD,
    MAX_GUARD_ENTRIES,
};
pub use message::{
    thread_id, MessageEnvelope, MessageError, Recipient, MAX_CIPHERTEXT, MAX_NETWORK_LEN,
    MAX_PLAINTEXT, MESSAGE_VERSION,
};
pub use ratchet::{RatchetSession, SessionSide};
