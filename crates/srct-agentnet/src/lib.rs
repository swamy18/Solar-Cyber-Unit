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
//!   being able to decrypt them, so an untrusted relay can host it, with a
//!   bounded snapshot encoding for restarts.
//! - [`padding`]: opt-in length hiding to five fixed buckets.
//! - [`transport`]: the delivery seam plus an in-memory loopback reference.
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
//! - **sealed-sender relay hosting**: sealed envelopes verify recipient-side
//!   only ([`sealed`]), so an untrusted relay can route but never host them.
//! - **group key agreement**: groups use creator-distributed sender keys
//!   ([`groups`]); MLS-style agreement is a later milestone.
//! - **network sockets**: [`transport`] is the delivery seam with an
//!   in-memory reference, [`http`] the wire codecs and [`presence`] the
//!   liveness book. P2P/HTTP/MCP sockets, push and multi-device fan-out
//!   daemons are the operator's.
//!
//! # Consensus
//!
//! Nothing here can mint, move, slash or finalize anything. The crate depends on
//! `srct-core` only for keys, signatures and hashing, and it changes no
//! consensus rule.

pub mod groups;
pub mod http;
pub mod mailbox;
pub mod message;
pub mod mls;
pub mod padding;
pub mod presence;
pub mod ratchet;
pub mod sealed;
pub mod transport;

pub use groups::{
    GroupError, GroupMessage, GroupSession, GroupSync, GROUP_VERSION, MAX_GROUP_BODY,
    MAX_GROUP_MEMBERS,
};
pub use http::{
    DeliverRequest, DeliverResponse, PollRequest, PollResponse, HTTP_CODEC_VERSION,
    MAX_POLL_MESSAGES, MAX_TRANSPORT_BODY,
};
pub use mailbox::{
    Mailbox, MailboxEntry, MailboxError, SealedMailboxEntry, DEFAULT_MAX_MESSAGES,
    DEFAULT_MAX_PER_THREAD, MAILBOX_VERSION, MAX_GUARD_ENTRIES, MAX_MAILBOX_ENTRIES,
};
pub use message::{
    thread_id, MessageEnvelope, MessageError, Recipient, MAX_CIPHERTEXT, MAX_NETWORK_LEN,
    MAX_PLAINTEXT, MESSAGE_VERSION,
};
pub use mls::{
    Commit, KeyPackage, LeafKey, Member, MlsError, MlsGroup, MlsMessage, Proposal, MAX_MLS_BODY,
    MAX_MLS_MEMBERS, MLS_VERSION,
};
pub use presence::{fanout_targets, AckSet, PresenceBook, MAX_DEVICES_PER_AGENT, MAX_DEVICE_LABEL};
pub use ratchet::{RatchetSession, SessionSide};
pub use sealed::{SealedEnvelope, MAX_SEALED_BLOB, SEALED_VERSION};
