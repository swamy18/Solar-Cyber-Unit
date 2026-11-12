//! Replay-safe, bounded message storage.
//!
//! A mailbox is the recipient-side half of the protocol: it accepts envelopes
//! it can verify but cannot decrypt, and hands them to the owner's wallet later.
//! It never needs key material, which is what lets an untrusted relay host one.
//!
//! The rules are deliberately fail-closed:
//!
//! - every envelope must verify (structure, identity binding, sender signature)
//!   before it is stored;
//! - it must name this mailbox's network and recipient agent, so a relay cannot
//!   dump another agent's traffic here;
//! - it must not be expired at the height it is offered;
//! - `(thread, sender)` sequences must strictly increase, so an exact replay, a
//!   re-signed duplicate sequence and any older message are refused;
//! - total and per-thread occupancy are capped, and a full mailbox refuses new
//!   messages instead of silently evicting an unread one;
//! - the number of tracked sequence slots is capped too, so a sender that
//!   opens unbounded threads cannot grow the guard without bound.
//!
//! # What a mailbox does not prove
//!
//! Strictly increasing sequences assume an ordered per-sender transport (one
//! relay per agent, or the sender retries in order). A message that arrives
//! *after* a higher sequence was accepted is refused rather than buffered; a
//! reordering transport therefore loses messages instead of accepting them out
//! of order. That is the conservative choice: buffering would need unbounded
//! gaps and a separate delivery policy.
//!
//! Draining a thread removes the envelopes but **keeps** the sequence guards,
//! so a drained message cannot be replayed back into the mailbox. Guards are
//! never evicted: when their cap is reached the mailbox refuses new
//! `(thread, sender)` pairs rather than forgetting a sequence it has seen.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::agent::{derive_agent_id, AgentId, MAX_NETWORK_ID_LEN};
use srct_core::hash::Hash;
use srct_core::ser::{Reader, Writer};
use srct_core::wallet::Wallet;

use crate::message::{MessageEnvelope, MessageError};
use crate::sealed::SealedEnvelope;

/// Default cap on stored envelopes across all threads.
pub const DEFAULT_MAX_MESSAGES: usize = 4096;
/// Default cap on stored envelopes in one thread.
pub const DEFAULT_MAX_PER_THREAD: usize = 256;
/// Cap on tracked `(thread, sender)` replay guards.
pub const MAX_GUARD_ENTRIES: usize = 8192;
/// Snapshot version for [`Mailbox`] restart persistence.
pub const MAILBOX_VERSION: u8 = 2;
/// Most entries one snapshot may hold.
pub const MAX_MAILBOX_ENTRIES: usize = 4096;
/// Most bytes one wire envelope may occupy in a snapshot.
pub const MAX_SNAPSHOT_ENVELOPE: usize = 128 * 1024;

/// Why a mailbox refused or could not find a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailboxError {
    /// The envelope itself is invalid.
    Message(MessageError),
    /// The envelope belongs to another network.
    WrongNetwork,
    /// The envelope is addressed to another agent.
    WrongRecipient,
    /// The envelope's expiry height has passed.
    Expired,
    /// This `(thread, sender)` sequence was already consumed.
    Replay,
    /// The stored-message cap is full.
    Full,
    /// The per-thread cap is full.
    ThreadFull,
    /// The replay-guard cap is full; new `(thread, sender)` pairs are refused.
    GuardFull,
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailboxError::Message(e) => write!(f, "{e}"),
            MailboxError::WrongNetwork => write!(f, "message is for another network"),
            MailboxError::WrongRecipient => write!(f, "message is for another recipient"),
            MailboxError::Expired => write!(f, "message has expired"),
            MailboxError::Replay => write!(f, "sequence was already consumed"),
            MailboxError::Full => write!(f, "mailbox is full"),
            MailboxError::ThreadFull => write!(f, "thread is full"),
            MailboxError::GuardFull => write!(f, "replay-guard capacity is full"),
        }
    }
}

impl std::error::Error for MailboxError {}

impl From<MessageError> for MailboxError {
    fn from(e: MessageError) -> Self {
        MailboxError::Message(e)
    }
}

/// One accepted envelope plus the height at which it was accepted.
#[derive(Clone, Debug, PartialEq)]
pub struct MailboxEntry {
    pub envelope: MessageEnvelope,
    pub accepted_height: u64,
}

/// One accepted sealed envelope plus its learned sender and accept height.
///
/// The sender agent is learned at accept time (sealed envelopes name no
/// sender on the wire) and drives the shared `(thread, sender)` guards.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedMailboxEntry {
    pub envelope: SealedEnvelope,
    pub sender_agent: AgentId,
    pub accepted_height: u64,
}

/// Bounded, replay-safe storage for one recipient agent.
#[derive(Clone, Debug)]
pub struct Mailbox {
    network_id: String,
    owner: AgentId,
    max_messages: usize,
    max_per_thread: usize,
    entries: Vec<MailboxEntry>,
    sealed_entries: Vec<SealedMailboxEntry>,
    /// Highest accepted sequence per `(thread, sender)`. Never pruned.
    /// Shared by the normal and sealed paths: one sequence space.
    last_seq: BTreeMap<(Hash, AgentId), u64>,
    /// Stored envelope ids, so a caller can check presence cheaply.
    ids: BTreeSet<Hash>,
    /// Stored count per thread, so the per-thread cap is O(1).
    per_thread: BTreeMap<Hash, usize>,
    /// Stored sealed count per thread.
    sealed_per_thread: BTreeMap<Hash, usize>,
}

impl Mailbox {
    /// A mailbox for `owner` on `network_id` with the default caps.
    pub fn new(network_id: impl Into<String>, owner: AgentId) -> Self {
        Self::with_limits(
            network_id,
            owner,
            DEFAULT_MAX_MESSAGES,
            DEFAULT_MAX_PER_THREAD,
        )
    }

    /// A mailbox with explicit caps. A zero cap refuses every message.
    pub fn with_limits(
        network_id: impl Into<String>,
        owner: AgentId,
        max_messages: usize,
        max_per_thread: usize,
    ) -> Self {
        Mailbox {
            network_id: network_id.into(),
            owner,
            max_messages,
            max_per_thread,
            entries: Vec::new(),
            sealed_entries: Vec::new(),
            last_seq: BTreeMap::new(),
            ids: BTreeSet::new(),
            per_thread: BTreeMap::new(),
            sealed_per_thread: BTreeMap::new(),
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn owner(&self) -> AgentId {
        self.owner
    }

    pub fn max_messages(&self) -> usize {
        self.max_messages
    }

    pub fn max_per_thread(&self) -> usize {
        self.max_per_thread
    }

    pub fn len(&self) -> usize {
        self.entries.len() + self.sealed_entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.sealed_entries.is_empty()
    }

    /// Stored sealed messages.
    pub fn sealed_len(&self) -> usize {
        self.sealed_entries.len()
    }

    /// Stored messages in one thread (normal and sealed combined).
    pub fn len_thread(&self, thread: &Hash) -> usize {
        self.per_thread.get(thread).copied().unwrap_or(0)
            + self.sealed_per_thread.get(thread).copied().unwrap_or(0)
    }

    /// The highest accepted sequence for this sender in this thread.
    pub fn last_seq(&self, thread: &Hash, sender: &AgentId) -> Option<u64> {
        self.last_seq.get(&(*thread, *sender)).copied()
    }

    /// Whether this exact envelope is currently stored.
    pub fn contains(&self, id: &Hash) -> bool {
        self.ids.contains(id)
    }

    /// Verify and store an envelope.
    ///
    /// Returns the envelope id (its signing hash). Expired stored messages are
    /// pruned first, so garbage that aged out cannot make the mailbox look full.
    pub fn accept(&mut self, envelope: MessageEnvelope, height: u64) -> Result<Hash, MailboxError> {
        self.validate_for_mailbox(&envelope, height)?;
        // Expired garbage must not make the mailbox look full. Pruning changes
        // only expired entries, so a refusal still never evicts readable mail.
        self.prune_expired(height);

        let id = envelope.id();
        self.claim_slot(envelope.thread, envelope.sender_agent, envelope.seq, id)?;
        *self.per_thread.entry(envelope.thread).or_insert(0) += 1;
        self.entries.push(MailboxEntry {
            envelope,
            accepted_height: height,
        });
        Ok(id)
    }

    /// Decode a wire envelope and accept it.
    pub fn accept_wire(&mut self, bytes: &[u8], height: u64) -> Result<Hash, MailboxError> {
        let envelope = MessageEnvelope::decode(bytes)?;
        self.accept(envelope, height)
    }

    /// Accept a sealed envelope with the owner's wallet. The wallet decrypts
    /// (learning the sender), verifies the sender signature, and the shared
    /// `(thread, sender)` guards apply exactly as on the normal path.
    ///
    /// Returns the sender agent and the envelope id. Relay-hosted mailboxes
    /// must never call this: without the owner's key there is nothing to
    /// verify against.
    pub fn accept_sealed(
        &mut self,
        bytes: &[u8],
        opener: &Wallet,
        height: u64,
    ) -> Result<(AgentId, Hash), MailboxError> {
        let envelope = SealedEnvelope::decode(bytes)?;
        if envelope.network_id != self.network_id {
            return Err(MailboxError::WrongNetwork);
        }
        if envelope.recipient_agent != self.owner {
            return Err(MailboxError::WrongRecipient);
        }
        if derive_agent_id(
            &envelope.network_id,
            envelope.recipient_role,
            &envelope.recipient_address,
        ) != envelope.recipient_agent
        {
            return Err(MailboxError::Message(MessageError::Malformed(
                "sealed recipient identity does not match its address".into(),
            )));
        }
        if height > envelope.expires_height {
            return Err(MailboxError::Expired);
        }
        let (sender_agent, _body) = envelope.open(opener)?;
        self.prune_expired(height);
        let id = self.store_sealed(envelope, sender_agent, height)?;
        Ok((sender_agent, id))
    }

    /// Shared guard claim for the normal and sealed paths: strictly
    /// increasing `(thread, sender)` sequences, per-thread and total caps.
    /// The caller pushes the entry into its own vec afterwards.
    fn claim_slot(
        &mut self,
        thread: Hash,
        sender: AgentId,
        seq: u64,
        id: Hash,
    ) -> Result<(), MailboxError> {
        let key = (thread, sender);
        if let Some(last) = self.last_seq.get(&key) {
            if seq <= *last {
                return Err(MailboxError::Replay);
            }
        } else if self.last_seq.len() >= MAX_GUARD_ENTRIES {
            return Err(MailboxError::GuardFull);
        }
        if self.len_thread(&thread) >= self.max_per_thread {
            return Err(MailboxError::ThreadFull);
        }
        if self.len() >= self.max_messages {
            return Err(MailboxError::Full);
        }
        self.last_seq.insert(key, seq);
        self.ids.insert(id);
        Ok(())
    }

    fn validate_for_mailbox(
        &self,
        envelope: &MessageEnvelope,
        height: u64,
    ) -> Result<(), MailboxError> {
        envelope.verify()?;
        if envelope.network_id != self.network_id {
            return Err(MailboxError::WrongNetwork);
        }
        if envelope.recipient_agent != self.owner {
            return Err(MailboxError::WrongRecipient);
        }
        if height > envelope.expires_height {
            return Err(MailboxError::Expired);
        }
        Ok(())
    }

    /// Every stored message, ordered by `(thread, sequence, sender)`.
    pub fn messages(&self) -> Vec<&MailboxEntry> {
        let mut out: Vec<&MailboxEntry> = self.entries.iter().collect();
        out.sort_by_key(|e| (e.envelope.thread, e.envelope.seq, e.envelope.sender_agent));
        out
    }

    /// Stored messages in one thread, ordered by `(sequence, sender)`.
    pub fn thread(&self, thread: &Hash) -> Vec<&MailboxEntry> {
        let mut out: Vec<&MailboxEntry> = self
            .entries
            .iter()
            .filter(|e| e.envelope.thread == *thread)
            .collect();
        out.sort_by_key(|e| (e.envelope.seq, e.envelope.sender_agent));
        out
    }

    /// Stored sealed messages in one thread, ordered by `(sequence, sender)`.
    pub fn sealed_thread(&self, thread: &Hash) -> Vec<&SealedMailboxEntry> {
        let mut out: Vec<&SealedMailboxEntry> = self
            .sealed_entries
            .iter()
            .filter(|e| e.envelope.thread == *thread)
            .collect();
        out.sort_by_key(|e| (e.envelope.seq, e.sender_agent));
        out
    }

    /// Remove and return up to `limit` messages from one thread.
    ///
    /// The sequence guards survive, so the returned messages cannot be replayed
    /// into this mailbox afterwards.
    pub fn drain_thread(&mut self, thread: &Hash, limit: usize) -> Vec<MailboxEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let entries = std::mem::take(&mut self.entries);
        let (mut taken, mut kept): (Vec<MailboxEntry>, Vec<MailboxEntry>) = entries
            .into_iter()
            .partition(|e| e.envelope.thread == *thread);
        taken.sort_by_key(|e| (e.envelope.seq, e.envelope.sender_agent));
        if taken.len() > limit {
            let rest = taken.split_off(limit);
            kept.extend(rest);
        }
        let removed = taken.len();
        for entry in &taken {
            self.ids.remove(&entry.envelope.id());
        }
        if let Some(count) = self.per_thread.get_mut(thread) {
            *count = count.saturating_sub(removed);
            if *count == 0 {
                self.per_thread.remove(thread);
            }
        }
        self.entries = kept;
        taken
    }

    /// Remove and return up to `limit` sealed messages from one thread.
    /// Guards survive, exactly as on the normal path.
    pub fn drain_sealed_thread(&mut self, thread: &Hash, limit: usize) -> Vec<SealedMailboxEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let entries = std::mem::take(&mut self.sealed_entries);
        let (mut taken, mut kept): (Vec<SealedMailboxEntry>, Vec<SealedMailboxEntry>) = entries
            .into_iter()
            .partition(|e| e.envelope.thread == *thread);
        taken.sort_by_key(|e| (e.envelope.seq, e.sender_agent));
        if taken.len() > limit {
            let rest = taken.split_off(limit);
            kept.extend(rest);
        }
        let removed = taken.len();
        for entry in &taken {
            self.ids.remove(&entry.envelope.id());
        }
        if let Some(count) = self.sealed_per_thread.get_mut(thread) {
            *count = count.saturating_sub(removed);
            if *count == 0 {
                self.sealed_per_thread.remove(thread);
            }
        }
        self.sealed_entries = kept;
        taken
    }

    /// Drop stored messages whose expiry height has passed.
    ///
    /// Returns how many were removed. Sequence guards are kept, so an expired
    /// message cannot be replayed after its expiry was noticed.
    pub fn prune_expired(&mut self, height: u64) -> usize {
        let before = self.entries.len() + self.sealed_entries.len();
        let entries = std::mem::take(&mut self.entries);
        let kept: Vec<MailboxEntry> = entries
            .into_iter()
            .filter(|e| {
                if height > e.envelope.expires_height {
                    self.ids.remove(&e.envelope.id());
                    false
                } else {
                    true
                }
            })
            .collect();
        let sealed = std::mem::take(&mut self.sealed_entries);
        let kept_sealed: Vec<SealedMailboxEntry> = sealed
            .into_iter()
            .filter(|e| {
                if height > e.envelope.expires_height {
                    self.ids.remove(&e.envelope.id());
                    false
                } else {
                    true
                }
            })
            .collect();
        let removed = before - kept.len() - kept_sealed.len();
        if removed > 0 {
            self.per_thread.clear();
            for entry in &kept {
                *self.per_thread.entry(entry.envelope.thread).or_insert(0) += 1;
            }
            self.sealed_per_thread.clear();
            for entry in &kept_sealed {
                *self
                    .sealed_per_thread
                    .entry(entry.envelope.thread)
                    .or_insert(0) += 1;
            }
        }
        self.entries = kept;
        self.sealed_entries = kept_sealed;
        removed
    }

    /// Bounded snapshot encoding for restarts. Stores the envelopes with the
    /// heights they were accepted at; guards rebuild by replay.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128 + self.entries.len() * 512);
        w.u8(MAILBOX_VERSION)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.owner)
            .u32le(self.max_messages as u32)
            .u32le(self.max_per_thread as u32)
            .u32le(self.entries.len() as u32);
        for entry in &self.entries {
            let bytes = entry.envelope.encode();
            w.u32le(bytes.len() as u32).raw(&bytes);
            w.u64le(entry.accepted_height);
        }
        w.u32le(self.sealed_entries.len() as u32);
        for entry in &self.sealed_entries {
            let bytes = entry.envelope.encode();
            w.u32le(bytes.len() as u32).raw(&bytes);
            w.fixed(&entry.sender_agent);
            w.u64le(entry.accepted_height);
        }
        w.into_vec()
    }

    /// Rebuild from a snapshot. Every envelope decodes through its signature
    /// check and replays through [`Mailbox::accept`] in stored order, so a
    /// tampered snapshot fails instead of loading half a mailbox.
    pub fn decode(bytes: &[u8]) -> Result<Self, MailboxError> {
        let mut r = Reader::new(bytes);
        if r.u8().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })? != MAILBOX_VERSION
        {
            return Err(MailboxError::Message(
                crate::message::MessageError::Malformed("mailbox version is unknown".into()),
            ));
        }
        let net_len = r.u16le().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(MailboxError::Message(
                crate::message::MessageError::Malformed("mailbox network id length".into()),
            ));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })?)
        .map_err(|_| {
            MailboxError::Message(crate::message::MessageError::Malformed(
                "mailbox network is not utf-8".into(),
            ))
        })?
        .to_string();
        let owner: AgentId = r.fixed().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })?;
        let max_messages = r.u32le().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })? as usize;
        let max_per_thread = r.u32le().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })? as usize;
        if max_messages > MAX_MAILBOX_ENTRIES || max_per_thread > MAX_MAILBOX_ENTRIES {
            return Err(MailboxError::Message(
                crate::message::MessageError::Malformed("mailbox caps are over cap".into()),
            ));
        }
        let count = r.u32le().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })? as usize;
        if count > max_messages || count > MAX_MAILBOX_ENTRIES {
            return Err(MailboxError::Message(
                crate::message::MessageError::Malformed("mailbox snapshot is over cap".into()),
            ));
        }
        let mut mailbox = Mailbox::with_limits(network_id, owner, max_messages, max_per_thread);
        for _ in 0..count {
            let len = r.u32le().map_err(|e| {
                MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
            })? as usize;
            if len > MAX_SNAPSHOT_ENVELOPE {
                return Err(MailboxError::Message(
                    crate::message::MessageError::Malformed("mailbox envelope is over cap".into()),
                ));
            }
            let envelope_bytes = r.fixed_slice(len).map_err(|e| {
                MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
            })?;
            let envelope = MessageEnvelope::decode(envelope_bytes)?;
            let accepted_height = r.u64le().map_err(|e| {
                MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
            })?;
            mailbox.accept(envelope, accepted_height)?;
        }
        let sealed_count = r.u32le().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })? as usize;
        if sealed_count > max_messages || sealed_count > MAX_MAILBOX_ENTRIES {
            return Err(MailboxError::Message(
                crate::message::MessageError::Malformed("mailbox snapshot is over cap".into()),
            ));
        }
        for _ in 0..sealed_count {
            let len = r.u32le().map_err(|e| {
                MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
            })? as usize;
            if len > MAX_SNAPSHOT_ENVELOPE {
                return Err(MailboxError::Message(
                    crate::message::MessageError::Malformed("mailbox envelope is over cap".into()),
                ));
            }
            let envelope_bytes = r.fixed_slice(len).map_err(|e| {
                MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
            })?;
            // Structure-only: the opener's key is what authenticates a sealed
            // envelope, and a restart must not need it. Guards replay exactly;
            // authenticity re-checks on `open`.
            let envelope = SealedEnvelope::decode(envelope_bytes)?;
            let sender_agent: AgentId = r.fixed().map_err(|e| {
                MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
            })?;
            let accepted_height = r.u64le().map_err(|e| {
                MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
            })?;
            mailbox.prune_expired(accepted_height);
            mailbox.store_sealed(envelope, sender_agent, accepted_height)?;
        }
        r.expect_end().map_err(|e| {
            MailboxError::Message(crate::message::MessageError::Malformed(e.to_string()))
        })?;
        Ok(mailbox)
    }

    /// Guard-and-store replay for a structurally decoded sealed envelope.
    /// Used by snapshot restore (no key available) and by [`Mailbox::accept_sealed`]
    /// after cryptography — one guard path, not two.
    fn store_sealed(
        &mut self,
        envelope: SealedEnvelope,
        sender_agent: AgentId,
        accepted_height: u64,
    ) -> Result<Hash, MailboxError> {
        if envelope.network_id != self.network_id {
            return Err(MailboxError::WrongNetwork);
        }
        if envelope.recipient_agent != self.owner {
            return Err(MailboxError::WrongRecipient);
        }
        if accepted_height > envelope.expires_height {
            return Err(MailboxError::Expired);
        }
        let id = envelope.id();
        self.claim_slot(envelope.thread, sender_agent, envelope.seq, id)?;
        *self.sealed_per_thread.entry(envelope.thread).or_insert(0) += 1;
        self.sealed_entries.push(SealedMailboxEntry {
            envelope,
            sender_agent,
            accepted_height,
        });
        Ok(id)
    }
}
