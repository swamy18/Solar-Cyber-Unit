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

use srct_core::agent::AgentId;
use srct_core::hash::Hash;

use crate::message::{MessageEnvelope, MessageError};

/// Default cap on stored envelopes across all threads.
pub const DEFAULT_MAX_MESSAGES: usize = 4096;
/// Default cap on stored envelopes in one thread.
pub const DEFAULT_MAX_PER_THREAD: usize = 256;
/// Cap on tracked `(thread, sender)` replay guards.
pub const MAX_GUARD_ENTRIES: usize = 8192;

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

/// Bounded, replay-safe storage for one recipient agent.
#[derive(Clone, Debug)]
pub struct Mailbox {
    network_id: String,
    owner: AgentId,
    max_messages: usize,
    max_per_thread: usize,
    entries: Vec<MailboxEntry>,
    /// Highest accepted sequence per `(thread, sender)`. Never pruned.
    last_seq: BTreeMap<(Hash, AgentId), u64>,
    /// Stored envelope ids, so a caller can check presence cheaply.
    ids: BTreeSet<Hash>,
    /// Stored count per thread, so the per-thread cap is O(1).
    per_thread: BTreeMap<Hash, usize>,
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
            last_seq: BTreeMap::new(),
            ids: BTreeSet::new(),
            per_thread: BTreeMap::new(),
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
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stored messages in one thread.
    pub fn len_thread(&self, thread: &Hash) -> usize {
        self.per_thread.get(thread).copied().unwrap_or(0)
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

        let key = (envelope.thread, envelope.sender_agent);
        if let Some(last) = self.last_seq.get(&key) {
            if envelope.seq <= *last {
                return Err(MailboxError::Replay);
            }
        } else if self.last_seq.len() >= MAX_GUARD_ENTRIES {
            return Err(MailboxError::GuardFull);
        }
        let in_thread = self.len_thread(&envelope.thread);
        if in_thread >= self.max_per_thread {
            return Err(MailboxError::ThreadFull);
        }
        if self.entries.len() >= self.max_messages {
            return Err(MailboxError::Full);
        }

        let id = envelope.id();
        self.last_seq.insert(key, envelope.seq);
        *self.per_thread.entry(envelope.thread).or_insert(0) += 1;
        self.ids.insert(id);
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

    /// Drop stored messages whose expiry height has passed.
    ///
    /// Returns how many were removed. Sequence guards are kept, so an expired
    /// message cannot be replayed after its expiry was noticed.
    pub fn prune_expired(&mut self, height: u64) -> usize {
        let before = self.entries.len();
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
        let removed = before - kept.len();
        if removed > 0 {
            self.per_thread.clear();
            for entry in &kept {
                *self.per_thread.entry(entry.envelope.thread).or_insert(0) += 1;
            }
        }
        self.entries = kept;
        removed
    }
}
