//! Transport-agnostic delivery for agent envelopes.
//!
//! Envelopes and mailboxes are bytes; moving them is the operator's rail
//! (P2P, HTTP, MCP). This module defines the narrow seam between the two: a
//! [`Transport`] queues wire bytes per recipient and delivers them into a
//! [`crate::mailbox::Mailbox`]. [`LoopbackTransport`] is the in-memory
//! reference: tests and single-host relays use it directly, network rails
//! implement the same two calls.

use std::collections::VecDeque;

use srct_core::agent::AgentId;
use srct_core::hash::Hash;

use crate::mailbox::Mailbox;

/// Queue wire envelopes for recipients, deliver them into mailboxes.
pub trait Transport {
    /// Queue wire bytes for `to`. No verification happens here.
    fn send(&mut self, to: &AgentId, bytes: Vec<u8>);
    /// Move every packet queued for this mailbox's owner into it.
    ///
    /// Returns `(accepted, refused)` envelope ids and counts. A refused
    /// packet never blocks the packets behind it.
    fn deliver(&mut self, mailbox: &mut Mailbox, height: u64) -> (Vec<Hash>, usize);
}

/// In-memory reference transport. Single-host relays and tests use it
/// directly; network rails mirror its two calls over their own links.
#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    queue: VecDeque<(AgentId, Vec<u8>)>,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Collect every packet queued for `to`, in send order. Anything else
    /// stays queued. Non-mailbox payloads (gossip batches, receipts) travel
    /// the same queue; the caller decodes its own bytes.
    pub fn receive(&mut self, to: &AgentId) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut kept = VecDeque::new();
        for (addr, bytes) in std::mem::take(&mut self.queue) {
            if addr == *to {
                out.push(bytes);
            } else {
                kept.push_back((addr, bytes));
            }
        }
        self.queue = kept;
        out
    }
}

impl Transport for LoopbackTransport {
    fn send(&mut self, to: &AgentId, bytes: Vec<u8>) {
        self.queue.push_back((*to, bytes));
    }

    fn deliver(&mut self, mailbox: &mut Mailbox, height: u64) -> (Vec<Hash>, usize) {
        let mut accepted = Vec::new();
        let mut refused = 0usize;
        let mut kept = VecDeque::new();
        for (to, bytes) in std::mem::take(&mut self.queue) {
            if to != mailbox.owner() {
                kept.push_back((to, bytes));
                continue;
            }
            match mailbox.accept_wire(&bytes, height) {
                Ok(id) => accepted.push(id),
                Err(_) => refused += 1,
            }
        }
        self.queue = kept;
        (accepted, refused)
    }
}
