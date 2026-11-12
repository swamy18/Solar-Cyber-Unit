//! Presence, delivery acknowledgements and multi-device fan-out (non-consensus).
//!
//! The transport routes bytes per agent; devices are what actually poll. A
//! [`PresenceBook`] records each `(agent, device)` heartbeat with a
//! time-to-live, so a relay knows which devices are live without tracking
//! anything else. Fan-out is then explicit: [`fanout_targets`] lists the
//! live devices for an agent, and the operator sends one copy per device
//! queue. [`AckSet`] records envelope ids the recipient confirmed, so a
//! sender (or relay) can stop retrying without trusting the network.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::agent::AgentId;
use srct_core::hash::Hash;

/// Most devices one agent may register. Past the cap the oldest heartbeat
/// must be pruned by the operator before new ones register.
pub const MAX_DEVICES_PER_AGENT: usize = 16;
/// Longest device label, in bytes.
pub const MAX_DEVICE_LABEL: usize = 64;

/// `(agent, device)` liveness with heartbeat heights.
#[derive(Clone, Debug, Default)]
pub struct PresenceBook {
    devices: BTreeMap<AgentId, BTreeMap<String, u64>>,
}

impl PresenceBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Heartbeat from `device` for `agent` at `height`. Replaces any older
    /// heartbeat from the same device label.
    pub fn heartbeat(
        &mut self,
        agent: AgentId,
        device: impl Into<String>,
        height: u64,
    ) -> Result<(), String> {
        let device = device.into();
        if device.is_empty() || device.len() > MAX_DEVICE_LABEL {
            return Err("device label length is bad".into());
        }
        let entry = self.devices.entry(agent).or_default();
        if !entry.contains_key(&device) && entry.len() >= MAX_DEVICES_PER_AGENT {
            return Err("agent device set is full".into());
        }
        entry.insert(device, height);
        Ok(())
    }

    /// Live device labels for `agent`: heartbeat within `ttl` heights of
    /// `height`, sorted for determinism.
    pub fn devices_for(&self, agent: &AgentId, height: u64, ttl: u64) -> Vec<String> {
        self.devices
            .get(agent)
            .map(|devices| {
                let mut out: Vec<String> = devices
                    .iter()
                    .filter(|(_, last)| height.saturating_sub(**last) <= ttl)
                    .map(|(label, _)| label.clone())
                    .collect();
                out.sort();
                out
            })
            .unwrap_or_default()
    }

    /// Drop heartbeats older than `ttl` at `height`. Returns removals.
    /// Empty agents are removed, so the book cannot fill with ghosts.
    pub fn prune(&mut self, height: u64, ttl: u64) -> usize {
        let mut removed = 0;
        let mut empty = Vec::new();
        for (agent, devices) in self.devices.iter_mut() {
            devices.retain(|_, last| {
                let live = height.saturating_sub(*last) <= ttl;
                if !live {
                    removed += 1;
                }
                live
            });
            if devices.is_empty() {
                empty.push(*agent);
            }
        }
        for agent in empty {
            self.devices.remove(&agent);
        }
        removed
    }
}

/// Device queues a fan-out targets: one `(agent, device)` copy each.
/// The operator maps each pair onto its own transport queue.
pub fn fanout_targets(agent: &AgentId, devices: &[String]) -> Vec<(AgentId, String)> {
    devices.iter().map(|d| (*agent, d.clone())).collect()
}

/// Confirmed envelope ids. Recording an ack is idempotent; only the first
/// confirmation of an id returns `true`.
#[derive(Clone, Debug, Default)]
pub struct AckSet {
    acked: BTreeSet<Hash>,
    order: Vec<Hash>,
}

impl AckSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.acked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.acked.is_empty()
    }

    pub fn is_acked(&self, id: &Hash) -> bool {
        self.acked.contains(id)
    }

    pub fn ack(&mut self, id: Hash) -> bool {
        if self.acked.insert(id) {
            self.order.push(id);
            true
        } else {
            false
        }
    }

    /// Acked ids in confirmation order.
    pub fn acked_in_order(&self) -> &[Hash] {
        &self.order
    }
}
