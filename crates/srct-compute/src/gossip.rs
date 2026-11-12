//! Transport-agnostic offer gossip: what to forward, what to drop.
//!
//! Offers move over whatever rail the operator runs (HTTP, MCP, an on-chain
//! record). This module defines the forwarding rules so every participant
//! converges on the same live set without trusting the relay: only signed,
//! live offers for this network are kept; duplicates, expired and forged
//! offers are dropped, never forwarded. Merging is deterministic — the same
//! batch in any order yields the same set.
//!
//! What this is not: a transport. There is no socket, timer or peer table
//! here. Liveness, retries and peer scoring are the operator's job.

use std::collections::BTreeMap;

use srct_core::hash::Hash;

use crate::market::SignedOffer;
use crate::ComputeError;

/// Most offers one gossip set holds. Past the cap the operator prunes
/// expired offers first ([`GossipSet::prune`]); new valid offers are refused
/// rather than silently evicting live ones.
pub const MAX_GOSSIP_OFFERS: usize = 1_024;

/// The live offer set for one network, as learned through gossip.
#[derive(Clone, Debug, Default)]
pub struct GossipSet {
    network_id: String,
    offers: BTreeMap<Hash, SignedOffer>,
}

impl GossipSet {
    pub fn new(network_id: impl Into<String>) -> Self {
        GossipSet {
            network_id: network_id.into(),
            offers: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.offers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.offers.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.offers.contains_key(hash)
    }

    /// All live offers, sorted by hash for deterministic consumers.
    pub fn offers(&self) -> Vec<&SignedOffer> {
        self.offers.values().collect()
    }

    /// Insert one offer. Verifies the signature, network and liveness;
    /// duplicates return `Ok(false)` and are never re-broadcast.
    pub fn insert(&mut self, offer: SignedOffer, height: u64) -> Result<bool, ComputeError> {
        offer.verify()?;
        if offer.offer.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if offer.offer.available_until < height {
            return Err(ComputeError::Expired);
        }
        if self.offers.contains_key(&offer.hash()) {
            return Ok(false);
        }
        if self.offers.len() >= MAX_GOSSIP_OFFERS {
            return Err(ComputeError::Malformed(
                "gossip set is full: prune first".into(),
            ));
        }
        self.offers.insert(offer.hash(), offer);
        Ok(true)
    }

    /// Merge a batch from a peer. Invalid, expired and duplicate offers are
    /// skipped individually; the rest merge deterministically regardless of
    /// batch order. Returns the number of newly added offers.
    pub fn merge(&mut self, batch: Vec<SignedOffer>, height: u64) -> usize {
        let mut added = 0;
        let mut batch: Vec<SignedOffer> = batch;
        batch.sort_by_key(|a| a.hash());
        batch.dedup_by(|a, b| a.hash() == b.hash());
        for offer in batch {
            if self.insert(offer, height).unwrap_or(false) {
                added += 1;
            }
        }
        added
    }

    /// Drop offers expired at `height`. Returns the number removed.
    pub fn prune(&mut self, height: u64) -> usize {
        let before = self.offers.len();
        self.offers
            .retain(|_, offer| offer.offer.available_until >= height);
        before - self.offers.len()
    }
}
