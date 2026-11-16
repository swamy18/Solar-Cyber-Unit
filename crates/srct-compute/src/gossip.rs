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
use crate::ticket::SignedTicket;
use crate::ComputeError;

/// Most offers one gossip set holds. Past the cap the operator prunes
/// expired offers first ([`GossipSet::prune`]); new valid offers are refused
/// rather than silently evicting live ones.
pub const MAX_GOSSIP_OFFERS: usize = 1_024;

/// Most tickets one gossip set holds.
pub const MAX_GOSSIP_TICKETS: usize = 1_024;

/// The live offer set for one network, as learned through gossip.
#[derive(Clone, Debug, Default)]
pub struct GossipSet {
    network_id: String,
    offers: BTreeMap<Hash, SignedOffer>,
}

/// The live ticket set for one network, as learned through gossip.
///
/// Tickets are demand announcements: a requester posts a ticket, it is
/// gossiped to connected nodes, and any capable provider auto-claims. The
/// same rules as offers apply — signed, live, deduplicated, size bounded —
/// plus a rate limit on insertions per peer.
#[derive(Clone, Debug, Default)]
pub struct TicketGossipSet {
    network_id: String,
    tickets: BTreeMap<Hash, SignedTicket>,
    /// Insertion count per peer address for rate limiting (test hook;
    /// production keys this by the peer id the transport assigns).
    insertions: BTreeMap<Hash, u32>,
}

/// Rate limit: max ticket insertions per peer per gossip round.
const MAX_TICKET_INSERTS_PER_PEER: u32 = 10;

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

impl TicketGossipSet {
    pub fn new(network_id: impl Into<String>) -> Self {
        TicketGossipSet {
            network_id: network_id.into(),
            tickets: BTreeMap::new(),
            insertions: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.tickets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.tickets.contains_key(hash)
    }

    /// All live tickets, sorted by hash for deterministic consumers.
    pub fn tickets(&self) -> Vec<&SignedTicket> {
        self.tickets.values().collect()
    }

    /// Insert one ticket. Verifies the signature, network and liveness;
    /// duplicates return `Ok(false)` and are never re-broadcast. Rate limited
    /// per peer by `peer_hash`.
    pub fn insert(
        &mut self,
        ticket: SignedTicket,
        height: u64,
        peer_hash: Hash,
    ) -> Result<bool, ComputeError> {
        ticket.verify()?;
        if ticket.ticket.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if height > ticket.ticket.deadline {
            return Err(ComputeError::Expired);
        }
        if self.tickets.contains_key(&ticket.hash()) {
            return Ok(false);
        }
        let count = self.insertions.entry(peer_hash).or_insert(0);
        if *count >= MAX_TICKET_INSERTS_PER_PEER {
            return Err(ComputeError::Malformed(
                "ticket gossip rate limit exceeded".into(),
            ));
        }
        if self.tickets.len() >= MAX_GOSSIP_TICKETS {
            return Err(ComputeError::Malformed(
                "ticket gossip set is full: prune first".into(),
            ));
        }
        *count += 1;
        self.tickets.insert(ticket.hash(), ticket);
        Ok(true)
    }

    /// Merge a batch from a peer. Invalid, expired and duplicate tickets are
    /// skipped individually; the rest merge deterministically regardless of
    /// batch order. Returns the number of newly added tickets.
    pub fn merge(&mut self, batch: Vec<SignedTicket>, height: u64, peer_hash: Hash) -> usize {
        let mut added = 0;
        let mut batch: Vec<SignedTicket> = batch;
        batch.sort_by_key(|a| a.hash());
        batch.dedup_by(|a, b| a.hash() == b.hash());
        for ticket in batch {
            if self.insert(ticket, height, peer_hash).unwrap_or(false) {
                added += 1;
            }
        }
        added
    }

    /// Drop tickets expired at `height`. Returns the number removed.
    pub fn prune(&mut self, height: u64) -> usize {
        let before = self.tickets.len();
        self.tickets
            .retain(|_, ticket| ticket.ticket.deadline >= height);
        before - self.tickets.len()
    }
}

/// Wire version for [`encode_batch`].
pub const GOSSIP_BATCH_VERSION: u8 = 1;
/// Most bytes one batch may carry. Offers are small and signed; a bigger
/// batch is two batches.
pub const MAX_BATCH_BYTES: usize = 256 * 1024;

/// Encode live offers for one transport packet. The batch carries only
/// signed bytes; the receiver re-verifies every offer through
/// [`GossipSet::merge`], so a relay can neither forge nor inflate.
pub fn encode_batch(offers: &[&SignedOffer]) -> Result<Vec<u8>, ComputeError> {
    use srct_core::ser::Writer;
    if offers.len() > MAX_GOSSIP_OFFERS {
        return Err(ComputeError::Malformed("gossip batch is over cap".into()));
    }
    let mut w = Writer::with_capacity(64 + offers.len() * 256);
    w.u8(GOSSIP_BATCH_VERSION).u32le(offers.len() as u32);
    for offer in offers {
        let bytes = offer.encode();
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(ComputeError::Malformed("gossip offer is over cap".into()));
        }
        w.u32le(bytes.len() as u32).raw(&bytes);
    }
    let out = w.into_vec();
    if out.len() > MAX_BATCH_BYTES {
        return Err(ComputeError::Malformed("gossip batch is over cap".into()));
    }
    Ok(out)
}

/// Decode a batch produced by [`encode_batch`]. Every offer decodes through
/// its signature check, so tampered bytes fail the whole batch instead of
/// merging half a peer's set.
pub fn decode_batch(bytes: &[u8]) -> Result<Vec<SignedOffer>, ComputeError> {
    use srct_core::ser::Reader;
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(ComputeError::Malformed("gossip batch is over cap".into()));
    }
    let mut r = Reader::new(bytes);
    let bad = |detail: &str| ComputeError::Malformed(format!("gossip batch {detail}"));
    if r.u8().map_err(|_| bad("version is missing"))? != GOSSIP_BATCH_VERSION {
        return Err(bad("version is unknown"));
    }
    let count = r.u32le().map_err(|_| bad("count is missing"))? as usize;
    if count > MAX_GOSSIP_OFFERS {
        return Err(bad("is over cap"));
    }
    let mut offers = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.u32le().map_err(|_| bad("offer length is missing"))? as usize;
        if len == 0 || len > MAX_BATCH_BYTES {
            return Err(bad("offer is over cap"));
        }
        let blob = r
            .fixed_slice(len)
            .map_err(|_| bad("offer bytes are missing"))?;
        offers.push(SignedOffer::decode(blob)?);
    }
    r.expect_end().map_err(|_| bad("has trailing bytes"))?;
    Ok(offers)
}

/// Encode live tickets for one transport packet.
pub fn encode_ticket_batch(tickets: &[&SignedTicket]) -> Result<Vec<u8>, ComputeError> {
    use srct_core::ser::Writer;
    if tickets.len() > MAX_GOSSIP_TICKETS {
        return Err(ComputeError::Malformed(
            "ticket gossip batch is over cap".into(),
        ));
    }
    let mut w = Writer::with_capacity(64 + tickets.len() * 256);
    w.u8(GOSSIP_BATCH_VERSION).u32le(tickets.len() as u32);
    for ticket in tickets {
        let bytes = ticket.encode();
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(ComputeError::Malformed(
                "ticket gossip ticket is over cap".into(),
            ));
        }
        w.u32le(bytes.len() as u32).raw(&bytes);
    }
    let out = w.into_vec();
    if out.len() > MAX_BATCH_BYTES {
        return Err(ComputeError::Malformed(
            "ticket gossip batch is over cap".into(),
        ));
    }
    Ok(out)
}

/// Decode a batch produced by [`encode_ticket_batch`].
pub fn decode_ticket_batch(bytes: &[u8]) -> Result<Vec<SignedTicket>, ComputeError> {
    use srct_core::ser::Reader;
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(ComputeError::Malformed(
            "ticket gossip batch is over cap".into(),
        ));
    }
    let mut r = Reader::new(bytes);
    let bad = |detail: &str| ComputeError::Malformed(format!("ticket gossip batch {detail}"));
    if r.u8().map_err(|_| bad("version is missing"))? != GOSSIP_BATCH_VERSION {
        return Err(bad("version is unknown"));
    }
    let count = r.u32le().map_err(|_| bad("count is missing"))? as usize;
    if count > MAX_GOSSIP_TICKETS {
        return Err(bad("is over cap"));
    }
    let mut tickets = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.u32le().map_err(|_| bad("ticket length is missing"))? as usize;
        if len == 0 || len > MAX_BATCH_BYTES {
            return Err(bad("ticket is over cap"));
        }
        let blob = r
            .fixed_slice(len)
            .map_err(|_| bad("ticket bytes are missing"))?;
        tickets.push(SignedTicket::decode(blob)?);
    }
    r.expect_end().map_err(|_| bad("has trailing bytes"))?;
    Ok(tickets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Determinism;
    use crate::market::Verification;
    use crate::ticket::{ClaimTicket, SignedTicket, TICKET_VERSION};
    use srct_core::wallet::Wallet;

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_private_key_bytes(&[seed; 32], "gossip-test").unwrap()
    }

    fn ticket(
        requester: &Wallet,
        units: u32,
        price: u64,
        deadline: u64,
        nonce: u64,
        provider: Option<srct_core::hash::Address>,
    ) -> SignedTicket {
        SignedTicket::sign(
            ClaimTicket {
                version: TICKET_VERSION,
                network_id: "srct/testnet".into(),
                requester: requester.address().unwrap(),
                job: [9u8; 32],
                shard: 0,
                units,
                unit_price_sat: price,
                total_sat: units as u64 * price,
                min_ram_mib: 512,
                min_units_per_sec: 100,
                min_bandwidth_kbps: 0,
                determinism: Determinism::Reproducible,
                required_kernel: [0u8; 32],
                min_verification: Verification::Receipt,
                sealed_input: false,
                input: [3u8; 32],
                deadline,
                nonce,
                provider,
            },
            requester,
        )
        .unwrap()
    }

    #[test]
    fn ticket_insert_verifies_dedups_and_enforces_ttl() {
        let requester = wallet(1);
        let mut set = TicketGossipSet::new("srct/testnet");
        let t = ticket(&requester, 10, 5, 100, 1, None);
        let peer = [1u8; 32];

        assert_eq!(set.insert(t.clone(), 5, peer), Ok(true));
        // Duplicate insert returns Ok(false) and is never re-broadcast.
        assert_eq!(set.insert(t.clone(), 5, peer), Ok(false));
        assert!(set.contains(&t.hash()));

        // Expired tickets are refused (TTL = deadline).
        assert_eq!(
            set.insert(ticket(&requester, 10, 5, 100, 2, None), 101, peer),
            Err(ComputeError::Expired)
        );

        // Wrong network is refused.
        let mut other = t.clone();
        other.ticket.network_id = "srct/mainnet".into();
        assert!(set.insert(other, 5, peer).is_err());

        // Forged signatures are refused.
        let mut forged = t.clone();
        forged.ticket.units = 99;
        assert!(forged.verify().is_err());
    }

    #[test]
    fn ticket_rate_limit_per_peer() {
        let requester = wallet(1);
        let mut set = TicketGossipSet::new("srct/testnet");
        let peer = [2u8; 32];
        for i in 1..=super::MAX_TICKET_INSERTS_PER_PEER {
            let t = ticket(&requester, 10, 5, 100, i as u64, None);
            assert_eq!(set.insert(t, 5, peer), Ok(true));
        }
        // The 11th insert from the same peer is refused.
        let overflow = ticket(&requester, 10, 5, 100, 999, None);
        assert_eq!(
            set.insert(overflow, 5, peer),
            Err(ComputeError::Malformed(
                "ticket gossip rate limit exceeded".into()
            ))
        );
        // A different peer still has its own budget.
        let other = ticket(&requester, 10, 5, 100, 1000, None);
        assert_eq!(set.insert(other, 5, [3u8; 32]), Ok(true));
    }

    #[test]
    fn ticket_merge_deterministic_and_prunes_expired() {
        let requester = wallet(1);
        let mut set = TicketGossipSet::new("srct/testnet");
        let a = ticket(&requester, 10, 5, 50, 1, None);
        let b = ticket(&requester, 10, 5, 200, 2, None);
        let batch = vec![b.clone(), a.clone(), b.clone()];
        assert_eq!(set.merge(batch, 5, [1u8; 32]), 2);
        assert_eq!(set.merge(vec![a.clone()], 5, [2u8; 32]), 0);
        assert_eq!(set.prune(51), 1);
        assert!(set.contains(&b.hash()));
        assert!(!set.contains(&a.hash()));
    }

    #[test]
    fn ticket_batch_roundtrip_and_size_bound() {
        let requester = wallet(1);
        let a = ticket(&requester, 10, 5, 100, 1, None);
        let b = ticket(&requester, 20, 5, 100, 2, None);
        let bytes = encode_ticket_batch(&[&a, &b]).unwrap();
        let decoded = decode_ticket_batch(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].hash(), a.hash());
        assert_eq!(decoded[1].hash(), b.hash());

        // Tampered bytes fail the whole batch.
        let mut bad = bytes.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(decode_ticket_batch(&bad).is_err());
        // Empty version and trailing bytes fail closed.
        assert!(decode_ticket_batch(&[]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert!(decode_ticket_batch(&trailing).is_err());
    }
}
