//! Solver discovery and quote gossip (non-consensus).
//!
//! Discovery is a transport buffer, not admission: solvers advertise
//! liveness, peers exchange signed quote batches, and every quote is
//! re-verified on decode and re-validated when it enters
//! [`crate::IntentBook::quote`]. A relay can neither forge a solver nor
//! inflate a price — the signatures would fail at merge time, and the book
//! re-checks caps, routes and deadlines at accept time anyway.

use std::collections::BTreeMap;

use srct_core::hash::{Address, Hash};
use srct_core::ser::{Reader, Writer};

use crate::book::IntentError;
use crate::types::SignedQuote;

pub const QUOTE_BATCH_VERSION: u8 = 1;
/// Most quotes one gossip batch may carry.
pub const MAX_GOSSIP_QUOTES: usize = 256;
/// Most bytes one batch may occupy on the wire.
pub const MAX_BATCH_BYTES: usize = 256 * 1024;

/// Encode live quotes for one gossip packet. Every quote carries its own
/// signature; the batch adds none.
pub fn encode_quote_batch(quotes: &[&SignedQuote]) -> Result<Vec<u8>, IntentError> {
    let bad = |detail: &str| IntentError::BadSignature(detail.into());
    if quotes.len() > MAX_GOSSIP_QUOTES {
        return Err(bad("quote batch is over cap"));
    }
    let mut w = Writer::with_capacity(64 + quotes.len() * 512);
    w.u8(QUOTE_BATCH_VERSION).u32le(quotes.len() as u32);
    for quote in quotes {
        let bytes = quote.encode();
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(bad("quote is over cap"));
        }
        w.u32le(bytes.len() as u32).raw(&bytes);
    }
    let out = w.into_vec();
    if out.len() > MAX_BATCH_BYTES {
        return Err(bad("quote batch is over cap"));
    }
    Ok(out)
}

/// Decode a batch from [`encode_quote_batch`]. Every quote decodes through
/// its signature check, so tampered bytes fail the whole batch instead of
/// merging half a peer's gossip.
pub fn decode_quote_batch(bytes: &[u8]) -> Result<Vec<SignedQuote>, IntentError> {
    let bad = |detail: &str| IntentError::BadSignature(detail.into());
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(bad("quote batch is over cap"));
    }
    let mut r = Reader::new(bytes);
    if r.u8().map_err(|_| bad("version is missing"))? != QUOTE_BATCH_VERSION {
        return Err(bad("version is unknown"));
    }
    let count = r.u32le().map_err(|_| bad("count is missing"))? as usize;
    if count > MAX_GOSSIP_QUOTES {
        return Err(bad("quote batch is over cap"));
    }
    let mut quotes = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.u32le().map_err(|_| bad("quote length is missing"))? as usize;
        if len == 0 || len > MAX_BATCH_BYTES {
            return Err(bad("quote is over cap"));
        }
        let blob = r
            .fixed_slice(len)
            .map_err(|_| bad("quote bytes are missing"))?;
        quotes.push(SignedQuote::decode(blob).map_err(|_| bad("quote is invalid"))?);
    }
    r.expect_end()
        .map_err(|_| bad("batch has trailing bytes"))?;
    Ok(quotes)
}

/// Known solvers and their gossiped quotes, keyed by intent.
#[derive(Clone, Debug, Default)]
pub struct SolverDirectory {
    network_id: String,
    solvers: BTreeMap<Address, u64>,
    quotes: BTreeMap<Hash, BTreeMap<Address, SignedQuote>>,
}

impl SolverDirectory {
    pub fn new(network_id: impl Into<String>) -> Self {
        SolverDirectory {
            network_id: network_id.into(),
            solvers: BTreeMap::new(),
            quotes: BTreeMap::new(),
        }
    }

    pub fn solver_count(&self) -> usize {
        self.solvers.len()
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn is_known(&self, solver: &Address) -> bool {
        self.solvers.contains_key(solver)
    }

    /// Advertise liveness. Records the solver with its latest heartbeat;
    /// unknown solvers become known here or on first merged quote.
    pub fn advertise(&mut self, solver: Address, height: u64) {
        self.solvers.insert(solver, height);
    }

    /// Merge a gossiped batch. Each quote is signature-checked by decode;
    /// quotes for another intent hash still merge (keyed by their own
    /// intent) — admission stays with `IntentBook::quote`, which re-checks
    /// caps, routes and deadlines. Returns newly added quotes.
    pub fn merge_batch(&mut self, bytes: &[u8], height: u64) -> Result<usize, IntentError> {
        let mut added = 0;
        for quote in decode_quote_batch(bytes)? {
            if quote.quote.valid_until_height < height {
                continue;
            }
            self.solvers.insert(quote.quote.solver, height);
            let entry = self.quotes.entry(quote.quote.intent).or_default();
            if entry.insert(quote.quote.solver, quote).is_none() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Live quotes gossiped for one intent, cheapest first by solver address
    /// order (ranking across assets is the book's `best_quote` job).
    pub fn quotes_for(&self, intent: &Hash) -> Vec<&SignedQuote> {
        self.quotes
            .get(intent)
            .map(|m| m.values().collect())
            .unwrap_or_default()
    }

    /// Drop quotes expired at `height`. Returns the number removed. Solver
    /// liveness is heartbeat state, not pruned here.
    pub fn prune(&mut self, height: u64) -> usize {
        let mut removed = 0;
        let mut empty = Vec::new();
        for (intent, quotes) in self.quotes.iter_mut() {
            quotes.retain(|_, q| {
                let live = q.quote.valid_until_height >= height;
                if !live {
                    removed += 1;
                }
                live
            });
            if quotes.is_empty() {
                empty.push(*intent);
            }
        }
        for intent in empty {
            self.quotes.remove(&intent);
        }
        removed
    }
}
