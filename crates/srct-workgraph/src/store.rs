//! Bounded content-addressed artifact store (non-consensus).
//!
//! The graph holds hashes; this is where the bytes behind them can live for
//! small artifacts. Content lives with its owner in production — this store
//! is the bounded, replay-safe local cache a node keeps beside the graph.
//! Keys are `sha256_dom` of the stored bytes, so a key always names exactly
//! the bytes it returns; there is no separate linking step to get wrong.

use std::collections::BTreeMap;

use srct_core::hash::{sha256_dom, Hash};
use srct_core::ser::{Reader, Writer};

use crate::WorkError;

pub const STORE_VERSION: u8 = 1;
/// Most blobs one store holds. Past the cap the operator archives.
pub const MAX_STORED_BLOBS: usize = 1024;
/// Most bytes one blob may hold. Model weights live with their owner;
/// this cache is for small artifacts (configs, manifests, receipts).
pub const MAX_BLOB_BYTES: usize = 256 * 1024;

const DOM_STORE: &[u8] = b"srct/workgraph/store/v1";

fn blob_key(bytes: &[u8]) -> Hash {
    sha256_dom(DOM_STORE, &[bytes])
}

/// Bounded cache of content-addressed bytes beside the [`crate::WorkGraph`].
#[derive(Clone, Debug, Default)]
pub struct ArtifactStore {
    blobs: BTreeMap<Hash, Vec<u8>>,
}

impl ArtifactStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Store bytes, returning their content key. Idempotent: storing the
    /// same bytes twice returns the same key and stores once.
    pub fn put(&mut self, bytes: Vec<u8>) -> Result<Hash, WorkError> {
        if bytes.is_empty() {
            return Err(WorkError::Malformed("store blob is empty".into()));
        }
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(WorkError::Malformed("store blob is over cap".into()));
        }
        let key = blob_key(&bytes);
        if !self.blobs.contains_key(&key) {
            if self.blobs.len() >= MAX_STORED_BLOBS {
                return Err(WorkError::Malformed("store is full".into()));
            }
            self.blobs.insert(key, bytes);
        }
        Ok(key)
    }

    /// Fetch bytes by content key. A key always returns exactly the bytes
    /// that produced it.
    pub fn get(&self, key: &Hash) -> Option<&[u8]> {
        self.blobs.get(key).map(Vec::as_slice)
    }

    /// Bounded snapshot encoding for restarts.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.blobs.len() * 128);
        w.u8(STORE_VERSION).u32le(self.blobs.len() as u32);
        for bytes in self.blobs.values() {
            w.u32le(bytes.len() as u32).raw(bytes);
        }
        w.into_vec()
    }

    /// Rebuild from a snapshot. Keys are recomputed from the bytes, so a
    /// tampered snapshot fails instead of loading mislabeled content.
    pub fn decode(bytes: &[u8]) -> Result<Self, WorkError> {
        let mut r = Reader::new(bytes);
        let bad = |detail: &str| WorkError::Malformed(format!("store snapshot {detail}"));
        if r.u8().map_err(|_| bad("version is missing"))? != STORE_VERSION {
            return Err(bad("version is unknown"));
        }
        let count = r.u32le().map_err(|_| bad("count is missing"))? as usize;
        if count > MAX_STORED_BLOBS {
            return Err(bad("is over cap"));
        }
        let mut store = ArtifactStore::new();
        for _ in 0..count {
            let len = r.u32le().map_err(|_| bad("blob length is missing"))? as usize;
            if len == 0 || len > MAX_BLOB_BYTES {
                return Err(bad("blob is over cap"));
            }
            let blob = r
                .fixed_slice(len)
                .map_err(|_| bad("blob bytes are missing"))?
                .to_vec();
            let key = blob_key(&blob);
            if store.blobs.contains_key(&key) {
                return Err(bad("holds a duplicate"));
            }
            store.blobs.insert(key, blob);
        }
        r.expect_end().map_err(|_| bad("has trailing bytes"))?;
        Ok(store)
    }
}
