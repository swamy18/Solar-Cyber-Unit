//! Tokenizer-level input adapters (non-consensus).
//!
//! A [`TokenizerMap`] is a signed vote table from a source tokenizer to a
//! target tokenizer, fitted from paired token id sequences. For every aligned
//! position the pair `(source, target)` casts one vote; each source token maps
//! to its most-voted target (ties break toward the smallest target id, so the
//! fit is deterministic). `coverage` reports the fraction of training
//! positions the winning map reproduces — a low number is the map telling on
//! itself, not a passing grade.
//!
//! Honest limits: alignment is positional — pair `i` must tokenize the same
//! text under both tokenizers with position `i` corresponding. Different
//! segmentations need a real aligner first; fitting one on misaligned pairs
//! yields a low-coverage map, which is exactly what `coverage` is for. Unknown
//! source tokens refuse instead of guessing.

use std::collections::BTreeMap;

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::Writer;
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

pub const TOKEN_MAP_VERSION: u8 = 1;
/// Most entries one map may hold. Vocabularies are large; a map is a focused
/// bridge, not a full vocabulary dump.
pub const MAX_MAP_ENTRIES: usize = 65_536;
/// Most token ids one pair may carry per side.
pub const MAX_PAIR_TOKENS: usize = 4096;
const DOM_TOKEN_MAP: &[u8] = b"srct/cnnp/token-map/v1";

/// A signed source-tokenizer to target-tokenizer vote table.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenizerMap {
    pub version: u8,
    /// Tokenizer identity the source ids belong to (a `ModelSpace.tokenizer`).
    pub source_tok: Hash,
    /// Tokenizer identity the target ids belong to.
    pub target_tok: Hash,
    /// Source token id to target token id, by positional vote.
    pub entries: BTreeMap<u32, u32>,
    /// Paired sequences the votes were counted from.
    pub samples: u32,
    /// Fraction of training positions the winning map reproduces, in [0, 1].
    pub coverage: f32,
    /// Address that fitted and signed the map.
    pub trainer: Address,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl TokenizerMap {
    /// Fit and sign a map from paired token id sequences.
    pub fn fit(
        source_tok: Hash,
        target_tok: Hash,
        pairs: &[(Vec<u32>, Vec<u32>)],
        trainer: &Wallet,
    ) -> Result<Self, String> {
        if pairs.is_empty() {
            return Err("tokenizer fit needs at least one paired sequence".into());
        }
        let mut votes: BTreeMap<(u32, u32), u64> = BTreeMap::new();
        let mut total: u64 = 0;
        for (i, (src, tgt)) in pairs.iter().enumerate() {
            if src.len() > MAX_PAIR_TOKENS || tgt.len() > MAX_PAIR_TOKENS {
                return Err(format!("pair {i} is over the token cap"));
            }
            for (s, t) in src.iter().zip(tgt.iter()) {
                *votes.entry((*s, *t)).or_insert(0) += 1;
                total += 1;
            }
        }
        if total == 0 {
            return Err("tokenizer fit saw no aligned positions".into());
        }
        // Per source token, the most-voted target wins; ties go to the
        // smallest target id so the fit is deterministic.
        let mut best: BTreeMap<u32, (u32, u64)> = BTreeMap::new();
        for ((s, t), n) in &votes {
            let entry = best.entry(*s).or_insert((*t, 0));
            if *n > entry.1 || (*n == entry.1 && *t < entry.0) {
                *entry = (*t, *n);
            }
        }
        let mut entries = BTreeMap::new();
        let mut hits: u64 = 0;
        for (s, (t, _)) in &best {
            entries.insert(*s, *t);
        }
        for ((s, t), n) in &votes {
            if best.get(s).is_some_and(|(w, _)| w == t) {
                hits += *n;
            }
        }
        if entries.len() > MAX_MAP_ENTRIES {
            return Err("tokenizer map is over the entry cap".into());
        }
        let address = trainer.address().map_err(|e| e.to_string())?;
        let mut map = TokenizerMap {
            version: TOKEN_MAP_VERSION,
            source_tok,
            target_tok,
            entries,
            samples: pairs.len() as u32,
            coverage: (hits as f64 / total as f64) as f32,
            trainer: address,
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        if !map.coverage.is_finite() || map.coverage < 0.0 || map.coverage > 1.0 {
            return Err("tokenizer coverage is out of range".into());
        }
        let auth = Auth::sign(trainer, &map.hash()).map_err(|e| e.to_string())?;
        map.sigs = auth.sigs;
        map.keys = auth.keys;
        Ok(map)
    }

    /// Translate one source token id. Unknown ids refuse instead of guessing.
    pub fn translate_token(&self, source: u32) -> Result<u32, String> {
        self.entries
            .get(&source)
            .copied()
            .ok_or_else(|| format!("tokenizer map has no entry for source token {source}"))
    }

    /// Translate a sequence, refusing on the first unknown token.
    pub fn translate(&self, tokens: &[u32]) -> Result<Vec<u32>, String> {
        tokens.iter().map(|t| self.translate_token(*t)).collect()
    }

    /// Exact-match rate of the map on held-out pairs: fraction of aligned
    /// positions reproduced exactly.
    pub fn heldout_exact_match(&self, pairs: &[(Vec<u32>, Vec<u32>)]) -> Result<f32, String> {
        if pairs.is_empty() {
            return Err("evaluation needs at least one pair".into());
        }
        let mut hits: u64 = 0;
        let mut total: u64 = 0;
        for (src, tgt) in pairs {
            for (s, t) in src.iter().zip(tgt.iter()) {
                total += 1;
                if self.entries.get(s).is_some_and(|w| w == t) {
                    hits += 1;
                }
            }
        }
        if total == 0 {
            return Err("evaluation saw no aligned positions".into());
        }
        Ok((hits as f64 / total as f64) as f32)
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_TOKEN_MAP, &[&self.encode_unsigned()])
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.version != TOKEN_MAP_VERSION {
            return Err(format!("unsupported token map version {}", self.version));
        }
        if self.entries.len() > MAX_MAP_ENTRIES {
            return Err("token map is over the entry cap".into());
        }
        if self.samples == 0 {
            return Err("token map claims zero training pairs".into());
        }
        if !self.coverage.is_finite() || self.coverage < 0.0 || self.coverage > 1.0 {
            return Err("token map coverage is out of range".into());
        }
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.trainer {
            return Err("token map key bundle is not the trainer".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.hash())
            .map_err(|_| "token map signature invalid".to_string())
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128 + self.entries.len() * 8);
        w.u8(self.version)
            .fixed(&self.source_tok)
            .fixed(&self.target_tok)
            .u32le(self.samples)
            .u32le(self.coverage.to_bits())
            .fixed(&self.trainer)
            .u32le(self.entries.len() as u32);
        for (s, t) in &self.entries {
            w.u32le(*s).u32le(*t);
        }
        w.into_vec()
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = self.encode_unsigned();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(body.len() + sigs.len() + keys.len() + 16);
        w.u32le(body.len() as u32)
            .raw(&body)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        use srct_core::ser::Reader;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("token map over the size cap".into());
        }
        let mut r = Reader::new(bytes);
        let body_len = r.u32le().map_err(|e| format!("token map: {e}"))? as usize;
        if body_len > 4 * 1024 * 1024 {
            return Err("token map: body over cap".into());
        }
        let mut br = Reader::new(
            r.fixed_slice(body_len)
                .map_err(|e| format!("token map: {e}"))?,
        );
        let version = br.u8().map_err(|e| format!("token map: {e}"))?;
        let source_tok: Hash = br.fixed().map_err(|e| format!("token map: {e}"))?;
        let target_tok: Hash = br.fixed().map_err(|e| format!("token map: {e}"))?;
        let samples = br.u32le().map_err(|e| format!("token map: {e}"))?;
        let coverage = f32::from_bits(br.u32le().map_err(|e| format!("token map: {e}"))?);
        let trainer: Address = br.fixed().map_err(|e| format!("token map: {e}"))?;
        let count = br.u32le().map_err(|e| format!("token map: {e}"))? as usize;
        if count > MAX_MAP_ENTRIES {
            return Err("token map: entry count over cap".into());
        }
        let mut entries = BTreeMap::new();
        let mut prev: Option<u32> = None;
        for _ in 0..count {
            let s = br.u32le().map_err(|e| format!("token map: {e}"))?;
            let t = br.u32le().map_err(|e| format!("token map: {e}"))?;
            // Canonical order: source ids strictly increasing on the wire.
            if prev.is_some_and(|p| s <= p) {
                return Err("token map: entries are not sorted".into());
            }
            prev = Some(s);
            entries.insert(s, t);
        }
        br.expect_end().map_err(|e| format!("token map: {e}"))?;
        let sigs_len = r.u32le().map_err(|e| format!("token map: {e}"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err("token map: signature bundle over cap".into());
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|e| format!("token map: {e}"))?,
        )
        .map_err(|e| format!("token map: {e}"))?;
        let keys_len = r.u32le().map_err(|e| format!("token map: {e}"))? as usize;
        if keys_len > 8 * 1024 {
            return Err("token map: key bundle over cap".into());
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|e| format!("token map: {e}"))?,
        )
        .map_err(|e| format!("token map: {e}"))?;
        r.expect_end().map_err(|e| format!("token map: {e}"))?;
        let map = TokenizerMap {
            version,
            source_tok,
            target_tok,
            entries,
            samples,
            coverage,
            trainer,
            sigs,
            keys,
        };
        map.verify()?;
        Ok(map)
    }
}
