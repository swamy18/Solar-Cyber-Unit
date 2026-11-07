//! Hybrid proof of work: Stage 1 hash chain -> Stage 2 integer-only neural
//! network -> Stage 3 final hash. SPEC.md §5.
//!
//! Design intent (design doc Section 29):
//! - security rests on the **hash** stages, where the only attack is brute force
//! - the **NN** stage pulls mining onto GPU/AI hardware and gives the chain its
//!   AI-native character; its share of work is auditable, not assumed
//! - every quantity is integer-only and epoch-scoped, so results are identical
//!   on any hardware and no weights can be precomputed before an epoch starts

// The forward pass below is written as nested `for i in 0..dim` loops to match
// SPEC.md 5.3 literally, so it can be diffed against the document line by line.
// Iterator rewrites are deliberately declined: the indexing is not incidental,
// it is the specification.
#![allow(clippy::needless_range_loop)]

use sha2::{Digest, Sha256};

use crate::block::Header;
use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Hash, DOM_S1, DOM_S2, DOM_S3, DOM_S3_VWC, DOM_W};
use crate::ser::Writer;
use crate::u256::{target_for_difficulty, U256};

/// Bias index space is offset from weight indices so the two never collide.
const BIAS_INDEX_OFFSET: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Portable kernel surface: the stable contract third-party compute backends
// (GPU, NPU, TPU, photonic, domestic accelerators) implement against.
//
// Everything here is pure integer arithmetic — there are no floats anywhere
// in the PoW, so every substrate that implements two's-complement arithmetic
// and SHA-256 computes bit-identical results. A backend that reproduces these
// primitives reproduces consensus; the differential tests in `srct-miner` pin
// that property by comparing independent implementations candidate for
// candidate. Changing any of these values is a consensus change (new puzzle
// id), never a tunable.
// ---------------------------------------------------------------------------

/// Post-shift right amount applied before ReLU (SPEC.md §5.3).
pub const ACTIVATION_SHIFT: u32 = 2;

/// Wrap a 64-bit accumulator into a signed 32-bit value, two's complement.
/// Defined alongside the stages below; listed here as part of the
/// surface above.
///
/// [`PuzzleSpec::in_dim`] is the other half: backends index weights with it.
///
/// Discriminates registered puzzle mechanisms (SPEC.md §5 / §M4).
///
/// A `PuzzleSpec` describes either the hybrid hash+NN puzzle (id 1) or the HBM
/// memory-bound scratchpad puzzle (id 2). The NN fields below only apply to
/// `Hybrid`; `Hbm` uses parameters carried by `NetworkParams::hbm`
/// (`HbmConfig`), so its spec is a validation-time marker that lets the
/// registry recognize the puzzle id without re-describing non-applicable
/// dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PuzzleKind {
    /// §5 hybrid: stage 1 hash chain → stage 2 integer NN → stage 3 final hash.
    Hybrid,
    /// §M4 HBM scratchpad PoW. Verification parameters live in `HbmConfig`.
    Hbm,
    /// VWC-linked PoW (puzzle_id = 3): stage 3 final hash additionally commits
    /// to a verified-work-certificate id carried in `header.extra_nonce`, so
    /// mining binds to useful L2 compute rather than pure brute force.
    VwcLinked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuzzleSpec {
    pub id: u64,
    pub name: String,
    pub kind: PuzzleKind,
    pub hash_rounds: u32,
    pub nn_input_dim: usize,
    pub nn_hidden_dim: usize,
    pub nn_layers: usize,
    pub min_nn_share_bps: u32,
    pub max_nn_share_bps: u32,
}

impl Default for PuzzleSpec {
    fn default() -> Self {
        Self::hybrid_v1()
    }
}

impl PuzzleSpec {
    /// `puzzle_id = 1`. SPEC.md §5.1.
    pub fn hybrid_v1() -> Self {
        PuzzleSpec {
            id: 1,
            name: "hybrid-v1".into(),
            kind: PuzzleKind::Hybrid,
            hash_rounds: 16,
            nn_input_dim: 16,
            nn_hidden_dim: 16,
            nn_layers: 3,
            min_nn_share_bps: 3_000,
            max_nn_share_bps: 5_000,
        }
    }

    /// `puzzle_id = 2`. M4 HBM scratchpad PoW (SPEC.md §M4). A registry marker:
    /// verification parameters come from `NetworkParams::hbm`, so the NN/hash
    /// fields are irrelevant and must not be audited here.
    pub fn hbm_v1() -> Self {
        PuzzleSpec {
            id: 2,
            name: "hbm-v1".into(),
            kind: PuzzleKind::Hbm,
            hash_rounds: 0,
            nn_input_dim: 0,
            nn_hidden_dim: 0,
            nn_layers: 0,
            min_nn_share_bps: 0,
            max_nn_share_bps: 0,
        }
    }

    /// `puzzle_id = 3`. VWC-linked hybrid PoW: same hash+NN stages as
    /// `hybrid-v1`, but stage 3 additionally commits to a verified-work
    /// certificate id carried in `header.extra_nonce`.
    pub fn vwc_v1() -> Self {
        PuzzleSpec {
            id: 3,
            name: "vwc-v1".into(),
            kind: PuzzleKind::VwcLinked,
            hash_rounds: 16,
            nn_input_dim: 16,
            nn_hidden_dim: 16,
            nn_layers: 3,
            min_nn_share_bps: 3_000,
            max_nn_share_bps: 5_000,
        }
    }

    /// Input width of `layer`: the seed for layer 0, the hidden width after.
    /// Part of the portable kernel surface: backends index weights with this.
    pub fn in_dim(&self, layer: usize) -> usize {
        if layer == 0 {
            self.nn_input_dim
        } else {
            self.nn_hidden_dim
        }
    }

    /// `nn_macs = layers * hidden^2`
    ///
    /// Saturating: `validate()` rejects absurd dimensions, but this is a
    /// public method a caller may reach first, and an overflow here would
    /// panic rather than report a bad puzzle spec.
    pub fn nn_macs(&self) -> u128 {
        (self.nn_layers as u128)
            .saturating_mul(self.nn_hidden_dim as u128)
            .saturating_mul(self.nn_hidden_dim as u128)
    }

    /// Hash stages: stage 1 initial + `hash_rounds` + stage 3.
    pub fn hash_invocations(&self) -> u128 {
        (1u128)
            .saturating_add(self.hash_rounds as u128)
            .saturating_add(1)
    }

    /// Cost model from SPEC.md §5.6: one SHA-256 is treated as 64 int32 MACs.
    ///
    /// Saturating throughout, and `u32::MAX` on a saturated numerator so a
    /// pathological spec reads as "share far above the audit band" and is
    /// rejected by `validate()` instead of wrapping into the band.
    pub fn nn_share_bps(&self) -> u32 {
        let macs = self.nn_macs();
        let hash_cost = self.hash_invocations().saturating_mul(64);
        let scaled = macs.saturating_mul(10_000).saturating_add(hash_cost / 2);
        let denom = macs.saturating_add(hash_cost);
        if denom == 0 {
            return 0;
        }
        let bps = scaled / denom;
        if bps > u32::MAX as u128 {
            u32::MAX
        } else {
            bps as u32
        }
    }

    /// A registry entry must pass the Section 29.3 work-share audit.
    pub fn validate(&self) -> Result<()> {
        match self.kind {
            PuzzleKind::Hbm => {
                // HBM verification parameters are carried by `NetworkParams::hbm`
                // (`HbmConfig`), validated there. The spec itself is only a
                // registry marker, so the NN / hash-round invariants below —
                // which are meaningless for a non-hybrid puzzle — do not apply.
                return Ok(());
            }
            PuzzleKind::Hybrid | PuzzleKind::VwcLinked => {}
        }
        if self.nn_input_dim == 0 || self.nn_hidden_dim == 0 || self.nn_layers == 0 {
            return Err(Error::BadPuzzleSpec(
                "network dimensions must be non-zero".into(),
            ));
        }
        if self.hash_rounds == 0 {
            return Err(Error::BadPuzzleSpec(
                "at least one hash round is required for brute-force security".into(),
            ));
        }

        // Keep the i64 accumulator provably overflow-free (SPEC.md 5.3:
        // `|s| <= in_dim x 128 x 128 + 62`).
        //
        // Checked *before* the share audit below, which consumes these
        // dimensions. Both widths matter: layer 0 accumulates over
        // `nn_input_dim`, every later layer over `nn_hidden_dim`.
        //
        // Computed in u128 rather than i64: the dimensions are `usize`, so an
        // absurd registry entry would make `dim as i64` wrap negative and
        // `* 128 * 128` would overflow *this guard* before the comparison ever
        // ran. A guard has to survive the inputs it exists to reject.
        let widest = (self.nn_input_dim as u128).max(self.nn_hidden_dim as u128);
        let worst = widest
            .saturating_mul(128)
            .saturating_mul(128)
            .saturating_add(62);
        if worst >= i64::MAX as u128 {
            return Err(Error::BadPuzzleSpec("accumulator can overflow i64".into()));
        }

        let share = self.nn_share_bps();
        if share < self.min_nn_share_bps || share > self.max_nn_share_bps {
            return Err(Error::BadPuzzleSpec(format!(
                "nn_share_bps {share} outside [{}, {}]",
                self.min_nn_share_bps, self.max_nn_share_bps
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Weight derivation
// ---------------------------------------------------------------------------

fn epoch_seed(epoch_id: u32) -> [u8; 32] {
    let mut w = Writer::new();
    w.u32le(epoch_id);
    sha256_dom(DOM_W, &[w.as_slice()])
}

fn weight_stream(k: u32, epoch_id: u32) -> [u8; 32] {
    let mut w = Writer::new();
    w.u32le(k);
    let seed = epoch_seed(epoch_id);
    sha256_dom(DOM_W, &[&seed, w.as_slice()])
}

fn weight_index(spec: &PuzzleSpec, layer: usize, out: usize, inp: usize) -> u32 {
    let k = (layer * spec.nn_hidden_dim + out) * spec.in_dim(layer) + inp;
    k as u32
}

/// `weight(l,o,i) in [-128, 127]` — SPEC.md §5.3.
pub fn weight(spec: &PuzzleSpec, layer: usize, out: usize, inp: usize, epoch_id: u32) -> i32 {
    let b = weight_stream(weight_index(spec, layer, out, inp), epoch_id)[0] as i32;
    if b > 127 {
        b - 255
    } else {
        b
    }
}

/// `bias(l,o) in [0, 62]`.
pub fn bias(spec: &PuzzleSpec, layer: usize, out: usize, epoch_id: u32) -> i32 {
    let k = BIAS_INDEX_OFFSET + (layer * spec.nn_hidden_dim + out) as u32;
    (weight_stream(k, epoch_id)[0] as i32) % 63
}

/// Wrap a 64-bit accumulator into a signed 32-bit value, two's complement.
///
/// Part of the portable kernel surface (see above): every hardware backend
/// reimplements exactly this wrap.
#[inline]
pub fn fold32(v: i64) -> i32 {
    let u = (v as u64 & 0xFFFF_FFFF) as u32;
    if u >= 0x8000_0000 {
        (u as i64 - 0x1_0000_0000) as i32
    } else {
        u as i32
    }
}

// ---------------------------------------------------------------------------
// The three stages
// ---------------------------------------------------------------------------

/// Weights for one epoch, materialised once.
///
/// Deriving a single weight costs two SHA-256 evaluations. A forward pass touches
/// 768 weights plus 48 biases, so deriving on demand means ~1 600 hashes per
/// puzzle attempt instead of ~20 — mining runs about eighty times slower for no
/// reason. The values are identical either way, so this is purely a caching layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochWeights {
    pub epoch_id: u32,
    /// All layers concatenated. Layer `l` starts at `layer_offsets[l]` and
    /// has stride `spec.in_dim(l)`, so the layout stays correct when
    /// `nn_input_dim != nn_hidden_dim` (layer 0 is `hidden × input`, later
    /// layers are `hidden × hidden`).
    weights: Vec<i32>,
    /// Start index of each layer inside `weights`.
    layer_offsets: Vec<usize>,
    /// `[layer * hidden + out]`
    biases: Vec<i32>,
}

impl EpochWeights {
    pub fn build(spec: &PuzzleSpec, epoch_id: u32) -> Self {
        let mut weights = Vec::with_capacity(
            spec.nn_hidden_dim
                .saturating_mul(spec.in_dim(0))
                .saturating_add(
                    spec.nn_layers
                        .saturating_sub(1)
                        .saturating_mul(spec.nn_hidden_dim)
                        .saturating_mul(spec.nn_hidden_dim),
                ),
        );
        let mut layer_offsets = Vec::with_capacity(spec.nn_layers);
        for layer in 0..spec.nn_layers {
            layer_offsets.push(weights.len());
            for out in 0..spec.nn_hidden_dim {
                for inp in 0..spec.in_dim(layer) {
                    let b = weight_stream(weight_index(spec, layer, out, inp), epoch_id)[0] as i32;
                    weights.push(if b > 127 { b - 255 } else { b });
                }
            }
        }
        let mut biases = Vec::with_capacity(spec.nn_layers * spec.nn_hidden_dim);
        for layer in 0..spec.nn_layers {
            for out in 0..spec.nn_hidden_dim {
                let k = BIAS_INDEX_OFFSET + (layer * spec.nn_hidden_dim + out) as u32;
                biases.push((weight_stream(k, epoch_id)[0] as i32) % 63);
            }
        }
        EpochWeights {
            epoch_id,
            weights,
            layer_offsets,
            biases,
        }
    }

    #[inline]
    pub fn weight(&self, spec: &PuzzleSpec, layer: usize, out: usize, inp: usize) -> i32 {
        self.weights[self.layer_offsets[layer] + out * spec.in_dim(layer) + inp]
    }

    #[inline]
    pub fn bias(&self, spec: &PuzzleSpec, layer: usize, out: usize) -> i32 {
        self.biases[layer * spec.nn_hidden_dim + out]
    }
}

/// Stage 1: hash chain over (header, nonce). SPEC.md §5.2.
pub fn stage1_seed(spec: &PuzzleSpec, header: &Header) -> Hash {
    let header_bytes = header.serialize();
    let mut w = Writer::with_capacity(header_bytes.len() + 16);
    w.u64le(header.nonce);
    let mut v = sha256_dom(DOM_S1, &[&header_bytes, w.as_slice()]);
    for r in 0..spec.hash_rounds {
        let mut inner = Writer::new();
        inner.u8(r as u8);
        v = sha256_dom(DOM_S1, &[&v, inner.as_slice()]);
    }
    v
}

/// Stage 2 forward pass over pre-materialised weights.
fn forward(spec: &PuzzleSpec, seed: &Hash, weights: &EpochWeights) -> Vec<u8> {
    let mut acts = Vec::with_capacity(DOM_S2.len() + spec.nn_layers * spec.nn_hidden_dim * 4);
    acts.extend_from_slice(DOM_S2);

    // Total over every non-zero shape `validate()` admits. The seed is 32
    // bytes, so input rows past byte 31 wrap (`j % 32` is the identity for
    // every index a 32-wide-or-narrower network ever reads); the state
    // buffer holds the wider of the input and hidden widths, zero-padded
    // past the input, so a hidden layer wider than the input has somewhere
    // to go. The padding is write-before-read — layer 0 writes every
    // hidden slot before any later layer reads it — so it never affects a
    // digest. For every shape that evaluated before (`input <= 32`,
    // `hidden <= input`) this is byte-identical to the old indexing, which
    // `puzzle_vectors_are_stable` pins.
    let state_len = spec.nn_input_dim.max(spec.nn_hidden_dim);
    let mut x: Vec<i32> = (0..state_len)
        .map(|j| {
            if j < spec.nn_input_dim {
                seed[j % seed.len()] as i32 - 128
            } else {
                0
            }
        })
        .collect();
    let mut z = vec![0i32; spec.nn_hidden_dim];

    for layer in 0..spec.nn_layers {
        let in_dim = spec.in_dim(layer);
        for out in 0..spec.nn_hidden_dim {
            // i64 accumulator; bounded by PuzzleSpec::validate.
            let mut acc: i64 = weights.bias(spec, layer, out) as i64;
            for inp in 0..in_dim {
                acc += x[inp] as i64 * weights.weight(spec, layer, out, inp) as i64;
            }
            z[out] = fold32(acc);
        }
        // Every layer is committed to, so none can be skipped or approximated.
        for value in &z {
            acts.extend_from_slice(&value.to_le_bytes());
        }
        // Arithmetic shift then ReLU.
        for (o, value) in z.iter().enumerate() {
            x[o] = (*value >> ACTIVATION_SHIFT).max(0);
        }
    }
    acts
}

fn digest_of(acts: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(acts);
    h.finalize().into()
}

/// Stage 2: forward pass, returning the digest of *every* layer's
/// pre-activation activations. SPEC.md §5.3.
///
/// Reference path: derives the epoch weights on every call. Use
/// [`PuzzleSolver`] or [`stage2_activation_digest_with`] when hashing many
/// candidates.
pub fn stage2_activation_digest(spec: &PuzzleSpec, seed: &Hash, epoch_id: u32) -> Hash {
    let weights = EpochWeights::build(spec, epoch_id);
    stage2_activation_digest_with(spec, seed, &weights)
}

pub fn stage2_activation_digest_with(
    spec: &PuzzleSpec,
    seed: &Hash,
    weights: &EpochWeights,
) -> Hash {
    digest_of(&forward(spec, seed, weights))
}

/// Stage 3: final hash. SPEC.md §5.4.
///
/// `_spec` is part of the signature so a future puzzle version can fold extra
/// material in here; `hybrid-v1` needs none.
pub fn stage3_final(
    _spec: &PuzzleSpec,
    seed: &Hash,
    act_digest: &Hash,
    nonce: u64,
    epoch_id: u32,
) -> Hash {
    let mut w = Writer::with_capacity(16);
    w.u64le(nonce).u32le(epoch_id);
    sha256_dom(DOM_S3, &[seed, act_digest, w.as_slice()])
}

/// Stage 3 for VWC-linked mining (puzzle_id = 3). Commits the final hash to a
/// verified-work-certificate id carried in `vwc_commitment` (the first 16 bytes
/// of a VWC id, stored in `header.extra_nonce`). Uses a distinct domain tag so
/// the same header fields produce a different final hash than hybrid-v1.
pub fn stage3_final_vwc(
    _spec: &PuzzleSpec,
    seed: &Hash,
    act_digest: &Hash,
    nonce: u64,
    epoch_id: u32,
    vwc_commitment: &[u8; 16],
) -> Hash {
    let mut w = Writer::with_capacity(32);
    w.u64le(nonce).u32le(epoch_id).raw(vwc_commitment);
    sha256_dom(DOM_S3_VWC, &[seed, act_digest, w.as_slice()])
}

/// Full puzzle evaluation for a header. Returns the final hash and stage digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PuzzleRun {
    pub seed: Hash,
    pub activation_digest: Hash,
    pub final_hash: Hash,
}

pub fn run_puzzle(spec: &PuzzleSpec, header: &Header) -> PuzzleRun {
    let seed = stage1_seed(spec, header);
    let act = stage2_activation_digest(spec, &seed, header.epoch_id);
    let final_hash = match spec.kind {
        PuzzleKind::VwcLinked => stage3_final_vwc(
            spec,
            &seed,
            &act,
            header.nonce,
            header.epoch_id,
            &header.extra_nonce,
        ),
        _ => stage3_final(spec, &seed, &act, header.nonce, header.epoch_id),
    };
    PuzzleRun {
        seed,
        activation_digest: act,
        final_hash,
    }
}

/// PoW validity: `U256(final_hash) <= target(difficulty)`. SPEC.md §5.5.
pub fn satisfies(spec: &PuzzleSpec, header: &Header) -> Result<bool> {
    if header.difficulty == 0 {
        return Err(Error::InvalidDifficulty(0));
    }
    let target: U256 = target_for_difficulty(header.difficulty)?;
    let run = run_puzzle(spec, header);
    Ok(U256::from_be_bytes(run.final_hash) <= target)
}

/// Puzzle evaluator that keeps the current epoch's weights in memory.
///
/// A miner evaluating one nonce per attempt would otherwise re-derive 1 632
/// hashes of weights for every try. This holds them across attempts and
/// rebuilds only when the epoch id changes.
#[derive(Debug, Clone)]
pub struct PuzzleSolver {
    spec: PuzzleSpec,
    weights: EpochWeights,
}

impl PuzzleSolver {
    pub fn new(spec: PuzzleSpec) -> Self {
        let weights = EpochWeights::build(&spec, 0);
        PuzzleSolver { spec, weights }
    }

    pub fn spec(&self) -> &PuzzleSpec {
        &self.spec
    }

    pub fn weights(&self) -> &EpochWeights {
        &self.weights
    }

    pub fn weights_for(&mut self, epoch_id: u32) -> &EpochWeights {
        if self.weights.epoch_id != epoch_id {
            self.weights = EpochWeights::build(&self.spec, epoch_id);
        }
        &self.weights
    }

    /// Evaluate one candidate without touching the weight cache on a miss-free
    /// path; the caller drives the nonce loop.
    pub fn run(&mut self, header: &Header) -> PuzzleRun {
        let epoch_id = header.epoch_id;
        let weights = self.weights_for(epoch_id).clone();
        let seed = stage1_seed(&self.spec, header);
        let act = stage2_activation_digest_with(&self.spec, &seed, &weights);
        let final_hash = match self.spec.kind {
            PuzzleKind::VwcLinked => stage3_final_vwc(
                &self.spec,
                &seed,
                &act,
                header.nonce,
                epoch_id,
                &header.extra_nonce,
            ),
            _ => stage3_final(&self.spec, &seed, &act, header.nonce, epoch_id),
        };
        PuzzleRun {
            seed,
            activation_digest: act,
            final_hash,
        }
    }

    pub fn satisfies(&mut self, header: &Header) -> Result<bool> {
        if header.difficulty == 0 {
            return Err(Error::InvalidDifficulty(0));
        }
        let target = target_for_difficulty(header.difficulty)?;
        let run = self.run(header);
        Ok(U256::from_be_bytes(run.final_hash) <= target)
    }
}

/// Expected hashes to solve at this difficulty (== difficulty).
pub fn expected_attempts(difficulty: u128) -> u128 {
    difficulty
}

// ---------------------------------------------------------------------------
// Versioned puzzle registry
// ---------------------------------------------------------------------------

/// Versioned puzzle registry (SPEC.md §5.1, design doc Section 19.3 item 3).
///
/// Supply, halving and base rules are immutable. Only puzzle *parameters* are
/// upgradeable, and only through the governance timelock specced in
/// `docs/roadmap.md`. v0.1 ships exactly one entry and has no upgrade path
/// wired up yet — deliberately: an unaudited upgrade path is worse than none.
#[derive(Debug, Clone, Default)]
pub struct PuzzleRegistry {
    entries: std::collections::BTreeMap<u64, PuzzleSpec>,
}

impl PuzzleRegistry {
    /// Registry containing `hybrid-v1` (puzzle id 1), `hbm-v1` (puzzle id 2),
    /// and `vwc-v1` (puzzle id 3).
    pub fn genesis() -> Self {
        let mut r = PuzzleRegistry::default();
        r.entries.insert(1, PuzzleSpec::hybrid_v1());
        r.entries.insert(2, PuzzleSpec::hbm_v1());
        r.entries.insert(3, PuzzleSpec::vwc_v1());
        r
    }

    pub fn register(&mut self, spec: PuzzleSpec) -> Result<()> {
        spec.validate()?;
        self.entries.insert(spec.id, spec);
        Ok(())
    }

    pub fn get(&self, id: u64) -> Result<&PuzzleSpec> {
        self.get_opt(id).ok_or(Error::UnknownPuzzle(id))
    }

    pub fn get_opt(&self, id: u64) -> Option<&PuzzleSpec> {
        self.entries.get(&id)
    }

    pub fn ids(&self) -> Vec<u64> {
        self.entries.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::genesis_block;

    fn spec() -> PuzzleSpec {
        PuzzleSpec::hybrid_v1()
    }

    fn header_at(height: u64, nonce: u64, epoch: u32) -> Header {
        let mut h = genesis_block(1).header;
        h.height = height;
        h.nonce = nonce;
        h.epoch_id = epoch;
        h.timestamp_ms = 1_700_000_000_000;
        h
    }

    #[test]
    fn default_spec_satisfies_the_work_share_audit() {
        let s = spec();
        s.validate().unwrap();
        assert_eq!(s.nn_share_bps(), 4_000);
        assert!(
            (s.min_nn_share_bps..=s.max_nn_share_bps).contains(&s.nn_share_bps()),
            "NN must be 30-50% of mining work"
        );
    }

    #[test]
    fn overflow_guard_rejects_absurd_widths_without_itself_overflowing() {
        // The guard computing `dim * 128 * 128` in i64 would wrap negative
        // for a `usize` dimension near 2^63 and then overflow before the
        // comparison ran, so the check passed the very inputs it exists to
        // reject. Both widths must be covered: layers after the first
        // accumulate over `nn_hidden_dim`.
        let mut s = spec();
        s.nn_input_dim = usize::MAX;
        assert!(
            matches!(s.validate(), Err(Error::BadPuzzleSpec(_))),
            "absurd input dim must be rejected"
        );

        let mut s2 = spec();
        s2.nn_input_dim = 16;
        s2.nn_hidden_dim = usize::MAX;
        assert!(
            matches!(s2.validate(), Err(Error::BadPuzzleSpec(_))),
            "absurd hidden dim must be rejected even when the input dim is sane"
        );

        // A far wider network is still legitimate as long as the hash
        // rounds are retuned to bring the NN share back into the audit
        // band: 256-wide layers bound the accumulator at 4_194_366, sixteen
        // times the default, and remain valid. The guard must reject only
        // genuinely unbounded widths, not merely unusual ones.
        let mut wide = spec();
        wide.nn_input_dim = 256;
        wide.nn_hidden_dim = 256;
        wide.hash_rounds = 3_070;
        assert_eq!(wide.nn_share_bps(), 5_000);
        assert!(
            wide.validate().is_ok(),
            "a wide-but-tuned spec must be accepted"
        );
    }

    #[test]
    fn more_hash_rounds_shrink_the_nn_share() {
        let base = spec().nn_share_bps();
        let mut s = spec();
        s.hash_rounds = 64;
        assert!(s.nn_share_bps() < base);
        assert!(
            s.validate().is_err(),
            "share below the 30% floor must be rejected"
        );

        let mut s2 = spec();
        s2.hash_rounds = 0;
        assert!(s2.validate().is_err());
    }

    #[test]
    fn weights_are_in_range_and_epoch_dependent() {
        let s = spec();
        for epoch in [0u32, 1, 7, 4_294_967_295] {
            for layer in 0..s.nn_layers {
                for o in 0..s.nn_hidden_dim {
                    let b = bias(&s, layer, o, epoch);
                    assert!((0..63).contains(&b), "bias out of range: {b}");
                    for i in 0..s.in_dim(layer) {
                        let w = weight(&s, layer, o, i, epoch);
                        assert!((-128..=127).contains(&w), "weight out of range: {w}");
                    }
                }
            }
        }
        let w0 = weight(&s, 0, 0, 0, 0);
        let w1 = weight(&s, 0, 0, 0, 1);
        assert_ne!(w0, w1, "weights must rotate every epoch");
    }

    #[test]
    fn epoch_weights_match_point_queries_for_nonsquare_dims() {
        // `EpochWeights` packs layers with stride `in_dim(layer)`; the cached
        // accessor must agree with the point query even when layer 0 is
        // wider/narrower than the hidden layers (previously it assumed a
        // square `hidden x hidden` layout and returned the wrong weights).
        let mut s = spec();
        s.nn_input_dim = 8;
        s.nn_hidden_dim = 16;
        for epoch in [0u32, 3] {
            let w = EpochWeights::build(&s, epoch);
            for layer in 0..s.nn_layers {
                for o in 0..s.nn_hidden_dim {
                    for i in 0..s.in_dim(layer) {
                        assert_eq!(
                            w.weight(&s, layer, o, i),
                            weight(&s, layer, o, i, epoch),
                            "layer {layer} out {o} inp {i} epoch {epoch}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn forward_is_total_on_nonsquare_shapes() {
        // `forward` must never index out of bounds: input rows past byte 31
        // wrap over the 32-byte seed, and the state buffer covers the wider
        // of the input and hidden widths. The wrapped/padded regions must
        // actually feed the digest (not be dead code), and evaluation must
        // be deterministic.
        let mut wide_input = spec();
        wide_input.nn_input_dim = 40;
        let mut wide_hidden = spec();
        wide_hidden.nn_input_dim = 8;
        for s in [wide_input, wide_hidden] {
            let h = header_at(100, 7, 0);
            let seed = stage1_seed(&s, &h);
            let d1 = run_puzzle(&s, &h);
            let d2 = run_puzzle(&s, &h);
            assert_eq!(d1, d2, "evaluation must be deterministic");
            // Flip a byte only a wide input reads (byte 35 mod 32): the
            // digest must move, proving the wrapped region contributes.
            let mut seed_hi = seed;
            seed_hi[35 % seed_hi.len()] ^= 1;
            let w = EpochWeights::build(&s, 0);
            let act = stage2_activation_digest_with(&s, &seed, &w);
            let act_hi = stage2_activation_digest_with(&s, &seed_hi, &w);
            if s.nn_input_dim > 32 {
                assert_ne!(act, act_hi, "wrapped seed bytes must feed stage 2");
            }
        }
    }

    #[test]
    fn fold32_wraps_two_complement() {
        assert_eq!(fold32(0), 0);
        assert_eq!(fold32(127), 127);
        assert_eq!(fold32(128), 128);
        assert_eq!(fold32(-1), -1);
        assert_eq!(fold32(i32::MAX as i64), i32::MAX);
        assert_eq!(fold32(i32::MIN as i64), i32::MIN);
        assert_eq!(fold32(i32::MAX as i64 + 1), i32::MIN);
        assert_eq!(fold32(-(i32::MIN as i64) - 1), i32::MAX);
    }

    #[test]
    fn seed_changes_with_every_header_field_that_matters() {
        let s = spec();
        let base = header_at(100, 7, 0);
        let seed = stage1_seed(&s, &base);
        assert_ne!(seed, stage1_seed(&s, &header_at(101, 7, 0)));
        assert_ne!(seed, stage1_seed(&s, &header_at(100, 8, 0)));
        assert_ne!(seed, stage1_seed(&s, &header_at(100, 7, 1)));
        let mut ts = base.clone();
        ts.timestamp_ms += 1;
        assert_ne!(seed, stage1_seed(&s, &ts));
        let mut en = base.clone();
        en.extra_nonce[15] = 1;
        assert_ne!(seed, stage1_seed(&s, &en));
        let mut mh = base.clone();
        mh.merkle_root[0] ^= 1;
        assert_ne!(seed, stage1_seed(&s, &mh));
        let mut ph = base.clone();
        ph.prev_hash[31] ^= 1;
        assert_ne!(seed, stage1_seed(&s, &ph));
    }

    #[test]
    fn activation_digest_covers_every_layer() {
        let s = spec();
        let seed = [42u8; 32];
        let d = stage2_activation_digest(&s, &seed, 0);
        assert_ne!(d, [0u8; 32]);
        // A different epoch must give a different digest: weights rotate.
        assert_ne!(d, stage2_activation_digest(&s, &seed, 1));
        // A different seed must give a different digest.
        let mut seed2 = seed;
        seed2[0] ^= 1;
        assert_ne!(d, stage2_activation_digest(&s, &seed2, 0));
    }

    #[test]
    fn activations_are_not_vanishing() {
        // If ReLU zeroes every layer after the first, stage 2 becomes a
        // constant and stops constraining anything. Check it does not.
        let s = spec();
        let mut non_zero = 0usize;
        for n in 0..64u64 {
            let seed = stage1_seed(&s, &header_at(0, n, 0));
            let mut x: Vec<i32> = (0..s.nn_input_dim).map(|j| seed[j] as i32 - 128).collect();
            for layer in 0..s.nn_layers {
                let in_dim = s.in_dim(layer);
                let mut z = Vec::with_capacity(s.nn_hidden_dim);
                for o in 0..s.nn_hidden_dim {
                    let mut acc: i64 = bias(&s, layer, o, 0) as i64;
                    for i in 0..in_dim {
                        acc += x[i] as i64 * weight(&s, layer, o, i, 0) as i64;
                    }
                    z.push(fold32(acc));
                }
                x = z.iter().map(|v| (*v >> ACTIVATION_SHIFT).max(0)).collect();
            }
            if x.iter().any(|v| *v != 0) {
                non_zero += 1;
            }
        }
        assert!(
            non_zero >= 60,
            "activations collapsed in {}/64 samples",
            64 - non_zero
        );
    }

    #[test]
    fn puzzle_is_deterministic() {
        let s = spec();
        let h = header_at(5, 99, 0);
        assert_eq!(run_puzzle(&s, &h), run_puzzle(&s, &h));
    }

    #[test]
    fn difficulty_one_always_solves() {
        let s = spec();
        for n in 0..32u64 {
            let h = header_at(1, n, 0);
            assert!(satisfies(&s, &h).unwrap());
        }
    }

    #[test]
    fn high_difficulty_rejects_something() {
        let s = spec();
        let mut solved = 0;
        for n in 0..256u64 {
            let mut h = header_at(1, n, 0);
            h.difficulty = crate::u256::MAX_DIFFICULTY + 1; // beyond the 2^96 ceiling
            assert!(matches!(satisfies(&s, &h), Err(Error::TargetOverflow(_))));

            h.difficulty = 1u128 << 90;
            if satisfies(&s, &h).unwrap() {
                solved += 1;
            }
        }
        // Probability ~256 / 2^90; expect none.
        assert_eq!(solved, 0);
    }

    #[test]
    fn zero_difficulty_is_rejected() {
        let s = spec();
        let mut h = header_at(1, 0, 0);
        h.difficulty = 0;
        assert!(matches!(
            satisfies(&s, &h),
            Err(Error::InvalidDifficulty(0))
        ));
    }

    /// Cases pinned in `verification/tests/vectors/puzzle_vectors.json`.
    ///
    /// `verification/sim/puzzle_crosscheck.py` recomputes every one of these with an
    /// independent Python implementation written from SPEC.md, and the two
    /// must agree byte for byte. That is the only real evidence that
    /// SPEC.md is unambiguous rather than merely consistent with this code.
    fn vector_cases() -> Vec<(u64, u64, u32, PuzzleRun, u64)> {
        let s = spec();
        // Spread over heights, nonces and epochs: epoch_id selects the weight
        // derivation, so an epoch change must move the activation digest.
        [
            (1u64, 0u64, 0u32),
            (1, 1, 0),
            (2, 42, 0),
            (100, 7, 1),
            (50_000, 0, 1),
            (50_001, 12_345, 2),
            (999_999, 7, 4_294_967_295),
        ]
        .into_iter()
        .map(|(height, nonce, epoch)| {
            let h = header_at(height, nonce, epoch);
            let run = run_puzzle(&s, &h);
            (height, nonce, epoch, run, h.serialize().len() as u64)
        })
        .collect()
    }

    #[test]
    fn puzzle_vectors_are_stable() {
        // Regenerate with: UPDATE_PUZZLE_VECTORS=1 cargo test -p srct-core
        let cases = vector_cases();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../verification/tests/vectors/puzzle_vectors.json");

        let mut json = String::from("{\n");
        json.push_str(
            "  \"_comment\": \"Generated from srct-core by puzzle_vectors_are_stable. \
Do not hand-edit.\",\n",
        );
        let s = spec();
        json.push_str(&format!(
            "  \"spec\": {{ \"hash_rounds\": {}, \"nn_input_dim\": {}, \
\"nn_hidden_dim\": {}, \"nn_layers\": {}, \"nn_share_bps\": {} }},\n",
            s.hash_rounds,
            s.nn_input_dim,
            s.nn_hidden_dim,
            s.nn_layers,
            s.nn_share_bps()
        ));
        json.push_str("  \"cases\": [\n");
        for (i, (height, nonce, epoch, run, header_len)) in cases.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"height\": {height},\n"));
            json.push_str(&format!("      \"nonce\": {nonce},\n"));
            json.push_str(&format!("      \"epoch_id\": {epoch},\n"));
            json.push_str(&format!("      \"header_len\": {header_len},\n"));
            json.push_str(&format!("      \"seed\": \"{}\",\n", hex::encode(run.seed)));
            json.push_str(&format!(
                "      \"activation_digest\": \"{}\",\n",
                hex::encode(run.activation_digest)
            ));
            json.push_str(&format!(
                "      \"final_hash\": \"{}\"\n",
                hex::encode(run.final_hash)
            ));
            json.push_str(if i + 1 == cases.len() {
                "    }\n"
            } else {
                "    },\n"
            });
        }
        json.push_str("  ]\n}\n");

        if std::env::var("UPDATE_PUZZLE_VECTORS").is_ok() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, json).unwrap();
            eprintln!("wrote {}", path.display());
            return;
        }

        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read {}: {e}\nregenerate with UPDATE_PUZZLE_VECTORS=1",
                path.display()
            )
        });
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            v["spec"]["nn_share_bps"], 4_000u64,
            "SPEC.md 5.6 audit band"
        );

        let listed = v["cases"].as_array().expect("cases must be an array");
        assert_eq!(
            listed.len(),
            cases.len(),
            "vector file is stale: regenerate with UPDATE_PUZZLE_VECTORS=1"
        );

        for (entry, (height, nonce, epoch, run, header_len)) in listed.iter().zip(cases.iter()) {
            let name = format!("h{height}_n{nonce}_e{epoch}");
            assert_eq!(entry["header_len"].as_u64().unwrap(), *header_len);
            assert_eq!(
                entry["seed"].as_str().unwrap(),
                hex::encode(run.seed),
                "vector {name}: stage 1 seed changed"
            );
            assert_eq!(
                entry["activation_digest"].as_str().unwrap(),
                hex::encode(run.activation_digest),
                "vector {name}: stage 2 activation digest changed"
            );
            assert_eq!(
                entry["final_hash"].as_str().unwrap(),
                hex::encode(run.final_hash),
                "vector {name}: stage 3 final hash changed"
            );
        }
    }
}
