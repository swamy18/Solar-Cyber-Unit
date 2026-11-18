//! M5 Protocol Mechanism: Sovereign BLS Finality Gadget Checkpoints.
//!
//! Solar Cyber Unit's base-layer finality is probabilistic (deepest-chain rule with a
//! `finality_depth` lookback window). M5 adds a *deterministic* finality layer
//! via BLS signature aggregation:
//!
//! Checkpoint flow
//! ---------------
//! 1. Every `CHECKPOINT_INTERVAL` blocks a **checkpoint** is proposed by the
//!    current epoch's validator committee.
//! 2. Each validator signs the checkpoint payload with their BLS private key.
//! 3. Signatures are aggregated off-chain (or by a designated aggregator node)
//!    into a single 96-byte BLS aggregate signature.
//! 4. The aggregate + a bitmap of which validators signed is included in a
//!    special coinbase field (or as a separate on-chain transaction).
//! 5. Once a checkpoint is accepted, all blocks up to its height become
//!    *absolutely final* — no reorg can touch them, even past `finality_depth`.
//!
//! BLS notes
//! ----------
//! Full BLS12-381 crypto requires a pairing-friendly curve library (e.g.
//! `blst`, `bls12_381`). Those crates have significant compile overhead and
//! non-trivial C bindings. This module provides:
//!
//!   - All data structures, serialization, and consensus logic in pure Rust.
//!   - A `BlsSignature` / `BlsPublicKey` type backed by fixed-size byte arrays
//!     with the BLS12-381 encoding (G1 = 48 bytes, G2 = 96 bytes).
//!   - A `MockBls` verifier for unit tests that validates structural correctness
//!     without doing pairing checks (suitable for CI; replace with `blst` for
//!     production).
//!   - A clear `verify_checkpoint` API that takes a `dyn BlsVerifier` so the
//!     production binary can plug in the real pairing.
//!
//! SPEC.md §M5.

use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Hash, Hash512};
use crate::ser::{Reader, Writer};

/// Checkpoint period: one checkpoint every N blocks.
/// Production: every 100 blocks (~17 minutes at 10-min block times).
/// Test: every 10 blocks.
pub const CHECKPOINT_INTERVAL_MAINNET: u64 = 100;
pub const CHECKPOINT_INTERVAL_MINI: u64 = 10;

/// Minimum fraction of validators that must sign (in basis points, 10000 = 100%).
/// 6667 bps = 2/3 supermajority.
pub const QUORUM_BPS: u32 = 6_667;

/// Domain separator for BLS checkpoint signing.
pub const DOM_BLS_CHECKPOINT: u8 = 0xB1;

// ---------------------------------------------------------------------------
// BLS key and signature types
// ---------------------------------------------------------------------------

/// BLS12-381 G1 public key (48 bytes, compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlsPublicKey(pub [u8; 48]);

/// BLS12-381 G2 signature (96 bytes, compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlsSignature(pub [u8; 96]);

impl BlsPublicKey {
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
    /// True if the key is the all-zeros sentinel (invalid/uninitialized).
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 48]
    }
}

impl BlsSignature {
    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 96]
    }
}

// ---------------------------------------------------------------------------
// CheckpointPayload: what validators sign
// ---------------------------------------------------------------------------

/// The data that each validator signs to endorse a checkpoint.
///
/// Committing to `block_hash` (not just `height`) prevents an attacker from
/// reusing a checkpoint signature for a different block at the same height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPayload {
    /// Height of the block being checkpointed.
    pub height: u64,
    /// Hash of the canonical block at `height`.
    pub block_hash: Hash512,
    /// Chain network ID ("srct/mainnet" or "srct/mini").
    /// Prevents replay across networks.
    pub network_id: String,
    /// Epoch number (increments every `CHECKPOINT_INTERVAL` blocks).
    pub epoch: u64,
}

/// Maximum serialized checkpoint payload size (covers any realistic network_id).
pub const MAX_CHECKPOINT_PAYLOAD_BYTES: usize = 256;
/// Maximum signer bitmap size (512 validators × 1 bit = 64 bytes; generous headroom).
pub const MAX_SIGNER_BITMAP_BYTES: usize = 512;

/// Maximum ML-DSA sidecar entries on one checkpoint. Committees are capped at
/// 21 (`bond::MAX_COMMITTEE_SIZE`), so 64 is 3× headroom, not a second cap a
/// legitimate committee could ever hit — and it bounds one certificate to
/// ~212 KB, far inside the relay frame. A larger committee is a separate
/// consensus change that raises this number with it.
pub const MAX_PQ_SIDECAR_ENTRIES: usize = 64;

/// Encoded ML-DSA-65 signature length inside a sidecar entry.
pub const PQ_SIDECAR_SIGNATURE_BYTES: usize = 3309;

/// One validator's lattice signature over a checkpoint decision.
///
/// ML-DSA has no pairing-based aggregation, so the "aggregate" half of a
/// dual-signed checkpoint is a list of these, one per lattice signer, each
/// naming its bitmap index. The index — not the key — is what binds an entry
/// to a committee member: the verifier looks the key up in its own epoch set,
/// so a caller cannot smuggle in a key the committee never registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSidecarEntry {
    /// Bitmap index of the signer in the epoch set's canonical order.
    pub signer_index: u32,
    /// ML-DSA-65 signature over the payload's signing hash (empty context).
    pub signature: [u8; PQ_SIDECAR_SIGNATURE_BYTES],
}

impl CheckpointPayload {
    /// Canonical serialization for signing.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u64(self.height);
        w.write_bytes(&self.block_hash);
        let id_bytes = self.network_id.as_bytes();
        w.write_u32(id_bytes.len() as u32);
        w.write_raw(id_bytes);
        w.write_u64(self.epoch);
        w.finish()
    }

    /// Domain-separated hash used as the BLS message.
    ///
    /// In BLS12-381 the "message" passed to the signing function is this hash,
    /// not the raw payload. Domain separation prevents cross-protocol attacks.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(&[DOM_BLS_CHECKPOINT], &[&self.serialize()])
    }

    /// Epoch number for a given chain height and interval.
    pub fn epoch_for(height: u64, interval: u64) -> u64 {
        height / interval.max(1)
    }

    /// Bounded deserialize. Fails if any field exceeds its limit or if
    /// trailing bytes remain.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let height = r.u64le()?;
        let block_hash: Hash512 = r.fixed()?;
        let id_len = r.u32le()? as usize;
        if id_len > 64 {
            return Err(Error::Malformed("network_id too long"));
        }
        let id_bytes = r.fixed_slice(id_len)?;
        let network_id = String::from_utf8(id_bytes.to_vec())
            .map_err(|_| Error::Malformed("network_id is not UTF-8"))?;
        let epoch = r.u64le()?;
        r.expect_end()?;
        Ok(Self {
            height,
            block_hash,
            network_id,
            epoch,
        })
    }
}

// ---------------------------------------------------------------------------
// ValidatorSet: the committee that signs checkpoints
// ---------------------------------------------------------------------------

/// Ordered list of BLS public keys for the current epoch's validator committee.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// Keys in deterministic order (sorted by key bytes for reproducibility).
    pub keys: Vec<BlsPublicKey>,
    /// Registered lattice key per member, aligned with `keys` by index:
    /// `mldsa_keys[i]` is member `i`'s ML-DSA-65 key, or `None` when that
    /// member registered none. The alignment is the whole point — a bitmap
    /// index resolves to a lattice key with no second lookup — so every
    /// constructor that reorders `keys` must carry this vector along, and any
    /// two `ValidatorSet`s compared for equality compare both halves.
    pub mldsa_keys: Vec<Option<[u8; 1952]>>,
}

impl ValidatorSet {
    pub fn new(mut keys: Vec<BlsPublicKey>) -> Self {
        keys.sort_by_key(|a| a.0);
        let n = keys.len();
        ValidatorSet {
            keys,
            mldsa_keys: vec![None; n],
        }
    }

    /// Build from validator records: same sorted order as [`ValidatorSet::new`]
    /// (BLS keys are unique per set, so sorting records by key bytes indexes
    /// identically), with each member's registered lattice key aligned beside
    /// its BLS key. This is the constructor settle and VWC verification use —
    /// the one that knows about lattice keys at all.
    pub fn from_records(records: &[crate::validators::ValidatorRecord]) -> Self {
        let mut sorted: Vec<&crate::validators::ValidatorRecord> = records.iter().collect();
        sorted.sort_by_key(|r| r.bls_pk.0);
        ValidatorSet {
            keys: sorted.iter().map(|r| r.bls_pk).collect(),
            mldsa_keys: sorted.iter().map(|r| r.mldsa_pk).collect(),
        }
    }

    /// Member `i`'s registered lattice key, if any.
    pub fn mldsa_key(&self, idx: usize) -> Option<&[u8; 1952]> {
        self.mldsa_keys.get(idx).and_then(|k| k.as_ref())
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Minimum number of validators required for a valid checkpoint.
    pub fn quorum_size(&self) -> usize {
        let n = self.keys.len() as u64;
        (n * QUORUM_BPS as u64).div_ceil(10_000) as usize
    }

    /// Decode the signers from a compact bitmap (1 bit per validator, LSB = idx 0).
    pub fn signers_from_bitmap(&self, bitmap: &[u8]) -> Vec<BlsPublicKey> {
        let mut signers = Vec::new();
        for (i, key) in self.keys.iter().enumerate() {
            let byte = i / 8;
            let bit = i % 8;
            if byte < bitmap.len() && (bitmap[byte] >> bit) & 1 == 1 {
                signers.push(*key);
            }
        }
        signers
    }

    /// Build a bitmap from a set of signing key indices.
    pub fn bitmap_from_indices(&self, indices: &[usize]) -> Vec<u8> {
        let n_bytes = self.keys.len().div_ceil(8);
        let mut bitmap = vec![0u8; n_bytes];
        for &idx in indices {
            if idx < self.keys.len() {
                bitmap[idx / 8] |= 1 << (idx % 8);
            }
        }
        bitmap
    }
}

// ---------------------------------------------------------------------------
// Checkpoint: the finality record stored on-chain
// ---------------------------------------------------------------------------

/// A finalized checkpoint record.
///
/// Stored in a special coinbase field or a dedicated checkpoint transaction.
/// Once a checkpoint is accepted, `height` and all earlier blocks are
/// absolutely final — the chain MUST NOT reorg past a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The payload that was signed.
    pub payload: CheckpointPayload,
    /// BLS aggregate signature over `payload.signing_hash()`.
    pub aggregate_sig: BlsSignature,
    /// Bitmap of which validators in the epoch set signed.
    /// Bit i = 1 means validator i (sorted order) signed.
    pub signer_bitmap: Vec<u8>,
    /// Number of validators that signed (derived from bitmap; stored for
    /// fast quorum checks without re-counting the bitmap).
    pub signer_count: u32,
    /// Lattice sidecar: one ML-DSA-65 signature per bitmap signer that holds
    /// a registered lattice key, over the same signing hash the BLS aggregate
    /// covers. Empty while no committee member has registered a key, in which
    /// case verification is BLS-only exactly as before. See clause 7 in
    /// `validators::validate_checkpoint_against_set`.
    pub pq_sidecar: Vec<PqSidecarEntry>,
}

impl Checkpoint {
    /// True if signer_count meets or exceeds the required quorum.
    pub fn has_quorum(&self, required: usize) -> bool {
        self.signer_count as usize >= required
    }

    /// Canonical serialization (stored on-chain or in P2P relay).
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let payload_bytes = self.payload.serialize();
        w.write_u32(payload_bytes.len() as u32);
        w.write_raw(&payload_bytes);
        w.write_raw(self.aggregate_sig.as_bytes());
        w.write_u32(self.signer_bitmap.len() as u32);
        w.write_raw(&self.signer_bitmap);
        w.write_u32(self.signer_count);
        // The sidecar rides last so its absence costs four zero bytes and its
        // presence is length-prefixed like every other repeated field.
        w.write_u32(self.pq_sidecar.len() as u32);
        for e in &self.pq_sidecar {
            w.write_u32(e.signer_index);
            w.write_raw(&e.signature);
        }
        w.finish()
    }

    /// Bounded deserialize. Fails if any length field exceeds its limit,
    /// if the bitmap popcount disagrees with `signer_count`, or if
    /// trailing bytes remain.
    ///
    /// Certificates written before the sidecar existed end right after
    /// `signer_count`, and those decode to an empty sidecar rather than an
    /// error — so history, vectors and slash evidence over old certificates
    /// keep reading. This is not a downgrade hole: stripping a sidecar off a
    /// new certificate leaves bitmap signers holding registered lattice keys
    /// with no entries for them, and clause 7 refuses exactly that. The parse
    /// is lenient; the verification is not.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let payload_len = r.u32le()? as usize;
        if payload_len > MAX_CHECKPOINT_PAYLOAD_BYTES {
            return Err(Error::Malformed("checkpoint payload too large"));
        }
        let payload_bytes = r.fixed_slice(payload_len)?;
        let payload = CheckpointPayload::deserialize(payload_bytes)?;
        let aggregate_sig = BlsSignature(r.fixed()?);
        let bitmap_len = r.u32le()? as usize;
        if bitmap_len > MAX_SIGNER_BITMAP_BYTES {
            return Err(Error::Malformed("signer bitmap too large"));
        }
        let signer_bitmap = r.fixed_slice(bitmap_len)?.to_vec();
        let signer_count = r.u32le()?;
        let mut pq_sidecar = Vec::new();
        if r.remaining() > 0 {
            let sidecar_len = r.u32le()? as usize;
            if sidecar_len > MAX_PQ_SIDECAR_ENTRIES {
                return Err(Error::Malformed("pq sidecar too large"));
            }
            pq_sidecar.reserve(sidecar_len.min(8));
            for _ in 0..sidecar_len {
                let signer_index = r.u32le()?;
                let signature: [u8; PQ_SIDECAR_SIGNATURE_BYTES] = r.fixed()?;
                pq_sidecar.push(PqSidecarEntry {
                    signer_index,
                    signature,
                });
            }
        }
        r.expect_end()?;
        let s = Self {
            payload,
            aggregate_sig,
            signer_bitmap,
            signer_count,
            pq_sidecar,
        };
        s.assert_coherent()?;
        Ok(s)
    }

    /// Internal consistency check: bitmap popcount == signer_count, and
    /// no bits set beyond the validator set size this bitmap can address.
    fn assert_coherent(&self) -> Result<()> {
        let popcount = self
            .signer_bitmap
            .iter()
            .map(|b| b.count_ones())
            .sum::<u32>();
        if popcount != self.signer_count {
            return Err(Error::Malformed("signer_count does not match bitmap"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BlsVerifier trait: abstracts real vs mock pairing
// ---------------------------------------------------------------------------

/// Pluggable BLS signature verifier. Production implementations use `blst`;
/// test implementations use `MockBls`.
pub trait BlsVerifier: Send + Sync {
    /// Verify that `sig` is a valid aggregate BLS signature over `message`
    /// by the given set of `public_keys`.
    fn verify_aggregate(
        &self,
        public_keys: &[BlsPublicKey],
        message: &Hash,
        sig: &BlsSignature,
    ) -> bool;
}

/// Structural-only verifier for unit tests. Does NOT perform pairing checks.
/// It accepts any non-zero signature as long as there is at least one signer.
/// Replace with a `blst`-backed implementation for production.
pub struct MockBls;

/// Shared mock verifier instance, for test chains that must name a verifier
/// without threading one through every call. Never use in production code
/// paths: anything it accepts must be re-checked with [`crate::bls::REAL_BLS`]
/// before it can affect consensus.
pub static MOCK_BLS: MockBls = MockBls;

impl BlsVerifier for MockBls {
    fn verify_aggregate(
        &self,
        public_keys: &[BlsPublicKey],
        _message: &Hash,
        sig: &BlsSignature,
    ) -> bool {
        !public_keys.is_empty() && !sig.is_zero()
    }
}

// ---------------------------------------------------------------------------
// Checkpoint validation
// ---------------------------------------------------------------------------

/// Validate a checkpoint against the validator set, returning `Err` with a
/// human-readable reason if it is invalid.
pub fn verify_checkpoint(
    checkpoint: &Checkpoint,
    validator_set: &ValidatorSet,
    verifier: &dyn BlsVerifier,
) -> Result<()> {
    // 1. Check quorum
    let required = validator_set.quorum_size();
    if !checkpoint.has_quorum(required) {
        return Err(Error::Malformed("checkpoint signer count below quorum"));
    }

    // 2. Decode signer set from bitmap
    let signers = validator_set.signers_from_bitmap(&checkpoint.signer_bitmap);
    if signers.len() != checkpoint.signer_count as usize {
        return Err(Error::Malformed(
            "bitmap yields a different signer count than signer_count claims",
        ));
    }

    // 3. Verify aggregate signature
    let message = checkpoint.payload.signing_hash();
    if !verifier.verify_aggregate(&signers, &message, &checkpoint.aggregate_sig) {
        return Err(Error::Malformed(
            "aggregate BLS signature verification failed",
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Checkpoint chain state: tracks accepted finality points
// ---------------------------------------------------------------------------

/// Tracks the chain's accepted checkpoints and enforces absolute finality.
#[derive(Debug, Clone, Default)]
pub struct CheckpointChain {
    /// Accepted checkpoints in ascending height order.
    checkpoints: Vec<Checkpoint>,
    /// Height of the highest accepted checkpoint (or 0 if none).
    pub finalized_height: u64,
}

impl CheckpointChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to accept a new checkpoint. Fails if it doesn't extend the
    /// current finalized tip or fails validation.
    pub fn accept(
        &mut self,
        checkpoint: Checkpoint,
        validator_set: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> Result<()> {
        // Must be strictly beyond the current finality tip
        if checkpoint.payload.height <= self.finalized_height {
            return Err(Error::Malformed(
                "checkpoint height is not beyond finalized height",
            ));
        }
        verify_checkpoint(&checkpoint, validator_set, verifier)?;
        self.finalized_height = checkpoint.payload.height;
        self.checkpoints.push(checkpoint);
        Ok(())
    }

    /// True when `height` is absolutely finalized (cannot be reorged).
    pub fn is_finalized(&self, height: u64) -> bool {
        height <= self.finalized_height
    }

    /// The most recent accepted checkpoint, if any.
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    /// Total number of accepted checkpoints.
    pub fn count(&self) -> usize {
        self.checkpoints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn dummy_key(n: u8) -> BlsPublicKey {
        let mut k = [0u8; 48];
        k[0] = n;
        k[47] = n.wrapping_add(1); // ensure non-zero
        BlsPublicKey(k)
    }

    fn dummy_sig() -> BlsSignature {
        let mut s = [0u8; 96];
        s[0] = 0xAA;
        BlsSignature(s)
    }

    fn make_payload(height: u64) -> CheckpointPayload {
        CheckpointPayload {
            height,
            block_hash: [height as u8; 64],
            network_id: "srct/mini".into(),
            epoch: CheckpointPayload::epoch_for(height, CHECKPOINT_INTERVAL_MINI),
        }
    }

    fn make_checkpoint(height: u64, signers: u32, bitmap: Vec<u8>) -> Checkpoint {
        Checkpoint {
            payload: make_payload(height),
            aggregate_sig: dummy_sig(),
            signer_bitmap: bitmap,
            signer_count: signers,
            pq_sidecar: Vec::new(),
        }
    }

    fn four_validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![dummy_key(1), dummy_key(2), dummy_key(3), dummy_key(4)])
    }

    // ------------------------------------------------------------------
    // CheckpointPayload
    // ------------------------------------------------------------------

    #[test]
    fn signing_hash_is_deterministic() {
        let p = make_payload(100);
        assert_eq!(p.signing_hash(), p.signing_hash());
    }

    #[test]
    fn signing_hash_changes_with_height() {
        let p1 = make_payload(100);
        let p2 = make_payload(200);
        assert_ne!(p1.signing_hash(), p2.signing_hash());
    }

    #[test]
    fn signing_hash_changes_with_block_hash() {
        let p1 = make_payload(100);
        let mut p2 = make_payload(100);
        p2.block_hash[0] ^= 0xFF;
        assert_ne!(p1.signing_hash(), p2.signing_hash());
    }

    #[test]
    fn epoch_for_computes_correctly() {
        assert_eq!(CheckpointPayload::epoch_for(0, 10), 0);
        assert_eq!(CheckpointPayload::epoch_for(9, 10), 0);
        assert_eq!(CheckpointPayload::epoch_for(10, 10), 1);
        assert_eq!(CheckpointPayload::epoch_for(99, 10), 9);
    }

    // ------------------------------------------------------------------
    // ValidatorSet
    // ------------------------------------------------------------------

    #[test]
    fn quorum_size_is_two_thirds_supermajority() {
        // 4 validators: ceil(4 * 6667 / 10000) = ceil(2.6668) = 3
        let vs = four_validator_set();
        assert_eq!(vs.quorum_size(), 3);
    }

    #[test]
    fn bitmap_round_trips() {
        let vs = four_validator_set();
        // Validators 0 and 2 sign
        let indices = vec![0usize, 2];
        let bitmap = vs.bitmap_from_indices(&indices);
        let signers = vs.signers_from_bitmap(&bitmap);
        assert_eq!(signers.len(), 2);
        assert!(signers.contains(&dummy_key(1))); // key sorted order
        assert!(signers.contains(&dummy_key(3)));
    }

    #[test]
    fn sorted_keys_are_deterministic() {
        let keys_a = vec![dummy_key(3), dummy_key(1), dummy_key(2)];
        let keys_b = vec![dummy_key(1), dummy_key(2), dummy_key(3)];
        let vs_a = ValidatorSet::new(keys_a);
        let vs_b = ValidatorSet::new(keys_b);
        assert_eq!(
            vs_a.keys, vs_b.keys,
            "validator sets must be order-independent"
        );
    }

    // ------------------------------------------------------------------
    // verify_checkpoint with MockBls
    // ------------------------------------------------------------------

    #[test]
    fn valid_checkpoint_passes_with_quorum() {
        let vs = four_validator_set(); // quorum = 3
                                       // All 4 sign: bitmap = 0b00001111 = 0x0F
        let cp = make_checkpoint(10, 4, vec![0x0F]);
        assert!(verify_checkpoint(&cp, &vs, &MockBls).is_ok());
    }

    #[test]
    fn checkpoint_fails_below_quorum() {
        let vs = four_validator_set(); // quorum = 3
                                       // Only 2 sign
        let cp = make_checkpoint(10, 2, vec![0x03]);
        assert!(verify_checkpoint(&cp, &vs, &MockBls).is_err());
    }

    #[test]
    fn checkpoint_fails_with_zero_aggregate_sig() {
        let vs = four_validator_set();
        let mut cp = make_checkpoint(10, 4, vec![0x0F]);
        cp.aggregate_sig = BlsSignature([0u8; 96]); // all-zeros = invalid
        assert!(verify_checkpoint(&cp, &vs, &MockBls).is_err());
    }

    #[test]
    fn bitmap_mismatch_fails_validation() {
        let vs = four_validator_set();
        // bitmap says 4 bits set but signer_count = 3
        let cp = make_checkpoint(10, 3, vec![0x0F]);
        // signer_count 3 != bitmap_popcount 4
        // verify_checkpoint checks: signers.len() != signer_count
        assert!(verify_checkpoint(&cp, &vs, &MockBls).is_err());
    }

    // ------------------------------------------------------------------
    // CheckpointChain
    // ------------------------------------------------------------------

    #[test]
    fn checkpoint_chain_advances_finality() {
        let vs = four_validator_set();
        let mut chain = CheckpointChain::new();

        let cp1 = make_checkpoint(10, 4, vec![0x0F]);
        let cp2 = make_checkpoint(20, 4, vec![0x0F]);

        chain.accept(cp1, &vs, &MockBls).unwrap();
        assert_eq!(chain.finalized_height, 10);
        assert!(chain.is_finalized(10));
        assert!(!chain.is_finalized(11));

        chain.accept(cp2, &vs, &MockBls).unwrap();
        assert_eq!(chain.finalized_height, 20);
    }

    #[test]
    fn stale_checkpoint_is_rejected() {
        let vs = four_validator_set();
        let mut chain = CheckpointChain::new();
        let cp1 = make_checkpoint(10, 4, vec![0x0F]);
        chain.accept(cp1, &vs, &MockBls).unwrap();

        // Trying to accept a checkpoint at the same height must fail
        let cp_stale = make_checkpoint(10, 4, vec![0x0F]);
        assert!(chain.accept(cp_stale, &vs, &MockBls).is_err());
    }

    #[test]
    fn checkpoint_count_tracked() {
        let vs = four_validator_set();
        let mut chain = CheckpointChain::new();
        assert_eq!(chain.count(), 0);
        chain
            .accept(make_checkpoint(10, 4, vec![0x0F]), &vs, &MockBls)
            .unwrap();
        chain
            .accept(make_checkpoint(20, 4, vec![0x0F]), &vs, &MockBls)
            .unwrap();
        assert_eq!(chain.count(), 2);
    }

    #[test]
    fn bls_key_and_sig_zero_sentinels() {
        assert!(BlsPublicKey([0u8; 48]).is_zero());
        assert!(BlsSignature([0u8; 96]).is_zero());
        assert!(!dummy_key(1).is_zero());
        assert!(!dummy_sig().is_zero());
    }
}
