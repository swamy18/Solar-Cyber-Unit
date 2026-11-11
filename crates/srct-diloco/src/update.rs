//! Signed DiLoCo update envelopes.
//!
//! A worker's submission is authority only if it is signed by the worker key
//! the round registered, and the signature must cover the actual update, not
//! just metadata. The signed preimage therefore contains a commitment to the
//! canonical delta bytes; the coordinator recomputes that commitment from the
//! bytes it received. A signature over `(round, worker, base)` alone would let
//! anyone swap the delta after signing.

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::model::Mlp;

pub const UPDATE_VERSION: u8 = 1;
const DOM_UPDATE: &[u8] = b"srct/diloco/update/v1";
const DOM_CLAIM: &[u8] = b"srct/diloco/claim/v1";

/// The metadata a worker signs plus the delta it commits to.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateClaim {
    /// Round this update belongs to. Doubles as the anti-replay nonce: a round
    /// accepts one update per worker and a finalized round is immutable.
    pub round_id: u64,
    /// Model format version the delta was computed against.
    pub model_version: u32,
    /// Registered worker address.
    pub worker: Address,
    /// Hash of the global model the worker started from.
    pub base: Hash,
    /// Number of training samples the worker claims to have used.
    pub samples: u64,
    /// Number of local SGD steps the worker claims to have taken.
    pub steps: u32,
    /// Worker-reported inner loss. Reported for observability only; never used
    /// to price a contribution, because it is unverifiable.
    pub inner_loss: f32,
    /// Commitment to `delta` and its binding metadata.
    pub commitment: Hash,
    /// The pseudo-gradient `theta_local - theta_global`.
    pub delta: Mlp,
}

impl UpdateClaim {
    /// Build a claim from a locally trained model. The commitment and the
    /// signature are derived, never supplied by the caller.
    pub fn new(
        round_id: u64,
        base: &Mlp,
        worker: Address,
        local: &Mlp,
        samples: u64,
        steps: u32,
        inner_loss: f32,
    ) -> Self {
        let delta = local.sub(base);
        let commitment = commit_delta(round_id, &worker, &base.hash(), &delta);
        UpdateClaim {
            round_id,
            model_version: crate::model::MODEL_VERSION,
            worker,
            base: base.hash(),
            samples,
            steps,
            inner_loss,
            commitment,
            delta,
        }
    }

    /// Canonical signed preimage (metadata and commitment, not the delta).
    pub fn encode_meta(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + 8 + 4 + 20 + 32 + 8 + 4 + 4 + 32);
        w.u8(UPDATE_VERSION)
            .u64le(self.round_id)
            .u32le(self.model_version)
            .fixed(&self.worker)
            .fixed(&self.base)
            .u64le(self.samples)
            .u32le(self.steps)
            .u32le(self.inner_loss.to_bits())
            .fixed(&self.commitment);
        w.into_vec()
    }

    /// Domain-separated hash the worker signs.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_CLAIM, &[&self.encode_meta()])
    }

    /// Whether the claimed commitment equals one recomputed from the delta.
    pub fn commitment_matches(&self) -> bool {
        self.commitment == commit_delta(self.round_id, &self.worker, &self.base, &self.delta)
    }
}

/// Commitment to the exact delta bytes plus the round, worker and base they
/// apply to.
pub fn commit_delta(round_id: u64, worker: &Address, base: &Hash, delta: &Mlp) -> Hash {
    sha256_dom(
        DOM_UPDATE,
        &[&round_id.to_le_bytes(), worker, base, &delta.encode()],
    )
}

/// A claim plus the worker's hybrid signature bundle.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedUpdate {
    pub version: u8,
    pub claim: UpdateClaim,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedUpdate {
    /// Sign `claim` with `worker`. The key bundle must derive to the claim's
    /// worker address; a mismatch is refused before a signature is produced.
    pub fn sign(worker: &Wallet, claim: UpdateClaim) -> Result<Self, String> {
        let address = worker.address().map_err(|e| e.to_string())?;
        if address != claim.worker {
            return Err("claim worker does not match the signing wallet".into());
        }
        let auth = Auth::sign(worker, &claim.signing_hash()).map_err(|e| e.to_string())?;
        Ok(SignedUpdate {
            version: UPDATE_VERSION,
            claim,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    /// Verify the envelope: supported version, key bundle bound to the worker
    /// address, signature over the claim, and a commitment that matches the
    /// delta bytes actually carried.
    pub fn verify(&self) -> Result<(), String> {
        if self.version != UPDATE_VERSION {
            return Err(format!("unsupported update version {}", self.version));
        }
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.claim.worker {
            return Err("update key bundle is not the worker".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.claim.signing_hash())
            .map_err(|_| "update signature invalid".to_string())?;
        if !self.claim.commitment_matches() {
            return Err("update commitment does not match its delta".into());
        }
        Ok(())
    }

    /// Canonical wire encoding, including the delta bytes.
    pub fn encode(&self) -> Vec<u8> {
        let meta = self.claim.encode_meta();
        let delta = self.claim.delta.encode();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(meta.len() + delta.len() + sigs.len() + keys.len() + 16);
        w.raw(&meta)
            .u32le(delta.len() as u32)
            .raw(&delta)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    /// Strict inverse of [`SignedUpdate::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("update: {e}"))?;
        let round_id = r.u64le().map_err(|e| format!("update: {e}"))?;
        let model_version = r.u32le().map_err(|e| format!("update: {e}"))?;
        let worker: Address = r.fixed().map_err(|e| format!("update: {e}"))?;
        let base: Hash = r.fixed().map_err(|e| format!("update: {e}"))?;
        let samples = r.u64le().map_err(|e| format!("update: {e}"))?;
        let steps = r.u32le().map_err(|e| format!("update: {e}"))?;
        let inner_loss = f32::from_bits(r.u32le().map_err(|e| format!("update: {e}"))?);
        let commitment: Hash = r.fixed().map_err(|e| format!("update: {e}"))?;
        let delta_len = r.u32le().map_err(|e| format!("update: {e}"))? as usize;
        if delta_len > 64 * 1024 {
            return Err("update: delta over cap".into());
        }
        let delta = Mlp::decode(
            r.fixed_slice(delta_len)
                .map_err(|e| format!("update: {e}"))?,
        )?;
        let sigs_len = r.u32le().map_err(|e| format!("update: {e}"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err("update: signature bundle over cap".into());
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|e| format!("update: {e}"))?,
        )
        .map_err(|e| format!("update: {e}"))?;
        let keys_len = r.u32le().map_err(|e| format!("update: {e}"))? as usize;
        if keys_len > 8 * 1024 {
            return Err("update: key bundle over cap".into());
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|e| format!("update: {e}"))?,
        )
        .map_err(|e| format!("update: {e}"))?;
        r.expect_end().map_err(|e| format!("update: {e}"))?;
        Ok(SignedUpdate {
            version,
            claim: UpdateClaim {
                round_id,
                model_version,
                worker,
                base,
                samples,
                steps,
                inner_loss,
                commitment,
                delta,
            },
            sigs,
            keys,
        })
    }
}
