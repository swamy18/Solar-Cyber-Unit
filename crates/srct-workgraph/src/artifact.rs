//! Reusable verifiable AI-compute artifacts with lineage and royalties.
//!
//! An artifact records what was computed (model/input/runtime/result hashes),
//! who owns it, what it was derived from (parents) and under what license it
//! may be reused. Deriving from an artifact (listing it as a parent) is a
//! use: when the child earns revenue, royalties flow upstream automatically.
//!
//! The graph stores hashes and signatures, not the data itself. It trusts the
//! issuing crates for proof validity (a TEE quote is checked by
//! `srct-compute::tee`, a ZK proof by `srct-zkml`, ...); what it enforces is
//! lineage integrity: parents exist, licenses allow derivation, the graph
//! stays a DAG, and every revenue split sums exactly.

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::WorkError;

pub const ARTIFACT_VERSION: u8 = 1;
/// Lineage entries per artifact: enough for real provenance, bounded for wire
/// safety.
pub const MAX_PARENTS: usize = 16;
/// Royalty walks stop here; deeper ancestors earn nothing from this use.
pub const MAX_ROYALTY_DEPTH: usize = 8;
/// Royalty basis points cap per artifact (100% would leave the owner nothing,
/// so the cap is 50%).
pub const MAX_ROYALTY_BPS: u64 = 5_000;

const DOM_ARTIFACT: &[u8] = b"srct/workgraph/artifact/v1";

/// What kind of verifiable work this artifact wraps. The evidence hash points
/// at the issuing crate's proof (VWC id, TEE quote, FHE receipt, ZK proof,
/// ...); this crate checks presence and binding, not proof validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactKind {
    TrainingUpdate = 0,
    InferenceResult = 1,
    AdapterWeights = 2,
    EncryptedResult = 3,
    AttestedExecution = 4,
    ZkProvenResult = 5,
}

impl ArtifactKind {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ArtifactKind::TrainingUpdate),
            1 => Some(ArtifactKind::InferenceResult),
            2 => Some(ArtifactKind::AdapterWeights),
            3 => Some(ArtifactKind::EncryptedResult),
            4 => Some(ArtifactKind::AttestedExecution),
            5 => Some(ArtifactKind::ZkProvenResult),
            _ => None,
        }
    }
}

/// Reuse permission and the royalty owed upstream on each revenue event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct License {
    /// Whether other artifacts may list this one as a parent.
    pub reusable: bool,
    /// Basis points of each revenue event owed to this artifact's lineage.
    pub royalty_bps: u64,
}

impl License {
    fn validate(&self) -> Result<(), WorkError> {
        if self.royalty_bps > MAX_ROYALTY_BPS {
            return Err(WorkError::Malformed(
                "artifact royalty exceeds the cap".into(),
            ));
        }
        Ok(())
    }

    fn encode(&self, w: &mut Writer) {
        w.u8(u8::from(self.reusable)).u64le(self.royalty_bps);
    }

    fn decode(r: &mut Reader) -> Result<Self, WorkError> {
        let reusable = match r.u8().map_err(malformed)? {
            0 => false,
            1 => true,
            _ => return Err(WorkError::Malformed("artifact license flag is bad".into())),
        };
        let royalty_bps = r.u64le().map_err(malformed)?;
        let license = License {
            reusable,
            royalty_bps,
        };
        license.validate()?;
        Ok(license)
    }
}

/// A reusable artifact: content hashes, owner, lineage, license and evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub version: u8,
    pub network_id: String,
    pub kind: ArtifactKind,
    pub owner: Address,
    pub model_hash: Hash,
    pub input_hash: Hash,
    pub runtime_hash: Hash,
    pub result_hash: Hash,
    /// Hash of the issuing crate's proof (VWC, quote, receipt, ...).
    pub evidence: Hash,
    pub parents: Vec<Hash>,
    pub license: License,
    pub created_height: u64,
    pub nonce: u64,
}

impl Artifact {
    fn validate(&self) -> Result<(), WorkError> {
        if self.version != ARTIFACT_VERSION {
            return Err(WorkError::Malformed(format!(
                "unsupported artifact version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(WorkError::Malformed("artifact network id length".into()));
        }
        if self.result_hash == [0u8; 32] {
            return Err(WorkError::Malformed("artifact result hash is zero".into()));
        }
        if self.evidence == [0u8; 32] {
            return Err(WorkError::Malformed(
                "artifact evidence hash is zero".into(),
            ));
        }
        if self.parents.len() > MAX_PARENTS {
            return Err(WorkError::Malformed("artifact has too many parents".into()));
        }
        if self.parents.iter().any(|p| p == &[0u8; 32]) {
            return Err(WorkError::Malformed("artifact parent hash is zero".into()));
        }
        self.license.validate()?;
        if self.nonce == 0 {
            return Err(WorkError::Malformed("artifact nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256 + 32 * self.parents.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .u8(self.kind.as_u8())
            .fixed(&self.owner)
            .fixed(&self.model_hash)
            .fixed(&self.input_hash)
            .fixed(&self.runtime_hash)
            .fixed(&self.result_hash)
            .fixed(&self.evidence)
            .u16le(self.parents.len() as u16);
        for parent in &self.parents {
            w.fixed(parent);
        }
        self.license.encode(&mut w);
        w.u64le(self.created_height).u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_ARTIFACT, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WorkError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(WorkError::Malformed("artifact network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| WorkError::Malformed("artifact network is not utf-8".into()))?
            .to_string();
        let kind = ArtifactKind::from_u8(r.u8().map_err(malformed)?)
            .ok_or_else(|| WorkError::Malformed("artifact kind is unknown".into()))?;
        let owner = r.fixed().map_err(malformed)?;
        let model_hash = r.fixed().map_err(malformed)?;
        let input_hash = r.fixed().map_err(malformed)?;
        let runtime_hash = r.fixed().map_err(malformed)?;
        let result_hash = r.fixed().map_err(malformed)?;
        let evidence = r.fixed().map_err(malformed)?;
        let count = r.u16le().map_err(malformed)? as usize;
        if count > MAX_PARENTS {
            return Err(WorkError::Malformed("artifact has too many parents".into()));
        }
        let mut parents = Vec::with_capacity(count);
        for _ in 0..count {
            parents.push(r.fixed().map_err(malformed)?);
        }
        let license = License::decode(&mut r)?;
        let created_height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let artifact = Artifact {
            version,
            network_id,
            kind,
            owner,
            model_hash,
            input_hash,
            runtime_hash,
            result_hash,
            evidence,
            parents,
            license,
            created_height,
            nonce,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

/// An owner-signed artifact registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedArtifact {
    pub artifact: Artifact,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedArtifact {
    pub fn sign(artifact: Artifact, owner: &Wallet) -> Result<Self, WorkError> {
        artifact.validate()?;
        let address = owner
            .address()
            .map_err(|e| WorkError::BadSignature(e.to_string()))?;
        if address != artifact.owner {
            return Err(WorkError::WrongOwner);
        }
        let auth = Auth::sign(owner, &artifact.hash())
            .map_err(|e| WorkError::BadSignature(e.to_string()))?;
        Ok(SignedArtifact {
            artifact,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), WorkError> {
        self.artifact.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| WorkError::BadSignature(e.to_string()))?;
        if signer != self.artifact.owner {
            return Err(WorkError::WrongOwner);
        }
        verify_bundle(&self.sigs, &self.keys, &self.artifact.hash())
            .map_err(|e| WorkError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.artifact.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.artifact.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WorkError> {
        let (body, sigs, keys) = decode_signed(bytes, "artifact")?;
        let artifact = Artifact::decode(&body)?;
        let signed = SignedArtifact {
            artifact,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

fn encode_signed(body: &[u8], sigs: &Bundle, keys: &Bundle) -> Vec<u8> {
    let sigs = sigs.to_bytes();
    let keys = keys.to_bytes();
    let mut w = Writer::with_capacity(body.len() + sigs.len() + keys.len() + 16);
    w.u32le(body.len() as u32)
        .raw(body)
        .u32le(sigs.len() as u32)
        .raw(&sigs)
        .u32le(keys.len() as u32)
        .raw(&keys);
    w.into_vec()
}

fn decode_signed(bytes: &[u8], what: &str) -> Result<(Vec<u8>, Bundle, Bundle), WorkError> {
    let err = |detail: String| WorkError::Malformed(format!("{what}: {detail}"));
    let mut r = Reader::new(bytes);
    let body_len = r.u32le().map_err(malformed)? as usize;
    if body_len > 64 * 1024 {
        return Err(err("body over cap".into()));
    }
    let body = r.fixed_slice(body_len).map_err(malformed)?.to_vec();
    let sigs_len = r.u32le().map_err(malformed)? as usize;
    if sigs_len > 8 * 1024 {
        return Err(err("signature bundle over cap".into()));
    }
    let sigs = Bundle::deserialize(r.fixed_slice(sigs_len).map_err(malformed)?)
        .map_err(|e| err(e.to_string()))?;
    let keys_len = r.u32le().map_err(malformed)? as usize;
    if keys_len > 8 * 1024 {
        return Err(err("key bundle over cap".into()));
    }
    let keys = Bundle::deserialize(r.fixed_slice(keys_len).map_err(malformed)?)
        .map_err(|e| err(e.to_string()))?;
    r.expect_end().map_err(malformed)?;
    Ok((body, sigs, keys))
}

fn malformed(e: srct_core::error::Error) -> WorkError {
    WorkError::Malformed(e.to_string())
}
