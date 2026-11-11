//! Representation spaces and signed/sealed representation envelopes.
//!
//! A representation is only meaningful relative to the model that produced it:
//! two 8-dimensional vectors from different layers, tokenizers or model
//! families are not interchangeable. Every envelope therefore names a
//! [`ModelSpace`] and every adapter binds a source space to a target space.
//!
//! Privacy is explicit rather than implied:
//!
//! - a plain envelope carries `f32` values and is integrity-protected but not
//!   confidential;
//! - a sealed envelope encrypts the values with XChaCha20-Poly1305 under a
//!   caller-supplied 32-byte key. The space metadata and owner stay visible,
//!   so this protects the representation, not the fact that a translation
//!   happened. Key exchange is deliberately out of scope and must come from a
//!   KEM or an existing secure channel.

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

pub const ENVELOPE_VERSION: u8 = 1;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_DIM: u32 = 65_536;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

const DOM_SPACE: &[u8] = b"srct/cnnp/space/v1";
const DOM_ENVELOPE: &[u8] = b"srct/cnnp/envelope/v1";
const DOM_ENVELOPE_COMMIT: &[u8] = b"srct/cnnp/envelope-commit/v1";

/// Element type of the representation. Only `f32` is implemented; naming the
/// type prevents a quantized source space being silently read as floats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DType {
    F32 = 0,
}

impl DType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DType::F32),
            _ => None,
        }
    }
}

/// The identity of one representational space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelSpace {
    /// Content hash of the model that produced the representation.
    pub model_id: Hash,
    /// Tokenizer/preprocessing identity. Different tokenizers produce
    /// incompatible inputs even when the layer dimensions coincidentally match.
    pub tokenizer: Hash,
    /// Model family or architecture label (bounded, human-readable).
    pub architecture: String,
    /// Layer or output name inside that architecture.
    pub layer: String,
    /// Vector length.
    pub dim: u32,
    pub dtype: DType,
}

impl ModelSpace {
    pub fn validate(&self) -> Result<(), String> {
        if self.architecture.is_empty() || self.architecture.len() > MAX_NAME_LEN {
            return Err("architecture name is empty or over the 64-byte cap".into());
        }
        if self.layer.is_empty() || self.layer.len() > MAX_NAME_LEN {
            return Err("layer name is empty or over the 64-byte cap".into());
        }
        if self.dim == 0 || self.dim > MAX_DIM {
            return Err(format!("dimension {} is outside 1..={MAX_DIM}", self.dim));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
        w.fixed(&self.model_id)
            .fixed(&self.tokenizer)
            .u16le(self.architecture.len() as u16)
            .raw(self.architecture.as_bytes())
            .u16le(self.layer.len() as u16)
            .raw(self.layer.as_bytes())
            .u32le(self.dim)
            .u8(self.dtype.as_u8());
        w.into_vec()
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, String> {
        let model_id = r.fixed().map_err(|e| format!("space: {e}"))?;
        let tokenizer = r.fixed().map_err(|e| format!("space: {e}"))?;
        let architecture = read_name(r, "architecture")?;
        let layer = read_name(r, "layer")?;
        let dim = r.u32le().map_err(|e| format!("space: {e}"))?;
        let dtype = DType::from_u8(r.u8().map_err(|e| format!("space: {e}"))?)
            .ok_or_else(|| "space: unsupported dtype".to_string())?;
        let space = ModelSpace {
            model_id,
            tokenizer,
            architecture,
            layer,
            dim,
            dtype,
        };
        space.validate()?;
        Ok(space)
    }

    /// Content identity of the space, used by adapters and envelopes.
    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_SPACE, &[&self.encode()])
    }
}

fn read_name(r: &mut Reader<'_>, what: &str) -> Result<String, String> {
    let len = r.u16le().map_err(|e| format!("space: {e}"))? as usize;
    if len == 0 || len > MAX_NAME_LEN {
        return Err(format!("space: {what} length {len} out of range"));
    }
    let bytes = r.fixed_slice(len).map_err(|e| format!("space: {e}"))?;
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| format!("space: {what} is not utf-8"))
}

/// A sealed payload nonce. `None` means the values are plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seal {
    pub nonce: [u8; NONCE_LEN],
}

/// One signed representation produced by a model owner.
#[derive(Clone, Debug, PartialEq)]
pub struct RepresentationEnvelope {
    pub version: u8,
    pub space: ModelSpace,
    pub owner: Address,
    /// Present when the payload is encrypted.
    pub seal: Option<Seal>,
    /// Plain `f32` little-endian bytes, or ciphertext including the AEAD tag.
    pub payload: Vec<u8>,
    /// Commitment to the space, owner, seal and exact payload bytes.
    pub commitment: Hash,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl RepresentationEnvelope {
    /// Build and sign a plaintext envelope.
    pub fn plain(owner: &Wallet, space: ModelSpace, values: &[f32]) -> Result<Self, String> {
        space.validate()?;
        let payload = encode_values(values)?;
        if values.len() as u32 != space.dim {
            return Err(format!(
                "space names {} dimensions but {} values were supplied",
                space.dim,
                values.len()
            ));
        }
        let address = owner.address().map_err(|e| e.to_string())?;
        let mut envelope = RepresentationEnvelope {
            version: ENVELOPE_VERSION,
            space,
            owner: address,
            seal: None,
            payload,
            commitment: [0u8; 32],
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        envelope.commitment = envelope.recompute_commitment();
        let auth = Auth::sign(owner, &envelope.signing_hash()).map_err(|e| e.to_string())?;
        envelope.sigs = auth.sigs;
        envelope.keys = auth.keys;
        Ok(envelope)
    }

    /// Build and sign an encrypted envelope. The 32-byte key is supplied by the
    /// caller; this function does not perform key exchange.
    pub fn sealed(
        owner: &Wallet,
        space: ModelSpace,
        values: &[f32],
        key: &[u8; 32],
    ) -> Result<Self, String> {
        space.validate()?;
        if values.len() as u32 != space.dim {
            return Err(format!(
                "space names {} dimensions but {} values were supplied",
                space.dim,
                values.len()
            ));
        }
        let plaintext = encode_values(values)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let address = owner.address().map_err(|e| e.to_string())?;
        let aad = seal_aad(&space.hash(), &address, &nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| "cnnp: invalid encryption key".to_string())?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| "cnnp: encryption failed".to_string())?;
        let mut envelope = RepresentationEnvelope {
            version: ENVELOPE_VERSION,
            space,
            owner: address,
            seal: Some(Seal { nonce }),
            payload: ciphertext,
            commitment: [0u8; 32],
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        envelope.commitment = envelope.recompute_commitment();
        let auth = Auth::sign(owner, &envelope.signing_hash()).map_err(|e| e.to_string())?;
        envelope.sigs = auth.sigs;
        envelope.keys = auth.keys;
        Ok(envelope)
    }

    /// Recompute the payload commitment from the bytes actually carried.
    pub fn recompute_commitment(&self) -> Hash {
        let mut w = Writer::with_capacity(64 + NONCE_LEN + self.payload.len());
        w.fixed(&self.space.hash())
            .fixed(&self.owner)
            .u8(u8::from(self.seal.is_some()));
        if let Some(seal) = &self.seal {
            w.fixed(&seal.nonce);
        }
        w.u32le(self.payload.len() as u32).raw(&self.payload);
        sha256_dom(DOM_ENVELOPE_COMMIT, &[w.as_slice()])
    }

    /// Bytes the owner signs: the space, owner, payload kind and commitment.
    pub fn signing_hash(&self) -> Hash {
        let mut w = Writer::with_capacity(1 + 32 + 20 + 1 + 32);
        w.u8(self.version)
            .fixed(&self.space.hash())
            .fixed(&self.owner)
            .u8(u8::from(self.seal.is_some()))
            .fixed(&self.commitment);
        sha256_dom(DOM_ENVELOPE, &[w.as_slice()])
    }

    /// Verify structure, owner binding, signature and commitment.
    ///
    /// Encryption is not a signature substitute: a sealed envelope is still
    /// signed by its owner over the ciphertext commitment.
    pub fn verify(&self) -> Result<(), String> {
        if self.version != ENVELOPE_VERSION {
            return Err(format!("unsupported envelope version {}", self.version));
        }
        self.space.validate()?;
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.owner {
            return Err("envelope key bundle is not the owner".into());
        }
        if self.commitment != self.recompute_commitment() {
            return Err("envelope commitment does not match its payload".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.signing_hash())
            .map_err(|_| "envelope signature invalid".to_string())?;
        match self.seal {
            None => {
                if self.payload.len() != self.space.dim as usize * 4 {
                    return Err("plain envelope payload length does not match the space".into());
                }
            }
            Some(_) => {
                if self.payload.len() < TAG_LEN {
                    return Err("sealed envelope is shorter than its tag".into());
                }
            }
        }
        Ok(())
    }

    /// Decode the values. `key` is required exactly for sealed envelopes and
    /// must be `None` for plain ones, so a caller cannot be ambiguous about
    /// which privacy mode it expected.
    pub fn values(&self, key: Option<&[u8; 32]>) -> Result<Vec<f32>, String> {
        self.verify()?;
        match (&self.seal, key) {
            (None, None) => decode_values(&self.payload, self.space.dim),
            (None, Some(_)) => Err("plain envelope does not take a decryption key".into()),
            (Some(seal), None) => {
                let _ = seal;
                Err("sealed envelope requires a decryption key".into())
            }
            (Some(seal), Some(key)) => {
                let aad = seal_aad(&self.space.hash(), &self.owner, &seal.nonce);
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| "cnnp: invalid encryption key".to_string())?;
                let plaintext = cipher
                    .decrypt(
                        &XNonce::from(seal.nonce),
                        AeadPayload {
                            msg: &self.payload,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        "cnnp: wrong key, wrong space or tampered ciphertext".to_string()
                    })?;
                decode_values(&plaintext, self.space.dim)
            }
        }
    }

    /// Canonical transport encoding.
    pub fn encode(&self) -> Vec<u8> {
        let space = self.space.encode();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w =
            Writer::with_capacity(space.len() + self.payload.len() + sigs.len() + keys.len() + 128);
        w.u8(self.version)
            .u32le(space.len() as u32)
            .raw(&space)
            .fixed(&self.owner)
            .u8(u8::from(self.seal.is_some()));
        if let Some(seal) = &self.seal {
            w.fixed(&seal.nonce);
        }
        w.u32le(self.payload.len() as u32)
            .raw(&self.payload)
            .fixed(&self.commitment)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    /// Strict inverse of [`RepresentationEnvelope::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("envelope: {e}"))?;
        let space_len = r.u32le().map_err(|e| format!("envelope: {e}"))? as usize;
        if space_len > 4 * 1024 {
            return Err("envelope: space section over cap".into());
        }
        let mut sr = Reader::new(
            r.fixed_slice(space_len)
                .map_err(|e| format!("envelope: {e}"))?,
        );
        let space = ModelSpace::decode(&mut sr)?;
        sr.expect_end().map_err(|e| format!("envelope: {e}"))?;
        let owner = r.fixed().map_err(|e| format!("envelope: {e}"))?;
        let sealed = r.u8().map_err(|e| format!("envelope: {e}"))?;
        let seal = match sealed {
            0 => None,
            1 => {
                let nonce = r.fixed().map_err(|e| format!("envelope: {e}"))?;
                Some(Seal { nonce })
            }
            _ => return Err("envelope: bad seal flag".into()),
        };
        let payload_len = r.u32le().map_err(|e| format!("envelope: {e}"))? as usize;
        if payload_len > 64 * 1024 * 1024 {
            return Err("envelope: payload over cap".into());
        }
        let payload = r
            .fixed_slice(payload_len)
            .map_err(|e| format!("envelope: {e}"))?
            .to_vec();
        let commitment = r.fixed().map_err(|e| format!("envelope: {e}"))?;
        let sigs_len = r.u32le().map_err(|e| format!("envelope: {e}"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err("envelope: signature bundle over cap".into());
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|e| format!("envelope: {e}"))?,
        )
        .map_err(|e| format!("envelope: {e}"))?;
        let keys_len = r.u32le().map_err(|e| format!("envelope: {e}"))? as usize;
        if keys_len > 8 * 1024 {
            return Err("envelope: key bundle over cap".into());
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|e| format!("envelope: {e}"))?,
        )
        .map_err(|e| format!("envelope: {e}"))?;
        r.expect_end().map_err(|e| format!("envelope: {e}"))?;
        Ok(RepresentationEnvelope {
            version,
            space,
            owner,
            seal,
            payload,
            commitment,
            sigs,
            keys,
        })
    }
}

fn seal_aad(space_hash: &Hash, owner: &Address, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 20 + NONCE_LEN + 1);
    aad.extend_from_slice(space_hash);
    aad.extend_from_slice(owner);
    aad.extend_from_slice(nonce);
    aad.push(ENVELOPE_VERSION);
    aad
}

fn encode_values(values: &[f32]) -> Result<Vec<u8>, String> {
    if values.iter().any(|v| !v.is_finite()) {
        return Err("representation values must be finite".into());
    }
    let mut out = Vec::with_capacity(values.len() * 4);
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    Ok(out)
}

fn decode_values(bytes: &[u8], dim: u32) -> Result<Vec<f32>, String> {
    if bytes.len() != dim as usize * 4 {
        return Err("representation byte length does not match its dimension".into());
    }
    let mut out = Vec::with_capacity(dim as usize);
    for chunk in bytes.chunks_exact(4) {
        let value = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if !value.is_finite() {
            return Err("representation contains a non-finite value".into());
        }
        out.push(value);
    }
    Ok(out)
}
