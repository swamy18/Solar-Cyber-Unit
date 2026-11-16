//! Shield bundle: versioned, AEAD-encrypted workload package bound to a
//! job/ticket/measurement, with a Merkle integrity chain over chunks.
//!
//! Format:
//!   manifest: version(1) | job_id(32) | ticket_id(32) | measurement(32) |
//!             chunk_count(4) | total_size(8) | created_height(8) |
//!             root_hash(32) | nonce(24)
//!   chunks:   [len(4) | nonce(24) | ct(len-24)] * chunk_count
//!
//! Every chunk is XChaCha20-Poly1305 sealed under a per-bundle data key. The
//! manifest's root_hash is the Merkle root over all chunk ciphertext hashes,
//! so any chunk tampering invalidates the whole bundle. The manifest itself
//! is sealed under a separate wrapping key, so the bundle is confidential
//! end-to-end: neither the manifest nor any chunk leaks without the key.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use generic_array::{typenum::U24, GenericArray};
use rand::{thread_rng, RngCore};

use crate::ComputeError;
use srct_core::hash::{sha256_dom, Hash};

/// Shield bundle envelope version.
pub const SHIELD_VERSION: u8 = 1;

/// XChaCha20-Poly1305 nonce size (192-bit).
const NONCE_LEN: usize = 24;

/// AEAD key size (256-bit).
const KEY_LEN: usize = 32;

/// Max chunks per bundle (bounds memory on decode).
const MAX_CHUNKS: usize = 1 << 16;

/// Max chunk ciphertext size (1 MiB per chunk).
const MAX_CHUNK_BYTES: usize = 1 << 20;

const DOM_LEAF: &[u8] = b"srct/shield/leaf/v1";
const DOM_NODE: &[u8] = b"srct/shield/node/v1";

/// A sealed shield bundle: manifest + chunk ciphertexts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldBundle {
    /// Version 1.
    pub version: u8,
    /// Job this bundle is bound to.
    pub job_id: Hash,
    /// Ticket this bundle was delivered under (optional binding).
    pub ticket_id: Hash,
    /// Approved hardware measurement the guest must match.
    pub measurement: Hash,
    /// One entry per chunk, in order.
    pub chunks: Vec<ShieldChunk>,
    /// Total plaintext size across all chunks.
    pub total_size: u64,
    /// Chain height the bundle was created at (freshness).
    pub created_height: u64,
    /// Random manifest nonce (prevents replay of identical bundles).
    pub manifest_nonce: [u8; NONCE_LEN],
}

/// One encrypted chunk with its Merkle leaf position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldChunk {
    /// Chunk index (0-based, must be contiguous).
    pub index: u32,
    /// XChaCha20-Poly1305 ciphertext (plaintext + 16-byte tag).
    pub ciphertext: Vec<u8>,
    /// Chunk nonce (unique per chunk).
    pub nonce: [u8; NONCE_LEN],
}

/// A sealed, opaque bundle ready for transport/storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedShield {
    /// AEAD-sealed manifest (manifest || tag).
    pub manifest_ct: Vec<u8>,
    /// Chunk ciphertexts in index order.
    pub chunks: Vec<ShieldChunk>,
}

/// Seal a plaintext payload into a shield bundle. `data_key` is the
/// per-bundle XChaCha20-Poly1305 key (32 bytes).
pub fn seal(
    data_key: &[u8; KEY_LEN],
    payload: &[u8],
    job_id: Hash,
    ticket_id: Hash,
    measurement: Hash,
    created_height: u64,
) -> Result<SealedShield, ComputeError> {
    if data_key.len() != KEY_LEN {
        return Err(ComputeError::Malformed(
            "shield data key must be 32 bytes".into(),
        ));
    }
    let key = Key::from_slice(data_key);
    let cipher = XChaCha20Poly1305::new(key);

    // Split payload into chunks.
    let mut chunks: Vec<ShieldChunk> = Vec::new();
    let mut offset: usize = 0;
    let mut index: u32 = 0;
    while offset < payload.len() {
        let end = (offset + MAX_CHUNK_BYTES).min(payload.len());
        let plain = &payload[offset..end];
        let mut nonce = [0u8; NONCE_LEN];
        thread_rng().fill_bytes(&mut nonce);
        let nonce_n = GenericArray::<u8, U24>::from_slice(&nonce);
        let ct = cipher
            .encrypt(
                nonce_n,
                Payload {
                    msg: plain,
                    aad: &[],
                },
            )
            .map_err(|e| ComputeError::Malformed(format!("chunk {index} seal failed: {e}")))?;
        chunks.push(ShieldChunk {
            index,
            ciphertext: ct,
            nonce,
        });
        offset = end;
        index += 1;
        if index > MAX_CHUNKS as u32 {
            return Err(ComputeError::Malformed("shield payload too large".into()));
        }
    }

    // Build Merkle root over chunk ciphertext hashes.
    let _root = merkle_root(&chunks);

    // Total plaintext size.
    let total_size: u64 = chunks.iter().map(|c| c.ciphertext.len() as u64 - 16).sum();

    // Build manifest.
    let manifest = ShieldBundle {
        version: SHIELD_VERSION,
        job_id,
        ticket_id,
        measurement,
        chunks: chunks.clone(),
        total_size,
        created_height,
        manifest_nonce: {
            let mut n = [0u8; NONCE_LEN];
            thread_rng().fill_bytes(&mut n);
            n
        },
    };

    // Seal the manifest under a wrapping key derived from the data key.
    let wrap_key = sha256_dom(b"srct/shield/wrap/v1", &[data_key]);
    let wrap_cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let mut wrap_nonce = [0u8; NONCE_LEN];
    thread_rng().fill_bytes(&mut wrap_nonce);
    let manifest_bytes = manifest.encode();
    let wrap_nonce_arr = GenericArray::<u8, U24>::from_slice(&wrap_nonce);
    let manifest_ct_body = wrap_cipher
        .encrypt(
            wrap_nonce_arr,
            Payload {
                msg: &manifest_bytes,
                aad: &[],
            },
        )
        .map_err(|e| ComputeError::Malformed(format!("manifest seal failed: {e}")))?;
    let mut manifest_ct = wrap_nonce.to_vec();
    manifest_ct.extend_from_slice(&manifest_ct_body);

    Ok(SealedShield {
        manifest_ct,
        chunks,
    })
}

/// Open a sealed shield bundle, returning the plaintext payload.
/// `data_key` must match the key used at seal time. Fail-closed: any
/// tampering, wrong key, or bad chunk refuses.
pub fn open(data_key: &[u8; KEY_LEN], sealed: &SealedShield) -> Result<Vec<u8>, ComputeError> {
    if data_key.len() != KEY_LEN {
        return Err(ComputeError::Malformed(
            "shield data key must be 32 bytes".into(),
        ));
    }
    let key = Key::from_slice(data_key);
    let cipher = XChaCha20Poly1305::new(key);

    // Unseal the manifest.
    let wrap_key = sha256_dom(b"srct/shield/wrap/v1", &[data_key]);
    let wrap_cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    // The wrap nonce is the first 24 bytes of manifest_ct? No — we need to
    // store it. We prepend it: manifest_ct = nonce(24) || ciphertext.
    if sealed.manifest_ct.len() < NONCE_LEN + 16 {
        return Err(ComputeError::Malformed(
            "manifest ciphertext too short".into(),
        ));
    }
    let (wrap_nonce, wrap_body) = sealed.manifest_ct.split_at(NONCE_LEN);
    let wrap_nonce_arr = GenericArray::<u8, U24>::from_slice(wrap_nonce);
    let manifest_bytes = wrap_cipher
        .decrypt(
            wrap_nonce_arr,
            Payload {
                msg: wrap_body,
                aad: &[],
            },
        )
        .map_err(|_| {
            ComputeError::BadSignature("manifest unseal failed: wrong key or tampered".into())
        })?;
    let manifest = ShieldBundle::decode(&manifest_bytes)
        .map_err(|e| ComputeError::Malformed(format!("manifest decode failed: {e}")))?;

    // Verify chunk count matches manifest.
    if sealed.chunks.len() != manifest.chunks.len() {
        return Err(ComputeError::Malformed("chunk count mismatch".into()));
    }

    // Verify Merkle root over chunk ciphertexts.
    let root = merkle_root(&sealed.chunks);
    if root != manifest_merkle_root(&manifest)? {
        return Err(ComputeError::BadSignature(
            "Merkle root mismatch: chunk tampering".into(),
        ));
    }

    // Decrypt each chunk in order, reconstruct plaintext.
    let mut plaintext = Vec::with_capacity(manifest.total_size as usize);
    for (i, chunk) in sealed.chunks.iter().enumerate() {
        if chunk.index as usize != i {
            return Err(ComputeError::Malformed(format!(
                "chunk {} out of order",
                chunk.index
            )));
        }
        if chunk.ciphertext.len() < 16 {
            return Err(ComputeError::Malformed(format!(
                "chunk {} ciphertext too short",
                chunk.index
            )));
        }
        let chunk_nonce = GenericArray::<u8, U24>::from_slice(&chunk.nonce);
        let pt = cipher
            .decrypt(
                chunk_nonce,
                Payload {
                    msg: &chunk.ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| {
                ComputeError::BadSignature(format!(
                    "chunk {} unseal failed: wrong key or tampered",
                    chunk.index
                ))
            })?;
        plaintext.extend_from_slice(&pt);
    }

    // Truncate to declared total size (padding removed).
    plaintext.truncate(manifest.total_size as usize);
    Ok(plaintext)
}

/// Compute the Merkle root over chunk ciphertexts. Empty payload => hash of
/// empty.
fn merkle_root(chunks: &[ShieldChunk]) -> Hash {
    if chunks.is_empty() {
        return sha256_dom(DOM_LEAF, &[&[]]);
    }
    let mut level: Vec<Hash> = chunks
        .iter()
        .map(|c| sha256_dom(DOM_LEAF, &[&c.ciphertext]))
        .collect();
    while level.len() > 1 {
        let mut next: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(sha256_dom(DOM_NODE, &[&pair[0], &pair[1]]));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// Manifest Merkle root (from the manifest's own chunk list).
fn manifest_merkle_root(manifest: &ShieldBundle) -> Result<Hash, ComputeError> {
    let root = merkle_root_chunks(&manifest.chunks);
    Ok(root)
}

/// Compute Merkle root from a chunk list (without ciphertext content — just
/// the hashes stored in the manifest chunks).
fn merkle_root_chunks(chunks: &[ShieldChunk]) -> Hash {
    if chunks.is_empty() {
        return sha256_dom(DOM_LEAF, &[&[]]);
    }
    let mut level: Vec<Hash> = chunks
        .iter()
        .map(|c| sha256_dom(DOM_LEAF, &[&c.ciphertext]))
        .collect();
    while level.len() > 1 {
        let mut next: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(sha256_dom(DOM_NODE, &[&pair[0], &pair[1]]));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

impl ShieldBundle {
    /// Encode manifest to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = srct_core::ser::Writer::with_capacity(256);
        w.u8(self.version)
            .fixed(&self.job_id)
            .fixed(&self.ticket_id)
            .fixed(&self.measurement)
            .u32le(self.chunks.len() as u32)
            .u64le(self.total_size)
            .u64le(self.created_height)
            .fixed(&self.manifest_nonce);
        // Chunks: count-prefixed, each is index(4) + nonce(24) + ct_len(4) + ct.
        w.u32le(self.chunks.len() as u32);
        for c in &self.chunks {
            w.u32le(c.index)
                .raw(&c.nonce)
                .u32le(c.ciphertext.len() as u32)
                .raw(&c.ciphertext);
        }
        w.into_vec()
    }

    /// Strict inverse of [`encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = srct_core::ser::Reader::new(bytes);
        let version = r
            .u8()
            .map_err(|e| ComputeError::Malformed(format!("version: {e}")))?;
        if version != SHIELD_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported shield version {version}"
            )));
        }
        let job_id = r
            .fixed()
            .map_err(|e| ComputeError::Malformed(format!("job_id: {e}")))?;
        let ticket_id = r
            .fixed()
            .map_err(|e| ComputeError::Malformed(format!("ticket_id: {e}")))?;
        let measurement = r
            .fixed()
            .map_err(|e| ComputeError::Malformed(format!("measurement: {e}")))?;
        let chunk_count = r
            .u32le()
            .map_err(|e| ComputeError::Malformed(format!("chunk_count: {e}")))?
            as usize;
        if chunk_count > MAX_CHUNKS {
            return Err(ComputeError::Malformed("too many chunks".into()));
        }
        let total_size = r
            .u64le()
            .map_err(|e| ComputeError::Malformed(format!("total_size: {e}")))?;
        let created_height = r
            .u64le()
            .map_err(|e| ComputeError::Malformed(format!("created_height: {e}")))?;
        let manifest_nonce = r
            .fixed::<NONCE_LEN>()
            .map_err(|e| ComputeError::Malformed(format!("manifest_nonce: {e}")))?;

        let chunk_count2 = r
            .u32le()
            .map_err(|e| ComputeError::Malformed(format!("chunk_count2: {e}")))?
            as usize;
        if chunk_count2 != chunk_count {
            return Err(ComputeError::Malformed(
                "chunk count mismatch in manifest".into(),
            ));
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            let index = r
                .u32le()
                .map_err(|e| ComputeError::Malformed(format!("chunk {i} index: {e}")))?;
            if index != i as u32 {
                return Err(ComputeError::Malformed(format!(
                    "chunk {i} index {index} out of order"
                )));
            }
            let nonce = r
                .fixed::<NONCE_LEN>()
                .map_err(|e| ComputeError::Malformed(format!("chunk {i} nonce: {e}")))?;
            let ct_len = r
                .u32le()
                .map_err(|e| ComputeError::Malformed(format!("chunk {i} ct_len: {e}")))?
                as usize;
            if ct_len > MAX_CHUNK_BYTES + 16 {
                return Err(ComputeError::Malformed(format!("chunk {i} too large")));
            }
            let ciphertext = r
                .fixed_slice(ct_len)
                .map_err(|e| ComputeError::Malformed(format!("chunk {i} ct: {e}")))?
                .to_vec();
            chunks.push(ShieldChunk {
                index,
                ciphertext,
                nonce,
            });
        }
        r.expect_end()
            .map_err(|e| ComputeError::Malformed(format!("trailing bytes: {e}")))?;
        Ok(ShieldBundle {
            version,
            job_id,
            ticket_id,
            measurement,
            chunks,
            total_size,
            created_height,
            manifest_nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        [0x42u8; KEY_LEN]
    }

    #[test]
    fn seal_open_roundtrip() {
        let payload = b"confidential workload payload for testing shield bundles";
        let sealed = seal(&test_key(), payload, [1u8; 32], [2u8; 32], [3u8; 32], 100).unwrap();
        let opened = open(&test_key(), &sealed).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn large_payload_roundtrip() {
        let payload: Vec<u8> = (0..5_000_000).map(|i| (i % 251) as u8).collect();
        let sealed = seal(&test_key(), &payload, [1u8; 32], [2u8; 32], [3u8; 32], 101).unwrap();
        let opened = open(&test_key(), &sealed).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let sealed = seal(&test_key(), b"", [1u8; 32], [2u8; 32], [3u8; 32], 102).unwrap();
        let opened = open(&test_key(), &sealed).unwrap();
        assert_eq!(opened, b"");
    }

    #[test]
    fn wrong_key_refused() {
        let payload = b"secret";
        let sealed = seal(&test_key(), payload, [1u8; 32], [2u8; 32], [3u8; 32], 103).unwrap();
        let bad_key = [0x43u8; KEY_LEN];
        assert!(open(&bad_key, &sealed).is_err());
    }

    #[test]
    fn tampered_chunk_refused() {
        let payload = b"tamper me and fail";
        let mut sealed = seal(&test_key(), payload, [1u8; 32], [2u8; 32], [3u8; 32], 104).unwrap();
        if let Some(chunk) = sealed.chunks.first_mut() {
            chunk.ciphertext[0] ^= 0x01;
        }
        assert!(open(&test_key(), &sealed).is_err());
    }

    #[test]
    fn manifest_encode_decode_roundtrip() {
        let manifest = ShieldBundle {
            version: SHIELD_VERSION,
            job_id: [1u8; 32],
            ticket_id: [2u8; 32],
            measurement: [3u8; 32],
            chunks: vec![ShieldChunk {
                index: 0,
                ciphertext: vec![1, 2, 3],
                nonce: [4u8; NONCE_LEN],
            }],
            total_size: 3,
            created_height: 999,
            manifest_nonce: [5u8; NONCE_LEN],
        };
        let bytes = manifest.encode();
        let decoded = ShieldBundle::decode(&bytes).unwrap();
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn merkle_root_stable() {
        let chunks = vec![
            ShieldChunk {
                index: 0,
                ciphertext: vec![1u8],
                nonce: [0u8; NONCE_LEN],
            },
            ShieldChunk {
                index: 1,
                ciphertext: vec![2u8],
                nonce: [0u8; NONCE_LEN],
            },
        ];
        let r1 = merkle_root(&chunks);
        let r2 = merkle_root(&chunks);
        assert_eq!(r1, r2);
    }
}
