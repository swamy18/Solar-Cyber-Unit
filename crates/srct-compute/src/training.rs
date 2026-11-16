//! Training scope: multi-GPU, parallel per-enclave jobs with encrypted
//! checkpoints and resume.
//!
//! A training job is split into per-GPU shards, each running inside its own
//! attested enclave. Checkpoints are encrypted under per-slice session keys
//! and can be resumed from any verified checkpoint height.

use chacha20poly1305::{XChaCha20Poly1305, KeyInit, Key};
use chacha20poly1305::aead::{Aead, Payload};
use generic_array::{GenericArray, typenum::U24};
use hex::FromHex as _;

use srct_core::hash::{Hash, sha256_dom};
use crate::ComputeError;

const DOM_CHECKPOINT: &[u8] = b"srct/training/checkpoint/v1";
const DOM_RESUME: &[u8] = b"srct/training/resume/v1";

/// A training job shard: one GPU, one enclave, one slice of the batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrainingShard {
    /// GPU index within the training job (0..num_gpus).
    pub gpu_index: u32,
    /// Total GPUs in the job.
    pub num_gpus: u32,
    /// Shard's slice of the dataset (start, end) in samples.
    pub sample_range: (u64, u64),
    /// Enclave session this shard runs in.
    pub session_id: Hash,
    /// Checkpoint height this shard last saved at.
    pub last_checkpoint_height: u64,
}

/// Encrypted checkpoint: model weights + optimizer state, sealed under a
/// per-slice session key. Bound to a specific GPU shard and height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedCheckpoint {
    pub shard_id: Hash,
    pub height: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    /// Hash of the plaintext checkpoint (for integrity without decryption).
    pub plaintext_hash: Hash,
}

/// Seal a checkpoint for a training shard.
pub fn seal_checkpoint(
    key: &[u8; 32],
    shard_id: Hash,
    height: u64,
    plaintext: &[u8],
) -> Result<EncryptedCheckpoint, ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 24];
    let nonce_input = sha256_dom(DOM_CHECKPOINT, &[&shard_id, &height.to_le_bytes(), plaintext]);
    nonce.copy_from_slice(&nonce_input[..24]);
    let nonce_n = GenericArray::<u8, U24>::from_slice(&nonce);
    let ct = cipher.encrypt(nonce_n, Payload { msg: plaintext, aad: &[] })
        .map_err(|e| ComputeError::Malformed(format!("checkpoint seal failed: {e}")))?;
    Ok(EncryptedCheckpoint {
        shard_id,
        height,
        nonce,
        ciphertext: ct,
        plaintext_hash: sha256_dom(DOM_CHECKPOINT, &[plaintext]),
    })
}

/// Open an encrypted checkpoint, returning the plaintext.
pub fn open_checkpoint(
    key: &[u8; 32],
    cp: &EncryptedCheckpoint,
) -> Result<Vec<u8>, ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let cp_nonce = GenericArray::<u8, U24>::from_slice(&cp.nonce);
    let pt = cipher.decrypt(cp_nonce, Payload { msg: &cp.ciphertext, aad: &[] })
        .map_err(|_| ComputeError::BadSignature("checkpoint unseal failed".into()))?;
    // Verify plaintext hash matches (integrity even if decryption succeeded).
    if sha256_dom(DOM_CHECKPOINT, &[&pt]) != cp.plaintext_hash {
        return Err(ComputeError::BadSignature("checkpoint plaintext hash mismatch".into()));
    }
    Ok(pt)
}

/// A resume token: proves a shard can resume from a specific checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeToken {
    pub shard_id: Hash,
    pub checkpoint_height: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Seal a resume token under the session key.
pub fn seal_resume_token(
    key: &[u8; 32],
    shard_id: Hash,
    checkpoint_height: u64,
) -> Result<ResumeToken, ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 24];
    let nonce_input = sha256_dom(DOM_RESUME, &[&shard_id, &checkpoint_height.to_le_bytes()]);
    nonce.copy_from_slice(&nonce_input[..24]);
    let payload = format!("resume:{}:{}", hex::encode(shard_id), checkpoint_height);
    let nonce_n = GenericArray::<u8, U24>::from_slice(&nonce);
    let ct = cipher.encrypt(nonce_n, Payload { msg: payload.as_bytes(), aad: &[] })
        .map_err(|e| ComputeError::Malformed(format!("resume token seal failed: {e}")))?;
    Ok(ResumeToken {
        shard_id,
        checkpoint_height,
        nonce,
        ciphertext: ct,
    })
}

/// Open a resume token.
pub fn open_resume_token(
    key: &[u8; 32],
    token: &ResumeToken,
) -> Result<(Hash, u64), ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let token_nonce = GenericArray::<u8, U24>::from_slice(&token.nonce);
    let pt = cipher.decrypt(token_nonce, Payload { msg: &token.ciphertext, aad: &[] })
        .map_err(|_| ComputeError::BadSignature("resume token unseal failed".into()))?;
    let text = String::from_utf8(pt).map_err(|e| ComputeError::Malformed(format!("resume token not utf-8: {e}")))?;
    let parts: Vec<&str> = text.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "resume" {
        return Err(ComputeError::Malformed("resume token malformed".into()));
    }
    let shard_id = Hash::from_hex(parts[1])
        .map_err(|e| ComputeError::Malformed(format!("resume token bad shard id: {e}")))?;
    let height = parts[2].parse::<u64>()
        .map_err(|e| ComputeError::Malformed(format!("resume token bad height: {e}")))?;
    Ok((shard_id, height))
}

/// Split a training job into per-GPU shards.
pub fn split_into_shards(
    num_gpus: u32,
    total_samples: u64,
) -> Result<Vec<TrainingShard>, ComputeError> {
    if num_gpus == 0 {
        return Err(ComputeError::Malformed("training needs at least one GPU".into()));
    }
    if total_samples == 0 {
        return Err(ComputeError::Malformed("training needs at least one sample".into()));
    }
    let mut shards = Vec::with_capacity(num_gpus as usize);
    let samples_per_gpu = total_samples / num_gpus as u64;
    let remainder = total_samples % num_gpus as u64;
    let mut start: u64 = 0;
    for gpu_index in 0..num_gpus {
        let mut end = start + samples_per_gpu;
        if gpu_index < remainder as u32 {
            end += 1;
        }
        shards.push(TrainingShard {
            gpu_index,
            num_gpus,
            sample_range: (start, end),
            session_id: [0u8; 32], // filled in after attestation
            last_checkpoint_height: 0,
        });
        start = end;
    }
    Ok(shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let shard_id = [1u8; 32];
        let checkpoint = b"model weights + optimizer state at step 1000";

        let cp = seal_checkpoint(&key, shard_id, 1000, checkpoint).unwrap();
        let decoded = open_checkpoint(&key, &cp).unwrap();
        assert_eq!(decoded, checkpoint);
    }

    #[test]
    fn wrong_key_refused() {
        let key = [0x42u8; 32];
        let bad_key = [0x43u8; 32];
        let cp = seal_checkpoint(&key, [1u8; 32], 1000, b"checkpoint").unwrap();
        assert!(open_checkpoint(&bad_key, &cp).is_err());
    }

    #[test]
    fn tampered_checkpoint_refused() {
        let key = [0x42u8; 32];
        let mut cp = seal_checkpoint(&key, [1u8; 32], 1000, b"checkpoint").unwrap();
        cp.ciphertext[0] ^= 0x01;
        assert!(open_checkpoint(&key, &cp).is_err());
    }

    #[test]
    fn resume_token_roundtrip() {
        let key = [0x42u8; 32];
        let shard_id = [1u8; 32];
        let token = seal_resume_token(&key, shard_id, 500).unwrap();
        let (sid, height) = open_resume_token(&key, &token).unwrap();
        assert_eq!(sid, shard_id);
        assert_eq!(height, 500);
    }

    #[test]
    fn split_shards_even() {
        let shards = split_into_shards(4, 1000).unwrap();
        assert_eq!(shards.len(), 4);
        assert_eq!(shards[0].sample_range, (0, 250));
        assert_eq!(shards[3].sample_range, (750, 1000));
    }

    #[test]
    fn split_shards_remainder() {
        let shards = split_into_shards(3, 1000).unwrap();
        assert_eq!(shards.len(), 3);
        // 1000 / 3 = 333 rem 1 → first shard gets 334
        assert_eq!(shards[0].sample_range, (0, 334));
        assert_eq!(shards[1].sample_range, (334, 667));
        assert_eq!(shards[2].sample_range, (667, 1000));
    }

    #[test]
    fn split_shards_zero_gpus_refused() {
        assert!(split_into_shards(0, 100).is_err());
    }
}
