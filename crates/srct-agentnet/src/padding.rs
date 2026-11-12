//! Optional length-hiding for message plaintexts.
//!
//! Ciphertext length leaks plaintext length. These helpers frame a plaintext
//! with a 2-byte big-endian length prefix and zero-pad it to a small set of
//! buckets, so a relay sees only one of five sizes. The recipient strips the
//! frame after [`crate::message::MessageEnvelope::open`].
//!
//! Use is opt-in: [`crate::message::MessageEnvelope::seal`] still takes raw
//! bytes. Callers that want hiding call [`frame_padded`] before sealing and
//! [`unframe_padded`] after opening.

use crate::message::{MessageError, MAX_PLAINTEXT};

/// Padded plaintext sizes a relay can observe.
pub const PAD_BUCKETS: [usize; 5] = [64, 256, 1024, 4096, 65536];

/// Smallest bucket holding `len` bytes, or `None` past the cap.
pub fn padded_len(len: usize) -> Option<usize> {
    PAD_BUCKETS.into_iter().find(|b| *b >= len)
}

/// Frame `plaintext` (2-byte length prefix) and pad to the next bucket.
pub fn frame_padded(plaintext: &[u8]) -> Result<Vec<u8>, MessageError> {
    if plaintext.len() + 2 > MAX_PLAINTEXT {
        return Err(MessageError::Malformed(
            "plaintext is too long to pad".into(),
        ));
    }
    let framed = 2 + plaintext.len();
    let bucket = padded_len(framed)
        .ok_or_else(|| MessageError::Malformed("plaintext is too long to pad".into()))?;
    let mut out = vec![0u8; bucket];
    out[..2].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
    out[2..framed].copy_from_slice(plaintext);
    Ok(out)
}

/// Strip a [`frame_padded`] frame. Non-zero padding is refused.
pub fn unframe_padded(framed: &[u8]) -> Result<Vec<u8>, MessageError> {
    if framed.len() < 2 || !PAD_BUCKETS.contains(&framed.len()) {
        return Err(MessageError::Malformed(
            "padded frame has a bad size".into(),
        ));
    }
    let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    if len + 2 > framed.len() {
        return Err(MessageError::Malformed(
            "padded frame length is lying".into(),
        ));
    }
    if framed[2 + len..].iter().any(|b| *b != 0) {
        return Err(MessageError::Malformed(
            "padded frame has non-zero padding".into(),
        ));
    }
    Ok(framed[2..2 + len].to_vec())
}
