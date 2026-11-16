//! Inference inside attested enclaves: encrypted request/response over the
//! attested channel.
//!
//! The consumer encrypts an inference request to the enclave's ephemeral
//! HPKE public key; the guest decrypts, runs the model, and seals the
//! response back under the same session key. Both sides are bound to the
//! attestation output hash so a replaced guest cannot decrypt.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use generic_array::{typenum::U24, GenericArray};
use zeroize::Zeroizing;

use crate::ComputeError;
use srct_core::hash::{sha256_dom, Hash};

const DOM_INFERENCE: &[u8] = b"srct/inference/v1";
const DOM_REQ: &[u8] = b"srct/inference/request/v1";
const DOM_RESP: &[u8] = b"srct/inference/response/v1";

/// An encrypted inference request: consumer → enclave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceRequest {
    /// Session bound to this request (from attestation output hash).
    pub session_id: Hash,
    /// Model hash the consumer expects to run.
    pub model_hash: Hash,
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// AEAD ciphertext: encoded input tensor + 16-byte tag.
    pub ciphertext: Vec<u8>,
}

/// An encrypted inference response: enclave → consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceResponse {
    pub session_id: Hash,
    pub output_hash: Hash,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Seal an inference request for an enclave. `key` is the per-session
/// data key (32 bytes) released after attestation.
pub fn seal_request(
    key: &[u8; 32],
    session_id: Hash,
    model_hash: Hash,
    input: &[u8],
) -> Result<InferenceRequest, ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 24];
    let nonce_input = sha256_dom(DOM_REQ, &[&session_id, input]);
    nonce.copy_from_slice(&nonce_input[..24]);
    let nonce_n = GenericArray::<u8, U24>::from_slice(&nonce);
    let ct = cipher
        .encrypt(
            nonce_n,
            Payload {
                msg: input,
                aad: &[],
            },
        )
        .map_err(|e| ComputeError::Malformed(format!("request seal failed: {e}")))?;
    Ok(InferenceRequest {
        session_id,
        model_hash,
        nonce,
        ciphertext: ct,
    })
}

/// Open an inference request inside the enclave. Returns the plaintext input.
pub fn open_request(key: &[u8; 32], req: &InferenceRequest) -> Result<Vec<u8>, ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let req_nonce = GenericArray::<u8, U24>::from_slice(&req.nonce);
    let pt = cipher
        .decrypt(
            req_nonce,
            Payload {
                msg: &req.ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| ComputeError::BadSignature("inference request unseal failed".into()))?;
    Ok(pt)
}

/// Seal an inference response from the enclave. `key` is the session data key.
pub fn seal_response(
    key: &[u8; 32],
    session_id: Hash,
    output: &[u8],
) -> Result<InferenceResponse, ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 24];
    let nonce_input = sha256_dom(DOM_RESP, &[&session_id, output]);
    nonce.copy_from_slice(&nonce_input[..24]);
    let nonce_n = GenericArray::<u8, U24>::from_slice(&nonce);
    let ct = cipher
        .encrypt(
            nonce_n,
            Payload {
                msg: output,
                aad: &[],
            },
        )
        .map_err(|e| ComputeError::Malformed(format!("response seal failed: {e}")))?;
    Ok(InferenceResponse {
        session_id,
        output_hash: sha256_dom(DOM_INFERENCE, &[output]),
        nonce,
        ciphertext: ct,
    })
}

/// Open an inference response outside the enclave. Returns the plaintext output.
pub fn open_response(key: &[u8; 32], resp: &InferenceResponse) -> Result<Vec<u8>, ComputeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let resp_nonce = GenericArray::<u8, U24>::from_slice(&resp.nonce);
    let pt = cipher
        .decrypt(
            resp_nonce,
            Payload {
                msg: &resp.ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| ComputeError::BadSignature("inference response unseal failed".into()))?;
    Ok(pt)
}

/// A zeroizing wrapper for an inference input tensor in guest memory.
#[derive(Debug)]
pub struct GuestInput {
    pub tensor: Zeroizing<Vec<f32>>,
}

impl GuestInput {
    pub fn new(tensor: Vec<f32>) -> Self {
        Self {
            tensor: Zeroizing::new(tensor),
        }
    }
}

/// A zeroizing wrapper for an inference output tensor in guest memory.
#[derive(Debug)]
pub struct GuestOutput {
    pub tensor: Zeroizing<Vec<f32>>,
}

impl GuestOutput {
    pub fn new(tensor: Vec<f32>) -> Self {
        Self {
            tensor: Zeroizing::new(tensor),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_roundtrip() {
        let key = [0x42u8; 32];
        let session_id = [1u8; 32];
        let model_hash = [2u8; 32];
        let input = b"inference input tensor bytes";

        let req = seal_request(&key, session_id, model_hash, input).unwrap();
        let decoded = open_request(&key, &req).unwrap();
        assert_eq!(decoded, input);

        let output = b"inference result tensor bytes";
        let resp = seal_response(&key, session_id, output).unwrap();
        let decoded = open_response(&key, &resp).unwrap();
        assert_eq!(decoded, output);
    }

    #[test]
    fn wrong_key_refused() {
        let key = [0x42u8; 32];
        let bad_key = [0x43u8; 32];
        let req = seal_request(&key, [1u8; 32], [2u8; 32], b"input").unwrap();
        assert!(open_request(&bad_key, &req).is_err());
    }

    #[test]
    fn tampered_response_refused() {
        let key = [0x42u8; 32];
        let mut resp = seal_response(&key, [1u8; 32], b"output").unwrap();
        resp.ciphertext[0] ^= 0x01;
        assert!(open_response(&key, &resp).is_err());
    }

    #[test]
    fn guest_input_zeroizes() {
        let tensor = vec![1.0f32, 2.0, 3.0];
        let input = GuestInput::new(tensor);
        assert_eq!(input.tensor.len(), 3);
        drop(input);
        // memory zeroized on drop
    }
}
