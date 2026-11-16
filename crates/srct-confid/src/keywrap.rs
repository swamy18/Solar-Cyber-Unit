//! HPKE key wrapping (RFC 9180), one fixed ciphersuite.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305,
//! base mode. The suite is fixed at the type level — no other combination
//! is instantiated anywhere in this crate, so a caller cannot negotiate
//! down to anything weaker.
//!
//! `info` binds the release context (purpose, workload, session nonce).
//! `aad` binds any additional envelope fields. Both are authenticated but
//! not encrypted; the data key itself is the only secret in the output.

use hpke::{Deserializable, Kem as KemTrait, Serializable};
use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256};
use zeroize::Zeroizing;

use crate::ConfidError;

/// Domain separator prefix for `info` strings built by [`crate::release`].
pub const HPKE_INFO: &[u8] = b"srct/confid/v1";

/// A data key sealed to an enclave ephemeral key: the 32-byte
/// encapsulation plus the AEAD ciphertext (key bytes + 16-byte tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedKey {
    pub encapped: Vec<u8>,
    pub ct: Vec<u8>,
}

impl SealedKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.encapped.len() + self.ct.len());
        out.extend_from_slice(&(self.encapped.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.encapped);
        out.extend_from_slice(&(self.ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ct);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ConfidError> {
        let malformed = |d: &str| ConfidError::Malformed(format!("sealed key {d}"));
        if bytes.len() < 8 {
            return Err(malformed("truncated"));
        }
        let enc_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let rest = &bytes[4..];
        if enc_len != 32 || rest.len() < enc_len + 4 {
            return Err(malformed("bad encapsulation length"));
        }
        let encapped = rest[..enc_len].to_vec();
        let ct_len = u32::from_le_bytes([
            rest[enc_len],
            rest[enc_len + 1],
            rest[enc_len + 2],
            rest[enc_len + 3],
        ]) as usize;
        if ct_len == 0 || ct_len > 1024 {
            return Err(malformed("bad ciphertext length"));
        }
        let ct_start = enc_len + 4;
        if rest.len() != ct_start + ct_len {
            return Err(malformed("trailing bytes"));
        }
        Ok(SealedKey {
            encapped,
            ct: rest[ct_start..].to_vec(),
        })
    }
}

/// Generate a fresh X25519 enclave-style ephemeral keypair. The private
/// half is returned zeroizing: it wipes itself when dropped.
pub fn generate_enclave_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let mut rng = rand::thread_rng();
    let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
    let mut skb = Zeroizing::new([0u8; 32]);
    skb.copy_from_slice(&sk.to_bytes());
    let mut pkb = [0u8; 32];
    pkb.copy_from_slice(&pk.to_bytes());
    (skb, pkb)
}

/// Seal a 32-byte data key to the enclave's public key.
pub fn seal_to_enclave(
    recipient_pub: &[u8; 32],
    key: &[u8; 32],
    info: &[u8],
    aad: &[u8],
) -> Result<SealedKey, ConfidError> {
    let pk = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(recipient_pub)
        .map_err(|e| ConfidError::Crypto(format!("bad enclave pubkey: {e:?}")))?;
    let mut rng = rand::thread_rng();
    let (encapped, mut sender) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
            &hpke::OpModeS::Base,
            &pk,
            info,
            &mut rng,
        )
        .map_err(|e| ConfidError::Crypto(format!("hpke setup failed: {e:?}")))?;
    let ct = sender
        .seal(key, aad)
        .map_err(|e| ConfidError::Crypto(format!("hpke seal failed: {e:?}")))?;
    Ok(SealedKey {
        encapped: encapped.to_bytes().to_vec(),
        ct,
    })
}

/// Open a sealed data key with the enclave private key. Any tampering,
/// wrong key, wrong info or wrong AAD fails here — never partially.
pub fn open_with_privkey(
    recipient_priv: &[u8; 32],
    sealed: &SealedKey,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ConfidError> {
    let sk = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(recipient_priv)
        .map_err(|e| ConfidError::Crypto(format!("bad enclave privkey: {e:?}")))?;
    let enc = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&sealed.encapped)
        .map_err(|e| ConfidError::Crypto(format!("bad encapsulation: {e:?}")))?;
    let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &hpke::OpModeR::Base,
        &sk,
        &enc,
        info,
    )
    .map_err(|e| ConfidError::Crypto(format!("hpke setup failed: {e:?}")))?;
    let pt = receiver
        .open(&sealed.ct, aad)
        .map_err(|e| ConfidError::Crypto(format!("hpke open failed: {e:?}")))?;
    if pt.len() != 32 {
        return Err(ConfidError::Crypto("hpke open returned wrong length".into()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    Ok(key)
}
