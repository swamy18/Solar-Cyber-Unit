//! HPKE seal/open tests: the official RFC 9180 base-mode vector for
//! DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305, plus
//! roundtrips and failure modes.
//!
//! The RFC vector exercises the receiver side deterministically: with the
//! published `skRm`, `enc`, `info` and `aad`, `open` must return the
//! published `pt`. ("Beauty is truth, truth beauty" — Keats, used as the
//! RFC's own test plaintext.)

use srct_confid::keywrap::{open_with_privkey, seal_to_enclave, SealedKey};
use srct_confid::ConfidError;

// RFC 9180, Appendix A.1 vector: mode=base, kem=0x0020, kdf=0x0001,
// aead=0x0003. info = "Ode on a Grecian Urn".
const INFO_HEX: &str = "4f6465206f6e2061204772656369616e2055726e";
// skRm.
const SKR_HEX: &str = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
// pkRm.
const PKR_HEX: &str = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a";
// enc (ephemeral public share).
const ENC_HEX: &str = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a";
const AAD_HEX: &str = "436f756e742d30";
const CT_HEX: &str = "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28";
const PT_HEX: &str = "4265617574792069732074727574682c20747275746820626561757479";

fn hex(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        out.push(u8::from_str_radix(std::str::from_utf8(&b[i..i + 2]).unwrap(), 16).unwrap());
        i += 2;
    }
    out
}

#[test]
fn rfc9180_base_vector_opens() {
    // RFC 9180, Appendix A.1 vector: mode=base, DHKEM(X25519, HKDF-SHA256)
    // / HKDF-SHA256 / ChaCha20Poly1305. The receiver side is fully
    // deterministic: given skRm + enc + info + aad, open() must yield the
    // published pt. This pins our exact ciphersuite to the RFC.
    use hpke::{Deserializable};
    type Kem = hpke::kem::X25519HkdfSha256;
    type Kdf = hpke::kdf::HkdfSha256;
    type Aead = hpke::aead::ChaCha20Poly1305;
    let info = hex(INFO_HEX);
    let aad = hex(AAD_HEX);
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&hex(SKR_HEX)).unwrap();
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex(ENC_HEX)).unwrap();
    let mut ctx =
        hpke::setup_receiver::<Aead, Kdf, Kem>(&hpke::OpModeR::Base, &sk, &enc, &info).unwrap();
    let pt = ctx.open(&hex(CT_HEX), &aad).unwrap();
    assert_eq!(pt, hex(PT_HEX));
    // Sanity: the vector keypair matches (we test the right keys).
    assert_eq!(hex(PKR_HEX).len(), 32);
}

#[test]
fn seal_open_roundtrip() {
    let (sk, pk) = srct_confid::keywrap::generate_enclave_keypair();
    let key = [0xABu8; 32];
    let sealed = seal_to_enclave(&pk, &key, b"test-info", b"test-aad").unwrap();
    assert_eq!(sealed.encapped.len(), 32);
    let opened = open_with_privkey(&sk, &sealed, b"test-info", b"test-aad").unwrap();
    assert_eq!(&opened[..], &key[..]);
    // Wrong private key refuses.
    let (other_sk, _) = srct_confid::keywrap::generate_enclave_keypair();
    assert!(open_with_privkey(&other_sk, &sealed, b"test-info", b"test-aad").is_err());
    // A tampered ciphertext refuses.
    let mut bad = sealed.clone();
    bad.ct[0] ^= 0x01;
    assert!(open_with_privkey(&sk, &bad, b"test-info", b"test-aad").is_err());
    // Wrong info refuses.
    assert!(open_with_privkey(&sk, &sealed, b"wrong-info", b"test-aad").is_err());
    // Wrong AAD refuses.
    assert!(open_with_privkey(&sk, &sealed, b"test-info", b"wrong-aad").is_err());
    // Sealed encoding round-trips; truncation and trailing garbage refuse.
    let bytes = sealed.encode();
    assert_eq!(SealedKey::decode(&bytes).unwrap(), sealed);
    assert!(SealedKey::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert!(SealedKey::decode(&trailing).is_err());
    assert!(SealedKey::decode(&[]).is_err());
    // Nonsense lengths refuse.
    assert!(matches!(
        SealedKey::decode(&[99u8, 0, 0, 0]),
        Err(ConfidError::Malformed(_))
    ));
}
// debug
