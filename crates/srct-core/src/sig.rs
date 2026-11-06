//! Signature schemes and hybrid signature bundles. SPEC.md §1.2.
//!
//! Design doc feature 9 ("post-quantum signature agility") and feature 11
//! ("hybrid post-quantum signatures"). Both were previously aspirational: the
//! code had a `sig_scheme` byte but accepted exactly one value, so there was
//! no mechanism to migrate away from a broken primitive.
//!
//! A HYBRID bundle
//! ---------------
//! An input carries a *bundle* of signature components, not one signature.
//! Each component names its own scheme. A pure-ECDSA input is a bundle of one;
//! a post-quantum-ready input is a bundle of several, so that a quantum
//! adversary who forges the classical component still cannot produce a valid
//! transaction.
//!
//! Two rules make that safe rather than merely decorative:
//!
//! 1. **Every component must verify.** A bundle where only one component needs
//!    to check is not a hybrid at all: an attacker forges the one scheme they
//!    can break and strips the components they cannot. Requiring all of them
//!    means breaking any single primitive does not let an attacker through.
//!
//! 2. **The address commits to the whole key set.** `address_from_bundle`
//!    hashes the serialized public-key bundle, so a hybrid key set cannot be
//!    quietly replaced with a smaller one that omits the post-quantum half.
//!    This is the analogue of the key pinning the source paper had to add for
//!    Lightning, which has no address to commit to the key set.
//!
//! On the quantum argument
//! -----------------------
//! A CRQC breaks secp256k1 (Shor's algorithm), so a purely-ECDSA bundle is
//! forgeable by a future attacker. But recorded transactions stay valid: a
//! forger must *produce* new signatures, it cannot alter old ones, and old ones
//! were made before the CRQC existed. So this is a forward-looking defence for
//! newly created transactions, not a repair for history.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Address, DOM_ADDR};

/// secp256k1 with ECDSA. Scheme id 1, the only scheme before hybrid support.
pub const SCHEME_SECP256K1_ECDSA: u8 = 1;
/// secp256k1 with BIP-340 Schnorr. Same key material, different signature
/// scheme. Present to exercise the multi-scheme path end to end; it is not a
/// post-quantum scheme and adds no quantum resistance on its own.
pub const SCHEME_SECP256K1_SCHNORR: u8 = 2;
/// ML-DSA-65 (FIPS 204, NIST security level 3). The post-quantum scheme: a
/// Shor break of secp256k1 does not touch it. Public keys are 1952 bytes and
/// signatures 3309, both under [`MAX_COMPONENT_BYTES`] by design — the cap was
/// sized for exactly this. A bundle carrying schemes 1 and 3 is quantum-safe
/// if *either* primitive holds classically and safe against a CRQC because of
/// the lattice half; every component must still verify.
pub const SCHEME_ML_DSA_65: u8 = 3;
/// Encoded ML-DSA-65 verifying-key length, in bytes.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// Encoded ML-DSA-65 signature length, in bytes.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

/// Largest number of components in one bundle. Four is generous: a
/// post-quantum + classical pair is two, and the cap exists so a bundle cannot
/// be used to smuggle an unbounded amount of data per input.
pub const MAX_BUNDLE_COMPONENTS: usize = 4;

/// Largest single component, in bytes. ML-DSA-65 signatures are 3309 bytes and
/// ML-DSA-44 are 2420, so 4096 accommodates a real post-quantum signature with
/// room to spare rather than sizing the field to today's ECDSA.
pub const MAX_COMPONENT_BYTES: usize = 4096;

/// Total serialized budget for one bundle, both halves together.
pub const MAX_BUNDLE_BYTES: usize = 2 * MAX_BUNDLE_COMPONENTS * MAX_COMPONENT_BYTES + 512;

pub fn scheme_name(scheme: u8) -> &'static str {
    match scheme {
        SCHEME_SECP256K1_ECDSA => "secp256k1-ecdsa",
        SCHEME_SECP256K1_SCHNORR => "secp256k1-schnorr",
        SCHEME_ML_DSA_65 => "ml-dsa-65",
        _ => "unknown",
    }
}

/// True for a scheme this implementation can actually verify.
pub fn scheme_supported(scheme: u8) -> bool {
    matches!(
        scheme,
        SCHEME_SECP256K1_ECDSA | SCHEME_SECP256K1_SCHNORR | SCHEME_ML_DSA_65
    )
}

/// One signature plus the scheme that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub scheme: u8,
    #[serde(with = "crate::hexserde::var_bytes")]
    pub bytes: Vec<u8>,
}

impl Component {
    pub fn new(scheme: u8, bytes: Vec<u8>) -> Self {
        Component { scheme, bytes }
    }
}

/// An ordered, canonical list of signature components.
///
/// Order matters: it is part of the address preimage and of the transaction
/// body, so reordering components changes the txid. That is intentional —
/// canonical encoding is what keeps txids unique.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Bundle {
    pub components: Vec<Component>,
}

impl Bundle {
    pub fn single(scheme: u8, bytes: Vec<u8>) -> Self {
        Bundle {
            components: vec![Component::new(scheme, bytes)],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    pub fn schemes(&self) -> Vec<u8> {
        self.components.iter().map(|c| c.scheme).collect()
    }

    /// True when one component declares `scheme`. The migration rule
    /// (`Transaction::verify_input_pq`) is a one-line question over this:
    /// does the bundle carry a lattice component, yes or no.
    pub fn has_scheme(&self, scheme: u8) -> bool {
        self.components.iter().any(|c| c.scheme == scheme)
    }

    /// Validate the structural rules every bundle must satisfy, independent of
    /// any signature checking: non-empty, within the component and total-size
    /// caps, no repeated scheme (a duplicate adds bytes without adding
    /// independence), and every scheme recognised.
    pub fn validate(&self) -> Result<()> {
        if self.components.is_empty() {
            return Err(Error::EmptySignatureBundle);
        }
        if self.components.len() > MAX_BUNDLE_COMPONENTS {
            return Err(Error::TooManyBundleComponents {
                got: self.components.len(),
                cap: MAX_BUNDLE_COMPONENTS,
            });
        }
        let mut seen: Vec<u8> = Vec::with_capacity(self.components.len());
        for c in &self.components {
            if !scheme_supported(c.scheme) {
                return Err(Error::UnsupportedSigScheme(c.scheme));
            }
            if c.bytes.is_empty() || c.bytes.len() > MAX_COMPONENT_BYTES {
                return Err(Error::BadComponentLength(c.bytes.len()));
            }
            if seen.contains(&c.scheme) {
                return Err(Error::DuplicateBundleScheme(c.scheme));
            }
            seen.push(c.scheme);
        }
        if self.serialized_len() > MAX_BUNDLE_BYTES {
            return Err(Error::Malformed("signature bundle over total size cap"));
        }
        Ok(())
    }

    /// Byte length this bundle will occupy, used for the total-size cap.
    pub fn serialized_len(&self) -> usize {
        // count(1) + per component: scheme(1) + len(2) + bytes
        1 + self
            .components
            .iter()
            .map(|c| 3 + c.bytes.len())
            .sum::<usize>()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_len());
        out.push(self.components.len() as u8);
        for c in &self.components {
            out.push(c.scheme);
            out.extend_from_slice(&(c.bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(&c.bytes);
        }
        out
    }

    /// Parse a bundle, checking every bound *before* allocating for it.
    ///
    /// A length prefix here is attacker-controlled, so the cap is applied to
    /// the declared length and not to what the buffer actually holds: an
    /// oversized declaration must be rejected, not reserved for.
    ///
    /// A zero count parses to an empty bundle rather than an error, because
    /// unsigned inputs and the genesis coinbase legitimately carry one -- the
    /// coinbase spends nothing and is part of the merkle root, so its encoding
    /// has to round-trip. Non-emptiness is enforced by [`Bundle::validate`],
    /// which only runs for inputs that actually claim to spend.
    pub fn from_reader(r: &mut crate::ser::Reader<'_>) -> Result<Self> {
        let count = r.u8()? as usize;
        if count > MAX_BUNDLE_COMPONENTS {
            return Err(Error::TooManyBundleComponents {
                got: count,
                cap: MAX_BUNDLE_COMPONENTS,
            });
        }
        let mut components = Vec::with_capacity(count);
        for _ in 0..count {
            let scheme = r.u8()?;
            if !scheme_supported(scheme) {
                return Err(Error::UnsupportedSigScheme(scheme));
            }
            // Canonical-form enforcement at parse time, not only in
            // `validate()`: a duplicate scheme adds bytes without adding
            // independence, so it is never a hybrid. `verify_bundle` calls
            // `validate` and would catch this, but wire decoding that accepts
            // a non-canonical bundle lets two byte strings name one spend and
            // forces every downstream caller to remember the second check.
            if components.iter().any(|c: &Component| c.scheme == scheme) {
                return Err(Error::DuplicateBundleScheme(scheme));
            }
            let len = r.u16le()? as usize;
            if len == 0 || len > MAX_COMPONENT_BYTES {
                return Err(Error::BadComponentLength(len));
            }
            if len > r.remaining() {
                return Err(Error::Malformed("signature component exceeds buffer"));
            }
            let bytes = r.fixed_slice(len)?.to_vec();
            components.push(Component { scheme, bytes });
        }
        let bundle = Bundle { components };
        if bundle.serialized_len() > MAX_BUNDLE_BYTES {
            return Err(Error::Malformed("signature bundle over total size cap"));
        }
        Ok(bundle)
    }

    /// `SHA256(DOM_ADDR || serialized)[0..20]`
    ///
    /// Commits to the scheme of every key as well as the keys themselves, so
    /// an ECDSA-only key set and a hybrid one can never share an address.
    ///
    /// Uses `DOM_ADDR` at `/v2` rather than `/v1` because the preimage changed
    /// from a bare 33-byte pubkey to a serialized bundle. Domain tags are
    /// frozen per SPEC.md §0, so a changed preimage needs a new tag rather than
    /// reusing the old one for a different construction.
    pub fn address(&self) -> Result<Address> {
        let bytes = self.to_bytes();
        let full = sha256_dom(DOM_ADDR, &[&bytes]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&full[..20]);
        Ok(addr)
    }
}

/// Verify every component of `sigs` against the matching key in `keys`.
///
/// All components must pass: see the module docs on why a one-of-N rule would
/// not be a hybrid. Each signature component is matched to the key component
/// declaring the same scheme, so a bundle cannot verify a Schnorr signature
/// against a secp256k1 key.
pub fn verify_bundle(sigs: &Bundle, keys: &Bundle, msg: &[u8; 32]) -> Result<()> {
    sigs.validate()?;
    keys.validate()?;

    if sigs.components.len() != keys.components.len() {
        return Err(Error::BundleKeyMismatch {
            sigs: sigs.components.len(),
            keys: keys.components.len(),
        });
    }

    for sig in &sigs.components {
        let key = keys
            .components
            .iter()
            .find(|k| k.scheme == sig.scheme)
            .ok_or(Error::MissingKeyForScheme(sig.scheme))?;
        verify_one(sig.scheme, &key.bytes, &sig.bytes, msg).map_err(|e| match e {
            Error::BadSignature { .. } => Error::BadSignature { scheme: sig.scheme },
            other => other,
        })?;
    }
    Ok(())
}

fn verify_one(scheme: u8, pubkey: &[u8], sig: &[u8], msg: &[u8; 32]) -> Result<()> {
    match scheme {
        SCHEME_SECP256K1_ECDSA => {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            let bad = Error::BadSignature { scheme };
            if sig.len() != 64 {
                return Err(Error::BadComponentLength(sig.len()));
            }
            if pubkey.len() != 33 {
                return Err(Error::BadComponentLength(pubkey.len()));
            }
            let key =
                k256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| Error::BadPubkey)?;
            let parsed = k256::ecdsa::Signature::from_slice(sig).map_err(|_| bad.clone())?;
            // `normalize_s` returns Some only when the signature is *high*-s,
            // i.e. malleable. Reject those so txids stay canonical.
            if parsed.normalize_s().is_some() {
                return Err(bad);
            }
            key.verify_prehash(msg, &parsed).map_err(|_| bad)
        }
        SCHEME_SECP256K1_SCHNORR => {
            // `verify_raw`, not `verify`: the digest here is already a hash, and
            // BIP-340's `verify` would hash it a second time. The signer used
            // `sign_prehash`, so verification has to match that. k256 exposes
            // no `PrehashVerifier` impl for schnorr, so this is the entry point
            // that takes the digest as-is.
            let bad = Error::BadSignature { scheme };
            if sig.len() != 64 {
                return Err(Error::BadComponentLength(sig.len()));
            }
            if pubkey.len() != 32 {
                return Err(Error::BadComponentLength(pubkey.len()));
            }
            let key =
                k256::schnorr::VerifyingKey::from_bytes(pubkey).map_err(|_| Error::BadPubkey)?;
            let parsed = k256::schnorr::Signature::try_from(sig).map_err(|_| bad.clone())?;
            key.verify_raw(msg, &parsed).map_err(|_| bad)
        }
        SCHEME_ML_DSA_65 => verify_ml_dsa(pubkey, sig, msg).map_err(|e| match e {
            Error::BadComponentLength(_) | Error::BadPubkey => e,
            _ => Error::BadSignature { scheme },
        }),
        other => Err(Error::UnsupportedSigScheme(other)),
    }
}

/// Verify one ML-DSA-65 signature, shared by the bundle path and the
/// checkpoint-sidecar path so the two cannot disagree on what "valid" means.
///
/// FIPS 204 verification over the 32-byte digest as the message. The digest is
/// already domain-separated upstream, so the ML-DSA context is empty: no
/// second domain tag inside the primitive. Lengths are refused before any
/// lattice work, so a truncated component cannot become a resource sink.
pub fn verify_ml_dsa(pubkey: &[u8], sig: &[u8], msg: &[u8; 32]) -> Result<()> {
    use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, Verifier as _, VerifyingKey};
    if sig.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(Error::BadComponentLength(sig.len()));
    }
    if pubkey.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(Error::BadComponentLength(pubkey.len()));
    }
    let parsed = Signature::<MlDsa65>::try_from(sig).map_err(|_| Error::BadSignature {
        scheme: SCHEME_ML_DSA_65,
    })?;
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pubkey).map_err(|_| Error::BadPubkey)?;
    let key = VerifyingKey::<MlDsa65>::decode(&enc);
    key.verify(msg, &parsed).map_err(|_| Error::BadSignature {
        scheme: SCHEME_ML_DSA_65,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecdsa_component() -> Component {
        Component::new(SCHEME_SECP256K1_ECDSA, vec![0xAB; 64])
    }

    #[test]
    fn a_bundle_must_not_be_empty() {
        assert!(matches!(
            Bundle::default().validate(),
            Err(Error::EmptySignatureBundle)
        ));
    }

    #[test]
    fn a_duplicate_scheme_is_rejected() {
        // Repeating a scheme adds bytes without adding independence: it looks
        // like a hybrid but is not one.
        let b = Bundle {
            components: vec![ecdsa_component(), ecdsa_component()],
        };
        assert!(matches!(
            b.validate(),
            Err(Error::DuplicateBundleScheme(SCHEME_SECP256K1_ECDSA))
        ));
    }

    #[test]
    fn an_unknown_scheme_is_rejected() {
        let b = Bundle::single(99, vec![0; 64]);
        assert!(matches!(b.validate(), Err(Error::UnsupportedSigScheme(99))));
    }

    #[test]
    fn component_count_and_size_are_capped() {
        let many = Bundle {
            components: (0..=MAX_BUNDLE_COMPONENTS)
                .map(|i| Component::new(1 + (i % 2) as u8, vec![1u8; 64]))
                .collect(),
        };
        assert!(matches!(
            many.validate(),
            Err(Error::TooManyBundleComponents { .. })
        ));

        let huge = Bundle::single(SCHEME_SECP256K1_ECDSA, vec![0u8; MAX_COMPONENT_BYTES + 1]);
        assert!(matches!(huge.validate(), Err(Error::BadComponentLength(_))));

        let empty = Bundle::single(SCHEME_SECP256K1_ECDSA, vec![]);
        assert!(matches!(
            empty.validate(),
            Err(Error::BadComponentLength(0))
        ));
    }

    #[test]
    fn a_post_quantum_sized_signature_fits() {
        // The reason the fields are variable-length at all. ML-DSA-65 is 3309
        // bytes, which no fixed 64-byte field could ever hold.
        for len in [2420usize, 3309, 4096] {
            let b = Bundle::single(200, vec![0u8; len]);
            // 200 is not implemented yet, so this must fail on the scheme, not
            // on the length -- proving the size check is not what rejected it.
            assert!(
                matches!(b.validate(), Err(Error::UnsupportedSigScheme(200))),
                "a {len}-byte component was rejected for the wrong reason"
            );
            assert!(len <= MAX_COMPONENT_BYTES);
        }
    }

    #[test]
    fn bundles_round_trip() {
        let b = Bundle {
            components: vec![
                ecdsa_component(),
                Component::new(SCHEME_SECP256K1_SCHNORR, vec![0xCD; 64]),
            ],
        };
        b.validate().unwrap();
        let bytes = b.to_bytes();
        let mut r = crate::ser::Reader::new(&bytes);
        let back = Bundle::from_reader(&mut r).unwrap();
        assert!(r.is_done(), "trailing bytes after bundle");
        assert_eq!(back, b);
        assert_eq!(back.schemes(), vec![1, 2]);
    }

    #[test]
    fn a_lying_length_prefix_is_rejected_before_allocating() {
        // Scheme 1, declared length 4000, but nothing follows it.
        let bytes = vec![1u8, SCHEME_SECP256K1_ECDSA, 0xA0, 0x0F];
        let mut r = crate::ser::Reader::new(&bytes);
        assert!(matches!(
            Bundle::from_reader(&mut r),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn an_overlarge_count_is_rejected_before_allocating() {
        let bytes = vec![200u8];
        let mut r = crate::ser::Reader::new(&bytes);
        assert!(matches!(
            Bundle::from_reader(&mut r),
            Err(Error::TooManyBundleComponents { .. })
        ));
    }

    #[test]
    fn a_duplicate_scheme_is_rejected_at_parse_time() {
        // Audit: `from_reader` accepted duplicate schemes and left the
        // canonical-form check to `validate()`. Wire decoding must reject a
        // non-canonical bundle itself so two byte strings never name one
        // spend.
        let b = Bundle {
            components: vec![ecdsa_component(), ecdsa_component()],
        };
        let bytes = b.to_bytes();
        let mut r = crate::ser::Reader::new(&bytes);
        assert!(matches!(
            Bundle::from_reader(&mut r),
            Err(Error::DuplicateBundleScheme(_))
        ));
    }

    #[test]
    fn the_address_commits_to_every_scheme_in_the_bundle() {
        let a = Bundle::single(SCHEME_SECP256K1_ECDSA, vec![0xAB; 64]);
        let b = Bundle::single(SCHEME_SECP256K1_ECDSA, vec![0xAB; 64]);
        assert_eq!(a.address().unwrap(), b.address().unwrap());

        // Same key bytes, different scheme id => different address, so an
        // ECDSA key set cannot masquerade as a hybrid one.
        let c = Bundle::single(SCHEME_SECP256K1_SCHNORR, vec![0xAB; 64]);
        assert_ne!(a.address().unwrap(), c.address().unwrap());

        // Different key bytes => different address.
        let d = Bundle::single(SCHEME_SECP256K1_ECDSA, vec![0xAC; 64]);
        assert_ne!(a.address().unwrap(), d.address().unwrap());
    }

    // --- Hybrid behaviour, with real keys -------------------------------
    //
    // These use a real wallet so the signatures are genuine, not fixtures.

    fn wallet() -> crate::wallet::Wallet {
        crate::wallet::Wallet::from_private_key_bytes(&[7u8; 32], "sig-test").unwrap()
    }

    /// A genuinely different key. `wallet()` is deterministic, so a second
    /// wallet built from the same scalar would be the same wallet.
    fn other_wallet() -> crate::wallet::Wallet {
        crate::wallet::Wallet::from_private_key_bytes(&[9u8; 32], "sig-test-other").unwrap()
    }

    fn hybrid_bundles(w: &crate::wallet::Wallet, msg: &[u8; 32]) -> (Bundle, Bundle) {
        let keys = Bundle {
            components: vec![
                Component::new(SCHEME_SECP256K1_ECDSA, w.pubkey().unwrap().to_vec()),
                Component::new(
                    SCHEME_SECP256K1_SCHNORR,
                    w.schnorr_pubkey().unwrap().to_vec(),
                ),
            ],
        };
        let sigs = Bundle {
            components: vec![
                Component::new(SCHEME_SECP256K1_ECDSA, w.sign_digest(msg).unwrap().to_vec()),
                Component::new(
                    SCHEME_SECP256K1_SCHNORR,
                    w.sign_schnorr(msg).unwrap().to_vec(),
                ),
            ],
        };
        (sigs, keys)
    }

    #[test]
    fn a_real_hybrid_bundle_verifies() {
        let w = wallet();
        let msg = crate::hash::sha256(&[b"hybrid test"]);
        let (sigs, keys) = hybrid_bundles(&w, &msg);
        sigs.validate().unwrap();
        keys.validate().unwrap();
        verify_bundle(&sigs, &keys, &msg).expect("a genuine hybrid must verify");
    }

    #[test]
    fn every_component_must_verify_not_just_one() {
        // The property that makes a hybrid a hybrid. A one-of-N rule would let
        // an attacker break one primitive and strip the rest, so corrupting any
        // single component must invalidate the whole bundle.
        let w = wallet();
        let msg = crate::hash::sha256(&[b"hybrid test"]);
        let (sigs, keys) = hybrid_bundles(&w, &msg);

        for victim in 0..sigs.components.len() {
            let mut broken = sigs.clone();
            broken.components[victim].bytes[0] ^= 0xFF;
            assert!(
                verify_bundle(&broken, &keys, &msg).is_err(),
                "corrupting component {victim} was accepted; a hybrid must fail if any part fails"
            );
        }
    }

    #[test]
    fn a_signature_cannot_be_verified_under_another_schemes_id() {
        let w = wallet();
        let msg = crate::hash::sha256(&[b"hybrid test"]);
        let (sigs, keys) = hybrid_bundles(&w, &msg);

        // Re-label the Schnorr signature as ECDSA while leaving its bytes
        // alone. Matching is by scheme id, so this routes the Schnorr bytes
        // into the ECDSA verifier with the 33-byte compressed key. If matching
        // were positional, or if the verifier ignored its scheme argument,
        // this would pass.
        let mut mislabelled = sigs.clone();
        mislabelled.components[1].scheme = SCHEME_SECP256K1_ECDSA;
        assert!(
            matches!(mislabelled.validate(), Err(Error::DuplicateBundleScheme(_))),
            "two components may not claim the same scheme"
        );

        // Keeping the ids distinct and simply swapping the two signatures is
        // *not* an attack: each signature still matches a key of its own
        // scheme. Verified explicitly so the distinction is pinned.
        let mut swapped = sigs.clone();
        swapped.components.swap(0, 1);
        verify_bundle(&swapped, &keys, &msg).expect("reordering valid signatures is legitimate");
    }

    #[test]
    fn a_mismatched_bundle_pair_is_rejected() {
        let w = wallet();
        let msg = crate::hash::sha256(&[b"hybrid test"]);
        let (sigs, keys) = hybrid_bundles(&w, &msg);

        // Unequal component counts are refused outright.
        let fewer = Bundle {
            components: vec![keys.components[0].clone()],
        };
        assert!(matches!(
            verify_bundle(&sigs, &fewer, &msg),
            Err(Error::BundleKeyMismatch { .. })
        ));

        // A signature by one key must not verify under a different key, even
        // when the scheme ids line up. This is the property that makes the
        // bundle meaningful rather than decorative.
        let other = other_wallet();
        let (_, other_keys) = hybrid_bundles(&other, &msg);
        assert!(
            verify_bundle(&sigs, &other_keys, &msg).is_err(),
            "a signature verified under the wrong key"
        );
    }

    #[test]
    fn a_single_scheme_bundle_still_verifies() {
        // Backwards compatibility: agility must not invalidate ordinary
        // single-scheme transactions, or every existing output becomes
        // unspendable the moment support ships.
        let w = wallet();
        let msg = crate::hash::sha256(&[b"legacy"]);
        let sigs = Bundle::single(
            SCHEME_SECP256K1_ECDSA,
            w.sign_digest(&msg).unwrap().to_vec(),
        );
        let keys = Bundle::single(SCHEME_SECP256K1_ECDSA, w.pubkey().unwrap().to_vec());
        verify_bundle(&sigs, &keys, &msg).expect("a plain ECDSA bundle must still work");
    }

    #[test]
    fn a_wallet_can_sign_either_shape_and_each_spends_from_its_own_address() {
        // The flag in `require_hybrid_signatures` only makes sense if both
        // shapes are actually producible and self-consistent.
        let w = wallet();
        let op = crate::tx::OutPoint {
            txid: [3u8; 64],
            index: 0,
        };
        let dest = [1u8; 20];

        for hybrid in [false, true] {
            let mut tx = crate::tx::Transaction::standard(
                vec![crate::tx::Input::unsigned(&op)],
                vec![crate::tx::Output {
                    value: 900,
                    address: dest,
                }],
            );
            w.sign_with(&mut tx, hybrid).unwrap();

            let owner = if hybrid {
                w.hybrid_address().unwrap()
            } else {
                w.ecdsa_address().unwrap()
            };
            tx.verify_input_any(0, &owner)
                .expect("own bundle must verify");

            // And it must not verify against the other shape's address: the
            // two are genuinely different accounts.
            let other = if hybrid {
                w.ecdsa_address().unwrap()
            } else {
                w.hybrid_address().unwrap()
            };
            assert!(
                matches!(
                    tx.verify_input_any(0, &other),
                    Err(crate::error::Error::WrongAddress)
                ),
                "hybrid={hybrid}: the two shapes must not share an address"
            );
        }
    }

    #[test]
    fn requiring_a_hybrid_rejects_a_single_scheme_input() {
        let w = wallet();
        let op = crate::tx::OutPoint {
            txid: [4u8; 64],
            index: 0,
        };
        let mut tx = crate::tx::Transaction::standard(
            vec![crate::tx::Input::unsigned(&op)],
            vec![crate::tx::Output {
                value: 900,
                address: w.ecdsa_address().unwrap(),
            }],
        );
        w.sign_with(&mut tx, false).unwrap();

        // Off by default, so existing transactions stay valid.
        assert!(tx.verify_input_any(0, &w.ecdsa_address().unwrap()).is_ok());
        // On, a single-scheme input is refused.
        assert!(matches!(
            tx.verify_input(0, &w.ecdsa_address().unwrap(), true),
            Err(crate::error::Error::HybridRequired)
        ));
        // And a hybrid input still passes when hybrids are required.
        w.sign_with(&mut tx, true).unwrap();
        assert!(tx
            .verify_input(0, &w.hybrid_address().unwrap(), true)
            .is_ok());
    }
}
