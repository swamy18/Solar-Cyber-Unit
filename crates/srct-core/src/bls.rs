//! Real BLS12-381 signatures over `blst` (SPEC.md §14.5).
//!
//! §14.4 defined the checkpoint *envelope* and verified it with a mock. This
//! module is the real thing: min-signature BLS (keys in G1, signatures in G2),
//! aggregate verification through a single pairing check, and key derivation
//! fixed by the IETF draft so tests are byte-for-byte reproducible.
//!
//! **This module does not activate M5 consensus.** Nothing in `Chain::submit`
//! calls into it; it exists so that when validator-set economics are resolved
//! (§14.6, unresolved), the cryptographic core is already real, tested against
//! malformed input, and shared. Until then a checkpoint's cryptographic
//! validity and its consensus relevance are separate questions, answered by
//! separate code.
//!
//! Wire rules (normative, §14.5):
//! - DST: `SRCT_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` — the IETF suite string
//!   under the protocol namespace. Everything Solar Cyber Unit ever signs with BLS signs
//!   under a `SRCT_`-prefixed DST, and each message type gets its own.
//! - Public keys: 48-byte compressed G1, validated at deserialization.
//! - Signatures: 96-byte compressed G2, validated at verification time, never
//!   trusted from the wire.
//! - Key generation: IETF `KeyGen` (HKDF-SHA256, "BLS-SIG-KEYGEN-SALT-"),
//!   so a fixed 32-byte seed yields the same key on every platform forever.

use blst::{min_pk, BLST_ERROR};

// Min-PK scheme (§14.5): public keys in G1 (48 bytes), signatures in G2
// (96 bytes). In blst terms that is the `min_pk` variant for both sides —
// `min_sig` is the opposite layout and is deliberately not used.

use crate::bls_checkpoint::{BlsPublicKey, BlsSignature};
use crate::hash::sha256_dom;
use zeroize::Zeroize as _;

/// Domain separation tag for all checkpoint signing (§14.5).
///
/// The IETF `BLS12381G2_XMD:SHA-256_SSWU_RO_` suite string, namespaced. Do not
/// sign anything else under this tag; new message types take a new `SRCT_`
/// prefix so signatures cannot be transplanted between protocols.
pub const DST_CHECKPOINT: &[u8] = b"SRCT_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// Domain tag for validator-set hashing (§14.5, set identity).
const DOM_SET_HASH: u8 = 0xB2;

/// Errors from parsing or verification. Every variant says what was wrong —
/// "invalid" without a reason is how a verifier gets blamed for a peer's bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// The 48/96 bytes do not decode to a valid curve point in the right
    /// subgroup, or are infinity.
    BadPoint { what: &'static str },
    /// blst rejected the signature or the aggregate.
    BadSignature { detail: String },
    /// A seed failed key derivation (only possible for seeds of the wrong
    /// length; fixed 32-byte seeds in this crate always derive).
    BadSeed,
}

impl std::fmt::Display for BlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlsError::BadPoint { what } => {
                write!(f, "{what} does not decode to a valid curve point")
            }
            BlsError::BadSignature { detail } => write!(f, "signature rejected: {detail}"),
            BlsError::BadSeed => write!(f, "seed is unusable for key derivation"),
        }
    }
}

impl std::error::Error for BlsError {}

/// A BLS secret key. Held un-serialized: keys move as 32-byte scalars, and the
/// `SecretKey` type refuses to be built from anything else.
///
/// Deliberately **not** `PartialEq`/`Eq`: comparing secret keys invites
/// non-constant-time checks on key material, and nothing in the protocol needs
/// it — `signing::Committee` compares *public* keys to refuse a duplicate,
/// which is both sufficient and safe. `Debug` is inherited from the inner type,
/// so anything holding one must not `Debug`-format it;
/// `signing::ValidatorKey` redacts for exactly that reason.
#[derive(Clone)]
pub struct SecretKey(min_pk::SecretKey);

/// Never render key material: the inner `blst` type derives `Debug`, so an
/// inherited impl would print the scalar into logs and backtraces.
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Wipe the wrapped `blst` scalar on drop. `min_pk::SecretKey` zeroizes its own
/// storage, so forwarding here keeps every owned copy wiped.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretKey {
    /// Derive a key from a 32-byte seed using the IETF `KeyGen` procedure
    /// (draft-irtf-cfrg-bls-signature-05 §2.3): HKDF-SHA256 with salt
    /// "BLS-SIG-KEYGEN-SALT-", IKM = seed ‖ I2OSP(len, 2), L = 48, then
    /// `sk = OS2IP(prk) mod r`. Deterministic, so a fixed seed gives the same
    /// key on every platform and every run — which is what makes the test
    /// fixtures in this crate byte-reproducible.
    pub fn derive(seed: &[u8; 32]) -> Result<SecretKey, BlsError> {
        // The seed-bearing input wipes on drop; it must not linger after key
        // generation returns.
        let mut ikm = zeroize::Zeroizing::new([0u8; 34]);
        ikm[..32].copy_from_slice(seed);
        ikm[32..].copy_from_slice(&[0x00, 0x20]); // I2OSP(len(seed), 2)
        let sk = min_pk::SecretKey::key_gen(&ikm[..], &[]).map_err(|_| BlsError::BadSeed)?;
        Ok(SecretKey(sk))
    }

    /// The compressed G1 public key, wire form (§14.5).
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk().compress())
    }

    /// Sign a 32-byte message (§14.5: the message is always the pre-hashed
    /// payload hash, never raw payload bytes) under the checkpoint DST.
    pub fn sign(&self, message: &crate::hash::Hash) -> BlsSignature {
        let sig = self.0.sign(message, DST_CHECKPOINT, &[]);
        BlsSignature(sig.compress())
    }

    /// The raw scalar, for tests that need to prove two derived keys differ.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The raw scalar, so a caller can persist a key. Companion to
    /// [`Self::from_scalar`]; see that method for why a key file stores this
    /// rather than the seed it was derived from.
    pub fn scalar(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Rebuild a key from its 32-byte scalar.
    ///
    /// The counterpart to a key file: `SecretKey::derive` maps a *seed* through
    /// the IETF `KeyGen` procedure, which makes the key a pure function of that
    /// seed. That is right for reproducible fixtures and wrong for custody, so a
    /// persisted validator key stores the scalar instead and is rebuilt here.
    ///
    /// Refuses a scalar that is zero or does not reduce into the group order:
    /// `blst` would carry it happily into signing and produce certificates that
    /// no verification accepts, which looks exactly like a network fault.
    pub fn from_scalar(scalar: &[u8; 32]) -> Result<SecretKey, BlsError> {
        let sk = min_pk::SecretKey::from_bytes(scalar).map_err(|_| BlsError::BadSeed)?;
        // Check for a zero scalar (blst would carry it through to signing,
        // producing a certificate every peer rejects). The temporary bytes
        // are wrapped so they wipe rather than sit in a freed stack slot.
        let bytes = zeroize::Zeroizing::new(sk.to_bytes());
        if bytes.iter().all(|b| *b == 0) {
            return Err(BlsError::BadSeed);
        }
        Ok(SecretKey(sk))
    }
}

/// Validate a compressed G1 point. Rejects infinity, wrong subgroup, and
/// bytes that are not a point at all — a key that fails this cannot enter a
/// validator set (§14.5).
///
/// `key_validate` is `from_bytes` **plus** `validate()`; `uncompress` alone
/// only decodes the point and would accept one in the wrong subgroup, which is
/// exactly the input a rogue-key attack feeds an aggregate verification.
pub fn validate_public_key(pk: &BlsPublicKey) -> Result<min_pk::PublicKey, BlsError> {
    min_pk::PublicKey::key_validate(pk.as_bytes())
        .map_err(|_| BlsError::BadPoint { what: "public key" })
}

/// Validate a compressed G2 point without verifying any message: decode,
/// reject the point at infinity, and check the subgroup.
///
/// As with keys, `uncompress` on its own skips the subgroup check — blst's
/// `sig_validate` is the decode plus that check, so a signature that reaches
/// verification has already been proven to be a usable curve point.
pub fn validate_signature(sig: &BlsSignature) -> Result<min_pk::Signature, BlsError> {
    min_pk::Signature::sig_validate(sig.as_bytes(), true)
        .map_err(|_| BlsError::BadPoint { what: "signature" })
}

/// The production verifier. Aggregate verification is one pairing check over
/// the sum of the signers' keys — cost is independent of signer count, which
/// is the entire reason BLS is the right primitive for a 21-member committee.
pub struct RealBls;

/// Shared production verifier instance, for contexts (like [`Chain`]) that
/// must name *which* verifier they use without carrying a fresh one around.
pub static REAL_BLS: RealBls = RealBls;

impl RealBls {
    /// Verify a single signature.
    pub fn verify(pk: &BlsPublicKey, message: &crate::hash::Hash, sig: &BlsSignature) -> bool {
        let Ok(pk) = validate_public_key(pk) else {
            return false;
        };
        let Ok(sig) = validate_signature(sig) else {
            return false;
        };
        sig.verify(true, message, DST_CHECKPOINT, &[], &pk, false) == BLST_ERROR::BLST_SUCCESS
    }

    /// Aggregate distinct signatures (same message) into one G2 point.
    ///
    /// `sigs` may arrive in any order; the aggregate is order-independent
    /// because point addition is commutative.
    pub fn aggregate(sigs: &[BlsSignature]) -> Result<BlsSignature, BlsError> {
        if sigs.is_empty() {
            return Err(BlsError::BadSignature {
                detail: "nothing to aggregate".into(),
            });
        }
        let mut parsed = Vec::with_capacity(sigs.len());
        for s in sigs {
            parsed.push(validate_signature(s)?);
        }
        let pts: Vec<&min_pk::Signature> = parsed.iter().collect();
        let agg = min_pk::AggregateSignature::aggregate(&pts, false).map_err(|e| {
            BlsError::BadSignature {
                detail: format!("aggregate failed: {e:?}"),
            }
        })?;
        Ok(BlsSignature(agg.to_signature().compress()))
    }

    /// The verifier the checkpoint machinery consumes. An empty signer list is
    /// refused (an aggregate over nothing proves nothing) rather than treated
    /// as trivially valid.
    pub fn verify_aggregate(
        public_keys: &[BlsPublicKey],
        message: &crate::hash::Hash,
        sig: &BlsSignature,
    ) -> bool {
        if public_keys.is_empty() {
            return false;
        }
        let mut pks = Vec::with_capacity(public_keys.len());
        for pk in public_keys {
            match validate_public_key(pk) {
                Ok(p) => pks.push(p),
                Err(_) => return false,
            }
        }
        let Ok(sig) = validate_signature(sig) else {
            return false;
        };
        let pk_refs: Vec<&min_pk::PublicKey> = pks.iter().collect();
        // fast_aggregate_verify: sum the keys, one pairing against the
        // aggregate. The first argument is the signature group check — it is
        // `true` so a point outside the G2 subgroup is refused here rather
        // than assumed; key validation already happened above. (blst's own
        // doc for this call assumes the keys carry proof of possession, which
        // `bond::check_bond_tx` now requires at bond time.)
        sig.fast_aggregate_verify(true, message, DST_CHECKPOINT, &pk_refs)
            == BLST_ERROR::BLST_SUCCESS
    }
}

impl crate::bls_checkpoint::BlsVerifier for RealBls {
    fn verify_aggregate(
        &self,
        public_keys: &[BlsPublicKey],
        message: &crate::hash::Hash,
        sig: &BlsSignature,
    ) -> bool {
        Self::verify_aggregate(public_keys, message, sig)
    }
}

/// Validator-set identity (§14.5): `sha256_dom([0xB2], [n(u32) ‖ pk_1 ‖ … ‖ pk_n])`
/// over the set's sorted keys. Two nodes that disagree about who the validators
/// are compute different set hashes and reject each other's checkpoints, which
/// is the property that makes an accidental fork-of-the-set loud instead of
/// silent.
pub fn validator_set_hash(keys: &[BlsPublicKey]) -> crate::hash::Hash {
    // Sort exactly as `ValidatorSet::new` does, so the identity of a set is a
    // property of its membership, not of the caller's insertion order. The
    // first version hashed caller order and two views of the same committee
    // computed two different identities — a fork of the set that would have
    // stayed silent until checkpoints started bouncing.
    let mut sorted: Vec<&BlsPublicKey> = keys.iter().collect();
    sorted.sort_by_key(|k| k.0);
    let mut buf = Vec::with_capacity(4 + 48 * sorted.len());
    buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for k in sorted {
        buf.extend_from_slice(k.as_bytes());
    }
    sha256_dom(&[DOM_SET_HASH], &[&buf])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_checkpoint::{CheckpointPayload, MockBls, ValidatorSet};
    use crate::hash::{hash_to_hex, Hash};

    /// Fixed seeds committed here, so every run derives the same keys and the
    /// same signatures (§14.5 fixtures). These are test keys with no value.
    const SEED_A: [u8; 32] = [0x11; 32];
    const SEED_B: [u8; 32] = [0x22; 32];
    const SEED_C: [u8; 32] = [0x33; 32];

    fn keys_for(seeds: &[[u8; 32]]) -> (Vec<SecretKey>, Vec<BlsPublicKey>) {
        let sks: Vec<SecretKey> = seeds
            .iter()
            .map(|s| SecretKey::derive(s).unwrap())
            .collect();
        let pks = sks.iter().map(|sk| sk.public_key()).collect();
        (sks, pks)
    }

    #[test]
    fn key_derivation_is_deterministic_and_distinct() {
        let a1 = SecretKey::derive(&SEED_A).unwrap();
        let a2 = SecretKey::derive(&SEED_A).unwrap();
        let b = SecretKey::derive(&SEED_B).unwrap();
        assert_eq!(a1.to_bytes(), a2.to_bytes(), "same seed, same key");
        assert_ne!(
            a1.to_bytes(),
            b.to_bytes(),
            "different seeds, different keys"
        );
        assert_ne!(a1.public_key().as_bytes(), b.public_key().as_bytes());
    }

    /// The byte-level fixture: this hex is what SEED_A must derive to, on this
    /// and every future platform. If blst or the KDF ever changes underneath
    /// us, this test is the tripwire.
    #[test]
    fn derived_public_key_matches_committed_fixture() {
        let sk = SecretKey::derive(&SEED_A).unwrap();
        let pk = sk.public_key();
        // Hash the 48-byte key so the fixture is a stable 32-byte string.
        let mut h = [0u8; 32];
        h.copy_from_slice(&crate::hash::sha256(&[pk.as_bytes()]));
        let hex = hash_to_hex(&h);
        // Committed fixture — do not regenerate this value without a SPEC note.
        assert_eq!(
            hex, "072d1be8f179066edc73fd3bcfdddeed756726acff99478fff54357ab576cff8",
            "SEED_A's public key changed; §14.5 fixtures are broken"
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (sks, pks) = keys_for(&[SEED_A]);
        let msg: Hash = crate::hash::sha256(&[b"some checkpoint payload"]);
        let sig = sks[0].sign(&msg);
        assert!(RealBls::verify(&pks[0], &msg, &sig));
    }

    #[test]
    fn a_tampered_message_is_rejected() {
        let (sks, pks) = keys_for(&[SEED_A]);
        let msg: Hash = crate::hash::sha256(&[b"payload one"]);
        let sig = sks[0].sign(&msg);
        let tampered: Hash = crate::hash::sha256(&[b"payload two"]);
        assert!(!RealBls::verify(&pks[0], &tampered, &sig));
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        let (sks, pks) = keys_for(&[SEED_A, SEED_B]);
        let msg: Hash = crate::hash::sha256(&[b"payload"]);
        let sig = sks[0].sign(&msg);
        assert!(
            !RealBls::verify(&pks[1], &msg, &sig),
            "B's key must not verify A's signature"
        );
    }

    #[test]
    fn aggregation_is_order_independent_and_verifies() {
        let (sks, pks) = keys_for(&[SEED_A, SEED_B, SEED_C]);
        let msg: Hash = crate::hash::sha256(&[b"three-signer checkpoint"]);
        let sigs: Vec<BlsSignature> = sks.iter().map(|sk| sk.sign(&msg)).collect();

        let agg_fwd = RealBls::aggregate(&sigs).unwrap();
        let agg_rev = RealBls::aggregate(&sigs.iter().rev().cloned().collect::<Vec<_>>()).unwrap();
        assert_eq!(
            agg_fwd.as_bytes(),
            agg_rev.as_bytes(),
            "aggregation is commutative"
        );

        // Verify through the trait the checkpoint machinery uses: the claim
        // "these three signed" must hold for the aggregate of all three.
        assert!(RealBls::verify_aggregate(&pks, &msg, &agg_fwd));
        // But the same aggregate must NOT verify against a subset claim —
        // fast_aggregate_verify sums the claimed keys, so a 3-signer aggregate
        // over a 2-key list fails.
        assert!(!RealBls::verify_aggregate(&pks[..2], &msg, &agg_fwd));
    }

    #[test]
    fn a_dropped_signer_breaks_the_aggregate() {
        let (sks, pks) = keys_for(&[SEED_A, SEED_B]);
        let msg: Hash = crate::hash::sha256(&[b"two-signer checkpoint"]);
        let agg = RealBls::aggregate(&[sks[0].sign(&msg)]).unwrap();
        // Aggregate of A alone must not verify against {A, B} — the verifier's
        // key list is the claim about who signed.
        assert!(!RealBls::verify_aggregate(&pks, &msg, &agg));
    }

    #[test]
    fn an_aggregate_over_one_signer_verifies_against_that_signer_only() {
        let (sks, pks) = keys_for(&[SEED_A, SEED_B, SEED_C]);
        let msg: Hash = crate::hash::sha256(&[b"one of three"]);
        let agg = RealBls::aggregate(&[sks[1].sign(&msg)]).unwrap();
        assert!(RealBls::verify_aggregate(&pks[1..2], &msg, &agg));
        assert!(!RealBls::verify_aggregate(&pks[0..1], &msg, &agg));
    }

    #[test]
    fn an_empty_signer_list_is_refused() {
        let (sks, _) = keys_for(&[SEED_A]);
        let msg: Hash = crate::hash::sha256(&[b"payload"]);
        let sig = sks[0].sign(&msg);
        assert!(!RealBls::verify_aggregate(&[], &msg, &sig));
        assert!(matches!(
            RealBls::aggregate(&[]),
            Err(BlsError::BadSignature { .. })
        ));
    }

    /// Malformed wire input must be rejected, never panic — this function is
    /// the boundary every future network peer hits.
    #[test]
    fn malformed_public_keys_are_rejected_not_panicked_on() {
        let (sks, pks) = keys_for(&[SEED_A]);
        let msg: Hash = crate::hash::sha256(&[b"payload"]);
        let sig = sks[0].sign(&msg);

        // All zeros: infinity, not a valid key.
        assert!(matches!(
            validate_public_key(&BlsPublicKey([0u8; 48])),
            Err(BlsError::BadPoint { .. })
        ));
        // Random bytes: overwhelmingly not a curve point.
        let mut junk = [0xFF; 48];
        assert!(matches!(
            validate_public_key(&BlsPublicKey(junk)),
            Err(BlsError::BadPoint { .. })
        ));
        // One flipped bit in a real key: still rejected, deterministically.
        let mut flipped = *pks[0].as_bytes();
        flipped[47] ^= 0x01;
        assert!(matches!(
            validate_public_key(&BlsPublicKey(flipped)),
            Err(BlsError::BadPoint { .. })
        ));
        // The verifier path refuses it too, without panicking.
        assert!(!RealBls::verify_aggregate(
            &[BlsPublicKey(flipped)],
            &msg,
            &sig
        ));
        assert!(!RealBls::verify_aggregate(
            &[BlsPublicKey(junk)],
            &msg,
            &sig
        ));

        // Silence the unused-variable lint for `junk` reuse below.
        let _ = &mut junk;
    }

    /// The exact gap `key_validate`/`sig_validate` close over bare
    /// `uncompress`: the compressed point-at-infinity encoding *decodes* just
    /// fine, and only the validate step refuses it. A committee that skipped
    /// that step would admit the all-important rogue element into an aggregate
    /// sum.
    #[test]
    fn the_point_at_infinity_decodes_but_never_validates() {
        let mut inf_pk = [0u8; 48];
        inf_pk[0] = 0xC0; // compressed | infinity
        assert!(
            blst::min_pk::PublicKey::uncompress(&inf_pk).is_ok(),
            "uncompress alone decodes infinity - this is the gap being tested"
        );
        assert!(matches!(
            validate_public_key(&BlsPublicKey(inf_pk)),
            Err(BlsError::BadPoint { what: "public key" })
        ));

        let mut inf_sig = [0u8; 96];
        inf_sig[0] = 0xC0;
        assert!(
            blst::min_pk::Signature::uncompress(&inf_sig).is_ok(),
            "uncompress alone decodes infinity - this is the gap being tested"
        );
        assert!(matches!(
            validate_signature(&BlsSignature(inf_sig)),
            Err(BlsError::BadPoint { what: "signature" })
        ));
    }

    #[test]
    fn malformed_signatures_are_rejected_not_panicked_on() {
        let (sks, pks) = keys_for(&[SEED_A]);
        let msg: Hash = crate::hash::sha256(&[b"payload"]);

        let zeros = BlsSignature([0u8; 96]);
        assert!(matches!(
            validate_signature(&zeros),
            Err(BlsError::BadPoint { .. })
        ));
        let junk = BlsSignature([0xAA; 96]);
        assert!(matches!(
            validate_signature(&junk),
            Err(BlsError::BadPoint { .. })
        ));
        assert!(!RealBls::verify_aggregate(&pks, &msg, &zeros));
        assert!(!RealBls::verify_aggregate(&pks, &msg, &junk));

        // A real signature with one bit flipped fails verification cleanly.
        let good = sks[0].sign(&msg);
        let mut bytes = good.as_bytes().to_vec();
        bytes[95] ^= 0x80;
        let bad = BlsSignature(bytes.try_into().unwrap());
        assert!(!RealBls::verify(&pks[0], &msg, &bad));
    }

    /// The end-to-end property the checkpoint machinery relies on: a real
    /// aggregate validates through `verify_checkpoint` where the same
    /// checkpoint with a forged signature fails, and MockBls — which accepts
    /// anything non-zero — would have accepted the forgery.
    #[test]
    fn verify_checkpoint_with_real_bls_rejects_a_forgery_mock_bls_accepts() {
        let (sks, pks) = keys_for(&[SEED_A, SEED_B, SEED_C]);
        let set = ValidatorSet::new(pks.clone());

        let payload = CheckpointPayload {
            height: 100,
            block_hash: crate::hash::sha512(&[b"block at 100"]),
            network_id: "srct/mini".into(),
            epoch: 10,
        };
        let msg = payload.signing_hash();
        let sigs: Vec<BlsSignature> = sks.iter().map(|sk| sk.sign(&msg)).collect();
        let agg = RealBls::aggregate(&sigs).unwrap();

        let cp = crate::bls_checkpoint::Checkpoint {
            payload: payload.clone(),
            aggregate_sig: agg,
            signer_bitmap: set.bitmap_from_indices(&[0, 1, 2]),
            signer_count: 3,
            pq_sidecar: Vec::new(),
        };
        assert!(crate::bls_checkpoint::verify_checkpoint(&cp, &set, &RealBls).is_ok());

        // Forge: same shape, garbage signature bytes. MockBls accepts anything
        // non-zero; RealBls must not.
        let forged = crate::bls_checkpoint::Checkpoint {
            payload,
            aggregate_sig: {
                let mut s = [0u8; 96];
                s[0] = 0xAA;
                BlsSignature(s)
            },
            signer_bitmap: set.bitmap_from_indices(&[0, 1, 2]),
            signer_count: 3,
            pq_sidecar: Vec::new(),
        };
        assert!(
            crate::bls_checkpoint::verify_checkpoint(&forged, &set, &MockBls).is_ok(),
            "mock accepts the forgery, proving it proves nothing"
        );
        assert!(
            crate::bls_checkpoint::verify_checkpoint(&forged, &set, &RealBls).is_err(),
            "real verification rejects it"
        );
    }

    #[test]
    fn validator_set_hash_is_order_insensitive_and_content_sensitive() {
        let (_, pks) = keys_for(&[SEED_A, SEED_B, SEED_C]);
        let h1 = validator_set_hash(&pks);
        let h2 = validator_set_hash(&pks.iter().rev().cloned().collect::<Vec<_>>());
        assert_eq!(h1, h2, "set identity must not depend on caller's order");
        let h3 = validator_set_hash(&pks[..2]);
        assert_ne!(h1, h3, "a different set is a different identity");
    }

    #[test]
    fn network_binding_separates_mainnet_from_mini() {
        // Same heights and hashes, different network_id: the signing hashes
        // differ, so a mini signature cannot verify a mainnet checkpoint.
        let mini = CheckpointPayload {
            height: 10,
            block_hash: [7u8; 64],
            network_id: "srct/mini".into(),
            epoch: 1,
        };
        let mainnet = CheckpointPayload {
            network_id: "srct/mainnet".into(),
            ..mini.clone()
        };
        assert_ne!(mini.signing_hash(), mainnet.signing_hash());
    }

    /// Cross-DST protection: a signature produced under the checkpoint DST
    /// must not verify under a different `SRCT_` DST, so a checkpoint signature
    /// can never be replayed as (say) a future dispute message.
    #[test]
    fn a_checkpoint_signature_does_not_verify_under_another_dst() {
        let (sks, pks) = keys_for(&[SEED_A]);
        let msg: Hash = crate::hash::sha256(&[b"checkpoint payload"]);
        let sig = sks[0].sign(&msg);
        // Simulate a future message type with its own DST by checking that the
        // blst-level verify with a different DST fails.
        let other_dst = b"SRCT_SIG_FUTURE_MESSAGE_XMD:SHA-256_SSWU_RO_";
        let pk = min_pk::PublicKey::uncompress(pks[0].as_bytes()).unwrap();
        let raw = min_pk::Signature::uncompress(sig.as_bytes()).unwrap();
        assert_ne!(
            raw.verify(false, &msg, other_dst, &[], &pk, false),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    /// The wrapper must never render key material: the inner `blst` type
    /// derives `Debug`, so an inherited impl would leak the scalar.
    #[test]
    fn debug_never_prints_the_secret_key() {
        assert!(
            std::mem::needs_drop::<SecretKey>(),
            "SecretKey must wipe on drop"
        );

        let sk = SecretKey::derive(&SEED_A).unwrap();
        let rendered = format!("{sk:?}");
        assert!(
            !rendered.contains(&hex::encode(sk.scalar())),
            "Debug leaked the scalar: {rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");
    }
}
