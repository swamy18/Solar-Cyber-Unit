use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

pub type Hash = [u8; 32];

/// 512-bit digest: the width of the **chain identity** hashes (txid and block
/// hash).
///
/// A 256-bit digest keeps only ~128 bits of preimage resistance against a
/// Grover-equipped adversary, and ~85 bits of collision resistance against a
/// quantum collision search (BHT). Doubling the output width restores a full
/// 256-bit classical *and* quantum margin on the two values an attacker most
/// wants to forge: the id a coin is locked to, and the id a chain is built on.
///
/// Deliberately a **separate type** from [`Hash`]. Widening the 256-bit digest
/// everywhere would also change the PoW target comparison (which is a 256-bit
/// arithmetic bound, not a collision-resistance claim) and every internal
/// commitment, turning one bounded change into a rewrite of the consensus
/// surface. Only the two wide values carry the wider type.
pub type Hash512 = [u8; 64];

pub type Address = [u8; 20];

/// All-zero hash: the placeholder identity used by `NoCreditGate` (no position
/// id, no reserved debit). Not a valid position id, by construction.
pub const ZERO_HASH: Hash = [0u8; 32];

/// All-zero 512-bit identity: the `prev_hash` of the genesis header, which has
/// no parent. Not the hash of anything, by construction.
pub const ZERO_HASH512: Hash512 = [0u8; 64];

/// Domain-separation tags. Frozen; the `/v1` suffix must never be reused by a
/// different construction. See SPEC.md §0.
pub const DOM_BLOCK: &[u8] = b"srct/blockhash/v1";
pub const DOM_TX: &[u8] = b"srct/txid/v1";
/// 512-bit block hash. A new tag, not a reuse of `DOM_BLOCK`: the output width
/// is part of the construction, and reusing the v1 tag for it would make one
/// tag name two different functions (SPEC.md §0).
pub const DOM_BLOCK512: &[u8] = b"srct/blockhash512/v1";
/// 512-bit transaction id.
pub const DOM_TX512: &[u8] = b"srct/txid512/v1";
pub const DOM_TXBODY: &[u8] = b"srct/txbody/v1";
pub const DOM_SIG: &[u8] = b"srct/sig/v1";
pub const DOM_ADDR: &[u8] = b"srct/addr/v2";
/// Domain tag for ML-DSA-65 seed derivation from a secp256k1 wallet key.
/// Keeps the seed derivation cryptographically separate from address
/// derivation, which also hashes private key material.
pub const DOM_ML_DSA_SEED: &[u8] = b"srct/ml-dsa-65-seed/v1";
/// Domain tag for ML-DSA-65 seed derivation from a BLS validator key.
pub const DOM_VALIDATOR_ML_DSA: &[u8] = b"srct/validator-mldsa/v1";
pub const DOM_S1: &[u8] = b"srct/puzzle/stage1/v1";
pub const DOM_S2: &[u8] = b"srct/puzzle/stage2/v1";
pub const DOM_S3: &[u8] = b"srct/puzzle/stage3/v1";
/// Stage 3 domain tag for VWC-linked mining (puzzle_id = 3). Commits the
/// final hash to a verified-work-certificate id so mining binds to useful
/// L2 compute, not just brute force.
pub const DOM_S3_VWC: &[u8] = b"srct/puzzle/stage3-vwc/v1";
pub const DOM_W: &[u8] = b"srct/puzzle/weights/v1";

pub const SIG_SCHEME_SECP256K1_ECDSA: u8 = 1;

/// SHA-256 over a domain tag followed by a concatenation of byte slices.
pub fn sha256_dom(dom: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(dom);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha256(parts: &[&[u8]]) -> Hash {
    sha256_dom(&[], parts)
}

/// SHA-512 over a domain tag followed by a concatenation of byte slices.
///
/// The 512-bit counterpart of [`sha256_dom`], used for txids and block hashes.
/// Separate function rather than a generic one: the two widths have different
/// callers and different security arguments (see [`Hash512`]).
pub fn sha512_dom(dom: &[u8], parts: &[&[u8]]) -> Hash512 {
    let mut h = Sha512::new();
    h.update(dom);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha512(parts: &[&[u8]]) -> Hash512 {
    sha512_dom(&[], parts)
}

/// Single-key address derivation, for the common case of an ECDSA-only bundle.
///
/// Equivalent to `Bundle::single(SCHEME_SECP256K1_ECDSA, pubkey).address()`.
/// Kept so callers that genuinely hold one key do not have to build a bundle.
pub fn address_from_pubkey(pubkey: &[u8; 33]) -> Address {
    // invariant: a single-scheme address is always structurally valid by construction.
    crate::sig::Bundle::single(crate::sig::SCHEME_SECP256K1_ECDSA, pubkey.to_vec())
        .address()
        .expect("a single ECDSA bundle is always structurally valid")
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim()).map_err(|_| Error::Malformed("invalid hex string"))
}

pub fn hash_to_hex(h: &Hash) -> String {
    to_hex(h)
}

pub fn hash_from_hex(s: &str) -> Result<Hash> {
    let v = from_hex(s)?;
    if v.len() != 32 {
        return Err(Error::BadLength {
            expected: 32,
            got: v.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

pub fn hash512_to_hex(h: &Hash512) -> String {
    to_hex(h)
}

pub fn hash512_from_hex(s: &str) -> Result<Hash512> {
    let v = from_hex(s)?;
    if v.len() != 64 {
        return Err(Error::BadLength {
            expected: 64,
            got: v.len(),
        });
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    Ok(out)
}

pub fn address_to_hex(a: &Address) -> String {
    format!("jt1{}", to_hex(a))
}

pub fn address_from_hex(s: &str) -> Result<Address> {
    let s = s.trim().strip_prefix("jt1").unwrap_or(s.trim());
    let v = from_hex(s)?;
    if v.len() != 20 {
        return Err(Error::BadLength {
            expected: 20,
            got: v.len(),
        });
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&v);
    Ok(out)
}
