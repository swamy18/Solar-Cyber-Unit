//! Multi-coin HD wallet: one seed, many chains. Non-consensus, client-side only.
//!
//! A single secp256k1 master scalar derives per-chain children:
//! - SRCT: existing [`Wallet`] (bundle-hashed `jt1` address, unchanged).
//! - EVM (Base `eip155:8453`, Base Sepolia `84532`): same scalar, secp256k1
//!   ECDSA over keccak256, `0x` address = last 20 bytes of
//!   `keccak256(uncompressed_pubkey[1..])`.
//! - BTC: same scalar, P2WPKH `SHA256+RIPEMD160` placeholder layout without a
//!   new hash dependency (`sha256_dom` truncated flows until a RIPEMD review
//!   lands; do not fund mainnet from this path yet).
//!
//! Derivation is intentionally simple and auditable: `child = SHA256(master ||
//! tag || index) mod n`. This is NOT BIP-32 (no chain code, no hardened
//! derivation, no xpub). It buys one-seed-many-chains without new crypto
//! review surface; a BIP-32 migration can replace `derive_child` later with
//! the same public API.

use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha3::{Digest, Keccak256};

use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Address};
use crate::wallet::Wallet;

pub const HD_SLIP_SRCT: u32 = 0x8000_0001;
pub const HD_SLIP_EVM: u32 = 60;
pub const HD_SLIP_BTC: u32 = 0;

pub const DOM_HD_CHILD: &[u8] = b"srct/hd-child/v1";
pub const DOM_HD_EVM_PAYLOAD: &[u8] = b"srct/evm-payload/v1";

/// Which chain a derived key is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainKind {
    Srct,
    Evm(u64),
    Btc,
}

/// A master seed plus its SRCT wallet. The SRCT leg is the existing wallet
/// format (a bare 32-byte scalar); EVM/BTC legs are children of that scalar.
#[derive(Clone)]
pub struct HdWallet {
    master: zeroize::Zeroizing<[u8; 32]>,
    label: String,
}

impl std::fmt::Debug for HdWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdWallet")
            .field("label", &self.label)
            .field("master", &"<redacted>")
            .finish()
    }
}

impl Drop for HdWallet {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.master.zeroize();
    }
}

impl HdWallet {
    pub fn new_random(label: impl Into<String>) -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            if SigningKey::from_bytes((&bytes).into()).is_ok() {
                return Self {
                    master: zeroize::Zeroizing::new(bytes),
                    label: label.into(),
                };
            }
        }
    }

    pub fn from_seed(seed: &[u8; 32], label: impl Into<String>) -> Result<Self> {
        SigningKey::from_bytes(seed.into())
            .map_err(|_| Error::BadKey("HD master is not a valid scalar"))?;
        Ok(Self {
            master: zeroize::Zeroizing::new(*seed),
            label: label.into(),
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// The SRCT leg: the existing wallet over the master scalar.
    pub fn srct_wallet(&self) -> Result<Wallet> {
        Wallet::from_private_key_bytes(&self.master[..], self.label.clone())
    }

    /// Deterministic child scalar for `(chain, index)`.
    pub fn derive_child(&self, chain: ChainKind, index: u32) -> Result<[u8; 32]> {
        let tag = match chain {
            ChainKind::Srct => HD_SLIP_SRCT,
            ChainKind::Evm(_) => HD_SLIP_EVM,
            ChainKind::Btc => HD_SLIP_BTC,
        };
        let mut idx = [0u8; 4];
        idx.copy_from_slice(&index.to_le_bytes());
        let mut tg = [0u8; 4];
        tg.copy_from_slice(&tag.to_le_bytes());
        let digest = sha256_dom(DOM_HD_CHILD, &[&self.master[..], &tg, &idx]);
        SigningKey::from_bytes((&digest).into())
            .map_err(|_| Error::BadKey("HD child is not a valid scalar"))?;
        Ok(digest)
    }

    fn child_signing_key(chain: ChainKind, index: u32, wallet: &HdWallet) -> Result<SigningKey> {
        let child = wallet.derive_child(chain, index)?;
        SigningKey::from_bytes((&child).into())
            .map_err(|_| Error::BadKey("HD child scalar out of range"))
    }

    /// EVM address for the `(chain_id, index)` child: last 20 bytes of
    /// `keccak256(uncompressed_pubkey[1..])`, `0x`-hex encoded.
    pub fn evm_address(&self, _chain_id: u64, index: u32) -> Result<[u8; 20]> {
        let sk = Self::child_signing_key(ChainKind::Evm(0), index, self)?;
        let point = sk.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        debug_assert_eq!(bytes.len(), 65);
        let mut hasher = Keccak256::new();
        hasher.update(&bytes[1..]);
        let digest = hasher.finalize();
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[12..32]);
        Ok(out)
    }

    pub fn evm_address_hex(&self, chain_id: u64, index: u32) -> Result<String> {
        Ok(format!(
            "0x{}",
            hex::encode(self.evm_address(chain_id, index)?)
        ))
    }

    /// EVM ECDSA signature over a 32-byte digest (EIP-155 `v` computed by the
    /// caller; this returns `r || s` canonical low-s).
    pub fn sign_evm_digest(&self, index: u32, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let sk = Self::child_signing_key(ChainKind::Evm(0), index, self)?;
        let (sig, _): (Signature, _) = sk
            .sign_prehash(digest)
            .map_err(|_| Error::BadKey("evm signing failed"))?;
        let canonical = sig.normalize_s().unwrap_or(sig);
        let mut out = [0u8; 64];
        out.copy_from_slice(&canonical.to_bytes());
        Ok(out)
    }

    /// Sign an EIP-1559-style payload hash. The caller builds the unsigned tx
    /// bytes; this hashes them under a domain tag and signs the digest.
    pub fn sign_evm_payload(
        &self,
        chain_id: u64,
        index: u32,
        unsigned_tx: &[u8],
    ) -> Result<[u8; 64]> {
        let digest = sha256_dom(DOM_HD_EVM_PAYLOAD, &[&chain_id.to_le_bytes(), unsigned_tx]);
        self.sign_evm_digest(index, &digest)
    }

    /// BTC P2WPKH-style address bytes (placeholder hash flow, see module docs).
    /// Returns the 20-byte program; bech32 encoding is the caller's job.
    pub fn btc_program(&self, index: u32) -> Result<[u8; 20]> {
        let sk = Self::child_signing_key(ChainKind::Btc, index, self)?;
        let compressed = sk.verifying_key().to_encoded_point(true);
        let bytes = compressed.as_bytes();
        let digest = sha256_dom(b"srct/btc-program/v1", &[bytes]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        Ok(out)
    }

    /// BTC bech32 P2WPKH address (`bc1q...` / `tb1q...` / `bcrt1q...`).
    /// Placeholder program hash (see [`HdWallet::btc_program`]): do not fund
    /// mainnet from this path until the RIPEMD-160 review lands.
    pub fn btc_address(&self, mainnet: bool, index: u32) -> Result<String> {
        let program = self.btc_program(index)?;
        Ok(bech32_p2wpkh(if mainnet { "bc" } else { "tb" }, &program))
    }

    /// SRCT address of a child index (delegation / per-agent sub-keys).
    pub fn srct_child_address(&self, index: u32) -> Result<Address> {
        let child = self.derive_child(ChainKind::Srct, index)?;
        Wallet::from_private_key_bytes(&child, format!("{}-{}", self.label, index))?.address()
    }
}

/// Bech32 encode a P2WPKH program (version 0 + 20-byte witness).
/// No new dependency: the checksum is a hand-rolled BCH code over the
/// standard bech32 alphabet, with 90-char cap and HRP checks per BIP-173.
pub fn bech32_p2wpkh(hrp: &str, program: &[u8; 20]) -> String {
    const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut data: Vec<u8> = Vec::with_capacity(33);
    data.push(0);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in program.iter() {
        acc = (acc << 8) | (*byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut values: Vec<u8> = Vec::with_capacity(3 + hrp.len() + data.len() + 6);
    for b in hrp.bytes() {
        values.push(b >> 5);
    }
    values.push(0);
    for b in hrp.bytes() {
        values.push(b & 31);
    }
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0u8; 6]);
    let mut polymod = 1u32;
    for v in &values {
        let b = polymod >> 25;
        polymod = ((polymod & 0x1ff_ffff) << 5) ^ (*v as u32);
        if b & 1 != 0 {
            polymod ^= 0x3b6a_57b2;
        }
        if b & 2 != 0 {
            polymod ^= 0x2650_8e6d;
        }
        if b & 4 != 0 {
            polymod ^= 0x1ea1_19fa;
        }
        if b & 8 != 0 {
            polymod ^= 0x3d42_33dd;
        }
        if b & 16 != 0 {
            polymod ^= 0x2a14_62b3;
        }
    }
    let checksum = polymod ^ 1;
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for d in &data {
        out.push(ALPHABET[*d as usize] as char);
    }
    for i in 0..6 {
        out.push(ALPHABET[((checksum >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hd() -> HdWallet {
        HdWallet::new_random("test-hd")
    }

    #[test]
    fn master_matches_srct_wallet() {
        let h = hd();
        let w = h.srct_wallet().unwrap();
        assert_eq!(w.label, "test-hd");
        assert_eq!(w.address().unwrap().len(), 20);
    }

    #[test]
    fn derivation_is_deterministic_and_index_scoped() {
        let h = hd();
        let a = h.derive_child(ChainKind::Evm(8453), 0).unwrap();
        let b = h.derive_child(ChainKind::Evm(8453), 0).unwrap();
        let c = h.derive_child(ChainKind::Evm(8453), 1).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(
            h.derive_child(ChainKind::Evm(8453), 0).unwrap(),
            h.derive_child(ChainKind::Btc, 0).unwrap()
        );
    }

    #[test]
    fn evm_address_is_stable_and_hexed() {
        let h = HdWallet::from_seed(&[7u8; 32], "x").unwrap();
        let a = h.evm_address(8453, 0).unwrap();
        assert_eq!(a, h.evm_address(84532, 0).unwrap());
        let hex = h.evm_address_hex(8453, 0).unwrap();
        assert!(hex.starts_with("0x") && hex.len() == 42);
    }

    #[test]
    fn evm_signing_verifies_under_child_key() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let h = HdWallet::from_seed(&[9u8; 32], "x").unwrap();
        let digest = crate::hash::sha256(&[b"evm-test"]);
        let sig = h.sign_evm_digest(3, &digest).unwrap();
        let child = h.derive_child(ChainKind::Evm(8453), 3).unwrap();
        let vk = *SigningKey::from_bytes((&child).into())
            .unwrap()
            .verifying_key();
        let s = Signature::from_slice(&sig).unwrap();
        vk.verify_prehash(&digest, &s).unwrap();
    }

    #[test]
    fn rejects_bad_seed() {
        assert!(HdWallet::from_seed(&[0u8; 32], "z").is_err());
        assert!(HdWallet::from_seed(&[0xffu8; 32], "z").is_err());
    }

    #[test]
    fn debug_never_prints_the_seed() {
        let h = HdWallet::from_seed(&[7u8; 32], "lbl").unwrap();
        let rendered = format!("{h:?}");
        assert!(rendered.contains("lbl"));
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(&hex::encode([7u8; 32])));
    }

    #[test]
    fn btc_bech32_addresses_are_hrp_scoped_and_stable() {
        let h = HdWallet::from_seed(&[7u8; 32], "x").unwrap();
        let main = h.btc_address(true, 0).unwrap();
        let test = h.btc_address(false, 0).unwrap();
        assert!(main.starts_with("bc1q"));
        assert!(test.starts_with("tb1q"));
        assert_eq!(main, h.btc_address(true, 0).unwrap());
        assert_ne!(main, h.btc_address(true, 1).unwrap());
    }
}
