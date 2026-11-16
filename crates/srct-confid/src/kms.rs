//! Pluggable key management.
//!
//! The [`KmsAdapter`] trait is the only thing the release gate talks to:
//! store a per-job data key, load it back (with TTL and revocation
//! enforced), revoke it. [`LocalKeystore`] is the default implementation —
//! an encrypted file in the same shape as `wallets.json` (Argon2id +
//! ChaCha20-Poly1305, `0600`, atomic write). [`VaultKms`] and [`CloudKms`]
//! are documented stubs: integrating HashiCorp Vault or a cloud KMS means
//! implementing this trait, not changing the release path.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::ConfidError;

/// File magic: `SRCTKEY` plus the format version `01`.
pub const MAGIC: &[u8] = b"SRCTKEY01";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Environment variable carrying the keystore passphrase. Read at each
/// open, never cached: nothing holds it beyond the call.
pub const PASSPHRASE_ENV: &str = "SRCT_CONFID_PASSPHRASE";

fn bad<S: Into<String>>(detail: S) -> ConfidError {
    ConfidError::Malformed(detail.into())
}

/// What the keystore tracks per key id. Confidentiality comes from the
/// whole-file seal (fresh salt + nonce per write), not from per-record
/// encryption: identical to the wallets.json posture.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyRecord {
    /// Base64 of the raw 32-byte key.
    key_b64: String,
    created_unix: u64,
    /// TTL in seconds from creation; `u64::MAX` means no expiry.
    ttl_secs: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct KeystoreFile {
    version: u8,
    keys: BTreeMap<String, KeyRecord>,
}

/// A key management backend. All methods are synchronous and local-first;
/// network backends implement the same trait with their own transport.
pub trait KmsAdapter {
    /// Store (or rotate: overwrite) the 32-byte key under `id` with a TTL
    /// in seconds measured from `now_unix`.
    fn store(&mut self, id: &str, key: &[u8; 32], ttl_secs: u64, now_unix: u64) -> Result<(), ConfidError>;
    /// Load the key, enforcing expiry and revocation. Returns a zeroizing
    /// buffer: the key wipes itself when the caller is done with it.
    fn load(&self, id: &str, now_unix: u64) -> Result<Zeroizing<[u8; 32]>, ConfidError>;
    /// Mark the key revoked. Returns whether it existed.
    fn revoke(&mut self, id: &str) -> Result<bool, ConfidError>;
    /// Key ids currently tracked (including revoked ones).
    fn ids(&self) -> Vec<String>;
}

/// Local encrypted keystore file. Same at-rest properties as
/// `wallets.json`: Argon2id (RFC 9106 second profile: 19 MiB, 2 passes,
/// 1 lane) derives the file key from the passphrase and a fresh random
/// salt; ChaCha20-Poly1305 seals the JSON body under a fresh nonce;
/// `0600` via temp-file + atomic rename.
///
/// No key material is ever logged: errors name the key id and the failed
/// check, never bytes.
pub struct LocalKeystore {
    path: PathBuf,
    passphrase: Zeroizing<String>,
    file: KeystoreFile,
}

impl LocalKeystore {
    /// Create a new empty keystore file. Refuses to overwrite an existing
    /// file: rotation happens through [`KmsAdapter::store`], not by
    /// re-creating the store out from under live keys.
    pub fn create(path: &Path, passphrase: &str) -> Result<Self, ConfidError> {
        if path.exists() {
            return Err(bad("keystore file already exists"));
        }
        let ks = LocalKeystore {
            path: path.to_path_buf(),
            passphrase: Zeroizing::new(passphrase.to_string()),
            file: KeystoreFile {
                version: 1,
                keys: BTreeMap::new(),
            },
        };
        ks.save()?;
        Ok(ks)
    }

    /// Open an existing keystore file. The passphrase is verified by the
    /// AEAD open: a wrong passphrase fails closed here, before any key is
    /// touched.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, ConfidError> {
        let blob = fs::read(path).map_err(|e| ConfidError::Io(format!("keystore read: {e}")))?;
        let plain = decrypt(passphrase, &blob)?;
        let file: KeystoreFile =
            serde_json::from_slice(&plain).map_err(|_| bad("keystore body is not valid JSON"))?;
        if file.version != 1 {
            return Err(bad("unsupported keystore version"));
        }
        Ok(LocalKeystore {
            path: path.to_path_buf(),
            passphrase: Zeroizing::new(passphrase.to_string()),
            file,
        })
    }

    fn save(&self) -> Result<(), ConfidError> {
        let plain =
            serde_json::to_vec(&self.file).map_err(|_| bad("keystore body does not serialize"))?;
        let blob = encrypt(&self.passphrase, &plain)?;
        write_private(&self.path, &blob)
    }

    fn encode_key(key: &[u8; 32]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    fn decode_key(s: &str) -> Result<Zeroizing<[u8; 32]>, ConfidError> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|_| bad("key body is not base64"))?;
        if raw.len() != 32 {
            return Err(bad("key body is not 32 bytes"));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&raw);
        Ok(key)
    }
}

fn check_id(id: &str) -> Result<(), ConfidError> {
    if id.is_empty() || id.len() > 128 {
        return Err(ConfidError::Malformed("key id length out of range".into()));
    }
    // Flat names only: no path separators, no whitespace, no shell
    // metacharacters. Ids appear in file names only inside the keystore
    // JSON (never as paths), but keeping them shell-safe avoids an entire
    // class of operator footguns.
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(ConfidError::Malformed("key id has illegal characters".into()));
    }
    Ok(())
}

impl KmsAdapter for LocalKeystore {
    fn store(&mut self, id: &str, key: &[u8; 32], ttl_secs: u64, now_unix: u64) -> Result<(), ConfidError> {
        check_id(id)?;
        self.file.keys.insert(
            id.to_string(),
            KeyRecord {
                key_b64: Self::encode_key(key),
                created_unix: now_unix,
                ttl_secs,
                revoked: false,
            },
        );
        // The whole file is re-sealed with a fresh salt and nonce on every
        // write, so storing twice never produces the same bytes.
        self.save()
    }

    fn load(&self, id: &str, now_unix: u64) -> Result<Zeroizing<[u8; 32]>, ConfidError> {
        let rec = self
            .file
            .keys
            .get(id)
            .ok_or_else(|| ConfidError::UnknownKey(id.to_string()))?;
        if rec.revoked {
            return Err(ConfidError::Revoked(id.to_string()));
        }
        if rec.ttl_secs != u64::MAX && now_unix.saturating_sub(rec.created_unix) > rec.ttl_secs {
            return Err(ConfidError::Expired(id.to_string()));
        }
        Self::decode_key(&rec.key_b64)
    }

    fn revoke(&mut self, id: &str) -> Result<bool, ConfidError> {
        match self.file.keys.get_mut(id) {
            Some(rec) => {
                rec.revoked = true;
                self.save()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn ids(&self) -> Vec<String> {
        self.file.keys.keys().cloned().collect()
    }
}

impl Drop for LocalKeystore {
    fn drop(&mut self) {
        // The passphrase buffer zeroizes itself; belt and suspenders.
        self.passphrase.zeroize();
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, ConfidError> {
    let mut key = Zeroizing::new([0u8; 32]);
    // Same pinned profile as wallets.json (Argon2id, RFC 9106 second
    // recommended option): a crate upgrade cannot silently re-derive.
    let params = argon2::Params::new(19 * 1024, 2, 1, None)
        .map_err(|e| ConfidError::Crypto(format!("argon2 params: {e}")))?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
        .map_err(|e| ConfidError::Crypto(format!("key derivation failed: {e}")))?;
    Ok(key)
}

fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, ConfidError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| ConfidError::Crypto("keystore cipher setup failed".into()))?;
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| ConfidError::Crypto("keystore encryption failed".into()))?;
    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(passphrase: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, ConfidError> {
    let header = MAGIC.len() + SALT_LEN + NONCE_LEN;
    // TAG_LEN (16) is the AEAD minimum: anything shorter cannot be valid.
    if blob.len() < header + TAG_LEN {
        return Err(ConfidError::Malformed("keystore file is truncated".into()));
    }
    let (prefix, rest) = blob.split_at(MAGIC.len());
    if prefix != MAGIC {
        return Err(ConfidError::Malformed("keystore file has an unknown format".into()));
    }
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce);
    let key = derive_key(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| ConfidError::Crypto("keystore cipher setup failed".into()))?;
    cipher
        .decrypt(&Nonce::from(nonce_bytes), ct)
        .map(Zeroizing::new)
        .map_err(|_| ConfidError::Crypto("wrong passphrase, or the keystore file was modified".into()))
}

/// Write bytes to `path` so no other account can read them and no crash
/// can leave a partial file: temp file created 0600, fsynced, renamed over
/// the destination; stale temp removed first. Mirrors the wallets.json
/// writer — same threat model, same guarantees.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ConfidError> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = Path::new(&tmp_name);
    let _ = fs::remove_file(tmp);
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(tmp)
            .map_err(|e| ConfidError::Io(format!("keystore temp file: {e}")))?;
        file.write_all(bytes)
            .map_err(|e| ConfidError::Io(format!("keystore write: {e}")))?;
        file.sync_all()
            .map_err(|e| ConfidError::Io(format!("keystore fsync: {e}")))?;
    }
    fs::rename(tmp, path).map_err(|e| ConfidError::Io(format!("keystore replace: {e}")))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// HashiCorp Vault adapter: documented stub. Integrating Vault means
/// implementing [`KmsAdapter`] over a Vault client here — the release gate
/// and key format do not change.
pub struct VaultKms {
    /// Vault address this stub would talk to, kept for configuration only.
    pub addr: String,
}

impl VaultKms {
    pub fn new(addr: impl Into<String>) -> Self {
        VaultKms { addr: addr.into() }
    }
}

impl KmsAdapter for VaultKms {
    fn store(&mut self, _id: &str, _key: &[u8; 32], _ttl_secs: u64, _now_unix: u64) -> Result<(), ConfidError> {
        Err(ConfidError::NotConfigured(
            "VaultKms is a documented stub: implement KmsAdapter over a Vault client to enable it".into(),
        ))
    }
    fn load(&self, id: &str, _now_unix: u64) -> Result<Zeroizing<[u8; 32]>, ConfidError> {
        Err(ConfidError::NotConfigured(format!(
            "VaultKms is a documented stub (key {id} not reachable)"
        )))
    }
    fn revoke(&mut self, _id: &str) -> Result<bool, ConfidError> {
        Err(ConfidError::NotConfigured(
            "VaultKms is a documented stub: implement KmsAdapter over a Vault client to enable it".into(),
        ))
    }
    fn ids(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Cloud KMS adapter (KMS-as-a-service envelope keys): documented stub with
/// the same contract as [`VaultKms`].
pub struct CloudKms {
    /// Key-ring identifier this stub would use, configuration only.
    pub key_ring: String,
}

impl CloudKms {
    pub fn new(key_ring: impl Into<String>) -> Self {
        CloudKms {
            key_ring: key_ring.into(),
        }
    }
}

impl KmsAdapter for CloudKms {
    fn store(&mut self, _id: &str, _key: &[u8; 32], _ttl_secs: u64, _now_unix: u64) -> Result<(), ConfidError> {
        Err(ConfidError::NotConfigured(
            "CloudKms is a documented stub: implement KmsAdapter over a cloud KMS client to enable it".into(),
        ))
    }
    fn load(&self, id: &str, _now_unix: u64) -> Result<Zeroizing<[u8; 32]>, ConfidError> {
        Err(ConfidError::NotConfigured(format!(
            "CloudKms is a documented stub (key {id} not reachable)"
        )))
    }
    fn revoke(&mut self, _id: &str) -> Result<bool, ConfidError> {
        Err(ConfidError::NotConfigured(
            "CloudKms is a documented stub: implement KmsAdapter over a cloud KMS client to enable it".into(),
        ))
    }
    fn ids(&self) -> Vec<String> {
        Vec::new()
    }
}
