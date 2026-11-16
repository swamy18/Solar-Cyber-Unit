//! Local encrypted keystore: roundtrip, wrong passphrase, tampering,
//! TTL expiry, revocation, atomic writes and file permissions.

use srct_confid::{ConfidError, KmsAdapter, LocalKeystore};

const PASS: &str = "correct horse passphrase";
const NOW: u64 = 1_700_000_000;

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("srct-confid-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn store_load_roundtrip() {
    let dir = dir("roundtrip");
    let path = dir.join("keys.srctconfid");
    LocalKeystore::create(&path, PASS).unwrap();
    let mut ks = LocalKeystore::open(&path, PASS).unwrap();
    ks.store("job-1", &[0xABu8; 32], u64::MAX, NOW).unwrap();
    let loaded = ks.load("job-1", NOW).unwrap();
    assert_eq!(&loaded[..], &[0xABu8; 32][..]);
    assert_eq!(ks.ids(), vec!["job-1".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_passphrase_and_tampering_refused() {
    let dir = dir("tamper");
    let path = dir.join("keys.srctconfid");
    LocalKeystore::create(&path, PASS).unwrap();
    let mut ks = LocalKeystore::open(&path, PASS).unwrap();
    ks.store("job-1", &[0x01u8; 32], u64::MAX, NOW).unwrap();
    drop(ks);
    assert!(LocalKeystore::open(&path, "wrong passphrase").is_err());
    let mut blob = std::fs::read(&path).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    std::fs::write(&path, &blob).unwrap();
    assert!(LocalKeystore::open(&path, PASS).is_err());
    // Truncation refused.
    let short = &blob[..20];
    std::fs::write(&path, short).unwrap();
    assert!(LocalKeystore::open(&path, PASS).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ttl_expiry_and_revocation_enforced() {
    let dir = dir("ttl");
    let path = dir.join("keys.srctconfid");
    LocalKeystore::create(&path, PASS).unwrap();
    let mut ks = LocalKeystore::open(&path, PASS).unwrap();
    ks.store("short", &[0xCDu8; 32], 10, NOW).unwrap();
    assert!(ks.load("short", NOW + 9).is_ok());
    assert_eq!(
        ks.load("short", NOW + 11),
        Err(ConfidError::Expired("short".into()))
    );
    assert!(ks.revoke("short").unwrap());
    assert_eq!(
        ks.load("short", NOW),
        Err(ConfidError::Revoked("short".into()))
    );
    assert!(!ks.revoke("nope").unwrap());
    assert!(matches!(
        ks.load("nope", NOW),
        Err(ConfidError::UnknownKey(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_store_rewrites_ciphertext_and_leaves_no_temp() {
    let dir = dir("atomic");
    let path = dir.join("keys.srctconfid");
    LocalKeystore::create(&path, PASS).unwrap();
    let mut ks = LocalKeystore::open(&path, PASS).unwrap();
    ks.store("a", &[0x01u8; 32], u64::MAX, NOW).unwrap();
    let first = std::fs::read(&path).unwrap();
    ks.store("a", &[0x01u8; 32], u64::MAX, NOW).unwrap();
    let second = std::fs::read(&path).unwrap();
    assert_ne!(first, second, "fresh salt+nonce per write");
    assert!(!path.with_extension("tmp").exists() && !dir.join("keys.srctconfid.tmp").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "keystore must not be group/world readable"
        );
    }
    // Bad key ids refused before touching disk.
    assert!(ks.store("", &[0u8; 32], u64::MAX, NOW).is_err());
    assert!(ks.store("../escape", &[0u8; 32], u64::MAX, NOW).is_err());
    assert!(ks
        .store(&"k".repeat(200), &[0u8; 32], u64::MAX, NOW)
        .is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_refuses_to_clobber_and_vault_is_a_stub() {
    let dir = dir("clobber");
    let path = dir.join("keys.srctconfid");
    LocalKeystore::create(&path, PASS).unwrap();
    assert!(LocalKeystore::create(&path, PASS).is_err());
    let _ = std::fs::remove_dir_all(&dir);

    use srct_confid::kms::{CloudKms, VaultKms};
    let mut vault = VaultKms::new("https://vault.example:8200");
    assert!(matches!(
        vault.store("a", &[0u8; 32], u64::MAX, NOW),
        Err(ConfidError::NotConfigured(_))
    ));
    assert!(vault.ids().is_empty());
    let mut cloud = CloudKms::new("projects/p/locations/l/keyRings/r");
    assert!(matches!(
        cloud.revoke("a"),
        Err(ConfidError::NotConfigured(_))
    ));
}
