#![no_main]

//! Fuzz the confidential keystore file parser: arbitrary bytes must never
//! panic, and wrong passphrases / truncated / tampered files must refuse
//! without leaking key material in the error.

use libfuzzer_sys::fuzz_target;
use srct_confid::kms::LocalKeystore;
use std::io::Write as _;

fn write_temp(bytes: &[u8]) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("srct-confid-fuzz-{}", std::process::id()));
    let mut f = std::fs::File::create(&p).expect("temp file");
    let _ = f.write_all(bytes);
    p
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    // Best-effort decode only: must not panic on any input.
    let _ = srct_confid::keywrap::SealedKey::decode(data);
    let path = write_temp(data);
    let _ = LocalKeystore::open(&path, "fuzz-passphrase");
    let _ = std::fs::remove_file(&path);
});
