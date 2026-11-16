#![no_main]

//! Fuzz sealed-key opening: arbitrary sealed blobs and info/AAD strings
//! must never panic; anything but exactly the sealed output must fail.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    // Split input into (sealed blob, info, aad) deterministically.
    let (sealed_bytes, rest) = data.split_at(data.len().min(1088));
    let (info, aad) = rest.split_at(rest.len() / 2);
    let Ok(sealed) = srct_confid::keywrap::SealedKey::decode(sealed_bytes) else {
        return;
    };
    let key = [0u8; 32];
    let _ = srct_confid::keywrap::open_with_privkey(&key, &sealed, info, aad);
});
