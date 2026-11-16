#![no_main]

//! Fuzz shield bundle sealing/opening: arbitrary inputs must never panic;
//! malformed bundles must fail closed.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let key = [0x42u8; 32];

    // Round-trip: seal a slice of the input, then open it back.
    let payload = if data.len() > 0 { &data[..data.len().min(4096)] } else { b"" };
    if let Ok(sealed) = srct_compute::shield::seal(
        &key,
        payload,
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        100,
    ) {
        let _ = srct_compute::shield::open(&key, &sealed);
    }

    // Try to open arbitrary bytes as a manifest: must never panic.
    let _ = srct_compute::shield::ShieldBundle::decode(data);
});
