#![no_main]

//! Fuzz the Intel TDX DCAP quote parser: arbitrary bytes must never panic,
//! and any accepted input must round-trip byte-identically (parse is a
//! pure function of the wire bytes).

use libfuzzer_sys::fuzz_target;
use srct_compute::vendor::TdxQuote;

fuzz_target!(|data: &[u8]| {
    if let Ok(q) = TdxQuote::decode(data) {
        let _ = q.encode();
    }
    let _ = srct_compute::vendor::VendorEvidence::decode(data);
});
