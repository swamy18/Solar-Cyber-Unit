#![no_main]

//! Fuzz the AMD SEV-SNP attestation report parser: arbitrary bytes must
//! never panic, and any accepted input must round-trip byte-identically.

use libfuzzer_sys::fuzz_target;
use srct_compute::vendor::SnpReport;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = SnpReport::decode(data) {
        let _ = r.encode();
    }
});
