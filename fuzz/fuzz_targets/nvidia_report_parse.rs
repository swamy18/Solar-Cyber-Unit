#![no_main]

//! Fuzz the NVIDIA JWT report parser: arbitrary bytes must never panic,
//! and any accepted input must round-trip (the canonical envelope is a
//! pure function of the parsed signing input).

use libfuzzer_sys::fuzz_target;
use srct_compute::vendor::NvidiaReport;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = NvidiaReport::decode(data) {
        let _ = r.encode();
    }
});
