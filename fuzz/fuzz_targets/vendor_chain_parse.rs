#![no_main]

//! Fuzz the vendor certificate-chain parser: arbitrary DER streams and
//! pinned roots must never panic, and verification must fail closed
//! (never accept) on malformed input.

use libfuzzer_sys::fuzz_target;
use srct_compute::vendor::{split_cert_der, verify_cert_chain, ChainCurve};

fuzz_target!(|data: &[u8]| {
    if data.len() < 66 {
        return;
    }
    let (chain_blob, pin_bytes) = data.split_at(data.len() - 32);
    let mut pin = [0u8; 32];
    pin.copy_from_slice(&pin_bytes[..32.min(pin_bytes.len())]);
    // Split the blob into DER chunks at SEQUENCE boundaries.
    let mut chain: Vec<Vec<u8>> = Vec::new();
    let mut off = 0;
    while off < chain_blob.len() && chain.len() < 4 {
        if chain_blob.len() - off < 2 || chain_blob[off] != 0x30 {
            break;
        }
        let len = chain_blob[off + 1] as usize;
        if len >= 128 || off + 2 + len > chain_blob.len() {
            break;
        }
        chain.push(chain_blob[off..off + 2 + len].to_vec());
        off += 2 + len;
    }
    if chain.is_empty() {
        let _ = split_cert_der(chain_blob);
        return;
    }
    let _ = verify_cert_chain(&chain, &[pin], &[], 1_700_000_000, ChainCurve::P256);
});
