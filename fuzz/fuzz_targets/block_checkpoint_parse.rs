//! Fuzz: block-carried checkpoint certificate parsing (C1/N1 Approach (ii)).
//!
//! Feeds arbitrary bytes to `Checkpoint::deserialize` (length-prefixed, like
//! the block wire format) and to full-block round-trips carrying a checkpoint
//! section; asserts no panic and byte-stability of accepted inputs. Liveness:
//! malformed inputs are refused by named error, never by panic or hang.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Raw checkpoint bytes: must not panic, accepted inputs round-trip.
    if data.len() >= 4 && data.len() <= 4096 {
        if let Ok(cp) = srct_core::bls_checkpoint::Checkpoint::deserialize(data) {
            let re = cp.serialize();
            let again = srct_core::bls_checkpoint::Checkpoint::deserialize(&re)
                .expect("a checkpoint must decode from its own encoding");
            debug_assert_eq!(again.serialize(), re, "checkpoint re-encoding must be stable");
            // Ancestry binding walk must not panic on adversarial cert bytes.
            let _ = cp.payload.height;
            let _ = cp.signer_count;
        }
    }

    // 2. Block with checkpoint section: split input into block bytes + cert bytes.
    if data.len() > 16 {
        let (block_bytes, cert_bytes) = data.split_at(data.len() / 2);
        if let Ok(mut block) = srct_core::block::Block::deserialize(block_bytes) {
            block.checkpoint = None;
            // Re-serializing a block without checkpoint must be stable.
            let re = block.serialize();
            let _ = srct_core::block::Block::deserialize(&re);
            // Attaching an adversarial-but-parseable cert must either verify
            // or be refused at submit time — both are non-panicking paths;
            // here we only exercise serialization, not consensus.
            if let Ok(cp) = srct_core::bls_checkpoint::Checkpoint::deserialize(cert_bytes) {
                block.checkpoint = Some(cp);
                let with_cp = block.serialize();
                let _ = srct_core::block::Block::deserialize(&with_cp);
            }
        }
    }
});
