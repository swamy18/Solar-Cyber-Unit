//! C1/N1 Approach (ii) tests: deterministic block-carried checkpoint finality.
//!
//! Covers: ancestry-derived binding on empty chains, carried-certificate
//! acceptance, pre-activation refusal, future/wrong-hash/duplicate/PQ-sidecar
//! refusal, fork-aware binding, and the L2 root-validation hook wiring
//! (accept on match, refuse on mismatch, skip when no validator is set).

use srct_core::bls_checkpoint::{BlsSignature, Checkpoint, CheckpointPayload};
use srct_core::chain::{Chain, ChainVerifier, L2RootError, L2RootValidator};
use srct_core::hash::{Address, Hash, Hash512};
use srct_core::params::NetworkParams;

fn addr(seed: u8) -> Address {
    [seed; 20]
}

fn ts(h: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + h * 1000
}

fn cert_profile() -> NetworkParams {
    let mut p = NetworkParams::mini();
    // Checkpoint carry active from 20 (multiple of mini interval 10).
    // Root validation stays off: these tests pin binding, not roots.
    p.checkpoint_carry_activation_height = 20;
    p.l2_root_validation_height = 0;
    p
}

fn root_validation_profile() -> NetworkParams {
    let mut p = NetworkParams::mini();
    p.checkpoint_carry_activation_height = 20;
    // Root validation active from 40: at least one checkpoint interval of
    // cert history exists before enforcement begins.
    p.l2_root_validation_height = 40;
    p
}

/// A structurally valid checkpoint for `height`/`block_hash` on the test
/// committee (mini bootstrap: 4 keys, quorum 3, LSB-first bitmap).
fn test_cert(height: u64, block_hash: Hash512) -> Checkpoint {
    Checkpoint {
        payload: CheckpointPayload {
            height,
            block_hash,
            network_id: "srct/mini".to_string(),
            epoch: height / NetworkParams::mini().checkpoint_interval_blocks,
        },
        aggregate_sig: BlsSignature([0xAB; 96]),
        signer_bitmap: vec![0x07],
        signer_count: 3,
        pq_sidecar: Vec::new(),
    }
}

fn mine_empty(chain: &mut Chain, miner: Address, h: u64) -> srct_core::block::Block {
    chain.mine_block(miner, vec![], ts(h)).unwrap()
}

#[test]
fn ancestry_binding_is_zero_without_certificates() {
    let mut chain = Chain::new(cert_profile()).unwrap();
    chain.set_bls_verifier(ChainVerifier::Mock);
    for h in 1..=30u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    let tip = chain.tip_hash();
    assert_eq!(chain.ancestry_binding_height(&tip), 0);
}

#[test]
fn carried_certificate_advances_binding() {
    let mut chain = Chain::new(cert_profile()).unwrap();
    chain.set_bls_verifier(ChainVerifier::Mock);
    for h in 1..=20u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    // Certify height 10 (already canonical on this single chain).
    let h10 = chain.block_at(10).unwrap().clone();
    let cp = test_cert(10, h10.block_hash());
    let carrier = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp,
            ts(21),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(carrier).unwrap();
    let tip = chain.tip_hash();
    assert_eq!(chain.ancestry_binding_height(&tip), 10);
    // Later blocks inherit the binding without carrying another cert.
    let b22 = mine_empty(&mut chain, addr(1), 22);
    chain.submit(b22).unwrap();
    let tip = chain.tip_hash();
    assert_eq!(chain.ancestry_binding_height(&tip), 10);
}

#[test]
fn checkpoint_before_carry_activation_is_refused() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=5u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    let h3 = chain.block_at(3).unwrap().clone();
    let cp = test_cert(3, h3.block_hash());
    let bad = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp,
            ts(6),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    let err = chain.submit(bad).unwrap_err();
    assert!(
        matches!(err, srct_core::error::Error::Malformed(m) if m == "checkpoint before carry activation")
    );
}

#[test]
fn future_checkpoint_is_refused() {
    let mut chain = Chain::new(cert_profile()).unwrap();
    chain.set_bls_verifier(ChainVerifier::Mock);
    for h in 1..=20u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    // Certify a height at/after the carrier (21): self-certification window.
    let tip = chain.tip().clone();
    let cp = test_cert(21, tip.block_hash());
    let bad = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp,
            ts(21),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    let err = chain.submit(bad).unwrap_err();
    assert!(
        matches!(err, srct_core::error::Error::Malformed(m) if m == "checkpoint must certify a strictly earlier height")
    );
}

#[test]
fn wrong_hash_checkpoint_is_refused() {
    let mut chain = Chain::new(cert_profile()).unwrap();
    chain.set_bls_verifier(ChainVerifier::Mock);
    for h in 1..=20u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    // Correct height, wrong hash.
    let mut fake = [0u8; 64];
    fake[0] = 0xFF;
    let cp = test_cert(10, fake);
    let bad = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp,
            ts(21),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    let err = chain.submit(bad).unwrap_err();
    assert!(
        matches!(err, srct_core::error::Error::Malformed(m) if m == "checkpoint does not match this fork's canonical block")
    );
}

#[test]
fn duplicate_checkpoint_height_is_refused() {
    let mut chain = Chain::new(cert_profile()).unwrap();
    chain.set_bls_verifier(ChainVerifier::Mock);
    for h in 1..=20u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    let h10 = chain.block_at(10).unwrap().clone();
    let cp = test_cert(10, h10.block_hash());
    let carrier = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp,
            ts(21),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(carrier).unwrap();
    // Second cert for an already-certified height: no binding advance.
    let h10b = chain.block_at(10).unwrap().clone();
    let cp2 = test_cert(10, h10b.block_hash());
    let dup = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp2,
            ts(22),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    let err = chain.submit(dup).unwrap_err();
    assert!(
        matches!(err, srct_core::error::Error::Malformed(m) if m == "checkpoint does not advance binding finality")
    );
}

#[test]
fn pq_sidecar_checkpoint_is_refused() {
    let mut chain = Chain::new(cert_profile()).unwrap();
    chain.set_bls_verifier(ChainVerifier::Mock);
    for h in 1..=20u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    let h10 = chain.block_at(10).unwrap().clone();
    let mut cp = test_cert(10, h10.block_hash());
    cp.pq_sidecar = vec![srct_core::bls_checkpoint::PqSidecarEntry {
        signer_index: 0,
        signature: [0u8; 3309],
    }];
    // mine_block_with_checkpoint does not inspect the sidecar; submit must.
    let bad = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp,
            ts(21),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    assert!(matches!(
        chain.submit(bad),
        Err(srct_core::error::Error::Malformed(_))
    ));
}

#[test]
fn binding_is_fork_aware() {
    let mut chain = Chain::new(cert_profile()).unwrap();
    chain.set_bls_verifier(ChainVerifier::Mock);
    for h in 1..=20u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    // Fork BEFORE the checkpoint block, so the two branches diverge: the
    // main fork carries a cert for height 10 at block 21; the side fork has
    // no cert at all.
    let mut fork = chain.clone();
    let h10 = chain.block_at(10).unwrap().clone();
    let cp = test_cert(10, h10.block_hash());
    let main21 = chain
        .mine_block_with_checkpoint(
            addr(1),
            vec![],
            Vec::new(),
            Vec::new(),
            None,
            cp,
            ts(21),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    let main21_hash = main21.block_hash();
    chain.submit(main21).unwrap();
    let side21 = fork.mine_block(addr(2), vec![], ts(21) + 7).unwrap();
    let side21_hash = side21.block_hash();
    fork.submit(side21).unwrap();
    // Binding differs per fork: main sees 10, side sees 0.
    assert_eq!(chain.ancestry_binding_height(&main21_hash), 10);
    assert_eq!(fork.ancestry_binding_height(&side21_hash), 0);
}

/// Stub L2 root validator for wiring tests: returns a fixed root.
#[derive(Debug)]
struct FixedRoot {
    root: Hash,
    err: bool,
}

impl L2RootValidator for FixedRoot {
    fn expected_root_at(
        &self,
        _chain: &Chain,
        _parent_hash: Hash512,
        _block: &srct_core::block::Block,
    ) -> std::result::Result<Hash, L2RootError> {
        if self.err {
            return Err(L2RootError::Replay("stub failure".to_string()));
        }
        Ok(self.root)
    }
}

#[test]
fn root_validation_rejects_mismatch_and_skips_without_validator() {
    // No validator wired: blocks with arbitrary roots are accepted as before.
    let mut chain = Chain::new(root_validation_profile()).unwrap();
    for h in 1..=40u64 {
        let b = mine_empty(&mut chain, addr(1), h);
        chain.submit(b).unwrap();
    }
    // Wire a stub validator returning the zero root.
    chain.set_l2_validator(std::sync::Arc::new(FixedRoot {
        root: [0u8; 32],
        err: false,
    }));
    // Block with a NON-matching root is refused.
    let wrong = chain
        .mine_block_with_l2_root(
            addr(1),
            vec![],
            Vec::new(),
            [9u8; 32],
            ts(41),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    assert!(matches!(
        chain.submit(wrong),
        Err(srct_core::error::Error::Malformed(_))
    ));
    // Block with the matching root is accepted.
    let right = chain
        .mine_block_with_l2_root(
            addr(1),
            vec![],
            Vec::new(),
            [0u8; 32],
            ts(41),
            None,
            srct_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(right).expect("matching root must be accepted");
}
