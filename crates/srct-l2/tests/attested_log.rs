//! Acceptance tests for the staged TEE execution log: activation switch,
//! verified filing, replay refusal and snapshot replay.

use srct_compute::tee::{TeeQuote, TeeType, TEE_VERSION};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;
use srct_l2::attested_log::AttestedExecutionLog;
use srct_l2::error::L2Error;
use srct_l2::tee_evidence::TeeBackedAttestation;
use srct_verify::{AttestationRoots, SignedTeeQuote, TeeSla, UnifiedVerifier};

const NET: &str = "srct/testnet";
const HEIGHT: u64 = 30;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-log-test").unwrap()
}

fn sla(provider: srct_core::hash::Address, workload: Hash) -> TeeSla {
    TeeSla {
        version: TEE_VERSION,
        network_id: NET.into(),
        provider,
        workload,
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::SevSnp,
        max_age_heights: 10,
    }
}

fn attestation(workload: Hash) -> (TeeBackedAttestation, AttestationRoots, UnifiedVerifier) {
    let provider = wallet(1).address().unwrap();
    let attester = wallet(2);
    let sla = sla(provider, workload);
    let quote = SignedTeeQuote::sign(
        TeeQuote {
            version: TEE_VERSION,
            network_id: sla.network_id.clone(),
            provider: sla.provider,
            tee: sla.tee,
            workload: sla.workload,
            model_hash: sla.model_hash,
            runtime_hash: sla.runtime_hash,
            config_hash: sla.config_hash,
            input_hash: sla.input_hash,
            output_hash: [25u8; 32],
            height: HEIGHT,
            nonce: 1,
        },
        &attester,
    )
    .unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(attester.address().unwrap(), TeeType::SevSnp);
    (
        TeeBackedAttestation { sla, quote },
        roots,
        UnifiedVerifier::new(),
    )
}

#[test]
fn disabled_log_records_nothing() {
    let (att, roots, mut verifier) = attestation([11u8; 32]);
    let mut log = AttestedExecutionLog::new(NET, false);
    assert_eq!(
        log.record(att, &roots, &mut verifier, HEIGHT),
        Err(L2Error::BadAttestation("attested log is not active"))
    );
    assert!(log.is_empty());
}

#[test]
fn enabled_log_files_verified_attestations_once() {
    let (att, roots, mut verifier) = attestation([11u8; 32]);
    let mut log = AttestedExecutionLog::new(NET, true);
    let task = log.record(att, &roots, &mut verifier, HEIGHT).unwrap();
    assert_eq!(task, [11u8; 32]);
    assert_eq!(log.len(), 1);
    assert!(log.get(&task).is_some());
    // A second attestation for the same task is a replay, never an update.
    let (att2, roots2, mut verifier2) = attestation([11u8; 32]);
    assert_eq!(
        log.record(att2, &roots2, &mut verifier2, HEIGHT),
        Err(L2Error::Replay)
    );
}

#[test]
fn log_refuses_foreign_and_untrusted_evidence() {
    let (att, roots, mut verifier) = attestation([12u8; 32]);
    let mut foreign = AttestedExecutionLog::new("srct/other", true);
    assert!(matches!(
        foreign.record(att, &roots, &mut verifier, HEIGHT),
        Err(L2Error::BadAttestation(_))
    ));
    // Unknown attester: the cryptographic check fails before filing.
    let provider = wallet(1).address().unwrap();
    let stranger = wallet(9);
    let sla = sla(provider, [13u8; 32]);
    let quote = SignedTeeQuote::sign(
        TeeQuote {
            version: TEE_VERSION,
            network_id: sla.network_id.clone(),
            provider: sla.provider,
            tee: sla.tee,
            workload: sla.workload,
            model_hash: sla.model_hash,
            runtime_hash: sla.runtime_hash,
            config_hash: sla.config_hash,
            input_hash: sla.input_hash,
            output_hash: [25u8; 32],
            height: HEIGHT,
            nonce: 1,
        },
        &stranger,
    )
    .unwrap();
    let mut log = AttestedExecutionLog::new(NET, true);
    assert!(log
        .record(
            TeeBackedAttestation { sla, quote },
            &AttestationRoots::new(),
            &mut UnifiedVerifier::new(),
            HEIGHT
        )
        .is_err());
    assert!(log.is_empty());
}

#[test]
fn log_snapshot_replays_identically() {
    let (att, roots, mut verifier) = attestation([14u8; 32]);
    let mut log = AttestedExecutionLog::new(NET, true);
    log.record(att, &roots, &mut verifier, HEIGHT).unwrap();
    let bytes = log.encode();
    let restored = AttestedExecutionLog::decode(&bytes).unwrap();
    assert!(restored.is_enabled());
    assert_eq!(restored.len(), 1);
    assert!(restored.get(&[14u8; 32]).is_some());
    // The switch is part of the snapshot: an unknown value fails closed.
    let mut bad = bytes.clone();
    bad[15] = 0x02;
    assert!(AttestedExecutionLog::decode(&bad).is_err());
    assert!(AttestedExecutionLog::decode(&bytes[..bytes.len() - 4]).is_err());
    assert!(AttestedExecutionLog::decode(&[99u8; 8]).is_err());
}
