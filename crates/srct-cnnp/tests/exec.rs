//! Acceptance tests for the execution-evidence gate: required-evidence
//! mapping and single-verifier stage checks across TEE, FHE and ZKML.

use rand::{rngs::StdRng, SeedableRng};
use srct_cnnp::registry::CAPABILITY_VERSION;
use srct_cnnp::{
    required_evidence, Capability, ModelSpace, Privacy, SignedCapability, StageError, StageGate,
    Verification,
};
use srct_compute::tee::{SignedTeeQuote, TeeQuote, TeeSla, TeeType, TEE_VERSION};
use srct_core::wallet::Wallet;
use srct_fhe::{
    eval, FheKeys, FheReceipt, FheTask, SignedFheReceipt, SignedFheTask, WeightedSum, FHE_VERSION,
};
use srct_verify::{AttestationRoots, Evidence, EvidenceKind};
use srct_zkml::{prove_linear, SignedZkReceipt, SignedZkTask, ZkReceipt, ZkTask, ZK_VERSION};

const HEIGHT: u64 = 30;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "cnnp-exec-test").unwrap()
}

fn space(id: u8) -> ModelSpace {
    ModelSpace {
        model_id: [id; 32],
        tokenizer: [id.wrapping_add(1); 32],
        architecture: "test-mlp".into(),
        layer: "hidden".into(),
        dim: 8,
        dtype: srct_cnnp::DType::F32,
    }
}

fn capability(
    provider: &Wallet,
    privacy: Privacy,
    verification: Verification,
    nonce: u64,
) -> SignedCapability {
    SignedCapability::sign(
        Capability {
            version: CAPABILITY_VERSION,
            provider: provider.address().unwrap(),
            source: space(1),
            target: space(2),
            service: "forward".into(),
            price_sat_per_unit: 5,
            max_units: 10,
            latency_ms: 50,
            privacy,
            verification,
            expires_height: 100,
            nonce,
        },
        provider,
    )
    .unwrap()
}

fn roots_for(attester: &Wallet, tee: TeeType) -> AttestationRoots {
    let mut roots = AttestationRoots::new();
    roots.add_root(attester.address().unwrap(), tee);
    roots
}

fn tee_evidence(provider: &Wallet, attester: &Wallet) -> (TeeSla, SignedTeeQuote) {
    let sla = TeeSla {
        version: TEE_VERSION,
        network_id: "srct/testnet".into(),
        provider: provider.address().unwrap(),
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::SevSnp,
        max_age_heights: 10,
    };
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
        attester,
    )
    .unwrap();
    (sla, quote)
}

fn fhe_evidence(provider: &Wallet) -> (SignedFheTask, SignedFheReceipt) {
    let requester = wallet(31);
    let keys = FheKeys::generate(&mut StdRng::seed_from_u64(41));
    let mut r = StdRng::seed_from_u64(42);
    let op = WeightedSum {
        weights: vec![3, -2],
        bias: 7,
    };
    let inputs = vec![keys.encrypt(10, &mut r), keys.encrypt(4, &mut r)];
    let task = SignedFheTask::sign(
        FheTask {
            version: FHE_VERSION,
            network_id: "srct/testnet".into(),
            requester: requester.address().unwrap(),
            provider: provider.address().unwrap(),
            enc_pubkey: keys.public_bytes(),
            op,
            inputs,
            deadline_height: HEIGHT + 10,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    let output = eval(&task.task.op, &task.task.inputs).unwrap();
    let receipt = SignedFheReceipt::sign(
        FheReceipt {
            version: FHE_VERSION,
            task: task.hash(),
            worker: provider.address().unwrap(),
            output,
            height: HEIGHT,
            nonce: 1,
        },
        provider,
    )
    .unwrap();
    (task, receipt)
}

fn zk_evidence(provider: &Wallet) -> (SignedZkTask, SignedZkReceipt) {
    let requester = wallet(51);
    let weights = vec![3, -2, 5, 1];
    let bias = 7u64;
    let inputs = vec![10u16, 4, 6, 9];
    let package = prove_linear(&weights, bias, &inputs, &mut StdRng::seed_from_u64(61)).unwrap();
    let task = SignedZkTask::sign(
        ZkTask {
            version: ZK_VERSION,
            network_id: "srct/testnet".into(),
            requester: requester.address().unwrap(),
            provider: provider.address().unwrap(),
            weights,
            bias,
            input_commitments: package.input_commitments.clone(),
            deadline_height: HEIGHT + 10,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    let receipt = SignedZkReceipt::sign(
        ZkReceipt {
            version: ZK_VERSION,
            task: task.hash(),
            worker: provider.address().unwrap(),
            bit_proofs: package.bit_proofs.clone(),
            output_commitment: package.output_commitment,
            height: HEIGHT,
            nonce: 1,
        },
        package.input_commitments.len(),
        provider,
    )
    .unwrap();
    (task, receipt)
}

#[test]
fn required_evidence_mapping_is_pinned() {
    use Privacy::{Fhe, Public, Sealed, Tee};
    use Verification::Tee as VTee;
    use Verification::{None, Optimistic, ProviderSigned, Zk};
    assert_eq!(required_evidence(Public, None), vec![]);
    assert_eq!(required_evidence(Sealed, ProviderSigned), vec![]);
    assert_eq!(required_evidence(Sealed, Optimistic), vec![]);
    assert_eq!(
        required_evidence(Tee, ProviderSigned),
        vec![EvidenceKind::Tee]
    );
    assert_eq!(required_evidence(Public, VTee), vec![EvidenceKind::Tee]);
    // Tee promised twice still needs one quote.
    assert_eq!(required_evidence(Tee, VTee), vec![EvidenceKind::Tee]);
    assert_eq!(
        required_evidence(Fhe, ProviderSigned),
        vec![EvidenceKind::Fhe]
    );
    assert_eq!(required_evidence(Public, Zk), vec![EvidenceKind::Zk]);
    assert_eq!(
        required_evidence(Fhe, Zk),
        vec![EvidenceKind::Fhe, EvidenceKind::Zk]
    );
    assert_eq!(
        required_evidence(Tee, Zk),
        vec![EvidenceKind::Tee, EvidenceKind::Zk]
    );
}

#[test]
fn plain_stage_verifies_without_evidence() {
    let provider = wallet(1);
    let cap = capability(&provider, Privacy::Sealed, Verification::ProviderSigned, 1);
    let mut gate = StageGate::new();
    let out = gate
        .verify_stage(&cap, &[], &AttestationRoots::new(), HEIGHT)
        .unwrap();
    assert!(out.is_empty());
}

#[test]
fn tee_stage_verifies_with_attestation() {
    let provider = wallet(2);
    let attester = wallet(3);
    let cap = capability(&provider, Privacy::Tee, Verification::ProviderSigned, 1);
    let (sla, quote) = tee_evidence(&provider, &attester);
    let mut gate = StageGate::new();
    let out = gate
        .verify_stage(
            &cap,
            &[Evidence::Tee { sla, quote }],
            &roots_for(&attester, TeeType::SevSnp),
            HEIGHT,
        )
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].output, [25u8; 32].to_vec());
}

#[test]
fn tee_stage_refuses_missing_wrong_and_tampered_evidence() {
    let provider = wallet(4);
    let stranger = wallet(5);
    let attester = wallet(6);
    let cap = capability(&provider, Privacy::Public, Verification::Tee, 1);
    let (sla, quote) = tee_evidence(&provider, &attester);
    let roots = roots_for(&attester, TeeType::SevSnp);
    let mut gate = StageGate::new();
    // Nothing supplied.
    assert_eq!(
        gate.verify_stage(&cap, &[], &roots, HEIGHT),
        Err(StageError::MissingEvidence(EvidenceKind::Tee))
    );
    // Another provider's quote.
    let (stranger_sla, stranger_quote) = tee_evidence(&stranger, &attester);
    let _ = stranger_sla;
    assert_eq!(
        gate.verify_stage(
            &cap,
            &[Evidence::Tee {
                sla: sla.clone(),
                quote: stranger_quote
            }],
            &roots,
            HEIGHT
        ),
        Err(StageError::WrongProvider)
    );
    // Tampered output breaks the attestation signature.
    let mut bad = quote.clone();
    bad.quote.output_hash = [99u8; 32];
    assert!(matches!(
        gate.verify_stage(&cap, &[Evidence::Tee { sla, quote: bad }], &roots, HEIGHT),
        Err(StageError::EvidenceRefused(_))
    ));
}

#[test]
fn zk_stage_verifies_with_proof() {
    let provider = wallet(7);
    let cap = capability(&provider, Privacy::Sealed, Verification::Zk, 1);
    let (task, receipt) = zk_evidence(&provider);
    let mut gate = StageGate::new();
    let out = gate
        .verify_stage(
            &cap,
            &[Evidence::Zk { task, receipt }],
            &AttestationRoots::new(),
            HEIGHT,
        )
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].output.len(), 33);
}

#[test]
fn fhe_stage_verifies_with_receipt() {
    let provider = wallet(8);
    let cap = capability(&provider, Privacy::Fhe, Verification::ProviderSigned, 1);
    let (task, receipt) = fhe_evidence(&provider);
    let mut gate = StageGate::new();
    let out = gate
        .verify_stage(
            &cap,
            &[Evidence::Fhe { task, receipt }],
            &AttestationRoots::new(),
            HEIGHT,
        )
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].output.len(), 66);
}

#[test]
fn bad_capability_and_replay_are_refused() {
    let provider = wallet(9);
    let attester = wallet(10);
    let mut cap = capability(&provider, Privacy::Tee, Verification::ProviderSigned, 1);
    cap.capability.price_sat_per_unit = 999;
    let (sla, quote) = tee_evidence(&provider, &attester);
    let roots = roots_for(&attester, TeeType::SevSnp);
    let mut gate = StageGate::new();
    assert!(matches!(
        gate.verify_stage(
            &cap,
            &[Evidence::Tee {
                sla: sla.clone(),
                quote: quote.clone()
            }],
            &roots,
            HEIGHT
        ),
        Err(StageError::BadCapability(_))
    ));
    // Fix the capability; the evidence verifies once, then replays.
    let cap = capability(&provider, Privacy::Tee, Verification::ProviderSigned, 2);
    gate.verify_stage(
        &cap,
        &[Evidence::Tee {
            sla: sla.clone(),
            quote: quote.clone(),
        }],
        &roots,
        HEIGHT,
    )
    .unwrap();
    assert!(matches!(
        gate.verify_stage(&cap, &[Evidence::Tee { sla, quote }], &roots, HEIGHT),
        Err(StageError::EvidenceRefused(_))
    ));
}

#[test]
fn wire_mutations_never_panic() {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let provider = wallet(21);
    let cap = capability(&provider, Privacy::Sealed, Verification::ProviderSigned, 1);
    let encoded = cap.encode();
    let mut rng = StdRng::seed_from_u64(0xbeef);
    for _ in 0..300 {
        let mut b = encoded.clone();
        match rng.gen_range(0..3) {
            0 => b.truncate(rng.gen_range(0..=b.len())),
            1 => {
                for _ in 0..rng.gen_range(1..=4) {
                    if !b.is_empty() {
                        let i = rng.gen_range(0..b.len());
                        b[i] ^= 1 << rng.gen_range(0..8);
                    }
                }
            }
            _ => b.extend((0..rng.gen_range(1..=8)).map(|_| rng.gen::<u8>())),
        }
        // Must return Ok or Err — never panic.
        let _ = SignedCapability::decode(&b);
    }
}
