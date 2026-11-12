//! Acceptance tests for unified verification: policy selection and
//! single-verifier dispatch across TEE, FHE and ZKML evidence.

use rand::{rngs::StdRng, SeedableRng};
use srct_compute::market::{
    plan_assignments, ComputeJob, ComputeOffer, Verification, JOB_VERSION, OFFER_VERSION,
};
use srct_compute::tee::{
    AttestationRoots, SignedTeeQuote, TeeError, TeeQuote, TeeSla, TeeType, TEE_VERSION,
};
use srct_compute::{
    ComputeError, ComputeReceipt, Determinism, DeviceClass, DeviceProfile, SignedAssignment,
    SignedReceipt,
};
use srct_core::wallet::Wallet;
use srct_fhe::{
    eval, FheError, FheKeys, FheReceipt, FheTask, SignedFheReceipt, SignedFheTask, WeightedSum,
    FHE_VERSION,
};
use srct_verify::{
    select_proofs, Evidence, EvidenceKind, ProofKind, SecurityLevel, TaskKind, TaskProfile,
    UnifiedVerifier, VerifyError,
};
use srct_zkml::{
    prove_linear, SignedZkReceipt, SignedZkTask, ZkError, ZkReceipt, ZkTask, ZK_VERSION,
};

const NET: &str = "srct/testnet";
const HEIGHT: u64 = 100;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "verify-test").unwrap()
}

fn profile(kind: TaskKind, security: SecurityLevel, value_sat: u64) -> TaskProfile {
    TaskProfile {
        kind,
        security,
        value_sat,
    }
}

#[test]
fn policy_selects_proofs() {
    use SecurityLevel::{Critical, High, Standard};
    // Cheap plain inference needs nothing; value or level raises correctness.
    assert_eq!(
        select_proofs(&profile(TaskKind::Inference, Standard, 0)),
        vec![]
    );
    assert_eq!(
        select_proofs(&profile(TaskKind::Inference, Standard, 1_000_000)),
        vec![ProofKind::Correctness]
    );
    assert_eq!(
        select_proofs(&profile(TaskKind::Inference, High, 0)),
        vec![ProofKind::Correctness]
    );
    // Encrypted compute always proves correctness; high stakes add execution.
    assert_eq!(
        select_proofs(&profile(TaskKind::EncryptedCompute, Standard, 0)),
        vec![ProofKind::Correctness]
    );
    assert_eq!(
        select_proofs(&profile(TaskKind::EncryptedCompute, High, 0)),
        vec![ProofKind::Execution, ProofKind::Correctness]
    );
    // Attested execution always proves execution; critical adds correctness.
    assert_eq!(
        select_proofs(&profile(TaskKind::AttestedExecution, Standard, 0)),
        vec![ProofKind::Execution]
    );
    assert_eq!(
        select_proofs(&profile(TaskKind::AttestedExecution, Critical, 0)),
        vec![ProofKind::Execution, ProofKind::Correctness]
    );
    // Proven compute is correctness only at every level.
    for level in [Standard, High, Critical] {
        assert_eq!(
            select_proofs(&profile(TaskKind::ProvenCompute, level, 0)),
            vec![ProofKind::Correctness]
        );
    }
}

fn tee_evidence() -> (AttestationRoots, TeeSla, SignedTeeQuote) {
    let provider = wallet(1);
    let attester = wallet(2);
    let sla = TeeSla {
        version: TEE_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::SevSnp,
        max_age_heights: 10,
    };
    let quote = TeeQuote {
        version: TEE_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        tee: TeeType::SevSnp,
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        output_hash: [25u8; 32],
        height: HEIGHT,
        nonce: 1,
    };
    let signed = SignedTeeQuote::sign(quote, &attester).unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(attester.address().unwrap(), TeeType::SevSnp);
    (roots, sla, signed)
}

#[test]
fn unified_tee_verifies_and_replays() {
    let (roots, sla, quote) = tee_evidence();
    let mut verifier = UnifiedVerifier::new();
    let out = verifier
        .verify(&Evidence::Tee { sla, quote }, &roots, HEIGHT)
        .unwrap();
    assert_eq!(out.kind, EvidenceKind::Tee);
    assert_eq!(out.output, [25u8; 32].to_vec());
    // Same quote again is a replay, surfaced transparently.
    let (roots, sla, quote) = tee_evidence();
    let mut verifier = UnifiedVerifier::new();
    verifier
        .verify(
            &Evidence::Tee {
                sla: sla.clone(),
                quote: quote.clone(),
            },
            &roots,
            HEIGHT,
        )
        .unwrap();
    assert_eq!(
        verifier.verify(&Evidence::Tee { sla, quote }, &roots, HEIGHT),
        Err(VerifyError::Tee(TeeError::Replay))
    );
}

fn fhe_evidence() -> (SignedFheTask, SignedFheReceipt) {
    let requester = wallet(3);
    let provider = wallet(4);
    let keys = FheKeys::generate(&mut StdRng::seed_from_u64(1));
    let mut r = StdRng::seed_from_u64(2);
    let op = WeightedSum {
        weights: vec![3, -2],
        bias: 7,
    };
    let inputs = vec![keys.encrypt(10, &mut r), keys.encrypt(4, &mut r)];
    let task = SignedFheTask::sign(
        FheTask {
            version: FHE_VERSION,
            network_id: NET.into(),
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
        &provider,
    )
    .unwrap();
    (task, receipt)
}

#[test]
fn unified_fhe_verifies_and_refuses_fraud() {
    let (task, receipt) = fhe_evidence();
    let roots = AttestationRoots::new();
    let mut verifier = UnifiedVerifier::new();
    let out = verifier
        .verify(
            &Evidence::Fhe {
                task: task.clone(),
                receipt,
            },
            &roots,
            HEIGHT,
        )
        .unwrap();
    assert_eq!(out.kind, EvidenceKind::Fhe);
    assert_eq!(out.output.len(), 66);
    // Tampered output fails as fraud, surfaced transparently.
    let bad_output = srct_fhe::Ciphertext::trivial_plaintext(1);
    let (task, _) = fhe_evidence();
    let provider = wallet(4);
    let bad = SignedFheReceipt::sign(
        FheReceipt {
            version: FHE_VERSION,
            task: task.hash(),
            worker: provider.address().unwrap(),
            output: bad_output,
            height: HEIGHT,
            nonce: 9,
        },
        &provider,
    )
    .unwrap();
    assert_eq!(
        verifier.verify(&Evidence::Fhe { task, receipt: bad }, &roots, HEIGHT),
        Err(VerifyError::Fhe(FheError::FraudulentOutput))
    );
}

fn zk_evidence() -> (SignedZkTask, SignedZkReceipt) {
    let requester = wallet(5);
    let provider = wallet(6);
    let weights = vec![3, -2, 5, 1];
    let bias = 7u64;
    let inputs = vec![10u16, 4, 6, 9];
    let package = prove_linear(&weights, bias, &inputs, &mut StdRng::seed_from_u64(3)).unwrap();
    let task = SignedZkTask::sign(
        ZkTask {
            version: ZK_VERSION,
            network_id: NET.into(),
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
        &provider,
    )
    .unwrap();
    (task, receipt)
}

#[test]
fn unified_zk_verifies_and_refuses_wrong_statement() {
    let (task, receipt) = zk_evidence();
    let roots = AttestationRoots::new();
    let mut verifier = UnifiedVerifier::new();
    let out = verifier
        .verify(
            &Evidence::Zk {
                task: task.clone(),
                receipt,
            },
            &roots,
            HEIGHT,
        )
        .unwrap();
    assert_eq!(out.kind, EvidenceKind::Zk);
    assert_eq!(out.output.len(), 33);
    // Same proofs under different public weights: invalid.
    let requester = wallet(5);
    let (old_task, _) = zk_evidence();
    let mut bad_weights = old_task.task.weights.clone();
    bad_weights[0] = 4;
    let bad_task = SignedZkTask::sign(
        ZkTask {
            weights: bad_weights,
            nonce: 2,
            ..old_task.task.clone()
        },
        &requester,
    )
    .unwrap();
    let (_, receipt) = zk_evidence();
    let bad_receipt = SignedZkReceipt::sign(
        ZkReceipt {
            task: bad_task.hash(),
            ..receipt.receipt.clone()
        },
        bad_task.task.input_commitments.len(),
        &wallet(6),
    )
    .unwrap();
    assert_eq!(
        verifier.verify(
            &Evidence::Zk {
                task: bad_task,
                receipt: bad_receipt
            },
            &roots,
            HEIGHT
        ),
        Err(VerifyError::Zk(ZkError::InvalidProof))
    );
}

#[test]
fn one_verifier_handles_mixed_evidence() {
    let roots = AttestationRoots::new();
    let mut verifier = UnifiedVerifier::new();
    let (troots, sla, quote) = tee_evidence();
    let (ftask, freceipt) = fhe_evidence();
    let (ztask, zreceipt) = zk_evidence();
    assert!(verifier
        .verify(&Evidence::Tee { sla, quote }, &troots, HEIGHT)
        .is_ok());
    assert!(verifier
        .verify(
            &Evidence::Fhe {
                task: ftask,
                receipt: freceipt
            },
            &roots,
            HEIGHT
        )
        .is_ok());
    assert!(verifier
        .verify(
            &Evidence::Zk {
                task: ztask,
                receipt: zreceipt
            },
            &roots,
            HEIGHT
        )
        .is_ok());
}

fn compute_evidence() -> (SignedAssignment, SignedReceipt) {
    let provider = wallet(11);
    let requester = wallet(12);
    let profile = DeviceProfile::new(
        DeviceClass::Gpu,
        Determinism::Reproducible,
        24_576,
        8,
        20,
        50_000,
        [7u8; 32],
    );
    let offer = srct_compute::market::SignedOffer::sign(
        ComputeOffer {
            version: OFFER_VERSION,
            network_id: NET.into(),
            provider: provider.address().unwrap(),
            service: "train.mlp".into(),
            profile,
            unit_price_sat: 7,
            min_units: 1,
            max_units_per_job: 20,
            privacy: false,
            verification: Verification::Receipt,
            available_from: 0,
            available_until: 1_000,
            nonce: 1,
        },
        &provider,
    )
    .unwrap();
    let job = srct_compute::market::SignedJob::sign(
        ComputeJob {
            version: JOB_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            service: "train.mlp".into(),
            units: 5,
            max_unit_price_sat: 20,
            max_total_sat: 100,
            class_mask: DeviceClass::Gpu.mask(),
            min_ram_mib: 512,
            determinism: Determinism::Reproducible,
            required_kernel: [7u8; 32],
            min_verification: Verification::Receipt,
            sealed_input: false,
            input: [3u8; 32],
            deadline: 100,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    let plan = plan_assignments(&job, std::slice::from_ref(&offer), 10, 1).unwrap();
    let assignment = plan.sign(&requester).unwrap().assignments.remove(0);
    let receipt = SignedReceipt::sign(
        ComputeReceipt::new(&assignment, 5, [4u8; 32], 1_000, 20, 1).unwrap(),
        &provider,
    )
    .unwrap();
    (assignment, receipt)
}

#[test]
fn unified_compute_verifies_and_refuses_replay() {
    let roots = AttestationRoots::new();
    let mut verifier = UnifiedVerifier::new();
    let (assignment, receipt) = compute_evidence();
    let out = verifier
        .verify(
            &Evidence::Compute {
                assignment: assignment.clone(),
                receipt: receipt.clone(),
            },
            &roots,
            HEIGHT,
        )
        .unwrap();
    assert_eq!(out.kind, EvidenceKind::Compute);
    assert_eq!(out.output, 35u64.to_le_bytes().to_vec());
    // Same receipt again is already settled.
    assert_eq!(
        verifier.verify(
            &Evidence::Compute {
                assignment,
                receipt
            },
            &roots,
            HEIGHT
        ),
        Err(VerifyError::Compute(ComputeError::AlreadySettled))
    );
}

#[test]
fn unified_compute_refuses_expired_receipt() {
    let roots = AttestationRoots::new();
    let mut verifier = UnifiedVerifier::new();
    let (assignment, receipt) = compute_evidence();
    assert_eq!(
        verifier.verify(
            &Evidence::Compute {
                assignment,
                receipt
            },
            &roots,
            101
        ),
        Err(VerifyError::Compute(ComputeError::Expired))
    );
}

#[test]
fn verify_for_profile_gates_release_on_policy() {
    // Attested execution (standard) needs Tee; compute receipt alone is not enough.
    let profile = TaskProfile {
        kind: TaskKind::AttestedExecution,
        security: SecurityLevel::Standard,
        value_sat: 0,
    };
    let (roots, sla, quote) = tee_evidence();
    let mut verifier = UnifiedVerifier::new();
    let tee_only = vec![Evidence::Tee {
        sla: sla.clone(),
        quote: quote.clone(),
    }];
    assert!(verifier
        .verify_for_profile(&profile, &tee_only, &roots, HEIGHT)
        .is_ok());
    let (assignment, receipt) = compute_evidence();
    let mut verifier = UnifiedVerifier::new();
    let compute_only = vec![Evidence::Compute {
        assignment,
        receipt,
    }];
    assert!(matches!(
        verifier.verify_for_profile(&profile, &compute_only, &roots, HEIGHT),
        Err(VerifyError::Policy(_))
    ));
    // Proven compute needs correctness; Tee alone is not enough, Zk passes.
    let proven = TaskProfile {
        kind: TaskKind::ProvenCompute,
        security: SecurityLevel::Standard,
        value_sat: 0,
    };
    let mut verifier = UnifiedVerifier::new();
    assert!(verifier
        .verify_for_profile(&profile, &tee_only, &roots, HEIGHT)
        .is_ok());
    let mut verifier = UnifiedVerifier::new();
    assert!(matches!(
        verifier.verify_for_profile(&proven, &tee_only, &roots, HEIGHT),
        Err(VerifyError::Policy(_))
    ));
    let (ztask, zreceipt) = zk_evidence();
    let mut verifier = UnifiedVerifier::new();
    let zk_only = vec![Evidence::Zk {
        task: ztask,
        receipt: zreceipt,
    }];
    assert!(verifier
        .verify_for_profile(&proven, &zk_only, &roots, HEIGHT)
        .is_ok());
}

#[test]
fn gated_release_runs_rail_only_on_policy_pass() {
    use srct_verify::{TaskKind, TaskProfile};
    let profile = TaskProfile {
        kind: TaskKind::ProvenCompute,
        security: SecurityLevel::Standard,
        value_sat: 0,
    };
    let roots = AttestationRoots::new();
    // Policy fails: the rail closure never runs.
    let mut verifier = UnifiedVerifier::new();
    let mut ran = false;
    let (assignment, receipt) = compute_evidence();
    let err = verifier.gated_release(
        &profile,
        &[Evidence::Compute {
            assignment,
            receipt,
        }],
        &roots,
        HEIGHT,
        |_| {
            ran = true;
        },
    );
    assert!(matches!(err, Err(VerifyError::Policy(_))));
    assert!(!ran);
    // Policy passes: the rail closure runs exactly once with the outputs.
    let mut verifier = UnifiedVerifier::new();
    let (ztask, zreceipt) = zk_evidence();
    let mut ran = false;
    let out = verifier
        .gated_release(
            &profile,
            &[Evidence::Zk {
                task: ztask,
                receipt: zreceipt,
            }],
            &roots,
            HEIGHT,
            |outputs| {
                ran = true;
                outputs.len()
            },
        )
        .unwrap();
    assert!(ran);
    assert_eq!(out, 1);
}
