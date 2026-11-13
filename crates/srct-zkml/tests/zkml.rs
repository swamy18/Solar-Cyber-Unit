//! Acceptance tests for ZKML verification: real Sigma-protocol proofs of
//! correct quantized linear evaluation, signed tasks/receipts and fail-closed
//! verification.

use rand::{rngs::StdRng, SeedableRng};
use srct_core::wallet::Wallet;
use srct_zkml::{
    eval_plaintext, prove_linear, verify_linear, SignedZkReceipt, SignedZkTask, ZkError, ZkReceipt,
    ZkTask, ZkVerifier, ZK_VERSION,
};

const NET: &str = "srct/testnet";
const HEIGHT: u64 = 100;

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x00be_ef42)
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "zkml-test").unwrap()
}

fn dims() -> (Vec<i64>, u64, Vec<u16>) {
    (vec![3, -2, 5, 1], 7, vec![10, 4, 6, 9])
}

fn task_for(
    requester: &Wallet,
    provider: &Wallet,
    weights: &[i64],
    bias: u64,
    input_coms: &[[u8; 33]],
    nonce: u64,
) -> SignedZkTask {
    SignedZkTask::sign(
        ZkTask {
            version: ZK_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            provider: provider.address().unwrap(),
            weights: weights.to_vec(),
            bias,
            input_commitments: input_coms.to_vec(),
            deadline_height: HEIGHT + 10,
            nonce,
        },
        requester,
    )
    .unwrap()
}

fn receipt_for(
    signed: &SignedZkTask,
    worker: &Wallet,
    package: &srct_zkml::LinearProof,
    height: u64,
    nonce: u64,
) -> SignedZkReceipt {
    SignedZkReceipt::sign(
        ZkReceipt {
            version: ZK_VERSION,
            task: signed.hash(),
            worker: worker.address().unwrap(),
            bit_proofs: package.bit_proofs.clone(),
            output_commitment: package.output_commitment,
            height,
            nonce,
        },
        package.input_commitments.len(),
        worker,
    )
    .unwrap()
}

#[test]
fn circuit_prove_and_verify() {
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    assert!(verify_linear(&weights, bias, &package).is_ok());
    // Plaintext cross-check: 7 + 3*10 - 2*4 + 5*6 + 1*9 = 68.
    assert_eq!(eval_plaintext(&weights, bias, &inputs), 68);
}

#[test]
fn full_workflow_settles() {
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let signed = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    );
    let receipt = receipt_for(&signed, &provider, &package, HEIGHT, 1);
    let mut verifier = ZkVerifier::new();
    assert_eq!(
        verifier.verify(&signed, &receipt, HEIGHT),
        Ok(package.output_commitment)
    );
}

#[test]
fn tampered_output_commitment_fails() {
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let signed = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    );
    let mut bad_out = package.output_commitment;
    bad_out[0] ^= 0x01;
    let bad_package = srct_zkml::LinearProof {
        input_commitments: package.input_commitments.clone(),
        bit_proofs: package.bit_proofs.clone(),
        output_commitment: bad_out,
    };
    let receipt = receipt_for(&signed, &provider, &bad_package, HEIGHT, 2);
    let mut verifier = ZkVerifier::new();
    assert_eq!(
        verifier.verify(&signed, &receipt, HEIGHT),
        Err(ZkError::InvalidProof)
    );
}

#[test]
fn wrong_statement_fails() {
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    // Same commitments, different public weights: the proofs do not match.
    let mut bad_weights = weights.clone();
    bad_weights[0] = 4;
    let signed = task_for(
        &requester,
        &provider,
        &bad_weights,
        bias,
        &package.input_commitments,
        1,
    );
    let receipt = receipt_for(&signed, &provider, &package, HEIGHT, 1);
    let mut verifier = ZkVerifier::new();
    assert_eq!(
        verifier.verify(&signed, &receipt, HEIGHT),
        Err(ZkError::InvalidProof)
    );
}

#[test]
fn tampered_commitments_break_the_task_signature() {
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let mut signed = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    );
    signed.task.input_commitments[0][0] ^= 0x01;
    assert!(matches!(signed.verify(), Err(ZkError::BadSignature(_))));
}

#[test]
fn impostor_and_wrong_worker_are_refused() {
    let requester = wallet(1);
    let provider = wallet(2);
    let stranger = wallet(9);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let signed = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    );
    let body = ZkReceipt {
        version: ZK_VERSION,
        task: signed.hash(),
        worker: provider.address().unwrap(),
        bit_proofs: package.bit_proofs.clone(),
        output_commitment: package.output_commitment,
        height: HEIGHT,
        nonce: 1,
    };
    assert!(matches!(
        SignedZkReceipt::sign(body, package.input_commitments.len(), &stranger),
        Err(ZkError::WrongWorker)
    ));
    let wrong = SignedZkReceipt::sign(
        ZkReceipt {
            version: ZK_VERSION,
            task: signed.hash(),
            worker: stranger.address().unwrap(),
            bit_proofs: package.bit_proofs.clone(),
            output_commitment: package.output_commitment,
            height: HEIGHT,
            nonce: 1,
        },
        package.input_commitments.len(),
        &stranger,
    )
    .unwrap();
    let mut verifier = ZkVerifier::new();
    assert_eq!(
        verifier.verify(&signed, &wrong, HEIGHT),
        Err(ZkError::BindingMismatch)
    );
}

#[test]
fn late_future_and_replay_are_refused() {
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let signed = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    );
    let make = |height: u64, nonce: u64| receipt_for(&signed, &provider, &package, height, nonce);
    let mut verifier = ZkVerifier::new();
    assert!(verifier.verify(&signed, &make(HEIGHT, 1), HEIGHT).is_ok());
    assert_eq!(
        verifier.verify(&signed, &make(HEIGHT, 2), HEIGHT),
        Err(ZkError::Replay)
    );
    assert_eq!(
        ZkVerifier::new().verify(&signed, &make(HEIGHT + 11, 3), HEIGHT + 11),
        Err(ZkError::Expired)
    );
    assert_eq!(
        ZkVerifier::new().verify(&signed, &make(HEIGHT + 1, 4), HEIGHT),
        Err(ZkError::FutureHeight)
    );
}

#[test]
fn malformed_tasks_and_receipts_are_refused() {
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let base = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    )
    .task;
    // Weight over the cap.
    let mut bad = base.clone();
    bad.weights[0] = 2_000_000;
    bad.nonce = 11;
    assert!(matches!(
        SignedZkTask::sign(bad, &requester),
        Err(ZkError::Malformed(_))
    ));
    // Weights/commitment count mismatch.
    let mut bad = base.clone();
    bad.input_commitments.pop();
    bad.nonce = 12;
    assert!(matches!(
        SignedZkTask::sign(bad, &requester),
        Err(ZkError::Malformed(_))
    ));
    // Zero deadline and zero nonce.
    let mut bad = base.clone();
    bad.deadline_height = 0;
    bad.nonce = 13;
    assert!(matches!(
        SignedZkTask::sign(bad, &requester),
        Err(ZkError::Malformed(_))
    ));
    let mut bad = base.clone();
    bad.nonce = 0;
    assert!(matches!(
        SignedZkTask::sign(bad, &requester),
        Err(ZkError::Malformed(_))
    ));
    // Truncated wire.
    let encoded = base.encode();
    assert!(matches!(
        ZkTask::decode(&encoded[..encoded.len() - 4]),
        Err(ZkError::Malformed(_))
    ));
    // Receipt with the wrong bit shape is refused against the task's count.
    let signed9 = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        9,
    );
    let mut raw = receipt_for(&signed9, &provider, &package, HEIGHT, 7);
    raw.receipt.bit_proofs.pop();
    assert!(matches!(
        SignedZkReceipt::decode(&raw.receipt.encode(), package.input_commitments.len()),
        Err(ZkError::Malformed(_))
    ));
}

#[test]
fn wire_roundtrips() {
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let signed = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    );
    assert_eq!(ZkTask::decode(&signed.task.encode()).unwrap(), signed.task);
    assert_eq!(
        SignedZkTask::decode(&signed.encode()).unwrap().task,
        signed.task
    );
    let receipt = receipt_for(&signed, &provider, &package, HEIGHT, 1);
    let back = ZkReceipt::decode(&receipt.receipt.encode()).unwrap();
    assert_eq!(back, receipt.receipt);
    let re_signed =
        SignedZkReceipt::decode(&receipt.encode(), package.input_commitments.len()).unwrap();
    assert_eq!(re_signed.receipt, receipt.receipt);
}

/// Release-mode timing probe (ignored in normal runs). Prints prove and
/// verify latency for the 4-input linear statement; numbers go to
/// `docs/benchmarks.md`.
#[test]
#[ignore]
fn bench_zk_prove_verify() {
    use std::time::Instant;
    let (weights, bias, inputs) = dims();
    let t0 = Instant::now();
    let package = prove_linear(&weights, bias, &inputs, &mut rng()).unwrap();
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let t0 = Instant::now();
    verify_linear(&weights, bias, &package).unwrap();
    let verify_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!("zk prove: {prove_ms:.1} ms; verify: {verify_ms:.1} ms");
}

#[test]
fn wire_mutations_never_panic() {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let requester = wallet(1);
    let provider = wallet(2);
    let (weights, bias, inputs) = dims();
    let package = prove_linear(&weights, bias, &inputs, &mut StdRng::seed_from_u64(99)).unwrap();
    let signed = task_for(
        &requester,
        &provider,
        &weights,
        bias,
        &package.input_commitments,
        1,
    );
    let receipt = receipt_for(&signed, &provider, &package, HEIGHT, 1);
    let corpora = vec![
        signed.task.encode(),
        signed.encode(),
        receipt.receipt.encode(),
        receipt.encode(),
    ];
    let mut rng = StdRng::seed_from_u64(0xbeef);
    for base in &corpora {
        for _ in 0..150 {
            let mut b = base.clone();
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
            let _ = ZkTask::decode(&b);
            let _ = SignedZkTask::decode(&b);
            let _ = ZkReceipt::decode(&b);
            let _ = SignedZkReceipt::decode(&b, package.input_commitments.len());
        }
    }
}

#[test]
fn threshold_gate_proves_a_lower_bound() {
    use srct_zkml::{prove_threshold, verify_threshold, ThresholdProof};
    // 1000 >= 500 proves and verifies, including the boundary.
    let proof = prove_threshold(1000, 500, &mut rng()).unwrap();
    verify_threshold(&proof).unwrap();
    let edge = prove_threshold(500, 500, &mut StdRng::seed_from_u64(7)).unwrap();
    verify_threshold(&edge).unwrap();
    // Full-range bound proves too.
    verify_threshold(&prove_threshold(65535, 0, &mut rng()).unwrap()).unwrap();
    // A false statement is refused at prove time — there is no proof of a lie.
    assert_eq!(
        prove_threshold(499, 500, &mut rng()),
        Err(ZkError::InvalidProof)
    );
    // Wire round-trip preserves the assertion.
    assert_eq!(ThresholdProof::decode(&proof.encode()).unwrap(), proof);
    // A retargeted threshold breaks the statement binding.
    let mut bad = proof.clone();
    bad.threshold = 501;
    assert_eq!(verify_threshold(&bad), Err(ZkError::InvalidProof));
    // Tampered and truncated bytes fail closed.
    let mut bytes = proof.encode();
    bytes[10] ^= 0x01;
    assert!(ThresholdProof::decode(&bytes).is_err());
    assert!(ThresholdProof::decode(&bytes[..bytes.len() - 4]).is_err());
}

#[test]
fn folding_verifies_a_batch_of_identical_statements() {
    use srct_zkml::{fold_summary, verify_fold};
    let (weights, bias, inputs) = dims();
    // Three independent proofs of the SAME statement.
    let packages: Vec<_> = (0..3)
        .map(|i| {
            prove_linear(
                &weights,
                bias,
                &inputs,
                &mut StdRng::seed_from_u64(0x100 + i),
            )
            .unwrap()
        })
        .collect();
    let mut rng = StdRng::seed_from_u64(0xabcd);
    verify_fold(&weights, bias, &packages, &mut rng).unwrap();
    // The summary pins the batch.
    let summary = fold_summary(&weights, bias, &packages, &mut rng).unwrap();
    assert_eq!(summary.proofs, 3);
    assert!(summary.transcript != [0u8; 32]);
    // A different batch gives a different summary.
    let other: Vec<_> = (0..2)
        .map(|i| {
            prove_linear(
                &weights,
                bias,
                &inputs,
                &mut StdRng::seed_from_u64(0x200 + i),
            )
            .unwrap()
        })
        .collect();
    let other_summary = fold_summary(&weights, bias, &other, &mut rng).unwrap();
    assert_ne!(summary.transcript, other_summary.transcript);
}

#[test]
fn folding_catches_a_cheating_proof() {
    use srct_zkml::verify_fold;
    let (weights, bias, inputs) = dims();
    let mut packages: Vec<_> = (0..3)
        .map(|i| {
            prove_linear(
                &weights,
                bias,
                &inputs,
                &mut StdRng::seed_from_u64(0x300 + i),
            )
            .unwrap()
        })
        .collect();
    // Break one output commitment: the folded check must fail.
    packages[1].output_commitment[0] ^= 0x01;
    let mut rng = StdRng::seed_from_u64(0x1111);
    assert!(verify_fold(&weights, bias, &packages, &mut rng).is_err());
}

#[test]
fn folding_refuses_mismatched_statements() {
    use srct_zkml::verify_fold;
    let (weights, bias, inputs) = dims();
    let a = prove_linear(&weights, bias, &inputs, &mut StdRng::seed_from_u64(0x400)).unwrap();
    let mut other_weights = weights.clone();
    other_weights[0] = 4;
    let b = prove_linear(
        &other_weights,
        bias,
        &inputs,
        &mut StdRng::seed_from_u64(0x401),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x2222);
    // Different statements must not fold together.
    assert!(verify_fold(&weights, bias, &[a.clone(), b], &mut rng).is_err());
    // An empty batch is refused.
    assert!(verify_fold(&weights, bias, &[], &mut rng).is_err());
}
