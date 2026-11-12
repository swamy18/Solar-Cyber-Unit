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
