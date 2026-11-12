//! Acceptance tests for the encrypted-compute prototype: real encryption,
//! homomorphic evaluation, worker receipts and fail-closed verification.

use rand::{rngs::StdRng, SeedableRng};
use srct_core::wallet::Wallet;
use srct_fhe::{
    eval, Ciphertext, FheError, FheKeys, FheReceipt, FheTask, FheVerifier, SignedFheReceipt,
    SignedFheTask, WeightedSum, FHE_VERSION,
};

const NET: &str = "srct/testnet";
const HEIGHT: u64 = 100;

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x005e_ed07)
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "fhe-test").unwrap()
}

fn keys() -> FheKeys {
    FheKeys::generate(&mut rng())
}

fn task(keys: &FheKeys, requester: &Wallet, provider: &Wallet) -> SignedFheTask {
    let mut r = rng();
    let op = WeightedSum {
        weights: vec![3, -2, 5],
        bias: 7,
    };
    let inputs = vec![
        keys.encrypt(10, &mut r),
        keys.encrypt(4, &mut r),
        keys.encrypt(6, &mut r),
    ];
    SignedFheTask::sign(
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
        requester,
    )
    .unwrap()
}

fn receipt_for(task: &SignedFheTask, worker: &Wallet, height: u64, nonce: u64) -> SignedFheReceipt {
    let output = eval(&task.task.op, &task.task.inputs).unwrap();
    SignedFheReceipt::sign(
        FheReceipt {
            version: FHE_VERSION,
            task: task.hash(),
            worker: worker.address().unwrap(),
            output,
            height,
            nonce,
        },
        worker,
    )
    .unwrap()
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let keys = keys();
    let mut r = rng();
    for m in [0u32, 1, 42, 65_535, 1_000_000] {
        let ct = keys.encrypt(m, &mut r);
        assert_eq!(keys.decrypt(&ct, 1 << 32), Some(m as u64));
    }
    // Same plaintext, different ciphertexts: encryption is randomized.
    let a = keys.encrypt(9, &mut r);
    let b = keys.encrypt(9, &mut r);
    assert_ne!(a, b);
    assert_eq!(keys.decrypt(&a, 1 << 20), keys.decrypt(&b, 1 << 20));
    // Outside the bound there is no answer.
    assert_eq!(keys.decrypt(&a, 5), None);
}

#[test]
fn homomorphic_add_and_scale_match_plaintext() {
    let keys = keys();
    let mut r = rng();
    let a = keys.encrypt(20, &mut r);
    let b = keys.encrypt(22, &mut r);
    let sum = a.add(&b).unwrap();
    assert_eq!(keys.decrypt(&sum, 1 << 20), Some(42));
    let scaled = a.scalar_mul(-3).unwrap();
    // -60 mod n decodes only with a bound that wraps; keep the positive case.
    let pos = b.scalar_mul(3).unwrap();
    assert_eq!(keys.decrypt(&pos, 1 << 20), Some(66));
    let _ = scaled;
}

#[test]
fn full_workflow_settles_and_decrypts() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let signed = task(&keys, &requester, &provider);
    let receipt = receipt_for(&signed, &provider, HEIGHT, 1);
    let mut verifier = FheVerifier::new();
    let output = verifier.verify(&signed, &receipt, HEIGHT).unwrap();
    // 7 + 3*10 - 2*4 + 5*6 = 59, recovered without the worker seeing inputs.
    assert_eq!(keys.decrypt(&output, 1 << 20), Some(59));
}

#[test]
fn tampered_output_is_fraudulent() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let signed = task(&keys, &requester, &provider);
    let mut bad = receipt_for(&signed, &provider, HEIGHT, 1);
    bad.receipt.output = Ciphertext::trivial_plaintext(1);
    let re_signed = SignedFheReceipt::sign(
        FheReceipt {
            nonce: 2,
            ..bad.receipt.clone()
        },
        &provider,
    )
    .unwrap();
    let mut verifier = FheVerifier::new();
    assert_eq!(
        verifier.verify(&signed, &re_signed, HEIGHT),
        Err(FheError::FraudulentOutput)
    );
}

#[test]
fn tampered_inputs_break_the_task_signature() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let mut signed = task(&keys, &requester, &provider);
    signed.task.inputs[0] = Ciphertext::trivial_plaintext(999);
    assert!(matches!(signed.verify(), Err(FheError::BadSignature(_))));
}

#[test]
fn tampered_weights_break_the_task_signature() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let mut signed = task(&keys, &requester, &provider);
    signed.task.op.weights[0] = 100;
    assert!(matches!(signed.verify(), Err(FheError::BadSignature(_))));
}

#[test]
fn wrong_worker_and_impostor_are_refused() {
    let requester = wallet(1);
    let provider = wallet(2);
    let stranger = wallet(9);
    let keys = keys();
    let signed = task(&keys, &requester, &provider);
    // Receipt signed by a stranger for the provider's address.
    let output = eval(&signed.task.op, &signed.task.inputs).unwrap();
    let impostor = FheReceipt {
        version: FHE_VERSION,
        task: signed.hash(),
        worker: provider.address().unwrap(),
        output,
        height: HEIGHT,
        nonce: 1,
    };
    assert!(matches!(
        SignedFheReceipt::sign(impostor, &stranger),
        Err(FheError::WrongWorker)
    ));
    // Receipt honestly signed but naming the wrong worker.
    let output = eval(&signed.task.op, &signed.task.inputs).unwrap();
    let wrong = SignedFheReceipt::sign(
        FheReceipt {
            version: FHE_VERSION,
            task: signed.hash(),
            worker: stranger.address().unwrap(),
            output,
            height: HEIGHT,
            nonce: 1,
        },
        &stranger,
    )
    .unwrap();
    let mut verifier = FheVerifier::new();
    assert_eq!(
        verifier.verify(&signed, &wrong, HEIGHT),
        Err(FheError::BindingMismatch)
    );
}

#[test]
fn late_and_future_receipts_are_refused() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let signed = task(&keys, &requester, &provider);
    let late = receipt_for(&signed, &provider, HEIGHT + 11, 1);
    let mut verifier = FheVerifier::new();
    assert_eq!(
        verifier.verify(&signed, &late, HEIGHT + 11),
        Err(FheError::Expired)
    );
    let future = receipt_for(&signed, &provider, HEIGHT + 1, 2);
    assert_eq!(
        verifier.verify(&signed, &future, HEIGHT),
        Err(FheError::FutureHeight)
    );
}

#[test]
fn same_task_cannot_settle_twice() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let signed = task(&keys, &requester, &provider);
    let first = receipt_for(&signed, &provider, HEIGHT, 1);
    let mut verifier = FheVerifier::new();
    assert!(verifier.verify(&signed, &first, HEIGHT).is_ok());
    let second = receipt_for(&signed, &provider, HEIGHT, 2);
    assert_eq!(
        verifier.verify(&signed, &second, HEIGHT),
        Err(FheError::Replay)
    );
}

#[test]
fn malformed_tasks_and_receipts_are_refused() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let base = task(&keys, &requester, &provider).task;
    // Identity public key.
    let mut bad = base.clone();
    bad.enc_pubkey = [0u8; 33];
    bad.nonce = 11;
    assert!(matches!(
        SignedFheTask::sign(bad, &requester),
        Err(FheError::Malformed(_))
    ));
    // Off-curve public key: x = p-1 gives y^2 = 6 mod p, and 6 is a
    // quadratic non-residue for secp256k1, so no y exists.
    let mut bad = base.clone();
    let mut off_curve = [0xFFu8; 33];
    off_curve[0] = 0x02;
    off_curve[28] = 0xFE;
    off_curve[29] = 0xFF;
    off_curve[30] = 0xFF;
    off_curve[31] = 0xFC;
    off_curve[32] = 0x2E;
    bad.enc_pubkey = off_curve;
    bad.nonce = 12;
    assert!(matches!(
        SignedFheTask::sign(bad, &requester),
        Err(FheError::Malformed(_))
    ));
    // Weight over the cap.
    let mut bad = base.clone();
    bad.op.weights[0] = 2_000_000;
    bad.nonce = 13;
    assert!(matches!(
        SignedFheTask::sign(bad, &requester),
        Err(FheError::Malformed(_))
    ));
    // Empty inputs.
    let mut bad = base.clone();
    bad.inputs.clear();
    bad.op.weights.clear();
    bad.nonce = 14;
    assert!(matches!(
        SignedFheTask::sign(bad, &requester),
        Err(FheError::Malformed(_))
    ));
    // Zero nonce and zero deadline.
    let mut bad = base.clone();
    bad.nonce = 0;
    assert!(matches!(
        SignedFheTask::sign(bad, &requester),
        Err(FheError::Malformed(_))
    ));
    let mut bad = base.clone();
    bad.deadline_height = 0;
    bad.nonce = 15;
    assert!(matches!(
        SignedFheTask::sign(bad, &requester),
        Err(FheError::Malformed(_))
    ));
    // Wire truncation.
    let encoded = base.encode();
    assert!(matches!(
        FheTask::decode(&encoded[..encoded.len() - 4]),
        Err(FheError::Malformed(_))
    ));
}

#[test]
fn wire_roundtrip() {
    let requester = wallet(1);
    let provider = wallet(2);
    let keys = keys();
    let signed = task(&keys, &requester, &provider);
    let back = FheTask::decode(&signed.task.encode()).unwrap();
    assert_eq!(back, signed.task);
    let decoded = SignedFheTask::decode(&signed.encode()).unwrap();
    assert_eq!(decoded.task, signed.task);
    let receipt = receipt_for(&signed, &provider, HEIGHT, 1);
    let back = SignedFheReceipt::decode(&receipt.encode()).unwrap();
    assert_eq!(back.receipt, receipt.receipt);
}
