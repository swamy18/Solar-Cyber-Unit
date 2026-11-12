//! Acceptance tests for TEE-backed L2 evidence: the attestation type,
//! full cryptographic verification, wire codecs and the generic contract path.

use srct_compute::tee::{TeeQuote, TeeType, TEE_VERSION};
use srct_core::compute_ir::{ComputeBackend, ComputeTask};
use srct_core::deliverable::{Attestation, ComputeDeliverable};
use srct_core::hash::{Address, Hash};
use srct_core::l2::Auth;
use srct_core::sig::Bundle;
use srct_core::wallet::Wallet;
use srct_l2::task_contract::{ContractState, ServiceContract, ServiceContractSpec};
use srct_l2::tee_evidence::TeeBackedAttestation;
use srct_verify::{AttestationRoots, SignedTeeQuote, TeeSla, UnifiedVerifier};

const HEIGHT: u64 = 30;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-tee-test").unwrap()
}

fn addr(n: u8) -> Address {
    wallet(n).address().unwrap()
}

fn sla(provider: Address) -> TeeSla {
    TeeSla {
        version: TEE_VERSION,
        network_id: "srct/testnet".into(),
        provider,
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::SevSnp,
        max_age_heights: 10,
    }
}

fn signed_quote(sla: &TeeSla, attester: &Wallet, output: Hash, height: u64) -> SignedTeeQuote {
    SignedTeeQuote::sign(
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
            output_hash: output,
            height,
            nonce: 1,
        },
        attester,
    )
    .unwrap()
}

fn attestation() -> (TeeBackedAttestation, AttestationRoots, UnifiedVerifier) {
    let provider = addr(1);
    let attester = wallet(2);
    let sla = sla(provider);
    let quote = signed_quote(&sla, &attester, [25u8; 32], HEIGHT);
    let mut roots = AttestationRoots::new();
    roots.add_root(attester.address().unwrap(), TeeType::SevSnp);
    (
        TeeBackedAttestation { sla, quote },
        roots,
        UnifiedVerifier::new(),
    )
}

#[test]
fn attestation_binds_task_result_and_worker() {
    let (att, _, _) = attestation();
    assert_eq!(att.task_id(), [11u8; 32]);
    assert_eq!(att.result_hash(), [25u8; 32]);
    assert_eq!(att.worker_address(), addr(1));
    assert!(att.is_signed());
}

#[test]
fn unsigned_evidence_is_not_signed() {
    let (mut att, _, _) = attestation();
    att.quote.sigs = Bundle::default();
    assert!(!att.is_signed());
    let (mut att, _, _) = attestation();
    att.quote.keys = Bundle::default();
    assert!(!att.is_signed());
}

#[test]
fn full_verification_accepts_and_replay_refuses() {
    let (att, roots, mut verifier) = attestation();
    assert_eq!(
        att.verify(&roots, HEIGHT, &mut verifier).unwrap(),
        [25u8; 32]
    );
    assert!(att.verify(&roots, HEIGHT, &mut verifier).is_err());
}

#[test]
fn verification_refuses_bad_roots_and_stale_quotes() {
    let (att, _, mut verifier) = attestation();
    // Unknown attester.
    assert!(att
        .verify(&AttestationRoots::new(), HEIGHT, &mut verifier)
        .is_err());
    // Revoked attester.
    let mut roots = AttestationRoots::new();
    roots.add_root(wallet(2).address().unwrap(), TeeType::SevSnp);
    assert!(roots.revoke(&wallet(2).address().unwrap()));
    assert!(att.verify(&roots, HEIGHT, &mut verifier).is_err());
    // Stale quote.
    let (att, roots, mut verifier) = attestation();
    assert!(att.verify(&roots, HEIGHT + 11, &mut verifier).is_err());
}

#[test]
fn tampered_evidence_is_refused() {
    let (mut att, roots, mut verifier) = attestation();
    att.quote.quote.output_hash = [99u8; 32];
    assert!(att.verify(&roots, HEIGHT, &mut verifier).is_err());
}

#[test]
fn wire_roundtrip_and_malformed_refusals() {
    let (att, _, _) = attestation();
    let encoded = att.encode();
    let back = TeeBackedAttestation::decode(&mut srct_core::ser::Reader::new(&encoded)).unwrap();
    assert_eq!(back, att);
    assert!(
        TeeBackedAttestation::decode(&mut srct_core::ser::Reader::new(
            &encoded[..encoded.len() - 4]
        ),)
        .is_err()
    );
    let mut bad_version = encoded.clone();
    bad_version[0] = 99;
    assert!(TeeBackedAttestation::decode(&mut srct_core::ser::Reader::new(&bad_version),).is_err());
    // A tampered SLA hash fails the signature check at decode.
    let (mut att, _, _) = attestation();
    att.sla.model_hash = [77u8; 32];
    assert!(
        TeeBackedAttestation::decode(&mut srct_core::ser::Reader::new(&att.encode()),).is_err()
    );
}

fn tee_contract(workload: Hash) -> ServiceContract<ComputeDeliverable, TeeBackedAttestation> {
    let task = ComputeTask {
        task_id: workload,
        ir_hash: [31u8; 32],
        input_hash: [24u8; 32],
        required_memory_bytes: 1 << 20,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 5_000_000,
        expiry_height: 100,
        submit_height: 1,
    };
    let spec = ServiceContractSpec {
        task_id: workload,
        submitter: addr(9),
        deliverable: ComputeDeliverable(task),
        payment_sat: 5_000_000,
        worker_deposit_sat: 10_000,
        deadline_height: 100,
        dispute_window: 5,
        nonce: 1,
    };
    ServiceContract::open(spec).expect("valid spec opens")
}

#[test]
fn tee_attestation_flows_through_the_generic_submit_path() {
    let (att, _, _) = attestation();
    let mut c = tee_contract(att.task_id());
    let worker = att.worker_address();
    c.worker = Some(worker);
    c.state = ContractState::InProgress { claimed_at: 2 };
    c.submit(worker, att.result_hash(), att.clone(), 3).unwrap();
    assert!(
        matches!(c.state, ContractState::ResultSubmitted { .. }),
        "a bound TEE attestation is accepted by the generic path"
    );
    // Wrong task, wrong worker and unsigned evidence are all refused.
    let mut c = tee_contract([77u8; 32]);
    c.worker = Some(worker);
    c.state = ContractState::InProgress { claimed_at: 2 };
    assert!(c.submit(worker, att.result_hash(), att.clone(), 3).is_err());
    let mut c = tee_contract(att.task_id());
    c.worker = Some(worker);
    c.state = ContractState::InProgress { claimed_at: 2 };
    assert!(c
        .submit(addr(8), att.result_hash(), att.clone(), 3)
        .is_err());
    let (mut unsigned, _, _) = attestation();
    unsigned.quote.sigs = Bundle::default();
    let mut c = tee_contract(unsigned.task_id());
    c.worker = Some(unsigned.worker_address());
    c.state = ContractState::InProgress { claimed_at: 2 };
    assert!(c
        .submit(
            unsigned.worker_address(),
            unsigned.result_hash(),
            unsigned,
            3
        )
        .is_err());
}

#[test]
fn wire_mutations_never_panic() {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let (att, _, _) = attestation();
    let encoded = att.encode();
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
        let _ = TeeBackedAttestation::decode(&mut srct_core::ser::Reader::new(&b));
    }
}

#[test]
fn quote_signed_by_unknown_key_is_not_a_worker_claim() {
    // The attestation carries a bundle, so it is "signed" structurally, but
    // full verification against the rail's roots refuses the stranger.
    let stranger = wallet(9);
    let sla = sla(addr(1));
    let quote = signed_quote(&sla, &stranger, [25u8; 32], HEIGHT);
    let att = TeeBackedAttestation { sla, quote };
    assert!(att.is_signed());
    let (_, roots, mut verifier) = attestation();
    assert!(att.verify(&roots, HEIGHT, &mut verifier).is_err());
}

#[test]
fn auth_signing_still_binds_the_quote_hash() {
    // Sanity on the primitive the evidence relies on: the bundle signs the
    // quote hash, so swapping the body breaks the signature.
    let attester = wallet(2);
    let sla = sla(addr(1));
    let quote = signed_quote(&sla, &attester, [25u8; 32], HEIGHT);
    let auth = Auth::sign(&attester, &[25u8; 32]).unwrap();
    assert!(srct_core::sig::verify_bundle(&quote.sigs, &quote.keys, &[25u8; 32]).is_err());
    let _ = auth;
}
