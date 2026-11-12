//! Acceptance tests for challenge re-execution: independent re-runs,
//! result comparison, and the fraud-verdict-to-slash chain.

use srct_compute::market::{
    plan_assignments, ComputeJob, ComputeOffer, Verification, JOB_VERSION, OFFER_VERSION,
};
use srct_compute::{
    BondBook, Challenge, ChallengeBook, ChallengeVerdict, ComputeError, ComputeReceipt,
    Determinism, DeviceClass, DeviceProfile, DisputeReason, ProviderBond, SignedAssignment,
    SignedBond, SignedChallenge, SignedDispute, SignedJob, SignedOffer, SignedReceipt,
    BOND_VERSION,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const SERVICE: &str = "train.mlp";
const KERNEL: Hash = [7u8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "challenge-test").unwrap()
}

fn mk_offer(provider: &Wallet, nonce: u64) -> SignedOffer {
    let profile = DeviceProfile::new(
        DeviceClass::Gpu,
        Determinism::Reproducible,
        24_576,
        8,
        20,
        50_000,
        KERNEL,
    );
    SignedOffer::sign(
        ComputeOffer {
            version: OFFER_VERSION,
            network_id: NET.into(),
            provider: provider.address().unwrap(),
            service: SERVICE.into(),
            profile,
            unit_price_sat: 7,
            min_units: 1,
            max_units_per_job: 20,
            privacy: false,
            verification: Verification::Challenge,
            available_from: 0,
            available_until: 1_000,
            nonce,
        },
        provider,
    )
    .unwrap()
}

fn assignment_for(requester: &Wallet, provider: &Wallet, job_nonce: u64) -> SignedAssignment {
    let offer = mk_offer(provider, job_nonce);
    let job = SignedJob::sign(
        ComputeJob {
            version: JOB_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            service: SERVICE.into(),
            units: 5,
            max_unit_price_sat: 20,
            max_total_sat: 100,
            class_mask: DeviceClass::Gpu.mask(),
            min_ram_mib: 512,
            determinism: Determinism::Reproducible,
            required_kernel: KERNEL,
            min_verification: Verification::Challenge,
            sealed_input: false,
            input: [3u8; 32],
            deadline: 100,
            nonce: job_nonce,
        },
        requester,
    )
    .unwrap();
    let plan = plan_assignments(&job, &[offer], 10, 1).unwrap();
    plan.sign(requester).unwrap().assignments.remove(0)
}

fn receipt_for(assignment: &SignedAssignment, worker: &Wallet, output: Hash) -> SignedReceipt {
    // The receipt names its signer as the worker: for a re-execution this is
    // the challenger, not the original provider. Such receipts are comparison
    // material only — the ledger refuses to settle them against the already
    // settled original assignment.
    let mut receipt = ComputeReceipt::new(assignment, 5, output, 1_000, 20, 1).unwrap();
    receipt.provider = worker.address().unwrap();
    SignedReceipt::sign(receipt, worker).unwrap()
}

fn challenge_for(
    requester: &Wallet,
    provider: &Wallet,
    challenger: &Wallet,
    assignment: &SignedAssignment,
    nonce: u64,
) -> SignedChallenge {
    SignedChallenge::sign(
        Challenge {
            version: srct_compute::challenge::CHALLENGE_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            provider: provider.address().unwrap(),
            challenger: challenger.address().unwrap(),
            assignment: assignment.hash(),
            deadline_height: 90,
            nonce,
        },
        requester,
    )
    .unwrap()
}

fn bonded_book(provider: &Wallet, amount: u64) -> BondBook {
    let mut book = BondBook::new(NET);
    let bond = SignedBond::sign(
        ProviderBond {
            version: BOND_VERSION,
            network_id: NET.into(),
            provider: provider.address().unwrap(),
            amount_sat: amount,
            registered_height: 5,
            nonce: 1,
        },
        provider,
    )
    .unwrap();
    book.register(&bond, 10).unwrap();
    book
}

#[test]
fn matching_re_execution_clears_the_receipt() {
    let requester = wallet(1);
    let provider = wallet(2);
    let challenger = wallet(3);
    let assignment = assignment_for(&requester, &provider, 1);
    let first = receipt_for(&assignment, &provider, [4u8; 32]);
    let mut book = ChallengeBook::new(NET);
    let challenge = challenge_for(&requester, &provider, &challenger, &assignment, 1);
    book.open(&challenge, &assignment, 10).unwrap();
    let second = receipt_for(&assignment, &challenger, [4u8; 32]);
    book.submit_second(&second, 20).unwrap();
    assert_eq!(
        book.verdict(&assignment.hash(), &first),
        Ok(ChallengeVerdict::Match {
            assignment: assignment.hash()
        })
    );
    assert!(book
        .verdict(&assignment.hash(), &first)
        .unwrap()
        .fraud_dispute(NET, 2)
        .is_none());
}

#[test]
fn mismatched_re_execution_slashes_the_bond() {
    let requester = wallet(10);
    let provider = wallet(11);
    let challenger = wallet(12);
    let assignment = assignment_for(&requester, &provider, 1);
    let first = receipt_for(&assignment, &provider, [4u8; 32]);
    let mut book = ChallengeBook::new(NET);
    book.open(
        &challenge_for(&requester, &provider, &challenger, &assignment, 1),
        &assignment,
        10,
    )
    .unwrap();
    let second = receipt_for(&assignment, &challenger, [5u8; 32]);
    book.submit_second(&second, 20).unwrap();
    let verdict = book.verdict(&assignment.hash(), &first).unwrap();
    let dispute = verdict
        .fraud_dispute(NET, 2)
        .expect("mismatch justifies a dispute");
    assert_eq!(dispute.reason, DisputeReason::WrongResult);
    assert_eq!(dispute.evidence, [5u8; 32]);
    // The existing slash path takes the fraud penalty and bans.
    let mut bonds = bonded_book(&provider, 100_000);
    let signed = SignedDispute::sign(dispute, &requester).unwrap();
    assert_eq!(bonds.slash(&signed, &assignment, 30), Ok(50_000));
    assert_eq!(bonds.score(&provider.address().unwrap()), -100);
}

#[test]
fn self_challenge_and_stranger_challenges_are_refused() {
    let requester = wallet(20);
    let provider = wallet(21);
    let assignment = assignment_for(&requester, &provider, 1);
    // Challenger must be independent of the provider.
    let bad = Challenge {
        version: srct_compute::challenge::CHALLENGE_VERSION,
        network_id: NET.into(),
        requester: requester.address().unwrap(),
        provider: provider.address().unwrap(),
        challenger: provider.address().unwrap(),
        assignment: assignment.hash(),
        deadline_height: 90,
        nonce: 1,
    };
    assert!(matches!(
        SignedChallenge::sign(bad, &requester),
        Err(ComputeError::Malformed(_))
    ));
    // Only the assignment's requester can challenge.
    let stranger = wallet(22);
    let challenger = wallet(23);
    let good = challenge_for(&requester, &provider, &challenger, &assignment, 1);
    assert_eq!(
        SignedChallenge::sign(good.challenge, &stranger),
        Err(ComputeError::WrongRequester)
    );
    // A challenge naming another requester does not bind this assignment.
    let mut foreign = challenge_for(&requester, &provider, &challenger, &assignment, 2);
    foreign.challenge.requester = stranger.address().unwrap();
    let foreign = SignedChallenge::sign(foreign.challenge, &stranger).unwrap();
    let mut book = ChallengeBook::new(NET);
    assert_eq!(
        book.open(&foreign, &assignment, 10),
        Err(ComputeError::WrongRequester)
    );
    // A challenge naming another assignment does not bind this one.
    let other = assignment_for(&requester, &provider, 9);
    let mut book = ChallengeBook::new(NET);
    book.open(
        &challenge_for(&requester, &provider, &challenger, &assignment, 3),
        &other,
        10,
    )
    .unwrap_err();
}

#[test]
fn duplicate_challenges_and_receipts_are_replays() {
    let requester = wallet(30);
    let provider = wallet(31);
    let challenger = wallet(32);
    let assignment = assignment_for(&requester, &provider, 1);
    let mut book = ChallengeBook::new(NET);
    let challenge = challenge_for(&requester, &provider, &challenger, &assignment, 1);
    book.open(&challenge, &assignment, 10).unwrap();
    assert_eq!(
        book.open(&challenge, &assignment, 10),
        Err(ComputeError::Replay)
    );
    let other_nonce = challenge_for(&requester, &provider, &challenger, &assignment, 2);
    assert_eq!(
        book.open(&other_nonce, &assignment, 10),
        Err(ComputeError::Replay)
    );
    let second = receipt_for(&assignment, &challenger, [4u8; 32]);
    book.submit_second(&second, 20).unwrap();
    assert_eq!(book.submit_second(&second, 20), Err(ComputeError::Replay));
}

#[test]
fn wrong_worker_late_and_misbound_receipts_are_refused() {
    let requester = wallet(40);
    let provider = wallet(41);
    let challenger = wallet(42);
    let assignment = assignment_for(&requester, &provider, 1);
    let mut book = ChallengeBook::new(NET);
    book.open(
        &challenge_for(&requester, &provider, &challenger, &assignment, 1),
        &assignment,
        10,
    )
    .unwrap();
    // The provider cannot "re-execute" its own work as the challenger.
    let cover_up = receipt_for(&assignment, &provider, [9u8; 32]);
    assert_eq!(
        book.submit_second(&cover_up, 20),
        Err(ComputeError::WrongProvider)
    );
    // A receipt for another assignment binds nothing here.
    let mut other_job = receipt_for(&assignment, &challenger, [4u8; 32]);
    other_job.receipt.assignment = [0xBBu8; 32];
    let other_job = SignedReceipt::sign(other_job.receipt, &challenger).unwrap();
    assert_eq!(
        book.submit_second(&other_job, 20),
        Err(ComputeError::BindingMismatch)
    );
    // Past the deadline the challenge expires.
    let late = receipt_for(&assignment, &challenger, [4u8; 32]);
    assert_eq!(book.submit_second(&late, 91), Err(ComputeError::Expired));
}

#[test]
fn tampered_challenges_are_refused_and_verdict_needs_a_second_receipt() {
    let requester = wallet(50);
    let provider = wallet(51);
    let challenger = wallet(52);
    let assignment = assignment_for(&requester, &provider, 1);
    let first = receipt_for(&assignment, &provider, [4u8; 32]);
    let mut signed = challenge_for(&requester, &provider, &challenger, &assignment, 1);
    signed.challenge.deadline_height = 10;
    assert!(matches!(
        signed.verify(),
        Err(ComputeError::BadSignature(_))
    ));
    let mut book = ChallengeBook::new(NET);
    book.open(
        &challenge_for(&requester, &provider, &challenger, &assignment, 2),
        &assignment,
        10,
    )
    .unwrap();
    assert!(matches!(
        book.verdict(&assignment.hash(), &first),
        Err(ComputeError::Malformed(_))
    ));
}

#[test]
fn challenge_wire_roundtrip_and_truncation() {
    let requester = wallet(60);
    let provider = wallet(61);
    let challenger = wallet(62);
    let assignment = assignment_for(&requester, &provider, 1);
    let signed = challenge_for(&requester, &provider, &challenger, &assignment, 1);
    let back = SignedChallenge::decode(&signed.encode()).unwrap();
    assert_eq!(back, signed);
    assert_eq!(
        SignedChallenge::decode(&signed.encode()).unwrap().hash(),
        signed.hash()
    );
    let encoded = signed.encode();
    assert!(matches!(
        SignedChallenge::decode(&encoded[..encoded.len() - 4]),
        Err(ComputeError::Malformed(_))
    ));
    let mut bad_version = signed.encode();
    bad_version[0] = 99;
    assert!(matches!(
        SignedChallenge::decode(&bad_version),
        Err(ComputeError::Malformed(_))
    ));
}
