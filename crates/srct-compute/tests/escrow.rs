//! Acceptance tests for job escrow: fund once, release per settled receipt,
//! refund the remainder after the deadline, and fail closed on every overrun.

use srct_compute::market::{
    plan_assignments, ComputeJob, ComputeOffer, Verification, JOB_VERSION, OFFER_VERSION,
};
use srct_compute::{
    ComputeError, ComputeReceipt, Determinism, DeviceClass, DeviceProfile, EscrowBook,
    EscrowFunding, SignedAssignment, SignedFunding, SignedJob, SignedOffer, SignedPlan,
    SignedReceipt, ESCROW_VERSION,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const SERVICE: &str = "train.mlp";
const KERNEL: Hash = [7u8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "escrow-test").unwrap()
}

fn mk_offer(provider: &Wallet, nonce: u64, price: u64, max_units: u32) -> SignedOffer {
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
            unit_price_sat: price,
            min_units: 1,
            max_units_per_job: max_units,
            privacy: false,
            verification: Verification::Receipt,
            available_from: 0,
            available_until: 1_000,
            nonce,
        },
        provider,
    )
    .unwrap()
}

fn mk_job(
    requester: &Wallet,
    units: u32,
    max_total_sat: u64,
    deadline: u64,
    nonce: u64,
) -> SignedJob {
    SignedJob::sign(
        ComputeJob {
            version: JOB_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            service: SERVICE.into(),
            units,
            max_unit_price_sat: 20,
            max_total_sat,
            class_mask: DeviceClass::Gpu.mask(),
            min_ram_mib: 512,
            determinism: Determinism::Reproducible,
            required_kernel: KERNEL,
            min_verification: Verification::Receipt,
            sealed_input: false,
            input: [3u8; 32],
            deadline,
            nonce,
        },
        requester,
    )
    .unwrap()
}

fn signed_plan(job: &SignedJob, offers: &[SignedOffer], requester: &Wallet) -> SignedPlan {
    plan_assignments(job, offers, 10, 1)
        .unwrap()
        .sign(requester)
        .unwrap()
}

fn funding(
    requester: &Wallet,
    job: Hash,
    amount_sat: u64,
    deadline: u64,
    nonce: u64,
) -> SignedFunding {
    SignedFunding::sign(
        EscrowFunding {
            version: ESCROW_VERSION,
            network_id: NET.into(),
            job,
            requester: requester.address().unwrap(),
            amount_sat,
            deadline,
            nonce,
        },
        requester,
    )
    .unwrap()
}

fn receipt(
    assignment: &SignedAssignment,
    provider: &Wallet,
    units_done: u32,
    height: u64,
    nonce: u64,
) -> SignedReceipt {
    let receipt =
        ComputeReceipt::new(assignment, units_done, [4u8; 32], 1_000, height, nonce).unwrap();
    SignedReceipt::sign(receipt, provider).unwrap()
}

#[test]
fn fund_release_and_refund_the_remainder() {
    let requester = wallet(1);
    let provider = wallet(2);
    let job = mk_job(&requester, 5, 100, 100, 1);
    let plan = signed_plan(&job, &[mk_offer(&provider, 1, 7, 20)], &requester);
    let assignment = &plan.assignments[0];
    assert_eq!(assignment.assignment.total_sat, 35);

    let mut book = EscrowBook::new(NET);
    assert_eq!(
        book.fund(&funding(&requester, job.hash(), 100, 100, 1), 10),
        Ok(100)
    );
    assert_eq!(book.remaining_sat(&job.hash()), 100);

    let payout = book
        .release(&receipt(assignment, &provider, 5, 20, 1), assignment, 20)
        .unwrap();
    assert_eq!(payout.from, requester.address().unwrap());
    assert_eq!(payout.to, provider.address().unwrap());
    assert_eq!(payout.amount_sat, 35);
    assert_eq!(book.remaining_sat(&job.hash()), 65);

    let refund = book.refund(&job.hash(), 101).unwrap();
    assert_eq!(refund.to, requester.address().unwrap());
    assert_eq!(refund.amount_sat, 65);
    assert_eq!(book.remaining_sat(&job.hash()), 0);
    assert!(book.account(&job.hash()).unwrap().refunded);

    // A closed pot cannot be reopened or refunded twice.
    assert_eq!(
        book.release(&receipt(assignment, &provider, 5, 20, 2), assignment, 20),
        Err(ComputeError::AlreadyRefunded)
    );
    assert_eq!(
        book.refund(&job.hash(), 102),
        Err(ComputeError::AlreadyRefunded)
    );
}

#[test]
fn releases_can_never_exceed_the_funded_pot() {
    let requester = wallet(10);
    let a = wallet(11);
    let b = wallet(12);
    let job = mk_job(&requester, 10, 200, 100, 1);
    let offers = [mk_offer(&a, 1, 7, 5), mk_offer(&b, 2, 7, 5)];
    let plan = signed_plan(&job, &offers, &requester);
    assert_eq!(plan.assignments.len(), 2);
    let first = &plan.assignments[0];
    let second = &plan.assignments[1];
    let first_wallet = if first.assignment.provider == a.address().unwrap() {
        &a
    } else {
        &b
    };
    let second_wallet = if second.assignment.provider == a.address().unwrap() {
        &a
    } else {
        &b
    };
    assert_eq!(first.assignment.total_sat, 35);
    assert_eq!(second.assignment.total_sat, 35);

    // 60 sat cannot cover two 35 sat shards.
    let mut book = EscrowBook::new(NET);
    book.fund(&funding(&requester, job.hash(), 60, 100, 1), 10)
        .unwrap();
    book.release(&receipt(first, first_wallet, 5, 20, 1), first, 20)
        .unwrap();
    assert_eq!(
        book.release(&receipt(second, second_wallet, 5, 20, 1), second, 20),
        Err(ComputeError::BudgetExceeded)
    );
    // The refused release did not consume the assignment or the pot.
    assert_eq!(book.remaining_sat(&job.hash()), 25);
    assert_eq!(
        book.release(&receipt(first, first_wallet, 5, 20, 2), first, 20),
        Err(ComputeError::AlreadySettled)
    );
}

#[test]
fn funding_is_signed_bounded_and_single_use() {
    let requester = wallet(20);
    let stranger = wallet(21);
    let job = mk_job(&requester, 5, 100, 100, 1);
    let mut book = EscrowBook::new(NET);

    // Wrong network.
    let mut foreign = funding(&requester, job.hash(), 100, 100, 1);
    foreign.funding.network_id = "srct/other".into();
    let foreign = SignedFunding::sign(foreign.funding, &requester).unwrap();
    assert_eq!(book.fund(&foreign, 10), Err(ComputeError::WrongNetwork));

    // Only the named requester can sign.
    let mut wrong = funding(&requester, job.hash(), 100, 100, 2);
    wrong.funding.requester = stranger.address().unwrap();
    assert_eq!(
        SignedFunding::sign(wrong.funding, &requester),
        Err(ComputeError::WrongRequester)
    );

    // Funding after the deadline is refused.
    assert_eq!(
        book.fund(&funding(&requester, job.hash(), 100, 100, 3), 101),
        Err(ComputeError::Expired)
    );

    // A job is funded exactly once.
    let good = funding(&requester, job.hash(), 100, 100, 4);
    assert_eq!(book.fund(&good, 10), Ok(100));
    assert_eq!(book.fund(&good, 10), Err(ComputeError::Replay));
    assert_eq!(
        book.fund(&funding(&requester, job.hash(), 50, 100, 5), 10),
        Err(ComputeError::Replay)
    );

    // Zero amounts and empty jobs are malformed.
    let mut zero = funding(&requester, job.hash(), 1, 100, 6);
    zero.funding.amount_sat = 0;
    assert!(matches!(
        SignedFunding::sign(zero.funding, &requester),
        Err(ComputeError::Malformed(_))
    ));
}

#[test]
fn release_refuses_unfunded_misbound_late_and_overclaiming_receipts() {
    let requester = wallet(30);
    let provider = wallet(31);
    let other = wallet(32);
    let job = mk_job(&requester, 5, 100, 100, 1);
    let plan = signed_plan(&job, &[mk_offer(&provider, 1, 7, 20)], &requester);
    let assignment = &plan.assignments[0];

    // Unfunded job.
    let mut book = EscrowBook::new(NET);
    assert_eq!(
        book.release(&receipt(assignment, &provider, 5, 20, 1), assignment, 20),
        Err(ComputeError::NotFunded)
    );
    book.fund(&funding(&requester, job.hash(), 100, 100, 1), 10)
        .unwrap();

    // A receipt for another assignment does not bind this one.
    let other_job = mk_job(&requester, 5, 100, 100, 2);
    let other_plan = signed_plan(&other_job, &[mk_offer(&provider, 2, 7, 20)], &requester);
    let other_assignment = &other_plan.assignments[0];
    assert_eq!(
        book.release(
            &receipt(other_assignment, &provider, 5, 20, 1),
            assignment,
            20
        ),
        Err(ComputeError::BindingMismatch)
    );

    // A late receipt or a late release is refused.
    assert_eq!(
        book.release(&receipt(assignment, &provider, 5, 101, 1), assignment, 20),
        Err(ComputeError::Expired)
    );
    assert_eq!(
        book.release(&receipt(assignment, &provider, 5, 20, 1), assignment, 101),
        Err(ComputeError::Expired)
    );

    // Overclaim: more units than the assignment granted.
    let mut over = ComputeReceipt::new(assignment, 5, [4u8; 32], 1_000, 20, 1).unwrap();
    over.units_done = 6;
    over.total_sat = 6 * over.unit_price_sat;
    let over = SignedReceipt::sign(over, &provider).unwrap();
    assert_eq!(
        book.release(&over, assignment, 20),
        Err(ComputeError::Overclaim)
    );

    // Price mismatch: the receipt cannot reprice the assignment.
    let mut price = ComputeReceipt::new(assignment, 5, [4u8; 32], 1_000, 20, 1).unwrap();
    price.unit_price_sat = 8;
    price.total_sat = 5 * 8;
    let price = SignedReceipt::sign(price, &provider).unwrap();
    assert_eq!(
        book.release(&price, assignment, 20),
        Err(ComputeError::PriceMismatch)
    );

    // A signed assignment naming the funded job but another requester does
    // not bind the pot.
    let mut foreign = assignment.assignment.clone();
    foreign.requester = other.address().unwrap();
    let foreign = SignedAssignment::sign(foreign, &other).unwrap();
    assert_eq!(
        book.release(&receipt(&foreign, &provider, 5, 20, 1), &foreign, 20),
        Err(ComputeError::BindingMismatch)
    );
}

#[test]
fn refund_is_after_the_deadline_and_exactly_once() {
    let requester = wallet(40);
    let provider = wallet(41);
    let job = mk_job(&requester, 5, 100, 100, 1);
    let plan = signed_plan(&job, &[mk_offer(&provider, 1, 7, 20)], &requester);
    let assignment = &plan.assignments[0];

    let mut book = EscrowBook::new(NET);
    assert_eq!(book.refund(&job.hash(), 101), Err(ComputeError::NotFunded));
    book.fund(&funding(&requester, job.hash(), 100, 100, 1), 10)
        .unwrap();
    assert_eq!(book.refund(&job.hash(), 100), Err(ComputeError::NotExpired));
    assert_eq!(book.refund(&job.hash(), 50), Err(ComputeError::NotExpired));

    // A fully released pot refunds zero and still closes.
    book.release(&receipt(assignment, &provider, 5, 20, 1), assignment, 20)
        .unwrap();
    let refund = book.refund(&job.hash(), 101).unwrap();
    assert_eq!(refund.amount_sat, 65);
    assert_eq!(
        book.refund(&job.hash(), 102),
        Err(ComputeError::AlreadyRefunded)
    );
}

#[test]
fn a_two_shard_job_releases_each_receipt_and_refunds_the_rest() {
    let requester = wallet(50);
    let a = wallet(51);
    let b = wallet(52);
    let job = mk_job(&requester, 10, 200, 100, 1);
    let offers = [mk_offer(&a, 1, 7, 5), mk_offer(&b, 2, 7, 5)];
    let plan = signed_plan(&job, &offers, &requester);
    let mut book = EscrowBook::new(NET);
    book.fund(&funding(&requester, job.hash(), 100, 100, 1), 10)
        .unwrap();

    let mut paid = 0;
    for assignment in &plan.assignments {
        let provider = if assignment.assignment.provider == a.address().unwrap() {
            &a
        } else {
            &b
        };
        let payout = book
            .release(&receipt(assignment, provider, 5, 20, 1), assignment, 20)
            .unwrap();
        assert_eq!(payout.amount_sat, 35);
        paid += payout.amount_sat;
    }
    assert_eq!(paid, 70);
    assert_eq!(book.remaining_sat(&job.hash()), 30);
    assert_eq!(book.refund(&job.hash(), 101).unwrap().amount_sat, 30);
}

#[test]
fn funding_wire_roundtrip_and_tamper_refusal() {
    let requester = wallet(60);
    let job = mk_job(&requester, 5, 100, 100, 1);
    let signed = funding(&requester, job.hash(), 100, 100, 1);
    let bytes = signed.encode();
    let decoded = SignedFunding::decode(&bytes).unwrap();
    assert_eq!(decoded, signed);

    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(SignedFunding::decode(&tampered).is_err());
    assert!(SignedFunding::decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(SignedFunding::decode(&[]).is_err());
}
