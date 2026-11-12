//! End-to-end compute flow across every module: bonded offers -> plan ->
//! funding -> receipts -> settlement -> release -> challenge -> slash ->
//! refund -> journal replay.

use srct_compute::market::{
    plan_assignments, ComputeJob, ComputeOffer, Verification, JOB_VERSION, OFFER_VERSION,
};
use srct_compute::{
    BondBook, Challenge, ChallengeBook, ChallengeVerdict, ComputeLedger, ComputeReceipt,
    Determinism, DeviceClass, DeviceProfile, DisputeReason, EscrowBook, EscrowFunding, FlowJournal,
    ProviderBond, SignedBond, SignedChallenge, SignedDispute, SignedFunding, SignedJob,
    SignedOffer, SignedReceipt, BOND_VERSION, CHALLENGE_VERSION, ESCROW_VERSION,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const SERVICE: &str = "train.mlp";
const KERNEL: Hash = [7u8; 32];
const DEADLINE: u64 = 100;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "compute-e2e").unwrap()
}

fn offer(provider: &Wallet, nonce: u64, price: u64, max_units: u32) -> SignedOffer {
    SignedOffer::sign(
        ComputeOffer {
            version: OFFER_VERSION,
            network_id: NET.into(),
            provider: provider.address().unwrap(),
            service: SERVICE.into(),
            profile: DeviceProfile::new(
                DeviceClass::Gpu,
                Determinism::Reproducible,
                24_576,
                8,
                20,
                50_000,
                KERNEL,
            ),
            unit_price_sat: price,
            min_units: 1,
            max_units_per_job: max_units,
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

fn job(requester: &Wallet) -> SignedJob {
    SignedJob::sign(
        ComputeJob {
            version: JOB_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            service: SERVICE.into(),
            units: 10,
            max_unit_price_sat: 20,
            max_total_sat: 200,
            class_mask: DeviceClass::Gpu.mask(),
            min_ram_mib: 512,
            determinism: Determinism::Reproducible,
            required_kernel: KERNEL,
            min_verification: Verification::Challenge,
            sealed_input: false,
            input: [3u8; 32],
            deadline: DEADLINE,
            nonce: 1,
        },
        requester,
    )
    .unwrap()
}

fn bond(provider: &Wallet, amount: u64) -> SignedBond {
    SignedBond::sign(
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
    .unwrap()
}

#[test]
fn a_job_runs_from_funding_to_settlement_to_refund() {
    let requester = wallet(1);
    let worker = wallet(2);
    let challenger = wallet(3);

    let worker_offer = offer(&worker, 1, 7, 5);
    let challenger_offer = offer(&challenger, 2, 7, 5);
    let offers = [worker_offer.clone(), challenger_offer.clone()];
    let job = job(&requester);
    let plan = plan_assignments(&job, &offers, 10, 1)
        .unwrap()
        .sign(&requester)
        .unwrap();
    assert_eq!(plan.assignments.len(), 2);
    assert_eq!(plan.total_sat, 70);

    // Both providers stand behind their offers with a bond.
    let mut bonds = BondBook::new(NET);
    let worker_bond = bond(&worker, 100_000);
    let challenger_bond = bond(&challenger, 100_000);
    bonds.register(&worker_bond, 10).unwrap();
    bonds.register(&challenger_bond, 10).unwrap();
    assert!(bonds.admit_offer(&worker_offer, 10).is_ok());
    assert!(bonds.admit_offer(&challenger_offer, 10).is_ok());

    // Fund the job and journal the whole flow as it is verified.
    let mut escrow = EscrowBook::new(NET);
    let funding = SignedFunding::sign(
        EscrowFunding {
            version: ESCROW_VERSION,
            network_id: NET.into(),
            job: job.hash(),
            requester: requester.address().unwrap(),
            amount_sat: plan.total_sat,
            deadline: DEADLINE,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    escrow.fund(&funding, 10).unwrap();

    let mut journal = FlowJournal::new(NET);
    journal.append_bond(&worker_bond).unwrap();
    journal.append_bond(&challenger_bond).unwrap();
    journal.append_funding(&funding).unwrap();
    journal.append_offer(&worker_offer).unwrap();
    journal.append_offer(&challenger_offer).unwrap();

    let mut ledger = ComputeLedger::new();
    let mut receipts = Vec::new();
    for assignment in &plan.assignments {
        journal.append_assignment(assignment).unwrap();
        let provider = if assignment.assignment.provider == worker.address().unwrap() {
            &worker
        } else {
            &challenger
        };
        let receipt = SignedReceipt::sign(
            ComputeReceipt::new(
                assignment,
                assignment.assignment.units,
                [assignment.assignment.shard as u8; 32],
                500,
                20,
                1,
            )
            .unwrap(),
            provider,
        )
        .unwrap();
        journal.append_receipt(&receipt).unwrap();
        ledger.settle(&receipt, assignment, 21).unwrap();
        escrow.release(&receipt, assignment, 21).unwrap();
        bonds.record_settlement(&receipt, assignment).unwrap();
        receipts.push(receipt);
    }
    assert_eq!(ledger.settled_total_sat(), 70);
    assert_eq!(escrow.remaining_sat(&job.hash()), 0);
    assert_eq!(bonds.score(&worker.address().unwrap()), 5);

    // A challenge re-runs one shard: a different result slashes the worker.
    let challenged = plan
        .assignments
        .iter()
        .find(|a| a.assignment.provider == worker.address().unwrap())
        .unwrap();
    let first = receipts
        .iter()
        .find(|r| r.receipt.assignment == challenged.hash())
        .unwrap();
    let mut challenges = ChallengeBook::new(NET);
    let demand = SignedChallenge::sign(
        Challenge {
            version: CHALLENGE_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            provider: worker.address().unwrap(),
            challenger: challenger.address().unwrap(),
            assignment: challenged.hash(),
            deadline_height: 90,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    challenges.open(&demand, challenged, 30).unwrap();
    let mut second = ComputeReceipt::new(
        challenged,
        challenged.assignment.units,
        [9u8; 32],
        500,
        40,
        1,
    )
    .unwrap();
    second.provider = challenger.address().unwrap();
    let second = SignedReceipt::sign(second, &challenger).unwrap();
    challenges.submit_second(&second, 40).unwrap();
    let verdict = challenges.verdict(&challenged.hash(), first).unwrap();
    let dispute = verdict
        .fraud_dispute(NET, 1)
        .expect("a different result is fraud");
    assert_eq!(dispute.reason, DisputeReason::WrongResult);
    let dispute = SignedDispute::sign(dispute, &requester).unwrap();
    assert_eq!(bonds.slash(&dispute, challenged, 50), Ok(50_000));
    assert_eq!(bonds.score(&worker.address().unwrap()), -95);

    // A matching re-execution would have cleared the receipt instead.
    assert!(ChallengeVerdict::Match {
        assignment: challenged.hash()
    }
    .fraud_dispute(NET, 2)
    .is_none());

    // After the deadline the unspent remainder is refunded exactly once.
    let refund = escrow.refund(&job.hash(), DEADLINE + 1).unwrap();
    assert_eq!(refund.amount_sat, 0);
    assert_eq!(
        escrow.refund(&job.hash(), DEADLINE + 2),
        Err(srct_compute::ComputeError::AlreadyRefunded)
    );

    // A restarted node replays the same signed objects and rebuilds the
    // registration/funding state.
    let replayed = FlowJournal::decode(&journal.encode())
        .unwrap()
        .replay()
        .unwrap();
    assert_eq!(replayed.bonds.len(), 2);
    assert_eq!(replayed.fundings, vec![funding]);
    assert_eq!(replayed.offers.len(), 2);
    assert_eq!(replayed.assignments.len(), 2);
    assert_eq!(replayed.receipts.len(), 2);
    let mut restored_bonds = BondBook::new(NET);
    for b in &replayed.bonds {
        restored_bonds
            .register(b, b.bond.registered_height)
            .unwrap();
    }
    let mut restored_escrow = EscrowBook::new(NET);
    for f in &replayed.fundings {
        restored_escrow.restore(f).unwrap();
    }
    assert_eq!(
        restored_bonds
            .bond(&worker.address().unwrap())
            .unwrap()
            .amount_sat,
        100_000
    );
    // Receipts rebuild the releases the same way they were first applied.
    for receipt in &replayed.receipts {
        let assignment = replayed
            .assignments
            .iter()
            .find(|a| a.hash() == receipt.receipt.assignment)
            .unwrap();
        restored_escrow.release(receipt, assignment, 21).unwrap();
    }
    assert_eq!(restored_escrow.remaining_sat(&job.hash()), 0);
}
