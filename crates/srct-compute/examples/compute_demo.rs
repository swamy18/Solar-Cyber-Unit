//! End-to-end compute-sharing demo:
//! one requester -> one job -> signed offers from a phone, laptop and GPU
//! -> capacity-aware shards -> requester-authorized assignments -> job escrow
//! -> provider receipts -> exact payouts and releases -> challenge re-run ->
//! `WrongResult` slash -> refund of the remainder -> replay refused.
//!
//! Run with:
//! ```text
//! cargo run --release -p srct-compute --example compute_demo
//! ```

use srct_compute::market::{
    plan_assignments, ComputeJob, ComputeOffer, Verification, JOB_VERSION, OFFER_VERSION,
};
use srct_compute::{
    BondBook, BondDispute, Challenge, ChallengeBook, ComputeLedger, ComputeReceipt, Determinism,
    DeviceClass, DeviceProfile, DisputeReason, EscrowBook, EscrowFunding, ProviderBond, SignedBond,
    SignedChallenge, SignedDispute, SignedFunding, SignedJob, SignedOffer, SignedReceipt,
    BOND_VERSION, CHALLENGE_VERSION, ESCROW_VERSION,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const SERVICE: &str = "train.mlp";
const KERNEL: Hash = [7u8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "compute-demo").unwrap()
}

fn offer(
    provider: &Wallet,
    class: DeviceClass,
    ram_mib: u32,
    shard_units: u32,
    max_units_per_job: u32,
    price: u64,
) -> SignedOffer {
    let offer = ComputeOffer {
        version: OFFER_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        service: SERVICE.into(),
        profile: DeviceProfile::new(
            class,
            Determinism::Reproducible,
            ram_mib,
            8,
            shard_units,
            50_000,
            KERNEL,
        ),
        unit_price_sat: price,
        min_units: 1,
        max_units_per_job,
        privacy: true,
        verification: Verification::Receipt,
        available_from: 0,
        available_until: 100,
        nonce: 1,
    };
    SignedOffer::sign(offer, provider).unwrap()
}

fn main() {
    let requester = wallet(9);
    let phone = wallet(1);
    let laptop = wallet(2);
    let desktop = wallet(3);
    let challenger = wallet(4);

    let offers = vec![
        offer(&phone, DeviceClass::Cpu, 2_048, 4, 8, 10),
        offer(&laptop, DeviceClass::AppleSilicon, 16_384, 10, 20, 12),
        offer(&desktop, DeviceClass::Gpu, 65_536, 25, 20, 7),
    ];

    let job = ComputeJob {
        version: JOB_VERSION,
        network_id: NET.into(),
        requester: requester.address().unwrap(),
        service: SERVICE.into(),
        units: 30,
        max_unit_price_sat: 20,
        max_total_sat: 1_000,
        class_mask: DeviceClass::ALL_MASK,
        min_ram_mib: 512,
        determinism: Determinism::Reproducible,
        required_kernel: KERNEL,
        min_verification: Verification::Receipt,
        sealed_input: true,
        input: [3u8; 32],
        deadline: 100,
        nonce: 1,
    };
    let job = SignedJob::sign(job, &requester).unwrap();

    let plan = plan_assignments(&job, &offers, 10, 1).unwrap();
    println!(
        "plan: {} units in {} shards for {} sat",
        plan.units(),
        plan.assignments.len(),
        plan.total_sat
    );
    for assignment in &plan.assignments {
        println!(
            "  shard {}: {} units -> provider {} at {} sat/unit",
            assignment.shard, assignment.units, assignment.provider[0], assignment.unit_price_sat
        );
    }
    let signed_plan = plan.sign(&requester).unwrap();
    signed_plan.verify().unwrap();

    // Job escrow: lock the plan budget once, then release each settled
    // receipt's exact total and refund whatever is left after the deadline.
    let mut escrow = EscrowBook::new(NET);
    let funding = SignedFunding::sign(
        EscrowFunding {
            version: ESCROW_VERSION,
            network_id: NET.into(),
            job: job.hash(),
            requester: requester.address().unwrap(),
            amount_sat: signed_plan.total_sat,
            deadline: job.job.deadline,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    escrow.fund(&funding, 10).unwrap();
    println!("---");
    println!(
        "escrow funds {} sat for the job",
        escrow.remaining_sat(&job.hash())
    );

    let mut ledger = ComputeLedger::new();
    let mut laptop_shard = None;
    for assignment in &signed_plan.assignments {
        let provider = if assignment.assignment.provider == phone.address().unwrap() {
            &phone
        } else if assignment.assignment.provider == laptop.address().unwrap() {
            &laptop
        } else {
            &desktop
        };
        let receipt = ComputeReceipt::new(
            assignment,
            assignment.assignment.units,
            [assignment.assignment.shard as u8; 32],
            500,
            20,
            1,
        )
        .unwrap();
        let receipt = SignedReceipt::sign(receipt, provider).unwrap();
        let payout = ledger.settle(&receipt, assignment, 21).unwrap();
        let released = escrow.release(&receipt, assignment, 21).unwrap();
        assert_eq!(released.amount_sat, payout.amount_sat);
        if assignment.assignment.provider == laptop.address().unwrap() {
            laptop_shard = Some((receipt.clone(), (*assignment).clone()));
        }
        println!(
            "  settled shard {}: {} sat (ref {}), escrow left {}",
            assignment.assignment.shard,
            payout.amount_sat,
            payout.receipt[0],
            escrow.remaining_sat(&job.hash())
        );
        println!(
            "  replay refused: {:?}",
            ledger.settle(&receipt, assignment, 21)
        );
    }
    println!(
        "total paid: {} sat across {} assignments",
        ledger.settled_total_sat(),
        signed_plan.assignments.len()
    );

    // Bonds and reputation: capacity claims cost stake. A challenge re-runs
    // the laptop's shard independently; a different result becomes a
    // `WrongResult` dispute, halves the bond and bans the provider.
    println!("---");
    let mut book = BondBook::new(NET);
    let bond = ProviderBond {
        version: BOND_VERSION,
        network_id: NET.into(),
        provider: laptop.address().unwrap(),
        amount_sat: srct_compute::MIN_BOND_SAT,
        registered_height: 1,
        nonce: 1,
    };
    let signed_bond = SignedBond::sign(bond, &laptop).unwrap();
    println!(
        "unbonded laptop admitted: {:?}",
        book.admit_offer(&offers[1], 10)
            .err()
            .map(|e| e.to_string())
    );
    book.register(&signed_bond, 5).unwrap();
    let laptop_offer = &offers[1];
    let admit = book.admit_offer(laptop_offer, 10);
    println!(
        "laptop bonds {} sat -> admitted: {:?}",
        srct_compute::MIN_BOND_SAT,
        admit.is_ok()
    );

    let (first, shard) = laptop_shard.expect("laptop shard was settled");
    let mut challenges = ChallengeBook::new(NET);
    let demand = SignedChallenge::sign(
        Challenge {
            version: CHALLENGE_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            provider: laptop.address().unwrap(),
            challenger: challenger.address().unwrap(),
            assignment: shard.hash(),
            deadline_height: 90,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    challenges.open(&demand, &shard, 30).unwrap();
    let mut second =
        ComputeReceipt::new(&shard, shard.assignment.units, [9u8; 32], 700, 40, 1).unwrap();
    second.provider = challenger.address().unwrap();
    let second = SignedReceipt::sign(second, &challenger).unwrap();
    challenges.submit_second(&second, 40).unwrap();
    let dispute: BondDispute = challenges
        .verdict(&shard.hash(), &first)
        .unwrap()
        .fraud_dispute(NET, 1)
        .expect("the re-run differs");
    assert_eq!(dispute.reason, DisputeReason::WrongResult);
    let signed_dispute = SignedDispute::sign(dispute, &requester).unwrap();
    let remaining = book.slash(&signed_dispute, &shard, 50).unwrap();
    println!(
        "challenge mismatch -> WrongResult: bond {} -> {} sat, score {}",
        srct_compute::MIN_BOND_SAT,
        remaining,
        book.score(&laptop.address().unwrap())
    );
    println!(
        "slashed laptop admission: {:?}",
        book.admit_offer(laptop_offer, 10)
            .err()
            .map(|e| e.to_string())
    );

    // The pot is fully released, so the refund is zero and closes it.
    let refund = escrow.refund(&job.hash(), job.job.deadline + 1).unwrap();
    println!(
        "escrow refund after deadline: {} sat to requester",
        refund.amount_sat
    );
}
