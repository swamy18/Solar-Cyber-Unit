//! End-to-end compute-sharing demo:
//! one requester -> one job -> signed offers from a phone, laptop and GPU
//! -> capacity-aware shards -> requester-authorized assignments -> provider
//! receipts -> exact payout instructions -> replay refused.
//!
//! Run with:
//! ```text
//! cargo run --release -p srct-compute --example compute_demo
//! ```

use srct_compute::market::{
    plan_assignments, ComputeJob, ComputeOffer, Verification, JOB_VERSION, OFFER_VERSION,
};
use srct_compute::{
    ComputeLedger, ComputeReceipt, Determinism, DeviceClass, DeviceProfile, SignedJob, SignedOffer,
    SignedReceipt,
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

    let mut ledger = ComputeLedger::new();
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
        println!(
            "  settled shard {}: {} sat (ref {})",
            assignment.assignment.shard, payout.amount_sat, payout.receipt[0]
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

    // Bonds and reputation: capacity claims now cost stake. A fraud dispute
    // halves the bond and the reputation ban keeps the provider out even
    // after it re-bonds.
    println!("---");
    let mut book = srct_compute::BondBook::new(NET);
    let bond = srct_compute::ProviderBond {
        version: srct_compute::bond::BOND_VERSION,
        network_id: NET.into(),
        provider: laptop.address().unwrap(),
        amount_sat: srct_compute::MIN_BOND_SAT,
        registered_height: 1,
        nonce: 1,
    };
    let signed_bond = srct_compute::SignedBond::sign(bond, &laptop).unwrap();
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

    let shard = &signed_plan
        .assignments
        .iter()
        .find(|a| a.assignment.provider == laptop.address().unwrap())
        .unwrap()
        .clone();
    let dispute = srct_compute::BondDispute {
        version: srct_compute::bond::BOND_VERSION,
        network_id: NET.into(),
        requester: requester.address().unwrap(),
        provider: laptop.address().unwrap(),
        assignment: shard.hash(),
        reason: srct_compute::DisputeReason::Overclaim,
        evidence: [5u8; 32],
        nonce: 1,
    };
    let signed_dispute = srct_compute::SignedDispute::sign(dispute, &requester).unwrap();
    let remaining = book.slash(&signed_dispute, shard, 20).unwrap();
    println!(
        "fraud dispute: bond {} -> {} sat, score {}",
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
}
