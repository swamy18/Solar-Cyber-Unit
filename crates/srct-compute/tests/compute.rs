//! Acceptance tests for decentralized compute sharing: heterogeneous devices,
//! capacity-aware sharding, signed assignments, provider receipts and exact
//! settlement with timeout handling.

use srct_compute::market::{plan_assignments, ComputeJob, ComputeOffer, Verification};
use srct_compute::{
    Assignment, ComputeError, ComputeLedger, ComputeReceipt, Determinism, DeviceClass,
    DeviceProfile, SettlementStatus, SignedJob, SignedOffer, SignedReceipt, MAX_ATTEMPTS,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const SERVICE: &str = "train.mlp";
const KERNEL: Hash = [7u8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "compute-test").unwrap()
}

fn profile(
    class: DeviceClass,
    determinism: Determinism,
    ram_mib: u32,
    shard: u32,
    throughput_per_sec: u32,
    kernel: Hash,
) -> DeviceProfile {
    DeviceProfile::new(
        class,
        determinism,
        ram_mib,
        8,
        shard,
        50_000,
        throughput_per_sec,
        kernel,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_offer(
    provider: &Wallet,
    service: &str,
    profile: DeviceProfile,
    unit_price_sat: u64,
    min_units: u32,
    max_units_per_job: u32,
    privacy: bool,
    verification: Verification,
    available_from: u64,
    available_until: u64,
) -> SignedOffer {
    let offer = ComputeOffer {
        version: srct_compute::market::OFFER_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        service: service.into(),
        profile,
        unit_price_sat,
        min_units,
        max_units_per_job,
        privacy,
        verification,
        available_from,
        available_until,
        nonce: 1,
    };
    SignedOffer::sign(offer, provider).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn signed_job(
    requester: &Wallet,
    units: u32,
    max_unit_price_sat: u64,
    max_total_sat: u64,
    class_mask: u8,
    min_ram_mib: u32,
    min_units_per_sec: u32,
    determinism: Determinism,
    required_kernel: Hash,
    min_verification: Verification,
    sealed_input: bool,
    deadline: u64,
) -> SignedJob {
    let job = ComputeJob {
        version: srct_compute::market::JOB_VERSION,
        network_id: NET.into(),
        requester: requester.address().unwrap(),
        service: SERVICE.into(),
        units,
        max_unit_price_sat,
        max_total_sat,
        class_mask,
        min_ram_mib,
        min_units_per_sec,
        min_bandwidth_kbps: 0,
        determinism,
        required_kernel,
        min_verification,
        sealed_input,
        input: [3u8; 32],
        deadline,
        nonce: 1,
        confidential: false,
    };
    SignedJob::sign(job, requester).unwrap()
}

/// A cheap GPU workstation, a mid Apple laptop and a small phone.
fn fleet() -> (Vec<SignedOffer>, Wallet, Wallet, Wallet, Wallet) {
    let phone = wallet(1);
    let laptop = wallet(2);
    let desktop = wallet(3);
    let requester = wallet(9);
    let offers = vec![
        signed_offer(
            &phone,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                2_048,
                4,
                500,
                KERNEL,
            ),
            10,
            1,
            8,
            false,
            Verification::Receipt,
            0,
            100,
        ),
        signed_offer(
            &laptop,
            SERVICE,
            profile(
                DeviceClass::AppleSilicon,
                Determinism::Reproducible,
                16_384,
                10,
                2_000,
                KERNEL,
            ),
            12,
            2,
            20,
            true,
            Verification::Receipt,
            0,
            100,
        ),
        signed_offer(
            &desktop,
            SERVICE,
            profile(
                DeviceClass::Gpu,
                Determinism::Reproducible,
                65_536,
                25,
                5_000,
                KERNEL,
            ),
            7,
            1,
            20,
            true,
            Verification::Receipt,
            0,
            100,
        ),
    ];
    (offers, phone, laptop, desktop, requester)
}

#[test]
fn a_job_is_split_across_heterogeneous_devices() {
    let (offers, phone, laptop, desktop, requester) = fleet();
    // CPU + Apple silicon + GPU are all acceptable: matching runs on
    // capabilities (RAM, throughput, determinism), never on class.
    let job = signed_job(
        &requester,
        30,
        20,
        1_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();

    // Max-min fair across provider identities: each of the 3 providers gets an
    // equal share (10 units) first, capped by capacity. The phone caps at 8,
    // so its overflow is redistributed. Laptop's per-shard cap (10) means its
    // 11-unit share can only deliver 10 in one shard; the unshardable unit is
    // redistributed to the next provider in price order. Price only breaks
    // ties and enforces the cap — it never lets one provider monopolize the
    // job. Fairness is per identity: the desktop's 25 cores do not give it
    // more than its equal share.
    assert_eq!(plan.units(), 30);
    let desktop_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == desktop.address().unwrap())
        .map(|a| a.units)
        .sum();
    let phone_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == phone.address().unwrap())
        .map(|a| a.units)
        .sum();
    let laptop_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == laptop.address().unwrap())
        .map(|a| a.units)
        .sum();
    assert_eq!(desktop_units + phone_units + laptop_units, 30);
    assert_eq!(phone_units, 8); // capped at its per-job cap
    assert!(desktop_units >= 10); // at least its equal share
    assert!(laptop_units >= 10); // at least its equal share
    assert!(desktop_units <= desktop_units + phone_units + laptop_units);
    // No provider exceeds its per-job cap.
    assert!(desktop_units <= 20);
    assert!(phone_units <= 8);
    assert!(laptop_units <= 20);
    // Per-job cap is never exceeded across an offer's shards.
    assert_eq!(
        plan.assignments
            .iter()
            .filter(|a| a.provider == phone.address().unwrap())
            .map(|a| a.units)
            .sum::<u32>(),
        8
    );
    // Every shard respects min_units.
    for a in &plan.assignments {
        let offer = offers.iter().find(|o| o.hash() == a.offer).unwrap();
        assert!(a.units >= offer.offer.min_units);
        assert!(a.units <= offer.offer.profile.max_units_per_shard);
    }

    // The same offers in a different order produce the same plan.
    let reversed: Vec<SignedOffer> = offers.into_iter().rev().collect();
    let again = plan_assignments(&job, &reversed, 10, 1, None).unwrap();
    assert_eq!(plan.units(), again.units());
    assert_eq!(plan.total_sat, again.total_sat);
    assert_eq!(plan.assignments.len(), again.assignments.len());
    for (a, b) in plan.assignments.iter().zip(again.assignments.iter()) {
        assert_eq!(a.provider, b.provider);
        assert_eq!(a.units, b.units);
        assert_eq!(a.unit_price_sat, b.unit_price_sat);
        assert_eq!(a.total_sat, b.total_sat);
    }
}

#[test]
fn a_small_phone_can_take_a_small_job_alone() {
    let (offers, phone, _, _, requester) = fleet();
    // Only the phone's offer is on the table: with class ignored, the
    // cheapest capable device would otherwise win, so isolation here is
    // about fit, not class.
    let phone_only = vec![offers[0].clone()];
    let job = signed_job(
        &requester,
        4,
        20,
        100,
        DeviceClass::Cpu.mask(),
        1_024,
        400,
        Determinism::Reproducible,
        [0u8; 32],
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &phone_only, 10, 1, None).unwrap();
    assert_eq!(plan.assignments.len(), 1);
    assert_eq!(plan.assignments[0].provider, phone.address().unwrap());
    assert_eq!(plan.assignments[0].units, 4);
}

#[test]
fn a_small_device_can_take_several_shards_up_to_its_cap() {
    let phone = wallet(5);
    let requester = wallet(9);
    let offers = vec![signed_offer(
        &phone,
        SERVICE,
        profile(
            DeviceClass::Cpu,
            Determinism::Reproducible,
            2_048,
            4,
            500,
            KERNEL,
        ),
        10,
        1,
        8,
        false,
        Verification::Receipt,
        0,
        100,
    )];
    let job = signed_job(
        &requester,
        8,
        20,
        1_000,
        DeviceClass::Cpu.mask(),
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    assert_eq!(plan.assignments.len(), 2);
    assert_eq!(plan.units(), 8);
    assert!(plan
        .assignments
        .iter()
        .all(|a| a.units == 4 && a.provider == phone.address().unwrap()));
}

#[test]
fn ineligible_offers_are_never_scheduled() {
    let (offers, _, _, _, requester) = fleet();
    let base = signed_job(
        &requester,
        4,
        20,
        100,
        DeviceClass::Cpu.mask(),
        512,
        400,
        Determinism::Reproducible,
        [0u8; 32],
        Verification::Receipt,
        false,
        100,
    );

    let cases: Vec<(&str, ComputeJob, Vec<SignedOffer>)> = vec![
        (
            "too little ram",
            ComputeJob {
                min_ram_mib: 32_768,
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "bit-exact required",
            ComputeJob {
                determinism: Determinism::BitExact,
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "kernel mismatch",
            ComputeJob {
                required_kernel: [8u8; 32],
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "throughput below the floor",
            ComputeJob {
                min_units_per_sec: 50_000,
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "bandwidth below the floor",
            ComputeJob {
                min_bandwidth_kbps: 500_000,
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "wrong service",
            ComputeJob {
                service: "infer.llm".into(),
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "price above the cap",
            ComputeJob {
                max_unit_price_sat: 5,
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "sealed input with a plaintext-only provider",
            ComputeJob {
                sealed_input: true,
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "attested verification not offered",
            ComputeJob {
                min_verification: Verification::Attested,
                ..base.job.clone()
            },
            vec![offers[0].clone()],
        ),
        (
            "availability window in the past",
            base.job.clone(),
            vec![offers[0].clone()],
        ),
    ];

    for (name, job, candidate) in cases {
        let height = if name == "availability window in the past" {
            101
        } else {
            10
        };
        let job = SignedJob::sign(job, &requester).unwrap();
        let err = plan_assignments(&job, &candidate, height, 1, None).unwrap_err();
        assert!(
            matches!(err, ComputeError::NoEligibleOffer | ComputeError::Expired),
            "{name}: got {err:?}"
        );
    }

    // Class is a display label, not a matching rule: a photonic-only mask
    // still matches a CPU offer when every capability floor passes.
    let photonic = ComputeJob {
        class_mask: DeviceClass::Photonic.mask(),
        ..base.job.clone()
    };
    let photonic = SignedJob::sign(photonic, &requester).unwrap();
    let plan = plan_assignments(&photonic, &[offers[0].clone()], 10, 1, None).unwrap();
    assert_eq!(plan.units(), 4);
}

#[test]
fn capacity_budget_and_minimum_shard_are_enforced() {
    let phone = wallet(4);
    let requester = wallet(9);
    let one = vec![signed_offer(
        &phone,
        SERVICE,
        profile(
            DeviceClass::Cpu,
            Determinism::Reproducible,
            2_048,
            4,
            500,
            KERNEL,
        ),
        10,
        3,
        8,
        false,
        Verification::Receipt,
        0,
        100,
    )];

    let too_much = signed_job(
        &requester,
        9,
        20,
        1_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    assert_eq!(
        plan_assignments(&too_much, &one, 10, 1, None).unwrap_err(),
        ComputeError::InsufficientCapacity
    );

    let below_min = signed_job(
        &requester,
        2,
        20,
        1_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    assert_eq!(
        plan_assignments(&below_min, &one, 10, 1, None).unwrap_err(),
        ComputeError::InsufficientCapacity
    );

    let over_budget = signed_job(
        &requester,
        4,
        20,
        39,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    assert_eq!(
        plan_assignments(&over_budget, &one, 10, 1, None).unwrap_err(),
        ComputeError::BudgetExceeded
    );
}

#[test]
fn only_the_requester_can_authorize_a_plan() {
    let (offers, _, _, _, requester) = fleet();
    let job = signed_job(
        &requester,
        4,
        20,
        100,
        DeviceClass::Cpu.mask(),
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    let signed = plan.sign(&requester).unwrap();
    signed.verify().unwrap();
    assert_eq!(signed.units(), 4);

    let stranger = wallet(10);
    assert_eq!(
        plan.sign(&stranger).unwrap_err(),
        ComputeError::WrongRequester
    );

    let mut tampered = signed.clone();
    tampered.assignments[0].assignment.provider = [0xAA; 20];
    assert!(tampered.verify().is_err());
}

#[test]
fn a_receipt_settles_exactly_once() {
    let (offers, _, _, _, requester) = fleet();
    let provider_wallet = wallet(3); // desktop
    let job = signed_job(
        &requester,
        5,
        20,
        100,
        DeviceClass::Gpu.mask(),
        32_768,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    let signed = plan.sign(&requester).unwrap();
    let assignment = signed.assignments[0].clone();
    assert_eq!(
        assignment.assignment.provider,
        provider_wallet.address().unwrap()
    );

    let receipt = ComputeReceipt::new(&assignment, 5, [4u8; 32], 1_000, 20, 1).unwrap();
    let receipt = SignedReceipt::sign(receipt, &provider_wallet).unwrap();

    let mut ledger = ComputeLedger::new();
    let payout = ledger.settle(&receipt, &assignment, 21).unwrap();
    assert_eq!(payout.from, requester.address().unwrap());
    assert_eq!(payout.to, provider_wallet.address().unwrap());
    assert_eq!(payout.amount_sat, 5 * 7);
    assert_eq!(ledger.settled_total_sat(), 35);
    assert!(matches!(
        ledger.status(&assignment.hash()),
        SettlementStatus::Settled(_)
    ));

    assert_eq!(
        ledger.settle(&receipt, &assignment, 21),
        Err(ComputeError::AlreadySettled)
    );
}

#[test]
fn overclaim_price_mismatch_and_wrong_binding_are_refused() {
    let (offers, _, _, _, requester) = fleet();
    let provider_wallet = wallet(3);
    let job = signed_job(
        &requester,
        5,
        20,
        100,
        DeviceClass::Gpu.mask(),
        32_768,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    let signed = plan.sign(&requester).unwrap();
    let assignment = signed.assignments[0].clone();

    // Overclaim: 6 units for a 5-unit assignment.
    let mut over = ComputeReceipt::new(&assignment, 5, [4u8; 32], 1, 20, 1).unwrap();
    over.units_done = 6;
    over.total_sat = 6 * over.unit_price_sat;
    let over = SignedReceipt::sign(over, &provider_wallet).unwrap();
    let mut ledger = ComputeLedger::new();
    assert_eq!(
        ledger.settle(&over, &assignment, 21),
        Err(ComputeError::Overclaim)
    );

    // Unit price differs from the assignment even though the arithmetic is
    // self-consistent.
    let mut cheap = ComputeReceipt::new(&assignment, 5, [4u8; 32], 1, 20, 1).unwrap();
    cheap.unit_price_sat = 1;
    cheap.total_sat = 5;
    let cheap = SignedReceipt::sign(cheap, &provider_wallet).unwrap();
    assert_eq!(
        ledger.settle(&cheap, &assignment, 21),
        Err(ComputeError::PriceMismatch)
    );

    // A receipt for another assignment cannot settle this one.
    let other = signed.assignments[0].clone();
    let mut receipt = ComputeReceipt::new(&other, 1, [4u8; 32], 1, 20, 1).unwrap();
    receipt.assignment = [0xBB; 32];
    let receipt = SignedReceipt::sign(receipt, &provider_wallet).unwrap();
    assert_eq!(
        ledger.settle(&receipt, &assignment, 21),
        Err(ComputeError::BindingMismatch)
    );

    // Only the assigned provider signs a valid receipt.
    let receipt = ComputeReceipt::new(&assignment, 5, [4u8; 32], 1, 20, 1).unwrap();
    let impostor = wallet(11);
    assert_eq!(
        SignedReceipt::sign(receipt.clone(), &impostor).unwrap_err(),
        ComputeError::WrongProvider
    );
    let mut forged = SignedReceipt::sign(receipt, &provider_wallet).unwrap();
    forged.receipt.units_done = 4;
    forged.receipt.total_sat = 4 * forged.receipt.unit_price_sat;
    assert!(forged.verify().is_err());
}

#[test]
fn late_receipts_and_expiry_are_refused() {
    let (offers, _, _, _, requester) = fleet();
    let provider_wallet = wallet(3);
    let job = signed_job(
        &requester,
        5,
        20,
        100,
        DeviceClass::Gpu.mask(),
        32_768,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        50,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    let signed = plan.sign(&requester).unwrap();
    let assignment = signed.assignments[0].clone();
    let receipt = ComputeReceipt::new(&assignment, 5, [4u8; 32], 1, 20, 1).unwrap();
    let receipt = SignedReceipt::sign(receipt, &provider_wallet).unwrap();

    let mut ledger = ComputeLedger::new();
    assert_eq!(
        ledger.settle(&receipt, &assignment, 51),
        Err(ComputeError::Expired)
    );
    assert_eq!(
        ledger.expire(&assignment, 50),
        Err(ComputeError::NotExpired)
    );
    assert!(ledger.expire(&assignment, 51).unwrap());
    assert!(!ledger.expire(&assignment, 52).unwrap());
    assert!(matches!(
        ledger.status(&assignment.hash()),
        SettlementStatus::Expired
    ));
    // Even with an in-deadline height argument, an expired assignment cannot
    // be resurrected by a late receipt.
    assert_eq!(
        ledger.settle(&receipt, &assignment, 50),
        Err(ComputeError::AssignmentExpired)
    );
}

#[test]
fn attempt_deadline_and_wire_codecs_are_bounded() {
    let (offers, _, _, _, requester) = fleet();
    let job = signed_job(
        &requester,
        4,
        20,
        100,
        DeviceClass::Cpu.mask(),
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        50,
    );
    assert_eq!(
        plan_assignments(&job, &offers, 10, MAX_ATTEMPTS + 1, None).unwrap_err(),
        ComputeError::TooManyAttempts
    );
    assert_eq!(
        plan_assignments(&job, &offers, 51, 1, None).unwrap_err(),
        ComputeError::Expired
    );

    let offer = &offers[0];
    let decoded = ComputeOffer::decode(&offer.offer.encode()).unwrap();
    assert_eq!(decoded, offer.offer);
    let decoded_job = ComputeJob::decode(&job.job.encode()).unwrap();
    assert_eq!(decoded_job, job.job);

    let mut tampered = offer.clone();
    tampered.offer.unit_price_sat = 1;
    assert!(matches!(
        tampered.verify(),
        Err(ComputeError::BadSignature(_))
    ));

    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    let signed = plan.sign(&requester).unwrap();
    let assignment_wire = signed.assignments[0].assignment.encode();
    assert_eq!(
        Assignment::decode(&assignment_wire).unwrap(),
        signed.assignments[0].assignment
    );
}

#[test]
fn fair_allocation_large_and_small_provider_both_get_shares() {
    let small = wallet(1);
    let large = wallet(2);
    let requester = wallet(9);
    // Large provider has ten times the per-job cap but the same price: it must
    // not crowd the small provider out.
    let offers = vec![
        signed_offer(
            &small,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                2_048,
                4,
                1_000,
                KERNEL,
            ),
            5,
            1,
            10,
            false,
            Verification::Receipt,
            0,
            100,
        ),
        signed_offer(
            &large,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                65_536,
                25,
                5_000,
                KERNEL,
            ),
            5,
            1,
            1000,
            false,
            Verification::Receipt,
            0,
            100,
        ),
    ];
    let job = signed_job(
        &requester,
        100,
        20,
        10_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    assert_eq!(plan.units(), 100);
    // Equal share is 50 each; the small provider caps at 10, so its overflow is
    // redistributed to the large provider. Both still receive a share.
    let small_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == small.address().unwrap())
        .map(|a| a.units)
        .sum();
    let large_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == large.address().unwrap())
        .map(|a| a.units)
        .sum();
    assert_eq!(small_units, 10);
    assert_eq!(large_units, 90);
    assert!(small_units > 0);
    assert!(large_units > 0);
}

#[test]
fn fair_allocation_is_per_identity_not_per_machine() {
    // One provider with many offers (many "machines") is a single identity and
    // gets no more than its equal share. Sybil resistance comes from the bond
    // and capacity rule, not from allocation.
    let many_machines = wallet(1);
    let single = wallet(2);
    let requester = wallet(9);
    let mut offers = Vec::new();
    for _ in 0..20 {
        offers.push(signed_offer(
            &many_machines,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                2_048,
                4,
                1_000,
                KERNEL,
            ),
            5,
            1,
            50,
            false,
            Verification::Receipt,
            0,
            100,
        ));
    }
    offers.push(signed_offer(
        &single,
        SERVICE,
        profile(
            DeviceClass::Cpu,
            Determinism::Reproducible,
            65_536,
            25,
            5_000,
            KERNEL,
        ),
        5,
        1,
        1000,
        false,
        Verification::Receipt,
        0,
        100,
    ));
    let job = signed_job(
        &requester,
        100,
        20,
        10_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    assert_eq!(plan.units(), 100);
    let many_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == many_machines.address().unwrap())
        .map(|a| a.units)
        .sum();
    let single_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == single.address().unwrap())
        .map(|a| a.units)
        .sum();
    // Equal share is 50 each; total capacity is more than enough, so both get
    // exactly their equal share regardless of how many offers one identity has.
    assert_eq!(many_units, 50);
    assert_eq!(single_units, 50);
}

#[test]
fn fair_allocation_capped_overflow_is_redistributed() {
    let capped = wallet(1);
    let uncapped = wallet(2);
    let requester = wallet(9);
    let offers = vec![
        signed_offer(
            &capped,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                2_048,
                4,
                1_000,
                KERNEL,
            ),
            5,
            1,
            5,
            false,
            Verification::Receipt,
            0,
            100,
        ),
        signed_offer(
            &uncapped,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                65_536,
                25,
                5_000,
                KERNEL,
            ),
            5,
            1,
            1000,
            false,
            Verification::Receipt,
            0,
            100,
        ),
    ];
    let job = signed_job(
        &requester,
        100,
        20,
        10_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    assert_eq!(plan.units(), 100);
    let capped_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == capped.address().unwrap())
        .map(|a| a.units)
        .sum();
    let uncapped_units: u32 = plan
        .assignments
        .iter()
        .filter(|a| a.provider == uncapped.address().unwrap())
        .map(|a| a.units)
        .sum();
    assert_eq!(capped_units, 5);
    assert_eq!(uncapped_units, 95);
}

#[test]
fn fair_allocation_is_deterministic_under_reordered_input() {
    let (offers, _phone, _laptop, _desktop, requester) = fleet();
    let job = signed_job(
        &requester,
        30,
        20,
        1_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let baseline = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    // Every permutation must yield the identical plan.
    let mut permuted = offers.clone();
    permuted.reverse();
    let rev = plan_assignments(&job, &permuted, 10, 1, None).unwrap();
    assert_eq!(baseline.assignments.len(), rev.assignments.len());
    for (a, b) in baseline.assignments.iter().zip(rev.assignments.iter()) {
        assert_eq!(a.provider, b.provider);
        assert_eq!(a.units, b.units);
        assert_eq!(a.unit_price_sat, b.unit_price_sat);
        assert_eq!(a.total_sat, b.total_sat);
    }
    // A third distinct ordering as well.
    let mut rotated = offers.clone();
    rotated.rotate_left(1);
    let rot = plan_assignments(&job, &rotated, 10, 1, None).unwrap();
    assert_eq!(baseline.total_sat, rot.total_sat);
    assert_eq!(baseline.units(), rot.units());
}

#[test]
fn fair_allocation_respects_price_cap() {
    let cheap = wallet(1);
    let expensive = wallet(2);
    let requester = wallet(9);
    // Expensive provider is above the job's price cap and must be excluded.
    let offers = vec![
        signed_offer(
            &cheap,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                2_048,
                4,
                1_000,
                KERNEL,
            ),
            5,
            1,
            100,
            false,
            Verification::Receipt,
            0,
            100,
        ),
        signed_offer(
            &expensive,
            SERVICE,
            profile(
                DeviceClass::Cpu,
                Determinism::Reproducible,
                65_536,
                25,
                5_000,
                KERNEL,
            ),
            50,
            1,
            100,
            false,
            Verification::Receipt,
            0,
            100,
        ),
    ];
    let job = signed_job(
        &requester,
        50,
        10,
        10_000,
        DeviceClass::ALL_MASK,
        512,
        400,
        Determinism::Reproducible,
        KERNEL,
        Verification::Receipt,
        false,
        100,
    );
    let plan = plan_assignments(&job, &offers, 10, 1, None).unwrap();
    assert_eq!(plan.units(), 50);
    for a in &plan.assignments {
        assert_eq!(a.provider, cheap.address().unwrap());
        assert_eq!(a.unit_price_sat, 5);
    }
}
