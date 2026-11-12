//! Acceptance tests for bonded provider registration and reputation:
//! signed stakes, requester-signed disputes, lockups and admission gating.

use srct_compute::bond::{
    BondBook, BondDispute, BondWithdrawal, DisputeReason, ProviderBond, SignedBond, SignedDispute,
    SignedWithdrawal, BOND_VERSION, LOCKUP_HEIGHTS, MIN_BOND_SAT,
};
use srct_compute::market::{ComputeOffer, Verification, ASSIGNMENT_VERSION, OFFER_VERSION};
use srct_compute::{
    Assignment, ComputeError, ComputeReceipt, Determinism, DeviceClass, DeviceProfile,
    SignedAssignment, SignedOffer, SignedReceipt,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const OTHER: &str = "srct/mini";
const SERVICE: &str = "train.mlp";
const KERNEL: Hash = [7u8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "compute-bond-test").unwrap()
}

fn provider_wallet(seed: u8) -> Wallet {
    wallet(seed)
}

fn gpu_offer(provider: &Wallet) -> SignedOffer {
    let profile = DeviceProfile::new(
        DeviceClass::Gpu,
        Determinism::BitExact,
        24_576,
        16,
        1_000,
        50_000,
        KERNEL,
    );
    let offer = ComputeOffer {
        version: OFFER_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        service: SERVICE.into(),
        profile,
        unit_price_sat: 7,
        min_units: 1,
        max_units_per_job: 20,
        privacy: false,
        verification: Verification::Receipt,
        available_from: 0,
        available_until: 1_000,
        nonce: 1,
    };
    SignedOffer::sign(offer, provider).unwrap()
}

fn bond(provider: &Wallet, amount_sat: u64, height: u64, nonce: u64) -> SignedBond {
    let b = ProviderBond {
        version: BOND_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        amount_sat,
        registered_height: height,
        nonce,
    };
    SignedBond::sign(b, provider).unwrap()
}

fn assignment(requester: &Wallet, provider: &Wallet, deadline: u64) -> SignedAssignment {
    let a = Assignment {
        version: ASSIGNMENT_VERSION,
        job: [1u8; 32],
        offer: [2u8; 32],
        requester: requester.address().unwrap(),
        provider: provider.address().unwrap(),
        shard: 0,
        units: 10,
        unit_price_sat: 5,
        total_sat: 50,
        deadline,
        attempt: 1,
    };
    SignedAssignment::sign(a, requester).unwrap()
}

fn receipt(
    provider: &Wallet,
    assignment: &SignedAssignment,
    units_done: u32,
    height: u64,
) -> SignedReceipt {
    let receipt = ComputeReceipt::new(assignment, units_done, [4u8; 32], 5, height, 1).unwrap();
    SignedReceipt::sign(receipt, provider).unwrap()
}

fn dispute(
    requester: &Wallet,
    provider: &Wallet,
    assignment: &SignedAssignment,
    reason: DisputeReason,
    nonce: u64,
) -> SignedDispute {
    let d = BondDispute {
        version: BOND_VERSION,
        network_id: NET.into(),
        requester: requester.address().unwrap(),
        provider: provider.address().unwrap(),
        assignment: assignment.hash(),
        reason,
        evidence: [9u8; 32],
        nonce,
    };
    SignedDispute::sign(d, requester).unwrap()
}

#[test]
fn bond_wire_round_trips_and_tampering_breaks_signatures() {
    let provider = provider_wallet(1);
    let requester = wallet(9);
    let mut book = BondBook::new(NET);

    let signed_bond = bond(&provider, MIN_BOND_SAT, 5, 1);
    let decoded_bond = ProviderBond::decode(&signed_bond.bond.encode()).unwrap();
    assert_eq!(decoded_bond, signed_bond.bond);
    assert_eq!(decoded_bond.lockup_until(), 5 + LOCKUP_HEIGHTS);
    assert!(ProviderBond::decode(&signed_bond.bond.encode()[..20]).is_err());

    let withdrawal = SignedWithdrawal::sign(
        BondWithdrawal {
            version: BOND_VERSION,
            network_id: NET.into(),
            provider: provider.address().unwrap(),
            amount_sat: 1_000,
            nonce: 1,
        },
        &provider,
    )
    .unwrap();
    let decoded = BondWithdrawal::decode(&withdrawal.withdrawal.encode()).unwrap();
    assert_eq!(decoded, withdrawal.withdrawal);

    let a = assignment(&requester, &provider, 100);
    let d = dispute(&requester, &provider, &a, DisputeReason::NoShow, 1);
    let decoded = BondDispute::decode(&d.dispute.encode()).unwrap();
    assert_eq!(decoded, d.dispute);
    assert!(DisputeReason::from_u8(9).is_none());
    assert_eq!(DisputeReason::from_u8(0), Some(DisputeReason::NoShow));

    // None of the signed bundles may be re-signed by a stranger.
    book.register(&signed_bond, 10).unwrap();
    let withdrawal_2 = SignedWithdrawal::sign(
        BondWithdrawal {
            version: BOND_VERSION,
            network_id: NET.into(),
            provider: provider.address().unwrap(),
            amount_sat: 1_000,
            nonce: 2,
        },
        &provider,
    )
    .unwrap();
    assert!(book.withdraw(&withdrawal_2, 5 + LOCKUP_HEIGHTS).is_ok());
}

#[test]
fn a_bonded_provider_passes_admission() {
    let provider = provider_wallet(1);
    let offer = gpu_offer(&provider);
    let mut book = BondBook::new(NET);

    assert!(matches!(
        book.admit_offer(&offer, 10),
        Err(ComputeError::NotBonded)
    ));

    let bonded = bond(&provider, MIN_BOND_SAT, 5, 1);
    let total = book.register(&bonded, 10).unwrap();
    assert_eq!(total, MIN_BOND_SAT);
    assert_eq!(
        book.bond(&provider.address().unwrap()).unwrap().amount_sat,
        MIN_BOND_SAT
    );
    assert!(book.admit_offer(&offer, 10).is_ok());
}

#[test]
fn an_underbonded_or_foreign_network_offer_is_refused() {
    let provider = provider_wallet(1);
    let offer = gpu_offer(&provider);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, 100, 5, 1), 10).unwrap();
    assert!(matches!(
        book.admit_offer(&offer, 10),
        Err(ComputeError::InsufficientBond)
    ));

    let other_book = BondBook::new(OTHER);
    assert!(matches!(
        other_book.admit_offer(&offer, 10),
        Err(ComputeError::WrongNetwork)
    ));
}

#[test]
fn forged_and_tampered_bonds_are_refused() {
    let provider = provider_wallet(1);
    let impostor = wallet(8);

    // Signed by a wallet that does not own the provider address.
    let forged = ProviderBond {
        version: BOND_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        amount_sat: MIN_BOND_SAT,
        registered_height: 5,
        nonce: 1,
    };
    assert!(matches!(
        SignedBond::sign(forged.clone(), &impostor),
        Err(ComputeError::WrongProvider)
    ));

    // Tamper the amount after signing.
    let signed = SignedBond::sign(forged, &provider).unwrap();
    let mut tampered = signed.clone();
    tampered.bond.amount_sat = u64::MAX;
    assert!(tampered.verify().is_err());

    // Wire decode is strict too.
    let decoded = SignedBond::hash(&signed);
    assert_ne!(decoded, [0u8; 32]);
}

#[test]
fn a_registration_replay_does_not_double_the_bond() {
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    let signed = bond(&provider, MIN_BOND_SAT, 5, 1);
    book.register(&signed, 10).unwrap();
    assert!(matches!(
        book.register(&signed, 10),
        Err(ComputeError::Replay)
    ));
    // A different registration (new nonce) does top the bond up.
    let top_up = bond(&provider, 5_000, 20, 2);
    assert_eq!(book.register(&top_up, 20).unwrap(), MIN_BOND_SAT + 5_000);
}

#[test]
fn a_fraud_dispute_halves_the_bond_and_bans_the_provider() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();
    let offer = gpu_offer(&provider);
    assert!(book.admit_offer(&offer, 10).is_ok());

    let a = assignment(&requester, &provider, 100);
    let d = dispute(&requester, &provider, &a, DisputeReason::Overclaim, 1);
    let remaining = book.slash(&d, &a, 20).unwrap();
    assert_eq!(remaining, MIN_BOND_SAT / 2);
    assert_eq!(book.score(&provider.address().unwrap()), -100);

    // A fraud-slasher's bond is also below the minimum, so admission fails on
    // the bond first.
    assert!(matches!(
        book.admit_offer(&offer, 10),
        Err(ComputeError::InsufficientBond)
    ));

    // Even with the stake restored, the reputation ban holds.
    book.register(&bond(&provider, MIN_BOND_SAT, 30, 2), 30)
        .unwrap();
    assert!(matches!(
        book.admit_offer(&offer, 30),
        Err(ComputeError::Banned)
    ));
}

#[test]
fn only_the_assignment_requester_can_slash() {
    let requester = wallet(9);
    let stranger = wallet(8);
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();

    let a = assignment(&requester, &provider, 100);
    let d = dispute(&stranger, &provider, &a, DisputeReason::Overclaim, 1);
    // The stranger signed a dispute naming *itself* as the requester, so the
    // assignment binding is what refuses it.
    assert!(matches!(
        book.slash(&d, &a, 20),
        Err(ComputeError::BindingMismatch)
    ));

    // Rewriting the requester onto a real requester's dispute breaks the
    // signature binding instead.
    let mut forged = dispute(&requester, &provider, &a, DisputeReason::Overclaim, 1);
    forged.dispute.requester = stranger.address().unwrap();
    assert!(matches!(
        book.slash(&forged, &a, 20),
        Err(ComputeError::WrongRequester)
    ));
    assert_eq!(
        book.bond(&provider.address().unwrap()).unwrap().amount_sat,
        MIN_BOND_SAT
    );
}

#[test]
fn a_dispute_must_bind_the_assignment_it_names() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let other_provider = provider_wallet(2);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();

    let a = assignment(&requester, &provider, 100);
    let d = dispute(&requester, &provider, &a, DisputeReason::Overclaim, 1);

    // The dispute names this assignment, but the book is shown a rival one.
    let rival = assignment(&requester, &other_provider, 100);
    assert!(matches!(
        book.slash(&d, &rival, 20),
        Err(ComputeError::BindingMismatch)
    ));

    // A dispute forged against a different assignment hash fails too.
    let mut forged = dispute(&requester, &provider, &a, DisputeReason::Overclaim, 1);
    forged.dispute.assignment = [5u8; 32];
    assert!(matches!(
        book.slash(&forged, &a, 20),
        Err(ComputeError::BadSignature(_))
    ));
}

#[test]
fn a_noshow_dispute_requires_the_deadline_to_pass() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();

    let a = assignment(&requester, &provider, 100);
    let d = dispute(&requester, &provider, &a, DisputeReason::NoShow, 1);
    assert!(matches!(
        book.slash(&d, &a, 100),
        Err(ComputeError::NotExpired)
    ));

    let remaining = book.slash(&d, &a, 101).unwrap();
    assert_eq!(remaining, MIN_BOND_SAT - MIN_BOND_SAT / 10);
}

#[test]
fn a_dispute_cannot_slash_twice() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();

    let a = assignment(&requester, &provider, 100);
    let d = dispute(&requester, &provider, &a, DisputeReason::Overclaim, 1);
    book.slash(&d, &a, 20).unwrap();
    assert!(matches!(
        book.slash(&d, &a, 20),
        Err(ComputeError::AlreadySlashed)
    ));
    assert_eq!(
        book.bond(&provider.address().unwrap()).unwrap().amount_sat,
        MIN_BOND_SAT / 2
    );
}

#[test]
fn timeouts_lower_reputation_and_ten_ban_the_provider() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();
    let offer = gpu_offer(&provider);
    let a = assignment(&requester, &provider, 100);

    // Nine timeouts stay schedulable; the tenth crosses the ban.
    for height in 101..=109u64 {
        book.record_timeout(&a, height).unwrap();
    }
    assert_eq!(book.score(&provider.address().unwrap()), -90);
    assert!(book.admit_offer(&offer, 110).is_ok());
    book.record_timeout(&a, 110).unwrap();
    assert!(matches!(
        book.admit_offer(&offer, 110),
        Err(ComputeError::Banned)
    ));

    // Settled units raise the score back over the threshold.
    let r = receipt(&provider, &a, 10, 60);
    book.record_settlement(&r, &a).unwrap();
    assert_eq!(book.score(&provider.address().unwrap()), -90);
    assert!(book.admit_offer(&offer, 120).is_ok());
}

#[test]
fn timeouts_are_refused_before_the_deadline() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    let a = assignment(&requester, &provider, 100);
    assert!(matches!(
        book.record_timeout(&a, 100),
        Err(ComputeError::NotExpired)
    ));
    assert_eq!(book.score(&provider.address().unwrap()), 0);
}

#[test]
fn rebonding_clears_timeouts_but_not_fraud_slashes() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();
    let a = assignment(&requester, &provider, 100);

    for height in 101..=104u64 {
        book.record_timeout(&a, height).unwrap();
    }
    assert_eq!(book.score(&provider.address().unwrap()), -40);

    book.register(&bond(&provider, 5_000, 30, 2), 30).unwrap();
    assert_eq!(book.score(&provider.address().unwrap()), 0);

    // A fraud slash is permanent: re-bonding restores the stake, not the score.
    let d = dispute(&requester, &provider, &a, DisputeReason::Overclaim, 1);
    book.slash(&d, &a, 40).unwrap();
    book.register(&bond(&provider, MIN_BOND_SAT, 50, 3), 50)
        .unwrap();
    assert_eq!(book.score(&provider.address().unwrap()), -100);
    let offer = gpu_offer(&provider);
    assert!(matches!(
        book.admit_offer(&offer, 60),
        Err(ComputeError::Banned)
    ));
}

#[test]
fn withdrawing_before_lockup_is_refused_and_after_works() {
    let provider = provider_wallet(1);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();

    let w = BondWithdrawal {
        version: BOND_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        amount_sat: 4_000,
        nonce: 1,
    };
    let signed = SignedWithdrawal::sign(w, &provider).unwrap();

    let locked_until = 5 + LOCKUP_HEIGHTS;
    assert!(matches!(
        book.withdraw(&signed, locked_until - 1),
        Err(ComputeError::LockupActive)
    ));
    assert_eq!(
        book.withdraw(&signed, locked_until).unwrap(),
        MIN_BOND_SAT - 4_000
    );

    // The same withdrawal cannot be replayed.
    assert!(matches!(
        book.withdraw(&signed, locked_until + 1),
        Err(ComputeError::Replay)
    ));

    // Withdrawing more than the remaining stake is refused.
    let big = BondWithdrawal {
        version: BOND_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        amount_sat: MIN_BOND_SAT,
        nonce: 2,
    };
    assert!(matches!(
        book.withdraw(
            &SignedWithdrawal::sign(big, &provider).unwrap(),
            locked_until + 1
        ),
        Err(ComputeError::InsufficientBond)
    ));

    // The drained bond can no longer back offers.
    let offer = gpu_offer(&provider);
    assert!(matches!(
        book.admit_offer(&offer, 200),
        Err(ComputeError::InsufficientBond)
    ));
}

#[test]
fn a_stranger_cannot_withdraw_a_bond() {
    let provider = provider_wallet(1);
    let stranger = wallet(8);
    let mut book = BondBook::new(NET);
    book.register(&bond(&provider, MIN_BOND_SAT, 5, 1), 10)
        .unwrap();

    let w = BondWithdrawal {
        version: BOND_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        amount_sat: MIN_BOND_SAT,
        nonce: 1,
    };
    assert!(matches!(
        SignedWithdrawal::sign(w.clone(), &stranger),
        Err(ComputeError::WrongProvider)
    ));

    let mut forged = SignedWithdrawal::sign(w, &provider).unwrap();
    forged.withdrawal.amount_sat = 999_999;
    assert!(forged.verify().is_err());
}

#[test]
fn receipts_must_bind_the_assignment_to_count() {
    let requester = wallet(9);
    let provider = provider_wallet(1);
    let other_provider = provider_wallet(2);
    let mut book = BondBook::new(NET);

    let a = assignment(&requester, &provider, 100);
    let r = receipt(&provider, &a, 10, 60);
    book.record_settlement(&r, &a).unwrap();
    assert_eq!(book.score(&provider.address().unwrap()), 10);

    // A receipt over a rival assignment must not raise anyone's score.
    let rival = assignment(&requester, &other_provider, 100);
    assert!(matches!(
        book.record_settlement(&r, &rival),
        Err(ComputeError::BindingMismatch)
    ));
    assert_eq!(book.score(&other_provider.address().unwrap()), 0);

    // Overclaims are refused before they ever reach the book.
    let too_big = ComputeReceipt::new(&a, 11, [4u8; 32], 5, 61, 1);
    assert!(matches!(too_big, Err(ComputeError::Overclaim)));
    assert_eq!(book.score(&provider.address().unwrap()), 10);
}

#[test]
fn timeout_checkpoint_restores_without_rewinding() {
    use srct_compute::TimeoutCheckpoint;
    let provider = wallet(41).address().unwrap();
    let other = wallet(42).address().unwrap();
    let mut book = BondBook::new(NET);
    // Fresh books start at zero; a checkpoint lifts the floor.
    let checkpoint = TimeoutCheckpoint {
        height: 200,
        timeouts: vec![(provider, 3), (other, 1)],
    };
    let bytes = checkpoint.encode();
    assert_eq!(TimeoutCheckpoint::decode(&bytes).unwrap(), checkpoint);
    checkpoint.apply(&mut book).unwrap();
    assert_eq!(book.reputation(&provider).timeouts, 3);
    assert_eq!(book.reputation(&other).timeouts, 1);
    // A newer checkpoint raises the floor; a stale one cannot rewind it.
    let newer = TimeoutCheckpoint {
        height: 300,
        timeouts: vec![(provider, 5)],
    };
    newer.apply(&mut book).unwrap();
    assert_eq!(book.reputation(&provider).timeouts, 5);
    assert_eq!(book.score(&provider), -50);
    let stale = TimeoutCheckpoint {
        height: 100,
        timeouts: vec![(provider, 2)],
    };
    assert!(stale.apply(&mut book).is_err());
    assert_eq!(book.reputation(&provider).timeouts, 5);
    // Tampered and truncated snapshots fail closed.
    let mut bad = bytes.clone();
    bad[0] = 99;
    assert!(TimeoutCheckpoint::decode(&bad).is_err());
    assert!(TimeoutCheckpoint::decode(&bytes[..bytes.len() - 2]).is_err());
}
