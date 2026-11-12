//! Acceptance tests for compute persistence and gossip: signed-object wire
//! codecs, the append-only restart journal, and the transport-agnostic offer
//! gossip set.

use srct_compute::market::{
    plan_assignments, ComputeJob, ComputeOffer, Verification, JOB_VERSION, OFFER_VERSION,
};
use srct_compute::{
    BondBook, ComputeError, ComputeReceipt, Determinism, DeviceClass, DeviceProfile, EscrowBook,
    EscrowFunding, FlowJournal, GossipSet, ProviderBond, SignedAssignment, SignedBond,
    SignedFunding, SignedJob, SignedOffer, SignedReceipt, BOND_VERSION, ESCROW_VERSION,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const SERVICE: &str = "train.mlp";
const KERNEL: Hash = [7u8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "compute-net-test").unwrap()
}

fn mk_offer(provider: &Wallet, nonce: u64, until: u64) -> SignedOffer {
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
            verification: Verification::Receipt,
            available_from: 0,
            available_until: until,
            nonce,
        },
        provider,
    )
    .unwrap()
}

fn flow() -> (SignedOffer, SignedAssignment, SignedReceipt, Wallet) {
    let provider = wallet(1);
    let requester = wallet(2);
    let offer = mk_offer(&provider, 1, 1_000);
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
            min_verification: Verification::Receipt,
            sealed_input: false,
            input: [3u8; 32],
            deadline: 100,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    let plan = plan_assignments(&job, std::slice::from_ref(&offer), 10, 1).unwrap();
    let assignment = plan.sign(&requester).unwrap().assignments.remove(0);
    let receipt = SignedReceipt::sign(
        ComputeReceipt::new(&assignment, 5, [4u8; 32], 1_000, 20, 1).unwrap(),
        &provider,
    )
    .unwrap();
    (offer, assignment, receipt, requester)
}

#[test]
fn signed_flow_objects_roundtrip() {
    let (offer, assignment, receipt, _) = flow();
    assert_eq!(SignedOffer::decode(&offer.encode()).unwrap(), offer);
    assert_eq!(
        SignedAssignment::decode(&assignment.encode()).unwrap(),
        assignment
    );
    assert_eq!(SignedReceipt::decode(&receipt.encode()).unwrap(), receipt);
    // Truncation and version corruption are refused at decode.
    let encoded = offer.encode();
    assert!(matches!(
        SignedOffer::decode(&encoded[..encoded.len() - 4]),
        Err(ComputeError::Malformed(_))
    ));
    let mut bad = assignment.encode();
    bad[0] = 99;
    assert!(matches!(
        SignedAssignment::decode(&bad),
        Err(ComputeError::Malformed(_))
    ));
}

#[test]
fn journal_appends_only_verified_objects() {
    let (offer, assignment, receipt, _) = flow();
    let mut journal = FlowJournal::new(NET);
    assert_eq!(journal.append_offer(&offer).unwrap(), 0);
    assert_eq!(journal.append_assignment(&assignment).unwrap(), 1);
    assert_eq!(journal.append_receipt(&receipt).unwrap(), 2);
    assert_eq!(journal.len(), 3);
    // A tampered offer is refused before it can pollute history.
    let mut bad = offer.clone();
    bad.offer.unit_price_sat = 1;
    assert!(matches!(
        journal.append_offer(&bad),
        Err(ComputeError::BadSignature(_))
    ));
    // Another network's offer is refused.
    let other = wallet(9);
    let mut inner = mk_offer(&other, 5, 1_000).offer;
    inner.network_id = "srct/other".into();
    let foreign = SignedOffer::sign(inner, &other).unwrap();
    assert_eq!(
        journal.append_offer(&foreign),
        Err(ComputeError::WrongNetwork)
    );
}

#[test]
fn journal_snapshot_restart_replays_identically() {
    let (offer, assignment, receipt, _) = flow();
    let mut journal = FlowJournal::new(NET);
    journal.append_offer(&offer).unwrap();
    journal.append_assignment(&assignment).unwrap();
    journal.append_receipt(&receipt).unwrap();
    let bytes = journal.encode();
    let restored = FlowJournal::decode(&bytes).unwrap();
    let replayed = restored.replay().unwrap();
    assert_eq!(replayed.offers, vec![offer]);
    assert_eq!(replayed.assignments, vec![assignment]);
    assert_eq!(replayed.receipts, vec![receipt]);
    // Truncation and tampering fail the whole restart, not one entry.
    assert!(matches!(
        FlowJournal::decode(&bytes[..bytes.len() - 4]),
        Err(ComputeError::Malformed(_))
    ));
    let mut bad = bytes.clone();
    bad[40] ^= 0x01;
    assert!(FlowJournal::decode(&bad).is_err());
}

#[test]
fn gossip_keeps_live_signed_offers_once() {
    let provider = wallet(1);
    let mut set = GossipSet::new(NET);
    let a = mk_offer(&provider, 1, 1_000);
    let b = mk_offer(&provider, 2, 1_000);
    assert!(set.insert(a.clone(), 10).unwrap());
    assert!(!set.insert(a.clone(), 10).unwrap());
    assert!(set.contains(&a.hash()));
    assert_eq!(set.len(), 1);
    assert!(set.insert(b, 10).unwrap());
    assert_eq!(set.len(), 2);
    // Forged and expired offers are dropped, never stored.
    let mut forged = a.clone();
    forged.offer.unit_price_sat = 1;
    assert!(set.insert(forged, 10).is_err());
    let stale = mk_offer(&provider, 3, 5);
    assert_eq!(set.insert(stale, 10), Err(ComputeError::Expired));
    assert_eq!(set.len(), 2);
}

#[test]
fn gossip_merge_is_order_independent_and_prunes() {
    let p1 = wallet(1);
    let p2 = wallet(2);
    let a = mk_offer(&p1, 1, 1_000);
    let b = mk_offer(&p2, 1, 1_000);
    let c = mk_offer(&p1, 2, 12);
    let mut first = GossipSet::new(NET);
    let mut second = GossipSet::new(NET);
    assert_eq!(first.merge(vec![a.clone(), b.clone(), c.clone()], 10), 3);
    assert_eq!(second.merge(vec![c.clone(), b.clone(), a.clone()], 10), 3);
    assert_eq!(first.len(), second.len());
    // Re-merging adds nothing; a forged batch member is skipped, not fatal.
    let mut forged = a.clone();
    forged.offer.unit_price_sat = 1;
    assert_eq!(first.merge(vec![a, forged, b], 10), 0);
    // Expiry prunes deterministically.
    assert_eq!(first.prune(13), 1);
    assert_eq!(first.len(), 2);
    assert_eq!(first.prune(1_001), 2);
    assert!(first.is_empty());
}

#[test]
fn wire_mutations_never_panic() {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let (offer, assignment, receipt, _) = flow();
    let mut journal = FlowJournal::new(NET);
    journal.append_offer(&offer).unwrap();
    let corpora: Vec<Vec<u8>> = vec![
        offer.encode(),
        assignment.encode(),
        receipt.encode(),
        journal.encode(),
    ];
    let mut rng = StdRng::seed_from_u64(0xbeef);
    for base in &corpora {
        for _ in 0..200 {
            let mut b = base.clone();
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
            let _ = SignedOffer::decode(&b);
            let _ = SignedAssignment::decode(&b);
            let _ = SignedReceipt::decode(&b);
            let _ = FlowJournal::decode(&b);
        }
    }
}

#[test]
fn gossip_refuses_foreign_networks_and_overflow() {
    let provider = wallet(1);
    let mut set = GossipSet::new(NET);
    let mut inner = mk_offer(&provider, 1, 1_000).offer;
    inner.network_id = "srct/other".into();
    let foreign = SignedOffer::sign(inner, &provider).unwrap();
    assert_eq!(set.insert(foreign, 10), Err(ComputeError::WrongNetwork));
    // Fill to the cap with distinct offers, then refuse rather than evict.
    let mut set = GossipSet::new(NET);
    for n in 1..=1_024u64 {
        assert!(set.insert(mk_offer(&provider, n, 1_000_000), 10).unwrap());
    }
    assert!(set
        .insert(mk_offer(&provider, 1_025, 1_000_000), 10)
        .is_err());
}

#[test]
fn journal_persists_bonds_and_escrow_fundings() {
    let provider = wallet(1);
    let requester = wallet(2);
    let bond = SignedBond::sign(
        ProviderBond {
            version: BOND_VERSION,
            network_id: NET.into(),
            provider: provider.address().unwrap(),
            amount_sat: 50_000,
            registered_height: 5,
            nonce: 1,
        },
        &provider,
    )
    .unwrap();
    let job = [9u8; 32];
    let funding = SignedFunding::sign(
        EscrowFunding {
            version: ESCROW_VERSION,
            network_id: NET.into(),
            job,
            requester: requester.address().unwrap(),
            amount_sat: 100,
            deadline: 100,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();

    let mut journal = FlowJournal::new(NET);
    assert_eq!(journal.append_bond(&bond).unwrap(), 0);
    assert_eq!(journal.append_funding(&funding).unwrap(), 1);
    let bytes = journal.encode();
    let replayed = FlowJournal::decode(&bytes).unwrap().replay().unwrap();
    assert_eq!(replayed.bonds, vec![bond.clone()]);
    assert_eq!(replayed.fundings, vec![funding.clone()]);

    // A restarted node rebuilds the same bond and escrow state.
    let mut bonds = BondBook::new(NET);
    for b in &replayed.bonds {
        bonds.register(b, b.bond.registered_height).unwrap();
    }
    assert_eq!(
        bonds.bond(&provider.address().unwrap()).unwrap().amount_sat,
        50_000
    );
    let mut escrow = EscrowBook::new(NET);
    for f in &replayed.fundings {
        escrow.restore(f).unwrap();
    }
    assert_eq!(escrow.remaining_sat(&job), 100);

    // A foreign-network bond is refused before it can enter history.
    let mut foreign = bond.clone();
    foreign.bond.network_id = "srct/other".into();
    let foreign = SignedBond::sign(foreign.bond, &provider).unwrap();
    assert_eq!(
        journal.append_bond(&foreign),
        Err(ComputeError::WrongNetwork)
    );

    // A snapshot whose network disagrees with its entries is a fork.
    let mut forked = bytes.clone();
    forked[3..3 + NET.len()].copy_from_slice(b"srct/otherxx");
    assert!(FlowJournal::decode(&forked).is_err());

    // Tampering with a bond entry fails the whole restart.
    let mut bad = bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(FlowJournal::decode(&bad).is_err());
}
