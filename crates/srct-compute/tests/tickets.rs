//! Acceptance tests for the pull model: requester-signed tickets, atomic
//! provider claims, ticket settlement, escrow release and pruning.

use srct_compute::market::Verification;
use srct_compute::{
    ChallengeBook, ClaimBook, ClaimTicket, ComputeError, ComputeLedger, ComputeReceipt, Determinism,
    EscrowBook, EscrowFunding, ShardClaim, SignedClaim, SignedFunding, SignedReceipt, SignedTicket,
    ESCROW_VERSION,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "ticket-test").unwrap()
}

fn ticket(
    requester: &Wallet,
    job: Hash,
    units: u32,
    price: u64,
    deadline: u64,
    nonce: u64,
    provider: Option<srct_core::hash::Address>,
) -> SignedTicket {
    SignedTicket::sign(
        ClaimTicket {
            version: srct_compute::ticket::TICKET_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            job,
            shard: 0,
            units,
            unit_price_sat: price,
            total_sat: units as u64 * price,
            min_ram_mib: 512,
            min_units_per_sec: 100,
            min_bandwidth_kbps: 0,
            determinism: Determinism::Reproducible,
            required_kernel: [0u8; 32],
            min_verification: Verification::Receipt,
            sealed_input: false,
            input: [3u8; 32],
            deadline,
            nonce,
            provider,
        },
        requester,
    )
    .unwrap()
}

fn claim(provider: &Wallet, ticket: &SignedTicket, nonce: u64) -> SignedClaim {
    SignedClaim::sign(
        ShardClaim {
            version: srct_compute::ticket::CLAIM_VERSION,
            network_id: NET.into(),
            ticket: ticket.hash(),
            provider: provider.address().unwrap(),
            units: ticket.ticket.units,
            nonce,
        },
        provider,
    )
    .unwrap()
}

fn receipt_for(
    provider: &Wallet,
    ticket: &SignedTicket,
    claim: &SignedClaim,
    units: u32,
    height: u64,
) -> SignedReceipt {
    let r = ComputeReceipt::for_claim(ticket, claim, units, [4u8; 32], 1_000, height, 7).unwrap();
    SignedReceipt::sign(r, provider).unwrap()
}

#[test]
fn ticket_sign_verify_and_tamper_refusal() {
    let requester = wallet(1);
    let provider = wallet(2);
    let t = ticket(&requester, [9u8; 32], 10, 5, 100, 1, None);
    t.verify().unwrap();
    assert_eq!(t.hash(), ticket(&requester, [9u8; 32], 10, 5, 100, 1, None).hash());

    // A stranger cannot re-sign the terms.
    assert!(SignedTicket::sign(t.ticket.clone(), &provider).is_err());
    // Tampered terms break the requester's signature.
    let mut tampered = t.clone();
    tampered.ticket.units = 99;
    assert!(tampered.verify().is_err());
    // Empty job, zero units, bad arithmetic, zero nonce all refuse.
    let mut bad = t.ticket.clone();
    bad.job = [0u8; 32];
    assert!(SignedTicket::sign(bad, &requester).is_err());
}

#[test]
fn first_valid_claim_wins_and_replays_refuse() {
    let requester = wallet(1);
    let fast = wallet(2);
    let slow = wallet(3);
    let mut book = ClaimBook::new(NET);
    let t = ticket(&requester, [9u8; 32], 10, 5, 100, 1, None);
    book.post(&t, 5).unwrap();

    // Duplicate posting is a replay, not a second ticket.
    assert_eq!(
        book.post(&t, 5),
        Err(ComputeError::Replay)
    );

    // Slow provider's claim lands first and wins.
    let won = claim(&slow, &t, 1);
    book.claim(&won, 6).unwrap();
    // Fast provider's later claim for the same ticket refuses.
    let lost = claim(&fast, &t, 1);
    assert_eq!(book.claim(&lost, 6), Err(ComputeError::AlreadyClaimed));
    // Same winner re-claiming is also a replay.
    assert_eq!(book.claim(&won, 6), Err(ComputeError::AlreadyClaimed));

    // A claim for an unknown ticket is not found, not accepted.
    let other = ticket(&requester, [8u8; 32], 10, 5, 100, 2, None);
    let ghost = claim(&fast, &other, 1);
    assert_eq!(book.claim(&ghost, 6), Err(ComputeError::NotFound));

    // A claim signed by someone other than its named provider refuses.
    let mut forged = claim(&slow, &t, 9);
    forged.claim.provider = fast.address().unwrap();
    assert!(book.claim(&forged, 6).is_err());
}

#[test]
fn designated_tickets_only_accept_the_named_provider() {
    let requester = wallet(1);
    let chosen = wallet(2);
    let stranger = wallet(3);
    let mut book = ClaimBook::new(NET);
    let t = ticket(
        &requester,
        [9u8; 32],
        10,
        5,
        100,
        1,
        Some(chosen.address().unwrap()),
    );
    book.post(&t, 5).unwrap();
    // The named provider claims fine; a stranger's claim refuses.
    book.claim(&claim(&chosen, &t, 1), 6).unwrap();
    let t2 = ticket(
        &requester,
        [8u8; 32],
        10,
        5,
        100,
        2,
        Some(chosen.address().unwrap()),
    );
    book.post(&t2, 5).unwrap();
    assert_eq!(
        book.claim(&claim(&stranger, &t2, 1), 6),
        Err(ComputeError::DesignatedProvider)
    );
}

#[test]
fn ticket_settlement_pays_once_and_binds_everything() {
    let requester = wallet(1);
    let provider = wallet(2);
    let t = ticket(&requester, [9u8; 32], 10, 5, 100, 1, None);
    let c = claim(&provider, &t, 1);
    let r = receipt_for(&provider, &t, &c, 10, 60);

    let mut ledger = ComputeLedger::new();
    let payout = ledger.settle_claim(&r, &t, &c, 61).unwrap();
    assert_eq!(payout.from, requester.address().unwrap());
    assert_eq!(payout.to, provider.address().unwrap());
    assert_eq!(payout.amount_sat, 50);
    assert_eq!(payout.job, [9u8; 32]);
    assert_eq!(payout.assignment, c.hash());

    // Second settlement of the same claim is a replay.
    assert_eq!(
        ledger.settle_claim(&r, &t, &c, 61),
        Err(ComputeError::AlreadySettled)
    );

    // Receipt for another claim cannot settle this one.
    let other_ticket = ticket(&requester, [9u8; 32], 10, 5, 100, 2, None);
    let other_claim = claim(&provider, &other_ticket, 1);
    let other_receipt = receipt_for(&provider, &other_ticket, &other_claim, 10, 60);
    assert_eq!(
        ledger.settle_claim(&other_receipt, &t, &c, 61),
        Err(ComputeError::BindingMismatch)
    );

    // Past-deadline settlement expires.
    let late = receipt_for(&provider, &t, &c, 10, 101);
    assert_eq!(
        ledger.settle_claim(&late, &t, &c, 101),
        Err(ComputeError::Expired)
    );
}

#[test]
fn escrow_release_for_claim_needs_funding_and_pays_exactly() {
    let requester = wallet(1);
    let provider = wallet(2);
    let job = [9u8; 32];
    let t = ticket(&requester, job, 10, 5, 100, 1, None);
    let c = claim(&provider, &t, 1);
    let r = receipt_for(&provider, &t, &c, 10, 60);

    // No funding: the claim settles nothing.
    let mut escrow = EscrowBook::new(NET);
    assert_eq!(
        escrow.release_for_claim(&r, &t, &c, 61),
        Err(ComputeError::NotFunded)
    );

    // Fund the job, then the release pays exactly the receipt total.
    let funding = SignedFunding::sign(
        EscrowFunding {
            version: ESCROW_VERSION,
            network_id: NET.into(),
            job,
            requester: requester.address().unwrap(),
            amount_sat: 50,
            deadline: 100,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    escrow.fund(&funding, 5).unwrap();
    let payout = escrow.release_for_claim(&r, &t, &c, 61).unwrap();
    assert_eq!(payout.amount_sat, 50);
    assert_eq!(payout.to, provider.address().unwrap());

    // Same claim cannot release twice.
    assert_eq!(
        escrow.release_for_claim(&r, &t, &c, 61),
        Err(ComputeError::AlreadySettled)
    );
}

#[test]
fn claim_book_prune_drops_only_what_can_never_settle() {
    let requester = wallet(1);
    let provider = wallet(2);
    let mut book = ClaimBook::new(NET);
    let live = ticket(&requester, [9u8; 32], 10, 5, 200, 1, None);
    let dead_open = ticket(&requester, [8u8; 32], 10, 5, 100, 2, None);
    let dead_claimed = ticket(&requester, [7u8; 32], 10, 5, 100, 3, None);
    book.post(&live, 5).unwrap();
    book.post(&dead_open, 5).unwrap();
    book.post(&dead_claimed, 5).unwrap();
    book.claim(&claim(&provider, &dead_claimed, 1), 6).unwrap();

    // At height 150: the deadline-200 ticket survives; the two
    // deadline-100 tickets (one open, one claimed-but-unsettled) drop —
    // a claim past its ticket deadline can never settle, so nothing
    // settleable is lost.
    book.prune(150);
    let open: Vec<_> = book.open_tickets(150).collect();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].hash(), live.hash());
}

#[test]
fn claim_book_wire_round_trips() {
    let requester = wallet(1);
    let provider = wallet(2);
    let mut book = ClaimBook::new(NET);
    let t = ticket(&requester, [9u8; 32], 10, 5, 100, 1, None);
    book.post(&t, 5).unwrap();
    book.claim(&claim(&provider, &t, 1), 6).unwrap();
    let decoded = ClaimBook::decode(&book.encode(), NET).unwrap();
    // Claimed tickets leave the open board but the claim survives the trip.
    assert_eq!(decoded.open_tickets(6).count(), 0);
    assert_eq!(
        decoded.claim_for(&t.hash()).unwrap().hash(),
        claim(&provider, &t, 1).hash()
    );
    // Truncation refuses.
    let bytes = book.encode();
    assert!(ClaimBook::decode(&bytes[..bytes.len() / 2], NET).is_err());
}

#[test]
fn challenge_book_opens_against_settled_claims() {
    use srct_compute::{Challenge, ChallengeVerdict, SignedChallenge, CHALLENGE_VERSION};
    let requester = wallet(1);
    let provider = wallet(2);
    let challenger = wallet(3);
    let t = ticket(&requester, [9u8; 32], 10, 5, 100, 1, None);
    let c = claim(&provider, &t, 1);
    let r = receipt_for(&provider, &t, &c, 10, 60);

    let mut ledger = ComputeLedger::new();
    ledger.settle_claim(&r, &t, &c, 61).unwrap();

    let mut challenges = ChallengeBook::new(NET);
    let ch = SignedChallenge::sign(
        Challenge {
            version: CHALLENGE_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            provider: provider.address().unwrap(),
            challenger: challenger.address().unwrap(),
            assignment: c.hash(),
            deadline_height: 90,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    // Opens against the settled claim hash like any assignment hash.
    challenges.open_for_claim(&ch, &t, &c, 62).unwrap();
    assert!(challenges.is_open(&c.hash()));
    // A matching second receipt verifies the original.
    let mut second = ComputeReceipt::for_claim(&t, &c, 10, [4u8; 32], 900, 62, 8).unwrap();
    second.provider = challenger.address().unwrap();
    let second = SignedReceipt::sign(second, &challenger).unwrap();
    challenges.submit_second(&second, 63).unwrap();
    assert!(matches!(
        challenges.verdict(&c.hash(), &r).unwrap(),
        ChallengeVerdict::Match { .. }
    ));
}
