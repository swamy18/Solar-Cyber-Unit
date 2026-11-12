//! Acceptance tests for sealed-sender messaging: hidden senders, recipient-side
//! verification, replay guards shared with the normal path, and snapshots.

use srct_agentnet::mailbox::Mailbox;
use srct_agentnet::message::{thread_id, MessageEnvelope, MessageError, Recipient};
use srct_agentnet::sealed::SealedEnvelope;
use srct_agentnet::MailboxError;
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const ROLE: AgentRole = AgentRole::Machine;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "sealed-test").unwrap()
}

fn agent(w: &Wallet) -> AgentId {
    derive_agent_id(NET, ROLE, &w.address().unwrap())
}

fn conversation(a: &Wallet, b: &Wallet) -> Hash {
    thread_id(&agent(a), &agent(b), 7)
}

fn seal(from: &Wallet, to: &Wallet, thread: Hash, seq: u64, text: &[u8]) -> SealedEnvelope {
    SealedEnvelope::seal(
        from,
        ROLE,
        NET,
        thread,
        seq,
        &Recipient::from_wallet(to, ROLE).unwrap(),
        text,
        100,
    )
    .unwrap()
}

#[test]
fn sealed_envelope_hides_the_sender_on_the_wire() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = conversation(&alice, &bob);
    let envelope = seal(&alice, &bob, thread, 1, b"quiet hello");
    let wire = envelope.encode();
    // The sender's address and agent id appear nowhere on the wire.
    let sender_addr = alice.address().unwrap();
    assert!(!wire
        .windows(20)
        .any(|w| w == sender_addr.as_slice() || w == agent(&alice).as_slice()));
    // Structure decodes; the recipient is still named (routing needs it).
    let back = SealedEnvelope::decode(&wire).unwrap();
    assert_eq!(back.recipient_agent, agent(&bob));
    assert_eq!(back.thread, thread);
    // The recipient learns the sender and the body.
    let (sender, body) = back.open(&bob).unwrap();
    assert_eq!(sender, agent(&alice));
    assert_eq!(body, b"quiet hello");
}

#[test]
fn only_the_named_recipient_opens() {
    let alice = wallet(3);
    let bob = wallet(4);
    let carol = wallet(5);
    let envelope = seal(&alice, &bob, conversation(&alice, &bob), 1, b"x");
    assert_eq!(envelope.open(&carol), Err(MessageError::WrongRecipient));
    // A stranger's wallet cannot open either.
    assert!(envelope.open(&wallet(6)).is_err());
}

#[test]
fn tampered_sealed_boxes_fail() {
    let alice = wallet(7);
    let bob = wallet(8);
    let mut wire = seal(&alice, &bob, conversation(&alice, &bob), 1, b"authentic").encode();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let decoded = SealedEnvelope::decode(&wire).unwrap();
    assert!(decoded.open(&bob).is_err());
    // Truncated and version-corrupted wires fail at structure level.
    assert!(SealedEnvelope::decode(&wire[..wire.len() - 4]).is_err());
    let mut bad = wire.clone();
    bad[0] = 99;
    assert!(SealedEnvelope::decode(&bad).is_err());
}

#[test]
fn sealed_mailbox_shares_guards_with_the_normal_path() {
    let alice = wallet(9);
    let bob = wallet(10);
    let thread = conversation(&alice, &bob);
    let mut mailbox = Mailbox::new(NET, agent(&bob));
    // A relay cannot accept sealed bytes: no key, no verification.
    let wire = seal(&alice, &bob, thread, 1, b"one").encode();
    assert!(mailbox.accept_wire(&wire, 5).is_err());
    // The owner accepts with the wallet; sender is revealed to them.
    let (sender, id) = mailbox.accept_sealed(&wire, &bob, 5).unwrap();
    assert_eq!(sender, agent(&alice));
    assert!(mailbox.contains(&id));
    assert_eq!(mailbox.len(), 1);
    // Exact replay is refused, and the normal path shares the sequence:
    // seq 1 from the same sender is consumed no matter the envelope kind.
    assert_eq!(
        mailbox.accept_sealed(&wire, &bob, 5),
        Err(MailboxError::Replay)
    );
    let normal = MessageEnvelope::seal(
        &alice,
        ROLE,
        NET,
        thread,
        1,
        &Recipient::from_wallet(&bob, ROLE).unwrap(),
        b"one-again",
        100,
    )
    .unwrap();
    assert_eq!(mailbox.accept(normal, 5), Err(MailboxError::Replay));
    // The next sequence works on both paths.
    mailbox
        .accept_sealed(&seal(&alice, &bob, thread, 2, b"two").encode(), &bob, 5)
        .unwrap();
    assert_eq!(mailbox.len(), 2);
    assert_eq!(mailbox.len_thread(&thread), 2);
    // Wrong-network and wrong-recipient sealed mail is refused unsigned-blind.
    let mut other = Mailbox::new("srct/other", agent(&bob));
    assert!(other.accept_sealed(&wire, &bob, 5).is_err());
}

#[test]
fn sealed_snapshot_replays_guards_without_the_key() {
    let alice = wallet(11);
    let bob = wallet(12);
    let thread = conversation(&alice, &bob);
    let mut mailbox = Mailbox::new(NET, agent(&bob));
    mailbox
        .accept_sealed(&seal(&alice, &bob, thread, 1, b"one").encode(), &bob, 5)
        .unwrap();
    let bytes = mailbox.encode();
    let mut restored = Mailbox::decode(&bytes).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored.sealed_len(), 1);
    // Guards survived: the same bytes cannot be accepted again.
    assert_eq!(
        restored.accept_sealed(&seal(&alice, &bob, thread, 1, b"one").encode(), &bob, 5),
        Err(MailboxError::Replay)
    );
    // ...but the next sequence is accepted, and the body still decrypts.
    restored
        .accept_sealed(&seal(&alice, &bob, thread, 2, b"two").encode(), &bob, 6)
        .unwrap();
    let drained = restored.drain_sealed_thread(&thread, 10);
    assert_eq!(drained.len(), 2);
    let (sender, _) = drained[0].envelope.open(&bob).unwrap();
    assert_eq!(sender, agent(&alice));
    // Tampered snapshots fail closed.
    let mut bad = bytes.clone();
    bad[20] ^= 0x01;
    assert!(Mailbox::decode(&bad).is_err());
}
