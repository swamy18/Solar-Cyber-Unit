//! Acceptance tests for the double ratchet: real wallets, ordered threads,
//! forward secrecy, post-compromise ratchet steps and fail-closed refusals.

use srct_agentnet::mailbox::Mailbox;
use srct_agentnet::message::{thread_id, MessageError, Recipient};
use srct_agentnet::{RatchetSession, SessionSide};
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const ROLE: AgentRole = AgentRole::Machine;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "agentnet-ratchet-test").unwrap()
}

fn agent(w: &Wallet, role: AgentRole) -> AgentId {
    derive_agent_id(NET, role, &w.address().unwrap())
}

fn thread_of(a: &Wallet, b: &Wallet) -> srct_core::hash::Hash {
    thread_id(&agent(a, ROLE), &agent(b, ROLE), 9)
}

fn initiator(alice: &Wallet, bob: &Wallet, thread: srct_core::hash::Hash) -> RatchetSession {
    RatchetSession::initiator(
        alice,
        ROLE,
        NET,
        thread,
        &Recipient::from_wallet(bob, ROLE).unwrap(),
    )
    .unwrap()
}

fn responder(bob: &Wallet, alice: &Wallet, thread: srct_core::hash::Hash) -> RatchetSession {
    RatchetSession::responder(
        bob,
        ROLE,
        NET,
        thread,
        &Recipient::from_wallet(alice, ROLE).unwrap(),
    )
    .unwrap()
}

#[test]
fn a_conversation_round_trips_in_both_directions() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    let m1 = session.send(&alice, b"first message", 100).unwrap();
    assert_eq!(m1.seq, 1);
    assert_eq!(m1.thread, thread);
    assert_eq!(peer.receive(&m1, &bob).unwrap(), b"first message".to_vec());

    let m2 = peer.send(&bob, b"reply from bob", 100).unwrap();
    assert_eq!(m2.seq, 1);
    assert_eq!(
        session.receive(&m2, &alice).unwrap(),
        b"reply from bob".to_vec()
    );

    let m3 = session.send(&alice, b"second alice message", 100).unwrap();
    assert_eq!(m3.seq, 2);
    assert_eq!(
        peer.receive(&m3, &bob).unwrap(),
        b"second alice message".to_vec()
    );
}

#[test]
fn the_responder_cannot_send_before_receiving() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut peer = responder(&bob, &alice, thread);
    let err = peer.send(&bob, b"too early", 100).unwrap_err();
    assert!(matches!(err, MessageError::RatchetState(_)));
}

#[test]
fn an_old_chain_state_cannot_decrypt_a_later_message() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    let m1 = session.send(&alice, b"message one", 100).unwrap();
    peer.receive(&m1, &bob).unwrap();

    // A snapshot of the peer's state right after the first message.
    let mut stale_peer = peer.clone();

    let m2 = session.send(&alice, b"message two", 100).unwrap();
    peer.receive(&m2, &bob).unwrap();
    let m3 = session.send(&alice, b"message three", 100).unwrap();

    // The snapshot still expects sequence 2 under the chain it held then.
    // The refusal is at the sequence guard; the chain-key property itself is
    // pinned by the unit test below (`an_old_chain_key_cannot_derive_a_...`).
    let err = stale_peer.receive(&m3, &bob);
    assert!(err.is_err(), "stale chain must not accept later messages");
    assert!(matches!(err.unwrap_err(), MessageError::RatchetState(_)));
}

#[test]
fn every_direction_change_rotates_the_ratchet_key() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    let m1 = session.send(&alice, b"one", 100).unwrap();
    let alice_header_0 = m1.ephemeral_pubkey;
    peer.receive(&m1, &bob).unwrap();

    let m2 = peer.send(&bob, b"two", 100).unwrap();
    let bob_header_1 = m2.ephemeral_pubkey;
    assert_ne!(
        alice_header_0, bob_header_1,
        "the responder must rotate its ratchet key on its first send"
    );
    assert_eq!(session.receive(&m2, &alice).unwrap(), b"two".to_vec());

    let m3 = session.send(&alice, b"three", 100).unwrap();
    let alice_header_2 = m3.ephemeral_pubkey;
    assert_ne!(
        alice_header_0, alice_header_2,
        "the initiator must rotate its ratchet key after receiving a step"
    );
    assert_ne!(alice_header_2, bob_header_1);
    assert_eq!(peer.receive(&m3, &bob).unwrap(), b"three".to_vec());
}

#[test]
fn a_sequence_gap_is_refused_and_the_thread_recovers() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    let m1 = session.send(&alice, b"one", 100).unwrap();
    let m2 = session.send(&alice, b"two", 100).unwrap();
    let m3 = session.send(&alice, b"three", 100).unwrap();
    peer.receive(&m1, &bob).unwrap();

    // Skipping m2 must fail...
    let err = peer.receive(&m3, &bob).unwrap_err();
    assert!(matches!(err, MessageError::RatchetState(_)));
    // ...must not advance the chain...
    assert_eq!(peer.next_recv(), 2);
    // ...and the honest m2 must still decrypt afterwards.
    assert_eq!(peer.receive(&m2, &bob).unwrap(), b"two".to_vec());
    assert_eq!(peer.receive(&m3, &bob).unwrap(), b"three".to_vec());
}

#[test]
fn a_replayed_ratchet_message_is_refused() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    let m1 = session.send(&alice, b"one", 100).unwrap();
    assert_eq!(peer.receive(&m1, &bob).unwrap(), b"one".to_vec());
    let err = peer.receive(&m1, &bob).unwrap_err();
    assert!(matches!(err, MessageError::RatchetState(_)));
}

#[test]
fn tampered_ciphertext_does_not_advance_the_chain() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    let m1 = session.send(&alice, b"one", 100).unwrap();
    peer.receive(&m1, &bob).unwrap();
    let m2 = session.send(&alice, b"two", 100).unwrap();

    let mut tampered = m2.clone();
    tampered.ciphertext[0] ^= 0x01;
    // The sender's signature covers the ciphertext, so tampering is caught by
    // verify() before any key is touched.
    let err = peer.receive(&tampered, &bob).unwrap_err();
    assert!(matches!(err, MessageError::BadSignature(_)));
    assert_eq!(peer.next_recv(), 2);

    // The honest message still decrypts: the refusal burned nothing.
    assert_eq!(peer.receive(&m2, &bob).unwrap(), b"two".to_vec());
}

#[test]
fn a_third_party_cannot_hijack_a_session() {
    let alice = wallet(1);
    let bob = wallet(2);
    let carol = wallet(3);
    let thread = thread_of(&alice, &bob);
    let mut peer = responder(&bob, &alice, thread);

    // Carol builds her own initiator session to Bob in the same thread id and
    // delivers her handshake first.
    let mut carol_session = initiator(&carol, &bob, thread);
    let intruder = carol_session.send(&carol, b"hello bob", 100).unwrap();

    let err = peer.receive(&intruder, &bob).unwrap_err();
    assert!(
        matches!(err, MessageError::WrongPeer),
        "an unexpected sender must not initialise the session, got {err:?}"
    );

    // The honest handshake still works afterwards.
    let mut session = initiator(&alice, &bob, thread);
    let m1 = session.send(&alice, b"real first message", 100).unwrap();
    assert_eq!(
        peer.receive(&m1, &bob).unwrap(),
        b"real first message".to_vec()
    );
}

#[test]
fn envelopes_from_another_thread_are_refused() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let other_thread = thread_id(&agent(&alice, ROLE), &agent(&bob, ROLE), 77);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, other_thread);

    let m1 = session.send(&alice, b"one", 100).unwrap();
    let err = peer.receive(&m1, &bob).unwrap_err();
    assert!(matches!(err, MessageError::WrongThread));
}

#[test]
fn the_static_key_path_cannot_open_a_ratchet_message() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let m1 = session.send(&alice, b"secret", 100).unwrap();

    // envelope.open derives its key from the recipient's static key plus the
    // header; a ratchet message key comes from the chain instead, so the
    // static path must fail. This is the forward-secrecy property at the API
    // boundary.
    let err = m1.open(&bob).unwrap_err();
    assert!(
        matches!(err, MessageError::Crypto(_)),
        "static decryption must not open ratchet messages, got {err:?}"
    );
}

#[test]
fn ratchet_messages_flow_through_the_mailbox_and_wire() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    let m1 = session.send(&alice, b"through the relay", 100).unwrap();
    let m2 = session.send(&alice, b"and a second one", 100).unwrap();

    // A relay stores the wire bytes without any key.
    let mut mailbox = Mailbox::new(NET, agent(&bob, ROLE));
    mailbox.accept_wire(&m1.encode(), 1).unwrap();
    mailbox.accept_wire(&m2.encode(), 1).unwrap();
    assert_eq!(mailbox.len(), 2);

    // Strict order: the relay's mailbox refuses the stale message too.
    let err = mailbox.accept_wire(&m1.encode(), 1).unwrap_err();
    assert!(matches!(err, srct_agentnet::MailboxError::Replay));

    let drained = mailbox.drain_thread(&thread, 10);
    assert_eq!(drained.len(), 2);
    assert_eq!(
        peer.receive(&drained[0].envelope, &bob).unwrap(),
        b"through the relay"
    );
    assert_eq!(
        peer.receive(&drained[1].envelope, &bob).unwrap(),
        b"and a second one"
    );
}

#[test]
fn a_session_refuses_the_wrong_wallet() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let m1 = session.send(&alice, b"one", 100).unwrap();

    let mut peer = responder(&bob, &alice, thread);
    let err = peer.receive(&m1, &wallet(9)).unwrap_err();
    assert!(matches!(err, MessageError::WrongRecipient));
}

#[test]
fn the_responder_rotates_its_key_even_without_replying() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = thread_of(&alice, &bob);
    let mut session = initiator(&alice, &bob, thread);
    let mut peer = responder(&bob, &alice, thread);

    assert_eq!(peer.side(), SessionSide::Responder);
    let before = peer.local_ratchet();
    let m1 = session.send(&alice, b"one", 100).unwrap();
    peer.receive(&m1, &bob).unwrap();
    let after = peer.local_ratchet();
    assert_ne!(
        before, after,
        "processing the handshake must rotate the responder's ratchet key"
    );
}
