//! Acceptance tests for the agent messaging core: real wallets, ECDH + AEAD
//! envelopes, hybrid signatures, and a replay-safe mailbox.

use srct_agentnet::mailbox::Mailbox;
use srct_agentnet::message::{
    thread_id, MessageEnvelope, MessageError, Recipient, MAX_PLAINTEXT, MESSAGE_VERSION,
};
use srct_agentnet::MailboxError;
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::hash::Hash;
use srct_core::l2::Auth;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const ROLE: AgentRole = AgentRole::Machine;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "agentnet-test").unwrap()
}

fn agent(w: &Wallet, role: AgentRole) -> AgentId {
    derive_agent_id(NET, role, &w.address().unwrap())
}

fn conversation(a: &Wallet, b: &Wallet) -> Hash {
    thread_id(&agent(a, ROLE), &agent(b, ROLE), 7)
}

fn seal(
    from: &Wallet,
    to: &Wallet,
    thread: Hash,
    seq: u64,
    text: &[u8],
    expires_height: u64,
) -> MessageEnvelope {
    MessageEnvelope::seal(
        from,
        ROLE,
        NET,
        thread,
        seq,
        &Recipient::from_wallet(to, ROLE).unwrap(),
        text,
        expires_height,
    )
    .unwrap()
}

#[test]
fn a_hybrid_wallet_can_seal_and_open() {
    let alice = wallet(1);
    let bob = wallet(2);
    let thread = conversation(&alice, &bob);
    let envelope = seal(&alice, &bob, thread, 1, b"hello agent", 100);

    assert_eq!(envelope.version, MESSAGE_VERSION);
    assert_eq!(envelope.sender_address, alice.address().unwrap());
    assert_eq!(envelope.recipient_address, bob.address().unwrap());
    assert_eq!(envelope.sender_agent, agent(&alice, ROLE));
    assert_eq!(envelope.recipient_agent, agent(&bob, ROLE));
    assert_ne!(envelope.ciphertext, b"hello agent");
    envelope.verify().unwrap();
    assert_eq!(envelope.open(&bob).unwrap(), b"hello agent");
}

#[test]
fn only_the_named_recipient_can_open() {
    let alice = wallet(3);
    let bob = wallet(4);
    let carol = wallet(5);
    let envelope = seal(&alice, &bob, conversation(&alice, &bob), 1, b"secret", 100);

    assert_eq!(envelope.open(&carol), Err(MessageError::WrongRecipient));
}

#[test]
fn a_recipient_with_mismatched_keys_is_refused() {
    let alice = wallet(6);
    let bob = wallet(7);
    let carol = wallet(8);
    let mut keys = Auth::keys_for(&bob).unwrap();
    // Swap the ECDSA component to Carol's key. The address no longer matches
    // the encryption key, so sealing must refuse instead of producing a
    // message labeled for Bob that Bob cannot read.
    let carol_keys = Auth::keys_for(&carol).unwrap();
    keys.components[0] = carol_keys.components[0].clone();
    let recipient = Recipient {
        address: bob.address().unwrap(),
        role: ROLE,
        keys,
    };
    let err = MessageEnvelope::seal(
        &alice,
        ROLE,
        NET,
        conversation(&alice, &bob),
        1,
        &recipient,
        b"hi",
        100,
    )
    .unwrap_err();
    assert!(matches!(err, MessageError::BadKey(_)), "got {err:?}");
}

#[test]
fn tampered_ciphertext_and_metadata_are_refused() {
    let alice = wallet(9);
    let bob = wallet(10);
    let thread = conversation(&alice, &bob);

    let mut envelope = seal(&alice, &bob, thread, 1, b"authentic", 100);
    envelope.ciphertext[0] ^= 0x01;
    assert!(matches!(
        envelope.verify(),
        Err(MessageError::BadSignature(_))
    ));

    let mut envelope = seal(&alice, &bob, thread, 1, b"authentic", 100);
    envelope.thread = [0xAA; 32];
    assert!(matches!(
        envelope.verify(),
        Err(MessageError::BadSignature(_))
    ));

    let mut envelope = seal(&alice, &bob, thread, 1, b"authentic", 100);
    envelope.seq = 2;
    assert!(matches!(
        envelope.verify(),
        Err(MessageError::BadSignature(_))
    ));

    let mut envelope = seal(&alice, &bob, thread, 1, b"authentic", 100);
    envelope.expires_height += 1;
    assert!(matches!(
        envelope.verify(),
        Err(MessageError::BadSignature(_))
    ));
}

#[test]
fn identity_and_network_binding_are_enforced() {
    let alice = wallet(11);
    let bob = wallet(12);
    let carol = wallet(13);

    // A relay cannot re-home the recipient while keeping the signature.
    let mut envelope = seal(&alice, &bob, conversation(&alice, &bob), 1, b"x", 100);
    envelope.recipient_address = carol.address().unwrap();
    assert!(matches!(envelope.verify(), Err(MessageError::Malformed(_))));

    // Changing only the claimed network breaks the derived sender identity.
    let mut envelope = seal(&alice, &bob, conversation(&alice, &bob), 1, b"x", 100);
    envelope.network_id = "srct/mini".into();
    assert!(matches!(envelope.verify(), Err(MessageError::Malformed(_))));

    // A key bundle that is not the named sender cannot verify.
    let mut envelope = seal(&alice, &bob, conversation(&alice, &bob), 1, b"x", 100);
    envelope.keys = Auth::keys_for(&carol).unwrap();
    envelope.sigs = Auth::sign(&carol, &envelope.signing_hash()).unwrap().sigs;
    assert!(matches!(
        envelope.verify(),
        Err(MessageError::BadSignature(_))
    ));
}

#[test]
fn wire_codec_round_trips_and_is_strict() {
    let alice = wallet(14);
    let bob = wallet(15);
    let envelope = seal(&alice, &bob, conversation(&alice, &bob), 1, b"wire", 100);
    let wire = envelope.encode();
    let decoded = MessageEnvelope::decode(&wire).unwrap();
    assert_eq!(decoded, envelope);

    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(MessageEnvelope::decode(&trailing).is_err());

    let truncated = &wire[..wire.len() - 1];
    assert!(MessageEnvelope::decode(truncated).is_err());

    let mut bad_version = envelope.clone();
    bad_version.version = 2;
    assert!(matches!(
        MessageEnvelope::decode(&bad_version.encode()),
        Err(MessageError::UnsupportedVersion(2))
    ));
}

#[test]
fn malformed_and_oversized_messages_are_refused() {
    let alice = wallet(16);
    let bob = wallet(17);
    let thread = conversation(&alice, &bob);
    let recipient = Recipient::from_wallet(&bob, ROLE).unwrap();

    let err =
        MessageEnvelope::seal(&alice, ROLE, NET, thread, 0, &recipient, b"x", 100).unwrap_err();
    assert_eq!(err, MessageError::InvalidSequence);

    let too_big = vec![0u8; MAX_PLAINTEXT + 1];
    let err =
        MessageEnvelope::seal(&alice, ROLE, NET, thread, 1, &recipient, &too_big, 100).unwrap_err();
    assert_eq!(err, MessageError::TooLarge);

    let err =
        MessageEnvelope::seal(&alice, ROLE, "", thread, 1, &recipient, b"x", 100).unwrap_err();
    assert!(matches!(err, MessageError::Malformed(_)));
}

#[test]
fn mailbox_stores_without_keys_and_orders_by_sequence() {
    let alice = wallet(18);
    let bob = wallet(19);
    let thread = conversation(&alice, &bob);
    let mut mailbox = Mailbox::new(NET, agent(&bob, ROLE));

    let first = seal(&alice, &bob, thread, 1, b"one", 100);
    let second = seal(&alice, &bob, thread, 2, b"two", 100);
    // A mailbox holds ciphertext only; it never needs Bob's private key.
    mailbox.accept(first, 5).unwrap();
    mailbox.accept(second, 5).unwrap();

    assert_eq!(mailbox.len(), 2);
    assert_eq!(mailbox.len_thread(&thread), 2);
    let messages = mailbox.thread(&thread);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].envelope.seq, 1);
    assert_eq!(messages[1].envelope.seq, 2);
    assert_eq!(messages[0].envelope.open(&bob).unwrap(), b"one");
}

#[test]
fn mailbox_refuses_replays_and_stale_sequences() {
    let alice = wallet(20);
    let bob = wallet(21);
    let thread = conversation(&alice, &bob);
    let mut mailbox = Mailbox::new(NET, agent(&bob, ROLE));

    let first = seal(&alice, &bob, thread, 2, b"two", 100);
    let id = mailbox.accept(first.clone(), 5).unwrap();
    assert!(mailbox.contains(&id));
    assert_eq!(mailbox.accept(first, 5), Err(MailboxError::Replay));

    // A re-signed envelope reusing an accepted sequence is still a replay.
    let same_seq = seal(&alice, &bob, thread, 2, b"different", 100);
    assert_eq!(mailbox.accept(same_seq, 5), Err(MailboxError::Replay));

    // Older sequences can never be inserted behind a newer one.
    let old = seal(&alice, &bob, thread, 1, b"old", 100);
    assert_eq!(mailbox.accept(old, 5), Err(MailboxError::Replay));

    let next = seal(&alice, &bob, thread, 3, b"three", 100);
    mailbox.accept(next, 5).unwrap();
    assert_eq!(mailbox.last_seq(&thread, &agent(&alice, ROLE)), Some(3));
}

#[test]
fn mailbox_refuses_wrong_network_and_wrong_recipient() {
    let alice = wallet(22);
    let bob = wallet(23);
    let carol = wallet(24);
    let mut mailbox = Mailbox::new(NET, agent(&bob, ROLE));

    let for_carol = seal(&alice, &carol, conversation(&alice, &carol), 1, b"x", 100);
    assert_eq!(
        mailbox.accept(for_carol, 5),
        Err(MailboxError::WrongRecipient)
    );

    let other_network = MessageEnvelope::seal(
        &alice,
        ROLE,
        "srct/mini",
        thread_id(
            &derive_agent_id("srct/mini", ROLE, &alice.address().unwrap()),
            &derive_agent_id("srct/mini", ROLE, &bob.address().unwrap()),
            7,
        ),
        1,
        &Recipient::from_wallet(&bob, ROLE).unwrap(),
        b"x",
        100,
    )
    .unwrap();
    assert_eq!(
        mailbox.accept(other_network, 5),
        Err(MailboxError::WrongNetwork)
    );
}

#[test]
fn mailbox_enforces_expiry_and_prunes_it() {
    let alice = wallet(25);
    let bob = wallet(26);
    let thread = conversation(&alice, &bob);
    let mut mailbox = Mailbox::new(NET, agent(&bob, ROLE));

    let last_valid = seal(&alice, &bob, thread, 1, b"x", 10);
    mailbox.accept(last_valid, 10).unwrap();
    let expired = seal(&alice, &bob, thread, 2, b"y", 10);
    assert_eq!(mailbox.accept(expired, 11), Err(MailboxError::Expired));

    assert_eq!(mailbox.prune_expired(11), 1);
    assert_eq!(mailbox.len(), 0);
    assert_eq!(mailbox.len_thread(&thread), 0);
}

#[test]
fn mailbox_caps_fail_closed_and_expired_mail_does_not_count() {
    let alice = wallet(27);
    let bob = wallet(28);
    let thread = conversation(&alice, &bob);
    let owner = agent(&bob, ROLE);

    // Total cap.
    let mut total = Mailbox::with_limits(NET, owner, 1, 4);
    total
        .accept(seal(&alice, &bob, thread, 1, b"a", 100), 5)
        .unwrap();
    assert_eq!(
        total.accept(seal(&alice, &bob, thread, 2, b"b", 100), 5),
        Err(MailboxError::Full)
    );

    // Per-thread cap.
    let mut per_thread = Mailbox::with_limits(NET, owner, 4, 1);
    per_thread
        .accept(seal(&alice, &bob, thread, 1, b"a", 100), 5)
        .unwrap();
    assert_eq!(
        per_thread.accept(seal(&alice, &bob, thread, 2, b"b", 100), 5),
        Err(MailboxError::ThreadFull)
    );

    // Expired entries are pruned before the cap is judged, so a fresh message
    // is accepted even though the mailbox was full a moment ago.
    let mut expiring = Mailbox::with_limits(NET, owner, 1, 4);
    expiring
        .accept(seal(&alice, &bob, thread, 1, b"old", 10), 5)
        .unwrap();
    expiring
        .accept(seal(&alice, &bob, thread, 2, b"new", 100), 11)
        .unwrap();
    assert_eq!(expiring.len(), 1);
    assert_eq!(expiring.messages()[0].envelope.seq, 2);
}

#[test]
fn draining_keeps_replay_guards() {
    let alice = wallet(29);
    let bob = wallet(30);
    let thread = conversation(&alice, &bob);
    let mut mailbox = Mailbox::new(NET, agent(&bob, ROLE));

    let first = seal(&alice, &bob, thread, 1, b"one", 100);
    let second = seal(&alice, &bob, thread, 2, b"two", 100);
    mailbox.accept(first.clone(), 5).unwrap();
    mailbox.accept(second, 5).unwrap();

    let drained = mailbox.drain_thread(&thread, 1);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].envelope.seq, 1);
    assert_eq!(mailbox.len_thread(&thread), 1);

    // The drained message cannot be pushed back in.
    assert_eq!(mailbox.accept(first, 5), Err(MailboxError::Replay));

    let third = seal(&alice, &bob, thread, 3, b"three", 100);
    mailbox.accept(third, 5).unwrap();
    assert_eq!(mailbox.drain_thread(&thread, 10).len(), 2);
    assert!(mailbox.is_empty());
}

#[test]
fn mailbox_accepts_wire_and_rejects_a_duplicate_wire() {
    let alice = wallet(31);
    let bob = wallet(32);
    let thread = conversation(&alice, &bob);
    let mut mailbox = Mailbox::new(NET, agent(&bob, ROLE));
    let wire = seal(&alice, &bob, thread, 1, b"wire", 100).encode();

    mailbox.accept_wire(&wire, 5).unwrap();
    assert_eq!(mailbox.accept_wire(&wire, 5), Err(MailboxError::Replay));

    let mut tampered = wire;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(mailbox.accept_wire(&tampered, 5).is_err());
}
