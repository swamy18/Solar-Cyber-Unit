//! Acceptance tests for sender-key groups: membership, per-sender forward
//! secrecy, removal with epoch rotation, and wire codecs.

use srct_agentnet::groups::{GroupMessage, GroupSession, GroupSync};
use srct_agentnet::GroupError;
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const ROLE: AgentRole = AgentRole::Machine;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "group-test").unwrap()
}

fn agent(w: &Wallet) -> AgentId {
    derive_agent_id(NET, ROLE, &w.address().unwrap())
}

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn three() -> (Wallet, Wallet, Wallet) {
    (wallet(21), wallet(22), wallet(23))
}

#[test]
fn group_round_trips_both_directions() {
    let (alice, bob, _) = three();
    let (a, b) = (agent(&alice), agent(&bob));
    let mut ga = GroupSession::create(NET, a, seed(1), 7);
    let sync = ga.add_member(&a, b, seed(2)).unwrap();
    let mut gb = GroupSession::join(NET, &sync, b).unwrap();
    assert_eq!(ga.group_id(), gb.group_id());
    assert_eq!(ga.members(), gb.members());
    let m1 = ga
        .encrypt(&alice, ROLE, &alice.address().unwrap(), b"hello group")
        .unwrap();
    assert_eq!(
        gb.decrypt(&GroupMessage::decode(&m1.encode(), NET).unwrap())
            .unwrap(),
        b"hello group"
    );
    let m2 = gb
        .encrypt(&bob, ROLE, &bob.address().unwrap(), b"hi alice")
        .unwrap();
    assert_eq!(ga.decrypt(&m2).unwrap(), b"hi alice");
    // Sequences advance per sender; replays are refused.
    assert_eq!(ga.decrypt(&m2), Err(GroupError::Replay));
    assert_eq!(gb.decrypt(&m1), Err(GroupError::Replay));
}

#[test]
fn non_members_cannot_write_or_read() {
    let (alice, bob, carol) = three();
    let (a, b) = (agent(&alice), agent(&bob));
    let mut ga = GroupSession::create(NET, a, seed(1), 7);
    let sync = ga.add_member(&a, b, seed(2)).unwrap();
    let mut gb = GroupSession::join(NET, &sync, b).unwrap();
    // Carol was never admitted: she cannot join and cannot read.
    assert!(GroupSession::join(NET, &sync, agent(&carol)).is_err());
    let m = ga
        .encrypt(&alice, ROLE, &alice.address().unwrap(), b"secret")
        .unwrap();
    let mut gc = GroupSession::create(NET, agent(&carol), seed(9), 99);
    let cmsg = gc
        .encrypt(&carol, ROLE, &carol.address().unwrap(), b"intruder")
        .unwrap();
    // A stranger's message names the wrong group for this session...
    assert!(matches!(
        gb.decrypt(&cmsg),
        Err(GroupError::UnknownGroup) | Err(GroupError::NotMember)
    ));
    // ...and a forged sender inside the right group fails the signature.
    let mut forged = m.clone();
    forged.sender = agent(&carol);
    assert!(gb.decrypt(&forged).is_err());
    let _ = gb;
}

#[test]
fn removal_rotates_everything_and_old_epochs_fail_closed() {
    let (alice, bob, carol) = three();
    let (a, b, c) = (agent(&alice), agent(&bob), agent(&carol));
    let mut ga = GroupSession::create(NET, a, seed(1), 7);
    ga.add_member(&a, b, seed(2)).unwrap();
    let sync = ga.add_member(&a, c, seed(3)).unwrap();
    let mut gb = GroupSession::join(NET, &sync, b).unwrap();
    let mut gc = GroupSession::join(NET, &sync, c).unwrap();
    assert_eq!(ga.epoch(), 0);
    // Bob speaks at epoch 0; everyone reads.
    let m0 = gb
        .encrypt(&bob, ROLE, &bob.address().unwrap(), b"before")
        .unwrap();
    assert_eq!(ga.decrypt(&m0).unwrap(), b"before");
    assert_eq!(gc.decrypt(&m0).unwrap(), b"before");
    // Alice removes Bob: epoch bumps, survivors get the new sync.
    let sync1 = ga.remove_member(&a, &b, || seed(42)).unwrap();
    assert_eq!(ga.epoch(), 1);
    gc.sync_from_creator(&sync1).unwrap();
    assert_eq!(gc.epoch(), 1);
    // Bob's epoch-0 state decrypts nothing new: his next message is stale.
    let stale = gb
        .encrypt(&bob, ROLE, &bob.address().unwrap(), b"after")
        .unwrap();
    assert_eq!(ga.decrypt(&stale), Err(GroupError::BadEpoch));
    assert_eq!(gc.decrypt(&stale), Err(GroupError::BadEpoch));
    // Survivors continue at epoch 1.
    let m1 = ga
        .encrypt(&alice, ROLE, &alice.address().unwrap(), b"rotated")
        .unwrap();
    assert_eq!(gc.decrypt(&m1).unwrap(), b"rotated");
    // Sync rules: stale refused, duplicate refused, foreign refused.
    assert_eq!(gc.sync_from_creator(&sync1), Err(GroupError::Replay));
    assert_eq!(gc.sync_from_creator(&sync), Err(GroupError::BadEpoch));
    let mut foreign: GroupSync = sync1.clone();
    foreign.group = [9u8; 32];
    assert_eq!(
        gc.sync_from_creator(&foreign),
        Err(GroupError::UnknownGroup)
    );
    // Only the creator manages membership.
    assert!(ga.add_member(&b, c, seed(5)).is_err());
    assert!(ga.remove_member(&b, &c, || seed(5)).is_err());
    assert!(ga.remove_member(&a, &a, || seed(5)).is_err());
}

#[test]
fn group_wire_codec_is_strict() {
    let (alice, bob, _) = three();
    let (a, b) = (agent(&alice), agent(&bob));
    let mut ga = GroupSession::create(NET, a, seed(1), 7);
    let sync = ga.add_member(&a, b, seed(2)).unwrap();
    let mut gb = GroupSession::join(NET, &sync, b).unwrap();
    let m = ga
        .encrypt(&alice, ROLE, &alice.address().unwrap(), b"codec")
        .unwrap();
    assert_eq!(GroupMessage::decode(&m.encode(), NET).unwrap(), m);
    assert!(gb.decrypt(&m).is_ok());
    // Version corruption and truncation fail at structure level...
    let mut bad = m.encode();
    bad[0] = 99;
    assert!(GroupMessage::decode(&bad, NET).is_err());
    assert!(GroupMessage::decode(&m.encode()[..20], NET).is_err());
    // ...while a flipped ciphertext byte fails the signature check.
    let mut tampered = m.encode();
    tampered[120] ^= 0x01;
    assert!(GroupMessage::decode(&tampered, NET).is_err());
    // A foreign network fails the binding.
    assert!(GroupMessage::decode(&m.encode(), "srct/other").is_err());
    let mut bad_sync = sync.encode();
    bad_sync[0] = 99;
    assert!(GroupSync::decode(&bad_sync).is_err());
    assert!(GroupSync::decode(&sync.encode()[..20]).is_err());
}
