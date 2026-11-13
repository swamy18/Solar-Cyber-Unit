//! Acceptance tests for MLS-style epoch-ratcheted group messaging: commits,
//! membership changes, epoch keys and replay refusal.

use rand::rngs::StdRng;
use rand::SeedableRng;
use srct_agentnet::mls::{
    Commit, KeyPackage, LeafKey, Member, MlsError, MlsGroup, MlsMessage, Proposal,
};
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const ROLE: AgentRole = AgentRole::Machine;
const NONCE: u64 = 0x5eed;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "mls-test").unwrap()
}

fn agent(w: &Wallet) -> AgentId {
    derive_agent_id(NET, ROLE, &w.address().unwrap())
}

fn leaf(seed: u8) -> LeafKey {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    LeafKey::generate(&mut rng)
}

fn creator_group(alice: &Wallet, la: &LeafKey, rng: &mut StdRng) -> MlsGroup {
    MlsGroup::create(NET, agent(alice), ROLE, la, NONCE, rng)
}

#[test]
fn a_commit_adds_a_member_and_both_read_the_message() {
    let alice = wallet(1);
    let bob = wallet(2);
    let mut rng = StdRng::seed_from_u64(0xa11ce);
    let la = leaf(11);
    let lb = leaf(12);
    let mut ga = creator_group(&alice, &la, &mut rng);
    let pkg = KeyPackage::create(agent(&bob), &lb, &bob).unwrap();
    let commit = ga
        .commit(vec![Proposal::Add(pkg)], &alice, &mut rng)
        .unwrap();
    assert_eq!(commit.epoch, 0);
    // Alice applies her own commit.
    ga.apply(&commit, &agent(&alice), &la).unwrap();
    assert_eq!(ga.epoch, 1);
    assert!(ga.is_member(&agent(&bob)));
    // Bob applies it too and unwraps his own epoch key.
    let mut gb = MlsGroup::create(NET, agent(&alice), ROLE, &la, NONCE, &mut rng);
    gb.apply(&commit, &agent(&bob), &lb).unwrap();
    assert_eq!(gb.epoch, 1);
    // Alice's message opens for both.
    let msg = ga.seal(b"hello group", &alice, &mut rng).unwrap();
    let wire = msg.encode();
    let mut gb = MlsGroup::create(NET, agent(&alice), ROLE, &la, NONCE, &mut rng);
    gb.apply(&commit, &agent(&bob), &lb).unwrap();
    assert_eq!(
        gb.open(&MlsMessage::decode(&wire).unwrap()).unwrap(),
        b"hello group"
    );
    // And Bob's message opens for Alice.
    let msg2 = gb.seal(b"hi alice", &bob, &mut rng).unwrap();
    assert_eq!(ga.open(&msg2).unwrap(), b"hi alice");
}

#[test]
fn a_removed_member_cannot_read_the_next_epoch() {
    let alice = wallet(3);
    let bob = wallet(4);
    let mut rng = StdRng::seed_from_u64(0xb0b);
    let la = leaf(21);
    let lb = leaf(22);
    let mut ga = creator_group(&alice, &la, &mut rng);
    let pkg = KeyPackage::create(agent(&bob), &lb, &bob).unwrap();
    let add = ga
        .commit(vec![Proposal::Add(pkg)], &alice, &mut rng)
        .unwrap();
    ga.apply(&add, &agent(&alice), &la).unwrap();
    let mut gb = MlsGroup::create(NET, agent(&alice), ROLE, &la, NONCE, &mut rng);
    gb.apply(&add, &agent(&bob), &lb).unwrap();
    // Bob speaks in epoch 1; Alice can read it.
    let in_epoch1 = gb.seal(b"before removal", &bob, &mut rng).unwrap();
    assert_eq!(ga.open(&in_epoch1).unwrap(), b"before removal");
    // Alice removes Bob: a new epoch with a new key.
    let remove = ga
        .commit(vec![Proposal::Remove(agent(&bob))], &alice, &mut rng)
        .unwrap();
    ga.apply(&remove, &agent(&alice), &la).unwrap();
    assert_eq!(ga.epoch, 2);
    assert!(!ga.is_member(&agent(&bob)));
    // Bob's stale epoch is refused by Alice.
    let stale = gb.seal(b"after removal", &bob, &mut rng).unwrap();
    assert_eq!(ga.open(&stale), Err(MlsError::WrongEpoch));
}

#[test]
fn replays_and_tampering_are_refused() {
    let alice = wallet(5);
    let mut rng = StdRng::seed_from_u64(0xdead);
    let la = leaf(31);
    let mut ga = creator_group(&alice, &la, &mut rng);
    let msg = ga.seal(b"once", &alice, &mut rng).unwrap();
    // A peer view of the same epoch: the same group id, epoch, membership and
    // epoch key. This is what a member receives when it joins the group.
    let mut viewer = MlsGroup::join(NET, ga.group, ga.epoch, ga.members.clone(), ga.epoch_key);
    assert_eq!(viewer.open(&msg).unwrap(), b"once");
    // The same message again is a replay.
    assert_eq!(viewer.open(&msg), Err(MlsError::Replay));
    // A tampered body does not open.
    let mut bad = msg.clone();
    bad.ciphertext[0] ^= 0x01;
    assert!(viewer.open(&bad).is_err());
    // A tampered wire does not decode.
    let mut wire = msg.encode();
    wire[10] ^= 0x01;
    assert!(MlsMessage::decode(&wire).is_err());
}

#[test]
fn a_commit_from_a_stranger_is_refused() {
    let alice = wallet(6);
    let stranger = wallet(7);
    let mut rng = StdRng::seed_from_u64(0xfeed);
    let la = leaf(41);
    let ga = creator_group(&alice, &la, &mut rng);
    // The stranger is not a member: it cannot commit.
    assert_eq!(
        ga.commit(vec![], &stranger, &mut rng).unwrap_err(),
        MlsError::NotMember
    );
    // A commit whose bytes were tampered with does not decode.
    let commit = ga.commit(vec![], &alice, &mut rng).unwrap();
    let mut wire = commit.encode();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    assert!(Commit::decode(&wire).is_err());
}

#[test]
fn membership_is_checked_on_both_sides() {
    let alice = wallet(8);
    let bob = wallet(9);
    let mut rng = StdRng::seed_from_u64(0x1234);
    let la = leaf(51);
    let lb = leaf(52);
    let ga = creator_group(&alice, &la, &mut rng);
    // Adding a member who is already present is refused.
    let pkg = KeyPackage::create(agent(&alice), &la, &alice).unwrap();
    let ga2 = creator_group(&alice, &la, &mut rng);
    assert!(ga2
        .commit(vec![Proposal::Add(pkg.clone())], &alice, &mut rng)
        .is_err());
    // Removing a non-member is refused.
    assert!(ga
        .commit(vec![Proposal::Remove(agent(&bob))], &alice, &mut rng)
        .is_err());
    // A commit that names a different group is refused on apply.
    let pkg = KeyPackage::create(agent(&bob), &lb, &bob).unwrap();
    let commit = ga
        .commit(vec![Proposal::Add(pkg)], &alice, &mut rng)
        .unwrap();
    let mut other = creator_group(&alice, &la, &mut rng);
    other.epoch = 99;
    assert_eq!(
        other.apply(&commit, &agent(&alice), &la).unwrap_err(),
        MlsError::WrongEpoch
    );
    // The creator cannot remove itself: the group would be empty.
    assert!(ga
        .commit(vec![Proposal::Remove(agent(&alice))], &alice, &mut rng)
        .is_err());
    // A commit whose epoch does not match the state is refused: a member
    // that already applied a newer commit cannot apply an older one.
    let mut ahead = MlsGroup::join(
        NET,
        ga.group,
        5,
        vec![Member {
            agent: agent(&alice),
            leaf_public: la.public_bytes(),
        }],
        [1u8; 32],
    );
    assert_eq!(
        ahead.apply(&commit, &agent(&alice), &la).unwrap_err(),
        MlsError::WrongEpoch
    );
}
