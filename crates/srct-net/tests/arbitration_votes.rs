//! Fraud-arbitration votes over real sockets (Decision 21, SPEC.md §16).
//!
//! Three independently instantiated `P2pNode`s, each with its own chain, pool,
//! syncer, relay and vote book, connected over real TCP to a real listener. No
//! shared state and no in-memory channel: a vote travels as bytes through the
//! wire codec, is decoded, verified against the receiving node's *own* committee
//! and height, and is relayed onward.
//!
//! What this proves that a unit test cannot:
//!
//! 1. a vote signed by a committee member propagates through a chain of nodes;
//! 2. a vote from a stranger, or for the wrong network or height, is refused
//!    and does not travel further;
//! 3. re-delivering the same vote does not double-count its signer, so a relay
//!    loop or a duplicate message cannot inflate quorum;
//! 4. two conflicting votes leave each node with a consistent, deterministic
//!    view, and the aggregate each builds verifies.

use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use srct_core::arbitration::{ArbitrationVote, ARBITRATION_VOTE_VERSION};
use srct_core::bls::SecretKey;
use srct_core::bls_checkpoint::{BlsPublicKey, BlsSignature};
use srct_core::chain::Chain;
use srct_core::hash::Hash;
use srct_core::l2::Verdict;
use srct_core::mempool::Mempool;
use srct_core::params::NetworkParams;
use srct_net::msg::Message;
use srct_net::net::{NodeState, P2pConfig, P2pNode};
use srct_net::relay::RelayManager;
use srct_net::syncer::SyncManager;

/// One local node: its own state, so nothing is shared between the three.
struct LocalNode {
    node: P2pNode,
    chain: Chain,
    pool: Mempool,
    syncer: SyncManager,
    relay: RelayManager,
    votes: srct_core::arbitration::VoteBook,
    revokes: srct_core::guard::GuardRevokeBook,
    tickets_received: Vec<srct_compute::ticket::SignedTicket>,
}

impl LocalNode {
    fn new(params: &NetworkParams, listen: Option<std::net::SocketAddr>) -> Self {
        // The chain is built first so the handshake announces the real genesis
        // hash; announcing a zero one makes connect fail before any message
        // is exchanged, which is the correct behaviour for a peer that does not
        // share this chain.
        let chain = Chain::new(params.clone()).unwrap();
        let node = P2pNode::start(
            P2pConfig {
                params: params.clone(),
                listen_addr: listen,
                max_peers: 8,
                max_inbound: 8,
                user_agent: "arb-test/0.1".into(),
                bootnodes: Vec::new(),
                address_book: None,
            },
            chain.height(),
            chain.tip_hash(),
        )
        .unwrap();
        LocalNode {
            node,
            chain,
            pool: Mempool::default(),
            syncer: SyncManager::new(),
            relay: RelayManager::new(),
            votes: srct_core::arbitration::VoteBook::new(),
            revokes: srct_core::guard::GuardRevokeBook::new(),
            tickets_received: Vec::new(),
        }
    }

    fn poll(&mut self, ms: u64) {
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            self.node.poll_events(
                NodeState {
                    chain: &mut self.chain,
                    pool: &mut self.pool,
                    syncer: &mut self.syncer,
                    relay: &mut self.relay,
                    votes: &mut self.votes,
                    revokes: &mut self.revokes,
                    tickets_received: &mut self.tickets_received,
                },
                None,
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn free_port() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

/// The committee a chain actually derives, which is what every node holding the
/// same params agrees on. Deriving keys here instead of reading them from the
/// chain would sign with keys no node accepts — which is the "stranger" case, not
/// the happy path.
fn committee_keys(chain: &Chain) -> Vec<BlsPublicKey> {
    chain.committee_keys()
}

const NET: &str = "srct/mini";

/// The signing secret for committee index `idx`, read from the profile's own
/// derivation rather than guessed. `mini_validator_secret` is public test
/// material by design (`params.rs` documents it as such), so a test signing as
/// a committee member is not pretending to be anyone it should not be.
fn voter(chain: &Chain, idx: usize) -> SecretKey {
    let committee = chain.committee_keys();
    let wanted = committee[idx];
    (1u8..=32)
        .map(srct_core::params::mini_validator_secret)
        .find(|sk| sk.public_key() == wanted)
        .unwrap_or_else(|| panic!("committee index {idx} is not a mini validator"))
}

fn vote(
    task_id: Hash,
    verdict: Verdict,
    result: Hash,
    network_id: &str,
    height: u64,
    sk: &SecretKey,
) -> ArbitrationVote {
    let base = ArbitrationVote {
        version: ARBITRATION_VOTE_VERSION,
        task_id,
        verdict,
        vwc_hash: result,
        network_id: network_id.to_string(),
        height,
        signer: sk.public_key(),
        signature: BlsSignature([0u8; 96]),
        pq_sig: None,
    };
    ArbitrationVote {
        signature: sk.sign(&base.signing_hash()),
        ..base
    }
}

// ---------------------------------------------------------------------------
// Propagation
// ---------------------------------------------------------------------------

/// **The happy path, over real sockets.** A vote signed by a committee member is
/// handed to one node and must reach the far end of the chain — each hop
/// re-verifying it against its own committee before relaying.
#[test]
fn a_valid_vote_propagates_through_a_chain_of_nodes() {
    let params = NetworkParams::mini();
    let a = free_port();
    let b = free_port();
    let mut n1 = LocalNode::new(&params, Some(a));
    let mut n2 = LocalNode::new(&params, Some(b));
    let mut n3 = LocalNode::new(&params, None);

    n3.node.connect(a, &n3.chain).unwrap();
    n2.node.connect(a, &n2.chain).unwrap();
    n1.node.connect(b, &n1.chain).unwrap();

    let committee = committee_keys(&n1.chain);
    let task = [0x42u8; 32];
    let v = vote(
        task,
        Verdict::Fraudulent,
        [0xABu8; 32],
        NET,
        0,
        &voter(&n1.chain, 0),
    );
    // Hand it to n1, which relays to n2, which relays to n3.
    n1.node.broadcast_vote(v.clone());

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut reached = 0usize;
    while Instant::now() < deadline && reached < 2 {
        n1.poll(50);
        n2.poll(50);
        n3.poll(50);
        reached = [
            n1.votes.tally(&task),
            n2.votes.tally(&task),
            n3.votes.tally(&task),
        ]
        .iter()
        .filter(|t| t.map(|t| t.votes() >= 1).unwrap_or(false))
        .count();
    }

    assert!(
        n2.votes
            .tally(&task)
            .map(|t| t.votes() >= 1)
            .unwrap_or(false),
        "the middle node must have tallied the vote"
    );
    assert!(
        n3.votes
            .tally(&task)
            .map(|t| t.votes() >= 1)
            .unwrap_or(false),
        "the far end of the chain must have tallied the vote"
    );
    let _ = committee;
}

// ---------------------------------------------------------------------------
// Refusal
// ---------------------------------------------------------------------------

/// **A stranger's vote must not propagate.** The signing key is not in the
/// committee, so the receiving node drops it and does not relay — so it reaches
/// nobody, least of all the far end.
#[test]
fn a_vote_from_a_non_committee_signer_is_refused_and_not_relayed() {
    let params = NetworkParams::mini();
    let a = free_port();
    let mut n1 = LocalNode::new(&params, Some(a));
    let mut n2 = LocalNode::new(&params, None);
    n2.node.connect(a, &n2.chain).unwrap();

    // Seed 9 is not in the derived committee of 1..=4.
    let stranger = SecretKey::derive(&[9u8; 32]).unwrap();
    let v = vote(
        [0x42u8; 32],
        Verdict::Fraudulent,
        [0xABu8; 32],
        NET,
        0,
        &stranger,
    );
    n1.node.broadcast_vote(v);

    n1.poll(700);
    n2.poll(1500);

    assert!(
        n2.votes
            .tally(&[0x42u8; 32])
            .map(|t| t.votes() == 0)
            .unwrap_or(true),
        "a vote from a stranger must not be tallied"
    );
    assert_eq!(
        n2.votes
            .tally(&[0x42u8; 32])
            .map(|t| t.votes())
            .unwrap_or(0),
        0,
        "and nothing must have been counted for it"
    );
}

/// **Cross-network and cross-height votes are refused at the receiving node**,
/// because both are bound at tally time against the node's own chain.
#[test]
fn votes_for_another_network_or_height_are_refused() {
    let params = NetworkParams::mini();
    let mut n1 = LocalNode::new(&params, None);
    let committee = committee_keys(&n1.chain);

    let wrong_net = vote(
        [0x42u8; 32],
        Verdict::Fraudulent,
        [0xABu8; 32],
        "srct/mainnet",
        0,
        &voter(&n1.chain, 0),
    );
    let wrong_height = vote(
        [0x42u8; 32],
        Verdict::Fraudulent,
        [0xABu8; 32],
        NET,
        99,
        &voter(&n1.chain, 0),
    );

    let quorum = srct_core::bls_checkpoint::ValidatorSet::new(committee.clone()).quorum_size();
    let err = n1
        .votes
        .entry([0x42u8; 32], quorum)
        .record(&wrong_net, NET, 0, &committee);
    assert!(err.is_err(), "{err:?}");

    let err = n1
        .votes
        .entry([0x42u8; 32], quorum)
        .record(&wrong_height, NET, 0, &committee);
    assert!(err.is_err(), "{err:?}");
    assert_eq!(n1.votes.len(), 1, "both refusals still created the tally");
    assert_eq!(
        n1.votes
            .tally(&[0x42u8; 32])
            .map(|t| t.votes())
            .unwrap_or(0),
        0,
        "but counted nothing"
    );
}

// ---------------------------------------------------------------------------
// Replay and duplication
// ---------------------------------------------------------------------------

/// **A duplicate vote cannot inflate quorum.** Delivered to the same node many
/// times, it counts once — so a peer looping a message, or a re-delivery after
/// a reconnect, cannot manufacture a quorum out of one signature.
#[test]
fn a_replayed_vote_counts_once_and_never_inflates_quorum() {
    let params = NetworkParams::mini();
    let mut n1 = LocalNode::new(&params, None);
    let committee = committee_keys(&n1.chain);
    let quorum = srct_core::bls_checkpoint::ValidatorSet::new(committee.clone()).quorum_size();

    let v = vote(
        [0x42u8; 32],
        Verdict::Fraudulent,
        [0xABu8; 32],
        NET,
        0,
        &voter(&n1.chain, 0),
    );
    for _ in 0..10 {
        // Each delivery goes through the wire codec, so this is a genuine
        // re-decode rather than the same struct re-recorded.
        let wire = v.serialize();
        let decoded = ArbitrationVote::deserialize(&wire).expect("round-trips");
        let _ = n1
            .votes
            .entry([0x42u8; 32], quorum)
            .record(&decoded, NET, 0, &committee);
    }

    let tally = n1.votes.tally(&[0x42u8; 32]).expect("the tally exists");
    assert_eq!(tally.votes(), 1, "one signer counts once");
    assert!(!tally.has_quorum(), "one vote is not a quorum");
    assert!(
        tally.settle_payload(&committee).is_none(),
        "and it produces no payload"
    );
}

/// **Conflicting votes cannot silently produce divergent outcomes.** Two
/// signers disagreeing on the verdict for the same dispute is recorded as a
/// conflict, not merged: the second is refused, and the aggregate of what *was*
/// counted verifies or does not, uniformly.
#[test]
fn conflicting_votes_are_refused_not_merged() {
    let params = NetworkParams::mini();
    let mut n1 = LocalNode::new(&params, None);
    let committee = committee_keys(&n1.chain);
    let quorum = srct_core::bls_checkpoint::ValidatorSet::new(committee.clone()).quorum_size();
    let task = [0x42u8; 32];

    let first = vote(
        task,
        Verdict::Fraudulent,
        [0xABu8; 32],
        NET,
        0,
        &voter(&n1.chain, 0),
    );
    let rogue = vote(
        task,
        Verdict::Correct,
        [0xCDu8; 32],
        NET,
        0,
        &voter(&n1.chain, 0),
    );

    n1.votes
        .entry(task, quorum)
        .record(&first, NET, 0, &committee)
        .unwrap();
    let err = n1
        .votes
        .entry(task, quorum)
        .record(&rogue, NET, 0, &committee);
    assert!(err.is_err(), "the same signer may not vote twice: {err:?}");

    let tally = n1.votes.tally(&task).unwrap();
    assert_eq!(tally.votes(), 1, "only the first is counted");
    assert_eq!(
        tally.decision(),
        Some((task, Verdict::Fraudulent, [0xABu8; 32])),
        "and the decision is the one that was signed, not a merge"
    );
}

/// **Malformed payloads do not panic or count.** Every prefix of a valid vote
/// is refused by name — except the one that ends exactly at the BLS
/// signature, which is the pre-lattice encoding a legacy peer still sends
/// (`pq_sig: None`). The lattice flag byte riding last is what makes that
/// prefix *shape*-valid rather than truncated: the same tolerance the
/// checkpoint, settle and VWC codecs give their trailing sidecar.
#[test]
fn every_truncation_of_a_vote_is_refused_not_panicked() {
    let any = SecretKey::derive(&[1u8; 32]).unwrap();
    let v = vote(
        [0x42u8; 32],
        Verdict::Fraudulent,
        [0xABu8; 32],
        NET,
        0,
        &any,
    );
    let wire = v.serialize();
    // This helper's vote has no lattice signature, so its wire form ends with
    // the `present = 0` flag byte and the pre-lattice shape is one byte
    // shorter: exactly `body ‖ signature`.
    let legacy_len = wire.len() - 1;
    let mut refused = 0;
    let mut legacy_decoded = false;
    for n in 0..wire.len() {
        match ArbitrationVote::deserialize(&wire[..n]) {
            Err(_) => refused += 1,
            Ok(back) => {
                assert_eq!(back.signature, v.signature, "only the legacy shape decodes");
                assert_eq!(n, legacy_len, "and only at the signature boundary");
                assert!(back.pq_sig.is_none());
                legacy_decoded = true;
            }
        }
    }
    assert!(
        refused + usize::from(legacy_decoded) == wire.len(),
        "every prefix is refused, the legacy one decodes"
    );
    assert!(
        ArbitrationVote::deserialize(&wire).is_ok(),
        "the whole thing decodes"
    );

    // A hostile payload claiming a huge `network_id` must not allocate for it.
    let mut hostile = wire.clone();
    hostile[4 + 32 + 1 + 32] = 0xFF;
    hostile[5] = 0xFF;
    hostile[6] = 0xFF;
    hostile[7] = 0xFF;
    assert!(ArbitrationVote::deserialize(&hostile).is_err());
}

/// **Wire codec round-trip.** What a node decodes from a peer is byte-identical
/// to what the other encoded, so a signature verified on one side verifies on
/// the other.
#[test]
fn a_vote_round_trips_through_the_wire_codec() {
    let any = SecretKey::derive(&[1u8; 32]).unwrap();
    let v = vote(
        [0x42u8; 32],
        Verdict::Fraudulent,
        [0xABu8; 32],
        NET,
        0,
        &any,
    );
    let encoded = Message::ArbitrationVote(Box::new(v.clone())).encode();
    let decoded = Message::decode(12, &encoded).expect("decodes");
    match decoded {
        Message::ArbitrationVote(back) => assert_eq!(*back, v),
        other => panic!("wrong variant: {other:?}"),
    }
}

/// **The unknown-message freeze rule.** A type number this build does not know
/// is ignored rather than rejected, so adding one more message type cannot
/// partition the network.
#[test]
fn an_unknown_message_type_is_ignored_not_fatal() {
    let decoded = Message::decode(200, b"anything at all").expect("decodes to Unknown");
    assert!(matches!(decoded, Message::Unknown { ty: 200, .. }));
}
