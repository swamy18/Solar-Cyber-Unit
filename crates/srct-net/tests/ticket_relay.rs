//! Three-node compute ticket relay over real sockets — the demand-broadcast gate.
//!
//! The topology mirrors `three_node_network.rs`: node A listens, node B dials
//! A, node C dials B only. A ticket announced on A must reach B *and* C (the
//! transit node re-relays it), with the requester's signature intact. When
//! both B and C try to claim the same ticket, the claim book admits the
//! first valid claim and refuses the second: no double claim, even though
//! every node holds the same ticket.
//!
//! Run with `cargo test -p srct-net --test ticket_relay`.

use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use srct_compute::market::Verification;
use srct_compute::ticket::{
    ClaimTicket, ShardClaim, SignedClaim, SignedTicket, CLAIM_VERSION, TICKET_VERSION,
};
use srct_compute::{ClaimBook, ComputeError, Determinism};
use srct_core::chain::Chain;
use srct_core::mempool::Mempool;
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;

use srct_net::net::{NodeState, P2pConfig, P2pNode};
use srct_net::relay::RelayManager;
use srct_net::syncer::SyncManager;

const NET: &str = "srct/mini";

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "ticket-relay-test").unwrap()
}

fn ticket(requester: &Wallet, nonce: u64) -> SignedTicket {
    SignedTicket::sign(
        ClaimTicket {
            version: TICKET_VERSION,
            network_id: NET.into(),
            requester: requester.address().unwrap(),
            job: [9u8; 32],
            shard: 0,
            units: 10,
            unit_price_sat: 5,
            total_sat: 50,
            min_ram_mib: 512,
            min_units_per_sec: 100,
            min_bandwidth_kbps: 0,
            determinism: Determinism::Reproducible,
            required_kernel: [0u8; 32],
            min_verification: Verification::Receipt,
            sealed_input: false,
            input: [3u8; 32],
            deadline: 1000,
            nonce,
            provider: None,
        },
        requester,
    )
    .unwrap()
}

fn claim_for(provider: &Wallet, ticket: &SignedTicket, nonce: u64) -> SignedClaim {
    SignedClaim::sign(
        ShardClaim {
            version: CLAIM_VERSION,
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

/// A port nothing is listening on yet. Same caveat as `tx_relay.rs`: there is
/// a small window between the drop and `P2pNode::start` rebinding the port.
fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

struct Peer {
    node: P2pNode,
    chain: Chain,
    pool: Mempool,
    syncer: SyncManager,
    relay: RelayManager,
    votes: srct_core::arbitration::VoteBook,
    revokes: srct_core::guard::GuardRevokeBook,
    tickets_received: Vec<SignedTicket>,
}

impl Peer {
    fn new(params: NetworkParams, listen: Option<SocketAddr>) -> Peer {
        let chain = Chain::new(params.clone()).unwrap();
        let node = P2pNode::start(
            P2pConfig {
                params,
                listen_addr: listen,
                max_peers: 8,
                max_inbound: 8,
                user_agent: "srct-net-ticket-test/0.3".into(),
                bootnodes: Vec::new(),
                address_book: None,
            },
            chain.height(),
            chain.tip_hash(),
        )
        .unwrap();
        Peer {
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

    fn poll(&mut self) {
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
    }
}

fn drive_until(peers: &mut [&mut Peer], ms: u64, done: impl Fn(&[&Peer]) -> bool) {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let reached = {
            let snapshot: Vec<&Peer> = peers.iter().map(|p| &**p).collect();
            done(&snapshot)
        };
        if reached || Instant::now() >= deadline {
            break;
        }
        for p in peers.iter_mut() {
            p.poll();
        }
        thread::sleep(Duration::from_millis(5));
    }
    for _ in 0..8 {
        for p in peers.iter_mut() {
            p.poll();
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn ticket_reaches_all_three_nodes_over_real_tcp() {
    let params = NetworkParams::mini();

    // A listens; B dials A; C dials B only — everything C learns must be
    // re-relayed through the transit node.
    let a_addr = free_addr();
    let mut a = Peer::new(params.clone(), Some(a_addr));
    let b_addr = free_addr();
    let mut b = Peer::new(params.clone(), Some(b_addr));
    let mut c = Peer::new(params.clone(), None);

    b.node.connect(a_addr, &b.chain).unwrap();
    c.node.connect(b_addr, &c.chain).unwrap();
    drive_until(&mut [&mut a, &mut b, &mut c], 15_000, |ps| {
        ps.iter().all(|p| p.node.peer_count() >= 1)
    });
    assert!(
        a.node.peer_count() >= 1 && b.node.peer_count() >= 1 && c.node.peer_count() >= 1,
        "peers never connected"
    );

    // Node A announces a ticket; every connected node must receive it with
    // the requester's signature intact.
    let requester = wallet(1);
    let t = ticket(&requester, 1);
    let want = t.hash();
    a.node.broadcast_ticket(t);

    drive_until(&mut [&mut a, &mut b, &mut c], 15_000, |ps| {
        !ps[1].tickets_received.is_empty() && !ps[2].tickets_received.is_empty()
    });
    assert!(
        !b.tickets_received.is_empty(),
        "the transit node never received the ticket"
    );
    assert!(
        !c.tickets_received.is_empty(),
        "the leaf node never received the re-relayed ticket"
    );
    for got in b.tickets_received.iter().chain(c.tickets_received.iter()) {
        assert_eq!(got.hash(), want, "relayed ticket is not the posted ticket");
        got.verify().expect("relayed ticket fails signature check");
    }

    // No double claim: both B and C hold the same ticket, the first valid
    // claim wins and the second is refused by name.
    let fast = wallet(2);
    let slow = wallet(3);
    let mut book = ClaimBook::new(NET);
    book.post(&ticket(&requester, 1), 0).unwrap();
    let won = claim_for(&fast, &ticket(&requester, 1), 1);
    book.claim(&won, 1).unwrap();
    let lost = claim_for(&slow, &ticket(&requester, 1), 1);
    assert_eq!(
        book.claim(&lost, 1),
        Err(ComputeError::AlreadyClaimed),
        "a second claim for the same ticket must not settle"
    );
}
