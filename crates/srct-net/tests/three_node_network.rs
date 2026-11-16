//! Three-node network over real sockets — the multi-node launch gate.
//!
//! `integration.rs` proves one node can sync one peer, and `tx_relay.rs`
//! proves a transaction crosses one connection. What neither proves is the
//! shape a real deployment has: a seed node, a transit node that only knows
//! the seed, and a third node that reaches the chain *through* the transit
//! node rather than by dialing the seed itself. That transit path is where a
//! re-relay bug would hide — a node that syncs but never forwards would look
//! healthy in every two-node test.
//!
//! The topology under test:
//!
//! ```text
//!   node A (seed, listens)
//!     ▲
//!     │ outbound                node C dials ONLY node B. Everything C
//!   node B (listens) ────────── learns must travel A → B → C.
//!     ▲
//!     └── node D (a restarted node: fresh process state, same network)
//! ```
//!
//! Verified end to end: identical genesis, initial sync through the transit
//! node, live block propagation through the transit node, transaction
//! propagation from a leaf back to the seed, and a restarted node catching
//! up from any live peer.
//!
//! Run with `cargo test -p srct-net --test three_node_network`.

use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use srct_core::chain::Chain;
use srct_core::hash::Address;
use srct_core::mempool::Mempool;
use srct_core::params::NetworkParams;
use srct_core::tx::{Input, OutPoint, Output, Transaction};
use srct_core::wallet::Wallet;

use srct_net::net::{NodeState, P2pConfig, P2pNode};
use srct_net::relay::RelayManager;
use srct_net::syncer::SyncManager;

/// Timestamps at exactly the mini target spacing, so difficulty stays at 1 and
/// every block here is cheap. These tests attack networking, not proof-of-work.
fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

/// Comfortably above `base_fee * gas_used` at every height in this file.
const FEE: u64 = 100_000_000;

/// Blocks the seed holds before anyone connects. Twelve puts the block-1
/// coinbase past mini's `coinbase_maturity` of 10, so the spend phase below
/// has a mature input without mining extra blocks mid-test.
const SYNCED_BLOCKS: u64 = 12;

/// A port nothing is listening on yet. Same caveat as `tx_relay.rs`: there is
/// a small window between the drop and `P2pNode::start` rebinding the port.
fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

/// One node, mirroring what `srct-node serve` holds: chain, pool, sync, relay.
struct Peer {
    node: P2pNode,
    chain: Chain,
    pool: Mempool,
    syncer: SyncManager,
    relay: RelayManager,
    votes: srct_core::arbitration::VoteBook,
    revokes: srct_core::guard::GuardRevokeBook,
    tickets_received: Vec<srct_compute::ticket::SignedTicket>,
    cursor: u64,
}

impl Peer {
    fn new(params: NetworkParams, listen: Option<SocketAddr>, miner: Address, blocks: u64) -> Peer {
        let mut chain = Chain::new(params.clone()).unwrap();
        for h in 1..=blocks {
            let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        let node = P2pNode::start(
            P2pConfig {
                params,
                listen_addr: listen,
                max_peers: 8,
                max_inbound: 8,
                user_agent: "srct-net-test/0.3".into(),
                bootnodes: Vec::new(),
                address_book: None,
            },
            chain.height(),
            chain.tip_hash(),
        )
        .unwrap();
        let cursor = chain.height();
        Peer {
            node,
            chain,
            pool: Mempool::default(),
            syncer: SyncManager::new(),
            relay: RelayManager::new(),
            votes: srct_core::arbitration::VoteBook::new(),
            revokes: srct_core::guard::GuardRevokeBook::new(),
            tickets_received: Vec::new(),
            cursor,
        }
    }

    /// Exactly what the serve loop does: drain events, then reconcile the pool
    /// against the canonical chain.
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
        let (cursor, _report) = self.chain.reconcile_mempool(&mut self.pool, self.cursor);
        self.cursor = cursor;
    }
}

/// Poll every peer until `done` or `ms` elapses, then drain a few more times so
/// a frame that arrived on the last iteration is still processed.
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

fn coinbase_of(chain: &Chain, height: u64) -> (OutPoint, u64) {
    let block = chain.block_at(height).expect("block exists");
    (
        OutPoint {
            txid: block.txs[0].txid(),
            index: 0,
        },
        srct_core::supply::block_reward_sat(chain.params(), height),
    )
}

fn signed_spend(w: &Wallet, op: OutPoint, pay: u64, to: Address) -> Transaction {
    let mut tx = Transaction::standard(
        vec![Input::unsigned(&op)],
        vec![Output {
            value: pay,
            address: to,
        }],
    );
    w.sign(&mut tx).unwrap();
    tx
}

#[test]
fn three_nodes_one_seed_converge_relay_and_recover() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();

    // Node A: the seed. Listens, and holds the whole chain so far.
    let a_addr = free_addr();
    let mut a = Peer::new(params.clone(), Some(a_addr), miner_addr, SYNCED_BLOCKS);

    // Node B: dials the seed only. It starts from genesis.
    let b_addr = free_addr();
    let mut b = Peer::new(params.clone(), Some(b_addr), miner_addr, 0);

    // Node C: dials B only — never A. Everything it learns must be re-relayed.
    let mut c = Peer::new(params.clone(), None, miner_addr, 0);

    // --- 1. Deterministic genesis on every node -----------------------------
    let genesis = a.chain.block_hash_at(0).unwrap();
    assert_eq!(b.chain.block_hash_at(0).unwrap(), genesis);
    assert_eq!(c.chain.block_hash_at(0).unwrap(), genesis);
    assert_eq!(a.chain.height(), SYNCED_BLOCKS);

    // --- 2. B dials the seed and syncs the existing chain -------------------
    b.node.connect(a_addr, &b.chain).unwrap();
    drive_until(&mut [&mut a, &mut b, &mut c], 15_000, |ps| {
        ps[1].chain.height() == SYNCED_BLOCKS
    });
    assert_eq!(
        b.chain.height(),
        SYNCED_BLOCKS,
        "node B never finished syncing from the seed"
    );
    assert_eq!(b.chain.tip_hash(), a.chain.tip_hash());

    // --- 3. C dials B (not A) and syncs through the transit node ------------
    c.node.connect(b_addr, &c.chain).unwrap();
    drive_until(&mut [&mut a, &mut b, &mut c], 15_000, |ps| {
        ps[2].chain.height() == SYNCED_BLOCKS
    });
    assert_eq!(
        c.chain.height(),
        SYNCED_BLOCKS,
        "node C never synced through the transit node"
    );
    assert_eq!(c.chain.tip_hash(), a.chain.tip_hash());
    assert_eq!(
        c.chain.verify_canonical_chain(),
        Ok(()),
        "node C's transit-synced chain does not verify"
    );

    // --- 4. A mines a new block; it must reach C via B's re-relay ------------
    let h = a.chain.height() + 1;
    let block = a.chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
    let new_hash = block.block_hash();
    a.chain.submit(block).unwrap();
    a.node.broadcast_block(new_hash, None);

    drive_until(&mut [&mut a, &mut b, &mut c], 15_000, |ps| {
        ps[1].chain.height() == h && ps[2].chain.height() == h
    });
    assert_eq!(
        b.chain.height(),
        h,
        "the live block never reached the transit node"
    );
    assert_eq!(
        c.chain.height(),
        h,
        "the live block was never re-relayed through the transit node to node C"
    );
    assert_eq!(b.chain.tip_hash(), new_hash);
    assert_eq!(c.chain.tip_hash(), new_hash);

    // --- 5. A transaction submitted at the leaf reaches the seed ------------
    // All chains share a byte-identical prefix (same miner address, same
    // timestamp sequence), so a spend signed against C's UTXO set is valid
    // everywhere — which is exactly what lets the relay path be tested.
    let (op, value) = coinbase_of(&c.chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let txid = tx.txid();
    c.pool
        .add(
            tx.clone(),
            c.chain.utxo(),
            c.chain.height() + 1,
            c.chain.params(),
            c.chain.expected_base_fee_for_next_block(),
            c.chain.bonds(),
        )
        .expect("a valid spend was refused locally on C");
    c.node.broadcast_tx(&[txid], None);

    drive_until(&mut [&mut a, &mut b, &mut c], 15_000, |ps| {
        ps[0].pool.contains(&txid) && ps[1].pool.contains(&txid)
    });
    assert!(
        a.pool.contains(&txid),
        "the leaf's transaction never propagated through the network to the seed"
    );
    assert!(
        b.pool.contains(&txid),
        "the transit node never pooled the leaf's transaction"
    );

    // --- 6. A restarted node catches up from any live peer ------------------
    // A fresh `Peer` is what a process restart looks like from the network's
    // point of view: new sockets, no peer history, chain replayed from disk.
    let mut d = Peer::new(params.clone(), None, miner_addr, 0);
    d.node.connect(a_addr, &d.chain).unwrap();
    let target = a.chain.height();
    drive_until(&mut [&mut a, &mut b, &mut c, &mut d], 15_000, |ps| {
        ps[3].chain.height() == target
    });
    assert_eq!(d.chain.height(), target, "a restarted node never caught up");
    assert_eq!(d.chain.tip_hash(), a.chain.tip_hash());
    assert_eq!(
        d.chain.verify_canonical_chain(),
        Ok(()),
        "the restarted node's chain does not verify"
    );
}
