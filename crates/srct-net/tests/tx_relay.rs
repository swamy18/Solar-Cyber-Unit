//! Transaction relay over real sockets. SPEC.md §13.14.
//!
//! `relay.rs` unit-tests the bookkeeping in isolation. These tests attack the
//! thing the unit tests cannot reach: the whole path from a locally pooled
//! transaction, through a real handshake and real TCP, into a second node's pool,
//! out again in a block, and back to eviction on the originator.
//!
//! The hostile cases drive a hand-rolled socket rather than a second `P2pNode`,
//! because an attacker is not obliged to use our API. A test that can only send
//! what our own code chooses to send cannot find a defect in what it chooses not
//! to check.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use srct_core::chain::Chain;
use srct_core::hash::Address;
use srct_core::mempool::Mempool;
use srct_core::params::NetworkParams;
use srct_core::tx::{Input, OutPoint, Output, Transaction};
use srct_core::wallet::Wallet;

use srct_net::frame::{read_frame, write_frame};
use srct_net::msg::{InvEntry, Message, MessageType, INV_TYPE_TX};
use srct_net::net::{NodeState, P2pConfig, P2pNode};
use srct_net::peer::{perform_handshake, HandshakeConfig};
use srct_net::relay::{RelayManager, TX_REQUEST_TIMEOUT_MS};
use srct_net::syncer::SyncManager;

/// Timestamps at exactly the mini target spacing, so difficulty stays at 1 and
/// every block here is cheap. These tests attack relay, not proof-of-work.
fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

/// Comfortably above `base_fee * gas_used` at every height in this file.
const FEE: u64 = 100_000_000;

const BLOCKS: u64 = 12;

/// A port nothing is listening on yet.
///
/// Binding to `0` and dropping the listener is the only way `std` offers to ask
/// the OS for a free port; there is a small race between the drop and
/// `P2pNode::start` binding it, which is why the tests that need a listener treat
/// a bind failure as a reason to skip rather than to fail.
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
    /// Inbound arbitration votes, tallied per dispute.
    votes: srct_core::arbitration::VoteBook,
    /// Inbound Smart Gate revocations, verified per statement.
    revokes: srct_core::guard::GuardRevokeBook,
    /// Inbound compute demand tickets, verified per statement.
    tickets_received: Vec<srct_compute::ticket::SignedTicket>,
    /// Height the pool was last reconciled against.
    cursor: u64,
    /// Synthetic clock handed to `poll_events`.
    ///
    /// `None` uses the real clock, which is what `serve` does. Setting it is how
    /// a test drives a rule the protocol states in wall-clock time — relay
    /// request expiry is 30 s — without waiting for it. It is deliberately all or
    /// nothing: mixing a synthetic value into some calls and the real clock into
    /// others would make a rate window or a timeout mean two different things in
    /// one test.
    clock: Option<u64>,
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
                user_agent: "srct-test/0.3".into(),
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
            clock: None,
        }
    }

    /// Exactly what the serve loop does: drain events, then reconcile the pool
    /// against the canonical chain.
    fn poll(&mut self) -> usize {
        let n = self.node.poll_events(
            NodeState {
                chain: &mut self.chain,
                pool: &mut self.pool,
                syncer: &mut self.syncer,
                relay: &mut self.relay,
                votes: &mut self.votes,
                revokes: &mut self.revokes,
                tickets_received: &mut self.tickets_received,
            },
            self.clock,
        );
        let (cursor, _report) = self.chain.reconcile_mempool(&mut self.pool, self.cursor);
        self.cursor = cursor;
        n
    }
}

/// Poll every peer until `done` or `ms` elapses, then drain a few more times so a
/// frame that arrived on the last iteration is still processed.
///
/// `done` receives the peers immutably rather than capturing them: a closure that
/// closes over a peer cannot be passed alongside the mutable borrow that polling
/// needs, and letting it capture would only push the borrow conflict into every
/// call site.
fn drive_until(peers: &mut [&mut Peer], ms: u64, done: impl Fn(&[&Peer]) -> bool) {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        // The immutable borrow ends before the mutable iteration below.
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

/// Admit locally, exactly as a node with a wallet submission path would.
fn admit_locally(peer: &mut Peer, tx: Transaction) -> Result<[u8; 64], String> {
    peer.pool
        .add(
            tx,
            peer.chain.utxo(),
            peer.chain.height() + 1,
            peer.chain.params(),
            peer.chain.expected_base_fee_for_next_block(),
            peer.chain.bonds(),
        )
        .map_err(|e| e.to_string())
}

/// A hand-rolled peer with complete control over what it sends.
///
/// An attacker is not obliged to use our API, so a test that can only send what
/// `P2pNode` chooses to send cannot find a defect in what `P2pNode` chooses not to
/// check. This drives `write_frame` directly against a real listener.
struct Hostile {
    stream: TcpStream,
    params: NetworkParams,
}

impl Hostile {
    fn connect(addr: SocketAddr, params: NetworkParams) -> Hostile {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // The handshake only has to satisfy the node; what we claim about our own
        // height is irrelevant to everything below.
        let tip = Chain::new(params.clone()).unwrap().tip_hash();
        let cfg = HandshakeConfig::new(params.clone(), 0, tip);
        perform_handshake(&mut stream, &cfg, true).unwrap();
        Hostile { stream, params }
    }

    fn send_tx(&mut self, tx: &Transaction) {
        let payload = Message::Tx(Box::new(tx.clone())).encode();
        write_frame(
            &mut self.stream,
            &self.params,
            MessageType::Tx as u8,
            &payload,
        )
        .unwrap();
    }

    fn send_inv(&mut self, entries: &[InvEntry]) {
        let payload = Message::Inv(entries.to_vec()).encode();
        write_frame(
            &mut self.stream,
            &self.params,
            MessageType::Inv as u8,
            &payload,
        )
        .unwrap();
    }

    fn send_get_data(&mut self, entries: &[InvEntry]) {
        let payload = Message::GetData(entries.to_vec()).encode();
        write_frame(
            &mut self.stream,
            &self.params,
            MessageType::GetData as u8,
            &payload,
        )
        .unwrap();
    }

    /// Read frames for `ms`, decoding each, and hand `want` the messages that
    /// match. Returns how many matched.
    ///
    /// Bounded twice on purpose: by wall-clock *and* by a frame count, so a node
    /// that answers with an endless stream fails an assertion rather than
    /// hanging the test. A read error ends the loop — that is either the timeout
    /// between frames or the node hanging up, and both mean there is nothing
    /// more to read.
    fn drain_matching<F: FnMut(&Message)>(&mut self, ms: u64, limit: usize, mut want: F) -> usize {
        let deadline = Instant::now() + Duration::from_millis(ms);
        let mut matched = 0usize;
        for _ in 0..limit {
            if Instant::now() >= deadline {
                break;
            }
            self.stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let Ok((ty, payload)) = read_frame(&mut self.stream, &self.params) else {
                break;
            };
            if let Ok(msg) = Message::decode(ty, &payload) {
                if ty == MessageType::Inv as u8
                    || ty == MessageType::GetData as u8
                    || ty == MessageType::Tx as u8
                {
                    want(&msg);
                    matched += 1;
                }
            }
        }
        matched
    }
}

/// Poll `peer` until `done` or the deadline, so a test never depends on a sleep
/// being long enough on a loaded machine.
fn poll_until(peer: &mut Peer, ms: u64, done: impl Fn(&Peer) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < deadline {
        peer.poll();
        if done(peer) {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    done(peer)
}

// ---------------------------------------------------------------------------
// 1. The whole path
// ---------------------------------------------------------------------------

/// **The rule:** a transaction submitted locally reaches a peer's pool, is mined
/// there, and is evicted on both nodes once confirmed.
///
/// This is the one test that asserts the feature exists rather than that a bound
/// holds. Every stage is a real one: a real listener, a real outbound connection,
/// a real handshake, `INV` → `GETDATA` → `TX` in one direction and `INV` →
/// `GETDATA` → `BLOCK` in the other, mining on the second node, fork choice and
/// eviction on the first.
#[test]
fn a_transaction_relays_is_mined_by_the_peer_and_both_nodes_evict() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();

    // Both nodes hold the same 12 blocks. Mining is deterministic in the miner
    // address and the timestamp sequence, so two independent chains share a
    // byte-identical prefix and therefore an identical UTXO set — which is what
    // makes a spend signed for one of them valid on the other.
    let addr = free_addr();
    let mut a = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);
    let mut b = Peer::new(params.clone(), None, miner_addr, BLOCKS);
    assert_eq!(
        a.chain.tip_hash(),
        b.chain.tip_hash(),
        "the two chains must share a prefix, or this is not a relay test"
    );

    let (op, value) = coinbase_of(&a.chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let txid = tx.txid();
    admit_locally(&mut a, tx.clone()).expect("a valid spend was refused locally");
    a.node.broadcast_tx(&[txid], None);

    let _b_id = b.node.connect(addr, &b.chain).unwrap();

    drive_until(&mut [&mut a, &mut b], 8_000, |ps| {
        ps[1].pool.contains(&txid)
    });
    assert!(
        b.pool.contains(&txid),
        "the transaction never crossed the wire into the peer's pool"
    );

    // The peer mines it.
    let block = b
        .chain
        .mine_from_pool(&mut b.pool, miner_addr, ts(BLOCKS + 1))
        .expect("the peer could not mine the relayed transaction");
    assert!(
        block.txs.iter().any(|t| t.txid() == txid),
        "the relayed transaction is not in the block the peer built"
    );
    assert!(b.pool.is_empty(), "the miner kept what it had just mined");
    let hash = block.block_hash();
    b.node.broadcast_block(hash, None);

    // Back to the originator: block relay, confirmation, eviction.
    drive_until(&mut [&mut a, &mut b], 8_000, |ps| {
        ps[0].chain.height() > BLOCKS
    });
    assert!(
        a.chain.height() > BLOCKS,
        "the block carrying the transaction never reached the originator"
    );
    assert!(
        !a.pool.contains(&txid),
        "a transaction the canonical chain confirmed stayed in the pool"
    );
    assert!(
        a.chain.utxo().get(&op).is_none(),
        "the confirmed spend's input is still unspent on the originator"
    );
}
/// Wait for the node to register the inbound connection.
fn await_inbound(peer: &mut Peer) {
    assert!(
        poll_until(peer, 3_000, |p| p.node.peer_count() == 1),
        "the inbound peer never registered, so nothing below was tested"
    );
}

fn tx_inv(txid: [u8; 64]) -> InvEntry {
    InvEntry {
        kind: INV_TYPE_TX,
        hash: txid,
    }
}

// ---------------------------------------------------------------------------
// 2. A peer cannot push a transaction the node should refuse
// ---------------------------------------------------------------------------

/// **The rule:** a transaction that fails `check_tx` is never pooled, whoever
/// sends it.
///
/// **The attack:** sign with a key that does not own the input. The signature is
/// well-formed and the encoding is valid, so nothing before `check_tx` can catch
/// it — this is the case that only real validation rejects.
#[test]
fn a_peer_cannot_push_a_transaction_signed_by_the_wrong_key() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let thief = Wallet::new_random("thief");
    let (op, value) = coinbase_of(&victim.chain, 1);
    let forged = signed_spend(&thief, op, value - FEE, [9u8; 20]);
    attacker.send_tx(&forged);

    for _ in 0..40 {
        victim.poll();
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        victim.pool.is_empty(),
        "a transaction signed by a key that does not own the input was pooled"
    );
}

/// **The rule:** malformed input is scored, and repeated abuse bans (§13.9 —
/// a `TX` failing validation is `+10`, so ten reach the threshold).
///
/// **The attack:** keep pushing invalid transactions. Charging nothing makes the
/// node free to abuse; banning on the *first* one would disconnect honest peers
/// whose view of the chain is simply behind (§13.9 makes that argument about
/// blocks). Ten is where the policy is meant to bite, and this asserts it
/// actually does rather than only scoring into a counter nobody reads.
#[test]
fn repeated_invalid_transactions_get_the_peer_banned() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let thief = Wallet::new_random("thief");
    let (op, value) = coinbase_of(&victim.chain, 1);
    let forged = signed_spend(&thief, op, value - FEE, [9u8; 20]);

    // 10 × +10 = the ban threshold (§13.9), after which the peer is stopped.
    for _ in 0..10 {
        attacker.send_tx(&forged);
        for _ in 0..3 {
            victim.poll();
            thread::sleep(Duration::from_millis(2));
        }
    }

    assert!(
        poll_until(&mut victim, 3_000, |p| p.node.peer_count() == 0),
        "ten invalid transactions did not reach the ban threshold (peer_count {})",
        victim.node.peer_count()
    );
    assert!(victim.pool.is_empty(), "an invalid transaction was pooled");
}

/// **The rule:** a re-announced transaction is not misbehaviour, and not a
/// second pool entry.
///
/// Two peers relaying the same transaction is what a network looks like. The
/// dangerous version of it is a relay loop — nodes re-announcing what they were
/// just handed — which is why dedup must be exact at the pool while the relay
/// bookkeeping is only approximate.
#[test]
fn a_duplicate_announcement_is_pooled_once_and_not_punished() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let (op, value) = coinbase_of(&victim.chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let txid = tx.txid();

    for _ in 0..3 {
        attacker.send_tx(&tx);
        for _ in 0..3 {
            victim.poll();
            thread::sleep(Duration::from_millis(2));
        }
    }

    assert!(
        poll_until(&mut victim, 3_000, |p| p.pool.contains(&txid)),
        "a valid relayed transaction was never pooled"
    );
    assert_eq!(
        victim.pool.len(),
        1,
        "the same transaction was pooled more than once"
    );
    assert_eq!(
        victim.node.peer_count(),
        1,
        "re-announcing a transaction was treated as misbehaviour"
    );
}

/// **The rule:** a conflicting spend is refused, and refusing it is not
/// misbehaviour.
///
/// The attacker races the node's own pool with a second spend of the same output.
/// Pooling both is not an inflation bug — the block layer catches the double
/// spend — it is a liveness bug: whichever side loses fork choice takes its input
/// with it, so the pool's contents would depend on a race rather than on fees.
/// And a peer that merely lost a fee race is honest.
#[test]
fn a_conflicting_spend_from_a_peer_is_refused_without_a_ban() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let (op, value) = coinbase_of(&victim.chain, 1);
    let ours = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let ours_id = ours.txid();
    admit_locally(&mut victim, ours).expect("the fixture's own spend must be valid");

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let rival = signed_spend(&miner, op, value - FEE - 1, [8u8; 20]);
    attacker.send_tx(&rival);

    for _ in 0..40 {
        victim.poll();
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(
        victim.pool.len(),
        1,
        "both sides of a double spend were pooled"
    );
    assert!(victim.pool.contains(&ours_id));
    assert!(!victim.pool.contains(&rival.txid()));
    assert_eq!(
        victim.node.peer_count(),
        1,
        "losing a fee race to the node's own pool was treated as misbehaviour"
    );
}

// ---------------------------------------------------------------------------
// 3. Oversized input
// ---------------------------------------------------------------------------

/// **The rule:** a transaction larger than a whole block is refused (SPEC.md
/// §13.14). No block can ever include it, so pooling it means every peer that
/// relays it spends bandwidth on something unmineable.
///
/// The limit is lowered here rather than building a four-megabyte transaction:
/// the rule is `size > max_block_bytes`, and a small limit exercises exactly that
/// comparison on a real wire payload. That the *default* limit is checked
/// precisely is `mempool::tests::a_transaction_larger_than_a_block_is_refused`.
///
/// This also pins the deliberate absence of a separate relay size cap: the
/// transaction below is well inside `max_frame_bytes`, so it arrives intact and
/// is refused by the pool — the layer that can explain why. Rejecting it at the
/// wire would make a transaction consensus accepts unrelayable.
#[test]
fn a_transaction_larger_than_a_block_is_refused_by_the_pool() {
    let mut params = NetworkParams::mini();
    params.max_block_bytes = 4_096;

    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let (op, value) = coinbase_of(&victim.chain, 1);
    // 200 outputs × 28 bytes is well over the 4 KiB block limit and nowhere near
    // the 4.1 MB frame limit, so this reaches the pool rather than the frame
    // layer, which is the point.
    let each = (value - FEE) / 200;
    let outputs: Vec<Output> = (0..200u64)
        .map(|i| Output {
            value: each + i,
            address: [9u8; 20],
        })
        .collect();
    let mut big = Transaction::standard(vec![Input::unsigned(&op)], outputs);
    miner.sign(&mut big).unwrap();
    let encoded = big.serialize();
    assert!(
        encoded.len() > params.max_block_bytes,
        "the fixture transaction is not actually oversized: {} bytes",
        encoded.len()
    );

    attacker.send_tx(&big);

    for _ in 0..40 {
        victim.poll();
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        victim.pool.is_empty(),
        "a transaction too large for any block was pooled"
    );
}

// ---------------------------------------------------------------------------
// 4. Announcement, request and service
// ---------------------------------------------------------------------------

/// Collect the txids a node asks a peer for, and the transactions it hands back,
/// over a bounded window.
///
/// Both bounds matter: by wall-clock so a slow machine does not flake, and by
/// frame count so a node that answers with an endless stream fails an assertion
/// instead of hanging the test.
fn collect(
    victim: &mut Peer,
    attacker: &mut Hostile,
    rounds: usize,
    stop_early: bool,
    out: &mut (Vec<[u8; 64]>, Vec<[u8; 64]>),
) {
    for _ in 0..rounds {
        victim.poll();
        attacker.drain_matching(30, 4, |m| match m {
            Message::GetData(entries) => out.0.extend(entries.iter().map(|e| e.hash)),
            Message::Tx(t) => out.1.push(t.txid()),
            _ => {}
        });
        if stop_early && (!out.0.is_empty() || !out.1.is_empty()) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// **The rule:** the full announcement round trip (§13.14) — `INV` for something
/// the node does not hold draws a request, the delivery is pooled, and the
/// transaction is then served to anyone who asks.
///
/// This is the half of relay the end-to-end test reaches only indirectly, and it
/// pins two opposing rules at once: the node requests what it does *not* have
/// (a node that re-requested what it already held would gossip in a loop), and it
/// serves only what it holds (a `GETDATA` for something unpooled gets nothing —
/// the node must never relay a transaction it did not validate).
#[test]
fn an_announced_transaction_is_requested_delivered_and_then_served() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let (op, value) = coinbase_of(&victim.chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let txid = tx.txid();

    // 1. Announce something the node does not hold. It must ask for it.
    let mut out = (Vec::new(), Vec::new());
    attacker.send_inv(&[tx_inv(txid)]);
    collect(&mut victim, &mut attacker, 40, true, &mut out);
    assert_eq!(
        out.0,
        vec![txid],
        "the announced txid was not requested exactly once"
    );
    assert!(
        victim.pool.is_empty(),
        "announcing a transaction must not pool it"
    );

    // 2. Deliver it. The node pools it — unsolicited is fine here, and must be:
    //    the request was ours, so refusing the answer would make relay one-way.
    attacker.send_tx(&tx);
    assert!(
        poll_until(&mut victim, 3_000, |p| p.pool.contains(&txid)),
        "the transaction the node itself asked for was not pooled on delivery"
    );

    // 3. Now it can be served. Exactly once per request.
    let mut out = (Vec::new(), Vec::new());
    attacker.send_get_data(&[tx_inv(txid)]);
    collect(&mut victim, &mut attacker, 40, true, &mut out);
    assert_eq!(
        out.1,
        vec![txid],
        "the pooled transaction was not served to the peer that asked for it"
    );

    // 4. A request for something the node never validated is answered with
    //    nothing. Serving it would make the node a relay for a transaction it
    //    does not hold, which §13.14 forbids.
    let mut out = (Vec::new(), Vec::new());
    attacker.send_get_data(&[tx_inv([0xAB; 64])]);
    collect(&mut victim, &mut attacker, 20, false, &mut out);
    assert!(
        out.1.is_empty(),
        "the node served a transaction it never validated: {:?}",
        out.1
    );
}

/// **The rule:** repeating an announcement costs nothing after the first time,
/// and a peer that never delivers what it announced cannot stall the node.
///
/// This is the anti-amplification property. Without the in-flight set, each
/// repeated `INV` would draw another `GETDATA`: a peer sends 32 bytes and the
/// node answers every time, so a tiny request stream produces an arbitrarily
/// large response stream. Nothing is owed to a peer that does not deliver, and
/// the node must not have staked anything on it.
#[test]
fn a_repeated_announcement_draws_one_request_and_a_silent_peer_stalls_nothing() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let (op, value) = coinbase_of(&victim.chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let txid = tx.txid();

    // Announce the same thing five times without ever delivering it.
    let mut requests = 0usize;
    for _ in 0..5 {
        attacker.send_inv(&[tx_inv(txid)]);
        for _ in 0..10 {
            victim.poll();
            attacker.drain_matching(20, 4, |m| {
                if let Message::GetData(entries) = m {
                    requests += entries.len();
                }
            });
            thread::sleep(Duration::from_millis(2));
        }
    }
    assert_eq!(
        requests, 1,
        "a repeated announcement was requested {requests} times"
    );
    assert!(
        victim.pool.is_empty(),
        "an undelivered announcement was pooled anyway"
    );
    assert_eq!(
        victim.node.peer_count(),
        1,
        "failing to deliver what was announced was treated as misbehaviour"
    );

    // The peer is still connected and still owed nothing: it can now deliver the
    // transaction unsolicited, and the node pools it. A request that outlived its
    // usefulness would otherwise have left the txid marked in flight forever.
    attacker.send_tx(&tx);
    for _ in 0..40 {
        victim.poll();
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        victim.pool.contains(&txid),
        "the node refused a transaction it had itself asked for"
    );
}
/// **The rule:** a request a peer never answers is forgotten after
/// `tx_request_timeout` and can be requested again (§13.14).
///
/// The attack this closes is not about one transaction. Requests are held until
/// answered, the in-flight set is global rather than per-peer, and nothing bounded
/// how long one could be held — so a peer could announce `max_relay_in_flight`
/// transactions, deliver none, and stop the node requesting transactions from
/// *anyone* for as long as it stayed connected. `relay.rs` pins the accounting;
/// this drives the same rule through the real event loop, because the clock has to
/// travel from `poll_events` down into the request set and a caller that forgot to
/// pass it would restore the stall silently.
///
/// The clock is synthetic, so a 30-second rule is tested in milliseconds. Nothing
/// here claims 30 000 is the right number — it asserts that the deadline exists, is
/// honoured, and is not so eager that a request still in flight is re-issued.
#[test]
fn an_unanswered_request_is_forgotten_after_the_timeout() {
    /// Poll both sides for a while, counting the txids the node asks for.
    fn rounds(victim: &mut Peer, attacker: &mut Hostile, requests: &mut usize) {
        for _ in 0..12 {
            victim.poll();
            attacker.drain_matching(20, 4, |m| {
                if let Message::GetData(entries) = m {
                    *requests += entries.len();
                }
            });
            thread::sleep(Duration::from_millis(2));
        }
    }

    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let mut attacker = Hostile::connect(addr, params.clone());
    await_inbound(&mut victim);

    let (op, value) = coinbase_of(&victim.chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let txid = tx.txid();

    // A fixed base instant, away from zero, so "no time has passed" and "the clock
    // is at the epoch" are distinguishable.
    const T0: u64 = 1_000_000;
    victim.clock = Some(T0);

    let mut requests = 0usize;

    // Announce. The node asks once.
    attacker.send_inv(&[tx_inv(txid)]);
    rounds(&mut victim, &mut attacker, &mut requests);
    assert_eq!(requests, 1, "the first announcement was not requested once");

    // Re-announce inside the window. The answer is still owed, so there must still
    // be one request: without this, expiry would be indistinguishable from "ask
    // again every time", which is a free amplification loop for any peer.
    victim.clock = Some(T0 + 1_000);
    attacker.send_inv(&[tx_inv(txid)]);
    rounds(&mut victim, &mut attacker, &mut requests);
    assert_eq!(
        requests, 1,
        "a request still inside the timeout was re-issued, so a peer could make the \
         node ask twice for everything simply by repeating itself"
    );

    // Past the deadline the same announcement draws a second request: the node has
    // stopped waiting on a peer that never answered.
    victim.clock = Some(T0 + TX_REQUEST_TIMEOUT_MS + 1);
    attacker.send_inv(&[tx_inv(txid)]);
    rounds(&mut victim, &mut attacker, &mut requests);
    assert_eq!(
        requests, 2,
        "the request outlived its timeout, so the peer that withheld the \
         transaction still owns the txid and no other peer can ever be asked"
    );

    // And the answer is still accepted: expiry must not blacklist the txid.
    attacker.send_tx(&tx);
    assert!(
        poll_until(&mut victim, 3_000, |p| p.pool.contains(&txid)),
        "the transaction was refused after its request had expired"
    );
}
/// **The rule:** a wallet that connects, submits one transaction and hangs up is
/// served, and doing so is normal rather than suspicious.
///
/// This is the shape of `srct-node send --relay`: no `INV`, no prior request, one
/// `TX`, then goodbye. It is the most common way a transaction enters the network
/// from a user's perspective, and it is a case the node gets wrong by default —
/// the peer is gone before the node finishes reading what it sent.
///
/// **This test found a real defect in the code it is testing.** A node removes a
/// peer from its live set as soon as it is stopped, without waiting for the reader
/// thread to report the disconnect — that sweep exists because a reader parked in
/// a blocking read does not reliably wake when its socket is shut down. But the
/// stop flag was *also* set by the reader thread whenever a stream ended, so a
/// peer closing cleanly looked identical to a peer being banned: the sweep fired
/// first and the transaction was discarded. The fix separates "we ended this
/// peer" from "this peer's stream ended"; the evidence was a node reporting
/// `accepted 0 refused 0` for a frame its reader had already logged as received.
#[test]
fn a_one_shot_submitter_is_served_and_then_let_go() {
    let params = NetworkParams::mini();
    let miner = Wallet::new_random("miner");
    let miner_addr = miner.address().unwrap();
    let addr = free_addr();
    let mut victim = Peer::new(params.clone(), Some(addr), miner_addr, BLOCKS);

    let (op, value) = coinbase_of(&victim.chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, [9u8; 20]);
    let txid = tx.txid();

    // Exactly what `srct-node send --relay` does: connect, handshake, one frame.
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    let cfg = HandshakeConfig::new(
        params.clone(),
        victim.chain.height(),
        victim.chain.tip_hash(),
    );
    perform_handshake(&mut stream, &cfg, true).expect("handshake with the node");
    let payload = Message::Tx(Box::new(tx.clone())).encode();
    write_frame(&mut stream, &params, MessageType::Tx as u8, &payload).expect("send TX");

    // Long enough for the frame to have been read, then gone — the point of the
    // test is that the node copes with the sender disappearing.
    thread::sleep(Duration::from_millis(300));
    let _ = stream.shutdown(std::net::Shutdown::Both);

    // Crucially, **no polling until the peer's reader thread has finished**. A
    // node whose event loop is slower than its peers come and go is the normal
    // case, not an edge case, and this makes the ordering deterministic instead
    // of a race: both the transaction and the disconnect report are queued before
    // the node looks. Getting that ordering wrong is what discarded the
    // transaction, and it only reproduces reliably if the reader has already
    // exited when the node decides what to release.
    thread::sleep(Duration::from_millis(500));

    assert!(
        poll_until(&mut victim, 3_000, |p| p.pool.contains(&txid)),
        "a wallet that submitted one transaction and hung up was dropped (accepted {}, refused {})",
        victim.relay.accepted_count(),
        victim.relay.refused_count()
    );

    // And the departure is noticed: the peer does not linger.
    assert!(
        poll_until(&mut victim, 3_000, |p| p.node.peer_count() == 0),
        "the submitter's connection was never released"
    );
    assert_eq!(
        victim.relay.refused_count(),
        0,
        "a valid transaction was refused"
    );
}
