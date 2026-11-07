//! Top-level P2P networking service. SPEC.md §13.1, §13.6, §13.8.
//!
//! Owns connection listening, peer management, and dispatches network events
//! to the chain thread.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rand::seq::SliceRandom;
use rand::thread_rng;

use srct_core::chain::Chain;
use srct_core::hash::{Hash512, ZERO_HASH512};
use srct_core::mempool::{Mempool, MempoolError};
use srct_core::params::NetworkParams;

use crate::addr_book::AddressBook;
use crate::error::{NetError, NetResult};
use crate::msg::{InvEntry, Message, INV_TYPE_BLOCK, INV_TYPE_TX, MAX_INV_PER_MSG};
use crate::peer::{
    perform_handshake, spawn_peer, HandshakeConfig, PeerEvent, PeerHandle, PeerTable,
    BAN_SCORE_THRESHOLD,
};
use crate::relay::RelayManager;
use crate::syncer::{create_locator, find_fork_and_collect_inv, SyncManager, SyncResult};

/// Score added to an address each time it exceeds an inbound bound.
/// SPEC.md §13.8: exceeding an inbound bound bans rather than merely
/// disconnecting. Five strikes reaches `ban_score_threshold`.
pub const INBOUND_VIOLATION_SCORE: u32 = 20;

/// Disputes with a live tally in the transport-level `VoteBook` (§13.8). The
/// book creates a tally for any task id it is handed, so without a cap a
/// flood of distinct ids grows it without bound — every one of them allocated
/// even when the vote inside is rejected.
const MAX_VOTE_TALLIES: usize = 4_096;

/// Maximum addresses tracked for inbound-bound scoring. Keeps the ban table
/// bounded against a flood of distinct source addresses (§13.11 invariant 6).
const MAX_BAN_TRACKED: usize = 1024;

/// Default TCP connect timeout for an outbound peer dial (§13.8).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Shorter timeout for reconnect attempts so a dead bootnode does not stall
/// the serve loop for the full `CONNECT_TIMEOUT`.
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Reconnect attempts per `poll_events` cycle. Each can block for up to
/// `RECONNECT_TIMEOUT`, so at the default 250 ms loop period this keeps a
/// single reconnect sweep under ~3 s without starving mining or sync.
const RECONNECT_ATTEMPTS_PER_CYCLE: usize = 1;

/// Per-address score with the wall-clock hour it was last updated, so the
/// 1-per-hour decay of §13.9 can be applied without a background timer.
#[derive(Debug, Clone, Copy)]
struct BanState {
    score: u32,
    updated_ms: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Apply §13.9's 1-per-hour decay and report whether the address is banned.
fn is_banned(bans: &Arc<Mutex<HashMap<IpAddr, BanState>>>, ip: IpAddr) -> bool {
    let mut map = bans.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
    let now = now_ms();
    let Some(state) = map.get_mut(&ip) else {
        return false;
    };
    let hours = now.saturating_sub(state.updated_ms) / 3_600_000;
    if hours > 0 {
        state.score = state.score.saturating_sub(hours as u32);
        state.updated_ms = now;
    }
    state.score >= BAN_SCORE_THRESHOLD
}

/// Record an inbound-bound violation and prune the table if it grew too large.
fn score_violation(bans: &Arc<Mutex<HashMap<IpAddr, BanState>>>, ip: IpAddr) {
    let mut map = bans.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
    let now = now_ms();
    let state = map.entry(ip).or_insert(BanState {
        score: 0,
        updated_ms: now,
    });
    let hours = now.saturating_sub(state.updated_ms) / 3_600_000;
    if hours > 0 {
        state.score = state.score.saturating_sub(hours as u32);
        state.updated_ms = now;
    }
    state.score = state.score.saturating_add(INBOUND_VIOLATION_SCORE);
    if map.len() > MAX_BAN_TRACKED {
        // Evict the lowest scores first, keeping banned addresses: the old
        // retain dropped every sub-threshold entry at once, which wiped the
        // 1-per-hour decay ledger for addresses that were merely old, and
        // cost O(n) on every violation past the cap.
        let excess = map.len() - MAX_BAN_TRACKED;
        let mut scores: Vec<(IpAddr, u32)> = map.iter().map(|(ip, s)| (*ip, s.score)).collect();
        scores.sort_unstable_by_key(|(_, s)| *s);
        for (ip, _) in scores.into_iter().take(excess) {
            map.remove(&ip);
        }
    }
}

/// Maximum total connected peers. SPEC.md §13.8.
pub const MAX_PEERS: usize = 125;

/// Maximum inbound connections accepted. SPEC.md §13.8.
pub const MAX_INBOUND: usize = 32;

/// Configuration for the P2P network node.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub params: NetworkParams,
    pub listen_addr: Option<SocketAddr>,
    pub max_peers: usize,
    pub max_inbound: usize,
    pub user_agent: String,
    /// Well-known peers to dial at startup and on every reconnect cycle.
    /// §13.6: v0.2 has no discovery protocol, so the only source of peers is
    /// this configured set plus whatever the address book remembers.
    pub bootnodes: Vec<SocketAddr>,
    /// Where the persistent address book is stored. `None` disables
    /// persistence — the book lives in memory only.
    pub address_book: Option<PathBuf>,
}

impl P2pConfig {
    pub fn new(params: NetworkParams, listen_addr: Option<SocketAddr>) -> Self {
        Self {
            params,
            listen_addr,
            max_peers: MAX_PEERS,
            max_inbound: MAX_INBOUND,
            user_agent: "srct/0.2.0".to_string(),
            bootnodes: Vec::new(),
            address_book: None,
        }
    }
}

/// Everything a poll may mutate, as one borrow.
///
/// These four always travel together: every message handler needs the chain to
/// validate against, the pool to admit into, the sync manager for blocks and the
/// relay manager for transactions. Passing them as four separate arguments is
/// what made `handle_message` an eight-parameter function whose signature had to
/// be suppressed rather than fixed.
///
/// Grouping them also states the invariant the node depends on: all five are
/// mutated by a single thread, so the pool can never be validated against a chain
/// that another thread is moving underneath it.
pub struct NodeState<'a> {
    pub chain: &'a mut Chain,
    pub pool: &'a mut Mempool,
    pub syncer: &'a mut SyncManager,
    pub relay: &'a mut RelayManager,
    /// Inbound arbitration votes, tallied per dispute (Decision 21). Owned by
    /// the node rather than by this layer so it survives across polls; see
    /// `srct_node::mediation` for what the node does with a reaching quorum.
    pub votes: &'a mut srct_core::arbitration::VoteBook,
}

impl<'a> NodeState<'a> {
    /// Reborrow for one call, so the caller keeps ownership of the state.
    ///
    /// Needed because the event loop hands the state to a handler inside a loop:
    /// moving the fields out would compile exactly once.
    pub fn reborrow(&mut self) -> NodeState<'_> {
        NodeState {
            chain: self.chain,
            pool: self.pool,
            syncer: self.syncer,
            relay: self.relay,
            votes: self.votes,
        }
    }
}

/// The P2P network controller.
pub struct P2pNode {
    config: P2pConfig,
    peers: Arc<Mutex<HashMap<usize, PeerHandle>>>,
    inbound_count: Arc<AtomicUsize>,
    next_peer_id: AtomicUsize,
    event_tx: SyncSender<PeerEvent>,
    event_rx: Receiver<PeerEvent>,
    running: Arc<AtomicBool>,
    /// Ban scores by address, for inbound-bound violations (SPEC.md §13.8/§13.9).
    /// v0.2 has no address book (§13.6), so this map is the only place an
    /// address can be remembered, and it is deliberately the only one.
    ban_scores: Arc<Mutex<HashMap<IpAddr, BanState>>>,
    /// Persistent peer address book. Populated from bootnodes and successful
    /// handshakes; the reconnect loop dials from it. `None` when no
    /// `address_book` path was configured.
    address_book: Arc<Mutex<Option<AddressBook>>>,
    listener_thread: Option<JoinHandle<()>>,
}

impl P2pNode {
    /// Bind the listener (if configured) and start the P2P networking layer.
    pub fn start(config: P2pConfig, initial_height: u64, initial_tip: Hash512) -> NetResult<Self> {
        // Bounded on purpose. The reader threads decode at line rate while the
        // event loop validates as fast as it can; an unbounded queue between
        // the two turns that gap into a memory-exhaustion vector (a peer
        // streaming 4 MB frames OOMs the node in seconds while validation
        // stalls). At capacity the reader blocks in `send`, which stops it
        // reading and pushes TCP backpressure onto the sender — the behaviour
        // a bounded queue is supposed to have. 256 comfortably covers honest
        // bursts (sync is at most 64 requests in flight globally) while
        // capping worst-case queued bytes.
        let (event_tx, event_rx) = sync_channel(256);
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let inbound_count = Arc::new(AtomicUsize::new(0));
        let ban_scores = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));

        let listener_thread = if let Some(addr) = config.listen_addr {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;

            let l_peers = Arc::clone(&peers);
            let l_inbound = Arc::clone(&inbound_count);
            let l_table = PeerTable::new(Arc::clone(&peers), Arc::clone(&inbound_count));
            let l_running = Arc::clone(&running);
            let l_event_tx = event_tx.clone();
            let l_bans = Arc::clone(&ban_scores);
            let l_config = config.clone();
            // In-flight handshakes are invisible to `inbound_count` and
            // `peers.len()` (both count only *registered* peers), so without
            // this counter a single IP can open thousands of connections,
            // complete no handshake, and pin one thread plus one socket each —
            // exhausting descriptors long before `max_inbound` ever trips.
            let l_handshakes = Arc::new(AtomicUsize::new(0));

            Some(thread::spawn(move || {
                let mut peer_id_counter = 100_000usize; // Separate space for inbound IDs

                while l_running.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, peer_addr)) => {
                            // The listener is non-blocking so `accept` can poll.
                            // On Windows an accepted socket *inherits*
                            // WSA_FLAG_NON_BLOCKED, which makes the blocking,
                            // timeout-based handshake underneath fail
                            // immediately with `WouldBlock` — every inbound
                            // connection was refused on that platform. Clear
                            // the flag explicitly rather than relying on the
                            // platform default.
                            if let Err(_e) = stream.set_nonblocking(false) {
                                drop(stream);
                                continue;
                            }
                            // Inbound bounds first, and they *ban* rather than
                            // merely close (§13.8). `max_peers` is checked as
                            // well as `max_inbound`: it caps the total thread and
                            // descriptor count, which `max_inbound` alone does
                            // not once a node makes its own outbound connections.
                            if is_banned(&l_bans, peer_addr.ip()) {
                                drop(stream);
                                continue;
                            }
                            if l_inbound.load(Ordering::Relaxed) >= l_config.max_inbound
                                || l_peers.lock().unwrap_or_else(|e| e.into_inner()).len()
                                    >= l_config.max_peers
                                || l_handshakes.load(Ordering::Relaxed) >= l_config.max_inbound
                            // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                            {
                                score_violation(&l_bans, peer_addr.ip());
                                drop(stream);
                                continue;
                            }

                            let hs_config = HandshakeConfig::new(
                                l_config.params.clone(),
                                initial_height,
                                initial_tip,
                            );

                            peer_id_counter += 1;
                            let pid = peer_id_counter;
                            let p_table = l_table.clone();
                            let p_event_tx = l_event_tx.clone();
                            let p_params = l_config.params.clone();
                            let h_count = Arc::clone(&l_handshakes);
                            h_count.fetch_add(1, Ordering::Relaxed);
                            // Cloned outside the handshake thread: the inner
                            // `move` closure would otherwise capture `l_bans`
                            // (and `peer_addr`) out of the accept loop.
                            let p_bans = Arc::clone(&l_bans);
                            let p_addr = peer_addr;

                            thread::spawn(move || {
                                match perform_handshake(&mut stream, &hs_config, false) {
                                    Ok(ver) => {
                                        // `spawn_peer` registers the peer and
                                        // counts the inbound slot itself, and it
                                        // does both before starting the reader
                                        // thread. Its comment explains why the
                                        // ordering matters.
                                        let _ = spawn_peer(
                                            pid, stream, ver, false, p_params, p_event_tx, p_table,
                                        );
                                    }
                                    Err(_) => {
                                        // Handshake failed or rejected: score
                                        // it. A wrong-magic or replayed
                                        // handshake is a misbehaving peer,
                                        // not weather — without scoring,
                                        // only connection *volume* was
                                        // gated while handshake spam that
                                        // passes the volume check was free.
                                        // The score is per-IP, so a test or
                                        // NAT peer that fails once is not
                                        // banned: five strikes make a ban.
                                        let ip = stream
                                            .peer_addr()
                                            .map(|a| a.ip())
                                            .unwrap_or(p_addr.ip());
                                        score_violation(&p_bans, ip);
                                        drop(stream);
                                    }
                                }
                                h_count.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            }))
        } else {
            None
        };

        let address_book = match &config.address_book {
            Some(path) => Arc::new(Mutex::new(Some(AddressBook::new(path)))),
            None => Arc::new(Mutex::new(None)),
        };

        Ok(Self {
            config,
            peers,
            inbound_count,
            next_peer_id: AtomicUsize::new(1),
            event_tx,
            event_rx,
            running,
            ban_scores,
            address_book,
            listener_thread,
        })
    }

    /// Connect to a remote peer address as an initiator.
    pub fn connect(&self, addr: SocketAddr, chain: &Chain) -> NetResult<usize> {
        self.connect_with_timeout(addr, chain, CONNECT_TIMEOUT)
    }

    /// Connect with a configurable TCP timeout. The default `connect` uses
    /// `CONNECT_TIMEOUT` (§13.8); `reconnect` uses a shorter one so a dead
    /// bootnode does not stall the serve loop.
    fn connect_with_timeout(
        &self,
        addr: SocketAddr,
        chain: &Chain,
        timeout: Duration,
    ) -> NetResult<usize> {
        // SPEC.md §13.8 bounds `max_peers` as the cap on thread and descriptor
        // count. It was never enforced here, so a node could open as many
        // outbound connections as it had addresses and blow past the bound the
        // rest of the design assumes.
        if self.peer_count() >= self.config.max_peers {
            return Err(NetError::Resource(format!(
                "peer limit reached ({} configured, {} connected)",
                self.config.max_peers,
                self.peer_count()
            )));
        }
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        let hs_config =
            HandshakeConfig::new(self.config.params.clone(), chain.height(), chain.tip_hash());

        let ver = perform_handshake(&mut stream, &hs_config, true)?;
        let peer_id = self.next_peer_id.fetch_add(1, Ordering::Relaxed);

        let handle = spawn_peer(
            peer_id,
            stream,
            ver,
            true,
            self.config.params.clone(),
            self.event_tx.clone(),
            PeerTable::new(Arc::clone(&self.peers), Arc::clone(&self.inbound_count)),
        )?;

        // Send initial GETBLOCKS locator to sync with the new peer
        let locator = create_locator(chain);
        let _ = handle.send(Message::GetBlocks {
            locator,
            stop: ZERO_HASH512,
        });

        // `spawn_peer` already registered it, before its reader thread started.
        Ok(peer_id)
    }

    /// Attempt to reconnect to bootnodes and address-book peers that are not
    /// currently connected.
    ///
    /// Called once per serve-loop cycle. Tries at most
    /// `RECONNECT_ATTEMPTS_PER_CYCLE` addresses per call, so a single dead
    /// bootnode costs one `RECONNECT_TIMEOUT` (3 s) rather than stalling the
    /// whole loop. Randomizes the candidate order for eclipse resistance
    /// (§13.6: without authenticated discovery, random order is the only
    /// defence against an adversary feeding us only its own connections).
    ///
    /// Returns the number of peers dialed this cycle, regardless of success.
    pub fn reconnect(&self, chain: &Chain) -> usize {
        // Collect candidate addresses and current peer state under the lock,
        // then drop it before dialing so `connect_with_timeout` can acquire it
        // without a deadlock.
        let (candidates, outbound_count, total_count) = {
            let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // invariant: poison needs a prior panic
            let outbound_count = peers.values().filter(|p| p.is_outbound).count();
            let total = peers.len();

            // Addresses already connected — never dial a peer we hold.
            let connected: HashSet<SocketAddr> = peers.values().map(|p| p.remote_addr).collect();

            let mut cands: Vec<SocketAddr> = Vec::new();

            // Bootnodes first — they are the highest-priority reconnect targets.
            for &b in &self.config.bootnodes {
                if !connected.contains(&b) && !self.is_banned(b.ip()) {
                    cands.push(b);
                }
            }

            // Then the address book, in most-recent-first order.
            // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
            if let Some(ab) = self
                .address_book
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                for addr in ab.addresses() {
                    if !connected.contains(&addr) && !self.is_banned(addr.ip()) {
                        cands.push(addr);
                    }
                }
            }

            (cands, outbound_count, total)
        };

        // §13.8 eclipse-resistance heuristic: cap outbound at 50% of max_peers.
        let max_outbound = self.config.max_peers / 2;
        let remaining = max_outbound.saturating_sub(outbound_count);
        if remaining == 0 || total_count >= self.config.max_peers {
            return 0;
        }

        // Randomize candidate order so an adversarial address book cannot force
        // a deterministic (and attackable) connection sequence.
        let mut rng = thread_rng();
        let mut shuffled = candidates;
        shuffled.shuffle(&mut rng);

        // Try up to `RECONNECT_ATTEMPTS_PER_CYCLE` addresses this cycle.
        let to_try = shuffled
            .into_iter()
            .take(remaining.min(RECONNECT_ATTEMPTS_PER_CYCLE));

        let mut dialed = 0;
        for addr in to_try {
            match self.connect_with_timeout(addr, chain, RECONNECT_TIMEOUT) {
                Ok(id) => {
                    println!("reconnected peer {id} -> {addr}");
                    dialed += 1;
                    // Record the address in the book.
                    // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                    if let Some(ab) = self
                        .address_book
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_mut()
                    {
                        ab.add(addr);
                    }
                }
                Err(e) => {
                    eprintln!("warn: reconnect {addr}: {e}");
                }
            }
        }

        dialed
    }

    /// Broadcast an inventory announcement to all peers except `exclude_peer`.
    pub fn broadcast_inv(&self, entries: Vec<InvEntry>, exclude_peer: Option<usize>) {
        let msg = Message::Inv(entries);
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
        for (id, peer) in peers.iter() {
            if Some(*id) != exclude_peer {
                let _ = peer.send(msg.clone());
            }
        }
    }

    /// Announce a new canonical block to all peers.
    pub fn broadcast_block(&self, block_hash: Hash512, exclude_peer: Option<usize>) {
        self.broadcast_inv(
            vec![InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: block_hash,
            }],
            exclude_peer,
        );
    }

    /// Relay a checkpoint certificate to every peer (M5, Decisions 12/14).
    ///
    /// Unlike a block or a transaction this carries the full certificate rather
    /// than an announcement, because a certificate is meaningless without its
    /// signature and there is nothing to fetch it by — there is no checkpoint
    /// store to serve a getdata from.
    ///
    /// The caller must have verified the certificate against its own chain first
    /// (`Chain::apply_checkpoint`), for the same reason `broadcast_tx` takes
    /// only txids: relaying something the node does not itself hold as valid
    /// would make it an amplifier. A peer receiving an invalid one refuses it
    /// the same way and does not re-relay.
    pub fn broadcast_checkpoint(&self, cp: srct_core::bls_checkpoint::Checkpoint) {
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
        for peer in peers.values() {
            let _ = peer.send(crate::msg::Message::Checkpoint(cp.clone()));
        }
    }

    /// Relay a signed arbitration vote to every peer (Decision 21, SPEC.md §16).
    ///
    /// Complete vote rather than an announcement, for the same reason
    /// `broadcast_checkpoint` carries the whole certificate: there is no vote
    /// store to serve a getdata from and the signature is the content.
    ///
    /// The caller must have verified the signature itself first — `VoteTally::
    /// record` does, against this node's own committee — for the same reason
    /// `broadcast_tx` takes only txids: relaying something the node does not
    /// itself hold as valid would make it an amplifier. A peer receiving a vote
    /// that fails its own checks drops it and does not re-relay, so a bad vote
    /// travels at most one hop.
    pub fn broadcast_vote(&self, vote: srct_core::arbitration::ArbitrationVote) {
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
        for peer in peers.values() {
            let _ = peer.send(crate::msg::Message::ArbitrationVote(Box::new(vote.clone())));
        }
    }

    /// Announce transaction ids to all peers except `exclude_peer` (§13.14).
    ///
    /// The caller is expected to have admitted these to its own pool first.
    /// Announcing something the node did not accept would make it an amplifier
    /// for data it knows to be invalid, which §13.14 forbids — so this function
    /// deliberately takes txids rather than transactions: the only way to have a
    /// txid is to have the transaction, and the only way to have a transaction
    /// the node will relay is to have pooled it.
    pub fn broadcast_tx(&self, txids: &[Hash512], exclude_peer: Option<usize>) {
        if txids.is_empty() {
            return;
        }
        self.broadcast_inv(
            txids
                .iter()
                .map(|h| InvEntry {
                    kind: INV_TYPE_TX,
                    hash: *h,
                })
                .collect(),
            exclude_peer,
        );
    }

    /// Process all pending network events against the chain, mempool and sync
    /// manager. Returns the number of events processed.
    ///
    /// The mutable state is borrowed rather than owned by `P2pNode` for the same
    /// reason `Chain` is: the mempool is validated against chain state, so all of
    /// it has to be in the same hands to be consistent, and only the chain thread
    /// mutates any of it. See [`NodeState`].
    pub fn poll_events(&self, mut state: NodeState<'_>, now_ms: Option<u64>) -> usize {
        let mut count = 0;

        // Peers stopped since the last call are released here rather than waiting
        // for their reader thread to report the disconnect itself. See
        // `swept_stopped_peers` for why that wait is not something to depend on.
        for peer_id in self.swept_stopped_peers() {
            self.release_peer(peer_id, state.syncer, state.relay);
        }

        while let Ok(event) = self.event_rx.try_recv() {
            count += 1;
            match event {
                PeerEvent::Connected {
                    peer_id,
                    version,
                    remote_addr,
                    ..
                } => {
                    // Record the address in the book for future reconnects.
                    // Inbound addresses are as valid a reconnect source as
                    // outbound — the peer was reachable, so it may be again.
                    // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                    if let Some(ab) = self
                        .address_book
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_mut()
                    {
                        ab.add(remote_addr);
                    }

                    // If the peer is ahead, ask for blocks
                    if version.height > state.chain.height() {
                        let locator = create_locator(state.chain);
                        if let Some(peer) = self
                            .peers
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&peer_id)
                        {
                            // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                            let _ = peer.send(Message::GetBlocks {
                                locator,
                                stop: ZERO_HASH512,
                            });
                        }
                    }
                    // Announce what this node already holds. Without this, a
                    // transaction pooled *before* this connection existed is
                    // never relayed to it: `broadcast_tx` reaches the peers
                    // connected at the time, and there were none. That is the
                    // ordinary case for a node that has been running a while and
                    // then gains a peer, so the pool would only ever propagate
                    // transactions that happened to arrive after the last
                    // connection.
                    //
                    // Bounded by `max_inv_per_msg` and by the pool's own size,
                    // and the pool is already bounded by bytes.
                    let entries: Vec<InvEntry> = state
                        .pool
                        .txids()
                        .into_iter()
                        .take(MAX_INV_PER_MSG)
                        .map(|hash| InvEntry {
                            kind: INV_TYPE_TX,
                            hash,
                        })
                        .collect();
                    if !entries.is_empty() {
                        if let Some(peer) = self
                            .peers
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&peer_id)
                        {
                            // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                            let _ = peer.send(Message::Inv(entries));
                        }
                    }
                }
                PeerEvent::Disconnected { peer_id, .. } => {
                    // Release everything queued for / owed by that peer before
                    // dropping the handle, so its hashes can be served by
                    // another connection instead of stalling sync (§13.7).
                    self.release_peer(peer_id, state.syncer, state.relay);
                }
                PeerEvent::Message { peer_id, msg } => {
                    // A message from a peer the node no longer tracks is dropped:
                    // it is work owed by a connection that no longer exists. This
                    // is what stops a banned peer's already-queued frames from
                    // still reaching the pool, the relay bookkeeping and the
                    // chain, and it is the reason the sweep can release a stopped
                    // peer without waiting for its reader.
                    //
                    // The test is membership, deliberately *not* the stop flag.
                    // The flag is also set by the reader thread when a stream
                    // simply ends, and a peer that closed cleanly can have
                    // messages queued ahead of its disconnect report — including
                    // a transaction it had already delivered. Rejecting those
                    // would discard a valid transaction from an honest peer at
                    // the moment it hung up. Membership has no such ambiguity: a
                    // peer is registered before its reader thread starts (see
                    // `spawn_peer`) and released only once the node has decided
                    // the connection is over.
                    if !self
                        .peers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains_key(&peer_id)
                    {
                        // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                        continue;
                    }
                    self.handle_message(peer_id, msg, state.reborrow(), now_ms);
                }
            }
        }

        // A peer can also be stopped by the messages just processed — that is
        // what a ban is — and the caller should see the effect of one call, not
        // have to make another.
        for peer_id in self.swept_stopped_peers() {
            self.release_peer(peer_id, state.syncer, state.relay);
        }

        count
    }

    /// Release everything a peer owned and drop it from the live set.
    ///
    /// Shared by the reader thread's `Disconnected` event and the sweep for
    /// stopped peers, so the two paths cannot drift apart. Idempotent: releasing
    /// a peer that is already gone does nothing.
    fn release_peer(&self, peer_id: usize, syncer: &mut SyncManager, relay: &mut RelayManager) {
        syncer.peer_disconnected(peer_id);
        relay.peer_disconnected(peer_id);
        if let Some(p) = self
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&peer_id)
        {
            // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
            if !p.is_outbound {
                self.inbound_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Peers that have been stopped but are still in the live set.
    ///
    /// `PeerHandle::stop()` shuts the socket down, but a reader thread parked in
    /// a blocking read with a 60 s timeout does not reliably wake for that. On
    /// Windows it demonstrably does not: a peer banned for ten invalid
    /// transactions stayed in the peer table for the whole of a test that polled
    /// for over a second, and its reader thread only returned at teardown. The
    /// node is then left believing it has a peer it has already banned — the slot
    /// counts against `max_peers`, broadcasts still queue for it, and nothing
    /// releases the sync or relay state it owes. The sweep makes the removal
    /// independent of a thread that may be asleep for a minute.
    ///
    /// The flag is the authority because `stop()` is the only thing that sets it,
    /// and it is set before the socket is touched.
    fn swept_stopped_peers(&self) -> Vec<usize> {
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
        peers
            .iter()
            // Only peers that have been ended *and* whose reader has not reported
            // it yet. Once the reader has finished, the `Disconnected` event is
            // already queued behind everything else that peer sent, and releasing
            // it here would jump that queue and drop its last messages.
            .filter(|(_, p)| p.is_stopped() && !p.has_reader_exited())
            .map(|(id, _)| *id)
            .collect()
    }

    fn handle_message(
        &self,
        peer_id: usize,
        msg: Message,
        state: NodeState<'_>,
        now_ms: Option<u64>,
    ) {
        // Destructured rather than reached through `state.` at every use: the
        // handlers below read the way they did before the state was grouped, and
        // a reborrow of four fields is not worth rewriting two hundred lines of
        // message handling to spell out.
        let NodeState {
            chain,
            pool,
            syncer,
            relay,
            votes,
        } = state;
        match msg {
            Message::GetBlocks { locator, stop } => {
                let inv = find_fork_and_collect_inv(chain, &locator, &stop);
                if !inv.is_empty() {
                    let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                    if let Some(peer) = peers.get(&peer_id) {
                        let _ = peer.send(Message::Inv(inv));
                    }
                }
            }
            Message::Inv(entries) => {
                // Blocks and transactions share `INV`, separated by `kind`
                // (§13.5). Splitting here rather than teaching the sync manager
                // about transactions keeps the two mechanisms independent: a
                // change to relay policy cannot alter block sync.
                let (block_entries, tx_entries): (Vec<InvEntry>, Vec<InvEntry>) =
                    entries.into_iter().partition(|e| e.kind == INV_TYPE_BLOCK);
                let to_request = syncer.handle_inv(peer_id, &block_entries, chain);
                self.send_get_data(peer_id, to_request);
                let tx_request = relay.handle_inv_tx(
                    peer_id,
                    &tx_entries,
                    pool,
                    now_ms.unwrap_or_else(crate::net::now_ms),
                );
                self.send_get_data(peer_id, tx_request);
            }
            Message::GetData(entries) => {
                let (block_entries, tx_entries): (Vec<InvEntry>, Vec<InvEntry>) =
                    entries.into_iter().partition(|e| e.kind == INV_TYPE_BLOCK);
                let blocks = syncer.handle_get_data(
                    &block_entries,
                    chain,
                    self.config.params.max_block_bytes,
                );
                // Bounded to one block's worth of transaction data: the request
                // is capped by `max_inv_per_msg`, but without this the response
                // would not be, and a peer could ask for 500 transactions and
                // receive gigabytes (§13.14).
                let txs =
                    relay.handle_get_data_tx(&tx_entries, pool, self.config.params.max_block_bytes);
                let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                if let Some(peer) = peers.get(&peer_id) {
                    for b in blocks {
                        let _ = peer.send(Message::Block(Box::new(b)));
                    }
                    for t in txs {
                        let _ = peer.send(Message::Tx(Box::new(t)));
                    }
                }
            }
            Message::Tx(tx) => {
                // Rate limit before validating. Decoding already happened, but
                // `check_tx` touches the whole UTXO set per input, so the
                // expensive work is behind this gate.
                let clock = now_ms.unwrap_or_else(crate::net::now_ms);
                if !relay.allow_from(peer_id, clock) {
                    // An inbound bound was exceeded, and §13.8 requires that this
                    // *bans* rather than merely dropping: dropping alone leaves
                    // the node doing the decoding work for every message.
                    let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                    if let Some(peer) = peers.get(&peer_id) {
                        peer.add_ban_score(INBOUND_VIOLATION_SCORE);
                    }
                    return;
                }

                let tx = *tx;
                let txid = tx.txid();
                // Whether or not we accept it, the request slot is finished.
                // Holding it would let a peer stall relay indefinitely by
                // answering with junk.
                relay.release(&txid);

                let outcome = pool.add(
                    tx,
                    chain.utxo(),
                    chain.height() + 1,
                    chain.params(),
                    chain.expected_base_fee_for_next_block(),
                    chain.bonds(),
                );
                match outcome {
                    Ok(_) => {
                        relay.mark_known(txid);
                        relay.note_accepted();
                        self.broadcast_tx(&[txid], Some(peer_id));
                    }
                    // Normal, not misbehaviour: two peers relaying the same
                    // transaction is what a network looks like.
                    Err(MempoolError::AlreadyKnown) => relay.mark_known(txid),
                    // Valid on its own terms; we disagree about price, or we
                    // already hold the conflicting spend. §13.9 makes exactly
                    // this argument about a block that fails validation: a peer
                    // racing us to a fee update is honest, and banning it would
                    // disconnect honest peers exactly when the network is busy.
                    Err(MempoolError::Underpaid { .. })
                    | Err(MempoolError::Conflict { .. })
                    | Err(MempoolError::Full) => {
                        relay.mark_known(txid);
                        relay.note_refused();
                    }
                    // Fails `check_tx`, or cannot fit a block. +10, so repeated
                    // abuse bans and a single honest race does not. Note this is
                    // not a ban: a node that is behind on sync will legitimately
                    // see spends of outputs it has not received yet.
                    Err(MempoolError::Invalid(_)) | Err(MempoolError::Oversized { .. }) => {
                        relay.mark_known(txid);
                        relay.note_refused();
                        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                        if let Some(peer) = peers.get(&peer_id) {
                            peer.add_ban_score(10);
                        }
                    }
                    // Unreachable here: `add` holds one lock for the whole
                    // call, so nothing can move the state it verified against.
                    // Kept exhaustively because `commit_admission` can return
                    // it and dropping an arm silently would hide a future
                    // split of this path.
                    Err(MempoolError::Stale) => relay.mark_known(txid),
                }
            }
            Message::Block(block) => {
                let block_val = *block;
                let outcome = syncer.handle_block(block_val, chain, now_ms);
                match outcome {
                    SyncResult::Accepted {
                        extended_tip,
                        new_tip,
                        orphans_resolved,
                    } => {
                        if extended_tip {
                            // Relay the new tip to all other peers
                            self.broadcast_block(new_tip, Some(peer_id));
                            for orphan_hash in orphans_resolved {
                                self.broadcast_block(orphan_hash, Some(peer_id));
                            }
                        }
                    }
                    SyncResult::Orphan { missing_parent } => {
                        // Request missing parent block from this peer
                        self.send_get_data(
                            peer_id,
                            vec![InvEntry {
                                kind: INV_TYPE_BLOCK,
                                hash: missing_parent,
                            }],
                        );
                    }
                    SyncResult::AlreadyKnown => {}
                    SyncResult::Invalid(_) => {
                        // Misbehaviour score +10 for an invalid block (§13.9)
                        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                        if let Some(peer) = peers.get(&peer_id) {
                            peer.add_ban_score(10);
                        }
                    }
                }
                // Keep the window moving: one block applied frees one request
                // slot, so ask for the next batch. Without this the requester
                // stops after the first batch and never finishes syncing
                // (§13.7 "and repeats").
                let next = syncer.take_batch(peer_id);
                self.send_get_data(peer_id, next);
            }
            Message::Addr(_) | Message::Unknown { .. } | Message::Pong { .. } => {
                // Ignored per spec
            }
            Message::Checkpoint(cp) => {
                // Rate-gated before `apply_checkpoint`: acceptance runs a real
                // BLS aggregate pairing, and the epoch/bitmap/quorum are public,
                // so forged-but-structurally-valid certificates are cheap to
                // produce and expensive to verify (§13.8).
                let clock = now_ms.unwrap_or_else(crate::net::now_ms);
                if !relay.allow_control_from(peer_id, clock) {
                    let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                    if let Some(peer) = peers.get(&peer_id) {
                        peer.add_ban_score(INBOUND_VIOLATION_SCORE);
                    }
                    return;
                }
                // M5 binding finality (Decisions 12/14). Apply the certificate
                // through the chain, which verifies it, binds it to the
                // canonical block at its height, and records any conflict
                // evidence. On acceptance we relay it; on any rejection we do
                // not — a bad or conflicting certificate must not propagate.
                // `RealBls` is pairing-checked, so a forged aggregate is
                // rejected here rather than merely counted.
                //
                // H3: a conflicting certificate is a quorum signing two
                // histories — the one condition that can lock the network onto
                // a forged branch (C2/H3). Cheap forgeries fail verification
                // silently, but a *conflict* means real keys equivocated, so
                // it gets a loud alert instead of a quiet drop. No ban: the
                // peer may be honestly relaying evidence, not attacking.
                match chain.apply_checkpoint(&cp, &srct_core::bls::RealBls) {
                    Ok(()) => {
                        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                        for (id, peer) in peers.iter() {
                            if *id != peer_id {
                                let _ = peer.send(Message::Checkpoint(cp.clone()));
                            }
                        }
                    }
                    Err(srct_core::finality::FinalityError::ConflictingFinality {
                        height,
                        finalized,
                        conflicting,
                    }) => {
                        // Rare path (a conflict means a quorum signed two
                        // histories), so a small allocation here is fine.
                        let short = |h: &srct_core::hash::Hash512| {
                            h.iter()
                                .take(8)
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        };
                        eprintln!(
                            "ALERT: conflicting finality at height {height}: quorum signed \
                             {}... but this node finalized {}... — possible forged-finality \
                             branch (C2/H3); refusing to reorg, not relaying",
                            short(&conflicting),
                            short(&finalized),
                        );
                    }
                    Err(_) => {}
                }
            }
            Message::ArbitrationVote(vote) => {
                // Same gate as checkpoints: `record` runs a BLS pairing per
                // vote, and votes are as cheap to forge structurally as
                // certificates are (§13.8).
                let clock = now_ms.unwrap_or_else(crate::net::now_ms);
                if !relay.allow_control_from(peer_id, clock) {
                    let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                    if let Some(peer) = peers.get(&peer_id) {
                        peer.add_ban_score(INBOUND_VIOLATION_SCORE);
                    }
                    return;
                }
                // Fraud arbitration (Decision 21). Record the vote against this
                // node's own committee and height — never against the sender's
                // say-so — then relay only what this node itself accepts, so a
                // vote that fails verification here does not travel further.
                //
                // The tally is a transport accumulator: the quorum is this
                // layer's judgement and nothing more, and `srct_node::mediation`
                // re-verifies the aggregate from the votes before anything is
                // proposed.
                let committee = chain.committee_keys();
                let quorum = {
                    let set = srct_core::bls_checkpoint::ValidatorSet::new(committee.clone());
                    set.quorum_size()
                };
                let height = chain.height();
                // `entry` creates a tally for any task id it is handed, so a
                // flood of distinct ids would grow the book without bound —
                // each rejected vote still allocating a tally. Cap the book;
                // an already-known dispute is always allowed through.
                let accepted = (votes.tally(&vote.task_id).is_some()
                    || votes.len() < MAX_VOTE_TALLIES)
                    && votes
                        .entry(vote.task_id, quorum)
                        .record(&vote, &chain.params().network_id, height, &committee)
                        .is_ok();
                if accepted {
                    let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
                    for (id, peer) in peers.iter() {
                        if *id != peer_id {
                            let _ = peer.send(Message::ArbitrationVote(vote.clone()));
                        }
                    }
                }
            }
            Message::Version(_) | Message::Verack { .. } | Message::Ping { .. } => {
                // Handled in peer thread
            }
        }
    }

    /// Number of active connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).len() // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
    }

    /// Whether an address is currently banned for inbound-bound violations.
    /// Also applies the §13.9 decay, so this is the authoritative answer rather
    /// than a raw table read.
    pub fn is_banned(&self, addr: IpAddr) -> bool {
        is_banned(&self.ban_scores, addr)
    }

    /// Addresses currently at or over the ban threshold.
    pub fn banned_count(&self) -> usize {
        let mut map = self.ban_scores.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
        let now = now_ms();
        let mut count = 0;
        for state in map.values_mut() {
            let hours = now.saturating_sub(state.updated_ms) / 3_600_000;
            if hours > 0 {
                state.score = state.score.saturating_sub(hours as u32);
                state.updated_ms = now;
            }
            if state.score >= BAN_SCORE_THRESHOLD {
                count += 1;
            }
        }
        count
    }

    /// Send a `GETDATA` to one peer, if it is still connected.
    fn send_get_data(&self, peer_id: usize, entries: Vec<InvEntry>) {
        if entries.is_empty() {
            return;
        }
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
        if let Some(peer) = peers.get(&peer_id) {
            let _ = peer.send(Message::GetData(entries));
        }
    }

    /// Stop the network listener and all peer threads.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
        for peer in peers.values() {
            peer.stop();
        }
    }
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self.stop();
        if let Some(handle) = self.listener_thread.take() {
            let _ = handle.join();
        }
    }
}
