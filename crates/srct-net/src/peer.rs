//! Peer connection lifecycle and handshake state machine. SPEC.md §13.4, §13.9.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use srct_core::block::genesis_block;
use srct_core::hash::Hash512;
use srct_core::params::NetworkParams;

use crate::error::{NetError, NetResult};
use crate::frame::{read_frame, write_frame};
use crate::magic::check_network;
use crate::msg::{Message, MessageType, Version, PROTOCOL_VERSION};

/// Timeout for completing the initial handshake. SPEC.md §13.8.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Ban threshold score. Reaching or exceeding 100 disconnects and bans. §13.8.
pub const BAN_SCORE_THRESHOLD: u32 = 100;

/// Cap on queued outbound messages per peer. The old channel was unbounded:
/// a slow (or deliberately stalled) peer accumulated every broadcast while its
/// writer thread waited on a full socket buffer, growing memory without bound
/// — one stalled peer could pin gigabytes while the node believed it was
/// merely "behind". A full queue now drops the peer instead of the memory
/// budget: the writer drains oldest-first and `send` refuses rather than
/// queuing past this.
pub const OUTBOUND_QUEUE_MAX: usize = 128;

/// Local node handshake configuration.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    pub params: NetworkParams,
    pub height: u64,
    pub tip_hash: Hash512,
    pub user_agent: String,
    pub services: u64,
}

impl HandshakeConfig {
    pub fn new(params: NetworkParams, height: u64, tip_hash: Hash512) -> Self {
        Self {
            params,
            height,
            tip_hash,
            user_agent: "srct/0.2.0".to_string(),
            services: 1, // bit 0 = serves blocks
        }
    }
}

/// Events emitted by peer connections to the chain / network manager.
#[derive(Debug)]
pub enum PeerEvent {
    Connected {
        peer_id: usize,
        remote_addr: SocketAddr,
        version: Version,
        is_outbound: bool,
    },
    Disconnected {
        peer_id: usize,
        reason: String,
    },
    Message {
        peer_id: usize,
        msg: Message,
    },
}

/// Handle to communicate with an active peer.
#[derive(Clone)]
pub struct PeerHandle {
    pub id: usize,
    pub remote_addr: SocketAddr,
    pub version: Version,
    pub is_outbound: bool,
    tx: SyncSender<Message>,
    ban_score: Arc<AtomicU32>,
    stopped: Arc<AtomicBool>,
    /// A handle on the socket, so `stop()` can actually close the connection.
    /// Setting a flag alone left the reader thread parked in `read_frame` for
    /// up to the 60 s read timeout, still consuming a thread and still able to
    /// deliver events for a peer the node believed it had dropped.
    socket: Arc<TcpStream>,
    /// Set by the reader thread when its loop ends, immediately before it reports
    /// the disconnect.
    ///
    /// Deliberately **not** `stopped`. Two different situations were sharing one
    /// flag: `stop()` means "we ended this peer", while the reader leaving its
    /// loop means "this peer's stream ended". On a normal close the reader may
    /// still have events queued — including a transaction it has already read and
    /// handed over — and treating the second as the first discarded a peer's last
    /// message as it was being delivered.
    reader_done: Arc<AtomicBool>,
}

/// The node's live peer table and inbound counter, as one thing.
///
/// Given to `spawn_peer` so a new peer can register itself *before* its reader
/// thread starts. Keeping the two together is deliberate: a peer that is
/// registered but not counted, or counted but not registered, is a slot that
/// either leaks or is invisible to `max_peers` (§13.8).
#[derive(Clone)]
pub struct PeerTable {
    live: Arc<Mutex<HashMap<usize, PeerHandle>>>,
    inbound: Arc<AtomicUsize>,
}

impl PeerTable {
    pub fn new(live: Arc<Mutex<HashMap<usize, PeerHandle>>>, inbound: Arc<AtomicUsize>) -> Self {
        Self { live, inbound }
    }

    /// Add a peer, counting an inbound slot for it if applicable.
    pub fn register(&self, handle: PeerHandle) {
        if !handle.is_outbound {
            self.inbound.fetch_add(1, Ordering::Relaxed);
        }
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handle.id, handle); // poison-tolerant: a prior panic while holding the lock must not cascade into a node shutdown
    }
}

impl PeerHandle {
    /// Send a message to this peer.
    pub fn send(&self, msg: Message) -> NetResult<()> {
        if self.stopped.load(Ordering::Relaxed) {
            return Err(NetError::Peer("peer disconnected".into()));
        }
        // `try_send`: never grow past `OUTBOUND_QUEUE_MAX`. A slow peer's
        // queue filling up is a disconnect, not backpressure on the event
        // loop — blocking here would stall every other peer behind one.
        match self.tx.try_send(msg) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.stop();
                Err(NetError::Peer("peer outbound queue full".into()))
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                Err(NetError::Peer("peer channel closed".into()))
            }
        }
    }

    /// Current misbehaviour ban score.
    pub fn ban_score(&self) -> u32 {
        self.ban_score.load(Ordering::Relaxed)
    }

    /// Whether this peer has been stopped.
    ///
    /// `stop()` is the only thing that sets this, and it sets it *before* it
    /// touches the socket, so this flag is the first and most reliable signal
    /// that a connection has been ended. Everything downstream is slower than
    /// it: the reader thread has to notice the closed socket and the event loop
    /// has to process the resulting `Disconnected`, neither of which is
    /// guaranteed to happen promptly — or, on Windows, at all before the read
    /// timeout expires.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Whether this peer's reader thread has finished.
    ///
    /// When it has, the `Disconnected` event is already on its way — the reader
    /// sends it immediately after setting this — so everything that peer said is
    /// ahead of that event in the queue and will be processed in order. A peer
    /// that is stopped *and* still being read from is the case that cannot wait:
    /// it has been ended, and its reader may not wake for a minute.
    pub fn has_reader_exited(&self) -> bool {
        self.reader_done.load(Ordering::Relaxed)
    }

    /// Add to the peer's ban score. If threshold is reached, disconnects.
    ///
    /// Saturating: at the boundary the score clamps at `u32::MAX` instead of
    /// wrapping to a small number that would un-ban a hostile peer.
    pub fn add_ban_score(&self, score: u32) {
        // CAS loop (no `fetch_update`: MSRV 1.75 predates it). The score
        // only moves up by at most `score` per call, so the loop
        // terminates; contention is one thread per peer.
        let prev = loop {
            let prev = self.ban_score.load(Ordering::SeqCst);
            let next = prev.saturating_add(score);
            match self.ban_score.compare_exchange_weak(
                prev,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break prev,
                Err(_) => continue,
            }
        };
        if prev.saturating_add(score) >= BAN_SCORE_THRESHOLD {
            self.stop();
        }
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        // Unblock the reader immediately rather than waiting for a timeout.
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

/// Perform the SPEC.md §13.4 handshake on a raw stream.
///
/// Both directions exchange `VERSION` and `VERACK`.
pub fn perform_handshake(
    stream: &mut TcpStream,
    config: &HandshakeConfig,
    is_initiator: bool,
) -> NetResult<Version> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let genesis = genesis_block(config.params.genesis_difficulty);
    let genesis_hash = genesis.block_hash();

    // Unique nonce for handshake challenge
    let local_nonce = generate_nonce();

    let local_version = Version {
        network_magic: config.params.network_magic,
        network_id: config.params.network_id.clone(),
        protocol_version: PROTOCOL_VERSION,
        services: config.services,
        height: config.height,
        tip_hash: config.tip_hash,
        user_agent: config.user_agent.clone(),
        nonce: local_nonce,
    };

    let peer_version = if is_initiator {
        // Initiator sends VERSION first
        let ver_payload = Message::Version(local_version).encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Version as u8,
            &ver_payload,
        )?;

        // Wait for peer's VERSION
        let (ty, payload) = read_frame(stream, &config.params)?;
        if ty != MessageType::Version as u8 {
            return Err(NetError::Protocol(format!(
                "expected VERSION (1), got {ty}"
            )));
        }
        let ver = match Message::decode(ty, &payload)? {
            Message::Version(v) => v,
            // `decode` dispatches on the type byte, so this arm is unreachable
            // as long as the two stay in lockstep. Refusing by name rather than
            // `unreachable!()` keeps a future decode change a protocol error
            // instead of a panic on network-controlled bytes.
            _ => {
                return Err(NetError::Protocol(
                    "VERSION frame did not decode to a VERSION message".into(),
                ))
            }
        };

        validate_peer_version(&ver, &config.params, &genesis_hash, local_nonce)?;

        // Send VERACK with peer's nonce
        let verack_payload = Message::Verack { nonce: ver.nonce }.encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Verack as u8,
            &verack_payload,
        )?;

        // Wait for peer's VERACK
        let (ack_ty, ack_payload) = read_frame(stream, &config.params)?;
        if ack_ty != MessageType::Verack as u8 {
            return Err(NetError::Protocol(format!(
                "expected VERACK (2), got {ack_ty}"
            )));
        }
        match Message::decode(ack_ty, &ack_payload)? {
            Message::Verack { nonce } => {
                if nonce != local_nonce {
                    return Err(NetError::Protocol(format!(
                        "VERACK nonce mismatch: got {nonce}, expected {local_nonce}"
                    )));
                }
            }
            // See the VERSION arm above: an error return, never a panic on
            // network-controlled bytes.
            _ => {
                return Err(NetError::Protocol(
                    "VERACK frame did not decode to a VERACK message".into(),
                ))
            }
        }

        ver
    } else {
        // Responder: First frame MUST be VERSION
        let (ty, payload) = read_frame(stream, &config.params)?;
        if ty != MessageType::Version as u8 {
            return Err(NetError::Protocol(format!(
                "first frame must be VERSION (1), got {ty}"
            )));
        }
        let ver = match Message::decode(ty, &payload)? {
            Message::Version(v) => v,
            // See the initiator's VERSION arm: an error return, never a panic on
            // network-controlled bytes.
            _ => {
                return Err(NetError::Protocol(
                    "VERSION frame did not decode to a VERSION message".into(),
                ))
            }
        };

        validate_peer_version(&ver, &config.params, &genesis_hash, local_nonce)?;

        // Send our VERSION
        let ver_payload = Message::Version(local_version).encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Version as u8,
            &ver_payload,
        )?;

        // Send VERACK acknowledging peer's nonce
        let verack_payload = Message::Verack { nonce: ver.nonce }.encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Verack as u8,
            &verack_payload,
        )?;

        // Wait for initiator's VERACK acknowledging our nonce
        let (ack_ty, ack_payload) = read_frame(stream, &config.params)?;
        if ack_ty != MessageType::Verack as u8 {
            return Err(NetError::Protocol(format!(
                "expected VERACK (2), got {ack_ty}"
            )));
        }
        match Message::decode(ack_ty, &ack_payload)? {
            Message::Verack { nonce } => {
                if nonce != local_nonce {
                    return Err(NetError::Protocol(format!(
                        "VERACK nonce mismatch: got {nonce}, expected {local_nonce}"
                    )));
                }
            }
            _ => {
                return Err(NetError::Protocol(
                    "VERACK frame did not decode to a VERACK message".into(),
                ))
            }
        }

        ver
    };

    // Reset timeouts for normal steady-state operation (e.g. 60s for keepalive)
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    Ok(peer_version)
}

fn validate_peer_version(
    ver: &Version,
    params: &NetworkParams,
    genesis_hash: &Hash512,
    local_nonce: u64,
) -> NetResult<()> {
    check_network(params, ver.network_magic, &ver.network_id)?;
    if ver.protocol_version > PROTOCOL_VERSION {
        return Err(NetError::Protocol(format!(
            "unsupported protocol version: {} > {}",
            ver.protocol_version, PROTOCOL_VERSION
        )));
    }
    if ver.height == 0 && ver.tip_hash != *genesis_hash {
        return Err(NetError::Protocol(
            "peer claiming height 0 has non-genesis tip hash".into(),
        ));
    }
    // Self-connection guard: a peer that echoes our own handshake nonce is
    // (almost certainly) us, reached through our own listen address or a
    // NAT reflection. Connecting to ourselves splits the peer table in two
    // halves of one node and can amplify relay loops.
    if ver.nonce == local_nonce {
        return Err(NetError::Protocol(
            "self-connection: peer echoed our handshake nonce".into(),
        ));
    }
    Ok(())
}

/// A per-process random 64-bit nonce, used for the handshake challenge (§13.4).
///
/// `RandomState`'s keys are seeded by the OS, so hashing a counter through it
/// yields values that are unpredictable to a remote peer. The previous
/// implementation was derived purely from the wall clock, which a peer can
/// estimate from block timestamps — it made the "proof of socket possession"
/// nonce guessable, and a guessable nonce is not a challenge.
fn generate_nonce() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(now);
    h.write_u64(seq);
    h.finish()
}

/// Spawn peer read and write loops on an established TCP stream.
///
/// `live` is the node's peer table and this function registers the peer in it
/// **before** the reader thread starts, rather than the caller doing it after
/// this returns. Two things depend on that ordering and both are silent when it
/// is wrong:
///
/// - A frame can be sitting in the socket buffer the moment the handshake
///   finishes, so the reader thread can decode and queue a `Message` in the
///   instant between `spawn_peer` returning and the caller's insert. The event
///   loop could then see a message from a peer it does not know about.
/// - The `Connected` event announces whatever the pool already holds. That runs
///   on the event loop, so if the peer is registered a moment late the
///   announcement is dropped and transactions pooled before the connection
///   existed are never relayed to it — the exact case it was added for.
///
/// `inbound` is only incremented once the peer is actually registered, so a
/// failed registration cannot leak an inbound slot (§13.8).
pub fn spawn_peer(
    peer_id: usize,
    mut stream: TcpStream,
    version: Version,
    is_outbound: bool,
    params: NetworkParams,
    event_tx: SyncSender<PeerEvent>,
    table: PeerTable,
) -> NetResult<PeerHandle> {
    let remote_addr = stream.peer_addr()?;
    let (outbound_tx, outbound_rx): (SyncSender<Message>, Receiver<Message>) =
        sync_channel(OUTBOUND_QUEUE_MAX);
    let ban_score = Arc::new(AtomicU32::new(0));
    let stopped = Arc::new(AtomicBool::new(false));
    let reader_done = Arc::new(AtomicBool::new(false));
    let socket = Arc::new(stream.try_clone()?);

    let handle = PeerHandle {
        id: peer_id,
        remote_addr,
        version: version.clone(),
        is_outbound,
        tx: outbound_tx.clone(),
        ban_score: Arc::clone(&ban_score),
        stopped: Arc::clone(&stopped),
        socket: Arc::clone(&socket),
        reader_done: Arc::clone(&reader_done),
    };

    // Registered before either thread starts, so no event this peer produces can
    // be observed by the event loop before the peer itself is known.
    table.register(handle.clone());

    // Notify connected
    let _ = event_tx.send(PeerEvent::Connected {
        peer_id,
        remote_addr,
        version,
        is_outbound,
    });

    let mut write_stream = stream.try_clone()?;
    let write_params = params.clone();
    let write_stopped = Arc::clone(&stopped);

    // Writer thread
    thread::spawn(move || {
        while let Ok(msg) = outbound_rx.recv() {
            if write_stopped.load(Ordering::Relaxed) {
                break;
            }
            let ty = match &msg {
                Message::Version(_) => MessageType::Version as u8,
                Message::Verack { .. } => MessageType::Verack as u8,
                Message::Ping { .. } => MessageType::Ping as u8,
                Message::Pong { .. } => MessageType::Pong as u8,
                Message::Inv(_) => MessageType::Inv as u8,
                Message::GetData(_) => MessageType::GetData as u8,
                Message::Block(_) => MessageType::Block as u8,
                Message::GetBlocks { .. } => MessageType::GetBlocks as u8,
                Message::Addr(_) => MessageType::Addr as u8,
                Message::Tx(_) => MessageType::Tx as u8,
                Message::Checkpoint(_) => MessageType::Checkpoint as u8,
                Message::ArbitrationVote(_) => MessageType::ArbitrationVote as u8,
                Message::Unknown { ty, .. } => *ty,
            };
            let payload = msg.encode();
            if write_frame(&mut write_stream, &write_params, ty, &payload).is_err() {
                break;
            }
        }
        write_stopped.store(true, Ordering::Relaxed);
    });

    // Reader thread
    let read_stopped = Arc::clone(&stopped);
    let read_done = Arc::clone(&reader_done);
    let read_ban = Arc::clone(&ban_score);
    let read_event_tx = event_tx;
    let auto_pong_tx = outbound_tx;

    thread::spawn(move || {
        let mut exit_reason = "connection closed".to_string();
        // Keepalive state: a read timeout means "nothing heard for 60 s". We
        // ping once, and a second timeout means the peer is unresponsive to
        // PING, which SPEC.md §13.9 scores at +10.
        let mut ping_sent = false;
        let mut ping_nonce = 0u64;

        while !read_stopped.load(Ordering::Relaxed) {
            match read_frame(&mut stream, &params) {
                Ok((ty, payload)) => {
                    ping_sent = false;
                    match Message::decode(ty, &payload) {
                        Ok(msg) => match msg {
                            Message::Ping { nonce } => {
                                // Auto respond with PONG. Non-blocking: if the
                                // peer's queue is full it is already being
                                // dropped; blocking the reader here would stall
                                // inbound processing behind one slow peer.
                                let _ = auto_pong_tx.try_send(Message::Pong { nonce });
                            }
                            Message::Pong { nonce } => {
                                if ping_sent && nonce == ping_nonce {
                                    ping_sent = false;
                                }
                            }
                            other => {
                                if read_event_tx
                                    .send(PeerEvent::Message {
                                        peer_id,
                                        msg: other,
                                    })
                                    .is_err()
                                {
                                    exit_reason = "event receiver dropped".into();
                                    break;
                                }
                            }
                        },
                        Err(e) => {
                            let curr = read_ban.fetch_add(20, Ordering::SeqCst);
                            if curr + 20 >= BAN_SCORE_THRESHOLD {
                                exit_reason = format!("banned: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(NetError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if ping_sent {
                        // §13.9: unresponsive to PING (60 s) scores +10.
                        let curr = read_ban.fetch_add(10, Ordering::SeqCst);
                        if curr + 10 >= BAN_SCORE_THRESHOLD {
                            exit_reason = "banned: unresponsive to PING".into();
                            break;
                        }
                        ping_sent = false;
                    } else {
                        ping_nonce = generate_nonce();
                        let _ = auto_pong_tx.try_send(Message::Ping { nonce: ping_nonce });
                        ping_sent = true;
                    }
                    continue;
                }
                Err(NetError::InvalidMagic { .. } | NetError::OversizedFrame { .. }) => {
                    // §13.9: a frame over `max_frame_bytes`, or a bad magic after
                    // a good handshake, is an immediate +100 ban. Without this
                    // they were just a disconnect, so a peer could probe the
                    // framing bounds for free and reconnect.
                    read_ban.store(BAN_SCORE_THRESHOLD, Ordering::SeqCst);
                    exit_reason = "banned: framing violation".into();
                    break;
                }
                Err(e) => {
                    exit_reason = e.to_string();
                    break;
                }
            }
        }

        read_stopped.store(true, Ordering::Relaxed);
        // Set before the event, so the event loop can distinguish "this reader is
        // finished and its report is queued" from "this peer was ended and its
        // reader is still parked".
        read_done.store(true, Ordering::Relaxed);
        let _ = read_event_tx.send(PeerEvent::Disconnected {
            peer_id,
            reason: exit_reason,
        });
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_outbound_queue_drops_the_peer_instead_of_growing_memory() {
        // Audit: the outbound channel was unbounded, so one stalled peer
        // pinned every broadcast queued behind it. The queue is now bounded
        // (`OUTBOUND_QUEUE_MAX`); filling it must disconnect the peer rather
        // than grow memory.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        // Never read from `server`: `client`'s writer has nowhere to drain.
        let _ = server;

        let params = NetworkParams::mini();
        let (event_tx, _event_rx) = std::sync::mpsc::sync_channel::<PeerEvent>(16);
        let live = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let inbound = std::sync::Arc::new(AtomicUsize::new(0));
        let table = PeerTable::new(live, inbound);
        let version = Version {
            network_magic: params.network_magic,
            network_id: params.network_id.clone(),
            protocol_version: PROTOCOL_VERSION,
            services: 1,
            height: 0,
            tip_hash: srct_core::block::genesis_block(1).block_hash(),
            user_agent: "test".into(),
            nonce: 0xA11CE,
        };
        let handle = spawn_peer(7, client, version, true, params, event_tx, table).unwrap();
        // Fill past the cap: `send` must eventually refuse and mark stopped
        // instead of queueing forever.
        let mut refused = false;
        for _ in 0..(OUTBOUND_QUEUE_MAX + 64) {
            if handle.send(Message::Ping { nonce: 1 }).is_err() {
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "a stalled peer must be dropped, not queued forever"
        );
        assert!(handle.is_stopped());
        handle.stop();
    }
}
