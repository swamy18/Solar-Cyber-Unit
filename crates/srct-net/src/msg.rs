//! Message type set and codecs. SPEC.md §13.4-§13.5.
//!
//! Message numbers are frozen; an unknown number MUST be ignored without
//! disconnecting, so a future version can extend the set. Counts are `u16`
//! little-endian; short handshake strings (network_id, user_agent) are
//! length-prefixed by a single byte, both being bounded to 64.

use srct_core::block::Block;
use srct_core::hash::Hash512;
use srct_core::ser::{Reader, Writer};
use srct_core::tx::Transaction;

use crate::error::{NetError, NetResult};

/// Protocol version for the `VERSION` message. Bump when the message set or a
/// payload layout changes in a backwards-compatible way.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum bytes of `user_agent` and `network_id` text.
pub const MAX_HANDSHAKE_STR_LEN: usize = 64;

/// Upper bounds on repeated fields. Each entry is `kind(1) ‖ hash(64)` = 65
/// bytes, so the cap also bounds the worst-case allocation.
pub const MAX_INV_PER_MSG: usize = 500;
pub const MAX_LOCATOR_ENTRIES: usize = 500;

/// `kind` values for inventory entries (§13.5).
///
/// `0` was reserved for transactions from the start (v0.2) precisely so that the
/// announcement would need no wire change once a mempool existed. Transaction
/// relay (§13.14) is the change that reservation was for.
pub const INV_TYPE_BLOCK: u8 = 1;
pub const INV_TYPE_TX: u8 = 0;

/// Message type numbers. Frozen: unknown numbers are ignored, not rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Version = 1,
    Verack = 2,
    Ping = 3,
    Pong = 4,
    Inv = 5,
    GetData = 6,
    Block = 7,
    GetBlocks = 8,
    Addr = 9,
    /// Added in v0.3 (§13.14). Additive: the freeze rule means a node built
    /// before this existed ignores it rather than disconnecting.
    Tx = 10,
    /// M4: checkpoint certificate relay (Decision 11, SPEC.md §14).
    /// Carry the complete certificate; the receiver verifies it against
    /// its local committee — consensus never consults it.
    Checkpoint = 11,
    /// Fraud arbitration vote (Decision 21, SPEC.md §16). One arbitrator's
    /// signed verdict for one dispute. Additive per the freeze rule: a node
    /// built before this existed ignores it rather than disconnecting.
    ///
    /// Carry the complete vote rather than an id, because there is no vote
    /// store to serve a getdata from and the signature *is* the content.
    ArbitrationVote = 12,
}

impl MessageType {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => MessageType::Version,
            2 => MessageType::Verack,
            3 => MessageType::Ping,
            4 => MessageType::Pong,
            5 => MessageType::Inv,
            6 => MessageType::GetData,
            7 => MessageType::Block,
            8 => MessageType::GetBlocks,
            9 => MessageType::Addr,
            10 => MessageType::Tx,
            11 => MessageType::Checkpoint,
            12 => MessageType::ArbitrationVote,
            _ => return None,
        })
    }
}

/// A decoded, typed message. `Block` carries the already-parsed block; the
/// caller runs consensus validation on it via `Chain::submit`.
#[derive(Debug, Clone)]
pub enum Message {
    Version(Version),
    Verack {
        nonce: u64,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Inv(Vec<InvEntry>),
    GetData(Vec<InvEntry>),
    Block(Box<Block>),
    GetBlocks {
        locator: Vec<Hash512>,
        stop: Hash512,
    },
    Addr(Vec<SocketAddr>),
    /// A relayed transaction (§13.14). Boxed because a transaction is by far the
    /// largest variant and every `Message` is cloned once per peer on broadcast.
    Tx(Box<Transaction>),
    /// M4 checkpoint certificate relay (Decision 11). Complete
    /// certificate — not a proposal/vote, because no BFT round
    /// protocol exists to give them meaning. Verified on receipt;
    /// consensus never consults it.
    Checkpoint(srct_core::bls_checkpoint::Checkpoint),
    /// A fraud-arbitration vote. Verified on receipt against the chain's own
    /// committee and its own height; consensus never consults it. See
    /// `srct_node::mediation` for what the node does with one that checks out.
    ArbitrationVote(Box<srct_core::arbitration::ArbitrationVote>),
    /// An unknown type number — ignored, per the freeze rule. Retained so
    /// tests can assert that unknown types are dropped without disconnect.
    Unknown {
        ty: u8,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvEntry {
    pub kind: u8,
    pub hash: Hash512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub network_magic: [u8; 4],
    pub network_id: String,
    pub protocol_version: u32,
    pub services: u64,
    pub height: u64,
    pub tip_hash: Hash512,
    pub user_agent: String,
    pub nonce: u64,
}

/// A socket address on the wire: 16-byte address (IPv6 / IPv6-mapped IPv4) and
/// a 2-byte port. §13.5, `ADDR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddr {
    pub ip: [u8; 16],
    pub port: u16,
}

impl Message {
    /// Encode to the payload bytes (without the frame envelope).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_into(&mut w);
        w.into_vec()
    }

    fn encode_into(&self, w: &mut Writer) {
        match self {
            Message::Version(v) => {
                // Clamp to the decoder's bound (`MAX_HANDSHAKE_STR_LEN`), not
                // to 255: the old code produced messages this node's own
                // decoder rejects (length byte > 64), so a node with a long
                // `user_agent` sent handshakes nobody — including itself —
                // accepts. Truncation keeps the shape encodable; the 64-byte
                // bound stays the consensus wire rule.
                let nid = &v.network_id.as_bytes()[..v.network_id.len().min(MAX_HANDSHAKE_STR_LEN)];
                let ua = &v.user_agent.as_bytes()[..v.user_agent.len().min(MAX_HANDSHAKE_STR_LEN)];
                w.raw(&v.network_magic)
                    .u8(u8::try_from(nid.len()).unwrap_or(0));
                w.raw(nid);
                w.u32le(v.protocol_version)
                    .u64le(v.services)
                    .u64le(v.height)
                    .fixed(&v.tip_hash)
                    .u8(u8::try_from(ua.len()).unwrap_or(0))
                    .raw(ua)
                    .u64le(v.nonce);
            }
            Message::Verack { nonce } => {
                w.u64le(*nonce);
            }
            Message::Ping { nonce } => {
                w.u64le(*nonce);
            }
            Message::Pong { nonce } => {
                w.u64le(*nonce);
            }
            Message::Inv(entries) | Message::GetData(entries) => {
                w.u16le(u16::try_from(entries.len()).unwrap_or(0));
                for e in entries {
                    w.u8(e.kind).fixed(&e.hash);
                }
            }
            Message::Block(block) => {
                w.raw(&block.serialize());
            }
            Message::GetBlocks { locator, stop } => {
                w.u16le(u16::try_from(locator.len()).unwrap_or(0));
                for h in locator {
                    w.fixed(h);
                }
                w.fixed(stop);
            }
            Message::Addr(addrs) => {
                w.u16le(u16::try_from(addrs.len()).unwrap_or(0));
                for a in addrs {
                    // SPEC.md §13.5: `count x (port(2 LE) | ip(16))` — port
                    // first. The previous order was `ip | port`, which still
                    // round-trips through our own decoder and so passed every
                    // test in this crate while disagreeing with the spec, and
                    // therefore with every other implementation. Caught by
                    // `sim/net_reference.py`, the independent encoder written
                    // from the prose. Note the payload length is identical
                    // either way (18 bytes per entry), so a length assertion
                    // could never have found it.
                    w.u16le(a.port).fixed(&a.ip);
                }
            }
            Message::Tx(tx) => {
                // No size check here: the frame layer bounded the payload at
                // `MAX_FRAME_PAYLOAD` before this was ever parsed, and
                // `Transaction::from_reader` bounds each count field before
                // reserving for it.
                w.raw(&tx.serialize());
            }
            Message::Checkpoint(cp) => {
                w.raw(&cp.serialize());
            }
            Message::ArbitrationVote(v) => {
                w.raw(&v.serialize());
            }
            Message::Unknown { raw, .. } => {
                // `raw` is the payload verbatim as received — decode stores the
                // whole payload, not a re-framed copy — so encoding is a
                // verbatim copy and decode(encode(x)) is the identity. (This
                // arm used to write `ty + len + raw` on top of bytes that
                // already were the payload, growing an unknown message by 5
                // bytes on every decode→encode cycle. Found by the
                // fuzz-invariant tests; never consensus-critical since nodes
                // do not relay unknown messages, but the asymmetry is a wire
                // correctness bug.)
                w.raw(raw);
            }
        }
    }

    /// Decode a payload given its type number.
    pub fn decode(ty: u8, payload: &[u8]) -> NetResult<Message> {
        let mut r = Reader::new(payload);
        let msg = match MessageType::from_u8(ty) {
            Some(MessageType::Version) => Message::Version(decode_version(&mut r)?),
            Some(MessageType::Verack) => Message::Verack { nonce: r.u64le()? },
            Some(MessageType::Ping) => Message::Ping { nonce: r.u64le()? },
            Some(MessageType::Pong) => Message::Pong { nonce: r.u64le()? },
            Some(MessageType::Inv) => Message::Inv(decode_inv(&mut r)?),
            Some(MessageType::GetData) => Message::GetData(decode_inv(&mut r)?),
            Some(MessageType::Block) => Message::Block(Box::new(
                Block::deserialize(payload)
                    .map_err(|e| NetError::Decode(format!("block deserialize: {e}")))?,
            )),
            Some(MessageType::GetBlocks) => Message::GetBlocks {
                locator: decode_locator(&mut r)?,
                stop: r.fixed()?,
            },
            Some(MessageType::Addr) => Message::Addr(decode_addr(&mut r)?),
            Some(MessageType::Tx) => Message::Tx(Box::new(
                Transaction::deserialize(payload)
                    .map_err(|e| NetError::Decode(format!("tx deserialize: {e}")))?,
            )),
            Some(MessageType::Checkpoint) => Message::Checkpoint(
                srct_core::bls_checkpoint::Checkpoint::deserialize(payload)
                    .map_err(|e| NetError::Decode(format!("checkpoint deserialize: {e}")))?,
            ),
            Some(MessageType::ArbitrationVote) => Message::ArbitrationVote(Box::new(
                srct_core::arbitration::ArbitrationVote::deserialize(payload)
                    .map_err(|e| NetError::Decode(format!("arbitration vote deserialize: {e}")))?,
            )),
            None => {
                // Unknown: preserve the raw payload so callers can log it, but
                // do not act on it. §13.5 freeze rule.
                Message::Unknown {
                    ty,
                    raw: payload.to_vec(),
                }
            }
        };
        // Trailing garbage is a protocol violation, not padding: a message
        // that decodes with bytes left over is either a version mismatch or
        // a smuggling attempt, and both must be refused by name. Unknown
        // types are exempt by the §13.5 freeze rule: a future version's
        // fields are opaque to this build, and refusing them would partition
        // the network on upgrade. Block, Tx, Checkpoint and Vote arms
        // decode straight from `payload` (their own codecs `expect_end`
        // internally), so the reader is untouched for them — the check
        // applies only to arms that actually read through it.
        let consumed_via_reader = payload.len() - r.remaining();
        if consumed_via_reader > 0 && r.remaining() != 0 && !matches!(msg, Message::Unknown { .. })
        {
            return Err(NetError::Decode(format!(
                "trailing {} bytes after message type {ty}",
                r.remaining()
            )));
        }
        Ok(msg)
    }
}

fn decode_version(r: &mut Reader<'_>) -> NetResult<Version> {
    let network_magic: [u8; 4] = r.fixed()?;
    let id_len = r.u8()? as usize;
    if id_len > MAX_HANDSHAKE_STR_LEN {
        return Err(NetError::Decode(format!("network_id too long: {id_len}")));
    }
    let id_bytes = r
        .fixed_slice(id_len)
        .map_err(|e| NetError::Decode(e.to_string()))?;
    let network_id = std::str::from_utf8(id_bytes)
        .map_err(|_| NetError::Decode("network_id not utf-8".into()))?
        .to_string();
    // Field order MUST match `Version::encode_into` and SPEC.md §13.4.
    let protocol_version = r.u32le()?;
    let services = r.u64le()?;
    let height = r.u64le()?;
    let tip_hash: Hash512 = r.fixed()?;
    let ua_len = r.u8()? as usize;
    if ua_len > MAX_HANDSHAKE_STR_LEN {
        return Err(NetError::Decode(format!("user_agent too long: {ua_len}")));
    }
    let ua_bytes = r
        .fixed_slice(ua_len)
        .map_err(|e| NetError::Decode(e.to_string()))?;
    let user_agent = std::str::from_utf8(ua_bytes)
        .map_err(|_| NetError::Decode("user_agent not utf-8".into()))?
        .to_string();
    let nonce = r.u64le()?;
    Ok(Version {
        network_magic,
        network_id,
        protocol_version,
        services,
        height,
        tip_hash,
        user_agent,
        nonce,
    })
}

fn decode_inv(r: &mut Reader<'_>) -> NetResult<Vec<InvEntry>> {
    let count = r.u16le()? as usize;
    if count > MAX_INV_PER_MSG {
        return Err(NetError::Decode(format!(
            "inventory count {count} exceeds {MAX_INV_PER_MSG}"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = r.u8()?;
        let hash: Hash512 = r.fixed()?;
        out.push(InvEntry { kind, hash });
    }
    Ok(out)
}

fn decode_locator(r: &mut Reader<'_>) -> NetResult<Vec<Hash512>> {
    let count = r.u16le()? as usize;
    if count > MAX_LOCATOR_ENTRIES {
        return Err(NetError::Decode(format!(
            "locator count {count} exceeds {MAX_LOCATOR_ENTRIES}"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.fixed()?);
    }
    Ok(out)
}

fn decode_addr(r: &mut Reader<'_>) -> NetResult<Vec<SocketAddr>> {
    let count = r.u16le()? as usize;
    if count > MAX_ADDR_PER_MSG {
        return Err(NetError::Decode(format!(
            "addr count {count} exceeds {MAX_ADDR_PER_MSG}"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // Field order MUST match `encode_into` and SPEC.md §13.5: port, then
        // ip.
        let port = r.u16le()?;
        let ip: [u8; 16] = r.fixed()?;
        out.push(SocketAddr { ip, port });
    }
    Ok(out)
}

pub const MAX_ADDR_PER_MSG: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn version_round_trips_and_bounds_strings() {
        let v = Version {
            network_magic: [0x6A, 0x4E, 0x54, 0x03],
            network_id: "srct/mini".into(),
            protocol_version: PROTOCOL_VERSION,
            services: 0,
            height: 31,
            tip_hash: [0xAB; 64],
            user_agent: "/srct-net:0.2".into(),
            nonce: 0x0123_4567_89AB_CDEF,
        };
        let enc = Message::Version(v.clone()).encode();
        let dec = Message::decode(1, &enc).unwrap();
        match dec {
            Message::Version(got) => assert_eq!(got, v),
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_is_preserved_not_rejected() {
        // §13.5: an unknown message number must not disconnect; encode it
        // verbatim and confirm decode keeps the raw payload verbatim so a
        // future layer can inspect/log it.
        let payload = {
            let mut w = Writer::new();
            w.u8(0x42).u32le(4).raw(b"test");
            w.into_vec()
        };
        let msg = Message::decode(0xFF, &payload).unwrap();
        match &msg {
            Message::Unknown { ty, raw } => {
                assert_eq!(*ty, 0xFF);
                assert_eq!(raw, &payload);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        // Encode must be the exact inverse: verbatim payload, no re-framing,
        // so a decode→encode→decode cycle is the identity (regression test for
        // the growth bug found by the fuzz-invariant tests).
        assert_eq!(msg.encode(), payload);
    }

    #[test]
    fn inv_round_trips_and_bounds_count() {
        let inv = Message::Inv(vec![
            InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: [0x11; 64],
            },
            InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: [0x22; 64],
            },
        ]);
        let dec = Message::decode(5, &inv.encode()).unwrap();
        match dec {
            Message::Inv(entries) => assert_eq!(entries.len(), 2),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn oversized_inv_count_is_rejected_without_allocating() {
        // Declare more entries than the cap then stop, so the decoder rejects
        // the count before allocating 65 000 entries.
        let mut w = Writer::new();
        w.u16le((MAX_INV_PER_MSG + 1) as u16);
        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        let res = decode_inv(&mut r);
        assert!(matches!(res, Err(NetError::Decode(_))));
    }

    /// ADDR carried `ip | port` and the spec says `port | ip` (§13.5). A
    /// round-trip test cannot see this, because both sides of our own codec
    /// agreed; only `sim/net_reference.py` caught it. Assert the literal bytes
    /// so the order cannot drift back.
    #[test]
    fn addr_entry_is_port_then_ip() {
        let mut ip = [0u8; 16];
        ip[10] = 0xFF;
        ip[11] = 0xFF;
        ip[12] = 127;
        ip[15] = 1;
        let msg = Message::Addr(vec![SocketAddr { ip, port: 8333 }]);
        let enc = msg.encode();
        assert_eq!(
            hex_of(&enc),
            concat!(
                "0100",                             // count = 1
                "8d20",                             // port 8333 LE, FIRST
                "00000000000000000000ffff7f000001", // 16-byte ip, SECOND
            ),
            "ADDR entry order must match SPEC.md 13.5"
        );
        match Message::decode(MessageType::Addr as u8, &enc).unwrap() {
            Message::Addr(got) => {
                assert_eq!(got.len(), 1);
                assert_eq!(got[0].port, 8333);
                assert_eq!(got[0].ip, ip);
            }
            other => panic!("expected Addr, got {other:?}"),
        }
    }

    #[test]
    fn oversized_handshake_strings_encode_within_the_wire_bound() {
        // Audit: `Version::encode` truncated at 255 while the decoder caps at
        // 64, so a node with a long `user_agent` emitted handshakes its own
        // decoder rejects. Encoding must clamp to `MAX_HANDSHAKE_STR_LEN` so
        // every encoded handshake decodes.
        let v = Version {
            network_magic: [0x6A, 0x4E, 0x54, 0x03],
            network_id: "x".repeat(200),
            protocol_version: PROTOCOL_VERSION,
            services: 1,
            height: 0,
            tip_hash: [0x00; 64],
            user_agent: "y".repeat(200),
            nonce: 1,
        };
        let enc = Message::Version(v).encode();
        match Message::decode(1, &enc).unwrap() {
            Message::Version(got) => {
                assert_eq!(got.network_id.len(), MAX_HANDSHAKE_STR_LEN);
                assert_eq!(got.user_agent.len(), MAX_HANDSHAKE_STR_LEN);
            }
            other => panic!("expected Version, got {other:?}"),
        }
    }
}
