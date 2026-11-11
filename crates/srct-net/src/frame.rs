//! Length-prefixed frame codec. SPEC.md §13.2.
//!
//! ```text
//! frame = magic(4) ‖ msg_type(1) ‖ payload_len(4 LE) ‖ payload(payload_len)
//! ```
//!
//! Two rules from the spec are non-negotiable here, and both are enforced in
//! this module:
//!
//! 1. `payload_len` is checked against `MAX_FRAME_PAYLOAD` **before** any
//!    allocation. The length prefix is attacker-controlled, which is the same
//!    class of bug as the bundle-length and input-count defects already fixed
//!    in `SPEC.md §3.1/§3.5`; the same discipline applies here.
//! 2. A frame larger than the cap closes the connection rather than being
//!    skipped. There is no resynchronisation point in a stream protocol, so
//!    skipping leaves the peer able to confuse every later message.

use std::io::{Read, Write};

use crate::error::{NetError, NetResult};
use srct_core::params::NetworkParams;
use srct_core::ser::Writer;

/// `max_block_bytes` (4 000 000) plus headroom for the frame envelope and the
/// largest legal `GETBLOCKS`/`INV` payloads. A `BLOCK` frame carrying a
/// maximum-size block is always within this cap.
pub const MAX_FRAME_PAYLOAD: u32 = 4_100_000;

/// Write one complete, self-delimiting frame to anything that is `Write`.
///
/// The magic is taken from the node's own `NetworkParams`, so a mismatch on the
/// receiving end is caught at the first byte — including on frames sent *after*
/// the handshake, which stops a peer from switching networks mid-session.
pub fn write_frame<W: Write>(
    w: &mut W,
    params: &NetworkParams,
    msg_type: u8,
    payload: &[u8],
) -> NetResult<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        NetError::Protocol(format!(
            "payload too large to frame: {} bytes",
            payload.len()
        ))
    })?;
    let mut buf = Writer::with_capacity(4 + 1 + 4 + payload.len());
    buf.raw(&params.network_magic).u8(msg_type).u32le(len);
    let head: &[u8] = buf.as_slice();
    w.write_all(head)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read and validate exactly one frame from a stream.
///
/// Returns `(msg_type, payload)` with `payload` already bounded to
/// `MAX_FRAME_PAYLOAD` bytes, grown incrementally as bytes arrive rather than
/// reserved up front. A violating length is rejected before `payload` is ever
/// read, so a peer cannot force an oversized allocation; a lying length that
/// passes the cap pins only the bytes actually delivered.
/// Upper bound on wall time spent reading a single frame. The socket read
/// timeout bounds each stalled `read`, but a peer dripping one byte per
/// timeout-minus-epsilon would otherwise hold a peer slot and its reader
/// thread forever (Slowloris): every `read` returns just in time, so the
/// timeout never fires, yet no frame ever completes. The deadline bounds the
/// whole frame instead — a maximum-size frame that cannot arrive in this time
/// is not a slow peer, it is a slot-exhaustion attempt, and the connection is
/// closed. Together with the keepalive ping in `peer.rs` (which bounds total
/// silence), a peer must either make progress or lose its slot.
pub const MAX_FRAME_DURATION: std::time::Duration = std::time::Duration::from_secs(90);

pub fn read_frame<R: Read>(r: &mut R, params: &NetworkParams) -> NetResult<(u8, Vec<u8>)> {
    read_frame_inner(r, params, MAX_FRAME_DURATION, |_| {})
}

/// `read_frame` with a per-chunk capacity probe, so tests can prove the
/// growth policy instead of trusting it. The probe sees the payload's
/// capacity after every chunk; production passes a no-op.
fn read_frame_inner<R: Read>(
    r: &mut R,
    params: &NetworkParams,
    deadline: std::time::Duration,
    mut on_chunk: impl FnMut(usize),
) -> NetResult<(u8, Vec<u8>)> {
    let started = std::time::Instant::now();
    let mut magic = [0u8; 4];
    read_exact_before_deadline(r, &mut magic, started, deadline, "magic")?;
    if magic != params.network_magic {
        // Checked on EVERY frame, not only at handshake. A peer that starts on
        // the right network and then spews garbage is caught here.
        return Err(NetError::InvalidMagic {
            got: magic,
            want: params.network_magic,
        });
    }

    let mut type_buf = [0u8; 1];
    read_exact_before_deadline(r, &mut type_buf, started, deadline, "msg_type")?;
    let msg_type = type_buf[0];

    let mut len_buf = [0u8; 4];
    read_exact_before_deadline(r, &mut len_buf, started, deadline, "payload_len")?;
    let payload_len = u32::from_le_bytes(len_buf);
    if payload_len > MAX_FRAME_PAYLOAD {
        // Deliberately reject rather than skip. Skipping desynchronises the
        // stream; the only safe action on a frame that cannot fit is to close.
        return Err(NetError::OversizedFrame { len: payload_len });
    }

    let payload_len = payload_len as usize;
    // Read incrementally in bounded chunks rather than `vec![0; payload_len]`,
    // so a peer that declares a large length but sends only a trickle of bytes
    // holds roughly the bytes it actually delivered, not the whole lie. With
    // `max_peers` inbound readers this caps the pinned memory at
    // `chunk_len * max_peers` rather than `MAX_FRAME_PAYLOAD * max_peers`.
    // The whole-frame deadline is checked per chunk: a drip that stays under
    // the per-read socket timeout but never finishes still loses its slot.
    let mut payload = Vec::new();
    if payload_len > 0 {
        let mut buf = [0u8; 64 * 1024];
        let mut remaining = payload_len;
        while remaining > 0 {
            let want = remaining.min(buf.len());
            read_exact_before_deadline(r, &mut buf[..want], started, deadline, "payload")?;
            payload.extend_from_slice(&buf[..want]);
            on_chunk(payload.capacity());
            remaining -= want;
        }
    }

    Ok((msg_type, payload))
}

/// Read exactly one frame field while checking the whole-frame deadline after
/// every partial read. `Read::read_exact` may loop internally for an
/// unbounded time when a peer drips bytes often enough to avoid the socket's
/// per-read timeout; keeping that loop here makes the deadline effective for
/// both the fixed header and the payload.
fn read_exact_before_deadline<R: Read>(
    r: &mut R,
    mut out: &mut [u8],
    started: std::time::Instant,
    deadline: std::time::Duration,
    what: &'static str,
) -> NetResult<()> {
    while !out.is_empty() {
        if started.elapsed() >= deadline {
            return Err(NetError::Truncated("frame read deadline exceeded".into()));
        }
        match r.read(out) {
            Ok(0) => return Err(NetError::Truncated(what.to_string())),
            Ok(n) => {
                if started.elapsed() >= deadline {
                    return Err(NetError::Truncated("frame read deadline exceeded".into()));
                }
                out = &mut out[n..];
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(trunc(e, what)),
        }
    }
    if started.elapsed() >= deadline {
        return Err(NetError::Truncated("frame read deadline exceeded".into()));
    }
    Ok(())
}

fn trunc(e: std::io::Error, what: &str) -> NetError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        NetError::Truncated(what.to_string())
    } else {
        NetError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::ser::Reader;
    use std::io::Cursor;

    #[test]
    fn round_trip_is_bytes() {
        let p = NetworkParams::mini();
        let payload = b"hello world".to_vec();
        let mut wire = Cursor::new(Vec::new());
        write_frame(&mut wire, &p, 7, &payload).unwrap();
        wire.set_position(0);
        let (ty, got) = read_frame(&mut wire, &p).unwrap();
        assert_eq!(ty, 7);
        assert_eq!(got, payload);
    }

    #[test]
    fn rejects_oversized_length_before_allocating() {
        let p = NetworkParams::mini();
        // A length that lies far past the cap: the read must reject without
        // reading `payload_len` bytes of payload, i.e. without allocating.
        let wire = {
            let mut w = Writer::new();
            w.raw(&p.network_magic).u8(7).u32le(MAX_FRAME_PAYLOAD + 1);
            w.into_vec()
        };
        let mut cursor = Cursor::new(wire);
        match read_frame(&mut cursor, &p) {
            Err(NetError::OversizedFrame { len }) => {
                assert_eq!(len, MAX_FRAME_PAYLOAD + 1);
            }
            other => panic!("expected OversizedFrame, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_magic() {
        let p = NetworkParams::mini();
        let mut w = Writer::new();
        w.raw(&[0xFF, 0xFF, 0xFF, 0xFF]).u8(7).u32le(0);
        let mut cursor = Cursor::new(w.into_vec());
        assert!(matches!(
            read_frame(&mut cursor, &p),
            Err(NetError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        let p = NetworkParams::mini();
        let mut w = Writer::new();
        w.raw(&p.network_magic).u8(7).u32le(10).raw(&[0u8; 4]);
        let mut cursor = Cursor::new(w.into_vec());
        assert!(matches!(
            read_frame(&mut cursor, &p),
            Err(NetError::Truncated(_))
        ));
    }

    /// A peer declares two megabytes and delivers three bytes. The read must
    /// fail truncated — and the peak allocation must stay near the delivered
    /// bytes, not the declared length. This is the test that would catch a
    /// reintroduction of `try_reserve(payload_len)`.
    #[test]
    fn a_lying_length_pins_only_delivered_bytes() {
        struct Drip {
            delivered: usize,
        }
        impl Read for Drip {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.delivered >= 3 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer went quiet",
                    ));
                }
                buf[0] = 0xAA;
                self.delivered += 1;
                Ok(1)
            }
        }

        let p = NetworkParams::mini();
        let mut w = Writer::new();
        w.raw(&p.network_magic).u8(7).u32le(2_000_000);
        let head = w.into_vec();
        let mut r = head.as_slice().chain(Drip { delivered: 0 });

        let mut peak = 0usize;
        let err = read_frame_inner(&mut r, &p, MAX_FRAME_DURATION, |cap| peak = peak.max(cap));
        assert!(
            matches!(err, Err(NetError::Truncated(_))),
            "a quiet peer is truncated, got {err:?}"
        );
        assert!(
            peak <= 1024,
            "declared 2MB but delivered 3 bytes, yet capacity peaked at {peak}"
        );
    }

    #[test]
    fn a_frame_that_drips_past_its_deadline_is_closed() {
        // Audit (Slowloris): the socket read timeout bounds each stalled
        // `read`, not the frame. A peer delivering slowly but steadily would
        // otherwise hold its slot forever. The whole-frame deadline closes
        // it instead.
        struct SlowDrip;
        impl Read for SlowDrip {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(5));
                buf[0] = 0xAA;
                Ok(1)
            }
        }
        let p = NetworkParams::mini();
        let mut w = Writer::new();
        w.raw(&p.network_magic).u8(7).u32le(1_000);
        let head = w.into_vec();
        let mut r = head.as_slice().chain(SlowDrip);
        let err = read_frame_inner(&mut r, &p, std::time::Duration::from_millis(30), |_| {});
        assert!(
            matches!(err, Err(NetError::Truncated(_))),
            "a dripping peer must hit the frame deadline, got {err:?}"
        );
    }

    // The Reader is the same one `srct_core`'s own serializers use, and the
    // `u16le` writer I added must agree with `Reader::u16le`.
    #[test]
    fn a_partial_read_cannot_hide_past_the_frame_deadline() {
        struct SlowPartial;
        impl Read for SlowPartial {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(5));
                buf[0] = 0xAA;
                Ok(1)
            }
        }

        let started = std::time::Instant::now();
        let mut field = [0u8; 16];
        let err = read_exact_before_deadline(
            &mut SlowPartial,
            &mut field,
            started,
            std::time::Duration::from_millis(25),
            "payload",
        )
        .unwrap_err();
        assert!(
            matches!(err, NetError::Truncated(ref why) if why == "frame read deadline exceeded")
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "partial reads must not be hidden inside read_exact"
        );
    }

    #[test]
    fn u16le_round_trips() {
        let mut w = Writer::new();
        w.u16le(0x0301);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(r.u16le().unwrap(), 0x0301);
        assert!(r.expect_end().is_ok());
    }
}
