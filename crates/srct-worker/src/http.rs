//! The node's HTTP transport (SPEC.md §18.3, roadmap §13/§19.2).
//!
//! [`HttpNode`] is a `L2NodeView + L2Broadcaster` over the node's opt-in REST
//! API, so a worker process no longer has to share an address space with the
//! node to see the chain. What it is, precisely:
//!
//! - **A transport, not a protocol.** Every rule still lives in `srct-l2` and in
//!   the node. The client fetches the node's *canonical* state (the §19.2 wire
//!   encoding), decodes it with the same codec the node encodes with, and lets
//!   the protocol's own checks — replay, balances, conservation — decide. It
//!   never re-implements a rule, never invents a state, and never holds a key:
//!   the only bytes it POSTs are a `L2Transaction` the SDK already signed.
//! - **Bounded and deterministic.** One response-size cap, one header cap, one
//!   connect timeout and one read timeout, all fixed at construction. Every
//!   failure maps to a named `WorkerError` / `BroadcastError`; nothing here
//!   panics, and no error string ever contains key material.
//! - **Fail closed.** A malformed status line, a header that never ends, a
//!   body over the cap, a truncated chunked frame, a JSON document that is not
//!   an object, a wrong `network_id`, undecodable hex, a state blob that does
//!   not decode — every one of them is an error *before* any state reaches the
//!   SDK. An unreachable node is an error, never an empty view: the read seam
//!   returns `Err`, so discovery offers nothing and no claim is built.
//!
//! ## Scope
//!
//! Plain `http://` only — this is the loopback API of §19.2, and this build
//! ships no TLS. HTTPS URLs are refused by name rather than silently
//! downgraded. HTTP/1.1 with `Connection: close`, no redirects, no cookies, no
//! keep-alive: one request, one bounded response, done.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use srct_core::hash::Hash;
use srct_core::l2::L2Transaction;
use srct_l2::{L2State, VerifiedWorkCertificate};

use crate::error::{WorkerError, WorkerResult};
use crate::node::{BroadcastError, L2Broadcaster, L2NodeView};

/// Default cap on one response body. The state blob grows with the chain, so
/// this is generous — but finite, and configurable by the operator.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Cap on the header block alone. A hostile or broken server must not be able
/// to stream headers forever.
const MAX_HEADER_BYTES: usize = 16 * 1024;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Transport errors
// ---------------------------------------------------------------------------

/// Why one HTTP exchange failed. Not public: callers see `WorkerError` /
/// `BroadcastError`, so the SDK's error vocabulary stays the one §18.10 defines.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Transport {
    /// Connect failed, timed out, or the socket broke mid-response.
    Unreachable(&'static str),
    /// The peer's bytes are not a well-formed HTTP response, or exceeded a cap.
    Malformed(&'static str),
    /// A well-formed response with a non-2xx status. `detail` is the node's
    /// own error text, which never contains signing material.
    Status { code: u16, detail: String },
}

impl Transport {
    /// Transport trouble as the *read* seam reports it: the observation did
    /// not arrive, which is a different fact from "the observation arrived and
    /// is untrustworthy" and is named differently for exactly that reason.
    fn into_observation(self) -> WorkerError {
        match self {
            Transport::Unreachable(why) => WorkerError::ObservationUnavailable(why),
            Transport::Malformed(why) => WorkerError::ObservationMalformed(why),
            Transport::Status { code, .. } => {
                WorkerError::ObservationUnavailable(status_class(code))
            }
        }
    }

    /// Transport trouble as the *write* seam reports it: 4xx means the node
    /// definitively refused these bytes (retrying identical bytes changes
    /// nothing, so it is a refusal), everything else is "unknown, reconcile".
    fn into_broadcast(self) -> BroadcastError {
        match self {
            Transport::Status { code, detail } if (400..500).contains(&code) => {
                BroadcastError::Refused(detail)
            }
            Transport::Status { code, .. } => {
                BroadcastError::Retryable(status_class(code).to_string())
            }
            Transport::Unreachable(why) => BroadcastError::Retryable(why.to_string()),
            Transport::Malformed(why) => BroadcastError::Retryable(why.to_string()),
        }
    }
}

fn status_class(code: u16) -> &'static str {
    match code {
        400..=499 => "node refused the request",
        500..=599 => "node failed the request",
        _ => "unexpected status from node",
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 exchange (bounded, no TLS, no redirects, no keep-alive)
// ---------------------------------------------------------------------------

/// A parsed URL: plain-HTTP authority plus an optional path prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    host: String,
    port: u16,
    prefix: String,
}

fn parse_url(base: &str) -> WorkerResult<Endpoint> {
    if base.starts_with("https://") {
        // Named rather than retried as plain HTTP: silently downgrading a URL
        // the operator wrote would be the opposite of fail-closed.
        return Err(WorkerError::ObservationMalformed(
            "https node URLs are not supported by this build",
        ));
    }
    let rest = base
        .strip_prefix("http://")
        .ok_or(WorkerError::ObservationMalformed(
            "node URL must start with http://",
        ))?;
    if rest.is_empty() {
        return Err(WorkerError::ObservationMalformed("node URL has no host"));
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = match authority.strip_prefix('[') {
        // Bracketed IPv6: [::1] or [::1]:8080.
        Some(rest) => {
            let end = rest.find(']').ok_or(WorkerError::ObservationMalformed(
                "node URL has a bad IPv6 host",
            ))?;
            let h = &rest[..end];
            let tail = &rest[end + 1..];
            let port: u16 = if let Some(p) = tail.strip_prefix(':') {
                p.parse()
                    .map_err(|_| WorkerError::ObservationMalformed("node URL port is not a number"))?
            } else if !tail.is_empty() {
                return Err(WorkerError::ObservationMalformed("node URL has a bad IPv6 host"));
            } else {
                80
            };
            (h.to_string(), port)
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => {
                let port: u16 = p.parse().map_err(|_| {
                    WorkerError::ObservationMalformed("node URL port is not a number")
                })?;
                (h.to_string(), port)
            }
            // Bare IPv6 without brackets is refused: it cannot be split
            // from a port unambiguously.
            Some((h, _)) if h.contains(':') || authority.contains(':') => {
                return Err(WorkerError::ObservationMalformed(
                    "bare IPv6 needs brackets, e.g. http://[::1]:8080",
                ));
            }
            _ => (authority.to_string(), 80),
        },
    };
    if host.is_empty() {
        return Err(WorkerError::ObservationMalformed("node URL has no host"));
    }
    let prefix = path.trim_end_matches('/').to_string();
    Ok(Endpoint { host, port, prefix })
}

fn find_crlfcrlf(haystack: &[u8]) -> Option<usize> {
    haystack.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Outcome of trying to finish a response body from what has been read.
#[derive(Debug, PartialEq, Eq)]
enum Body {
    Complete(Vec<u8>),
    NeedMore,
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// Decode a complete chunked body, or say it is incomplete. Anything else —
/// a bad size line, a short chunk, a missing terminator — is malformed.
#[allow(dead_code)]
fn decode_chunked(input: &[u8]) -> Result<Body, Transport> {
    decode_chunked_capped(input, 8 * 1024 * 1024)
}

fn decode_chunked_capped(input: &[u8], max_bytes: usize) -> Result<Body, Transport> {
    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0usize;
    loop {
        let line_end = find_subslice(&input[pos..], b"\r\n").ok_or(Transport::Malformed(
            "chunked frame has no size line terminator",
        ))?;
        let size_line = std::str::from_utf8(&input[pos..pos + line_end])
            .map_err(|_| Transport::Malformed("chunk size is not ascii"))?;
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        if size_str.is_empty() {
            return Err(Transport::Malformed("empty chunk size"));
        }
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| Transport::Malformed("chunk size is not hex"))?;
        pos += line_end + 2;
        if size == 0 {
            // Trailer section: ends at the next CRLF CRLF, or one bare CRLF.
            // A partial trailer is incomplete input, not malformed.
            if input.len() < pos + 2 {
                return Ok(Body::NeedMore);
            }
            if &input[pos..pos + 2] == b"\r\n" {
                return Ok(Body::Complete(out));
            }
            match find_crlfcrlf(&input[pos..]) {
                Some(_) => return Ok(Body::Complete(out)),
                None => {
                    // No terminator yet — could be a split trailer.
                    // Only malformed if we can prove it: a trailer must be
                    // header lines, so a bare LF-free garbage block longer
                    // than any sane header means malformed. Otherwise wait.
                    return Ok(Body::NeedMore);
                }
            }
        }
        if input.len() < pos + size + 2 {
            return Ok(Body::NeedMore);
        }
        if &input[pos + size..pos + size + 2] != b"\r\n" {
            return Err(Transport::Malformed("chunk is not terminated by CRLF"));
        }
        out.extend_from_slice(&input[pos..pos + size]);
        if out.len() > max_bytes {
            return Err(Transport::Malformed("chunked body over cap"));
        }
        pos += size + 2;
    }
}

/// One bounded request/response exchange. Returns the body of a 2xx response.
///
/// Reads in bounded steps and never waits on the peer after the declared body
/// has arrived, so a server that keeps the socket open cannot hang a worker.
fn exchange(
    endpoint: &Endpoint,
    connect_timeout: Duration,
    read_timeout: Duration,
    max_response_bytes: usize,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Vec<u8>, Transport> {
    exchange_full(
        endpoint,
        connect_timeout,
        read_timeout,
        max_response_bytes,
        method,
        path,
        body,
        &[],
    )
    .and_then(|(code, _, done)| {
        if (200..300).contains(&code) {
            return Ok(done);
        }
        let detail = String::from_utf8_lossy(&done);
        let detail = serde_json::from_slice::<Value>(&done)
            .ok()
            .and_then(|v| {
                v.get("detail")
                    .or_else(|| v.get("error"))
                    .map(|d| d.to_string())
            })
            .unwrap_or_else(|| truncate(&detail, 200));
        Err(Transport::Status { code, detail })
    })
}

/// The same exchange, but with caller-supplied request headers and the full
/// response: status code, response headers as `(name, value)` pairs, and the
/// body. Non-2xx is returned, not refused — the x402 challenge *is* a 402.
/// `exchange` above is this function with the historical 2xx-only contract, so
/// every existing call site keeps its exact behaviour.
/// A full HTTP response: status code, response headers as `(name, value)`
/// pairs, and the body. Used by the x402 paid path, where the challenge *is*
/// a non-2xx and headers carry the protocol.
pub type FullResponse = (u16, Vec<(String, String)>, Vec<u8>);

/// Same knobs as [`exchange`], plus caller headers — kept as one function
/// rather than a new transport so the framing, caps and error taxonomy stay
/// in exactly one place.
#[allow(clippy::too_many_arguments)]
fn exchange_full(
    endpoint: &Endpoint,
    connect_timeout: Duration,
    read_timeout: Duration,
    max_response_bytes: usize,
    method: &str,
    path: &str,
    body: Option<&str>,
    extra_headers: &[(String, String)],
) -> Result<FullResponse, Transport> {
    let addrs = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|_| Transport::Unreachable("node address does not resolve"))?
        .collect::<Vec<_>>();
    let addr = addrs
        .first()
        .ok_or(Transport::Unreachable("node address does not resolve"))?;
    let mut stream = TcpStream::connect_timeout(addr, connect_timeout)
        .map_err(|_| Transport::Unreachable("connect failed"))?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|_| Transport::Unreachable("cannot set read timeout"))?;
    stream
        .set_write_timeout(Some(read_timeout))
        .map_err(|_| Transport::Unreachable("cannot set write timeout"))?;

    let target = format!("{}/{}", endpoint.prefix, path.trim_start_matches('/'));
    let target = if target.starts_with('/') {
        target
    } else {
        format!("/{target}")
    };
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nAccept: application/json\r\n",
        endpoint.host, endpoint.port
    );
    for (name, value) in extra_headers {
        if name.len() > 128 || value.len() > 16 * 1024 {
            return Err(Transport::Malformed("request header over cap"));
        }
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(Transport::Malformed("request header name is not a token"));
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(Transport::Malformed("request header value splits lines"));
        }
        req.push_str(name);
        req.push_str(": ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    stream
        .write_all(req.as_bytes())
        .map_err(|_| Transport::Unreachable("write failed"))?;
    stream
        .flush()
        .map_err(|_| Transport::Unreachable("write failed"))?;

    // --- headers ---------------------------------------------------------
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let head_end = loop {
        if let Some(pos) = find_crlfcrlf(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Transport::Malformed("header block over cap"));
        }
        let mut chunk = [0u8; 4096];
        let n = stream
            .read(&mut chunk)
            .map_err(|_| Transport::Unreachable("read failed"))?;
        if n == 0 {
            return Err(Transport::Malformed(
                "connection closed before headers ended",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| Transport::Malformed("status line is not ascii"))?;
    let status_line = head
        .lines()
        .next()
        .ok_or(Transport::Malformed("empty status line"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(Transport::Malformed("not an HTTP/1.x response"));
    }
    let code: u16 = parts
        .next()
        .ok_or(Transport::Malformed("status line has no code"))?
        .parse()
        .map_err(|_| Transport::Malformed("status code is not a number"))?;
    if !(100..=599).contains(&code) {
        return Err(Transport::Malformed("status code out of range"));
    }
    let header_block = &head[head_line_len(head)..];
    let content_length = match header_value(header_block, "content-length") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| Transport::Malformed("content-length is not a number"))?,
        ),
        None => None,
    };
    let chunked = header_value(header_block, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    let mut body_buf = buf[head_end + 4..].to_vec();
    if body_buf.len() > max_response_bytes {
        return Err(Transport::Malformed("response body over cap"));
    }

    // --- body ------------------------------------------------------------
    let done = loop {
        let attempt = if chunked {
            decode_chunked_capped(&body_buf, max_response_bytes)?
        } else if let Some(n) = content_length {
            if n > max_response_bytes {
                return Err(Transport::Malformed("declared body over cap"));
            }
            if body_buf.len() >= n {
                Body::Complete(body_buf[..n].to_vec())
            } else {
                Body::NeedMore
            }
        } else {
            // No framing: the body ends when the connection does (we asked
            // for `Connection: close`), so it is only complete at EOF.
            Body::NeedMore
        };
        match attempt {
            Body::Complete(b) => break b,
            Body::NeedMore => {
                if body_buf.len() > max_response_bytes {
                    return Err(Transport::Malformed("response body over cap"));
                }
                let mut chunk = [0u8; 8192];
                let n = match stream.read(&mut chunk) {
                    Ok(0) => {
                        // EOF completes an unframed body; it truncates every
                        // other framing, which is a malformed response.
                        if content_length.is_none() && !chunked {
                            break body_buf;
                        }
                        return Err(Transport::Malformed("connection closed before body ended"));
                    }
                    Ok(n) => n,
                    Err(_) => return Err(Transport::Unreachable("read failed")),
                };
                body_buf.extend_from_slice(&chunk[..n]);
            }
        }
    };
    if done.len() > max_response_bytes {
        return Err(Transport::Malformed("response body over cap"));
    }

    let mut headers_out: Vec<(String, String)> = Vec::new();
    for line in header_block.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Transport::Malformed("response header has no colon"));
        };
        if headers_out.len() >= 64 {
            return Err(Transport::Malformed("too many response headers"));
        }
        headers_out.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok((code, headers_out, done))
}

fn head_line_len(head: &str) -> usize {
    head.find("\r\n").map(|i| i + 2).unwrap_or(head.len())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }
}

// ---------------------------------------------------------------------------
// The node handle
// ---------------------------------------------------------------------------

/// What one successful observation of `/v1/l2/state` yielded.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The node's canonical L2 state, decoded and self-validated.
    pub state: L2State,
    /// The chain height that state reflects — read from the *same* response,
    /// so a block landing between two calls can never pair one height with
    /// another state's contents.
    pub height: u64,
    /// The network the node says it is on.
    pub network_id: String,
}

/// What the node's `GET /v1/conservation` reported about joint supply.
///
/// The node sums the terms; the SDK re-derives the verdict from the numbers
/// itself ([`holds`](ConservationReport::holds)) rather than trusting the
/// node's `ok` flag — a view is untrusted data (§18.3), and a node that is
/// wrong about conservation is exactly the node a worker must not earn from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConservationReport {
    /// Live L1 UTXO supply, sat.
    pub l1_live_sat: u64,
    /// Everything L2 still holds, sat.
    pub l2_held_sat: u64,
    /// Value sitting in the deposit sink (counted on both sides; subtracted once).
    pub sink_held_sat: u64,
    /// The node's own `l1 + l2 − sink` figure, sat.
    pub joint_sat: u64,
    /// The joint ceiling the verdict uses: the node's `joint_bound_sat`
    /// (issuance integral at the tip plus escrow ceiling). Required: the
    /// stock cap it once fell back to is gone with Decision 18.
    pub joint_bound_sat: u64,
    /// L2's buckets still sum to what was released into L2.
    pub l2_closed: bool,
    /// L2 was funded by exactly genesis plus matured deposits.
    pub l2_funding_ok: bool,
    /// The node's own all-clear, kept for the record; never relied on.
    pub node_ok: bool,
}

impl ConservationReport {
    /// The invariant, recomputed here: joint equals `l1 + l2 − sink`, that is
    /// inside the joint bound, and both L2 checks hold. A report whose numbers do
    /// not re-add is refused exactly like one that states a breach — a node
    /// that cannot add is as untrusted as one that lies.
    pub fn holds(&self) -> bool {
        let recomputed = self
            .l1_live_sat
            .saturating_add(self.l2_held_sat)
            .saturating_sub(self.sink_held_sat);
        recomputed == self.joint_sat
            && self.joint_sat <= self.joint_bound_sat
            && self.l2_closed
            && self.l2_funding_ok
    }

    /// Satoshis of headroom the report carries under the joint bound.
    pub fn headroom_sat(&self) -> u64 {
        self.joint_bound_sat.saturating_sub(self.joint_sat)
    }
}

/// Decode a `/v1/conservation` body. Every field is required: a report a
/// worker cannot fully read is one it cannot act on.
fn parse_conservation(value: &Value) -> WorkerResult<ConservationReport> {
    let num = |key: &str| -> WorkerResult<u64> {
        value
            .get(key)
            .and_then(Value::as_u64)
            .ok_or(WorkerError::ObservationMalformed(
                "conservation response is missing a numeric field",
            ))
    };
    let flag = |key: &str| -> WorkerResult<bool> {
        value
            .get(key)
            .and_then(Value::as_bool)
            .ok_or(WorkerError::ObservationMalformed(
                "conservation response is missing a boolean field",
            ))
    };
    Ok(ConservationReport {
        l1_live_sat: num("l1_live_sat")?,
        l2_held_sat: num("l2_held_sat")?,
        sink_held_sat: num("sink_held_sat")?,
        joint_sat: num("joint_sat")?,
        joint_bound_sat: num("joint_bound_sat")?,
        l2_closed: flag("l2_closed")?,
        l2_funding_ok: flag("l2_funding_ok")?,
        node_ok: flag("ok")?,
    })
}

/// A worker's view of a node over HTTP.
///
/// Construct with [`HttpNode::new`] (or [`HttpNode::for_network`] to bind the
/// node to an expected `network_id`) and pass it to `WorkerClient::new` as
/// both `V` and `B`: it implements the read and the write seam.
#[derive(Debug)]
pub struct HttpNode {
    endpoint: Endpoint,
    connect_timeout: Duration,
    read_timeout: Duration,
    max_response_bytes: usize,
    expected_network: Option<String>,
    /// Height of the last state this handle returned. `chain_height` serves
    /// it rather than fetching again, so the state and the height a decision
    /// is built from always come from one observation.
    observed_height: Mutex<Option<u64>>,
}

impl HttpNode {
    /// Connect to `base_url` — e.g. `http://127.0.0.1:8080`. Plain HTTP only.
    pub fn new(base_url: impl Into<String>) -> WorkerResult<Self> {
        Ok(HttpNode {
            endpoint: parse_url(&base_url.into())?,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            expected_network: None,
            observed_height: Mutex::new(None),
        })
    }

    /// Bind the handle to a network: an observation from any other network is
    /// refused instead of being handed to the SDK. A worker pointed at the
    /// wrong node fails closed rather than discovering foreign tasks.
    pub fn for_network(
        base_url: impl Into<String>,
        network_id: impl Into<String>,
    ) -> WorkerResult<Self> {
        let mut node = Self::new(base_url)?;
        node.expected_network = Some(network_id.into());
        Ok(node)
    }

    pub fn with_timeouts(mut self, connect: Duration, read: Duration) -> Self {
        self.connect_timeout = connect;
        self.read_timeout = read;
        self
    }

    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    /// One exchange, with `404` turned into `Ok(None)` — the node's own
    /// "no such resource" answer, which is a fact rather than a transport
    /// failure (a task that does not exist is not an unreachable node).
    fn raw(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<Option<Vec<u8>>, Transport> {
        match exchange(
            &self.endpoint,
            self.connect_timeout,
            self.read_timeout,
            self.max_response_bytes,
            method,
            path,
            body,
        ) {
            Ok(b) => Ok(Some(b)),
            Err(Transport::Status { code: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> WorkerResult<Vec<u8>> {
        self.raw(method, path, body)
            .map_err(|e| e.into_observation())?
            .ok_or(WorkerError::ObservationMalformed(
                "node has no such resource",
            ))
    }

    /// Fetch and decode the node's JSON object at `path`. The paid-resource,
    /// stream and policy reads share this seam rather than each growing one.
    pub fn get_json(&self, path: &str) -> WorkerResult<Value> {
        let body = self.request("GET", path, None)?;
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| WorkerError::ObservationMalformed("response is not JSON"))?;
        if !value.is_object() {
            return Err(WorkerError::ObservationMalformed(
                "response is not a JSON object",
            ));
        }
        Ok(value)
    }

    /// Fetch and decode the node's canonical state. The one place an
    /// observation enters the SDK.
    pub fn observe(&self) -> WorkerResult<Observation> {
        let value = self.get_json("/v1/l2/state")?;
        let network_id = value
            .get("network_id")
            .and_then(Value::as_str)
            .ok_or(WorkerError::ObservationMalformed(
                "state response has no network_id",
            ))?
            .to_string();
        if let Some(expected) = &self.expected_network {
            if &network_id != expected {
                // Wrong network, stated by name: never treated as "no tasks".
                return Err(WorkerError::ObservationMalformed(
                    "node serves another network",
                ));
            }
        }
        let height = value.get("height").and_then(Value::as_u64).ok_or(
            WorkerError::ObservationMalformed("state response has no height"),
        )?;
        let hex = value.get("state_hex").and_then(Value::as_str).ok_or(
            WorkerError::ObservationMalformed("state response has no state_hex"),
        )?;
        let bytes = hex::decode(hex)
            .map_err(|_| WorkerError::ObservationMalformed("state_hex is not valid hex"))?;
        // The codec version-checks, bounds every count, rejects trailing bytes
        // and re-checks the conservation invariant before returning a state.
        let state = L2State::decode(&bytes)
            .map_err(|_| WorkerError::ObservationMalformed("state blob does not decode"))?;

        if let Ok(mut slot) = self.observed_height.lock() {
            *slot = Some(height);
        }
        Ok(Observation {
            state,
            height,
            network_id,
        })
    }

    /// The task view the node holds for `task_id`, as the node renders it.
    /// `Err(UnknownTask)` is the node saying it does not have that task.
    pub fn task(&self, task_id: &Hash) -> WorkerResult<Value> {
        let path = format!("/v1/task/{}", hex::encode(task_id));
        let body = self
            .raw("GET", &path, None)
            .map_err(|e| e.into_observation())?
            .ok_or(WorkerError::UnknownTask)?;
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| WorkerError::ObservationMalformed("task response is not JSON"))?;
        if !value.is_object() {
            return Err(WorkerError::ObservationMalformed(
                "task response is not a JSON object",
            ));
        }
        Ok(value)
    }

    /// The node's list of claimable tasks.
    pub fn open_tasks(&self) -> WorkerResult<Vec<Value>> {
        let value = self.get_json("/v1/tasks/open")?;
        value.get("tasks").and_then(Value::as_array).cloned().ok_or(
            WorkerError::ObservationMalformed("open-tasks response has no tasks array"),
        )
    }

    /// The certificate for a task, decoded from the node's canonical encoding
    /// so a relying party can verify it against the validator set itself
    /// (§17.6) rather than trusting the node's summary. `Ok(None)` is the
    /// node saying there is no certificate — a fact, not a failure.
    pub fn vwc(&self, task_id: &Hash) -> WorkerResult<Option<VerifiedWorkCertificate>> {
        let path = format!("/v1/vwc/{}", hex::encode(task_id));
        let Some(body) = self
            .raw("GET", &path, None)
            .map_err(|e| e.into_observation())?
        else {
            // The node has no certificate for this task — a fact about the
            // chain, not a transport failure.
            return Ok(None);
        };
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| WorkerError::ObservationMalformed("vwc response is not JSON"))?;
        let hex = value.get("vwc_hex").and_then(Value::as_str).ok_or(
            WorkerError::ObservationMalformed("vwc response has no vwc_hex"),
        )?;
        let bytes = hex::decode(hex)
            .map_err(|_| WorkerError::ObservationMalformed("vwc_hex is not valid hex"))?;
        let cert = VerifiedWorkCertificate::decode(&bytes)
            .map_err(|_| WorkerError::ObservationMalformed("certificate does not decode"))?;
        if cert.task_id != *task_id {
            return Err(WorkerError::ObservationMalformed(
                "certificate names another task",
            ));
        }
        Ok(Some(cert))
    }

    /// A stored receipt by receipt id or payment id, as the node renders it.
    /// The canonical bytes ride along as `receipt_hex` for offline verification.
    pub fn receipt(&self, receipt_id: &Hash) -> WorkerResult<Value> {
        self.get_json(&format!("/v1/receipt/{}", hex::encode(receipt_id)))
    }

    /// The stored payment for `payment_id`, as the node renders it
    /// (`payment_hex` carries the canonical `MachinePayment` bytes).
    pub fn payment(&self, payment_id: &Hash) -> WorkerResult<Value> {
        self.get_json(&format!("/v1/payment/{}", hex::encode(payment_id)))
    }

    /// Raw exchange with caller headers and the full response: status code,
    /// response headers, body. The x402 challenge *is* a non-2xx, so the paid
    /// path cannot use the 2xx-only `request` above.
    pub fn get_full(
        &self,
        path: &str,
        extra_headers: &[(String, String)],
    ) -> WorkerResult<FullResponse> {
        exchange_full(
            &self.endpoint,
            self.connect_timeout,
            self.read_timeout,
            self.max_response_bytes,
            "GET",
            path,
            None,
            extra_headers,
        )
        .map_err(|e| e.into_observation())
    }

    /// The chain's nonce counter for one agent's live grant, or `None` when the
    /// agent has no published grant. The next spend must use exactly one more —
    /// anything else is refused at admission, so a client that guesses instead
    /// of reading burns a broadcast.
    pub fn policy_last_nonce(&self, agent_id: &[u8; 20]) -> WorkerResult<Option<u64>> {
        let path = format!("/v1/policies/{}", hex::encode(agent_id));
        let Some(body) = self
            .raw("GET", &path, None)
            .map_err(|e| e.into_observation())?
        else {
            return Ok(None);
        };
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| WorkerError::ObservationMalformed("policy response is not JSON"))?;
        value
            .get("last_nonce")
            .and_then(Value::as_u64)
            .map(Some)
            .ok_or(WorkerError::ObservationMalformed(
                "policy response has no last_nonce",
            ))
    }

    /// POST a JSON body and decode the JSON object answer. Used by the
    /// micro-payment helpers (batch quotes, stream open/settle), which are
    /// read/admission calls rather than observations or broadcasts.
    pub fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> WorkerResult<serde_json::Value> {
        let raw = exchange(
            &self.endpoint,
            self.connect_timeout,
            self.read_timeout,
            self.max_response_bytes,
            "POST",
            path,
            Some(&body.to_string()),
        )
        .map_err(|e| e.into_observation())?;
        let value: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|_| WorkerError::ObservationMalformed("response is not JSON"))?;
        if !value.is_object() {
            return Err(WorkerError::ObservationMalformed(
                "response is not a JSON object",
            ));
        }
        Ok(value)
    }

    /// POST a JSON body and return the status with the body, without deciding
    /// success: a refusal carries the server's named reason (`error` +
    /// `detail`), and the verb — not the transport — decides what a status
    /// means. Without this the node names the cause and the CLI swallows it.
    pub fn post_full(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> WorkerResult<(u16, serde_json::Value)> {
        let (code, _, done) = exchange_full(
            &self.endpoint,
            self.connect_timeout,
            self.read_timeout,
            self.max_response_bytes,
            "POST",
            path,
            Some(&body.to_string()),
            &[],
        )
        .map_err(|e| e.into_observation())?;
        if done.is_empty() {
            return Ok((code, serde_json::Value::Null));
        }
        let value: serde_json::Value = serde_json::from_slice(&done)
            .map_err(|_| WorkerError::ObservationMalformed("response is not JSON"))?;
        Ok((code, value))
    }

    /// GET and return the status with the decoded body. Like [`Self::post_full`]:
    /// the caller decides what the status means; the node names its refusals.
    pub fn get_full_json(&self, path: &str) -> WorkerResult<(u16, serde_json::Value)> {
        let (code, _, done) = exchange_full(
            &self.endpoint,
            self.connect_timeout,
            self.read_timeout,
            self.max_response_bytes,
            "GET",
            path,
            None,
            &[],
        )
        .map_err(|e| e.into_observation())?;
        if done.is_empty() {
            return Ok((code, serde_json::Value::Null));
        }
        let value: serde_json::Value = serde_json::from_slice(&done)
            .map_err(|_| WorkerError::ObservationMalformed("response is not JSON"))?;
        Ok((code, value))
    }

    /// The server's own refusal (`error: detail`), when it bothered to name
    /// one. Callers print this rather than a generic transport line so the
    /// operator sees the node's reason, not the SDK's paraphrase.
    pub fn refusal_detail(body: &serde_json::Value) -> Option<String> {
        let error = body.get("error")?.as_str()?;
        let detail = body
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        Some(if detail.is_empty() {
            error.to_string()
        } else {
            format!("{error}: {detail}")
        })
    }

    /// The node's live conservation report (joint L1 + L2 − sink supply vs
    /// the joint bound), or `Ok(None)` when the node does not expose the endpoint —
    /// an older build, which is a fact about the node rather than a failure.
    ///
    /// A `200` whose body cannot be read is `ObservationMalformed`: the node
    /// *answered*, and its answer cannot be trusted — a different fact from
    /// the node being unreachable (`ObservationUnavailable`), which this
    /// returns like any other transport failure. The verdict is never taken
    /// from the node's `ok` flag; see [`ConservationReport::holds`].
    pub fn conservation(&self) -> WorkerResult<Option<ConservationReport>> {
        let Some(body) = self
            .raw("GET", "/v1/conservation", None)
            .map_err(|e| e.into_observation())?
        else {
            return Ok(None);
        };
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| WorkerError::ObservationMalformed("conservation response is not JSON"))?;
        if !value.is_object() {
            return Err(WorkerError::ObservationMalformed(
                "conservation response is not a JSON object",
            ));
        }
        parse_conservation(&value).map(Some)
    }
}

impl L2NodeView for HttpNode {
    fn l2_state(&self) -> WorkerResult<L2State> {
        self.observe().map(|o| o.state)
    }

    fn chain_height(&self) -> WorkerResult<u64> {
        // Serve the height of the state this handle already returned, so state
        // and height always describe one observation. Fetch only when nothing
        // has been observed yet.
        if let Ok(slot) = self.observed_height.lock() {
            if let Some(h) = *slot {
                return Ok(h);
            }
        }
        self.observe().map(|o| o.height)
    }
}

impl L2Broadcaster for HttpNode {
    fn broadcast(&mut self, tx: &L2Transaction) -> Result<(), BroadcastError> {
        let body = json!({ "l2_tx_hex": hex::encode(tx.serialize()) }).to_string();
        // The write seam reports its own errors (4xx = refusal), so it does not
        // go through `into_observation`.
        exchange(
            &self.endpoint,
            self.connect_timeout,
            self.read_timeout,
            self.max_response_bytes,
            "POST",
            "/v1/l2/broadcast",
            Some(&body),
        )
        .map(|_| ())
        .map_err(|e| e.into_broadcast())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing_is_total_and_named() {
        let e = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.port, 8080);
        assert_eq!(e.prefix, "");

        let e = parse_url("http://node.local/api/v1/").unwrap();
        assert_eq!(e.prefix, "/api/v1");

        let e = parse_url("http://node.local").unwrap();
        assert_eq!(e.port, 80);

        // https is refused by name, never silently downgraded.
        assert!(parse_url("https://node.local").is_err());
        assert!(parse_url("node.local").is_err());
        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://host:99999").is_err());
    }

    #[test]
    fn chunked_frames_decode_or_say_they_are_incomplete() {
        let ok = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(
            decode_chunked(ok).unwrap(),
            Body::Complete(b"hello".to_vec())
        );
        let partial = b"5\r\nhel";
        assert!(matches!(decode_chunked(partial).unwrap(), Body::NeedMore));
        // Missing CRLF after the chunk data.
        assert!(decode_chunked(b"5\r\nhelloXX").is_err());
        // Not hex.
        assert!(decode_chunked(b"zz\r\nx\r\n").is_err());
        // Empty size line.
        assert!(decode_chunked(b"\r\n").is_err());
    }

    /// A well-formed healthy report body, with fields the tests may tweak.
    fn report_json() -> Value {
        json!({
            "ok": true,
            "l2_closed": true,
            "l2_funding_ok": true,
            "joint_sat": 1_010,
            "joint_bound_sat": 10_000,
            "l1_bound_sat": 9_000,
            "escrow_ceiling_sat": 1_000,
            "headroom_sat": 8_990,
            "l1_live_sat": 10,
            "l2_held_sat": 1_000,
            "sink_held_sat": 0,
            "network_id": "srct/mini",
            "height": 3,
        })
    }

    #[test]
    fn conservation_holds_only_when_the_numbers_re_add() {
        let r = parse_conservation(&report_json()).unwrap();
        assert!(r.holds());
        assert_eq!(r.headroom_sat(), 8_990);

        // Joint claims more than the terms sum to — refused.
        let mut v = report_json();
        v["joint_sat"] = json!(1_011);
        assert!(!parse_conservation(&v).unwrap().holds());

        // Joint over the bound — refused, even though it re-adds.
        let mut v = report_json();
        v["joint_sat"] = json!(10_001);
        v["l1_live_sat"] = json!(10_001);
        assert!(!parse_conservation(&v).unwrap().holds());

        // Each L2 check broken on its own — refused.
        let mut v = report_json();
        v["l2_closed"] = json!(false);
        assert!(!parse_conservation(&v).unwrap().holds());
        let mut v = report_json();
        v["l2_funding_ok"] = json!(false);
        assert!(!parse_conservation(&v).unwrap().holds());

        // The node's own `ok` claim is never what the verdict rests on.
        let mut v = report_json();
        v["ok"] = json!(false);
        let r = parse_conservation(&v).unwrap();
        assert!(r.holds() && !r.node_ok);
    }

    #[test]
    fn conservation_decode_requires_every_field() {
        for key in [
            "l1_live_sat",
            "l2_held_sat",
            "sink_held_sat",
            "joint_sat",
            "joint_bound_sat",
            "l2_closed",
            "l2_funding_ok",
            "ok",
        ] {
            let mut v = report_json();
            v.as_object_mut().unwrap().remove(key);
            assert!(
                matches!(
                    parse_conservation(&v),
                    Err(WorkerError::ObservationMalformed(_))
                ),
                "a report missing {key} must be refused"
            );
        }
        // A present-but-wrong-typed field is refused the same way.
        let mut v = report_json();
        v["joint_sat"] = json!("a lot");
        assert!(matches!(
            parse_conservation(&v),
            Err(WorkerError::ObservationMalformed(_))
        ));
    }

    #[test]
    fn transport_errors_map_to_the_seam_that_reported_them() {
        let refused = Transport::Status {
            code: 409,
            detail: "replay".into(),
        };
        assert_eq!(
            refused.clone().into_broadcast(),
            BroadcastError::Refused("replay".into())
        );
        assert!(matches!(
            refused.into_observation(),
            WorkerError::ObservationUnavailable(_)
        ));

        let server_broke = Transport::Status {
            code: 503,
            detail: "overloaded".into(),
        };
        assert!(matches!(
            server_broke.clone().into_broadcast(),
            BroadcastError::Retryable(_)
        ));
        // The server's own text never rides into the write path's reason when
        // the status is not a refusal — a retry reason is a classification.
        let unreachable = Transport::Unreachable("connect failed");
        assert_eq!(
            unreachable.clone().into_broadcast(),
            BroadcastError::Retryable("connect failed".to_string())
        );
        assert!(matches!(
            unreachable.into_observation(),
            WorkerError::ObservationUnavailable("connect failed")
        ));
    }
}
