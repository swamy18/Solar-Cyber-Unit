//! HTTP/MCP transport wire formats (non-consensus).
//!
//! The socket is the operator's: a loopback HTTP server, an MCP tool call, a
//! queue. These are the bytes it carries, with the same fail-closed decoding
//! as every other wire format in this crate. `deliver` pushes envelopes,
//! `poll` pulls them, `ack` confirms them (see [`crate::presence::AckSet`]).

use srct_core::agent::AgentId;
use srct_core::hash::Hash;
use srct_core::ser::{Reader, Writer};

use crate::message::MessageError;

pub const HTTP_CODEC_VERSION: u8 = 1;
/// Most bytes one transport body may carry.
pub const MAX_TRANSPORT_BODY: usize = 256 * 1024;
/// Most envelopes one poll response may carry.
pub const MAX_POLL_MESSAGES: usize = 256;

fn bad(detail: &str) -> MessageError {
    MessageError::Malformed(format!("transport: {detail}"))
}

fn write_blob(w: &mut Writer, bytes: &[u8]) {
    w.u32le(bytes.len() as u32).raw(bytes);
}

fn read_blob(r: &mut Reader) -> Result<Vec<u8>, MessageError> {
    let len = r.u32le().map_err(|e| bad(&e.to_string()))? as usize;
    if len == 0 || len > MAX_TRANSPORT_BODY {
        return Err(bad("body is over cap"));
    }
    Ok(r.fixed_slice(len)
        .map_err(|e| bad(&e.to_string()))?
        .to_vec())
}

/// Push one envelope (normal or sealed wire bytes) to a recipient agent.
#[derive(Clone, Debug, PartialEq)]
pub struct DeliverRequest {
    pub version: u8,
    pub recipient: AgentId,
    pub envelope: Vec<u8>,
}

impl DeliverRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.envelope.len());
        w.u8(self.version).fixed(&self.recipient);
        write_blob(&mut w, &self.envelope);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_TRANSPORT_BODY {
            return Err(bad("request is over cap"));
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| bad(&e.to_string()))?;
        if version != HTTP_CODEC_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let recipient: AgentId = r.fixed().map_err(|e| bad(&e.to_string()))?;
        let envelope = read_blob(&mut r)?;
        r.expect_end().map_err(|e| bad(&e.to_string()))?;
        Ok(DeliverRequest {
            version,
            recipient,
            envelope,
        })
    }
}

/// Result of one `deliver`: accepted envelope ids plus a refusal count.
/// A refused packet never blocks the packets behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliverResponse {
    pub version: u8,
    pub accepted: Vec<Hash>,
    pub refused: u32,
}

impl DeliverResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.accepted.len() * 32);
        w.u8(self.version).u32le(self.accepted.len() as u32);
        for id in &self.accepted {
            w.fixed(id);
        }
        w.u32le(self.refused);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_TRANSPORT_BODY {
            return Err(bad("response is over cap"));
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| bad(&e.to_string()))?;
        if version != HTTP_CODEC_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let count = r.u32le().map_err(|e| bad(&e.to_string()))? as usize;
        if count > MAX_POLL_MESSAGES {
            return Err(bad("response is over cap"));
        }
        let mut accepted = Vec::with_capacity(count);
        for _ in 0..count {
            accepted.push(r.fixed().map_err(|e| bad(&e.to_string()))?);
        }
        let refused = r.u32le().map_err(|e| bad(&e.to_string()))?;
        r.expect_end().map_err(|e| bad(&e.to_string()))?;
        Ok(DeliverResponse {
            version,
            accepted,
            refused,
        })
    }
}

/// Ask for queued envelopes for one agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollRequest {
    pub version: u8,
    pub agent: AgentId,
    pub since_height: u64,
    pub limit: u16,
}

impl PollRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.u8(self.version)
            .fixed(&self.agent)
            .u64le(self.since_height)
            .u16le(self.limit);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > 128 {
            return Err(bad("poll request is over cap"));
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| bad(&e.to_string()))?;
        if version != HTTP_CODEC_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let agent: AgentId = r.fixed().map_err(|e| bad(&e.to_string()))?;
        let since_height = r.u64le().map_err(|e| bad(&e.to_string()))?;
        let limit = r.u16le().map_err(|e| bad(&e.to_string()))?;
        r.expect_end().map_err(|e| bad(&e.to_string()))?;
        Ok(PollRequest {
            version,
            agent,
            since_height,
            limit,
        })
    }
}

/// Queued envelopes for one agent, in queue order.
#[derive(Clone, Debug, PartialEq)]
pub struct PollResponse {
    pub version: u8,
    pub messages: Vec<Vec<u8>>,
}

impl PollResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.messages.len() * 256);
        w.u8(self.version).u32le(self.messages.len() as u32);
        for m in &self.messages {
            write_blob(&mut w, m);
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_TRANSPORT_BODY {
            return Err(bad("response is over cap"));
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| bad(&e.to_string()))?;
        if version != HTTP_CODEC_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let count = r.u32le().map_err(|e| bad(&e.to_string()))? as usize;
        if count > MAX_POLL_MESSAGES {
            return Err(bad("response is over cap"));
        }
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            messages.push(read_blob(&mut r)?);
        }
        r.expect_end().map_err(|e| bad(&e.to_string()))?;
        Ok(PollResponse { version, messages })
    }
}
