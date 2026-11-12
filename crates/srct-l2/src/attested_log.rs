//! Staged TEE execution log (inactive by default).
//!
//! A bounded, replay-safe record of verified TEE attestations keyed by task.
//! `record` verifies the full attestation (signature, measurements, bindings,
//! freshness, replay) through the same verifier the rails use, then files it
//! under the task id. A task logs once; a second attestation for the same
//! task is a replay, never an update.
//!
//! What this is not: consensus activation. `L2State` does not read this log
//! and no block rule depends on it — that wiring needs the formal
//! consensus-change process. The log is staged state with an explicit switch:
//! `enabled = false` refuses every record, `enabled = true` enforces every
//! check. Snapshots re-verify every attestation on replay.

use std::collections::BTreeMap;

use srct_core::hash::Hash;
use srct_core::ser::{Reader, Writer};
use srct_verify::{AttestationRoots, UnifiedVerifier};

use crate::error::{L2Error, L2Result};
use crate::tee_evidence::TeeBackedAttestation;

pub const ATTESTED_LOG_VERSION: u8 = 1;
/// Most tasks one log holds. Past the cap the operator archives.
pub const MAX_LOG_TASKS: usize = 4096;
/// Most bytes one encoded attestation may occupy in a snapshot.
pub const MAX_LOG_BLOB: usize = 8 * 1024;

/// Staged record of verified TEE executions, keyed by task id.
#[derive(Clone, Debug, Default)]
pub struct AttestedExecutionLog {
    enabled: bool,
    network_id: String,
    entries: BTreeMap<Hash, (TeeBackedAttestation, u64)>,
}

impl AttestedExecutionLog {
    pub fn new(network_id: impl Into<String>, enabled: bool) -> Self {
        AttestedExecutionLog {
            enabled,
            network_id: network_id.into(),
            entries: BTreeMap::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, task: &Hash) -> Option<&(TeeBackedAttestation, u64)> {
        self.entries.get(task)
    }

    /// Verify and file an attestation under its task id.
    ///
    /// Refuses when the log is disabled, when the attestation names another
    /// network, when the task already logged (replay), when the log is full,
    /// and when any cryptographic check fails.
    pub fn record(
        &mut self,
        attestation: TeeBackedAttestation,
        roots: &AttestationRoots,
        verifier: &mut UnifiedVerifier,
        height: u64,
    ) -> Result<Hash, L2Error> {
        if !self.enabled {
            return Err(L2Error::BadAttestation("attested log is not active"));
        }
        if attestation.sla.network_id != self.network_id {
            return Err(L2Error::BadAttestation(
                "attestation is for another network",
            ));
        }
        let task = attestation.sla.workload;
        if self.entries.contains_key(&task) {
            return Err(L2Error::Replay);
        }
        if self.entries.len() >= MAX_LOG_TASKS {
            return Err(L2Error::BadAttestation("attested log is full"));
        }
        attestation.verify(roots, height, verifier)?;
        self.entries.insert(task, (attestation, height));
        Ok(task)
    }

    /// Bounded snapshot encoding for restarts.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.entries.len() * 512);
        w.u8(ATTESTED_LOG_VERSION)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .u8(u8::from(self.enabled))
            .u32le(self.entries.len() as u32);
        for (attestation, height) in self.entries.values() {
            let sla_bytes = attestation.sla.encode();
            let quote_bytes = attestation.quote.encode();
            w.u32le(sla_bytes.len() as u32).raw(&sla_bytes);
            w.u32le(quote_bytes.len() as u32).raw(&quote_bytes);
            w.u64le(*height);
        }
        w.into_vec()
    }

    /// Rebuild from a snapshot. Every attestation decodes through its
    /// signature check, so tampered bytes fail the whole replay instead of
    /// loading half a log. The `enabled` switch is part of the snapshot: a
    /// disabled log that replays as enabled would change admission.
    pub fn decode(bytes: &[u8]) -> L2Result<Self> {
        let bad = |detail: &'static str| L2Error::BadAttestation(detail);
        let mut r = Reader::new(bytes);
        if r.u8().map_err(|_| bad("version is missing"))? != ATTESTED_LOG_VERSION {
            return Err(bad("version is unknown"));
        }
        let net_len = r.u16le().map_err(|_| bad("network is missing"))? as usize;
        if net_len == 0 || net_len > 128 {
            return Err(bad("network id length is bad"));
        }
        let network_id = std::str::from_utf8(
            r.fixed_slice(net_len)
                .map_err(|_| bad("network bytes are missing"))?,
        )
        .map_err(|_| bad("network is not utf-8"))?
        .to_string();
        let enabled = match r.u8().map_err(|_| bad("switch is missing"))? {
            0 => false,
            1 => true,
            _ => return Err(bad("switch is unknown")),
        };
        let count = r.u32le().map_err(|_| bad("count is missing"))? as usize;
        if count > MAX_LOG_TASKS {
            return Err(bad("snapshot is over cap"));
        }
        let mut log = AttestedExecutionLog::new(network_id, enabled);
        for _ in 0..count {
            let sla_len = r.u32le().map_err(|_| bad("sla length is missing"))? as usize;
            if sla_len == 0 || sla_len > MAX_LOG_BLOB {
                return Err(bad("attestation is over cap"));
            }
            let sla = srct_verify::TeeSla::decode(
                r.fixed_slice(sla_len)
                    .map_err(|_| bad("sla bytes are missing"))?,
            )
            .map_err(|_| bad("sla bytes are invalid"))?;
            let quote_len = r.u32le().map_err(|_| bad("quote length is missing"))? as usize;
            if quote_len == 0 || quote_len > MAX_LOG_BLOB {
                return Err(bad("attestation is over cap"));
            }
            let quote = srct_verify::SignedTeeQuote::decode(
                r.fixed_slice(quote_len)
                    .map_err(|_| bad("quote bytes are missing"))?,
            )
            .map_err(|_| bad("quote bytes are invalid"))?;
            let height = r.u64le().map_err(|_| bad("height is missing"))?;
            let attestation = TeeBackedAttestation { sla, quote };
            let task = attestation.sla.workload;
            if log.entries.contains_key(&task) {
                return Err(bad("snapshot holds a duplicate"));
            }
            log.entries.insert(task, (attestation, height));
        }
        r.expect_end()
            .map_err(|_| bad("snapshot has trailing bytes"))?;
        Ok(log)
    }
}
