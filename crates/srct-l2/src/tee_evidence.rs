//! TEE-backed execution evidence for L2 tasks (non-consensus).
//!
//! [`TeeBackedAttestation`] implements the generic `Attestation` trait over a
//! verified TEE quote: `task_id` is the SLA's workload commitment,
//! `result_hash` the quote's output commitment, `worker` the SLA's provider.
//! A rail posts the L2 task with the workload hash as its id; the worker's
//! quote then binds by construction, and the existing generic
//! `ServiceContract::submit` path enforces the bindings with no consensus
//! change.
//!
//! What this is not: consensus activation. `L2State` settles
//! `ServiceContract<ComputeDeliverable, ComputeAttestation>`; using this
//! attestation type in consensus state requires the formal consensus-change
//! process. Here it is verified evidence for rails, relayers and tests —
//! including a full contract lifecycle through the real generic transitions.

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::deliverable::Attestation;
use srct_core::error::{Error, Result};
use srct_core::hash::{Address, Hash};
use srct_core::ser::{Reader, Writer};
use srct_core::sig::Bundle;
use srct_verify::{
    AttestationRoots, SignedTeeQuote, TeeQuote, TeeSla, TeeType, UnifiedVerifier, VerifyError,
    TEE_VERSION,
};

use crate::error::{L2Error, L2Result};

pub const TEE_EVIDENCE_VERSION: u8 = 1;
const DOM_TEE_SLA: &[u8] = b"srct/l2/tee-sla/v1";

/// A TEE quote plus the SLA it must satisfy, as one L2 evidence object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeBackedAttestation {
    pub sla: TeeSla,
    pub quote: SignedTeeQuote,
}

impl TeeBackedAttestation {
    /// SLA bytes, domain-separated so an SLA hash can be committed elsewhere.
    pub fn sla_encode(&self) -> Vec<u8> {
        encode_sla(&self.sla)
    }

    pub fn sla_hash(&self) -> Hash {
        srct_core::hash::sha256_dom(DOM_TEE_SLA, &[&self.sla_encode()])
    }

    /// Full cryptographic verification against the rail's trust roots:
    /// signature, measurements, bindings, freshness and replay.
    pub fn verify(
        &self,
        roots: &AttestationRoots,
        height: u64,
        verifier: &mut UnifiedVerifier,
    ) -> L2Result<Hash> {
        if self.quote.sigs.is_empty() || self.quote.keys.is_empty() {
            return Err(L2Error::BadAttestation("tee evidence is unsigned"));
        }
        verifier
            .verify(
                &srct_verify::Evidence::Tee {
                    sla: self.sla.clone(),
                    quote: self.quote.clone(),
                },
                roots,
                height,
            )
            .map(|out| {
                let mut hash = [0u8; 32];
                let n = out.output.len().min(32);
                hash[..n].copy_from_slice(&out.output[..n]);
                hash
            })
            .map_err(|e| {
                L2Error::BadAttestation(match e {
                    VerifyError::Tee(_) => "tee quote refused",
                    _ => "wrong evidence kind",
                })
            })
    }
}

impl Attestation for TeeBackedAttestation {
    fn task_id(&self) -> Hash {
        self.sla.workload
    }

    fn result_hash(&self) -> Hash {
        self.quote.quote.output_hash
    }

    fn worker_address(&self) -> Address {
        self.sla.provider
    }

    fn is_signed(&self) -> bool {
        !self.quote.sigs.is_empty() && !self.quote.keys.is_empty()
    }

    fn encode(&self) -> Vec<u8> {
        let sla = self.sla_encode();
        let quote = self.quote.quote.encode();
        let sigs = self.quote.sigs.to_bytes();
        let keys = self.quote.keys.to_bytes();
        let mut w = Writer::with_capacity(64 + sla.len() + quote.len() + sigs.len() + keys.len());
        w.u8(TEE_EVIDENCE_VERSION)
            .u32le(sla.len() as u32)
            .raw(&sla)
            .u32le(quote.len() as u32)
            .raw(&quote)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.u8().map_err(malformed)?;
        if version != TEE_EVIDENCE_VERSION {
            return Err(malformed_str("tee evidence version"));
        }
        let sla_len = r.u32le().map_err(malformed)? as usize;
        if sla_len > 4 * 1024 {
            return Err(malformed_str("tee sla over cap"));
        }
        let mut sr = Reader::new(r.fixed_slice(sla_len).map_err(malformed)?);
        let sla_version = sr.u8().map_err(malformed)?;
        if sla_version != TEE_VERSION {
            return Err(malformed_str("tee sla version"));
        }
        let net_len = sr.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(malformed_str("tee network length"));
        }
        let network_id = std::str::from_utf8(sr.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| malformed_str("tee network utf-8"))?
            .to_string();
        let provider = sr.fixed().map_err(malformed)?;
        let tee = TeeType::from_u8(sr.u8().map_err(malformed)?)
            .ok_or_else(|| malformed_str("tee type"))?;
        let workload = sr.fixed().map_err(malformed)?;
        let model_hash = sr.fixed().map_err(malformed)?;
        let runtime_hash = sr.fixed().map_err(malformed)?;
        let config_hash = sr.fixed().map_err(malformed)?;
        let input_hash = sr.fixed().map_err(malformed)?;
        let max_age_heights = sr.u64le().map_err(malformed)?;
        sr.expect_end().map_err(malformed)?;
        let quote_len = r.u32le().map_err(malformed)? as usize;
        if quote_len > 4 * 1024 {
            return Err(malformed_str("tee quote over cap"));
        }
        let quote = TeeQuote::decode(r.fixed_slice(quote_len).map_err(malformed)?)
            .map_err(|_| malformed_str("tee quote malformed"))?;
        let sigs_len = r.u32le().map_err(malformed)? as usize;
        if sigs_len > 8 * 1024 {
            return Err(malformed_str("tee sigs over cap"));
        }
        let sigs = Bundle::deserialize(r.fixed_slice(sigs_len).map_err(malformed)?)
            .map_err(|_| malformed_str("tee sigs"))?;
        let keys_len = r.u32le().map_err(malformed)? as usize;
        if keys_len > 8 * 1024 {
            return Err(malformed_str("tee keys over cap"));
        }
        let keys = Bundle::deserialize(r.fixed_slice(keys_len).map_err(malformed)?)
            .map_err(|_| malformed_str("tee keys"))?;
        r.expect_end().map_err(malformed)?;
        // The SLA and the quote must describe the same execution: a tampered
        // SLA paired with a valid quote (or vice versa) is refused here, not
        // left for the verifier to untangle.
        if provider != quote.provider
            || tee != quote.tee
            || workload != quote.workload
            || model_hash != quote.model_hash
            || runtime_hash != quote.runtime_hash
            || config_hash != quote.config_hash
            || input_hash != quote.input_hash
        {
            return Err(malformed_str("tee sla and quote disagree"));
        }
        let signed = SignedTeeQuote { quote, sigs, keys };
        signed
            .verify()
            .map_err(|_| malformed_str("tee signature invalid"))?;
        let sla = TeeSla {
            version: sla_version,
            network_id,
            provider,
            workload,
            model_hash,
            runtime_hash,
            config_hash,
            input_hash,
            tee,
            max_age_heights,
        };
        Ok(TeeBackedAttestation { sla, quote: signed })
    }
}

fn encode_sla(sla: &TeeSla) -> Vec<u8> {
    let mut w = Writer::with_capacity(256 + sla.network_id.len());
    w.u8(sla.version)
        .u16le(sla.network_id.len() as u16)
        .raw(sla.network_id.as_bytes())
        .fixed(&sla.provider)
        .u8(sla.tee.as_u8())
        .fixed(&sla.workload)
        .fixed(&sla.model_hash)
        .fixed(&sla.runtime_hash)
        .fixed(&sla.config_hash)
        .fixed(&sla.input_hash)
        .u64le(sla.max_age_heights);
    w.into_vec()
}

fn malformed(_: srct_core::error::Error) -> Error {
    Error::Malformed("tee evidence malformed")
}

fn malformed_str(detail: &'static str) -> Error {
    Error::Malformed(detail)
}
