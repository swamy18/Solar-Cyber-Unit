//! Capability discovery and routing.
//!
//! A capability is a signed offer: which representation space a provider can
//! consume or produce, which service it offers, its price per unit, its
//! latency, and its privacy/verification level. Discovery is a pure function
//! over verified offers, so every participant ranks the same candidates the
//! same way.
//!
//! This is deliberately not a gossip protocol. Offers are transported by
//! whatever rail the operator uses (HTTP, MCP, an on-chain record); this crate
//! only defines what an offer means and how it is selected.

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::space::{ModelSpace, MAX_NAME_LEN};

pub const CAPABILITY_VERSION: u8 = 1;
const DOM_CAPABILITY: &[u8] = b"srct/cnnp/capability/v1";

/// How much the transport protects the representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Privacy {
    /// Plain representation over the caller's transport.
    Public = 0,
    /// Sealed representation envelope.
    Sealed = 1,
    /// Executed inside an attested enclave.
    Tee = 2,
    /// Executed over encrypted inputs with FHE.
    Fhe = 3,
}

impl Privacy {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Privacy::Public),
            1 => Some(Privacy::Sealed),
            2 => Some(Privacy::Tee),
            3 => Some(Privacy::Fhe),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// What the provider commits to proving about the execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verification {
    /// No evidence beyond the provider's signature.
    None = 0,
    /// A signed usage receipt.
    ProviderSigned = 1,
    /// The existing optimistic escrow/dispute path.
    Optimistic = 2,
    /// A hardware attestation of approved execution.
    Tee = 3,
    /// A cryptographic proof of the specified computation.
    Zk = 4,
}

impl Verification {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Verification::None),
            1 => Some(Verification::ProviderSigned),
            2 => Some(Verification::Optimistic),
            3 => Some(Verification::Tee),
            4 => Some(Verification::Zk),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A provider-signed offer.
#[derive(Clone, Debug, PartialEq)]
pub struct Capability {
    pub version: u8,
    pub provider: Address,
    /// Space the provider consumes.
    pub source: ModelSpace,
    /// Space the provider produces. For a translation this is the target;
    /// for inference it may equal the source (the output is a scalar vector in
    /// the same space) or name a distinct output space.
    pub target: ModelSpace,
    /// Service name, e.g. `translate`, `forward`, `train-round`.
    pub service: String,
    /// Price per unit (one representation for translation/inference).
    pub price_sat_per_unit: u64,
    /// Largest batch accepted in one receipt.
    pub max_units: u32,
    /// Advertised latency in milliseconds.
    pub latency_ms: u32,
    pub privacy: Privacy,
    pub verification: Verification,
    /// Height after which the offer is stale.
    pub expires_height: u64,
    /// Provider nonce, so re-publishing the same terms is distinct.
    pub nonce: u64,
}

impl Capability {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CAPABILITY_VERSION {
            return Err(format!("unsupported capability version {}", self.version));
        }
        self.source.validate()?;
        self.target.validate()?;
        if self.service.is_empty() || self.service.len() > MAX_NAME_LEN {
            return Err("service name is empty or over the 64-byte cap".into());
        }
        if self.max_units == 0 {
            return Err("max_units must be positive".into());
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let source = self.source.encode();
        let target = self.target.encode();
        let mut w = Writer::with_capacity(256 + source.len() + target.len());
        w.u8(self.version)
            .fixed(&self.provider)
            .u32le(source.len() as u32)
            .raw(&source)
            .u32le(target.len() as u32)
            .raw(&target)
            .u16le(self.service.len() as u16)
            .raw(self.service.as_bytes())
            .u64le(self.price_sat_per_unit)
            .u32le(self.max_units)
            .u32le(self.latency_ms)
            .u8(self.privacy.as_u8())
            .u8(self.verification.as_u8())
            .u64le(self.expires_height)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_CAPABILITY, &[&self.encode()])
    }
}

/// A capability plus the provider's signature.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedCapability {
    pub capability: Capability,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedCapability {
    pub fn sign(capability: Capability, provider: &Wallet) -> Result<Self, String> {
        capability.validate()?;
        let address = provider.address().map_err(|e| e.to_string())?;
        if address != capability.provider {
            return Err("capability provider does not match the signing wallet".into());
        }
        let auth = Auth::sign(provider, &capability.hash()).map_err(|e| e.to_string())?;
        Ok(SignedCapability {
            capability,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        self.capability.validate()?;
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.capability.provider {
            return Err("capability key bundle is not the provider".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.capability.hash())
            .map_err(|_| "capability signature invalid".to_string())
    }

    pub fn encode(&self) -> Vec<u8> {
        let cap = self.capability.encode();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(cap.len() + sigs.len() + keys.len() + 16);
        w.u32le(cap.len() as u32)
            .raw(&cap)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let cap_len = r.u32le().map_err(|e| format!("capability: {e}"))? as usize;
        if cap_len > 8 * 1024 {
            return Err("capability: body over cap".into());
        }
        let mut cr = Reader::new(
            r.fixed_slice(cap_len)
                .map_err(|e| format!("capability: {e}"))?,
        );
        let capability = decode_capability(&mut cr)?;
        cr.expect_end().map_err(|e| format!("capability: {e}"))?;
        let sigs_len = r.u32le().map_err(|e| format!("capability: {e}"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err("capability: signature bundle over cap".into());
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|e| format!("capability: {e}"))?,
        )
        .map_err(|e| format!("capability: {e}"))?;
        let keys_len = r.u32le().map_err(|e| format!("capability: {e}"))? as usize;
        if keys_len > 8 * 1024 {
            return Err("capability: key bundle over cap".into());
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|e| format!("capability: {e}"))?,
        )
        .map_err(|e| format!("capability: {e}"))?;
        r.expect_end().map_err(|e| format!("capability: {e}"))?;
        let signed = SignedCapability {
            capability,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

fn decode_capability(r: &mut Reader<'_>) -> Result<Capability, String> {
    let version = r.u8().map_err(|e| format!("capability: {e}"))?;
    let provider = r.fixed().map_err(|e| format!("capability: {e}"))?;
    let source_len = r.u32le().map_err(|e| format!("capability: {e}"))? as usize;
    if source_len > 4 * 1024 {
        return Err("capability: source space over cap".into());
    }
    let mut sr = Reader::new(
        r.fixed_slice(source_len)
            .map_err(|e| format!("capability: {e}"))?,
    );
    let source = ModelSpace::decode(&mut sr)?;
    sr.expect_end().map_err(|e| format!("capability: {e}"))?;
    let target_len = r.u32le().map_err(|e| format!("capability: {e}"))? as usize;
    if target_len > 4 * 1024 {
        return Err("capability: target space over cap".into());
    }
    let mut tr = Reader::new(
        r.fixed_slice(target_len)
            .map_err(|e| format!("capability: {e}"))?,
    );
    let target = ModelSpace::decode(&mut tr)?;
    tr.expect_end().map_err(|e| format!("capability: {e}"))?;
    let service_len = r.u16le().map_err(|e| format!("capability: {e}"))? as usize;
    if service_len == 0 || service_len > MAX_NAME_LEN {
        return Err("capability: bad service length".into());
    }
    let service = std::str::from_utf8(
        r.fixed_slice(service_len)
            .map_err(|e| format!("capability: {e}"))?,
    )
    .map_err(|_| "capability: service is not utf-8".to_string())?
    .to_string();
    let price_sat_per_unit = r.u64le().map_err(|e| format!("capability: {e}"))?;
    let max_units = r.u32le().map_err(|e| format!("capability: {e}"))?;
    let latency_ms = r.u32le().map_err(|e| format!("capability: {e}"))?;
    let privacy = Privacy::from_u8(r.u8().map_err(|e| format!("capability: {e}"))?)
        .ok_or_else(|| "capability: bad privacy level".to_string())?;
    let verification = Verification::from_u8(r.u8().map_err(|e| format!("capability: {e}"))?)
        .ok_or_else(|| "capability: bad verification level".to_string())?;
    let expires_height = r.u64le().map_err(|e| format!("capability: {e}"))?;
    let nonce = r.u64le().map_err(|e| format!("capability: {e}"))?;
    Ok(Capability {
        version,
        provider,
        source,
        target,
        service,
        price_sat_per_unit,
        max_units,
        latency_ms,
        privacy,
        verification,
        expires_height,
        nonce,
    })
}

/// Constraints for one discovery call. Only the fields that are set filter.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryQuery {
    pub service: Option<String>,
    pub source: Option<Hash>,
    pub target: Option<Hash>,
    pub max_price_sat_per_unit: Option<u64>,
    pub max_latency_ms: Option<u32>,
    pub min_privacy: Option<Privacy>,
    pub min_verification: Option<Verification>,
}

/// Discovery result: the offer plus its verified hash.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub capability_hash: Hash,
    pub signed: SignedCapability,
}

/// Filter and rank offers.
///
/// Order is `(price, latency, provider address, nonce)`, so every caller ranks
/// the same valid offers identically. Invalid signatures and expired offers are
/// skipped rather than trusted.
pub fn discover(
    offers: &[SignedCapability],
    query: &DiscoveryQuery,
    height: u64,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = offers
        .iter()
        .filter(|signed| signed.verify().is_ok())
        .filter(|signed| {
            let c = &signed.capability;
            c.expires_height >= height
                && query
                    .service
                    .as_ref()
                    .map(|s| s == &c.service)
                    .unwrap_or(true)
                && query.source.map(|h| h == c.source.hash()).unwrap_or(true)
                && query.target.map(|h| h == c.target.hash()).unwrap_or(true)
                && query
                    .max_price_sat_per_unit
                    .map(|p| c.price_sat_per_unit <= p)
                    .unwrap_or(true)
                && query
                    .max_latency_ms
                    .map(|l| c.latency_ms <= l)
                    .unwrap_or(true)
                && query.min_privacy.map(|p| c.privacy >= p).unwrap_or(true)
                && query
                    .min_verification
                    .map(|v| c.verification >= v)
                    .unwrap_or(true)
        })
        .map(|signed| Candidate {
            capability_hash: signed.capability.hash(),
            signed: signed.clone(),
        })
        .collect();
    out.sort_by(|a, b| {
        let ca = &a.signed.capability;
        let cb = &b.signed.capability;
        ca.price_sat_per_unit
            .cmp(&cb.price_sat_per_unit)
            .then_with(|| ca.latency_ms.cmp(&cb.latency_ms))
            .then_with(|| ca.provider.cmp(&cb.provider))
            .then_with(|| ca.nonce.cmp(&cb.nonce))
    });
    out
}

/// Find the cheapest offer that translates `source` to `target`.
pub fn cheapest_translation(
    offers: &[SignedCapability],
    source: Hash,
    target: Hash,
    max_price_sat_per_unit: u64,
    height: u64,
) -> Option<Candidate> {
    discover(
        offers,
        &DiscoveryQuery {
            service: Some("translate".into()),
            source: Some(source),
            target: Some(target),
            max_price_sat_per_unit: Some(max_price_sat_per_unit),
            ..DiscoveryQuery::default()
        },
        height,
    )
    .into_iter()
    .next()
}
