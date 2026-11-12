//! TEE-backed execution evidence (non-consensus).
//!
//! A worker that runs the requested workload inside an approved execution
//! environment proves it with a **signed attestation quote**: the quoting key
//! signs a body that binds the provider, the workload, the model/runtime/
//! configuration measurements and the input/output commitments. The verifier
//! checks the signature against a registry of trusted attestation roots,
//! checks the measurements against the requester's SLA, and enforces
//! freshness and replay protection.
//!
//! # Threat model (honest limits)
//!
//! - The quote proves the approved environment **executed** the workload
//!   (proof of execution). It does not prove the output is factually correct
//!   or useful — a correct model can still produce a useless answer.
//! - Trust lives in the [`AttestationRoots`] registry: whoever controls which
//!   roots are trusted decides which hardware is approved. Root compromise is
//!   handled by [`AttestationRoots::revoke`], not by this crate.
//! - `TeeType::Software` is a test/simulator label. It is only accepted when
//!   the SLA explicitly asks for it; a production SLA pins `Tdx` or `SevSnp`.
//! - Nothing here moves coin. [`TeeVerifier::verify`] returns the accepted
//!   output hash; the escrow or payment rail releases funds on `Ok` and
//!   applies its own penalties on `Err`.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

pub const TEE_VERSION: u8 = 1;

const DOM_TEE_QUOTE: &[u8] = b"srct/compute/tee-quote/v1";

/// Which execution-environment family produced the quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TeeType {
    /// Test/simulator builds. Accepted only when the SLA asks for it.
    Software = 0,
    /// Intel TDX.
    Tdx = 1,
    /// AMD SEV-SNP.
    SevSnp = 2,
}

impl TeeType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TeeType::Software),
            1 => Some(TeeType::Tdx),
            2 => Some(TeeType::SevSnp),
            _ => None,
        }
    }
}

/// Why a TEE quote was refused. Fail-closed: any variant means no payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TeeError {
    Malformed(String),
    BadSignature(String),
    UnknownAttester,
    RevokedAttester,
    TeeTypeMismatch,
    BindingMismatch,
    MeasurementMismatch,
    InputMismatch,
    Expired,
    FutureHeight,
    Replay,
}

impl std::fmt::Display for TeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeError::Malformed(detail) => write!(f, "malformed tee data: {detail}"),
            TeeError::BadSignature(detail) => write!(f, "invalid signature: {detail}"),
            TeeError::UnknownAttester => write!(f, "attester is not a trusted root"),
            TeeError::RevokedAttester => write!(f, "attester root was revoked"),
            TeeError::TeeTypeMismatch => write!(f, "tee type does not match the SLA"),
            TeeError::BindingMismatch => write!(f, "provider, workload or network does not match"),
            TeeError::MeasurementMismatch => {
                write!(f, "model, runtime or config measurement does not match")
            }
            TeeError::InputMismatch => write!(f, "input commitment does not match"),
            TeeError::Expired => write!(f, "quote is older than the SLA allows"),
            TeeError::FutureHeight => write!(f, "quote claims a future height"),
            TeeError::Replay => write!(f, "quote was already accepted"),
        }
    }
}

impl std::error::Error for TeeError {}

/// One trusted quoting key: which address signs quotes and for which TEE family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationRoot {
    pub attester: Address,
    pub tee: TeeType,
    pub revoked: bool,
}

/// Registry of trusted attestation (quoting) keys.
#[derive(Clone, Debug, Default)]
pub struct AttestationRoots {
    roots: BTreeMap<Address, AttestationRoot>,
}

impl AttestationRoots {
    pub fn new() -> Self {
        Self {
            roots: BTreeMap::new(),
        }
    }

    /// Trust `attester` for quotes of family `tee`. Re-adding an attester
    /// replaces its entry and clears revocation.
    pub fn add_root(&mut self, attester: Address, tee: TeeType) {
        self.roots.insert(
            attester,
            AttestationRoot {
                attester,
                tee,
                revoked: false,
            },
        );
    }

    /// Mark an attester compromised. Unknown attesters are refused anyway,
    /// so revoking one is a no-op that reports whether it was present.
    pub fn revoke(&mut self, attester: &Address) -> bool {
        match self.roots.get_mut(attester) {
            Some(root) => {
                root.revoked = true;
                true
            }
            None => false,
        }
    }

    fn lookup(&self, attester: &Address) -> Result<&AttestationRoot, TeeError> {
        let root = self.roots.get(attester).ok_or(TeeError::UnknownAttester)?;
        if root.revoked {
            return Err(TeeError::RevokedAttester);
        }
        Ok(root)
    }
}

/// The requester's conditions for accepting TEE execution evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeSla {
    pub version: u8,
    pub network_id: String,
    pub provider: Address,
    /// Hash of the job or assignment this evidence must be bound to.
    pub workload: Hash,
    pub model_hash: Hash,
    pub runtime_hash: Hash,
    pub config_hash: Hash,
    pub input_hash: Hash,
    pub tee: TeeType,
    /// How many heights old a quote may be at verification time.
    pub max_age_heights: u64,
}

impl TeeSla {
    fn validate(&self) -> Result<(), TeeError> {
        if self.version != TEE_VERSION {
            return Err(TeeError::Malformed(format!(
                "unsupported tee sla version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(TeeError::Malformed("tee sla network id length".into()));
        }
        for (name, hash) in [
            ("model", &self.model_hash),
            ("runtime", &self.runtime_hash),
            ("config", &self.config_hash),
            ("input", &self.input_hash),
        ] {
            if hash == &[0u8; 32] {
                return Err(TeeError::Malformed(format!("tee sla {name} hash is zero")));
            }
        }
        if self.workload == [0u8; 32] {
            return Err(TeeError::Malformed("tee sla workload hash is zero".into()));
        }
        Ok(())
    }
}

/// A signed statement by a quoting key that the workload executed inside the
/// approved environment. The signer is the **attester**, not the provider:
/// the provider address is bound inside the signed body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeQuote {
    pub version: u8,
    pub network_id: String,
    pub provider: Address,
    pub tee: TeeType,
    pub workload: Hash,
    pub model_hash: Hash,
    pub runtime_hash: Hash,
    pub config_hash: Hash,
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub height: u64,
    pub nonce: u64,
}

impl TeeQuote {
    fn validate(&self) -> Result<(), TeeError> {
        if self.version != TEE_VERSION {
            return Err(TeeError::Malformed(format!(
                "unsupported tee quote version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(TeeError::Malformed("tee quote network id length".into()));
        }
        if self.output_hash == [0u8; 32] {
            return Err(TeeError::Malformed("tee quote output hash is zero".into()));
        }
        if self.nonce == 0 {
            return Err(TeeError::Malformed("tee quote nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256 + self.network_id.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.provider)
            .u8(self.tee.as_u8())
            .fixed(&self.workload)
            .fixed(&self.model_hash)
            .fixed(&self.runtime_hash)
            .fixed(&self.config_hash)
            .fixed(&self.input_hash)
            .fixed(&self.output_hash)
            .u64le(self.height)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_TEE_QUOTE, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TeeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(TeeError::Malformed("tee quote network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| TeeError::Malformed("tee quote network is not utf-8".into()))?
            .to_string();
        let provider = r.fixed().map_err(malformed)?;
        let tee = TeeType::from_u8(r.u8().map_err(malformed)?)
            .ok_or_else(|| TeeError::Malformed("tee quote tee type is unknown".into()))?;
        let workload = r.fixed().map_err(malformed)?;
        let model_hash = r.fixed().map_err(malformed)?;
        let runtime_hash = r.fixed().map_err(malformed)?;
        let config_hash = r.fixed().map_err(malformed)?;
        let input_hash = r.fixed().map_err(malformed)?;
        let output_hash = r.fixed().map_err(malformed)?;
        let height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let quote = TeeQuote {
            version,
            network_id,
            provider,
            tee,
            workload,
            model_hash,
            runtime_hash,
            config_hash,
            input_hash,
            output_hash,
            height,
            nonce,
        };
        quote.validate()?;
        Ok(quote)
    }
}

/// A [`TeeQuote`] signed by an attestation (quoting) key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTeeQuote {
    pub quote: TeeQuote,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedTeeQuote {
    /// Sign with the attester's quoting key. Any wallet can sign; trust is
    /// decided by [`AttestationRoots`], not here.
    pub fn sign(quote: TeeQuote, attester: &Wallet) -> Result<Self, TeeError> {
        quote.validate()?;
        let auth = Auth::sign(attester, &quote.hash())
            .map_err(|e| TeeError::BadSignature(e.to_string()))?;
        Ok(SignedTeeQuote {
            quote,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    /// The address whose key signed this quote.
    pub fn attester(&self) -> Result<Address, TeeError> {
        self.quote.validate()?;
        self.keys
            .address()
            .map_err(|e| TeeError::BadSignature(e.to_string()))
    }

    /// Validate the body and verify the attestation signature, returning the
    /// signer. Used by integrators (L2 evidence, escrow rails) that decode a
    /// quote far from where it was created.
    pub fn verify(&self) -> Result<Address, TeeError> {
        self.verify_signature()
    }

    fn verify_signature(&self) -> Result<Address, TeeError> {
        self.quote.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| TeeError::BadSignature(e.to_string()))?;
        verify_bundle(&self.sigs, &self.keys, &self.quote.hash())
            .map_err(|e| TeeError::BadSignature(e.to_string()))?;
        Ok(signer)
    }
}

/// Fail-closed verifier: trusted roots, an accepted-quote replay book, and
/// the deterministic SLA checks from the master Section 6 rules.
#[derive(Clone, Debug, Default)]
pub struct TeeVerifier {
    seen: BTreeSet<Hash>,
}

impl TeeVerifier {
    pub fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }

    /// Accept the quote and return its output hash, or refuse with the exact
    /// reason. Accepting records the quote hash, so the same bytes can never
    /// verify twice.
    pub fn verify(
        &mut self,
        sla: &TeeSla,
        signed: &SignedTeeQuote,
        roots: &AttestationRoots,
        current_height: u64,
    ) -> Result<Hash, TeeError> {
        sla.validate()?;
        let signer = signed.verify_signature()?;
        let root = roots.lookup(&signer)?;
        let quote = &signed.quote;
        if root.tee != quote.tee || quote.tee != sla.tee {
            return Err(TeeError::TeeTypeMismatch);
        }
        if quote.network_id != sla.network_id
            || quote.provider != sla.provider
            || quote.workload != sla.workload
        {
            return Err(TeeError::BindingMismatch);
        }
        if quote.model_hash != sla.model_hash
            || quote.runtime_hash != sla.runtime_hash
            || quote.config_hash != sla.config_hash
        {
            return Err(TeeError::MeasurementMismatch);
        }
        if quote.input_hash != sla.input_hash {
            return Err(TeeError::InputMismatch);
        }
        if quote.height > current_height {
            return Err(TeeError::FutureHeight);
        }
        if current_height.saturating_sub(quote.height) > sla.max_age_heights {
            return Err(TeeError::Expired);
        }
        let digest = quote.hash();
        if !self.seen.insert(digest) {
            return Err(TeeError::Replay);
        }
        Ok(quote.output_hash)
    }
}

fn malformed(e: srct_core::error::Error) -> TeeError {
    TeeError::Malformed(e.to_string())
}
