//! Portable agent policy: the signed format any chain or rail can verify.
//!
//! `agent.rs` answers *may this agent spend?* for this node; this module answers
//! how that answer **travels**. A [`SignedPolicy`] is a `SpendPolicy` plus the
//! owner's signature over it, so anyone holding the bytes — another chain, an
//! x402 facilitator on Base, an insurer's auditor — can check the grant without
//! the issuing node and without any private key. A [`DelegationProof`] is the
//! same idea for a whole delegation tree: the root-first chain of signed
//! policies, each checked with [`delegation::assert_chain`], so a service sees
//! one proof that the owner authorized this agent, not a pile of claims.
//!
//! [`BoundAuthorization`] turns the advisory approval into an **enforced** one:
//! the owner signs the exact transaction hash the grant may settle plus a short
//! expiry, so a stolen or replayed authorization settles nothing. The lifetime
//! cap ([`MAX_BOUND_LIFETIME_BLOCKS`]) is what makes "short-lived" structural
//! rather than aspirational.
//!
//! [`PaymentIntent`] + [`PolicyDecision`] is the chain-agnostic engine seam:
//! input a payment intent, get back allow, deny, or approval-needed — the same
//! shape the `srct-policy` crate and its TypeScript/Python bindings speak.
//! `evaluate_policy` is the stateless pre-check (every clause that needs no
//! committed state); the stateful clauses (nonce, tumbling-window spend) stay
//! in `PolicyBook::authorize`, which remains the only path that commits.
//!
//! Fail-closed: every refusal is a named [`PortableError`]; malformed bytes, a
//! wrong owner binding, an expired grant, a widened link, or a transaction
//! mismatch all refuse rather than partially verify.

use crate::agent::{
    verify_authorization_for_policy, AgentId, Authorization, PolicyError, SpendPolicy,
};
use crate::delegation::{assert_chain, DelegationError, MAX_DELEGATION_DEPTH};
use crate::hash::{
    address_from_hex, address_to_hex, hash_from_hex, hash_to_hex, sha256_dom, Address, Hash,
};
use crate::ser::{Reader, Writer};
use crate::sig::Bundle;
use serde::{Deserialize, Serialize};

/// Version of the portable envelope. A future format MUST use a new value.
pub const PORTABLE_POLICY_VERSION: u8 = 1;
/// Domain tag for the bound-authorization signing hash.
pub const DOM_BOUND_AUTH: &[u8] = b"srct/bound-auth/v1";
/// Longest accepted portable JSON document (bytes). Bounds what a hostile peer
/// can make a verifier parse before anything validates.
pub const MAX_PORTABLE_JSON_LEN: usize = 256 * 1024;
/// Longest a bound authorization may live, in blocks, measured from the grant
/// height it wraps. Short-lived is enforced here, not documented elsewhere.
pub const MAX_BOUND_LIFETIME_BLOCKS: u64 = 30;

/// Why a portable object was refused.
#[derive(Debug, Clone)]
pub enum PortableError {
    /// Bytes or JSON could not be decoded.
    Malformed(&'static str),
    /// Envelope `version` is not [`PORTABLE_POLICY_VERSION`].
    UnsupportedVersion(u8),
    /// A policy-engine refusal, passed through unchanged.
    Policy(PolicyError),
    /// A delegation refusal, passed through unchanged.
    Delegation(DelegationError),
    /// A payment-layer refusal (e.g. the payment is not linked to the grant).
    Payment(crate::payment::PaymentError),
    /// A signature or key-bundle failure.
    Signature(crate::error::Error),
    /// Two bound objects disagree (wrong owner, wrong grant, wrong tx, ...).
    Binding(&'static str),
    /// The bound grant is spent past its expiry.
    Expired { expires_at_height: u64, height: u64 },
    /// The bound grant lives longer than [`MAX_BOUND_LIFETIME_BLOCKS`].
    LifetimeTooLong { lifetime: u64, max: u64 },
}

impl std::fmt::Display for PortableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortableError::Malformed(w) => write!(f, "malformed portable policy: {w}"),
            PortableError::UnsupportedVersion(v) => {
                write!(f, "unsupported portable version {v}")
            }
            PortableError::Policy(e) => write!(f, "policy refused: {e}"),
            PortableError::Delegation(e) => write!(f, "delegation refused: {e}"),
            PortableError::Payment(e) => write!(f, "payment refused: {e}"),
            PortableError::Signature(e) => write!(f, "signature invalid: {e}"),
            PortableError::Binding(w) => write!(f, "portable binding failed: {w}"),
            PortableError::Expired {
                expires_at_height,
                height,
            } => write!(
                f,
                "bound authorization expired at {expires_at_height}, spent at {height}"
            ),
            PortableError::LifetimeTooLong { lifetime, max } => {
                write!(f, "bound lifetime {lifetime} exceeds cap {max}")
            }
        }
    }
}

impl std::error::Error for PortableError {}

impl From<PolicyError> for PortableError {
    fn from(e: PolicyError) -> Self {
        PortableError::Policy(e)
    }
}

impl From<DelegationError> for PortableError {
    fn from(e: DelegationError) -> Self {
        PortableError::Delegation(e)
    }
}

impl From<crate::payment::PaymentError> for PortableError {
    fn from(e: crate::payment::PaymentError) -> Self {
        PortableError::Payment(e)
    }
}

impl From<crate::error::Error> for PortableError {
    fn from(e: crate::error::Error) -> Self {
        PortableError::Signature(e)
    }
}

fn decode_hex_field(raw: &str, what: &'static str) -> Result<Vec<u8>, PortableError> {
    hex::decode(raw.trim().trim_start_matches("0x")).map_err(|_| PortableError::Malformed(what))
}

// ---------------------------------------------------------------------------
// SignedPolicy: the portable grant
// ---------------------------------------------------------------------------

/// A spending policy plus the owner's signature over it — the unit that
/// travels across chains and rails.
///
/// The signature covers `policy.signing_hash()`, so every field (caps,
/// allow-lists, window, parent link, revocation flag) is covered; a policy
/// cannot be widened after it was signed. Verification needs only these bytes:
/// no node, no chain state, no private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPolicy {
    pub policy: SpendPolicy,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedPolicy {
    /// Sign a policy with the owner's wallet. The wallet is borrowed and never
    /// stored — the bridge holds no key material.
    pub fn issue(
        owner: &crate::wallet::Wallet,
        policy: &SpendPolicy,
    ) -> Result<Self, PortableError> {
        policy.validate()?;
        let keys = crate::l2::Auth::keys_for(owner).map_err(PortableError::Signature)?;
        let sigs = crate::l2::Auth::sigs_for(owner, &policy.signing_hash())
            .map_err(PortableError::Signature)?;
        Ok(SignedPolicy {
            policy: policy.clone(),
            sigs,
            keys,
        })
    }

    /// Verify structure, owner binding, and signature. Anyone, anywhere.
    pub fn verify(&self) -> Result<(), PortableError> {
        self.policy.validate()?;
        if self.keys.address()? != self.policy.owner {
            return Err(PortableError::Binding("keys are not the policy owner's"));
        }
        crate::sig::verify_bundle(&self.sigs, &self.keys, &self.policy.signing_hash())?;
        Ok(())
    }

    /// Canonical bytes: `version ‖ u32 policy_len ‖ policy ‖ sigs ‖ keys`.
    /// Bundles are self-delimiting (`Bundle::from_reader`), so no second
    /// length prefix is needed.
    pub fn serialize(&self) -> Vec<u8> {
        let policy = self.policy.serialize();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(1 + 4 + policy.len() + sigs.len() + keys.len());
        w.u8(PORTABLE_POLICY_VERSION)
            .u32le(policy.len() as u32)
            .raw(&policy)
            .raw(&sigs)
            .raw(&keys);
        w.into_vec()
    }

    /// Decode what [`SignedPolicy::serialize`] wrote. Bounded and fail-closed.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PortableError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| PortableError::Malformed("version"))?;
        if version != PORTABLE_POLICY_VERSION {
            return Err(PortableError::UnsupportedVersion(version));
        }
        let len = r
            .u32le()
            .map_err(|_| PortableError::Malformed("policy length"))? as usize;
        let policy_bytes = r
            .fixed_slice(len)
            .map_err(|_| PortableError::Malformed("policy bytes"))?;
        let policy = SpendPolicy::deserialize(policy_bytes)?;
        let sigs =
            Bundle::from_reader(&mut r).map_err(|_| PortableError::Malformed("sigs bundle"))?;
        let keys =
            Bundle::from_reader(&mut r).map_err(|_| PortableError::Malformed("keys bundle"))?;
        r.expect_end()
            .map_err(|_| PortableError::Malformed("trailing bytes"))?;
        Ok(SignedPolicy { policy, sigs, keys })
    }

    /// Portable JSON: hex fields a non-Rust verifier can read without the
    /// canonical codec. Denormalized hashes (`policy_hash`, `owner`) let a rail
    /// route before it decodes.
    pub fn to_json(&self) -> String {
        let doc = SignedPolicyDoc {
            version: PORTABLE_POLICY_VERSION,
            policy_hex: hex::encode(self.policy.serialize()),
            sigs_hex: hex::encode(self.sigs.to_bytes()),
            keys_hex: hex::encode(self.keys.to_bytes()),
            policy_hash: hash_to_hex(&self.policy.hash()),
            owner: address_to_hex(&self.policy.owner),
            agent_id: hex::encode(self.policy.agent_id),
            network_id: self.policy.network_id.clone(),
        };
        serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
    }

    /// Parse [`SignedPolicy::to_json`] output and verify it. Parsing without
    /// verifying is how a widened grant travels; this refuses to do that.
    pub fn from_json(raw: &str) -> Result<Self, PortableError> {
        if raw.len() > MAX_PORTABLE_JSON_LEN {
            return Err(PortableError::Malformed("portable json over cap"));
        }
        let doc: SignedPolicyDoc =
            serde_json::from_str(raw).map_err(|_| PortableError::Malformed("portable json"))?;
        if doc.version != PORTABLE_POLICY_VERSION {
            return Err(PortableError::UnsupportedVersion(doc.version));
        }
        let policy = SpendPolicy::deserialize(&decode_hex_field(&doc.policy_hex, "policy hex")?)?;
        // Strict bundle decode: a grant hex field with trailing garbage is a
        // different byte string naming the "same" grant, so it is refused.
        let sigs = Bundle::deserialize(&decode_hex_field(&doc.sigs_hex, "sigs hex")?)
            .map_err(|_| PortableError::Malformed("sigs bundle"))?;
        let keys = Bundle::deserialize(&decode_hex_field(&doc.keys_hex, "keys hex")?)
            .map_err(|_| PortableError::Malformed("keys bundle"))?;
        let signed = SignedPolicy { policy, sigs, keys };
        // The denormalized routing fields must describe the decoded grant: a
        // document that routes one way and verifies another is a confusion
        // attack, not a grant. Hash and owner were the original two; agent
        // and network ride the same route decision, so they are checked too.
        if hash_to_hex(&signed.policy.hash()) != doc.policy_hash.to_lowercase()
            || address_to_hex(&signed.policy.owner) != doc.owner.to_lowercase()
            || hex::encode(signed.policy.agent_id) != doc.agent_id.to_lowercase()
            || signed.policy.network_id != doc.network_id
        {
            return Err(PortableError::Binding(
                "portable document hashes do not match the grant",
            ));
        }
        signed.verify()?;
        Ok(signed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedPolicyDoc {
    version: u8,
    policy_hex: String,
    sigs_hex: String,
    keys_hex: String,
    policy_hash: String,
    owner: String,
    agent_id: String,
    network_id: String,
}

// ---------------------------------------------------------------------------
// DelegationProof: the verifiable tree
// ---------------------------------------------------------------------------

/// A root-first chain of signed policies — the clean proof a service verifies
/// to learn that an agent acts under the real owner's authority.
///
/// Verification is three layers, and all three must hold: every link verifies
/// as a [`SignedPolicy`], the inner policies narrow link-by-link
/// ([`assert_chain`]), and the chain starts at a root (no manufactured
/// ancestry). The leaf is what spends; everything above it is why it may.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationProof {
    /// Root first, spending leaf last. Empty proves nothing.
    pub links: Vec<SignedPolicy>,
}

impl DelegationProof {
    /// Assemble from already-signed links. Refuses an empty chain and anything
    /// deeper than [`MAX_DELEGATION_DEPTH`] before any signature work.
    pub fn new(links: Vec<SignedPolicy>) -> Result<Self, PortableError> {
        if links.is_empty() {
            return Err(PortableError::Binding("delegation proof is empty"));
        }
        if links.len() > MAX_DELEGATION_DEPTH {
            return Err(PortableError::Delegation(DelegationError::TooDeep {
                got: links.len(),
                cap: MAX_DELEGATION_DEPTH,
            }));
        }
        Ok(DelegationProof { links })
    }

    /// The spending leaf.
    pub fn leaf(&self) -> &SpendPolicy {
        &self.links.last().expect("proof is never empty").policy
    }

    /// The root owner — the authority the whole chain attenuates.
    pub fn root_owner(&self) -> &Address {
        &self.links[0].policy.owner
    }

    /// Full verification: every signature, every narrowing link, root-first.
    pub fn verify(&self) -> Result<(), PortableError> {
        if self.links.is_empty() {
            return Err(PortableError::Binding("delegation proof is empty"));
        }
        if self.links.len() > MAX_DELEGATION_DEPTH {
            return Err(PortableError::Delegation(DelegationError::TooDeep {
                got: self.links.len(),
                cap: MAX_DELEGATION_DEPTH,
            }));
        }
        for link in &self.links {
            link.verify()?;
        }
        let refs: Vec<&SpendPolicy> = self.links.iter().map(|l| &l.policy).collect();
        assert_chain(&refs)?;
        if self.links[0].policy.parent_agent_id.is_some() {
            return Err(PortableError::Binding(
                "delegation proof must start at a root policy",
            ));
        }
        Ok(())
    }

    /// Portable JSON: the links in order plus routing fields for the leaf.
    pub fn to_json(&self) -> String {
        let doc = DelegationProofDoc {
            version: PORTABLE_POLICY_VERSION,
            links: self.links.iter().map(|l| l.to_json()).collect(),
            root_owner: address_to_hex(self.root_owner()),
            leaf_agent: hex::encode(self.leaf().agent_id),
            leaf_policy_hash: hash_to_hex(&self.leaf().hash()),
        };
        serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
    }

    /// Parse and verify. A proof that parses but does not verify is refused —
    /// a service must never act on an unverified ancestry.
    pub fn from_json(raw: &str) -> Result<Self, PortableError> {
        if raw.len() > MAX_PORTABLE_JSON_LEN {
            return Err(PortableError::Malformed("proof json over cap"));
        }
        let doc: DelegationProofDoc =
            serde_json::from_str(raw).map_err(|_| PortableError::Malformed("proof json"))?;
        if doc.version != PORTABLE_POLICY_VERSION {
            return Err(PortableError::UnsupportedVersion(doc.version));
        }
        if doc.links.is_empty() || doc.links.len() > MAX_DELEGATION_DEPTH {
            return Err(PortableError::Malformed("proof link count"));
        }
        let mut links = Vec::with_capacity(doc.links.len());
        for raw_link in &doc.links {
            links.push(SignedPolicy::from_json(raw_link)?);
        }
        let proof = DelegationProof::new(links)?;
        if address_to_hex(proof.root_owner()) != doc.root_owner.to_lowercase()
            || hash_to_hex(&proof.leaf().hash()) != doc.leaf_policy_hash.to_lowercase()
            || hex::encode(proof.leaf().agent_id) != doc.leaf_agent.to_lowercase()
        {
            return Err(PortableError::Binding(
                "proof routing fields do not match the links",
            ));
        }
        proof.verify()?;
        Ok(proof)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DelegationProofDoc {
    version: u8,
    links: Vec<String>,
    root_owner: String,
    leaf_agent: String,
    leaf_policy_hash: String,
}

// ---------------------------------------------------------------------------
// BoundAuthorization: short-lived, exact-transaction, enforced
// ---------------------------------------------------------------------------

/// An owner-signed grant for **one exact transaction**, alive for a short
/// window. This is what turns the advisory approval into an enforced one: the
/// signature covers the grant, the expiry, and the transaction hash together,
/// so a stolen authorization cannot be re-aimed at another payment and cannot
/// outlive its window.
///
/// Flow: the agent builds the payment, the owner signs this binding for that
/// payment's hash with a near expiry, the verifier (or the node at admission)
/// checks all three. A binding that names another transaction, or a height at
/// or past its expiry, refuses by name.
///
/// The inner authorization's own owner signature travels inside the binding
/// (`auth_sigs`/`auth_keys`), so verification is self-contained: one object,
/// two signatures (one over the grant, one over the binding), no callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAuthorization {
    pub version: u8,
    pub auth: Authorization,
    /// Exclusive: the spend must land at a height below this.
    pub expires_at_height: u64,
    /// `MachinePayment::signing_hash()` of the exact payment this may settle.
    pub bound_tx: Hash,
    /// Owner signatures over [`BoundAuthorization::signing_hash`].
    pub sigs: Bundle,
    /// Owner keys (must bind to `auth.owner`).
    pub keys: Bundle,
    /// Owner signatures over the inner [`Authorization`] (the grant itself).
    pub auth_sigs: Bundle,
    /// Owner keys for the inner grant (must bind to `auth.owner`).
    pub auth_keys: Bundle,
}

impl BoundAuthorization {
    /// Domain-separated hash the owner signs: the grant, the expiry and the
    /// exact transaction, so none of the three can be swapped afterwards.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_BOUND_AUTH, &[&self.binding_bytes()])
    }

    fn binding_bytes(&self) -> Vec<u8> {
        let auth = self.auth.serialize();
        let mut w = Writer::with_capacity(auth.len() + 48);
        w.u8(self.version)
            .raw(&auth)
            .u64le(self.expires_at_height)
            .fixed(&self.bound_tx);
        w.into_vec()
    }

    /// Sign the binding with the owner's wallet. `auth_sigs`/`auth_keys` are
    /// the owner's signature over the inner grant (as produced by the
    /// authorize flow and verified by `verify.authorization`); they must bind
    /// to the same owner or issuance refuses.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        owner: &crate::wallet::Wallet,
        auth: &Authorization,
        auth_sigs: &Bundle,
        auth_keys: &Bundle,
        expires_at_height: u64,
        bound_tx: Hash,
    ) -> Result<Self, PortableError> {
        if auth_keys.address()? != auth.owner {
            return Err(PortableError::Binding(
                "grant keys are not the authorization owner's",
            ));
        }
        crate::sig::verify_bundle(auth_sigs, auth_keys, &auth.signing_hash())?;
        if expires_at_height <= auth.height {
            return Err(PortableError::Binding(
                "bound expiry must be after the grant height",
            ));
        }
        let lifetime = expires_at_height.saturating_sub(auth.height);
        if lifetime > MAX_BOUND_LIFETIME_BLOCKS {
            return Err(PortableError::LifetimeTooLong {
                lifetime,
                max: MAX_BOUND_LIFETIME_BLOCKS,
            });
        }
        let draft = BoundAuthorization {
            version: PORTABLE_POLICY_VERSION,
            auth: auth.clone(),
            expires_at_height,
            bound_tx,
            sigs: Bundle::default(),
            keys: Bundle::default(),
            auth_sigs: auth_sigs.clone(),
            auth_keys: auth_keys.clone(),
        };
        let keys = crate::l2::Auth::keys_for(owner).map_err(PortableError::Signature)?;
        if keys.address()? != auth.owner {
            return Err(PortableError::Binding(
                "binding wallet is not the grant owner's",
            ));
        }
        let sigs = crate::l2::Auth::sigs_for(owner, &draft.signing_hash())
            .map_err(PortableError::Signature)?;
        Ok(BoundAuthorization {
            keys,
            sigs,
            ..draft
        })
    }

    /// Enforced verification against the grant, the exact payment, and the
    /// current height. Order: owner binding, outer signature, inner grant
    /// (signature + liveness), expiry, lifetime, transaction match.
    pub fn verify(
        &self,
        policy: &SpendPolicy,
        payment: &crate::payment::MachinePayment,
        height: u64,
    ) -> Result<(), PortableError> {
        if self.version != PORTABLE_POLICY_VERSION {
            return Err(PortableError::UnsupportedVersion(self.version));
        }
        if self.keys.address()? != self.auth.owner {
            return Err(PortableError::Binding(
                "binding keys are not the grant owner's",
            ));
        }
        crate::sig::verify_bundle(&self.sigs, &self.keys, &self.signing_hash())?;
        verify_authorization_for_policy(
            &self.auth_sigs,
            &self.auth_keys,
            &self.auth,
            policy,
            height,
        )?;
        if height >= self.expires_at_height {
            return Err(PortableError::Expired {
                expires_at_height: self.expires_at_height,
                height,
            });
        }
        let lifetime = self.expires_at_height.saturating_sub(self.auth.height);
        if lifetime > MAX_BOUND_LIFETIME_BLOCKS {
            return Err(PortableError::LifetimeTooLong {
                lifetime,
                max: MAX_BOUND_LIFETIME_BLOCKS,
            });
        }
        if payment.signing_hash() != self.bound_tx {
            return Err(PortableError::Binding(
                "bound authorization names another transaction",
            ));
        }
        payment.linked_to(&self.auth)?;
        Ok(())
    }

    /// Canonical bytes: `version ‖ auth_len u32 ‖ auth ‖ expires ‖ tx ‖ sigs ‖
    /// keys ‖ auth_sigs ‖ auth_keys`.
    pub fn serialize(&self) -> Vec<u8> {
        let auth = self.auth.serialize();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let auth_sigs = self.auth_sigs.to_bytes();
        let auth_keys = self.auth_keys.to_bytes();
        let mut w = Writer::with_capacity(
            1 + 4
                + auth.len()
                + 8
                + 32
                + sigs.len()
                + keys.len()
                + auth_sigs.len()
                + auth_keys.len(),
        );
        w.u8(self.version)
            .u32le(auth.len() as u32)
            .raw(&auth)
            .u64le(self.expires_at_height)
            .fixed(&self.bound_tx)
            .raw(&sigs)
            .raw(&keys)
            .raw(&auth_sigs)
            .raw(&auth_keys);
        w.into_vec()
    }

    /// Decode what [`BoundAuthorization::serialize`] wrote.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PortableError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| PortableError::Malformed("version"))?;
        if version != PORTABLE_POLICY_VERSION {
            return Err(PortableError::UnsupportedVersion(version));
        }
        let len = r
            .u32le()
            .map_err(|_| PortableError::Malformed("auth length"))? as usize;
        let auth_bytes = r
            .fixed_slice(len)
            .map_err(|_| PortableError::Malformed("auth bytes"))?;
        let auth = Authorization::deserialize(auth_bytes)?;
        let expires_at_height = r.u64le().map_err(|_| PortableError::Malformed("expiry"))?;
        let bound_tx: Hash = r
            .fixed()
            .map_err(|_| PortableError::Malformed("bound tx"))?;
        let sigs =
            Bundle::from_reader(&mut r).map_err(|_| PortableError::Malformed("sigs bundle"))?;
        let keys =
            Bundle::from_reader(&mut r).map_err(|_| PortableError::Malformed("keys bundle"))?;
        let auth_sigs = Bundle::from_reader(&mut r)
            .map_err(|_| PortableError::Malformed("auth sigs bundle"))?;
        let auth_keys = Bundle::from_reader(&mut r)
            .map_err(|_| PortableError::Malformed("auth keys bundle"))?;
        r.expect_end()
            .map_err(|_| PortableError::Malformed("trailing bytes"))?;
        Ok(BoundAuthorization {
            version,
            auth,
            expires_at_height,
            bound_tx,
            sigs,
            keys,
            auth_sigs,
            auth_keys,
        })
    }

    /// Portable JSON for rails that cannot speak the canonical codec.
    pub fn to_json(&self) -> String {
        let doc = BoundAuthDoc {
            version: self.version,
            auth_hex: hex::encode(self.auth.serialize()),
            expires_at_height: self.expires_at_height,
            bound_tx: hash_to_hex(&self.bound_tx),
            binding_hash: hash_to_hex(&self.signing_hash()),
            sigs_hex: hex::encode(self.sigs.to_bytes()),
            keys_hex: hex::encode(self.keys.to_bytes()),
            auth_sigs_hex: hex::encode(self.auth_sigs.to_bytes()),
            auth_keys_hex: hex::encode(self.auth_keys.to_bytes()),
        };
        serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
    }

    /// Parse portable JSON (structure only — call
    /// [`BoundAuthorization::verify`] with the grant and payment before acting
    /// on it).
    pub fn from_json_parsed(raw: &str) -> Result<Self, PortableError> {
        if raw.len() > MAX_PORTABLE_JSON_LEN {
            return Err(PortableError::Malformed("bound json over cap"));
        }
        let doc: BoundAuthDoc =
            serde_json::from_str(raw).map_err(|_| PortableError::Malformed("bound json"))?;
        if doc.version != PORTABLE_POLICY_VERSION {
            return Err(PortableError::UnsupportedVersion(doc.version));
        }
        let auth = Authorization::deserialize(&decode_hex_field(&doc.auth_hex, "auth hex")?)?;
        let bound_tx =
            hash_from_hex(doc.bound_tx.trim()).map_err(|_| PortableError::Malformed("tx hex"))?;
        let bundle = |raw_hex: &str, what: &'static str| {
            Bundle::deserialize(&decode_hex_field(raw_hex, what)?)
                .map_err(|_| PortableError::Malformed(what))
        };
        let bound = BoundAuthorization {
            version: doc.version,
            auth,
            expires_at_height: doc.expires_at_height,
            bound_tx,
            sigs: bundle(&doc.sigs_hex, "sigs bundle")?,
            keys: bundle(&doc.keys_hex, "keys bundle")?,
            auth_sigs: bundle(&doc.auth_sigs_hex, "auth sigs bundle")?,
            auth_keys: bundle(&doc.auth_keys_hex, "auth keys bundle")?,
        };
        if hash_to_hex(&bound.signing_hash()) != doc.binding_hash.to_lowercase() {
            return Err(PortableError::Binding(
                "binding hash does not match the bound grant",
            ));
        }
        Ok(bound)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BoundAuthDoc {
    version: u8,
    auth_hex: String,
    expires_at_height: u64,
    bound_tx: String,
    binding_hash: String,
    sigs_hex: String,
    keys_hex: String,
    auth_sigs_hex: String,
    auth_keys_hex: String,
}

// ---------------------------------------------------------------------------
// PaymentIntent + PolicyDecision: the chain-agnostic engine seam
// ---------------------------------------------------------------------------

/// What an agent wants to do, in the smallest shape every rail understands.
/// This is the input to the policy engine; the `srct-policy` crate and its
/// TypeScript/Python bindings speak exactly this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub agent_id: String,
    pub recipient: String,
    pub amount_sat: u64,
    pub service: Option<String>,
    pub height: u64,
    pub nonce: u64,
    pub network_id: String,
}

impl PaymentIntent {
    /// Decode hex ids into engine types. Refuses malformed ids by name.
    pub fn decoded(&self) -> Result<DecodedIntent, PortableError> {
        let agent_id: AgentId = decode_hex_field(&self.agent_id, "agent id hex")?
            .try_into()
            .map_err(|_| PortableError::Malformed("agent id length"))?;
        let recipient: Address = address_from_hex(self.recipient.trim())
            .map_err(|_| PortableError::Malformed("recipient hex"))?;
        let service: Option<[u8; 32]> = match &self.service {
            None => None,
            Some(s) => Some(
                decode_hex_field(s, "service hex")?
                    .try_into()
                    .map_err(|_| PortableError::Malformed("service length"))?,
            ),
        };
        Ok(DecodedIntent {
            agent_id,
            recipient,
            service,
            amount_sat: self.amount_sat,
        })
    }
}

/// A decoded intent: engine types, no parsing left to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedIntent {
    pub agent_id: AgentId,
    pub recipient: Address,
    pub service: Option<[u8; 32]>,
    pub amount_sat: u64,
}

/// The engine's answer: allow, deny, or approval-needed. The third state is
/// what keeps high-value spend human-gated without refusing it outright.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    NeedsApproval { reason: String },
}

impl PolicyDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

/// Stateless pre-check of every clause that needs no committed state:
/// network binding first (a grant for another rail is not a grant here),
/// then structure, agent, kill switch, window, amount, allow-lists, and an
/// optional high-value approval threshold. Stateful clauses (nonce freshness,
/// tumbling-window spend) stay in `PolicyBook::authorize` — this never commits,
/// so calling it twice decides twice with no side effect.
pub fn evaluate_policy(
    policy: &SpendPolicy,
    intent: &DecodedIntent,
    network_id: &str,
    height: u64,
    approval_threshold_sat: Option<u64>,
) -> PolicyDecision {
    if policy.network_id != network_id {
        return PolicyDecision::Deny {
            reason: format!(
                "policy is for network {}, asked on {network_id}",
                policy.network_id
            ),
        };
    }
    if let Err(e) = policy.validate() {
        return PolicyDecision::Deny {
            reason: e.to_string(),
        };
    }
    if intent.agent_id != policy.agent_id {
        return PolicyDecision::Deny {
            reason: "authorization names another agent".to_string(),
        };
    }
    if policy.revoked {
        return PolicyDecision::Deny {
            reason: "policy is revoked".to_string(),
        };
    }
    if height < policy.not_before_height {
        return PolicyDecision::Deny {
            reason: format!(
                "policy not valid until {}, request at {height}",
                policy.not_before_height
            ),
        };
    }
    if height >= policy.expires_at_height {
        return PolicyDecision::Deny {
            reason: format!(
                "policy expired at {}, request at {height}",
                policy.expires_at_height
            ),
        };
    }
    if intent.amount_sat == 0 {
        return PolicyDecision::Deny {
            reason: "amount is zero".to_string(),
        };
    }
    if intent.amount_sat > policy.per_tx_max_sat {
        return PolicyDecision::Deny {
            reason: format!(
                "amount {} exceeds per-tx limit {}",
                intent.amount_sat, policy.per_tx_max_sat
            ),
        };
    }
    if !policy.allowed_recipients.contains(&intent.recipient) {
        return PolicyDecision::Deny {
            reason: "recipient is not allowed".to_string(),
        };
    }
    match &intent.service {
        None => {
            if !policy.allowed_services.is_empty() {
                return PolicyDecision::Deny {
                    reason: "service is not allowed".to_string(),
                };
            }
        }
        Some(tag) => {
            if !policy.allowed_services.contains(tag) {
                return PolicyDecision::Deny {
                    reason: "service is not allowed".to_string(),
                };
            }
        }
    }
    if let Some(threshold) = approval_threshold_sat {
        if threshold > 0 && intent.amount_sat >= threshold {
            return PolicyDecision::NeedsApproval {
                reason: format!(
                    "amount {} needs human approval (threshold {threshold})",
                    intent.amount_sat
                ),
            };
        }
    }
    PolicyDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{
        derive_agent_id, AgentRole, AuthorizationRequest, PolicyBook, POLICY_VERSION,
    };
    use crate::l2::Auth;
    use crate::wallet::Wallet;

    const NET: &str = "srct/testnet";

    fn owner_wallet() -> Wallet {
        Wallet::new_random("owner")
    }

    fn root_policy(owner: &Address) -> SpendPolicy {
        SpendPolicy {
            version: POLICY_VERSION,
            network_id: NET.to_string(),
            agent_id: derive_agent_id(NET, AgentRole::Machine, owner),
            owner: *owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 1_000,
            window_blocks: 100,
            cumulative_max_sat: 5_000,
            allowed_recipients: vec![[1u8; 20], [2u8; 20]],
            allowed_services: vec![],
            not_before_height: 0,
            expires_at_height: 10_000,
            revoked: false,
            parent_agent_id: None,
        }
    }

    #[test]
    fn a_signed_policy_verifies_anywhere_from_its_bytes() {
        let w = owner_wallet();
        let owner = w.address().unwrap();
        let signed = SignedPolicy::issue(&w, &root_policy(&owner)).unwrap();
        signed.verify().unwrap();
        let back = SignedPolicy::deserialize(&signed.serialize()).unwrap();
        assert_eq!(back, signed);
        back.verify().unwrap();
        // JSON is the cross-rail shape: parse verifies, and the hashes route.
        let json = signed.to_json();
        let parsed = SignedPolicy::from_json(&json).unwrap();
        assert_eq!(parsed.policy.hash(), signed.policy.hash());
    }

    #[test]
    fn a_grant_bundle_with_trailing_bytes_is_refused() {
        // Audit: standalone bundle hex fields used `from_reader` without
        // `expect_end`, ignoring smuggled trailing bytes. The strict helper
        // refuses them so two byte strings never name one grant.
        let w = owner_wallet();
        let owner = w.address().unwrap();
        let signed = SignedPolicy::issue(&w, &root_policy(&owner)).unwrap();
        let json = signed.to_json();
        let mut doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let sigs_hex = doc["sigs_hex"].as_str().unwrap().to_string();
        doc["sigs_hex"] = serde_json::Value::String(format!("{sigs_hex}ff"));
        assert!(
            SignedPolicy::from_json(&doc.to_string()).is_err(),
            "trailing bundle bytes must be refused"
        );
        SignedPolicy::from_json(&json).unwrap();
    }

    #[test]
    fn portable_routing_fields_must_match_the_grant() {
        let w = owner_wallet();
        let owner = w.address().unwrap();
        let signed = SignedPolicy::issue(&w, &root_policy(&owner)).unwrap();
        let json = signed.to_json();
        // Rewriting any routing field the grant did not earn is a confusion
        // attack, not a grant: parse refuses it before verify ever runs.
        for (field, value) in [
            ("agent_id", "ab".repeat(20)),
            ("network_id", "srct/elsewhere".to_string()),
            ("owner", address_to_hex(&owner_wallet().address().unwrap())),
            ("policy_hash", "ab".repeat(32)),
        ] {
            let mut doc: serde_json::Value = serde_json::from_str(&json).unwrap();
            doc[field] = serde_json::Value::String(value);
            assert!(
                SignedPolicy::from_json(&doc.to_string()).is_err(),
                "rewritten {field} must be refused"
            );
        }
        // The honest document still parses and verifies.
        SignedPolicy::from_json(&json).unwrap();
    }

    #[test]
    fn a_signed_policy_with_another_owners_keys_is_refused() {
        let w = owner_wallet();
        let owner = w.address().unwrap();
        let other = owner_wallet();
        let mut signed = SignedPolicy::issue(&w, &root_policy(&owner)).unwrap();
        signed.keys = Auth::keys_for(&other).unwrap();
        assert!(matches!(
            signed.verify(),
            Err(PortableError::Signature(_)) | Err(PortableError::Binding(_))
        ));
        // Routing-field confusion is refused at parse, not at verify.
        let mut doc: serde_json::Value = serde_json::from_str(&signed.to_json()).unwrap();
        doc["owner"] = serde_json::Value::String(address_to_hex(&other.address().unwrap()));
        assert!(SignedPolicy::from_json(&doc.to_string()).is_err());
    }

    #[test]
    fn a_delegation_proof_verifies_and_a_widened_link_does_not() {
        use crate::agent::derive_sub_agent_id;
        use crate::delegation::dominates;

        let w = owner_wallet();
        let owner = w.address().unwrap();
        let root = root_policy(&owner);
        let child_agent = derive_sub_agent_id(NET, &root.agent_id, root.role);
        let child = SpendPolicy {
            agent_id: child_agent,
            parent_agent_id: Some(root.agent_id),
            per_tx_max_sat: 100,
            cumulative_max_sat: 500,
            window_blocks: 10,
            allowed_recipients: vec![[1u8; 20]],
            not_before_height: 5,
            expires_at_height: 5_000,
            ..root.clone()
        };
        dominates(&root, &child).unwrap();
        let proof = DelegationProof::new(vec![
            SignedPolicy::issue(&w, &root).unwrap(),
            SignedPolicy::issue(&w, &child).unwrap(),
        ])
        .unwrap();
        proof.verify().unwrap();
        let back = DelegationProof::from_json(&proof.to_json()).unwrap();
        assert_eq!(back.leaf().hash(), proof.leaf().hash());
        // A rewritten leaf agent routes one way and verifies another.
        let mut doc: serde_json::Value = serde_json::from_str(&proof.to_json()).unwrap();
        doc["leaf_agent"] = serde_json::Value::String("ab".repeat(20));
        assert!(DelegationProof::from_json(&doc.to_string()).is_err());

        // A widened leaf keeps a valid signature but breaks the narrowing rule.
        // (Widened on cumulative: still standalone-valid, so it reaches the
        // chain check instead of failing issuance.)
        let mut wide = child.clone();
        wide.cumulative_max_sat = 9_999;
        let bad = DelegationProof::new(vec![
            SignedPolicy::issue(&w, &root).unwrap(),
            SignedPolicy::issue(&w, &wide).unwrap(),
        ])
        .unwrap();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn the_engine_seam_answers_allow_deny_or_approval_needed() {
        let w = owner_wallet();
        let owner = w.address().unwrap();
        let policy = root_policy(&owner);
        let base = DecodedIntent {
            agent_id: policy.agent_id,
            recipient: [1u8; 20],
            service: None,
            amount_sat: 500,
        };
        assert_eq!(
            evaluate_policy(&policy, &base, NET, 100, Some(10_000)),
            PolicyDecision::Allow
        );
        let over = DecodedIntent {
            amount_sat: 50_000,
            ..base
        };
        assert!(matches!(
            evaluate_policy(&policy, &over, NET, 100, None),
            PolicyDecision::Deny { .. }
        ));
        assert!(matches!(
            evaluate_policy(&policy, &base, NET, 100, Some(100)),
            PolicyDecision::NeedsApproval { .. }
        ));
        let stranger = DecodedIntent {
            recipient: [9u8; 20],
            amount_sat: 10,
            ..base
        };
        assert!(matches!(
            evaluate_policy(&policy, &stranger, NET, 100, None),
            PolicyDecision::Deny { .. }
        ));
        // A grant for another rail is not a grant here: the engine owns the
        // network binding, so no caller can forget it.
        let foreign = DecodedIntent { ..base };
        let denied = evaluate_policy(&policy, &foreign, "srct/elsewhere", 100, None);
        assert!(
            matches!(&denied, PolicyDecision::Deny { reason } if reason.contains("srct/testnet")),
            "{denied:?}"
        );
    }

    #[test]
    fn a_bound_authorization_is_short_lived_and_tx_exact() {
        let w = owner_wallet();
        let owner = w.address().unwrap();
        let policy = root_policy(&owner);
        let mut book = PolicyBook::default();
        let auth = book
            .authorize(
                &policy,
                NET,
                &AuthorizationRequest {
                    agent_id: policy.agent_id,
                    recipient: [1u8; 20],
                    amount_sat: 400,
                    service: None,
                    height: 100,
                    nonce: 1,
                },
            )
            .unwrap();
        let payment = crate::payment::build_signed_payment(
            &w,
            &auth,
            NET,
            AgentRole::Machine,
            0,
            9_000,
            [3u8; 32],
            &[],
        )
        .unwrap();
        let auth_sigs = Auth::sigs_for(&w, &auth.signing_hash()).unwrap();
        let auth_keys = Auth::keys_for(&w).unwrap();
        let bound = BoundAuthorization::issue(
            &w,
            &auth,
            &auth_sigs,
            &auth_keys,
            110,
            payment.signing_hash(),
        )
        .unwrap();
        bound.verify(&policy, &payment, 105).unwrap();
        let back = BoundAuthorization::deserialize(&bound.serialize()).unwrap();
        assert_eq!(back, bound);
        back.verify(&policy, &payment, 105).unwrap();
        let parsed = BoundAuthorization::from_json_parsed(&bound.to_json()).unwrap();
        assert_eq!(parsed, bound);
        // Past expiry refuses by name.
        assert!(matches!(
            bound.verify(&policy, &payment, 110),
            Err(PortableError::Expired { .. })
        ));
        // Another transaction refuses by name.
        let mut other_payment = payment.clone();
        other_payment.amount_sat = 401;
        assert!(matches!(
            bound.verify(&policy, &other_payment, 105),
            Err(PortableError::Binding(_))
        ));
        // A lifetime longer than the cap is refused at issuance, not at spend.
        assert!(BoundAuthorization::issue(
            &w,
            &auth,
            &auth_sigs,
            &auth_keys,
            100 + MAX_BOUND_LIFETIME_BLOCKS + 1,
            payment.signing_hash(),
        )
        .is_err());
    }
}
