//! Solar Smart Gate: universal context-bound capability layer.
//!
//! Answers one question: *may this workload do this exact action at this
//! exact moment under this grant?* Pure and deterministic: no clock, no
//! randomness, no I/O. Two callers with the same inputs reach the same answer.
//!
//! This is deliberately not a tool allow-list. The policy never names tools,
//! containers, or cloud APIs. It bounds rate, validity, and ancestry. The
//! exactness comes from hash equality: the capability binds
//! `policy_hash || action_hash || context_hash || expiry || nonce`, and the
//! runtime re-derives `action_hash` and `context_hash` from what it is about
//! to execute. One bit of drift denies.
//!
//! Fail-closed: every refusal is a named [`GuardError`]. Nothing mutates on
//! refusal. Nonces must strictly increase. Windows tumble forward only.

use crate::agent::AgentId;
use crate::hash::{sha256_dom, Address, Hash};
use crate::ser::{Reader, Writer};
use std::collections::BTreeMap;

/// Version of the infra grant encoding. A future format MUST use a new value.
/// Current grant/envelope version. `InfraPolicy` decoding still accepts v1
/// bytes (new fields default to legacy semantics); signed capability and
/// approval envelopes only accept the current version.
pub const GUARD_POLICY_VERSION: u8 = 2;
const GUARD_POLICY_VERSION_V1: u8 = 1;
/// Longest accepted network id, mirrors agent policy bound.
pub const MAX_GUARD_NETWORK_LEN: usize = 64;
/// Most grants tracked per book, cap-with-refusal like PolicyBook.
pub const DEFAULT_MAX_GUARDS: usize = 1024;
/// Longest a capability may live, in heights, from the check height.
pub const MAX_CAP_LIFETIME: u64 = 30;
/// Longest an approval may live, in heights, from the check height.
pub const MAX_APPROVAL_LIFETIME: u64 = 30;
/// Most grants tracked in one node's registry, cap-with-refusal like the book.
pub const MAX_GUARD_REGISTRY: usize = 1024;

/// Domain tag for the grant signing hash.
pub const DOM_GUARD_POLICY: &[u8] = b"srct/guard-policy/v1";
/// Domain tag for the capability signing hash.
pub const DOM_GUARD_CAP: &[u8] = b"srct/guard-cap/v1";
/// Domain tag for context derivation (workload || height).
pub const DOM_GUARD_CTX: &[u8] = b"srct/guard-ctx/v1";
/// Domain tag for the canonical action hash (action preimage bytes).
pub const DOM_GUARD_ACTION: &[u8] = b"srct/guard-action/v1";
/// Domain tag for the high-risk approval signing hash.
pub const DOM_GUARD_APPROVAL: &[u8] = b"srct/guard-approval/v1";

/// Why the gate refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    Malformed(&'static str),
    UnsupportedVersion(u8),
    EmptyNetworkId,
    NetworkIdTooLong(usize),
    NetworkMismatch,
    Revoked,
    NotYetValid { height: u64, valid_from: u64 },
    ExpiredGrant { height: u64, valid_until: u64 },
    ExpiredCap { height: u64, expiry: u64 },
    LifetimeTooLong { lifetime: u64, max: u64 },
    PolicyMismatch,
    ActionMismatch,
    ContextMismatch,
    CrossPrincipal,
    ZeroNonce,
    UnsignedCapability,
    BadApproval(&'static str),
    ActionUnverified,
    SelfApproval,
    WrongAudience,
    NonceNotIncreasing { nonce: u64, last_nonce: u64 },
    HeightRewind { height: u64, window_start: u64 },
    WindowExhausted { calls: u64, max: u64 },
    Overflow,
    BookFull { cap: usize },
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::Malformed(w) => write!(f, "malformed guard object: {w}"),
            GuardError::UnsupportedVersion(v) => write!(f, "unsupported guard version {v}"),
            GuardError::EmptyNetworkId => write!(f, "empty network id"),
            GuardError::NetworkIdTooLong(n) => write!(f, "network id too long ({n})"),
            GuardError::NetworkMismatch => write!(f, "network id mismatch"),
            GuardError::Revoked => write!(f, "grant revoked"),
            GuardError::NotYetValid { height, valid_from } => {
                write!(f, "not yet valid: height {height} before {valid_from}")
            }
            GuardError::ExpiredGrant {
                height,
                valid_until,
            } => {
                write!(f, "grant expired: height {height} at {valid_until}")
            }
            GuardError::ExpiredCap { height, expiry } => {
                write!(f, "capability expired at {expiry}, checked at {height}")
            }
            GuardError::LifetimeTooLong { lifetime, max } => {
                write!(f, "capability lifetime {lifetime} exceeds cap {max}")
            }
            GuardError::PolicyMismatch => write!(f, "capability does not name this grant"),
            GuardError::ActionMismatch => write!(f, "action hash mismatch"),
            GuardError::ContextMismatch => write!(f, "context hash mismatch"),
            GuardError::CrossPrincipal => write!(f, "capability principal is not this agent"),
            GuardError::ZeroNonce => write!(f, "capability nonce is zero"),
            GuardError::SelfApproval => {
                write!(f, "high-assurance grant names no independent approver")
            }
            GuardError::WrongAudience => {
                write!(f, "capability is scoped to another enforcing node")
            }
            GuardError::UnsignedCapability => {
                write!(f, "capability is not signed by the grant owner")
            }
            GuardError::BadApproval(w) => write!(f, "approval invalid: {w}"),
            GuardError::ActionUnverified => {
                write!(f, "action preimage required at the execution boundary")
            }
            GuardError::NonceNotIncreasing { nonce, last_nonce } => {
                write!(f, "nonce {nonce} is not greater than last {last_nonce}")
            }
            GuardError::HeightRewind {
                height,
                window_start,
            } => {
                write!(f, "height {height} precedes window start {window_start}")
            }
            GuardError::WindowExhausted { calls, max } => {
                write!(f, "window exhausted: {calls} of {max} calls used")
            }
            GuardError::Overflow => write!(f, "arithmetic overflow in guard accounting"),
            GuardError::BookFull { cap } => write!(f, "guard book full ({cap})"),
        }
    }
}

impl std::error::Error for GuardError {}

/// Owner-signed narrow grant for one workload identity.
///
/// Bounds rate and validity only. Names no tools, images, or APIs.
///
/// Risk classification lives here, set by the owner at issuance — never in
/// the request. `requires_approval` marks a high-assurance grant: every
/// admission under it needs a signed [`GuardApproval`], and a caller-supplied
/// `high_risk: false` cannot switch that off (callers can only escalate a
/// low-assurance grant into `needs_approval`, never de-escalate a
/// high-assurance one). A high-assurance grant MUST name a genuinely
/// independent `approver` (non-zero, distinct from both owner and agent);
/// owner-as-approver is refused as [`GuardError::SelfApproval`], because a
/// second signature from the same authority is not a second channel.
/// `workload_id` binds the grant to one authenticated workload (zero means
/// unbound legacy semantics: the presented id is trusted). Capabilities may
/// additionally scope themselves to one enforcing node via
/// [`Capability::audience`] (multi-node replay rule, §6 of the architecture
/// doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfraPolicy {
    pub version: u8,
    pub network_id: String,
    pub agent_id: AgentId,
    pub owner: Address,
    pub max_calls_per_window: u64,
    pub window_blocks: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub revoked: bool,
    pub parent_agent_id: Option<AgentId>,
    pub requires_approval: bool,
    pub approver: Address,
    pub workload_id: Hash,
}

impl InfraPolicy {
    pub fn hash(&self) -> Hash {
        self.signing_hash()
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_GUARD_POLICY, &[&self.serialize()])
    }

    /// The address whose signature counts as approval: the designated
    /// approver, or the owner for legacy grants that name none.
    pub fn effective_approver(&self) -> Address {
        if self.approver == [0u8; 20] {
            self.owner
        } else {
            self.approver
        }
    }

    /// The workload every admission context is recomputed from: the bound id
    /// when the grant names one, so a caller-supplied id is ignored rather
    /// than trusted.
    pub fn effective_workload(&self, presented: &Hash) -> Hash {
        if self.workload_id == [0u8; 32] {
            *presented
        } else {
            self.workload_id
        }
    }

    /// Structural plus risk-model validation. Called on every admission path
    /// and at grant registration, so a misconfigured high-assurance grant
    /// fails closed instead of silently degrading to owner self-approval.
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.max_calls_per_window == 0 {
            return Err(GuardError::Malformed("max calls is zero"));
        }
        if self.window_blocks == 0 {
            return Err(GuardError::Malformed("window is zero"));
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err(GuardError::Malformed("empty validity range"));
        }
        if self.requires_approval
            && (self.approver == [0u8; 20]
                || self.approver == self.owner
                || self.approver == self.agent_id)
        {
            return Err(GuardError::SelfApproval);
        }
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(192);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.agent_id)
            .fixed(&self.owner)
            .u64le(self.max_calls_per_window)
            .u64le(self.window_blocks)
            .u64le(self.valid_from_height)
            .u64le(self.valid_until_height)
            .u8(u8::from(self.revoked));
        match &self.parent_agent_id {
            Some(p) => {
                w.u8(1).fixed(p);
            }
            None => {
                w.u8(0);
            }
        }
        w.u8(u8::from(self.requires_approval))
            .fixed(&self.approver)
            .fixed(&self.workload_id);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, GuardError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| GuardError::Malformed("version"))?;
        // v1 grants (pre risk-model) still decode: the new fields default to
        // legacy semantics (no mandated approval, owner approves, unbound
        // workload). Persisted registry grants migrate by decoding, never by
        // resurrection.
        if version != GUARD_POLICY_VERSION && version != GUARD_POLICY_VERSION_V1 {
            return Err(GuardError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| GuardError::Malformed("network len"))? as usize;
        if net_len == 0 {
            return Err(GuardError::EmptyNetworkId);
        }
        if net_len > MAX_GUARD_NETWORK_LEN {
            return Err(GuardError::NetworkIdTooLong(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| GuardError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| GuardError::Malformed("network id utf-8"))?
            .to_string();
        let agent_id = r
            .fixed::<20>()
            .map_err(|_| GuardError::Malformed("agent"))?;
        let owner = r
            .fixed::<20>()
            .map_err(|_| GuardError::Malformed("owner"))?;
        let max_calls_per_window = r.u64le().map_err(|_| GuardError::Malformed("max calls"))?;
        let window_blocks = r.u64le().map_err(|_| GuardError::Malformed("window"))?;
        if window_blocks == 0 {
            return Err(GuardError::Malformed("window is zero"));
        }
        if max_calls_per_window == 0 {
            return Err(GuardError::Malformed("max calls is zero"));
        }
        let valid_from_height = r.u64le().map_err(|_| GuardError::Malformed("valid from"))?;
        let valid_until_height = r
            .u64le()
            .map_err(|_| GuardError::Malformed("valid until"))?;
        if valid_until_height <= valid_from_height {
            return Err(GuardError::Malformed("empty validity range"));
        }
        let revoked_raw = r.u8().map_err(|_| GuardError::Malformed("revoked"))?;
        if revoked_raw > 1 {
            return Err(GuardError::Malformed("revoked out of range"));
        }
        let link = r.u8().map_err(|_| GuardError::Malformed("parent link"))?;
        let parent_agent_id = match link {
            0 => None,
            1 => Some(
                r.fixed::<20>()
                    .map_err(|_| GuardError::Malformed("parent"))?,
            ),
            _ => return Err(GuardError::Malformed("parent link out of range")),
        };
        let (requires_approval, approver, workload_id) = if version == GUARD_POLICY_VERSION_V1 {
            if r.remaining() != 0 {
                return Err(GuardError::Malformed("trailing bytes"));
            }
            (false, [0u8; 20], [0u8; 32])
        } else {
            let risk_raw = r.u8().map_err(|_| GuardError::Malformed("risk flags"))?;
            if risk_raw > 1 {
                return Err(GuardError::Malformed("risk flags out of range"));
            }
            let approver = r
                .fixed::<20>()
                .map_err(|_| GuardError::Malformed("approver"))?;
            let workload_id = r
                .fixed::<32>()
                .map_err(|_| GuardError::Malformed("workload"))?;
            if r.remaining() != 0 {
                return Err(GuardError::Malformed("trailing bytes"));
            }
            (risk_raw == 1, approver, workload_id)
        };
        Ok(InfraPolicy {
            version,
            network_id,
            agent_id,
            owner,
            max_calls_per_window,
            window_blocks,
            valid_from_height,
            valid_until_height,
            revoked: revoked_raw == 1,
            parent_agent_id,
            requires_approval,
            approver,
            workload_id,
        })
    }
}

/// Short-lived exact-action capability. What the owner signs.
///
/// `audience` scopes the capability to one enforcing node (zero means
/// unscoped legacy semantics: admittable anywhere). An enforcing node admits
/// only capabilities whose audience equals its own configured audience, so an
/// owner that scopes a capability to node A denies its replay on node B by
/// name. This is scoping, not a cross-node lock: unscoped capabilities remain
/// independently admittable on every node, which the architecture doc states
/// plainly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub policy_hash: Hash,
    pub action_hash: Hash,
    pub context_hash: Hash,
    pub expiry_height: u64,
    pub nonce: u64,
    pub audience: Hash,
}

impl Capability {
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_GUARD_CAP, &[&self.serialize()])
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(144);
        w.fixed(&self.policy_hash)
            .fixed(&self.action_hash)
            .fixed(&self.context_hash)
            .u64le(self.expiry_height)
            .u64le(self.nonce)
            .fixed(&self.audience);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, GuardError> {
        let mut r = Reader::new(bytes);
        let policy_hash = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("policy hash"))?;
        let action_hash = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("action hash"))?;
        let context_hash = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("context hash"))?;
        let expiry_height = r.u64le().map_err(|_| GuardError::Malformed("expiry"))?;
        let nonce = r.u64le().map_err(|_| GuardError::Malformed("nonce"))?;
        let audience = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("audience"))?;
        if r.remaining() != 0 {
            return Err(GuardError::Malformed("trailing bytes"));
        }
        Ok(Capability {
            policy_hash,
            action_hash,
            context_hash,
            expiry_height,
            nonce,
            audience,
        })
    }
}

/// Canonical action hash: SHA-256 over the domain tag and the exact bytes
/// the runtime is about to execute. The execution boundary MUST recompute
/// this from the preimage it observes and compare it to the capability's
/// `action_hash`; comparing two caller-supplied hashes proves nothing, which
/// is the action-swap hole this closes.
pub fn derive_action_hash(preimage: &[u8]) -> Hash {
    sha256_dom(DOM_GUARD_ACTION, &[preimage])
}

/// An owner-signed capability: the exact-action grant plus the owner's
/// signature over it. A bare [`Capability`] is bytes anyone can write down
/// (policy hash + action + context + expiry + nonce are all public or
/// guessable); only the owner's signature turns it into authority. Every
/// admission boundary MUST verify this signature before anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCapability {
    pub version: u8,
    pub cap: Capability,
    pub sigs: crate::sig::Bundle,
    pub keys: crate::sig::Bundle,
}

impl SignedCapability {
    /// Sign a capability with the grant owner's wallet. The wallet is borrowed
    /// and never stored.
    pub fn issue(
        owner: &crate::wallet::Wallet,
        cap: &Capability,
    ) -> Result<Self, crate::error::Error> {
        let keys = crate::l2::Auth::keys_for(owner)?;
        let sigs = crate::l2::Auth::sigs_for(owner, &cap.signing_hash())?;
        Ok(SignedCapability {
            version: GUARD_POLICY_VERSION,
            cap: cap.clone(),
            sigs,
            keys,
        })
    }

    /// Verify the envelope: version, owner binding, and signature over the
    /// capability's signing hash (which covers policy, action, context,
    /// expiry and nonce together, so none of the five can be swapped).
    pub fn verify(&self, policy: &InfraPolicy) -> Result<(), GuardError> {
        if self.version != GUARD_POLICY_VERSION {
            return Err(GuardError::UnsupportedVersion(self.version));
        }
        let addr = self
            .keys
            .address()
            .map_err(|_| GuardError::UnsignedCapability)?;
        if addr != policy.owner {
            return Err(GuardError::UnsignedCapability);
        }
        crate::sig::verify_bundle(&self.sigs, &self.keys, &self.cap.signing_hash())
            .map_err(|_| GuardError::UnsignedCapability)?;
        if self.cap.policy_hash != policy.hash() {
            return Err(GuardError::PolicyMismatch);
        }
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let cap = self.cap.serialize();
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(1 + cap.len() + sigs.len() + keys.len());
        w.u8(self.version).raw(&cap).raw(&sigs).raw(&keys);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, GuardError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| GuardError::Malformed("version"))?;
        if version != GUARD_POLICY_VERSION {
            return Err(GuardError::UnsupportedVersion(version));
        }
        let cap_bytes = r
            .fixed_slice(144)
            .map_err(|_| GuardError::Malformed("capability bytes"))?;
        let cap = Capability::deserialize(cap_bytes)?;
        let sigs = crate::sig::Bundle::from_reader(&mut r)
            .map_err(|_| GuardError::Malformed("sigs bundle"))?;
        let keys = crate::sig::Bundle::from_reader(&mut r)
            .map_err(|_| GuardError::Malformed("keys bundle"))?;
        if r.remaining() != 0 {
            return Err(GuardError::Malformed("trailing bytes"));
        }
        Ok(SignedCapability {
            version,
            cap,
            sigs,
            keys,
        })
    }
}

/// A cryptographically verifiable high-risk approval. Replaces the old
/// `approved: bool` flag, which let any caller claim approval without proof.
/// The approver signs the exact capability instance (grant + capability hash +
/// agent + action + context + expiry) under [`DOM_GUARD_APPROVAL`], so an
/// approval cannot be moved to another action, another agent, another nonce,
/// or a later height. Authority: the approver MUST be the grant owner — the
/// second channel is a second signature, not a second boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardApproval {
    pub version: u8,
    pub policy_hash: Hash,
    pub cap_hash: Hash,
    pub agent_id: AgentId,
    pub action_hash: Hash,
    pub context_hash: Hash,
    pub expiry_height: u64,
    pub sigs: crate::sig::Bundle,
    pub keys: crate::sig::Bundle,
}

impl GuardApproval {
    pub fn signing_hash(&self) -> Hash {
        let mut w = Writer::with_capacity(32 * 4 + 20 + 8 + 1);
        w.u8(self.version)
            .fixed(&self.policy_hash)
            .fixed(&self.cap_hash)
            .fixed(&self.agent_id)
            .fixed(&self.action_hash)
            .fixed(&self.context_hash)
            .u64le(self.expiry_height);
        sha256_dom(DOM_GUARD_APPROVAL, &[&w.into_vec()])
    }

    pub fn serialize(&self) -> Vec<u8> {
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(1 + 32 * 4 + 20 + 8 + sigs.len() + keys.len());
        w.u8(self.version)
            .fixed(&self.policy_hash)
            .fixed(&self.cap_hash)
            .fixed(&self.agent_id)
            .fixed(&self.action_hash)
            .fixed(&self.context_hash)
            .u64le(self.expiry_height)
            .raw(&sigs)
            .raw(&keys);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, GuardError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| GuardError::Malformed("version"))?;
        if version != GUARD_POLICY_VERSION {
            return Err(GuardError::UnsupportedVersion(version));
        }
        let policy_hash = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("policy hash"))?;
        let cap_hash = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("cap hash"))?;
        let agent_id = r
            .fixed::<20>()
            .map_err(|_| GuardError::Malformed("agent"))?;
        let action_hash = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("action hash"))?;
        let context_hash = r
            .fixed::<32>()
            .map_err(|_| GuardError::Malformed("context hash"))?;
        let expiry_height = r.u64le().map_err(|_| GuardError::Malformed("expiry"))?;
        let sigs = crate::sig::Bundle::from_reader(&mut r)
            .map_err(|_| GuardError::Malformed("sigs bundle"))?;
        let keys = crate::sig::Bundle::from_reader(&mut r)
            .map_err(|_| GuardError::Malformed("keys bundle"))?;
        if r.remaining() != 0 {
            return Err(GuardError::Malformed("trailing bytes"));
        }
        Ok(GuardApproval {
            version,
            policy_hash,
            cap_hash,
            agent_id,
            action_hash,
            context_hash,
            expiry_height,
            sigs,
            keys,
        })
    }

    /// Verify against the live grant, the capability being approved, and the
    /// values the boundary recomputed. Every mismatch is a named refusal.
    /// Authority is the grant's designated approver — an address the owner
    /// named at issuance, distinct from the owner — never whoever happens to
    /// hold the capability. Legacy grants that name no approver fall back to
    /// the owner (documented as self-managed, not second-channel).
    pub fn verify(
        &self,
        policy: &InfraPolicy,
        cap: &Capability,
        agent_id: &AgentId,
        action_hash: &Hash,
        context_hash: &Hash,
        height: u64,
    ) -> Result<(), GuardError> {
        if self.version != GUARD_POLICY_VERSION {
            return Err(GuardError::UnsupportedVersion(self.version));
        }
        let addr = self
            .keys
            .address()
            .map_err(|_| GuardError::BadApproval("keys do not form an address"))?;
        if addr != policy.effective_approver() {
            return Err(GuardError::BadApproval(
                "approval is not from the designated approver",
            ));
        }
        crate::sig::verify_bundle(&self.sigs, &self.keys, &self.signing_hash())
            .map_err(|_| GuardError::BadApproval("approval signature invalid"))?;
        if self.policy_hash != policy.hash() {
            return Err(GuardError::BadApproval("approval names another grant"));
        }
        if self.cap_hash != cap.signing_hash() {
            return Err(GuardError::BadApproval("approval names another capability"));
        }
        if self.agent_id != *agent_id {
            return Err(GuardError::BadApproval("approval names another agent"));
        }
        if self.action_hash != *action_hash {
            return Err(GuardError::BadApproval("approval names another action"));
        }
        if self.context_hash != *context_hash {
            return Err(GuardError::BadApproval("approval names another context"));
        }
        if height >= self.expiry_height {
            return Err(GuardError::BadApproval("approval expired"));
        }
        if self.expiry_height.saturating_sub(height) > MAX_APPROVAL_LIFETIME {
            return Err(GuardError::BadApproval("approval lifetime exceeds cap"));
        }
        Ok(())
    }
}

/// Derive the context a verifier recomputes from what it observes.
pub fn derive_context_hash(workload_id: &Hash, height: u64) -> Hash {
    let mut hb = [0u8; 8];
    hb.copy_from_slice(&height.to_le_bytes());
    sha256_dom(DOM_GUARD_CTX, &[workload_id, &hb])
}

/// Gate answer. `NeedsApproval` commits nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    NeedsApproval,
    Deny(GuardError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardState {
    pub window_start_height: u64,
    pub calls_in_window: u64,
    pub last_nonce: u64,
    pub total_calls: u64,
}

/// Tumbling-window capability book keyed by grant hash.
#[derive(Debug, Clone)]
pub struct GuardBook {
    states: BTreeMap<Hash, GuardState>,
    max_grants: usize,
}

impl Default for GuardBook {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_GUARDS)
    }
}

/// Largest entry count the guard-book codec will read back. Checked before
/// any allocation; real books are capped at [`DEFAULT_MAX_GUARDS`].
pub const MAX_GUARD_BOOK_READ: usize = 1 << 20;

impl GuardBook {
    pub fn with_capacity(max_grants: usize) -> Self {
        GuardBook {
            states: BTreeMap::new(),
            max_grants,
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub fn state(&self, grant_hash: &Hash) -> Option<GuardState> {
        self.states.get(grant_hash).copied()
    }

    /// Forget a grant's accounting (used when a grant is revoked or rotated).
    pub fn forget(&mut self, grant_hash: &Hash) -> Option<GuardState> {
        self.states.remove(grant_hash)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Hash, GuardState)> {
        self.states.iter().map(|(k, v)| (k, *v))
    }

    /// Restore one grant's accounting (restart recovery only). Refuses a
    /// duplicate grant or a full book.
    pub fn restore(&mut self, grant_hash: Hash, state: GuardState) -> Result<(), GuardError> {
        if self.states.contains_key(&grant_hash) {
            return Err(GuardError::Malformed("duplicate guard grant"));
        }
        if self.states.len() >= self.max_grants {
            return Err(GuardError::BookFull {
                cap: self.max_grants,
            });
        }
        self.states.insert(grant_hash, state);
        Ok(())
    }

    /// Canonical encoding of the whole book: cap + entries.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(16 + self.states.len() * 64);
        w.u64le(self.max_grants as u64);
        w.u32le(self.states.len() as u32);
        for (hash, st) in &self.states {
            w.fixed(hash)
                .u64le(st.window_start_height)
                .u64le(st.calls_in_window)
                .u64le(st.last_nonce)
                .u64le(st.total_calls);
        }
        w.into_vec()
    }

    /// Decode what [`GuardBook::encode`] wrote. Bounded and fail-closed.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, crate::error::Error> {
        use crate::error::Error;
        let max_raw = r.u64le()?;
        if max_raw > MAX_GUARD_BOOK_READ as u64 {
            return Err(Error::Malformed("guard book capacity over codec cap"));
        }
        let max = max_raw as usize;
        let count = r.u32le()? as usize;
        if count > max {
            return Err(Error::Malformed("guard count over book capacity"));
        }
        let mut book = GuardBook::with_capacity(max);
        for _ in 0..count {
            let hash: Hash = r.fixed()?;
            let state = GuardState {
                window_start_height: r.u64le()?,
                calls_in_window: r.u64le()?,
                last_nonce: r.u64le()?,
                total_calls: r.u64le()?,
            };
            book.states.insert(hash, state);
        }
        if book.states.len() != count {
            return Err(Error::Malformed("duplicate guard grant in book"));
        }
        Ok(book)
    }

    /// Full check. On `Allow` the state commits. On `NeedsApproval` or any
    /// `Deny` nothing mutates, so a refused burst cannot consume budget.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &mut self,
        policy: &InfraPolicy,
        cap: &Capability,
        agent_id: &AgentId,
        network_id: &str,
        height: u64,
        expected_action: &Hash,
        expected_context: &Hash,
        high_risk: bool,
        approved: bool,
    ) -> Decision {
        match self.authorize_inner(
            policy,
            cap,
            agent_id,
            network_id,
            height,
            expected_action,
            expected_context,
            high_risk,
            approved,
        ) {
            Ok(d) => d,
            Err(e) => Decision::Deny(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_inner(
        &mut self,
        policy: &InfraPolicy,
        cap: &Capability,
        agent_id: &AgentId,
        network_id: &str,
        height: u64,
        expected_action: &Hash,
        expected_context: &Hash,
        high_risk: bool,
        approved: bool,
    ) -> Result<Decision, GuardError> {
        if policy.version != GUARD_POLICY_VERSION {
            return Err(GuardError::UnsupportedVersion(policy.version));
        }
        if policy.network_id != network_id {
            return Err(GuardError::NetworkMismatch);
        }
        if policy.revoked {
            return Err(GuardError::Revoked);
        }
        if height < policy.valid_from_height {
            return Err(GuardError::NotYetValid {
                height,
                valid_from: policy.valid_from_height,
            });
        }
        if height >= policy.valid_until_height {
            return Err(GuardError::ExpiredGrant {
                height,
                valid_until: policy.valid_until_height,
            });
        }
        policy.validate()?;
        if policy.agent_id != *agent_id {
            return Err(GuardError::CrossPrincipal);
        }
        if cap.nonce == 0 {
            return Err(GuardError::ZeroNonce);
        }
        if cap.policy_hash != policy.hash() {
            return Err(GuardError::PolicyMismatch);
        }
        if cap.action_hash != *expected_action {
            return Err(GuardError::ActionMismatch);
        }
        if cap.context_hash != *expected_context {
            return Err(GuardError::ContextMismatch);
        }
        if height >= cap.expiry_height {
            return Err(GuardError::ExpiredCap {
                height,
                expiry: cap.expiry_height,
            });
        }
        let lifetime = cap.expiry_height.saturating_sub(height);
        if lifetime > MAX_CAP_LIFETIME {
            return Err(GuardError::LifetimeTooLong {
                lifetime,
                max: MAX_CAP_LIFETIME,
            });
        }
        let key = policy.hash();
        let state = self.states.get(&key).copied().unwrap_or(GuardState {
            window_start_height: height,
            calls_in_window: 0,
            last_nonce: 0,
            total_calls: 0,
        });
        if height < state.window_start_height {
            return Err(GuardError::HeightRewind {
                height,
                window_start: state.window_start_height,
            });
        }
        if cap.nonce <= state.last_nonce {
            return Err(GuardError::NonceNotIncreasing {
                nonce: cap.nonce,
                last_nonce: state.last_nonce,
            });
        }
        let window_end = state
            .window_start_height
            .checked_add(policy.window_blocks)
            .ok_or(GuardError::Overflow)?;
        let (window_start, calls) = if height >= window_end {
            (height, 0)
        } else {
            (state.window_start_height, state.calls_in_window)
        };
        if calls >= policy.max_calls_per_window {
            return Err(GuardError::WindowExhausted {
                calls,
                max: policy.max_calls_per_window,
            });
        }
        if high_risk && !approved {
            return Ok(Decision::NeedsApproval);
        }
        if !self.states.contains_key(&key) && self.states.len() >= self.max_grants {
            return Err(GuardError::BookFull {
                cap: self.max_grants,
            });
        }
        let next_calls = calls.checked_add(1).ok_or(GuardError::Overflow)?;
        let next_total = state
            .total_calls
            .checked_add(1)
            .ok_or(GuardError::Overflow)?;
        self.states.insert(
            key,
            GuardState {
                window_start_height: window_start,
                calls_in_window: next_calls,
                last_nonce: cap.nonce,
                total_calls: next_total,
            },
        );
        Ok(Decision::Allow)
    }

    /// Execution-boundary admission: the signed-capability + recomputed-action
    /// + cryptographic-approval path every trust boundary MUST use.
    ///
    /// - Verifies the owner's signature over the capability, then the grant's
    ///   structural and risk-model validity (`SelfApproval` fails closed).
    /// - Refuses capabilities scoped to another enforcing node (`audience`).
    /// - Recomputes the canonical action hash from the `action_preimage` the
    ///   boundary observes, and refuses unless it equals the capability's
    ///   action. There is no hash-only overload here: a boundary that cannot
    ///   name the preimage cannot authorize.
    /// - Recomputes the context from the grant-bound workload when the grant
    ///   names one, ignoring any caller-supplied id; a caller-supplied
    ///   workload id is only trusted for unbound (legacy) grants.
    /// - Risk comes from the grant (`requires_approval`) OR-ed with the
    ///   caller's escalation flag — a caller can escalate into
    ///   `NeedsApproval`, never de-escalate out of it. High-assurance calls
    ///   require a [`GuardApproval`] from the grant's designated approver
    ///   (independent of the owner): missing gates, forged denies.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_signed(
        &mut self,
        policy: &InfraPolicy,
        signed: &SignedCapability,
        agent_id: &AgentId,
        network_id: &str,
        height: u64,
        action_preimage: &[u8],
        workload_id: &Hash,
        node_audience: &Hash,
        high_risk: bool,
        approval: Option<&GuardApproval>,
    ) -> Decision {
        if let Err(e) = signed.verify(policy) {
            return Decision::Deny(e);
        }
        if signed.cap.audience != *node_audience {
            return Decision::Deny(GuardError::WrongAudience);
        }
        let recomputed = derive_action_hash(action_preimage);
        if recomputed != signed.cap.action_hash {
            return Decision::Deny(GuardError::ActionMismatch);
        }
        let effective_ctx = derive_context_hash(&policy.effective_workload(workload_id), height);
        if effective_ctx != signed.cap.context_hash {
            return Decision::Deny(GuardError::ContextMismatch);
        }
        if high_risk || policy.requires_approval {
            match approval {
                None => return Decision::NeedsApproval,
                Some(ap) => {
                    if let Err(e) = ap.verify(
                        policy,
                        &signed.cap,
                        agent_id,
                        &recomputed,
                        &effective_ctx,
                        height,
                    ) {
                        return Decision::Deny(e);
                    }
                }
            }
        }
        match self.authorize_inner(
            policy,
            &signed.cap,
            agent_id,
            network_id,
            height,
            &recomputed,
            &effective_ctx,
            false,
            true,
        ) {
            Ok(d) => d,
            Err(e) => Decision::Deny(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> InfraPolicy {
        InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: "srct/testnet".to_string(),
            agent_id: [7u8; 20],
            owner: [9u8; 20],
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 10,
            valid_until_height: 1000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: false,
            approver: [0u8; 20],
            workload_id: [0u8; 32],
        }
    }

    fn test_cap(policy: &InfraPolicy, nonce: u64, height: u64) -> (Capability, Hash, Hash) {
        let action: Hash = [1u8; 32];
        let workload: Hash = [2u8; 32];
        let ctx = derive_context_hash(&workload, height);
        let cap = Capability {
            policy_hash: policy.hash(),
            action_hash: action,
            context_hash: ctx,
            expiry_height: height + 10,
            nonce,
            audience: [0u8; 32],
        };
        (cap, action, ctx)
    }

    #[test]
    fn guard_allow_happy_path() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        let d = book.authorize(
            &policy,
            &cap,
            &[7u8; 20],
            "srct/testnet",
            50,
            &action,
            &ctx,
            false,
            false,
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn guard_replay_denied() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        assert_eq!(
            book.authorize(
                &policy,
                &cap,
                &[7u8; 20],
                "srct/testnet",
                50,
                &action,
                &ctx,
                false,
                false
            ),
            Decision::Allow
        );
        let (cap2, action2, ctx2) = test_cap(&policy, 1, 51);
        match book.authorize(
            &policy,
            &cap2,
            &[7u8; 20],
            "srct/testnet",
            51,
            &action2,
            &ctx2,
            false,
            false,
        ) {
            Decision::Deny(GuardError::NonceNotIncreasing { .. }) => {}
            other => panic!("expected replay deny, got {other:?}"),
        }
    }

    #[test]
    fn guard_wrong_action_denied() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, _, ctx) = test_cap(&policy, 1, 50);
        let wrong_action: Hash = [0xFFu8; 32];
        match book.authorize(
            &policy,
            &cap,
            &[7u8; 20],
            "srct/testnet",
            50,
            &wrong_action,
            &ctx,
            false,
            false,
        ) {
            Decision::Deny(GuardError::ActionMismatch) => {}
            other => panic!("expected action mismatch, got {other:?}"),
        }
    }

    #[test]
    fn guard_cross_principal_denied() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        match book.authorize(
            &policy,
            &cap,
            &[8u8; 20],
            "srct/testnet",
            50,
            &action,
            &ctx,
            false,
            false,
        ) {
            Decision::Deny(GuardError::CrossPrincipal) => {}
            other => panic!("expected cross principal deny, got {other:?}"),
        }
    }

    #[test]
    fn guard_high_risk_needs_approval() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        assert_eq!(
            book.authorize(
                &policy,
                &cap,
                &[7u8; 20],
                "srct/testnet",
                50,
                &action,
                &ctx,
                true,
                false
            ),
            Decision::NeedsApproval
        );
        assert_eq!(
            book.authorize(
                &policy,
                &cap,
                &[7u8; 20],
                "srct/testnet",
                50,
                &action,
                &ctx,
                true,
                true
            ),
            Decision::Allow
        );
    }

    #[test]
    fn guard_roundtrip_serialization() {
        let policy = test_policy();
        let bytes = policy.serialize();
        let back = InfraPolicy::deserialize(&bytes).expect("roundtrip");
        assert_eq!(policy, back);
        let (cap, _, _) = test_cap(&policy, 3, 60);
        let cbytes = cap.serialize();
        let cback = Capability::deserialize(&cbytes).expect("cap roundtrip");
        assert_eq!(cap, cback);
    }

    #[test]
    fn guard_book_roundtrip_encode() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        assert_eq!(
            book.authorize(
                &policy,
                &cap,
                &[7u8; 20],
                "srct/testnet",
                50,
                &action,
                &ctx,
                false,
                false
            ),
            Decision::Allow
        );
        let bytes = book.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        let back = GuardBook::decode(&mut r).expect("book roundtrip");
        assert_eq!(back.encode(), bytes, "decoded book re-encodes identically");
        assert_eq!(back.len(), 1);
        assert_eq!(back.state(&policy.hash()).map(|s| s.last_nonce), Some(1));
    }

    fn owned_policy() -> (crate::wallet::Wallet, InfraPolicy) {
        use crate::agent::{derive_agent_id, AgentRole};
        let owner = crate::wallet::Wallet::new_random("guard-owner");
        let addr = owner.address().unwrap();
        let policy = InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: "srct/testnet".to_string(),
            agent_id: derive_agent_id("srct/testnet", AgentRole::Machine, &addr),
            owner: addr,
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 10,
            valid_until_height: 1000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: false,
            approver: [0u8; 20],
            workload_id: [0u8; 32],
        };
        (owner, policy)
    }

    /// A high-assurance grant: the owner names a genuinely independent
    /// approver and a bound workload. Returns owner, approver, policy.
    fn owned_assured_policy() -> (crate::wallet::Wallet, crate::wallet::Wallet, InfraPolicy) {
        use crate::agent::{derive_agent_id, AgentRole};
        let owner = crate::wallet::Wallet::new_random("guard-owner");
        let approver = crate::wallet::Wallet::new_random("guard-approver");
        let addr = owner.address().unwrap();
        let policy = InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: "srct/testnet".to_string(),
            agent_id: derive_agent_id("srct/testnet", AgentRole::Machine, &addr),
            owner: addr,
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 10,
            valid_until_height: 1000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: true,
            approver: approver.address().unwrap(),
            workload_id: [5u8; 32],
        };
        (owner, approver, policy)
    }

    fn owned_cap(
        policy: &InfraPolicy,
        preimage: &[u8],
        workload: &Hash,
        height: u64,
        nonce: u64,
    ) -> Capability {
        Capability {
            policy_hash: policy.hash(),
            action_hash: derive_action_hash(preimage),
            context_hash: derive_context_hash(workload, height),
            expiry_height: height + 10,
            nonce,
            audience: [0u8; 32],
        }
    }

    #[test]
    fn signed_capability_allows_and_forgery_denies() {
        let (owner, policy) = owned_policy();
        let workload = [2u8; 32];
        let height = 50u64;
        let cap = owned_cap(&policy, b"deploy-42", &workload, height, 1);
        let signed = SignedCapability::issue(&owner, &cap).unwrap();
        signed.verify(&policy).unwrap();
        let back = SignedCapability::deserialize(&signed.serialize()).unwrap();
        assert_eq!(back, signed);

        let mut book = GuardBook::default();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                b"deploy-42",
                &workload,
                &[0u8; 32],
                false,
                None
            ),
            Decision::Allow
        );

        // Forgery: same bytes, signature from a stranger's key.
        let stranger = crate::wallet::Wallet::new_random("stranger");
        let forged = SignedCapability::issue(&stranger, &cap).unwrap();
        assert!(matches!(
            forged.verify(&policy),
            Err(GuardError::UnsignedCapability)
        ));
        let mut book2 = GuardBook::default();
        assert!(matches!(
            book2.authorize_signed(
                &policy,
                &forged,
                &policy.agent_id,
                "srct/testnet",
                height,
                b"deploy-42",
                &workload,
                &[0u8; 32],
                false,
                None
            ),
            Decision::Deny(GuardError::UnsignedCapability)
        ));

        // Tampering: valid signature over a modified action is a mismatch,
        // because the signature covers all five fields together.
        let mut tampered_cap = cap.clone();
        tampered_cap.expiry_height += 1;
        let tampered = SignedCapability {
            version: GUARD_POLICY_VERSION,
            cap: tampered_cap,
            sigs: signed.sigs.clone(),
            keys: signed.keys.clone(),
        };
        assert!(matches!(
            tampered.verify(&policy),
            Err(GuardError::UnsignedCapability)
        ));
    }

    #[test]
    fn zero_nonce_is_refused() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (mut cap, action, ctx) = test_cap(&policy, 1, 50);
        cap.nonce = 0;
        assert_eq!(
            book.authorize(
                &policy,
                &cap,
                &[7u8; 20],
                "srct/testnet",
                50,
                &action,
                &ctx,
                false,
                false
            ),
            Decision::Deny(GuardError::ZeroNonce)
        );
    }

    #[test]
    fn approval_missing_gates_but_forged_denies() {
        use crate::sig::Bundle;
        let (owner, policy) = owned_policy();
        let workload = [2u8; 32];
        let height = 50u64;
        let ctx = derive_context_hash(&workload, height);
        let preimage = b"transfer-1M";
        let cap = owned_cap(&policy, preimage, &workload, height, 1);
        let signed = SignedCapability::issue(&owner, &cap).unwrap();
        let action = derive_action_hash(preimage);

        // No approval on a high-risk call: gated, commits nothing.
        let mut book = GuardBook::default();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &workload,
                &[0u8; 32],
                true,
                None
            ),
            Decision::NeedsApproval
        );
        assert!(book.is_empty(), "a gated call commits no nonce");

        // Honest approval from the owner allows.
        let approval = GuardApproval {
            version: GUARD_POLICY_VERSION,
            policy_hash: policy.hash(),
            cap_hash: cap.signing_hash(),
            agent_id: policy.agent_id,
            action_hash: action,
            context_hash: ctx,
            expiry_height: height + 5,
            sigs: crate::l2::Auth::sigs_for(
                &owner,
                &GuardApproval {
                    version: GUARD_POLICY_VERSION,
                    policy_hash: policy.hash(),
                    cap_hash: cap.signing_hash(),
                    agent_id: policy.agent_id,
                    action_hash: action,
                    context_hash: ctx,
                    expiry_height: height + 5,
                    sigs: Bundle::default(),
                    keys: Bundle::default(),
                }
                .signing_hash(),
            )
            .unwrap(),
            keys: crate::l2::Auth::keys_for(&owner).unwrap(),
        };
        approval
            .verify(&policy, &cap, &policy.agent_id, &action, &ctx, height)
            .unwrap();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &workload,
                &[0u8; 32],
                true,
                Some(&approval)
            ),
            Decision::Allow
        );

        // Fake approval: boolean-style claim with no valid signature denies.
        let stranger = crate::wallet::Wallet::new_random("stranger");
        let fake = GuardApproval {
            version: GUARD_POLICY_VERSION,
            policy_hash: policy.hash(),
            cap_hash: cap.signing_hash(),
            agent_id: policy.agent_id,
            action_hash: action,
            context_hash: ctx,
            expiry_height: height + 5,
            sigs: crate::l2::Auth::sigs_for(&stranger, &approval.signing_hash()).unwrap(),
            keys: crate::l2::Auth::keys_for(&stranger).unwrap(),
        };
        let mut book2 = GuardBook::default();
        assert!(matches!(
            book2.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &workload,
                &[0u8; 32],
                true,
                Some(&fake)
            ),
            Decision::Deny(GuardError::BadApproval(_))
        ));

        // Reused approval on a different action denies by name.
        let other_cap = owned_cap(&policy, b"transfer-2M", &workload, height, 2);
        let other_signed = SignedCapability::issue(&owner, &other_cap).unwrap();
        let mut book3 = GuardBook::default();
        assert!(matches!(
            book3.authorize_signed(
                &policy,
                &other_signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                b"transfer-2M",
                &workload,
                &[0u8; 32],
                true,
                Some(&approval)
            ),
            Decision::Deny(GuardError::BadApproval(_))
        ));
    }

    #[test]
    fn action_swap_is_refused_at_the_boundary() {
        let (owner, policy) = owned_policy();
        let workload = [2u8; 32];
        let height = 50u64;
        // The owner approved "deploy-42"; the runtime is about to run "deploy-43".
        let cap = owned_cap(&policy, b"deploy-42", &workload, height, 1);
        let signed = SignedCapability::issue(&owner, &cap).unwrap();
        let mut book = GuardBook::default();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                b"deploy-43",
                &workload,
                &[0u8; 32],
                false,
                None
            ),
            Decision::Deny(GuardError::ActionMismatch)
        );
        assert!(book.is_empty(), "a swapped action commits no nonce");
    }

    #[test]
    fn caller_cannot_deescalate_a_high_assurance_grant() {
        use crate::sig::Bundle;
        let (owner, approver, policy) = owned_assured_policy();
        let bound = policy.workload_id;
        let height = 50u64;
        let preimage = b"deploy-42";
        let cap = owned_cap(&policy, preimage, &bound, height, 1);
        let signed = SignedCapability::issue(&owner, &cap).unwrap();

        // The caller claims low risk. The grant says otherwise: gated anyway.
        let mut book = GuardBook::default();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &bound,
                &[0u8; 32],
                false,
                None
            ),
            Decision::NeedsApproval
        );
        assert!(book.is_empty(), "a gated call commits no nonce");

        // The designated approver — independent of the owner — allows.
        let action = derive_action_hash(preimage);
        let ctx = derive_context_hash(&bound, height);
        let draft = GuardApproval {
            version: GUARD_POLICY_VERSION,
            policy_hash: policy.hash(),
            cap_hash: cap.signing_hash(),
            agent_id: policy.agent_id,
            action_hash: action,
            context_hash: ctx,
            expiry_height: height + 5,
            sigs: Bundle::default(),
            keys: Bundle::default(),
        };
        let honest = GuardApproval {
            sigs: crate::l2::Auth::sigs_for(&approver, &draft.signing_hash()).unwrap(),
            keys: crate::l2::Auth::keys_for(&approver).unwrap(),
            ..draft.clone()
        };
        honest
            .verify(&policy, &cap, &policy.agent_id, &action, &ctx, height)
            .unwrap();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &bound,
                &[0u8; 32],
                false,
                Some(&honest)
            ),
            Decision::Allow
        );

        // The owner's own signature is NOT an approval here: only the
        // designated approver counts, so owner self-approval denies.
        let owner_signed = GuardApproval {
            sigs: crate::l2::Auth::sigs_for(&owner, &draft.signing_hash()).unwrap(),
            keys: crate::l2::Auth::keys_for(&owner).unwrap(),
            ..draft
        };
        let mut book2 = GuardBook::default();
        assert!(matches!(
            book2.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &bound,
                &[0u8; 32],
                false,
                Some(&owner_signed)
            ),
            Decision::Deny(GuardError::BadApproval(_))
        ));
    }

    #[test]
    fn self_approval_grant_is_refused_at_admission() {
        let (owner, mut policy) = owned_policy();
        // Owner marks high assurance but names itself approver: misconfigured.
        policy.requires_approval = true;
        policy.approver = owner.address().unwrap();
        assert!(matches!(policy.validate(), Err(GuardError::SelfApproval)));
        let workload = [2u8; 32];
        let height = 50u64;
        let cap = owned_cap(&policy, b"deploy-42", &workload, height, 1);
        let mut book = GuardBook::default();
        let ctx = derive_context_hash(&workload, height);
        assert_eq!(
            book.authorize(
                &policy,
                &cap,
                &policy.agent_id,
                "srct/testnet",
                height,
                &derive_action_hash(b"deploy-42"),
                &ctx,
                false,
                true,
            ),
            Decision::Deny(GuardError::SelfApproval)
        );
    }

    #[test]
    fn bound_workload_ignores_a_spoofed_presented_id() {
        let (owner, _approver, policy) = owned_assured_policy();
        let bound = policy.workload_id;
        let height = 50u64;
        let preimage = b"deploy-42";
        let cap = owned_cap(&policy, preimage, &bound, height, 1);
        let signed = SignedCapability::issue(&owner, &cap).unwrap();

        // The caller presents a stranger's workload id. The grant is bound,
        // so the boundary recomputes the context from the bound id and the
        // check passes — the call gates on the missing approval instead of
        // denying on context. A presented id can neither help nor hurt.
        let mut book = GuardBook::default();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &[9u8; 32],
                &[0u8; 32],
                true,
                None
            ),
            Decision::NeedsApproval
        );

        // A capability whose context was actually built for another workload
        // denies by name.
        let mut spoofed = cap.clone();
        spoofed.context_hash = derive_context_hash(&[9u8; 32], height);
        let spoofed_signed = SignedCapability::issue(&owner, &spoofed).unwrap();
        let mut book2 = GuardBook::default();
        assert_eq!(
            book2.authorize_signed(
                &policy,
                &spoofed_signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                preimage,
                &[9u8; 32],
                &[0u8; 32],
                true,
                None
            ),
            Decision::Deny(GuardError::ContextMismatch)
        );
    }

    #[test]
    fn scoped_capability_is_refused_on_another_node() {
        let (owner, policy) = owned_policy();
        let workload = [2u8; 32];
        let height = 50u64;
        let node_a: Hash = [0xAAu8; 32];
        let node_b: Hash = [0xBBu8; 32];
        let mut cap = owned_cap(&policy, b"deploy-42", &workload, height, 1);
        cap.audience = node_a;
        let signed = SignedCapability::issue(&owner, &cap).unwrap();

        // Home node admits (no approval needed on this low-assurance grant).
        let mut book = GuardBook::default();
        assert_eq!(
            book.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                b"deploy-42",
                &workload,
                &node_a,
                false,
                None
            ),
            Decision::Allow
        );
        // The same bytes on another node deny by name and commit nothing.
        let mut book2 = GuardBook::default();
        assert_eq!(
            book2.authorize_signed(
                &policy,
                &signed,
                &policy.agent_id,
                "srct/testnet",
                height,
                b"deploy-42",
                &workload,
                &node_b,
                false,
                None
            ),
            Decision::Deny(GuardError::WrongAudience)
        );
        assert!(book2.is_empty(), "a mis-scoped capability commits no nonce");
    }

    #[test]
    fn v1_grant_bytes_decode_with_legacy_semantics() {
        // A persisted v1 grant (pre risk-model) decodes: the new fields
        // default to legacy semantics rather than bricking the registry.
        let policy = test_policy();
        let mut v2 = policy.serialize();
        assert_eq!(v2[0], GUARD_POLICY_VERSION);
        v2.truncate(v2.len() - 53);
        v2[0] = 1;
        let back = InfraPolicy::deserialize(&v2).expect("v1 grant decodes");
        assert!(!back.requires_approval);
        assert_eq!(back.approver, [0u8; 20]);
        assert_eq!(back.workload_id, [0u8; 32]);
        assert_eq!(back.owner, policy.owner);
    }
}
