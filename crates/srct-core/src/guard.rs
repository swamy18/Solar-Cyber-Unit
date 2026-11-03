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
pub const GUARD_POLICY_VERSION: u8 = 1;
/// Longest accepted network id, mirrors agent policy bound.
pub const MAX_GUARD_NETWORK_LEN: usize = 64;
/// Most grants tracked per book, cap-with-refusal like PolicyBook.
pub const DEFAULT_MAX_GUARDS: usize = 1024;
/// Longest a capability may live, in heights, from the check height.
pub const MAX_CAP_LIFETIME: u64 = 30;

/// Domain tag for the grant signing hash.
pub const DOM_GUARD_POLICY: &[u8] = b"srct/guard-policy/v1";
/// Domain tag for the capability signing hash.
pub const DOM_GUARD_CAP: &[u8] = b"srct/guard-cap/v1";
/// Domain tag for context derivation (workload || height).
pub const DOM_GUARD_CTX: &[u8] = b"srct/guard-ctx/v1";

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
            GuardError::ExpiredGrant { height, valid_until } => {
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
            GuardError::NonceNotIncreasing { nonce, last_nonce } => {
                write!(f, "nonce {nonce} is not greater than last {last_nonce}")
            }
            GuardError::HeightRewind { height, window_start } => {
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
}

impl InfraPolicy {
    pub fn hash(&self) -> Hash {
        self.signing_hash()
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_GUARD_POLICY, &[&self.serialize()])
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
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
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, GuardError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| GuardError::Malformed("version"))?;
        if version != GUARD_POLICY_VERSION {
            return Err(GuardError::UnsupportedVersion(version));
        }
        let net_len = r.u16le().map_err(|_| GuardError::Malformed("network len"))? as usize;
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
        let agent_id = r.fixed::<20>().map_err(|_| GuardError::Malformed("agent"))?;
        let owner = r.fixed::<20>().map_err(|_| GuardError::Malformed("owner"))?;
        let max_calls_per_window = r.u64le().map_err(|_| GuardError::Malformed("max calls"))?;
        let window_blocks = r.u64le().map_err(|_| GuardError::Malformed("window"))?;
        if window_blocks == 0 {
            return Err(GuardError::Malformed("window is zero"));
        }
        if max_calls_per_window == 0 {
            return Err(GuardError::Malformed("max calls is zero"));
        }
        let valid_from_height = r.u64le().map_err(|_| GuardError::Malformed("valid from"))?;
        let valid_until_height = r.u64le().map_err(|_| GuardError::Malformed("valid until"))?;
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
            1 => Some(r.fixed::<20>().map_err(|_| GuardError::Malformed("parent"))?),
            _ => return Err(GuardError::Malformed("parent link out of range")),
        };
        if r.remaining() != 0 {
            return Err(GuardError::Malformed("trailing bytes"));
        }
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
        })
    }
}

/// Short-lived exact-action capability. What the owner signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub policy_hash: Hash,
    pub action_hash: Hash,
    pub context_hash: Hash,
    pub expiry_height: u64,
    pub nonce: u64,
}

impl Capability {
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_GUARD_CAP, &[&self.serialize()])
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(112);
        w.fixed(&self.policy_hash)
            .fixed(&self.action_hash)
            .fixed(&self.context_hash)
            .u64le(self.expiry_height)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, GuardError> {
        let mut r = Reader::new(bytes);
        let policy_hash = r.fixed::<32>().map_err(|_| GuardError::Malformed("policy hash"))?;
        let action_hash = r.fixed::<32>().map_err(|_| GuardError::Malformed("action hash"))?;
        let context_hash = r.fixed::<32>().map_err(|_| GuardError::Malformed("context hash"))?;
        let expiry_height = r.u64le().map_err(|_| GuardError::Malformed("expiry"))?;
        let nonce = r.u64le().map_err(|_| GuardError::Malformed("nonce"))?;
        if r.remaining() != 0 {
            return Err(GuardError::Malformed("trailing bytes"));
        }
        Ok(Capability {
            policy_hash,
            action_hash,
            context_hash,
            expiry_height,
            nonce,
        })
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
struct GuardState {
    window_start_height: u64,
    calls_in_window: u64,
    last_nonce: u64,
    total_calls: u64,
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

impl GuardBook {
    pub fn with_capacity(max_grants: usize) -> Self {
        GuardBook {
            states: BTreeMap::new(),
            max_grants,
        }
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
        if policy.agent_id != *agent_id {
            return Err(GuardError::CrossPrincipal);
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
        if cap.nonce <= state.last_nonce && state.total_calls > 0 {
            return Err(GuardError::NonceNotIncreasing {
                nonce: cap.nonce,
                last_nonce: state.last_nonce,
            });
        }
        let (window_start, calls) = if height >= state.window_start_height + policy.window_blocks {
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
            return Err(GuardError::BookFull { cap: self.max_grants });
        }
        let next_calls = calls.checked_add(1).ok_or(GuardError::Overflow)?;
        let next_total = state.total_calls.checked_add(1).ok_or(GuardError::Overflow)?;
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
        };
        (cap, action, ctx)
    }

    #[test]
    fn guard_allow_happy_path() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        let d = book.authorize(&policy, &cap, &[7u8; 20], "srct/testnet", 50, &action, &ctx, false, false);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn guard_replay_denied() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        assert_eq!(
            book.authorize(&policy, &cap, &[7u8; 20], "srct/testnet", 50, &action, &ctx, false, false),
            Decision::Allow
        );
        let (cap2, action2, ctx2) = test_cap(&policy, 1, 51);
        match book.authorize(&policy, &cap2, &[7u8; 20], "srct/testnet", 51, &action2, &ctx2, false, false) {
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
        match book.authorize(&policy, &cap, &[7u8; 20], "srct/testnet", 50, &wrong_action, &ctx, false, false) {
            Decision::Deny(GuardError::ActionMismatch) => {}
            other => panic!("expected action mismatch, got {other:?}"),
        }
    }

    #[test]
    fn guard_cross_principal_denied() {
        let policy = test_policy();
        let mut book = GuardBook::default();
        let (cap, action, ctx) = test_cap(&policy, 1, 50);
        match book.authorize(&policy, &cap, &[8u8; 20], "srct/testnet", 50, &action, &ctx, false, false) {
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
            book.authorize(&policy, &cap, &[7u8; 20], "srct/testnet", 50, &action, &ctx, true, false),
            Decision::NeedsApproval
        );
        assert_eq!(
            book.authorize(&policy, &cap, &[7u8; 20], "srct/testnet", 50, &action, &ctx, true, true),
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
}
