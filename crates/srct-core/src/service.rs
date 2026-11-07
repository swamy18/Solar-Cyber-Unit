//! The Solar Cyber Unit service/payment bridge (roadmap items 2, 6, 5, 7, 8).
//!
//! The bridge is the protocol-neutral layer that turns the pieces shipped by
//! Decision 16 and items 11/12 into one **coherent, testable flow**:
//!
//! ```text
//! Agent ──(1) PaymentRequest──▶ SpendPolicy ──(2) Authorization
//!        ──(3) MachinePayment──▶ Service ──(4) ServiceReceipt
//! ```
//!
//! ```text
//! AI Agent → Service/API → SRCT Payment → Service Execution → Cryptographic Receipt
//! ```
//!
//! It is **not** a Stripe clone and not a second payment system: every step
//! uses the existing primitives — `agent.rs` for identity and policy,
//! `payment.rs` for the machine payment, `receipt.rs` for the receipt — and
//! the coin itself still moves through the ordinary §1 UTXO transaction (or
//! the L2 task escrow). This module adds the glue:
//!
//! - [`derive_service_id`] — deterministic, network-bound **service
//!   identity** derived from a provider address and a name;
//! - [`PaymentRequest`] — the payer-signed intent naming the service, the
//!   recipient, and the **maximum authorized amount**;
//! - [`authorize_request`] — the only path from a request to an
//!   [`Authorization`]; it delegates every budget rule to `PolicyBook`, so
//!   there is exactly one authorization engine;
//! - [`verify_session`] — offline verification of whichever stages exist,
//!   each bound to the stage before it;
//! - [`aggregate_payments`] — batching many machine payments into one
//!   settlement's worth of outputs (the safe, consensus-free micropayment
//!   primitive: one `GAS_TX_BASE` for N payments);
//! - [`parse_amount_sat`] / [`format_amount_sat`] — exact integer
//!   denomination handling with **no floating point anywhere**, so machines
//!   quote, sign and verify the same number a human reads.
//!
//! # Fail-closed rules (locked)
//!
//! - a machine/service payer's request must name its governing policy
//!   (zero policy hash only for `Human` payers);
//! - a machine payment presented inside a session **must** present its
//!   authorization: no privileged path skips the policy;
//! - a receipt without a payment, or a receipt/payment that disagrees with
//!   the request on payer, recipient, service, amount or network, is refused
//!   by name — a forged service response can never authorize payment,
//!   because `authorize_request` does not take a receipt as input at all;
//! - `verify_session` verifies **only** what it is given and refuses
//!   contradictory stage orderings; nothing it says overrides a refusal by a
//!   lower layer.

use crate::agent::{
    derive_agent_id, verify_authorization, AgentId, AgentRole, Authorization, AuthorizationRequest,
    PolicyBook, PolicyError, SpendPolicy,
};
use crate::credit::CreditGate;
use crate::hash::{sha256_dom, Address, Hash};
use crate::payment::{MachinePayment, PaymentError};
use crate::receipt::ServiceReceipt;
use crate::ser::{Reader, Writer};
use crate::sig::Bundle;
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use std::fmt;

/// Request encoding version. A future format MUST use a new value.
pub const REQUEST_VERSION: u8 = 2;
/// Domain tag for a derived service identity.
pub const DOM_SERVICE_ID: &[u8] = b"srct/service-id/v1";
/// Domain tag for the payment-request signing hash.
pub const DOM_SERVICE_REQUEST: &[u8] = b"srct/service-request/v1";
/// Domain tag for a service result hash.
pub const DOM_SERVICE_RESULT: &[u8] = b"srct/service-result/v1";
/// Longest accepted network id (bytes).
pub const MAX_REQUEST_NETWORK_ID_LEN: usize = 64;
/// Decimal places in one SRCT (satoshis per SRCT is 10^9).
pub const SAT_DECIMALS: u32 = 9;

/// Why a bridge step was refused. Named and `PartialEq`, so tests can assert
/// the exact clause. The inner families are the ones the lower layers own —
/// this module never reinterprets them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A payment/request-level refusal (structure, network, signature,
    /// expiry, policy presence).
    Payment(PaymentError),
    /// A receipt-level refusal.
    Receipt(crate::receipt::ReceiptError),
    /// A policy-engine refusal (budget, nonce, allow lists).
    Policy(PolicyError),
    /// Two stages of the session disagree.
    Binding(&'static str),
    /// A payment was otherwise valid but the payer's credit line could not
    /// cover it: `free + unencumbered position headroom` was less than
    /// `amount_sat`. Distinct from a policy refusal so a caller can surface
    /// "not enough credit" specifically.
    InsufficientCredit(crate::error::Error),
    /// An amount string is not an exact decimal number of satoshis.
    BadAmount(&'static str),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Payment(e) => write!(f, "payment layer: {e}"),
            SessionError::Receipt(e) => write!(f, "receipt layer: {e}"),
            SessionError::Policy(e) => write!(f, "policy layer: {e}"),
            SessionError::Binding(w) => write!(f, "session binding failed: {w}"),
            SessionError::InsufficientCredit(e) => {
                write!(f, "payer credit line insufficient: {e}")
            }
            SessionError::BadAmount(w) => write!(f, "bad amount: {w}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<PaymentError> for SessionError {
    fn from(e: PaymentError) -> Self {
        SessionError::Payment(e)
    }
}
impl From<crate::receipt::ReceiptError> for SessionError {
    fn from(e: crate::receipt::ReceiptError) -> Self {
        SessionError::Receipt(e)
    }
}
impl From<PolicyError> for SessionError {
    fn from(e: PolicyError) -> Self {
        SessionError::Policy(e)
    }
}
impl From<crate::error::Error> for SessionError {
    fn from(e: crate::error::Error) -> Self {
        SessionError::Payment(PaymentError::from(e))
    }
}

/// Deterministic, network-bound **service identity**:
/// `SHA256("srct/service-id/v1" ‖ network_id ‖ provider ‖ name)[..32]`.
///
/// The provider's address is inside the derivation, so a service id cannot
/// claim another provider's payout address, and the network is inside, so a
/// `mini` service id is not a `testnet` service id. The result doubles as the
/// tag a `SpendPolicy` puts on its service allow list.
pub fn derive_service_id(network_id: &str, provider: &Address, name: &[u8]) -> [u8; 32] {
    sha256_dom(DOM_SERVICE_ID, &[network_id.as_bytes(), provider, name])
}

/// Hash of a service's raw result bytes. This is what a receipt carries as
/// `result_hash`, so "what was delivered" is committed without transporting
/// the result itself.
pub fn result_hash_of(result_bytes: &[u8]) -> Hash {
    sha256_dom(DOM_SERVICE_RESULT, &[result_bytes])
}

/// A payer-signed intent to buy a named service from a named provider, up to
/// a maximum authorized amount. The bridge's entry point: everything after
/// this is verification and bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequest {
    pub version: u8,
    /// Network binding, ≤ [`MAX_REQUEST_NETWORK_ID_LEN`] bytes.
    pub network_id: String,
    /// Payer's ordinary §1 address; the signature must match it.
    pub payer: Address,
    /// Who is paying: human, machine or service.
    pub payer_type: AgentRole,
    /// `derive_agent_id(network_id, payer_type, payer)`.
    pub agent_id: AgentId,
    /// Which service is being bought (see [`derive_service_id`]).
    pub service_id: [u8; 32],
    /// Provider payout address.
    pub recipient: Address,
    /// The requested service's price ceiling: the maximum authorized amount.
    pub max_amount_sat: u64,
    /// Last height at which the request is acceptable (exclusive).
    pub expires_at_height: u64,
    /// Governing `SpendPolicy::hash()`. Zero only for human payers.
    pub policy_hash: Hash,
    /// The delegation chain this request is spent under, oldest first, ending at
    /// the policy named by `policy_hash`. Empty for a root policy.
    ///
    /// Signed, and therefore un-widenable after the fact: a request that names a
    /// delegated identity claims authority from every link above it, so the
    /// links are part of what the requester signs.
    pub chain: Vec<SpendPolicy>,
    /// Payer keys (hybrid bundle).
    pub keys: Bundle,
    /// Payer signatures over [`PaymentRequest::signing_hash`].
    pub sigs: Bundle,
}

impl PaymentRequest {
    /// Canonical body: every field, no signatures.
    pub fn body(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.payer)
            .u8(self.payer_type.as_u8())
            .fixed(&self.agent_id)
            .fixed(&self.service_id)
            .fixed(&self.recipient)
            .u64le(self.max_amount_sat)
            .u64le(self.expires_at_height)
            .fixed(&self.policy_hash);
        // The chain lives inside the signed body for the same reason it lives
        // inside a payment's: it is the authority the spend exercises.
        w.u16le(self.chain.len() as u16);
        for policy in &self.chain {
            let bytes = policy.serialize();
            w.u32le(bytes.len() as u32).raw(&bytes);
        }
        w.into_vec()
    }

    /// Domain-separated hash of the body; doubles as the request id.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_SERVICE_REQUEST, &[&self.body()])
    }

    /// The deterministic request/intent id.
    pub fn request_id(&self) -> Hash {
        self.signing_hash()
    }

    /// Canonical wire encoding: `body ‖ keys ‖ sigs`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.keys.to_bytes());
        out.extend_from_slice(&self.sigs.to_bytes());
        out
    }

    /// Bounded decode; the exact inverse of [`PaymentRequest::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PaymentError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| PaymentError::Malformed("version"))?;
        if version != REQUEST_VERSION {
            return Err(PaymentError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| PaymentError::Malformed("network len"))? as usize;
        if net_len == 0 {
            return Err(PaymentError::EmptyNetworkId);
        }
        if net_len > MAX_REQUEST_NETWORK_ID_LEN {
            return Err(PaymentError::NetworkIdTooLong(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| PaymentError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| PaymentError::Malformed("network id is not utf-8"))?
            .to_string();
        let payer = r
            .fixed::<20>()
            .map_err(|_| PaymentError::Malformed("payer"))?;
        let payer_type_raw = r.u8().map_err(|_| PaymentError::Malformed("payer type"))?;
        let payer_type = AgentRole::from_u8(payer_type_raw)
            .ok_or(PaymentError::Malformed("payer type out of range"))?;
        let agent_id = r
            .fixed::<20>()
            .map_err(|_| PaymentError::Malformed("agent id"))?;
        let service_id = r
            .fixed::<32>()
            .map_err(|_| PaymentError::Malformed("service id"))?;
        let recipient = r
            .fixed::<20>()
            .map_err(|_| PaymentError::Malformed("recipient"))?;
        let max_amount_sat = r
            .u64le()
            .map_err(|_| PaymentError::Malformed("max amount"))?;
        let expires_at_height = r
            .u64le()
            .map_err(|_| PaymentError::Malformed("expires_at"))?;
        let policy_hash = r
            .fixed::<32>()
            .map_err(|_| PaymentError::Malformed("policy hash"))?;
        let chain = decode_request_chain(&mut r)?;
        let keys = Bundle::from_reader(&mut r).map_err(PaymentError::from)?;
        let sigs = Bundle::from_reader(&mut r).map_err(PaymentError::from)?;
        r.expect_end()
            .map_err(|_| PaymentError::Malformed("trailing bytes"))?;

        let request = PaymentRequest {
            version,
            network_id,
            payer,
            payer_type,
            agent_id,
            service_id,
            recipient,
            max_amount_sat,
            expires_at_height,
            policy_hash,
            chain,
            keys,
            sigs,
        };
        request.validate()?;
        Ok(request)
    }

    /// Structural self-consistency (no signature work).
    pub fn validate(&self) -> Result<(), PaymentError> {
        if self.version != REQUEST_VERSION {
            return Err(PaymentError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() {
            return Err(PaymentError::EmptyNetworkId);
        }
        if self.network_id.len() > MAX_REQUEST_NETWORK_ID_LEN {
            return Err(PaymentError::NetworkIdTooLong(self.network_id.len()));
        }
        if self.max_amount_sat == 0 {
            return Err(PaymentError::ZeroAmount);
        }
        if self.expires_at_height == 0 {
            return Err(PaymentError::NoExpiry);
        }
        let expected = derive_agent_id(&self.network_id, self.payer_type, &self.payer);
        if self.chain.is_empty() {
            if expected != self.agent_id {
                return Err(PaymentError::IdentityMismatch);
            }
        } else {
            // A delegated request proves its identity from the chain rather than
            // from the payer address, so a caller cannot claim a sub-agent id
            // without the ancestry that derives it.
            crate::delegation::assert_chain(&self.chain.iter().collect::<Vec<_>>())
                .map_err(|e| PaymentError::ChainRefused(e.to_string()))?;
            if self.chain.len() > crate::delegation::MAX_DELEGATION_DEPTH {
                return Err(PaymentError::ChainRefused(
                    "delegation chain is deeper than the cap".to_string(),
                ));
            }
            if self.chain[0].parent_agent_id.is_some() {
                return Err(PaymentError::ChainRefused(
                    "delegation chain must start at a root policy".to_string(),
                ));
            }
            let leaf = self.chain.last().ok_or(PaymentError::IdentityMismatch)?;
            if leaf.agent_id != self.agent_id || leaf.owner != self.payer {
                return Err(PaymentError::IdentityMismatch);
            }
            if leaf.network_id != self.network_id {
                return Err(PaymentError::WrongNetwork {
                    expected: leaf.network_id.clone(),
                    got: self.network_id.clone(),
                });
            }
            if leaf.hash() != self.policy_hash {
                return Err(PaymentError::NotLinkedToAuthorization("policy hash"));
            }
        }
        if self.payer_type != AgentRole::Human && self.policy_hash == [0u8; 32] {
            return Err(PaymentError::PolicyRequired);
        }
        Ok(())
    }

    /// Offline verification: structure, network, expiry at `height`,
    /// payer-address binding and every signature component.
    pub fn verify(&self, network_id: &str, height: u64) -> Result<(), PaymentError> {
        if self.network_id != network_id {
            return Err(PaymentError::WrongNetwork {
                expected: self.network_id.clone(),
                got: network_id.to_string(),
            });
        }
        self.validate()?;
        if height >= self.expires_at_height {
            return Err(PaymentError::Expired {
                expires_at: self.expires_at_height,
                height,
            });
        }
        let signer = self.keys.address()?;
        if signer != self.payer {
            return Err(PaymentError::SignerNotPayer {
                signer,
                payer: self.payer,
            });
        }
        let msg = self.signing_hash();
        crate::sig::verify_bundle(&self.sigs, &self.keys, &msg)?;
        Ok(())
    }
}

/// Everything but the key that builds a payment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSpec {
    pub network_id: String,
    pub payer_type: AgentRole,
    /// Which service is being bought (see [`derive_service_id`]).
    pub service_id: [u8; 32],
    pub recipient: Address,
    /// The price ceiling: the maximum authorized amount.
    pub max_amount_sat: u64,
    pub expires_at_height: u64,
    /// Governing `SpendPolicy::hash()`; zero only for human payers.
    pub policy_hash: Hash,
}

/// A delegation chain is decoded with the same bounds as any other policy list:
/// the declared count is checked against the cap *and* the bytes actually
/// present, so a lying count cannot reserve a megabyte.
fn decode_request_chain(r: &mut Reader<'_>) -> Result<Vec<SpendPolicy>, PaymentError> {
    let count = r
        .u16le()
        .map_err(|_| PaymentError::Malformed("delegation chain count"))? as usize;
    if count > crate::delegation::MAX_DELEGATION_DEPTH {
        return Err(PaymentError::ChainRefused(
            "delegation chain is deeper than the cap".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(count.min(8));
    for _ in 0..count {
        let len = r
            .u32le()
            .map_err(|_| PaymentError::Malformed("delegation policy length"))?
            as usize;
        if len > crate::agent::MAX_NETWORK_ID_LEN * 2 + 1_024 {
            return Err(PaymentError::Malformed("delegation policy too large"));
        }
        let bytes = r
            .fixed_slice(len)
            .map_err(|_| PaymentError::Malformed("delegation policy bytes"))?;
        out.push(
            SpendPolicy::deserialize(bytes)
                .map_err(|e| PaymentError::ChainRefused(e.to_string()))?,
        );
    }
    Ok(out)
}

/// Build and sign a payment request with the payer's wallet. The wallet is
/// passed in and never stored — the bridge holds no key material.
///
/// `chain` is the delegation ancestry the request is spent under, oldest first.
/// Empty for a root policy, which is the ordinary case and the only one version
/// 1 could express.
pub fn build_signed_request(
    wallet: &Wallet,
    spec: RequestSpec,
    chain: &[SpendPolicy],
) -> Result<PaymentRequest, PaymentError> {
    let payer = wallet.address()?;
    // A delegated request is identified by the leaf of its chain, not by the
    // payer's address, so the two paths diverge here and nowhere else.
    let agent_id = match chain.last() {
        Some(leaf) => leaf.agent_id,
        None => derive_agent_id(&spec.network_id, spec.payer_type, &payer),
    };
    let mut request = PaymentRequest {
        version: REQUEST_VERSION,
        network_id: spec.network_id.clone(),
        payer,
        payer_type: spec.payer_type,
        agent_id,
        service_id: spec.service_id,
        recipient: spec.recipient,
        max_amount_sat: spec.max_amount_sat,
        expires_at_height: spec.expires_at_height,
        policy_hash: spec.policy_hash,
        chain: chain.to_vec(),
        keys: crate::l2::Auth::keys_for(wallet)?,
        sigs: Bundle::default(),
    };
    if spec.payer_type != AgentRole::Human && spec.policy_hash == [0u8; 32] {
        return Err(PaymentError::PolicyRequired);
    }
    request.validate()?;
    let msg = request.signing_hash();
    request.sigs = crate::l2::Auth::sigs_for(wallet, &msg)?;
    request.verify(&spec.network_id, spec.expires_at_height.saturating_sub(1))?;
    Ok(request)
}

/// The **only** path from a payment request to an authorization.
///
/// Every budget rule stays inside `PolicyBook` — per-transaction limit,
/// tumbling cumulative window, recipient/service allow lists, validity
/// window, strictly increasing nonce, revocation. This function adds only
/// the bridge-specific bindings: the request must self-verify (payer-signed,
/// unexpired, network-bound, identity-re-derived) and must name exactly the
/// policy presented. A receipt or any service response is **not** an input
/// here, by type: a forged service response cannot authorize payment.
pub fn authorize_request(
    book: &mut PolicyBook,
    policy: &SpendPolicy,
    network_id: &str,
    request: &PaymentRequest,
    height: u64,
    nonce: u64,
) -> Result<Authorization, SessionError> {
    request.verify(network_id, height)?;
    if request.policy_hash != policy.hash() {
        return Err(SessionError::Binding("request names a different policy"));
    }
    let areq = AuthorizationRequest {
        agent_id: request.agent_id,
        recipient: request.recipient,
        amount_sat: request.max_amount_sat,
        service: Some(request.service_id),
        height,
        nonce,
    };
    Ok(book.authorize(policy, network_id, &areq)?)
}

/// The delegation-aware sibling of [`authorize_request`].
///
/// This is the entry point a *chained* request uses, and the reason it is a
/// separate function is that the two paths check different things: a root
/// request's identity is re-derived from the payer, while a chained request's
/// identity is proved by its ancestry. Handing both to one function would mean
/// the authorization path silently accepts whichever of the two proofs the
/// caller found easier to forge.
///
/// The chain is validated twice, by two different owners, and both are needed:
/// `assert_chain` proves the bytes narrow all the way to a root, and
/// `DelegationBook` proves the links are the ones this node recorded — so a
/// caller cannot manufacture a lineage by presenting policies nobody linked.
#[allow(clippy::too_many_arguments)]
pub fn authorize_request_with_chain(
    book: &mut PolicyBook,
    delegations: &mut crate::delegation::DelegationBook,
    policy: &SpendPolicy,
    chain: &[SpendPolicy],
    network_id: &str,
    request: &PaymentRequest,
    height: u64,
    nonce: u64,
) -> Result<Authorization, SessionError> {
    request.verify(network_id, height)?;
    if request.policy_hash != policy.hash() {
        return Err(SessionError::Binding("request names a different policy"));
    }
    // The chain the request carries is the chain it is authorized under: the
    // request's bytes and the presented chain are the same ancestry.
    if request.chain.len() != chain.len() {
        return Err(SessionError::Binding(
            "the request carries a delegation chain that does not match the one presented",
        ));
    }
    for (a, b) in request.chain.iter().zip(chain.iter()) {
        if a.hash() != b.hash() {
            return Err(SessionError::Binding(
                "the request carries a delegation chain that does not match the one presented",
            ));
        }
    }
    // A root request and a chained request are different claims; neither may be
    // smuggled through the other's entry point.
    if policy.parent_agent_id.is_some() {
        if chain.is_empty() || chain[0].parent_agent_id.is_some() {
            return Err(SessionError::Binding(
                "a delegated policy must be presented with a whole chain that starts at its root",
            ));
        }
        // Record every link before the spend rule runs, so the authorization
        // issued is under a lineage the node can later reconstruct and revoke.
        // Re-presenting a link that is already recorded is the same lineage, not
        // a second one, so it is idempotent rather than a refusal.
        for window in chain.windows(2) {
            let (parent, child) = (&window[0], &window[1]);
            if delegations.parent_of(child) != Some(parent.hash()) {
                delegations.link(parent, child).map_err(|e| {
                    SessionError::Payment(PaymentError::ChainRefused(e.to_string()))
                })?;
            }
        }
        delegations
            .record_root(&chain[0])
            .map_err(|e| SessionError::Payment(PaymentError::ChainRefused(e.to_string())))?;
        // The spend rule runs on the leaf, exactly as `authorize_request` runs
        // it on a root policy: one engine, one set of budget rules, reached
        // through the narrowing rule instead of through identity derivation.
        let areq = AuthorizationRequest {
            agent_id: request.agent_id,
            recipient: request.recipient,
            amount_sat: request.max_amount_sat,
            service: Some(request.service_id),
            height,
            nonce,
        };
        let refs: Vec<&SpendPolicy> = chain.iter().collect();
        crate::delegation::authorize_with_chain(book, &refs, network_id, &areq)
            .map_err(|e| SessionError::Payment(PaymentError::ChainRefused(e.to_string())))
    } else {
        if !chain.is_empty() {
            return Err(SessionError::Binding(
                "a root policy cannot be presented with a delegation chain",
            ));
        }
        authorize_request(book, policy, network_id, request, height, nonce)
    }
}

/// The **only** admission for a machine payment into a node's record.
///
/// This closes the gap the seam had. `MachinePayment::verify` proves the payer
/// signed *a* payment, and `PaymentTracker::accept` refuses a replay — but
/// neither consults the policy engine, so a payment that *named* a policy hash
/// nobody ever authorized under was accepted on the payer's own signature
/// alone. A policy hash in a payment was, until now, a decorative field.
///
/// Four things must hold, and they are the four that make the hash mean what it
/// says:
///
/// 1. the payment is structurally sound, network-bound, unexpired and signed by
///    the payer it names (`MachinePayment::verify`);
/// 2. the policy it names is the one it is being admitted under, that policy is
///    for this network, and it is **known to the engine** — the engine has
///    issued at least one authorization under it, which is what makes the hash a
///    claim the engine can check rather than a string the payer chose;
/// 3. that policy is still live at `height`;
/// 4. the authorization is the **owner's** (`verify_authorization`), and the
///    payment is exactly what it granted (`MachinePayment::linked_to`).
///
/// What this deliberately does **not** do: re-run the budget rules. They were
/// checked, once, by the engine when the authorization was issued, and
/// re-running them here with a state the authorization already advanced would
/// refuse every legitimate payment. The budget rule has one home; this is the
/// admission check, not a second engine.
///
/// Revocation is also not here, and for a structural reason: `revoked` is inside
/// the canonical encoding, so a revoked policy is a **different hash** from the
/// one the engine issued under. A gate handed a revoked variant sees a policy the
/// engine has never issued under and refuses it on (2) — the right outcome for
/// the wrong reason, and the original authorization is left standing. Killing
/// that one is the record-keeper's job, because only the record-keeper knows
/// which hash a revocation statement was aimed at; the node keeps a revocation
/// set keyed by original hash, populated from an owner-signed revocation, and
/// checks it before this gate runs.
///
/// Nothing is mutated — the engine is borrowed read-only. Committing the
/// accounting for the *spend* is the caller's job, through the same
/// `PolicyBook` that issued the grant.
pub fn admit_payment(
    book: &PolicyBook,
    policy: &SpendPolicy,
    payment: &MachinePayment,
    presented: AuthPresentation<'_>,
    network_id: &str,
    height: u64,
    gate: &mut dyn CreditGate,
) -> Result<crate::credit::Reservation, SessionError> {
    // 1. the payment proves itself.
    payment.verify(network_id, height)?;

    // 2. it names the policy it is admitted under, for this network, and that
    //    policy is one the engine has actually issued under.
    if payment.policy_hash != policy.hash() {
        return Err(SessionError::Binding("payment names another policy"));
    }
    if policy.network_id != network_id {
        return Err(SessionError::Binding("policy is for another network"));
    }
    if book.state(&policy.hash()).is_none() {
        return Err(SessionError::Binding(
            "policy is unknown to the engine: no authorization was issued under it",
        ));
    }

    // 3. the policy is live at this height.
    //
    // The revoked flag is checked even though revocation also changes the
    // hash: a gate handed a revoked variant refuses it here by name rather
    // than on (2) "for the wrong reason", and a caller holding a stale
    // object cannot lean on the record-keeper having forgotten the state
    // yet. Killing the original authorization remains the record-keeper's
    // job (node `revoked_policies` set, worker authority book), because
    // only the record-keeper knows which hash a revocation aimed at — this
    // check is the fail-closed backstop, not the mechanism.
    if policy.revoked {
        return Err(SessionError::Policy(PolicyError::PolicyRevoked));
    }
    if height < policy.not_before_height {
        return Err(SessionError::Policy(PolicyError::NotYetValid {
            not_before: policy.not_before_height,
            height,
        }));
    }
    if height >= policy.expires_at_height {
        return Err(SessionError::Policy(PolicyError::PolicyExpired {
            expires_at: policy.expires_at_height,
            height,
        }));
    }

    // 4. the grant is authentic and this payment is what it granted.
    verify_authorization(presented.sigs, presented.keys, presented.auth)?;
    if presented.auth.policy_hash != payment.policy_hash {
        return Err(SessionError::Binding("authorization names another policy"));
    }
    payment.linked_to(presented.auth)?;

    // 5. credit. Admission only goes as far as the policy layer; funding the
    //    payment (consuming real coin) is a later step (roadmap item 10/§19.4).
    //    But a policy that authorizes a spend must still be backed by *something*
    //    that will pay it, and that is the credit book's job: confirm the payer's
    //    free balance or live position can cover `amount + fee`, and reserve it
    //    so the later settlement cannot overdraw. A book that has wired nothing
    //    in gets `NoCreditGate` and this step is a no-op — pre-credit behavior.
    let total = payment.total_sat().ok_or(SessionError::InsufficientCredit(
        crate::error::Error::Malformed("payment amount + fee overflows"),
    ))?;
    let reservation = gate
        .reserve(&payment.payer, total, height)
        .map_err(SessionError::InsufficientCredit)?;

    Ok(reservation)
}

/// Map a portable-layer refusal onto the session error: policy clauses keep
/// their names, everything else (expiry, lifetime, transaction mismatch,
/// delegation) is a binding refusal with the message intact.
fn portable_refused(e: crate::portable::PortableError) -> SessionError {
    match e {
        crate::portable::PortableError::Policy(p) => SessionError::Policy(p),
        crate::portable::PortableError::Payment(p) => SessionError::Payment(p),
        other => SessionError::Payment(PaymentError::ChainRefused(other.to_string())),
    }
}

/// The **enforced** admission: a machine payment plus the short-lived,
/// exact-transaction binding that authorizes it.
///
/// This is what turns the advisory approval into a rule. `admit_payment`
/// trusts the authorization the caller presents; this gate additionally
/// requires a [`crate::portable::BoundAuthorization`] for the exact payment
/// hash with a live short expiry, verified here before anything else runs. A
/// stolen authorization re-aimed at another transaction, or replayed past its
/// window, is refused by name and nothing is reserved.
///
/// The node wires this into `payment_submit` (and both x402 money paths) for
/// policy-governed payments; human payments keep the existing path.
pub fn admit_bound_payment(
    book: &PolicyBook,
    policy: &SpendPolicy,
    payment: &MachinePayment,
    bound: &crate::portable::BoundAuthorization,
    network_id: &str,
    height: u64,
    gate: &mut dyn CreditGate,
) -> Result<crate::credit::Reservation, SessionError> {
    // 0. the binding proves the grant, the expiry and the exact transaction.
    bound
        .verify(policy, payment, height)
        .map_err(portable_refused)?;
    // 1..5. the standard admission under the same grant.
    let presented = AuthPresentation {
        auth: &bound.auth,
        sigs: &bound.auth_sigs,
        keys: &bound.auth_keys,
    };
    admit_payment(book, policy, payment, presented, network_id, height, gate)
}
/// A granted authorization plus the signature material that proves the owner
/// issued it, as presented by a session verifier.
#[derive(Debug, Clone, Copy)]
pub struct AuthPresentation<'a> {
    pub auth: &'a Authorization,
    pub sigs: &'a Bundle,
    pub keys: &'a Bundle,
}

/// The stages of a bridge session. Every stage after the request is
/// optional — whatever exists must verify and must bind to the stage before
/// it. Stage *order* is enforced: a receipt requires a payment, and a
/// machine payment (policy-governed request) requires its authorization.
#[derive(Debug, Clone, Copy)]
pub struct Session<'a> {
    pub request: &'a PaymentRequest,
    pub authorization: Option<AuthPresentation<'a>>,
    pub payment: Option<&'a MachinePayment>,
    pub receipt: Option<&'a ServiceReceipt>,
    /// The grant the authorization names. Without it the authorization stage
    /// can check the owner's signature but not whether the grant is live —
    /// and a stale grant would verify. Pass the policy the node issued
    /// under; verification refuses revoked and out-of-window grants.
    pub policy: Option<&'a crate::agent::SpendPolicy>,
}

impl<'a> Session<'a> {
    pub fn new(request: &'a PaymentRequest) -> Self {
        Session {
            request,
            authorization: None,
            payment: None,
            receipt: None,
            policy: None,
        }
    }

    pub fn with_policy(mut self, policy: &'a crate::agent::SpendPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_authorization(
        mut self,
        auth: &'a Authorization,
        sigs: &'a Bundle,
        keys: &'a Bundle,
    ) -> Self {
        self.authorization = Some(AuthPresentation { auth, sigs, keys });
        self
    }

    pub fn with_payment(mut self, payment: &'a MachinePayment) -> Self {
        self.payment = Some(payment);
        self
    }

    pub fn with_receipt(mut self, receipt: &'a ServiceReceipt) -> Self {
        self.receipt = Some(receipt);
        self
    }

    /// Offline verification of the whole chain, at `height`, on
    /// `network_id`. Every refusal is a named [`SessionError`]; nothing is
    /// mutated because nothing is owned.
    pub fn verify(&self, network_id: &str, height: u64) -> Result<(), SessionError> {
        self.request.verify(network_id, height)?;

        // Authorization stage: offline-verifiable and bound to the request.
        // With the grant attached, liveness is checked too — a stale grant
        // verifies a signature but must not verify a session.
        if let Some(presented) = self.authorization {
            if let Some(policy) = self.policy {
                crate::agent::verify_authorization_for_policy(
                    presented.sigs,
                    presented.keys,
                    presented.auth,
                    policy,
                    height,
                )
                .map_err(SessionError::Policy)?;
            } else {
                verify_authorization(presented.sigs, presented.keys, presented.auth)?;
            }
            let auth = presented.auth;
            if auth.owner != self.request.payer {
                return Err(SessionError::Binding("authorization owner"));
            }
            if auth.agent_id != self.request.agent_id {
                return Err(SessionError::Binding("authorization agent"));
            }
            if auth.recipient != self.request.recipient {
                return Err(SessionError::Binding("authorization recipient"));
            }
            if auth.amount_sat != self.request.max_amount_sat {
                return Err(SessionError::Binding("authorization amount"));
            }
            if auth.service != Some(self.request.service_id) {
                return Err(SessionError::Binding("authorization service"));
            }
            if auth.policy_hash != self.request.policy_hash {
                return Err(SessionError::Binding("authorization policy"));
            }
        }

        // Payment stage.
        if let Some(payment) = self.payment {
            payment.verify(network_id, height)?;
            if payment.reference != self.request.request_id() {
                return Err(SessionError::Binding("payment reference"));
            }
            if payment.payer != self.request.payer
                || payment.agent_id != self.request.agent_id
                || payment.recipient != self.request.recipient
                || payment.amount_sat != self.request.max_amount_sat
                || payment.service != Some(self.request.service_id)
                || payment.policy_hash != self.request.policy_hash
            {
                return Err(SessionError::Binding("payment disagrees with request"));
            }
            match self.authorization {
                Some(presented) => payment.linked_to(presented.auth)?,
                None => {
                    // No privileged path: a policy-governed request may not
                    // be settled by a payment that never showed its grant.
                    if self.request.policy_hash != [0u8; 32] {
                        return Err(SessionError::Binding(
                            "machine payment presented without its authorization",
                        ));
                    }
                }
            }
        }

        // Receipt stage: requires a payment and must agree with it.
        if let Some(receipt) = self.receipt {
            let payment = self
                .payment
                .ok_or(SessionError::Binding("receipt without payment"))?;
            receipt.verify(network_id)?;
            receipt.verify_binding(payment)?;
            if receipt.request_id != self.request.request_id() {
                return Err(SessionError::Binding("receipt request"));
            }
        }

        Ok(())
    }
}

/// One settlement's worth of payments: per-recipient outputs with the shared
/// payer, so N machine payments ride one L1 transaction and pay `GAS_TX_BASE`
/// once instead of N times. This is the safe micropayment primitive — it
/// changes no consensus rule, it just stops paying the base fee N times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentBatch {
    /// Every payment must come from this payer (one signer, one transaction).
    pub payer: Address,
    /// Payment ids, in input order.
    pub payment_ids: Vec<Hash>,
    /// Net amounts per distinct recipient, ordered by recipient address
    /// (deterministic between two nodes batching the same set).
    pub outputs: Vec<(Address, u64)>,
    pub total_amount_sat: u64,
    /// Sum of the payments' declared fees; the transaction's actual fee is
    /// set by whoever builds it.
    pub declared_fee_sat: u64,
}

impl PaymentBatch {
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Gas this settlement's transaction would consume, given how many
    /// inputs fund it. Uses the existing `GAS_TX_*` constants unchanged.
    /// `None` on overflow: the caller prices, never the saturating figure,
    /// so a clamped gas total cannot masquerade as a cheap settlement.
    pub fn gas_used(&self, input_count: usize) -> Option<u64> {
        crate::tx::GAS_TX_BASE
            .checked_add(crate::tx::GAS_PER_INPUT.checked_mul(input_count as u64)?)
            .and_then(|g| {
                g.checked_add(crate::tx::GAS_PER_OUTPUT.checked_mul(self.output_count() as u64)?)
            })
    }

    /// The base-fee obligation for this settlement at `base_fee` sat/gas.
    /// `None` when the gas total or the fee product overflows.
    pub fn required_fee(&self, base_fee: u64, input_count: usize) -> Option<u64> {
        crate::fees::checked_required_fee(base_fee, self.gas_used(input_count)?).ok()
    }
}

/// Verify a set of machine payments and merge them into one settlement.
/// Refuses anything a single payment would refuse, plus payments from
/// different payers (they could not share one signed transaction) and any
/// arithmetic overflow.
pub fn aggregate_payments(
    payments: &[MachinePayment],
    network_id: &str,
    height: u64,
) -> Result<PaymentBatch, PaymentError> {
    if payments.is_empty() {
        return Err(PaymentError::Malformed("empty payment batch"));
    }
    let payer = payments[0].payer;
    let mut per_recipient: BTreeMap<Address, u64> = BTreeMap::new();
    let mut payment_ids = Vec::with_capacity(payments.len());
    let mut total_amount_sat: u64 = 0;
    let mut declared_fee_sat: u64 = 0;
    for p in payments {
        p.verify(network_id, height)?;
        if p.payer != payer {
            return Err(PaymentError::MixedPayers);
        }
        payment_ids.push(p.signing_hash());
        total_amount_sat = total_amount_sat
            .checked_add(p.amount_sat)
            .ok_or(PaymentError::Overflow)?;
        declared_fee_sat = declared_fee_sat
            .checked_add(p.fee_sat)
            .ok_or(PaymentError::Overflow)?;
        let slot = per_recipient.entry(p.recipient).or_insert(0);
        *slot = slot
            .checked_add(p.amount_sat)
            .ok_or(PaymentError::Overflow)?;
    }
    Ok(PaymentBatch {
        payer,
        payment_ids,
        outputs: per_recipient.into_iter().collect(),
        total_amount_sat,
        declared_fee_sat,
    })
}

/// Parse an exact decimal SRCT amount into satoshis. **No floating point**:
/// the string is consumed digit by digit, at most [`SAT_DECIMALS`] decimals
/// are accepted (anything finer would round, and a machine payment must
/// never round), and a value above `u64::MAX` satoshis is refused.
///
/// ```
/// # use srct_core::service::parse_amount_sat;
/// assert_eq!(parse_amount_sat("1.5").unwrap(), 1_500_000_000);
/// assert_eq!(parse_amount_sat("0.000000001").unwrap(), 1);
/// assert!(parse_amount_sat("1.0000000001").is_err()); // 10 decimals
/// assert!(parse_amount_sat("-1").is_err());
/// ```
pub fn parse_amount_sat(s: &str) -> Result<u64, SessionError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(SessionError::BadAmount("empty"));
    }
    if bytes[0] == b'-' || bytes[0] == b'+' {
        return Err(SessionError::BadAmount("sign not allowed"));
    }
    let dot = bytes.iter().position(|&b| b == b'.');
    let (int_part, frac_part) = match dot {
        Some(i) => (&bytes[..i], &bytes[i + 1..]),
        None => (bytes, &bytes[bytes.len()..]),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(SessionError::BadAmount("no digits"));
    }
    if frac_part.len() as u32 > SAT_DECIMALS {
        return Err(SessionError::BadAmount("finer than one satoshi"));
    }
    let mut total: u64 = 0;
    for &b in int_part {
        if !b.is_ascii_digit() {
            return Err(SessionError::BadAmount("non-digit"));
        }
        total = total
            .checked_mul(10)
            .and_then(|t| t.checked_add((b - b'0') as u64))
            .ok_or(SessionError::BadAmount("integer overflow"))?;
    }
    let mut scale: u64 = 10u64.pow(SAT_DECIMALS);
    let mut frac: u64 = 0;
    for &b in frac_part {
        if !b.is_ascii_digit() {
            return Err(SessionError::BadAmount("non-digit"));
        }
        scale /= 10;
        frac = frac
            .checked_mul(10)
            .and_then(|f| f.checked_add((b - b'0') as u64))
            .ok_or(SessionError::BadAmount("fraction overflow"))?;
    }
    let whole = total
        .checked_mul(10u64.pow(SAT_DECIMALS))
        .ok_or(SessionError::BadAmount("overflow"))?;
    let frac = frac
        .checked_mul(scale)
        .ok_or(SessionError::BadAmount("overflow"))?;
    whole
        .checked_add(frac)
        .ok_or(SessionError::BadAmount("overflow"))
}

/// Exact inverse of [`parse_amount_sat`]: always [`SAT_DECIMALS`] decimals,
/// no thousands separators, no exponent, no float. `parse(format(x)) == x`
/// for every `x`.
pub fn format_amount_sat(sat: u64) -> String {
    let unit = 10u64.pow(SAT_DECIMALS);
    let whole = sat / unit;
    let frac = sat % unit;
    format!("{whole}.{frac:09}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "srct/testnet";

    fn wallet() -> Wallet {
        Wallet::from_private_key_bytes(&[31u8; 32], "payer").expect("valid key")
    }

    fn service_wallet() -> Wallet {
        Wallet::from_private_key_bytes(&[32u8; 32], "provider").expect("valid key")
    }

    fn machine_policy(owner: Address, service: [u8; 32]) -> SpendPolicy {
        SpendPolicy {
            version: crate::agent::POLICY_VERSION,
            network_id: NET.to_string(),
            agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
            owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 600,
            window_blocks: 10,
            cumulative_max_sat: 1_000,
            allowed_recipients: vec![service_wallet().address().unwrap()],
            allowed_services: vec![service],
            not_before_height: 0,
            expires_at_height: 10_000,
            revoked: false,
            parent_agent_id: None,
        }
    }

    #[test]
    fn service_ids_are_deterministic_network_bound_and_provider_bound() {
        let provider = [9u8; 20];
        let a = derive_service_id(NET, &provider, b"srct-llm");
        let b = derive_service_id(NET, &provider, b"srct-llm");
        assert_eq!(a, b);
        assert_ne!(a, derive_service_id("srct/mini", &provider, b"srct-llm"));
        assert_ne!(a, derive_service_id(NET, &[8u8; 20], b"srct-llm"));
        assert_ne!(a, derive_service_id(NET, &provider, b"other"));
    }

    #[test]
    fn amounts_parse_and_format_exactly_without_floats() {
        assert_eq!(parse_amount_sat("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_amount_sat("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_amount_sat(".5").unwrap(), 500_000_000);
        assert_eq!(parse_amount_sat("0.000000001").unwrap(), 1);
        assert_eq!(parse_amount_sat("0").unwrap(), 0);
        assert!(parse_amount_sat("").is_err());
        assert!(parse_amount_sat("-1").is_err());
        assert!(parse_amount_sat("+1").is_err());
        assert!(parse_amount_sat("1.0000000001").is_err());
        assert!(parse_amount_sat("1e9").is_err());
        assert!(parse_amount_sat(".").is_err());
        assert!(parse_amount_sat("abc").is_err());
        for v in [0u64, 1, 999_999_999, 1_000_000_000, u64::MAX] {
            assert_eq!(parse_amount_sat(&format_amount_sat(v)).unwrap(), v);
        }
    }

    #[test]
    fn a_request_round_trips_and_verifies_offline() {
        let w = wallet();
        let provider = service_wallet().address().unwrap();
        let service = derive_service_id(NET, &provider, b"svc");
        let policy = machine_policy(w.address().unwrap(), service);
        let req = build_signed_request(
            &w,
            RequestSpec {
                network_id: NET.to_string(),
                payer_type: AgentRole::Machine,
                service_id: service,
                recipient: provider,
                max_amount_sat: 500,
                expires_at_height: 9_000,
                policy_hash: policy.hash(),
            },
            &[],
        )
        .expect("request builds");
        req.verify(NET, 100).expect("verifies");
        let bytes = req.serialize();
        let back = PaymentRequest::deserialize(&bytes).expect("decode");
        assert_eq!(back, req);
        assert_eq!(back.serialize(), bytes);

        let mut wrong_net = req.clone();
        wrong_net.network_id = "srct/mini".into();
        assert!(wrong_net.verify(NET, 100).is_err());
    }

    #[test]
    fn aggregate_merges_recipients_and_refuses_mixed_payers() {
        let w = wallet();
        let provider = service_wallet().address().unwrap();
        let service = derive_service_id(NET, &provider, b"svc");
        let policy = machine_policy(w.address().unwrap(), service);
        let mut book = PolicyBook::default();
        let mut payments = Vec::new();
        // Three in-policy grants: 300 + 300 + 400 = 1000 = the window cap.
        for (i, amount) in [300u64, 300, 400].into_iter().enumerate() {
            let p = machine_policy(w.address().unwrap(), service);
            let req = build_signed_request(
                &w,
                RequestSpec {
                    network_id: NET.to_string(),
                    payer_type: AgentRole::Machine,
                    service_id: service,
                    recipient: provider,
                    max_amount_sat: amount,
                    expires_at_height: 9_000,
                    policy_hash: p.hash(),
                },
                &[],
            )
            .unwrap();
            let auth = authorize_request(&mut book, &p, NET, &req, 100, (i + 1) as u64).unwrap();
            payments.push(
                crate::payment::build_signed_payment(
                    &w,
                    &auth,
                    NET,
                    AgentRole::Machine,
                    0,
                    9_000,
                    req.request_id(),
                    &[],
                )
                .unwrap(),
            );
        }
        // A fourth recipient under a second policy to exercise grouping.
        let other_recipient = [7u8; 20];
        {
            let mut p = policy.clone();
            p.allowed_recipients = vec![other_recipient];
            let req = build_signed_request(
                &w,
                RequestSpec {
                    network_id: NET.to_string(),
                    payer_type: AgentRole::Machine,
                    service_id: service,
                    recipient: other_recipient,
                    max_amount_sat: 100,
                    expires_at_height: 9_000,
                    policy_hash: p.hash(),
                },
                &[],
            )
            .unwrap();
            let auth = authorize_request(&mut book, &p, NET, &req, 100, 100).unwrap();
            payments.push(
                crate::payment::build_signed_payment(
                    &w,
                    &auth,
                    NET,
                    AgentRole::Machine,
                    0,
                    9_000,
                    req.request_id(),
                    &[],
                )
                .unwrap(),
            );
        }

        let batch = aggregate_payments(&payments, NET, 100).expect("aggregates");
        assert_eq!(batch.payer, w.address().unwrap());
        assert_eq!(batch.total_amount_sat, 1_100);
        assert_eq!(batch.output_count(), 2, "same recipient must merge");
        assert_eq!(batch.outputs[0].1 + batch.outputs[1].1, 1_100);
        assert_eq!(batch.payment_ids.len(), 4);
        // One settlement costs one base: 2 outputs, 1 input at 100 sat/gas.
        assert_eq!(
            batch.gas_used(1),
            Some(crate::tx::GAS_TX_BASE + 1_000 + 500)
        );
        assert_eq!(
            batch.required_fee(100, 1),
            Some(100 * (crate::tx::GAS_TX_BASE + 1_000 + 500))
        );

        // Mixed payers cannot share one signed transaction: a *second*,
        // fully valid payer joins the batch and the merge refuses by name.
        let w2 = Wallet::from_private_key_bytes(&[41u8; 32], "payer2").expect("valid key");
        let p2 = machine_policy(w2.address().unwrap(), service);
        let req2 = build_signed_request(
            &w2,
            RequestSpec {
                network_id: NET.to_string(),
                payer_type: AgentRole::Machine,
                service_id: service,
                recipient: provider,
                max_amount_sat: 100,
                expires_at_height: 9_000,
                policy_hash: p2.hash(),
            },
            &[],
        )
        .unwrap();
        let auth2 = authorize_request(&mut book, &p2, NET, &req2, 100, 1).unwrap();
        let payment2 = crate::payment::build_signed_payment(
            &w2,
            &auth2,
            NET,
            AgentRole::Machine,
            0,
            9_000,
            req2.request_id(),
            &[],
        )
        .unwrap();
        let mut mixed = payments.clone();
        mixed.push(payment2);
        assert_eq!(
            aggregate_payments(&mixed, NET, 100),
            Err(PaymentError::MixedPayers)
        );
    }

    /// Everything an admission test needs: a live policy, an authorization
    /// issued under it, and the payment built from that authorization.
    fn granted(
        w: &Wallet,
        book: &mut PolicyBook,
    ) -> (
        SpendPolicy,
        Authorization,
        crate::payment::MachinePayment,
        PaymentRequest,
    ) {
        let provider = service_wallet().address().unwrap();
        let service = derive_service_id(NET, &provider, b"svc");
        let policy = machine_policy(w.address().unwrap(), service);
        let request = build_signed_request(
            w,
            RequestSpec {
                network_id: NET.to_string(),
                payer_type: AgentRole::Machine,
                service_id: service,
                recipient: provider,
                max_amount_sat: 400,
                expires_at_height: 9_000,
                policy_hash: policy.hash(),
            },
            &[],
        )
        .unwrap();
        let auth = authorize_request(book, &policy, NET, &request, 100, 1).unwrap();
        let payment = crate::payment::build_signed_payment(
            w,
            &auth,
            NET,
            AgentRole::Machine,
            0,
            9_000,
            request.request_id(),
            &[],
        )
        .unwrap();
        (policy, auth, payment, request)
    }

    /// The owner's signature over the authorization, and the key bundle it
    /// verifies against.
    fn grants(w: &Wallet, auth: &Authorization) -> (Bundle, Bundle) {
        (
            crate::l2::Auth::sigs_for(w, &auth.signing_hash()).unwrap(),
            crate::l2::Auth::keys_for(w).unwrap(),
        )
    }

    #[test]
    fn a_payment_the_owner_authorized_is_admitted() {
        let w = wallet();
        let mut book = PolicyBook::default();
        let (policy, auth, payment, _request) = granted(&w, &mut book);
        let (sigs, keys) = grants(&w, &auth);
        let presented = AuthPresentation {
            auth: &auth,
            sigs: &sigs,
            keys: &keys,
        };
        let mut gate = crate::credit::NoCreditGate;
        assert!(admit_payment(&book, &policy, &payment, presented, NET, 100, &mut gate).is_ok());
    }

    #[test]
    fn a_payment_naming_a_policy_the_engine_never_issued_under_is_refused() {
        // The leak this closes: the policy hash in a payment used to be a
        // decorative field, because nothing consulted the engine. Now the
        // engine must have issued under the policy the payment names.
        let w = wallet();
        let mut book = PolicyBook::default();
        let (policy, auth, payment, _request) = granted(&w, &mut book);

        // A second, perfectly valid policy the engine has never seen: the
        // payment names it, so admission must refuse.
        let mut other = policy.clone();
        other.allowed_services = vec![[9u8; 32]];
        other.per_tx_max_sat = 500;
        assert_ne!(other.hash(), policy.hash());
        assert!(book.state(&other.hash()).is_none());

        let (sigs, keys) = grants(&w, &auth);
        let presented = AuthPresentation {
            auth: &auth,
            sigs: &sigs,
            keys: &keys,
        };
        let mut gate = crate::credit::NoCreditGate;
        assert_eq!(
            admit_payment(&book, &other, &payment, presented, NET, 100, &mut gate),
            Err(SessionError::Binding("payment names another policy"))
        );
    }

    #[test]
    fn a_payment_whose_authorization_is_not_the_owners_is_refused() {
        // The authorization is well-formed and binds correctly, but it was
        // signed by someone else's key: the owner never granted this spend.
        let w = wallet();
        let mut book = PolicyBook::default();
        let (policy, auth, payment, _request) = granted(&w, &mut book);

        let forger = service_wallet();
        let (sigs, keys) = grants(&forger, &auth);
        let presented = AuthPresentation {
            auth: &auth,
            sigs: &sigs,
            keys: &keys,
        };
        let mut gate = crate::credit::NoCreditGate;
        assert!(admit_payment(&book, &policy, &payment, presented, NET, 100, &mut gate).is_err());
    }

    #[test]
    fn a_payment_tampered_after_its_authorization_is_refused() {
        // The payer re-signs a *bigger* payment: every budget rule passed when
        // the authorization was issued, the payment is structurally valid, and
        // it is still not what the owner authorized.
        let w = wallet();
        let mut book = PolicyBook::default();
        let (policy, auth, payment, _request) = granted(&w, &mut book);
        let mut forged = payment.clone();
        forged.amount_sat = auth.amount_sat + 1;
        forged.sigs = crate::l2::Auth::sigs_for(&w, &forged.signing_hash()).unwrap();
        forged.verify(NET, 100).unwrap();

        let (sigs, keys) = grants(&w, &auth);
        let presented = AuthPresentation {
            auth: &auth,
            sigs: &sigs,
            keys: &keys,
        };
        let mut gate = crate::credit::NoCreditGate;
        assert_eq!(
            admit_payment(&book, &policy, &forged, presented, NET, 100, &mut gate),
            Err(SessionError::Payment(
                PaymentError::NotLinkedToAuthorization("amount")
            ))
        );
    }

    #[test]
    fn a_revoked_policy_variant_is_not_the_policy_the_engine_issued_under() {
        // Revocation lives in the signed bytes, so a revoked variant is a
        // *different hash*: the engine has no state under it, and a payment
        // naming it is refused as an unknown policy rather than admitted.
        let w = wallet();
        let mut book = PolicyBook::default();
        let (policy, auth, payment, _request) = granted(&w, &mut book);
        let mut variant = policy.clone();
        variant.revoked = true;
        assert_ne!(variant.hash(), policy.hash());

        let (sigs, keys) = grants(&w, &auth);
        let presented = AuthPresentation {
            auth: &auth,
            sigs: &sigs,
            keys: &keys,
        };
        let mut gate = crate::credit::NoCreditGate;
        assert_eq!(
            admit_payment(&book, &variant, &payment, presented, NET, 100, &mut gate),
            Err(SessionError::Binding("payment names another policy"))
        );
    }

    #[test]
    fn a_policy_that_has_since_expired_refuses_a_later_payment() {
        // The payment outlives its policy, and admitting it at a height past the
        // policy's own expiry is refused: a grant does not extend the envelope
        // it was issued inside.
        let w = wallet();
        let mut book = PolicyBook::default();
        let (policy, auth, payment, _request) = granted(&w, &mut book);
        assert_eq!(payment.expires_at_height, 9_000);
        assert_eq!(policy.expires_at_height, 10_000);

        let (sigs, keys) = grants(&w, &auth);
        let presented = AuthPresentation {
            auth: &auth,
            sigs: &sigs,
            keys: &keys,
        };
        let mut gate = crate::credit::NoCreditGate;
        assert_eq!(
            admit_payment(&book, &policy, &payment, presented, NET, 9_500, &mut gate),
            Err(SessionError::Payment(PaymentError::Expired {
                expires_at: 9_000,
                height: 9_500
            }))
        );
        // Rebuild the payment with a later expiry of its own, and now it is the
        // *policy* that refuses it.
        let mut later = crate::payment::MachinePayment {
            expires_at_height: 11_000,
            ..payment
        };
        later.sigs = crate::l2::Auth::sigs_for(&w, &later.signing_hash()).unwrap();
        let mut gate = crate::credit::NoCreditGate;
        assert_eq!(
            admit_payment(&book, &policy, &later, presented, NET, 10_050, &mut gate),
            Err(SessionError::Policy(PolicyError::PolicyExpired {
                expires_at: 10_000,
                height: 10_050
            }))
        );
    }
}
