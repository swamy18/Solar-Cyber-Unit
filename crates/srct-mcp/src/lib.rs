//! A **keyless** MCP surface over the Solar Cyber Unit payment/policy layer
//! (roadmap §10, SPEC.md §21–§22).
//!
//! # What this is
//!
//! A deterministic JSON request/response dispatcher that lets an MCP server
//! expose Solar Cyber Unit payment operations to an agent without ever touching a
//! private key. Every operation is one of:
//!
//! - **build** an authorization from a payer-signed request (delegates every
//!   budget rule to the existing `PolicyBook` — no rules are re-implemented
//!   here);
//! - **guard** a payment against a budget before signing (the agent wallet
//!   guard: short-lived, exact, keyless — allow, deny or approval-needed);
//! - **prove/verify** portable policy and delegation objects any rail can
//!   check (`SignedPolicy`, `DelegationProof`, `BoundAuthorization`);
//! - **inspect/verify** a request, authorization, payment or receipt offline,
//!   against a network and height the caller supplies;
//! - **submit** an already-signed payment or receipt to a node's opt-in REST
//!   API, or read that node's status.
//!
//! # What this is not
//!
//! - **Not a trust authority.** It verifies using the same public functions
//!   every other verifier uses; it cannot mint an authorization, a payment, a
//!   bound grant or a receipt, and a "valid: true" answer is just the shared
//!   verification result.
//! - **Not a key holder.** No operation accepts, returns or stores a private
//!   key. Signing is the client's job: this layer hands back the bytes and the
//!   signing hash, and the client signs them (exactly as `POST /v1/authorize`
//!   does).
//! - **Not a consensus surface.** The only writes reach a node's opt-in API,
//!   which itself never touches `Chain::submit`.
//!
//! The dispatch table is [`SolarCyberUnitMcp::capabilities`]; every failure is a named
//! [`McpError`] and malformed input is refused rather than partially acted on.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Value};

use srct_core::agent::{verify_authorization, PolicyBook, SpendPolicy};
use srct_core::guard::{
    derive_action_hash, derive_context_hash, Decision as GuardDecision, GuardApproval, GuardBook,
    InfraPolicy, SignedCapability,
};
use srct_core::hash::{address_from_hex, hash_from_hex, hash_to_hex};
use srct_core::payment::MachinePayment;
use srct_core::receipt::{ReceiptBook, ServiceReceipt};
use srct_core::service::{authorize_request, PaymentRequest, SessionError};

/// A named refusal. `code` is the stable machine-readable name; `detail` is a
/// human string that never contains signing material (nothing here holds any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpError {
    pub code: &'static str,
    pub detail: String,
}

impl McpError {
    fn bad(detail: impl Into<String>) -> Self {
        McpError {
            code: "bad_request",
            detail: detail.into(),
        }
    }

    fn refused(code: &'static str, detail: impl Into<String>) -> Self {
        McpError {
            code,
            detail: detail.into(),
        }
    }

    fn transport(detail: impl Into<String>) -> Self {
        McpError {
            code: "transport",
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for McpError {}

/// The dispatcher. It holds a [`PolicyBook`] so authorization state (nonce and
/// the tumbling spend window) survives across calls — a fresh book per call
/// would silently reset every anti-replay counter. It holds **no** key
/// material.
pub struct SolarCyberUnitMcp {
    policies: PolicyBook,
    guards: GuardBook,
}

impl Default for SolarCyberUnitMcp {
    fn default() -> Self {
        SolarCyberUnitMcp::new()
    }
}

impl SolarCyberUnitMcp {
    pub fn new() -> Self {
        SolarCyberUnitMcp {
            policies: PolicyBook::default(),
            guards: GuardBook::default(),
        }
    }

    /// The operation names this surface answers. Advertise them to the agent
    /// so it never guesses a tool name.
    pub fn capabilities(&self) -> Vec<&'static str> {
        vec![
            "authorize",
            "wallet.guard",
            "guard.check",
            "guard.authorize",
            "policy.decide",
            "policy.export",
            "policy.verify",
            "delegation.prove",
            "delegation.verify",
            "auth.bind",
            "auth.verify_bound",
            "audit.verify",
            "inspect.authorization",
            "inspect.request",
            "inspect.payment",
            "inspect.receipt",
            "inspect.policy",
            "inspect.agent_spend",
            "inspect.credit",
            "verify.authorization",
            "node.status",
            "payment.submit",
            "receipt.submit",
        ]
    }

    /// Dispatch one JSON request. `{"op": "...", ...}`.
    pub fn handle(&mut self, request: &Value) -> Result<Value, McpError> {
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::bad("missing `op`"))?;
        match op {
            "authorize" => self.authorize(request),
            "wallet.guard" => self.wallet_guard(request),
            "guard.check" => self.guard_check(request),
            "guard.authorize" => self.guard_authorize(request),
            "policy.decide" => self.policy_decide(request),
            "policy.export" => self.policy_export(request),
            "policy.verify" => self.policy_verify(request),
            "delegation.prove" => self.delegation_prove(request),
            "delegation.verify" => self.delegation_verify(request),
            "auth.bind" => self.auth_bind(request),
            "auth.verify_bound" => self.auth_verify_bound(request),
            "audit.verify" => self.audit_verify(request),
            "inspect.authorization" => self.inspect_authorization(request),
            "inspect.request" => self.inspect_request(request),
            "inspect.payment" => self.inspect_payment(request),
            "inspect.receipt" => self.inspect_receipt(request),
            "inspect.policy" => self.inspect_policy(request),
            "inspect.agent_spend" => self.inspect_agent_spend(request),
            "inspect.credit" => self.inspect_credit(request),
            "verify.authorization" => self.verify_authorization(request),
            "node.status" => self.node_status(request),
            "payment.submit" => self.payment_submit(request),
            "receipt.submit" => self.receipt_submit(request),
            other => Err(McpError::bad(format!("unknown op `{other}`"))),
        }
    }

    // -----------------------------------------------------------------------
    // Authorization
    // -----------------------------------------------------------------------

    /// `authorize` — the request → authorization step. Adds no rule of its own:
    /// `authorize_request` delegates entirely to the policy engine. Returns the
    /// authorization bytes and the signing hash the *owner* signs; this layer
    /// never signs.
    fn authorize(&mut self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let nonce = u64_field(request, "nonce")?;
        let policy_bytes = hex_field(request, "policy_hex")?;
        let request_bytes = hex_field(request, "request_hex")?;

        let policy = SpendPolicy::deserialize(&policy_bytes)
            .map_err(|e| McpError::bad(format!("policy: {e}")))?;
        let parsed = PaymentRequest::deserialize(&request_bytes)
            .map_err(|e| McpError::bad(format!("request: {e}")))?;

        let auth = authorize_request(
            &mut self.policies,
            &policy,
            network_id,
            &parsed,
            height,
            nonce,
        )
        .map_err(session_error)?;

        Ok(json!({
            "authorization_hex": hex::encode(auth.serialize()),
            "signing_hash": hash_to_hex(&auth.signing_hash()),
            "policy_hash": hash_to_hex(&auth.policy_hash),
            "amount_sat": auth.amount_sat,
            "nonce": auth.nonce,
            "height": auth.height,
            "note": "the policy owner signs `signing_hash`; this layer holds no key",
        }))
    }

    // -----------------------------------------------------------------------
    // Agent wallet guard: budget + short-lived checks before any key is used
    // -----------------------------------------------------------------------

    /// `wallet.guard` — the keyless pre-sign check. Runs the budget
    /// (`X402Budget::check_guarded`: amount, allow-lists, short expiry) and an
    /// optional high-value approval threshold, and answers allow, deny, or
    /// approval-needed. Nothing is signed and no key is touched: the agent
    /// signs only what this approves.
    fn wallet_guard(&self, request: &Value) -> Result<Value, McpError> {
        let budget = budget_from(request)?;
        let amount_sat = u64_field(request, "amount_sat")?;
        let recipient = address_from_hex(str_field(request, "recipient_hex")?.trim())
            .map_err(|e| McpError::bad(format!("recipient: {e}")))?;
        let service = opt_service(request)?;
        let height = u64_field(request, "height")?;
        let expires_at_height = u64_field(request, "expires_at_height")?;

        match budget.check_guarded(amount_sat, &recipient, &service, height, expires_at_height) {
            Ok(grant) => {
                if let Some(threshold) = request
                    .get("approval_threshold_sat")
                    .and_then(Value::as_u64)
                {
                    if threshold > 0 && amount_sat >= threshold {
                        return Ok(json!({
                            "decision": "needs_approval",
                            "reason": format!("amount {amount_sat} needs human approval (threshold {threshold})"),
                        }));
                    }
                }
                Ok(json!({
                    "decision": "allow",
                    "amount_sat": grant.amount_sat,
                    "recipient": hex::encode(grant.recipient),
                    "expires_at_height": grant.expires_at_height,
                    "note": "sign only this exact payment inside this window",
                }))
            }
            Err(e) => Err(McpError::refused("guard_refused", e.to_string())),
        }
    }

    /// `guard.check` — stateless Smart Gate pre-check. No book, no commit.
    /// Verifies the owner's signature over the capability, then grant shape,
    /// network binding, validity, capability equality, expiry and lifetime.
    /// `cap_hex` MUST be a signed [`SignedCapability`] envelope; a bare
    /// capability is refused as `unsigned_capability`. Answers allow /
    /// needs_approval, refuses by name. This is a pre-check only: execution
    /// authorization recomputes the action hash from the observed preimage in
    /// `guard.authorize`.
    fn guard_check(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let policy_bytes = hex_field(request, "policy_hex")?;
        let policy = InfraPolicy::deserialize(&policy_bytes)
            .map_err(|e| McpError::bad(format!("policy: {e}")))?;
        let cap_bytes = hex_field(request, "cap_hex")?;
        let signed = SignedCapability::deserialize(&cap_bytes).map_err(|_| {
            McpError::refused(
                "unsigned_capability",
                "capability is not signed by the grant owner",
            )
        })?;
        signed
            .verify(&policy)
            .map_err(|e| McpError::refused("guard_refused", e.to_string()))?;
        let cap = &signed.cap;
        let agent_raw = hex_field(request, "agent_id_hex")?;
        if agent_raw.len() != 20 {
            return Err(McpError::bad("agent_id_hex must be 20 bytes"));
        }
        let mut agent_id = [0u8; 20];
        agent_id.copy_from_slice(&agent_raw);
        let action_hash = hash_from_hex(str_field(request, "action_hash_hex")?.trim())
            .map_err(|e| McpError::bad(format!("action_hash: {e}")))?;
        let workload_id = hash_from_hex(str_field(request, "workload_id_hex")?.trim())
            .map_err(|e| McpError::bad(format!("workload_id: {e}")))?;
        let expected_ctx = derive_context_hash(&workload_id, height);
        let high_risk = request
            .get("high_risk")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if policy.network_id != network_id {
            return Err(McpError::refused(
                "guard_refused",
                "grant is for another network",
            ));
        }
        if policy.revoked {
            return Err(McpError::refused("guard_refused", "grant revoked"));
        }
        if height < policy.valid_from_height {
            return Err(McpError::refused("guard_refused", "grant not yet valid"));
        }
        if height >= policy.valid_until_height {
            return Err(McpError::refused("guard_refused", "grant expired"));
        }
        if policy.agent_id != agent_id {
            return Err(McpError::refused(
                "guard_refused",
                "cross-principal capability",
            ));
        }
        if cap.nonce == 0 {
            return Err(McpError::refused(
                "guard_refused",
                "capability nonce is zero",
            ));
        }
        if cap.policy_hash != policy.hash() {
            return Err(McpError::refused(
                "guard_refused",
                "capability does not name this grant",
            ));
        }
        if cap.action_hash != action_hash {
            return Err(McpError::refused("guard_refused", "action hash mismatch"));
        }
        if cap.context_hash != expected_ctx {
            return Err(McpError::refused("guard_refused", "context hash mismatch"));
        }
        if height >= cap.expiry_height {
            return Err(McpError::refused("guard_refused", "capability expired"));
        }
        if cap.expiry_height.saturating_sub(height) > srct_core::guard::MAX_CAP_LIFETIME {
            return Err(McpError::refused(
                "guard_refused",
                "capability lifetime exceeds cap",
            ));
        }
        if high_risk {
            return Ok(
                json!({"decision": "needs_approval", "reason": "high-risk action needs a signed approval, not a boolean"}),
            );
        }
        Ok(json!({"decision": "allow", "policy_hash": hash_to_hex(&policy.hash())}))
    }

    /// `guard.authorize` — stateful execution-boundary admission. Same checks
    /// as `guard.check` plus tumbling-window budget and strictly increasing
    /// nonce via `GuardBook::authorize_signed`. The caller MUST supply
    /// `action_preimage_hex`: the boundary recomputes
    /// `derive_action_hash(preimage)` from what it is about to execute and
    /// refuses unless it equals the capability's action (action-swap fix).
    /// High-risk calls MUST supply `approval_hex` (a signed [`GuardApproval`]
    /// envelope); the old `approved: true` boolean is no longer accepted. On
    /// allow the state commits; on deny or approval-needed nothing mutates.
    /// Local MCP state is a non-authoritative cache: the node's registry +
    /// revocation set is authoritative (see the Smart Gate architecture doc).
    fn guard_authorize(&mut self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let policy_bytes = hex_field(request, "policy_hex")?;
        let policy = InfraPolicy::deserialize(&policy_bytes)
            .map_err(|e| McpError::bad(format!("policy: {e}")))?;
        let cap_bytes = hex_field(request, "cap_hex")?;
        let signed = SignedCapability::deserialize(&cap_bytes).map_err(|_| {
            McpError::refused(
                "unsigned_capability",
                "capability is not signed by the grant owner",
            )
        })?;
        let agent_raw = hex_field(request, "agent_id_hex")?;
        if agent_raw.len() != 20 {
            return Err(McpError::bad("agent_id_hex must be 20 bytes"));
        }
        let mut agent_id = [0u8; 20];
        agent_id.copy_from_slice(&agent_raw);
        let preimage = hex_field(request, "action_preimage_hex")?;
        if preimage.is_empty() || preimage.len() > 64 * 1024 {
            return Err(McpError::bad(
                "action_preimage_hex must name the executed bytes",
            ));
        }
        let recomputed = derive_action_hash(&preimage);
        if let Some(claimed) = request.get("action_hash_hex").and_then(Value::as_str) {
            let claimed_hash = hash_from_hex(claimed.trim())
                .map_err(|e| McpError::bad(format!("action_hash: {e}")))?;
            if claimed_hash != recomputed {
                return Err(McpError::refused(
                    "guard_refused",
                    "claimed action hash does not match the executed bytes",
                ));
            }
        }
        let workload_id = hash_from_hex(str_field(request, "workload_id_hex")?.trim())
            .map_err(|e| McpError::bad(format!("workload_id: {e}")))?;
        let expected_ctx = derive_context_hash(&workload_id, height);
        let high_risk = request
            .get("high_risk")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if request
            .get("approved")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(McpError::refused(
                "approval_invalid",
                "approved:true is no longer accepted; supply a signed approval_hex",
            ));
        }
        let approval_bytes = match request.get("approval_hex").and_then(Value::as_str) {
            None => None,
            Some(s) => {
                let raw = s.trim().trim_start_matches("0x");
                if raw.len() > MAX_HEX_FIELD_CHARS {
                    return Err(McpError::bad("approval_hex over the hex cap"));
                }
                Some(hex::decode(raw).map_err(|e| McpError::bad(format!("approval_hex: {e}")))?)
            }
        };
        let approval = match approval_bytes {
            None => None,
            Some(b) => Some(
                GuardApproval::deserialize(&b)
                    .map_err(|e| McpError::refused("approval_invalid", e.to_string()))?,
            ),
        };
        match self.guards.authorize_signed(
            &policy,
            &signed,
            &agent_id,
            network_id,
            height,
            &preimage,
            &expected_ctx,
            high_risk,
            approval.as_ref(),
        ) {
            GuardDecision::Allow => {
                Ok(json!({"decision": "allow", "policy_hash": hash_to_hex(&policy.hash())}))
            }
            GuardDecision::NeedsApproval => Ok(
                json!({"decision": "needs_approval", "reason": "high-risk action needs a signed approval_hex"}),
            ),
            GuardDecision::Deny(e) => Err(McpError::refused("guard_refused", e.to_string())),
        }
    }

    /// `policy.decide` — the stateless engine seam over MCP: evaluate a policy
    /// against a payment intent and answer allow, deny, or approval-needed.
    /// No state is committed; the nonce/window accounting still runs in
    /// `authorize` (or the node).
    fn policy_decide(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let policy_bytes = hex_field(request, "policy_hex")?;
        let policy = SpendPolicy::deserialize(&policy_bytes)
            .map_err(|e| McpError::bad(format!("policy: {e}")))?;
        // No local network check: the engine owns the binding below, so no
        // caller — here or on any rail — can forget it.
        let intent = srct_core::portable::PaymentIntent {
            agent_id: str_field(request, "agent_id_hex")?.to_string(),
            recipient: str_field(request, "recipient_hex")?.to_string(),
            amount_sat: u64_field(request, "amount_sat")?,
            service: request
                .get("service_hex")
                .and_then(Value::as_str)
                .map(str::to_string),
            height,
            nonce: request.get("nonce").and_then(Value::as_u64).unwrap_or(0),
            network_id: network_id.to_string(),
        };
        let decoded = intent
            .decoded()
            .map_err(|e| McpError::bad(format!("intent: {e}")))?;
        let threshold = request
            .get("approval_threshold_sat")
            .and_then(Value::as_u64);
        match srct_core::portable::evaluate_policy(&policy, &decoded, network_id, height, threshold)
        {
            srct_core::portable::PolicyDecision::Allow => Ok(json!({"decision": "allow"})),
            srct_core::portable::PolicyDecision::Deny { reason } => {
                Err(McpError::refused("policy_refused", reason))
            }
            srct_core::portable::PolicyDecision::NeedsApproval { reason } => Ok(json!({
                "decision": "needs_approval",
                "reason": reason,
            })),
        }
    }

    /// `policy.export` — wrap a signed policy as portable JSON (verified on
    /// the way out, so an unverified grant never leaves as "portable").
    fn policy_export(&self, request: &Value) -> Result<Value, McpError> {
        let signed = signed_policy_from(request)?;
        serde_json::from_str(&signed.to_json())
            .map_err(|e| McpError::bad(format!("portable json: {e}")))
    }

    /// `policy.verify` — verify portable policy JSON from any rail.
    fn policy_verify(&self, request: &Value) -> Result<Value, McpError> {
        let raw = str_field(request, "portable_json")?;
        let signed = srct_core::portable::SignedPolicy::from_json(raw)
            .map_err(|e| McpError::refused("policy_invalid", e.to_string()))?;
        Ok(json!({
            "valid": true,
            "policy_hash": hash_to_hex(&signed.policy.hash()),
            "owner": hex::encode(signed.policy.owner),
            "agent_id": hex::encode(signed.policy.agent_id),
            "network_id": signed.policy.network_id,
        }))
    }

    /// `delegation.prove` — assemble parallel `policies_hex`/`sigs_hex`/
    /// `keys_hex` arrays (root first) into a verified [`DelegationProof`]
    /// and return its portable JSON: the clean proof a service checks.
    fn delegation_prove(&self, request: &Value) -> Result<Value, McpError> {
        let policies = hex_array(request, "policies_hex")?;
        let sigs = hex_array(request, "sigs_hex")?;
        let keys = hex_array(request, "keys_hex")?;
        if policies.len() != sigs.len()
            || policies.len() != keys.len()
            || policies.is_empty()
            || policies.len() > srct_core::delegation::MAX_DELEGATION_DEPTH
        {
            return Err(McpError::bad(
                "parallel link arrays must be non-empty and equal",
            ));
        }
        let mut links = Vec::with_capacity(policies.len());
        for (((policy_bytes, sigs_bytes), keys_bytes), i) in
            policies.iter().zip(sigs.iter()).zip(keys.iter()).zip(0..)
        {
            let policy = SpendPolicy::deserialize(policy_bytes)
                .map_err(|e| McpError::bad(format!("policy[{i}]: {e}")))?;
            let mut r = srct_core::ser::Reader::new(sigs_bytes);
            let sig_bundle = srct_core::sig::Bundle::from_reader(&mut r)
                .map_err(|e| McpError::bad(format!("sigs[{i}]: {e}")))?;
            let mut r = srct_core::ser::Reader::new(keys_bytes);
            let key_bundle = srct_core::sig::Bundle::from_reader(&mut r)
                .map_err(|e| McpError::bad(format!("keys[{i}]: {e}")))?;
            links.push(srct_core::portable::SignedPolicy {
                policy,
                sigs: sig_bundle,
                keys: key_bundle,
            });
        }
        let proof = srct_core::portable::DelegationProof::new(links)
            .map_err(|e| McpError::refused("delegation_invalid", e.to_string()))?;
        proof
            .verify()
            .map_err(|e| McpError::refused("delegation_invalid", e.to_string()))?;
        serde_json::from_str(&proof.to_json())
            .map_err(|e| McpError::bad(format!("proof json: {e}")))
    }

    /// `delegation.verify` — verify a delegation proof from any rail.
    fn delegation_verify(&self, request: &Value) -> Result<Value, McpError> {
        let raw = str_field(request, "proof_json")?;
        let proof = srct_core::portable::DelegationProof::from_json(raw)
            .map_err(|e| McpError::refused("delegation_invalid", e.to_string()))?;
        Ok(json!({
            "valid": true,
            "depth": proof.links.len(),
            "root_owner": hex::encode(proof.root_owner()),
            "leaf_agent": hex::encode(proof.leaf().agent_id),
            "leaf_policy_hash": hash_to_hex(&proof.leaf().hash()),
        }))
    }

    /// `auth.bind` — keyless step of the enforced approval: given an
    /// authorization, an expiry and the exact transaction hash, return the
    /// binding hash the *owner* signs. This layer never signs.
    fn auth_bind(&self, request: &Value) -> Result<Value, McpError> {
        let auth_bytes = hex_field(request, "authorization_hex")?;
        let auth = srct_core::agent::Authorization::deserialize(&auth_bytes)
            .map_err(|e| McpError::bad(format!("authorization: {e}")))?;
        let expires_at_height = u64_field(request, "expires_at_height")?;
        let bound_tx = hash_from_hex(str_field(request, "tx_hash_hex")?.trim())
            .map_err(|e| McpError::bad(format!("tx hash: {e}")))?;
        if expires_at_height <= auth.height {
            return Err(McpError::bad("bound expiry must be after the grant height"));
        }
        let lifetime = expires_at_height.saturating_sub(auth.height);
        if lifetime > srct_core::portable::MAX_BOUND_LIFETIME_BLOCKS {
            return Err(McpError::refused(
                "bound_invalid",
                format!(
                    "bound lifetime {lifetime} exceeds cap {}",
                    srct_core::portable::MAX_BOUND_LIFETIME_BLOCKS
                ),
            ));
        }
        let draft = srct_core::portable::BoundAuthorization {
            version: srct_core::portable::PORTABLE_POLICY_VERSION,
            auth: auth.clone(),
            expires_at_height,
            bound_tx,
            sigs: srct_core::sig::Bundle::default(),
            keys: srct_core::sig::Bundle::default(),
            auth_sigs: srct_core::sig::Bundle::default(),
            auth_keys: srct_core::sig::Bundle::default(),
        };
        Ok(json!({
            "binding_hash": hash_to_hex(&draft.signing_hash()),
            "auth_hash": hash_to_hex(&auth.signing_hash()),
            "expires_at_height": expires_at_height,
            "note": "the policy owner signs `binding_hash`; this layer holds no key",
        }))
    }

    /// `auth.verify_bound` — verify a bound authorization against its grant,
    /// the exact payment, and the height: the enforced check.
    fn auth_verify_bound(&self, request: &Value) -> Result<Value, McpError> {
        let bound_raw = str_field(request, "bound_json")?;
        let bound = srct_core::portable::BoundAuthorization::from_json_parsed(bound_raw)
            .map_err(|e| McpError::bad(format!("bound: {e}")))?;
        let policy_bytes = hex_field(request, "policy_hex")?;
        let policy = SpendPolicy::deserialize(&policy_bytes)
            .map_err(|e| McpError::bad(format!("policy: {e}")))?;
        let payment_bytes = hex_field(request, "payment_hex")?;
        let payment = srct_core::payment::MachinePayment::deserialize(&payment_bytes)
            .map_err(|e| McpError::bad(format!("payment: {e}")))?;
        let height = u64_field(request, "height")?;
        bound
            .verify(&policy, &payment, height)
            .map_err(|e| McpError::refused("bound_invalid", e.to_string()))?;
        Ok(json!({
            "valid": true,
            "owner": hex::encode(bound.auth.owner),
            "bound_tx": hash_to_hex(&bound.bound_tx),
            "expires_at_height": bound.expires_at_height,
        }))
    }

    /// `audit.verify` — verify an exported audit chain (auditor/insurer
    /// readable): links, entry hashes, order and tip.
    fn audit_verify(&self, request: &Value) -> Result<Value, McpError> {
        let raw = str_field(request, "audit_json")?;
        let count = srct_core::safety::AuditLog::verify_export_json(raw)
            .map_err(|e| McpError::refused("audit_invalid", e.to_string()))?;
        Ok(json!({ "valid": true, "entries": count }))
    }

    // -----------------------------------------------------------------------
    // Agent authority and credit, read side
    // -----------------------------------------------------------------------

    /// `inspect.policy` — read a published-grant payload: the terms, the
    /// spender the grant names, and the hash the owner signs.
    ///
    /// Pure inspection. This layer holds no key, so it cannot sign a
    /// publication; it tells an agent what it is signing.
    fn inspect_policy(&self, request: &Value) -> Result<Value, McpError> {
        let bytes = hex_field(request, "payload_hex")?;
        let payload =
            srct_core::l2::PolicyPayload::from_reader(&mut srct_core::ser::Reader::new(&bytes))
                .map_err(|e| McpError::bad(format!("policy payload: {e}")))?;
        let grant = srct_core::agent::SpendPolicy::deserialize(&payload.policy)
            .map_err(|e| McpError::bad(format!("grant: {e}")))?;
        Ok(json!({
            "owner": hex::encode(payload.owner),
            "spender": hex::encode(payload.spender),
            "agent_id": hex::encode(payload.agent_id),
            "policy_hash": hash_to_hex(&grant.hash()),
            "signing_hash": hash_to_hex(&payload.signing_hash()),
            "network_id": grant.network_id,
            "role": role_name(grant.role),
            "per_tx_max_sat": grant.per_tx_max_sat,
            "window_blocks": grant.window_blocks,
            "cumulative_max_sat": grant.cumulative_max_sat,
            "allowed_recipients": grant.allowed_recipients.iter().map(hex::encode).collect::<Vec<_>>(),
            "not_before_height": grant.not_before_height,
            "expires_at_height": grant.expires_at_height,
        }))
    }

    /// `inspect.agent_spend` — read a spend under a published grant.
    fn inspect_agent_spend(&self, request: &Value) -> Result<Value, McpError> {
        let bytes = hex_field(request, "payload_hex")?;
        let payload =
            srct_core::l2::AgentSpendPayload::from_reader(&mut srct_core::ser::Reader::new(&bytes))
                .map_err(|e| McpError::bad(format!("spend payload: {e}")))?;
        Ok(json!({
            "agent": hex::encode(payload.agent),
            "policy_hash": hash_to_hex(&payload.policy_hash),
            "signing_hash": hash_to_hex(&payload.signing_hash()),
            "recipient": hex::encode(payload.recipient),
            "amount_sat": payload.amount_sat,
            "nonce": payload.nonce,
            "service": payload.service.map(hex::encode),
        }))
    }

    /// `inspect.credit` — read a credit-position opening: the terms, the
    /// derived position id, and the hash the **lender** signs.
    fn inspect_credit(&self, request: &Value) -> Result<Value, McpError> {
        let bytes = hex_field(request, "payload_hex")?;
        let payload =
            srct_core::l2::CreditOpenPayload::from_reader(&mut srct_core::ser::Reader::new(&bytes))
                .map_err(|e| McpError::bad(format!("credit payload: {e}")))?;
        Ok(json!({
            "lender": hex::encode(payload.lender),
            "borrower": hex::encode(payload.borrower),
            "amount_sat": payload.amount_sat,
            "collateral_sat": payload.collateral_sat,
            "rate_bps_per_window": payload.rate_bps_per_window,
            "window_blocks": payload.window_blocks,
            "deadline_height": payload.deadline_height,
            "nonce": payload.nonce,
            "position_id": hash_to_hex(&payload.derived_position_id()),
            "signing_hash": hash_to_hex(&payload.signing_hash()),
        }))
    }

    fn inspect_authorization(&self, request: &Value) -> Result<Value, McpError> {
        let bytes = hex_field(request, "authorization_hex")?;
        let auth = srct_core::agent::Authorization::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("authorization: {e}")))?;
        Ok(json!({
            "signing_hash": hash_to_hex(&auth.signing_hash()),
            "policy_hash": hash_to_hex(&auth.policy_hash),
            "owner": hex::encode(auth.owner),
            "recipient": hex::encode(auth.recipient),
            "amount_sat": auth.amount_sat,
            "service_id": auth.service.map(hex::encode),
            "height": auth.height,
            "nonce": auth.nonce,
        }))
    }

    // -----------------------------------------------------------------------
    // Offline verification of the bridge stages
    // -----------------------------------------------------------------------

    fn inspect_request(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let bytes = hex_field(request, "request_hex")?;
        let parsed = PaymentRequest::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("request: {e}")))?;
        parsed
            .verify(network_id, height)
            .map_err(|e| McpError::refused("request_invalid", e.to_string()))?;
        Ok(json!({
            "valid": true,
            // Offline inspection only: cryptographically well-formed is not
            // node-admitted. Structural checks (policy windows, revocation,
            // balances) still run at `/v1/payment/submit`.
            "admissible": false,
            "request_id": hash_to_hex(&parsed.request_id()),
            "payer": hex::encode(parsed.payer),
            "payer_type": role_name(parsed.payer_type),
            "service_id": hex::encode(parsed.service_id),
            "recipient": hex::encode(parsed.recipient),
            "max_amount_sat": parsed.max_amount_sat,
            "expires_at_height": parsed.expires_at_height,
            "policy_hash": hash_to_hex(&parsed.policy_hash),
        }))
    }

    fn inspect_payment(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let bytes = hex_field(request, "payment_hex")?;
        let payment = MachinePayment::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("payment: {e}")))?;
        payment
            .verify(network_id, height)
            .map_err(|e| McpError::refused("payment_invalid", e.to_string()))?;
        Ok(json!({
            "valid": true,
            // Offline inspection only: see `inspect_request`.
            "admissible": false,
            "payment_id": hash_to_hex(&payment.signing_hash()),
            "payer": hex::encode(payment.payer),
            "payer_type": role_name(payment.payer_type),
            "recipient": hex::encode(payment.recipient),
            "amount_sat": payment.amount_sat,
            "fee_sat": payment.fee_sat,
            "nonce": payment.nonce,
            "expires_at_height": payment.expires_at_height,
        }))
    }

    fn inspect_receipt(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let bytes = hex_field(request, "receipt_hex")?;
        let receipt = ServiceReceipt::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("receipt: {e}")))?;
        receipt
            .verify(network_id)
            .map_err(|e| McpError::refused("receipt_invalid", e.to_string()))?;

        // When the caller supplies the payment too, check the binding — a
        // receipt that verifies in isolation can still be for another payment.
        let mut bound = Value::Null;
        if let Some(payment_hex) = request.get("payment_hex").and_then(Value::as_str) {
            let trimmed = payment_hex.trim().trim_start_matches("0x");
            if trimmed.len() > MAX_HEX_FIELD_CHARS {
                return Err(McpError::bad("payment_hex over the hex cap"));
            }
            let payment_bytes =
                hex::decode(trimmed).map_err(|e| McpError::bad(format!("payment hex: {e}")))?;
            let payment = MachinePayment::deserialize(&payment_bytes)
                .map_err(|e| McpError::bad(format!("payment: {e}")))?;
            receipt
                .verify_binding(&payment)
                .map_err(|e| McpError::refused("receipt_not_bound", e.to_string()))?;
            bound = Value::Bool(true);
        }

        // `ReceiptBook` is the same replay-safe store the node uses; accepting
        // into a one-shot book answers "is this internally consistent and not
        // a self-contradiction" without inventing a second policy.
        let mut book = ReceiptBook::default();
        let outcome = book
            .accept(&receipt, network_id)
            .map_err(|e| McpError::refused("receipt_invalid", e.to_string()))?;

        Ok(json!({
            "valid": true,
            "bound_to_payment": bound,
            "outcome": format!("{outcome:?}").to_lowercase(),
            "receipt_id": hash_to_hex(&receipt.receipt_id()),
            "payment_id": hash_to_hex(&receipt.payment_id),
            "request_id": hash_to_hex(&receipt.request_id),
            "payer": hex::encode(receipt.payer),
            "recipient": hex::encode(receipt.recipient),
            "amount_sat": receipt.amount_sat,
            "result_hash": receipt.result_hash.map(|h| hash_to_hex(&h)),
        }))
    }

    /// Verify an authorization signature bundle presented by a third party.
    /// Uses the shared `verify_authorization`, which checks the keys bind to
    /// the owner *before* looking at the signature.
    fn verify_authorization(&self, request: &Value) -> Result<Value, McpError> {
        let auth_bytes = hex_field(request, "authorization_hex")?;
        let auth = srct_core::agent::Authorization::deserialize(&auth_bytes)
            .map_err(|e| McpError::bad(format!("authorization: {e}")))?;
        let sigs_bytes = hex_field(request, "sigs_hex")?;
        let keys_bytes = hex_field(request, "keys_hex")?;
        let sigs = bundle_from_bytes(&sigs_bytes)?;
        let keys = bundle_from_bytes(&keys_bytes)?;
        verify_authorization(&sigs, &keys, &auth)
            .map_err(|e| McpError::refused("authorization_invalid", e.to_string()))?;
        Ok(json!({ "valid": true, "owner": hex::encode(auth.owner) }))
    }

    // -----------------------------------------------------------------------
    // Node transport (the opt-in REST API, loopback by design)
    // -----------------------------------------------------------------------

    fn node_status(&self, request: &Value) -> Result<Value, McpError> {
        let endpoint = str_field(request, "endpoint")?;
        http_json(endpoint, "GET", "/v1/status", None)
    }

    fn payment_submit(&self, request: &Value) -> Result<Value, McpError> {
        let endpoint = str_field(request, "endpoint")?;
        let payment_hex = str_field(request, "payment_hex")?;
        // The node admits a machine payment only with the grant it claims to
        // spend under plus the owner's signature over that grant — three
        // fields beyond the payment itself. Forward them under the same
        // names `verify.authorization` already uses, so an agent builds one
        // shape and reuses it for both.
        let authorization_hex = str_field(request, "authorization_hex")?;
        let sigs_hex = str_field(request, "sigs_hex")?;
        let keys_hex = str_field(request, "keys_hex")?;
        http_json(
            endpoint,
            "POST",
            "/v1/payment/submit",
            Some(
                &json!({
                    "payment_hex": payment_hex,
                    "authorization_hex": authorization_hex,
                    "auth_sigs_hex": sigs_hex,
                    "auth_keys_hex": keys_hex,
                })
                .to_string(),
            ),
        )
    }

    fn receipt_submit(&self, request: &Value) -> Result<Value, McpError> {
        let endpoint = str_field(request, "endpoint")?;
        let receipt_hex = str_field(request, "receipt_hex")?;
        http_json(
            endpoint,
            "POST",
            "/v1/receipt",
            Some(&json!({ "receipt_hex": receipt_hex }).to_string()),
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A stable lowercase role name for JSON output.
fn role_name(role: srct_core::agent::AgentRole) -> &'static str {
    match role {
        srct_core::agent::AgentRole::Human => "human",
        srct_core::agent::AgentRole::Machine => "machine",
        srct_core::agent::AgentRole::Service => "service",
    }
}

fn session_error(e: SessionError) -> McpError {
    match &e {
        SessionError::Policy(_) => McpError::refused("policy_refused", e.to_string()),
        SessionError::Binding(_) => McpError::refused("session_binding", e.to_string()),
        _ => McpError::bad(e.to_string()),
    }
}

/// Parse an `X402Budget` from `max_amount_sat` + optional hex allow-lists.
/// An absent list means unbounded on that axis (same as `X402Budget::check`).
fn budget_from(v: &Value) -> Result<srct_core::x402::X402Budget, McpError> {
    let max_amount_sat = v
        .get("max_amount_sat")
        .and_then(Value::as_u64)
        .ok_or_else(|| McpError::bad("missing integer field `max_amount_sat`"))?;
    let mut allowed_recipients = Vec::new();
    if let Some(list) = v.get("allowed_recipients_hex") {
        let arr = list
            .as_array()
            .ok_or_else(|| McpError::bad("`allowed_recipients_hex` must be an array"))?;
        for item in arr {
            let s = item
                .as_str()
                .ok_or_else(|| McpError::bad("recipient entry must be a string"))?;
            allowed_recipients.push(
                address_from_hex(s.trim()).map_err(|e| McpError::bad(format!("recipient: {e}")))?,
            );
        }
    }
    let mut allowed_services = Vec::new();
    if let Some(list) = v.get("allowed_services_hex") {
        let arr = list
            .as_array()
            .ok_or_else(|| McpError::bad("`allowed_services_hex` must be an array"))?;
        for item in arr {
            let s = item
                .as_str()
                .ok_or_else(|| McpError::bad("service entry must be a string"))?;
            let raw = s.trim().trim_start_matches("0x").to_string();
            let bytes = hex::decode(&raw).map_err(|e| McpError::bad(format!("service: {e}")))?;
            let tag: [u8; 32] = bytes
                .try_into()
                .map_err(|_| McpError::bad("service tag must be 32 bytes"))?;
            allowed_services.push(tag);
        }
    }
    Ok(srct_core::x402::X402Budget {
        max_amount_sat,
        allowed_recipients,
        allowed_services,
    })
}

/// Optional `service_hex` field: absent means untagged.
fn opt_service(v: &Value) -> Result<Option<[u8; 32]>, McpError> {
    match v.get("service_hex").and_then(Value::as_str) {
        None => Ok(None),
        Some(s) => {
            let bytes = hex::decode(s.trim().trim_start_matches("0x"))
                .map_err(|e| McpError::bad(format!("service: {e}")))?;
            let tag: [u8; 32] = bytes
                .try_into()
                .map_err(|_| McpError::bad("service tag must be 32 bytes"))?;
            Ok(Some(tag))
        }
    }
}

/// A JSON array of hex strings, each under the hex cap.
fn hex_array(v: &Value, name: &str) -> Result<Vec<Vec<u8>>, McpError> {
    let arr = v
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| McpError::bad(format!("missing array field `{name}`")))?;
    if arr.len() > srct_core::delegation::MAX_DELEGATION_DEPTH {
        return Err(McpError::bad(format!("{name} over the delegation cap")));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| McpError::bad(format!("{name} entries must be strings")))?;
        let s = s.trim().trim_start_matches("0x");
        if s.len() > MAX_HEX_FIELD_CHARS {
            return Err(McpError::bad(format!("{name} entry over the hex cap")));
        }
        out.push(hex::decode(s).map_err(|e| McpError::bad(format!("{name}: {e}")))?);
    }
    Ok(out)
}

/// A signed policy from `policy_hex` + `sigs_hex` + `keys_hex`, verified on
/// the way in — an unverified grant never becomes a proof.
fn signed_policy_from(v: &Value) -> Result<srct_core::portable::SignedPolicy, McpError> {
    let policy_bytes = hex_field(v, "policy_hex")?;
    let policy = SpendPolicy::deserialize(&policy_bytes)
        .map_err(|e| McpError::bad(format!("policy: {e}")))?;
    let sigs_bytes = hex_field(v, "sigs_hex")?;
    let keys_bytes = hex_field(v, "keys_hex")?;
    let sigs = bundle_from_bytes(&sigs_bytes)?;
    let keys = bundle_from_bytes(&keys_bytes)?;
    let signed = srct_core::portable::SignedPolicy { policy, sigs, keys };
    signed
        .verify()
        .map_err(|e| McpError::refused("policy_invalid", e.to_string()))?;
    Ok(signed)
}

fn str_field<'a>(v: &'a Value, name: &str) -> Result<&'a str, McpError> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::bad(format!("missing string field `{name}`")))
}

fn u64_field(v: &Value, name: &str) -> Result<u64, McpError> {
    v.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| McpError::bad(format!("missing integer field `{name}`")))
}

/// Cap for one hex field in chars: the largest legitimate bundle is a few
/// KiB, and an uncapped `hex::decode` turns a hostile tool call into a big
/// allocation before anything validates it.
const MAX_HEX_FIELD_CHARS: usize = 8 * 1024 * 1024;

fn hex_field(v: &Value, name: &str) -> Result<Vec<u8>, McpError> {
    let s = str_field(v, name)?;
    let s = s.trim().trim_start_matches("0x");
    if s.len() > MAX_HEX_FIELD_CHARS {
        return Err(McpError::bad(format!("{name} over the hex cap")));
    }
    hex::decode(s).map_err(|e| McpError::bad(format!("{name}: {e}")))
}

fn bundle_from_bytes(bytes: &[u8]) -> Result<srct_core::sig::Bundle, McpError> {
    let mut reader = srct_core::ser::Reader::new(bytes);
    let bundle = srct_core::sig::Bundle::from_reader(&mut reader)
        .map_err(|e| McpError::bad(format!("bundle: {e}")))?;
    reader
        .expect_end()
        .map_err(|_| McpError::bad("bundle has trailing bytes"))?;
    Ok(bundle)
}

/// Cap for a single node response body (same 16 MiB as the miner reader).
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Is this IP a loopback address (v4 127/8 or v6 ::1)? Only loopback targets
/// receive the API bearer token and need no allow-list entry.
fn is_loopback_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.octets()[0] == 127,
        std::net::IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// MCP endpoint trust gate (token-theft fix). The bearer token is a credential:
/// it MUST NOT follow a caller-supplied URL to an untrusted host. Rules:
///
/// - The endpoint MUST be `host:port` (no scheme, no userinfo, no path); any
///   `http(s)://` prefix, `@`, or `/` is refused before resolution.
/// - Loopback (`127/8`, `::1`, or a hostname that resolves ONLY to loopback)
///   is trusted by default and is the only target that ever receives the
///   bearer token.
/// - Anything else is refused as `untrusted_endpoint` unless the exact
///   `host:port` appears in `SRCT_MCP_TRUSTED_ENDPOINTS` (comma-separated)
///   AND `SRCT_MCP_ALLOW_REMOTE=1` is set. Even then the bearer token is
///   NEVER sent (this client is plain HTTP with no TLS): remote calls go
///   out unauthenticated and fail closed at the node if it requires a token.
/// - Every resolved address must be identical-trusted: if DNS returns a mix
///   of loopback and non-loopback (rebinding), the endpoint is refused.
/// - Redirects are never followed (single request/response exchange); a 3xx
///   with a `Location` is a transport error, so a token can never be
///   re-sent to the redirect target.
/// - Endpoint values and tokens never appear in error strings.
fn check_endpoint_trust(host: &str, port: u16, addrs: &[SocketAddr]) -> Result<bool, McpError> {
    if addrs.is_empty() {
        return Err(McpError::bad("endpoint resolves to nothing"));
    }
    let all_loopback = addrs.iter().all(|a| is_loopback_ip(&a.ip()));
    let any_loopback = addrs.iter().any(|a| is_loopback_ip(&a.ip()));
    if all_loopback {
        return Ok(true);
    }
    if any_loopback {
        // Mixed resolution: classic DNS-rebinding shape. Refuse.
        return Err(McpError::refused(
            "untrusted_endpoint",
            "endpoint resolves to mixed loopback and non-loopback addresses",
        ));
    }
    let allow_remote = matches!(
        std::env::var("SRCT_MCP_ALLOW_REMOTE").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    );
    let allowlisted = std::env::var("SRCT_MCP_TRUSTED_ENDPOINTS")
        .map(|list| {
            list.split(',')
                .map(|e| e.trim().to_lowercase())
                .any(|e| e == format!("{}:{port}", host.to_lowercase()))
        })
        .unwrap_or(false);
    if allow_remote && allowlisted {
        return Ok(false);
    }
    Err(McpError::refused(
        "untrusted_endpoint",
        "endpoint is not loopback and is not in SRCT_MCP_TRUSTED_ENDPOINTS with SRCT_MCP_ALLOW_REMOTE=1",
    ))
}

/// A minimal `host:port` HTTP/1.1 client, so this crate stays dependency-free
/// and never reaches an address the caller did not name. Loopback is the
/// expected endpoint (the node API is loopback by default). When the operator
/// has set `SRCT_API_TOKEN`, it is sent as a bearer header ONLY to loopback
/// targets (see `check_endpoint_trust`): an exposed bind requires it
/// (SPEC.md §19.2); a loopback node ignores it. Non-loopback targets never
/// receive the token over this plaintext transport — a compromised or
/// malicious endpoint can therefore never harvest it. The token never appears
/// in error strings or logs.
fn http_json(
    endpoint: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Value, McpError> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(McpError::bad("malformed endpoint"));
    }
    if trimmed.contains("://") || trimmed.contains('@') || trimmed.contains('/') {
        return Err(McpError::refused(
            "untrusted_endpoint",
            "endpoint must be host:port with no scheme, userinfo, or path",
        ));
    }
    // Hostnames resolve via the system resolver (a plain IP:port parses as
    // before): operators behind DNS no longer hand-edit an IP in. The trust
    // gate below checks every resolved address, so a rebinding hostname that
    // flips between loopback and public between calls is refused.
    let mut addrs_iter = trimmed
        .to_socket_addrs()
        .map_err(|_| McpError::bad("malformed endpoint"))?;
    let addrs: Vec<SocketAddr> = addrs_iter.by_ref().take(16).collect();
    if addrs.is_empty() {
        return Err(McpError::bad("malformed endpoint"));
    }
    let (host, port) = match trimmed.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            let port: u16 = p.parse().map_err(|_| McpError::bad("malformed endpoint"))?;
            (h.to_string(), port)
        }
        _ => return Err(McpError::bad("malformed endpoint")),
    };
    let send_token = check_endpoint_trust(&host, port, &addrs)?;
    let addr: SocketAddr = addrs[0];
    let body = body.unwrap_or("");
    let auth = if send_token {
        match std::env::var("SRCT_API_TOKEN") {
            Ok(token) if !token.is_empty() => format!("Authorization: Bearer {token}\r\n"),
            _ => String::new(),
        }
    } else {
        String::new()
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         {auth}Connection: close\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );

    // Bounded connect: the read timeout below only starts after the socket
    // exists, so without this a black-holed endpoint hangs the tool call
    // (and whatever agent loop called it) with no deadline at all.
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| McpError::transport(format!("connect {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| McpError::transport(e.to_string()))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| McpError::transport(format!("send: {e}")))?;
    // Cap the response: a compromised or hostile node must not be able to
    // OOM this client with an unbounded body (same 16 MiB cap as the miner
    // and node readers).
    let mut buf = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| McpError::transport(format!("receive: {e}")))?;
    if buf.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(McpError::transport("node response over the 16 MiB cap"));
    }

    let text = String::from_utf8_lossy(&buf);
    // Strict status line: the version token must be present and the code a
    // real 3-digit status. The old split-whitespace parse accepted any
    // second token, so garbage before the headers read as success.
    let mut words = text.split_whitespace();
    let version = words.next().unwrap_or_default();
    let status = words.next().unwrap_or_default();
    if !version.starts_with("HTTP/") || status.len() != 3 {
        return Err(McpError::transport("node returned no HTTP status"));
    }
    let status: u16 = status
        .parse()
        .map_err(|_| McpError::transport("node returned no HTTP status"))?;
    let payload = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .ok_or_else(|| McpError::transport("node response has no header terminator"))?;
    let value: Value = serde_json::from_str(payload)
        .map_err(|e| McpError::transport(format!("node reply was not JSON: {e}")))?;

    if (300..400).contains(&status) {
        // Redirects are never followed: a malicious endpoint must not be able
        // to bounce this client (and its bearer header) to a second host.
        return Err(McpError::transport(
            "node sent a redirect, which is refused",
        ));
    }
    if status >= 400 {
        let code = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("node_refused");
        return Err(McpError::refused(
            match code {
                "bad_request" => "bad_request",
                "not_found" => "not_found",
                "payment_refused" => "payment_refused",
                "receipt_refused" => "receipt_refused",
                "receipt_conflict" => "receipt_conflict",
                _ => "node_refused",
            },
            value
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("node refused the request")
                .to_string(),
        ));
    }
    Ok(value)
}
