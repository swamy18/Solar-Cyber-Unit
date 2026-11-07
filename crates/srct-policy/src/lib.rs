//! Chain-agnostic agent policy engine.
//!
//! The policy layer (`agent`, `delegation`, `safety`, `tiers`, `x402` guard,
//! portable envelopes) is pure: no chain state, no clock, no I/O. This crate
//! is its cross-chain face — it depends on `srct-core` only for those pure
//! modules and re-exports the portable surface every rail speaks:
//!
//! - input: a [`PaymentIntent`] (who pays whom how much, where, when);
//! - output: a [`PolicyDecision`] — allow, deny, or approval-needed;
//! - travel: [`SignedPolicy`] (the grant any chain verifies), [`DelegationProof`]
//!   (the verifiable tree), [`BoundAuthorization`] (the short-lived,
//!   exact-transaction grant), and the hash-chained [`AuditExport`].
//!
//! Nothing here imports consensus (`chain`, `ledger`, `l2` state, mempool): a
//! foreign rail vendors this crate (or its TypeScript/Python bindings, which
//! speak the same JSON) and gets the same decisions the node gets.
//!
//! Honest weight note (Decision 31): this crate is a stable API facade, not
//! a slim dependency — vendoring it still compiles `srct-core` in full
//! (BLS, ML-DSA and all). Outsiders who only need answers should not vendor
//! Rust at all: speak HTTP (`POST /v1/policy/decide`,
//! `/v1/delegation/verify`, `/v1/audit/verify`) or use the TypeScript/Python
//! bindings against a node URL (`NodeHttpBackend`, stdlib only, no build
//! step). Extracting a crypto-light codec crate is recorded follow-up work,
//! deliberately not done here: splitting the signature bundles risks two
//! implementations of one rule.
//!
//! [`PaymentIntent`]: portable::PaymentIntent
//! [`PolicyDecision`]: portable::PolicyDecision
//! [`SignedPolicy`]: portable::SignedPolicy
//! [`DelegationProof`]: portable::DelegationProof
//! [`BoundAuthorization`]: portable::BoundAuthorization
//! [`AuditExport`]: safety::AuditExport

pub use srct_core::guard::{
    check_workload_credential, derive_action_hash, derive_context_hash, workload_key_fingerprint,
    Capability, Decision as GuardDecision, GuardApproval, GuardBook, GuardError, InfraPolicy,
    SignedCapability, WorkloadCredential, GUARD_POLICY_VERSION, MAX_APPROVAL_LIFETIME,
    MAX_CAP_LIFETIME, MAX_GUARD_REGISTRY,
};
pub use srct_core::portable::{
    evaluate_policy, BoundAuthorization, DecodedIntent, DelegationProof, PaymentIntent,
    PolicyDecision, SignedPolicy, MAX_BOUND_LIFETIME_BLOCKS, MAX_PORTABLE_JSON_LEN,
    PORTABLE_POLICY_VERSION,
};
pub use srct_core::safety::{AuditExport, AuditExportEntry, AuditLog};
pub use srct_core::x402::{GuardGrant, X402Budget, MAX_GUARD_LIFETIME_BLOCKS};

/// Decide from JSON on an explicitly named rail: parse a portable policy,
/// parse a payment intent, and answer allow / deny / approval-needed as
/// [`PolicyDecision`] JSON.
///
/// `network_id` is the rail asking the question — the caller's own network,
/// never a field copied from the (possibly agent-supplied) intent JSON. The
/// engine checks both bindings: an intent naming another network is a deny
/// (confused routing, not a grant for this rail), and a grant for another
/// rail is a deny via `evaluate_policy`.
///
/// Both JSON inputs are verified on parse (`SignedPolicy::from_json` refuses
/// an unverified grant), so a caller holding hostile bytes gets an `Err`,
/// never a forged allow. Stateful clauses (nonce freshness, tumbling-window
/// spend) are not committed here — this is the pre-check;
/// `PolicyBook::authorize` on the settling rail commits.
pub fn decide(
    network_id: &str,
    policy_portable_json: &str,
    intent_json: &str,
    approval_threshold_sat: Option<u64>,
) -> Result<String, String> {
    // The rail must name itself: an empty, over-long or padded id is a
    // caller bug, not a routing answer. Reject it as malformed so a
    // `decide("", …)` cannot read as a confusing deny.
    if network_id.is_empty() || network_id.len() > 64 {
        return Err("malformed rail network id".to_string());
    }
    if network_id.trim() != network_id {
        return Err("malformed rail network id".to_string());
    }
    let signed = SignedPolicy::from_json(policy_portable_json).map_err(|e| e.to_string())?;
    let intent: PaymentIntent =
        serde_json::from_str(intent_json).map_err(|_| "malformed intent json".to_string())?;
    let decoded = intent.decoded().map_err(|e| e.to_string())?;
    // The rail owns its identity: an intent claiming another network is
    // routed confusion, answered as deny — never re-framed silently.
    if intent.network_id != network_id {
        let decision = PolicyDecision::Deny {
            reason: format!(
                "intent is for network {}, asked on {network_id}",
                intent.network_id
            ),
        };
        return serde_json::to_string(&decision).map_err(|_| "decision json".to_string());
    }
    // The engine owns the grant binding: a grant for another rail is a
    // deny, not a transport error — the question was answered, and the
    // answer is no.
    let decision = evaluate_policy(
        &signed.policy,
        &decoded,
        network_id,
        intent.height,
        approval_threshold_sat,
    );
    serde_json::to_string(&decision).map_err(|_| "decision json".to_string())
}

/// Stateless Smart Gate check over hex inputs. No book, no commit: verifies
/// the owner's signature over the capability, the grant's risk-model
/// validity, then grant shape, network binding, validity window, capability
/// hash equality, expiry and lifetime cap. `cap_hex` MUST be a signed
/// [`SignedCapability`] envelope — a bare capability is public bytes anyone
/// can write down, so an unsigned envelope is denied as `UnsignedCapability`,
/// never allowed. Risk comes from the grant (`requires_approval`) OR-ed with
/// the caller's flag: callers escalate, never de-escalate. When the grant
/// binds a workload, the context is recomputed from the bound id and any
/// caller-supplied id is ignored. When the grant binds a workload identity
/// key, an optional `workload_cred_hex` envelope is verified as proof the
/// presenting process holds the key; a bound grant without a valid credential
/// denies (see [`guard_verify_full`]). Audience is NOT checked here — this
/// check is portable and node-agnostic; the admitting node enforces scoping.
/// Window counts and nonce replay need the stateful
/// `GuardBook::authorize_signed` on the settling side; this is the pre-check
/// every rail runs before that. It is NOT execution authorization: the
/// execution boundary recomputes the action hash from the preimage it
/// observes (see `GuardBook::authorize_signed`).
#[allow(clippy::too_many_arguments)]
pub fn guard_verify(
    network_id: &str,
    policy_hex: &str,
    cap_hex: &str,
    agent_id_hex: &str,
    action_hash_hex: &str,
    workload_id_hex: &str,
    height: u64,
    high_risk: bool,
) -> Result<String, String> {
    guard_verify_full(
        network_id,
        policy_hex,
        cap_hex,
        agent_id_hex,
        action_hash_hex,
        workload_id_hex,
        height,
        high_risk,
        None,
    )
}

/// [`guard_verify`] with an optional workload proof-of-possession credential
/// (`workload_cred_hex`, a signed [`WorkloadCredential`] envelope). Required
/// for key-bound grants; ignored for unbound (legacy) ones.
#[allow(clippy::too_many_arguments)]
pub fn guard_verify_full(
    network_id: &str,
    policy_hex: &str,
    cap_hex: &str,
    agent_id_hex: &str,
    action_hash_hex: &str,
    workload_id_hex: &str,
    height: u64,
    high_risk: bool,
    workload_cred_hex: Option<&str>,
) -> Result<String, String> {
    use srct_core::guard::{
        check_workload_credential, InfraPolicy, SignedCapability, WorkloadCredential,
    };
    use srct_core::hash::{hash_from_hex, hash_to_hex};
    if network_id.is_empty() || network_id.len() > 64 {
        return Err("malformed rail network id".to_string());
    }
    if network_id.trim() != network_id {
        return Err("malformed rail network id".to_string());
    }
    let policy_bytes = hex::decode(policy_hex.trim().trim_start_matches("0x"))
        .map_err(|_| "malformed policy hex".to_string())?;
    let policy = InfraPolicy::deserialize(&policy_bytes).map_err(|e| e.to_string())?;
    let cap_bytes = hex::decode(cap_hex.trim().trim_start_matches("0x"))
        .map_err(|_| "malformed capability hex".to_string())?;
    let signed = SignedCapability::deserialize(&cap_bytes)
        .map_err(|_| "capability is not signed".to_string())?;
    signed.verify(&policy).map_err(|e| e.to_string())?;
    policy.validate().map_err(|e| e.to_string())?;
    let cap = &signed.cap;
    let agent_bytes = hex::decode(agent_id_hex.trim().trim_start_matches("0x"))
        .map_err(|_| "malformed agent id hex".to_string())?;
    if agent_bytes.len() != 20 {
        return Err("malformed agent id hex".to_string());
    }
    let mut agent_id = [0u8; 20];
    agent_bytes
        .iter()
        .enumerate()
        .for_each(|(i, b)| agent_id[i] = *b);
    let action_hash =
        hash_from_hex(action_hash_hex).map_err(|_| "malformed action hash".to_string())?;
    let workload_id =
        hash_from_hex(workload_id_hex).map_err(|_| "malformed workload id".to_string())?;
    // Bound grants recompute from the bound id; the presented id is ignored.
    // (The version gate lives in `InfraPolicy::deserialize`: only the
    // current layout and the legacy v1 layout decode.)
    let expected_context = derive_context_hash(&policy.effective_workload(&workload_id), height);
    if policy.network_id != network_id {
        return Ok(json_deny(
            "grant is for another network",
            network_id,
            height,
        ));
    }
    if policy.revoked {
        return Ok(json_deny("grant revoked", network_id, height));
    }
    if height < policy.valid_from_height {
        return Ok(json_deny("grant not yet valid", network_id, height));
    }
    if height >= policy.valid_until_height {
        return Ok(json_deny("grant expired", network_id, height));
    }
    if policy.agent_id != agent_id {
        return Ok(json_deny("cross-principal capability", network_id, height));
    }
    if cap.nonce == 0 {
        return Ok(json_deny("capability nonce is zero", network_id, height));
    }
    if cap.policy_hash != policy.hash() {
        return Ok(json_deny(
            "capability does not name this grant",
            network_id,
            height,
        ));
    }
    if cap.action_hash != action_hash {
        return Ok(json_deny("action hash mismatch", network_id, height));
    }
    if cap.context_hash != expected_context {
        return Ok(json_deny("context hash mismatch", network_id, height));
    }
    // Possession: one shared rule with the stateful admission. Key-bound
    // grants deny without a fresh credential for this exact admission.
    let cred = match workload_cred_hex {
        None => None,
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
                .map_err(|_| "malformed workload credential hex".to_string())?;
            Some(
                WorkloadCredential::deserialize(&bytes)
                    .map_err(|e| format!("workload credential: {e}"))?,
            )
        }
    };
    if let Err(e) = check_workload_credential(
        &policy,
        cap,
        &action_hash,
        &expected_context,
        height,
        cred.as_ref(),
    ) {
        return Ok(json_deny(&e.to_string(), network_id, height));
    }
    if height >= cap.expiry_height {
        return Ok(json_deny("capability expired", network_id, height));
    }
    if cap.expiry_height.saturating_sub(height) > MAX_CAP_LIFETIME {
        return Ok(json_deny(
            "capability lifetime exceeds cap",
            network_id,
            height,
        ));
    }
    // Risk is owner-set; the caller flag can only escalate.
    if high_risk || policy.requires_approval {
        return Ok(format!(
            "{{\"decision\":\"needs_approval\",\"reason\":\"high-risk action needs a signed approval from the designated approver\",\"network_id\":\"{network_id}\",\"height\":{height},\"policy_hash\":\"{}\"}}",
            hash_to_hex(&policy.hash())
        ));
    }
    Ok(format!(
        "{{\"decision\":\"allow\",\"network_id\":\"{network_id}\",\"height\":{height},\"policy_hash\":\"{}\"}}",
        hash_to_hex(&policy.hash())
    ))
}

fn json_deny(reason: &str, network_id: &str, height: u64) -> String {
    format!("{{\"decision\":\"deny\",\"reason\":\"{reason}\",\"network_id\":\"{network_id}\",\"height\":{height}}}")
}

/// Verify a delegation proof from JSON. Returns `leaf_agent/leaf_policy_hash`
/// on success so the caller can route without re-parsing.
pub fn verify_proof(proof_json: &str) -> Result<String, String> {
    let proof = DelegationProof::from_json(proof_json).map_err(|e| e.to_string())?;
    Ok(format!(
        "{}/{}",
        hex::encode(proof.leaf().agent_id),
        srct_core::hash::hash_to_hex(&proof.leaf().hash())
    ))
}

/// Verify an exported audit chain from JSON. Returns the entry count.
pub fn verify_audit(audit_json: &str) -> Result<usize, String> {
    AuditLog::verify_export_json(audit_json).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::agent::{
        derive_agent_id, derive_sub_agent_id, AgentRole, SpendPolicy, POLICY_VERSION,
    };
    use srct_core::l2::Auth;
    use srct_core::wallet::Wallet;

    const NETWORK: &str = "srct/testnet";

    fn owner() -> Wallet {
        Wallet::new_random("owner")
    }

    fn root_policy(wallet: &Wallet) -> SpendPolicy {
        let owner = wallet.address().unwrap();
        SpendPolicy {
            version: POLICY_VERSION,
            network_id: NETWORK.to_string(),
            agent_id: derive_agent_id(NETWORK, AgentRole::Machine, &owner),
            owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 1_000,
            window_blocks: 100,
            cumulative_max_sat: 5_000,
            allowed_recipients: vec![[1u8; 20]],
            allowed_services: vec![],
            not_before_height: 0,
            expires_at_height: 10_000,
            revoked: false,
            parent_agent_id: None,
        }
    }

    fn signed_json(wallet: &Wallet, policy: &SpendPolicy) -> String {
        let keys = Auth::keys_for(wallet).unwrap();
        let sigs = Auth::sigs_for(wallet, &policy.signing_hash()).unwrap();
        SignedPolicy {
            policy: policy.clone(),
            sigs,
            keys,
        }
        .to_json()
    }

    fn intent_for(policy: &SpendPolicy, amount_sat: u64) -> PaymentIntent {
        PaymentIntent {
            agent_id: hex::encode(policy.agent_id),
            recipient: srct_core::hash::address_to_hex(&policy.allowed_recipients[0]),
            amount_sat,
            service: None,
            height: 100,
            nonce: 1,
            network_id: NETWORK.to_string(),
        }
    }

    fn decide_parsed(
        network_id: &str,
        policy_json: &str,
        intent: &PaymentIntent,
        threshold: Option<u64>,
    ) -> PolicyDecision {
        let out = decide(
            network_id,
            policy_json,
            &serde_json::to_string(intent).unwrap(),
            threshold,
        )
        .expect("a well-formed pair must answer");
        serde_json::from_str(&out).expect("the answer is decision JSON")
    }

    #[test]
    fn decide_json_answers_allow_deny_and_approval_needed() {
        let wallet = owner();
        let policy = root_policy(&wallet);
        let policy_json = signed_json(&wallet, &policy);

        assert_eq!(
            decide_parsed(NETWORK, &policy_json, &intent_for(&policy, 500), None),
            PolicyDecision::Allow
        );
        // Over the per-tx cap is a deny with the reason, never a forged allow.
        let denied = decide_parsed(NETWORK, &policy_json, &intent_for(&policy, 50_000), None);
        assert!(matches!(denied, PolicyDecision::Deny { .. }), "{denied:?}");
        // Inside the cap but above the threshold is gated, not refused.
        let gated = decide_parsed(NETWORK, &policy_json, &intent_for(&policy, 500), Some(100));
        assert!(
            matches!(gated, PolicyDecision::NeedsApproval { .. }),
            "{gated:?}"
        );
        // A stranger recipient is a deny.
        let mut stranger = intent_for(&policy, 10);
        stranger.recipient = srct_core::hash::address_to_hex(&[9u8; 20]);
        let denied = decide_parsed(NETWORK, &policy_json, &stranger, None);
        assert!(matches!(denied, PolicyDecision::Deny { .. }), "{denied:?}");
        // A revoked grant denies from the same JSON shape.
        let mut revoked = policy.clone();
        revoked.revoked = true;
        let revoked_json = signed_json(&wallet, &revoked);
        let denied = decide_parsed(NETWORK, &revoked_json, &intent_for(&revoked, 10), None);
        assert!(matches!(denied, PolicyDecision::Deny { .. }), "{denied:?}");
    }

    #[test]
    fn decide_refuses_hostile_inputs_by_name_not_silence() {
        let wallet = owner();
        let policy = root_policy(&wallet);
        let policy_json = signed_json(&wallet, &policy);
        // Not JSON at all.
        assert!(decide(NETWORK, "not json", "{}", None).is_err());
        // Valid JSON, wrong shape.
        assert!(decide(NETWORK, &policy_json, r#"{"amount_sat": 1}"#, None).is_err());
        // A grant for another rail is a deny, not a transport error.
        let mut foreign = intent_for(&policy, 10);
        foreign.network_id = "srct/elsewhere".to_string();
        let out = decide(
            NETWORK,
            &policy_json,
            &serde_json::to_string(&foreign).unwrap(),
            None,
        )
        .expect("cross-network intents are answered, not refused");
        let decision: PolicyDecision = serde_json::from_str(&out).unwrap();
        assert!(
            matches!(&decision, PolicyDecision::Deny { reason } if reason.contains("srct/testnet")),
            "{decision:?}"
        );
        // A routing-confused document (hashes rewritten) is refused at parse.
        let mut doc: serde_json::Value = serde_json::from_str(&policy_json).unwrap();
        doc["policy_hash"] = serde_json::Value::String("ab".repeat(32));
        assert!(decide(
            NETWORK,
            &doc.to_string(),
            &serde_json::to_string(&intent_for(&policy, 10)).unwrap(),
            None
        )
        .is_err());
    }

    #[test]
    fn decide_on_another_rail_denies_a_matching_intent() {
        // The bypass this signature closes: a testnet grant plus a testnet
        // intent used to answer Allow with no rail identity in the call, so
        // a mainnet service vendoring the crate had no way to get a Deny.
        // The rail now names itself, and both the intent and the grant must
        // match it.
        let wallet = owner();
        let policy = root_policy(&wallet);
        let policy_json = signed_json(&wallet, &policy);
        let intent_json = serde_json::to_string(&intent_for(&policy, 10)).unwrap();
        let allow: PolicyDecision =
            serde_json::from_str(&decide(NETWORK, &policy_json, &intent_json, None).unwrap())
                .unwrap();
        assert_eq!(allow, PolicyDecision::Allow);
        // Same bytes, asked on mainnet: deny, not allow.
        let out = decide("srct/mainnet", &policy_json, &intent_json, None)
            .expect("a rail mismatch is answered, not refused");
        let decision: PolicyDecision = serde_json::from_str(&out).unwrap();
        assert!(
            matches!(&decision, PolicyDecision::Deny { .. }),
            "{decision:?}"
        );
    }

    #[test]
    fn verify_proof_names_the_leaf_and_refuses_a_widened_link() {
        let wallet = owner();
        let root = root_policy(&wallet);
        let child_agent = derive_sub_agent_id(NETWORK, &root.agent_id, AgentRole::Machine);
        let child = SpendPolicy {
            agent_id: child_agent,
            parent_agent_id: Some(root.agent_id),
            per_tx_max_sat: 100,
            cumulative_max_sat: 500,
            window_blocks: 10,
            not_before_height: 5,
            expires_at_height: 5_000,
            ..root.clone()
        };
        let keys = Auth::keys_for(&wallet).unwrap();
        let link = |policy: &SpendPolicy| SignedPolicy {
            policy: policy.clone(),
            sigs: Auth::sigs_for(&wallet, &policy.signing_hash()).unwrap(),
            keys: keys.clone(),
        };
        let proof = DelegationProof::new(vec![link(&root), link(&child)]).unwrap();
        let named = verify_proof(&proof.to_json()).expect("a narrowed ancestry verifies");
        assert_eq!(
            named,
            format!(
                "{}/{}",
                hex::encode(child.agent_id),
                srct_core::hash::hash_to_hex(&child.hash())
            )
        );
        // A widened leaf keeps a valid signature but breaks the chain rule.
        let mut wide = child.clone();
        wide.cumulative_max_sat = 9_999;
        let bad = DelegationProof::new(vec![link(&root), link(&wide)]).unwrap();
        assert!(verify_proof(&bad.to_json()).is_err());
        // Garbage is not a proof.
        assert!(verify_proof("not json").is_err());
    }

    #[test]
    fn verify_audit_counts_entries_and_refuses_rewritten_history() {
        let mut log = AuditLog::default();
        log.push("authorize", None, Some(500), "grant".to_string())
            .unwrap();
        log.push("payment", Some([1u8; 32]), Some(500), "submit".to_string())
            .unwrap();
        assert_eq!(verify_audit(&log.export_json()).unwrap(), 2);
        let mut forged = log.export();
        forged.entries[0].detail = "forged".to_string();
        assert!(verify_audit(&serde_json::to_string(&forged).unwrap()).is_err());
        let mut truncated = log.export();
        truncated.tip = srct_core::hash::hash_to_hex(&[0u8; 32]);
        assert!(verify_audit(&serde_json::to_string(&truncated).unwrap()).is_err());
    }

    #[test]
    fn guard_and_engine_agree_on_a_fitting_payment() {
        let wallet = owner();
        let policy = root_policy(&wallet);
        // The pre-sign guard (budget + short window) and the engine seam
        // answer the same payment the same way: both allow here.
        let budget = X402Budget {
            max_amount_sat: 600,
            allowed_recipients: Some(vec![[1u8; 20]]),
            allowed_services: Some(vec![]),
        };
        let grant = budget
            .check_guarded(500, &[1u8; 20], &None, 100, 110)
            .expect("fits the budget and the window");
        assert_eq!(grant.expires_at_height, 110);
        let policy_json = signed_json(&wallet, &policy);
        assert_eq!(
            decide_parsed(NETWORK, &policy_json, &intent_for(&policy, 500), None),
            PolicyDecision::Allow
        );
        // And both refuse the same over-budget payment, each by name.
        assert!(budget
            .check_guarded(700, &[1u8; 20], &None, 100, 110)
            .is_err());
        let denied = decide_parsed(NETWORK, &policy_json, &intent_for(&policy, 50_000), None);
        assert!(matches!(denied, PolicyDecision::Deny { .. }), "{denied:?}");
    }

    #[test]
    fn guard_verify_allows_exact_and_denies_drift() {
        use srct_core::guard::{
            derive_context_hash, Capability, InfraPolicy, SignedCapability, GUARD_POLICY_VERSION,
        };
        let owner_wallet = Wallet::new_random("guard-owner");
        let owner_addr = owner_wallet.address().unwrap();
        let agent_id = derive_agent_id(NETWORK, AgentRole::Machine, &owner_addr);
        let policy = InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: NETWORK.to_string(),
            agent_id,
            owner: owner_addr,
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 10,
            valid_until_height: 1000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: false,
            approver: [0u8; 20],
            workload_id: [0u8; 32],
            workload_key: [0u8; 32],
        };
        let action_hash = [1u8; 32];
        let workload = [2u8; 32];
        let height = 50u64;
        let ctx = derive_context_hash(&workload, height);
        let cap = Capability {
            policy_hash: policy.hash(),
            action_hash,
            context_hash: ctx,
            expiry_height: height + 10,
            nonce: 1,
            audience: [0u8; 32],
        };
        let signed = SignedCapability::issue(&owner_wallet, &cap).unwrap();
        let policy_hex = hex::encode(policy.serialize());
        let cap_hex = hex::encode(signed.serialize());
        let out = guard_verify(
            NETWORK,
            &policy_hex,
            &cap_hex,
            &hex::encode(agent_id),
            &srct_core::hash::hash_to_hex(&action_hash),
            &srct_core::hash::hash_to_hex(&workload),
            height,
            false,
        )
        .expect("well-formed guard inputs must answer");
        assert!(out.contains("\"allow\""), "{out}");
        let drifted = guard_verify(
            NETWORK,
            &policy_hex,
            &cap_hex,
            &hex::encode(agent_id),
            &srct_core::hash::hash_to_hex(&[0xFFu8; 32]),
            &srct_core::hash::hash_to_hex(&workload),
            height,
            false,
        )
        .expect("drift must answer deny, not error");
        assert!(drifted.contains("action hash mismatch"), "{drifted}");
        let gated = guard_verify(
            NETWORK,
            &policy_hex,
            &cap_hex,
            &hex::encode(agent_id),
            &srct_core::hash::hash_to_hex(&action_hash),
            &srct_core::hash::hash_to_hex(&workload),
            height,
            true,
        )
        .expect("high-risk must answer");
        assert!(gated.contains("needs_approval"), "{gated}");
    }

    #[test]
    fn guard_verify_enforces_owner_set_risk_and_bound_workload() {
        use srct_core::guard::{
            derive_context_hash, Capability, InfraPolicy, SignedCapability, GUARD_POLICY_VERSION,
        };
        let owner_wallet = Wallet::new_random("guard-owner-3");
        let owner_addr = owner_wallet.address().unwrap();
        let approver_wallet = Wallet::new_random("guard-approver-3");
        let agent_id = derive_agent_id(NETWORK, AgentRole::Machine, &owner_addr);
        let bound = [7u8; 32];
        let policy = InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: NETWORK.to_string(),
            agent_id,
            owner: owner_addr,
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 10,
            valid_until_height: 1000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: true,
            approver: approver_wallet.address().unwrap(),
            workload_id: bound,
            workload_key: [0u8; 32],
        };
        let height = 50u64;
        let cap = Capability {
            policy_hash: policy.hash(),
            action_hash: [1u8; 32],
            context_hash: derive_context_hash(&bound, height),
            expiry_height: height + 10,
            nonce: 1,
            audience: [0u8; 32],
        };
        let signed = SignedCapability::issue(&owner_wallet, &cap).unwrap();
        let policy_hex = hex::encode(policy.serialize());
        let cap_hex = hex::encode(signed.serialize());
        // Caller claims low risk; the grant disagrees: gated anyway.
        let out = guard_verify(
            NETWORK,
            &policy_hex,
            &cap_hex,
            &hex::encode(agent_id),
            &srct_core::hash::hash_to_hex(&[1u8; 32]),
            &srct_core::hash::hash_to_hex(&bound),
            height,
            false,
        )
        .expect("owner-set risk must answer");
        assert!(out.contains("needs_approval"), "{out}");
        // A spoofed presented workload id is ignored for bound grants.
        let out = guard_verify(
            NETWORK,
            &policy_hex,
            &cap_hex,
            &hex::encode(agent_id),
            &srct_core::hash::hash_to_hex(&[1u8; 32]),
            &srct_core::hash::hash_to_hex(&[9u8; 32]),
            height,
            false,
        )
        .expect("bound workload must answer");
        assert!(out.contains("needs_approval"), "{out}");
        // A self-approval grant (owner as approver) never verifies: re-issue
        // the capability against it so the signature passes and the risk
        // model itself is what refuses.
        let mut bad = policy.clone();
        bad.approver = owner_addr;
        let bad_cap = Capability {
            policy_hash: bad.hash(),
            ..cap.clone()
        };
        let bad_signed = SignedCapability::issue(&owner_wallet, &bad_cap).unwrap();
        let err = guard_verify(
            NETWORK,
            &hex::encode(bad.serialize()),
            &hex::encode(bad_signed.serialize()),
            &hex::encode(agent_id),
            &srct_core::hash::hash_to_hex(&[1u8; 32]),
            &srct_core::hash::hash_to_hex(&bound),
            height,
            false,
        )
        .expect_err("owner-as-approver must not verify");
        assert!(err.contains("independent approver"), "{err}");
    }

    #[test]
    fn guard_verify_full_enforces_workload_possession() {
        use srct_core::guard::{
            derive_context_hash, workload_key_fingerprint, Capability, InfraPolicy,
            SignedCapability, WorkloadCredential, GUARD_POLICY_VERSION,
        };
        let owner_wallet = Wallet::new_random("guard-owner-4");
        let owner_addr = owner_wallet.address().unwrap();
        let workload_wallet = Wallet::new_random("guard-workload-4");
        let workload_keys = srct_core::l2::Auth::keys_for(&workload_wallet).unwrap();
        let agent_id = derive_agent_id(NETWORK, AgentRole::Machine, &owner_addr);
        let policy = InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: NETWORK.to_string(),
            agent_id,
            owner: owner_addr,
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 10,
            valid_until_height: 1000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: false,
            approver: [0u8; 20],
            workload_id: [0u8; 32],
            workload_key: workload_key_fingerprint(&workload_keys),
        };
        let height = 50u64;
        let action_hash = [1u8; 32];
        let presented = [2u8; 32];
        let ctx = derive_context_hash(&presented, height);
        let cap = Capability {
            policy_hash: policy.hash(),
            action_hash,
            context_hash: ctx,
            expiry_height: height + 10,
            nonce: 1,
            audience: [0u8; 32],
        };
        let signed = SignedCapability::issue(&owner_wallet, &cap).unwrap();
        let policy_hex = hex::encode(policy.serialize());
        let cap_hex = hex::encode(signed.serialize());
        let check = |cred_hex: Option<String>| {
            guard_verify_full(
                NETWORK,
                &policy_hex,
                &cap_hex,
                &hex::encode(agent_id),
                &srct_core::hash::hash_to_hex(&action_hash),
                &srct_core::hash::hash_to_hex(&presented),
                height,
                false,
                cred_hex.as_deref(),
            )
        };
        // No credential on a key-bound grant: deny, never allow.
        let out = check(None).expect("a key-bound grant must answer");
        assert!(out.contains("deny") && out.contains("credential"), "{out}");
        // Stranger's key: impersonation denies by fingerprint.
        let stranger = Wallet::new_random("guard-stranger-4");
        let fake =
            WorkloadCredential::issue(&stranger, &policy.hash(), &cap, &action_hash, &ctx, height)
                .unwrap();
        let out = check(Some(hex::encode(fake.serialize()))).expect("forgery must answer");
        assert!(out.contains("deny"), "{out}");
        // Honest proof of possession: allow.
        let cred = WorkloadCredential::issue(
            &workload_wallet,
            &policy.hash(),
            &cap,
            &action_hash,
            &ctx,
            height,
        )
        .unwrap();
        let out = check(Some(hex::encode(cred.serialize()))).expect("proof must answer");
        assert!(out.contains("\"allow\""), "{out}");
    }

    #[test]
    fn guard_verify_refuses_an_unsigned_capability() {
        use srct_core::guard::{
            derive_context_hash, Capability, InfraPolicy, GUARD_POLICY_VERSION,
        };
        let owner_wallet = Wallet::new_random("guard-owner-2");
        let owner_addr = owner_wallet.address().unwrap();
        let agent_id = derive_agent_id(NETWORK, AgentRole::Machine, &owner_addr);
        let policy = InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: NETWORK.to_string(),
            agent_id,
            owner: owner_addr,
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 10,
            valid_until_height: 1000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: false,
            approver: [0u8; 20],
            workload_id: [0u8; 32],
            workload_key: [0u8; 32],
        };
        let workload = [2u8; 32];
        let height = 50u64;
        let raw = Capability {
            policy_hash: policy.hash(),
            action_hash: [1u8; 32],
            context_hash: derive_context_hash(&workload, height),
            expiry_height: height + 10,
            nonce: 1,
            audience: [0u8; 32],
        };
        let policy_hex = hex::encode(policy.serialize());
        // A bare capability any observer could write down: denied, never allowed.
        let err = guard_verify(
            NETWORK,
            &policy_hex,
            &hex::encode(raw.serialize()),
            &hex::encode(agent_id),
            &srct_core::hash::hash_to_hex(&[1u8; 32]),
            &srct_core::hash::hash_to_hex(&workload),
            height,
            false,
        )
        .expect_err("an unsigned capability must not verify");
        assert!(err.contains("not signed"), "{err}");
    }
}
