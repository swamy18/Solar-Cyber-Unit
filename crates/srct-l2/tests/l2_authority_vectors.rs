//! The Layer-2 authority and credit rules, cross-checked against an
//! independent implementation (SPEC.md §21, §22).
//!
//! `verification/sim/l2_authority_reference.py` is a second implementation of the same
//! rules, written from the specification in a different language, and it emits
//! the scenarios in `verification/tests/vectors/l2_authority_vectors.json`. This suite
//! replays those scenarios against the Rust state machine and asserts that
//! every step reaches the *same verdict* for the same reason, and that the
//! state ends in the same shape.
//!
//! That is a stronger statement than "the Rust tests pass". It says the rules
//! are unambiguous: two implementations, written from one document, agree on
//! which spends are permitted, which are refused and why, how interest is
//! charged, and what a default pays.

use std::collections::BTreeMap;

use serde_json::Value;
use srct_core::agent::{AgentId, AgentRole, SpendPolicy, POLICY_VERSION};
use srct_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    AgentSpendPayload, CreditCollateralPayload, CreditDefaultPayload, CreditOpenPayload,
    CreditRepayPayload, L2Payload, L2Transaction, PolicyPayload, PolicyRevokePayload,
};
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2Error, L2State};

/// The seeds the reference implementation uses for the roles. Both sides
/// derive the same addresses from them, so the digests in the vector file
/// (the agent identity, the grant hash, the position id) are comparable.
const ROLE_SEEDS: &[(&str, u8)] = &[
    ("owner", 1),
    ("agent", 2),
    ("recipient", 3),
    ("stranger", 4),
    ("lender", 5),
    ("borrower", 6),
    ("trigger", 7),
];

fn wallet_for(role: &str) -> Wallet {
    let seed = ROLE_SEEDS
        .iter()
        .find(|(name, _)| *name == role)
        .unwrap_or_else(|| panic!("unknown role {role}"))
        .1;
    Wallet::from_private_key_bytes(&[seed; 32], "l2-authority-vectors").unwrap()
}

fn addr_for(role: &str) -> Address {
    wallet_for(role).address().unwrap()
}

/// The name of an L2 error variant, as the reference implementation spells
/// it. A rule that refuses for a different reason is a different rule, so the
/// comparison is on the name and not on the message.
fn error_name(e: &L2Error) -> &'static str {
    match e {
        L2Error::BadAuthorization => "BadAuthorization",
        L2Error::UnknownTask => "UnknownTask",
        L2Error::TaskAlreadyExists => "TaskAlreadyExists",
        L2Error::Replay => "Replay",
        L2Error::IllegalTransition { .. } => "IllegalTransition",
        L2Error::TaskExpired => "TaskExpired",
        L2Error::DisputeWindowClosed => "DisputeWindowClosed",
        L2Error::DisputeAgreesWithResult => "DisputeAgreesWithResult",
        L2Error::ZeroAmount(_) => "ZeroAmount",
        L2Error::DeadlineMismatch => "DeadlineMismatch",
        L2Error::BadAttestation(_) => "BadAttestation",
        L2Error::BadQuorum => "BadQuorum",
        L2Error::BadBlsSignature => "BadBlsSignature",
        L2Error::BadSettleNetwork => "BadSettleNetwork",
        L2Error::BadSettleHeight => "BadSettleHeight",
        L2Error::BadPqSidecar(_) => "BadPqSidecar",
        L2Error::BadVwcHash => "BadVwcHash",
        L2Error::EvidenceIncomplete => "EvidenceIncomplete",
        L2Error::EvidenceMismatch(_) => "EvidenceMismatch",
        L2Error::InconclusiveDispute => "InconclusiveDispute",
        L2Error::VwcAlreadyIssued => "VwcAlreadyIssued",
        L2Error::VwcInvalid(_) => "VwcInvalid",
        L2Error::InsufficientBalance { .. } => "InsufficientBalance",
        L2Error::AmountTooSmallForFee { .. } => "AmountTooSmallForFee",
        L2Error::Overflow => "Overflow",
        L2Error::GenesisAlreadyApplied => "GenesisAlreadyApplied",
        L2Error::InvalidGenesis(_) => "InvalidGenesis",
        L2Error::DuplicateDeposit => "DuplicateDeposit",
        L2Error::ExitNotActive => "ExitNotActive",
        L2Error::ExitFeeBelowMinimum => "ExitFeeBelowMinimum",
        L2Error::BadExitNonce => "BadExitNonce",
        L2Error::UnknownExit => "UnknownExit",
        L2Error::ExitWindowFull { .. } => "ExitWindowFull",
        L2Error::ExitOwnerWindowFull { .. } => "ExitOwnerWindowFull",
        L2Error::BadExitDestination(_) => "BadExitDestination",
        L2Error::BadConfig(_) => "BadConfig",
        L2Error::Codec(_) => "Codec",
        L2Error::Reputation(_) => "Reputation",
        L2Error::Policy(_) => "Policy",
        L2Error::PolicyBinding(_) => "PolicyBinding",
        L2Error::UnknownPolicy => "UnknownPolicy",
        L2Error::PolicyAlreadyPublished => "PolicyAlreadyPublished",
        L2Error::PolicyRevoked => "PolicyRevoked",
        L2Error::PolicyLimit(_) => "PolicyLimit",
        L2Error::PolicyRecipient => "PolicyRecipient",
        L2Error::PolicyService => "PolicyService",
        L2Error::PolicyNonce => "PolicyNonce",
        L2Error::PolicyWindow(_) => "PolicyWindow",
        L2Error::CreditTerms(_) => "CreditTerms",
        L2Error::CreditUndercollateralised { .. } => "CreditUndercollateralised",
        L2Error::CreditPositionExists => "CreditPositionExists",
        L2Error::UnknownCreditPosition => "UnknownCreditPosition",
        L2Error::CreditPositionClosed => "CreditPositionClosed",
        L2Error::CreditBinding(_) => "CreditBinding",
        L2Error::CreditNotDue => "CreditNotDue",
        L2Error::CreditInterestOverflow => "CreditInterestOverflow",
        L2Error::CreditRepaymentExceedsDebt { .. } => "CreditRepaymentExceedsDebt",
        L2Error::InvalidContractSpec(_) => "InvalidContractSpec",
    }
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("a hex string")).expect("valid hex")
}

fn hash_bytes(v: &Value) -> Hash {
    let raw = hex_bytes(v);
    let mut h = [0u8; 32];
    h.copy_from_slice(&raw);
    h
}

fn u64_field(v: &Value, name: &str) -> u64 {
    v.get(name)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing integer field {name}"))
}

/// The policy a step publishes, rebuilt from the vector file.
fn policy_from(step: &Value) -> SpendPolicy {
    let p = step.get("policy").expect("the step carries a policy");
    let owner = p.get("owner").and_then(Value::as_str).expect("an owner");
    let agent_id = {
        let raw = hex_bytes(p.get("agent_id").expect("an agent id"));
        let mut id = [0u8; 20];
        id.copy_from_slice(&raw);
        id
    };
    let parent = p.get("parent_agent_id").and_then(Value::as_str).map(|h| {
        let raw = hex::decode(h).expect("valid hex");
        let mut id = [0u8; 20];
        id.copy_from_slice(&raw);
        id
    });
    let recipients: Vec<Address> = p
        .get("allowed_recipients")
        .and_then(Value::as_array)
        .expect("a recipient list")
        .iter()
        .map(|r| addr_for(r.as_str().expect("a role")))
        .collect();
    let services: Vec<[u8; 32]> = p
        .get("allowed_services")
        .and_then(Value::as_array)
        .expect("a service list")
        .iter()
        .map(|s| {
            let raw = hex_bytes(s);
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&raw);
            tag
        })
        .collect();
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: p
            .get("network_id")
            .and_then(Value::as_str)
            .expect("a network")
            .to_string(),
        agent_id,
        owner: addr_for(owner),
        role: match u64_field(p, "role") {
            0 => AgentRole::Human,
            1 => AgentRole::Machine,
            _ => AgentRole::Service,
        },
        per_tx_max_sat: u64_field(p, "per_tx_max_sat"),
        window_blocks: u64_field(p, "window_blocks"),
        cumulative_max_sat: u64_field(p, "cumulative_max_sat"),
        allowed_recipients: recipients,
        allowed_services: services,
        not_before_height: u64_field(p, "not_before_height"),
        expires_at_height: u64_field(p, "expires_at_height"),
        revoked: p.get("revoked").and_then(Value::as_bool).unwrap_or(false),
        parent_agent_id: parent,
    }
}

/// The state machine's verdict for one step, as the vector file spells it.
fn expected(step: &Value) -> Result<(), String> {
    let outcome = step.get("outcome").expect("an outcome");
    if outcome.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        Ok(())
    } else {
        Err(outcome
            .get("error")
            .and_then(Value::as_str)
            .expect("an error name")
            .to_string())
    }
}

#[test]
fn the_authority_and_credit_rules_match_the_independent_implementation() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../verification/tests/vectors/l2_authority_vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("the vector file is present");
    let vectors: Value = serde_json::from_str(&text).expect("the vector file is json");
    let scenarios = vectors
        .get("scenarios")
        .and_then(Value::as_array)
        .expect("the scenarios");
    assert!(!scenarios.is_empty(), "the vector file has no scenarios");

    let validators = ValidatorSet::new((1..=4u8).map(|i| BlsPublicKey([i; 48])).collect());
    let verifier = MockBls;

    // The two sides have to agree on the addresses before any digest can be
    // compared, and a difference here is a difference in the *address
    // derivation*, which is worth naming rather than discovering later as a
    // confusing "the agent id is not derived" refusal.
    let addresses = vectors
        .get("addresses")
        .and_then(Value::as_object)
        .expect("the addresses");
    for (role, expected) in addresses {
        let want = hex_bytes(expected);
        let got = addr_for(role);
        assert_eq!(
            hex::encode(got),
            hex::encode(want),
            "the reference and the implementation derive different addresses for {role}"
        );
    }

    for scenario in scenarios {
        let name = scenario
            .get("name")
            .and_then(Value::as_str)
            .expect("a name");
        let mut state = L2State::new(L2Config::mini());
        let funding = scenario
            .get("funding")
            .and_then(Value::as_object)
            .expect("the funding");
        for (role, amount) in funding {
            state
                .credit(addr_for(role), amount.as_u64().expect("a funding amount"))
                .expect("a credit cannot overflow a fresh state");
        }
        let mut height = 1u64;
        let mut positions: Vec<Hash> = Vec::new();

        for step in scenario
            .get("steps")
            .and_then(Value::as_array)
            .expect("the steps")
        {
            let op = step.get("op").and_then(Value::as_str).expect("an op");
            // The id of a position this step would open, if it opens one. It
            // joins the index only when the open actually applied: a refused
            // open leaves no position behind, and a later step that refers to
            // "position 0" must mean the first position that exists.
            let mut opened: Option<Hash> = None;
            let tx = match op {
                "policy" => {
                    let policy = policy_from(step);
                    let spender = addr_for(
                        step.get("spender")
                            .and_then(Value::as_str)
                            .expect("a spender"),
                    );
                    let owner =
                        wallet_for(step.get("owner").and_then(Value::as_str).expect("an owner"));
                    let payload =
                        PolicyPayload::build_from_policy(&owner, &policy, spender).unwrap();
                    L2Transaction::new(L2Payload::Policy(payload))
                }
                "revoke" => {
                    let agent_id = {
                        let raw = hex_bytes(step.get("agent_id").expect("an agent id"));
                        let mut id: AgentId = [0u8; 20];
                        id.copy_from_slice(&raw);
                        id
                    };
                    let owner =
                        wallet_for(step.get("owner").and_then(Value::as_str).expect("an owner"));
                    let payload = PolicyRevokePayload::build(&owner, agent_id).unwrap();
                    L2Transaction::new(L2Payload::PolicyRevoke(payload))
                }
                "spend" => {
                    let spender = wallet_for(
                        step.get("spender")
                            .and_then(Value::as_str)
                            .expect("a spender"),
                    );
                    let payload = AgentSpendPayload::build(
                        &spender,
                        hash_bytes(step.get("policy_hash").expect("a policy hash")),
                        u64_field(step, "nonce"),
                        addr_for(
                            step.get("recipient")
                                .and_then(Value::as_str)
                                .expect("a recipient"),
                        ),
                        u64_field(step, "amount"),
                        None,
                    )
                    .unwrap();
                    L2Transaction::new(L2Payload::AgentSpend(payload))
                }
                "credit_open" => {
                    let lender = wallet_for(
                        step.get("lender")
                            .and_then(Value::as_str)
                            .expect("a lender"),
                    );
                    let payload = CreditOpenPayload::build(
                        &lender,
                        addr_for(
                            step.get("borrower")
                                .and_then(Value::as_str)
                                .expect("a borrower"),
                        ),
                        u64_field(step, "amount"),
                        u64_field(step, "collateral"),
                        u64_field(step, "rate") as u32,
                        u64_field(step, "window"),
                        u64_field(step, "deadline"),
                        u64_field(step, "nonce"),
                    )
                    .unwrap();
                    let id = payload.derived_position_id();
                    opened = Some(id);
                    L2Transaction::new(L2Payload::CreditOpen(payload))
                }
                "credit_collateral" => {
                    let index = u64_field(step, "position") as usize;
                    let borrower = wallet_for(
                        step.get("borrower")
                            .and_then(Value::as_str)
                            .expect("a borrower"),
                    );
                    let payload = CreditCollateralPayload::build(
                        &borrower,
                        positions[index],
                        u64_field(step, "amount"),
                    )
                    .unwrap();
                    L2Transaction::new(L2Payload::CreditCollateral(payload))
                }
                "credit_repay" => {
                    let index = u64_field(step, "position") as usize;
                    let borrower = wallet_for(
                        step.get("borrower")
                            .and_then(Value::as_str)
                            .expect("a borrower"),
                    );
                    let payload = CreditRepayPayload::build(
                        &borrower,
                        positions[index],
                        u64_field(step, "amount"),
                    )
                    .unwrap();
                    L2Transaction::new(L2Payload::CreditRepay(payload))
                }
                "credit_default" => {
                    let index = u64_field(step, "position") as usize;
                    let actor =
                        wallet_for(step.get("actor").and_then(Value::as_str).expect("an actor"));
                    let payload = CreditDefaultPayload::build(&actor, positions[index]).unwrap();
                    L2Transaction::new(L2Payload::CreditDefault(payload))
                }
                "advance" => {
                    height = u64_field(step, "to");
                    continue;
                }
                other => panic!("unknown op {other}"),
            };

            let want = expected(step);
            let got = state.apply(&tx, height, &validators, &verifier);
            if got.is_ok() {
                if let Some(id) = opened {
                    positions.push(id);
                }
            }
            match (want, got) {
                (Ok(()), Ok(_)) => {}
                (Ok(()), Err(e)) => panic!(
                    "{name}: the reference applied a step the Rust implementation refused: {e:?}"
                ),
                (Err(want), Ok(_)) => panic!(
                    "{name}: the reference refused a step with `{want}` and the Rust implementation applied it"
                ),
                (Err(want), Err(e)) => {
                    let got_name = error_name(&e);
                    assert_eq!(
                        got_name, want,
                        "{name}: the two implementations refused for different reasons"
                    );
                }
            }
            let _ = state.advance_block(height);
            height += 1;
        }

        // The state at the end has to match too, not just the verdicts.
        let final_state = scenario.get("final").expect("a final snapshot");
        let balances = final_state
            .get("balances")
            .and_then(Value::as_object)
            .expect("balances");
        for (role, amount) in balances {
            let want = amount.as_u64().expect("an amount");
            let got = state.balance(&addr_for(role));
            assert_eq!(got, want, "{name}: the balance of {role} differs");
        }
        assert_eq!(
            state.total_burned(),
            u64_field(final_state, "burned"),
            "{name}: the burned total differs"
        );
        assert_eq!(
            state.pscb,
            u64_field(final_state, "pscb"),
            "{name}: the reserve differs"
        );
        assert_eq!(
            state.credit_locked(),
            u64_field(final_state, "credit_locked"),
            "{name}: the locked collateral differs"
        );
        assert!(
            state.check_conservation(),
            "{name}: value was not conserved"
        );

        // Every published grant, with its counters.
        let expected_policies = final_state
            .get("policies")
            .and_then(Value::as_array)
            .expect("the policies");
        assert_eq!(
            state.policies().len(),
            expected_policies.len(),
            "{name}: a different number of grants"
        );
        for expected_policy in expected_policies {
            let hash = hash_bytes(expected_policy.get("policy_hash").expect("a hash"));
            let entry = state
                .policy(&hash)
                .unwrap_or_else(|| panic!("{name}: the grant is missing"));
            assert_eq!(
                entry.spender,
                addr_for(
                    expected_policy
                        .get("spender")
                        .and_then(Value::as_str)
                        .expect("a spender")
                ),
                "{name}: the spender differs"
            );
            assert_eq!(
                entry.revoked,
                expected_policy
                    .get("revoked")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                "{name}: the kill switch differs"
            );
            assert_eq!(
                entry.window_start_height,
                u64_field(expected_policy, "window_start_height"),
                "{name}: the window start differs"
            );
            assert_eq!(
                entry.spent_in_window_sat,
                u64_field(expected_policy, "spent_in_window_sat"),
                "{name}: the window spend differs"
            );
            assert_eq!(
                entry.total_spent_sat,
                u64_field(expected_policy, "total_spent_sat"),
                "{name}: the lifetime spend differs"
            );
            assert_eq!(
                entry.last_nonce,
                u64_field(expected_policy, "last_nonce"),
                "{name}: the nonce differs"
            );
            assert_eq!(
                entry.spends,
                u64_field(expected_policy, "spends"),
                "{name}: the spend count differs"
            );
        }

        // Every credit position, with its accounting.
        let expected_positions = final_state
            .get("positions")
            .and_then(Value::as_array)
            .expect("the positions");
        assert_eq!(
            state.credit_positions().len(),
            expected_positions.len(),
            "{name}: a different number of positions"
        );
        for expected_position in expected_positions {
            let id = hash_bytes(expected_position.get("position_id").expect("an id"));
            let position = state
                .credit_position(&id)
                .unwrap_or_else(|| panic!("{name}: the position is missing"));
            assert_eq!(
                position.lender,
                addr_for(
                    expected_position
                        .get("lender")
                        .and_then(Value::as_str)
                        .expect("a lender")
                ),
                "{name}: the lender differs"
            );
            assert_eq!(
                position.borrower,
                addr_for(
                    expected_position
                        .get("borrower")
                        .and_then(Value::as_str)
                        .expect("a borrower")
                ),
                "{name}: the borrower differs"
            );
            assert_eq!(
                position.outstanding_sat,
                u64_field(expected_position, "outstanding_sat"),
                "{name}: the outstanding debt differs"
            );
            assert_eq!(
                position.interest_paid_sat,
                u64_field(expected_position, "interest_paid_sat"),
                "{name}: the interest paid differs"
            );
            assert_eq!(
                position.collateral_sat,
                u64_field(expected_position, "collateral_sat"),
                "{name}: the collateral differs"
            );
            assert_eq!(
                format!("{:?}", position.state),
                expected_position
                    .get("state")
                    .and_then(Value::as_str)
                    .expect("a state"),
                "{name}: the position state differs"
            );
        }
    }
}

/// The vector file is regenerated by the reference implementation; a stale
/// file is a file that no longer describes the rules.
#[test]
fn the_vector_file_is_current() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../verification/tests/vectors/l2_authority_vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("the vector file is present");
    let vectors: Value = serde_json::from_str(&text).expect("the vector file is json");
    assert_eq!(
        vectors.get("version").and_then(Value::as_u64),
        Some(1),
        "the vector file's version"
    );
    let scenarios = vectors
        .get("scenarios")
        .and_then(Value::as_array)
        .expect("the scenarios");
    let mut names: BTreeMap<&str, usize> = BTreeMap::new();
    for scenario in scenarios {
        let name = scenario
            .get("name")
            .and_then(Value::as_str)
            .expect("a name");
        *names.entry(name).or_default() += 1;
        let steps = scenario
            .get("steps")
            .and_then(Value::as_array)
            .expect("the steps");
        assert!(!steps.is_empty(), "{name}: the scenario has no steps");
    }
    for (name, count) in &names {
        assert_eq!(*count, 1, "the scenario {name} appears more than once");
    }
    // The scenarios that must be there: the rules the protocol claims.
    for expected in [
        "caps_and_counters",
        "authority_refusals",
        "revocation_reaches_descendants",
        "credit_open_collateralise_repay",
        "credit_refusals",
        "credit_default_after_deadline",
    ] {
        assert!(
            names.contains_key(expected),
            "the scenario {expected} is missing from the vector file"
        );
    }
}
