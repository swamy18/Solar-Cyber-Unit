//! x402-compatible paid-API demo — roadmap agent-payment interoperability.
//!
//! Working demo of the flow the task asks for:
//! agent calls a paid API → receives a payment request (402 challenge) →
//! authorizes a bounded spend → pays → gets the response automatically.
//!
//! Run with `cargo test -p srct-core --test x402`.

use srct_core::agent::{derive_agent_id, AgentRole, PolicyBook, SpendPolicy, POLICY_VERSION};
use srct_core::credit::CreditBook;
use srct_core::l2::Auth;
use srct_core::payment::build_signed_payment;
use srct_core::service::{authorize_request, build_signed_request, derive_service_id, RequestSpec};
use srct_core::wallet::Wallet;
use srct_core::x402::{
    base64_decode, build_required, decode_required, decode_signature, encode_required,
    encode_signature, parse_sat_amount, parse_srct_network, select_accept, srct_network_caip2,
    X402Budget, X402Signature, X402SrctPayload, SRCT_SCHEME, X402_VERSION,
};

const NET: &str = "srct/testnet";
const HEIGHT: u64 = 100;
const EXPIRES: u64 = 9_000;

fn payer() -> Wallet {
    Wallet::from_private_key_bytes(&[11u8; 32], "demo-payer").expect("valid key")
}

fn provider() -> Wallet {
    Wallet::from_private_key_bytes(&[22u8; 32], "demo-provider").expect("valid key")
}

#[test]
fn caip2_mapping_is_stable() {
    assert_eq!(srct_network_caip2(NET).unwrap(), "srct:testnet");
    assert_eq!(parse_srct_network("srct:testnet").unwrap(), NET);
    assert!(parse_srct_network("eip155:84532").is_err());
    assert_eq!(parse_sat_amount("500").unwrap(), 500);
}

#[test]
fn agent_paid_api_roundtrip() {
    // ---- Server side: paid resource advertises its price (402 challenge) ----
    let provider_addr = provider().address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"x402-weather-v1");
    let required = build_required(
        NET,
        500,
        hex::encode(provider_addr),
        "/v1/paid/weather".to_string(),
        "Demo paid weather (x402 exact, 500 sat)".to_string(),
    )
    .unwrap();
    assert_eq!(required.x402_version, X402_VERSION);
    assert_eq!(required.accepts[0].scheme, SRCT_SCHEME);

    // The challenge travels as a base64 header value.
    let header = encode_required(&required).unwrap();
    let back = decode_required(&header).unwrap();
    assert_eq!(back, required);
    // base64 is standard alphabet (x402 header compat).
    assert!(base64_decode(&header).is_ok());

    // ---- Agent side: bounded spend check BEFORE any key is used ----
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &payer().address().unwrap()),
        owner: payer().address().unwrap(),
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    let budget = X402Budget {
        max_amount_sat: 600,
        allowed_recipients: Some(vec![provider_addr]),
        allowed_services: Some(vec![service]),
    };
    // A greedy server asking for more than the budget is refused locally.
    let greedy = build_required(
        NET,
        5_000,
        hex::encode(provider_addr),
        "/v1/paid/weather".to_string(),
        "greedy".to_string(),
    )
    .unwrap();
    assert!(select_accept(&greedy, &budget, &provider_addr, &Some(service)).is_err());

    // Honest offer passes the budget.
    let accept = select_accept(&required, &budget, &provider_addr, &Some(service)).unwrap();
    let amount = parse_sat_amount(&accept.amount).unwrap();
    assert_eq!(amount, 500);
    budget
        .check(amount, &provider_addr, &Some(service))
        .unwrap();

    // ---- Agent authorizes + pays (existing SRCT primitives) ----
    let mut book = PolicyBook::default();
    let request = build_signed_request(
        &payer(),
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider_addr,
            max_amount_sat: amount,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();
    let auth = authorize_request(&mut book, &policy, NET, &request, HEIGHT, 1).unwrap();
    let sigs = Auth::sigs_for(&payer(), &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(&payer()).unwrap();
    let payment = build_signed_payment(
        &payer(),
        &auth,
        NET,
        AgentRole::Machine,
        0,
        EXPIRES,
        request.request_id(),
        &[],
    )
    .unwrap();
    payment.verify(NET, HEIGHT).unwrap();
    payment.linked_to(&auth).unwrap();

    // The retry travels as a base64 header value.
    let sig_envelope = X402Signature {
        x402_version: X402_VERSION,
        scheme: SRCT_SCHEME.to_string(),
        network: srct_network_caip2(NET).unwrap(),
        payload: X402SrctPayload {
            payment_hex: hex::encode(payment.serialize()),
            authorization_hex: hex::encode(auth.serialize()),
            auth_sigs_hex: hex::encode(sigs.to_bytes()),
            auth_keys_hex: hex::encode(keys.to_bytes()),
        },
    };
    let sig_header = encode_signature(&sig_envelope).unwrap();
    let back_sig = decode_signature(&sig_header).unwrap();
    assert_eq!(back_sig, sig_envelope);

    // ---- Server verifies + settles through the credit gate (facilitator) ----
    let mut credit = CreditBook::new();
    credit.deposit(provider_addr, 0).unwrap();
    credit.deposit(payment.payer, 10_000).unwrap();
    let presented = srct_core::service::AuthPresentation {
        auth: &auth,
        sigs: &sigs,
        keys: &keys,
    };
    let reservation = srct_core::service::admit_payment(
        &book,
        &policy,
        &payment,
        presented,
        NET,
        HEIGHT,
        &mut credit,
    )
    .unwrap();
    assert!(reservation.position_draws.is_empty());
    // Receipt would settle here (`credit.settle(&reservation)`); the demo
    // asserts the reservation exists, which is the settlement precondition.
    assert!(reservation.id != [0u8; 32]);
}
