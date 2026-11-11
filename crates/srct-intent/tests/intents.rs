//! Acceptance tests for the cross-network intent lifecycle.

use srct_core::wallet::Wallet;
use srct_intent::book::{IntentBook, IntentError, IntentState, RefundReason};
use srct_intent::types::{
    Amount, AssetId, AssetRoute, Delivery, Dispute, DisputeResolution, Intent, Privacy, Quote,
    SignedDelivery, SignedDispute, SignedIntent, SignedQuote, SignedResolution, SignedRoute,
    Verification, DELIVERY_VERSION, DISPUTE_VERSION, INTENT_VERSION, QUOTE_VERSION,
    RESOLUTION_VERSION, ROUTE_VERSION,
};

const USDC: AssetId = AssetId([1u8; 32]);
const SRCT: AssetId = AssetId([2u8; 32]);

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "intent-test").unwrap()
}

fn intent(creator: &Wallet, arbiter: &Wallet, max: u64, assets: Vec<AssetId>) -> Intent {
    Intent {
        version: INTENT_VERSION,
        creator: creator.address().unwrap(),
        service: [3u8; 32],
        input: [4u8; 32],
        arbiter: arbiter.address().unwrap(),
        max_price: Amount {
            asset: USDC,
            amount: max,
        },
        max_latency_ms: 100,
        min_verification: Verification::ProviderSigned,
        min_privacy: Privacy::Sealed,
        accepted_assets: assets,
        deadline_height: 100,
        nonce: 1,
    }
}

fn quote(intent: &Intent, solver: &Wallet, price: u64, route: Option<SignedRoute>) -> Quote {
    Quote {
        version: QUOTE_VERSION,
        intent: intent.hash(),
        solver: solver.address().unwrap(),
        price: Amount {
            asset: route.as_ref().map(|r| r.route.to).unwrap_or(USDC),
            amount: price,
        },
        route,
        latency_ms: 40,
        verification: Verification::ProviderSigned,
        privacy: Privacy::Sealed,
        valid_until_height: 100,
        nonce: 1,
    }
}

fn route(router: &Wallet, fee_bps: u32) -> SignedRoute {
    SignedRoute::sign(
        AssetRoute {
            version: ROUTE_VERSION,
            router: router.address().unwrap(),
            from: USDC,
            to: SRCT,
            numerator: 2,
            denominator: 1,
            fee_bps,
            valid_until_height: 100,
            nonce: 1,
        },
        router,
    )
    .unwrap()
}

fn open(
    book: &mut IntentBook,
    creator: &Wallet,
    arbiter: &Wallet,
) -> (Intent, srct_core::hash::Hash) {
    let intent = intent(creator, arbiter, 1_000, vec![USDC, SRCT]);
    let signed = SignedIntent::sign(intent.clone(), creator).unwrap();
    let id = book.open(signed, 10).unwrap();
    (intent, id)
}

#[test]
fn an_intent_is_signed_and_tamper_evident() {
    let creator = wallet(1);
    let arbiter = wallet(2);
    let intent = intent(&creator, &arbiter, 1_000, vec![USDC]);
    let mut signed = SignedIntent::sign(intent.clone(), &creator).unwrap();
    signed.verify().unwrap();
    let bytes = signed.encode();
    assert_eq!(SignedIntent::decode(&bytes).unwrap(), signed);
    signed.intent.max_price.amount += 1;
    assert!(signed.verify().is_err());

    let encoded = intent.encode();
    assert_eq!(Intent::decode(&encoded).unwrap(), intent);
}

#[test]
fn a_route_converts_exactly_with_fees_and_bounds() {
    let router = wallet(3);
    let route = AssetRoute {
        version: ROUTE_VERSION,
        router: router.address().unwrap(),
        from: USDC,
        to: SRCT,
        numerator: 2,
        denominator: 1,
        fee_bps: 100,
        valid_until_height: 100,
        nonce: 1,
    };
    assert_eq!(route.convert(1_000).unwrap(), 1_980);
    assert_eq!(route.inverse_estimate(1_980).unwrap(), 1_000);
    let signed = SignedRoute::sign(route, &router).unwrap();
    signed.verify().unwrap();
    assert_eq!(SignedRoute::decode(&signed.encode()).unwrap(), signed);
}

#[test]
fn a_same_asset_quote_over_the_cap_is_refused() {
    let creator = wallet(10);
    let arbiter = wallet(11);
    let solver = wallet(12);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    let over = quote(&intent, &solver, 1_001, None);
    let signed = SignedQuote::sign(over, &solver).unwrap();
    assert_eq!(book.quote(signed, 10), Err(IntentError::QuoteTooExpensive));

    let good = quote(&intent, &solver, 1_000, None);
    let signed = SignedQuote::sign(good, &solver).unwrap();
    book.quote(signed, 10).unwrap();
    assert_eq!(book.best_quote(&id, 10).unwrap().quote.price.amount, 1_000);
}

#[test]
fn a_cross_asset_quote_needs_a_valid_route_and_converts_the_cap() {
    let creator = wallet(20);
    let arbiter = wallet(21);
    let solver = wallet(22);
    let router = wallet(23);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);

    let mut missing = quote(&intent, &solver, 1_800, None);
    missing.price.asset = SRCT;
    let signed = SignedQuote::sign(missing, &solver).unwrap();
    assert_eq!(book.quote(signed, 10), Err(IntentError::RouteMissing));

    let bad_route = route(&router, 1_000);
    let mut over = quote(&intent, &solver, 1_801, Some(bad_route.clone()));
    over.price.asset = SRCT;
    let signed = SignedQuote::sign(over, &solver).unwrap();
    assert_eq!(book.quote(signed, 10), Err(IntentError::QuoteTooExpensive));

    let good = quote(&intent, &solver, 1_800, Some(bad_route));
    let signed = SignedQuote::sign(good, &solver).unwrap();
    book.quote(signed, 10).unwrap();
    assert_eq!(book.best_quote(&id, 10).unwrap().quote.price.asset, SRCT);
}

#[test]
fn the_best_quote_is_ranked_by_converted_cost_then_latency() {
    let creator = wallet(30);
    let arbiter = wallet(31);
    let cheap = wallet(32);
    let fast = wallet(33);
    let router = wallet(34);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    let mut same = quote(&intent, &cheap, 900, None);
    same.latency_ms = 60;
    book.quote(SignedQuote::sign(same, &cheap).unwrap(), 10)
        .unwrap();
    let mut converted = quote(&intent, &fast, 1_800, Some(route(&router, 1_000)));
    converted.price.asset = SRCT;
    converted.latency_ms = 5;
    book.quote(SignedQuote::sign(converted, &fast).unwrap(), 10)
        .unwrap();
    // 900 USDC beats a 1800 SRCT quote whose inverse estimate is 1000 USDC.
    assert_eq!(
        book.best_quote(&id, 10).unwrap().quote.solver,
        cheap.address().unwrap()
    );
    // Adding a cheaper same-asset quote changes the winner deterministically.
    let cheapest = wallet(35);
    let mut better = quote(&intent, &cheapest, 500, None);
    better.latency_ms = 80;
    book.quote(SignedQuote::sign(better, &cheapest).unwrap(), 10)
        .unwrap();
    assert_eq!(
        book.best_quote(&id, 10).unwrap().quote.solver,
        cheapest.address().unwrap()
    );
}

#[test]
fn the_full_lifecycle_settles_once() {
    let creator = wallet(40);
    let arbiter = wallet(41);
    let solver = wallet(42);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    let signed = SignedQuote::sign(quote(&intent, &solver, 700, None), &solver).unwrap();
    let quote_hash = book.quote(signed, 10).unwrap();
    let accepted = book.accept(&id, None, 10).unwrap();
    assert_eq!(accepted, quote_hash);
    assert!(matches!(
        book.state(&id),
        Some(IntentState::Accepted { .. })
    ));

    let delivery = Delivery {
        version: DELIVERY_VERSION,
        intent: id,
        quote: quote_hash,
        solver: solver.address().unwrap(),
        result: [9u8; 32],
        height: 20,
        nonce: 1,
    };
    let signed = SignedDelivery::sign(delivery, &solver).unwrap();
    book.fulfill(&id, signed, 21).unwrap();
    let instruction = book.settle(&id, 22).unwrap();
    assert_eq!(instruction.from, creator.address().unwrap());
    assert_eq!(instruction.to, solver.address().unwrap());
    assert_eq!(instruction.amount.amount, 700);
    assert_eq!(
        book.settle(&id, 23),
        Err(IntentError::BadState("intent is not fulfilled"))
    );
}

#[test]
fn a_late_or_wrong_solver_delivery_is_refused() {
    let creator = wallet(50);
    let arbiter = wallet(51);
    let solver = wallet(52);
    let stranger = wallet(53);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    let q = SignedQuote::sign(quote(&intent, &solver, 700, None), &solver).unwrap();
    let quote_hash = book.quote(q, 10).unwrap();
    let accepted = book
        .accept(&id, Some(solver.address().unwrap()), 10)
        .unwrap();
    assert_eq!(accepted, quote_hash);

    let wrong = Delivery {
        version: DELIVERY_VERSION,
        intent: id,
        quote: quote_hash,
        solver: stranger.address().unwrap(),
        result: [7u8; 32],
        height: 20,
        nonce: 1,
    };
    let signed = SignedDelivery::sign(wrong, &stranger).unwrap();
    assert_eq!(book.fulfill(&id, signed, 21), Err(IntentError::WrongSolver));

    let late = Delivery {
        version: DELIVERY_VERSION,
        intent: id,
        quote: quote_hash,
        solver: solver.address().unwrap(),
        result: [7u8; 32],
        height: 101,
        nonce: 2,
    };
    let signed = SignedDelivery::sign(late, &solver).unwrap();
    assert_eq!(
        book.fulfill(&id, signed, 101),
        Err(IntentError::LateDelivery)
    );
}

#[test]
fn an_accepted_intent_refunds_after_its_deadline_and_not_before() {
    let creator = wallet(60);
    let arbiter = wallet(61);
    let solver = wallet(62);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    let q = SignedQuote::sign(quote(&intent, &solver, 700, None), &solver).unwrap();
    book.quote(q, 10).unwrap();
    book.accept(&id, None, 10).unwrap();
    assert!(book.refund(&id, 90).is_err());
    let refund = book.refund(&id, 101).unwrap();
    assert_eq!(refund.to, creator.address().unwrap());
    assert_eq!(refund.amount.amount, 1_000);
    assert_eq!(refund.reason, RefundReason::Expired);
    assert!(book.settle(&id, 102).is_err());
}

#[test]
fn only_the_creator_can_dispute_and_only_the_arbiter_can_resolve() {
    let creator = wallet(70);
    let arbiter = wallet(71);
    let solver = wallet(72);
    let stranger = wallet(73);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    let q = SignedQuote::sign(quote(&intent, &solver, 700, None), &solver).unwrap();
    let quote_hash = book.quote(q, 10).unwrap();
    book.accept(&id, None, 10).unwrap();
    let delivery = Delivery {
        version: DELIVERY_VERSION,
        intent: id,
        quote: quote_hash,
        solver: solver.address().unwrap(),
        result: [9u8; 32],
        height: 20,
        nonce: 1,
    };
    let signed = SignedDelivery::sign(delivery, &solver).unwrap();
    book.fulfill(&id, signed, 21).unwrap();

    let wrong = SignedDispute::sign(
        Dispute {
            version: DISPUTE_VERSION,
            intent: id,
            creator: stranger.address().unwrap(),
            evidence: [5u8; 32],
            nonce: 1,
        },
        &stranger,
    )
    .unwrap();
    assert!(matches!(
        book.dispute(wrong, 22),
        Err(IntentError::BadSignature(_))
    ));

    let dispute = SignedDispute::sign(
        Dispute {
            version: DISPUTE_VERSION,
            intent: id,
            creator: creator.address().unwrap(),
            evidence: [5u8; 32],
            nonce: 2,
        },
        &creator,
    )
    .unwrap();
    book.dispute(dispute, 22).unwrap();

    let wrong_arbiter = wallet(74);
    let wrong = SignedResolution::sign(
        DisputeResolution {
            version: RESOLUTION_VERSION,
            intent: id,
            arbiter: wrong_arbiter.address().unwrap(),
            release_to_solver: true,
            evidence: [5u8; 32],
            nonce: 1,
        },
        &wrong_arbiter,
    )
    .unwrap();
    assert_eq!(book.resolve(wrong, 23), Err(IntentError::WrongArbiter));

    let resolution = SignedResolution::sign(
        DisputeResolution {
            version: RESOLUTION_VERSION,
            intent: id,
            arbiter: arbiter.address().unwrap(),
            release_to_solver: false,
            evidence: [5u8; 32],
            nonce: 2,
        },
        &arbiter,
    )
    .unwrap();
    let outcome = book.resolve(resolution, 23).unwrap();
    assert!(outcome.settlement.is_none());
    assert_eq!(
        outcome.refund.as_ref().unwrap().reason,
        RefundReason::Resolved
    );
    assert!(book.settle(&id, 24).is_err());
}

#[test]
fn a_second_quote_from_the_same_solver_is_refused() {
    let creator = wallet(80);
    let arbiter = wallet(81);
    let solver = wallet(82);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    book.quote(
        SignedQuote::sign(quote(&intent, &solver, 800, None), &solver).unwrap(),
        10,
    )
    .unwrap();
    let mut second = quote(&intent, &solver, 700, None);
    second.nonce = 2;
    assert_eq!(
        book.quote(SignedQuote::sign(second, &solver).unwrap(), 10),
        Err(IntentError::DuplicateQuote)
    );
    assert_eq!(book.state(&id), Some(&IntentState::Open));
}
