//! Cross-network intent demo: two competing solvers, one cross-asset route,
//! acceptance, delivery and the exact settlement instruction.
//!
//! Run with:
//! ```text
//! cargo run --release -p srct-intent --example intent_demo
//! ```

use srct_core::wallet::Wallet;
use srct_intent::book::IntentBook;
use srct_intent::types::{
    Amount, AssetId, AssetRoute, Delivery, Intent, Privacy, Quote, SignedDelivery, SignedIntent,
    SignedQuote, SignedRoute, Verification, DELIVERY_VERSION, INTENT_VERSION, QUOTE_VERSION,
    ROUTE_VERSION,
};

const USDC: AssetId = AssetId([1u8; 32]);
const SRCT: AssetId = AssetId([2u8; 32]);

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "intent-demo").unwrap()
}

fn main() {
    let creator = wallet(1);
    let arbiter = wallet(2);
    let solver_a = wallet(3);
    let solver_b = wallet(4);
    let router = wallet(5);

    let intent = Intent {
        version: INTENT_VERSION,
        creator: creator.address().unwrap(),
        service: [7u8; 32],
        input: [8u8; 32],
        arbiter: arbiter.address().unwrap(),
        max_price: Amount {
            asset: USDC,
            amount: 1_000,
        },
        max_latency_ms: 100,
        min_verification: Verification::ProviderSigned,
        min_privacy: Privacy::Sealed,
        accepted_assets: vec![USDC, SRCT],
        deadline_height: 100,
        nonce: 1,
    };
    let signed_intent = SignedIntent::sign(intent.clone(), &creator).unwrap();
    let mut book = IntentBook::new();
    let id = book.open(signed_intent, 10).unwrap();
    println!("intent {} opened at height 10", id[0]);

    let direct = Quote {
        version: QUOTE_VERSION,
        intent: intent.hash(),
        solver: solver_a.address().unwrap(),
        price: Amount {
            asset: USDC,
            amount: 900,
        },
        route: None,
        latency_ms: 60,
        verification: Verification::ProviderSigned,
        privacy: Privacy::Sealed,
        valid_until_height: 100,
        nonce: 1,
    };
    let direct_hash = book
        .quote(SignedQuote::sign(direct, &solver_a).unwrap(), 10)
        .unwrap();
    println!("solver A: 900 USDC, 60 ms, quote {}", direct_hash[0]);

    let route = SignedRoute::sign(
        AssetRoute {
            version: ROUTE_VERSION,
            router: router.address().unwrap(),
            from: USDC,
            to: SRCT,
            numerator: 2,
            denominator: 1,
            fee_bps: 1_000,
            valid_until_height: 100,
            nonce: 1,
        },
        &router,
    )
    .unwrap();
    println!("route: 1 USDC -> {:.2} SRCT after 10% fee", 2.0 * 0.9);
    let converted = Quote {
        version: QUOTE_VERSION,
        intent: intent.hash(),
        solver: solver_b.address().unwrap(),
        price: Amount {
            asset: SRCT,
            amount: 1_800,
        },
        route: Some(route),
        latency_ms: 5,
        verification: Verification::Optimistic,
        privacy: Privacy::Sealed,
        valid_until_height: 100,
        nonce: 1,
    };
    let converted_hash = book
        .quote(SignedQuote::sign(converted, &solver_b).unwrap(), 10)
        .unwrap();
    println!(
        "solver B: 1800 SRCT via route, 5 ms, quote {}",
        converted_hash[0]
    );

    let best = book
        .best_quote(&id, 10)
        .expect("a valid quote")
        .quote
        .clone();
    println!(
        "best: solver {}, {} units of asset {}, {} ms",
        best.solver[0], best.price.amount, best.price.asset.0[0], best.latency_ms
    );

    let accepted = book.accept(&id, None, 10).unwrap();
    println!("accepted quote {}", accepted[0]);
    let delivery = Delivery {
        version: DELIVERY_VERSION,
        intent: id,
        quote: accepted,
        solver: best.solver,
        result: [9u8; 32],
        height: 20,
        nonce: 1,
    };
    let signed = SignedDelivery::sign(delivery, &solver_a).unwrap();
    book.fulfill(&id, signed, 21).unwrap();
    let settlement = book.settle(&id, 22).unwrap();
    println!(
        "settlement: {} -> {} for {} units of asset {} (ref {})",
        settlement.from[0],
        settlement.to[0],
        settlement.amount.amount,
        settlement.amount.asset.0[0],
        settlement.reference[0]
    );
}
