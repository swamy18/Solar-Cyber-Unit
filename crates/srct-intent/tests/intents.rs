//! Acceptance tests for the cross-network intent lifecycle.

use srct_core::wallet::Wallet;
use srct_intent::book::{
    ExpectedEvidence, IntentBook, IntentError, IntentEvidence, IntentState, RefundReason,
};
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

#[test]
fn wire_mutations_never_panic() {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let creator = wallet(200);
    let arbiter = wallet(201);
    let solver = wallet(202);
    let intent = intent(&creator, &arbiter, 1_000, vec![USDC, SRCT]);
    let signed_intent = SignedIntent::sign(intent.clone(), &creator).unwrap();
    let signed_quote = SignedQuote::sign(quote(&intent, &solver, 700, None), &solver).unwrap();
    let delivery = SignedDelivery::sign(
        Delivery {
            version: DELIVERY_VERSION,
            intent: intent.hash(),
            quote: signed_quote.quote.hash(),
            solver: solver.address().unwrap(),
            result: [9u8; 32],
            height: 20,
            nonce: 1,
        },
        &solver,
    )
    .unwrap();
    let corpora = vec![
        signed_intent.encode(),
        signed_quote.encode(),
        delivery.encode(),
        intent.encode(),
    ];
    let mut rng = StdRng::seed_from_u64(0xbeef);
    for base in &corpora {
        for _ in 0..150 {
            let mut b = base.clone();
            match rng.gen_range(0..3) {
                0 => b.truncate(rng.gen_range(0..=b.len())),
                1 => {
                    for _ in 0..rng.gen_range(1..=4) {
                        if !b.is_empty() {
                            let i = rng.gen_range(0..b.len());
                            b[i] ^= 1 << rng.gen_range(0..8);
                        }
                    }
                }
                _ => b.extend((0..rng.gen_range(1..=8)).map(|_| rng.gen::<u8>())),
            }
            // Must return Ok or Err — never panic.
            let _ = SignedIntent::decode(&b);
            let _ = SignedQuote::decode(&b);
            let _ = SignedDelivery::decode(&b);
            let _ = Intent::decode(&b);
        }
    }
}

// --- Execution-evidence enforcement (Verification::Tee/Zk) ---

use rand::{rngs::StdRng, SeedableRng};
use srct_compute::tee::{SignedTeeQuote, TeeQuote, TeeSla, TeeType, TEE_VERSION};
use srct_zkml::{prove_linear, SignedZkReceipt, SignedZkTask, ZkReceipt, ZkTask, ZK_VERSION};

fn ev_intent(creator: &Wallet, arbiter: &Wallet, level: Verification, nonce: u64) -> Intent {
    Intent {
        version: INTENT_VERSION,
        creator: creator.address().unwrap(),
        service: [3u8; 32],
        input: [4u8; 32],
        arbiter: arbiter.address().unwrap(),
        max_price: Amount {
            asset: USDC,
            amount: 1_000,
        },
        max_latency_ms: 100,
        min_verification: level,
        min_privacy: Privacy::Sealed,
        accepted_assets: vec![USDC, SRCT],
        deadline_height: 100,
        nonce,
    }
}

fn ev_quote(intent: &Intent, solver: &Wallet, level: Verification) -> Quote {
    Quote {
        version: QUOTE_VERSION,
        intent: intent.hash(),
        solver: solver.address().unwrap(),
        price: Amount {
            asset: USDC,
            amount: 700,
        },
        route: None,
        latency_ms: 40,
        verification: level,
        privacy: Privacy::Sealed,
        valid_until_height: 100,
        nonce: 1,
    }
}

fn open_accept_fulfill(
    book: &mut IntentBook,
    creator: &Wallet,
    arbiter: &Wallet,
    solver: &Wallet,
    level: Verification,
) -> (Intent, srct_core::hash::Hash, srct_core::hash::Hash) {
    let intent = ev_intent(creator, arbiter, level, 1);
    let signed = SignedIntent::sign(intent.clone(), creator).unwrap();
    let id = book.open(signed, 10).unwrap();
    let signed = SignedQuote::sign(ev_quote(&intent, solver, level), solver).unwrap();
    let quote_hash = book.quote(signed, 10).unwrap();
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
    book.fulfill(&id, SignedDelivery::sign(delivery, solver).unwrap(), 21)
        .unwrap();
    (intent, id, quote_hash)
}

fn tee_sla(provider: &Wallet) -> TeeSla {
    TeeSla {
        version: TEE_VERSION,
        network_id: "srct/testnet".into(),
        provider: provider.address().unwrap(),
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::SevSnp,
        max_age_heights: 10,
    }
}

fn tee_quote_for(sla: &TeeSla, attester: &Wallet, output: [u8; 32]) -> SignedTeeQuote {
    SignedTeeQuote::sign(
        TeeQuote {
            version: TEE_VERSION,
            network_id: sla.network_id.clone(),
            provider: sla.provider,
            tee: sla.tee,
            workload: sla.workload,
            model_hash: sla.model_hash,
            runtime_hash: sla.runtime_hash,
            config_hash: sla.config_hash,
            input_hash: sla.input_hash,
            output_hash: output,
            height: 30,
            nonce: 1,
        },
        attester,
    )
    .unwrap()
}

fn zk_package(provider: &Wallet) -> (SignedZkTask, SignedZkReceipt, Vec<i64>, u64) {
    let weights = vec![3, -2, 5, 1];
    let bias = 7u64;
    let inputs = vec![10u16, 4, 6, 9];
    let package = prove_linear(&weights, bias, &inputs, &mut StdRng::seed_from_u64(11)).unwrap();
    let requester = wallet(71);
    let task = SignedZkTask::sign(
        ZkTask {
            version: ZK_VERSION,
            network_id: "srct/testnet".into(),
            requester: requester.address().unwrap(),
            provider: provider.address().unwrap(),
            weights: weights.clone(),
            bias,
            input_commitments: package.input_commitments.clone(),
            deadline_height: 100,
            nonce: 1,
        },
        &requester,
    )
    .unwrap();
    let receipt = SignedZkReceipt::sign(
        ZkReceipt {
            version: ZK_VERSION,
            task: task.hash(),
            worker: provider.address().unwrap(),
            bit_proofs: package.bit_proofs.clone(),
            output_commitment: package.output_commitment,
            height: 30,
            nonce: 1,
        },
        package.input_commitments.len(),
        provider,
    )
    .unwrap();
    (task, receipt, weights, bias)
}

#[test]
fn tee_evidence_settles_a_tee_intent() {
    let creator = wallet(90);
    let arbiter = wallet(91);
    let solver = wallet(92);
    let attester = wallet(93);
    let mut book = IntentBook::new();
    book.attestation_roots_mut()
        .add_root(attester.address().unwrap(), TeeType::SevSnp);
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Tee);
    let sla = tee_sla(&solver);
    book.expect_evidence(
        &id,
        ExpectedEvidence::Tee(sla.clone()),
        &creator.address().unwrap(),
    )
    .unwrap();
    let quote = tee_quote_for(&sla, &attester, [25u8; 32]);
    let output = book
        .attach_evidence(&id, IntentEvidence::Tee(quote), 30)
        .unwrap();
    assert_eq!(output.output, [25u8; 32].to_vec());
    let instruction = book.settle(&id, 31).unwrap();
    assert_eq!(instruction.to, solver.address().unwrap());
    assert_eq!(instruction.amount.amount, 700);
}

#[test]
fn tee_intent_refuses_settlement_without_evidence() {
    let creator = wallet(100);
    let arbiter = wallet(101);
    let solver = wallet(102);
    let mut book = IntentBook::new();
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Tee);
    // No expectation and no evidence at all.
    assert_eq!(book.settle(&id, 31), Err(IntentError::EvidenceMissing));
    // Expectation alone is not evidence.
    let sla = tee_sla(&solver);
    book.expect_evidence(&id, ExpectedEvidence::Tee(sla), &creator.address().unwrap())
        .unwrap();
    assert_eq!(book.settle(&id, 31), Err(IntentError::EvidenceMissing));
}

#[test]
fn tee_attach_without_expectation_is_refused() {
    let creator = wallet(110);
    let arbiter = wallet(111);
    let solver = wallet(112);
    let attester = wallet(113);
    let mut book = IntentBook::new();
    book.attestation_roots_mut()
        .add_root(attester.address().unwrap(), TeeType::SevSnp);
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Tee);
    let quote = tee_quote_for(&tee_sla(&solver), &attester, [25u8; 32]);
    assert_eq!(
        book.attach_evidence(&id, IntentEvidence::Tee(quote), 30),
        Err(IntentError::EvidenceMissing)
    );
}

#[test]
fn only_creator_or_arbiter_pins_expectations() {
    let creator = wallet(120);
    let arbiter = wallet(121);
    let solver = wallet(122);
    let stranger = wallet(123);
    let mut book = IntentBook::new();
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Tee);
    let sla = tee_sla(&solver);
    assert_eq!(
        book.expect_evidence(
            &id,
            ExpectedEvidence::Tee(sla.clone()),
            &stranger.address().unwrap()
        ),
        Err(IntentError::NotAuthorized)
    );
    // The arbiter may pin instead of the creator.
    book.expect_evidence(&id, ExpectedEvidence::Tee(sla), &arbiter.address().unwrap())
        .unwrap();
}

#[test]
fn tee_tampered_and_wrong_solver_evidence_is_refused() {
    let creator = wallet(130);
    let arbiter = wallet(131);
    let solver = wallet(132);
    let stranger = wallet(133);
    let attester = wallet(134);
    let mut book = IntentBook::new();
    book.attestation_roots_mut()
        .add_root(attester.address().unwrap(), TeeType::SevSnp);
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Tee);
    let sla = tee_sla(&solver);
    book.expect_evidence(
        &id,
        ExpectedEvidence::Tee(sla.clone()),
        &creator.address().unwrap(),
    )
    .unwrap();
    // Tampered output breaks the attestation signature.
    let mut bad = tee_quote_for(&sla, &attester, [25u8; 32]);
    bad.quote.output_hash = [99u8; 32];
    assert!(matches!(
        book.attach_evidence(&id, IntentEvidence::Tee(bad), 30),
        Err(IntentError::BadEvidence(_))
    ));
    // A quote for another provider does not bind this solver.
    let stranger_sla = tee_sla(&stranger);
    let stranger_quote = tee_quote_for(&stranger_sla, &attester, [25u8; 32]);
    assert_eq!(
        book.attach_evidence(&id, IntentEvidence::Tee(stranger_quote), 30),
        Err(IntentError::EvidenceMismatch)
    );
}

#[test]
fn wrong_kind_evidence_is_refused() {
    let creator = wallet(140);
    let arbiter = wallet(141);
    let solver = wallet(142);
    let mut book = IntentBook::new();
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Tee);
    let sla = tee_sla(&solver);
    book.expect_evidence(&id, ExpectedEvidence::Tee(sla), &creator.address().unwrap())
        .unwrap();
    // A ZK receipt is valid evidence, but not the expected kind.
    let (task, receipt, _weights, _bias) = zk_package(&solver);
    assert_eq!(
        book.attach_evidence(&id, IntentEvidence::Zk(task, receipt), 30),
        Err(IntentError::EvidenceMismatch)
    );
}

#[test]
fn tee_evidence_cannot_attach_twice_but_settles_once() {
    let creator = wallet(150);
    let arbiter = wallet(151);
    let solver = wallet(152);
    let attester = wallet(153);
    let mut book = IntentBook::new();
    book.attestation_roots_mut()
        .add_root(attester.address().unwrap(), TeeType::SevSnp);
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Tee);
    let sla = tee_sla(&solver);
    book.expect_evidence(
        &id,
        ExpectedEvidence::Tee(sla.clone()),
        &creator.address().unwrap(),
    )
    .unwrap();
    let quote = tee_quote_for(&sla, &attester, [25u8; 32]);
    book.attach_evidence(&id, IntentEvidence::Tee(quote.clone()), 30)
        .unwrap();
    // The replay book refuses the same bytes; settlement still works.
    assert!(matches!(
        book.attach_evidence(&id, IntentEvidence::Tee(quote), 30),
        Err(IntentError::BadEvidence(_))
    ));
    assert!(book.settle(&id, 31).is_ok());
}

#[test]
fn zk_evidence_settles_a_zk_intent() {
    let creator = wallet(160);
    let arbiter = wallet(161);
    let solver = wallet(162);
    let mut book = IntentBook::new();
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Zk);
    let (task, receipt, _weights, _bias) = zk_package(&solver);
    book.expect_evidence(
        &id,
        ExpectedEvidence::Zk(task.clone()),
        &creator.address().unwrap(),
    )
    .unwrap();
    let output = book
        .attach_evidence(&id, IntentEvidence::Zk(task, receipt), 30)
        .unwrap();
    assert!(!output.output.is_empty());
    let instruction = book.settle(&id, 31).unwrap();
    assert_eq!(instruction.to, solver.address().unwrap());
}

#[test]
fn zk_intent_refuses_settlement_without_evidence() {
    let creator = wallet(170);
    let arbiter = wallet(171);
    let solver = wallet(172);
    let mut book = IntentBook::new();
    let (_intent, id, _quote) =
        open_accept_fulfill(&mut book, &creator, &arbiter, &solver, Verification::Zk);
    assert_eq!(book.settle(&id, 31), Err(IntentError::EvidenceMissing));
}

#[test]
fn low_verification_intents_settle_without_evidence() {
    let creator = wallet(180);
    let arbiter = wallet(181);
    let solver = wallet(182);
    let mut book = IntentBook::new();
    // ProviderSigned (like the other lifecycle tests): no evidence needed.
    let (_intent, id, _quote) = open_accept_fulfill(
        &mut book,
        &creator,
        &arbiter,
        &solver,
        Verification::ProviderSigned,
    );
    assert!(book.settle(&id, 31).is_ok());
}

#[test]
fn snapshot_restart_replays_identically() {
    let creator = wallet(190);
    let arbiter = wallet(191);
    let solver_a = wallet(192);
    let solver_b = wallet(193);
    let mut book = IntentBook::new();
    let (intent, id) = open(&mut book, &creator, &arbiter);
    for (solver, price, nonce) in [(&solver_a, 900, 1), (&solver_b, 800, 2)] {
        let mut q = quote(&intent, solver, price, None);
        q.nonce = nonce;
        book.quote(SignedQuote::sign(q, solver).unwrap(), 10)
            .unwrap();
    }
    book.accept(&id, None, 10).unwrap();
    // A second open intent rides in the same snapshot.
    let creator2 = wallet(194);
    let arbiter2 = wallet(195);
    let (_, id2) = open(&mut book, &creator2, &arbiter2);
    let bytes = book.encode();
    let restored = IntentBook::decode(&bytes).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.state(&id), book.state(&id));
    assert_eq!(restored.state(&id2), book.state(&id2));
    assert_eq!(
        restored.quote_for(&id, &solver_a.address().unwrap()),
        book.quote_for(&id, &solver_a.address().unwrap())
    );
    // Quotes stay signed by their solvers after the round trip.
    restored
        .quote_for(&id, &solver_b.address().unwrap())
        .unwrap()
        .verify()
        .unwrap();
    // Tampered bytes fail the whole replay; truncation fails too.
    let mut bad = bytes.clone();
    bad[10] ^= 0x01;
    assert!(IntentBook::decode(&bad).is_err());
    assert!(IntentBook::decode(&bytes[..bytes.len() - 4]).is_err());
    assert!(IntentBook::decode(&[99u8; 8]).is_err());
}

#[test]
fn fhe_privacy_intents_settle_only_on_verified_fhe() {
    use srct_fhe::{
        eval, FheKeys, FheReceipt, FheTask, SignedFheReceipt, SignedFheTask, WeightedSum,
        FHE_VERSION,
    };
    use srct_intent::book::{ExpectedEvidence, IntentEvidence};
    let creator = wallet(200);
    let arbiter = wallet(201);
    let solver = wallet(202);
    let mut rng = StdRng::seed_from_u64(0xF00D);
    let keys = FheKeys::generate(&mut rng);
    let mut book = IntentBook::new();
    let mut it = ev_intent(&creator, &arbiter, Verification::ProviderSigned, 11);
    it.min_privacy = Privacy::Fhe;
    let signed = SignedIntent::sign(it.clone(), &creator).unwrap();
    let id = book.open(signed, 10).unwrap();
    let mut q = ev_quote(&it, &solver, Verification::ProviderSigned);
    q.privacy = Privacy::Fhe;
    q.nonce = 2;
    let quote_hash = book
        .quote(SignedQuote::sign(q, &solver).unwrap(), 10)
        .unwrap();
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
    book.fulfill(&id, SignedDelivery::sign(delivery, &solver).unwrap(), 21)
        .unwrap();
    // Sealed FHE execution settles only on verified FHE evidence.
    assert_eq!(book.settle(&id, 31), Err(IntentError::EvidenceMissing));
    let op = WeightedSum {
        weights: vec![3, -2],
        bias: 7,
    };
    let inputs = vec![keys.encrypt(10, &mut rng), keys.encrypt(4, &mut rng)];
    let task = SignedFheTask::sign(
        FheTask {
            version: FHE_VERSION,
            network_id: "srct/testnet".into(),
            requester: creator.address().unwrap(),
            provider: solver.address().unwrap(),
            enc_pubkey: keys.public_bytes(),
            op,
            inputs,
            deadline_height: 100,
            nonce: 1,
        },
        &creator,
    )
    .unwrap();
    book.expect_evidence(
        &id,
        ExpectedEvidence::Fhe(task.clone()),
        &creator.address().unwrap(),
    )
    .unwrap();
    // Wrong-kind evidence is refused even when the privacy floor is FHE.
    let (ztask, zreceipt, _, _) = zk_package(&solver);
    assert_eq!(
        book.attach_evidence(&id, IntentEvidence::Zk(ztask, zreceipt), 30),
        Err(IntentError::EvidenceMismatch)
    );
    let output = eval(&task.task.op, &task.task.inputs).unwrap();
    let receipt = SignedFheReceipt::sign(
        FheReceipt {
            version: FHE_VERSION,
            task: task.hash(),
            worker: solver.address().unwrap(),
            output,
            height: 30,
            nonce: 1,
        },
        &solver,
    )
    .unwrap();
    book.attach_evidence(&id, IntentEvidence::Fhe(task, receipt), 30)
        .unwrap();
    assert!(book.settle(&id, 31).is_ok());
}

#[test]
fn dispute_bonds_release_on_honest_and_slash_on_frivolous() {
    let creator = wallet(210);
    let arbiter = wallet(211);
    let solver = wallet(212);
    let stranger = wallet(213);
    // Honest challenge: bond returns with the refund.
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
    book.fulfill(&id, SignedDelivery::sign(delivery, &solver).unwrap(), 21)
        .unwrap();
    // Only the creator bonds, only once, only positive.
    assert!(book
        .bond_dispute(&id, stranger.address().unwrap(), 100)
        .is_err());
    assert!(book
        .bond_dispute(&id, creator.address().unwrap(), 0)
        .is_err());
    book.bond_dispute(&id, creator.address().unwrap(), 100)
        .unwrap();
    assert!(book
        .bond_dispute(&id, creator.address().unwrap(), 100)
        .is_err());
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
    assert!(outcome.refund.is_some());
    let release = outcome.bond_release.unwrap();
    assert_eq!(release.to, creator.address().unwrap());
    assert_eq!(release.amount_sat, 100);
    assert!(outcome.bond_slash.is_none());
    // Frivolous challenge: bond goes to the wronged solver.
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
    book.fulfill(&id, SignedDelivery::sign(delivery, &solver).unwrap(), 21)
        .unwrap();
    book.bond_dispute(&id, creator.address().unwrap(), 100)
        .unwrap();
    let dispute = SignedDispute::sign(
        Dispute {
            version: DISPUTE_VERSION,
            intent: id,
            creator: creator.address().unwrap(),
            evidence: [5u8; 32],
            nonce: 3,
        },
        &creator,
    )
    .unwrap();
    book.dispute(dispute, 22).unwrap();
    let resolution = SignedResolution::sign(
        DisputeResolution {
            version: RESOLUTION_VERSION,
            intent: id,
            arbiter: arbiter.address().unwrap(),
            release_to_solver: true,
            evidence: [5u8; 32],
            nonce: 3,
        },
        &arbiter,
    )
    .unwrap();
    let outcome = book.resolve(resolution, 23).unwrap();
    assert!(outcome.settlement.is_some());
    let slash = outcome.bond_slash.unwrap();
    assert_eq!(slash.from, creator.address().unwrap());
    assert_eq!(slash.to, solver.address().unwrap());
    assert!(outcome.bond_release.is_none());
    // Unbonded disputes keep the legacy path: no bond instructions.
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
    book.fulfill(&id, SignedDelivery::sign(delivery, &solver).unwrap(), 21)
        .unwrap();
    let dispute = SignedDispute::sign(
        Dispute {
            version: DISPUTE_VERSION,
            intent: id,
            creator: creator.address().unwrap(),
            evidence: [5u8; 32],
            nonce: 4,
        },
        &creator,
    )
    .unwrap();
    book.dispute(dispute, 22).unwrap();
    let resolution = SignedResolution::sign(
        DisputeResolution {
            version: RESOLUTION_VERSION,
            intent: id,
            arbiter: arbiter.address().unwrap(),
            release_to_solver: false,
            evidence: [5u8; 32],
            nonce: 4,
        },
        &arbiter,
    )
    .unwrap();
    let outcome = book.resolve(resolution, 23).unwrap();
    assert!(outcome.bond_release.is_none());
    assert!(outcome.bond_slash.is_none());
}

#[test]
fn open_split_opens_stages_atomically() {
    let creator = wallet(220);
    let arbiter = wallet(221);
    let mut book = IntentBook::new();
    let a = intent(&creator, &arbiter, 1_000, vec![USDC]);
    let mut b = a.clone();
    b.nonce = 2;
    let batch = vec![
        SignedIntent::sign(a, &creator).unwrap(),
        SignedIntent::sign(b, &creator).unwrap(),
    ];
    let ids = book.open_split(batch, 10).unwrap();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    // A batch with a duplicate share opens nothing, not half.
    let c = intent(&creator, &arbiter, 500, vec![USDC, SRCT]);
    let before = book.len();
    let bad = vec![
        SignedIntent::sign(c.clone(), &creator).unwrap(),
        SignedIntent::sign(c, &creator).unwrap(),
    ];
    assert_eq!(book.open_split(bad, 10), Err(IntentError::DuplicateIntent));
    assert_eq!(book.len(), before);
    // Empty and over-cap batches are refused.
    assert!(book.open_split(vec![], 10).is_err());
}

#[test]
fn solver_directory_merges_gossip_and_feeds_the_book() {
    use srct_intent::solver::{decode_quote_batch, encode_quote_batch, SolverDirectory};
    let creator = wallet(230);
    let arbiter = wallet(231);
    let solver_a = wallet(232);
    let solver_b = wallet(233);
    let mut book = IntentBook::new();
    let (it, id) = open(&mut book, &creator, &arbiter);
    let qa = SignedQuote::sign(quote(&it, &solver_a, 900, None), &solver_a).unwrap();
    let mut qb_raw = quote(&it, &solver_b, 800, None);
    qb_raw.nonce = 2;
    let qb = SignedQuote::sign(qb_raw, &solver_b).unwrap();
    let batch = encode_quote_batch(&[&qa, &qb]).unwrap();
    let mut dir = SolverDirectory::new("srct/testnet");
    dir.advertise(solver_a.address().unwrap(), 9);
    assert_eq!(dir.merge_batch(&batch, 10).unwrap(), 2);
    assert!(dir.is_known(&solver_b.address().unwrap()));
    assert_eq!(dir.quotes_for(&id).len(), 2);
    // Re-merging adds nothing; tampered batches fail whole.
    assert_eq!(dir.merge_batch(&batch, 10).unwrap(), 0);
    let mut bad = batch.clone();
    bad[10] ^= 0x01;
    assert!(decode_quote_batch(&bad).is_err());
    assert!(decode_quote_batch(&batch[..batch.len() - 3]).is_err());
    // Gossiped quotes enter the book through the normal admission path,
    // and the book still picks the best one.
    for q in dir.quotes_for(&id) {
        book.quote(q.clone(), 10).unwrap();
    }
    assert_eq!(book.accept(&id, None, 10).unwrap(), qb.quote.hash());
    // Expired gossip prunes.
    assert!(dir.prune(101) > 0);
}

#[test]
fn adapter_rail_executes_settlement_end_to_end() {
    use srct_intent::adapter::{MemRail, SettlementAdapter};
    let creator = wallet(240);
    let arbiter = wallet(241);
    let solver = wallet(242);
    let mut book = IntentBook::new();
    let (intent, id, _) = open_accept_fulfill(
        &mut book,
        &creator,
        &arbiter,
        &solver,
        Verification::ProviderSigned,
    );
    let instruction = book.settle(&id, 31).unwrap();
    let mut rail = MemRail::new();
    rail.fund(creator.address().unwrap(), 5_000);
    rail.fund_escrow(id, creator.address().unwrap(), intent.max_price.amount)
        .unwrap();
    // Over-funding past the balance is refused (4000 left, 4001 asked).
    assert!(rail
        .fund_escrow([9u8; 32], creator.address().unwrap(), 4_001)
        .is_err());
    let receipt = rail.execute_settlement(&instruction).unwrap();
    assert_eq!(receipt.to, solver.address().unwrap());
    assert_eq!(receipt.amount.amount, 700);
    assert_eq!(rail.balance(&solver.address().unwrap()), 700);
    // A replayed instruction pays nothing twice.
    assert!(rail.execute_settlement(&instruction).is_err());
    // A second intent refunds through the same rail.
    let (intent2, id2, _) = {
        let it = ev_intent(&creator, &arbiter, Verification::ProviderSigned, 21);
        let signed = SignedIntent::sign(it.clone(), &creator).unwrap();
        let id = book.open(signed, 10).unwrap();
        (it, id, [0u8; 32])
    };
    rail.fund_escrow(id2, creator.address().unwrap(), intent2.max_price.amount)
        .unwrap();
    let refund = book.refund(&id2, 101).unwrap();
    let receipt = rail.execute_refund(&refund).unwrap();
    assert_eq!(receipt.to, creator.address().unwrap());
    assert_eq!(
        rail.balance(&creator.address().unwrap()),
        5_000 - 1_000 - 1_000 + 1_000
    );
    assert!(rail.execute_refund(&refund).is_err());
}
