//! Acceptance tests for the CNNP core: real adapters across different
//! representation spaces, signed and sealed envelopes, discovery, metering and
//! multi-stage plan quoting.

use srct_cnnp::adapter::LinearAdapter;
use srct_cnnp::metering::{
    quote_plan, settle_receipt, Plan, ReceiptBook, SignedReceipt, UsageReceipt, PLAN_VERSION,
};
use srct_cnnp::registry::{
    discover, Capability, DiscoveryQuery, Privacy, SignedCapability, Verification,
    CAPABILITY_VERSION,
};
use srct_cnnp::space::{DType, ModelSpace, RepresentationEnvelope};
use srct_core::hash::Address;
use srct_core::l2::Auth;
use srct_core::wallet::Wallet;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "cnnp-test").unwrap()
}

fn space(id: u8, architecture: &str, layer: &str, dim: u32) -> ModelSpace {
    ModelSpace {
        model_id: [id; 32],
        tokenizer: [id.wrapping_add(1); 32],
        architecture: architecture.into(),
        layer: layer.into(),
        dim,
        dtype: DType::F32,
    }
}

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next(&mut self) -> f32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 40) as f32) / ((1u32 << 24) as f32)
    }

    fn signed(&mut self) -> f32 {
        self.next() * 2.0 - 1.0
    }
}

fn source_features(x: [f32; 2], dim: usize) -> Vec<f32> {
    (0..dim)
        .map(|j| {
            let a = (j as f32 + 1.0) * 0.7;
            (a * x[0] - (j as f32 * 0.3) * x[1]).tanh()
        })
        .collect()
}

/// A different "model family": 16 dimensions produced by a fixed linear map of
/// the source features plus a small nonlinear term. The adapter must recover
/// the linear part; the nonlinear term is the honest residual.
fn target_features(source: &[f32], matrix: &[f32], bias: &[f32], x: [f32; 2]) -> Vec<f32> {
    let d = source.len();
    matrix
        .chunks_exact(d)
        .zip(bias.iter())
        .map(|(row, b)| {
            let mut acc = *b;
            for (w, v) in row.iter().zip(source.iter()) {
                acc += w * v;
            }
            acc + 0.02 * (x[0] * x[1]).sin()
        })
        .collect()
}

type Pairs = Vec<(Vec<f32>, Vec<f32>)>;

fn paired_data(
    source_space: &ModelSpace,
    target_space: &ModelSpace,
    count: usize,
    seed: u64,
) -> (Pairs, Vec<f32>) {
    let mut rng = Lcg::new(seed);
    let sdim = source_space.dim as usize;
    let tdim = target_space.dim as usize;
    let mut matrix = vec![0.0f32; tdim * sdim];
    for w in matrix.iter_mut() {
        *w = rng.signed() * 0.6;
    }
    let bias: Vec<f32> = (0..tdim).map(|_| rng.signed() * 0.1).collect();
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let x = [rng.signed(), rng.signed()];
        let s = source_features(x, sdim);
        let t = target_features(&s, &matrix, &bias, x);
        pairs.push((s, t));
    }
    (pairs, bias)
}

fn baseline_mse(pairs: &[(Vec<f32>, Vec<f32>)], dim: usize) -> f32 {
    let mut mean = vec![0.0f32; dim];
    for (_, y) in pairs {
        for (m, v) in mean.iter_mut().zip(y.iter()) {
            *m += *v;
        }
    }
    for m in mean.iter_mut() {
        *m /= pairs.len() as f32;
    }
    let mut total = 0.0f64;
    for (_, y) in pairs {
        for (m, v) in mean.iter().zip(y.iter()) {
            let d = *m as f64 - *v as f64;
            total += d * d;
        }
    }
    (total / (pairs.len() as f64 * dim as f64)) as f32
}

fn resign(envelope: &mut RepresentationEnvelope, owner: &Wallet) {
    envelope.commitment = envelope.recompute_commitment();
    let auth = Auth::sign(owner, &envelope.signing_hash()).unwrap();
    envelope.sigs = auth.sigs;
    envelope.keys = auth.keys;
}

#[test]
fn spaces_are_distinct_and_dimension_bound() {
    let a = space(1, "transformer-a", "layer-7", 8);
    let b = space(2, "transformer-a", "layer-7", 8);
    let c = space(1, "transformer-b", "layer-7", 8);
    let d = space(1, "transformer-a", "layer-7", 16);
    assert_ne!(a.hash(), b.hash());
    assert_ne!(a.hash(), c.hash());
    assert_ne!(a.hash(), d.hash());
    let encoded = a.encode();
    let mut r = srct_core::ser::Reader::new(&encoded);
    assert_eq!(ModelSpace::decode(&mut r).unwrap(), a);
}

#[test]
fn a_plain_envelope_is_signed_and_tamper_evident() {
    let owner = wallet(1);
    let space = space(1, "model-a", "hidden", 4);
    let values = vec![0.1, -0.2, 0.3, 0.4];
    let mut envelope = RepresentationEnvelope::plain(&owner, space.clone(), &values).unwrap();
    envelope.verify().unwrap();
    assert_eq!(envelope.values(None).unwrap(), values);
    let bytes = envelope.encode();
    assert_eq!(RepresentationEnvelope::decode(&bytes).unwrap(), envelope);

    envelope.payload[0] ^= 0x01;
    assert!(envelope.verify().is_err());
    assert!(envelope.values(None).is_err());
}

#[test]
fn a_sealed_envelope_hides_values_and_binds_the_space() {
    let owner = wallet(2);
    let space_a = space(2, "model-a", "hidden", 4);
    let key = [9u8; 32];
    let values = vec![1.0, 2.0, 3.0, 4.0];
    let envelope = RepresentationEnvelope::sealed(&owner, space_a.clone(), &values, &key).unwrap();
    envelope.verify().unwrap();
    assert_ne!(envelope.payload, {
        let mut plain = Vec::new();
        for v in &values {
            plain.extend_from_slice(&v.to_le_bytes());
        }
        plain
    });
    assert!(envelope.values(None).is_err());
    assert!(envelope.values(Some(&[8u8; 32])).is_err());
    assert_eq!(envelope.values(Some(&key)).unwrap(), values);

    // Re-home the ciphertext to another space with the same dimension and sign
    // it honestly: decryption must still fail because the AAD binds the space.
    let mut moved = envelope.clone();
    moved.space = space(3, "model-b", "hidden", 4);
    resign(&mut moved, &owner);
    moved.verify().unwrap();
    assert!(moved.values(Some(&key)).is_err());
}

#[test]
fn an_adapter_translates_between_different_spaces_with_real_fit() {
    let source_space = space(10, "family-a", "penultimate", 8);
    let target_space = space(11, "family-b", "embedding", 16);
    let (pairs, _) = paired_data(&source_space, &target_space, 128, 7);
    let trainer = wallet(10);
    let adapter = LinearAdapter::fit(
        source_space.clone(),
        target_space.clone(),
        &pairs,
        1e-4,
        &trainer,
    )
    .unwrap();
    adapter.verify().unwrap();
    let mse = adapter.mse(&pairs).unwrap();
    let baseline = baseline_mse(&pairs, 16);
    assert!(
        mse < baseline * 0.1,
        "adapter MSE {mse} must be far below the mean baseline {baseline}"
    );

    let bytes = adapter.encode();
    assert_eq!(LinearAdapter::decode(&bytes).unwrap(), adapter);

    let owner = wallet(11);
    let envelope = RepresentationEnvelope::plain(&owner, source_space, &pairs[0].0).unwrap();
    let translated = adapter.translate(&envelope, None).unwrap();
    assert_eq!(translated.len(), 16);
    assert!(translated.iter().all(|v| v.is_finite()));

    let mut tampered = adapter.clone();
    tampered.weight[0] += 0.5;
    assert!(tampered.verify().is_err());
}

#[test]
fn an_adapter_refuses_the_wrong_source_space() {
    let source_space = space(20, "family-a", "penultimate", 8);
    let target_space = space(21, "family-b", "embedding", 16);
    let (pairs, _) = paired_data(&source_space, &target_space, 32, 8);
    let adapter =
        LinearAdapter::fit(source_space, target_space, &pairs, 1e-3, &wallet(20)).unwrap();
    let other = space(22, "family-c", "penultimate", 8);
    let envelope = RepresentationEnvelope::plain(&wallet(21), other, &[0.0; 8]).unwrap();
    assert!(adapter.translate(&envelope, None).is_err());
}

// Test helper: a readable list of offer fields beats an 11-field builder here.
#[allow(clippy::too_many_arguments)]
fn capability(
    provider: &Wallet,
    source: ModelSpace,
    target: ModelSpace,
    service: &str,
    price: u64,
    max_units: u32,
    latency: u32,
    privacy: Privacy,
    verification: Verification,
    expires: u64,
    nonce: u64,
) -> SignedCapability {
    SignedCapability::sign(
        Capability {
            version: CAPABILITY_VERSION,
            provider: provider.address().unwrap(),
            source,
            target,
            service: service.into(),
            price_sat_per_unit: price,
            max_units,
            latency_ms: latency,
            privacy,
            verification,
            expires_height: expires,
            nonce,
        },
        provider,
    )
    .unwrap()
}

#[test]
fn discovery_filters_and_ranks_deterministically() {
    let a = space(30, "a", "hidden", 8);
    let b = space(31, "b", "hidden", 16);
    let cheap = capability(
        &wallet(30),
        a.clone(),
        b.clone(),
        "translate",
        5,
        8,
        200,
        Privacy::Sealed,
        Verification::ProviderSigned,
        100,
        1,
    );
    let fast = capability(
        &wallet(31),
        a.clone(),
        b.clone(),
        "translate",
        10,
        8,
        20,
        Privacy::Public,
        Verification::ProviderSigned,
        100,
        2,
    );
    let expired = capability(
        &wallet(32),
        a.clone(),
        b.clone(),
        "translate",
        1,
        8,
        10,
        Privacy::Public,
        Verification::ProviderSigned,
        10,
        3,
    );
    let offers = vec![cheap, fast, expired];
    let all = discover(
        &offers,
        &DiscoveryQuery {
            service: Some("translate".into()),
            source: Some(a.hash()),
            target: Some(b.hash()),
            ..DiscoveryQuery::default()
        },
        20,
    );
    assert_eq!(all.len(), 2, "the expired offer is skipped");
    assert_eq!(all[0].signed.capability.price_sat_per_unit, 5);
    assert_eq!(all[1].signed.capability.price_sat_per_unit, 10);

    let fast_only = discover(
        &offers,
        &DiscoveryQuery {
            max_latency_ms: Some(50),
            ..DiscoveryQuery::default()
        },
        20,
    );
    assert_eq!(fast_only.len(), 1);
    assert_eq!(fast_only[0].signed.capability.latency_ms, 20);

    let sealed = discover(
        &offers,
        &DiscoveryQuery {
            min_privacy: Some(Privacy::Sealed),
            ..DiscoveryQuery::default()
        },
        20,
    );
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].signed.capability.price_sat_per_unit, 5);
}

#[test]
fn a_receipt_settles_exactly_and_refuses_wrong_terms() {
    let provider = wallet(40);
    let payer = wallet(41);
    let a = space(40, "a", "hidden", 8);
    let b = space(41, "b", "hidden", 16);
    let offer = capability(
        &provider,
        a,
        b,
        "translate",
        10,
        5,
        50,
        Privacy::Sealed,
        Verification::ProviderSigned,
        100,
        1,
    );
    let receipt = UsageReceipt::new(
        &offer.capability,
        payer.address().unwrap(),
        [0xA1; 32],
        3,
        40,
        1,
    )
    .unwrap();
    let signed = SignedReceipt::sign(receipt, &provider).unwrap();
    signed.verify().unwrap();
    let settlement = settle_receipt(&signed, &offer, 60).unwrap();
    assert_eq!(settlement.from, payer.address().unwrap());
    assert_eq!(settlement.to, provider.address().unwrap());
    assert_eq!(settlement.amount_sat, 30);

    let too_many = UsageReceipt::new(
        &offer.capability,
        payer.address().unwrap(),
        [0xA2; 32],
        6,
        40,
        2,
    )
    .unwrap();
    let signed = SignedReceipt::sign(too_many, &provider).unwrap();
    assert!(settle_receipt(&signed, &offer, 60).is_err());

    let mut wrong_price = UsageReceipt::new(
        &offer.capability,
        payer.address().unwrap(),
        [0xA3; 32],
        1,
        40,
        3,
    )
    .unwrap();
    wrong_price.unit_price_sat = 9;
    wrong_price.total_sat = 9;
    let signed = SignedReceipt::sign(wrong_price, &provider).unwrap();
    assert!(settle_receipt(&signed, &offer, 60).is_err());

    let future = UsageReceipt::new(
        &offer.capability,
        payer.address().unwrap(),
        [0xA4; 32],
        1,
        61,
        4,
    )
    .unwrap();
    let signed = SignedReceipt::sign(future, &provider).unwrap();
    assert!(settle_receipt(&signed, &offer, 60).is_err());
}

#[test]
fn a_receipt_book_settles_once_per_request_id() {
    let provider = wallet(42);
    let payer = wallet(43);
    let a = space(42, "a", "hidden", 8);
    let b = space(43, "b", "hidden", 16);
    let offer = capability(
        &provider,
        a,
        b,
        "translate",
        10,
        5,
        50,
        Privacy::Sealed,
        Verification::ProviderSigned,
        100,
        1,
    );
    let request = [0xB1; 32];
    let receipt = UsageReceipt::new(
        &offer.capability,
        payer.address().unwrap(),
        request,
        2,
        40,
        1,
    )
    .unwrap();
    let signed = SignedReceipt::sign(receipt, &provider).unwrap();
    let mut book = ReceiptBook::new();
    let settlement = book.settle_once(&signed, &offer, 60).unwrap();
    assert_eq!(settlement.amount_sat, 20);
    assert!(book.is_settled(&request));
    assert!(
        book.settle_once(&signed, &offer, 60).is_err(),
        "replay refused"
    );

    let second = UsageReceipt::new(
        &offer.capability,
        payer.address().unwrap(),
        request,
        2,
        40,
        2,
    )
    .unwrap();
    let second = SignedReceipt::sign(second, &provider).unwrap();
    assert!(
        book.settle_once(&second, &offer, 60).is_err(),
        "a second receipt for the same work is refused"
    );

    let other = UsageReceipt::new(
        &offer.capability,
        payer.address().unwrap(),
        [0xB2; 32],
        2,
        40,
        3,
    )
    .unwrap();
    let other = SignedReceipt::sign(other, &provider).unwrap();
    assert!(book.settle_once(&other, &offer, 60).is_ok());
}

#[test]
fn a_plan_quotes_only_when_spaces_chain_and_constraints_hold() {
    let p1 = wallet(50);
    let p2 = wallet(51);
    let a = space(50, "a", "hidden", 8);
    let b = space(51, "b", "hidden", 16);
    let c = space(52, "c", "hidden", 24);
    let first = capability(
        &p1,
        a.clone(),
        b.clone(),
        "translate",
        10,
        8,
        50,
        Privacy::Sealed,
        Verification::ProviderSigned,
        100,
        1,
    );
    let second = capability(
        &p2,
        b.clone(),
        c.clone(),
        "translate",
        20,
        8,
        70,
        Privacy::Sealed,
        Verification::Optimistic,
        100,
        2,
    );
    let offers = vec![first.clone(), second.clone()];
    let plan = Plan {
        version: PLAN_VERSION,
        payer: wallet(52).address().unwrap(),
        input: a.hash(),
        output: c.hash(),
        stages: vec![first.capability.hash(), second.capability.hash()],
        units: vec![1, 1],
        max_total_sat: 50,
        min_privacy: Privacy::Sealed,
        min_verification: Verification::ProviderSigned,
        deadline_height: 90,
    };
    let quote = quote_plan(&plan, &offers, 50).unwrap();
    assert_eq!(quote.total_sat, 30);
    assert_eq!(quote.total_latency_ms, 120);
    assert_eq!(
        quote.providers,
        vec![p1.address().unwrap(), p2.address().unwrap()]
    );

    let broken = Plan {
        stages: vec![second.capability.hash()],
        units: vec![1],
        ..plan.clone()
    };
    assert!(
        quote_plan(&broken, &offers, 50).is_err(),
        "space does not chain"
    );

    let multi_unit = Plan {
        units: vec![2, 1],
        ..plan.clone()
    };
    let quote = quote_plan(&multi_unit, &offers, 50).unwrap();
    assert_eq!(
        quote.total_sat, 40,
        "two units at stage one, one at stage two"
    );

    let over_unit_cap = Plan {
        units: vec![100, 1],
        ..plan.clone()
    };
    assert!(quote_plan(&over_unit_cap, &offers, 50).is_err());

    let over_budget = Plan {
        max_total_sat: 20,
        ..plan.clone()
    };
    assert!(quote_plan(&over_budget, &offers, 50).is_err());

    let wrong_output = Plan {
        output: b.hash(),
        ..plan.clone()
    };
    assert!(quote_plan(&wrong_output, &offers, 50).is_err());

    let too_private = Plan {
        min_privacy: Privacy::Tee,
        ..plan.clone()
    };
    assert!(quote_plan(&too_private, &offers, 50).is_err());

    let expired = Plan {
        deadline_height: 10,
        ..plan
    };
    assert!(quote_plan(&expired, &offers, 50).is_err());
}

#[test]
fn a_capability_cannot_be_signed_for_another_provider() {
    let owner = wallet(60);
    let other = wallet(61);
    let a = space(60, "a", "hidden", 8);
    let b = space(61, "b", "hidden", 16);
    let cap = Capability {
        version: CAPABILITY_VERSION,
        provider: other.address().unwrap(),
        source: a,
        target: b,
        service: "translate".into(),
        price_sat_per_unit: 1,
        max_units: 1,
        latency_ms: 1,
        privacy: Privacy::Public,
        verification: Verification::ProviderSigned,
        expires_height: 100,
        nonce: 1,
    };
    assert!(SignedCapability::sign(cap, &owner).is_err());
}

#[test]
fn address_helpers_do_not_confuse_providers() {
    let a: Address = wallet(70).address().unwrap();
    let b: Address = wallet(71).address().unwrap();
    assert_ne!(a, b);
    assert_eq!(a.len(), 20);
}
