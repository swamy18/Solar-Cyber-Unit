//! End-to-end CNNP demo:
//! two different representation spaces -> fitted adapter -> signed envelope
//! -> sealed translation -> capability discovery -> plan quote -> settlement.
//!
//! Run with:
//! ```text
//! cargo run --release -p srct-cnnp --example cnnp_demo
//! ```

use srct_cnnp::adapter::LinearAdapter;
use srct_cnnp::metering::{
    quote_plan, settle_receipt, Plan, SignedReceipt, UsageReceipt, PLAN_VERSION,
};
use srct_cnnp::registry::{
    cheapest_translation, Capability, SignedCapability, Verification, CAPABILITY_VERSION,
};
use srct_cnnp::space::{DType, ModelSpace, RepresentationEnvelope};
use srct_core::wallet::Wallet;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "cnnp-demo").unwrap()
}

fn space(id: u8, architecture: &str, dim: u32) -> ModelSpace {
    ModelSpace {
        model_id: [id; 32],
        tokenizer: [id.wrapping_add(1); 32],
        architecture: architecture.into(),
        layer: "hidden".into(),
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

fn main() {
    let a = space(10, "family-a", 8);
    let b = space(11, "family-b", 16);
    let c = space(12, "family-c", 24);

    let mut rng = Lcg::new(7);
    let mut matrix = vec![0.0f32; 16 * 8];
    for w in matrix.iter_mut() {
        *w = rng.signed() * 0.6;
    }
    let bias: Vec<f32> = (0..16).map(|_| rng.signed() * 0.1).collect();
    let mut pairs = Vec::new();
    for _ in 0..128 {
        let x = [rng.signed(), rng.signed()];
        let s: Vec<f32> = (0..8)
            .map(|j| ((j as f32 + 1.0) * 0.7 * x[0] - (j as f32 * 0.3) * x[1]).tanh())
            .collect();
        let t: Vec<f32> = matrix
            .chunks_exact(8)
            .zip(bias.iter())
            .map(|(row, b)| {
                let mut acc = *b;
                for (w, v) in row.iter().zip(s.iter()) {
                    acc += w * v;
                }
                acc + 0.02 * (x[0] * x[1]).sin()
            })
            .collect();
        pairs.push((s, t));
    }

    let started = std::time::Instant::now();
    let trainer = wallet(10);
    let adapter = LinearAdapter::fit(a.clone(), b.clone(), &pairs, 1e-4, &trainer).unwrap();
    let fit_us = started.elapsed().as_micros();
    let adapter_mse = adapter.mse(&pairs).unwrap();
    let mut mean = [0.0f32; 16];
    for (_, y) in &pairs {
        for (m, v) in mean.iter_mut().zip(y.iter()) {
            *m += *v;
        }
    }
    for m in mean.iter_mut() {
        *m /= pairs.len() as f32;
    }
    let mut base_total = 0.0f64;
    for (_, y) in &pairs {
        for (m, v) in mean.iter().zip(y.iter()) {
            let d = *m as f64 - *v as f64;
            base_total += d * d;
        }
    }
    let baseline = (base_total / (pairs.len() as f64 * 16.0)) as f32;
    println!(
        "adapter: {:.6} MSE vs {:.6} mean baseline (fit {} us, {} samples)",
        adapter_mse, baseline, fit_us, adapter.samples
    );

    let owner = wallet(11);
    let key = [42u8; 32];
    let envelope = RepresentationEnvelope::sealed(&owner, a.clone(), &pairs[0].0, &key).unwrap();
    let translated = adapter.translate(&envelope, Some(&key)).unwrap();
    println!(
        "envelope: {} bytes sealed, translated to {} dims, first {:.4}",
        envelope.encode().len(),
        translated.len(),
        translated[0]
    );

    let provider_b = wallet(20);
    let provider_c = wallet(21);
    let offer_ab = SignedCapability::sign(
        Capability {
            version: CAPABILITY_VERSION,
            provider: provider_b.address().unwrap(),
            source: a.clone(),
            target: b.clone(),
            service: "translate".into(),
            price_sat_per_unit: 10,
            max_units: 8,
            latency_ms: 40,
            privacy: srct_cnnp::Privacy::Sealed,
            verification: Verification::ProviderSigned,
            expires_height: 1_000,
            nonce: 1,
        },
        &provider_b,
    )
    .unwrap();
    let offer_bc = SignedCapability::sign(
        Capability {
            version: CAPABILITY_VERSION,
            provider: provider_c.address().unwrap(),
            source: b.clone(),
            target: c.clone(),
            service: "translate".into(),
            price_sat_per_unit: 20,
            max_units: 8,
            latency_ms: 60,
            privacy: srct_cnnp::Privacy::Sealed,
            verification: Verification::Optimistic,
            expires_height: 1_000,
            nonce: 2,
        },
        &provider_c,
    )
    .unwrap();
    let offers = vec![offer_ab.clone(), offer_bc.clone()];
    let cheapest = cheapest_translation(&offers, a.hash(), c.hash(), 100, 100);
    println!(
        "direct A->C offer: {:?}",
        cheapest.map(|c| c.capability_hash[0])
    );

    let plan = Plan {
        version: PLAN_VERSION,
        payer: wallet(30).address().unwrap(),
        input: a.hash(),
        output: c.hash(),
        stages: vec![offer_ab.capability.hash(), offer_bc.capability.hash()],
        units: vec![1, 1],
        max_total_sat: 100,
        min_privacy: srct_cnnp::Privacy::Sealed,
        min_verification: Verification::ProviderSigned,
        deadline_height: 500,
    };
    let quote = quote_plan(&plan, &offers, 100).unwrap();
    println!(
        "plan: {} stages, {} sat, {} ms, providers {:?}",
        quote.stages.len(),
        quote.total_sat,
        quote.total_latency_ms,
        quote.providers.iter().map(|p| p[0]).collect::<Vec<u8>>()
    );

    let receipt =
        UsageReceipt::new(&offer_ab.capability, plan.payer, [0xC1; 32], 3, 100, 1).unwrap();
    let signed = SignedReceipt::sign(receipt, &provider_b).unwrap();
    let settlement = settle_receipt(&signed, &offer_ab, 110).unwrap();
    println!(
        "settlement: {} -> {} for {} sat",
        settlement.from[0], settlement.to[0], settlement.amount_sat
    );
}
