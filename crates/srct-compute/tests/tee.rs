//! Acceptance tests for TEE-backed execution evidence: signed attestation
//! quotes, trusted roots with revocation, SLA measurement checks, freshness
//! and replay protection.

use srct_compute::tee::{
    AttestationRoots, SignedTeeQuote, TeeError, TeeQuote, TeeSla, TeeType, TeeVerifier, TEE_VERSION,
};
use srct_core::hash::Hash;
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const MAX_AGE: u64 = 10;
const HEIGHT: u64 = 100;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "compute-tee-test").unwrap()
}

fn hashes() -> (Hash, Hash, Hash, Hash, Hash, Hash) {
    (
        [11u8; 32], [21u8; 32], [22u8; 32], [23u8; 32], [24u8; 32], [25u8; 32],
    )
}

fn setup() -> (Wallet, Wallet, Wallet, TeeSla, AttestationRoots) {
    let provider = wallet(1);
    let attester = wallet(2);
    let stranger = wallet(9);
    let (workload, model, runtime, config, input, _output) = hashes();
    let sla = TeeSla {
        version: TEE_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        workload,
        model_hash: model,
        runtime_hash: runtime,
        config_hash: config,
        input_hash: input,
        tee: TeeType::SevSnp,
        max_age_heights: MAX_AGE,
    };
    let mut roots = AttestationRoots::new();
    roots.add_root(attester.address().unwrap(), TeeType::SevSnp);
    (provider, attester, stranger, sla, roots)
}

fn quote_for(sla: &TeeSla, height: u64, nonce: u64, output: Hash) -> TeeQuote {
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
        height,
        nonce,
    }
}

#[test]
fn valid_quote_verifies_and_returns_output() {
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let signed = SignedTeeQuote::sign(quote_for(&sla, HEIGHT, 1, output), &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(verifier.verify(&sla, &signed, &roots, HEIGHT), Ok(output));
}

#[test]
fn tampered_output_breaks_the_signature() {
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let mut signed = SignedTeeQuote::sign(quote_for(&sla, HEIGHT, 1, output), &attester).unwrap();
    signed.quote.output_hash = [99u8; 32];
    let mut verifier = TeeVerifier::new();
    assert!(matches!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::BadSignature(_))
    ));
}

#[test]
fn unknown_attester_is_refused() {
    let (_provider, _attester, stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let signed = SignedTeeQuote::sign(quote_for(&sla, HEIGHT, 1, output), &stranger).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::UnknownAttester)
    );
}

#[test]
fn revoked_root_is_refused() {
    let (_provider, attester, _stranger, sla, mut roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let signed = SignedTeeQuote::sign(quote_for(&sla, HEIGHT, 1, output), &attester).unwrap();
    assert!(roots.revoke(&attester.address().unwrap()));
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::RevokedAttester)
    );
}

#[test]
fn measurement_mismatch_is_refused() {
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let mut bad = quote_for(&sla, HEIGHT, 1, output);
    bad.model_hash = [77u8; 32];
    let signed = SignedTeeQuote::sign(bad, &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::MeasurementMismatch)
    );

    let mut bad = quote_for(&sla, HEIGHT, 2, output);
    bad.runtime_hash = [78u8; 32];
    let signed = SignedTeeQuote::sign(bad, &attester).unwrap();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::MeasurementMismatch)
    );

    let mut bad = quote_for(&sla, HEIGHT, 3, output);
    bad.config_hash = [79u8; 32];
    let signed = SignedTeeQuote::sign(bad, &attester).unwrap();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::MeasurementMismatch)
    );
}

#[test]
fn wrong_binding_is_refused() {
    let (provider, attester, stranger, sla, roots) = setup();
    let _ = provider;
    let (_, _, _, _, _, output) = hashes();
    // Quote names a different provider than the SLA pins.
    let mut bad = quote_for(&sla, HEIGHT, 1, output);
    bad.provider = stranger.address().unwrap();
    let signed = SignedTeeQuote::sign(bad, &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::BindingMismatch)
    );

    // Quote is bound to a different workload.
    let mut bad = quote_for(&sla, HEIGHT, 2, output);
    bad.workload = [88u8; 32];
    let signed = SignedTeeQuote::sign(bad, &attester).unwrap();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::BindingMismatch)
    );
}

#[test]
fn input_mismatch_is_refused() {
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let mut bad = quote_for(&sla, HEIGHT, 1, output);
    bad.input_hash = [66u8; 32];
    let signed = SignedTeeQuote::sign(bad, &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::InputMismatch)
    );
}

#[test]
fn stale_and_future_quotes_are_refused() {
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let stale =
        SignedTeeQuote::sign(quote_for(&sla, HEIGHT - MAX_AGE - 1, 1, output), &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla, &stale, &roots, HEIGHT),
        Err(TeeError::Expired)
    );

    let future = SignedTeeQuote::sign(quote_for(&sla, HEIGHT + 1, 2, output), &attester).unwrap();
    assert_eq!(
        verifier.verify(&sla, &future, &roots, HEIGHT),
        Err(TeeError::FutureHeight)
    );

    // Exactly at the age limit is still fresh.
    let edge =
        SignedTeeQuote::sign(quote_for(&sla, HEIGHT - MAX_AGE, 3, output), &attester).unwrap();
    assert_eq!(verifier.verify(&sla, &edge, &roots, HEIGHT), Ok(output));
}

#[test]
fn same_quote_cannot_verify_twice() {
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let signed = SignedTeeQuote::sign(quote_for(&sla, HEIGHT, 1, output), &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(verifier.verify(&sla, &signed, &roots, HEIGHT), Ok(output));
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::Replay)
    );
}

#[test]
fn tee_type_mismatch_is_refused() {
    let (provider, attester, _stranger, sla, mut roots) = setup();
    let _ = provider;
    let (_, _, _, _, _, output) = hashes();
    // Same trusted attester, but the quote claims a family the SLA did not ask for.
    roots.add_root(attester.address().unwrap(), TeeType::SevSnp);
    let mut bad = quote_for(&sla, HEIGHT, 1, output);
    bad.tee = TeeType::Tdx;
    let signed = SignedTeeQuote::sign(bad, &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla, &signed, &roots, HEIGHT),
        Err(TeeError::TeeTypeMismatch)
    );

    // A simulator quote is accepted only by an SLA that asks for one.
    let mut sim_roots = AttestationRoots::new();
    sim_roots.add_root(attester.address().unwrap(), TeeType::Software);
    let mut sim_sla = sla.clone();
    sim_sla.tee = TeeType::Software;
    let mut sim = quote_for(&sim_sla, HEIGHT, 7, output);
    sim.tee = TeeType::Software;
    let signed = SignedTeeQuote::sign(sim, &attester).unwrap();
    assert_eq!(
        TeeVerifier::new().verify(&sim_sla, &signed, &sim_roots, HEIGHT),
        Ok(output)
    );
}

#[test]
fn wire_roundtrip_and_malformed_refusals() {
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let quote = quote_for(&sla, HEIGHT, 1, output);
    let back = TeeQuote::decode(&quote.encode()).unwrap();
    assert_eq!(back, quote);
    let signed = SignedTeeQuote::sign(quote, &attester).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(verifier.verify(&sla, &signed, &roots, HEIGHT), Ok(output));

    // Unknown version and truncation are refused at decode.
    let mut bad_version = quote_for(&sla, HEIGHT, 2, output).encode();
    bad_version[0] = 99;
    assert!(matches!(
        TeeQuote::decode(&bad_version),
        Err(TeeError::Malformed(_))
    ));
    let encoded = quote_for(&sla, HEIGHT, 3, output).encode();
    assert!(matches!(
        TeeQuote::decode(&encoded[..encoded.len() - 4]),
        Err(TeeError::Malformed(_))
    ));
    // Zero output hash and zero nonce never sign.
    let mut zero_out = quote_for(&sla, HEIGHT, 4, output);
    zero_out.output_hash = [0u8; 32];
    assert!(matches!(
        SignedTeeQuote::sign(zero_out, &attester),
        Err(TeeError::Malformed(_))
    ));
    let mut zero_nonce = quote_for(&sla, HEIGHT, 0, output);
    zero_nonce.nonce = 0;
    assert!(matches!(
        SignedTeeQuote::sign(zero_nonce, &attester),
        Err(TeeError::Malformed(_))
    ));
}

/// Release-mode timing probe (ignored in normal runs). Prints mean sign and
/// verify latency; numbers go to `docs/benchmarks.md`.
#[test]
#[ignore]
fn bench_tee_quote_verify() {
    use std::time::Instant;
    let (_provider, attester, _stranger, sla, roots) = setup();
    let (_, _, _, _, _, output) = hashes();
    let t0 = Instant::now();
    let n = 200u32;
    for i in 0..n {
        let signed =
            SignedTeeQuote::sign(quote_for(&sla, HEIGHT, (i + 1) as u64, output), &attester)
                .unwrap();
        TeeVerifier::new()
            .verify(&sla, &signed, &roots, HEIGHT)
            .unwrap();
    }
    let ms = t0.elapsed().as_secs_f64() * 1000.0 / f64::from(n);
    println!("tee sign+verify: {ms:.3} ms/op over {n} ops");
}
