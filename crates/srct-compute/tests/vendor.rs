//! Simulator tests for vendor attestation evidence (Phase B).
//!
//! Every chain, quote and report here is built in-test with fresh P-256
//! keys: no fixtures, no network, no hardware. Real DCAP/KDS/NRAS hosts
//! are gated separately (see the hardware runbook); until those runs
//! pass, everything this file proves is simulator-only.
//!
//! Negative tests pin the key-release rule: any mismatch must make
//! verification fail, because the Phase C broker sends the data key only
//! on `Ok`.

use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey};
use sha2::{Digest, Sha256};
use srct_compute::tee::{
    AttestationRoots, SignedTeeQuote, TeeError, TeeQuote, TeeSla, TeeType, TeeVerifier,
    TEE_VERSION, TEE_VERSION_V1,
};
use srct_compute::vendor::{
    verify_cert_chain, verify_nvidia, verify_snp, verify_tdx, ChainCurve, NvidiaReport, SnpReport,
    TcbPolicy, TdxQuote, VendorEvidence, VendorInputs, VendorRoots,
};
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";
const NOW: u64 = 1_700_000_000; // 2023-11-14T22:13:20Z, inside test cert validity.

// ---------------------------------------------------------------------------
// Minimal DER builders (test-only X.509)
// ---------------------------------------------------------------------------

fn der_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else {
        let mut b = Vec::new();
        let mut v = n;
        while v > 0 {
            b.push((v & 0xff) as u8);
            v >>= 8;
        }
        b.reverse();
        let mut out = vec![0x80 | (b.len() as u8)];
        out.extend_from_slice(&b);
        out
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_SECP256R1: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

fn der_name_cn(cn: &str) -> Vec<u8> {
    let atv = [OID_COMMON_NAME, &tlv(0x0C, cn.as_bytes())].concat();
    tlv(0x30, &tlv(0x31, &atv))
}

fn der_time_utc(s: &str) -> Vec<u8> {
    assert_eq!(s.len(), 13, "UTCTime YYMMDDHHMMSSZ");
    tlv(0x17, s.as_bytes())
}

fn der_spki(pubkey65: &[u8; 65]) -> Vec<u8> {
    assert_eq!(pubkey65[0], 0x04);
    let alg = tlv(0x30, &[OID_EC_PUBLIC_KEY, OID_SECP256R1].concat());
    let mut bitstring_body = vec![0x00];
    bitstring_body.extend_from_slice(pubkey65);
    let bitstring = tlv(0x03, &bitstring_body);
    tlv(0x30, &[alg, bitstring].concat())
}

const OID_SECP384R1: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_ECDSA_SHA384: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

fn raw_sig_to_der(sig: &[u8]) -> Vec<u8> {
    fn int_part(x: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = x.iter().cloned().skip_while(|&b| b == 0).collect();
        if v.is_empty() {
            v.push(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0x00);
        }
        tlv(0x02, &v)
    }
    let (r, s) = sig.split_at(sig.len() / 2);
    tlv(0x30, &[int_part(r), int_part(s)].concat())
}

/// Build a minimal DER certificate. Returns the DER bytes.
#[allow(clippy::too_many_arguments)]
fn make_cert(
    serial: u64,
    issuer_cn: &str,
    subject_cn: &str,
    subject_pubkey65: &[u8; 65],
    not_before: &str,
    not_after: &str,
    signer: &SigningKey,
) -> Vec<u8> {
    let mut serial_body = serial.to_be_bytes().to_vec();
    while serial_body.len() > 1 && serial_body[0] == 0 {
        serial_body.remove(0);
    }
    if serial_body[0] & 0x80 != 0 {
        serial_body.insert(0, 0);
    }
    let tbs = tlv(
        0x30,
        &[
            tlv(0xA0, &tlv(0x02, &[2])),
            tlv(0x02, &serial_body),
            tlv(0x30, OID_ECDSA_SHA256),
            der_name_cn(issuer_cn),
            tlv(
                0x30,
                &[der_time_utc(not_before), der_time_utc(not_after)].concat(),
            ),
            der_name_cn(subject_cn),
            der_spki(subject_pubkey65),
        ]
        .concat(),
    );
    let sig: P256Sig = signer.sign(&tbs);
    let sig_der = raw_sig_to_der(&sig.to_bytes());
    let mut sig_bitstring = vec![0x00];
    sig_bitstring.extend_from_slice(&sig_der);
    tlv(
        0x30,
        &[tbs, tlv(0x30, OID_ECDSA_SHA256), tlv(0x03, &sig_bitstring)].concat(),
    )
}

fn p256_keypair(seed: u8) -> (SigningKey, [u8; 65]) {
    let mut secret = [seed; 32];
    secret[0] = secret[0].wrapping_add(0x11);
    secret[31] = secret[31].wrapping_add(0x37);
    let sk = SigningKey::from_bytes((&secret).into()).unwrap();
    let mut pk = [0u8; 65];
    pk.copy_from_slice(sk.verifying_key().to_encoded_point(false).as_bytes());
    (sk, pk)
}

fn p384_keypair(seed: u8) -> (p384::ecdsa::SigningKey, [u8; 97]) {
    let _ = seed;
    // Deterministic bytes (no RNG): same domain separation idea as above.
    let mut secret = [seed; 48];
    secret[0] = secret[0].wrapping_add(0x11);
    secret[47] = secret[47].wrapping_add(0x37);
    let sk = p384::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
    let mut pk = [0u8; 97];
    pk.copy_from_slice(sk.verifying_key().to_encoded_point(false).as_bytes());
    (sk, pk)
}

fn make_cert_p384(
    serial: u64,
    issuer_cn: &str,
    subject_cn: &str,
    subject_pubkey97: &[u8; 97],
    not_before: &str,
    not_after: &str,
    signer: &p384::ecdsa::SigningKey,
) -> Vec<u8> {
    let mut serial_body = serial.to_be_bytes().to_vec();
    while serial_body.len() > 1 && serial_body[0] == 0 {
        serial_body.remove(0);
    }
    if serial_body[0] & 0x80 != 0 {
        serial_body.insert(0, 0);
    }
    let alg_spki = tlv(0x30, &[OID_EC_PUBLIC_KEY, OID_SECP384R1].concat());
    let mut bs_body = vec![0x00];
    bs_body.extend_from_slice(subject_pubkey97);
    let spki = tlv(0x30, &[alg_spki, tlv(0x03, &bs_body)].concat());
    let tbs = tlv(
        0x30,
        &[
            tlv(0xA0, &tlv(0x02, &[2])),
            tlv(0x02, &serial_body),
            tlv(0x30, OID_ECDSA_SHA384),
            der_name_cn(issuer_cn),
            tlv(
                0x30,
                &[der_time_utc(not_before), der_time_utc(not_after)].concat(),
            ),
            der_name_cn(subject_cn),
            spki,
        ]
        .concat(),
    );
    let sig: p384::ecdsa::Signature = signer.sign(&tbs);
    let sig_der = raw_sig_to_der(&sig.to_bytes());
    let mut sig_bitstring = vec![0x00];
    sig_bitstring.extend_from_slice(&sig_der);
    tlv(
        0x30,
        &[tbs, tlv(0x30, OID_ECDSA_SHA384), tlv(0x03, &sig_bitstring)].concat(),
    )
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "compute-vendor-test").unwrap()
}

/// Root (self-signed) + leaf chain plus the pinned root SPKI hash.
/// Simulator PKI bundle: (leaf DER, root DER, pinned root SPKI hash,
/// leaf pubkey, root pubkey).
type PckChain = (Vec<u8>, Vec<u8>, [u8; 32], [u8; 65], [u8; 65]);

fn pck_chain() -> PckChain {
    let (root_sk, root_pk) = p256_keypair(0xA1);
    let (leaf_sk, leaf_pk) = p256_keypair(0xB2);
    let root_der = make_cert(
        1,
        "sim-root",
        "sim-root",
        &root_pk,
        "230101000000Z",
        "350101000000Z",
        &root_sk,
    );
    let leaf_der = make_cert(
        2,
        "sim-root",
        "sim-pck-leaf",
        &leaf_pk,
        "230101000000Z",
        "350101000000Z",
        &root_sk,
    );
    let mut h = Sha256::new();
    h.update(canonical_spki(&root_pk));
    let pin: [u8; 32] = h.finalize().into();
    let _ = leaf_sk;
    (leaf_der, root_der, pin, leaf_pk, root_pk)
}

fn canonical_spki(pubkey65: &[u8; 65]) -> Vec<u8> {
    let alg = tlv(0x30, &[OID_EC_PUBLIC_KEY, OID_SECP256R1].concat());
    let mut bitstring_body = vec![0x00];
    bitstring_body.extend_from_slice(pubkey65);
    tlv(0x30, &[alg, tlv(0x03, &bitstring_body)].concat())
}

fn canonical_spki384(pubkey97: &[u8; 97]) -> Vec<u8> {
    let alg = tlv(0x30, &[OID_EC_PUBLIC_KEY, OID_SECP384R1].concat());
    let mut bitstring_body = vec![0x00];
    bitstring_body.extend_from_slice(pubkey97);
    tlv(0x30, &[alg, tlv(0x03, &bitstring_body)].concat())
}

fn roots_with(pin: [u8; 32]) -> VendorRoots {
    VendorRoots {
        pinned_root_spki: vec![pin],
        revoked_serials: vec![],
    }
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

#[test]
fn chain_verifies_against_pinned_root() {
    let (leaf_der, root_der, pin, leaf_pk, _root_pk) = pck_chain();
    let leaf_key =
        verify_cert_chain(&[leaf_der, root_der], &[pin], &[], NOW, ChainCurve::P256).unwrap();
    assert_eq!(leaf_key, leaf_pk.to_vec());
}

#[test]
fn chain_refuses_wrong_pin_expired_revoked_and_tampered() {
    let (leaf_der, root_der, pin, _leaf_pk, _root_pk) = pck_chain();
    // Unknown pin.
    assert!(matches!(
        verify_cert_chain(
            &[leaf_der.clone(), root_der.clone()],
            &[[9u8; 32]],
            &[],
            NOW,
            ChainCurve::P256
        ),
        Err(srct_compute::tee::TeeError::Malformed(_))
    ));
    // Expired (after not_after 2035).
    assert_eq!(
        verify_cert_chain(
            &[leaf_der.clone(), root_der.clone()],
            &[pin],
            &[],
            4_102_444_800,
            ChainCurve::P256
        ),
        Err(srct_compute::tee::TeeError::Expired)
    );
    // Revoked leaf serial (leaf serial is 2).
    assert_eq!(
        verify_cert_chain(
            &[leaf_der.clone(), root_der.clone()],
            &[pin],
            &[vec![2u8]],
            NOW,
            ChainCurve::P256,
        ),
        Err(srct_compute::tee::TeeError::RevokedVendorCert)
    );
    // Tampered leaf byte.
    let mut bad = leaf_der.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(
        verify_cert_chain(&[bad, root_der.clone()], &[pin], &[], NOW, ChainCurve::P256).is_err()
    );
    // Empty chain and oversized blob.
    assert!(verify_cert_chain(&[], &[pin], &[], NOW, ChainCurve::P256).is_err());
    assert!(verify_cert_chain(&[vec![0u8; 9_000]], &[pin], &[], NOW, ChainCurve::P256).is_err());
    // Trailing garbage.
    let mut trailing = leaf_der.clone();
    trailing.extend_from_slice(&root_der);
    trailing.push(0x00);
    assert!(verify_cert_chain(&[trailing], &[pin], &[], NOW, ChainCurve::P256).is_err());
}

#[test]
fn split_cert_der_rejects_malformed() {
    use srct_compute::vendor::split_cert_der;
    assert!(split_cert_der(&[]).is_err());
    assert!(split_cert_der(&[0x30, 0x03, 0x01, 0x02, 0x03]).is_err());
    let (leaf_der, _, _, _, _) = pck_chain();
    let (tbs, sig) = split_cert_der(&leaf_der).unwrap();
    assert!(!tbs.is_empty() && !sig.is_empty());
}

// ---------------------------------------------------------------------------
// Simulator TDX evidence
// ---------------------------------------------------------------------------

/// Simulator TDX evidence bundle: (quote, attestation pubkey, session
/// ephem pubkey bytes, nonce bytes, pinned root SPKI hash, root pubkey).
#[allow(clippy::type_complexity)]
type SimTdxEvidence = (TdxQuote, [u8; 65], Vec<u8>, Vec<u8>, [u8; 32], [u8; 65]);

fn sim_tdx(nonce: u64) -> SimTdxEvidence {
    let (root_sk, _root_pk) = p256_keypair(0xA1);
    let (leaf_sk, leaf_pk) = p256_keypair(0xB2);
    let root_der = make_cert(
        1,
        "sim-root",
        "sim-root",
        &_root_pk_of(0xA1),
        "230101000000Z",
        "350101000000Z",
        &root_sk,
    );
    let leaf_der = make_cert(
        2,
        "sim-root",
        "sim-pck-leaf",
        &leaf_pk,
        "230101000000Z",
        "350101000000Z",
        &root_sk,
    );
    let (_att_sk, att_pub) = p256_keypair(0xC3);
    let (eph_sk, eph_pub) = p256_keypair(0xD4);
    let qe_auth_data = b"sim-qe-auth".to_vec();
    // QE report binds the attestation key.
    let mut h = Sha256::new();
    h.update(att_pub);
    h.update(&qe_auth_data);
    let qe_binding: [u8; 32] = h.finalize().into();
    let mut qe_report = [0u8; 384];
    qe_report[320..352].copy_from_slice(&qe_binding);
    // QE report signature (P-256, raw r||s).
    let qe_sig: P256Sig = leaf_sk.sign(&qe_report);
    let mut qe_report_sig = [0u8; 64];
    qe_report_sig.copy_from_slice(&qe_sig.to_bytes());
    // TD report_data binds the session key and nonce.
    let mut r = Sha256::new();
    r.update(eph_pub);
    r.update(nonce.to_le_bytes());
    let binding: [u8; 32] = r.finalize().into();
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&binding);
    let mut mr_td = [0u8; 48];
    mr_td[0] = 0x54;
    let mut rtmrs = [[0u8; 48]; 4];
    rtmrs[0][0] = 0x52;
    let q = TdxQuote {
        version: 4,
        att_key_type: 2,
        tee_type: 0x81,
        qe_svn: 3,
        pce_svn: 5,
        qe_vendor_id: [0u8; 16],
        tee_tcb_svn: [0u8; 16],
        td_attributes: 0,
        mr_td,
        rtmrs,
        report_data,
        qe_report,
        qe_report_sig,
        qe_auth_data,
        cert_chain_der: vec![leaf_der, root_der],
        attestation_pubkey: att_pub,
    };
    let _ = eph_sk;
    let mut pin_h = Sha256::new();
    pin_h.update(canonical_spki(&_root_pk_of(0xA1)));
    let pin: [u8; 32] = pin_h.finalize().into();
    (
        q,
        att_pub,
        eph_pub.to_vec(),
        nonce.to_le_bytes().to_vec(),
        pin,
        _root_pk_of(0xA1),
    )
}

fn _root_pk_of(seed: u8) -> [u8; 65] {
    p256_keypair(seed).1
}

fn sim_inputs(
    measurement: [u8; 32],
    presented: Vec<u8>,
    nonce: u64,
    roots: VendorRoots,
) -> VendorInputs {
    VendorInputs {
        now_unix: NOW,
        presented_pubkey: presented,
        expected_nonce: nonce,
        approved_measurement: measurement,
        tcb: TcbPolicy::default(),
        roots,
        allow_debug: false,
        nvidia_signing_key: None,
        snp_vcek_chain: Vec::new(),
    }
}

fn sim_inputs_full(
    measurement: [u8; 32],
    presented: Vec<u8>,
    nonce: u64,
    roots: VendorRoots,
    vcek_chain: Vec<Vec<u8>>,
    allow_debug: bool,
) -> VendorInputs {
    VendorInputs {
        now_unix: NOW,
        presented_pubkey: presented,
        expected_nonce: nonce,
        approved_measurement: measurement,
        tcb: TcbPolicy::default(),
        roots,
        allow_debug,
        nvidia_signing_key: None,
        snp_vcek_chain: vcek_chain,
    }
}

fn tdx_measurement_id(q: &TdxQuote) -> [u8; 32] {
    VendorEvidence::Tdx(q.clone()).measurement_id()
}

#[test]
fn tdx_roundtrip_and_full_verify_ok() {
    let nonce = 7u64;
    let (q, _att, eph_pub, _, pin, _) = sim_tdx(nonce);
    let encoded = VendorEvidence::Tdx(q.clone()).encode();
    let back = VendorEvidence::decode(&encoded).unwrap();
    assert_eq!(back, VendorEvidence::Tdx(q.clone()));
    let inputs = sim_inputs(tdx_measurement_id(&q), eph_pub, nonce, roots_with(pin));
    verify_tdx(&q, &inputs).unwrap();
}

#[test]
fn tdx_negatives_each_fail_closed() {
    let nonce = 7u64;
    // Debug guest.
    let (mut q, _, eph_pub, _, pin, _) = sim_tdx(nonce);
    q.td_attributes = 1;
    let inputs = sim_inputs(tdx_measurement_id(&q), eph_pub, nonce, roots_with(pin));
    assert_eq!(
        verify_tdx(&q, &inputs),
        Err(srct_compute::tee::TeeError::DebugForbidden)
    );
    // TCB too old.
    let (q, _, eph_pub, _, pin, _) = sim_tdx(nonce);
    let mut old_inputs = sim_inputs(tdx_measurement_id(&q), eph_pub, nonce, roots_with(pin));
    old_inputs.tcb.min_tdx_svn = [0xFFu8; 16];
    assert_eq!(
        verify_tdx(&q, &old_inputs),
        Err(srct_compute::tee::TeeError::TcbTooOld)
    );
    // Wrong measurement.
    let (q, _, eph_pub, _, pin, _) = sim_tdx(nonce);
    let inputs = sim_inputs([9u8; 32], eph_pub, nonce, roots_with(pin));
    assert_eq!(
        verify_tdx(&q, &inputs),
        Err(srct_compute::tee::TeeError::MeasurementMismatch)
    );
    // Broken QE binding (wrong attestation key in report).
    let (mut q, _, eph_pub, _, pin, _) = sim_tdx(nonce);
    q.qe_report[320] ^= 0x01;
    let inputs = sim_inputs(tdx_measurement_id(&q), eph_pub, nonce, roots_with(pin));
    assert!(matches!(
        verify_tdx(&q, &inputs),
        Err(srct_compute::tee::TeeError::BadSignature(_))
    ));
    // Wrong session binding (report_data does not bind presented key).
    let (mut q, _, _, _, pin, _) = sim_tdx(nonce);
    q.report_data[0] ^= 0x01;
    let inputs = sim_inputs(
        tdx_measurement_id(&q),
        vec![0x04u8; 65],
        nonce,
        roots_with(pin),
    );
    assert_eq!(
        verify_tdx(&q, &inputs),
        Err(srct_compute::tee::TeeError::BadReportData)
    );
    // Tampered wire bytes refuse at decode.
    let (q, _, _, _, _, _) = sim_tdx(nonce);
    let bytes = VendorEvidence::Tdx(q).encode();
    // Version byte corruption refuses at decode; content tampering is
    // caught by the signature and report-data checks above.
    let mut bad = bytes.clone();
    bad[1] ^= 0xFF;
    assert!(VendorEvidence::decode(&bad).is_err());
    assert!(VendorEvidence::decode(&bytes[..bytes.len() - 10]).is_err());
    assert!(VendorEvidence::decode(&[]).is_err());
}

// ---------------------------------------------------------------------------
// SNP (full P-384 verification against a simulator VCEK chain)
// ---------------------------------------------------------------------------

/// Build a simulator SNP report signed by a fresh P-384 VCEK leaf, plus
/// the DER chain (leaf, root) and the pinned root SPKI hash.
#[allow(clippy::type_complexity)]
fn sim_snp(nonce: u64) -> (SnpReport, Vec<u8>, Vec<Vec<u8>>, [u8; 32]) {
    sim_snp_with_policy(nonce, 0)
}

fn sim_snp_with_policy(nonce: u64, policy: u64) -> (SnpReport, Vec<u8>, Vec<Vec<u8>>, [u8; 32]) {
    use p384::ecdsa::signature::Signer as _;
    let (root_sk, root_pk) = p384_keypair(0xA1);
    let (leaf_sk, leaf_pk) = p384_keypair(0xB2);
    let root_der = make_cert_p384(
        1,
        "sim-amd-ark",
        "sim-amd-ark",
        &root_pk,
        "230101000000Z",
        "350101000000Z",
        &root_sk,
    );
    let leaf_der = make_cert_p384(
        2,
        "sim-amd-ark",
        "sim-vcek",
        &leaf_pk,
        "230101000000Z",
        "350101000000Z",
        &root_sk,
    );
    let mut pin_h = Sha256::new();
    pin_h.update(canonical_spki384(&root_pk));
    let pin: [u8; 32] = pin_h.finalize().into();
    let (eph_sk, eph_pub) = p256_keypair(0xE5);
    let _ = eph_sk;
    let mut r = Sha256::new();
    r.update(eph_pub);
    r.update(nonce.to_le_bytes());
    let binding: [u8; 32] = r.finalize().into();
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&binding);
    let mut measurement = [0u8; 48];
    measurement[0] = 0x53;
    let mut report = SnpReport {
        version: 2,
        policy,
        report_data,
        measurement,
        reported_tcb: [0, 0, 0, 0, 0, 0, 0, 5],
        current_tcb: [0, 0, 0, 0, 0, 0, 0, 5],
        chip_id: [0xC1u8; 64],
        signature: [0u8; 512],
    };
    // VCEK signs the canonical ABI bytes; the 96-byte raw signature goes
    // in the first 96 bytes of the 512-byte slot.
    let abi = report.abi_bytes();
    let sig: p384::ecdsa::Signature = leaf_sk.sign(&abi);
    report.signature[..96].copy_from_slice(&sig.to_bytes());
    let chain = vec![leaf_der, root_der];
    (report, eph_pub.to_vec(), chain, pin)
}

#[test]
fn snp_full_verify_with_p384_chain() {
    let nonce = 11u64;
    let (r, eph_pub, chain, pin) = sim_snp(nonce);
    let encoded = VendorEvidence::Snp(r.clone()).encode();
    let back = VendorEvidence::decode(&encoded).unwrap();
    assert_eq!(back, VendorEvidence::Snp(r.clone()));
    let mid = VendorEvidence::Snp(r.clone()).measurement_id();
    let inputs = sim_inputs_full(mid, eph_pub, nonce, roots_with(pin), chain, false);
    assert!(verify_snp(&r, &inputs).is_ok());
    // Debug guest without opt-in fails closed.
    let mut debug = r.clone();
    debug.policy = 1u64 << 19;
    assert_eq!(
        verify_snp(&debug, &inputs),
        Err(srct_compute::tee::TeeError::DebugForbidden)
    );
    // ...but passes with an explicit opt-in (freshly signed report, since
    // the policy bits are covered by the VCEK signature).
    let (debug2, _, _, _) = sim_snp_with_policy(nonce, 1u64 << 19);
    let inputs_dbg = sim_inputs_full(
        VendorEvidence::Snp(debug2.clone()).measurement_id(),
        inputs.presented_pubkey.clone(),
        nonce,
        roots_with(pin),
        inputs.snp_vcek_chain.clone(),
        true,
    );
    assert!(verify_snp(&debug2, &inputs_dbg).is_ok());
    // TCB minimum enforced.
    let mut inputs_old = inputs.clone();
    inputs_old.tcb.min_snp_tcb = [0xFFu8; 16];
    assert_eq!(
        verify_snp(&r, &inputs_old),
        Err(srct_compute::tee::TeeError::TcbTooOld)
    );
    // Wrong measurement refuses.
    let inputs_bad_m = VendorInputs {
        approved_measurement: [9u8; 32],
        ..inputs.clone()
    };
    assert_eq!(
        verify_snp(&r, &inputs_bad_m),
        Err(srct_compute::tee::TeeError::MeasurementMismatch)
    );
    // Wrong session binding refuses.
    let inputs_bad_b = VendorInputs {
        presented_pubkey: vec![0x04u8; 65],
        ..inputs.clone()
    };
    assert_eq!(
        verify_snp(&r, &inputs_bad_b),
        Err(srct_compute::tee::TeeError::BadReportData)
    );
    // Tampered report signature refuses.
    let mut bad_sig = r.clone();
    bad_sig.signature[10] ^= 0x01;
    assert!(matches!(
        verify_snp(&bad_sig, &inputs),
        Err(srct_compute::tee::TeeError::BadSignature(_))
    ));
    // Unknown pin refuses (proving the chain is actually checked).
    let inputs_bad_pin = sim_inputs_full(
        mid,
        inputs.presented_pubkey.clone(),
        nonce,
        roots_with([9u8; 32]),
        inputs.snp_vcek_chain.clone(),
        false,
    );
    assert!(verify_snp(&r, &inputs_bad_pin).is_err());
    // Revoked leaf serial refuses.
    let mut inputs_rev = inputs.clone();
    inputs_rev.roots.revoked_serials = vec![vec![2u8]];
    assert_eq!(
        verify_snp(&r, &inputs_rev),
        Err(srct_compute::tee::TeeError::RevokedVendorCert)
    );
    // Truncated and version-skewed blobs refuse at decode.
    assert!(VendorEvidence::decode(&encoded[..encoded.len() - 20]).is_err());
    let mut bad = encoded.clone();
    bad[7] = 0xFF;
    assert!(VendorEvidence::decode(&bad).is_err());
}

// ---------------------------------------------------------------------------
// NVIDIA JWT reports
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn sim_jwt(payload_extra: Option<serde_json::Value>, nonce: u64) -> (Vec<u8>, [u8; 64], [u8; 65]) {
    use base64::Engine as _;
    let (sk, pk) = p256_keypair(0xF6);
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#);
    let (eph_sk, eph_pub) = p256_keypair(0xE5);
    let _ = eph_sk;
    let mut r = Sha256::new();
    r.update(eph_pub);
    r.update(nonce.to_le_bytes());
    let binding: [u8; 32] = r.finalize().into();
    let mut payload = serde_json::json!({
        "x-nvidia-overall-cc-mode": "on",
        "measurements": ["ab".repeat(32)],
        "nonce": hex_encode(&binding),
        "exp": NOW + 3600,
        "iss": "sim-nras",
        "fw_version": 3u64,
    });
    if let Some(extra) = payload_extra {
        for (k, v) in extra.as_object().unwrap() {
            payload[k] = v.clone();
        }
    }
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    let input = format!("{header_b64}.{payload_b64}");
    let sig: P256Sig = sk.sign(input.as_bytes());
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig.to_bytes());
    (input.into_bytes(), sig64, pk)
}

#[test]
fn nvidia_roundtrip_and_full_verify_ok() {
    let nonce = 13u64;
    let (input, sig, pk) = sim_jwt(None, nonce);
    let r = NvidiaReport::from_signing_input(&input, sig).unwrap();
    let (eph_sk, eph_pub) = p256_keypair(0xE5);
    let _ = eph_sk;
    let mut inputs = sim_inputs(
        r.measurement_id(),
        eph_pub.to_vec(),
        nonce,
        roots_with([0u8; 32]),
    );
    inputs.nvidia_signing_key = None;
    assert!(verify_nvidia(&r, &inputs, &pk).is_ok());
    assert_eq!(r.fw_version, 3);
    // Encode/decode roundtrip preserves the parsed report.
    let bytes = VendorEvidence::Nvidia(r.clone()).encode();
    assert_eq!(
        VendorEvidence::decode(&bytes).unwrap(),
        VendorEvidence::Nvidia(r)
    );
}

#[test]
fn nvidia_negatives_each_fail_closed() {
    let nonce = 13u64;
    let (input, sig, pk) = sim_jwt(None, nonce);
    let r = NvidiaReport::from_signing_input(&input, sig).unwrap();
    let (eph_sk, eph_pub) = p256_keypair(0xE5);
    let _ = eph_sk;
    let base = sim_inputs(
        r.measurement_id(),
        eph_pub.to_vec(),
        nonce,
        roots_with([0u8; 32]),
    );
    // Wrong signing key (a genuinely different key, not just a different nonce).
    let other = p256_keypair(0x77).1;
    assert!(matches!(
        verify_nvidia(&r, &base, &other),
        Err(srct_compute::tee::TeeError::BadSignature(_))
    ));
    // CC mode off.
    let (input_off, sig_off, _) = sim_jwt(
        Some(serde_json::json!({"x-nvidia-overall-cc-mode": "off"})),
        nonce,
    );
    assert!(NvidiaReport::from_signing_input(&input_off, sig_off).is_err());
    // Stale expiry.
    let (input_old, sig_old, _) = sim_jwt(Some(serde_json::json!({"exp": NOW - 1})), nonce);
    let r_old = NvidiaReport::from_signing_input(&input_old, sig_old).unwrap();
    assert_eq!(
        verify_nvidia(&r_old, &base, &pk),
        Err(srct_compute::tee::TeeError::Expired)
    );
    // Wrong measurement.
    let base_bad_m = VendorInputs {
        approved_measurement: [9u8; 32],
        ..base.clone()
    };
    assert_eq!(
        verify_nvidia(&r, &base_bad_m, &pk),
        Err(srct_compute::tee::TeeError::MeasurementMismatch)
    );
    // Wrong session binding.
    let base_bad_b = VendorInputs {
        presented_pubkey: vec![0x04u8; 65],
        ..base.clone()
    };
    assert_eq!(
        verify_nvidia(&r, &base_bad_b, &pk),
        Err(srct_compute::tee::TeeError::BadReportData)
    );
    // Non-ES256 header and truncated envelopes refuse at parse.
    use base64::Engine as _;
    let bad_header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let parts: Vec<&str> = std::str::from_utf8(&input).unwrap().split('.').collect();
    let forged = format!("{}.{}", bad_header, parts[1]);
    assert!(NvidiaReport::from_signing_input(forged.as_bytes(), sig).is_err());
    assert!(NvidiaReport::from_signing_input(b"not-a-jwt", sig).is_err());
    assert!(NvidiaReport::from_signing_input(&[], sig).is_err());
}

// ---------------------------------------------------------------------------
// TeeVerifier v2 end to end (simulator TDX evidence)
// ---------------------------------------------------------------------------

fn attester() -> Wallet {
    wallet(2)
}

fn sim_sla_v2(provider: [u8; 20], measurement: [u8; 32]) -> TeeSla {
    TeeSla {
        version: TEE_VERSION,
        network_id: NET.into(),
        provider,
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::Tdx,
        max_age_heights: 10,
        min_tcb_svn: [0u8; 16],
        allow_debug: false,
        measurement,
    }
}

fn sim_quote_v2(sla: &TeeSla, q: TdxQuote, output: [u8; 32]) -> TeeQuote {
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
        height: 100,
        nonce: 7,
        debug: false,
        tcb_svn: [0u8; 16],
        report_data: q.report_binding(),
        vendor: Some(VendorEvidence::Tdx(q)),
    }
}

#[test]
fn v2_full_verify_ok_and_key_release_gate() {
    let provider = wallet(1);
    let att = attester();
    let nonce = 7u64;
    let (q, _, eph_pub, _, pin, _) = sim_tdx(nonce);
    let measurement = VendorEvidence::Tdx(q.clone()).measurement_id();
    let sla = sim_sla_v2(provider.address().unwrap(), measurement);
    let signed = SignedTeeQuote::sign(sim_quote_v2(&sla, q, [25u8; 32]), &att).unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(att.address().unwrap(), TeeType::Tdx);
    let inputs = sim_inputs(measurement, eph_pub, nonce, roots_with(pin));
    // The broker rule, pinned here: the data key is released only on Ok.
    let mut verifier = TeeVerifier::new();
    let released = verifier.verify_v2(
        &sla,
        &signed,
        &roots,
        &inputs,
        &inputs.presented_pubkey.clone(),
        100,
    );
    assert_eq!(released, Ok([25u8; 32]));
}

#[test]
fn v2_report_data_mismatch_never_releases() {
    let provider = wallet(1);
    let att = attester();
    let nonce = 7u64;
    let (q, _, _, _, pin, _) = sim_tdx(nonce);
    let measurement = VendorEvidence::Tdx(q.clone()).measurement_id();
    let sla = sim_sla_v2(provider.address().unwrap(), measurement);
    let signed = SignedTeeQuote::sign(sim_quote_v2(&sla, q, [25u8; 32]), &att).unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(att.address().unwrap(), TeeType::Tdx);
    // Wrong presented key: both the evidence check and the quote-header
    // check must refuse, so no key is ever released on this path.
    let inputs = sim_inputs(measurement, vec![0x04u8; 65], nonce, roots_with(pin));
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify_v2(&sla, &signed, &roots, &inputs, &[0x04u8; 65], 100),
        Err(TeeError::BadReportData)
    );
}

#[test]
fn v2_debug_needs_explicit_opt_in() {
    let provider = wallet(1);
    let att = attester();
    let nonce = 7u64;
    let (mut q, _, eph_pub, _, pin, _) = sim_tdx(nonce);
    q.td_attributes = 1;
    let measurement = VendorEvidence::Tdx(q.clone()).measurement_id();
    let sla = sim_sla_v2(provider.address().unwrap(), measurement);
    let mut quote_dbg = sim_quote_v2(&sla, q, [25u8; 32]);
    // Honest attester mirrors the guest state in the quote header.
    quote_dbg.debug = true;
    let signed = SignedTeeQuote::sign(quote_dbg, &att).unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(att.address().unwrap(), TeeType::Tdx);
    let inputs = sim_inputs(measurement, eph_pub, nonce, roots_with(pin));
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify_v2(
            &sla,
            &signed,
            &roots,
            &inputs,
            &inputs.presented_pubkey.clone(),
            100
        ),
        Err(TeeError::DebugForbidden)
    );
    // A quote that claims non-debug for a debug guest is a lying attester,
    // refused before the policy gate is even reached.
    let (mut q_lying, _, _, _, _, _) = sim_tdx(nonce);
    q_lying.td_attributes = 1;
    let measurement_lying = VendorEvidence::Tdx(q_lying.clone()).measurement_id();
    let sla_lying = sim_sla_v2(provider.address().unwrap(), measurement_lying);
    let lying_quote = sim_quote_v2(&sla_lying, q_lying, [25u8; 32]);
    assert!(!lying_quote.debug);
    let signed_lying = SignedTeeQuote::sign(lying_quote, &att).unwrap();
    let inputs_lying = sim_inputs(
        measurement_lying,
        inputs.presented_pubkey.clone(),
        nonce,
        roots_with(pin),
    );
    let mut verifier_lying = TeeVerifier::new();
    assert_eq!(
        verifier_lying.verify_v2(
            &sla_lying,
            &signed_lying,
            &roots,
            &inputs_lying,
            &inputs_lying.presented_pubkey.clone(),
            100
        ),
        Err(TeeError::BindingMismatch)
    );
    // Explicit opt-in passes the debug gate (other checks still apply).
    // Fresh evidence so every other check passes.
    let (mut q2, _, eph2, _, _, _) = sim_tdx(nonce);
    q2.td_attributes = 1;
    let measurement2 = VendorEvidence::Tdx(q2.clone()).measurement_id();
    let mut sla_opt2 = sim_sla_v2(provider.address().unwrap(), measurement2);
    sla_opt2.allow_debug = true;
    let mut quote2 = sim_quote_v2(&sla_opt2, q2, [25u8; 32]);
    quote2.debug = true;
    let signed2 = SignedTeeQuote::sign(quote2, &att).unwrap();
    let inputs2 = sim_inputs(measurement2, eph2, nonce, roots_with(pin));
    let mut verifier2 = TeeVerifier::new();
    assert_eq!(
        verifier2.verify_v2(
            &sla_opt2,
            &signed2,
            &roots,
            &inputs2,
            &inputs2.presented_pubkey.clone(),
            100
        ),
        Ok([25u8; 32])
    );
}

#[test]
fn v2_without_vendor_context_is_refused() {
    let provider = wallet(1);
    let att = attester();
    let nonce = 7u64;
    let (q, _, _, _, _, _) = sim_tdx(nonce);
    let measurement = VendorEvidence::Tdx(q.clone()).measurement_id();
    let sla = sim_sla_v2(provider.address().unwrap(), measurement);
    let signed = SignedTeeQuote::sign(sim_quote_v2(&sla, q, [25u8; 32]), &att).unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(att.address().unwrap(), TeeType::Tdx);
    // Plain verify() has no vendor context: fail closed, never verify.
    let mut verifier = TeeVerifier::new();
    assert!(matches!(
        verifier.verify(&sla, &signed, &roots, 100),
        Err(TeeError::Malformed(_))
    ));
}

#[test]
fn software_on_mainnet_is_always_refused() {
    let provider = wallet(1);
    let att = attester();
    let output = [25u8; 32];
    let mut roots = AttestationRoots::new();
    roots.add_root(att.address().unwrap(), TeeType::Software);
    // v1 simulator quote on mainnet.
    let sla_v1 = TeeSla {
        version: TEE_VERSION_V1,
        network_id: "srct/mainnet".into(),
        provider: provider.address().unwrap(),
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::Software,
        max_age_heights: 10,
        min_tcb_svn: [0u8; 16],
        allow_debug: false,
        measurement: [0u8; 32],
    };
    let quote_v1 = TeeQuote {
        version: TEE_VERSION_V1,
        network_id: "srct/mainnet".into(),
        provider: provider.address().unwrap(),
        tee: TeeType::Software,
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        output_hash: output,
        height: 100,
        nonce: 1,
        debug: false,
        tcb_svn: [0u8; 16],
        report_data: [0u8; 32],
        vendor: None,
    };
    let signed_v1 = SignedTeeQuote::sign(quote_v1, &att).unwrap();
    let mut verifier = TeeVerifier::new();
    assert_eq!(
        verifier.verify(&sla_v1, &signed_v1, &roots, 100),
        Err(TeeError::SoftwareOnMainnet)
    );
    // v2 simulator quote on mainnet: refused before any vendor work.
    let nonce = 7u64;
    let (q, _, eph_pub, _, pin, _) = sim_tdx(nonce);
    let measurement = VendorEvidence::Tdx(q.clone()).measurement_id();
    let mut sla_v2 = sim_sla_v2(provider.address().unwrap(), measurement);
    sla_v2.network_id = "srct/mainnet".into();
    sla_v2.tee = TeeType::Software;
    roots.add_root(att.address().unwrap(), TeeType::Software);
    let mut quote_v2 = sim_quote_v2(&sla_v2, q, output);
    quote_v2.tee = TeeType::Software;
    quote_v2.network_id = "srct/mainnet".into();
    let signed_v2 = SignedTeeQuote::sign(quote_v2, &att).unwrap();
    let inputs = sim_inputs(measurement, eph_pub, nonce, roots_with(pin));
    let mut verifier2 = TeeVerifier::new();
    assert_eq!(
        verifier2.verify_v2(
            &sla_v2,
            &signed_v2,
            &roots,
            &inputs,
            &inputs.presented_pubkey.clone(),
            100
        ),
        Err(TeeError::SoftwareOnMainnet)
    );
}

#[test]
fn v1_wire_still_decodes_and_verifies() {
    // A v1 quote and SLA built with the old layout verify through the
    // unchanged v1 path, including after the v2 additions.
    let provider = wallet(1);
    let att = wallet(2);
    let sla = TeeSla {
        version: TEE_VERSION_V1,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::Tdx,
        max_age_heights: 10,
        min_tcb_svn: [0u8; 16],
        allow_debug: false,
        measurement: [0u8; 32],
    };
    let quote = TeeQuote {
        version: TEE_VERSION_V1,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        tee: TeeType::Tdx,
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        output_hash: [25u8; 32],
        height: 100,
        nonce: 3,
        debug: false,
        tcb_svn: [0u8; 16],
        report_data: [0u8; 32],
        vendor: None,
    };
    let back = TeeQuote::decode(&quote.encode()).unwrap();
    assert_eq!(back, quote);
    let back_sla = TeeSla::decode(
        &{
            // v1 SLA encoding omits the confidential fields.
            vec![TEE_VERSION_V1]
        }[..],
    )
    .unwrap_err();
    let _ = back_sla;
    let signed = SignedTeeQuote::sign(quote, &att).unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(att.address().unwrap(), TeeType::Tdx);
    let mut verifier = TeeVerifier::new();
    assert_eq!(verifier.verify(&sla, &signed, &roots, 100), Ok([25u8; 32]));
}
