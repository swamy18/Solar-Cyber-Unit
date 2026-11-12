//! Acceptance tests for the AI Work Graph: lineage registration, license
//! enforcement and exact royalty settlement.

use srct_core::wallet::Wallet;
use srct_workgraph::{
    Artifact, ArtifactKind, ArtifactStore, License, SignedArtifact, UsageLedger, WorkError,
    WorkGraph, ARTIFACT_VERSION, MAX_BLOB_BYTES,
};

const NET: &str = "srct/testnet";

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "workgraph-test").unwrap()
}

fn license(reusable: bool, royalty_bps: u64) -> License {
    License {
        reusable,
        royalty_bps,
    }
}

fn artifact(
    owner: &Wallet,
    kind: ArtifactKind,
    parents: Vec<[u8; 32]>,
    lic: License,
    height: u64,
    nonce: u64,
) -> SignedArtifact {
    SignedArtifact::sign(
        Artifact {
            version: ARTIFACT_VERSION,
            network_id: NET.into(),
            kind,
            owner: owner.address().unwrap(),
            model_hash: [11u8; 32],
            input_hash: [12u8; 32],
            runtime_hash: [13u8; 32],
            result_hash: [14u8; 32],
            evidence: [15u8; 32],
            parents,
            license: lic,
            created_height: height,
            nonce,
        },
        owner,
    )
    .unwrap()
}

fn register_root(graph: &mut WorkGraph, owner: &Wallet, bps: u64, nonce: u64) -> [u8; 32] {
    let signed = artifact(
        owner,
        ArtifactKind::TrainingUpdate,
        vec![],
        license(true, bps),
        10,
        nonce,
    );
    graph.register(&signed).unwrap()
}

#[test]
fn register_and_descendants() {
    let a = wallet(1);
    let b = wallet(2);
    let mut graph = WorkGraph::new(NET);
    let root = register_root(&mut graph, &a, 1_000, 1);
    let child = artifact(
        &b,
        ArtifactKind::InferenceResult,
        vec![root],
        license(true, 0),
        11,
        1,
    );
    let child_hash = graph.register(&child).unwrap();
    assert_eq!(graph.descendants(&root), vec![child_hash]);
    assert!(graph.descendants(&child_hash).is_empty());
    // Same bytes cannot register twice.
    assert_eq!(graph.register(&child), Err(WorkError::Replay));
}

#[test]
fn tampered_artifact_fails_the_signature() {
    let a = wallet(1);
    let mut graph = WorkGraph::new(NET);
    let mut signed = artifact(
        &a,
        ArtifactKind::AdapterWeights,
        vec![],
        license(true, 0),
        10,
        1,
    );
    signed.artifact.result_hash = [99u8; 32];
    assert!(matches!(
        graph.register(&signed),
        Err(WorkError::BadSignature(_))
    ));
}

#[test]
fn wrong_owner_cannot_sign() {
    let a = wallet(1);
    let stranger = wallet(9);
    // The body names `a` but the stranger signs: refused.
    let body = artifact(
        &a,
        ArtifactKind::InferenceResult,
        vec![],
        license(true, 0),
        10,
        1,
    )
    .artifact;
    assert_eq!(
        SignedArtifact::sign(body, &stranger),
        Err(WorkError::WrongOwner)
    );
    // The body names the stranger and the stranger signs: accepted.
    let mut body = artifact(
        &a,
        ArtifactKind::InferenceResult,
        vec![],
        license(true, 0),
        10,
        2,
    )
    .artifact;
    body.owner = stranger.address().unwrap();
    assert!(SignedArtifact::sign(body, &stranger).is_ok());
}

#[test]
fn unknown_and_unreusable_parents_are_refused() {
    let a = wallet(1);
    let b = wallet(2);
    let mut graph = WorkGraph::new(NET);
    let child = artifact(
        &a,
        ArtifactKind::InferenceResult,
        vec![[7u8; 32]],
        license(true, 0),
        11,
        1,
    );
    assert_eq!(graph.register(&child), Err(WorkError::UnknownParent));

    let locked = artifact(
        &b,
        ArtifactKind::AdapterWeights,
        vec![],
        license(false, 0),
        10,
        1,
    );
    let locked_hash = graph.register(&locked).unwrap();
    let child = artifact(
        &a,
        ArtifactKind::InferenceResult,
        vec![locked_hash],
        license(true, 0),
        11,
        2,
    );
    assert_eq!(graph.register(&child), Err(WorkError::NotReusable));
}

#[test]
fn parent_newer_than_child_is_refused() {
    let a = wallet(1);
    let b = wallet(2);
    let mut graph = WorkGraph::new(NET);
    let root = register_root(&mut graph, &a, 0, 1);
    // Child claims an earlier creation height than its parent.
    let child = artifact(
        &b,
        ArtifactKind::InferenceResult,
        vec![root],
        license(true, 0),
        5,
        1,
    );
    // Sanity: the fixture really is older than the registered parent.
    assert!(child.artifact.created_height < 10);
    assert!(matches!(
        graph.register(&child),
        Err(WorkError::Malformed(_))
    ));
}

#[test]
fn royalty_chain_splits_exactly() {
    let o1 = wallet(1);
    let o2 = wallet(2);
    let o3 = wallet(3);
    let mut graph = WorkGraph::new(NET);
    // R(10%) <- M(20%) <- L(5%), revenue 100_000 on L.
    let r = register_root(&mut graph, &o1, 1_000, 1);
    let m = graph
        .register(&artifact(
            &o2,
            ArtifactKind::AdapterWeights,
            vec![r],
            license(true, 2_000),
            11,
            1,
        ))
        .unwrap();
    let l = graph
        .register(&artifact(
            &o3,
            ArtifactKind::InferenceResult,
            vec![m],
            license(true, 500),
            12,
            1,
        ))
        .unwrap();
    let payouts = graph.settle_revenue(&l, 100_000).unwrap();
    let get = |w: &Wallet| {
        payouts
            .iter()
            .find(|(a, _)| *a == w.address().unwrap())
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    assert_eq!(get(&o3), 95_000);
    assert_eq!(get(&o2), 4_000);
    assert_eq!(get(&o1), 1_000);
    assert_eq!(payouts.iter().map(|(_, v)| v).sum::<u64>(), 100_000);
}

#[test]
fn multi_parent_split_keeps_dust_with_owner() {
    let o1 = wallet(1);
    let o2 = wallet(2);
    let o3 = wallet(3);
    let owner = wallet(4);
    let mut graph = WorkGraph::new(NET);
    let p1 = register_root(&mut graph, &o1, 0, 1);
    let p2 = register_root(&mut graph, &o2, 0, 2);
    let p3 = register_root(&mut graph, &o3, 0, 3);
    // Royalty 10% of 100_003 = 10_000 (floor); 10_000 / 3 = 3333 each + 1 dust.
    let c = graph
        .register(&artifact(
            &owner,
            ArtifactKind::InferenceResult,
            vec![p1, p2, p3],
            license(true, 1_000),
            12,
            1,
        ))
        .unwrap();
    let payouts = graph.settle_revenue(&c, 100_003).unwrap();
    let get = |w: &Wallet| {
        payouts
            .iter()
            .find(|(a, _)| *a == w.address().unwrap())
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    assert_eq!(get(&o1), 3_333);
    assert_eq!(get(&o2), 3_333);
    assert_eq!(get(&o3), 3_333);
    assert_eq!(get(&owner), 90_004);
    assert_eq!(payouts.iter().map(|(_, v)| v).sum::<u64>(), 100_003);
}

#[test]
fn depth_cap_stops_royalties() {
    let owners: Vec<Wallet> = (1..=12u8).map(wallet).collect();
    let mut graph = WorkGraph::new(NET);
    // Chain C0 <- C1 <- ... <- C11, every link takes 50%.
    let mut prev = register_root(&mut graph, &owners[0], 5_000, 1);
    let mut hashes = vec![prev];
    for (i, owner) in owners.iter().enumerate().skip(1) {
        prev = graph
            .register(&artifact(
                owner,
                ArtifactKind::TrainingUpdate,
                vec![prev],
                license(true, 5_000),
                10 + i as u64,
                1,
            ))
            .unwrap();
        hashes.push(prev);
    }
    let payouts = graph.settle_revenue(&hashes[11], 1_000_000).unwrap();
    assert_eq!(payouts.iter().map(|(_, v)| v).sum::<u64>(), 1_000_000);
    // C0 and C1 are deeper than MAX_ROYALTY_DEPTH below C11: they earn nothing.
    let get = |i: usize| {
        payouts
            .iter()
            .find(|(a, _)| *a == owners[i].address().unwrap())
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    assert_eq!(get(0), 0);
    assert_eq!(get(1), 0);
    // The cutoff artifact keeps what reaches it.
    assert!(get(2) > 0);
}

#[test]
fn zero_royalty_and_bad_revenue() {
    let a = wallet(1);
    let b = wallet(2);
    let mut graph = WorkGraph::new(NET);
    let root = register_root(&mut graph, &a, 0, 1);
    let child = graph
        .register(&artifact(
            &b,
            ArtifactKind::InferenceResult,
            vec![root],
            license(true, 0),
            11,
            1,
        ))
        .unwrap();
    let payouts = graph.settle_revenue(&child, 7_500).unwrap();
    assert_eq!(payouts.len(), 1);
    assert_eq!(payouts[0].1, 7_500);
    assert_eq!(
        graph.settle_revenue(&child, 0),
        Err(WorkError::Malformed("revenue must be positive".into()))
    );
    assert_eq!(
        graph.settle_revenue(&[9u8; 32], 100),
        Err(WorkError::UnknownArtifact)
    );
}

#[test]
fn malformed_artifacts_are_refused() {
    let a = wallet(1);
    let mut graph = WorkGraph::new(NET);
    let base = artifact(
        &a,
        ArtifactKind::ZkProvenResult,
        vec![],
        license(true, 100),
        10,
        1,
    )
    .artifact;
    // Royalty over the cap.
    let mut bad = base.clone();
    bad.license.royalty_bps = 5_001;
    bad.nonce = 11;
    assert!(matches!(
        SignedArtifact::sign(bad, &a),
        Err(WorkError::Malformed(_))
    ));
    // Zero result and zero evidence.
    let mut bad = base.clone();
    bad.result_hash = [0u8; 32];
    bad.nonce = 12;
    assert!(matches!(
        SignedArtifact::sign(bad, &a),
        Err(WorkError::Malformed(_))
    ));
    let mut bad = base.clone();
    bad.evidence = [0u8; 32];
    bad.nonce = 13;
    assert!(matches!(
        SignedArtifact::sign(bad, &a),
        Err(WorkError::Malformed(_))
    ));
    // Zero nonce, unknown kind and truncation at the wire level.
    let mut bad = base.clone();
    bad.nonce = 0;
    assert!(matches!(
        SignedArtifact::sign(bad, &a),
        Err(WorkError::Malformed(_))
    ));
    // Unknown kind byte (offset 15: version || net_len || 12 network bytes).
    let mut encoded = base.encode();
    encoded[15] = 99;
    assert!(matches!(
        Artifact::decode(&encoded),
        Err(WorkError::Malformed(_))
    ));
    assert!(matches!(
        Artifact::decode(&encoded[..encoded.len() - 4]),
        Err(WorkError::Malformed(_))
    ));
    // Wrong network is refused at registration, not at signing.
    let mut net = base.clone();
    net.network_id = "srct/other".into();
    net.nonce = 21;
    let signed = SignedArtifact::sign(net, &a).unwrap();
    assert_eq!(graph.register(&signed), Err(WorkError::WrongNetwork));
}

#[test]
fn wire_mutations_never_panic() {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let a = wallet(1);
    let base = artifact(
        &a,
        ArtifactKind::ZkProvenResult,
        vec![],
        license(true, 100),
        10,
        1,
    );
    let signed = SignedArtifact::sign(base.artifact.clone(), &a).unwrap();
    let corpora = vec![signed.artifact.encode(), signed.encode()];
    let mut rng = StdRng::seed_from_u64(0xbeef);
    for based in &corpora {
        for _ in 0..150 {
            let mut b = based.clone();
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
            let _ = Artifact::decode(&b);
            let _ = SignedArtifact::decode(&b);
        }
    }
}

fn tee_setup() -> (
    srct_verify::AttestationRoots,
    srct_verify::TeeSla,
    srct_verify::SignedTeeQuote,
) {
    use srct_verify::{AttestationRoots, SignedTeeQuote, TeeQuote, TeeSla, TeeType, TEE_VERSION};
    let provider = wallet(21);
    let attester = wallet(22);
    let sla = TeeSla {
        version: TEE_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        tee: TeeType::SevSnp,
        max_age_heights: 10,
    };
    let quote = TeeQuote {
        version: TEE_VERSION,
        network_id: NET.into(),
        provider: provider.address().unwrap(),
        tee: TeeType::SevSnp,
        workload: [11u8; 32],
        model_hash: [21u8; 32],
        runtime_hash: [22u8; 32],
        config_hash: [23u8; 32],
        input_hash: [24u8; 32],
        output_hash: [25u8; 32],
        height: 50,
        nonce: 1,
    };
    let signed = SignedTeeQuote::sign(quote, &attester).unwrap();
    let mut roots = AttestationRoots::new();
    roots.add_root(attester.address().unwrap(), TeeType::SevSnp);
    (roots, sla, signed)
}

#[test]
fn register_with_evidence_checks_the_proof() {
    use srct_verify::{Evidence, UnifiedVerifier};
    let owner = wallet(31);
    let (roots, sla, quote) = tee_setup();
    // Evidence hash is the TEE output hash directly.
    let body = Artifact {
        version: ARTIFACT_VERSION,
        network_id: NET.into(),
        kind: ArtifactKind::AttestedExecution,
        owner: owner.address().unwrap(),
        model_hash: [21u8; 32],
        input_hash: [24u8; 32],
        runtime_hash: [22u8; 32],
        result_hash: [25u8; 32],
        evidence: [25u8; 32],
        parents: vec![],
        license: license(true, 0),
        created_height: 50,
        nonce: 1,
    };
    let signed = SignedArtifact::sign(body, &owner).unwrap();
    let mut graph = WorkGraph::new(NET);
    let mut verifier = UnifiedVerifier::new();
    let evidence = Evidence::Tee {
        sla: sla.clone(),
        quote: quote.clone(),
    };
    graph
        .register_with_evidence(&signed, &evidence, &mut verifier, &roots, 50)
        .unwrap();
    // Same bytes are now a replay (fresh verifier: the proof verifies again,
    // then lineage refuses the duplicate).
    let mut verifier = UnifiedVerifier::new();
    assert_eq!(
        graph.register_with_evidence(&signed, &evidence, &mut verifier, &roots, 50),
        Err(WorkError::Replay)
    );
}

#[test]
fn register_with_evidence_refuses_mismatch_and_fraud() {
    use srct_verify::{Evidence, UnifiedVerifier};
    let owner = wallet(41);
    let (roots, sla, quote) = tee_setup();
    // Wrong evidence hash: proof verifies, binding fails.
    let body = Artifact {
        version: ARTIFACT_VERSION,
        network_id: NET.into(),
        kind: ArtifactKind::AttestedExecution,
        owner: owner.address().unwrap(),
        model_hash: [21u8; 32],
        input_hash: [24u8; 32],
        runtime_hash: [22u8; 32],
        result_hash: [25u8; 32],
        evidence: [99u8; 32],
        parents: vec![],
        license: license(true, 0),
        created_height: 50,
        nonce: 1,
    };
    let signed = SignedArtifact::sign(body, &owner).unwrap();
    let mut graph = WorkGraph::new(NET);
    let mut verifier = UnifiedVerifier::new();
    let evidence = Evidence::Tee {
        sla: sla.clone(),
        quote: quote.clone(),
    };
    assert_eq!(
        graph.register_with_evidence(&signed, &evidence, &mut verifier, &roots, 50),
        Err(WorkError::EvidenceMismatch)
    );
    // Tampered quote: the proof itself is refused, nothing registers.
    let mut bad_quote = quote.clone();
    bad_quote.quote.output_hash = [77u8; 32];
    let bad = Evidence::Tee {
        sla,
        quote: bad_quote,
    };
    let mut verifier = UnifiedVerifier::new();
    assert!(matches!(
        graph.register_with_evidence(&signed, &bad, &mut verifier, &roots, 50),
        Err(WorkError::EvidenceRefused(_))
    ));
    assert!(graph.get(&signed.hash()).is_none());
}

#[test]
fn artifact_store_is_content_addressed_and_bounded() {
    let mut store = ArtifactStore::new();
    let key = store.put(b"manifest-bytes".to_vec()).unwrap();
    // Same bytes are idempotent, not a second entry.
    assert_eq!(store.put(b"manifest-bytes".to_vec()).unwrap(), key);
    assert_eq!(store.len(), 1);
    assert_eq!(store.get(&key).unwrap(), b"manifest-bytes");
    assert!(store.get(&[9u8; 32]).is_none());
    // Empty and over-cap blobs are refused.
    assert!(matches!(
        store.put(Vec::new()),
        Err(WorkError::Malformed(_))
    ));
    assert!(matches!(
        store.put(vec![1u8; MAX_BLOB_BYTES + 1]),
        Err(WorkError::Malformed(_))
    ));
    // Snapshot round-trips; framing tamper and truncation fail closed.
    // (Flipping content bytes just addresses different content — the key
    // is the hash of the bytes, so there is nothing to disagree about.)
    let bytes = store.encode();
    let restored = ArtifactStore::decode(&bytes).unwrap();
    assert_eq!(restored.get(&key).unwrap(), b"manifest-bytes");
    let mut bad = bytes.clone();
    bad[5] ^= 0x01;
    assert!(ArtifactStore::decode(&bad).is_err());
    assert!(ArtifactStore::decode(&bytes[..bytes.len() - 2]).is_err());
    assert!(ArtifactStore::decode(&[99u8; 4]).is_err());
}

#[test]
fn usage_ledger_counts_verified_receipts_once() {
    use srct_cnnp::metering::{SignedReceipt, UsageReceipt};
    use srct_cnnp::registry::{Capability, Privacy, Verification, CAPABILITY_VERSION};
    use srct_cnnp::space::{DType, ModelSpace};
    let provider = wallet(51);
    let payer = wallet(52);
    let space = |id: u8, dim: u32| ModelSpace {
        model_id: [id; 32],
        tokenizer: [id.wrapping_add(1); 32],
        architecture: "mlp".into(),
        layer: "hidden".into(),
        dim,
        dtype: DType::F32,
    };
    let capability = Capability {
        version: CAPABILITY_VERSION,
        provider: provider.address().unwrap(),
        source: space(51, 8),
        target: space(52, 16),
        service: "translate".into(),
        price_sat_per_unit: 5,
        max_units: 100,
        latency_ms: 50,
        privacy: Privacy::Public,
        verification: Verification::ProviderSigned,
        expires_height: 1_000,
        nonce: 1,
    };
    let receipt = SignedReceipt::sign(
        UsageReceipt::new(&capability, payer.address().unwrap(), [7u8; 32], 4, 10, 1).unwrap(),
        &provider,
    )
    .unwrap();
    let mut ledger = UsageLedger::new();
    assert_eq!(ledger.record(&receipt).unwrap(), 4);
    assert_eq!(ledger.units_for_capability(&capability.hash()), 4);
    assert_eq!(ledger.revenue_for_capability(&capability.hash()), 20);
    assert_eq!(ledger.units_for_provider(&provider.address().unwrap()), 4);
    // The same receipt never counts twice.
    assert_eq!(ledger.record(&receipt), Err(WorkError::Replay));
    // A tampered receipt counts never.
    let mut bad = receipt.clone();
    bad.receipt.units = 9;
    assert!(matches!(
        ledger.record(&bad),
        Err(WorkError::EvidenceRefused(_))
    ));
    assert_eq!(ledger.units_for_capability(&capability.hash()), 4);
}

#[test]
fn revenue_escrow_locks_releases_and_refunds_once() {
    use srct_workgraph::{RevenueEscrow, WorkError};
    let payer = wallet(61).address().unwrap();
    let alice = wallet(62).address().unwrap();
    let bob = wallet(63).address().unwrap();
    let artifact = [77u8; 32];
    let mut escrow = RevenueEscrow::new(NET);
    // Zero locks and duplicate locks are refused.
    assert!(escrow.lock(&artifact, payer, 0, 1).is_err());
    let id = escrow.lock(&artifact, payer, 1_000, 1).unwrap();
    assert!(escrow.lock(&artifact, payer, 1_000, 1).is_err());
    // A different nonce is a different earning event.
    let id2 = escrow.lock(&artifact, payer, 500, 2).unwrap();
    assert_ne!(id, id2);
    // Releases split the locked total across owners, never above it.
    let p1 = escrow.release(&id, alice, 700).unwrap();
    assert_eq!(p1.from, payer);
    assert_eq!(p1.to, alice);
    assert_eq!(p1.amount_sat, 700);
    assert_eq!(escrow.released_total(&id), 700);
    let p2 = escrow.release(&id, bob, 200).unwrap();
    assert_eq!(p2.amount_sat, 200);
    assert!(escrow.release(&id, bob, 101).is_err());
    assert!(escrow.release(&[9u8; 32], bob, 1).is_err());
    // The remainder refunds to the payer exactly once.
    let refund = escrow.refund(&id).unwrap();
    assert_eq!(refund.to, payer);
    assert_eq!(refund.amount_sat, 100);
    assert_eq!(escrow.refund(&id), Err(WorkError::Replay));
    assert!(escrow.release(&id, bob, 1).is_err());
    // A fully released revenue has no remainder to refund.
    let id3 = escrow.lock(&artifact, payer, 300, 3).unwrap();
    escrow.release(&id3, alice, 300).unwrap();
    assert!(matches!(escrow.refund(&id3), Err(WorkError::Malformed(_))));
}
