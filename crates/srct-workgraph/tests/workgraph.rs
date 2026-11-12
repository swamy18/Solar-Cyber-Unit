//! Acceptance tests for the AI Work Graph: lineage registration, license
//! enforcement and exact royalty settlement.

use srct_core::wallet::Wallet;
use srct_workgraph::{
    Artifact, ArtifactKind, License, SignedArtifact, WorkError, WorkGraph, ARTIFACT_VERSION,
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
