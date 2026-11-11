//! Acceptance tests for the DiLoCo PoUW prototype.
//!
//! These are not interface tests: they train the model, check that loss falls
//! and accuracy rises, and then attack the round with fabricated, duplicated,
//! oversized and low-quality updates. A passing run is the evidence that the
//! useful-work half of dual mining has a working, measurable prototype.

use srct_core::wallet::Wallet;
use srct_diloco::data::{accuracy, mean_loss, shards, two_moons};
use srct_diloco::model::Mlp;
use srct_diloco::round::{Rejection, RoundConfig, RoundOutcome, RoundState};
use srct_diloco::update::{commit_delta, SignedUpdate, UpdateClaim};

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "diloco-acceptance").unwrap()
}

fn train_local(base: &Mlp, shard: &[srct_diloco::Sample], steps: u32, lr: f32) -> Mlp {
    let mut local = base.clone();
    for _ in 0..steps {
        let (_, grad) = local.loss_and_grad(shard);
        local.sgd_step(&grad, lr);
    }
    local
}

fn signed(
    round_id: u64,
    base: &Mlp,
    worker: &Wallet,
    local: &Mlp,
    samples: u64,
    steps: u32,
) -> SignedUpdate {
    let claim = UpdateClaim::new(
        round_id,
        base,
        worker.address().unwrap(),
        local,
        samples,
        steps,
        0.5,
    );
    SignedUpdate::sign(worker, claim).unwrap()
}

#[test]
fn diloco_training_reduces_loss_and_reaches_accuracy() {
    let data = two_moons(96, 21);
    let parts = shards(&data, 3);
    let initial_model = Mlp::new(21);
    let initial_loss = mean_loss(&initial_model, &data);
    let initial_accuracy = accuracy(&initial_model, &data);

    let mut global = initial_model;
    let mut velocity = Mlp::zeros();
    let worker_wallets = [wallet(31), wallet(32), wallet(33)];
    let mut last_round = None;

    for round_id in 1..=24u64 {
        let mut cfg = RoundConfig::new(round_id, 2);
        cfg.reward_pot_sat = 1_000_000;
        cfg.max_update_norm = 20.0;
        cfg.min_cosine = 0.0;
        cfg.momentum = 0.0;
        cfg.outer_lr = 1.0;
        let mut round = RoundState::new(cfg, global.clone(), velocity.clone()).unwrap();
        for (i, w) in worker_wallets.iter().enumerate() {
            round
                .register_worker(w.address().unwrap(), 10_000, parts[i].len() as u64)
                .unwrap();
            let local = train_local(&global, &parts[i], 20, 0.05);
            round
                .submit(signed(
                    round_id,
                    &global,
                    w,
                    &local,
                    parts[i].len() as u64,
                    20,
                ))
                .unwrap();
        }
        match round.finalize() {
            RoundOutcome::Finalized(done) => {
                assert!(done.rewards_are_exact());
                assert_eq!(done.accepted.len(), 3, "round {round_id}");
                global = done.model.clone();
                velocity = round.velocity().clone();
                last_round = Some(done);
            }
            other => panic!("round {round_id} failed: {other:?}"),
        }
    }

    let final_loss = mean_loss(&global, &data);
    let final_accuracy = accuracy(&global, &data);
    let last = last_round.expect("at least one finalized round");
    let checkpoint: String = last
        .model_hash
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    println!(
        "diloco: loss {initial_loss:.4} -> {final_loss:.4}, accuracy {initial_accuracy:.3} -> {final_accuracy:.3}, checkpoint {checkpoint}"
    );
    assert!(
        final_loss < initial_loss * 0.85,
        "training must measurably reduce loss: {initial_loss} -> {final_loss}"
    );
    assert!(
        final_accuracy > 0.85,
        "two-moons accuracy must clear 85%: {final_accuracy}"
    );
}

#[test]
fn oversized_and_non_finite_updates_are_rejected_before_aggregation() {
    let base = Mlp::new(41);
    let worker = wallet(41);
    let mut cfg = RoundConfig::new(1, 1);
    cfg.max_update_norm = 2.0;
    let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
    round
        .register_worker(worker.address().unwrap(), 10_000, 16)
        .unwrap();

    let mut local = base.clone();
    local.b2[0] += 0.1;
    let honest = signed(1, &base, &worker, &local, 16, 4);
    let mut huge = honest.clone();
    huge.claim.delta = huge.claim.delta.scale(100.0);
    huge.claim.commitment = commit_delta(
        1,
        &worker.address().unwrap(),
        &base.hash(),
        &huge.claim.delta,
    );
    let auth = srct_core::l2::Auth::sign(&worker, &huge.claim.signing_hash()).unwrap();
    huge.sigs = auth.sigs;
    huge.keys = auth.keys;
    assert!(matches!(
        round.submit(huge),
        Err(Rejection::UpdateTooLarge { .. })
    ));

    let mut not_finite = honest.clone();
    not_finite.claim.delta.b2[0] = f32::NAN;
    not_finite.claim.commitment = commit_delta(
        1,
        &worker.address().unwrap(),
        &base.hash(),
        &not_finite.claim.delta,
    );
    let auth = srct_core::l2::Auth::sign(&worker, &not_finite.claim.signing_hash()).unwrap();
    not_finite.sigs = auth.sigs;
    not_finite.keys = auth.keys;
    assert!(matches!(
        round.submit(not_finite),
        Err(Rejection::NonFinite)
    ));
}

#[test]
fn a_worker_cannot_claim_more_samples_than_the_coordinator_assigned() {
    let base = Mlp::new(56);
    let worker = wallet(56);
    let cfg = RoundConfig::new(1, 1);
    let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
    round
        .register_worker(worker.address().unwrap(), 10_000, 16)
        .unwrap();
    let mut local = base.clone();
    local.b2[0] += 0.1;
    let update = signed(1, &base, &worker, &local, 64, 4);
    assert!(matches!(
        round.submit(update),
        Err(Rejection::SamplesExceedAssignment {
            claimed: 64,
            assigned: 16
        })
    ));
}

#[test]
fn duplicate_and_replayed_updates_cannot_count_twice() {
    let base = Mlp::new(51);
    let worker = wallet(51);
    let mut cfg = RoundConfig::new(1, 2);
    cfg.reward_pot_sat = 100;
    let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
    round
        .register_worker(worker.address().unwrap(), 10_000, 16)
        .unwrap();
    let mut local = base.clone();
    local.b2[0] += 0.1;
    let update = signed(1, &base, &worker, &local, 16, 4);
    round.submit(update.clone()).unwrap();
    assert!(matches!(
        round.submit(update),
        Err(Rejection::DuplicateCommitment)
    ));
}

#[test]
fn the_wrong_round_model_or_base_is_refused() {
    let base = Mlp::new(61);
    let worker = wallet(61);
    let cfg = RoundConfig::new(7, 1);
    let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
    round
        .register_worker(worker.address().unwrap(), 10_000, 16)
        .unwrap();
    let mut local = base.clone();
    local.b2[0] += 0.1;
    let update = signed(6, &base, &worker, &local, 16, 4);
    assert!(matches!(
        round.submit(update),
        Err(Rejection::WrongRound { .. })
    ));

    let mut wrong_base = base.clone();
    wrong_base.b2[0] += 0.2;
    let update = signed(7, &wrong_base, &worker, &local, 16, 4);
    assert!(matches!(round.submit(update), Err(Rejection::BaseMismatch)));
}

#[test]
fn a_forged_worker_key_is_refused() {
    let base = Mlp::new(71);
    let worker = wallet(71);
    let stranger = wallet(72);
    let cfg = RoundConfig::new(1, 1);
    let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
    round
        .register_worker(worker.address().unwrap(), 10_000, 16)
        .unwrap();
    let mut local = base.clone();
    local.b2[0] += 0.1;
    let mut update = signed(1, &base, &worker, &local, 16, 4);
    let auth = srct_core::l2::Auth::sign(&stranger, &update.claim.signing_hash()).unwrap();
    update.sigs = auth.sigs;
    update.keys = auth.keys;
    assert!(matches!(
        round.submit(update),
        Err(Rejection::BadSignature(_))
    ));
}

#[test]
fn a_low_quality_outlier_is_excluded_from_aggregation_and_rewards() {
    let base = Mlp::new(81);
    let parts = shards(&two_moons(48, 81), 3);
    let mut local_a = base.clone();
    let (_, grad) = local_a.loss_and_grad(&parts[0]);
    local_a.sgd_step(&grad, 0.5);
    let mut local_b = base.clone();
    let (_, grad) = local_b.loss_and_grad(&parts[1]);
    local_b.sgd_step(&grad, 0.5);
    let delta = local_a.sub(&base);
    let opposite_params: Vec<f32> = base
        .params()
        .iter()
        .zip(delta.params().iter())
        .map(|(p, d)| p - d)
        .collect();
    let opposite = Mlp::from_params(&opposite_params).unwrap();

    let a = wallet(81);
    let b = wallet(82);
    let c = wallet(83);
    let mut cfg = RoundConfig::new(1, 2);
    cfg.reward_pot_sat = 1_000;
    cfg.min_cosine = 0.0;
    cfg.max_update_norm = 20.0;
    let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
    for w in [&a, &b, &c] {
        round
            .register_worker(w.address().unwrap(), 10_000, 32)
            .unwrap();
    }
    round.submit(signed(1, &base, &a, &local_a, 32, 1)).unwrap();
    round.submit(signed(1, &base, &b, &local_b, 32, 1)).unwrap();
    round
        .submit(signed(1, &base, &c, &opposite, 32, 1))
        .unwrap();
    match round.finalize() {
        RoundOutcome::Finalized(done) => {
            assert_eq!(done.accepted.len(), 2, "the opposite update is excluded");
            assert!(done
                .rejected
                .iter()
                .any(|(worker, reason)| *worker == c.address().unwrap()
                    && matches!(reason, Rejection::LowQuality { .. })));
            assert_eq!(done.rewards.len(), 2);
            assert!(!done.rewards.contains_key(&c.address().unwrap()));
            assert!(done.rewards_are_exact());
        }
        other => panic!("expected a finalized round, got {other:?}"),
    }
}

#[test]
fn a_failed_round_leaves_the_optimizer_state_unchanged() {
    let base = Mlp::new(91);
    let mut velocity = Mlp::zeros();
    velocity.b2[0] = 0.25;
    let cfg = RoundConfig::new(1, 3);
    let mut round = RoundState::new(cfg, base, velocity.clone()).unwrap();
    match round.finalize() {
        RoundOutcome::Failed { reason, .. } => {
            assert!(matches!(reason, Rejection::NotEnoughUpdates { .. }));
        }
        other => panic!("expected failure, got {other:?}"),
    }
    assert_eq!(round.velocity(), &velocity);
}

#[test]
fn identical_inputs_produce_the_same_checkpoint_across_coordinators() {
    let base = Mlp::new(101);
    let data = two_moons(24, 101);
    let parts = shards(&data, 2);
    let wallets = [wallet(101), wallet(102)];
    let mut locals = Vec::new();
    for part in parts.iter().take(2) {
        locals.push(train_local(&base, part, 8, 0.2));
    }
    let mut hashes = Vec::new();
    let mut reward_maps = Vec::new();
    for _ in 0..2 {
        let mut cfg = RoundConfig::new(1, 2);
        cfg.reward_pot_sat = 9_999;
        cfg.max_update_norm = 20.0;
        cfg.momentum = 0.0;
        cfg.outer_lr = 1.0;
        let mut round = RoundState::new(cfg, base.clone(), Mlp::zeros()).unwrap();
        for (i, w) in wallets.iter().enumerate() {
            round
                .register_worker(w.address().unwrap(), 5_000 + i as u64, 24)
                .unwrap();
            round
                .submit(signed(1, &base, w, &locals[i], 24, 8))
                .unwrap();
        }
        match round.finalize() {
            RoundOutcome::Finalized(done) => {
                hashes.push(done.model_hash);
                reward_maps.push(done.rewards);
            }
            other => panic!("expected finalization, got {other:?}"),
        }
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(reward_maps[0], reward_maps[1]);
}

#[test]
fn wire_decoding_is_strict_about_truncation() {
    let base = Mlp::new(111);
    let worker = wallet(111);
    let mut local = base.clone();
    local.b2[0] += 0.1;
    let bytes = signed(1, &base, &worker, &local, 16, 4).encode();
    assert!(SignedUpdate::decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(SignedUpdate::decode(&bytes).is_ok());
}
