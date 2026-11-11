//! Real DiLoCo training demo: three independent workers, twelve rounds,
//! signed updates, Byzantine filtering and exact reward settlement.
//!
//! Run with:
//! ```text
//! cargo run -p srct-diloco --example train_demo
//! ```

use srct_core::wallet::Wallet;
use srct_diloco::data::{accuracy, mean_loss, shards, two_moons};
use srct_diloco::model::Mlp;
use srct_diloco::round::{RoundConfig, RoundOutcome, RoundState};
use srct_diloco::update::{SignedUpdate, UpdateClaim};

fn train_local(base: &Mlp, shard: &[srct_diloco::Sample], steps: u32, lr: f32) -> Mlp {
    let mut local = base.clone();
    for _ in 0..steps {
        let (_, grad) = local.loss_and_grad(shard);
        local.sgd_step(&grad, lr);
    }
    local
}

fn main() {
    let data = two_moons(96, 21);
    let parts = shards(&data, 3);
    let wallets: Vec<Wallet> = [31u8, 32, 33]
        .iter()
        .map(|seed| Wallet::from_private_key_bytes(&[*seed; 32], "diloco-demo").unwrap())
        .collect();
    let mut global = Mlp::new(21);
    let mut velocity = Mlp::zeros();
    let initial_loss = mean_loss(&global, &data);
    let initial_accuracy = accuracy(&global, &data);
    let started = std::time::Instant::now();

    for round_id in 1..=24u64 {
        let mut cfg = RoundConfig::new(round_id, 2);
        cfg.reward_pot_sat = 1_000_000;
        cfg.max_update_norm = 20.0;
        cfg.momentum = 0.0;
        cfg.outer_lr = 1.0;
        let mut round = RoundState::new(cfg, global.clone(), velocity.clone()).unwrap();
        for (i, worker) in wallets.iter().enumerate() {
            round
                .register_worker(worker.address().unwrap(), 10_000, parts[i].len() as u64)
                .unwrap();
            let local = train_local(&global, &parts[i], 20, 0.05);
            let claim = UpdateClaim::new(
                round_id,
                &global,
                worker.address().unwrap(),
                &local,
                parts[i].len() as u64,
                20,
                mean_loss(&local, &parts[i]),
            );
            round
                .submit(SignedUpdate::sign(worker, claim).unwrap())
                .unwrap();
        }
        match round.finalize() {
            RoundOutcome::Finalized(done) => {
                global = done.model.clone();
                velocity = round.velocity().clone();
                let paid: u64 = done.rewards.values().sum();
                println!(
                    "round {:>2}  loss {:.4}  accuracy {:.3}  accepted {}  rejected {}  rewards {}/{} sat",
                    round_id,
                    mean_loss(&global, &data),
                    accuracy(&global, &data),
                    done.accepted.len(),
                    done.rejected.len(),
                    paid,
                    done.reward_pot_sat
                );
            }
            other => {
                eprintln!("round {round_id} failed: {other:?}");
                std::process::exit(1);
            }
        }
    }

    let elapsed = started.elapsed();
    println!(
        "final: loss {:.4} -> {:.4}, accuracy {:.3} -> {:.3}, {:.1} ms/round",
        initial_loss,
        mean_loss(&global, &data),
        initial_accuracy,
        accuracy(&global, &data),
        elapsed.as_secs_f64() * 1000.0 / 24.0
    );
    let checkpoint: String = global
        .hash()
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("checkpoint {checkpoint}");
}
