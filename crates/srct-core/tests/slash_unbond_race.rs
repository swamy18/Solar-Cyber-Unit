//! N2 confirmation: a validator escapes slashing by unbonding first.
//!
//! `check_unbond_tx` (`bond.rs`) demands only a minimum bond *age*
//! (`bond_height + UNBONDING_PERIOD_BLOCKS`); once past it, the caller deletes
//! the record and releases the value in the same step. `check_slash_tx`
//! demands an *active* bond (`find_by_key`), so slash evidence arriving after
//! the unbond is refused with "slash offender has no active bond". There is no
//! post-request unbonding state in which the stake stays slashable — the only
//! protection is winning the race against the equivocator.
//!
//! This test proves the race on a live chain: valid equivocation evidence is
//! accepted by the slash rule before the unbond (positive control) and refused
//! after it, and a block carrying the slash is rejected end to end.
//!
//! DO NOT "fix" this test by deleting it. The correct fix keeps the stake in
//! an "unbonding" state for the full delay after the unbond request and keeps
//! it slashable there; when that lands, the post-unbond assertions below must
//! be rewritten into acceptance assertions.
//!
//! Run with `cargo test -p srct-core --test slash_unbond_race`.

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::bls::{RealBls, SecretKey};
use srct_core::bls_checkpoint::{BlsPublicKey, Checkpoint, CheckpointPayload};
use srct_core::bond::{bond_identity, bond_pop, UNBONDING_PERIOD_BLOCKS};
use srct_core::chain::Chain;
use srct_core::error::Error;
use srct_core::hash::Address;
use srct_core::params::NetworkParams;
use srct_core::tx::{
    OutPoint, Output, StakePayload, Transaction, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE,
    TX_BOND, TX_SLASH, TX_UNBOND,
};
use srct_core::wallet::Wallet;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "slash-unbond-race").unwrap()
}

fn bls_pair(seed: u8) -> (SecretKey, BlsPublicKey) {
    let sk = SecretKey::derive(&[seed; 32]).unwrap();
    let pk = sk.public_key();
    (sk, pk)
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

fn gas(n_in: usize, n_out: usize) -> u64 {
    GAS_TX_BASE + GAS_PER_INPUT * n_in as u64 + GAS_PER_OUTPUT * n_out as u64
}

fn mine(chain: &mut Chain, to: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(to, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn mine_to(chain: &mut Chain, to: Address, target: u64) {
    while chain.height() < target {
        mine(chain, to, 1);
    }
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas(n_in, n_out))
        .saturating_add(1_000_000)
}

fn utxo_total(chain: &Chain, ops: &[OutPoint]) -> u64 {
    ops.iter()
        .map(|op| chain.utxo().get(op).unwrap().out.value)
        .fold(0u64, |a, v| a.saturating_add(v))
}

fn bond_tx(chain: &Chain, w: &Wallet, ops: &[OutPoint], sk: &SecretKey, value: u64) -> Transaction {
    let pk = sk.public_key();
    let net = chain.params().clone();
    let total = utxo_total(chain, ops);
    let fee = fee_for(chain, ops.len(), 2);
    let bonder = w.address().unwrap();
    let mut tx = w
        .build_tx(
            ops,
            vec![
                Output {
                    value,
                    address: bond_identity(&net.network_id, &bonder, &pk),
                },
                Output {
                    value: total - value - fee,
                    address: bonder,
                },
            ],
            fee,
        )
        .unwrap();
    tx.tx_type = TX_BOND;
    tx.stake = Some(StakePayload::Bond {
        bls_pk: pk,
        pop: bond_pop(sk, &net.network_id, &bonder),
        mldsa_pk: None,
    });
    w.sign(&mut tx).unwrap();
    tx
}

fn unbond_tx(
    chain: &Chain,
    w: &Wallet,
    ops: &[OutPoint],
    bond_id: srct_core::hash::Hash512,
) -> Transaction {
    let total = utxo_total(chain, ops);
    let fee = fee_for(chain, ops.len(), 1);
    let to = w.address().unwrap();
    let mut tx = w
        .build_tx(
            ops,
            vec![Output {
                value: total - fee,
                address: to,
            }],
            fee,
        )
        .unwrap();
    tx.tx_type = TX_UNBOND;
    tx.stake = Some(StakePayload::Unbond { bond_id });
    w.sign(&mut tx).unwrap();
    tx
}

fn lone_checkpoint(sk: &SecretKey, payload: CheckpointPayload) -> Checkpoint {
    let msg = payload.signing_hash();
    let agg = RealBls::aggregate(&[sk.sign(&msg)]).unwrap();
    Checkpoint {
        payload,
        aggregate_sig: agg,
        signer_bitmap: vec![1u8],
        signer_count: 1,
        pq_sidecar: Vec::new(),
    }
}

fn conflicting_pair(
    sk: &SecretKey,
    height: u64,
    epoch: u64,
    network_id: &str,
) -> (Checkpoint, Checkpoint) {
    let a = CheckpointPayload {
        height,
        block_hash: [0xAAu8; 64],
        network_id: network_id.to_string(),
        epoch,
    };
    let b = CheckpointPayload {
        height,
        block_hash: [0xBBu8; 64],
        network_id: network_id.to_string(),
        epoch,
    };
    (lone_checkpoint(sk, a), lone_checkpoint(sk, b))
}

fn slash_tx(
    chain: &Chain,
    w: &Wallet,
    ops: &[OutPoint],
    first: Checkpoint,
    second: Checkpoint,
) -> Transaction {
    let total = utxo_total(chain, ops);
    let fee = fee_for(chain, ops.len(), 1);
    let to = w.address().unwrap();
    let mut tx = w
        .build_tx(
            ops,
            vec![Output {
                value: total - fee,
                address: to,
            }],
            fee,
        )
        .unwrap();
    tx.tx_type = TX_SLASH;
    tx.stake = Some(StakePayload::Slash {
        first: Box::new(first),
        second: Box::new(second),
    });
    w.sign(&mut tx).unwrap();
    tx
}

fn epoch_at(chain: &Chain, height: u64) -> u64 {
    CheckpointPayload::epoch_for(height, chain.params().checkpoint_interval_blocks)
}

#[test]
fn equivocator_unbonds_then_slash_evidence_is_refused() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let w = wallet(1);
    let bonder = w.address().unwrap();
    mine(&mut chain, bonder, 80);
    let mut ops = Vec::new();
    for h in 1..=70u64 {
        ops.push(OutPoint {
            txid: chain.block_at(h).unwrap().txs[0].txid(),
            index: 0,
        });
    }

    let (sk, pk) = bls_pair(7);
    let bond = bond_tx(&chain, &w, &ops[..66], &sk, 5_000_000);
    let bond_id = bond.txid();
    let bond_height = chain.height() + 1;
    let bb = chain
        .mine_block(bonder, vec![bond], ts(bond_height))
        .unwrap();
    chain.submit(bb).unwrap();
    assert!(
        chain.bonds().get(&bond_id).is_some(),
        "bond must be recorded"
    );

    // Rotation puts the bonded key in sole charge (same rule the committee
    // suite pins).
    mine_to(&mut chain, bonder, 110);
    assert_eq!(chain.committee_keys(), vec![pk]);

    // The equivocation: two conflicting checkpoints at the tip, both signed
    // by the bonded key alone.
    let ev_h = chain.height();
    let (first, second) = conflicting_pair(&sk, ev_h, epoch_at(&chain, ev_h), "srct/mini");
    let slash = slash_tx(&chain, &w, &ops[67..68], first.clone(), second.clone());
    let net_id = chain.params().network_id.clone();
    let epoch_blocks = chain.params().checkpoint_interval_blocks;

    // Positive control: while the bond is active the same evidence verifies.
    srct_core::bond::check_slash_tx(
        &slash,
        chain.bonds(),
        |e| chain.historical_epoch_set(e),
        &net_id,
        chain.height(),
        epoch_blocks,
        &RealBls,
    )
    .expect("valid equivocation evidence against an active bond must verify");

    // Past the minimum bond age the validator unbonds; the record is deleted
    // and the value released in the same step.
    mine_to(&mut chain, bonder, bond_height + UNBONDING_PERIOD_BLOCKS);
    let unbond = unbond_tx(&chain, &w, &ops[68..69], bond_id);
    let uh = chain.height() + 1;
    let ub = chain.mine_block(bonder, vec![unbond], ts(uh)).unwrap();
    chain.submit(ub).unwrap();
    assert!(
        chain.bonds().get(&bond_id).is_none(),
        "unbond deletes the record"
    );

    // N2: the identical evidence is now refused — the offender has no active
    // bond — and a block carrying the slash is rejected end to end. Winning
    // this race is the only thing protecting an equivocator's stake.
    let err = srct_core::bond::check_slash_tx(
        &slash,
        chain.bonds(),
        |e| chain.historical_epoch_set(e),
        &net_id,
        chain.height(),
        epoch_blocks,
        &RealBls,
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::StakeInvalid("slash offender has no active bond"),
        "N2: post-unbond slash evidence must be refused for the missing bond"
    );
    let sh = chain.height() + 1;
    // Rebuild the slash with a fresh fee input (fees may have moved on); the
    // refusal must still be the missing bond, not funding.
    let slash2 = slash_tx(&chain, &w, &ops[67..68], first.clone(), second.clone());
    let sb = chain.mine_block(bonder, vec![slash2], ts(sh)).unwrap();
    let submit_err = chain.submit(sb).unwrap_err();
    assert!(
        format!("{submit_err}").contains("no active bond"),
        "N2: chain must refuse the slash once the bond is gone, got: {submit_err}"
    );
}
