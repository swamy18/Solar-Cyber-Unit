//! Deposit detection and application tests — Decision 10, SPEC.md §19.5.
//!
//! State- and block-level coverage (the full node flow, reorgs and restarts
//! live in `srct-node/tests/l2_deposits.rs`):
//!
//! - the scan finds single-owner sink outputs with exact recipient and amount;
//! - mixed owners, coinbase, dust, wrong sink and non-sink outputs credit
//!   nothing, each with its named reason (or silence, for non-sink);
//! - `apply_deposit` is exactly-once and conservation-closed;
//! - `ChainL2` holds deposits pending until final depth, then credits them,
//!   identically by replay and incrementally.

use srct_core::block::{Block, Header};
use srct_core::chain::Chain;
use srct_core::hash::Address;
use srct_core::l2::Auth;
use srct_core::params::{NetworkParams, SAT_PER_SRCT};
use srct_core::sig::Bundle;
use srct_core::tx::{Input, OutPoint, Output, Transaction};
use srct_core::wallet::Wallet;
use srct_l2::{ChainL2, DepositIgnoreReason, DepositParams, L2Config, L2Error, L2Genesis, L2State};

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "deposit-flow-test").unwrap()
}

fn addr_of(seed: u8) -> Address {
    wallet(seed).address().unwrap()
}

fn params() -> DepositParams {
    DepositParams::for_params(&NetworkParams::mini())
}

fn sink() -> Address {
    NetworkParams::mini().l2_deposit_sink()
}

/// An input whose key bundle names `seed`'s wallet. Signatures are irrelevant
/// to the scan (L1 consensus verified them at acceptance); only the owner
/// derivation matters here.
fn input_owned_by(seed: u8) -> Input {
    Input {
        prev_hash: [seed; 64],
        prev_index: 0,
        sigs: Bundle::default(),
        keys: Auth::keys_for(&wallet(seed)).unwrap(),
    }
}

fn sink_output(value: u64) -> Output {
    Output {
        value,
        address: sink(),
    }
}

fn block_with(tx: Transaction, height: u64) -> Block {
    // Hand-built: the scan reads only `txs`, so the header is a placeholder
    // carrying the height under test. Chain-level tests use mined blocks.
    let coinbase = Transaction::coinbase(
        [0u8; 64],
        height,
        Output {
            value: 1,
            address: [7u8; 20],
        },
    );
    let mut header = Header::genesis([0u8; 32], 1);
    header.height = height;
    Block {
        header,
        signature: [0u8; 64],
        signer_pubkey: [0u8; 33],
        txs: vec![coinbase, tx],
        l2_txs: Vec::new(),
        l2_state_root: None,
        exit_claims: Vec::new(),
        checkpoint: None,
    }
}

fn standard_tx(inputs: Vec<Input>, outputs: Vec<Output>) -> Transaction {
    Transaction::standard(inputs, outputs)
}

// --- scan -------------------------------------------------------------------

#[test]
fn scan_finds_a_single_owner_sink_output_exactly() {
    let p = params();
    let tx = standard_tx(
        vec![input_owned_by(30)],
        vec![
            sink_output(2_000_000),
            Output {
                value: 500,
                address: addr_of(30),
            },
        ],
    );
    let (found, ignored) = srct_l2::deposits::scan_block(&block_with(tx.clone(), 5), 5, &p);
    assert!(ignored.is_empty());
    assert_eq!(found.len(), 1);
    let d = found[0];
    assert_eq!(d.height, 5);
    assert_eq!(d.txid, tx.txid());
    assert_eq!(d.index, 0);
    assert_eq!(d.recipient, addr_of(30));
    assert_eq!(d.amount_sat, 2_000_000);
    assert_eq!(d.matures_at(p.maturity_depth), 5 + p.maturity_depth);
    assert_eq!(d.id(), (tx.txid(), 0));
}

#[test]
fn scan_credits_each_sink_output_independently() {
    let p = params();
    let tx = standard_tx(
        vec![input_owned_by(31)],
        vec![sink_output(1_500_000), sink_output(3_000_000)],
    );
    let (found, ignored) = srct_l2::deposits::scan_block(&block_with(tx.clone(), 5), 5, &p);
    assert!(ignored.is_empty());
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].id(), (tx.txid(), 0));
    assert_eq!(found[1].id(), (tx.txid(), 1));
    assert_eq!(found[0].amount_sat, 1_500_000);
    assert_eq!(found[1].amount_sat, 3_000_000);
    assert_eq!(found[0].recipient, found[1].recipient);
}

#[test]
fn mixed_owner_inputs_are_burns_not_deposits() {
    let p = params();
    // Two inputs owned by different wallets: no unique owner, so the sink
    // output stays burned and the refusal is named.
    let tx = standard_tx(
        vec![input_owned_by(32), input_owned_by(33)],
        vec![sink_output(2_000_000)],
    );
    let (found, ignored) = srct_l2::deposits::scan_block(&block_with(tx.clone(), 5), 5, &p);
    assert!(found.is_empty());
    assert_eq!(ignored.len(), 1);
    assert_eq!(ignored[0].reason, DepositIgnoreReason::MixedOwners);
    assert_eq!(ignored[0].txid, tx.txid());
    assert_eq!(ignored[0].amount_sat, 2_000_000);
}

#[test]
fn coinbase_to_sink_is_never_a_deposit() {
    // A miner paying the sink from a coinbase has no signed inputs and hence
    // no proven owner: burn, not deposit. (The scan skips tx 0 regardless.)
    let p = params();
    let coinbase_to_sink = Transaction::coinbase([0u8; 64], 9, sink_output(50_000_000));
    let mut header = Header::genesis([0u8; 32], 1);
    header.height = 9;
    let block = Block {
        header,
        signature: [0u8; 64],
        signer_pubkey: [0u8; 33],
        txs: vec![coinbase_to_sink],
        l2_txs: Vec::new(),
        l2_state_root: None,
        exit_claims: Vec::new(),
        checkpoint: None,
    };
    let (found, ignored) = srct_l2::deposits::scan_block(&block, 9, &p);
    assert!(found.is_empty());
    assert!(ignored.is_empty());
}

#[test]
fn dust_to_sink_stays_burned() {
    let p = params();
    assert_eq!(p.minimum_sat, 1_000_000);
    let tx = standard_tx(vec![input_owned_by(34)], vec![sink_output(999_999)]);
    let (found, ignored) = srct_l2::deposits::scan_block(&block_with(tx, 5), 5, &p);
    assert!(found.is_empty());
    assert_eq!(ignored.len(), 1);
    assert_eq!(ignored[0].reason, DepositIgnoreReason::BelowMinimum);
    // Exactly at the floor: a deposit.
    let tx = standard_tx(vec![input_owned_by(34)], vec![sink_output(1_000_000)]);
    let (found, ignored) = srct_l2::deposits::scan_block(&block_with(tx, 5), 5, &p);
    assert_eq!(found.len(), 1);
    assert!(ignored.is_empty());
}

#[test]
fn wrong_sink_and_non_sink_outputs_are_silent() {
    let p = params();
    // Mainnet sink on mini: an ordinary burn. Escrow address: a payment.
    // Neither is detected, and neither is "ignored" either — they are not
    // deposits at all, so there is nothing to name.
    let tx = standard_tx(
        vec![input_owned_by(35)],
        vec![
            Output {
                value: 5_000_000,
                address: NetworkParams::mainnet().l2_deposit_sink(),
            },
            Output {
                value: 5_000_000,
                address: NetworkParams::mini().l2_escrow_address(),
            },
            Output {
                value: 5_000_000,
                address: addr_of(35),
            },
        ],
    );
    let (found, ignored) = srct_l2::deposits::scan_block(&block_with(tx, 5), 5, &p);
    assert!(found.is_empty());
    assert!(ignored.is_empty());
}

// --- apply ------------------------------------------------------------------

#[test]
fn apply_deposit_credits_once_and_conserves() {
    let mut s = L2State::new(L2Config::mini());
    let id = ([0xDBu8; 64], 0u32);
    s.apply_deposit(addr_of(40), 2_000_000, id).unwrap();
    assert_eq!(s.balance(&addr_of(40)), 2_000_000);
    assert_eq!(s.deposited_total(), 2_000_000);
    assert_eq!(s.funded_total(), 2_000_000);
    assert!(s.check_conservation());
    assert!(s.deposit_credited(&id));

    // Same identity again: refused by name, nothing moves.
    let err = s.apply_deposit(addr_of(40), 2_000_000, id).unwrap_err();
    assert_eq!(err, L2Error::DuplicateDeposit);
    assert_eq!(s.balance(&addr_of(40)), 2_000_000);
    assert!(s.check_conservation());

    // Zero is not a deposit even if it reaches here.
    assert_eq!(
        s.apply_deposit(addr_of(40), 0, ([0xDBu8; 64], 1u32))
            .unwrap_err(),
        L2Error::ZeroAmount("deposit")
    );
}

// --- ChainL2 maturity (mined chain) ------------------------------------------

fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

/// Mine `n` blocks to `miner`, returning the chain. All coinbases pay the
/// miner wallet so later tests can spend them.
fn mine_to(chain: &mut Chain, miner: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    let gas = 16_000 + 1_000 * n_in as u64 + 250 * n_out as u64;
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000)
}

#[test]
fn deposits_mature_at_final_depth_and_replay_agrees_incrementally() {
    let net = NetworkParams::mini();
    let depth = net.finality_depth;
    assert_eq!(depth, 20);
    let mut chain = Chain::new(net.clone()).unwrap();
    let miner = wallet(50);
    let miner_addr = miner.address().unwrap();
    // Fund the miner and mature the first coinbase (maturity 10).
    mine_to(&mut chain, miner_addr, 11);

    // Spend coinbase h1 into the sink (2 SRCT) plus change.
    let op = OutPoint {
        txid: chain.block_at(1).unwrap().txs[0].txid(),
        index: 0,
    };
    let reward = srct_core::supply::block_reward_sat(chain.params(), 1);
    let fee = fee_for(&chain, 1, 2);
    let to_sink = 2 * SAT_PER_SRCT;
    let deposit_tx = miner
        .build_tx(
            &[op],
            vec![
                Output {
                    value: to_sink,
                    address: net.l2_deposit_sink(),
                },
                Output {
                    value: reward - to_sink - fee,
                    address: miner_addr,
                },
            ],
            fee,
        )
        .unwrap();
    let deposit_height = chain.height() + 1;
    let b = chain
        .mine_block(miner_addr, vec![deposit_tx.clone()], ts(deposit_height))
        .unwrap();
    chain.submit(b).unwrap();

    let g = L2Genesis::empty();
    let d = DepositParams::for_params(&net);
    let replay_at = |c: &Chain| {
        // Authority resolves per height inside replay; no settlements here,
        // so any committee verifies identically.
        let v = srct_core::bls_checkpoint::MockBls;
        ChainL2::replay(c, L2Config::mini(), &g, d, &v).unwrap()
    };

    // Just before maturity: detected, pending, uncredited.
    while chain.height() < deposit_height + depth - 1 {
        mine_to(&mut chain, miner_addr, 1);
    }
    let before = replay_at(&chain);
    assert_eq!(before.pending_deposits().len(), 1);
    assert_eq!(before.deposits_applied_count(), 0);
    assert_eq!(before.state().balance(&miner_addr), 0);
    let p = before.pending_deposits()[0];
    assert_eq!(p.deposit.amount_sat, to_sink);
    assert_eq!(p.deposit.recipient, miner_addr);
    assert_eq!(p.matures_at, deposit_height + depth);

    // At maturity: credited exactly, pending empty, conservation closed.
    mine_to(&mut chain, miner_addr, 1);
    assert_eq!(chain.height(), deposit_height + depth);
    let after = replay_at(&chain);
    assert!(after.pending_deposits().is_empty());
    assert_eq!(after.deposits_applied_count(), 1);
    assert_eq!(after.state().balance(&miner_addr), to_sink);
    assert_eq!(after.state().deposited_total(), to_sink);
    assert!(after.state().check_conservation());

    // Incremental from empty converges to the same state.
    let (set, v) = (
        srct_core::bls_checkpoint::ValidatorSet::new(vec![]),
        srct_core::bls_checkpoint::MockBls,
    );
    let mut inc = ChainL2::empty(L2Config::mini(), &g, d).unwrap();
    let tip = chain.height();
    let binding = chain.finality().binding_finalized_height();
    for h in 1..=tip {
        inc.apply_block(chain.block_at(h).unwrap(), tip, binding, &set, &v);
    }
    assert_eq!(inc.state(), after.state());
    assert_eq!(inc.pending_deposits(), after.pending_deposits());
}

#[test]
fn absorbing_the_same_block_twice_credits_once() {
    // The Duplicate path, reached without breaking L1 rules: no canonical
    // chain can hold the same bytes twice (the second block would double-spend
    // and be rejected), so this drives `apply_block` directly. A wrapper that
    // re-syncs an already-seen block must still never double-credit.
    use srct_l2::DepositIgnoreReason;

    let net = NetworkParams::mini();
    let depth = net.finality_depth;
    let mut chain = Chain::new(net.clone()).unwrap();
    let miner = wallet(51);
    let miner_addr = miner.address().unwrap();
    mine_to(&mut chain, miner_addr, 11);
    let op = OutPoint {
        txid: chain.block_at(1).unwrap().txs[0].txid(),
        index: 0,
    };
    let reward = srct_core::supply::block_reward_sat(chain.params(), 1);
    let fee = fee_for(&chain, 1, 2);
    let to_sink = 2 * SAT_PER_SRCT;
    let deposit_tx = miner
        .build_tx(
            &[op],
            vec![
                Output {
                    value: to_sink,
                    address: net.l2_deposit_sink(),
                },
                Output {
                    value: reward - to_sink - fee,
                    address: miner_addr,
                },
            ],
            fee,
        )
        .unwrap();
    let h = chain.height() + 1;
    let b = chain
        .mine_block(miner_addr, vec![deposit_tx], ts(h))
        .unwrap();
    chain.submit(b.clone()).unwrap();
    mine_to(&mut chain, miner_addr, depth);

    let g = L2Genesis::empty();
    let d = DepositParams::for_params(&net);
    let (set, v) = (
        srct_core::bls_checkpoint::ValidatorSet::new(vec![]),
        srct_core::bls_checkpoint::MockBls,
    );
    let tip = chain.height();
    let binding = chain.finality().binding_finalized_height();
    let mut view = ChainL2::empty(L2Config::mini(), &g, d).unwrap();
    view.apply_block(&b, tip, binding, &set, &v);
    assert_eq!(view.deposits_applied_count(), 1);
    assert_eq!(view.state().balance(&miner_addr), to_sink);
    // Second absorption of the same block: duplicate by name, balance and
    // totals untouched.
    view.apply_block(&b, tip, binding, &set, &v);
    assert_eq!(view.deposits_applied_count(), 1);
    assert_eq!(view.state().balance(&miner_addr), to_sink);
    assert_eq!(view.state().deposited_total(), to_sink);
    let dups: Vec<_> = view
        .ignored_deposits()
        .iter()
        .filter(|i| i.reason == DepositIgnoreReason::Duplicate)
        .collect();
    assert_eq!(dups.len(), 1);
    assert!(view.state().check_conservation());
}
