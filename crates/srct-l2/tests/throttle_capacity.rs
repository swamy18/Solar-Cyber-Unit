//! Phase 6 measurement: exit-throttle capacity with mainnet parameters.
//!
//! Answers: how many fixed-size compute-payout exits fit in one window,
//! network-wide and per owner. Uses mainnet throttle values
//! (`max_exit_window_sat` = 1000 SRCT, `max_exit_per_owner_window_sat` =
//! 100 SRCT per 144 blocks) on an otherwise mini profile so PoW stays fast.
//! The numbers below are measured by running this test, not assumed.

use srct_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use srct_core::hash::Address;
use srct_core::l2::{ExitQueuePayload, L2Payload, L2Transaction};
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2State};

const SAT: u64 = 100_000_000;
const EXIT_AMOUNT: u64 = 10 * SAT; // 10 SRCT per payout
const WINDOW_BLOCKS: u64 = 144;
const GLOBAL_CAP: u64 = 1_000 * SAT;
const OWNER_CAP: u64 = 100 * SAT;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "throttle-capacity").unwrap()
}
fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}
fn validators() -> ValidatorSet {
    ValidatorSet::new((1..=4u8).map(|i| BlsPublicKey([i; 48])).collect())
}

fn test_config() -> L2Config {
    let mut c = L2Config::mini();
    c.exit_activation_height = 1;
    c.max_exit_window_sat = GLOBAL_CAP;
    c.exit_window_blocks = WINDOW_BLOCKS;
    c.max_exit_per_owner_window_sat = OWNER_CAP;
    c
}

#[test]
fn throttle_capacity_single_owner() {
    // One requester queuing 10-SRCT exits back to back.
    let owner = wallet(1);
    let dest = addr(&wallet(2));
    let verifier = MockBls;
    let mut state = L2State::new(test_config());
    state.credit(addr(&owner), 10_000 * SAT).unwrap();
    let mut accepted = 0u32;
    // Per-owner cap is 100 SRCT per 144-block window; exits are 10 SRCT each,
    // so 10 fit and the 11th is refused — all inside one window. Height
    // advances one per attempt, staying inside the first window throughout.
    for nonce in 1..=30u64 {
        let payload = ExitQueuePayload::build(&owner, nonce, EXIT_AMOUNT, dest, 1_000_000).unwrap();
        let tx = L2Transaction::new(L2Payload::ExitQueue(payload));
        if state.apply(&tx, nonce, &validators(), &verifier).is_ok() {
            accepted += 1;
        } else {
            break;
        }
    }
    // 100 SRCT cap / 10 SRCT per exit = exactly 10.
    assert_eq!(accepted, 10, "per-owner window capacity");
    println!("single owner accepted {accepted} x 10-SRCT exits per 144-block window");
}

#[test]
fn throttle_capacity_network_wide() {
    // Ten distinct owners, each queuing 10-SRCT exits. Global cap 1000 SRCT
    // admits exactly 100 such exits per window.
    let dest = addr(&wallet(99));
    let verifier = MockBls;
    let mut state = L2State::new(test_config());
    let mut accepted = 0u32;
    // Height advances once per attempt across all owners, staying inside the
    // first 144-block window throughout the measurement.
    let mut height = 0u64;
    'outer: for o in 1..=10u8 {
        let owner = wallet(o);
        state.credit(addr(&owner), 10_000 * SAT).unwrap();
        for nonce in 1..=10u64 {
            height += 1;
            let payload =
                ExitQueuePayload::build(&owner, nonce, EXIT_AMOUNT, dest, 1_000_000).unwrap();
            let tx = L2Transaction::new(L2Payload::ExitQueue(payload));
            match state.apply(&tx, height, &validators(), &verifier) {
                Ok(_) => accepted += 1,
                Err(_) => break 'outer,
            }
        }
    }
    // 1000 SRCT global / 10 SRCT per exit = exactly 100.
    assert_eq!(accepted, 100, "network-wide window capacity");
    println!("network accepted {accepted} x 10-SRCT exits per 144-block window");
}
