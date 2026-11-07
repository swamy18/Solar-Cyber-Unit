//! N3 confirmation: L2 transactions other than settlement carry no network
//! binding, so a signature made for one network verifies for any other.
//!
//! Only `SettlePayload` embeds `network_id` in its signed body (`l2.rs`).
//! `ExitQueue`, `Policy`, `PolicyRevoke`, `AgentSpend`, `CreditOpen`,
//! `CreditCollateral`, `CreditRepay` and `CreditDefault` sign domain-separated
//! type tags over owner/counterparty/amount/nonce fields with no network
//! anywhere in the envelope. `verify_auth` takes no network parameter, and the
//! serialized bytes contain neither network string. A testnet signature
//! therefore verifies unchanged on mainnet: if the owner reuses the key and
//! the nonces line up, the same signed bytes apply on both chains.
//!
//! Each test below builds a real signed payload and asserts the two halves of
//! that claim: (a) the wire bytes name no network, (b) authentication succeeds
//! with no network context at all.
//!
//! DO NOT "fix" these tests by deleting them. The correct fix adds the
//! network identifier to every L2 signing hash and envelope (a wire-format and
//! consensus change) with per-payload replay tests; when that lands, these
//! assertions must be rewritten to assert refusal across networks.
//!
//! Run with `cargo test -p srct-core --test l2_cross_network`.

use srct_core::hash::Address;
use srct_core::l2::{
    AgentSpendPayload, CreditOpenPayload, ExitQueuePayload, L2Payload, L2Transaction,
    PolicyPayload,
};
use srct_core::wallet::Wallet;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-cross-network").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn wire_has_no_network(bytes: &[u8]) {
    for net in [b"srct/mini".as_slice(), b"srct/testnet".as_slice(), b"srct/mainnet".as_slice()] {
        assert!(
            bytes.windows(net.len()).all(|w| w != net),
            "N3: signed L2 bytes must not name a network, yet contain {:?}",
            String::from_utf8_lossy(net)
        );
    }
}

#[test]
fn exit_queue_signature_carries_no_network() {
    let owner = wallet(1);
    let dest = addr(&wallet(2));
    let p = ExitQueuePayload::build(&owner, 1, 50_000, dest, 1_000).unwrap();
    // Verifies with no network context — the same bytes verify anywhere.
    p.verify_auth().expect("exit queue must verify");
    wire_has_no_network(&p.serialize());
    // And inside a full transaction envelope: still no network.
    let tx = L2Transaction::new(L2Payload::ExitQueue(p));
    wire_has_no_network(&tx.serialize());
    let back = L2Transaction::deserialize(&tx.serialize()).unwrap();
    match back.payload {
        L2Payload::ExitQueue(q) => q.verify_auth().expect("replayed bytes verify"),
        _ => panic!("wrong payload"),
    }
}

#[test]
fn policy_grant_envelope_carries_no_network() {
    // The envelope (owner/spender/agent/signature) names no network: binding
    // comes only from the grant *content* (`SpendPolicy.network_id`) plus the
    // apply-time checks (`state.rs`: policy publish and agent spend both
    // refuse grants for another network). An opaque grant without a network_id
    // rides the envelope with no binding at all.
    let owner = wallet(3);
    let spender = addr(&wallet(4));
    let agent_id = [9u8; 20];
    let policy_bytes = vec![0x01, 0x02, 0x03];
    let p = PolicyPayload::build(&owner, policy_bytes, spender, agent_id).unwrap();
    p.verify_auth().expect("policy grant must verify");
    wire_has_no_network(&p.serialize());
}

#[test]
fn agent_spend_signature_carries_no_network() {
    let agent = wallet(5);
    let recipient = addr(&wallet(6));
    let p = AgentSpendPayload::build(&agent, [0x11u8; 32], 1, recipient, 10_000, None).unwrap();
    p.verify_auth().expect("agent spend must verify");
    wire_has_no_network(&p.serialize());
}

#[test]
fn credit_open_signature_carries_no_network() {
    let lender = wallet(7);
    let borrower = addr(&wallet(8));
    let p = CreditOpenPayload::build(&lender, borrower, 200_000, 100_000, 50, 100, 500, 1)
        .unwrap();
    p.verify_auth().expect("credit open must verify");
    wire_has_no_network(&p.serialize());
}

#[test]
fn l1_sighash_takes_no_network_parameter() {
    // N7 companion: the L1 signature hash is a pure function of the
    // transaction bytes (`sighash(&self)`), with no network argument in its
    // signature. Identical spendable outputs on two networks share a sighash;
    // only divergent genesis/history blocks practical replay today.
    let tx = srct_core::tx::Transaction::standard(vec![], vec![]);
    assert_eq!(
        tx.sighash(),
        tx.sighash(),
        "sighash is deterministic over the bytes alone"
    );
}
