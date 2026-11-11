//! End-to-end agent messaging demo:
//! two wallet-owned agents -> derived identities -> sealed envelope ->
//! relay-side mailbox -> owner decryption -> replay refused.
//!
//! Run with:
//! ```text
//! cargo run --release -p srct-agentnet --example agentnet_demo
//! ```

use srct_agentnet::mailbox::Mailbox;
use srct_agentnet::message::{thread_id, MessageEnvelope, Recipient};
use srct_core::agent::{derive_agent_id, AgentRole};
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "agentnet-demo").unwrap()
}

fn main() {
    let alice = wallet(1);
    let bob = wallet(2);
    let alice_address = alice.address().unwrap();
    let bob_address = bob.address().unwrap();
    let alice_agent = derive_agent_id(NET, AgentRole::Machine, &alice_address);
    let bob_agent = derive_agent_id(NET, AgentRole::Machine, &bob_address);
    let thread = thread_id(&alice_agent, &bob_agent, 1);
    println!("thread: {}", hex::encode(thread));

    let recipient = Recipient::from_wallet(&bob, AgentRole::Machine).unwrap();
    let mut relay = Mailbox::new(NET, bob_agent);

    for seq in 1..=4u64 {
        let text = format!("agent message {seq}");
        let envelope = MessageEnvelope::seal(
            &alice,
            AgentRole::Machine,
            NET,
            thread,
            seq,
            &recipient,
            text.as_bytes(),
            1_000,
        )
        .unwrap();
        let wire = envelope.encode();
        relay.accept_wire(&wire, 100).unwrap();
        println!(
            "seq {seq}: plaintext {} B -> envelope {} B; relay stores {} messages",
            text.len(),
            wire.len(),
            relay.len()
        );

        let replay = relay.accept_wire(&wire, 100);
        println!("  replay refused: {replay:?}");
    }

    for entry in relay.drain_thread(&thread, 10) {
        let text = entry.envelope.open(&bob).unwrap();
        println!(
            "  bob opened seq {}: {}",
            entry.envelope.seq,
            String::from_utf8(text).unwrap()
        );
    }

    let last = MessageEnvelope::seal(
        &alice,
        AgentRole::Machine,
        NET,
        thread,
        5,
        &recipient,
        b"tampered",
        1_000,
    )
    .unwrap();
    let mut tampered = last;
    tampered.ciphertext[0] ^= 0x01;
    println!(
        "tampered wire refused: {:?}",
        MessageEnvelope::decode(&tampered.encode())
    );
}
