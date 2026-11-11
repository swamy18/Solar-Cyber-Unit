# Agent messaging

Status: **working non-consensus prototype** in `crates/srct-agentnet`. It
implements pairwise, end-to-end encrypted, signed agent messages and a bounded
replay-safe mailbox. It changes no consensus rule and moves no coin.

```bash
cargo test -p srct-agentnet
cargo run --release -p srct-agentnet --example agentnet_demo
```

## 1. What problem it solves

Agents need a private conversation channel that survives untrusted relays:

- only the recipient's wallet should be able to read a message;
- a relay must be able to store and forward without holding any key;
- the recipient must know which agent sent a message;
- a relay must not be able to re-home a message to another thread, recipient or
  network, or replay one that was already delivered;
- a 2 GB device and a server must use the same protocol.

`srct-agentnet` answers those with data formats, signatures and a mailbox state
machine. Transport, discovery and presence are deliberately out of scope.

## 2. Identity

An agent is an ordinary SRCT address plus a role, bound to a network:

```
agent_id = SHA256("srct/agent-id/v1" || network || role || address)[0..20]
```

The address is the wallet's **hybrid** address, the same one that owns funds.
The recipient's ECDH key is the ECDSA component of that same key bundle, so the
encryption key and the named recipient are structurally the same key set.
`Recipient::from_wallet` / `Recipient::new` verify that binding; `seal` re-checks
it, so a caller cannot pair an address with a key bundle that does not control
it.

`thread_id(a, b, nonce)` sorts the two agent ids and hashes them with a nonce, so
both sides derive the same conversation id and one pair can run several
independent threads.

## 3. Envelope

```
version(1) || network || thread(32) || seq(8) ||
sender_agent(20) || sender_address(20) || sender_role(1) ||
recipient_agent(20) || recipient_address(20) || recipient_role(1) ||
ephemeral_pubkey(33) || nonce(24) || expires_height(8) ||
ciphertext_len(4) || ciphertext ||
sigs_len(4) || sigs || keys_len(4) || keys
```

Key schedule:

```
shared = ECDH(ephemeral_secret, recipient_ecdsa_pubkey)
key    = HKDF-SHA256(salt = thread, ikm = shared,
                     info = "srct/agentnet/kdf/v1" || network || sender_agent || recipient_agent)
AEAD   = XChaCha20-Poly1305(key, nonce, aad)
```

The AAD is the version, network, thread, sequence, both identities, both
addresses, both roles and the ephemeral key. The sender's hybrid signature
covers the AAD **plus** the nonce, expiry and ciphertext, through:

```
signing_hash = SHA256("srct/agentnet/message/v1" || aad || nonce || expires || ciphertext)
```

Consequences:

- changing the thread, sequence, recipient, network or ephemeral key breaks the
  signature and the AEAD;
- a fresh ephemeral key and nonce per message mean one message's key cannot open
  another;
- `seq == 0` is invalid, and plaintext is capped at 64 KiB;
- the wire decoder refuses unknown versions, oversized ciphertext, malformed
  bundles, trailing bytes and anything that fails `verify()`.

## 4. Mailbox

A mailbox is bound to one `(network, recipient agent)`. `accept` first verifies
the envelope, so a mailbox never stores unauthenticated data and never needs a
private key.

Rules:

| Rule | Refusal |
|---|---|
| envelope must verify | `MessageError` |
| same network | `WrongNetwork` |
| same recipient agent | `WrongRecipient` |
| `height <= expires_height` | `Expired` |
| `seq` strictly increases per `(thread, sender)` | `Replay` |
| total occupancy below the cap | `Full` |
| per-thread occupancy below the cap | `ThreadFull` |
| replay-guard slots below the cap | `GuardFull` |

Expired entries are pruned before the capacity check, so aged-out garbage cannot
make a mailbox look full. A full mailbox refuses new mail; it never silently
evicts an unread message. `drain_thread` removes envelopes but keeps the sequence
guards, so a drained message cannot be pushed back in. Guards are never evicted.

Because sequences must increase, the mailbox assumes an ordered per-sender
transport. A message that arrives after a higher sequence was accepted is
refused rather than buffered — the conservative choice, since buffering would
need unbounded gap state.

## 5. Hidden and visible

Hidden: plaintext, plaintext length (only ciphertext length is visible), and the
per-message key.

Visible by design: sender and recipient agents, addresses and roles, thread id,
sequence, expiry and ciphertext size.

## 6. Not provided yet

- **Sealed sender** — the sender is in the envelope, so a relay sees the
  conversation graph.
- **Forward secrecy / post-compromise security** — the recipient's static key
  plus a captured ephemeral key decrypts that message. A double ratchet is not
  implemented.
- **Groups** — a thread is pairwise. Groups need a sender-key or MLS layer.
- **Transport and push** — envelopes and mailboxes are bytes; moving them is the
  operator's P2P/HTTP/MCP rail. Multi-device fan-out and presence are absent.
- **Padding policy** — length hiding is the caller's job.

## 7. Verified behavior

`cargo test -p srct-agentnet` passes 14 acceptance tests:

- hybrid-wallet seal/open round trip (including the address/ECDH binding);
- only the named recipient can open;
- mismatched recipient key bundles are refused at seal time;
- tampered ciphertext, thread, sequence, expiry and recipient make `verify` fail;
- spoofed sender key bundles fail;
- strict wire decode (trailing, truncated, wrong version);
- zero sequence, oversized plaintext and empty network refused;
- mailbox stores ciphertext without keys and orders by sequence;
- exact replay, re-signed duplicate sequence and stale sequence refused;
- wrong network and wrong recipient refused;
- expiry enforced and pruned;
- total/per-thread caps fail closed, expired mail does not count;
- draining keeps replay guards;
- duplicate wire delivery refused.

## 8. Next milestones

1. Double ratchet for forward secrecy and post-compromise security.
2. Sealed-sender routing (sender hidden from relays).
3. Group threads (sender keys or MLS).
4. Persistent mailbox storage with the same caps and guards.
5. HTTP/MCP transport plus delivery acknowledgements and multi-device fan-out.
6. Optional payload padding to a small set of sizes.
