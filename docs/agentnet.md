# Agent messaging

Status: **working non-consensus prototype** in `crates/srct-agentnet`. It
implements pairwise, end-to-end encrypted, signed agent messages, a double
ratchet with forward secrecy and post-compromise security, and a bounded
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

## 5. Double ratchet

`RatchetSession` wraps the same envelope format in a standard double ratchet,
specialised for this crate's ordered transport:

- The **initiator** generates a fresh DH ratchet key; the root key is
  `KDF_RK(salt, ECDH(that key, the recipient's static key))`, where the salt
  binds the session to the network, thread and pair of agents. The first
  envelope header carries the ratchet key in the `ephemeral_pubkey` field.
- The **responder** performs the same ECDH with its static key on the first
  received message and immediately rotates its own ratchet key, so its first
  reply already mixes a second DH into the root key. It also rotates on every
  later direction change, even if it never sends.
- Every message advances only its sending chain (`KDF_CK`); the old chain key
  is overwritten and the message key is never stored. A compromised chain key
  therefore cannot recover messages sent after it (forward secrecy).
- Every direction change feeds a fresh ECDH into the root key (`KDF_RK`), so
  an attacker who learns one endpoint's *current* state loses access to
  future traffic after the next reply and cannot read past traffic
  (post-compromise security).
- Message keys are derived as `HKDF(ck, seq)`, where `seq` is the same global
  per-sender sequence the mailbox enforces. A gap (`seq != expected`) is
  refused rather than buffered, matching the mailbox's conservative rule, and
  a refusal never advances the chains: the honest message that follows still
  decrypts.

Consequences:

- a ratchet message **cannot** be opened with `MessageEnvelope::open` — the
  static path derives a different key. Only the session can decrypt.
- the envelope wire format, the sender's hybrid signature and the mailbox are
  unchanged: a relay stores ratchet messages exactly like any other envelope.
- the responder binds the expected peer at construction, so a third party
  cannot hijack a session by delivering its own handshake first.
- one session covers one `(network, thread)` pair. Multiple threads between
  the same pair need separate sessions with separate thread nonces.
- like Signal without one-time prekeys, the root key is a function of the
  recipient's static key, so compromise of that key recovers the *initial*
  chain; forward secrecy starts at the first DH ratchet step (the
  responder's first reply) and post-compromise security from then on.

## 6. Hidden and visible

Hidden: plaintext, plaintext length (only ciphertext length is visible), and the
per-message key.

Visible by design: sender and recipient agents, addresses and roles, thread id,
sequence, expiry and ciphertext size.

## 7. Not provided yet

- **Sealed sender** — the sender is in the envelope, so a relay sees the
  conversation graph.
- **Groups** — a thread is pairwise. Groups need a sender-key or MLS layer.
- **Transport and push** — envelopes and mailboxes are bytes; moving them is the
  operator's P2P/HTTP/MCP rail. Multi-device fan-out and presence are absent.
- **Out-of-order delivery** — the ratchet and the mailbox both assume an
  ordered per-sender transport and refuse gaps instead of buffering them.
- **Padding policy** — length hiding is the caller's job.

## 8. Verified behavior

`cargo test -p srct-agentnet` passes 29 tests (2 unit, 27 acceptance):

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
- duplicate wire delivery refused;
- a ratchet conversation round-trips in both directions and sequences agree;
- the responder cannot send before receiving;
- a stale snapshot of session state cannot accept a later message, and an old
  chain key cannot derive a later message key (unit-pinned);
- every direction change rotates the DH ratchet key, including the
  responder's key rotation when it has not replied;
- a sequence gap is refused without advancing the chain, and the thread
  recovers on the honest message;
- replayed ratchet messages are refused;
- tampered ciphertext fails before any key is touched and the chain is intact;
- a third party cannot hijack a responder session;
- envelopes from another thread are refused;
- the static key path cannot open a ratchet message;
- ratchet envelopes flow through the wire codec, a relay mailbox and the
  session end to end;
- a session refuses a wallet other than its owner's.

## 9. Next milestones

1. Sealed-sender routing (sender hidden from relays).
2. Group threads (sender keys or MLS).
3. Persistent mailbox storage with the same caps and guards.
4. HTTP/MCP transport plus delivery acknowledgements and multi-device fan-out.
5. Optional payload padding to a small set of sizes.
