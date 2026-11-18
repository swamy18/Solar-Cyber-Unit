# Phase 4 — L1 Guarded Outputs Proposal (Design Doc Only, No Code)

**Status:** PROPOSED — design only. No implementation, no consensus change, no parameter change is authorised by this document. Requires explicit owner approval before any code, SPEC, params, or vector change.

**Scope:** A new L1 `tx_type` carrying *guarded outputs*: UTXO encumbrances with a guardian, an allow-list commitment, and delay parameters. Mining rewards and compute earnings settle in these outputs. L1 owns the rule.

**Normative references (current truth, unchanged by this proposal):**
- `crates/srct-core/src/tx.rs`: `TX_STANDARD = 0`, `TX_COINBASE = 1`, `TX_BOND = 2`, `TX_UNBOND = 3`, `TX_SLASH = 4`; header comment: "future primitives … will add new `tx_type` values, never a scripting language" (v0.1 is scriptless by design).
- `crates/srct-core/src/ledger.rs::check_tx`: unknown `tx_type` values are refused, never interpreted as standard.
- SPEC §3.1–§3.3 (serialization), §9.2 (transaction validity: types 0–4; anything else refused), §9.3 (activation-height convention).
- Decisions 20 (bond/unbond/slash arrived as new `tx_type` values with positional payloads), 24 Step 4, 12/14/19 (0 = never for every activation height).

## 1. New `tx_type` value

**Proposed: `TX_GUARDED = 5`.** Next free value after 0–4. Positional guard payload after outputs, omitted for other types (byte-identical history). Follows Decision 20 precedent.

## 2. Guarded output structure (proposed, not built)

Per guarded output index: `guardian` (20B address), `allowlist_commitment` (32B SHA-256), `guard_delay_blocks` (u64), `guard_expiry_height` (u64), `flags` (u8). Fixed 73 bytes per descriptor. Spend paths: owner+delay+allow-list, guardian co-sign fast path, expiry release. Allow-list proven via preimage witness; change policy fail-closed.

## 3. Consensus interaction (not implemented)

`check_tx` whitelist adds type 5 gated by activation. UTXO entries carry encumbrance; spends enforce paths. Coinbase outputs must NOT be directly guarded (guard via second tx after maturity). Fee: ordinary L1 gas + `GAS_PER_GUARDED_OUTPUT`. No new fee schedule.

## 4. Activation height gating

New `NetworkParams::guarded_activation_height` (`0` = never). Testnet/mini first; mainnet stays `0` until sign-off. No post-quantum-style coupling; no live-chain governance.

## 5. Why this stays L1-owned

Issuance, conservation, and spend authorization are L1 consensus (Decision 25: a rule every node replays is a rule). Mining rewards and compute earnings are L1 value; a guard enforced anywhere but L1 is advice. L2 grants cannot bind L1 releases. Node policy (SpendPolicy, high-value approval) is deliberately non-consensus; guarded outputs are the consensus complement.

## 6. Explicitly OUT OF SCOPE

No code, no activation values, no SPEC change, no vector change, no economics set, no wallet/miner UX, no governance mechanism. Nothing in §§1–5 may be implemented without explicit approval against this document.

*End of Phase 4 proposal — design only.*
