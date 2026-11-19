# Cross-chain interop (HD wallet + EVM rail) — 19 Nov 2026

Status: **implemented, tested, non-consensus.** L1/L2 untouched. SRCT stays
the settlement coin; foreign chains settle via the solver/intent pattern.

## Pieces (all live)

- **HD wallet** (`crates/srct-core/src/hd.rs`): one seed, many chains.
  SRCT leg = existing `Wallet` (bundle `jt1` address). EVM = same scalar,
  secp256k1 ECDSA over keccak256, `0x` address. BTC = placeholder
  `SHA256`-truncated program with real bech32 (`bc1q`/`tb1q`) encoding —
  review RIPEMD-160 before mainnet funding. 7 tests (`hd::tests`).
- **EVM rail** (`crates/srct-intent/src/evm.rs`): canonical asset ids
  (`srct_asset`, `evm_native_asset`, `erc20_asset`), `EvmRail`
  (local SRCT-side ledger + exactly-once), foreign receipt gate.
  Settlement releases only after `confirm_foreign` (operator trust) or
  `confirm_verified` (RPC report: mined + status ok + value covers +
  `>= EVM_MIN_CONFIRMATIONS (12)` + txhash/recipient match).
- **Agent budget** (`x402.rs`): `X402Budget::{allowed_chains, allowed_assets}`
  + `check_asset(chain, asset)`. Default `srct_only()` = old behavior.
- **Worker**: `hd-address --chain evm|btc|srct`, `evm-sign`,
  `xchain-quote`, `xchain-confirm`.
- **Node REST**: `GET /v1/assets`, `POST /v1/xchain/status`.
- **RPC checker**: `templates/check_evm_receipt.py` (read-only, no keys).

## Try it

```bash
cargo run -q -p srct-worker -- generate --out-file /tmp/w.json --label demo
cargo run -q -p srct-worker -- hd-address --from-file /tmp/w.json --chain evm
cargo run -q -p srct-worker -- hd-address --from-file /tmp/w.json --chain btc
cargo run -q -p srct-worker -- xchain-quote --kind erc20 --chain-id 8453 \
  --contract 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
python templates/check_evm_receipt.py --rpc <RPC> --chain-id 84532 \
  --tx 0x<hash> --to 0x<addr> --min-value-wei 1000000
curl "$NODE/v1/assets"
```

## Solver flow

1. Agent intent opens with `accepted_assets` incl. the foreign asset.
2. Solver quotes with an `AssetRoute` + executes the EVM tx itself.
3. Solver posts `ForeignReceipt{chain_id, tx_hash, to, amount_atomic}`.
4. Operator runs `check_evm_receipt.py`, feeds the report to
   `confirm_verified`. Match + 12 confs = confirmed.
5. Rail `execute_settlement` releases SRCT escrow to the solver.
   Refund path unchanged (`execute_refund`).

## Trust model

Same as FX/ramps: RPC + operator whitelist, per-node books, signed paper
trail. No light client, no bridge mint, no atomicity claim. Start with 2-3
bonded solvers, slash on mis-settle.
