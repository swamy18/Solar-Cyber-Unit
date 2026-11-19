#!/usr/bin/env python3
"""Check one EVM transaction receipt and print a rail verification report.

The operator runs this against their own RPC before calling the rail's
confirm step. No keys, no signing, no fund movement: read-only lookup.

Usage:
    python templates/check_evm_receipt.py \
        --rpc https://sepolia.base.org \
        --chain-id 84532 \
        --tx 0x<hash> --to 0x<addr> --min-value-wei 1000000

Output is JSON: {chain_id, tx_hash, to, value, confirmations, confirmed}.
`confirmed` is true only when the tx is mined, successful (status 1),
pays at least --min-value-wei to --to, and has >= --min-conf confirmations.
"""

import argparse
import json
import sys
import urllib.request


def rpc_call(url: str, method: str, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.loads(resp.read().decode())
    if "error" in out:
        raise RuntimeError(f"rpc error: {out['error']}")
    return out["result"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--chain-id", required=True, type=int)
    ap.add_argument("--tx", required=True)
    ap.add_argument("--to", required=True)
    ap.add_argument("--min-value-wei", required=True, type=int)
    ap.add_argument("--min-conf", default=12, type=int)
    args = ap.parse_args()

    want_to = args.to.lower()
    tx = rpc_call(args.rpc, "eth_getTransactionByHash", [args.tx])
    if tx is None:
        print(json.dumps({"confirmed": False, "reason": "tx not found"}))
        return 0
    if (tx.get("to") or "").lower() != want_to:
        print(json.dumps({"confirmed": False, "reason": "recipient mismatch"}))
        return 0
    value = int(tx.get("value", "0x0"), 16)
    if value < args.min_value_wei:
        print(json.dumps({"confirmed": False, "reason": "value below minimum"}))
        return 0
    receipt = rpc_call(args.rpc, "eth_getTransactionReceipt", [args.tx])
    if receipt is None or receipt.get("status") != "0x1":
        print(json.dumps({"confirmed": False, "reason": "tx not mined ok"}))
        return 0
    head = rpc_call(args.rpc, "eth_blockNumber", [])
    confs = int(head, 16) - int(receipt["blockNumber"], 16)
    print(
        json.dumps(
            {
                "chain_id": args.chain_id,
                "tx_hash": args.tx.lower(),
                "to": want_to,
                "value": str(value),
                "confirmations": confs,
                "confirmed": confs >= args.min_conf,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
