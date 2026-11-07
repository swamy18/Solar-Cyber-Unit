//! Solar Cyber Unit node CLI.
//!
//! Commands operate on a chain directory (`--data-dir`, default `./chain`):
//!
//! ```text
//! srct-node init      --network mini --wallet <name>   create the chain + a miner wallet
//! srct-node mine      --blocks 100                     mine N blocks
//! srct-node status                                 height, tip, supply, difficulty
//! srct-node verify                                 replay the chain and diff the state
//! srct-node show-block --height 10
//! srct-node balance  --address jt1...
//! srct-node send     --to jt1... --amount 10          build a tx, mine it, keep it
//!                                                   (--amount is in SRCT; use --amount-sat for satoshis)
//! srct-node wallet   --new --label miner
//! srct-node export   --out chain.json
//! srct-node serve     --listen 0.0.0.0:8333         relay blocks to and from peers
//! ```
//!
//! A `serve` subcommand runs the P2P node (`srct-net`); everything else operates
//! on a local chain directory. See `docs/roadmap.md` for what a real node still
//! needs.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use srct_core::agent::{derive_agent_id, derive_sub_agent_id, AgentId, AgentRole, SpendPolicy};
use srct_core::block::Block;
use srct_core::chain::Chain;
use srct_core::hash::{
    address_from_hex, address_to_hex, hash512_to_hex, hash_from_hex, hash_to_hex, Hash512,
};
use srct_core::l2::{
    AgentSpendPayload, CreditDefaultPayload, CreditOpenPayload, CreditRepayPayload, L2Payload,
    L2Transaction, PolicyPayload, PolicyRevokePayload,
};
use srct_core::params::{NetworkParams, SAT_PER_SRCT};
use srct_core::supply::{block_reward_sat, cumulative_supply_sat, halvings, max_issuance_sat};
use srct_core::tx::{OutPoint, Output, Transaction};
use srct_core::wallet::Wallet;
use srct_net::frame::write_frame;
use srct_net::msg::{Message, MessageType};
use srct_net::net::{NodeState, P2pConfig, P2pNode};
use srct_net::peer::{perform_handshake, HandshakeConfig};
use srct_net::relay::RelayManager;
use srct_net::syncer::SyncManager;
use srct_node::l2::NodeL2;
use srct_node::wallet_store;
use srct_store::{AppendOutcome, BlockStore, StateFile};

const USAGE: &str = "\
srct-node - Solar Cyber Unit base-layer node

USAGE:
  srct-node <COMMAND> [OPTIONS]

COMMANDS:
  init      Create a chain directory, a miner wallet and the genesis block
  mine      Mine blocks and extend the chain
  send      Spend from a wallet address, local or over P2P
  status    Print chain tip, difficulty, supply and wallet balance
  verify    Replay the chain from genesis and diff it against stored state
  show-block  Print one block
  balance   List the unspent outputs of an address
  wallet    Create or list wallets
  policy    Publish, revoke or list spending grants (agent authority)
  agent-spend  Spend under a published grant
  credit    Open, repay, default or list credit positions
  l2        Layer-2 summary, and the deposit address
  export    Write the canonical chain to JSON
  serve     Run a P2P node (block relay, multi-peer sync)
  validator Manage checkpoint-signing keys (M5 binding finality)
  help      This text

SEND OPTIONS:
  --to <address>             Recipient (required)
  --amount <srct>             Amount to send in SRCT (required)
  --amount-sat <sat>         Exact amount in satoshis (alternative to --amount)
  --relay <host:port>        Hand the signed transaction to a running node
                             instead of mining it here; the node's mempool
                             holds it and relays it to its peers
  --fee <sat>                Override the computed fee

COMMON OPTIONS:
  --network <mainnet|mini>   Default: mini
  --data-dir <path>          Default: ./chain
  --allow-plaintext-wallet   Permit wallets.json to hold unencrypted keys
                              (default: refuse; set SRCT_WALLET_PASSPHRASE to
                              encrypt the file with Argon2id + ChaCha20-Poly1305
                              and 0600 permissions instead)

POLICY OPTIONS (agent authority, SPEC 21):
  --spender <address>        The key that may exercise the grant (required)
  --per-tx <sat>             Largest single spend the grant allows (required)
  --cumulative <sat>         Largest total spend per window (required)
  --window <blocks>          Length of the tumbling window (default: 100)
  --expires <height>         Height the grant stops being usable
  --recipients <a,b,c>       Comma-separated allow-list; empty allows nothing
  --role <human|machine|service>  The role the grant names (default: machine)
  --parent <agent-id>        Delegate from this agent instead of being a root
  --agent-id <hex>           The agent to revoke (with --revoke)
  --list                     List what is published instead of changing it

AGENT-SPEND OPTIONS:
  --policy <hash>            The grant to spend under (required)
  --to <address>             Recipient (required)
  --amount <srct>             Amount to spend (required)
  --nonce <n>                Strictly increasing per grant (required)

CREDIT OPTIONS (SPEC 22):
  --to <address>             The borrower (with --open)
  --amount <srct>             Principal, or the repayment amount
  --collateral <sat>         Collateral the borrower locks (default: --amount)
  --rate-bps <bps>           Interest per window (default: 100)
  --window <blocks>          Length of an interest window (default: 100)
  --deadline <height>        Height the debt is due by
  --position <hash>          The position to repay or default
  --nonce <n>                Per-lender sequence number
  --list                     List the positions instead of changing one

VALIDATOR KEY OPTIONS:
  --add                       Create one random validator key
  --bootstrap                 Create all 21 deterministic mainnet bootstrap
                              keys (mainnet only; quorum is 15). A fresh
                              mainnet node needs a quorum locally to produce
                              the first checkpoint.
  (no flag; environment only)  Validator keys are encrypted under
                              SRCT_VALIDATOR_PASSPHRASE, falling back to
                              SRCT_WALLET_PASSPHRASE with a one-time warning
                              that sharing one passphrase for both is
                              discouraged. A validator key file in plaintext
                              still loads, with a warning per file

SERVE OPTIONS:
  --listen <host:port>       TCP address to accept inbound peers (optional)
  --api-listen <host:port>   Start the opt-in REST service API (disabled by
                             default; loopback expected — see SPEC.md §19.2)
  --api-token <token>        Bearer token the API requires. A non-loopback
                              --api-listen is refused without one; absent, the
                              SRCT_API_TOKEN environment variable is used.
                              Prefer the environment variable: --api-token is
                              visible in `ps` to other local users
  --api-allowed-host <names> Extra hostnames accepted in the HTTP `Host`
                              header on a non-loopback API bind,
                              comma-separated. Merged with
                              SRCT_API_ALLOWED_HOSTS. IP literals need no
                              allowlisting; unknown names get 403
  --connect <host:port>      Dial an outbound peer (repeatable via CSV)
  --bootnodes <list>           Comma-separated bootnode addresses to dial at
                               startup and retry on each reconnect cycle
                               (optional; v0.2 has no ADDR gossip so these are
                               the only peer source alongside --connect)
  --peers <n>                Max total peers (default: 125)
  --interval <ms>            Serve loop period (default: 250)
  --no-mine                  Relay and validate only, never mine
  --allow-bootstrap-committee
                               Serve mainnet while the loaded validator keys
                               are the 21 public bootstrap keys (default:
                               refuse). Cold start only: replace them with
                               bonded keys; anyone can sign alongside you
                               until the first bond rotates authority
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Args {
    network: String,
    data_dir: PathBuf,
    flags: BTreeMap<String, String>,
    switches: Vec<String>,
}

impl Args {
    fn parse(raw: &[String]) -> Result<Self, String> {
        let mut out = Args {
            network: "mini".into(),
            data_dir: PathBuf::from("chain"),
            flags: BTreeMap::new(),
            switches: Vec::new(),
        };
        let mut i = 0;
        while i < raw.len() {
            let a = &raw[i];
            if let Some(name) = a.strip_prefix("--") {
                // Flags that take a value; everything else is a boolean switch.
                let takes_value = matches!(
                    name,
                    "network"
                        | "data-dir"
                        | "blocks"
                        | "amount"
                        | "amount-sat"
                        | "to"
                        | "address"
                        | "wallet"
                        | "label"
                        | "height"
                        | "out"
                        | "from"
                        | "interval"
                        | "fee"
                        | "listen"
                        | "api-listen"
                        | "api-token"
                        | "api-allowed-host"
                        | "connect"
                        | "peers"
                        | "relay"
                        | "bootnodes"
                        | "grant-hex"
                        | "spender"
                        | "agent-id"
                        | "parent"
                        | "policy"
                        | "nonce"
                        | "recipients"
                        | "role"
                        | "per-tx"
                        | "window"
                        | "cumulative"
                        | "expires"
                        | "collateral"
                        | "rate-bps"
                        | "deadline"
                        | "position"
                        | "credit-issuer"
                );
                if takes_value {
                    let value = raw
                        .get(i + 1)
                        .ok_or_else(|| format!("--{name} needs a value"))?;
                    match name {
                        "network" => out.network = value.clone(),
                        "data-dir" => out.data_dir = PathBuf::from(value),
                        _ => {
                            out.flags.insert(name.to_string(), value.clone());
                        }
                    }
                    i += 2;
                } else {
                    // Boolean switches are allow-listed: a typo like
                    // `--no_mine` or `--mine-blocks 5` used to parse as a
                    // silent no-op switch, and the node ran without the
                    // operator's intent (mining when they meant not to, or
                    // vice versa). Unknown `--x` is a hard error.
                    const SWITCHES: &[&str] = &[
                        "allow-bootstrap-committee",
                        "allow-plaintext-wallet",
                        "help",
                        "list",
                        "revoke",
                        "default",
                        "repay",
                        "deposit-address",
                        "bootstrap",
                        "add",
                        "new",
                        "no-mine",
                    ];
                    if !SWITCHES.contains(&name) {
                        return Err(format!("unknown switch `--{name}` (typo? see `help`)"));
                    }
                    out.switches.push(name.to_string());
                    i += 1;
                }
            } else if a == "-h" {
                out.switches.push("help".into());
                i += 1;
            } else {
                return Err(format!("unexpected argument `{a}`"));
            }
        }
        Ok(out)
    }

    fn str(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(|s| s.as_str())
    }

    /// True when the user asked for help rather than for work.
    ///
    /// `--help` parses as a boolean switch, but `-h` is not `--`-prefixed and
    /// would otherwise be rejected as an unexpected argument.
    fn wants_help(&self) -> bool {
        self.switches.iter().any(|s| s == "help")
    }

    fn str_or(&self, name: &str, default: &str) -> String {
        self.str(name).unwrap_or(default).to_string()
    }

    fn num(&self, name: &str, default: u64) -> Result<u64, String> {
        match self.flags.get(name) {
            Some(v) => v.parse().map_err(|_| format!("--{name} must be a number")),
            None => Ok(default),
        }
    }

    /// Parse a SRCT amount (decimal, e.g. `10.5`) into satoshis. Returns `None`
    /// when the flag is absent.
    fn srct(&self, name: &str) -> Result<Option<u64>, String> {
        match self.flags.get(name) {
            Some(v) => parse_srct_sat(v).map(Some),
            None => Ok(None),
        }
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    fn params(&self) -> Result<NetworkParams, String> {
        NetworkParams::by_name(&self.network).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

struct Store {
    dir: PathBuf,
    params: NetworkParams,
    /// The append-only block store. Opened lazily alongside the JSON chain
    /// during migration; once present it is the authoritative block data.
    block_store: Option<BlockStore>,
    /// `--allow-plaintext-wallet`: the explicit opt-in that lets
    /// `save_wallets` write unencrypted private keys. Absent means refuse —
    /// an operator who has not thought about at-rest protection still gets it.
    allow_plaintext_wallet: bool,
}

impl Store {
    fn open(args: &Args) -> Result<Self, String> {
        let params = args.params()?;
        Ok(Store {
            dir: args.data_dir.clone(),
            params,
            block_store: None,
            allow_plaintext_wallet: args.has("allow-plaintext-wallet"),
        })
    }

    fn chain_path(&self) -> PathBuf {
        self.dir.join("blocks.json")
    }

    fn wallets_path(&self) -> PathBuf {
        self.dir.join("wallets.json")
    }

    /// Directory holding validator key files, one per `.json` file. Created on
    /// demand so `validator add` never fails on a fresh data dir, and never
    /// confused with `wallets.json`, which holds *spending* keys.
    fn validator_keys_path(&self) -> PathBuf {
        self.dir.join("validators")
    }

    fn meta_path(&self) -> PathBuf {
        // The srct-store metadata. blocks.json is legacy; this is what the
        // append-only store reads.
        self.dir.join("meta.json")
    }

    /// Open the append-only store, migrating `blocks.json` if it exists and
    /// the store does not.
    fn ensure_block_store(&mut self) -> Result<&mut BlockStore, String> {
        if self.block_store.is_none() {
            let legacy = self.chain_path();
            let store_dir = self.dir.join("store");
            let fresh = !store_dir.join("blocks.log").exists();
            let (mut bs, recovery) =
                BlockStore::open(&store_dir, &self.params).map_err(|e| e.to_string())?;
            if !recovery.truncated {
                // recovery handled below via bs.recovery()
            }
            if fresh && legacy.exists() {
                // One-time migration: read every block from the JSON chain and
                // append it, then mark the store's tip at the JSON tip. The
                // JSON file is kept until the migration is verified on the
                // next open, then left in place (harmless, and deleting a
                // user's chain file automatically is not a decision a node
                // makes silently).
                let text = fs::read_to_string(&legacy).map_err(|e| e.to_string())?;
                let blocks: Vec<Block> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
                for b in &blocks {
                    bs.append_block(b).map_err(|e| e.to_string())?;
                }
                if let Some(last) = blocks.last() {
                    bs.set_tip(&last.block_hash()).map_err(|e| e.to_string())?;
                }
                bs.sync().map_err(|e| e.to_string())?;
                println!(
                    "migrated {} blocks from blocks.json into the append-only store",
                    blocks.len()
                );
            }
            let rec = bs.recovery();
            if rec.discarded_tail_bytes > 0 {
                println!(
                    "store recovered: {} record(s), dropped {} byte torn tail",
                    rec.records, rec.discarded_tail_bytes
                );
            }
            self.block_store = Some(bs);
        }
        // invariant: the `if` block above always sets `block_store` before this.
        Ok(self.block_store.as_mut().expect("just set"))
    }

    fn load_chain(&mut self) -> Result<Chain, String> {
        // The block store is the source of truth once it exists. Every stored
        // block is re-validated on load by `Chain::submit`, so a store bug that
        // hands the chain a bad block fails here, not silently.
        let params = self.params.clone();
        let mut chain = Chain::new(params).map_err(|e| e.to_string())?;
        {
            let bs = self.ensure_block_store()?;
            let (_tip, height) = bs.tip();
            for h in 1..=height {
                let block = bs
                    .block_at_height(h)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("store has no block at canonical height {h}"))?;
                chain.submit(block).map_err(|e| e.to_string())?;
            }
            // Binding finality (Decision 12) survives restart: restore the
            // persisted point, but only onto the exact canonical block the
            // chain just replayed — `restore_finality` refuses anything else,
            // so a stale or forged metadata row cannot finalize a block the
            // chain does not hold.
            if let Some((fh, fhash)) = bs.finalized() {
                if !chain.restore_finality(fh, fhash) {
                    return Err(format!(
                        "persisted finalized point {fh} does not match the canonical chain"
                    ));
                }
            }
        }
        Ok(chain)
    }

    /// Append new blocks and move the canonical tip. O(new blocks), not O(chain).
    fn save_chain(&mut self, chain: &Chain) -> Result<(), String> {
        let bs = self.ensure_block_store()?;
        let (_, stored_height) = bs.tip();
        for h in stored_height + 1..=chain.height() {
            let block = chain
                .block_at(h)
                .ok_or_else(|| format!("chain has no block at height {h}"))?;
            let outcome = bs.append_block(block).map_err(|e| e.to_string())?;
            match outcome {
                AppendOutcome::Stored | AppendOutcome::Duplicate => {
                    bs.set_tip(&block.block_hash()).map_err(|e| e.to_string())?;
                }
                AppendOutcome::Orphaned => {
                    return Err(format!(
                        "block at height {h} has no stored parent; refusing to advance the tip"
                    ))
                }
            }
        }
        bs.sync().map_err(|e| e.to_string())
    }

    /// Read the wallet file — encrypted when it was saved that way.
    ///
    /// An encrypted file with no passphrase is an error, not a fallback: there
    /// is nothing else the file could usefully be, and silently returning an
    /// empty wallet list would make a node look like it had lost its keys.
    fn load_wallets(&self) -> Result<Vec<Wallet>, String> {
        let path = self.wallets_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        if wallet_store::is_encrypted(&bytes) {
            let passphrase = wallet_store::passphrase_from_env().ok_or_else(|| {
                format!(
                    "{} is encrypted; set {} to read it",
                    path.display(),
                    wallet_store::PASSPHRASE_ENV
                )
            })?;
            // Zeroized end to end: the JSON is parsed straight from the
            // wiping buffer, with no intermediate `String` or `Vec` copy.
            let plain = wallet_store::decrypt(&passphrase, &bytes)?;
            serde_json::from_slice(&plain).map_err(|e| e.to_string())
        } else {
            // One note, not a refusal: refusing to *read* an existing plaintext
            // file would lock the operator out of their own keys. The refusal
            // lives in `save_wallets`, where the next write happens.
            eprintln!(
                "note: {} holds plaintext private keys; set {} and save to encrypt it",
                path.display(),
                wallet_store::PASSPHRASE_ENV
            );
            let bytes = zeroize::Zeroizing::new(bytes);
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())
        }
    }

    /// Persist wallets encrypted under `SRCT_WALLET_PASSPHRASE`, written 0600
    /// and atomically so a crash cannot leave a torn or briefly-readable key
    /// file. Without a passphrase, plaintext is refused unless
    /// `--allow-plaintext-wallet` says the operator has decided to accept it.
    fn save_wallets(&self, wallets: &[Wallet]) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        // The serialized wallets hold secrets, so the buffer wipes on drop.
        // The plaintext path keeps the `Zeroizing` wrapper to the write:
        // moving the inner `Vec` out would leave a plain buffer that is
        // never wiped.
        let text =
            zeroize::Zeroizing::new(serde_json::to_vec_pretty(wallets).map_err(|e| e.to_string())?);
        let payload: zeroize::Zeroizing<Vec<u8>> = match wallet_store::passphrase_from_env() {
            Some(passphrase) => zeroize::Zeroizing::new(wallet_store::encrypt(&passphrase, &text)?),
            // Explicit operator opt-in: the plaintext file is the accepted
            // risk, but the in-memory copy is still wiped after the write.
            None if self.allow_plaintext_wallet => text,
            None => {
                return Err(format!(
                    "refusing to write plaintext private keys to {}: set {} to \
                     encrypt them, or pass --allow-plaintext-wallet to accept the risk",
                    self.wallets_path().display(),
                    wallet_store::PASSPHRASE_ENV
                ));
            }
        };
        wallet_store::write_private(&self.wallets_path(), &payload)
    }

    fn write_meta(&self, chain: &Chain) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let meta = serde_json::json!({
            "network": self.params.name,
            "genesis_hash": hash512_to_hex(&chain.block_hash_at(0).unwrap_or([0u8; 64])),
            "height": chain.height(),
        });
        let text = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
        fs::write(self.meta_path(), text).map_err(|e| e.to_string())
    }

    /// Persist the chain's binding-finalized point if it advanced (Decision 12).
    ///
    /// A checkpoint moves finality without moving the tip, so this runs on its
    /// own condition, not on the height-change condition. Blocks are saved
    /// first — a finalized height must always be provable from stored history.
    /// Idempotent: an unchanged point is a no-op, and the store refuses any
    /// regressing or conflicting write.
    fn persist_finality(&mut self, chain: &Chain) -> Result<(), String> {
        let Some((fh, fhash)) = chain.finalized_point() else {
            return Ok(());
        };
        let bs = self.ensure_block_store()?;
        if bs.finalized() == Some((fh, fhash)) {
            return Ok(());
        }
        if bs.tip().1 < fh {
            // The blocks below the finalized height are not stored yet (a
            // checkpoint arrived in the same batch as the blocks it finalizes).
            // Save them first; `set_finalized` proves against stored history.
            self.save_chain(chain)?;
        }
        let bs = self.ensure_block_store()?;
        bs.set_finalized(fh, fhash).map_err(|e| e.to_string())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn srct(sat: u64) -> String {
    format!("{}.{:08}", sat / SAT_PER_SRCT, sat % SAT_PER_SRCT)
}

/// Convert a SRCT decimal string (e.g. `10.5`) to satoshis. Rejects negatives and
/// values with more than 8 decimal places.
fn parse_srct_sat(v: &str) -> Result<u64, String> {
    let neg = v.starts_with('-');
    let v = v.trim_start_matches('-');
    let (whole, frac) = match v.split_once('.') {
        Some((w, f)) => (w, f),
        None => (v, ""),
    };
    let whole: u64 = whole
        .parse()
        .map_err(|_| "--amount must be a number".to_string())?;
    let frac_sat: u64 = if frac.is_empty() {
        0
    } else {
        if frac.len() > 8 {
            return Err("--amount has more than 8 decimal places".into());
        }
        // Zero-pad on the right: `1.5` is one SRCT and fifty million satoshis.
        // The fill character has to come *before* the alignment in the format
        // spec, so this is `{frac:0<8}` and not `{frac:<0width$}` — the
        // latter left-aligns with spaces, and "5       " does not parse as a
        // number, which is why every fractional amount used to be refused
        // with "--amount must be a number".
        let padded = format!("{frac:0<8}");
        padded
            .parse::<u64>()
            .map_err(|_| "--amount must be a number".to_string())?
    };
    if neg {
        return Err("--amount must be positive".into());
    }
    whole
        .checked_mul(SAT_PER_SRCT)
        .and_then(|v| v.checked_add(frac_sat))
        .ok_or_else(|| "--amount overflows satoshis".into())
}

/// One-line L2 summary shared by every command that moves the tip.
///
/// This is the whole of the node's L2 observability for M1: which height was
/// replayed to, how many payloads applied, how many were refused. The reasons
/// for each refusal live in `NodeL2::skipped` (height, txid, named error); a
/// full REST surface for them belongs to the M3 transport milestone, not here.
fn print_l2_summary(l2: &NodeL2, chain: &Chain) {
    let s = l2.status(chain.height());
    println!(
        "l2             height {}  applied {}  skipped {}{}  deposits {} credited / {} pending / {} ignored",
        s.l2_height,
        s.applied,
        s.skipped,
        if s.clean { "" } else { " (see verify)" },
        s.deposits_applied,
        s.deposits_pending,
        s.deposits_ignored,
    );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn run(raw: &[String]) -> Result<(), String> {
    let command = raw[0].clone();
    let args = Args::parse(&raw[1..])?;

    // `--help` and `-h` anywhere on the line means help, not work. Without
    // this, `mine --help` opened a chain directory and failed on a fresh
    // checkout, which reads like a broken install rather than a help request.
    if args.wants_help() {
        println!("{USAGE}");
        return Ok(());
    }

    match command.as_str() {
        "init" => cmd_init(&args),
        "mine" => cmd_mine(&args),
        "send" => cmd_send(&args),
        "status" => cmd_status(&args),
        "verify" => cmd_verify(&args),
        "show-block" => cmd_show_block(&args),
        "balance" => cmd_balance(&args),
        "wallet" => cmd_wallet(&args),
        "export" => cmd_export(&args),
        "validator" => cmd_validator(&args),
        "policy" => cmd_policy(&args),
        "agent-spend" => cmd_agent_spend(&args),
        "credit" => cmd_credit(&args),
        "l2" => cmd_l2(&args),
        "serve" => cmd_serve(&args),
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

fn cmd_init(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    if store.chain_path().exists() || store.dir.join("store/blocks.log").exists() {
        return Err(format!(
            "{} already holds a chain; delete it to start over",
            store.dir.display()
        ));
    }
    if store.dir.join("wallets.json").exists() {
        return Err(format!(
            "{} already holds a wallets.json; init would overwrite existing keys — \
             move the file aside or use another --data-dir",
            store.dir.display()
        ));
    }
    let chain = Chain::new(store.params.clone()).map_err(|e| e.to_string())?;

    let mut wallets = Vec::new();
    let label = args.str_or("label", "miner");
    let w = Wallet::new_random(&label);
    println!("wallet `{}`", w.label);
    println!(
        "  address  {}",
        address_to_hex(&w.address().map_err(|e| e.to_string())?)
    );
    println!(
        "  pubkey   {}",
        w.public_key_hex().map_err(|e| e.to_string())?
    );
    wallets.push(w);
    store.save_wallets(&wallets)?;

    store.save_chain(&chain)?;
    store.write_meta(&chain)?;

    println!();
    println!("network        {}", store.params.name);
    println!("genesis        {}", hash512_to_hex(&chain.tip_hash()));
    println!("block time     {} ms", store.params.target_block_time_ms);
    println!(
        "issuance       ladder then a permanent tail; rate-anchored at 1% of issued per halving period (no stock cap, Decision 18)"
    );
    println!(
        "ladder reachable {} SRCT",
        max_issuance_sat(&store.params) / SAT_PER_SRCT
    );
    println!("data dir       {}", store.dir.display());
    Ok(())
}

fn cmd_mine(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let mut chain = store.load_chain()?;
    // The L2 view starts from replaying what is stored, then follows the tip
    // as blocks are mined below. Genesis-funded accounts apply; genuinely
    // unfunded payloads are expected `InsufficientBalance` skips, not errors
    // — the view still advances and still names what it refused.
    let mut l2 = NodeL2::replay_from(&chain, &store.params).map_err(|e| e.to_string())?;
    let wallets = store.load_wallets()?;
    if wallets.is_empty() {
        return Err("no wallet in this data dir".into());
    }
    let miner_label = args.str_or("wallet", &wallets[0].label.clone());
    let miner = wallets
        .iter()
        .find(|w| w.label == miner_label)
        .ok_or_else(|| format!("no wallet labelled `{miner_label}`"))?;
    let address = miner.address().map_err(|e| e.to_string())?;

    let count = args.num("blocks", 1)?;
    let interval = args.num("interval", 0)?;
    let mut mined = 0u64;
    for _ in 0..count {
        let block = chain
            .mine_block(address, vec![], now_ms())
            .map_err(|e| e.to_string())?;
        let hash = block.block_hash();
        let height = block.header.height;
        let difficulty = block.header.difficulty;
        chain.submit(block).map_err(|e| e.to_string())?;
        // `submit` accepted the block, so the L2 view follows it. A block the
        // L1 layer rejects never moves the tip and therefore never reaches the
        // view — that ordering is what keeps rejected blocks from mutating L2
        // state.
        l2.sync(&chain).map_err(|e| e.to_string())?;
        println!(
            "height {:>6}  diff {:>10}  reward {:>12} SRCT  {}",
            height,
            difficulty,
            srct(block_reward_sat(chain.params(), height)),
            &hash512_to_hex(&hash)[..16]
        );
        mined += 1;
        if interval > 0 {
            std::thread::sleep(std::time::Duration::from_millis(interval));
        }
    }
    store.save_chain(&chain)?;
    store.write_meta(&chain)?;
    println!("mined {mined} block(s); tip height {}", chain.height());
    print_l2_summary(&l2, &chain);
    Ok(())
}

fn cmd_send(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let mut chain = store.load_chain()?;
    let wallets = store.load_wallets()?;
    if wallets.is_empty() {
        return Err("no wallet in this data dir".into());
    }

    let from_label = args.str_or("wallet", &wallets[0].label.clone());
    let sender = wallets
        .iter()
        .find(|w| w.label == from_label)
        .ok_or_else(|| format!("no wallet labelled `{from_label}`"))?;
    let from = sender.address().map_err(|e| e.to_string())?;

    let to = address_from_hex(args.str("to").ok_or("--to <address> is required")?)
        .map_err(|e| e.to_string())?;
    // `--amount` is denominated in SRCT (matching every other printed figure).
    // `--amount-sat` is available for exact satoshi amounts.
    let amount_sat = if let Some(sat) = args.str("amount-sat") {
        sat.parse::<u64>()
            .map_err(|_| "--amount-sat must be a number")?
    } else {
        match args.srct("amount")? {
            Some(sat) => sat,
            None => return Err("--amount is required".into()),
        }
    };
    if amount_sat == 0 {
        return Err("--amount must be greater than zero".into());
    }

    // Only matured coinbase outputs are spendable in v0.1.
    let candidates: Vec<(OutPoint, u64)> = chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == from && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .collect();
    if candidates.is_empty() {
        return Err(format!(
            "no mature outputs for {} (a coinbase needs {} blocks)",
            address_to_hex(&from),
            chain.params().coinbase_maturity
        ));
    }

    let base_fee = chain.expected_base_fee_for_next_block();

    // Gather inputs until `amount + fee` is covered. The fee depends on the
    // number of inputs, and the input count depends on the fee, so this settles
    // by iteration rather than in one guess.
    let fee_override = args.num("fee", 0)?;
    // An explicit `--fee` below the consensus floor builds a transaction the
    // chain refuses (`BadFee`) — fail here with the floor stated instead of
    // mining a block that wastes the work. The floor uses the final input
    // count, so this is re-checked after selection below.
    let mut chosen: Vec<OutPoint> = Vec::new();
    let mut total = 0u64;
    for (op, value) in candidates {
        let gas = 16_000 + 1_000 * (chosen.len() + 1) as u64 + 250 * 2;
        let fee = if fee_override > 0 {
            fee_override
        } else {
            base_fee.saturating_mul(gas).saturating_add(1_000)
        };
        if total >= amount_sat.saturating_add(fee) {
            break;
        }
        total += value;
        chosen.push(op);
    }
    let gas = 16_000 + 1_000 * chosen.len() as u64 + 250 * 2;
    let floor = base_fee
        .checked_mul(gas)
        .and_then(|f| f.checked_add(1_000))
        .ok_or_else(|| "fee floor overflows u64; refusing to build".to_string())?;
    let fee = if fee_override > 0 {
        if fee_override < floor {
            return Err(format!(
                "fee {fee_override} sat is below the consensus floor of {floor} sat \
                 (base_fee {base_fee} * gas {gas} + 1000); raise --fee or omit it"
            ));
        }
        // An explicit fee larger than the payment itself is refused: it is
        // almost always a misplaced decimal, and the protocol minimum is
        // already enforced by the floor above.
        if fee_override > amount_sat {
            return Err(format!(
                "fee {fee_override} sat exceeds the payment of {amount_sat} sat; \
                 refusing a transfer that costs more than it moves"
            ));
        }
        fee_override
    } else {
        floor
    };
    if total < amount_sat.saturating_add(fee) {
        return Err(format!(
            "insufficient funds: have {total} sat, need {} sat",
            amount_sat.saturating_add(fee)
        ));
    }

    let change = total.saturating_sub(amount_sat).saturating_sub(fee);
    let mut outputs = vec![Output {
        value: amount_sat,
        address: to,
    }];
    if change > 0 {
        outputs.push(Output {
            value: change,
            address: from,
        });
    }

    let tx = sender
        .build_tx(&chosen, outputs, fee)
        .map_err(|e| e.to_string())?;
    let txid = srct_core::hash::hash512_to_hex(&tx.txid());
    // Show the money before it moves: amount, fee and change hit the screen
    // while the transaction is still unsigned-in-a-block and abortable by
    // the operator reading them — not after the block is already mined.
    println!("amount  {} SRCT", srct(amount_sat));
    println!("fee     {} SRCT", srct(fee));
    println!("change  {} SRCT", srct(change));

    // `--relay <addr>` hands the signed transaction to a running node over the
    // real P2P protocol instead of mining it here (SPEC.md §13.14). Without it
    // there was no way to get a locally built transaction into a node's pool at
    // all: this command mined it straight into a block, so the wallet path was
    // "build a transaction, then be your own miner", and the relay path was only
    // reachable from another node. A transaction that never enters the pool
    // cannot be relayed, cannot be replaced by a better fee, and cannot be seen
    // by any peer before it is already confirmed.
    //
    // Mining in place is kept as the default for the ordinary case of a single
    // node with no peers, where there is nothing to relay to and no mempool for
    // anything else to fill.
    if let Some(relay_addr) = args.str("relay") {
        let relay_addr: std::net::SocketAddr = relay_addr
            .parse()
            .map_err(|e| format!("--relay `{relay_addr}`: {e}"))?;
        relay_transaction(relay_addr, &chain, &tx)?;
        println!("txid    {txid}");
        println!("relayed to {relay_addr} (not mined here; the node's mempool holds it)");
        return Ok(());
    }

    let block = chain
        .mine_block(from, vec![tx], now_ms())
        .map_err(|e| e.to_string())?;
    let height = block.header.height;
    let burned = block.header.base_fee_sat * block.txs[1].gas_used();
    chain.submit(block).map_err(|e| e.to_string())?;
    let l2 = NodeL2::replay_from(&chain, &store.params).map_err(|e| e.to_string())?;
    store.save_chain(&chain)?;
    store.write_meta(&chain)?;

    println!("txid    {txid}");
    println!("height  {height}");
    println!("burned  {} SRCT (base fee, destroyed)", srct(burned));
    print_l2_summary(&l2, &chain);
    Ok(())
}

/// Hand a signed transaction to a running node.
///
/// Deliberately the smallest client that can do this: connect, complete the
/// §13.4 handshake, send `TX`, keep the connection open long enough for the node
/// to read the frame, close. No `INV` first — the node admits a `TX` whether or
/// not it asked for it, which is what lets a wallet that was never in the
/// announcement path contribute one.
///
/// It does **not** read a reply, because the protocol has no `TX` acknowledgement
/// to read: admission is silent, and the node announces the txid to *its* peers
/// rather than back to the sender. That is honest about what this can promise —
/// the transaction reached a node, not that the node accepted it. `status` on
/// that node is the check, and the sender still owns the outputs until a block
/// spends them.
fn relay_transaction(
    addr: std::net::SocketAddr,
    chain: &Chain,
    tx: &Transaction,
) -> Result<(), String> {
    use std::io::Write;

    let params = chain.params().clone();
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))
            .map_err(|e| format!("relay connect {addr}: {e}"))?;
    let cfg = HandshakeConfig::new(params.clone(), chain.height(), chain.tip_hash());
    perform_handshake(&mut stream, &cfg, true).map_err(|e| format!("relay handshake: {e}"))?;

    let payload = Message::Tx(Box::new(tx.clone())).encode();
    write_frame(&mut stream, &params, MessageType::Tx as u8, &payload)
        .map_err(|e| format!("relay send: {e}"))?;
    stream.flush().map_err(|e| e.to_string())?;

    // Closing immediately after a write is normally safe — TCP delivers what was
    // written before the FIN — but the node's side of this is a thread that may
    // not have been scheduled yet, and a connection that lands in the backlog and
    // is then reset is a transaction the sender believes it sent. One short pause
    // turns "probably delivered" into "delivered".
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

/// Mine a block carrying one Layer-2 transaction, and report what happened.
///
/// The L2 state root is computed by the node's own replay, so the block commits
/// to exactly the state the node believes — the same rule a miner follows.
fn mine_l2_tx(
    store: &mut Store,
    chain: &mut Chain,
    l2: &NodeL2,
    miner: srct_core::hash::Address,
    tx: L2Transaction,
) -> Result<u64, String> {
    let height = chain.height() + 1;
    // Check it against the state the chain will replay. A transaction the
    // state machine refuses is *skipped* by the replay, so mining it would
    // produce a block that says nothing happened — and the command would
    // report a height for work that never took effect. Refuse here, with the
    // reason the chain gave.
    l2.check(chain, &tx, height)
        .map_err(|e| format!("the chain would skip this transaction: {e}"))?;
    let root = l2.simulate_root(chain, height, std::slice::from_ref(&tx));
    let block = chain
        .mine_block_with_l2_root(
            miner,
            Vec::new(),
            vec![tx],
            root,
            now_ms(),
            None,
            200_000_000,
        )
        .map_err(|e| e.to_string())?;
    let mined = block.header.height;
    chain.submit(block).map_err(|e| e.to_string())?;
    store.save_chain(chain)?;
    store.write_meta(chain)?;
    Ok(mined)
}

/// The wallet the command acts as, and the address it acts from.
fn acting_wallet(args: &Args, store: &Store) -> Result<(Wallet, srct_core::hash::Address), String> {
    let wallets = store.load_wallets()?;
    if wallets.is_empty() {
        return Err("no wallet in this data dir".into());
    }
    let label = args.str_or("wallet", &wallets[0].label.clone());
    let wallet = wallets
        .iter()
        .find(|w| w.label == label)
        .ok_or_else(|| format!("no wallet labelled `{label}`"))?;
    let address = wallet.address().map_err(|e| e.to_string())?;
    Ok((wallet.clone(), address))
}

/// The Layer-2 state as this node sees it, rebuilt from the canonical chain.
fn l2_state_of(store: &Store, chain: &Chain) -> Result<NodeL2, String> {
    NodeL2::replay_from(chain, &store.params).map_err(|e| e.to_string())
}

/// `srct-node policy` — publish, revoke or list spending grants (SPEC.md §21).
///
/// A grant is the owner's signed authority for a named spender, bounded by
/// caps and allow-lists. Publishing it puts it on chain, where every node
/// enforces it.
fn cmd_policy(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let mut chain = store.load_chain()?;
    let (wallet, owner) = acting_wallet(args, &store)?;

    if args.has("list") {
        let l2 = l2_state_of(&store, &chain)?;
        let state = l2.state();
        let policies = state.policies();
        if policies.is_empty() {
            println!("no published grants");
        }
        for p in policies {
            println!(
                "{}  agent {}  spender {}  per-tx {}  window {}  cumulative {}  spent {}  spends {}  revoked {}",
                hash_to_hex(&p.hash()),
                address_to_hex(&p.agent_id),
                address_to_hex(&p.spender),
                srct(p.policy.per_tx_max_sat),
                p.policy.window_blocks,
                srct(p.policy.cumulative_max_sat),
                srct(p.spent_in_window_sat),
                p.spends,
                p.revoked,
            );
        }
        return Ok(());
    }

    if args.has("revoke") {
        let agent_id = args.str("agent-id").ok_or("--agent-id <hex> is required")?;
        let agent_id = decode_agent_id(agent_id)?;
        let payload = PolicyRevokePayload::build(&wallet, agent_id).map_err(|e| e.to_string())?;
        let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
        let l2 = l2_state_of(&store, &chain)?;
        let height = mine_l2_tx(&mut store, &mut chain, &l2, owner, tx)?;
        println!("height  {height}");
        println!("revoked agent {}", address_to_hex(&agent_id));
        return Ok(());
    }

    // Publish.
    let spender = address_from_hex(
        args.str("spender")
            .ok_or("--spender <address> is required")?,
    )
    .map_err(|e| e.to_string())?;
    let network_id = store.params.network_id.clone();
    let role = match args.str_or("role", "machine").as_str() {
        "human" => AgentRole::Human,
        "machine" => AgentRole::Machine,
        "service" => AgentRole::Service,
        other => {
            return Err(format!(
                "--role must be human, machine or service, got `{other}`"
            ))
        }
    };
    let parent = match args.str("parent") {
        Some(hex) => Some(decode_agent_id(hex)?),
        None => None,
    };
    let agent_id = match parent {
        Some(p) => derive_sub_agent_id(&network_id, &p, role),
        None => derive_agent_id(&network_id, role, &owner),
    };
    let recipients = match args.str("recipients") {
        Some(list) => {
            let mut out = Vec::new();
            for part in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                out.push(address_from_hex(part).map_err(|e| e.to_string())?);
            }
            out
        }
        None => Vec::new(),
    };
    let per_tx = args.num("per-tx", 0)?;
    let window = args.num("window", 100)?;
    let cumulative = args.num("cumulative", 0)?;
    if per_tx == 0 {
        return Err("--per-tx <sat> is required".into());
    }
    if cumulative == 0 {
        return Err("--cumulative <sat> is required".into());
    }
    let expires = args.num("expires", 0)?;
    let expires_at_height = if expires == 0 {
        chain.height() + 1_000_000
    } else {
        expires
    };

    let policy = SpendPolicy {
        version: srct_core::agent::POLICY_VERSION,
        network_id,
        agent_id,
        owner,
        role,
        per_tx_max_sat: per_tx,
        window_blocks: window,
        cumulative_max_sat: cumulative,
        allowed_recipients: recipients,
        allowed_services: Vec::new(),
        not_before_height: 0,
        expires_at_height,
        revoked: false,
        parent_agent_id: parent,
    };
    policy
        .validate()
        .map_err(|e| format!("grant refused: {e}"))?;

    let payload =
        PolicyPayload::build_from_policy(&wallet, &policy, spender).map_err(|e| e.to_string())?;
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    let l2 = l2_state_of(&store, &chain)?;
    let height = mine_l2_tx(&mut store, &mut chain, &l2, owner, tx)?;
    println!("height      {height}");
    println!("policy      {}", hash_to_hex(&policy.hash()));
    println!("agent       {}", address_to_hex(&agent_id));
    println!("spender     {}", address_to_hex(&spender));
    println!("per-tx      {}", srct(per_tx));
    println!("cumulative  {}", srct(cumulative));
    println!("window      {window} blocks");
    Ok(())
}

/// `srct-node agent-spend` — spend under a published grant (SPEC.md §21).
fn cmd_agent_spend(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let mut chain = store.load_chain()?;
    let (wallet, agent) = acting_wallet(args, &store)?;

    let policy_hash = hash_from_hex(args.str("policy").ok_or("--policy <hash> is required")?)
        .map_err(|e| e.to_string())?;
    let to = address_from_hex(args.str("to").ok_or("--to <address> is required")?)
        .map_err(|e| e.to_string())?;
    let amount_sat = if let Some(sat) = args.str("amount-sat") {
        sat.parse::<u64>()
            .map_err(|_| "--amount-sat must be a number")?
    } else {
        match args.srct("amount")? {
            Some(sat) => sat,
            None => return Err("--amount is required".into()),
        }
    };
    if amount_sat == 0 {
        return Err("--amount must be greater than zero".into());
    }
    let nonce = args.num("nonce", 0)?;

    let payload = AgentSpendPayload::build(&wallet, policy_hash, nonce, to, amount_sat, None)
        .map_err(|e| e.to_string())?;
    let tx = L2Transaction::new(L2Payload::AgentSpend(payload));
    let l2 = l2_state_of(&store, &chain)?;
    let height = mine_l2_tx(&mut store, &mut chain, &l2, agent, tx)?;
    println!("height  {height}");
    println!(
        "spent   {} SRCT to {}",
        srct(amount_sat),
        address_to_hex(&to)
    );
    println!("policy  {}", hash_to_hex(&policy_hash));
    Ok(())
}

/// `srct-node credit` — open, repay or default a credit position (SPEC.md §22).
fn cmd_credit(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let mut chain = store.load_chain()?;
    let (wallet, actor) = acting_wallet(args, &store)?;

    if args.has("list") {
        let l2 = l2_state_of(&store, &chain)?;
        let state = l2.state();
        let positions = state.credit_positions();
        if positions.is_empty() {
            println!("no credit positions");
        }
        for p in positions {
            println!(
                "{}  lender {}  borrower {}  principal {}  outstanding {}  collateral {}  state {:?}",
                hash_to_hex(&p.id),
                address_to_hex(&p.lender),
                address_to_hex(&p.borrower),
                srct(p.principal_sat),
                srct(p.outstanding_sat),
                srct(p.collateral_sat),
                p.state,
            );
        }
        return Ok(());
    }

    if args.has("default") {
        let position_id = hash_from_hex(
            args.str("position")
                .ok_or("--position <hash> is required")?,
        )
        .map_err(|e| e.to_string())?;
        let payload =
            CreditDefaultPayload::build(&wallet, position_id).map_err(|e| e.to_string())?;
        let tx = L2Transaction::new(L2Payload::CreditDefault(payload));
        let l2 = l2_state_of(&store, &chain)?;
        let height = mine_l2_tx(&mut store, &mut chain, &l2, actor, tx)?;
        println!("height    {height}");
        println!("defaulted position {}", hash_to_hex(&position_id));
        return Ok(());
    }

    if args.has("repay") {
        let position_id = hash_from_hex(
            args.str("position")
                .ok_or("--position <hash> is required")?,
        )
        .map_err(|e| e.to_string())?;
        let amount_sat = if let Some(sat) = args.str("amount-sat") {
            sat.parse::<u64>()
                .map_err(|_| "--amount-sat must be a number")?
        } else {
            match args.srct("amount")? {
                Some(sat) => sat,
                None => return Err("--amount is required".into()),
            }
        };
        let payload = CreditRepayPayload::build(&wallet, position_id, amount_sat)
            .map_err(|e| e.to_string())?;
        let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
        let l2 = l2_state_of(&store, &chain)?;
        let height = mine_l2_tx(&mut store, &mut chain, &l2, actor, tx)?;
        println!("height  {height}");
        println!("repaid  {} SRCT", srct(amount_sat));
        println!("position {}", hash_to_hex(&position_id));
        return Ok(());
    }

    // Open.
    let borrower = address_from_hex(args.str("to").ok_or("--to <address> is required")?)
        .map_err(|e| e.to_string())?;
    let amount_sat = if let Some(sat) = args.str("amount-sat") {
        sat.parse::<u64>()
            .map_err(|_| "--amount-sat must be a number")?
    } else {
        match args.srct("amount")? {
            Some(sat) => sat,
            None => return Err("--amount is required".into()),
        }
    };
    let collateral_sat = match args.str("collateral") {
        Some(sat) => sat
            .parse::<u64>()
            .map_err(|_| "--collateral must be a number")?,
        None => amount_sat,
    };
    let rate_bps = args.num("rate-bps", 100)? as u32;
    let window = args.num("window", 100)?;
    let deadline = args.num("deadline", chain.height() + 100_000)?;
    let nonce = args.num("nonce", 0)?;

    let payload = CreditOpenPayload::build(
        &wallet,
        borrower,
        amount_sat,
        collateral_sat,
        rate_bps,
        window,
        deadline,
        nonce,
    )
    .map_err(|e| e.to_string())?;
    let position_id = payload.derived_position_id();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    let l2 = l2_state_of(&store, &chain)?;
    let height = mine_l2_tx(&mut store, &mut chain, &l2, actor, tx)?;
    println!("height     {height}");
    println!("position   {}", hash_to_hex(&position_id));
    println!("borrower   {}", address_to_hex(&borrower));
    println!("principal  {} SRCT", srct(amount_sat));
    println!("collateral {} SRCT", srct(collateral_sat));
    Ok(())
}

/// `srct-node l2` — the Layer-2 deposit address and balance helpers.
///
/// A deposit is an ordinary Layer-1 payment to the profile's sink address; the
/// node credits it once the transaction is final.
fn cmd_l2(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;

    if args.has("deposit-address") {
        println!("{}", address_to_hex(&store.params.l2_deposit_sink()));
        println!();
        println!("deposit with: srct-node send --to <address> --amount <srct>");
        println!("the credit appears after the transaction is final");
        return Ok(());
    }

    let l2 = l2_state_of(&store, &chain)?;
    let state = l2.state();
    println!("height        {}", l2.height());
    println!("accounts      {}", state.total_accounts());
    println!("locked        {}", state.total_locked());
    println!("deposits      {}", state.deposited_total());
    println!("exited        {}", state.exited_total());
    println!("burned        {}", state.total_burned());
    println!("pscb          {}", state.pscb);
    println!("applied       {}", state.applied_count());
    println!("conserved     {}", state.check_conservation());
    Ok(())
}

/// Parse a 20-byte agent id from hex.
///
/// Accepts the `jt1` display form as well as raw hex, because that is how
/// the id is printed everywhere else - a caller should be able to copy it
/// straight out of `policy --list`.
fn decode_agent_id(s: &str) -> Result<AgentId, String> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("jt1");
    let bytes = hex::decode(raw).map_err(|e| format!("agent id hex: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("an agent id is 20 bytes, got {}", bytes.len()));
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn cmd_status(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let report = chain.supply_report();
    let tip = chain.tip();

    println!("network        {}", store.params.name);
    println!("height         {}", chain.height());
    println!("finalized      {}", chain.finalized_height());
    println!("tip            {}", hash512_to_hex(&chain.tip_hash()));
    println!("difficulty     {}", tip.header.difficulty);
    println!("base fee       {} sat", tip.header.base_fee_sat);
    println!(
        "halving        {} (next in {} blocks)",
        halvings(&store.params, tip.header.height),
        store.params.halving_period - (tip.header.height % store.params.halving_period)
    );
    println!(
        "block reward   {} SRCT",
        srct(block_reward_sat(&store.params, tip.header.height + 1))
    );
    println!(
        "puzzle         {} (id {})",
        chain
            .registry()
            .get_opt(tip.header.puzzle_id)
            .map(|p| p.name.clone())
            .unwrap_or_default(),
        tip.header.puzzle_id
    );
    println!();
    println!("live supply    {} SRCT", srct(report.live_sat));
    println!(
        "issued to {}  {} SRCT",
        report.height,
        srct(cumulative_supply_sat(&store.params, report.height))
    );
    println!("reachable max  {} SRCT", srct(report.reachable_sat));
    if report.rate_allowance_sat == u64::MAX {
        println!("rate anchor    ladder era (grandfathered, bounded by the rungs)");
    } else {
        println!(
            "rate anchor    {} SRCT max per halving period (1% of issued)",
            srct(report.rate_allowance_sat)
        );
    }
    println!(
        "removed        {} SRCT (base fees burned + PSCB + B-Saver, all usage ever)",
        srct(report.removed_sat)
    );
    println!(
        "bsaver         {} SRCT (5% of fee PSCB leg, floor reserve)",
        srct(chain.bsaver_reserve())
    );
    println!(
        "net supply     {} SRCT (issued minus removed)",
        srct(report.net_supply_sat)
    );

    // L2 is derived from the stored chain, so `status` reconstructs it the
    // same way a restart does: replay, no persisted L2 state to go stale.
    let l2 = NodeL2::replay_from(&chain, &store.params).map_err(|e| e.to_string())?;
    let ls = l2.status(chain.height());
    println!();
    println!(
        "l2 height      {} (chain {})",
        ls.l2_height, ls.chain_height
    );
    println!("l2 applied     {}", ls.applied);
    println!("l2 skipped     {}", ls.skipped);
    if !ls.clean {
        println!("l2 replay      not clean (run verify for the named refusals)");
    }
    println!(
        "l2 deposits    {} credited ({} sat) / {} pending / {} ignored",
        ls.deposits_applied, ls.deposited_sat, ls.deposits_pending, ls.deposits_ignored
    );
    println!(
        "l2 exits       {} queued / {} sat released to L1",
        ls.pending_exits, ls.exited_sat
    );

    let wallets = store.load_wallets()?;
    if !wallets.is_empty() {
        println!();
        for w in &wallets {
            let addr = w.address().map_err(|e| e.to_string())?;
            let outputs = chain.utxo().outputs_for_address(&addr);
            let total: u64 = outputs
                .iter()
                .fold(0u64, |acc, (_, v)| acc.saturating_add(*v));
            // `is_mature` is the rule the mempool admission uses (a spend
            // lands in the next block, at `height() + 1`), so the report
            // matches what the API would actually accept — a plain
            // `<= chain.height()` understates by one block.
            let mature: u64 = chain
                .utxo()
                .iter()
                .filter(|(_, u)| u.out.address == addr)
                .filter(|(_, u)| chain.is_mature(u.height))
                .fold(0u64, |acc, (_, u)| acc.saturating_add(u.out.value));
            println!(
                "wallet {:<10} {}  balance {} SRCT ({} spendable)",
                w.label,
                address_to_hex(&addr),
                srct(total),
                srct(mature)
            );
        }
    }
    Ok(())
}

fn cmd_verify(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    chain.verify_canonical_chain().map_err(|e| e.to_string())?;
    println!(
        "ok: replayed {} block(s) from genesis, UTXO and supply match",
        chain.height() + 1
    );
    // L2 determinism: two independent replays of the same stored blocks must
    // hold equal state, and the incremental following-the-tip path must agree
    // with full replay. Equality is total (`L2State` derives `PartialEq` over
    // all fields), so this is agreement on every L2 fact, not a summary.
    let params = store.params.clone();
    let a = NodeL2::replay_from(&chain, &params).map_err(|e| e.to_string())?;
    let b = NodeL2::replay_from(&chain, &params).map_err(|e| e.to_string())?;
    if a.state() != b.state() || a.skipped() != b.skipped() {
        return Err("l2 replay diverged: two replays of the same chain disagree".into());
    }
    let mut inc = NodeL2::fresh(&params).map_err(|e| e.to_string())?;
    inc.sync(&chain).map_err(|e| e.to_string())?;
    if inc.state() != a.state()
        || inc.applied_count() != a.applied_count()
        || inc.skipped() != a.skipped()
    {
        return Err(
            "l2 replay diverged: incremental application disagrees with full replay".into(),
        );
    }
    println!(
        "ok: l2 replay deterministic to height {} (applied {}, skipped {})",
        a.height(),
        a.applied_count(),
        a.skipped().len()
    );
    // Joint conservation (Decisions 7 and 10, SPEC.md §19.4–§19.5): L2 holds
    // at most genesis plus matured deposits, and L1 live supply plus
    // everything L2 ever held, minus what sits identifiably in the deposit
    // sink, stays under the joint bound — the issuance integral at the tip
    // plus the escrow ceiling (approved M-E). The stock cap is gone entirely
    // (Decision 18): the rate anchor bounds issuance, so there is no sanity
    // ceiling term to report here. The sink term is the M3 correction: sink
    // outputs remain in the L1 UTXO set (unspendable) while their twins live
    // in L2, so counting both sides without subtracting the sink would cry
    // inflation on every deposit. Burns anywhere move the sum down, never up —
    // either check failing means value was created, which must never print
    // "ok".
    // The three conservation checks now live in one tested place; this command
    // only reports the terms it returns.
    let supply =
        srct_node::conservation::verify_conservation(&chain, &a).map_err(|e| e.to_string())?;
    println!(
        "ok: joint supply conserved (l1 live {} + l2 held {} - sink {} = {} sat of {} bound)\n    bound = l1 issuance integral {} + escrow ceiling {}",
        supply.l1_live_sat,
        supply.l2_held_sat,
        supply.sink_held_sat,
        supply.joint_sat,
        supply.bound_sat(),
        supply.l1_bound_sat,
        supply.escrow_ceiling_sat,
    );
    for s in a.skipped().iter().take(10) {
        println!(
            "  skipped height {:>6}  {}  {}",
            s.height,
            &hash512_to_hex(&s.txid)[..16],
            s.error
        );
    }
    if a.skipped().len() > 10 {
        println!("  ... and {} more", a.skipped().len() - 10);
    }
    for p in a.pending_deposits().iter().take(10) {
        println!(
            "  pending height {:>6}  {}:{}  {} sat (spendable at {})",
            p.deposit.height,
            &hash512_to_hex(&p.deposit.txid)[..16],
            p.deposit.index,
            p.deposit.amount_sat,
            p.matures_at
        );
    }
    if a.pending_deposits().len() > 10 {
        println!("  ... and {} more", a.pending_deposits().len() - 10);
    }
    for ig in a.ignored_deposits().iter().take(10) {
        println!(
            "  ignored height {:>6}  {}:{}  {} sat ({:?})",
            ig.height,
            &hash512_to_hex(&ig.txid)[..16],
            ig.index,
            ig.amount_sat,
            ig.reason
        );
    }
    if a.ignored_deposits().len() > 10 {
        println!("  ... and {} more", a.ignored_deposits().len() - 10);
    }
    Ok(())
}

fn cmd_show_block(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let height = args.num("height", chain.height())?;
    let block = chain
        .block_at(height)
        .ok_or_else(|| format!("no block at height {height}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(block).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn cmd_balance(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let addr = address_from_hex(
        args.str("address")
            .ok_or("--address <jt1...> is required")?,
    )
    .map_err(|e| e.to_string())?;
    let mut total = 0u64;
    let mut mature_total = 0u64;
    let maturity = store.params.coinbase_maturity;
    let next_height = chain.height() + 1;
    for (op, u) in chain.utxo().iter() {
        if u.out.address != addr {
            continue;
        }
        let mature = u.height + maturity <= next_height;
        if mature {
            mature_total += u.out.value;
        }
        total += u.out.value;
        println!(
            "{}:{}  {:>16} SRCT  height {:>6}  {}",
            &hash512_to_hex(&op.txid)[..16],
            op.index,
            srct(u.out.value),
            u.height,
            if mature { "spendable" } else { "immature" }
        );
    }
    if total == 0 {
        println!("no unspent outputs for {}", address_to_hex(&addr));
        return Ok(());
    }
    println!(
        "total {} SRCT, of which {} SRCT spendable",
        srct(total),
        srct(mature_total)
    );
    Ok(())
}

/// Every validator key in the data dir, as one committee.
///
/// `Ok(None)` when the directory holds no key files — the ordinary non-validating
/// node, which verifies and relays checkpoints and signs nothing. A file that
/// fails to load is an error, not a skip: an operator who placed a key file
/// expects it to be used, and silently ignoring it would leave them believing
/// they were validating.
fn load_validator_committee(
    store: &Store,
    params: &NetworkParams,
) -> Result<Option<srct_core::signing::Committee>, String> {
    let dir = store.validator_keys_path();
    if !dir.exists() {
        return Ok(None);
    }
    let mut committee = srct_core::signing::Committee::new();
    for entry in fs::read_dir(&dir).map_err(|e| format!("validators dir: {e}"))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let bytes = if wallet_store::is_encrypted(&bytes) {
            let passphrase = validator_passphrase().ok_or_else(|| {
                format!(
                    "{} is encrypted; set {} (or {}) to read it",
                    path.display(),
                    VALIDATOR_PASSPHRASE_ENV,
                    wallet_store::PASSPHRASE_ENV
                )
            })?;
            wallet_store::decrypt(&passphrase, &bytes)
                .map_err(|e| format!("{}: {e}", path.display()))?
        } else {
            // Loud on every load, not just the first: a plaintext key file
            // is the exposure `validator add` now refuses to create.
            eprintln!(
                "warning: {} holds an unencrypted validator key; set {} (or {}) and re-add it to encrypt it",
                path.display(),
                VALIDATOR_PASSPHRASE_ENV,
                wallet_store::PASSPHRASE_ENV
            );
            zeroize::Zeroizing::new(bytes)
        };
        let key = srct_core::signing::ValidatorKey::from_bytes(&bytes, &params.network_id)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        committee.add(key).map_err(|e| e.to_string())?;
    }
    if committee.is_empty() {
        return Ok(None);
    }
    Ok(Some(committee))
}

/// `validator` — manage this node's checkpoint-signing keys (M5).
///
/// Keys live in `<data-dir>/validators/*.json`, one file per validator, and are
/// separate from `wallets.json` by design: a wallet holds funds this node spends,
/// a validator key signs consensus messages. Mixing them would make a wallet
/// backup a validator key backup, which is a different risk entirely.
///
/// A new key is written encrypted under `SRCT_VALIDATOR_PASSPHRASE` (falling back
/// to `SRCT_WALLET_PASSPHRASE`) with Argon2id + ChaCha20-Poly1305, mode 0600
/// where the platform supports it, because the file *is* the key — creation
/// without a passphrase is refused rather than writing plaintext.
/// `validator --bootstrap` writes the 21 declared mainnet bootstrap keys, which
/// a fresh chain needs locally to reach quorum before any bond exists.
/// `validator list` prints public keys only.
fn cmd_validator(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
    let params = store.params.clone();
    let dir = store.validator_keys_path();

    if args.has("bootstrap") {
        if args.has("add") {
            return Err("`validator --bootstrap` and `--add` are mutually exclusive".into());
        }
        if params.name != "mainnet" {
            return Err(format!(
                "`validator --bootstrap` is mainnet-only; {} has its own declared test keys",
                params.name
            ));
        }
        let Some(passphrase) = validator_passphrase() else {
            return Err(format!(
                "refusing to write unencrypted validator keys: set {} and retry",
                VALIDATOR_PASSPHRASE_ENV
            ));
        };
        // Public cold-start keys over a live committee is a slash-by-replay
        // kit: refuse unless the directory holds no committee keys yet.
        let existing = std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
                    .count()
            })
            .unwrap_or(0);
        if existing > 0 {
            return Err(format!(
                "`validator --bootstrap` refuses a non-empty committee directory ({} key file(s) in {}): \
                 merge or clear it by hand instead of letting bootstrap silently coexist with a live committee",
                existing,
                dir.display()
            ));
        }
        for (index, secret) in srct_core::params::mainnet_committee_secrets()
            .into_iter()
            .enumerate()
        {
            let label = format!("bootstrap-{:02}", index + 1);
            let key = srct_core::signing::ValidatorKey::new(secret, params.network_id.clone());
            write_validator_key(&dir, &label, &key, &passphrase)?;
        }
        println!(
            "created 21 mainnet bootstrap validator keys in {}",
            dir.display()
        );
        println!("  quorum     15 of 21");
        println!("  warning    public cold-start keys: deterministic in source, so anyone");
        println!("             can sign alongside you until the first bond rotates authority.");
        println!("             `serve` on mainnet refuses these keys unless you pass");
        println!("             --allow-bootstrap-committee; replace them with bonded keys.");
        return Ok(());
    }

    if !args.has("add") {
        // List: public keys only, never scalars, never the file contents.
        match load_validator_committee(&store, &params)? {
            Some(c) => {
                for pk in c.public_keys() {
                    println!("{}", hex::encode(pk.as_bytes()));
                }
                println!("{} validator(s)", c.len());
            }
            None => {
                println!("no validator keys in {}", dir.display());
            }
        }
        return Ok(());
    }

    let label = args.str_or("label", "validator");
    // The label becomes a filename (`validators/<label>.json`): allowlist it
    // so `--label ../x`, `C:\x`, control characters and `.`/`..` cannot place
    // a key file outside the validators directory. Blocklist checks miss
    // dotfiles and unicode separators; the allowlist cannot.
    if label.is_empty()
        || label.len() > 64
        || !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        || label == "."
        || label == ".."
    {
        return Err(format!(
            "invalid label `{label}`: letters, digits, dot, dash and underscore only"
        ));
    }
    // OS entropy, harvested here rather than inside `srct-core`, so the consensus
    // library stays free of any way to reach for randomness.
    // OS entropy, harvested here rather than inside srct-core, so the consensus
    // library stays free of any way to reach for randomness.
    // The seed wipes on drop; it must not linger after the key is derived.
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed[..]);
    let sk = srct_core::bls::SecretKey::derive(&seed).map_err(|e| e.to_string())?;
    let key = srct_core::signing::ValidatorKey::new(sk, params.network_id.clone());
    // New keys are never written plaintext: without a passphrase there is no
    // key to encrypt under, so creation is refused rather than writing a
    // 0600 JSON scalar. Existing plaintext keys still load (with a loud
    // warning at load time), so this refuses new exposure without locking
    // operators out of keys they already hold.
    let Some(passphrase) = validator_passphrase() else {
        return Err(format!(
            "refusing to write an unencrypted validator key: set {} and retry",
            VALIDATOR_PASSPHRASE_ENV
        ));
    };
    let path = write_validator_key(&dir, &label, &key, &passphrase)?;

    println!("created validator `{label}`");
    println!("  file       {}", path.display());
    println!("  network    {}", params.network_id);
    println!("  public key {}", hex::encode(key.public_key().as_bytes()));
    println!("  committee  public key must be bonded on chain before its signature counts");
    Ok(())
}

/// Encrypt one validator key and write it as `validators/<label>.json`.
///
/// `create_new` refuses to overwrite an existing key file: a silent replace
/// would orphan the public key an operator may already have bonded.
fn write_validator_key(
    dir: &Path,
    label: &str,
    key: &srct_core::signing::ValidatorKey,
    passphrase: &str,
) -> Result<PathBuf, String> {
    let file = key.to_file();
    let bytes =
        zeroize::Zeroizing::new(serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?);
    let bytes = wallet_store::encrypt(passphrase, &bytes)
        .map_err(|e| format!("validator key encryption: {e}"))?;

    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(format!("{label}.json"));
    // `create_new` refuses to overwrite an existing key file: a silent replace
    // would orphan the public key an operator may already have bonded. Check
    // first so the error names the conflict rather than an OS open failure.
    if path.exists() {
        return Err(format!(
            "{}: refusing to overwrite an existing validator key",
            path.display()
        ));
    }
    // Same atomic 0600 write the wallet file gets: temp + fsync + rename, so
    // a torn validator key is impossible the same way a torn wallet is.
    crate::wallet_store::write_private(&path, &bytes)?;
    Ok(path)
}

/// Passphrase validator keys are encrypted under: `SRCT_VALIDATOR_PASSPHRASE`,
/// falling back to `SRCT_WALLET_PASSPHRASE` with a one-time warning. Returned
/// `Zeroizing`, so the parsed copy wipes on drop.
///
/// The variables are separate on purpose: one passphrase for a wallet and for
/// consensus-signing keys means one compromise opens both, and an operator
/// who reuses one has usually not thought about it. The fallback exists for
/// the existing deployments that set only the wallet variable — a new key
/// can be re-added under the dedicated one, and a shared passphrase is
/// reported rather than silently accepted.
fn validator_passphrase() -> Option<zeroize::Zeroizing<String>> {
    if let Some(p) = std::env::var(VALIDATOR_PASSPHRASE_ENV)
        .ok()
        .filter(|p| !p.is_empty())
    {
        return Some(zeroize::Zeroizing::new(p));
    }
    use std::sync::OnceLock;
    static WARNED: OnceLock<()> = OnceLock::new();
    if let Some(p) = wallet_store::passphrase_from_env() {
        if WARNED.set(()).is_ok() {
            eprintln!(
                "warning: validator keys are using {}; set {} to give validator keys their own passphrase",
                wallet_store::PASSPHRASE_ENV,
                VALIDATOR_PASSPHRASE_ENV
            );
        }
        return Some(p);
    }
    None
}

/// Environment variable carrying the validator-key passphrase.
const VALIDATOR_PASSPHRASE_ENV: &str = "SRCT_VALIDATOR_PASSPHRASE";

fn cmd_wallet(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
    let mut wallets = store.load_wallets()?;
    if !args.has("new") {
        if wallets.is_empty() {
            println!("no wallets");
            return Ok(());
        }
        for w in &wallets {
            println!(
                "{:<12} {}",
                w.label,
                address_to_hex(&w.address().map_err(|e| e.to_string())?)
            );
        }
        return Ok(());
    }
    let label = args.str_or("label", &format!("w{}", wallets.len()));
    // Duplicate labels shadow: `acting_wallet`/`cmd_send`/`cmd_mine` resolve
    // by first match, so a second wallet under the same label is unreachable
    // and its funds look lost through the CLI. Refuse rather than shadow.
    if wallets.iter().any(|w| w.label == label) {
        return Err(format!("a wallet named `{label}` already exists"));
    }
    let w = Wallet::new_random(&label);
    println!("created `{}`", w.label);
    println!(
        "  address  {}",
        address_to_hex(&w.address().map_err(|e| e.to_string())?)
    );
    println!(
        "  pubkey   {}",
        w.public_key_hex().map_err(|e| e.to_string())?
    );
    wallets.push(w);
    store.save_wallets(&wallets)
}

fn cmd_export(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let out = PathBuf::from(args.str_or("out", "chain.json"));
    let mut blocks = Vec::new();
    for h in 0..=chain.height() {
        if let Some(b) = chain.block_at(h) {
            blocks.push(b.clone());
        }
    }
    fs::write(
        &out,
        serde_json::to_string_pretty(&blocks).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("wrote {} block(s) to {}", blocks.len(), out.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// serve — P2P node run loop (§13.1 chain-thread model)
// ---------------------------------------------------------------------------

fn cmd_serve(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let wallets = store.load_wallets()?;

    let listen_addr: Option<std::net::SocketAddr> = args
        .str("listen")
        .map(|s| s.parse().map_err(|e| format!("--listen: {e}")))
        .transpose()?;

    let connect_peers: Vec<std::net::SocketAddr> = args
        .str("connect")
        .map(|s| {
            s.split(',')
                .map(|a| {
                    a.trim()
                        .parse()
                        .map_err(|e| format!("--connect `{a}`: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let max_peers = args.num("peers", 125)? as usize;
    // A relay-only node: it validates, relays and syncs, but does not mine.
    let no_mine = args.has("no-mine");
    // Parse bootnode addresses (§13.6: v0.2 has no ADDR gossip, so bootnodes
    // plus the address book are the only peer source).
    let bootnodes: Vec<std::net::SocketAddr> = args
        .str("bootnodes")
        .map(|s| {
            s.split(',')
                .map(|a| {
                    a.trim()
                        .parse()
                        .map_err(|e| format!("--bootnodes `{a}`: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let mut config = P2pConfig::new(store.params.clone(), listen_addr);
    config.max_peers = max_peers;
    config.bootnodes = bootnodes.clone();
    // Persist known peer addresses to peers.json in the data directory, so
    // a restart can reconnect to peers the node learned. Reuses the store's
    // atomic-write pattern (write beside → fsync → rename → 0600).
    config.address_book = Some(store.dir.join("peers.json"));
    // Loop period. Without one the loop mined as fast as the CPU allowed and
    // rewrote the whole chain file each time (SPEC.md §13.10 item 4).
    let interval_ms = args.num("interval", 250)?;

    // Opt-in service API (Decision 9): absent unless --api-listen is given,
    // so the default `serve` is exactly the P2P node it always was.
    let api_listen: Option<std::net::SocketAddr> = args
        .str("api-listen")
        .map(|s| s.parse().map_err(|e| format!("--api-listen: {e}")))
        .transpose()?;
    // A non-loopback API bind requires auth (§19.2). The token comes from
    // `--api-token` or, failing that, the `SRCT_API_TOKEN` env var; prefer the
    // env var, because a flag value is visible to other local users in `ps`.
    // Either is left unset for a loopback bind, which stays unauthenticated
    // by design.
    // The flag is accepted, and reported on: argv is world-readable through
    // `/proc` and `ps`, so a token there is a token every local account knows.
    // The environment of a started process is not, which is why the env var is
    // the recommended path and the flag is not removed (an operator who has
    // already decided to accept the risk should not be blocked).
    if args.str("api-token").is_some() {
        eprintln!(
            "warning: --api-token is visible in the process list; use the \
             SRCT_API_TOKEN environment variable instead"
        );
    }
    let api_token: Option<String> = args
        .str("api-token")
        .map(str::to_owned)
        .or_else(|| std::env::var("SRCT_API_TOKEN").ok())
        .filter(|t| !t.is_empty());
    // Hostnames the Host-header check accepts on a non-loopback bind, beyond
    // the bound address and any IP literal. Comma-separated in both places;
    // flag and env merge, so one cannot silently clear the other.
    fn split_hosts(raw: &str) -> Vec<String> {
        raw.split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }
    let mut api_allowed_hosts: Vec<String> = std::env::var("SRCT_API_ALLOWED_HOSTS")
        .map(|s| split_hosts(&s))
        .unwrap_or_default();
    if let Some(flag) = args.str("api-allowed-host") {
        api_allowed_hosts.extend(split_hosts(flag));
    }

    // Trusted credit issuers for POST /v1/credit/mint: comma-separated
    // 48-byte hex BLS public keys. Absent = no issuer = every mint refused
    // (fail-closed); credit backing is configured, never assumed.
    let mut credit_issuers: Vec<srct_core::bls_checkpoint::BlsPublicKey> = Vec::new();
    for part in args.str_or("credit-issuer", "").split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let raw = hex::decode(part).map_err(|e| format!("--credit-issuer: {e}"))?;
        let mut key = [0u8; 48];
        if raw.len() != 48 {
            return Err(format!(
                "--credit-issuer: each key must be 48 bytes, got {}",
                raw.len()
            ));
        }
        key.copy_from_slice(&raw);
        credit_issuers.push(srct_core::bls_checkpoint::BlsPublicKey(key));
    }

    // Capture address book path before config is moved into P2pNode::start.
    let has_address_book = config.address_book.is_some();

    let node =
        P2pNode::start(config, chain.height(), chain.tip_hash()).map_err(|e| e.to_string())?;

    let mut syncer = SyncManager::new();
    // The mempool is in-memory only: a restart begins with an empty pool
    // (see `docs/status.md`).
    let mut relay = RelayManager::new();
    let mut pool_cursor = chain.height();
    let mut relay_seen = (0u64, 0u64);
    // Validator signing (M5). Empty when no key files are loaded, which is the
    // normal case for a non-validating node — it verifies and relays what others
    // produce and signs nothing.
    let validator_committee = load_validator_committee(&store, &store.params.clone())?;
    // Cold-start bootstrap keys are public by construction (deterministic in
    // source): anyone holding them can sign finality until the first bond
    // rotates authority. Serving mainnet as a bootstrap-key validator is
    // therefore an explicit, revocable operator decision — never the default
    // that a fresh `validator --bootstrap` silently becomes.
    if store.params.name == "mainnet" {
        if let Some(committee) = &validator_committee {
            let mut loaded = committee.public_keys();
            loaded.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            let mut bootstrap: Vec<_> = (1u8..=21)
                .map(srct_core::params::mainnet_validator_key)
                .collect();
            bootstrap.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            if loaded == bootstrap && !args.has("allow-bootstrap-committee") {
                return Err(
                    "refusing to serve mainnet as a bootstrap-key validator: these 21 keys \
                     are public (deterministic in source), so anyone can sign finality alongside \
                     you until the first bond rotates authority. Replace them with bonded keys, \
                     or pass --allow-bootstrap-committee to accept the risk explicitly"
                        .into(),
                );
            }
        }
    }
    let mut signed_epochs = std::collections::BTreeSet::new();
    let mut finality_keys_missing_warning =
        validator_committee.is_none() && store.params.finality_activation_height > 0;
    // Fraud arbitration (Decision 21): inbound votes, tallied per dispute. Not
    // persisted — see `srct_node::mediation` for why losing it costs only the
    // ability to *propose*, never the ability to verify or relay.
    let mut votes = srct_core::arbitration::VoteBook::new();
    // L2 follows the tip by replay; nothing L2 is persisted.
    let l2 = NodeL2::replay_from(&chain, &store.params).map_err(|e| e.to_string())?;
    let mut l2_skipped_seen = l2.skipped().len();

    println!("network        {}", store.params.name);
    println!("height         {}", chain.height());
    println!("tip            {}", hash512_to_hex(&chain.tip_hash()));
    if let Some(addr) = listen_addr {
        println!("listening      {addr}");
    }
    if !bootnodes.is_empty() {
        let list = bootnodes
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("bootnodes      {list}");
    }
    if has_address_book {
        println!("address book   {}", store.dir.join("peers.json").display());
    }

    // Everything mutable now lives behind one lock shared with the API
    // thread: the serve loop takes it once per iteration, handlers take it
    // per request, and no handler holds it across an await (they do not
    // await). The P2P node, the store and the relay cursors stay loop-local:
    // the API must not reach the network or the disk on its own.
    let peers = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Mutex::new(srct_node::api::SharedNode::new(chain, l2)));

    // Node-local books: receipts, replay tracker, payments, reservations,
    // policy accounting, credit, delegations, issued policies, revocations.
    // They are not consensus state - the chain is durable and L2 replays
    // from it - but they exist only in this process, so they load here,
    // before the API starts, and a corrupt file refuses to start instead of
    // silently serving an empty book (fail-closed).
    let state_file = StateFile::new(store.dir.join("state.bin"));
    if let Some(bytes) = state_file
        .load()
        .map_err(|e| format!("node state failed to load: {e}"))?
    {
        let mut sh = shared
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        sh.decode_state(&bytes)
            .map_err(|e| format!("node state failed to decode: {e}"))?;
        println!("state          {}", store.dir.join("state.bin").display());
    }
    if let Some(api_addr) = api_listen {
        let bound = srct_node::api::spawn_with_options(
            Arc::clone(&shared),
            Arc::clone(&peers),
            api_addr,
            api_token.clone(),
            api_allowed_hosts,
            credit_issuers,
        )?;
        println!("api            {bound}");
    }

    // Dial configured outbound peers: --bootnodes first, then --connect.
    for addr in &bootnodes {
        let dialed = {
            let sh = shared
                .lock()
                .map_err(|_| "state lock poisoned".to_string())?;
            node.connect(*addr, &sh.chain)
        };
        match dialed {
            Ok(id) => println!("connected peer {id} -> {addr} (bootnode)"),
            Err(e) => eprintln!("warn: bootnode connect {addr}: {e}"),
        }
    }
    for addr in &connect_peers {
        let dialed = {
            let sh = shared
                .lock()
                .map_err(|_| "state lock poisoned".to_string())?;
            node.connect(*addr, &sh.chain)
        };
        match dialed {
            Ok(id) => println!("connected peer {id} -> {addr}"),
            Err(e) => eprintln!("warn: connect {addr}: {e}"),
        }
    }

    // Pick miner address if a wallet exists. `--no-mine` keeps the wallet —
    // it is still the address the node reports balances for.
    let miner_addr = if no_mine {
        None
    } else {
        wallets.first().and_then(|w| w.address().ok())
    };

    println!("press Ctrl-C to stop");

    // Graceful shutdown: an atomic flag set by the Ctrl-C / SIGTERM handler so
    // the serve loop can flush its store and stop the P2P node cleanly instead
    // of being killed mid-write. `P2pNode::stop` and `BlockStore` flushes run
    // in the Drop handlers that fire after the loop breaks.
    let running = Arc::new(AtomicBool::new(true));
    {
        let flag = Arc::clone(&running);
        ctrlc::set_handler(move || {
            flag.store(false, Ordering::SeqCst);
        })
        .expect("only one Ctrl-C handler can be registered per process");
    }

    // Decision 17's alarm half. The state machine (and its rate limit, which
    // exists because this loop can spin with `--interval-ms 0`) lives in
    // `conservation::BreachAlarm` so its timing rule is unit-testable; see the
    // poll below.
    let mut breach_alarm = srct_node::conservation::BreachAlarm::new();

    // Node books flush on this schedule: at most once every 5s, and only
    // when their bytes changed, so an idle node never rewrites the file.
    // The final flush runs after the loop, in the shutdown block.
    let mut last_state_save = std::time::Instant::now();
    let mut last_state_blob: Option<Vec<u8>> = None;
    // Chain/meta persist retry flag: a failed save must be retried even if
    // no new block arrives (the batch gate below keys off height change),
    // and a freshly mined block must not be relayed until it has survived
    // to disk — peers building on a block we cannot restart from opens
    // the confirmed-effects-lost window the retry paths would then fill
    // with replacements.
    let mut persist_dirty = false;

    // Chain thread: mine + relay loop
    while running.load(Ordering::SeqCst) {
        // Bind through one `&mut` so the loop's field accesses are disjoint
        // borrows of the shared state rather than repeated reborrows of the
        // guard (which the borrow checker rejects for `chain` + `pool`).
        let mut guard = shared
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        let sh = &mut *guard;

        // What the API accepted since the last iteration. Relayed after the
        // lock drops: announcing needs the P2P node, not the state.
        let relay_now: Vec<Hash512> = std::mem::take(&mut sh.tx_to_relay);

        // Decision 17 — the alarm half: a breached node keeps running but must
        // never be *quiet* about it. The closure is only invoked when the alarm
        // decides a look is due, so the whole-UTXO report is not recomputed on
        // every spin. The refusal half is in the API, on the two funding paths
        // only; reads stay up on purpose.
        match breach_alarm.poll(|| srct_node::conservation::conservation_report(&sh.chain, &sh.l2))
        {
            Some(srct_node::conservation::BreachNotice::Breach(line)) => eprintln!("{line}"),
            Some(srct_node::conservation::BreachNotice::Cleared) => {
                println!("conservation   breach cleared — joint supply conserved again")
            }
            None => {}
        }

        // Item 10 / §20.2: advance released escrows to Finalized once their
        // release has matured under finality — and, for an escrow bound to an
        // exit via /v1/escrow/{id}/settle, only once consensus released that
        // exit (the coin actually moved). Height math plus one release lookup:
        // safe on every tick alongside the mine step.
        sh.advance_escrow_finality();

        // Drain the inclusion queue every tick, not only when mining. With
        // `--no-mine` (or while mining is stalled) nothing else would ever
        // take it, and `live_proposals` re-derives the same tasks each tick,
        // so the queue would grow without bound. A node that builds no
        // blocks discards them honestly: inclusion is the only way L2 state
        // changes (SPEC.md §19.1), and other miners re-derive the same
        // proposals from the votes they share.
        let l2_queue = std::mem::take(&mut sh.l2_to_include);

        // Mine one block if we have a miner wallet. `mine_from_pool` selects
        // from the pool and evicts what the *canonical* chain confirms; the
        // L2 queue only matters when the API has actually received L2
        // transactions, because inclusion in a block is the only way L2
        // state changes (SPEC.md §19.1).
        if let Some(addr) = miner_addr {
            // The crank (approved P1, E-2): matured, funded, proven exits are
            // settled permissionlessly. Nobody is privileged here — consensus
            // pays only the destinations the L2 records name. An exit whose
            // funding is not exactly present stays queued, which is a delay,
            // never a wrong payment.
            let exit_claims = sh
                .l2
                .crank_claims(&sh.chain, addr)
                .into_iter()
                // A block over `max_tx_count` claims is refused outright, so the
                // crank stops at the cap rather than making the node unable to
                // mine at all. The rest are simply settled in a later block.
                .take(sh.chain.params().max_tx_count)
                .collect::<Vec<_>>();
            // An L2-bearing block must commit the root replay will derive
            // (approved P1). The chain may not consult the L2 view — that is
            // the view the chain exists to authenticate — so the miner derives
            // it from its own view and hands it over. A block that committed
            // nothing would be refused on every peer, so this is not optional.
            let l2_root = if l2_queue.is_empty() {
                None
            } else {
                Some(
                    sh.l2
                        .simulate_root(&sh.chain, sh.chain.height() + 1, &l2_queue),
                )
            };
            let mined = if l2_queue.is_empty() && exit_claims.is_empty() {
                sh.chain.mine_from_pool(&mut sh.pool, addr, now_ms())
            } else {
                sh.chain.mine_from_pool_with_exits(
                    &mut sh.pool,
                    addr,
                    now_ms(),
                    l2_queue,
                    exit_claims,
                    l2_root,
                )
            };
            if let Ok(block) = mined {
                let hash = block.block_hash();
                let height = block.header.height;
                // Durability gates relay (see `persist_dirty` above).
                let mut ok = true;
                if let Err(e) = store.save_chain(&sh.chain) {
                    eprintln!("warning: chain persist failed: {e}");
                    ok = false;
                }
                if let Err(e) = store.write_meta(&sh.chain) {
                    eprintln!("warning: meta persist failed: {e}");
                    ok = false;
                }
                persist_dirty = !ok;
                println!("mined height {height}  {}", &hash512_to_hex(&hash)[..16]);
                if ok {
                    node.broadcast_block(hash, None);
                } else {
                    eprintln!("warning: mined block held back: persist failed, retrying");
                }
            }

            // Sign and broadcast a checkpoint at an epoch boundary (M5,
            // Decisions 12/14). This is the "a quorum produced this" side of the
            // protocol: the node only signs a block it holds canonically as its
            // own tip, so a certificate can never name a hash this node does not
            // have. With no validator keys configured it signs nothing and says
            // so once, rather than looking like a broken validator.
            //
            // Signed against the committee this chain derives for the
            // certificate's epoch — the set a peer verifies against — so the
            // bitmap's indices mean the same thing on both sides. Signing
            // against a locally assembled key list would place this node's key at
            // index 0 of a short bitmap and a peer would read that as a different
            // validator having signed.
            if let Some(committee) = validator_committee.as_ref() {
                let height = sh.chain.height();
                let epoch_blocks = sh.chain.params().checkpoint_interval_blocks.max(1);
                let boundary_height = (height / epoch_blocks) * epoch_blocks;
                if boundary_height > 0
                    && boundary_height <= height
                    && !signed_epochs.contains(&boundary_height)
                {
                    // The set a verifier will use for this epoch: the chain's own
                    // committee records for that height, in the sorted order
                    // `EpochSet` uses — records, not bare keys, so members
                    // holding registered lattice keys get their sidecar entry
                    // and the certificate stays valid past the migration.
                    let epoch = boundary_height / epoch_blocks;
                    let records = sh.chain.committee_signing_records();
                    if !records.is_empty() {
                        let signer = srct_core::signing::CheckpointSigner::new(
                            &sh.chain.params().network_id,
                            epoch_blocks,
                        );
                        if let Some(Ok(cp)) = signer.sign_for_set_with_records(
                            boundary_height,
                            sh.chain.tip_hash(),
                            committee,
                            &records,
                        ) {
                            debug_assert_eq!(cp.payload.epoch, epoch);
                            if let Ok(()) = sh.chain.apply_checkpoint(&cp, &srct_core::bls::RealBls)
                            {
                                signed_epochs.insert(boundary_height);
                                node.broadcast_checkpoint(cp.clone());
                                println!(
                                    "checkpoint   height {boundary_height} signed by {} validators",
                                    cp.signer_count
                                );
                            }
                        }
                    }
                }
            } else if finality_keys_missing_warning {
                eprintln!(
                    "note: binding finality is active for this profile but no validator key \
                     files are loaded, so this node cannot sign checkpoints. It will still \
                     verify and relay the ones other validators produce."
                );
                finality_keys_missing_warning = false;
            }
        }

        // Drain inbound P2P events and apply to chain. Inbound arbitration votes
        // are tallied here, against this node's own committee and height.
        let before = sh.chain.height();
        node.poll_events(
            NodeState {
                chain: &mut sh.chain,
                pool: &mut sh.pool,
                syncer: &mut syncer,
                relay: &mut relay,
                votes: &mut votes,
            },
            Some(now_ms()),
        );

        // §13.6 reconnect sweep: dial back to bootnodes and address-book peers
        // that dropped. Tries at most one address per cycle (3 s timeout) so
        // a dead peer does not stall the mine/validate path.
        if !bootnodes.is_empty() || has_address_book {
            node.reconnect(&sh.chain);
        }

        // Keep the L2 view on the tip after both paths above. A reorg that
        // rewrote history takes the full-replay arm inside `sync`. A genesis
        // refusal here is unreachable (same inputs as startup, which
        // succeeded) — but the loop fails closed and loud rather than
        // serving on a view it cannot rebuild.
        let report = sh.l2.sync(&sh.chain).map_err(|e| format!("l2 sync: {e}"))?;
        match report.outcome {
            srct_node::l2::SyncOutcome::FullReplay { .. }
                if report.to_height != report.from_height =>
            {
                println!(
                    "l2             full replay to height {} (applied {}, skipped {})",
                    report.to_height,
                    sh.l2.applied_count(),
                    sh.l2.skipped().len()
                );
                l2_skipped_seen = sh.l2.skipped().len();
            }
            _ => {
                if sh.l2.skipped().len() != l2_skipped_seen {
                    println!(
                        "l2             height {} applied {} skipped {}",
                        sh.l2.height(),
                        sh.l2.applied_count(),
                        sh.l2.skipped().len()
                    );
                    l2_skipped_seen = sh.l2.skipped().len();
                }
            }
        }

        // Reconciliation is unconditional: a reorg can land at the same
        // height, and gating on height would skip exactly the case where the
        // pool most needs updating.
        let (cursor, mreport) = sh.chain.reconcile_mempool(&mut sh.pool, pool_cursor);
        pool_cursor = cursor;
        if mreport.evicted > 0 || mreport.readmitted > 0 || mreport.refused > 0 {
            println!(
                "mempool        evicted {} re-admitted {} refused {}",
                mreport.evicted, mreport.readmitted, mreport.refused
            );
        }

        // Relay outcomes, printed on change.
        let (accepted, refused) = (relay.accepted_count(), relay.refused_count());
        if accepted != relay_seen.0 || refused != relay_seen.1 {
            if accepted > relay_seen.0 || refused > relay_seen.1 {
                println!(
                    "relay          accepted {accepted} refused {refused} (pool holds {})",
                    sh.pool.len()
                );
            }
            relay_seen = (accepted, refused);
        }

        // Fraud arbitration (Decision 21). Two halves, in this order:
        //
        // 1. Sign. If this node holds arbitrator keys, derive the canonical
        //    reference for every live dispute and broadcast one signed vote per
        //    key. Deterministic, so every honest arbitrator over the same chain
        //    signs the same bytes.
        // 2. Propose. Any dispute with a reaching quorum becomes a `Settle`
        //    transaction in the L2 include queue, applied by the existing
        //    settlement path - which re-verifies the aggregate from scratch.
        //
        // Signing first so a node's own vote is not waiting on its own relay.
        if let Some(committee) = validator_committee.as_ref() {
            let mine = srct_node::mediation::votes_for(
                &sh.chain,
                sh.l2.state(),
                committee,
                sh.chain.height(),
            );
            for vote in mine {
                let task = vote.task_id;
                node.broadcast_vote(vote);
                println!(
                    "arbitration    vote signed for task {}",
                    &hash_to_hex(&task)[..16]
                );
            }
        }
        {
            let committee = sh.chain.committee_keys();
            let proposals = srct_node::mediation::live_proposals(&votes, &committee, sh.l2.state());
            for p in proposals {
                // Internal re-derivation, retried every tick: skip rather
                // than grow past the cap the API enforces.
                if sh.l2_to_include.len() < srct_node::api::MAX_L2_QUEUE {
                    sh.l2_to_include.push(p.tx);
                }
                println!(
                    "arbitration    quorum reached for task {}",
                    &hash_to_hex(&p.task_id)[..16]
                );
            }
        }

        // Blocks from peers are persisted per batch, not per event — plus any
        // batch while a previous save is still dirty, so one failed write
        // cannot strand the chain behind its files until the next block.
        if sh.chain.height() != before || persist_dirty {
            let mut ok = true;
            if let Err(e) = store.save_chain(&sh.chain) {
                eprintln!("warning: chain persist failed: {e}");
                ok = false;
            }
            if let Err(e) = store.write_meta(&sh.chain) {
                eprintln!("warning: meta persist failed: {e}");
                ok = false;
            }
            persist_dirty = !ok;
        }
        // Binding finality can advance without a height change.
        if let Err(e) = store.persist_finality(&sh.chain) {
            eprintln!("warning: finality persist failed: {e}");
        }

        // Node books on the 5s/changed schedule, encoded under the lock this
        // iteration already holds. `last_state_blob` only advances on a
        // successful save, so a failed write retries on the next window.
        if last_state_save.elapsed() >= std::time::Duration::from_secs(5) {
            let blob = sh.encode_state();
            if last_state_blob.as_deref() != Some(blob.as_slice()) {
                if let Err(e) = state_file.save(&blob) {
                    eprintln!("warning: node state persist failed: {e}");
                } else {
                    last_state_blob = Some(blob);
                }
            }
            last_state_save = std::time::Instant::now();
        }

        // Monitors read this through the API; a plain counter, never a
        // consensus input.
        peers.store(node.peer_count(), Ordering::Relaxed);
        drop(guard);

        // Announce API-accepted transactions to peers. The pool already
        // holds them, so GETDATA is answerable.
        if !relay_now.is_empty() {
            for txid in &relay_now {
                relay.mark_known(*txid);
            }
            node.broadcast_tx(&relay_now, None);
        }

        if interval_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        }
    }

    // --- Graceful shutdown -------------------------------------------------
    // Ctrl-C was observed: flush the chain before exiting so the store is left
    // consistent, then let `P2pNode::stop` tear down peer threads on drop.
    println!("shutting down: flushing chain state");
    {
        let sh = shared
            .lock()
            .map_err(|_| "state lock poisoned during shutdown".to_string())?;
        store
            .save_chain(&sh.chain)
            .map_err(|e| format!("shutdown flush failed (chain): {e}"))?;
        store
            .write_meta(&sh.chain)
            .map_err(|e| format!("shutdown flush failed (meta): {e}"))?;
        store
            .persist_finality(&sh.chain)
            .map_err(|e| format!("shutdown flush failed (finality): {e}"))?;
        state_file
            .save(&sh.encode_state())
            .map_err(|e| format!("shutdown flush failed (state): {e}"))?;
    }
    node.stop();
    println!("shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A decimal amount is the documented way to say how much to send, so the
    /// parser has to accept one. This pins the zero-padding: `1.5` is one
    /// SRCT and fifty million satoshis, and a space-padded "5" would not
    /// parse at all.
    #[test]
    fn a_decimal_amount_parses_to_satoshis() {
        assert_eq!(parse_srct_sat("1").unwrap(), 100_000_000);
        assert_eq!(parse_srct_sat("1.5").unwrap(), 150_000_000);
        assert_eq!(parse_srct_sat("0.5").unwrap(), 50_000_000);
        assert_eq!(parse_srct_sat("10.25").unwrap(), 1_025_000_000);
        assert_eq!(parse_srct_sat("0.00000001").unwrap(), 1);
        // The trailing zeros of a whole number are the same amount.
        assert_eq!(parse_srct_sat("1.00000000").unwrap(), 100_000_000);
    }

    #[test]
    fn a_bad_amount_is_refused_by_name() {
        assert!(parse_srct_sat("abc").is_err());
        assert!(parse_srct_sat("1.123456789").is_err());
        assert!(parse_srct_sat("-1").is_err());
    }

    /// An agent id is twenty bytes; anything else is a caller error, not a
    /// truncated id.
    #[test]
    fn an_agent_id_is_twenty_bytes() {
        let id = decode_agent_id(&"11".repeat(20)).unwrap();
        assert_eq!(id, [0x11u8; 20]);
        assert!(decode_agent_id("1111").is_err());
        assert!(decode_agent_id("zz").is_err());
    }
}
