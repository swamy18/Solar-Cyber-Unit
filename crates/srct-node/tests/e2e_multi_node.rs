//! Live multi-node end-to-end test — three real node processes, real P2P.
//!
//! Unlike `e2e_two_process.rs` (one node plus an in-process client), this
//! test starts **three** `srct-node serve` processes with real P2P links
//! between them and drives a real transaction through them. It proves the
//! thing a deployment actually depends on:
//!
//! 1. the nodes find each other and converge on one tip;
//! 2. a transaction signed by one node's wallet is accepted by the chain and
//!    reaches every other node;
//! 3. the recipient's balance moves on **every** node, not just the sender's;
//! 4. the chain still verifies (`srct-node verify` replays from genesis);
//! 5. a node that is stopped and restarted catches up and agrees again.
//!
//! Design notes — this test must be deterministic and exact, so the money
//! moves while the chain is **frozen**:
//!
//! - The seed node mines initially so the others have something to sync,
//!   with a long enough mine interval that "all tips equal" is observable.
//! - The seed is then stopped, and the transaction is mined **offline** by
//!   the one-shot `send` command against its data directory — the ordinary
//!   operator flow. Nothing moves while it happens, so the before/after
//!   balances are exact numbers, not races.
//! - The seed restarts as a relay-only node and the others re-sync to the
//!   new tip through real P2P.
//!
//! Run with `cargo test -p srct-node --test e2e_multi_node`.
//!
//! The test is self-contained: it makes its own temporary data directories,
//! picks free loopback ports, and kills every process it started (including
//! on panic, via the `Drop` impl).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSPHRASE: &str = "e2e-multi-node-test-passphrase";
/// The seed mines slowly so that "all nodes hold the same tip" is observable
/// while it is mining at all: a relay node trails a continuously mining seed
/// by a couple of blocks by design (fetch, then apply), so demanding exact
/// equality at a fast mine rate is a race the test always loses. Two seconds
/// is an eternity compared to a relay's sync latency.
const SEED_INTERVAL_MS: u64 = 2000;
/// Relay-only nodes tick fast: every tick drains their inbound events, so a
/// new block is applied within a tick or two of arriving.
const RELAY_INTERVAL_MS: u64 = 100;
const API_TIMEOUT: Duration = Duration::from_secs(60);
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(25);

/// Bind an ephemeral port to learn a free one, then release it.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn temp_root(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("srct-e2e-multi-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// One chain status read off a node's API.
#[derive(Clone, Debug)]
struct ChainStatus {
    height: u64,
    tip: String,
}

/// A `srct-node` process under test.
struct Node {
    process: Child,
    dir: PathBuf,
    p2p: String,
    api: String,
}

impl Node {
    fn bin() -> &'static str {
        env!("CARGO_BIN_EXE_srct-node")
    }

    fn init(dir: &Path, label: &str) -> Result<(), String> {
        let out = Command::new(Self::bin())
            .args([
                "init",
                "--network",
                "mini",
                "--data-dir",
                dir.to_str().unwrap(),
                "--label",
                label,
            ])
            .env("SRCT_WALLET_PASSPHRASE", PASSPHRASE)
            .output()
            .map_err(|e| format!("init failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "init failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }

    fn start(
        dir: &Path,
        bootnodes: Option<&str>,
        mine: bool,
        interval_ms: u64,
    ) -> Result<Node, String> {
        let p2p = format!("127.0.0.1:{}", free_port());
        let api = format!("127.0.0.1:{}", free_port());
        Self::start_at(dir, &p2p, &api, bootnodes, mine, interval_ms)
    }

    /// Start on fixed ports: a restart must bind the same P2P port all over
    /// again, because the peers' bootnode/address-book entries name it. The
    /// API port may be fresh — nothing depends on it.
    fn start_at(
        dir: &Path,
        p2p: &str,
        api: &str,
        bootnodes: Option<&str>,
        mine: bool,
        interval_ms: u64,
    ) -> Result<Node, String> {
        let mut cmd = Command::new(Self::bin());
        cmd.args([
            "serve",
            "--network",
            "mini",
            "--data-dir",
            dir.to_str().unwrap(),
            "--listen",
            p2p,
            "--api-listen",
            api,
            "--interval",
            &interval_ms.to_string(),
        ]);
        if !mine {
            cmd.arg("--no-mine");
        }
        if let Some(boot) = bootnodes {
            cmd.args(["--bootnodes", boot]);
        }
        let mut process = cmd
            .env("SRCT_WALLET_PASSPHRASE", PASSPHRASE)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("serve failed: {e}"))?;

        // Drain stdout/stderr into log files. A miner prints every block; an
        // undrained pipe blocks the node once the buffer fills, freezing
        // mining and sync alike — so the pipes are never left unread.
        let _ = std::fs::create_dir_all(dir);
        if let Some(stdout) = process.stdout.take() {
            let log = dir.join("serve.out.log");
            std::thread::spawn(move || drain(stdout, &log));
        }
        if let Some(stderr) = process.stderr.take() {
            let log = dir.join("serve.err.log");
            std::thread::spawn(move || drain(stderr, &log));
        }

        Ok(Node {
            process,
            dir: dir.to_path_buf(),
            p2p: p2p.to_string(),
            api: api.to_string(),
        })
    }

    /// Wait until the node's API answers.
    fn wait_for_api(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + API_TIMEOUT;
        loop {
            match self.process.try_wait() {
                Ok(Some(status)) => {
                    let err_log =
                        std::fs::read_to_string(self.dir.join("serve.err.log")).unwrap_or_default();
                    return Err(format!("node exited early with {status}\n{err_log}"));
                }
                Ok(None) => {}
                Err(e) => return Err(format!("wait error: {e}")),
            }
            if let Ok((code, _)) = http("GET", &self.api, "/v1/health", None) {
                if code == 200 {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err("API did not come up within timeout".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The node's current height and tip, as reported by its own API.
    fn status(&self) -> Result<ChainStatus, String> {
        let (code, body) = http("GET", &self.api, "/v1/status", None)?;
        if code != 200 {
            return Err(format!("status returned {code}: {body}"));
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("status is not JSON: {e}"))?;
        let tip = v
            .get("tip_hash")
            .and_then(|h| h.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "status has no tip_hash".to_string())?;
        let height = v
            .get("height")
            .and_then(|h| h.as_u64())
            .ok_or_else(|| "status has no height".to_string())?;
        Ok(ChainStatus { height, tip })
    }

    /// The confirmed balance of an address, as reported by this node's API.
    fn balance(&self, address: &str) -> Result<u64, String> {
        let (code, body) = http("GET", &self.api, &format!("/v1/balance/{address}"), None)?;
        if code != 200 {
            return Err(format!("balance returned {code}: {body}"));
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("balance is not JSON: {e}"))?;
        v.get("confirmed_sat")
            .and_then(|b| b.as_u64())
            .ok_or_else(|| "balance response has no confirmed_sat".to_string())
    }

    /// The spendable (mature) balance of an address, as reported by this node's API.
    fn spendable(&self, address: &str) -> Result<u64, String> {
        let (code, body) = http("GET", &self.api, &format!("/v1/balance/{address}"), None)?;
        if code != 200 {
            return Err(format!("balance returned {code}: {body}"));
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("balance is not JSON: {e}"))?;
        v.get("spendable_sat")
            .and_then(|b| b.as_u64())
            .ok_or_else(|| "balance response has no spendable_sat".to_string())
    }

    /// The wallet addresses held by this node, from `wallet`.
    fn wallet_addresses(&self) -> Result<Vec<String>, String> {
        let out = Command::new(Self::bin())
            .args([
                "wallet",
                "--network",
                "mini",
                "--data-dir",
                self.dir.to_str().unwrap(),
            ])
            .env("SRCT_WALLET_PASSPHRASE", PASSPHRASE)
            .output()
            .map_err(|e| format!("wallet failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "wallet failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        // The output is "<label> <address>" per wallet.
        let mut out = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let (_label, address) = match (parts.next(), parts.next()) {
                (Some(l), Some(a)) => (l, a),
                _ => continue,
            };
            if address.starts_with("jt1") {
                out.push(address.to_string());
            }
        }
        if out.is_empty() {
            return Err(format!("no wallet address in output: {text}"));
        }
        Ok(out)
    }

    /// Replay the whole chain from genesis and compare the UTXO set.
    fn verify_chain(&self) -> Result<(), String> {
        let out = Command::new(Self::bin())
            .args([
                "verify",
                "--network",
                "mini",
                "--data-dir",
                self.dir.to_str().unwrap(),
            ])
            .env("SRCT_WALLET_PASSPHRASE", PASSPHRASE)
            .output()
            .map_err(|e| format!("verify failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "verify failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Copy a child process's output into a log file until it exits.
fn drain<R: Read + Send + 'static>(mut reader: R, path: &Path) {
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = file.write_all(&buf[..n]);
            }
        }
    }
}

/// Mine a transaction offline against a stopped node's data directory.
///
/// This is the ordinary operator flow: stop the node, run a one-shot command,
/// start the node again. The transaction lands in a single block and nothing
/// races while it does.
fn send_and_mine(dir: &Path, from_label: &str, to: &str, amount_sat: u64) -> Result<(), String> {
    let out = Command::new(Node::bin())
        .args([
            "send",
            "--network",
            "mini",
            "--data-dir",
            dir.to_str().unwrap(),
            "--wallet",
            from_label,
            "--to",
            to,
            "--amount-sat",
            &amount_sat.to_string(),
        ])
        .env("SRCT_WALLET_PASSPHRASE", PASSPHRASE)
        .output()
        .map_err(|e| format!("send failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "send failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Read a confirmed balance straight from the chain file on disk — the
/// offline exact read, used while the chain is frozen.
fn balance_cli(dir: &Path, address: &str) -> Result<u64, String> {
    let out = Command::new(Node::bin())
        .args([
            "balance",
            "--network",
            "mini",
            "--data-dir",
            dir.to_str().unwrap(),
            "--address",
            address,
        ])
        .env("SRCT_WALLET_PASSPHRASE", PASSPHRASE)
        .output()
        .map_err(|e| format!("balance failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "balance failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("no unspent outputs") {
        return Ok(0);
    }
    // The summary line is `total <whole>.<frac8> SRCT, of which ...` — satoshi
    // exact, not a rounded display.
    let line = text
        .lines()
        .find(|l| l.starts_with("total "))
        .ok_or_else(|| format!("no total in balance output: {text}"))?;
    let number = line
        .strip_prefix("total ")
        .and_then(|r| r.split_whitespace().next())
        .ok_or_else(|| format!("no amount in balance output: {text}"))?;
    parse_srct_exact(number)
}

/// Read the coinbase value of a chain's tip block from the chain file on
/// disk. The offline `send` mines exactly one block with the transaction in
/// it, and the sender is also the miner wallet, so the sender's balance
/// movement over that block is `reward - amount - fee`: with the reward
/// known, the fee is exact.
fn tip_coinbase(dir: &Path) -> Result<u64, String> {
    let out = Command::new(Node::bin())
        .args([
            "show-block",
            "--network",
            "mini",
            "--data-dir",
            dir.to_str().unwrap(),
        ])
        .env("SRCT_WALLET_PASSPHRASE", PASSPHRASE)
        .output()
        .map_err(|e| format!("show-block failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "show-block failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("block is not JSON: {e}"))?;
    // The coinbase is always txs[0] and consensus rejects a coinbase whose
    // output count is not exactly one, so the reward is outputs[0].value.
    v.get("txs")
        .and_then(|txs| txs.get(0))
        .and_then(|coinbase| coinbase.get("outputs"))
        .and_then(|outputs| outputs.get(0))
        .and_then(|out| out.get("value"))
        .and_then(|val| val.as_u64())
        .ok_or_else(|| "tip block has no coinbase value".to_string())
}

/// Parse the CLI's exact 8-decimal SRCT formatting back into satoshis.
fn parse_srct_exact(s: &str) -> Result<u64, String> {
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: u64 = whole.parse().map_err(|_| format!("bad amount `{s}`"))?;
    let mut frac_sat: u64 = 0;
    if !frac.is_empty() {
        let mut padded = frac.to_string();
        while padded.len() < 8 {
            padded.push('0');
        }
        if padded.len() != 8 {
            return Err(format!("bad amount `{s}`"));
        }
        frac_sat = padded.parse().map_err(|_| format!("bad amount `{s}`"))?;
    }
    Ok(whole * 100_000_000 + frac_sat)
}

/// A minimal HTTP/1.1 client over a raw socket.
fn http(method: &str, addr: &str, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
    let mut stream = std::net::TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let blen = body.unwrap_or("").len();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {blen}\r\n\r\n{}",
        body.unwrap_or("")
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    drop(stream);
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// Wait until every node reports the same height and tip.
///
/// Use this only while the chain is frozen: a continuously mining seed
/// serves `GETDATA` on its next mine tick, so a relay always trails it by
/// about one mine interval — exact equality during mining is a race the
/// test would always lose. (See `wait_for_syncing` for the mining phase.)
fn wait_for_convergence(nodes: &[Node]) -> Result<ChainStatus, String> {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        let mut statuses = Vec::new();
        let mut alive = 0;
        for node in nodes {
            if let Ok(s) = node.status() {
                statuses.push(s);
                alive += 1;
            }
        }
        if alive == nodes.len() {
            let first = &statuses[0];
            if statuses
                .iter()
                .all(|s| s.height == first.height && s.tip == first.tip)
            {
                return Ok(first.clone());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("nodes did not converge; statuses = {statuses:?}"));
        }
        std::thread::sleep(POLL);
    }
}

/// Wait until the nodes are demonstrably syncing against the mining seed:
/// every node past `min_height`, and no node more than `max_gap` behind the
/// leader, for several consecutive samples. This is the initial phase's
/// property — exact equality is impossible while the seed mines (a relay
/// trails by one mine tick by design), and unnecessary: after the freeze
/// the exact check takes over.
fn wait_for_syncing(
    nodes: &[Node],
    min_height: u64,
    max_gap: u64,
    samples: u32,
) -> Result<(), String> {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    let mut streak = 0u32;
    loop {
        let mut heights = Vec::new();
        for node in nodes {
            match node.status() {
                Ok(st) => heights.push(st.height),
                Err(_) => heights.clear(),
            }
        }
        if heights.len() == nodes.len() {
            let leader = *heights.iter().max().unwrap();
            let quiet = heights
                .iter()
                .all(|h| *h >= min_height && leader - h <= max_gap);
            if quiet {
                streak += 1;
                if streak >= samples {
                    return Ok(());
                }
            } else {
                streak = 0;
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "nodes never settled into sync; heights = {heights:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait until the sender holds a spendable (mature) coinbase output.
fn wait_for_mature_funds(node: &Node, address: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match node.spendable(address) {
            Ok(b) if b > 0 => return Ok(()),
            Ok(_) => {}
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("balance query failed: {e}"));
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("sender never held a spendable balance".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn three_live_nodes_sync_settle_and_restart() {
    let root = temp_root("sync");

    // --- bring up three nodes, each dialed to the first -------------------
    // Only the seed mines. Three independent miners fork constantly, and
    // "the nodes agree" then becomes a race instead of a property.
    let mut nodes: Vec<Node> = Vec::new();
    for i in 0..3 {
        let dir = root.join(format!("node{i}"));
        Node::init(&dir, &format!("miner{i}")).expect("init chain");
        let node = if i == 0 {
            Node::start(&dir, None, true, SEED_INTERVAL_MS).expect("start node 0")
        } else {
            let boot = nodes[0].p2p.clone();
            Node::start(&dir, Some(&boot), false, RELAY_INTERVAL_MS).expect("start node")
        };
        nodes.push(node);
    }
    for node in nodes.iter_mut() {
        node.wait_for_api().expect("node API up");
    }

    // --- the relays catch up to the mining seed ---------------------------
    // Tolerant check only: exact equality cannot hold while the seed mines.
    wait_for_syncing(&nodes, 5, 3, 3).expect("nodes sync with the mining seed");

    // --- freeze the seed and move money offline ---------------------------
    let sender_address = nodes[0].wallet_addresses().expect("sender wallet")[0].clone();
    let recipient_address = nodes[1].wallet_addresses().expect("recipient wallet")[0].clone();

    // The sender needs a mature coinbase output, so wait for the seed to
    // have mined past the coinbase maturity.
    wait_for_mature_funds(&nodes[0], &sender_address, Duration::from_secs(120))
        .expect("sender has mature funds");

    // Freeze the chain: stop the seed (its process is killed on drop).
    let frozen = nodes.remove(0);
    let dir0 = frozen.dir.clone();
    let p2p0 = frozen.p2p.clone();
    drop(frozen);

    // Exact before-values, read straight from the chain file on disk.
    let sender_before = balance_cli(&dir0, &sender_address).expect("sender before (offline)");
    let recipient_before =
        balance_cli(&dir0, &recipient_address).expect("recipient before (offline)");

    let amount_sat = 10_000_000u64;
    send_and_mine(&dir0, "miner0", &recipient_address, amount_sat).expect("send + mine offline");

    let sender_after = balance_cli(&dir0, &sender_address).expect("sender after (offline)");
    let recipient_after =
        balance_cli(&dir0, &recipient_address).expect("recipient after (offline)");
    assert_eq!(
        recipient_after,
        recipient_before + amount_sat,
        "recipient did not receive exactly the payment"
    );
    // The block the offline `send` mined pays its coinbase to the sender
    // wallet too, so the sender's movement is `reward - amount - fee`.
    // Remove the reward and the fee is exact.
    let reward = tip_coinbase(&dir0).expect("coinbase of the payment block");
    let fee =
        (sender_before as i128) - (sender_after as i128) - (amount_sat as i128) + (reward as i128);
    assert!(
        // The coinbase includes the fee the block's transactions paid, so the
        // fee is exactly what remains after crediting the reward; it must be
        // nowhere near the amount (0.1 SRCT) — 1M sat is the base fee for the
        // one-input, two-output payment at mini's rate.
        (0..1_000_000).contains(&fee),
        "sender fee accounting broke: before {sender_before}, after {sender_after},          amount {amount_sat}, reward {reward} -> fee {fee}"
    );

    // --- restart the seed as a relay node and let the others resync -------
    let api0 = format!("127.0.0.1:{}", free_port());
    let mut node0 =
        Node::start_at(&dir0, &p2p0, &api0, None, false, RELAY_INTERVAL_MS).expect("restart seed");
    node0.wait_for_api().expect("restarted seed API up");
    nodes.insert(0, node0);

    let settled = wait_for_convergence(&nodes).expect("nodes converge on the new tip");
    assert!(settled.height > 0, "chain did not grow");

    // Every node shows the exact same balances.
    for node in &nodes {
        assert_eq!(
            node.balance(&recipient_address).expect("recipient balance"),
            recipient_after,
            "recipient balance disagrees on a node"
        );
        assert_eq!(
            node.balance(&sender_address).expect("sender balance"),
            sender_after,
            "sender balance disagrees on a node"
        );
    }

    // --- the chain still verifies from genesis on every node -------------
    for node in &nodes {
        node.verify_chain().expect("chain verifies");
    }

    // --- a relay node restarts, catches up and agrees again ---------------
    let relay = nodes.remove(2);
    let dir2 = relay.dir.clone();
    let p2p2 = relay.p2p.clone();
    drop(relay);

    let api2 = format!("127.0.0.1:{}", free_port());
    let mut node2 = Node::start_at(
        &dir2,
        &p2p2,
        &api2,
        Some(&nodes[0].p2p),
        false,
        RELAY_INTERVAL_MS,
    )
    .expect("restart node 2");
    node2.wait_for_api().expect("restarted API up");
    nodes.push(node2);

    wait_for_convergence(&nodes).expect("restarted node caught up");
    for node in &nodes {
        assert_eq!(
            node.balance(&recipient_address)
                .expect("recipient balance post-restart"),
            recipient_after,
            "recipient balance disagrees after restart"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}
