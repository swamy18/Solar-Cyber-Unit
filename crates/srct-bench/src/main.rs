//! SRCT Phase A performance harness.
//!
//! Measurement only. This binary builds deterministic chains, times each
//! pipeline stage separately, and writes machine-readable JSON plus a
//! human-readable Markdown report. It changes nothing about consensus,
//! storage formats, validation, mining, cryptography or the network:
//! every block it mines and submits goes through the same
//! [`srct_core::chain::Chain::submit`] production validation, and every
//! store it touches is a scratch directory.
//!
//! Workloads (mini profile, fixed seeds, `GENESIS + h*1000` timestamps):
//! - `empty`: coinbase-only blocks. Floor cost: headers, indexing, replay.
//! - `realistic`: 14 spends per block, 1-in-2-out, net +14 UTXOs/block,
//!   sized near the 250k gas target so fees stay flat. Exercises validation,
//!   UTXO growth, store append and replay.
//! - `adversarial`: gas-cap-full blocks (~110 1-in-2-out spends, ~1.9M gas)
//!   with 6 interleaved empty blocks per full block to keep EIP-1559 fees in
//!   a band. Worst-case validation CPU inside protocol limits.
//!
//! Usage:
//! ```text
//! cargo run -p srct-bench -- run --workload realistic --blocks 200 \
//!     --dir ./target/bench --json out.json --markdown out.md
//! ```

use std::path::{Path, PathBuf};
use std::time::Instant;

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::Chain;
use srct_core::hash::Address;
use srct_core::params::NetworkParams;
use srct_core::tx::{OutPoint, Output, Transaction, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE};
use srct_core::wallet::Wallet;

/// One timed stage. `detail` carries stage-specific counters.
struct Stage {
    name: &'static str,
    wall_ms: u128,
    detail: serde_json::Value,
}

/// Point-in-time process resource usage. Every field is `None` on platforms
/// where it cannot be measured; the report says "unavailable" instead of
/// inventing a number (never report a missing measurement as zero).
#[derive(Clone, Copy, Default)]
struct ProcStats {
    peak_rss_bytes: Option<u64>,
    rss_bytes: Option<u64>,
    peak_pagefile_bytes: Option<u64>,
    pagefile_bytes: Option<u64>,
    user_cpu_ms: Option<u64>,
    kernel_cpu_ms: Option<u64>,
}

impl ProcStats {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "peak_rss_bytes": self.peak_rss_bytes,
            "rss_bytes": self.rss_bytes,
            "peak_pagefile_bytes": self.peak_pagefile_bytes,
            "pagefile_bytes": self.pagefile_bytes,
            "user_cpu_ms": self.user_cpu_ms,
            "kernel_cpu_ms": self.kernel_cpu_ms,
        })
    }
}

/// Raw Windows process APIs, declared by hand so the harness needs no new
/// dependencies. Layouts follow the documented `PROCESS_MEMORY_COUNTERS_EX`
/// and `FILETIME` structs; `GetCurrentProcess` returns a pseudo-handle that
/// must not be closed.
#[cfg(windows)]
mod win {
    #[repr(C)]
    pub struct ProcessMemoryCountersEx {
        pub cb: u32,
        pub page_fault_count: u32,
        pub peak_working_set_size: usize,
        pub working_set_size: usize,
        pub quota_peak_paged_pool_usage: usize,
        pub quota_paged_pool_usage: usize,
        pub quota_peak_non_paged_pool_usage: usize,
        pub quota_non_paged_pool_usage: usize,
        pub pagefile_usage: usize,
        pub peak_pagefile_usage: usize,
        pub private_usage: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct FileTime {
        pub dw_low_date_time: u32,
        pub dw_high_date_time: u32,
    }

    impl FileTime {
        pub fn as_millis(&self) -> u64 {
            // 100-nanosecond intervals since 1601-01-01.
            (((self.dw_high_date_time as u64) << 32) | self.dw_low_date_time as u64) / 10_000
        }
    }

    pub type Handle = *mut core::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> Handle;
        pub fn GetProcessTimes(
            h_process: Handle,
            lp_creation_time: *mut FileTime,
            lp_exit_time: *mut FileTime,
            lp_kernel_time: *mut FileTime,
            lp_user_time: *mut FileTime,
        ) -> i32;
    }

    #[link(name = "psapi")]
    extern "system" {
        pub fn GetProcessMemoryInfo(
            h_process: Handle,
            ppsmem_counters: *mut ProcessMemoryCountersEx,
            cb: u32,
        ) -> i32;
    }
}

fn proc_stats() -> ProcStats {
    // 64-bit pointers: the FFI structs above use `usize` for SIZE_T fields.
    const _: () = assert!(std::mem::size_of::<usize>() == 8);

    #[cfg(target_os = "linux")]
    {
        let mut st = ProcStats::default();
        if let Ok(text) = std::fs::read_to_string("/proc/self/status") {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                match it.next() {
                    Some("VmHWM:") => {
                        st.peak_rss_bytes = it.next().and_then(|v| v.parse::<u64>().ok()).map(|kb| kb * 1024);
                    }
                    Some("VmRSS:") => {
                        st.rss_bytes = it.next().and_then(|v| v.parse::<u64>().ok()).map(|kb| kb * 1024);
                    }
                    _ => {}
                }
            }
        }
        // utime (field 14) and stime (field 15) in clock ticks; the tick is
        // 100 Hz on Linux, so each tick is 10 ms.
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            if let Some(end) = stat.rfind(')') {
                let fields: Vec<&str> = stat[end + 1..].split_whitespace().collect();
                // fields[0] is the field after `comm` (field 2 overall), so
                // utime (14) is at index 11 and stime (15) at index 12.
                if fields.len() > 12 {
                    st.user_cpu_ms = fields[11].parse::<u64>().ok().map(|t| t * 10);
                    st.kernel_cpu_ms = fields[12].parse::<u64>().ok().map(|t| t * 10);
                }
            }
        }
        st
    }
    #[cfg(windows)]
    {
        use std::mem::{size_of, zeroed};
        let mut st = ProcStats::default();
        // SAFETY: fixed-layout OS structs, valid pseudo-handle, checked
        // return codes before reading any out-param.
        unsafe {
            let h = win::GetCurrentProcess();
            let mut mc: win::ProcessMemoryCountersEx = zeroed();
            mc.cb = size_of::<win::ProcessMemoryCountersEx>() as u32;
            if win::GetProcessMemoryInfo(h, &mut mc, mc.cb) != 0 {
                st.peak_rss_bytes = Some(mc.peak_working_set_size as u64);
                st.rss_bytes = Some(mc.working_set_size as u64);
                st.peak_pagefile_bytes = Some(mc.peak_pagefile_usage as u64);
                st.pagefile_bytes = Some(mc.pagefile_usage as u64);
            }
            let (mut c, mut e, mut k, mut u) = (
                win::FileTime::default(),
                win::FileTime::default(),
                win::FileTime::default(),
                win::FileTime::default(),
            );
            if win::GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) != 0 {
                st.kernel_cpu_ms = Some(k.as_millis());
                st.user_cpu_ms = Some(u.as_millis());
            }
        }
        st
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        ProcStats::default()
    }
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "srct-bench").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn gas(n_in: usize, n_out: usize) -> u64 {
    GAS_TX_BASE + GAS_PER_INPUT * n_in as u64 + GAS_PER_OUTPUT * n_out as u64
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas(n_in, n_out))
        .saturating_add(1_000_000)
}

/// Retained signing keys. Outputs always pay bank addresses, so every pool
/// entry's owner wallet is retained and can sign the next spend.
struct Bank {
    wallets: Vec<Wallet>,
    addrs: Vec<Address>,
}

impl Bank {
    fn new(n: usize) -> Self {
        // Seeds stay in 1..=200: 0x00.. is not a valid secret scalar and
        // 0xFF.. can exceed the curve order. Duplicates across cycles are
        // fine (several outputs may pay the same address).
        let wallets: Vec<Wallet> = (0..n).map(|i| wallet(1 + (i % 200) as u8)).collect();
        let addrs = wallets.iter().map(addr).collect();
        Bank { wallets, addrs }
    }
}

/// Mine a few maturing blocks to the faucet. Returns (chain, faucet, miner).
fn base_chain(faucet_seed: u8, maturing_blocks: u64) -> (Chain, Wallet, Address) {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params).unwrap();
    let faucet = wallet(faucet_seed);
    let miner = addr(&faucet);
    for h in 1..=maturing_blocks {
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    (chain, faucet, miner)
}

/// Split mature faucet coinbases into `total` outputs paying bank addresses.
/// Each output is sized to stay spendable (several future fees deep).
fn fund_pool(
    chain: &mut Chain,
    faucet: &Wallet,
    miner: &Address,
    bank: &Bank,
    total: usize,
) -> Vec<(OutPoint, u64, usize, u64)> {
    let mut mature: Vec<(OutPoint, u64, u64)> = chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == *miner && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value, u.height))
        .collect();
    // Oldest first: the deepest coinbases stay mature no matter how many
    // setup blocks the splits themselves add.
    mature.sort_by_key(|(_, _, h)| *h);
    assert!(mature.len() >= 2, "need maturing blocks first");
    let mut out = Vec::new();
    let mut bi = 0usize;
    // A split output must stay spendable through the measured loop: it has
    // to cover its own future 1-in-2-out fee with change left over, at
    // whatever base fee the chain currently quotes.
    let min_out = fee_for(chain, 1, 2).saturating_mul(3).max(1_000_000);
    for (op, value, _) in mature.iter().take(6) {
        if out.len() >= total {
            break;
        }
        let afford = (value / min_out).min(220) as usize;
        assert!(
            afford > 0,
            "faucet output {value} too small for even one spendable split (need {min_out})"
        );
        let want = (total - out.len()).min(afford);
        let fee = fee_for(chain, 1, want);
        let each = (value.saturating_sub(fee)) / want as u64;
        // Owner indices and payee addresses advance together: output i pays
        // bank[(bi0 + i)] and is spent by that wallet. (An earlier revision
        // paid every output to one address while recording round-robin
        // owners — correctly-signed spends need the two to agree.)
        let outputs: Vec<Output> = (0..want)
            .map(|i| Output {
                value: each,
                address: bank.addrs[(bi + i) % bank.addrs.len()],
            })
            .collect::<Vec<_>>();
        let owners: Vec<usize> = (0..want).map(|i| (bi + i) % bank.addrs.len()).collect();
        bi += want;
        let mut tx = faucet
            .build_tx(std::slice::from_ref(op), outputs, fee)
            .unwrap();
        faucet.sign(&mut tx).unwrap();
        let h = chain.height() + 1;
        let b = chain.mine_block(*miner, vec![tx.clone()], ts(h)).unwrap();
        chain.submit(b).unwrap();
        let txid = tx.txid();
        let split_h = chain.height();
        for (i, owner) in owners.into_iter().enumerate() {
            let op = OutPoint {
                txid,
                index: i as u32,
            };
            let u = chain.utxo().get(&op).unwrap();
            out.push((op, u.out.value, owner, split_h));
        }
    }
    out.truncate(total);
    assert_eq!(out.len(), total, "faucet could not fund the pool");
    out
}

/// One 1-in-`outs_per_tx`-out spend. Outputs cycle bank addresses so the pool
/// stays funded and every owner is retained.
fn spend(
    chain: &Chain,
    op: &OutPoint,
    value: u64,
    owner: &Wallet,
    outs_per_tx: usize,
    bank: &Bank,
    cursor: &mut usize,
) -> (Transaction, Vec<(OutPoint, u64, usize)>) {
    let fee = fee_for(chain, 1, outs_per_tx);
    let each = (value.saturating_sub(fee)) / outs_per_tx as u64;
    assert!(each > 0, "input too small for outs");
    let mut owners = Vec::with_capacity(outs_per_tx);
    let outputs: Vec<Output> = (0..outs_per_tx)
        .map(|_| {
            let idx = *cursor % bank.addrs.len();
            *cursor += 1;
            owners.push(idx);
            Output {
                value: each,
                address: bank.addrs[idx],
            }
        })
        .collect();
    let mut tx = owner
        .build_tx(std::slice::from_ref(op), outputs, fee)
        .unwrap();
    owner.sign(&mut tx).unwrap();
    let txid = tx.txid();
    let next: Vec<(OutPoint, u64, usize)> = owners
        .into_iter()
        .enumerate()
        .map(|(i, idx)| {
            (
                OutPoint {
                    txid,
                    index: i as u32,
                },
                each,
                idx,
            )
        })
        .collect();
    (tx, next)
}

struct BuiltChain {
    chain: Chain,
    faucet: Wallet,
    sign_ms: u128,
}

fn build_empty(blocks: u64) -> BuiltChain {
    let (mut chain, faucet, miner) = base_chain(1, 12);
    for _ in 0..blocks {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    BuiltChain {
        chain,
        faucet,
        sign_ms: 0,
    }
}

fn build_sized(
    blocks: u64,
    spends_per_block: usize,
    outs_per_tx: usize,
    empty_gap: usize,
) -> BuiltChain {
    // Extra maturing headroom: the faucet splits themselves add blocks, and
    // every split input must stay deeply mature.
    let (mut chain, faucet, miner) = base_chain(1, 24);
    let bank = Bank::new(256);
    let maturity = chain.params().coinbase_maturity;
    // Pipeline depth: THIS chain requires every output (not just coinbases)
    // to age `maturity` blocks before it may be spent
    // (`ledger.rs::check_tx`). Each measured block consumes
    // `spends_per_block` inputs and returns `outs_per_tx` per input maturing
    // `maturity` blocks later, so the pool must cover the whole pipeline:
    // seed it with a dozen blocks' worth and fast-forward empties until the
    // seed outputs are spendable.
    let mut pool: Vec<(OutPoint, u64, usize, u64)> =
        fund_pool(&mut chain, &faucet, &miner, &bank, spends_per_block * 12);
    while pool
        .iter()
        .any(|(_, _, _, h)| h + maturity > chain.height() + 1)
    {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    let mut cursor = 0usize;
    let mut sign_ms = 0u128;
    for _ in 0..blocks {
        // Spend only outputs old enough for the next block: partition the
        // pool into spendable-now vs still-ripening, oldest first.
        let spend_h = chain.height() + 1;
        let mut ready = Vec::new();
        let mut waiting = Vec::new();
        for e in pool.drain(..) {
            if e.3 + maturity <= spend_h {
                ready.push(e);
            } else {
                waiting.push(e);
            }
        }
        assert!(
            ready.len() >= spends_per_block,
            "only {} mature inputs (pool {}, min_h {:?}, max_h {:?}) for {spends_per_block} spends at height {spend_h}, maturity {maturity}",
            ready.len(),
            ready.len() + waiting.len(),
            pool_min_h(&waiting),
            pool_max_h(&waiting),
        );
        let mut txs = Vec::with_capacity(spends_per_block);
        let mut fresh = Vec::new();
        let t1 = Instant::now();
        for (op, v, oi, _) in ready.drain(..spends_per_block) {
            let (tx, next) = spend(
                &chain,
                &op,
                v,
                &bank.wallets[oi],
                outs_per_tx,
                &bank,
                &mut cursor,
            );
            let next: Vec<(OutPoint, u64, usize, u64)> = next
                .into_iter()
                .map(|(op, v, oi)| (op, v, oi, spend_h))
                .collect();
            txs.push(tx);
            fresh.extend(next);
        }
        // The remainder AND the still-ripening outputs both go back: dropping
        // `waiting` here silently destroyed every output younger than the
        // maturity window and starved the pool after the seed ran out.
        pool.extend(ready);
        pool.extend(waiting);
        sign_ms += t1.elapsed().as_millis();
        // Only outputs actually in the UTXO set join the pool (defensive:
        // a bug that mints unspendable outputs surfaces here, not silently).
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, txs, ts(h)).unwrap();
        chain.submit(b).unwrap();
        pool.extend(
            fresh
                .into_iter()
                .filter(|(op, _, _, _)| chain.utxo().get(op).is_some()),
        );
        assert!(
            pool.len() >= spends_per_block,
            "pool underfilled: workload is not self-sustaining"
        );
        // Fee pacing: EIP-1559 raises the base fee ~+84% per gas-cap-full
        // block and relaxes ~-12% per empty one. Sustained full blocks would
        // compound fees until no funded output can pay them — real protocol
        // behavior, but it measures fee explosion, not validation. Interleave
        // empties so the fee oscillates in a band instead.
        for _ in 0..empty_gap {
            let h = chain.height() + 1;
            let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
    }
    BuiltChain {
        chain,
        faucet,
        sign_ms,
    }
}

fn pool_min_h(pool: &[(OutPoint, u64, usize, u64)]) -> Option<u64> {
    pool.iter().map(|(_, _, _, h)| *h).min()
}

fn pool_max_h(pool: &[(OutPoint, u64, usize, u64)]) -> Option<u64> {
    pool.iter().map(|(_, _, _, h)| *h).max()
}

fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    total += m.len();
                }
            }
        }
    }
    total
}

/// Abort the run early when the process working set exceeds the safety
/// budget. Returns true when the run must stop: the caller records a final
/// `aborted` stage with the partial results instead of pushing through into
/// swap/OOM-killer territory on a small box.
fn over_budget(max_rss_bytes: Option<u64>, context: &str) -> bool {
    let Some(max) = max_rss_bytes else {
        return false;
    };
    match proc_stats().rss_bytes {
        Some(rss) if rss > max => {
            eprintln!(
                "srct-bench: stopping gracefully at {context}: working set {rss} B exceeds --max-rss budget {max} B"
            );
            true
        }
        // Unmeasurable on this platform: never abort on a missing reading
        // (a missing measurement must not be treated as zero usage either).
        _ => false,
    }
}

fn run_stages(workload: &str, blocks: u64, dir: &Path, max_rss_bytes: Option<u64>) -> Vec<Stage> {
    let mut stages = Vec::new();

    // Safety gate before the heavy in-memory build: never push a small box
    // into swap/OOM-killer territory. An abort is recorded, not silent.
    if over_budget(max_rss_bytes, "startup") {
        stages.push(Stage {
            name: "aborted",
            wall_ms: 0,
            detail: serde_json::json!({
                "at": "startup",
                "reason": "working set already over --max-rss budget",
            }),
        });
        return stages;
    }

    // Stage 1: build + validate in memory (mine + submit together, as a node
    // would when producing).
    let t0 = Instant::now();
    let stats_before = proc_stats();
    let built = match workload {
        "empty" => build_empty(blocks),
        // ~14 spends ~= the 250k gas target: fees stay flat, so this
        // measures validation, not fee dynamics.
        "realistic" => build_sized(blocks, 14, 2, 0),
        // Gas-cap-full blocks with fee pacing (6 empties per full block
        // keeps the base fee oscillating instead of exploding).
        "adversarial" => build_sized(blocks, 110, 2, 6),
        other => panic!("unknown workload: {other} (empty|realistic|adversarial)"),
    };
    let build_validate_ms = t0.elapsed().as_millis();
    let chain = built.chain;
    let utxo_entries = chain.utxo().len() as u64;
    let height = chain.height();
    stages.push(Stage {
        name: "build_and_validate",
        wall_ms: build_validate_ms,
        detail: serde_json::json!({
            "measured_blocks": blocks,
            "chain_height": height,
            "setup_blocks_included": height.saturating_sub(blocks),
            "mine_plus_submit_ms": build_validate_ms,
            "sign_ms_included": built.sign_ms,
            "utxo_entries": utxo_entries,
        }),
    });

    // Stage 2: persist to a fresh store, block by block (what a syncing node
    // pays on top of validation). Uses only public store APIs.
    let store_dir = dir.join("store");
    let _ = std::fs::remove_dir_all(&store_dir);
    let t0 = Instant::now();
    let (mut store, _) = srct_store::BlockStore::open(&store_dir, &NetworkParams::mini()).unwrap();
    for h in 1..=height {
        let block = chain.block_at(h).unwrap();
        store.append_block(block).unwrap();
        store.set_tip(&block.block_hash()).unwrap();
    }
    store.sync().unwrap();
    let persist_ms = t0.elapsed().as_millis();
    let log_bytes = dir_bytes(&store_dir);
    drop(store);
    stages.push(Stage {
        name: "store_persist",
        wall_ms: persist_ms,
        detail: serde_json::json!({ "log_bytes": log_bytes }),
    });

    // Stage 3: cold open — RecordLog recovery + full index rebuild + height
    // walk + journal adoption (Phase B). This is the price of having no
    // index file.
    if over_budget(max_rss_bytes, "reopen") {
        stages.push(Stage {
            name: "aborted",
            wall_ms: 0,
            detail: serde_json::json!({
                "at": "store_reopen_index_rebuild",
                "reason": "working set over --max-rss budget",
                "chain_height": height,
            }),
        });
        return stages;
    }
    let t0 = Instant::now();
    let (mut store2, recovery) =
        srct_store::BlockStore::open(&store_dir, &NetworkParams::mini()).unwrap();
    let reopen_ms = t0.elapsed().as_millis();
    // Recovery correctness at scale: the reopened tip must be exactly the
    // persisted tip (journal adoption re-derives unflushed advances).
    assert_eq!(
        store2.tip(),
        (chain.tip_hash(), height),
        "reopened tip must match the persisted tip"
    );
    stages.push(Stage {
        name: "store_reopen_index_rebuild",
        wall_ms: reopen_ms,
        detail: serde_json::json!({
            "records": recovery.records,
            "discarded_tail_bytes": recovery.discarded_tail_bytes,
            "blocks_indexed": store2.block_count(),
            "journal_adopted": store2.tip().1 == height,
        }),
    });

    // Stage 4: canonical replay into a fresh Chain (what every boot does).
    let t0 = Instant::now();
    let params = NetworkParams::mini();
    let mut fresh = Chain::new(params).unwrap();
    for h in 1..=height {
        let block = store2.block_at_height(h).unwrap().unwrap();
        fresh.submit(block).unwrap();
    }
    let replay_ms = t0.elapsed().as_millis();
    drop(store2);
    stages.push(Stage {
        name: "chain_replay_validate",
        wall_ms: replay_ms,
        detail: serde_json::json!({ "replayed_blocks": height }),
    });

    // Stage 5: L2 replay over the replayed chain (production startup path).
    let t0 = Instant::now();
    let l2 = srct_node::l2::NodeL2::replay_from(&fresh, &NetworkParams::mini()).unwrap();
    let l2_ms = t0.elapsed().as_millis();
    drop(l2);
    stages.push(Stage {
        name: "l2_replay",
        wall_ms: l2_ms,
        detail: serde_json::json!({}),
    });

    // Stage 6: mempool admission micro-stage — up to 2000 standard spends
    // against the tip UTXO set. Bounds the relay-admission cost on a small box.
    let t0 = Instant::now();
    let mut pool = srct_core::mempool::Mempool::new(32 * 1024 * 1024);
    let base_fee = fresh.expected_base_fee_for_next_block();
    let tip_h = fresh.height();
    // Spend the faucet's own mature outputs, signed by the faucet: the pool
    // must see correctly-signed spends or it measures rejection, not admission.
    let faucet_addr = addr(&built.faucet);
    let mut admitted = 0usize;
    for (op, u) in fresh.utxo().iter() {
        if admitted >= 2000 {
            break;
        }
        // Mature at the height the pool would include it (same rule as
        // `Chain::is_mature`, evaluated for tip+1).
        if u.out.address != faucet_addr || u.height + fresh.params().coinbase_maturity > tip_h + 1 {
            continue;
        }
        // No fixed dust floor: anything that covers its own fee exercises the
        // real admission path (check_tx + signature verification).
        let fee = base_fee.saturating_mul(gas(1, 1)).saturating_add(1_000_000);
        let out_val = u.out.value.saturating_sub(fee);
        if out_val == 0 {
            continue;
        }
        let mut tx = built
            .faucet
            .build_tx(
                &[op],
                vec![Output {
                    value: out_val,
                    address: faucet_addr,
                }],
                fee,
            )
            .unwrap();
        built.faucet.sign(&mut tx).unwrap();
        if pool
            .add(
                tx,
                fresh.utxo(),
                tip_h + 1,
                fresh.params(),
                base_fee,
                fresh.bonds(),
            )
            .is_ok()
        {
            admitted += 1;
        }
    }
    let mempool_ms = t0.elapsed().as_millis();
    stages.push(Stage {
        name: "mempool_admit_2000",
        wall_ms: mempool_ms,
        detail: serde_json::json!({ "admitted": admitted, "pool_len": pool.len() }),
    });

    let stats_after = proc_stats();
    // Storage growth: every file the node actually keeps on disk.
    let meta_bytes = std::fs::metadata(store_dir.join("meta.json")).map(|m| m.len()).unwrap_or(0);
    let journal_bytes = std::fs::metadata(store_dir.join("tip.journal")).map(|m| m.len()).unwrap_or(0);
    let dir_bytes_total = dir_bytes(&store_dir);
    let parallelism = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    stages.push(Stage {
        name: "totals",
        wall_ms: stages.iter().map(|s| s.wall_ms).sum(),
        detail: serde_json::json!({
            "workload": workload,
            "measured_blocks": blocks,
            "chain_height": height,
            "utxo_entries": utxo_entries,
            "log_bytes": log_bytes,
            "meta_json_bytes": meta_bytes,
            "tip_journal_bytes": journal_bytes,
            "store_dir_bytes": dir_bytes_total,
            "bytes_per_block": log_bytes / height.max(1),
            "stats_before": stats_before.json(),
            "stats_after": stats_after.json(),
            "available_parallelism": parallelism,
        }),
    });
    stages
}

fn print_usage() -> ! {
    eprintln!("usage: srct-bench run --workload empty|realistic|adversarial --blocks N --dir PATH [--json OUT] [--markdown OUT] [--max-rss-gb N]");
    eprintln!("       srct-bench persist-profile --blocks N --dir PATH [--json OUT]");
    std::process::exit(2);
}

/// Phase B micro-profile: isolate the per-block persist cost on a prebuilt
/// chain. Builds N empty blocks in memory once, then times 50 sequential
/// `set_tip` calls (the production persist path: fast-path link proof plus
/// batched journal append) against 50 plain `append_block` calls.
/// No consensus, storage-format or wire changes: all store calls are the
/// production `BlockStore` API on a scratch dir.
fn persist_profile(blocks: u64, dir: &Path) -> serde_json::Value {
    use std::time::Instant;
    let (mut chain, _, miner) = base_chain(1, 12);
    for _ in 0..blocks {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    let tip0 = chain.height();
    assert!(
        tip0 >= 112,
        "need a tall-enough chain for the walk to matter"
    );

    // Fresh store, all blocks appended once (not timed beyond setup).
    let store_dir = dir.join("store");
    let _ = std::fs::remove_dir_all(&store_dir);
    let (mut store, _) = srct_store::BlockStore::open(&store_dir, &NetworkParams::mini()).unwrap();
    for h in 1..=tip0 {
        let block = chain.block_at(h).unwrap();
        store.append_block(block).unwrap();
    }
    store.sync().unwrap();

    // set_tip per direct child on a tall chain: fast path verifies one link
    // per call, so this measures the O(1)-per-tip persist path directly
    // (compare against pre-Phase-B runs for the old full-walk cost).
    let t0 = Instant::now();
    for h in 1..=50u64 {
        let block = chain.block_at(h).unwrap();
        store.set_tip(&block.block_hash()).unwrap();
    }
    let set_tip_ms = t0.elapsed().as_millis();

    // append_block alone (no tip moves, no sync): fresh store, same blocks.
    let dir2 = dir.join("store2");
    let (mut store2, _) = srct_store::BlockStore::open(&dir2, &NetworkParams::mini()).unwrap();
    let t0 = Instant::now();
    for h in 1..=50u64 {
        let block = chain.block_at(h).unwrap();
        store2.append_block(block).unwrap();
    }
    let append_ms = t0.elapsed().as_millis();

    serde_json::json!({
        "blocks_indexed": tip0,
        "set_tip_50x_ms": set_tip_ms,
        "append_50x_ms": append_ms,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("persist-profile") {
        let mut blocks: u64 = 300;
        let mut dir = PathBuf::from("./target/bench-persist-profile");
        let mut json_out: Option<PathBuf> = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--blocks" => {
                    blocks = args
                        .get(i + 1)
                        .unwrap_or_else(|| print_usage())
                        .parse()
                        .unwrap_or_else(|_| print_usage());
                    i += 2;
                }
                "--dir" => {
                    dir = PathBuf::from(args.get(i + 1).unwrap_or_else(|| print_usage()));
                    i += 2;
                }
                "--json" => {
                    json_out = Some(PathBuf::from(
                        args.get(i + 1).unwrap_or_else(|| print_usage()),
                    ));
                    i += 2;
                }
                _ => print_usage(),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let detail = persist_profile(blocks, &dir);
        let doc =
            serde_json::json!({"tool": "srct-bench", "mode": "persist-profile", "detail": detail});
        let pretty = serde_json::to_string_pretty(&doc).unwrap();
        let json_path = json_out.unwrap_or_else(|| dir.join("results.json"));
        std::fs::write(&json_path, &pretty).unwrap();
        println!("{pretty}");
        return;
    }
    if args.get(1).map(|s| s.as_str()) != Some("run") {
        print_usage();
    }
    let mut workload = "realistic".to_string();
    let mut blocks: u64 = 200;
    let mut dir = PathBuf::from("./target/bench");
    let mut json_out: Option<PathBuf> = None;
    let mut md_out: Option<PathBuf> = None;
    // Optional safety budget in GiB: stop gracefully (partial results kept)
    // instead of pushing a small box into swap/OOM-killer territory.
    // Unset = no limit; unmeasurable platforms never trip it.
    let mut max_rss_bytes: Option<u64> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--workload" => {
                workload = args.get(i + 1).unwrap_or_else(|| print_usage()).clone();
                i += 2;
            }
            "--blocks" => {
                blocks = args
                    .get(i + 1)
                    .unwrap_or_else(|| print_usage())
                    .parse()
                    .unwrap_or_else(|_| print_usage());
                i += 2;
            }
            "--dir" => {
                dir = PathBuf::from(args.get(i + 1).unwrap_or_else(|| print_usage()));
                i += 2;
            }
            "--json" => {
                json_out = Some(PathBuf::from(
                    args.get(i + 1).unwrap_or_else(|| print_usage()),
                ));
                i += 2;
            }
            "--markdown" => {
                md_out = Some(PathBuf::from(
                    args.get(i + 1).unwrap_or_else(|| print_usage()),
                ));
                i += 2;
            }
            "--max-rss-gb" => {
                let gb: u64 = args
                    .get(i + 1)
                    .unwrap_or_else(|| print_usage())
                    .parse()
                    .unwrap_or_else(|_| print_usage());
                max_rss_bytes = Some(gb * 1024 * 1024 * 1024);
                i += 2;
            }
            _ => print_usage(),
        }
    }
    // The hardware-protection rule: benchmark data lives in a scratch dir,
    // never near real chain data or source trees. Refuse a --dir that looks
    // like a node data directory (blocks.log/meta.json/state.bin markers)
    // or like a repo/checkout (Cargo/rust markers) rather than a scratch dir.
    for marker in [
        "blocks.log",
        "meta.json",
        "state.bin",
        "tip.journal",
        "wallets",
        "Cargo.toml",
        "Cargo.lock",
        ".git",
        "crates",
        "src",
    ] {
        if dir.join(marker).exists() {
            eprintln!("refusing --dir {}: looks like real data or a source tree (found {marker}), not a scratch dir", dir.display());
            std::process::exit(2);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let stages = run_stages(&workload, blocks, &dir, max_rss_bytes);

    let rows: Vec<serde_json::Value> = stages
        .iter()
        .map(|s| {
            serde_json::json!({
                "workload": workload,
                "blocks": blocks,
                "stage": s.name,
                "wall_ms": s.wall_ms,
                "detail": s.detail,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "tool": "srct-bench",
        "workload": workload,
        "blocks": blocks,
        "note": "mini profile, deterministic seeds; no consensus/storage/wire changes",
        "stages": rows,
    });
    let pretty = serde_json::to_string_pretty(&doc).unwrap();
    let json_path = json_out.unwrap_or_else(|| dir.join("results.json"));
    std::fs::write(&json_path, &pretty).unwrap();

    let mut md = format!(
        "# srct-bench: {workload} x {blocks} blocks\n\nNo consensus, storage-format, validation or wire changes. Mini profile, deterministic seeds.\n\n| stage | wall_ms | detail |\n|---|---:|---|\n"
    );
    for s in &stages {
        md.push_str(&format!("| {} | {} | {} |\n", s.name, s.wall_ms, s.detail));
    }
    let md_path = md_out.unwrap_or_else(|| dir.join("report.md"));
    std::fs::write(&md_path, md).unwrap();
    println!("{pretty}");
    eprintln!("wrote {} and {}", json_path.display(), md_path.display());
    if stages.iter().any(|s| s.name == "aborted") {
        eprintln!("run aborted on --max-rss budget; partial results kept above");
        std::process::exit(2);
    }
}
