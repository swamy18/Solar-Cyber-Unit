//! The worker CLI — secret-free (SPEC.md §18, "CLI" item).
//!
//! Commands:
//!
//! - `address`   print the wallet's Solar Cyber Unit address (`jt1…`)
//! - `generate`  create a wallet file (0600-equivalent, operator-supplied path)
//! - `run`       the worker daemon loop: discover → claim → execute → submit,
//!   over a live node's REST API (§18.3). It uses the SDK's injected seams
//!   and the **production** `RealBls` verifier, so it exercises the same code
//!   path an operator's own integration would; it implements no consensus
//!   rule of its own. Before the first pass it gates on the node's live
//!   conservation report (`GET /v1/conservation`): this daemon moves real
//!   value, so a node reporting joint supply over the joint bound — or numbers that
//!   do not re-add — is refused rather than earned from.
//! - `verify-cert` check one verified-work certificate (`GET /v1/vwc/{task}`):
//!   quorum-backed or merely unchallenged. Read-only: no wallet, no key, no
//!   broadcast, so it cannot move a coin even when pointed at mainnet.
//!
//! `verify-cert` exit codes are its API (scripts decide on them, not on the
//! prose): `0` quorum-backed (verified), `2` window-elapsed (paid, **not**
//! verified), `3` no certificate (not settled `Correct`), `1` any error.
//!
//! No command ever prints a private key; `generate` writes the file and prints
//! only the path, and `run` logs task ids and errors but never key material
//! (§18.16).
//!
//! **Shutdown:** the `run` loop is bounded by `--iterations` for operators who
//! want that, and otherwise runs until the process is terminated. There is no
//! portable signal handler here (and the node's own `serve` loop has none
//! either); between passes nothing is left half-written, because every step in
//! a pass is a complete signed transaction broadcast to the node.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use srct_core::agent::{derive_agent_id, derive_sub_agent_id, AgentRole, PolicyBook, SpendPolicy};
use srct_core::bls::RealBls;
use srct_core::bls_checkpoint::ValidatorSet;
use srct_core::hash::{address_from_hex, address_to_hex, hash_to_hex, Hash};
use srct_core::l2::Auth;
use srct_core::params::NetworkParams;
use srct_core::service::derive_service_id;
use srct_worker::node::Host;
use srct_worker::{
    is_retryable, publish_policy, CpuExecutor, HttpNode, WorkerClient, WorkerConfig, WorkerError,
};

/// The concrete client the CLI builds: the HTTP transport serves as both the
/// read view and the broadcaster, and the CPU executor is the SDK's reference
/// engine.
type CliClient = WorkerClient<HttpNode, HttpNode, CpuExecutor>;

fn usage() -> String {
    "usage:
  srct-worker address  --from-file <path>
  srct-worker generate --out-file <path> [--label <label>]
  srct-worker run      --from-file <path> --node <base-url> [--network <name>]
                      [--iterations <n>] [--interval-ms <n>] [--max-tasks <n>]
                      [--deposit-sat <n>]

  srct-worker verify-cert --node <base-url> --task <task-id-hex> [--network <name>]
  srct-worker grant --from-file <path> --node <base-url> --spender <addr>
                       --per-tx <sat> --cumulative <sat> [--window <blocks>]
                       [--recipients <a,b>] [--services <tag-or-name,...>]
                       [--service-provider <addr>] [--role <role>]
                       [--parent <agent-hex>] [--not-before <h>] [--expires <h>]
                       [--network <name>]

  run defaults: --network mini, --iterations 0 (until stopped),
                --interval-ms 2000, --max-tasks 4, --deposit-sat 0

  run gates on GET /v1/conservation first: a node reporting joint supply
  over the joint bound (or unreadable numbers) is refused; an unreachable or
  non-reporting node warns and continues.

  srct-worker pay --node <base-url> --resource </path> --from-file <wallet>
                       --policy-hex <hex> --max-amount <sat> --recipients <a,b>
                       --service-name <name> [--service-provider <addr>]
                       [--expiry-blocks <n>] [--network <name>]
  srct-worker claim --node <base-url> --from-file <wallet> --task <task-id-hex>
                       [--deposit <sat>] [--network <name>]
  srct-worker submit-result --node <base-url> --from-file <wallet>
                       --task <task-id-hex> --result <hex|@file>
                       [--network <name>]
  srct-worker stream-open --node <base-url> --from-file <wallet> --to <addr>
                       --rate <sat/block> --cap <sat> --expires <h>
                       [--start <h>] [--payer-type <role>] [--policy-hash <hex>]
                       [--service-name <name>] [--service-provider <addr>]
                       [--network <name>]
  srct-worker stream-voucher --node <base-url> --from-file <wallet>
                       --stream-hex <hex> --through <h> [--reference <hex>]
                       [--network <name>]
  srct-worker stream-status --node <base-url> --stream <id-hex> [--network <name>]
  srct-worker batch-quote --node <base-url> --payments <id,...> [--network <name>]
  srct-worker trial-request --node <base-url> --agent <agent-hex> [--network <name>]
  srct-worker trial-fund --node <base-url> --agent <agent-hex> --txid <txid-hex>
                       [--network <name>]
  srct-worker trial-status --node <base-url> --agent <agent-hex> [--network <name>]
  srct-worker trial-repay --node <base-url> --agent <agent-hex> --txid <txid-hex>
  srct-worker treats-balance --node <base-url> --agent <agent-hex> [--role <role>]
                       [--network <name>]
  verify-cert defaults: --network mini.
  pay defaults: --network mini, --expiry-blocks 10 (guard caps the window at 30).
  verify-cert exits: 0 quorum-backed (verified), 2 window-elapsed (paid, not
                verified), 3 no certificate, 1 error — read-only, no wallet."
        .to_string()
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<i32, String> {
    let cmd = args.first().ok_or_else(usage)?;
    match cmd.as_str() {
        "--help" | "help" => {
            println!("{}", usage());
            Ok(0)
        }
        "address" => cmd_address(args),
        "generate" => cmd_generate(args),
        "run" => cmd_run(args),
        "grant" => cmd_grant(args),
        "pay" => cmd_pay(args),
        "claim" => cmd_claim(args),
        "submit-result" => cmd_submit_result(args),
        "stream-open" => cmd_stream_open(args),
        "stream-voucher" => cmd_stream_voucher(args),
        "stream-status" => cmd_stream_status(args),
        "batch-quote" => cmd_batch_quote(args),
        "trial-request" => cmd_trial_request(args),
        "trial-fund" => cmd_trial_fund(args),
        "trial-status" => cmd_trial_status(args),
        "trial-repay" => cmd_trial_repay(args),
        "treats-balance" => cmd_treats_balance(args),
        "verify-cert" => cmd_verify_cert(args),
        other => Err(format!("unknown command `{other}`\n{}", usage())),
    }
}

fn str_arg<'a>(args: &'a [String], name: &str) -> Option<&'a String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
}

fn cmd_address(args: &[String]) -> Result<i32, String> {
    let path = str_arg(args, "--from-file").ok_or("address needs --from-file <path>")?;
    let wallet = load_wallet(path)?;
    let addr = wallet
        .address()
        .map_err(|e| format!("wallet unusable: {e}"))?;
    println!("{}", srct_core::hash::address_to_hex(&addr));
    Ok(0)
}

fn cmd_generate(args: &[String]) -> Result<i32, String> {
    let out = str_arg(args, "--out-file").ok_or("generate needs --out-file <path>")?;
    let label = str_arg(args, "--label")
        .cloned()
        .unwrap_or_else(|| "worker".to_string());
    let wallet = srct_core::wallet::Wallet::new_random(label);
    let json =
        serde_json::to_string_pretty(&wallet).map_err(|e| format!("wallet encode failed: {e}"))?;
    // W1: this file holds a plaintext private key, so it must never be
    // world-readable — not even between creation and chmod. On Unix the mode
    // is set atomically at creation (`create_new` + `mode(0o600)` ignores the
    // umask for this file); the post-write `set_permissions` is a second
    // barrier, and its error is fatal rather than swallowed — a silent chmod
    // failure used to leave the key world-readable. On Windows the file
    // inherits the directory ACL, which the operator must place sensibly.
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true).mode(0o600);
        o.open(out)
            .map_err(|e| format!("cannot create {out}: {e}"))?
    };
    #[cfg(not(unix))]
    let mut file = {
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        o.open(out)
            .map_err(|e| format!("cannot create {out}: {e}"))?
    };
    file.write_all(json.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot restrict {out} to owner-only: {e}"))?;
    }
    // Print only the path. The key bytes now exist in exactly one operator-
    // controlled file and nowhere else in this process's output.
    println!("{}", out);
    Ok(0)
}

/// A u64 flag, or `default` when absent. A present-but-unparseable value is an
/// error rather than a silent fallback, so a typo cannot change the daemon's
/// behaviour behind the operator's back.
fn num_arg(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    match str_arg(args, name) {
        None => Ok(default),
        Some(v) => v.parse::<u64>().map_err(|e| format!("{name}: {e}")),
    }
}

/// First 12 hex chars of a hash, for legible logs. Never truncates fewer than
/// the string it has.
fn short(id: &Hash) -> String {
    let h = hash_to_hex(id);
    h[..12.min(h.len())].to_string()
}

/// The worker daemon loop (§18.3 transport, §18.4–§18.7 lifecycle).
fn cmd_run(args: &[String]) -> Result<i32, String> {
    let file = str_arg(args, "--from-file").ok_or("run needs --from-file <wallet>")?;
    let node_url = str_arg(args, "--node").ok_or("run needs --node <base-url>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;

    let iterations = num_arg(args, "--iterations", 0)?;
    let interval_ms = num_arg(args, "--interval-ms", 2_000)?;
    let max_tasks = num_arg(args, "--max-tasks", 4)?;
    let deposit_sat = num_arg(args, "--deposit-sat", 0)?;

    let wallet = load_wallet(file)?;
    let address = wallet
        .address()
        .map_err(|e| format!("wallet unusable: {e}"))?;
    let config = WorkerConfig::from_wallet(&wallet).with_deposit(deposit_sat);

    // Two independent transports: a view (reads) and a broadcaster (writes).
    // Neither sees the key — signing happens inside the client (§18.3). The
    // network id is checked by `for_network`, so a mini worker cannot be
    // pointed at a mainnet node by accident.
    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;

    // Conservation gate (SPEC §19.4–§19.5): value created anywhere — L1 or
    // L2 — turns every later payment into a claim on nothing, so the daemon
    // refuses to run against a node whose joint supply is broken. The three
    // verdicts are recomputed here from the report's own numbers rather than
    // trusted from its `ok` flag. An unreachable node, or one too old to
    // report, warns and continues: discovery's own retry loop is the right
    // handler for those. An answer that is wrong or unreadable is refused —
    // that node is answering, and cannot be trusted.
    match view.conservation() {
        Ok(Some(r)) if r.holds() => println!(
            "conservation  ok (joint {} of {} sat bound, headroom {})",
            r.joint_sat,
            r.joint_bound_sat,
            r.headroom_sat()
        ),
        Ok(Some(r)) => {
            return Err(format!(
                "conservation gate failed: joint {} of {} sat (l1 {} + l2 {} - sink {}), \
                 l2_closed {}, l2_funding_ok {} — refusing to run against this node",
                r.joint_sat, r.joint_bound_sat, r.l1_live_sat, r.l2_held_sat, r.sink_held_sat,
                r.l2_closed, r.l2_funding_ok
            ));
        }
        Ok(None) => eprintln!(
            "conservation  not reported by this node (older build?); continuing without the self-check"
        ),
        Err(WorkerError::ObservationUnavailable(why)) => {
            eprintln!("conservation  unavailable ({why}); continuing without the self-check")
        }
        Err(e) => return Err(format!("conservation gate could not read the node: {e}")),
    }

    let broadcaster =
        HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let host = Host::new(view, broadcaster);
    let validators = ValidatorSet::new(params.l2_settlement_validators.clone());
    let mut client = WorkerClient::new(host, wallet, CpuExecutor::default(), validators, &RealBls)
        .with_config(config)
        .map_err(|e| format!("worker config: {e}"))?;

    println!("worker         {}", address_to_hex(&address));
    println!("node           {node_url}");
    println!("network        {}", params.network_id);
    println!("max tasks/pass {max_tasks}");
    println!("deposit (sat)  {deposit_sat}");

    let mut pass: u64 = 0;
    loop {
        pass += 1;
        run_one_pass(&mut client, max_tasks, pass)?;
        if iterations != 0 && pass >= iterations {
            break;
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
    Ok(0)
}

/// One discovery → claim → execute → submit pass.
///
/// Task-local failures are logged and skipped: a task that expires mid-flight
/// must not stop the daemon, and a claim the protocol refused is information,
/// not a crash. Only a discovery failure that `is_retryable` rejects is fatal,
/// because at that point the node is answering but its answer is unusable.
fn run_one_pass(client: &mut CliClient, max_tasks: u64, pass: u64) -> Result<(), String> {
    let tasks = match client.discover() {
        Ok(t) => t,
        Err(e) if is_retryable(&e) => {
            eprintln!("pass {pass}: discovery unavailable, will retry: {e}");
            return Ok(());
        }
        Err(e) => return Err(format!("discovery failed, refusing to continue: {e}")),
    };
    println!("pass {pass}: {} claimable task(s)", tasks.len());

    for task in tasks.iter().take(max_tasks as usize) {
        let id = task.task_id;
        // A zero deposit never claims: the protocol refuses anything below
        // the settle fee. Treat `--deposit-sat 0` as "the on-chain minimum
        // for this task" so the daemon claims out of the box; an explicit
        // value is the operator's insurance override.
        if client.config.worker_deposit_sat == 0 {
            client.config.worker_deposit_sat = srct_core::l2::settle_fee_sat(task.payment_sat);
        }
        match client.claim(id) {
            Ok(_) => println!(
                "  claim   {} net={} sat",
                short(&id),
                task.net_payment_sat()
            ),
            Err(e) => {
                eprintln!("  claim   {} refused: {e}", short(&id));
                continue;
            }
        }
        match client.execute_and_submit(id) {
            Ok(_) => println!("  submit  {} ok", short(&id)),
            Err(e) => eprintln!("  submit  {} refused: {e}", short(&id)),
        }
    }
    Ok(())
}

/// Pay a paid resource over x402 with a client-side budget (SPEC.md §19.2).
///
/// The challenge/response shape, reused end to end: GET the resource, read the
/// `402` + `PAYMENT-REQUIRED` challenge, enforce the budget *before any key is
/// used*, sign the exact payment under the agent's grant, retry with
/// `PAYMENT-SIGNATURE`, print what the server returns. Read-only until the
/// final retry: nothing is signed until the budget passes.
///
/// The wallet must be the grant's owner (a self-grant: `build_signed_payment`
/// refuses a payer that is not the authorization's owner). The grant must name
/// the bought service — use `grant --services` for that. Exit `0` on `200`
/// with the resource body, `1` on any refusal.
fn cmd_pay(args: &[String]) -> Result<i32, String> {
    use srct_core::payment::build_signed_payment;
    use srct_core::service::{authorize_request, build_signed_request, RequestSpec};
    use srct_core::x402::{
        decode_required, encode_signature, parse_sat_amount, select_accept, X402Budget,
        X402Signature, X402SrctPayload, SRCT_SCHEME, X402_HEADER_REQUIRED, X402_HEADER_RESPONSE,
        X402_HEADER_SIGNATURE, X402_STATUS_PAYMENT_REQUIRED, X402_VERSION,
    };

    let node_url = str_arg(args, "--node").ok_or("pay needs --node <base-url>")?;
    let resource = str_arg(args, "--resource").ok_or("pay needs --resource </path>")?;
    let file = str_arg(args, "--from-file").ok_or("pay needs --from-file <wallet>")?;
    let policy_hex = str_arg(args, "--policy-hex").ok_or("pay needs --policy-hex <hex>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let wallet = load_wallet(file)?;
    let me = wallet
        .address()
        .map_err(|e| format!("wallet unusable: {e}"))?;

    let policy_bytes =
        hex::decode(policy_hex.trim()).map_err(|_| "pay: --policy-hex is not hex".to_string())?;
    let policy = SpendPolicy::deserialize(&policy_bytes)
        .map_err(|e| format!("pay: grant does not decode: {e}"))?;
    policy
        .validate()
        .map_err(|e| format!("pay: grant refused: {e}"))?;
    if derive_agent_id(&params.network_id, policy.role, &me) != policy.agent_id {
        return Err(
            "pay: this wallet is not the grant's owner — a self-grant pays for its own agent only"
                .into(),
        );
    }

    let max_amount = num_arg(args, "--max-amount", 0)?;
    if max_amount == 0 {
        return Err("--max-amount <sat> is required".into());
    }
    // Absent flag = unbounded recipients (None); a present flag is an
    // exact allow-list, exactly like `SpendPolicy` (empty = deny-all).
    let mut recipients: Option<Vec<[u8; 20]>> = None;
    if let Some(list) = str_arg(args, "--recipients") {
        let mut parsed = Vec::new();
        for part in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            parsed.push(address_from_hex(part).map_err(|e| format!("--recipients: {e}"))?);
        }
        recipients = Some(parsed);
    }
    let service_name = str_arg(args, "--service-name")
        .ok_or("pay needs --service-name <name> (the grant must name this service)")?;
    let expiry_blocks = num_arg(args, "--expiry-blocks", 10)?;
    if expiry_blocks == 0 || expiry_blocks > srct_core::x402::MAX_GUARD_LIFETIME_BLOCKS {
        return Err(format!(
            "--expiry-blocks must be 1..={} (the guard window cap)",
            srct_core::x402::MAX_GUARD_LIFETIME_BLOCKS
        ));
    }

    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;

    // 1. The challenge: a free resource answers 200 and there is nothing to pay.
    let (code, headers, body) = view
        .get_full(resource, &[])
        .map_err(|e| format!("could not reach resource: {e}"))?;
    if (200..300).contains(&code) {
        println!("{}", String::from_utf8_lossy(&body));
        return Ok(0);
    }
    if code != X402_STATUS_PAYMENT_REQUIRED {
        return Err(format!("resource answered {code}, not 200 or 402"));
    }
    let challenge = find_header(&headers, X402_HEADER_REQUIRED)
        .ok_or("402 without a PAYMENT-REQUIRED challenge")?;
    let required =
        decode_required(challenge).map_err(|e| format!("challenge does not decode: {e}"))?;

    // 2. Pick the cheapest SRCT offer inside the client budget. The recipient
    // comes from the offer itself; the service from --service-name scoped
    // under its provider (override with --service-provider).
    let provider_override = match str_arg(args, "--service-provider") {
        Some(h) => Some(address_from_hex(h).map_err(|e| format!("--service-provider: {e}"))?),
        None => None,
    };
    let mut chosen: Option<(srct_core::hash::Address, u64)> = None;
    let mut seen: Vec<srct_core::hash::Address> = Vec::new();
    for accept in &required.accepts {
        if accept.scheme != SRCT_SCHEME {
            continue;
        }
        if srct_core::x402::parse_srct_network(&accept.network).is_err() {
            continue;
        }
        let Ok(pay_to) = address_from_hex(&accept.pay_to) else {
            continue;
        };
        if seen.contains(&pay_to) {
            continue;
        }
        seen.push(pay_to);
        let provider = provider_override.unwrap_or(pay_to);
        let tag = derive_service_id(&params.network_id, &provider, service_name.as_bytes());
        let budget = X402Budget {
            max_amount_sat: max_amount,
            allowed_recipients: recipients.clone(),
            allowed_services: Some(vec![tag]),
        };
        let Ok(offer) = select_accept(&required, &budget, &pay_to, &Some(tag)) else {
            continue;
        };
        if offer.pay_to.to_lowercase() != hex::encode(pay_to).to_lowercase() {
            continue;
        }
        let Ok(amount) = parse_sat_amount(&offer.amount) else {
            continue;
        };
        match chosen {
            Some((_, best)) if best <= amount => {}
            _ => chosen = Some((pay_to, amount)),
        }
    }
    let Some((recipient, amount)) = chosen else {
        return Err("no x402 offer fits the budget — refusing to sign".into());
    };
    let provider = provider_override.unwrap_or(recipient);
    let tag = derive_service_id(&params.network_id, &provider, service_name.as_bytes());

    // 3. Guard + height from the node, nonce from the chain's own counter.
    let height = view
        .observe()
        .map_err(|e| format!("could not read node height: {e}"))?
        .height;
    let expires_at = height + expiry_blocks;
    let budget = X402Budget {
        max_amount_sat: max_amount,
        allowed_recipients: recipients,
        allowed_services: Some(vec![tag]),
    };
    budget
        .check_guarded(amount, &recipient, &Some(tag), height, expires_at)
        .map_err(|e| format!("budget refuses this payment: {e}"))?;
    let nonce = view
        .policy_last_nonce(&policy.agent_id)
        .map_err(|e| format!("could not read grant counter: {e}"))?
        .ok_or("grant not published yet — no live policy for this agent")?
        .checked_add(1)
        .ok_or("grant nonce exhausted")?;

    // 4. Sign the exact payment and retry with it. Nothing before this point
    // touched a key: every refusal above is free.
    let request = build_signed_request(
        &wallet,
        RequestSpec {
            network_id: params.network_id.clone(),
            payer_type: policy.role,
            service_id: tag,
            recipient,
            max_amount_sat: amount,
            expires_at_height: expires_at,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .map_err(|e| format!("request refused: {e}"))?;
    let mut book = PolicyBook::default();
    let auth = authorize_request(
        &mut book,
        &policy,
        &params.network_id,
        &request,
        height,
        nonce,
    )
    .map_err(|e| format!("grant refuses this payment: {e}"))?;
    let sigs = Auth::sigs_for(&wallet, &auth.signing_hash()).map_err(|e| format!("sign: {e}"))?;
    let keys = Auth::keys_for(&wallet).map_err(|e| format!("sign: {e}"))?;
    let payment = build_signed_payment(
        &wallet,
        &auth,
        &params.network_id,
        policy.role,
        0,
        expires_at,
        request.request_id(),
        &[],
    )
    .map_err(|e| format!("payment refused: {e}"))?;
    let envelope = X402Signature {
        x402_version: X402_VERSION,
        scheme: SRCT_SCHEME.to_string(),
        network: srct_core::x402::srct_network_caip2(&params.network_id)
            .ok_or("network id has no SRCT CAIP-2 mapping")?,
        payload: X402SrctPayload {
            payment_hex: hex::encode(payment.serialize()),
            authorization_hex: hex::encode(auth.serialize()),
            auth_sigs_hex: hex::encode(sigs.to_bytes()),
            auth_keys_hex: hex::encode(keys.to_bytes()),
        },
    };
    let sig_header = encode_signature(&envelope).map_err(|e| format!("envelope refused: {e}"))?;
    let (code, headers, body) = view
        .get_full(resource, &[(X402_HEADER_SIGNATURE.to_string(), sig_header)])
        .map_err(|e| format!("signed retry failed: {e}"))?;
    if !(200..300).contains(&code) {
        return Err(format!("server refused the signed payment with {code}"));
    }
    if let Some(resp) = find_header(&headers, X402_HEADER_RESPONSE) {
        println!("payment_response: {resp}");
    }
    println!("paid {amount} sat to {}", address_to_hex(&recipient));
    println!("{}", String::from_utf8_lossy(&body));
    Ok(0)
}

/// Claim one open task (SPEC.md §15). The worker's deposit comes from its own
/// L2 balance — a broke agent cannot claim, which is exactly what the trial
/// faucet (`POST /v1/trials/*`) exists to fix for first tasks. Without
/// `--deposit` the CLI posts exactly the on-chain minimum for the task
/// (the settle fee), so a plain `claim` works out of the box; pass more only
/// as a deliberate insurance decision. Broadcast is queued; re-running
/// `claim` names the claimant instead of double-claiming.
fn cmd_claim(args: &[String]) -> Result<i32, String> {
    use srct_worker::claim_task;

    let node_url = str_arg(args, "--node").ok_or("claim needs --node <base-url>")?;
    let file = str_arg(args, "--from-file").ok_or("claim needs --from-file <wallet>")?;
    let task_hex = str_arg(args, "--task").ok_or("claim needs --task <task-id-hex>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let wallet = load_wallet(file)?;
    let task_id = decode_task_hex(task_hex).map_err(|e| format!("--task: {e}"))?;

    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let deposit = match num_arg(args, "--deposit", 0)? {
        0 => {
            // The chain refuses a deposit below the settle fee, so the
            // default is the on-chain minimum for *this* task — read from
            // the canonical observed state (codec + conservation checked),
            // not the rendered task JSON. An explicit --deposit overrides
            // that minimum with a larger insurance deposit.
            let obs = view
                .observe()
                .map_err(|e| format!("could not read state: {e}"))?;
            let contract = obs.state.task(&task_id).ok_or("unknown task")?;
            srct_core::l2::settle_fee_sat(contract.payment_sat)
        }
        n => n,
    };
    let broadcaster =
        HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let mut host = Host::new(view, broadcaster);
    let config = WorkerConfig::from_wallet(&wallet).with_deposit(deposit);
    let plan = claim_task(&mut host, &wallet, &config, task_id)
        .map_err(|e| format!("claim refused: {e}"))?;
    println!("claimed     {}", hash_to_hex(&plan.task_id));
    println!("deposit     {deposit} sat");
    println!(
        "txid        {}",
        srct_core::hash::hash512_to_hex(&plan.txid)
    );
    println!(
        "execute the work, then: submit-result --task {} --result <hex|@file>",
        hash_to_hex(&plan.task_id)
    );
    Ok(0)
}

/// Submit a result the agent produced elsewhere — an AI framework, a robot
/// controller, any external engine. The bytes are attested as external
/// execution, hashed, signed and broadcast. The framework stays dumb about
/// keys; this command holds the only signing step.
fn cmd_submit_result(args: &[String]) -> Result<i32, String> {
    use srct_worker::node::{L2Broadcaster, L2NodeView};

    let node_url = str_arg(args, "--node").ok_or("submit-result needs --node <base-url>")?;
    let file = str_arg(args, "--from-file").ok_or("submit-result needs --from-file <wallet>")?;
    let task_hex = str_arg(args, "--task").ok_or("submit-result needs --task <task-id-hex>")?;
    let result_arg = str_arg(args, "--result").ok_or("submit-result needs --result <hex|@file>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let wallet = load_wallet(file)?;
    let task_id = decode_task_hex(task_hex).map_err(|e| format!("--task: {e}"))?;
    let output_bytes = if let Some(path) = result_arg.strip_prefix('@') {
        std::fs::read(path).map_err(|e| format!("--result file unreadable: {e}"))?
    } else {
        hex::decode(result_arg.trim())
            .map_err(|_| "submit-result: --result is not hex".to_string())?
    };
    if output_bytes.is_empty() {
        return Err("submit-result: empty result settles nothing".into());
    }

    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let broadcaster =
        HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let mut host = Host::new(view, broadcaster);
    let (state, height) = host
        .observe()
        .map_err(|e| format!("could not read node state: {e}"))?;
    let plan = srct_worker::submit_plan(
        &wallet,
        task_id,
        &output_bytes,
        srct_core::compute_ir::ComputeBackend::Unknown(EXTERNAL_BACKEND),
        &state,
        height,
    )
    .map_err(|e| format!("submit refused: {e}"))?;
    host.broadcast(&plan.tx)
        .map_err(|e| format!("broadcast refused: {e}"))?;
    println!(
        "submitted   {} result {}",
        hash_to_hex(&plan.task_id),
        hash_to_hex(&plan.result_hash)
    );
    println!(
        "txid        {}",
        srct_core::hash::hash512_to_hex(&plan.txid)
    );
    Ok(0)
}

/// Backend tag for results executed outside the reference executor (AI
/// frameworks, robot controllers). Recorded in the attestation, never
/// interpreted by consensus: verification always re-executes the reference.
const EXTERNAL_BACKEND: u8 = 0xFE;

/// Case-insensitive response header lookup. Header names on the wire vary in
/// case; the x402 contract must not depend on the server's capitalisation.
fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// POST and demand 2xx: on any other status the server's own named reason
/// (`error: detail`) becomes the error. Without this the node names the cause
/// and the CLI prints a transport paraphrase instead.
fn post_ok(
    view: &HttpNode,
    path: &str,
    body: &serde_json::Value,
    verb: &str,
) -> Result<serde_json::Value, String> {
    let (code, answer) = view
        .post_full(path, body)
        .map_err(|e| format!("{verb} failed: {e}"))?;
    if (200..300).contains(&code) {
        return Ok(answer);
    }
    let why = HttpNode::refusal_detail(&answer).unwrap_or_else(|| format!("HTTP {code}"));
    Err(format!("{verb} refused: {why}"))
}

/// Open a pay-as-you-use stream channel (SPEC.md §21, micro-payments).
///
/// The payer signs the open; the node records it without moving coins on
/// chain. Later `stream-voucher` calls mint exact off-chain receipts against
/// it, and only the final receipt needs an on-chain payment. Read the printed
/// `stream_hex` back into `stream-voucher --stream-hex`.
fn cmd_stream_open(args: &[String]) -> Result<i32, String> {
    use srct_core::stream::{build_stream, StreamOpenSpec};

    let node_url = str_arg(args, "--node").ok_or("stream-open needs --node <base-url>")?;
    let file = str_arg(args, "--from-file").ok_or("stream-open needs --from-file <wallet>")?;
    let to = str_arg(args, "--to").ok_or("stream-open needs --to <recipient>")?;
    let recipient = address_from_hex(to).map_err(|e| format!("--to: {e}"))?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let wallet = load_wallet(file)?;
    let rate = num_arg(args, "--rate", 0)?;
    let cap = num_arg(args, "--cap", 0)?;
    if rate == 0 {
        return Err("--rate <sat/block> is required".into());
    }
    if cap == 0 {
        return Err("--cap <sat> is required".into());
    }
    let expires = num_arg(args, "--expires", 0)?;
    if expires == 0 {
        return Err("--expires <height> is required".into());
    }
    let payer_type = match str_arg(args, "--payer-type")
        .map(String::as_str)
        .unwrap_or("machine")
    {
        "human" => AgentRole::Human,
        "machine" => AgentRole::Machine,
        "service" => AgentRole::Service,
        other => {
            return Err(format!(
                "--payer-type must be human, machine or service, got `{other}`"
            ))
        }
    };
    let policy_hash = match str_arg(args, "--policy-hash") {
        Some(h) => decode_task_hex(h).map_err(|e| format!("--policy-hash: {e}"))?,
        None => {
            if payer_type != AgentRole::Human {
                return Err(
                    "a non-human stream needs --policy-hash <hex> (the governing grant)".into(),
                );
            }
            [0u8; 32]
        }
    };
    let service = match str_arg(args, "--service-name") {
        Some(name) => {
            let provider = match str_arg(args, "--service-provider") {
                Some(h) => address_from_hex(h).map_err(|e| format!("--service-provider: {e}"))?,
                None => recipient,
            };
            Some(derive_service_id(
                &params.network_id,
                &provider,
                name.as_bytes(),
            ))
        }
        None => None,
    };

    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let start = match str_arg(args, "--start") {
        Some(h) => h
            .parse::<u64>()
            .map_err(|_| "--start must be a number".to_string())?,
        None => {
            view.observe()
                .map_err(|e| format!("could not read node height: {e}"))?
                .height
        }
    };
    let stream = build_stream(
        &wallet,
        StreamOpenSpec {
            network_id: params.network_id.clone(),
            payer_type,
            recipient,
            service,
            rate_sat_per_block: rate,
            start_height: start,
            expires_at_height: expires,
            max_total_sat: cap,
            nonce: 1,
            policy_hash,
        },
    )
    .map_err(|e| format!("stream refused: {e}"))?;
    let stream_hex = hex::encode(stream.serialize());
    let answer = post_ok(
        &view,
        "/v1/streams/open",
        &serde_json::json!({ "stream_hex": stream_hex }),
        "open",
    )?;
    let id = answer
        .get("stream_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("open answer has no stream_id")?;
    println!("stream_id   {id}");
    println!("stream_hex  {stream_hex}");
    println!("rate        {rate} sat/block, cap {cap} sat");
    println!("window      {start}..{expires}");
    println!("mint vouchers with: stream-voucher --stream-hex {stream_hex} --through <h>");
    Ok(0)
}

/// Mint the exact off-chain voucher for `through_height` and file it with the
/// node. Only the newly accrued amount settles — replaying an old height is
/// refused as nothing-new, and anything past expiry is refused outright.
fn cmd_stream_voucher(args: &[String]) -> Result<i32, String> {
    use srct_core::micro::voucher_spec;
    use srct_core::stream::{build_settlement, PaymentStream};

    let node_url = str_arg(args, "--node").ok_or("stream-voucher needs --node <base-url>")?;
    let file = str_arg(args, "--from-file").ok_or("stream-voucher needs --from-file <wallet>")?;
    let stream_hex =
        str_arg(args, "--stream-hex").ok_or("stream-voucher needs --stream-hex <hex>")?;
    let through = num_arg(args, "--through", 0)?;
    if through == 0 {
        return Err("--through <height> is required".into());
    }
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let wallet = load_wallet(file)?;

    let stream_bytes = hex::decode(stream_hex.trim())
        .map_err(|_| "stream-voucher: --stream-hex is not hex".to_string())?;
    let stream = PaymentStream::deserialize(&stream_bytes)
        .map_err(|e| format!("stream-voucher: stream does not decode: {e}"))?;
    if stream.network_id != params.network_id {
        return Err(format!(
            "stream-voucher: stream is for {}, node is {}",
            stream.network_id, params.network_id
        ));
    }
    let reference = match str_arg(args, "--reference") {
        Some(h) => decode_task_hex(h).map_err(|e| format!("--reference: {e}"))?,
        None => [0u8; 32],
    };

    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let status = view
        .get_json(&format!(
            "/v1/streams/{}",
            hex::encode(stream.signing_hash())
        ))
        .map_err(|e| format!("could not read stream status: {e}"))?;
    let settled = status
        .get("settled_sat")
        .and_then(serde_json::Value::as_u64)
        .ok_or("stream status has no settled_sat")?;
    let last_nonce = status
        .get("last_nonce")
        .and_then(serde_json::Value::as_u64)
        .ok_or("stream status has no last_nonce")?;
    let spec = voucher_spec(&stream, settled, last_nonce, through, reference)
        .map_err(|e| format!("voucher refused: {e}"))?;
    let settlement =
        build_settlement(&wallet, &stream, spec).map_err(|e| format!("voucher refused: {e}"))?;
    let amount = settlement.amount_sat;
    let nonce = settlement.nonce;
    post_ok(
        &view,
        "/v1/streams/settle",
        &serde_json::json!({
            "stream_hex": stream_hex.trim(),
            "settlement_hex": hex::encode(settlement.serialize()),
        }),
        "settle",
    )?;
    println!("settled     {amount} sat through height {through} (voucher {nonce})");
    println!("settle it on chain with a payment whose reference is the stream id");
    Ok(0)
}

/// Print a stream channel's accounting at the current height.
fn cmd_stream_status(args: &[String]) -> Result<i32, String> {
    let node_url = str_arg(args, "--node").ok_or("stream-status needs --node <base-url>")?;
    let id = str_arg(args, "--stream").ok_or("stream-status needs --stream <id-hex>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let sid = decode_task_hex(id).map_err(|e| format!("--stream: {e}"))?;
    let _ = sid;
    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let (code, status) = view
        .get_full_json(&format!("/v1/streams/{}", id.trim().to_lowercase()))
        .map_err(|e| format!("could not read stream: {e}"))?;
    if code == 404 {
        return Err("no such stream on this node".into());
    }
    if !(200..300).contains(&code) {
        let why = HttpNode::refusal_detail(&status).unwrap_or_else(|| format!("HTTP {code}"));
        return Err(format!("stream status refused: {why}"));
    }
    for key in [
        "stream_id",
        "recipient",
        "rate_sat_per_block",
        "max_total_sat",
        "settled_sat",
        "claimable_sat",
        "last_nonce",
        "settlements",
        "height",
    ] {
        if let Some(v) = status.get(key) {
            println!("{key:<20} {v}");
        }
    }
    Ok(0)
}

/// Price one shared settlement for N recorded payments (read-only).
fn cmd_batch_quote(args: &[String]) -> Result<i32, String> {
    let node_url = str_arg(args, "--node").ok_or("batch-quote needs --node <base-url>")?;
    let list = str_arg(args, "--payments").ok_or("batch-quote needs --payments <id,...>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let ids: Vec<String> = list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect();
    if ids.is_empty() || ids.len() > 256 {
        return Err("batch-quote needs 1..=256 payment ids".into());
    }
    for id in &ids {
        decode_task_hex(id).map_err(|e| format!("--payments: {e}"))?;
    }
    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let quote = post_ok(
        &view,
        "/v1/payments/aggregate",
        &serde_json::json!({ "payment_ids": ids }),
        "quote",
    )?;
    for key in [
        "payer",
        "payments",
        "total_amount_sat",
        "gas_used",
        "required_fee_sat",
        "fee_per_payment_sat",
        "separate_total_fee_sat",
        "savings_sat",
    ] {
        if let Some(v) = quote.get(key) {
            println!("{key:<24} {v}");
        }
    }
    Ok(0)
}

/// Usage-based credits: the trial faucet from the agent's side.
///
/// A broke agent cannot post a claim deposit, so its first task is unfundable.
/// `trial-request` records the trial, the sponsor pays the drip out of band,
/// `trial-fund` confirms the L1 payment against this node's chain, and
/// `trial-repay` confirms the payback the same way. One trial per agent, ever;
/// every refusal names its cause.
fn cmd_trial_request(args: &[String]) -> Result<i32, String> {
    let (view, agent) = trial_node(args, "trial-request")?;
    let answer = post_ok(
        &view,
        "/v1/trials/request",
        &serde_json::json!({ "agent_hex": hex::encode(agent) }),
        "trial request",
    )?;
    let state = answer
        .get("state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let amount = answer
        .get("amount_sat")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let sponsor = answer
        .get("sponsor")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    println!("trial       requested");
    println!("amount_sat  {amount}");
    println!("sponsor     {sponsor}");
    println!("state       {state}");
    println!("next: the sponsor pays {amount} sat to the agent, then trial-fund --txid <l1-txid>");
    Ok(0)
}

fn cmd_trial_fund(args: &[String]) -> Result<i32, String> {
    let (view, agent) = trial_node(args, "trial-fund")?;
    let txid = str_arg(args, "--txid").ok_or("trial-fund needs --txid <l1-txid-hex>")?;
    let answer = post_ok(
        &view,
        "/v1/trials/fund",
        &serde_json::json!({ "agent_hex": hex::encode(agent), "txid_hex": txid.trim().to_lowercase() }),
        "trial fund",
    )?;
    let state = answer
        .get("state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    println!("trial       funded ({state})");
    println!("next: deposit to the L2 sink, then claim tasks normally");
    Ok(0)
}

fn cmd_trial_status(args: &[String]) -> Result<i32, String> {
    let (view, agent) = trial_node(args, "trial-status")?;
    let (code, status) = view
        .get_full_json(&format!("/v1/trials/{}", hex::encode(agent)))
        .map_err(|e| format!("could not read trial: {e}"))?;
    if code == 404 {
        return Err("no trial recorded for this agent".into());
    }
    if !(200..300).contains(&code) {
        let why = HttpNode::refusal_detail(&status).unwrap_or_else(|| format!("HTTP {code}"));
        return Err(format!("trial status refused: {why}"));
    }
    for key in [
        "agent",
        "amount_sat",
        "sponsor",
        "state",
        "fund_txid",
        "repay_txid",
        "requested_height",
    ] {
        if let Some(v) = status.get(key) {
            println!("{key:<16} {v}");
        }
    }
    Ok(0)
}

fn cmd_trial_repay(args: &[String]) -> Result<i32, String> {
    let (view, agent) = trial_node(args, "trial-repay")?;
    let txid = str_arg(args, "--txid").ok_or("trial-repay needs --txid <l1-txid-hex>")?;
    let answer = post_ok(
        &view,
        "/v1/trials/repay",
        &serde_json::json!({ "agent_hex": hex::encode(agent), "txid_hex": txid.trim().to_lowercase() }),
        "trial repay",
    )?;
    let state = answer
        .get("state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    println!("trial       {state}");
    Ok(0)
}

fn cmd_treats_balance(args: &[String]) -> Result<i32, String> {
    let (view, agent) = trial_node(args, "treats-balance")?;
    let role = str_arg(args, "--role")
        .map(|s| s.as_str())
        .unwrap_or("machine");
    let (code, doc) = view
        .get_full_json(&format!(
            "/v1/treats/balance/{}?role={}",
            hex::encode(agent),
            role
        ))
        .map_err(|e| format!("could not read treats: {e}"))?;
    if !(200..300).contains(&code) {
        let why = HttpNode::refusal_detail(&doc).unwrap_or_else(|| format!("HTTP {code}"));
        return Err(format!("treats balance refused: {why}"));
    }
    for key in [
        "balance",
        "lifetime_earned",
        "lifetime_redeemed",
        "streak",
        "outstanding",
        "reserve_sat",
    ] {
        if let Some(v) = doc.get(key) {
            println!("{key:<16} {v}");
        }
    }
    Ok(0)
}

fn trial_node(args: &[String], verb: &str) -> Result<(HttpNode, [u8; 20]), String> {
    let node_url = str_arg(args, "--node").ok_or(format!("{verb} needs --node <base-url>"))?;
    let agent_hex = str_arg(args, "--agent").ok_or(format!("{verb} needs --agent <agent-hex>"))?;
    let agent_bytes =
        hex::decode(agent_hex.trim()).map_err(|_| format!("{verb}: --agent is not hex"))?;
    if agent_bytes.len() != 20 {
        return Err(format!(
            "{verb}: --agent must be 20 bytes (40 hex chars), got {}",
            agent_bytes.len()
        ));
    }
    let mut agent = [0u8; 20];
    agent.copy_from_slice(&agent_bytes);
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    Ok((view, agent))
}

/// Check one verified-work certificate (SPEC.md §17; the usable face of
/// `vwc::observe_verified_certificate`).
///
/// Read-only: no wallet is loaded, no key is touched, nothing is broadcast.
/// The exit code is the machine-readable verdict — `0` quorum-backed
/// (verified), `2` window-elapsed (paid, **not** verified), `3` no
/// certificate — so scripts decide on the code, not on the prose.
fn cmd_verify_cert(args: &[String]) -> Result<i32, String> {
    let node_url = str_arg(args, "--node").ok_or("verify-cert needs --node <base-url>")?;
    let task_hex = str_arg(args, "--task").ok_or("verify-cert needs --task <task-id-hex>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let task_id = decode_task_hex(task_hex)?;

    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let cert = view
        .vwc(&task_id)
        .map_err(|e| format!("could not read certificate: {e}"))?;
    let Some(cert) = cert else {
        println!(
            "no certificate: task {} has no Correct settlement (open, disputed, fraudulent, or expired)",
            task_hex.to_lowercase()
        );
        return Ok(3);
    };

    println!("task            {}", hash_to_hex(&cert.task_id));
    println!("worker          {}", address_to_hex(&cert.worker));
    println!("result          {}", hash_to_hex(&cert.result_hash));
    println!("settled_height  {}", cert.settled_height);
    println!("payment_sat     {}", cert.payment_sat);
    println!(
        "offline_checkable {}",
        cert.verification.is_offline_verifiable()
    );
    match &cert.verification {
        srct_l2::VwcVerification::Quorum { signer_count, .. } => {
            println!("kind            quorum (signers: {signer_count})");
            // The same committee the daemon verifies against: the profile's
            // declared settlement set. A quorum that does not verify here is
            // refused, never presented as evidence.
            let validators = ValidatorSet::new(params.l2_settlement_validators.clone());
            if let Err(e) = cert.validate(&validators, &RealBls) {
                return Err(format!(
                    "quorum certificate does NOT validate ({e}): do not trust it"
                ));
            }
            println!("verdict: QUORUM-BACKED — the result was verified by committee quorum");
            Ok(0)
        }
        srct_l2::VwcVerification::WindowElapsed => {
            println!("kind            window_elapsed");
            println!("verdict: NOT verification — nobody challenged in time, which says nothing about whether the result is correct");
            Ok(2)
        }
    }
}

/// A 32-byte task id from hex. Anything else is refused: a truncated id that
/// silently matched nothing would turn "no certificate" into a lie.
fn decode_task_hex(hex_str: &str) -> Result<Hash, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| format!("--task is not hex: {hex_str}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "--task must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Grant one agent a bounded spending authority and publish it (SPEC.md §21).
///
/// The caller is the owner: `--from-file` names the wallet whose address funds
/// the grant. Remote-first — unlike the node's `policy` command this needs no
/// local chain data, only a node URL to broadcast through. The transaction is
/// queued for the next block; the grant goes live once mined, not when this
/// command returns.
///
/// Service tags are provider-bound (`derive_service_id`): each `--services`
/// entry is either a 32-byte hex tag or a plain service *name*, in which case
/// `--service-provider` must name the provider whose address the name is
/// scoped under. An empty recipient list authorises nothing.
fn cmd_grant(args: &[String]) -> Result<i32, String> {
    let file = str_arg(args, "--from-file").ok_or("grant needs --from-file <owner wallet>")?;
    let node_url = str_arg(args, "--node").ok_or("grant needs --node <base-url>")?;
    let spender_hex = str_arg(args, "--spender").ok_or("grant needs --spender <address>")?;
    let spender = address_from_hex(spender_hex).map_err(|e| format!("--spender: {e}"))?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;
    let wallet = load_wallet(file)?;
    let owner = wallet
        .address()
        .map_err(|e| format!("wallet unusable: {e}"))?;

    let role = match str_arg(args, "--role")
        .map(String::as_str)
        .unwrap_or("machine")
    {
        "human" => AgentRole::Human,
        "machine" => AgentRole::Machine,
        "service" => AgentRole::Service,
        other => {
            return Err(format!(
                "--role must be human, machine or service, got `{other}`"
            ))
        }
    };
    let parent = match str_arg(args, "--parent") {
        Some(h) => Some(decode_agent_hex(h)?),
        None => None,
    };
    let agent_id = match parent {
        Some(p) => derive_sub_agent_id(&params.network_id, &p, role),
        None => derive_agent_id(&params.network_id, role, &owner),
    };
    let mut recipients = Vec::new();
    if let Some(list) = str_arg(args, "--recipients") {
        for part in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            recipients.push(address_from_hex(part).map_err(|e| format!("--recipients: {e}"))?);
        }
    }
    let services = parse_service_tags(args, &params.network_id, str_arg(args, "--services"))?;

    let per_tx = num_arg(args, "--per-tx", 0)?;
    let window = num_arg(args, "--window", 100)?;
    let cumulative = num_arg(args, "--cumulative", 0)?;
    if per_tx == 0 {
        return Err("--per-tx <sat> is required".into());
    }
    if cumulative == 0 {
        return Err("--cumulative <sat> is required".into());
    }
    let not_before = num_arg(args, "--not-before", 0)?;
    let expires = num_arg(args, "--expires", u64::MAX)?;

    let policy = SpendPolicy {
        version: srct_core::agent::POLICY_VERSION,
        network_id: params.network_id.clone(),
        agent_id,
        owner,
        role,
        per_tx_max_sat: per_tx,
        window_blocks: window,
        cumulative_max_sat: cumulative,
        allowed_recipients: recipients,
        allowed_services: services,
        not_before_height: not_before,
        expires_at_height: expires,
        revoked: false,
        parent_agent_id: parent,
    };
    policy
        .validate()
        .map_err(|e| format!("grant refused: {e}"))?;

    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let broadcaster =
        HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let mut host = Host::new(view, broadcaster);
    let plan = publish_policy(&mut host, &wallet, &policy, spender)
        .map_err(|e| format!("grant not admitted: {e}"))?;

    println!("policy      {}", hash_to_hex(&plan.policy_hash));
    println!("policy_hex  {}", hex::encode(policy.serialize()));
    if plan.policy_hash != policy.hash() {
        return Err("internal: published grant hash disagrees with the built policy".into());
    }
    println!("agent       {}", address_to_hex(&agent_id));
    println!("spender     {}", address_to_hex(&spender));
    println!("per-tx      {per_tx} sat");
    println!("cumulative  {cumulative} sat per {window} blocks");
    println!(
        "txid        {}",
        srct_core::hash::hash512_to_hex(&plan.txid)
    );
    println!("queued for the next block; the grant goes live once mined");
    Ok(0)
}

/// Service allow-list entries: a 64-hex-char tag is used as-is; anything else
/// is a service *name* resolved under `--service-provider` via
/// `derive_service_id`, because a bare name claims no provider.
fn parse_service_tags(
    args: &[String],
    network_id: &str,
    list: Option<&String>,
) -> Result<Vec<[u8; 32]>, String> {
    let Some(list) = list else {
        return Ok(Vec::new());
    };
    let provider = match str_arg(args, "--service-provider") {
        Some(h) => Some(address_from_hex(h).map_err(|e| format!("--service-provider: {e}"))?),
        None => None,
    };
    let mut out = Vec::new();
    for part in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if part.len() == 64 {
            let bytes = hex::decode(part).map_err(|_| format!("--services: bad tag `{part}`"))?;
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&bytes);
            out.push(tag);
        } else {
            let Some(p) = provider else {
                return Err(format!(
                    "--services: `{part}` is a name, not a tag — pass --service-provider <addr> so it can be scoped"
                ));
            };
            out.push(derive_service_id(network_id, &p, part.as_bytes()));
        }
    }
    Ok(out)
}

/// A 20-byte agent id from hex.
fn decode_agent_hex(hex_str: &str) -> Result<srct_core::hash::Address, String> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|_| format!("--parent is not hex: {hex_str}"))?;
    if bytes.len() != 20 {
        return Err(format!(
            "--parent must be 20 bytes (40 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn load_wallet(path: &str) -> Result<srct_core::wallet::Wallet, String> {
    let text =
        fs::read_to_string(PathBuf::from(path)).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path} is not a wallet file: {e}"))
}
