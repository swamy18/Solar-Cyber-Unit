//! CLI-level tests for the `srct-worker` binary, focused on the `run` verb.
//!
//! These spawn the real binary through `CARGO_BIN_EXE_srct-worker`, so they cover
//! argument parsing, the usage text, the transport's failure mode, and — the
//! part that matters most — that no code path renders the private key.
//!
//! They deliberately do **not** test the successful claim/submit path: that
//! needs a live node, and it is already covered end-to-end by
//! `srct-node/tests/e2e_two_process.rs` and `worker_transport.rs`, which drive a
//! real `WorkerClient` over a real socket.
//!
//! The conservation gate is tested here against a **fake node** (a canned
//! `/v1/conservation` body, 404 for everything else): a report whose joint
//! supply exceeds the cap and a report that is not readable JSON are both
//! refused with a non-zero exit, while a healthy report passes the gate and
//! the daemon moves on to discovery.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_srct-worker");

/// A per-process temp path, so parallel test binaries cannot collide.
fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("srct-worker-cli-{}-{name}", std::process::id()))
}

/// Run the binary and return `(exit_code, stdout, stderr)`.
fn exec(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn srct-worker");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A loopback port nothing is listening on: bind, read the port, drop it.
fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// A healthy `/v1/conservation` body: 10 + 1000 − 0 re-adds to 1010, well
/// under the 10000 joint bound, both L2 checks true.
const HEALTHY_REPORT: &str = concat!(
    r#"{"ok":true,"l2_closed":true,"l2_funding_ok":true,"#,
    r#""joint_sat":1010,"joint_bound_sat":10000,"headroom_sat":8990,"#,
    r#""l1_live_sat":10,"l2_held_sat":1000,"sink_held_sat":0,"#,
    r#""network_id":"srct/mini","height":3}"#
);

/// A broken body: the terms re-add (101 + 0 − 0), but joint 101 > bound 100.
const BROKEN_REPORT: &str = concat!(
    r#"{"ok":false,"l2_closed":true,"l2_funding_ok":true,"#,
    r#""joint_sat":101,"joint_bound_sat":100,"headroom_sat":0,"#,
    r#""l1_live_sat":101,"l2_held_sat":0,"sink_held_sat":0,"#,
    r#""network_id":"srct/mini","height":3}"#
);

/// A fake node: serves the canned conservation body for `/v1/conservation`
/// and 404 for everything else, for a bounded number of connections so the
/// listener thread always ends.
fn fake_node(conservation_body: &str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let body = conservation_body.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let response = if request.starts_with("GET /v1/conservation ") {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn help_lists_the_run_verb_and_its_required_flag() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("run"), "usage must document `run`:\n{out}");
    assert!(out.contains("--node"), "usage must document --node:\n{out}");
}

#[test]
fn run_without_a_node_url_fails_and_names_the_missing_flag() {
    let wallet = tmp("missing-node.json");
    let (code, _, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--iterations",
        "1",
    ]);
    assert_ne!(code, 0, "a missing --node must fail, not silently succeed");
    assert!(
        err.contains("--node"),
        "the refusal must name the missing flag: {err}"
    );
}

/// Generate a wallet at `wallet` and return its private-key hex — the one
/// secret these tests must never see rendered back.
fn make_wallet(wallet: &PathBuf) -> String {
    let _ = std::fs::remove_file(wallet);
    let (code, _, err) = exec(&[
        "generate",
        "--out-file",
        wallet.to_str().unwrap(),
        "--label",
        "cli-gate",
    ]);
    assert_eq!(code, 0, "generate failed: {err}");
    let raw = std::fs::read_to_string(wallet).expect("wallet file");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("wallet is JSON");
    v["private_key"]
        .as_str()
        .expect("private_key field")
        .to_string()
}

/// W1: a generated wallet holds a plaintext private key, so the file must be
/// owner-only from creation — never 0644, not even briefly. Unix-only: on
/// Windows the file inherits the directory ACL instead.
#[cfg(unix)]
#[test]
fn generated_wallet_file_is_owner_only_from_creation() {
    use std::os::unix::fs::PermissionsExt;
    let wallet = tmp("perm-owner-only.json");
    let _ = std::fs::remove_file(&wallet);
    let (code, _, err) = exec(&[
        "generate",
        "--out-file",
        wallet.to_str().unwrap(),
        "--label",
        "perm-check",
    ]);
    assert_eq!(code, 0, "generate failed: {err}");
    let mode = std::fs::metadata(&wallet).expect("wallet file").permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "W1: generated wallet must be 0600, got {mode:o}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn run_refuses_a_node_whose_joint_supply_exceeds_the_cap() {
    let wallet = tmp("gate-broken.json");
    let secret = make_wallet(&wallet);
    let url = format!("http://127.0.0.1:{}", fake_node(BROKEN_REPORT));

    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    assert_ne!(code, 0, "a node reporting inflation must be refused: {out}");
    assert!(
        err.contains("conservation"),
        "the refusal must name conservation: {err}"
    );
    assert!(
        err.contains("101") && err.contains("100"),
        "the refusal must name the joint figure and the cap: {err}"
    );
    assert!(
        !out.contains(&secret) && !err.contains(&secret),
        "the private key must never render; stdout={out}\nstderr={err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn run_refuses_an_unreadable_conservation_answer() {
    let wallet = tmp("gate-garbage.json");
    let _ = make_wallet(&wallet);
    let url = format!("http://127.0.0.1:{}", fake_node("this is not json"));

    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    assert_ne!(
        code, 0,
        "a node answering garbage on the gate endpoint must be refused: {out}"
    );
    assert!(
        err.contains("conservation"),
        "the refusal must name the gate: {err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn run_passes_the_gate_on_a_healthy_node_and_moves_on_to_discovery() {
    let wallet = tmp("gate-healthy.json");
    let secret = make_wallet(&wallet);
    let url = format!("http://127.0.0.1:{}", fake_node(HEALTHY_REPORT));

    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    // The gate passes and the daemon proceeds: discovery then hits the fake
    // node's 404 for `/v1/l2/state`, which is retryable, so the bounded run
    // still exits cleanly — with the gate's own line visible on stdout.
    assert_eq!(code, 0, "unexpected exit: stdout={out}\nstderr={err}");
    assert!(
        out.contains("conservation  ok"),
        "the gate's pass must be visible to the operator: {out}"
    );
    assert!(
        err.contains("will retry"),
        "the retryable path must be visible: {err}"
    );
    assert!(
        !out.contains(&secret) && !err.contains(&secret),
        "the private key must never render; stdout={out}\nstderr={err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn run_against_an_unreachable_node_retries_cleanly_and_never_prints_key_material() {
    let wallet = tmp("cli-run-wallet.json");
    let _ = std::fs::remove_file(&wallet);
    let (code, _, err) = exec(&[
        "generate",
        "--out-file",
        wallet.to_str().unwrap(),
        "--label",
        "cli-test",
    ]);
    assert_eq!(code, 0, "generate failed: {err}");

    // The wallet file's only secret is `private_key`; capture it verbatim.
    let raw = std::fs::read_to_string(&wallet).expect("wallet file");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("wallet is JSON");
    let secret = v["private_key"]
        .as_str()
        .expect("private_key field")
        .to_string();
    assert_eq!(secret.len(), 64, "a 32-byte key is 64 hex chars");

    let url = format!("http://127.0.0.1:{}", closed_port());
    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    // A transient transport failure is retryable, so a bounded run still exits
    // cleanly — and it says so on stderr rather than panicking.
    assert_eq!(code, 0, "unexpected exit: stdout={out}\nstderr={err}");
    assert!(
        err.contains("will retry"),
        "the retryable path must be visible to the operator: {err}"
    );

    assert!(
        !out.contains(&secret) && !err.contains(&secret),
        "the private key must never render; stdout={out}\nstderr={err}"
    );

    let _ = std::fs::remove_file(&wallet);
}

// ---- verify-cert: the read-only certificate checker. No wallet, no key, no
// broadcast — so these tests need no secrets at all, only a fake node.

/// A fake node that serves one canned `/v1/vwc/{task}` body and 404s the rest.
fn fake_vwc_node(task_hex: &str, vwc_body: &str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let want = format!("GET /v1/vwc/{task_hex} ");
    let body = vwc_body.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let response = if request.starts_with(&want) {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

fn window_elapsed_body(task: &[u8; 32]) -> String {
    let cert = srct_l2::VerifiedWorkCertificate::from_settlement(
        *task,
        [9u8; 20],
        [11u8; 32],
        42,
        5000,
        srct_l2::VwcVerification::WindowElapsed,
    )
    .expect("a window-elapsed cert builds without keys");
    format!("{{\"vwc_hex\":\"{}\"}}", hex::encode(cert.encode()))
}

fn forged_quorum_body(task: &[u8; 32]) -> String {
    // Well-formed bytes, forged aggregate: a zero signature never verifies
    // under RealBls, so the checker must refuse it rather than present it.
    let cert = srct_l2::VerifiedWorkCertificate::from_settlement(
        *task,
        [9u8; 20],
        [11u8; 32],
        42,
        5000,
        srct_l2::VwcVerification::Quorum {
            bls_sig: [0u8; 96],
            signer_bitmap: vec![0x01],
            signer_count: 1,
            pq_sidecar: vec![],
            network_id: "srct/mini".to_string(),
            vote_height: 1,
        },
    )
    .expect("a forged quorum cert still encodes");
    format!("{{\"vwc_hex\":\"{}\"}}", hex::encode(cert.encode()))
}

#[test]
fn verify_cert_help_names_the_verb_and_its_exit_codes() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("verify-cert"),
        "usage must document verify-cert:\n{out}"
    );
    assert!(out.contains("--task"), "usage must document --task:\n{out}");
}

#[test]
fn verify_cert_without_flags_fails_and_names_what_is_missing() {
    let (code, _, err) = exec(&["verify-cert", "--node", "http://127.0.0.1:9"]);
    assert_ne!(code, 0, "a missing --task must fail, not silently succeed");
    assert!(
        err.contains("--task"),
        "the refusal must name --task: {err}"
    );
}

#[test]
fn verify_cert_reports_no_certificate_with_exit_3() {
    let task = [7u8; 32];
    let other = [8u8; 32];
    let url = format!(
        "http://127.0.0.1:{}",
        fake_vwc_node(&hex::encode(task), &window_elapsed_body(&task))
    );
    let (code, out, _) = exec(&[
        "verify-cert",
        "--node",
        &url,
        "--task",
        &hex::encode(other),
        "--network",
        "mini",
    ]);
    assert_eq!(code, 3, "an unknown task must exit 3, not 0: {out}");
    assert!(
        out.contains("no certificate"),
        "the answer must say so: {out}"
    );
}

#[test]
fn verify_cert_refuses_a_window_elapsed_certificate_with_exit_2() {
    let task = [7u8; 32];
    let url = format!(
        "http://127.0.0.1:{}",
        fake_vwc_node(&hex::encode(task), &window_elapsed_body(&task))
    );
    let (code, out, _) = exec(&[
        "verify-cert",
        "--node",
        &url,
        "--task",
        &hex::encode(task),
        "--network",
        "mini",
    ]);
    assert_eq!(code, 2, "window-elapsed is paid, not verified: {out}");
    assert!(
        out.contains("window_elapsed"),
        "the kind must be explicit: {out}"
    );
    assert!(
        out.contains("NOT verification"),
        "the verdict must not be mistakable for proof: {out}"
    );
}

#[test]
fn verify_cert_refuses_a_forged_quorum_aggregate() {
    let task = [7u8; 32];
    let url = format!(
        "http://127.0.0.1:{}",
        fake_vwc_node(&hex::encode(task), &forged_quorum_body(&task))
    );
    let (code, _, err) = exec(&[
        "verify-cert",
        "--node",
        &url,
        "--task",
        &hex::encode(task),
        "--network",
        "mini",
    ]);
    assert_ne!(code, 0, "a forged quorum must never exit 0");
    assert!(
        err.contains("does NOT validate"),
        "the refusal must say the aggregate failed: {err}"
    );
}

// ---- grant: one command from owner key to a published spending authority.

// A fake node that serves one funded `/v1/l2/state` and accepts the broadcast.
fn fake_grant_node(owner: &[u8; 20]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let mut state = srct_l2::L2State::new(srct_l2::L2Config::mini());
    state.credit(*owner, 1_000_000).expect("fund owner");
    let state_hex = hex::encode(state.encode());
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 32768];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let response = if request.starts_with("GET /v1/l2/state ") {
                let body = format!(
                    "{{\"network_id\":\"srct/mini\",\"height\":5,\"state_hex\":\"{state_hex}\"}}"
                );
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else if request.starts_with("POST /v1/l2/broadcast ") {
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string()
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

/// Write an owner wallet file directly (not through the binary): the grant
/// tool takes a file, and this keeps the test hermetic.
fn owner_wallet(path: &PathBuf) -> [u8; 20] {
    let _ = std::fs::remove_file(path);
    let wallet = srct_core::wallet::Wallet::new_random("grant-owner".to_string());
    let addr = wallet.address().expect("fresh wallet has an address");
    let json = serde_json::to_string_pretty(&wallet).expect("wallet is JSON");
    std::fs::write(path, json).expect("wallet file");
    addr
}

#[test]
fn grant_help_names_the_verb_and_its_limits() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("grant"), "usage must document grant:\n{out}");
    assert!(
        out.contains("--per-tx"),
        "usage must document --per-tx:\n{out}"
    );
    assert!(
        out.contains("--spender"),
        "usage must document --spender:\n{out}"
    );
}

#[test]
fn grant_without_a_spender_fails_and_names_it() {
    let wallet = tmp("grant-missing.json");
    let _ = owner_wallet(&wallet);
    let (code, _, err) = exec(&[
        "grant",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        "http://127.0.0.1:9",
        "--per-tx",
        "1000",
        "--cumulative",
        "5000",
    ]);
    assert_ne!(code, 0, "a missing --spender must fail");
    assert!(
        err.contains("--spender"),
        "the refusal must name --spender: {err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn grant_refuses_a_policy_wider_than_its_own_caps() {
    let wallet = tmp("grant-wide.json");
    let _ = owner_wallet(&wallet);
    let (code, _, err) = exec(&[
        "grant",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        "http://127.0.0.1:9",
        "--spender",
        &hex::encode([5u8; 20]),
        "--per-tx",
        "9000",
        "--cumulative",
        "5000",
        "--network",
        "mini",
    ]);
    assert_ne!(
        code, 0,
        "per-tx above cumulative must fail before any network use"
    );
    assert!(
        err.contains("grant refused"),
        "the refusal must say so: {err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn grant_publishes_a_bounded_authority_through_a_node() {
    let wallet = tmp("grant-ok.json");
    let owner = owner_wallet(&wallet);
    let url = format!("http://127.0.0.1:{}", fake_grant_node(&owner));
    let spender = hex::encode([5u8; 20]);
    let recipient = hex::encode([6u8; 20]);
    let (code, out, err) = exec(&[
        "grant",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--spender",
        &spender,
        "--per-tx",
        "1000",
        "--cumulative",
        "5000",
        "--window",
        "50",
        "--recipients",
        &recipient,
        "--network",
        "mini",
    ]);
    assert_eq!(
        code, 0,
        "a bounded grant must publish: stdout={out}\nstderr={err}"
    );
    assert!(out.contains("policy"), "the grant hash must print: {out}");
    assert!(
        out.contains("queued"),
        "the grant is queued, not instantly live: {out}"
    );
    let _ = std::fs::remove_file(&wallet);
}

// ---- pay: the x402 challenge/response round trip with a client-side budget.
// Read-only until the final retry: every refusal above names its cause and no
// key is used before the budget passes.

/// A fake paid resource. Serves the 402 challenge until the request carries a
/// `PAYMENT-SIGNATURE` header, then serves the paid body — plus the funded
/// state and the grant counter the client reads before signing.
fn fake_pay_node(
    state_hex: &str,
    agent_hex: &str,
    challenge_b64: Option<&str>,
    paid_body: &str,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let state_hex = state_hex.to_string();
    let agent_hex = agent_hex.to_string();
    let challenge = challenge_b64.map(str::to_string);
    let paid = paid_body.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(16) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 65536];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let response = if request.starts_with("GET /v1/l2/state ") {
                let body = format!(
                    "{{\"network_id\":\"srct/mini\",\"height\":5,\"state_hex\":\"{state_hex}\"}}"
                );
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else if request.starts_with(&format!("GET /v1/policies/{agent_hex} ")) {
                let body = "{\"last_nonce\":0}".to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else if request.starts_with("GET /v1/paid/weather ") {
                if request.contains("PAYMENT-SIGNATURE:") {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nPAYMENT-RESPONSE: ok\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        paid.len(),
                        paid
                    )
                } else if let Some(ch) = &challenge {
                    let body = "{\"error\":\"payment required\"}".to_string();
                    format!(
                        "HTTP/1.1 402 Payment Required\r\nPAYMENT-REQUIRED: {ch}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        paid.len(),
                        paid
                    )
                }
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

fn pay_grant(owner: &[u8; 20], recipient: &[u8; 20], service: &[u8; 32]) -> (String, String) {
    use srct_core::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: "srct/mini".to_string(),
        agent_id: derive_agent_id("srct/mini", AgentRole::Machine, owner),
        owner: *owner,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![*recipient],
        allowed_services: vec![*service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    (
        hex::encode(policy.serialize()),
        hex::encode(policy.agent_id),
    )
}

fn pay_challenge(amount: u64, pay_to: &[u8; 20]) -> String {
    use srct_core::x402::{build_required, encode_required};
    let required = build_required(
        "srct/mini",
        amount,
        hex::encode(pay_to),
        "/v1/paid/weather".to_string(),
        "Demo paid weather".to_string(),
    )
    .expect("challenge builds");
    encode_required(&required).expect("challenge encodes")
}

fn pay_owner(path: &PathBuf) -> ([u8; 20], String) {
    let _ = std::fs::remove_file(path);
    let wallet = srct_core::wallet::Wallet::new_random("pay-owner".to_string());
    let addr = wallet.address().expect("fresh wallet has an address");
    let json = serde_json::to_string_pretty(&wallet).expect("wallet is JSON");
    std::fs::write(path, json).expect("wallet file");
    let mut a = [0u8; 20];
    a.copy_from_slice(&addr);
    (a, hex::encode(addr))
}

#[test]
fn pay_help_names_the_verb_and_the_budget_flags() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("pay"), "usage must document pay:\n{out}");
    assert!(
        out.contains("--policy-hex"),
        "usage must document --policy-hex:\n{out}"
    );
    assert!(
        out.contains("--max-amount"),
        "usage must document --max-amount:\n{out}"
    );
}

#[test]
fn pay_refuses_a_challenge_over_budget_without_signing() {
    let wallet = tmp("pay-greedy.json");
    let (owner, _) = pay_owner(&wallet);
    let provider = [4u8; 20];
    let service = srct_core::service::derive_service_id("srct/mini", &provider, b"weather");
    let (policy_hex, _) = pay_grant(&owner, &provider, &service);
    let mut state = srct_l2::L2State::new(srct_l2::L2Config::mini());
    state.credit(owner, 1_000_000).expect("fund owner");
    let url = format!(
        "http://127.0.0.1:{}",
        fake_pay_node(
            &hex::encode(state.encode()),
            &hex::encode([0u8; 20]),
            Some(&pay_challenge(5_000, &provider)),
            "{}",
        )
    );
    let (code, _, err) = exec(&[
        "pay",
        "--node",
        &url,
        "--resource",
        "/v1/paid/weather",
        "--from-file",
        wallet.to_str().unwrap(),
        "--policy-hex",
        &policy_hex,
        "--max-amount",
        "600",
        "--recipients",
        &hex::encode(provider),
        "--service-name",
        "weather",
        "--network",
        "mini",
    ]);
    assert_ne!(code, 0, "an over-budget challenge must fail");
    assert!(
        err.contains("budget"),
        "the refusal must name the budget: {err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn pay_serves_a_free_resource_without_signing() {
    let wallet = tmp("pay-free.json");
    let (owner, _) = pay_owner(&wallet);
    let provider = [4u8; 20];
    let service = srct_core::service::derive_service_id("srct/mini", &provider, b"weather");
    let (policy_hex, _) = pay_grant(&owner, &provider, &service);
    let mut state = srct_l2::L2State::new(srct_l2::L2Config::mini());
    state.credit(owner, 1_000_000).expect("fund owner");
    let url = format!(
        "http://127.0.0.1:{}",
        fake_pay_node(
            &hex::encode(state.encode()),
            &hex::encode([0u8; 20]),
            None,
            "{\"report\":{\"weather\":\"sunny\"}}",
        )
    );
    let (code, out, _) = exec(&[
        "pay",
        "--node",
        &url,
        "--resource",
        "/v1/paid/weather",
        "--from-file",
        wallet.to_str().unwrap(),
        "--policy-hex",
        &policy_hex,
        "--max-amount",
        "600",
        "--recipients",
        &hex::encode(provider),
        "--service-name",
        "weather",
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "a free resource needs no payment: {out}");
    assert!(out.contains("sunny"), "the body must print: {out}");
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn pay_completes_the_challenge_response_round_trip() {
    let wallet = tmp("pay-ok.json");
    let (owner, _) = pay_owner(&wallet);
    let provider = [4u8; 20];
    let service = srct_core::service::derive_service_id("srct/mini", &provider, b"weather");
    let (policy_hex, agent_hex) = pay_grant(&owner, &provider, &service);
    let mut state = srct_l2::L2State::new(srct_l2::L2Config::mini());
    state.credit(owner, 1_000_000).expect("fund owner");
    let url = format!(
        "http://127.0.0.1:{}",
        fake_pay_node(
            &hex::encode(state.encode()),
            &agent_hex,
            Some(&pay_challenge(500, &provider)),
            "{\"report\":{\"weather\":\"sunny\"}}",
        )
    );
    let (code, out, err) = exec(&[
        "pay",
        "--node",
        &url,
        "--resource",
        "/v1/paid/weather",
        "--from-file",
        wallet.to_str().unwrap(),
        "--policy-hex",
        &policy_hex,
        "--max-amount",
        "600",
        "--recipients",
        &hex::encode(provider),
        "--service-name",
        "weather",
        "--network",
        "mini",
    ]);
    assert_eq!(
        code, 0,
        "the paid round trip must succeed: stdout={out}\nstderr={err}"
    );
    assert!(out.contains("paid 500 sat"), "the spend must print: {out}");
    assert!(out.contains("sunny"), "the resource body must print: {out}");
    let _ = std::fs::remove_file(&wallet);
}

// ---- stream-open / stream-voucher / stream-status / batch-quote: the
// micro-payment helpers. All signing stays in the payer wallet file; the
// node only records and quotes.

/// A fake micro-payment node: funded state, stream open/settle/status and a
/// batch quote. Flat routes — the CLI under test builds valid bytes, and the
/// node's own admission rules are covered by the node's test suites.
#[allow(clippy::too_many_arguments)]
fn fake_micro_node(
    state_hex: &str,
    stream_status: &str,
    open_body: &str,
    settle_body: &str,
    quote_body: &str,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let state_hex = state_hex.to_string();
    let status = stream_status.to_string();
    let open = open_body.to_string();
    let settle = settle_body.to_string();
    let quote = quote_body.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(16) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 65536];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let body = if request.starts_with("GET /v1/l2/state ") {
                format!(
                    "{{\"network_id\":\"srct/mini\",\"height\":5,\"state_hex\":\"{state_hex}\"}}"
                )
            } else if request.starts_with("GET /v1/streams/") {
                status.clone()
            } else if request.starts_with("POST /v1/streams/open ") {
                open.clone()
            } else if request.starts_with("POST /v1/streams/settle ") {
                settle.clone()
            } else if request.starts_with("POST /v1/payments/aggregate ") {
                quote.clone()
            } else {
                "404".to_string()
            };
            let (code, phrase) = if body == "404" {
                (404u16, "Not Found")
            } else {
                (200u16, "OK")
            };
            let response = format!(
                "HTTP/1.1 {code} {phrase}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

fn stream_wallet(path: &PathBuf, label: &str) -> srct_core::wallet::Wallet {
    let _ = std::fs::remove_file(path);
    let wallet = srct_core::wallet::Wallet::new_random(label.to_string());
    let json = serde_json::to_string_pretty(&wallet).expect("wallet is JSON");
    std::fs::write(path, json).expect("wallet file");
    wallet
}

fn funded_state_hex(owner: &[u8; 20]) -> String {
    let mut state = srct_l2::L2State::new(srct_l2::L2Config::mini());
    state.credit(*owner, 1_000_000).expect("fund owner");
    hex::encode(state.encode())
}

#[test]
fn micro_help_names_all_four_verbs() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    for verb in [
        "stream-open",
        "stream-voucher",
        "stream-status",
        "batch-quote",
    ] {
        assert!(out.contains(verb), "usage must document {verb}:\n{out}");
    }
}

#[test]
fn stream_open_publishes_a_channel_and_prints_its_bytes() {
    let wallet = tmp("stream-open.json");
    let w = stream_wallet(&wallet, "stream-payer");
    let owner = w.address().expect("addr");
    let recipient = hex::encode([6u8; 20]);
    let url = format!(
        "http://127.0.0.1:{}",
        fake_micro_node(
            &funded_state_hex(&owner),
            "{}",
            "{\"stream_id\":\"aa\",\"rate_sat_per_block\":10,\"max_total_sat\":1000}",
            "{}",
            "{}",
        )
    );
    let (code, out, err) = exec(&[
        "stream-open",
        "--node",
        &url,
        "--from-file",
        wallet.to_str().unwrap(),
        "--to",
        &recipient,
        "--rate",
        "10",
        "--cap",
        "1000",
        "--expires",
        "100",
        "--policy-hash",
        &hex::encode([1u8; 32]),
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "open must succeed: stdout={out}\nstderr={err}");
    assert!(out.contains("stream_id"), "the id must print: {out}");
    assert!(
        out.contains("stream_hex"),
        "the bytes must print for voucher use: {out}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn stream_open_refuses_an_expiry_inside_its_start() {
    let wallet = tmp("stream-bad.json");
    let _ = stream_wallet(&wallet, "stream-payer");
    let (code, _, err) = exec(&[
        "stream-open",
        "--node",
        "http://127.0.0.1:9",
        "--from-file",
        wallet.to_str().unwrap(),
        "--to",
        &hex::encode([6u8; 20]),
        "--rate",
        "10",
        "--cap",
        "1000",
        "--start",
        "10",
        "--expires",
        "5",
        "--policy-hash",
        &hex::encode([1u8; 32]),
        "--network",
        "mini",
    ]);
    assert_ne!(
        code, 0,
        "expiry inside start must fail before any network use"
    );
    assert!(err.contains("refused"), "the refusal must say so: {err}");
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn stream_voucher_files_the_exact_accrual() {
    use srct_core::agent::AgentRole;
    use srct_core::stream::{build_stream, StreamOpenSpec};
    let wallet = tmp("stream-v.json");
    let w = stream_wallet(&wallet, "stream-payer");
    let owner = w.address().expect("addr");
    let stream = build_stream(
        &w,
        StreamOpenSpec {
            network_id: "srct/mini".to_string(),
            payer_type: AgentRole::Machine,
            recipient: [6u8; 20],
            service: None,
            rate_sat_per_block: 10,
            start_height: 5,
            expires_at_height: 100,
            max_total_sat: 1000,
            nonce: 1,
            policy_hash: [1u8; 32],
        },
    )
    .expect("stream builds");
    let stream_hex = hex::encode(stream.serialize());
    let stream_id = hex::encode(stream.signing_hash());
    let status = "{\"settled_sat\":0,\"last_nonce\":0,\"settlements\":0}".to_string();
    let url = format!(
        "http://127.0.0.1:{}",
        fake_micro_node(
            &funded_state_hex(&owner),
            &status,
            "{}",
            "{\"accepted\":true}",
            "{}",
        )
    );
    let _ = stream_id;
    let (code, out, err) = exec(&[
        "stream-voucher",
        "--node",
        &url,
        "--from-file",
        wallet.to_str().unwrap(),
        "--stream-hex",
        &stream_hex,
        "--through",
        "8",
        "--network",
        "mini",
    ]);
    // rate 10 from height 5 through 8 = 40 sat accrued, nothing settled yet.
    assert_eq!(code, 0, "voucher must file: stdout={out}\nstderr={err}");
    assert!(
        out.contains("40 sat"),
        "the exact accrual must print: {out}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn stream_status_prints_accounting() {
    let wallet = tmp("stream-st.json");
    let w = stream_wallet(&wallet, "stream-payer");
    let owner = w.address().expect("addr");
    let url = format!(
        "http://127.0.0.1:{}",
        fake_micro_node(
            &funded_state_hex(&owner),
            "{\"stream_id\":\"aa\",\"settled_sat\":40,\"claimable_sat\":60,\"last_nonce\":2}",
            "{}",
            "{}",
            "{}",
        )
    );
    let (code, out, _) = exec(&[
        "stream-status",
        "--node",
        &url,
        "--stream",
        &hex::encode([9u8; 32]),
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "status must print: {out}");
    assert!(out.contains("settled_sat"), "accounting must print: {out}");
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn batch_quote_prints_the_shared_settlement_price() {
    let wallet = tmp("batch-q.json");
    let w = stream_wallet(&wallet, "stream-payer");
    let owner = w.address().expect("addr");
    let url = format!(
        "http://127.0.0.1:{}",
        fake_micro_node(
            &funded_state_hex(&owner),
            "{}",
            "{}",
            "{}",
            "{\"payer\":\"00\",\"total_amount_sat\":1000,\"required_fee_sat\":100,\"fee_per_payment_sat\":50,\"separate_total_fee_sat\":400,\"savings_sat\":300}",
        )
    );
    let (code, out, _) = exec(&[
        "batch-quote",
        "--node",
        &url,
        "--payments",
        &hex::encode([1u8; 32]),
        "--network",
        "mini",
    ]);
    // one id is enough for the shape test; the node prices, the CLI prints.
    assert_eq!(code, 0, "quote must print: {out}");
    assert!(out.contains("savings_sat"), "savings must print: {out}");
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn batch_quote_refuses_an_empty_list_before_any_network_use() {
    let (code, _, err) = exec(&[
        "batch-quote",
        "--node",
        "http://127.0.0.1:9",
        "--payments",
        "",
        "--network",
        "mini",
    ]);
    assert_ne!(code, 0, "an empty batch must fail locally");
    assert!(err.contains("1..=256"), "the bound must print: {err}");
}

#[test]
fn batch_quote_prints_the_servers_named_refusal() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let body = "{\"error\":\"aggregate_refused\",\"detail\":\"mixed payers\"}";
            let response = format!(
                "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(response.as_bytes());
        }
    });
    let (code, _, err) = exec(&[
        "batch-quote",
        "--node",
        &format!("http://127.0.0.1:{port}"),
        "--payments",
        &hex::encode([1u8; 32]),
        "--network",
        "mini",
    ]);
    assert_ne!(code, 0, "a refused quote must fail");
    assert!(
        err.contains("aggregate_refused") && err.contains("mixed payers"),
        "the server's named reason must print, not a paraphrase: {err}"
    );
}

// ---- claim / submit-result: the template's two signing steps. The fake node
// serves a real funded state (built with the SDK's own Core) plus the task
// record the CLI reads its minimum deposit from; the binary signs with the
// wallet file, exactly as an agent framework would drive it.

mod common;

fn fake_l2_node(state_hex: &str, task_hex: &str, payment_sat: u64) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let state_hex = state_hex.to_string();
    let task_hex = task_hex.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(16) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 65536];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let body = if request.starts_with("GET /v1/l2/state ") {
                format!(
                    "{{\"network_id\":\"srct/mini\",\"height\":1,\"state_hex\":\"{state_hex}\"}}"
                )
            } else if request.starts_with("GET /v1/task/") {
                format!("{{\"task_id\":\"{task_hex}\",\"payment_sat\":{payment_sat}}}")
            } else if request.starts_with("POST /v1/l2/broadcast ") {
                "{\"accepted\":true}".to_string()
            } else {
                "404".to_string()
            };
            let (code, phrase) = if body == "404" {
                (404u16, "Not Found")
            } else {
                (200u16, "OK")
            };
            let response = format!(
                "HTTP/1.1 {code} {phrase}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

fn open_task_in(core: &mut common::Core, nonce: u64, pay: u64) -> srct_core::hash::Hash {
    use srct_core::compute_ir::{ComputeBackend, ComputeTask};
    use srct_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
    let task = ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 1024,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 0,
        expiry_height: 100,
        submit_height: 0,
    };
    let payload =
        PostTaskPayload::build(&common::wallet(1), nonce, pay, 100, task).expect("post builds");
    let task_id = payload.task_id;
    let tx = L2Transaction::new(L2Payload::Post(payload));
    core.apply(&tx).expect("post applies");
    task_id
}

#[test]
fn claim_help_names_the_verb_and_its_task_flag() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("claim"), "usage must document claim:\n{out}");
    assert!(
        out.contains("submit-result"),
        "usage must document submit-result:\n{out}"
    );
}

#[test]
fn claim_refuses_an_unknown_task_without_signing_anything() {
    let wallet = tmp("claim-unknown.json");
    let _ = stream_wallet(&wallet, "claim-agent");
    let mut core = common::Core::new(30_000_000);
    let url = format!(
        "http://127.0.0.1:{}",
        fake_l2_node(
            &hex::encode(core.state.encode()),
            &hex::encode([0x77u8; 32]),
            1_000_000
        )
    );
    let _ = &mut core;
    let (code, _, err) = exec(&[
        "claim",
        "--node",
        &url,
        "--from-file",
        wallet.to_str().unwrap(),
        "--task",
        &hex::encode([0x77u8; 32]),
        "--network",
        "mini",
    ]);
    assert_ne!(code, 0, "an unknown task must fail");
    assert!(
        err.contains("refused") || err.contains("UnknownTask") || err.contains("unknown"),
        "the refusal must name the cause: {err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn claim_then_submit_round_trip_through_a_node() {
    use srct_core::compute_ir::ComputeBackend;
    use srct_core::l2::{ClaimTaskPayload, L2Payload, L2Transaction};
    let wallet = tmp("claim-ok.json");
    let agent_wallet = stream_wallet(&wallet, "claim-agent");
    let agent = agent_wallet.address().expect("addr");
    let mut core = common::Core::new(30_000_000);
    core.state.credit(agent, 30_000_000).expect("fund agent");
    let task_id = open_task_in(&mut core, 7, 1_000_000);
    let task_hex = hex::encode(task_id);
    let url = format!(
        "http://127.0.0.1:{}",
        fake_l2_node(&hex::encode(core.state.encode()), &task_hex, 1_000_000)
    );
    let (code, out, err) = exec(&[
        "claim",
        "--node",
        &url,
        "--from-file",
        wallet.to_str().unwrap(),
        "--task",
        &task_hex,
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "claim must succeed: stdout={out}\nstderr={err}");
    assert!(out.contains("claimed"), "the claim must print: {out}");
    // The auto-deposit is the on-chain minimum for this task: 0.1% of 1M,
    // floored at 1000 sat — read from the task, never guessed.
    assert!(
        out.contains("deposit     1000 sat"),
        "the minimum deposit must print: {out}"
    );

    // The submit half: the served state must show our claim in progress.
    let claim_payload = ClaimTaskPayload::build(&agent_wallet, task_id, ComputeBackend::Cpu, 5_000)
        .expect("claim builds");
    let claim_tx = L2Transaction::new(L2Payload::Claim(claim_payload));
    core.apply(&claim_tx).expect("claim applies");
    let url2 = format!(
        "http://127.0.0.1:{}",
        fake_l2_node(&hex::encode(core.state.encode()), &task_hex, 1_000_000)
    );
    let (code, out, err) = exec(&[
        "submit-result",
        "--node",
        &url2,
        "--from-file",
        wallet.to_str().unwrap(),
        "--task",
        &task_hex,
        "--result",
        &hex::encode(b"langchain-output-bytes"),
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "submit must succeed: stdout={out}\nstderr={err}");
    assert!(
        out.contains("submitted"),
        "the submission must print: {out}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn submit_refuses_a_result_for_a_task_nobody_claimed() {
    let wallet = tmp("submit-open.json");
    let agent_wallet = stream_wallet(&wallet, "claim-agent");
    let agent = agent_wallet.address().expect("addr");
    let mut core = common::Core::new(30_000_000);
    core.state.credit(agent, 30_000_000).expect("fund agent");
    let task_id = open_task_in(&mut core, 8, 1_000_000);
    let url = format!(
        "http://127.0.0.1:{}",
        fake_l2_node(
            &hex::encode(core.state.encode()),
            &hex::encode(task_id),
            1_000_000
        )
    );
    let (code, _, _err) = exec(&[
        "submit-result",
        "--node",
        &url,
        "--from-file",
        wallet.to_str().unwrap(),
        "--task",
        &hex::encode(task_id),
        "--result",
        &hex::encode(b"too-early"),
        "--network",
        "mini",
    ]);
    assert_ne!(code, 0, "submitting to an unclaimed task must fail");
    let _ = std::fs::remove_file(&wallet);
}

// ---- trial-request / trial-fund / trial-status / trial-repay: the faucet
// from the agent's side. The node verifies; the CLI only carries.

fn fake_trial_node(status_body: &str, action_body: &str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let status = status_body.to_string();
    let action = action_body.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(16) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let body = if request.starts_with("GET /v1/trials/") {
                status.clone()
            } else if request.starts_with("POST /v1/trials/") {
                action.clone()
            } else {
                "404".to_string()
            };
            let (code, phrase) = if body == "404" {
                (404u16, "Not Found")
            } else {
                (200u16, "OK")
            };
            let response = format!(
                "HTTP/1.1 {code} {phrase}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn trial_help_names_all_four_verbs() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    for verb in ["trial-request", "trial-fund", "trial-status", "trial-repay"] {
        assert!(out.contains(verb), "usage must document {verb}:\n{out}");
    }
}

#[test]
fn trial_request_records_and_status_reads_it_back() {
    let agent = hex::encode([5u8; 20]);
    let status_body = format!(
        "{{\"agent\":\"{agent}\",\"amount_sat\":50000,\"sponsor\":\"aa\",\
         \"state\":\"requested\",\"fund_txid\":null,\"repay_txid\":null,\
         \"requested_height\":3}}"
    );
    let url = format!(
        "http://127.0.0.1:{}",
        fake_trial_node(&status_body, &status_body)
    );
    let (code, out, _) = exec(&[
        "trial-request",
        "--node",
        &url,
        "--agent",
        &agent,
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "request must record: {out}");
    assert!(out.contains("requested"), "the state must print: {out}");
    let (code, out, _) = exec(&[
        "trial-status",
        "--node",
        &url,
        "--agent",
        &agent,
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "status must read: {out}");
    assert!(out.contains("amount_sat"), "accounting must print: {out}");
}

#[test]
fn trial_fund_and_repay_confirm_through_the_node() {
    let agent = hex::encode([5u8; 20]);
    let funded = format!(
        "{{\"agent\":\"{agent}\",\"amount_sat\":50000,\"sponsor\":\"aa\",\
         \"state\":\"funded\",\"fund_txid\":\"bb\",\"repay_txid\":null,\
         \"requested_height\":3}}"
    );
    let repaid = funded.replace("\"state\":\"funded\"", "\"state\":\"repaid\"");
    let url = format!("http://127.0.0.1:{}", fake_trial_node(&repaid, &funded));
    let (code, out, _) = exec(&[
        "trial-fund",
        "--node",
        &url,
        "--agent",
        &agent,
        "--txid",
        &"bb".repeat(32),
        "--network",
        "mini",
    ]);
    assert_eq!(code, 0, "fund must confirm: {out}");
    assert!(out.contains("funded"), "the state must print: {out}");
    let (code, out, _) = exec(&[
        "trial-repay",
        "--node",
        &url,
        "--agent",
        &agent,
        "--txid",
        &"cc".repeat(32),
        "--network",
        "mini",
    ]);
    // The fake node answers every POST with the funded record: the CLI prints
    // what the node says, and the node's own tests pin the real transitions.
    assert_eq!(code, 0, "repay must submit: {out}");
}
