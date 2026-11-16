//! `srct-confid`: the consumer-side confidential-tier CLI.
//!
//! Everything here runs on the consumer's machine. Key release requires a
//! verified attestation; without one the tool exits non-zero *before* any
//! sealed bytes exist. Passphrases arrive via `SRCT_CONFID_PASSPHRASE`,
//! never argv (argv is visible to every local process).

use std::path::PathBuf;

use srct_confid::{ConfidError, KmsAdapter, LocalKeystore};

fn usage() -> String {
    "usage:
  srct-confid keystore init --file <path>
  srct-confid key new --keystore <path> --id <key-id> [--ttl-secs <n>]
  srct-confid key list --keystore <path>
  srct-confid key revoke --keystore <path> --id <key-id>
  srct-confid key wrap --keystore <path> --id <key-id> --to-pubkey <hex>
                       --info <hex> [--aad <hex>] --out <path>
  srct-confid key open --privkey <hex> --sealed <path> --info <hex> [--aad <hex>]
  srct-confid release --keystore <path> --request <path> --out <path>

Passphrase comes from SRCT_CONFID_PASSPHRASE. Exit codes: 0 released /
done, 2 attestation or policy refused (nothing was sealed), 1 error."
        .to_string()
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(ConfidError::AttestationFailed(d)) => {
            eprintln!("attestation refused: {d}");
            std::process::ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<i32, ConfidError> {
    let cmd = args
        .first()
        .ok_or_else(|| ConfidError::Malformed(usage()))?;
    match cmd.as_str() {
        "--help" | "help" => {
            println!("{}", usage());
            Ok(0)
        }
        "keystore" => match args.get(1).map(String::as_str) {
            Some("init") => cmd_keystore_init(&args[1..]),
            Some(other) => Err(ConfidError::Malformed(format!(
                "unknown keystore subcommand `{other}`\n{}",
                usage()
            ))),
            None => Err(ConfidError::Malformed(usage())),
        },
        "key" => match args.get(1).map(String::as_str) {
            Some("new") => cmd_key_new(&args[1..]),
            Some("list") => cmd_key_list(&args[1..]),
            Some("revoke") => cmd_key_revoke(&args[1..]),
            Some("wrap") => cmd_key_wrap(&args[1..]),
            Some("open") => cmd_key_open(&args[1..]),
            Some(other) => Err(ConfidError::Malformed(format!(
                "unknown key subcommand `{other}`\n{}",
                usage()
            ))),
            None => Err(ConfidError::Malformed(usage())),
        },
        "release" => cmd_release(&args[1..]),
        other => Err(ConfidError::Malformed(format!(
            "unknown command `{other}`\n{}",
            usage()
        ))),
    }
}

fn str_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).map(String::as_str))
}

fn req_arg(args: &[String], name: &str) -> Result<String, ConfidError> {
    str_arg(args, name)
        .map(str::to_string)
        .ok_or_else(|| ConfidError::Malformed(format!("missing {name}\n{}", usage())))
}

fn num_arg(args: &[String], name: &str, default: u64) -> Result<u64, ConfidError> {
    match str_arg(args, name) {
        None => Ok(default),
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| ConfidError::Malformed(format!("bad number for {name}: {v}"))),
    }
}

fn passphrase() -> Result<String, ConfidError> {
    std::env::var(srct_confid::kms::PASSPHRASE_ENV)
        .ok()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            ConfidError::Malformed(format!(
                "set {} with the keystore passphrase",
                srct_confid::kms::PASSPHRASE_ENV
            ))
        })
}

fn open_store(args: &[String]) -> Result<LocalKeystore, ConfidError> {
    let path = PathBuf::from(req_arg(args, "--keystore")?);
    LocalKeystore::open(&path, &passphrase()?)
}

fn hex_decode(s: &str, what: &str) -> Result<Vec<u8>, ConfidError> {
    // Empty info/AAD seal over empty associated data; every other empty
    // input fails its length check downstream with a specific message.
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ConfidError::Malformed(format!("{what} is not hex")));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap();
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn cmd_keystore_init(args: &[String]) -> Result<i32, ConfidError> {
    let path = PathBuf::from(req_arg(args, "--file")?);
    LocalKeystore::create(&path, &passphrase()?)?;
    println!("keystore: created {}", path.display());
    Ok(0)
}

fn cmd_key_new(args: &[String]) -> Result<i32, ConfidError> {
    use rand::RngCore as _;
    let path = PathBuf::from(req_arg(args, "--keystore")?);
    let id = req_arg(args, "--id")?;
    let ttl = num_arg(args, "--ttl-secs", u64::MAX)?;
    let mut ks = LocalKeystore::open(&path, &passphrase()?)?;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let now = unix_now()?;
    ks.store(&id, &key, ttl, now)?;
    use zeroize::Zeroize as _;
    key.zeroize();
    println!("keystore: stored key `{id}`");
    Ok(0)
}

fn cmd_key_list(args: &[String]) -> Result<i32, ConfidError> {
    let store = open_store(args)?;
    let ids = store.ids();
    println!("keys: {}", ids.join(", "));
    Ok(0)
}

fn cmd_key_revoke(args: &[String]) -> Result<i32, ConfidError> {
    let id = req_arg(args, "--id")?;
    let mut ks = open_store(args)?;
    if ks.revoke(&id)? {
        println!("keystore: revoked `{id}`");
    } else {
        println!("keystore: no such key `{id}`");
    }
    Ok(0)
}

fn cmd_key_wrap(args: &[String]) -> Result<i32, ConfidError> {
    let id = req_arg(args, "--id")?;
    let to_pub = hex_decode(&req_arg(args, "--to-pubkey")?, "to-pubkey")?;
    let info = hex_decode(str_arg(args, "--info").unwrap_or(""), "info")?;
    let aad = hex_decode(str_arg(args, "--aad").unwrap_or(""), "aad")?;
    let out = PathBuf::from(req_arg(args, "--out")?);
    if to_pub.len() != 32 {
        return Err(ConfidError::Malformed("to-pubkey must be 32 bytes".into()));
    }
    let mut to_pub32 = [0u8; 32];
    to_pub32.copy_from_slice(&to_pub);
    let ks = open_store(args)?;
    let now = unix_now()?;
    let key = ks.load(&id, now)?;
    let sealed = srct_confid::keywrap::seal_to_enclave(&to_pub32, &key, &info, &aad)?;
    let bytes = sealed.encode();
    std::fs::write(&out, hex_encode(&bytes))
        .map_err(|e| ConfidError::Io(format!("write sealed bundle: {e}")))?;
    println!("keystore: wrapped `{id}` -> {}", out.display());
    Ok(0)
}

fn cmd_key_open(args: &[String]) -> Result<i32, ConfidError> {
    let priv_hex = req_arg(args, "--privkey")?;
    let sealed_hex = std::fs::read_to_string(req_arg(args, "--sealed")?)
        .map_err(|e| ConfidError::Io(format!("read sealed bundle: {e}")))?;
    let info = hex_decode(str_arg(args, "--info").unwrap_or(""), "info")?;
    let aad = hex_decode(str_arg(args, "--aad").unwrap_or(""), "aad")?;
    let priv_bytes = hex_decode(priv_hex.trim(), "privkey")?;
    if priv_bytes.len() != 32 {
        return Err(ConfidError::Malformed("privkey must be 32 bytes".into()));
    }
    let mut priv32 = [0u8; 32];
    priv32.copy_from_slice(&priv_bytes);
    let sealed_bytes = hex_decode(sealed_hex.trim(), "sealed bundle")?;
    let sealed = srct_confid::keywrap::SealedKey::decode(&sealed_bytes)?;
    let key = srct_confid::keywrap::open_with_privkey(&priv32, &sealed, &info, &aad)?;
    use zeroize::Zeroize as _;
    let mut k = key;
    println!("key: {}", hex_encode(&k[..]));
    k.zeroize();
    Ok(0)
}

fn unix_now() -> Result<u64, ConfidError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ConfidError::Io(format!("wall clock before epoch: {e}")))
}

/// `release --keystore F --request REQ --out OUT`.
///
/// The request file is JSON (schema version 1):
/// ```json
/// {"version": 1, "key_id": "...",
///  "sla_hex": "...", "quote_hex": "...",
///  "attesters": [{"pubkey_hex": "<40 hex = 20 bytes>", "tee": "tdx"}],
///  "vendor": {"approved_measurement_hex": "<64 hex>",
///             "min_tcb_hex": "<32 hex, optional>",
///             "allow_debug": false,
///             "now_unix": 1700000000,
///             "presented_pubkey_hex": "<128 hex>",
///             "expected_nonce": 7,
///             "nvidia_signing_key_hex": "<128 hex, optional>",
///             "snp_vcek_chain_hex": ["...", "..."],
///             "pinned_root_spki": ["<64 hex>", ...],
///             "revoked_serials_hex": ["..."]},
///  "enclave_pubkey_hex": "<64 hex>",
///  "purpose": "data"|"result"|"checkpoint",
///  "aad_hex": "<hex>", "height": 100}
/// ```
/// Attestation is verified in full before any seal happens; failure exits
/// 2 and writes nothing.
fn cmd_release(args: &[String]) -> Result<i32, ConfidError> {
    let out_path = PathBuf::from(req_arg(args, "--out")?);
    let req_bytes = std::fs::read(req_arg(args, "--request")?)
        .map_err(|e| ConfidError::Io(format!("read request: {e}")))?;
    let req: serde_json::Value = serde_json::from_slice(&req_bytes)
        .map_err(|_| ConfidError::Malformed("request is not valid JSON".into()))?;
    let get = |name: &str| -> Result<&serde_json::Value, ConfidError> {
        req.get(name)
            .ok_or_else(|| ConfidError::Malformed(format!("request misses `{name}`")))
    };
    if get("version")?.as_u64() != Some(1) {
        return Err(ConfidError::Malformed("unsupported request version".into()));
    }
    let key_id = get("key_id")?
        .as_str()
        .ok_or_else(|| ConfidError::Malformed("key_id is not a string".into()))?;
    let sla_hex = get("sla_hex")?
        .as_str()
        .ok_or_else(|| ConfidError::Malformed("sla_hex is not a string".into()))?;
    let quote_hex = get("quote_hex")?
        .as_str()
        .ok_or_else(|| ConfidError::Malformed("quote_hex is not a string".into()))?;
    let enclave_hex = get("enclave_pubkey_hex")?
        .as_str()
        .ok_or_else(|| ConfidError::Malformed("enclave_pubkey_hex is not a string".into()))?;
    let purpose = match get("purpose")?.as_str() {
        Some("data") => srct_confid::KeyPurpose::Data,
        Some("result") => srct_confid::KeyPurpose::Result,
        Some("checkpoint") => srct_confid::KeyPurpose::Checkpoint,
        _ => {
            return Err(ConfidError::Malformed(
                "purpose must be data|result|checkpoint".into(),
            ))
        }
    };
    let aad_hex: &str = match get("aad_hex") {
        Ok(v) => v.as_str().unwrap_or(""),
        Err(_) => "",
    };
    let height = match get("height") {
        Ok(v) => v
            .as_u64()
            .ok_or_else(|| ConfidError::Malformed("height must be a number".into()))?,
        Err(_) => return Err(ConfidError::Malformed("request misses `height`".into())),
    };
    let now_unix = get("vendor")?
        .get("now_unix")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ConfidError::Malformed("vendor.now_unix must be a number".into()))?;

    let sla = srct_compute::tee::TeeSla::decode(&hex_decode(sla_hex, "sla_hex")?)
        .map_err(srct_confid::ConfidError::from)?;
    let quote = srct_compute::tee::SignedTeeQuote::decode(&hex_decode(quote_hex, "quote_hex")?)
        .map_err(srct_confid::ConfidError::from)?;
    let mut roots = srct_compute::tee::AttestationRoots::new();
    let attesters = get("attesters")?
        .as_array()
        .ok_or_else(|| ConfidError::Malformed("attesters must be an array".into()))?;
    for a in attesters {
        let pk_hex = a
            .get("pubkey_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ConfidError::Malformed("attester misses pubkey_hex".into()))?;
        let tee = match a.get("tee").and_then(|v| v.as_str()) {
            Some("software") => srct_compute::tee::TeeType::Software,
            Some("tdx") => srct_compute::tee::TeeType::Tdx,
            Some("sevsnp") => srct_compute::tee::TeeType::SevSnp,
            Some("nvidia-cc") => srct_compute::tee::TeeType::NvidiaCc,
            _ => {
                return Err(ConfidError::Malformed(
                    "attester tee must be software|tdx|sevsnp|nvidia-cc".into(),
                ))
            }
        };
        let pk = hex_decode(pk_hex, "attester pubkey")?;
        if pk.len() != 20 {
            return Err(ConfidError::Malformed(
                "attester pubkey must be 20 bytes".into(),
            ));
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&pk);
        roots.add_root(addr, tee);
    }
    let v = get("vendor")?;
    let str_hex = |name: &str, what: &str| -> Result<Vec<u8>, ConfidError> {
        v.get(name)
            .and_then(|x| x.as_str())
            .ok_or_else(|| ConfidError::Malformed(format!("vendor misses `{name}`")))
            .and_then(|s| hex_decode(s, what))
    };
    let approved = str_hex("approved_measurement_hex", "approved measurement")?;
    if approved.len() != 32 {
        return Err(ConfidError::Malformed(
            "approved measurement must be 32 bytes".into(),
        ));
    }
    let mut approved_measurement = [0u8; 32];
    approved_measurement.copy_from_slice(&approved);
    let mut min_tcb = [0u8; 16];
    if let Some(hex) = v.get("min_tcb_hex").and_then(|x| x.as_str()) {
        let raw = hex_decode(hex, "min_tcb")?;
        if raw.len() != 16 {
            return Err(ConfidError::Malformed("min_tcb must be 16 bytes".into()));
        }
        min_tcb.copy_from_slice(&raw);
    }
    let allow_debug = v
        .get("allow_debug")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let presented = str_hex("presented_pubkey_hex", "presented pubkey")?;
    let enclave_raw = hex_decode(enclave_hex, "enclave pubkey")?;
    if enclave_raw.len() != 32 {
        return Err(ConfidError::Malformed(
            "enclave pubkey must be 32 bytes".into(),
        ));
    }
    let mut enclave_pubkey = [0u8; 32];
    enclave_pubkey.copy_from_slice(&enclave_raw);
    let expected_nonce = v
        .get("expected_nonce")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| ConfidError::Malformed("vendor misses expected_nonce".into()))?;
    let nvidia_key = match v.get("nvidia_signing_key_hex") {
        Some(x) => {
            let raw = hex_decode(
                x.as_str()
                    .ok_or_else(|| ConfidError::Malformed("nvidia key must be hex".into()))?,
                "nvidia signing key",
            )?;
            if raw.len() != 65 || raw[0] != 0x04 {
                return Err(ConfidError::Malformed(
                    "nvidia key must be uncompressed P-256".into(),
                ));
            }
            let mut k = [0u8; 65];
            k.copy_from_slice(&raw);
            Some(k)
        }
        None => None,
    };
    let mut vcek_chain = Vec::new();
    if let Some(arr) = v.get("snp_vcek_chain_hex").and_then(|x| x.as_array()) {
        for c in arr {
            let hex = c
                .as_str()
                .ok_or_else(|| ConfidError::Malformed("vcek chain entries must be hex".into()))?;
            vcek_chain.push(hex_decode(hex, "vcek cert")?);
        }
    }
    let mut pins = Vec::new();
    if let Some(arr) = v.get("pinned_root_spki").and_then(|x| x.as_array()) {
        for p in arr {
            let hex = p
                .as_str()
                .ok_or_else(|| ConfidError::Malformed("pins must be hex".into()))?;
            let raw = hex_decode(hex, "pin")?;
            if raw.len() != 32 {
                return Err(ConfidError::Malformed("pins must be 32 bytes".into()));
            }
            let mut pin = [0u8; 32];
            pin.copy_from_slice(&raw);
            pins.push(pin);
        }
    }
    let mut crls = Vec::new();
    if let Some(arr) = v.get("revoked_serials_hex").and_then(|x| x.as_array()) {
        for s in arr {
            let hex = s
                .as_str()
                .ok_or_else(|| ConfidError::Malformed("crl entries must be hex".into()))?;
            crls.push(hex_decode(hex, "crl serial")?);
        }
    }
    let vendor = srct_compute::vendor::VendorInputs {
        now_unix: v
            .get("now_unix")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| ConfidError::Malformed("vendor misses now_unix".into()))?,
        presented_pubkey: presented,
        expected_nonce,
        approved_measurement,
        tcb: srct_compute::vendor::TcbPolicy::default(),
        roots: srct_compute::vendor::VendorRoots {
            pinned_root_spki: pins,
            revoked_serials: crls,
        },
        allow_debug,
        nvidia_signing_key: nvidia_key,
        snp_vcek_chain: vcek_chain,
    };
    let ks = open_store(args)?;
    let aad = hex_decode(aad_hex, "aad")?;
    let presented = vendor.presented_pubkey.clone();
    let policy = srct_confid::release::ReleasePolicy {
        sla: &sla,
        quote: &quote,
        roots: &roots,
        vendor: &vendor,
        presented_pubkey: &presented,
        current_height: height,
    };
    let released = srct_confid::release_data_key(
        &ks,
        key_id,
        &enclave_pubkey,
        purpose,
        &aad,
        now_unix,
        &policy,
    )?;
    let bundle = serde_json::json!({
        "version": 1,
        "sealed_hex": hex_encode(&released.sealed.encode()),
        "info_hex": hex_encode(&released.info),
    });
    std::fs::write(&out_path, serde_json::to_vec_pretty(&bundle).unwrap())
        .map_err(|e| ConfidError::Io(format!("write release bundle: {e}")))?;
    println!("release: sealed key for `{key_id}`");
    Ok(0)
}
