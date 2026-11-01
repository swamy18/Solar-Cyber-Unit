//! x402-compatible payment adapter for SRCT (agent-payment interoperability).
//!
//! x402 (Linux Foundation, 2026) is an HTTP-native standard: a client calls a
//! paid resource, the server answers `402 Payment Required` with a
//! `PAYMENT-REQUIRED` header (base64 JSON [`X402Required`]), the client
//! retries with a `PAYMENT-SIGNATURE` header (base64 JSON [`X402Signature`]),
//! the server verifies (itself or via a facilitator `/verify`) and settles
//! (via `/settle`), then answers `200` with a `PAYMENT-RESPONSE` header.
//!
//! This module maps that flow onto the existing SRCT primitives without
//! inventing a second payment system:
//!
//! ```text
//! Agent ──GET /paid ──▶ 402 + PAYMENT-REQUIRED (accepts: scheme=exact, network=srct:*)
//! Agent ──checks budget──▶ builds PaymentRequest → Authorization → MachinePayment
//! Agent ──GET /paid + PAYMENT-SIGNATURE──▶ verify → payment_submit → receipt → 200 + PAYMENT-RESPONSE
//! ```
//!
//! - The **scheme** is always `exact` (fixed price per call). `upto` maps
//!   naturally onto `PaymentRequest.max_amount_sat` in the future but is
//!   refused here until a settlement-override rule is locked.
//! - The **network** is CAIP-2 `srct:<reference>` where `reference` is the
//!   SRCT network id after `srct/` (e.g. `srct/testnet` ↔ `srct:testnet`).
//! - The **payload** is the exact envelope `POST /v1/payment/submit` already
//!   takes (`payment_hex`, `authorization_hex`, `auth_sigs_hex`,
//!   `auth_keys_hex`), so verification and settlement reuse
//!   `service::admit_payment` and the node-local `CreditBook` with no new
//!   consensus rule.
//! - The client never skips its own [`X402Budget`]: recipient allow-list,
//!   service allow-list and a hard `max_amount_sat` cap. A server that asks
//!   for more than the budget is refused locally before any key is used.
//!
//! Fail-closed: unknown version, unknown scheme, unknown network, zero amount,
//! budget overrun, or recipient/service outside the allow-list is refused by
//! name. Base64 errors are `Malformed`, never panics.

use crate::hash::address_from_hex;
use crate::hash::Address;
use serde::{Deserialize, Serialize};

/// x402 protocol version this adapter speaks (x402 v2).
pub const X402_VERSION: u32 = 2;
/// HTTP status for a payment challenge.
pub const X402_STATUS_PAYMENT_REQUIRED: u16 = 402;
/// Header carrying base64 JSON [`X402Required`].
pub const X402_HEADER_REQUIRED: &str = "PAYMENT-REQUIRED";
/// Header carrying base64 JSON [`X402Signature`].
pub const X402_HEADER_SIGNATURE: &str = "PAYMENT-SIGNATURE";
/// Header carrying base64 JSON [`X402Response`].
pub const X402_HEADER_RESPONSE: &str = "PAYMENT-RESPONSE";
/// The only scheme this adapter settles today.
pub const SRCT_SCHEME: &str = "exact";
/// CAIP-2 namespace for SRCT.
pub const SRCT_NAMESPACE: &str = "srct";
/// CAIP-2 namespace for EVM chains (Base settles here; the node settles SRCT).
pub const EVM_NAMESPACE: &str = "eip155";
/// Base mainnet chain id: the EVM rail this adapter speaks beside SRCT.
pub const BASE_CHAIN_ID: u64 = 8453;
/// Base Sepolia chain id (test rail).
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;
/// Longest a guarded payment may live, in blocks, measured from the challenge
/// height. The wallet guard is short-lived by construction: a grant that
/// outlives this is refused before any key is touched.
pub const MAX_GUARD_LIFETIME_BLOCKS: u64 = 30;
/// Longest accepted resource/description string (bounds the 402 body).
pub const MAX_X402_STRING_LEN: usize = 512;
/// Most payment options one challenge may carry.
pub const MAX_X402_ACCEPTS: usize = 8;

/// Why an x402 envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X402Error {
    Malformed(&'static str),
    UnsupportedVersion(u32),
    UnsupportedScheme(String),
    UnknownNetwork(String),
    ZeroAmount,
    AmountTooLarge {
        amount: u64,
        max: u64,
    },
    RecipientNotAllowed,
    ServiceNotAllowed,
    BudgetExceeded(String),
    /// The guarded payment is spent at or past its expiry.
    Expired {
        expires_at_height: u64,
        height: u64,
    },
    /// The guarded window outlives [`MAX_GUARD_LIFETIME_BLOCKS`].
    LifetimeTooLong {
        lifetime: u64,
        max: u64,
    },
}

impl std::fmt::Display for X402Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            X402Error::Malformed(w) => write!(f, "malformed x402 envelope: {w}"),
            X402Error::UnsupportedVersion(v) => write!(f, "unsupported x402 version {v}"),
            X402Error::UnsupportedScheme(s) => write!(f, "unsupported x402 scheme {s}"),
            X402Error::UnknownNetwork(n) => write!(f, "unknown x402 network {n}"),
            X402Error::ZeroAmount => write!(f, "x402 amount is zero"),
            X402Error::AmountTooLarge { amount, max } => {
                write!(f, "x402 amount {amount} exceeds budget {max}")
            }
            X402Error::RecipientNotAllowed => write!(f, "x402 recipient outside budget allow-list"),
            X402Error::ServiceNotAllowed => write!(f, "x402 service outside budget allow-list"),
            X402Error::BudgetExceeded(w) => write!(f, "x402 budget exceeded: {w}"),
            X402Error::Expired {
                expires_at_height,
                height,
            } => write!(
                f,
                "x402 guard expired at {expires_at_height}, spent at {height}"
            ),
            X402Error::LifetimeTooLong { lifetime, max } => {
                write!(f, "x402 guard lifetime {lifetime} exceeds cap {max}")
            }
        }
    }
}

impl std::error::Error for X402Error {}

/// One payment option the server accepts (subset of the x402 `accepts` entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402Accept {
    pub scheme: String,
    pub network: String,
    /// Amount in satoshis, decimal string (x402 atomic units).
    pub amount: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    pub description: String,
    #[serde(rename = "mimeType", default)]
    pub mime_type: String,
    #[serde(default)]
    pub resource: String,
    #[serde(rename = "maxTimeoutSecs", default)]
    pub max_timeout_secs: u64,
}

/// The 402 challenge body (subset of x402 `PaymentRequired`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402Required {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub accepts: Vec<X402Accept>,
    pub resource: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub error: String,
}

/// The SRCT payment envelope inside `PAYMENT-SIGNATURE` (same fields as
/// `POST /v1/payment/submit` so the facilitator reuses one path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402SrctPayload {
    pub payment_hex: String,
    pub authorization_hex: String,
    pub auth_sigs_hex: String,
    pub auth_keys_hex: String,
}

/// The retry header body (subset of x402 `PaymentPayload`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402Signature {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub payload: X402SrctPayload,
}

/// The success header body (subset of x402 `SettlementResponse`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402Response {
    pub success: bool,
    #[serde(rename = "paymentId")]
    pub payment_id: String,
    #[serde(default)]
    pub error: String,
}

/// A bounded-spend budget the agent client enforces *before* signing.
/// Mirrors `SpendPolicy` allow-lists without moving consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402Budget {
    pub max_amount_sat: u64,
    pub allowed_recipients: Vec<Address>,
    pub allowed_services: Vec<[u8; 32]>,
}

impl X402Budget {
    /// Refuse anything outside the budget before any key is touched.
    pub fn check(
        &self,
        amount_sat: u64,
        recipient: &Address,
        service: &Option<[u8; 32]>,
    ) -> Result<(), X402Error> {
        if amount_sat == 0 {
            return Err(X402Error::ZeroAmount);
        }
        if amount_sat > self.max_amount_sat {
            return Err(X402Error::AmountTooLarge {
                amount: amount_sat,
                max: self.max_amount_sat,
            });
        }
        if !self.allowed_recipients.is_empty() && !self.allowed_recipients.contains(recipient) {
            return Err(X402Error::RecipientNotAllowed);
        }
        if let Some(svc) = service {
            if !self.allowed_services.is_empty() && !self.allowed_services.contains(svc) {
                return Err(X402Error::ServiceNotAllowed);
            }
        }
        Ok(())
    }
}

/// Map `srct/testnet` ↔ `srct:testnet` (CAIP-2 `namespace:reference`).
pub fn srct_network_caip2(network_id: &str) -> Option<String> {
    let rest = network_id.strip_prefix("srct/")?;
    if rest.is_empty() || rest.len() > 64 {
        return None;
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(format!("{SRCT_NAMESPACE}:{rest}"))
}

/// Inverse of [`srct_network_caip2`]; refuses non-SRCT namespaces by name.
pub fn parse_srct_network(caip2: &str) -> Result<String, X402Error> {
    let (ns, reference) = caip2
        .split_once(':')
        .ok_or_else(|| X402Error::UnknownNetwork(caip2.to_string()))?;
    if ns != SRCT_NAMESPACE {
        return Err(X402Error::UnknownNetwork(caip2.to_string()));
    }
    if reference.is_empty() || reference.len() > 64 {
        return Err(X402Error::UnknownNetwork(caip2.to_string()));
    }
    if !reference
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(X402Error::UnknownNetwork(caip2.to_string()));
    }
    Ok(format!("srct/{reference}"))
}

/// Parse a decimal satoshi amount; no floats anywhere.
pub fn parse_sat_amount(raw: &str) -> Result<u64, X402Error> {
    if raw.is_empty() || raw.len() > 20 {
        return Err(X402Error::Malformed("amount length"));
    }
    if !raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(X402Error::Malformed("amount digits"));
    }
    raw.parse::<u64>()
        .map_err(|_| X402Error::Malformed("amount parse"))
}

/// Build a 402 challenge for one SRCT price point.
pub fn build_required(
    network_id: &str,
    amount_sat: u64,
    pay_to_hex: String,
    resource: String,
    description: String,
) -> Result<X402Required, X402Error> {
    if amount_sat == 0 {
        return Err(X402Error::ZeroAmount);
    }
    if resource.len() > MAX_X402_STRING_LEN || description.len() > MAX_X402_STRING_LEN {
        return Err(X402Error::Malformed("resource/description too long"));
    }
    let network = srct_network_caip2(network_id)
        .ok_or_else(|| X402Error::UnknownNetwork(network_id.to_string()))?;
    Ok(X402Required {
        x402_version: X402_VERSION,
        accepts: vec![X402Accept {
            scheme: SRCT_SCHEME.to_string(),
            network,
            amount: amount_sat.to_string(),
            pay_to: pay_to_hex,
            description: description.clone(),
            mime_type: "application/json".to_string(),
            resource: resource.clone(),
            max_timeout_secs: 60,
        }],
        resource,
        description,
        error: "payment required".to_string(),
    })
}

/// Pick the cheapest compatible option inside the budget.
pub fn select_accept<'a>(
    required: &'a X402Required,
    budget: &X402Budget,
    recipient: &Address,
    service: &Option<[u8; 32]>,
) -> Result<&'a X402Accept, X402Error> {
    if required.x402_version != X402_VERSION {
        return Err(X402Error::UnsupportedVersion(required.x402_version));
    }
    if required.accepts.is_empty() || required.accepts.len() > MAX_X402_ACCEPTS {
        return Err(X402Error::Malformed("accepts length"));
    }
    let mut best: Option<&X402Accept> = None;
    let mut best_amount = u64::MAX;
    for accept in &required.accepts {
        if accept.scheme != SRCT_SCHEME {
            continue;
        }
        // Network must parse as SRCT; non-SRCT options are skipped, not fatal,
        // so one server can advertise EVM + SRCT side by side.
        if parse_srct_network(&accept.network).is_err() {
            continue;
        }
        // One malformed amount must not poison the whole challenge: skip it
        // so a server can advertise a bad option beside good ones.
        let Ok(amount) = parse_sat_amount(&accept.amount) else {
            continue;
        };
        if amount == 0 {
            continue;
        }
        // The choice must be for this recipient: budget is per-payee, and a
        // global cheapest across payees would route to the wrong guard.
        if address_from_hex(&accept.pay_to).ok() != Some(*recipient) {
            continue;
        }
        budget.check(amount, recipient, service)?;
        if amount < best_amount {
            best_amount = amount;
            best = Some(accept);
        }
    }
    best.ok_or_else(|| X402Error::BudgetExceeded("no compatible accept inside budget".to_string()))
}

/// Parse an EVM CAIP-2 id (`eip155:<chain>`) for the rails this adapter speaks
/// beside SRCT: Base mainnet and Base Sepolia. Returns the chain id. Anything
/// else — including SRCT — is refused by name, so an EVM route can never be
/// mistaken for an SRCT settlement the node would admit.
pub fn parse_evm_caip2(caip2: &str) -> Result<u64, X402Error> {
    let (ns, reference) = caip2
        .split_once(':')
        .ok_or_else(|| X402Error::UnknownNetwork(caip2.to_string()))?;
    if ns != EVM_NAMESPACE {
        return Err(X402Error::UnknownNetwork(caip2.to_string()));
    }
    let chain: u64 = reference
        .parse()
        .map_err(|_| X402Error::UnknownNetwork(caip2.to_string()))?;
    if chain == BASE_CHAIN_ID || chain == BASE_SEPOLIA_CHAIN_ID {
        Ok(chain)
    } else {
        Err(X402Error::UnknownNetwork(caip2.to_string()))
    }
}

impl X402Accept {
    /// An EVM payment option (e.g. USDC on Base) advertised beside the SRCT
    /// option. `amount` is in the route's own atomic units and `pay_to` is the
    /// route's address encoding — the guard checks the SRCT-equivalent budget
    /// before signing, but settlement on the EVM rail is the external
    /// facilitator's job, never this node's.
    pub fn evm(
        chain_id: u64,
        amount_atomic: String,
        pay_to: String,
        resource: String,
        description: String,
    ) -> Result<Self, X402Error> {
        if chain_id != BASE_CHAIN_ID && chain_id != BASE_SEPOLIA_CHAIN_ID {
            return Err(X402Error::UnknownNetwork(format!(
                "{EVM_NAMESPACE}:{chain_id}"
            )));
        }
        if amount_atomic.is_empty() || amount_atomic.len() > 64 {
            return Err(X402Error::Malformed("evm amount length"));
        }
        if !amount_atomic.chars().all(|c| c.is_ascii_digit()) {
            return Err(X402Error::Malformed("evm amount digits"));
        }
        if pay_to.len() > MAX_X402_STRING_LEN
            || resource.len() > MAX_X402_STRING_LEN
            || description.len() > MAX_X402_STRING_LEN
        {
            return Err(X402Error::Malformed("evm option too long"));
        }
        Ok(X402Accept {
            scheme: SRCT_SCHEME.to_string(),
            network: format!("{EVM_NAMESPACE}:{chain_id}"),
            amount: amount_atomic,
            pay_to,
            description,
            mime_type: "application/json".to_string(),
            resource,
            max_timeout_secs: 60,
        })
    }
}

/// Build a challenge that advertises SRCT first and one EVM rail (Base)
/// second. A server that only settles SRCT uses [`build_required`]; a server
/// reachable from Base wallets uses this, and the agent picks the SRCT option
/// whenever the budget covers it (`select_accept` skips non-SRCT networks, so
/// EVM options never enter the SRCT signing path by accident).
pub fn build_required_with_evm(
    network_id: &str,
    amount_sat: u64,
    pay_to_hex: String,
    resource: String,
    description: String,
    evm: X402Accept,
) -> Result<X402Required, X402Error> {
    parse_evm_caip2(&evm.network)?;
    let mut required = build_required(network_id, amount_sat, pay_to_hex, resource, description)?;
    if required.accepts.len() + 1 > MAX_X402_ACCEPTS {
        return Err(X402Error::Malformed("accepts length"));
    }
    required.accepts.push(evm);
    Ok(required)
}

/// A granted wallet check: the exact payment the guard approved. The agent
/// signs only what matches this — amount, recipient, service and a short
/// expiry — so the budget is enforced *before* any key is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardGrant {
    pub amount_sat: u64,
    pub recipient: Address,
    pub service: Option<[u8; 32]>,
    /// Exclusive: the payment must land at a height below this.
    pub expires_at_height: u64,
}

impl X402Budget {
    /// Budget check plus short-lived expiry: the amount/recipient/service must
    /// fit the budget, the challenge height must precede the expiry, and the
    /// window must fit inside [`MAX_GUARD_LIFETIME_BLOCKS`]. Returns the grant
    /// the agent may sign — nothing else.
    pub fn check_guarded(
        &self,
        amount_sat: u64,
        recipient: &Address,
        service: &Option<[u8; 32]>,
        height: u64,
        expires_at_height: u64,
    ) -> Result<GuardGrant, X402Error> {
        self.check(amount_sat, recipient, service)?;
        if height >= expires_at_height {
            return Err(X402Error::Expired {
                expires_at_height,
                height,
            });
        }
        let lifetime = expires_at_height.saturating_sub(height);
        if lifetime > MAX_GUARD_LIFETIME_BLOCKS {
            return Err(X402Error::LifetimeTooLong {
                lifetime,
                max: MAX_GUARD_LIFETIME_BLOCKS,
            });
        }
        Ok(GuardGrant {
            amount_sat,
            recipient: *recipient,
            service: *service,
            expires_at_height,
        })
    }
}

// --- minimal base64 (RFC 4648, standard alphabet) so no new dependency ---

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard base64 encode.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_TABLE[((triple >> 18) & 63) as usize] as char);
        out.push(B64_TABLE[((triple >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_TABLE[((triple >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_TABLE[(triple & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Standard base64 decode; padding-aware, refuses trailing bytes.
pub fn base64_decode(raw: &str) -> Result<Vec<u8>, X402Error> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err(X402Error::Malformed("base64 length"));
    }
    if bytes.len() > 64 * 1024 {
        return Err(X402Error::Malformed("base64 too long"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 {
            return Err(X402Error::Malformed("base64 padding"));
        }
        let mut sextets = [0u8; 4];
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                if i < 4 - pad {
                    return Err(X402Error::Malformed("base64 padding position"));
                }
                sextets[i] = 0;
            } else {
                if pad > 0 && i >= 4 - pad {
                    return Err(X402Error::Malformed("base64 data after padding"));
                }
                sextets[i] = b64_value(b).ok_or(X402Error::Malformed("base64 alphabet"))?;
            }
        }
        let triple = ((sextets[0] as u32) << 18)
            | ((sextets[1] as u32) << 12)
            | ((sextets[2] as u32) << 6)
            | (sextets[3] as u32);
        out.push(((triple >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if pad == 0 {
            out.push((triple & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Encode a challenge for the `PAYMENT-REQUIRED` header.
pub fn encode_required(required: &X402Required) -> Result<String, X402Error> {
    let json = serde_json::to_vec(required).map_err(|_| X402Error::Malformed("required json"))?;
    Ok(base64_encode(&json))
}

/// Decode a `PAYMENT-REQUIRED` header value.
pub fn decode_required(header: &str) -> Result<X402Required, X402Error> {
    let bytes = base64_decode(header)?;
    let required: X402Required =
        serde_json::from_slice(&bytes).map_err(|_| X402Error::Malformed("required json"))?;
    if required.x402_version != X402_VERSION {
        return Err(X402Error::UnsupportedVersion(required.x402_version));
    }
    if required.accepts.is_empty() || required.accepts.len() > MAX_X402_ACCEPTS {
        return Err(X402Error::Malformed("accepts length"));
    }
    Ok(required)
}

/// Encode a client retry for the `PAYMENT-SIGNATURE` header.
pub fn encode_signature(sig: &X402Signature) -> Result<String, X402Error> {
    if sig.x402_version != X402_VERSION {
        return Err(X402Error::UnsupportedVersion(sig.x402_version));
    }
    if sig.scheme != SRCT_SCHEME {
        return Err(X402Error::UnsupportedScheme(sig.scheme.clone()));
    }
    parse_srct_network(&sig.network)?;
    let json = serde_json::to_vec(sig).map_err(|_| X402Error::Malformed("signature json"))?;
    Ok(base64_encode(&json))
}

/// Decode a `PAYMENT-SIGNATURE` header value.
pub fn decode_signature(header: &str) -> Result<X402Signature, X402Error> {
    let bytes = base64_decode(header)?;
    let sig: X402Signature =
        serde_json::from_slice(&bytes).map_err(|_| X402Error::Malformed("signature json"))?;
    if sig.x402_version != X402_VERSION {
        return Err(X402Error::UnsupportedVersion(sig.x402_version));
    }
    if sig.scheme != SRCT_SCHEME {
        return Err(X402Error::UnsupportedScheme(sig.scheme.clone()));
    }
    parse_srct_network(&sig.network)?;
    if sig.payload.payment_hex.is_empty() || sig.payload.payment_hex.len() > 64 * 1024 {
        return Err(X402Error::Malformed("payload length"));
    }
    Ok(sig)
}

/// Encode a success for the `PAYMENT-RESPONSE` header.
pub fn encode_response(resp: &X402Response) -> String {
    let json = serde_json::to_vec(resp).unwrap_or_else(|_| b"{}".to_vec());
    base64_encode(&json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caip2_roundtrip() {
        assert_eq!(srct_network_caip2("srct/testnet").unwrap(), "srct:testnet");
        assert_eq!(parse_srct_network("srct:testnet").unwrap(), "srct/testnet");
        assert!(parse_srct_network("eip155:84532").is_err());
        assert!(srct_network_caip2("other/testnet").is_none());
    }

    #[test]
    fn base64_roundtrip_vectors() {
        for raw in [b"".as_slice(), b"f", b"fo", b"foo", b"foob", b"hello world"] {
            let enc = base64_encode(raw);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec, raw);
        }
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert!(base64_decode("!!!").is_err());
    }

    #[test]
    fn required_signature_roundtrip() {
        let req = build_required(
            "srct/testnet",
            500,
            "ab".to_string(),
            "/v1/paid/weather".to_string(),
            "weather".to_string(),
        )
        .unwrap();
        let header = encode_required(&req).unwrap();
        let back = decode_required(&header).unwrap();
        assert_eq!(back, req);
        let sig = X402Signature {
            x402_version: X402_VERSION,
            scheme: SRCT_SCHEME.to_string(),
            network: "srct:testnet".to_string(),
            payload: X402SrctPayload {
                payment_hex: "aa".to_string(),
                authorization_hex: "bb".to_string(),
                auth_sigs_hex: "cc".to_string(),
                auth_keys_hex: "dd".to_string(),
            },
        };
        let sh = encode_signature(&sig).unwrap();
        assert_eq!(decode_signature(&sh).unwrap(), sig);
    }

    #[test]
    fn budget_refuses_overrun_and_allowlist() {
        let budget = X402Budget {
            max_amount_sat: 600,
            allowed_recipients: vec![[1u8; 20]],
            allowed_services: vec![[2u8; 32]],
        };
        assert!(budget.check(500, &[1u8; 20], &Some([2u8; 32])).is_ok());
        assert!(matches!(
            budget.check(700, &[1u8; 20], &Some([2u8; 32])),
            Err(X402Error::AmountTooLarge { .. })
        ));
        assert_eq!(
            budget.check(500, &[9u8; 20], &Some([2u8; 32])),
            Err(X402Error::RecipientNotAllowed)
        );
        assert_eq!(
            budget.check(500, &[1u8; 20], &Some([9u8; 32])),
            Err(X402Error::ServiceNotAllowed)
        );
    }

    #[test]
    fn guard_is_short_lived_and_evm_routes_parse() {
        let budget = X402Budget {
            max_amount_sat: 600,
            allowed_recipients: vec![[1u8; 20]],
            allowed_services: vec![],
        };
        let grant = budget
            .check_guarded(500, &[1u8; 20], &None, 100, 110)
            .unwrap();
        assert_eq!(grant.expires_at_height, 110);
        // Past expiry refuses by name.
        assert!(matches!(
            budget.check_guarded(500, &[1u8; 20], &None, 110, 110),
            Err(X402Error::Expired { .. })
        ));
        // A window longer than the cap refuses at guard time, not at signing.
        assert!(matches!(
            budget.check_guarded(
                500,
                &[1u8; 20],
                &None,
                100,
                100 + MAX_GUARD_LIFETIME_BLOCKS + 1
            ),
            Err(X402Error::LifetimeTooLong { .. })
        ));
        // Over-budget still refuses first.
        assert!(matches!(
            budget.check_guarded(700, &[1u8; 20], &None, 100, 110),
            Err(X402Error::AmountTooLarge { .. })
        ));
        // Base rails parse; anything else (including SRCT) is not an EVM route.
        assert_eq!(parse_evm_caip2("eip155:8453").unwrap(), BASE_CHAIN_ID);
        assert_eq!(
            parse_evm_caip2("eip155:84532").unwrap(),
            BASE_SEPOLIA_CHAIN_ID
        );
        assert!(parse_evm_caip2("srct:testnet").is_err());
        assert!(parse_evm_caip2("eip155:1").is_err());
        // A dual-rail challenge advertises SRCT first, Base second, and the
        // SRCT signing path still picks the SRCT option.
        let evm = X402Accept::evm(
            BASE_CHAIN_ID,
            "1000000".to_string(),
            "0xbasepayee".to_string(),
            "/v1/paid/weather".to_string(),
            "weather".to_string(),
        )
        .unwrap();
        let required = build_required_with_evm(
            "srct/testnet",
            500,
            "0101010101010101010101010101010101010101".to_string(),
            "/v1/paid/weather".to_string(),
            "weather".to_string(),
            evm,
        )
        .unwrap();
        assert_eq!(required.accepts.len(), 2);
        assert_eq!(required.accepts[0].network, "srct:testnet");
        assert_eq!(required.accepts[1].network, "eip155:8453");
        let picked = select_accept(&required, &budget, &[1u8; 20], &None).unwrap();
        assert_eq!(picked.network, "srct:testnet");
    }
}
