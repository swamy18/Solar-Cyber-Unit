//! Dollar-denominated quotes settled in SRCT, plus stablecoin-in records.
//!
//! SRCT is a mined coin, not a pegged asset: its schedule never promises a
//! dollar price. Services that want dollar pricing quote in USD (or in a
//! supported stablecoin) and settle in SRCT at a transparent, locked rate:
//!
//! - an operator-trusted FX issuer signs [`FxRate`]s (base/quoted pair, sat
//!   per minor unit, validity window);
//! - [`quote_usd`] converts `amount_usd_cents` to `sat_due` with an explicit
//!   service fee and slippage bound, all integer math, expiring at a height;
//! - [`SwapIntent`] records a stablecoin-in payment: the agent holds USDC
//!   off-protocol, pays SRCT on the marketplace at the locked quote, and the
//!   intent (amount, rate, fee, slippage, stablecoin reference) is the audit
//!   trail — custody of the stablecoin never touches this node.
//!
//! What this is not: a pegged asset. If SRCT ever ships a dollar-pegged
//! asset, it needs a credible reserve, redemption, legal and independent-audit
//! model — never an unsupported algorithmic promise. See `docs/stablecoin.md`.

use crate::agent::AgentId;
use crate::hash::{sha256_dom, Hash};

/// Domain tag for FX rate attestations.
pub const DOM_FX_RATE: &[u8] = b"srct/fx-rate/v1";
/// Domain tag for swap intents.
pub const DOM_SWAP_INTENT: &[u8] = b"srct/swap-intent/v1";
/// Basis points denominator.
pub const BPS: u64 = 10_000;
/// Longest accepted asset/network string (bounds quote parsing).
pub const MAX_FX_SYMBOL_LEN: usize = 16;

/// One attested conversion rate: 1 minor unit of `base` costs
/// `sat_per_minor` satoshis of SRCT (e.g. base "USDC", 1 cent -> N sat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FxRate {
    pub base: String,
    pub sat_per_minor: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub source: String,
    pub issuer: crate::bls_checkpoint::BlsPublicKey,
    pub sig: crate::bls_checkpoint::BlsSignature,
}

impl FxRate {
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(
            DOM_FX_RATE,
            &[
                self.base.as_bytes(),
                &self.sat_per_minor.to_le_bytes(),
                &self.valid_from_height.to_le_bytes(),
                &self.valid_until_height.to_le_bytes(),
                self.source.as_bytes(),
                &self.issuer.0,
            ],
        )
    }

    pub fn validate(&self) -> Result<(), FxError> {
        if self.base.is_empty() || self.base.len() > MAX_FX_SYMBOL_LEN {
            return Err(FxError::Malformed("base asset"));
        }
        if self.sat_per_minor == 0 {
            return Err(FxError::Malformed("zero rate"));
        }
        if self.source.len() > 64 {
            return Err(FxError::Malformed("source"));
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err(FxError::Malformed("validity window"));
        }
        Ok(())
    }

    pub fn live_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height <= self.valid_until_height
    }

    pub fn verify_sig(&self) -> bool {
        crate::bls::RealBls::verify(&self.issuer, &self.signing_hash(), &self.sig)
    }
}

/// A locked service quote: USD cents in, exact satoshis due, fee and slippage
/// stated up front, expiring at a height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub base: String,
    pub amount_minor: u64,
    pub sat_due: u64,
    pub fee_sat: u64,
    pub slippage_bps: u64,
    pub rate_sat_per_minor: u64,
    pub expires_height: u64,
}

/// Stablecoin-in record: the agent's off-protocol stablecoin budget and the
/// locked SRCT quote it settles at. The stablecoin leg happens off-protocol
/// (user wallet / exchange); this intent is the transparent record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapIntent {
    pub network_id: String,
    pub payer: AgentId,
    pub stable_asset: String,
    pub stable_minor: u64,
    pub quote: Quote,
    pub stable_ref: String,
    pub nonce: u64,
}

impl SwapIntent {
    /// Audit identity: every economic term, not just the total. Two quotes
    /// with the same `sat_due` but different rates, fees, slippage or
    /// expiry are different deals and must never share an id — otherwise
    /// the off-protocol stablecoin leg and the on-protocol SRCT leg can
    /// reference different economics under one reference.
    pub fn id(&self) -> Hash {
        sha256_dom(
            DOM_SWAP_INTENT,
            &[
                self.network_id.as_bytes(),
                &self.payer,
                self.stable_asset.as_bytes(),
                &self.stable_minor.to_le_bytes(),
                self.quote.base.as_bytes(),
                &self.quote.amount_minor.to_le_bytes(),
                &self.quote.sat_due.to_le_bytes(),
                &self.quote.fee_sat.to_le_bytes(),
                &self.quote.slippage_bps.to_le_bytes(),
                &self.quote.rate_sat_per_minor.to_le_bytes(),
                &self.quote.expires_height.to_le_bytes(),
                self.stable_ref.as_bytes(),
                &self.nonce.to_le_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), FxError> {
        if self.network_id.is_empty() || self.network_id.len() > 64 {
            return Err(FxError::Malformed("network id"));
        }
        if self.stable_asset.is_empty() || self.stable_asset.len() > MAX_FX_SYMBOL_LEN {
            return Err(FxError::Malformed("stable asset"));
        }
        if self.stable_minor == 0 || self.quote.sat_due == 0 {
            return Err(FxError::Malformed("zero amounts"));
        }
        if self.stable_ref.is_empty() || self.stable_ref.len() > 128 {
            return Err(FxError::Malformed("stable reference"));
        }
        if self.quote.slippage_bps > BPS {
            return Err(FxError::Malformed("slippage over 100%"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FxError {
    Malformed(&'static str),
    StaleRate,
    Overflow,
}

impl std::fmt::Display for FxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FxError::Malformed(w) => write!(f, "malformed fx: {w}"),
            FxError::StaleRate => write!(f, "fx rate not live at this height"),
            FxError::Overflow => write!(f, "fx arithmetic overflow"),
        }
    }
}

impl std::error::Error for FxError {}

/// Convert `amount_minor` at `rate`, adding `fee_bps` and reserving
/// `slippage_bps` headroom. `sat_due` is the exact SRCT amount the payment
/// must carry; the fee is stated separately for the audit trail.
pub fn quote_usd(
    rate: &FxRate,
    amount_minor: u64,
    fee_bps: u64,
    slippage_bps: u64,
    height: u64,
    ttl_blocks: u64,
) -> Result<Quote, FxError> {
    rate.validate()?;
    if !rate.live_at(height) {
        return Err(FxError::StaleRate);
    }
    if amount_minor == 0 {
        return Err(FxError::Malformed("zero amount"));
    }
    if fee_bps > BPS || slippage_bps > BPS {
        return Err(FxError::Malformed("bps over 100%"));
    }
    // A zero lifetime encodes an instantly-expired quote: refuse it rather
    // than minting paper no one can settle.
    if ttl_blocks == 0 {
        return Err(FxError::Malformed("ttl_blocks must be > 0"));
    }
    let gross = (amount_minor as u128)
        .checked_mul(rate.sat_per_minor as u128)
        .ok_or(FxError::Overflow)?;
    // Fee and slippage round UP: the dust remainder (< 1 sat) belongs to
    // the quoter, not the payer. Flooring biases every quote the same
    // way; the operator would bleed a sat per leg forever.
    let fee = gross
        .checked_mul(fee_bps as u128)
        .ok_or(FxError::Overflow)?
        .checked_add(BPS as u128 - 1)
        .ok_or(FxError::Overflow)?
        / BPS as u128;
    // Slippage headroom is reserved inside sat_due so the payment still
    // covers the service if the next rate ticks against the payer.
    let slip = gross
        .checked_mul(slippage_bps as u128)
        .ok_or(FxError::Overflow)?
        .checked_add(BPS as u128 - 1)
        .ok_or(FxError::Overflow)?
        / BPS as u128;
    let total = gross
        .checked_add(fee)
        .and_then(|t| t.checked_add(slip))
        .ok_or(FxError::Overflow)?;
    let sat_due: u64 = total.try_into().map_err(|_| FxError::Overflow)?;
    let fee_sat: u64 = fee.try_into().map_err(|_| FxError::Overflow)?;
    Ok(Quote {
        base: rate.base.clone(),
        amount_minor,
        sat_due,
        fee_sat,
        slippage_bps,
        rate_sat_per_minor: rate.sat_per_minor,
        expires_height: height.checked_add(ttl_blocks).ok_or(FxError::Overflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate() -> FxRate {
        FxRate {
            base: "USDC".to_string(),
            sat_per_minor: 1_000,
            valid_from_height: 0,
            valid_until_height: 10_000,
            source: "operator-oracle".to_string(),
            issuer: crate::bls_checkpoint::BlsPublicKey([5u8; 48]),
            sig: crate::bls_checkpoint::BlsSignature([0u8; 96]),
        }
    }

    #[test]
    fn quote_is_exact_and_transparent() {
        // $1.00 at 1000 sat/cent, 1% fee, 0.5% slippage: 100*1000=100_000,
        // fee 1_000, slip 500 → 101_500 due.
        let q = quote_usd(&rate(), 100, 100, 50, 500, 60).unwrap();
        assert_eq!(q.sat_due, 101_500);
        assert_eq!(q.fee_sat, 1_000);
        assert_eq!(q.expires_height, 560);
    }

    #[test]
    fn stale_rate_and_overflow_refuse() {
        assert_eq!(
            quote_usd(&rate(), 100, 0, 0, 20_000, 60),
            Err(FxError::StaleRate)
        );
        assert!(quote_usd(&rate(), u64::MAX, 0, 0, 500, 60).is_err());
    }

    #[test]
    fn dust_rounds_up_and_zero_ttl_refuses() {
        // 1 minor at 1000 sat/minor, 1.51% fee: gross 1000, fee 15.1 -> 16.
        let q = quote_usd(&rate(), 1, 151, 0, 500, 60).unwrap();
        assert_eq!(q.fee_sat, 16, "dust belongs to the quoter");
        assert_eq!(q.sat_due, 1016);
        // A zero lifetime is an instantly-expired quote: refuse it.
        assert!(quote_usd(&rate(), 100, 100, 50, 500, 0).is_err());
    }

    #[test]
    fn swap_id_covers_all_economics() {
        // Same total, different deal: must never share an audit id.
        let a = SwapIntent {
            network_id: "srct/testnet".to_string(),
            payer: [1u8; 20],
            stable_asset: "USDC".to_string(),
            stable_minor: 100,
            quote: Quote {
                base: "USDC".to_string(),
                amount_minor: 100,
                sat_due: 101_500,
                fee_sat: 1_000,
                slippage_bps: 50,
                rate_sat_per_minor: 1_000,
                expires_height: 560,
            },
            stable_ref: "r".to_string(),
            nonce: 7,
        };
        let mut b = a.clone();
        b.quote.fee_sat = 900;
        b.quote.slippage_bps = 150;
        assert_ne!(a.id(), b.id(), "different economics, different id");
    }
}
