//! Metering, usage receipts and multi-stage plans.
//!
//! A usage receipt is the provider's signed statement that it served `units`
//! at the offered unit price. Settlement is a pure function of the verified
//! receipt and the verified offer: it checks the price, the units cap, the
//! expiry and the arithmetic, then returns the exact transfer the existing
//! payment layer should make. No coin moves here.
//!
//! A plan is a short pipeline of capabilities. Quoting it checks that every
//! stage exists, that consecutive spaces chain (`stage[i].target ==
//! stage[i+1].source`), that the requested input/output spaces are reached,
//! and that price/privacy/verification constraints hold.

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::registry::{Candidate, Capability, Privacy, SignedCapability, Verification};

pub const RECEIPT_VERSION: u8 = 1;
pub const PLAN_VERSION: u8 = 1;
pub const MAX_PLAN_STAGES: usize = 8;
const DOM_RECEIPT: &[u8] = b"srct/cnnp/usage-receipt/v1";

/// A provider-signed proof of service.
#[derive(Clone, Debug, PartialEq)]
pub struct UsageReceipt {
    pub version: u8,
    /// Hash of the capability that priced the work.
    pub capability: Hash,
    pub payer: Address,
    /// Payer-assigned work id. Two receipts cannot claim the same request, so a
    /// provider cannot bill the same work twice under different nonces.
    pub request_id: Hash,
    pub provider: Address,
    /// Units served. One unit is one representation for translate/forward.
    pub units: u32,
    pub unit_price_sat: u64,
    pub total_sat: u64,
    /// Height the service was performed at.
    pub height: u64,
    /// Provider nonce, so two identical services have distinct receipts.
    pub nonce: u64,
}

impl UsageReceipt {
    pub fn new(
        capability: &Capability,
        payer: Address,
        request_id: Hash,
        units: u32,
        height: u64,
        nonce: u64,
    ) -> Result<Self, String> {
        let total = (units as u64)
            .checked_mul(capability.price_sat_per_unit)
            .ok_or_else(|| "receipt total overflows".to_string())?;
        Ok(UsageReceipt {
            version: RECEIPT_VERSION,
            capability: capability.hash(),
            payer,
            request_id,
            provider: capability.provider,
            units,
            unit_price_sat: capability.price_sat_per_unit,
            total_sat: total,
            height,
            nonce,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .fixed(&self.capability)
            .fixed(&self.payer)
            .fixed(&self.request_id)
            .fixed(&self.provider)
            .u32le(self.units)
            .u64le(self.unit_price_sat)
            .u64le(self.total_sat)
            .u64le(self.height)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_RECEIPT, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != RECEIPT_VERSION {
            return Err(format!("unsupported receipt version {}", self.version));
        }
        if self.request_id == [0u8; 32] {
            return Err("receipt request id must not be zero".into());
        }
        if self.units == 0 {
            return Err("receipt units must be positive".into());
        }
        let expected = (self.units as u64)
            .checked_mul(self.unit_price_sat)
            .ok_or_else(|| "receipt total overflows".to_string())?;
        if expected != self.total_sat {
            return Err("receipt total does not equal units times price".into());
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("receipt: {e}"))?;
        let capability = r.fixed().map_err(|e| format!("receipt: {e}"))?;
        let payer = r.fixed().map_err(|e| format!("receipt: {e}"))?;
        let request_id = r.fixed().map_err(|e| format!("receipt: {e}"))?;
        let provider = r.fixed().map_err(|e| format!("receipt: {e}"))?;
        let units = r.u32le().map_err(|e| format!("receipt: {e}"))?;
        let unit_price_sat = r.u64le().map_err(|e| format!("receipt: {e}"))?;
        let total_sat = r.u64le().map_err(|e| format!("receipt: {e}"))?;
        let height = r.u64le().map_err(|e| format!("receipt: {e}"))?;
        let nonce = r.u64le().map_err(|e| format!("receipt: {e}"))?;
        r.expect_end().map_err(|e| format!("receipt: {e}"))?;
        let receipt = UsageReceipt {
            version,
            capability,
            payer,
            request_id,
            provider,
            units,
            unit_price_sat,
            total_sat,
            height,
            nonce,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

/// A receipt plus the provider's signature over it.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedReceipt {
    pub receipt: UsageReceipt,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedReceipt {
    pub fn sign(receipt: UsageReceipt, provider: &Wallet) -> Result<Self, String> {
        receipt.validate()?;
        let address = provider.address().map_err(|e| e.to_string())?;
        if address != receipt.provider {
            return Err("receipt provider does not match the signing wallet".into());
        }
        let auth = Auth::sign(provider, &receipt.hash()).map_err(|e| e.to_string())?;
        Ok(SignedReceipt {
            receipt,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        self.receipt.validate()?;
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.receipt.provider {
            return Err("receipt key bundle is not the provider".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.receipt.hash())
            .map_err(|_| "receipt signature invalid".to_string())
    }
}

/// The exact transfer a settled receipt authorizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub from: Address,
    pub to: Address,
    pub amount_sat: u64,
}

/// Settle a receipt against the offer that priced it.
///
/// Refusals cover: bad signatures, a different offer, a different provider, a
/// stale offer, a future receipt, a unit count above the offer's cap, and a
/// price that does not match the offer.
pub fn settle_receipt(
    signed: &SignedReceipt,
    offer: &SignedCapability,
    height: u64,
) -> Result<Settlement, String> {
    signed.verify()?;
    offer.verify()?;
    let cap = &offer.capability;
    let receipt = &signed.receipt;
    if receipt.capability != cap.hash() {
        return Err("receipt names another capability".into());
    }
    if receipt.provider != cap.provider {
        return Err("receipt provider is not the offer provider".into());
    }
    if receipt.unit_price_sat != cap.price_sat_per_unit {
        return Err("receipt price does not match the offer".into());
    }
    if receipt.units > cap.max_units {
        return Err(format!(
            "receipt serves {} units, offer caps at {}",
            receipt.units, cap.max_units
        ));
    }
    if receipt.height > height {
        return Err("receipt is from a future height".into());
    }
    if receipt.height > cap.expires_height {
        return Err("receipt was served after the offer expired".into());
    }
    Ok(Settlement {
        from: receipt.payer,
        to: receipt.provider,
        amount_sat: receipt.total_sat,
    })
}

/// Replay guard for settled receipts.
///
/// Settlement is idempotent only in the sense that the same receipt cannot be
/// settled twice; a second receipt for the same payer-assigned `request_id` is
/// refused even if its nonce differs. This is the economic nullifier the
/// payment layer needs before moving value.
#[derive(Clone, Debug, Default)]
pub struct ReceiptBook {
    by_request: std::collections::BTreeMap<Hash, (Hash, Settlement)>,
}

impl ReceiptBook {
    pub fn new() -> Self {
        ReceiptBook::default()
    }

    pub fn len(&self) -> usize {
        self.by_request.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_request.is_empty()
    }

    pub fn is_settled(&self, request_id: &Hash) -> bool {
        self.by_request.contains_key(request_id)
    }

    /// Settle once per request id. A replay or a second receipt for the same
    /// work is refused rather than paid again.
    pub fn settle_once(
        &mut self,
        signed: &SignedReceipt,
        offer: &SignedCapability,
        height: u64,
    ) -> Result<Settlement, String> {
        let receipt_hash = signed.receipt.hash();
        if let Some((existing, _)) = self.by_request.get(&signed.receipt.request_id) {
            if *existing == receipt_hash {
                return Err("receipt already settled".into());
            }
            return Err("another receipt already settled this request".into());
        }
        let settlement = settle_receipt(signed, offer, height)?;
        self.by_request
            .insert(signed.receipt.request_id, (receipt_hash, settlement));
        Ok(settlement)
    }
}

/// A multi-stage plan: chained representation transformations or inference
/// calls across independently operated providers.
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub version: u8,
    pub payer: Address,
    /// Space the caller starts from.
    pub input: Hash,
    /// Space the caller wants back.
    pub output: Hash,
    /// Capability hashes, in execution order.
    pub stages: Vec<Hash>,
    /// Units requested from each stage, parallel to `stages`.
    pub units: Vec<u32>,
    pub max_total_sat: u64,
    pub min_privacy: Privacy,
    pub min_verification: Verification,
    /// Height after which the plan is no longer valid.
    pub deadline_height: u64,
}

impl Plan {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != PLAN_VERSION {
            return Err(format!("unsupported plan version {}", self.version));
        }
        if self.stages.is_empty() || self.stages.len() > MAX_PLAN_STAGES {
            return Err(format!(
                "plan needs 1..={MAX_PLAN_STAGES} stages, got {}",
                self.stages.len()
            ));
        }
        if self.units.len() != self.stages.len() {
            return Err("plan units must be parallel to its stages".into());
        }
        if self.units.contains(&0) {
            return Err("every plan stage needs at least one unit".into());
        }
        Ok(())
    }
}

/// A quoted plan with the exact offers and total.
#[derive(Clone, Debug)]
pub struct Quote {
    pub stages: Vec<Candidate>,
    pub total_sat: u64,
    pub total_latency_ms: u64,
    pub providers: Vec<Address>,
}

/// Quote a plan against a set of offers.
///
/// Every stage must be present, valid, within the plan's privacy and
/// verification floors, and space-continuous: the plan's input must match the
/// first stage's source, each stage's target must equal the next stage's
/// source, and the last target must equal the plan's output. A plan that asks
/// for one provider to do everything is legal; a plan that silently skips a
/// space is not.
pub fn quote_plan(plan: &Plan, offers: &[SignedCapability], height: u64) -> Result<Quote, String> {
    plan.validate()?;
    if height > plan.deadline_height {
        return Err("plan deadline has passed".into());
    }
    let mut stages: Vec<Candidate> = Vec::with_capacity(plan.stages.len());
    let mut total_sat = 0u64;
    let mut total_latency_ms = 0u64;
    let mut providers = Vec::with_capacity(plan.stages.len());
    let mut expected_source = plan.input;
    for (i, hash) in plan.stages.iter().enumerate() {
        let offer = offers
            .iter()
            .find(|s| s.capability.hash() == *hash)
            .ok_or_else(|| format!("stage {i}: offer {hash:?} not found"))?;
        offer.verify().map_err(|e| format!("stage {i}: {e}"))?;
        let cap = &offer.capability;
        if cap.source.hash() != expected_source {
            return Err(format!(
                "stage {i}: expected source space {expected_source:?}, offer consumes {:?}",
                cap.source.hash()
            ));
        }
        if cap.privacy < plan.min_privacy {
            return Err(format!("stage {i}: privacy below the plan floor"));
        }
        if cap.verification < plan.min_verification {
            return Err(format!("stage {i}: verification below the plan floor"));
        }
        if cap.expires_height < height {
            return Err(format!("stage {i}: offer expired"));
        }
        let units = plan.units[i];
        if units > cap.max_units {
            return Err(format!(
                "stage {i}: requests {units} units, offer caps at {}",
                cap.max_units
            ));
        }
        let stage_total = (units as u64)
            .checked_mul(cap.price_sat_per_unit)
            .ok_or_else(|| "plan stage total overflows".to_string())?;
        total_sat = total_sat
            .checked_add(stage_total)
            .ok_or_else(|| "plan total overflows".to_string())?;
        total_latency_ms = total_latency_ms
            .checked_add(cap.latency_ms as u64)
            .ok_or_else(|| "plan latency overflows".to_string())?;
        providers.push(cap.provider);
        expected_source = cap.target.hash();
        stages.push(Candidate {
            capability_hash: *hash,
            signed: offer.clone(),
        });
    }
    if expected_source != plan.output {
        return Err(format!(
            "plan ends at space {expected_source:?}, expected {:?}",
            plan.output
        ));
    }
    if total_sat > plan.max_total_sat {
        return Err(format!(
            "plan costs {total_sat} sat, cap is {}",
            plan.max_total_sat
        ));
    }
    Ok(Quote {
        stages,
        total_sat,
        total_latency_ms,
        providers,
    })
}
