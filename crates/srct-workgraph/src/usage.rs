//! Metered-reuse oracle fed by CNNP receipts (non-consensus).
//!
//! [`crate::WorkGraph`] records *that* a derivation happened; this ledger
//! records *how much* a capability was actually used. Each entry is a
//! provider-signed CNNP [`srct_cnnp::metering::SignedReceipt`], verified on
//! the way in and counted exactly once: the same receipt hash never counts
//! twice. Totals per capability and per provider are exact sums, so a royalty
//! split over metered revenue adds up by construction.
//!
//! What this is not: attribution. A receipt names a capability, not an
//! artifact — which artifact a capability belongs to is lineage the reporter
//! asserts (and [`crate::WorkGraph::register_with_evidence`] checks). The
//! escrow rail turning metered totals into payouts is the next step, not
//! this crate.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{Address, Hash};

use crate::WorkError;

/// Exact reuse counts from verified CNNP metering receipts.
#[derive(Clone, Debug, Default)]
pub struct UsageLedger {
    seen: BTreeSet<Hash>,
    units_per_capability: BTreeMap<Hash, u64>,
    revenue_per_capability: BTreeMap<Hash, u64>,
    units_per_provider: BTreeMap<Address, u64>,
}

impl UsageLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many distinct receipts have been counted.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Verify a metering receipt and count it. Returns the capability's
    /// running unit total. A receipt hash counts once; tampered receipts
    /// count never.
    pub fn record(
        &mut self,
        receipt: &srct_cnnp::metering::SignedReceipt,
    ) -> Result<u64, WorkError> {
        receipt
            .verify()
            .map_err(|e| WorkError::EvidenceRefused(e.to_string()))?;
        let id = receipt.receipt.hash();
        if !self.seen.insert(id) {
            return Err(WorkError::Replay);
        }
        let units = receipt.receipt.units as u64;
        let total = receipt.receipt.total_sat;
        let cap = receipt.receipt.capability;
        let provider = receipt.receipt.provider;
        *self.units_per_capability.entry(cap).or_insert(0) = self
            .units_per_capability
            .get(&cap)
            .copied()
            .unwrap_or(0)
            .checked_add(units)
            .ok_or_else(|| WorkError::Malformed("usage units overflow".into()))?;
        *self.revenue_per_capability.entry(cap).or_insert(0) = self
            .revenue_per_capability
            .get(&cap)
            .copied()
            .unwrap_or(0)
            .checked_add(total)
            .ok_or_else(|| WorkError::Malformed("usage revenue overflows".into()))?;
        *self.units_per_provider.entry(provider).or_insert(0) = self
            .units_per_provider
            .get(&provider)
            .copied()
            .unwrap_or(0)
            .checked_add(units)
            .ok_or_else(|| WorkError::Malformed("usage units overflow".into()))?;
        Ok(self.units_per_capability[&cap])
    }

    /// Total units counted for one capability hash.
    pub fn units_for_capability(&self, capability: &Hash) -> u64 {
        self.units_per_capability
            .get(capability)
            .copied()
            .unwrap_or(0)
    }

    /// Total sats counted for one capability hash.
    pub fn revenue_for_capability(&self, capability: &Hash) -> u64 {
        self.revenue_per_capability
            .get(capability)
            .copied()
            .unwrap_or(0)
    }

    /// Total units counted for one provider.
    pub fn units_for_provider(&self, provider: &Address) -> u64 {
        self.units_per_provider.get(provider).copied().unwrap_or(0)
    }
}
