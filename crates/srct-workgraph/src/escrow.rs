//! Revenue escrow for royalty settlement (non-consensus).
//!
//! [`crate::WorkGraph::settle_revenue`] computes who is owed what; this book
//! holds the money side as instructions. A payer locks revenue for a child
//! artifact once, the rail releases each computed payout (never more than the
//! locked total across all releases), and the remainder refunds to the payer
//! exactly once. Nothing here moves coin — releases and refunds are the
//! payment rail's instructions, in the same idiom as the compute job escrow.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::Address;
use srct_core::hash::{sha256_dom, Hash};
use srct_core::ser::Writer;

use crate::WorkError;

/// The exact transfer the payment layer should execute on release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevenuePayout {
    pub from: Address,
    pub to: Address,
    pub amount_sat: u64,
    pub artifact: Hash,
    pub revenue: Hash,
}

/// The exact return the payment layer should execute on refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevenueRefund {
    pub to: Address,
    pub amount_sat: u64,
    pub artifact: Hash,
    pub revenue: Hash,
}

#[derive(Clone, Debug)]
struct LockedRevenue {
    artifact: Hash,
    payer: Address,
    amount_sat: u64,
}

/// One-shot revenue lock per earning event, with cumulative releases.
#[derive(Clone, Debug, Default)]
pub struct RevenueEscrow {
    network_id: String,
    locked: BTreeMap<Hash, LockedRevenue>,
    released: BTreeMap<Hash, u64>,
    refunded: BTreeSet<Hash>,
}

const DOM_REVENUE: &[u8] = b"srct/workgraph/revenue/v1";

impl RevenueEscrow {
    pub fn new(network_id: impl Into<String>) -> Self {
        RevenueEscrow {
            network_id: network_id.into(),
            locked: BTreeMap::new(),
            released: BTreeMap::new(),
            refunded: BTreeSet::new(),
        }
    }

    /// Lock `amount_sat` of revenue for `artifact`, funded by `payer`.
    /// The `nonce` keeps two identical earnings distinct; the same terms
    /// fund once.
    pub fn lock(
        &mut self,
        artifact: &Hash,
        payer: Address,
        amount_sat: u64,
        nonce: u64,
    ) -> Result<Hash, WorkError> {
        if amount_sat == 0 {
            return Err(WorkError::Malformed("revenue lock amount is zero".into()));
        }
        let mut w = Writer::with_capacity(128);
        w.u8(1)
            .raw(self.network_id.as_bytes())
            .fixed(artifact)
            .fixed(&payer)
            .u64le(amount_sat)
            .u64le(nonce);
        let id: Hash = sha256_dom(DOM_REVENUE, &[&w.into_vec()]);
        if self.locked.contains_key(&id) {
            return Err(WorkError::Replay);
        }
        self.locked.insert(
            id,
            LockedRevenue {
                artifact: *artifact,
                payer,
                amount_sat,
            },
        );
        Ok(id)
    }

    /// Release one computed payout. Cumulative releases never exceed the
    /// locked total; a revenue locks once, releases many times, refunds once.
    pub fn release(
        &mut self,
        revenue: &Hash,
        to: Address,
        amount_sat: u64,
    ) -> Result<RevenuePayout, WorkError> {
        let funding = self.locked.get(revenue).ok_or(WorkError::UnknownArtifact)?;
        if self.refunded.contains(revenue) {
            return Err(WorkError::Malformed("revenue already refunded".into()));
        }
        if amount_sat == 0 {
            return Err(WorkError::Malformed(
                "revenue release amount is zero".into(),
            ));
        }
        let paid = self.released.get(revenue).copied().unwrap_or(0);
        let total = paid
            .checked_add(amount_sat)
            .ok_or_else(|| WorkError::Malformed("revenue release overflows".into()))?;
        if total > funding.amount_sat {
            return Err(WorkError::Malformed(
                "revenue releases exceed the locked total".into(),
            ));
        }
        self.released.insert(*revenue, total);
        Ok(RevenuePayout {
            from: funding.payer,
            to,
            amount_sat,
            artifact: funding.artifact,
            revenue: *revenue,
        })
    }

    /// Refund the unreleased remainder to the payer, exactly once. Refused
    /// after any release pattern that leaves nothing, and after a refund.
    pub fn refund(&mut self, revenue: &Hash) -> Result<RevenueRefund, WorkError> {
        let funding = self.locked.get(revenue).ok_or(WorkError::UnknownArtifact)?;
        if !self.refunded.insert(*revenue) {
            return Err(WorkError::Replay);
        }
        let paid = self.released.get(revenue).copied().unwrap_or(0);
        let remainder = funding
            .amount_sat
            .checked_sub(paid)
            .ok_or_else(|| WorkError::Malformed("revenue accounting underflows".into()))?;
        if remainder == 0 {
            self.refunded.remove(revenue);
            return Err(WorkError::Malformed(
                "revenue has no remainder to refund".into(),
            ));
        }
        Ok(RevenueRefund {
            to: funding.payer,
            amount_sat: remainder,
            artifact: funding.artifact,
            revenue: *revenue,
        })
    }

    /// Total released for one revenue id.
    pub fn released_total(&self, revenue: &Hash) -> u64 {
        self.released.get(revenue).copied().unwrap_or(0)
    }
}
