//! Job escrow for encrypted-compute tasks (non-consensus).
//!
//! A requester funds a task once; each verified receipt releases exactly its
//! task's amount; the remainder refunds once after the deadline. Settlement
//! here is an instruction — [`Payout`] names from/to/amount — which the
//! payment or escrow rail executes. Nothing here moves coin.
//!
//! The rules mirror the compute job escrow on purpose: fund once, release per
//! verified receipt, refund the remainder exactly once after the deadline, and
//! never let releases exceed the funded pot.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{Address, Hash};

use crate::task::{FheVerifier, SignedFheReceipt, SignedFheTask};
use crate::FheError;

/// The exact transfer the payment layer should execute on release or refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payout {
    pub from: Address,
    pub to: Address,
    pub amount_sat: u64,
    pub task: Hash,
}

/// The exact return the payment layer should execute on refund: the locked
/// funds go back to the requester. No `from` — a refund leaves the pot, it
/// is never a provider payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refund {
    pub to: Address,
    pub amount_sat: u64,
    pub task: Hash,
}

#[derive(Clone, Copy, Debug)]
struct Funding {
    requester: Address,
    provider: Address,
    amount_sat: u64,
    deadline: u64,
}

/// One-shot escrow per encrypted-compute task.
#[derive(Clone, Debug, Default)]
pub struct FheEscrow {
    network_id: String,
    funds: BTreeMap<Hash, Funding>,
    released: BTreeSet<Hash>,
    refunded: BTreeSet<Hash>,
}

impl FheEscrow {
    pub fn new(network_id: impl Into<String>) -> Self {
        FheEscrow {
            network_id: network_id.into(),
            funds: BTreeMap::new(),
            released: BTreeSet::new(),
            refunded: BTreeSet::new(),
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Lock funds for a task. The task signature must verify, the network
    /// must match, the amount must be positive, funding must precede the
    /// deadline, and a task funds once.
    pub fn fund(
        &mut self,
        task: &SignedFheTask,
        amount_sat: u64,
        height: u64,
    ) -> Result<Hash, FheError> {
        task.verify()?;
        if task.task.network_id != self.network_id {
            return Err(FheError::Malformed(
                "fhe task is for another network".into(),
            ));
        }
        if amount_sat == 0 {
            return Err(FheError::Malformed("fhe funding amount is zero".into()));
        }
        if height >= task.task.deadline_height {
            return Err(FheError::Malformed(
                "fhe funding is past the deadline".into(),
            ));
        }
        let id = task.hash();
        if self.funds.contains_key(&id) {
            return Err(FheError::Malformed("fhe task is already funded".into()));
        }
        self.funds.insert(
            id,
            Funding {
                requester: task.task.requester,
                provider: task.task.provider,
                amount_sat,
                deadline: task.task.deadline_height,
            },
        );
        Ok(id)
    }

    /// Release the funded amount against a verified receipt. The receipt is
    /// cryptographically verified (bindings, deadline, exact recomputation,
    /// replay) before any money moves conceptually; a task releases once and
    /// never after a refund.
    pub fn release(
        &mut self,
        task: &SignedFheTask,
        receipt: &SignedFheReceipt,
        verifier: &mut FheVerifier,
        height: u64,
    ) -> Result<Payout, FheError> {
        let id = task.hash();
        let funding = self
            .funds
            .get(&id)
            .ok_or_else(|| FheError::Malformed("fhe task is not funded".into()))?;
        if self.released.contains(&id) {
            return Err(FheError::Malformed("fhe task already released".into()));
        }
        if self.refunded.contains(&id) {
            return Err(FheError::Malformed("fhe task already refunded".into()));
        }
        verifier.verify(task, receipt, height)?;
        self.released.insert(id);
        Ok(Payout {
            from: funding.requester,
            to: funding.provider,
            amount_sat: funding.amount_sat,
            task: id,
        })
    }

    /// Refund the funded amount after the deadline. Exactly once, and never
    /// after a release.
    pub fn refund(&mut self, task_hash: &Hash, height: u64) -> Result<Refund, FheError> {
        let funding = self
            .funds
            .get(task_hash)
            .ok_or_else(|| FheError::Malformed("fhe task is not funded".into()))?;
        if self.released.contains(task_hash) {
            return Err(FheError::Malformed("fhe task already released".into()));
        }
        if !self.refunded.insert(*task_hash) {
            return Err(FheError::Malformed("fhe task already refunded".into()));
        }
        if height <= funding.deadline {
            self.refunded.remove(task_hash);
            return Err(FheError::Malformed(
                "fhe refund is before the deadline".into(),
            ));
        }
        Ok(Refund {
            to: funding.requester,
            amount_sat: funding.amount_sat,
            task: *task_hash,
        })
    }
}
