//! Settlement adapter seam and an executing in-memory rail (non-consensus).
//!
//! [`crate::IntentBook`] produces instructions; something must execute them.
//! [`SettlementAdapter`] is that seam: `execute_settlement` pays the solver,
//! `execute_refund` returns the creator's escrow. [`MemRail`] is the
//! reference executor — real balance movements with replay refusal, not a
//! stub — so the full lifecycle settles end to end in tests. A chain adapter
//! (SRCT escrow, EVM rail, ramp payout) implements the same two calls against
//! its own ledger; the book never changes.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{Address, Hash};

use crate::book::{RefundInstruction, SettlementInstruction};
use crate::types::Amount;

/// Why an adapter refused an instruction. Fail-closed: a refusal moves
/// nothing and changes no rail state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    InsufficientFunds { needed: u64, available: u64 },
    UnknownEscrow,
    AlreadyExecuted,
    Refused(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::InsufficientFunds { needed, available } => {
                write!(f, "adapter needs {needed} sat, escrow holds {available}")
            }
            AdapterError::UnknownEscrow => write!(f, "no escrow for this intent"),
            AdapterError::AlreadyExecuted => write!(f, "instruction already executed"),
            AdapterError::Refused(detail) => write!(f, "adapter refused: {detail}"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// What the rail did with an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterReceipt {
    pub intent: Hash,
    pub to: Address,
    pub amount: Amount,
    pub reference: Hash,
}

/// Executes book instructions against a value rail.
pub trait SettlementAdapter {
    fn execute_settlement(
        &mut self,
        instruction: &SettlementInstruction,
    ) -> Result<AdapterReceipt, AdapterError>;
    fn execute_refund(
        &mut self,
        instruction: &RefundInstruction,
    ) -> Result<AdapterReceipt, AdapterError>;
}

/// In-memory executing rail. Balances are faucet-funded in tests; escrow is
/// locked per intent at open, settlement pays the solver from it, and a
/// refund returns the remainder to the creator. Every execution is recorded,
/// so a replayed instruction is refused instead of paid twice.
#[derive(Clone, Debug, Default)]
pub struct MemRail {
    balances: BTreeMap<Address, u64>,
    escrowed: BTreeMap<Hash, (Address, u64)>,
    settled: BTreeSet<(Hash, Hash)>,
    refunded: BTreeSet<Hash>,
    log: Vec<AdapterReceipt>,
}

impl MemRail {
    pub fn new() -> Self {
        Self::default()
    }

    /// Faucet-fund an address (test and demo setup only).
    pub fn fund(&mut self, to: Address, amount_sat: u64) {
        *self.balances.entry(to).or_insert(0) = self
            .balances
            .get(&to)
            .copied()
            .unwrap_or(0)
            .saturating_add(amount_sat);
    }

    pub fn balance(&self, of: &Address) -> u64 {
        self.balances.get(of).copied().unwrap_or(0)
    }

    /// Lock escrow for an intent. Funded once; a second funding is refused.
    pub fn fund_escrow(
        &mut self,
        intent: Hash,
        from: Address,
        amount_sat: u64,
    ) -> Result<(), AdapterError> {
        if self.escrowed.contains_key(&intent) {
            return Err(AdapterError::AlreadyExecuted);
        }
        let balance = self.balances.get(&from).copied().unwrap_or(0);
        if balance < amount_sat {
            return Err(AdapterError::InsufficientFunds {
                needed: amount_sat,
                available: balance,
            });
        }
        self.balances.insert(from, balance - amount_sat);
        self.escrowed.insert(intent, (from, amount_sat));
        Ok(())
    }

    pub fn receipts(&self) -> &[AdapterReceipt] {
        &self.log
    }
}

impl SettlementAdapter for MemRail {
    fn execute_settlement(
        &mut self,
        instruction: &SettlementInstruction,
    ) -> Result<AdapterReceipt, AdapterError> {
        // Every check first; state changes only after the last refusal.
        if self
            .settled
            .contains(&(instruction.intent, instruction.reference))
        {
            return Err(AdapterError::AlreadyExecuted);
        }
        if self.refunded.contains(&instruction.intent) {
            return Err(AdapterError::Refused("intent already refunded".into()));
        }
        let (from, locked) = self
            .escrowed
            .get(&instruction.intent)
            .copied()
            .ok_or(AdapterError::UnknownEscrow)?;
        if from != instruction.from {
            return Err(AdapterError::Refused(
                "settlement payer is not the escrow".into(),
            ));
        }
        if locked < instruction.amount.amount {
            return Err(AdapterError::InsufficientFunds {
                needed: instruction.amount.amount,
                available: locked,
            });
        }
        self.settled
            .insert((instruction.intent, instruction.reference));
        self.escrowed.insert(
            instruction.intent,
            (from, locked - instruction.amount.amount),
        );
        *self.balances.entry(instruction.to).or_insert(0) = self
            .balances
            .get(&instruction.to)
            .copied()
            .unwrap_or(0)
            .saturating_add(instruction.amount.amount);
        let receipt = AdapterReceipt {
            intent: instruction.intent,
            to: instruction.to,
            amount: instruction.amount,
            reference: instruction.reference,
        };
        self.log.push(receipt);
        Ok(receipt)
    }

    fn execute_refund(
        &mut self,
        instruction: &RefundInstruction,
    ) -> Result<AdapterReceipt, AdapterError> {
        if !self.refunded.insert(instruction.intent) {
            return Err(AdapterError::AlreadyExecuted);
        }
        let locked = self
            .escrowed
            .get(&instruction.intent)
            .copied()
            .ok_or(AdapterError::UnknownEscrow)
            .map(|(_, amount)| amount)?;
        if locked < instruction.amount.amount {
            self.refunded.remove(&instruction.intent);
            return Err(AdapterError::InsufficientFunds {
                needed: instruction.amount.amount,
                available: locked,
            });
        }
        self.escrowed.remove(&instruction.intent);
        *self.balances.entry(instruction.to).or_insert(0) = self
            .balances
            .get(&instruction.to)
            .copied()
            .unwrap_or(0)
            .saturating_add(instruction.amount.amount);
        let receipt = AdapterReceipt {
            intent: instruction.intent,
            to: instruction.to,
            amount: instruction.amount,
            reference: instruction.intent,
        };
        self.log.push(receipt);
        Ok(receipt)
    }
}
