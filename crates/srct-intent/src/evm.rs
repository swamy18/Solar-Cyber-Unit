//! Well-known cross-chain asset ids and EVM rail settlement. Non-consensus.
//!
//! [`AssetId`] is an opaque 32-byte tag. This module pins the canonical ids
//! so every solver, quote and route names the same asset the same way:
//! `SRCT` (native), EVM-native per chain, and ERC-20 stablecoins by contract.
//!
//! [`EvmRail`] implements [`SettlementAdapter`] as an auditable local ledger
//! plus an execution plan: it validates the instruction, checks the solver
//! posted a foreign-chain receipt, and records exactly-once settlement. It
//! does NOT submit foreign transactions itself — the solver (or an external
//! facilitator) executes on the EVM side, and this rail verifies the receipt.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{sha256_dom, Address, Hash};

use super::adapter::{AdapterError, AdapterReceipt, SettlementAdapter};
use super::book::{RefundInstruction, SettlementInstruction};
use super::types::AssetId;

pub const SRCT_ASSET_TAG: &[u8] = b"srct/native/v1";
pub const EVM_NATIVE_TAG: &[u8] = b"srct/evm-native/v1";
pub const ERC20_TAG: &[u8] = b"srct/erc20/v1";

/// Canonical id for native SRCT.
pub fn srct_asset() -> AssetId {
    AssetId(sha256_dom(SRCT_ASSET_TAG, &[]))
}

/// Canonical id for an EVM chain's native coin (ETH on Base, etc.).
pub fn evm_native_asset(chain_id: u64) -> AssetId {
    AssetId(sha256_dom(EVM_NATIVE_TAG, &[&chain_id.to_le_bytes()]))
}

/// Canonical id for an ERC-20 token on an EVM chain.
pub fn erc20_asset(chain_id: u64, contract_20: &[u8; 20]) -> AssetId {
    AssetId(sha256_dom(
        ERC20_TAG,
        &[&chain_id.to_le_bytes(), &contract_20[..]],
    ))
}

/// A solver-posted proof that the foreign leg executed. Verified by the rail
/// operator (RPC tx lookup) before [`EvmRail::confirm_foreign`] is called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignReceipt {
    pub chain_id: u64,
    pub tx_hash: Hash,
    pub to: Vec<u8>,
    pub amount_atomic: u64,
    pub at_height: u64,
}

/// What RPC verification reported about a foreign transaction. Built by the
/// operator's RPC checker (see `templates/check_evm_receipt.py`) and handed
/// to [`EvmRail::confirm_verified`] — the rail trusts the operator, not the
/// solver, exactly like the FX/ramp whitelists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedForeignTx {
    pub chain_id: u64,
    pub tx_hash: Hash,
    pub to: Vec<u8>,
    pub amount_atomic: u64,
    pub at_height: u64,
    pub confirmed: bool,
    pub confirmations: u64,
}

/// Minimum confirmations before the rail releases escrow.
pub const EVM_MIN_CONFIRMATIONS: u64 = 12;

impl ForeignReceipt {
    pub fn id(&self) -> Hash {
        sha256_dom(
            b"srct/evm-receipt/v1",
            &[
                &self.chain_id.to_le_bytes(),
                &self.tx_hash,
                &self.to,
                &self.amount_atomic.to_le_bytes(),
            ],
        )
    }
}

/// EVM settlement rail: local SRCT-side ledger + foreign receipt gate.
///
/// Lifecycle: solver calls `note_foreign` after executing on the EVM side;
/// the operator verifies via RPC, then `confirm_foreign` marks it valid;
/// `execute_settlement` releases the SRCT escrow only when a confirmed
/// receipt covers the instruction amount.
pub struct EvmRail {
    balances: BTreeMap<Address, u64>,
    escrowed: BTreeMap<Hash, (Address, u64)>,
    settled: BTreeSet<(Hash, Hash)>,
    refunded: BTreeSet<Hash>,
    receipts: BTreeMap<Hash, ForeignReceipt>,
    confirmed: BTreeSet<Hash>,
    log: Vec<AdapterReceipt>,
}

impl EvmRail {
    pub fn new() -> Self {
        Self {
            balances: BTreeMap::new(),
            escrowed: BTreeMap::new(),
            settled: BTreeSet::new(),
            refunded: BTreeSet::new(),
            receipts: BTreeMap::new(),
            confirmed: BTreeSet::new(),
            log: Vec::new(),
        }
    }

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

    /// Solver posts a foreign receipt; operator verifies out of band.
    pub fn note_foreign(&mut self, intent: Hash, receipt: ForeignReceipt) {
        self.receipts.insert(intent, receipt);
    }

    /// Mark the solver's foreign receipt as RPC-verified.
    pub fn confirm_foreign(&mut self, intent: &Hash) -> Result<(), AdapterError> {
        if !self.receipts.contains_key(intent) {
            return Err(AdapterError::UnknownEscrow);
        }
        self.confirmed.insert(*intent);
        Ok(())
    }

    /// Confirm from an RPC verification report. Refuses unconfirmed or
    /// under-confirmed transactions by name; a mismatch against the solver's
    /// posted receipt is also a refusal, so a solver cannot post one tx and
    /// settle against another.
    pub fn confirm_verified(
        &mut self,
        intent: &Hash,
        report: &VerifiedForeignTx,
    ) -> Result<(), AdapterError> {
        let posted = self
            .receipts
            .get(intent)
            .ok_or(AdapterError::UnknownEscrow)?;
        if !report.confirmed || report.confirmations < EVM_MIN_CONFIRMATIONS {
            return Err(AdapterError::Refused(
                "foreign tx is not sufficiently confirmed".into(),
            ));
        }
        if posted.chain_id != report.chain_id
            || posted.tx_hash != report.tx_hash
            || posted.to != report.to
            || posted.amount_atomic > report.amount_atomic
        {
            return Err(AdapterError::Refused(
                "verification report does not match the posted receipt".into(),
            ));
        }
        self.confirmed.insert(*intent);
        Ok(())
    }

    pub fn receipts(&self) -> &[AdapterReceipt] {
        &self.log
    }
}

impl Default for EvmRail {
    fn default() -> Self {
        Self::new()
    }
}

impl SettlementAdapter for EvmRail {
    fn execute_settlement(
        &mut self,
        instruction: &SettlementInstruction,
    ) -> Result<AdapterReceipt, AdapterError> {
        if self
            .settled
            .contains(&(instruction.intent, instruction.reference))
        {
            return Err(AdapterError::AlreadyExecuted);
        }
        if self.refunded.contains(&instruction.intent) {
            return Err(AdapterError::Refused("intent already refunded".into()));
        }
        if !self.confirmed.contains(&instruction.intent) {
            return Err(AdapterError::Refused(
                "no confirmed foreign receipt for this intent".into(),
            ));
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

#[cfg(test)]
mod tests {
    use super::super::types::Amount;
    use super::*;
    use srct_core::wallet::Wallet;

    fn addr(label: &str) -> Address {
        Wallet::new_random(label).address().unwrap()
    }

    #[test]
    fn asset_ids_are_stable_and_distinct() {
        assert_eq!(srct_asset(), srct_asset());
        assert_ne!(srct_asset(), evm_native_asset(8453));
        assert_ne!(evm_native_asset(8453), evm_native_asset(84532));
        assert_ne!(erc20_asset(8453, &[1u8; 20]), erc20_asset(8453, &[2u8; 20]));
    }

    #[test]
    fn settlement_needs_a_confirmed_foreign_receipt() {
        let creator = addr("creator");
        let solver = addr("solver");
        let mut rail = EvmRail::new();
        rail.fund(creator, 10_000);
        let intent = [7u8; 32];
        rail.fund_escrow(intent, creator, 5_000).unwrap();
        let instruction = SettlementInstruction {
            from: creator,
            to: solver,
            amount: Amount {
                asset: srct_asset(),
                amount: 5_000,
            },
            intent,
            reference: [9u8; 32],
        };
        assert!(rail.execute_settlement(&instruction).is_err());
        rail.note_foreign(
            intent,
            ForeignReceipt {
                chain_id: 8453,
                tx_hash: [1u8; 32],
                to: vec![0xabu8; 20],
                amount_atomic: 1_000_000,
                at_height: 100,
            },
        );
        assert!(rail.execute_settlement(&instruction).is_err());
        rail.confirm_foreign(&intent).unwrap();
        let receipt = rail.execute_settlement(&instruction).unwrap();
        assert_eq!(receipt.to, solver);
        assert_eq!(rail.balance(&solver), 5_000);
        assert!(rail.execute_settlement(&instruction).is_err());
    }

    #[test]
    fn verified_reports_gate_on_confirmations_and_match() {
        let creator = addr("creator");
        let solver = addr("solver");
        let instruction = SettlementInstruction {
            from: creator,
            to: solver,
            amount: Amount {
                asset: srct_asset(),
                amount: 5_000,
            },
            intent: [8u8; 32],
            reference: [9u8; 32],
        };
        let posted = ForeignReceipt {
            chain_id: 8453,
            tx_hash: [1u8; 32],
            to: vec![0xabu8; 20],
            amount_atomic: 1_000_000,
            at_height: 100,
        };
        let good = VerifiedForeignTx {
            chain_id: 8453,
            tx_hash: [1u8; 32],
            to: vec![0xabu8; 20],
            amount_atomic: 1_000_000,
            at_height: 100,
            confirmed: true,
            confirmations: EVM_MIN_CONFIRMATIONS,
        };
        let mut rail = EvmRail::new();
        rail.fund(creator, 10_000);
        rail.fund_escrow(instruction.intent, creator, 5_000)
            .unwrap();
        rail.note_foreign(instruction.intent, posted);
        let shallow = VerifiedForeignTx {
            confirmations: EVM_MIN_CONFIRMATIONS - 1,
            ..good.clone()
        };
        assert!(rail
            .confirm_verified(&instruction.intent, &shallow)
            .is_err());
        let wrong_tx = VerifiedForeignTx {
            tx_hash: [2u8; 32],
            ..good.clone()
        };
        assert!(rail
            .confirm_verified(&instruction.intent, &wrong_tx)
            .is_err());
        rail.confirm_verified(&instruction.intent, &good).unwrap();
        rail.execute_settlement(&instruction).unwrap();
    }
}
