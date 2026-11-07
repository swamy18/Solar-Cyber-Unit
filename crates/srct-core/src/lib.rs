//! # srct-core
//!
//! Reference implementation of the Solar Cyber Unit base layer (SPEC.md v0.1).
//!
//! Scope of this crate:
//! - hybrid hash + neural PoW puzzle (SPEC.md §5) with a versioned puzzle registry
//! - canonical byte-level serialization (§3)
//! - UTXO ledger, transaction and block validation (§9)
//! - LWMA difficulty adjustment and tamper-resistant timestamp rules (§6)
//! - halving-ladder supply schedule with a tail and a per-height rate anchor,
//!   plus EIP-1559-shaped fee burn (§7, §8)
//! - deepest-chain fork choice with a finality rule
//!
//! Protocol Mechanisms (in-scope, SPEC.md §M1–§M5):
//! - M1: 50/50 PSCB base-fee split  (`fees.rs`, `chain.rs`)
//! - M2: Slash vesting vault          (`slash.rs`)
//! - M3: Hardware-agnostic compute IR (`compute_ir.rs`)
//! - M4: Memory-bound HBM scratchpad PoW (`hbm_pow.rs`)
//! - M5: Sovereign BLS finality gadget  (`bls_checkpoint.rs`)
//!
//! Machine/agent layer (roadmap items 3, 4, 6, 10 — policy, not consensus):
//! - deterministic agent identity + reusable authorization policies (`agent.rs`)
//! - canonical machine/agent payments and settlement batching (`payment.rs`)
//! - streaming micro-payments for pay-as-you-use (`stream.rs`)

pub mod agent;
pub mod arbitration;
pub mod block;
pub mod bls;
pub mod bls_checkpoint;
pub mod bond;
pub mod bsaver;
pub mod chain;
pub mod compute_ir;
pub mod credit;
pub mod delegation;
pub mod deliverable;
pub mod difficulty;
pub mod error;
pub mod escrow;
pub mod exit;
pub mod fees;
pub mod finality;
pub mod fx;
pub mod guard;
pub mod hash;
pub mod hbm_pow;
pub mod hexserde;
pub mod jobs;
pub mod l2;
pub mod ledger;
pub mod lending;
pub mod mempool;
pub mod micro;
pub mod params;
pub mod passport;
pub mod payment;
pub mod portable;
pub mod puzzle;
pub mod ramp;
pub mod receipt;
pub mod reputation;
pub mod safety;
pub mod ser;
pub mod service;
pub mod sig;
pub mod signing;
pub mod slash;
pub mod state_root;
pub mod stream;
pub mod supply;
pub mod tiers;
pub mod treats;
pub mod tx;
pub mod u256;
pub mod validators;
pub mod wallet;
pub mod x402;

pub use error::{Error, Result};
pub use hash::{Address, Hash};
