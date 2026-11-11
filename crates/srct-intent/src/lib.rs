//! Universal cross-network intent settlement (non-consensus).
//!
//! An AI agent publishes a signed intent for work it wants from any
//! participating network: the service and input hashes, a price ceiling, a
//! latency ceiling, verification and privacy floors, accepted settlement
//! assets, a deadline and an arbiter. Solvers quote competitively; the creator
//! accepts one; the solver delivers a result; the book returns the exact
//! settlement or refund instruction the existing SRCT payment/escrow layer
//! should execute.
//!
//! # What this crate is
//!
//! - A deterministic, signed intent/quote/delivery/resolution wire format.
//! - Cross-asset quotes with router-signed conversion routes and integer-only
//!   conversion and ranking.
//! - A lifecycle state machine: open, accepted, fulfilled, settled, refunded,
//!   disputed, with explicit failure and timeout paths.
//! - Replay guards: one quote per solver per intent, one delivery per accepted
//!   quote, one settlement or refund per intent.
//!
//! # What this crate is not
//!
//! - Not a bridge and not an atomic swap. It produces settlement instructions;
//!   a chain adapter must execute them.
//! - Not consensus. Nothing here mints, moves or finalizes a coin.
//! - Not a light client. External-chain verification is an adapter concern.
//! - Not an escrow implementation. The existing SRCT L2 escrow/payment path is
//!   where value is locked and released.
//! - Not a complete dispute system. The arbiter is a named address; how that
//!   address is selected or held accountable is outside this crate.

pub mod book;
pub mod types;

pub use book::{
    meets_privacy, meets_verification, IntentBook, IntentError, IntentState, RefundInstruction,
    RefundReason, ResolutionOutcome, SettlementInstruction,
};
pub use types::{
    Amount, AssetId, AssetRoute, Delivery, Dispute, DisputeResolution, Intent, Privacy, Quote,
    SignedDelivery, SignedDispute, SignedIntent, SignedQuote, SignedResolution, SignedRoute,
    Verification, DELIVERY_VERSION, DISPUTE_VERSION, INTENT_VERSION, MAX_ASSETS, QUOTE_VERSION,
    RESOLUTION_VERSION, ROUTE_VERSION,
};
