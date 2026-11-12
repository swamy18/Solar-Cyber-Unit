//! Cross-Neural Network Protocol (CNNP) core (non-consensus).
//!
//! Independently developed models can cooperate without merging weights or
//! sharing a single runtime: each model publishes a description of the space
//! its representations live in, owners sign the representations they produce,
//! adapters translate between spaces, and discovered capabilities are priced
//! and settled per unit.
//!
//! # Scope of this crate
//!
//! - [`space::ModelSpace`]: model, tokenizer, architecture, layer, dimension.
//! - [`space::RepresentationEnvelope`]: signed representations, optionally
//!   sealed with XChaCha20-Poly1305. The owner signs a commitment to the exact
//!   payload; the AEAD binds the ciphertext to the space, owner and nonce.
//! - [`adapter::LinearAdapter`]: a signed ridge-regression map from one space
//!   to another, fitted on paired activations. It transfers representations,
//!   not model weights.
//! - [`quad::QuadraticAdapter`]: a signed second-order map on the expanded
//!   features `[x, x_i * x_j]`, fitted with the same ridge solver. It fits
//!   curves a linear projection cannot.
//! - [`registry`]: signed capability offers and deterministic discovery by
//!   service, space, price, latency, privacy and verification level.
//! - [`metering`]: provider-signed usage receipts, exact settlement checks and
//!   multi-stage plans with space continuity.
//! - [`exec`]: execution-evidence gate — `Tee`/`Fhe`/`Zk` stages require
//!   verified attestation/proof evidence (via `srct-verify`) before they
//!   settle; plain stages need only the metering receipt.
//!
//! # What this is not
//!
//! - Not consensus. Nothing here can mint, move or finalize a coin. Settlement
//!   returns the transfer the existing payment/escrow layer should make.
//! - Not a transport. Offers, envelopes and receipts are byte formats; moving
//!   them is the operator's HTTP/MCP rail.
//! - Not semantic alignment. Adapters are projections fitted to paired
//!   activations; they do not prove that two spaces mean the same thing. A
//!   semantic evaluation suite is a later milestone.
//! - Not key exchange. Sealed envelopes take a 32-byte key from the caller;
//!   deriving that key needs a KEM or an existing secure channel.
//! - Not a privacy proof. Sealing hides the representation, not the fact that a
//!   translation occurred or the space metadata.

pub mod adapter;
pub mod eval;
pub mod exec;
pub mod metering;
pub mod quad;
pub mod registry;
pub mod space;
pub mod token;

pub use adapter::LinearAdapter;
pub use eval::{evaluate, HeldOutReport};
pub use exec::{required_evidence, StageError, StageGate};
pub use metering::{
    quote_plan, settle_receipt, Plan, Quote, Settlement, SignedReceipt, UsageReceipt,
};
pub use quad::{expand, expanded_dim, QuadraticAdapter, MAX_QUAD_SOURCE_DIM, QUAD_ADAPTER_VERSION};
pub use registry::{
    cheapest_translation, discover, Candidate, Capability, DiscoveryQuery, Privacy,
    SignedCapability, Verification,
};
pub use space::{DType, ModelSpace, RepresentationEnvelope, Seal};
pub use token::{TokenizerMap, MAX_MAP_ENTRIES, MAX_PAIR_TOKENS, TOKEN_MAP_VERSION};
