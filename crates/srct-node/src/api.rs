//! The opt-in service API (Decision 9, roadmap §13, SPEC.md §19.2).
//!
//! `srct-node serve --api-listen <addr>` starts an HTTP/REST server beside the
//! P2P daemon. Disabled by default; loopback is the expected binding and a
//! non-loopback bind prints a warning, because exposing this port is an
//! operator decision (§19.2).
//!
//! # What this is, and what it is not
//!
//! - **Not a consensus surface.** Nothing here reaches `Chain::submit`. The
//!   only writes are: an L1 transaction that passes the exact `pool.add` path
//!   a peer's relayed transaction passes, and an L2 transaction that passes a
//!   dry-run against a *clone* of L2 state and then waits in a queue for a
//!   block to carry it — L2 state is still derived from canonical blocks
//!   alone (SPEC §19.1).
//! - **No signing, ever.** The API never sees a private key. `POST
//!   /v1/tx/build` returns *unsigned* bytes for the caller to sign;
//!   `POST /v1/authorize` returns the authorization bytes and their signing
//!   hash for the owner to sign. Refusals never echo signing material.
//! - **Bounded everything.** One body-size cap for all inputs; the receipt
//!   book, payment store and policy book are cap-with-refusal, so a flood
//!   cannot grow node memory without bound.
//! - **State it holds is non-consensus and node-local**: receipts, payment
//!   ids, policy accounting and the credit book (`CreditBook`: free balances,
//!   bonds, positions) are this node's view for lookup/authorization
//!   convenience. They are never consensus, but they do survive a restart:
//!   the serve command persists them to `state.bin` (atomic, digest-checked,
//!   fail-closed load) and flushes at shutdown. A bad file can only cost this
//!   node its own bookkeeping — it can never mint or move a coin.
//!
//! Endpoints (§13 for L1, §19.2 for the L2 additions, plus the payment/
//! receipt surface items 16–17 require):
//!
//! ```text
//! GET  /v1/health              liveness for monitors
//! GET  /metrics                Prometheus text exposition of the gauges below
//! GET  /v1/status              network, height, tip, peers, supply, finality, L2
//! GET  /v1/conservation        live joint L1+L2−sink supply vs the joint bound (the `verify` arithmetic)
//! GET  /v1/finality            finality status
//! GET  /v1/fees                fee schedule: gas, base fee, D3 L2 flat fees
//! GET  /v1/balance/{address}   confirmed / spendable / pending
//! GET  /v1/utxo/{address}      unspent outputs
//! GET  /v1/block/latest        newest block
//! GET  /v1/block/{hash}        one block by hash
//! GET  /v1/tx/{hash}           confirmed | pending | unknown (404)
//! GET  /v1/mempool             pool summary
//! POST /v1/tx/build            unsigned L1 tx (caller signs)
//! POST /v1/tx/broadcast        signed L1 tx -> pool -> relay
//! POST /v1/l2/broadcast        signed L2 tx -> dry-run -> include queue
//! GET  /v1/tasks/open          claimable tasks
//! GET  /v1/task/{task_id}      task state
//! GET  /v1/l2/state            canonical L2 state (§19.2 wire encoding)
//! GET  /v1/vwc/{task_id}       verified work certificate
//! GET  /v1/reputation/{id}      derived reputation score for a worker address
//! POST /v1/authorize           policy + payer-signed request -> authorization
//! POST /v1/policy/decide      policy + payment intent -> allow/deny/approval-needed (read-only)
//! POST /v1/delegation/verify  delegation proof -> valid/depth/leaf (read-only, any rail)
//! POST /v1/audit/verify       exported audit chain -> valid/entries (read-only, any rail)
//! POST /v1/payment/submit      verify + record a machine payment
//! GET  /v1/payment/{id}        recorded payment
//! POST /v1/payment/{id}/settle bind it to the tx that paid the recipient
//! POST /v1/receipt             verify + record a service receipt
//! GET  /v1/receipt/{id}        receipt by id (or by payment id)
//! POST /v1/payments/aggregate  quote one shared settlement for N payments
//! POST /v1/streams/open        open a pay-as-you-use stream channel
//! POST /v1/streams/settle      accept one stream voucher receipt
//! GET  /v1/streams/{id}        stream accounting + claimable at this height
//! GET /v1/payments/unsettled  recorded payments with no settlement bound
//! GET /v1/receipts/orphans    receipts claiming unrecorded payments
//! GET /v1/audit               tamper-evident audit ring + chain check
//! GET /v1/risk/policy         safety knobs: thresholds, velocity, test mode
//! POST /v1/reputation/passport/attest  assemble verifiable history events
//! POST /v1/reputation/batch   register an issuer-signed passport batch
//! GET /v1/reputation/score/{agent}     combined score + access tier
//! POST /v1/wallet/tier        validate + register a max/min-spend tier
//! GET /v1/wallet/tiers/{agent} tiers under an agent id
//! POST /v1/jobs/open          hirer locks escrow + posts an agent job
//! POST /v1/jobs/{id}/accept|deliver|dispute|resolve  job lifecycle
//! GET /v1/jobs/{id}           job record + escrow state + hold flag
//! GET /v1/payments/{id}/receipt_status  recorded/receipt/settlement state
//! POST /v1/fx/rates           register an operator-signed USD rate
//! GET /v1/fx/rates/list       live rates at this height
//! POST /v1/fx/quote           lock a dollar price into exact satoshis
//! POST /v1/fx/swap            record a stablecoin-in SRCT settlement
//! POST /v1/ramp/quote         register a provider-signed ramp quote
//! GET /v1/ramp/quotes         live entry/exit quotes
//! POST /v1/ramp/intent        accept a quote; provider fills out of band
//! POST /v1/ramp/intent/{id}/settle  provider closes filled/refunded
//! GET /v1/ramp/intents        registry trail for entry and exit
//! POST /v1/loans/offers       lender publishes signed standard terms
//! GET /v1/loans/offers/list   discover live offers, cheapest first
//! POST /v1/loans/accept       open a position on signed offer terms
//! GET /v1/lending/borrower/{a} verified history + suggested ceiling
//! GET /v1/lending/dashboard   exposure, due-soon, defaults, interest
//! GET /v1/lending/limit/{b}   suggested ceiling + loss-bearing rule
//! GET /v1/lending/collateral/{p} live collateral vs debt valuation
//! POST /v1/lending/autorepay  register standing auto-repay instruction
//! GET /v1/lending/autorepay/{b} the live instruction, if any
//! POST /v1/trials/request     record a sponsored first task (usage-based credit)
//! POST /v1/trials/fund        confirm the sponsor's L1 payment to the agent
//! GET /v1/trials/{agent}      trial record + state
//! POST /v1/trials/repay       confirm the agent's L1 repayment to the sponsor
//! GET  /v1/exit/crankable      the exit claims this node could settle now
//! POST /v1/escrow/open         open a conditional escrow with a chosen arbitrator
//! POST /v1/escrow/{id}/release arbiter- or mutual-release a live escrow (non-consensus)
//! POST /v1/escrow/{id}/settle  bind the release to the L2 exit that pays it
//! GET  /v1/escrow/{id}         escrow state
//! POST /v1/credit/deposit      fund an address's credit line (non-consensus book)
//! POST /v1/credit/mint         mint via a trusted issuer's signed attestation
//! POST /v1/credit/bond         move free credit into a posted bond, or release it
//! POST /v1/credit/open         open a credit position under a lender's terms
//! POST /v1/credit/repay        repay against a position, interest first
//! POST /v1/credit/default      settle an unpaid position at or after its deadline
//! GET  /v1/credit/balance/{address} free balance + bond + live positions
//! ```
//!
//! The list endpoints (`/v1/utxo/{address}`, `/v1/mempool`,
//! `/v1/tasks/open`) page with `?limit=&cursor=`: `limit` defaults to 100 and
//! caps at 1,000, `cursor` is an offset into a deterministically ordered list
//! (outpoint, then txid, then task id — never `HashMap` order), `count` is
//! always the total before pagination, and `next_cursor` carries the offset
//! for the next page or `null` on the last one.
//!
//! # Exposure and its guards
//!
//! Loopback is the default binding and is unauthenticated by design: every test
//! drives a socket on `127.0.0.1:0` with no token. A **non-loopback bind is
//! refused** unless a bearer token is supplied, because exposing this surface is
//! an operator decision the node will not make silently (SPEC.md §19.2).
//!
//! - **Host-header validation runs on *every* bind**, loopback included.
//!   On a loopback bind only loopback names pass (`localhost`, `127.0.0.1`,
//!   `::1`, any loopback IP literal). On a non-loopback bind any IP literal
//!   passes too — DNS rebinding cannot use an IP literal — plus the bound
//!   address and the operator's allowlisted names (`--api-allowed-host` /
//!   `SRCT_API_ALLOWED_HOSTS`). Anything else, including a missing or
//!   bracket-malformed `Host`, is 403.
//! - **Bearer authentication on an exposed bind** — every request carries
//!   `Authorization: Bearer <token>`, compared in constant time. Supply the
//!   token through the `SRCT_API_TOKEN` environment variable, not
//!   `--api-token`: command-line flags are visible to other users in `ps`,
//!   while the environment of a started process is not.
//! - **A per-IP token bucket on an exposed bind** — a flood is shed to the
//!   server. The table is bounded (idle entries are evicted), so a spray of
//!   source addresses cannot grow it without limit.
//! - **A per-request deadline and a global in-flight cap** — these apply on
//!   *every* binding, loopback included, because they bound the hold time on
//!   the shared-state `Mutex` rather than defending against a remote attacker.
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tower::Service as _;

use srct_core::agent::{derive_agent_id, AgentRole};
use srct_core::block::Block;
use srct_core::chain::Chain;
use srct_core::credit::CreditGate;
use srct_core::fees;
use srct_core::hash::{
    address_from_hex, address_to_hex, hash512_from_hex, hash512_to_hex, hash_from_hex, hash_to_hex,
    Address, Hash, Hash512,
};
use srct_core::l2::{L2Payload, L2Transaction};
use srct_core::mempool::Mempool;
use srct_core::params::{NetworkParams, L2_FEE_SCHEDULE, SAT_PER_SRCT};
use srct_core::payment::{MachinePayment, PaymentTracker};
use srct_core::receipt::{ReceiptBook, ReceiptOutcome};
use srct_core::ser::{Reader, Writer};
use srct_core::service::{authorize_request_with_chain, SessionError};
use srct_core::tx::{Transaction, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE};
use srct_l2::reputation::ledger_from_state;
use srct_l2::task_contract::{ContractState, TaskContract};

use crate::conservation::conservation_report;
use crate::l2::NodeL2;

/// Largest request body. A block is at most `max_block_bytes` (4 MB on every
/// profile), and the API only ever accepts transactions, payments, receipts,
/// policies and requests — none of which approach that. Explicit rather than
/// framework-default so the bound is visible in this file's docs.
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Version of the node-local state envelope written by
/// [`SharedNode::encode_state`]. A build that writes a different format writes
/// a different value, so an old file is refused by name instead of misread
/// field by field.
///
/// Version 6 adds the agent-economy books: disputed-escrow holds, job
/// records, passport batches, FX rates, ramp quotes/intents, loan offers and
/// standing auto-repay instructions. The audit ring is intentionally not
/// persisted: it restarts empty, full history stays in the payment/receipt
/// stores.
///
/// Version 5 added the stream opens/settlement accounting and the session
/// budgets (micro-payment channels + wallet safety).
///
/// Version 8 binds the envelope to its network: the first section names the
/// network the books were written on, and a file from another network is
/// refused instead of merged. Books are network-scoped (payment networks,
/// policy scopes, job ids), so loading `srct/mini` books onto `srct/mainnet`
/// would mix scopes that must never meet.
const STATE_ENVELOPE_VERSION: u8 = 9;

/// Largest entry count any single map section in the state envelope may
/// declare, checked before allocation. Real books are bounded by their own
/// caps (thousands of entries) and the state file itself is bounded at 64 MB
/// by `srct-store`, so this is a lying-count guard, not a target.
const MAX_STATE_ENTRIES: usize = 1 << 20;

/// Length-prefix one section into the state envelope.
fn put_section(w: &mut Writer, bytes: &[u8]) {
    w.u32le(bytes.len() as u32).raw(bytes);
}

/// Read one length-prefixed section out of the state envelope.
fn take_section(r: &mut Reader<'_>, what: &str) -> Result<Vec<u8>, String> {
    let len = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
    let bytes = r.fixed_slice(len).map_err(|e| format!("{what}: {e}"))?;
    Ok(bytes.to_vec())
}

/// Decode one section with a decoder that must consume it exactly: trailing
/// bytes inside a section are malformed here, not left for a later section to
/// trip over.
fn decode_section<T>(
    r: &mut Reader<'_>,
    what: &str,
    dec: impl FnOnce(&mut Reader<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let section = take_section(r, what)?;
    let mut inner = Reader::new(&section);
    let out = dec(&mut inner)?;
    inner
        .expect_end()
        .map_err(|e| format!("{what}: trailing bytes ({e})"))?;
    Ok(out)
}

/// Encode a `Hash`-keyed map as `count + (key, length-prefixed value)*`.
fn encode_state_map<T>(map: &BTreeMap<Hash, T>, enc: impl Fn(&T) -> Vec<u8>) -> Vec<u8> {
    let mut w = Writer::with_capacity(8 + map.len() * 64);
    w.u32le(map.len() as u32);
    for (key, value) in map {
        w.fixed(key);
        let bytes = enc(value);
        w.u32le(bytes.len() as u32).raw(&bytes);
    }
    w.into_vec()
}

/// Encode a signature/key bundle length-prefixed.
fn put_bundle(w: &mut Writer, b: &srct_core::sig::Bundle) {
    let bytes = b.to_bytes();
    w.u32le(bytes.len() as u32).raw(&bytes);
}

/// Decode a length-prefixed bundle, bounded like every other section.
fn get_bundle(r: &mut Reader<'_>, what: &str) -> Result<srct_core::sig::Bundle, String> {
    let len = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
    if len > 8 * 1024 {
        return Err(format!("{what}: bundle over the 8 KiB cap"));
    }
    let bytes = r.fixed_slice(len).map_err(|e| format!("{what}: {e}"))?;
    let mut br = Reader::new(bytes);
    srct_core::sig::Bundle::from_reader(&mut br).map_err(|e| format!("{what}: {e}"))
}

/// Inverse of [`encode_state_map`]: bounded count, no duplicate keys, every
/// value fully decoded before it is admitted to the map.
fn decode_state_map<T>(
    r: &mut Reader<'_>,
    what: &str,
    dec: impl Fn(&[u8]) -> Result<T, String>,
) -> Result<BTreeMap<Hash, T>, String> {
    let count = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
    if count > MAX_STATE_ENTRIES {
        return Err(format!(
            "{what}: {count} entries over the {MAX_STATE_ENTRIES} cap"
        ));
    }
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let key: Hash = r.fixed().map_err(|e| format!("{what}: {e}"))?;
        let len = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
        let bytes = r.fixed_slice(len).map_err(|e| format!("{what}: {e}"))?;
        let value = dec(bytes)?;
        if map.insert(key, value).is_some() {
            return Err(format!("{what}: duplicate key"));
        }
    }
    Ok(map)
}

/// Locate a transaction in the chain (as a confirmed height) or the mempool
/// (as pending). The chain walk mirrors `tx_lookup`: a node with no tx index
/// pays O(tip) per lookup, which is the honest cost of that design choice.
fn locate_tx(sh: &SharedNode, txid: &Hash512) -> Option<(Option<u64>, Transaction)> {
    for height in 1..=sh.chain.height() {
        let Some(block) = sh.chain.block_at(height) else {
            continue;
        };
        for tx in &block.txs {
            if tx.txid() == *txid {
                return Some((Some(height), tx.clone()));
            }
        }
    }
    sh.pool.get(txid).map(|entry| (None, entry.tx.clone()))
}

/// The settlement object a client sees: the txid plus where that tx lives
/// right now.
fn settlement_json(txid: &Hash512, confirmed_height: Option<u64>) -> Value {
    json!({
        "tx_hash": hash512_to_hex(txid),
        "status": if confirmed_height.is_some() { "confirmed" } else { "pending" },
        "confirmed_height": confirmed_height,
    })
}

/// A payment's settlement field: `null` when nothing is linked, otherwise the
/// link re-resolved against the live chain and mempool. A linked tx this node
/// can no longer find (evicted from the mempool or reorged out) is reported
/// as `missing`, never silently dropped.
fn settlement_value(sh: &SharedNode, id: &Hash) -> Value {
    let Some(txid) = sh.payment_tx.get(id) else {
        return Value::Null;
    };
    match locate_tx(sh, txid) {
        Some((confirmed_height, _)) => settlement_json(txid, confirmed_height),
        None => json!({
            "tx_hash": hash512_to_hex(txid),
            "status": "missing",
            "confirmed_height": null,
        }),
    }
}

/// A released escrow whose coin move is bound to a real L2 exit: the exit's
/// identity (owner, nonce) plus the queue txid the settle call carried. The
/// identity is what lets [`SharedNode::advance_escrow_finality`] ask consensus
/// whether *this* exit paid the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowExitBinding {
    pub txid: Hash512,
    pub owner: Address,
    pub nonce: u64,
}

/// One usage-based-credit trial: a first task funded by a sponsor, not by the
/// agent. The sponsor's coins are real (an ordinary L1 payment the node itself
/// verifies), so every trial is real SRCT consumption. The node never signs
/// anything here: it records intents and verifies receipts against its own
/// chain. One trial per agent, ever — a second request for a funded or repaid
/// agent is refused by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialState {
    /// Recorded, awaiting the sponsor's payment.
    Requested,
    /// A confirmed L1 payment to the agent covers the trial amount.
    Funded,
    /// A confirmed L1 payment back to the sponsor covers it.
    Repaid,
}

impl TrialState {
    fn as_u8(self) -> u8 {
        match self {
            TrialState::Requested => 0,
            TrialState::Funded => 1,
            TrialState::Repaid => 2,
        }
    }

    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(TrialState::Requested),
            1 => Some(TrialState::Funded),
            2 => Some(TrialState::Repaid),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            TrialState::Requested => "requested",
            TrialState::Funded => "funded",
            TrialState::Repaid => "repaid",
        }
    }
}

/// The trial book entry for one agent identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialRecord {
    pub agent: Address,
    pub amount_sat: u64,
    pub sponsor: Address,
    pub state: TrialState,
    pub fund_txid: Option<Hash512>,
    pub repay_txid: Option<Hash512>,
    pub requested_height: u64,
}

/// Everything the API and the serve loop share. One lock: the serve loop
/// takes it per iteration, handlers take it per request. No handler ever
/// holds it across an await (handlers do not await), so the async runtime
/// only exists to accept sockets and parse HTTP.
///
/// # State classification: consensus vs. node-local
///
/// **Consensus state** (rebuilt from blocks, replayed identically by every
/// node): `chain` (L1), `pool` (mempool admission view), and `l2` (NodeL2 —
/// accounts, tasks, escrow balances, exit queue). An L2 transaction that fails
/// to apply is *skipped deterministically*, never made a consensus rule.
///
/// **Node-local state** (not consensus, not replayed, not committed to blocks):
/// `receipts`, `payment_tracker`, `payment_store`, `payment_tx`,
/// `reservations`, `credit`, `delegations`, `escrows`, `policies`,
/// `policy_registry`, `revoked_policies`.
/// These are operational caches and service-layer features: they must never be
/// treated as an alternative source of truth for global SRCT ownership or
/// spendable balance. Coin movement happens only through L1 UTXOs and L2
/// account balances (the consensus surface above); credit/escrow are gates
/// on admission, not sources of spendable funds. The one thing they do
/// survive is a restart: [`SharedNode::encode_state`] and
/// [`SharedNode::decode_state`] carry them into the node's `state.bin`,
/// loaded fail-closed by the serve command. Persistence restores this node's
/// own view; it never confers ownership.
pub struct SharedNode {
    pub chain: Chain,
    pub pool: Mempool,
    pub l2: NodeL2,
    /// Verified receipts this node holds (lookup, replay-safe semantics).
    pub receipts: ReceiptBook,
    /// Exact-payment replay guard.
    pub payment_tracker: PaymentTracker,
    /// Payment id -> payment, same cap as the tracker.
    pub payment_store: BTreeMap<Hash, MachinePayment>,
    /// payment id -> the L1 transaction that paid this payment's recipient at
    /// least its amount, as this node saw it. Evidence of settlement, not an
    /// accounting lock: no coin moves here (see the state classification
    /// above), and a link whose tx vanishes is reported as `missing`, never
    /// silently dropped.
    pub payment_tx: BTreeMap<Hash, Hash512>,
    /// Admission-time credit reservation keyed by payment id. Consumed when the
    /// matching `ServiceReceipt` is accepted (roadmap item 10 / §19.4): that is
    /// the settlement event, so the credit debit is committed here rather than
    // at admission. Pre-credit nodes wire `NoCreditGate`, which yields a zero-id
    // reservation whose settle is a no-op, so this stays safe when credit is
    // unconfigured.
    pub reservations: BTreeMap<Hash, srct_core::credit::Reservation>,
    /// Policy accounting for `POST /v1/authorize`.
    pub policies: srct_core::agent::PolicyBook,
    /// Credit book for `POST /v1/credit/*`: free balances, posted bonds and
    /// positions. Item 2 wiring (roadmap item 2); kept here, off consensus, so
    /// a payment can only be committed if the payer's line covers it, but the
    /// coin itself still moves through the ordinary §1 UTXO path later.
    pub credit: srct_core::credit::CreditBook,
    /// Attestation hash -> the height its validity ends. One attestation, one
    /// mint: without this a trusted signature inside its window would mint the
    /// same credit repeatedly. Persisted, so a restart is not a replay, and
    /// pruned the moment an entry's own expiry passes — an expired attestation
    /// is unusable anyway, height check first.
    pub attestations_used: BTreeMap<Hash, u64>,
    /// Delegation link book (roadmap item 3). Node-local authority for who
    /// descends from whom: the policy layer is not a consensus rule (SPEC §18.2.1
    /// / D4), but the engine that *issued* the policies must be the one that
    /// registers their parent links, so a delegation is auditable against the
    /// lineage that was actually permitted. `link` enforces domination on every
    /// field and the depth cap in the same pass, reusing `delegation::dominates`.
    pub delegations: srct_core::delegation::DelegationBook,
    /// Stream opens this node tracks (pay-as-you-use channels): id -> the
    /// signed open. Settlement receipts are checked against the open plus
    /// [`StreamBook`] accounting. Node-local and persisted like receipts.
    pub stream_store: BTreeMap<Hash, srct_core::stream::PaymentStream>,
    /// Per-stream settlement accounting. Persisted with the opens above: losing
    /// it across a restart would reopen the double-withdrawal window the book
    /// exists to close.
    pub streams: srct_core::stream::StreamBook,
    /// Per-agent aggregate spend across rotated policies (tumbling window).
    /// A policy rotation starts a fresh policy window by design; the session
    /// book is what stops spend being split across N policies.
    pub sessions: srct_core::safety::SessionBook,
    /// Escrow ids under dispute: release, settlement and auto-refund are all
    /// refused while an id is held. Funds stay locked until resolve.
    pub held_escrows: BTreeSet<Hash>,
    /// Agent-to-agent job records by job id.
    pub jobs: BTreeMap<Hash, srct_core::jobs::JobRecord>,
    /// Issuer-signed reputation passport batches by batch id.
    pub passport_batches: BTreeMap<Hash, srct_core::passport::PassportBatch>,
    /// Live FX rates by base asset (e.g. "USDC"), from trusted issuers.
    pub fx_rates: BTreeMap<String, srct_core::fx::FxRate>,
    /// Provider-signed ramp quotes by quote id.
    pub ramp_quotes: BTreeMap<
        Hash,
        (
            srct_core::ramp::RampQuote,
            srct_core::sig::Bundle,
            srct_core::sig::Bundle,
        ),
    >,
    /// Ramp intents by intent id.
    pub ramp_intents: BTreeMap<Hash, srct_core::ramp::RampIntent>,
    /// Lender-signed standard loan offers by offer id.
    pub loan_offers: BTreeMap<
        Hash,
        (
            srct_core::lending::LoanOffer,
            srct_core::sig::Bundle,
            srct_core::sig::Bundle,
        ),
    >,
    /// One live standing auto-repay instruction per borrower.
    pub standing_repay: BTreeMap<
        Address,
        (
            srct_core::lending::StandingRepay,
            srct_core::sig::Bundle,
            srct_core::sig::Bundle,
        ),
    >,
    /// Usage-based-credit trials by agent: one sponsored first task per agent.
    /// Node-local like jobs and ramps (never consensus, never committed); the
    /// money itself moves through ordinary L1 payments the node verifies.
    pub trials: BTreeMap<Address, TrialRecord>,
    /// Bounded in-memory audit ring (hash-chained, tamper-evident). The full
    /// history lives in the payment/receipt stores this ring references;
    /// intentionally not persisted, so a restart starts a fresh chain.
    pub audit: srct_core::safety::AuditLog,
    /// Conditional-escrow store for Item 4 (contract-selected arbitrators).
    /// Non-consensus: the ledger tracks the state machine, and the actual coin
    /// release reuses the §1 L1 exit / §19.4 path.
    pub escrows: BTreeMap<srct_core::hash::Hash, srct_core::escrow::ConditionalEscrow>,
    /// escrow id -> the L2 exit queued to pay that escrow's release: the
    /// bond that makes `Finalized` mean "the coin actually left". With a
    /// binding recorded, the escrow finalizes only when
    /// `Chain::exit_released` says consensus paid the destination (SPEC
    /// §20.2); without one, the height-stamp behavior of an un-settled
    /// escrow stands.
    pub escrow_exit: BTreeMap<Hash, EscrowExitBinding>,
    /// Policies this node has issued authorizations under, keyed by policy hash.
    ///
    /// The node keeps the policy object because admission (`POST
    /// /v1/payment/submit`) must check the policy a payment *names* is the one
    /// the engine issued under, and that it is still live at this height —
    /// neither of which the accounting alone answers. A payment naming a policy
    /// the node has never authorized under is refused, however well-formed.
    pub policy_registry: BTreeMap<Hash, srct_core::agent::SpendPolicy>,
    /// Policy hashes the owner has revoked, by the hash the engine actually
    /// issued under.
    ///
    /// Revocation needs this set because `revoked` is inside the canonical
    /// encoding: a revoked policy is a *different hash* from the one the engine
    /// authorized, so the revoked statement cannot find the original by itself.
    /// The node maps it back — variant bytes with `revoked` cleared — and
    /// records the original. Only the owner can produce that statement, because
    /// it is the statement they sign.
    pub revoked_policies: BTreeSet<Hash>,
    /// L1 txids the API accepted; drained by the serve loop, which owns the
    /// P2P node and announces them to peers.
    pub tx_to_relay: Vec<Hash512>,
    /// L2 transactions that passed the dry-run; drained by the serve loop
    /// into the next mined block's trailer.
    pub l2_to_include: Vec<L2Transaction>,
}

impl SharedNode {
    pub fn new(chain: Chain, l2: NodeL2) -> Self {
        SharedNode {
            chain,
            pool: Mempool::default(),
            l2,
            receipts: ReceiptBook::default(),
            payment_tracker: PaymentTracker::default(),
            payment_store: BTreeMap::new(),
            payment_tx: BTreeMap::new(),
            reservations: BTreeMap::new(),
            policies: srct_core::agent::PolicyBook::default(),
            credit: srct_core::credit::CreditBook::new(),
            delegations: srct_core::delegation::DelegationBook::new(),
            stream_store: BTreeMap::new(),
            streams: srct_core::stream::StreamBook::default(),
            sessions: srct_core::safety::SessionBook::default(),
            held_escrows: BTreeSet::new(),
            jobs: BTreeMap::new(),
            passport_batches: BTreeMap::new(),
            fx_rates: BTreeMap::new(),
            ramp_quotes: BTreeMap::new(),
            ramp_intents: BTreeMap::new(),
            loan_offers: BTreeMap::new(),
            standing_repay: BTreeMap::new(),
            trials: BTreeMap::new(),
            audit: srct_core::safety::AuditLog::default(),
            escrows: BTreeMap::new(),
            escrow_exit: BTreeMap::new(),
            policy_registry: BTreeMap::new(),
            revoked_policies: BTreeSet::new(),
            attestations_used: BTreeMap::new(),
            tx_to_relay: Vec::new(),
            l2_to_include: Vec::new(),
        }
    }

    /// Encode every node-local book this node owns - receipts, replay tracker,
    /// recorded payments, settlement links, credit reservations, policy
    /// accounting, credit book, delegation links, escrows, issued policies and
    /// revocations - into one versioned, section-length-prefixed blob for
    /// `srct_store::StateFile`.
    ///
    /// Chain, mempool, L2 and the relay queues are deliberately absent: the
    /// chain is already durable, L2 is replayed from it, and the rest is
    /// derived or transient. This is node-local bookkeeping only, never a
    /// consensus input - see the state classification on [`SharedNode`].
    pub fn encode_state(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4096);
        w.u8(STATE_ENVELOPE_VERSION);
        // v8: the network first, so a foreign file fails by name on load.
        put_section(&mut w, self.chain.params().network_id.as_bytes());
        put_section(&mut w, &self.receipts.encode());
        put_section(&mut w, &self.payment_tracker.encode());
        put_section(
            &mut w,
            &encode_state_map(&self.payment_store, |p| p.serialize()),
        );
        put_section(
            &mut w,
            &encode_state_map(&self.reservations, |r| r.encode()),
        );
        put_section(&mut w, &self.policies.encode());
        put_section(&mut w, &self.credit.encode());
        put_section(&mut w, &self.delegations.encode());
        put_section(&mut w, &encode_state_map(&self.escrows, |e| e.encode()));
        put_section(
            &mut w,
            &encode_state_map(&self.policy_registry, |p| p.serialize()),
        );
        let mut revoked = Writer::with_capacity(4 + self.revoked_policies.len() * 32);
        revoked.u32le(self.revoked_policies.len() as u32);
        for hash in &self.revoked_policies {
            revoked.fixed(hash);
        }
        put_section(&mut w, &revoked.into_vec());
        let mut settled = Writer::with_capacity(4 + self.payment_tx.len() * 96);
        settled.u32le(self.payment_tx.len() as u32);
        for (payment, txid) in &self.payment_tx {
            settled.fixed(payment).fixed(txid);
        }
        put_section(&mut w, &settled.into_vec());
        let mut bound = Writer::with_capacity(4 + self.escrow_exit.len() * 124);
        bound.u32le(self.escrow_exit.len() as u32);
        for (id, b) in &self.escrow_exit {
            bound.fixed(id).fixed(&b.txid).fixed(&b.owner);
            bound.u64le(b.nonce);
        }
        put_section(&mut w, &bound.into_vec());
        let mut used = Writer::with_capacity(4 + self.attestations_used.len() * 40);
        used.u32le(self.attestations_used.len() as u32);
        for (id, expires) in &self.attestations_used {
            used.fixed(id).u64le(*expires);
        }
        put_section(&mut w, &used.into_vec());
        // Stream opens + settlement accounting (v5): id -> stream bytes + state.
        // The id must equal the stream's signing hash; checked on decode.
        let mut streams = Writer::with_capacity(4 + self.stream_store.len() * 160);
        streams.u32le(self.stream_store.len() as u32);
        for (id, stream) in &self.stream_store {
            let bytes = stream.serialize();
            let st = self
                .streams
                .state(id)
                .copied()
                .unwrap_or(srct_core::stream::StreamState {
                    settled_sat: 0,
                    last_settled_height: None,
                    last_nonce: 0,
                    settlements: 0,
                });
            streams.fixed(id);
            streams.u32le(bytes.len() as u32).raw(&bytes);
            streams.u64le(st.settled_sat);
            match st.last_settled_height {
                Some(h) => {
                    streams.u8(1).u64le(h);
                }
                None => {
                    streams.u8(0);
                }
            }
            streams.u64le(st.last_nonce).u64le(st.settlements);
        }
        put_section(&mut w, &streams.into_vec());
        // Session budgets (v5): agent -> window_start + spent + total.
        let mut sessions = Writer::with_capacity(4 + self.sessions.len() * 44);
        sessions.u32le(self.sessions.len() as u32);
        for (agent, st) in self.sessions.iter() {
            sessions.fixed(agent);
            sessions
                .u64le(st.window_start_height)
                .u64le(st.spent_in_window_sat)
                .u64le(st.total_spent_sat);
        }
        put_section(&mut w, &sessions.into_vec());
        // Agent economy (v6): dispute holds, jobs, passports, FX, ramps,
        // loan offers, standing auto-repay. All node-local books.
        let mut held = Writer::with_capacity(4 + self.held_escrows.len() * 32);
        held.u32le(self.held_escrows.len() as u32);
        for id in &self.held_escrows {
            held.fixed(id);
        }
        put_section(&mut w, &held.into_vec());
        put_section(
            &mut w,
            &encode_state_map(&self.jobs, |j| {
                let mut jw = Writer::with_capacity(256);
                jw.u32le(j.network_id.len() as u32)
                    .raw(j.network_id.as_bytes());
                jw.fixed(&j.hirer).fixed(&j.worker).fixed(&j.arbitrator.0);
                jw.fixed(&j.service_id).u64le(j.amount_sat);
                match j.result_hash {
                    Some(h) => {
                        jw.u8(1).fixed(&h);
                    }
                    None => {
                        jw.u8(0);
                    }
                }
                jw.u64le(j.deadline_height);
                match j.escrow_id {
                    Some(e) => {
                        jw.u8(1).fixed(&e);
                    }
                    None => {
                        jw.u8(0);
                    }
                }
                jw.u8(j.state.as_u8());
                // v7: the funding nonce joins the identity (distinct funding
                // runs are distinct jobs).
                jw.u64le(j.nonce);
                jw.into_vec()
            }),
        );
        put_section(
            &mut w,
            &encode_state_map(&self.passport_batches, |b| {
                let mut bw = Writer::with_capacity(256 + b.events.len() * 80);
                bw.u32le(b.network_id.len() as u32)
                    .raw(b.network_id.as_bytes());
                bw.fixed(&b.subject);
                bw.u32le(b.events.len() as u32);
                for e in &b.events {
                    bw.u8(e.kind.as_u8()).u64le(e.height).fixed(&e.source);
                    bw.fixed(&e.counterparty).u64le(e.amount_sat);
                }
                bw.fixed(&b.issuer.0);
                bw.u64le(b.issued_height).u64le(b.expires_height);
                bw.fixed(&b.sig.0);
                bw.into_vec()
            }),
        );
        let mut fx = Writer::with_capacity(4 + self.fx_rates.len() * 200);
        fx.u32le(self.fx_rates.len() as u32);
        for (base, rate) in &self.fx_rates {
            fx.u32le(base.len() as u32).raw(base.as_bytes());
            fx.u64le(rate.sat_per_minor);
            fx.u64le(rate.valid_from_height)
                .u64le(rate.valid_until_height);
            fx.u32le(rate.source.len() as u32)
                .raw(rate.source.as_bytes());
            fx.fixed(&rate.issuer.0).fixed(&rate.sig.0);
        }
        put_section(&mut w, &fx.into_vec());
        put_section(
            &mut w,
            &encode_state_map(&self.ramp_quotes, |(q, sigs, keys)| {
                let mut qw = Writer::with_capacity(256);
                qw.u32le(q.network_id.len() as u32)
                    .raw(q.network_id.as_bytes());
                qw.fixed(&q.provider).u8(q.direction.as_u8());
                qw.u32le(q.asset.len() as u32).raw(q.asset.as_bytes());
                qw.u64le(q.asset_minor).u64le(q.sat_amount).u64le(q.fee_sat);
                qw.u64le(q.expires_height).u64le(q.nonce);
                put_bundle(&mut qw, sigs);
                put_bundle(&mut qw, keys);
                qw.into_vec()
            }),
        );
        put_section(
            &mut w,
            &encode_state_map(&self.ramp_intents, |i| {
                let mut iw = Writer::with_capacity(128);
                iw.fixed(&i.quote_id).fixed(&i.user).fixed(&i.provider);
                iw.u32le(i.fill_ref.len() as u32).raw(i.fill_ref.as_bytes());
                iw.u8(i.filled as u8).u8(i.refunded as u8);
                iw.into_vec()
            }),
        );
        put_section(
            &mut w,
            &encode_state_map(&self.loan_offers, |(o, sigs, keys)| {
                let mut ow = Writer::with_capacity(256);
                ow.u32le(o.network_id.len() as u32)
                    .raw(o.network_id.as_bytes());
                ow.fixed(&o.lender);
                ow.u64le(o.min_principal_sat).u64le(o.max_principal_sat);
                ow.u64le(o.rate_bps_per_window).u64le(o.window_blocks);
                ow.u32le(o.base_collateral_bps)
                    .u32le(o.max_discount_bps)
                    .u32le(o.bond_ratio_bps)
                    .u32le(o.min_collateral_bps);
                ow.u64le(o.expires_height).u64le(o.nonce);
                put_bundle(&mut ow, sigs);
                put_bundle(&mut ow, keys);
                ow.into_vec()
            }),
        );
        let mut standing = Writer::with_capacity(4 + self.standing_repay.len() * 200);
        standing.u32le(self.standing_repay.len() as u32);
        for (borrower, (instr, sigs, keys)) in &self.standing_repay {
            standing.fixed(borrower);
            standing
                .u32le(instr.network_id.len() as u32)
                .raw(instr.network_id.as_bytes());
            standing.fixed(&instr.position_id);
            standing
                .u64le(instr.pct_bps)
                .u64le(instr.cap_sat)
                .u64le(instr.applied_sat);
            standing.u64le(instr.expires_height).u64le(instr.nonce);
            put_bundle(&mut standing, sigs);
            put_bundle(&mut standing, keys);
        }
        put_section(&mut w, &standing.into_vec());
        // Usage-based-credit trials (v9): one sponsored first task per agent.
        // agent -> amount + sponsor + state + optional fund/repay txids.
        let mut trials = Writer::with_capacity(4 + self.trials.len() * 160);
        trials.u32le(self.trials.len() as u32);
        for (agent, t) in self.trials.iter() {
            trials.fixed(agent);
            trials.u64le(t.amount_sat).fixed(&t.sponsor);
            trials.u8(t.state.as_u8());
            match t.fund_txid {
                Some(h) => {
                    trials.u8(1).fixed(&h);
                }
                None => {
                    trials.u8(0);
                }
            }
            match t.repay_txid {
                Some(h) => {
                    trials.u8(1).fixed(&h);
                }
                None => {
                    trials.u8(0);
                }
            }
            trials.u64le(t.requested_height);
        }
        put_section(&mut w, &trials.into_vec());
        w.into_vec()
    }

    /// Inverse of [`SharedNode::encode_state`]. Every section decodes into a
    /// local first and only then commits to `self`, so a refused blob leaves
    /// the node's books exactly as they were - a failed load is never a
    /// half-loaded state.
    ///
    /// Every failure is a refusal, never a partial best effort: the caller is
    /// startup, and a node that cannot read its own books must stop rather
    /// than run on an empty set of them.
    pub fn decode_state(&mut self, bytes: &[u8]) -> Result<(), String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("state envelope: {e}"))?;
        if version != STATE_ENVELOPE_VERSION {
            return Err(format!(
                "state envelope version {version}, this build reads {STATE_ENVELOPE_VERSION}"
            ));
        }

        // v8: the envelope names its network; a file from another network is
        // refused instead of merged. The chain's params are the authority —
        // not any field inside the file being checked. The section decode
        // also enforces exact consumption and a sane length.
        let stored_network = decode_section(&mut r, "network", |sr| {
            let n = sr.remaining();
            if n == 0 || n > 64 {
                return Err(format!("network: {n} bytes is not a network id"));
            }
            let bytes = sr.fixed_slice(n).map_err(|e| format!("network: {e}"))?;
            String::from_utf8(bytes.to_vec()).map_err(|e| format!("network: {e}"))
        })?;
        let mine = self.chain.params().network_id.clone();
        if stored_network != mine {
            return Err(format!(
                "state envelope is for network \"{stored_network}\", this node is \"{mine}\": \
                 refusing a foreign book instead of merging it"
            ));
        }

        let receipts = decode_section(&mut r, "receipts", |sr| {
            ReceiptBook::decode(sr).map_err(|e| format!("{e}"))
        })?;
        let payment_tracker = decode_section(&mut r, "payment_tracker", |sr| {
            PaymentTracker::decode(sr).map_err(|e| format!("{e}"))
        })?;
        let payment_store = decode_section(&mut r, "payment_store", |sr| {
            decode_state_map(sr, "payment_store", |b| {
                MachinePayment::deserialize(b).map_err(|e| format!("payment: {e}"))
            })
        })?;
        let reservations = decode_section(&mut r, "reservations", |sr| {
            decode_state_map(sr, "reservations", |b| {
                srct_core::credit::Reservation::decode(&mut Reader::new(b))
                    .map_err(|e| format!("reservation: {e}"))
            })
        })?;
        let policies = decode_section(&mut r, "policies", |sr| {
            srct_core::agent::PolicyBook::decode(sr).map_err(|e| format!("{e}"))
        })?;
        let credit = decode_section(&mut r, "credit", |sr| {
            srct_core::credit::CreditBook::decode(sr).map_err(|e| format!("{e}"))
        })?;
        let delegations = decode_section(&mut r, "delegations", |sr| {
            srct_core::delegation::DelegationBook::decode(sr).map_err(|e| format!("{e}"))
        })?;
        let escrows = decode_section(&mut r, "escrows", |sr| {
            decode_state_map(sr, "escrows", |b| {
                srct_core::escrow::ConditionalEscrow::decode(&mut Reader::new(b))
                    .map_err(|e| format!("escrow: {e}"))
            })
        })?;
        let policy_registry = decode_section(&mut r, "policy_registry", |sr| {
            decode_state_map(sr, "policy_registry", |b| {
                srct_core::agent::SpendPolicy::deserialize(b).map_err(|e| format!("policy: {e}"))
            })
        })?;
        let revoked_policies = decode_section(&mut r, "revoked_policies", |sr| {
            let count = sr.u32le().map_err(|e| format!("revoked_policies: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "revoked_policies: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut set = BTreeSet::new();
            for _ in 0..count {
                let hash: Hash = sr.fixed().map_err(|e| format!("revoked_policies: {e}"))?;
                set.insert(hash);
            }
            if set.len() != count {
                return Err("revoked_policies: duplicate entry".into());
            }
            Ok(set)
        })?;
        let payment_tx = decode_section(&mut r, "payment_tx", |sr| {
            let count = sr.u32le().map_err(|e| format!("payment_tx: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "payment_tx: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let payment: Hash = sr.fixed().map_err(|e| format!("payment_tx: {e}"))?;
                let txid: Hash512 = sr.fixed().map_err(|e| format!("payment_tx: {e}"))?;
                if map.insert(payment, txid).is_some() {
                    return Err("payment_tx: duplicate key".into());
                }
            }
            Ok(map)
        })?;
        let escrow_exit = decode_section(&mut r, "escrow_exit", |sr| {
            let count = sr.u32le().map_err(|e| format!("escrow_exit: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "escrow_exit: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let id: Hash = sr.fixed().map_err(|e| format!("escrow_exit: {e}"))?;
                let txid: Hash512 = sr.fixed().map_err(|e| format!("escrow_exit: {e}"))?;
                let owner: Address = sr.fixed().map_err(|e| format!("escrow_exit: {e}"))?;
                let nonce = sr.u64le().map_err(|e| format!("escrow_exit: {e}"))?;
                if map
                    .insert(id, EscrowExitBinding { txid, owner, nonce })
                    .is_some()
                {
                    return Err("escrow_exit: duplicate key".into());
                }
            }
            Ok(map)
        })?;
        let attestations_used = decode_section(&mut r, "attestations_used", |sr| {
            let count = sr.u32le().map_err(|e| format!("attestations_used: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "attestations_used: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let id: Hash = sr.fixed().map_err(|e| format!("attestations_used: {e}"))?;
                let expires = sr.u64le().map_err(|e| format!("attestations_used: {e}"))?;
                if map.insert(id, expires).is_some() {
                    return Err("attestations_used: duplicate key".into());
                }
            }
            Ok(map)
        })?;
        let (stream_store, streams) = decode_section(&mut r, "streams", |sr| {
            let count = sr.u32le().map_err(|e| format!("streams: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "streams: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut store = BTreeMap::new();
            let mut book = srct_core::stream::StreamBook::default();
            for _ in 0..count {
                let id: Hash = sr.fixed().map_err(|e| format!("streams: {e}"))?;
                let len = sr.u32le().map_err(|e| format!("streams: {e}"))? as usize;
                if len > 4 * 1024 {
                    return Err("streams: stream bytes over the 4 KiB cap".into());
                }
                let bytes = sr.fixed_slice(len).map_err(|e| format!("streams: {e}"))?;
                let stream = srct_core::stream::PaymentStream::deserialize(bytes)
                    .map_err(|e| format!("streams: {e}"))?;
                if stream.signing_hash() != id {
                    return Err("streams: id is not the stream signing hash".into());
                }
                let settled_sat = sr.u64le().map_err(|e| format!("streams: {e}"))?;
                let has_height = sr.u8().map_err(|e| format!("streams: {e}"))?;
                let last_settled_height = match has_height {
                    0 => None,
                    1 => Some(sr.u64le().map_err(|e| format!("streams: {e}"))?),
                    _ => return Err("streams: bad height flag".into()),
                };
                let last_nonce = sr.u64le().map_err(|e| format!("streams: {e}"))?;
                let settlements = sr.u64le().map_err(|e| format!("streams: {e}"))?;
                book.restore(
                    id,
                    srct_core::stream::StreamState {
                        settled_sat,
                        last_settled_height,
                        last_nonce,
                        settlements,
                    },
                )
                .map_err(|e| format!("streams: {e}"))?;
                if store.insert(id, stream).is_some() {
                    return Err("streams: duplicate id".into());
                }
            }
            Ok((store, book))
        })?;
        let sessions = decode_section(&mut r, "sessions", |sr| {
            let count = sr.u32le().map_err(|e| format!("sessions: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "sessions: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut book = srct_core::safety::SessionBook::default();
            for _ in 0..count {
                let agent: srct_core::agent::AgentId =
                    sr.fixed().map_err(|e| format!("sessions: {e}"))?;
                let window_start_height = sr.u64le().map_err(|e| format!("sessions: {e}"))?;
                let spent_in_window_sat = sr.u64le().map_err(|e| format!("sessions: {e}"))?;
                let total_spent_sat = sr.u64le().map_err(|e| format!("sessions: {e}"))?;
                book.restore(
                    agent,
                    srct_core::safety::SessionState {
                        window_start_height,
                        spent_in_window_sat,
                        total_spent_sat,
                    },
                )
                .map_err(|e| format!("sessions: {e}"))?;
            }
            Ok(book)
        })?;
        let held_escrows = decode_section(&mut r, "held_escrows", |sr| {
            let count = sr.u32le().map_err(|e| format!("held_escrows: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "held_escrows: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut set = BTreeSet::new();
            for _ in 0..count {
                let id: Hash = sr.fixed().map_err(|e| format!("held_escrows: {e}"))?;
                if !set.insert(id) {
                    return Err("held_escrows: duplicate id".into());
                }
            }
            Ok(set)
        })?;
        let jobs = decode_section(&mut r, "jobs", |sr| {
            decode_state_map(sr, "jobs", |bytes| {
                let mut jr = Reader::new(bytes);
                let net_len = jr.u32le().map_err(|e| format!("jobs: {e}"))? as usize;
                if net_len > 64 {
                    return Err("jobs: network id over cap".into());
                }
                let net_bytes = jr.fixed_slice(net_len).map_err(|e| format!("jobs: {e}"))?;
                let network_id = std::str::from_utf8(net_bytes)
                    .map_err(|_| "jobs: network id not utf-8".to_string())?
                    .to_string();
                let hirer: Address = jr.fixed().map_err(|e| format!("jobs: {e}"))?;
                let worker: Address = jr.fixed().map_err(|e| format!("jobs: {e}"))?;
                let arbitrator: [u8; 48] = jr.fixed().map_err(|e| format!("jobs: {e}"))?;
                let service_id: [u8; 32] = jr.fixed().map_err(|e| format!("jobs: {e}"))?;
                let amount_sat = jr.u64le().map_err(|e| format!("jobs: {e}"))?;
                let has_result = jr.u8().map_err(|e| format!("jobs: {e}"))?;
                let result_hash = match has_result {
                    0 => None,
                    1 => Some(jr.fixed().map_err(|e| format!("jobs: {e}"))?),
                    _ => return Err("jobs: bad result flag".into()),
                };
                let deadline_height = jr.u64le().map_err(|e| format!("jobs: {e}"))?;
                let has_escrow = jr.u8().map_err(|e| format!("jobs: {e}"))?;
                let escrow_id = match has_escrow {
                    0 => None,
                    1 => Some(jr.fixed().map_err(|e| format!("jobs: {e}"))?),
                    _ => return Err("jobs: bad escrow flag".into()),
                };
                let state =
                    srct_core::jobs::JobState::from_u8(jr.u8().map_err(|e| format!("jobs: {e}"))?)
                        .ok_or("jobs: unknown state")?;
                // v7: the funding nonce.
                let nonce = jr.u64le().map_err(|e| format!("jobs: {e}"))?;
                jr.expect_end().map_err(|e| format!("jobs: {e}"))?;
                Ok(srct_core::jobs::JobRecord {
                    network_id,
                    hirer,
                    worker,
                    arbitrator: srct_core::bls_checkpoint::BlsPublicKey(arbitrator),
                    service_id,
                    amount_sat,
                    result_hash,
                    deadline_height,
                    escrow_id,
                    state,
                    nonce,
                })
            })
        })?;
        let passport_batches = decode_section(&mut r, "passport_batches", |sr| {
            decode_state_map(sr, "passport_batches", |bytes| {
                let mut pr = Reader::new(bytes);
                let net_len = pr.u32le().map_err(|e| format!("passport: {e}"))? as usize;
                if net_len > 64 {
                    return Err("passport: network id over cap".into());
                }
                let net_bytes = pr
                    .fixed_slice(net_len)
                    .map_err(|e| format!("passport: {e}"))?;
                let network_id = std::str::from_utf8(net_bytes)
                    .map_err(|_| "passport: network id not utf-8".to_string())?
                    .to_string();
                let subject: srct_core::agent::AgentId =
                    pr.fixed().map_err(|e| format!("passport: {e}"))?;
                let count = pr.u32le().map_err(|e| format!("passport: {e}"))? as usize;
                if count > srct_core::passport::MAX_PASSPORT_EVENTS {
                    return Err("passport: too many events".into());
                }
                let mut events = Vec::with_capacity(count);
                for _ in 0..count {
                    let kind = srct_core::passport::PassportEventKind::from_u8(
                        pr.u8().map_err(|e| format!("passport: {e}"))?,
                    )
                    .ok_or("passport: unknown event kind")?;
                    let height = pr.u64le().map_err(|e| format!("passport: {e}"))?;
                    let source: Hash = pr.fixed().map_err(|e| format!("passport: {e}"))?;
                    let counterparty: srct_core::agent::AgentId =
                        pr.fixed().map_err(|e| format!("passport: {e}"))?;
                    let amount_sat = pr.u64le().map_err(|e| format!("passport: {e}"))?;
                    events.push(srct_core::passport::PassportEvent {
                        kind,
                        height,
                        source,
                        counterparty,
                        amount_sat,
                    });
                }
                let issuer: [u8; 48] = pr.fixed().map_err(|e| format!("passport: {e}"))?;
                let issued_height = pr.u64le().map_err(|e| format!("passport: {e}"))?;
                let expires_height = pr.u64le().map_err(|e| format!("passport: {e}"))?;
                let sig: [u8; 96] = pr.fixed().map_err(|e| format!("passport: {e}"))?;
                pr.expect_end().map_err(|e| format!("passport: {e}"))?;
                Ok(srct_core::passport::PassportBatch {
                    network_id,
                    subject,
                    events,
                    issuer: srct_core::bls_checkpoint::BlsPublicKey(issuer),
                    issued_height,
                    expires_height,
                    sig: srct_core::bls_checkpoint::BlsSignature(sig),
                })
            })
        })?;
        let fx_rates = decode_section(&mut r, "fx_rates", |sr| {
            let count = sr.u32le().map_err(|e| format!("fx_rates: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "fx_rates: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let base_len = sr.u32le().map_err(|e| format!("fx_rates: {e}"))? as usize;
                if base_len == 0 || base_len > srct_core::fx::MAX_FX_SYMBOL_LEN {
                    return Err("fx_rates: bad base length".into());
                }
                let base_bytes = sr
                    .fixed_slice(base_len)
                    .map_err(|e| format!("fx_rates: {e}"))?;
                let base = std::str::from_utf8(base_bytes)
                    .map_err(|_| "fx_rates: base not utf-8".to_string())?
                    .to_string();
                let sat_per_minor = sr.u64le().map_err(|e| format!("fx_rates: {e}"))?;
                let valid_from_height = sr.u64le().map_err(|e| format!("fx_rates: {e}"))?;
                let valid_until_height = sr.u64le().map_err(|e| format!("fx_rates: {e}"))?;
                let src_len = sr.u32le().map_err(|e| format!("fx_rates: {e}"))? as usize;
                if src_len > 64 {
                    return Err("fx_rates: source over cap".into());
                }
                let src_bytes = sr
                    .fixed_slice(src_len)
                    .map_err(|e| format!("fx_rates: {e}"))?;
                let source = std::str::from_utf8(src_bytes)
                    .map_err(|_| "fx_rates: source not utf-8".to_string())?
                    .to_string();
                let issuer: [u8; 48] = sr.fixed().map_err(|e| format!("fx_rates: {e}"))?;
                let sig: [u8; 96] = sr.fixed().map_err(|e| format!("fx_rates: {e}"))?;
                let rate = srct_core::fx::FxRate {
                    base: base.clone(),
                    sat_per_minor,
                    valid_from_height,
                    valid_until_height,
                    source,
                    issuer: srct_core::bls_checkpoint::BlsPublicKey(issuer),
                    sig: srct_core::bls_checkpoint::BlsSignature(sig),
                };
                if map.insert(base, rate).is_some() {
                    return Err("fx_rates: duplicate base".into());
                }
            }
            Ok(map)
        })?;
        let ramp_quotes = decode_section(&mut r, "ramp_quotes", |sr| {
            decode_state_map(sr, "ramp_quotes", |bytes| {
                let mut qr = Reader::new(bytes);
                let net_len = qr.u32le().map_err(|e| format!("ramp_quotes: {e}"))? as usize;
                if net_len > 64 {
                    return Err("ramp_quotes: network id over cap".into());
                }
                let net_bytes = qr
                    .fixed_slice(net_len)
                    .map_err(|e| format!("ramp_quotes: {e}"))?;
                let network_id = std::str::from_utf8(net_bytes)
                    .map_err(|_| "ramp_quotes: network id not utf-8".to_string())?
                    .to_string();
                let provider: Address = qr.fixed().map_err(|e| format!("ramp_quotes: {e}"))?;
                let direction = srct_core::ramp::RampDirection::from_u8(
                    qr.u8().map_err(|e| format!("ramp_quotes: {e}"))?,
                )
                .ok_or("ramp_quotes: unknown direction")?;
                let asset_len = qr.u32le().map_err(|e| format!("ramp_quotes: {e}"))? as usize;
                if asset_len == 0 || asset_len > 16 {
                    return Err("ramp_quotes: bad asset length".into());
                }
                let asset = std::str::from_utf8(
                    qr.fixed_slice(asset_len)
                        .map_err(|e| format!("ramp_quotes: {e}"))?,
                )
                .map_err(|_| "ramp_quotes: asset not utf-8".to_string())?
                .to_string();
                let asset_minor = qr.u64le().map_err(|e| format!("ramp_quotes: {e}"))?;
                let sat_amount = qr.u64le().map_err(|e| format!("ramp_quotes: {e}"))?;
                let fee_sat = qr.u64le().map_err(|e| format!("ramp_quotes: {e}"))?;
                let expires_height = qr.u64le().map_err(|e| format!("ramp_quotes: {e}"))?;
                let nonce = qr.u64le().map_err(|e| format!("ramp_quotes: {e}"))?;
                let sigs = get_bundle(&mut qr, "ramp_quotes")?;
                let keys = get_bundle(&mut qr, "ramp_quotes")?;
                qr.expect_end().map_err(|e| format!("ramp_quotes: {e}"))?;
                Ok((
                    srct_core::ramp::RampQuote {
                        network_id,
                        provider,
                        direction,
                        asset,
                        asset_minor,
                        sat_amount,
                        fee_sat,
                        expires_height,
                        nonce,
                    },
                    sigs,
                    keys,
                ))
            })
        })?;
        let ramp_intents = decode_section(&mut r, "ramp_intents", |sr| {
            decode_state_map(sr, "ramp_intents", |bytes| {
                let mut ir = Reader::new(bytes);
                let quote_id: Hash = ir.fixed().map_err(|e| format!("ramp_intents: {e}"))?;
                let user: Address = ir.fixed().map_err(|e| format!("ramp_intents: {e}"))?;
                let provider: Address = ir.fixed().map_err(|e| format!("ramp_intents: {e}"))?;
                let fill_len = ir.u32le().map_err(|e| format!("ramp_intents: {e}"))? as usize;
                if fill_len > 128 {
                    return Err("ramp_intents: fill ref over cap".into());
                }
                let fill_ref = std::str::from_utf8(
                    ir.fixed_slice(fill_len)
                        .map_err(|e| format!("ramp_intents: {e}"))?,
                )
                .map_err(|_| "ramp_intents: fill ref not utf-8".to_string())?
                .to_string();
                let filled = ir.u8().map_err(|e| format!("ramp_intents: {e}"))? != 0;
                let refunded = ir.u8().map_err(|e| format!("ramp_intents: {e}"))? != 0;
                ir.expect_end().map_err(|e| format!("ramp_intents: {e}"))?;
                Ok(srct_core::ramp::RampIntent {
                    quote_id,
                    user,
                    provider,
                    fill_ref,
                    filled,
                    refunded,
                })
            })
        })?;
        let loan_offers = decode_section(&mut r, "loan_offers", |sr| {
            decode_state_map(sr, "loan_offers", |bytes| {
                let mut lor = Reader::new(bytes);
                let net_len = lor.u32le().map_err(|e| format!("loan_offers: {e}"))? as usize;
                if net_len > 64 {
                    return Err("loan_offers: network id over cap".into());
                }
                let net_bytes = lor
                    .fixed_slice(net_len)
                    .map_err(|e| format!("loan_offers: {e}"))?;
                let network_id = std::str::from_utf8(net_bytes)
                    .map_err(|_| "loan_offers: network id not utf-8".to_string())?
                    .to_string();
                let lender: Address = lor.fixed().map_err(|e| format!("loan_offers: {e}"))?;
                let min_principal_sat = lor.u64le().map_err(|e| format!("loan_offers: {e}"))?;
                let max_principal_sat = lor.u64le().map_err(|e| format!("loan_offers: {e}"))?;
                let rate_bps_per_window = lor.u64le().map_err(|e| format!("loan_offers: {e}"))?;
                let window_blocks = lor.u64le().map_err(|e| format!("loan_offers: {e}"))?;
                let base_collateral_bps = lor.u32le().map_err(|e| format!("loan_offers: {e}"))?;
                let max_discount_bps = lor.u32le().map_err(|e| format!("loan_offers: {e}"))?;
                let bond_ratio_bps = lor.u32le().map_err(|e| format!("loan_offers: {e}"))?;
                let min_collateral_bps = lor.u32le().map_err(|e| format!("loan_offers: {e}"))?;
                let expires_height = lor.u64le().map_err(|e| format!("loan_offers: {e}"))?;
                let nonce = lor.u64le().map_err(|e| format!("loan_offers: {e}"))?;
                let sigs = get_bundle(&mut lor, "loan_offers")?;
                let keys = get_bundle(&mut lor, "loan_offers")?;
                lor.expect_end().map_err(|e| format!("loan_offers: {e}"))?;
                Ok((
                    srct_core::lending::LoanOffer {
                        network_id,
                        lender,
                        min_principal_sat,
                        max_principal_sat,
                        rate_bps_per_window,
                        window_blocks,
                        base_collateral_bps,
                        max_discount_bps,
                        bond_ratio_bps,
                        min_collateral_bps,
                        expires_height,
                        nonce,
                    },
                    sigs,
                    keys,
                ))
            })
        })?;
        let standing_repay = decode_section(&mut r, "standing_repay", |sr| {
            let count = sr.u32le().map_err(|e| format!("standing_repay: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "standing_repay: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let borrower: Address = sr.fixed().map_err(|e| format!("standing_repay: {e}"))?;
                let net_len = sr.u32le().map_err(|e| format!("standing_repay: {e}"))? as usize;
                if net_len > 64 {
                    return Err("standing_repay: network id over cap".into());
                }
                let network_id = std::str::from_utf8(
                    sr.fixed_slice(net_len)
                        .map_err(|e| format!("standing_repay: {e}"))?,
                )
                .map_err(|_| "standing_repay: network id not utf-8".to_string())?
                .to_string();
                let position_id: Hash = sr.fixed().map_err(|e| format!("standing_repay: {e}"))?;
                let pct_bps = sr.u64le().map_err(|e| format!("standing_repay: {e}"))?;
                let cap_sat = sr.u64le().map_err(|e| format!("standing_repay: {e}"))?;
                let applied_sat = sr.u64le().map_err(|e| format!("standing_repay: {e}"))?;
                let expires_height = sr.u64le().map_err(|e| format!("standing_repay: {e}"))?;
                let nonce = sr.u64le().map_err(|e| format!("standing_repay: {e}"))?;
                let sigs = get_bundle(sr, "standing_repay")?;
                let keys = get_bundle(sr, "standing_repay")?;
                let instr = srct_core::lending::StandingRepay {
                    network_id,
                    borrower,
                    position_id,
                    pct_bps,
                    cap_sat,
                    applied_sat,
                    expires_height,
                    nonce,
                };
                if map.insert(borrower, (instr, sigs, keys)).is_some() {
                    return Err("standing_repay: duplicate borrower".into());
                }
            }
            Ok(map)
        })?;
        let trials = decode_section(&mut r, "trials", |sr| {
            let count = sr.u32le().map_err(|e| format!("trials: {e}"))? as usize;
            if count > MAX_STATE_ENTRIES {
                return Err(format!(
                    "trials: {count} entries over the {MAX_STATE_ENTRIES} cap"
                ));
            }
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let agent: Address = sr.fixed().map_err(|e| format!("trials: {e}"))?;
                let amount_sat = sr.u64le().map_err(|e| format!("trials: {e}"))?;
                let sponsor: Address = sr.fixed().map_err(|e| format!("trials: {e}"))?;
                let state = TrialState::from_u8(sr.u8().map_err(|e| format!("trials: {e}"))?)
                    .ok_or("trials: unknown state")?;
                let fund_txid = match sr.u8().map_err(|e| format!("trials: {e}"))? {
                    0 => None,
                    1 => Some(sr.fixed().map_err(|e| format!("trials: {e}"))?),
                    _ => return Err("trials: bad fund flag".into()),
                };
                let repay_txid = match sr.u8().map_err(|e| format!("trials: {e}"))? {
                    0 => None,
                    1 => Some(sr.fixed().map_err(|e| format!("trials: {e}"))?),
                    _ => return Err("trials: bad repay flag".into()),
                };
                let requested_height = sr.u64le().map_err(|e| format!("trials: {e}"))?;
                // A funded trial without its funding proof, or a repaid trial
                // without its repayment proof, is a half-written record: refuse
                // the file rather than trusting a bare flag.
                if (state == TrialState::Funded || state == TrialState::Repaid)
                    && fund_txid.is_none()
                {
                    return Err("trials: funded without fund txid".into());
                }
                if state == TrialState::Repaid && repay_txid.is_none() {
                    return Err("trials: repaid without repay txid".into());
                }
                if map
                    .insert(
                        agent,
                        TrialRecord {
                            agent,
                            amount_sat,
                            sponsor,
                            state,
                            fund_txid,
                            repay_txid,
                            requested_height,
                        },
                    )
                    .is_some()
                {
                    return Err("trials: duplicate agent".into());
                }
            }
            Ok(map)
        })?;
        // Anything after the last section means the envelope is malformed.
        r.expect_end().map_err(|e| format!("state envelope: {e}"))?;

        self.receipts = receipts;
        self.payment_tracker = payment_tracker;
        self.payment_store = payment_store;
        self.payment_tx = payment_tx;
        self.reservations = reservations;
        self.policies = policies;
        self.credit = credit;
        self.delegations = delegations;
        self.escrows = escrows;
        self.escrow_exit = escrow_exit;
        self.attestations_used = attestations_used;
        self.policy_registry = policy_registry;
        self.revoked_policies = revoked_policies;
        self.stream_store = stream_store;
        self.streams = streams;
        self.sessions = sessions;
        self.held_escrows = held_escrows;
        self.jobs = jobs;
        self.passport_batches = passport_batches;
        self.fx_rates = fx_rates;
        self.ramp_quotes = ramp_quotes;
        self.ramp_intents = ramp_intents;
        self.loan_offers = loan_offers;
        self.standing_repay = standing_repay;
        self.trials = trials;
        Ok(())
    }

    /// Advance escrows whose release has matured under finality to `Finalized`
    /// (roadmap item 10, §19.4). Called each serve-loop tick so a released
    /// escrow becomes settleable without an extra client round-trip; it is also
    /// safe to call from read paths because it is idempotent.
    ///
    /// For an escrow bound to an exit, `Finalized` is written only when
    /// `Chain::exit_released` says consensus actually paid the destination -
    /// SPEC §20.2's "when the coin actually leaves ... on the base layer". An
    /// unbound escrow keeps the ledger height-stamp it has always had: no coin
    /// was ever tied to it, so there is nothing to wait for.
    pub fn advance_escrow_finality(&mut self) {
        let now = self.chain.height();
        let activation = self.chain.params().finality_activation_height;
        // Collect the held ids first: the loop borrows the escrows, and a
        // disputed escrow must neither auto-refund on expiry nor finalize —
        // funds stay locked until the arbitrator resolves.
        let held: Vec<Hash> = self.held_escrows.iter().copied().collect();
        for (id, escrow) in self.escrows.iter_mut() {
            if held.contains(id) {
                continue;
            }
            // The timeout first: an open escrow past `ESCROW_EXPIRY_BLOCKS`
            // refunds its payer, which is what stops a silent or unreachable
            // arbitrator from holding the value forever. Only a *released*
            // escrow can then mature to Finalized; a refunded one is terminal.
            if escrow.expired_at(now) {
                let _ = escrow.refund(now);
            }
            let released = match self.escrow_exit.get(id) {
                Some(binding) => self.chain.exit_released(&binding.owner, binding.nonce),
                None => true,
            };
            if released {
                let _ = escrow.finalize(now, activation);
            }
        }
        // Reservations whose payment expired: the payer's line was locked
        // for a receipt that can now never settle (an expired payment is
        // unadmittable and unreceivable). Release the lock; the payment
        // record itself stays, so a late receipt is refused as expired
        // rather than resurrected.
        let expired: Vec<Hash> = self
            .reservations
            .keys()
            .copied()
            .filter(|id| {
                self.payment_store
                    .get(id)
                    .map(|p| now >= p.expires_at_height)
                    .unwrap_or(true)
            })
            .collect();
        for id in expired {
            if let Some(reservation) = self.reservations.remove(&id) {
                let _ = self.credit.release(&reservation);
            }
        }
    }
}

#[derive(Clone)]
pub struct ApiState {
    shared: Arc<Mutex<SharedNode>>,
    peers: Arc<AtomicUsize>,
    /// BLS public keys trusted to sign credit attestations. Empty — the
    /// default — means no issuer is trusted and `POST /v1/credit/mint`
    /// refuses everything: credit backing is fail-closed, never implicit.
    credit_issuers: Vec<srct_core::bls_checkpoint::BlsPublicKey>,
    /// Whether this API serves a non-loopback bind: self-serve credit
    /// funding is refused there (the attested `credit/mint` path is the
    /// only backing an exposed node accepts).
    exposed: bool,
}

/// Uniform error body: a stable machine-readable code plus a detail string
/// that never contains signing material (nothing here holds any).
#[derive(Debug, serde::Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub detail: String,
}

pub type ApiResult = Result<Json<Value>, (StatusCode, Json<ErrorBody>)>;

fn fail(
    status: StatusCode,
    error: &'static str,
    detail: impl Into<String>,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            error,
            detail: detail.into(),
        }),
    )
}

fn bad(detail: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    fail(StatusCode::BAD_REQUEST, "bad_request", detail)
}

fn not_found(detail: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    fail(StatusCode::NOT_FOUND, "not_found", detail)
}

/// Run `f` with exclusive access to the shared node state.
fn with_shared<T>(
    state: &ApiState,
    f: impl FnOnce(&mut SharedNode) -> T,
) -> Result<T, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.shared.lock().map_err(|_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "state lock poisoned",
        )
    })?;
    Ok(f(&mut guard))
}

/// How long a request waits for the shared-state lock before giving up.
///
/// Long enough that a serve-loop iteration (which holds it for one pass of
/// cheap, in-memory work) never makes a reader fail, short enough that a
/// request never waits without bound behind it.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// How long the bounded lock sleeps between attempts.
const LOCK_POLL: Duration = Duration::from_millis(1);

/// How many transactions may be verifying signatures at once.
///
/// Separate from the in-flight request cap, which counts *all* requests:
/// verification is the only per-request work that runs on the blocking pool
/// and costs real CPU, so a burst of broadcasts could otherwise occupy every
/// blocking thread while reads queue behind them for the lock.
const MAX_CONCURRENT_VERIFIES: usize = 4;

/// The process-wide cap on concurrent `tx_broadcast` verifications.
///
/// Lazy, and held in an `Arc` because `try_acquire_owned` hands out a permit
/// that owns a handle: the released permit must come back to this same
/// counter, not a copy of it.
fn verify_permits() -> std::sync::Arc<tokio::sync::Semaphore> {
    static PERMITS: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    std::sync::Arc::clone(
        PERMITS.get_or_init(|| {
            std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFIES))
        }),
    )
}

/// Take one verification permit from the blocking pool.
///
/// Refuses rather than queues: a burst of broadcasts is shed here instead of
/// occupying the blocking pool while reads queue behind them for the lock.
/// The request is then retried by its owner, which is the honest answer to
/// "the node is busy verifying".
fn acquire_verify_permit(
) -> Result<tokio::sync::OwnedSemaphorePermit, (StatusCode, Json<ErrorBody>)> {
    match verify_permits().try_acquire_owned() {
        Ok(permit) => Ok(permit),
        Err(_) => Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            "too many transactions are being verified; retry shortly",
        )),
    }
}

/// Run `f` with exclusive access, but never wait without bound.
///
/// `lock()` waits for as long as the holder takes, so a request that arrives
/// while the serve loop works is *queued*, not failed — and a request whose
/// deadline fires mid-wait is still holding its turn when it is dropped. This
/// polls with a deadline instead and reports 503 `busy`, which is a truthful
/// answer: the caller can retry and the node is still healthy.
///
/// Must be called from a blocking thread: the loop sleeps, and sleeping on the
/// current-threaded async runtime would stall every other request.
fn with_shared_bounded<T>(
    state: &ApiState,
    f: impl FnOnce(&mut SharedNode) -> T,
) -> Result<T, (StatusCode, Json<ErrorBody>)> {
    let deadline = Instant::now() + LOCK_WAIT;
    let mut guard = loop {
        match state.shared.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(fail(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "busy",
                        "node state is busy; retry shortly",
                    ));
                }
                std::thread::sleep(LOCK_POLL);
            }
            // A poisoned lock means a panic happened while it was held. Every
            // earlier holder completed (the release profile aborts on panic),
            // so the data is intact — report it as busy rather than 500, so an
            // operator sees "contended", not "corrupt".
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "busy",
                    "node state lock is unavailable",
                ));
            }
        }
    };
    Ok(f(&mut guard))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn decode_address(s: &str) -> Result<Address, (StatusCode, Json<ErrorBody>)> {
    address_from_hex(s).map_err(|e| bad(format!("address: {e}")))
}

fn decode_hash(s: &str) -> Result<Hash, (StatusCode, Json<ErrorBody>)> {
    hash_from_hex(s).map_err(|e| bad(format!("hash: {e}")))
}

/// Block hashes and txids are the 512-bit identities; requests that name one
/// parse with this, every other id keeps [`decode_hash`].
fn decode_hash512(s: &str) -> Result<Hash512, (StatusCode, Json<ErrorBody>)> {
    hash512_from_hex(s).map_err(|e| bad(format!("hash: {e}")))
}

/// Hex-decode a request field with a global 16 MiB cap (8 MiB decoded).
/// Without it, a single `block_hex` field could force a 500 MB allocation
/// before the codec ever sees the bytes: consensus caps blocks at
/// `max_block_bytes` (4 MB on every profile, i.e. 8 M hex chars), so nothing
/// legitimate is even close to this bar, and the codec additionally bounds
/// every count before allocating.
fn decode_hex_bytes(s: &str, what: &str) -> Result<Vec<u8>, (StatusCode, Json<ErrorBody>)> {
    const MAX_HEX_CHARS: usize = 16 * 1024 * 1024;
    let raw = s.trim().trim_start_matches("0x");
    if raw.len() > MAX_HEX_CHARS {
        return Err(bad(format!("{what} exceeds the 16 MiB request cap")));
    }
    hex::decode(raw).map_err(|e| bad(format!("{what} hex: {e}")))
}

/// Parse and length-check a 48-byte BLS public key hex string.
fn decode_public_key(
    s: &str,
    what: &str,
) -> Result<srct_core::bls_checkpoint::BlsPublicKey, (StatusCode, Json<ErrorBody>)> {
    let raw = decode_hex_bytes(s, what)?;
    let mut key = [0u8; 48];
    if raw.len() != 48 {
        return Err(bad(format!("{what} must be 48 hex bytes")));
    }
    key.copy_from_slice(&raw);
    Ok(srct_core::bls_checkpoint::BlsPublicKey(key))
}

fn task_json(t: &TaskContract) -> Value {
    let mut v = json!({
        "task_id": hash_to_hex(&t.task_id),
        "submitter": address_to_hex(&t.submitter),
        "worker": t.worker.map(|a| address_to_hex(&a)),
        "payment_sat": t.payment_sat,
        "worker_deposit_sat": t.worker_deposit_sat,
        "deadline_height": t.deadline_height,
        "dispute_window": t.dispute_window,
        "state": t.state.name(),
    });
    if let ContractState::ResultSubmitted { result_hash, .. } = &t.state {
        v["result_hash"] = json!(hash_to_hex(result_hash));
    }
    v
}

// ---------------------------------------------------------------------------
// Handlers — read paths
// ---------------------------------------------------------------------------

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn status(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let p: &NetworkParams = sh.chain.params();
        Json(json!({
            "network": p.name,
            "network_id": p.network_id,
            "height": sh.chain.height(),
            "tip_hash": hash512_to_hex(&sh.chain.tip_hash()),
            "peers": state.peers.load(Ordering::Relaxed),
            "base_fee_sat": sh.chain.expected_base_fee_for_next_block(),
            "total_supply_sat": sh.chain.total_supply_sat(),
            "pscb_reserve_sat": sh.chain.pscb_reserve(),
            "finalized_height": sh.chain.finalized_height(),
            "finality_activation_height": p.finality_activation_height,
            "finality_depth": p.finality_depth,
            "mempool_len": sh.pool.len(),
            "l2": {
                "height": sh.l2.height(),
                "applied": sh.l2.applied_count(),
                "skipped": sh.l2.skipped().len(),
                "pending_deposits": sh.l2.pending_deposits().len(),
                // The exit pipeline (approved P1): queued exits awaiting an L1
                // release, and value that has already left L2 for L1. An
                // operator watches `exited_sat` to confirm the two directions
                // balanced rather than one side inflating.
                "pending_exits": sh.l2.pending_exits().len(),
                "exited_sat": sh.l2.state().exited_total(),
            },
        }))
    })
}

/// Live joint conservation (SPEC.md §19.4–§19.5): the arithmetic
/// `srct-node verify` prints, served from the same state and reported for all
/// three checks at once.
///
/// Read-only, under the same lock as `/v1/status`. The terms sum the whole
/// UTXO set, so this is a self-check/monitoring endpoint, not a hot path.
/// `ok` is the full verdict (L2 closed, L2 funded by genesis plus matured
/// deposits, joint supply inside the joint bound); the component booleans and
/// the terms say *which* check moved. `srct-worker run` gates on this before
/// its first pass, and `/metrics` exports the same joint figure as gauges —
/// all from the one implementation in `crate::conservation`, so the endpoint,
/// the exporter and `verify` cannot disagree.
async fn conservation(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let report = conservation_report(&sh.chain, &sh.l2);
        Json(json!({
            "ok": report.ok(),
            "l2_closed": report.l2_closed,
            "l2_funding_ok": report.l2_funding_ok(),
            "joint_sat": report.supply.joint_sat,
            "joint_overflow": report.supply.joint_overflow,
            "joint_bound_sat": report.supply.bound_sat(),
            "l1_bound_sat": report.supply.l1_bound_sat,
            "escrow_ceiling_sat": report.supply.escrow_ceiling_sat,
            "exited_sat": report.supply.exited_sat,
            "l1_issued_sat": srct_core::supply::cumulative_issuance_sat(sh.chain.params(), sh.chain.height()),
            "l1_removed_sat": sh.chain.base_removed_total(),
            "l1_net_sat": srct_core::supply::cumulative_issuance_sat(sh.chain.params(), sh.chain.height()).saturating_sub(sh.chain.base_removed_total()),
            "headroom_sat": report.supply.headroom_sat(),
            "l1_live_sat": report.supply.l1_live_sat,
            "l2_held_sat": report.supply.l2_held_sat,
            "sink_held_sat": report.supply.sink_held_sat,
            // Exit-outflow watch (lesson: the sink is a honeypot). An operator
            // alerts when the window fills faster than legitimate use: the
            // window total and its reset height say how much can still leave
            // this window, and `pending_exit_sat` says how much is already
            // queued. Conservation cannot see theft — a stolen exit still
            // conserves — so this is the signal theft trips.
            "exit_window_start": sh.l2.state().exit_window_start(),
            "exit_window_total_sat": sh.l2.state().exit_window_total(),
            "exit_window_cap_sat": sh.chain.params().max_exit_window_sat,
            "exit_window_ends_at": sh
                .l2
                .state()
                .exit_window_start()
                .saturating_add(sh.chain.params().exit_window_blocks),
            "pending_exit_sat": sh
                .l2
                .pending_exits()
                .iter()
                .fold(0u64, |a, w| a.saturating_add(w.record.amount_sat)),
            "network_id": sh.chain.params().network_id,
            "height": sh.chain.height(),
        }))
    })
}

async fn finality(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let p = sh.chain.params();
        Json(json!({
            "tip_height": sh.chain.height(),
            "finalized_height": sh.chain.finalized_height(),
            "finality_depth": p.finality_depth,
            "finality_activation_height": p.finality_activation_height,
            "binding": p.finality_activation_height > 0,
        }))
    })
}

async fn fee_schedule(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let p = sh.chain.params();
        let base = sh.chain.expected_base_fee_for_next_block();
        let l2: Vec<Value> = L2_FEE_SCHEDULE
            .iter()
            .map(|(name, sat)| json!({ "tx": name, "fee_sat": sat }))
            .collect();
        Json(json!({
            "sat_per_srct": SAT_PER_SRCT,
            "base_fee_sat_per_gas": base,
            "gas_base": GAS_TX_BASE,
            "gas_per_input": GAS_PER_INPUT,
            "gas_per_output": GAS_PER_OUTPUT,
            "min_tx_fee_sat": fees::required_fee(base, GAS_TX_BASE),
            "l2_fee_schedule": l2,
            "l2_deposit_minimum_sat": p.l2_deposit_minimum_sat,
            "coinbase_maturity": p.coinbase_maturity,
        }))
    })
}

/// Escape a Prometheus label value: backslash, double quote and newline are the
/// only three characters the exposition format requires to be escaped.
fn escape_label_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Append one gauge with its `# HELP` / `# TYPE` preamble.
fn gauge(out: &mut String, name: &str, help: &str, net: &str, value: u64) {
    // Writing into a String is infallible; the `let _` keeps the fmt::Write
    // contract explicit without an unwrap that clippy would prefer anyway.
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name}{{network=\"{net}\"}} {value}");
}

/// Prometheus text exposition (Phase 7 observability).
///
/// Gauges only, read straight out of the same state `/v1/status` reports, plus
/// the two relay-queue depths the node already tracks. Deliberately no counters
/// that would need per-request bookkeeping inside the consensus loop, and the
/// only label is the static network id — so label cardinality is bounded by
/// construction and a scraper cannot amplify memory. Nothing here renders key
/// material or per-user data.
///
/// Served at `/metrics` because that is the path a Prometheus scrape config
/// expects; it carries the same loopback-by-default exposure as every other
/// route in this module.
async fn metrics(
    State(state): State<ApiState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let body = with_shared(&state, |sh| {
        let p = sh.chain.params();
        let net = escape_label_value(&p.network_id);
        let peers = state.peers.load(Ordering::Relaxed) as u64;
        let mut out = String::with_capacity(2048);

        gauge(
            &mut out,
            "srct_height",
            "Current chain tip height.",
            &net,
            sh.chain.height(),
        );
        gauge(
            &mut out,
            "srct_finalized_height",
            "Highest finalized height.",
            &net,
            sh.chain.finalized_height(),
        );
        gauge(
            &mut out,
            "srct_finality_depth",
            "Depth-based finality window, in blocks.",
            &net,
            p.finality_depth,
        );
        gauge(
            &mut out,
            "srct_finality_activation_height",
            "Binding-finality activation height (0 disables binding finality).",
            &net,
            p.finality_activation_height,
        );
        gauge(&mut out, "srct_peers", "Connected peer count.", &net, peers);
        gauge(
            &mut out,
            "srct_base_fee_sat_per_gas",
            "Base fee for the next block, in satoshi per gas.",
            &net,
            sh.chain.expected_base_fee_for_next_block(),
        );
        gauge(
            &mut out,
            "srct_total_supply_sat",
            "Live UTXO supply, in satoshi.",
            &net,
            sh.chain.total_supply_sat(),
        );
        gauge(
            &mut out,
            "srct_rate_anchor_allowance_sat",
            "Rate anchor (Decision 18): the most gross issuance the current halving period may add, 1% of supply issued at the window's start, in satoshi. u64::MAX inside the grandfathered ladder era.",
            &net,
            srct_core::supply::rate_anchor_allowance(p, sh.chain.height() + 1),
        );
        gauge(
            &mut out,
            "srct_issued_sat",
            "Gross issuance so far (the issuance integral at the tip height), in satoshi; burns are what make net supply lower.",
            &net,
            srct_core::supply::cumulative_issuance_sat(p, sh.chain.height()),
        );
        gauge(
            &mut out,
            "srct_net_supply_sat",
            "Net supply (gross issuance minus base fees burned and PSCB-routed), in satoshi: the dilution holders experience.",
            &net,
            srct_core::supply::cumulative_issuance_sat(p, sh.chain.height())
                .saturating_sub(sh.chain.base_removed_total()),
        );
        // Joint conservation (SPEC §19.4–§19.5): the same report
        // `GET /v1/conservation` serves and `srct-node verify` prints. Adds one
        // UTXO-set pass per scrape — the same cost class
        // `srct_total_supply_sat` above already pays.
        let report = conservation_report(&sh.chain, &sh.l2);
        gauge(
            &mut out,
            "srct_joint_supply_sat",
            "Joint supply (L1 live + L2 held − deposit sink), in satoshi; must stay at or below the joint bound.",
            &net,
            report.supply.joint_sat,
        );
        gauge(
            &mut out,
            "srct_joint_bound_sat",
            "Joint ceiling (issuance integral at the tip plus the escrow ceiling), in satoshi.",
            &net,
            report.supply.bound_sat(),
        );
        gauge(
            &mut out,
            "srct_conservation_ok",
            "1 while L2 balances, L2 funding is genesis plus matured deposits minus value released to L1, and joint supply is inside the bound; 0 means value was created.",
            &net,
            u64::from(report.ok()),
        );
        gauge(
            &mut out,
            "srct_pscb_reserve_sat",
            "PSCB reserve counter, in satoshi (non-spendable; never re-enters supply).",
            &net,
            sh.chain.pscb_reserve(),
        );
        gauge(
            &mut out,
            "srct_mempool_transactions",
            "L1 transactions currently in the mempool.",
            &net,
            sh.pool.len() as u64,
        );
        gauge(
            &mut out,
            "srct_l1_relay_queue",
            "Accepted L1 txids queued for peer relay.",
            &net,
            sh.tx_to_relay.len() as u64,
        );
        gauge(
            &mut out,
            "srct_l2_include_queue",
            "L2 transactions queued to ride the next mined block.",
            &net,
            sh.l2_to_include.len() as u64,
        );
        gauge(
            &mut out,
            "srct_l2_height",
            "Canonical L2 height.",
            &net,
            sh.l2.height(),
        );
        gauge(
            &mut out,
            "srct_l2_applied_total",
            "L2 payloads applied to canonical state.",
            &net,
            sh.l2.applied_count(),
        );
        gauge(
            &mut out,
            "srct_l2_skipped_total",
            "L2 payloads skipped (fail-closed count).",
            &net,
            sh.l2.skipped().len() as u64,
        );
        gauge(
            &mut out,
            "srct_l2_pending_deposits",
            "L2 deposits awaiting maturity.",
            &net,
            sh.l2.pending_deposits().len() as u64,
        );
        out
    })?;
    Ok((
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ))
}

async fn balance(State(state): State<ApiState>, Path(addr): Path<String>) -> ApiResult {
    let addr = decode_address(&addr)?;
    with_shared(&state, |sh| {
        let mut confirmed = 0u64;
        let mut spendable = 0u64;
        let next_height = sh.chain.height() + 1;
        for (_, u) in sh.chain.utxo().iter() {
            if u.out.address == addr {
                confirmed = confirmed.saturating_add(u.out.value);
                if sh.chain.is_mature(u.height) {
                    spendable = spendable.saturating_add(u.out.value);
                }
            }
        }
        let mut pending_in = 0u64;
        for (_, entry) in sh.pool.entries() {
            for o in &entry.tx.outputs {
                if o.address == addr {
                    pending_in = pending_in.saturating_add(o.value);
                }
            }
        }
        Json(json!({
            "address": address_to_hex(&addr),
            "confirmed_sat": confirmed,
            "spendable_sat": spendable,
            "pending_sat": pending_in,
            "next_height": next_height,
        }))
    })
}

/// Pagination for the list endpoints: `?limit=&cursor=`. The cursor is an
/// offset into a deterministically ordered list, so page N means the same on
/// every node and every call. Lists at or below [`DEFAULT_PAGE_LIMIT`] return
/// whole, exactly as before the parameters existed.
#[derive(Debug, Default, serde::Deserialize)]
struct PageParams {
    limit: Option<usize>,
    cursor: Option<u64>,
}

/// Unrequested page size, and the hard cap when one is requested.
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 1_000;

/// The requested page of `all`: items `[cursor, cursor + limit)`, the total
/// before pagination, and the cursor for the next page — `null` once this page
/// was the last. `limit` is clamped, and a cursor past the end yields an empty
/// page rather than an error.
fn take_page<T>(all: Vec<T>, page: &PageParams) -> (Vec<T>, usize, Value) {
    let limit = page
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT);
    let total = all.len();
    let start = page.cursor.unwrap_or(0).min(total as u64) as usize;
    let end = start.saturating_add(limit).min(total);
    let next = if end < total {
        json!(end as u64)
    } else {
        Value::Null
    };
    let items = all.into_iter().skip(start).take(end - start).collect();
    (items, total, next)
}

async fn utxos(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
    Query(page): Query<PageParams>,
) -> ApiResult {
    let addr = decode_address(&addr)?;
    with_shared(&state, |sh| {
        let mut out = Vec::new();
        for (op, u) in sh.chain.utxo().iter() {
            if u.out.address == addr {
                out.push((
                    (op.txid, op.index),
                    json!({
                        "txid": hash512_to_hex(&op.txid),
                        "index": op.index,
                        "value_sat": u.out.value,
                        "height": u.height,
                        "spendable": sh.chain.is_mature(u.height),
                    }),
                ));
            }
        }
        // Outpoint order, not `HashMap` iteration order: the cursor's offsets
        // must mean the same thing on every node and on every call.
        out.sort_by_key(|(k, _)| *k);
        let (items, total, next) = take_page(out.into_iter().map(|(_, v)| v).collect(), &page);
        Json(json!({
            "address": address_to_hex(&addr),
            "count": total,
            "next_cursor": next,
            "utxos": items,
        }))
    })
}

async fn block_latest(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let h = sh.chain.height();
        let block = sh.chain.block_at(h).ok_or_else(|| not_found("no block"))?;
        let value = serde_json::to_value(block)
            .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
        Ok(Json(
            json!({ "hash": hash512_to_hex(&block.block_hash()), "block": value }),
        ))
    })?
}

async fn block_by_hash(State(state): State<ApiState>, Path(hash): Path<String>) -> ApiResult {
    let hash = decode_hash512(&hash)?;
    with_shared(&state, |sh| {
        let block = sh
            .chain
            .block_by_hash(&hash)
            .ok_or_else(|| not_found("unknown block"))?;
        let value = serde_json::to_value(block)
            .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
        Ok(Json(
            json!({ "hash": hash512_to_hex(&hash), "block": value }),
        ))
    })?
}

/// External-miner template (mining-stack seam).
///
/// Returns an unsolved block paying `miner` at tip height + 1, built by
/// [`Chain::build_template_with`]: everything is fixed except `nonce` /
/// `extra_nonce`, which the miner grinds (both commit into the proof through
/// the serialized header). The template is returned as binary `block_hex`
/// plus the fields a miner needs without decoding it. Submit the solved
/// block to `POST /v1/mine/submit`, which re-validates the proof — the miner
/// is never trusted.
///
/// Template and submit are not atomic: by the time a solution lands, the tip
/// may have moved and the block lands as a side branch (`canonical: false`
/// in the submit answer). External miners should re-fetch the template and
/// compare `prev_hash` rather than grind one template forever. Mempool
/// transactions are included like the internal miner's; L2 writes and exit
/// claims stay with the internal miner, which also carries the L2 root the
/// chain requires.
#[derive(Deserialize)]
struct MineTemplateQuery {
    miner: String,
}

async fn mine_template(
    State(state): State<ApiState>,
    Query(q): Query<MineTemplateQuery>,
) -> ApiResult {
    let miner = decode_address(&q.miner)?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    with_shared(&state, |sh| {
        // Same mempool selection as the internal miner (minus L2/exits,
        // which need the L2 root only the internal path derives).
        let body = sh
            .chain
            .select_from_pool_for_template(&sh.pool)
            .map_err(|e| bad(format!("template: {e}")))?;
        let template = sh
            .chain
            .build_template_with(miner, body, now_ms, None)
            .map_err(|e| bad(format!("template: {e}")))?;
        Ok(Json(json!({
            "height": template.header.height,
            "difficulty": template.header.difficulty.to_string(),
            "puzzle_id": template.header.puzzle_id,
            "prev_hash": hash512_to_hex(&template.header.prev_hash),
            "block_hex": hex::encode(template.serialize()),
        })))
    })?
}

/// Accept a miner-solved block: decode, then `submit`, which re-validates
/// everything including the proof of work and the claimed difficulty.
#[derive(Deserialize)]
struct MineSubmitReq {
    block_hex: String,
}

async fn mine_submit(State(state): State<ApiState>, Json(req): Json<MineSubmitReq>) -> ApiResult {
    // A block is at most 4 MiB on the wire (8M hex chars); the generic hex
    // cap is larger, so bound this field explicitly before decoding.
    if req.block_hex.len() > 8 * 1024 * 1024 {
        return Err(bad("block_hex over the 8M-char cap"));
    }
    let bytes = decode_hex_bytes(&req.block_hex, "block")?;
    let block = Block::deserialize(&bytes).map_err(|e| bad(format!("block decode: {e}")))?;
    let want = block.block_hash();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    with_shared(&state, |sh| {
        // The local-clock rule the P2P path enforces: a far-future block
        // must not enter canon through HTTP that relay would refuse.
        match sh.chain.submit_at(block.clone(), Some(now_ms)) {
            Ok(()) => {
                // The next block the node builds spends the confirmed
                // outputs; without this the internal miner's next attempt
                // probes (and fails) on inputs this block just spent.
                sh.pool.evict_confirmed(&block.txs);
                let h = sh.chain.height();
                let tip = sh.chain.tip_hash();
                // Template and submit are not atomic: report whether the
                // block won fork choice, so a miner grinding a stale
                // template sees `canonical: false` instead of a success
                // that never pays.
                Ok(Json(json!({
                    "height": h,
                    "hash": hash512_to_hex(&want),
                    "canonical": tip == want,
                })))
            }
            Err(e) => Err(fail(
                StatusCode::BAD_REQUEST,
                "block_refused",
                e.to_string(),
            )),
        }
    })?
}

async fn tx_lookup(State(state): State<ApiState>, Path(hash): Path<String>) -> ApiResult {
    let hash = decode_hash512(&hash)?;
    with_shared(&state, |sh| {
        // Canonical scan: O(tip) per lookup, which is the honest cost of a
        // node with no tx index. Documented in the status docs.
        for height in 1..=sh.chain.height() {
            let Some(block) = sh.chain.block_at(height) else {
                continue;
            };
            for tx in &block.txs {
                if tx.txid() == hash {
                    let value = serde_json::to_value(tx).unwrap_or(Value::Null);
                    return Ok(Json(json!({
                        "status": "confirmed",
                        "block_hash": hash512_to_hex(&block.block_hash()),
                        "block_height": height,
                        "tx": value,
                    })));
                }
            }
        }
        if let Some(entry) = sh.pool.get(&hash) {
            let value = serde_json::to_value(&entry.tx).unwrap_or(Value::Null);
            return Ok(Json(json!({ "status": "pending", "tx": value })));
        }
        Err(not_found("unknown transaction"))
    })?
}

async fn mempool_view(State(state): State<ApiState>, Query(page): Query<PageParams>) -> ApiResult {
    with_shared(&state, |sh| {
        let mut entries = Vec::new();
        for (txid, e) in sh.pool.entries() {
            entries.push((
                *txid,
                json!({
                    "tx_hash": hash512_to_hex(txid),
                    "fee_rate": e.fee_rate,
                    "fee_sat": e.fee_total,
                    "inputs": e.tx.inputs.len(),
                    "outputs": e.tx.outputs.len(),
                }),
            ));
        }
        // Txid order: pool iteration is `HashMap` order and must not leak into
        // a cursor, or two calls could hand out different pages.
        entries.sort_by_key(|(k, _)| *k);
        let (items, total, next) = take_page(entries.into_iter().map(|(_, v)| v).collect(), &page);
        Json(json!({ "count": total, "entries": items, "next_cursor": next }))
    })
}

async fn tasks_open(State(state): State<ApiState>, Query(page): Query<PageParams>) -> ApiResult {
    with_shared(&state, |sh| {
        let open: Vec<Value> = sh
            .l2
            .state()
            .tasks()
            .iter()
            .filter(|t| matches!(t.state, ContractState::Open))
            .map(|t| task_json(t))
            .collect();
        // `tasks()` is documented sorted by task id and the filter preserves
        // that order, so the cursor's offsets are stable without a re-sort.
        let (items, total, next) = take_page(open, &page);
        Json(json!({ "count": total, "tasks": items, "next_cursor": next }))
    })
}

async fn task_by_id(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let task = sh
            .l2
            .state()
            .tasks()
            .into_iter()
            .find(|t| t.task_id == id)
            .ok_or_else(|| not_found("unknown task"))?;
        Ok(Json(task_json(task)))
    })?
}

async fn vwc_by_task(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let cert = sh
            .l2
            .state()
            .vwc(&id)
            .ok_or_else(|| not_found("no certificate for task"))?;
        Ok(Json(json!({
            "id": hash_to_hex(&cert.id),
            "task_id": hash_to_hex(&cert.task_id),
            "worker": address_to_hex(&cert.worker),
            "result_hash": hash_to_hex(&cert.result_hash),
            "settled_height": cert.settled_height,
            "payment_sat": cert.payment_sat,
            // The certificate's own canonical encoding, so a relying party can
            // verify it offline against the validator set instead of trusting
            // this summary (SPEC.md §17.6).
            "vwc_hex": hex::encode(cert.encode()),
            "verification": match &cert.verification {
                srct_l2::VwcVerification::Quorum { signer_count, .. } => {
                    json!({ "kind": "quorum", "signer_count": signer_count })
                }
                srct_l2::VwcVerification::WindowElapsed => json!({ "kind": "window_elapsed" }),
            },
        })))
    })?
}

/// One published spending policy, in JSON.
///
/// The whole grant, plus the counters the chain keeps. A caller that wants to
/// know what an agent may spend, and how much of it is left, reads it here
/// rather than re-deriving the rules.
fn policy_json(p: &srct_core::agent::PolicyEntry) -> Value {
    json!({
        "policy_hash": hash_to_hex(&p.hash()),
        "agent_id": address_to_hex(&p.agent_id),
        "owner": address_to_hex(&p.policy.owner),
        "spender": address_to_hex(&p.spender),
        "role": format!("{:?}", p.policy.role),
        "revoked": p.revoked,
        "network_id": p.policy.network_id,
        "per_tx_max_sat": p.policy.per_tx_max_sat,
        "window_blocks": p.policy.window_blocks,
        "cumulative_max_sat": p.policy.cumulative_max_sat,
        "allowed_recipients": p.policy.allowed_recipients.iter().map(address_to_hex).collect::<Vec<_>>(),
        "allowed_services": p.policy.allowed_services.iter().map(hex::encode).collect::<Vec<_>>(),
        "not_before_height": p.policy.not_before_height,
        "expires_at_height": p.policy.expires_at_height,
        "parent_agent_id": p.policy.parent_agent_id.map(|a| address_to_hex(&a)),
        "window_start_height": p.window_start_height,
        "spent_in_window_sat": p.spent_in_window_sat,
        "total_spent_sat": p.total_spent_sat,
        "last_nonce": p.last_nonce,
        "spends": p.spends,
    })
}

/// One credit position, in JSON.
fn credit_position_json(p: &srct_l2::CreditPosition) -> Value {
    json!({
        "position_id": hash_to_hex(&p.id),
        "lender": address_to_hex(&p.lender),
        "borrower": address_to_hex(&p.borrower),
        "principal_sat": p.principal_sat,
        "outstanding_sat": p.outstanding_sat,
        "interest_paid_sat": p.interest_paid_sat,
        "collateral_sat": p.collateral_sat,
        "rate_bps_per_window": p.rate_bps_per_window,
        "window_blocks": p.window_blocks,
        "opened_height": p.opened_height,
        "deadline_height": p.deadline_height,
        "state": format!("{:?}", p.state),
    })
}

/// Every published spending policy, paginated.
async fn policies(State(state): State<ApiState>, Query(page): Query<PageParams>) -> ApiResult {
    with_shared(&state, |sh| {
        let all: Vec<Value> = sh
            .l2
            .state()
            .policies()
            .into_iter()
            .map(policy_json)
            .collect();
        let (items, total, next) = take_page(all, &page);
        Json(json!({ "count": total, "policies": items, "next_cursor": next }))
    })
}

/// The live grant for one agent.
async fn policy_by_agent(State(state): State<ApiState>, Path(agent_id): Path<String>) -> ApiResult {
    let agent_id = decode_address(&agent_id)?;
    with_shared(&state, |sh| {
        let policy = sh
            .l2
            .state()
            .policy_for_agent(&agent_id)
            .ok_or_else(|| not_found("no published policy for this agent"))?;
        Ok(Json(policy_json(policy)))
    })?
}

/// Every credit position, paginated.
async fn credit_positions(
    State(state): State<ApiState>,
    Query(page): Query<PageParams>,
) -> ApiResult {
    with_shared(&state, |sh| {
        let all: Vec<Value> = sh
            .l2
            .state()
            .credit_positions()
            .into_iter()
            .map(credit_position_json)
            .collect();
        let (items, total, next) = take_page(all, &page);
        Json(json!({ "count": total, "positions": items, "next_cursor": next }))
    })
}

/// One credit position, by id.
async fn credit_position_by_id(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let position = sh
            .l2
            .state()
            .credit_position(&id)
            .ok_or_else(|| not_found("no such credit position"))?;
        Ok(Json(credit_position_json(position)))
    })?
}

/// The canonical L2 state, in the §19.2 wire encoding.
///
/// This is the one endpoint a worker SDK needs that a task-shaped summary
/// cannot serve: `L2NodeView` hands the SDK an `L2State`, so a remote view has
/// to carry the whole state or duplicate the protocol's own rules. The bytes
/// are the node's *derived* state — replaying the canonical blocks produces
/// exactly this — so the client decodes and then checks the conservation
/// invariant itself before it believes a single balance. No signature
/// material is in here: a state is not an actor's claim.
async fn l2_state(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let l2 = sh.l2.state();
        Json(json!({
            "network_id": sh.chain.params().network_id,
            "height": sh.chain.height(),
            "tasks": l2.task_count(),
            "certificates": l2.vwc_count(),
            "state_hex": hex::encode(l2.encode()),
        }))
    })
}

/// Derived reputation for a worker, computed from canonical L2 state.
///
/// The `{id}` is the worker's **address**; the node derives the machine
/// `AgentId` from it (same derivation every identity uses) and then builds the
/// reputation ledger from the L2 state the same way a node derives L2 itself.
/// A worker that has never had a verified-work certificate or a settled dispute
/// reads as a zero score — that is genuine standing, not an error.
///
/// This is read-only, derived, and non-consensus: it cannot fork the chain, and
/// the derivation rules are the same as the ones a peer running this code
/// independently would apply.
async fn reputation_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let address = decode_address(&id)?;
    with_shared(&state, |sh| {
        let params = sh.chain.params();
        let network_id = &params.network_id;
        let subject = derive_agent_id(network_id, AgentRole::Machine, &address);
        let ledger = ledger_from_state(sh.l2.state(), network_id)
            .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
        let mut score_obj = match ledger.score(&subject) {
            Some(s) => json!({
                "score": s.score,
                "events": s.events,
                "by_kind": {
                    "service_completed": s.by_kind[0],
                    "payment_completed": s.by_kind[1],
                    "verified_work": s.by_kind[2],
                    "dispute_won": s.by_kind[3],
                    "dispute_lost": s.by_kind[4],
                },
                "last_height": s.last_height,
                "accumulator": hash_to_hex(&s.accumulator),
                "subjects_tracked": ledger.subjects(),
            }),
            None => json!({
                "score": 0,
                "events": 0,
                "by_kind": {
                    "service_completed": 0,
                    "payment_completed": 0,
                    "verified_work": 0,
                    "dispute_won": 0,
                    "dispute_lost": 0,
                },
                "last_height": 0,
                "accumulator": hash_to_hex(&Hash::default()),
                "subjects_tracked": ledger.subjects(),
            }),
        };
        score_obj["worker_address"] = json!(address_to_hex(&address));
        score_obj["agent_id"] = json!(address_to_hex(&subject));
        score_obj["network_id"] = json!(network_id);
        Ok(Json(json!({
            "worker_address": address_to_hex(&address),
            "agent_id": address_to_hex(&subject),
            "network_id": network_id,
            "score": score_obj["score"],
            "events": score_obj["events"],
            "by_kind": score_obj["by_kind"],
            "last_height": score_obj["last_height"],
            "accumulator": score_obj["accumulator"],
            "subjects_tracked": score_obj["subjects_tracked"],
        })))
    })?
}

async fn payment_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let p = sh
            .payment_store
            .get(&id)
            .ok_or_else(|| not_found("unknown payment"))?;
        Ok(Json(json!({
            "payment_id": hash_to_hex(&id),
            "payment_hex": hex::encode(p.serialize()),
            "payer": address_to_hex(&p.payer),
            "recipient": address_to_hex(&p.recipient),
            "amount_sat": p.amount_sat,
            "fee_sat": p.fee_sat,
            "service": p.service.map(hex::encode),
            "nonce": p.nonce,
            "expires_at_height": p.expires_at_height,
            "network_id": p.network_id,
            "settlement": settlement_value(sh, &id),
        })))
    })?
}

#[derive(Deserialize)]
struct PaymentSettleReq {
    tx_hash: String,
}

/// Bind a recorded payment to the L1 transaction that settles it.
///
/// The node verifies the binding itself — the transaction must exist in this
/// node's chain or mempool and must pay the payment's recipient at least the
/// payment's amount — so the link is evidence, not a caller's say-so. A repeat
/// of the same txid is idempotent; a second, different txid is a conflict.
async fn payment_settle(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<PaymentSettleReq>,
) -> ApiResult {
    let id = decode_hash(&id)?;
    let txid = decode_hash512(&req.tx_hash)?;
    with_shared(&state, |sh| {
        let (recipient, amount_sat) = {
            let p = sh
                .payment_store
                .get(&id)
                .ok_or_else(|| not_found("unknown payment"))?;
            (p.recipient, p.amount_sat)
        };
        if let Some(linked) = sh.payment_tx.get(&id) {
            if *linked == txid {
                let height = locate_tx(sh, &txid).and_then(|(h, _)| h);
                return Ok(Json(json!({
                    "payment_id": hash_to_hex(&id),
                    "settlement": settlement_json(&txid, height),
                    "duplicate": true,
                })));
            }
            return Err(fail(
                StatusCode::CONFLICT,
                "already_settled",
                format!("payment already settles against {}", hash512_to_hex(linked)),
            ));
        }
        let Some((confirmed_height, tx)) = locate_tx(sh, &txid) else {
            return Err(fail(
                StatusCode::NOT_FOUND,
                "unknown_transaction",
                "no such transaction in this node's chain or mempool",
            ));
        };
        let paid: u64 = tx
            .outputs
            .iter()
            .filter(|o| o.address == recipient)
            .map(|o| o.value)
            .fold(0u64, u64::saturating_add);
        if paid < amount_sat {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "settlement_does_not_pay_recipient",
                format!(
                    "transaction pays {paid} sat to the recipient; this payment needs {amount_sat} sat"
                ),
            ));
        }
        // No double-counting: the same transaction output cannot settle two
        // payments. Sum what this node already attributed to this txid for
        // the same recipient, and require the tx to cover the old links
        // plus this one. Checked math: a saturated sum would hide an
        // over-attribution as fitting.
        let mut committed: u64 = 0;
        for (pid, linked) in &sh.payment_tx {
            if *linked == txid && *pid != id {
                if let Some(p) = sh.payment_store.get(pid) {
                    if p.recipient == recipient {
                        committed = committed.checked_add(p.amount_sat).ok_or_else(|| {
                            fail(
                                StatusCode::CONFLICT,
                                "settlement_overlaps",
                                "transaction outputs already fully attributed",
                            )
                        })?;
                    }
                }
            }
        }
        let need = amount_sat.checked_add(committed).ok_or_else(|| {
            fail(
                StatusCode::CONFLICT,
                "settlement_overlaps",
                "transaction outputs already fully attributed",
            )
        })?;
        if paid < need {
            return Err(fail(
                StatusCode::CONFLICT,
                "settlement_overlaps",
                format!(
                    "transaction pays {paid} sat to the recipient but {committed} sat are already attributed to other payments; this payment needs {amount_sat} sat more"
                ),
            ));
        }
        sh.payment_tx.insert(id, txid);
        Ok(Json(json!({
            "payment_id": hash_to_hex(&id),
            "settlement": settlement_json(&txid, confirmed_height),
        })))
    })?
}

async fn receipt_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let r = sh
            .receipts
            .by_receipt_id(&id)
            .or_else(|| sh.receipts.by_payment_id(&id))
            .ok_or_else(|| not_found("unknown receipt"))?;
        Ok(Json(json!({
            "receipt_id": hash_to_hex(&r.receipt_id()),
            "payment_id": hash_to_hex(&r.payment_id),
            "request_id": hash_to_hex(&r.request_id),
            "payer": address_to_hex(&r.payer),
            "recipient": address_to_hex(&r.recipient),
            "amount_sat": r.amount_sat,
            "service_id": r.service_id.map(hex::encode),
            "result_hash": r.result_hash.map(|h| hash_to_hex(&h)),
            "anchor_height": r.anchor.map(|a| a.height),
            "receipt_hex": hex::encode(r.serialize()),
        })))
    })?
}

// ---------------------------------------------------------------------------
// Handlers — write paths (no signing, no consensus surface)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TxBuildReq {
    from: String,
    to: String,
    amount_sat: u64,
    /// Ceiling on the computed fee. The build refuses rather than silently
    /// exceeding it.
    max_fee_sat: u64,
}

async fn tx_build(State(state): State<ApiState>, Json(req): Json<TxBuildReq>) -> ApiResult {
    if req.amount_sat == 0 {
        return Err(bad("amount_sat must be > 0"));
    }
    let from = decode_address(&req.from)?;
    let to = decode_address(&req.to)?;
    with_shared(&state, |sh| {
        let base_fee = sh.chain.expected_base_fee_for_next_block();
        let maturity = sh.chain.params().coinbase_maturity;
        let candidates: Vec<(srct_core::tx::OutPoint, u64)> = sh
            .chain
            .utxo()
            .iter()
            .filter(|(_, u)| u.out.address == from && sh.chain.is_mature(u.height))
            .map(|(op, u)| (op, u.out.value))
            .collect();
        if candidates.is_empty() {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "insufficient_funds",
                format!(
                    "no mature outputs for {} (a coinbase needs {maturity} blocks)",
                    address_to_hex(&from)
                ),
            ));
        }

        // Gather inputs until amount + fee is covered; the fee depends on the
        // input count and the input count on the fee, so it settles by
        // iteration — the same rule `srct-node send` uses.
        let mut chosen = Vec::new();
        let mut total = 0u64;
        for (op, value) in candidates {
            let gas = GAS_TX_BASE + GAS_PER_INPUT * (chosen.len() as u64 + 1) + GAS_PER_OUTPUT * 2;
            let fee = fees::required_fee(base_fee, gas).saturating_add(1_000);
            if total >= req.amount_sat.saturating_add(fee) {
                break;
            }
            total = total.saturating_add(value);
            chosen.push(op);
        }
        let gas = GAS_TX_BASE + GAS_PER_INPUT * chosen.len() as u64 + GAS_PER_OUTPUT * 2;
        let fee = fees::required_fee(base_fee, gas).saturating_add(1_000);
        if total < req.amount_sat.saturating_add(fee) {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "insufficient_funds",
                format!(
                    "have {total} sat, need {} sat",
                    req.amount_sat.saturating_add(fee)
                ),
            ));
        }
        if fee > req.max_fee_sat {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "fee_exceeds_max",
                format!("fee {fee} sat > max_fee_sat {}", req.max_fee_sat),
            ));
        }

        let change = total.saturating_sub(req.amount_sat).saturating_sub(fee);
        let mut outputs = vec![srct_core::tx::Output {
            value: req.amount_sat,
            address: to,
        }];
        if change > 0 {
            outputs.push(srct_core::tx::Output {
                value: change,
                address: from,
            });
        }
        // Unsigned by design: the caller signs these bytes with their wallet.
        // The API has no key material and must never acquire any.
        let unsigned = Transaction::standard(
            chosen.iter().map(srct_core::tx::Input::unsigned).collect(),
            outputs,
        );
        let selected: Vec<Value> = chosen
            .iter()
            .map(|op| json!({ "txid": hash512_to_hex(&op.txid), "index": op.index }))
            .collect();
        Ok(Json(json!({
            "unsigned_tx_hex": hex::encode(unsigned.serialize()),
            "fee_sat": fee,
            "change_sat": change,
            "selected_utxos": selected,
            "note": "sign every input with the `from` wallet, then POST /v1/tx/broadcast",
        })))
    })?
}

/// Which funding-shaped path a request wanted (Decision 17).
///
/// Only these two are refused during a breach. A blanket freeze was rejected:
/// it would take the node's ordinary payment traffic down with the accounting,
/// and a node that stops serving everything is indistinguishable from one that
/// crashed. The set is exactly the paths that make the broken number *worse*.
#[derive(Debug, Clone, Copy)]
enum FundingPath {
    /// L2 include-queue admission — a write into a state already known bad.
    L2Write,
    /// An L1 payment carrying an output to the deposit sink — it debits L1 and
    /// credits L2, so it grows both sides of a bound that is already broken.
    Deposit,
}

impl FundingPath {
    fn what(self) -> &'static str {
        match self {
            FundingPath::L2Write => "L2 write",
            FundingPath::Deposit => "deposit",
        }
    }
}

/// Decision 17 — the conservation-breach refusal.
///
/// When the joint-supply bound is broken, value exists that should not, and any
/// further funding-shaped write makes the accounting worse. The approved
/// response is to refuse exactly those writes, name conservation in the error,
/// and keep every read up (`/v1/conservation`, `/metrics`, blocks, UTXO and
/// balance queries) so an operator can see what happened. Halt (process exit)
/// was rejected: a crash-loop converts a safety alarm into a liveness loss and
/// destroys the diagnostics.
///
/// Recomputed per request from the one `crate::conservation` implementation the
/// endpoint, the exporter and `verify` all share, so the three cannot disagree
/// about whether there is a breach. No state is discarded and nothing is cached:
/// recovery is the operator restarting once the cause is understood, and the
/// check immediately reports all-clear.
fn refuse_funding_if_breached(
    sh: &SharedNode,
    path: FundingPath,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let report = conservation_report(&sh.chain, &sh.l2);
    if report.ok() {
        return Ok(());
    }
    let detail = report
        .first_error()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "conservation check failed".to_string());
    // Loud on every refusal, not just the first: an operator grepping logs must
    // see the condition is still live rather than infer it from silence.
    eprintln!(
        "CONSERVATION BREACH — refusing {}: {detail} (joint {} of {} sat)",
        path.what(),
        report.supply.joint_sat,
        report.supply.bound_sat()
    );
    Err(fail(
        StatusCode::SERVICE_UNAVAILABLE,
        "conservation_breach",
        format!(
            "refusing {}: joint supply is not conserved ({detail}); reads stay available — see GET /v1/conservation",
            path.what()
        ),
    ))
}

/// Refuse a funding path whose payload does not need to be inspected.
///
/// Used by `/v1/l2/broadcast`: the node refuses the *path* while the bound is
/// broken, so it does not decode, validate or queue a payload it would only
/// discard. The deposit path cannot use this — a payment has to be parsed to
/// know it carries a sink output — so there the check runs after decode.
fn ensure_funding_allowed(
    state: &ApiState,
    path: FundingPath,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    with_shared(state, |sh| refuse_funding_if_breached(sh, path))?
}

#[derive(Deserialize)]
struct TxBroadcastReq {
    signed_tx_hex: String,
}

async fn tx_broadcast(State(state): State<ApiState>, Json(req): Json<TxBroadcastReq>) -> ApiResult {
    let bytes = decode_hex_bytes(&req.signed_tx_hex, "signed_tx")?;
    let tx = Transaction::deserialize(&bytes).map_err(|e| bad(format!("tx decode: {e}")))?;
    let txid = tx.txid();
    // Signature verification and admission (BLS/ML-DSA/ECDSA) happen on a
    // blocking thread, so the async runtime is never stalled by crypto and
    // the request timeout and concurrency cap stay effective: the timeout
    // races the `spawn_blocking` await, and the in-flight cap bounds how many
    // such tasks can exist at once.
    let state_for_task = state.clone();
    let tx_for_task = tx;
    let txid_for_result = txid;
    // Verification, then commit, then the relay note: three bounded lock
    // sections, so the signature checks run with no lock held and anything
    // that moved the chain between them is refused as stale rather than
    // admitted on a verdict the chain has left behind.
    let outcome = tokio::task::spawn_blocking(move || {
        // One permit for the whole admission: the in-flight request cap above
        // counts requests, and this counts the part of one that costs real
        // CPU, so a burst of broadcasts cannot occupy the blocking pool.
        let _verify = acquire_verify_permit()?;

        // Phase 1 — snapshot the state verification reads, under the lock.
        let snapshot = with_shared_bounded(&state_for_task, |sh| {
            sh.pool.admission_snapshot(
                &tx_for_task,
                sh.chain.utxo(),
                sh.chain.height() + 1,
                sh.chain.params(),
                sh.chain.expected_base_fee_for_next_block(),
                sh.chain.bonds(),
            )
        })?;

        // Phase 2 — every pairing, no lock held. A pure function of the
        // transaction and its snapshot, so the serve loop keeps mining while
        // this runs. A refusal here is the same 400 the one-lock path gave.
        let verified = match Mempool::default().verify_admission(&tx_for_task, &snapshot) {
            Ok(verified) => verified,
            Err(e) => {
                return Err(fail(StatusCode::BAD_REQUEST, "tx_refused", e.to_string()));
            }
        };

        // Phase 3 — re-check the cheap conditions against live state, commit,
        // and note the relay. A refusal here may be `Stale`: the chain moved
        // while the transaction was being verified.
        let outcome = with_shared_bounded(&state_for_task, |sh| {
            let sink = sh.chain.params().l2_deposit_sink();
            if tx_for_task.outputs.iter().any(|o| o.address == sink) {
                refuse_funding_if_breached(sh, FundingPath::Deposit)?;
            }
            let outcome = sh.pool.commit_admission(
                &tx_for_task,
                &verified,
                sh.chain.utxo(),
                sh.chain.height() + 1,
                sh.chain.expected_base_fee_for_next_block(),
                sh.chain.bonds(),
            );
            match outcome {
                Ok(txid) => {
                    sh.tx_to_relay.push(txid);
                    Ok(Json(json!({ "tx_hash": hash512_to_hex(&txid) })))
                }
                Err(srct_core::mempool::MempoolError::AlreadyKnown) => Ok(Json(
                    json!({ "tx_hash": hash512_to_hex(&txid_for_result), "already_known": true }),
                )),
                Err(e) => Err(fail(StatusCode::BAD_REQUEST, "tx_refused", e.to_string())),
            }
        });
        outcome
    })
    .await
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", "task join"))??;
    outcome
}

#[derive(Deserialize)]
struct L2BroadcastReq {
    l2_tx_hex: String,
}

async fn l2_broadcast(State(state): State<ApiState>, Json(req): Json<L2BroadcastReq>) -> ApiResult {
    // Decision 17, before anything else: on a breached node this write path is
    // refused outright, ahead of decode, dedup and the dry-run — the node
    // refuses the path, not the payload, and does no work it would only throw
    // away. Reads are untouched, so an operator can still diagnose.
    ensure_funding_allowed(&state, FundingPath::L2Write)?;
    let bytes = decode_hex_bytes(&req.l2_tx_hex, "l2_tx")?;
    let tx = L2Transaction::deserialize(&bytes).map_err(|e| bad(format!("l2 tx decode: {e}")))?;
    let txid = tx.txid();
    with_shared(&state, |sh| {
        if sh.l2_to_include.iter().any(|t| t.txid() == txid) {
            return Ok(Json(
                json!({ "txid": hash512_to_hex(&txid), "already_queued": true }),
            ));
        }
        // Dry-run against a *clone*: the real L2 state is derived from
        // canonical blocks only (SPEC §19.1). Advisory verdict — replay at
        // inclusion height is still the authority.
        sh.l2
            .check(&sh.chain, &tx, sh.chain.height() + 1)
            .map_err(|e| fail(StatusCode::CONFLICT, "l2_refused", format!("{e}")))?;
        sh.l2_to_include.push(tx);
        Ok(Json(
            json!({ "txid": hash512_to_hex(&txid), "queued": true }),
        ))
    })?
}

#[derive(Deserialize)]
struct AuthorizeReq {
    /// Canonical `SpendPolicy` encoding (public: policies hold rules, keys).
    policy_hex: String,
    /// Owner signature over `SpendPolicy::signing_hash` (hybrid bundle).
    policy_sigs_hex: Option<String>,
    /// Owner public keys, whose address must be the policy's `owner`.
    policy_keys_hex: Option<String>,
    /// The ancestry for a delegated policy, oldest first. Required — and
    /// validated — whenever the policy names a parent.
    chain_hex: Option<Vec<String>>,
    /// Canonical `PaymentRequest` encoding — must be signed by the payer.
    request_hex: String,
    /// Strictly increasing per policy; the caller's own anti-replay counter.
    nonce: u64,
}

/// Decode a hex-encoded policy and check that the owner signed it.
///
/// A policy is authority: per-transaction caps, recipient allow lists, validity
/// window. A route that accepts policy bytes without the owner's signature is a
/// route where anyone may mint authority for anyone else — which is the widening
/// a delegation chain exists to prevent, arriving one step earlier. The owner's
/// keys must derive to the address the policy names as `owner`, and the
/// signature must verify over `signing_hash`, which covers every field.
fn decode_owned_policy(
    hex_str: &str,
    field: &str,
    sigs_hex: &Option<String>,
    keys_hex: &Option<String>,
) -> Result<srct_core::agent::SpendPolicy, (StatusCode, Json<ErrorBody>)> {
    let bytes = decode_hex_bytes(hex_str, field)?;
    let policy = srct_core::agent::SpendPolicy::deserialize(&bytes)
        .map_err(|e| bad(format!("{field}: {e}")))?;
    let (sigs_hex, keys_hex) = match (sigs_hex, keys_hex) {
        (Some(s), Some(k)) => (s, k),
        _ => {
            return Err(bad(format!(
                "{field} must carry the owner's signature over its signing hash"
            )))
        }
    };
    let sigs = decode_bundle(sigs_hex, "policy_sigs")?;
    let keys = decode_bundle(keys_hex, "policy_keys")?;
    let signing_key = keys
        .address()
        .map_err(|e| bad(format!("policy_keys: {e}")))?;
    if signing_key != policy.owner {
        return Err(bad(format!(
            "{field}: the signing key is not the policy's owner"
        )));
    }
    srct_core::sig::verify_bundle(&sigs, &keys, &policy.signing_hash())
        .map_err(|e| bad(format!("{field}: {e}")))?;
    Ok(policy)
}

async fn authorize(State(state): State<ApiState>, Json(req): Json<AuthorizeReq>) -> ApiResult {
    let policy = decode_owned_policy(
        &req.policy_hex,
        "policy",
        &req.policy_sigs_hex,
        &req.policy_keys_hex,
    )?;
    let request_bytes = decode_hex_bytes(&req.request_hex, "request")?;
    let request = srct_core::service::PaymentRequest::deserialize(&request_bytes)
        .map_err(|e| bad(format!("request: {e}")))?;
    // A delegated policy is authorized with, and only with, its ancestry: the
    // bytes that prove which root's authority it narrows.
    let chain = decode_chain(&req.chain_hex, "chain")?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let auth = authorize_request_with_chain(
            &mut sh.policies,
            &mut sh.delegations,
            &policy,
            &chain,
            &network,
            &request,
            height,
            req.nonce,
        )
        .map_err(session_err)?;
        // Remember the policy under the hash the authorization carries, so
        // admission later can check the payment names a policy this engine
        // actually issued under. Idempotent: the same bytes hash the same.
        sh.policy_registry.insert(auth.policy_hash, policy.clone());
        audit_push(
            sh,
            "authorize",
            None,
            Some(auth.amount_sat),
            format!(
                "grant {} nonce {}",
                hash_to_hex(&auth.policy_hash),
                auth.nonce
            ),
        );
        // Unsigned: the *owner* signs `signing_hash` with their wallet. The
        // API never signs and never sees a key.
        Ok(Json(json!({
            "authorization_hex": hex::encode(auth.serialize()),
            "signing_hash": hash_to_hex(&auth.signing_hash()),
            "policy_hash": hash_to_hex(&auth.policy_hash),
            "agent_id": hex::encode(auth.agent_id),
            "delegation_depth": sh.delegations.depth_of(&policy),
            "amount_sat": auth.amount_sat,
            "nonce": auth.nonce,
            "height": auth.height,
            "note": "sign signing_hash with the policy owner's wallet, then use the payment layer",
        })))
    })?
}

/// `POST /v1/policy/decide` — the engine seam over HTTP: evaluate a payment
/// intent against an owner-signed policy and answer allow, deny, or
/// approval-needed. Read-only: nothing is committed (no nonce consumed, no
/// window spend recorded), so calling it twice decides twice with no side
/// effect. This is the backend the TypeScript/Python bindings speak to —
/// verification runs here, the bindings only codec the JSON.
///
/// The policy arrives either as portable JSON (`policy_portable_json`,
/// parsed *and* verified) or as raw bytes plus the owner's signature
/// (`policy_hex` + `policy_sigs_hex` + `policy_keys_hex`, verified the same
/// way `/v1/authorize` verifies). The frame is the node's own: its network
/// id and its height. A policy for another network is refused by name.
/// Node admission additionally applies `RiskPolicy` (velocity, test mode,
/// mainnet approval default) — this route answers the policy engine only.
#[derive(Deserialize)]
struct PolicyDecideReq {
    policy_portable_json: Option<String>,
    policy_hex: Option<String>,
    policy_sigs_hex: Option<String>,
    policy_keys_hex: Option<String>,
    agent_id_hex: String,
    recipient_hex: String,
    amount_sat: u64,
    service_hex: Option<String>,
    approval_threshold_sat: Option<u64>,
}

async fn policy_decide(
    State(state): State<ApiState>,
    Json(req): Json<PolicyDecideReq>,
) -> ApiResult {
    let signed = match req.policy_portable_json {
        Some(raw) => {
            if raw.len() > srct_core::portable::MAX_PORTABLE_JSON_LEN {
                return Err(bad("policy_portable_json over cap"));
            }
            srct_core::portable::SignedPolicy::from_json(&raw)
                .map_err(|e| bad(format!("policy: {e}")))?
        }
        None => {
            let (hex_str, sigs_hex, keys_hex) = match (
                &req.policy_hex,
                &req.policy_sigs_hex,
                &req.policy_keys_hex,
            ) {
                (Some(h), Some(s), Some(k)) => (h, s, k),
                _ => return Err(bad(
                    "supply policy_portable_json or policy_hex + policy_sigs_hex + policy_keys_hex",
                )),
            };
            let policy = decode_owned_policy(
                hex_str,
                "policy",
                &Some(sigs_hex.clone()),
                &Some(keys_hex.clone()),
            )?;
            let sigs = decode_bundle(sigs_hex, "policy_sigs")?;
            let keys = decode_bundle(keys_hex, "policy_keys")?;
            srct_core::portable::SignedPolicy { policy, sigs, keys }
        }
    };
    // Both input shapes verified on the way in; re-check anyway — decide
    // must never answer from an unverified grant.
    signed.verify().map_err(|e| bad(format!("policy: {e}")))?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        // A query answers; only malformed input is an error. A deny is a
        // 200 with the reason — the query was answered, and the answer is
        // no; a "no" is never mistaken for a transport failure. The network
        // binding lives in the engine, not here.
        let intent = srct_core::portable::PaymentIntent {
            agent_id: req.agent_id_hex,
            recipient: req.recipient_hex,
            amount_sat: req.amount_sat,
            service: req.service_hex,
            height,
            nonce: 0,
            network_id: network.clone(),
        };
        let decoded = intent.decoded().map_err(|e| bad(format!("intent: {e}")))?;
        let (decision, reason) = match srct_core::portable::evaluate_policy(
            &signed.policy,
            &decoded,
            &network,
            height,
            req.approval_threshold_sat,
        ) {
            srct_core::portable::PolicyDecision::Allow => ("allow", None),
            srct_core::portable::PolicyDecision::NeedsApproval { reason } => {
                ("needs_approval", Some(reason))
            }
            srct_core::portable::PolicyDecision::Deny { reason } => ("deny", Some(reason)),
        };
        Ok(Json(json!({
            "decision": decision,
            "reason": reason,
            "network_id": network,
            "height": height,
        })))
    })?
}

/// `POST /v1/delegation/verify` — verify a delegation proof from any rail.
/// Read-only: an ancestry that parses but does not verify is refused, never
/// acted on. This is the HTTP backend for the bindings' `verifyProof`.
#[derive(Deserialize)]
struct DelegationVerifyReq {
    proof_json: String,
}

async fn delegation_verify(
    State(_state): State<ApiState>,
    Json(req): Json<DelegationVerifyReq>,
) -> ApiResult {
    if req.proof_json.len() > srct_core::portable::MAX_PORTABLE_JSON_LEN {
        return Err(bad("proof_json over cap"));
    }
    let proof = srct_core::portable::DelegationProof::from_json(&req.proof_json)
        .map_err(|e| bad(format!("proof: {e}")))?;
    Ok(Json(json!({
        "valid": true,
        "depth": proof.links.len(),
        "root_owner": srct_core::hash::address_to_hex(proof.root_owner()),
        "leaf_agent": hex::encode(proof.leaf().agent_id),
        "leaf_policy_hash": srct_core::hash::hash_to_hex(&proof.leaf().hash()),
    })))
}

/// `POST /v1/audit/verify` — verify an exported audit chain from any rail.
/// Read-only: links, entry hashes, order and tip are re-checked, and the
/// entry count is returned. This is the HTTP backend for the bindings'
/// `verifyAudit`.
#[derive(Deserialize)]
struct AuditVerifyReq {
    audit_json: String,
}

async fn audit_verify_route(
    State(_state): State<ApiState>,
    Json(req): Json<AuditVerifyReq>,
) -> ApiResult {
    let count = srct_core::safety::AuditLog::verify_export_json(&req.audit_json)
        .map_err(|e| bad(format!("audit: {e}")))?;
    Ok(Json(json!({ "valid": true, "entries": count })))
}

/// Decode a presented delegation chain, oldest first. An empty list is a root
/// spend; a non-empty one must be a chain, and it is validated against the
/// narrowing rule before the caller uses it.
fn decode_chain(
    items: &Option<Vec<String>>,
    field: &str,
) -> Result<Vec<srct_core::agent::SpendPolicy>, (StatusCode, Json<ErrorBody>)> {
    let Some(items) = items else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(items.len());
    for (i, hex_str) in items.iter().enumerate() {
        let bytes = decode_hex_bytes(hex_str, field)?;
        let policy = srct_core::agent::SpendPolicy::deserialize(&bytes)
            .map_err(|e| bad(format!("{field}[{i}]: {e}")))?;
        out.push(policy);
    }
    if out.len() > srct_core::delegation::MAX_DELEGATION_DEPTH {
        return Err(bad(format!(
            "{field} is {} policies deep, over the cap of {}",
            out.len(),
            srct_core::delegation::MAX_DELEGATION_DEPTH
        )));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct DelegationLinkReq {
    /// The parent policy bytes: the delegator whose authority is being narrowed.
    parent_policy_hex: String,
    /// The child policy bytes: the delegate, already dominated by `parent`.
    child_policy_hex: String,
    /// Owner signatures over each policy, in the same order: parent first.
    parent_sigs_hex: Option<String>,
    parent_keys_hex: Option<String>,
    child_sigs_hex: Option<String>,
    child_keys_hex: Option<String>,
}

/// `POST /v1/delegation/link` — register a parent→child delegation link through
/// the node's lineage authority.
///
/// Delegation is a policy-layer narrowing (SPEC §18.2.1), not a consensus rule,
/// but the engine that issued the policies is the only party that may attest to
/// a lineage. Registering here is optional for admission — a chain is still
/// validated by `delegation::assert_chain` wherever it is presented — and the
/// link book is node-local so a refusal never changes a block's validity.
async fn delegation_link(
    State(state): State<ApiState>,
    Json(req): Json<DelegationLinkReq>,
) -> ApiResult {
    let parent = decode_owned_policy(
        &req.parent_policy_hex,
        "parent_policy",
        &req.parent_sigs_hex,
        &req.parent_keys_hex,
    )?;
    let child = decode_owned_policy(
        &req.child_policy_hex,
        "child_policy",
        &req.child_sigs_hex,
        &req.child_keys_hex,
    )?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        // Lineage only makes sense within one network; a cross-network link is
        // refused by `dominates` as `NetworkMismatch`, which is the right error.
        if parent.network_id != network || child.network_id != network {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "delegation_refused",
                "delegation must be scoped to this node's network",
            ));
        }
        match sh.delegations.link(&parent, &child) {
            Ok(()) => {
                // Let admission resolve the child as a known policy, the same way
                // `/v1/authorize` records a granted policy under its hash.
                sh.policy_registry.insert(child.hash(), child.clone());
                Ok(Json(json!({
                    "linked": true,
                    "child_policy_hash": hash_to_hex(&child.hash()),
                    "depth": sh.delegations.depth_of(&child),
                })))
            }
            Err(e) => Err(fail(
                StatusCode::CONFLICT,
                "delegation_refused",
                e.to_string(),
            )),
        }
    })?
}

fn session_err(e: SessionError) -> (StatusCode, Json<ErrorBody>) {
    // Refusals by the policy engine are conflicts (the policy said no);
    // malformed material is a client error. Both are non-2xx; the detail
    // names the exact clause.
    match &e {
        SessionError::Policy(_) => fail(StatusCode::CONFLICT, "policy_refused", e.to_string()),
        SessionError::Binding(_) => fail(StatusCode::CONFLICT, "session_binding", e.to_string()),
        _ => bad(e.to_string()),
    }
}

/// Append one audit entry; a full ring never fails the payment it records —
/// the full history lives in the payment/receipt stores, the ring is the
/// tamper-evident index over them.
fn audit_push(
    sh: &mut SharedNode,
    kind: &'static str,
    payment_id: Option<Hash>,
    amount_sat: Option<u64>,
    detail: String,
) {
    let _ = sh.audit.push(kind, payment_id, amount_sat, detail);
}

/// Addresses allowed to approve high-value payments, from
/// `SRCT_HIGH_VALUE_APPROVERS` (comma-separated hex, `0x` optional). Empty —
/// the default — means nobody can approve, so any payment at or above the
/// high-value threshold is refused outright rather than admitted on a flag.
fn high_value_approvers() -> Vec<srct_core::hash::Address> {
    std::env::var("SRCT_HIGH_VALUE_APPROVERS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| {
            let s = s.trim().trim_start_matches("0x");
            hex::decode(s).ok().and_then(|b| b.try_into().ok())
        })
        .collect()
}

/// Enforce the human-approval gate: a payment that tripped the threshold is
/// refused unless it carries a signature over its signing hash from a
/// configured approver. The advisory flag alone used to admit the payment —
/// now the signature is the admission.
fn require_high_value_approval(
    payment: &MachinePayment,
    id: Hash,
    approval: Option<(&srct_core::sig::Bundle, &srct_core::sig::Bundle)>,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let approvers = high_value_approvers();
    let (sigs, keys) = approval.ok_or_else(|| {
        fail(
            StatusCode::FORBIDDEN,
            "human_approval_required",
            format!(
                "this payment is at or above the high-value threshold and no approval was supplied: \
                 have a key listed in SRCT_HIGH_VALUE_APPROVERS ({} configured) sign the payment id {}",
                approvers.len(),
                hash_to_hex(&id),
            ),
        )
    })?;
    let signer = keys
        .address()
        .map_err(|e| bad(format!("approval_keys: {e}")))?;
    if !approvers.contains(&signer) {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "human_approval_required",
            "the approval is signed by a key this node does not list as an approver",
        ));
    }
    srct_core::sig::verify_bundle(sigs, keys, &id).map_err(|_| {
        fail(
            StatusCode::FORBIDDEN,
            "human_approval_required",
            "the human-approval signature does not verify against this payment",
        )
    })?;
    if signer == payment.payer {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "human_approval_required",
            "the approver must be a second key, not the payer itself",
        ));
    }
    Ok(())
}

/// Wallet-safety pre-admission gates shared by `payment_submit` and the x402
/// settle path: test-mode mainnet refusal + per-payer velocity cap. Returns
/// the human-approval advisory. No state change on any path.
fn risk_gate(
    sh: &mut SharedNode,
    payment: &MachinePayment,
    network: &str,
    id: Hash,
) -> Result<bool, (StatusCode, Json<ErrorBody>)> {
    // Network-aware: the operator's env wins, but a missing threshold still
    // gates mainnet (Decision 31) — the drain playbook must not depend on an
    // env var somebody forgot.
    let risk = srct_core::safety::RiskPolicy::from_env_for_network(network);
    let recent = sh
        .payment_store
        .values()
        .filter(|p| p.payer == payment.payer)
        .count();
    match risk.check(network, payment.amount_sat, recent) {
        Ok(v) => Ok(v == srct_core::safety::RiskVerdict::RequireHumanApproval),
        Err(e) => {
            use srct_core::safety::SafetyError as SE;
            let (status, error) = match &e {
                SE::MainnetBlockedInTestMode => (StatusCode::CONFLICT, "test_mode"),
                SE::VelocityLimited { .. } => (StatusCode::CONFLICT, "velocity_limited"),
                _ => (StatusCode::BAD_REQUEST, "risk_refused"),
            };
            audit_push(
                sh,
                "payment_risk_refused",
                Some(id),
                Some(payment.amount_sat),
                e.to_string(),
            );
            Err(fail(status, error, e.to_string()))
        }
    }
}

/// Session-budget gate shared by both admission paths. Runs after credit
/// admission so a refusal can release the reservation it just took. Off by
/// default (cap 0).
fn session_gate(
    sh: &mut SharedNode,
    payment: &MachinePayment,
    height: u64,
    id: Hash,
    reservation: &srct_core::credit::Reservation,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let (session_window, session_cap) = session_envelope();
    if session_cap == 0 {
        return Ok(());
    }
    if let Err(e) = sh.sessions.record(
        &payment.agent_id,
        height,
        payment.amount_sat,
        session_window.max(1),
        session_cap,
    ) {
        let _ = sh.credit.release(reservation);
        audit_push(
            sh,
            "payment_session_refused",
            Some(id),
            Some(payment.amount_sat),
            e.to_string(),
        );
        return Err(fail(StatusCode::CONFLICT, "session_budget", e.to_string()));
    }
    Ok(())
}

/// Session-budget envelope from the environment: window and cap, both zero
/// (the default) meaning the session gate is off and only policy windows apply.
fn session_envelope() -> (u64, u64) {
    let window = std::env::var("SRCT_SESSION_WINDOW_BLOCKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cap = std::env::var("SRCT_SESSION_CAP_SAT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    (window, cap)
}

#[derive(Deserialize)]
struct PaymentSubmitReq {
    payment_hex: String,
    /// Canonical `Authorization` encoding the payment claims to be spending
    /// under. Required: a machine payment without its grant is not admitted.
    authorization_hex: String,
    /// The owner's signature over the authorization's signing hash, and the
    /// public key bundle it verifies against.
    auth_sigs_hex: String,
    auth_keys_hex: String,
    /// Human approval over the payment's signing hash, by a key listed in
    /// `SRCT_HIGH_VALUE_APPROVERS`. Required only when the payment trips the
    /// high-value threshold (`SRCT_HIGH_VALUE_THRESHOLD_SAT`); absent
    /// otherwise.
    approval_sigs_hex: Option<String>,
    approval_keys_hex: Option<String>,
}

/// Decode a signature/key bundle from its canonical bytes.
fn decode_bundle(
    hex_str: &str,
    what: &str,
) -> Result<srct_core::sig::Bundle, (StatusCode, Json<ErrorBody>)> {
    let bytes = decode_hex_bytes(hex_str, what)?;
    let mut r = srct_core::ser::Reader::new(&bytes);
    srct_core::sig::Bundle::from_reader(&mut r).map_err(|e| bad(format!("{what}: {e}")))
}

/// Revoke a policy this node has issued under.
///
/// The statement is the owner's: the same policy with `revoked` set, signed by
/// the owner. The node maps it back to the hash it actually authorized by
/// clearing the flag — only possible because the encoding is known — and records
/// that hash as revoked. Nothing else may revoke: a revocation signed by anyone
/// else is a griefing vector, not a kill switch.
#[derive(Deserialize)]
struct PolicyRevokeReq {
    policy_hex: String,
    sigs_hex: String,
    keys_hex: String,
}

async fn policy_revoke(
    State(state): State<ApiState>,
    Json(req): Json<PolicyRevokeReq>,
) -> ApiResult {
    let bytes = decode_hex_bytes(&req.policy_hex, "policy")?;
    let variant = srct_core::agent::SpendPolicy::deserialize(&bytes)
        .map_err(|e| bad(format!("policy: {e}")))?;
    let sigs = decode_bundle(&req.sigs_hex, "sigs")?;
    let keys = decode_bundle(&req.keys_hex, "keys")?;
    with_shared(&state, |sh| {
        // The statement must be the owner's, over exactly these bytes.
        let owner = keys.address().map_err(|e| bad(format!("keys: {e}")))?;
        if owner != variant.owner {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "policy_revoked",
                "the revocation is signed by someone other than the policy owner",
            ));
        }
        srct_core::sig::verify_bundle(&sigs, &keys, &variant.signing_hash())
            .map_err(|e| bad(format!("revocation signature: {e}")))?;
        // Map back to the hash the engine issued under.
        let mut original = variant.clone();
        original.revoked = false;
        if !sh.policy_registry.contains_key(&original.hash()) {
            return Err(fail(
                StatusCode::CONFLICT,
                "policy_refused",
                "this node never issued under the policy being revoked",
            ));
        }
        let was_new = sh.revoked_policies.insert(original.hash());
        // Revocation propagates down the recorded lineage: a kill switch on an
        // ancestor that left its descendants live would not be a kill switch at
        // all. The book's own edges decide who is downstream, so a node cannot
        // be asked to revoke a link it never recorded.
        let descendants: Vec<[u8; 32]> = sh
            .delegations
            .descendants_of(&original.hash())
            .into_iter()
            .collect();
        let mut propagated = 0usize;
        for hash in descendants {
            if sh.revoked_policies.insert(hash) {
                propagated += 1;
            }
        }
        Ok(Json(json!({
            "policy_hash": hash_to_hex(&original.hash()),
            "revoked": was_new,
            "descendants_revoked": propagated,
        })))
    })?
}

async fn payment_submit(
    State(state): State<ApiState>,
    Json(req): Json<PaymentSubmitReq>,
) -> ApiResult {
    let bytes = decode_hex_bytes(&req.payment_hex, "payment")?;
    let payment = MachinePayment::deserialize(&bytes).map_err(|e| bad(format!("payment: {e}")))?;
    let auth_bytes = decode_hex_bytes(&req.authorization_hex, "authorization")?;
    let authorization = srct_core::agent::Authorization::deserialize(&auth_bytes)
        .map_err(|e| bad(format!("authorization: {e}")))?;
    let auth_sigs = decode_bundle(&req.auth_sigs_hex, "auth_sigs")?;
    let auth_keys = decode_bundle(&req.auth_keys_hex, "auth_keys")?;
    // Decoded only when present: most payments are below the threshold and
    // must not pay a parse cost — or a parse failure — for a field they do
    // not need.
    let approval_sigs = req
        .approval_sigs_hex
        .as_deref()
        .map(|s| decode_bundle(s, "approval_sigs"))
        .transpose()?;
    let approval_keys = req
        .approval_keys_hex
        .as_deref()
        .map(|s| decode_bundle(s, "approval_keys"))
        .transpose()?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let id = payment.signing_hash();
        // Stream-bound payments move the coin the voucher accounting already
        // advanced: when the reference names a stream open on this node, the
        // recipient must be that stream's recipient. Without this the
        // accounting could advance (via a separate settle call) while the
        // coin went somewhere else entirely. A reference that names no open
        // stream is an ordinary request id and is left alone.
        if let Some(stream) = sh.stream_store.get(&payment.reference) {
            if payment.recipient != stream.recipient {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "stream_recipient_mismatch",
                    "a stream-bound payment must pay the stream's recipient",
                ));
            }
        }
        // A revoked policy admits nothing further, whatever else is in order —
        // and that includes a policy whose *ancestor* was revoked, which is why
        // the whole chain is checked rather than the hash the payment names.
        let mut revoked_in_chain = sh.revoked_policies.contains(&payment.policy_hash);
        for ancestor in &payment.chain {
            if sh.revoked_policies.contains(&ancestor.hash()) {
                revoked_in_chain = true;
            }
        }
        if revoked_in_chain {
            return Err(fail(
                StatusCode::CONFLICT,
                "policy_revoked",
                "the policy this payment names, or an ancestor of it, has been revoked by its owner",
            ));
        }
        // A delegated spend must be under a lineage this node recorded. The
        // chain bytes are signed, which proves they narrow; recording proves the
        // links are the ones this node accepted, so an unrecorded ancestor is
        // not authority the node can vouch for.
        if !payment.chain.is_empty() {
            // invariant: `last()` on a non-empty slice always succeeds; the
            // guard above is what makes this total rather than hopeful.
            let recorded = sh.delegations.chain_of(payment.chain.last().unwrap());
            let provable = recorded.as_ref().map(|chain| {
                chain.len() == payment.chain.len()
                    && chain
                        .iter()
                        .zip(payment.chain.iter())
                        .all(|(a, b)| a.hash() == b.hash())
            });
            if provable != Some(true) {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "payment_refused",
                    "the delegation chain this payment names is not a lineage this node recorded",
                ));
            }
        }
        // An exact re-submission is idempotent, and it is answered *before*
        // admission: a second admission would reserve the same value twice, and
        // the second reservation would be refused for a payment that is already
        // recorded. Replay is not a refusal; it is a repeat of the first answer.
        if sh.payment_tracker.contains(&id) {
            audit_push(
                sh,
                "payment_duplicate",
                Some(id),
                Some(payment.amount_sat),
                format!("replay of {}", hash_to_hex(&id)),
            );
            return Ok(Json(json!({
                "payment_id": hash_to_hex(&id),
                "duplicate": true,
            })));
        }
        // Wallet-safety gates (no state change): test mode refuses mainnet,
        // velocity caps bursts per payer. Both are operator-configured and
        // off by default, so existing flows are unaffected.
        let requires_human_approval = risk_gate(sh, &payment, &network, id)?;
        // The advisory used to be the end of it: the payment was admitted
        // and the response merely noted a human should have looked. Now the
        // threshold is a refusal until a configured approver co-signs — the
        // signature is checked before admission, the payer's own key does
        // not count, and nothing about this path changes while the
        // threshold is 0 (disabled).
        if requires_human_approval {
            require_high_value_approval(
                &payment,
                id,
                approval_sigs.as_ref().zip(approval_keys.as_ref()),
            )?;
            audit_push(
                sh,
                "payment_approved",
                Some(id),
                Some(payment.amount_sat),
                format!("human-approved {}", hash_to_hex(&id)),
            );
        }
        // Admission first: the payment must be what an authentic, live policy
        // granted. A payment that names a policy this node never authorized
        // under — or one that has since expired, or one whose authorization is
        // not signed by the owner — is refused before it touches the replay
        // tracker and before any credit is encumbered.
        let policy = match sh.policy_registry.get(&payment.policy_hash).cloned() {
            Some(policy) => policy,
            None => {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "payment_refused",
                    "the policy this payment names was never authorized under on this node",
                ));
            }
        };
        payment
            .verify(&network, height)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "payment_refused", e.to_string()))?;
        let presented = srct_core::service::AuthPresentation {
            auth: &authorization,
            sigs: &auth_sigs,
            keys: &auth_keys,
        };
        let reservation = srct_core::service::admit_payment(
            &sh.policies,
            &policy,
            &payment,
            presented,
            &network,
            height,
            &mut sh.credit,
        )
        .map_err(session_err)?;
        // A reservation that draws on position headroom can never settle: the
        // ledger `settle` refuses it by name (headroom is capacity, not value —
        // its debit is a position-lifecycle event), and this node exposes no
        // release for an admitted payment. Admitting it would lock the payer's
        // swept free balance and headroom forever with no recourse, so fail
        // fast here and give the encumbrance straight back.
        if !reservation.position_draws.is_empty() {
            let _ = sh.credit.release(&reservation);
            return Err(fail(
                StatusCode::CONFLICT,
                "payment_refused",
                "the payer's free balance cannot cover this payment and the \
                 remainder would draw on position headroom, which never settles \
                 through a receipt: fund the free balance or repay the position first",
            ));
        }
        // Session budget: the per-agent aggregate across rotated policies.
        // Runs after admission so a refusal can release the reservation it
        // just took; off by default (cap 0), so only operators who set
        // SRCT_SESSION_CAP_SAT/SRCT_SESSION_WINDOW_BLOCKS are affected.
        session_gate(sh, &payment, height, id, &reservation)?;
        match sh.payment_tracker.accept(&payment, &network, height) {
            Ok(id) => {
                // The payment is recorded, so the reservation it holds is real:
                // it stays until the receipt settles it (§19.4), or until it is
                // released because the payment never committed.
                sh.payment_store.insert(id, payment);
                sh.reservations.insert(id, reservation);
                audit_push(
                    sh,
                    "payment_admitted",
                    Some(id),
                    Some(sh.payment_store.get(&id).map(|p| p.amount_sat).unwrap_or(0)),
                    format!("admitted requires_human_approval={requires_human_approval}"),
                );
                Ok(Json(json!({
                    "payment_id": hash_to_hex(&id),
                    "duplicate": false,
                    "requires_human_approval": requires_human_approval,
                })))
            }
            // Same bytes, same id: an idempotent re-submission, not an error.
            Err(srct_core::payment::PaymentError::AlreadySeen) => {
                let _ = sh.credit.release(&reservation);
                Ok(Json(
                    json!({ "payment_id": hash_to_hex(&id), "duplicate": true }),
                ))
            }
            Err(e) => {
                // The payment was not recorded, so the value it encumbered goes
                // straight back: a reservation for a payment nobody accepted is
                // a hold on the payer's line for nothing.
                let _ = sh.credit.release(&reservation);
                Err(fail(
                    StatusCode::BAD_REQUEST,
                    "payment_refused",
                    e.to_string(),
                ))
            }
        }
    })?
}

#[derive(Deserialize)]
struct ReceiptSubmitReq {
    receipt_hex: String,
}

async fn receipt_submit(
    State(state): State<ApiState>,
    Json(req): Json<ReceiptSubmitReq>,
) -> ApiResult {
    let bytes = decode_hex_bytes(&req.receipt_hex, "receipt")?;
    let receipt = srct_core::receipt::ServiceReceipt::deserialize(&bytes)
        .map_err(|e| bad(format!("receipt: {e}")))?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        // Validate and bind before anything is recorded or debited. A receipt
        // that cannot be bound to a recorded payment must not reach the book,
        // because the book is what makes a conflicting receipt impossible.
        receipt
            .verify(&network)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "receipt_refused", e.to_string()))?;
        // Orphan receipts are refused, not filed: a receipt naming an
        // unrecorded payment debited nothing, and accepting it would put
        // proof of a payment that never happened into the book.
        let payment = sh.payment_store.get(&receipt.payment_id).ok_or_else(|| {
            fail(
                StatusCode::NOT_FOUND,
                "unknown_payment",
                "no recorded payment for this receipt",
            )
        })?;
        receipt
            .verify_binding(payment)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "receipt_refused", e.to_string()))?;
        // A re-submitted receipt is idempotent, and it is answered before any
        // debit: the second call must not debit again. A *contradicting* receipt
        // for the same payment is not a replay, it is a second claim, and the
        // book refuses it — so the two are distinguished by id, not by order.
        if sh.receipts.by_receipt_id(&receipt.receipt_id()).is_some() {
            return Ok(Json(json!({
                "receipt_id": hash_to_hex(&receipt.receipt_id()),
                "outcome": "duplicate",
            })));
        }
        if let Some(existing) = sh.receipts.by_payment_id(&receipt.payment_id) {
            let existing = existing.receipt_id();
            return Err(fail(
                StatusCode::CONFLICT,
                "receipt_conflict",
                format!(
                    "another receipt {} already claims this payment",
                    hash_to_hex(&existing)
                ),
            ));
        }
        // Settlement event (roadmap item 10 / §19.4): the admission-time
        // reservation commits as a real debit against the payer's credit line.
        // The reservation is taken out of the map *before* the receipt is
        // accepted, so a debit that fails leaves nothing half-applied and the
        // reservation is still available for the retry.
        if let Some(reservation) = sh.reservations.remove(&receipt.payment_id) {
            if let Err(e) = sh.credit.settle(&reservation) {
                sh.reservations.insert(receipt.payment_id, reservation);
                return Err(fail(
                    StatusCode::CONFLICT,
                    "credit_settle_failed",
                    format!(
                        "receipt {} refused: credit settlement failed: {e}",
                        hash_to_hex(&receipt.receipt_id())
                    ),
                ));
            }
        }
        match sh.receipts.accept(&receipt, &network) {
            Ok(outcome) => {
                audit_push(
                    sh,
                    "receipt_settled",
                    Some(receipt.payment_id),
                    Some(receipt.amount_sat),
                    format!("receipt {}", hash_to_hex(&receipt.receipt_id())),
                );
                Ok(Json(json!({
                    "receipt_id": hash_to_hex(&receipt.receipt_id()),
                    "outcome": match outcome {
                        ReceiptOutcome::Inserted => "inserted",
                        ReceiptOutcome::Duplicate => "duplicate",
                    },
                })))
            }
            Err(srct_core::receipt::ReceiptError::PaymentConflict { existing }) => Err(fail(
                StatusCode::CONFLICT,
                "receipt_conflict",
                format!(
                    "another receipt {} already claims this payment",
                    hash_to_hex(&existing)
                ),
            )),
            Err(e) => Err(fail(
                StatusCode::BAD_REQUEST,
                "receipt_refused",
                e.to_string(),
            )),
        }
    })?
}

/// `GET /v1/exit/crankable?claimant=<address>` — the exit claims this node could
/// settle right now, as encoded bytes ready to drop into a block.
///
/// The crank is permissionless by design (SPEC.md §19.6): consensus pays only
/// the destination the proven L2 record names, and the exit fee was prepaid by
/// the owner at queue time, so nothing depends on who builds the block. Until
/// now the only way to obtain a claim was to be the node's own miner. This route
/// hands them out, so a third party can build a block with them too.
///
/// Read-only and secret-free: a claim is authorised by an inclusion proof
/// against the committed L2 root, never by a signature, so returning one grants
/// no power it does not already have. `claimant` is where the prepaid fee goes
/// and is *not* trusted for anything else.
///
/// Returns 200 with `crankable` (possibly empty) and `queued`, the number of
/// exits still awaiting release, because an empty list with exits pending is
/// the exact-funding case the node cannot help (see `NodeL2::crank_claims`).
async fn exit_crankable(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let Some(raw) = query.get("claimant") else {
        return Err(bad("claimant address is required (?claimant=<address>)"));
    };
    let claimant = decode_address(raw)?;
    with_shared(&state, |sh| {
        if !sh.chain.exit_active_at(sh.chain.height() + 1) {
            return Err(fail(
                StatusCode::CONFLICT,
                "exits_inactive",
                "this profile has no exit activation height, so no exit can be claimed \
                 (exit_activation_height = 0 means never)",
            ));
        }
        let crankable: Vec<Value> = sh
            .l2
            .crank_claims(&sh.chain, claimant)
            .iter()
            .map(|claim| {
                json!({
                    "encoding": "hex",
                    "bytes": hex::encode(claim.serialize()),
                    "claim_id": hash512_to_hex(&claim.claim_id()),
                    "owner": address_to_hex(&claim.owner),
                    "nonce": claim.nonce,
                    "amount_sat": claim.amount_sat,
                    "destination": address_to_hex(&claim.destination),
                    "exit_fee_sat": claim.exit_fee_sat,
                    "queued_height": claim.queued_height,
                    "gas_used": claim.gas_used(),
                })
            })
            .collect();
        // Queued but not crankable, with the reason each one waits: an
        // empty crankable list with pending exits used to be silent.
        let pending: Vec<Value> = sh
            .l2
            .crank_pending_reasons(&sh.chain)
            .iter()
            .map(|(owner, nonce, reason)| {
                json!({
                    "owner": address_to_hex(owner),
                    "nonce": nonce,
                    "reason": reason,
                })
            })
            .collect();
        Ok(Json(json!({
            "claimant": address_to_hex(&claimant),
            "crankable": crankable,
            "crankable_count": crankable.len(),
            "queued": sh.l2.pending_exits().len(),
            "pending": pending,
            "unbacked_claims": sh.l2.unbacked_claims().len(),
        })))
    })?
}

// ---------------------------------------------------------------------------
// Credit (roadmap item 2 wiring; non-consensus)
// ---------------------------------------------------------------------------
/// `POST /v1/credit/deposit` — fund an address's credit line.
///
/// Item 2 wiring only: this mints a *credit* balance in `CreditBook`, not an L1
/// coin. It exists so the credit gate can be exercised end-to-end (the book is
/// otherwise empty and every admission would refuse). A production node would
/// gate this behind an L1 deposit proof; in this crate the gate is pure
/// arithmetic and consensus-neutral regardless. The production-shaped gate this
/// node does ship is `POST /v1/credit/mint` — a trusted issuer's signed
/// attestation — and a production operator should route backing through it.
#[derive(Deserialize)]
struct CreditDepositReq {
    address_hex: String,
    amount_sat: u64,
}

async fn credit_deposit(
    State(state): State<ApiState>,
    Json(req): Json<CreditDepositReq>,
) -> ApiResult {
    let addr = decode_address(&req.address_hex)?;
    // Self-serve funding is a loopback-only exercise path: on an exposed
    // bind anyone with the bearer could print node-local credit and spend
    // it through admission. Exposed operators back credit through the
    // issuer-signed `credit/mint` path instead.
    if state.exposed {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "credit_refused",
            "self-serve deposit is disabled on an exposed bind; use issuer-signed credit/mint",
        ));
    }
    // A zero deposit moves nothing but still creates book entries and still
    // costs a request: refused like every other zero-amount credit call, so
    // a flood of them cannot grow the book one empty row at a time.
    if req.amount_sat == 0 {
        return Err(bad(
            "amount_sat must be positive; a zero deposit moves nothing",
        ));
    }
    with_shared(&state, |sh| {
        sh.credit
            .deposit(addr, req.amount_sat)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "credit_refused", e.to_string()))?;
        // Standing auto-repay (opt-in, borrower-signed): earned revenue pays
        // the position down without a second transaction. The deposit is real
        // regardless — if the position settled or the instruction lapsed, the
        // value simply stays free and the node says so.
        let mut autorepay: Option<Value> = None;
        let height = sh.chain.height();
        let network = sh.chain.params().network_id.clone();
        if let Some((instr, sigs, keys)) = sh.standing_repay.get(&addr).cloned() {
            if instr.network_id == network
                && srct_core::lending::verify_standing_repay(&instr, &sigs, &keys, &network, height)
                    .is_ok()
            {
                if let Some(position) = sh.credit.position(&instr.position_id) {
                    let debt_now: Option<u64> = match &position.state {
                        srct_core::credit::PositionState::Drawn {
                            repaid_principal_sat,
                            repaid_interest_sat,
                            ..
                        } => {
                            let interest = position
                                .charge
                                .accrued_interest(
                                    position.amount_sat,
                                    position.drawn_at_height,
                                    height,
                                )
                                .unwrap_or(0);
                            let total = position.amount_sat.saturating_add(interest);
                            let paid = repaid_principal_sat.saturating_add(*repaid_interest_sat);
                            Some(total.saturating_sub(paid))
                        }
                        _ => None,
                    };
                    if let Some(debt) = debt_now {
                        if debt > 0 {
                            let (to_position, _) = srct_core::lending::apply_standing_repay(
                                &instr,
                                req.amount_sat,
                                debt,
                            );
                            if to_position > 0 {
                                match sh.credit.repay(&instr.position_id, to_position, height) {
                                    Ok(result) => {
                                        if let Some((live, _, _)) = sh.standing_repay.get_mut(&addr)
                                        {
                                            live.applied_sat =
                                                live.applied_sat.saturating_add(to_position);
                                        }
                                        audit_push(
                                            sh,
                                            "autorepay",
                                            Some(instr.position_id),
                                            Some(to_position),
                                            format!("standing instruction repaid {to_position}"),
                                        );
                                        autorepay = Some(json!({
                                            "position_id": hash_to_hex(&instr.position_id),
                                            "repaid_sat": to_position,
                                            "remaining_debt_sat": result.remaining_debt_sat,
                                        }));
                                    }
                                    Err(e) => {
                                        audit_push(
                                            sh,
                                            "autorepay_skipped",
                                            Some(instr.position_id),
                                            Some(to_position),
                                            e.to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Json(json!({
            "address": address_to_hex(&addr),
            "balance": sh.credit.free(&addr),
            "autorepay": autorepay,
        })))
    })?
}

/// `POST /v1/credit/mint` — mint credit carrying a trusted issuer's signed
/// attestation: the production gate that `POST /v1/credit/deposit` documents
/// but does not have. Fail-closed three independent ways: a node configured
/// with no issuer keys refuses every mint; an attestation from any other key,
/// for another network, outside its height window, or with a bad signature is
/// refused; and a minted attestation's hash is recorded (persisted, so a
/// restart is not a replay) so one authorization can never mint twice. This
/// credits the local book only — no coin moves.
#[derive(Deserialize)]
struct CreditMintReq {
    network_id: String,
    subject: String,
    amount_sat: u64,
    issue_height: u64,
    expires_height: u64,
    issuer: String,
    sig: String,
}

async fn credit_mint(State(state): State<ApiState>, Json(req): Json<CreditMintReq>) -> ApiResult {
    let issuers = state.credit_issuers.clone();
    if issuers.is_empty() {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "no_credit_issuers",
            "no trusted credit issuer is configured; pass --credit-issuer <48-byte hex>",
        ));
    }
    if req.amount_sat == 0 {
        return Err(bad(
            "amount_sat must be positive; a zero mint moves nothing",
        ));
    }
    let subject = decode_address(&req.subject)?;
    let issuer = decode_public_key(&req.issuer, "issuer")?;
    let sig_raw = decode_hex_bytes(&req.sig, "sig")?;
    let sig: [u8; 96] = sig_raw
        .as_slice()
        .try_into()
        .map_err(|_| bad("sig must be 96 hex bytes"))?;
    let att = srct_core::credit::CreditAttestation {
        network_id: req.network_id,
        subject,
        amount_sat: req.amount_sat,
        issue_height: req.issue_height,
        expires_height: req.expires_height,
        issuer,
        sig: srct_core::bls_checkpoint::BlsSignature(sig),
    };
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        if att.network_id != network {
            return Err(fail(
                StatusCode::CONFLICT,
                "wrong_network",
                format!(
                    "the attestation is for {:?}, this node runs {network:?}",
                    att.network_id
                ),
            ));
        }
        let height = sh.chain.height();
        if height < att.issue_height {
            return Err(fail(
                StatusCode::CONFLICT,
                "attestation_from_the_future",
                format!(
                    "issued at height {}, this node is at {height}",
                    att.issue_height
                ),
            ));
        }
        if height > att.expires_height {
            return Err(fail(
                StatusCode::CONFLICT,
                "attestation_expired",
                format!(
                    "expired at height {}, this node is at {height}",
                    att.expires_height
                ),
            ));
        }
        if !issuers.contains(&att.issuer) {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "untrusted_issuer",
                "the issuer is not one of this node's trusted keys",
            ));
        }
        if !att.verify() {
            return Err(bad("attestation signature does not verify"));
        }
        // Prune first: an entry past its own expiry is unusable anyway (the
        // height check above already refused it), so the map holds exactly
        // the attestations still inside their window.
        sh.attestations_used.retain(|_, expires| *expires >= height);
        let id = att.signing_hash();
        if sh.attestations_used.contains_key(&id) {
            return Err(fail(
                StatusCode::CONFLICT,
                "attestation_reused",
                "this attestation has already minted",
            ));
        }
        sh.credit
            .deposit(att.subject, att.amount_sat)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "credit_refused", e.to_string()))?;
        sh.attestations_used.insert(id, att.expires_height);
        Ok(Json(json!({
            "address": address_to_hex(&att.subject),
            "amount_sat": att.amount_sat,
            "balance": sh.credit.free(&att.subject),
            "attestation_hash": hash_to_hex(&id),
            "height": height,
        })))
    })?
}

/// `GET /v1/credit/balance/{address}` — free balance + bond + live positions.
async fn credit_balance(State(state): State<ApiState>, Path(addr): Path<String>) -> ApiResult {
    let addr = decode_address(&addr)?;
    with_shared(&state, |sh| {
        let free = sh.credit.free(&addr);
        let bond = sh.credit.bond(&addr);
        let reserved = sh.credit.reserved_by(&addr);
        let positions: Vec<_> = sh
            .credit
            .live_positions()
            .filter(|(_, p)| p.borrower == addr)
            .map(|(id, p)| {
                json!({
                    "position_id": hash_to_hex(id),
                    "amount_sat": p.amount_sat,
                    "bond_sat": p.bond_sat,
                    "collateral_sat": p.collateral_sat,
                    "deadline_height": p.deadline_height,
                    "state": match p.state {
                        srct_core::credit::PositionState::Drawn { .. } => "drawn",
                        srct_core::credit::PositionState::Repaid { .. } => "repaid",
                        srct_core::credit::PositionState::Defaulted { .. } => "defaulted",
                    },
                })
            })
            .collect();
        Ok(Json(json!({
            "address": address_to_hex(&addr),
            "free_balance": free,
            "reserved": reserved,
            "available": sh.credit.available(&addr),
            "bond": bond,
            "bond_pledged": bond.saturating_sub(sh.credit.unpledged_bond(&addr)),
            "positions": positions,
        })))
    })?
}

// ---------------------------------------------------------------------------
// Credit position lifecycle (roadmap item 2; non-consensus).
//
// These routes are the operations the payment path only *reads*: posting and
// releasing bonds, opening a position, repaying it, and settling one that
// reached its deadline unpaid. Without them the position machinery has no
// caller outside the core unit tests, and "the full credit lifecycle" is a
// claim about arithmetic nobody can exercise.
// ---------------------------------------------------------------------------

/// `POST /v1/credit/bond` — move free balance into a posted bond.
///
/// A bond is the discount a position is priced with, so it has to be real value
/// the agent already holds. It is not coins: nothing here touches the ledger.
#[derive(Deserialize)]
struct CreditBondReq {
    address_hex: String,
    /// `post` or `release`.
    action: String,
    amount_sat: u64,
}

async fn credit_bond(State(state): State<ApiState>, Json(req): Json<CreditBondReq>) -> ApiResult {
    let addr = decode_address(&req.address_hex)?;
    if req.amount_sat == 0 {
        return Err(bad(
            "amount_sat must be positive; a zero bond moves nothing",
        ));
    }
    with_shared(&state, |sh| {
        match req.action.as_str() {
            "post" => {
                sh.credit
                    .post_bond(addr, req.amount_sat)
                    .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
            }
            "release" => {
                sh.credit
                    .release_bond(addr, req.amount_sat)
                    .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
            }
            other => {
                return Err(bad(format!("unknown bond action: {other}")));
            }
        }
        Ok(Json(json!({
            "address": address_to_hex(&addr),
            "bond": sh.credit.bond(&addr),
            "bond_unpledged": sh.credit.unpledged_bond(&addr),
        })))
    })?
}
/// `POST /v1/credit/open` — open a credit position under a lender's terms.
///
/// The spec is the canonical `PositionSpec` encoding, so the terms a position is
/// priced with are exactly the bytes the caller submitted and cannot drift.
#[derive(Deserialize)]
struct CreditOpenReq {
    spec_hex: String,
}

async fn credit_open(State(state): State<ApiState>, Json(req): Json<CreditOpenReq>) -> ApiResult {
    let bytes = decode_hex_bytes(&req.spec_hex, "spec")?;
    let mut r = srct_core::ser::Reader::new(&bytes);
    let spec =
        srct_core::credit::PositionSpec::decode(&mut r).map_err(|e| bad(format!("spec: {e}")))?;
    if r.remaining() != 0 {
        return Err(bad("spec has trailing bytes"));
    }
    with_shared(&state, |sh| {
        let id = sh
            .credit
            .open(&spec)
            .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
        let position = sh.credit.position(&id);
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "collateral_sat": position.map(|p| p.collateral_sat).unwrap_or(0),
        })))
    })?
}

/// `POST /v1/credit/repay` — repay against a position, interest first.
#[derive(Deserialize)]
struct CreditRepayReq {
    position_id: String,
    amount_sat: u64,
}

async fn credit_repay(State(state): State<ApiState>, Json(req): Json<CreditRepayReq>) -> ApiResult {
    let id = decode_hash(&req.position_id)?;
    if req.amount_sat == 0 {
        return Err(bad(
            "amount_sat must be positive; a zero repayment pays nothing",
        ));
    }
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let repayment = sh
            .credit
            .repay(&id, req.amount_sat, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "interest_paid_sat": repayment.interest_paid_sat,
            "principal_paid_sat": repayment.principal_paid_sat,
            "remaining_debt_sat": repayment.remaining_debt_sat,
        })))
    })?
}

/// `POST /v1/credit/default` — settle an unpaid position at or after its
/// deadline. Collateral first, then the bond, never reputation.
#[derive(Deserialize)]
struct CreditDefaultReq {
    position_id: String,
}

async fn credit_default(
    State(state): State<ApiState>,
    Json(req): Json<CreditDefaultReq>,
) -> ApiResult {
    let id = decode_hash(&req.position_id)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let settlement = sh
            .credit
            .default(&id, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "debt_sat": settlement.debt_sat,
            "from_collateral_sat": settlement.from_collateral_sat,
            "from_bond_sat": settlement.from_bond_sat,
            "shortfall_sat": settlement.shortfall_sat,
            "excess_returned_sat": settlement.excess_returned_sat,
        })))
    })?
}

// ---------------------------------------------------------------------------
// Item 4: conditional escrow with contract-selected arbitrators (non-consensus
// state machine; coin release reuses the normal L1 exit path).
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct EscrowOpenReq {
    network_id: String,
    payer: String,
    /// The payer's BLS public key — bound into the escrow so a mutual release
    /// can only be signed by the actual party, not any key the releaser names.
    payer_bls: String,
    payee: String,
    /// The payee's BLS public key.
    payee_bls: String,
    /// The arbitrator's 48-byte BLS public key, hex. Contract-selected.
    arbitrator: String,
    amount_sat: u64,
    nonce: u64,
}

/// `POST /v1/escrow/open` — open an escrow naming a chosen arbitrator. The node
/// records the state machine only; the locked value still comes from the payer's
/// L1/L2 balance at settlement, not from this call. The chain height rides in so
/// the escrow's refund timeout starts here rather than at some guessed value.
async fn escrow_open(State(state): State<ApiState>, Json(req): Json<EscrowOpenReq>) -> ApiResult {
    let payer = decode_address(&req.payer)?;
    let payee = decode_address(&req.payee)?;
    let payer_key = decode_public_key(&req.payer_bls, "payer_bls")?;
    let payee_key = decode_public_key(&req.payee_bls, "payee_bls")?;
    let arbitrator = decode_public_key(&req.arbitrator, "arbitrator")?;
    let height = with_shared(&state, |sh| sh.chain.height())?;
    let escrow = srct_core::escrow::ConditionalEscrow::open(
        req.network_id.clone(),
        payer,
        payer_key,
        payee,
        payee_key,
        arbitrator,
        req.amount_sat,
        req.nonce,
        height,
    )
    .map_err(|e| fail(StatusCode::BAD_REQUEST, "escrow_refused", e.to_string()))?;
    let id = escrow.id();
    with_shared(&state, |sh| {
        if sh.escrows.contains_key(&id) {
            return Err(fail(
                StatusCode::CONFLICT,
                "escrow_exists",
                "an escrow with this id already exists",
            ));
        }
        sh.escrows.insert(id, escrow);
        Ok(Json(json!({ "escrow_id": hash_to_hex(&id) })))
    })?
}

#[derive(Deserialize)]
struct EscrowSettleReq {
    /// Signed L2 `ExitQueue` transaction whose owner, destination and amount
    /// are exactly this escrow's payer, payee and amount.
    l2_tx_hex: String,
}

/// `POST /v1/escrow/{id}/settle` - bind a released escrow's coin move to a
/// real L2 exit and queue it for the crank (SPEC §20.2 / Item 10). The node
/// verifies the exit *is* this escrow's settlement: owner = payer,
/// destination = payee, amount = the escrow amount, then dry-runs it exactly
/// like any other L2 write. The coin actually moves when consensus releases
/// the exit; only then does `advance_escrow_finality` write `Finalized` for
/// this escrow.
async fn escrow_settle(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<EscrowSettleReq>,
) -> ApiResult {
    // An exit queue is an L2 write: on a breached node it is refused at the
    // same boundary /v1/l2/broadcast draws (Decision 17).
    ensure_funding_allowed(&state, FundingPath::L2Write)?;
    let id = decode_hash(&id)?;
    let bytes = decode_hex_bytes(&req.l2_tx_hex, "l2_tx")?;
    let tx = L2Transaction::deserialize(&bytes).map_err(|e| bad(format!("l2 tx decode: {e}")))?;
    let txid = tx.txid();
    // The payload identity, read once before `tx` is moved into the include queue.
    let (exit_owner, exit_destination, exit_amount, exit_nonce) = match &tx.payload {
        L2Payload::ExitQueue(exit) => (exit.owner, exit.destination, exit.amount_sat, exit.nonce),
        _ => return Err(bad("settlement must carry an ExitQueue transaction")),
    };
    with_shared(&state, |sh| {
        // Dispute hold: no settlement binds while the job is disputed.
        if sh.held_escrows.contains(&id) {
            return Err(fail(
                StatusCode::CONFLICT,
                "escrow_held",
                "this escrow is under dispute; settlement is refused until resolve",
            ));
        }
        let (payer, payee, amount_sat) = {
            let e = sh
                .escrows
                .get(&id)
                .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such escrow"))?;
            if !matches!(
                e.state,
                srct_core::escrow::EscrowState::ReleasedMutual { .. }
                    | srct_core::escrow::EscrowState::ReleasedArbiter { .. }
            ) {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "escrow_not_released",
                    "the coin moves only after a release; this escrow is not released",
                ));
            }
            (e.payer, e.payee, e.amount_sat)
        };
        if let Some(bound) = sh.escrow_exit.get(&id) {
            if bound.txid == txid {
                return Ok(Json(json!({
                    "escrow_id": hash_to_hex(&id),
                    "txid": hash512_to_hex(&txid),
                    "duplicate": true,
                })));
            }
            // A binding to a dead exit is not a settlement: when replay
            // skipped the bound exit (fee race, nonce race) and it is neither
            // released on chain, still queued locally, nor re-submitted in
            // this call, the old binding is stale. Drop it and bind the new
            // exit below, instead of locking the escrow against an exit that
            // will never land.
            let stale = !sh.chain.exit_released(&bound.owner, bound.nonce)
                && !sh
                    .l2
                    .pending_exits()
                    .iter()
                    .any(|w| w.owner == bound.owner && w.nonce == bound.nonce)
                && !sh.l2_to_include.iter().any(|t| t.txid() == bound.txid);
            if !stale {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "escrow_settled",
                    "this escrow's coin move is already bound to another exit",
                ));
            }
            sh.escrow_exit.remove(&id);
        }
        if exit_owner != payer {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "settlement_owner_mismatch",
                "the exit's owner must be the escrow's payer",
            ));
        }
        if exit_destination != payee {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "settlement_destination_mismatch",
                "the exit's destination must be the escrow's payee",
            ));
        }
        if exit_amount != amount_sat {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "settlement_amount_mismatch",
                format!("the exit moves {exit_amount} sat; this escrow is for {amount_sat} sat"),
            ));
        }
        if sh.l2_to_include.iter().any(|t| t.txid() == txid) {
            return Ok(Json(json!({
                "escrow_id": hash_to_hex(&id),
                "txid": hash512_to_hex(&txid),
                "already_queued": true,
            })));
        }
        sh.l2
            .check(&sh.chain, &tx, sh.chain.height() + 1)
            .map_err(|e| fail(StatusCode::CONFLICT, "l2_refused", format!("{e}")))?;
        sh.l2_to_include.push(tx);
        sh.escrow_exit.insert(
            id,
            EscrowExitBinding {
                txid,
                owner: exit_owner,
                nonce: exit_nonce,
            },
        );
        Ok(Json(json!({
            "escrow_id": hash_to_hex(&id),
            "txid": hash512_to_hex(&txid),
            "queued": true,
        })))
    })?
}

/// `GET /v1/escrow/{id}` — escrow state, or 404.
async fn escrow_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        // Refresh finality first (borrows all escrows mutably), then read —
        // done in this order so the GET reflects a matured release as Finalized
        // without a second mutable borrow overlapping the lookup.
        sh.advance_escrow_finality();
        match sh.escrows.get(&id) {
            Some(e) => Ok(Json(json!({
                "escrow_id": hash_to_hex(&id),
                "payer": address_to_hex(&e.payer),
                "payee": address_to_hex(&e.payee),
                "amount_sat": e.amount_sat,
                "condition": match e.condition() {
                    srct_core::escrow::EscrowCondition::ReleaseToPayee => "release_to_payee",
                    srct_core::escrow::EscrowCondition::Oracle { .. } => "oracle",
                },
                "releasable": e.releasable(),
                // What an arbiter signs, and what both parties sign for a
                // mutual release. Published so a relayer can prepare a release
                // without recomputing it, and so the test can check the node is
                // asking for a signature over exactly this escrow.
                "release_hash": hash_to_hex(
                    &e.release_signing_hash(srct_core::escrow::EscrowVerdict::ReleasedToPayee)
                ),
                "state": escrow_state_name(&e.state),
                // The bound coin move, re-resolved against consensus: queued
                // exits report `exit_released: false` until the crank settles
                // one, and only then does this escrow read as `finalized`.
                "settlement": sh
                    .escrow_exit
                    .get(&id)
                    .map(|b| {
                        json!({
                            "txid": hash512_to_hex(&b.txid),
                            "exit_owner": address_to_hex(&b.owner),
                            "exit_nonce": b.nonce,
                            "exit_released": sh.chain.exit_released(&b.owner, b.nonce),
                        })
                    })
                    .unwrap_or(Value::Null),
            }))),
            None => Err(fail(StatusCode::NOT_FOUND, "not_found", "no such escrow")),
        }
    })?
}

fn escrow_state_name(s: &srct_core::escrow::EscrowState) -> &'static str {
    match s {
        srct_core::escrow::EscrowState::Open => "open",
        srct_core::escrow::EscrowState::ReleasedMutual { .. } => "released_mutual",
        srct_core::escrow::EscrowState::ReleasedArbiter { .. } => "released_arbiter",
        srct_core::escrow::EscrowState::Finalized { .. } => "finalized",
        srct_core::escrow::EscrowState::Refunded { .. } => "refunded",
    }
}

#[derive(Deserialize)]
struct EscrowReleaseReq {
    /// One of "arbiter" or "mutual".
    mode: String,
    /// Arbiter release: a single 96-byte BLS signature.
    arbiter_sig_hex: Option<String>,
    /// Mutual release: two 96-byte BLS signatures, in payer-then-payee order.
    mutual_sigs_hex: Option<Vec<String>>,
}

/// `POST /v1/escrow/{id}/release` — release a live escrow. `arbiter` mode
/// requires a signature from the designated arbitrator; `mutual` requires both
/// parties. The released state is recorded but the coin move is deferred to
/// settlement (§19.4) — `POST /v1/escrow/{id}/settle` binds it to the exit.
async fn escrow_release(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<EscrowReleaseReq>,
) -> ApiResult {
    let id = decode_hash(&id)?;
    let sig_to_bls = |h: Option<&String>| {
        let h = h.ok_or_else(|| bad("signature hex required"))?;
        let b = decode_hex_bytes(h, "signature")?;
        let mut s = [0u8; 96];
        if b.len() != 96 {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "escrow_refused",
                "signature must be 96 hex bytes",
            ));
        }
        s.copy_from_slice(&b);
        Ok(srct_core::bls_checkpoint::BlsSignature(s))
    };
    let keys = srct_core::escrow::RealBls;
    with_shared(&state, |sh| {
        // Dispute hold: funds stay locked until the arbitrator resolves.
        if sh.held_escrows.contains(&id) {
            return Err(fail(
                StatusCode::CONFLICT,
                "escrow_held",
                "this escrow is under dispute; release is refused until resolve",
            ));
        }
        let escrow = sh
            .escrows
            .get_mut(&id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such escrow"))?;
        match req.mode.as_str() {
            // The transition belongs to the escrow: this handler checks the shape
            // of what was presented, and the escrow is the only thing that
            // changes its own state.
            "arbiter" => {
                let sig = sig_to_bls(req.arbiter_sig_hex.as_ref())?;
                if !escrow.releasable() {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "escrow_refused",
                        "this escrow is gated on an oracle condition, which has no implemented verifier, so it cannot release",
                    ));
                }
                escrow
                    .release_arbiter(&sig, sh.chain.height(), &keys)
                    .map_err(|e| fail(StatusCode::CONFLICT, "escrow_refused", e.to_string()))?;
                Ok(Json(
                    json!({ "escrow_id": hash_to_hex(&id), "state": "released_arbiter" }),
                ))
            }
            "mutual" => {
                let sigs_hex = req
                    .mutual_sigs_hex
                    .ok_or_else(|| bad("mutual_sigs_hex required"))?;
                if sigs_hex.len() != 2 {
                    return Err(fail(
                        StatusCode::BAD_REQUEST,
                        "escrow_refused",
                        "a mutual release needs exactly two signatures",
                    ));
                }
                let sig_objs: Vec<_> = sigs_hex
                    .iter()
                    .map(|h| sig_to_bls(Some(h)))
                    .collect::<Result<_, _>>()?;
                // Mutual release is verified against the keys the escrow bound
                // at open time; the request only supplies the signatures.
                if !escrow.releasable() {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "escrow_refused",
                        "this escrow is gated on an oracle condition, which has no implemented verifier, so it cannot release",
                    ));
                }
                escrow
                    .release_mutual(
                        &sig_objs,
                        &[escrow.payer_key, escrow.payee_key],
                        sh.chain.height(),
                        &keys,
                    )
                    .map_err(|e| fail(StatusCode::CONFLICT, "escrow_refused", e.to_string()))?;
                Ok(Json(
                    json!({ "escrow_id": hash_to_hex(&id), "state": "released_mutual" }),
                ))
            }
            // Fail closed: an unknown release mode is a refusal, never a default.
            // A handler that guesses which rule to apply releases on the wrong
            // one.
            other => Err(fail(
                StatusCode::BAD_REQUEST,
                "escrow_refused",
                format!("unknown release mode: {other}"),
            )),
        }
    })?
}

// ---------------------------------------------------------------------------
// Server and DoS guards (SPEC.md §19.2: opt-in, loopback by default)
// ---------------------------------------------------------------------------

use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::Response;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Hard ceiling on how long a single request may run before the server drops
/// it. Bounds the hold time on the shared-state `Mutex`, so a flood of slow
/// requests cannot wedge block production.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How many requests the API admits at once. With a current-threaded runtime
/// this is an in-flight cap, not a thread count; it is what stops a flood of
/// long-held requests from exhausting the runtime's readiness to accept new
/// connections.
const MAX_CONCURRENCY: usize = 64;

/// Concurrent connections the API listener holds open. The router's semaphore
/// only counts requests that finished reading their headers, so connections
/// stuck mid-headers (the slowloris shape) need their own bound: over the cap
/// an accept is closed before any bytes are read.
const MAX_API_CONNECTIONS: usize = 128;

/// Time a client gets to finish sending request headers — including the idle
/// gap between keep-alive requests. hyper's default is the same 30s, but only
/// when a timer is installed; `axum::serve` installs none, which leaves the
/// deadline inert and header reading unbounded. The request handler has its
/// own deadline in `REQUEST_TIMEOUT`.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Opt-in service API configuration. Carries the bearer token an exposed bind
/// requires, the bound address plus the hostname allowlist checked by
/// Host-header validation (DNS-rebinding defense), the in-flight request
/// budget for the always-on DoS guard, and the per-IP rate limiter.
#[derive(Clone)]
pub struct ApiConfig {
    /// Bearer token required on every request when this node is exposed.
    pub token: Option<String>,
    /// The host portion of the bound address, for Host-header validation.
    pub bind_host: String,
    /// Whether the bound address is loopback. Decides how strict the Host
    /// check is: a loopback bind accepts loopback names only, while a
    /// non-loopback bind additionally accepts any IP literal.
    bind_loopback: bool,
    /// Lowercased hostnames (no ports) accepted in `Host` on a non-loopback
    /// bind, from `--api-allowed-host` / `SRCT_API_ALLOWED_HOSTS`.
    allowed_hosts: Vec<String>,
    /// In-flight request budget shared across the always-on guard.
    concurrency: Arc<tokio::sync::Semaphore>,
    /// Per-IP token bucket, only consulted on an exposed bind.
    limiter: RateLimiter,
}

impl ApiConfig {
    /// Whether the API is in exposed (authenticated) mode.
    pub fn is_exposed(&self) -> bool {
        self.token.is_some()
    }

    /// Snapshot the DoS guard configuration for `from_fn_with_state`.
    fn dos(&self) -> DosConfig {
        DosConfig {
            timeout: REQUEST_TIMEOUT,
            concurrency: Arc::clone(&self.concurrency),
        }
    }

    /// Snapshot the host-validation configuration for `from_fn_with_state`.
    /// Runs on every bind, loopback included.
    fn host(&self) -> HostConfig {
        HostConfig {
            bind_host: self.bind_host.clone(),
            bind_loopback: self.bind_loopback,
            allowed_hosts: self.allowed_hosts.clone(),
        }
    }

    /// Snapshot the auth/rate-limit configuration for `from_fn_with_state`.
    fn auth(&self) -> AuthConfig {
        AuthConfig {
            token: self.token.clone(),
            limiter: self.limiter.clone(),
        }
    }
}

/// Always-on DoS guard config: a request deadline and a per-node in-flight cap.
/// These protect the shared-state lock even on a loopback bind (§19.2).
#[derive(Clone)]
struct DosConfig {
    timeout: Duration,
    concurrency: Arc<tokio::sync::Semaphore>,
}

/// Host-header validation config, applied on every bind.
#[derive(Clone)]
struct HostConfig {
    bind_host: String,
    bind_loopback: bool,
    allowed_hosts: Vec<String>,
}

/// Split a `Host` header value into its host part: strip one optional
/// `:port`, unwrapping one layer of `[` `]` around IPv6 literals. Returns
/// `None` for a missing, empty, or bracket-malformed value — the caller
/// refuses those rather than guessing at them.
///
/// `None` here can never panic: it is all slicing on `find`/`split` results,
/// so hostile bytes cost a rejection, not the process.
fn host_part(header: &str) -> Option<&str> {
    let header = header.trim();
    if header.is_empty() {
        return None;
    }
    if let Some(rest) = header.strip_prefix('[') {
        let end = rest.find(']')?;
        let tail = &rest[end + 1..];
        // After `]` only `:port` (or nothing) may follow. Anything else —
        // `[::1]evil`, a missing `]` — is malformed.
        if !tail.is_empty()
            && !(tail.starts_with(':') && tail[1..].chars().all(|c| c.is_ascii_digit()))
        {
            return None;
        }
        return Some(&rest[..end]);
    }
    // No brackets: strip one `:port`. A bare multi-colon value (`::1`) is not
    // a valid Host header; treating it whole lets the IP parse decide rather
    // than a guess at where a port starts.
    if header.chars().filter(|&c| c == ':').count() == 1 {
        Some(header.split(':').next().unwrap_or(header))
    } else {
        Some(header)
    }
}

/// Normalize a hostname for the allowlist and for comparison: lowercase,
/// no port, no brackets. `None` for values `host_part` refuses.
fn normalize_host(value: &str) -> Option<String> {
    host_part(value).map(|h| h.to_lowercase())
}

/// Whether a `Host` header value is accepted on this bind.
///
/// - IP literals that parse as loopback are always accepted.
/// - On a loopback bind nothing else is: the threat is a page reaching
///   127.0.0.1 under an attacker's name, so only loopback names pass.
/// - On a non-loopback bind any other IP literal is accepted too — DNS
///   rebinding cannot use an IP literal, so there is nothing to spoof — plus
///   the bound address itself and the operator's allowlisted names.
///   Comparison is case-insensitive; a missing or malformed header is refused.
fn host_allowed(cfg: &HostConfig, header: Option<&str>) -> bool {
    let part = match header.and_then(normalize_host) {
        Some(p) => p,
        None => return false,
    };
    // The one loopback name that is not an IP literal. Allowed on every bind:
    // it can only ever name the local machine.
    if part == "localhost" {
        return true;
    }
    if let Ok(ip) = part.parse::<IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
        return !cfg.bind_loopback;
    }
    part == cfg.bind_host.to_lowercase() || cfg.allowed_hosts.iter().any(|a| a == &part)
}

/// Auth + rate-limit config, only applied on an exposed bind.
#[derive(Clone)]
struct AuthConfig {
    token: Option<String>,
    limiter: RateLimiter,
}

// ---------------------------------------------------------------------------
// Per-IP rate limiting (only active when the API is exposed)
// ---------------------------------------------------------------------------

/// Per-IP token bucket. Refills at `RATE_LIMIT_RATE` tokens/sec up to
/// `RATE_LIMIT_CAPACITY`, so a client that bursts can proceed but a flood is
/// shed to the server rather than through it. Holds only counters keyed by IP.
#[derive(Clone)]
struct RateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, Bucket>>>,
}

#[derive(Debug)]
struct Bucket {
    /// Tokens remaining, scaled by `TOKEN_SCALE` for sub-request resolution.
    tokens: u64,
    /// Last refill instant.
    last: Instant,
}

/// Refill rate and burst ceiling, in requests per second; and the fixed-point
/// scale used for sub-request token accounting.
const RATE_LIMIT_RATE: u64 = 60;
const RATE_LIMIT_CAPACITY: u64 = 120;
const TOKEN_SCALE: u64 = 1_000;
const CAP: u64 = RATE_LIMIT_CAPACITY * TOKEN_SCALE;
/// Upper bound on the number of distinct IPs tracked by the rate limiter, so
/// memory cannot grow without limit under a spray of IPv6 sources.
const MAX_RATE_TRACKED: usize = 8192;

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl RateLimiter {
    /// Bucket key for a peer address. IPv6 sources are grouped by /64: one
    /// delegated prefix can mint 2^64 addresses, so keying per-address would
    /// let a single holder rotate past `MAX_RATE_TRACKED` and restart with a
    /// full bucket every time. IPv4 stays per-address.
    fn bucket_key(peer: IpAddr) -> IpAddr {
        match peer {
            IpAddr::V4(_) => peer,
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let mut masked = [0u8; 16];
                masked[..8].copy_from_slice(&octets[..8]);
                IpAddr::V6(std::net::Ipv6Addr::from(masked))
            }
        }
    }

    /// Refuse a request when the bucket for `peer` is empty. Uses a blocking
    /// lock because the API runtime is current-threaded and the critical
    /// section is a few integer ops — an async lock would needlessly yield on
    /// the hot path.
    fn check(&self, peer: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Bound the table: drop idle buckets first, then the stalest single
        // entry, so a spray of sources cannot grow memory without limit.
        if map.len() >= MAX_RATE_TRACKED {
            map.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(300));
            if map.len() >= MAX_RATE_TRACKED {
                if let Some(oldest) = map.iter().min_by_key(|(_, b)| b.last).map(|(ip, _)| *ip) {
                    map.remove(&oldest);
                }
            }
        }
        let bucket = map.entry(Self::bucket_key(peer)).or_insert(Bucket {
            tokens: CAP,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        let refill = (elapsed * RATE_LIMIT_RATE as f64 * TOKEN_SCALE as f64).floor() as u64;
        if refill > 0 {
            bucket.tokens = (bucket.tokens + refill).min(CAP);
            bucket.last = now;
        }
        if bucket.tokens >= TOKEN_SCALE {
            bucket.tokens -= TOKEN_SCALE;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// x402-compatible adapter (internet-native agent payments, facilitator mode)
// ---------------------------------------------------------------------------
// The node speaks the x402 challenge/response shape without a second payment
// system: `GET /v1/paid/weather` answers 402 + `PAYMENT-REQUIRED` (base64
// `srct_core::x402::X402Required`), the agent retries with `PAYMENT-SIGNATURE`
// (base64 `X402Signature` carrying the exact `payment_submit` envelope), and
// the node verifies/settles through the same `admit_payment` + credit path
// `POST /v1/payment/submit` uses. `POST /v1/x402/verify` and
// `POST /v1/x402/settle` expose the facilitator verbs directly.

/// Fixed demo price for the paid weather resource (satoshis).
const X402_DEMO_AMOUNT_SAT: u64 = 500;
/// Fixed demo recipient the 402 challenge advertises (operator wallet in prod).
const X402_DEMO_RECIPIENT: Address = [0x42; 20];
/// Service tag for the demo resource.
const X402_DEMO_SERVICE_NAME: &[u8] = b"x402-weather-v1";

fn x402_err(e: srct_core::x402::X402Error) -> (StatusCode, Json<ErrorBody>) {
    use srct_core::x402::X402Error as E;
    match &e {
        E::UnsupportedVersion(_) | E::UnsupportedScheme(_) => {
            fail(StatusCode::BAD_REQUEST, "x402_unsupported", e.to_string())
        }
        E::UnknownNetwork(_) | E::RecipientNotAllowed | E::ServiceNotAllowed => {
            fail(StatusCode::CONFLICT, "x402_refused", e.to_string())
        }
        _ => bad(e.to_string()),
    }
}

fn x402_demo_service_id(network_id: &str) -> [u8; 32] {
    srct_core::service::derive_service_id(network_id, &X402_DEMO_RECIPIENT, X402_DEMO_SERVICE_NAME)
}

fn x402_challenge(
    network_id: &str,
    resource: &str,
    description: &str,
) -> Result<(srct_core::x402::X402Required, String), (StatusCode, Json<ErrorBody>)> {
    let required = srct_core::x402::build_required(
        network_id,
        X402_DEMO_AMOUNT_SAT,
        address_to_hex(&X402_DEMO_RECIPIENT),
        resource.to_string(),
        description.to_string(),
    )
    .map_err(x402_err)?;
    let header = srct_core::x402::encode_required(&required).map_err(x402_err)?;
    Ok((required, header))
}

/// Shared admission: identical checks to `payment_submit` so the x402 path
/// cannot admit anything the native path would refuse — including the
/// human-approval gate, which `payment_submit` enforces separately.
fn admit_machine_payment_inner(
    sh: &mut SharedNode,
    payment: MachinePayment,
    authorization: srct_core::agent::Authorization,
    auth_sigs: srct_core::sig::Bundle,
    auth_keys: srct_core::sig::Bundle,
    approval: Option<(srct_core::sig::Bundle, srct_core::sig::Bundle)>,
) -> Result<Hash, (StatusCode, Json<ErrorBody>)> {
    let network = sh.chain.params().network_id.clone();
    let height = sh.chain.height();
    let id = payment.signing_hash();
    let mut revoked_in_chain = sh.revoked_policies.contains(&payment.policy_hash);
    for ancestor in &payment.chain {
        if sh.revoked_policies.contains(&ancestor.hash()) {
            revoked_in_chain = true;
        }
    }
    if revoked_in_chain {
        return Err(fail(
            StatusCode::CONFLICT,
            "policy_revoked",
            "the policy this payment names, or an ancestor of it, has been revoked by its owner",
        ));
    }
    if !payment.chain.is_empty() {
        let recorded = sh.delegations.chain_of(payment.chain.last().unwrap());
        let provable = recorded.as_ref().map(|chain| {
            chain.len() == payment.chain.len()
                && chain
                    .iter()
                    .zip(payment.chain.iter())
                    .all(|(a, b)| a.hash() == b.hash())
        });
        if provable != Some(true) {
            return Err(fail(
                StatusCode::CONFLICT,
                "payment_refused",
                "the delegation chain this payment names is not a lineage this node recorded",
            ));
        }
    }
    if sh.payment_tracker.contains(&id) {
        return Ok(id);
    }
    // Same wallet-safety gates as `payment_submit`, including the enforced
    // human-approval refusal above the threshold.
    if risk_gate(sh, &payment, &network, id)? {
        require_high_value_approval(&payment, id, approval.as_ref().map(|(s, k)| (s, k)))?;
        audit_push(
            sh,
            "payment_approved",
            Some(id),
            Some(payment.amount_sat),
            format!("human-approved {}", hash_to_hex(&id)),
        );
    }
    let policy = match sh.policy_registry.get(&payment.policy_hash).cloned() {
        Some(policy) => policy,
        None => {
            return Err(fail(
                StatusCode::CONFLICT,
                "payment_refused",
                "the policy this payment names was never authorized under on this node",
            ));
        }
    };
    payment
        .verify(&network, height)
        .map_err(|e| fail(StatusCode::BAD_REQUEST, "payment_refused", e.to_string()))?;
    let presented = srct_core::service::AuthPresentation {
        auth: &authorization,
        sigs: &auth_sigs,
        keys: &auth_keys,
    };
    let reservation = srct_core::service::admit_payment(
        &sh.policies,
        &policy,
        &payment,
        presented,
        &network,
        height,
        &mut sh.credit,
    )
    .map_err(session_err)?;
    if !reservation.position_draws.is_empty() {
        let _ = sh.credit.release(&reservation);
        return Err(fail(
            StatusCode::CONFLICT,
            "payment_refused",
            "the payer's free balance cannot cover this payment and the remainder would draw on position headroom, which never settles through a receipt: fund the free balance or repay the position first",
        ));
    }
    session_gate(sh, &payment, height, id, &reservation)?;
    match sh.payment_tracker.accept(&payment, &network, height) {
        Ok(id) => {
            sh.payment_store.insert(id, payment);
            sh.reservations.insert(id, reservation);
            audit_push(
                sh,
                "payment_admitted",
                Some(id),
                Some(sh.payment_store.get(&id).map(|p| p.amount_sat).unwrap_or(0)),
                "admitted via x402 settle".to_string(),
            );
            Ok(id)
        }
        Err(srct_core::payment::PaymentError::AlreadySeen) => {
            let _ = sh.credit.release(&reservation);
            Ok(id)
        }
        Err(e) => {
            let _ = sh.credit.release(&reservation);
            Err(fail(
                StatusCode::BAD_REQUEST,
                "payment_refused",
                e.to_string(),
            ))
        }
    }
}

#[derive(Deserialize)]
struct X402VerifyReq {
    payment_hex: String,
    authorization_hex: String,
    auth_sigs_hex: String,
    auth_keys_hex: String,
}

/// Facilitator `verify`: offline checks only, no state change.
async fn x402_verify(State(state): State<ApiState>, Json(req): Json<X402VerifyReq>) -> ApiResult {
    let payment_bytes = decode_hex_bytes(&req.payment_hex, "payment")?;
    let payment =
        MachinePayment::deserialize(&payment_bytes).map_err(|e| bad(format!("payment: {e}")))?;
    let auth_bytes = decode_hex_bytes(&req.authorization_hex, "authorization")?;
    let authorization = srct_core::agent::Authorization::deserialize(&auth_bytes)
        .map_err(|e| bad(format!("authorization: {e}")))?;
    let auth_sigs = decode_bundle(&req.auth_sigs_hex, "auth_sigs")?;
    let auth_keys = decode_bundle(&req.auth_keys_hex, "auth_keys")?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        if let Err(e) = payment.verify(&network, height) {
            return Err(fail(
                StatusCode::CONFLICT,
                "x402_invalid",
                format!("payment verify: {e}"),
            ));
        }
        // The grant itself is checked, not just the signature: an offline
        // `verify` that skipped the policy window would bless a payment
        // whose grant expired, and a facilitator serving from that answer
        // would credit work the settle path refuses.
        let policy = sh.policy_registry.get(&authorization.policy_hash).cloned();
        let policy = match policy {
            Some(p) => p,
            None => {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "x402_invalid",
                    "the policy this authorization names was never issued on this node",
                ))
            }
        };
        if let Err(e) = srct_core::agent::verify_authorization_for_policy(
            &auth_sigs,
            &auth_keys,
            &authorization,
            &policy,
            height,
        ) {
            return Err(fail(
                StatusCode::CONFLICT,
                "x402_invalid",
                format!("authorization verify: {e}"),
            ));
        }
        if let Err(e) = payment.linked_to(&authorization) {
            return Err(fail(
                StatusCode::CONFLICT,
                "x402_invalid",
                format!("payment/authorization binding: {e}"),
            ));
        }
        // Advisory only: `valid` means "this node would admit this
        // payment right now" — it records nothing and settles nothing.
        // A facilitator that treats verify as settlement will credit work
        // that never lands; settle through `/v1/x402/settle` instead.
        Ok(Json(json!({
            "valid": true,
            "advisory": true,
            "payment_id": hash_to_hex(&payment.signing_hash()),
            "amount_sat": payment.amount_sat,
            "recipient": address_to_hex(&payment.recipient),
        })))
    })?
}

#[derive(Deserialize)]
struct X402SettleReq {
    payment_hex: String,
    authorization_hex: String,
    auth_sigs_hex: String,
    auth_keys_hex: String,
    /// Same human-approval flow as `POST /v1/payment/submit`: required when
    /// the payment trips the high-value threshold.
    approval_sigs_hex: Option<String>,
    approval_keys_hex: Option<String>,
}

/// Facilitator `settle`: verify + record through the shared admission path.
async fn x402_settle(State(state): State<ApiState>, Json(req): Json<X402SettleReq>) -> ApiResult {
    let payment_bytes = decode_hex_bytes(&req.payment_hex, "payment")?;
    let payment =
        MachinePayment::deserialize(&payment_bytes).map_err(|e| bad(format!("payment: {e}")))?;
    let auth_bytes = decode_hex_bytes(&req.authorization_hex, "authorization")?;
    let authorization = srct_core::agent::Authorization::deserialize(&auth_bytes)
        .map_err(|e| bad(format!("authorization: {e}")))?;
    let auth_sigs = decode_bundle(&req.auth_sigs_hex, "auth_sigs")?;
    let auth_keys = decode_bundle(&req.auth_keys_hex, "auth_keys")?;
    let approval_sigs = req
        .approval_sigs_hex
        .as_deref()
        .map(|s| decode_bundle(s, "approval_sigs"))
        .transpose()?;
    let approval_keys = req
        .approval_keys_hex
        .as_deref()
        .map(|s| decode_bundle(s, "approval_keys"))
        .transpose()?;
    let approval = approval_sigs.zip(approval_keys);
    with_shared(&state, |sh| {
        match admit_machine_payment_inner(
            sh,
            payment,
            authorization,
            auth_sigs,
            auth_keys,
            approval,
        ) {
            Ok(id) => {
                let resp = srct_core::x402::X402Response {
                    success: true,
                    payment_id: hash_to_hex(&id),
                    error: String::new(),
                };
                Ok(Json(json!({
                    "success": true,
                    "payment_id": hash_to_hex(&id),
                    "payment_response": srct_core::x402::encode_response(&resp),
                })))
            }
            Err(e) => Err(e),
        }
    })?
}

/// Paid demo resource: `GET /v1/paid/weather`.
///
/// Without `PAYMENT-SIGNATURE` this answers `402` + `PAYMENT-REQUIRED` (the
/// x402 challenge). With a valid signature for the demo price it admits the
/// payment and answers `200` + `PAYMENT-RESPONSE` + the weather body.
async fn paid_weather(State(state): State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
    let (network_id, height) = match with_shared(&state, |sh| {
        (sh.chain.params().network_id.clone(), sh.chain.height())
    }) {
        Ok(v) => v,
        Err((status, body)) => return (status, HeaderMap::new(), body).into_response(),
    };
    let resource = "/v1/paid/weather".to_string();
    let description = "Demo paid weather (x402 exact, 500 sat)".to_string();
    let (_required, challenge) = match x402_challenge(&network_id, &resource, &description) {
        Ok(v) => v,
        Err((status, body)) => return (status, HeaderMap::new(), body).into_response(),
    };
    let sig_header = headers
        .get(srct_core::x402::X402_HEADER_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    if sig_header.is_empty() {
        let mut out_headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&challenge) {
            out_headers.insert(srct_core::x402::X402_HEADER_REQUIRED, v);
        }
        let body = Json(json!({
            "error": "payment required",
            "x402Version": srct_core::x402::X402_VERSION,
            "accepts": [{
                "scheme": srct_core::x402::SRCT_SCHEME,
                "network": srct_core::x402::srct_network_caip2(&network_id).unwrap_or(network_id.clone()),
                "amount": X402_DEMO_AMOUNT_SAT.to_string(),
                "payTo": address_to_hex(&X402_DEMO_RECIPIENT),
                "description": description,
                "mimeType": "application/json",
                "resource": resource,
                "maxTimeoutSecs": 60,
            }],
            "resource": resource,
        }));
        return (StatusCode::PAYMENT_REQUIRED, out_headers, body).into_response();
    }
    let sig = match srct_core::x402::decode_signature(&sig_header) {
        Ok(sig) => sig,
        Err(e) => {
            let (status, body) = x402_err(e);
            return (status, HeaderMap::new(), body).into_response();
        }
    };
    let network_expected = match srct_core::x402::parse_srct_network(&sig.network) {
        Ok(n) => n,
        Err(e) => {
            let (status, body) = x402_err(e);
            return (status, HeaderMap::new(), body).into_response();
        }
    };
    if network_expected != network_id {
        let (status, body) = x402_err(srct_core::x402::X402Error::UnknownNetwork(sig.network));
        return (status, HeaderMap::new(), body).into_response();
    }
    let payment_bytes = match hex::decode(sig.payload.payment_hex.trim().trim_start_matches("0x")) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(json!({"error": "bad_request", "detail": "payment hex"})),
            )
                .into_response()
        }
    };
    let payment = match MachinePayment::deserialize(&payment_bytes) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(json!({"error": "bad_request", "detail": format!("payment: {e}")})),
            )
                .into_response()
        }
    };
    let auth_bytes = match hex::decode(
        sig.payload
            .authorization_hex
            .trim()
            .trim_start_matches("0x"),
    ) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(json!({"error": "bad_request", "detail": "authorization hex"})),
            )
                .into_response()
        }
    };
    let authorization = match srct_core::agent::Authorization::deserialize(&auth_bytes) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(json!({"error": "bad_request", "detail": format!("authorization: {e}")})),
            )
                .into_response()
        }
    };
    let decode_bundle_hex = |raw: &str| -> Result<srct_core::sig::Bundle, String> {
        let bytes = hex::decode(raw.trim().trim_start_matches("0x")).map_err(|e| e.to_string())?;
        // Same 8 KiB cap as every other bundle input: an uncapped hex blob
        // here decoded straight into the bundle reader.
        if bytes.len() > 8 * 1024 {
            return Err("bundle over the 8 KiB cap".to_string());
        }
        let mut r = srct_core::ser::Reader::new(&bytes);
        let bundle = srct_core::sig::Bundle::from_reader(&mut r).map_err(|e| e.to_string())?;
        r.expect_end().map_err(|e| e.to_string())?;
        Ok(bundle)
    };
    let auth_sigs = match decode_bundle_hex(&sig.payload.auth_sigs_hex) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(json!({"error": "bad_request", "detail": format!("auth_sigs: {e}")})),
            )
                .into_response()
        }
    };
    let auth_keys = match decode_bundle_hex(&sig.payload.auth_keys_hex) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(json!({"error": "bad_request", "detail": format!("auth_keys: {e}")})),
            )
                .into_response()
        }
    };
    // Demo price/service/recipient gate before admission. Exact amount:
    // an overpay is not a valid exact-scheme payment, and admitting it
    // would leave the excess unaccounted.
    let demo_service = x402_demo_service_id(&network_id);
    if payment.amount_sat != X402_DEMO_AMOUNT_SAT {
        return (
            StatusCode::PAYMENT_REQUIRED,
            HeaderMap::new(),
            Json(json!({"error": "payment required", "detail": format!("demo price is exactly {X402_DEMO_AMOUNT_SAT} sat") })),
        )
            .into_response();
    }
    if payment.recipient != X402_DEMO_RECIPIENT || payment.service != Some(demo_service) {
        return (
            StatusCode::CONFLICT,
            HeaderMap::new(),
            Json(json!({"error": "x402_refused", "detail": "payment recipient/service does not match the demo offer"})),
        )
            .into_response();
    }
    if payment.verify(&network_id, height).is_err() || payment.linked_to(&authorization).is_err() {
        return (
            StatusCode::CONFLICT,
            HeaderMap::new(),
            Json(json!({"error": "x402_invalid", "detail": "payment/authorization verify failed"})),
        )
            .into_response();
    }
    let payment_id = match with_shared(&state, |sh| {
        // The demo price sits far below any sane high-value threshold; the
        // demo carries no approver flow, so `None` is correct here rather
        // than a gap. An operator who sets a threshold at or below 500 sat
        // refuses the demo by configuration, loudly.
        admit_machine_payment_inner(sh, payment, authorization, auth_sigs, auth_keys, None)
    }) {
        Ok(Ok(id)) => id,
        Ok(Err((status, body))) => return (status, HeaderMap::new(), body).into_response(),
        Err((status, body)) => return (status, HeaderMap::new(), body).into_response(),
    };
    let resp = srct_core::x402::X402Response {
        success: true,
        payment_id: hash_to_hex(&payment_id),
        error: String::new(),
    };
    let mut out_headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&srct_core::x402::encode_response(&resp)) {
        out_headers.insert(srct_core::x402::X402_HEADER_RESPONSE, v);
    }
    (
        StatusCode::OK,
        out_headers,
        Json(json!({
            "report": { "weather": "sunny", "temperature": 70 },
            "payment_id": hash_to_hex(&payment_id),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Micro-payments: batch quotes, stream channels, sponsored intents
// ---------------------------------------------------------------------------
//
// Batching and streaming change *how many* chain transactions N payments
// cost, not what a payment is: every payment in a batch still verifies, and
// every stream voucher still settles exactly the newly accrued amount.

#[derive(Deserialize)]
struct AggregateReq {
    payment_ids: Vec<String>,
}

/// `POST /v1/payments/aggregate` — price one shared settlement for recorded
/// payments. Read-only: verifies each payment, merges same-payer payments
/// into one `PaymentBatch`, and quotes gas/fee/savings at the current base
/// fee. The caller builds and broadcasts the batch transaction out of band;
///
/// a quote is not a settlement.
async fn payments_aggregate(
    State(state): State<ApiState>,
    Json(req): Json<AggregateReq>,
) -> ApiResult {
    if req.payment_ids.is_empty() || req.payment_ids.len() > 256 {
        return Err(bad("payment_ids must name 1..=256 recorded payments"));
    }
    let mut ids = Vec::with_capacity(req.payment_ids.len());
    for raw in &req.payment_ids {
        ids.push(decode_hash(raw)?);
    }
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let base_fee = sh.chain.expected_base_fee_for_next_block();
        let mut payments = Vec::with_capacity(ids.len());
        for id in &ids {
            match sh.payment_store.get(id) {
                Some(p) => payments.push(p.clone()),
                None => {
                    return Err(fail(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        format!("no recorded payment {}", hash_to_hex(id)),
                    ))
                }
            }
        }
        let (batch, quote) =
            srct_core::micro::quote_batch(&payments, &network, height, base_fee, 1)
                .map_err(|e| bad(format!("aggregate: {e}")))?;
        Ok(Json(json!({
            "payer": address_to_hex(&batch.payer),
            "payments": batch.payment_ids.iter().map(hash_to_hex).collect::<Vec<_>>(),
            "outputs": batch.outputs.iter().map(|(a, s)| json!({
                "recipient": address_to_hex(a),
                "amount_sat": s,
            })).collect::<Vec<_>>(),
            "total_amount_sat": batch.total_amount_sat,
            "declared_fee_sat": batch.declared_fee_sat,
            "gas_used": quote.gas_used,
            "required_fee_sat": quote.required_fee_sat,
            "fee_per_payment_sat": quote.fee_per_payment_sat,
            "separate_total_fee_sat": quote.separate_total_fee_sat,
            "savings_sat": quote.savings_sat,
        })))
    })?
}

#[derive(Deserialize)]
struct StreamOpenReq {
    stream_hex: String,
}

/// `POST /v1/streams/open` — open a pay-as-you-use channel. The open locks
/// nothing on chain; the cap is enforced by exact-settlement accounting.
async fn stream_open(State(state): State<ApiState>, Json(req): Json<StreamOpenReq>) -> ApiResult {
    let bytes = decode_hex_bytes(&req.stream_hex, "stream")?;
    let stream = srct_core::stream::PaymentStream::deserialize(&bytes)
        .map_err(|e| bad(format!("stream: {e}")))?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let id = sh
            .streams
            .open(&stream, &network)
            .map_err(|e| fail(StatusCode::CONFLICT, "stream_refused", e.to_string()))?;
        sh.stream_store.insert(id, stream.clone());
        audit_push(
            sh,
            "stream_open",
            None,
            Some(stream.max_total_sat),
            format!("stream {} cap {}", hash_to_hex(&id), stream.max_total_sat),
        );
        Ok(Json(json!({
            "stream_id": hash_to_hex(&id),
            "rate_sat_per_block": stream.rate_sat_per_block,
            "max_total_sat": stream.max_total_sat,
        })))
    })?
}

#[derive(Deserialize)]
struct StreamSettleReq {
    stream_hex: String,
    settlement_hex: String,
}

/// `POST /v1/streams/settle` — accept one off-chain voucher receipt. The
/// voucher must settle exactly the newly accrued amount; the coin itself
/// still moves via `POST /v1/payment/submit` with `reference` = stream id.
async fn stream_settle(
    State(state): State<ApiState>,
    Json(req): Json<StreamSettleReq>,
) -> ApiResult {
    let stream_bytes = decode_hex_bytes(&req.stream_hex, "stream")?;
    let stream = srct_core::stream::PaymentStream::deserialize(&stream_bytes)
        .map_err(|e| bad(format!("stream: {e}")))?;
    let settle_bytes = decode_hex_bytes(&req.settlement_hex, "settlement")?;
    let settlement = srct_core::stream::StreamSettlement::deserialize(&settle_bytes, &stream)
        .map_err(|e| bad(format!("settlement: {e}")))?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        if stream.network_id != network {
            return Err(fail(
                StatusCode::CONFLICT,
                "stream_refused",
                "stream is for another network",
            ));
        }
        let id = stream.signing_hash();
        if !sh.stream_store.contains_key(&id) {
            return Err(fail(
                StatusCode::NOT_FOUND,
                "not_found",
                "stream is not open on this node",
            ));
        }
        let settled = sh
            .streams
            .settle(&stream, &settlement, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "stream_refused", e.to_string()))?;
        let claimable = sh.streams.claimable(&stream, height).unwrap_or(0);
        audit_push(
            sh,
            "stream_settle",
            None,
            Some(settlement.amount_sat),
            format!("stream {} settled {settled}", hash_to_hex(&id)),
        );
        Ok(Json(json!({
            "stream_id": hash_to_hex(&id),
            "settled_sat": settled,
            "claimable_sat": claimable,
        })))
    })?
}

/// `GET /v1/streams/{stream_id}` — channel accounting at the current height.
async fn stream_get(State(state): State<ApiState>, Path(raw): Path<String>) -> ApiResult {
    let id = decode_hash(&raw)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let stream = sh.stream_store.get(&id).ok_or_else(|| {
            fail(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("no stream {}", hash_to_hex(&id)),
            )
        })?;
        let st = sh
            .streams
            .state(&id)
            .copied()
            .unwrap_or(srct_core::stream::StreamState {
                settled_sat: 0,
                last_settled_height: None,
                last_nonce: 0,
                settlements: 0,
            });
        Ok(Json(json!({
            "stream_id": hash_to_hex(&id),
            "recipient": address_to_hex(&stream.recipient),
            "rate_sat_per_block": stream.rate_sat_per_block,
            "max_total_sat": stream.max_total_sat,
            "settled_sat": st.settled_sat,
            "last_settled_height": st.last_settled_height,
            "last_nonce": st.last_nonce,
            "settlements": st.settlements,
            "claimable_sat": sh.streams.claimable(stream, height).unwrap_or(0),
            "height": height,
        })))
    })?
}

// ---------------------------------------------------------------------------
// Wallet safety: reconciliation, audit export, risk policy
// ---------------------------------------------------------------------------
//
// A network timeout must never cause a double-pay: the agent lists what is in
// flight (`unsettled`) and what claims nothing recorded (`orphans`) before
// retrying, and the audit ring gives developers the complete trail.

/// `GET /v1/payments/unsettled` — recorded payments with no settlement tx
/// bound and not yet expired. Retry these idempotently; do not rebuild them.
async fn payments_unsettled(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit = page_limit(&query);
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let settled: std::collections::BTreeSet<Hash> = sh.payment_tx.keys().copied().collect();
        let mut out = Vec::new();
        let mut total = 0usize;
        for (id, payment) in &sh.payment_store {
            if settled.contains(id) || height >= payment.expires_at_height {
                continue;
            }
            total += 1;
            if out.len() < limit {
                out.push(json!({
                    "payment_id": hash_to_hex(id),
                    "amount_sat": payment.amount_sat,
                    "recipient": address_to_hex(&payment.recipient),
                    "expires_at_height": payment.expires_at_height,
                }));
            }
        }
        let truncated = total > out.len();
        Ok(Json(
            json!({ "count": out.len(), "total": total, "truncated": truncated, "payments": out }),
        ))
    })?
}

/// Page size for unbounded list endpoints: `?limit=N` honored up to
/// `MAX_PAGE`, default `MAX_PAGE`. A node that has served for years holds
/// millions of records; an uncapped serialization is a memory spike on both
/// sides. `total` + `truncated` let the client re-ask with a larger window.
const MAX_PAGE: usize = 1_000;

/// Resolve `?limit=` for a list endpoint: parse failure and zero mean the
/// default; anything over the cap clamps to the cap.
fn page_limit(query: &HashMap<String, String>) -> usize {
    query
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(MAX_PAGE)
        .min(MAX_PAGE)
}

/// `GET /v1/receipts/orphans` — receipts claiming payments this node never
/// recorded. Investigate, never auto-settle.
async fn receipts_orphans(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit = page_limit(&query);
    with_shared(&state, |sh| {
        let known: std::collections::BTreeSet<Hash> = sh.payment_store.keys().copied().collect();
        let mut out = Vec::new();
        let mut total = 0usize;
        for receipt in sh.receipts.iter() {
            if !known.contains(&receipt.payment_id) {
                total += 1;
                if out.len() < limit {
                    out.push(json!({
                        "receipt_id": hash_to_hex(&receipt.receipt_id()),
                        "payment_id": hash_to_hex(&receipt.payment_id),
                        "amount_sat": receipt.amount_sat,
                    }));
                }
            }
        }
        let truncated = total > out.len();
        Ok(Json(
            json!({ "count": out.len(), "total": total, "truncated": truncated, "orphans": out }),
        ))
    })?
}

/// `GET /v1/audit[?limit=]` — the tamper-evident audit ring (newest last),
/// plus chain verification. Full history lives in the payment/receipt
/// stores; the ring is the index over them.
async fn audit_list(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit: usize = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(512);
    with_shared(&state, |sh| {
        let valid = sh.audit.verify_chain().is_ok();
        let entries: Vec<Value> = sh
            .audit
            .iter()
            .rev()
            .take(limit)
            .map(|e| {
                json!({
                    "seq": e.seq,
                    "kind": e.kind,
                    "payment_id": e.payment_id.map(|h| hash_to_hex(&h)),
                    "amount_sat": e.amount_sat,
                    "detail": e.detail,
                })
            })
            .collect();
        Ok(Json(json!({
            "chain_valid": valid,
            "count": entries.len(),
            "dropped": sh.audit.dropped(),
            "entries": entries,
        })))
    })?
}

/// `GET /v1/risk/policy` — current wallet-safety knobs (thresholds, velocity,
/// test mode) and session-budget envelope, so developers know when approval
/// is required before they pay.
async fn risk_policy(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        // The node's own network decides the fallback: a mainnet node
        // reports the mainnet default unless the operator overrode it.
        let network = sh.chain.params().network_id.clone();
        let risk = srct_core::safety::RiskPolicy::from_env_for_network(&network);
        let (window, cap) = session_envelope();
        Ok(Json(json!({
            "high_value_threshold_sat": risk.high_value_threshold_sat,
            "max_payments_per_payer": risk.max_payments_per_payer,
            "test_mode": risk.test_mode,
            "session_window_blocks": window,
            "session_cap_sat": cap,
        })))
    })?
}

/// Parse a comma-separated env list of hex BLS public keys (trust anchors).
fn env_bls_keys(var: &str) -> Vec<srct_core::bls_checkpoint::BlsPublicKey> {
    let raw = std::env::var(var).unwrap_or_default();
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim().trim_start_matches("0x");
        let Ok(bytes) = hex::decode(part) else {
            continue;
        };
        if bytes.len() != 48 {
            continue;
        }
        let mut key = [0u8; 48];
        key.copy_from_slice(&bytes);
        out.push(srct_core::bls_checkpoint::BlsPublicKey(key));
    }
    out
}

fn decode_bls_sig(
    hex_str: &str,
) -> Result<srct_core::bls_checkpoint::BlsSignature, (StatusCode, Json<ErrorBody>)> {
    let b = decode_hex_bytes(hex_str, "signature")?;
    if b.len() != 96 {
        return Err(bad("signature must be 96 hex bytes"));
    }
    let mut s = [0u8; 96];
    s.copy_from_slice(&b);
    Ok(srct_core::bls_checkpoint::BlsSignature(s))
}

fn decode_agent(hex_str: &str) -> Result<srct_core::agent::AgentId, (StatusCode, Json<ErrorBody>)> {
    // Accepts raw 20-byte hex or the `jt1`-prefixed address form: passport
    // counterparties are addresses, subjects are raw agent ids.
    if let Ok(addr) = decode_address(hex_str) {
        return Ok(addr);
    }
    let b = decode_hex_bytes(hex_str, "agent")?;
    if b.len() != 20 {
        return Err(bad("agent must be 20 hex bytes"));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    Ok(a)
}

// --- Portable reputation ---

/// `POST /v1/reputation/passport/attest` — assemble a subject's verifiable
/// events from this node's own books (receipts → task/payment completions,
/// positions → repayments/defaults). Unsigned: an issuer signs the returned
/// event list out of band; `POST /v1/reputation/batch` registers the signed
/// batch after re-verifying every source.
async fn passport_attest(State(state): State<ApiState>, Json(req): Json<Value>) -> ApiResult {
    let address_hex = req
        .get("address_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("address_hex required"))?;
    let role = req
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("machine");
    let addr = decode_address(address_hex)?;
    let agent_role = match role {
        "machine" => srct_core::agent::AgentRole::Machine,
        "human" => srct_core::agent::AgentRole::Human,
        "service" => srct_core::agent::AgentRole::Service,
        _ => return Err(bad("role must be machine, human or service")),
    };
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let agent_id = srct_core::agent::derive_agent_id(&network, agent_role, &addr);
        let mut events = Vec::new();
        for receipt in sh.receipts.iter() {
            if receipt.payer == addr {
                events.push(json!({
                    "kind": "PaymentCompleted",
                    "height": 0,
                    "source": hash_to_hex(&receipt.receipt_id()),
                    "counterparty": address_to_hex(&receipt.recipient),
                    "amount_sat": receipt.amount_sat,
                }));
            }
            if receipt.recipient == addr {
                events.push(json!({
                    "kind": "TaskCompleted",
                    "height": 0,
                    "source": hash_to_hex(&receipt.receipt_id()),
                    "counterparty": address_to_hex(&receipt.payer),
                    "amount_sat": receipt.amount_sat,
                }));
            }
        }
        for (pid, position) in sh.credit.positions() {
            if position.borrower != addr {
                continue;
            }
            match &position.state {
                srct_core::credit::PositionState::Repaid { .. } => events.push(json!({
                    "kind": "LoanRepaid",
                    "height": 0,
                    "source": hash_to_hex(pid),
                    "counterparty": address_to_hex(&position.lender),
                    "amount_sat": position.amount_sat,
                })),
                srct_core::credit::PositionState::Defaulted { .. } => events.push(json!({
                    "kind": "LoanDefaulted",
                    "height": 0,
                    "source": hash_to_hex(pid),
                    "counterparty": address_to_hex(&position.lender),
                    "amount_sat": position.amount_sat,
                })),
                _ => {}
            }
        }
        Ok(Json(json!({
            "network_id": network,
            "subject": hex::encode(agent_id),
            "events": events,
            "note": "unsigned event list: have an issuer sign it, then register via /v1/reputation/batch",
        })))
    })?
}

#[derive(Deserialize)]
struct PassportBatchReq {
    network_id: String,
    subject_hex: String,
    events: Vec<PassportEventReq>,
    issuer_hex: String,
    issued_height: u64,
    expires_height: u64,
    sig_hex: String,
}

#[derive(Deserialize)]
struct PassportEventReq {
    kind: String,
    height: u64,
    source_hex: String,
    counterparty_hex: String,
    amount_sat: u64,
}

fn parse_passport_kind(raw: &str) -> Option<srct_core::passport::PassportEventKind> {
    use srct_core::passport::PassportEventKind as K;
    match raw {
        "TaskCompleted" => Some(K::TaskCompleted),
        "PaymentCompleted" => Some(K::PaymentCompleted),
        "DisputeWon" => Some(K::DisputeWon),
        "RefundIssued" => Some(K::RefundIssued),
        "LoanRepaid" => Some(K::LoanRepaid),
        "RefundReceived" => Some(K::RefundReceived),
        "DisputeLost" => Some(K::DisputeLost),
        "LoanDefaulted" => Some(K::LoanDefaulted),
        _ => None,
    }
}

/// `POST /v1/reputation/batch` — register an issuer-signed batch. Verifies
/// the signature, the issuer trust list (`SRCT_PASSPORT_ISSUERS`; empty means
/// accept any valid signature, dev only), and every event source against
/// local books: payments must be recorded, loans must match terminal state.
/// Task/dispute/refund events are issuer-attested (the issuer verified them).
async fn passport_batch_register(
    State(state): State<ApiState>,
    Json(req): Json<PassportBatchReq>,
) -> ApiResult {
    let subject = decode_agent(&req.subject_hex)?;
    let issuer = decode_public_key(&req.issuer_hex, "issuer")?;
    let sig = decode_bls_sig(&req.sig_hex)?;
    let mut events = Vec::with_capacity(req.events.len());
    for e in &req.events {
        let kind = parse_passport_kind(&e.kind)
            .ok_or_else(|| bad(format!("unknown event kind: {}", e.kind)))?;
        events.push(srct_core::passport::PassportEvent {
            kind,
            height: e.height,
            source: decode_hash(&e.source_hex)?,
            counterparty: decode_agent(&e.counterparty_hex)?,
            amount_sat: e.amount_sat,
        });
    }
    let batch = srct_core::passport::PassportBatch {
        network_id: req.network_id.clone(),
        subject,
        events,
        issuer,
        issued_height: req.issued_height,
        expires_height: req.expires_height,
        sig,
    };
    batch.validate().map_err(|e| bad(e.to_string()))?;
    if !batch.verify_sig() {
        return Err(fail(
            StatusCode::CONFLICT,
            "passport_refused",
            "issuer signature invalid",
        ));
    }
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        if batch.network_id != network {
            return Err(fail(
                StatusCode::CONFLICT,
                "passport_refused",
                "batch is for another network",
            ));
        }
        let trusted = env_bls_keys("SRCT_PASSPORT_ISSUERS");
        if !trusted.is_empty() && !trusted.contains(&batch.issuer) {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "passport_untrusted",
                "issuer is not trusted by this node",
            ));
        }
        let height = sh.chain.height();
        if height < batch.issued_height || height > batch.expires_height {
            return Err(fail(
                StatusCode::CONFLICT,
                "passport_refused",
                "batch not live at this height",
            ));
        }
        use srct_core::passport::PassportEventKind as K;
        // Every event is bound to its source, not just present alongside it:
        // existence alone let an issuer inflate any subject's score with
        // real-but-unrelated payments and loans. The subject must be a party
        // to the source, the counterparty the other party, and the amounts
        // must agree.
        for e in &batch.events {
            match e.kind {
                K::PaymentCompleted => {
                    let p = sh.payment_store.get(&e.source).ok_or_else(|| {
                        fail(
                            StatusCode::CONFLICT,
                            "passport_refused",
                            format!("payment source {} not recorded", hash_to_hex(&e.source)),
                        )
                    })?;
                    // The subject is an agent identity, not a raw address:
                    // it must equal the payment's derived `agent_id`
                    // (`derive_agent_id(network, payer_type, payer)`), and
                    // the counterparty must be the other side — the
                    // recipient of the subject's payment.
                    let sides = p.agent_id == batch.subject && p.recipient == e.counterparty;
                    if !sides || p.amount_sat != e.amount_sat {
                        return Err(fail(
                            StatusCode::CONFLICT,
                            "passport_refused",
                            format!(
                                "passport event does not match payment {}",
                                hash_to_hex(&e.source)
                            ),
                        ));
                    }
                }
                K::LoanRepaid => match sh.credit.position(&e.source) {
                    Some(p)
                        if matches!(p.state, srct_core::credit::PositionState::Repaid { .. })
                            && p.borrower == batch.subject
                            && p.amount_sat == e.amount_sat => {}
                    _ => {
                        return Err(fail(
                            StatusCode::CONFLICT,
                            "passport_refused",
                            format!(
                                "loan source {} is not this subject's repaid position",
                                hash_to_hex(&e.source)
                            ),
                        ))
                    }
                },
                K::LoanDefaulted => match sh.credit.position(&e.source) {
                    Some(p)
                        if matches!(
                            p.state,
                            srct_core::credit::PositionState::Defaulted { .. }
                        ) && p.borrower == batch.subject
                            && p.amount_sat == e.amount_sat => {}
                    _ => {
                        return Err(fail(
                            StatusCode::CONFLICT,
                            "passport_refused",
                            format!(
                                "loan source {} is not this subject's defaulted position",
                                hash_to_hex(&e.source)
                            ),
                        ))
                    }
                },
                _ => {}
            }
        }
        let id = batch.signing_hash();
        let score = srct_core::passport::score_batch(&batch);
        let tier = srct_core::passport::access_tier(score);
        sh.passport_batches.insert(id, batch);
        audit_push(
            sh,
            "passport_batch",
            Some(id),
            None,
            format!("registered score {score}"),
        );
        Ok(Json(json!({
            "batch_id": hash_to_hex(&id),
            "score": score,
            "tier": format!("{tier:?}"),
        })))
    })?
}

/// `GET /v1/reputation/score/{agent_hex}?role=machine` — combine live batches
/// for the subject into one score + tier.
async fn passport_score(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let addr = decode_address(&raw)?;
    let role = query.get("role").map(|s| s.as_str()).unwrap_or("machine");
    let agent_role = match role {
        "machine" => srct_core::agent::AgentRole::Machine,
        "human" => srct_core::agent::AgentRole::Human,
        "service" => srct_core::agent::AgentRole::Service,
        _ => return Err(bad("role must be machine, human or service")),
    };
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let subject = srct_core::agent::derive_agent_id(&network, agent_role, &addr);
        let mut total: i64 = 0;
        let mut batches = 0u64;
        for batch in sh.passport_batches.values() {
            if batch.subject != subject || batch.network_id != network {
                continue;
            }
            if height < batch.issued_height || height > batch.expires_height {
                continue;
            }
            total = total.saturating_add(srct_core::passport::score_batch(batch));
            batches += 1;
        }
        let tier = srct_core::passport::access_tier(total);
        Ok(Json(json!({
            "subject": hex::encode(subject),
            "score": total,
            "tier": format!("{tier:?}"),
            "live_batches": batches,
        })))
    })?
}

// --- Tiered wallets ---

#[derive(Deserialize)]
struct WalletTierReq {
    parent_policy_hex: String,
    parent_sigs_hex: Option<String>,
    parent_keys_hex: Option<String>,
    tier_policy_hex: String,
    tier_sigs_hex: Option<String>,
    tier_keys_hex: Option<String>,
}

/// `POST /v1/wallet/tier` — validate a max/min-spend tier against its parent
/// and register the lineage. Both policies carry owner signatures; the node
/// never signs. The child must narrow the parent (caps, recipients, services,
/// window) and link to the parent agent id.
async fn wallet_tier(State(state): State<ApiState>, Json(req): Json<WalletTierReq>) -> ApiResult {
    let parent = decode_owned_policy(
        &req.parent_policy_hex,
        "parent_policy",
        &req.parent_sigs_hex,
        &req.parent_keys_hex,
    )?;
    let tier = decode_owned_policy(
        &req.tier_policy_hex,
        "tier_policy",
        &req.tier_sigs_hex,
        &req.tier_keys_hex,
    )?;
    if !srct_core::tiers::is_valid_tier(&parent, &tier) {
        return Err(fail(
            StatusCode::CONFLICT,
            "tier_refused",
            "tier does not narrow its parent",
        ));
    }
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        if parent.network_id != network || tier.network_id != network {
            return Err(fail(
                StatusCode::CONFLICT,
                "tier_refused",
                "tier must be scoped to this node's network",
            ));
        }
        // An already-expired tier is a dead record: `link` would store it
        // and only the spend check would refuse it. Refuse the registration
        // instead, so the book holds no tier that can never authorize.
        let height = sh.chain.height();
        if tier.expires_at_height <= height {
            return Err(fail(
                StatusCode::CONFLICT,
                "tier_refused",
                "tier is already expired",
            ));
        }
        match sh.delegations.link(&parent, &tier) {
            Ok(()) => {
                sh.policy_registry.insert(tier.hash(), tier.clone());
                audit_push(
                    sh,
                    "tier_registered",
                    None,
                    Some(tier.per_tx_max_sat),
                    format!(
                        "tier {} under {}",
                        hash_to_hex(&tier.hash()),
                        hash_to_hex(&parent.hash())
                    ),
                );
                Ok(Json(json!({
                    "tier_policy_hash": hash_to_hex(&tier.hash()),
                    "agent_id": hex::encode(tier.agent_id),
                    "per_tx_max_sat": tier.per_tx_max_sat,
                    "expires_at_height": tier.expires_at_height,
                })))
            }
            Err(e) => Err(fail(StatusCode::CONFLICT, "tier_refused", e.to_string())),
        }
    })?
}

/// `GET /v1/wallet/tiers/{agent_hex}[?limit=]` — tiers registered under an
/// agent id.
async fn wallet_tiers(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let agent = decode_agent(&raw)?;
    let limit = page_limit(&query);
    with_shared(&state, |sh| {
        let mut out = Vec::new();
        let mut total = 0usize;
        for policy in sh.policy_registry.values() {
            if policy.parent_agent_id == Some(agent) {
                total += 1;
                if out.len() < limit {
                    out.push(json!({
                        "tier_policy_hash": hash_to_hex(&policy.hash()),
                        "per_tx_max_sat": policy.per_tx_max_sat,
                        "cumulative_max_sat": policy.cumulative_max_sat,
                        "expires_at_height": policy.expires_at_height,
                    }));
                }
            }
        }
        let truncated = total > out.len();
        Ok(Json(
            json!({ "count": out.len(), "total": total, "truncated": truncated, "tiers": out }),
        ))
    })?
}

// --- Agent-to-agent jobs ---

#[derive(Deserialize)]
struct JobOpenReq {
    hirer_hex: String,
    worker_hex: String,
    payer_bls: String,
    payee_bls: String,
    arbitrator: String,
    service_hex: String,
    amount_sat: u64,
    deadline_height: u64,
    nonce: u64,
    /// Hirer's BLS signature over `open_hash(...)`: opening commits the
    /// hirer's funds, so the open must be the hirer's own authorization.
    hirer_sig_hex: String,
}

/// `POST /v1/jobs/open` — hirer locks payment in an escrow and posts the job.
/// The escrow opens now (funds committed); the worker accepts, delivers, and
/// the hirer (or arbitrator) releases against the delivered result.
async fn job_open(State(state): State<ApiState>, Json(req): Json<JobOpenReq>) -> ApiResult {
    let hirer = decode_address(&req.hirer_hex)?;
    let worker = decode_address(&req.worker_hex)?;
    let payer_key = decode_public_key(&req.payer_bls, "payer_bls")?;
    let payee_key = decode_public_key(&req.payee_bls, "payee_bls")?;
    let arbitrator = decode_public_key(&req.arbitrator, "arbitrator")?;
    let service_bytes = decode_hex_bytes(&req.service_hex, "service")?;
    if service_bytes.len() != 32 {
        return Err(bad("service must be 32 hex bytes"));
    }
    let mut service = [0u8; 32];
    service.copy_from_slice(&service_bytes);
    let hirer_sig = decode_bls_sig(&req.hirer_sig_hex)?;
    // The open commits the hirer's funds: verify the hirer's own
    // authorization over every term before any escrow or job exists.
    let open_msg = srct_core::jobs::open_hash(
        &hirer,
        &worker,
        &arbitrator,
        &service,
        req.amount_sat,
        req.deadline_height,
        req.nonce,
    );
    if !srct_core::bls::RealBls::verify(&payer_key, &open_msg, &hirer_sig) {
        return Err(fail(
            StatusCode::CONFLICT,
            "job_refused",
            "open is not signed by the hirer",
        ));
    }
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let mut job = srct_core::jobs::JobRecord {
            network_id: network.clone(),
            hirer,
            worker,
            arbitrator,
            service_id: service,
            amount_sat: req.amount_sat,
            result_hash: None,
            deadline_height: req.deadline_height,
            escrow_id: None,
            state: srct_core::jobs::JobState::Offered,
            nonce: req.nonce,
        };
        job.validate().map_err(|e| bad(e.to_string()))?;
        let escrow = srct_core::escrow::ConditionalEscrow::open(
            network,
            hirer,
            payer_key,
            worker,
            payee_key,
            arbitrator,
            req.amount_sat,
            req.nonce,
            height,
        )
        .map_err(|e| fail(StatusCode::BAD_REQUEST, "escrow_refused", e.to_string()))?;
        let escrow_id = escrow.id();
        if sh.escrows.contains_key(&escrow_id) {
            return Err(fail(
                StatusCode::CONFLICT,
                "escrow_exists",
                "an escrow with this id already exists",
            ));
        }
        sh.escrows.insert(escrow_id, escrow);
        job.escrow_id = Some(escrow_id);
        let job_id = job.id();
        if sh.jobs.contains_key(&job_id) {
            return Err(fail(
                StatusCode::CONFLICT,
                "job_exists",
                "a job with this id already exists",
            ));
        }
        sh.jobs.insert(job_id, job);
        audit_push(
            sh,
            "job_open",
            None,
            Some(req.amount_sat),
            format!(
                "job {} escrow {}",
                hash_to_hex(&job_id),
                hash_to_hex(&escrow_id)
            ),
        );
        Ok(Json(json!({
            "job_id": hash_to_hex(&job_id),
            "escrow_id": hash_to_hex(&escrow_id),
            "state": "Offered",
        })))
    })?
}

#[derive(Deserialize)]
struct JobAcceptReq {
    worker_sigs_hex: String,
    worker_keys_hex: String,
}

/// `POST /v1/jobs/{id}/accept` — worker commits (signature over the job id).
async fn job_accept(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
    Json(req): Json<JobAcceptReq>,
) -> ApiResult {
    let job_id = decode_hash(&raw)?;
    let sigs = decode_bundle(&req.worker_sigs_hex, "worker_sigs")?;
    let keys = decode_bundle(&req.worker_keys_hex, "worker_keys")?;
    with_shared(&state, |sh| {
        let job = sh
            .jobs
            .get(&job_id)
            .cloned()
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such job"))?;
        let signer = keys
            .address()
            .map_err(|e| bad(format!("worker_keys: {e}")))?;
        if signer != job.worker {
            return Err(fail(
                StatusCode::CONFLICT,
                "job_refused",
                "acceptance is not signed by the worker",
            ));
        }
        srct_core::sig::verify_bundle(&sigs, &keys, &job_id).map_err(|_| {
            fail(
                StatusCode::CONFLICT,
                "job_refused",
                "worker signature invalid",
            )
        })?;
        let mut job = job;
        let escrow_id = job
            .escrow_id
            .ok_or_else(|| fail(StatusCode::CONFLICT, "job_refused", "job has no escrow"))?;
        srct_core::jobs::accept(&mut job, escrow_id)
            .map_err(|e| fail(StatusCode::CONFLICT, "job_refused", e.to_string()))?;
        sh.jobs.insert(job_id, job);
        audit_push(
            sh,
            "job_accept",
            None,
            None,
            format!("job {}", hash_to_hex(&job_id)),
        );
        Ok(Json(
            json!({ "job_id": hash_to_hex(&job_id), "state": "Accepted" }),
        ))
    })?
}

#[derive(Deserialize)]
struct JobDeliverReq {
    result_hash_hex: String,
    receipt_hex: Option<String>,
    /// Worker's bundle signature over `deliver_hash(job_id, result)`: only
    /// the worker names in the job may finalize it to `Delivered`.
    worker_sigs_hex: String,
    worker_keys_hex: String,
}

/// `POST /v1/jobs/{id}/deliver` — worker posts the result (+ optional signed
/// receipt binding the work product). Release later requires this hash.
async fn job_deliver(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
    Json(req): Json<JobDeliverReq>,
) -> ApiResult {
    let job_id = decode_hash(&raw)?;
    let result = decode_hash(&req.result_hash_hex)?;
    let receipt_bytes = req
        .receipt_hex
        .as_deref()
        .map(|h| decode_hex_bytes(h, "receipt"))
        .transpose()?;
    let sigs = decode_bundle(&req.worker_sigs_hex, "worker_sigs")?;
    let keys = decode_bundle(&req.worker_keys_hex, "worker_keys")?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        if let Some(bytes) = receipt_bytes {
            let receipt = srct_core::receipt::ServiceReceipt::deserialize(&bytes)
                .map_err(|e| bad(format!("receipt: {e}")))?;
            receipt
                .verify(&network)
                .map_err(|e| fail(StatusCode::BAD_REQUEST, "receipt_refused", e.to_string()))?;
            // A receipt naming a different result is not evidence for this
            // delivery: refuse the mismatch rather than file it alongside.
            if let Some(named) = receipt.result_hash {
                if named != result {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "job_refused",
                        "receipt names a different result",
                    ));
                }
            }
        }
        let mut job = sh
            .jobs
            .get(&job_id)
            .cloned()
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such job"))?;
        let signer = keys
            .address()
            .map_err(|e| bad(format!("worker_keys: {e}")))?;
        if signer != job.worker {
            return Err(fail(
                StatusCode::CONFLICT,
                "job_refused",
                "delivery is not signed by the worker",
            ));
        }
        // The message binds the result: an `accept`-shaped signature over
        // the bare job id does not authorize delivery.
        let msg = srct_core::jobs::deliver_hash(&job_id, &result);
        srct_core::sig::verify_bundle(&sigs, &keys, &msg).map_err(|_| {
            fail(
                StatusCode::CONFLICT,
                "job_refused",
                "worker delivery signature invalid",
            )
        })?;
        srct_core::jobs::deliver(&mut job, result, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "job_refused", e.to_string()))?;
        sh.jobs.insert(job_id, job);
        audit_push(
            sh,
            "job_deliver",
            None,
            None,
            format!(
                "job {} result {}",
                hash_to_hex(&job_id),
                hash_to_hex(&result)
            ),
        );
        Ok(Json(
            json!({ "job_id": hash_to_hex(&job_id), "state": "Delivered" }),
        ))
    })?
}

#[derive(Deserialize)]
struct JobDisputeReq {
    by: String,
    reason: String,
    sig_hex: String,
}

/// `POST /v1/jobs/{id}/dispute` — hirer, worker or arbitrator freezes the
/// funds: release, settlement and auto-refund are refused while held.
async fn job_dispute(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
    Json(req): Json<JobDisputeReq>,
) -> ApiResult {
    let job_id = decode_hash(&raw)?;
    if req.reason.is_empty() || req.reason.len() > 256 {
        return Err(bad("reason must be 1..=256 chars"));
    }
    let sig = decode_bls_sig(&req.sig_hex)?;
    with_shared(&state, |sh| {
        let mut job = sh
            .jobs
            .get(&job_id)
            .cloned()
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such job"))?;
        let escrow_id = job
            .escrow_id
            .ok_or_else(|| fail(StatusCode::CONFLICT, "job_refused", "job has no escrow"))?;
        let escrow = sh
            .escrows
            .get(&escrow_id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "job escrow missing"))?;
        let key = match req.by.as_str() {
            "hirer" => escrow.payer_key,
            "worker" => escrow.payee_key,
            "arbitrator" => escrow.arbitrator,
            _ => return Err(bad("by must be hirer, worker or arbitrator")),
        };
        let msg = srct_core::jobs::dispute_hash(&job_id, &req.reason);
        if !srct_core::bls::RealBls::verify(&key, &msg, &sig) {
            return Err(fail(
                StatusCode::CONFLICT,
                "job_refused",
                "dispute signature is not the named party",
            ));
        }
        srct_core::jobs::dispute(&mut job)
            .map_err(|e| fail(StatusCode::CONFLICT, "job_refused", e.to_string()))?;
        sh.jobs.insert(job_id, job);
        sh.held_escrows.insert(escrow_id);
        audit_push(
            sh,
            "job_dispute",
            None,
            None,
            format!("job {} held by {}", hash_to_hex(&job_id), req.by),
        );
        Ok(Json(
            json!({ "job_id": hash_to_hex(&job_id), "state": "Disputed", "held": true }),
        ))
    })?
}

#[derive(Deserialize)]
struct JobResolveReq {
    pay_worker: bool,
    result_hash_hex: Option<String>,
    arbitrator_sig_hex: String,
}

/// `POST /v1/jobs/{id}/resolve` — arbitrator decides: pay the worker or
/// refund the hirer. The signature binds (job, direction, result), and the
/// hold lifts; the coin moves through the existing escrow release/settle.
async fn job_resolve(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
    Json(req): Json<JobResolveReq>,
) -> ApiResult {
    let job_id = decode_hash(&raw)?;
    let result = req
        .result_hash_hex
        .as_deref()
        .map(decode_hash)
        .transpose()?
        .unwrap_or([0u8; 32]);
    let sig = decode_bls_sig(&req.arbitrator_sig_hex)?;
    with_shared(&state, |sh| {
        let mut job = sh
            .jobs
            .get(&job_id)
            .cloned()
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such job"))?;
        let msg = srct_core::jobs::resolve_hash(&job_id, req.pay_worker, &result);
        if !srct_core::bls::RealBls::verify(&job.arbitrator, &msg, &sig) {
            return Err(fail(
                StatusCode::CONFLICT,
                "job_refused",
                "resolve signature is not the arbitrator",
            ));
        }
        // The verified `result` is the same one the state machine checks:
        // a resolve that pays for result B while the record holds result A
        // is refused here, not settled.
        srct_core::jobs::resolve(&mut job, req.pay_worker, &result)
            .map_err(|e| fail(StatusCode::CONFLICT, "job_refused", e.to_string()))?;
        if let Some(escrow_id) = job.escrow_id {
            sh.held_escrows.remove(&escrow_id);
        }
        let state = job.state;
        sh.jobs.insert(job_id, job);
        audit_push(
            sh,
            "job_resolve",
            None,
            None,
            format!("job {} pay_worker={}", hash_to_hex(&job_id), req.pay_worker),
        );
        Ok(Json(
            json!({ "job_id": hash_to_hex(&job_id), "state": format!("{state:?}") }),
        ))
    })?
}

/// `GET /v1/jobs/{id}` — job record + escrow state + hold flag.
async fn job_get(State(state): State<ApiState>, Path(raw): Path<String>) -> ApiResult {
    let job_id = decode_hash(&raw)?;
    with_shared(&state, |sh| {
        let job = sh
            .jobs
            .get(&job_id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such job"))?;
        let (escrow_state, held) = match job.escrow_id {
            Some(eid) => (
                sh.escrows.get(&eid).map(|e| escrow_state_name(&e.state)),
                sh.held_escrows.contains(&eid),
            ),
            None => (None, false),
        };
        Ok(Json(json!({
            "job_id": hash_to_hex(&job_id),
            "hirer": address_to_hex(&job.hirer),
            "worker": address_to_hex(&job.worker),
            "service": hex::encode(job.service_id),
            "amount_sat": job.amount_sat,
            "result": job.result_hash.map(|h| hash_to_hex(&h)),
            "deadline_height": job.deadline_height,
            "escrow_id": job.escrow_id.map(|h| hash_to_hex(&h)),
            "state": format!("{:?}", job.state),
            "escrow_state": escrow_state,
            "held": held,
        })))
    })?
}

// --- Receipt status (every payment gets its receipt) ---

/// `GET /v1/payments/{id}/receipt_status` — is the payment recorded, is its
/// receipt present, is its settlement bound? Agents poll this and demand the
/// receipt before treating a payment as complete.
async fn receipt_status(State(state): State<ApiState>, Path(raw): Path<String>) -> ApiResult {
    let id = decode_hash(&raw)?;
    with_shared(&state, |sh| {
        let recorded = sh.payment_store.contains_key(&id);
        let receipt = sh.receipts.by_payment_id(&id);
        let settled = sh.payment_tx.get(&id).map(hash512_to_hex);
        Ok(Json(json!({
            "payment_id": hash_to_hex(&id),
            "recorded": recorded,
            "receipt_present": receipt.is_some(),
            "receipt_id": receipt.map(|r| hash_to_hex(&r.receipt_id())),
            "settlement_tx": settled,
        })))
    })?
}

// --- USD quotes + stablecoin-in ---

/// `POST /v1/fx/rates` — register an operator-signed rate. The issuer must be
/// in `SRCT_FX_ISSUERS` (comma-separated 48-byte hex BLS keys); empty means
/// no rate is trusted and every registration is refused.
async fn fx_rate_register(State(state): State<ApiState>, Json(req): Json<Value>) -> ApiResult {
    let base = req
        .get("base")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("base required"))?
        .to_string();
    let sat_per_minor = req
        .get("sat_per_minor")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| bad("sat_per_minor required"))?;
    let from = req
        .get("valid_from_height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| bad("valid_from_height required"))?;
    let until = req
        .get("valid_until_height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| bad("valid_until_height required"))?;
    let source = req
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("operator")
        .to_string();
    let issuer_hex = req
        .get("issuer_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("issuer_hex required"))?;
    let sig_hex = req
        .get("sig_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("sig_hex required"))?;
    let issuer = decode_public_key(issuer_hex, "issuer")?;
    let sig = decode_bls_sig(sig_hex)?;
    let rate = srct_core::fx::FxRate {
        base,
        sat_per_minor,
        valid_from_height: from,
        valid_until_height: until,
        source,
        issuer,
        sig,
    };
    rate.validate().map_err(|e| bad(e.to_string()))?;
    if !rate.verify_sig() {
        return Err(fail(
            StatusCode::CONFLICT,
            "fx_refused",
            "rate signature invalid",
        ));
    }
    with_shared(&state, |sh| {
        let trusted = env_bls_keys("SRCT_FX_ISSUERS");
        if trusted.is_empty() {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "no_fx_issuers",
                "no FX issuer is trusted; set SRCT_FX_ISSUERS",
            ));
        }
        if !trusted.contains(&rate.issuer) {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "fx_untrusted",
                "rate issuer is not trusted by this node",
            ));
        }
        sh.fx_rates.insert(rate.base.clone(), rate.clone());
        audit_push(
            sh,
            "fx_rate",
            None,
            Some(rate.sat_per_minor),
            format!("rate {} @ {}", rate.base, rate.sat_per_minor),
        );
        Ok(Json(
            json!({ "base": rate.base, "sat_per_minor": rate.sat_per_minor }),
        ))
    })?
}

/// `GET /v1/fx/rates[?limit=]` — live rates at this height.
async fn fx_rates(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit = page_limit(&query);
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let rates: Vec<Value> = sh
            .fx_rates
            .values()
            .filter(|r| r.live_at(height))
            .take(limit)
            .map(|r| {
                json!({
                    "base": r.base,
                    "sat_per_minor": r.sat_per_minor,
                    "valid_from_height": r.valid_from_height,
                    "valid_until_height": r.valid_until_height,
                    "source": r.source,
                })
            })
            .collect();
        // The rate book is trustee-curated and tiny (bounded by
        // `MAX_FX_RATES`); the cap here is uniformity, not load.
        let total = sh.fx_rates.values().filter(|r| r.live_at(height)).count();
        let truncated = total > rates.len();
        Ok(Json(
            json!({ "height": height, "count": rates.len(), "total": total, "truncated": truncated, "rates": rates }),
        ))
    })?
}

#[derive(Deserialize)]
struct FxQuoteReq {
    base: String,
    amount_minor: u64,
    fee_bps: u64,
    slippage_bps: u64,
    ttl_blocks: u64,
}

/// `POST /v1/fx/quote` — lock a dollar (or stablecoin) price into exact
/// satoshis: amount, fee and slippage stated up front, expiring at a height.
async fn fx_quote(State(state): State<ApiState>, Json(req): Json<FxQuoteReq>) -> ApiResult {
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let rate = sh.fx_rates.get(&req.base).ok_or_else(|| {
            fail(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("no rate for {}", req.base),
            )
        })?;
        let quote = srct_core::fx::quote_usd(
            rate,
            req.amount_minor,
            req.fee_bps,
            req.slippage_bps,
            height,
            req.ttl_blocks,
        )
        .map_err(|e| fail(StatusCode::CONFLICT, "fx_refused", e.to_string()))?;
        Ok(Json(json!({
            "base": quote.base,
            "amount_minor": quote.amount_minor,
            "sat_due": quote.sat_due,
            "fee_sat": quote.fee_sat,
            "slippage_bps": quote.slippage_bps,
            "rate_sat_per_minor": quote.rate_sat_per_minor,
            "expires_height": quote.expires_height,
        })))
    })?
}

#[derive(Deserialize)]
struct FxSwapReq {
    payer_hex: String,
    role: Option<String>,
    stable_asset: String,
    stable_minor: u64,
    sat_due: u64,
    fee_sat: u64,
    rate_sat_per_minor: u64,
    expires_height: u64,
    stable_ref: String,
    nonce: u64,
}

/// `POST /v1/fx/swap` — record a stablecoin-in payment: the agent holds USDC
/// (or a supported stablecoin) off-protocol and settles in SRCT at the locked
/// quote. Custody never touches this node; the intent is the audit trail.
async fn fx_swap(State(state): State<ApiState>, Json(req): Json<FxSwapReq>) -> ApiResult {
    let payer_addr = decode_address(&req.payer_hex)?;
    let role = req.role.as_deref().unwrap_or("machine");
    let agent_role = match role {
        "machine" => srct_core::agent::AgentRole::Machine,
        "human" => srct_core::agent::AgentRole::Human,
        "service" => srct_core::agent::AgentRole::Service,
        _ => return Err(bad("role must be machine, human or service")),
    };
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let rate = sh.fx_rates.get(&req.stable_asset).ok_or_else(|| {
            fail(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("no rate for {}", req.stable_asset),
            )
        })?;
        if !rate.live_at(height) || rate.sat_per_minor != req.rate_sat_per_minor {
            return Err(fail(
                StatusCode::CONFLICT,
                "fx_refused",
                "quote rate is not the live rate",
            ));
        }
        // Recompute the due amount server-side: the request's `sat_due`
        // must equal gross-at-live-rate plus the declared fee. Trusting the
        // client's figure let a swap understate what the payer owes while
        // the audit trail pointed at the live rate.
        let gross = (req.stable_minor as u128)
            .checked_mul(req.rate_sat_per_minor as u128)
            .ok_or_else(|| fail(StatusCode::CONFLICT, "fx_refused", "amount overflows"))?;
        let expected = gross
            .checked_add(req.fee_sat as u128)
            .and_then(|t| u64::try_from(t).ok())
            .ok_or_else(|| fail(StatusCode::CONFLICT, "fx_refused", "amount overflows"))?;
        if req.sat_due != expected {
            return Err(fail(
                StatusCode::CONFLICT,
                "fx_refused",
                "sat_due does not match the live rate plus fee",
            ));
        }
        let intent = srct_core::fx::SwapIntent {
            network_id: network,
            payer: srct_core::agent::derive_agent_id(
                &sh.chain.params().network_id,
                agent_role,
                &payer_addr,
            ),
            stable_asset: req.stable_asset.clone(),
            stable_minor: req.stable_minor,
            quote: srct_core::fx::Quote {
                base: req.stable_asset.clone(),
                amount_minor: req.stable_minor,
                sat_due: req.sat_due,
                fee_sat: req.fee_sat,
                slippage_bps: 0,
                rate_sat_per_minor: req.rate_sat_per_minor,
                expires_height: req.expires_height,
            },
            stable_ref: req.stable_ref.clone(),
            nonce: req.nonce,
        };
        intent.validate().map_err(|e| bad(e.to_string()))?;
        if height > intent.quote.expires_height {
            return Err(fail(StatusCode::CONFLICT, "fx_refused", "quote expired"));
        }
        let id = intent.id();
        audit_push(
            sh,
            "fx_swap",
            None,
            Some(intent.quote.sat_due),
            format!(
                "{} {} -> {} sat",
                intent.stable_minor, intent.stable_asset, intent.quote.sat_due
            ),
        );
        Ok(Json(json!({
            "swap_id": hash_to_hex(&id),
            "sat_due": intent.quote.sat_due,
            "fee_sat": intent.quote.fee_sat,
            "expires_height": intent.quote.expires_height,
        })))
    })?
}

// --- Ramps: fiat / stablecoin on- and off-ramps ---

#[derive(Deserialize)]
struct RampQuoteReq {
    network_id: String,
    provider_hex: String,
    direction: String,
    asset: String,
    asset_minor: u64,
    sat_amount: u64,
    fee_sat: u64,
    expires_height: u64,
    nonce: u64,
    provider_sigs_hex: String,
    provider_keys_hex: String,
}

/// `POST /v1/ramp/quote` — register a provider-signed ramp quote.
async fn ramp_quote(State(state): State<ApiState>, Json(req): Json<RampQuoteReq>) -> ApiResult {
    let provider = decode_address(&req.provider_hex)?;
    let direction =
        match req.direction.as_str() {
            "fiat_to_srct" => srct_core::ramp::RampDirection::FiatToSrct,
            "srct_to_fiat" => srct_core::ramp::RampDirection::SrctToFiat,
            "stable_to_srct" => srct_core::ramp::RampDirection::StableToSrct,
            "srct_to_stable" => srct_core::ramp::RampDirection::SrctToStable,
            _ => return Err(bad(
                "direction must be fiat_to_srct, srct_to_fiat, stable_to_srct or srct_to_stable",
            )),
        };
    let sigs = decode_bundle(&req.provider_sigs_hex, "provider_sigs")?;
    let keys = decode_bundle(&req.provider_keys_hex, "provider_keys")?;
    let quote = srct_core::ramp::RampQuote {
        network_id: req.network_id.clone(),
        provider,
        direction,
        asset: req.asset.clone(),
        asset_minor: req.asset_minor,
        sat_amount: req.sat_amount,
        fee_sat: req.fee_sat,
        expires_height: req.expires_height,
        nonce: req.nonce,
    };
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        if quote.network_id != sh.chain.params().network_id {
            return Err(fail(
                StatusCode::CONFLICT,
                "ramp_refused",
                "quote is for another network",
            ));
        }
        srct_core::ramp::verify_quote(&quote, &sigs, &keys, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "ramp_refused", e.to_string()))?;
        let id = quote.id();
        if sh.ramp_quotes.contains_key(&id) {
            return Ok(Json(
                json!({ "quote_id": hash_to_hex(&id), "duplicate": true }),
            ));
        }
        sh.ramp_quotes.insert(id, (quote, sigs, keys));
        audit_push(
            sh,
            "ramp_quote",
            None,
            None,
            format!("quote {}", hash_to_hex(&id)),
        );
        Ok(Json(
            json!({ "quote_id": hash_to_hex(&id), "duplicate": false }),
        ))
    })?
}

/// `GET /v1/ramp/quotes[?direction=&limit=]` — live quotes for entry and exit.
async fn ramp_quotes(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit = page_limit(&query);
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let mut out = Vec::new();
        let mut total = 0usize;
        for (id, (q, _, _)) in &sh.ramp_quotes {
            if q.expires_height < height {
                continue;
            }
            if let Some(dir) = query.get("direction") {
                let want = match dir.as_str() {
                    "fiat_to_srct" => srct_core::ramp::RampDirection::FiatToSrct,
                    "srct_to_fiat" => srct_core::ramp::RampDirection::SrctToFiat,
                    "stable_to_srct" => srct_core::ramp::RampDirection::StableToSrct,
                    "srct_to_stable" => srct_core::ramp::RampDirection::SrctToStable,
                    _ => return Err(bad("bad direction filter")),
                };
                if q.direction != want {
                    continue;
                }
            }
            total += 1;
            if out.len() < limit {
                out.push(json!({
                    "quote_id": hash_to_hex(id),
                    "provider": address_to_hex(&q.provider),
                    "asset": q.asset,
                    "asset_minor": q.asset_minor,
                    "sat_amount": q.sat_amount,
                    "fee_sat": q.fee_sat,
                    "expires_height": q.expires_height,
                }));
            }
        }
        let truncated = total > out.len();
        Ok(Json(
            json!({ "count": out.len(), "total": total, "truncated": truncated, "quotes": out }),
        ))
    })?
}

#[derive(Deserialize)]
struct RampIntentReq {
    quote_id: String,
    user_hex: String,
    fill_ref: String,
}

/// `POST /v1/ramp/intent` — user accepts a live quote; provider fills out of
/// band and settles the intent below.
async fn ramp_intent(State(state): State<ApiState>, Json(req): Json<RampIntentReq>) -> ApiResult {
    let quote_id = decode_hash(&req.quote_id)?;
    let user = decode_address(&req.user_hex)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let (quote, _, _) = sh
            .ramp_quotes
            .get(&quote_id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such quote"))?;
        if height > quote.expires_height {
            return Err(fail(StatusCode::CONFLICT, "ramp_refused", "quote expired"));
        }
        let intent = srct_core::ramp::RampIntent {
            quote_id,
            user,
            provider: quote.provider,
            fill_ref: req.fill_ref.clone(),
            filled: false,
            refunded: false,
        };
        intent.validate().map_err(|e| bad(e.to_string()))?;
        let id = intent.id();
        if sh.ramp_intents.contains_key(&id) {
            return Ok(Json(
                json!({ "intent_id": hash_to_hex(&id), "duplicate": true }),
            ));
        }
        sh.ramp_intents.insert(id, intent);
        audit_push(
            sh,
            "ramp_intent",
            None,
            None,
            format!("intent {}", hash_to_hex(&id)),
        );
        Ok(Json(
            json!({ "intent_id": hash_to_hex(&id), "duplicate": false }),
        ))
    })?
}

#[derive(Deserialize)]
struct RampSettleReq {
    outcome: String,
    fill_ref: String,
    provider_sigs_hex: String,
    provider_keys_hex: String,
}

/// `POST /v1/ramp/intent/{id}/settle` — provider marks filled or refunded,
/// signed over the intent id + outcome so only the quoted provider closes it.
async fn ramp_intent_settle(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
    Json(req): Json<RampSettleReq>,
) -> ApiResult {
    let id = decode_hash(&raw)?;
    let sigs = decode_bundle(&req.provider_sigs_hex, "provider_sigs")?;
    let keys = decode_bundle(&req.provider_keys_hex, "provider_keys")?;
    with_shared(&state, |sh| {
        let intent = sh
            .ramp_intents
            .get(&id)
            .cloned()
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such intent"))?;
        let (quote, _, _) = sh
            .ramp_quotes
            .get(&intent.quote_id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "quote missing"))?;
        let signer = keys
            .address()
            .map_err(|e| bad(format!("provider_keys: {e}")))?;
        if signer != quote.provider {
            return Err(fail(
                StatusCode::CONFLICT,
                "ramp_refused",
                "settle signature is not the provider",
            ));
        }
        if req.fill_ref.len() > 128 {
            return Err(bad("fill ref over cap"));
        }
        let mut msg = Vec::with_capacity(64 + req.fill_ref.len());
        msg.extend_from_slice(&id);
        msg.extend_from_slice(req.outcome.as_bytes());
        // The fill reference rides inside the signed digest: without it, one
        // provider signature authorized *any* fill_ref, so a tampered receipt
        // reference carried a valid receipt signature.
        msg.extend_from_slice(&(req.fill_ref.len() as u64).to_le_bytes());
        msg.extend_from_slice(req.fill_ref.as_bytes());
        let digest = srct_core::hash::sha256_dom(b"srct/ramp-settle/v1", &[&msg]);
        srct_core::sig::verify_bundle(&sigs, &keys, &digest).map_err(|_| {
            fail(
                StatusCode::CONFLICT,
                "ramp_refused",
                "provider signature invalid",
            )
        })?;
        let mut intent = intent;
        match req.outcome.as_str() {
            "filled" => {
                if intent.filled || intent.refunded {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "ramp_refused",
                        "intent already terminal",
                    ));
                }
                intent.filled = true;
            }
            "refunded" => {
                if intent.filled || intent.refunded {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "ramp_refused",
                        "intent already terminal",
                    ));
                }
                intent.refunded = true;
            }
            _ => return Err(bad("outcome must be filled or refunded")),
        }
        intent.fill_ref = req.fill_ref.clone();
        sh.ramp_intents.insert(id, intent);
        audit_push(
            sh,
            "ramp_settle",
            None,
            None,
            format!("intent {} {}", hash_to_hex(&id), req.outcome),
        );
        Ok(Json(
            json!({ "intent_id": hash_to_hex(&id), "outcome": req.outcome }),
        ))
    })?
}

/// `GET /v1/ramp/intents[?limit=]` — the registry trail for entry and exit.
async fn ramp_intents(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit = page_limit(&query);
    with_shared(&state, |sh| {
        let total = sh.ramp_intents.len();
        let mut out = Vec::new();
        for (id, intent) in sh.ramp_intents.iter().take(limit) {
            out.push(json!({
                "intent_id": hash_to_hex(id),
                "quote_id": hash_to_hex(&intent.quote_id),
                "user": address_to_hex(&intent.user),
                "provider": address_to_hex(&intent.provider),
                "fill_ref": intent.fill_ref,
                "filled": intent.filled,
                "refunded": intent.refunded,
            }));
        }
        let truncated = total > out.len();
        Ok(Json(
            json!({ "count": out.len(), "total": total, "truncated": truncated, "intents": out }),
        ))
    })?
}

// --- Productive lending ---

#[derive(Deserialize)]
struct LoanOfferReq {
    network_id: String,
    lender_hex: String,
    min_principal_sat: u64,
    max_principal_sat: u64,
    rate_bps_per_window: u64,
    window_blocks: u64,
    base_collateral_bps: u32,
    max_discount_bps: u32,
    bond_ratio_bps: u32,
    min_collateral_bps: u32,
    expires_height: u64,
    nonce: u64,
    lender_sigs_hex: String,
    lender_keys_hex: String,
}

/// `POST /v1/loans/offers` — lender publishes signed standard terms.
async fn loan_offer_post(
    State(state): State<ApiState>,
    Json(req): Json<LoanOfferReq>,
) -> ApiResult {
    let lender = decode_address(&req.lender_hex)?;
    let sigs = decode_bundle(&req.lender_sigs_hex, "lender_sigs")?;
    let keys = decode_bundle(&req.lender_keys_hex, "lender_keys")?;
    let offer = srct_core::lending::LoanOffer {
        network_id: req.network_id.clone(),
        lender,
        min_principal_sat: req.min_principal_sat,
        max_principal_sat: req.max_principal_sat,
        rate_bps_per_window: req.rate_bps_per_window,
        window_blocks: req.window_blocks,
        base_collateral_bps: req.base_collateral_bps,
        max_discount_bps: req.max_discount_bps,
        bond_ratio_bps: req.bond_ratio_bps,
        min_collateral_bps: req.min_collateral_bps,
        expires_height: req.expires_height,
        nonce: req.nonce,
    };
    offer.validate().map_err(|e| bad(e.to_string()))?;
    with_shared(&state, |sh| {
        if offer.network_id != sh.chain.params().network_id {
            return Err(fail(
                StatusCode::CONFLICT,
                "loan_refused",
                "offer is for another network",
            ));
        }
        let height = sh.chain.height();
        if height > offer.expires_height {
            return Err(fail(StatusCode::CONFLICT, "loan_refused", "offer expired"));
        }
        let signer = keys
            .address()
            .map_err(|e| bad(format!("lender_keys: {e}")))?;
        if signer != offer.lender {
            return Err(fail(
                StatusCode::CONFLICT,
                "loan_refused",
                "offer signature is not the lender",
            ));
        }
        srct_core::sig::verify_bundle(&sigs, &keys, &offer.id()).map_err(|_| {
            fail(
                StatusCode::CONFLICT,
                "loan_refused",
                "lender signature invalid",
            )
        })?;
        let id = offer.id();
        if sh.loan_offers.contains_key(&id) {
            return Ok(Json(
                json!({ "offer_id": hash_to_hex(&id), "duplicate": true }),
            ));
        }
        if sh.loan_offers.len() >= srct_core::lending::MAX_LOAN_OFFERS {
            return Err(fail(
                StatusCode::CONFLICT,
                "loan_refused",
                "offer book full",
            ));
        }
        sh.loan_offers.insert(id, (offer, sigs, keys));
        audit_push(
            sh,
            "loan_offer",
            None,
            None,
            format!("offer {}", hash_to_hex(&id)),
        );
        Ok(Json(
            json!({ "offer_id": hash_to_hex(&id), "duplicate": false }),
        ))
    })?
}

/// `GET /v1/loans/offers?principal=&limit=` — discover live offers, cheapest
/// rate first. Loan discovery without bespoke negotiation.
async fn loan_offers(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit = page_limit(&query);
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let principal: u64 = query
            .get("principal")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut out: Vec<(&Hash, &srct_core::lending::LoanOffer)> = sh
            .loan_offers
            .iter()
            .filter(|(_, (o, _, _))| {
                height <= o.expires_height && (principal == 0 || o.fits(principal, height))
            })
            .map(|(id, (o, _, _))| (id, o))
            .collect();
        let total = out.len();
        out.sort_by_key(|(_, o)| (o.rate_bps_per_window, o.id()));
        out.truncate(limit);
        let truncated = total > out.len();
        let offers: Vec<Value> = out
            .iter()
            .map(|(id, o)| {
                json!({
                    "offer_id": hash_to_hex(id),
                    "lender": address_to_hex(&o.lender),
                    "min_principal_sat": o.min_principal_sat,
                    "max_principal_sat": o.max_principal_sat,
                    "rate_bps_per_window": o.rate_bps_per_window,
                    "window_blocks": o.window_blocks,
                    "base_collateral_bps": o.base_collateral_bps,
                    "max_discount_bps": o.max_discount_bps,
                    "bond_ratio_bps": o.bond_ratio_bps,
                    "min_collateral_bps": o.min_collateral_bps,
                    "expires_height": o.expires_height,
                })
            })
            .collect();
        Ok(Json(
            json!({ "count": offers.len(), "total": total, "truncated": truncated, "offers": offers }),
        ))
    })?
}

#[derive(Deserialize)]
struct LoanAcceptReq {
    offer_id: String,
    borrower_hex: String,
    bond_sat: u64,
    amount_sat: u64,
    deadline_height: u64,
    /// Borrower's bundle signature over `accept_hash(...)`: the debit lands
    /// in the named borrower's book, so the named borrower must authorize it.
    borrower_sigs_hex: String,
    borrower_keys_hex: String,
}

/// `POST /v1/loans/accept` — borrower takes a standard offer: terms come from
/// the signed offer, never from the borrower's request. Bond and collateral
/// must already be funded in the borrower's book balances.
async fn loan_accept(State(state): State<ApiState>, Json(req): Json<LoanAcceptReq>) -> ApiResult {
    let offer_id = decode_hash(&req.offer_id)?;
    let borrower = decode_address(&req.borrower_hex)?;
    let sigs = decode_bundle(&req.borrower_sigs_hex, "borrower_sigs")?;
    let keys = decode_bundle(&req.borrower_keys_hex, "borrower_keys")?;
    let signer = keys
        .address()
        .map_err(|e| bad(format!("borrower_keys: {e}")))?;
    if signer != borrower {
        return Err(fail(
            StatusCode::CONFLICT,
            "loan_refused",
            "accept is not signed by the borrower",
        ));
    }
    let msg = srct_core::lending::accept_hash(
        &offer_id,
        &borrower,
        req.amount_sat,
        req.bond_sat,
        req.deadline_height,
    );
    srct_core::sig::verify_bundle(&sigs, &keys, &msg).map_err(|_| {
        fail(
            StatusCode::CONFLICT,
            "loan_refused",
            "borrower signature invalid",
        )
    })?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let (offer, _, _) = sh
            .loan_offers
            .get(&offer_id)
            .cloned()
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such offer"))?;
        if !offer.fits(req.amount_sat, height) {
            return Err(fail(
                StatusCode::CONFLICT,
                "loan_refused",
                "amount or expiry outside the offer",
            ));
        }
        if req.deadline_height <= height {
            return Err(fail(
                StatusCode::CONFLICT,
                "loan_refused",
                "deadline must be in the future",
            ));
        }
        let rate = u32::try_from(offer.rate_bps_per_window)
            .map_err(|_| bad("offer rate does not fit u32"))?;
        let agent_id = srct_core::agent::derive_agent_id(
            &network,
            srct_core::agent::AgentRole::Machine,
            &borrower,
        );
        let mut agent_hash = [0u8; 32];
        agent_hash[..20].copy_from_slice(&agent_id);
        let spec = srct_core::credit::PositionSpec {
            terms: offer.terms(),
            charge: srct_core::credit::ChargeSchedule {
                rate_bps_per_window: rate,
                window_blocks: offer.window_blocks,
            },
            borrower,
            agent_id: agent_hash,
            lender: offer.lender,
            amount_sat: req.amount_sat,
            bond_sat: req.bond_sat,
            drawn_at_height: height,
            deadline_height: req.deadline_height,
        };
        let required = spec
            .terms
            .required_collateral(req.amount_sat, req.bond_sat)
            .map_err(|e| fail(StatusCode::CONFLICT, "loan_refused", e.to_string()))?;
        let id = sh
            .credit
            .open(&spec)
            .map_err(|e| fail(StatusCode::CONFLICT, "loan_refused", e.to_string()))?;
        audit_push(
            sh,
            "loan_open",
            Some(id),
            Some(req.amount_sat),
            format!("offer {} collateral {required}", hash_to_hex(&offer_id)),
        );
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "required_collateral_sat": required,
        })))
    })?
}

/// Verified repayment history + a conservative suggested ceiling for one
/// borrower. The suggestion is advisory: the lender decides, and a default
/// zeroes it.
async fn lending_borrower(State(state): State<ApiState>, Path(raw): Path<String>) -> ApiResult {
    let borrower = decode_address(&raw)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let history = srct_core::lending::RepaymentHistory::from_positions(
            &borrower,
            sh.credit.positions().map(|(_, p)| p),
            height,
        );
        let network = sh.chain.params().network_id.clone();
        let subject = srct_core::agent::derive_agent_id(
            &network,
            srct_core::agent::AgentRole::Machine,
            &borrower,
        );
        let mut score: i64 = 0;
        for batch in sh.passport_batches.values() {
            if batch.subject == subject
                && batch.network_id == network
                && height >= batch.issued_height
                && height <= batch.expires_height
            {
                score = score.saturating_add(srct_core::passport::score_batch(batch));
            }
        }
        let suggested = srct_core::lending::suggested_limit(&history, score);
        Ok(Json(json!({
            "borrower": address_to_hex(&borrower),
            "repaid_positions": history.repaid_positions,
            "defaulted_positions": history.defaulted_positions,
            "total_repaid_sat": history.total_repaid_sat,
            "total_borrowed_sat": history.total_borrowed_sat,
            "on_time_rate_bps": history.on_time_rate_bps(),
            "reputation_score": score,
            "suggested_max_principal_sat": suggested,
            "advisory_only": true,
        })))
    })?
}

/// Lender risk dashboard: exposure by lender, positions due soon, defaulted
/// positions with shortfalls, expected interest. Read-only over the book.
async fn lending_dashboard(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let due_soon_window: u64 = 100;
        let mut open = Vec::new();
        let mut exposure: BTreeMap<String, u64> = BTreeMap::new();
        let mut due_soon = Vec::new();
        let mut defaulted = Vec::new();
        let mut expected_interest: u64 = 0;
        for (id, p) in sh.credit.positions() {
            match &p.state {
                srct_core::credit::PositionState::Drawn {
                    repaid_principal_sat,
                    repaid_interest_sat,
                    ..
                } => {
                    let interest = p
                        .charge
                        .accrued_interest(p.amount_sat, p.drawn_at_height, height)
                        .unwrap_or(0);
                    let total = p.amount_sat.saturating_add(interest);
                    let paid = repaid_principal_sat.saturating_add(*repaid_interest_sat);
                    let outstanding = total.saturating_sub(paid);
                    let key = address_to_hex(&p.lender);
                    let entry = exposure.entry(key).or_insert(0);
                    *entry = entry.saturating_add(outstanding);
                    expected_interest = expected_interest.saturating_add(interest);
                    open.push(json!({
                        "position_id": hash_to_hex(id),
                        "borrower": address_to_hex(&p.borrower),
                        "lender": address_to_hex(&p.lender),
                        "outstanding_sat": outstanding,
                        "deadline_height": p.deadline_height,
                    }));
                    if p.deadline_height <= height + due_soon_window {
                        due_soon.push(json!({
                            "position_id": hash_to_hex(id),
                            "deadline_height": p.deadline_height,
                            "outstanding_sat": outstanding,
                        }));
                    }
                }
                srct_core::credit::PositionState::Defaulted { settlement, .. } => {
                    defaulted.push(json!({
                        "position_id": hash_to_hex(id),
                        "borrower": address_to_hex(&p.borrower),
                        "lender": address_to_hex(&p.lender),
                        "debt_sat": settlement.debt_sat,
                        "shortfall_sat": settlement.shortfall_sat,
                    }));
                }
                _ => {}
            }
        }
        Ok(Json(json!({
            "height": height,
            "open_positions": open.len(),
            "exposure_by_lender": exposure,
            "due_soon": due_soon,
            "defaulted": defaulted,
            "expected_interest_sat": expected_interest,
        })))
    })?
}

/// `GET /v1/lending/limit/{borrower}` — suggested ceiling + the factors behind
/// it. Advisory only; who bears losses is the position's settlement, not this
/// number (collateral first, then the bond, then the lender absorbs it).
async fn lending_limit(State(state): State<ApiState>, Path(raw): Path<String>) -> ApiResult {
    let borrower = decode_address(&raw)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let network = sh.chain.params().network_id.clone();
        let history = srct_core::lending::RepaymentHistory::from_positions(
            &borrower,
            sh.credit.positions().map(|(_, p)| p),
            height,
        );
        let subject = srct_core::agent::derive_agent_id(
            &network,
            srct_core::agent::AgentRole::Machine,
            &borrower,
        );
        let mut score: i64 = 0;
        for batch in sh.passport_batches.values() {
            if batch.subject == subject
                && batch.network_id == network
                && height >= batch.issued_height
                && height <= batch.expires_height
            {
                score = score.saturating_add(srct_core::passport::score_batch(batch));
            }
        }
        Ok(Json(json!({
            "borrower": address_to_hex(&borrower),
            "suggested_max_principal_sat": srct_core::lending::suggested_limit(&history, score),
            "factors": {
                "repaid_positions": history.repaid_positions,
                "defaulted_positions": history.defaulted_positions,
                "total_repaid_sat": history.total_repaid_sat,
                "reputation_score": score,
            },
            "loss_bearing": "collateral first, then the borrower's posted bond, then the lender absorbs the shortfall",
        })))
    })?
}

/// Live valuation of one position: collateral vs debt + accrued interest.
async fn lending_collateral(State(state): State<ApiState>, Path(raw): Path<String>) -> ApiResult {
    let id = decode_hash(&raw)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let p = sh
            .credit
            .position(&id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such position"))?;
        let interest = p
            .charge
            .accrued_interest(p.amount_sat, p.drawn_at_height, height)
            .unwrap_or(0);
        let debt = p.amount_sat.saturating_add(interest);
        let backing = (p.collateral_sat as u128) + (p.bond_sat as u128);
        let coverage_bps = if debt == 0 {
            u64::MAX
        } else {
            u64::try_from(backing * 10_000 / debt as u128).unwrap_or(u64::MAX)
        };
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "collateral_sat": p.collateral_sat,
            "bond_sat": p.bond_sat,
            "principal_sat": p.amount_sat,
            "accrued_interest_sat": interest,
            "debt_sat": debt,
            "coverage_bps": coverage_bps,
            "state": format!("{:?}", p.state),
        })))
    })?
}

#[derive(Deserialize)]
struct AutorepayReq {
    borrower_hex: String,
    position_id: String,
    pct_bps: u64,
    cap_sat: u64,
    expires_height: u64,
    nonce: u64,
    sigs_hex: String,
    keys_hex: String,
}

/// `POST /v1/lending/autorepay` — register the borrower's signed standing
/// instruction: route a share of each credit deposit to the position.
/// Revoke by registering an expired replacement.
async fn lending_autorepay(
    State(state): State<ApiState>,
    Json(req): Json<AutorepayReq>,
) -> ApiResult {
    let borrower = decode_address(&req.borrower_hex)?;
    let position_id = decode_hash(&req.position_id)?;
    let sigs = decode_bundle(&req.sigs_hex, "sigs")?;
    let keys = decode_bundle(&req.keys_hex, "keys")?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let signer = keys.address().map_err(|e| bad(format!("keys: {e}")))?;
        if signer != borrower {
            return Err(fail(
                StatusCode::CONFLICT,
                "loan_refused",
                "instruction is not signed by the borrower",
            ));
        }
        // Replay guard + lifetime accounting: a replacement must carry a
        // strictly greater nonce than the live instruction, and the routed
        // total survives the swap — resetting it to zero on every edit
        // would silently lift the borrower's own cap.
        let carried_applied = match sh.standing_repay.get(&borrower) {
            Some((existing, _, _)) => {
                if req.nonce <= existing.nonce {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "loan_refused",
                        "instruction nonce must exceed the live instruction",
                    ));
                }
                existing.applied_sat
            }
            None => 0,
        };
        let instr = srct_core::lending::StandingRepay {
            network_id: network.clone(),
            borrower,
            position_id,
            pct_bps: req.pct_bps,
            cap_sat: req.cap_sat,
            applied_sat: carried_applied,
            expires_height: req.expires_height,
            nonce: req.nonce,
        };
        srct_core::lending::verify_standing_repay(&instr, &sigs, &keys, &network, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "loan_refused", e.to_string()))?;
        match sh.credit.position(&position_id) {
            Some(p) if p.borrower == borrower => {}
            _ => {
                return Err(fail(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "no such borrower position",
                ))
            }
        }
        sh.standing_repay.insert(borrower, (instr, sigs, keys));
        audit_push(
            sh,
            "autorepay_registered",
            Some(position_id),
            None,
            format!("borrower {}", address_to_hex(&borrower)),
        );
        Ok(Json(
            json!({ "borrower": address_to_hex(&borrower), "position_id": hash_to_hex(&position_id) }),
        ))
    })?
}

/// `GET /v1/lending/autorepay/{borrower}` — the live instruction, if any.
async fn lending_autorepay_get(
    State(state): State<ApiState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let borrower = decode_address(&raw)?;
    with_shared(&state, |sh| match sh.standing_repay.get(&borrower) {
        Some((instr, _, _)) => Ok(Json(json!({
            "borrower": address_to_hex(&borrower),
            "position_id": hash_to_hex(&instr.position_id),
            "pct_bps": instr.pct_bps,
            "cap_sat": instr.cap_sat,
            "applied_sat": instr.applied_sat,
            "expires_height": instr.expires_height,
        }))),
        None => Ok(Json(
            json!({ "borrower": address_to_hex(&borrower), "instruction": Value::Null }),
        )),
    })?
}

// ---------------------------------------------------------------------------
// Usage-based credits: the trial faucet (service layer, never consensus)
// ---------------------------------------------------------------------------
// A new agent with no coins cannot post the claim deposit a task requires, so
// its first task is unfundable — and an on-chain loan cannot help either,
// because collateral must be the borrower's own money. The trial faucet closes
// that gap without touching consensus: an operator-funded sponsor drips one
// fixed amount to the agent over ordinary L1 rails, the node verifies the
// receipt against its own chain, and the agent repays the same way later.
// Every trial is real SRCT the sponsor spent; the node only records and
// verifies, it never signs and never mints. One trial per agent, ever.

/// Trial drip in satoshis (`SRCT_TRIAL_AMOUNT_SAT`). The default is the L2
/// deposit floor: a trial must at least clear one minimum sink output, or the
/// agent cannot move the drip onto Layer 2 at all.
const TRIAL_DEFAULT_AMOUNT_SAT: u64 = 1_000_000;
/// Cap on unpaid trial money at once (`SRCT_TRIAL_MAX_OUTSTANDING_SAT`): the
/// sponsor's live exposure across requested-but-unrepaid trials.
const TRIAL_DEFAULT_MAX_OUTSTANDING_SAT: u64 = 10_000_000;

/// The trial sponsor (`SRCT_TRIAL_SPONSOR`, hex address). Unset means trials
/// are closed: with no sponsor there is no money behind a trial, so every
/// request is refused rather than recorded against nothing.
fn trial_sponsor() -> Option<Address> {
    let raw = std::env::var("SRCT_TRIAL_SPONSOR").unwrap_or_default();
    decode_address(&raw).ok()
}

fn trial_amount_sat() -> u64 {
    std::env::var("SRCT_TRIAL_AMOUNT_SAT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(TRIAL_DEFAULT_AMOUNT_SAT)
}

fn trial_max_outstanding_sat() -> u64 {
    std::env::var("SRCT_TRIAL_MAX_OUTSTANDING_SAT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(TRIAL_DEFAULT_MAX_OUTSTANDING_SAT)
}

/// Sponsor exposure right now: trials recorded but not yet repaid.
fn trial_outstanding(trials: &BTreeMap<Address, TrialRecord>) -> u64 {
    trials
        .values()
        .filter(|t| t.state != TrialState::Repaid)
        .map(|t| t.amount_sat)
        .fold(0u64, u64::saturating_add)
}

fn trial_json(t: &TrialRecord) -> Value {
    json!({
        "agent": address_to_hex(&t.agent),
        "amount_sat": t.amount_sat,
        "sponsor": address_to_hex(&t.sponsor),
        "state": t.state.name(),
        "fund_txid": t.fund_txid.map(|h| hash512_to_hex(&h)),
        "repay_txid": t.repay_txid.map(|h| hash512_to_hex(&h)),
        "requested_height": t.requested_height,
    })
}

/// A confirmed L1 payment of at least `amount_sat` to `to`, by txid. The scan
/// is the same canonical O(tip) walk `tx_lookup` pays for a node with no tx
/// index. Only confirmed blocks count: a trial funded by a mempool payment
/// could vanish on a reorg and leave the books claiming money moved.
fn confirmed_payment_to(
    chain: &srct_core::chain::Chain,
    txid: &Hash512,
    to: &Address,
    amount_sat: u64,
) -> bool {
    for height in 1..=chain.height() {
        let Some(block) = chain.block_at(height) else {
            continue;
        };
        for tx in &block.txs {
            if &tx.txid() != txid {
                continue;
            }
            let mut paid = 0u64;
            for out in &tx.outputs {
                if &out.address == to {
                    paid = paid.saturating_add(out.value);
                }
            }
            if paid >= amount_sat {
                return true;
            }
        }
    }
    false
}

/// A txid is single-use across the whole trial book: one L1 payment funds or
/// repays at most one trial, so a receipt can never be double-counted.
fn trial_txid_used(
    trials: &BTreeMap<Address, TrialRecord>,
    except: Option<&Address>,
    txid: &Hash512,
) -> bool {
    trials.iter().any(|(agent, t)| {
        Some(agent) != except
            && (t.fund_txid.as_ref() == Some(txid) || t.repay_txid.as_ref() == Some(txid))
    })
}

#[derive(Deserialize)]
struct TrialAgentReq {
    agent_hex: String,
}

#[derive(Deserialize)]
struct TrialTxReq {
    agent_hex: String,
    txid_hex: String,
}

/// `POST /v1/trials/request` — record a sponsored first task. No coin moves
/// here: the record is the sponsor's promise of a drip, and the drip itself
/// is an ordinary L1 payment the operator (or their sponsor script) makes out
/// of band, confirmed by `POST /v1/trials/fund`.
async fn trial_request(State(state): State<ApiState>, Json(req): Json<TrialAgentReq>) -> ApiResult {
    let agent = decode_address(&req.agent_hex)?;
    with_shared(&state, |sh| {
        let sponsor = trial_sponsor().ok_or_else(|| {
            fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "trials_disabled",
                "no trial sponsor is configured; set SRCT_TRIAL_SPONSOR",
            )
        })?;
        if sh.trials.contains_key(&agent) {
            return Err(fail(
                StatusCode::CONFLICT,
                "trial_exists",
                "one trial per agent, ever — this agent already has one",
            ));
        }
        let amount = trial_amount_sat();
        let live = trial_outstanding(&sh.trials).saturating_add(amount);
        if live > trial_max_outstanding_sat() {
            return Err(fail(
                StatusCode::CONFLICT,
                "trial_cap_reached",
                "unpaid trials would exceed the sponsor cap; repay first",
            ));
        }
        let record = TrialRecord {
            agent,
            amount_sat: amount,
            sponsor,
            state: TrialState::Requested,
            fund_txid: None,
            repay_txid: None,
            requested_height: sh.chain.height(),
        };
        sh.trials.insert(agent, record.clone());
        audit_push(
            sh,
            "trial_request",
            None,
            Some(amount),
            format!("trial {} drip {}", address_to_hex(&agent), amount),
        );
        Ok(Json(trial_json(&record)))
    })?
}

/// `POST /v1/trials/fund` — confirm an L1 payment to the agent covering the
/// trial amount. The tx must be confirmed on this node's chain; who sent it
/// is not checked (a self-funded trial buys nothing — the agent could have
/// deposited directly — while the receipt check is what gates progress).
/// A fund whose tx later orphans off the chain may be re-confirmed with its
/// replacement: the books follow the chain, never lead it.
async fn trial_fund(State(state): State<ApiState>, Json(req): Json<TrialTxReq>) -> ApiResult {
    let agent = decode_address(&req.agent_hex)?;
    let txid = decode_hash512(&req.txid_hex)?;
    with_shared(&state, |sh| {
        let trial = sh.trials.get(&agent).cloned().ok_or_else(|| {
            fail(
                StatusCode::NOT_FOUND,
                "no_trial",
                "no trial recorded for this agent — request one first",
            )
        })?;
        match trial.state {
            TrialState::Requested => {}
            TrialState::Funded => {
                // Idempotent re-confirmation, or a re-fund after the recorded
                // payment orphaned off the chain. A live funding cannot be
                // replaced by pointing at another payment.
                if trial.fund_txid == Some(txid)
                    && confirmed_payment_to(&sh.chain, &txid, &agent, trial.amount_sat)
                {
                    return Ok(Json(trial_json(&trial)));
                }
                if let Some(old) = trial.fund_txid {
                    if confirmed_payment_to(&sh.chain, &old, &agent, trial.amount_sat) {
                        return Err(fail(
                            StatusCode::CONFLICT,
                            "trial_funded",
                            "this trial already has a confirmed funding payment",
                        ));
                    }
                }
            }
            TrialState::Repaid => {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "trial_closed",
                    "this trial is repaid and closed",
                ));
            }
        }
        if trial_txid_used(&sh.trials, Some(&agent), &txid) {
            return Err(fail(
                StatusCode::CONFLICT,
                "txid_reused",
                "one L1 payment funds at most one trial",
            ));
        }
        if !confirmed_payment_to(&sh.chain, &txid, &agent, trial.amount_sat) {
            return Err(fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "trial_unfunded",
                "no confirmed L1 payment of the trial amount to this agent in that tx",
            ));
        }
        let mut updated = trial.clone();
        updated.state = TrialState::Funded;
        updated.fund_txid = Some(txid);
        sh.trials.insert(agent, updated.clone());
        audit_push(
            sh,
            "trial_fund",
            None,
            Some(trial.amount_sat),
            format!(
                "trial {} funded by {}",
                address_to_hex(&agent),
                hash512_to_hex(&txid)
            ),
        );
        Ok(Json(trial_json(&updated)))
    })?
}

/// `GET /v1/trials/{agent}` — the trial record and its state.
async fn trial_get(State(state): State<ApiState>, Path(raw): Path<String>) -> ApiResult {
    let agent = decode_address(&raw)?;
    with_shared(&state, |sh| {
        sh.trials
            .get(&agent)
            .map(|t| Ok(Json(trial_json(t))))
            .unwrap_or_else(|| {
                Err(fail(
                    StatusCode::NOT_FOUND,
                    "no_trial",
                    "no trial recorded for this agent",
                ))
            })
    })?
}

/// `POST /v1/trials/repay` — confirm the agent's L1 repayment to the sponsor.
/// Same confirmation rule as funding: the tx must be on this node's chain and
/// pay the sponsor at least the trial amount. A repayment that orphans may be
/// re-confirmed with its replacement.
async fn trial_repay(State(state): State<ApiState>, Json(req): Json<TrialTxReq>) -> ApiResult {
    let agent = decode_address(&req.agent_hex)?;
    let txid = decode_hash512(&req.txid_hex)?;
    with_shared(&state, |sh| {
        let trial = sh.trials.get(&agent).cloned().ok_or_else(|| {
            fail(
                StatusCode::NOT_FOUND,
                "no_trial",
                "no trial recorded for this agent — request one first",
            )
        })?;
        if trial.state != TrialState::Funded {
            return Err(fail(
                StatusCode::CONFLICT,
                "trial_not_due",
                "only a funded trial can be repaid",
            ));
        }
        if let Some(old) = trial.repay_txid {
            if old == txid
                && confirmed_payment_to(&sh.chain, &txid, &trial.sponsor, trial.amount_sat)
            {
                return Ok(Json(trial_json(&trial)));
            }
            if confirmed_payment_to(&sh.chain, &old, &trial.sponsor, trial.amount_sat) {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "trial_repaid",
                    "this trial already has a confirmed repayment",
                ));
            }
        }
        if trial_txid_used(&sh.trials, Some(&agent), &txid) {
            return Err(fail(
                StatusCode::CONFLICT,
                "txid_reused",
                "one L1 payment repays at most one trial",
            ));
        }
        if !confirmed_payment_to(&sh.chain, &txid, &trial.sponsor, trial.amount_sat) {
            return Err(fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "trial_unpaid",
                "no confirmed L1 payment of the trial amount back to the sponsor in that tx",
            ));
        }
        let mut updated = trial.clone();
        updated.state = TrialState::Repaid;
        updated.repay_txid = Some(txid);
        sh.trials.insert(agent, updated.clone());
        audit_push(
            sh,
            "trial_repay",
            None,
            Some(trial.amount_sat),
            format!(
                "trial {} repaid by {}",
                address_to_hex(&agent),
                hash512_to_hex(&txid)
            ),
        );
        Ok(Json(trial_json(&updated)))
    })?
}

// ---------------------------------------------------------------------------
// Always-on + exposed middleware (SPEC.md §19.2: opt-in, loopback by default)
// ---------------------------------------------------------------------------
// `dos_guard` always runs (timeout + in-flight cap, on every bind including
// loopback). `exposed_auth` (Host check + bearer + per-IP rate limit) runs only
// when the API is bound non-loopback with a token. Loopback-only binds, which
// every test uses, stay unauthenticated by design.

pub fn router(state: ApiState, cfg: &ApiConfig) -> Router {
    let mut app = Router::new();
    app = app
        .route("/v1/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/conservation", get(conservation))
        .route("/v1/finality", get(finality))
        .route("/v1/fees", get(fee_schedule))
        .route("/v1/balance/{address}", get(balance))
        .route("/v1/utxo/{address}", get(utxos))
        .route("/v1/block/latest", get(block_latest))
        .route("/v1/block/{hash}", get(block_by_hash))
        .route("/v1/mine/template", get(mine_template))
        .route("/v1/mine/submit", post(mine_submit))
        .route("/v1/tx/{hash}", get(tx_lookup))
        .route("/v1/mempool", get(mempool_view))
        .route("/v1/tx/build", post(tx_build))
        .route("/v1/tx/broadcast", post(tx_broadcast))
        .route("/v1/l2/broadcast", post(l2_broadcast))
        .route("/v1/tasks/open", get(tasks_open))
        .route("/v1/task/{task_id}", get(task_by_id))
        .route("/v1/l2/state", get(l2_state))
        .route("/v1/vwc/{task_id}", get(vwc_by_task))
        .route("/v1/policies", get(policies))
        .route("/v1/policies/{agent_id}", get(policy_by_agent))
        .route("/v1/credit/positions", get(credit_positions))
        .route("/v1/credit/positions/{id}", get(credit_position_by_id))
        .route("/v1/reputation/{id}", get(reputation_get))
        .route("/v1/authorize", post(authorize))
        .route("/v1/policy/decide", post(policy_decide))
        .route("/v1/delegation/verify", post(delegation_verify))
        .route("/v1/audit/verify", post(audit_verify_route))
        .route("/v1/delegation/link", post(delegation_link))
        .route("/v1/policy/revoke", post(policy_revoke))
        .route("/v1/payment/submit", post(payment_submit))
        .route("/v1/payment/{payment_id}", get(payment_get))
        .route("/v1/payment/{payment_id}/settle", post(payment_settle))
        .route("/v1/receipt", post(receipt_submit))
        .route("/v1/receipt/{receipt_id}", get(receipt_get))
        .route("/v1/credit/deposit", post(credit_deposit))
        .route("/v1/credit/mint", post(credit_mint))
        .route("/v1/credit/bond", post(credit_bond))
        .route("/v1/credit/open", post(credit_open))
        .route("/v1/credit/repay", post(credit_repay))
        .route("/v1/credit/default", post(credit_default))
        .route("/v1/credit/balance/{address}", get(credit_balance))
        .route("/v1/escrow/open", post(escrow_open))
        .route("/v1/escrow/{id}/release", post(escrow_release))
        .route("/v1/escrow/{id}/settle", post(escrow_settle))
        .route("/v1/escrow/{id}", get(escrow_get))
        .route("/v1/exit/crankable", get(exit_crankable))
        .route("/v1/x402/verify", post(x402_verify))
        .route("/v1/x402/settle", post(x402_settle))
        .route("/v1/paid/weather", get(paid_weather))
        .route("/v1/payments/aggregate", post(payments_aggregate))
        .route("/v1/streams/open", post(stream_open))
        .route("/v1/streams/settle", post(stream_settle))
        .route("/v1/streams/{stream_id}", get(stream_get))
        .route("/v1/payments/unsettled", get(payments_unsettled))
        .route("/v1/receipts/orphans", get(receipts_orphans))
        .route("/v1/audit", get(audit_list))
        .route("/v1/risk/policy", get(risk_policy))
        .route("/v1/reputation/passport/attest", post(passport_attest))
        .route("/v1/reputation/batch", post(passport_batch_register))
        .route("/v1/reputation/score/{agent_hex}", get(passport_score))
        .route("/v1/wallet/tier", post(wallet_tier))
        .route("/v1/wallet/tiers/{agent_hex}", get(wallet_tiers))
        .route("/v1/jobs/open", post(job_open))
        .route("/v1/jobs/{job_id}/accept", post(job_accept))
        .route("/v1/jobs/{job_id}/deliver", post(job_deliver))
        .route("/v1/jobs/{job_id}/dispute", post(job_dispute))
        .route("/v1/jobs/{job_id}/resolve", post(job_resolve))
        .route("/v1/jobs/{job_id}", get(job_get))
        .route("/v1/payments/{id}/receipt_status", get(receipt_status))
        .route("/v1/fx/rates", post(fx_rate_register))
        .route("/v1/fx/rates/list", get(fx_rates))
        .route("/v1/fx/quote", post(fx_quote))
        .route("/v1/fx/swap", post(fx_swap))
        .route("/v1/ramp/quote", post(ramp_quote))
        .route("/v1/ramp/quotes", get(ramp_quotes))
        .route("/v1/ramp/intent", post(ramp_intent))
        .route("/v1/ramp/intent/{id}/settle", post(ramp_intent_settle))
        .route("/v1/ramp/intents", get(ramp_intents))
        .route("/v1/loans/offers", post(loan_offer_post))
        .route("/v1/loans/offers/list", get(loan_offers))
        .route("/v1/loans/accept", post(loan_accept))
        .route("/v1/lending/borrower/{addr}", get(lending_borrower))
        .route("/v1/lending/dashboard", get(lending_dashboard))
        .route("/v1/lending/limit/{borrower}", get(lending_limit))
        .route(
            "/v1/lending/collateral/{position_id}",
            get(lending_collateral),
        )
        .route("/v1/lending/autorepay", post(lending_autorepay))
        .route(
            "/v1/lending/autorepay/{borrower}",
            get(lending_autorepay_get),
        )
        .route("/v1/trials/request", post(trial_request))
        .route("/v1/trials/fund", post(trial_fund))
        .route("/v1/trials/{agent}", get(trial_get))
        .route("/v1/trials/repay", post(trial_repay));
    // The stack stays `Router<ApiState>` (no state yet) until the end, where a
    // single `with_state` resolves it to the servable `Router<()>`.
    let mut app: Router<ApiState> = app.layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    // Always-on DoS guard: a per-request deadline and a cap on how many
    // requests are in flight at once. Implemented as a `from_fn_with_state`
    // middleware so it produces a `Response` (never a service error) and
    // satisfies `Router::layer`'s `Into<Infallible>` bound. This protects the
    // runtime even on a loopback bind.
    app = app.layer(from_fn_with_state(cfg.dos(), dos_guard));

    // Host-header validation runs on every bind (DNS-rebinding defense), including
    // loopback; loopback binds are no longer exempt.
    app = app.layer(from_fn_with_state(cfg.host(), host_check));

    if cfg.is_exposed() {
        // Bearer auth and per-IP rate limiting require the API to be exposed.
        // Loopback-only binds stay open for those by design.
        app = app.layer(from_fn_with_state(cfg.auth(), exposed_auth));
    }
    app.with_state(state)
}

/// A middleware refusal in the handlers' `{error, detail}` JSON shape, so rate
/// limits, auth failures and timeouts are parsed by the same decoder as every
/// other error instead of being prose.
fn guard_fail(status: StatusCode, error: &'static str, detail: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error,
            detail: detail.to_string(),
        }),
    )
        .into_response()
}

/// Wrap a plain-text error produced deeper in the stack — axum's default
/// 404/405 and `Json` extractor rejections arrive as `text/plain` — in the
/// same JSON shape the handlers use, so one parser sees every failure.
/// Anything already JSON or non-error passes through untouched.
async fn jsonize_errors(resp: Response) -> Response {
    let status = resp.status();
    if !status.is_client_error() {
        return resp;
    }
    let is_text = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/plain"));
    if !is_text {
        return resp;
    }
    let detail = match axum::body::to_bytes(resp.into_body(), 16 * 1024).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    };
    let error = match status {
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        _ => "bad_request",
    };
    guard_fail(status, error, &detail)
}

/// Always-on guard: bound the in-flight request count, then run the request
/// with a deadline. A peer that can't acquire a permit gets 429; a peer whose
/// request overruns the deadline gets 504. Either way the response is produced
/// here, so the downstream service error stays `Infallible`.
async fn dos_guard(State(cfg): State<DosConfig>, req: Request, next: Next) -> Response {
    let permit = match cfg.concurrency.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return guard_fail(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many concurrent requests",
            )
        }
    };
    match tokio::time::timeout(cfg.timeout, next.run(req)).await {
        Ok(resp) => jsonize_errors(resp).await,
        Err(_) => {
            drop(permit);
            guard_fail(
                StatusCode::GATEWAY_TIMEOUT,
                "timeout",
                "request exceeded the deadline",
            )
        }
    }
}

/// Host-header gate, applied on every bind including loopback. Returns a
/// plain `Response` so the layer stays `Infallible` for `Router::layer`.
async fn host_check(State(cfg): State<HostConfig>, req: Request, next: Next) -> Response {
    // The exact rule lives in `host_allowed` so it is unit-testable without a
    // socket. A refused Host is 403, never a guess.
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    if !host_allowed(&cfg, host) {
        return guard_fail(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Host header not allowed",
        );
    }
    next.run(req).await
}

async fn exposed_auth(
    State(cfg): State<AuthConfig>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    // Per-IP token bucket: shed floods before doing any auth work.
    if !cfg.limiter.check(addr.ip()) {
        return guard_fail(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "request rate exceeded",
        );
    }
    if let Some(token) = &cfg.token {
        let bearer = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.trim());
        use subtle::ConstantTimeEq;
        let provided = bearer.unwrap_or("");
        // Hash both sides to a fixed width first: `ct_eq` is constant time in
        // the bytes it does compare, but it stops at the first difference —
        // and a direct compare against the token leaks its length. SHA-256
        // makes every input exactly 32 bytes, so neither length nor content
        // of the secret escapes.
        let provided_hash = srct_core::hash::sha256(&[provided.as_bytes()]);
        let token_hash = srct_core::hash::sha256(&[token.as_bytes()]);
        if !bool::from(provided_hash[..].ct_eq(&token_hash)) {
            return guard_fail(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or invalid bearer token",
            );
        }
    }
    next.run(req).await
}

/// Start the API on a background thread and return the bound address.
///
/// The socket is bound here (on the caller's thread) so the caller learns the
/// real address even when it asked for port 0 — that is how tests get a free
/// port without racing. The runtime lives entirely inside the thread: it
/// exists to accept connections and parse HTTP, nothing else.
///
/// A non-loopback bind is refused unless `token` is set, because exposing this
/// surface without authentication is an operator decision the node will not
/// make silently.
pub fn spawn(
    shared: Arc<Mutex<SharedNode>>,
    peers: Arc<AtomicUsize>,
    listen: SocketAddr,
    token: Option<String>,
) -> Result<SocketAddr, String> {
    spawn_with_options(shared, peers, listen, token, Vec::new(), Vec::new())
}

/// Start the API like [`spawn`], additionally allowlisting hostnames for the
/// Host-header check on a non-loopback bind (`--api-allowed-host` /
/// `SRCT_API_ALLOWED_HOSTS`) and naming the BLS keys trusted to sign credit
/// attestations (`--credit-issuer`). Entries are normalized (lowercased, port
/// stripped); empties are dropped.
pub fn spawn_with_options(
    shared: Arc<Mutex<SharedNode>>,
    peers: Arc<AtomicUsize>,
    listen: SocketAddr,
    token: Option<String>,
    allowed_hosts: Vec<String>,
    credit_issuers: Vec<srct_core::bls_checkpoint::BlsPublicKey>,
) -> Result<SocketAddr, String> {
    // An empty token is no token: the guard below filters empties out of the
    // config, so accepting `Some("")` here would pass the refusal and then
    // run the exposed surface unauthenticated.
    if !listen.ip().is_loopback() && token.as_deref().unwrap_or("").is_empty() {
        return Err(format!(
            "refusing non-loopback API bind {listen} without a bearer token: \
             set SRCT_API_TOKEN and supply --api-listen, or bind loopback \
             (SPEC.md §19.2)"
        ));
    }
    let std_listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("api bind {listen}: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("api listener: {e}"))?;
    let addr = std_listener
        .local_addr()
        .map_err(|e| format!("api listener: {e}"))?;
    let non_empty_token = token.filter(|t| !t.is_empty());
    let cfg = ApiConfig {
        token: non_empty_token.clone(),
        bind_host: listen.ip().to_string(),
        bind_loopback: listen.ip().is_loopback(),
        allowed_hosts: allowed_hosts
            .iter()
            .filter_map(|h| normalize_host(h))
            .filter(|h| !h.is_empty())
            .collect(),
        concurrency: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENCY)),
        limiter: RateLimiter::default(),
    };
    let app = router(
        ApiState {
            shared,
            peers,
            credit_issuers,
            exposed: cfg.is_exposed(),
        },
        &cfg,
    );

    std::thread::Builder::new()
        .name("srct-api".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("api: runtime init failed: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                // Bound inside this runtime's context so the socket registers
                // with the reactor: `from_std` must run where a reactor exists.
                // A conversion failure is reported on stderr, not panicked:
                // this thread owns the whole API surface, and a panic here
                // aborts the node under the release profile.
                let listener = match tokio::net::TcpListener::from_std(std_listener) {
                    Ok(listener) => listener,
                    Err(e) => {
                        eprintln!("api: listener conversion failed: {e}");
                        return;
                    }
                };
                // A manual accept loop rather than `axum::serve`, for the two
                // bounds that exposes and `axum::serve` does not: a cap on
                // concurrent *connections* (`MAX_CONCURRENCY` only counts
                // requests that reached the router, so sockets stuck in the
                // header phase need their own bound) and hyper's header-read
                // deadline, which only arms with a timer installed.
                let connections = Arc::new(tokio::sync::Semaphore::new(MAX_API_CONNECTIONS));
                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok(x) => x,
                        Err(e) => {
                            // Accept failures are transient (EMFILE, an aborted
                            // handshake): the API outlives them instead of
                            // exiting with this thread.
                            eprintln!("api: accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                        // Over the cap: close before reading a single byte.
                        drop(stream);
                        continue;
                    };
                    let app = app.clone();
                    tokio::spawn(async move {
                        // `ConnectInfo` on every request: without it the
                        // `exposed_auth` extractor on an exposed bind finds
                        // nothing and every request fails 500 — the peer's
                        // address is what the per-IP rate limiter keys on.
                        // hyper hands each request's `Incoming` body to the
                        // service; the Router takes axum's `Body`, which wraps
                        // any http body.
                        let svc = tower::service_fn(move |mut req: axum::http::Request<_>| {
                            req.extensions_mut().insert(ConnectInfo(peer));
                            let req = req.map(axum::body::Body::new);
                            let mut app = app.clone();
                            async move { app.call(req).await }
                        });
                        let mut builder = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        );
                        builder.http1().timer(hyper_util::rt::TokioTimer::new());
                        builder.http1().header_read_timeout(HEADER_READ_TIMEOUT);
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let _ = builder
                            .serve_connection_with_upgrades(
                                io,
                                hyper_util::service::TowerToHyperService::new(svc),
                            )
                            .await;
                        // Released only when the connection is fully closed: the
                        // cap holds for a connection's whole life, not a request.
                        drop(permit);
                    });
                }
            });
        })
        .map_err(|e| format!("api thread: {e}"))?;
    Ok(addr)
}

#[cfg(test)]
mod high_value_tests {
    use super::*;
    use srct_core::l2::Auth;
    use srct_core::sig::Bundle;
    use srct_core::wallet::Wallet;

    /// Env vars are process-global, so these tests own their keys outright:
    /// no other test in this binary reads `SRCT_HIGH_VALUE_*`, and each case
    /// removes what it sets even on panic paths (the guard drops on unwind).
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            // `set_var` is process-global by nature; this module is the only
            // reader/writer of these two keys in the test binary.
            unsafe { std::env::set_var(key, value) };
            EnvGuard { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    /// Serializes the env-touching tests below: env vars are process-global
    /// and Rust runs tests on threads, so two of these tests racing on
    /// `SRCT_HIGH_VALUE_APPROVERS` would read each other's values.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn payer_and_payment(amount: u64) -> (Wallet, MachinePayment) {
        let wallet = Wallet::new_random("payer");
        let owner = wallet.address().unwrap();
        let auth = srct_core::agent::Authorization {
            version: srct_core::agent::POLICY_VERSION,
            policy_hash: [0xABu8; 32],
            agent_id: srct_core::agent::derive_agent_id(
                "srct/testnet",
                srct_core::agent::AgentRole::Machine,
                &owner,
            ),
            owner,
            recipient: [0xCDu8; 20],
            amount_sat: amount,
            service: None,
            height: 1,
            nonce: 1,
        };
        let payment = srct_core::payment::build_signed_payment(
            &wallet,
            &auth,
            "srct/testnet",
            srct_core::agent::AgentRole::Machine,
            0,
            100,
            [0u8; 32],
            &[],
        )
        .unwrap();
        (wallet, payment)
    }

    fn approval_for(wallet: &Wallet, payment_id: &Hash) -> (Bundle, Bundle) {
        (
            Auth::sigs_for(wallet, payment_id).unwrap(),
            Auth::keys_for(wallet).unwrap(),
        )
    }

    fn hex_addr(a: &srct_core::hash::Address) -> String {
        hex::encode(a)
    }

    #[test]
    fn approver_list_parses_csv_and_skips_garbage() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(
            "SRCT_HIGH_VALUE_APPROVERS",
            " 0x0102030405060708090a0b0c0d0e0f1011121314 , not-an-address, 0x0102030405060708090a0b0c0d0e0f1011121314",
        );
        let list = high_value_approvers();
        assert_eq!(list.len(), 2, "garbage entries are skipped, not fatal");
        assert_eq!(list[0], list[1]);
        let _h = EnvGuard::set("SRCT_HIGH_VALUE_APPROVERS", "");
        let _ = _g;
        assert!(high_value_approvers().is_empty());
    }

    #[test]
    fn high_payment_without_approval_is_refused() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("SRCT_HIGH_VALUE_APPROVERS", &hex_addr(&[0x99u8; 20]));
        let (_payer, payment) = payer_and_payment(1_000_000);
        let id = payment.signing_hash();
        let err = require_high_value_approval(&payment, id, None).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn unlisted_and_self_approvals_are_refused_but_listed_passes() {
        let _lock = ENV_LOCK.lock().unwrap();
        let approver = Wallet::new_random("approver");
        let approver_addr = approver.address().unwrap();
        let _g = EnvGuard::set("SRCT_HIGH_VALUE_APPROVERS", &hex_addr(&approver_addr));
        let (payer, payment) = payer_and_payment(1_000_000);
        let id = payment.signing_hash();

        // A stranger's co-signature is not an approval.
        let stranger = Wallet::new_random("stranger");
        let (ss, sk) = approval_for(&stranger, &id);
        let err = require_high_value_approval(&payment, id, Some((&ss, &sk))).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        // Neither is the payer approving its own spend: the second key must
        // be a second human, not a second signature from the same hand.
        let (ps, pk) = approval_for(&payer, &id);
        let err = require_high_value_approval(&payment, id, Some((&ps, &pk))).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        // The listed approver passes.
        let (asigs, akeys) = approval_for(&approver, &id);
        require_high_value_approval(&payment, id, Some((&asigs, &akeys))).unwrap();
    }
}
