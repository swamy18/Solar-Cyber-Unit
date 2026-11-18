//! `L2State`: the deterministic value layer under the task contracts.
//!
//! This is where an L2 transaction actually *does* something. `TaskContract`
//! decides whether a transition is legal; this module decides who pays, in what
//! order, and where every satoshi ends up.
//!
//! Three rules define the model:
//!
//! 1. **Accounts, not UTXOs.** L2 carries a simple account balance per address.
//!    Funding is genesis-explicit ([`L2State::apply_genesis`], SPEC.md §19.4):
//!    the profile's escrow total is released once — grants to named accounts,
//!    remainder to the protocol escrow identity. Two later production credits
//!    exist and both ride L1 blocks: matured deposits (Decision 10,
//!    `apply_deposit`) and the exit debits that pair with them (Decision 19).
//!    What is real today is the accounting below them.
//! 2. **Every explicit transaction pays its D3 flat fee**, split 50/50
//!    burned/PSCB through `fees::split_flat_fee` — the unchanged M1 rule. Implicit
//!    transitions (a deadline passing, a dispute window closing) cost nothing,
//!    because nothing was transacted.
//! 3. **Value is conserved.** An L2 fee or a slashed deposit is *moved*, never
//!    conjured: burned and PSCB satoshis leave the account set and land in the
//!    counters, and a slashed deposit lands in the M2 vault. `conservation_total`
//!    is the check, and the integration tests assert it after every scenario.
//!
//! Replay is refused by transaction id, and a failed transaction is not marked
//! applied — a transaction that was rejected for a transient reason (a task not
//! yet posted) can be retried once the precondition holds, but it can never be
//! applied twice.

use std::collections::{BTreeMap, HashMap, HashSet};

use srct_core::agent::{AgentId, PolicyEntry, SpendPolicy};
use srct_core::bls_checkpoint::{BlsSignature, BlsVerifier, ValidatorSet};
use srct_core::credit::{ChargeSchedule, CreditTerms};
use srct_core::delegation;
use srct_core::fees::split_flat_fee;
use srct_core::hash::{Address, Hash, Hash512};
use srct_core::l2::{
    settle_fee_sat, AgentSpendPayload, ClaimTaskPayload, CreditCollateralPayload,
    CreditDefaultPayload, CreditOpenPayload, CreditOpenV2Payload, CreditRepayPayload,
    DisputePayload, ExitQueuePayload, L2Payload, L2Transaction, PolicyPayload, PolicyRevokePayload,
    PostTaskPayload, SettlePayload, SubmitResultPayload, Verdict, MIN_EXIT_FEE_SAT, VWC_HASH_EXPIRED,
};
use srct_core::params::MAX_CREDIT_RATE_BPS_PER_WINDOW;
use srct_core::ser::{Reader, Writer};
use srct_core::slash::SlashVault;
use srct_core::state_root::{
    account_leaf, exit_record_leaf, exit_record_leaf_v7, prove_inclusion, state_root,
    InclusionProof,
};

use crate::error::{L2Error, L2Result};
use crate::genesis::L2Genesis;
use crate::task_contract::{ContractState, L2Config, SettlementOutcome, TaskContract};
use crate::vwc::{VerifiedWorkCertificate, VwcVerification};

/// What an applied transaction did, for logging, tests and (later) event streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Effect {
    Posted {
        task_id: Hash,
        submitter: Address,
        payment_sat: u64,
    },
    Claimed {
        task_id: Hash,
        worker: Address,
    },
    ResultSubmitted {
        task_id: Hash,
        worker: Address,
        result_hash: Hash,
    },
    DisputeFiled {
        task_id: Hash,
        challenger: Address,
    },
    Settled {
        task_id: Hash,
        verdict: Verdict,
        worker_paid: u64,
        submitter_refunded: u64,
        worker_deposit_slashed: u64,
        /// Whistleblower bounty paid from the PSCB reserve (Phase 3). Zero
        /// unless the challenge was upheld and the reserve had funds.
        challenger_bonus: u64,
        /// The Verified Work Certificate issued by this settlement (Phase 4).
        /// `Some` only for a `Correct` settlement of real work; `Fraudulent`
        /// and `Expired` issue nothing (SPEC.md §17.4).
        vwc_id: Option<Hash>,
    },
    Expired {
        task_id: Hash,
        submitter_refunded: u64,
        worker_deposit_burned: u64,
    },
    ExitQueued {
        owner: Address,
        nonce: u64,
        amount_sat: u64,
        destination: Address,
    },
    ExitReleased {
        owner: Address,
        nonce: u64,
        amount_sat: u64,
        destination: Address,
    },
    /// A spending policy was published (SPEC.md §21.1).
    PolicyPublished {
        policy_hash: Hash,
        agent_id: AgentId,
        spender: Address,
    },
    /// A spending policy was revoked by its owner (SPEC.md §21.2).
    PolicyRevoked {
        agent_id: AgentId,
    },
    /// A spend was made under a published policy (SPEC.md §21.3).
    AgentSpent {
        policy_hash: Hash,
        agent: Address,
        recipient: Address,
        amount_sat: u64,
    },
    /// A credit position was opened (SPEC.md §22.3).
    CreditOpened {
        position_id: Hash,
        lender: Address,
        borrower: Address,
        amount_sat: u64,
    },
    /// Collateral was added to a credit position (SPEC.md §22.4).
    CreditCollateralAdded {
        position_id: Hash,
        borrower: Address,
        amount_sat: u64,
    },
    /// A credit position was repaid (SPEC.md §22.5).
    CreditRepaid {
        position_id: Hash,
        borrower: Address,
        amount_sat: u64,
        interest_paid_sat: u64,
        principal_paid_sat: u64,
        remaining_debt_sat: u64,
    },
    /// A credit position was settled as a default (SPEC.md §22.6).
    CreditDefaulted {
        position_id: Hash,
        lender: Address,
        debt_sat: u64,
        from_collateral_sat: u64,
        shortfall_sat: u64,
        excess_returned_sat: u64,
    },
    /// A guarded account was opted in (Phase 3).
    GuardedOptedIn { owner: Address, guardian: Address },
    /// A guarded action was taken (cancel/freeze, Phase 3).
    GuardedAction { account: Address, kind: &'static str },
    /// An audit root was anchored (Phase 3).
    AuditAnchored { anchorer: Address, root: Hash },
    /// Generic catch-all for future effects (kept for extensibility).
    Custom(&'static str),
}

/// Equality here is *state* equality: two nodes that replayed the same
/// canonical chain hold equal `L2State`s, which is what Phase 6's replay and
/// cross-node agreement checks assert (SPEC.md §19.1). It is derived, so it
/// compares every field — accounts, tasks, the applied-id set, the counters,
/// the vault and the certificate registry — rather than a hand-picked subset
/// that could silently stop covering a new one.
#[derive(Debug, Clone, PartialEq)]
pub struct L2State {
    config: L2Config,
    accounts: HashMap<Address, u64>,
    tasks: HashMap<Hash, TaskContract>,
    /// Transaction ids that have been applied. Replay protection.
    applied: HashSet<Hash512>,
    /// Every satoshi ever released into L2: genesis allocation plus test
    /// credits. Append-only. `conservation_total() == funded_total()` is the
    /// M2 invariant — value is moved, never created — and a production state
    /// whose `funded_total` exceeds its profile's escrow total proves an
    /// unauthorized funding happened.
    funded_total: u64,
    /// Whether the genesis allocation was applied to this state. Exactly-once
    /// by construction (only the constructors apply it, to fresh state) and
    /// enforced by flag: a second application is refused rather than
    /// double-funding every grant.
    genesis_applied: bool,
    /// Deposit `(txid, output_index)` identities already credited (Decision 10
    /// item 5, SPEC.md §19.5). The same L1 bytes in a later block hit this set
    /// and are refused — replay protection for value that arrives via blocks
    /// rather than via L2 transactions (which have the separate `applied` set).
    deposits: HashSet<(Hash512, u32)>,
    /// Satoshis credited through deposits, append-only. Feeds `funded_total`
    /// (every deposit credit counts there too) and lets `verify` prove
    /// `funded == escrow + deposits` — i.e. no unauthorized funding — without
    /// re-scanning blocks.
    deposited_total: u64,
    /// Permanently destroyed satoshis (fees + failed-challenge and expiry burns).
    pub burned: u64,
    /// Protocol Security & Compute Buffer accrual from L2 fees (M1).
    pub pscb: u64,
    /// M2 slash vault. Fraud slashes vest here.
    pub slash_vault: SlashVault,
    /// Verified Work Certificates, keyed by task id (Phase 4, SPEC.md §17.7).
    /// Certificates hold no value, so they are outside the conservation sum.
    vwcs: HashMap<Hash, VerifiedWorkCertificate>,
    /// Queued L2 → L1 exits, keyed by `(owner, nonce)` (approved P1). A record
    /// exists from queue until release; release *removes* it rather than
    /// flagging it, so the map is exactly the outstanding-exit set and replay
    /// re-derives it from the winning chain with no persisted ledger.
    exits: HashMap<(Address, u64), ExitRecord>,
    /// Last queue nonce used per owner. Strictly increasing nonces are the
    /// replay protection for exits (mirroring the agent authorization
    /// discipline); a repeated or rewound nonce is refused by name.
    exit_nonce: HashMap<Address, u64>,
    /// Value currently encumbered in queued exits (`amount + exit_fee` per
    /// record). Part of the conservation sum: queueing moves value out of an
    /// account into this bucket, release moves it out of L2 entirely.
    exits_locked: u64,
    /// Value ever released to L1, append-only. `funded_total` equals genesis
    /// plus deposits minus this — anything else is invented or vanished money.
    exited_total: u64,
    /// Start height of the current exit-principal window. `0` means no window
    /// is open yet; the first queue at or above `height` opens one. Derived
    /// by replay like everything else in this struct — a reorg replays the
    /// winning chain, so windows always describe the chain they were built
    /// on, with no undo bookkeeping.
    exit_window_start: u64,
    /// Exit principal queued inside the current window. Refusals keep funds
    /// in place (only the window delays the queue), so this is a throttle,
    /// never a taking.
    exit_window_total: u64,
    /// Per-owner queued principal inside the current window. Same replay
    /// derivation as the total (reset on rollover, rebuilt by replay): the
    /// fairness bound that stops one actor filling the whole window and
    /// starving every other owner until it rolls over.
    exit_window_owner: BTreeMap<Address, u64>,
    /// Published spending policies, keyed by the grant's hash (SPEC.md §21.1).
    /// A revoked grant stays in the map for the record; revocation is a flag on
    /// the entry, and a descendant of a revoked grant is dead by ancestry
    /// rather than by a second revocation transaction per link.
    policies: BTreeMap<Hash, PolicyEntry>,
    /// The live grant for each agent, by agent identity. One grant per agent at
    /// a time, so a second grant cannot be used to double the first one's caps.
    policy_by_agent: BTreeMap<AgentId, Hash>,
    /// Credit positions, keyed by position id (SPEC.md §22). A position holds
    /// no value of its own: the principal has already moved to the borrower,
    /// and the collateral is held in the `credit_locked` bucket.
    positions: BTreeMap<Hash, CreditPosition>,
    /// Collateral locked against credit positions. Part of the conservation
    /// sum: it is in the system, but not spendable.
    credit_locked: u64,
    /// Guarded accounts (Phase 3), keyed by owner address. An opt-in protected
    /// account with its own record (leaf tag 0x07, state wire 8). Opt-in is per
    /// account only, never a global key. Guarded accounts protect L2 balances;
    /// they must never become a place where L1-destined earnings get stuck.
    guarded: BTreeMap<Address, GuardedAccount>,
    /// Audit anchor roots (Phase 3), keyed by anchor id. Commits an off-chain
    /// audit Merkle root on-chain. No dust-to-derived-address hack.
    audit_anchors: BTreeMap<Hash, AuditAnchorRecord>,
}

/// One queued L2 → L1 exit: the exact record the L1 release proof re-states.
///
/// The leaf committed under the L2 state root is computed from these fields
/// only (see [`L2State::committed_root`]); maturity and release are judged by
/// consensus against the chain, never by this hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRecord {
    pub owner: Address,
    pub nonce: u64,
    pub amount_sat: u64,
    pub destination: Address,
    pub exit_fee_sat: u64,
    pub queued_height: u64,
    /// True when the owner was guarded at queue time. Committed in the leaf
    /// (v8) so L1 can distinguish guarded exits without L2 state access:
    /// guarded claims must prove against a post-delay root.
    pub guarded: bool,
}

impl ExitRecord {
    /// Fixed 72-byte v7 encoding: owner(20) + nonce(8) + amount(8) +
    /// destination(20) + fee(8) + height(8). Fixed size, so the wire count is
    /// bounded by the buffer with no prefix to lie about. v8 appends one
    /// guarded byte (73 total); v7 blobs decode with `guarded: false`.
    pub const ENCODED_LEN: usize = 72;

    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.owner)
            .u64le(self.nonce)
            .u64le(self.amount_sat)
            .fixed(&self.destination)
            .u64le(self.exit_fee_sat)
            .u64le(self.queued_height)
            .u8(u8::from(self.guarded));
    }

    /// v7 decode: 72-byte records, no guarded flag (pre-activation exits are
    /// never guarded, and guarded mode did not exist).
    pub fn decode(r: &mut Reader<'_>) -> L2Result<Self> {
        Self::decode_inner(r, false)
    }

    fn decode_inner(r: &mut Reader<'_>, guarded_default: bool) -> L2Result<Self> {
        let owner: Address = r.fixed().map_err(|_| codec_err("exit owner"))?;
        let nonce = r.u64le().map_err(|_| codec_err("exit nonce"))?;
        let amount_sat = r.u64le().map_err(|_| codec_err("exit amount"))?;
        let destination: Address = r.fixed().map_err(|_| codec_err("exit destination"))?;
        let exit_fee_sat = r.u64le().map_err(|_| codec_err("exit fee"))?;
        let queued_height = r.u64le().map_err(|_| codec_err("exit height"))?;
        Ok(ExitRecord {
            owner,
            nonce,
            amount_sat,
            destination,
            exit_fee_sat,
            queued_height,
            guarded: guarded_default,
        })
    }

    pub fn decode_v8(r: &mut Reader<'_>) -> L2Result<Self> {
        let mut rec = Self::decode_inner(r, false)?;
        rec.guarded = match r.u8().map_err(|_| codec_err("exit guarded flag"))? {
            0 => false,
            1 => true,
            _ => return Err(codec_err("exit guarded flag out of range")),
        };
        Ok(rec)
    }

    /// The committed leaf for this exit. Unguarded exits keep the exact
    /// pre-upgrade encoding (byte-identical to v7), so all existing roots,
    /// proofs, and tests are untouched. Guarded exits commit one extra flag
    /// byte: the guarded bit is part of what the Merkle proof binds, which is
    /// what makes a legacy (unguarded) claim against a guarded exit fail
    /// closed without any extra flag to trust.
    pub fn leaf(&self) -> Hash {
        if self.guarded {
            exit_record_leaf(
                &self.owner,
                self.nonce,
                self.amount_sat,
                &self.destination,
                self.exit_fee_sat,
                self.queued_height,
                true,
            )
        } else {
            Self::leaf_v7_inner(self)
        }
    }

    /// v7 leaf: byte-identical to the pre-guarded format.
    pub fn leaf_v7(&self) -> Hash {
        Self::leaf_v7_inner(self)
    }

    fn leaf_v7_inner(r: &ExitRecord) -> Hash {
        exit_record_leaf_v7(
            &r.owner,
            r.nonce,
            r.amount_sat,
            &r.destination,
            r.exit_fee_sat,
            r.queued_height,
        )
    }
}

/// A guarded L2 account (Phase 3). Opt-in per account only, never global.
/// Protects L2 balances with guardian oversight, delayed allow-lists, and
/// price-independent caps. Must never become a place where L1-destined
/// earnings get stuck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedAccount {
    /// The protected account owner.
    pub owner: Address,
    /// Guardian address (independent of owner, enforced distinct). Signs
    /// GuardedCancel/GuardedFreeze and co-signs high-value transfers.
    pub guardian: Address,
    /// Destination allow-list for exits and AgentSpend recipients. Changes
    /// take effect only after `allowlist_delay_blocks`.
    pub allow_list: Vec<Address>,
    /// Height at which the current allow-list became active.
    pub allowlist_active_height: u64,
    /// Pending allow-list change (new list + activation height), if any.
    pub pending_allowlist: Option<(Vec<Address>, u64)>,
    /// Grant-activation delay D (blocks). Policies for guarded owners require
    /// `not_before_height >= publish_height + D`. Revocation stays instant.
    pub grant_delay_blocks: u64,
    /// Maximum grant lifetime in blocks (`expires_at - not_before <= max`).
    pub max_grant_lifetime_blocks: u64,
    /// Balance-relative outflow cap in basis points per window (e.g. 1000 = 10%).
    /// Total outflow per window <= balance_snapshot * bps / 10000.
    pub outflow_cap_bps: u64,
    /// Window length for outflow cap in blocks.
    pub outflow_window_blocks: u64,
    /// Balance snapshot at window start (prevents mid-window deposit inflation).
    pub window_balance_snapshot: u64,
    /// Window start height (0 = no window open yet).
    pub window_start_height: u64,
    /// Outflow total inside current window.
    pub window_outflow_total: u64,
    /// Whether the account is frozen by guardian (halts all outflows).
    pub frozen: bool,
    /// Height at which the opt-in took effect.
    pub created_height: u64,
}

impl GuardedAccount {
    pub fn leaf(&self) -> Hash {
        use srct_core::hash::sha256_dom;
        use srct_core::ser::Writer;
        // Domain-separated leaf: tag 0x07 + owner + guardian + allow-list commitment
        // + delays + caps + frozen flag + heights. Allow-list hashed (not listed)
        // to keep leaves constant-size regardless of list length.
        const DOM_GUARDED_LEAF: &[u8] = b"srct/l2/guarded-leaf/v1";
        let mut w = Writer::new();
        w.fixed(&self.owner).fixed(&self.guardian);
        // Allow-list commitment: sorted join hashed.
        let mut sorted = self.allow_list.clone();
        sorted.sort_unstable();
        let mut lw = Writer::new();
        for a in &sorted {
            lw.fixed(a);
        }
        w.fixed(&sha256_dom(DOM_GUARDED_LEAF, &[lw.as_slice()]));
        w.u64le(self.allowlist_active_height)
            .u64le(self.grant_delay_blocks)
            .u64le(self.max_grant_lifetime_blocks)
            .u64le(self.outflow_cap_bps)
            .u64le(self.outflow_window_blocks)
            .u64le(self.window_balance_snapshot)
            .u64le(self.window_start_height)
            .u64le(self.window_outflow_total)
            .u8(u8::from(self.frozen))
            .u64le(self.created_height);
        // Pending allow-list (if any) committed too.
        if let Some((list, height)) = &self.pending_allowlist {
            let mut pw = Writer::new();
            let mut s2 = list.clone();
            s2.sort_unstable();
            for a in &s2 {
                pw.fixed(a);
            }
            w.fixed(&sha256_dom(DOM_GUARDED_LEAF, &[pw.as_slice()]))
                .u64le(*height);
        } else {
            w.fixed(&[0u8; 32]).u64le(0);
        }
        srct_core::state_root::guarded_account_leaf(&w.into_vec())
    }

    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.owner).fixed(&self.guardian);
        w.u64le(self.allow_list.len() as u64);
        for a in &self.allow_list {
            w.fixed(a);
        }
        w.u64le(self.allowlist_active_height);
        match &self.pending_allowlist {
            None => {
                w.u64le(0);
            }
            Some((list, height)) => {
                w.u64le(list.len() as u64);
                for a in list {
                    w.fixed(a);
                }
                w.u64le(*height);
            }
        }
        w.u64le(self.grant_delay_blocks)
            .u64le(self.max_grant_lifetime_blocks)
            .u64le(self.outflow_cap_bps)
            .u64le(self.outflow_window_blocks)
            .u64le(self.window_balance_snapshot)
            .u64le(self.window_start_height)
            .u64le(self.window_outflow_total)
            .u8(u8::from(self.frozen))
            .u64le(self.created_height);
    }

    pub fn decode(r: &mut Reader) -> L2Result<Self> {
        let owner: Address = r.fixed().map_err(|_| codec_err("guarded owner"))?;
        let guardian: Address = r.fixed().map_err(|_| codec_err("guardian"))?;
        let n = r.u64le().map_err(|_| codec_err("allow-list len"))? as usize;
        if n > 10_000 {
            return Err(codec_err("allow-list too long"));
        }
        let mut allow_list = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            allow_list.push(r.fixed().map_err(|_| codec_err("allow-list entry"))?);
        }
        let m = r.u64le().map_err(|_| codec_err("pending allow-list len"))? as usize;
        let pending_allowlist = if m == 0 {
            None
        } else {
            if m > 10_000 {
                return Err(codec_err("pending allow-list too long"));
            }
            let mut list = Vec::with_capacity(m.min(64));
            for _ in 0..m {
                list.push(r.fixed().map_err(|_| codec_err("pending entry"))?);
            }
            let height = r.u64le().map_err(|_| codec_err("pending height"))?;
            Some((list, height))
        };
        Ok(GuardedAccount {
            owner,
            guardian,
            allow_list,
            allowlist_active_height: r.u64le().map_err(|_| codec_err("allowlist height"))?,
            pending_allowlist,
            grant_delay_blocks: r.u64le().map_err(|_| codec_err("grant delay"))?,
            max_grant_lifetime_blocks: r.u64le().map_err(|_| codec_err("max lifetime"))?,
            outflow_cap_bps: r.u64le().map_err(|_| codec_err("cap bps"))?,
            outflow_window_blocks: r.u64le().map_err(|_| codec_err("cap window"))?,
            window_balance_snapshot: r.u64le().map_err(|_| codec_err("window snapshot"))?,
            window_start_height: r.u64le().map_err(|_| codec_err("window start"))?,
            window_outflow_total: r.u64le().map_err(|_| codec_err("window total"))?,
            frozen: match r.u8().map_err(|_| codec_err("frozen"))? {
                0 => false,
                1 => true,
                _ => return Err(codec_err("frozen flag out of range")),
            },
            created_height: r.u64le().map_err(|_| codec_err("created height"))?,
        })
    }
}

/// An audit anchor record (Phase 3). Commits an off-chain audit Merkle root
/// on-chain. No dust-to-derived-address hack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAnchorRecord {
    pub anchorer: Address,
    pub root: Hash,
    pub height: u64,
    pub nonce: u64,
}

/// Where a credit position stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditPositionState {
    /// The debt is live.
    Open,
    /// The debt was repaid in full; the collateral came back to the borrower.
    Repaid,
    /// The debt was settled as a default at or after its deadline.
    Defaulted,
}

impl CreditPositionState {
    pub fn to_wire(self) -> u8 {
        match self {
            CreditPositionState::Open => 0,
            CreditPositionState::Repaid => 1,
            CreditPositionState::Defaulted => 2,
        }
    }

    pub fn from_wire(b: u8) -> Option<Self> {
        match b {
            0 => Some(CreditPositionState::Open),
            1 => Some(CreditPositionState::Repaid),
            2 => Some(CreditPositionState::Defaulted),
            _ => None,
        }
    }
}

/// One credit position: a loan, as the chain holds it (SPEC.md §22).
///
/// The lender's signature created it, so the debt is one the lender agreed to.
/// The principal has already moved to the borrower; what the chain holds here
/// is the debt and the collateral that secures it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditPosition {
    pub id: Hash,
    pub lender: Address,
    pub borrower: Address,
    /// The principal lent.
    pub principal_sat: u64,
    /// Principal not yet repaid.
    pub outstanding_sat: u64,
    /// Interest already paid to the lender.
    pub interest_paid_sat: u64,
    /// Collateral the borrower has locked. Part of the conservation sum: it is
    /// in the system, but not spendable.
    pub collateral_sat: u64,
    /// Interest per window, in basis points of the outstanding principal.
    pub rate_bps_per_window: u32,
    /// Length of a window, in blocks.
    pub window_blocks: u64,
    /// The height the position was opened at.
    pub opened_height: u64,
    /// The height the debt is due by.
    pub deadline_height: u64,
    /// The height up to which interest has been charged. Interest is charged
    /// once per period on the balance that was outstanding, so two
    /// instalments do not each pay for the whole elapsed time.
    pub interest_settled_height: u64,
    pub state: CreditPositionState,
}

impl CreditPosition {
    /// Fixed-size encoding, so the wire count is bounded by the buffer with no
    /// prefix to lie about.
    pub const ENCODED_LEN: usize = 141;

    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.id)
            .fixed(&self.lender)
            .fixed(&self.borrower)
            .u64le(self.principal_sat)
            .u64le(self.outstanding_sat)
            .u64le(self.interest_paid_sat)
            .u64le(self.collateral_sat)
            .u32le(self.rate_bps_per_window)
            .u64le(self.window_blocks)
            .u64le(self.opened_height)
            .u64le(self.deadline_height)
            .u64le(self.interest_settled_height)
            .u8(self.state.to_wire());
    }

    pub fn decode(r: &mut Reader<'_>) -> L2Result<Self> {
        let id: Hash = r.fixed().map_err(|_| codec_err("credit position id"))?;
        let lender: Address = r.fixed().map_err(|_| codec_err("credit lender"))?;
        let borrower: Address = r.fixed().map_err(|_| codec_err("credit borrower"))?;
        let principal_sat = r.u64le().map_err(|_| codec_err("credit principal"))?;
        let outstanding_sat = r.u64le().map_err(|_| codec_err("credit outstanding"))?;
        let interest_paid_sat = r.u64le().map_err(|_| codec_err("credit interest"))?;
        let collateral_sat = r.u64le().map_err(|_| codec_err("credit collateral"))?;
        let rate_bps_per_window = r.u32le().map_err(|_| codec_err("credit rate"))?;
        let window_blocks = r.u64le().map_err(|_| codec_err("credit window"))?;
        let opened_height = r.u64le().map_err(|_| codec_err("credit opened height"))?;
        let deadline_height = r.u64le().map_err(|_| codec_err("credit deadline"))?;
        let interest_settled_height = r.u64le().map_err(|_| codec_err("credit interest height"))?;
        let state = CreditPositionState::from_wire(r.u8().map_err(|_| codec_err("credit state"))?)
            .ok_or_else(|| codec_err("credit state tag out of range"))?;
        Ok(CreditPosition {
            id,
            lender,
            borrower,
            principal_sat,
            outstanding_sat,
            interest_paid_sat,
            collateral_sat,
            rate_bps_per_window,
            window_blocks,
            opened_height,
            deadline_height,
            interest_settled_height,
            state,
        })
    }

    /// The committed leaf for this position.
    pub fn leaf(&self) -> Hash {
        srct_core::state_root::credit_position_leaf(
            &self.id,
            &self.lender,
            &self.borrower,
            self.principal_sat,
            self.outstanding_sat,
            self.interest_paid_sat,
            self.collateral_sat,
            self.rate_bps_per_window,
            self.window_blocks,
            self.opened_height,
            self.deadline_height,
            self.state.to_wire(),
        )
    }

    /// The charge schedule, as the interest rule sees it.
    pub fn schedule(&self) -> ChargeSchedule {
        ChargeSchedule {
            rate_bps_per_window: self.rate_bps_per_window,
            window_blocks: self.window_blocks,
        }
    }
}

impl L2State {
    pub fn new(config: L2Config) -> Self {
        L2State {
            config,
            accounts: HashMap::new(),
            tasks: HashMap::new(),
            applied: HashSet::new(),
            funded_total: 0,
            genesis_applied: false,
            deposits: HashSet::new(),
            deposited_total: 0,
            burned: 0,
            pscb: 0,
            slash_vault: SlashVault::new(),
            vwcs: HashMap::new(),
            exits: HashMap::new(),
            exit_nonce: HashMap::new(),
            exits_locked: 0,
            exited_total: 0,
            exit_window_start: 0,
            exit_window_total: 0,
            exit_window_owner: BTreeMap::new(),
            policies: BTreeMap::new(),
            policy_by_agent: BTreeMap::new(),
            positions: BTreeMap::new(),
            credit_locked: 0,
            guarded: BTreeMap::new(),
            audit_anchors: BTreeMap::new(),
        }
    }

    /// Release the genesis allocation into this state: grants to named
    /// accounts, remainder to the protocol escrow identity (SPEC.md §19.4).
    ///
    /// Only for freshly constructed states, exactly once. Replay, restart and
    /// reorg all rebuild through constructors that call this once, which is
    /// what makes funding exist exactly once in every derived state without a
    /// persisted funding record.
    pub fn apply_genesis(&mut self, genesis: &L2Genesis) -> L2Result<()> {
        if self.genesis_applied {
            return Err(L2Error::GenesisAlreadyApplied);
        }
        genesis.validate()?;
        for (addr, amount) in &genesis.grants {
            self.credit(*addr, *amount)?;
        }
        let remainder = genesis.escrow_remainder()?;
        if remainder > 0 {
            self.credit(genesis.escrow_id, remainder)?;
        }
        self.genesis_applied = true;
        Ok(())
    }

    /// Whether this state's funding came from genesis (production) rather than
    /// ad-hoc credits (unit tests).
    pub fn has_genesis(&self) -> bool {
        self.genesis_applied
    }

    /// The L1 deposit sink for this state's network: an ordinary address
    /// nobody can spend from (same derivation as
    /// `NetworkParams::l2_deposit_sink`, bound to this state's network id).
    /// An exit naming it as destination would lock value in an unspendable
    /// address — value in, never out — so callers refuse it before building
    /// the payload.
    pub fn deposit_sink(&self) -> Address {
        let digest = srct_core::hash::sha256_dom(
            srct_core::params::DOM_L2_DEPOSIT_SINK,
            &[self.config.network_id.as_bytes()],
        );
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        out
    }

    /// Credit a detected L1 deposit: exactly the sink output's satoshis to the
    /// common input owner, 1:1, no rate, no fee on the credit itself (Decision
    /// 10 item 6).
    ///
    /// The caller (replay) guarantees maturity and detection; this enforces
    /// exactly-once per `(txid, index)` and conservation. A duplicate is
    /// refused by name rather than double-credited — the second occurrence of
    /// the same L1 bytes is a replay, never a second deposit.
    pub fn apply_deposit(
        &mut self,
        recipient: Address,
        amount_sat: u64,
        id: (Hash512, u32),
    ) -> L2Result<()> {
        if self.deposits.contains(&id) {
            return Err(L2Error::DuplicateDeposit);
        }
        if amount_sat == 0 {
            return Err(L2Error::ZeroAmount("deposit"));
        }
        self.credit(recipient, amount_sat)?;
        self.deposits.insert(id);
        self.deposited_total = self
            .deposited_total
            .checked_add(amount_sat)
            .ok_or(L2Error::Overflow)?;
        Ok(())
    }

    /// Whether this deposit identity already credited.
    pub fn deposit_credited(&self, id: &(Hash512, u32)) -> bool {
        self.deposits.contains(id)
    }

    /// Satoshis credited through deposits. `funded_total` equals the genesis
    /// release plus this, minus `exited_total` — anything else is invented or
    /// vanished money.
    pub fn deposited_total(&self) -> u64 {
        self.deposited_total
    }

    pub fn config(&self) -> L2Config {
        self.config.clone()
    }

    // --- accounts ------------------------------------------------------

    /// Add free balance to an address.
    ///
    /// Production calls this only through [`Self::apply_genesis`]: the
    /// Decision 7 bridge funds L2 exactly once, at genesis, and user deposits
    /// are deferred — so any post-genesis production credit would be invented
    /// money. Direct calls are the unit-test seam (custom-funded states) and
    /// the future deposit mechanism's entry point, not a funding source the
    /// node may invoke on its own.
    pub fn credit(&mut self, addr: Address, amount: u64) -> L2Result<()> {
        let next = self
            .balance(&addr)
            .checked_add(amount)
            .ok_or(L2Error::Overflow)?;
        self.accounts.insert(addr, next);
        self.funded_total = self
            .funded_total
            .checked_add(amount)
            .ok_or(L2Error::Overflow)?;
        Ok(())
    }

    /// Every satoshi ever released into this state, minus what exits have
    /// taken out. In production this equals the profile's escrow total plus
    /// credited deposits minus `exited_total` — anything else proves an
    /// unauthorized funding happened.
    pub fn funded_total(&self) -> u64 {
        self.funded_total
    }

    pub fn balance(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).copied().unwrap_or(0)
    }

    // --- state commitment (P1 exit proof, non-consensus) ----------------

    /// Every account as `(address, balance)` in canonical address order.
    ///
    /// This is the exact ordering the state root commits to and the same
    /// ordering `encode` uses, so a root and a wire blob can never disagree
    /// about which account is where.
    pub fn account_leaves(&self) -> Vec<(Address, u64)> {
        let mut accounts: Vec<(Address, u64)> =
            self.accounts.iter().map(|(a, b)| (*a, *b)).collect();
        accounts.sort_by_key(|(a, _)| *a);
        accounts
    }

    /// The canonical ordered leaf set for the commitment tree.
    ///
    /// Leaves are: account leaves in address order, then exit leaves in
    /// `(owner, nonce)` order, then policy leaves in hash order, then credit
    /// position leaves in id order. This is the single source of truth both
    /// [`L2State::committed_root`] and [`L2State::exit_proof`] build from, so
    /// the proof index a verifier computes can never disagree with the
    /// commitment it proves against.
    fn commitment_leaves(&self) -> Vec<Hash> {
        let mut leaves: Vec<Hash> = self
            .account_leaves()
            .iter()
            .map(|(a, b)| account_leaf(a, *b))
            .collect();
        let mut exits: Vec<(&(Address, u64), &ExitRecord)> = self.exits.iter().collect();
        exits.sort_by_key(|(k, _)| **k);
        leaves.extend(exits.iter().map(|(_, r)| r.leaf()));
        let mut policies: Vec<(&Hash, &PolicyEntry)> = self.policies.iter().collect();
        policies.sort_by_key(|(h, _)| **h);
        leaves.extend(policies.iter().map(|(_, e)| e.leaf()));
        let mut positions: Vec<(&Hash, &CreditPosition)> = self.positions.iter().collect();
        positions.sort_by_key(|(h, _)| **h);
        leaves.extend(positions.iter().map(|(_, p)| p.leaf()));
        // Guarded accounts (Phase 3, leaf tag 0x07) in owner address order.
        let mut guarded: Vec<(&Address, &GuardedAccount)> = self.guarded.iter().collect();
        guarded.sort_by_key(|(a, _)| **a);
        leaves.extend(guarded.iter().map(|(_, g)| g.leaf()));
        // Audit anchors are NOT in the commitment tree (they are attestations,
        // not value state). They are stored and proven separately.
        leaves
    }

    /// The committed root over every account balance.
    ///
    /// Zero-balance accounts are still leaves: the account *exists*, and
    /// dropping it would let a root for {alice: 0} collide with a root for an
    /// empty state.
    pub fn state_root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .account_leaves()
            .iter()
            .map(|(a, b)| account_leaf(a, *b))
            .collect();
        state_root(&leaves)
    }

    /// Prove `addr`'s current balance against [`L2State::state_root`].
    ///
    /// `None` for an address that holds no account — there is no leaf, so
    /// there is nothing to prove. Proving a zero balance for an absent account
    /// would claim a fact the commitment does not contain.
    pub fn account_proof(&self, addr: &Address) -> Option<InclusionProof> {
        let leaves = self.account_leaves();
        let index = leaves.iter().position(|(a, _)| a == addr)?;
        let hashed: Vec<Hash> = leaves.iter().map(|(a, b)| account_leaf(a, *b)).collect();
        prove_inclusion(&hashed, index)
    }

    /// Convenience for a verifier holding only the root: does this address and
    /// balance belong to that commitment?
    pub fn verify_account(&self, addr: &Address, balance_sat: u64) -> bool {
        match self.account_proof(addr) {
            Some(proof) => srct_core::state_root::verify_inclusion(
                self.state_root(),
                account_leaf(addr, balance_sat),
                &proof,
            ),
            None => false,
        }
    }

    // --- exits (approved P1) -------------------------------------------

    /// The consensus-committed root: account leaves in address order, then exit
    /// leaves in `(owner, nonce)` order, then policy leaves in hash order, under
    /// one tree.
    ///
    /// With no queued exits and no published policies the leaf list is the
    /// account list, so this equals [`L2State::state_root`]: a pre-exit state
    /// commits identically under both functions, and the block commitment never
    /// disagrees with the SDK root for states that predate exits.
    pub fn committed_root(&self) -> Hash {
        let leaves = self.commitment_leaves();
        state_root(&leaves)
    }

    /// Every queued exit, sorted by `(owner, nonce)`. Deterministic
    /// enumeration, like [`L2State::tasks`]: two nodes holding the same state
    /// list the same records in the same order.
    pub fn exit_records(&self) -> Vec<&ExitRecord> {
        let mut ids: Vec<(Address, u64)> = self.exits.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.exits[&id]).collect()
    }

    pub fn exit(&self, owner: &Address, nonce: u64) -> Option<&ExitRecord> {
        self.exits.get(&(*owner, nonce))
    }

    pub fn exit_count(&self) -> usize {
        self.exits.len()
    }

    /// Value currently encumbered in queued exits.
    pub fn exits_locked_total(&self) -> u64 {
        self.exits_locked
    }

    /// Value ever released to L1, append-only.
    pub fn exited_total(&self) -> u64 {
        self.exited_total
    }

    /// Start height of the current exit-principal window (`0` = none open).
    pub fn exit_window_start(&self) -> u64 {
        self.exit_window_start
    }

    /// Exit principal queued inside the current window.
    pub fn exit_window_total(&self) -> u64 {
        self.exit_window_total
    }

    /// Prove a queued exit record against [`L2State::committed_root`].
    ///
    /// `None` for an unknown or already-released record — there is no leaf, so
    /// there is nothing to prove. Release *removes* the record precisely so a
    /// spent exit can never be proven again.
    pub fn exit_proof(&self, owner: &Address, nonce: u64) -> Option<InclusionProof> {
        let leaves = self.commitment_leaves();
        let offset = self.account_leaves().len();
        let exits: Vec<(&(Address, u64), &ExitRecord)> = {
            let mut e: Vec<_> = self.exits.iter().collect();
            e.sort_by_key(|(k, _)| **k);
            e
        };
        let position = offset + exits.iter().position(|(k, _)| **k == (*owner, nonce))?;
        prove_inclusion(&leaves, position)
    }

    /// Whether a queued exit may be released at `tip`: its queue block is
    /// final under the stronger of the two Decision-15 rules — depth
    /// `maturity_depth` **and**, once binding finality is active, the binding
    /// checkpoint height. The same rule that governs deposit maturity, never
    /// weaker for exits. `binding_finalized == 0` means binding finality has
    /// not activated and depth alone governs.
    pub fn exit_is_mature(
        queued_height: u64,
        tip: u64,
        binding_finalized: u64,
        maturity_depth: u64,
    ) -> bool {
        let depth_ok = tip >= queued_height.saturating_add(maturity_depth);
        let binding_ok = binding_finalized == 0 || queued_height <= binding_finalized;
        depth_ok && binding_ok
    }

    /// Maturity depth for an exit of `amount_sat`: the base depth plus the
    /// large-exit extra delay when the principal crosses the profile
    /// threshold. Both halves of an exit (L2 queue accounting here, L1
    /// release in `check_claim`) compute the same number from the same
    /// inputs, so neither half can release early. Zero thresholds mean zero
    /// extra — the bare depth the tests pin.
    pub fn exit_maturity_depth_for(
        amount_sat: u64,
        base_depth: u64,
        threshold_sat: u64,
        extra_delay: u64,
    ) -> u64 {
        if threshold_sat > 0 && amount_sat >= threshold_sat {
            base_depth.saturating_add(extra_delay)
        } else {
            base_depth
        }
    }

    /// Whether this profile accepts an exit queue at `height`.
    ///
    /// `exit_activation_height == 0` means *never*, not *from genesis* — a
    /// profile that has chosen no height must not encumber funds with no
    /// release. Exposed so callers can refuse before building a transaction
    /// rather than after broadcasting one.
    pub fn exit_queue_is_active(&self, height: u64) -> bool {
        self.config.exit_activation_height != 0 && height >= self.config.exit_activation_height
    }

    /// Queue an L2 → L1 exit: debit `amount + exit_fee + queue fee` from the
    /// owner and record the pending exit the release rule later pays out.
    ///
    /// Fail-closed: below the activation height, on a zero amount, on a fee
    /// below [`MIN_EXIT_FEE_SAT`], on a repeated or rewound nonce, or on
    /// insufficient balance — the record is written only after every check
    /// passes, so a refused queue leaves no partial state.
    pub fn queue_exit(
        &mut self,
        p: &ExitQueuePayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        // `0` means the profile never activates exits: queueing would encumber
        // funds with no release, so it is refused rather than left to mature
        // into nothing.
        if self.config.exit_activation_height == 0 || height < self.config.exit_activation_height {
            return Err(L2Error::ExitNotActive);
        }
        if p.amount_sat == 0 {
            return Err(L2Error::ZeroAmount("exit"));
        }
        // The fee pays whoever later files the L1 release claim; zero or dust
        // would leave the exit unclaimed. A payload rule like the zero-amount
        // check, so it fires before any state is touched (SPEC.md exit rules).
        if p.exit_fee_sat < MIN_EXIT_FEE_SAT {
            return Err(L2Error::ExitFeeBelowMinimum);
        }
        // Phase 3 guarded enforcement: guarded owners may only exit to an
        // allow-listed destination active for at least the delay, never while
        // frozen, and the principal counts against the outflow cap.
        if self.guarded.contains_key(&p.owner) {
            self.guarded_check_spend(&p.owner, &p.destination, p.amount_sat, height)?;
        }
        // Nonces start at 1 (see the spend path): a first queue with
        // nonce 0 is refused by name.
        let last = self.exit_nonce.get(&p.owner).copied().unwrap_or(0);
        if p.nonce <= last {
            return Err(L2Error::BadExitNonce);
        }
        let need = p
            .amount_sat
            .checked_add(p.exit_fee_sat)
            .and_then(|v| v.checked_add(fee))
            .ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.owner, need)?;
        if self.exits.contains_key(&(p.owner, p.nonce)) {
            return Err(L2Error::BadExitNonce);
        }
        // Compute-then-mutate: the locked-total add is checked *before*
        // the debit lands, so an overflow refuses with balances untouched
        // instead of leaving a half-applied queue behind.
        let new_locked = p
            .amount_sat
            .checked_add(p.exit_fee_sat)
            .and_then(|v| self.exits_locked.checked_add(v))
            .ok_or(L2Error::Overflow)?;
        // Exit window throttle: the sink is a honeypot, and one window must
        // not drain it. A refused queue keeps its funds — the owner retries
        // in the next window — so this is a delay, never a taking. Windows
        // are replay-derived (first queue opens one), so reorgs rebuild them
        // from the winning chain with no undo bookkeeping.
        //
        // The global cap alone is starvable: one actor can fill the window
        // and hold every other owner out until it rolls over, at fee cost
        // (refused queues keep their funds, accepted ones release). The
        // per-owner sub-cap bounds one owner's share of the window, so a
        // filler is refused by name while other owners still queue.
        let window_on = self.config.max_exit_window_sat > 0 && self.config.exit_window_blocks > 0;
        let rolled = window_on
            && (self.exit_window_start == 0
                || height
                    >= self
                        .exit_window_start
                        .saturating_add(self.config.exit_window_blocks));
        let (window_start, window_total) = if window_on {
            let (start, total) = if rolled {
                (height, 0)
            } else {
                (self.exit_window_start, self.exit_window_total)
            };
            let total = total.checked_add(p.amount_sat).ok_or(L2Error::Overflow)?;
            if total > self.config.max_exit_window_sat {
                return Err(L2Error::ExitWindowFull {
                    window_total: total,
                    window_cap: self.config.max_exit_window_sat,
                    window_ends_at: start.saturating_add(self.config.exit_window_blocks),
                });
            }
            (start, total)
        } else {
            (self.exit_window_start, self.exit_window_total)
        };
        // The fairness bound, checked before any state moves like the global
        // one. A rolled window has no per-owner history, so the previous
        // share is zero by construction, not by lookup.
        let owner_total = if window_on {
            let prev = if rolled {
                0
            } else {
                self.exit_window_owner.get(&p.owner).copied().unwrap_or(0)
            };
            let total = prev.checked_add(p.amount_sat).ok_or(L2Error::Overflow)?;
            if self.config.max_exit_per_owner_window_sat > 0
                && total > self.config.max_exit_per_owner_window_sat
            {
                return Err(L2Error::ExitOwnerWindowFull {
                    owner_total: total,
                    owner_cap: self.config.max_exit_per_owner_window_sat,
                    window_ends_at: window_start.saturating_add(self.config.exit_window_blocks),
                });
            }
            total
        } else {
            0
        };
        self.charge(&p.owner, need)?;
        self.collect_fee(fee);
        self.exits_locked = new_locked;
        self.exit_window_start = window_start;
        self.exit_window_total = window_total;
        if rolled {
            self.exit_window_owner.clear();
        }
        if window_on {
            self.exit_window_owner.insert(p.owner, owner_total);
        }
        // Guarded exits commit the guarded bit so L1 can distinguish them:
        // a guarded exit is only claimable with a guarded proof against a
        // post-delay root; an unguarded one with the legacy queue-block proof.
        let is_guarded = self.guarded.contains_key(&p.owner);
        self.exits.insert(
            (p.owner, p.nonce),
            ExitRecord {
                owner: p.owner,
                nonce: p.nonce,
                amount_sat: p.amount_sat,
                destination: p.destination,
                exit_fee_sat: p.exit_fee_sat,
                queued_height: height,
                guarded: is_guarded,
            },
        );
        self.exit_nonce.insert(p.owner, p.nonce);
        // Record guarded outflow (window accounting, Phase 3).
        self.guarded_record_outflow(&p.owner, p.amount_sat, height)?;
        Ok(L2Effect::ExitQueued {
            owner: p.owner,
            nonce: p.nonce,
            amount_sat: p.amount_sat,
            destination: p.destination,
        })
    }

    /// Release a queued exit to L1: remove the record and move its value out
    /// of L2 accounting entirely.
    ///
    /// Called by replay when it observes a consensus-valid release in an L1
    /// block body — validity (proof, maturity, idempotency) is the L1 rule's
    /// job; this enforces the L2 side effects exactly once. An unknown record
    /// (never queued, or already released and therefore removed) is refused by
    /// name rather than debited twice.
    pub fn note_release(&mut self, owner: &Address, nonce: u64) -> L2Result<ExitRecord> {
        // Peek-then-commit: all three counter updates are proven first, and
        // the record is removed only after every one succeeds. A failure used
        // to land after the removal, leaving the exit neither queued nor
        // accounted while replay recorded it as unbacked.
        let record = self
            .exits
            .get(&(*owner, nonce))
            .ok_or(L2Error::UnknownExit)?
            .clone();
        let value = record
            .amount_sat
            .checked_add(record.exit_fee_sat)
            .ok_or(L2Error::Overflow)?;
        let new_locked = self
            .exits_locked
            .checked_sub(value)
            .ok_or(L2Error::Overflow)?;
        let new_exited = self
            .exited_total
            .checked_add(value)
            .ok_or(L2Error::Overflow)?;
        let new_funded = self
            .funded_total
            .checked_sub(value)
            .ok_or(L2Error::Overflow)?;
        self.exits.remove(&(*owner, nonce));
        self.exits_locked = new_locked;
        self.exited_total = new_exited;
        self.funded_total = new_funded;
        Ok(record)
    }

    fn ensure_balance(&self, addr: &Address, amount: u64) -> L2Result<()> {
        let have = self.balance(addr);
        if have < amount {
            return Err(L2Error::InsufficientBalance {
                needed: amount,
                available: have,
            });
        }
        Ok(())
    }

    /// Debit a balance. The caller must have verified sufficiency first via
    /// [`ensure_balance`]; this is the debit that follows. Uses `checked_sub`
    /// so an underflow is a protocol error rather than a silent wrap — with
    /// `overflow-checks` on, a contract violation surfaces as `Overflow` and
    /// halts the transaction before it can corrupt consensus state.
    fn charge(&mut self, addr: &Address, amount: u64) -> L2Result<()> {
        let have = self.balance(addr);
        let next = have.checked_sub(amount).ok_or(L2Error::Overflow)?;
        self.accounts.insert(*addr, next);
        Ok(())
    }

    fn pay(&mut self, addr: &Address, amount: u64) -> L2Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let next = self
            .balance(addr)
            .checked_add(amount)
            .ok_or(L2Error::Overflow)?;
        self.accounts.insert(*addr, next);
        Ok(())
    }

    fn collect_fee(&mut self, fee: u64) {
        let split = split_flat_fee(fee);
        self.burned = self.burned.saturating_add(split.burned);
        self.pscb = self.pscb.saturating_add(split.pscb);
    }

    // --- policy view ----------------------------------------------------

    /// One published policy, by its grant hash.
    pub fn policy(&self, policy_hash: &Hash) -> Option<&PolicyEntry> {
        self.policies.get(policy_hash)
    }

    /// The live grant for an agent, by agent identity.
    pub fn policy_for_agent(&self, agent_id: &AgentId) -> Option<&PolicyEntry> {
        let hash = self.policy_by_agent.get(agent_id)?;
        self.policies.get(hash)
    }

    /// Every published policy, sorted by grant hash. Deterministic
    /// enumeration, like [`L2State::tasks`].
    pub fn policies(&self) -> Vec<&PolicyEntry> {
        let mut ids: Vec<Hash> = self.policies.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.policies[&id]).collect()
    }

    // --- credit view ----------------------------------------------------

    /// One credit position, by id.
    pub fn credit_position(&self, id: &Hash) -> Option<&CreditPosition> {
        self.positions.get(id)
    }

    /// Every credit position, sorted by id. Deterministic enumeration, like
    /// [`L2State::tasks`]: two nodes holding the same state list the same
    /// positions in the same order.
    pub fn credit_positions(&self) -> Vec<&CreditPosition> {
        let mut ids: Vec<Hash> = self.positions.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.positions[&id]).collect()
    }

    /// Total collateral locked against credit positions.
    pub fn credit_locked(&self) -> u64 {
        self.credit_locked
    }

    /// Guarded accounts, for audit and cross-checks (Phase 3).
    pub fn guarded_accounts(&self) -> Vec<&GuardedAccount> {
        let mut out: Vec<&GuardedAccount> = self.guarded.values().collect();
        out.sort_by_key(|g| g.owner);
        out
    }

    /// Number of anchored audit roots (Phase 3).
    pub fn audit_anchor_count(&self) -> usize {
        self.audit_anchors.len()
    }

    // --- task view -----------------------------------------------------

    pub fn task(&self, task_id: &Hash) -> Option<&TaskContract> {
        self.tasks.get(task_id)
    }
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Every task, sorted by task id. Enumeration is never `HashMap` order, so
    /// two nodes holding the same state list the same contracts in the same
    /// order — the property task discovery (Phase 5's worker SDK, SPEC.md
    /// §18.4) is defined on.
    pub fn tasks(&self) -> Vec<&TaskContract> {
        let mut ids: Vec<Hash> = self.tasks.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.tasks[&id]).collect()
    }

    /// Every task currently in the `Disputed` state, sorted by task id.
    ///
    /// The arbitrator worklist (§16): these are the tasks whose result is under
    /// challenge and whose canonical reference an arbitrator will run. Sorted
    /// for the same reason `tasks()` is — two nodes holding the same state must
    /// enumerate disputes in the same order.
    pub fn disputed_tasks(&self) -> Vec<&TaskContract> {
        self.tasks()
            .into_iter()
            .filter(|t| matches!(t.state, ContractState::Disputed(_)))
            .collect()
    }

    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    // --- applying transactions ----------------------------------------

    /// Apply one L2 transaction at `height`.
    ///
    /// `validators` and `verifier` are consulted only for `Settle`; a non-settle
    /// call still needs them because the signature is uniform. That is a small
    /// cost for one call shape rather than five.
    pub fn apply(
        &mut self,
        tx: &L2Transaction,
        height: u64,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> L2Result<L2Effect> {
        let txid = tx.txid();
        if self.applied.contains(&txid) {
            return Err(L2Error::Replay);
        }
        tx.payload
            .verify_auth()
            .map_err(|_| L2Error::BadAuthorization)?;

        let fee = tx.fee_sat();
        let effect = match &tx.payload {
            L2Payload::Post(p) => self.apply_post(p, height, fee),
            L2Payload::Claim(p) => self.apply_claim(p, height, fee),
            L2Payload::Submit(p) => self.apply_submit(p, height, fee),
            L2Payload::Dispute(p) => self.apply_dispute(p, height, fee),
            L2Payload::Settle(p) => self.apply_settle(p, txid, height, validators, verifier),
            L2Payload::ExitQueue(p) => self.queue_exit(p, height, fee),
            L2Payload::Policy(p) => self.apply_policy(p, height, fee),
            L2Payload::PolicyRevoke(p) => self.apply_policy_revoke(p, height, fee),
            L2Payload::AgentSpend(p) => self.apply_agent_spend(p, height, fee),
            L2Payload::CreditOpen(p) => {
                // Phase 2: at/after activation, new positions require the
                // borrower-consented 0x1D form. Old 0x19 blocks still replay
                // (pre-activation history), but new 0x19 opens are refused.
                let a = self.config.credit_consent_activation_height;
                if a != 0 && height >= a {
                    return Err(L2Error::CreditTerms(
                        "legacy credit open retired: use guarded CreditOpenV2",
                    ));
                }
                self.apply_credit_open(p, height, fee)
            }
            L2Payload::CreditCollateral(p) => self.apply_credit_collateral(p, height, fee),
            L2Payload::CreditRepay(p) => self.apply_credit_repay(p, height, fee),
            L2Payload::CreditDefault(p) => self.apply_credit_default(p, height, fee),
            L2Payload::CreditOpenV2(p) => self.apply_credit_open_v2(p, height, fee),
            L2Payload::GuardedOptIn(p) => self.apply_guarded_optin(p, height, fee),
            L2Payload::GuardedCancel(p) => self.apply_guarded_cancel(p, height, fee),
            L2Payload::GuardedFreeze(p) => self.apply_guarded_freeze(p, height, fee),
            L2Payload::AuditAnchor(p) => self.apply_audit_anchor(p, height, fee),
        }?;

        // Only a transaction that actually applied is marked applied. A
        // rejection leaves the id free, so a precondition that later holds lets
        // the same bytes be retried — but it can never apply twice.
        self.applied.insert(txid);
        Ok(effect)
    }

    // --- spending policies (SPEC.md §21) --------------------------------

    /// Publish a spending policy (SPEC.md §21.1).
    ///
    /// The owner's signature covers the grant bytes, the spender and the agent
    /// identity together, so a grant cannot be published for a spender the
    /// owner did not name. What lands in state is the grant, the spender, and
    /// the counters that make the caps enforceable.
    fn apply_policy(&mut self, p: &PolicyPayload, height: u64, fee: u64) -> L2Result<L2Effect> {
        let policy = SpendPolicy::deserialize(&p.policy)
            .map_err(|e| L2Error::Policy(format!("grant refused: {e}")))?;
        policy
            .validate()
            .map_err(|e| L2Error::Policy(format!("grant refused: {e}")))?;
        // The signer is the owner the grant names.
        if policy.owner != p.owner {
            return Err(L2Error::PolicyBinding("the grant names another owner"));
        }
        // The grant is for this network.
        if policy.network_id != self.config.network_id {
            return Err(L2Error::PolicyBinding("the grant is for another network"));
        }
        // A revoked grant is published by revoking, not by publishing.
        if policy.revoked {
            return Err(L2Error::PolicyBinding(
                "a revoked grant cannot be published",
            ));
        }
        // The grant names the agent the transaction names.
        if policy.agent_id != p.agent_id {
            return Err(L2Error::PolicyBinding("the grant names another agent"));
        }
        // One live grant per agent: a second grant cannot be used to double the
        // caps the first one grants.
        if let Some(existing) = self.policy_by_agent.get(&p.agent_id) {
            let entry = self.policies.get(existing).ok_or(L2Error::UnknownPolicy)?;
            if !entry.revoked {
                return Err(L2Error::PolicyAlreadyPublished);
            }
        }
        // A delegated grant must narrow a parent that is on chain and live.
        if let Some(parent_id) = policy.parent_agent_id {
            let parent_hash = self
                .policy_by_agent
                .get(&parent_id)
                .copied()
                .ok_or(L2Error::UnknownPolicy)?;
            if !self.policy_is_live(&parent_hash) {
                return Err(L2Error::PolicyRevoked);
            }
            let parent = self
                .policies
                .get(&parent_hash)
                .ok_or(L2Error::UnknownPolicy)?;
            delegation::dominates(&parent.policy, &policy)
                .map_err(|e| L2Error::Policy(format!("grant widens its parent: {e:?}")))?;
        }
        // Phase 3 guarded enforcement: for guarded owners, not_before must be
        // at least `grant_delay_blocks` after the publish height, and the grant
        // lifetime must fit `max_grant_lifetime_blocks`. Revocation stays
        // instant (handled by PolicyRevoke, unchanged).
        if let Some(g) = self.guarded.get(&p.owner) {
            if g.frozen {
                return Err(L2Error::AccountFrozen);
            }
            let delay = g.grant_delay_blocks.max(self.config.guarded_grant_delay_blocks);
            if policy.not_before_height < height.saturating_add(delay) {
                return Err(L2Error::GrantDelayNotSatisfied);
            }
            let lifetime = policy
                .expires_at_height
                .saturating_sub(policy.not_before_height);
            // Account-level cap wins when set; otherwise the chain default.
            // Zero (either side) means no lifetime cap.
            let max_life = if g.max_grant_lifetime_blocks != 0 {
                g.max_grant_lifetime_blocks
            } else {
                self.config.guarded_max_grant_lifetime_blocks
            };
            if max_life != 0 && lifetime > max_life {
                return Err(L2Error::GrantLifetimeExceeded);
            }
        }
        // The fee comes out of the owner's balance, like every other L2 fee.
        self.ensure_balance(&p.owner, fee)?;
        self.charge(&p.owner, fee)?;
        self.collect_fee(fee);

        let hash = policy.hash();
        let entry = PolicyEntry {
            policy,
            spender: p.spender,
            agent_id: p.agent_id,
            revoked: false,
            window_start_height: height,
            spent_in_window_sat: 0,
            total_spent_sat: 0,
            last_nonce: 0,
            spends: 0,
        };
        self.policies.insert(hash, entry);
        self.policy_by_agent.insert(p.agent_id, hash);
        Ok(L2Effect::PolicyPublished {
            policy_hash: hash,
            agent_id: p.agent_id,
            spender: p.spender,
        })
    }

    /// Revoke a published policy (SPEC.md §21.2).
    ///
    /// The owner's kill switch, on chain. Revocation reaches every descendant
    /// without a separate revocation transaction per link: a spend checks the
    /// whole ancestry.
    fn apply_policy_revoke(
        &mut self,
        p: &PolicyRevokePayload,
        _height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        let hash = self
            .policy_by_agent
            .get(&p.agent_id)
            .copied()
            .ok_or(L2Error::UnknownPolicy)?;
        let entry = self.policies.get(&hash).ok_or(L2Error::UnknownPolicy)?;
        if entry.policy.owner != p.owner {
            return Err(L2Error::PolicyBinding("the grant names another owner"));
        }
        // Idempotent kill switch: revoking twice charges once. A second
        // revoke is a no-op success — charging again would bill the owner
        // for flipping an already-dead switch.
        if entry.revoked {
            return Ok(L2Effect::PolicyRevoked {
                agent_id: p.agent_id,
            });
        }
        self.ensure_balance(&p.owner, fee)?;
        self.charge(&p.owner, fee)?;
        self.collect_fee(fee);
        let entry = self.policies.get_mut(&hash).ok_or(L2Error::UnknownPolicy)?;
        entry.revoked = true;
        Ok(L2Effect::PolicyRevoked {
            agent_id: p.agent_id,
        })
    }

    /// Spend under a published policy (SPEC.md §21.3).
    ///
    /// Every rule in the grant is checked against state the chain keeps, so a
    /// per-window cap and a nonce are rules rather than advice. The money comes
    /// out of the grant owner's balance — the grant is an allowance over the
    /// owner's own funds — and the fee comes out of the same balance on top.
    fn apply_agent_spend(
        &mut self,
        p: &AgentSpendPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        let hash = p.policy_hash;
        let entry = self
            .policies
            .get(&hash)
            .cloned()
            .ok_or(L2Error::UnknownPolicy)?;
        // Only the spender the grant names may exercise it.
        if entry.spender != p.agent {
            return Err(L2Error::PolicyBinding(
                "the spender is not the one the grant names",
            ));
        }
        // The grant must be live: not revoked, and with no revoked ancestor.
        if !self.policy_is_live(&hash) {
            return Err(L2Error::PolicyRevoked);
        }
        let policy = &entry.policy;
        if policy.network_id != self.config.network_id {
            return Err(L2Error::PolicyBinding("the grant is for another network"));
        }
        if height < policy.not_before_height {
            return Err(L2Error::PolicyWindow("the grant is not yet valid"));
        }
        if height >= policy.expires_at_height {
            return Err(L2Error::PolicyWindow("the grant has expired"));
        }
        if p.amount_sat == 0 {
            return Err(L2Error::ZeroAmount("agent spend"));
        }
        if p.amount_sat > policy.per_tx_max_sat {
            return Err(L2Error::PolicyLimit("per-transaction cap exceeded"));
        }
        // An empty allow-list allows nothing. That is the safe reading of an
        // empty list, and it is the same rule the node-local policy engine
        // applies.
        if !policy.allowed_recipients.contains(&p.recipient) {
            return Err(L2Error::PolicyRecipient);
        }
        // Phase 3 guarded enforcement: the grant owner's account may be
        // guarded. Then the recipient must be in the allow-list that has been
        // active for at least the delay, the account must not be frozen, and
        // the spend counts against the balance-relative window cap.
        if self.guarded.contains_key(&policy.owner) {
            self.guarded_check_spend(&policy.owner, &p.recipient, p.amount_sat, height)?;
            // Human-approval tier: spends at/above the configured tier need
            // the guardian's co-signature on the identical terms, verified
            // against the registered guardian (verify_auth already checked
            // the signature itself; this binds it to the right guardian).
            let tier = self.config.guarded_approval_threshold_sat;
            if tier != 0 && p.amount_sat >= tier {
                let co = p.guardian_approval.as_ref().ok_or(L2Error::GuardedApprovalRequired)?;
                let g = self
                    .guarded
                    .get(&policy.owner)
                    .ok_or(L2Error::GuardedNotOptedIn)?;
                if co.guardian != g.guardian {
                    return Err(L2Error::GuardedGuardianMismatch);
                }
            }
        }
        match &p.service {
            None => {
                if !policy.allowed_services.is_empty() {
                    return Err(L2Error::PolicyService);
                }
            }
            Some(tag) => {
                if !policy.allowed_services.contains(tag) {
                    return Err(L2Error::PolicyService);
                }
            }
        }
        // Nonces start at 1: `last_nonce` defaults to 0 and must strictly
        // increase, so a first spend/queue with nonce 0 is refused by name.
        if p.nonce <= entry.last_nonce {
            return Err(L2Error::PolicyNonce);
        }
        if height < entry.window_start_height {
            return Err(L2Error::PolicyWindow(
                "the height ran backwards inside the grant",
            ));
        }
        // Tumbling window, forward only, overflow-safe.
        let window_end = entry
            .window_start_height
            .checked_add(policy.window_blocks)
            .ok_or(L2Error::Overflow)?;
        let (window_start, spent_in_window) = if height >= window_end {
            (height, 0u64)
        } else {
            (entry.window_start_height, entry.spent_in_window_sat)
        };
        let requested = spent_in_window
            .checked_add(p.amount_sat)
            .ok_or(L2Error::Overflow)?;
        if requested > policy.cumulative_max_sat {
            return Err(L2Error::PolicyLimit("per-window cap exceeded"));
        }
        let owner = policy.owner;
        let need = p.amount_sat.checked_add(fee).ok_or(L2Error::Overflow)?;
        self.ensure_balance(&owner, need)?;
        self.charge(&owner, need)?;
        self.pay(&p.recipient, p.amount_sat)?;
        self.collect_fee(fee);
        // Record guarded outflow (window accounting, Phase 3).
        self.guarded_record_outflow(&owner, p.amount_sat, height)?;
        let e = self.policies.get_mut(&hash).ok_or(L2Error::UnknownPolicy)?;
        e.window_start_height = window_start;
        e.spent_in_window_sat = requested;
        e.total_spent_sat = e.total_spent_sat.saturating_add(p.amount_sat);
        e.last_nonce = p.nonce;
        e.spends = e.spends.saturating_add(1);
        Ok(L2Effect::AgentSpent {
            policy_hash: hash,
            agent: p.agent,
            recipient: p.recipient,
            amount_sat: p.amount_sat,
        })
    }

    /// Phase 3 guarded pre-check for an outflow (AgentSpend or ExitQueue).
    ///
    /// Fails closed: unknown owner is not guarded (Ok), frozen guarded
    /// accounts refuse, recipients outside the allow-list active for at least
    /// the delay are refused, and outflows beyond the balance-relative window
    /// cap are refused. Pure check — accounting happens in
    /// [`Self::guarded_record_outflow`] after the spend succeeds.
    fn guarded_check_spend(
        &self,
        owner: &Address,
        recipient: &Address,
        amount_sat: u64,
        height: u64,
    ) -> L2Result<()> {
        let Some(g) = self.guarded.get(owner) else {
            return Ok(());
        };
        if g.frozen {
            return Err(L2Error::AccountFrozen);
        }
        // Allow-list must contain the recipient AND have been active long
        // enough (changes take effect only after the delay).
        let delay = g.grant_delay_blocks.max(self.config.guarded_grant_delay_blocks);
        if !g.allow_list.contains(recipient)
            || height < g.allowlist_active_height.saturating_add(delay)
        {
            return Err(L2Error::GuardedDestinationNotAllowed);
        }
        // Balance-relative window cap: total outflow per window <= snapshot * bps / 10000.
        let window = if g.outflow_window_blocks != 0 {
            g.outflow_window_blocks
        } else {
            self.config.guarded_outflow_window_blocks
        };
        let bps = if g.outflow_cap_bps != 0 {
            g.outflow_cap_bps
        } else {
            self.config.guarded_outflow_cap_bps
        };
        if window == 0 || bps == 0 {
            return Ok(());
        }
        let (window_total, snapshot) = if height >= g.window_start_height.saturating_add(window) {
            // New window would start at this height; snapshot is the current balance.
            (0u64, self.balance(owner))
        } else {
            (g.window_outflow_total, g.window_balance_snapshot)
        };
        let cap = (snapshot as u128)
            .saturating_mul(bps as u128)
            .saturating_div(10_000) as u64;
        let after = window_total.saturating_add(amount_sat);
        if after > cap {
            return Err(L2Error::GuardedOutflowCapped {
                allowed: cap.saturating_sub(window_total),
                requested: amount_sat,
            });
        }
        Ok(())
    }

    /// Phase 3 guarded outflow accounting. Called after a guarded-account
    /// outflow succeeds. Rolls windows forward (snapshot = current balance,
    /// which the spend just reduced) and accumulates the window total.
    fn guarded_record_outflow(
        &mut self,
        owner: &Address,
        amount_sat: u64,
        height: u64,
    ) -> L2Result<()> {
        let window = self
            .guarded
            .get(owner)
            .map(|g| {
                if g.outflow_window_blocks != 0 {
                    g.outflow_window_blocks
                } else {
                    self.config.guarded_outflow_window_blocks
                }
            })
            .unwrap_or(0);
        if window == 0 {
            return Ok(());
        }
        // Read-only snapshot first: `balance` borrows `self` immutably and
        // must not run while the guarded entry is mutably borrowed below.
        let snap = self.balance(owner);
        let g = self.guarded.get_mut(owner).ok_or(L2Error::GuardedNotOptedIn)?;
        if height >= g.window_start_height.saturating_add(window) {
            g.window_start_height = height;
            g.window_balance_snapshot = snap;
            g.window_outflow_total = 0;
        }
        g.window_outflow_total = g.window_outflow_total.saturating_add(amount_sat);
        Ok(())
    }

    /// Is this grant live — not revoked itself, and with no revoked ancestor?
    ///
    /// The walk is bounded by the delegation depth cap and fails closed: a
    /// missing ancestor, a revoked one, or a chain deeper than the cap all
    /// mean "not live".
    fn policy_is_live(&self, hash: &Hash) -> bool {
        let mut current = *hash;
        for _ in 0..=delegation::MAX_DELEGATION_DEPTH {
            let Some(entry) = self.policies.get(&current) else {
                return false;
            };
            if entry.revoked {
                return false;
            }
            match entry.policy.parent_agent_id {
                Some(parent_id) => match self.policy_by_agent.get(&parent_id) {
                    Some(parent_hash) => current = *parent_hash,
                    None => return false,
                },
                None => return true,
            }
        }
        false
    }

    // --- credit positions (SPEC.md §22) ----------------------------------

    /// Open a credit position (SPEC.md §22.3).
    ///
    /// The lender's signature is what makes this a loan rather than a claim
    /// somebody else made about the lender. The principal moves to the
    /// borrower now, and the borrower's own funds are locked as collateral —
    /// the collateral is checked *before* the principal arrives, so it cannot
    /// be the borrowed money securing itself.
    fn apply_credit_open(
        &mut self,
        p: &CreditOpenPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        if p.amount_sat == 0 {
            return Err(L2Error::ZeroAmount("credit principal"));
        }
        if p.collateral_sat == 0 {
            return Err(L2Error::ZeroAmount("credit collateral"));
        }
        if p.window_blocks == 0 {
            return Err(L2Error::CreditTerms("the window must be non-zero"));
        }
        if p.rate_bps_per_window > MAX_CREDIT_RATE_BPS_PER_WINDOW {
            return Err(L2Error::CreditTerms("the rate is above the cap"));
        }
        if p.deadline_height <= height {
            return Err(L2Error::CreditTerms("the deadline must be in the future"));
        }
        // Full collateralisation without a bond: the same arithmetic the
        // node-local credit book uses, with a zero bond.
        let required = CreditTerms::default()
            .required_collateral(p.amount_sat, 0)
            .map_err(|_| L2Error::CreditTerms("the collateral rule refused the amount"))?;
        if p.collateral_sat < required {
            return Err(L2Error::CreditUndercollateralised {
                required,
                posted: p.collateral_sat,
            });
        }
        let id = p.derived_position_id();
        if self.positions.contains_key(&id) {
            return Err(L2Error::CreditPositionExists);
        }
        let lender_total = p.amount_sat.checked_add(fee).ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.lender, lender_total)?;
        // The collateral must be the borrower's own money, so it is checked
        // before the principal arrives.
        self.ensure_balance(&p.borrower, p.collateral_sat)?;
        self.charge(&p.lender, lender_total)?;
        self.pay(&p.borrower, p.amount_sat)?;
        self.charge(&p.borrower, p.collateral_sat)?;
        self.credit_locked = self
            .credit_locked
            .checked_add(p.collateral_sat)
            .ok_or(L2Error::Overflow)?;
        self.collect_fee(fee);
        self.positions.insert(
            id,
            CreditPosition {
                id,
                lender: p.lender,
                borrower: p.borrower,
                principal_sat: p.amount_sat,
                outstanding_sat: p.amount_sat,
                interest_paid_sat: 0,
                collateral_sat: p.collateral_sat,
                rate_bps_per_window: p.rate_bps_per_window,
                window_blocks: p.window_blocks,
                opened_height: height,
                deadline_height: p.deadline_height,
                interest_settled_height: height,
                state: CreditPositionState::Open,
            },
        );
        Ok(L2Effect::CreditOpened {
            position_id: id,
            lender: p.lender,
            borrower: p.borrower,
            amount_sat: p.amount_sat,
        })
    }

    /// Open a credit position with borrower consent (Phase 2 fix, type 0x1D).
    ///
    /// Requires BOTH lender and borrower signatures (verified by `verify_auth`
    /// before dispatch). Caps enforced when configured (non-zero).
    ///
    /// Old 0x19 path unchanged for pre-activation replay.
    fn apply_credit_open_v2(
        &mut self,
        p: &CreditOpenV2Payload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        // NOTE: CreditOpenV2Payload lives in srct-core::l2; import via full path
        // to avoid cycle. Field-for-field identical to CreditOpen plus borrower_auth.
        self.apply_credit_open_v2_inner(
            &p.lender,
            &p.borrower,
            p.amount_sat,
            p.collateral_sat,
            p.rate_bps_per_window,
            p.window_blocks,
            p.deadline_height,
            p.nonce,
            height,
            fee,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_credit_open_v2_inner(
        &mut self,
        lender: &Address,
        borrower: &Address,
        amount_sat: u64,
        collateral_sat: u64,
        rate_bps_per_window: u32,
        window_blocks: u64,
        deadline_height: u64,
        nonce: u64,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        // Phase 2 activation: V2 opens exist only at/after the consent height.
        // Pre-activation, 0x1D is refused so old replay stays byte-identical
        // and no new consented position can be created before the rules do.
        if self.config.credit_consent_activation_height == 0
            || height < self.config.credit_consent_activation_height
        {
            return Err(L2Error::BadConfig("credit consent not active"));
        }
        use srct_core::credit::CreditTerms;
        if amount_sat == 0 {
            return Err(L2Error::ZeroAmount("credit principal"));
        }
        if collateral_sat == 0 {
            return Err(L2Error::ZeroAmount("credit collateral"));
        }
        if window_blocks == 0 {
            return Err(L2Error::CreditTerms("the window must be non-zero"));
        }
        // Phase 2 caps (enforced only when configured non-zero).
        if self.config.credit_min_window_blocks != 0
            && window_blocks < self.config.credit_min_window_blocks
        {
            return Err(L2Error::CreditTerms("the window is below the minimum"));
        }
        if rate_bps_per_window > MAX_CREDIT_RATE_BPS_PER_WINDOW {
            return Err(L2Error::CreditTerms("the rate is above the cap"));
        }
        if deadline_height <= height {
            return Err(L2Error::CreditTerms("the deadline must be in the future"));
        }
        if self.config.credit_max_term_blocks != 0
            && deadline_height.saturating_sub(height) > self.config.credit_max_term_blocks
        {
            return Err(L2Error::CreditTerms("the term exceeds the maximum"));
        }
        let required = CreditTerms::default()
            .required_collateral(amount_sat, 0)
            .map_err(|_| L2Error::CreditTerms("the collateral rule refused the amount"))?;
        if collateral_sat < required {
            return Err(L2Error::CreditUndercollateralised {
                required,
                posted: collateral_sat,
            });
        }
        if self.config.credit_max_collateral_multiple != 0 {
            let max_allowed = required
                .checked_mul(self.config.credit_max_collateral_multiple)
                .ok_or(L2Error::Overflow)?;
            if collateral_sat > max_allowed {
                return Err(L2Error::CreditTerms("collateral exceeds the maximum multiple"));
            }
        }
        // Position id covers all terms (same scheme as v1 so vectors stay comparable).
        let id = {
            use srct_core::hash::sha256_dom;
            use srct_core::l2::DOM_L2_CREDIT_POSITION;
            use srct_core::ser::Writer;
            let mut w = Writer::new();
            w.fixed(lender)
                .fixed(borrower)
                .u64le(amount_sat)
                .u64le(collateral_sat)
                .u32le(rate_bps_per_window)
                .u64le(window_blocks)
                .u64le(deadline_height)
                .u64le(nonce);
            sha256_dom(DOM_L2_CREDIT_POSITION, &[w.as_slice()])
        };
        if self.positions.contains_key(&id) {
            return Err(L2Error::CreditPositionExists);
        }
        let lender_total = amount_sat.checked_add(fee).ok_or(L2Error::Overflow)?;
        self.ensure_balance(lender, lender_total)?;
        self.ensure_balance(borrower, collateral_sat)?;
        self.charge(lender, lender_total)?;
        self.pay(borrower, amount_sat)?;
        self.charge(borrower, collateral_sat)?;
        self.credit_locked = self
            .credit_locked
            .checked_add(collateral_sat)
            .ok_or(L2Error::Overflow)?;
        self.collect_fee(fee);
        self.positions.insert(
            id,
            CreditPosition {
                id,
                lender: *lender,
                borrower: *borrower,
                principal_sat: amount_sat,
                outstanding_sat: amount_sat,
                interest_paid_sat: 0,
                collateral_sat,
                rate_bps_per_window,
                window_blocks,
                opened_height: height,
                deadline_height,
                interest_settled_height: height,
                state: CreditPositionState::Open,
            },
        );
        Ok(L2Effect::CreditOpened {
            position_id: id,
            lender: *lender,
            borrower: *borrower,
            amount_sat,
        })
    }

    /// Opt an L2 account into guarded mode (Phase 3).
    /// Creates the guarded-account record; per-account only, never global.
    /// Guardian must be distinct from owner. Requires activation height.
    fn apply_guarded_optin(
        &mut self,
        p: &srct_core::l2::GuardedOptInPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        if self.config.guarded_activation_height == 0
            || height < self.config.guarded_activation_height
        {
            return Err(L2Error::BadConfig("guarded accounts not active"));
        }
        // Guardian must be independent of the owner: a self-guardian is a
        // no-op control, refused by name (Phase 3 SPEC).
        if p.guardian == p.owner {
            return Err(L2Error::GuardedGuardianMustDiffer);
        }
        if self.guarded.contains_key(&p.owner) {
            return Err(L2Error::GuardedAlreadyOptedIn);
        }
        // Empty allow-list locks every outflow until a delayed update lands.
        // That is fail-closed and intentional: opt-in is explicit.
        self.ensure_balance(&p.owner, fee)?;
        self.charge(&p.owner, fee)?;
        self.collect_fee(fee);
        let snapshot = self.balance(&p.owner);
        self.guarded.insert(
            p.owner,
            GuardedAccount {
                owner: p.owner,
                guardian: p.guardian,
                allow_list: p.allow_list.clone(),
                allowlist_active_height: height,
                pending_allowlist: None,
                grant_delay_blocks: p.grant_delay_blocks,
                max_grant_lifetime_blocks: p.max_grant_lifetime_blocks,
                outflow_cap_bps: p.outflow_cap_bps,
                outflow_window_blocks: p.outflow_window_blocks,
                window_balance_snapshot: snapshot,
                window_start_height: height,
                window_outflow_total: 0,
                frozen: false,
                created_height: height,
            },
        );
        Ok(L2Effect::GuardedOptedIn {
            owner: p.owner,
            guardian: p.guardian,
        })
    }

    /// Guardian cancellation (Phase 3): GuardedCancel.
    ///
    /// `target_kind == 0`: queued exit — `target_id[0..8]` is the exit nonce
    /// (LE u64). Cancelling removes the exit record and returns the locked
    /// principal to the owner's balance, so conservation holds. Valid only
    /// while `tip < queued_height + D` (the shared guarded delay): after the
    /// delay the exit is claimable and cancellation would race a proof that a
    /// post-delay root already commits to. A claim against a post-delay root
    /// then finds no record — the L1 side refuses it as unbacked, so the
    /// cancel/claim order is deterministic by block height.
    /// `target_kind == 1`: published grant — `target_id` is the grant hash;
    /// marks the grant revoked (instant, like owner revocation).
    fn apply_guarded_cancel(
        &mut self,
        p: &srct_core::l2::GuardedCancelPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        if self.config.guarded_activation_height == 0 {
            return Err(L2Error::BadConfig("guarded accounts not active"));
        }
        let g = self
            .guarded
            .get(&p.account)
            .ok_or(L2Error::GuardedNotOptedIn)?;
        if g.guardian != p.guardian {
            return Err(L2Error::GuardedGuardianMismatch);
        }
        // The guarded account pays: the guardian authorizes (signature above)
        // but holds no balance requirement; the protected owner funds it.
        // This also keeps frozen accounts actionable — the freeze itself does
        // not block the guardian's fee debit (outflow caps apply to spends,
        // not to protection actions).
        self.ensure_balance(&p.account, fee)?;
        self.charge(&p.account, fee)?;
        self.collect_fee(fee);
        match p.kind {
            0 => {
                let mut nb = [0u8; 8];
                nb.copy_from_slice(&p.target[..8]);
                let nonce = u64::from_le_bytes(nb);
                let key = (p.account, nonce);
                let record = self
                    .exits
                    .get(&key)
                    .ok_or(L2Error::UnknownExit)?
                    .clone();
                // Cancel window: only before queued_height + D. At or after,
                // the exit is claimable and the L1 side may already hold a
                // post-delay proof; removing the record then would fork the
                // two halves of the release. The shared constant D makes the
                // cancel/claim ordering deterministic by block height.
                let d = self.config.guarded_exit_delay_blocks.max(1);
                if height >= record.queued_height.saturating_add(d) {
                    return Err(L2Error::GuardedCancelWindowClosed);
                }
                // Reverse exactly what queue_exit booked: locked principal +
                // prepaid exit fee return to the owner; the queue's own L2
                // fee stays burned (the work was done). `exited_total` is
                // untouched: it only moves on L1 release (`note_release`),
                // and a cancelled exit never reaches L1.
                let locked = record
                    .amount_sat
                    .checked_add(record.exit_fee_sat)
                    .ok_or(L2Error::Overflow)?;
                let record = self.exits.remove(&key).ok_or(L2Error::UnknownExit)?;
                self.exits_locked = self
                    .exits_locked
                    .checked_sub(locked)
                    .ok_or(L2Error::Overflow)?;
                self.pay(&p.account, locked)?;
                // Release the window budget this queue consumed: queueing counts
                // only `amount_sat` (fees burn separately), so unwind exactly
                // that. A cancelled exit never left; counting it would brick
                // the account for the rest of the window. Bounded wart: if
                // the window rolled between queue and cancel, this frees
                // budget in the *new* window (saturating at zero) - at most
                // one exit of extra headway.
                if let Some(g) = self.guarded.get_mut(&p.account) {
                    g.window_outflow_total = g
                        .window_outflow_total
                        .saturating_sub(record.amount_sat);
                }
                Ok(L2Effect::GuardedAction {
                    account: p.account,
                    kind: "cancel-exit",
                })
            }
            1 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&p.target);
                let entry = self.policies.get_mut(&hash).ok_or(L2Error::UnknownPolicy)?;
                entry.revoked = true;
                Ok(L2Effect::GuardedAction {
                    account: p.account,
                    kind: "cancel-grant",
                })
            }
            _ => Err(L2Error::GuardedUnknownTarget),
        }
    }

    /// Guardian freeze (Phase 3): GuardedFreeze.
    fn apply_guarded_freeze(
        &mut self,
        p: &srct_core::l2::GuardedFreezePayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        let _ = height;
        if self.config.guarded_activation_height == 0 {
            return Err(L2Error::BadConfig("guarded accounts not active"));
        }
        // Check guardian identity first and drop the borrow before the fee
        // calls below (each borrows `self` mutably in turn).
        let registered = self
            .guarded
            .get(&p.account)
            .map(|g| g.guardian)
            .ok_or(L2Error::GuardedNotOptedIn)?;
        if registered != p.guardian {
            return Err(L2Error::GuardedGuardianMismatch);
        }
        // The guarded account pays (same rule as cancellation: the guardian
        // authorizes, the protected owner funds).
        self.ensure_balance(&p.account, fee)?;
        self.charge(&p.account, fee)?;
        self.collect_fee(fee);
        let g = self
            .guarded
            .get_mut(&p.account)
            .ok_or(L2Error::GuardedNotOptedIn)?;
        g.frozen = p.frozen;
        Ok(L2Effect::GuardedAction {
            account: p.account,
            kind: if p.frozen { "freeze" } else { "unfreeze" },
        })
    }

    /// Audit anchor (Phase 3): commits an off-chain audit Merkle root.
    fn apply_audit_anchor(
        &mut self,
        p: &srct_core::l2::AuditAnchorPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        let _ = fee;
        if self.config.guarded_activation_height == 0 {
            return Err(L2Error::BadConfig("audit anchor not active"));
        }
        use srct_core::hash::sha256_dom;
        const DOM_AUDIT: &[u8] = b"srct/l2/audit-anchor/v1";
        let id = sha256_dom(DOM_AUDIT, &[&p.anchorer, &p.root, &height.to_le_bytes(), &p.nonce.to_le_bytes()]);
        if self.audit_anchors.contains_key(&id) {
            return Err(L2Error::Replay);
        }
        // Charge fee from anchorer.
        let total = fee;
        self.ensure_balance(&p.anchorer, total)?;
        self.charge(&p.anchorer, total)?;
        self.collect_fee(fee);
        self.audit_anchors.insert(
            id,
            AuditAnchorRecord {
                anchorer: p.anchorer,
                root: p.root,
                height,
                nonce: p.nonce,
            },
        );
        Ok(L2Effect::AuditAnchored {
            anchorer: p.anchorer,
            root: p.root,
        })
    }

    /// Add collateral to a credit position (SPEC.md §22.4).
    fn apply_credit_collateral(
        &mut self,
        p: &CreditCollateralPayload,
        _height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        let position = self
            .positions
            .get(&p.position_id)
            .cloned()
            .ok_or(L2Error::UnknownCreditPosition)?;
        if position.borrower != p.borrower {
            return Err(L2Error::CreditBinding(
                "the position names another borrower",
            ));
        }
        if position.state != CreditPositionState::Open {
            return Err(L2Error::CreditPositionClosed);
        }
        if p.amount_sat == 0 {
            return Err(L2Error::ZeroAmount("credit collateral"));
        }
        let need = p.amount_sat.checked_add(fee).ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.borrower, need)?;
        self.charge(&p.borrower, need)?;
        self.credit_locked = self
            .credit_locked
            .checked_add(p.amount_sat)
            .ok_or(L2Error::Overflow)?;
        self.collect_fee(fee);
        let pos = self
            .positions
            .get_mut(&p.position_id)
            .ok_or(L2Error::UnknownCreditPosition)?;
        pos.collateral_sat = pos
            .collateral_sat
            .checked_add(p.amount_sat)
            .ok_or(L2Error::Overflow)?;
        Ok(L2Effect::CreditCollateralAdded {
            position_id: p.position_id,
            borrower: p.borrower,
            amount_sat: p.amount_sat,
        })
    }

    /// Repay a credit position (SPEC.md §22.5).
    ///
    /// Interest first, then principal: the same order the node-local credit
    /// book uses, for the same reason. Interest is charged once per period on
    /// the balance that was outstanding, so two instalments do not each pay
    /// for the whole elapsed time.
    fn apply_credit_repay(
        &mut self,
        p: &CreditRepayPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        let position = self
            .positions
            .get(&p.position_id)
            .cloned()
            .ok_or(L2Error::UnknownCreditPosition)?;
        if position.borrower != p.borrower {
            return Err(L2Error::CreditBinding(
                "the position names another borrower",
            ));
        }
        if position.state != CreditPositionState::Open {
            return Err(L2Error::CreditPositionClosed);
        }
        if p.amount_sat == 0 {
            return Err(L2Error::ZeroAmount("credit repayment"));
        }
        let interest_due = position
            .schedule()
            .accrued_interest(
                position.outstanding_sat,
                position.interest_settled_height,
                height,
            )
            .map_err(|_| L2Error::CreditInterestOverflow)?;
        // A repayment may not exceed the debt. The lender is paid the debt and
        // not a satoshi more, and the borrower's excess is not silently taken
        // - the node-local credit book refuses the same shape, and the two
        // implementations of the same rule must agree.
        let debt = position
            .outstanding_sat
            .checked_add(interest_due)
            .ok_or(L2Error::Overflow)?;
        if p.amount_sat > debt {
            return Err(L2Error::CreditRepaymentExceedsDebt { debt });
        }
        let interest_paid = p.amount_sat.min(interest_due);
        let principal_paid = (p.amount_sat - interest_paid).min(position.outstanding_sat);
        let need = p.amount_sat.checked_add(fee).ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.borrower, need)?;
        self.charge(&p.borrower, need)?;
        self.pay(&position.lender, p.amount_sat)?;
        self.collect_fee(fee);
        let remaining = {
            let pos = self
                .positions
                .get_mut(&p.position_id)
                .ok_or(L2Error::UnknownCreditPosition)?;
            pos.outstanding_sat -= principal_paid;
            pos.interest_paid_sat += interest_paid;
            pos.interest_settled_height = height;
            if pos.outstanding_sat == 0 {
                pos.state = CreditPositionState::Repaid;
            }
            pos.outstanding_sat
        };
        // A settled position releases the collateral back to the borrower.
        if remaining == 0 {
            let collateral = {
                let pos = self
                    .positions
                    .get_mut(&p.position_id)
                    .ok_or(L2Error::UnknownCreditPosition)?;
                let c = pos.collateral_sat;
                pos.collateral_sat = 0;
                c
            };
            self.credit_locked = self
                .credit_locked
                .checked_sub(collateral)
                .ok_or(L2Error::Overflow)?;
            self.pay(&p.borrower, collateral)?;
        }
        Ok(L2Effect::CreditRepaid {
            position_id: p.position_id,
            borrower: p.borrower,
            amount_sat: p.amount_sat,
            interest_paid_sat: interest_paid,
            principal_paid_sat: principal_paid,
            remaining_debt_sat: remaining,
        })
    }

    /// Settle an overdue credit position (SPEC.md §22.6).
    ///
    /// Permissionless: anyone may trigger it, because a default only the
    /// lender could trigger is a default that could be delayed. The collateral
    /// answers for the debt, any surplus returns to the borrower, and what is
    /// left uncovered is a shortfall the lender absorbs rather than a loss the
    /// protocol invents money to cover.
    fn apply_credit_default(
        &mut self,
        p: &CreditDefaultPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        let position = self
            .positions
            .get(&p.position_id)
            .cloned()
            .ok_or(L2Error::UnknownCreditPosition)?;
        if position.state != CreditPositionState::Open {
            return Err(L2Error::CreditPositionClosed);
        }
        if height < position.deadline_height {
            return Err(L2Error::CreditNotDue);
        }
        let interest_due = position
            .schedule()
            .accrued_interest(
                position.outstanding_sat,
                position.interest_settled_height,
                height,
            )
            .map_err(|_| L2Error::CreditInterestOverflow)?;
        let debt = position
            .outstanding_sat
            .checked_add(interest_due)
            .ok_or(L2Error::Overflow)?;
        let take = position.collateral_sat.min(debt);
        let excess = position.collateral_sat - take;
        self.ensure_balance(&p.actor, fee)?;
        self.charge(&p.actor, fee)?;
        self.collect_fee(fee);
        self.credit_locked = self
            .credit_locked
            .checked_sub(position.collateral_sat)
            .ok_or(L2Error::Overflow)?;
        self.pay(&position.lender, take)?;
        self.pay(&position.borrower, excess)?;
        {
            let pos = self
                .positions
                .get_mut(&p.position_id)
                .ok_or(L2Error::UnknownCreditPosition)?;
            let principal_covered = take.min(pos.outstanding_sat);
            pos.outstanding_sat -= principal_covered;
            pos.interest_paid_sat += take - principal_covered;
            pos.collateral_sat = 0;
            pos.state = CreditPositionState::Defaulted;
        }
        Ok(L2Effect::CreditDefaulted {
            position_id: p.position_id,
            lender: position.lender,
            debt_sat: debt,
            from_collateral_sat: take,
            shortfall_sat: debt - take,
            excess_returned_sat: excess,
        })
    }

    fn apply_post(&mut self, p: &PostTaskPayload, height: u64, fee: u64) -> L2Result<L2Effect> {
        if self.tasks.contains_key(&p.task_id) {
            return Err(L2Error::TaskAlreadyExists);
        }
        let contract = TaskContract::new(p, height, self.config.dispute_window)?;
        let need = p.payment_sat.checked_add(fee).ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.submitter, need)?;
        self.charge(&p.submitter, need)?;
        self.collect_fee(fee);
        self.tasks.insert(p.task_id, contract);
        Ok(L2Effect::Posted {
            task_id: p.task_id,
            submitter: p.submitter,
            payment_sat: p.payment_sat,
        })
    }

    fn apply_claim(&mut self, p: &ClaimTaskPayload, height: u64, fee: u64) -> L2Result<L2Effect> {
        let need = p
            .worker_deposit_sat
            .checked_add(fee)
            .ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.worker, need)?;
        self.tasks
            .get_mut(&p.task_id)
            .ok_or(L2Error::UnknownTask)?
            .claim(p.worker, p, height)?;
        self.charge(&p.worker, need)?;
        self.collect_fee(fee);
        Ok(L2Effect::Claimed {
            task_id: p.task_id,
            worker: p.worker,
        })
    }

    fn apply_submit(
        &mut self,
        p: &SubmitResultPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        self.ensure_balance(&p.worker, fee)?;
        self.tasks
            .get_mut(&p.task_id)
            .ok_or(L2Error::UnknownTask)?
            .submit_result(p.worker, p, height)?;
        self.charge(&p.worker, fee)?;
        self.collect_fee(fee);
        Ok(L2Effect::ResultSubmitted {
            task_id: p.task_id,
            worker: p.worker,
            result_hash: p.result_hash,
        })
    }

    fn apply_dispute(&mut self, p: &DisputePayload, height: u64, fee: u64) -> L2Result<L2Effect> {
        let need = p
            .challenge_deposit_sat
            .checked_add(fee)
            .ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.challenger, need)?;
        self.tasks
            .get_mut(&p.task_id)
            .ok_or(L2Error::UnknownTask)?
            .file_dispute(p.challenger, p, height)?;
        self.charge(&p.challenger, need)?;
        self.collect_fee(fee);
        Ok(L2Effect::DisputeFiled {
            task_id: p.task_id,
            challenger: p.challenger,
        })
    }

    fn apply_settle(
        &mut self,
        p: &SettlePayload,
        txid: Hash512,
        height: u64,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> L2Result<L2Effect> {
        // The signed chain context first: a quorum aggregate binds the network
        // it was signed for and the height it was signed at, so a payload
        // naming another network — or a vote from the future — is refused by
        // name before any pairing runs.
        if p.network_id != self.config.network_id {
            return Err(L2Error::BadSettleNetwork);
        }
        if p.height > height {
            return Err(L2Error::BadSettleHeight);
        }
        // Quorum is three checks, in the order the M5 checkpoint validator uses:
        // the bitmap and the declared count must agree, the count must meet the
        // threshold, and the aggregate must verify over the bound message.
        let signers = validators.signers_from_bitmap(&p.signer_bitmap);
        if signers.len() != p.signer_count as usize {
            return Err(L2Error::BadQuorum);
        }
        if signers.len() < validators.quorum_size() {
            return Err(L2Error::BadQuorum);
        }
        let msg = p.signing_hash();
        if !verifier.verify_aggregate(&signers, &msg, &BlsSignature(p.bls_sig)) {
            return Err(L2Error::BadBlsSignature);
        }
        // Lattice sidecar, clause-7 shape: every bitmap signer holding a
        // registered lattice key in this set needs a valid entry over the
        // same decision hash. Sets without registered keys verify BLS-only,
        // exactly as before — the rule tightens only where keys exist.
        {
            let n = validators.keys.len();
            let mut seen = vec![false; n];
            srct_core::validators::check_sidecar(
                &p.pq_sidecar,
                n,
                // Bounds-checked: `signers_from_bitmap` tolerates a short
                // bitmap (missing bytes read as zero), but this closure runs
                // for every member index — an unchecked index here panics on
                // a truncated bitmap instead of refusing it.
                |idx| {
                    idx < n
                        && idx / 8 < p.signer_bitmap.len()
                        && (p.signer_bitmap[idx / 8] >> (idx % 8)) & 1 == 1
                },
                |idx| validators.mldsa_key(idx).copied(),
                &msg,
                &mut seen,
            )
            .map_err(|r| L2Error::BadPqSidecar(r.detail))?;
        }
        let (submitter, worker, challenger, outcome) = {
            let contract = self.tasks.get_mut(&p.task_id).ok_or(L2Error::UnknownTask)?;
            // Decision 23 (P5): the settle fee is proportional to the task's
            // escrow, not the flat `tx.fee_sat()` every other type uses. The
            // static schedule value is only the floor; the contract settles
            // what the rule says, charged by the existing paths below.
            let fee = settle_fee_sat(contract.payment_sat);
            let submitter = contract.submitter;
            let worker = contract.worker;
            let challenger = contract.challenger();
            let outcome = contract.settle(p.verdict, p.vwc_hash, height, fee)?;
            (submitter, worker, challenger, outcome)
        };

        // Issue the certificate *before* any value moves, so a refusal leaves
        // the state untouched (fail closed). Only a `Correct` settlement of real
        // work certifies: a `Fraudulent` verdict is a SlashRecord and an
        // `Expired` one is a refund, neither of which is a certificate
        // (SPEC.md §17.4). The evidence is the payload's own quorum aggregate.
        let vwc_id = if p.verdict == Verdict::Correct {
            if p.vwc_hash == VWC_HASH_EXPIRED {
                return Err(L2Error::VwcInvalid(
                    "a correct settlement named the expired-placeholder hash",
                ));
            }
            let worker =
                worker.ok_or(L2Error::VwcInvalid("a correct settlement without a worker"))?;
            let cert = VerifiedWorkCertificate::from_settlement(
                p.task_id,
                worker,
                p.vwc_hash,
                height,
                outcome.worker_paid,
                VwcVerification::Quorum {
                    bls_sig: p.bls_sig,
                    signer_bitmap: p.signer_bitmap.clone(),
                    signer_count: p.signer_count,
                    pq_sidecar: p.pq_sidecar.clone(),
                    network_id: p.network_id.clone(),
                    vote_height: p.height,
                },
            )?;
            Some(self.issue_vwc(cert)?)
        } else {
            None
        };

        let challenger_bonus =
            self.apply_settlement(submitter, worker, challenger, outcome, txid, height)?;
        Ok(L2Effect::Settled {
            task_id: p.task_id,
            verdict: p.verdict,
            worker_paid: outcome.worker_paid,
            submitter_refunded: outcome.submitter_refunded,
            worker_deposit_slashed: outcome.worker_deposit_slashed,
            challenger_bonus,
            vwc_id,
        })
    }

    /// Move value according to a settlement. Shared by explicit `Settle` and the
    /// implicit auto-settle/lapse paths, so all are accounted identically.
    ///
    /// Returns the whistleblower bounty paid, which is the only part of a
    /// settlement that depends on state outside the contract (the PSCB balance).
    ///
    /// The bounty is a transfer *out of* the reserve to the challenger, not a
    /// mint: the reserve falls by exactly what the challenger gains, so the
    /// conservation invariant is untouched. It is computed against the reserve
    /// balance *before* this settlement's own PSCB fee share is added, so a
    /// settlement cannot fund its own bounty.
    #[allow(clippy::too_many_arguments)]
    fn apply_settlement(
        &mut self,
        submitter: Address,
        worker: Option<Address>,
        challenger: Option<Address>,
        o: SettlementOutcome,
        txid: Hash512,
        height: u64,
    ) -> L2Result<u64> {
        // The submitter is always owed a refund on the paths that refund them
        // (fraud, expiry) and zero on the paths that do not, so it is credited
        // unconditionally rather than behind an `Option`.
        self.pay(&submitter, o.submitter_refunded)?;
        if let Some(w) = worker {
            self.pay(&w, o.worker_paid)?;
            self.pay(&w, o.worker_deposit_returned)?;
            if o.worker_deposit_slashed > 0 {
                // 50% is burned immediately and 50% vests through M2. Nothing is
                // credited here: the vault owns the vesting half.
                self.slash_vault.slash(
                    txid,
                    o.worker_deposit_slashed,
                    height,
                    self.config.vesting_period,
                    w,
                );
            }
        }
        let mut bonus = 0u64;
        if let Some(c) = challenger {
            self.pay(&c, o.challenger_refunded)?;
            if o.worker_deposit_slashed > 0 {
                // Checked: a saturated product would silently shrink the
                // challenger's bounty at the boundary instead of refusing.
                // (`validate` caps the percent at 100, but the deposit half
                // of the product is still attacker-chosen.)
                let wanted = o
                    .worker_deposit_slashed
                    .checked_mul(self.config.whistleblower_bounty_percent)
                    .ok_or(L2Error::Overflow)?
                    / 100;
                bonus = wanted.min(self.pscb);
                if bonus > 0 {
                    self.pay(&c, bonus)?;
                    self.pscb -= bonus;
                }
            }
        }
        // Checked like every adjacent `pay`/`charge` path: a clamped total
        // would make `check_conservation` meaningless at the boundary.
        self.burned = self
            .burned
            .checked_add(o.challenger_deposit_burned)
            .and_then(|v| v.checked_add(o.worker_deposit_burned))
            .and_then(|v| v.checked_add(o.fee_burned))
            .ok_or(L2Error::Overflow)?;
        self.pscb = self.pscb.checked_add(o.fee_pscb).ok_or(L2Error::Overflow)?;
        Ok(bonus)
    }

    // --- implicit transitions -----------------------------------------

    /// Advance the state to `height`: vest M2 payouts, then auto-settle or expire
    /// every task whose clock has run out.
    ///
    /// Processed in sorted task-id order so two nodes holding the same state
    /// produce the same effects in the same order. Nothing here charges a fee.
    pub fn advance_block(&mut self, height: u64) -> Vec<L2Effect> {
        let mut effects = Vec::new();

        for (addr, amount) in self.slash_vault.advance_block(height) {
            // A payout can only fail on an impossible overflow; dropping it would
            // lose value, so a failure is ignored rather than allowed to abort
            // the transition of every other task.
            let _ = self.pay(&addr, amount);
        }

        let mut ids: Vec<Hash> = self.tasks.keys().copied().collect();
        ids.sort_unstable();

        for id in ids {
            // Two implicit settlements share this path: the dispute window
            // closing with no challenge, and a filed dispute lapsing without a
            // resolution. Both settle as `Correct` with no fee; the difference
            // is which deposits move, and `settle_inner` accounts for that.
            let settled = {
                // invariant: `ids` was collected from these keys, and `tasks`
                // is insert-only, so the entry cannot be gone — a miss would
                // be a bug in this module, not an input to route around.
                let t = self.tasks.get_mut(&id).expect("id came from the map");
                let attrs = (t.submitter, t.worker, t.challenger());
                // The certificate binds to the result the settlement names, so
                // read it while the contract still carries it.
                let result = t.correct_settlement_hash(height);
                let outcome = if t.due_for_auto_settle(height) {
                    t.auto_settle_correct(height).ok()
                } else if t.due_for_dispute_lapse(height) {
                    t.lapse_dispute(height).ok()
                } else {
                    None
                };
                outcome.map(|o| (attrs, result, o))
            };
            if let Some(((submitter, worker, challenger), result, outcome)) = settled {
                let bonus = self
                    .apply_settlement(submitter, worker, challenger, outcome, [0u8; 64], height)
                    .unwrap_or(0);
                // An implicit settlement carries no aggregate (nothing was
                // transacted), so its certificate is `WindowElapsed` (§17.5).
                //
                // That certificate is a receipt for an uncontested settlement
                // and nothing more: the dispute window closing says nobody
                // objected, not that the result is right. A worker who submits
                // a wrong result and is never challenged reaches exactly here.
                // The settlement and the payment are correct either way — the
                // timeout economics requires a challenge to overturn one, or a
                // griefer could stall every task forever — so what must not
                // happen is the certificate reading as verification. It is
                // registered as `WindowElapsed`, `asserts_correctness()` is
                // false for it, and `validate_verified` refuses it by name.
                //
                // A task settles once, so a duplicate issuance is impossible;
                // `expect` rather than `unwrap_or(0)`/`Err(_) => None` because
                // silently recording nothing here would mean a corrupt state,
                // and a lost certificate is exactly the kind of drift that
                // makes two nodes disagree about a settled task.
                let vwc_id = worker.zip(result).map(|(w, r)| {
                    let cert = VerifiedWorkCertificate::from_settlement(
                        id,
                        w,
                        r,
                        height,
                        outcome.worker_paid,
                        VwcVerification::WindowElapsed,
                    )
                    // invariant: an implicit settlement carries a real worker,
                    // result and nonzero height by construction above.
                    .expect("an implicit settlement has a real worker, result and height");
                    let cert_id = cert.id;
                    self.issue_vwc(cert)
                        // invariant: a task settles once, so issuance cannot
                        // collide — a collision would be registry corruption.
                        .expect("a task settles once, so issuance cannot collide");
                    cert_id
                });
                effects.push(L2Effect::Settled {
                    task_id: id,
                    verdict: Verdict::Correct,
                    worker_paid: outcome.worker_paid,
                    submitter_refunded: outcome.submitter_refunded,
                    worker_deposit_slashed: 0,
                    challenger_bonus: bonus,
                    vwc_id,
                });
                continue;
            }

            let expired = self
                .tasks
                .get_mut(&id)
                // invariant: `id` came from the map and tasks is insert-only.
                .expect("id came from the map; tasks is insert-only")
                .try_expire(height);
            if let Some(o) = expired {
                let submitter = self
                    .tasks
                    .get(&id)
                    .map(|t| t.submitter)
                    // invariant: the entry above just produced this outcome.
                    .expect("expired task still exists; tasks is insert-only");
                let _ = self.pay(&submitter, o.submitter_refunded);
                self.burned = self.burned.saturating_add(o.worker_deposit_burned);
                effects.push(L2Effect::Expired {
                    task_id: id,
                    submitter_refunded: o.submitter_refunded,
                    worker_deposit_burned: o.worker_deposit_burned,
                });
            }
        }

        effects
    }

    // --- verified work certificates (Phase 4, SPEC.md §17) -------------

    /// The certificate issued for a task, if it settled as `Correct`.
    pub fn vwc(&self, task_id: &Hash) -> Option<&VerifiedWorkCertificate> {
        self.vwcs.get(task_id)
    }

    pub fn vwc_count(&self) -> usize {
        self.vwcs.len()
    }

    /// Every certificate, sorted by task id. Enumeration is never `HashMap`
    /// order, so two nodes holding the same state list the same certificates in
    /// the same order (§17.9).
    pub fn vwcs(&self) -> Vec<&VerifiedWorkCertificate> {
        let mut ids: Vec<Hash> = self.vwcs.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.vwcs[&id]).collect()
    }

    /// Validate a certificate against live state: everything
    /// `VerifiedWorkCertificate::validate` checks, plus the registry comparison
    /// (§17.6 check 4) — the certificate must be the one this state issued, byte
    /// for byte. A structurally valid certificate that no state issued proves
    /// nothing.
    ///
    /// This accepts a `WindowElapsed` certificate. Use
    /// [`Self::validate_vwc_verified`] when the question is whether the *result*
    /// is verified rather than whether the certificate is genuine.
    pub fn validate_vwc(
        &self,
        cert: &VerifiedWorkCertificate,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> L2Result<()> {
        cert.validate(validators, verifier)?;
        match self.vwcs.get(&cert.task_id) {
            Some(issued) if issued == cert => Ok(()),
            Some(_) => Err(L2Error::VwcInvalid("differs from the issued certificate")),
            None => Err(L2Error::VwcInvalid("was never issued by this state")),
        }
    }

    /// The registry check **plus** the requirement that the certificate actually
    /// verifies its result.
    ///
    /// A relying party that is about to pay for, publish, or otherwise act on a
    /// compute result must call this. The only difference from
    /// [`Self::validate_vwc`] is that a certificate resting on an unchallenged
    /// dispute window is refused — see
    /// [`crate::vwc::VerifiedWorkCertificate::validate_verified`] for why that
    /// state is reachable and what it does and does not prove.
    pub fn validate_vwc_verified(
        &self,
        cert: &VerifiedWorkCertificate,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> L2Result<()> {
        self.validate_vwc(cert, validators, verifier)?;
        cert.validate_verified(validators, verifier)
    }

    /// Record a certificate. Exactly one per task, ever: a second issuance for
    /// the same task is a protocol violation and is refused, never silently
    /// overwritten (§17.7).
    fn issue_vwc(&mut self, cert: VerifiedWorkCertificate) -> L2Result<Hash> {
        if self.vwcs.contains_key(&cert.task_id) {
            return Err(L2Error::VwcAlreadyIssued);
        }
        let id = cert.id;
        self.vwcs.insert(cert.task_id, cert);
        Ok(id)
    }

    // --- invariants ----------------------------------------------------

    pub fn total_accounts(&self) -> u64 {
        self.accounts
            .values()
            .copied()
            .fold(0u64, u64::saturating_add)
    }

    pub fn total_locked(&self) -> u64 {
        self.tasks
            .values()
            .map(|t| t.locked_total())
            .fold(0u64, u64::saturating_add)
    }

    /// Everything permanently destroyed: L2 fee burns plus failed-challenge and
    /// expiry burns, and the M2 vault's immediate burns.
    pub fn total_burned(&self) -> u64 {
        self.burned.saturating_add(self.slash_vault.total_burned)
    }

    /// The vesting half still held by the M2 vault. Saturating, like every
    /// other conservation leg: a plain sum would wrap on absurd record
    /// counts and misreport the conservation total instead of capping it.
    pub fn vault_remaining(&self) -> u64 {
        self.slash_vault
            .records()
            .iter()
            .map(|r| r.remaining_vest)
            .fold(0u64, u64::saturating_add)
    }

    /// Every satoshi still inside the system, in whatever bucket. Compared
    /// against total credited to prove nothing was created or destroyed.
    pub fn conservation_total(&self) -> u64 {
        self.total_accounts()
            .saturating_add(self.total_locked())
            .saturating_add(self.exits_locked)
            .saturating_add(self.credit_locked)
            .saturating_add(self.total_burned())
            .saturating_add(self.pscb)
            .saturating_add(self.vault_remaining())
    }

    /// The M2 invariant, self-checked: everything ever released is still
    /// somewhere in the system. Burns and PSCB accrual move value between
    /// buckets; they must never change the sum.
    pub fn check_conservation(&self) -> bool {
        self.conservation_total() == self.funded_total
    }
}

// ---------------------------------------------------------------------------
// Wire encoding (SPEC.md §19.2): the state a node serves a remote observer
// ---------------------------------------------------------------------------

/// The only state-transport version this build writes *and* reads. A blob
/// carrying another version is refused, never guessed at.
///
/// Version 2 adds the exit queue (approved P1): the activation height in the
/// config area, the exit records and per-owner nonces after the deposits, and
/// the two exit counters with the other counters. Version-1 blobs are refused
/// rather than guessed at — a state without exits cannot describe a chain
/// that queued one.
///
/// Version 3 adds the config `network_id` to the config area: the state now
/// names the chain it belongs to, which is what lets `apply` refuse a settle
/// aggregate signed for another network. Older blobs are refused rather than
/// guessed at — a state without a network cannot verify a network-bound
/// settlement.
///
/// Version 4 adds the published spending policies and grants (Decision 25);
/// version 5 adds credit positions, `credit_locked` and the credit transaction
/// state (Decision 26). Pre-bump blobs are refused rather than guessed at,
/// because a state that cannot describe a committed policy or credit position
/// would silently diverge from the chain.
pub const L2_STATE_WIRE_VERSION: u8 = 8;

/// Smallest possible encoded account entry: `20` address + `8` balance.
const WIRE_ACCOUNT_MIN: usize = 28;
/// Smallest possible encoded exit record: owner(20) + nonce(8) + amount(8) +
/// destination(20) + fee(8) + height(8). Fixed size, no prefix to lie about.
const WIRE_EXIT_MIN: usize = 72;
/// Smallest possible encoded exit-nonce entry: `20` owner + `8` nonce.
const WIRE_NONCE_MIN: usize = 28;
/// Smallest possible encoded per-owner window share: `20` owner + `8` total.
const WIRE_OWNER_MIN: usize = 28;
/// Smallest possible encoded applied-id entry.
const WIRE_HASH_MIN: usize = 32;
/// Smallest possible encoded deposit identity: `32` txid + `4` output index.
const WIRE_DEPOSIT_MIN: usize = 36;
/// Smallest possible encoded length-prefixed entry.
const WIRE_PREFIX_MIN: usize = 4;
/// Minimum bytes one published policy entry occupies on the wire.
const WIRE_POLICY_MIN: usize = 128;
/// Minimum bytes one credit position occupies on the wire.
const WIRE_CREDIT_MIN: usize = 141;

fn codec_err(what: &'static str) -> L2Error {
    L2Error::Codec(srct_core::Error::Malformed(what))
}

/// Counted section bound: a declared count can never exceed the bytes that
/// remain divided by the smallest entry it can encode, so a four-byte lie
/// cannot drive an allocation.
fn bounded_count(
    r: &Reader<'_>,
    declared: u64,
    min_entry: usize,
    what: &'static str,
) -> L2Result<usize> {
    let n = declared as usize;
    if declared > u64::try_from(usize::MAX).unwrap_or(u64::MAX) || n > r.remaining() / min_entry {
        return Err(codec_err(what));
    }
    Ok(n)
}

impl L2State {
    /// Canonical wire encoding of the whole state.
    ///
    /// Deterministic: every map is written in sorted key order, so two nodes
    /// holding equal states produce byte-identical blobs and a client can hash
    /// one for comparison. Nothing here is signed — a state is derived data,
    /// and the node's canonical blocks are what give it authority; this is only
    /// a transport (SPEC.md §19.2).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            128 + self.accounts.len() * WIRE_ACCOUNT_MIN + self.tasks.len() * 256,
        );
        w.u8(L2_STATE_WIRE_VERSION)
            .u32le(self.config.network_id.len() as u32)
            .raw(self.config.network_id.as_bytes())
            .u64le(self.config.dispute_window)
            .u64le(self.config.vesting_period)
            .u64le(self.config.whistleblower_bounty_percent)
            .u64le(self.config.exit_activation_height)
            // v6: exit throttle (window cap + large-exit delay).
            .u64le(self.config.max_exit_window_sat)
            .u64le(self.config.exit_window_blocks)
            // v7: per-owner window sub-cap (fairness bound on the v6 window).
            .u64le(self.config.max_exit_per_owner_window_sat)
            .u64le(self.config.large_exit_threshold_sat)
            .u64le(self.config.large_exit_extra_delay_blocks)
            // v8: credit-consent activation + caps, guarded activation + caps.
            .u64le(self.config.credit_consent_activation_height)
            .u64le(self.config.credit_max_collateral_multiple)
            .u64le(self.config.credit_max_term_blocks)
            .u64le(self.config.credit_min_window_blocks)
            .u64le(self.config.guarded_activation_height)
            .u64le(self.config.guarded_grant_delay_blocks)
            .u64le(self.config.guarded_max_grant_lifetime_blocks)
            .u64le(self.config.guarded_outflow_cap_bps)
        .u64le(self.config.guarded_outflow_window_blocks)
        .u64le(self.config.guarded_exit_delay_blocks)
        .u64le(self.config.guarded_approval_threshold_sat)
        .u8(u8::from(self.genesis_applied))
            .u64le(self.funded_total)
            .u64le(self.deposited_total)
            .u64le(self.exited_total)
            .u64le(self.burned)
            .u64le(self.pscb);

        let mut accounts: Vec<(&Address, &u64)> = self.accounts.iter().collect();
        accounts.sort_by_key(|(a, _)| **a);
        w.u64le(accounts.len() as u64);
        for (a, bal) in accounts {
            w.fixed(a).u64le(*bal);
        }

        let mut tasks: Vec<(&Hash, &TaskContract)> = self.tasks.iter().collect();
        tasks.sort_by_key(|(id, _)| **id);
        w.u64le(tasks.len() as u64);
        for (id, contract) in tasks {
            let bytes = contract.encode();
            w.fixed(id).u32le(bytes.len() as u32).raw(&bytes);
        }

        let mut applied: Vec<&Hash512> = self.applied.iter().collect();
        applied.sort();
        w.u64le(applied.len() as u64);
        for id in applied {
            w.fixed(id);
        }

        let mut deposits: Vec<&(Hash512, u32)> = self.deposits.iter().collect();
        deposits.sort_by_key(|d| d.0);
        w.u64le(deposits.len() as u64);
        for d in deposits {
            w.fixed(&d.0).u32le(d.1);
        }

        let mut exits: Vec<(&(Address, u64), &ExitRecord)> = self.exits.iter().collect();
        exits.sort_by_key(|(k, _)| **k);
        w.u64le(exits.len() as u64);
        for ((owner, nonce), record) in exits {
            debug_assert_eq!(*owner, record.owner);
            debug_assert_eq!(*nonce, record.nonce);
            record.encode(&mut w);
        }

        let mut nonces: Vec<(&Address, &u64)> = self.exit_nonce.iter().collect();
        nonces.sort_by_key(|(a, _)| **a);
        w.u64le(nonces.len() as u64);
        for (owner, nonce) in nonces {
            w.fixed(owner).u64le(*nonce);
        }
        w.u64le(self.exits_locked);
        // v6: exit window accounting (replay-derived, but encoded so a
        // transported state keeps the throttle it was built under).
        // v7: per-owner window shares, in address order like every map.
        w.u64le(self.exit_window_start)
            .u64le(self.exit_window_total);
        w.u64le(self.exit_window_owner.len() as u64);
        for (owner, total) in &self.exit_window_owner {
            w.fixed(owner).u64le(*total);
        }

        let mut vwcs: Vec<(&Hash, &VerifiedWorkCertificate)> = self.vwcs.iter().collect();
        vwcs.sort_by_key(|(id, _)| **id);
        w.u64le(vwcs.len() as u64);
        for (task_id, cert) in vwcs {
            let bytes = cert.encode();
            w.fixed(task_id).u32le(bytes.len() as u32).raw(&bytes);
        }

        let mut policies: Vec<(&Hash, &PolicyEntry)> = self.policies.iter().collect();
        policies.sort_by_key(|(h, _)| **h);
        w.u64le(policies.len() as u64);
        for (hash, entry) in policies {
            let bytes = entry.serialize();
            w.fixed(hash).u32le(bytes.len() as u32).raw(&bytes);
        }

        let mut positions: Vec<(&Hash, &CreditPosition)> = self.positions.iter().collect();
        positions.sort_by_key(|(h, _)| **h);
        w.u64le(positions.len() as u64);
        for (hash, position) in positions {
            w.fixed(hash);
            position.encode(&mut w);
        }
        w.u64le(self.credit_locked);

        w.raw(&self.slash_vault.encode());
        // v8: guarded accounts + audit anchors (Phase 3), in address/id order.
        let mut guarded: Vec<(&Address, &GuardedAccount)> = self.guarded.iter().collect();
        guarded.sort_by_key(|(a, _)| **a);
        w.u64le(guarded.len() as u64);
        for (_, g) in guarded {
            g.encode(&mut w);
        }
        let mut anchors: Vec<(&Hash, &AuditAnchorRecord)> = self.audit_anchors.iter().collect();
        anchors.sort_by_key(|(h, _)| **h);
        w.u64le(anchors.len() as u64);
        for (id, a) in anchors {
            w.fixed(id).fixed(&a.anchorer).fixed(&a.root).u64le(a.height).u64le(a.nonce);
        }
        w.into_vec()
    }

    /// Decode [`L2State::encode`]: bounded, self-validating, fail-closed.
    ///
    /// A refusal yields no state at all — never a partially populated one. On
    /// top of the structural checks (version, counts, duplicate keys, unknown
    /// tags, trailing bytes) this runs the protocol's own invariant
    /// ([`L2State::check_conservation`]), so a blob whose counters do not add
    /// up is rejected here rather than handed to a worker that would act on it.
    pub fn decode(bytes: &[u8]) -> L2Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| codec_err("state version"))?;
        // Accept v7 (pre-guarded) and v8 (guarded). v7 blobs have no guarded
        // section; v8 blobs do. This preserves pre-activation replay.
        if version != 7 && version != 8 && version != L2_STATE_WIRE_VERSION {
            return Err(L2Error::Codec(srct_core::Error::Malformed(match version {
                v if v > L2_STATE_WIRE_VERSION => "state version ahead of this build",
                _ => "state version not supported",
            })));
        }
        let wire_v8 = version >= 8;
        let id_len = r.u32le().map_err(|_| codec_err("network id length"))? as usize;
        if id_len > 64 || id_len > r.remaining() {
            return Err(codec_err("network id over cap"));
        }
        let network_id =
            std::str::from_utf8(r.fixed_slice(id_len).map_err(|_| codec_err("network id"))?)
                .map_err(|_| codec_err("network id not utf-8"))?
                .to_string();
        let config = L2Config {
            network_id,
            dispute_window: r.u64le().map_err(|_| codec_err("dispute window"))?,
            vesting_period: r.u64le().map_err(|_| codec_err("vesting period"))?,
            whistleblower_bounty_percent: r.u64le().map_err(|_| codec_err("bounty percent"))?,
            exit_activation_height: r.u64le().map_err(|_| codec_err("exit activation height"))?,
            max_exit_window_sat: r.u64le().map_err(|_| codec_err("exit window cap"))?,
            exit_window_blocks: r.u64le().map_err(|_| codec_err("exit window length"))?,
            // v7: the fairness bound on the window above.
            max_exit_per_owner_window_sat: r
                .u64le()
                .map_err(|_| codec_err("exit per-owner window cap"))?,
            large_exit_threshold_sat: r.u64le().map_err(|_| codec_err("large exit threshold"))?,
            large_exit_extra_delay_blocks: r.u64le().map_err(|_| codec_err("large exit delay"))?,
            // v8: credit-consent + guarded activation and caps. v7 blobs end
            // above; they decode with zeros (never active), preserving replay.
            credit_consent_activation_height: if wire_v8 {
                r.u64le().map_err(|_| codec_err("credit consent height"))?
            } else {
                0
            },
            credit_max_collateral_multiple: if wire_v8 {
                r.u64le().map_err(|_| codec_err("credit max multiple"))?
            } else {
                0
            },
            credit_max_term_blocks: if wire_v8 {
                r.u64le().map_err(|_| codec_err("credit max term"))?
            } else {
                0
            },
            credit_min_window_blocks: if wire_v8 {
                r.u64le().map_err(|_| codec_err("credit min window"))?
            } else {
                0
            },
            guarded_activation_height: if wire_v8 {
                r.u64le().map_err(|_| codec_err("guarded activation"))?
            } else {
                0
            },
            guarded_grant_delay_blocks: if wire_v8 {
                r.u64le().map_err(|_| codec_err("guarded delay"))?
            } else {
                0
            },
            guarded_max_grant_lifetime_blocks: if wire_v8 {
                r.u64le().map_err(|_| codec_err("guarded max lifetime"))?
            } else {
                0
            },
            guarded_outflow_cap_bps: if wire_v8 {
                r.u64le().map_err(|_| codec_err("guarded cap bps"))?
            } else {
                0
            },
        guarded_outflow_window_blocks: if wire_v8 {
            r.u64le().map_err(|_| codec_err("guarded window"))?
        } else {
            0
        },
        guarded_exit_delay_blocks: if wire_v8 {
            r.u64le().map_err(|_| codec_err("guarded exit delay"))?
        } else {
            0
        },
            guarded_approval_threshold_sat: if wire_v8 {
                r.u64le().map_err(|_| codec_err("guarded approval tier"))?
            } else {
                0
            },
        };
        // A blob carrying a config the constructors would never build (a
        // 200% bounty, a zero window) decodes into what `apply` could never
        // produce — validate it here rather than running under it.
        config.validate().map_err(|e| match e {
            L2Error::BadConfig(why) => codec_err(why),
            other => other,
        })?;
        let genesis_applied = match r.u8().map_err(|_| codec_err("genesis flag"))? {
            0 => false,
            1 => true,
            _ => return Err(codec_err("genesis flag out of range")),
        };
        let funded_total = r.u64le().map_err(|_| codec_err("funded total"))?;
        let deposited_total = r.u64le().map_err(|_| codec_err("deposited total"))?;
        let exited_total = r.u64le().map_err(|_| codec_err("exited total"))?;
        let burned = r.u64le().map_err(|_| codec_err("burned"))?;
        let pscb = r.u64le().map_err(|_| codec_err("pscb"))?;

        let declared_accounts = r.u64le().map_err(|_| codec_err("account count"))?;
        let n_accounts = bounded_count(
            &r,
            declared_accounts,
            WIRE_ACCOUNT_MIN,
            "account count exceeds buffer",
        )?;
        let mut accounts = HashMap::with_capacity(n_accounts);
        for _ in 0..n_accounts {
            let a: Address = r.fixed().map_err(|_| codec_err("account address"))?;
            let bal = r.u64le().map_err(|_| codec_err("account balance"))?;
            if accounts.insert(a, bal).is_some() {
                return Err(codec_err("duplicate account in state"));
            }
        }

        let declared_tasks = r.u64le().map_err(|_| codec_err("task count"))?;
        let n_tasks = bounded_count(
            &r,
            declared_tasks,
            WIRE_PREFIX_MIN,
            "task count exceeds buffer",
        )?;
        let mut tasks = HashMap::with_capacity(n_tasks);
        for _ in 0..n_tasks {
            let id: Hash = r.fixed().map_err(|_| codec_err("task id"))?;
            let len = r.u32le().map_err(|_| codec_err("task length"))? as usize;
            if len > r.remaining() {
                return Err(codec_err("task length exceeds buffer"));
            }
            let raw = r.fixed_slice(len).map_err(|_| codec_err("task bytes"))?;
            let contract = {
                let mut sub = Reader::new(raw);
                let c = TaskContract::decode(&mut sub)?;
                sub.expect_end()
                    .map_err(|_| codec_err("task has trailing bytes"))?;
                c
            };
            if contract.task_id != id {
                return Err(codec_err("task id disagrees with its contract"));
            }
            if tasks.insert(id, contract).is_some() {
                return Err(codec_err("duplicate task in state"));
            }
        }

        let declared_applied = r.u64le().map_err(|_| codec_err("applied count"))?;
        let n_applied = bounded_count(
            &r,
            declared_applied,
            WIRE_HASH_MIN,
            "applied count exceeds buffer",
        )?;
        let mut applied = HashSet::with_capacity(n_applied);
        for _ in 0..n_applied {
            let id: Hash512 = r.fixed().map_err(|_| codec_err("applied id"))?;
            if !applied.insert(id) {
                return Err(codec_err("duplicate applied id"));
            }
        }

        let declared_deposits = r.u64le().map_err(|_| codec_err("deposit count"))?;
        let n_deposits = bounded_count(
            &r,
            declared_deposits,
            WIRE_DEPOSIT_MIN,
            "deposit count exceeds buffer",
        )?;
        let mut deposits = HashSet::with_capacity(n_deposits);
        for _ in 0..n_deposits {
            let txid: Hash512 = r.fixed().map_err(|_| codec_err("deposit txid"))?;
            let idx = r.u32le().map_err(|_| codec_err("deposit index"))?;
            if !deposits.insert((txid, idx)) {
                return Err(codec_err("duplicate deposit identity"));
            }
        }

        let declared_exits = r.u64le().map_err(|_| codec_err("exit count"))?;
        let n_exits = bounded_count(
            &r,
            declared_exits,
            WIRE_EXIT_MIN,
            "exit count exceeds buffer",
        )?;
        let mut exits = HashMap::with_capacity(n_exits);
        let mut exits_locked = 0u64;
        for _ in 0..n_exits {
            // v8 records carry the guarded flag byte; v7 records do not.
            let record = if wire_v8 {
                ExitRecord::decode_v8(&mut r)?
            } else {
                ExitRecord::decode(&mut r)?
            };
            exits_locked = exits_locked
                .checked_add(
                    record
                        .amount_sat
                        .checked_add(record.exit_fee_sat)
                        .ok_or(codec_err("exit value overflows"))?,
                )
                .ok_or(codec_err("locked exits overflow"))?;
            if exits.insert((record.owner, record.nonce), record).is_some() {
                return Err(codec_err("duplicate exit identity"));
            }
        }

        let declared_nonces = r.u64le().map_err(|_| codec_err("exit nonce count"))?;
        let n_nonces = bounded_count(
            &r,
            declared_nonces,
            WIRE_NONCE_MIN,
            "exit nonce count exceeds buffer",
        )?;
        let mut exit_nonce = HashMap::with_capacity(n_nonces);
        for _ in 0..n_nonces {
            let owner: Address = r.fixed().map_err(|_| codec_err("nonce owner"))?;
            let nonce = r.u64le().map_err(|_| codec_err("nonce value"))?;
            if exit_nonce.insert(owner, nonce).is_some() {
                return Err(codec_err("duplicate nonce owner"));
            }
        }
        let decoded_exits_locked = r.u64le().map_err(|_| codec_err("locked exits"))?;
        if decoded_exits_locked != exits_locked {
            return Err(codec_err("locked exits disagree with the records"));
        }
        // v6: exit window accounting.
        let exit_window_start = r.u64le().map_err(|_| codec_err("exit window start"))?;
        let exit_window_total = r.u64le().map_err(|_| codec_err("exit window total"))?;
        // v7: per-owner shares. The count is bounded like every map, keys
        // must be unique, and the shares must add up to the window total
        // they break down — a blob whose breakdown disagrees with its total
        // is tampered with, not merely odd.
        let declared_owners = r.u64le().map_err(|_| codec_err("exit owner count"))?;
        let n_owners = bounded_count(
            &r,
            declared_owners,
            WIRE_OWNER_MIN,
            "exit owner count exceeds buffer",
        )?;
        let mut exit_window_owner = BTreeMap::new();
        let mut owner_sum = 0u64;
        for _ in 0..n_owners {
            let owner: Address = r.fixed().map_err(|_| codec_err("exit owner address"))?;
            let total = r.u64le().map_err(|_| codec_err("exit owner total"))?;
            owner_sum = owner_sum
                .checked_add(total)
                .ok_or(codec_err("exit owner shares overflow"))?;
            if exit_window_owner.insert(owner, total).is_some() {
                return Err(codec_err("duplicate exit owner in state"));
            }
        }
        if owner_sum != exit_window_total {
            return Err(codec_err(
                "exit owner shares disagree with the window total",
            ));
        }

        let declared_vwcs = r.u64le().map_err(|_| codec_err("certificate count"))?;
        let n_vwcs = bounded_count(
            &r,
            declared_vwcs,
            WIRE_PREFIX_MIN,
            "certificate count exceeds buffer",
        )?;
        let mut vwcs = HashMap::with_capacity(n_vwcs);
        for _ in 0..n_vwcs {
            let task_id: Hash = r.fixed().map_err(|_| codec_err("certificate task id"))?;
            let len = r.u32le().map_err(|_| codec_err("certificate length"))? as usize;
            if len > r.remaining() {
                return Err(codec_err("certificate length exceeds buffer"));
            }
            let raw = r
                .fixed_slice(len)
                .map_err(|_| codec_err("certificate bytes"))?;
            let cert = VerifiedWorkCertificate::decode(raw)?;
            if cert.task_id != task_id {
                return Err(codec_err("certificate names another task"));
            }
            if vwcs.insert(task_id, cert).is_some() {
                return Err(codec_err("duplicate certificate in state"));
            }
        }

        let declared_policies = r.u64le().map_err(|_| codec_err("policy count"))?;
        let n_policies = bounded_count(
            &r,
            declared_policies,
            WIRE_POLICY_MIN,
            "policy count exceeds buffer",
        )?;
        let mut policies: BTreeMap<Hash, PolicyEntry> = BTreeMap::new();
        for _ in 0..n_policies {
            let hash: Hash = r.fixed().map_err(|_| codec_err("policy hash"))?;
            let len = r.u32le().map_err(|_| codec_err("policy length"))? as usize;
            if len > r.remaining() {
                return Err(codec_err("policy length exceeds buffer"));
            }
            let raw = r.fixed_slice(len).map_err(|_| codec_err("policy bytes"))?;
            let entry =
                PolicyEntry::deserialize(raw).map_err(|_| codec_err("policy entry refused"))?;
            if entry.hash() != hash {
                return Err(codec_err("policy names another hash"));
            }
            if policies.insert(hash, entry).is_some() {
                return Err(codec_err("duplicate policy in state"));
            }
        }
        // The agent index is derived, not stored: one grant per agent, and a
        // live grant wins over a revoked one.
        let mut policy_by_agent: BTreeMap<AgentId, Hash> = BTreeMap::new();
        for (hash, entry) in policies.iter() {
            match policy_by_agent.get(&entry.agent_id).copied() {
                Some(existing) => {
                    let previous = &policies[&existing];
                    if previous.revoked && !entry.revoked {
                        policy_by_agent.insert(entry.agent_id, *hash);
                    }
                }
                None => {
                    policy_by_agent.insert(entry.agent_id, *hash);
                }
            }
        }

        let declared_positions = r.u64le().map_err(|_| codec_err("credit position count"))?;
        let n_positions = bounded_count(
            &r,
            declared_positions,
            WIRE_CREDIT_MIN,
            "credit position count exceeds buffer",
        )?;
        let mut positions: BTreeMap<Hash, CreditPosition> = BTreeMap::new();
        for _ in 0..n_positions {
            let hash: Hash = r.fixed().map_err(|_| codec_err("credit position id"))?;
            let position = CreditPosition::decode(&mut r)?;
            if position.id != hash {
                return Err(codec_err("credit position names another id"));
            }
            if positions.insert(hash, position).is_some() {
                return Err(codec_err("duplicate credit position in state"));
            }
        }
        let decoded_credit_locked = r.u64le().map_err(|_| codec_err("locked credit"))?;
        let credit_locked: u64 = positions
            .values()
            .map(|p| p.collateral_sat)
            .fold(0u64, u64::saturating_add);
        if decoded_credit_locked != credit_locked {
            return Err(codec_err("locked credit disagrees with the positions"));
        }

        let slash_vault = SlashVault::decode(&mut r)?;

        // v8: guarded accounts + audit anchors (Phase 3). v7 blobs end here.
        let (guarded, audit_anchors) = if wire_v8 {
            let ng = r.u64le().map_err(|_| codec_err("guarded count"))? as usize;
            if ng > 10_000 {
                return Err(codec_err("guarded count too large"));
            }
            let mut guarded = BTreeMap::new();
            for _ in 0..ng {
                let g = GuardedAccount::decode(&mut r)?;
                if guarded.insert(g.owner, g).is_some() {
                    return Err(codec_err("duplicate guarded account"));
                }
            }
            let na = r.u64le().map_err(|_| codec_err("audit anchor count"))? as usize;
            if na > 10_000 {
                return Err(codec_err("audit anchor count too large"));
            }
            let mut audit_anchors = BTreeMap::new();
            for _ in 0..na {
                let id: Hash = r.fixed().map_err(|_| codec_err("audit id"))?;
                let anchorer: Address = r.fixed().map_err(|_| codec_err("audit anchorer"))?;
                let root: Hash = r.fixed().map_err(|_| codec_err("audit root"))?;
                let height = r.u64le().map_err(|_| codec_err("audit height"))?;
                let nonce = r.u64le().map_err(|_| codec_err("audit nonce"))?;
                if audit_anchors
                    .insert(id, AuditAnchorRecord { anchorer, root, height, nonce })
                    .is_some()
                {
                    return Err(codec_err("duplicate audit anchor"));
                }
            }
            (guarded, audit_anchors)
        } else {
            (BTreeMap::new(), BTreeMap::new())
        };

        r.expect_end()
            .map_err(|_| codec_err("state has trailing bytes"))?;

        let state = L2State {
            config,
            accounts,
            tasks,
            applied,
            funded_total,
            genesis_applied,
            deposits,
            deposited_total,
            burned,
            pscb,
            slash_vault,
            vwcs,
            exits,
            exit_nonce,
            exits_locked,
            exited_total,
            exit_window_start,
            exit_window_total,
            exit_window_owner,
            policies,
            policy_by_agent,
            positions,
            credit_locked,
            guarded,
            audit_anchors,
        };
        // The protocol's own invariant. A state that does not conserve is not
        // a valid observation of the chain, whatever its structure said.
        // A disabled throttle never accumulates window accounting, so a blob
        // carrying it under a zero cap is tampered with, not merely odd.
        if state.config.max_exit_window_sat == 0
            && (state.exit_window_start != 0
                || state.exit_window_total != 0
                || !state.exit_window_owner.is_empty())
        {
            return Err(codec_err("exit window accounting under a disabled cap"));
        }
        // Shares obey the sub-cap they were built under: a blob carrying a
        // share above its own cap was never queueable.
        if state.config.max_exit_per_owner_window_sat > 0 {
            for total in state.exit_window_owner.values() {
                if *total > state.config.max_exit_per_owner_window_sat {
                    return Err(codec_err("exit owner share exceeds its cap"));
                }
            }
        }
        // Exit nonces must also cover their records: a record beyond its
        // owner's last nonce was never queueable.
        for (owner, nonce) in state.exits.keys() {
            if state.exit_nonce.get(owner).copied().unwrap_or(0) < *nonce {
                return Err(codec_err("exit record beyond the owner's last nonce"));
            }
        }
        if !state.check_conservation() {
            return Err(codec_err("decoded state fails the conservation invariant"));
        }
        Ok(state)
    }
}
