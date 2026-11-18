//! Layer-2 transaction types. Decision D3, `docs/decisions.md`.
//!
//! Solar Cyber Unit's L2 is the verified-work marketplace: a submitter posts a compute
//! task with a locked payment, a worker claims and runs it, and settlement
//! releases the payment against a verdict. A sixth type, `ExitQueue`, moves
//! value the other way — out of L2 and back to L1 (Decision 19, SPEC.md §19.6).
//! These six payload types are the protocol vocabulary for that loop.
//!
//! Scope, stated precisely because it is easy to over-read: these are *payload*
//! types. They are validated and fee-routed here — the flat D3 schedule routes
//! through `fees::split_flat_fee`, so the L1 `base_fee · gas_used` floor is
//! untouched and no exemption is created. M1 (SPEC.md §19.1) carries them inside
//! L1 blocks as a length-prefixed trailer committed by
//! `block::merkle_root_with_l2`.
//!
//! Nothing here changes the L1 fee floor, the L1 gas model, or any frozen
//! vector: a block with no L2 transactions still encodes byte-identically to the
//! pre-M1 format.
//!
//! Encoding discipline, matching the rest of `srct-core`:
//! - Every payload is canonically encodable: `serialize`/`from_reader` are exact
//!   inverses, and every length prefix is bounded before it drives an
//!   allocation.
//! - Authorization payloads commit to an explicit actor address and a signature
//!   bundle over a domain-separated signing hash. The hash covers the key bundle
//!   but not the signature bundle, exactly as the L1 `sighash` does.
//! - `Settle` has no single signer: its authorization is a validator-quorum BLS
//!   aggregate, reusing the M5 `ValidatorSet`/`BlsVerifier` machinery. The
//!   aggregate covers the same domain-separated hash, so a settle decision
//!   cannot be replayed at another task or verdict.
//!
//! Fees are the flat D3 schedule (`params::FEE_TX_*`). They are charged on a
//! path of their own through `fees::split_flat_fee`, which keeps the M1 50/50
//! burn/PSCB invariant and leaves the L1 `base_fee * gas_used` floor untouched.

use crate::agent::AgentId;
use crate::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use crate::error::{Error, Result};
use crate::hash::{sha256_dom, sha512_dom, Address, Hash, Hash512};
use crate::params::{
    FEE_TX_AGENT_SPEND_SAT, FEE_TX_CLAIM_TASK_SAT, FEE_TX_CREDIT_COLLATERAL_SAT,
    FEE_TX_CREDIT_DEFAULT_SAT, FEE_TX_CREDIT_OPEN_SAT, FEE_TX_CREDIT_REPAY_SAT, FEE_TX_DISPUTE_SAT,
    FEE_TX_EXIT_QUEUE_SAT, FEE_TX_POLICY_REVOKE_SAT, FEE_TX_POLICY_SAT, FEE_TX_POST_TASK_SAT,
    FEE_TX_SUBMIT_RESULT_SAT, L2_FLAT_FEE_MINIMUM_SAT, SETTLE_FEE_MIN_SAT,
};
use crate::ser::{Reader, Writer};
use crate::sig::{Bundle, Component, SCHEME_SECP256K1_ECDSA, SCHEME_SECP256K1_SCHNORR};
use crate::wallet::Wallet;

// ---------------------------------------------------------------------------
// Domain tags and wire type codes
// ---------------------------------------------------------------------------

/// `srct/l2/...` construction tags, frozen like `hash.rs`'s. A changed
/// preimage needs a new tag rather than a reused one.
pub const DOM_L2_POST: &[u8] = b"srct/l2/post/v1";
pub const DOM_L2_CLAIM: &[u8] = b"srct/l2/claim/v1";
pub const DOM_L2_SUBMIT: &[u8] = b"srct/l2/submit/v1";
pub const DOM_L2_DISPUTE: &[u8] = b"srct/l2/dispute/v1";
pub const DOM_L2_SETTLE: &[u8] = b"srct/l2/settle/v1";
pub const DOM_L2_TXID: &[u8] = b"srct/l2/txid/v1";
/// 512-bit L2 transaction id. An L2 txid is a transaction id, so it carries
/// the widened width for the same reason the L1 one does.
pub const DOM_L2_TXID512: &[u8] = b"srct/l2/txid512/v1";
/// Exit queue authorization (approved P1, E-1…E-3). Covers the owner, the
/// per-owner nonce, the amount, the destination and the prepaid release fee —
/// exactly the record the L1 release proof re-states, so a queue
/// authorization cannot be reinterpreted as anything else.
pub const DOM_L2_EXIT_QUEUE: &[u8] = b"srct/l2/exit-queue/v1";
/// Verified Work Certificate identity (SPEC.md §17.3). Derives a certificate id
/// from its canonical encoding; a different preimage needs a new tag.
pub const DOM_L2_VWC: &[u8] = b"srct/l2/vwc/v1";
/// Policy publication (SPEC.md §21.1). Covers the owner's signature over the
/// grant bytes, the spender the grant names and the agent identity it names.
pub const DOM_L2_POLICY: &[u8] = b"srct/l2/policy/v1";
/// Policy revocation (SPEC.md §21.2). Covers the owner and the agent whose
/// grant is being killed.
pub const DOM_L2_POLICY_REVOKE: &[u8] = b"srct/l2/policy-revoke/v1";
/// Agent spend under a published policy (SPEC.md §21.3). Covers the spender,
/// the policy it names, the nonce, the recipient, the amount and the service tag.
pub const DOM_L2_AGENT_SPEND: &[u8] = b"srct/l2/agent-spend/v1";
/// Credit position identity (SPEC.md §22.2). Derives a position id from its
/// terms, so two positions that differ in any term are different positions.
pub const DOM_L2_CREDIT_POSITION: &[u8] = b"srct/l2/credit-position/v1";
/// Credit opening (SPEC.md §22.3). Covers the lender's signature over the
/// whole set of terms.
pub const DOM_L2_CREDIT_OPEN: &[u8] = b"srct/l2/credit-open/v1";
/// Additional collateral (SPEC.md §22.4).
pub const DOM_L2_CREDIT_COLLATERAL: &[u8] = b"srct/l2/credit-collateral/v1";
/// Credit repayment (SPEC.md §22.5).
pub const DOM_L2_CREDIT_REPAY: &[u8] = b"srct/l2/credit-repay/v1";
/// Credit default (SPEC.md §22.6).
pub const DOM_L2_CREDIT_DEFAULT: &[u8] = b"srct/l2/credit-default/v1";
/// Guarded opt-in (Phase 3). Covers the account opting into guarded mode and
/// the per-account nonce, so an opt-in cannot be replayed for another account.
pub const DOM_L2_GUARDED_OPTIN: &[u8] = b"srct/l2/guarded-optin/v1";
/// Guardian cancellation (Phase 3). Covers the guardian, the guarded account,
/// the cancelled target and the nonce.
pub const DOM_L2_GUARDED_CANCEL: &[u8] = b"srct/l2/guarded-cancel/v1";
/// Guardian freeze (Phase 3). Covers the guardian, the frozen account and the nonce.
pub const DOM_L2_GUARDED_FREEZE: &[u8] = b"srct/l2/guarded-freeze/v1";
/// Audit anchor (Phase 3). Covers the anchorer, the anchored Merkle root, the
/// height and the nonce.
pub const DOM_L2_AUDIT_ANCHOR: &[u8] = b"srct/l2/audit-anchor/v1";

/// Wire type codes. Deliberately `0x10`-based: L1 uses `0` and `1`, and leaving a
/// clear gap means an L1 `tx_type` this build does not know is rejected as an
/// unknown *L1* type rather than silently read as an L2 one.
pub const L2_TX_POST: u8 = 0x10;
pub const L2_TX_CLAIM: u8 = 0x11;
pub const L2_TX_SUBMIT: u8 = 0x12;
pub const L2_TX_DISPUTE: u8 = 0x13;
pub const L2_TX_SETTLE: u8 = 0x14;
/// L2 → L1 exit queue (approved P1). Next free byte after the Phase-2 five;
/// an older node reads it as an unknown L2 type and skips the transaction,
/// exactly as it does for any future type.
pub const L2_TX_EXIT_QUEUE: u8 = 0x15;
/// Publish a spending policy (SPEC.md §21.1). The owner's signed grant enters
/// the chain here; every later spend under it is authorised by the policy.
pub const L2_TX_POLICY: u8 = 0x16;
/// Revoke a published policy (SPEC.md §21.2). The owner's kill switch.
pub const L2_TX_POLICY_REVOKE: u8 = 0x17;
/// Spend under a published policy (SPEC.md §21.3). Signed by the spender the
/// grant names, bounded by the grant's own caps and allow-lists.
pub const L2_TX_AGENT_SPEND: u8 = 0x18;
/// Open a credit position (SPEC.md §22.3). Signed by the **lender**: without
/// the lender's signature there is no loan, only a claim.
pub const L2_TX_CREDIT_OPEN: u8 = 0x19;
/// Add collateral to a credit position (SPEC.md §22.4).
pub const L2_TX_CREDIT_COLLATERAL: u8 = 0x1A;
/// Repay a credit position (SPEC.md §22.5).
pub const L2_TX_CREDIT_REPAY: u8 = 0x1B;
/// Settle a credit position that was not repaid by its deadline
/// (SPEC.md §22.6). Permissionless: anyone may trigger it.
pub const L2_TX_CREDIT_DEFAULT: u8 = 0x1C;
/// Open a credit position with borrower consent (Phase 2 fix).
/// Requires BOTH lender and borrower signatures over identical terms.
/// Caps: collateral <= 2x required, deadline bounded, window >= minimum.
/// Activated at `credit_consent_activation_height`; old 0x19 kept decoding
/// for pre-activation replay.
pub const L2_TX_CREDIT_OPEN_V2: u8 = 0x1D;
/// Opt an L2 account into guarded mode (Phase 3). Creates the guarded-account
/// record (leaf tag 0x07, state wire 8). Per-account opt-in only, never global.
pub const L2_TX_GUARDED_OPTIN: u8 = 0x1E;
/// Guardian cancellation of a pending guarded exit or grant (Phase 3).
/// Valid only during the extra delay window, only for guarded accounts.
pub const L2_TX_GUARDED_CANCEL: u8 = 0x1F;
/// Guardian freeze of a guarded account (Phase 3). Halts outflows pending review.
pub const L2_TX_GUARDED_FREEZE: u8 = 0x20;
/// Anchor an audit Merkle root (Phase 3). Commits an off-chain audit log root
/// on-chain for verifiability. No dust-to-derived-address hack.
pub const L2_TX_AUDIT_ANCHOR: u8 = 0x21;

/// Largest policy grant accepted in a publish transaction, in bytes. The policy
/// encoding is bounded by its own field caps (64 recipients, 64 services), so
/// this is a generous structural ceiling whose only job is to stop a length
/// prefix from driving an allocation.
pub const MAX_POLICY_BYTES: usize = 4_096;

/// Largest settle signer bitmap accepted, in bytes (512 validators). `TopN = 21`
/// is the decided committee size, so this is a generous structural cap whose only
/// job is to stop a length prefix from driving an allocation.
pub const MAX_SIGNER_BITMAP_BYTES: usize = 64;

/// The `vwc_hash` value used before Verified Work Certificates exist (Phase 4):
/// the validated result hash for `Correct`, the challenger's counter-result for
/// `Fraudulent`, and all-zero for `Expired`.
pub const VWC_HASH_EXPIRED: Hash = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L2TxType {
    PostTask,
    ClaimTask,
    SubmitResult,
    Dispute,
    Settle,
    ExitQueue,
    Policy,
    PolicyRevoke,
    AgentSpend,
    CreditOpen,
    CreditCollateral,
    CreditRepay,
    CreditDefault,
    CreditOpenV2,
    GuardedOptIn,
    GuardedCancel,
    GuardedFreeze,
    AuditAnchor,
}

impl L2TxType {
    pub fn to_wire(self) -> u8 {
        match self {
            L2TxType::PostTask => L2_TX_POST,
            L2TxType::ClaimTask => L2_TX_CLAIM,
            L2TxType::SubmitResult => L2_TX_SUBMIT,
            L2TxType::Dispute => L2_TX_DISPUTE,
            L2TxType::Settle => L2_TX_SETTLE,
            L2TxType::ExitQueue => L2_TX_EXIT_QUEUE,
            L2TxType::Policy => L2_TX_POLICY,
            L2TxType::PolicyRevoke => L2_TX_POLICY_REVOKE,
            L2TxType::AgentSpend => L2_TX_AGENT_SPEND,
            L2TxType::CreditOpen => L2_TX_CREDIT_OPEN,
            L2TxType::CreditCollateral => L2_TX_CREDIT_COLLATERAL,
            L2TxType::CreditRepay => L2_TX_CREDIT_REPAY,
            L2TxType::CreditDefault => L2_TX_CREDIT_DEFAULT,
            L2TxType::CreditOpenV2 => L2_TX_CREDIT_OPEN_V2,
            L2TxType::GuardedOptIn => L2_TX_GUARDED_OPTIN,
            L2TxType::GuardedCancel => L2_TX_GUARDED_CANCEL,
            L2TxType::GuardedFreeze => L2_TX_GUARDED_FREEZE,
            L2TxType::AuditAnchor => L2_TX_AUDIT_ANCHOR,
        }
    }

    pub fn from_wire(b: u8) -> Result<Self> {
        match b {
            L2_TX_POST => Ok(L2TxType::PostTask),
            L2_TX_CLAIM => Ok(L2TxType::ClaimTask),
            L2_TX_SUBMIT => Ok(L2TxType::SubmitResult),
            L2_TX_DISPUTE => Ok(L2TxType::Dispute),
            L2_TX_SETTLE => Ok(L2TxType::Settle),
            L2_TX_EXIT_QUEUE => Ok(L2TxType::ExitQueue),
            L2_TX_POLICY => Ok(L2TxType::Policy),
            L2_TX_POLICY_REVOKE => Ok(L2TxType::PolicyRevoke),
            L2_TX_AGENT_SPEND => Ok(L2TxType::AgentSpend),
            L2_TX_CREDIT_OPEN => Ok(L2TxType::CreditOpen),
            L2_TX_CREDIT_COLLATERAL => Ok(L2TxType::CreditCollateral),
            L2_TX_CREDIT_REPAY => Ok(L2TxType::CreditRepay),
            L2_TX_CREDIT_DEFAULT => Ok(L2TxType::CreditDefault),
            L2_TX_CREDIT_OPEN_V2 => Ok(L2TxType::CreditOpenV2),
            L2_TX_GUARDED_OPTIN => Ok(L2TxType::GuardedOptIn),
            L2_TX_GUARDED_CANCEL => Ok(L2TxType::GuardedCancel),
            L2_TX_GUARDED_FREEZE => Ok(L2TxType::GuardedFreeze),
            L2_TX_AUDIT_ANCHOR => Ok(L2TxType::AuditAnchor),
            _ => Err(Error::Malformed("unknown L2 transaction type")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            L2TxType::PostTask => "PostTask",
            L2TxType::ClaimTask => "ClaimTask",
            L2TxType::SubmitResult => "SubmitResult",
            L2TxType::Dispute => "Dispute",
            L2TxType::Settle => "Settle",
            L2TxType::ExitQueue => "ExitQueue",
            L2TxType::Policy => "Policy",
            L2TxType::PolicyRevoke => "PolicyRevoke",
            L2TxType::AgentSpend => "AgentSpend",
            L2TxType::CreditOpen => "CreditOpen",
            L2TxType::CreditCollateral => "CreditCollateral",
            L2TxType::CreditRepay => "CreditRepay",
            L2TxType::CreditDefault => "CreditDefault",
            L2TxType::CreditOpenV2 => "CreditOpenV2",
            L2TxType::GuardedOptIn => "GuardedOptIn",
            L2TxType::GuardedCancel => "GuardedCancel",
            L2TxType::GuardedFreeze => "GuardedFreeze",
            L2TxType::AuditAnchor => "AuditAnchor",
        }
    }

    /// The D3 flat fee for this type, in satoshis.
    ///
    /// `Settle` returns the anti-spam floor, not the fee: the actual settle
    /// fee is proportional to task value — see [`settle_fee_sat`]. Callers
    /// estimating a settlement must use that function with the task's escrow;
    /// this floor is only the minimum every settle pays.
    ///
    /// Every fee is clamped to [`L2_FLAT_FEE_MINIMUM_SAT`] so that no
    /// re-parameterization can accidentally produce a zero or sub-floor fee.
    pub fn fee_sat(self) -> u64 {
        self.fee_sat_raw().max(L2_FLAT_FEE_MINIMUM_SAT)
    }

    /// The raw D3 flat fee before the minimum-fee floor. Internal callers that
    /// need the exact constant (e.g. for fee accounting displays) use this;
    /// consensus application must use [`fee_sat`] to get the floored value.
    pub fn fee_sat_raw(self) -> u64 {
        match self {
            L2TxType::PostTask => FEE_TX_POST_TASK_SAT,
            L2TxType::ClaimTask => FEE_TX_CLAIM_TASK_SAT,
            L2TxType::SubmitResult => FEE_TX_SUBMIT_RESULT_SAT,
            L2TxType::Dispute => FEE_TX_DISPUTE_SAT,
            L2TxType::Settle => SETTLE_FEE_MIN_SAT,
            L2TxType::ExitQueue => FEE_TX_EXIT_QUEUE_SAT,
            L2TxType::Policy => FEE_TX_POLICY_SAT,
            L2TxType::PolicyRevoke => FEE_TX_POLICY_REVOKE_SAT,
            L2TxType::AgentSpend => FEE_TX_AGENT_SPEND_SAT,
            L2TxType::CreditOpen => FEE_TX_CREDIT_OPEN_SAT,
            L2TxType::CreditCollateral => FEE_TX_CREDIT_COLLATERAL_SAT,
            L2TxType::CreditRepay => FEE_TX_CREDIT_REPAY_SAT,
            L2TxType::CreditDefault => FEE_TX_CREDIT_DEFAULT_SAT,
            L2TxType::CreditOpenV2 => FEE_TX_CREDIT_OPEN_SAT,
            L2TxType::GuardedOptIn => FEE_TX_POLICY_SAT,
            L2TxType::GuardedCancel => FEE_TX_POLICY_SAT,
            L2TxType::GuardedFreeze => FEE_TX_POLICY_SAT,
            L2TxType::AuditAnchor => FEE_TX_POLICY_SAT,
        }
    }
}

/// Decision 23 (P5): the proportional settle fee — 0.1% of the task's escrow
/// value, minimum [`SETTLE_FEE_MIN_SAT`] sat. A task settles exactly when its
/// escrow covers this: below the floor the fee exceeds the value (refused),
/// at or above it the fee is always payable, since `payment/1000 <= payment`
/// for every non-zero payment. Deterministic protocol rule, no discretion.
pub fn settle_fee_sat(payment_sat: u64) -> u64 {
    (payment_sat / 1000).max(SETTLE_FEE_MIN_SAT)
}

/// The settlement verdict a validator quorum signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Verdict {
    /// The worker's submitted result is correct. Payment releases to the worker.
    #[default]
    Correct,
    /// The challenger's counter-result is correct. The worker's deposit is
    /// slashed through M2.
    Fraudulent,
    /// The task lapsed. The submitter is refunded; the worker's deposit, if any,
    /// is burned in full (no vest — a smaller penalty than a fraud slash).
    Expired,
}

impl Verdict {
    pub fn to_wire(self) -> u8 {
        match self {
            Verdict::Correct => 0,
            Verdict::Fraudulent => 1,
            Verdict::Expired => 2,
        }
    }

    pub fn from_wire(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Verdict::Correct),
            1 => Ok(Verdict::Fraudulent),
            2 => Ok(Verdict::Expired),
            _ => Err(Error::Malformed("unknown settlement verdict")),
        }
    }
}

// ---------------------------------------------------------------------------
// Authorization bundle
// ---------------------------------------------------------------------------

/// A signed actor identity: a public-key bundle and the matching signature
/// bundle over the payload's signing hash.
///
/// The shape mirrors an L1 input, and for the same two reasons recorded in
/// `sig.rs`: every component must verify, and the address commits to the whole
/// key bundle so a hybrid key set cannot be swapped for a single-scheme one.
/// Newly built authorizations are hybrid (ECDSA + Schnorr), so an L2 actor's
/// address is the same as the address their L1 wallet funds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Auth {
    pub keys: Bundle,
    pub sigs: Bundle,
}

impl Auth {
    /// The hybrid key bundle for `wallet`. Its address is [`Wallet::address`],
    /// identical to the wallet's L1 funding address.
    pub fn keys_for(wallet: &Wallet) -> Result<Bundle> {
        Ok(Bundle {
            components: vec![
                Component::new(SCHEME_SECP256K1_ECDSA, wallet.pubkey()?.to_vec()),
                Component::new(SCHEME_SECP256K1_SCHNORR, wallet.schnorr_pubkey()?.to_vec()),
            ],
        })
    }

    /// The hybrid signature bundle for `wallet` over `msg`.
    pub fn sigs_for(wallet: &Wallet, msg: &Hash) -> Result<Bundle> {
        Ok(Bundle {
            components: vec![
                Component::new(SCHEME_SECP256K1_ECDSA, wallet.sign_digest(msg)?.to_vec()),
                Component::new(SCHEME_SECP256K1_SCHNORR, wallet.sign_schnorr(msg)?.to_vec()),
            ],
        })
    }

    /// Sign `msg` as a hybrid bundle from `wallet`.
    pub fn sign(wallet: &Wallet, msg: &Hash) -> Result<Self> {
        Ok(Auth {
            keys: Self::keys_for(wallet)?,
            sigs: Self::sigs_for(wallet, msg)?,
        })
    }

    /// The address this authorization acts as.
    pub fn address(&self) -> Result<Address> {
        self.keys.address()
    }

    /// Verify the signature bundle against the key bundle over `msg`.
    pub fn verify(&self, msg: &Hash) -> Result<()> {
        crate::sig::verify_bundle(&self.sigs, &self.keys, msg)
    }

    /// Check the signature *and* that it acts as `actor`.
    pub fn verify_as(&self, actor: &Address, msg: &Hash) -> Result<()> {
        if &self.address()? != actor {
            return Err(Error::WrongAddress);
        }
        self.verify(msg)
    }

    fn write_full(&self, w: &mut Writer) {
        w.raw(&self.keys.to_bytes());
        w.raw(&self.sigs.to_bytes());
    }

    fn write_body(&self, w: &mut Writer) {
        w.raw(&self.keys.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Auth {
            keys: Bundle::from_reader(r)?,
            sigs: Bundle::from_reader(r)?,
        })
    }
}

/// Task id derived from the posting actor, a nonce, and the task hash.
///
/// Deterministic and unique per `(submitter, nonce, task)`. The nonce is what
/// makes two otherwise identical posts distinct; the submitter is bound in so a
/// third party cannot repost another actor's task under a colliding id.
pub fn derive_task_id(submitter: &Address, nonce: u64, task_hash: &Hash) -> Hash {
    let mut w = Writer::new();
    w.fixed(submitter).u64le(nonce).fixed(task_hash);
    sha256_dom(DOM_L2_POST, &[w.as_slice()])
}

// ---------------------------------------------------------------------------
// PostTask
// ---------------------------------------------------------------------------

/// Locks `payment_sat` from `submitter` until the task settles or expires, and
/// publishes the M3 compute envelope on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostTaskPayload {
    pub submitter: Address,
    pub auth: Auth,
    /// Must equal [`PostTaskPayload::derived_task_id`]; validated on admission so
    /// an actor cannot choose an arbitrary (or colliding) id.
    pub task_id: Hash,
    pub payment_sat: u64,
    /// Per-submitter sequence number, part of the task id derivation.
    pub nonce: u64,
    pub deadline_height: u64,
    pub compute_task: ComputeTask,
}

impl PostTaskPayload {
    /// Build and hybrid-sign a post. `task_id` is derived, never supplied.
    pub fn build(
        wallet: &Wallet,
        nonce: u64,
        payment_sat: u64,
        deadline_height: u64,
        compute_task: ComputeTask,
    ) -> Result<Self> {
        let submitter = wallet.address()?;
        let mut p = PostTaskPayload {
            submitter,
            auth: Auth::default(),
            task_id: [0u8; 32],
            payment_sat,
            nonce,
            deadline_height,
            compute_task,
        };
        p.task_id = p.derived_task_id();
        // Sign with the key bundle already in place; only the signature half is
        // excluded from the hash.
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn derived_task_id(&self) -> Hash {
        derive_task_id(&self.submitter, self.nonce, &self.compute_task.task_hash())
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_POST, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.submitter, &self.signing_hash())
    }

    /// The signing preimage: everything but the signature bundle.
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.submitter);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .u64le(self.payment_sat)
            .u64le(self.nonce)
            .u64le(self.deadline_height)
            .raw(&self.compute_task.serialize());
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let submitter: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let payment_sat = r.u64le()?;
        let nonce = r.u64le()?;
        let deadline_height = r.u64le()?;
        let compute_task = ComputeTask::from_reader(r)?;
        Ok(PostTaskPayload {
            submitter,
            auth,
            task_id,
            payment_sat,
            nonce,
            deadline_height,
            compute_task,
        })
    }
}

// ---------------------------------------------------------------------------
// ClaimTask
// ---------------------------------------------------------------------------

/// Reserves an open task for `worker` and locks `worker_deposit_sat`, which is
/// burned or slashed if the worker never delivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTaskPayload {
    pub worker: Address,
    pub auth: Auth,
    pub task_id: Hash,
    pub backend: ComputeBackend,
    pub worker_deposit_sat: u64,
}

impl ClaimTaskPayload {
    pub fn build(
        wallet: &Wallet,
        task_id: Hash,
        backend: ComputeBackend,
        worker_deposit_sat: u64,
    ) -> Result<Self> {
        let mut p = ClaimTaskPayload {
            worker: wallet.address()?,
            auth: Auth::default(),
            task_id,
            backend,
            worker_deposit_sat,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_CLAIM, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.worker, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.worker);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .u8(self.backend.to_wire())
            .u64le(self.worker_deposit_sat);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let worker: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let backend = ComputeBackend::from_wire(r.u8()?);
        let worker_deposit_sat = r.u64le()?;
        Ok(ClaimTaskPayload {
            worker,
            auth,
            task_id,
            backend,
            worker_deposit_sat,
        })
    }
}

// ---------------------------------------------------------------------------
// SubmitResult
// ---------------------------------------------------------------------------

/// Publishes the worker's result hash and M3 attestation, opening the dispute
/// window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitResultPayload {
    pub worker: Address,
    pub auth: Auth,
    pub task_id: Hash,
    pub result_hash: Hash,
    pub attestation: ComputeAttestation,
}

impl SubmitResultPayload {
    pub fn build(wallet: &Wallet, task_id: Hash, attestation: ComputeAttestation) -> Result<Self> {
        let mut p = SubmitResultPayload {
            worker: wallet.address()?,
            auth: Auth::default(),
            task_id,
            result_hash: attestation.result_hash,
            attestation,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_SUBMIT, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.worker, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.worker);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .fixed(&self.result_hash)
            .raw(&self.attestation.serialize());
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let worker: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let result_hash = r.fixed()?;
        let attestation = ComputeAttestation::from_reader(r)?;
        Ok(SubmitResultPayload {
            worker,
            auth,
            task_id,
            result_hash,
            attestation,
        })
    }
}

// ---------------------------------------------------------------------------
// Dispute
// ---------------------------------------------------------------------------

/// Challenges a submitted result. `challenger` locks a deposit that is burned if
/// the challenge fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputePayload {
    pub challenger: Address,
    pub auth: Auth,
    pub task_id: Hash,
    pub counter_result: Hash,
    pub counter_attestation: ComputeAttestation,
    pub challenge_deposit_sat: u64,
}

impl DisputePayload {
    pub fn build(
        wallet: &Wallet,
        task_id: Hash,
        counter_result: Hash,
        counter_attestation: ComputeAttestation,
        challenge_deposit_sat: u64,
    ) -> Result<Self> {
        let mut p = DisputePayload {
            challenger: wallet.address()?,
            auth: Auth::default(),
            task_id,
            counter_result,
            counter_attestation,
            challenge_deposit_sat,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_DISPUTE, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.challenger, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.challenger);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .fixed(&self.counter_result)
            .raw(&self.counter_attestation.serialize())
            .u64le(self.challenge_deposit_sat);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let challenger: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let counter_result = r.fixed()?;
        let counter_attestation = ComputeAttestation::from_reader(r)?;
        let challenge_deposit_sat = r.u64le()?;
        Ok(DisputePayload {
            challenger,
            auth,
            task_id,
            counter_result,
            counter_attestation,
            challenge_deposit_sat,
        })
    }
}

// ---------------------------------------------------------------------------
// Settle
// ---------------------------------------------------------------------------

/// Longest `network_id` a settle payload may name, matching the arbitration
/// vote bound so the two encodings agree on what fits.
pub const MAX_SETTLE_NETWORK_ID_BYTES: usize = 64;

/// The validator quorum's settlement decision. Not user-facing: it is produced
/// by the arbitrator set (the M5 committee) and authorized by its BLS aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlePayload {
    pub task_id: Hash,
    pub verdict: Verdict,
    /// The hash the verdict settles on — see [`VWC_HASH_EXPIRED`] for the
    /// pre-VWC convention.
    pub vwc_hash: Hash,
    /// Chain the quorum signed for. Part of the signed message, and `apply`
    /// refuses a payload naming another network: without this, a quorum's
    /// aggregate over the decision alone would verify on any chain whose
    /// committee overlaps.
    pub network_id: String,
    /// Height the quorum signed at. Part of the signed message; `apply`
    /// refuses a vote from the future (`height` above the applying height).
    /// A quorum formed at `H` may still settle at `H+1` — votes are signed as
    /// the chain moves — so the rule is "not from the future", with the
    /// dispute lifecycle (a task settles once) closing the replay window.
    pub height: u64,
    /// BLS12-381 G2 aggregate signature over [`SettlePayload::signing_hash`].
    pub bls_sig: [u8; 96],
    /// One bit per validator (LSB = index 0) in the epoch's sorted set.
    pub signer_bitmap: Vec<u8>,
    /// Number of validators that signed. Must agree with the bitmap.
    pub signer_count: u32,
    /// Lattice sidecar: one ML-DSA-65 signature per bitmap signer that voted
    /// with a lattice signature, over the same signing hash the aggregate
    /// covers. Collected, not verified, at tally time — the tally is not a
    /// trust boundary (consensus re-verifies at apply) — and verified at
    /// `apply_settle` against the epoch set's registered keys, exactly like
    /// checkpoint clause 7. Empty while no voter carries a lattice signature.
    pub pq_sidecar: Vec<crate::bls_checkpoint::PqSidecarEntry>,
}

impl SettlePayload {
    pub fn signing_hash(&self) -> Hash {
        // Covers the decision plus the chain it was signed for: not the
        // signature, not the bitmap, not the count. Those are evidence *of*
        // the decision.
        let mut w = Writer::new();
        w.fixed(&self.task_id)
            .u8(self.verdict.to_wire())
            .fixed(&self.vwc_hash)
            .u32le(self.network_id.len() as u32)
            .raw(self.network_id.as_bytes())
            .u64le(self.height);
        sha256_dom(DOM_L2_SETTLE, &[w.as_slice()])
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.task_id)
            .u8(self.verdict.to_wire())
            .fixed(&self.vwc_hash)
            .u32le(self.network_id.len() as u32)
            .raw(self.network_id.as_bytes())
            .u64le(self.height)
            .raw(&self.bls_sig);
        w.u32le(self.signer_bitmap.len() as u32)
            .raw(&self.signer_bitmap)
            .u32le(self.signer_count);
        // The sidecar rides last, length-prefixed like every repeated field.
        w.u32le(self.pq_sidecar.len() as u32);
        for e in &self.pq_sidecar {
            w.u32le(e.signer_index).raw(&e.signature);
        }
        w.into_vec()
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let task_id = r.fixed()?;
        let verdict = Verdict::from_wire(r.u8()?)?;
        let vwc_hash = r.fixed()?;
        // Required, not tolerant: a payload written before network/height
        // binding carries a signature over the decision alone, which must no
        // longer verify. Old bytes fail here rather than decode.
        let id_len = r.u32le()? as usize;
        if id_len > MAX_SETTLE_NETWORK_ID_BYTES {
            return Err(Error::Malformed("settle network_id over cap"));
        }
        if id_len > r.remaining() {
            return Err(Error::Malformed("settle network_id exceeds buffer"));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(id_len)?)
            .map_err(|_| Error::Malformed("settle network_id not utf-8"))?
            .to_string();
        let height = r.u64le()?;
        let bls_sig: [u8; 96] = r.fixed()?;
        let n = r.u32le()? as usize;
        if n > MAX_SIGNER_BITMAP_BYTES {
            return Err(Error::Malformed("signer bitmap over cap"));
        }
        if n > r.remaining() {
            return Err(Error::Malformed("signer bitmap exceeds buffer"));
        }
        let signer_bitmap = r.fixed_slice(n)?.to_vec();
        let signer_count = r.u32le()?;
        // Tolerant: payloads written before the sidecar end here and decode
        // to an empty one. Stripping is not a downgrade: apply refuses a
        // keyed signer with no entry.
        let mut pq_sidecar = Vec::new();
        if r.remaining() > 0 {
            let m = r.u32le()? as usize;
            if m > crate::bls_checkpoint::MAX_PQ_SIDECAR_ENTRIES {
                return Err(Error::Malformed("settle pq sidecar too large"));
            }
            pq_sidecar.reserve(m.min(8));
            for _ in 0..m {
                let signer_index = r.u32le()?;
                let signature: [u8; crate::bls_checkpoint::PQ_SIDECAR_SIGNATURE_BYTES] =
                    r.fixed()?;
                pq_sidecar.push(crate::bls_checkpoint::PqSidecarEntry {
                    signer_index,
                    signature,
                });
            }
        }
        Ok(SettlePayload {
            task_id,
            verdict,
            vwc_hash,
            network_id,
            height,
            bls_sig,
            signer_bitmap,
            signer_count,
            pq_sidecar,
        })
    }
}

// ---------------------------------------------------------------------------
// ExitQueue
// ---------------------------------------------------------------------------

/// Smallest `exit_fee_sat` an exit may carry (SPEC.md exit rules).
///
/// A zero-fee exit still gets confirmed — it debits the owner and encumbers
/// the value — but nobody is paid to file the L1 release, so it would never
/// be claimed. The floor makes "the fee is zero" a refusal at queue time
/// rather than an exit that stalls for free.
pub const MIN_EXIT_FEE_SAT: u64 = 1_000;

/// Queues an L2 → L1 exit (approved P1, E-1…E-3): debits `amount_sat` plus the
/// prepaid L1 release fee (`exit_fee_sat`) from the owner's L2 account and
/// records the pending exit the release rule later pays out.
///
/// The fee is what pays whoever later files the L1 release claim — an exit
/// queued with no fee earns its cranker nothing, so it would sit unclaimed
/// forever. [`MIN_EXIT_FEE_SAT`] is the enforced floor (SPEC.md exit rules).
///
/// The nonce is strictly increasing per owner (replay protection, mirroring
/// the agent authorization discipline); the destination is bound by the
/// owner's own signature, so no third party can redirect the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitQueuePayload {
    pub owner: Address,
    pub auth: Auth,
    pub nonce: u64,
    pub amount_sat: u64,
    pub destination: Address,
    pub exit_fee_sat: u64,
}

impl ExitQueuePayload {
    pub fn build(
        wallet: &Wallet,
        nonce: u64,
        amount_sat: u64,
        destination: Address,
        exit_fee_sat: u64,
    ) -> Result<Self> {
        let mut p = ExitQueuePayload {
            owner: wallet.address()?,
            auth: Auth::default(),
            nonce,
            amount_sat,
            destination,
            exit_fee_sat,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_EXIT_QUEUE, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.owner, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.owner);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.u64le(self.nonce)
            .u64le(self.amount_sat)
            .fixed(&self.destination)
            .u64le(self.exit_fee_sat);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let owner: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let nonce = r.u64le()?;
        let amount_sat = r.u64le()?;
        let destination: Address = r.fixed()?;
        let exit_fee_sat = r.u64le()?;
        Ok(ExitQueuePayload {
            owner,
            auth,
            nonce,
            amount_sat,
            destination,
            exit_fee_sat,
        })
    }
}

// ---------------------------------------------------------------------------
// Policy publication, revocation and spend (SPEC.md §21)
// ---------------------------------------------------------------------------

/// Publish a spending policy on chain (SPEC.md §21.1).
///
/// The owner signs once here, and the signature covers three things at once:
/// the grant bytes themselves, the **spender** — the address whose signature
/// will exercise the grant — and the **agent identity** the grant names. That
/// binding is the point. A policy hash on its own is a capability, and a
/// capability that anyone can exercise is worthless; here the owner's
/// signature says *this* key may spend under *these* caps, and the chain
/// remembers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPayload {
    pub owner: Address,
    pub auth: Auth,
    /// The canonical `SpendPolicy` bytes the owner signs.
    pub policy: Vec<u8>,
    /// The address whose signature may exercise the grant.
    pub spender: Address,
    /// The agent identity this grant names.
    pub agent_id: AgentId,
}

impl PolicyPayload {
    /// Build and sign a publication from raw grant bytes.
    pub fn build(
        wallet: &Wallet,
        policy: Vec<u8>,
        spender: Address,
        agent_id: AgentId,
    ) -> Result<Self> {
        if policy.len() > MAX_POLICY_BYTES {
            return Err(Error::Malformed("policy grant over the size cap"));
        }
        let mut p = PolicyPayload {
            owner: wallet.address()?,
            auth: Auth::default(),
            policy,
            spender,
            agent_id,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    /// Build and sign a publication from a decoded policy.
    pub fn build_from_policy(
        wallet: &Wallet,
        policy: &crate::agent::SpendPolicy,
        spender: Address,
    ) -> Result<Self> {
        Self::build(wallet, policy.serialize(), spender, policy.agent_id)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_POLICY, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.owner, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.owner);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.u32le(self.policy.len() as u32)
            .raw(&self.policy)
            .fixed(&self.spender)
            .fixed(&self.agent_id);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let owner: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let len = r.u32le()? as usize;
        if len > MAX_POLICY_BYTES {
            return Err(Error::Malformed("policy grant over the size cap"));
        }
        if len > r.remaining() {
            return Err(Error::Malformed("policy grant longer than the input"));
        }
        let policy = r.fixed_slice(len)?.to_vec();
        let spender: Address = r.fixed()?;
        let agent_id: AgentId = r.fixed()?;
        Ok(PolicyPayload {
            owner,
            auth,
            policy,
            spender,
            agent_id,
        })
    }
}

/// Revoke a published policy (SPEC.md §21.2).
///
/// The owner's kill switch, on chain. A revoked policy authorises nothing, and
/// so does any policy delegated from it: the chain walks the ancestry at spend
/// time, so revocation reaches every descendant without a separate
/// revocation transaction per link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRevokePayload {
    pub owner: Address,
    pub auth: Auth,
    /// The agent whose grant is being killed.
    pub agent_id: AgentId,
}

impl PolicyRevokePayload {
    pub fn build(wallet: &Wallet, agent_id: AgentId) -> Result<Self> {
        let mut p = PolicyRevokePayload {
            owner: wallet.address()?,
            auth: Auth::default(),
            agent_id,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_POLICY_REVOKE, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.owner, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.owner);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.agent_id);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let owner: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let agent_id: AgentId = r.fixed()?;
        Ok(PolicyRevokePayload {
            owner,
            auth,
            agent_id,
        })
    }
}

/// Spend under a published policy (SPEC.md §21.3).
///
/// Signed by the **spender** the grant names, not by the owner: the owner
/// signed once, at publication, and every later spend is authorised by the
/// policy itself. The chain checks the grant's own rules — per-transaction cap,
/// per-window cap, recipient allow-list, service allow-list, validity window,
/// strictly increasing nonce — and enforces them against state it keeps, so
/// the limits are rules rather than advice.
/// Guardian co-signature for a guarded-account spend above the human-approval
/// tier (Phase 3). The guardian signs the same body message as the agent, so
/// both signatures commit to identical terms. Carried only when present;
/// old blobs without the trailing section decode as `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianCoSign {
    pub guardian: Address,
    pub auth: Auth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpendPayload {
    /// The spender's address: the actor whose signature authorises this spend.
    pub agent: Address,
    pub auth: Auth,
    /// The published grant this spend is made under.
    pub policy_hash: Hash,
    /// Strictly increasing per policy: the anti-replay counter.
    pub nonce: u64,
    /// Who is paid.
    pub recipient: Address,
    /// How much is paid.
    pub amount_sat: u64,
    /// The service tag, when the grant restricts spending to named services.
    pub service: Option<[u8; 32]>,
    /// Guardian co-signature for guarded accounts above the approval tier.
    /// `None` for ordinary spends and all pre-upgrade blobs.
    pub guardian_approval: Option<GuardianCoSign>,
}

impl AgentSpendPayload {
    pub fn build(
        wallet: &Wallet,
        policy_hash: Hash,
        nonce: u64,
        recipient: Address,
        amount_sat: u64,
        service: Option<[u8; 32]>,
    ) -> Result<Self> {
        let mut p = AgentSpendPayload {
            agent: wallet.address()?,
            auth: Auth::default(),
            policy_hash,
            nonce,
            recipient,
            amount_sat,
            service,
            guardian_approval: None,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    /// Build a spend with a guardian co-signature (Phase 3 guarded accounts
    /// above the human-approval tier). The agent builds and signs first with
    /// the guardian's public bundle present in the body; the guardian then
    /// countersigns the identical body message via [`Self::co_sign`].
    #[allow(clippy::too_many_arguments)]
    pub fn build_with_guardian(
        wallet: &Wallet,
        guardian_keys: crate::sig::Bundle,
        policy_hash: Hash,
        nonce: u64,
        recipient: Address,
        amount_sat: u64,
        service: Option<[u8; 32]>,
        guardian: Address,
    ) -> Result<Self> {
        use crate::sig::Bundle;
        let guardian_auth = Auth {
            keys: guardian_keys,
            sigs: Bundle { components: vec![] },
        };
        let mut p = AgentSpendPayload {
            agent: wallet.address()?,
            auth: Auth::default(),
            policy_hash,
            nonce,
            recipient,
            amount_sat,
            service,
            guardian_approval: Some(GuardianCoSign {
                guardian,
                auth: guardian_auth,
            }),
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    /// Guardian countersignature over the identical body message. Call after
    /// the agent has signed; both signatures commit to the same terms.
    pub fn co_sign(&mut self, guardian_wallet: &Wallet) -> Result<()> {
        let guardian = guardian_wallet.address()?;
        // Compute the message first: it borrows `self` immutably, which would
        // conflict with the mutable slot borrow below.
        let msg = self.signing_hash();
        let slot = self
            .guardian_approval
            .as_mut()
            .ok_or(Error::Malformed("no guardian approval slot to co-sign"))?;
        if slot.guardian != guardian {
            return Err(Error::WrongAddress);
        }
        slot.auth.sigs = Auth::sigs_for(guardian_wallet, &msg)?;
        Ok(())
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_AGENT_SPEND, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.agent, &self.signing_hash())?;
        if let Some(co) = &self.guardian_approval {
            co.auth.verify_as(&co.guardian, &self.signing_hash())?;
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.agent);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.policy_hash)
            .u64le(self.nonce)
            .fixed(&self.recipient)
            .u64le(self.amount_sat);
        match &self.service {
            Some(tag) => {
                w.u8(1).fixed(tag);
            }
            None => {
                w.u8(0);
            }
        }
        // Guardian co-signature section (Phase 3). Omitted entirely when
        // absent, so pre-upgrade spends keep their exact bytes and txids.
        if let Some(co) = &self.guardian_approval {
            w.u8(1).fixed(&co.guardian);
            if with_sigs {
                co.auth.write_full(w);
            } else {
                co.auth.write_body(w);
            }
        }
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let agent: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let policy_hash: Hash = r.fixed()?;
        let nonce = r.u64le()?;
        let recipient: Address = r.fixed()?;
        let amount_sat = r.u64le()?;
        let service = match r.u8()? {
            0 => None,
            1 => Some(r.fixed::<32>()?),
            _ => return Err(Error::Malformed("service tag out of range")),
        };
        // Trailing guardian section: absent on pre-upgrade blobs.
        let guardian_approval = if r.remaining() == 0 {
            None
        } else {
            match r.u8()? {
                0 => None,
                1 => {
                    let guardian: Address = r.fixed()?;
                    let gauth = Auth::read(r)?;
                    Some(GuardianCoSign {
                        guardian,
                        auth: gauth,
                    })
                }
                _ => return Err(Error::Malformed("guardian flag out of range")),
            }
        };
        Ok(AgentSpendPayload {
            agent,
            auth,
            policy_hash,
            nonce,
            recipient,
            amount_sat,
            service,
            guardian_approval,
        })
    }
}

// ---------------------------------------------------------------------------
// Credit positions (SPEC.md §22)
// ---------------------------------------------------------------------------

/// Open a credit position (SPEC.md §22.3).
///
/// The **lender** signs this one, and that signature is the whole difference
/// between a loan and a claim: without it, anybody could name a lender and
/// record a debt against them. The signature covers every term — the
/// borrower, the amount, the collateral, the rate, the window and the deadline
/// — so a lender cannot be shown terms they did not agree to.
///
/// The principal moves to the borrower when the position opens, and the
/// borrower's collateral is locked for the life of the position. That is what
/// makes this a loan rather than an accounting entry: the value is on chain,
/// visible to every node, and the debt is settled by value moving back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditOpenPayload {
    pub lender: Address,
    pub auth: Auth,
    /// Who the loan is for.
    pub borrower: Address,
    /// The principal lent, in satoshis.
    pub amount_sat: u64,
    /// The collateral the borrower locks against the principal.
    pub collateral_sat: u64,
    /// Interest per window, in basis points of the outstanding principal.
    pub rate_bps_per_window: u32,
    /// Length of a window, in blocks.
    pub window_blocks: u64,
    /// The height the debt is due by.
    pub deadline_height: u64,
    /// Per-lender sequence number, so two identical loans are two positions.
    pub nonce: u64,
}

impl CreditOpenPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        wallet: &Wallet,
        borrower: Address,
        amount_sat: u64,
        collateral_sat: u64,
        rate_bps_per_window: u32,
        window_blocks: u64,
        deadline_height: u64,
        nonce: u64,
    ) -> Result<Self> {
        let mut p = CreditOpenPayload {
            lender: wallet.address()?,
            auth: Auth::default(),
            borrower,
            amount_sat,
            collateral_sat,
            rate_bps_per_window,
            window_blocks,
            deadline_height,
            nonce,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    /// The position id: a hash over every term, so two positions that differ
    /// in any term are different positions and one set of terms is one
    /// position.
    pub fn derived_position_id(&self) -> Hash {
        let mut w = Writer::new();
        w.fixed(&self.lender)
            .fixed(&self.borrower)
            .u64le(self.amount_sat)
            .u64le(self.collateral_sat)
            .u32le(self.rate_bps_per_window)
            .u64le(self.window_blocks)
            .u64le(self.deadline_height)
            .u64le(self.nonce);
        sha256_dom(DOM_L2_CREDIT_POSITION, &[w.as_slice()])
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_CREDIT_OPEN, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.lender, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.lender);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.borrower)
            .u64le(self.amount_sat)
            .u64le(self.collateral_sat)
            .u32le(self.rate_bps_per_window)
            .u64le(self.window_blocks)
            .u64le(self.deadline_height)
            .u64le(self.nonce);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let lender: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let borrower: Address = r.fixed()?;
        let amount_sat = r.u64le()?;
        let collateral_sat = r.u64le()?;
        let rate_bps_per_window = r.u32le()?;
        let window_blocks = r.u64le()?;
        let deadline_height = r.u64le()?;
        let nonce = r.u64le()?;
        Ok(CreditOpenPayload {
            lender,
            auth,
            borrower,
            amount_sat,
            collateral_sat,
            rate_bps_per_window,
            window_blocks,
            deadline_height,
            nonce,
        })
    }
}

/// Open a credit position with borrower consent (Phase 2 fix).
/// Identical terms to CreditOpen plus a borrower signature over the exact
/// same terms. Both lender and borrower must sign; the position id covers
/// both signatures' messages (same terms hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditOpenV2Payload {
    pub lender: Address,
    pub lender_auth: Auth,
    pub borrower: Address,
    pub borrower_auth: Auth,
    pub amount_sat: u64,
    pub collateral_sat: u64,
    pub rate_bps_per_window: u32,
    pub window_blocks: u64,
    pub deadline_height: u64,
    pub nonce: u64,
}

impl CreditOpenV2Payload {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        lender: &Wallet,
        borrower: &Wallet,
        amount_sat: u64,
        collateral_sat: u64,
        rate_bps_per_window: u32,
        window_blocks: u64,
        deadline_height: u64,
        nonce: u64,
    ) -> Result<Self> {
        let borrower_addr = borrower.address()?;
        let mut p = CreditOpenV2Payload {
            lender: lender.address()?,
            lender_auth: Auth::default(),
            borrower: borrower_addr,
            borrower_auth: Auth::default(),
            amount_sat,
            collateral_sat,
            rate_bps_per_window,
            window_blocks,
            deadline_height,
            nonce,
        };
        // Both parties sign the identical terms body.
        p.lender_auth.keys = Auth::keys_for(lender)?;
        p.borrower_auth.keys = Auth::keys_for(borrower)?;
        let msg = p.signing_hash();
        p.lender_auth.sigs = Auth::sigs_for(lender, &msg)?;
        p.borrower_auth.sigs = Auth::sigs_for(borrower, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_CREDIT_OPEN, &[&self.body()])
    }
    pub fn verify_auth(&self) -> Result<()> {
        let msg = self.signing_hash();
        self.lender_auth.verify_as(&self.lender, &msg)?;
        self.borrower_auth.verify_as(&self.borrower, &msg)?;
        Ok(())
    }
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }
    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.lender);
        if with_sigs {
            self.lender_auth.write_full(w);
        } else {
            self.lender_auth.write_body(w);
        }
        w.fixed(&self.borrower);
        if with_sigs {
            self.borrower_auth.write_full(w);
        } else {
            self.borrower_auth.write_body(w);
        }
        w.u64le(self.amount_sat)
            .u64le(self.collateral_sat)
            .u32le(self.rate_bps_per_window)
            .u64le(self.window_blocks)
            .u64le(self.deadline_height)
            .u64le(self.nonce);
    }
    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let lender: Address = r.fixed()?;
        let lender_auth = Auth::read(r)?;
        let borrower: Address = r.fixed()?;
        let borrower_auth = Auth::read(r)?;
        let amount_sat = r.u64le()?;
        let collateral_sat = r.u64le()?;
        let rate_bps_per_window = r.u32le()?;
        let window_blocks = r.u64le()?;
        let deadline_height = r.u64le()?;
        let nonce = r.u64le()?;
        Ok(CreditOpenV2Payload {
            lender,
            lender_auth,
            borrower,
            borrower_auth,
            amount_sat,
            collateral_sat,
            rate_bps_per_window,
            window_blocks,
            deadline_height,
            nonce,
        })
    }
    pub fn derived_position_id(&self) -> Hash {
        let mut w = Writer::new();
        w.fixed(&self.lender)
            .fixed(&self.borrower)
            .u64le(self.amount_sat)
            .u64le(self.collateral_sat)
            .u32le(self.rate_bps_per_window)
            .u64le(self.window_blocks)
            .u64le(self.deadline_height)
            .u64le(self.nonce);
        sha256_dom(DOM_L2_CREDIT_POSITION, &[w.as_slice()])
    }
}

/// Add collateral to a credit position (SPEC.md §22.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditCollateralPayload {
    pub borrower: Address,
    pub auth: Auth,
    pub position_id: Hash,
    pub amount_sat: u64,
}

impl CreditCollateralPayload {
    pub fn build(wallet: &Wallet, position_id: Hash, amount_sat: u64) -> Result<Self> {
        let mut p = CreditCollateralPayload {
            borrower: wallet.address()?,
            auth: Auth::default(),
            position_id,
            amount_sat,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_CREDIT_COLLATERAL, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.borrower, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.borrower);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.position_id).u64le(self.amount_sat);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let borrower: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let position_id: Hash = r.fixed()?;
        let amount_sat = r.u64le()?;
        Ok(CreditCollateralPayload {
            borrower,
            auth,
            position_id,
            amount_sat,
        })
    }
}

/// Repay a credit position (SPEC.md §22.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditRepayPayload {
    pub borrower: Address,
    pub auth: Auth,
    pub position_id: Hash,
    pub amount_sat: u64,
}

impl CreditRepayPayload {
    pub fn build(wallet: &Wallet, position_id: Hash, amount_sat: u64) -> Result<Self> {
        let mut p = CreditRepayPayload {
            borrower: wallet.address()?,
            auth: Auth::default(),
            position_id,
            amount_sat,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_CREDIT_REPAY, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.borrower, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.borrower);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.position_id).u64le(self.amount_sat);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let borrower: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let position_id: Hash = r.fixed()?;
        let amount_sat = r.u64le()?;
        Ok(CreditRepayPayload {
            borrower,
            auth,
            position_id,
            amount_sat,
        })
    }
}

/// Settle a credit position that was not repaid (SPEC.md §22.6).
///
/// Permissionless: anyone may trigger the settlement of an overdue position,
/// because a default that only the lender can trigger is a default that can be
/// delayed. The actor pays the fee; the collateral answers for the debt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditDefaultPayload {
    pub actor: Address,
    pub auth: Auth,
    pub position_id: Hash,
}

impl CreditDefaultPayload {
    pub fn build(wallet: &Wallet, position_id: Hash) -> Result<Self> {
        let mut p = CreditDefaultPayload {
            actor: wallet.address()?,
            auth: Auth::default(),
            position_id,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_CREDIT_DEFAULT, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.actor, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.actor);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.position_id);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let actor: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let position_id: Hash = r.fixed()?;
        Ok(CreditDefaultPayload {
            actor,
            auth,
            position_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Phase 3: guarded accounts and audit anchors
// ---------------------------------------------------------------------------

/// Opt an L2 account into guarded mode (Phase 3).
///
/// Creates the guarded-account record (leaf tag 0x07, state wire 8).
/// Per-account opt-in only, never global. The owner signs; the guardian
/// named here must differ from the owner. The allow-list, delay, lifetime
/// and cap travel in the transaction so the record is fully determined by
/// consensus bytes. At most [`MAX_GUARDED_ALLOW_LIST`] entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedOptInPayload {
    pub owner: Address,
    pub auth: Auth,
    pub guardian: Address,
    pub allow_list: Vec<Address>,
    pub grant_delay_blocks: u64,
    pub max_grant_lifetime_blocks: u64,
    pub outflow_cap_bps: u64,
    pub outflow_window_blocks: u64,
    pub nonce: u64,
}

/// Maximum allow-list entries per guarded account (mirrors the recipient-list
/// discipline of [`MAX_POLICY_RECIPIENTS`]).
pub const MAX_GUARDED_ALLOW_LIST: usize = 64;

impl GuardedOptInPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        owner_wallet: &Wallet,
        guardian: Address,
        allow_list: Vec<Address>,
        grant_delay_blocks: u64,
        max_grant_lifetime_blocks: u64,
        outflow_cap_bps: u64,
        outflow_window_blocks: u64,
        nonce: u64,
    ) -> Result<Self> {
        if allow_list.len() > MAX_GUARDED_ALLOW_LIST {
            return Err(Error::Malformed("guarded allow-list too long"));
        }
        let mut p = GuardedOptInPayload {
            owner: owner_wallet.address()?,
            auth: Auth::default(),
            guardian,
            allow_list,
            grant_delay_blocks,
            max_grant_lifetime_blocks,
            outflow_cap_bps,
            outflow_window_blocks,
            nonce,
        };
        p.auth.keys = Auth::keys_for(owner_wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(owner_wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_GUARDED_OPTIN, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.owner, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.owner);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.guardian);
        w.u16le(self.allow_list.len() as u16);
        for a in &self.allow_list {
            w.fixed(a);
        }
        w.u64le(self.grant_delay_blocks)
            .u64le(self.max_grant_lifetime_blocks)
            .u64le(self.outflow_cap_bps)
            .u64le(self.outflow_window_blocks)
            .u64le(self.nonce);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let owner: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let guardian: Address = r.fixed()?;
        let n = r.u16le()? as usize;
        if n > MAX_GUARDED_ALLOW_LIST {
            return Err(Error::Malformed("guarded allow-list too long"));
        }
        let mut allow_list = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            allow_list.push(r.fixed()?);
        }
        Ok(GuardedOptInPayload {
            owner,
            auth,
            guardian,
            allow_list,
            grant_delay_blocks: r.u64le()?,
            max_grant_lifetime_blocks: r.u64le()?,
            outflow_cap_bps: r.u64le()?,
            outflow_window_blocks: r.u64le()?,
            nonce: r.u64le()?,
        })
    }
}

/// Guardian cancellation of a pending guarded exit or grant (Phase 3).
///
/// Valid only during the extra delay window, only for guarded accounts.
/// `kind` selects the target: 0 = queued exit (target's first 8 bytes are the
/// exit nonce, little-endian), 1 = published grant (target is the grant
/// hash). `nonce` is the guardian's replay counter for this guarded account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedCancelPayload {
    pub guardian: Address,
    pub auth: Auth,
    pub account: Address,
    pub kind: u8,
    pub target: Hash,
    pub nonce: u64,
}

impl GuardedCancelPayload {
    pub fn build(
        wallet: &Wallet,
        account: Address,
        kind: u8,
        target: Hash,
        nonce: u64,
    ) -> Result<Self> {
        if kind > 1 {
            return Err(Error::Malformed("guarded cancel names an unknown kind"));
        }
        let mut p = GuardedCancelPayload {
            guardian: wallet.address()?,
            auth: Auth::default(),
            account,
            kind,
            target,
            nonce,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_GUARDED_CANCEL, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.guardian, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.guardian);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.account)
            .u8(self.kind)
            .fixed(&self.target)
            .u64le(self.nonce);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let guardian: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let account: Address = r.fixed()?;
        let kind = r.u8()?;
        if kind > 1 {
            return Err(Error::Malformed("guarded cancel names an unknown kind"));
        }
        let target: Hash = r.fixed()?;
        let nonce = r.u64le()?;
        Ok(GuardedCancelPayload {
            guardian,
            auth,
            account,
            kind,
            target,
            nonce,
        })
    }
}

/// Guardian freeze of a guarded account (Phase 3). Halts outflows while frozen;
/// unfreezing restores them. Both directions require the guardian's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedFreezePayload {
    pub guardian: Address,
    pub auth: Auth,
    pub account: Address,
    pub frozen: bool,
    pub nonce: u64,
}

impl GuardedFreezePayload {
    pub fn build(wallet: &Wallet, account: Address, frozen: bool, nonce: u64) -> Result<Self> {
        let mut p = GuardedFreezePayload {
            guardian: wallet.address()?,
            auth: Auth::default(),
            account,
            frozen,
            nonce,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_GUARDED_FREEZE, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.guardian, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.guardian);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.account)
            .u8(u8::from(self.frozen))
            .u64le(self.nonce);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let guardian: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let account: Address = r.fixed()?;
        let frozen = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Malformed("guarded freeze flag out of range")),
        };
        let nonce = r.u64le()?;
        Ok(GuardedFreezePayload {
            guardian,
            auth,
            account,
            frozen,
            nonce,
        })
    }
}

/// Anchor an audit Merkle root on chain (Phase 3). Commits an off-chain audit
/// log root for verifiability. No dust-to-derived-address hack: the root rides
/// as an explicit field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAnchorPayload {
    pub anchorer: Address,
    pub auth: Auth,
    pub root: Hash,
    pub height: u64,
    pub nonce: u64,
}

impl AuditAnchorPayload {
    pub fn build(wallet: &Wallet, root: Hash, height: u64, nonce: u64) -> Result<Self> {
        let mut p = AuditAnchorPayload {
            anchorer: wallet.address()?,
            auth: Auth::default(),
            root,
            height,
            nonce,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_AUDIT_ANCHOR, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.anchorer, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.anchorer);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.root).u64le(self.height).u64le(self.nonce);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let anchorer: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let root: Hash = r.fixed()?;
        let height = r.u64le()?;
        let nonce = r.u64le()?;
        Ok(AuditAnchorPayload {
            anchorer,
            auth,
            root,
            height,
            nonce,
        })
    }
}

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Payload {
    Post(PostTaskPayload),
    Claim(ClaimTaskPayload),
    Submit(SubmitResultPayload),
    Dispute(DisputePayload),
    Settle(SettlePayload),
    ExitQueue(ExitQueuePayload),
    Policy(PolicyPayload),
    PolicyRevoke(PolicyRevokePayload),
    AgentSpend(AgentSpendPayload),
    CreditOpen(CreditOpenPayload),
    CreditCollateral(CreditCollateralPayload),
    CreditRepay(CreditRepayPayload),
    CreditDefault(CreditDefaultPayload),
    CreditOpenV2(CreditOpenV2Payload),
    GuardedOptIn(GuardedOptInPayload),
    GuardedCancel(GuardedCancelPayload),
    GuardedFreeze(GuardedFreezePayload),
    AuditAnchor(AuditAnchorPayload),
}

impl L2Payload {
    pub fn tx_type(&self) -> L2TxType {
        match self {
            L2Payload::Post(_) => L2TxType::PostTask,
            L2Payload::Claim(_) => L2TxType::ClaimTask,
            L2Payload::Submit(_) => L2TxType::SubmitResult,
            L2Payload::Dispute(_) => L2TxType::Dispute,
            L2Payload::Settle(_) => L2TxType::Settle,
            L2Payload::ExitQueue(_) => L2TxType::ExitQueue,
            L2Payload::Policy(_) => L2TxType::Policy,
            L2Payload::PolicyRevoke(_) => L2TxType::PolicyRevoke,
            L2Payload::AgentSpend(_) => L2TxType::AgentSpend,
            L2Payload::CreditOpen(_) => L2TxType::CreditOpen,
            L2Payload::CreditCollateral(_) => L2TxType::CreditCollateral,
            L2Payload::CreditRepay(_) => L2TxType::CreditRepay,
            L2Payload::CreditDefault(_) => L2TxType::CreditDefault,
            L2Payload::CreditOpenV2(_) => L2TxType::CreditOpenV2,
            L2Payload::GuardedOptIn(_) => L2TxType::GuardedOptIn,
            L2Payload::GuardedCancel(_) => L2TxType::GuardedCancel,
            L2Payload::GuardedFreeze(_) => L2TxType::GuardedFreeze,
            L2Payload::AuditAnchor(_) => L2TxType::AuditAnchor,
        }
    }

    /// The verified actor for an authorization payload, or `None` for `Settle`,
    /// whose authorization is the BLS quorum rather than a single key.
    pub fn actor(&self) -> Option<Address> {
        match self {
            L2Payload::Post(p) => Some(p.submitter),
            L2Payload::Claim(p) => Some(p.worker),
            L2Payload::Submit(p) => Some(p.worker),
            L2Payload::Dispute(p) => Some(p.challenger),
            L2Payload::Settle(_) => None,
            L2Payload::ExitQueue(p) => Some(p.owner),
            L2Payload::Policy(p) => Some(p.owner),
            L2Payload::PolicyRevoke(p) => Some(p.owner),
            L2Payload::AgentSpend(p) => Some(p.agent),
            L2Payload::CreditOpen(p) => Some(p.lender),
            L2Payload::CreditCollateral(p) => Some(p.borrower),
            L2Payload::CreditRepay(p) => Some(p.borrower),
            L2Payload::CreditDefault(p) => Some(p.actor),
            L2Payload::CreditOpenV2(p) => Some(p.lender),
            L2Payload::GuardedOptIn(p) => Some(p.owner),
            L2Payload::GuardedCancel(p) => Some(p.guardian),
            L2Payload::GuardedFreeze(p) => Some(p.guardian),
            L2Payload::AuditAnchor(p) => Some(p.anchorer),
        }
    }

    pub fn signing_hash(&self) -> Hash {
        match self {
            L2Payload::Post(p) => p.signing_hash(),
            L2Payload::Claim(p) => p.signing_hash(),
            L2Payload::Submit(p) => p.signing_hash(),
            L2Payload::Dispute(p) => p.signing_hash(),
            L2Payload::Settle(p) => p.signing_hash(),
            L2Payload::ExitQueue(p) => p.signing_hash(),
            L2Payload::Policy(p) => p.signing_hash(),
            L2Payload::PolicyRevoke(p) => p.signing_hash(),
            L2Payload::AgentSpend(p) => p.signing_hash(),
            L2Payload::CreditOpen(p) => p.signing_hash(),
            L2Payload::CreditCollateral(p) => p.signing_hash(),
            L2Payload::CreditRepay(p) => p.signing_hash(),
            L2Payload::CreditDefault(p) => p.signing_hash(),
            L2Payload::CreditOpenV2(p) => p.signing_hash(),
            L2Payload::GuardedOptIn(p) => p.signing_hash(),
            L2Payload::GuardedCancel(p) => p.signing_hash(),
            L2Payload::GuardedFreeze(p) => p.signing_hash(),
            L2Payload::AuditAnchor(p) => p.signing_hash(),
        }
    }

    /// Verify a single-actor authorization. `Settle` returns `Ok(())`: it carries
    /// no single signature, and its quorum check lives with the L2 state machine.
    pub fn verify_auth(&self) -> Result<()> {
        match self {
            L2Payload::Post(p) => p.verify_auth(),
            L2Payload::Claim(p) => p.verify_auth(),
            L2Payload::Submit(p) => p.verify_auth(),
            L2Payload::Dispute(p) => p.verify_auth(),
            L2Payload::Settle(_) => Ok(()),
            L2Payload::ExitQueue(p) => p.verify_auth(),
            L2Payload::Policy(p) => p.verify_auth(),
            L2Payload::PolicyRevoke(p) => p.verify_auth(),
            L2Payload::AgentSpend(p) => p.verify_auth(),
            L2Payload::CreditOpen(p) => p.verify_auth(),
            L2Payload::CreditCollateral(p) => p.verify_auth(),
            L2Payload::CreditRepay(p) => p.verify_auth(),
            L2Payload::CreditDefault(p) => p.verify_auth(),
            L2Payload::CreditOpenV2(p) => p.verify_auth(),
            L2Payload::GuardedOptIn(p) => p.verify_auth(),
            L2Payload::GuardedCancel(p) => p.verify_auth(),
            L2Payload::GuardedFreeze(p) => p.verify_auth(),
            L2Payload::AuditAnchor(p) => p.verify_auth(),
        }
    }

    fn serialize_payload(&self) -> Vec<u8> {
        match self {
            L2Payload::Post(p) => p.serialize(),
            L2Payload::Claim(p) => p.serialize(),
            L2Payload::Submit(p) => p.serialize(),
            L2Payload::Dispute(p) => p.serialize(),
            L2Payload::Settle(p) => p.serialize(),
            L2Payload::ExitQueue(p) => p.serialize(),
            L2Payload::Policy(p) => p.serialize(),
            L2Payload::PolicyRevoke(p) => p.serialize(),
            L2Payload::AgentSpend(p) => p.serialize(),
            L2Payload::CreditOpen(p) => p.serialize(),
            L2Payload::CreditCollateral(p) => p.serialize(),
            L2Payload::CreditRepay(p) => p.serialize(),
            L2Payload::CreditDefault(p) => p.serialize(),
            L2Payload::CreditOpenV2(p) => p.serialize(),
            L2Payload::GuardedOptIn(p) => p.serialize(),
            L2Payload::GuardedCancel(p) => p.serialize(),
            L2Payload::GuardedFreeze(p) => p.serialize(),
            L2Payload::AuditAnchor(p) => p.serialize(),
        }
    }

    fn from_reader(t: L2TxType, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match t {
            L2TxType::PostTask => L2Payload::Post(PostTaskPayload::from_reader(r)?),
            L2TxType::ClaimTask => L2Payload::Claim(ClaimTaskPayload::from_reader(r)?),
            L2TxType::SubmitResult => L2Payload::Submit(SubmitResultPayload::from_reader(r)?),
            L2TxType::Dispute => L2Payload::Dispute(DisputePayload::from_reader(r)?),
            L2TxType::Settle => L2Payload::Settle(SettlePayload::from_reader(r)?),
            L2TxType::ExitQueue => L2Payload::ExitQueue(ExitQueuePayload::from_reader(r)?),
            L2TxType::Policy => L2Payload::Policy(PolicyPayload::from_reader(r)?),
            L2TxType::PolicyRevoke => L2Payload::PolicyRevoke(PolicyRevokePayload::from_reader(r)?),
            L2TxType::AgentSpend => L2Payload::AgentSpend(AgentSpendPayload::from_reader(r)?),
            L2TxType::CreditOpen => L2Payload::CreditOpen(CreditOpenPayload::from_reader(r)?),
            L2TxType::CreditCollateral => {
                L2Payload::CreditCollateral(CreditCollateralPayload::from_reader(r)?)
            }
            L2TxType::CreditRepay => L2Payload::CreditRepay(CreditRepayPayload::from_reader(r)?),
            L2TxType::CreditDefault => {
                L2Payload::CreditDefault(CreditDefaultPayload::from_reader(r)?)
            }
            L2TxType::CreditOpenV2 => L2Payload::CreditOpenV2(CreditOpenV2Payload::from_reader(r)?),
            L2TxType::GuardedOptIn => L2Payload::GuardedOptIn(GuardedOptInPayload::from_reader(r)?),
            L2TxType::GuardedCancel => {
                L2Payload::GuardedCancel(GuardedCancelPayload::from_reader(r)?)
            }
            L2TxType::GuardedFreeze => {
                L2Payload::GuardedFreeze(GuardedFreezePayload::from_reader(r)?)
            }
            L2TxType::AuditAnchor => L2Payload::AuditAnchor(AuditAnchorPayload::from_reader(r)?),
        })
    }
}

/// A versioned envelope around an L2 payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Transaction {
    pub version: u32,
    pub payload: L2Payload,
}

impl L2Transaction {
    pub const VERSION: u32 = 1;

    pub fn new(payload: L2Payload) -> Self {
        L2Transaction {
            version: Self::VERSION,
            payload,
        }
    }

    pub fn tx_type(&self) -> L2TxType {
        self.payload.tx_type()
    }

    pub fn fee_sat(&self) -> u64 {
        self.tx_type().fee_sat()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + 1 + 64);
        w.u32le(self.version)
            .u8(self.tx_type().to_wire())
            .raw(&self.payload.serialize_payload());
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u32le()?;
        // The envelope is versioned for a reason: a future version may
        // reframe the bytes that follow, so decoding them as v1 would
        // misinterpret rather than merely accept.
        if version != Self::VERSION {
            return Err(Error::Malformed("unsupported L2 transaction version"));
        }
        let t = L2TxType::from_wire(r.u8()?)?;
        let payload = L2Payload::from_reader(t, &mut r)?;
        r.expect_end()?;
        Ok(L2Transaction { version, payload })
    }

    /// Unique transaction id, used for replay protection.
    pub fn txid(&self) -> Hash512 {
        sha512_dom(DOM_L2_TXID512, &[&self.serialize()])
    }
}

/// Serde identity of an L2 transaction is its **canonical binary encoding**
/// (Decision 6).
///
/// This exists so a whole `Block` can still be serialized, which the node's
/// chain export needs. Representing the JSON form as the binary bytes keeps a
/// single authority for what an L2 transaction is: the same encoding `txid`,
/// the signing hashes and the block-commitment path already use. A
/// field-by-field serde form would be a second encoding to keep in step with
/// the first — exactly the drift §15's canonical-encoding rule exists to
/// prevent. It also means an L2 payload stored in JSON is decoded through
/// `L2Transaction::deserialize`, so its bounds and validation apply there too.
impl serde::Serialize for L2Transaction {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.serialize()))
    }
}

impl<'de> serde::Deserialize<'de> for L2Transaction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        // Fully qualified: this module has its own `Result` alias and its own
        // `Error`, and both would otherwise shadow what serde's trait wants.
        let s = <String as serde::Deserialize>::deserialize(d)?;
        let bytes =
            hex::decode(&s).map_err(|e| <D::Error as serde::de::Error>::custom(e.to_string()))?;
        // Go through the canonical decoder, so a JSON-supplied L2 transaction
        // is held to exactly the rules a wire-supplied one is.
        L2Transaction::deserialize(&bytes).map_err(<D::Error as serde::de::Error>::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_private_key_bytes(&[seed; 32], "l2-test").unwrap()
    }

    fn task(submit_height: u64, expiry: u64) -> ComputeTask {
        ComputeTask {
            task_id: [0x11u8; 32],
            ir_hash: [0x22u8; 32],
            input_hash: [0x33u8; 32],
            required_memory_bytes: 4 * 1024 * 1024,
            backend_hint: ComputeBackend::Gpu,
            reward_sat: 1_000_000,
            expiry_height: expiry,
            submit_height,
        }
    }

    fn post(seed: u8, nonce: u64, deadline: u64) -> PostTaskPayload {
        PostTaskPayload::build(&wallet(seed), nonce, 5_000_000, deadline, task(1, deadline))
            .unwrap()
    }

    fn attest(w: &Wallet, task_id: Hash, result: Hash) -> ComputeAttestation {
        let mut a = ComputeAttestation {
            task_id,
            result_hash: result,
            backend: ComputeBackend::Gpu,
            worker_address: w.address().unwrap(),
            attest_height: 10,
            signature: vec![],
        };
        a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
        a
    }

    // --- wire codes -----------------------------------------------------

    #[test]
    fn type_codes_round_trip_and_are_distinct_from_l1() {
        for t in [
            L2TxType::PostTask,
            L2TxType::ClaimTask,
            L2TxType::SubmitResult,
            L2TxType::Dispute,
            L2TxType::Settle,
            L2TxType::ExitQueue,
        ] {
            assert_eq!(L2TxType::from_wire(t.to_wire()).unwrap(), t);
            assert!(t.to_wire() >= 0x10, "L2 codes must not collide with L1");
            assert!(!t.name().is_empty());
        }
        assert!(L2TxType::from_wire(0).is_err(), "L1 STANDARD is not L2");
        assert!(L2TxType::from_wire(0x99).is_err());
        assert!(Verdict::from_wire(3).is_err());
    }

    #[test]
    fn fee_mapping_is_the_decided_d3_schedule() {
        assert_eq!(L2TxType::PostTask.fee_sat(), 5_000);
        assert_eq!(L2TxType::ClaimTask.fee_sat(), 2_000);
        assert_eq!(L2TxType::SubmitResult.fee_sat(), 2_000);
        assert_eq!(L2TxType::Dispute.fee_sat(), 10_000);
        assert_eq!(L2TxType::Settle.fee_sat(), 1_000);
        assert_eq!(L2TxType::ExitQueue.fee_sat(), 2_000);
    }

    #[test]
    fn every_fee_meets_the_flat_minimum_floor() {
        // D3: flat minimum fee floor — no L2 fee may fall below
        // L2_FLAT_FEE_MINIMUM_SAT, even if a per-type constant were re-parameterized.
        for t in [
            L2TxType::PostTask,
            L2TxType::ClaimTask,
            L2TxType::SubmitResult,
            L2TxType::Dispute,
            L2TxType::Settle,
            L2TxType::ExitQueue,
        ] {
            assert!(
                t.fee_sat() >= L2_FLAT_FEE_MINIMUM_SAT,
                "{} fee {} below minimum {}",
                t.name(),
                t.fee_sat(),
                L2_FLAT_FEE_MINIMUM_SAT
            );
        }
    }

    #[test]
    fn settle_fee_is_proportional_with_an_anti_spam_floor() {
        // Decision 23: 0.1% of task value, minimum 1,000 sat.
        assert_eq!(settle_fee_sat(0), 1_000);
        assert_eq!(settle_fee_sat(999), 1_000);
        assert_eq!(settle_fee_sat(1_000), 1_000);
        assert_eq!(settle_fee_sat(1_000_000), 1_000);
        assert_eq!(settle_fee_sat(5_000_000), 5_000);
        assert_eq!(settle_fee_sat(100_000_000), 100_000);
        // No overflow at the top: division first, then the floor.
        assert_eq!(settle_fee_sat(u64::MAX), u64::MAX / 1000);
    }

    // --- task id --------------------------------------------------------

    #[test]
    fn task_id_binds_submitter_nonce_and_task() {
        let w = wallet(1);
        let t = task(1, 100);
        let submitter = w.address().unwrap();
        let a = derive_task_id(&submitter, 1, &t.task_hash());
        assert_eq!(a, derive_task_id(&submitter, 1, &t.task_hash()));
        assert_ne!(a, derive_task_id(&submitter, 2, &t.task_hash()));
        assert_ne!(
            a,
            derive_task_id(&wallet(2).address().unwrap(), 1, &t.task_hash())
        );
        let mut t2 = t.clone();
        t2.reward_sat += 1;
        assert_ne!(a, derive_task_id(&submitter, 1, &t2.task_hash()));
    }

    #[test]
    fn a_built_post_derives_and_signs_consistently() {
        let p = post(3, 7, 50);
        assert_eq!(p.task_id, p.derived_task_id());
        assert_eq!(p.submitter, wallet(3).address().unwrap());
        p.verify_auth().unwrap();
    }

    // --- signing hash coverage -----------------------------------------

    #[test]
    fn signing_hash_covers_every_consensus_field() {
        let base = post(4, 1, 100);
        let mut changed = base.clone();
        changed.payment_sat += 1;
        assert_ne!(base.signing_hash(), changed.signing_hash());

        let mut changed = base.clone();
        changed.deadline_height += 1;
        assert_ne!(base.signing_hash(), changed.signing_hash());

        let mut changed = base.clone();
        changed.submitter = [9u8; 20];
        assert_ne!(base.signing_hash(), changed.signing_hash());

        let mut changed = base.clone();
        changed.compute_task.reward_sat += 1;
        assert_ne!(base.signing_hash(), changed.signing_hash());
    }

    #[test]
    fn signing_hash_excludes_the_signature_but_includes_the_keys() {
        // Exactly the L1 sighash discipline: re-signing must not change the
        // message, but a swapped key bundle must.
        let base = post(5, 1, 100);
        let mut resigned = base.clone();
        resigned.auth.sigs = Auth::sign(&wallet(5), &base.signing_hash()).unwrap().sigs;
        assert_eq!(base.signing_hash(), resigned.signing_hash());

        let mut rekeyed = base.clone();
        rekeyed.auth.keys = Auth::sign(&wallet(6), &[0u8; 32]).unwrap().keys;
        assert_ne!(base.signing_hash(), rekeyed.signing_hash());
    }

    #[test]
    fn a_tampered_payload_fails_authorization() {
        let mut p = post(6, 1, 100);
        p.payment_sat += 1; // signature no longer matches
        assert!(p.verify_auth().is_err());

        // Signing as one wallet while claiming another actor's address is
        // rejected as a wrong-address case, not a signature failure.
        let w = wallet(7);
        let mut q = post(8, 1, 100);
        let msg = {
            q.submitter = w.address().unwrap();
            q.auth.keys = Auth::sign(&w, &[0u8; 32]).unwrap().keys;
            q.signing_hash()
        };
        q.auth.sigs = Auth::sign(&w, &msg).unwrap().sigs;
        assert!(q.verify_auth().is_ok());
        q.submitter = wallet(9).address().unwrap();
        assert!(matches!(q.verify_auth(), Err(Error::WrongAddress)));
    }

    // --- round trips ----------------------------------------------------

    #[test]
    fn every_payload_round_trips_and_ids_are_stable() {
        let w = wallet(10);
        let p = post(10, 1, 100);
        let t = p.task_id;
        let result = [0xAAu8; 32];
        let att = attest(&w, t, result);
        let payloads = vec![
            L2Payload::Post(p.clone()),
            L2Payload::Claim(ClaimTaskPayload::build(&w, t, ComputeBackend::Cpu, 1_000).unwrap()),
            L2Payload::Submit(SubmitResultPayload::build(&w, t, att.clone()).unwrap()),
            L2Payload::Dispute(
                DisputePayload::build(&w, t, [0xBBu8; 32], att.clone(), 2_000).unwrap(),
            ),
            L2Payload::Settle(SettlePayload {
                task_id: t,
                verdict: Verdict::Correct,
                vwc_hash: result,
                network_id: "srct/mini".to_string(),
                height: 9,
                bls_sig: [0x7Fu8; 96],
                signer_bitmap: vec![0b0000_0111],
                signer_count: 3,
                pq_sidecar: Vec::new(),
            }),
            L2Payload::ExitQueue(
                ExitQueuePayload::build(&w, 1, 50_000, [0xCCu8; 20], 1_000).unwrap(),
            ),
        ];
        for payload in payloads {
            let tx = L2Transaction::new(payload);
            let bytes = tx.serialize();
            let back = L2Transaction::deserialize(&bytes).unwrap();
            assert_eq!(back, tx, "{} did not round-trip", tx.tx_type().name());
            assert_eq!(back.txid(), tx.txid());
            assert_eq!(back.tx_type(), tx.tx_type());
            tx.payload.verify_auth().unwrap();
        }
    }

    #[test]
    fn deserialize_rejects_trailing_bytes_and_unknown_types() {
        let tx = L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&wallet(11), [1u8; 32], ComputeBackend::Npu, 1).unwrap(),
        ));
        let mut bytes = tx.serialize();
        bytes.push(0);
        assert!(matches!(
            L2Transaction::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));

        let mut bad = tx.serialize();
        bad[4] = 0x42; // overwrite the type byte
        assert!(L2Transaction::deserialize(&bad).is_err());
    }

    #[test]
    fn settle_hash_covers_the_verdict_task_network_and_height_not_the_evidence() {
        let base = SettlePayload {
            task_id: [1u8; 32],
            verdict: Verdict::Correct,
            vwc_hash: [2u8; 32],
            network_id: "srct/mini".to_string(),
            height: 7,
            bls_sig: [0u8; 96],
            signer_bitmap: vec![],
            signer_count: 0,
            pq_sidecar: Vec::new(),
        };
        let mut other_verdict = base.clone();
        other_verdict.verdict = Verdict::Fraudulent;
        assert_ne!(base.signing_hash(), other_verdict.signing_hash());

        let mut other_task = base.clone();
        other_task.task_id = [3u8; 32];
        assert_ne!(base.signing_hash(), other_task.signing_hash());

        let mut other_network = base.clone();
        other_network.network_id = "srct/other".to_string();
        assert_ne!(base.signing_hash(), other_network.signing_hash());

        let mut other_height = base.clone();
        other_height.height = 8;
        assert_ne!(base.signing_hash(), other_height.signing_hash());

        // Evidence fields are not part of the signed decision.
        let mut other_sig = base.clone();
        other_sig.bls_sig = [9u8; 96];
        other_sig.signer_bitmap = vec![0xFF];
        other_sig.signer_count = 8;
        assert_eq!(base.signing_hash(), other_sig.signing_hash());
    }

    #[test]
    fn a_settle_bitmap_prefix_is_bounded_before_allocating() {
        // Declares 1 GiB of bitmap with nothing behind it.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[1u8; 32]); // task_id
        bytes.push(0); // verdict
        bytes.extend_from_slice(&[0u8; 32]); // vwc_hash
        bytes.extend_from_slice(&[0u8; 96]); // bls sig
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // bitmap len
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            SettlePayload::from_reader(&mut r),
            Err(Error::Malformed(_))
        ));
    }
}
