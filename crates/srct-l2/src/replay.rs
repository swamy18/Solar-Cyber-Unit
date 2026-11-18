//! L2 state rebuilt from the canonical L1 chain — Decision 6, SPEC.md §19.1.
//!
//! # Why this lives here and not in `srct-core`
//!
//! L2 state is a pure function of the canonical chain: the L2 transactions are
//! carried in L1 blocks and committed by each block's merkle root, so every node
//! that replays the same blocks in the same order reaches the same state. That
//! function needs *both* crates — `Chain` to read blocks, `L2State` to apply
//! them — and the dependency direction is `srct-l2 → srct-core`. Putting the
//! replay here therefore adds no dependency edge and, more importantly, requires
//! no change to `Chain::submit`: L1 block validity is not made to depend on L2
//! rules, which is the property that keeps this integration from touching
//! consensus.
//!
//! # The one ordering rule
//!
//! For each height, the clock advances first (`L2State::advance_block`), then
//! the block's own L2 transactions are applied in block order, then the
//! block's detected deposits are processed in output order. That order is
//! fixed and stated once, because two nodes must agree on whether a transaction
//! that lands on the same height as an expiry sees the task open or expired.
//! Vesting and expiry happen *at* the height; the block's transactions then act
//! on the result. Deposits credit recipient accounts, never tasks, so their
//! position after the transactions is observable only in balances.
//!
//! Deposit maturity is evaluated against the *tip*, not the block: a deposit
//! detected at height `h` credits once `tip − h ≥ finality_depth`. Full replay
//! evaluates every deposit at the final tip; the incremental path evaluates new
//! blocks at the new tip and rebuilds by full replay when an old pending
//! deposit matures (`has_pending_matured`), so the two paths cannot disagree.
//!
//! # Binding finality (Decision 15, SPEC.md §19.4.1)
//!
//! Depth is the *minimum* safety, never the whole of it. Once the L1 chain has
//! a binding checkpoint (Decision 12), a deposit also requires that its own
//! block height lies at or below the binding-finalized height — so depth alone
//! cannot make a deposit spendable when the canonical history it sits in is not
//! yet finalized. Before binding finality activates (the finalized height is
//! 0), the M3 depth rule governs alone, unchanged: this gate can only make
//! deposits *safer* than M3, never less safe. The binding floor is read from
//! the L1 [`Chain`]'s own finality layer — L2 never grows a second finality
//! system; it consumes the one consensus answer.
//!
//! # What replay does with a transaction that does not apply
//!
//! It records it in [`ChainL2::skipped`] and carries on. This is deliberate and
//! documented in Decision 6: L2 validity is not an L1 block-validity rule, so a
//! miner *can* include an L2 transaction that fails — and every other node must
//! then reach the same conclusion about it, which it does, because `apply` is a
//! pure function of state and the rejection is deterministic. The transaction is
//! not marked applied, so it stays retryable, and nothing about it can corrupt
//! state. Recording the list rather than ignoring it is what makes that visible:
//! a node can report which payloads in a block it refused, and why.

use crate::deposits::{
    scan_block, DepositIgnoreReason, DepositParams, DetectedDeposit, IgnoredDeposit, PendingDeposit,
};
use crate::error::{L2Error, L2Result};
use crate::genesis::L2Genesis;
use crate::state::{ExitRecord, L2State};
use crate::task_contract::L2Config;
use srct_core::bls_checkpoint::{BlsVerifier, ValidatorSet};
use srct_core::chain::Chain;
use srct_core::hash::{Address, Hash512};
use srct_core::state_root::InclusionProof;

/// An L2 transaction that a canonical block carried but that did not apply.
///
/// Not an error in the chain — an error *about* a payload. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedL2 {
    /// Height of the block that carried it.
    pub height: u64,
    /// Canonical transaction id, so the payload can be named without holding it.
    pub txid: Hash512,
    /// The named reason it did not apply.
    pub error: L2Error,
}

/// A queued exit whose record has just been committed under a block's L2 state
/// root, with the inclusion proof that binds it to that root.
///
/// The proof is captured **at the block that queued the exit** and nowhere
/// else, because that is the only moment the node holds a state whose root
/// equals the block's committed `l2_state_root`. A crank therefore never has to
/// replay back to `queued_height` to build a claim — the expensive alternative
/// the exit design rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitWatch {
    pub owner: Address,
    pub nonce: u64,
    pub record: ExitRecord,
    pub proof: InclusionProof,
}

/// An L1 exit claim that this node's L2 state cannot account for.
///
/// L1 accepted and released the claim, so the value has already left L2 from
/// the chain's point of view. Reaching that state without a matching queued L2
/// record means this node's replayed L2 view disagrees with the chain it just
/// accepted — an integrity problem, not a payload problem. It is recorded rather
/// than swallowed so a release build reports it too: a `debug_assert` compiles
/// out exactly where a long-running node would be, which is the one place the
/// disagreement matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbackedClaim {
    /// Height of the block that carried the claim.
    pub height: u64,
    /// Owner named by the claim.
    pub owner: Address,
    /// Nonce named by the claim.
    pub nonce: u64,
    /// The named reason the local L2 state refused it.
    pub error: L2Error,
}

/// The L2 view of one canonical L1 chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainL2 {
    state: L2State,
    height: u64,
    applied: u64,
    skipped: Vec<SkippedL2>,
    deposits: DepositParams,
    /// Deposits detected but not yet final-deep: visible, not spendable
    /// (Decision 10 item 4). Re-derived on every replay, never persisted.
    pending: Vec<PendingDeposit>,
    /// Sink outputs that credited nothing, with the named reason.
    ignored: Vec<IgnoredDeposit>,
    /// Deposits credited (matured and applied).
    deposits_applied: u64,
    /// Queued exits still awaiting an L1 release, newest last. Re-derived on
    /// every replay; a release removes its entry, a reorg replays.
    watches: Vec<ExitWatch>,
    /// L1 exit claims this node's L2 state could not back. Empty in a healthy
    /// replay; non-empty means L1 and L2 disagree and the node is wrong.
    unbacked: Vec<UnbackedClaim>,
}

impl ChainL2 {
    /// A view with no history yet — the state a node starts from before it has
    /// applied anything, so it can follow the tip with [`Self::apply_block`].
    ///
    /// Genesis funding is applied here, before any block: L2 height 0 holds
    /// the allocation, and block 1 is the first that can spend it. Recovery
    /// (`replay`) builds through this same constructor, so "start empty, then
    /// apply each block" and full replay cannot disagree about funding.
    ///
    /// This is also the second half of the recovery story: `replay` and
    /// "start empty, then apply each block" must reach the same state, and a
    /// test asserts exactly that.
    ///
    /// Returns the genesis refusal instead of panicking on it: the caller
    /// that built this genesis (usually `L2Genesis::for_params` of a
    /// validated profile) names the failure, and a library constructor has
    /// no business aborting the process — with `panic = "abort"` that would
    /// take down every peer connection and request.
    pub fn empty(config: L2Config, genesis: &L2Genesis, deposits: DepositParams) -> L2Result<Self> {
        let mut state = L2State::new(config);
        state.apply_genesis(genesis)?;
        Ok(ChainL2 {
            state,
            height: 0,
            applied: 0,
            skipped: Vec::new(),
            deposits,
            pending: Vec::new(),
            ignored: Vec::new(),
            deposits_applied: 0,
            watches: Vec::new(),
            unbacked: Vec::new(),
        })
    }

    /// Replay a whole chain from genesis to its tip.
    ///
    /// This is the recovery path: nothing about `L2State` is persisted, so a
    /// restarting node rebuilds it from the blocks it already holds. It is also
    /// the reorg path — a fork choice that rewrites history is answered by
    /// replaying the chain that won, with no undo bookkeeping to get wrong.
    ///
    /// Settlement authority resolves per block height from the chain itself
    /// (`Chain::settlement_committee_at`, Decision 28): the bootstrap set
    /// before the first bond, the bonded TopN after. A fixed set passed once
    /// for the whole pass would verify pre-bond history against the
    /// post-bond committee after a rotation — replay must not depend on when
    /// it runs.
    pub fn replay(
        chain: &Chain,
        config: L2Config,
        genesis: &L2Genesis,
        deposits: DepositParams,
        verifier: &dyn BlsVerifier,
    ) -> L2Result<Self> {
        Self::replay_to(chain, config, genesis, deposits, verifier, chain.height())
    }

    /// Replay a whole chain from genesis to `upto` (inclusive), not to the tip.
    ///
    /// The miner crank needs the L2 state *as of the queue block* to build an
    /// exit proof against the root that block committed: the tip state has
    /// moved on since, and a proof is only valid against its own root. Same
    /// pass as [`Self::replay`], capped early.
    pub fn replay_to(
        chain: &Chain,
        config: L2Config,
        genesis: &L2Genesis,
        deposits: DepositParams,
        verifier: &dyn BlsVerifier,
        upto: u64,
    ) -> L2Result<Self> {
        let tip = chain.height().min(upto);
        // The one binding-finality floor for this replay: a pure read of the L1
        // chain's finality layer, fixed for the whole pass so every deposit is
        // judged against the same consensus answer (Decision 15).
        let binding = chain.finality().binding_finalized_height();
        let mut l2 = ChainL2::empty(config, genesis, deposits)?;
        for height in 1..=tip {
            // `block_at` is total over 1..=tip on a canonical chain: `canon`
            // indexes every canonical height and `Chain::prune_side_branches`
            // keeps every canonical block, so a miss means the chain is
            // internally inconsistent — a bug in `Chain`, not an input to route
            // around here. Rather than abort the process (which is every peer
            // connection and every request from then on, with `panic = "abort"`),
            // stop the replay at the first height that cannot be read: the node's
            // `apply_block` catch-up then resumes from the L2 tip and the chain
            // keeps moving. It cannot silently diverge, because the case is
            // unreachable — this only removes the abort mode if that changes.
            let Some(block) = chain.block_at(height) else {
                break;
            };
            // Authority as of the block, not the tip: after a rotation, the
            // committee at old heights is the old committee, on every replay.
            let validators = chain.settlement_committee_at(height);
            l2.absorb(height, block, tip, binding, &validators, verifier);
        }
        Ok(l2)
    }

    /// Apply one newly accepted block. The incremental twin of [`Self::replay`],
    /// used by a node that already holds state and is following the tip.
    ///
    /// `height` is taken from the block itself so the two paths cannot disagree
    /// about which height a transaction was applied at; `tip` is the chain tip
    /// *after* this block, which is what deposit depth-maturity is evaluated
    /// against (Decision 10 item 4). `binding_finalized` is the L1 binding-
    /// finalized height at call time (0 = not activated), the second of the two
    /// Decision 15 conditions — the caller reads it from the same `Chain` the
    /// tip came from, so the two inputs can never describe different views.
    pub fn apply_block(
        &mut self,
        block: &srct_core::block::Block,
        tip: u64,
        binding_finalized: u64,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) {
        self.absorb(
            block.header.height,
            block,
            tip,
            binding_finalized,
            validators,
            verifier,
        );
    }

    fn absorb(
        &mut self,
        height: u64,
        block: &srct_core::block::Block,
        tip: u64,
        binding: u64,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) {
        // The clock first, then the block's transactions. See the module docs.
        self.state.advance_block(height);
        for tx in &block.l2_txs {
            match self.state.apply(tx, height, validators, verifier) {
                Ok(_) => self.applied += 1,
                Err(error) => self.skipped.push(SkippedL2 {
                    height,
                    txid: tx.txid(),
                    error,
                }),
            }
        }
        // Exits queued by this block become crankable here, and only here:
        // this is the moment the node's root is the block's committed root, so
        // the proof it captures is the one L1 will verify against. Deposits in
        // the same block change balances and move the root, so they are applied
        // after — a block that mixes both simply yields no watch, and the exit
        // stays queued rather than being provable against the wrong root.
        if block.l2_state_root == Some(self.state.committed_root()) {
            self.watch_exits(height);
        }
        // A release the chain accepted moves value off L2 (approved P1). L1 is
        // the authority — it already proved maturity, exact funding and the
        // identity — so this mirrors it rather than re-deciding. A claim with no
        // record here means this node's L2 state disagrees with the chain it
        // replayed. The watch is dropped either way (L1 already released, so a
        // re-crank would only be refused), but the disagreement is recorded
        // instead of being swallowed: `debug_assert` alone compiles out of the
        // release build, which is the build a real node runs in.
        for claim in &block.exit_claims {
            if let Err(error) = self.state.note_release(&claim.owner, claim.nonce) {
                self.unbacked.push(UnbackedClaim {
                    height,
                    owner: claim.owner,
                    nonce: claim.nonce,
                    error,
                });
            }
            self.watches
                .retain(|w| !(w.owner == claim.owner && w.nonce == claim.nonce));
        }
        // Deposits ride the same block in the same order: detection is a pure
        // function of the block, maturity a pure function of tip + binding
        // finality, and exactly-once comes from the state's consumed set.
        let (detected, mut ignored) = scan_block(block, height, &self.deposits);
        self.ignored.append(&mut ignored);
        for d in detected {
            self.absorb_deposit(d, tip, binding);
        }
        self.height = height;
    }

    fn absorb_deposit(&mut self, d: DetectedDeposit, tip: u64, binding: u64) {
        let id = d.id();
        if self.state.deposit_credited(&id) {
            // Same bytes in an earlier block: refused by name, never twice.
            self.ignored.push(IgnoredDeposit {
                height: d.height,
                txid: d.txid,
                index: d.index,
                amount_sat: d.amount_sat,
                reason: DepositIgnoreReason::Duplicate,
            });
            return;
        }
        if deposit_is_spendable(&d, tip, binding, self.deposits.maturity_depth) {
            // Mature under both Decision 15 conditions: depth *and* binding
            // finality (when activated). Credit exactly the sink output's
            // satoshis. `apply_deposit` cannot fail here — the id is fresh
            // (checked above) and the amount is non-zero (the scan enforces the
            // minimum, and L1 rejects zero outputs) — but fail closed rather
            // than unwrap, because this is value creation and an error must
            // never become a silent credit.
            // Credit first, unpend on success only: if `apply_deposit`
            // fails the deposit stays visible in `pending` rather than
            // becoming invisible — in neither `applied` nor `pending` nor
            // `ignored` — which is where a dropped deposit used to go.
            if self
                .state
                .apply_deposit(d.recipient, d.amount_sat, id)
                .is_ok()
            {
                // It was detected immature and is now credited, and `pending`
                // must describe exactly the uncredited set.
                self.pending.retain(|p| p.deposit.id() != id);
                self.deposits_applied += 1;
            } else if !self.pending.iter().any(|p| p.deposit.id() == id) {
                // Checked maturity: a wrapped `saturating_add` near u64::MAX
                // would collapse the wait to spendable. `None` means never —
                // the deposit stays pending rather than maturing at once.
                match d.checked_matures_at(self.deposits.maturity_depth) {
                    Some(matures_at) => self.pending.push(PendingDeposit {
                        deposit: d,
                        matures_at,
                    }),
                    None => self.pending.push(PendingDeposit {
                        deposit: d,
                        matures_at: u64::MAX,
                    }),
                }
            }
        } else {
            // Detected but not yet safe: visible, not spendable. Recorded
            // once — a re-scan of the same block (incremental re-sync after a
            // restart of the loop, never a reorg, which replays) must not stack
            // duplicate pending entries.
            if !self.pending.iter().any(|p| p.deposit.id() == id) {
                self.pending.push(PendingDeposit {
                    deposit: d,
                    matures_at: d.matures_at(self.deposits.maturity_depth),
                });
            }
        }
    }

    /// The replayed state. Compare two of these directly: equal means the two
    /// nodes agree on every L2 fact, because `L2State`'s equality is derived
    /// over all of its fields.
    pub fn state(&self) -> &L2State {
        &self.state
    }

    /// Mutable access, for the funding bridge (Decision 7) and nothing else.
    /// Replay on its own never needs it.
    pub fn state_mut(&mut self) -> &mut L2State {
        &mut self.state
    }

    /// Height replayed to.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// How many L2 transactions applied.
    pub fn applied_count(&self) -> u64 {
        self.applied
    }

    /// Transactions a canonical block carried that did not apply, in block
    /// order. Empty on a healthy chain, and never a reason to reject a block.
    pub fn skipped(&self) -> &[SkippedL2] {
        &self.skipped
    }

    /// Whether every L2 transaction in every block applied.
    pub fn is_clean(&self) -> bool {
        self.skipped.is_empty()
    }

    /// Record a proof for every exit this block queued, so a crank can build a
    /// claim without replaying back to the queue height.
    fn watch_exits(&mut self, height: u64) {
        let fresh: Vec<(Address, u64)> = self
            .state
            .exit_records()
            .into_iter()
            .filter(|r| r.queued_height == height)
            .map(|r| (r.owner, r.nonce))
            .collect();
        for (owner, nonce) in fresh {
            if self
                .watches
                .iter()
                .any(|w| w.owner == owner && w.nonce == nonce)
            {
                continue;
            }
            let Some(proof) = self.state.exit_proof(&owner, nonce) else {
                continue;
            };
            let Some(record) = self.state.exit(&owner, nonce) else {
                continue;
            };
            self.watches.push(ExitWatch {
                owner,
                nonce,
                record: record.clone(),
                proof,
            });
        }
    }

    /// Queued exits still awaiting an L1 release, oldest first.
    pub fn pending_exits(&self) -> &[ExitWatch] {
        &self.watches
    }

    /// Deposits detected but not yet final-deep: visible, not spendable.
    pub fn pending_deposits(&self) -> &[PendingDeposit] {
        &self.pending
    }

    /// Sink outputs that credited nothing, with the named reason, in block
    /// order. Never a reason to reject a block.
    pub fn ignored_deposits(&self) -> &[IgnoredDeposit] {
        &self.ignored
    }

    /// L1 exit claims this node's L2 state could not back, in block order.
    ///
    /// Empty on a healthy node. A non-empty list is a real integrity signal,
    /// not noise: it means the chain accepted an exit release for an identity
    /// this replay never queued, so the two views disagree. Surfaced here so a
    /// release build reports it — see [`UnbackedClaim`].
    pub fn unbacked_claims(&self) -> &[UnbackedClaim] {
        &self.unbacked
    }

    /// Deposits credited (matured and applied).
    pub fn deposits_applied_count(&self) -> u64 {
        self.deposits_applied
    }

    /// Whether any pending deposit is now spendable under **both** Decision 15
    /// conditions (depth and binding finality). The node's incremental path
    /// calls this after extending the tip *and* after a checkpoint moves the
    /// binding floor: either event can mature a pending deposit that lives in
    /// an old block the incremental path never re-scans, so `true` means
    /// rebuild by full replay (which evaluates every deposit against both
    /// conditions) instead of extending.
    pub fn has_pending_matured(&self, tip: u64, binding_finalized: u64) -> bool {
        self.pending.iter().any(|p| {
            deposit_is_spendable(
                &p.deposit,
                tip,
                binding_finalized,
                self.deposits.maturity_depth,
            )
        })
    }
}

/// The two safety conditions for spendability (Decision 15): depth over the
/// tip, and — once binding finality has activated — the deposit's own height at
/// or below the binding-finalized height. `binding == 0` means binding finality
/// has never activated on this chain, in which case the M3 depth rule governs
/// alone, exactly as before.
///
/// A deposit becomes spendable only when BOTH required conditions hold, so
/// this can only ever be stricter than the depth rule, never weaker.
fn deposit_is_spendable(
    d: &DetectedDeposit,
    tip: u64,
    binding_finalized: u64,
    maturity_depth: u64,
) -> bool {
    let depth_ok = tip >= d.matures_at(maturity_depth);
    let binding_ok = binding_finalized == 0 || d.height <= binding_finalized;
    depth_ok && binding_ok
}

// ---------------------------------------------------------------------------
// C1/N1 Approach (ii): deterministic L2 root validator
// ---------------------------------------------------------------------------

/// Deterministic L2 root validator (C1/N1 Approach (ii)).
///
/// Replays L2 from genesis with `tip = block.height()` and `binding` derived
/// deterministically from block ancestry (never node-local P2P state).
/// The `verifier` selects the BLS backend used for L2 settlement checks
/// during replay: [`ChainVerifier::Real`] in production, `Mock` in tests.
/// It must match the verifier real nodes replay with, or the same block
/// maps to different roots in test vs production (a test-only divergence
/// by construction, never a consensus rule).
#[derive(Debug, Clone)]
pub struct AncestryRootValidator {
    config: L2Config,
    deposits: DepositParams,
    verifier: srct_core::chain::ChainVerifier,
}

impl AncestryRootValidator {
    pub fn new(
        config: L2Config,
        deposits: DepositParams,
        verifier: srct_core::chain::ChainVerifier,
    ) -> Self {
        Self {
            config,
            deposits,
            verifier,
        }
    }
}

impl srct_core::chain::L2RootValidator for AncestryRootValidator {
    fn expected_root_at(
        &self,
        chain: &srct_core::chain::Chain,
        parent_hash: srct_core::hash::Hash512,
        block: &srct_core::block::Block,
    ) -> std::result::Result<srct_core::hash::Hash, srct_core::chain::L2RootError> {
        use srct_core::chain::L2RootError;

        let height = block.header.height;
        // Tip is the block's own height (deterministic per ancestry).
        let tip = height;
        // Binding derived from ancestry, not node-local FinalityManager.
        let binding = chain.ancestry_binding_height(&parent_hash);
        let verifier = self.verifier.verifier();

        // Rebuild L2 state from genesis to parent, then apply this block.
        // Full rebuild ensures determinism regardless of cache state.
        let mut l2 = ChainL2::empty(
            self.config.clone(),
            &L2Genesis::empty(),
            self.deposits,
        )
        .map_err(|e| L2RootError::Replay(e.to_string()))?;

        // Replay blocks 1..=parent height via ancestry walk.
        // Collect the ancestry path first (genesis to parent).
        let mut ancestry: Vec<srct_core::block::Block> = Vec::new();
        let mut cursor = parent_hash;
        while let Some(b) = chain.block_by_hash(&cursor) {
            if b.header.height == 0 {
                break;
            }
            ancestry.push(b.clone());
            cursor = b.header.prev_hash;
        }
        ancestry.reverse();

        // Authority as of each block, mirroring `replay_to`: a post-rotation
        // committee must not verify pre-rotation history against post-rotation
        // keys on some nodes and old keys on others.
        for b in &ancestry {
            // Authority as of the block, not the tip or the candidate.
            let validators = chain.settlement_committee_at(b.header.height);
            l2.apply_block(b, tip, binding, &validators, verifier);
        }
        // Apply the candidate block itself.
        let validators = chain.settlement_committee_at(height);
        l2.apply_block(block, tip, binding, &validators, verifier);

        Ok(l2.state().committed_root())
    }
}
