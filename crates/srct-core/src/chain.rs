//! Chain state: validation, application, fork choice, reorg, finality.
//! SPEC.md §9.
//!
//! Fork choice is heaviest cumulative difficulty. Selection is deterministic:
//! ties break on lower height, then on the lowest block hash, so two nodes
//! holding the same set of valid blocks always agree on the tip. (An earlier
//! version of this comment claimed a first-seen tie-break; that was the arrival
//! counter bug, since fixed — the comment outlived the code and misdescribed a
//! consensus rule, which is worse than no comment at all.)

use std::collections::{HashMap, HashSet};

use crate::block::{genesis_block, Block, Header};
use crate::bls::RealBls;
use crate::bls_checkpoint::BlsPublicKey;
use crate::bond::{
    check_bond_tx, check_slash_tx, check_unbond_tx, slash_vesting_period, unwind_bond_op,
    BondLedger, BondRecord, BondUndoOp, StakeApply,
};
use crate::difficulty::{next_difficulty, validate_local_clock, validate_timestamp};
use crate::error::{Error, Result};
use crate::exit::ExitClaim;
use crate::fees::{next_base_fee, required_fee, split_fees, FeeSplit};
use crate::finality::{FinalityError, FinalityManager};
use crate::hash::{Address, Hash, Hash512, DOM_BLOCK512};
use crate::hbm_pow;
use crate::ledger::{check_tx, Undo, Utxo, UtxoSet};
use crate::mempool::{Mempool, ReconcileReport};
use crate::params::NetworkParams;
use crate::puzzle::{PuzzleKind, PuzzleRegistry, PuzzleSolver, PuzzleSpec};
use crate::slash::SlashVault;
use crate::supply::{
    block_reward_sat, check_mint_at_height, cumulative_issuance_sat, max_issuance_sat,
    rate_anchor_allowance,
};
use crate::tx::{OutPoint, Output, Transaction, TX_BOND, TX_COINBASE, TX_SLASH, TX_UNBOND};

/// Upper bound on mining attempts for a single block. Difficulty that would need
/// more work than this is a bug or an attack, not something to hang on.
pub const DEFAULT_MAX_ATTEMPTS: u64 = 200_000_000;

#[derive(Debug, Clone)]
struct Snapshot {
    canon: Vec<Hash512>,
    utxo: UtxoSet,
    undo: HashMap<Hash512, Undo>,
    pscb_reserve: u64,
    pscb_undo: HashMap<Hash512, u64>,
    bsaver_reserve: u64,
    bsaver_undo: HashMap<Hash512, u64>,
    treat_reserve: u64,
    treat_undo: HashMap<Hash512, u64>,
    burned_fees_total: u64,
    burned_undo: HashMap<Hash512, u64>,
    released_exits: HashSet<(Address, u64)>,
    exit_undo: HashMap<Hash512, Vec<(Address, u64)>>,
    bonds: BondLedger,
    bond_undo: HashMap<Hash512, Vec<BondUndoOp>>,
    bond_snapshots: HashMap<u64, BondLedger>,
    slash_vault: SlashVault,
    slash_undo: HashMap<Hash512, SlashVault>,
    /// Latest verified-work-certificate id committed to by VWC-linked mining
    /// (puzzle_id = 3). The first 16 bytes go into `header.extra_nonce` so
    /// stage 3 binds the block to useful L2 compute. Saved/restored by
    /// `snapshot`/`restore` on reorg; the node re-feeds it after L2 replay.
    latest_vwc_hash: Option<Hash>,
    finality: FinalityManager,
}

#[derive(Debug, Clone)]
pub struct Chain {
    params: NetworkParams,
    registry: PuzzleRegistry,
    /// Caches the active epoch's neural weights across mining attempts.
    solver: PuzzleSolver,
    blocks: HashMap<Hash512, Block>,
    /// `cumulative_work` for each stored block, recorded at insert as
    /// `parent_work + difficulty`. Lets fork choice be O(1) per block instead of
    /// a walk to genesis, which makes `best_candidate` O(stored) rather than
    /// O(stored²). Every block in `blocks` has an entry here.
    work: HashMap<Hash512, u128>,
    canon: Vec<Hash512>,
    utxo: UtxoSet,
    undo: HashMap<Hash512, Undo>,
    /// Accumulated PSCB (Protocol Security & Compute Buffer) reserve.
    /// M1 protocol mechanism: 50% of every block's base-fee portion is routed
    /// here rather than burned. The reserve backs the M2 Time-Locked Compute
    /// Reserve vault; it is already-removed supply, tracked as a
    /// protocol-owned accounting claim rather than re-entering circulation.
    pscb_reserve: u64,
    /// Per-block PSCB deltas, keyed by block hash. Required for reorg
    /// correctness: when a canonical block is rolled back, its PSCB contribution
    /// must be subtracted from the running total.
    pscb_undo: HashMap<Hash512, u64>,
    /// B-Saver reserve: 5% carve-out from the fee PSCB leg (cap 10%).
    /// Physical split — `burned + pscb + bsaver + tip == total` still holds
    /// via `burned + (pscb + bsaver) == full_base`. Tracked separately so the
    /// floor is auditable; rewound exactly like PSCB.
    bsaver_reserve: u64,
    /// Per-block B-Saver deltas, keyed by block hash.
    bsaver_undo: HashMap<Hash512, u64>,
    /// SRCT Treats reserve: 10% carve-out from the fee PSCB leg (cap 20%).
    /// Backs transferable agent Treat redemptions; rewound like PSCB.
    treat_reserve: u64,
    /// Per-block Treat deltas, keyed by block hash.
    treat_undo: HashMap<Hash512, u64>,
    /// Exit identities already released to L1, keyed by `(owner, nonce)`
    /// (approved P1). One release per identity, ever: consensus refuses a
    /// replay by this set rather than by bookkeeping, so a re-submitted
    /// claim is invalid on every node, not just on nodes that remember it.
    released_exits: HashSet<(Address, u64)>,
    /// Per-block released identities, keyed by block hash. Required for reorg
    /// correctness exactly like the PSCB deltas: rolling a block back unmarks
    /// its releases, so a reorged-away release can happen again on the
    /// winning branch — and a release the winner keeps stays released.
    exit_undo: HashMap<Hash512, Vec<(Address, u64)>>,
    /// Accumulated base-fee burn (M1's destroyed half, Stage SA-4). The other
    /// half is the PSCB reserve above; together they are everything usage
    /// ever removed from live supply, so `issued integral − (burned +
    /// PSCB)` is the net supply holders experience (Decision 18 §4.5).
    burned_fees_total: u64,
    /// Per-block burn deltas, keyed by block hash — rewound exactly like the
    /// PSCB deltas, for the same reason.
    burned_undo: HashMap<Hash512, u64>,
    /// Active validator bonds (Decision 20 — P2). Bond value parks in
    /// unspendable bond-identity outputs in the UTXO set; the *rights* live
    /// here, maintained with the same undo discipline as the ledger.
    bonds: BondLedger,
    /// Per-block bond inverses, keyed by block hash — rewound exactly like
    /// the UTXO undo records, for the same reason.
    bond_undo: HashMap<Hash512, Vec<BondUndoOp>>,
    /// Bond-ledger snapshots at seed heights (P0-1). The committee for epoch
    /// `e` is derived from the bond state at `seed_height(e)`, not from
    /// whatever bonds exist mid-epoch. Keyed by seed height so each epoch's
    /// committee is stable for the whole epoch. Snapshots are taken when a
    /// block at a seed height is applied and rewound on reorg via `bond_undo`
    /// replay (a rolled-back seed block removes its snapshot).
    bond_snapshots: HashMap<u64, BondLedger>,
    /// M2 slash vault (Decision 2 item 4, Decision 20 item 4): equivocation
    /// slashes write full-bond records here — half burned at once, half
    /// vested to the PSCB reserve over time. Rebuilt by replay like every
    /// other chain state, rewound per block below.
    slash_vault: SlashVault,
    /// Pre-block vault states for blocks that touched the vault, keyed by
    /// block hash. Stored only when touched: an empty, untouched vault needs
    /// no undo because there is nothing to restore.
    slash_undo: HashMap<Hash512, SlashVault>,
    /// Latest VWC id for VWC-linked mining. See `Snapshot` comment above.
    /// Set by the node after L2 application (never by `apply_block`);
    /// reorgs restore it via `snapshot`/`restore`, and the node re-feeds it
    /// after every reorg, so no per-block undo map is kept.
    latest_vwc_hash: Option<Hash>,
    /// Non-coinbase transactions the most recent successful reorg rolled back,
    /// oldest block first. Drained by the caller so the mempool can re-admit
    /// them.
    ///
    /// Held on `Chain` rather than returned from `submit_at` because a reorg that
    /// fails is restored wholesale: a list published from a reorg that did not
    /// happen would put transactions back into the pool that the canonical chain
    /// still contains, and the pool would then relay an unmineable duplicate of
    /// a confirmed transaction.
    disconnected_txs: Vec<Transaction>,
    /// M5 binding finality (Decisions 12/14, SPEC.md §14.8). Observation before
    /// activation; once activated, `adopt()` refuses to rewrite finalized
    /// history. Restored from the store on load, never re-derived from blocks
    /// (see `restore_finality`).
    finality: FinalityManager,
}

impl Chain {
    /// Build a chain with the canonical genesis block.
    pub fn new(params: NetworkParams) -> Result<Self> {
        params.validate()?;
        let registry = PuzzleRegistry::genesis();
        // The cached solver must run the profile's active puzzle: a
        // hybrid-built solver rejects VWC-linked headers (and vice versa),
        // so constructing the wrong one bricks the profile at genesis.
        let solver_spec = registry.get(params.puzzle_id)?.clone();
        let solver = PuzzleSolver::new(solver_spec);
        let genesis = genesis_block(params.genesis_difficulty);
        let hash = genesis.block_hash();
        debug_assert_eq!(hash, {
            let hb = genesis.header.serialize();
            crate::hash::sha512_dom(DOM_BLOCK512, &[&hb])
        });

        let mut chain = Chain {
            params,
            registry,
            solver,
            blocks: HashMap::new(),
            work: HashMap::new(),
            canon: Vec::new(),
            utxo: UtxoSet::new(),
            undo: HashMap::new(),
            pscb_reserve: 0,
            pscb_undo: HashMap::new(),
            bsaver_reserve: 0,
            bsaver_undo: HashMap::new(),
            treat_reserve: 0,
            treat_undo: HashMap::new(),
            burned_fees_total: 0,
            burned_undo: HashMap::new(),
            bonds: BondLedger::default(),
            bond_undo: HashMap::new(),
            bond_snapshots: HashMap::from([(0u64, BondLedger::default())]),
            slash_vault: SlashVault::new(),
            slash_undo: HashMap::new(),
            latest_vwc_hash: None,
            released_exits: HashSet::new(),
            exit_undo: HashMap::new(),
            disconnected_txs: Vec::new(),
            finality: FinalityManager::default(),
        };
        chain.finality = FinalityManager::new(&chain.params);
        chain.blocks.insert(hash, genesis.clone());
        chain.work.insert(hash, genesis.header.difficulty);
        // Genesis mints nothing, so the UTXO set stays empty; only the block
        // bookkeeping matters.
        chain.undo.insert(hash, Undo::default());
        chain.canon = vec![hash];
        Ok(chain)
    }

    pub fn params(&self) -> &NetworkParams {
        &self.params
    }

    pub fn registry(&self) -> &PuzzleRegistry {
        &self.registry
    }

    pub fn height(&self) -> u64 {
        // invariant: `canon` always has at least the genesis block, so len() - 1 cannot underflow.
        (self.canon.len() - 1) as u64
    }

    pub fn tip_hash(&self) -> Hash512 {
        // invariant: `canon` always has at least the genesis block.
        *self.canon.last().expect("chain always has a genesis block")
    }

    pub fn tip(&self) -> &Block {
        // invariant: the tip hash was just read from `canon`, so it must resolve.
        self.block_by_hash(&self.tip_hash())
            .expect("tip is in canon")
    }

    pub fn block_hash_at(&self, height: u64) -> Option<Hash512> {
        self.canon.get(height as usize).copied()
    }

    pub fn block_at(&self, height: u64) -> Option<&Block> {
        let h = self.block_hash_at(height)?;
        self.block_by_hash(&h)
    }

    pub fn block_by_hash(&self, h: &Hash512) -> Option<&Block> {
        self.blocks.get(h)
    }

    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    pub fn total_supply_sat(&self) -> u64 {
        self.utxo.total_value()
    }

    /// Accumulated Protocol Security & Compute Buffer reserve (M1).
    ///
    /// This is the 50% of every block's base-fee portion that is diverted from
    /// the burn to the on-chain reserve. It is already-removed supply for
    /// net-supply reporting (Decision 18 §4.5), tracked here to power the M2
    /// slash recovery vault.
    pub fn pscb_reserve(&self) -> u64 {
        self.pscb_reserve
    }

    /// B-Saver exogenous-floor reserve (5% of the fee PSCB leg, cap 10%).
    pub fn bsaver_reserve(&self) -> u64 {
        self.bsaver_reserve
    }

    /// SRCT Treats reserve: 10% of the fee PSCB leg backing Treat redemptions.
    pub fn treat_reserve(&self) -> u64 {
        self.treat_reserve
    }

    /// Debit the Treat reserve for a redemption payout. Fails when empty.
    pub fn spend_treat_reserve(&mut self, amount: u64) -> crate::error::Result<()> {
        if amount > self.treat_reserve {
            return Err(crate::error::Error::BadFee("treat reserve exhausted"));
        }
        self.treat_reserve -= amount;
        Ok(())
    }

    /// Cumulative base-fee value destroyed by the M1 burn half (Stage SA-4).
    ///
    /// Together with [`Chain::pscb_reserve`] this is everything usage ever
    /// removed from live supply: net supply = issuance integral − (burned +
    /// PSCB). Rewound per rolled-back block, exactly like the reserve.
    pub fn burned_fees_total(&self) -> u64 {
        self.burned_fees_total
    }

    /// Everything usage ever removed from live supply: the destroyed half
    /// plus the PSCB half of every block's base fee (Stage SA-4).
    pub fn base_removed_total(&self) -> u64 {
        self.burned_fees_total
            .saturating_add(self.pscb_reserve)
            .saturating_add(self.bsaver_reserve)
            .saturating_add(self.treat_reserve)
    }

    /// Height below which history is immutable.
    ///
    /// The stronger of the depth rule and any binding checkpoint finality
    /// (Decision 12): before activation this is exactly the old depth rule, so
    /// pre-M5 behavior is unchanged; after a checkpoint finalizes at H it is
    /// at least H. `adopt()` consults this, which is what makes checkpoints
    /// binding rather than merely observed.
    pub fn finalized_height(&self) -> u64 {
        self.height()
            .saturating_sub(self.params.finality_depth)
            .max(self.finality.binding_finalized_height())
    }

    /// The binding-finality manager (Decisions 12/14). Read-only inspection;
    /// checkpoints are applied through [`Chain::apply_checkpoint`].
    pub fn finality(&self) -> &FinalityManager {
        &self.finality
    }

    /// Apply a verified checkpoint certificate, updating observed and binding
    /// finality. Returns the accepted point or a named rejection; a rejection
    /// never changes consensus state.
    ///
    /// The certificate must name the block this chain holds canonically at its
    /// height; a valid signature over a non-canonical or future block is
    /// refused (`NotCanonical`). Passing a height already finalized to a
    /// *different* hash is refused as conflicting finality and retained as
    /// evidence (Decision 14).
    #[allow(clippy::result_large_err)]
    pub fn apply_checkpoint(
        &mut self,
        checkpoint: &crate::bls_checkpoint::Checkpoint,
        verify: &dyn crate::bls_checkpoint::BlsVerifier,
    ) -> std::result::Result<(), FinalityError> {
        let height = checkpoint.payload.height;
        // The canonical hash this node holds at that height, if any. Fetch
        // before borrowing `finality` mutably.
        let canonical = self.block_hash_at(height);
        self.finality.accept(checkpoint, canonical, verify)
    }

    /// Restore the binding-finalized point after a restart.
    ///
    /// Only installs it if this chain actually holds that exact block
    /// canonically at that height — a stale or forged metadata row cannot
    /// finalize a block the chain does not have. Returns whether it was
    /// installed.
    pub fn restore_finality(&mut self, height: u64, hash: Hash512) -> bool {
        if height == 0 {
            return false;
        }
        if self.block_hash_at(height) != Some(hash) {
            return false;
        }
        self.finality.restore_finalized(height, hash);
        true
    }

    /// The `(height, hash)` of the binding-finalized point, for persistence.
    /// `None` when binding finality has not activated or has not advanced.
    pub fn finalized_point(&self) -> Option<(u64, Hash512)> {
        let h = self.finality.binding_finalized_height();
        if h == 0 {
            None
        } else {
            Some((h, self.finality.binding_finalized_hash()))
        }
    }

    /// Store size above which side-branch pruning runs. Sized off the finality
    /// window so a healthy chain never trips it, and off the canonical length
    /// so a node with real history still has room for a live fork.
    fn prune_threshold(&self) -> usize {
        let window = (self.params.finality_depth as usize).saturating_mul(4);
        (self.canon.len() + window).max(64)
    }

    /// `timestamps` of the previous `n` blocks, newest first (index 0 = tip).
    fn history(&self, n: usize) -> Vec<u64> {
        let tip_height = self.height() as usize;
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            if i > tip_height {
                break;
            }
            let h = tip_height - i;
            if let Some(hash) = self.canon.get(h) {
                if let Some(b) = self.blocks.get(hash) {
                    v.push(b.header.timestamp_ms);
                }
            }
        }
        v
    }

    /// The difficulty a child of `parent_hash` must declare, computed from the
    /// parent's *own* branch: `history` walks `canon`, which for a side parent
    /// would read the wrong timestamps. An ancestry that does not reach a
    /// stored ancestor can never be applied canonically either, so it is
    /// refused rather than guessed at. This must agree term-for-term with
    /// `apply_block`'s check or a valid side branch would be refused here and
    /// accepted there.
    fn expected_difficulty_at(&self, parent_hash: &Hash512) -> Result<u128> {
        let window = self.params.difficulty_window as usize + 1;
        let mut stamps: Vec<u64> = Vec::with_capacity(window);
        let mut cursor = *parent_hash;
        let mut parent_difficulty = 0u128;
        loop {
            let b = self.blocks.get(&cursor).ok_or(Error::UnknownParent)?;
            if stamps.is_empty() {
                parent_difficulty = b.header.difficulty;
            }
            stamps.push(b.header.timestamp_ms);
            if stamps.len() >= window || b.header.height == 0 {
                break;
            }
            cursor = b.header.prev_hash;
        }
        Ok(next_difficulty(&self.params, parent_difficulty, &stamps))
    }

    fn puzzle_for(&self, id: u64) -> Result<&PuzzleSpec> {
        self.registry.get(id)
    }

    /// Dispatch PoW verification by the header's `puzzle_id`.
    ///
    /// `puzzle_id == 1` uses the cached hybrid `PuzzleSolver` (§5); `puzzle_id == 2`
    /// verifies the M4 HBM scratchpad proof against the network's `hbm` config;
    /// `puzzle_id == 3` uses the cached solver with VWC-linked stage 3, where
    /// `header.extra_nonce` carries a verified-work-certificate id commitment.
    /// Unknown ids are rejected structurally by `puzzle_for` first. This is the
    /// single authority for PoW acceptance so `check_block` and `mine_block`
    /// can never disagree on what a valid proof is.
    fn pow_satisfies(&mut self, header: &crate::block::Header) -> Result<bool> {
        let spec = self.puzzle_for(header.puzzle_id)?;
        match spec.kind {
            PuzzleKind::Hybrid | PuzzleKind::VwcLinked => {
                // The cached solver must match the header's puzzle id; the
                // solver's `run` dispatches stage 3 by spec kind.
                if spec.id != self.solver.spec().id {
                    return Err(Error::BadPuzzleSpec(format!(
                        "solver holds puzzle {} but the header names {}",
                        self.solver.spec().id,
                        header.puzzle_id
                    )));
                }
                if spec.kind == PuzzleKind::VwcLinked {
                    // The VWC commitment is real, not decorative: the header
                    // must commit to exactly the chain-acknowledged latest
                    // verified-work certificate (zeros before the first VWC
                    // settles). Templates emit these exact bytes, so honest
                    // miners are unaffected; arbitrary bytes never validate.
                    // The node feeds `latest_vwc_hash` after L2 application
                    // (and re-feeds it after every reorg); without a feed
                    // the rule pins extra_nonce to zero, which is what the
                    // template builder emits in that case.
                    let mut expected = [0u8; 16];
                    if let Some(h) = self.latest_vwc_hash {
                        expected.copy_from_slice(&h[..16]);
                    }
                    if header.extra_nonce != expected {
                        return Err(Error::BadPuzzleSpec(
                            "vwc-v1 header does not commit to the latest verified-work certificate"
                                .into(),
                        ));
                    }
                }
                self.solver.satisfies(header)
            }
            PuzzleKind::Hbm => {
                let res = hbm_pow::hbm_satisfies_cfg(header, header.difficulty, &self.params.hbm)?;
                Ok(res)
            }
        }
    }

    /// Record the latest verified-work-certificate id for VWC-linked mining.
    /// Called by the node after applying L2 state so the next template's
    /// `extra_nonce` carries a real VWC commitment. `None` clears the
    /// commitment (no VWC settled yet).
    pub fn set_latest_vwc_hash(&mut self, hash: Option<Hash>) {
        self.latest_vwc_hash = hash;
    }

    /// The latest VWC hash, if any. Read by the template builder to populate
    /// `extra_nonce` for `puzzle_id = 3` blocks.
    pub fn latest_vwc_hash(&self) -> Option<Hash> {
        self.latest_vwc_hash
    }

    /// Build the `extra_nonce` for a template: the first 16 bytes of the
    /// latest VWC hash when mining `puzzle_id = 3`, otherwise zero bytes.
    fn vwc_extra_nonce(&self) -> [u8; 16] {
        if self.params.puzzle_id == 3 {
            if let Some(hash) = self.latest_vwc_hash {
                let mut enc = [0u8; 16];
                enc.copy_from_slice(&hash[..16]);
                return enc;
            }
        }
        [0u8; 16]
    }

    /// Cumulative PoW difficulty along the chain ending at `hash`.
    ///
    /// Recorded incrementally at insert time as `parent_work + difficulty`, so
    /// this is an O(1) lookup rather than the O(chain-length) walk to genesis it
    /// used to be. That walk made `best_candidate` O(stored²), which a peer
    /// relaying many blocks could turn into a quadratic CPU amplifier.
    ///
    /// Every block in `blocks` is entered here on insert (`Chain::new` for
    /// genesis, `submit_at` for every later block). A miss is therefore a logic
    /// error, but the walk is kept as a defensive fallback so the value stays
    /// correct for any block added outside that path; no consensus outcome
    /// depends on which branch runs.
    fn cumulative_work(&self, hash: &Hash512) -> u128 {
        if let Some(&w) = self.work.get(hash) {
            return w;
        }
        debug_assert!(false, "cumulative_work miss for a stored block");
        let mut total = 0u128;
        let mut cursor = *hash;
        loop {
            let Some(block) = self.blocks.get(&cursor) else {
                return total;
            };
            total = total.saturating_add(block.header.difficulty);
            if block.header.height == 0 {
                return total;
            }
            cursor = block.header.prev_hash;
        }
    }

    // -----------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------

    /// Everything checkable without chain state. SPEC.md §9.1 items 3, 5, 7, 8, 10.
    pub fn validate_standalone(&mut self, block: &Block) -> Result<()> {
        let bytes = block.serialize();
        if bytes.len() > self.params.max_block_bytes {
            return Err(Error::BlockTooLarge {
                got: bytes.len(),
                cap: self.params.max_block_bytes,
            });
        }
        if block.txs.len() > self.params.max_tx_count {
            return Err(Error::TooManyTxs {
                got: block.txs.len(),
                cap: self.params.max_tx_count,
            });
        }
        if block.exit_claims.len() > self.params.max_tx_count {
            return Err(Error::TooManyTxs {
                got: block.exit_claims.len(),
                cap: self.params.max_tx_count,
            });
        }
        if block.txs.is_empty() {
            return Err(Error::BadCoinbase("block has no transactions"));
        }
        // SPEC.md §1: nodes MUST reject unknown `sig_scheme` values. The field
        // is committed to by the block hash and is what a signature-scheme
        // upgrade hangs off, so accepting an unrecognised value leaves the node
        // unable to tell a v0.1 block from a hypothetical future one.
        if block.header.sig_scheme != crate::hash::SIG_SCHEME_SECP256K1_ECDSA {
            return Err(Error::UnsupportedSigScheme(block.header.sig_scheme));
        }
        if block.header.merkle_root != block.merkle_root() {
            return Err(Error::BadMerkleRoot);
        }

        let expected_epoch = block.header.expected_epoch(self.params.nn_epoch_blocks);
        if block.header.epoch_id != expected_epoch {
            return Err(Error::BadEpoch {
                expected: expected_epoch,
                got: block.header.epoch_id,
            });
        }

        let gas_used = block.total_gas_used()?;
        let claims_gas = block.claims_gas_used()?;
        let gas_used = gas_used
            .checked_add(claims_gas)
            .ok_or(Error::ValueOverflow)?;
        if gas_used > self.params.gas_cap {
            return Err(Error::GasOverCap {
                used: gas_used,
                cap: self.params.gas_cap,
            });
        }

        let mut seen = std::collections::HashSet::new();
        for tx in &block.txs {
            if !seen.insert(tx.txid()) {
                return Err(Error::DuplicateTxid);
            }
        }
        // Claims live in the same id space for duplication purposes: a
        // replayed claim is the same bytes with the same id, and an id that
        // collides across the two lists is refused rather than interpreted.
        for claim in &block.exit_claims {
            if !seen.insert(claim.claim_id()) {
                return Err(Error::DuplicateTxid);
            }
        }

        // Exit activation (approved P1): below the height the profile
        // activates, a committed root or a claim is a second encoding rule
        // the network never agreed to — refused structurally, before any
        // proof is read. At and after activation, L2 transactions without a
        // committed root are refused: a queue in such a block could never be
        // proven, so the block would silently disable exits.
        let active = self.exit_active_at(block.header.height);
        if !active {
            if block.l2_state_root.is_some() {
                return Err(Error::Malformed("l2 root before exit activation"));
            }
            if !block.exit_claims.is_empty() {
                return Err(Error::Malformed("exit claim before activation"));
            }
        } else if !block.l2_txs.is_empty() && block.l2_state_root.is_none() {
            return Err(Error::Malformed(
                "post-activation L2 section must commit a root",
            ));
        }

        // Proof of work. `puzzle_for` (called inside `pow_satisfies`) rejects
        // any puzzle_id the registry does not know; the hybrid solver is used
        // for id 1, the HBM scratchpad path for id 2. Mining and validation
        // share this single rule.
        if !self.pow_satisfies(&block.header)? {
            return Err(Error::PowInvalid {
                hash: crate::hash::hash512_to_hex(&block.block_hash()),
                difficulty: block.header.difficulty,
            });
        }
        Ok(())
    }

    /// Validate against chain state and apply. The UTXO set must already
    /// correspond to the block's parent.
    fn apply_block(&mut self, block: &Block) -> Result<()> {
        let parent_hash = block.header.prev_hash;
        let parent = self
            .blocks
            .get(&parent_hash)
            .ok_or(Error::UnknownParent)?
            .clone();

        let height = parent.header.height + 1;
        if block.header.height != height {
            return Err(Error::BadHeight {
                expected: height,
                got: block.header.height,
            });
        }
        // The coinbase input commits to its own height through a `u32` index
        // (SPEC.md 3.1). Past `u32::MAX` that encoding stops being injective,
        // so refuse rather than compare a truncated index.
        if height > u32::MAX as u64 {
            return Err(Error::BadHeight {
                expected: u32::MAX as u64,
                got: height,
            });
        }

        // Difficulty: SPEC.md §6.
        let history = self.history(self.params.difficulty_window as usize + 1);
        let expected_diff = next_difficulty(&self.params, parent.header.difficulty, &history);
        if block.header.difficulty != expected_diff {
            return Err(Error::BadDifficulty {
                expected: expected_diff,
                got: block.header.difficulty,
            });
        }

        // Timestamps: SPEC.md §6.1.
        validate_timestamp(&self.params, block.header.timestamp_ms, &history)?;

        // Base fee: SPEC.md §8.
        let expected_base_fee = if height == 1 {
            self.params.base_fee_initial_sat
        } else {
            // Claims are ordinary block space (approved P1), so their gas feeds
            // the next block's base fee exactly like body gas. This must match
            // `build_block` and `expected_base_fee_for_next_block` term for
            // term: a validator that omitted claim gas here would compute a
            // lower floor than the miner produced and reject a block that every
            // other node accepts, a consensus split reachable by anyone who
            // cranks a single exit claim.
            let parent_gas = parent
                .total_gas_used()?
                .checked_add(parent.claims_gas_used()?)
                .ok_or(Error::ValueOverflow)?;
            next_base_fee(&self.params, parent.header.base_fee_sat, parent_gas)
        };
        if block.header.base_fee_sat != expected_base_fee {
            return Err(Error::BadFee("base fee does not follow the schedule"));
        }

        // Coinbase shape: SPEC.md §9.2 rules 1-3.
        let coinbase = &block.txs[0];
        if coinbase.tx_type != TX_COINBASE {
            return Err(Error::BadCoinbase("tx 0 must be the coinbase"));
        }
        if coinbase.inputs.len() != 1 || coinbase.outputs.len() != 1 {
            return Err(Error::BadCoinbase(
                "coinbase needs exactly one input and one output",
            ));
        }
        if coinbase.inputs[0].prev_hash != parent_hash
            || coinbase.inputs[0].prev_index != height as u32
        {
            return Err(Error::BadCoinbase(
                "coinbase input must reference the parent block",
            ));
        }

        // A zero-value coinbase is legitimate, not an error. SPEC.md §7 says
        // that once the reward ladder is exhausted the coinbase collects the
        // tips only, and tips can be zero on an empty block. Rejecting it
        // unconditionally halted the chain at a fixed, known height.

        // Everything after the coinbase is an ordinary spend.
        let body = &block.txs[1..];
        let mut body_undo = Undo::default();
        let mut total_gas = 0u64;
        let mut total_fees = 0u64;

        // Every write from here on is recorded so it can be unwound: a block
        // that fails partway through must leave the ledger exactly as it found
        // it, or the node credits outputs from a block it just rejected.
        let mut applied: Vec<Undo> = Vec::new();
        // Exit claims (approved P1) settle before the body, so a body
        // transaction may spend a release output in the same block. Their gas
        // and fees fold into the block totals below, exactly like body
        // transactions — a claim is ordinary block space, not an exemption.
        let marked = self.apply_exit_claims(
            block,
            height,
            &mut applied,
            &mut body_undo,
            &mut total_gas,
            &mut total_fees,
        )?;
        let mut stake_apply = StakeApply::default();
        let outcome = self.apply_body(
            block,
            body,
            height,
            &mut applied,
            &mut body_undo,
            &mut total_gas,
            &mut total_fees,
            &mut stake_apply,
        );
        let split = match outcome {
            Ok(split) => split,
            Err(e) => {
                for u in applied.iter().rev() {
                    self.utxo.undo(u);
                }
                self.unwind_stake(&stake_apply);
                self.unwind_claims(&marked);
                return Err(e);
            }
        };

        // Reward + tip only: the base fee is burned (SPEC.md §8).
        let reward = block_reward_sat(&self.params, height);
        let max_claim = reward.saturating_add(split.tip);
        let minted = coinbase.outputs[0].value;
        if minted > max_claim {
            for u in applied.iter().rev() {
                self.utxo.undo(u);
            }
            self.unwind_stake(&stake_apply);
            self.unwind_claims(&marked);
            return Err(Error::BadFee("coinbase claims more than reward plus tip"));
        }

        // Derived supply bound (monetary-redesign §5.1 rule 1, approved
        // 2026-10-09): live UTXO value may never exceed the issuance integral
        // at this height. Defence in depth over the reward+tip rule above —
        // a reward-function bug becomes a rejected block here instead of an
        // inflation incident. O(periods), effectively O(1). Decision 18
        // (2026-10-09) removed the stock cap; the second bound is the rate
        // anchor, enforced by the same function.
        //
        // The comparison itself lives in `supply::check_mint_at_height` so the
        // miner, this validator and the node report share one rule rather than
        // three copies of it (§5.2 invariant 1).
        let already = self.utxo.total_value();
        if let Err(e) = check_mint_at_height(&self.params, already, minted, height) {
            for u in applied.iter().rev() {
                self.utxo.undo(u);
            }
            self.unwind_stake(&stake_apply);
            self.unwind_claims(&marked);
            return Err(e);
        }

        // Committee inputs are pure reads: resolve them before any tail
        // mutation (coinbase insert, vault advance, reserve credits) so a
        // lookup failure unwinds through the body/stake/claims pattern
        // above instead of leaving tail writes behind. Unreachable on a
        // processable chain — seed snapshots are never pruned and the seed
        // block is always applied — but ordered here so even the
        // theoretical failure is a clean refusal.
        let committee_keys = self
            .committee_keys_at(height)
            .ok_or(Error::StakeInvalid("missing seed snapshot"))?;
        let committee_records = self
            .committee_records_at(height)
            .ok_or(Error::StakeInvalid("missing seed snapshot"))?;

        // Apply the coinbase last so its output is the freshest. A zero-value
        // coinbase is not recorded at all: `check_tx` refuses to spend a
        // zero-value output, so recording it would only grow the UTXO set with
        // permanently unspendable entries.
        let cb_txid = coinbase.txid();
        let cb_op = OutPoint {
            txid: cb_txid,
            index: 0,
        };
        if minted > 0 {
            // Overwrite guard (see `UtxoSet::apply_tx`): the coinbase input
            // commits to its height, so a live output here is a duplicate
            // block, never a coincidence.
            if self.utxo.contains(&cb_op) {
                return Err(Error::Malformed("coinbase output already exists"));
            }
            body_undo.created.push(cb_op);
            self.utxo.insert(
                cb_op,
                Utxo {
                    out: coinbase.outputs[0],
                    height,
                },
            );
        }

        let hash = block.block_hash();
        // M2 vesting advance (Decision 20 item 4): vested payouts route to the
        // PSCB reserve — an equivocator earns nothing back. A snapshot is taken
        // exactly when the vault is touched (slash event) or holds records
        // (vesting trickle); an empty, untouched vault needs no undo because
        // there is nothing to restore.
        if stake_apply.vault_before.is_none() && !self.slash_vault.records().is_empty() {
            stake_apply.vault_before = Some(self.slash_vault.clone());
        }
        let mut vault_payouts = 0u64;
        if stake_apply.vault_before.is_some() {
            for (_, amount) in self.slash_vault.advance_block(height) {
                vault_payouts = vault_payouts
                    .checked_add(amount)
                    .ok_or(Error::ValueOverflow)?;
            }
        }
        // Credit the PSCB reserve (M1). Checked, not saturating: after
        // saturation an undo would subtract the delta from a clamped total
        // and permanently corrupt the reserve — fail the block instead.
        // In practice the hard-capped fee schedule makes this unreachable,
        // which is exactly why refusing is safe.
        //
        // Vesting payouts fold into the same delta: they are reserve-bound
        // value like the fee half, so reorgs rewind them together.
        // B-Saver: 5% carve-out from the *fee* PSCB leg only — vault
        // payouts stay fully in PSCB so the floor stays small by construction.
        let bsaver_delta = crate::bsaver::bsaver_cut_default(split.pscb);
        let treat_delta = crate::treats::treat_cut_default(split.pscb);
        let pscb_delta = split
            .pscb
            .checked_sub(bsaver_delta)
            .ok_or(Error::ValueOverflow)?
            .checked_sub(treat_delta)
            .ok_or(Error::ValueOverflow)?
            .checked_add(vault_payouts)
            .ok_or(Error::ValueOverflow)?;
        self.pscb_reserve = self
            .pscb_reserve
            .checked_add(pscb_delta)
            .ok_or(Error::ValueOverflow)?;
        self.pscb_undo.insert(hash, pscb_delta);
        self.bsaver_reserve = self
            .bsaver_reserve
            .checked_add(bsaver_delta)
            .ok_or(Error::ValueOverflow)?;
        self.bsaver_undo.insert(hash, bsaver_delta);
        self.treat_reserve = self
            .treat_reserve
            .checked_add(treat_delta)
            .ok_or(Error::ValueOverflow)?;
        self.treat_undo.insert(hash, treat_delta);
        // The destroyed half, tracked the same way (Stage SA-4): the two
        // halves together are the removal term net-supply reporting needs.
        // Slash burns fold in likewise — removed supply is removed supply.
        let burned_delta = split
            .burned
            .checked_add(stake_apply.slash_burned)
            .ok_or(Error::ValueOverflow)?;
        self.burned_fees_total = self
            .burned_fees_total
            .checked_add(burned_delta)
            .ok_or(Error::ValueOverflow)?;
        self.burned_undo.insert(hash, burned_delta);
        // Bond inverses for reorgs, rewound exactly like the UTXO undo
        // records, for the same reason.
        self.bond_undo
            .insert(hash, std::mem::take(&mut stake_apply.ops));
        // Vault pre-state, but only for blocks that touched it (see above).
        if let Some(vault) = stake_apply.vault_before.take() {
            self.slash_undo.insert(hash, vault);
        }
        // Record this block's releases (approved P1): the identities stay
        // marked while the block is canonical and are unmarked by
        // `rollback_block` if a reorg takes it.
        self.exit_undo.insert(hash, marked);
        self.undo.insert(hash, body_undo);
        // Snapshot the bond ledger whenever the applied block lands on a seed
        // height, so each epoch's committee is derived from the bond state that
        // existed at its seed height rather than from mid-epoch bond changes.
        // Taken before the refresh so the seed block's own bond state is the
        // one that seeds its epoch's committee. `height` here is the applied
        // block's height (`canon` is pushed by the caller afterwards).
        if crate::validators::is_seed_height(
            height,
            self.params.checkpoint_interval_blocks,
            crate::validators::EPOCH_LOOKBACK_DEFAULT,
        ) {
            self.bond_snapshots.insert(height, self.bonds.clone());
        }
        // The committee follows the seed-height bonds: refresh the finality
        // key set now that canonical state advanced. Side branches never reach
        // here (only canonical advancement applies blocks). The epoch set is
        // derived from seed-height bond state (P0-1), so it stays stable for
        // the whole epoch. Inputs were resolved above, before any tail
        // mutation; the refresh itself cannot fail on them — bond admission
        // already validated every key and refused every duplicate, so
        // `derive_set` sees only clean records. The remaining `?` arms in
        // this tail (fee-capped checked arithmetic) are unreachable by
        // construction for the same reason: refusing them would also be
        // correct, unwinding them is provably never needed.
        self.finality.set_keys(committee_keys);
        self.finality
            .refresh_committee(
                &committee_records,
                height,
                self.params.checkpoint_interval_blocks,
                crate::validators::EPOCH_LOOKBACK_DEFAULT,
            )
            .map_err(|_| Error::StakeInvalid("committee derivation failed"))?;
        Ok(())
    }

    /// Apply every non-coinbase transaction of `block`, accumulating gas, fees
    /// and undo data. Caller unwinds with the returned `applied` list on error.
    #[allow(clippy::too_many_arguments)]
    fn apply_body(
        &mut self,
        block: &Block,
        body: &[Transaction],
        height: u64,
        applied: &mut Vec<Undo>,
        body_undo: &mut Undo,
        total_gas: &mut u64,
        total_fees: &mut u64,
        stake: &mut StakeApply,
    ) -> Result<FeeSplit> {
        for (i, tx) in body.iter().enumerate() {
            let delta = check_tx(
                &self.utxo,
                tx,
                height,
                &self.params,
                block.header.base_fee_sat,
                self.params.coinbase_maturity,
            )?;
            let mut undo = self.utxo.apply_tx(tx, height)?;
            // Stake overlay (Decision 20): checks run before any ledger write
            // inside `apply_stake_tx`, so a refusal only needs the UTXO undo
            // of this one transaction — which is discarded, never pushed.
            if tx.is_stake_tx() {
                let tx_index = u32::try_from(i + 1).map_err(|_| Error::ValueOverflow)?;
                if let Err(e) = self.apply_stake_tx(tx, tx_index, height, &mut undo, stake) {
                    self.utxo.undo(&undo);
                    return Err(e);
                }
            }
            applied.push(undo.clone());
            body_undo.spent.extend(undo.spent);
            body_undo.created.extend(undo.created);
            // Accumulated across the block, so use checked arithmetic: `+=`
            // panics in debug and wraps in release, and a wrapped total feeds
            // straight into the burn/tip split below, where wrapping could
            // understate the burned portion or invent a miner tip.
            *total_gas = total_gas
                .checked_add(delta.gas_used)
                .ok_or(Error::ValueOverflow)?;
            *total_fees = total_fees
                .checked_add(delta.fee_total)
                .ok_or(Error::ValueOverflow)?;
        }
        // Genesis-adjacent blocks pay no base fee on their first transaction;
        // the schedule above already starts at `base_fee_initial_sat`.
        split_fees(*total_gas, *total_fees, block.header.base_fee_sat)
    }

    /// Bond-ledger effects of one stake transaction (Decision 20). Checks run
    /// before any ledger write, so a refusal leaves bonds and vault untouched
    /// and the caller only unwinds the UTXO application. Release outputs ride
    /// the transaction's own `undo.created`, so the block-level unwind covers
    /// them with no special case.
    fn apply_stake_tx(
        &mut self,
        tx: &Transaction,
        tx_index: u32,
        height: u64,
        undo: &mut Undo,
        stake: &mut StakeApply,
    ) -> Result<()> {
        match tx.tx_type {
            TX_BOND => {
                let draft = check_bond_tx(
                    tx,
                    &self.bonds,
                    &self.params.network_id,
                    self.params.min_bond_sat,
                )?;
                let id = tx.txid();
                // Consume the bond output into the ledger: the value parks in
                // the record, not in the UTXO set. Leaving it in place would
                // double-count — the output plus a later release would exceed
                // issuance, which the supply gate refuses. The bond amount is
                // still declared by the transaction (conservation ran in
                // `check_tx`); only its resting place changes.
                let identity = crate::bond::bond_identity(
                    &self.params.network_id,
                    &draft.bonder,
                    &draft.bls_pk,
                );
                let pos = tx
                    .outputs
                    .iter()
                    .position(|o| o.address == identity)
                    .ok_or(Error::StakeInvalid(
                        "bond needs exactly one bond-identity output",
                    ))?;
                let bond_op = OutPoint {
                    txid: id,
                    index: u32::try_from(pos).map_err(|_| Error::ValueOverflow)?,
                };
                self.utxo
                    .remove(&bond_op)
                    .ok_or(Error::StakeInvalid("bond output missing"))?;
                undo.created.retain(|op| op != &bond_op);
                self.bonds.insert(
                    id,
                    BondRecord {
                        bonder: draft.bonder,
                        bls_pk: draft.bls_pk,
                        mldsa_pk: draft.mldsa_pk,
                        amount_sat: draft.amount_sat,
                        bond_height: height,
                        bond_index: tx_index,
                    },
                );
                stake.ops.push(BondUndoOp::Inserted(id));
            }
            TX_UNBOND => {
                let (id, record) = check_unbond_tx(tx, &self.bonds, height)?;
                self.bonds.remove(&id);
                stake
                    .ops
                    .push(BondUndoOp::Removed(id, Box::new(record.clone())));
                let release = OutPoint {
                    txid: tx.txid(),
                    index: u32::try_from(tx.outputs.len()).map_err(|_| Error::ValueOverflow)?,
                };
                // Overwrite guard (see `UtxoSet::apply_tx`): an unbond release
                // is unique per transaction, so a live output here is a
                // replay, never a coincidence.
                if self.utxo.contains(&release) {
                    return Err(Error::Malformed("unbond release output already exists"));
                }
                self.utxo.insert(
                    release,
                    Utxo {
                        out: Output {
                            value: record.amount_sat,
                            address: record.bonder,
                        },
                        height,
                    },
                );
                undo.created.push(release);
            }
            TX_SLASH => {
                // P0-2: verify each checkpoint against the committee
                // authoritative for its own checkpoint epoch, reconstructed
                // from the seed-height bond snapshot — not the cache, and
                // never the current committee.
                let epoch_blocks = self.params.checkpoint_interval_blocks;
                let set_for_epoch = |epoch| self.historical_epoch_set(epoch);
                let (id, record) = check_slash_tx(
                    tx,
                    &self.bonds,
                    set_for_epoch,
                    &self.params.network_id,
                    height,
                    epoch_blocks,
                    &RealBls,
                )?;
                self.bonds.remove(&id);
                stake
                    .ops
                    .push(BondUndoOp::Removed(id, Box::new(record.clone())));
                if stake.vault_before.is_none() {
                    stake.vault_before = Some(self.slash_vault.clone());
                }
                let burned = self
                    .slash_vault
                    .slash(
                        tx.txid(),
                        record.amount_sat,
                        height,
                        slash_vesting_period(&self.params.network_id),
                        record.bonder,
                    )
                    .burned;
                stake.slash_burned = stake
                    .slash_burned
                    .checked_add(burned)
                    .ok_or(Error::ValueOverflow)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Reverse a block's stake effects: ledger inverses in reverse order, then
    /// the vault's pre-block state. Called on every apply error path alongside
    /// the UTXO unwind, so a refused block leaves bonds and vault exactly as
    /// it found them.
    fn unwind_stake(&mut self, stake: &StakeApply) {
        for op in stake.ops.iter().rev() {
            unwind_bond_op(&mut self.bonds, op);
        }
        if let Some(vault) = &stake.vault_before {
            self.slash_vault = vault.clone();
        }
    }

    /// Validator records for one bond ledger: the committee's TopN members
    /// with network-bound bond identities, BLS keys, lattice keys and stakes.
    /// The single mapping from ledger state to candidate records, shared by
    /// the live committee and historical reconstruction.
    fn records_from_ledger(&self, ledger: &BondLedger) -> Vec<crate::validators::ValidatorRecord> {
        use crate::bond::bond_identity;
        ledger
            .committee()
            .into_iter()
            .map(|r| crate::validators::ValidatorRecord {
                stake_address: bond_identity(&self.params.network_id, &r.bonder, &r.bls_pk),
                bls_pk: r.bls_pk,
                stake_sat: r.amount_sat,
                mldsa_pk: r.mldsa_pk,
            })
            .collect()
    }

    /// The bond ledger state at the seed height for the epoch containing
    /// `height` (P0-1). Returns `None` when no snapshot exists for that seed
    /// height, so callers fail closed instead of substituting live state.
    fn seed_bonds_at(&self, height: u64) -> Option<&BondLedger> {
        let epoch = crate::validators::epoch_of(height, self.params.checkpoint_interval_blocks);
        let seed = crate::validators::seed_height(
            epoch,
            self.params.checkpoint_interval_blocks,
            crate::validators::EPOCH_LOOKBACK_DEFAULT,
        );
        self.bond_snapshots.get(&seed)
    }

    /// Committee candidate records for the epoch containing `height`, derived
    /// from that epoch's seed-height bond snapshot. `None` when the snapshot
    /// is missing — the caller must fail closed, never substitute live bonds.
    fn committee_records_at(&self, height: u64) -> Option<Vec<crate::validators::ValidatorRecord>> {
        self.seed_bonds_at(height)
            .map(|l| self.records_from_ledger(l))
    }

    /// Committee keys for the epoch containing `height`: the seed-height TopN,
    /// or the declared bootstrap committee when the seed state holds no bonds.
    /// `None` when the seed snapshot is missing (fail closed).
    fn committee_keys_at(&self, height: u64) -> Option<Vec<BlsPublicKey>> {
        let ledger = self.seed_bonds_at(height)?;
        let bonded = ledger.committee();
        Some(if bonded.is_empty() {
            self.params.genesis_validators.clone()
        } else {
            bonded.into_iter().map(|r| r.bls_pk).collect()
        })
    }

    /// Reconstruct the exact `EpochSet` for `epoch` from the bond snapshot at
    /// its seed height (P0-1/P0-2). Independent of the one-epoch-grace cache,
    /// so slash evidence stays verifiable while it is within the evidence
    /// window. Missing snapshots, empty seed ledgers and derivation failures
    /// are all reported — never silently replaced with another committee.
    pub fn historical_epoch_set(
        &self,
        epoch: u64,
    ) -> std::result::Result<crate::validators::EpochSet, crate::validators::ValidatorError> {
        use crate::validators::ValidatorError;
        let seed = crate::validators::seed_height(
            epoch,
            self.params.checkpoint_interval_blocks,
            crate::validators::EPOCH_LOOKBACK_DEFAULT,
        );
        let snapshot = self
            .bond_snapshots
            .get(&seed)
            .ok_or(ValidatorError::NoCandidates { epoch })?;
        let records = self.records_from_ledger(snapshot);
        // Empty seed ledger means the bootstrap committee was authoritative
        // at that height — the same fallback `committee_keys_at` and
        // `settlement_committee_at` apply. Returning `NoCandidates` here
        // made genesis-era slash evidence unverifiable exactly when no
        // bonds existed, while every other committee accessor agreed on
        // the bootstrap keys.
        if records.is_empty() {
            return crate::validators::genesis_epoch_set_at(epoch, &self.params.genesis_validators);
        }
        crate::validators::derive_set(
            epoch,
            &records,
            crate::validators::SelectionRule::TopN,
            crate::bond::MAX_COMMITTEE_SIZE,
        )
    }

    /// Active checkpoint committee (Decision 20 item 2): the 21
    /// highest-staked bonds, per [`BondLedger::committee`] — the one
    /// definition shared with slashing and with the epoch set. An empty ledger
    /// falls back to the profile's declared bootstrap committee: 21 public
    /// deterministic keys on mainnet (Decision 27), four test keys on mini and
    /// testnet. The first bond replaces the bootstrap set under the existing
    /// TopN rule.
    ///
    /// The committee is derived from seed-height bond state (P0-1), so it is
    /// stable for the current epoch and does not rotate mid-epoch when later
    /// blocks add or remove bonds.
    pub fn committee_keys(&self) -> Vec<BlsPublicKey> {
        // The tip always has its seed snapshot once the chain advances past
        // genesis (snapshots are taken at every seed height); fall back to the
        // live ledger only for a chain that has never snapshotted.
        let height = self.height();
        self.committee_keys_at(height).unwrap_or_else(|| {
            let bonded = self.bonds.committee();
            if bonded.is_empty() {
                self.params.genesis_validators.clone()
            } else {
                bonded.into_iter().map(|r| r.bls_pk).collect()
            }
        })
    }

    /// The L2 settlement authority at `height`: the live L1 validator
    /// committee, as a [`ValidatorSet`](crate::bls_checkpoint::ValidatorSet).
    /// Seed-derived records (lattice keys ride along, so bonded members keep
    /// the sidecar rule), with the same live-ledger fallback as
    /// [`Chain::committee_keys`] for a chain that has never snapshotted, and
    /// the profile's bootstrap keys when no bonds exist.
    ///
    /// This is what L2 `Settle` verification resolves per block height
    /// (Decision 28): pre-bond it names the bootstrap committee that also
    /// secures L1; the first bond rotates it to the bonded TopN under the
    /// existing rule, so bootstrap keys lose L2 authority exactly when they
    /// lose L1 authority — never a permanent bootstrap settlement set, never
    /// an empty fail-closed one. Resolving per height (not per tip) keeps
    /// replay deterministic across rotations: a pre-bond settle verifies
    /// against the pre-bond committee on every replay, whenever it runs.
    pub fn settlement_committee_at(&self, height: u64) -> crate::bls_checkpoint::ValidatorSet {
        let records = match self.committee_records_at(height) {
            Some(records) => records,
            None => self.records_from_ledger(&self.bonds),
        };
        if records.is_empty() {
            crate::bls_checkpoint::ValidatorSet::new(self.params.genesis_validators.clone())
        } else {
            crate::bls_checkpoint::ValidatorSet::from_records(&records)
        }
    }

    /// The same membership as [`Chain::committee_keys`], as full records: each
    /// member's registered lattice key rides along, so the signing loop can
    /// produce dual-signed certificates. Genesis fallback members carry no
    /// lattice key, exactly like the genesis epoch set the verifier derives.
    pub fn committee_signing_records(&self) -> Vec<crate::validators::ValidatorRecord> {
        use crate::bond::bond_identity;
        let height = self.height();
        // Seed-derived membership, with the same live-ledger fallback as
        // `committee_keys` for a chain that has never snapshotted.
        let bonded = match self.seed_bonds_at(height) {
            Some(ledger) => ledger.committee(),
            None => self.bonds.committee(),
        };
        if bonded.is_empty() {
            self.params
                .genesis_validators
                .iter()
                .map(|k| crate::validators::ValidatorRecord {
                    stake_address: crate::hash::Address::default(),
                    bls_pk: *k,
                    stake_sat: 0,
                    mldsa_pk: None,
                })
                .collect()
        } else {
            bonded
                .into_iter()
                .map(|r| crate::validators::ValidatorRecord {
                    stake_address: bond_identity(&self.params.network_id, &r.bonder, &r.bls_pk),
                    bls_pk: r.bls_pk,
                    stake_sat: r.amount_sat,
                    mldsa_pk: r.mldsa_pk,
                })
                .collect()
        }
    }

    /// Stake-backed validator records for the current epoch's committee
    /// derivation (Item 5). One `ValidatorRecord` per committee member: the
    /// bond's identity address (network-bound, so a mainnet bond cannot
    /// masquerade as a mini bond), its BLS key, its registered lattice key if
    /// any, and its locked value as `stake_sat`.
    ///
    /// The members come from seed-height bond state (P0-1): the seed snapshot
    /// for the current epoch, then [`BondLedger::committee`] — the same 21
    /// signing/slashing already uses — so `derive_set`'s TopN pass over this
    /// list re-selects exactly those 21 and the epoch set cannot drift from
    /// the set that signed.
    pub fn committee_records(&self) -> Vec<crate::validators::ValidatorRecord> {
        let height = self.height();
        match self.committee_records_at(height) {
            Some(records) => records,
            None => self.records_from_ledger(&self.bonds),
        }
    }

    /// Rebuild the finality cache for a rewound tip (reorg across an epoch
    /// boundary). Forward application inserts epochs in increasing order, but
    /// a rollback can move the tip to an earlier epoch, which a plain
    /// `refresh_committee` insert cannot represent (its out-of-order branch
    /// would leave a newer previous set beside an older current set). Clearing
    /// and re-inserting previous-then-current from the restored seed snapshots
    /// reproduces exactly what forward application to this tip would hold —
    /// including clearing when the seed state holds no bonds.
    fn rebuild_finality_at(
        &mut self,
        tip_height: u64,
    ) -> std::result::Result<(), crate::validators::ValidatorError> {
        let epoch_blocks = self.params.checkpoint_interval_blocks;
        let lookback = crate::validators::EPOCH_LOOKBACK_DEFAULT;
        self.finality.clear_sets();
        let epoch = crate::validators::epoch_of(tip_height, epoch_blocks);
        if epoch > 0 {
            let prev = epoch - 1;
            if let Some(records) = self.committee_records_at(
                prev.saturating_mul(epoch_blocks)
                    .saturating_add(epoch_blocks.saturating_sub(1)),
            ) {
                if !records.is_empty() {
                    // Any height inside the previous epoch labels the insert.
                    let prev_height = prev
                        .saturating_mul(epoch_blocks)
                        .saturating_add(epoch_blocks.saturating_sub(1));
                    self.finality.refresh_committee(
                        &records,
                        prev_height,
                        epoch_blocks,
                        lookback,
                    )?;
                }
            }
        }
        match self.committee_records_at(tip_height) {
            Some(records) => {
                self.finality
                    .refresh_committee(&records, tip_height, epoch_blocks, lookback)?;
            }
            None => {
                self.finality.clear_sets();
            }
        }
        self.finality.rewind_observation(tip_height);
        Ok(())
    }

    /// Current epoch on this branch, for committee derivation.
    pub fn epoch_of(&self) -> u64 {
        crate::validators::epoch_of(self.height(), self.params.checkpoint_interval_blocks)
    }

    /// Read-only access to the bond ledger (mempool admission, views).
    pub fn bonds(&self) -> &BondLedger {
        &self.bonds
    }

    /// Read-only access to the M2 slash vault (views, tests).
    pub fn slash_vault(&self) -> &SlashVault {
        &self.slash_vault
    }

    /// Validate one exit claim against current state (approved P1, E-1…E-3).
    ///
    /// Pure validation: resolves sink inputs against `utxo`, checks the exit
    /// proof against the root the queue block committed, maturity under the
    /// stronger Decision-15 rule, idempotency against the released set, and
    /// exact funding (`inputs == amount + exit_fee + required L1 fee` — no
    /// change output, no tip). Returns the gas and the L1 fee for the caller
    /// to fold into the block totals. Every refusal names its reason, exactly
    /// like `check_tx`: a claim that fails must say which rule failed.
    /// Whether exit claims and committed L2 roots are live at `height` on this
    /// profile (approved P1). `exit_activation_height == 0` means *never*, not
    /// *from genesis*: a profile that has not chosen a height must not accept
    /// the encoding rules early.
    pub fn exit_active_at(&self, height: u64) -> bool {
        let activation = self.params.exit_activation_height;
        activation != 0 && height >= activation
    }

    fn check_claim(
        &self,
        utxo: &UtxoSet,
        claim: &ExitClaim,
        height: u64,
        base_fee: u64,
    ) -> Result<(u64, u64)> {
        let activation = self.params.exit_activation_height;
        if !self.exit_active_at(height) {
            return Err(Error::Malformed("exit claim before activation"));
        }
        if claim.queued_height < activation {
            return Err(Error::Malformed("exit queued before activation"));
        }
        if claim.queued_height >= height {
            return Err(Error::Malformed("exit queue height not yet final"));
        }
        // Maturity: depth *and* the binding checkpoint once binding finality
        // is active (Decision 15) — exits are never less safe than deposits,
        // and `binding == 0` keeps depth-only finality where it never
        // activated. `height - 1` is the tip this block extends. Large exits
        // wait the profile's extra delay on top — the same number the L2
        // queue side enforces, so neither half releases early.
        let depth = if self.params.large_exit_threshold_sat > 0
            && claim.amount_sat >= self.params.large_exit_threshold_sat
        {
            self.params
                .finality_depth
                .saturating_add(self.params.large_exit_extra_delay_blocks)
        } else {
            self.params.finality_depth
        };
        let mature_at = claim.queued_height.saturating_add(depth);
        if height.saturating_sub(1) < mature_at {
            return Err(Error::Malformed("exit not yet mature"));
        }
        let binding = self.finality().binding_finalized_height();
        if binding != 0 && claim.queued_height > binding {
            return Err(Error::Malformed("exit queue block not binding-final"));
        }
        // Idempotency by exit identity: one release per `(owner, nonce)`,
        // ever, refused by consensus rather than by bookkeeping.
        if self.released_exits.contains(&(claim.owner, claim.nonce)) {
            return Err(Error::Malformed("exit already released"));
        }
        // A zero-amount claim would create an unspendable index-0 output
        // (`check_tx` refuses to spend zero-value outputs): state bloat with
        // no holder. Refused like any other zero-value output.
        if claim.amount_sat == 0 {
            return Err(Error::Malformed("exit claim amount must be nonzero"));
        }
        // The anchor: the queue block's committed root must exist and the
        // record proof must verify against it. A queue in a block that
        // committed no root cannot be proven — which is why post-activation
        // L2 sections must carry one.
        let root = self
            .block_at(claim.queued_height)
            .and_then(|b| b.l2_state_root)
            .ok_or(Error::Malformed("no committed root at queue height"))?;
        if !claim.verify_proof(&root) {
            return Err(Error::Malformed("exit proof does not verify"));
        }
        // Sink inputs: real UTXOs, all sink outputs, no duplicates (a doubled
        // outpoint would resolve twice and count its value twice), totalling
        // exactly principal + prepaid fee + the required L1 fee.
        let mut seen: Vec<OutPoint> = claim.inputs.clone();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        if seen.len() != before {
            return Err(Error::Malformed("exit claim repeats an input"));
        }
        let sink = self.params.l2_deposit_sink();
        let mut value_in = 0u64;
        for op in &claim.inputs {
            let u = utxo.get(op).ok_or(Error::UnknownOutPoint)?;
            if u.out.address != sink {
                return Err(Error::Malformed("exit claim input is not a sink output"));
            }
            value_in = value_in
                .checked_add(u.out.value)
                .ok_or(Error::ValueOverflow)?;
        }
        let gas = claim.gas_used();
        let l1_fee = required_fee(base_fee, gas);
        let want = claim
            .amount_sat
            .checked_add(claim.exit_fee_sat)
            .and_then(|v| v.checked_add(l1_fee))
            .ok_or(Error::ValueOverflow)?;
        if value_in != want {
            return Err(Error::Malformed(
                "exit claim inputs must total exactly amount + fee + l1 fee",
            ));
        }
        // Overwrite guard, after the input checks (see `UtxoSet::apply_tx`):
        // release outputs are keyed by claim id, and a blind insert would
        // destroy live coins. Ordered last so a double-spend reports the
        // missing inputs (`UnknownOutPoint`), while a genuine id collision
        // with live inputs reports the collision.
        if utxo.contains(&OutPoint {
            txid: claim.claim_id(),
            index: 0,
        }) {
            return Err(Error::Malformed("exit release output already exists"));
        }
        Ok((gas, l1_fee))
    }

    /// Apply every exit claim of `block`, accumulating gas, fees and undo
    /// data. Claims settle before the body so a body transaction may spend a
    /// release output in the same block; the order is deterministic either
    /// way, and claims-first is what lets a crank's release be immediately
    /// usable. Caller unwinds UTXO writes with `applied` and identity marks
    /// with the returned list on error — a block that fails partway must
    /// leave the ledger *and* the released set exactly as it found them.
    ///
    /// Atomic within itself: a claim that fails unwinds the claims this call
    /// already applied, so the caller never sees a half-applied claim list.
    #[allow(clippy::too_many_arguments)]
    fn apply_exit_claims(
        &mut self,
        block: &Block,
        height: u64,
        applied: &mut Vec<Undo>,
        body_undo: &mut Undo,
        total_gas: &mut u64,
        total_fees: &mut u64,
    ) -> Result<Vec<(Address, u64)>> {
        let mut marked = Vec::with_capacity(block.exit_claims.len());
        // Local undo tail so a failing claim unwinds exactly what this call
        // wrote (the caller's `applied` only ever grows, never shrinks).
        let applied_base = applied.len();
        let spent_base = body_undo.spent.len();
        let created_base = body_undo.created.len();
        for claim in &block.exit_claims {
            if let Err(e) = self.apply_one_claim(
                claim,
                block,
                height,
                applied,
                body_undo,
                total_gas,
                total_fees,
                &mut marked,
            ) {
                for u in applied[applied_base..].iter().rev() {
                    self.utxo.undo(u);
                }
                applied.truncate(applied_base);
                body_undo.spent.truncate(spent_base);
                body_undo.created.truncate(created_base);
                self.unwind_claims(&marked);
                return Err(e);
            }
        }
        Ok(marked)
    }

    /// Validate and apply a single exit claim. See [`Self::apply_exit_claims`]
    /// for the ordering and unwinding discipline.
    #[allow(clippy::too_many_arguments)]
    fn apply_one_claim(
        &mut self,
        claim: &ExitClaim,
        block: &Block,
        height: u64,
        applied: &mut Vec<Undo>,
        body_undo: &mut Undo,
        total_gas: &mut u64,
        total_fees: &mut u64,
        marked: &mut Vec<(Address, u64)>,
    ) -> Result<()> {
        let (gas, l1_fee) =
            self.check_claim(&self.utxo, claim, height, block.header.base_fee_sat)?;
        // Resolve first, mutate second (the `apply_tx` atomicity rule):
        // every input must exist before any of them is removed. The pairs
        // below are the undo record; the mutation itself goes through the
        // shared helper so the live path and the miner probe agree.
        let mut spent = Vec::with_capacity(claim.inputs.len());
        for op in &claim.inputs {
            let u = self.utxo.get(op).ok_or(Error::UnknownOutPoint)?.clone();
            spent.push((*op, u));
        }
        Self::apply_claim_utxo(&mut self.utxo, claim, height);
        let id = claim.claim_id();
        let mut created = Vec::with_capacity(2);
        created.push(OutPoint { txid: id, index: 0 });
        if claim.exit_fee_sat > 0 {
            created.push(OutPoint { txid: id, index: 1 });
        }
        let undo = Undo { spent, created };
        applied.push(undo.clone());
        body_undo.spent.extend(undo.spent);
        body_undo.created.extend(undo.created);
        self.released_exits.insert((claim.owner, claim.nonce));
        marked.push((claim.owner, claim.nonce));
        *total_gas = total_gas.checked_add(gas).ok_or(Error::ValueOverflow)?;
        // The L1 fee rides the totals like any transaction fee; the split
        // burns half and PSCBs half, and there is no tip on a claim
        // (exact funding was checked above).
        *total_fees = total_fees.checked_add(l1_fee).ok_or(Error::ValueOverflow)?;
        Ok(())
    }

    /// Unmark exit identities a failed block had claimed. UTXO writes unwind
    /// through `applied`; this unwinds the consensus identity set, so a
    /// rejected block changes neither.
    fn unwind_claims(&mut self, marked: &[(Address, u64)]) {
        for id in marked {
            self.released_exits.remove(id);
        }
    }

    /// Whether an exit identity is already released (approved P1). The miner
    /// crank reads this to skip spent exits; consensus writes it.
    pub fn exit_released(&self, owner: &Address, nonce: u64) -> bool {
        self.released_exits.contains(&(*owner, nonce))
    }

    /// Apply a *checked* claim's UTXO effects to an arbitrary set.
    ///
    /// The caller validated everything first (miner probe in `build_block`,
    /// live set in [`Chain::apply_one_claim`]); this only moves value, so
    /// mining and applying cannot disagree about what a claim does to the
    /// ledger. Outputs are keyed by claim id, exactly as a transaction's are
    /// keyed by txid.
    fn apply_claim_utxo(utxo: &mut UtxoSet, claim: &ExitClaim, height: u64) {
        for op in &claim.inputs {
            let _ = utxo.remove(op);
        }
        let id = claim.claim_id();
        utxo.insert(
            OutPoint { txid: id, index: 0 },
            Utxo {
                out: crate::tx::Output {
                    value: claim.amount_sat,
                    address: claim.destination,
                },
                height,
            },
        );
        // A zero prepaid fee creates no output (see `apply_one_claim`).
        if claim.exit_fee_sat > 0 {
            utxo.insert(
                OutPoint { txid: id, index: 1 },
                Utxo {
                    out: crate::tx::Output {
                        value: claim.exit_fee_sat,
                        address: claim.claimant,
                    },
                    height,
                },
            );
        }
    }

    fn rollback_block(&mut self, hash: &Hash512) -> std::result::Result<(), Error> {
        let Some(block) = self.blocks.get(hash).cloned() else {
            return Ok(());
        };
        if let Some(undo) = self.undo.get(hash).cloned() {
            // Undo the whole record once: it covers body transactions AND
            // exit claims, which share the record but have no body transaction
            // to loop over. Looping per body transaction never ran for a
            // body-empty claim block, so its writes survived the rollback —
            // found by the exit reorg test, fixed by undoing unconditionally.
            self.utxo.undo(&undo);
            // Identify the coinbase output directly rather than by its position
            // at the end of `undo.created`: a zero-value coinbase is never
            // recorded there, so position was not a reliable handle.
            if let Some(cb) = block.txs.first() {
                self.utxo.drop_created(&[OutPoint {
                    txid: cb.txid(),
                    index: 0,
                }]);
            }
        }
        self.undo.remove(hash);
        // Undo the PSCB credit for this block (M1 reorg correctness).
        // Checked pairing with the checked credit above: the reserve can
        // never hold less than a canonical block credited, so an underflow
        // here means state corruption, not an edge to clamp through.
        if let Some(delta) = self.pscb_undo.remove(hash) {
            self.pscb_reserve = self
                .pscb_reserve
                .checked_sub(delta)
                .ok_or(Error::ValueOverflow)?;
        }
        if let Some(delta) = self.bsaver_undo.remove(hash) {
            self.bsaver_reserve = self
                .bsaver_reserve
                .checked_sub(delta)
                .ok_or(Error::ValueOverflow)?;
        }
        // Treat unwinds by saturation, not by checked subtraction like the
        // PSCB/B-Saver/burn legs above: redemptions debit `treat_reserve`
        // live through `spend_treat_reserve`, so the reserve can hold less
        // than this block credited. Subtracting the credit back then lands
        // exactly on `pre_block_reserve - redemptions_since`, floored at
        // zero — the credit is gone, the redemption stands, and the reserve
        // is empty rather than negative. Refusing here (`Err`) would reject
        // a valid heavier branch on redeemed nodes while clean nodes adopt
        // it: a consensus split over bookkeeping. The voucher liability
        // stands in the Treats book either way.
        if let Some(delta) = self.treat_undo.remove(hash) {
            self.treat_reserve = self.treat_reserve.saturating_sub(delta);
        }
        // Undo the burn debit the same way, or a reorg would leave phantom
        // removal behind and net-supply reporting would drift from replay.
        if let Some(delta) = self.burned_undo.remove(hash) {
            self.burned_fees_total = self
                .burned_fees_total
                .checked_sub(delta)
                .ok_or(Error::ValueOverflow)?;
        }
        // Unmark this block's releases (approved P1 reorg correctness): a
        // rolled-back release never happened, so its identity is spendable
        // again on the winning branch — and a release the winner keeps is
        // re-marked when the winner applies.
        if let Some(ids) = self.exit_undo.remove(hash) {
            self.unwind_claims(&ids);
        }
        // Rewind this block's bond effects (Decision 20 reorg correctness): a
        // rolled-back bond never bonded, so its key leaves the committee — and
        // an unbond/slash the winner keeps is re-applied when the winner
        // applies. The vault returns to its pre-block state for the same
        // reason the PSCB delta is subtracted above.
        if let Some(ops) = self.bond_undo.remove(hash) {
            for op in ops.iter().rev() {
                unwind_bond_op(&mut self.bonds, op);
            }
        }
        if let Some(vault) = self.slash_undo.remove(hash) {
            self.slash_vault = vault;
        }
        // A rolled-back seed block removes its snapshot so the epochs it
        // seeded are re-derived from the restored seed-height state. `canon`
        // is truncated by the caller afterwards; rebuild the finality cache
        // for the rewound tip explicitly, since a rollback can move the tip
        // to an earlier epoch, which incremental insertion cannot represent.
        let rolled_height = block.header.height;
        if crate::validators::is_seed_height(
            rolled_height,
            self.params.checkpoint_interval_blocks,
            crate::validators::EPOCH_LOOKBACK_DEFAULT,
        ) {
            self.bond_snapshots.remove(&rolled_height);
        }
        let tip_height = rolled_height.saturating_sub(1);
        if let Some(keys) = self.committee_keys_at(tip_height) {
            self.finality.set_keys(keys);
        }
        self.rebuild_finality_at(tip_height)
            .map_err(|_| Error::StakeInvalid("committee derivation failed"))?;
        Ok(())
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            canon: self.canon.clone(),
            utxo: self.utxo.clone(),
            undo: self.undo.clone(),
            pscb_reserve: self.pscb_reserve,
            pscb_undo: self.pscb_undo.clone(),
            bsaver_reserve: self.bsaver_reserve,
            bsaver_undo: self.bsaver_undo.clone(),
            treat_reserve: self.treat_reserve,
            treat_undo: self.treat_undo.clone(),
            burned_fees_total: self.burned_fees_total,
            burned_undo: self.burned_undo.clone(),
            released_exits: self.released_exits.clone(),
            exit_undo: self.exit_undo.clone(),
            bonds: self.bonds.clone(),
            bond_undo: self.bond_undo.clone(),
            bond_snapshots: self.bond_snapshots.clone(),
            slash_vault: self.slash_vault.clone(),
            slash_undo: self.slash_undo.clone(),
            latest_vwc_hash: self.latest_vwc_hash,
            finality: self.finality.clone(),
        }
    }

    fn restore(&mut self, s: Snapshot) {
        self.canon = s.canon;
        self.utxo = s.utxo;
        self.undo = s.undo;
        self.pscb_reserve = s.pscb_reserve;
        self.pscb_undo = s.pscb_undo;
        self.bsaver_reserve = s.bsaver_reserve;
        self.bsaver_undo = s.bsaver_undo;
        self.treat_reserve = s.treat_reserve;
        self.treat_undo = s.treat_undo;
        self.burned_fees_total = s.burned_fees_total;
        self.burned_undo = s.burned_undo;
        self.released_exits = s.released_exits;
        self.exit_undo = s.exit_undo;
        self.bonds = s.bonds;
        self.bond_undo = s.bond_undo;
        self.bond_snapshots = s.bond_snapshots;
        self.slash_vault = s.slash_vault;
        self.slash_undo = s.slash_undo;
        self.latest_vwc_hash = s.latest_vwc_hash;
        self.finality = s.finality;
    }

    fn path_to(&self, target: &Hash512) -> Option<Vec<Hash512>> {
        let mut path = Vec::new();
        let mut cursor = *target;
        loop {
            let block = self.blocks.get(&cursor)?;
            path.push(cursor);
            if block.header.height == 0 {
                path.reverse();
                return Some(path);
            }
            cursor = block.header.prev_hash;
        }
    }

    /// Pick the tip: most work, then lower height, then lowest block hash.
    ///
    /// Every tie-break is a function of block data alone. An earlier version
    /// used an arrival counter as the final tie-break, which made the result
    /// depend on the order blocks happened to be delivered — two nodes holding
    /// an identical set of valid blocks could and did choose different tips,
    /// which is a consensus split rather than a rounding difference.
    fn best_candidate(&self) -> Hash512 {
        let tip = self.tip_hash();
        let mut best = tip;
        let mut best_key = self.fork_choice_key(&tip);

        let mut candidates: Vec<(&Hash512, &Block)> = self.blocks.iter().collect();
        candidates.sort_by(|a, b| a.0.cmp(b.0)); // deterministic iteration
        for (hash, block) in candidates {
            let key = self.fork_choice_key(hash);
            debug_assert_eq!(key.1, std::cmp::Reverse(block.header.height));
            if key > best_key {
                best_key = key;
                best = *hash;
            }
        }
        best
    }

    /// Total ordering for fork choice: `(work, lower height first, lowest hash
    /// first)`. Derived only from the block graph, never from arrival order.
    fn fork_choice_key(
        &self,
        hash: &Hash512,
    ) -> (u128, std::cmp::Reverse<u64>, std::cmp::Reverse<Hash512>) {
        let work = self.cumulative_work(hash);
        let height = self.blocks.get(hash).map(|b| b.header.height).unwrap_or(0);
        (work, std::cmp::Reverse(height), std::cmp::Reverse(*hash))
    }

    /// Accept a block: store it, then re-run fork choice. Extends the tip or
    /// triggers a reorganization.
    pub fn submit(&mut self, block: Block) -> Result<()> {
        self.submit_at(block, None)
    }

    /// `now_ms` enables the non-consensus local-clock sanity check. Pass `None`
    /// when replaying historical blocks, where "now" is meaningless.
    pub fn submit_at(&mut self, block: Block, now_ms: Option<u64>) -> Result<()> {
        let hash = block.block_hash();
        if self.blocks.contains_key(&hash) {
            return Err(Error::AlreadyKnown);
        }
        if let Some(now) = now_ms {
            validate_local_clock(block.header.timestamp_ms, now, &self.params)?;
        }
        // Cheap refusals before any proof-of-work is verified. The parent must
        // be known, and the declared difficulty must be exactly what the
        // retarget rule produces from that parent's branch — the same rule
        // `apply_block` enforces, hoisted ahead of `pow_satisfies`. A header
        // claiming difficulty 1 has a trivially satisfiable target but still
        // costs the verifier a full proof check (an 8 MiB HBM scratchpad in
        // production), so checking difficulty after the proof would let anyone
        // burn the node's CPU for free, repeatedly, with a "valid" side block.
        if !self.blocks.contains_key(&block.header.prev_hash) {
            return Err(Error::UnknownParent);
        }
        let expected_diff = self.expected_difficulty_at(&block.header.prev_hash)?;
        if block.header.difficulty != expected_diff {
            return Err(Error::BadDifficulty {
                expected: expected_diff,
                got: block.header.difficulty,
            });
        }
        self.validate_standalone(&block)?;

        // Validate that the parent exists before recording work against it.
        let parent_work = self.cumulative_work(&block.header.prev_hash);
        let block_difficulty = block.header.difficulty; // before `block` is moved
        self.blocks.insert(hash, block);
        // Work is parent_work + this block's difficulty, computed once. Fork
        // choice reads it as an O(1) lookup instead of walking to genesis.
        self.work
            .insert(hash, parent_work.saturating_add(block_difficulty));

        let outcome = self.reselect(hash);
        if let Err(e) = &outcome {
            // A block that cannot be applied must not stay in the store.
            // `cumulative_work` sums the declared difficulty of every stored
            // block, so retaining an unusable one lets an attacker accumulate
            // chain weight that no reorganization can ever realize: fork choice
            // keeps selecting the dead branch and every honest block is
            // rejected until honest work catches up.
            //
            // A finality refusal is not that case: the block is valid, we
            // simply decline to reorganize to it, and dropping it would orphan
            // every later block already stacked on top of it.
            if !matches!(e, Error::ReorgWouldCrossFinality { .. }) {
                self.blocks.remove(&hash);
                self.work.remove(&hash);
            }
        }
        // Side branches outside the finality window are useless to us and
        // unbounded in supply (SPEC.md §13.10 item 2). Prune on a threshold so
        // the cost is amortised rather than paid per block.
        if self.blocks.len() > self.prune_threshold() {
            self.prune_side_branches();
        }
        outcome
    }

    /// Run fork choice over the stored blocks and apply whatever wins.
    fn reselect(&mut self, submitted: Hash512) -> Result<()> {
        // Nothing is cleared here, and that is deliberate. Transactions
        // disconnected by an earlier reorg are still disconnected, and they stay
        // pending until the caller drains them — a reorg landing before the
        // caller gets a chance to reconcile must not wipe them. An earlier
        // version cleared this set on entry, so two reorgs in quick succession
        // (exactly what a syncing node sees) silently destroyed the first
        // reorg's transactions. Published sets are only ever *added* to, and only
        // after the reorg has committed.
        let target = self.best_candidate();
        if target != self.tip_hash() {
            return self.adopt(target);
        }
        let Some(b) = self.blocks.get(&submitted).cloned() else {
            return Ok(());
        };
        if b.header.prev_hash != self.tip_hash() {
            // A side block that lost fork choice: stored, not canonical.
            return Ok(());
        }
        // Extends the tip and nothing out-worked it. `apply_block` unwinds its
        // own writes on failure, so no snapshot is needed here.
        self.apply_block(&b)?;
        self.canon.push(submitted);
        Ok(())
    }

    fn adopt(&mut self, target: Hash512) -> Result<()> {
        let new_canon = self.path_to(&target).ok_or(Error::UnknownParent)?;
        let saved = self.snapshot();

        let mut common = 0usize;
        while common < new_canon.len()
            && common < self.canon.len()
            && new_canon[common] == self.canon[common]
        {
            common += 1;
        }

        // A reorg must never rewrite finalized history. The check is on the
        // fork point alone: it used to be qualified with
        // `self.canon.len() > new_canon.len()`, which meant a rival that forked
        // below the finality point but ended up *longer* was adopted and
        // rewrote settled history.
        let finalized = self.finalized_height() as usize;
        if common <= finalized {
            self.restore(saved);
            return Err(Error::ReorgWouldCrossFinality {
                finalized_height: finalized as u64,
            });
        }

        // Collect what the reorg takes off the chain, oldest block first, so the
        // mempool can re-admit it. Recorded locally and published only once the
        // rival branch has applied cleanly — see `disconnected_txs`.
        let mut disconnected: Vec<Transaction> = Vec::new();
        for i in common..self.canon.len() {
            if let Some(block) = self.blocks.get(&self.canon[i]) {
                disconnected.extend(block.txs.iter().skip(1).cloned());
            }
        }

        for i in (common..self.canon.len()).rev() {
            let hash = self.canon[i];
            if let Err(e) = self.rollback_block(&hash) {
                self.restore(saved);
                return Err(e);
            }
        }
        self.canon.truncate(common);

        for hash in new_canon.iter().skip(common) {
            let Some(block) = self.blocks.get(hash).cloned() else {
                self.restore(saved);
                return Err(Error::UnknownParent);
            };
            if let Err(e) = self.apply_block(&block) {
                self.restore(saved);
                return Err(e);
            }
            self.canon.push(*hash);
        }
        // The rival branch applied cleanly, so the reorg actually happened and
        // those transactions are now genuinely unconfirmed. Extend rather than
        // assign: an earlier reorg's transactions may not have been drained yet,
        // and they are still unconfirmed.
        self.disconnected_txs.extend(disconnected);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Mining
    // -----------------------------------------------------------------

    /// Unsolved block template for external miners (mining-stack seam).
    ///
    /// Returns the block `build_block` would mine with `nonce = 0` and a zero
    /// `extra_nonce`: coinbase, merkle root, difficulty, base fee, timestamp,
    /// `epoch_id` and `puzzle_id` are all fixed, so the header is fully
    /// determined except for the two proof fields. An external miner grinds
    /// `nonce` (u64) and `extra_nonce` ([u8; 16]) — both already commit into
    /// `stage1_seed` via the serialized header — until `pow_satisfies` holds,
    /// then hands the solved block to `submit`, which re-validates everything
    /// including the proof. The template itself is *not* submittable at real
    /// difficulty (its proof is almost surely invalid); that is expected.
    ///
    /// `difficulty_override` is the test/benchmark seam (same meaning as in
    /// `mine_block_with`); production callers pass `None`.
    pub fn build_template_with(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        now_ms: u64,
        difficulty_override: Option<u128>,
    ) -> Result<Block> {
        // Filter here, at the external-miner boundary — not in the shared
        // inner: the probe must see the same body `apply_block` will, or the
        // template's coinbase mismatches what the chain accepts. `mine_block`
        // keeps the old loud behavior (an invalid stake tx in an explicit
        // body fails at submit, which is what the bond tests pin), and the
        // internal pool miner filters in `mine_from_pool_with_l2`.
        let body = self.filter_stake_body(body);
        self.build_template_inner(
            miner_address,
            body,
            Vec::new(),
            Vec::new(),
            None,
            now_ms,
            difficulty_override,
        )
    }

    // Nine parameters: body, L2 trailer, claims and root are independent
    // caller-supplied lists, like `apply_body`'s accumulators. Bundling them
    // would trade one lint for a struct every caller constructs.
    #[allow(clippy::too_many_arguments)]
    fn build_template_inner(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        l2_txs: Vec<crate::l2::L2Transaction>,
        exit_claims: Vec<ExitClaim>,
        l2_root: Option<Hash>,
        now_ms: u64,
        difficulty_override: Option<u128>,
    ) -> Result<Block> {
        let parent = self.tip().clone();
        let parent_hash = parent.block_hash();
        let height = parent.header.height + 1;

        let history = self.history(self.params.difficulty_window as usize + 1);
        let difficulty = difficulty_override
            .unwrap_or_else(|| next_difficulty(&self.params, parent.header.difficulty, &history));
        let base_fee = if height == 1 {
            self.params.base_fee_initial_sat
        } else {
            // Claims are ordinary block space, so their gas feeds the next
            // block's base fee exactly like body gas (approved P1).
            let parent_gas = parent
                .total_gas_used()?
                .checked_add(parent.claims_gas_used()?);
            let parent_gas = match parent_gas {
                Some(g) => g,
                None => return Err(Error::ValueOverflow),
            };
            next_base_fee(&self.params, parent.header.base_fee_sat, parent_gas)
        };
        // Capped at both ends: the consensus floor is the median of the
        // previous timestamps, and the node-policy ceiling is now plus the
        // future allowance — the same bound `submit_at` enforces, so a
        // template built here is submittable by construction.
        let median = crate::difficulty::median_previous_timestamp(&history).unwrap_or(0);
        let ceiling = now_ms.saturating_add(self.params.future_limit_ms());
        if ceiling < median {
            // The local clock lags the chain: any timestamp this node could
            // put in a block is either older than consensus allows or newer
            // than its own policy allows. Refuse the template instead of
            // grinding on an unsubmittable block.
            return Err(Error::TimestampTooFuture {
                limit: ceiling,
                got: median,
            });
        }
        let timestamp_ms = now_ms.max(median).min(ceiling);

        // Fee split needs a UTXO view with the body applied. Do it on a copy.
        // Claims settle first (approved P1), so they are checked and applied
        // on the probe before the body: a body transaction may spend a release
        // output, and claim gas/fees fold into the same totals. A claim the
        // chain would refuse fails the miner here instead — with the same
        // named error `submit` would return.
        let mut probe = self.utxo.clone();
        let mut total_gas = 0u64;
        let mut total_fees = 0u64;
        for claim in &exit_claims {
            let (gas, l1_fee) = self.check_claim(&probe, claim, height, base_fee)?;
            Self::apply_claim_utxo(&mut probe, claim, height);
            total_gas = total_gas.checked_add(gas).ok_or(Error::ValueOverflow)?;
            total_fees = total_fees.checked_add(l1_fee).ok_or(Error::ValueOverflow)?;
        }
        for tx in &body {
            let delta = check_tx(
                &probe,
                tx,
                height,
                &self.params,
                base_fee,
                self.params.coinbase_maturity,
            )?;
            probe.apply_tx(tx, height)?;
            total_gas = total_gas
                .checked_add(delta.gas_used)
                .ok_or(Error::ValueOverflow)?;
            total_fees = total_fees
                .checked_add(delta.fee_total)
                .ok_or(Error::ValueOverflow)?;
        }
        let split = split_fees(total_gas, total_fees, base_fee)?;
        let reward = block_reward_sat(&self.params, height);

        let claim = reward.saturating_add(split.tip);
        let cb_tx = Transaction::coinbase(
            parent_hash,
            height,
            Output {
                value: claim,
                address: miner_address,
            },
        );

        let mut txs = vec![cb_tx];
        txs.extend(body);
        let merkle =
            crate::block::merkle_root_with_l2(&txs, &l2_txs, l2_root.as_ref(), &exit_claims);

        let header = Header {
            version: crate::block::BLOCK_VERSION,
            height,
            prev_hash: parent_hash,
            merkle_root: merkle,
            timestamp_ms,
            base_fee_sat: base_fee,
            difficulty,
            nonce: 0,
            puzzle_id: self.params.puzzle_id,
            epoch_id: height
                .checked_div(self.params.nn_epoch_blocks)
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32,
            extra_nonce: self.vwc_extra_nonce(),
            sig_scheme: crate::hash::SIG_SCHEME_SECP256K1_ECDSA,
        };

        Ok(Block {
            header,
            signature: [0u8; 64],
            signer_pubkey: [0u8; 33],
            txs,
            l2_txs,
            l2_state_root: l2_root,
            exit_claims,
        })
    }

    // Nine parameters: same shape as the template builder above; the attempt
    // cap is the only addition. Callers that need an unsolved block for an
    // external miner use `build_template_with` instead.
    #[allow(clippy::too_many_arguments)]
    fn build_block(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        l2_txs: Vec<crate::l2::L2Transaction>,
        exit_claims: Vec<ExitClaim>,
        l2_root: Option<Hash>,
        now_ms: u64,
        difficulty_override: Option<u128>,
        max_attempts: u64,
    ) -> Result<Block> {
        let mut template = self.build_template_inner(
            miner_address,
            body,
            l2_txs,
            exit_claims,
            l2_root,
            now_ms,
            difficulty_override,
        )?;
        let mut header = template.header.clone();
        let mut nonce = 0u64;
        // The attempt budget is enforced here, in the loop that actually does
        // the work. It used to be applied only by the second loop in
        // `mine_block_with`, which is unreachable until this one has already
        // finished: a hostile retarget or a mis-set difficulty therefore hung
        // the node regardless of the cap its caller had asked for.
        for _ in 0..max_attempts {
            header.nonce = nonce;
            if self.pow_satisfies(&header)? {
                template.header = header;
                return Ok(template);
            }
            nonce = nonce.wrapping_add(1);
        }
        let unmined = template;
        Err(Error::PowInvalid {
            hash: crate::hash::hash512_to_hex(&unmined.block_hash()),
            difficulty: unmined.header.difficulty,
        })
    }

    /// Mine the next block on top of the tip.
    pub fn mine_block(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        now_ms: u64,
    ) -> Result<Block> {
        self.mine_block_with(miner_address, body, now_ms, None, DEFAULT_MAX_ATTEMPTS)
    }

    /// Mining with an explicit attempt cap, so a mis-set difficulty or a hostile
    /// retarget cannot hang a node forever. The override is for tests and for
    /// the difficulty-attack harness; a real miner loops without a cap.
    pub fn mine_block_with(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        now_ms: u64,
        difficulty_override: Option<u128>,
        max_attempts: u64,
    ) -> Result<Block> {
        self.build_block(
            miner_address,
            body,
            Vec::new(),
            Vec::new(),
            None,
            now_ms,
            difficulty_override,
            max_attempts,
        )
    }

    /// Mine a block that also carries L2 transactions (Decision 6, SPEC.md §19.1).
    ///
    /// Additive rather than a new parameter on `mine_block_with`: every existing
    /// caller mines L1-only blocks, and threading an empty vector through all of
    /// them would be churn with no behaviour attached. The block's merkle root
    /// covers both lists, so the header commits to the L2 payload exactly as it
    /// commits to the L1 one.
    ///
    /// Note what this does *not* do: it does not validate the L2 transactions.
    /// L2 validity is not an L1 block rule (Decision 6) — the miner is expected
    /// to have applied them to its own L2 state first, and a peer that disagrees
    /// still reaches the same L2 state by replaying the same bytes.
    pub fn mine_block_with_l2(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        l2_txs: Vec<crate::l2::L2Transaction>,
        now_ms: u64,
        difficulty_override: Option<u128>,
        max_attempts: u64,
    ) -> Result<Block> {
        self.build_block(
            miner_address,
            body,
            l2_txs,
            Vec::new(),
            None,
            now_ms,
            difficulty_override,
            max_attempts,
        )
    }

    /// Mine a block that carries L2 transactions **and** commits the L2 state
    /// root after them (approved P1).
    ///
    /// The caller (which holds the L2 view the chain must not consult) computed
    /// the root by replaying this block's L2 transitions. Post-activation
    /// blocks with L2 transactions and no root are refused by consensus, so a
    /// miner that includes L2 activity must use this path, not
    /// [`Self::mine_block_with_l2`].
    #[allow(clippy::too_many_arguments)]
    pub fn mine_block_with_l2_root(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        l2_txs: Vec<crate::l2::L2Transaction>,
        l2_root: Hash,
        now_ms: u64,
        difficulty_override: Option<u128>,
        max_attempts: u64,
    ) -> Result<Block> {
        self.build_block(
            miner_address,
            body,
            l2_txs,
            Vec::new(),
            Some(l2_root),
            now_ms,
            difficulty_override,
            max_attempts,
        )
    }

    /// Mine the next block out of `pool`, submit it, and evict what it confirmed.
    ///
    /// Selection happens against the *next* block's height and base fee, which are
    /// the same numbers `build_block` re-checks every transaction against, so a
    /// selection `check_tx` would reject cannot be produced here.
    ///
    /// **The three steps are one function deliberately.** Mining, submitting and
    /// evicting were briefly separate, and the split is wrong in a way that is easy
    /// to miss: a mined block is not a confirmed transaction until it wins fork
    /// choice. A peer's heavier block arriving at the same height leaves ours as a
    /// side branch, and evicting on "mined" rather than on "canonical" would then
    /// silently drop transactions the chain never confirmed. Submitting inside
    /// means the eviction decision is made against what actually became canonical.
    pub fn mine_from_pool(
        &mut self,
        pool: &mut Mempool,
        miner_address: crate::hash::Address,
        now_ms: u64,
    ) -> Result<Block> {
        self.mine_from_pool_with_l2(pool, miner_address, now_ms, Vec::new())
    }

    /// The mempool half of pool mining, shared with the external-miner
    /// template: the same gas-capped selection the internal miner takes,
    /// minus L2/exit content (which needs the L2 root only the internal
    /// path derives). A template built any other way would grind on a body
    /// the chain applies differently.
    pub fn select_from_pool_for_template(&self, pool: &Mempool) -> Result<Vec<Transaction>> {
        let body = pool.select_for_block(self.params.gas_cap, self.params.max_block_bytes);
        Ok(self.filter_stake_body(body))
    }

    /// [`mine_from_pool`] that also carries queued L2 transactions in the
    /// block's trailer (Decision 6, SPEC.md §19.1).
    ///
    /// This is the node's L2 ingress: an L2 transaction accepted over the API
    /// waits in a queue until a block carries it, because L2 state is derived
    /// from canonical blocks alone — there is no path that applies an L2
    /// transaction *outside* a block, and inventing one would fork this node's
    /// view from every peer's replay. Selection, submission and eviction are
    /// exactly `mine_from_pool`'s; the only difference is the trailer.
    pub fn mine_from_pool_with_l2(
        &mut self,
        pool: &mut Mempool,
        miner_address: crate::hash::Address,
        now_ms: u64,
        l2_txs: Vec<crate::l2::L2Transaction>,
    ) -> Result<Block> {
        self.mine_from_pool_with_exits(pool, miner_address, now_ms, l2_txs, Vec::new(), None)
    }

    /// [`mine_from_pool_with_l2`] that additionally settles exit claims and
    /// commits the caller's L2 state root (approved P1).
    ///
    /// This is the node's crank path: the caller (which holds the L2 view the
    /// chain must not consult) supplies the matured claims and the root its
    /// replay computed for this block's L2 transitions. The chain checks every
    /// claim with the same named errors `submit` would return, so a bad claim
    /// fails the miner here instead of producing a block the network refuses.
    pub fn mine_from_pool_with_exits(
        &mut self,
        pool: &mut Mempool,
        miner_address: crate::hash::Address,
        now_ms: u64,
        l2_txs: Vec<crate::l2::L2Transaction>,
        exit_claims: Vec<ExitClaim>,
        l2_root: Option<Hash>,
    ) -> Result<Block> {
        let cursor = self.height();
        let body = pool.select_for_block(self.params.gas_cap, self.params.max_block_bytes);
        // Pool mining is L1-only: the mempool holds L1 transactions. L2
        // transactions arrive through the caller's queue.
        let body = self.filter_stake_body(body);
        let block = self.build_block(
            miner_address,
            body,
            l2_txs,
            exit_claims,
            l2_root,
            now_ms,
            None,
            DEFAULT_MAX_ATTEMPTS,
        )?;
        self.submit_at(block.clone(), Some(now_ms))?;
        // Eviction is derived from the **canonical chain**, never from the fact
        // that we mined something. `reconcile_mempool` evicts what canonical
        // blocks above the cursor confirm, so a mined block that lost fork choice
        // evicts nothing with no special case, and a competing block that won
        // evicts its own transactions instead. An earlier version evicted the
        // block we had just built, guarded by a `tip_hash() == hash` check; that
        // guard is unreachable on today's single-threaded chain loop, which makes
        // it untestable rather than wrong — and an eviction rule that cannot be
        // exercised is one nobody will notice breaking.
        //
        // Only what the chain confirms is evicted, never the whole selection: a
        // transaction the gas or byte cap left out is still the best candidate
        // for the next block.
        let _ = self.reconcile_mempool(pool, cursor);
        Ok(block)
    }

    /// Transactions of canonical blocks in `(from_height, tip]`, oldest first.
    ///
    /// `from_height` is the caller's cursor — the height it last reconciled the
    /// pool against. At or above the tip this returns nothing, which is the
    /// common case and costs a bounds check.
    pub fn confirmed_above(&self, from_height: u64) -> Vec<Transaction> {
        let mut out = Vec::new();
        for height in from_height.saturating_add(1)..self.canon.len() as u64 {
            if let Some(block) = self.block_at(height) {
                out.extend(block.txs.iter().skip(1).cloned());
            }
        }
        out
    }

    /// Take the transactions the most recent reorg disconnected.
    ///
    /// Draining rather than reading, because re-admission must happen exactly
    /// once per reorg: a transaction re-admitted twice is at best redundant, and
    /// after the pool has changed it is a conflict against itself.
    pub fn take_disconnected(&mut self) -> Vec<Transaction> {
        std::mem::take(&mut self.disconnected_txs)
    }

    /// Keep `pool` in step with this chain: evict what the canonical chain now
    /// confirms, re-admit what a reorg un-confirmed.
    ///
    /// Returns the height the pool is now reconciled to, plus what moved. Holding
    /// that cursor is the caller's job, and it is the only state this needs:
    /// after a restart the pool is empty too, so reconciling from the tip is both
    /// correct and free.
    pub fn reconcile_mempool(
        &mut self,
        pool: &mut Mempool,
        from_height: u64,
    ) -> (u64, ReconcileReport) {
        let tip_height = self.height();
        let confirmed = self.confirmed_above(from_height);
        let disconnected = self.take_disconnected();
        let report = pool.reconcile(
            self.utxo(),
            tip_height + 1,
            &self.params,
            self.expected_base_fee_for_next_block(),
            &confirmed,
            &disconnected,
            &self.bonds,
        );
        (tip_height, report)
    }

    /// Drop stake transactions the next block could not include (Decision 20).
    /// Bond state moves under the pool: a bond confirmed since admission turns
    /// a pooled duplicate invalid, and an unbonded key voids pooled slashes.
    /// Failing the whole block over one stale transaction would wedge the
    /// miner, so selection skips them — admission already filtered them once,
    /// this is the re-check at mining time, in block order, on a scratch
    /// ledger. Only relative order matters for the committee, and filtering
    /// preserves it, so the scratch agrees with apply exactly.
    fn filter_stake_body(&self, body: Vec<Transaction>) -> Vec<Transaction> {
        let height = self.height() + 1;
        let mut scratch = self.bonds.clone();
        let mut kept = Vec::with_capacity(body.len());
        for (i, tx) in body.into_iter().enumerate() {
            if !tx.is_stake_tx() {
                kept.push(tx);
                continue;
            }
            let index = u32::try_from(i + 1).unwrap_or(u32::MAX);
            if crate::bond::probe_stake_tx(
                &tx,
                &mut scratch,
                &self.params.network_id,
                self.params.min_bond_sat,
                height,
                self.params.checkpoint_interval_blocks,
                index,
                &RealBls,
            )
            .is_ok()
            {
                kept.push(tx);
            }
        }
        kept
    }

    /// Cumulative difficulty of the canonical chain. This is what fork choice
    /// compares, so it is also the honest measure of "heavier".
    pub fn total_work(&self) -> u128 {
        self.cumulative_work(&self.tip_hash())
    }

    /// Number of blocks in the store, canonical and side branch alike.
    pub fn stored_block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Drop side branches the node can no longer act on. SPEC.md §13.10 item 2.
    ///
    /// Canonical history is kept in full: undo records, `verify_canonical_chain`
    /// and the persistence layer all replay from genesis, and history below the
    /// tip is the node's own, not a peer's. What is dropped is every
    /// **non-canonical** block at or below `tip − finality_depth`, plus any
    /// stored descendant of a dropped block, since a block whose parent is gone
    /// cannot be applied or walked to (`path_to` would fail).
    ///
    /// This closes the growth vector §13.10 item 2 exists for: a peer could
    /// submit an unbounded number of valid side blocks, each retained forever,
    /// with no work of its own. It also resolves a long-standing behaviour
    /// question — see `docs/status.md`: a branch that forked *below* the
    /// finality point used to be retained with its work counted, so fork choice
    /// kept selecting it and honest blocks were refused until honest work caught
    /// up. Once forgotten, the node accepts honest blocks again. The §9.3
    /// finality rule is unchanged: a reorg across it is still refused.
    fn prune_side_branches(&mut self) -> usize {
        let tip_height = self.height();
        let cutoff = tip_height.saturating_sub(self.params.finality_depth);

        let mut canonical: HashMap<Hash512, ()> = HashMap::with_capacity(self.canon.len());
        for hash in &self.canon {
            canonical.insert(*hash, ());
        }

        // Decide by ascending height so a block is only dropped after its parent
        // has been decided; a survivor therefore always has a surviving parent.
        let mut by_height: Vec<(u64, Hash512)> = self
            .blocks
            .iter()
            .map(|(h, b)| (b.header.height, *h))
            .collect();
        by_height.sort_unstable();

        let mut keep: HashMap<Hash512, ()> =
            HashMap::with_capacity(self.canon.len() + by_height.len());
        for hash in &self.canon {
            keep.insert(*hash, ());
        }

        let mut dropped = Vec::new();
        for (height, hash) in by_height {
            if canonical.contains_key(&hash) {
                continue;
            }
            if height > cutoff {
                // Above the window: keep only if it chains to something kept.
                let parent_kept = self
                    .blocks
                    .get(&hash)
                    .map(|b| keep.contains_key(&b.header.prev_hash))
                    .unwrap_or(false);
                if parent_kept {
                    keep.insert(hash, ());
                } else {
                    dropped.push(hash);
                }
            } else {
                dropped.push(hash);
            }
        }

        // Every per-block undo map is pruned together: entries only exist
        // for applied (canonical) blocks, which are never in `dropped`,
        // so these removes are no-ops today — but leaving any map out
        // would leak it the day a stored non-canonical block records undo.
        for hash in &dropped {
            self.blocks.remove(hash);
            self.work.remove(hash);
            self.undo.remove(hash);
            self.pscb_undo.remove(hash);
            self.bsaver_undo.remove(hash);
            self.treat_undo.remove(hash);
            self.burned_undo.remove(hash);
            self.exit_undo.remove(hash);
            self.bond_undo.remove(hash);
            self.slash_undo.remove(hash);
        }
        dropped.len()
    }

    /// Base fee the next block must carry. A wallet building a transaction has
    /// to know this, and duplicating the schedule in the client is how clients
    /// end up paying a fee the node then rejects.
    pub fn expected_base_fee_for_next_block(&self) -> u64 {
        let parent = self.tip();
        if parent.header.height == 0 {
            self.params.base_fee_initial_sat
        } else {
            // A canonical block's gas total cannot overflow (validate_standalone
            // rejects anything over the cap); fall back to the cap if it somehow
            // does rather than panicking on a display path. Claims are block
            // space too (approved P1), so their gas feeds the schedule.
            let gas = parent
                .total_gas_used()
                .ok()
                .and_then(|g| g.checked_add(parent.claims_gas_used().unwrap_or(u64::MAX)))
                .unwrap_or(self.params.gas_cap);
            next_base_fee(&self.params, parent.header.base_fee_sat, gas)
        }
    }

    /// Difficulty the next block must carry.
    pub fn expected_difficulty_for_next_block(&self) -> u128 {
        let history = self.history(self.params.difficulty_window as usize + 1);
        next_difficulty(&self.params, self.tip().header.difficulty, &history)
    }

    /// Coinbase maturity check for a UTXO entry at the next height.
    pub fn is_mature(&self, height: u64) -> bool {
        height + self.params.coinbase_maturity <= self.height() + 1
    }

    /// Replay the whole canonical chain from genesis and compare the result with
    /// the live state. Used by `srct-node verify` and after every reorg in tests:
    /// if undo data were wrong, a replay would diverge here.
    pub fn verify_canonical_chain(&self) -> Result<()> {
        let mut probe = Chain::new(self.params.clone())?;
        if probe.canon[0] != self.canon[0] {
            return Err(Error::BadPrevHash);
        }
        for hash in self.canon.iter().skip(1) {
            let block = self.blocks.get(hash).ok_or(Error::UnknownParent)?;
            probe.validate_standalone(block)?;
            probe.blocks.insert(*hash, block.clone());
            probe.apply_block(block)?;
            probe.canon.push(*hash);
        }
        if probe.canon != self.canon {
            return Err(Error::Malformed("canonical path differs from replay"));
        }
        if probe.utxo.len() != self.utxo.len() {
            return Err(Error::Malformed("utxo entry count diverged on replay"));
        }
        if probe.utxo.total_value() != self.utxo.total_value() {
            return Err(Error::Malformed("utxo value diverged on replay"));
        }
        // M1's PSCB reserve is part of live state and is rewound on reorg, so a
        // wrong undo there would silently accumulate or lose funds. It was not
        // checked at all, which made `verify` blind to the one thing M1 added.
        if probe.pscb_reserve != self.pscb_reserve {
            return Err(Error::Malformed("pscb reserve diverged on replay"));
        }
        if probe.burned_fees_total != self.burned_fees_total {
            return Err(Error::Malformed("burned fee total diverged on replay"));
        }
        if probe.pscb_undo != self.pscb_undo {
            return Err(Error::Malformed("pscb undo records diverged on replay"));
        }
        if probe.bsaver_reserve != self.bsaver_reserve {
            return Err(Error::Malformed("bsaver reserve diverged on replay"));
        }
        if probe.bsaver_undo != self.bsaver_undo {
            return Err(Error::Malformed("bsaver undo records diverged on replay"));
        }
        if probe.treat_reserve != self.treat_reserve {
            return Err(Error::Malformed("treat reserve diverged on replay"));
        }
        if probe.treat_undo != self.treat_undo {
            return Err(Error::Malformed("treat undo records diverged on replay"));
        }
        // Released exit identities are consensus state (approved P1): a wrong
        // undo here would unmark a spent exit or keep a reorged one marked,
        // and `verify` would be blind to both.
        if probe.released_exits != self.released_exits {
            return Err(Error::Malformed("released exits diverged on replay"));
        }
        // The bond ledger is consensus state (Decision 20): a wrong undo
        // here would keep a reorged bond validating or drop a live one, and
        // `verify` would be blind to both — the same blindness M1's reserve
        // had before it was checked above.
        if probe.bonds != self.bonds {
            return Err(Error::Malformed("bond ledger diverged on replay"));
        }
        if probe.slash_vault != self.slash_vault {
            return Err(Error::Malformed("slash vault diverged on replay"));
        }
        // The stake undo records themselves, for the same reason the PSCB ones
        // are checked above: the ledger comparison proves the applied state,
        // not that a reorg would undo it correctly.
        if probe.bond_undo != self.bond_undo {
            return Err(Error::Malformed("bond undo records diverged on replay"));
        }
        if probe.slash_undo != self.slash_undo {
            return Err(Error::Malformed("slash vault undo diverged on replay"));
        }
        // Seed-height bond snapshots are consensus derivation input (P0-1):
        // the epoch committees are derived from them, so a reorg that
        // forgets to restore them would verify checkpoints against the wrong
        // committee while every ledger above still matches.
        if probe.bond_snapshots != self.bond_snapshots {
            return Err(Error::Malformed("bond snapshots diverged on replay"));
        }
        Ok(())
    }

    /// Provable statements for `status` / the whitepaper.
    pub fn supply_report(&self) -> SupplyReport {
        let issued = cumulative_issuance_sat(&self.params, self.height());
        SupplyReport {
            // The stock cap is gone (Decision 18): the report names the rate
            // anchor instead — the most the current halving period may issue.
            rate_allowance_sat: rate_anchor_allowance(&self.params, self.height() + 1),
            reachable_sat: max_issuance_sat(&self.params),
            live_sat: self.utxo.total_value(),
            height: self.height(),
            reward_sat: block_reward_sat(&self.params, self.height() + 1),
            issued_sat: issued,
            // Net supply (Decision 18 §4.5): gross issuance minus everything
            // usage removed (burned half + PSCB half). This is the dilution
            // holders experience; gross issuance is what the anchor bounds.
            removed_sat: self.base_removed_total(),
            net_supply_sat: issued.saturating_sub(self.base_removed_total()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupplyReport {
    /// The rate anchor at the next height: the most gross issuance the current
    /// `halving_period` window may add (1 % of supply at the window's start).
    /// `u64::MAX` inside the grandfathered ladder era.
    pub rate_allowance_sat: u64,
    pub reachable_sat: u64,
    pub live_sat: u64,
    pub height: u64,
    pub reward_sat: u64,
    pub issued_sat: u64,
    /// Everything usage ever removed from live supply (burned + PSCB).
    pub removed_sat: u64,
    /// Gross issuance minus removal: the supply holders experience.
    pub net_supply_sat: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Address;
    use crate::wallet::Wallet;

    fn addr(tag: u8) -> Address {
        [tag; 20]
    }

    fn ts(height: u64) -> u64 {
        crate::block::GENESIS_TIMESTAMP_MS + height * 1_000
    }

    /// Timestamps for a chain whose difficulty has genuinely risen above 1.
    ///
    /// Spacing is half a target-time, so the weighted average solve time is
    /// *below* target and the retarget rule raises difficulty. Spacing blocks
    /// out instead would lower difficulty, which is the correct response to
    /// slow blocks and would leave this at the genesis difficulty of 1.
    fn fast_ts(height: u64) -> u64 {
        let t = NetworkParams::mini().target_block_time_ms;
        crate::block::GENESIS_TIMESTAMP_MS + height * (t / 2)
    }

    #[test]
    fn genesis_is_valid_and_mines_nothing() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        assert_eq!(chain.height(), 0);
        assert_eq!(
            chain.total_supply_sat(),
            0,
            "0% premine is enforced in code"
        );
        let genesis = chain.tip().clone();
        chain.validate_standalone(&genesis).unwrap();
    }

    #[test]
    fn mines_and_extends_a_chain() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=8u64 {
            let b = chain.mine_block(addr(1), vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
            assert_eq!(chain.height(), h);
            assert_eq!(
                chain.total_supply_sat(),
                block_reward_sat(chain.params(), h) * h
            );
        }
        chain.verify_canonical_chain().unwrap();
    }

    /// The validator's next-base-fee computation must count claim gas, exactly as
    /// the miner's does.
    ///
    /// Claims are ordinary block space (approved P1), so `build_block` and
    /// `expected_base_fee_for_next_block` both fold the parent's
    /// `claims_gas_used()` into the parent's gas. `apply_block` computed the
    /// same schedule from `total_gas_used()` alone, so after any block carrying
    /// a claim it expected a strictly lower base fee than the miner produced
    /// and rejected the node's own next block with `BadFee`. One permissionless
    /// exit crank was enough to wedge every honest miner on an exit-enabled
    /// network.
    ///
    /// A `next_base_fee` clamp hides this whenever the fee sits at a bound, so
    /// the regime here sits strictly inside `[min, max]`: high enough that the
    /// downward pressure from claim gas cannot floor it, and with a tight gas
    /// cap so the two gas figures land on different sides of the target.
    #[test]
    fn claim_gas_changes_the_next_base_fee_and_must_be_counted() {
        let mut params = NetworkParams::mini();
        params.base_fee_initial_sat = 1_000_000;
        params.base_fee_min_sat = 1;
        params.base_fee_max_sat = 100_000_000;
        params.gas_cap = 100_000;

        let mut chain = Chain::new(params).unwrap();
        let miner = addr(1);
        for h in 1..=4u64 {
            let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }

        let parent = chain.tip().clone();
        let body_gas = parent.total_gas_used().unwrap();
        // One claim's worth of block space on top of the body's.
        let claim_gas = 17_500u64;
        let total_gas = body_gas.checked_add(claim_gas).unwrap();
        assert!(
            total_gas <= chain.params().gas_cap,
            "the block must stay valid under the tightened cap"
        );

        let params = chain.params().clone();
        let with_claims =
            crate::fees::next_base_fee(&params, parent.header.base_fee_sat, total_gas);
        let body_only = crate::fees::next_base_fee(&params, parent.header.base_fee_sat, body_gas);

        // The regime must discriminate, or this test proves nothing: with the
        // fee clamped, the two agree and the bug hides.
        assert_ne!(
            with_claims, body_only,
            "claim gas must move the base fee once the fee is clear of its clamp"
        );
    }

    #[test]
    fn coinbase_matures_then_can_be_spent() {
        let miner = Wallet::new_random("miner");
        let miner_addr = miner.address().unwrap();
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=11u64 {
            let b = chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        let reward = block_reward_sat(chain.params(), 11);
        assert_eq!(chain.total_supply_sat(), reward * 11);
        // Eleven coinbases exist; maturity only decides which may be *spent*.
        assert_eq!(chain.utxo().outputs_for_address(&miner_addr).len(), 11);

        // A matured coinbase pays a fee large enough to clear the burned base fee, so
        // the maturity rule is what decides the outcome, not the fee rule.
        let burn_fee = chain.tip().header.base_fee_sat * 100_000 + 1;

        let immature = OutPoint {
            txid: chain.block_at(11).unwrap().txs[0].txid(),
            index: 0,
        };
        let tx = signed_spend(&miner, immature, reward - 1 - burn_fee, [8u8; 20]);
        assert!(matches!(
            crate::ledger::check_tx(
                chain.utxo(),
                &tx,
                11,
                chain.params(),
                chain.tip().header.base_fee_sat,
                chain.params().coinbase_maturity,
            ),
            Err(Error::ImmatureCoinbase { .. })
        ));

        let mature = OutPoint {
            txid: chain.block_at(1).unwrap().txs[0].txid(),
            index: 0,
        };
        let tx = signed_spend(&miner, mature, reward - 1 - burn_fee, [8u8; 20]);
        let delta = crate::ledger::check_tx(
            chain.utxo(),
            &tx,
            11,
            chain.params(),
            chain.tip().header.base_fee_sat,
            chain.params().coinbase_maturity,
        )
        .unwrap();
        assert_eq!(delta.fee_total, burn_fee + 1);
    }

    /// Build a correctly signed 1-in 1-out spend of `op`, for rule checks that
    /// need a real transaction without mining one.
    fn signed_spend(wallet: &Wallet, op: OutPoint, pay: u64, to: Address) -> Transaction {
        let mut tx = Transaction::standard(
            vec![crate::tx::Input::unsigned(&op)],
            vec![crate::tx::Output {
                value: pay,
                address: to,
            }],
        );
        wallet.sign(&mut tx).unwrap();
        tx
    }

    #[test]
    fn duplicate_submission_is_rejected() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let b = chain.mine_block(addr(1), vec![], ts(1)).unwrap();
        chain.submit(b.clone()).unwrap();
        assert!(matches!(chain.submit(b), Err(Error::AlreadyKnown)));
    }
    #[test]
    fn tampering_with_a_header_breaks_the_proof_of_work() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=6u64 {
            let b = chain.mine_block(addr(1), vec![], fast_ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        let tip = chain.tip().clone();
        assert!(tip.header.difficulty > 1, "difficulty must exceed 1");

        // Merkle commitment and difficulty are checked before the proof, so
        // those two are deterministic rejections.
        let mut bad = tip.clone();
        bad.header.merkle_root[0] ^= 1;
        assert!(matches!(chain.submit(bad), Err(Error::BadMerkleRoot)));

        // A difficulty the retarget rule would not produce is refused outright
        // by `submit`, before the proof for that (too-cheap) difficulty is even
        // checked — a side block nobody paid real work for must never reach
        // the verifier's PoW path. `validate_standalone` alone still accepts
        // it: without a parent it cannot know what difficulty the branch is at.
        let mut easy = tip.clone();
        easy.header.difficulty = 1;
        easy.header.nonce = 0;
        chain.validate_standalone(&easy).unwrap();
        assert!(matches!(
            chain.submit(easy),
            Err(Error::BadDifficulty { .. })
        ));
        assert_eq!(chain.tip_hash(), tip.block_hash());

        // Now a high-difficulty block where a single header bit is flipped.
        // At 2^18 work a lucky pass has probability 2^-18.
        let hard = chain
            .mine_block_with(addr(1), vec![], fast_ts(7), Some(1u128 << 18), 4_000_000)
            .unwrap();
        chain.validate_standalone(&hard).unwrap();
        let mut flipped = hard.clone();
        flipped.header.extra_nonce[7] ^= 1;
        assert_ne!(flipped.block_hash(), hard.block_hash());
        assert!(matches!(
            chain.validate_standalone(&flipped),
            Err(Error::PowInvalid { .. })
        ));
    }

    #[test]
    fn wrong_difficulty_is_rejected() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=6u64 {
            let b = chain.mine_block(addr(1), vec![], fast_ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        let expected = chain.tip().header.difficulty;

        // Mine honestly, then declare a difficulty the retarget rule would never
        // produce. The proof is valid for the declared difficulty, so only the
        // state rules can catch it. Note the +1: at this spacing the rule
        // raises difficulty by exactly one per block, so `expected + 1` is
        // what it *would* legitimately produce and must not be used here.
        let wrong = chain
            .mine_block_with(addr(1), vec![], fast_ts(7), Some(expected * 10), 500_000)
            .unwrap();
        chain.validate_standalone(&wrong).unwrap();
        assert!(matches!(
            chain.submit(wrong),
            Err(Error::BadDifficulty { .. })
        ));
        assert_eq!(chain.height(), 6, "a rejected block must not be adopted");
    }

    #[test]
    fn wrong_epoch_is_rejected() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let b = chain.mine_block(addr(1), vec![], ts(1)).unwrap();
        chain.validate_standalone(&b).unwrap();

        let mut wrong = b.clone();
        wrong.header.epoch_id = 7;
        assert!(matches!(
            chain.validate_standalone(&wrong),
            Err(Error::BadEpoch { .. })
        ));
    }

    #[test]
    fn heavier_fork_wins_and_state_rewinds() {
        // Node A: 1..=4.
        let mut a = Chain::new(NetworkParams::mini()).unwrap();
        let mut a_blocks = Vec::new();
        for h in 1..=4u64 {
            let b = a.mine_block(addr(1), vec![], ts(h)).unwrap();
            a.submit(b.clone()).unwrap();
            a_blocks.push(b);
        }
        let a_tip = a.tip_hash();

        // Node B: 1..=8, shared prefix then its own branch.
        let mut b = Chain::new(NetworkParams::mini()).unwrap();
        let mut b_blocks = Vec::new();
        for h in 1..=2u64 {
            let blk = b.mine_block(addr(1), vec![], ts(h)).unwrap();
            b.submit(blk.clone()).unwrap();
            b_blocks.push(blk);
        }
        for h in 3..=8u64 {
            let blk = b.mine_block(addr(9), vec![], ts(h)).unwrap();
            b.submit(blk.clone()).unwrap();
            b_blocks.push(blk);
        }
        assert_eq!(b.height(), 8);
        let b_tip = b.tip_hash();

        // Deliver B's blocks to A in an adversarial order.
        assert!(matches!(
            a.submit(b_blocks[7].clone()),
            Err(Error::UnknownParent)
        ));
        assert!(matches!(
            a.submit(b_blocks[0].clone()),
            Err(Error::AlreadyKnown)
        ));
        assert!(matches!(
            a.submit(b_blocks[1].clone()),
            Err(Error::AlreadyKnown)
        ));
        for blk in b_blocks.iter().skip(2) {
            a.submit(blk.clone()).unwrap();
        }

        assert_eq!(a.height(), 8);
        assert_eq!(a.tip_hash(), b_tip, "heavier branch must win");
        assert_ne!(a.tip_hash(), a_tip);
        assert_eq!(
            a.total_supply_sat(),
            b.total_supply_sat(),
            "state must rewind"
        );
        a.verify_canonical_chain().unwrap();

        // The abandoned branch is still stored, just no longer canonical.
        assert!(a.block_by_hash(&a_tip).is_some());
        assert_ne!(a.block_at(4).unwrap().block_hash(), a_tip);
    }

    #[test]
    fn fork_choice_prefers_more_work_at_equal_height() {
        // Both branches reach height 3. The rival's blocks arrive slowly, so the
        // retarget rule raises its difficulty and it ends up carrying more work.
        let mut main = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=3u64 {
            let blk = main.mine_block(addr(1), vec![], ts(h)).unwrap();
            main.submit(blk).unwrap();
        }
        let main_tip = main.tip_hash();
        assert_eq!(main.tip().header.difficulty, 1);

        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        let mut rival_blocks = Vec::new();
        for h in 1..=2u64 {
            let blk = rival.mine_block(addr(1), vec![], fast_ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        // The rival's prefix diverges at height 1 (slow timestamps), so this is
        // a genuine competitor rather than the same chain.
        assert_ne!(
            rival_blocks[0].block_hash(),
            main.block_at(1).unwrap().block_hash()
        );

        let mut heavy = Vec::new();
        for h in 3..=3u64 {
            let blk = rival.mine_block(addr(5), vec![], fast_ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            heavy.push(blk);
        }
        assert!(rival.tip().header.difficulty > 1);

        for blk in rival_blocks.iter().chain(heavy.iter()) {
            main.submit(blk.clone()).unwrap();
        }
        assert_eq!(main.height(), 3, "equal height, but more work must win");
        assert_eq!(main.tip_hash(), heavy[0].block_hash());
        assert_ne!(main.tip_hash(), main_tip);
    }

    #[test]
    fn reorg_cannot_rewrite_finalized_history() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=25u64 {
            let b = chain.mine_block(addr(1), vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        assert_eq!(chain.finalized_height(), 5);

        // A rival chain that forks at genesis and climbs in difficulty. Delivering its
        // tip would rewrite finalized history, so it must be refused no matter how
        // much work it carries.
        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        let mut rival_blocks = Vec::new();
        for h in 1..=20u64 {
            let blk = rival.mine_block(addr(7), vec![], fast_ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        assert!(
            rival.total_work() > chain.total_work(),
            "the rival must carry more work ({}) than the tip ({}) for this test to mean anything",
            rival.total_work(),
            chain.total_work()
        );

        let mut rejected = 0;
        for blk in rival_blocks.iter() {
            if let Err(e) = chain.submit(blk.clone()) {
                assert!(
                    matches!(e, Error::ReorgWouldCrossFinality { .. }),
                    "unexpected rejection reason: {e}"
                );
                rejected += 1;
            }
        }
        assert!(
            rejected > 0,
            "a reorg across the finality point was accepted"
        );
        assert_eq!(
            chain.height(),
            25,
            "tip must be unchanged after a rejected reorg"
        );
        chain.verify_canonical_chain().unwrap();
    }

    #[test]
    fn reorg_inside_the_finality_window_is_allowed() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=25u64 {
            let b = chain.mine_block(addr(1), vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        // Rival forks at height 24, which is above finalized_height() == 5.
        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        let mut rival_blocks = Vec::new();
        for h in 1..=23u64 {
            let blk = rival.mine_block(addr(1), vec![], ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        let old_tip = chain.tip_hash();
        for h in 24..=27u64 {
            let blk = rival.mine_block(addr(4), vec![], ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        for blk in rival_blocks.iter().skip(23) {
            chain.submit(blk.clone()).unwrap();
        }
        assert_eq!(chain.height(), 27);
        assert_ne!(chain.tip_hash(), old_tip);
        chain.verify_canonical_chain().unwrap();
    }

    #[test]
    fn a_paid_transaction_moves_value_and_burns_the_base_fee() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let miner = Wallet::new_random("miner");
        let alice = Wallet::new_random("alice");
        let miner_addr = miner.address().unwrap();
        let alice_addr = alice.address().unwrap();

        for h in 1..=12u64 {
            let b = chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }

        // A matured coinbase pays Alice.
        let coinbase = chain.block_at(1).unwrap();
        let op = OutPoint {
            txid: coinbase.txs[0].txid(),
            index: 0,
        };
        let spendable = chain.utxo().get(&op).expect("matured coinbase").out.value;
        let base_fee = chain.tip().header.base_fee_sat;

        // Spend half of it, paying a fee comfortably above the burned base fee.
        let send = spendable / 2;
        let fee = base_fee * 50_000 + 1_000;
        let tx = miner
            .build_tx(
                &[op],
                vec![crate::tx::Output {
                    value: send,
                    address: alice_addr,
                }],
                fee,
            )
            .unwrap();

        let supply_before = chain.total_supply_sat();
        let gas_used = tx.gas_used();

        let b = chain.mine_block(miner_addr, vec![tx], ts(13)).unwrap();
        // The burned amount must be read from the block that was actually mined:
        // its base fee follows the schedule, not the previous block's.
        let burned = b.header.base_fee_sat * gas_used;
        chain.submit(b).unwrap();
        chain.verify_canonical_chain().unwrap();

        assert_eq!(
            chain.utxo().outputs_for_address(&alice_addr),
            vec![(
                OutPoint {
                    txid: chain.block_at(13).unwrap().txs[1].txid(),
                    index: 0
                },
                send
            )]
        );
        // A coinbase was minted, but the base fee was burned on top of it.
        let reward = block_reward_sat(chain.params(), 13);
        assert!(
            burned > 0,
            "the test is only meaningful when something is actually burned"
        );
        assert_eq!(
            chain.total_supply_sat(),
            supply_before + reward - burned,
            "base fee must be destroyed, not redistributed"
        );
    }

    /// Stage SA-4: the removal counter and the net-supply report. Net supply
    /// is gross issuance minus everything usage removed (burned half + PSCB
    /// half) — the dilution holders experience (Decision 18 §4.5). On L1,
    /// live supply equals it exactly: no other leak exists.
    #[test]
    fn the_burn_counter_and_net_report_track_removal() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let miner = Wallet::new_random("miner");
        let alice = Wallet::new_random("alice");
        let miner_addr = miner.address().unwrap();
        let alice_addr = alice.address().unwrap();
        for h in 1..=12u64 {
            let b = chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        assert_eq!(chain.base_removed_total(), 0, "empty blocks remove nothing");

        // A matured coinbase pays Alice with a fee, so block 13 removes its
        // full base fee from live supply.
        let coinbase = chain.block_at(1).unwrap();
        let op = OutPoint {
            txid: coinbase.txs[0].txid(),
            index: 0,
        };
        let spendable = chain.utxo().get(&op).expect("matured coinbase").out.value;
        let base_fee = chain.tip().header.base_fee_sat;
        let fee = base_fee * 50_000 + 1_000;
        let tx = miner
            .build_tx(
                &[op],
                vec![crate::tx::Output {
                    value: spendable / 2,
                    address: alice_addr,
                }],
                fee,
            )
            .unwrap();
        let gas_used = tx.gas_used();
        let b = chain.mine_block(miner_addr, vec![tx], ts(13)).unwrap();
        let full_base = b.header.base_fee_sat * gas_used;
        assert!(full_base > 0, "the test needs a block that removes supply");
        chain.submit(b).unwrap();

        let removed = chain.base_removed_total();
        assert_eq!(removed, full_base, "removal is the whole base fee");
        assert_eq!(
            removed,
            chain.burned_fees_total()
                + chain.pscb_reserve()
                + chain.bsaver_reserve()
                + chain.treat_reserve(),
            "removal is burned plus PSCB plus B-Saver plus Treats"
        );
        let r = chain.supply_report();
        assert_eq!(r.removed_sat, removed);
        assert_eq!(r.net_supply_sat, r.issued_sat.saturating_sub(removed));
        assert_eq!(
            r.live_sat, r.net_supply_sat,
            "on L1, live supply is net supply — no other leak exists"
        );
        chain.verify_canonical_chain().unwrap();
    }

    /// M1's PSCB reserve must survive a reorganization intact: credited per
    /// canonical block, rewound per rolled-back block, and equal to the sum a
    /// clean replay produces. Before the M1 checks were added to
    /// `verify_canonical_chain`, `srct-node verify` could not see a PSCB bug at
    /// all — it compared the UTXO set only.
    #[test]
    fn the_pscb_reserve_is_rewound_exactly_on_reorg() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let miner = Wallet::new_random("miner");
        let alice = Wallet::new_random("alice");
        let miner_addr = miner.address().unwrap();
        let alice_addr = alice.address().unwrap();

        for h in 1..=12u64 {
            let b = chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }

        // A block that pays a fee, so a non-zero PSCB credit exists.
        let op = OutPoint {
            txid: chain.block_at(1).unwrap().txs[0].txid(),
            index: 0,
        };
        let spendable = chain.utxo().get(&op).unwrap().out.value;
        let fee = chain.expected_base_fee_for_next_block() * 50_000 + 1_000;
        let tx = miner
            .build_tx(
                &[op],
                vec![Output {
                    value: spendable / 2,
                    address: alice_addr,
                }],
                fee,
            )
            .unwrap();
        let gas_used = tx.gas_used();
        let paid = chain.mine_block(miner_addr, vec![tx], ts(13)).unwrap();
        // PSCB is 50% of the base-fee portion, not of the whole fee: the tip
        // above it belongs to the miner (§8, M1).
        let base_portion = paid.header.base_fee_sat * gas_used;
        chain.submit(paid).unwrap();

        let reserve_with_fee = chain.pscb_reserve();
        let bsaver_with_fee = chain.bsaver_reserve();
        let treat_with_fee = chain.treat_reserve();
        assert!(reserve_with_fee > 0, "no PSCB was credited for the fee");
        assert_eq!(
            bsaver_with_fee,
            crate::bsaver::bsaver_cut_default(base_portion / 2),
            "B-Saver is 5% of the PSCB leg"
        );
        assert_eq!(
            treat_with_fee,
            crate::treats::treat_cut_default(base_portion / 2),
            "Treats is 10% of the PSCB leg"
        );
        assert_eq!(
            reserve_with_fee + bsaver_with_fee + treat_with_fee,
            base_portion / 2,
            "PSCB + B-Saver + Treats is 50% of the base-fee portion"
        );

        // Reorg inside the finality window: fork at 11 and rebuild 12..=15.
        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=10u64 {
            let blk = rival.mine_block(miner_addr, vec![], ts(h)).unwrap();
            rival.submit(blk).unwrap();
        }
        assert_eq!(
            rival.tip_hash(),
            chain.block_hash_at(10).unwrap(),
            "the rival must share the prefix"
        );
        let mut rival_blocks = Vec::new();
        for h in 11..=15u64 {
            let blk = rival.mine_block(addr(9), vec![], ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        assert!(rival.total_work() > chain.total_work());
        for blk in rival_blocks {
            chain.submit(blk).unwrap();
        }

        assert_eq!(chain.height(), 15);
        assert_eq!(
            chain.pscb_reserve(),
            0,
            "the paying block was rolled back, so its PSCB credit must be rewound"
        );
        assert_eq!(
            chain.bsaver_reserve(),
            0,
            "the paying block was rolled back, so its B-Saver credit must be rewound"
        );
        assert_eq!(
            chain.treat_reserve(),
            0,
            "the paying block was rolled back, so its Treat credit must be rewound"
        );
        chain
            .verify_canonical_chain()
            .expect("pscb state diverged from a clean replay");
    }
}
