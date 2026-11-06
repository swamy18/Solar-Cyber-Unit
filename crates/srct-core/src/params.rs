//! Network profiles. SPEC.md §10.
//!
//! Section 17 of the design doc requires the mini version to be the *same code*
//! with different parameters — never a second codebase. Every consensus constant
//! therefore lives here, and the mini profile differs only in numbers.

use crate::bls_checkpoint::BlsPublicKey;
use crate::error::{Error, Result};
use crate::hash::{Address, Hash};

pub const SAT_PER_SRCT: u64 = 100_000_000;

/// Domain tag for the L2 protocol-escrow identity (Decision 7, SPEC.md §19.4).
/// The escrow address is `SHA256(tag ‖ network_id)[..20]`: deterministic per
/// network, consensus-visible, and holding no key — value parked there moves
/// only by protocol rule, never by signature.
pub const DOM_L2_ESCROW: &[u8] = b"srct/l2-escrow/v1";

/// Domain tag for the L2 deposit sink (Decision 10, SPEC.md §19.5). A distinct
/// tag from the escrow identity so the two can never coincide; a sink output
/// is an ordinary L1 payment that L2 replay interprets as a deposit.
pub const DOM_L2_DEPOSIT_SINK: &[u8] = b"srct/l2-deposit-sink/v1";

/// Minimum deposit per sink output, in satoshis (Decision 10 item 3). A
/// dust/bloat floor, not a fee: every credited deposit leaves permanent
/// unspendable UTXO entries, so crediting dust would bloat both ledgers for
/// free. Identical on both profiles — it is economic, not timing.
pub const L2_DEPOSIT_MINIMUM_SAT: u64 = 1_000_000;

/// Flat fee per L2 transaction type, in satoshis (decision D3).
///
/// Flat **per type, not per byte.** A worker deciding whether to post a task has
/// to know the price before it builds the transaction, and a size-metered fee
/// makes the price of the same logical operation depend on how the payload
/// serializer happens to encode it.
///
/// **These do not clear the L1 fee floor, and they are not supposed to.** The
/// only L1 fee rule is `base_fee * gas_used` (`fees::required_fee`), and even the
/// smallest transaction uses `GAS_TX_BASE` gas, so that floor is orders of
/// magnitude above every number below. Decision D3 resolved this by giving L2 a
/// fee path of its own rather than an exemption: `l2::L2TxType::fee_sat` returns
/// these values, and `fees::split_flat_fee` routes the whole flat fee through the
/// unchanged M1 50/50 burn/PSCB rule. The L1 floor is untouched and L2 never
/// consults it. `l2_fees_do_not_use_the_l1_gas_floor` pins that separation.
pub const FEE_TX_POST_TASK_SAT: u64 = 5_000;
pub const FEE_TX_CLAIM_TASK_SAT: u64 = 2_000;
pub const FEE_TX_SUBMIT_RESULT_SAT: u64 = 2_000;
pub const FEE_TX_DISPUTE_SAT: u64 = 10_000;
/// Decision 23 (P5): the settle fee is proportional — 0.1% of task value —
/// so there is no flat settle constant any more. What remains fixed is the
/// anti-spam floor every settle pays at least (`settle_fee_sat` in `l2.rs`).
pub const SETTLE_FEE_MIN_SAT: u64 = 1_000;
/// Queueing an L2 → L1 exit (approved P1, E-1…E-3). Same tier as claim/submit:
/// a simple owner-signed debit-and-record, not arbitration. Chosen with the
/// exit implementation and recorded in `docs/decisions.md` (P1 record); it is a
/// fee for a *new* type, not a change to any decided value.
pub const FEE_TX_EXIT_QUEUE_SAT: u64 = 2_000;
/// Publishing a spending policy on chain (SPEC.md §21.1). Same tier as
/// claim/submit: a simple owner-signed record, not arbitration.
pub const FEE_TX_POLICY_SAT: u64 = 2_000;
/// Revoking a published policy (SPEC.md §21.2). Same tier as the publish it
/// undoes.
pub const FEE_TX_POLICY_REVOKE_SAT: u64 = 2_000;
/// Spending under a published policy (SPEC.md §21.3). Same tier as the exit
/// queue: a signed debit-and-credit with no arbitration.
pub const FEE_TX_AGENT_SPEND_SAT: u64 = 2_000;
/// Opening a credit position (SPEC.md §22.3). Same tier as the exit queue:
/// a signed record with no arbitration.
pub const FEE_TX_CREDIT_OPEN_SAT: u64 = 2_000;
/// Adding collateral to a credit position (SPEC.md §22.4).
pub const FEE_TX_CREDIT_COLLATERAL_SAT: u64 = 2_000;
/// Repaying a credit position (SPEC.md §22.5).
pub const FEE_TX_CREDIT_REPAY_SAT: u64 = 2_000;
/// Settling an overdue credit position (SPEC.md §22.6).
pub const FEE_TX_CREDIT_DEFAULT_SAT: u64 = 2_000;
/// Highest interest a credit position may charge per window, in basis points
/// of the outstanding principal (10%). A rate above this is refused rather
/// than clamped: a lender who wanted 10 000 bps would be able to charge the
/// principal back in a single window, and a cap that silently lowers the rate
/// would hide that.
pub const MAX_CREDIT_RATE_BPS_PER_WINDOW: u32 = 1_000;
/// The flat minimum fee floor for any L2 transaction (D3). Every L2 fee type
/// must meet or exceed this value. The `fee_sat` function applies `max(fee,
/// L2_FLAT_FEE_MINIMUM_SAT)` as a final floor so a future re-parameterization
/// cannot accidentally produce a zero or sub-floor fee.
pub const L2_FLAT_FEE_MINIMUM_SAT: u64 = 1_000;

/// The D3 schedule as one table, so the exact set is asserted in one place and a
/// future change has a single spot to be checked against the decision record.
/// `TxSettle` lists the anti-spam floor, not the fee: the actual settle fee is
/// proportional to task value (Decision 23, `settle_fee_sat` in `l2.rs`).
/// Every entry is at least `L2_FLAT_FEE_MINIMUM_SAT` — the flat minimum fee
/// floor applied by `L2TxType::fee_sat`.
pub const L2_FEE_SCHEDULE: &[(&str, u64)] = &[
    ("TxPostTask", FEE_TX_POST_TASK_SAT),
    ("TxClaimTask", FEE_TX_CLAIM_TASK_SAT),
    ("TxSubmitResult", FEE_TX_SUBMIT_RESULT_SAT),
    ("TxDispute", FEE_TX_DISPUTE_SAT),
    ("TxSettle", SETTLE_FEE_MIN_SAT),
    ("TxExitQueue", FEE_TX_EXIT_QUEUE_SAT),
    ("TxPolicy", FEE_TX_POLICY_SAT),
    ("TxPolicyRevoke", FEE_TX_POLICY_REVOKE_SAT),
    ("TxAgentSpend", FEE_TX_AGENT_SPEND_SAT),
    ("TxCreditOpen", FEE_TX_CREDIT_OPEN_SAT),
    ("TxCreditCollateral", FEE_TX_CREDIT_COLLATERAL_SAT),
    ("TxCreditRepay", FEE_TX_CREDIT_REPAY_SAT),
    ("TxCreditDefault", FEE_TX_CREDIT_DEFAULT_SAT),
];

/// One genesis-funded L2 balance (Decision 7, SPEC.md §19.4).
///
/// The address is a plain L2 account address; the amount is satoshis released
/// to it once, at L2 genesis, out of the profile's escrow total. Mainnet
/// carries no grants (real allocation arrives with the deposit mechanism, and
/// inventing mainnet beneficiaries here would be inventing economics); `mini`
/// grants three deterministic operator identities so the funded flow is
/// exercisable end to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2GenesisGrant {
    pub address: Address,
    pub amount_sat: u64,
}

/// Address of the deterministic `mini` operator identity for `seed`.
///
/// The same derivation the integration tests use for their wallets
/// (`Wallet::from_private_key_bytes(&[seed; 32])`), so the genesis grants name
/// accounts the tests can actually sign for. Seeds are public test values, not
/// secrets: `mini` is the integration profile, and mainnet carries no grants.
fn l2_operator_address(seed: u8) -> Address {
    crate::wallet::Wallet::from_private_key_bytes(&[seed; 32], "l2-genesis-operator")
        .expect("constant seeds are valid scalars")
        .address()
        .expect("a wallet always has an address")
}

/// Domain tag for the mainnet bootstrap committee's deterministic seed
/// derivation. Distinct from the mini and testnet seed layouts.
const DOM_MAINNET_VALIDATOR_SEED: &[u8] = b"srct/mainnet-validator-seed/v1";

/// Canonical committee order: key bytes, duplicate-free.
fn canonical_committee(keys: impl IntoIterator<Item = BlsPublicKey>) -> Vec<BlsPublicKey> {
    let mut keys: Vec<BlsPublicKey> = keys.into_iter().collect();
    keys.sort_by_key(|a| a.0);
    keys.dedup();
    keys
}

fn mini_committee_keys() -> Vec<BlsPublicKey> {
    canonical_committee((1u8..=4).map(mini_validator_key))
}

fn testnet_committee_keys() -> Vec<BlsPublicKey> {
    canonical_committee((1u8..=4).map(testnet_validator_key))
}

fn mainnet_committee_keys() -> Vec<BlsPublicKey> {
    canonical_committee((1u8..=21).map(mainnet_validator_key))
}

/// Deterministic `mini` validator key for `seed`.
///
/// Derives a real BLS12-381 public key from the same public test seeds, so
/// the mini committee is a valid committee and checkpoint verification is
/// exercisable. Panics only if `min_pk` rejects a constant seed, which is a
/// build-time property, not a runtime input.
fn mini_validator_key(seed: u8) -> BlsPublicKey {
    mini_validator_secret(seed).public_key()
}

/// The deterministic `mini` committee secret for `seed`.
///
/// Public test material, not a secret in the cryptographic sense: these seeds
/// are in the source, so anyone can sign as a mini validator — which is
/// exactly what a permissionless testnet committee means. Exposed so tests
/// (and mini validator nodes) can produce real checkpoint certificates.
/// `mainnet` has its own bootstrap committee and derives secrets through
/// `mainnet_validator_secret`.
pub fn mini_validator_secret(seed: u8) -> crate::bls::SecretKey {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed;
    crate::bls::SecretKey::derive(&s).expect("constant seeds are valid scalars")
}

/// The four `mini` committee secrets, in the same order as the seeds.
pub fn mini_committee_secrets() -> Vec<crate::bls::SecretKey> {
    (1u8..=4).map(mini_validator_secret).collect()
}

/// Deterministic `mainnet` bootstrap validator key for `seed` (Decision 27).
///
/// A domain-separated derivation distinct from mini and testnet, so the
/// mainnet bootstrap committee shares no keys with either test profile while
/// every independently constructed `mainnet` profile remains byte-identical.
/// This is public bootstrap material, not a secret: any node can sign for it
/// until a bond-derived committee takes over. The value is a pure function of
/// the seed, with no runtime entropy.
pub fn mainnet_validator_key(seed: u8) -> BlsPublicKey {
    mainnet_validator_secret(seed).public_key()
}

/// The deterministic `mainnet` bootstrap secret for `seed`.
///
/// Public material by construction (the seed is in source), matching the mini
/// and testnet committees' status. It exists so a fresh mainnet node can
/// produce the certificate that activates binding finality at height 100
/// before any validator has bonded. Bonding replaces this committee through
/// `Chain::committee_keys`; it is not a permanent authority.
pub fn mainnet_validator_secret(seed: u8) -> crate::bls::SecretKey {
    let seed = crate::hash::sha256_dom(DOM_MAINNET_VALIDATOR_SEED, &[&[seed]]);
    crate::bls::SecretKey::derive(&seed).expect("constant seeds are valid scalars")
}

/// The 21 `mainnet` bootstrap committee secrets, in seed order.
pub fn mainnet_committee_secrets() -> Vec<crate::bls::SecretKey> {
    (1u8..=21).map(mainnet_validator_secret).collect()
}

/// Deterministic `testnet` validator key for `seed` (Decision 13).
///
/// A distinct seed domain from `mini`'s, so testnet and mini committees never
/// coincide, while staying a pure function of the seed - no runtime entropy,
/// two independently constructed `testnet` profiles are identical.
pub fn testnet_validator_key(seed: u8) -> BlsPublicKey {
    testnet_validator_secret(seed).public_key()
}

/// The deterministic `testnet` committee secret for `seed`. Public test
/// material (the seeds are in source), matching the mini committee's status.
pub fn testnet_validator_secret(seed: u8) -> crate::bls::SecretKey {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[16] = seed;
    s[31] = seed;
    crate::bls::SecretKey::derive(&s).expect("constant seeds are valid scalars")
}

/// The four `testnet` committee secrets, in the same order as the seeds.
pub fn testnet_committee_secrets() -> Vec<crate::bls::SecretKey> {
    (1u8..=4).map(testnet_validator_secret).collect()
}

/// Emission once the halving ladder is exhausted (approved 2026-10-09,
/// `docs/decisions.md` M-A..M-C).
///
/// A tail is *miner* emission only: no validator reward and no fee share
/// exists anywhere in this schedule (Decision 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailEmission {
    /// Issuance stops at ladder exhaustion (the pre-tail rule; legal for a
    /// profile, chosen by none of the shipped ones).
    None,
    /// Policy E: halve the subsidy in **satoshis** every halving period from
    /// 1 SRCT down to a permanent `floor_sat`, then pay the floor forever
    /// (mainnet: 0.1 SRCT). Every step is at most a halving; the step into
    /// the floor is the smallest of the series.
    DecayToFloor { floor_sat: u64 },
    /// Fast profiles (1-second blocks): a constant token tail so mining
    /// never stops. Applying a mainnet-sized tail here would mint >1000 %/yr
    /// against the fast cap (monetary-redesign F5).
    Constant { per_block_sat: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    pub name: String,
    /// Block spacing the difficulty retarget algorithm aims for.
    pub target_block_time_ms: u64,
    /// Blocks between halvings.
    pub halving_period: u64,
    /// Block reward at halving 0, in satoshis.
    pub start_reward_sat: u64,
    pub difficulty_window: u32,
    /// Max per-block difficulty change, in basis points (1000 = +/-10%).
    pub change_limit_bps: u32,
    pub genesis_difficulty: u128,
    pub min_difficulty: u128,
    pub max_difficulty: u128,
    /// Blocks before coinbase value is spendable.
    pub coinbase_maturity: u64,
    /// Blocks below the tip that can never be reorganized away.
    pub finality_depth: u64,
    pub gas_cap: u64,
    pub base_fee_initial_sat: u64,
    pub base_fee_min_sat: u64,
    pub base_fee_max_sat: u64,
    /// Height interval after which the neural-net weights rotate.
    pub nn_epoch_blocks: u64,
    pub puzzle_id: u64,
    /// M4 HBM scratchpad PoW parameters (SPEC.md §M4). Recognized only when
    /// `puzzle_id == 2`; ignored for the hybrid puzzle. Carried as a network
    /// parameter (rather than a compile-time constant) so the memory parameters
    /// are governance-upgradeable and never silently wrong — see
    /// `docs/security-review-hbm-2026-10-12.md` §5.
    pub hbm: crate::hbm_pow::HbmConfig,
    pub max_tx_count: usize,
    pub max_block_bytes: usize,
    /// Reject inputs that carry a single-scheme signature bundle, requiring a
    /// hybrid (multi-scheme) one. Off by default so existing single-scheme
    /// transactions stay valid; flipping it on is how a network would declare
    /// itself post-quantum ready without a hard fork.
    pub require_hybrid_signatures: bool,
    /// 4-byte discriminator checked on every incoming frame (§13.2/§13.3) and
    /// mandatory in the handshake. `mainnet` and `mini` MUST differ; reuse
    /// across two live networks lets a node accept a foreign chain's traffic.
    /// Zero is rejected by `validate()`.
    pub network_magic: [u8; 4],
    /// Human-readable network tag exchanged in the handshake (§13.4). Also
    /// distinguishes profiles when a magic collision is ever introduced.
    pub network_id: String,
    /// Total L2 genesis allocation in satoshis (Decision 7, SPEC.md §19.4).
    /// Released once, at L2 genesis: the grants below plus the remainder to
    /// the protocol escrow identity. Bounded by the explicit
    /// `escrow_ceiling_sat` (approved M-E) and validated against it; L1's side
    /// is bounded separately by the issuance integral at the tip height, so
    /// combined L1 + L2 money can never exceed that joint bound with zero L1
    /// consensus change. There is no stock supply cap any more (Decision 18:
    /// the rate anchor replaced it 2026-10-09).
    pub l2_genesis_escrow_sat: u64,
    /// Explicit backing ceiling for the L2 genesis escrow (approved M-E).
    /// Replaces the old implicit `cap − max_issuance_sat` gap rule, which
    /// stops being a meaningful quantity the moment issuance has a tail.
    /// Validated: `l2_genesis_escrow_sat <= escrow_ceiling_sat`.
    pub escrow_ceiling_sat: u64,
    /// Emission after ladder exhaustion (approved M-A/M-B/M-C).
    pub tail: TailEmission,
    /// Genesis-funded L2 accounts, paid out of `l2_genesis_escrow_sat`.
    pub l2_genesis_grants: Vec<L2GenesisGrant>,
    /// Minimum deposit per sink output in satoshis (Decision 10, SPEC.md
    /// §19.5). A per-profile field rather than the shared constant so a
    /// future network can price its own dust floor without touching code —
    /// but both shipped profiles carry the constant's value.
    pub l2_deposit_minimum_sat: u64,
    /// Fixed genesis validator committee (Decisions 11 and 27, SPEC.md §14).
    /// Explicit BLS keys. Decision 20 added bonded stake, so this is a
    /// *bootstrap* list rather than the source of authority: `Chain::
    /// committee_keys` derives the committee from the bond ledger whenever any
    /// bond exists and falls back to these keys only while none does.
    ///
    /// `mainnet` carries 21 deterministic public bootstrap keys, so a fresh
    /// chain can produce a valid quorum-15 checkpoint at activation height 100.
    /// The first bond replaces them under the existing TopN rule; they are not
    /// a permanent seat. `mini` and `testnet` carry four deterministic test
    /// keys. Canonically sorted by key bytes at construction; every node holding
    /// these params derives the same set.
    pub genesis_validators: Vec<BlsPublicKey>,
    /// Validator set that authorizes L2 `Settle` payloads (Decision 15).
    ///
    /// Kept separate from `genesis_validators` so the mainnet L1 bootstrap
    /// committee cannot silently become the L2 settlement authority. `mainnet`
    /// stays empty and therefore fails closed with `BadQuorum`; `mini` and
    /// `testnet` carry their four declared keys, preserving existing behaviour.
    pub l2_settlement_validators: Vec<BlsPublicKey>,
    /// Blocks per checkpoint epoch (Decision 11). `mini` uses 10 so finality
    /// observation is exercisable in tests; `mainnet` uses 100.
    pub checkpoint_interval_blocks: u64,
    /// Height at which a valid checkpoint certificate becomes **binding**
    /// finality (Decisions 12/13, SPEC.md §14.8). `0` means never: the profile
    /// keeps the depth-based fallback only. A checkpoint at a height below this
    /// is observed but never gates `Chain::adopt()`.
    pub finality_activation_height: u64,
    /// First L1 height at which an L2 → L1 exit may be queued and released
    /// (approved P1). `0` means never — the same convention as
    /// `finality_activation_height`: queueing is refused below activation so
    /// funds can never be encumbered with no release. All shipped profiles
    /// carry `1` (active from the first block).
    pub exit_activation_height: u64,
    /// Maximum total exit principal per `exit_window_blocks` window, in
    /// satoshis. The L2 deposit sink is a honeypot: without a window cap a
    /// single compromised key set drains it in one window. A refused queue
    /// keeps its funds (nothing is lost, only delayed) and retries in the
    /// next window. `0` disables the cap (`mini`/`testnet`).
    pub max_exit_window_sat: u64,
    /// Length of the exit window in blocks. Must be nonzero when
    /// `max_exit_window_sat` is nonzero (`validate` enforces the pairing).
    pub exit_window_blocks: u64,
    /// Maximum exit principal *one owner* may queue per window, in satoshis.
    /// The global cap alone lets a single actor fill the window and starve
    /// every other owner until it rolls over (griefing at fee cost, since
    /// refused queues keep their funds and accepted ones release). The
    /// sub-cap bounds one owner's share of the window, so a filler is
    /// refused by name while other owners still queue. Must not exceed the
    /// global cap, and requires the window to be on (`validate` enforces
    /// both); `0` disables the sub-cap, leaving the global cap as the only
    /// bound (`mini`/`testnet`).
    pub max_exit_per_owner_window_sat: u64,
    /// Exits at or above this principal wait an additional
    /// `large_exit_extra_delay_blocks` on top of maturity: large outflows
    /// give monitors and operators time to react. `0` disables the delay
    /// (`mini`/`testnet`).
    pub large_exit_threshold_sat: u64,
    /// Extra maturity blocks for large exits. Meaningless without a
    /// threshold and refused by `validate` in that shape.
    pub large_exit_extra_delay_blocks: u64,
    /// Height at which the network begins enforcing post-quantum (ML-DSA-65,
    /// scheme 3) spends. `0` means never: the rule is inert and every profile
    /// is byte-identical to the current consensus, so flipping it is the single
    /// switch that activates the migration.
    ///
    /// Scope is age-gated, not blanket: once active, only outputs created at or
    /// after this height must be spent with a bundle carrying scheme 3. Outputs
    /// created before it (including plain ECDSA ones) keep spending under their
    /// original bundle, so history is never invalidated — a wallet can move its
    /// old funds exactly as before, and only newly created outputs demand PQ.
    pub pq_activation_height: u64,
    /// Minimum bond per validator in satoshis. A bond below this is refused
    /// at admission and in blocks: without a floor, 1-sat bonds cost their
    /// submitter only L1 fees while permanently occupying ledger, snapshot
    /// and committee-derivation entries on every node. `0` disables the floor
    /// (`mini`/`testnet` keep `0` so tests exercise dust behavior);
    /// `mainnet` carries 1_000_000 sat (0.01 SRCT), the same anti-dust scale
    /// as `l2_deposit_minimum_sat`.
    pub min_bond_sat: u64,
}

impl NetworkParams {
    /// Deterministic future-timestamp allowance (SPEC.md §6.1).
    ///
    /// The 2-hour allowance used by Bitcoin was shown by `sim/difficulty_attack_sim.py`
    /// to let a 40% attacker pull difficulty down; one block time does not.
    pub fn future_limit_ms(&self) -> u64 {
        self.target_block_time_ms
    }

    /// The protocol escrow identity holding the un-granted remainder of the L2
    /// genesis allocation (Decision 7, SPEC.md §19.4).
    ///
    /// Derived, not stored: `SHA256(DOM_L2_ESCROW ‖ network_id)[..20]`. Every
    /// node holding these params derives the same address, and no wallet can
    /// hold its key — the remainder is inert until a later milestone authorises
    /// a disbursement rule for it.
    pub fn l2_escrow_address(&self) -> Address {
        let digest: Hash = crate::hash::sha256_dom(DOM_L2_ESCROW, &[self.network_id.as_bytes()]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        out
    }

    /// The deposit sink: an ordinary address nobody can spend from (Decision
    /// 10, SPEC.md §19.5).
    ///
    /// Derived exactly like the escrow identity but under its own domain tag,
    /// so the two can never coincide, and bound to `network_id` so one
    /// network's sink is another network's ordinary burn address. A STANDARD
    /// payment here is valid L1 with no rule change; only L2 replay reads a
    /// deposit into it.
    pub fn l2_deposit_sink(&self) -> Address {
        let digest: Hash =
            crate::hash::sha256_dom(DOM_L2_DEPOSIT_SINK, &[self.network_id.as_bytes()]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        out
    }

    /// Satoshis granted to named accounts at L2 genesis. Checked, not summed
    /// with `+`: a crafted params value overflowing here would understate the
    /// allocation and admit funding above the escrow total.
    pub fn l2_granted_sat(&self) -> Result<u64> {
        let mut total = 0u64;
        for g in &self.l2_genesis_grants {
            total = total
                .checked_add(g.amount_sat)
                .ok_or(Error::Malformed("l2 genesis grants overflow"))?;
        }
        Ok(total)
    }

    pub fn start_reward_srct(&self) -> u64 {
        self.start_reward_sat / SAT_PER_SRCT
    }

    pub fn by_name(name: &str) -> Result<Self> {
        match name {
            "mainnet" => Ok(Self::mainnet()),
            "mini" => Ok(Self::mini()),
            "testnet" => Ok(Self::testnet()),
            _ => Err(Error::Malformed(
                "unknown network; use \"mainnet\", \"testnet\", or \"mini\"",
            )),
        }
    }

    /// Mainnet: 10-minute blocks, 5-year halving, no stock cap (Decision 18
    /// replaced it with the rate anchor) (SPEC.md §7, §10).
    pub fn mainnet() -> Self {
        NetworkParams {
            name: "mainnet".into(),
            target_block_time_ms: 600_000,
            halving_period: 262_800,
            start_reward_sat: 76 * SAT_PER_SRCT,

            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: crate::u256::MAX_DIFFICULTY,
            coinbase_maturity: 100,
            finality_depth: 100,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 1_000,
            base_fee_min_sat: 100,
            base_fee_max_sat: 50_000_000,
            nn_epoch_blocks: 50_000,
            puzzle_id: 1,
            // HBM recognized but inactive: mainnet mines the hybrid puzzle.
            // Production memory parameters are the large config (see review §5).
            hbm: crate::hbm_pow::HbmConfig::production(),
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            // Protocol version bump: 01 -> 02. A pre-bump node carries 01 and
            // is refused at the framing layer, so it cannot join this network.
            network_magic: [0x6A, 0x4E, 0x54, 0x02],
            network_id: "srct/mainnet".into(),
            // The L2 genesis escrow (Decision 7): 100,000 SRCT held entirely by
            // the protocol escrow identity, bounded by the explicit
            // `escrow_ceiling_sat` below (approved M-E). No mainnet grants —
            // real beneficiaries arrive with the deposit mechanism, not as
            // hard-coded allocations.
            l2_genesis_escrow_sat: 100_000 * SAT_PER_SRCT,
            // M-E: the ceiling is exactly the allocation — tight, so the
            // explicit parameter constrains rather than rubber-stamps.
            escrow_ceiling_sat: 100_000 * SAT_PER_SRCT,
            // M-A/M-B: Policy E decay to a permanent 0.1 SRCT floor.
            tail: TailEmission::DecayToFloor {
                floor_sat: 10_000_000,
            },
            l2_genesis_grants: Vec::new(),
            l2_deposit_minimum_sat: L2_DEPOSIT_MINIMUM_SAT,
            // Decision 27: 21 deterministic public bootstrap keys, sorted, so a
            // fresh chain has a live committee from genesis. Quorum is 15.
            // The first bond replaces this set under the existing TopN rule.
            genesis_validators: mainnet_committee_keys(),
            // L2 settlement authority on mainnet (Decision 28, superseding
            // Decision 27 item 5): the declared set is the same 21 bootstrap
            // keys that secure L1 pre-bond — the mini/testnet precedent of
            // reusing the L1 keys. This declaration alone does not make the
            // bootstrap permanent: verification resolves the live committee
            // per block height (`Chain::settlement_committee_at`), so the
            // first bond rotates L2 authority to the bonded TopN and the
            // bootstrap keys authorize nothing further. The declaration
            // matters for the worker and offline verifiers, which have no
            // chain to resolve against.
            l2_settlement_validators: mainnet_committee_keys(),
            checkpoint_interval_blocks: 100,
            // Binding finality active from height 100 on mainnet — checkpoints
            // become binding once the committee signs them; depth-based
            // finality (100 blocks) covers everything before that.
            finality_activation_height: 100,
            // Exits active from genesis on mainnet — withdrawals work without a
            // committee, same as Bitcoin spends.
            exit_activation_height: 1,
            // PQ spend enforcement is off on mainnet until the post-quantum
            // launch decision sets a height.
            pq_activation_height: 0,
            // Anti-dust bond floor on mainnet (see the field doc): 1-sat
            // bonds cost every node permanent ledger entries at no stake.
            min_bond_sat: 1_000_000,
            // Exit throttle on mainnet: at most 1,000 SRCT of exit principal
            // per 144-block (~24h) window, no more than 100 SRCT of it from
            // any one owner; exits of 100 SRCT or more wait an extra 144
            // blocks. Refusals delay, never destroy: funds stay put and the
            // owner retries in the next window. `mini`/testnet leave all five
            // at 0 (disabled) so tests exercise bare rules.
            max_exit_window_sat: 1_000 * SAT_PER_SRCT,
            exit_window_blocks: 144,
            max_exit_per_owner_window_sat: 100 * SAT_PER_SRCT,
            large_exit_threshold_sat: 100 * SAT_PER_SRCT,
            large_exit_extra_delay_blocks: 144,
        }
    }

    /// Mini: identical logic, parameters chosen so a full halving cycle and a
    /// reorg both happen within minutes. Used to validate the production code
    /// end to end (SPEC.md §10, design doc Section 17 step 3).
    pub fn mini() -> Self {
        NetworkParams {
            name: "mini".into(),
            target_block_time_ms: 1_000,
            halving_period: 2_000,
            start_reward_sat: 76 * SAT_PER_SRCT,

            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: 1u128 << 40,
            coinbase_maturity: 10,
            finality_depth: 20,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 100,
            base_fee_min_sat: 10,
            base_fee_max_sat: 1_000_000,
            nn_epoch_blocks: 2_000,
            puzzle_id: 1,
            // HBM recognized but inactive: mini mines the hybrid puzzle. Test
            // config keeps HBM verification cheap if ever exercised.
            hbm: crate::hbm_pow::HbmConfig::test(),
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            // Distinct 4-byte magic so a mini peer can never be mistaken for
            // mainnet at the framing layer (§13.3). Genesis cannot do that job:
            // both profiles have genesis_difficulty=1, so genesis_block() is
            // identical, hence the identical genesis hash.
            network_magic: [0x6A, 0x4E, 0x54, 0x03],
            network_id: "srct/mini".into(),
            // 10 SRCT of L2 genesis escrow, all of it bounded by
            // `escrow_ceiling_sat`: 3 × 1 SRCT to deterministic operator
            // identities (seeds 1–3, whose keys the integration tests hold),
            // 7 SRCT remainder to the protocol escrow identity.
            l2_genesis_escrow_sat: 10 * SAT_PER_SRCT,
            // M-C: a 1-sat token tail on 1-second blocks — enough to keep
            // mining alive forever, a trickle against issued supply.
            escrow_ceiling_sat: 10 * SAT_PER_SRCT,
            tail: TailEmission::Constant { per_block_sat: 1 },
            l2_genesis_grants: vec![
                L2GenesisGrant {
                    address: l2_operator_address(1),
                    amount_sat: SAT_PER_SRCT,
                },
                L2GenesisGrant {
                    address: l2_operator_address(2),
                    amount_sat: SAT_PER_SRCT,
                },
                L2GenesisGrant {
                    address: l2_operator_address(3),
                    amount_sat: SAT_PER_SRCT,
                },
            ],
            l2_deposit_minimum_sat: L2_DEPOSIT_MINIMUM_SAT,
            // Test committee (Decision 11, SPEC.md §14): deterministic
            // BLS keys so mini exercises checkpoint finality end to end.
            genesis_validators: mini_committee_keys(),
            // L2 settlements keep the existing four-key declared committee.
            l2_settlement_validators: mini_committee_keys(),
            checkpoint_interval_blocks: 10,
            // M4 built the machinery; M5 does not activate binding finality on
            // mini either (that is the dedicated `testnet` profile's job), so
            // mini keeps depth-only finality.
            finality_activation_height: 0,
            // Exits are active from the first block on mini, so the queue →
            // mature → release loop is exercisable in tests.
            exit_activation_height: 1,
            // PQ enforcement off on mini; the migration tests build their own
            // profile with a nonzero activation height.
            pq_activation_height: 0,
            // No bond floor on mini: tests exercise dust behavior deliberately.
            min_bond_sat: 0,
            // Exit throttle disabled on mini (all five zero): bare rules.
            max_exit_window_sat: 0,
            exit_window_blocks: 0,
            max_exit_per_owner_window_sat: 0,
            large_exit_threshold_sat: 0,
            large_exit_extra_delay_blocks: 0,
        }
    }

    /// Testnet: the binding-finality profile (Decision 13). Fast blocks and a
    /// small deterministic committee so the full finality path — certificate,
    /// quorum, conflict, reorg-refusal — is exercisable end to end before any
    /// public deployment.
    ///
    /// Distinct `network_magic`/`network_id` from both other profiles; genesis
    /// is (as always) identical, so the magic/id are the chain identifiers.
    /// No staking, no rotation: the committee is the fixed genesis list.
    pub fn testnet() -> Self {
        NetworkParams {
            name: "testnet".into(),
            target_block_time_ms: 1_000,
            halving_period: 2_000,
            start_reward_sat: 76 * SAT_PER_SRCT,

            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: 1u128 << 40,
            coinbase_maturity: 10,
            // Depth fallback before activation (Decision 12). After activation
            // the checkpoint rule is authoritative and strictly stronger.
            finality_depth: 20,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 100,
            base_fee_min_sat: 10,
            base_fee_max_sat: 1_000_000,
            nn_epoch_blocks: 2_000,
            puzzle_id: 1,
            // HBM recognized but inactive: testnet mines the hybrid puzzle. Test
            // config keeps HBM verification cheap if exercised.
            hbm: crate::hbm_pow::HbmConfig::test(),
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            network_magic: [0x6A, 0x4E, 0x54, 0x04],
            network_id: "srct/testnet".into(),
            // Testnet carries no user grants yet (deposits/exits remain
            // deferred); the escrow is a real, accountable genesis reserve.
            l2_genesis_escrow_sat: 10 * SAT_PER_SRCT,
            escrow_ceiling_sat: 10 * SAT_PER_SRCT,
            tail: TailEmission::Constant { per_block_sat: 1 },
            l2_genesis_grants: Vec::new(),
            l2_deposit_minimum_sat: L2_DEPOSIT_MINIMUM_SAT,
            // Four deterministic testnet keys (distinct derivation from mini),
            // canonically sorted. Quorum for n=4 is ceil(4×6667/10000)=3.
            genesis_validators: testnet_committee_keys(),
            // L2 settlements keep the existing four-key declared committee.
            l2_settlement_validators: testnet_committee_keys(),
            checkpoint_interval_blocks: 10,
            // Binding finality turns on at height 20 (Decision 13): an explicit,
            // deterministic activation condition. Below it, observed
            // certificates are never binding.
            finality_activation_height: 20,
            // Exits are active from the first block on testnet, like mini.
            exit_activation_height: 1,
            // PQ enforcement off on testnet too; activated by governance.
            pq_activation_height: 0,
            // No bond floor on testnet either: play money, dust is test data.
            min_bond_sat: 0,
            // Exit throttle disabled on testnet too.
            max_exit_window_sat: 0,
            exit_window_blocks: 0,
            max_exit_per_owner_window_sat: 0,
            large_exit_threshold_sat: 0,
            large_exit_extra_delay_blocks: 0,
        }
    }

    /// Reject a profile that could never produce a valid block.
    pub fn validate(&self) -> Result<()> {
        if self.target_block_time_ms == 0 {
            return Err(Error::Malformed("target_block_time_ms must be > 0"));
        }
        if self.halving_period == 0 {
            return Err(Error::Malformed("halving_period must be > 0"));
        }
        if self.genesis_difficulty < self.min_difficulty {
            return Err(Error::Malformed("genesis_difficulty below min_difficulty"));
        }
        if self.max_difficulty < self.min_difficulty {
            return Err(Error::Malformed("max_difficulty below min_difficulty"));
        }
        if self.max_difficulty > crate::u256::MAX_DIFFICULTY {
            return Err(Error::Malformed("max_difficulty above MAX_DIFFICULTY"));
        }
        // Retarget arithmetic divides by the window and subtracts the change
        // limit from 10 000: a zero window is a divide-by-zero in
        // `difficulty.rs`, and a limit above 10 000 underflows the `u128`
        // subtraction. Both are profile bugs, refused at construction.
        if self.difficulty_window == 0 {
            return Err(Error::Malformed("difficulty_window must be > 0"));
        }
        if self.change_limit_bps > 10_000 {
            return Err(Error::Malformed("change_limit_bps must be <= 10000"));
        }
        if self.genesis_difficulty > self.max_difficulty {
            return Err(Error::Malformed("genesis_difficulty above max_difficulty"));
        }
        if self.coinbase_maturity == 0 {
            return Err(Error::Malformed("coinbase_maturity must be > 0"));
        }
        // Exit throttle pairing: a cap without a window (or a threshold
        // without its delay) is a half-rule the state machine cannot apply,
        // so the profile is refused instead of running half-throttled.
        if (self.max_exit_window_sat == 0) != (self.exit_window_blocks == 0) {
            return Err(Error::Malformed(
                "max_exit_window_sat and exit_window_blocks must be set together",
            ));
        }
        // Per-owner sub-cap: a share bigger than the whole is nonsense, and a
        // share of a window that does not exist is a half-rule.
        if self.max_exit_per_owner_window_sat > self.max_exit_window_sat {
            return Err(Error::Malformed(
                "max_exit_per_owner_window_sat must not exceed max_exit_window_sat",
            ));
        }
        if self.max_exit_per_owner_window_sat > 0 && self.exit_window_blocks == 0 {
            return Err(Error::Malformed(
                "max_exit_per_owner_window_sat needs exit_window_blocks",
            ));
        }
        if (self.large_exit_threshold_sat == 0) != (self.large_exit_extra_delay_blocks == 0) {
            return Err(Error::Malformed(
                "large_exit_threshold_sat and large_exit_extra_delay_blocks must be set together",
            ));
        }
        if self.gas_cap == 0 {
            return Err(Error::Malformed("gas_cap must be > 0"));
        }
        if self.start_reward_sat == 0 {
            return Err(Error::Malformed("start_reward_sat must be > 0"));
        }
        if self.network_magic == [0, 0, 0, 0] {
            return Err(Error::Malformed("network_magic must be non-zero"));
        }
        if self.network_id.is_empty() {
            return Err(Error::Malformed("network_id must be non-empty"));
        }
        // L2 genesis escrow (Decision 7, SPEC.md §19.4). Every rule here is a
        // conservation rule: together they prove combined L1 + L2 money can
        // never exceed the joint bound — L1's issuance integral at the tip
        // plus `escrow_ceiling_sat` (see the module docs on
        // `l2_genesis_escrow_sat`).
        if self.l2_genesis_escrow_sat == 0 {
            return Err(Error::Malformed("l2_genesis_escrow_sat must be > 0"));
        }
        let escrow = self.l2_escrow_address();
        let mut seen: Vec<Address> = Vec::with_capacity(self.l2_genesis_grants.len());
        for g in &self.l2_genesis_grants {
            if g.amount_sat == 0 {
                return Err(Error::Malformed("l2 genesis grant must be > 0"));
            }
            if g.address == escrow {
                return Err(Error::Malformed(
                    "l2 genesis grant must not name the escrow identity",
                ));
            }
            if seen.contains(&g.address) {
                return Err(Error::Malformed("duplicate l2 genesis grant address"));
            }
            seen.push(g.address);
        }
        let granted = self.l2_granted_sat()?;
        if granted > self.l2_genesis_escrow_sat {
            return Err(Error::Malformed(
                "l2 genesis grants exceed the escrow total",
            ));
        }
        // Escrow backing (approved M-E, 2026-10-09): an explicit, validated
        // ceiling replaces the old implicit `cap − max_issuance` gap — with a
        // tail, "unmintable gap" is no longer a meaningful quantity.
        if self.escrow_ceiling_sat == 0 {
            return Err(Error::Malformed("escrow_ceiling_sat must be > 0"));
        }
        if self.l2_genesis_escrow_sat > self.escrow_ceiling_sat {
            return Err(Error::Malformed(
                "l2 genesis escrow exceeds escrow_ceiling_sat",
            ));
        }
        // Tail positivity (approved M-B/M-C): a zero floor would silently
        // reinstate "issuance stops", which is policy A — rejected.
        match self.tail {
            TailEmission::DecayToFloor { floor_sat: 0 } => {
                return Err(Error::Malformed("tail floor must be > 0"));
            }
            TailEmission::Constant { per_block_sat: 0 } => {
                return Err(Error::Malformed("constant tail must be > 0"));
            }
            TailEmission::DecayToFloor { .. }
            | TailEmission::Constant { .. }
            | TailEmission::None => {}
        }
        // Deposit floor (Decision 10 item 3): a zero minimum would credit dust
        // and let anyone bloat the UTXO set and L2 state for free.
        if self.l2_deposit_minimum_sat == 0 {
            return Err(Error::Malformed("l2_deposit_minimum_sat must be > 0"));
        }
        // Validator committee (Decision 11): no zero keys (which would
        // silently pass signature verification) and no duplicates.
        let mut seen_keys: Vec<BlsPublicKey> = Vec::with_capacity(self.genesis_validators.len());
        for k in &self.genesis_validators {
            if k.is_zero() {
                return Err(Error::Malformed("genesis_validators contains a zero key"));
            }
            if seen_keys.contains(k) {
                return Err(Error::Malformed(
                    "genesis_validators contains duplicate keys",
                ));
            }
            seen_keys.push(*k);
        }
        let mut seen_l2_keys: Vec<BlsPublicKey> =
            Vec::with_capacity(self.l2_settlement_validators.len());
        for k in &self.l2_settlement_validators {
            if k.is_zero() {
                return Err(Error::Malformed(
                    "l2_settlement_validators contains a zero key",
                ));
            }
            if seen_l2_keys.contains(k) {
                return Err(Error::Malformed(
                    "l2_settlement_validators contains duplicate keys",
                ));
            }
            seen_l2_keys.push(*k);
        }
        if self.checkpoint_interval_blocks == 0 {
            return Err(Error::Malformed("checkpoint_interval_blocks must be > 0"));
        }
        // Epoch cadence divides in `Header::expected_epoch` and the mining
        // template path: zero is a divide-by-zero panic on profile data, so a
        // malformed profile is refused at construction instead of crashing the
        // node that loads it.
        if self.nn_epoch_blocks == 0 {
            return Err(Error::Malformed("nn_epoch_blocks must be > 0"));
        }
        // Block-shape caps gate allocation in `Chain::validate_standalone` and
        // `Block::deserialize`: zero would refuse every block (including
        // genesis) or admit nothing, so refuse the profile, not the chain.
        if self.max_tx_count == 0 {
            return Err(Error::Malformed("max_tx_count must be > 0"));
        }
        if self.max_block_bytes == 0 {
            return Err(Error::Malformed("max_block_bytes must be > 0"));
        }
        // Fee-schedule ordering: the base-fee retarget clamps into
        // `[min, max]`, so an inverted range would pin every block at an
        // unintended floor and split nodes that clamp differently.
        if self.base_fee_min_sat > self.base_fee_max_sat {
            return Err(Error::Malformed("base_fee_min_sat must not exceed base_fee_max_sat"));
        }
        if self.base_fee_initial_sat < self.base_fee_min_sat
            || self.base_fee_initial_sat > self.base_fee_max_sat
        {
            return Err(Error::Malformed(
                "base_fee_initial_sat must lie within [base_fee_min_sat, base_fee_max_sat]",
            ));
        }
        // M4 HBM parameters: validated structurally so a bad config can never
        // land in a profile that opts into puzzle_id == 2 (which would otherwise
        // panic on the modular index in `memory_hash`). See review §6. Unknown
        // puzzle ids are rejected later by `Chain::puzzle_for` / `UnknownPuzzle`.
        self.hbm.validate()?;
        // Binding finality (Decisions 12/13): an activation height must land on
        // an epoch boundary, or no epoch-aligned checkpoint could ever reach it
        // and finality would silently never activate.
        if self.finality_activation_height > 0
            && self.finality_activation_height % self.checkpoint_interval_blocks != 0
        {
            return Err(Error::Malformed(
                "finality_activation_height must be a multiple of checkpoint_interval_blocks",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_matches_design_doc_section_16() {
        let p = NetworkParams::mainnet();
        p.validate().unwrap();
        // No stock cap any more (Decision 18): mainnet is identified by its
        // ladder start, period and timing, not by a supply number.
        assert_eq!(p.start_reward_srct(), 76);
        assert_eq!(p.halving_period, 5 * 365 * 144);
        assert_eq!(p.target_block_time_ms, 10 * 60 * 1000);
        assert_eq!(
            p.genesis_difficulty, 1,
            "genesis must be trivially mineable"
        );
    }

    #[test]
    fn mainnet_bootstrap_committee_is_21_sorted_keys_with_quorum_15_and_declared_l2() {
        let p = NetworkParams::mainnet();
        p.validate().unwrap();
        assert_eq!(p.genesis_validators.len(), 21);
        assert!(p.genesis_validators.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(
            crate::bls_checkpoint::ValidatorSet::new(p.genesis_validators.clone()).quorum_size(),
            15
        );
        // Decision 28: the declared L2 settlement set is the same 21
        // bootstrap keys that secure L1 pre-bond (mini/testnet precedent).
        // The declaration is not a permanent grant — verification resolves
        // the live committee per height, so the first bond rotates L2
        // authority to the bonded TopN.
        assert_eq!(p.l2_settlement_validators, p.genesis_validators);
        assert_eq!(
            crate::bls_checkpoint::ValidatorSet::new(p.l2_settlement_validators.clone())
                .quorum_size(),
            15
        );

        // The bootstrap secrets are a pure function of their seeds and match
        // the declared keys after canonical sorting.
        let mut from_secrets: Vec<BlsPublicKey> = mainnet_committee_secrets()
            .iter()
            .map(|sk| sk.public_key())
            .collect();
        from_secrets.sort_by_key(|a| a.0);
        assert_eq!(from_secrets, p.genesis_validators);
    }

    #[test]
    fn mini_ladder_shape_matches_its_pinned_integral() {
        let p = NetworkParams::mini();
        p.validate().unwrap();
        // Was "mini_cap_is_two_halving_periods_of_rewards": the ladder's
        // *integral* is what the test pins; the cap it once computed is gone.
        assert_eq!(crate::supply::max_issuance_sat(&p), 297_924 * SAT_PER_SRCT);
        assert_eq!(p.target_block_time_ms, 1_000);
    }

    #[test]
    fn future_limit_is_one_block_time() {
        assert_eq!(NetworkParams::mainnet().future_limit_ms(), 600_000);
        assert_eq!(NetworkParams::mini().future_limit_ms(), 1_000);
    }

    #[test]
    fn profiles_resolve_by_name() {
        assert_eq!(
            NetworkParams::by_name("mini").unwrap(),
            NetworkParams::mini()
        );
        assert!(NetworkParams::by_name("nope").is_err());
    }

    #[test]
    fn network_magic_is_distinct_and_nonzero() {
        let m = NetworkParams::mainnet();
        let n = NetworkParams::mini();
        let t = NetworkParams::testnet();
        // Literal values, not derived: this is the protocol identity, and a typo
        // in a constant is exactly the mistake a self-referential test agrees
        // with. The bump moved mainnet 01 -> 02; mini/testnet shifted so every
        // profile still has a unique discriminator.
        assert_eq!(m.network_magic, [0x6A, 0x4E, 0x54, 0x02]);
        assert_eq!(n.network_magic, [0x6A, 0x4E, 0x54, 0x03]);
        assert_eq!(t.network_magic, [0x6A, 0x4E, 0x54, 0x04]);
        // The pre-bump mainnet magic must not name any live profile.
        let old_mainnet = [0x6A, 0x4E, 0x54, 0x01];
        assert_ne!(m.network_magic, old_mainnet);
        assert_ne!(n.network_magic, old_mainnet);
        assert_ne!(t.network_magic, old_mainnet);
        // Non-zero, lest a default profile silently pass for any network.
        assert_ne!(m.network_magic, [0, 0, 0, 0]);
        assert_ne!(n.network_magic, [0, 0, 0, 0]);
        // Distinct across profiles: the whole reason it exists (§13.3). Genesis
        // cannot do this job because both profiles have genesis_difficulty = 1.
        assert_ne!(m.network_magic, n.network_magic);
        assert_ne!(m.network_magic, t.network_magic);
        assert_ne!(n.network_magic, t.network_magic);
        assert_ne!(m.network_id, n.network_id);
        assert!(m.network_id.starts_with("srct/"));
    }

    #[test]
    fn genesis_hash_is_identical_across_profiles() {
        // The property that makes network_magic necessary: genesis_block() takes
        // only difficulty, and both profiles set genesis_difficulty = 1.
        let g = crate::block::genesis_block(NetworkParams::mainnet().genesis_difficulty);
        let h = crate::block::genesis_block(NetworkParams::mini().genesis_difficulty);
        assert_eq!(g.block_hash(), h.block_hash());
    }

    #[test]
    fn mainnet_genesis_is_frozen_for_the_version_bump() {
        // Re-freeze the mainnet genesis value for this protocol version. The
        // bump changes the network magic and the state wire format, neither of
        // which is a header field, so the genesis bytes stay byte-identical;
        // pinning the hash makes any accidental future drift fail here first.
        let g = crate::block::genesis_block(NetworkParams::mainnet().genesis_difficulty);
        let got: String = g.block_hash().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            "052d2f2b9fe3bdc0ccb87c9af556d8e5d0e31611e9af1195f52cb9f814ed0a5d\
             792838f1f29336517c000737536e77df21715191ed37ee2b9a727260a836aa1c"
        );
    }

    #[test]
    fn l2_fee_schedule_is_the_decided_d3_set() {
        // Written out literally rather than derived from the constants: these are
        // a decision, and a typo in a constant is exactly the mistake a
        // self-referential assertion would agree with.
        assert_eq!(
            L2_FEE_SCHEDULE,
            &[
                ("TxPostTask", 5_000u64),
                ("TxClaimTask", 2_000),
                ("TxSubmitResult", 2_000),
                ("TxDispute", 10_000),
                ("TxSettle", 1_000),
                ("TxExitQueue", 2_000),
                ("TxPolicy", 2_000),
                ("TxPolicyRevoke", 2_000),
                ("TxAgentSpend", 2_000),
                ("TxCreditOpen", 2_000),
                ("TxCreditCollateral", 2_000),
                ("TxCreditRepay", 2_000),
                ("TxCreditDefault", 2_000),
            ]
        );
    }

    /// The decision, stated as a test: L2 fees ride a flat path of their own, the
    /// L1 `base_fee * gas_used` floor is unchanged, and the two are deliberately
    /// unrelated. Fails if someone makes an L2 fee clear the gas floor (which
    /// would mean L1 and L2 had been quietly merged) or if the D3 path stops
    /// preserving the M1 invariant.
    #[test]
    fn l2_fees_do_not_use_the_l1_gas_floor() {
        use crate::fees::{required_fee, split_flat_fee};
        for profile in [NetworkParams::mainnet(), NetworkParams::mini()] {
            // The cheapest fee the L1 rule can ever charge, for the smallest
            // possible transaction.
            let floor = required_fee(profile.base_fee_min_sat, crate::tx::GAS_TX_BASE);
            assert_eq!(
                floor,
                profile.base_fee_min_sat * crate::tx::GAS_TX_BASE,
                "the L1 floor must be exactly base_fee * gas_used"
            );
            for (name, fee) in L2_FEE_SCHEDULE {
                assert!(
                    *fee < floor,
                    "{name} at {fee} sat now clears the {floor} sat L1 gas floor on {} \
                     — L2 must keep its own path, not inherit the L1 floor",
                    profile.name
                );
                let split = split_flat_fee(*fee);
                assert_eq!(split.total_fees, *fee);
                assert_eq!(split.tip, 0);
                assert_eq!(split.burned + split.pscb, *fee);
                assert_eq!(split.pscb, *fee / 2);
            }
        }
    }

    // --- L2 genesis escrow (Decision 7, SPEC.md §19.4) -----------------------

    #[test]
    fn escrow_respects_the_new_ceiling() {
        // M-E: the backing rule is an explicit validated parameter, not the
        // old implicit gap (which a tail would have invalidated).
        for p in [
            NetworkParams::mainnet(),
            NetworkParams::mini(),
            NetworkParams::testnet(),
        ] {
            p.validate().unwrap();
            assert!(
                p.l2_genesis_escrow_sat <= p.escrow_ceiling_sat,
                "{}: escrow {} exceeds ceiling {}",
                p.name,
                p.l2_genesis_escrow_sat,
                p.escrow_ceiling_sat
            );
        }
        // The shipped ceilings are exactly their allocations — tight, so the
        // parameter constrains rather than rubber-stamps.
        assert_eq!(
            NetworkParams::mainnet().escrow_ceiling_sat,
            100_000 * SAT_PER_SRCT
        );
        assert_eq!(NetworkParams::mini().escrow_ceiling_sat, 10 * SAT_PER_SRCT);
        assert_eq!(
            NetworkParams::testnet().escrow_ceiling_sat,
            10 * SAT_PER_SRCT
        );

        // Config-time refusal: an escrow above its own ceiling. The old
        // implicit `cap − max_issuance_sat` gap no longer backs anything, so
        // this is the only rule that bounds the escrow.
        let mut bad = NetworkParams::mini();
        bad.escrow_ceiling_sat = bad.l2_genesis_escrow_sat - 1;
        assert!(bad.validate().is_err(), "escrow above the ceiling");
        // A default-constructed profile with no ceiling set is refused too.
        let mut bad = NetworkParams::mini();
        bad.escrow_ceiling_sat = 0;
        assert!(bad.validate().is_err(), "zero ceiling is not a ceiling");
    }

    #[test]
    fn exit_per_owner_subcap_pairing_is_enforced() {
        // Mainnet carries the sub-cap: one owner gets a tenth of the window.
        let main = NetworkParams::mainnet();
        main.validate().unwrap();
        assert_eq!(main.max_exit_per_owner_window_sat, 100 * SAT_PER_SRCT);
        // A share bigger than the whole is nonsense.
        let mut bad = NetworkParams::mini();
        bad.max_exit_window_sat = 1_000;
        bad.exit_window_blocks = 10;
        bad.max_exit_per_owner_window_sat = 1_001;
        assert!(bad.validate().is_err());
        // A share of a window that does not exist is a half-rule.
        let mut bad = NetworkParams::mini();
        bad.max_exit_per_owner_window_sat = 100;
        assert!(bad.validate().is_err());
        // Equal to the whole is degenerate but coherent: the global cap is
        // the only bound that can ever fire first.
        let mut ok = NetworkParams::mini();
        ok.max_exit_window_sat = 1_000;
        ok.exit_window_blocks = 10;
        ok.max_exit_per_owner_window_sat = 1_000;
        ok.validate().unwrap();
    }

    #[test]
    fn tail_floor_sat_must_be_positive() {
        // §6.1 #14 (approved M-B/M-C): a zero floor or a zero constant tail
        // silently reinstates policy A — "issuance stops" — which the owner
        // rejected. `validate` is what turns that into a config error instead
        // of a consensus surprise.
        let mut bad = NetworkParams::mini();
        bad.tail = TailEmission::DecayToFloor { floor_sat: 0 };
        assert!(bad.validate().is_err());
        let mut bad = NetworkParams::mainnet();
        bad.tail = TailEmission::DecayToFloor { floor_sat: 0 };
        assert!(bad.validate().is_err());
        let mut bad = NetworkParams::mini();
        bad.tail = TailEmission::Constant { per_block_sat: 0 };
        assert!(bad.validate().is_err());

        // The shipped profiles are positive by construction, and the mainnet
        // floor is exactly the approved 0.1 SRCT.
        for p in [
            NetworkParams::mainnet(),
            NetworkParams::mini(),
            NetworkParams::testnet(),
        ] {
            p.validate().unwrap();
            let floor = match p.tail {
                TailEmission::DecayToFloor { floor_sat } => floor_sat,
                TailEmission::Constant { per_block_sat } => per_block_sat,
                TailEmission::None => panic!("{}: a shipped profile must pay a tail", p.name),
            };
            assert!(floor > 0, "{}: the tail must be positive", p.name);
        }
        assert_eq!(
            NetworkParams::mainnet().tail,
            TailEmission::DecayToFloor {
                floor_sat: 10_000_000
            }
        );
        assert_eq!(
            NetworkParams::mini().tail,
            TailEmission::Constant { per_block_sat: 1 }
        );
    }

    #[test]
    fn l2_escrow_identity_is_deterministic_and_network_bound() {
        let mini = NetworkParams::mini();
        let main = NetworkParams::mainnet();
        assert_eq!(mini.l2_escrow_address(), mini.l2_escrow_address());
        // Bound to the network: sharing an escrow identity across profiles
        // would let a mini replay claim mainnet backing.
        assert_ne!(mini.l2_escrow_address(), main.l2_escrow_address());
        assert_ne!(mini.l2_escrow_address(), [0u8; 20]);
        // No grant may collide with it.
        for g in &mini.l2_genesis_grants {
            assert_ne!(g.address, mini.l2_escrow_address());
        }
    }

    #[test]
    fn mini_grants_name_signable_operator_identities_and_sum_to_escrow() {
        let p = NetworkParams::mini();
        p.validate().unwrap();
        assert_eq!(p.l2_genesis_grants.len(), 3);
        for (i, g) in p.l2_genesis_grants.iter().enumerate() {
            // The tests hold these keys: seed i+1 must derive this address, or
            // the grant names an account nobody can operate.
            let w = crate::wallet::Wallet::from_private_key_bytes(
                &[(i + 1) as u8; 32],
                "l2-genesis-operator",
            )
            .unwrap();
            assert_eq!(g.address, w.address().unwrap());
            assert_eq!(g.amount_sat, SAT_PER_SRCT);
        }
        assert_eq!(p.l2_granted_sat().unwrap(), 3 * SAT_PER_SRCT);
        assert_eq!(p.l2_genesis_escrow_sat, 10 * SAT_PER_SRCT);
        assert!(NetworkParams::mainnet().l2_genesis_grants.is_empty());
    }

    #[test]
    fn malformed_l2_genesis_params_are_rejected() {
        let good = NetworkParams::mini();
        // Zero escrow funds nothing: not a bridge.
        let mut p = good.clone();
        p.l2_genesis_escrow_sat = 0;
        assert!(p.validate().is_err());
        // Grants above the total invent value.
        let mut p = good.clone();
        p.l2_genesis_escrow_sat = 1;
        assert!(p.validate().is_err());
        // Zero-amount grant.
        let mut p = good.clone();
        p.l2_genesis_grants[0].amount_sat = 0;
        assert!(p.validate().is_err());
        // Duplicate address pays twice.
        let mut p = good.clone();
        p.l2_genesis_grants[1].address = p.l2_genesis_grants[0].address;
        assert!(p.validate().is_err());
        // Grant to the escrow identity blurs backing and remainder.
        let mut p = good.clone();
        p.l2_genesis_grants[0].address = p.l2_escrow_address();
        assert!(p.validate().is_err());
        // Escrow above its explicit ceiling is refused (approved M-E); with
        // the stock cap gone (Decision 18) this ceiling is the only bound.
        let mut p = good.clone();
        p.l2_genesis_escrow_sat = p.escrow_ceiling_sat + 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn l2_deposit_sink_is_deterministic_network_bound_and_not_escrow() {
        let mini = NetworkParams::mini();
        let main = NetworkParams::mainnet();
        assert_eq!(mini.l2_deposit_sink(), mini.l2_deposit_sink());
        // Bound to the network: a mainnet sink output on mini is a plain burn.
        assert_ne!(mini.l2_deposit_sink(), main.l2_deposit_sink());
        assert_ne!(mini.l2_deposit_sink(), [0u8; 20]);
        // A distinct domain tag from the escrow identity, so the two can never
        // coincide and a deposit can never fund the escrow by confusion.
        assert_ne!(mini.l2_deposit_sink(), mini.l2_escrow_address());
        assert_ne!(main.l2_deposit_sink(), main.l2_escrow_address());
        // The minimum is the decided floor on both profiles.
        assert_eq!(mini.l2_deposit_minimum_sat, L2_DEPOSIT_MINIMUM_SAT);
        assert_eq!(main.l2_deposit_minimum_sat, L2_DEPOSIT_MINIMUM_SAT);
        assert_eq!(L2_DEPOSIT_MINIMUM_SAT, 1_000_000);
        // No grant may name the sink either: grants fund accounts, the sink
        // only receives burns.
        for g in &mini.l2_genesis_grants {
            assert_ne!(g.address, mini.l2_deposit_sink());
        }
        // A zero floor admits dust: refused.
        let mut p = mini.clone();
        p.l2_deposit_minimum_sat = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn degenerate_block_shape_and_epoch_profiles_are_rejected() {
        // `nn_epoch_blocks == 0` is a divide-by-zero in `expected_epoch` and
        // the mining template; `max_tx_count/max_block_bytes == 0` refuses
        // every block including genesis; inverted fee bounds pin the retarget
        // at an unintended floor. All are profile bugs, refused here rather
        // than panicking or splitting at runtime (audit: consensus-DoS).
        let good = NetworkParams::mini();
        let mut p = good.clone();
        p.nn_epoch_blocks = 0;
        assert!(p.validate().is_err());
        let mut p = good.clone();
        p.max_tx_count = 0;
        assert!(p.validate().is_err());
        let mut p = good.clone();
        p.max_block_bytes = 0;
        assert!(p.validate().is_err());
        let mut p = good.clone();
        p.base_fee_min_sat = p.base_fee_max_sat + 1;
        assert!(p.validate().is_err());
        let mut p = good.clone();
        p.base_fee_initial_sat = p.base_fee_max_sat + 1;
        assert!(p.validate().is_err());
        // Shipped profiles stay valid.
        good.validate().unwrap();
        NetworkParams::mainnet().validate().unwrap();
    }
}
