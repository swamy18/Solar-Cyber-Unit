//! `credit`: bond-backed credit terms (roadmap item 2, decision D1).
//!
//! An agent with a demonstrated record can borrow against future work instead of
//! pre-funding every transaction. **D1 fixes the shape, and it is worth stating
//! plainly because the obvious design is the wrong one:**
//!
//! | | |
//! |---|---|
//! | **Reputation** | A deterministic **view**, read off on-chain events. Never a consensus input. |
//! | **Credit** | Always **collateralized**. A posted bond *discounts* the requirement, nothing more. |
//!
//! Two rules that follow, and are the whole reason this module is safe:
//!
//! ## 1. A bond discounts the requirement; it does not replace it
//!
//! [CreditTerms::required_collateral] returns `max(base, amount - discount)`, and
//! the discount is capped at a fraction of `amount`. It never returns less than
//! `MIN_COLLATERAL_RATIO` of the amount, whatever the agent's score or bond. There
//! is **no path to a zero-collateral line**, which is what "undercollateralized"
//! means here: *under*, not *un*.
//!
//! ## 2. Reputation is an input to a lender's decision, not to a protocol rule
//!
//! The score affects the discount a lender may *offer*. It does not affect
//! `required_collateral` except through the terms the lender chose, and no
//! consensus rule reads it. This matters for a specific reason: a credit limit
//! computed on-chain from a mutable score would make every reputation update a
//! consensus event and make fresh identities farmable, which is the cheapest
//! attack against the gate and the most expensive to defend.
//!
//! The consequence, accepted deliberately: a brand-new agent with score 0 gets no
//! discount but still gets a line, because it can still post collateral. That is
//! the correct outcome — reputation buys better terms, not access. It also means
//! this module is not a Sybil surface: farming an id yields nothing, because
//! nothing gates on the id.
//!
//! # What this module is not
//!
//! Not a lending protocol. It is the arithmetic that decides *how much*
//! collateral a given position needs, and the tests that pin the invariants. The
//! position itself, its lifecycle and its settlement belong to whoever wires this
//! up — and they must be built so a default is paid out of the bond, not out of
//! the reputation.

use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Address, Hash};
use crate::ser::{Reader, Writer};
use std::collections::BTreeMap;

/// Domain tag for credit terms, so a term set can never be confused with a
/// bond, a policy or a receipt.
pub const DOM_CREDIT_TERMS: &[u8] = b"srct/credit-terms/v1";

/// Domain tag for a credit position, so a position id can never be confused
/// with a terms id or any other derived hash.
pub const DOM_CREDIT_POSITION: &[u8] = b"srct/credit-position/v1";

/// Domain tag for a credit attestation: a mint authorization's signing hash
/// never collides with terms, positions, or any other message its issuer signs.
pub const DOM_CREDIT_ATTESTATION: &[u8] = b"srct/credit-attestation/v1";

/// A trusted issuer's signed authorization to mint `amount_sat` of local
/// credit for `subject` on `network_id`, accepted only at heights
/// `issue_height ..= expires_height`. Non-consensus: it gates this node's
/// `CreditBook` only — it moves no coin and means nothing to any other node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditAttestation {
    pub network_id: String,
    pub subject: Address,
    pub amount_sat: u64,
    pub issue_height: u64,
    pub expires_height: u64,
    pub issuer: crate::bls_checkpoint::BlsPublicKey,
    pub sig: crate::bls_checkpoint::BlsSignature,
}

impl CreditAttestation {
    /// Sign an attestation. The signature covers every field — the network
    /// string included — so changing any of them invalidates it.
    pub fn sign(
        sk: &crate::bls::SecretKey,
        network_id: String,
        subject: Address,
        amount_sat: u64,
        issue_height: u64,
        expires_height: u64,
    ) -> Self {
        let mut att = CreditAttestation {
            network_id,
            subject,
            amount_sat,
            issue_height,
            expires_height,
            issuer: sk.public_key(),
            sig: crate::bls_checkpoint::BlsSignature([0u8; 96]),
        };
        att.sig = sk.sign(&att.signing_hash());
        att
    }

    /// The hash the signature covers.
    pub fn signing_hash(&self) -> Hash {
        let mut w = Writer::new();
        w.u32le(self.network_id.len() as u32)
            .raw(self.network_id.as_bytes())
            .fixed(&self.subject)
            .u64le(self.amount_sat)
            .u64le(self.issue_height)
            .u64le(self.expires_height)
            .fixed(&self.issuer.0);
        sha256_dom(DOM_CREDIT_ATTESTATION, &[w.as_slice()])
    }

    /// Verify the signature against `self.issuer`. Height, network and
    /// trusted-issuer checks are the accepting node's to make; this only says
    /// the issuer really signed this attestation.
    pub fn verify(&self) -> bool {
        crate::bls::RealBls::verify(&self.issuer, &self.signing_hash(), &self.sig)
    }
}

/// A lender's underwriting parameters for one class of position.
///
/// These are a lender's choice, set before a position is opened and immutable
/// afterwards. Nothing here is derived from the borrower's reputation — an agent
/// does not get to write the terms it is judged by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditTerms {
    /// Collateral the position holds at zero discount, as a fraction of the
    /// borrowed amount in basis points. 10 000 bp = fully collateralized.
    pub base_collateral_bps: u32,
    /// Largest discount any bond may earn, in basis points of the amount.
    pub max_discount_bps: u32,
    /// Largest share of the bond that counts toward the discount. A bond worth
    /// more than the borrowed amount cannot buy a bigger discount than one that
    /// matches it, so `required_collateral` stays proportional to `amount`.
    pub bond_ratio_bps: u32,
    /// Collateral floor as a fraction of `amount`. Never breached, by design.
    pub min_collateral_bps: u32,
}

impl Default for CreditTerms {
    /// Conservative defaults, chosen so the floor is meaningful rather than
    /// reachable: the base is full collateralization, and the largest discount
    /// leaves 80% required.
    fn default() -> Self {
        CreditTerms {
            base_collateral_bps: 10_000,
            max_discount_bps: 2_000,
            bond_ratio_bps: 2_000,
            min_collateral_bps: 8_000,
        }
    }
}

impl CreditTerms {
    /// Largest bond this lender will credit toward a discount, for a given
    /// borrowed amount. Caps the bond rather than trusting it to be bounded.
    pub fn max_creditable_bond(&self, amount_sat: u64) -> u64 {
        sat_mul_bps(amount_sat, self.bond_ratio_bps)
    }

    /// The discount a posted bond earns, before the floor is applied.
    ///
    /// A bond is real value at risk, so it discounts the requirement
    /// satoshi-for-satoshi — never more than `max_discount_bps` of the amount can
    /// be bought off, whatever the bond's size. This is a single cap, not a
    /// scaling: applying a rate to the bond as well would charge the borrower for
    /// their own collateral twice.
    ///
    /// Returns `0` with no error for a bond larger than the creditable share,
    /// rather than an error: an oversized bond is not a reason to refuse a
    /// position, it is a reason to stop counting it.
    pub fn discount_for_bond(&self, amount_sat: u64, bond_sat: u64) -> u64 {
        if amount_sat == 0 {
            return 0;
        }
        let creditable = self.max_creditable_bond(amount_sat).min(bond_sat);
        creditable.min(sat_mul_bps(amount_sat, self.max_discount_bps))
    }

    /// Collateral a position must hold to borrow `amount_sat` with `bond_sat`
    /// posted.
    ///
    /// This is the security-critical function in the module, so its properties
    /// are worth stating and are tested below:
    ///
    /// - **Never zero, and never below the floor.** Whatever the bond or the
    ///   terms, `required >= floor(amount)`.
    /// - **Never increases.** Posting more bond can lower the requirement, never
    ///   raise it.
    /// - **Monotone in amount.** Borrowing more requires more collateral.
    /// - **No overflow.** Every product is checked; a wrapped value would compare
    ///   small and pass the bound.
    ///
    /// A `CreditTerms` with `min_collateral_bps == 0` is rejected here, not just
    /// at the call site: the invariant "there is no path to a zero-collateral
    /// line" is enforced where the arithmetic lives, so a bad term set cannot be
    /// slipped past an unwary caller.
    pub fn required_collateral(&self, amount_sat: u64, bond_sat: u64) -> Result<u64> {
        if amount_sat == 0 {
            return Err(Error::Malformed(
                "a credit position borrows a positive amount",
            ));
        }
        if self.base_collateral_bps > 20_000 {
            return Err(Error::Malformed("credit terms: base collateral above 200%"));
        }
        if self.max_discount_bps > self.base_collateral_bps {
            return Err(Error::Malformed(
                "credit terms: discount may not exceed the base requirement",
            ));
        }
        if self.min_collateral_bps > self.base_collateral_bps {
            return Err(Error::Malformed(
                "credit terms: floor above the base requirement",
            ));
        }
        if self.min_collateral_bps == 0 {
            return Err(Error::Malformed(
                "credit terms: a zero collateral floor is not permitted",
            ));
        }

        // Both bounds are computed in u128: a u64 product of satoshis and basis
        // points overflows long before it looks large, and a wrapped sum would
        // compare small and pass.
        let base = (amount_sat as u128) * (self.base_collateral_bps as u128) / 10_000;
        let discount = self.discount_for_bond(amount_sat, bond_sat) as u128;
        let floor = (amount_sat as u128) * (self.min_collateral_bps as u128) / 10_000;

        let requirement = base.saturating_sub(discount).max(floor);
        if requirement > u64::MAX as u128 {
            return Err(Error::ValueOverflow);
        }
        Ok(requirement as u64)
    }

    /// Canonical encoding of the terms a position was opened under, so a
    /// settlement can be checked against the rule it was priced with.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(20);
        w.u32le(self.base_collateral_bps)
            .u32le(self.max_discount_bps)
            .u32le(self.bond_ratio_bps)
            .u32le(self.min_collateral_bps);
        w.into_vec()
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(CreditTerms {
            base_collateral_bps: r.u32le()?,
            max_discount_bps: r.u32le()?,
            bond_ratio_bps: r.u32le()?,
            min_collateral_bps: r.u32le()?,
        })
    }

    /// The terms' own identity, so a position records which rule priced it.
    pub fn id(&self) -> Hash {
        sha256_dom(DOM_CREDIT_TERMS, &[&self.encode()])
    }
}

/// An agent's position in a lender's book.
///
/// The bond is held outside this module; what it holds is what the terms priced,
/// so a settlement can be recomputed from the position alone rather than from a
/// ledger that may have moved underneath it.
/// Where a position is in its life.
///
/// Only two of these are terminal, and nothing distinguishes them except what was
/// paid and when — a caller cannot settle a terminal position again, and cannot
/// settle a live one with the other state's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PositionState {
    /// Alive: principal, interest and the amount owed are all still outstanding.
    Drawn {
        at_height: u64,
        /// Principal already repaid.
        repaid_principal_sat: u64,
        /// Interest already repaid.
        repaid_interest_sat: u64,
        /// The height up to which interest has been charged. Interest is
        /// charged once per window on the balance that was outstanding, so
        /// two instalments do not each pay for the whole elapsed time.
        /// Advanced to the repayment height on every non-terminal repay;
        /// starts at `drawn_at_height` on open.
        interest_settled_height: u64,
    },
    /// Paid off. Collateral returns to the borrower, untouched.
    Repaid {
        at_height: u64,
        interest_paid_sat: u64,
    },
    /// Not paid by the deadline. Settled as [`DefaultSettlement`].
    Defaulted {
        at_height: u64,
        settlement: DefaultSettlement,
    },
}

/// What a default actually paid, and who paid it.
///
/// Every field is a name rather than a netted number so an auditor can see *why*
/// value moved. The critical one is `from_bond_sat`: the bond is what backs a
/// default, and nothing in this module ever reaches for reputation instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DefaultSettlement {
    /// Debt at the deadline: principal plus accrued interest.
    pub debt_sat: u64,
    /// Taken from the position's own collateral.
    pub from_collateral_sat: u64,
    /// Taken from the borrower's posted bond, once collateral ran out.
    pub from_bond_sat: u64,
    /// Debt the lender absorbed because collateral and bond together were short.
    /// A default is not free, and this is the honest way to say so.
    pub shortfall_sat: u64,
    /// Collateral in excess of the debt, returned to the borrower.
    pub excess_returned_sat: u64,
}

impl DefaultSettlement {
    /// The borrower loses exactly what the default took: collateral plus bond.
    pub fn borrower_lost_sat(&self) -> u64 {
        self.from_collateral_sat + self.from_bond_sat
    }

    /// The lender recovers the debt less any shortfall, and nothing more.
    pub fn lender_recovered_sat(&self) -> u64 {
        self.debt_sat - self.shortfall_sat
    }

    /// True when the position was so overcollateralized that the borrower came
    /// out of a default with value to spare. Rare by construction, but not
    /// impossible, and taking it would be theft - so it is a reported field.
    pub fn was_overcollateralized(&self) -> bool {
        self.excess_returned_sat > 0
    }
}

/// Where credit positions and their value actually live.
///
/// A position is arithmetic; this is what makes it real. It holds three kinds of
/// value — unencumbered balances, posted bonds, and collateral locked inside live
/// positions — and it enforces the one invariant that matters:
///
/// ```text
/// free + bonds + collateral(live) + recovered(lender) == deposited
/// ```
///
/// Value is **moved, never created**. `check_conservation` is the guard, in the
/// same spirit as `L2State`'s, and it is asserted across every test below because
/// a conservation failure in a credit book is how a position acquires funds with
/// no accounting reason for them.
///
/// The bond ledger is deliberately separate from `crate::bond`'s validator bonds.
/// A validator bond secures consensus; a credit bond secures a debt. Mixing them
/// would mean a validator's stake could back an agent's borrowing, which is a
/// different risk with a different holder, and the two slashes would compete for
/// the same value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreditBook {
    /// Unencumbered balances.
    free: BTreeMap<Address, u64>,
    /// Bonds posted against future borrowing, held separately from `free` so a
    /// borrower cannot spend the very thing backing its own credit.
    bonds: BTreeMap<Address, u64>,
    /// Live and terminal positions, keyed by their derived id.
    positions: std::collections::BTreeMap<Hash, CreditPosition>,
    /// Value received by lenders: what a default's settlement covered, and what
    /// repayments paid out. The book is where a lender's earnings accumulate,
    /// and this is the running total.
    recovered: BTreeMap<Address, u64>,
    /// Every satoshi ever put in. Append-only.
    deposited_total: u64,
    /// Free-balance value committed to a settled payment (Item 10, §19.4).
    /// Debited out of `free` at settlement; the matching on-chain payout still
    /// happens only through the ordinary L1/L2 exit path, so this is a ledger
    /// liability (a committed outbound) rather than a coin move. Tracked as its
    /// own bucket so conservation (`free + bonds + collateral + recovered +
    /// settled_payments == deposited`) survives a settlement debit.
    settled_payments: u64,
    /// Bond value already pledged as the discount backing of a live position.
    ///
    /// Sub-accounting of `bonds`, not a second value: the satoshis stay in
    /// `bonds`, and only `bond - bond_pledged` may price the *next* position.
    /// Without this, one posted bond could back any number of positions, each of
    /// which would claim the same discount — the bond would be counted once per
    /// obligation it secures, which is exactly what a bond must never be.
    bond_pledged: BTreeMap<Address, u64>,
    /// Free-balance value encumbered by an outstanding reservation.
    ///
    /// A reservation must *reduce* spendable capacity the moment it is granted,
    /// or two payments can each reserve the same balance, both be admitted, and
    /// only one of them can ever be debited. Moving the value into `reserved`
    /// makes capacity exact: it is neither spendable nor settled, and it is the
    /// bucket `settle` debits.
    reserved: BTreeMap<Address, u64>,
    /// Outstanding principal headroom encumbered by reservations drawn against a
    /// live position (same rule as `reserved`, per position).
    position_reserved: BTreeMap<Hash, u64>,
    /// Reservation ids that have already been consumed, and how.
    ///
    /// A settlement must be idempotent and a released reservation must not be
    /// settleable afterwards, so the book records the outcome per reservation
    /// instead of trusting the caller to call once. Bounded: the log is a FIFO
    /// cap-with-eviction, so a flood of reservations cannot grow it forever.
    reservation_log: BTreeMap<Hash, ReservationOutcome>,
    /// Reservations created and not yet consumed.
    ///
    /// The outcome log alone cannot tell "consumed long ago, evicted" from
    /// "never existed": after an eviction both read as absent, and a replay
    /// would debit again. Settle and release therefore require membership
    /// here (removed on consume); the log only decides replays of ids it
    /// still holds. Runtime-only on purpose: on restart the node re-marks
    /// every reservation its persisted map still holds, so no format change
    /// is needed and an upgrade never strands in-flight reservations.
    outstanding: std::collections::BTreeSet<Hash>,
    /// Insertion order for the reservation log, so eviction is deterministic.
    reservation_order: std::collections::VecDeque<Hash>,
    /// Monotonic reservation counter. Every reservation gets its own id, so two
    /// payments from one payer at one height are never conflated.
    reservation_seq: u64,
}

/// What a consumed reservation was used for. Replay of either is refused by
/// name rather than silently applied twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationOutcome {
    /// Settled: the debit landed.
    Settled,
    /// Released: the payment never committed and the encumbrance returned.
    Released,
}

/// Longest reservation log. Old entries are evicted first, so a node that
/// settles a bounded number of payments has an exact replay guard and a node
/// that settles a million does not grow without bound.
const MAX_RESERVATION_LOG: usize = 4_096;

impl CreditBook {
    /// An empty book.
    ///
    /// The explicit trait path is load-bearing: this book has an inherent
    /// `default` that settles positions, and bare `CreditBook::default()` would
    /// resolve to *that*, three arguments short.
    pub fn new() -> Self {
        <CreditBook as Default>::default()
    }

    /// Credit an agent's balance. This is the only way value enters the book.
    pub fn deposit(&mut self, agent: Address, amount_sat: u64) -> Result<()> {
        let e = self.free.entry(agent).or_insert(0);
        *e = e.checked_add(amount_sat).ok_or(Error::ValueOverflow)?;
        self.deposited_total = self
            .deposited_total
            .checked_add(amount_sat)
            .ok_or(Error::ValueOverflow)?;
        Ok(())
    }

    /// Free (unencumbered) balance.
    pub fn free(&self, agent: &Address) -> u64 {
        self.free.get(agent).copied().unwrap_or(0)
    }

    /// Bond posted by an agent.
    pub fn bond(&self, agent: &Address) -> u64 {
        self.bonds.get(agent).copied().unwrap_or(0)
    }

    /// Bond an agent may still pledge to a *new* position: the posted bond less
    /// what live positions have already claimed.
    ///
    /// This is the number a position's discount must be priced against, not the
    /// gross bond. A bond is real value at risk, and counting it once per
    /// obligation it secures would let one bond discount any number of positions
    /// — the arithmetic of an undercollateralized line wearing a discount's
    /// clothes.
    pub fn unpledged_bond(&self, agent: &Address) -> u64 {
        self.bond(agent)
            .saturating_sub(self.bond_pledged.get(agent).copied().unwrap_or(0))
    }

    /// Free balance an agent may still spend.
    ///
    /// An outstanding reservation has already had its value moved out of `free`,
    /// so the unencumbered balance is simply what is left in `free`. This is the
    /// number a new payment or a new position's collateral is checked against.
    pub fn available(&self, agent: &Address) -> u64 {
        self.free(agent)
    }

    /// Post a bond from the agent's free balance.
    ///
    /// A bond cannot be posted from itself: it comes out of free money, or it is
    /// nothing. That is also what stops a borrower from uncollateralizing by
    /// moving value into a bond and out of reach of the position.
    pub fn post_bond(&mut self, agent: Address, amount_sat: u64) -> Result<()> {
        if amount_sat == 0 {
            return Err(Error::Malformed(
                "a bond posts a positive amount; zero is a client error, not a no-op",
            ));
        }
        if self.free(&agent) < amount_sat {
            return Err(Error::Malformed(
                "free balance cannot cover the bond being posted",
            ));
        }
        // `entry().or_insert(0)` rather than `get_mut().unwrap()`: a missing
        // entry is a borrower this book has never seen, and an unwrap there is
        // a panic reachable from the API's JSON surface. The balance check
        // above already guarantees the subtraction cannot underflow.
        let f = self.free.entry(agent).or_insert(0);
        *f -= amount_sat;
        let b = self.bonds.entry(agent).or_insert(0);
        *b = b.checked_add(amount_sat).ok_or(Error::ValueOverflow)?;
        self.check_conservation()
    }

    /// Release a bond back to the agent's free balance.
    ///
    /// Refuses to release bond that a live position is *priced with*: that
    /// portion is at risk for the position it secures, and releasing it would
    /// leave the position's discount unbacked — the exact defect the pledge
    /// accounting exists to prevent.
    pub fn release_bond(&mut self, agent: Address, amount_sat: u64) -> Result<()> {
        if amount_sat == 0 {
            return Err(Error::Malformed(
                "a bond release moves a positive amount; zero is a client error, not a no-op",
            ));
        }
        if self.bond(&agent) < amount_sat {
            return Err(Error::Malformed(
                "no posted bond covers the release requested",
            ));
        }
        if amount_sat > self.unpledged_bond(&agent) {
            return Err(Error::Malformed(
                "bond pledged to a live position cannot be released",
            ));
        }
        // `entry().or_insert(0)` rather than `get_mut().unwrap()`: with the
        // checks above the entry is guaranteed to exist, but reaching for the
        // key makes the failure mode a panic instead of an unreachable branch.
        let b = self.bonds.entry(agent).or_insert(0);
        *b -= amount_sat;
        let f = self.free.entry(agent).or_insert(0);
        *f = f.checked_add(amount_sat).ok_or(Error::ValueOverflow)?;
        self.check_conservation()
    }

    /// Open a position, locking its collateral out of the borrower's free balance.
    ///
    /// Three upstream requirements, all enforced here rather than assumed:
    ///
    /// - The bond the position is priced with must be **posted first**. A bond
    ///   that exists only in the spec buys a discount the borrower never backed,
    ///   which is undercollateralization wearing a discount's clothes.
    /// - That bond must be **unpledged**. A bond already backing a live position
    ///   has discounted that position; counting it again would let one bond
    ///   secure any number of obligations.
    /// - The collateral must be in the borrower's free balance, because this is
    ///   where it leaves it.
    ///
    /// The bond itself is *credited* rather than moved: it stays posted, and the
    /// terms only count it toward the discount. A position therefore never
    /// becomes able to spend the bond backing it — and the pledge release on
    /// settlement is what makes that safe over the whole book.
    pub fn open(&mut self, spec: &PositionSpec) -> Result<Hash> {
        let id = spec.id();
        if self.positions.contains_key(&id) {
            return Err(Error::Malformed("this position is already open"));
        }
        let position = CreditPosition::open(spec)?;
        if spec.bond_sat > self.unpledged_bond(&spec.borrower) {
            return Err(Error::Malformed(
                "the bond a position is priced with must be posted, and unpledged, before it opens",
            ));
        }
        if self.available(&spec.borrower) < position.collateral_sat {
            return Err(Error::Malformed(
                "free balance cannot cover the collateral required",
            ));
        }
        let f = self.free.entry(spec.borrower).or_insert(0);
        *f -= position.collateral_sat;
        // Pledge the bond: it is at risk for this position until the position
        // settles, and no second position may price against the same satoshis.
        let pledged = self.bond_pledged.entry(spec.borrower).or_insert(0);
        *pledged = pledged
            .checked_add(spec.bond_sat)
            .ok_or(Error::ValueOverflow)?;
        self.positions.insert(id, position);
        self.check_conservation()?;
        Ok(id)
    }

    /// Release the bond pledge a settled position held, returning it to the
    /// pool a new position may price against. Value does not move: only the
    /// sub-accounting of who has claimed the discount.
    fn release_pledge(&mut self, borrower: Address, pledged_sat: u64) -> Result<()> {
        if pledged_sat == 0 {
            return Ok(());
        }
        let pledged = self.bond_pledged.entry(borrower).or_insert(0);
        *pledged = pledged.saturating_sub(pledged_sat);
        if *pledged == 0 {
            self.bond_pledged.remove(&borrower);
        }
        self.check_conservation()
    }

    /// Look a position up.
    pub fn position(&self, id: &Hash) -> Option<&CreditPosition> {
        self.positions.get(id)
    }

    /// Every live position. Terminal ones stay in the book for the record but are
    /// not iterated here, because nothing can change them.
    pub fn live_positions(&self) -> impl Iterator<Item = (&Hash, &CreditPosition)> {
        self.positions.iter().filter(|(_, p)| !p.is_terminal())
    }

    /// Every position, live and terminal, in id order. Read-only views
    /// (repayment history, lender dashboards) iterate here; nothing here
    /// changes a position.
    pub fn positions(&self) -> impl Iterator<Item = (&Hash, &CreditPosition)> {
        self.positions.iter()
    }

    /// Repay against a position.
    ///
    /// The payment comes from the borrower's free balance and lands with the
    /// lender. A caller that wants to fund a repayment from elsewhere must
    /// deposit first; accepting an unfunded payment would let a position settle
    /// without the value existing.
    pub fn repay(&mut self, id: &Hash, payment_sat: u64, height: u64) -> Result<Repayment> {
        // Charge and read the parties before touching the position, so a
        // refusal leaves the position untouched and no borrow outlives its scope.
        let (borrower, lender) = {
            let position = self
                .positions
                .get(id)
                .ok_or(Error::Malformed("no such position"))?;
            (position.borrower, position.lender)
        };
        if self.available(&borrower) < payment_sat {
            return Err(Error::Malformed("free balance cannot cover the repayment"));
        }
        let result = {
            let position = self
                .positions
                .get_mut(id)
                .ok_or(Error::Malformed("no such position"))?;
            position.repay(payment_sat, height)?
        };
        // `entry().or_insert(0)` rather than `get_mut().unwrap()`: a zero
        // payment against a borrower whose free balance is already fully
        // encumbered reaches here with no `free` entry at all, and the check
        // above guarantees the subtraction cannot underflow.
        let f = self.free.entry(borrower).or_insert(0);
        *f -= payment_sat;

        // The lender is paid: the value left the borrower and it went somewhere,
        // which is the half of conservation a repayment has to get right.
        let paid = self.recovered.entry(lender).or_insert(0);
        *paid = paid.checked_add(payment_sat).ok_or(Error::ValueOverflow)?;

        // A fully repaid position returns its collateral to the borrower. The
        // repayment says whether it settled; the position holds the collateral.
        if result.remaining_debt_sat == 0 {
            let (returned, pledge) = {
                let position = self
                    .positions
                    .get(id)
                    .ok_or(Error::Malformed("no such position"))?;
                (position.collateral_sat, position.bond_sat)
            };
            if returned > 0 {
                let f = self.free.entry(borrower).or_insert(0);
                *f = f.checked_add(returned).ok_or(Error::ValueOverflow)?;
            }
            // The debt is gone, so the bond that discounted it is no longer at
            // risk and may price the next position.
            self.release_pledge(borrower, pledge)?;
        }
        self.check_conservation()?;
        Ok(result)
    }

    /// Default a position at its deadline.
    ///
    /// Order of payment is the settlement's own, unchanged: collateral first,
    /// then the bond, never reputation. The difference here is that the bond is
    /// *actually taken* — this is where a default's values leave the locked
    /// pools, and the conservation check confirms exactly where they land.
    ///
    /// Everything is computed and pre-checked *before* any bucket is written, so
    /// a refusal (a posted bond smaller than the default requires) leaves the
    /// book exactly as it was rather than half-settled.
    pub fn default(&mut self, id: &Hash, height: u64) -> Result<DefaultSettlement> {
        // Read everything, and refuse on every condition, before mutating. The
        // pure arithmetic lives on the position so the book can price the
        // settlement without committing it — an early return after a mutation is
        // how a book ends up half-settled.
        let (settlement, borrower, lender, pledge) = {
            let position = self
                .positions
                .get(id)
                .ok_or(Error::Malformed("no such position"))?;
            (
                position.simulate_default(height)?,
                position.borrower,
                position.lender,
                position.bond_sat,
            )
        };
        if settlement.from_bond_sat > self.bond(&borrower) {
            return Err(Error::Malformed(
                "posted bond is smaller than the default requires",
            ));
        }

        // The position settles; from here on every write is unconditional.
        self.positions
            .get_mut(id)
            .ok_or(Error::Malformed("no such position"))?
            .default(height)?;

        let f = self.free.entry(borrower).or_insert(0);
        *f = f
            .checked_add(settlement.excess_returned_sat)
            .ok_or(Error::ValueOverflow)?;
        if settlement.from_bond_sat > 0 {
            let b = self
                .bonds
                .get_mut(&borrower)
                .ok_or(Error::Malformed("no posted bond to take the default from"))?;
            *b -= settlement.from_bond_sat;
        }
        let r = self.recovered.entry(lender).or_insert(0);
        *r = r
            .checked_add(settlement.lender_recovered_sat())
            .ok_or(Error::ValueOverflow)?;
        // The whole pledge is retired with the position: the part the default
        // consumed is already out of `bonds`, and the part it did not consume
        // returns to the pool a new position may price against.
        self.release_pledge(borrower, pledge)?;
        self.check_conservation()?;
        Ok(settlement)
    }

    /// Value a lender has received — recovered from defaults and paid out by
    /// repayments alike.
    pub fn recovered(&self, lender: &Address) -> u64 {
        self.recovered.get(lender).copied().unwrap_or(0)
    }

    /// Collateral currently locked inside live positions.
    fn locked_collateral(&self) -> u64 {
        self.positions
            .values()
            .filter(|p| !p.is_terminal())
            .fold(0u64, |acc, p| acc.saturating_add(p.collateral_sat))
    }

    /// The invariant: value is moved, never created.
    ///
    /// A failed check is a bug, not a policy disagreement, which is why it
    /// returns an error rather than a bool — a caller that cannot proceed on
    /// failure must not be able to ignore it.
    ///
    /// `reserved` is a bucket of its own because an outstanding reservation is
    /// neither spendable nor settled: counting it inside `free` would let one
    /// balance back two admitted payments, and dropping it would make the
    /// invariant fail the moment a reservation is made.
    pub fn check_conservation(&self) -> Result<()> {
        let accounted = self
            .free
            .values()
            .chain(self.bonds.values())
            .fold(0u64, |acc, v| acc.saturating_add(*v))
            .saturating_add(self.locked_collateral())
            .saturating_add(
                self.recovered
                    .values()
                    .fold(0u64, |acc, v| acc.saturating_add(*v)),
            )
            .saturating_add(self.settled_payments)
            .saturating_add(
                self.reserved
                    .values()
                    .fold(0u64, |acc, v| acc.saturating_add(*v)),
            );
        if accounted != self.deposited_total {
            return Err(Error::Malformed(
                "credit conservation: accounted value does not equal deposited",
            ));
        }
        Ok(())
    }

    /// Totals, for diagnostics and for asserting the invariant directly.
    pub fn total_deposited(&self) -> u64 {
        self.deposited_total
    }

    pub fn total_locked_collateral(&self) -> u64 {
        self.locked_collateral()
    }

    /// Value committed to settled (outbound) payments. See [`Self::settled_payments`].
    pub fn total_settled(&self) -> u64 {
        self.settled_payments
    }
}

/// A codec for a whole position, so a node can serve one and a worker can read it.
impl CreditPosition {
    /// Canonical encoding. Self-delimiting: the attestation-free fields are
    /// fixed-size or written by their own encoders, so `decode` never guesses.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(256);
        w.fixed(&self.borrower)
            .fixed(&self.agent_id)
            .fixed(&self.lender)
            .raw(&self.terms.encode())
            .u32le(self.charge.rate_bps_per_window)
            .u64le(self.charge.window_blocks)
            .u64le(self.amount_sat)
            .u64le(self.bond_sat)
            .u64le(self.collateral_sat)
            .u64le(self.drawn_at_height)
            .u64le(self.deadline_height);
        match &self.state {
            PositionState::Drawn {
                at_height,
                repaid_principal_sat,
                repaid_interest_sat,
                interest_settled_height,
            } => {
                w.u8(WIRE_DRAWN_V2)
                    .u64le(*at_height)
                    .u64le(*repaid_principal_sat)
                    .u64le(*repaid_interest_sat)
                    .u64le(*interest_settled_height);
            }
            PositionState::Repaid {
                at_height,
                interest_paid_sat,
            } => {
                w.u8(WIRE_REPAID)
                    .u64le(*at_height)
                    .u64le(*interest_paid_sat);
            }
            PositionState::Defaulted {
                at_height,
                settlement,
            } => {
                w.u8(WIRE_DEFAULTED).u64le(*at_height);
                w.u64le(settlement.debt_sat)
                    .u64le(settlement.from_collateral_sat)
                    .u64le(settlement.from_bond_sat)
                    .u64le(settlement.shortfall_sat)
                    .u64le(settlement.excess_returned_sat);
            }
        }
        w.into_vec()
    }

    /// Decode what [`CreditPosition::encode`] wrote. Bounded and fail-closed.
    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self> {
        let borrower = r.fixed()?;
        let agent_id = r.fixed()?;
        let lender = r.fixed()?;
        let terms = CreditTerms::decode(r)?;
        let charge = ChargeSchedule {
            rate_bps_per_window: r.u32le()?,
            window_blocks: r.u64le()?,
        };
        let amount_sat = r.u64le()?;
        let bond_sat = r.u64le()?;
        let collateral_sat = r.u64le()?;
        let drawn_at_height = r.u64le()?;
        let deadline_height = r.u64le()?;
        let state = match r.u8()? {
            // Pre-settlement-marker blobs settle interest from draw: that
            // reproduces exactly the debt those blobs computed, so loading
            // old state never jumps what anyone owes — later repays settle
            // forward from there.
            WIRE_DRAWN => {
                let at_height = r.u64le()?;
                let repaid_principal_sat = r.u64le()?;
                let repaid_interest_sat = r.u64le()?;
                PositionState::Drawn {
                    at_height,
                    repaid_principal_sat,
                    repaid_interest_sat,
                    interest_settled_height: drawn_at_height,
                }
            }
            WIRE_DRAWN_V2 => PositionState::Drawn {
                at_height: r.u64le()?,
                repaid_principal_sat: r.u64le()?,
                repaid_interest_sat: r.u64le()?,
                interest_settled_height: r.u64le()?,
            },
            WIRE_REPAID => PositionState::Repaid {
                at_height: r.u64le()?,
                interest_paid_sat: r.u64le()?,
            },
            WIRE_DEFAULTED => {
                let at_height = r.u64le()?;
                let settlement = DefaultSettlement {
                    debt_sat: r.u64le()?,
                    from_collateral_sat: r.u64le()?,
                    from_bond_sat: r.u64le()?,
                    shortfall_sat: r.u64le()?,
                    excess_returned_sat: r.u64le()?,
                };
                PositionState::Defaulted {
                    at_height,
                    settlement,
                }
            }
            _ => return Err(Error::Malformed("unknown position state tag")),
        };
        Ok(CreditPosition {
            borrower,
            agent_id,
            lender,
            terms,
            charge,
            amount_sat,
            bond_sat,
            collateral_sat,
            drawn_at_height,
            deadline_height,
            state,
        })
    }
}

const WIRE_DRAWN: u8 = 0;
const WIRE_REPAID: u8 = 1;
const WIRE_DEFAULTED: u8 = 2;
/// `Drawn` with the interest-settlement marker. Old `WIRE_DRAWN` blobs still
/// decode (settling from draw), so persisted books load without migration.
const WIRE_DRAWN_V2: u8 = 3;

/// Maximum entries the book codec will read back per map. The book is bounded by
/// what a node's own depositors created, but a decoded count still has to be
/// checked against the bytes actually present before anything is allocated.
const MAX_BOOK_ENTRIES: usize = 1 << 20;

/// Restart recovery for the whole book.
///
/// The book is node-local and non-consensus, but losing it loses every free
/// balance, posted bond, locked position and outstanding reservation a node has
/// accepted — so it is encodable and decodable, and a restart round-trips byte
/// for byte with the conservation invariant intact.
impl CreditBook {
    /// Canonical encoding of the whole book.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(512);
        Self::encode_u64_map(&mut w, &self.free);
        Self::encode_u64_map(&mut w, &self.bonds);
        Self::encode_u64_map(&mut w, &self.bond_pledged);
        Self::encode_u64_map(&mut w, &self.reserved);
        Self::encode_u64_map(&mut w, &self.recovered);
        w.u64le(self.deposited_total).u64le(self.settled_payments);
        w.u64le(self.reservation_seq);
        // Positions, keyed by their derived id: an id is part of the record, so
        // a book that round-trips keeps pointing at the same positions.
        w.u32le(self.positions.len() as u32);
        for (id, position) in &self.positions {
            w.fixed(id);
            let bytes = position.encode();
            w.u32le(bytes.len() as u32).raw(&bytes);
        }
        w.u32le(self.position_reserved.len() as u32);
        for (id, amount) in &self.position_reserved {
            w.fixed(id).u64le(*amount);
        }
        w.u32le(self.reservation_log.len() as u32);
        for (id, outcome) in &self.reservation_log {
            w.fixed(id).u8(match outcome {
                ReservationOutcome::Settled => 0,
                ReservationOutcome::Released => 1,
            });
        }
        w.into_vec()
    }

    fn encode_u64_map(w: &mut crate::ser::Writer, map: &BTreeMap<Address, u64>) {
        w.u32le(map.len() as u32);
        for (addr, amount) in map {
            w.fixed(addr).u64le(*amount);
        }
    }

    /// Decode what [`CreditBook::encode`] wrote. Bounded and fail-closed: a
    /// declared count beyond the cap, a truncated field, or trailing bytes
    /// produce an error rather than a half-built book.
    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self> {
        let free = Self::decode_u64_map(r)?;
        let bonds = Self::decode_u64_map(r)?;
        let bond_pledged = Self::decode_u64_map(r)?;
        let reserved = Self::decode_u64_map(r)?;
        let recovered = Self::decode_u64_map(r)?;
        let deposited_total = r.u64le()?;
        let settled_payments = r.u64le()?;
        let reservation_seq = r.u64le()?;
        let mut book = CreditBook {
            free,
            bonds,
            bond_pledged,
            reserved,
            recovered,
            deposited_total,
            settled_payments,
            reservation_seq,
            ..CreditBook::new()
        };
        let positions = r.u32le()? as usize;
        if positions > MAX_BOOK_ENTRIES {
            return Err(Error::Malformed("credit book position count over cap"));
        }
        for _ in 0..positions {
            let id: Hash = r.fixed()?;
            // Length-prefixed so a lying count cannot read past the buffer, and
            // so the position's own decoder sees exactly its own bytes.
            let len = r.u32le()? as usize;
            if len > MAX_BOOK_ENTRIES * 256 {
                return Err(Error::Malformed("credit book position over cap"));
            }
            let bytes = r.fixed_slice(len)?;
            let mut sub = crate::ser::Reader::new(bytes);
            let position = CreditPosition::decode(&mut sub)?;
            if sub.remaining() != 0 {
                return Err(Error::Malformed("credit book position has trailing bytes"));
            }
            book.positions.insert(id, position);
        }
        let position_reserved = r.u32le()? as usize;
        if position_reserved > MAX_BOOK_ENTRIES {
            return Err(Error::Malformed("credit book reservation count over cap"));
        }
        for _ in 0..position_reserved {
            let id: Hash = r.fixed()?;
            book.position_reserved.insert(id, r.u64le()?);
        }
        let log = r.u32le()? as usize;
        if log > MAX_RESERVATION_LOG {
            return Err(Error::Malformed("credit book reservation log over cap"));
        }
        for _ in 0..log {
            let id: Hash = r.fixed()?;
            let outcome = match r.u8()? {
                0 => ReservationOutcome::Settled,
                1 => ReservationOutcome::Released,
                _ => return Err(Error::Malformed("unknown reservation outcome tag")),
            };
            book.reservation_order.push_back(id);
            book.reservation_log.insert(id, outcome);
        }
        // A restored book must satisfy the invariant it was saved under, or the
        // bytes were not a book at all.
        book.check_conservation()?;
        Ok(book)
    }

    fn decode_u64_map(r: &mut crate::ser::Reader<'_>) -> Result<BTreeMap<Address, u64>> {
        let count = r.u32le()? as usize;
        if count > MAX_BOOK_ENTRIES {
            return Err(Error::Malformed("credit book entry count over cap"));
        }
        let mut map = BTreeMap::new();
        for _ in 0..count {
            let addr: Address = r.fixed()?;
            map.insert(addr, r.u64le()?);
        }
        Ok(map)
    }
}

/// What a repayment did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repayment {
    pub interest_paid_sat: u64,
    pub principal_paid_sat: u64,
    /// Debt still outstanding. Zero only when the position settled.
    pub remaining_debt_sat: u64,
}

/// A charge schedule for a position: simple interest, charged per whole window.
///
/// Deterministic by construction — `accrued_interest` depends only on heights, so
/// every node recomputes the same figure. No sub-window fractions, which would
/// otherwise make the total depend on rounding order rather than on time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChargeSchedule {
    /// Interest per window in basis points of the outstanding principal.
    pub rate_bps_per_window: u32,
    /// Length of a window in blocks.
    pub window_blocks: u64,
}

impl ChargeSchedule {
    /// Interest owed on `principal` between `from_height` and `to_height`.
    ///
    /// Refuses a backwards window rather than returning zero: a negative elapsed
    /// time is a caller error, and zero would silently forgive it.
    pub fn accrued_interest(
        &self,
        principal_sat: u64,
        from_height: u64,
        to_height: u64,
    ) -> Result<u64> {
        if to_height < from_height {
            return Err(Error::Malformed(
                "credit interest computed over a backwards window",
            ));
        }
        let windows = (to_height - from_height) / self.window_blocks.max(1);
        if windows == 0 || principal_sat == 0 {
            return Ok(0);
        }
        // Checked in u128: the triple product overflows u128 for adversarial
        // (principal, rate, windows) — a wrapped or silently capped value would
        // undercharge interest and diverge between debug (panic) and release
        // (wrap) builds, so overflow is a refusal, not a number.
        let units = (principal_sat as u128)
            .checked_mul(self.rate_bps_per_window as u128)
            .and_then(|v| v.checked_mul(windows as u128))
            .ok_or(Error::ValueOverflow)?;
        let scaled = units / 10_000;
        u64::try_from(scaled).map_err(|_| Error::ValueOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditPosition {
    pub borrower: Address,
    /// The agent id the reputation view is read for. Informational: nothing in
    /// `required_collateral` reads it, per D1.
    pub agent_id: Hash,
    pub lender: Address,
    pub terms: CreditTerms,
    /// Satoshi borrowed.
    pub amount_sat: u64,
    /// Satoshi of bond credited at open time.
    pub bond_sat: u64,
    /// Collateral the position must hold, priced at open time.
    pub collateral_sat: u64,
    /// Height the position was drawn at.
    pub drawn_at_height: u64,
    /// Height the position must be repaid by. Before it, `default` is refused;
    /// at or after it, an unpaid position may be settled. A deadline before the
    /// draw is a caller error, not a position that is already due.
    pub deadline_height: u64,
    /// The charge schedule the position was opened under.
    pub charge: ChargeSchedule,
    pub state: PositionState,
}

/// What a position is opened from.
///
/// A struct rather than nine positional arguments: `open` takes enough context
/// that a caller transposing two `Address` arguments is a real mistake, and the
/// spec is what a node deserializes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionSpec {
    pub terms: CreditTerms,
    pub charge: ChargeSchedule,
    pub borrower: Address,
    pub agent_id: Hash,
    pub lender: Address,
    /// Satoshi borrowed.
    pub amount_sat: u64,
    /// Satoshi of bond pledged, credited toward the collateral discount.
    pub bond_sat: u64,
    pub drawn_at_height: u64,
    /// Height the position must be repaid by. Before it, `default` is refused;
    /// at or after it, an unpaid position may be settled. A deadline before the
    /// draw is a caller error, not a position that is already due.
    pub deadline_height: u64,
}

impl PositionSpec {
    /// The position's derived id, over every field that makes it what it is.
    ///
    /// Deterministic and position-specific, so two positions that differ in any
    /// term are different positions. One position id, ever: a caller cannot
    /// re-open an existing one.
    pub fn id(&self) -> Hash {
        sha256_dom(DOM_CREDIT_POSITION, &[&self.encode()])
    }

    /// Canonical encoding of the whole spec, so the id is over stable bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(168);
        w.raw(&self.terms.encode())
            .u32le(self.charge.rate_bps_per_window)
            .u64le(self.charge.window_blocks)
            .fixed(&self.borrower)
            .fixed(&self.agent_id)
            .fixed(&self.lender)
            .u64le(self.amount_sat)
            .u64le(self.bond_sat)
            .u64le(self.drawn_at_height)
            .u64le(self.deadline_height);
        w.into_vec()
    }

    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self> {
        let terms = CreditTerms::decode(r)?;
        let charge = ChargeSchedule {
            rate_bps_per_window: r.u32le()?,
            window_blocks: r.u64le()?,
        };
        Ok(PositionSpec {
            terms,
            charge,
            borrower: r.fixed()?,
            agent_id: r.fixed()?,
            lender: r.fixed()?,
            amount_sat: r.u64le()?,
            bond_sat: r.u64le()?,
            drawn_at_height: r.u64le()?,
            deadline_height: r.u64le()?,
        })
    }
}

impl CreditPosition {
    /// Price a position, refusing one that cannot be collateralized.
    ///
    /// Note what is absent from [`PositionSpec`]: any reputation score. That is
    /// D1's invariant rather than an omission, and it is easier to keep absent
    /// than to keep ignored - an earlier shape of this function took a
    /// `ReputationScore` and discarded it, which put the dependency one careless
    /// caller away from becoming real.
    pub fn open(spec: &PositionSpec) -> Result<Self> {
        if spec.deadline_height < spec.drawn_at_height {
            return Err(Error::Malformed(
                "a position cannot mature before it is drawn",
            ));
        }
        let collateral_sat = spec
            .terms
            .required_collateral(spec.amount_sat, spec.bond_sat)?;
        Ok(CreditPosition {
            borrower: spec.borrower,
            agent_id: spec.agent_id,
            lender: spec.lender,
            terms: spec.terms,
            amount_sat: spec.amount_sat,
            bond_sat: spec.bond_sat,
            collateral_sat,
            drawn_at_height: spec.drawn_at_height,
            deadline_height: spec.deadline_height,
            charge: spec.charge,
            state: PositionState::Drawn {
                at_height: spec.drawn_at_height,
                repaid_principal_sat: 0,
                repaid_interest_sat: 0,
                interest_settled_height: spec.drawn_at_height,
            },
        })
    }

    /// Collateral still required, if the terms were recomputed at a new bond.
    /// Only ever falls, because `CreditTerms` guarantees monotonicity.
    pub fn reprice(&self, new_bond_sat: u64) -> Result<u64> {
        self.terms
            .required_collateral(self.amount_sat, new_bond_sat)
    }

    /// True once the position can no longer change: repaid or defaulted.
    pub fn is_terminal(&self) -> bool {
        !matches!(self.state, PositionState::Drawn { .. })
    }

    /// Principal still outstanding on a live position. Zero for a settled one.
    fn outstanding_principal(&self) -> u64 {
        match self.state {
            PositionState::Drawn {
                repaid_principal_sat,
                ..
            } => self.amount_sat.saturating_sub(repaid_principal_sat),
            _ => 0,
        }
    }

    /// The debt at `height`: outstanding principal plus accrued interest less
    /// whatever has already been repaid.
    ///
    /// Interest accrues on the outstanding balance *since the last
    /// settlement*, not since draw: interest on repaid principal stops the
    /// moment that principal is repaid, exactly like the L2 book (the two
    /// implementations of the same rule must agree — L2 settles the marker
    /// forward on every repay, and so does this).
    ///
    /// `repaid_interest_sat` is a receipt total, not a subtrahend: each
    /// repay settles its window, so only the current window's accrual is
    /// ever owed. A partial interest payment settles the window too (the
    /// remainder is forgiven, as in L2) — the borrower still cannot pay
    /// more than the debt, and the lender's receipt total stays exact.
    pub fn debt_at(&self, height: u64) -> Result<u64> {
        match self.state {
            PositionState::Drawn {
                repaid_principal_sat,
                interest_settled_height,
                ..
            } => {
                let outstanding_principal = self
                    .amount_sat
                    .checked_sub(repaid_principal_sat)
                    .ok_or(Error::Malformed("repaid more principal than borrowed"))?;
                let accrued = self.charge.accrued_interest(
                    outstanding_principal,
                    interest_settled_height,
                    height,
                )?;
                accrued
                    .checked_add(outstanding_principal)
                    .ok_or(Error::ValueOverflow)
            }
            _ => Err(Error::Malformed("a settled position has no debt")),
        }
    }

    /// Repay against the debt, interest first.
    ///
    /// Returns what the payment did, never more than the debt. Overpayment is
    /// refused rather than silently clipped: a caller paying more than they owe
    /// is paying the wrong amount, and quietly accepting the surplus is how
    /// positions acquire funds with no accounting reason for them.
    pub fn repay(&mut self, payment_sat: u64, height: u64) -> Result<Repayment> {
        let (mut repaid_principal, mut repaid_interest) = match self.state {
            PositionState::Drawn {
                repaid_principal_sat,
                repaid_interest_sat,
                ..
            } => (repaid_principal_sat, repaid_interest_sat),
            _ => return Err(Error::Malformed("a settled position cannot be repaid")),
        };

        let debt = self.debt_at(height)?;
        if payment_sat > debt {
            return Err(Error::Malformed("repayment exceeds the debt owed"));
        }

        // Interest first, then principal. Paying principal down before the
        // lender's own charge would leave that charge unpaid, and the borrower
        // does not get to choose the order. The window settles here: whatever
        // of this window's accrual the payment covers is paid, the window
        // closes, and later windows accrue on the new outstanding balance.
        let outstanding_principal = self.outstanding_principal();
        let settled = match self.state {
            PositionState::Drawn {
                interest_settled_height,
                ..
            } => interest_settled_height,
            _ => self.drawn_at_height,
        };
        let accrued_interest =
            self.charge
                .accrued_interest(outstanding_principal, settled, height)?;
        let interest_paid = payment_sat.min(accrued_interest);
        let principal_paid = payment_sat - interest_paid;

        repaid_interest = repaid_interest
            .checked_add(interest_paid)
            .ok_or(Error::ValueOverflow)?;
        repaid_principal = repaid_principal
            .checked_add(principal_paid)
            .ok_or(Error::ValueOverflow)?;

        // The window settled with this payment, so the remainder is priced
        // from the *new* state, not as old-debt-minus-payment: with the
        // marker advanced, a fresh `debt_at` is the only number that agrees
        // with what any later caller computes.
        if payment_sat == debt {
            self.state = PositionState::Repaid {
                at_height: height,
                interest_paid_sat: repaid_interest,
            };
            return Ok(Repayment {
                interest_paid_sat: interest_paid,
                principal_paid_sat: principal_paid,
                remaining_debt_sat: 0,
            });
        }
        self.state = PositionState::Drawn {
            at_height: height,
            repaid_principal_sat: repaid_principal,
            repaid_interest_sat: repaid_interest,
            interest_settled_height: height,
        };
        let remaining_debt = self.debt_at(height)?;

        Ok(Repayment {
            interest_paid_sat: interest_paid,
            principal_paid_sat: principal_paid,
            remaining_debt_sat: remaining_debt,
        })
    }

    /// The settlement this default would produce, **without** committing it.
    ///
    /// Pure arithmetic: `default` calls this and then commits, so the book (and
    /// any caller) can price a default — and refuse one whose bond is short —
    /// before a single bucket is written.
    pub fn simulate_default(&self, height: u64) -> Result<DefaultSettlement> {
        if height < self.deadline_height {
            return Err(Error::Malformed(
                "the position has not yet reached its deadline",
            ));
        }
        if !matches!(self.state, PositionState::Drawn { .. }) {
            return Err(Error::Malformed("a settled position cannot default twice"));
        }
        let outstanding_principal = self.outstanding_principal();
        if outstanding_principal == 0 {
            return Err(Error::Malformed("nothing is owed, so nothing can default"));
        }
        let debt = self
            .debt_at(height)
            .map_err(|_| Error::Malformed("the position's debt could not be computed"))?;

        let from_collateral = self.collateral_sat.min(debt);
        let still_owed = debt - from_collateral;
        let from_bond = still_owed.min(self.bond_sat);
        let shortfall = still_owed - from_bond;
        let excess_returned = self.collateral_sat - from_collateral;

        Ok(DefaultSettlement {
            debt_sat: debt,
            from_collateral_sat: from_collateral,
            from_bond_sat: from_bond,
            shortfall_sat: shortfall,
            excess_returned_sat: excess_returned,
        })
    }

    /// Settle an unpaid position at its deadline.
    ///
    /// The order of payments is the whole point: **collateral first, then the
    /// bond, and never reputation.** The position's own collateral is what was
    /// pledged for it; the bond is what backs a default.
    ///
    /// The deadline is the lender's patience made checkable: before it, an
    /// unpaid position is merely late, not defaulted — a lender that could
    /// settle on a whim would make every term it offered meaningless.
    ///
    /// Collateral in excess of the debt returns to the borrower. A default takes
    /// what it is owed and no more — an overcollateralized position that went
    /// bad still belongs to its borrower outside the debt.
    pub fn default(&mut self, height: u64) -> Result<DefaultSettlement> {
        let settlement = self.simulate_default(height)?;
        self.state = PositionState::Defaulted {
            at_height: height,
            settlement,
        };
        Ok(settlement)
    }
}

/// Saturating satoshis-times-basis-points.
///
/// Deliberately not `saturating_mul` on u64: that would wrap at the *satoshis*
/// step for large `sat`, and a wrapped product compares small and passes a
/// bound. Compute in u128 and clamp once.
fn sat_mul_bps(sat: u64, bps: u32) -> u64 {
    // Divide before clamping: clamping the raw product would overstate the
    // result up to 10 000x whenever sat * bps exceeds u64::MAX but the divided
    // value does not. The caps downstream assume this names the true quotient.
    ((sat as u128) * (bps as u128) / 10_000).min(u64::MAX as u128) as u64
}

/// The one thing `admit_payment` needs from a credit book, kept to a trait so
/// the admission path stays consensus-free and testable without a real lender:
/// given a payer and the amount it is trying to spend, either confirm credit is
/// available or refuse. A default-implemented `NoCreditGate` opts out, so
/// callers that have not wired credit yet behave exactly as before — credit
/// gating is added only when a node plugs a book in.
pub trait CreditGate {
    /// Confirm payer `agent`/address has `amount_sat` available credit, and
    /// reserve it against this payment. Returns the reserved id on success;
    /// a reserved debit must be released if admission later fails, so this is
    /// always called after every other check passes.
    fn reserve(&mut self, payer: &Address, amount_sat: u64, height: u64) -> Result<Reservation>;

    /// Commit the debit a reservation made against the ledger. Called by the
    /// settlement layer (roadmap item 10 / §19.4) once a payment is
    /// irrevocably settled: the receipt is accepted and the L1 payout is either
    /// queued via the exit sink or already confirmed. This debits the payer's
    /// credit line — it does **not** move on-chain coins, which still happen only
    /// through the ordinary L1/L2 payout path. The reservation is consumed:
    /// calling this twice on the same reservation is idempotent (the second call
    /// debits nothing) rather than a second debit.
    fn settle(&mut self, _reservation: &Reservation) -> Result<()> {
        Err(Error::Malformed("settle is not wired on this CreditGate"))
    }

    /// Give back a reservation that was never settled — the payment was refused
    /// after admission, or the connection died. Without this the encumbrance
    /// would last forever and the payer's line would shrink without any payment.
    fn release(&mut self, _reservation: &Reservation) -> Result<()> {
        Err(Error::Malformed("release is not wired on this CreditGate"))
    }
}

/// A debit reserved against a credit line. The holder of the `CreditGate` must
/// release it if the payment never commits; otherwise it is a claim the
/// settlement layer settles against the position named by `position_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub id: Hash,
    /// The payer whose credit line was charged. Carried so the settlement
    /// layer can debit the right account without re-deriving the id.
    pub debtor: Address,
    /// Satoshis reserved. The settlement debit is exactly this amount — a
    /// reservation must never settle for more or less than it reserved.
    pub amount_sat: u64,
    /// Free-balance satoshis swept into `reserved` at admission. Zero for a
    /// pure position-backed draw; equal to `amount_sat` for a pure free draw.
    /// A mixed reservation sweeps the whole free balance and draws the rest
    /// against position headroom, so no spendable value is left behind for a
    /// second payment to re-admit.
    pub from_free_sat: u64,
    /// Per-position headroom encumbered, in the order drawn. Empty for a pure
    /// free-balance draw. Every entry is released (or refused at settle) by
    /// name, so a draw spread over several positions cannot leak on the ones
    /// the reservation forgot to record.
    pub position_draws: Vec<(Hash, u64)>,
    /// The position this debit was charged against, if any (a free-balance draw
    /// has none). Informational: lets a lender reconcile without storing it.
    pub position_id: Option<Hash>,
}

/// Largest entry count the reservation codec will read back for one draw list.
/// Checked before any allocation; a draw list is bounded in practice by the
/// book's own position count.
const MAX_RESERVATION_DRAWS: usize = 1 << 20;

/// Restart recovery for a reservation.
///
/// Reservations are node-local and non-consensus, but losing one loses the
/// record that a credit line was already charged: without it the same credit
/// admits a second payment. The encoding is the struct field for field, and
/// the draw list is checked against the bytes actually present before any
/// buffer is allocated.
impl Reservation {
    /// Canonical encoding, self-delimiting.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(80 + 40 * self.position_draws.len());
        w.fixed(&self.id)
            .fixed(&self.debtor)
            .u64le(self.amount_sat)
            .u64le(self.from_free_sat);
        w.u32le(self.position_draws.len() as u32);
        for (position, amount) in &self.position_draws {
            w.fixed(position).u64le(*amount);
        }
        match self.position_id {
            Some(id) => {
                w.u8(1).fixed(&id);
            }
            None => {
                w.u8(0);
            }
        }
        w.into_vec()
    }

    /// Decode what [`Reservation::encode`] wrote. Bounded and fail-closed: a
    /// draw count the remaining bytes cannot back, an unknown position tag, or
    /// trailing bytes produce an error rather than a half-built reservation.
    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self> {
        let id: Hash = r.fixed()?;
        let debtor: Address = r.fixed()?;
        let amount_sat = r.u64le()?;
        let from_free_sat = r.u64le()?;
        let draws = r.u32le()? as usize;
        if draws > MAX_RESERVATION_DRAWS {
            return Err(Error::Malformed("reservation draw count over codec cap"));
        }
        // Each draw is exactly 40 bytes on the wire: a count the remaining
        // buffer cannot hold is a lying count, refused before allocation.
        if draws.saturating_mul(40) > r.remaining() {
            return Err(Error::Malformed(
                "reservation draw count over remaining bytes",
            ));
        }
        let mut position_draws = Vec::with_capacity(draws);
        for _ in 0..draws {
            let position: Hash = r.fixed()?;
            let amount = r.u64le()?;
            position_draws.push((position, amount));
        }
        let position_id = match r.u8()? {
            0 => None,
            1 => Some(r.fixed()?),
            _ => return Err(Error::Malformed("reservation position tag")),
        };
        Ok(Reservation {
            id,
            debtor,
            amount_sat,
            from_free_sat,
            position_draws,
            position_id,
        })
    }
}

/// The credit-gate is the only optional input to admission, so a node that has
/// not wired credit plugs this in and gets the pre-credit behavior: every
/// payment that is otherwise valid is admitted.
pub struct NoCreditGate;
impl CreditGate for NoCreditGate {
    fn reserve(&mut self, payer: &Address, amount_sat: u64, _height: u64) -> Result<Reservation> {
        Ok(Reservation {
            id: crate::hash::ZERO_HASH,
            debtor: *payer,
            amount_sat,
            from_free_sat: amount_sat,
            position_draws: Vec::new(),
            position_id: None,
        })
    }

    // NoCreditGate debits nothing — it is the opt-out path for callers that have
    // not wired a credit book. Settle is a no-op on an empty book by design.
    fn settle(&mut self, _reservation: &Reservation) -> Result<()> {
        Ok(())
    }

    fn release(&mut self, _reservation: &Reservation) -> Result<()> {
        Ok(())
    }
}

/// `CreditBook` is its own credit gate: a payment is admitted only if the payer's
/// unencumbered capacity (unencumbered free balance plus the headroom in every
/// live position that can absorb a debit) covers `amount_sat`.
///
/// A reservation **encumbers** that capacity immediately — it moves out of
/// `free` into `reserved`, or off a live position's principal headroom — so two
/// payments cannot both be admitted against the same value. The debit still
/// lands at settlement (§19.4); reserving is what makes that promise exact
/// rather than advisory.
impl CreditGate for CreditBook {
    fn reserve(&mut self, payer: &Address, amount_sat: u64, height: u64) -> Result<Reservation> {
        // The sequence is committed only on success: a refused admission must
        // leave the book exactly as it was, with no observable side effect.
        let seq = self.reservation_seq.saturating_add(1);
        // Every reservation gets its own id, so two payments from one payer at
        // one height are never conflated into the same reservation.
        let id = sha256_dom(
            DOM_CREDIT_POSITION,
            &[
                payer.as_ref(),
                &amount_sat.to_le_bytes(),
                &height.to_le_bytes(),
                &seq.to_le_bytes(),
            ],
        );

        let spendable = self.available(payer);
        if spendable >= amount_sat {
            // The unencumbered balance alone covers it: no position is consumed,
            // and the value moves to `reserved` so nothing else may spend it.
            let f = self
                .free
                .get_mut(payer)
                .ok_or(Error::Malformed("no free balance to reserve against"))?;
            *f = f.checked_sub(amount_sat).ok_or(Error::InsufficientFunds {
                needed: amount_sat,
                available: spendable,
            })?;
            let r = self.reserved.entry(*payer).or_insert(0);
            *r = r.checked_add(amount_sat).ok_or(Error::ValueOverflow)?;
            self.reservation_seq = seq;
            self.outstanding.insert(id);
            return Ok(Reservation {
                id,
                debtor: *payer,
                amount_sat,
                from_free_sat: amount_sat,
                position_draws: Vec::new(),
                position_id: None,
            });
        }

        // Otherwise sweep the whole free balance into `reserved` first, then
        // draw the remainder against live positions. Leaving the free balance
        // in place would let a second payment re-admit the same value while
        // this reservation also claims it.
        let from_free_sat = spendable;
        if from_free_sat > 0 {
            let f = self
                .free
                .get_mut(payer)
                .ok_or(Error::Malformed("no free balance to reserve against"))?;
            *f = f
                .checked_sub(from_free_sat)
                .ok_or(Error::InsufficientFunds {
                    needed: from_free_sat,
                    available: spendable,
                })?;
            let r = self.reserved.entry(*payer).or_insert(0);
            *r = r.checked_add(from_free_sat).ok_or(Error::ValueOverflow)?;
        }
        let mut remaining = amount_sat.saturating_sub(from_free_sat);
        let mut chosen: Option<Hash> = None;
        // The positions the draw is spread over, in line order, so the
        // encumbrance below is computed from the same numbers the loop walked.
        let mut spread: Vec<(Hash, u64)> = Vec::new();
        for (pos_id, position) in self.live_positions() {
            if position.borrower != *payer {
                continue;
            }
            let headroom = match position.state {
                PositionState::Drawn {
                    repaid_principal_sat,
                    ..
                } => position
                    .amount_sat
                    .saturating_sub(repaid_principal_sat)
                    .saturating_sub(self.position_reserved.get(pos_id).copied().unwrap_or(0)),
                _ => 0,
            };
            if headroom == 0 {
                continue;
            }
            if remaining <= headroom {
                remaining = 0;
                chosen = Some(*pos_id);
                spread.push((*pos_id, headroom));
                break;
            }
            remaining -= headroom;
            spread.push((*pos_id, headroom));
        }

        if remaining > 0 {
            // The line cannot cover it: give the swept free balance straight
            // back, so a refused admission leaves the book exactly as it was.
            if from_free_sat > 0 {
                if let Some(debit) = self.reserved.get_mut(payer) {
                    *debit = debit.saturating_sub(from_free_sat);
                    if *debit == 0 {
                        self.reserved.remove(payer);
                    }
                }
                let f = self.free.entry(*payer).or_insert(0);
                *f = f.saturating_add(from_free_sat);
            }
            return Err(Error::InsufficientFunds {
                needed: amount_sat,
                available: spendable,
            });
        }
        // Encumber the drawn part, position by position, recording the exact
        // take per position so the release returns each one by name.
        let mut to_encumber = amount_sat.saturating_sub(from_free_sat);
        let mut draws: Vec<(Hash, u64)> = Vec::with_capacity(spread.len());
        for (pos_id, headroom) in spread {
            let take = to_encumber.min(headroom);
            if take == 0 {
                continue;
            }
            let slot = self.position_reserved.entry(pos_id).or_insert(0);
            *slot = slot.saturating_add(take);
            to_encumber -= take;
            draws.push((pos_id, take));
        }
        debug_assert_eq!(to_encumber, 0);
        self.reservation_seq = seq;
        self.outstanding.insert(id);
        Ok(Reservation {
            id,
            debtor: *payer,
            amount_sat,
            from_free_sat,
            position_draws: draws,
            position_id: chosen,
        })
    }

    /// Commit a reservation returned by [`CreditGate::reserve`], moving its
    /// encumbrance into `settled_payments`. Ledger half of coin settlement
    /// (roadmap item 10, §19.4): the credit line is reduced here; the on-chain
    /// coins still move only through the ordinary L1/L2 payout path.
    ///
    /// Idempotent and replay-safe: the reservation id is recorded once it is
    /// consumed, so a re-submitted receipt settling the same reservation again
    /// debits nothing rather than debiting twice.
    fn settle(&mut self, reservation: &Reservation) -> Result<()> {
        if reservation.amount_sat == 0 {
            return Ok(());
        }
        match self.reservation_log.get(&reservation.id) {
            Some(ReservationOutcome::Settled) => return Ok(()),
            Some(ReservationOutcome::Released) => {
                return Err(Error::Malformed(
                    "this reservation was released and cannot be settled",
                ))
            }
            // Unknown means either never issued or consumed so long ago the
            // outcome log evicted it: both refuse. Without membership here a
            // replayed receipt re-debits the moment the debtor re-reserves.
            None => {
                if !self.outstanding.remove(&reservation.id) {
                    return Err(Error::Malformed("unknown or already-consumed reservation"));
                }
            }
        }
        // A draw against position headroom is capacity, not value: the debit is
        // a position-lifecycle event (repay), so there is no outstanding free
        // reservation for the drawn part to settle into. Refuse by name before
        // touching any bucket, rather than settling the free part and silently
        // dropping the rest.
        if !reservation.position_draws.is_empty() {
            return Err(Error::Malformed(
                "no outstanding free reservation for this payer to settle: the reservation draws on position headroom, which settles through the position lifecycle, not the ledger",
            ));
        }
        let debit = self
            .reserved
            .get_mut(&reservation.debtor)
            .ok_or(Error::Malformed(
                "no outstanding reservation for this payer to settle",
            ))?;
        if *debit < reservation.amount_sat {
            return Err(Error::Malformed(
                "reserved value does not cover the reservation being settled",
            ));
        }
        *debit -= reservation.amount_sat;
        if *debit == 0 {
            self.reserved.remove(&reservation.debtor);
        }
        self.settled_payments = self
            .settled_payments
            .checked_add(reservation.amount_sat)
            .ok_or(Error::ValueOverflow)?;
        self.record_reservation(reservation.id, ReservationOutcome::Settled);
        Ok(())
    }

    /// Return a reservation's encumbrance to the payer's spendable capacity.
    ///
    /// A reservation that was never settled must not keep shrinking the line it
    /// came from: admission that fails afterwards, or a payment the payer
    /// abandons, puts the value back where it was.
    fn release(&mut self, reservation: &Reservation) -> Result<()> {
        if reservation.amount_sat == 0 {
            return Ok(());
        }
        match self.reservation_log.get(&reservation.id) {
            Some(ReservationOutcome::Released) => return Ok(()),
            Some(ReservationOutcome::Settled) => {
                return Err(Error::Malformed(
                    "this reservation was settled and cannot be released",
                ))
            }
            // Same rule as `settle`: an id the book never issued — or one
            // whose outcome was evicted — releases nothing.
            None => {
                if !self.outstanding.remove(&reservation.id) {
                    return Err(Error::Malformed("unknown or already-consumed reservation"));
                }
            }
        }
        // Return the swept free balance, exactly what admission moved.
        if reservation.from_free_sat > 0 {
            if let Some(debit) = self.reserved.get_mut(&reservation.debtor) {
                let give = reservation.from_free_sat.min(*debit);
                *debit -= give;
                if *debit == 0 {
                    self.reserved.remove(&reservation.debtor);
                }
                let free = self.free.entry(reservation.debtor).or_insert(0);
                *free = free.checked_add(give).ok_or(Error::ValueOverflow)?;
            }
        }
        // Return every position draw by name, exactly what admission took. A
        // draw spread over several positions releases each one; releasing the
        // whole amount from a single recorded position would over-release it
        // and leak the rest.
        for (position_id, take) in &reservation.position_draws {
            if *take == 0 {
                continue;
            }
            if let Some(slot) = self.position_reserved.get_mut(position_id) {
                *slot = slot.saturating_sub(*take);
                if *slot == 0 {
                    self.position_reserved.remove(position_id);
                }
            }
        }
        self.record_reservation(reservation.id, ReservationOutcome::Released);
        self.check_conservation()
    }
}

impl CreditBook {
    /// Record a consumed reservation, evicting the oldest entry past the cap so
    /// the log stays bounded rather than growing with the settlement count.
    fn record_reservation(&mut self, id: Hash, outcome: ReservationOutcome) {
        if self.reservation_log.insert(id, outcome).is_none() {
            self.reservation_order.push_back(id);
        }
        while self.reservation_order.len() > MAX_RESERVATION_LOG {
            match self.reservation_order.pop_front() {
                Some(oldest) => {
                    self.reservation_log.remove(&oldest);
                }
                None => break,
            }
        }
    }

    /// Value currently encumbered by outstanding reservations, free-balance and
    /// position-backed together.
    pub fn total_reserved(&self) -> u64 {
        self.reserved
            .values()
            .fold(0u64, |acc, v| acc.saturating_add(*v))
            .saturating_add(
                self.position_reserved
                    .values()
                    .fold(0u64, |acc, v| acc.saturating_add(*v)),
            )
    }

    /// Free-balance value this payer has encumbered right now.
    pub fn reserved_by(&self, agent: &Address) -> u64 {
        self.reserved.get(agent).copied().unwrap_or(0)
    }

    /// Whether a reservation id has already been consumed, and how. Exposed so a
    /// caller (and a test) can assert the replay guard directly.
    pub fn reservation_outcome(&self, id: &Hash) -> Option<ReservationOutcome> {
        self.reservation_log.get(id).copied()
    }

    /// Mark a reservation id as outstanding (created, not yet consumed).
    ///
    /// `reserve` does this itself; this exists for restart recovery, where
    /// the node re-marks every reservation its persisted map still holds
    /// (the outstanding set itself is runtime-only, like that map). Marking
    /// an already-consumed id is harmless: the outcome log is consulted
    /// first, so a settle still returns idempotent-Ok and a release still
    /// refuses — the mark only admits ids the log has never seen.
    pub fn mark_outstanding(&mut self, id: &Hash) {
        self.outstanding.insert(*id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live schedule: 10% per 100-block window.
    fn charge() -> ChargeSchedule {
        ChargeSchedule {
            rate_bps_per_window: 1_000,
            window_blocks: 100,
        }
    }

    /// A drawn position: 1_000_000 borrowed with the given bond. Deterministic
    /// and small enough to reason about on paper. Defaultable from the draw
    /// height, so the tests below can settle it wherever they like.
    fn drawn(bond: u64) -> CreditPosition {
        CreditPosition::open(&spec(1_000_000, bond, 0, 0)).unwrap()
    }

    /// Build a position without opening it, so a test can inspect or perturb it.
    fn spec(amount: u64, bond: u64, at: u64, deadline: u64) -> PositionSpec {
        PositionSpec {
            terms: CreditTerms::default(),
            charge: charge(),
            borrower: [1u8; 20],
            agent_id: [9u8; 32],
            lender: [2u8; 20],
            amount_sat: amount,
            bond_sat: bond,
            drawn_at_height: at,
            deadline_height: deadline,
        }
    }

    /// D1's invariant, in its strongest available form.
    ///
    /// An earlier shape of `open` took a `ReputationScore` and discarded it. That
    /// version was *conventional* and weaker than this one, because it left the
    /// dependency one careless caller away from becoming real: a future edit that
    /// started reading the score would have compiled. Removing the parameter
    /// entirely means credit cannot be computed from a reputation score even by
    /// accident - the type system refuses the call rather than the code refusing
    /// it.
    ///
    /// The score is still the lender's underwriting input, exactly as before. The
    /// point is that it is the lender's, off the chain's critical path, so a
    /// reputation update is not a consensus event and a fresh id is not farmable.
    #[test]
    fn credit_cannot_be_computed_from_a_reputation_score_at_all() {
        // The compile-time assertion: no signature in this module accepts one.
        // If `PositionSpec` or `open` ever gains a score field, stop and think
        // about D1 again, because that is the change the decision refuses.
        let p = spec(1_000_000, 0, 0, 0);
        // The same figures, whatever an agent's score might be, price identically.
        assert_eq!(
            CreditPosition::open(&p).unwrap().collateral_sat,
            CreditPosition::open(&p).unwrap().collateral_sat
        );
    }

    #[test]
    fn a_position_with_no_bond_still_requires_full_collateral() {
        let t = CreditTerms::default();
        let c = t.required_collateral(1_000_000, 0).unwrap();
        assert_eq!(c, 1_000_000, "zero bond buys zero discount");
    }

    #[test]
    fn a_bond_discounts_but_neither_to_zero_nor_below_the_floor() {
        let t = CreditTerms::default();
        // A bond far larger than the creditable share: the discount stops at
        // `max_discount_bps` of the amount, so size stops earning anything.
        let big = t.required_collateral(1_000_000, 1_000_000_000).unwrap();
        assert_eq!(
            big, 800_000,
            "the floor, and the cap, coincide at the defaults"
        );
        assert_ne!(big, 0, "there is no path to a zero-collateral line");

        // A bond below the creditable share discounts satoshi for satoshi, and
        // no further: 20 000 of bond buys 20 000 off a 1 000 000 line.
        let exact = t.required_collateral(1_000_000, 20_000).unwrap();
        assert_eq!(exact, 1_000_000 - 20_000);

        // The creditable share itself is the largest discount any bond can buy,
        // which is exactly `max_discount_bps` of the amount.
        let at_share = t
            .required_collateral(1_000_000, t.max_creditable_bond(1_000_000))
            .unwrap();
        assert_eq!(
            at_share, big,
            "a bond at the creditable share is already capped"
        );
    }

    #[test]
    fn the_requirement_never_rises_as_more_bond_is_posted() {
        let t = CreditTerms::default();
        let mut prev = t.required_collateral(10_000_000, 0).unwrap();
        for bond in [1u64, 100, 1_000, 10_000, 100_000, 1_000_000] {
            let next = t.required_collateral(10_000_000, bond).unwrap();
            assert!(
                next <= prev,
                "bond {bond}: collateral rose from {prev} to {next}"
            );
            prev = next;
        }
    }

    #[test]
    fn the_requirement_is_monotone_in_the_amount_borrowed() {
        let t = CreditTerms::default();
        let mut prev = 0;
        for amount in [1u64, 10, 1_000, 1_000_000, 1_000_000_000] {
            let c = t.required_collateral(amount, 1_000_000).unwrap();
            assert!(c >= prev, "amount {amount}: collateral fell");
            prev = c;
        }
    }

    #[test]
    fn reputation_is_not_an_input_to_the_collateral_required() {
        // D1's core property, tested directly: the same bond and amount produce
        // the same requirement whatever the score, including a fresh id.
        let t = CreditTerms::default();
        let a = t.required_collateral(1_000_000, 50_000).unwrap();
        assert_eq!(
            CreditPosition::open(&spec(1_000_000, 50_000, 0, 0))
                .unwrap()
                .collateral_sat,
            a
        );
        assert_eq!(
            CreditPosition::open(&spec(1_000_000, 50_000, 0, 0))
                .unwrap()
                .collateral_sat,
            a
        );
    }

    #[test]
    fn a_zero_amount_position_is_refused() {
        assert!(CreditTerms::default()
            .required_collateral(0, 1_000)
            .is_err());
    }

    #[test]
    fn self_contradictory_terms_are_refused() {
        let t = CreditTerms {
            max_discount_bps: 20_000,
            ..Default::default()
        };
        assert!(
            t.required_collateral(1_000_000, 10_000).is_err(),
            "a discount above the base would drive the requirement to nothing"
        );
    }

    #[test]
    fn interest_accrues_per_whole_window_only() {
        let c = charge();
        // One window of 10% on 1 000 000 is 100 000.
        assert_eq!(c.accrued_interest(1_000_000, 0, 100).unwrap(), 100_000);
        // A fraction of a window accrues nothing: there is no sub-window
        // fraction, so the total never depends on rounding order.
        assert_eq!(c.accrued_interest(1_000_000, 0, 50).unwrap(), 0);
        assert_eq!(c.accrued_interest(1_000_000, 0, 99).unwrap(), 0);
        assert_eq!(c.accrued_interest(1_000_000, 0, 200).unwrap(), 200_000);
        // Interest is charged on outstanding principal, so repaying reduces it.
        assert_eq!(c.accrued_interest(500_000, 0, 100).unwrap(), 50_000);
        // A backwards window is a caller error, not zero.
        assert!(c.accrued_interest(1_000_000, 100, 0).is_err());
    }

    #[test]
    fn a_position_repays_interest_before_principal() {
        // 1 000 000 borrowed, one window elapsed before any repayment.
        let mut p = drawn(0);
        let r = p.repay(50_000, 100).unwrap();
        // The whole payment lands on interest, because that is the lender's
        // charge and comes first. The principal is untouched.
        assert_eq!(r.interest_paid_sat, 50_000);
        assert_eq!(r.principal_paid_sat, 0);
        // The window settles on every repay (L2 parity): the 50 000 of this
        // window's 100 000 charge that went unpaid is forgiven, exactly as
        // the L2 book does — the debt is the outstanding principal plus the
        // current window's accrual, never a remembered remainder.
        assert_eq!(
            r.remaining_debt_sat, 1_000_000,
            "1 000 000 principal, window settled"
        );

        // Paying the rest settles it, and the collateral returns whole.
        let r2 = p.repay(1_000_000, 100).unwrap();
        assert_eq!(r2.remaining_debt_sat, 0);
        assert!(p.is_terminal());
        assert!(
            matches!(p.state, PositionState::Repaid { interest_paid_sat, .. } if interest_paid_sat == 50_000)
        );
    }

    #[test]
    fn partial_principal_repay_stops_interest_on_what_left() {
        // 1 000 000 at 10 %/window: at h=100 the full 100 000 interest plus
        // 500 000 principal goes in. Later windows charge only the 500 000
        // still out — interest on repaid principal stops at repayment.
        let mut p = drawn(0);
        let r = p.repay(600_000, 100).unwrap();
        assert_eq!(r.interest_paid_sat, 100_000);
        assert_eq!(r.principal_paid_sat, 500_000);
        // One more window on 500 000: 50 000 interest, 550 000 debt.
        assert_eq!(p.debt_at(200).unwrap(), 550_000);
        let r2 = p.repay(550_000, 200).unwrap();
        assert_eq!(r2.remaining_debt_sat, 0);
        assert!(p.is_terminal());
        assert!(
            matches!(p.state, PositionState::Repaid { interest_paid_sat, .. } if interest_paid_sat == 150_000)
        );
    }

    #[test]
    fn repaying_more_than_the_debt_is_refused() {
        // A payment larger than the debt is the caller paying the wrong amount.
        // Accepting it quietly is how a position acquires funds with no reason.
        let mut p = drawn(0);
        assert!(p.repay(1_000_001, 0).is_err());
    }

    #[test]
    fn a_default_takes_collateral_first_then_the_bond_and_never_reputation() {
        // 1 000 000 borrowed with a 0 bond: collateral is the full amount, and
        // with one window of interest the debt exceeds it.
        let mut p = drawn(0);
        let s = p.default(100).unwrap();

        assert_eq!(s.debt_sat, 1_100_000);
        assert_eq!(
            s.from_collateral_sat, 1_000_000,
            "the position's own collateral is taken first"
        );
        assert_eq!(s.from_bond_sat, 0, "there was no bond to take");
        assert_eq!(
            s.shortfall_sat, 100_000,
            "the lender absorbs what collateral could not cover"
        );
        assert_eq!(s.excess_returned_sat, 0, "nothing was left over");

        // The bond is what backs a default; posting one discounts the collateral
        // requirement, so the debt now spills past the collateral into the bond.
        let mut p2 = drawn(50_000);
        assert_eq!(
            p2.collateral_sat, 950_000,
            "the bond discounted the requirement"
        );
        let s2 = p2.default(100).unwrap();
        assert_eq!(s2.debt_sat, 1_100_000);
        assert_eq!(
            s2.from_collateral_sat, 950_000,
            "the position's collateral goes first"
        );
        assert_eq!(s2.from_bond_sat, 50_000, "the bond covers all it can");
        assert_eq!(
            s2.shortfall_sat, 100_000,
            "and the lender absorbs the remainder"
        );
        assert_eq!(s2.lender_recovered_sat(), 1_000_000);
        assert_eq!(
            s2.borrower_lost_sat(),
            1_000_000,
            "collateral plus bond, and nothing else"
        );
    }

    #[test]
    fn a_default_returns_excess_collateral_to_the_borrower() {
        // Borrow far less than the collateral held. A default must take the debt
        // and no more: the rest is the borrower's, and keeping it would be theft.
        let mut p = CreditPosition::open(&spec(100_000, 0, 0, 0)).unwrap();
        assert_eq!(p.collateral_sat, 100_000, "fully collateralized at open");
        p.bond_sat = 0;

        // Default before any interest accrues, so the debt is exactly principal.
        let s = p.default(0).unwrap();
        assert_eq!(s.debt_sat, 100_000);
        assert_eq!(s.from_collateral_sat, 100_000);
        assert_eq!(s.excess_returned_sat, 0);

        // Now the same position but the collateral is deliberately larger.
        let mut p2 = p.clone();
        p2.state = PositionState::Drawn {
            at_height: 0,
            repaid_principal_sat: 0,
            repaid_interest_sat: 0,
            interest_settled_height: 0,
        };
        p2.collateral_sat = 250_000;
        let s2 = p2.default(0).unwrap();
        assert_eq!(
            s2.excess_returned_sat, 150_000,
            "collateral in excess of the debt returns to the borrower"
        );
        assert_eq!(
            s2.borrower_lost_sat(),
            100_000,
            "the borrower loses the debt, not the collateral"
        );
    }

    #[test]
    fn a_settled_position_cannot_change_again() {
        // Terminal means terminal, in both directions.
        let mut p = drawn(0);
        p.default(0).unwrap();
        assert!(p.default(10).is_err(), "cannot default twice");
        assert!(p.debt_at(10).is_err(), "a settled position has no debt");
        assert!(
            p.repay(100, 10).is_err(),
            "cannot repay a defaulted position"
        );

        let mut q = drawn(0);
        q.repay(1_000_000, 0).unwrap();
        assert!(q.is_terminal());
        assert!(
            q.default(100).is_err(),
            "nothing is owed, so nothing defaults"
        );
        assert!(q.repay(1, 100).is_err(), "cannot repay a repaid position");
    }

    #[test]
    fn a_default_of_a_nothing_owed_position_is_refused() {
        let mut p = drawn(0);
        // Repay the principal and all interest, leaving a live but zero-debt
        // position would be impossible; a partial repayment leaving principal
        // still owes, so it can default.
        p.repay(100_000, 0).unwrap();
        assert!(!p.is_terminal());
        // But zero outstanding principal is refused rather than settled at zero.
        p.state = PositionState::Drawn {
            at_height: 0,
            repaid_principal_sat: 1_000_000,
            repaid_interest_sat: 0,
            interest_settled_height: 0,
        };
        assert!(
            p.default(0).is_err(),
            "nothing is owed, so nothing can default"
        );
    }

    #[test]
    fn the_terms_round_trip_and_identify_themselves() {
        let t = CreditTerms::default();
        let bytes = t.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(CreditTerms::decode(&mut r).unwrap(), t);
        assert_eq!(r.remaining(), 0);
        assert_eq!(
            t.id(),
            CreditTerms::decode(&mut crate::ser::Reader::new(&bytes))
                .unwrap()
                .id()
        );
    }

    #[test]
    fn a_position_cannot_default_before_its_deadline() {
        // The deadline is the lender's patience made checkable. Before it, an
        // unpaid position is late, not defaulted — a lender that could settle on
        // a whim would make the terms it offered meaningless.
        let mut p = CreditPosition::open(&spec(1_000_000, 0, 0, 100)).unwrap();
        assert!(
            p.default(99).is_err(),
            "a position cannot be settled one block early"
        );
        // Repaying is not gated by the deadline: a borrower may clear its debt
        // whenever it likes, which is the entire point of having a debt.
        let mut q = CreditPosition::open(&spec(1_000_000, 0, 0, 100)).unwrap();
        assert!(q.repay(1_000, 50).is_ok());
        let s = p.default(100).unwrap();
        assert_eq!(s.debt_sat, 1_100_000, "one window of interest is owed");
    }

    #[test]
    fn a_deadline_before_the_position_is_drawn_is_refused() {
        // A position that is already due at draw time is a caller error, not a
        // discount.
        assert!(CreditPosition::open(&spec(1_000_000, 0, 100, 50)).is_err());
    }

    #[test]
    fn the_position_id_covers_the_deadline() {
        // Two positions identical but for their deadline are different
        // positions, and the book keys them apart.
        assert_ne!(
            spec(1_000_000, 0, 0, 100).id(),
            spec(1_000_000, 0, 0, 200).id()
        );
    }

    #[test]
    fn the_book_moves_value_and_never_creates_it() {
        let borrower = [1u8; 20];
        let lender = [2u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 2_150_000).unwrap();
        assert_eq!(book.total_deposited(), 2_150_000);

        // Bond first, because the position is priced with it.
        book.post_bond(borrower, 50_000).unwrap();
        let id = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        // 50 000 of bond discounts the 1 000 000 line by 50 000.
        assert_eq!(book.free(&borrower), 1_150_000);
        assert_eq!(book.bond(&borrower), 50_000);
        assert_eq!(book.total_locked_collateral(), 950_000);
        assert_eq!(book.live_positions().count(), 1);
        book.check_conservation().unwrap();

        // One window of interest: 100 000 at height 100 pays all of it and none
        // of the principal. The lender is the one who ends up with it.
        let r = book.repay(&id, 100_000, 100).unwrap();
        assert_eq!(r.interest_paid_sat, 100_000);
        assert_eq!(r.principal_paid_sat, 0);
        assert_eq!(book.recovered(&lender), 100_000);
        book.check_conservation().unwrap();

        // Repaying the rest settles the position and returns its collateral.
        let r = book.repay(&id, 1_000_000, 100).unwrap();
        assert_eq!(r.remaining_debt_sat, 0);
        assert_eq!(book.free(&borrower), 1_000_000);
        assert_eq!(book.recovered(&lender), 1_100_000);
        assert_eq!(book.live_positions().count(), 0);
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_bond_discount_requires_the_bond_to_be_posted() {
        // A bond that exists only in the spec buys a discount nobody backed,
        // which is undercollateralization wearing a discount's clothes.
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 1_100_000).unwrap();
        let s = spec(1_000_000, 50_000, 0, 0);
        assert!(book.open(&s).is_err(), "no bond was posted");

        // Post it, and the very same spec opens.
        book.post_bond(borrower, 50_000).unwrap();
        assert!(book.open(&s).is_ok());
        // And not twice: one position id, ever.
        assert!(book.open(&s).is_err(), "a position cannot be re-opened");
    }

    #[test]
    fn one_bond_cannot_price_two_positions_at_the_same_time() {
        // The bond-reuse defect, pinned: a posted bond discounts the collateral
        // of the position it is pledged to, and nothing else, for as long as
        // that position is live. Without the pledge a 50 000 bond could back any
        // number of positions, each claiming the same 50 000 discount, and the
        // book's collateral would fall once per obligation secured.
        let borrower = [1u8; 20];
        let lender = [2u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 2_300_000).unwrap();
        book.post_bond(borrower, 50_000).unwrap();
        assert_eq!(book.unpledged_bond(&borrower), 50_000);

        let first = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        assert_eq!(book.unpledged_bond(&borrower), 0, "the bond is pledged");
        assert_eq!(book.total_locked_collateral(), 950_000);
        book.check_conservation().unwrap();

        // A second position priced with the same bond has no unpledged bond to
        // claim, so it must be refused — not priced with a discount that is
        // already at risk elsewhere.
        let second = spec(1_000_000, 50_000, 0, 200);
        assert!(
            book.open(&second).is_err(),
            "the same bond cannot secure two obligations"
        );
        assert_eq!(book.live_positions().count(), 1, "nothing was recorded");
        assert_eq!(book.total_locked_collateral(), 950_000);
        book.check_conservation().unwrap();

        // A smaller bond posts and prices the second position against *its own*
        // value, which is the honest way to get more than one line open.
        book.deposit(borrower, 50_000).unwrap();
        book.post_bond(borrower, 20_000).unwrap();
        let second_id = book.open(&spec(1_000_000, 20_000, 0, 200)).unwrap();
        assert_eq!(book.live_positions().count(), 2);
        assert_eq!(book.unpledged_bond(&borrower), 0);
        book.check_conservation().unwrap();

        // Settling the first position frees its pledge: the bond is still posted
        // (a default did not take it), but it may price a new position again.
        book.deposit(borrower, 1_100_000).unwrap();
        book.repay(&first, 1_100_000, 100).unwrap();
        assert_eq!(book.unpledged_bond(&borrower), 50_000, "pledge released");
        book.open(&spec(1_000_000, 50_000, 300, 400)).unwrap();
        book.check_conservation().unwrap();
        assert!(book.position(&second_id).is_some());
        assert_eq!(book.recovered(&lender), 1_100_000);
    }

    #[test]
    fn a_defaulted_positions_bond_pledge_is_released_after_the_bond_is_taken() {
        // The pledge must track what the default actually consumed: the part the
        // default took is already out of `bonds`, and only the unspent part
        // returns to the pool a new position may price against.
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 1_100_000).unwrap();
        book.post_bond(borrower, 50_000).unwrap();
        let id = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        assert_eq!(book.unpledged_bond(&borrower), 0);

        // One window of interest puts the debt at 1 100 000: 950 000 of
        // collateral, then all 50 000 of the bond, and a shortfall.
        let s = book.default(&id, 100).unwrap();
        assert_eq!(s.from_bond_sat, 50_000);
        assert_eq!(book.bond(&borrower), 0, "the bond was taken in full");
        assert_eq!(book.unpledged_bond(&borrower), 0, "nothing left to pledge");
        book.check_conservation().unwrap();

        // Posting again is what creates capacity, exactly as at the start.
        book.deposit(borrower, 1_000_000).unwrap();
        book.post_bond(borrower, 50_000).unwrap();
        assert_eq!(book.unpledged_bond(&borrower), 50_000);
        book.open(&spec(1_000_000, 50_000, 0, 200)).unwrap();
        assert_eq!(book.total_locked_collateral(), 950_000);
        book.check_conservation().unwrap();
    }

    #[test]
    fn the_book_round_trips_through_a_restart_with_the_invariant_intact() {
        // Restart/recovery: a book that is saved and restored must come back
        // byte-identical in every bucket, still satisfy conservation, and be
        // able to continue its lifecycle. Anything less loses a balance, a bond
        // or an outstanding reservation on restart.
        let borrower = [1u8; 20];
        let lender = [2u8; 20];
        let payer = [7u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 2_400_000).unwrap();
        book.deposit(payer, 900_000).unwrap();
        book.post_bond(borrower, 50_000).unwrap();
        let id = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        book.repay(&id, 100_000, 100).unwrap();
        // A partial repayment leaves a live position, a partial debt, and an
        // outstanding reservation all at once.
        let res = book.reserve(&payer, 400_000, 5).unwrap();
        book.check_conservation().unwrap();

        let bytes = book.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        let mut restored = CreditBook::decode(&mut r).unwrap();
        assert_eq!(r.remaining(), 0, "the codec is self-delimiting");
        // Every value bucket round-trips; the outstanding set is
        // runtime-only by design, so it comes back empty and the node
        // re-marks what its reservations map still holds (below).
        let mut expect = book.clone();
        expect.outstanding.clear();
        assert_eq!(restored, expect, "every value bucket round-trips");
        restored.check_conservation().unwrap();

        // And the restored book can finish the job once the live
        // reservation is re-marked: it settles exactly once, and the
        // position still repays to zero.
        assert!(restored.settle(&res).is_err(), "unmarked id refuses");
        restored.mark_outstanding(&res.id);
        restored.settle(&res).unwrap();
        restored.settle(&res).unwrap();
        assert_eq!(restored.total_settled(), 400_000);
        restored.deposit(borrower, 1_100_000).unwrap();
        restored.repay(&id, 1_000_000, 100).unwrap();
        assert_eq!(restored.recovered(&lender), 1_100_000);
        assert_eq!(restored.live_positions().count(), 0);
        assert_eq!(restored.unpledged_bond(&borrower), 50_000);
        restored.check_conservation().unwrap();

        // A decoded blob that is not a book is refused rather than half-built.
        let mut truncated = crate::ser::Reader::new(&bytes[..bytes.len() - 20]);
        assert!(CreditBook::decode(&mut truncated).is_err());
    }

    #[test]
    fn a_default_takes_the_bond_from_the_book() {
        let borrower = [1u8; 20];
        let lender = [2u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 1_100_000).unwrap();
        book.post_bond(borrower, 50_000).unwrap();
        let id = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();

        // One window of interest puts the debt at 1 100 000: the 950 000 of
        // collateral goes first, then the 50 000 bond, and the lender absorbs
        // the rest.
        let s = book.default(&id, 100).unwrap();
        assert_eq!(s.from_collateral_sat, 950_000);
        assert_eq!(s.from_bond_sat, 50_000);
        assert_eq!(s.shortfall_sat, 100_000);
        assert_eq!(book.bond(&borrower), 0, "the bond is actually taken");
        assert_eq!(book.recovered(&lender), 1_000_000);
        book.check_conservation().unwrap();

        // The position is spent: it cannot be defaulted again or repaid.
        assert!(book.default(&id, 200).is_err());
        assert!(book.repay(&id, 1, 200).is_err());
    }

    #[test]
    fn a_position_cannot_be_opened_without_the_collateral() {
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 900_000).unwrap();
        // The line prices at 1 000 000 of collateral and the borrower has less.
        assert!(book.open(&spec(1_000_000, 0, 0, 0)).is_err());
        assert_eq!(book.live_positions().count(), 0);
        book.check_conservation().unwrap();
    }

    #[test]
    fn the_position_codec_round_trips_every_state() {
        let mut p = CreditPosition::open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        let bytes = p.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(CreditPosition::decode(&mut r).unwrap(), p);
        assert_eq!(r.remaining(), 0);

        p.repay(100_000, 50).unwrap();
        p.default(100).unwrap();
        let bytes = p.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(CreditPosition::decode(&mut r).unwrap(), p);
        assert_eq!(r.remaining(), 0);

        // Pre-marker (tag 0) blobs still decode: interest settles from
        // draw, reproducing exactly the debt those blobs computed, so
        // loading persisted books never jumps what anyone owes.
        let mut legacy = crate::ser::Writer::with_capacity(256);
        let q = CreditPosition::open(&spec(1_000_000, 50_000, 10, 100)).unwrap();
        legacy
            .fixed(&q.borrower)
            .fixed(&q.agent_id)
            .fixed(&q.lender);
        legacy.raw(&q.terms.encode());
        legacy
            .u32le(q.charge.rate_bps_per_window)
            .u64le(q.charge.window_blocks)
            .u64le(q.amount_sat)
            .u64le(q.bond_sat)
            .u64le(q.collateral_sat)
            .u64le(q.drawn_at_height)
            .u64le(q.deadline_height);
        legacy.u8(0).u64le(10).u64le(0).u64le(0);
        let bytes = legacy.into_vec();
        let mut r = crate::ser::Reader::new(&bytes);
        let old = CreditPosition::decode(&mut r).unwrap();
        assert_eq!(r.remaining(), 0);
        match old.state {
            PositionState::Drawn {
                interest_settled_height,
                ..
            } => assert_eq!(interest_settled_height, 10),
            _ => panic!("legacy blob must decode as drawn"),
        }
        assert_eq!(old.debt_at(110).unwrap(), q.debt_at(110).unwrap());

        // A spec round-trips too, and keeps the id the position was opened
        // under: a node can serve one and a worker can read the same position.
        let s = spec(1_000_000, 50_000, 0, 100);
        let bytes = s.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(PositionSpec::decode(&mut r).unwrap(), s);
        assert_eq!(r.remaining(), 0);
    }

    // ------------------------------------------------------------------
    // Settlement debit commit (roadmap item 10, §19.4)
    // ------------------------------------------------------------------

    #[test]
    fn a_settled_free_balance_reservation_is_debited() {
        // A reservation must *encumber* the value it names, or two payments can
        // each reserve the same balance, both be admitted, and only one of them
        // ever be debited. Encumbrance is what makes the debit a promise the
        // settlement can keep.
        let payer = [7u8; 20];
        let mut book = CreditBook::new();
        book.deposit(payer, 1_000_000).unwrap();
        let res = book.reserve(&payer, 300_000, 1).unwrap();
        assert!(res.position_id.is_none(), "free-balance reservation");
        assert_eq!(book.reserved_by(&payer), 300_000, "but it is encumbered");
        assert_eq!(book.available(&payer), 700_000, "spendable capacity fell");
        book.check_conservation().unwrap();

        book.settle(&res).unwrap();
        assert_eq!(book.available(&payer), 700_000, "spendable capacity holds");
        assert_eq!(book.reserved_by(&payer), 0, "the encumbrance was consumed");
        assert_eq!(book.total_settled(), 300_000);
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_reservation_encumbers_capacity_the_moment_it_is_made() {
        // The over-reservation defect, pinned: two payments each naming the full
        // free balance must not both be admitted.
        let payer = [9u8; 20];
        let mut book = CreditBook::new();
        book.deposit(payer, 100_000).unwrap();
        let first = book.reserve(&payer, 100_000, 5).unwrap();
        assert_eq!(book.available(&payer), 0, "the whole line is encumbered");
        let second = book.reserve(&payer, 100_000, 5);
        assert!(
            second.is_err(),
            "the same balance cannot back two admitted payments"
        );
        book.settle(&first).unwrap();
        book.check_conservation().unwrap();
    }

    #[test]
    fn settlement_is_idempotent_and_a_released_reservation_cannot_settle() {
        let payer = [11u8; 20];
        let mut book = CreditBook::new();
        book.deposit(payer, 500_000).unwrap();
        let res = book.reserve(&payer, 200_000, 3).unwrap();

        // A replayed receipt settles the same reservation twice: the second call
        // debits nothing rather than debiting twice.
        book.settle(&res).unwrap();
        book.settle(&res).unwrap();
        assert_eq!(book.total_settled(), 200_000, "one debit, not two");
        book.check_conservation().unwrap();

        // And a released reservation is dead: admission failed afterwards, so the
        // value went back and there is nothing left to settle.
        let other = book.reserve(&payer, 100_000, 4).unwrap();
        book.release(&other).unwrap();
        assert_eq!(book.available(&payer), 300_000, "the line is restored");
        assert!(book.settle(&other).is_err(), "released cannot settle");
        assert_eq!(book.total_settled(), 200_000, "no second debit");
        book.check_conservation().unwrap();

        // A settled reservation cannot be released either: the value has moved.
        assert!(book.release(&res).is_err());
        book.check_conservation().unwrap();
    }

    #[test]
    fn unknown_and_evicted_reservations_settle_nothing() {
        // A fabricated reservation — one the book never issued — must not
        // debit, even when the named debtor currently has cover.
        let payer = [12u8; 20];
        let mut book = CreditBook::new();
        book.deposit(payer, 500_000).unwrap();
        let fake = Reservation {
            id: [9u8; 32],
            debtor: payer,
            amount_sat: 100_000,
            from_free_sat: 100_000,
            position_draws: Vec::new(),
            position_id: None,
        };
        assert!(book.settle(&fake).is_err(), "unknown id settles nothing");
        assert!(book.release(&fake).is_err(), "unknown id releases nothing");
        assert_eq!(book.total_settled(), 0);
        book.check_conservation().unwrap();

        // The real one settles once, then 4096 further consumptions evict
        // its outcome from the bounded log. A replay after eviction must
        // refuse — not debit the debtor's refilled line a second time.
        let res = book.reserve(&payer, 200_000, 3).unwrap();
        book.settle(&res).unwrap();
        let filler = [13u8; 20];
        book.deposit(filler, 10_000_000_000).unwrap();
        let mut last = book.reserve(&filler, 1_000, 4).unwrap();
        book.settle(&last).unwrap();
        for h in 5..(5 + 4_099) {
            let r = book.reserve(&filler, 1_000, h).unwrap();
            book.settle(&r).unwrap();
            last = r;
        }
        assert!(book.reservation_outcome(&res.id).is_none(), "evicted");
        book.deposit(payer, 200_000).unwrap();
        assert!(book.settle(&res).is_err(), "evicted replay refuses");
        assert_eq!(book.total_settled(), 200_000 + 4_100_000, "no second debit");
        book.check_conservation().unwrap();

        // Restart recovery: the outstanding set is runtime-only, so a
        // persisted-and-reloaded book cannot settle a live reservation
        // until the node re-marks it from its persisted reservations map.
        // Re-marking a consumed id stays decided by the outcome log.
        let live = book.reserve(&payer, 50_000, 99_999).unwrap();
        let bytes = book.encode();
        let mut rebooted = CreditBook::decode(&mut crate::ser::Reader::new(&bytes)).unwrap();
        assert!(rebooted.settle(&live).is_err(), "unmarked id refuses");
        rebooted.mark_outstanding(&live.id);
        rebooted.settle(&live).unwrap();
        rebooted.settle(&live).unwrap();
        assert_eq!(rebooted.total_settled(), 200_000 + 4_100_000 + 50_000);
        // Re-marking a consumed id changes nothing: the outcome log is
        // consulted first, so settle stays idempotent and release refused.
        rebooted.mark_outstanding(&last.id);
        rebooted.settle(&last).unwrap();
        assert!(rebooted.release(&last).is_err(), "settled stays settled");
        rebooted.check_conservation().unwrap();
    }

    #[test]
    fn a_reservation_is_refused_when_the_line_cannot_cover_it() {
        // Admission fails closed before anything is encumbered, so a refused
        // payment leaves the line exactly as it was.
        let payer = [12u8; 20];
        let mut book = CreditBook::new();
        book.deposit(payer, 10_000).unwrap();
        let err = book.reserve(&payer, 10_001, 1).unwrap_err();
        assert!(matches!(err, Error::InsufficientFunds { .. }), "{err:?}");
        assert_eq!(book.available(&payer), 10_000);
        assert_eq!(book.total_reserved(), 0);
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_position_backed_reservation_is_encumbered_not_double_spent() {
        // Position headroom is encumbered just like a free balance, so a second
        // payment cannot draw the same principal twice.
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        let s = spec(1_000_000, 1_000_000, 1, 10_000);
        let collateral = CreditPosition::open(&s).unwrap().collateral_sat;
        book.deposit(borrower, collateral.saturating_add(1_000_000))
            .unwrap();
        book.post_bond(borrower, 1_000_000).unwrap();
        let id = book.open(&s).unwrap();
        let before = book.positions.get(&id).unwrap().clone();
        // Free balance is exhausted (all collateral locked), so the draw is
        // charged against the position's outstanding principal.
        let res = book
            .reserve(&borrower, 1_000_000, 1)
            .expect("line covers the amount via the position");
        assert_eq!(res.position_id, Some(id));
        assert_eq!(book.total_reserved(), 1_000_000);
        // A second draw of the same principal has nothing left to encumber.
        assert!(book.reserve(&borrower, 1, 1).is_err(), "headroom is spent");
        // And nothing has been debited yet: the position is untouched.
        assert_eq!(book.positions.get(&id).unwrap(), &before);

        // Releasing gives the headroom back and leaves the position alone.
        book.release(&res).unwrap();
        assert_eq!(book.total_reserved(), 0);
        assert_eq!(book.positions.get(&id).unwrap(), &before);
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_default_whose_bond_is_short_leaves_the_book_untouched() {
        // The interrupted-operation defect, pinned: a default is priced before a
        // single bucket is written, so a refusal cannot strand a position in a
        // settled state with the value never recovered.
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 1_100_000).unwrap();
        book.post_bond(borrower, 50_000).unwrap();
        let id = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        let snapshot = book.clone();

        // Half the bond is taken elsewhere — the position still carries its
        // 50 000 price tag, but only 10 000 of bond is left to be taken. The
        // move keeps the book's own invariant intact, so the refusal below has
        // to be the *name* of the failure and not a conservation panic.
        let b = book.bonds.get_mut(&borrower).unwrap();
        *b -= 40_000;
        let f = book.free.entry(borrower).or_insert(0);
        *f += 40_000;
        let p = book.bond_pledged.get_mut(&borrower).unwrap();
        *p -= 40_000;
        book.check_conservation().unwrap();

        let err = book.default(&id, 100).unwrap_err();
        assert!(err.to_string().contains("bond"), "{err}");

        // Nothing was applied: the position is still live, so it can still be
        // repaid, and the book still balances.
        assert!(book.live_positions().any(|(pid, _)| pid == &id));
        assert_eq!(
            book.positions.get(&id).unwrap(),
            snapshot.positions.get(&id).unwrap()
        );
        assert_eq!(book.total_locked_collateral(), 950_000);
        assert_eq!(book.total_settled(), 0);
        assert_eq!(book.recovered(&[2u8; 20]), 0);
        book.check_conservation().unwrap();
    }

    #[test]
    fn settling_a_reservation_that_was_never_made_fails_cleanly() {
        // The failure mode a settlement must actually defend against now that
        // capacity is encumbered at admission: a caller handing over a
        // reservation the book never granted. There is nothing to debit, so the
        // settle refuses rather than inventing a debit.
        let payer = [8u8; 20];
        let mut book = CreditBook::new();
        book.deposit(payer, 100_000).unwrap();
        let res = book.reserve(&payer, 100_000, 1).unwrap();
        assert!(res.position_id.is_none());
        book.release(&res).unwrap();
        let err = book.settle(&res).unwrap_err();
        match err {
            crate::error::Error::Malformed(m) => assert!(m.contains("released")),
            other => panic!("expected Malformed, got {other:?}"),
        }
        assert_eq!(book.total_settled(), 0);
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_position_backed_reservation_is_encumbered_until_settled_or_released() {
        // Position headroom is encumbered at admission just like a free
        // balance, so the same principal cannot back two admitted payments, and
        // the position itself is only ever touched by the lifecycle.
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        let s = spec(1_000_000, 1_000_000, 1, 10_000);
        let collateral = CreditPosition::open(&s).unwrap().collateral_sat;
        book.deposit(borrower, collateral.saturating_add(1_000_000))
            .unwrap();
        book.post_bond(borrower, 1_000_000).unwrap();
        let id = book.open(&s).unwrap();
        let before = book.positions.get(&id).unwrap().clone();
        let res = book
            .reserve(&borrower, 1_000_000, 1)
            .expect("line covers the amount via the position");
        assert_eq!(res.position_id, Some(id));
        assert_eq!(book.total_reserved(), 1_000_000);

        // The charge against the position is a lifecycle event: `repay` is how a
        // position's principal moves, and the settlement layer calls that. The
        // reservation only ever holds the capacity.
        assert_eq!(
            book.positions.get(&id).unwrap(),
            &before,
            "no half-applied debit"
        );
        book.release(&res).unwrap();
        assert_eq!(book.total_reserved(), 0);
        assert_eq!(book.positions.get(&id).unwrap(), &before);
        book.check_conservation().unwrap();
    }

    // -- remote-crash regressions (routed from the unauthenticated API) ------

    #[test]
    fn a_zero_amount_bond_operation_is_refused_not_a_panic() {
        // The node's `POST /v1/credit/bond` reaches these calls with whatever
        // amount the JSON carries. A zero amount used to fall through both
        // guards (`0 < 0` is false for a missing entry) and hit a `get_mut`
        // unwrap on a key that was never inserted — an abort for the whole
        // node under `panic = "abort"`. Zero is now a named refusal.
        let unknown = [7u8; 20];
        let mut book = CreditBook::new();
        let err = book.post_bond(unknown, 0).unwrap_err();
        assert!(err.to_string().contains("positive"), "{err}");
        let err = book.release_bond(unknown, 0).unwrap_err();
        assert!(err.to_string().contains("positive"), "{err}");

        // A funded agent gets the same refusal: zero is a client error whatever
        // the balance.
        book.deposit(unknown, 1_000).unwrap();
        assert!(book.post_bond(unknown, 0).is_err());
        book.post_bond(unknown, 1_000).unwrap();
        assert!(book.release_bond(unknown, 0).is_err());
        assert_eq!(book.bond(&unknown), 1_000);
        book.check_conservation().unwrap();
    }

    #[test]
    fn bond_operations_against_an_unknown_address_fail_cleanly() {
        let mut book = CreditBook::new();
        let err = book.post_bond([8u8; 20], 1_000).unwrap_err();
        assert!(err.to_string().contains("free balance"), "{err}");
        let err = book.release_bond([8u8; 20], 1_000).unwrap_err();
        assert!(err.to_string().contains("no posted bond"), "{err}");
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_zero_collateral_term_set_is_rejected_by_name() {
        // The documentation promises there is no path to a zero-collateral line.
        // That invariant is enforced in `required_collateral`, not left to callers
        // to remember.
        let zero_terms = CreditTerms {
            base_collateral_bps: 10_000,
            max_discount_bps: 0,
            bond_ratio_bps: 0,
            min_collateral_bps: 0,
        };
        let s = PositionSpec {
            terms: zero_terms,
            charge: ChargeSchedule {
                rate_bps_per_window: 0,
                window_blocks: 100,
            },
            borrower: [3u8; 20],
            agent_id: [9u8; 32],
            lender: [2u8; 20],
            amount_sat: 1,
            bond_sat: 0,
            drawn_at_height: 0,
            deadline_height: 100,
        };
        assert!(
            matches!(
                CreditPosition::open(&s),
                Err(Error::Malformed(
                    "credit terms: a zero collateral floor is not permitted"
                ))
            ),
            "zero-collateral terms must be refused by name"
        );
    }

    #[test]
    fn a_new_borrower_with_a_small_position_does_not_panic() {
        // The original bug: a 1-sat position under terms with a small floor hit
        // `self.free.get_mut(..).unwrap()` on a missing borrower key. The fix
        // uses `entry().or_insert(0)`; this pins it with real (non-zero) terms.
        let mut book = CreditBook::new();
        let terms = CreditTerms::default(); // 80% floor
        let s = PositionSpec {
            terms,
            charge: ChargeSchedule {
                rate_bps_per_window: 0,
                window_blocks: 100,
            },
            borrower: [3u8; 20],
            agent_id: [9u8; 32],
            lender: [2u8; 20],
            amount_sat: 100,
            bond_sat: 0,
            drawn_at_height: 0,
            deadline_height: 100,
        };
        let required = terms.required_collateral(100, 0).unwrap();
        // Fund the lender and borrower with the required values.
        book.deposit([2u8; 20], 1000).unwrap();
        book.deposit([3u8; 20], required).unwrap();
        let id = book
            .open(&s)
            .expect("a collateralised position still opens");
        // A zero repayment against it is a clean no-op, not a panic.
        let r = book.repay(&id, 0, 1).unwrap();
        assert_eq!(r.remaining_debt_sat, 100);
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_reservation_survives_restart_round_trip() {
        let reservation = Reservation {
            id: [9u8; 32],
            debtor: [7u8; 20],
            amount_sat: 500,
            from_free_sat: 200,
            position_draws: vec![([3u8; 32], 200), ([4u8; 32], 300)],
            position_id: Some([3u8; 32]),
        };

        let bytes = reservation.encode();
        let mut cursor = crate::ser::Reader::new(&bytes);
        let back = Reservation::decode(&mut cursor).expect("reservation decodes");
        assert!(cursor.is_done(), "decode must consume exactly its bytes");
        assert_eq!(back, reservation);
        assert_eq!(back.encode(), bytes, "re-encode must be byte-identical");

        // A draw count the remaining bytes cannot back is refused before any
        // allocation: 999 draws * 40 bytes is more than the file holds.
        let mut lying = bytes.clone();
        lying[68..72].copy_from_slice(&999u32.to_le_bytes());
        assert!(Reservation::decode(&mut crate::ser::Reader::new(&lying)).is_err());

        // An unknown position tag is refused rather than guessed.
        let mut bad_tag = bytes.clone();
        bad_tag[152] = 2;
        assert!(Reservation::decode(&mut crate::ser::Reader::new(&bad_tag)).is_err());
    }
}
