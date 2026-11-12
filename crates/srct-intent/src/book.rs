//! Intent lifecycle and settlement instructions.
//!
//! The book is a pure state machine. It verifies signatures, quote constraints,
//! delivery timing and dispute authority, and returns the exact instruction the
//! existing payment/escrow layer should execute. It never moves value itself.

use std::collections::BTreeMap;

use srct_core::hash::{Address, Hash};
use srct_verify::{
    AttestationRoots, Evidence as VerifyEvidence, EvidenceKind, SignedFheReceipt, SignedFheTask,
    SignedTeeQuote, SignedZkReceipt, SignedZkTask, TeeSla, UnifiedVerifier, VerifiedOutput,
    VerifyError,
};

use crate::types::{
    Amount, Delivery, Intent, Privacy, Quote, SignedDelivery, SignedDispute, SignedIntent,
    SignedQuote, SignedResolution, Verification, DELIVERY_VERSION,
};

/// Why an intent operation was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum IntentError {
    UnknownIntent,
    DuplicateIntent,
    IntentExpired,
    DuplicateQuote,
    QuoteUnknown,
    QuoteExpired,
    QuoteTooExpensive,
    QuoteTooSlow,
    AssetNotAccepted,
    RouteMissing,
    RouteMismatch,
    RouteExpired,
    VerificationTooLow,
    PrivacyTooLow,
    BadSignature(String),
    BadState(&'static str),
    WrongSolver,
    FutureDelivery,
    LateDelivery,
    EmptyResult,
    EmptyEvidence,
    EvidenceMismatch,
    EvidenceMissing,
    BadEvidence(String),
    NotAuthorized,
    WrongArbiter,
    Overflow,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::UnknownIntent => write!(f, "unknown intent"),
            IntentError::DuplicateIntent => write!(f, "intent already exists"),
            IntentError::IntentExpired => write!(f, "intent deadline has passed"),
            IntentError::DuplicateQuote => write!(f, "solver already quoted this intent"),
            IntentError::QuoteUnknown => write!(f, "quote is not recorded for this intent"),
            IntentError::QuoteExpired => write!(f, "quote has expired"),
            IntentError::QuoteTooExpensive => write!(f, "quote exceeds the price cap"),
            IntentError::QuoteTooSlow => write!(f, "quote exceeds the latency cap"),
            IntentError::AssetNotAccepted => write!(f, "quote asset is not accepted"),
            IntentError::RouteMissing => write!(f, "cross-asset quote needs a route"),
            IntentError::RouteMismatch => write!(f, "route does not connect the required assets"),
            IntentError::RouteExpired => write!(f, "route has expired"),
            IntentError::VerificationTooLow => write!(f, "quote verification is below the floor"),
            IntentError::PrivacyTooLow => write!(f, "quote privacy is below the floor"),
            IntentError::BadSignature(detail) => write!(f, "invalid signature: {detail}"),
            IntentError::BadState(detail) => write!(f, "intent is in the wrong state: {detail}"),
            IntentError::WrongSolver => write!(f, "delivery is not from the accepted solver"),
            IntentError::FutureDelivery => write!(f, "delivery claims a future height"),
            IntentError::LateDelivery => write!(f, "delivery arrived after its deadline"),
            IntentError::EmptyResult => write!(f, "delivery result hash is zero"),
            IntentError::EmptyEvidence => write!(f, "dispute evidence hash is zero"),
            IntentError::EvidenceMismatch => write!(f, "evidence does not match"),
            IntentError::EvidenceMissing => write!(f, "required execution evidence is missing"),
            IntentError::BadEvidence(detail) => write!(f, "evidence refused: {detail}"),
            IntentError::NotAuthorized => write!(f, "caller is not the creator or arbiter"),
            IntentError::WrongArbiter => write!(f, "resolution is not signed by the arbiter"),
            IntentError::Overflow => write!(f, "arithmetic overflow"),
        }
    }
}

impl std::error::Error for IntentError {}

/// Lifecycle state of one intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentState {
    Open,
    Accepted {
        quote: Hash,
        solver: Address,
        price: Amount,
        delivery_by_height: u64,
    },
    Fulfilled {
        quote: Hash,
        solver: Address,
        price: Amount,
        result: Hash,
        delivery: Hash,
        at_height: u64,
    },
    Disputed {
        quote: Hash,
        solver: Address,
        price: Amount,
        evidence: Hash,
        at_height: u64,
    },
    Settled {
        solver: Address,
        amount: Amount,
        at_height: u64,
    },
    Refunded {
        at_height: u64,
    },
}

/// What the settlement layer should do after a fulfilled intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementInstruction {
    pub from: Address,
    pub to: Address,
    pub amount: Amount,
    pub intent: Hash,
    pub reference: Hash,
}

/// Why the creator's escrow is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundReason {
    Expired,
    Resolved,
}

/// What the settlement layer should do after an expiry or a dispute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefundInstruction {
    pub to: Address,
    pub amount: Amount,
    pub intent: Hash,
    pub reason: RefundReason,
}

/// Outcome of an arbiter resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolutionOutcome {
    pub settlement: Option<SettlementInstruction>,
    pub refund: Option<RefundInstruction>,
    /// Bond back to an honest challenger (arbiter ruled for the creator).
    pub bond_release: Option<BondRelease>,
    /// Bond slashed from a frivolous challenger to the wronged solver.
    pub bond_slash: Option<BondSlash>,
}

/// A posted dispute bond returned to its challenger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondRelease {
    pub to: Address,
    pub amount_sat: u64,
    pub intent: Hash,
}

/// A posted dispute bond slashed to the solver it wrongly accused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondSlash {
    pub from: Address,
    pub to: Address,
    pub amount_sat: u64,
    pub intent: Hash,
}

struct Record {
    signed: SignedIntent,
    quotes: BTreeMap<Address, SignedQuote>,
    state: IntentState,
    expected: Option<ExpectedEvidence>,
    verified: Option<EvidenceKind>,
    /// Optional challenger bond posted against a frivolous dispute. Set by
    /// `bond_dispute`, consumed by `resolve`.
    dispute_bond: Option<(Address, u64)>,
}

/// What the rail expects the solver to prove, pinned by the creator or the
/// arbiter. The SLA/task pins the exact measurements; the rail checks the
/// worker against them at `attach_evidence` time.
#[derive(Clone, Debug)]
pub enum ExpectedEvidence {
    Tee(TeeSla),
    Zk(SignedZkTask),
    Fhe(SignedFheTask),
}

impl ExpectedEvidence {
    fn kind(&self) -> EvidenceKind {
        match self {
            ExpectedEvidence::Tee(_) => EvidenceKind::Tee,
            ExpectedEvidence::Zk(_) => EvidenceKind::Zk,
            ExpectedEvidence::Fhe(_) => EvidenceKind::Fhe,
        }
    }
}

/// Solver-submitted evidence. The request is checked against the pinned
/// expectation (kind, worker binding) and then verified cryptographically.
#[derive(Clone, Debug)]
pub enum IntentEvidence {
    Tee(SignedTeeQuote),
    Zk(SignedZkTask, SignedZkReceipt),
    Fhe(SignedFheTask, SignedFheReceipt),
}

impl IntentEvidence {
    fn kind(&self) -> EvidenceKind {
        match self {
            IntentEvidence::Tee(_) => EvidenceKind::Tee,
            IntentEvidence::Zk(_, _) => EvidenceKind::Zk,
            IntentEvidence::Fhe(_, _) => EvidenceKind::Fhe,
        }
    }
}

/// In-memory intent book. Persistence is the caller's responsibility; the
/// state machine itself is deterministic.
///
/// The book is also the evidence rail: it holds the attestation trust roots
/// and a unified verifier, pins creator/arbiter expectations, and refuses to
/// settle high-verification intents without matching verified evidence.
/// Arbitration (`dispute`/`resolve`) stays available as the fallback.
#[derive(Default)]
pub struct IntentBook {
    records: BTreeMap<Hash, Record>,
    roots: AttestationRoots,
    verifier: UnifiedVerifier,
}

/// Most intents one atomic split may open. Past the cap the caller batches.
pub const MAX_SPLIT_INTENTS: usize = 64;

impl IntentBook {
    pub fn new() -> Self {
        IntentBook::default()
    }

    /// Trust roots for TEE attestation quotes. The rail operator configures
    /// hardware trust out of band; unknown attesters are refused.
    pub fn attestation_roots_mut(&mut self) -> &mut AttestationRoots {
        &mut self.roots
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn state(&self, intent: &Hash) -> Option<&IntentState> {
        self.records.get(intent).map(|r| &r.state)
    }

    pub fn intent(&self, intent: &Hash) -> Option<&Intent> {
        self.records.get(intent).map(|r| &r.signed.intent)
    }

    pub fn signed_intent(&self, intent: &Hash) -> Option<&SignedIntent> {
        self.records.get(intent).map(|r| &r.signed)
    }

    pub fn quote_for(&self, intent: &Hash, solver: &Address) -> Option<&SignedQuote> {
        self.records.get(intent)?.quotes.get(solver)
    }

    /// Publish a signed intent.
    pub fn open(&mut self, signed: SignedIntent, height: u64) -> Result<Hash, IntentError> {
        signed.verify().map_err(IntentError::BadSignature)?;
        let intent = &signed.intent;
        if height > intent.deadline_height {
            return Err(IntentError::IntentExpired);
        }
        let id = intent.hash();
        if self.records.contains_key(&id) {
            return Err(IntentError::DuplicateIntent);
        }
        self.records.insert(
            id,
            Record {
                signed,
                quotes: BTreeMap::new(),
                state: IntentState::Open,
                expected: None,
                verified: None,
                dispute_bond: None,
            },
        );
        Ok(id)
    }

    /// Open several intents atomically for multi-solver stages: either every
    /// intent opens or none does. Each intent is validated exactly as in
    /// [`IntentBook::open`] (signature, deadline, no duplicate) — including
    /// against its siblings, so two identical shares in one batch are
    /// refused rather than half-opened.
    pub fn open_split(
        &mut self,
        batch: Vec<SignedIntent>,
        height: u64,
    ) -> Result<Vec<Hash>, IntentError> {
        if batch.is_empty() {
            return Err(IntentError::BadState("split holds no intents"));
        }
        if batch.len() > MAX_SPLIT_INTENTS {
            return Err(IntentError::BadState("split is over cap"));
        }
        let mut ids = Vec::with_capacity(batch.len());
        for signed in &batch {
            signed.verify().map_err(IntentError::BadSignature)?;
            if height > signed.intent.deadline_height {
                return Err(IntentError::IntentExpired);
            }
            let id = signed.intent.hash();
            if self.records.contains_key(&id) || ids.contains(&id) {
                return Err(IntentError::DuplicateIntent);
            }
            ids.push(id);
        }
        for (signed, id) in batch.into_iter().zip(ids.iter()) {
            self.records.insert(
                *id,
                Record {
                    signed,
                    quotes: BTreeMap::new(),
                    state: IntentState::Open,
                    expected: None,
                    verified: None,
                    dispute_bond: None,
                },
            );
        }
        Ok(ids)
    }

    /// Submit a solver quote. One quote per solver per intent; a second quote
    /// is refused rather than silently replacing the first.
    pub fn quote(&mut self, signed: SignedQuote, height: u64) -> Result<Hash, IntentError> {
        signed.verify().map_err(IntentError::BadSignature)?;
        let id = signed.quote.intent;
        let record = self
            .records
            .get_mut(&id)
            .ok_or(IntentError::UnknownIntent)?;
        if record.state != IntentState::Open {
            return Err(IntentError::BadState("intent is no longer open"));
        }
        if record.quotes.contains_key(&signed.quote.solver) {
            return Err(IntentError::DuplicateQuote);
        }
        validate_quote(&signed.quote, &record.signed.intent, height)?;
        let hash = signed.quote.hash();
        record.quotes.insert(signed.quote.solver, signed);
        Ok(hash)
    }

    /// Best currently valid quote, ordered by converted cost, then latency,
    /// then solver address. Cross-asset quotes are ranked by the route's
    /// inverse estimate in the intent's max-price asset.
    pub fn best_quote(&self, intent: &Hash, height: u64) -> Option<&SignedQuote> {
        let record = self.records.get(intent)?;
        if record.state != IntentState::Open {
            return None;
        }
        let cap = &record.signed.intent;
        record
            .quotes
            .values()
            .filter(|q| validate_quote(&q.quote, cap, height).is_ok())
            .min_by(|a, b| {
                rank_cost(&a.quote, cap)
                    .cmp(&rank_cost(&b.quote, cap))
                    .then_with(|| a.quote.latency_ms.cmp(&b.quote.latency_ms))
                    .then_with(|| a.quote.solver.cmp(&b.quote.solver))
            })
    }

    /// Accept the best quote, or a named solver's quote. Returns the accepted
    /// quote hash.
    pub fn accept(
        &mut self,
        intent: &Hash,
        solver: Option<Address>,
        height: u64,
    ) -> Result<Hash, IntentError> {
        let record = self
            .records
            .get_mut(intent)
            .ok_or(IntentError::UnknownIntent)?;
        if record.state != IntentState::Open {
            return Err(IntentError::BadState("intent is no longer open"));
        }
        let chosen = match solver {
            Some(solver) => record
                .quotes
                .get(&solver)
                .ok_or(IntentError::QuoteUnknown)?,
            None => {
                let cap = &record.signed.intent;
                record
                    .quotes
                    .values()
                    .filter(|q| validate_quote(&q.quote, cap, height).is_ok())
                    .min_by(|a, b| {
                        rank_cost(&a.quote, cap)
                            .cmp(&rank_cost(&b.quote, cap))
                            .then_with(|| a.quote.latency_ms.cmp(&b.quote.latency_ms))
                            .then_with(|| a.quote.solver.cmp(&b.quote.solver))
                    })
                    .ok_or(IntentError::QuoteUnknown)?
            }
        };
        validate_quote(&chosen.quote, &record.signed.intent, height)?;
        let delivery_by_height = chosen
            .quote
            .valid_until_height
            .min(record.signed.intent.deadline_height);
        if height > delivery_by_height {
            return Err(IntentError::QuoteExpired);
        }
        let quote_hash = chosen.quote.hash();
        record.state = IntentState::Accepted {
            quote: quote_hash,
            solver: chosen.quote.solver,
            price: chosen.quote.price,
            delivery_by_height,
        };
        Ok(quote_hash)
    }

    /// Record a solver delivery against the accepted quote.
    pub fn fulfill(
        &mut self,
        intent: &Hash,
        signed: SignedDelivery,
        height: u64,
    ) -> Result<(), IntentError> {
        signed.verify().map_err(IntentError::BadSignature)?;
        let record = self
            .records
            .get_mut(intent)
            .ok_or(IntentError::UnknownIntent)?;
        let (quote, solver, price, delivery_by_height) = match &record.state {
            IntentState::Accepted {
                quote,
                solver,
                price,
                delivery_by_height,
            } => (*quote, *solver, *price, *delivery_by_height),
            _ => return Err(IntentError::BadState("intent is not accepted")),
        };
        let delivery: &Delivery = &signed.delivery;
        if delivery.version != DELIVERY_VERSION {
            return Err(IntentError::BadSignature(
                "unsupported delivery version".into(),
            ));
        }
        if delivery.intent != *intent {
            return Err(IntentError::BadSignature(
                "delivery names another intent".into(),
            ));
        }
        if delivery.quote != quote {
            return Err(IntentError::BadSignature(
                "delivery names another quote".into(),
            ));
        }
        if delivery.solver != solver {
            return Err(IntentError::WrongSolver);
        }
        if delivery.height > height {
            return Err(IntentError::FutureDelivery);
        }
        if delivery.height > delivery_by_height {
            return Err(IntentError::LateDelivery);
        }
        if delivery.result == [0u8; 32] {
            return Err(IntentError::EmptyResult);
        }
        record.state = IntentState::Fulfilled {
            quote,
            solver,
            price,
            result: delivery.result,
            delivery: delivery.hash(),
            at_height: height,
        };
        Ok(())
    }

    /// Pin what evidence the solver must present, signed off by the creator
    /// or the arbiter. Allowed while the intent is open, accepted or
    /// fulfilled; the rail authenticates the caller and passes its address.
    pub fn expect_evidence(
        &mut self,
        intent: &Hash,
        expected: ExpectedEvidence,
        authority: &Address,
    ) -> Result<(), IntentError> {
        let record = self
            .records
            .get_mut(intent)
            .ok_or(IntentError::UnknownIntent)?;
        if *authority != record.signed.intent.creator && *authority != record.signed.intent.arbiter
        {
            return Err(IntentError::NotAuthorized);
        }
        match &record.state {
            IntentState::Open | IntentState::Accepted { .. } | IntentState::Fulfilled { .. } => {}
            _ => {
                return Err(IntentError::BadState(
                    "intent can no longer take expectations",
                ))
            }
        }
        if let ExpectedEvidence::Zk(task) = &expected {
            task.verify()
                .map_err(|e| IntentError::BadEvidence(e.to_string()))?;
        }
        record.expected = Some(expected);
        Ok(())
    }

    /// Verify solver-submitted evidence against the pinned expectation and
    /// the accepted solver. Only on fulfilled intents: evidence arrives with
    /// or after the delivery, and settlement consumes the verdict.
    pub fn attach_evidence(
        &mut self,
        intent: &Hash,
        evidence: IntentEvidence,
        height: u64,
    ) -> Result<VerifiedOutput, IntentError> {
        // Read the expectation and the accepted solver first; the borrow ends
        // before verification takes `&mut self`.
        let (solver, expected) = {
            let record = self.records.get(intent).ok_or(IntentError::UnknownIntent)?;
            let solver = match &record.state {
                IntentState::Fulfilled { solver, .. } => *solver,
                _ => return Err(IntentError::BadState("intent is not fulfilled")),
            };
            let expected = record
                .expected
                .clone()
                .ok_or(IntentError::EvidenceMissing)?;
            (solver, expected)
        };
        if evidence.kind() != expected.kind() {
            return Err(IntentError::EvidenceMismatch);
        }
        let bundle = match (expected, &evidence) {
            (ExpectedEvidence::Tee(sla), IntentEvidence::Tee(quote)) => {
                if sla.provider != solver || quote.quote.provider != sla.provider {
                    return Err(IntentError::EvidenceMismatch);
                }
                VerifyEvidence::Tee {
                    sla,
                    quote: quote.clone(),
                }
            }
            (ExpectedEvidence::Zk(task), IntentEvidence::Zk(submitted, receipt)) => {
                if submitted.hash() != task.hash() {
                    return Err(IntentError::EvidenceMismatch);
                }
                if task.task.provider != solver {
                    return Err(IntentError::EvidenceMismatch);
                }
                VerifyEvidence::Zk {
                    task,
                    receipt: receipt.clone(),
                }
            }
            (ExpectedEvidence::Fhe(task), IntentEvidence::Fhe(submitted, receipt)) => {
                if submitted.hash() != task.hash() {
                    return Err(IntentError::EvidenceMismatch);
                }
                if task.task.provider != solver {
                    return Err(IntentError::EvidenceMismatch);
                }
                VerifyEvidence::Fhe {
                    task,
                    receipt: receipt.clone(),
                }
            }
            _ => return Err(IntentError::EvidenceMismatch),
        };
        let output = self
            .verifier
            .verify(&bundle, &self.roots, height)
            .map_err(|e| IntentError::BadEvidence(map_verify_error(e)))?;
        let record = self
            .records
            .get_mut(intent)
            .ok_or(IntentError::UnknownIntent)?;
        record.verified = Some(evidence.kind());
        Ok(output)
    }

    /// Release the escrow to the solver after a delivery.
    ///
    /// High-verification intents (`Tee` and above) additionally require
    /// verified evidence of a satisfying kind: a stronger proof satisfies a
    /// weaker requirement, never the reverse.
    pub fn settle(
        &mut self,
        intent: &Hash,
        height: u64,
    ) -> Result<SettlementInstruction, IntentError> {
        let record = self
            .records
            .get_mut(intent)
            .ok_or(IntentError::UnknownIntent)?;
        let (solver, price, delivery) = match &record.state {
            IntentState::Fulfilled {
                solver,
                price,
                delivery,
                ..
            } => (*solver, *price, *delivery),
            _ => return Err(IntentError::BadState("intent is not fulfilled")),
        };
        let required = record.signed.intent.min_verification;
        if required >= Verification::Tee {
            match record.verified {
                Some(kind) if evidence_level(kind) >= required => {}
                _ => return Err(IntentError::EvidenceMissing),
            }
        }
        // Sealed execution settles only on verified encrypted compute: the
        // privacy label is a gate now, not a comment. Tee-privacy delivery
        // still rides the verification gate above; Fhe-privacy demands the
        // homomorphic receipt itself.
        if record.signed.intent.min_privacy == Privacy::Fhe
            && record.verified != Some(EvidenceKind::Fhe)
        {
            return Err(IntentError::EvidenceMissing);
        }
        record.state = IntentState::Settled {
            solver,
            amount: price,
            at_height: height,
        };
        Ok(SettlementInstruction {
            from: record.signed.intent.creator,
            to: solver,
            amount: price,
            intent: *intent,
            reference: delivery,
        })
    }

    /// Return the creator's escrow after an expiry. An accepted-but-undelivered
    /// intent refunds after its delivery deadline; an open intent refunds after
    /// its own deadline.
    pub fn refund(&mut self, intent: &Hash, height: u64) -> Result<RefundInstruction, IntentError> {
        let record = self
            .records
            .get_mut(intent)
            .ok_or(IntentError::UnknownIntent)?;
        let refundable = match &record.state {
            IntentState::Open => height > record.signed.intent.deadline_height,
            IntentState::Accepted {
                delivery_by_height, ..
            } => height > *delivery_by_height,
            _ => false,
        };
        if !refundable {
            return Err(IntentError::BadState("intent is not refundable"));
        }
        record.state = IntentState::Refunded { at_height: height };
        Ok(RefundInstruction {
            to: record.signed.intent.creator,
            amount: record.signed.intent.max_price,
            intent: *intent,
            reason: RefundReason::Expired,
        })
    }

    /// Challenge a delivered result. The creator signs the challenge and only
    /// a fulfilled, unsettled intent can be disputed.
    pub fn dispute(&mut self, signed: SignedDispute, height: u64) -> Result<(), IntentError> {
        signed.verify().map_err(IntentError::BadSignature)?;
        if signed.dispute.evidence == [0u8; 32] {
            return Err(IntentError::EmptyEvidence);
        }
        let id = signed.dispute.intent;
        let record = self
            .records
            .get_mut(&id)
            .ok_or(IntentError::UnknownIntent)?;
        if signed.dispute.creator != record.signed.intent.creator {
            return Err(IntentError::BadSignature(
                "dispute is not from the creator".into(),
            ));
        }
        let (quote, solver, price) = match &record.state {
            IntentState::Fulfilled {
                quote,
                solver,
                price,
                ..
            } => (*quote, *solver, *price),
            _ => return Err(IntentError::BadState("intent is not fulfilled")),
        };
        record.state = IntentState::Disputed {
            quote,
            solver,
            price,
            evidence: signed.dispute.evidence,
            at_height: height,
        };
        Ok(())
    }

    /// Post a bond against a frivolous dispute. Only the creator — the only
    /// party that can dispute — may bond, only while fulfilled, only once,
    /// and only a positive amount. The bond is an instruction the escrow rail
    /// executes; this book records it. Unbonded disputes keep the legacy
    /// path: `resolve` without bond instructions.
    pub fn bond_dispute(
        &mut self,
        intent: &Hash,
        challenger: Address,
        amount_sat: u64,
    ) -> Result<(), IntentError> {
        let record = self
            .records
            .get_mut(intent)
            .ok_or(IntentError::UnknownIntent)?;
        if challenger != record.signed.intent.creator {
            return Err(IntentError::BadSignature(
                "dispute bond is not from the creator".into(),
            ));
        }
        match &record.state {
            IntentState::Fulfilled { .. } => {}
            _ => return Err(IntentError::BadState("intent is not fulfilled")),
        }
        if amount_sat == 0 {
            return Err(IntentError::BadSignature(
                "dispute bond amount is zero".into(),
            ));
        }
        if record.dispute_bond.is_some() {
            return Err(IntentError::BadState("intent already bonded"));
        }
        record.dispute_bond = Some((challenger, amount_sat));
        Ok(())
    }

    /// Apply an arbiter-signed resolution to a disputed intent.
    pub fn resolve(
        &mut self,
        signed: SignedResolution,
        height: u64,
    ) -> Result<ResolutionOutcome, IntentError> {
        signed.verify().map_err(IntentError::BadSignature)?;
        let id = signed.resolution.intent;
        let record = self
            .records
            .get_mut(&id)
            .ok_or(IntentError::UnknownIntent)?;
        let (solver, price, evidence) = match &record.state {
            IntentState::Disputed {
                solver,
                price,
                evidence,
                ..
            } => (*solver, *price, *evidence),
            _ => return Err(IntentError::BadState("intent is not disputed")),
        };
        if signed.resolution.arbiter != record.signed.intent.arbiter {
            return Err(IntentError::WrongArbiter);
        }
        if signed.resolution.evidence != evidence {
            return Err(IntentError::EvidenceMismatch);
        }
        if signed.resolution.release_to_solver {
            record.state = IntentState::Settled {
                solver,
                amount: price,
                at_height: height,
            };
            // The challenge was frivolous: a posted bond goes to the
            // wronged solver. No bond, no instruction — the legacy path.
            let bond_slash = record
                .dispute_bond
                .take()
                .map(|(from, amount_sat)| BondSlash {
                    from,
                    to: solver,
                    amount_sat,
                    intent: id,
                });
            Ok(ResolutionOutcome {
                settlement: Some(SettlementInstruction {
                    from: record.signed.intent.creator,
                    to: solver,
                    amount: price,
                    intent: id,
                    reference: evidence,
                }),
                refund: None,
                bond_release: None,
                bond_slash,
            })
        } else {
            record.state = IntentState::Refunded { at_height: height };
            // The challenge was honest: a posted bond returns to the
            // challenger alongside the creator's refund.
            let bond_release = record
                .dispute_bond
                .take()
                .map(|(to, amount_sat)| BondRelease {
                    to,
                    amount_sat,
                    intent: id,
                });
            Ok(ResolutionOutcome {
                settlement: None,
                refund: Some(RefundInstruction {
                    to: record.signed.intent.creator,
                    amount: record.signed.intent.max_price,
                    intent: id,
                    reason: RefundReason::Resolved,
                }),
                bond_release,
                bond_slash: None,
            })
        }
    }
}

fn validate_quote(quote: &Quote, intent: &Intent, height: u64) -> Result<(), IntentError> {
    if quote.version != crate::types::QUOTE_VERSION {
        return Err(IntentError::BadSignature(
            "unsupported quote version".into(),
        ));
    }
    if quote.intent != intent.hash() {
        return Err(IntentError::BadSignature(
            "quote names another intent".into(),
        ));
    }
    if quote.price.amount == 0 {
        return Err(IntentError::QuoteTooExpensive);
    }
    if quote.latency_ms == 0 || quote.latency_ms > intent.max_latency_ms {
        return Err(IntentError::QuoteTooSlow);
    }
    if quote.verification < intent.min_verification {
        return Err(IntentError::VerificationTooLow);
    }
    if quote.privacy < intent.min_privacy {
        return Err(IntentError::PrivacyTooLow);
    }
    if height > quote.valid_until_height || quote.valid_until_height > intent.deadline_height {
        return Err(IntentError::QuoteExpired);
    }
    if !intent.accepted_assets.contains(&quote.price.asset) {
        return Err(IntentError::AssetNotAccepted);
    }
    if quote.price.asset == intent.max_price.asset {
        if quote.route.is_some() {
            return Err(IntentError::RouteMismatch);
        }
        if quote.price.amount > intent.max_price.amount {
            return Err(IntentError::QuoteTooExpensive);
        }
        return Ok(());
    }
    let route = quote.route.as_ref().ok_or(IntentError::RouteMissing)?;
    if route.route.from != intent.max_price.asset || route.route.to != quote.price.asset {
        return Err(IntentError::RouteMismatch);
    }
    if height > route.route.valid_until_height {
        return Err(IntentError::RouteExpired);
    }
    let affordable = route
        .route
        .convert(intent.max_price.amount)
        .map_err(|_| IntentError::Overflow)?;
    if quote.price.amount > affordable {
        return Err(IntentError::QuoteTooExpensive);
    }
    Ok(())
}

fn rank_cost(quote: &Quote, intent: &Intent) -> u64 {
    if quote.price.asset == intent.max_price.asset {
        return quote.price.amount;
    }
    quote
        .route
        .as_ref()
        .and_then(|r| r.route.inverse_estimate(quote.price.amount).ok())
        .unwrap_or(u64::MAX)
}

/// Convenience: a gate that refuses a quote whose verification floor is not
/// met. Kept explicit so callers do not compare raw bytes by accident.
pub fn meets_verification(quote: &Quote, required: Verification) -> bool {
    quote.verification >= required
}

/// Convenience for privacy floors.
pub fn meets_privacy(quote: &Quote, required: Privacy) -> bool {
    quote.privacy >= required
}

/// Verification strength of verified evidence, for the settle gate.
/// `Fhe`/`Compute` are unreachable as intent delivery evidence (intents take
/// Tee/Zk evidence only) and map below the gate on purpose.
fn evidence_level(kind: EvidenceKind) -> Verification {
    match kind {
        EvidenceKind::Tee => Verification::Tee,
        EvidenceKind::Fhe => Verification::ProviderSigned,
        EvidenceKind::Zk => Verification::Zk,
        EvidenceKind::Compute => Verification::ProviderSigned,
    }
}

fn map_verify_error(e: VerifyError) -> String {
    e.to_string()
}

/// Snapshot version for [`IntentBook`] restart persistence.
pub const BOOK_VERSION: u8 = 1;
/// Most intents one snapshot holds. Past the cap the operator archives.
pub const MAX_BOOK_INTENTS: usize = 10_000;
/// Most quotes one intent carries in a snapshot.
pub const MAX_BOOK_QUOTES: usize = 64;
/// Most bytes one signed blob may occupy in a snapshot.
pub const MAX_BOOK_BLOB: usize = 65_536;

fn book_fail(detail: String) -> IntentError {
    IntentError::BadSignature(detail)
}

fn write_blob(w: &mut srct_core::ser::Writer, bytes: &[u8]) {
    w.u32le(bytes.len() as u32).raw(bytes);
}

fn read_blob(r: &mut srct_core::ser::Reader) -> Result<Vec<u8>, IntentError> {
    let len = r.u32le().map_err(|e| book_fail(e.to_string()))? as usize;
    if len > MAX_BOOK_BLOB {
        return Err(book_fail("intent snapshot blob is over cap".into()));
    }
    let bytes = r
        .fixed_slice(len)
        .map_err(|e| book_fail(e.to_string()))?
        .to_vec();
    Ok(bytes)
}

fn write_amount(w: &mut srct_core::ser::Writer, amount: &Amount) {
    w.fixed(&amount.asset.0).u64le(amount.amount);
}

fn read_amount(r: &mut srct_core::ser::Reader) -> Result<Amount, IntentError> {
    let asset: [u8; 32] = r.fixed().map_err(|e| book_fail(e.to_string()))?;
    let amount = r.u64le().map_err(|e| book_fail(e.to_string()))?;
    Ok(Amount {
        asset: crate::types::AssetId(asset),
        amount,
    })
}

fn write_state(w: &mut srct_core::ser::Writer, state: &IntentState) {
    match state {
        IntentState::Open => {
            w.u8(0);
        }
        IntentState::Accepted {
            quote,
            solver,
            price,
            delivery_by_height,
        } => {
            w.u8(1).fixed(quote).fixed(solver);
            write_amount(w, price);
            w.u64le(*delivery_by_height);
        }
        IntentState::Fulfilled {
            quote,
            solver,
            price,
            result,
            delivery,
            at_height,
        } => {
            w.u8(2).fixed(quote).fixed(solver);
            write_amount(w, price);
            w.fixed(result).fixed(delivery).u64le(*at_height);
        }
        IntentState::Disputed {
            quote,
            solver,
            price,
            evidence,
            at_height,
        } => {
            w.u8(3).fixed(quote).fixed(solver);
            write_amount(w, price);
            w.fixed(evidence).u64le(*at_height);
        }
        IntentState::Settled {
            solver,
            amount,
            at_height,
        } => {
            w.u8(4).fixed(solver);
            write_amount(w, amount);
            w.u64le(*at_height);
        }
        IntentState::Refunded { at_height } => {
            w.u8(5).u64le(*at_height);
        }
    }
}

fn read_state(r: &mut srct_core::ser::Reader) -> Result<IntentState, IntentError> {
    match r.u8().map_err(|e| book_fail(e.to_string()))? {
        0 => Ok(IntentState::Open),
        1 => {
            let quote = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let solver = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let price = read_amount(r)?;
            let delivery_by_height = r.u64le().map_err(|e| book_fail(e.to_string()))?;
            Ok(IntentState::Accepted {
                quote,
                solver,
                price,
                delivery_by_height,
            })
        }
        2 => {
            let quote = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let solver = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let price = read_amount(r)?;
            let result = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let delivery = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let at_height = r.u64le().map_err(|e| book_fail(e.to_string()))?;
            Ok(IntentState::Fulfilled {
                quote,
                solver,
                price,
                result,
                delivery,
                at_height,
            })
        }
        3 => {
            let quote = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let solver = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let price = read_amount(r)?;
            let evidence = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let at_height = r.u64le().map_err(|e| book_fail(e.to_string()))?;
            Ok(IntentState::Disputed {
                quote,
                solver,
                price,
                evidence,
                at_height,
            })
        }
        4 => {
            let solver = r.fixed().map_err(|e| book_fail(e.to_string()))?;
            let amount = read_amount(r)?;
            let at_height = r.u64le().map_err(|e| book_fail(e.to_string()))?;
            Ok(IntentState::Settled {
                solver,
                amount,
                at_height,
            })
        }
        5 => {
            let at_height = r.u64le().map_err(|e| book_fail(e.to_string()))?;
            Ok(IntentState::Refunded { at_height })
        }
        _ => Err(book_fail("intent snapshot state is unknown".into())),
    }
}

impl IntentBook {
    /// Bounded snapshot encoding for restarts. Every signed blob is stored
    /// with its bytes; trust roots and verifier replay books are operator
    /// state and are NOT persisted — the operator reconfigures roots after
    /// restart, and evidence replays fail closed per attach rules.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = srct_core::ser::Writer::with_capacity(256 + self.records.len() * 512);
        w.u8(BOOK_VERSION).u32le(self.records.len() as u32);
        for record in self.records.values() {
            write_blob(&mut w, &record.signed.encode());
            w.u16le(record.quotes.len() as u16);
            for quote in record.quotes.values() {
                write_blob(&mut w, &quote.encode());
            }
            write_state(&mut w, &record.state);
            match &record.expected {
                None => {
                    w.u8(0);
                }
                Some(ExpectedEvidence::Tee(sla)) => {
                    w.u8(1);
                    write_blob(&mut w, &sla.encode());
                }
                Some(ExpectedEvidence::Zk(task)) => {
                    w.u8(2);
                    write_blob(&mut w, &task.encode());
                }
                Some(ExpectedEvidence::Fhe(task)) => {
                    w.u8(3);
                    write_blob(&mut w, &task.encode());
                }
            }
            match &record.verified {
                None => w.u8(0),
                Some(EvidenceKind::Tee) => w.u8(1),
                Some(EvidenceKind::Fhe) => w.u8(2),
                Some(EvidenceKind::Zk) => w.u8(3),
                Some(EvidenceKind::Compute) => w.u8(4),
            };
            match &record.dispute_bond {
                None => w.u8(0),
                Some((challenger, amount)) => w.u8(1).fixed(challenger).u64le(*amount),
            };
        }
        w.into_vec()
    }

    /// Rebuild from a snapshot. Every signed blob is decoded through its
    /// signature check, so tampered bytes fail the whole replay instead of
    /// loading half a book.
    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        let mut r = srct_core::ser::Reader::new(bytes);
        if r.u8().map_err(|e| book_fail(e.to_string()))? != BOOK_VERSION {
            return Err(book_fail("intent snapshot version is unknown".into()));
        }
        let count = r.u32le().map_err(|e| book_fail(e.to_string()))? as usize;
        if count > MAX_BOOK_INTENTS {
            return Err(book_fail("intent snapshot is over cap".into()));
        }
        let mut book = IntentBook::new();
        for _ in 0..count {
            let intent_bytes = read_blob(&mut r)?;
            let signed =
                SignedIntent::decode(&intent_bytes).map_err(|e| book_fail(e.to_string()))?;
            let quote_count = r.u16le().map_err(|e| book_fail(e.to_string()))? as usize;
            if quote_count > MAX_BOOK_QUOTES {
                return Err(book_fail("intent snapshot quotes are over cap".into()));
            }
            let mut quotes = BTreeMap::new();
            for _ in 0..quote_count {
                let quote_bytes = read_blob(&mut r)?;
                let quote =
                    SignedQuote::decode(&quote_bytes).map_err(|e| book_fail(e.to_string()))?;
                if quote.quote.intent != signed.intent.hash() {
                    return Err(book_fail(
                        "intent snapshot quote names another intent".into(),
                    ));
                }
                quotes.insert(quote.quote.solver, quote);
            }
            let state = read_state(&mut r)?;
            let expected = match r.u8().map_err(|e| book_fail(e.to_string()))? {
                0 => None,
                1 => {
                    let sla_bytes = read_blob(&mut r)?;
                    let sla = srct_verify::TeeSla::decode(&sla_bytes)
                        .map_err(|e| book_fail(e.to_string()))?;
                    Some(ExpectedEvidence::Tee(sla))
                }
                2 => {
                    let task_bytes = read_blob(&mut r)?;
                    let task = srct_verify::SignedZkTask::decode(&task_bytes)
                        .map_err(|e| book_fail(e.to_string()))?;
                    Some(ExpectedEvidence::Zk(task))
                }
                3 => {
                    let task_bytes = read_blob(&mut r)?;
                    let task = srct_verify::SignedFheTask::decode(&task_bytes)
                        .map_err(|e| book_fail(e.to_string()))?;
                    Some(ExpectedEvidence::Fhe(task))
                }
                _ => return Err(book_fail("intent snapshot expectation is unknown".into())),
            };
            let verified = match r.u8().map_err(|e| book_fail(e.to_string()))? {
                0 => None,
                1 => Some(EvidenceKind::Tee),
                2 => Some(EvidenceKind::Fhe),
                3 => Some(EvidenceKind::Zk),
                4 => Some(EvidenceKind::Compute),
                _ => return Err(book_fail("intent snapshot evidence kind is unknown".into())),
            };
            let dispute_bond = match r.u8().map_err(|e| book_fail(e.to_string()))? {
                0 => None,
                1 => {
                    let challenger: Address = r.fixed().map_err(|e| book_fail(e.to_string()))?;
                    let amount = r.u64le().map_err(|e| book_fail(e.to_string()))?;
                    Some((challenger, amount))
                }
                _ => return Err(book_fail("intent snapshot bond is unknown".into())),
            };
            let id = signed.intent.hash();
            if book.records.contains_key(&id) {
                return Err(book_fail("intent snapshot holds a duplicate".into()));
            }
            book.records.insert(
                id,
                Record {
                    signed,
                    quotes,
                    state,
                    expected,
                    verified,
                    dispute_bond,
                },
            );
        }
        r.expect_end().map_err(|e| book_fail(e.to_string()))?;
        Ok(book)
    }
}
