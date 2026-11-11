//! Intent lifecycle and settlement instructions.
//!
//! The book is a pure state machine. It verifies signatures, quote constraints,
//! delivery timing and dispute authority, and returns the exact instruction the
//! existing payment/escrow layer should execute. It never moves value itself.

use std::collections::BTreeMap;

use srct_core::hash::{Address, Hash};

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
            IntentError::EvidenceMismatch => write!(f, "resolution evidence does not match"),
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
}

struct Record {
    signed: SignedIntent,
    quotes: BTreeMap<Address, SignedQuote>,
    state: IntentState,
}

/// In-memory intent book. Persistence is the caller's responsibility; the
/// state machine itself is deterministic.
#[derive(Default)]
pub struct IntentBook {
    records: BTreeMap<Hash, Record>,
}

impl IntentBook {
    pub fn new() -> Self {
        IntentBook::default()
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
            },
        );
        Ok(id)
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

    /// Release the escrow to the solver after a delivery.
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
            Ok(ResolutionOutcome {
                settlement: Some(SettlementInstruction {
                    from: record.signed.intent.creator,
                    to: solver,
                    amount: price,
                    intent: id,
                    reference: evidence,
                }),
                refund: None,
            })
        } else {
            record.state = IntentState::Refunded { at_height: height };
            Ok(ResolutionOutcome {
                settlement: None,
                refund: Some(RefundInstruction {
                    to: record.signed.intent.creator,
                    amount: record.signed.intent.max_price,
                    intent: id,
                    reason: RefundReason::Resolved,
                }),
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
