//! Wire types for cross-network intents.
//!
//! Every object a participant signs has a canonical encoding and a
//! domain-separated signing hash. Asset amounts are integer minor units; no
//! floating point is used for money. A quote for a different asset must carry
//! a router-signed conversion route, and the intent only settles if the route
//! is valid at quote time.

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

pub const INTENT_VERSION: u8 = 1;
pub const QUOTE_VERSION: u8 = 1;
pub const ROUTE_VERSION: u8 = 1;
pub const DELIVERY_VERSION: u8 = 1;
pub const RESOLUTION_VERSION: u8 = 1;
pub const DISPUTE_VERSION: u8 = 1;
pub const MAX_ASSETS: usize = 8;

const DOM_INTENT: &[u8] = b"srct/intent/v1";
const DOM_QUOTE: &[u8] = b"srct/intent-quote/v1";
const DOM_ROUTE: &[u8] = b"srct/intent-route/v1";
const DOM_DELIVERY: &[u8] = b"srct/intent-delivery/v1";
const DOM_RESOLUTION: &[u8] = b"srct/intent-resolution/v1";
const DOM_DISPUTE: &[u8] = b"srct/intent-dispute/v1";

/// Opaque asset identity. It can name SRCT, a stablecoin, a wrapped asset or a
/// chain-specific token; settlement adapters interpret it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssetId(pub [u8; 32]);

/// An integer amount of one asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount {
    pub asset: AssetId,
    pub amount: u64,
}

/// How much execution evidence the requester accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verification {
    None = 0,
    ProviderSigned = 1,
    Optimistic = 2,
    Tee = 3,
    Zk = 4,
}

impl Verification {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Verification::None),
            1 => Some(Verification::ProviderSigned),
            2 => Some(Verification::Optimistic),
            3 => Some(Verification::Tee),
            4 => Some(Verification::Zk),
            _ => None,
        }
    }
}

/// How much input/output privacy the requester requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Privacy {
    Public = 0,
    Sealed = 1,
    Tee = 2,
    Fhe = 3,
}

impl Privacy {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Privacy::Public),
            1 => Some(Privacy::Sealed),
            2 => Some(Privacy::Tee),
            3 => Some(Privacy::Fhe),
            _ => None,
        }
    }
}

/// A signed request for work from any participating network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub version: u8,
    pub creator: Address,
    /// Hash of the service or computation specification.
    pub service: Hash,
    /// Hash of the committed input.
    pub input: Hash,
    /// Address that can resolve a dispute.
    pub arbiter: Address,
    /// Ceiling on the total price.
    pub max_price: Amount,
    pub max_latency_ms: u32,
    pub min_verification: Verification,
    pub min_privacy: Privacy,
    /// Assets the creator will settle in. Must include `max_price.asset`.
    pub accepted_assets: Vec<AssetId>,
    /// Height after which the request is no longer valid.
    pub deadline_height: u64,
    /// Creator nonce, so two identical requests are distinct.
    pub nonce: u64,
}

impl Intent {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != INTENT_VERSION {
            return Err(format!("unsupported intent version {}", self.version));
        }
        if self.max_price.amount == 0 {
            return Err("max price must be positive".into());
        }
        if self.max_latency_ms == 0 {
            return Err("max latency must be positive".into());
        }
        if self.deadline_height == 0 {
            return Err("deadline must be positive".into());
        }
        if self.accepted_assets.is_empty() || self.accepted_assets.len() > MAX_ASSETS {
            return Err(format!(
                "accepted assets must be 1..={MAX_ASSETS}, got {}",
                self.accepted_assets.len()
            ));
        }
        if !self.accepted_assets.contains(&self.max_price.asset) {
            return Err("accepted assets must include the max-price asset".into());
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256);
        w.u8(self.version)
            .fixed(&self.creator)
            .fixed(&self.service)
            .fixed(&self.input)
            .fixed(&self.arbiter)
            .fixed(&self.max_price.asset.0)
            .u64le(self.max_price.amount)
            .u32le(self.max_latency_ms)
            .u8(self.min_verification.as_u8())
            .u8(self.min_privacy.as_u8())
            .u16le(self.accepted_assets.len() as u16);
        for asset in &self.accepted_assets {
            w.fixed(&asset.0);
        }
        w.u64le(self.deadline_height).u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_INTENT, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("intent: {e}"))?;
        let creator = r.fixed().map_err(|e| format!("intent: {e}"))?;
        let service = r.fixed().map_err(|e| format!("intent: {e}"))?;
        let input = r.fixed().map_err(|e| format!("intent: {e}"))?;
        let arbiter = r.fixed().map_err(|e| format!("intent: {e}"))?;
        let asset = r.fixed().map_err(|e| format!("intent: {e}"))?;
        let amount = r.u64le().map_err(|e| format!("intent: {e}"))?;
        let max_latency_ms = r.u32le().map_err(|e| format!("intent: {e}"))?;
        let min_verification = Verification::from_u8(r.u8().map_err(|e| format!("intent: {e}"))?)
            .ok_or_else(|| "intent: bad verification level".to_string())?;
        let min_privacy = Privacy::from_u8(r.u8().map_err(|e| format!("intent: {e}"))?)
            .ok_or_else(|| "intent: bad privacy level".to_string())?;
        let count = r.u16le().map_err(|e| format!("intent: {e}"))? as usize;
        if count > MAX_ASSETS {
            return Err("intent: too many accepted assets".into());
        }
        let mut accepted_assets = Vec::with_capacity(count);
        for _ in 0..count {
            accepted_assets.push(AssetId(r.fixed().map_err(|e| format!("intent: {e}"))?));
        }
        let deadline_height = r.u64le().map_err(|e| format!("intent: {e}"))?;
        let nonce = r.u64le().map_err(|e| format!("intent: {e}"))?;
        r.expect_end().map_err(|e| format!("intent: {e}"))?;
        let intent = Intent {
            version,
            creator,
            service,
            input,
            arbiter,
            max_price: Amount {
                asset: AssetId(asset),
                amount,
            },
            max_latency_ms,
            min_verification,
            min_privacy,
            accepted_assets,
            deadline_height,
            nonce,
        };
        intent.validate()?;
        Ok(intent)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIntent {
    pub intent: Intent,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedIntent {
    pub fn sign(intent: Intent, creator: &Wallet) -> Result<Self, String> {
        intent.validate()?;
        let address = creator.address().map_err(|e| e.to_string())?;
        if address != intent.creator {
            return Err("intent creator does not match the signing wallet".into());
        }
        let auth = Auth::sign(creator, &intent.hash()).map_err(|e| e.to_string())?;
        Ok(SignedIntent {
            intent,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        self.intent.validate()?;
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.intent.creator {
            return Err("intent key bundle is not the creator".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.intent.hash())
            .map_err(|_| "intent signature invalid".to_string())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.intent.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let (body, sigs, keys) = decode_signed(bytes, "intent")?;
        let intent = Intent::decode(&body)?;
        let signed = SignedIntent { intent, sigs, keys };
        signed.verify()?;
        Ok(signed)
    }
}

/// A router-signed conversion between two assets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRoute {
    pub version: u8,
    pub router: Address,
    pub from: AssetId,
    pub to: AssetId,
    /// `from` units per `to` unit, as a rational. `amount * numerator / denominator`.
    pub numerator: u64,
    pub denominator: u64,
    /// Fee in basis points, taken from the converted output.
    pub fee_bps: u32,
    pub valid_until_height: u64,
    pub nonce: u64,
}

impl AssetRoute {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != ROUTE_VERSION {
            return Err(format!("unsupported route version {}", self.version));
        }
        if self.from == self.to {
            return Err("route must convert between different assets".into());
        }
        if self.numerator == 0 || self.denominator == 0 {
            return Err("route ratio must be positive".into());
        }
        if self.fee_bps > 10_000 {
            return Err("route fee exceeds 100%".into());
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .fixed(&self.router)
            .fixed(&self.from.0)
            .fixed(&self.to.0)
            .u64le(self.numerator)
            .u64le(self.denominator)
            .u32le(self.fee_bps)
            .u64le(self.valid_until_height)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_ROUTE, &[&self.encode()])
    }

    /// Convert `amount` of `from` into `to`, floor after the fee.
    pub fn convert(&self, amount: u64) -> Result<u64, String> {
        let gross = (amount as u128)
            .checked_mul(self.numerator as u128)
            .ok_or_else(|| "route conversion overflows".to_string())?
            / self.denominator as u128;
        let net = gross
            .checked_mul(10_000 - self.fee_bps as u128)
            .ok_or_else(|| "route fee overflows".to_string())?
            / 10_000;
        u64::try_from(net).map_err(|_| "route conversion overflows u64".to_string())
    }

    /// Ranking estimate: how much of the source asset a target price costs,
    /// rounded up. Used only for comparing quotes, never for settlement.
    pub fn inverse_estimate(&self, amount: u64) -> Result<u64, String> {
        let keep = 10_000u128
            .checked_sub(self.fee_bps as u128)
            .ok_or_else(|| "route fee invalid".to_string())?;
        if keep == 0 {
            return Err("route fee leaves no value".into());
        }
        let denom = (self.numerator as u128)
            .checked_mul(keep)
            .ok_or_else(|| "route inverse overflows".to_string())?;
        let numer = (amount as u128)
            .checked_mul(self.denominator as u128)
            .and_then(|v| v.checked_mul(10_000))
            .ok_or_else(|| "route inverse overflows".to_string())?;
        let cost = numer.div_ceil(denom);
        u64::try_from(cost).map_err(|_| "route inverse overflows u64".to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("route: {e}"))?;
        let router = r.fixed().map_err(|e| format!("route: {e}"))?;
        let from = AssetId(r.fixed().map_err(|e| format!("route: {e}"))?);
        let to = AssetId(r.fixed().map_err(|e| format!("route: {e}"))?);
        let numerator = r.u64le().map_err(|e| format!("route: {e}"))?;
        let denominator = r.u64le().map_err(|e| format!("route: {e}"))?;
        let fee_bps = r.u32le().map_err(|e| format!("route: {e}"))?;
        let valid_until_height = r.u64le().map_err(|e| format!("route: {e}"))?;
        let nonce = r.u64le().map_err(|e| format!("route: {e}"))?;
        r.expect_end().map_err(|e| format!("route: {e}"))?;
        let route = AssetRoute {
            version,
            router,
            from,
            to,
            numerator,
            denominator,
            fee_bps,
            valid_until_height,
            nonce,
        };
        route.validate()?;
        Ok(route)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRoute {
    pub route: AssetRoute,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedRoute {
    pub fn sign(route: AssetRoute, router: &Wallet) -> Result<Self, String> {
        route.validate()?;
        let address = router.address().map_err(|e| e.to_string())?;
        if address != route.router {
            return Err("route router does not match the signing wallet".into());
        }
        let auth = Auth::sign(router, &route.hash()).map_err(|e| e.to_string())?;
        Ok(SignedRoute {
            route,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        self.route.validate()?;
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.route.router {
            return Err("route key bundle is not the router".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.route.hash())
            .map_err(|_| "route signature invalid".to_string())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.route.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let (body, sigs, keys) = decode_signed(bytes, "route")?;
        let route = AssetRoute::decode(&body)?;
        let signed = SignedRoute { route, sigs, keys };
        signed.verify()?;
        Ok(signed)
    }
}

/// A solver's offer for one intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote {
    pub version: u8,
    pub intent: Hash,
    pub solver: Address,
    pub price: Amount,
    /// Required when `price.asset` differs from the intent's max-price asset.
    pub route: Option<SignedRoute>,
    pub latency_ms: u32,
    pub verification: Verification,
    pub privacy: Privacy,
    pub valid_until_height: u64,
    pub nonce: u64,
}

impl Quote {
    pub fn encode(&self) -> Vec<u8> {
        let route = self.route.as_ref().map(SignedRoute::encode);
        let mut w = Writer::with_capacity(256 + route.as_ref().map(Vec::len).unwrap_or(0));
        w.u8(self.version)
            .fixed(&self.intent)
            .fixed(&self.solver)
            .fixed(&self.price.asset.0)
            .u64le(self.price.amount)
            .u8(u8::from(route.is_some()));
        if let Some(route) = &route {
            w.u32le(route.len() as u32).raw(route);
        }
        w.u32le(self.latency_ms)
            .u8(self.verification.as_u8())
            .u8(self.privacy.as_u8())
            .u64le(self.valid_until_height)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_QUOTE, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| format!("quote: {e}"))?;
        let intent = r.fixed().map_err(|e| format!("quote: {e}"))?;
        let solver = r.fixed().map_err(|e| format!("quote: {e}"))?;
        let asset = r.fixed().map_err(|e| format!("quote: {e}"))?;
        let amount = r.u64le().map_err(|e| format!("quote: {e}"))?;
        let has_route = r.u8().map_err(|e| format!("quote: {e}"))?;
        let route = match has_route {
            0 => None,
            1 => {
                let len = r.u32le().map_err(|e| format!("quote: {e}"))? as usize;
                if len > 16 * 1024 {
                    return Err("quote: route over cap".into());
                }
                Some(SignedRoute::decode(
                    r.fixed_slice(len).map_err(|e| format!("quote: {e}"))?,
                )?)
            }
            _ => return Err("quote: bad route flag".into()),
        };
        let latency_ms = r.u32le().map_err(|e| format!("quote: {e}"))?;
        let verification = Verification::from_u8(r.u8().map_err(|e| format!("quote: {e}"))?)
            .ok_or_else(|| "quote: bad verification level".to_string())?;
        let privacy = Privacy::from_u8(r.u8().map_err(|e| format!("quote: {e}"))?)
            .ok_or_else(|| "quote: bad privacy level".to_string())?;
        let valid_until_height = r.u64le().map_err(|e| format!("quote: {e}"))?;
        let nonce = r.u64le().map_err(|e| format!("quote: {e}"))?;
        r.expect_end().map_err(|e| format!("quote: {e}"))?;
        Ok(Quote {
            version,
            intent,
            solver,
            price: Amount {
                asset: AssetId(asset),
                amount,
            },
            route,
            latency_ms,
            verification,
            privacy,
            valid_until_height,
            nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedQuote {
    pub quote: Quote,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedQuote {
    pub fn sign(quote: Quote, solver: &Wallet) -> Result<Self, String> {
        if quote.version != QUOTE_VERSION {
            return Err(format!("unsupported quote version {}", quote.version));
        }
        let address = solver.address().map_err(|e| e.to_string())?;
        if address != quote.solver {
            return Err("quote solver does not match the signing wallet".into());
        }
        if let Some(route) = &quote.route {
            route.verify()?;
        }
        let auth = Auth::sign(solver, &quote.hash()).map_err(|e| e.to_string())?;
        Ok(SignedQuote {
            quote,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.quote.version != QUOTE_VERSION {
            return Err(format!("unsupported quote version {}", self.quote.version));
        }
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.quote.solver {
            return Err("quote key bundle is not the solver".into());
        }
        if let Some(route) = &self.quote.route {
            route.verify()?;
        }
        verify_bundle(&self.sigs, &self.keys, &self.quote.hash())
            .map_err(|_| "quote signature invalid".to_string())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.quote.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let (body, sigs, keys) = decode_signed(bytes, "quote")?;
        let quote = Quote::decode(&body)?;
        let signed = SignedQuote { quote, sigs, keys };
        signed.verify()?;
        Ok(signed)
    }
}

/// A solver-signed claim that the requested work was completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub version: u8,
    pub intent: Hash,
    pub quote: Hash,
    pub solver: Address,
    pub result: Hash,
    pub height: u64,
    pub nonce: u64,
}

impl Delivery {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .fixed(&self.intent)
            .fixed(&self.quote)
            .fixed(&self.solver)
            .fixed(&self.result)
            .u64le(self.height)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_DELIVERY, &[&self.encode()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDelivery {
    pub delivery: Delivery,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedDelivery {
    pub fn sign(delivery: Delivery, solver: &Wallet) -> Result<Self, String> {
        if delivery.version != DELIVERY_VERSION {
            return Err(format!("unsupported delivery version {}", delivery.version));
        }
        let address = solver.address().map_err(|e| e.to_string())?;
        if address != delivery.solver {
            return Err("delivery solver does not match the signing wallet".into());
        }
        let auth = Auth::sign(solver, &delivery.hash()).map_err(|e| e.to_string())?;
        Ok(SignedDelivery {
            delivery,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.delivery.version != DELIVERY_VERSION {
            return Err(format!(
                "unsupported delivery version {}",
                self.delivery.version
            ));
        }
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.delivery.solver {
            return Err("delivery key bundle is not the solver".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.delivery.hash())
            .map_err(|_| "delivery signature invalid".to_string())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.delivery.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let (body, sigs, keys) = decode_signed(bytes, "delivery")?;
        let mut r = Reader::new(&body);
        let version = r.u8().map_err(|e| format!("delivery: {e}"))?;
        let intent = r.fixed().map_err(|e| format!("delivery: {e}"))?;
        let quote = r.fixed().map_err(|e| format!("delivery: {e}"))?;
        let solver = r.fixed().map_err(|e| format!("delivery: {e}"))?;
        let result = r.fixed().map_err(|e| format!("delivery: {e}"))?;
        let height = r.u64le().map_err(|e| format!("delivery: {e}"))?;
        let nonce = r.u64le().map_err(|e| format!("delivery: {e}"))?;
        r.expect_end().map_err(|e| format!("delivery: {e}"))?;
        let signed = SignedDelivery {
            delivery: Delivery {
                version,
                intent,
                quote,
                solver,
                result,
                height,
                nonce,
            },
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// A creator-signed challenge to a delivered result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispute {
    pub version: u8,
    pub intent: Hash,
    pub creator: Address,
    pub evidence: Hash,
    pub nonce: u64,
}

impl Dispute {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
        w.u8(self.version)
            .fixed(&self.intent)
            .fixed(&self.creator)
            .fixed(&self.evidence)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_DISPUTE, &[&self.encode()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDispute {
    pub dispute: Dispute,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedDispute {
    pub fn sign(dispute: Dispute, creator: &Wallet) -> Result<Self, String> {
        if dispute.version != DISPUTE_VERSION {
            return Err(format!("unsupported dispute version {}", dispute.version));
        }
        let address = creator.address().map_err(|e| e.to_string())?;
        if address != dispute.creator {
            return Err("dispute creator does not match the signing wallet".into());
        }
        let auth = Auth::sign(creator, &dispute.hash()).map_err(|e| e.to_string())?;
        Ok(SignedDispute {
            dispute,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.dispute.version != DISPUTE_VERSION {
            return Err(format!(
                "unsupported dispute version {}",
                self.dispute.version
            ));
        }
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.dispute.creator {
            return Err("dispute key bundle is not the creator".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.dispute.hash())
            .map_err(|_| "dispute signature invalid".to_string())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.dispute.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let (body, sigs, keys) = decode_signed(bytes, "dispute")?;
        let mut r = Reader::new(&body);
        let version = r.u8().map_err(|e| format!("dispute: {e}"))?;
        let intent = r.fixed().map_err(|e| format!("dispute: {e}"))?;
        let creator = r.fixed().map_err(|e| format!("dispute: {e}"))?;
        let evidence = r.fixed().map_err(|e| format!("dispute: {e}"))?;
        let nonce = r.u64le().map_err(|e| format!("dispute: {e}"))?;
        r.expect_end().map_err(|e| format!("dispute: {e}"))?;
        let signed = SignedDispute {
            dispute: Dispute {
                version,
                intent,
                creator,
                evidence,
                nonce,
            },
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// An arbiter's decision after a dispute. `release_to_solver = true` pays the
/// solver; `false` refunds the creator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeResolution {
    pub version: u8,
    pub intent: Hash,
    pub arbiter: Address,
    pub release_to_solver: bool,
    pub evidence: Hash,
    pub nonce: u64,
}

impl DisputeResolution {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
        w.u8(self.version)
            .fixed(&self.intent)
            .fixed(&self.arbiter)
            .u8(u8::from(self.release_to_solver))
            .fixed(&self.evidence)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_RESOLUTION, &[&self.encode()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedResolution {
    pub resolution: DisputeResolution,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedResolution {
    pub fn sign(resolution: DisputeResolution, arbiter: &Wallet) -> Result<Self, String> {
        if resolution.version != RESOLUTION_VERSION {
            return Err(format!(
                "unsupported resolution version {}",
                resolution.version
            ));
        }
        let address = arbiter.address().map_err(|e| e.to_string())?;
        if address != resolution.arbiter {
            return Err("resolution arbiter does not match the signing wallet".into());
        }
        let auth = Auth::sign(arbiter, &resolution.hash()).map_err(|e| e.to_string())?;
        Ok(SignedResolution {
            resolution,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.resolution.version != RESOLUTION_VERSION {
            return Err(format!(
                "unsupported resolution version {}",
                self.resolution.version
            ));
        }
        let signer = self.keys.address().map_err(|e| e.to_string())?;
        if signer != self.resolution.arbiter {
            return Err("resolution key bundle is not the arbiter".into());
        }
        verify_bundle(&self.sigs, &self.keys, &self.resolution.hash())
            .map_err(|_| "resolution signature invalid".to_string())
    }
}

fn encode_signed(body: &[u8], sigs: &Bundle, keys: &Bundle) -> Vec<u8> {
    let sigs = sigs.to_bytes();
    let keys = keys.to_bytes();
    let mut w = Writer::with_capacity(body.len() + sigs.len() + keys.len() + 16);
    w.u32le(body.len() as u32)
        .raw(body)
        .u32le(sigs.len() as u32)
        .raw(&sigs)
        .u32le(keys.len() as u32)
        .raw(&keys);
    w.into_vec()
}

fn decode_signed(bytes: &[u8], what: &str) -> Result<(Vec<u8>, Bundle, Bundle), String> {
    let mut r = Reader::new(bytes);
    let body_len = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
    if body_len > 64 * 1024 {
        return Err(format!("{what}: body over cap"));
    }
    let body = r
        .fixed_slice(body_len)
        .map_err(|e| format!("{what}: {e}"))?
        .to_vec();
    let sigs_len = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
    if sigs_len > 8 * 1024 {
        return Err(format!("{what}: signature bundle over cap"));
    }
    let sigs = Bundle::deserialize(
        r.fixed_slice(sigs_len)
            .map_err(|e| format!("{what}: {e}"))?,
    )
    .map_err(|e| format!("{what}: {e}"))?;
    let keys_len = r.u32le().map_err(|e| format!("{what}: {e}"))? as usize;
    if keys_len > 8 * 1024 {
        return Err(format!("{what}: key bundle over cap"));
    }
    let keys = Bundle::deserialize(
        r.fixed_slice(keys_len)
            .map_err(|e| format!("{what}: {e}"))?,
    )
    .map_err(|e| format!("{what}: {e}"))?;
    r.expect_end().map_err(|e| format!("{what}: {e}"))?;
    Ok((body, sigs, keys))
}
