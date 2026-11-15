//! Pull-model compute claims: requester-signed shard tickets and
//! provider-signed claims.
//!
//! The push path (`market::Assignment`) names one provider chosen by the
//! requester's planner. The pull path inverts that: the requester posts
//! **tickets** — signed shard authorizations with no provider attached — on
//! an open board, and any capable provider **claims** one. The first valid
//! claim wins; the claim is atomic because the node's single-threaded
//! admission inserts it once and refuses replays by name.
//!
//! Two signatures authorize every payout, same as the push path:
//! the requester signs the shard terms (ticket), the provider signs the
//! take (claim). Settlement verifies both plus the receipt, exactly like
//! `settle::ComputeLedger::settle` verifies receipt plus assignment. The
//! escrow release, challenge, slash and bond paths all key off the claim
//! hash the same way they key off the assignment hash.
//!
//! A ticket may name a designated provider (`provider: Some`). Only a
//! designated ticket can carry a pre-signed payout exit (the destination
//! must be known when the requester signs), so only designated tickets
//! pay without a second signature. Open tickets settle into the manual
//! claim path with an auto-built exit template.

use std::collections::BTreeMap;

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::device::{
    Determinism, MAX_BANDWIDTH_KBPS, MAX_RAM_MIB, MAX_UNITS_PER_SEC, MIN_RAM_MIB,
};
use crate::market::{Verification, MAX_JOB_UNITS};
use crate::settle::{decode_signed, encode_signed};
use crate::ComputeError;

pub const TICKET_VERSION: u8 = 1;
pub const CLAIM_VERSION: u8 = 1;
/// Most open tickets or claims one book holds. Bounds the worst-case
/// allocation when decoding an untrusted `state.bin` section.
pub const MAX_TICKETS: usize = 100_000;

const DOM_TICKET: &[u8] = b"srct/compute/ticket/v1";
const DOM_CLAIM: &[u8] = b"srct/compute/claim/v1";

/// A requester-signed shard authorization on the open board.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimTicket {
    pub version: u8,
    pub network_id: String,
    /// Address that pays and that signs the ticket.
    pub requester: Address,
    /// Job this shard belongs to. The ticket's terms must fit the job's
    /// ceilings; the node checks that against its stored job.
    pub job: Hash,
    /// Dense shard index inside the job.
    pub shard: u16,
    pub units: u32,
    pub unit_price_sat: u64,
    pub total_sat: u64,
    pub min_ram_mib: u32,
    pub min_units_per_sec: u32,
    pub min_bandwidth_kbps: u32,
    pub determinism: Determinism,
    pub required_kernel: Hash,
    pub min_verification: Verification,
    pub sealed_input: bool,
    pub input: Hash,
    pub deadline: u64,
    pub nonce: u64,
    /// Designated winner, or `None` for an open pull anyone capable may
    /// take. Only a designated ticket can carry a pre-signed payout exit.
    pub provider: Option<Address>,
}

impl ClaimTicket {
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != TICKET_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported ticket version {}",
                self.version
            )));
        }
        if self.network_id.is_empty()
            || self.network_id.len() > srct_core::agent::MAX_NETWORK_ID_LEN
        {
            return Err(ComputeError::Malformed("ticket network id length".into()));
        }
        if self.job == [0u8; 32] {
            return Err(ComputeError::Malformed("ticket names an empty job".into()));
        }
        if self.units == 0 || self.units > MAX_JOB_UNITS {
            return Err(ComputeError::Malformed("ticket units out of range".into()));
        }
        if self.unit_price_sat == 0 {
            return Err(ComputeError::Malformed(
                "ticket unit price must be positive".into(),
            ));
        }
        let expected = (self.units as u64)
            .checked_mul(self.unit_price_sat)
            .ok_or_else(|| ComputeError::Malformed("ticket total overflows".into()))?;
        if expected != self.total_sat {
            return Err(ComputeError::Malformed(
                "ticket total does not equal units times price".into(),
            ));
        }
        if !(MIN_RAM_MIB..=MAX_RAM_MIB).contains(&self.min_ram_mib) {
            return Err(ComputeError::Malformed("ticket ram requirement".into()));
        }
        if self.min_units_per_sec > MAX_UNITS_PER_SEC {
            return Err(ComputeError::Malformed(
                "ticket throughput requirement out of range".into(),
            ));
        }
        if self.min_bandwidth_kbps > MAX_BANDWIDTH_KBPS {
            return Err(ComputeError::Malformed(
                "ticket bandwidth requirement out of range".into(),
            ));
        }
        if self.deadline == 0 {
            return Err(ComputeError::Malformed("ticket deadline is zero".into()));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("ticket nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(200);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.requester)
            .fixed(&self.job)
            .u16le(self.shard)
            .u32le(self.units)
            .u64le(self.unit_price_sat)
            .u64le(self.total_sat)
            .u32le(self.min_ram_mib)
            .u32le(self.min_units_per_sec)
            .u32le(self.min_bandwidth_kbps)
            .u8(self.determinism.as_u8())
            .fixed(&self.required_kernel)
            .u8(self.min_verification.as_u8())
            .u8(self.sealed_input as u8)
            .fixed(&self.input)
            .u64le(self.deadline)
            .u64le(self.nonce);
        match self.provider {
            Some(p) => {
                w.u8(1).fixed(&p);
            }
            None => {
                w.u8(0);
            }
        }
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_TICKET, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > srct_core::agent::MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("ticket network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("ticket network is not utf-8".into()))?
            .to_string();
        let requester: Address = r.fixed().map_err(malformed)?;
        let job: Hash = r.fixed().map_err(malformed)?;
        let shard = r.u16le().map_err(malformed)?;
        let units = r.u32le().map_err(malformed)?;
        let unit_price_sat = r.u64le().map_err(malformed)?;
        let total_sat = r.u64le().map_err(malformed)?;
        let min_ram_mib = r.u32le().map_err(malformed)?;
        let min_units_per_sec = r.u32le().map_err(malformed)?;
        let min_bandwidth_kbps = r.u32le().map_err(malformed)?;
        let determinism =
            Determinism::from_u8(r.u8().map_err(malformed)?).ok_or_else(|| {
                ComputeError::Malformed("ticket determinism class".into())
            })?;
        let required_kernel: Hash = r.fixed().map_err(malformed)?;
        let min_verification =
            Verification::from_u8(r.u8().map_err(malformed)?).ok_or_else(|| {
                ComputeError::Malformed("ticket verification level".into())
            })?;
        let sealed_input = r.u8().map_err(malformed)?;
        if sealed_input > 1 {
            return Err(ComputeError::Malformed("ticket sealed-input flag".into()));
        }
        let input: Hash = r.fixed().map_err(malformed)?;
        let deadline = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        let provider = match r.u8().map_err(malformed)? {
            0 => None,
            1 => Some(r.fixed().map_err(malformed)?),
            _ => {
                return Err(ComputeError::Malformed("ticket provider flag".into()));
            }
        };
        let ticket = ClaimTicket {
            version,
            network_id,
            requester,
            job,
            shard,
            units,
            unit_price_sat,
            total_sat,
            min_ram_mib,
            min_units_per_sec,
            min_bandwidth_kbps,
            determinism,
            required_kernel,
            min_verification,
            sealed_input: sealed_input == 1,
            input,
            deadline,
            nonce,
            provider,
        };
        r.expect_end().map_err(malformed)?;
        ticket.validate()?;
        Ok(ticket)
    }
}

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}

/// A requester-signed ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTicket {
    pub ticket: ClaimTicket,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedTicket {
    pub fn sign(ticket: ClaimTicket, wallet: &Wallet) -> Result<Self, ComputeError> {
        ticket.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != ticket.requester {
            return Err(ComputeError::WrongRequester);
        }
        let auth = Auth::sign(wallet, &ticket.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedTicket {
            ticket,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.ticket.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.ticket.requester {
            return Err(ComputeError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.ticket.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.ticket.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.ticket.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let (body, sigs, keys) = decode_signed(bytes, "ticket")?;
        let ticket = ClaimTicket::decode(&body)?;
        let signed = SignedTicket {
            ticket,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// A provider's signed take of one ticket: the second signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardClaim {
    pub version: u8,
    pub network_id: String,
    /// Ticket being claimed.
    pub ticket: Hash,
    /// Provider taking the shard. Must match the claim signer, and the
    /// ticket's designated provider when the ticket names one.
    pub provider: Address,
    /// Units taken. Must equal the ticket's units: a claim takes the whole
    /// shard or nothing, which is what makes the pre-signed payout exact.
    pub units: u32,
    pub nonce: u64,
}

impl ShardClaim {
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.version != CLAIM_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported claim version {}",
                self.version
            )));
        }
        if self.network_id.is_empty()
            || self.network_id.len() > srct_core::agent::MAX_NETWORK_ID_LEN
        {
            return Err(ComputeError::Malformed("claim network id length".into()));
        }
        if self.ticket == [0u8; 32] {
            return Err(ComputeError::Malformed("claim names an empty ticket".into()));
        }
        if self.units == 0 || self.units > MAX_JOB_UNITS {
            return Err(ComputeError::Malformed("claim units out of range".into()));
        }
        if self.nonce == 0 {
            return Err(ComputeError::Malformed("claim nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(120);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.ticket)
            .fixed(&self.provider)
            .u32le(self.units)
            .u64le(self.nonce);
        w.into_vec()
    }

    pub fn hash(&self) -> Hash {
        sha256_dom(DOM_CLAIM, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > srct_core::agent::MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("claim network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("claim network is not utf-8".into()))?
            .to_string();
        let claim = ShardClaim {
            version,
            network_id,
            ticket: r.fixed().map_err(malformed)?,
            provider: r.fixed().map_err(malformed)?,
            units: r.u32le().map_err(malformed)?,
            nonce: r.u64le().map_err(malformed)?,
        };
        r.expect_end().map_err(malformed)?;
        claim.validate()?;
        Ok(claim)
    }
}

/// A provider-signed shard claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedClaim {
    pub claim: ShardClaim,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedClaim {
    pub fn sign(claim: ShardClaim, wallet: &Wallet) -> Result<Self, ComputeError> {
        claim.validate()?;
        let address = wallet
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if address != claim.provider {
            return Err(ComputeError::WrongProvider);
        }
        let auth = Auth::sign(wallet, &claim.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        Ok(SignedClaim {
            claim,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ComputeError> {
        self.claim.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ComputeError::BadSignature(e.to_string()))?;
        if signer != self.claim.provider {
            return Err(ComputeError::WrongProvider);
        }
        verify_bundle(&self.sigs, &self.keys, &self.claim.hash())
            .map_err(|e| ComputeError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.claim.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.claim.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let (body, sigs, keys) = decode_signed(bytes, "claim")?;
        let claim = ShardClaim::decode(&body)?;
        let signed = SignedClaim {
            claim,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// Open board and atomic claim set for one network.
///
/// Tickets are keyed by hash; claims are keyed by ticket hash, so the first
/// valid claim wins and every later one for the same ticket is refused by
/// name. Expired tickets prune with their claims: a claim past its ticket
/// deadline can never settle, so dropping it loses nothing settleable.
#[derive(Clone, Debug, Default)]
pub struct ClaimBook {
    network_id: String,
    tickets: BTreeMap<Hash, SignedTicket>,
    claims: BTreeMap<Hash, SignedClaim>,
}

impl ClaimBook {
    pub fn new(network_id: impl Into<String>) -> Self {
        ClaimBook {
            network_id: network_id.into(),
            tickets: BTreeMap::new(),
            claims: BTreeMap::new(),
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn ticket(&self, id: &Hash) -> Option<&SignedTicket> {
        self.tickets.get(id)
    }

    pub fn claim_for(&self, ticket: &Hash) -> Option<&SignedClaim> {
        self.claims.get(ticket)
    }

    pub fn all_claims(&self) -> impl Iterator<Item = &SignedClaim> {
        self.claims.values()
    }

    pub fn open_tickets(&self, height: u64) -> impl Iterator<Item = &SignedTicket> {
        self.tickets
            .values()
            .filter(move |t| !self.claims.contains_key(&t.hash()) && height <= t.ticket.deadline)
    }

    /// Post a ticket to the open board. Verifies the requester's signature,
    /// the network, and that the ticket is not already posted and not
    /// already expired.
    pub fn post(&mut self, ticket: &SignedTicket, height: u64) -> Result<Hash, ComputeError> {
        ticket.verify()?;
        if ticket.ticket.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        if height > ticket.ticket.deadline {
            return Err(ComputeError::Expired);
        }
        let id = ticket.hash();
        if self.tickets.contains_key(&id) {
            return Err(ComputeError::Replay);
        }
        if self.tickets.len() >= MAX_TICKETS {
            return Err(ComputeError::Malformed("ticket board over cap".into()));
        }
        self.tickets.insert(id, ticket.clone());
        Ok(id)
    }

    /// Take a ticket: first valid claim wins. Verifies both signatures, the
    /// network, the ticket/claim binding, the designated provider when the
    /// ticket names one, whole-shard units, and the deadline. Atomic: the
    /// insert either happens or the claim is refused; a second claim for
    /// the same ticket is refused even if it is otherwise valid.
    pub fn claim(&mut self, claim: &SignedClaim, height: u64) -> Result<Hash, ComputeError> {
        claim.verify()?;
        if claim.claim.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        let ticket = self
            .tickets
            .get(&claim.claim.ticket)
            .ok_or(ComputeError::NotFound)?;
        ticket.verify()?;
        let t = &ticket.ticket;
        let c = &claim.claim;
        if c.units != t.units {
            return Err(ComputeError::Overclaim);
        }
        if let Some(designated) = t.provider {
            if c.provider != designated {
                return Err(ComputeError::DesignatedProvider);
            }
        }
        if height > t.deadline {
            return Err(ComputeError::Expired);
        }
        let ticket_id = ticket.hash();
        if self.claims.contains_key(&ticket_id) {
            return Err(ComputeError::AlreadyClaimed);
        }
        if self.claims.len() >= MAX_TICKETS {
            return Err(ComputeError::Malformed("claim set over cap".into()));
        }
        self.claims.insert(ticket_id, claim.clone());
        Ok(claim.hash())
    }

    /// Drop what can never settle: unclaimed tickets past deadline, and
    /// claims whose ticket expired without settlement. Settlement and escrow
    /// refuse past-deadline work, so pruning loses nothing settleable.
    pub fn prune(&mut self, height: u64) {
        let mut dead_tickets = Vec::new();
        for (id, ticket) in &self.tickets {
            if height > ticket.ticket.deadline {
                dead_tickets.push(*id);
            }
        }
        for id in dead_tickets {
            self.tickets.remove(&id);
            self.claims.remove(&id);
        }
    }

    /// Open exposure counted against capacity: designated open tickets plus
    /// unsettled claims for this provider. Unclaimed open tickets name no
    /// provider and bind nothing.
    pub fn exposure(&self, provider: &Address) -> u64 {
        let mut total = 0u64;
        for ticket in self.tickets.values() {
            if ticket.ticket.provider == Some(*provider)
                && !self.claims.contains_key(&ticket.hash())
            {
                total = total.saturating_add(ticket.ticket.total_sat);
            }
        }
        for (ticket_id, claim) in &self.claims {
            if claim.claim.provider == *provider {
                if let Some(ticket) = self.tickets.get(ticket_id) {
                    total = total.saturating_add(ticket.ticket.total_sat);
                }
            }
        }
        total
    }

    /// Encode the whole book for `state.bin`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.tickets.len() * 300);
        w.u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes());
        w.u32le(self.tickets.len() as u32);
        for (id, ticket) in &self.tickets {
            let bytes = ticket.encode();
            w.fixed(id).u32le(bytes.len() as u32).raw(&bytes);
        }
        w.u32le(self.claims.len() as u32);
        for (ticket_id, claim) in &self.claims {
            let bytes = claim.encode();
            w.fixed(ticket_id).u32le(bytes.len() as u32).raw(&bytes);
        }
        w.into_vec()
    }

    /// Decode a book written by [`ClaimBook::encode`]. Fail-closed: any
    /// truncation, trailing garbage, over-cap count, duplicate id or
    /// network mismatch refuses the whole blob. Tickets and claims
    /// re-verify through their own codecs.
    pub fn decode(bytes: &[u8], network_id: &str) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > srct_core::agent::MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("claim book network id length".into()));
        }
        let net_bytes = r.fixed_slice(net_len).map_err(malformed)?;
        let stored = std::str::from_utf8(net_bytes)
            .map_err(|_| ComputeError::Malformed("claim book network is not utf-8".into()))?;
        if stored != network_id {
            return Err(ComputeError::WrongNetwork);
        }
        let mut tickets = BTreeMap::new();
        let n_tickets = r.u32le().map_err(malformed)? as usize;
        if n_tickets > MAX_TICKETS {
            return Err(ComputeError::Malformed("tickets over cap".into()));
        }
        for _ in 0..n_tickets {
            let id: Hash = r.fixed().map_err(malformed)?;
            let len = r.u32le().map_err(malformed)? as usize;
            if len > 64 * 1024 {
                return Err(ComputeError::Malformed("ticket over cap".into()));
            }
            let ticket = SignedTicket::decode(r.fixed_slice(len).map_err(malformed)?)?;
            if ticket.hash() != id {
                return Err(ComputeError::Malformed("ticket id mismatch".into()));
            }
            if tickets.insert(id, ticket).is_some() {
                return Err(ComputeError::Malformed("duplicate ticket".into()));
            }
        }
        let mut claims = BTreeMap::new();
        let n_claims = r.u32le().map_err(malformed)? as usize;
        if n_claims > MAX_TICKETS {
            return Err(ComputeError::Malformed("claims over cap".into()));
        }
        for _ in 0..n_claims {
            let ticket_id: Hash = r.fixed().map_err(malformed)?;
            let len = r.u32le().map_err(malformed)? as usize;
            if len > 64 * 1024 {
                return Err(ComputeError::Malformed("claim over cap".into()));
            }
            let claim = SignedClaim::decode(r.fixed_slice(len).map_err(malformed)?)?;
            if claim.claim.ticket != ticket_id {
                return Err(ComputeError::Malformed("claim ticket mismatch".into()));
            }
            if claims.insert(ticket_id, claim).is_some() {
                return Err(ComputeError::Malformed("duplicate claim".into()));
            }
        }
        r.expect_end().map_err(malformed)?;
        Ok(ClaimBook {
            network_id: network_id.into(),
            tickets,
            claims,
        })
    }
}