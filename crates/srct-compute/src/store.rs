//! Append-only journal of signed flow objects for restart and audit.
//!
//! Operators crash. The journal records every network-visible signed object —
//! offers, assignments, receipts, bonds and escrow fundings — as it is first
//! verified, so a restarted node replays the same bytes through the same
//! checks and rebuilds market/ledger/bond/escrow state instead of trusting a
//! checkpoint. Unsigned, invalid or over-cap entries are refused at append
//! time, and the whole journal round-trips through a bounded encoding.
//!
//! Replay returns verified objects. A restarted node feeds bonds to
//! [`crate::bond::BondBook::register`] at their recorded `registered_height`
//! and fundings to [`crate::escrow::EscrowBook::restore`], which skips the
//! append-time height check that already passed. Slash and withdrawal
//! outcomes are not signed objects and are not journaled here; an operator
//! that needs exact bond balances must checkpoint those separately.
//!
//! What this is not: a database. There is no index, no query language, no
//! compaction and no pruning of settled history.

use srct_core::ser::{Reader, Writer};

use crate::bond::SignedBond;
use crate::escrow::SignedFunding;
use crate::market::{SignedAssignment, SignedOffer};
use crate::settle::SignedReceipt;
use crate::ComputeError;

pub const JOURNAL_VERSION: u8 = 1;
/// Most entries one journal holds. Past the cap the operator archives and
/// starts a new journal; silently dropping history would rewrite it.
pub const MAX_JOURNAL_ENTRIES: usize = 4_096;
/// Largest single entry in bytes. Signed flow objects are a few hundred
/// bytes; the cap stops a corrupt length prefix from reserving memory.
pub const MAX_ENTRY_BYTES: usize = 8 * 1024;

/// Which flow object an entry carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Offer = 0,
    Assignment = 1,
    Receipt = 2,
    Bond = 3,
    Funding = 4,
}

impl EntryKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EntryKind::Offer),
            1 => Some(EntryKind::Assignment),
            2 => Some(EntryKind::Receipt),
            3 => Some(EntryKind::Bond),
            4 => Some(EntryKind::Funding),
            _ => None,
        }
    }
}

/// One verified signed object with its sequence number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub seq: u64,
    pub kind: EntryKind,
    pub bytes: Vec<u8>,
}

/// An append-only, replay-verified journal for one network.
#[derive(Clone, Debug, Default)]
pub struct FlowJournal {
    network_id: String,
    entries: Vec<JournalEntry>,
}

impl FlowJournal {
    pub fn new(network_id: impl Into<String>) -> Self {
        FlowJournal {
            network_id: network_id.into(),
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    fn push(&mut self, kind: EntryKind, bytes: Vec<u8>) -> Result<u64, ComputeError> {
        if bytes.is_empty() || bytes.len() > MAX_ENTRY_BYTES {
            return Err(ComputeError::Malformed("journal entry over cap".into()));
        }
        if self.entries.len() >= MAX_JOURNAL_ENTRIES {
            return Err(ComputeError::Malformed(
                "journal is full: archive and rotate".into(),
            ));
        }
        let seq = self.entries.len() as u64;
        self.entries.push(JournalEntry { seq, kind, bytes });
        Ok(seq)
    }

    /// Append an offer after verifying it belongs to this network.
    pub fn append_offer(&mut self, offer: &SignedOffer) -> Result<u64, ComputeError> {
        offer.verify()?;
        if offer.offer.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        self.push(EntryKind::Offer, offer.encode())
    }

    /// Append an assignment after verifying it. Assignments carry no
    /// network field of their own — they bind job and offer hashes, and
    /// network scoping comes from the referenced offer and job.
    pub fn append_assignment(
        &mut self,
        assignment: &SignedAssignment,
    ) -> Result<u64, ComputeError> {
        assignment.verify()?;
        self.push(EntryKind::Assignment, assignment.encode())
    }

    /// Append a receipt after verifying it.
    pub fn append_receipt(&mut self, receipt: &SignedReceipt) -> Result<u64, ComputeError> {
        receipt.verify()?;
        self.push(EntryKind::Receipt, receipt.encode())
    }

    /// Append a bond registration after verifying it belongs to this network.
    pub fn append_bond(&mut self, bond: &SignedBond) -> Result<u64, ComputeError> {
        bond.verify()?;
        if bond.bond.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        self.push(EntryKind::Bond, bond.encode())
    }

    /// Append an escrow funding after verifying it belongs to this network.
    pub fn append_funding(&mut self, funding: &SignedFunding) -> Result<u64, ComputeError> {
        funding.verify()?;
        if funding.funding.network_id != self.network_id {
            return Err(ComputeError::WrongNetwork);
        }
        self.push(EntryKind::Funding, funding.encode())
    }

    /// Replay every entry through decode + signature verification, in order.
    /// A restarted node calls this before rebuilding market/ledger state; any
    /// tampered entry fails the whole replay rather than being skipped.
    pub fn replay(&self) -> Result<Replayed, ComputeError> {
        replay_entries(&self.entries)
    }

    /// Bounded snapshot encoding for restart persistence.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.network_id.len());
        w.u8(JOURNAL_VERSION)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .u32le(self.entries.len() as u32);
        for entry in &self.entries {
            w.u8(entry.kind as u8)
                .u32le(entry.bytes.len() as u32)
                .raw(&entry.bytes);
        }
        w.into_vec()
    }

    /// Decode a snapshot and re-verify every entry. A restarted node gets the
    /// same verified objects or nothing at all.
    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        if version != JOURNAL_VERSION {
            return Err(ComputeError::Malformed("journal version".into()));
        }
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > srct_core::agent::MAX_NETWORK_ID_LEN {
            return Err(ComputeError::Malformed("journal network length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ComputeError::Malformed("journal network utf-8".into()))?
            .to_string();
        let count = r.u32le().map_err(malformed)? as usize;
        if count > MAX_JOURNAL_ENTRIES {
            return Err(ComputeError::Malformed("journal entry count".into()));
        }
        let mut journal = FlowJournal::new(network_id);
        for seq in 0..count {
            let kind = EntryKind::from_u8(r.u8().map_err(malformed)?)
                .ok_or_else(|| ComputeError::Malformed("journal entry kind".into()))?;
            let len = r.u32le().map_err(malformed)? as usize;
            if len == 0 || len > MAX_ENTRY_BYTES {
                return Err(ComputeError::Malformed("journal entry length".into()));
            }
            let entry_bytes = r.fixed_slice(len).map_err(malformed)?.to_vec();
            // Verify before storing: a snapshot that fails here is corrupt,
            // and loading it would fork the operator's view of history.
            // Offers must also agree with the snapshot's network: a journal
            // for one network replaying another's offers is a fork.
            verify_entry(kind, &entry_bytes)?;
            let entry_network = match kind {
                EntryKind::Offer => Some(SignedOffer::decode(&entry_bytes)?.offer.network_id),
                EntryKind::Bond => Some(SignedBond::decode(&entry_bytes)?.bond.network_id),
                EntryKind::Funding => Some(SignedFunding::decode(&entry_bytes)?.funding.network_id),
                EntryKind::Assignment | EntryKind::Receipt => None,
            };
            if entry_network.is_some_and(|net| net != journal.network_id) {
                return Err(ComputeError::Malformed("journal entry network".into()));
            }
            journal.entries.push(JournalEntry {
                seq: seq as u64,
                kind,
                bytes: entry_bytes,
            });
        }
        r.expect_end().map_err(malformed)?;
        Ok(journal)
    }
}

fn verify_entry(kind: EntryKind, bytes: &[u8]) -> Result<(), ComputeError> {
    match kind {
        EntryKind::Offer => SignedOffer::decode(bytes).map(|_| ()),
        EntryKind::Assignment => SignedAssignment::decode(bytes).map(|_| ()),
        EntryKind::Receipt => SignedReceipt::decode(bytes).map(|_| ()),
        EntryKind::Bond => SignedBond::decode(bytes).map(|_| ()),
        EntryKind::Funding => SignedFunding::decode(bytes).map(|_| ()),
    }
}

fn replay_entries(entries: &[JournalEntry]) -> Result<Replayed, ComputeError> {
    let mut offers = Vec::new();
    let mut assignments = Vec::new();
    let mut receipts = Vec::new();
    let mut bonds = Vec::new();
    let mut fundings = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        if entry.seq != i as u64 {
            return Err(ComputeError::Malformed("journal sequence gap".into()));
        }
        match entry.kind {
            EntryKind::Offer => offers.push(SignedOffer::decode(&entry.bytes)?),
            EntryKind::Assignment => assignments.push(SignedAssignment::decode(&entry.bytes)?),
            EntryKind::Receipt => receipts.push(SignedReceipt::decode(&entry.bytes)?),
            EntryKind::Bond => bonds.push(SignedBond::decode(&entry.bytes)?),
            EntryKind::Funding => fundings.push(SignedFunding::decode(&entry.bytes)?),
        }
    }
    Ok(Replayed {
        offers,
        assignments,
        receipts,
        bonds,
        fundings,
    })
}

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}

/// The verified contents of a journal replay, in original order.
#[derive(Clone, Debug, Default)]
pub struct Replayed {
    pub offers: Vec<SignedOffer>,
    pub assignments: Vec<SignedAssignment>,
    pub bonds: Vec<SignedBond>,
    pub fundings: Vec<SignedFunding>,
    pub receipts: Vec<SignedReceipt>,
}
