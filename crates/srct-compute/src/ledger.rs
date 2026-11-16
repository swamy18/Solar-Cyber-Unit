//! Metering ledger: block-level tracking of compute consumption.
//!
//! A *compute slice* is a fixed amount of units delivered per fixed number of
//! chain blocks. Mainnet: [`SLICE_UNITS`] units per 1 block (~10 minutes).
//! Testnet/mini: [`SLICE_UNITS`] units per 10 blocks.
//!
//! When a receipt settles, both consumer and provider sign a [`UsageRecord`]
//! naming the ticket, provider, units consumed and the height range of the
//! slice. If the two sides' records disagree (units or height range don't
//! match), the mismatch opens a dispute through the existing bond/challenge
//! path.
//!
//! Each node keeps a local ledger indexed by chain height: where compute came
//! from, how much each provider supplied, where it went. The ledger is
//! persisted in `state.bin` with a fail-closed decode. There is **no**
//! consensus commitment in this round — a ledger-root commitment is a proposal
//! only.
//!
//! What this does **not** do:
//! - **Not result correctness.** A usage record attests that units were
//!   delivered and used, not that the output is correct.
//! - **Not consensus.** Each node tracks its own view; there is no shared
//!   state machine here.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::ser::{Reader, Writer};

use crate::ComputeError;

fn malformed(e: srct_core::error::Error) -> ComputeError {
    ComputeError::Malformed(e.to_string())
}

/// Units delivered per slice.
pub const SLICE_UNITS: u32 = 100;

/// Number of chain blocks per slice on mainnet (~10 min blocks).
pub const SLICE_BLOCKS_MAINNET: u64 = 1;

/// Number of chain blocks per slice on testnet/mini.
pub const SLICE_BLOCKS_TESTNET_MINI: u64 = 10;

/// Envelope version for the ledger section in `state.bin`.
pub const LEDGER_VERSION: u8 = 1;

const DOM_USAGE: &[u8] = b"srct/compute/usage/v1";

/// The number of chain blocks in one slice for a given network.
pub fn slice_blocks(network_id: &str) -> u64 {
    match network_id {
        "srct/mainnet" => SLICE_BLOCKS_MAINNET,
        "srct/testnet" | "srct/mini" => SLICE_BLOCKS_TESTNET_MINI,
        _ => SLICE_BLOCKS_MAINNET,
    }
}

/// The slice index that `height` falls into: `height / slice_blocks`.
pub fn slice_index(height: u64, slice_blocks: u64) -> u64 {
    height / slice_blocks
}

/// The inclusive start and end heights of the slice containing `height`.
pub fn slice_window(height: u64, network_id: &str) -> (u64, u64) {
    let sb = slice_blocks(network_id);
    let idx = slice_index(height, sb);
    (idx * sb, idx * sb + sb.saturating_sub(1))
}

/// A usage record signed by both the consumer and the provider for one slice.
///
/// The consumer's node and the provider's node each keep a record. If they
/// disagree on units or height range, the mismatch opens a dispute through the
/// existing bond/challenge path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageRecord {
    pub version: u8,
    /// The ticket the work was authorised under.
    pub ticket: Hash,
    /// The provider that delivered the units.
    pub provider: Address,
    /// Units consumed in this slice.
    pub units: u32,
    /// Inclusive start height of the slice.
    pub start_height: u64,
    /// Inclusive end height of the slice.
    pub end_height: u64,
    /// Consumer's signature over the record hash.
    pub consumer_sig: [u8; 64],
    /// Provider's signature over the record hash.
    pub provider_sig: [u8; 64],
}

impl UsageRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32 + 20 + 4 + 8 * 2 + 64 * 2 + 2);
        w.u8(self.version)
            .fixed(&self.ticket)
            .fixed(&self.provider)
            .u32le(self.units)
            .u64le(self.start_height)
            .u64le(self.end_height)
            .raw(&self.consumer_sig)
            .raw(&self.provider_sig);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let record = UsageRecord {
            version: r.u8().map_err(malformed)?,
            ticket: r.fixed().map_err(malformed)?,
            provider: r.fixed().map_err(malformed)?,
            units: r.u32le().map_err(malformed)?,
            start_height: r.u64le().map_err(malformed)?,
            end_height: r.u64le().map_err(malformed)?,
            consumer_sig: {
                let mut s = [0u8; 64];
                s.copy_from_slice(
                    r.fixed_slice(64).map_err(malformed)?,
                );
                s
            },
            provider_sig: {
                let mut s = [0u8; 64];
                s.copy_from_slice(
                    r.fixed_slice(64).map_err(malformed)?,
                );
                s
            },
        };
        r.expect_end().map_err(malformed)?;
        if record.version != LEDGER_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported usage record version {}",
                record.version
            )));
        }
        if record.ticket == [0u8; 32] {
            return Err(ComputeError::Malformed("usage record names no ticket".into()));
        }
        if record.provider == [0u8; 20] {
            return Err(ComputeError::Malformed("usage record names no provider".into()));
        }
        if record.units == 0 {
            return Err(ComputeError::Malformed("usage record has zero units".into()));
        }
        if record.end_height < record.start_height {
            return Err(ComputeError::Malformed(
                "usage record end height before start height".into(),
            ));
        }
        Ok(record)
    }

    /// Hash of the record content (excluding signatures, so both parties sign
    /// the same bytes).
    pub fn hash(&self) -> Hash {
        let mut w = Writer::with_capacity(32 + 20 + 4 + 8 * 2);
        w.u8(self.version)
            .fixed(&self.ticket)
            .fixed(&self.provider)
            .u32le(self.units)
            .u64le(self.start_height)
            .u64le(self.end_height);
        sha256_dom(DOM_USAGE, &[&w.into_vec()])
    }
}

/// Slice boundary: the start and end heights of one slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SliceWindow {
    pub start_height: u64,
    pub end_height: u64,
}

/// One entry in the node-local ledger: where compute came from, how much, and
/// where it went, at a given chain height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub height: u64,
    pub ticket: Hash,
    pub provider: Address,
    pub units: u32,
    pub consumer: Address,
}

/// Node-local compute usage ledger, indexed by chain height.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ComputeUsageLedger {
    /// height -> (usage record, consumer) pairs recorded at that height.
    entries: BTreeMap<u64, Vec<(UsageRecord, Address)>>,
    /// provider -> total units supplied across all slices.
    provider_totals: BTreeMap<Address, u32>,
    /// ticket -> set of heights where units were recorded for this ticket.
    ticket_heights: BTreeMap<Hash, BTreeSet<u64>>,
}

impl ComputeUsageLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a usage record at a slice's end height. Returns the slice
    /// window the record covers.
    pub fn record(
        &mut self,
        record: &UsageRecord,
        consumer: Address,
    ) -> Result<SliceWindow, ComputeError> {
        if record.units == 0 {
            return Err(ComputeError::Malformed("usage record has zero units".into()));
        }
        if record.end_height < record.start_height {
            return Err(ComputeError::Malformed(
                "usage record end height before start height".into(),
            ));
        }

        let window = SliceWindow {
            start_height: record.start_height,
            end_height: record.end_height,
        };

        self.entries
            .entry(record.end_height)
            .or_default()
            .push((record.clone(), consumer));
        *self
            .provider_totals
            .entry(record.provider)
            .or_insert(0) += record.units;
        self.ticket_heights
            .entry(record.ticket)
            .or_default()
            .insert(record.end_height);
        Ok(window)
    }

    /// Query all ledger entries with height in `[from, to]` (inclusive).
    /// Returns entries sorted by height.
    pub fn query(&self, from: u64, to: u64) -> Vec<LedgerEntry> {
        let mut out = Vec::new();
        for (height, records) in self.entries.range(from..=to) {
            for (record, consumer) in records {
                out.push(LedgerEntry {
                    height: *height,
                    ticket: record.ticket,
                    provider: record.provider,
                    units: record.units,
                    consumer: *consumer,
                });
            }
        }
        out.sort_by_key(|e| e.height);
        out
    }

    /// Total units supplied by a provider across all slices.
    pub fn provider_total(&self, provider: &Address) -> u32 {
        self.provider_totals.get(provider).copied().unwrap_or(0)
    }

    /// Number of slices (distinct end heights) recorded.
    pub fn slice_count(&self) -> usize {
        self.entries.len()
    }

    /// Encode the whole ledger for `state.bin`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.entries.len() * 120);
        w.u8(LEDGER_VERSION);
        w.u32le(self.entries.len() as u32);
        for (height, records) in &self.entries {
            w.u64le(*height);
            w.u32le(records.len() as u32);
            for (record, consumer) in records {
                let mut rec_bytes = record.encode();
                rec_bytes.extend_from_slice(consumer.as_ref());
                w.u32le(rec_bytes.len() as u32);
                w.raw(&rec_bytes);
            }
        }
        w.u32le(self.provider_totals.len() as u32);
        for (provider, total) in &self.provider_totals {
            w.fixed(provider).u32le(*total);
        }
        w.u32le(self.ticket_heights.len() as u32);
        for (ticket, heights) in &self.ticket_heights {
            w.fixed(ticket);
            w.u32le(heights.len() as u32);
            for h in heights {
                w.u64le(*h);
            }
        }
        w.into_vec()
    }

    /// Decode a ledger written by [`ComputeUsageLedger::encode`]. Fail-closed:
    /// any truncation, trailing garbage, over-cap count or internally
    /// inconsistent record refuses the whole blob.
    pub fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        if version != LEDGER_VERSION {
            return Err(ComputeError::Malformed(format!(
                "unsupported ledger version {version}"
            )));
        }
        let n_entries = r.u32le().map_err(malformed)? as usize;
        if n_entries > 100_000 {
            return Err(ComputeError::Malformed("ledger entries over cap".into()));
        }
        let mut entries = BTreeMap::new();
        for _ in 0..n_entries {
            let height = r.u64le().map_err(malformed)?;
            let n_records = r.u32le().map_err(malformed)? as usize;
            if n_records > 10_000 {
                return Err(ComputeError::Malformed("ledger records over cap".into()));
            }
            let mut records = Vec::new();
            for _ in 0..n_records {
                let n = r.u32le().map_err(malformed)? as usize;
                if n > MAX_ENTRY_BYTES {
                    return Err(ComputeError::Malformed("usage record over cap".into()));
                }
                let rec_bytes = r
                    .fixed_slice(n)
                    .map_err(malformed)?;
                // rec_bytes = usage_record_bytes || consumer_address(20)
                if rec_bytes.len() < 20 {
                    return Err(ComputeError::Malformed("usage record too short".into()));
                }
                let (rec_part, consumer_part) = rec_bytes.split_at(rec_bytes.len() - 20);
                let record = UsageRecord::decode(rec_part)?;
                let mut consumer = [0u8; 20];
                consumer.copy_from_slice(consumer_part);
                records.push((record, consumer));
            }
            if entries.insert(height, records).is_some() {
                return Err(ComputeError::Malformed("duplicate ledger height".into()));
            }
        }
        let n_providers = r.u32le().map_err(malformed)? as usize;
        if n_providers > 100_000 {
            return Err(ComputeError::Malformed("ledger providers over cap".into()));
        }
        let mut provider_totals = BTreeMap::new();
        for _ in 0..n_providers {
            let provider: Address = r.fixed().map_err(malformed)?;
            let total = r.u32le().map_err(malformed)?;
            if provider_totals.insert(provider, total).is_some() {
                return Err(ComputeError::Malformed("duplicate ledger provider".into()));
            }
        }
        let n_tickets = r.u32le().map_err(malformed)? as usize;
        if n_tickets > 100_000 {
            return Err(ComputeError::Malformed("ledger tickets over cap".into()));
        }
        let mut ticket_heights = BTreeMap::new();
        for _ in 0..n_tickets {
            let ticket: Hash = r.fixed().map_err(malformed)?;
            let n_heights = r.u32le().map_err(malformed)? as usize;
            if n_heights > 10_000 {
                return Err(ComputeError::Malformed("ledger ticket heights over cap".into()));
            }
            let mut heights = BTreeSet::new();
            for _ in 0..n_heights {
                let h = r.u64le().map_err(malformed)?;
                if !heights.insert(h) {
                    return Err(ComputeError::Malformed("duplicate ledger ticket height".into()));
                }
            }
            if ticket_heights.insert(ticket, heights).is_some() {
                return Err(ComputeError::Malformed("duplicate ledger ticket".into()));
            }
        }
        r.expect_end().map_err(malformed)?;
        Ok(ComputeUsageLedger {
            entries,
            provider_totals,
            ticket_heights,
        })
    }
}

const MAX_ENTRY_BYTES: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::wallet::Wallet;

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_private_key_bytes(&[seed; 32], "ledger-test").unwrap()
    }

    fn record(seed: u8, ticket: Hash, units: u32, start: u64, end: u64) -> UsageRecord {
        UsageRecord {
            version: LEDGER_VERSION,
            ticket,
            provider: wallet(seed).address().unwrap(),
            units,
            start_height: start,
            end_height: end,
            consumer_sig: [seed; 64],
            provider_sig: [seed.wrapping_add(1); 64],
        }
    }

    #[test]
    fn slice_windows_mainnet_and_testnet() {
        // Mainnet: 1 block per slice.
        assert_eq!(slice_window(0, "srct/mainnet"), (0, 0));
        assert_eq!(slice_window(1, "srct/mainnet"), (1, 1));
        assert_eq!(slice_window(5, "srct/mainnet"), (5, 5));
        // Testnet/mini: 10 blocks per slice.
        assert_eq!(slice_window(0, "srct/testnet"), (0, 9));
        assert_eq!(slice_window(5, "srct/testnet"), (0, 9));
        assert_eq!(slice_window(10, "srct/testnet"), (10, 19));
        assert_eq!(slice_window(9, "srct/mini"), (0, 9));
        assert_eq!(slice_window(10, "srct/mini"), (10, 19));
    }

    #[test]
    fn ledger_record_and_query_by_height() {
        let mut ledger = ComputeUsageLedger::new();
        let ticket = [1u8; 32];
        let provider = wallet(1).address().unwrap();

        let r1 = record(1, ticket, 100, 0, 9);
        let r2 = record(1, ticket, 100, 10, 19);
        let r3 = record(2, ticket, 50, 20, 29);

        let consumer = wallet(9).address().unwrap();
        ledger.record(&r1, consumer).unwrap();
        ledger.record(&r2, consumer).unwrap();
        ledger.record(&r3, consumer).unwrap();

        // Query range covering slices 0-9 and 10-19.
        let entries = ledger.query(0, 19);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].height, 9);
        assert_eq!(entries[0].units, 100);
        assert_eq!(entries[0].provider, provider);
        assert_eq!(entries[1].height, 19);
        assert_eq!(entries[1].units, 100);

        // Query a narrower range.
        let entries = ledger.query(10, 29);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].height, 19);
        assert_eq!(entries[1].height, 29);

        // Provider totals: wallet(1) supplied 100+100=200, wallet(2) supplied 50.
        assert_eq!(ledger.provider_total(&provider), 200);
        assert_eq!(ledger.provider_total(&wallet(2).address().unwrap()), 50);
        assert_eq!(ledger.provider_total(&wallet(99).address().unwrap()), 0);
        assert_eq!(ledger.slice_count(), 3);
    }

    #[test]
    fn ledger_wire_roundtrip_and_tamper_refusal() {
        let mut ledger = ComputeUsageLedger::new();
        let ticket = [2u8; 32];
        ledger
            .record(
                &record(1, ticket, 100, 0, 9),
                Address::default(),
            )
            .unwrap();
        ledger
            .record(
                &record(2, ticket, 200, 10, 19),
                Address::default(),
            )
            .unwrap();

        let bytes = ledger.encode();
        let decoded = ComputeUsageLedger::decode(&bytes).unwrap();
        assert_eq!(decoded, ledger);

        // Tampered version byte -> fail-closed.
        let mut tampered = bytes.clone();
        tampered[0] ^= 0xFF;
        assert!(ComputeUsageLedger::decode(&tampered).is_err());

        // Truncation -> fail-closed.
        assert!(ComputeUsageLedger::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(ComputeUsageLedger::decode(&[]).is_err());
    }

    #[test]
    fn usage_record_hash_is_deterministic() {
        let r1 = record(1, [3u8; 32], 100, 0, 9);
        let r2 = record(1, [3u8; 32], 100, 0, 9);
        assert_eq!(r1.hash(), r2.hash());
        // Different units -> different hash.
        let r3 = record(1, [3u8; 32], 200, 0, 9);
        assert_ne!(r1.hash(), r3.hash());
    }
}
