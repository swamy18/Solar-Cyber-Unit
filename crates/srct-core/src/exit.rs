//! L2 → L1 exit claims (approved P1, E-1…E-3, SPEC.md §19.6).
//!
//! A claim pays a matured, queued L2 exit out on L1. It consumes sink outputs
//! — real UTXOs with real value, so the ordinary `value_in >= value_out`
//! conservation rule holds unchanged — and is authorised by an **exit proof**,
//! not by a signature: a Merkle inclusion proof of the exit record against the
//! L2 state root the queue block committed.
//!
//! What this module does and does not do: it defines the claim shape, its
//! canonical codec, its identity and its gas, and it verifies a proof against
//! a *given* committed root. It does **not** decide whether a root, a height
//! or an identity is acceptable — that is the chain's job (`Chain` owns the
//! blocks that carry roots, the finality view that judges maturity, and the
//! consumed-identity set that makes a release exactly-once). Splitting
//! proof-checking from chain-checking is what keeps a forged proof
//! cryptographically impossible even if a miner commits a lying root: at
//! worst, exits from that queue block stall — the same one-way behaviour as
//! before exits existed — because no proof verifies against a root that does
//! not contain the record.

use crate::error::{Error, Result};
use crate::hash::{sha512_dom, Address, Hash, Hash512};
use crate::ser::{Reader, Writer};
use crate::state_root::{exit_record_leaf, exit_record_leaf_v7, verify_inclusion, InclusionProof};
use crate::tx::{OutPoint, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE};

/// Domain tag for the claim identity. Covers every consensus field, so a
/// claim cannot be reinterpreted as anything else that hashes bytes.
pub const DOM_EXIT_CLAIM: &[u8] = b"srct/exit-claim/v1";
/// 512-bit claim id. The claim id is used as the `txid` of the release
/// outpoints it creates, so it is one of the chain-identity hashes and carries
/// the widened width; the tag is new for the same reason as `DOM_BLOCK512`.
pub const DOM_EXIT_CLAIM512: &[u8] = b"srct/exit-claim512/v1";

/// Hard cap on sink inputs per claim. Each input is a 36-byte outpoint that
/// must resolve to a real sink output; the bound keeps a hostile claim from
/// forcing unbounded UTXO lookups. A normal exit needs one or two.
pub const MAX_CLAIM_INPUTS: usize = 16;

/// Smallest a claim can serialize to: all fixed fields (20+8+8+20+20+8+8),
/// an input count (4), one outpoint (36), a proof length (4) and an empty
/// proof (8+8+8). Bounds a declared claim count before anything is reserved.
pub const EXIT_CLAIM_MIN_ENCODED_LEN: usize = 20 + 8 + 8 + 20 + 20 + 8 + 8 + 4 + 68 + 4 + 24;

/// A permissionless release crank (approved P1, E-2): anyone may submit it,
/// and consensus pays only the recorded destination (E-3). The claimant named
/// here collects the prepaid release fee; the destination collects the
/// principal. No operator privilege, no second authorisation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitClaim {
    /// The L2 account that queued the exit.
    pub owner: Address,
    /// The per-owner queue nonce. `(owner, nonce)` is the exit identity:
    /// released exactly once, ever.
    pub nonce: u64,
    /// Satoshis the destination receives. Must equal the proven record.
    pub amount_sat: u64,
    /// Where the principal goes. Must equal the proven record — never a
    /// caller-supplied override.
    pub destination: Address,
    /// Whoever submitted this claim. Collects the prepaid release fee.
    pub claimant: Address,
    /// Satoshis the claimant receives, prepaid by the owner at queue time
    /// (approved P1, E-3). Prepaying is what makes a permissionless crank
    /// griefing-bounded.
    pub exit_fee_sat: u64,
    /// The L1 height whose L2 state contains the queue transition. Must be
    /// final under the stronger of the two Decision-15 rules before any
    /// release — exits are never less safe than deposits.
    pub queued_height: u64,
    /// Sink outputs this claim consumes. Must total exactly
    /// `amount + exit_fee + required L1 fee` — no change output, no tip.
    pub inputs: Vec<OutPoint>,
    /// Inclusion proof of the exit record against the state root committed
    /// in the `queued_height` block.
    pub proof: InclusionProof,
    /// Guarded-exit proof height (Phase 3, Decision 36).
    ///
    /// `None` is the legacy path: the proof is verified against the queue
    /// block's committed root. `Some(h)` is the guarded path: the proof is
    /// verified against block `h`'s committed root, and consensus requires
    /// `h >= queued_height + D` (see `guarded_exit_delay_blocks`), so a
    /// cancelled exit — removed from L2 state — has no block left to prove
    /// against. Omitted from the wire when `None`, so legacy claims keep
    /// their exact bytes and claim ids.
    pub proof_height: Option<u64>,
}

impl ExitClaim {
    /// Gas is the L1 gas model (SPEC.md §8): base plus per-input plus the two
    /// outputs (destination and claimant). A zero-fee exit creates only the
    /// destination output — recording an unspendable zero-value output would
    /// only bloat the UTXO set, the same reason a zero-value coinbase is not
    /// recorded.
    pub fn gas_used(&self) -> u64 {
        let outputs = if self.exit_fee_sat == 0 { 1 } else { 2 };
        GAS_TX_BASE
            .saturating_add(GAS_PER_INPUT.saturating_mul(self.inputs.len() as u64))
            .saturating_add(GAS_PER_OUTPUT.saturating_mul(outputs))
    }

    /// Claim identity: commits to every consensus field. Output outpoints of a
    /// release are `(claim_id, 0)` for the destination and `(claim_id, 1)` for
    /// the claimant, so two claims can never create the same outpoint and a
    /// replayed claim is the same bytes with the same id.
    pub fn claim_id(&self) -> Hash512 {
        sha512_dom(DOM_EXIT_CLAIM512, &[&self.serialize()])
    }

    /// Verify the record proof against the root the queue block committed.
    /// Pure: needs only the root, not the chain. Every field the leaf commits
    /// to comes from `self` — a caller-supplied override of amount,
    /// destination or fee fails here, not later. This is the pre-guarded
    /// (v7) leaf; post-activation claims use [`Self::verify_proof_v8`].
    pub fn verify_proof(&self, committed_root: &Hash) -> bool {
        let leaf = exit_record_leaf_v7(
            &self.owner,
            self.nonce,
            self.amount_sat,
            &self.destination,
            self.exit_fee_sat,
            self.queued_height,
        );
        verify_inclusion(*committed_root, leaf, &self.proof)
    }

    /// Verify against a v8 (post-activation) root. `guarded` selects the leaf
    /// variant: a guarded exit can only be proven with the guarded leaf and
    /// an unguarded one only with the unguarded leaf, so the inclusion proof
    /// itself binds which kind was committed — no flag needs trusting.
    pub fn verify_proof_v8(&self, committed_root: &Hash, guarded: bool) -> bool {
        let leaf = exit_record_leaf(
            &self.owner,
            self.nonce,
            self.amount_sat,
            &self.destination,
            self.exit_fee_sat,
            self.queued_height,
            guarded,
        );
        verify_inclusion(*committed_root, leaf, &self.proof)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.owner)
            .u64le(self.nonce)
            .u64le(self.amount_sat)
            .fixed(&self.destination)
            .fixed(&self.claimant)
            .u64le(self.exit_fee_sat)
            .u64le(self.queued_height)
            .u32le(self.inputs.len() as u32);
        for op in &self.inputs {
            w.fixed(&op.txid).u32le(op.index);
        }
        let proof = self.proof.serialize();
        w.u32le(proof.len() as u32).raw(&proof);
        // Trailing optional proof height (Phase 3). Omitted when None so
        // legacy claims keep their exact bytes and claim ids.
        if let Some(h) = self.proof_height {
            w.u64le(h);
        }
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let claim = Self::from_reader(&mut r)?;
        r.expect_end()?;
        Ok(claim)
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let owner: Address = r.fixed()?;
        let nonce = r.u64le()?;
        let amount_sat = r.u64le()?;
        let destination: Address = r.fixed()?;
        let claimant: Address = r.fixed()?;
        let exit_fee_sat = r.u64le()?;
        let queued_height = r.u64le()?;
        let n_in = r.u32le()? as usize;
        // Bounded before it drives anything: each input forces a UTXO lookup,
        // and the hard cap above is the load-bearing bound.
        if n_in == 0 || n_in > MAX_CLAIM_INPUTS {
            return Err(Error::Malformed("exit claim input count out of range"));
        }
        if n_in > r.remaining() / 68 {
            return Err(Error::Malformed("exit claim inputs exceed buffer"));
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let txid: Hash512 = r.fixed()?;
            let index = r.u32le()?;
            inputs.push(OutPoint { txid, index });
        }
        let proof_len = r.u32le()? as usize;
        if proof_len > r.remaining() {
            return Err(Error::Malformed("exit claim proof exceeds buffer"));
        }
        let raw = r.fixed_slice(proof_len)?;
        let mut pr = Reader::new(raw);
        let proof = InclusionProof::from_reader(&mut pr)?;
        pr.expect_end()?;
        // Trailing optional proof height (Phase 3). Absent on every legacy
        // claim; present only for guarded claims that must prove against a
        // post-delay root.
        let proof_height = if r.remaining() == 0 {
            None
        } else {
            Some(r.u64le()?)
        };
        r.expect_end()?;
        Ok(ExitClaim {
            owner,
            nonce,
            amount_sat,
            destination,
            claimant,
            exit_fee_sat,
            queued_height,
            inputs,
            proof,
            proof_height,
        })
    }
}

/// Serde identity of an exit claim is its **canonical binary encoding**, the
/// same discipline as `L2Transaction` (Decision 6): one authority for what a
/// claim is, so a JSON-supplied claim is held to exactly the rules a
/// wire-supplied one is.
impl serde::Serialize for ExitClaim {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.serialize()))
    }
}

impl<'de> serde::Deserialize<'de> for ExitClaim {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        let bytes =
            hex::decode(&s).map_err(|e| <D::Error as serde::de::Error>::custom(e.to_string()))?;
        ExitClaim::deserialize(&bytes).map_err(<D::Error as serde::de::Error>::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> ExitClaim {
        ExitClaim {
            owner: [0x11u8; 20],
            nonce: 3,
            amount_sat: 100_000,
            destination: [0x22u8; 20],
            claimant: [0x33u8; 20],
            exit_fee_sat: 500,
            queued_height: 41,
            inputs: vec![OutPoint {
                txid: [0x44u8; 64],
                index: 0,
            }],
            proof: InclusionProof {
                index: 0,
                leaf_count: 1,
                siblings: vec![],
            },
            proof_height: None,
        }
    }

    #[test]
    fn claim_round_trips_and_ids_are_stable() {
        let c = claim();
        let back = ExitClaim::deserialize(&c.serialize()).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.claim_id(), c.claim_id());
        // Gas covers the base, the input and both outputs.
        assert_eq!(
            c.gas_used(),
            GAS_TX_BASE + GAS_PER_INPUT + 2 * GAS_PER_OUTPUT
        );
    }

    #[test]
    fn claim_with_zero_fee_pays_for_one_output() {
        let mut c = claim();
        c.exit_fee_sat = 0;
        assert_eq!(c.gas_used(), GAS_TX_BASE + GAS_PER_INPUT + GAS_PER_OUTPUT);
        let back = ExitClaim::deserialize(&c.serialize()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn claim_decode_refuses_empty_inputs_and_oversize_counts() {
        let mut c = claim();
        c.inputs.clear();
        assert!(ExitClaim::deserialize(&c.serialize()).is_err());
        let mut bytes = claim().serialize();
        // Corrupt the input count to u32::MAX: refused before allocating.
        let off = 20 + 8 + 8 + 20 + 20 + 8 + 8;
        bytes[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(ExitClaim::deserialize(&bytes).is_err());
    }

    #[test]
    fn every_truncation_is_rejected_not_panicked() {
        let bytes = claim().serialize();
        for cut in 0..bytes.len() {
            let _ = ExitClaim::deserialize(&bytes[..cut]);
        }
    }
}
