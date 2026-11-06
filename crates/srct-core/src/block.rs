//! Block header, block, merkle root and the genesis block. SPEC.md §2, §3.4-§3.5, §11.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::exit::{ExitClaim, EXIT_CLAIM_MIN_ENCODED_LEN};
use crate::hash::{sha256, sha512_dom, Hash, Hash512, DOM_BLOCK512, ZERO_HASH512};
#[cfg(test)]
use crate::hash::{sha256_dom, DOM_BLOCK};
use crate::l2::L2Transaction;
use crate::ser::{Reader, Writer};
use crate::tx::{Output, Transaction, TX_COINBASE};

/// Smallest byte length an encoded L2 entry can occupy: its 4-byte length
/// prefix plus the 4-byte version and 1-byte type tag of the payload that
/// follows. Used only to bound `l2_count` before allocating (SPEC.md §19.1),
/// the same discipline §3 and §13.5 apply to every other count field.
const L2_TX_MIN_ENCODED_LEN: usize = 9;

pub const HEADER_SERIALIZED_LEN: usize = 177;
pub const BLOCK_VERSION: u32 = 1;

/// Frozen genesis timestamp: 2026-01-01T00:00:00Z.
///
/// It must be a realistic time, not zero: the median-time rule anchors on it, so
/// a zero genesis would make the first blocks unsatisfiable.
pub const GENESIS_TIMESTAMP_MS: u64 = 1_767_225_600_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub height: u64,
    /// Parent block hash. 512-bit: see [`Hash512`]. This is what makes the
    /// *chain* — not just a block — resist a quantum collision search.
    #[serde(with = "crate::hexserde::h64")]
    pub prev_hash: Hash512,
    #[serde(with = "crate::hexserde::h32")]
    pub merkle_root: Hash,
    pub timestamp_ms: u64,
    pub base_fee_sat: u64,
    pub difficulty: u128,
    pub nonce: u64,
    pub puzzle_id: u64,
    pub epoch_id: u32,
    #[serde(with = "crate::hexserde::h16")]
    pub extra_nonce: [u8; 16],
    pub sig_scheme: u8,
}

impl Header {
    pub fn genesis(merkle_root: Hash, difficulty: u128) -> Self {
        let mut extra = [0u8; 16];
        extra[..12].copy_from_slice(b"srct-genesis");
        Header {
            version: BLOCK_VERSION,
            height: 0,
            prev_hash: ZERO_HASH512,
            merkle_root,
            timestamp_ms: GENESIS_TIMESTAMP_MS,
            base_fee_sat: 0,
            difficulty,
            nonce: 0,
            puzzle_id: 1,
            epoch_id: 0,
            extra_nonce: extra,
            sig_scheme: crate::hash::SIG_SCHEME_SECP256K1_ECDSA,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(HEADER_SERIALIZED_LEN);
        w.u32le(self.version)
            .u64le(self.height)
            .fixed(&self.prev_hash)
            .fixed(&self.merkle_root)
            .u64le(self.timestamp_ms)
            .u64le(self.base_fee_sat)
            .u128le(self.difficulty)
            .u64le(self.nonce)
            .u64le(self.puzzle_id)
            .u32le(self.epoch_id)
            .fixed(&self.extra_nonce)
            .u8(self.sig_scheme);
        debug_assert_eq!(w.len(), HEADER_SERIALIZED_LEN);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_SERIALIZED_LEN {
            return Err(Error::BadLength {
                expected: HEADER_SERIALIZED_LEN,
                got: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let h = Header {
            version: r.u32le()?,
            height: r.u64le()?,
            prev_hash: r.fixed()?,
            merkle_root: r.fixed()?,
            timestamp_ms: r.u64le()?,
            base_fee_sat: r.u64le()?,
            difficulty: r.u128le()?,
            nonce: r.u64le()?,
            puzzle_id: r.u64le()?,
            epoch_id: r.u32le()?,
            extra_nonce: r.fixed()?,
            sig_scheme: r.u8()?,
        };
        r.expect_end()?;
        Ok(h)
    }

    pub fn block_hash(&self) -> Hash512 {
        sha512_dom(DOM_BLOCK512, &[&self.serialize()])
    }

    pub fn expected_epoch(&self, nn_epoch_blocks: u64) -> u32 {
        // Clamped rather than truncated: `height / nn_epoch_blocks` exceeds
        // `u32::MAX` past ~2.1e14 blocks, and a silent `as u32` wrap would make
        // the epoch check disagree with itself. A zero interval is refused by
        // `NetworkParams::validate`; return 0 here so a malformed profile
        // fails closed through the epoch check instead of panicking on divide
        // by zero (consensus code must never panic on profile data).
        if nn_epoch_blocks == 0 {
            return 0;
        }
        (self.height / nn_epoch_blocks).min(u32::MAX as u64) as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: Header,
    #[serde(with = "crate::hexserde::h64")]
    pub signature: [u8; 64],
    #[serde(with = "crate::hexserde::h33")]
    pub signer_pubkey: [u8; 33],
    pub txs: Vec<Transaction>,
    /// L2 transactions carried by this block (Decision 6, SPEC.md §19.1).
    ///
    /// Empty for every block that predates the L2-in-blocks (M1) upgrade, which is why the field is
    /// skipped in the JSON form and the binary form omits its section entirely:
    /// a block with no L2 transactions has exactly one encoding — the original
    /// one — so no frozen vector and no stored block changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub l2_txs: Vec<L2Transaction>,
    /// The committed L2 state root after this block's L2 transitions
    /// (approved P1, SPEC.md §19.6): the `L2State::committed_root` over
    /// accounts plus queued exits, which the exit release rule verifies proofs
    /// against.
    ///
    /// `None` for every pre-activation block and for post-activation blocks
    /// with no L2 transactions — the section rules below keep those encodings
    /// byte-identical to history. A post-activation block that carries L2
    /// transactions without a root is refused by consensus (the queue in it
    /// could never be proven), and a root below activation is refused (one
    /// encoding per block, and the upgrade must be explicit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2_state_root: Option<Hash>,
    /// L2 → L1 exit claims settled by this block (approved P1, E-1…E-3).
    ///
    /// Each claim consumes sink outputs and pays the recorded destination plus
    /// the claimant, authorised by an exit proof rather than a signature (see
    /// `crate::exit`). Empty for every pre-exit block; the section below is
    /// omitted when empty, so history is byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_claims: Vec<ExitClaim>,
}

impl Block {
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.header.serialize().len() + 512);
        w.raw(&self.header.serialize())
            .fixed(&self.signature)
            .fixed(&self.signer_pubkey)
            .u32le(self.txs.len() as u32);
        for tx in &self.txs {
            w.raw(&tx.serialize());
        }
        // L2 section (Decision 6 + P1 root). Omitted entirely when there is
        // nothing to commit — see the field comment: absence is what keeps
        // every pre-Phase-6 block byte-identical. Each entry is length-prefixed
        // so it can be read back without an L2 reader, and so a malformed
        // entry cannot desynchronise the parse. The root flag closes the
        // section explicitly (`0x00` = no root, `0x01` = 32 root bytes
        // follow): a bare length check could not tell a 32-byte root from a
        // 32-byte claims section, so the flag — not position — disambiguates.
        if !self.l2_txs.is_empty() || self.l2_state_root.is_some() {
            w.u32le(self.l2_txs.len() as u32);
            for tx in &self.l2_txs {
                let bytes = tx.serialize();
                w.u32le(bytes.len() as u32).raw(&bytes);
            }
            match &self.l2_state_root {
                None => w.u8(0x00),
                Some(root) => w.u8(0x01).fixed(root),
            };
        }
        // Exit-claim section (approved P1). Omitted entirely when empty, the
        // same discipline as the L2 section: every pre-exit block keeps its
        // exact bytes. Entries are length-prefixed like L2 transactions.
        if !self.exit_claims.is_empty() {
            w.u32le(self.exit_claims.len() as u32);
            for claim in &self.exit_claims {
                let bytes = claim.serialize();
                w.u32le(bytes.len() as u32).raw(&bytes);
            }
        }
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SERIALIZED_LEN {
            return Err(Error::Malformed("block shorter than header"));
        }
        let header = Header::deserialize(&bytes[..HEADER_SERIALIZED_LEN])?;
        let mut r = Reader::new(&bytes[HEADER_SERIALIZED_LEN..]);
        let signature = r.fixed()?;
        let signer_pubkey = r.fixed()?;
        let n = r.u32le()? as usize;
        // Bounded by the smallest a transaction can be, not by the raw byte
        // count, so a small buffer cannot force a large reservation.
        if n > r.remaining() / crate::tx::TX_MIN_SERIALIZED_LEN {
            return Err(Error::Malformed("tx_count exceeds buffer"));
        }
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            let tx = Transaction::from_reader(&mut r)?;
            txs.push(tx);
        }

        // L2 section (Decision 6 + P1 root). It is present only when it commits
        // something: L2 transactions, a state root, or both. An empty section
        // is a *second* encoding of a block that serializes without one, so it
        // is refused rather than accepted: two encodings for one block would
        // mean two byte strings claiming the same identity. The root flag
        // closes the section explicitly; any flag byte but `0x00`/`0x01` is
        // malformed, and anything trailing the section that is not the claim
        // section below is malformed.
        let mut l2_txs = Vec::new();
        let mut l2_state_root = None;
        // L2 transactions, if any, come first; the exit-claim section, if
        // any, comes last. Both are decoded here so one `expect_end` still
        // guards the whole body.
        let mut exit_claims = Vec::new();
        if r.remaining() > 0 {
            let m = r.u32le()? as usize;
            if m == 0 && r.remaining() == 0 {
                return Err(Error::Malformed(
                    "empty L2 section is not a canonical block encoding",
                ));
            }
            if m > r.remaining() / L2_TX_MIN_ENCODED_LEN {
                return Err(Error::Malformed("l2_tx_count exceeds buffer"));
            }
            l2_txs.reserve(m);
            for _ in 0..m {
                let len = r.u32le()? as usize;
                let bytes = r.fixed_slice(len)?;
                l2_txs.push(L2Transaction::deserialize(bytes)?);
            }
            match r.u8()? {
                0x00 => {}
                0x01 => {
                    l2_state_root = Some(r.fixed()?);
                }
                _ => {
                    return Err(Error::Malformed("l2 root flag must be 0x00 or 0x01"));
                }
            }
            // A section with no transactions and no root is the empty section
            // by another name: refused, so one block keeps one encoding.
            if m == 0 && l2_state_root.is_none() {
                return Err(Error::Malformed(
                    "empty L2 section is not a canonical block encoding",
                ));
            }
            // A root with no transactions commits nothing new — but it is a
            // distinct shape, not a second encoding, so decoding accepts it
            // and consensus validation decides (it refuses a rootless L2
            // section post-activation, never a redundant root).
            if r.remaining() > 0 {
                let k = r.u32le()? as usize;
                if k == 0 {
                    return Err(Error::Malformed(
                        "empty exit-claim section is not a canonical block encoding",
                    ));
                }
                if k > r.remaining() / EXIT_CLAIM_MIN_ENCODED_LEN {
                    return Err(Error::Malformed("exit claim count exceeds buffer"));
                }
                exit_claims.reserve(k);
                for _ in 0..k {
                    let len = r.u32le()? as usize;
                    let bytes = r.fixed_slice(len)?;
                    exit_claims.push(ExitClaim::deserialize(bytes)?);
                }
            }
        }

        r.expect_end()?;
        Ok(Block {
            header,
            signature,
            signer_pubkey,
            txs,
            l2_txs,
            l2_state_root,
            exit_claims,
        })
    }

    pub fn block_hash(&self) -> Hash512 {
        self.header.block_hash()
    }

    /// The root the header commits to. Covers L1 transactions first, then L2
    /// transactions (Decision 6), then the committed L2 state root when the
    /// block carries one, then exit claims in block order (approved P1) — a
    /// claim stripped from the body no longer matches the header, exactly as
    /// for L2 transactions.
    pub fn merkle_root(&self) -> Hash {
        merkle_root_with_l2(
            &self.txs,
            &self.l2_txs,
            self.l2_state_root.as_ref(),
            &self.exit_claims,
        )
    }

    /// Number of L2 transactions carried. Zero for every pre-Phase-6 block.
    pub fn l2_count(&self) -> usize {
        self.l2_txs.len()
    }

    /// Gas for the whole block.
    ///
    /// Checked, not `.sum()`: `sum` panics on overflow in debug and wraps in
    /// release, and this feeds the base-fee schedule and the gas cap. A node
    /// reading blocks from a file or the network must not be crashable by one.
    pub fn total_gas_used(&self) -> Result<u64> {
        self.txs.iter().try_fold(0u64, |acc, t| {
            acc.checked_add(t.gas_used()).ok_or(Error::ValueOverflow)
        })
    }

    /// Gas burned by this block's exit claims (approved P1). Claims are
    /// ordinary block space: they count toward the gas cap and the base-fee
    /// schedule exactly like body transactions, so exits cannot buy cheap
    /// block space the fee market never sees.
    pub fn claims_gas_used(&self) -> Result<u64> {
        self.exit_claims.iter().try_fold(0u64, |acc, c| {
            acc.checked_add(c.gas_used()).ok_or(Error::ValueOverflow)
        })
    }
}

const LEAF_TAG: u8 = 0x00;
const INTERNAL_TAG: u8 = 0x01;
/// L2 leaves are domain-separated from L1 leaves so an L2 payload can never be
/// reinterpreted as an L1 transaction leaf (Decision 6, SPEC.md §2 and §19.1).
const LEAF_TAG_L2: u8 = 0x02;
/// The committed L2 state root rides as its own leaf (approved P1), after the
/// L2 transaction leaves. `0x03` is sequential in *this* tree; the L2 state
/// tree's account-leaf `0x03` lives in a different tree (different root,
/// different verifier), exactly as the `0x01` internal tag already appears in
/// both trees without ambiguity.
const LEAF_TAG_L2_ROOT: u8 = 0x03;
/// Exit-claim leaves close the tree (approved P1): each claim's canonical
/// bytes under their own tag, so a claim can never be reinterpreted as a
/// transaction of either kind. `0x04` is sequential here; the L2 state tree's
/// exit-record `0x04` is a different tree's tag, same precedent as above.
const LEAF_TAG_EXIT_CLAIM: u8 = 0x04;

/// Binary merkle root with domain-separated leaves and internal nodes.
/// Odd nodes are duplicated, Bitcoin-style. SPEC.md §2.
pub fn merkle_root(txs: &[Transaction]) -> Hash {
    let leaves: Vec<Hash> = txs
        .iter()
        .map(|t| sha256(&[&[LEAF_TAG], &t.serialize()]))
        .collect();
    merkle_from_leaves(leaves)
}

/// Merkle root over a block body that may carry L2 transactions (Decision 6),
/// a committed L2 state root and exit claims (approved P1).
///
/// L1 leaves come first in block order, then L2 leaves in block order, then
/// the root leaf, then claim leaves in block order. When there is nothing but
/// L1 to commit this is **bit-identical** to `merkle_root(l1)`, which is the
/// property that keeps `genesis_block()` and every existing block unchanged.
/// Every leaf kind uses its own domain tag, so a body cannot be presented
/// with one kind where another is expected.
pub fn merkle_root_with_l2(
    l1: &[Transaction],
    l2: &[L2Transaction],
    root: Option<&Hash>,
    claims: &[ExitClaim],
) -> Hash {
    if l2.is_empty() && root.is_none() && claims.is_empty() {
        return merkle_root(l1);
    }
    let mut leaves: Vec<Hash> = Vec::with_capacity(l1.len() + l2.len() + claims.len() + 1);
    leaves.extend(l1.iter().map(|t| sha256(&[&[LEAF_TAG], &t.serialize()])));
    leaves.extend(l2.iter().map(|t| sha256(&[&[LEAF_TAG_L2], &t.serialize()])));
    if let Some(r) = root {
        leaves.push(sha256(&[&[LEAF_TAG_L2_ROOT], r]));
    }
    leaves.extend(
        claims
            .iter()
            .map(|c| sha256(&[&[LEAF_TAG_EXIT_CLAIM], &c.serialize()])),
    );
    merkle_from_leaves(leaves)
}

/// Fold leaves into a root. Total: an empty block body hashes to all zeroes,
/// which is unreachable in consensus (every valid block carries a coinbase)
/// but keeps the function defined for every input.
fn merkle_from_leaves(mut level: Vec<Hash>) -> Hash {
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(sha256(&[&[INTERNAL_TAG], &pair[0], &pair[0]]));
            } else {
                next.push(sha256(&[&[INTERNAL_TAG], &pair[0], &pair[1]]));
            }
        }
        level = next;
    }
    level[0]
}

/// The canonical inscription embedded in the genesis block, carried in the
/// coinbase output address — the Solar Cyber Unit analogue of Bitcoin's genesis headline
/// (SPEC.md §2.3, "The Times 03/Jan/2009…" precedent).
///
/// The protocol is scriptless (tx.rs §3.1), so there is no `OP_RETURN`. The
/// genesis coinbase output carries zero value, making its 20-byte address
/// unreachable as a spend target (`Chain::apply_block` never records zero-value
/// coinbases into the UTXO set). That leaves the address field free to carry
/// arbitrary permanent data without a protocol change or a new consensus rule.
///
/// "One Consciousness." is 18 bytes; the field is 20, so it is zero-padded on
/// the right. The padding is deterministic and recoverable.
pub const GENESIS_INSCRIPTION: &str = "One Consciousness.";

/// Build the 20-byte genesis output address from the inscription, right-padded
/// with zero bytes. Deterministic: every profile produces the identical address.
fn genesis_inscription_address() -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr[..GENESIS_INSCRIPTION.len()].copy_from_slice(GENESIS_INSCRIPTION.as_bytes());
    addr
}

/// The canonical genesis block. Contains zero value and no spendable output:
/// the 0% premine promised in the design doc (Section 16) is enforced by code.
/// The coinbase output address carries [`GENESIS_INSCRIPTION`] as a permanent
/// on-chain message (SPEC.md §2.3).
pub fn genesis_block(difficulty: u128) -> Block {
    let coinbase = Transaction::coinbase(
        ZERO_HASH512,
        0,
        Output {
            value: 0,
            address: genesis_inscription_address(),
        },
    );
    debug_assert!(coinbase.is_coinbase());
    let header = Header::genesis(merkle_root(std::slice::from_ref(&coinbase)), difficulty);
    Block {
        header,
        signature: [0u8; 64],
        signer_pubkey: [0u8; 33],
        txs: vec![coinbase],
        l2_txs: Vec::new(),
        l2_state_root: None,
        exit_claims: Vec::new(),
    }
}

pub fn is_genesis_shape_ok(block: &Block) -> bool {
    block.txs.len() == 1
        && block.txs[0].tx_type == TX_COINBASE
        && block.txs[0].outputs[0].value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Input;

    fn tx_with_tag(tag: u8) -> Transaction {
        Transaction::standard(
            vec![Input::unsigned(&crate::tx::OutPoint {
                txid: [tag; 64],
                index: 0,
            })],
            vec![Output {
                value: 1,
                address: [tag; 20],
            }],
        )
    }

    #[test]
    fn header_is_exactly_177_bytes_and_roundtrips() {
        let g = genesis_block(1);
        let bytes = g.header.serialize();
        assert_eq!(bytes.len(), HEADER_SERIALIZED_LEN);
        assert_eq!(Header::deserialize(&bytes).unwrap(), g.header);
    }

    #[test]
    fn header_hash_is_domain_separated_and_512_bit() {
        let g = genesis_block(1);
        assert_eq!(
            g.header.block_hash(),
            sha512_dom(DOM_BLOCK512, &[&g.header.serialize()])
        );
        // The 256-bit construction under the *old* tag must give a different
        // answer even truncated, or the widening would be cosmetic.
        let narrow = sha256_dom(DOM_BLOCK, &[&g.header.serialize()]);
        assert_ne!(&g.header.block_hash()[..32], &narrow[..]);
    }

    #[test]
    fn block_roundtrips() {
        let mut g = genesis_block(1);
        g.txs.push(tx_with_tag(3));
        g.header.merkle_root = g.merkle_root();
        let bytes = g.serialize();
        assert_eq!(Block::deserialize(&bytes).unwrap(), g);
    }

    #[test]
    fn block_hash_commits_to_the_merkle_root_not_the_tx_list() {
        let g1 = genesis_block(1);
        let mut g2 = genesis_block(1);
        g2.txs.push(tx_with_tag(9));
        // The header is what gets hashed, so an unchanged header means an
        // unchanged block hash even though the tx list differs. In practice the
        // merkle root inside the header is what binds the two.
        g2.header.merkle_root = g2.merkle_root();
        assert_eq!(g1.block_hash(), g1.block_hash());
        assert_ne!(g1.merkle_root(), g2.merkle_root());
        assert_ne!(g1.block_hash(), g2.block_hash());
    }

    #[test]
    fn merkle_single_tx_is_the_leaf() {
        let t = tx_with_tag(1);
        let leaf = sha256(&[&[LEAF_TAG], &t.serialize()]);
        assert_eq!(merkle_root(&[t]), leaf);
    }

    #[test]
    fn merkle_duplicate_last_for_odd_count() {
        let a = tx_with_tag(1);
        let b = tx_with_tag(2);
        let c = tx_with_tag(3);
        let la = sha256(&[&[LEAF_TAG], &a.serialize()]);
        let lb = sha256(&[&[LEAF_TAG], &b.serialize()]);
        let lc = sha256(&[&[LEAF_TAG], &c.serialize()]);
        let left = sha256(&[&[INTERNAL_TAG], &la, &lb]);
        let right = sha256(&[&[INTERNAL_TAG], &lc, &lc]);
        assert_eq!(
            merkle_root(&[a, b, c]),
            sha256(&[&[INTERNAL_TAG], &left, &right])
        );
    }

    #[test]
    fn genesis_mints_nothing() {
        let g = genesis_block(1);
        assert!(is_genesis_shape_ok(&g));
        assert_eq!(g.txs[0].value_out(), 0);
        assert_eq!(g.header.height, 0);
        assert_eq!(g.header.difficulty, 1);
        assert_eq!(g.header.prev_hash, [0u8; 64]);
        assert_eq!(g.header.merkle_root, g.merkle_root());
    }

    #[test]
    fn genesis_carries_the_canonical_inscription() {
        let g = genesis_block(1);
        // The exact text is recoverable from the genesis coinbase output address
        // (SPEC.md §2.3): the address is right-padded with zero bytes.
        let addr = g.txs[0].outputs[0].address;
        let trimmed: Vec<u8> = addr.iter().copied().take_while(|&b| b != 0).collect();
        assert_eq!(
            String::from_utf8(trimmed).unwrap(),
            GENESIS_INSCRIPTION,
            "the genesis inscription must round-trip exactly"
        );
        assert!(
            is_genesis_shape_ok(&g),
            "the inscription must not break the genesis shape check"
        );
    }

    #[test]
    fn genesis_inscription_is_zero_padded_and_deterministic() {
        let addr = crate::block::genesis_block(1).txs[0].outputs[0].address;
        // Exactly the message bytes, followed by zero padding to 20.
        assert_eq!(
            &addr[..GENESIS_INSCRIPTION.len()],
            GENESIS_INSCRIPTION.as_bytes()
        );
        assert_eq!(&addr[GENESIS_INSCRIPTION.len()..], &[0u8; 2]);
        // Identical across profiles (both call genesis_block with difficulty 1).
        let mainnet =
            crate::block::genesis_block(crate::params::NetworkParams::mainnet().genesis_difficulty)
                .txs[0]
                .outputs[0]
                .address;
        let mini =
            crate::block::genesis_block(crate::params::NetworkParams::mini().genesis_difficulty)
                .txs[0]
                .outputs[0]
                .address;
        assert_eq!(addr, mainnet, "mainnet genesis inscription must match");
        assert_eq!(addr, mini, "mini genesis inscription must match");
    }

    #[test]
    fn genesis_block_serializes_deserializes_with_inscription() {
        let g = genesis_block(1);
        let bytes = g.serialize();
        let back = Block::deserialize(&bytes).unwrap();
        assert_eq!(back, g, "genesis must round-trip through serialize");
        assert_eq!(
            back.txs[0].outputs[0].address, g.txs[0].outputs[0].address,
            "inscription must survive serialization"
        );
    }

    #[test]
    fn expected_epoch_follows_height() {
        let mut h = Header::genesis([0u8; 32], 1);
        assert_eq!(h.expected_epoch(50_000), 0);
        h.height = 49_999;
        assert_eq!(h.expected_epoch(50_000), 0);
        h.height = 50_000;
        assert_eq!(h.expected_epoch(50_000), 1);
        h.height = 120_000;
        assert_eq!(h.expected_epoch(50_000), 2);
    }

    #[test]
    fn expected_epoch_never_panics_and_template_matches_validation() {
        // Audit: `nn_epoch_blocks == 0` was a divide-by-zero panic in both
        // `expected_epoch` and the mining template (`as u32` truncation also
        // diverged from the clamped form past u32::MAX). A malformed profile
        // must fail closed, never panic, and the template must compute exactly
        // what validation checks.
        let h = Header::genesis([0u8; 32], 1);
        assert_eq!(h.expected_epoch(0), 0);
        let mut big = Header::genesis([0u8; 32], 1);
        big.height = u64::MAX;
        assert_eq!(big.expected_epoch(1), u32::MAX);
        assert_eq!(big.expected_epoch(2_000), u32::MAX);
    }

    // --- Properties -------------------------------------------------------
    //
    // A node parses bytes it did not produce, so every deserializer has to
    // reject hostile input by returning an error, never by panicking. There is
    // no fuzz harness here yet, so these properties run over a deterministic
    // spread of adversarial shapes instead of random bytes only: truncated
    // buffers, count fields claiming more entries than the buffer holds, and
    // length-prefix fields pinned to their extremes.

    /// Deterministic pseudo-random bytes, so a failure is reproducible from
    /// the seed alone rather than needing the original fuzz corpus.
    fn pseudo_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                // xorshift64*, chosen for being short and obviously
                // deterministic rather than for quality.
                s ^= s >> 12;
                s ^= s << 25;
                s ^= s >> 27;
                (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_deserializers() {
        for seed in 0..256u64 {
            let len = (seed as usize * 37) % 400;
            let bytes = pseudo_bytes(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), len);
            // The only requirement is that these return rather than panic.
            let _ = Block::deserialize(&bytes);
            let _ = Header::deserialize(&bytes);
            let _ = Transaction::deserialize(&bytes);
        }
    }

    #[test]
    fn every_truncation_of_a_valid_block_is_rejected_not_panicked() {
        let mut b = genesis_block(1);
        b.header.height = 1;
        b.header.prev_hash = [7u8; 64];
        b.header.timestamp_ms = GENESIS_TIMESTAMP_MS + 600_000;
        b.header.difficulty = 1;
        b.header.nonce = 1;
        let full = b.serialize();

        // Any prefix short of the whole thing must fail cleanly.
        for cut in 0..full.len() {
            assert!(
                Block::deserialize(&full[..cut]).is_err(),
                "a {cut}-byte prefix of a {}-byte block was accepted",
                full.len()
            );
        }
        // And trailing junk must fail rather than be ignored.
        let mut extended = full.clone();
        extended.push(0xAB);
        assert!(Block::deserialize(&extended).is_err());
    }

    #[test]
    fn a_count_field_cannot_claim_more_entries_than_the_buffer_holds() {
        // header + signature + pubkey, then a tx_count of u32::MAX against a
        // buffer with nothing after it. Without the remaining-buffer check
        // this would try to reserve four billion entries.
        let mut b = genesis_block(1);
        b.txs.clear();
        let mut bytes = b.serialize();
        bytes.truncate(HEADER_SERIALIZED_LEN + 64 + 33);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        assert!(matches!(
            Block::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));

        // Same shape one level down, inside a transaction. The count fields are
        // hand-assembled because `Transaction::standard` would refuse the
        // empty input and output lists this needs.
        let mut raw = Vec::new();
        raw.extend_from_slice(&1u32.to_le_bytes()); // version
        raw.push(crate::tx::TX_STANDARD);
        raw.extend_from_slice(&0u64.to_le_bytes()); // lock_time
        raw.extend_from_slice(&u32::MAX.to_le_bytes()); // input_count
        raw.extend_from_slice(&u32::MAX.to_le_bytes()); // output_count
        assert!(Transaction::deserialize(&raw).is_err());
    }

    #[test]
    fn serialization_round_trips_bit_for_bit() {
        let b = genesis_block(1);
        let bytes = b.serialize();
        let back = Block::deserialize(&bytes).unwrap();
        assert_eq!(back.serialize(), bytes, "block round-trip is not stable");
        assert_eq!(back.block_hash(), b.block_hash());

        let tx = &b.txs[0];
        let raw = tx.serialize();
        assert_eq!(Transaction::deserialize(&raw).unwrap(), *tx);
    }

    #[test]
    fn serialization_is_injective_for_every_output_value() {
        // Distinct value/address pairs must not collide on the wire, which is
        // what makes the coinbase value check in apply_block meaningful.
        let mut seen = std::collections::HashSet::new();
        for v in [0u64, 1, 76 * 100_000_000, u64::MAX - 1, u64::MAX] {
            let out = crate::tx::Output {
                value: v,
                address: [0xABu8; 20],
            };
            let bytes = out.to_bytes();
            assert!(
                seen.insert(bytes),
                "output value {v} collided with another on the wire"
            );
        }
    }

    // --- L2 transactions in the block body (Decision 6, SPEC.md §19.1) ------

    fn l2_post() -> L2Transaction {
        let w = crate::wallet::Wallet::from_private_key_bytes(&[9u8; 32], "block-l2").unwrap();
        let task = crate::compute_ir::ComputeTask {
            task_id: [0x11u8; 32],
            ir_hash: [0x22u8; 32],
            input_hash: [0x33u8; 32],
            required_memory_bytes: 4 * 1024 * 1024,
            backend_hint: crate::compute_ir::ComputeBackend::Gpu,
            reward_sat: 1_000_000,
            expiry_height: 500,
            submit_height: 1,
        };
        L2Transaction::new(crate::l2::L2Payload::Post(
            crate::l2::PostTaskPayload::build(&w, 1, 5_000_000, 500, task).unwrap(),
        ))
    }

    /// The property that lets this land without a format fork: a block with no
    /// L2 transactions encodes to exactly the pre-Phase-6 byte string, with no
    /// section, no length prefix and no version bump.
    #[test]
    fn a_block_without_l2_transactions_encodes_exactly_as_before() {
        let b = genesis_block(1);
        assert_eq!(b.l2_count(), 0);

        let mut expected = b.header.serialize();
        expected.extend_from_slice(&b.signature);
        expected.extend_from_slice(&b.signer_pubkey);
        expected.extend_from_slice(&(b.txs.len() as u32).to_le_bytes());
        for t in &b.txs {
            expected.extend_from_slice(&t.serialize());
        }
        assert_eq!(
            b.serialize(),
            expected,
            "an L2-free block must keep its original encoding byte for byte"
        );
    }

    /// An L2 transaction survives the round trip and — the point of the whole
    /// design — moves the value the header commits to.
    #[test]
    fn an_l2_transaction_round_trips_and_moves_the_commitment() {
        let mut b = genesis_block(1);
        let root_without = b.merkle_root();
        let hash_without = b.block_hash();

        // The compatibility direction first: no L2 txs means the same root.
        assert_eq!(
            merkle_root_with_l2(&b.txs, &[], None, &[]),
            merkle_root(&b.txs)
        );

        b.l2_txs.push(l2_post());
        let bytes = b.serialize();
        let back = Block::deserialize(&bytes).unwrap();
        assert_eq!(back, b, "block with L2 transactions did not round-trip");
        assert_eq!(back.l2_count(), 1);

        assert_ne!(
            b.merkle_root(),
            root_without,
            "carrying an L2 transaction must change the committed root"
        );
        // With the header updated, the block hash moves too — which is what
        // makes `Chain::submit`'s existing merkle check authenticate L2 content.
        b.header.merkle_root = b.merkle_root();
        assert_ne!(b.block_hash(), hash_without);
    }

    /// The malleability the commitment exists to stop: strip the L2 section from
    /// a block that has one and you get a decodable block — with a header whose
    /// merkle root no longer matches, so consensus refuses it.
    #[test]
    fn stripping_the_l2_section_leaves_a_block_its_header_rejects() {
        let mut b = genesis_block(1);
        b.l2_txs.push(l2_post());
        b.header.merkle_root = b.merkle_root();
        let full = b.serialize();

        // Rebuild the same body without the L2 section: a valid encoding of a
        // *different* block, whose header commitment no longer holds.
        let stripped = Block {
            l2_txs: Vec::new(),
            ..b.clone()
        };
        let stripped_bytes = stripped.serialize();
        assert!(stripped_bytes.len() < full.len());
        let decoded = Block::deserialize(&stripped_bytes).unwrap();
        assert_eq!(decoded.l2_count(), 0);
        assert_ne!(
            decoded.merkle_root(),
            decoded.header.merkle_root,
            "a stripped block must not satisfy its own header commitment"
        );

        // And the original bytes still decode to the committed content.
        assert_eq!(Block::deserialize(&full).unwrap(), b);
    }

    /// One block, one encoding: an empty section is refused rather than
    /// accepted as a second representation of the same block.
    #[test]
    fn an_empty_l2_section_is_rejected_as_non_canonical() {
        let b = genesis_block(1);
        let mut bytes = b.serialize();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Block::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn a_committed_l2_root_round_trips_and_moves_the_commitment() {
        let mut b = genesis_block(1);
        b.l2_txs.push(l2_post());
        let rootless = b.merkle_root();
        b.l2_state_root = Some([0xABu8; 32]);
        let bytes = b.serialize();
        let back = Block::deserialize(&bytes).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.l2_state_root, Some([0xABu8; 32]));
        // The root is its own leaf: the commitment moves.
        assert_ne!(b.merkle_root(), rootless);
        // Stripping the flag + root (33 bytes) leaves a section the decoder
        // refuses: the flag is load-bearing, so the root cannot be silently
        // dropped from committed bytes.
        let stripped = Block::deserialize(&bytes[..bytes.len() - 33]);
        assert!(stripped.is_err());
    }

    #[test]
    fn trailing_bytes_that_are_not_a_root_are_rejected() {
        let mut b = genesis_block(1);
        b.l2_txs.push(l2_post());
        let mut bytes = b.serialize();
        // 31 bytes: neither absent nor a full root.
        bytes.extend_from_slice(&[0x55u8; 31]);
        assert!(matches!(
            Block::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn an_l2_count_cannot_claim_more_entries_than_the_buffer_holds() {
        let b = genesis_block(1);
        let mut bytes = b.serialize();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Block::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));

        // A count that passes the cheap bound but is followed by a length
        // prefix larger than what remains must also fail, not allocate.
        let mut bytes = b.serialize();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Block::deserialize(&bytes).is_err());
    }

    #[test]
    fn every_truncation_of_an_l2_bearing_block_is_rejected_not_panicked() {
        let mut b = genesis_block(1);
        b.l2_txs.push(l2_post());
        b.header.merkle_root = b.merkle_root();
        let full = b.serialize();

        let body_end = {
            let mut no_l2 = b.clone();
            no_l2.l2_txs.clear();
            no_l2.serialize().len()
        };

        // Cuts inside the L2 section must fail. (The cut exactly at `body_end`
        // is the L2-free encoding, which decodes — and is then rejected by the
        // header commitment, as the stripping test above pins.)
        for cut in body_end + 1..full.len() {
            assert!(
                Block::deserialize(&full[..cut]).is_err(),
                "a {cut}-byte prefix of a {}-byte block was accepted",
                full.len()
            );
        }
        // Trailing junk is still junk.
        let mut extended = full.clone();
        extended.push(0xAB);
        assert!(Block::deserialize(&extended).is_err());
    }
}
