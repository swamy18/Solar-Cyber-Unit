//! Transactions. SPEC.md §3.1-§3.3, §9.2.
//!
//! v0.1 is scriptless by design (design doc Section 20.3: keep the consensus
//! layer small). Validity is decided by the rules in this module plus the
//! profile parameters; future primitives (bonds, certificates, channels) will
//! add new `tx_type` values, never a scripting language.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bls_checkpoint::{BlsPublicKey, BlsSignature, Checkpoint};
use crate::error::{Error, Result};
use crate::hash::{sha256_dom, sha512_dom, Address, Hash, Hash512, DOM_SIG, DOM_TX512, DOM_TXBODY};
use crate::hexserde;
use crate::ser::{Reader, Writer};

pub const TX_STANDARD: u8 = 0;
pub const TX_COINBASE: u8 = 1;
/// Decision 20 (P2): bonded-stake operations. Each carries a `stake` payload
/// (see [`StakePayload`]); STANDARD and COINBASE transactions carry no payload
/// byte, so their encodings — and txids — are unchanged.
pub const TX_BOND: u8 = 2;
pub const TX_UNBOND: u8 = 3;
pub const TX_SLASH: u8 = 4;

/// Maximum bytes of one checkpoint inside a slash payload.
///
/// A BLS-only checkpoint is a few hundred bytes, but a dual-signed one carries
/// up to 64 lattice signatures at 3 313 bytes each (~212 KB worst case). The
/// cap must admit the largest honest evidence or equivocation with a sidecar
/// becomes unslashable — which is exactly the equivocation a quantum adversary
/// would commit. It still stops a declared length from driving an allocation
/// off the actual buffer; that job does not depend on the number.
pub const MAX_SLASH_CHECKPOINT_BYTES: usize = 262_144;

/// Fixed part of a serialized input: `prev_hash(64) + prev_index(4)`. The
/// signature and key bundles that follow are variable-length (SPEC.md §3.2),
/// because a post-quantum signature is ~2.4 KB and no fixed field sized to
/// today's ECDSA could ever hold one.
pub const INPUT_FIXED_LEN: usize = 68;

/// Smallest an input can serialize to: the fixed prefix plus two empty bundle
/// counts. Used to bound a declared `input_count` before anything is reserved.
pub const INPUT_MIN_SERIALIZED_LEN: usize = INPUT_FIXED_LEN + 2;

/// `value(8) + address(20)`
pub const OUTPUT_SERIALIZED_LEN: usize = 28;

/// Smallest a transaction can serialize to: `version(4) + tx_type(1) +
/// lock_time(8) + input_count(4) + output_count(4)`, with no entries.
pub const TX_MIN_SERIALIZED_LEN: usize = 4 + 1 + 8 + 4 + 4;

/// Gas model (SPEC.md §8). No scripts, so cost is linear in size.
pub const GAS_TX_BASE: u64 = 16_000;
pub const GAS_PER_INPUT: u64 = 1_000;
pub const GAS_PER_OUTPUT: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutPoint {
    #[serde(with = "hexserde::h64")]
    pub txid: Hash512,
    pub index: u32,
}

impl OutPoint {
    pub fn to_bytes(&self) -> [u8; 68] {
        let mut w = Writer::with_capacity(68);
        w.fixed(&self.txid).u32le(self.index);
        let v = w.into_vec();
        let mut out = [0u8; 68];
        out.copy_from_slice(&v);
        out
    }
}

/// One spent outpoint plus a hybrid signature bundle over it.
///
/// `sigs` and `keys` are parallel bundles of equal length: `sigs[i]` is signed by
/// `keys[i]`, and **all** components must verify. A bundle of one is an ordinary
/// single-scheme signature; a bundle of several is a hybrid that survives one
/// primitive being broken. See `sig.rs` for why "all must verify" is the rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    #[serde(with = "hexserde::h64")]
    pub prev_hash: Hash512,
    pub prev_index: u32,
    pub sigs: crate::sig::Bundle,
    pub keys: crate::sig::Bundle,
}

impl Input {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.prev_hash,
            index: self.prev_index,
        }
    }

    pub fn unsigned(prev: &OutPoint) -> Self {
        Input {
            prev_hash: prev.txid,
            prev_index: prev.index,
            sigs: crate::sig::Bundle::default(),
            keys: crate::sig::Bundle::default(),
        }
    }

    /// Attach a single ECDSA signature, the common case.
    pub fn with_ecdsa(mut self, pubkey: [u8; 33], sig: [u8; 64]) -> Self {
        self.keys = crate::sig::Bundle::single(crate::sig::SCHEME_SECP256K1_ECDSA, pubkey.to_vec());
        self.sigs = crate::sig::Bundle::single(crate::sig::SCHEME_SECP256K1_ECDSA, sig.to_vec());
        self
    }

    /// Serialized length, known without serializing.
    pub fn serialized_len(&self) -> usize {
        INPUT_FIXED_LEN + self.sigs.serialized_len() + self.keys.serialized_len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.serialized_len());
        w.fixed(&self.prev_hash).u32le(self.prev_index);
        w.raw(&self.sigs.to_bytes()).raw(&self.keys.to_bytes());
        w.into_vec()
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let prev_hash: Hash512 = r.fixed()?;
        let prev_index = r.u32le()?;
        let sigs = crate::sig::Bundle::from_reader(r)?;
        let keys = crate::sig::Bundle::from_reader(r)?;
        Ok(Input {
            prev_hash,
            prev_index,
            sigs,
            keys,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub value: u64,
    #[serde(with = "hexserde::h20")]
    pub address: Address,
}

impl Output {
    pub fn to_bytes(&self) -> [u8; OUTPUT_SERIALIZED_LEN] {
        let mut w = Writer::with_capacity(OUTPUT_SERIALIZED_LEN);
        w.u64le(self.value).fixed(&self.address);
        let v = w.into_vec();
        let mut out = [0u8; OUTPUT_SERIALIZED_LEN];
        out.copy_from_slice(&v);
        out
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Output {
            value: r.u64le()?,
            address: r.fixed()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub tx_type: u8,
    pub lock_time: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    /// Stake-operation payload. `Some` only for `TX_BOND`/`TX_UNBOND`/`TX_SLASH`
    /// (see [`StakePayload`]); `None` for STANDARD and COINBASE, whose bytes
    /// are exactly what they were before this field existed.
    pub stake: Option<StakePayload>,
}

/// Stake-operation payload for bonded-stake transactions (Decision 20).
///
/// The canonical encoding is positional by `tx_type` — `Bond` is 48 key bytes
/// plus a 96-byte proof of possession (and optionally a lattice key), `Unbond`
/// is a 32-byte bond id, `Slash` is two length-prefixed checkpoints —
/// so there is exactly one byte string per operation. Semantic checks (single
/// signer, minimum stake, maturity, evidence validity) live in `bond.rs`, not
/// here: the codec stays dumb and total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakePayload {
    /// `TX_BOND`: the BLS key this bond authorizes for checkpoints, that key's
    /// proof of possession, plus the validator's lattice key when it registers
    /// one (`None` for bonds written before lattice registration existed, and
    /// for validators that have not migrated). The lattice key is looked up by
    /// BLS identity — it never replaces the BLS key as the committee identity,
    /// so bitmap order and `bond_identity` are unchanged by its presence.
    /// Boxed: 1952 bytes would otherwise make every stake payload pay for the
    /// largest variant, the same reason `Slash` is boxed.
    ///
    /// `pop` is mandatory: it is the BLS signature over
    /// [`crate::bond::bond_pop_message`] that proves the bonder holds the
    /// secret key behind `bls_pk`. Without it anyone could bond a public key
    /// they do not own — griefing a real validator out of their own key, or
    /// registering a rogue key chosen to cancel another key in an aggregate.
    /// See `bond::check_bond_tx`.
    Bond {
        bls_pk: BlsPublicKey,
        pop: BlsSignature,
        mldsa_pk: Option<Box<[u8; 1952]>>,
    },
    /// `TX_UNBOND`: the bond being released (the BOND transaction's txid).
    Unbond { bond_id: Hash512 },
    /// `TX_SLASH`: two conflicting checkpoints proving equivocation. Boxed:
    /// two checkpoints are ~400 bytes and every `Transaction` carries this
    /// enum inline, so the box keeps ordinary transactions small.
    Slash {
        first: Box<Checkpoint>,
        second: Box<Checkpoint>,
    },
}

impl StakePayload {
    /// The `tx_type` this payload belongs to.
    pub fn tx_type(&self) -> u8 {
        match self {
            StakePayload::Bond { .. } => TX_BOND,
            StakePayload::Unbond { .. } => TX_UNBOND,
            StakePayload::Slash { .. } => TX_SLASH,
        }
    }

    /// Canonical payload bytes (without any tag — `tx_type` says the shape).
    ///
    /// A bond is `bls_pk(48) ‖ pop(96)` when no lattice key is registered, and
    /// `bls_pk(48) ‖ pop(96) ‖ 0x01 ‖ mldsa_pk(1952)` when one is. A `0x00`
    /// flag byte is accepted and also means absent, so both spellings of "no
    /// key" name the same payload.
    ///
    /// The proof of possession is positional and always present, which is what
    /// makes a payload *without* one undecodable: the pre-PoP shape
    /// (`bls_pk(48)` alone) is refused by [`Self::from_reader`] rather than
    /// silently upgraded to a bond nobody proved they could sign for.
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            StakePayload::Bond {
                bls_pk,
                pop,
                mldsa_pk,
            } => {
                w.raw(bls_pk.as_bytes());
                w.raw(pop.as_bytes());
                if let Some(pk) = mldsa_pk {
                    w.u8(1).raw(&pk[..]);
                }
            }
            StakePayload::Unbond { bond_id } => {
                w.fixed(bond_id);
            }
            StakePayload::Slash { first, second } => {
                let a = first.serialize();
                let b = second.serialize();
                w.u32le(a.len() as u32).raw(&a);
                w.u32le(b.len() as u32).raw(&b);
            }
        }
        w.into_vec()
    }

    /// Decode payload bytes produced by [`StakePayload::body_bytes`]. Bounded:
    /// checkpoint lengths are capped before anything is allocated.
    pub fn from_reader(r: &mut Reader<'_>, tx_type: u8) -> Result<Self> {
        match tx_type {
            TX_BOND => {
                let raw = r.fixed::<48>().map_err(|_| Error::Malformed("bond key"))?;
                // The proof of possession is not optional: a payload that
                // stops after the key is the pre-PoP encoding, and a bond
                // nobody proved possession of is exactly what this field
                // exists to prevent.
                let pop: [u8; 96] = r
                    .fixed()
                    .map_err(|_| Error::Malformed("bond proof of possession"))?;
                // Anything past the proof must be the flag byte plus, for
                // `0x01`, exactly one 1952-byte key — then end of payload.
                if r.remaining() == 0 {
                    return Ok(StakePayload::Bond {
                        bls_pk: BlsPublicKey(raw),
                        pop: BlsSignature(pop),
                        mldsa_pk: None,
                    });
                }
                let flag = r.u8()?;
                let mldsa_pk = match flag {
                    0 => None,
                    1 => {
                        let key: [u8; 1952] = r.fixed()?;
                        Some(Box::new(key))
                    }
                    _ => return Err(Error::Malformed("bond lattice-key flag")),
                };
                r.expect_end()?;
                Ok(StakePayload::Bond {
                    bls_pk: BlsPublicKey(raw),
                    pop: BlsSignature(pop),
                    mldsa_pk,
                })
            }
            TX_UNBOND => {
                let bond_id = r.fixed::<64>().map_err(|_| Error::Malformed("bond id"))?;
                Ok(StakePayload::Unbond { bond_id })
            }
            TX_SLASH => {
                let a_len = r
                    .u32le()
                    .map_err(|_| Error::Malformed("slash checkpoint"))?
                    as usize;
                if a_len > MAX_SLASH_CHECKPOINT_BYTES {
                    return Err(Error::Malformed("slash checkpoint too large"));
                }
                let a_bytes = r
                    .fixed_slice(a_len)
                    .map_err(|_| Error::Malformed("slash checkpoint"))?
                    .to_vec();
                let b_len = r
                    .u32le()
                    .map_err(|_| Error::Malformed("slash checkpoint"))?
                    as usize;
                if b_len > MAX_SLASH_CHECKPOINT_BYTES {
                    return Err(Error::Malformed("slash checkpoint too large"));
                }
                let b_bytes = r
                    .fixed_slice(b_len)
                    .map_err(|_| Error::Malformed("slash checkpoint"))?
                    .to_vec();
                Ok(StakePayload::Slash {
                    first: Box::new(Checkpoint::deserialize(&a_bytes)?),
                    second: Box::new(Checkpoint::deserialize(&b_bytes)?),
                })
            }
            _ => Err(Error::Malformed("stake payload without stake type")),
        }
    }
}

/// Serde form of [`StakePayload`]: the owning `tx_type` plus hex of
/// [`StakePayload::body_bytes`]. JSON export (the `export` command) needs a
/// self-describing shape; consensus uses the canonical bytes, never this.
#[derive(Serialize, Deserialize)]
struct StakePayloadSer {
    t: u8,
    payload: String,
}

impl Serialize for StakePayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        StakePayloadSer {
            t: self.tx_type(),
            payload: crate::hash::to_hex(&self.body_bytes()),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StakePayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let v = StakePayloadSer::deserialize(deserializer)?;
        let bytes = crate::hash::from_hex(&v.payload).map_err(serde::de::Error::custom)?;
        let mut r = Reader::new(&bytes);
        let p = StakePayload::from_reader(&mut r, v.t).map_err(serde::de::Error::custom)?;
        r.expect_end().map_err(serde::de::Error::custom)?;
        Ok(p)
    }
}

impl Transaction {
    pub fn standard(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Transaction {
            version: 1,
            tx_type: TX_STANDARD,
            lock_time: 0,
            inputs,
            outputs,
            stake: None,
        }
    }

    pub fn coinbase(prev_hash: Hash512, height: u64, output: Output) -> Self {
        Transaction {
            version: 1,
            tx_type: TX_COINBASE,
            lock_time: 0,
            inputs: vec![Input::unsigned(&OutPoint {
                txid: prev_hash,
                index: height as u32,
            })],
            outputs: vec![output],
            stake: None,
        }
    }

    /// Bond/unbond/slash transaction with its stake payload. The caller must
    /// match the payload variant to `tx_type`; [`crate::bond`] refuses a
    /// mismatch rather than interpreting it.
    pub fn stake_tx(
        tx_type: u8,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        stake: StakePayload,
    ) -> Self {
        Transaction {
            version: 1,
            tx_type,
            lock_time: 0,
            inputs,
            outputs,
            stake: Some(stake),
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.tx_type == TX_COINBASE
    }

    /// True for the three bonded-stake operation types (Decision 20).
    pub fn is_stake_tx(&self) -> bool {
        matches!(self.tx_type, TX_BOND | TX_UNBOND | TX_SLASH)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.inputs.len() * INPUT_FIXED_LEN);
        w.u32le(self.version)
            .u8(self.tx_type)
            .u64le(self.lock_time)
            .u32le(self.inputs.len() as u32);
        for i in &self.inputs {
            w.raw(&i.to_bytes());
        }
        w.u32le(self.outputs.len() as u32);
        for o in &self.outputs {
            w.raw(&o.to_bytes());
        }
        // Stake payload bytes ride after the outputs, and only for stake
        // transaction types: STANDARD and COINBASE encodings are byte-identical
        // to before this field existed, so their txids are unchanged.
        if let Some(p) = &self.stake {
            w.raw(&p.body_bytes());
        }
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let tx = Transaction::from_reader(&mut r)?;
        r.expect_end()?;
        Ok(tx)
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.u32le()?;
        let tx_type = r.u8()?;
        let lock_time = r.u64le()?;
        let n_in = r.u32le()? as usize;
        // A count field is attacker-controlled and is checked *before* the
        // reservation it drives. Comparing it against the raw remaining-byte
        // count is not enough: every input costs at least
        // `INPUT_MIN_SERIALIZED_LEN`, so a buffer could declare up to its own
        // length in entries and force a Vec of `Input` structs many times
        // larger than the bytes describing them.
        if n_in > r.remaining() / INPUT_MIN_SERIALIZED_LEN {
            return Err(Error::Malformed("input_count exceeds buffer"));
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            inputs.push(Input::from_reader(r)?);
        }
        let n_out = r.u32le()? as usize;
        if n_out > r.remaining() / OUTPUT_SERIALIZED_LEN {
            return Err(Error::Malformed("output_count exceeds buffer"));
        }
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outputs.push(Output::from_reader(r)?);
        }
        // Positional by type: only stake transaction types carry payload bytes.
        // Anything trailing a STANDARD/COINBASE body is refused by `expect_end`
        // in `deserialize`, so a smuggled payload cannot hide there.
        let stake = match tx_type {
            TX_BOND | TX_UNBOND | TX_SLASH => Some(StakePayload::from_reader(r, tx_type)?),
            _ => None,
        };
        Ok(Transaction {
            version,
            tx_type,
            lock_time,
            inputs,
            outputs,
            stake,
        })
    }

    pub fn txid(&self) -> Hash512 {
        sha512_dom(DOM_TX512, &[&self.serialize()])
    }

    /// Hash of the transaction with all signatures and pubkeys blanked.
    ///
    /// Signing against this (rather than the raw body) is what stops an output
    /// being swapped after the inputs were signed — SPEC.md §1.1.
    pub fn sighash(&self) -> Hash {
        let mut blanked = self.clone();
        for i in blanked.inputs.iter_mut() {
            i.sigs = crate::sig::Bundle::default();
            i.keys = crate::sig::Bundle::default();
        }
        sha256_dom(DOM_TXBODY, &[&blanked.serialize()])
    }

    /// Exact bytes signed for input `k`.
    ///
    /// # Panics
    ///
    /// Panics if `k` is out of bounds. Callers with a wire-supplied index
    /// must use [`Self::try_message_for_input`] instead.
    pub fn message_for_input(&self, k: usize) -> Hash {
        self.try_message_for_input(k)
            .expect("message_for_input index out of bounds")
    }

    /// Fallible form of [`Self::message_for_input`] for wire-supplied indices:
    /// a bad index is `Malformed`, never a panic.
    pub fn try_message_for_input(&self, k: usize) -> crate::error::Result<Hash> {
        let input = self
            .inputs
            .get(k)
            .ok_or(crate::error::Error::Malformed("input index out of bounds"))?;
        let k32 = u32::try_from(k)
            .map_err(|_| crate::error::Error::Malformed("input index overflows u32"))?;
        let mut w = Writer::with_capacity(48);
        w.u32le(k32).fixed(&self.sighash()).u32le(input.prev_index);
        Ok(sha256_dom(DOM_SIG, &[w.as_slice()]))
    }

    /// Total value of all outputs.
    ///
    /// Saturating, and the caller must treat `u64::MAX` as overflow: a
    /// transaction can declare more output value than a `u64` holds, and
    /// summing it with `.sum()` would panic in debug builds and wrap in
    /// release ones. `check_tx` compares this against the resolved input
    /// total and rejects it, so a wrapped sum could otherwise masquerade
    /// as a transaction spending less than it creates.
    pub fn value_out(&self) -> u64 {
        self.outputs
            .iter()
            .fold(0u64, |acc, o| acc.saturating_add(o.value))
    }

    /// True when the output total cannot be represented. `check_tx` calls
    /// this before trusting `value_out`.
    pub fn value_out_overflows(&self) -> bool {
        let mut acc: u64 = 0;
        for o in &self.outputs {
            match acc.checked_add(o.value) {
                Some(next) => acc = next,
                None => return true,
            }
        }
        false
    }

    /// Sum of input values. Only meaningful once inputs have been resolved
    /// against the UTXO set; `build`/`validate` pass those values in.
    pub fn gas_used(&self) -> u64 {
        GAS_TX_BASE
            .saturating_add(GAS_PER_INPUT * self.inputs.len() as u64)
            .saturating_add(GAS_PER_OUTPUT * self.outputs.len() as u64)
    }

    pub fn has_duplicate_inputs(&self) -> bool {
        let mut seen: Vec<OutPoint> = self.inputs.iter().map(|i| i.outpoint()).collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        seen.len() != before
    }

    pub fn has_zero_value_output(&self) -> bool {
        self.outputs.iter().any(|o| o.value == 0)
    }

    /// Verify input `k` against the address that owns the spent output.
    ///
    /// The scheme is no longer passed in: each input carries its own bundles
    /// and names its schemes, which is what makes agility real rather than a
    /// byte that only ever has one legal value. `require_hybrid` is kept for
    /// callers that want to reject single-scheme inputs, and is what a network
    /// would switch on to require post-quantum readiness.
    pub fn verify_input(&self, k: usize, owner: &Address, require_hybrid: bool) -> Result<()> {
        let input = &self.inputs[k];

        input.sigs.validate()?;
        input.keys.validate()?;
        if require_hybrid && input.sigs.components.len() < 2 {
            return Err(Error::HybridRequired);
        }

        // The address commits to the whole key bundle, so a hybrid key set
        // cannot be swapped for a smaller one that omits a component.
        let addr = input.keys.address()?;
        if &addr != owner {
            return Err(Error::WrongAddress);
        }

        let msg = self.message_for_input(k);
        crate::sig::verify_bundle(&input.sigs, &input.keys, &msg)
    }

    /// Convenience wrapper for the common single-scheme-allowed case.
    pub fn verify_input_any(&self, k: usize, owner: &Address) -> Result<()> {
        self.verify_input(k, owner, false)
    }

    /// The migration-rule verifier (Decision 24, step 4): exactly
    /// [`Transaction::verify_input`] with hybrid required, plus a refusal for
    /// any bundle that does not carry scheme 3 (ML-DSA-65).
    ///
    /// The scheme check runs *before* any cryptography: a bundle that cannot
    /// satisfy the rule is a structural refusal, not a verification failure.
    /// Consensus does not call this yet — flipping to it happens through an
    /// explicit `pq_activation_height`, `0` meaning never like every other
    /// activation, and that wiring is a separate change.
    pub fn verify_input_pq(&self, k: usize, owner: &Address) -> Result<()> {
        let input = &self.inputs[k];
        if !input.sigs.has_scheme(crate::sig::SCHEME_ML_DSA_65) {
            return Err(Error::HybridRequired);
        }
        self.verify_input(k, owner, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey() -> [u8; 33] {
        // x = 1 generator point, a well-known valid compressed key.
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn an_unsigned_input_is_the_fixed_prefix_plus_two_empty_bundles() {
        // The signature and key bundles are length-prefixed, so an unsigned
        // input is `prev_hash(32) + prev_index(4) + count(0) + count(0)`.
        let i = Input::unsigned(&OutPoint {
            txid: [7u8; 64],
            index: 3,
        });
        assert_eq!(i.to_bytes().len(), INPUT_FIXED_LEN + 2);
        assert_eq!(i.serialized_len(), INPUT_FIXED_LEN + 2);
        assert_eq!(
            Output {
                value: 1,
                address: [0u8; 20]
            }
            .to_bytes()
            .len(),
            OUTPUT_SERIALIZED_LEN
        );
    }

    #[test]
    fn transaction_roundtrips() {
        let tx = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [1u8; 64],
                index: 0,
            })],
            vec![Output {
                value: 500,
                address: [9u8; 20],
            }],
        );
        let bytes = tx.serialize();
        let back = Transaction::deserialize(&bytes).unwrap();
        assert_eq!(tx, back);
        assert_eq!(back.txid(), tx.txid());
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let tx = Transaction::standard(
            vec![],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        let mut bytes = tx.serialize();
        bytes.push(0);
        assert!(matches!(
            Transaction::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn deserialize_rejects_absurd_counts() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(TX_STANDARD);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Transaction::deserialize(&bytes).is_err());
    }

    #[test]
    fn sighash_ignores_signatures_but_covers_outputs() {
        let base = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [2u8; 64],
                index: 1,
            })],
            vec![Output {
                value: 100,
                address: [1u8; 20],
            }],
        );
        let mut signed = base.clone();
        signed.inputs[0] = signed.inputs[0]
            .clone()
            .with_ecdsa(sample_pubkey(), [0xab; 64]);
        assert_eq!(
            base.sighash(),
            signed.sighash(),
            "sig must not affect sighash"
        );

        let mut retargeted = base.clone();
        retargeted.outputs[0].address = [2u8; 20];
        assert_ne!(
            base.sighash(),
            retargeted.sighash(),
            "outputs must be committed"
        );
    }

    #[test]
    fn duplicate_inputs_detected() {
        let prev = OutPoint {
            txid: [5u8; 64],
            index: 0,
        };
        let tx = Transaction::standard(
            vec![Input::unsigned(&prev), Input::unsigned(&prev)],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        assert!(tx.has_duplicate_inputs());

        let tx2 = Transaction::standard(
            vec![
                Input::unsigned(&prev),
                Input::unsigned(&OutPoint {
                    txid: [5u8; 64],
                    index: 1,
                }),
            ],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        assert!(!tx2.has_duplicate_inputs());
    }

    #[test]
    fn wrong_owner_address_is_rejected() {
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [1u8; 64],
                index: 0,
            })],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        // The address now commits to the whole key bundle, so derive it the
        // same way rather than reaching for a bare-pubkey helper.
        tx.inputs[0] = tx.inputs[0].clone().with_ecdsa(sample_pubkey(), [0xab; 64]);
        let real = tx.inputs[0].keys.address().unwrap();
        assert!(
            matches!(
                tx.verify_input_any(0, &real),
                Err(Error::BadSignature { .. })
            ),
            "a bogus signature must not verify"
        );
        assert!(matches!(
            tx.verify_input_any(0, &[0u8; 20]),
            Err(Error::WrongAddress)
        ));

        // A scheme this build cannot verify is refused at the bundle level.
        tx.inputs[0].sigs.components[0].scheme = 99;
        assert!(matches!(
            tx.verify_input_any(0, &real),
            Err(Error::UnsupportedSigScheme(99))
        ));
    }

    #[test]
    fn an_unrepresentable_output_total_is_detected_not_wrapped() {
        // Outputs summing past u64::MAX. `.sum()` used to panic in debug and
        // wrap in release; `value_out_overflows` is what `check_tx` consults,
        // and `value_out` saturates rather than lying about the total.
        let tx = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [0; 64],
                index: 0,
            })],
            vec![
                Output {
                    value: u64::MAX,
                    address: [1; 20],
                },
                Output {
                    value: 1,
                    address: [2; 20],
                },
            ],
        );
        assert!(tx.value_out_overflows());
        assert_eq!(tx.value_out(), u64::MAX, "must saturate, not wrap to 0");

        // And a representable total must not be reported as overflow.
        let ok = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [0; 64],
                index: 0,
            })],
            vec![
                Output {
                    value: 1_000,
                    address: [1; 20],
                },
                Output {
                    value: 2_000,
                    address: [2; 20],
                },
            ],
        );
        assert!(!ok.value_out_overflows());
        assert_eq!(ok.value_out(), 3_000);
    }

    #[test]
    fn gas_is_linear_in_size() {
        let one = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [0; 64],
                index: 0,
            })],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        assert_eq!(one.gas_used(), GAS_TX_BASE + GAS_PER_INPUT + GAS_PER_OUTPUT);
    }

    /// Byte layouts pinned in `verification/tests/vectors/ser_vectors.json`.
    ///
    /// Section sizes alone are already asserted above; what matters for a
    /// second implementation is the exact byte order, so the full
    /// serializations are recorded rather than just their lengths.
    #[test]
    fn serialization_vectors_are_stable() {
        // Regenerate with: UPDATE_SER_VECTORS=1 cargo test -p srct-core
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../verification/tests/vectors/ser_vectors.json");

        // A hybrid input: two schemes over one outpoint, which is the shape
        // the variable-length encoding exists for.
        let mut ecdsa_pub = [0xEFu8; 33];
        ecdsa_pub[0] = 0x02; // compressed secp256k1 prefix
        let schnorr_pub = [0x11u8; 32];
        let input = Input {
            prev_hash: [0xABu8; 64],
            prev_index: 0xDEAD_BEEF,
            keys: crate::sig::Bundle {
                components: vec![
                    crate::sig::Component::new(
                        crate::sig::SCHEME_SECP256K1_ECDSA,
                        ecdsa_pub.to_vec(),
                    ),
                    crate::sig::Component::new(
                        crate::sig::SCHEME_SECP256K1_SCHNORR,
                        schnorr_pub.to_vec(),
                    ),
                ],
            },
            sigs: crate::sig::Bundle {
                components: vec![
                    crate::sig::Component::new(crate::sig::SCHEME_SECP256K1_ECDSA, vec![0xCD; 64]),
                    crate::sig::Component::new(
                        crate::sig::SCHEME_SECP256K1_SCHNORR,
                        vec![0x77; 64],
                    ),
                ],
            },
        };
        let input_len = input.serialized_len();
        let output = Output {
            value: 0x0123_4567_89AB_CDEF,
            address: [0x42u8; 20],
        };
        let tx = Transaction {
            version: 1,
            tx_type: TX_STANDARD,
            lock_time: 0x11_22_33_44_55_66_77_88,
            inputs: vec![input.clone()],
            outputs: vec![output],
            stake: None,
        };

        let entries: Vec<(&str, Vec<u8>, usize)> = vec![
            ("input", input.to_bytes(), input_len),
            ("output", output.to_bytes().to_vec(), OUTPUT_SERIALIZED_LEN),
            ("transaction", tx.serialize(), 0),
        ];

        let mut json = String::from("{\n");
        json.push_str(
            "  \"_comment\": \"Generated from srct-core by serialization_vectors_are_stable. \
Do not hand-edit.\",\n",
        );
        json.push_str(&format!("  \"input_fixed_len\": {INPUT_FIXED_LEN},\n"));
        json.push_str(&format!("  \"output_len\": {OUTPUT_SERIALIZED_LEN},\n"));
        json.push_str("  \"items\": [\n");
        for (i, (name, bytes, declared)) in entries.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"name\": \"{name}\",\n"));
            json.push_str(&format!("      \"len\": {},\n", bytes.len()));
            if *declared > 0 {
                json.push_str(&format!("      \"declared_len\": {declared},\n"));
            }
            json.push_str(&format!("      \"hex\": \"{}\"\n", hex::encode(bytes)));
            json.push_str(if i + 1 == entries.len() {
                "    }\n"
            } else {
                "    },\n"
            });
        }
        json.push_str("  ]\n}\n");

        if std::env::var("UPDATE_SER_VECTORS").is_ok() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, json).unwrap();
            eprintln!("wrote {}", path.display());
            return;
        }

        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read {}: {e}\nregenerate with UPDATE_SER_VECTORS=1",
                path.display()
            )
        });
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["input_fixed_len"].as_u64().unwrap(), 68, "SPEC.md 3.2");
        assert_eq!(v["output_len"].as_u64().unwrap(), 28, "SPEC.md 3.3");

        let listed = v["items"].as_array().expect("items must be an array");
        assert_eq!(listed.len(), entries.len(), "vector file is stale");
        for (entry, (name, bytes, _)) in listed.iter().zip(entries.iter()) {
            assert_eq!(entry["name"], *name);
            assert_eq!(
                entry["len"].as_u64().unwrap() as usize,
                bytes.len(),
                "{name}: serialized length changed"
            );
            assert_eq!(
                entry["hex"].as_str().unwrap(),
                hex::encode(bytes),
                "{name}: serialized bytes changed -- this is a consensus change"
            );
        }
    }
}
