//! Signed encrypted-compute tasks and worker receipts.
//!
//! The workflow mirrors the master brief §5, narrowed to the operations the
//! [`crate::elgamal`] prototype honestly supports:
//!
//! 1. Agent A generates [`crate::elgamal::FheKeys`], encrypts its inputs and
//!    signs an [`FheTask`] (inputs + plaintext weights/bias + provider +
//!    deadline). The secret never leaves A.
//! 2. Worker B homomorphically evaluates [`eval`] over the ciphertexts and
//!    signs an [`FheReceipt`] binding the task hash and the output ciphertext.
//! 3. A (or any verifier) re-runs [`eval`] — the operation is public — and
//!    [`FheVerifier::verify`] accepts only an exact match. A decrypts the
//!    output with its secret.
//! 4. The escrow rail releases payment on `Ok` and penalizes on `Err`.
//!
//! Weights and bias are public (the worker sees them); inputs and outputs
//! stay encrypted. Arithmetic is modulo the curve order — keep values in
//! range and decrypt with a bound above the largest expected result.

use std::collections::BTreeSet;

use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::ProjectivePoint;
use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::elgamal::{Ciphertext, CIPHERTEXT_LEN, POINT_LEN};
use crate::FheError;

pub const FHE_VERSION: u8 = 1;
/// Ciphertext inputs per task: enough for a small linear layer, bounded for
/// wire safety.
pub const MAX_INPUTS: usize = 64;
/// Plaintext weights stay small so evaluated sums stay inside the decode bound.
pub const MAX_WEIGHT_ABS: i64 = 1_000_000;

const DOM_FHE_TASK: &[u8] = b"srct/fhe/task/v1";
const DOM_FHE_RECEIPT: &[u8] = b"srct/fhe/receipt/v1";

/// The one supported operation: `output = bias + Σ weights[i] * inputs[i]`
/// over ciphertexts. The linear core of private-input neural inference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightedSum {
    pub weights: Vec<i64>,
    pub bias: u64,
}

impl WeightedSum {
    fn validate(&self, inputs: usize) -> Result<(), FheError> {
        if self.weights.len() != inputs {
            return Err(FheError::Malformed(
                "fhe weights must match the input count".into(),
            ));
        }
        if self.weights.is_empty() || self.weights.len() > MAX_INPUTS {
            return Err(FheError::Malformed("fhe input count out of range".into()));
        }
        if self.weights.iter().any(|w| w.abs() > MAX_WEIGHT_ABS) {
            return Err(FheError::Malformed("fhe weight exceeds the cap".into()));
        }
        Ok(())
    }

    fn encode(&self, w: &mut Writer) {
        w.u16le(self.weights.len() as u16);
        for weight in &self.weights {
            w.u64le(*weight as u64);
        }
        w.u64le(self.bias);
    }

    fn decode(r: &mut Reader) -> Result<Self, FheError> {
        let count = r.u16le().map_err(malformed)? as usize;
        if count == 0 || count > MAX_INPUTS {
            return Err(FheError::Malformed("fhe input count out of range".into()));
        }
        let mut weights = Vec::with_capacity(count);
        for _ in 0..count {
            let weight = r.u64le().map_err(malformed)? as i64;
            if weight.abs() > MAX_WEIGHT_ABS {
                return Err(FheError::Malformed("fhe weight exceeds the cap".into()));
            }
            weights.push(weight);
        }
        let bias = r.u64le().map_err(malformed)?;
        Ok(WeightedSum { weights, bias })
    }
}

/// Evaluate the weighted sum homomorphically. Public and deterministic: the
/// worker and every verifier compute the same output ciphertext.
pub fn eval(op: &WeightedSum, inputs: &[Ciphertext]) -> Result<Ciphertext, FheError> {
    op.validate(inputs.len())?;
    let mut acc = Ciphertext::trivial_plaintext(op.bias);
    for (input, weight) in inputs.iter().zip(op.weights.iter()) {
        acc = acc.add(&input.scalar_mul(*weight)?)?;
    }
    Ok(acc)
}

/// A requester-signed encrypted-compute task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FheTask {
    pub version: u8,
    pub network_id: String,
    pub requester: Address,
    pub provider: Address,
    /// Requester's encryption public key (compressed). Ciphertexts that do
    /// not validate under it are refused at decode.
    pub enc_pubkey: [u8; POINT_LEN],
    pub op: WeightedSum,
    pub inputs: Vec<Ciphertext>,
    pub deadline_height: u64,
    pub nonce: u64,
}

impl FheTask {
    fn validate(&self) -> Result<(), FheError> {
        if self.version != FHE_VERSION {
            return Err(FheError::Malformed(format!(
                "unsupported fhe task version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(FheError::Malformed("fhe task network id length".into()));
        }
        decode_pubkey(&self.enc_pubkey)?;
        self.op.validate(self.inputs.len())?;
        if self.deadline_height == 0 {
            return Err(FheError::Malformed("fhe task deadline is zero".into()));
        }
        if self.nonce == 0 {
            return Err(FheError::Malformed("fhe task nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256 + self.inputs.len() * CIPHERTEXT_LEN);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.requester)
            .fixed(&self.provider)
            .raw(&self.enc_pubkey);
        self.op.encode(&mut w);
        w.u16le(self.inputs.len() as u16);
        for input in &self.inputs {
            w.raw(&input.encode());
        }
        w.u64le(self.deadline_height).u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_FHE_TASK, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FheError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(FheError::Malformed("fhe task network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| FheError::Malformed("fhe task network is not utf-8".into()))?
            .to_string();
        let requester = r.fixed().map_err(malformed)?;
        let provider = r.fixed().map_err(malformed)?;
        let mut enc_pubkey = [0u8; POINT_LEN];
        enc_pubkey.copy_from_slice(r.fixed_slice(POINT_LEN).map_err(malformed)?);
        let op = WeightedSum::decode(&mut r)?;
        let count = r.u16le().map_err(malformed)? as usize;
        if count == 0 || count > MAX_INPUTS || count != op.weights.len() {
            return Err(FheError::Malformed("fhe input count out of range".into()));
        }
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            let raw: &[u8] = r.fixed_slice(CIPHERTEXT_LEN).map_err(malformed)?;
            let mut bytes = [0u8; CIPHERTEXT_LEN];
            bytes.copy_from_slice(raw);
            inputs.push(Ciphertext::decode(&bytes)?);
        }
        let deadline_height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let task = FheTask {
            version,
            network_id,
            requester,
            provider,
            enc_pubkey,
            op,
            inputs,
            deadline_height,
            nonce,
        };
        task.validate()?;
        Ok(task)
    }
}

fn decode_pubkey(raw: &[u8; POINT_LEN]) -> Result<ProjectivePoint, FheError> {
    if *raw == [0u8; POINT_LEN] {
        return Err(FheError::Malformed(
            "fhe public key must not be the identity".into(),
        ));
    }
    let enc = k256::EncodedPoint::from_bytes(raw.as_slice())
        .map_err(|_| FheError::Malformed("fhe public key encoding is invalid".into()))?;
    // A 33-byte compressed encoding can never be the identity point.
    Option::from(<ProjectivePoint as FromEncodedPoint<k256::Secp256k1>>::from_encoded_point(&enc))
        .ok_or_else(|| FheError::Malformed("fhe public key is not on the curve".into()))
}

/// A requester-signed task: the signature covers inputs, weights, provider
/// and deadline, so none can be swapped under the worker or the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFheTask {
    pub task: FheTask,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedFheTask {
    pub fn sign(task: FheTask, requester: &Wallet) -> Result<Self, FheError> {
        task.validate()?;
        let address = requester
            .address()
            .map_err(|e| FheError::BadSignature(e.to_string()))?;
        if address != task.requester {
            return Err(FheError::WrongRequester);
        }
        let auth = Auth::sign(requester, &task.hash())
            .map_err(|e| FheError::BadSignature(e.to_string()))?;
        Ok(SignedFheTask {
            task,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), FheError> {
        self.task.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| FheError::BadSignature(e.to_string()))?;
        if signer != self.task.requester {
            return Err(FheError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.task.hash())
            .map_err(|e| FheError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.task.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.task.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FheError> {
        let (body, sigs, keys) = decode_signed(bytes, "fhe task")?;
        let task = FheTask::decode(&body)?;
        let signed = SignedFheTask { task, sigs, keys };
        signed.verify()?;
        Ok(signed)
    }
}

/// A worker-signed claim: the output ciphertext for one task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FheReceipt {
    pub version: u8,
    pub task: Hash,
    pub worker: Address,
    pub output: Ciphertext,
    pub height: u64,
    pub nonce: u64,
}

impl FheReceipt {
    fn validate(&self) -> Result<(), FheError> {
        if self.version != FHE_VERSION {
            return Err(FheError::Malformed(format!(
                "unsupported fhe receipt version {}",
                self.version
            )));
        }
        if self.task == [0u8; 32] {
            return Err(FheError::Malformed("fhe receipt task hash is zero".into()));
        }
        if self.nonce == 0 {
            return Err(FheError::Malformed("fhe receipt nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160 + CIPHERTEXT_LEN);
        w.u8(self.version)
            .fixed(&self.task)
            .fixed(&self.worker)
            .raw(&self.output.encode())
            .u64le(self.height)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_FHE_RECEIPT, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FheError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let task = r.fixed().map_err(malformed)?;
        let worker = r.fixed().map_err(malformed)?;
        let raw: &[u8] = r.fixed_slice(CIPHERTEXT_LEN).map_err(malformed)?;
        let mut ct = [0u8; CIPHERTEXT_LEN];
        ct.copy_from_slice(raw);
        let output = Ciphertext::decode(&ct)?;
        let height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let receipt = FheReceipt {
            version,
            task,
            worker,
            output,
            height,
            nonce,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFheReceipt {
    pub receipt: FheReceipt,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedFheReceipt {
    pub fn sign(receipt: FheReceipt, worker: &Wallet) -> Result<Self, FheError> {
        receipt.validate()?;
        let address = worker
            .address()
            .map_err(|e| FheError::BadSignature(e.to_string()))?;
        if address != receipt.worker {
            return Err(FheError::WrongWorker);
        }
        let auth = Auth::sign(worker, &receipt.hash())
            .map_err(|e| FheError::BadSignature(e.to_string()))?;
        Ok(SignedFheReceipt {
            receipt,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), FheError> {
        self.receipt.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| FheError::BadSignature(e.to_string()))?;
        if signer != self.receipt.worker {
            return Err(FheError::WrongWorker);
        }
        verify_bundle(&self.sigs, &self.keys, &self.receipt.hash())
            .map_err(|e| FheError::BadSignature(e.to_string()))
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.receipt.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FheError> {
        let (body, sigs, keys) = decode_signed(bytes, "fhe receipt")?;
        let receipt = FheReceipt::decode(&body)?;
        let signed = SignedFheReceipt {
            receipt,
            sigs,
            keys,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// Fail-closed verifier: signatures, bindings, deadline, exact homomorphic
/// recomputation, and a replay book. Returns the accepted output ciphertext;
/// the escrow rail releases payment on `Ok`.
#[derive(Clone, Debug, Default)]
pub struct FheVerifier {
    settled: BTreeSet<Hash>,
}

impl FheVerifier {
    pub fn new() -> Self {
        Self {
            settled: BTreeSet::new(),
        }
    }

    pub fn verify(
        &mut self,
        task: &SignedFheTask,
        receipt: &SignedFheReceipt,
        current_height: u64,
    ) -> Result<Ciphertext, FheError> {
        task.verify()?;
        receipt.verify()?;
        let t = &task.task;
        let r = &receipt.receipt;
        if r.task != task.hash() || r.worker != t.provider {
            return Err(FheError::BindingMismatch);
        }
        if r.height > current_height {
            return Err(FheError::FutureHeight);
        }
        if r.height > t.deadline_height {
            return Err(FheError::Expired);
        }
        // The operation is public: recompute it and require an exact match.
        // A worker that skips the work or fabricates the output fails here.
        if eval(&t.op, &t.inputs)? != r.output {
            return Err(FheError::FraudulentOutput);
        }
        if !self.settled.insert(task.hash()) {
            return Err(FheError::Replay);
        }
        Ok(r.output)
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

fn decode_signed(bytes: &[u8], what: &str) -> Result<(Vec<u8>, Bundle, Bundle), FheError> {
    let err = |detail: String| FheError::Malformed(format!("{what}: {detail}"));
    let mut r = Reader::new(bytes);
    let body_len = r.u32le().map_err(malformed)? as usize;
    if body_len > 64 * 1024 {
        return Err(err("body over cap".into()));
    }
    let body = r.fixed_slice(body_len).map_err(malformed)?.to_vec();
    let sigs_len = r.u32le().map_err(malformed)? as usize;
    if sigs_len > 8 * 1024 {
        return Err(err("signature bundle over cap".into()));
    }
    let sigs = Bundle::deserialize(r.fixed_slice(sigs_len).map_err(malformed)?)
        .map_err(|e| err(e.to_string()))?;
    let keys_len = r.u32le().map_err(malformed)? as usize;
    if keys_len > 8 * 1024 {
        return Err(err("key bundle over cap".into()));
    }
    let keys = Bundle::deserialize(r.fixed_slice(keys_len).map_err(malformed)?)
        .map_err(|e| err(e.to_string()))?;
    r.expect_end().map_err(malformed)?;
    Ok((body, sigs, keys))
}

fn malformed(e: srct_core::error::Error) -> FheError {
    FheError::Malformed(e.to_string())
}
