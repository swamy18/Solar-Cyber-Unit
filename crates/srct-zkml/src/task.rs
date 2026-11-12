//! Signed ZKML tasks and worker receipts.
//!
//! The requester signs a task binding the network, provider, public model
//! (weights/bias), the input commitments and a deadline. The worker proves
//! evaluation and signs a receipt carrying the bit-proofs and the output
//! commitment. Verification is signatures, bindings and deadline first, then
//! the zero-knowledge checks, then the replay book.

use std::collections::BTreeSet;

use srct_core::agent::MAX_NETWORK_ID_LEN;
use srct_core::hash::{sha256_dom, Address, Hash};
use srct_core::l2::Auth;
use srct_core::ser::{Reader, Writer};
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::circuit::{
    verify_linear, BitProof, LinearProof, BIT_WIDTH, MAX_INPUTS, MAX_WEIGHT_ABS, POINT_LEN,
};
use crate::ZkError;

pub const ZK_VERSION: u8 = 1;
/// One bit-proof on the wire: 3 points + 4 scalars.
pub const BIT_PROOF_LEN: usize = 3 * POINT_LEN + 4 * 32;

const DOM_ZK_TASK: &[u8] = b"srct/zkml/task/v1";
const DOM_ZK_RECEIPT: &[u8] = b"srct/zkml/receipt/v1";

/// A requester-signed ZKML task. Weights and bias are public (the proof is
/// about the private inputs); the commitments bind them to this task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkTask {
    pub version: u8,
    pub network_id: String,
    pub requester: Address,
    pub provider: Address,
    pub weights: Vec<i64>,
    pub bias: u64,
    pub input_commitments: Vec<[u8; POINT_LEN]>,
    pub deadline_height: u64,
    pub nonce: u64,
}

impl ZkTask {
    fn validate(&self) -> Result<(), ZkError> {
        if self.version != ZK_VERSION {
            return Err(ZkError::Malformed(format!(
                "unsupported zk task version {}",
                self.version
            )));
        }
        if self.network_id.is_empty() || self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ZkError::Malformed("zk task network id length".into()));
        }
        if self.weights.len() != self.input_commitments.len() {
            return Err(ZkError::Malformed(
                "zk weights must match the input commitments".into(),
            ));
        }
        if self.weights.is_empty() || self.weights.len() > MAX_INPUTS {
            return Err(ZkError::Malformed("zk input count out of range".into()));
        }
        if self.weights.iter().any(|w| w.abs() > MAX_WEIGHT_ABS) {
            return Err(ZkError::Malformed("zk weight exceeds the cap".into()));
        }
        if self.deadline_height == 0 {
            return Err(ZkError::Malformed("zk task deadline is zero".into()));
        }
        if self.nonce == 0 {
            return Err(ZkError::Malformed("zk task nonce is zero".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256 + (POINT_LEN + 8) * self.input_commitments.len());
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.requester)
            .fixed(&self.provider)
            .u16le(self.weights.len() as u16);
        for weight in &self.weights {
            w.u64le(*weight as u64);
        }
        w.u64le(self.bias);
        for com in &self.input_commitments {
            w.raw(com);
        }
        w.u64le(self.deadline_height).u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_ZK_TASK, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ZkError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let net_len = r.u16le().map_err(malformed)? as usize;
        if net_len == 0 || net_len > MAX_NETWORK_ID_LEN {
            return Err(ZkError::Malformed("zk task network id length".into()));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(net_len).map_err(malformed)?)
            .map_err(|_| ZkError::Malformed("zk task network is not utf-8".into()))?
            .to_string();
        let requester = r.fixed().map_err(malformed)?;
        let provider = r.fixed().map_err(malformed)?;
        let count = r.u16le().map_err(malformed)? as usize;
        if count == 0 || count > MAX_INPUTS {
            return Err(ZkError::Malformed("zk input count out of range".into()));
        }
        let mut weights = Vec::with_capacity(count);
        for _ in 0..count {
            let weight = r.u64le().map_err(malformed)? as i64;
            if weight.abs() > MAX_WEIGHT_ABS {
                return Err(ZkError::Malformed("zk weight exceeds the cap".into()));
            }
            weights.push(weight);
        }
        let bias = r.u64le().map_err(malformed)?;
        let mut input_commitments = Vec::with_capacity(count);
        for _ in 0..count {
            let mut com = [0u8; POINT_LEN];
            com.copy_from_slice(r.fixed_slice(POINT_LEN).map_err(malformed)?);
            input_commitments.push(com);
        }
        let deadline_height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let task = ZkTask {
            version,
            network_id,
            requester,
            provider,
            weights,
            bias,
            input_commitments,
            deadline_height,
            nonce,
        };
        task.validate()?;
        Ok(task)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedZkTask {
    pub task: ZkTask,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedZkTask {
    pub fn sign(task: ZkTask, requester: &Wallet) -> Result<Self, ZkError> {
        task.validate()?;
        let address = requester
            .address()
            .map_err(|e| ZkError::BadSignature(e.to_string()))?;
        if address != task.requester {
            return Err(ZkError::WrongRequester);
        }
        let auth = Auth::sign(requester, &task.hash())
            .map_err(|e| ZkError::BadSignature(e.to_string()))?;
        Ok(SignedZkTask {
            task,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self) -> Result<(), ZkError> {
        self.task.validate()?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ZkError::BadSignature(e.to_string()))?;
        if signer != self.task.requester {
            return Err(ZkError::WrongRequester);
        }
        verify_bundle(&self.sigs, &self.keys, &self.task.hash())
            .map_err(|e| ZkError::BadSignature(e.to_string()))
    }

    pub fn hash(&self) -> Hash {
        self.task.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.task.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ZkError> {
        let (body, sigs, keys) = decode_signed(bytes, "zk task")?;
        let task = ZkTask::decode(&body)?;
        let signed = SignedZkTask { task, sigs, keys };
        signed.verify()?;
        Ok(signed)
    }
}

/// A worker-signed receipt carrying the bit-proofs and output commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkReceipt {
    pub version: u8,
    pub task: Hash,
    pub worker: Address,
    pub bit_proofs: Vec<Vec<BitProof>>,
    pub output_commitment: [u8; POINT_LEN],
    pub height: u64,
    pub nonce: u64,
}

impl ZkReceipt {
    fn validate(&self, n_inputs: usize) -> Result<(), ZkError> {
        if self.version != ZK_VERSION {
            return Err(ZkError::Malformed(format!(
                "unsupported zk receipt version {}",
                self.version
            )));
        }
        if self.task == [0u8; 32] {
            return Err(ZkError::Malformed("zk receipt task hash is zero".into()));
        }
        if self.bit_proofs.len() != n_inputs
            || self.bit_proofs.iter().any(|bits| bits.len() != BIT_WIDTH)
        {
            return Err(ZkError::Malformed("zk bit proof shape is wrong".into()));
        }
        if self.nonce == 0 {
            return Err(ZkError::Malformed("zk receipt nonce is zero".into()));
        }
        Ok(())
    }

    pub fn package(&self, input_commitments: &[[u8; POINT_LEN]]) -> LinearProof {
        LinearProof {
            input_commitments: input_commitments.to_vec(),
            bit_proofs: self.bit_proofs.clone(),
            output_commitment: self.output_commitment,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            160 + self.bit_proofs.len() * BIT_WIDTH * BIT_PROOF_LEN + POINT_LEN,
        );
        w.u8(self.version)
            .fixed(&self.task)
            .fixed(&self.worker)
            .u16le(self.bit_proofs.len() as u16);
        for bits in &self.bit_proofs {
            for proof in bits {
                proof.encode(&mut w);
            }
        }
        w.raw(&self.output_commitment)
            .u64le(self.height)
            .u64le(self.nonce);
        w.into_vec()
    }

    fn hash(&self) -> Hash {
        sha256_dom(DOM_ZK_RECEIPT, &[&self.encode()])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ZkError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        let task = r.fixed().map_err(malformed)?;
        let worker = r.fixed().map_err(malformed)?;
        let n_inputs = r.u16le().map_err(malformed)? as usize;
        if n_inputs == 0 || n_inputs > MAX_INPUTS {
            return Err(ZkError::Malformed("zk input count out of range".into()));
        }
        let mut bit_proofs = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            let mut bits = Vec::with_capacity(BIT_WIDTH);
            for _ in 0..BIT_WIDTH {
                bits.push(BitProof::decode(&mut r)?);
            }
            bit_proofs.push(bits);
        }
        let mut output_commitment = [0u8; POINT_LEN];
        output_commitment.copy_from_slice(r.fixed_slice(POINT_LEN).map_err(malformed)?);
        let height = r.u64le().map_err(malformed)?;
        let nonce = r.u64le().map_err(malformed)?;
        r.expect_end().map_err(malformed)?;
        let receipt = ZkReceipt {
            version,
            task,
            worker,
            bit_proofs,
            output_commitment,
            height,
            nonce,
        };
        receipt.validate(n_inputs)?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedZkReceipt {
    pub receipt: ZkReceipt,
    pub sigs: Bundle,
    pub keys: Bundle,
}

impl SignedZkReceipt {
    pub fn sign(receipt: ZkReceipt, n_inputs: usize, worker: &Wallet) -> Result<Self, ZkError> {
        receipt.validate(n_inputs)?;
        let address = worker
            .address()
            .map_err(|e| ZkError::BadSignature(e.to_string()))?;
        if address != receipt.worker {
            return Err(ZkError::WrongWorker);
        }
        let auth = Auth::sign(worker, &receipt.hash())
            .map_err(|e| ZkError::BadSignature(e.to_string()))?;
        Ok(SignedZkReceipt {
            receipt,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    pub fn verify(&self, n_inputs: usize) -> Result<(), ZkError> {
        self.receipt.validate(n_inputs)?;
        let signer = self
            .keys
            .address()
            .map_err(|e| ZkError::BadSignature(e.to_string()))?;
        if signer != self.receipt.worker {
            return Err(ZkError::WrongWorker);
        }
        verify_bundle(&self.sigs, &self.keys, &self.receipt.hash())
            .map_err(|e| ZkError::BadSignature(e.to_string()))
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.receipt.encode(), &self.sigs, &self.keys)
    }

    pub fn decode(bytes: &[u8], n_inputs: usize) -> Result<Self, ZkError> {
        let (body, sigs, keys) = decode_signed(bytes, "zk receipt")?;
        let receipt = ZkReceipt::decode(&body)?;
        let signed = SignedZkReceipt {
            receipt,
            sigs,
            keys,
        };
        signed.verify(n_inputs)?;
        Ok(signed)
    }
}

/// Fail-closed verifier: signatures, bindings, deadline, then the
/// zero-knowledge checks, then the replay book. Returns the accepted output
/// commitment; the escrow rail releases payment on `Ok`.
#[derive(Clone, Debug, Default)]
pub struct ZkVerifier {
    settled: BTreeSet<Hash>,
}

impl ZkVerifier {
    pub fn new() -> Self {
        Self {
            settled: BTreeSet::new(),
        }
    }

    pub fn verify(
        &mut self,
        task: &SignedZkTask,
        receipt: &SignedZkReceipt,
        current_height: u64,
    ) -> Result<[u8; POINT_LEN], ZkError> {
        task.verify()?;
        let n_inputs = task.task.input_commitments.len();
        receipt.verify(n_inputs)?;
        let t = &task.task;
        let r = &receipt.receipt;
        if r.task != task.hash() || r.worker != t.provider {
            return Err(ZkError::BindingMismatch);
        }
        if r.bit_proofs.len() != n_inputs {
            return Err(ZkError::BindingMismatch);
        }
        if r.height > current_height {
            return Err(ZkError::FutureHeight);
        }
        if r.height > t.deadline_height {
            return Err(ZkError::Expired);
        }
        verify_linear(&t.weights, t.bias, &r.package(&t.input_commitments))?;
        if !self.settled.insert(task.hash()) {
            return Err(ZkError::Replay);
        }
        Ok(r.output_commitment)
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

fn decode_signed(bytes: &[u8], what: &str) -> Result<(Vec<u8>, Bundle, Bundle), ZkError> {
    let err = |detail: String| ZkError::Malformed(format!("{what}: {detail}"));
    let mut r = Reader::new(bytes);
    let body_len = r.u32le().map_err(malformed)? as usize;
    if body_len > 256 * 1024 {
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

fn malformed(e: srct_core::error::Error) -> ZkError {
    ZkError::Malformed(e.to_string())
}
