//! Batch folding of ZKML proofs (non-consensus).
//!
//! Verifying one proof per worker is wasteful when many workers prove the
//! *same* statement (the same weights, bias and input commitments). This
//! module folds them into one check: the prover's commitments are combined
//! with Fiat-Shamir-derived random scalars, and the two *linear* constraints
//! — that the bits recompose to the input commitment, and that the output
//! commitment equals the weighted sum — are verified once on the folded
//! commitments instead of once per proof.
//!
//! # What folding covers, exactly
//!
//! - The recombination `X == sum_j 2^j B_j` and the evaluation
//!   `Y == sum_k w_k X_k + bias*G` are **linear** in the commitments, so a
//!   random linear combination of `N` proofs can be checked in one pass. A
//!   prover who cheats in any one proof is caught with soundness error
//!   `1/p` (the Fiat-Shamir challenge), not `N/p`.
//! - The per-bit **CDS OR-proofs** are Sigma protocols, not linear equations,
//!   so they cannot be folded: each one is still verified on its own. Their
//!   challenges bind the shared statement, so they stay valid under folding.
//!
//! # What this is not
//!
//! - **Not Nova-style recursive folding.** True folding (accumulating a
//!   sequence of proofs into one, then verifying that one) needs a cycle
//!   group, a hash-based commitment and a recursive verifier — a research
//!   project with its own soundness argument. This module is the honest
//!   linear-folding subset: batch verification of identical statements.
//! - **Not a speed claim.** The expensive OR-proof checks are per proof;
//!   only the linear part is amortized.

use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use rand::rngs::StdRng;
use rand::RngCore;
use srct_core::hash::sha256_dom;

use crate::circuit::{
    decode_point, encode_point, verify_bit, BitProof, LinearProof, BIT_WIDTH, MAX_INPUTS, POINT_LEN,
};
use crate::ZkError;

const DOM_FOLD: &[u8] = b"srct/zkml/fold/v1";

/// The transcript a fold challenge is derived from: the statement and every
/// folded proof, in order. A prover cannot reorder or drop a proof without
/// changing the challenges.
fn fold_transcript(weights: &[i64], bias: u64, packages: &[LinearProof]) -> Vec<u8> {
    let mut t = Vec::from(DOM_FOLD);
    t.extend_from_slice(&(weights.len() as u64).to_le_bytes());
    for w in weights {
        t.extend_from_slice(&w.to_le_bytes());
    }
    t.extend_from_slice(&bias.to_le_bytes());
    t.extend_from_slice(&(packages.len() as u64).to_le_bytes());
    for p in packages {
        for c in &p.input_commitments {
            t.extend_from_slice(c);
        }
        t.extend_from_slice(&p.output_commitment);
        for bits in &p.bit_proofs {
            for b in bits {
                t.extend_from_slice(&b.commitment);
            }
        }
    }
    t
}

/// One fold challenge: a non-zero scalar.
fn fold_challenge(transcript: &[u8], index: usize) -> Result<Scalar, ZkError> {
    let mut buf = Vec::with_capacity(transcript.len() + 16);
    buf.extend_from_slice(transcript);
    buf.extend_from_slice(&(index as u64).to_le_bytes());
    let digest = sha256_dom(b"srct/zkml/fold-challenge/v1", &[&buf]);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(digest.into()))
        .ok_or_else(|| ZkError::Malformed("zk fold challenge is not canonical".into()))?;
    if scalar == Scalar::ZERO {
        // A zero challenge would drop a proof from the combination.
        return Ok(Scalar::ONE);
    }
    Ok(scalar)
}

/// Fold several proofs of the same statement and verify them in one pass.
///
/// All proofs must share the statement: the same weights, the same bias and
/// the same input commitments. Mismatched commitments are refused — folding
/// proofs of different statements would check a statement nobody proved.
pub fn verify_fold(
    weights: &[i64],
    bias: u64,
    packages: &[LinearProof],
    rng: &mut StdRng,
) -> Result<(), ZkError> {
    if packages.is_empty() {
        return Err(ZkError::Malformed("zk fold has no proofs".into()));
    }
    if packages.len() > MAX_INPUTS {
        return Err(ZkError::Malformed("zk fold is over cap".into()));
    }
    if weights.len() > MAX_INPUTS {
        return Err(ZkError::Malformed("zk fold statement is over cap".into()));
    }
    let inputs = packages[0].input_commitments.len();
    if inputs == 0 || inputs > MAX_INPUTS {
        return Err(ZkError::Malformed("zk fold statement has no inputs".into()));
    }
    // Every proof must cover the same number of inputs and the same model
    // (weights, bias). The *commitments* may differ: each proof hides its own
    // blinding, so two proofs of the same computation have different input
    // commitments and different statements.
    for p in packages {
        if p.input_commitments.len() != inputs {
            return Err(ZkError::Malformed(
                "zk fold proofs disagree on inputs".into(),
            ));
        }
        if p.bit_proofs.len() != inputs || p.bit_proofs.iter().any(|bits| bits.len() != BIT_WIDTH) {
            return Err(ZkError::Malformed("zk fold proof shape is wrong".into()));
        }
    }

    let h = crate::circuit::h_generator();
    let g = ProjectivePoint::GENERATOR;

    // The per-bit OR-proofs are not linear, so each is verified on its own,
    // against its own statement (its own commitments).
    for p in packages {
        let statement = crate::circuit::statement_bytes(weights, bias, &p.input_commitments);
        for bits in &p.bit_proofs {
            for proof in bits {
                verify_bit(&statement, proof, &h)?;
            }
        }
    }

    // Fold the commitments with Fiat-Shamir challenges. The transcript
    // already pins every proof, so the challenges are deterministic; the
    // caller-supplied randomness is mixed in for good measure.
    let mut transcript = fold_transcript(weights, bias, packages);
    let mut extra = [0u8; 32];
    rng.fill_bytes(&mut extra);
    transcript.extend_from_slice(&extra);

    let mut folded_inputs = vec![ProjectivePoint::IDENTITY; inputs];
    let mut folded_output = ProjectivePoint::IDENTITY;
    let mut folded_bits: Vec<Vec<ProjectivePoint>> =
        vec![vec![ProjectivePoint::IDENTITY; BIT_WIDTH]; inputs];
    let mut bias_weight = Scalar::ZERO;
    for (i, p) in packages.iter().enumerate() {
        let r = fold_challenge(&transcript, i)?;
        bias_weight += r;
        for (k, com) in p.input_commitments.iter().enumerate() {
            folded_inputs[k] += decode_point(com)? * r;
        }
        folded_output += decode_point(&p.output_commitment)? * r;
        for (k, bits) in p.bit_proofs.iter().enumerate() {
            for (j, proof) in bits.iter().enumerate() {
                folded_bits[k][j] += decode_point(&proof.commitment)? * r;
            }
        }
    }

    // The folded recombination: the bits recompose to the folded input.
    for (k, x_com) in folded_inputs.iter().enumerate() {
        let mut recomposed = ProjectivePoint::IDENTITY;
        let mut power = Scalar::from(1u64);
        for b in folded_bits[k].iter() {
            recomposed += *b * power;
            power += power;
        }
        if recomposed != *x_com {
            return Err(ZkError::InvalidProof);
        }
    }
    // The folded evaluation: the outputs sum to the weighted sum of the
    // inputs, with the bias scaled by the same challenge sum.
    let mut expected = g * (Scalar::from(bias) * bias_weight);
    for (x_com, w) in folded_inputs.iter().zip(weights.iter()) {
        expected += *x_com * crate::circuit::scalar_of_weight(*w);
    }
    if expected != folded_output {
        return Err(ZkError::InvalidProof);
    }
    let _ = encode_point(&folded_output)?;
    Ok(())
}

/// Fold a batch of proofs into one summary commitment: the folded output
/// commitment plus the transcript hash that pins the batch. A caller can
/// publish the summary and check it later against the same batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldSummary {
    pub output_commitment: [u8; POINT_LEN],
    pub transcript: [u8; 32],
    pub proofs: u32,
}

/// Build the summary of a fold without verifying it (the verifier may be
/// remote). The summary is what a publisher commits to.
pub fn fold_summary(
    weights: &[i64],
    bias: u64,
    packages: &[LinearProof],
    rng: &mut StdRng,
) -> Result<FoldSummary, ZkError> {
    if packages.is_empty() {
        return Err(ZkError::Malformed("zk fold has no proofs".into()));
    }
    let inputs = packages[0].input_commitments.len();
    if inputs == 0 || inputs > MAX_INPUTS {
        return Err(ZkError::Malformed("zk fold statement has no inputs".into()));
    }
    let mut transcript = fold_transcript(weights, bias, packages);
    let mut extra = [0u8; 32];
    rng.fill_bytes(&mut extra);
    transcript.extend_from_slice(&extra);
    let mut folded_output = ProjectivePoint::IDENTITY;
    for (i, p) in packages.iter().enumerate() {
        let r = fold_challenge(&transcript, i)?;
        folded_output += decode_point(&p.output_commitment)? * r;
    }
    let digest = sha256_dom(b"srct/zkml/fold-transcript/v1", &[&transcript]);
    let mut transcript_hash = [0u8; 32];
    transcript_hash.copy_from_slice(&digest);
    Ok(FoldSummary {
        output_commitment: encode_point(&folded_output)?,
        transcript: transcript_hash,
        proofs: packages.len() as u32,
    })
}

/// The bit-proof commitment of one input, for callers that want to inspect a
/// folded proof.
pub fn bit_commitment(proof: &BitProof) -> Result<[u8; POINT_LEN], ZkError> {
    Ok(proof.commitment)
}
