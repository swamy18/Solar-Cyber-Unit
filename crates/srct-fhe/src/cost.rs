//! Measured-cost pricing for encrypted-compute tasks (non-consensus).
//!
//! [`crate::task::eval`] is public and deterministic: one bias encryption,
//! one scalar multiplication per input and one addition per input. This module
//! turns those exact operation counts into a priced cost the escrow rail can
//! charge before the worker runs. The constants are prototype policy, not
//! measured silicon — they are pinned here so quotes are reproducible, and
//! re-tuning them is a one-line change with a test update.

use crate::task::WeightedSum;
use crate::FheError;

/// Flat task overhead in cost units (decode, signature checks, binding).
pub const COST_BASE: u64 = 50;
/// Cost of one scalar multiplication (one per input).
pub const COST_SCALAR_MUL: u64 = 20;
/// Cost of one homomorphic addition (one per input).
pub const COST_ADD: u64 = 10;

/// Exact operation cost of evaluating `op`, in cost units.
///
/// `COST_BASE + inputs * (COST_SCALAR_MUL + COST_ADD)`. Fails closed on a
/// malformed op, exactly like [`crate::task::eval`] would.
pub fn task_cost(op: &WeightedSum) -> Result<u64, FheError> {
    if op.weights.is_empty() || op.weights.len() > crate::task::MAX_INPUTS {
        return Err(FheError::Malformed("fhe input count out of range".into()));
    }
    if op
        .weights
        .iter()
        .any(|w| w.abs() > crate::task::MAX_WEIGHT_ABS)
    {
        return Err(FheError::Malformed("fhe weight exceeds the cap".into()));
    }
    Ok(COST_BASE + op.weights.len() as u64 * (COST_SCALAR_MUL + COST_ADD))
}

/// Price a task in satoshis at `unit_price_sat` per cost unit.
/// Refuses overflow instead of wrapping.
pub fn price_task(op: &WeightedSum, unit_price_sat: u64) -> Result<u64, FheError> {
    let cost = task_cost(op)?;
    cost.checked_mul(unit_price_sat)
        .ok_or_else(|| FheError::Malformed("fhe task price overflows".into()))
}

/// Largest plaintext the weighted sum can produce when every input is at
/// most `max_input`: `bias + Σ |w| * max_input`, checked exactly.
///
/// Arithmetic here is modulo the curve order and decryption searches
/// `[0, decode_bound)` — a sum past the bound wraps silently and decrypts to
/// the wrong value. The rail pins `max_input` per task profile and refuses
/// evaluation whose worst case exceeds the bound it will decrypt with.
pub fn max_output(op: &WeightedSum, max_input: u64) -> Result<u64, FheError> {
    if op.weights.is_empty() || op.weights.len() > crate::task::MAX_INPUTS {
        return Err(FheError::Malformed("fhe input count out of range".into()));
    }
    if op
        .weights
        .iter()
        .any(|w| w.abs() > crate::task::MAX_WEIGHT_ABS)
    {
        return Err(FheError::Malformed("fhe weight exceeds the cap".into()));
    }
    let mut total = op.bias;
    for w in &op.weights {
        let term = (w.unsigned_abs())
            .checked_mul(max_input)
            .ok_or_else(|| FheError::Malformed("fhe bound overflows".into()))?;
        total = total
            .checked_add(term)
            .ok_or_else(|| FheError::Malformed("fhe bound overflows".into()))?;
    }
    Ok(total)
}

/// Evaluate only when the worst case fits the decryption bound. Fails closed
/// before any ciphertext work: an over-bound sum would decrypt to a wrong
/// value, and a wrong value must never reach a receipt.
pub fn eval_bounded(
    op: &WeightedSum,
    inputs: &[crate::Ciphertext],
    max_input: u64,
    decode_bound: u64,
) -> Result<crate::Ciphertext, FheError> {
    if max_output(op, max_input)? > decode_bound {
        return Err(FheError::Malformed(
            "fhe worst-case output exceeds the decode bound".into(),
        ));
    }
    crate::task::eval(op, inputs)
}
