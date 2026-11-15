//! The execution seam (SPEC.md §18.6).
//!
//! Execution is the SDK's one pluggable boundary: the operator supplies an
//! [`Executor`] (CPU worker, GPU worker, AI agent loop, external compute
//! service); the SDK routes the task's commitment hashes to it and hashes the
//! output into the result the protocol sees. Execution holds no keys, no state
//! handle and no broadcast path — isolation by type, not by convention.
//!
//! The SDK ships exactly one executor ([`CpuExecutor`]): the SPEC.md §16
//! CPU-reference shape, needed by tests and by dispute observation. Everything
//! real roots its own `Executor` impl; the SDK never interprets `ir_hash` or
//! `input_hash` (fetching off-chain IR is the operator's transport).

use srct_core::compute_ir::{ComputeBackend, ComputeTask};
use srct_core::hash::{sha256, Hash};

use srct_l2::TaskContract;

use crate::error::{WorkerError, WorkerResult};

/// The work one execution receives: commitment hashes and constraints, never
/// keys, never state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionWork {
    pub task_id: Hash,
    pub ir_hash: Hash,
    pub input_hash: Hash,
    pub required_memory_bytes: u64,
    pub backend_hint: ComputeBackend,
    pub current_height: u64,
}

impl ExecutionWork {
    /// Project from a live contract, or refuse when it is not claimable work.
    /// Only `InProgress` contracts are executable — and only before their
    /// deadline: executing an `Open` task burns electricity on work nobody
    /// claimed, and executing past expiry burns it on work nobody can
    /// submit. Both used to produce an attestation nobody would accept.
    pub fn from_contract(contract: &TaskContract, current_height: u64) -> WorkerResult<Self> {
        if !matches!(contract.state, srct_l2::ContractState::InProgress { .. }) {
            return Err(WorkerError::TaskNotAvailable("task is not in progress"));
        }
        if current_height > contract.deadline_height {
            return Err(WorkerError::TaskExpired);
        }
        let t: &ComputeTask = &contract.deliverable.0;
        Ok(ExecutionWork {
            task_id: contract.task_id,
            ir_hash: t.ir_hash,
            input_hash: t.input_hash,
            required_memory_bytes: t.required_memory_bytes,
            backend_hint: t.backend_hint,
            current_height,
        })
    }
}

/// The executor's declared capabilities, matched against a task before claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorCapabilities {
    pub backend: ComputeBackend,
    pub max_memory_bytes: u64,
}

/// What an executor produced: the raw output bytes (whose SHA-256 is the
/// protocol's `result_hash`) and the backend that ran, which MUST be one the
/// executor declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub output: Vec<u8>,
    pub backend: ComputeBackend,
}

/// Failure from inside the executor. The reason is opaque operator text; keys
/// never cross this seam, and the SDK never echoes executor output or errors
/// into protocol-visible fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecError {
    pub reason: String,
}

/// The pluggable execution engine.
pub trait Executor {
    fn capabilities(&self) -> ExecutorCapabilities;

    fn execute(&self, work: &ExecutionWork) -> Result<ExecutionOutput, ExecError>;
}

/// Run `executor` against `contract` and produce the signed-attestation-ready
/// output. Fails closed on a capability mismatch or an empty result.
pub fn execute_task<E: Executor>(
    executor: &E,
    work: &ExecutionWork,
) -> WorkerResult<ExecutionOutput> {
    let caps = executor.capabilities();
    // The executor must be able to do the job the task describes: a mismatch
    // is refused rather than downgraded (a claim on hardware that cannot run
    // the task would burn the worker's deposit through expiry, §15.4). An
    // `Unknown(hint)` task carries no class commitment, so any executor MAY
    // attempt it — that is what the wire value means (§M3).
    if work.backend_hint != ComputeBackend::Unknown(0) && caps.backend != work.backend_hint {
        return Err(WorkerError::TaskNotAvailable("backend mismatch"));
    }
    if caps.max_memory_bytes < work.required_memory_bytes {
        return Err(WorkerError::TaskNotAvailable("insufficient memory"));
    }
    let out = executor
        .execute(work)
        .map_err(|e| WorkerError::ExecutionFailed {
            backend: caps.backend.name(),
            reason: e.reason,
        })?;
    if out.output.is_empty() {
        return Err(WorkerError::EmptyResult);
    }
    Ok(out)
}

/// The SHA-256 of executor output — the `result_hash` the protocol sees.
///
/// Free-standing because it is also the disputed-side rule: a challenger
/// re-execution hashes the same way (SPEC.md §16.2).
pub fn result_hash_of(output: &[u8]) -> Hash {
    sha256(&[output])
}

/// The reference executor: the SPEC.md §16 CPU shape.
///
/// Deterministic by construction — same work, same bytes, no clock, no RNG —
/// which is what lets a challenger reproduce it. The embedded program is a
/// pure function of the task's own commitment hashes: it mixes `ir_hash` and
/// `input_hash` through a fixed permutation, so two tasks agreeing on the
/// chain produce the same result and different tasks (almost always) do not.
pub struct CpuExecutor {
    /// Memory budget the operator provisions; defaults permissive.
    pub max_memory_bytes: u64,
}

impl Default for CpuExecutor {
    fn default() -> Self {
        CpuExecutor {
            max_memory_bytes: u64::MAX,
        }
    }
}

impl Executor for CpuExecutor {
    fn capabilities(&self) -> ExecutorCapabilities {
        ExecutorCapabilities {
            backend: ComputeBackend::Cpu,
            max_memory_bytes: self.max_memory_bytes,
        }
    }

    fn execute(&self, work: &ExecutionWork) -> Result<ExecutionOutput, ExecError> {
        // The canonical CPU reference lives in `srct_core::compute_ir` — one
        // definition for worker, challenger and arbitrator (Decision 21).
        // The height this work was projected for is deliberately NOT mixed
        // in: reproducibility demands identical inputs across runs at
        // different times, and a height is never identical.
        let out = srct_core::compute_ir::reference_output(
            &work.task_id,
            &work.ir_hash,
            &work.input_hash,
            work.required_memory_bytes,
        )
        .to_vec();
        Ok(ExecutionOutput {
            output: out,
            backend: ComputeBackend::Cpu,
        })
    }
}

/// An executor that delegates to a real external AI process, command or script.
///
/// Passes task commitment parameters via environment variables and captures
/// stdout as the raw result bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecutor {
    pub backend: ComputeBackend,
    pub command: String,
    pub args: Vec<String>,
    pub max_memory_bytes: u64,
}

impl CommandExecutor {
    pub fn new(backend: ComputeBackend, command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            backend,
            command: command.into(),
            args,
            max_memory_bytes: u64::MAX,
        }
    }
}

impl Executor for CommandExecutor {
    fn capabilities(&self) -> ExecutorCapabilities {
        ExecutorCapabilities {
            backend: self.backend,
            max_memory_bytes: self.max_memory_bytes,
        }
    }

    fn execute(&self, work: &ExecutionWork) -> Result<ExecutionOutput, ExecError> {
        let mut cmd = std::process::Command::new(&self.command);
        cmd.args(&self.args);
        cmd.env("SRCT_TASK_ID", srct_core::hash::hash_to_hex(&work.task_id));
        cmd.env("SRCT_IR_HASH", srct_core::hash::hash_to_hex(&work.ir_hash));
        cmd.env(
            "SRCT_INPUT_HASH",
            srct_core::hash::hash_to_hex(&work.input_hash),
        );
        cmd.env(
            "SRCT_REQUIRED_MEMORY_BYTES",
            work.required_memory_bytes.to_string(),
        );
        cmd.env("SRCT_BACKEND", self.backend.name());

        let out = cmd.output().map_err(|e| ExecError {
            reason: format!("failed to spawn '{}': {}", self.command, e),
        })?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(ExecError {
                reason: format!("command exited with {}: {}", out.status, stderr),
            });
        }

        if out.stdout.is_empty() {
            return Err(ExecError {
                reason: "command produced empty output".into(),
            });
        }

        Ok(ExecutionOutput {
            output: out.stdout,
            backend: self.backend,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(seed: u8) -> ExecutionWork {
        ExecutionWork {
            task_id: [seed; 32],
            ir_hash: [seed.wrapping_add(1); 32],
            input_hash: [seed.wrapping_add(2); 32],
            required_memory_bytes: 1024,
            backend_hint: ComputeBackend::Cpu,
            current_height: 10,
        }
    }

    #[test]
    fn cpu_reference_is_deterministic() {
        let e = CpuExecutor::default();
        let a = e.execute(&work(7)).unwrap();
        let b = e.execute(&work(7)).unwrap();
        assert_eq!(a, b, "same work must produce the same bytes");
        let c = e.execute(&work(8)).unwrap();
        assert_ne!(a.output, c.output, "different tasks must diverge");
    }

    #[test]
    fn result_hash_is_the_sha256_of_the_output() {
        let e = CpuExecutor::default();
        let out = e.execute(&work(3)).unwrap();
        assert_eq!(result_hash_of(&out.output), sha256(&[&out.output]));
    }

    #[test]
    fn worker_output_is_the_canonical_core_reference() {
        // The SDK holds no second implementation: worker, challenger and
        // arbitrator run one definition (Decision 21).
        let e = CpuExecutor::default();
        let w = work(7);
        let out = e.execute(&w).unwrap();
        assert_eq!(
            out.output,
            srct_core::compute_ir::reference_output(
                &w.task_id,
                &w.ir_hash,
                &w.input_hash,
                w.required_memory_bytes,
            )
            .to_vec()
        );
        // ...and the height is not an input: runs at different heights agree.
        let mut later = w.clone();
        later.current_height = 99_999;
        assert_eq!(e.execute(&later).unwrap(), out);
    }

    #[test]
    fn command_executor_runs_external_task() {
        let e = CommandExecutor::new(
            ComputeBackend::Cpu,
            "python",
            vec![
                "-c".into(),
                "import os; print(f'result:{os.environ.get(\"SRCT_TASK_ID\", \"\")}')".into(),
            ],
        );
        let w = work(42);
        let out = e.execute(&w).expect("command execution should succeed");
        assert!(
            out.output.starts_with(b"result:"),
            "output must match python script output"
        );
        assert_eq!(out.backend, ComputeBackend::Cpu);
    }
}
