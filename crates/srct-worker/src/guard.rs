//! Smart Gate execution boundary for the worker SDK.
//!
//! The gate answers `allow / deny / needs_approval` for exact actions; this
//! module is where a worker turns an `allow` into running bytes. The rule is
//! the boundary rule: the action hash is recomputed from the [`ExecutionWork`]
////! the executor is *about to run* — task, IR and input commitments plus the
//! backend class — and admission is enforced before the inner executor is
//! touched. A swapped binary, a rebound input, or a forged capability denies
//! here, inside the process that would otherwise have executed it.
//!
//! The owner signs a capability over [`guard_action_preimage`] of the exact
//! work; the worker recomputes the same bytes and the gate compares hashes.
//! Callers escalate into approval-gating, never out of it; high-assurance
//! grants need the designated approver's signed approval. The local book is
//! a non-authoritative cache — the enforcing node's registry is authoritative
//! — but what this boundary refuses never executes, whichever node settles.

use srct_core::guard::{
    derive_action_hash, Decision as GuardDecision, GuardApproval, GuardBook, InfraPolicy,
    SignedCapability,
};
use srct_core::hash::Hash;

use crate::error::{WorkerError, WorkerResult};
use crate::executor::{execute_task, ExecutionOutput, ExecutionWork, Executor};

/// Domain tag for the worker execution preimage. Distinct from the gate's
/// own action tag: this names *how the worker canonicalises work*, and the
/// owner must sign capabilities over exactly these bytes.
const DOM_WORKER_ACTION: &[u8] = b"srct/worker-action/v1";

/// Canonical preimage of the work about to execute. Deterministic in the
/// inputs — no height, no clock, no RNG — so the owner's signed capability
/// and the boundary's recomputation agree bit-for-bit, and any drift in
/// task, IR, input, memory bound or backend class changes the hash.
pub fn guard_action_preimage(work: &ExecutionWork) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * 3 + 8 + 1 + DOM_WORKER_ACTION.len());
    out.extend_from_slice(DOM_WORKER_ACTION);
    out.extend_from_slice(&work.task_id);
    out.extend_from_slice(&work.ir_hash);
    out.extend_from_slice(&work.input_hash);
    out.extend_from_slice(&work.required_memory_bytes.to_le_bytes());
    out.extend_from_slice(work.backend_hint.name().as_bytes());
    out
}

/// The gate material for one admission: the owner-signed grant and capability,
/// an optional designated-approver approval, the local capability book, and
/// the identities the boundary recomputes from. The worker holds no keys —
/// signatures arrive verified-or-refused, never minted here.
pub struct GuardGate {
    /// The grant under which admission is evaluated (registry copy).
    pub policy: InfraPolicy,
    /// The owner-signed capability naming the exact action.
    pub signed: SignedCapability,
    /// The designated approver's signed approval, if fetched.
    pub approval: Option<GuardApproval>,
    /// Local capability book: window budget and consumed nonces.
    pub book: GuardBook,
    /// The agent on whose behalf the worker executes.
    pub agent_id: [u8; 20],
    /// Network the grant must name.
    pub network_id: String,
    /// Chain height the boundary observes.
    pub height: u64,
    /// Workload identity the boundary observes (ignored when the grant binds
    /// one — the bound id governs, so a spoofed presented id is harmless).
    pub workload_id: Hash,
    /// Enforcing-node scope: capabilities scoped elsewhere deny. The local
    /// cache is unscoped, so scoped capabilities belong to their node.
    pub node_audience: Hash,
    /// Caller escalation only: `true` requests approval-gating on a
    /// low-assurance grant. A `false` here never de-escalates a high-assurance
    /// grant — that bit lives in the policy.
    pub escalate_to_approval: bool,
}

impl GuardGate {
    /// Admit `work` through the gate, then run it. The preimage is recomputed
    /// from the work the executor is about to receive; on `Allow` the inner
    /// executor runs untouched, otherwise nothing executes and no nonce is
    /// consumed.
    pub fn execute<E: Executor>(
        &mut self,
        executor: &E,
        work: &ExecutionWork,
    ) -> WorkerResult<ExecutionOutput> {
        let preimage = guard_action_preimage(work);
        match self.book.authorize_signed(
            &self.policy,
            &self.signed,
            &self.agent_id,
            &self.network_id,
            self.height,
            &preimage,
            &self.workload_id,
            &self.node_audience,
            self.escalate_to_approval,
            self.approval.as_ref(),
        ) {
            GuardDecision::Allow => execute_task(executor, work),
            GuardDecision::NeedsApproval => Err(WorkerError::GuardApprovalNeeded),
            GuardDecision::Deny(e) => Err(WorkerError::GuardDenied(e.to_string())),
        }
    }
}

/// Convenience: the canonical action hash of work about to execute, for owner
/// tooling that signs capabilities over [`guard_action_preimage`].
pub fn guard_action_hash(work: &ExecutionWork) -> Hash {
    derive_action_hash(&guard_action_preimage(work))
}

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::agent::{derive_agent_id, AgentRole};
    use srct_core::compute_ir::ComputeBackend;
    use srct_core::guard::{derive_context_hash, Capability, InfraPolicy, GUARD_POLICY_VERSION};
    use srct_core::wallet::Wallet;

    fn test_work() -> ExecutionWork {
        ExecutionWork {
            task_id: [1u8; 32],
            ir_hash: [2u8; 32],
            input_hash: [3u8; 32],
            required_memory_bytes: 1024,
            backend_hint: ComputeBackend::Cpu,
            current_height: 10,
        }
    }

    fn owner_and_policy(assured: bool) -> (Wallet, Option<Wallet>, InfraPolicy) {
        let owner = Wallet::new_random("gate-owner");
        let addr = owner.address().unwrap();
        let approver = if assured {
            Some(Wallet::new_random("gate-approver"))
        } else {
            None
        };
        let policy = InfraPolicy {
            version: GUARD_POLICY_VERSION,
            network_id: "srct/testnet".to_string(),
            agent_id: derive_agent_id("srct/testnet", AgentRole::Machine, &addr),
            owner: addr,
            max_calls_per_window: 5,
            window_blocks: 100,
            valid_from_height: 0,
            valid_until_height: 10_000,
            revoked: false,
            parent_agent_id: None,
            requires_approval: assured,
            approver: approver
                .as_ref()
                .map(|w: &Wallet| w.address().unwrap())
                .unwrap_or([0u8; 20]),
            workload_id: [0u8; 32],
        };
        (owner, approver, policy)
    }

    fn gate_for(
        owner: &Wallet,
        approver: &Option<Wallet>,
        policy: &InfraPolicy,
        preimage_sign: &[u8],
        approval: bool,
    ) -> GuardGate {
        let workload = [4u8; 32];
        let cap = Capability {
            policy_hash: policy.hash(),
            action_hash: derive_action_hash(preimage_sign),
            context_hash: derive_context_hash(&workload, 50),
            expiry_height: 60,
            nonce: 1,
            audience: [0u8; 32],
        };
        let signed = SignedCapability::issue(owner, &cap).unwrap();
        let approval = if approval {
            let signer = approver.as_ref().unwrap();
            let draft = GuardApproval {
                version: GUARD_POLICY_VERSION,
                policy_hash: policy.hash(),
                cap_hash: cap.signing_hash(),
                agent_id: policy.agent_id,
                action_hash: derive_action_hash(preimage_sign),
                context_hash: derive_context_hash(&workload, 50),
                expiry_height: 55,
                sigs: srct_core::sig::Bundle::default(),
                keys: srct_core::sig::Bundle::default(),
            };
            Some(GuardApproval {
                sigs: srct_core::l2::Auth::sigs_for(signer, &draft.signing_hash()).unwrap(),
                keys: srct_core::l2::Auth::keys_for(signer).unwrap(),
                ..draft
            })
        } else {
            None
        };
        GuardGate {
            policy: policy.clone(),
            signed,
            approval,
            book: GuardBook::default(),
            agent_id: policy.agent_id,
            network_id: "srct/testnet".to_string(),
            height: 50,
            workload_id: workload,
            node_audience: [0u8; 32],
            escalate_to_approval: false,
        }
    }

    #[test]
    fn exact_work_executes_and_drift_refuses() {
        use crate::executor::CpuExecutor;
        let (owner, approver, policy) = owner_and_policy(false);
        let work = test_work();
        let preimage = guard_action_preimage(&work);
        let mut gate = gate_for(&owner, &approver, &policy, &preimage, false);
        let out = gate
            .execute(&CpuExecutor::default(), &work)
            .expect("exact work executes");
        assert!(!out.output.is_empty());

        // Drifted work (rebound input): the same capability no longer admits.
        let mut drifted = work.clone();
        drifted.input_hash = [9u8; 32];
        let mut gate2 = gate_for(&owner, &approver, &policy, &preimage, false);
        let err = gate2
            .execute(&CpuExecutor::default(), &drifted)
            .expect_err("drifted work must refuse");
        assert!(
            matches!(err, WorkerError::GuardDenied(_)),
            "unexpected: {err}"
        );
        assert!(
            gate2.book.is_empty(),
            "a refused execution consumes no nonce"
        );
    }

    #[test]
    fn high_assurance_work_gates_then_admits_with_approver() {
        use crate::executor::CpuExecutor;
        let (owner, approver, policy) = owner_and_policy(true);
        let work = test_work();
        let preimage = guard_action_preimage(&work);
        let mut gated = gate_for(&owner, &approver, &policy, &preimage, false);
        assert_eq!(
            gated.execute(&CpuExecutor::default(), &work),
            Err(WorkerError::GuardApprovalNeeded)
        );
        let mut admitted = gate_for(&owner, &approver, &policy, &preimage, true);
        admitted
            .execute(&CpuExecutor::default(), &work)
            .expect("designated approval admits");
    }
}
