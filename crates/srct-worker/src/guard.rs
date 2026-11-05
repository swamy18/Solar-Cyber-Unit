//! Smart Gate execution boundary for the worker SDK.
//!
//! The gate answers `allow / deny / needs_approval` for exact actions; this
//! module is where a worker turns an `allow` into running bytes. The rule is
//! the boundary rule: the action hash is recomputed from the [`ExecutionWork`]
//! the executor is *about to run* — task, IR and input commitments plus the
//! backend class — and admission is enforced before the inner executor is
//! touched. A swapped binary, a rebound input, or a forged capability denies
//! here, inside the process that would otherwise have executed it.
//!
//! The owner signs a capability over [`guard_action_preimage`] of the exact
//! work; the worker recomputes the same bytes and the gate compares hashes.
//! Callers escalate into approval-gating, never out of it; high-assurance
//! grants need the designated approver's signed approval. The local book is
//! a non-authoritative cache — the enforcing node's registry is authoritative
//! — which is why every execution first asks the authority whether the grant
//! is still good, and refuses when the authority cannot be reached. Refusal
//! also forgets the grant's local accounting, so stale state can never be
//! replayed back into use.

use srct_core::guard::{
    derive_action_hash, workload_key_fingerprint, Decision as GuardDecision, GuardApproval,
    GuardBook, InfraPolicy, SignedCapability, WorkloadCredential,
};
use srct_core::hash::{hash_to_hex, Hash};

use crate::error::{WorkerError, WorkerResult};
use crate::executor::{execute_task, ExecutionOutput, ExecutionWork, Executor};
use crate::http::HttpNode;

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

/// What the authority said about one admission, right now. `Fresh` means the
/// grant is live at the authority (or needs an approval the local gate will
/// still enforce); `Stale` carries the authority's named reason. Transport or
/// decode failures are not a variant: they surface as `Err`, and `Err` never
/// executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale(String),
}

/// The authoritative revocation source consulted at the execution boundary.
/// The local book stops replays it has seen; only the authority knows about
/// revocations issued elsewhere. Implementations MUST fail closed: `Err`
/// means "unknown", and unknown never executes. There is deliberately no
/// "allow on unreachable" mode and no cached-allow fallback — a worker cut
/// off from its authority stops executing gated work instead of running on
/// stale permission.
pub trait RevocationAuthority {
    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        policy: &InfraPolicy,
        signed: &SignedCapability,
        agent_id: &[u8; 20],
        network_id: &str,
        height: u64,
        action_hash: &Hash,
        workload_id: &Hash,
        escalate_to_approval: bool,
    ) -> WorkerResult<Freshness>;
}

/// Freshness via the enforcing node's stateless `POST /v1/guard/decide`: one
/// round trip that re-verifies signature, risk model, revocation set,
/// validity, binding and audience at the authority's current height. No new
/// endpoint, no new trust root — the same read path operators already use.
pub struct NodeDecideAuthority {
    /// Node HTTP client (loopback by default; see [`HttpNode`]).
    pub http: HttpNode,
}

impl NodeDecideAuthority {
    pub fn new(http: HttpNode) -> Self {
        NodeDecideAuthority { http }
    }
}

impl RevocationAuthority for NodeDecideAuthority {
    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        policy: &InfraPolicy,
        signed: &SignedCapability,
        agent_id: &[u8; 20],
        _network_id: &str,
        _height: u64,
        action_hash: &Hash,
        workload_id: &Hash,
        escalate_to_approval: bool,
    ) -> WorkerResult<Freshness> {
        use serde_json::json;
        let body = json!({
            "policy_hex": hex::encode(policy.serialize()),
            "cap_hex": hex::encode(signed.serialize()),
            "agent_id_hex": hex::encode(agent_id),
            "action_hash_hex": hash_to_hex(action_hash),
            "workload_id_hex": hash_to_hex(workload_id),
            "high_risk": escalate_to_approval,
        });
        let answer = self.http.post_json("/v1/guard/decide", &body)?;
        match answer.get("decision").and_then(|d| d.as_str()) {
            Some("allow") | Some("needs_approval") => Ok(Freshness::Fresh),
            Some("deny") => Ok(Freshness::Stale(
                answer
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .unwrap_or("denied at authority")
                    .to_string(),
            )),
            _ => Err(WorkerError::ObservationMalformed(
                "authority answer has no decision",
            )),
        }
    }
}

/// The gate material for one admission: the owner-signed grant and capability,
/// an optional designated-approver approval, the local capability book, the
/// identities the boundary recomputes from, and the mandatory authoritative
/// revocation source. The worker holds no grant keys — grant signatures
/// arrive verified-or-refused, never minted here. It *does* hold the workload
/// identity key (when the grant binds one): possession is proved fresh at
/// every execution, never replayed from an old credential.
pub struct GuardGate {
    /// The grant under which admission is evaluated (registry copy).
    pub policy: InfraPolicy,
    /// The owner-signed capability naming the exact action.
    pub signed: SignedCapability,
    /// The designated approver's signed approval, if fetched.
    pub approval: Option<GuardApproval>,
    /// Local capability book: window budget and consumed nonces.
    /// Non-authoritative: a cache, never the source of truth.
    pub book: GuardBook,
    /// Mandatory freshness source. Consulted on EVERY execution, before the
    /// local book and before the executor. Unreachable means unknown, and
    /// unknown never executes — there is no offline fallback.
    pub authority: Box<dyn RevocationAuthority>,
    /// Workload identity key that signs the per-execution possession proof.
    /// Required when the grant binds a workload key; ignored otherwise.
    pub workload_wallet: Option<srct_core::wallet::Wallet>,
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
    /// Admit `work` through the gate, then run it, in this order:
    ///
    /// 1. Recompute the action preimage from the work about to run.
    /// 2. Ask the authority whether the grant is still good. A `Stale`
    ///    answer forgets the grant's local accounting (so stale state can
    ///    never be replayed back) and denies. An unreachable authority
    ///    denies without touching local state.
    /// 3. Enforce the local book (nonce/window) plus possession proof and
    ///    approval through `authorize_signed`. Nothing commits on refusal.
    /// 4. Only on `Allow`, run the executor.
    ///
    /// The executor is never called before all mandatory checks pass; step 2
    /// and 3 both deny fail-closed, so a revocation that lands between them
    /// at worst stops this execution at the next one (documented residual:
    /// no cross-node lock).
    pub fn execute<E: Executor>(
        &mut self,
        executor: &E,
        work: &ExecutionWork,
    ) -> WorkerResult<ExecutionOutput> {
        let preimage = guard_action_preimage(work);
        let action = derive_action_hash(&preimage);
        match self.authority.check(
            &self.policy,
            &self.signed,
            &self.agent_id,
            &self.network_id,
            self.height,
            &action,
            &self.workload_id,
            self.escalate_to_approval,
        )? {
            Freshness::Stale(reason) => {
                self.book.forget(&self.policy.hash());
                return Err(WorkerError::GuardDenied(format!(
                    "grant revoked at authority: {reason}"
                )));
            }
            Freshness::Fresh => {}
        }
        let workload_cred = match &self.workload_wallet {
            Some(wallet) if self.policy.workload_key != [0u8; 32] => {
                let effective_ctx = srct_core::guard::derive_context_hash(
                    &self.policy.effective_workload(&self.workload_id),
                    self.height,
                );
                Some(WorkloadCredential::issue(
                    wallet,
                    &self.policy.hash(),
                    &self.signed.cap,
                    &action,
                    &effective_ctx,
                    self.height,
                )?)
            }
            _ => None,
        };
        // A fingerprint sanity check before the gate runs: proving with the
        // wrong key is a configuration error, and it must fail here — loudly
        // and before any nonce is consumed — not deep inside admission.
        if self.policy.workload_key != [0u8; 32] {
            let cred = workload_cred.as_ref().ok_or_else(|| {
                WorkerError::GuardDenied(
                    "grant binds a workload key but no workload key is provisioned".to_string(),
                )
            })?;
            if workload_key_fingerprint(&cred.keys) != self.policy.workload_key {
                return Err(WorkerError::GuardDenied(
                    "provisioned workload key does not match the grant".to_string(),
                ));
            }
        }
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
            workload_cred.as_ref(),
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
    use srct_core::guard::{
        derive_action_hash, derive_context_hash, Capability, InfraPolicy, GUARD_POLICY_VERSION,
    };
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

    /// Test freshness sources: allow-all, revoked, and unreachable.
    struct AllowAll;
    struct RevokedAs(&'static str);
    struct Unreachable;
    impl RevocationAuthority for AllowAll {
        #[allow(clippy::too_many_arguments)]
        fn check(
            &self,
            _policy: &InfraPolicy,
            _signed: &SignedCapability,
            _agent_id: &[u8; 20],
            _network_id: &str,
            _height: u64,
            _action_hash: &Hash,
            _workload_id: &Hash,
            _escalate_to_approval: bool,
        ) -> WorkerResult<Freshness> {
            Ok(Freshness::Fresh)
        }
    }
    impl RevocationAuthority for RevokedAs {
        #[allow(clippy::too_many_arguments)]
        fn check(
            &self,
            _policy: &InfraPolicy,
            _signed: &SignedCapability,
            _agent_id: &[u8; 20],
            _network_id: &str,
            _height: u64,
            _action_hash: &Hash,
            _workload_id: &Hash,
            _escalate_to_approval: bool,
        ) -> WorkerResult<Freshness> {
            Ok(Freshness::Stale(self.0.to_string()))
        }
    }
    impl RevocationAuthority for Unreachable {
        #[allow(clippy::too_many_arguments)]
        fn check(
            &self,
            _policy: &InfraPolicy,
            _signed: &SignedCapability,
            _agent_id: &[u8; 20],
            _network_id: &str,
            _height: u64,
            _action_hash: &Hash,
            _workload_id: &Hash,
            _escalate_to_approval: bool,
        ) -> WorkerResult<Freshness> {
            Err(WorkerError::ObservationUnavailable("authority unreachable"))
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
            workload_key: [0u8; 32],
        };
        (owner, approver, policy)
    }

    fn gate_for(
        owner: &Wallet,
        approver: &Option<Wallet>,
        policy: &InfraPolicy,
        preimage_sign: &[u8],
        approval: bool,
        authority: Box<dyn RevocationAuthority>,
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
            authority,
            workload_wallet: None,
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
        let mut gate = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            false,
            Box::new(AllowAll),
        );
        let out = gate
            .execute(&CpuExecutor::default(), &work)
            .expect("exact work executes");
        assert!(!out.output.is_empty());

        // Drifted work (rebound input): the same capability no longer admits.
        let mut drifted = work.clone();
        drifted.input_hash = [9u8; 32];
        let mut gate2 = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            false,
            Box::new(AllowAll),
        );
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
        let mut gated = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            false,
            Box::new(AllowAll),
        );
        assert_eq!(
            gated.execute(&CpuExecutor::default(), &work),
            Err(WorkerError::GuardApprovalNeeded)
        );
        let mut admitted = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            true,
            Box::new(AllowAll),
        );
        admitted
            .execute(&CpuExecutor::default(), &work)
            .expect("designated approval admits");
    }

    #[test]
    fn revocation_at_the_authority_stops_execution_and_forgets_state() {
        use crate::executor::CpuExecutor;
        let (owner, approver, policy) = owner_and_policy(false);
        let work = test_work();
        let preimage = guard_action_preimage(&work);
        // First execution succeeds against a live authority and consumes the
        // nonce.
        let mut gate = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            false,
            Box::new(AllowAll),
        );
        gate.execute(&CpuExecutor::default(), &work)
            .expect("first execution admits");
        assert!(!gate.book.is_empty(), "an admission commits nonce state");

        // The grant is revoked elsewhere. The next execution asks first: the
        // authority says stale, local accounting is forgotten, nothing runs.
        gate.authority = Box::new(RevokedAs("grant revoked"));
        let err = gate
            .execute(&CpuExecutor::default(), &work)
            .expect_err("a revoked grant must not execute");
        assert!(
            matches!(err, WorkerError::GuardDenied(_)),
            "unexpected: {err}"
        );
        assert!(gate.book.is_empty(), "revocation forgets stale local state");
    }

    #[test]
    fn unreachable_authority_never_executes() {
        use crate::executor::CpuExecutor;
        let (owner, approver, policy) = owner_and_policy(false);
        let work = test_work();
        let preimage = guard_action_preimage(&work);
        let mut gate = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            false,
            Box::new(Unreachable),
        );
        let err = gate
            .execute(&CpuExecutor::default(), &work)
            .expect_err("unknown authority must not execute");
        // Fail closed with the transport error, not a gate decision: there is
        // no silent fallback to stale authorization.
        assert!(
            matches!(err, WorkerError::ObservationUnavailable(_)),
            "unexpected: {err}"
        );
        assert!(
            gate.book.is_empty(),
            "an unknown authority commits no local state"
        );
    }

    #[test]
    fn keybound_grant_proves_possession_per_execution() {
        use crate::executor::CpuExecutor;
        use srct_core::guard::workload_key_fingerprint;
        let owner = Wallet::new_random("kb-owner");
        let addr = owner.address().unwrap();
        let workload_wallet = Wallet::new_random("kb-workload");
        let workload_keys = srct_core::l2::Auth::keys_for(&workload_wallet).unwrap();
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
            requires_approval: false,
            approver: [0u8; 20],
            workload_id: [0u8; 32],
            workload_key: workload_key_fingerprint(&workload_keys),
        };
        let work = test_work();
        let preimage = guard_action_preimage(&work);
        let workload = [4u8; 32];
        let cap = Capability {
            policy_hash: policy.hash(),
            action_hash: derive_action_hash(&preimage),
            context_hash: derive_context_hash(&workload, 50),
            expiry_height: 60,
            nonce: 1,
            audience: [0u8; 32],
        };
        let signed = SignedCapability::issue(&owner, &cap).unwrap();
        let mut gate = GuardGate {
            policy: policy.clone(),
            signed,
            approval: None,
            book: GuardBook::default(),
            authority: Box::new(AllowAll),
            workload_wallet: Some(workload_wallet),
            agent_id: policy.agent_id,
            network_id: "srct/testnet".to_string(),
            height: 50,
            workload_id: workload,
            node_audience: [0u8; 32],
            escalate_to_approval: false,
        };
        gate.execute(&CpuExecutor::default(), &work)
            .expect("possession proof admits");

        // Same grant, wrong key provisioned: the gate refuses before admission.
        let mut impostor = gate_for(&owner, &None, &policy, &preimage, false, Box::new(AllowAll));
        impostor.workload_wallet = Some(Wallet::new_random("impostor-key"));
        let err = impostor
            .execute(&CpuExecutor::default(), &work)
            .expect_err("a wrong workload key must not admit");
        assert!(
            matches!(err, WorkerError::GuardDenied(_)),
            "unexpected: {err}"
        );

        // Same grant, no key provisioned: the gate refuses, never the executor.
        let mut keyless = gate_for(&owner, &None, &policy, &preimage, false, Box::new(AllowAll));
        let err = keyless
            .execute(&CpuExecutor::default(), &work)
            .expect_err("a missing workload key must not admit");
        assert!(
            matches!(err, WorkerError::GuardDenied(_)),
            "unexpected: {err}"
        );
    }
}
