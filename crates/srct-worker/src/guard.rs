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

/// What the authority said about one admission, right now. `Allow` means the
/// authority admitted *and committed* (nonce consumed, window spent) at its
/// live state; `NeedsApproval` means the authority gates on a designated
/// approval the local gate still enforces; `Deny` carries the authority's
/// named reason. Transport or decode failures are not a variant: they surface
/// as `Err`, and `Err` never executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Allow,
    NeedsApproval,
    Deny(String),
}

/// One admission request to the authority: everything the enforcing node needs
/// to admit statefully, including the optional possession proof.
pub struct AdmissionRequest<'a> {
    pub policy: &'a InfraPolicy,
    pub signed: &'a SignedCapability,
    pub agent_id: &'a [u8; 20],
    pub action_preimage: &'a [u8],
    pub workload_id: &'a Hash,
    pub escalate_to_approval: bool,
    pub approval_hex: Option<String>,
    pub workload_cred_hex: Option<String>,
}

/// The authoritative admission source consulted at the execution boundary.
/// Nonce and window accounting live HERE — not in the worker's local book —
/// so restarts and sibling workers cannot independently accept the same
/// nonce: the authority commits once, and a replayed nonce denies by name.
/// The local book is a monotonic mirror plus an independent cryptographic
/// re-verification, never the source of truth.
///
/// Implementations MUST fail closed: `Err` means "unknown", and unknown never
/// executes. There is deliberately no "allow on unreachable" mode and no
/// cached-allow fallback — a worker cut off from its authority stops
/// executing gated work instead of running on stale permission.
pub trait GateAuthority {
    fn admit(&self, req: &AdmissionRequest) -> WorkerResult<Admission>;
}

/// Admission via the enforcing node's stateful `POST /v1/guard/authorize`:
/// one round trip that verifies signature, risk model, possession,
/// revocation set, validity, binding and audience, approves, and commits
/// nonce + window at the authority's live state. No new endpoint, no new
/// trust root — the same admission path operators already use.
pub struct NodeGateAuthority {
    /// Node HTTP client (loopback by default; see [`HttpNode`]).
    pub http: HttpNode,
}

impl NodeGateAuthority {
    pub fn new(http: HttpNode) -> Self {
        NodeGateAuthority { http }
    }
}

impl GateAuthority for NodeGateAuthority {
    fn admit(&self, req: &AdmissionRequest) -> WorkerResult<Admission> {
        use serde_json::json;
        let action = derive_action_hash(req.action_preimage);
        let body = json!({
            "cap_hex": hex::encode(req.signed.serialize()),
            "agent_id_hex": hex::encode(req.agent_id),
            "action_hash_hex": hash_to_hex(&action),
            "action_preimage_hex": hex::encode(req.action_preimage),
            "workload_id_hex": hash_to_hex(req.workload_id),
            "high_risk": req.escalate_to_approval,
            "approval_hex": req.approval_hex,
            "workload_cred_hex": req.workload_cred_hex,
        });
        let answer = self.http.post_json("/v1/guard/authorize", &body)?;
        match answer.get("decision").and_then(|d| d.as_str()) {
            Some("allow") => Ok(Admission::Allow),
            Some("needs_approval") => Ok(Admission::NeedsApproval),
            Some("deny") => Ok(Admission::Deny(
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
    /// Mandatory admission authority. Consulted on EVERY execution, before the
    /// local book and before the executor: the authority commits nonce +
    /// window at its live state, so restarts and sibling workers cannot
    /// independently accept the same nonce. Unreachable means unknown, and
    /// unknown never executes — there is no offline fallback.
    pub authority: Box<dyn GateAuthority>,
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
    /// 1. Recompute the action preimage (and context) from the work about
    ///    to run, and build the fresh possession proof when the grant binds
    ///    a workload key. A missing or mismatched provisioned key fails
    ///    HERE — loudly and before any nonce is consumed — not deep inside
    ///    admission.
    /// 2. Ask the authority to admit statefully. The authority commits
    ///    nonce + window at its live state, so this is where replays die: a
    ///    restarted worker or a sibling worker replaying the same nonce gets
    ///    a named deny from the single commit point. A deny forgets the
    ///    grant's local accounting (so stale state can never be replayed
    ///    back); an unreachable authority denies without touching anything.
    /// 3. Re-verify locally through `authorize_signed` (signature, binding,
    ///    possession, approval) and mirror the commit in the local book.
    ///    Nothing commits on refusal, locally or remotely.
    /// 4. Only on `Allow`, run the executor.
    ///
    /// The local book is a monotonic mirror plus independent cryptographic
    /// re-verification — it can only ever trail the authority, because it
    /// commits solely after the authority allowed. The executor is never
    /// called before all mandatory checks pass.
    pub fn execute<E: Executor>(
        &mut self,
        executor: &E,
        work: &ExecutionWork,
    ) -> WorkerResult<ExecutionOutput> {
        let preimage = guard_action_preimage(work);
        let action = derive_action_hash(&preimage);
        let effective_ctx = srct_core::guard::derive_context_hash(
            &self.policy.effective_workload(&self.workload_id),
            self.height,
        );
        // Possession is proved BEFORE the authority is asked, so the proof
        // travels with the admission request: a key-bound grant that reaches
        // a credential-requiring authority without proof denies there — not
        // silently, and not later.
        let workload_cred = match &self.workload_wallet {
            Some(wallet) if self.policy.workload_key != [0u8; 32] => {
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
        let approval_hex = self.approval.as_ref().map(|ap| hex::encode(ap.serialize()));
        let workload_cred_hex = workload_cred
            .as_ref()
            .map(|cred| hex::encode(cred.serialize()));
        match self.authority.admit(&AdmissionRequest {
            policy: &self.policy,
            signed: &self.signed,
            agent_id: &self.agent_id,
            action_preimage: &preimage,
            workload_id: &self.workload_id,
            escalate_to_approval: self.escalate_to_approval,
            approval_hex,
            workload_cred_hex,
        })? {
            Admission::Deny(reason) => {
                self.book.forget(&self.policy.hash());
                return Err(WorkerError::GuardDenied(format!(
                    "denied at authority: {reason}"
                )));
            }
            Admission::NeedsApproval => return Err(WorkerError::GuardApprovalNeeded),
            Admission::Allow => {}
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

    /// Test authorities: allow-all, deny-with-reason, unreachable, and a
    /// shared ledger that mimics the node's authoritative book: nonces commit
    /// once per grant hash, so a replayed nonce denies no matter which local
    /// book presents it.
    struct AllowAll;
    struct DenyAs(&'static str);
    struct Unreachable;
    struct SharedLedger {
        last_nonce: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<Hash, u64>>>,
    }
    impl GateAuthority for AllowAll {
        fn admit(&self, _req: &AdmissionRequest) -> WorkerResult<Admission> {
            Ok(Admission::Allow)
        }
    }
    impl GateAuthority for DenyAs {
        fn admit(&self, _req: &AdmissionRequest) -> WorkerResult<Admission> {
            Ok(Admission::Deny(self.0.to_string()))
        }
    }
    impl GateAuthority for Unreachable {
        fn admit(&self, _req: &AdmissionRequest) -> WorkerResult<Admission> {
            Err(WorkerError::ObservationUnavailable("authority unreachable"))
        }
    }
    impl GateAuthority for SharedLedger {
        fn admit(&self, req: &AdmissionRequest) -> WorkerResult<Admission> {
            // The credential travels with the request now: a key-bound grant
            // without proof denies at the authority, not just locally.
            if req.policy.workload_key != [0u8; 32] && req.workload_cred_hex.is_none() {
                return Ok(Admission::Deny(
                    "grant requires a workload credential".to_string(),
                ));
            }
            let mut ledger = self.last_nonce.lock().unwrap();
            let last = ledger.get(&req.policy.hash()).copied().unwrap_or(0);
            if req.signed.cap.nonce <= last {
                return Ok(Admission::Deny("replayed nonce at authority".to_string()));
            }
            ledger.insert(req.policy.hash(), req.signed.cap.nonce);
            Ok(Admission::Allow)
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
        authority: Box<dyn GateAuthority>,
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
        // authority denies, local accounting is forgotten, nothing runs.
        gate.authority = Box::new(DenyAs("grant revoked"));
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
    fn replay_across_workers_dies_at_the_authority() {
        use crate::executor::CpuExecutor;
        // Two workers, two fresh local books, one shared authority ledger:
        // the same capability (same nonce) can only ever execute once.
        let (owner, approver, policy) = owner_and_policy(false);
        let work = test_work();
        let preimage = guard_action_preimage(&work);
        let ledger = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let mut first = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            false,
            Box::new(SharedLedger {
                last_nonce: ledger.clone(),
            }),
        );
        first
            .execute(&CpuExecutor::default(), &work)
            .expect("first worker admits");
        // A restarted worker (empty local book) replaying the same nonce, and
        // a sibling worker with its own book, both deny at the authority.
        let mut restarted = gate_for(
            &owner,
            &approver,
            &policy,
            &preimage,
            false,
            Box::new(SharedLedger {
                last_nonce: ledger.clone(),
            }),
        );
        let err = restarted
            .execute(&CpuExecutor::default(), &work)
            .expect_err("a replayed nonce must not execute twice");
        assert!(
            matches!(err, WorkerError::GuardDenied(_)),
            "unexpected: {err}"
        );
        assert!(
            restarted.book.is_empty(),
            "an authority-denied replay commits no local state"
        );
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
        // The shared ledger stands in for the node: it also requires the
        // credential to travel with the request, so this test proves the
        // proof reaches the authority — not just the local book.
        let ledger = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let mut gate = GuardGate {
            policy: policy.clone(),
            signed,
            approval: None,
            book: GuardBook::default(),
            authority: Box::new(SharedLedger {
                last_nonce: ledger.clone(),
            }),
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
