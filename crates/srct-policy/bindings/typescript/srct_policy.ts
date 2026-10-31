/**
 * srct_policy — TypeScript binding for the chain-agnostic SRCT policy engine.
 *
 * The engine itself stays in Rust (one implementation of every rule, in
 * `crates/srct-policy`): this module is the JSON codec + client seam. It
 * builds payment intents, parses decisions, and structurally reads portable
 * documents — it never re-implements a budget, narrowing, or signature rule.
 * Verification that matters (signatures, chains, bindings) runs in Rust:
 * either behind the injected `PolicyBackend` or on any node speaking
 * `POST /v1/policy/decide`, `/v1/delegation/verify` and `/v1/audit/verify`
 * (see `NodeHttpBackend` — no Rust toolchain needed, just a node URL).
 *
 * Wire `decide`/`verifyProof`/`verifyAudit` to any of:
 * - a `NodeHttpBackend` pointed at a node (works today, no build step),
 * - the `srct-policy` Rust functions over FFI/WASM,
 * - a node speaking the portable JSON (`policy.decide`, `delegation.verify`,
 *   `audit.verify` over the MCP guard),
 * - an HTTP helper posting to `/v1/authorize` + friends.
 */

/** What an agent wants to do — mirrors `portable::PaymentIntent`. */
export interface PaymentIntent {
  /** 20-byte agent id, hex (`0x` optional). */
  agent_id: string;
  /** 20-byte recipient, hex. */
  recipient: string;
  amount_sat: number;
  /** 32-byte service tag, hex, or null for untagged. */
  service: string | null;
  height: number;
  nonce: number;
  network_id: string;
}

/** The engine's answer — mirrors `portable::PolicyDecision`. */
export type PolicyDecision =
  | { decision: "allow" }
  | { decision: "deny"; reason: string }
  | { decision: "needs_approval"; reason: string };

/** Structural view of a portable policy document (`SignedPolicy::to_json`). */
export interface PortablePolicyDoc {
  version: number;
  policy_hex: string;
  sigs_hex: string;
  keys_hex: string;
  policy_hash: string;
  owner: string;
  agent_id: string;
  network_id: string;
}

/** Structural view of a delegation proof (`DelegationProof::to_json`). */
export interface DelegationProofDoc {
  version: number;
  links: string[];
  root_owner: string;
  leaf_agent: string;
  leaf_policy_hash: string;
}

/** The Rust backend behind this binding. */
export interface PolicyBackend {
  decide(
    networkId: string,
    policyPortableJson: string,
    intentJson: string,
    approvalThresholdSat?: number | null,
  ): Promise<string>;
  verifyProof(proofJson: string): Promise<string>;
  verifyAudit(auditJson: string): Promise<number>;
}

/**
 * A backend that speaks to any node over HTTP — no Rust toolchain, no
 * build step, just a node URL. Verification runs on the node (the same
 * engine that admits payments); this module only codecs the JSON.
 *
 * ```ts
 * const guard = new PolicyClient(new NodeHttpBackend("http://127.0.0.1:8080"));
 * const decision = await guard.decide("srct/testnet", portablePolicyJson, intent, 100);
 * ```
 */
export class NodeHttpBackend implements PolicyBackend {
  constructor(private readonly baseUrl: string) {}

  private async post(path: string, body: unknown): Promise<any> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const doc = (await res.json()) as any;
    if (!res.ok) {
      const detail = doc.detail ?? doc.reason ?? JSON.stringify(doc);
      throw new Error(`node refused (${res.status} ${doc.error ?? "error"}): ${detail}`);
    }
    return doc;
  }

  async decide(
    networkId: string,
    policyPortableJson: string,
    intentJson: string,
    approvalThresholdSat?: number | null,
  ): Promise<string> {
    // The node frames the intent in its own network and height, so the
    // caller's networkId never travels: it exists so direct-Rust backends
    // and this backend share one call shape, and the rail cannot forget
    // to name itself.
    void networkId;
    const intent = JSON.parse(intentJson) as PaymentIntent;
    const doc = await this.post("/v1/policy/decide", {
      policy_portable_json: policyPortableJson,
      agent_id_hex: intent.agent_id,
      recipient_hex: intent.recipient,
      amount_sat: intent.amount_sat,
      service_hex: intent.service,
      approval_threshold_sat: approvalThresholdSat ?? null,
    });
    if (doc.decision !== "allow" && doc.decision !== "deny" && doc.decision !== "needs_approval") {
      throw new Error("malformed policy decision from node");
    }
    return JSON.stringify({ decision: doc.decision, reason: doc.reason ?? "" });
  }

  async verifyProof(proofJson: string): Promise<string> {
    const doc = await this.post("/v1/delegation/verify", { proof_json: proofJson });
    if (doc.valid !== true) throw new Error("node did not verify the proof");
    return `${doc.leaf_agent}/${doc.leaf_policy_hash}`;
  }

  async verifyAudit(auditJson: string): Promise<number> {
    const doc = await this.post("/v1/audit/verify", { audit_json: auditJson });
    if (doc.valid !== true || typeof doc.entries !== "number") {
      throw new Error("node did not verify the audit chain");
    }
    return doc.entries;
  }
}

/** Build the intent JSON the engine parses — no defaults are invented. */
export function encodeIntent(intent: PaymentIntent): string {
  for (const [name, value] of Object.entries(intent)) {
    if (value === undefined || value === null) {
      if (name === "service") continue;
      throw new Error(`intent field ${name} is missing`);
    }
  }
  if (!Number.isInteger(intent.amount_sat) || intent.amount_sat < 0) {
    throw new Error("amount_sat must be a non-negative integer");
  }
  return JSON.stringify(intent);
}

/** Parse an engine answer; unknown shapes are refused, not defaulted. */
export function parseDecision(raw: string): PolicyDecision {
  const doc = JSON.parse(raw) as PolicyDecision;
  if (doc.decision === "allow") return doc;
  if ((doc.decision === "deny" || doc.decision === "needs_approval") && typeof doc.reason === "string") {
    return doc;
  }
  throw new Error("malformed policy decision");
}

/** Structurally read a portable policy (routing without trusting). */
export function parsePortablePolicy(raw: string): PortablePolicyDoc {
  const doc = JSON.parse(raw) as PortablePolicyDoc;
  if (
    doc.version !== 1 ||
    typeof doc.policy_hex !== "string" ||
    typeof doc.policy_hash !== "string" ||
    typeof doc.owner !== "string" ||
    typeof doc.network_id !== "string"
  ) {
    throw new Error("malformed portable policy");
  }
  return doc;
}

/** Structurally read a delegation proof (routing without trusting). */
export function parseDelegationProof(raw: string): DelegationProofDoc {
  const doc = JSON.parse(raw) as DelegationProofDoc;
  if (doc.version !== 1 || !Array.isArray(doc.links) || doc.links.length === 0) {
    throw new Error("malformed delegation proof");
  }
  return doc;
}

/** The agent wallet guard: allow, deny, or approval-needed, via the backend. */
export class PolicyClient {
  constructor(private readonly backend: PolicyBackend) {}

  async decide(
    networkId: string,
    policyPortableJson: string,
    intent: PaymentIntent,
    approvalThresholdSat?: number | null,
  ): Promise<PolicyDecision> {
    const out = await this.backend.decide(
      networkId,
      policyPortableJson,
      encodeIntent(intent),
      approvalThresholdSat ?? null,
    );
    return parseDecision(out);
  }

  /** Verify a delegation proof; resolves to `leaf_agent/leaf_policy_hash`. */
  async verifyProof(proofJson: string): Promise<string> {
    return this.backend.verifyProof(proofJson);
  }

  /** Verify an exported audit chain; resolves to the entry count. */
  async verifyAudit(auditJson: string): Promise<number> {
    return this.backend.verifyAudit(auditJson);
  }
}
