//! Dependency-free JavaScript client for the SRCT node REST API.
//!
//! Covers the agent-facing surface: node health/status, balances, the job
//! lifecycle (open/accept/deliver/dispute/resolve/get), machine payments,
//! escrow (open/get/release/settle) and VWC certificates. Every method takes
//! plain JSON-shaped objects with the exact field names the Rust API expects
//! (`*_hex` payloads, `*_sat` amounts) and returns the decoded JSON body.
//!
//! What this is not: a signer. Callers build signatures with their own keys
//! (see `templates/` for Python signing flows); this client only transports
//! them. Live-node end-to-end coverage is future work — the suite below runs
//! against a mock HTTP server and pins method, path, body and errors.

const DEFAULT_TIMEOUT_MS = 10_000;

/** The node's `{error, detail}` failure, with the HTTP status attached. */
export class SrctApiError extends Error {
  /**
   * @param {number} status HTTP status code.
   * @param {string} code machine-readable `error` string.
   * @param {string} detail human-readable `detail` string.
   */
  constructor(status, code, detail) {
    super(`${status} ${code}: ${detail}`);
    this.name = "SrctApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

function joinUrl(base, path) {
  const trimmed = base.endsWith("/") ? base.slice(0, -1) : base;
  return `${trimmed}${path}`;
}

/**
 * @typedef {object} ClientOptions
 * @property {number} [timeoutMs] per-request deadline (default 10000).
 * @property {typeof fetch} [fetchImpl] fetch-compatible function (for tests).
 */
export class SrctClient {
  /**
   * @param {string} baseUrl e.g. "http://127.0.0.1:8080".
   * @param {ClientOptions} [options]
   */
  constructor(baseUrl, options = {}) {
    if (!baseUrl || typeof baseUrl !== "string") {
      throw new TypeError("baseUrl must be a non-empty string");
    }
    this.baseUrl = baseUrl;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? fetch;
    if (typeof this.fetchImpl !== "function") {
      throw new TypeError("fetchImpl must be a function");
    }
  }

  /** @private */
  async request(method, path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res;
    try {
      res = await this.fetchImpl(joinUrl(this.baseUrl, path), {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      throw new SrctApiError(0, "transport_error", String(err?.message ?? err));
    } finally {
      clearTimeout(timer);
    }
    let parsed = null;
    try {
      parsed = await res.json();
    } catch {
      parsed = null;
    }
    if (!res.ok) {
      const code = parsed?.error ?? "http_error";
      const detail = parsed?.detail ?? `HTTP ${res.status}`;
      throw new SrctApiError(res.status, code, detail);
    }
    return parsed;
  }

  // --- Node ---

  /** GET /v1/health */
  health() {
    return this.request("GET", "/v1/health");
  }

  /** GET /v1/status */
  status() {
    return this.request("GET", "/v1/status");
  }

  /**
   * GET /v1/balance/{address}
   * @param {string} address bech32 address.
   */
  balance(address) {
    return this.request("GET", `/v1/balance/${encodeURIComponent(address)}`);
  }

  /** GET /v1/block/latest */
  blockLatest() {
    return this.request("GET", "/v1/block/latest");
  }

  // --- Jobs ---

  /**
   * POST /v1/jobs/open — hirer locks payment and posts the job.
   * @param {object} params hirer_hex, worker_hex, payer_bls, payee_bls,
   * arbitrator, service_hex (32 bytes hex), amount_sat, deadline_height,
   * nonce, hirer_sig_hex.
   */
  jobOpen(params) {
    return this.request("POST", "/v1/jobs/open", params);
  }

  /**
   * GET /v1/jobs/{job_id}
   * @param {string} jobId
   */
  jobGet(jobId) {
    return this.request("GET", `/v1/jobs/${encodeURIComponent(jobId)}`);
  }

  /**
   * POST /v1/jobs/{id}/accept — worker commits.
   * @param {string} jobId
   * @param {object} params worker_sigs_hex, worker_keys_hex.
   */
  jobAccept(jobId, params) {
    return this.request("POST", `/v1/jobs/${encodeURIComponent(jobId)}/accept`, params);
  }

  /**
   * POST /v1/jobs/{id}/deliver — worker posts the result.
   * @param {string} jobId
   * @param {object} params result_hash_hex, receipt_hex?, worker_sigs_hex, worker_keys_hex.
   */
  jobDeliver(jobId, params) {
    return this.request("POST", `/v1/jobs/${encodeURIComponent(jobId)}/deliver`, params);
  }

  /**
   * POST /v1/jobs/{id}/dispute — freeze the funds.
   * @param {string} jobId
   * @param {object} params by, reason, sig_hex.
   */
  jobDispute(jobId, params) {
    return this.request("POST", `/v1/jobs/${encodeURIComponent(jobId)}/dispute`, params);
  }

  /**
   * POST /v1/jobs/{id}/resolve — arbitrator decides.
   * @param {string} jobId
   * @param {object} params pay_worker, result_hash_hex?, arbitrator_sig_hex.
   */
  jobResolve(jobId, params) {
    return this.request("POST", `/v1/jobs/${encodeURIComponent(jobId)}/resolve`, params);
  }

  // --- Payments ---

  /**
   * POST /v1/payment/submit — admit a machine payment.
   * @param {object} params payment_hex, authorization_hex, auth_sigs_hex, auth_keys_hex, ...
   */
  paymentSubmit(params) {
    return this.request("POST", "/v1/payment/submit", params);
  }

  /**
   * GET /v1/payment/{payment_id}
   * @param {string} paymentId
   */
  paymentGet(paymentId) {
    return this.request("GET", `/v1/payment/${encodeURIComponent(paymentId)}`);
  }

  // --- Escrow ---

  /**
   * POST /v1/escrow/open
   * @param {object} params network_id, payer, payer_bls, payee, payee_bls,
   * arbitrator, amount_sat, nonce.
   */
  escrowOpen(params) {
    return this.request("POST", "/v1/escrow/open", params);
  }

  /**
   * GET /v1/escrow/{id}
   * @param {string} id
   */
  escrowGet(id) {
    return this.request("GET", `/v1/escrow/${encodeURIComponent(id)}`);
  }

  /**
   * POST /v1/escrow/{id}/release
   * @param {string} id
   * @param {object} params mode ("arbiter"|"mutual"), arbiter_sig_hex?, mutual_sigs_hex?.
   */
  escrowRelease(id, params) {
    return this.request("POST", `/v1/escrow/${encodeURIComponent(id)}/release`, params);
  }

  /**
   * POST /v1/escrow/{id}/settle
   * @param {string} id
   * @param {object} [params] route-dependent body (pass-through).
   */
  escrowSettle(id, params = {}) {
    return this.request("POST", `/v1/escrow/${encodeURIComponent(id)}/settle`, params);
  }

  // --- VWC ---

  /**
   * GET /v1/vwc/{task_id}
   * @param {string} taskId hex task id.
   */
  vwc(taskId) {
    return this.request("GET", `/v1/vwc/${encodeURIComponent(taskId)}`);
  }
}
