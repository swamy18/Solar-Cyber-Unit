//! Mock-transport acceptance tests for the SDK: every method pins its HTTP
//! method, path and JSON body, responses decode, and node failures surface
//! as SrctApiError with status, code and detail. No live node needed.

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { SrctClient, SrctApiError } from "../src/srct.mjs";

/** Start a mock node. `routes` maps "METHOD path" to {status, body}. */
function mockNode(routes, onRequest) {
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const key = `${req.method} ${req.url}`;
      onRequest?.(key, raw ? JSON.parse(raw) : undefined);
      const hit = routes[key];
      if (!hit) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not_found", detail: `no mock for ${key}` }));
        return;
      }
      res.writeHead(hit.status, { "content-type": "application/json" });
      res.end(JSON.stringify(hit.body));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

test("constructor validates its inputs", () => {
  assert.throws(() => new SrctClient(""), TypeError);
  // @ts-expect-error testing invalid input
  assert.throws(() => new SrctClient(42), TypeError);
  assert.throws(() => new SrctClient("http://x", { fetchImpl: 42 }), TypeError);
});

test("health, status, balance and blockLatest use GET paths", async () => {
  const seen = [];
  const { server, base } = await mockNode(
    {
      "GET /v1/health": { status: 200, body: { ok: true } },
      "GET /v1/status": { status: 200, body: { height: 41 } },
      "GET /v1/balance/jt1abc": { status: 200, body: { balance_sat: 7 } },
      "GET /v1/block/latest": { status: 200, body: { height: 41 } },
    },
    (key) => seen.push(key),
  );
  try {
    const c = new SrctClient(base);
    assert.deepEqual(await c.health(), { ok: true });
    assert.deepEqual(await c.status(), { height: 41 });
    assert.deepEqual(await c.balance("jt1abc"), { balance_sat: 7 });
    assert.deepEqual(await c.blockLatest(), { height: 41 });
    assert.deepEqual(seen, [
      "GET /v1/health",
      "GET /v1/status",
      "GET /v1/balance/jt1abc",
      "GET /v1/block/latest",
    ]);
  } finally {
    server.close();
  }
});

test("job lifecycle posts exact bodies", async () => {
  const bodies = {};
  const { server, base } = await mockNode(
    {
      "POST /v1/jobs/open": { status: 200, body: { job_id: "job1", escrow_id: "e1" } },
      "GET /v1/jobs/job1": { status: 200, body: { state: "Offered" } },
      "POST /v1/jobs/job1/accept": { status: 200, body: { accepted: true } },
      "POST /v1/jobs/job1/deliver": { status: 200, body: { delivered: true } },
      "POST /v1/jobs/job1/dispute": { status: 200, body: { held: true } },
      "POST /v1/jobs/job1/resolve": { status: 200, body: { released: true } },
    },
    (key, body) => (bodies[key] = body),
  );
  try {
    const c = new SrctClient(base);
    const openBody = {
      hirer_hex: "aa",
      worker_hex: "bb",
      payer_bls: "cc",
      payee_bls: "dd",
      arbitrator: "ee",
      service_hex: "ff".repeat(32),
      amount_sat: 1000,
      deadline_height: 50,
      nonce: 1,
      hirer_sig_hex: "aa",
    };
    assert.deepEqual(await c.jobOpen(openBody), { job_id: "job1", escrow_id: "e1" });
    assert.deepEqual(bodies["POST /v1/jobs/open"], openBody);
    assert.deepEqual(await c.jobGet("job1"), { state: "Offered" });
    const accept = { worker_sigs_hex: "aa", worker_keys_hex: "bb" };
    await c.jobAccept("job1", accept);
    assert.deepEqual(bodies["POST /v1/jobs/job1/accept"], accept);
    const deliver = { result_hash_hex: "cc", worker_sigs_hex: "aa", worker_keys_hex: "bb" };
    await c.jobDeliver("job1", deliver);
    assert.deepEqual(bodies["POST /v1/jobs/job1/deliver"], deliver);
    const dispute = { by: "hirer", reason: "late", sig_hex: "aa" };
    await c.jobDispute("job1", dispute);
    assert.deepEqual(bodies["POST /v1/jobs/job1/dispute"], dispute);
    const resolve = { pay_worker: true, arbitrator_sig_hex: "aa" };
    await c.jobResolve("job1", resolve);
    assert.deepEqual(bodies["POST /v1/jobs/job1/resolve"], resolve);
  } finally {
    server.close();
  }
});

test("payments, escrow and vwc round-trip", async () => {
  const bodies = {};
  const { server, base } = await mockNode(
    {
      "POST /v1/payment/submit": { status: 200, body: { payment_id: "p1" } },
      "GET /v1/payment/p1": { status: 200, body: { state: "settled" } },
      "POST /v1/escrow/open": { status: 200, body: { escrow_id: "e9" } },
      "GET /v1/escrow/e9": { status: 200, body: { state: "live" } },
      "POST /v1/escrow/e9/release": { status: 200, body: { released: true } },
      "POST /v1/escrow/e9/settle": { status: 200, body: { settled: true } },
      "GET /v1/vwc/abcd": { status: 200, body: { certificate: "cert" } },
    },
    (key, body) => (bodies[key] = body),
  );
  try {
    const c = new SrctClient(base);
    const pay = { payment_hex: "aa", authorization_hex: "bb", auth_sigs_hex: "cc", auth_keys_hex: "dd" };
    assert.deepEqual(await c.paymentSubmit(pay), { payment_id: "p1" });
    assert.deepEqual(bodies["POST /v1/payment/submit"], pay);
    assert.deepEqual(await c.paymentGet("p1"), { state: "settled" });
    const esc = {
      network_id: "srct/testnet",
      payer: "aa",
      payer_bls: "bb",
      payee: "cc",
      payee_bls: "dd",
      arbitrator: "ee",
      amount_sat: 5,
      nonce: 1,
    };
    assert.deepEqual(await c.escrowOpen(esc), { escrow_id: "e9" });
    assert.deepEqual(bodies["POST /v1/escrow/open"], esc);
    assert.deepEqual(await c.escrowGet("e9"), { state: "live" });
    const rel = { mode: "mutual", mutual_sigs_hex: ["aa", "bb"] };
    assert.deepEqual(await c.escrowRelease("e9", rel), { released: true });
    assert.deepEqual(bodies["POST /v1/escrow/e9/release"], rel);
    assert.deepEqual(await c.escrowSettle("e9", {}), { settled: true });
    assert.deepEqual(await c.vwc("abcd"), { certificate: "cert" });
  } finally {
    server.close();
  }
});

test("node failures surface as SrctApiError", async () => {
  const { server, base } = await mockNode({
    "POST /v1/jobs/open": { status: 409, body: { error: "job_refused", detail: "bad open" } },
  });
  try {
    const c = new SrctClient(base);
    await assert.rejects(() => c.jobOpen({}), (err) => {
      assert.ok(err instanceof SrctApiError);
      assert.equal(err.status, 409);
      assert.equal(err.code, "job_refused");
      assert.equal(err.detail, "bad open");
      assert.match(err.message, /409 job_refused/);
      return true;
    });
  } finally {
    server.close();
  }
});

test("unreachable node maps to a transport error", async () => {
  const c = new SrctClient("http://127.0.0.1:1", { timeoutMs: 500 });
  await assert.rejects(() => c.health(), (err) => {
    assert.ok(err instanceof SrctApiError);
    assert.equal(err.status, 0);
    assert.equal(err.code, "transport_error");
    return true;
  });
});

test("a custom fetch implementation is honored", async () => {
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push([url, init]);
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };
  const c = new SrctClient("http://node:1234/", { fetchImpl: fakeFetch });
  assert.deepEqual(await c.health(), { ok: true });
  assert.equal(calls[0][0], "http://node:1234/v1/health");
  assert.equal(calls[0][1].method, "GET");
});

test("client validates inputs before touching the network", () => {
  let fetched = 0;
  const c = new SrctClient("http://127.0.0.1:9", {
    fetchImpl: () => {
      fetched += 1;
      throw new Error("must not fetch");
    },
  });
  // Path ids.
  assert.throws(() => c.jobGet(""), TypeError);
  assert.throws(() => c.balance(""), TypeError);
  assert.throws(() => c.escrowSettle(""), TypeError);
  // Bad amounts and bad hex never leave the client.
  assert.throws(() => c.jobOpen({ amount_sat: -1 }), TypeError);
  assert.throws(() => c.jobOpen({ amount_sat: 1.5 }), TypeError);
  assert.throws(() => c.jobOpen({ hirer_hex: "zz" }), TypeError);
  assert.throws(() => c.jobOpen({ hirer_hex: "abc" }), TypeError);
  assert.throws(() => c.jobDeliver("j", { result_hash_hex: "zz" }), TypeError);
  assert.throws(() => c.paymentSubmit({ payment_hex: "zz" }), TypeError);
  assert.throws(() => c.escrowOpen({ amount_sat: Number.MAX_SAFE_INTEGER + 1 }), TypeError);
  assert.throws(() => c.escrowRelease("e", { mode: "sometimes" }), TypeError);
  assert.throws(() => c.jobResolve("j", { pay_worker: 1 }), TypeError);
  assert.throws(() => c.jobAccept("j", null), TypeError);
  assert.equal(fetched, 0);
});
