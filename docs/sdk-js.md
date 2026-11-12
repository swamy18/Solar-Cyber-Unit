# JavaScript SDK (`sdk-js/`)

Dependency-free ESM client for the SRCT node REST API. No installs needed —
`node --test` runs the suite, and the only dev-time dependency (TypeScript
for `checkJs`) lives outside the repo.

## What it covers

Node health/status, balances, latest block, the full job lifecycle
(open/accept/deliver/dispute/resolve/get), machine payments (submit/get),
escrow (open/get/release/settle) and VWC certificates. Every method takes
plain JSON with the exact field names the Rust API expects (`*_hex`
payloads, `*_sat` amounts) and returns the decoded JSON body. Node failures
(`{error, detail}` + status) surface as `SrctApiError` with
`status`/`code`/`detail`.

## What it is not

- **Not a signer.** Callers build signatures with their own keys (see
  `templates/` for Python signing flows); the client only transports them.
- **Not live-node tested.** The suite runs against a mock HTTP server and
  pins method, path, body, parsing and errors. Live-node end-to-end coverage
  is future work.

## Verified behavior

`npm test` (7 tests): constructor validation, GET paths, exact job-lifecycle
bodies, payment/escrow/VWC round-trips, `SrctApiError` mapping (409
`job_refused` case), unreachable-node transport errors, and custom
`fetchImpl` injection. `tsc --noEmit --allowJs --checkJs --strict` passes on
the JSDoc-typed source.

## Next milestones

1. Python client parity (typed wrappers over the same surface, tested).
2. Live-node end-to-end journey (open → accept → deliver → settle).
3. Signing helpers (BLS/Bundle) so agents can authorize without Python.
4. WebSocket/subscription surface if the node adds one.
