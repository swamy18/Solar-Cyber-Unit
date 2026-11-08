# SRCT Universal Security — Packaging Plan (API pehle, library baad me)

## Goal (simple me)
Company apne payment ke aage SRCT ka lock lagaye: sahi user ek sign me andar, attacker ka try bekar. SRCT coin/mining alag chalta rahe, security check halka aur sasta rahe.

## Locked decisions
1. Pehla adopter: dono, par **API pehle** — hosted authorize API, embed library baad me.
2. Pehla use-case: **payment/finance** — paisa move hone wali action pe gate.
3. Keys: **SRCT sirf verify karega** — private key hamesha company ke paas, SRCT ke paas sirf public key + signature check.
4. Cost: **free + rate-limit (V1)** — security check pe coin fee nahi, strict budget se spam rokna, L1 pe load nahi.

## Abhi code me kya hai (reuse, dobara mat likho)
- `srct-core/src/guard.rs` — pure deterministic gate: `action_hash` + `context_hash` exact match, expiry + `MAX_CAP_LIFETIME=30`, strictly increasing nonce, deny pe koi mutate nahi, high-risk pe independent approver (`SelfApproval` refuse).
- `srct-policy/src/lib.rs` — `decide()` stateless pre-check, `SignedPolicy::from_json` bina verify ke grant manta hi nahi. Note: vendoring abhi full `srct-core` (BLS + ML-DSA) kheenchta hai — crypto-light split jaan-boojh ke nahi kiya.
- `srct-node/src/api.rs` — `POST /v1/guard/decide` (stateless pre-check) + `POST /v1/guard/authorize` (budget commit) + `POST /v1/policy/decide` already live. Loopback default unauthenticated, exposed bind pe bearer token.
- `srct-mcp` — `guard.check` / `guard.authorize`, `srct-worker` SDK — adoption ka rasta.

## Kya banana hai (ordered tasks)
1. **Payment intent freeze karo** — `PaymentIntent` JSON fields (payer, payee, amount_sat, network_id, expiry, nonce) ka ek example + ek negative example docs me. Koi naya crypto nahi, sirf format lock.
2. **Hosted API ko company-ready banao** — `POST /v1/policy/decide` + `/v1/guard/decide` + `/v1/guard/authorize` pe: per-company rate-limit/budget, `network_id` server-side se (requester se copy nahi), har deny ka named reason. Bearer token exposed bind pe mandatory rakho.
3. **Integrator guide (1 page)** — company steps: owner key + approver key khud banaye, public key register kare, har payment se pehle `decide` call kare, `needs_approval` ko deny mane jab tak approver sign na aaye, `action_hash/context_hash` khud recompute kare (requester se copy nahi).
4. **Demo: finance front-run** — ek chhota script: sahi sign → allow, galat amount/nonce/expiry/replay → deny, `window_exhausted` burst pe alert. Yehi sales demo hai.
5. **Library (phase 2, abhi nahi)** — `srct-policy` ko publishable banana + TS/Python bindings (`NodeHttpBackend`, stdlib only). Crypto-light split mat karna — do rule implementations ka risk hai (lib.rs me recorded).

## Data flow
Company app → `POST /v1/policy/decide` (intent + signed policy) → allow / deny / approval-needed → bada payment ho to `POST /v1/guard/authorize` (approver sign ke saath) → company tabhi paisa move kare. SRCT L1 state ko chhoota nahi, sirf verify + audit log.

## Fail-closed rules (todna mana hai)
- Hash mismatch, expired, lifetime > 30, nonce reuse, cross-principal, self-approval → hamesha deny.
- Deny pe window/budget mutate nahi.
- Unknown `sig_scheme` refuse, kabhi standard mat samjho.
- Private key SRCT server pe kabhi mat mango/store karo.

## Risks
- Integrator `action_hash` khud compute na kare aur requester wala copy kare → forged allow. Guide + server-side recompute example se rokna.
- Free API pe spam → rate-limit + per-company budget + `ADDR`/frame wale bounds (`max_frame_bytes`, count caps) reuse karo.
- Replay → nonce strictly increasing + short expiry mandatory.

## Validation
- `cargo test -p srct-core --lib guard policy`
- `cargo test -p srct-node --test api guard policy`
- Vectors stable rahe: `python sim/verify_vectors.py --check`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`

## Out of scope (V1 me nahi)
- Key custody/hosting, coin fee per check, generic infra actions, P2P auth, PQ-enforcement (`pq_activation_height=0` rehta hai), crypto-light crate split.
