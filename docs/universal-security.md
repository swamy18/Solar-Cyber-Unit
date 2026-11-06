# Universal Security: finance gate integrator guide (V1)

Goal: company apne payment ke aage SRCT ka lock lagaye. Sahi user ek sign me andar, attacker ka try bekar. Private key hamesha company ke paas, SRCT sirf verify karta hai. V1 me check free hai par rate-limit ke saath, L1 coin ko chhoota nahi.

## Frozen payment intent (V1)

`POST /v1/policy/decide` ka intent shape fixed hai. `network_id` aur `height` tum mat bhejo — node apne chain se khud bharta hai. Tum sirf ye bhejo:

```json
{
  "policy_hex": "<owner-signed SpendPolicy>",
  "policy_sigs_hex": "<owner sig bundle>",
  "policy_keys_hex": "<owner key bundle>",
  "agent_id_hex": "<20-byte agent id hex>",
  "recipient_hex": "<20-byte provider address hex>",
  "amount_sat": 400,
  "service_hex": "<32-byte service id hex, optional>"
}
```

Good intent (allow): amount `per_tx_max_sat` ke andar, recipient allow-list me, service allow-list me, policy valid window me, revoke nahi.

Bad intent (deny, 200 + named reason): amount 0 ya cap ke upar, galat recipient/service, expired ya revoked policy, doosre network ki policy.

```json
{
  "policy_hex": "<same as above>",
  "policy_sigs_hex": "<same>",
  "policy_keys_hex": "<same>",
  "agent_id_hex": "<same>",
  "recipient_hex": "<attacker address, not allow-listed>",
  "service_hex": "<same>",
  "amount_sat": 50000
}
```

Jawab: `{"decision": "deny", "reason": "recipient is not allowed", ...}` — HTTP 200 hai kyunki sawal ka jawab mila, transport fail nahi hua.

## Company steps (5 min integration)

1. Owner key + approver key khud banao, public key node pe grant register karo (`POST /v1/guard/grant`). Private key kabhi server ko mat bhejo.
2. Har payment se pehle `POST /v1/policy/decide` call karo. `allow` aaye tabhi paisa move karo.
3. `needs_approval` ko deny mano jab tak approver ka sign `POST /v1/guard/authorize` pe pass na ho. Owner ka sign approver nahi banta (self-approval refuse hota hai).
4. Smart Gate pe `action_preimage_hex` (exact bytes jo execute hone wale hain) hamesha khud recompute karo, requester wala hash copy mat karo. Node hash dobara nikalta hai, mismatch pe deny hota hai.
5. `window_exhausted` burst dikhe to alert lagao — ye attack ka signal hai, normal traffic nahi.

## Kya guarantee hai, kya nahi

Hai: exact hash match, expiry + 30-height lifetime cap, nonce strictly increasing (replay deny), deny pe budget mutate nahi, cross-principal refuse, revoked grant dead.

Nahi hai: P2P auth, endpoint malware se bachav, workload binary ka attestation, network privacy. Ye V1 ke bahar hai.

## Demo

`python scripts/finance_gate_demo.py --node http://127.0.0.1:PORT` chalao: allow, over-cap deny, replayed nonce deny, swapped preimage deny, window burst alert — paanchon case ek saath dikhenge.
