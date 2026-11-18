//! The L2 state wire codec (SPEC.md §19.2) — the transport between a node and
//! a remote worker.
//!
//! Two properties are under attack here, because both decide whether a worker
//! may trust what an HTTP response handed it:
//!
//! 1. **A faithful round trip.** Encoding a state and decoding it back yields
//!    the *same* state — for every contract state, not just the happy one, and
//!    byte-deterministically (maps are sorted, so two equal states encode to
//!    equal bytes and a client can compare hashes).
//! 2. **Fail closed.** A truncated, extended, re-versioned, count-inflated,
//!    key-duplicated or value-tampered blob produces *no state at all* — never
//!    a partial one — and the protocol's own conservation invariant is checked
//!    before a decode succeeds.
//!
//! Run with `cargo test -p srct-l2 --test state_wire`.

use srct_core::bls::{RealBls, SecretKey};
use srct_core::bls_checkpoint::ValidatorSet;
use srct_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use srct_core::hash::{Address, Hash, Hash512};
use srct_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use srct_core::slash::SlashVault;
use srct_core::wallet::Wallet;
use srct_l2::{ContractState, L2Config, L2Error, L2State, VwcVerification};

const DEADLINE: u64 = 400;
/// The one task built to expire: the fixture's final `advance_block` crosses
/// this deadline and nothing else.
const EXPIRE_DEADLINE: u64 = 20;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "state-wire").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn validators() -> ValidatorSet {
    let secrets: Vec<SecretKey> = (1u8..=4)
        .map(|i| SecretKey::derive(&[i; 32]).unwrap())
        .collect();
    ValidatorSet::new(secrets.iter().map(|sk| sk.public_key()).collect())
}

fn attestation(w: &Wallet, task_id: Hash, result: Hash) -> ComputeAttestation {
    let mut a = ComputeAttestation {
        task_id,
        result_hash: result,
        backend: ComputeBackend::Cpu,
        worker_address: addr(w),
        attest_height: 0,
        signature: Vec::new(),
    };
    a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
    a
}

fn compute_task(task_id: Hash, deadline: u64) -> ComputeTask {
    ComputeTask {
        task_id,
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 0,
        expiry_height: deadline,
        submit_height: 0,
    }
}

/// A state carrying one contract in *every* contract state — all six live at
/// once, on six different tasks — plus applied ids, a slash vault, PSCB and a
/// non-trivial counter set. Six tasks rather than one task driven through six
/// transitions, because a transition supersedes the state it came from: to
/// prove each *state* round-trips, each has to be frozen on its own contract.
///
/// Heights are planned so that nothing time-based fires except the one expiry
/// we want: the submitted and disputed tasks are filed inside a five-block
/// window of the final `advance_block`, so the auto-settlement and the dispute
/// lapse are both still in the future when the fixture stops.
fn fully_populated_state() -> (L2State, Vec<Hash512>) {
    let mut state = L2State::new(L2Config::mini());
    state
        .apply_genesis(&srct_l2::L2Genesis::for_params(
            &srct_core::params::NetworkParams::mini(),
        ))
        .unwrap();
    let vs = validators();
    let secrets: Vec<SecretKey> = (1u8..=4)
        .map(|i| SecretKey::derive(&[i; 32]).unwrap())
        .collect();

    let post = |n: u64, deadline: u64| -> L2Transaction {
        let mut t = compute_task([0; 32], deadline);
        let mut id = [0x10u8; 32];
        id[8..16].copy_from_slice(&n.to_le_bytes());
        t.task_id = id;
        let p = PostTaskPayload::build(&wallet(1), n, 1_000_000, deadline, t).unwrap();
        L2Transaction::new(L2Payload::Post(p))
    };
    let claim = |n: u8, task: Hash| -> L2Transaction {
        L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&wallet(n), task, ComputeBackend::Cpu, 100_000).unwrap(),
        ))
    };
    let submit = |n: u8, task: Hash, result: Hash| -> L2Transaction {
        L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&wallet(n), task, attestation(&wallet(n), task, result))
                .unwrap(),
        ))
    };
    let dispute = |task: Hash, counter: Hash| -> L2Transaction {
        L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &wallet(3),
                task,
                counter,
                attestation(&wallet(3), task, counter),
                50_000,
            )
            .unwrap(),
        ))
    };
    let quorum_settle =
        |task: Hash, verdict: Verdict, vwc_hash: Hash, height: u64| -> L2Transaction {
            let draft = SettlePayload {
                task_id: task,
                verdict,
                vwc_hash,
                network_id: "srct/mini".to_string(),
                height,
                bls_sig: [0u8; 96],
                signer_bitmap: Vec::new(),
                signer_count: 0,
                pq_sidecar: Vec::new(),
            };
            let msg = draft.signing_hash();
            let bitmap = vs.bitmap_from_indices(&(0..vs.quorum_size()).collect::<Vec<_>>());
            let signers = vs.signers_from_bitmap(&bitmap);
            let sigs: Vec<_> = signers
                .iter()
                .map(|pk| {
                    secrets
                        .iter()
                        .find(|sk| sk.public_key().0 == pk.0)
                        .expect("committee keys come from the secrets")
                        .sign(&msg)
                })
                .collect();
            let payload = SettlePayload {
                bls_sig: *RealBls::aggregate(&sigs).unwrap().as_bytes(),
                signer_bitmap: bitmap,
                signer_count: vs.quorum_size() as u32,
                pq_sidecar: Vec::new(),
                ..draft
            };
            L2Transaction::new(L2Payload::Settle(payload))
        };
    let apply = |state: &mut L2State, tx: &L2Transaction, h: u64| {
        state.apply(tx, h, &vs, &RealBls).unwrap();
    };

    let mut ids = Vec::new();
    // --- height 1: task A, left Open -------------------------------------
    let tx_a = post(1, DEADLINE);
    ids.push(tx_a.txid());
    apply(&mut state, &tx_a, 1);
    let task_a = task_of_nonce(&state, 1);

    // --- height 2: task B, claimed → InProgress ---------------------------
    let tx_b = post(2, DEADLINE);
    ids.push(tx_b.txid());
    apply(&mut state, &tx_b, 2);
    let task_b = task_of_nonce(&state, 2);
    apply(&mut state, &claim(2, task_b), 2);

    // --- heights 3–5: tasks C, D, E claimed (E has the near deadline) -----
    let tx_c = post(3, DEADLINE);
    ids.push(tx_c.txid());
    apply(&mut state, &tx_c, 3);
    let task_c = task_of_nonce(&state, 3);
    apply(&mut state, &claim(2, task_c), 3);

    let tx_d = post(4, DEADLINE);
    ids.push(tx_d.txid());
    apply(&mut state, &tx_d, 4);
    let task_d = task_of_nonce(&state, 4);
    apply(&mut state, &claim(2, task_d), 4);

    let tx_e = post(5, EXPIRE_DEADLINE);
    ids.push(tx_e.txid());
    apply(&mut state, &tx_e, 5);
    let task_e = task_of_nonce(&state, 5);
    apply(&mut state, &claim(2, task_e), 5);

    // --- heights 6–9: task F through the whole fraud path → Settled -------
    let tx_f = post(6, DEADLINE);
    ids.push(tx_f.txid());
    apply(&mut state, &tx_f, 6);
    let task_f = task_of_nonce(&state, 6);
    apply(&mut state, &claim(2, task_f), 6);
    apply(&mut state, &submit(2, task_f, [0xAAu8; 32]), 7);
    let counter = [0xBBu8; 32];
    apply(&mut state, &dispute(task_f, counter), 8);
    apply(
        &mut state,
        &quorum_settle(task_f, Verdict::Fraudulent, counter, 9),
        9,
    );
    assert!(
        matches!(
            state.task(&task_f).unwrap().state,
            ContractState::Settled(_)
        ),
        "task F must settle"
    );

    // --- heights 10–15: empty blocks --------------------------------------
    for h in 10..=15 {
        state.advance_block(h);
    }

    // --- height 16: task C submitted (window closes at 21, still open) ----
    apply(&mut state, &submit(2, task_c, [0xCCu8; 32]), 16);

    // --- height 17: task D submitted and challenged -----------------------
    apply(&mut state, &submit(2, task_d, [0xDDu8; 32]), 17);
    apply(&mut state, &dispute(task_d, [0xEEu8; 32]), 17);
    assert!(matches!(
        state.task(&task_d).unwrap().state,
        ContractState::Disputed(_)
    ));

    // --- heights 18–21: the clock crosses E's deadline, and no other
    //     task's window (C settles only after 21, D lapses only after 22) ---
    for h in 18..=EXPIRE_DEADLINE + 1 {
        state.advance_block(h);
    }
    assert!(matches!(
        state.task(&task_e).unwrap().state,
        ContractState::Expired(_)
    ));
    assert!(
        matches!(
            state.task(&task_c).unwrap().state,
            ContractState::ResultSubmitted { .. }
        ),
        "C must still be waiting on its window"
    );
    assert!(matches!(
        state.task(&task_a).unwrap().state,
        ContractState::Open
    ));
    assert!(matches!(
        state.task(&task_b).unwrap().state,
        ContractState::InProgress { .. }
    ));

    // The fraudulent settlement routed the slashed deposit through the M2
    // vault and accrued the settle fee — so the vault and the counters are
    // non-trivial without any out-of-band mutation (which would create value
    // the invariant would rightly refuse).
    assert!(
        state.slash_vault.active_count() >= 1,
        "the slash left a record"
    );
    assert!(state.pscb > 0, "the settle fee accrued to the PSCB");
    assert!(state.check_conservation(), "fixture must itself be valid");
    (state, ids)
}

/// The task posted with `nonce` — `TaskContract::nonce` carries the post's own
/// anti-replay counter, which is unique per submitter.
fn task_of_nonce(state: &L2State, nonce: u64) -> Hash {
    state
        .tasks()
        .iter()
        .find(|c| c.nonce == nonce)
        .map(|c| c.task_id)
        .unwrap_or_else(|| panic!("task posted with nonce {nonce} must exist"))
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

#[test]
fn every_contract_state_round_trips_byte_identically() {
    let (state, _) = fully_populated_state();

    let kinds: Vec<&str> = state.tasks().iter().map(|t| t.state.name()).collect();
    for expected in [
        "Open",
        "InProgress",
        "ResultSubmitted",
        "Disputed",
        "Settled",
        "Expired",
    ] {
        assert!(
            kinds.contains(&expected),
            "fixture is missing the {expected} state (has {kinds:?})"
        );
    }

    let bytes = state.encode();
    let back = L2State::decode(&bytes).expect("a faithful encoding must decode");
    assert_eq!(back, state, "decode must reproduce the exact state");
    assert_eq!(back.encode(), bytes, "encode is deterministic");
}

#[test]
fn encoding_is_stable_across_clone_and_reencode() {
    let (state, _) = fully_populated_state();
    let a = state.encode();
    let b = state.clone().encode();
    assert_eq!(a, b, "equal states encode to equal bytes");
    assert_eq!(
        L2State::decode(&a).unwrap().encode(),
        a,
        "re-encoding a decoded state is a fixed point"
    );
}

#[test]
fn a_certificate_round_trips_through_the_state_blob() {
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&wallet(1)), 10_000_000).unwrap();
    state.credit(addr(&wallet(2)), 10_000_000).unwrap();
    let vs = validators();
    let t = compute_task([0x99u8; 32], DEADLINE);
    let p = PostTaskPayload::build(&wallet(1), 1, 1_000_000, DEADLINE, t).unwrap();
    let task_id = p.task_id;
    state
        .apply(&L2Transaction::new(L2Payload::Post(p)), 1, &vs, &RealBls)
        .unwrap();
    state
        .apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&wallet(2), task_id, ComputeBackend::Cpu, 100_000).unwrap(),
            )),
            2,
            &vs,
            &RealBls,
        )
        .unwrap();
    let result = [0xCCu8; 32];
    state
        .apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(
                    &wallet(2),
                    task_id,
                    attestation(&wallet(2), task_id, result),
                )
                .unwrap(),
            )),
            3,
            &vs,
            &RealBls,
        )
        .unwrap();
    // Window elapses → implicit settlement issues a WindowElapsed certificate.
    state.advance_block(3 + L2Config::mini().dispute_window + 1);
    let cert = state.vwc(&task_id).expect("the window certifies").clone();
    assert!(matches!(cert.verification, VwcVerification::WindowElapsed));
    assert!(state.check_conservation());

    let back = L2State::decode(&state.encode()).unwrap();
    assert_eq!(back.vwc(&task_id), Some(&cert));
    assert_eq!(back.vwc_count(), 1);
}

// ---------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------

#[test]
fn a_truncated_blob_produces_no_state() {
    let (state, _) = fully_populated_state();
    let bytes = state.encode();
    for cut in [0usize, 1, bytes.len() / 3, bytes.len() - 1] {
        let out = L2State::decode(&bytes[..cut]);
        assert!(
            out.is_err(),
            "a blob truncated to {cut} bytes must be refused"
        );
    }
}

#[test]
fn trailing_bytes_are_refused_not_ignored() {
    let (state, _) = fully_populated_state();
    let mut bytes = state.encode();
    bytes.push(0);
    assert!(matches!(L2State::decode(&bytes), Err(L2Error::Codec(_))));
}

#[test]
fn an_unsupported_version_is_refused_by_name() {
    use srct_l2::state::L2_STATE_WIRE_VERSION;

    let (state, _) = fully_populated_state();
    let mut bytes = state.encode();
    assert_eq!(bytes[0], L2_STATE_WIRE_VERSION);
    // Current protocol bump: the wire format is version 8 (v8 adds the
    // Phase 2 credit-consent fields and the Phase 3 guarded-account fields
    // to the config section, plus guarded/audit sections at the end).
    assert_eq!(L2_STATE_WIRE_VERSION, 8);
    // v7 is the only accepted predecessor (pre-activation replay decodes v7
    // blobs with zeroed Phase 2/3 config and empty guarded sets); anything
    // else is refused so a stale node cannot hand over state the new chain
    // would silently trust. (v8 is the only version this binary writes.)
    for v in [0u8, 1, 2, 3, 4, 5, 6, 9] {
        bytes[0] = v;
        assert!(
            L2State::decode(&bytes).is_err(),
            "state version {v} must be refused"
        );
    }
}

#[test]
fn an_inflated_account_count_is_refused_before_it_allocates() {
    let (state, _) = fully_populated_state();
    let mut bytes = state.encode();
    // The account count sits right after the fixed header:
    // version(1) + id_len(4) + network_id(11, "srct/mini")
    // + 20·u64 config (9 legacy incl. v6 exit throttle and v7 per-owner
    // sub-cap, plus 11 v8 fields: 4 credit-consent + 7 guarded incl. exit
    // delay and approval tier) + flag(1) + 5·u64 counters = 217.
    let count_at = 217;
    bytes[count_at..count_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(L2State::decode(&bytes).is_err());
}

#[test]
fn a_tampered_counter_that_breaks_conservation_is_refused() {
    let (state, _) = fully_populated_state();
    let mut bytes = state.encode();
    // The funded_total field sits after version + network + config + flag:
    // 1 + 4 + 11 + 160 (9 legacy + 11 v8 u64s) + 1 = 177.
    let funded_at = 177;
    let current = u64::from_le_bytes(bytes[funded_at..funded_at + 8].try_into().unwrap());
    bytes[funded_at..funded_at + 8].copy_from_slice(&(current + 1).to_le_bytes());
    let err = L2State::decode(&bytes).expect_err("inflated funding must be refused");
    assert!(
        err.to_string().contains("conservation"),
        "the refusal names the invariant: {err}"
    );
}

#[test]
fn a_flipped_byte_anywhere_is_refused_or_yields_a_different_state() {
    let (state, _) = fully_populated_state();
    let bytes = state.encode();
    // Flip one byte in the middle of the task section (not the version byte,
    // which has its own test). Either the decoder refuses it, or — if the byte
    // landed in redundant padding-free data — the result must not be the
    // original state.
    let at = bytes.len() / 2;
    let mut mutated = bytes.clone();
    mutated[at] ^= 0xFF;
    match L2State::decode(&mutated) {
        Err(_) => {}
        Ok(other) => assert_ne!(other, state, "a mutated blob must not decode to the source"),
    }
}

#[test]
fn a_task_whose_id_disagrees_with_its_contract_is_refused() {
    let (state, _) = fully_populated_state();
    let bytes = state.encode();
    let back = L2State::decode(&bytes).unwrap();
    for contract in back.tasks() {
        assert!(
            back.task(&contract.task_id).is_some(),
            "every contract is reachable under its own id"
        );
    }
    assert!(!back.tasks().is_empty(), "the fixture really has tasks");
    // The structural check fires: rewrite a task-id *key* so it no longer
    // matches the contract stored under it.
    let mut a = bytes;
    let first_id = state.tasks()[0].task_id;
    if let Some(pos) = a.windows(32).position(|w| w == first_id) {
        a[pos] ^= 0x5A;
        let err = L2State::decode(&a).expect_err("a key/contract mismatch must be refused");
        assert!(
            err.to_string().contains("disagrees"),
            "refusal names the mismatch: {err}"
        );
    }
}

#[test]
fn an_empty_but_well_formed_state_round_trips() {
    let state = L2State::new(L2Config::mini());
    let bytes = state.encode();
    assert_eq!(L2State::decode(&bytes).unwrap(), state);
}

#[test]
fn a_vault_with_records_round_trips() {
    let mut vault = SlashVault::new();
    vault.slash([1u8; 64], 1_000, 5, 100, addr(&wallet(9)));
    let mut w = srct_core::ser::Writer::new();
    w.raw(&vault.encode());
    let bytes = w.into_vec();
    let mut r = srct_core::ser::Reader::new(&bytes);
    let back = SlashVault::decode(&mut r).unwrap();
    assert_eq!(back, vault);
    assert_eq!(back.records().len(), 1);
    assert!(r.expect_end().is_ok());
}
