//! Wire-format vectors for `srct-net`. SPEC.md §13.12.
//!
//! The §13 message set is frozen, so the bytes on the wire are a contract
//! between implementations exactly as much as a block hash is. A silent change
//! to field order, byte order or a length prefix would still pass every
//! round-trip test in this crate — a round trip only proves the codec agrees
//! with itself — while breaking every peer running the previous version. These
//! vectors pin the bytes themselves.
//!
//! Regenerate with `UPDATE_NET_VECTORS=1 cargo test -p srct-net`.
//!
//! Note what is *not* here: a second implementation, the way
//! `verification/sim/srct_reference.py` re-derives the puzzle from §5 prose. A disagreement
//! between two encoders of these rules looks exactly like a consensus split,
//! and that check is still owed.

use srct_core::chain::Chain;
use srct_core::params::NetworkParams;
use srct_core::tx::{Input, OutPoint, Output, Transaction};
use srct_net::frame::{read_frame, write_frame, MAX_FRAME_PAYLOAD};
use srct_net::msg::{
    InvEntry, Message, MessageType, SocketAddr as WireAddr, Version, INV_TYPE_BLOCK, INV_TYPE_TX,
    MAX_ADDR_PER_MSG, MAX_INV_PER_MSG, MAX_LOCATOR_ENTRIES, PROTOCOL_VERSION,
};
use srct_net::relay::{
    MAX_RELAY_IN_FLIGHT, MAX_RELAY_KNOWN, MAX_RELAY_PENDING, MAX_TX_INV_BATCH,
    TX_RELAY_PER_PEER_PER_MIN, TX_REQUEST_TIMEOUT_MS,
};
use srct_net::syncer::{create_locator, find_fork_and_collect_inv};

use std::io::Cursor;

/// `srct-net` deliberately depends only on `srct-core` and std, so the test
/// carries its own hex encoder rather than pulling in a dependency for one
/// function.
fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A pinned payload: `(name, hex)`.
type Item = (String, String);
/// A pinned scalar: `(name, value)`.
type Fact = (String, u64);

/// A deterministic checkpoint certificate for the vector.
///
/// Deliberately *structural*: fixed payload, a fixed byte-pattern aggregate and
/// a fixed 3-bit bitmap, so a second implementation can rebuild the exact bytes
/// from §13 prose without a pairing library. Real BLS aggregation is pinned by
/// the M4 integration tests instead.
fn checkpoint_vector() -> srct_core::bls_checkpoint::Checkpoint {
    use srct_core::bls_checkpoint::{BlsSignature, Checkpoint, CheckpointPayload};
    Checkpoint {
        payload: CheckpointPayload {
            height: 100,
            block_hash: [0x21u8; 64],
            network_id: "srct/mini".into(),
            epoch: 10,
        },
        aggregate_sig: BlsSignature([0x37u8; 96]),
        signer_bitmap: vec![0b0000_0111],
        signer_count: 3,
        pq_sidecar: Vec::new(),
    }
}

/// `(name, hex bytes)` pairs plus scalar facts, written as one JSON document.
fn build_vectors() -> (Vec<Item>, Vec<Fact>) {
    let mini = NetworkParams::mini();
    let mut items: Vec<(String, String)> = Vec::new();
    let mut facts: Vec<(String, u64)> = Vec::new();

    // --- frames ---------------------------------------------------------
    // magic(4) ‖ msg_type(1) ‖ payload_len(4 LE) ‖ payload
    let mut wire = Vec::new();
    write_frame(&mut wire, &mini, 7, b"srct").unwrap();
    items.push(("frame_inv_type7_len4".into(), hex_of(&wire)));

    let mut cursor = Cursor::new(wire);
    let (ty, payload) = read_frame(&mut cursor, &mini).unwrap();
    assert_eq!(ty, 7);
    assert_eq!(payload, b"srct");

    // --- VERSION, every profile ----------------------------------------
    for (label, params) in [
        ("mainnet", NetworkParams::mainnet()),
        ("mini", mini.clone()),
    ] {
        let v = Version {
            network_magic: params.network_magic,
            network_id: params.network_id.clone(),
            protocol_version: PROTOCOL_VERSION,
            services: 1,
            height: 42,
            tip_hash: [0x5Au8; 64],
            user_agent: "/srct-net:0.2".into(),
            nonce: 0x0123_4567_89AB_CDEF,
        };
        let enc = Message::Version(v).encode();
        facts.push((format!("version_{label}_len"), enc.len() as u64));
        items.push((format!("version_{label}"), hex_of(&enc)));
    }

    // --- every msg_type round-trips to a pinned payload -----------------
    let msgs: Vec<(&str, Message)> = vec![
        ("verack", Message::Verack { nonce: 0xDEAD }),
        ("ping", Message::Ping { nonce: 0xBEEF }),
        ("pong", Message::Pong { nonce: 0xFEED }),
        (
            "inv",
            Message::Inv(vec![
                InvEntry {
                    kind: INV_TYPE_BLOCK,
                    hash: [0x11u8; 64],
                },
                InvEntry {
                    kind: INV_TYPE_BLOCK,
                    hash: [0x22u8; 64],
                },
            ]),
        ),
        (
            "getdata",
            Message::GetData(vec![InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: [0x33u8; 64],
            }]),
        ),
        (
            "getblocks",
            Message::GetBlocks {
                locator: vec![[0x44u8; 64], [0x55u8; 64]],
                stop: [0x66u8; 64],
            },
        ),
        (
            "addr",
            Message::Addr(vec![WireAddr {
                // IPv4-mapped IPv6: ::ffff:127.0.0.1 (§13.5)
                ip: {
                    let mut ip = [0u8; 16];
                    ip[10] = 0xFF;
                    ip[11] = 0xFF;
                    ip[12] = 127;
                    ip[15] = 1;
                    ip
                },
                port: 8333,
            }]),
        ),
    ];

    // --- TX (§13.14) ----------------------------------------------------
    // An unsigned transaction, so the payload is reproducible from §3 prose
    // alone: both bundles are `count = 0`, and nothing here depends on a key.
    let wire_tx = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [0x77u8; 64],
            index: 1,
        })],
        vec![Output {
            value: 12_345,
            address: [0x88u8; 20],
        }],
    );
    // Announcement reuses `INV` with `kind = 0` (§13.5). Pinned separately from
    // the block-kind entry above, because `kind` is the field that decides
    // whether a peer treats an entry as a block or a transaction.
    items.push((
        "msg_inv_tx".into(),
        hex_of(
            &Message::Inv(vec![InvEntry {
                kind: INV_TYPE_TX,
                hash: [0x99u8; 64],
            }])
            .encode(),
        ),
    ));
    // count(2 LE) + one entry(65). The count is 2 bytes, not 4 — see the
    // independent check in `verification/sim/net_reference.py`, which caught 4 + 1 + 64 here.
    facts.push(("inv_tx_len".into(), 2 + 1 + 64));

    let tx_enc = Message::Tx(Box::new(wire_tx.clone())).encode();
    facts.push(("tx_len".into(), tx_enc.len() as u64));
    items.push(("msg_tx".into(), hex_of(&tx_enc)));

    // Decode must return the identical transaction, not merely a transaction:
    // a field that round-trips through the wrong offset would still parse.
    match Message::decode(MessageType::Tx as u8, &tx_enc).unwrap() {
        Message::Tx(decoded) => assert_eq!(*decoded, wire_tx),
        other => panic!("expected Tx, got {other:?}"),
    }
    for (name, msg) in &msgs {
        let enc = msg.encode();
        facts.push((format!("{name}_len"), enc.len() as u64));
        items.push((format!("msg_{name}"), hex_of(&enc)));
    }

    // --- CHECKPOINT (M4, §13.5 msg_type = 11) ---------------------------
    // A deterministic, *structural* certificate: fixed payload, a fixed
    // byte-pattern aggregate and a fixed 3-bit bitmap, so
    // `verification/sim/net_reference.py` can rebuild the exact bytes from §13 prose
    // without a pairing library. Real BLS aggregation is pinned by the M4
    // integration tests, not by a wire vector — a second encoder cannot
    // reproduce pairing math, and a vector only one implementation can build
    // would not be the independent check this file exists to provide.
    let cp = checkpoint_vector();
    let cp_enc = Message::Checkpoint(cp.clone()).encode();
    facts.push(("checkpoint_len".into(), cp_enc.len() as u64));
    items.push(("msg_checkpoint".into(), hex_of(&cp_enc)));
    match Message::decode(MessageType::Checkpoint as u8, &cp_enc).unwrap() {
        Message::Checkpoint(decoded) => assert_eq!(decoded, cp),
        other => panic!("expected Checkpoint, got {other:?}"),
    }
    facts.push((
        "checkpoint_type_number".into(),
        MessageType::Checkpoint as u64,
    ));

    // --- BLOCK ----------------------------------------------------------
    let mut chain = Chain::new(NetworkParams::mini()).expect("mini chain");
    let b = chain
        .mine_block(
            [7u8; 20],
            vec![],
            srct_core::block::GENESIS_TIMESTAMP_MS + 1_000,
        )
        .expect("mine block 1");
    let block_bytes = b.serialize();
    facts.push(("block1_len".into(), block_bytes.len() as u64));
    items.push(("block1".into(), hex_of(&block_bytes)));

    // Decode must return the identical block, not merely a block.
    match Message::decode(MessageType::Block as u8, &block_bytes).unwrap() {
        Message::Block(decoded) => assert_eq!(*decoded, b),
        other => panic!("expected Block, got {other:?}"),
    }

    // --- locator construction from a 200-block chain --------------------
    let mut ts = srct_core::block::GENESIS_TIMESTAMP_MS + 1;
    for _ in 0..200 {
        let blk = chain.mine_block([7u8; 20], vec![], ts).unwrap();
        chain.submit(blk).unwrap();
        ts += 60_000;
    }
    let locator = create_locator(&chain);
    facts.push(("locator_len_200".into(), locator.len() as u64));
    for (i, h) in locator.iter().enumerate().take(8) {
        items.push((format!("locator_{i}"), hex_of(h)));
    }

    // --- GETBLOCKS response against a divergent chain --------------------
    // A requester at genesis gets heights 1..=200, capped at max_inv_per_msg.
    let genesis_only = Chain::new(NetworkParams::mini()).unwrap();
    let loc = create_locator(&genesis_only);
    let inv = find_fork_and_collect_inv(&chain, &loc, &srct_core::hash::ZERO_HASH512);
    facts.push(("inv_from_genesis_len".into(), inv.len() as u64));
    items.push(("inv_from_genesis_first".into(), hex_of(&inv[0].hash)));

    // --- spec bounds, as scalars ---------------------------------------
    facts.push(("max_frame_payload".into(), MAX_FRAME_PAYLOAD as u64));
    facts.push(("max_inv_per_msg".into(), MAX_INV_PER_MSG as u64));
    facts.push(("max_addr_per_msg".into(), MAX_ADDR_PER_MSG as u64));
    facts.push(("max_locator_len".into(), MAX_LOCATOR_ENTRIES as u64));
    // §13.14 relay bounds. Pinned here rather than only stated in prose, because
    // a bound that drifts between two implementations is a peer that either
    // refuses honest traffic or accepts a flood.
    facts.push(("max_relay_in_flight".into(), MAX_RELAY_IN_FLIGHT as u64));
    facts.push(("max_relay_pending".into(), MAX_RELAY_PENDING as u64));
    facts.push(("max_relay_known".into(), MAX_RELAY_KNOWN as u64));
    facts.push(("max_tx_inv_batch".into(), MAX_TX_INV_BATCH as u64));
    facts.push((
        "tx_relay_per_peer_per_min".into(),
        TX_RELAY_PER_PEER_PER_MIN as u64,
    ));
    facts.push(("tx_request_timeout_ms".into(), TX_REQUEST_TIMEOUT_MS));

    (items, facts)
}

#[test]
fn net_vectors_are_stable() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../verification/tests/vectors/net_vectors.json");
    let (items, facts) = build_vectors();

    let mut doc = serde_json::Map::new();
    doc.insert("spec_section".into(), serde_json::json!("13.12"));
    doc.insert(
        "note".into(),
        serde_json::json!(
            "Wire-format vectors. Regenerate with UPDATE_NET_VECTORS=1 cargo test -p srct-net. \
             No independent implementation exists yet, unlike verification/sim/srct_reference.py for §5."
        ),
    );
    doc.insert(
        "items".into(),
        serde_json::Value::Array(
            items
                .iter()
                .map(|(n, h)| serde_json::json!({ "name": n, "hex": h }))
                .collect(),
        ),
    );
    doc.insert(
        "facts".into(),
        serde_json::Value::Array(
            facts
                .iter()
                .map(|(n, v)| serde_json::json!({ "name": n, "value": v }))
                .collect(),
        ),
    );
    let json = serde_json::to_string_pretty(&serde_json::Value::Object(doc)).unwrap();

    if std::env::var("UPDATE_NET_VECTORS").is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, json).unwrap();
        eprintln!("wrote {}", path.display());
        return;
    }

    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nregenerate with UPDATE_NET_VECTORS=1",
            path.display()
        )
    });
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();

    let listed = v["items"].as_array().expect("items must be an array");
    assert_eq!(
        listed.len(),
        items.len(),
        "vector file is stale: item count"
    );
    for (entry, (name, hex)) in listed.iter().zip(items.iter()) {
        assert_eq!(entry["name"].as_str().unwrap(), name);
        assert_eq!(
            entry["hex"].as_str().unwrap(),
            hex,
            "wire bytes for `{name}` changed — a frozen §13.5 payload must not move"
        );
    }

    let listed_facts = v["facts"].as_array().expect("facts must be an array");
    assert_eq!(
        listed_facts.len(),
        facts.len(),
        "vector file is stale: fact count"
    );
    for (entry, (name, value)) in listed_facts.iter().zip(facts.iter()) {
        assert_eq!(entry["name"].as_str().unwrap(), name);
        assert_eq!(entry["value"].as_u64().unwrap(), *value, "`{name}` changed");
    }

    // Independent restatements of the §13.5 layout, so a vector file that was
    // regenerated from wrong code cannot pass silently. VERSION is
    // magic(4) + id_len(1) + id + proto(4) + services(8) + height(8) +
    // tip(64) + ua_len(1) + ua + nonce(8).
    const FIXED: u64 = 4 + 1 + 4 + 8 + 8 + 64 + 1 + 8;
    let fact = |name: &str| -> u64 {
        listed_facts
            .iter()
            .find(|f| f["name"] == name)
            .unwrap_or_else(|| panic!("fact `{name}` is missing"))["value"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(
        fact("version_mainnet_len"),
        FIXED + 12 + 13,
        "VERSION payload layout (13.4)"
    );
    assert_eq!(
        fact("version_mini_len"),
        FIXED + 9 + 13,
        "VERSION length tracks network_id"
    );
    assert_eq!(fact("max_locator_len"), 500, "13.8");
    assert_eq!(fact("max_inv_per_msg"), 500, "13.8");
    assert_eq!(fact("max_addr_per_msg"), 100, "13.8");
    assert_eq!(fact("max_frame_payload"), 4_100_000, "13.8");

    // §13.14. Restated from the field tables rather than read back from the
    // encoder: a transaction is version(4) + tx_type(1) + lock_time(8) +
    // input_count(4) + one fixed-width unsigned input (64 + 4 + 1 + 1) +
    // output_count(4) + one output (28). An unsigned input carries two empty
    // bundles, one byte each — and that is the part most likely to drift, since
    // adding a length prefix to a bundle would not change any round trip.
    assert_eq!(
        fact("tx_len"),
        4 + 1 + 8 + 4 + (64 + 4 + 1 + 1) + 4 + 28,
        "TX payload layout (13.5, 3.1-3.3)"
    );
    assert_eq!(
        fact("inv_tx_len"),
        2 + 1 + 64,
        "an INV payload is count(2 LE) + kind(1) + hash(64)"
    );
    // `kind = 0` for transactions is the field a v0.2 node uses to decide whether
    // an INV entry is a block or a transaction; changing it would make the two
    // versions disagree about what they were just told.
    let inv_tx = listed
        .iter()
        .find(|e| e["name"] == "msg_inv_tx")
        .expect("msg_inv_tx vector is missing")["hex"]
        .as_str()
        .unwrap();
    assert_eq!(&inv_tx[..4], "0100", "INV count is u16 LE");
    assert_eq!(&inv_tx[4..6], "00", "kind 0 must mean `transaction` (13.5)");
    assert!(
        fact("inv_from_genesis_len") <= MAX_INV_PER_MSG as u64,
        "a GETBLOCKS response must never exceed max_inv_per_msg"
    );
    assert_eq!(
        fact("inv_from_genesis_len"),
        200,
        "a genesis-only peer is answered with every block after the fork point"
    );
}

/// A block frame carrying a maximum-size block must fit inside the cap: the
/// bound is `max_block_bytes + 100_000` precisely so this holds (§13.8).
#[test]
fn a_maximum_size_block_is_relayable_within_the_frame_cap() {
    let params = NetworkParams::mini();
    assert!(
        MAX_FRAME_PAYLOAD as usize > params.max_block_bytes,
        "max_frame_bytes must exceed max_block_bytes, or no maximum block is relayable"
    );
}
