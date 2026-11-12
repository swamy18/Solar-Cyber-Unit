//! Acceptance tests for presence, acknowledgements, fan-out and the
//! HTTP/MCP transport codecs.

use srct_agentnet::http::{DeliverRequest, DeliverResponse, PollRequest, PollResponse};
use srct_agentnet::presence::{fanout_targets, AckSet, PresenceBook};
use srct_core::agent::AgentId;

fn agent(n: u8) -> AgentId {
    [n; 20]
}

#[test]
fn presence_tracks_liveness_and_prunes_ghosts() {
    let mut book = PresenceBook::new();
    assert!(book.is_empty());
    book.heartbeat(agent(1), "phone", 10).unwrap();
    book.heartbeat(agent(1), "laptop", 12).unwrap();
    book.heartbeat(agent(2), "server", 5).unwrap();
    // ttl 5 at height 12: phone (10) and laptop (12) live, server (5) stale.
    assert_eq!(
        book.devices_for(&agent(1), 12, 5),
        vec!["laptop".to_string(), "phone".to_string()]
    );
    assert!(book.devices_for(&agent(2), 12, 5).is_empty());
    assert!(book.prune(12, 5) == 1);
    assert!(book.devices_for(&agent(2), 12, 100).is_empty());
    // Empty labels and over-long labels are refused.
    assert!(book.heartbeat(agent(1), "", 13).is_err());
    assert!(book.heartbeat(agent(1), "x".repeat(65), 13).is_err());
}

#[test]
fn fanout_targets_every_live_device_once() {
    let devices = vec!["phone".to_string(), "laptop".to_string()];
    let targets = fanout_targets(&agent(7), &devices);
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&(agent(7), "phone".to_string())));
    assert!(targets.contains(&(agent(7), "laptop".to_string())));
    assert!(fanout_targets(&agent(7), &[]).is_empty());
}

#[test]
fn acks_confirm_once_and_replay_is_free() {
    let mut acks = AckSet::new();
    assert!(acks.is_empty());
    assert!(acks.ack([1u8; 32]));
    assert!(!acks.ack([1u8; 32]));
    assert!(acks.is_acked(&[1u8; 32]));
    assert!(!acks.is_acked(&[2u8; 32]));
    assert_eq!(acks.len(), 1);
    assert_eq!(acks.acked_in_order(), &[[1u8; 32]]);
}

#[test]
fn transport_codecs_round_trip_and_refuse_tamper() {
    let deliver = DeliverRequest {
        version: srct_agentnet::http::HTTP_CODEC_VERSION,
        recipient: agent(3),
        envelope: vec![9u8; 64],
    };
    assert_eq!(DeliverRequest::decode(&deliver.encode()).unwrap(), deliver);
    let mut bad = deliver.encode();
    bad[0] = 99;
    assert!(DeliverRequest::decode(&bad).is_err());
    assert!(DeliverRequest::decode(&deliver.encode()[..10]).is_err());

    let response = DeliverResponse {
        version: srct_agentnet::http::HTTP_CODEC_VERSION,
        accepted: vec![[1u8; 32], [2u8; 32]],
        refused: 1,
    };
    assert_eq!(
        DeliverResponse::decode(&response.encode()).unwrap(),
        response
    );

    let poll = PollRequest {
        version: srct_agentnet::http::HTTP_CODEC_VERSION,
        agent: agent(4),
        since_height: 90,
        limit: 32,
    };
    assert_eq!(PollRequest::decode(&poll.encode()).unwrap(), poll);

    let listing = PollResponse {
        version: srct_agentnet::http::HTTP_CODEC_VERSION,
        messages: vec![vec![7u8; 40], vec![8u8; 40]],
    };
    assert_eq!(PollResponse::decode(&listing.encode()).unwrap(), listing);
    let mut bad = listing.encode();
    bad[0] = 99;
    assert!(PollResponse::decode(&bad).is_err());
    assert!(PollResponse::decode(&listing.encode()[..6]).is_err());
}
