//! cffix-rustoshi-event-lane-byte-budget: the peer -> main-loop lanes must be
//! bounded by the bytes they hold, not only by their 2 x 1024 slot count.
//!
//! Peer tasks decode a frame fully before queueing it, so a lane slot holds
//! the DECODED message. A 4,000,000-byte `tx` whose one input carries
//! 3,999,933 empty witness items decodes to ~96 MB (one 24-byte `Vec` header
//! per item), so 1024 bulk slots could retain ~96 GB while the main loop is
//! behind -- and the main loop being behind for minutes is the documented
//! normal overload state (event_lane.rs module docs, 2026-09-26). Core never
//! queues decoded messages: `CNode::MarkReceivedMsgsForProcessing` sets
//! `fPauseRecv` once a peer's queued bytes exceed `-maxreceivebuffer`
//! (net.cpp), and decoding happens serially in the message handler.
//!
//! The receiver below is held but never drained (the main loop is stalled).

use rustoshi_network::event_lane::{event_channel, BulkOffer, EVENT_LANE_CAPACITY};
use rustoshi_network::{NetworkMessage, PeerEvent, PeerId};

const FIXTURE_ITEMS: u32 = 3_999_933;

/// The audit fixture: a 4,000,000-byte segwit tx, one input, 3,999,933 empty
/// witness items.
fn fixture_payload() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&2i32.to_le_bytes());
    b.extend_from_slice(&[0x00, 0x01]);
    b.push(1);
    b.extend_from_slice(&[0x11; 32]);
    b.extend_from_slice(&0u32.to_le_bytes());
    b.push(0);
    b.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    b.push(1);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.push(0);
    b.push(0xfe);
    b.extend_from_slice(&FIXTURE_ITEMS.to_le_bytes());
    b.extend(std::iter::repeat_n(0u8, FIXTURE_ITEMS as usize));
    b.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(b.len(), 4_000_000);
    b
}

fn rss_bytes() -> usize {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: usize = statm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    pages * 4096
}

/// Eight decoded copies of the fixture offered to a stalled bulk lane. Master
/// accepts all eight (~768 MB retained by a lane whose count limit is 1024);
/// the bulk lane must refuse once its byte budget is spent. Asserted bound:
/// at most 256 MiB of decoded fixture retained (2 copies).
#[tokio::test]
async fn bulk_lane_refuses_decoded_bytes_beyond_budget() {
    let payload = fixture_payload();
    let (tx, rx) = event_channel(EVENT_LANE_CAPACITY);
    let rss0 = rss_bytes();
    let mut delivered = 0usize;
    for _ in 0..8 {
        // Decode per copy, exactly as a peer task does before queueing.
        let msg = NetworkMessage::deserialize("tx", &payload).expect("fixture decodes");
        if let NetworkMessage::Tx(t) = &msg {
            assert!(t.inputs[0].witness.capacity() >= FIXTURE_ITEMS as usize);
        } else {
            panic!("not a tx");
        }
        match tx.offer_bulk(PeerEvent::Message(PeerId(1), msg)) {
            BulkOffer::Delivered => delivered += 1,
            BulkOffer::Dropped => {}
            BulkOffer::Closed => panic!("receiver is alive"),
        }
    }
    let rss1 = rss_bytes();
    eprintln!(
        "MEASURE bulk lane: delivered {}/8 decoded 4 MB fixtures, backlog {}, \
         RSS delta {} MiB",
        delivered,
        rx.bulk_backlog(),
        rss1.saturating_sub(rss0) >> 20
    );
    assert!(
        delivered <= 2,
        "stalled bulk lane retained {} decoded ~96 MB fixtures (~{} MiB); the lane \
         must carry a byte budget",
        delivered,
        delivered * 96
    );
    drop(rx);
}

/// The priority lane keeps back-pressure (the peer task stops reading), but
/// it too must stop accepting once its byte budget is spent: a stalled loop
/// must not retain 1024 slots x a decoded block. Capacity-only `Vec`s keep
/// the test cheap (the pages are never touched). Asserted bound: at most
/// 1 GiB of priority-lane payload retained.
#[tokio::test]
async fn priority_lane_stops_at_byte_budget() {
    const EACH: usize = 128 << 20;
    let (tx, rx) = event_channel(EVENT_LANE_CAPACITY);
    let mut accepted = 0usize;
    for _ in 0..12 {
        let ev = PeerEvent::Message(
            PeerId(2),
            NetworkMessage::CmpctBlock(Vec::with_capacity(EACH)),
        );
        if tx.try_send(ev).is_ok() {
            accepted += 1;
        }
    }
    eprintln!("MEASURE priority lane: accepted {}/12 x 128 MiB", accepted);
    assert!(
        accepted * EACH <= 1 << 30,
        "stalled priority lane retained {} x 128 MiB",
        accepted
    );
    assert!(accepted >= 1, "a single event must always fit");
    drop(rx);
}

/// Draining releases the budget: after the main loop takes the queued
/// events, the lane accepts the same load again.
#[tokio::test]
async fn draining_releases_the_budget() {
    const EACH: usize = 128 << 20;
    let (tx, mut rx) = event_channel(EVENT_LANE_CAPACITY);
    let fill = |tx: &rustoshi_network::event_lane::EventSender| {
        let mut n = 0;
        for _ in 0..12 {
            let ev = PeerEvent::Message(
                PeerId(3),
                NetworkMessage::CmpctBlock(Vec::with_capacity(EACH)),
            );
            if tx.try_send(ev).is_ok() {
                n += 1;
            }
        }
        n
    };
    let first = fill(&tx);
    for _ in 0..first {
        rx.recv().await.expect("queued event");
    }
    let second = fill(&tx);
    assert_eq!(first, second, "drained budget must be reusable");
    // Small events are never refused while the lane is under budget.
    for _ in 0..first {
        rx.recv().await.expect("queued event");
    }
    for _ in 0..100 {
        tx.try_send(PeerEvent::Message(PeerId(3), NetworkMessage::Ping(1)))
            .expect("small event fits");
    }
}

/// An unrecognised command keeps its whole payload and rides the priority
/// lane, so it must be charged for that payload like any other message (a
/// wildcard `0` let 1024 x 4 MB unknown frames through on slot count alone).
/// Capacity-only payloads keep the test cheap. Asserted bound: at most 1 GiB.
#[tokio::test]
async fn priority_lane_charges_unknown_command_payload() {
    const EACH: usize = 128 << 20;
    let (tx, rx) = event_channel(EVENT_LANE_CAPACITY);
    let mut accepted = 0usize;
    for _ in 0..12 {
        let ev = PeerEvent::Message(
            PeerId(4),
            NetworkMessage::Unknown {
                command: "madeup".to_string(),
                payload: Vec::with_capacity(EACH),
            },
        );
        if tx.try_send(ev).is_ok() {
            accepted += 1;
        }
    }
    eprintln!(
        "MEASURE priority lane unknown: accepted {}/12 x 128 MiB",
        accepted
    );
    assert!(
        accepted * EACH <= 1 << 30,
        "stalled priority lane retained {} x 128 MiB unknown-command payloads",
        accepted
    );
    drop(rx);
}
