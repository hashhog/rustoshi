//! cffix-rustoshi-event-lane-byte-budget: the priority lane's byte charge
//! must survive `select!` cancellation.
//!
//! The peer loops rebuild their `select!` arms on every pass. An acquire
//! that lived in an arm would be dropped each time the command arm or the
//! ping timer fired, losing its FIFO place, so a large staged event could be
//! starved while its socket stays paused. `StagedCharge` owns the acquire
//! across passes.
//!
//! This file tests API the fix adds (`StagedCharge`), so it does not build
//! on master. The tests that fail on master by name are in
//! `test_cffix_event_lane_byte_budget.rs` and
//! `crates/primitives/tests/test_cffix_witness_reserve.rs`.

use rustoshi_network::event_lane::{
    event_channel, event_cost, StagedCharge, EVENT_LANE_CAPACITY, PRIORITY_LANE_BYTE_BUDGET,
};
use rustoshi_network::{NetworkMessage, PeerEvent, PeerId};
use std::time::Duration;

fn big(p: u64, bytes: usize) -> PeerEvent {
    // Capacity-only: charged by capacity, pages never touched.
    PeerEvent::Message(
        PeerId(p),
        NetworkMessage::CmpctBlock(Vec::with_capacity(bytes)),
    )
}

/// A staged charge whose `wait()` is cancelled over and over (another
/// `select!` arm firing in the peer loop) must keep its queue place: it is
/// satisfied before a waiter that queued after it, even though that later
/// waiter is never cancelled. Rebuilding the acquire on every pass would
/// drop the waiter and could starve a large staged event. (Exercises the
/// head's `StagedCharge`; master has no byte budget at all.)
#[tokio::test]
async fn staged_charge_keeps_its_place_across_cancelled_waits() {
    const EACH: usize = 128 << 20;
    let (tx, mut rx) = event_channel(EVENT_LANE_CAPACITY);
    let mut filled = 0;
    while tx.try_send(big(1, EACH)).is_ok() {
        filled += 1;
    }
    assert!(filled >= 4, "budget should hold several 128 MiB events");

    // A queues first, for half the budget.
    let a = big(2, PRIORITY_LANE_BYTE_BUDGET / 2);
    let mut staged = StagedCharge::default();
    staged.start(&tx, event_cost(&a));
    assert!(staged.is_waiting());
    assert!(
        tokio::time::timeout(Duration::from_millis(5), staged.wait())
            .await
            .is_err(),
        "lane is full: A must wait"
    );

    // B queues second, for the same amount, and is never cancelled.
    let tx_b = tx.clone();
    let b = tokio::spawn(async move {
        let _ = tx_b.send(big(3, PRIORITY_LANE_BYTE_BUDGET / 2)).await;
    });
    tokio::task::yield_now().await;

    // The main loop drains filler events one at a time; between drains A is
    // polled and cancelled again.
    for _ in 0..filled {
        match rx.try_recv() {
            Ok(PeerEvent::Message(PeerId(1), _)) => {}
            Ok(_) => panic!("expected a filler event"),
            Err(e) => panic!("expected a filler event, got {e:?}"),
        }
        let _ = tokio::time::timeout(Duration::from_millis(2), staged.wait()).await;
        if staged.is_held() {
            break;
        }
    }
    assert!(staged.is_held(), "A never got its charge");
    assert!(!b.is_finished(), "B (queued after A) was served first");
    let permit = tx.reserve_priority().await.unwrap();
    permit.send(a, &mut staged);
    assert!(staged.is_idle());
    drop(rx);
    let _ = b.await;
}

/// The charge travels with the event and is returned when the main loop
/// takes it, not before.
#[tokio::test]
async fn staged_charge_is_released_on_receive() {
    let (tx, mut rx) = event_channel(EVENT_LANE_CAPACITY);
    let ev = big(1, PRIORITY_LANE_BYTE_BUDGET);
    let mut staged = StagedCharge::default();
    staged.start(&tx, event_cost(&ev));
    staged.wait().await;
    tx.reserve_priority().await.unwrap().send(ev, &mut staged);
    // The whole budget is now in the lane: nothing else fits.
    assert!(tx
        .try_send(PeerEvent::Message(PeerId(2), NetworkMessage::Ping(1)))
        .is_err());
    rx.recv().await.unwrap();
    tx.try_send(PeerEvent::Message(PeerId(2), NetworkMessage::Ping(1)))
        .expect("budget released on receive");
}
