//! Two-lane peer → main-loop event channel.
//!
//! # Why (mainnet 2026-09-26, "fourth lag mode")
//!
//! Every peer task used to feed ONE bounded FIFO (`mpsc::channel(1024)`) that
//! the single-threaded main loop drains. Under box I/O pressure the main loop
//! handles transaction traffic slower than mainnet produces it, so the FIFO
//! sat full of `tx`/`inv` for many minutes. Measured on the live log as the gap
//! between a peer task's "v2 application handshake COMPLETE" (the task has
//! already enqueued `Connected`) and the main loop's "Peer N connected":
//! routinely 200-680 s, 944 s for peer 316. Everything else waited in the same
//! queue:
//!
//! * the new-tip announcement (`headers` / `inv` / `cmpctblock`) — block
//!   968755 (header time 23:42:28Z) was not processed until 23:58:22Z;
//! * `Disconnected` — dead peer tasks stayed in the peer table for 14 min,
//!   producing the `send_to_peer: command channel closed` storm (3,069 in 30
//!   min) and leaving a dead peer as the header-sync peer;
//! * and because a peer task stops READING its socket while an event is
//!   staged (fPauseRecv-style back-pressure), it also stopped reading `pong`,
//!   so healthy peers were dropped on ping timeout, all at once.
//!
//! Bitcoin Core never lets transaction relay delay block relay: the message
//! handler takes ONE message per peer per round-robin pass, so a peer's
//! `headers` waits behind at most one message of each other peer, not behind
//! a global backlog; and transaction relay is best-effort (TxRequestTracker
//! re-requests from other announcers).
//!
//! # What
//!
//! * **Priority lane** — everything except bulk transaction/address traffic:
//!   lifecycle (`Connected` / `Disconnected` / `Misbehaving`), `headers`,
//!   `cmpctblock`, `block`, `blocktxn`, block `inv`/`getdata`, control
//!   messages. Delivered with back-pressure exactly as before (the peer task
//!   pauses reading while a priority event is staged). The main loop always
//!   drains this lane first ([`EventReceiver::recv`] is `biased`).
//! * **Bulk lane** — `tx`, `addr`/`addrv2`, and `inv`/`getdata` that name only
//!   transactions. Offered with `try_send`: when the lane is full the event is
//!   DROPPED, never staged, so bulk traffic can neither pause the socket read
//!   (the pong keeps flowing) nor delay a block announcement. A dropped `tx`
//!   inv is simply not requested (another peer will announce it, or it
//!   arrives in a block); a dropped `getdata` for our tx is a request the peer
//!   retries elsewhere after its own timeout.
//!
//! Ordering: a task's events within one lane stay FIFO. A `Disconnected` can
//! overtake that peer's own earlier BULK events; the main loop drops bulk
//! messages from a peer it no longer knows.
//!
//! A plain `mpsc::Sender<PeerEvent>` converts into an [`EventSender`] whose two
//! lanes are the same channel (tests and single-channel callers keep their
//! previous behaviour, except that bulk events are dropped rather than staged
//! when that channel is full).

use crate::message::{InvType, InvVector, NetworkMessage};
use crate::peer::PeerEvent;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Capacity of each lane between the peer tasks and the main loop.
pub const EVENT_LANE_CAPACITY: usize = 1024;

fn is_tx_inv(item: &InvVector) -> bool {
    matches!(
        item.inv_type,
        InvType::MsgTx | InvType::MsgWitnessTx | InvType::MsgWtx
    )
}

/// True for events that may be dropped under overload (transaction and
/// address relay). Everything else is chain-critical or lifecycle.
pub fn is_bulk_event(ev: &PeerEvent) -> bool {
    match ev {
        PeerEvent::Message(_, msg) => is_bulk_message(msg),
        _ => false,
    }
}

/// The message-level half of [`is_bulk_event`].
pub fn is_bulk_message(msg: &NetworkMessage) -> bool {
    match msg {
        NetworkMessage::Tx(_) | NetworkMessage::Addr(_) | NetworkMessage::AddrV2(_) => true,
        NetworkMessage::Inv(items) | NetworkMessage::GetData(items) => {
            !items.is_empty() && items.iter().all(is_tx_inv)
        }
        _ => false,
    }
}

/// Outcome of offering a bulk event.
#[derive(Debug, PartialEq, Eq)]
pub enum BulkOffer {
    Delivered,
    /// The bulk lane was full; the event was discarded.
    Dropped,
    /// The receiver is gone (shutdown).
    Closed,
}

/// Sending half: routes each event to its lane.
#[derive(Clone, Debug)]
pub struct EventSender {
    prio: mpsc::Sender<PeerEvent>,
    bulk: mpsc::Sender<PeerEvent>,
    dropped: Arc<AtomicU64>,
}

impl From<mpsc::Sender<PeerEvent>> for EventSender {
    fn from(tx: mpsc::Sender<PeerEvent>) -> Self {
        EventSender {
            prio: tx.clone(),
            bulk: tx,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl EventSender {
    /// Deliver `ev`, waiting for room. Bulk events that find their lane full
    /// are dropped instead of waited for (returns `Ok`).
    pub async fn send(&self, ev: PeerEvent) -> Result<(), mpsc::error::SendError<PeerEvent>> {
        if is_bulk_event(&ev) {
            return match self.offer_bulk(ev) {
                BulkOffer::Closed => Err(mpsc::error::SendError(PeerEvent::Disconnected(
                    crate::peer::PeerId(0),
                    crate::peer::DisconnectReason::PeerRequested,
                ))),
                _ => Ok(()),
            };
        }
        self.prio.send(ev).await
    }

    /// Non-blocking send (routes by lane).
    pub fn try_send(&self, ev: PeerEvent) -> Result<(), mpsc::error::TrySendError<PeerEvent>> {
        if is_bulk_event(&ev) {
            self.bulk.try_send(ev)
        } else {
            self.prio.try_send(ev)
        }
    }

    /// Offer a bulk event without waiting; drop it if the bulk lane is full.
    pub fn offer_bulk(&self, ev: PeerEvent) -> BulkOffer {
        match self.bulk.try_send(ev) {
            Ok(()) => BulkOffer::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() || n % 10_000 == 0 {
                    tracing::warn!(
                        "peer event bulk lane full: dropped {} tx/addr event(s) so far \
                         (main loop behind; block relay unaffected)",
                        n
                    );
                }
                BulkOffer::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(_)) => BulkOffer::Closed,
        }
    }

    /// Reserve a slot on the priority lane (cancel-safe; for `select!`).
    pub async fn reserve_priority(
        &self,
    ) -> Result<mpsc::Permit<'_, PeerEvent>, mpsc::error::SendError<()>> {
        self.prio.reserve().await
    }

    /// Hand every BULK event at the front of `outbox` to the bulk lane
    /// (dropping on overflow) so the front of `outbox`, if any, is a priority
    /// event. Returns `false` if the main loop is gone.
    pub fn flush_bulk_front(&self, outbox: &mut VecDeque<PeerEvent>) -> bool {
        while outbox.front().is_some_and(is_bulk_event) {
            let ev = outbox.pop_front().expect("checked non-empty");
            if self.offer_bulk(ev) == BulkOffer::Closed {
                return false;
            }
        }
        true
    }

    /// Total bulk events dropped through this sender (shared by its clones).
    pub fn dropped_bulk(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.prio.is_closed()
    }
}

/// Receiving half: priority lane first.
#[derive(Debug)]
pub struct EventReceiver {
    prio: mpsc::Receiver<PeerEvent>,
    bulk: mpsc::Receiver<PeerEvent>,
}

impl EventReceiver {
    /// Next event, priority lane first. Cancel-safe (both arms are
    /// `mpsc::Receiver::recv`). `None` once both lanes are closed and empty.
    pub async fn recv(&mut self) -> Option<PeerEvent> {
        tokio::select! {
            biased;
            Some(ev) = self.prio.recv() => Some(ev),
            Some(ev) = self.bulk.recv() => Some(ev),
            else => None,
        }
    }

    /// Non-blocking receive, priority lane first.
    pub fn try_recv(&mut self) -> Result<PeerEvent, mpsc::error::TryRecvError> {
        match self.prio.try_recv() {
            Ok(ev) => Ok(ev),
            Err(_) => self.bulk.try_recv(),
        }
    }
}

/// Create the two-lane channel.
pub fn event_channel(capacity: usize) -> (EventSender, EventReceiver) {
    let (ptx, prx) = mpsc::channel(capacity);
    let (btx, brx) = mpsc::channel(capacity);
    (
        EventSender {
            prio: ptx,
            bulk: btx,
            dropped: Arc::new(AtomicU64::new(0)),
        },
        EventReceiver {
            prio: prx,
            bulk: brx,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{DisconnectReason, PeerId};
    use rustoshi_primitives::{BlockHeader, Hash256, Transaction};

    fn tx_msg(p: u64) -> PeerEvent {
        PeerEvent::Message(
            PeerId(p),
            NetworkMessage::Tx(Transaction {
                version: 2,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            }),
        )
    }

    fn tx_inv(p: u64, n: u8) -> PeerEvent {
        PeerEvent::Message(
            PeerId(p),
            NetworkMessage::Inv(vec![InvVector {
                inv_type: InvType::MsgWtx,
                hash: Hash256([n; 32]),
            }]),
        )
    }

    fn headers_msg(p: u64) -> PeerEvent {
        PeerEvent::Message(PeerId(p), NetworkMessage::Headers(vec![BlockHeader::default()]))
    }

    #[test]
    fn classification() {
        assert!(is_bulk_event(&tx_msg(1)));
        assert!(is_bulk_event(&tx_inv(1, 1)));
        assert!(!is_bulk_event(&headers_msg(1)));
        let mixed = PeerEvent::Message(
            PeerId(1),
            NetworkMessage::Inv(vec![
                InvVector { inv_type: InvType::MsgWtx, hash: Hash256([1; 32]) },
                InvVector { inv_type: InvType::MsgBlock, hash: Hash256([2; 32]) },
            ]),
        );
        assert!(!is_bulk_event(&mixed), "an inv naming a block is priority");
        assert!(!is_bulk_event(&PeerEvent::Disconnected(PeerId(1), DisconnectReason::Timeout)));
        let block_getdata = PeerEvent::Message(
            PeerId(1),
            NetworkMessage::GetData(vec![InvVector {
                inv_type: InvType::MsgWitnessBlock,
                hash: Hash256([3; 32]),
            }]),
        );
        assert!(!is_bulk_event(&block_getdata));
    }

    /// The LAG-4 property: with the bulk lane saturated by transaction
    /// traffic, a block announcement and a Disconnected are the NEXT things
    /// the main loop sees — not the 1025th.
    #[tokio::test]
    async fn priority_events_overtake_a_saturated_bulk_backlog() {
        let (tx, mut rx) = event_channel(64);
        for i in 0..64u8 {
            tx.send(tx_inv(1, i)).await.unwrap();
        }
        // Overflow is dropped, not queued and not blocking.
        assert_eq!(tx.offer_bulk(tx_msg(1)), BulkOffer::Dropped);
        assert_eq!(tx.dropped_bulk(), 1);
        tx.send(headers_msg(2)).await.unwrap();
        tx.send(PeerEvent::Disconnected(PeerId(3), DisconnectReason::Timeout))
            .await
            .unwrap();

        match rx.recv().await {
            Some(PeerEvent::Message(PeerId(2), NetworkMessage::Headers(_))) => {}
            other => panic!("expected the headers announcement first, got {other:?}"),
        }
        match rx.recv().await {
            Some(PeerEvent::Disconnected(PeerId(3), _)) => {}
            other => panic!("expected Disconnected second, got {other:?}"),
        }
        let mut bulk = 0;
        while let Ok(ev) = rx.try_recv() {
            assert!(is_bulk_event(&ev));
            bulk += 1;
        }
        assert_eq!(bulk, 64);
    }

    #[test]
    fn flush_bulk_front_leaves_a_priority_event_at_the_front() {
        let (tx, _rx) = event_channel(2);
        let mut outbox: VecDeque<PeerEvent> =
            vec![tx_inv(1, 1), tx_inv(1, 2), tx_inv(1, 3), headers_msg(1), tx_msg(1)].into();
        assert!(tx.flush_bulk_front(&mut outbox));
        assert_eq!(outbox.len(), 2);
        assert!(!is_bulk_event(outbox.front().unwrap()));
        assert_eq!(tx.dropped_bulk(), 1, "third bulk event overflowed the 2-slot lane");
    }
}
