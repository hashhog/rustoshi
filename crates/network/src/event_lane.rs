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
use std::time::{Duration, Instant};
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

/// An event plus the instant it entered its lane, so the main loop can
/// measure how long it waited (enqueue -> handle). Internal to the two-lane
/// channel; callers see plain [`PeerEvent`]s.
#[derive(Debug)]
pub struct Stamped {
    at: Instant,
    ev: PeerEvent,
}

impl Stamped {
    fn now(ev: PeerEvent) -> Self {
        Stamped { at: Instant::now(), ev }
    }
}

/// One lane's sending half. [`event_channel`] builds stamped lanes; a plain
/// `mpsc::Sender<PeerEvent>` (tests, single-channel callers) stays plain.
#[derive(Clone, Debug)]
enum LaneTx {
    Plain(mpsc::Sender<PeerEvent>),
    Stamped(mpsc::Sender<Stamped>),
}

fn unstamp_try(e: mpsc::error::TrySendError<Stamped>) -> mpsc::error::TrySendError<PeerEvent> {
    match e {
        mpsc::error::TrySendError::Full(s) => mpsc::error::TrySendError::Full(s.ev),
        mpsc::error::TrySendError::Closed(s) => mpsc::error::TrySendError::Closed(s.ev),
    }
}

impl LaneTx {
    async fn send(&self, ev: PeerEvent) -> Result<(), mpsc::error::SendError<PeerEvent>> {
        match self {
            LaneTx::Plain(tx) => tx.send(ev).await,
            LaneTx::Stamped(tx) => tx
                .send(Stamped::now(ev))
                .await
                .map_err(|e| mpsc::error::SendError(e.0.ev)),
        }
    }

    fn try_send(&self, ev: PeerEvent) -> Result<(), mpsc::error::TrySendError<PeerEvent>> {
        match self {
            LaneTx::Plain(tx) => tx.try_send(ev),
            LaneTx::Stamped(tx) => tx.try_send(Stamped::now(ev)).map_err(unstamp_try),
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            LaneTx::Plain(tx) => tx.is_closed(),
            LaneTx::Stamped(tx) => tx.is_closed(),
        }
    }
}

/// A reserved priority-lane slot (see [`EventSender::reserve_priority`]).
/// `send` stamps the event with the instant it enters the lane.
pub enum PriorityPermit<'a> {
    Plain(mpsc::Permit<'a, PeerEvent>),
    Stamped(mpsc::Permit<'a, Stamped>),
}

impl PriorityPermit<'_> {
    pub fn send(self, ev: PeerEvent) {
        match self {
            PriorityPermit::Plain(p) => p.send(ev),
            PriorityPermit::Stamped(p) => p.send(Stamped::now(ev)),
        }
    }
}

/// Sending half: routes each event to its lane.
#[derive(Clone, Debug)]
pub struct EventSender {
    prio: LaneTx,
    bulk: LaneTx,
    dropped: Arc<AtomicU64>,
}

impl From<mpsc::Sender<PeerEvent>> for EventSender {
    fn from(tx: mpsc::Sender<PeerEvent>) -> Self {
        EventSender {
            prio: LaneTx::Plain(tx.clone()),
            bulk: LaneTx::Plain(tx),
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
    pub async fn reserve_priority(&self) -> Result<PriorityPermit<'_>, mpsc::error::SendError<()>> {
        match &self.prio {
            LaneTx::Plain(tx) => tx.reserve().await.map(PriorityPermit::Plain),
            LaneTx::Stamped(tx) => tx.reserve().await.map(PriorityPermit::Stamped),
        }
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
    prio: mpsc::Receiver<Stamped>,
    bulk: mpsc::Receiver<Stamped>,
    /// Enqueue -> dequeue wait of the event most recently returned.
    last_wait: Duration,
}

impl EventReceiver {
    /// Next event, priority lane first. Cancel-safe (both arms are
    /// `mpsc::Receiver::recv`). `None` once both lanes are closed and empty.
    /// Records the event's lane wait, readable via [`Self::last_wait`].
    pub async fn recv(&mut self) -> Option<PeerEvent> {
        let s = tokio::select! {
            biased;
            Some(s) = self.prio.recv() => s,
            Some(s) = self.bulk.recv() => s,
            else => return None,
        };
        self.last_wait = s.at.elapsed();
        Some(s.ev)
    }

    /// Non-blocking receive, priority lane first.
    pub fn try_recv(&mut self) -> Result<PeerEvent, mpsc::error::TryRecvError> {
        let s = match self.prio.try_recv() {
            Ok(s) => s,
            Err(_) => self.bulk.try_recv()?,
        };
        self.last_wait = s.at.elapsed();
        Ok(s.ev)
    }

    /// How long the most recently returned event sat in its lane between the
    /// peer task handing it over and the main loop taking it. This is the
    /// main loop's backlog as a peer experiences it (2026-09-28: a
    /// `Connected` was handled 875 s after the handshake, inferred from log
    /// timestamps because nothing measured it).
    pub fn last_wait(&self) -> Duration {
        self.last_wait
    }

    /// Events currently queued on the priority lane.
    pub fn priority_backlog(&self) -> usize {
        self.prio.len()
    }

    /// Events currently queued on the bulk lane.
    pub fn bulk_backlog(&self) -> usize {
        self.bulk.len()
    }
}

/// Create the two-lane channel.
pub fn event_channel(capacity: usize) -> (EventSender, EventReceiver) {
    let (ptx, prx) = mpsc::channel(capacity);
    let (btx, brx) = mpsc::channel(capacity);
    (
        EventSender {
            prio: LaneTx::Stamped(ptx),
            bulk: LaneTx::Stamped(btx),
            dropped: Arc::new(AtomicU64::new(0)),
        },
        EventReceiver {
            prio: prx,
            bulk: brx,
            last_wait: Duration::ZERO,
        },
    )
}

/// Main-loop latency accounting: how long events waited in the lanes and how
/// long the loop spent handling each one. Cheap (two `Instant` reads per
/// event); emits at most one WARN per [`LoopLatency::WARN_EVERY`] so a long
/// backlog is visible without flooding the log.
#[derive(Debug)]
pub struct LoopLatency {
    window_start: Instant,
    last_warn: Option<Instant>,
    events: u64,
    max_wait: Duration,
    max_handle: Duration,
    max_handle_kind: &'static str,
    slow_waits: u64,
    slow_handles: u64,
}

/// Classification of an event for the latency log.
pub fn event_kind(ev: &PeerEvent) -> &'static str {
    match ev {
        PeerEvent::Connected(..) => "connected",
        PeerEvent::Disconnected(..) => "disconnected",
        PeerEvent::Message(_, m) => match m {
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::CmpctBlock(_) => "cmpctblock",
            NetworkMessage::BlockTxn(_) => "blocktxn",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            _ => "message",
        },
        PeerEvent::Misbehaving(..) => "misbehaving",
    }
}

impl Default for LoopLatency {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}

impl LoopLatency {
    /// An event that waited at least this long in its lane is logged.
    pub const SLOW_WAIT: Duration = Duration::from_secs(30);
    /// A single event whose handling took at least this long is logged.
    pub const SLOW_HANDLE: Duration = Duration::from_secs(5);
    /// Minimum spacing of WARN lines.
    pub const WARN_EVERY: Duration = Duration::from_secs(60);

    pub fn new(now: Instant) -> Self {
        LoopLatency {
            window_start: now,
            last_warn: None,
            events: 0,
            max_wait: Duration::ZERO,
            max_handle: Duration::ZERO,
            max_handle_kind: "",
            slow_waits: 0,
            slow_handles: 0,
        }
    }

    /// Record one handled event. Returns the WARN line to emit, if any (the
    /// caller logs it so the rate limit is testable without a subscriber).
    pub fn record(
        &mut self,
        now: Instant,
        kind: &'static str,
        wait: Duration,
        handle: Duration,
        prio_backlog: usize,
    ) -> Option<String> {
        self.events += 1;
        self.max_wait = self.max_wait.max(wait);
        if handle > self.max_handle {
            self.max_handle = handle;
            self.max_handle_kind = kind;
        }
        let slow_wait = wait >= Self::SLOW_WAIT;
        let slow_handle = handle >= Self::SLOW_HANDLE;
        self.slow_waits += slow_wait as u64;
        self.slow_handles += slow_handle as u64;
        if !(slow_wait || slow_handle) {
            return None;
        }
        if self
            .last_warn
            .is_some_and(|t| now.saturating_duration_since(t) < Self::WARN_EVERY)
        {
            return None;
        }
        let line = format!(
            "main loop behind: `{kind}` waited {:.1}s in the event lane and took {:.1}s to handle \
             (priority backlog {prio_backlog}); last {:.0}s: {} events, max wait {:.1}s, \
             max handle {:.1}s (`{}`), {} waits >= {}s, {} handles >= {}s",
            wait.as_secs_f64(),
            handle.as_secs_f64(),
            now.saturating_duration_since(self.window_start).as_secs_f64(),
            self.events,
            self.max_wait.as_secs_f64(),
            self.max_handle.as_secs_f64(),
            self.max_handle_kind,
            self.slow_waits,
            Self::SLOW_WAIT.as_secs(),
            self.slow_handles,
            Self::SLOW_HANDLE.as_secs(),
        );
        *self = LoopLatency {
            last_warn: Some(now),
            ..LoopLatency::new(now)
        };
        Some(line)
    }
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

    /// (d) The lane measures how long an event waited, so a main-loop
    /// backlog is observed rather than inferred from log timestamps.
    #[tokio::test]
    async fn receiver_reports_enqueue_to_dequeue_wait() {
        let (tx, mut rx) = event_channel(8);
        tx.send(headers_msg(1)).await.unwrap();
        std::thread::sleep(Duration::from_millis(60));
        tx.send(PeerEvent::Disconnected(PeerId(2), DisconnectReason::Timeout))
            .await
            .unwrap();
        assert_eq!(rx.priority_backlog(), 2);
        rx.recv().await.unwrap();
        assert!(
            rx.last_wait() >= Duration::from_millis(60),
            "the first event sat in the lane >= 60 ms, got {:?}",
            rx.last_wait()
        );
        rx.recv().await.unwrap();
        assert!(
            rx.last_wait() < Duration::from_millis(60),
            "the second event was enqueued just before recv, got {:?}",
            rx.last_wait()
        );
        // A reserved permit stamps too.
        let permit = tx.reserve_priority().await.unwrap();
        permit.send(headers_msg(3));
        assert!(matches!(rx.try_recv(), Ok(PeerEvent::Message(PeerId(3), _))));
    }

    #[test]
    fn loop_latency_warns_on_slow_wait_or_handle_and_rate_limits() {
        let t0 = Instant::now();
        let mut l = LoopLatency::new(t0);
        let fast = Duration::from_millis(5);
        assert!(l.record(t0, "headers", fast, fast, 0).is_none());
        // Just under both thresholds: silent.
        assert!(l
            .record(t0, "block", LoopLatency::SLOW_WAIT - fast, LoopLatency::SLOW_HANDLE - fast, 3)
            .is_none());
        // Slow wait warns, and names the event kind and the backlog.
        let w = l
            .record(t0, "connected", Duration::from_secs(875), fast, 900)
            .expect("an 875 s lane wait must warn");
        assert!(w.contains("`connected` waited 875.0s"), "{w}");
        assert!(w.contains("priority backlog 900"), "{w}");
        // Rate limited inside WARN_EVERY...
        assert!(l
            .record(t0 + Duration::from_secs(1), "block", fast, Duration::from_secs(9), 0)
            .is_none());
        // ...but the window keeps the worst handle for the next line.
        let w = l
            .record(t0 + LoopLatency::WARN_EVERY, "block", fast, LoopLatency::SLOW_HANDLE, 0)
            .expect("slow handle after the rate-limit window must warn");
        assert!(w.contains("max handle 9.0s (`block`)"), "{w}");
    }
}
