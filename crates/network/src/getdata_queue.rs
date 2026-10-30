//! Per-peer queue of `getdata` items still to be served.
//!
//! Core's `ProcessGetData` (net_processing.cpp) does not answer a getdata in
//! one pass: it serves items from the peer's `m_getdata_requests` until the
//! peer's send buffer is full (`fPauseSend`), at most one block per call, and
//! leaves the rest queued for later message-handler passes. The work it does
//! for a peer therefore tracks what that peer actually drains.
//!
//! rustoshi used to loop over every item of a getdata inline, reading each
//! block from disk even after the peer's outbound queue was full and the reply
//! was being dropped: 50,000 `MSG_WITNESS_BLOCK` items naming one ~2 MB block
//! cost 50,000 reads + deserializes per message (audit H4). This queue holds
//! the items; the caller pops at most as many as the peer has free send slots
//! for, and serves the rest on later passes.

use crate::message::{InvVector, MAX_INV_SIZE};
use crate::peer::PeerId;
use std::collections::{HashMap, VecDeque};

/// Most items queued for one peer. Core never holds more than one getdata's
/// worth for a peer, because it stops reading the peer's messages while
/// `m_getdata_requests` is non-empty; a getdata itself is capped at
/// `MAX_INV_SZ`. Items past this are dropped.
pub const MAX_QUEUED_GETDATA_PER_PEER: usize = MAX_INV_SIZE;

/// Pending getdata items, per peer, in arrival order.
#[derive(Debug, Default)]
pub struct GetDataQueue {
    queues: HashMap<PeerId, VecDeque<InvVector>>,
}

impl GetDataQueue {
    /// Empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a getdata's items for `peer`. Returns how many were dropped
    /// because the peer already had `MAX_QUEUED_GETDATA_PER_PEER` pending.
    pub fn push(&mut self, peer: PeerId, items: Vec<InvVector>) -> usize {
        let q = self.queues.entry(peer).or_default();
        let room = MAX_QUEUED_GETDATA_PER_PEER.saturating_sub(q.len());
        let dropped = items.len().saturating_sub(room);
        q.extend(items.into_iter().take(room));
        if q.is_empty() {
            self.queues.remove(&peer);
        }
        dropped
    }

    /// Pop up to `send_capacity` items for `peer`, oldest first. Each served
    /// item sends at most one message, so the caller passes the peer's free
    /// outbound slots; 0 pops nothing and the items wait for a later pass.
    pub fn take_batch(&mut self, peer: PeerId, send_capacity: usize) -> Vec<InvVector> {
        let Some(q) = self.queues.get_mut(&peer) else {
            return Vec::new();
        };
        let n = send_capacity.min(q.len());
        let batch: Vec<InvVector> = q.drain(..n).collect();
        if q.is_empty() {
            self.queues.remove(&peer);
        }
        batch
    }

    /// Items still pending for `peer`.
    pub fn pending(&self, peer: PeerId) -> usize {
        self.queues.get(&peer).map_or(0, VecDeque::len)
    }

    /// Peers with items pending.
    pub fn peers(&self) -> Vec<PeerId> {
        self.queues.keys().copied().collect()
    }

    /// Forget a disconnected peer's pending items.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.queues.remove(&peer);
    }
}
