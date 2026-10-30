//! Security audit 2026-10-28, finding H4: getdata items are served as the
//! peer drains its send queue, not all in one pass. `GetDataQueue` is new
//! API; the end-to-end repro (50,000 block items, peer not reading) is
//! `tools/sec_headers_getdata_regtest.py h4_getdata_flood`.

use rustoshi_network::{
    GetDataQueue, InvType, InvVector, PeerId, MAX_INV_SIZE, MAX_QUEUED_GETDATA_PER_PEER,
};
use rustoshi_primitives::Hash256;

fn items(n: usize, tag: u8) -> Vec<InvVector> {
    (0..n)
        .map(|i| InvVector {
            inv_type: InvType::MsgWitnessBlock,
            hash: Hash256([tag ^ (i as u8); 32]),
        })
        .collect()
}

#[test]
fn h4_take_batch_is_bounded_by_send_capacity() {
    let mut q = GetDataQueue::new();
    let p = PeerId(1);
    assert_eq!(q.push(p, items(MAX_INV_SIZE, 0)), 0);
    // A peer whose send queue is full gets nothing read for it.
    assert!(q.take_batch(p, 0).is_empty());
    assert_eq!(q.pending(p), MAX_INV_SIZE);
    // Free slots bound the batch.
    assert_eq!(q.take_batch(p, 32).len(), 32);
    assert_eq!(q.pending(p), MAX_INV_SIZE - 32);
}

#[test]
fn h4_items_served_in_order_and_all_eventually() {
    let mut q = GetDataQueue::new();
    let p = PeerId(2);
    let want = items(100, 7);
    q.push(p, want.clone());
    let mut got = Vec::new();
    while q.pending(p) > 0 {
        got.extend(q.take_batch(p, 16));
    }
    assert_eq!(got, want);
    assert!(q.peers().is_empty(), "drained peer must not stay listed");
}

#[test]
fn h4_queue_per_peer_is_capped() {
    let mut q = GetDataQueue::new();
    let p = PeerId(3);
    assert_eq!(q.push(p, items(MAX_INV_SIZE, 1)), 0);
    assert_eq!(q.push(p, items(10, 2)), 10);
    assert_eq!(q.pending(p), MAX_QUEUED_GETDATA_PER_PEER);
}

#[test]
fn h4_peers_are_independent_and_removed_on_disconnect() {
    let mut q = GetDataQueue::new();
    q.push(PeerId(4), items(5, 3));
    q.push(PeerId(5), items(5, 4));
    assert_eq!(q.take_batch(PeerId(4), 100).len(), 5);
    assert_eq!(q.pending(PeerId(5)), 5);
    q.remove_peer(PeerId(5));
    assert_eq!(q.pending(PeerId(5)), 0);
    assert!(q.peers().is_empty());
}
