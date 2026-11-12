//! cfaudit 2026-11-09 (cffix-rustoshi-unrequested-block-buffer): any peer
//! could push `block` messages with fresh nonces and every body was kept in
//! `BlockDownloader::received_blocks` until restart -- the buffer cap was
//! read only by `assign_requests`, never on insert. Core keeps no such
//! buffer (`ProcessMessage` "block" -> `AcceptBlock`, which drops an
//! unrequested block unless it has more work and is not too far ahead,
//! validation.cpp).

use rustoshi_network::{BlockDownloader, PeerId};
use rustoshi_primitives::{Block, BlockHeader, Hash256};

/// Mirrors `block_download::MAX_RECEIVED_BLOCKS` (private before this fix,
/// so the literal keeps this file compiling on the base commit).
const MAX_RECEIVED_BLOCKS: usize = 512;

fn make_test_block_n(n: u32) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1231006505,
            bits: 0x207fffff,
            nonce: n,
        },
        transactions: vec![],
    }
}

#[test]
fn unrequested_bodies_are_bounded() {
    let mut dl = BlockDownloader::with_per_peer_cap(0, 0, 16);
    let peers: Vec<PeerId> = (1..=64).map(PeerId).collect();
    for p in &peers {
        dl.add_peer(*p);
    }
    // Never enqueued, never requested: every one of these is unsolicited.
    for i in 0..(2 * MAX_RECEIVED_BLOCKS) as u32 {
        let peer = peers[i as usize % peers.len()];
        dl.block_received(peer, make_test_block_n(i));
    }
    let buffered = dl.received_blocks_count();
    assert!(
        buffered <= MAX_RECEIVED_BLOCKS,
        "{buffered} unsolicited bodies buffered (cap {MAX_RECEIVED_BLOCKS})"
    );

    // A single peer cannot hold the buffer either.
    let mut dl = BlockDownloader::with_per_peer_cap(0, 0, 16);
    let a = PeerId(1);
    let b = PeerId(2);
    dl.add_peer(a);
    dl.add_peer(b);
    for i in 0..(2 * MAX_RECEIVED_BLOCKS) as u32 {
        dl.block_received(a, make_test_block_n(i));
    }
    let from_a = dl.received_blocks_count();
    assert!(
        from_a <= MAX_RECEIVED_BLOCKS,
        "{from_a} bodies from one peer"
    );
    dl.block_received(b, make_test_block_n(1_000_000));
    assert_eq!(
        dl.received_blocks_count(),
        from_a + 1,
        "peer b's body was crowded out"
    );

    // Disconnecting a frees its unsolicited bodies; b's stays.
    dl.remove_peer(a);
    assert_eq!(
        dl.received_blocks_count(),
        1,
        "remove_peer left the disconnected peer's unsolicited bodies buffered"
    );
    assert!(dl.is_in_received(&make_test_block_n(1_000_000).block_hash()));
}

/// Control (audit RU-5): a block that beats its own header is still kept and
/// connects once the header enqueues it -- and once enqueued it is solicited,
/// so its deliverer disconnecting does not drop it.
#[test]
fn early_block_still_reaches_validation_after_its_deliverer_leaves() {
    let mut dl = BlockDownloader::with_per_peer_cap(0, 0, 16);
    let a = PeerId(7);
    dl.add_peer(a);
    let block = make_test_block_n(42);
    let hash = block.block_hash();
    assert_eq!(dl.block_received(a, block), Some(hash));
    dl.set_best_header_height(1);
    dl.enqueue_blocks(vec![(hash, 1)]);
    dl.remove_peer(a);
    let got = dl
        .next_block_to_validate()
        .expect("early body must still validate");
    assert_eq!(got.block_hash(), hash);
}

/// Control: requested bodies are not subject to the unsolicited cap.
#[test]
fn requested_bodies_are_not_capped_by_the_unsolicited_limit() {
    let n = 128u32;
    let mut dl = BlockDownloader::with_per_peer_cap(0, n, 128);
    let a = PeerId(1);
    dl.add_peer(a);
    let blocks: Vec<Block> = (1..=n).map(make_test_block_n).collect();
    dl.enqueue_blocks(
        blocks
            .iter()
            .zip(1..)
            .map(|(b, h)| (b.block_hash(), h))
            .collect(),
    );
    let _ = dl.assign_requests();
    // Deliver in reverse so nothing can be popped for validation yet.
    for b in blocks.into_iter().rev() {
        dl.block_received(a, b);
    }
    assert_eq!(dl.received_blocks_count(), n as usize);
}
