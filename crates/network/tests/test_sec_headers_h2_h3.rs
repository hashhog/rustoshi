//! Security audit 2026-10-28, findings H2 and H3 (headers from a sync peer).
//!
//! H2: the heavier-fork compare summed the DECLARED work of a batch before any
//! header in it had been checked, and moved `best_header_*` / `pending_rewind`
//! to the fork point at once. One unmined header declaring target 1 rewound
//! the header tip to its parent and left a sticky download-floor rewind, even
//! though the header then failed PoW.
//!
//! H3: a cheap lighter fork at height 1 made the work compare read our header
//! bits for every height of our chain, per message, with no penalty.
//!
//! Only `HeaderSync::process_headers` API that exists on the base commit is
//! used, so these tests fail there by name.

use rustoshi_network::{HeaderSync, PeerId};
use rustoshi_primitives::{BlockHeader, Hash256};
use std::cell::Cell;
use std::collections::HashMap;

const REGTEST_BITS: u32 = 0x207fffff;
const PEER: PeerId = PeerId(7);

fn mine(prev: Hash256, timestamp: u32, salt: u32) -> BlockHeader {
    let mut header = BlockHeader {
        version: 0x2000_0000,
        prev_block_hash: prev,
        merkle_root: Hash256([salt as u8; 32]),
        timestamp,
        bits: REGTEST_BITS,
        nonce: 0,
    };
    while !header.validate_pow_against_declared_target() {
        header.nonce += 1;
    }
    header
}

/// A header chain of `n` headers on `genesis`, fed through `process_headers`
/// as announcements, plus our height index (hash and bits per height).
struct Chain {
    hs: HeaderSync,
    hashes: HashMap<u32, Hash256>,
    bits: HashMap<u32, u32>,
}

impl Chain {
    fn new(n: u32) -> Self {
        let genesis = Hash256([0x11; 32]);
        let mut hs = HeaderSync::new(genesis);
        let mut hashes = HashMap::from([(0, genesis)]);
        let mut bits = HashMap::from([(0, REGTEST_BITS)]);
        let mut prev = genesis;
        let mut height = 0u32;
        while height < n {
            let batch_len = (n - height).min(2000);
            let mut batch = Vec::new();
            for _ in 0..batch_len {
                height += 1;
                let h = mine(prev, 1_700_000_000 + height, 0);
                prev = h.block_hash();
                hashes.insert(height, prev);
                bits.insert(height, h.bits);
                batch.push(h);
            }
            hs.process_headers(PEER, batch, &mut |_, _| Ok(()), &|_| None, &|_| None)
                .expect("own chain must extend");
        }
        assert_eq!(hs.best_header_height(), n);
        Chain { hs, hashes, bits }
    }

    /// Make PEER the active header-sync peer (what a huge advertised
    /// start_height or an unconnecting-announcement hint does on the node).
    fn make_sync_peer(&mut self) {
        let hashes = self.hashes.clone();
        let _ = self
            .hs
            .request_headers_from(PEER, |h| hashes.get(&h).copied());
    }

    fn feed(
        &mut self,
        headers: Vec<BlockHeader>,
        store: &mut dyn FnMut(&BlockHeader, u32) -> Result<(), String>,
        bits_reads: &Cell<usize>,
    ) -> Result<bool, String> {
        let hashes = &self.hashes;
        let bits = &self.bits;
        self.hs.process_headers(
            PEER,
            headers,
            store,
            &|hash| hashes.iter().find(|(_, v)| *v == hash).map(|(k, _)| *k),
            &|height| {
                bits_reads.set(bits_reads.get() + 1);
                bits.get(&height).copied()
            },
        )
    }
}

/// H2: one unmined header forking at height 1 with nBits 0x03000001 (target 1,
/// declared proof ~2^255) must be rejected without touching the header tip or
/// leaving a pending rewind. Base: tip drops to height 1, pending_rewind = 1.
#[test]
fn h2_unmined_heavy_header_does_not_rewind_header_tip() {
    let mut c = Chain::new(50);
    let tip = (c.hs.best_header_height(), c.hs.best_header_hash());
    c.make_sync_peer();

    let attack = BlockHeader {
        version: 0x2000_0000,
        prev_block_hash: c.hashes[&1],
        merkle_root: Hash256([0xaa; 32]),
        timestamp: 1_700_000_002,
        bits: 0x0300_0001,
        nonce: 0,
    };
    let reads = Cell::new(0);
    let res = c.feed(vec![attack], &mut |_, _| Ok(()), &reads);

    assert!(res.is_err(), "unmined header must be rejected, got {res:?}");
    assert_eq!(
        (c.hs.best_header_height(), c.hs.best_header_hash()),
        tip,
        "header tip moved for a header that failed PoW"
    );
    assert_eq!(
        c.hs.take_pending_rewind(),
        None,
        "sticky rewind left behind"
    );
}

/// H2: a heavier fork whose batch fails validation part-way (the caller's
/// params-aware gate rejects its 2nd header) must not commit the rewind.
/// Base: tip drops to the fork point and pending_rewind is set.
#[test]
fn h2_fork_batch_failing_midway_does_not_commit_rewind() {
    let mut c = Chain::new(50);
    let tip = (c.hs.best_header_height(), c.hs.best_header_hash());
    c.make_sync_peer();

    // Fork at 47: 5 headers (work 5 units) beat our 3 (48..=50).
    let mut fork = Vec::new();
    let mut prev = c.hashes[&47];
    for i in 0..5 {
        let h = mine(prev, 1_700_000_100 + i, 0xf0);
        prev = h.block_hash();
        fork.push(h);
    }
    let bad = fork[1].block_hash();
    let reads = Cell::new(0);
    let res = c.feed(
        fork,
        &mut |h, _| {
            if h.block_hash() == bad {
                Err("bad-diffbits".into())
            } else {
                Ok(())
            }
        },
        &reads,
    );

    assert!(res.is_err());
    assert_eq!((c.hs.best_header_height(), c.hs.best_header_hash()), tip);
    assert_eq!(c.hs.take_pending_rewind(), None);
}

/// Regression guard: a valid heavier fork still rewinds and records the
/// fork point (Reorg Unit E behaviour). Passes on base and head.
#[test]
fn h2_valid_heavier_fork_still_rewinds() {
    let mut c = Chain::new(50);
    c.make_sync_peer();

    let mut fork = Vec::new();
    let mut prev = c.hashes[&47];
    for i in 0..5 {
        let h = mine(prev, 1_700_000_100 + i, 0xf1);
        prev = h.block_hash();
        fork.push(h);
    }
    let fork_tip = prev;
    let reads = Cell::new(0);
    let res = c.feed(fork, &mut |_, _| Ok(()), &reads);

    assert_eq!(res, Ok(false));
    assert_eq!(
        (c.hs.best_header_height(), c.hs.best_header_hash()),
        (52, fork_tip)
    );
    assert_eq!(c.hs.take_pending_rewind(), Some(47));
}

/// Regression guard: an equal-work fork is still ignored (no rewind).
#[test]
fn h2_equal_work_fork_is_ignored() {
    let mut c = Chain::new(50);
    let tip = (c.hs.best_header_height(), c.hs.best_header_hash());
    c.make_sync_peer();

    let mut fork = Vec::new();
    let mut prev = c.hashes[&47];
    for i in 0..3 {
        let h = mine(prev, 1_700_000_100 + i, 0xf2);
        prev = h.block_hash();
        fork.push(h);
    }
    let reads = Cell::new(0);
    assert_eq!(c.feed(fork, &mut |_, _| Ok(()), &reads), Ok(false));
    assert_eq!((c.hs.best_header_height(), c.hs.best_header_hash()), tip);
    assert_eq!(c.hs.take_pending_rewind(), None);
}

/// H3: a valid one-header fork at height 1 of a 6,000-header chain is lighter
/// after one height of ours; the compare must stop there instead of reading
/// all 5,999 heights. Base: 5,999 reads per message.
#[test]
fn h3_light_deep_fork_reads_constant_heights() {
    let mut c = Chain::new(6_000);
    let tip = (c.hs.best_header_height(), c.hs.best_header_hash());
    c.make_sync_peer();

    let attack = mine(c.hashes[&1], 1_700_000_002, 0xee);
    let reads = Cell::new(0);
    assert_eq!(c.feed(vec![attack], &mut |_, _| Ok(()), &reads), Ok(false));
    assert_eq!((c.hs.best_header_height(), c.hs.best_header_hash()), tip);
    assert!(
        reads.get() <= 2,
        "lighter fork read {} heights of our chain (expected <= 2)",
        reads.get()
    );
}
