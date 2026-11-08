//! State-machine sweep (sm-sweep-rustoshi), path b: block-index failure marks
//! on the P2P connect path.
//!
//! Child module of the binary crate root so it can call the private
//! `mark_connect_failed_block_invalid`. The test fails on master by design (the
//! sweep confirms gaps, it does not fix them); it is `#[ignore]`d so CI stays
//! green. Run with
//! `cargo test -p rustoshi --bin rustoshi sm_sweep -- --ignored`.

use super::*;
use rustoshi_primitives::BlockHeader;

fn hdr(prev: Hash256, timestamp: u32) -> BlockHeader {
    BlockHeader {
        version: 0x2000_0000,
        prev_block_hash: prev,
        merkle_root: Hash256::ZERO,
        timestamp,
        bits: 0x1702_0684,
        nonce: 0,
    }
}

fn index_entry(store: &BlockStore, h: &BlockHeader, height: u32) {
    let mut status = BlockStatus::new();
    status.set(BlockStatus::VALID_TREE);
    store.put_header(&h.block_hash(), h).unwrap();
    store
        .put_block_index(
            &h.block_hash(),
            &BlockIndexEntry {
                height,
                status,
                n_tx: 1,
                timestamp: h.timestamp,
                bits: h.bits,
                nonce: h.nonce,
                version: h.version,
                prev_hash: h.prev_block_hash,
                chain_work: [0u8; 32],
            },
        )
        .unwrap();
}

/// Gap B-2: a block that fails to connect while the header tip is ABOVE it
/// (the normal case in IBD and catch-up) leaves the header chain on the
/// invalid branch, and its header-only descendants unflagged.
///
/// `mark_connect_failed_block_invalid` (main.rs) flags only the failed block,
/// and rewinds `HeaderSync` only when the failed block IS the header tip. The
/// P2P connect site does not call `rewind_headers_off_invalid_branch` (only the
/// attach-and-reorg site does). Core's InvalidBlockFound -> InvalidChainFound
/// marks every descendant BLOCK_FAILED_VALID (SetBlockFailureFlags) and calls
/// RecalculateBestHeader when the best header descends from the bad block
/// (validation.cpp). With the header tip left on the invalid branch, an
/// honest sibling chain with less header work than the invalid one is "not
/// heavier" and is ignored: the same wedge `rewind_headers_off_invalid_branch`
/// was written to clear on the reorg path.
#[test]
#[ignore = "sm-sweep-rustoshi gap B-2: fails on master until sm-fix-rustoshi-connect-fail-descendants"]
fn sm_sweep_connect_fail_below_header_tip_leaves_invalid_branch() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = ChainDb::open(dir.path()).unwrap();
    let store = BlockStore::new(&db);
    let params = ChainParams::mainnet();

    // genesis <- P (1) <- A (2, fails to connect) <- B (3, header only)
    let parent = hdr(params.genesis_hash, 1_775_651_930);
    let block = rustoshi_primitives::Block {
        header: hdr(parent.block_hash(), 1_775_653_126),
        transactions: params.genesis_block.transactions.clone(),
    };
    let a = block.header.block_hash();
    let b = hdr(a, 1_775_653_726);
    index_entry(&store, &parent, 1);
    index_entry(&store, &block.header, 2);
    index_entry(&store, &b, 3);
    store.put_height_index(1, &parent.block_hash()).unwrap();
    store.put_height_index(2, &a).unwrap();
    store.put_height_index(3, &b.block_hash()).unwrap();

    let mut hs = HeaderSync::new(params.genesis_hash);
    hs.set_best_header(3, b.block_hash()); // header tip above the failed block
    let mut dl = BlockDownloader::new(1, 3);

    mark_connect_failed_block_invalid(&store, &mut hs, &mut dl, &block, a, 2);

    // Control: the failed block itself is flagged (passes on master).
    assert!(store
        .get_block_index(&a)
        .unwrap()
        .unwrap()
        .status
        .has(BlockStatus::FAILED_VALIDITY));

    assert!(
        hs.best_header_height() < 2,
        "header tip stayed on the invalid branch at height {} (Core RecalculateBestHeader)",
        hs.best_header_height()
    );
    let bst = store.get_block_index(&b.block_hash()).unwrap().unwrap().status;
    assert!(
        bst.has(BlockStatus::FAILED_VALIDITY) || bst.has(BlockStatus::FAILED_CHILD),
        "descendant of a failed block is not marked failed (Core SetBlockFailureFlags)"
    );
}
