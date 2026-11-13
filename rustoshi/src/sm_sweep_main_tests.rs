//! State-machine sweep (sm-sweep-rustoshi), path b: block-index failure marks
//! on the P2P connect path.
//!
//! Child module of the binary crate root so it can call the private
//! `mark_connect_failed_block_invalid`. Gap B-2 is fixed by
//! sm-fix-rustoshi-connect-fail-descendants, so its pin runs un-ignored.
//! Run with `cargo test -p rustoshi --bin rustoshi sm_sweep`.

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

fn status(store: &BlockStore, h: &Hash256) -> BlockStatus {
    store.get_block_index(h).unwrap().unwrap().status
}

fn failed(store: &BlockStore, h: &Hash256) -> bool {
    let st = status(store, h);
    st.has(BlockStatus::FAILED_VALIDITY) || st.has(BlockStatus::FAILED_CHILD)
}

/// genesis <- P (1) <- A (2, the block that fails) <- B (3) <- C (4), all
/// indexed and in the height index, header tip at C. Returns (P, A block, B,
/// C).
fn four_block_header_chain(
    store: &BlockStore,
    params: &ChainParams,
) -> (BlockHeader, rustoshi_primitives::Block, BlockHeader, BlockHeader) {
    let p = hdr(params.genesis_hash, 1_775_651_930);
    let a = rustoshi_primitives::Block {
        header: hdr(p.block_hash(), 1_775_653_126),
        transactions: params.genesis_block.transactions.clone(),
    };
    let b = hdr(a.header.block_hash(), 1_775_653_726);
    let c = hdr(b.block_hash(), 1_775_654_326);
    for (h, ht) in [(&p, 1), (&a.header, 2), (&b, 3), (&c, 4)] {
        index_entry(store, h, ht);
        store.put_height_index(ht, &h.block_hash()).unwrap();
    }
    (p, a, b, c)
}

/// Gap B-2, whole-branch form: with the header tip two blocks above the
/// failed block, EVERY header-chain descendant is flagged (not just the
/// child), the height index stops naming the invalid branch, the header tip
/// and downloader come back to the failed block's parent, and an honest
/// sibling of the failed block, with less header work than the invalid branch
/// (height 2 vs 4), then EXTENDS the header chain instead of being ignored.
#[test]
fn sm_sweep_connect_fail_flags_every_descendant_and_honest_sibling_extends() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = ChainDb::open(dir.path()).unwrap();
    let store = BlockStore::new(&db);
    let params = ChainParams::mainnet();
    let (p, a, b, c) = four_block_header_chain(&store, &params);
    let a_hash = a.header.block_hash();

    let mut hs = HeaderSync::new(params.genesis_hash);
    hs.set_best_header(4, c.block_hash());
    let mut dl = BlockDownloader::new(1, 4);
    dl.enqueue_blocks(vec![(b.block_hash(), 3), (c.block_hash(), 4)]);

    mark_connect_failed_block_invalid(&store, &mut hs, &mut dl, &a, a_hash, 2);

    assert!(status(&store, &a_hash).has(BlockStatus::FAILED_VALIDITY));
    assert!(failed(&store, &b.block_hash()), "child of the failed block is not flagged");
    assert!(failed(&store, &c.block_hash()), "grandchild of the failed block is not flagged");
    assert!(!failed(&store, &p.block_hash()), "the valid parent must stay unflagged");
    assert_eq!(
        (hs.best_header_height(), hs.best_header_hash()),
        (1, p.block_hash()),
        "header tip must come back to the failed block's parent"
    );
    assert_eq!(store.get_hash_by_height(1).unwrap(), Some(p.block_hash()));
    for ht in 2..=4 {
        assert_eq!(
            store.get_hash_by_height(ht).unwrap(),
            None,
            "height index still names the invalid branch at {ht}"
        );
    }
    assert_eq!(dl.best_header_height(), 1);
    assert_eq!(dl.validated_tip_height(), 1);
    assert_eq!(dl.download_queue_len(), 0, "invalid descendants must not stay queued");

    // The honest sibling of A (one header, less work than A..C) extends.
    let mut sib = BlockHeader {
        version: 0x2000_0000,
        prev_block_hash: p.block_hash(),
        merkle_root: Hash256::ZERO,
        timestamp: 1_775_653_200,
        bits: 0x207f_ffff,
        nonce: 0,
    };
    while !sib.validate_pow_against_declared_target() {
        sib.nonce += 1;
    }
    let res = hs.process_headers(
        rustoshi_network::PeerId(7),
        vec![sib.clone()],
        &mut |_, _| Ok(()),
        &|_| None,
        &|_| None,
    );
    assert!(res.is_ok(), "{res:?}");
    assert_eq!((hs.best_header_height(), hs.best_header_hash()), (2, sib.block_hash()));
}

/// Consensus guard (what could make a valid block invalid): the connect
/// path's verdict gate decides whether anything is marked. For every
/// NON-verdict result (a system fault, a missing ancestor header, a missing
/// parent, a mutated block, too little chainwork) nothing is flagged -- not
/// the block, not its descendants -- and the header chain is left where it
/// was. The verdict control proves the harness does see a mark.
#[test]
fn sm_sweep_connect_fail_non_verdict_marks_no_descendant() {
    use rustoshi_consensus::validation::ValidationError as V;
    let run = |e: &V| {
        let dir = tempfile::TempDir::new().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let params = ChainParams::mainnet();
        let (_p, a, b, c) = four_block_header_chain(&store, &params);
        let a_hash = a.header.block_hash();
        let mut hs = HeaderSync::new(params.genesis_hash);
        hs.set_best_header(4, c.block_hash());
        let mut dl = BlockDownloader::new(1, 4);
        // Same gate as both P2P connect sites.
        if connect_error_is_verdict(e) {
            mark_connect_failed_block_invalid(&store, &mut hs, &mut dl, &a, a_hash, 2);
        }
        (
            failed(&store, &a_hash),
            failed(&store, &b.block_hash()),
            failed(&store, &c.block_hash()),
            hs.best_header_height(),
            store.get_hash_by_height(4).unwrap() == Some(c.block_hash()),
        )
    };
    for e in [
        V::SystemFault("disk read failed".into()),
        V::MissingAncestorHeader(1),
        V::PrevBlockNotFound("x".into()),
        V::BadMerkleRoot,
        V::BadWitnessCommitment,
        V::BadTxnsDuplicate,
        V::TooLittleChainwork,
    ] {
        assert_eq!(
            run(&e),
            (false, false, false, 4, true),
            "non-verdict {e:?} marked something or moved the header chain"
        );
    }
    // Control: a content verdict marks the block and both descendants.
    assert_eq!(run(&V::BadSubsidy(1, 0)), (true, true, true, 1, false));
}

/// A header tip that does NOT descend from the failed block (it is on another
/// branch at that height) is left alone, and nothing past the failed block is
/// marked: descent is proven by the header links, not assumed from heights.
#[test]
fn sm_sweep_connect_fail_off_header_chain_marks_only_the_block() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = ChainDb::open(dir.path()).unwrap();
    let store = BlockStore::new(&db);
    let params = ChainParams::mainnet();
    // genesis <- P (1) <- X (2) <- Y (3): the header chain.
    // genesis <- P (1) <- A (2): the block that fails, not on the header chain.
    let p = hdr(params.genesis_hash, 1_775_651_930);
    let x = hdr(p.block_hash(), 1_775_652_000);
    let y = hdr(x.block_hash(), 1_775_652_600);
    let a = rustoshi_primitives::Block {
        header: hdr(p.block_hash(), 1_775_653_126),
        transactions: params.genesis_block.transactions.clone(),
    };
    let a_hash = a.header.block_hash();
    for (h, ht) in [(&p, 1), (&x, 2), (&y, 3)] {
        index_entry(&store, h, ht);
        store.put_height_index(ht, &h.block_hash()).unwrap();
    }
    index_entry(&store, &a.header, 2);
    let mut hs = HeaderSync::new(params.genesis_hash);
    hs.set_best_header(3, y.block_hash());
    let mut dl = BlockDownloader::new(1, 3);

    mark_connect_failed_block_invalid(&store, &mut hs, &mut dl, &a, a_hash, 2);

    assert!(status(&store, &a_hash).has(BlockStatus::FAILED_VALIDITY));
    assert!(!failed(&store, &x.block_hash()));
    assert!(!failed(&store, &y.block_hash()));
    assert_eq!((hs.best_header_height(), hs.best_header_hash()), (3, y.block_hash()));
    assert_eq!(store.get_hash_by_height(2).unwrap(), Some(x.block_hash()));
    assert_eq!(store.get_hash_by_height(3).unwrap(), Some(y.block_hash()));
}

/// A gap in the stored headers between the tip and the failed block means
/// descent cannot be proven: nothing past the failed block is marked and the
/// header chain is not moved (fail closed, never guess).
#[test]
fn sm_sweep_connect_fail_unprovable_descent_marks_only_the_block() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = ChainDb::open(dir.path()).unwrap();
    let store = BlockStore::new(&db);
    let params = ChainParams::mainnet();
    let p = hdr(params.genesis_hash, 1_775_651_930);
    let a = rustoshi_primitives::Block {
        header: hdr(p.block_hash(), 1_775_653_126),
        transactions: params.genesis_block.transactions.clone(),
    };
    let a_hash = a.header.block_hash();
    let b = hdr(a_hash, 1_775_653_726); // header NOT stored
    let c = hdr(b.block_hash(), 1_775_654_326);
    for (h, ht) in [(&p, 1), (&a.header, 2), (&c, 4)] {
        index_entry(&store, h, ht);
        store.put_height_index(ht, &h.block_hash()).unwrap();
    }
    let mut hs = HeaderSync::new(params.genesis_hash);
    hs.set_best_header(4, c.block_hash());
    let mut dl = BlockDownloader::new(1, 4);

    mark_connect_failed_block_invalid(&store, &mut hs, &mut dl, &a, a_hash, 2);

    assert!(status(&store, &a_hash).has(BlockStatus::FAILED_VALIDITY));
    assert!(!failed(&store, &c.block_hash()));
    assert_eq!(hs.best_header_height(), 4);
    assert_eq!(store.get_hash_by_height(4).unwrap(), Some(c.block_hash()));
}
