//! KB-180: `invalidateblock` must finish with Core's `ActivateBestChain`.
//!
//! Core `Chainstate::InvalidateBlock` disconnects the active chain to the
//! parent of the invalidated block, marks that block and its descendants
//! failed, then `InvalidChainFound` puts every non-failed block with data
//! and enough work back into `setBlockIndexCandidates`. The RPC then calls
//! `ActivateBestChain`: the most-work candidate whose branch has data and no
//! failure flag is connected, and a candidate that fails `ConnectTip` is
//! marked `BLOCK_FAILED_VALID` and skipped.
//!
//! Pre-fix rustoshi disconnects to the parent and returns. A fully valid
//! heavier side branch stays inactive, so the tip rests on the parent
//! (here, block 3a) instead of the side chain.

use std::path::Path;
use std::sync::Arc;

use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{
    Block, BlockHeader, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut,
};
use rustoshi_rpc::server::PeerState;
use rustoshi_rpc::{RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::block_store::BlockStatus;
use rustoshi_storage::{BlockStore, ChainDb};
use tokio::sync::RwLock;

const BASE_TIME: u32 = 1_700_000_000;
const SUBSIDY: u64 = 50 * 100_000_000;

struct LiveChain {
    server: RpcServerImpl,
    db: Arc<ChainDb>,
    /// Active chain, index 0 = genesis, index h = height h. Built as G-1-2-3a-4a-5a.
    blocks: Vec<Block>,
    path: std::path::PathBuf,
    dir: tempfile::TempDir,
}

fn bip34_push(height: u32) -> Vec<u8> {
    if height == 0 {
        return vec![0x00];
    }
    if height <= 16 {
        return vec![0x50 + height as u8];
    }
    let mut h = height;
    let mut le = Vec::new();
    while h > 0 {
        le.push((h & 0xFF) as u8);
        h >>= 8;
    }
    if le.last().is_some_and(|b| b & 0x80 != 0) {
        le.push(0);
    }
    let mut out = vec![le.len() as u8];
    out.extend(le);
    out
}

/// `marker` distinguishes coinbases at the same height so each branch has its
/// own txid. `value` is the coinbase output (subsidy, or over-subsidy).
fn mine_marked(height: u32, prev: Hash256, step: u32, value: u64, marker: u8) -> Block {
    let mut script_sig = bip34_push(height);
    script_sig.extend_from_slice(&[marker, 0xC5]);
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: BASE_TIME + step * 600,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: vec![Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig,
                sequence: 0xFFFF_FFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        }],
    };
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_of<T: Encodable>(value: &T) -> String {
    let mut buf = Vec::new();
    value.encode(&mut buf).unwrap();
    hex_encode(&buf)
}

fn index_status(db: &ChainDb, hash: &Hash256) -> BlockStatus {
    BlockStore::new(db)
        .get_block_index(hash)
        .expect("block index read")
        .expect("block index entry")
        .status
}

fn is_failed(status: BlockStatus) -> bool {
    status.has(BlockStatus::FAILED_VALIDITY) || status.has(BlockStatus::FAILED_CHILD)
}

/// Regtest chain G-1-2-3a-4a-5a accepted through `submitblock`.
async fn active_chain() -> LiveChain {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let db = Arc::new(ChainDb::open(&path).expect("open ChainDb"));
    let params = ChainParams::regtest();
    BlockStore::new(&db).init_genesis(&params).expect("genesis");
    let mut st = RpcState::new(db.clone(), params.clone());
    st.best_hash = params.genesis_hash;
    st.best_height = 0;
    st.data_dir = Some(path.clone());
    let server = RpcServerImpl::new(
        Arc::new(RwLock::new(st)),
        Arc::new(RwLock::new(PeerState::default())),
    );
    let mut blocks = vec![params.genesis_block.clone()];
    let mut prev = params.genesis_hash;
    for h in 1..=5 {
        // Marker 0x01 matches the chain helper the other submit tests use.
        let block = mine_marked(h, prev, h, SUBSIDY, 0x01);
        let result = server
            .submit_block(hex_of(&block))
            .await
            .expect("submitblock rpc");
        assert!(result.is_none(), "setup block {h} rejected: {result:?}");
        prev = block.block_hash();
        blocks.push(block);
    }
    assert_eq!(server.get_block_count().await.unwrap(), 5);
    LiveChain {
        server,
        db,
        blocks,
        path,
        dir,
    }
}

/// Submit 3'-4'-tip on top of block 2. Equal height to 5a, so the branch stays
/// inactive. `tip_value` is the subsidy for a valid 5', or above it for 5''.
async fn submit_side(chain: &LiveChain, tip_value: u64) -> Vec<Block> {
    let parent = chain.blocks[2].block_hash();
    let b3 = mine_marked(3, parent, 30, SUBSIDY, 0x99);
    let b4 = mine_marked(4, b3.block_hash(), 31, SUBSIDY, 0x99);
    let b5 = mine_marked(5, b4.block_hash(), 32, tip_value, 0x99);
    for (block, name) in [(&b3, "3'"), (&b4, "4'"), (&b5, "5'")] {
        let result = chain
            .server
            .submit_block(hex_of(block))
            .await
            .expect("submitblock rpc");
        assert_eq!(
            result.as_deref(),
            Some("inconclusive"),
            "equal-work side block {name} must be stored and not connected, got {result:?}"
        );
    }
    assert_eq!(
        chain.server.get_best_block_hash().await.unwrap(),
        chain.blocks[5].block_hash().to_hex(),
        "side branch must stay inactive before invalidateblock"
    );
    vec![b3, b4, b5]
}

/// Same open the node uses at startup: `ChainDb::open` then `RpcState::init_from_db`.
fn reopen_like_node(path: &Path) -> (RpcServerImpl, Arc<ChainDb>) {
    let db = Arc::new(ChainDb::open(path).expect("reopen ChainDb"));
    let params = ChainParams::regtest();
    let mut st = RpcState::new(db.clone(), params);
    st.data_dir = Some(path.to_path_buf());
    st.init_from_db().expect("init_from_db");
    let server = RpcServerImpl::new(
        Arc::new(RwLock::new(st)),
        Arc::new(RwLock::new(PeerState::default())),
    );
    (server, db)
}

async fn assert_tip(server: &RpcServerImpl, expected: &Block, what: &str) {
    let tip = server.get_best_block_hash().await.expect("getbestblockhash");
    assert_eq!(tip, expected.block_hash().to_hex(), "{what}");
    assert_eq!(
        server.get_block_count().await.expect("getblockcount"),
        5,
        "{what}: height"
    );
}

async fn assert_height_index(server: &RpcServerImpl, heights: &[(u32, &Block)]) {
    for (height, block) in heights {
        let got = server
            .get_block_hash(serde_json::json!(height))
            .await
            .unwrap_or_else(|e| panic!("getblockhash({height}) failed: {e}"));
        assert_eq!(
            got,
            block.block_hash().to_hex(),
            "height index at {height} must agree with the active chain"
        );
    }
}

async fn assert_coin(server: &RpcServerImpl, block: &Block, present: bool, best: &Block) {
    let txid = block.transactions[0].txid();
    let raw = server
        .get_tx_out(txid.to_hex(), serde_json::json!(0), Some(false))
        .await
        .expect("gettxout");
    if !present {
        assert!(
            raw.is_none(),
            "coinbase of {} must not be in the UTXO set, got {}",
            block.block_hash().to_hex(),
            raw.unwrap().get()
        );
        return;
    }
    let raw = raw.unwrap_or_else(|| {
        panic!(
            "coinbase of {} must be in the UTXO set",
            block.block_hash().to_hex()
        )
    });
    let json: serde_json::Value = serde_json::from_str(raw.get()).expect("gettxout json");
    assert_eq!(
        json["bestblock"].as_str(),
        Some(best.block_hash().to_hex().as_str()),
        "gettxout bestblock"
    );
    assert_eq!(json["coinbase"], serde_json::Value::Bool(true));
}

/// Active G-1-2-3a-4a-5a, valid side 3'-4'-5' on 2. `invalidateblock 4a`
/// must activate 5' (Core). Master stops on 3a.
#[tokio::test]
async fn test_kb180_invalidateblock_activates_heavier_side_branch() {
    let chain = active_chain().await;
    let side = submit_side(&chain, SUBSIDY).await;

    chain
        .server
        .invalidate_block(chain.blocks[4].block_hash().to_hex())
        .await
        .expect("invalidateblock");

    assert_tip(
        &chain.server,
        &side[2],
        "invalidateblock 4a must activate heavier side tip 5'; the pre-fix tip is 3a",
    )
    .await;
    assert_height_index(
        &chain.server,
        &[(2, &chain.blocks[2]), (3, &side[0]), (4, &side[1]), (5, &side[2])],
    )
    .await;
    assert_coin(&chain.server, &side[0], true, &side[2]).await;
    assert_coin(&chain.server, &side[2], true, &side[2]).await;
    assert_coin(&chain.server, &chain.blocks[3], false, &side[2]).await;
    assert_coin(&chain.server, &chain.blocks[5], false, &side[2]).await;

    let failed_4a = index_status(&chain.db, &chain.blocks[4].block_hash());
    let failed_5a = index_status(&chain.db, &chain.blocks[5].block_hash());
    assert!(
        is_failed(failed_4a),
        "4a must be failed, status {:#x}",
        failed_4a.raw()
    );
    assert!(
        is_failed(failed_5a),
        "5a must be failed, status {:#x}",
        failed_5a.raw()
    );
}

/// Same shape, but side tip 5'' overpays its coinbase. `invalidateblock 4a`
/// must land on 4', mark 5'' `BLOCK_FAILED_VALID`, and not return an RPC error.
/// Master stops on 3a and leaves 5'' unmarked.
#[tokio::test]
async fn test_kb180_invalidateblock_skips_bad_side_tip() {
    let chain = active_chain().await;
    let side = submit_side(&chain, SUBSIDY + 100_000_000).await;
    let bad = &side[2];
    assert!(
        !is_failed(index_status(&chain.db, &bad.block_hash())),
        "equal-work bad tip must be stored without a failure flag until it is connected"
    );

    chain
        .server
        .invalidate_block(chain.blocks[4].block_hash().to_hex())
        .await
        .expect("invalidateblock must not return an RPC error when a candidate fails validation");

    let tip = chain.server.get_best_block_hash().await.expect("getbestblockhash");
    assert_eq!(
        tip,
        side[1].block_hash().to_hex(),
        "invalidateblock 4a must activate 4' and skip bad-cb-amount 5''; the pre-fix tip is 3a"
    );
    assert_eq!(chain.server.get_block_count().await.unwrap(), 4);
    assert_height_index(
        &chain.server,
        &[(2, &chain.blocks[2]), (3, &side[0]), (4, &side[1])],
    )
    .await;
    assert_coin(&chain.server, &side[0], true, &side[1]).await;
    assert_coin(&chain.server, &side[1], true, &side[1]).await;
    assert_coin(&chain.server, &chain.blocks[3], false, &side[1]).await;

    let bad_status = index_status(&chain.db, &bad.block_hash());
    assert!(
        bad_status.has(BlockStatus::FAILED_VALIDITY),
        "5'' must be BLOCK_FAILED_VALID, status {:#x}",
        bad_status.raw()
    );
    assert!(
        is_failed(index_status(&chain.db, &chain.blocks[4].block_hash())),
        "4a must stay failed"
    );
    assert!(
        is_failed(index_status(&chain.db, &chain.blocks[5].block_hash())),
        "5a must stay failed"
    );
}

/// The switch in case 1 is the chain the node loads on the next start.
/// 4a and 5a stay failed. Tie-break against a later `reconsiderblock` is out
/// of scope (5a and 5' have equal work).
#[tokio::test]
async fn test_kb180_invalidate_switch_survives_restart() {
    let chain = active_chain().await;
    let side = submit_side(&chain, SUBSIDY).await;
    let tip5 = side[2].block_hash();
    let block_4a = chain.blocks[4].block_hash();
    let block_5a = chain.blocks[5].block_hash();
    let block_3a = chain.blocks[3].block_hash();
    let fork = chain.blocks[2].block_hash();
    let side_hashes: Vec<Hash256> = side.iter().map(|b| b.block_hash()).collect();
    let side_coin = side[0].transactions[0].txid();

    chain
        .server
        .invalidate_block(block_4a.to_hex())
        .await
        .expect("invalidateblock");

    let path = chain.path.clone();
    let dir = chain.dir;
    drop(chain.server);
    drop(chain.db);

    let (server, db) = reopen_like_node(&path);
    let _keep_dir = dir;

    let tip = server.get_best_block_hash().await.expect("getbestblockhash");
    assert_eq!(
        tip, tip5.to_hex(),
        "after restart the active tip must still be 5'"
    );
    assert_ne!(tip, block_5a.to_hex(), "restart reverted the active chain to 5a");
    assert_ne!(tip, block_3a.to_hex(), "restart reverted the active chain to 3a");
    assert_eq!(server.get_block_count().await.unwrap(), 5);
    for (height, hash) in [
        (2, fork),
        (3, side_hashes[0]),
        (4, side_hashes[1]),
        (5, side_hashes[2]),
    ] {
        let got = server
            .get_block_hash(serde_json::json!(height))
            .await
            .unwrap_or_else(|e| panic!("getblockhash({height}) after restart: {e}"));
        assert_eq!(got, hash.to_hex(), "height index at {height} after restart");
    }

    assert!(
        is_failed(index_status(&db, &block_4a)),
        "4a must still be failed after restart"
    );
    assert!(
        is_failed(index_status(&db, &block_5a)),
        "5a must still be failed after restart"
    );

    let coin = server
        .get_tx_out(side_coin.to_hex(), serde_json::json!(0), Some(false))
        .await
        .expect("gettxout");
    assert!(
        coin.is_some(),
        "3' coinbase must still be in the UTXO set after restart"
    );
}
