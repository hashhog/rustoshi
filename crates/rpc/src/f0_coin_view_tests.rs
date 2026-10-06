//! F0 coin-view pins (2026-10-06).
//!
//! The connect loop (`rustoshi/src/main.rs`) owns the node's one write-back
//! coin view and publishes `RpcState::best_*` per block while the coins it
//! spent are still only in that cache. These tests reproduce that state
//! exactly — blocks 1..=101 flushed through `submitblock`, block 102 connected
//! into a long-lived `BlockStoreUtxoView` that is NOT flushed, its index entry
//! written and the tip published, and an ARMED flush signal serviced by a
//! "connect loop" thread that commits `flush_with_tip_and_blocks` on request,
//! as main.rs does — and then ask the RPC surface about the coin block 102
//! spent. Core answers every probe from CoinsTip() under cs_main
//! (coins.cpp FetchCoin/SpendCoin, validation.cpp ConnectTip), so the spend is
//! always visible.
//!
//! The rollback test pins the second finding: `dumptxoutset` rollback's replay
//! re-added outputs with an ad-hoc OP_RETURN-only filter (plus a skip of empty
//! zero-value coinbase outputs) instead of Core's AddCoin rule
//! (`coins.cpp:84-91`, `CScript::IsUnspendable`).
//!
//! Public crate surface only, so the file compiles against the deployed tree
//! (that is how "fails before" was measured).

use crate::server::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{
    Block, BlockHeader, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut,
};
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus};
use rustoshi_storage::{BlockStore, ChainDb, CF_UTXO};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

const BASE_TIME: u32 = 1_700_000_000;

fn p2sh_true() -> Vec<u8> {
    let h = rustoshi_crypto::hash160(&[0x51]);
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&h.0);
    s.push(0x87);
    s
}

/// BIP34 height push (CScript() << h), plus a marker so txids differ.
fn coinbase(h: u32, value: u64, marker: u8, extra_outputs: Vec<TxOut>) -> Transaction {
    let mut ss = if h == 0 {
        vec![0x00]
    } else if h <= 16 {
        vec![0x50 + h as u8]
    } else {
        let mut v = Vec::new();
        let mut n = h;
        while n > 0 {
            v.push((n & 0xff) as u8);
            n >>= 8;
        }
        if v.last().copied().unwrap_or(0) & 0x80 != 0 {
            v.push(0);
        }
        let mut s = vec![v.len() as u8];
        s.extend(v);
        s
    };
    ss.extend_from_slice(&[0x01, marker]);
    let mut outputs = vec![TxOut { value, script_pubkey: p2sh_true() }];
    outputs.extend(extra_outputs);
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
            script_sig: ss,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs,
        lock_time: 0,
    }
}

/// Spend a P2SH(OP_TRUE) coin.
fn spend(prev: OutPoint, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![0x01, 0x51],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs,
        lock_time: 0,
    }
}

fn mine(h: u32, prev: Hash256, txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: BASE_TIME + h * 600,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: txs,
    };
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn hex_of<T: Encodable>(x: &T) -> String {
    let mut buf = Vec::new();
    x.encode(&mut buf).unwrap();
    hex::encode(buf)
}

struct Chain {
    db: Arc<ChainDb>,
    params: ChainParams,
    state: Arc<RwLock<RpcState>>,
    server: RpcServerImpl,
    /// Block 1's coinbase output: the coin block 102 spends.
    u: OutPoint,
    u_value: u64,
    blocks: Vec<Block>, // index = height (0 = genesis placeholder)
}

/// Regtest chain 1..=101 accepted through `submitblock` (flushed per block).
async fn chain_to_101() -> Chain {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    std::mem::forget(dir);
    let db = Arc::new(ChainDb::open(&path).unwrap());
    let params = ChainParams::regtest();
    BlockStore::new(&db).init_genesis(&params).unwrap();
    let mut st = RpcState::new(db.clone(), params.clone());
    st.best_hash = params.genesis_hash;
    st.best_height = 0;
    st.data_dir = Some(path);
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));
    let mut blocks = vec![params.genesis_block.clone()];
    let mut prev = params.genesis_hash;
    for h in 1..=101u32 {
        let b = mine(h, prev, vec![coinbase(h, 50 * 100_000_000, 0xF0, vec![])]);
        let r = server.submit_block(hex_of(&b)).await.expect("submitblock rpc");
        assert!(r.is_none(), "setup block {h} rejected: {r:?}");
        prev = b.block_hash();
        blocks.push(b);
    }
    let u = OutPoint { txid: blocks[1].transactions[0].txid(), vout: 0 };
    Chain { db, params, state, server, u, u_value: 50 * 100_000_000, blocks }
}

/// What the connect loop does for one block between flushes: connect it into
/// its long-lived view, write the block-index entry, keep body+undo pending,
/// publish the tip. Then service flush requests exactly like main.rs until
/// `stop` is set. Returns once block 102 is connected and published.
fn start_connect_loop(c: &Chain, block102: Block, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    let db = c.db.clone();
    let params = c.params.clone();
    let state = c.state.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        use rustoshi_consensus::validation::UtxoView;
        let store = BlockStore::new(&db);
        let mut view = store.utxo_view();
        let seq = rustoshi_storage::StoreSeqLockCtx::new(&store);
        let hash = block102.block_hash();
        let (undo, _fees) = rustoshi_consensus::validation::connect_block_with_sequence_locks(
            &block102,
            102,
            &mut view as &mut dyn UtxoView,
            &params,
            &seq,
            0,
            false,
            None,
        )
        .expect("block 102 is valid");
        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_SCRIPTS);
        status.set(BlockStatus::HAVE_DATA);
        store.put_header(&hash, &block102.header).unwrap();
        store
            .put_block_index(
                &hash,
                &BlockIndexEntry {
                    height: 102,
                    status,
                    n_tx: block102.transactions.len() as u32,
                    timestamp: block102.header.timestamp,
                    bits: block102.header.bits,
                    nonce: block102.header.nonce,
                    version: block102.header.version,
                    prev_hash: block102.header.prev_block_hash,
                    chain_work: [0u8; 32],
                },
            )
            .unwrap();
        store.put_height_index(102, &hash).unwrap();
        let storage_undo = rustoshi_storage::block_store::UndoData {
            spent_coins: undo
                .spent_coins
                .iter()
                .map(|c| rustoshi_storage::block_store::CoinEntry {
                    height: c.height,
                    is_coinbase: c.is_coinbase,
                    value: c.value,
                    script_pubkey: c.script_pubkey.clone(),
                })
                .collect(),
        };
        let mut pending = vec![(hash, block102.clone(), storage_undo)];
        let signal = {
            let mut st = state.blocking_write();
            st.best_hash = hash;
            st.best_height = 102;
            st.chainstate_flush.clone()
        };
        signal.arm();
        ready_tx.send(()).unwrap();
        while !stop.load(Ordering::SeqCst) {
            if let Some(seq_no) = signal.pending() {
                if view.cache_len() > 0 || !pending.is_empty() {
                    view.flush_with_tip_and_blocks(&hash, 102, &pending, &[], None)
                        .expect("flush");
                    pending.clear();
                }
                signal.complete(seq_no);
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });
    ready_rx.recv().unwrap();
    handle
}

/// The double spend: a tx re-spending U, and a block 103 carrying it.
fn double_spend(c: &Chain, tip102: Hash256) -> (Transaction, Block) {
    let d = spend(c.u.clone(), vec![TxOut { value: c.u_value - 20_000, script_pubkey: p2sh_true() }]);
    let x = mine(103, tip102, vec![coinbase(103, 50 * 100_000_000, 0xD5, vec![]), d.clone()]);
    (d, x)
}

/// Blocks 1..=101 flushed; block 102 (spends U) connected in the loop's view
/// but NOT flushed, tip published -- the state every unflushed P2P block
/// leaves behind.
async fn unflushed_window() -> (Chain, Hash256, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let c = chain_to_101().await;
    let t1 = spend(c.u.clone(), vec![TxOut { value: c.u_value - 10_000, script_pubkey: p2sh_true() }]);
    let b102 = mine(
        102,
        c.blocks[101].block_hash(),
        vec![coinbase(102, 50 * 100_000_000 + 10_000, 0xF1, vec![]), t1],
    );
    let h102 = b102.block_hash();
    let stop = Arc::new(AtomicBool::new(false));
    let handle = start_connect_loop(&c, b102, stop.clone());
    // The window really is open: the disk still holds U.
    assert!(
        BlockStore::new(&c.db).get_utxo(&c.u).unwrap().is_some(),
        "setup: U must still be on disk (block 102 unflushed)"
    );
    (c, h102, stop, handle)
}

fn finish(stop: Arc<AtomicBool>, handle: std::thread::JoinHandle<()>) {
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f0_gettxout_sees_unflushed_spend() {
    let (c, _h102, stop, handle) = unflushed_window().await;
    let r = c
        .server
        .get_tx_out(c.u.txid.to_hex(), serde_json::json!(0), Some(false))
        .await;
    finish(stop, handle);
    let r = r.expect("gettxout answered");
    assert!(
        r.is_none(),
        "gettxout reported U unspent although block 102 (the tip) spent it: {}",
        r.unwrap().get()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f0_testmempoolaccept_rejects_tx_spending_unflushed_spend() {
    let (c, h102, stop, handle) = unflushed_window().await;
    let (d, _x) = double_spend(&c, h102);
    let r = c.server.test_mempool_accept(vec![hex_of(&d)], None).await;
    finish(stop, handle);
    let r = r.expect("testmempoolaccept answered");
    assert_eq!(
        r[0]["allowed"].as_bool(),
        Some(false),
        "mempool admitted a tx re-spending U, which the tip (block 102) already spent: {r}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f0_submitblock_rejects_block_respending_unflushed_spend() {
    let (c, h102, stop, handle) = unflushed_window().await;
    let (_d, x103) = double_spend(&c, h102);
    let r = c.server.submit_block(hex_of(&x103)).await;
    let best = c.state.read().await.best_hash;
    finish(stop, handle);
    let r = r.expect("submitblock answered");
    assert_ne!(best, x103.block_hash(), "submitblock CONNECTED a block re-spending U");
    assert_eq!(
        r.as_deref(),
        Some("bad-txns-inputs-missingorspent"),
        "Core rejects a block re-spending a spent coin with bad-txns-inputs-missingorspent"
    );
}

/// Control: the same probes once the loop HAS flushed (the at-tip flush every
/// block on a caught-up node). Passes on both trees; it proves the probes and
/// the setup can tell a correct answer from a wrong one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f0_control_flushed_window_answers_like_core() {
    let (c, h102, stop, handle) = unflushed_window().await;
    {
        let sig = c.state.read().await.chainstate_flush.clone();
        let t = sig.request();
        while !sig.is_satisfied(t) {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }
    assert!(BlockStore::new(&c.db).get_utxo(&c.u).unwrap().is_none(), "flushed: U gone from disk");
    let (d, x103) = double_spend(&c, h102);
    let g = c.server.get_tx_out(c.u.txid.to_hex(), serde_json::json!(0), Some(false)).await;
    let t = c.server.test_mempool_accept(vec![hex_of(&d)], None).await;
    let s = c.server.submit_block(hex_of(&x103)).await;
    finish(stop, handle);
    assert!(g.expect("gettxout").is_none());
    assert_eq!(t.expect("tma")[0]["allowed"].as_bool(), Some(false));
    assert_eq!(s.expect("submitblock").as_deref(), Some("bad-txns-inputs-missingorspent"));
}

fn utxo_rows(db: &ChainDb) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows: Vec<_> = db
        .iter_cf(CF_UTXO)
        .unwrap()
        .filter(|(k, _)| k.len() == 36)
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

/// `dumptxoutset` rollback must leave the UTXO set byte-identical. Block 102
/// carries the two output kinds whose treatment differs between Core's AddCoin
/// rule and the replay's old ad-hoc filter:
///   * a > MAX_SCRIPT_SIZE (10,000-byte) output -- unspendable, never a coin
///     (connect skips it; the old replay ADDED it: a phantom coin);
///   * an empty-script, zero-value coinbase output -- spendable, a coin
///     (connect adds it; the old replay SKIPPED it: a vanished coin).
#[tokio::test]
async fn f0_dumptxoutset_rollback_replay_applies_core_addcoin_rule() {
    let c = chain_to_101().await;
    let oversized = vec![0x51u8; 10_001];
    let t1 = spend(
        c.u.clone(),
        vec![
            TxOut { value: 1_000, script_pubkey: oversized },
            TxOut { value: c.u_value - 101_000, script_pubkey: p2sh_true() },
        ],
    );
    let cb = coinbase(
        102,
        50 * 100_000_000 + 100_000,
        0xF2,
        vec![TxOut { value: 0, script_pubkey: vec![] }],
    );
    let b102 = mine(102, c.blocks[101].block_hash(), vec![cb.clone(), t1.clone()]);
    let r = c.server.submit_block(hex_of(&b102)).await.expect("rpc");
    assert!(r.is_none(), "block 102 must connect: {r:?}");

    let store = BlockStore::new(&c.db);
    let phantom = OutPoint { txid: t1.txid(), vout: 0 };
    let empty_cb = OutPoint { txid: cb.txid(), vout: 1 };
    assert!(store.get_utxo(&phantom).unwrap().is_none(), "connect: oversized output is not a coin");
    assert!(store.get_utxo(&empty_cb).unwrap().is_some(), "connect: empty zero-value output IS a coin");
    let before = utxo_rows(&c.db);

    c.server
        .dump_tx_outset("f0-rollback.dat".to_string(), None, Some(serde_json::json!({"rollback": 100})))
        .await
        .expect("rollback dump");

    let after = utxo_rows(&c.db);
    assert!(
        store.get_utxo(&phantom).unwrap().is_none(),
        "rollback replay ADDED the unspendable >10,000-byte output as a coin"
    );
    assert!(
        store.get_utxo(&empty_cb).unwrap().is_some(),
        "rollback replay DROPPED the empty-script zero-value coinbase coin"
    );
    assert_eq!(before, after, "UTXO set must round-trip through rollback byte-for-byte");
}

/// I5 (the install race found in blockbrew/hotbuns/beamchain/camlcoin/haskoin):
/// a reader misses, the coin is spent and the flush commits, then the stale
/// read would be installed. rustoshi's `BlockStoreUtxoView` never installs a
/// read (`get_utxo`/`try_get_utxo` only consult the cache, then the store), so
/// there is nothing to install: the miss leaves no entry, and after the spend
/// is flushed both the same view and a fresh one answer "absent". Passes on
/// the deployed tree too -- this is the proof that the class does not apply.
#[test]
fn f0_i5_view_never_installs_a_read() {
    use rustoshi_consensus::validation::{CoinEntry, UtxoView};
    let dir = tempfile::tempdir().unwrap();
    let db = ChainDb::open(dir.path()).unwrap();
    let store = BlockStore::new(&db);
    let x = OutPoint { txid: Hash256([0x5a; 32]), vout: 0 };
    {
        let mut v = store.utxo_view();
        v.add_utxo(&x, CoinEntry { height: 1, is_coinbase: false, value: 7, script_pubkey: vec![0x51] });
        v.flush().unwrap();
    }
    let mut reader = store.utxo_view();
    assert!(reader.get_utxo(&x).is_some(), "miss reads through to disk");
    assert_eq!(reader.cache_len(), 0, "a read is never installed in the cache");
    let mut writer = store.utxo_view();
    writer.spend_utxo(&x);
    writer.flush().unwrap();
    assert!(reader.get_utxo(&x).is_none(), "the earlier read left nothing to resurrect");
    assert!(store.utxo_view().get_utxo(&x).is_none());
    reader.spend_utxo(&x); // a stale view can still only tombstone, never re-add
    reader.flush().unwrap();
    assert!(store.get_utxo(&x).unwrap().is_none());
}
