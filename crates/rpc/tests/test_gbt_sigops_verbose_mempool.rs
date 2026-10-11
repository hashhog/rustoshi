//! Core v31.1 parity for two pre-existing mismatches:
//!
//! * `getblocktemplate` `sigops` is `GetTransactionSigOpCost`
//!   (legacy×4 + P2SH×4 + witness sigops), and that same cost is what the
//!   template charges against `sigoplimit` (80_000).
//! * Verbose `getrawmempool` / `getmempoolentry` follow `entryToJSON`
//!   (`src/rpc/mempool.cpp` at tag v31.1): in-mempool `depends` / `spentby`,
//!   opt-in `bip125-replaceable` (not forced true by full-RBF), `unbroadcast`
//!   until a local submission is announced, admission `height`, and
//!   `chunkweight` + `fees.chunk` from the chunk feerate.
//!
//! Modeled on Core's `mining_getblocktemplate*.py`, `mempool_packages.py`,
//! and `rpc_mempool_info.py`.

use std::collections::HashMap;
use std::sync::Arc;

use rustoshi_consensus::{
    build_block_template, AtmpOptions, BlockTemplateConfig, ChainParams, CoinEntry, Mempool,
    MempoolConfig, MAX_BLOCK_SIGOPS_COST,
};
use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::block_store::CoinEntry as StoreCoin;
use rustoshi_storage::{BlockStore, ChainDb};
use serde_json::Value;
use tokio::sync::RwLock;

fn p2pkh(tag: u8) -> Vec<u8> {
    let mut v = vec![0x76, 0xa9, 0x14];
    v.extend_from_slice(&[tag; 20]);
    v.extend_from_slice(&[0x88, 0xac]);
    v
}

fn p2wpkh(tag: u8) -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[tag; 20]);
    v
}

fn p2sh_script() -> Vec<u8> {
    let mut v = vec![0xa9, 0x14];
    v.extend_from_slice(&[0xab; 20]);
    v.push(0x87);
    v
}

/// 2-of-3 bare multisig redeem: accurate sigop count is 3 (the OP_3).
fn multisig_2_of_3_redeem() -> Vec<u8> {
    let pk = |b: u8| {
        let mut k = vec![0x02];
        k.extend_from_slice(&[b; 32]);
        k
    };
    let mut r = vec![0x52]; // OP_2
    for b in [0x11, 0x22, 0x33] {
        let k = pk(b);
        r.push(k.len() as u8);
        r.extend_from_slice(&k);
    }
    r.push(0x53); // OP_3
    r.push(0xae); // OP_CHECKMULTISIG
    r
}

fn push_script(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    if data.len() < 76 {
        v.push(data.len() as u8);
    } else {
        v.push(0x4c);
        v.push(data.len() as u8);
    }
    v.extend_from_slice(data);
    v
}

fn coin(value: u64, script: Vec<u8>) -> CoinEntry {
    CoinEntry {
        value,
        script_pubkey: script,
        height: 1,
        is_coinbase: false,
    }
}

fn tx_in(prev: Hash256, vout: u32, sequence: u32, script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid: prev, vout },
        script_sig,
        sequence,
        witness,
    }
}

fn tx_out(value: u64, script: Vec<u8>) -> TxOut {
    TxOut {
        value,
        script_pubkey: script,
    }
}

fn tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        inputs,
        outputs,
        lock_time: 0,
    }
}

fn p2wpkh_witness() -> Vec<Vec<u8>> {
    vec![vec![0x30; 71], vec![0x02; 33]]
}

async fn fixture() -> (RpcServerImpl, Arc<RwLock<RpcState>>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("db"));
    // Leak the tempdir for the test process; the db must outlive the guard.
    std::mem::forget(tmp);
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let peers = Arc::new(RwLock::new(PeerState::default()));
    let rpc = RpcServerImpl::new(state.clone(), peers);
    (rpc, state)
}

async fn admit(
    state: &RwLock<RpcState>,
    tx: Transaction,
    utxos: &HashMap<OutPoint, CoinEntry>,
) -> Hash256 {
    let mut s = state.write().await;
    let opts = AtmpOptions {
        skip_script_checks: true,
        ..AtmpOptions::default()
    };
    s.mempool
        .add_transaction_with_options(tx, &|op| utxos.get(op).cloned(), opts)
        .expect("tx admitted")
}

fn parse_raw(raw: &serde_json::value::RawValue) -> Value {
    serde_json::from_str(raw.get()).expect("json")
}

fn sats(v: &Value) -> i64 {
    let n = v.as_f64().unwrap_or_else(|| panic!("amount {v}"));
    (n * 100_000_000.0).round() as i64
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap_or_else(|| panic!("array {v}"))
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn keys_of(v: &Value) -> Vec<String> {
    v.as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

/// Core `depends` is a `std::set<std::string>` of display txids.
fn hex_sorted(ids: &[Hash256]) -> Vec<String> {
    let mut s: Vec<String> = ids.iter().map(|h| h.to_hex()).collect();
    s.sort();
    s.dedup();
    s
}

/// Core `spentby` sorts children with `uint256` memcmp (internal byte order).
fn internal_sorted(ids: &[Hash256]) -> Vec<String> {
    let mut v = ids.to_vec();
    v.sort();
    v.dedup();
    v.into_iter().map(|h| h.to_hex()).collect()
}

fn orders_differ(a: Hash256, b: Hash256) -> bool {
    hex_sorted(&[a, b]) != internal_sorted(&[a, b])
}

async fn pool_map(rpc: &RpcServerImpl) -> Value {
    parse_raw(
        &rpc.get_raw_mempool(Some(true))
            .await
            .expect("getrawmempool"),
    )
}

async fn one_entry(rpc: &RpcServerImpl, txid: &str) -> Value {
    parse_raw(
        &rpc.get_mempool_entry(txid.to_string())
            .await
            .expect("getmempoolentry"),
    )
}

const ENTRY_KEYS: &[&str] = &[
    "vsize",
    "weight",
    "time",
    "height",
    "descendantcount",
    "descendantsize",
    "ancestorcount",
    "ancestorsize",
    "wtxid",
    "chunkweight",
    "fees",
    "depends",
    "spentby",
    "bip125-replaceable",
    "unbroadcast",
];

const FEE_KEYS: &[&str] = &["base", "modified", "ancestor", "descendant", "chunk"];

fn assert_entry_shape(entry: &Value) {
    let got = keys_of(entry);
    let want: Vec<String> = ENTRY_KEYS.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(got, want, "entryToJSON key order");
    let fee_keys = keys_of(&entry["fees"]);
    let want_fees: Vec<String> = FEE_KEYS.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(fee_keys, want_fees, "fees key order");
    assert!(entry["depends"].is_array());
    assert!(entry["spentby"].is_array());
    assert!(entry["bip125-replaceable"].is_boolean());
    assert!(entry["unbroadcast"].is_boolean());
    assert!(entry["height"].is_u64());
    assert!(entry["chunkweight"].is_u64());
    assert!(entry["fees"]["chunk"].is_number());
}

// ---------------------------------------------------------------- sigops

/// P2WPKH spend: legacy sigops are 0, witness sigop is 1. Core reports 1.
#[tokio::test]
async fn gbt_p2wpkh_spend_reports_sigop_cost_one() {
    let (rpc, state) = fixture().await;
    let prev = Hash256::from_bytes([0x11; 32]);
    let mut utxos = HashMap::new();
    utxos.insert(OutPoint { txid: prev, vout: 0 }, coin(1_000_000, p2wpkh(1)));
    let spend = tx(
        vec![tx_in(prev, 0, 0xffff_ffff, vec![], p2wpkh_witness())],
        vec![tx_out(900_000, p2wpkh(2))],
    );
    let id = admit(&state, spend, &utxos).await;

    let template = rpc
        .get_block_template(Some(serde_json::json!({"rules": ["segwit"]})))
        .await
        .expect("gbt");
    assert_eq!(
        template["sigoplimit"].as_u64(),
        Some(MAX_BLOCK_SIGOPS_COST),
        "sigoplimit stays MAX_BLOCK_SIGOPS_COST"
    );
    let txs = template["transactions"].as_array().unwrap();
    let entry = txs
        .iter()
        .find(|t| t["txid"].as_str() == Some(id.to_hex().as_str()))
        .expect("spend in template");
    assert_eq!(
        entry["sigops"].as_u64(),
        Some(1),
        "P2WPKH spend sigop cost is the witness sigop, not legacy×4"
    );
    let summed: u64 = txs.iter().map(|t| t["sigops"].as_u64().unwrap()).sum();
    assert!(
        summed <= MAX_BLOCK_SIGOPS_COST,
        "template sigops {summed} must stay within sigoplimit"
    );
    assert_eq!(summed, 1, "the one spend is the whole non-coinbase sigop total");
}

/// P2SH 2-of-3: accurate redeem sigops 3, scaled by 4 → cost 12. Legacy is 0.
#[tokio::test]
async fn gbt_p2sh_multisig_spend_reports_scaled_sigop_cost() {
    let (rpc, state) = fixture().await;
    let prev = Hash256::from_bytes([0x22; 32]);
    let redeem = multisig_2_of_3_redeem();
    let mut script_sig = vec![0x00];
    script_sig.extend(push_script(&[0x30, 0x01]));
    script_sig.extend(push_script(&[0x30, 0x02]));
    script_sig.extend(push_script(&redeem));
    let mut utxos = HashMap::new();
    utxos.insert(OutPoint { txid: prev, vout: 0 }, coin(1_000_000, p2sh_script()));
    let spend = tx(
        vec![tx_in(prev, 0, 0xffff_ffff, script_sig, vec![])],
        vec![tx_out(900_000, p2wpkh(9))],
    );
    let id = admit(&state, spend, &utxos).await;

    let template = rpc
        .get_block_template(Some(serde_json::json!({"rules": ["segwit"]})))
        .await
        .expect("gbt");
    let txs = template["transactions"].as_array().unwrap();
    let entry = txs
        .iter()
        .find(|t| t["txid"].as_str() == Some(id.to_hex().as_str()))
        .expect("p2sh spend in template");
    assert_eq!(
        entry["sigops"].as_u64(),
        Some(12),
        "P2SH 2-of-3 sigop cost is 3×WITNESS_SCALE_FACTOR"
    );
    assert_eq!(template["sigoplimit"].as_u64(), Some(80_000));
}

/// Witness sigops count against the same budget `sigoplimit` advertises.
/// Three cost-1 spends and `max_sigops = 2` (strict `>=`) admit one.
#[test]
fn gbt_sigop_budget_charges_witness_sigop_cost() {
    let mut mempool = Mempool::new(MempoolConfig::default());
    let mut utxos = HashMap::new();
    for i in 0u8..3 {
        let prev = Hash256::from_bytes([0x30 + i; 32]);
        utxos.insert(OutPoint { txid: prev, vout: 0 }, coin(1_000_000, p2wpkh(i)));
        // Decreasing fee so selection order is deterministic.
        let out = 900_000 - i as u64 * 10_000;
        let spend = tx(
            vec![tx_in(prev, 0, 0xffff_ffff, vec![], p2wpkh_witness())],
            vec![tx_out(out, p2wpkh(0x40 + i))],
        );
        mempool
            .add_transaction_with_options(
                spend,
                &|op| utxos.get(op).cloned(),
                AtmpOptions {
                    skip_script_checks: true,
                    ..AtmpOptions::default()
                },
            )
            .expect("admit");
    }
    let template = build_block_template(
        &mempool,
        Hash256::ZERO,
        1,
        1_700_000_000,
        0x207f_ffff,
        0,
        &ChainParams::regtest(),
        &BlockTemplateConfig {
            coinbase_script_pubkey: vec![0x51],
            max_sigops: 2,
            ..BlockTemplateConfig::default()
        },
    );
    assert_eq!(
        template.transactions.len(),
        2,
        "coinbase + one cost-1 spend; a second makes 1+1 >= 2"
    );
    assert_eq!(template.per_tx_sigops, vec![0, 1]);
    assert_eq!(template.total_sigops, template.per_tx_sigops.iter().sum::<u64>());
    assert!(template.total_sigops <= 2);
}

/// A legacy P2PKH output is still cost 4, and that cost is inside the total.
#[test]
fn gbt_legacy_p2pkh_sigop_cost_stays_four_and_sums() {
    let mut mempool = Mempool::new(MempoolConfig::default());
    let prev = Hash256::from_bytes([0x44; 32]);
    let mut utxos = HashMap::new();
    utxos.insert(OutPoint { txid: prev, vout: 0 }, coin(1_000_000, p2pkh(1)));
    let spend = tx(
        vec![tx_in(prev, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(900_000, p2pkh(2))],
    );
    mempool
        .add_transaction_with_options(
            spend,
            &|op| utxos.get(op).cloned(),
            AtmpOptions {
                skip_script_checks: true,
                ..AtmpOptions::default()
            },
        )
        .unwrap();
    let template = build_block_template(
        &mempool,
        Hash256::ZERO,
        1,
        1_700_000_000,
        0x207f_ffff,
        0,
        &ChainParams::regtest(),
        &BlockTemplateConfig {
            coinbase_script_pubkey: vec![0x51],
            ..BlockTemplateConfig::default()
        },
    );
    assert_eq!(template.per_tx_sigops, vec![0, 4]);
    assert_eq!(template.total_sigops, 4);
}

// ------------------------------------------------------- verbose mempool

#[tokio::test]
async fn verbose_chain_depends_spentby_and_rpc_agreement() {
    let (rpc, state) = fixture().await;
    {
        let mut s = state.write().await;
        s.mempool.notify_new_tip(40, 1_700_000_000);
        s.best_height = 40;
    }
    let confirmed = Hash256::from_bytes([0x51; 32]);
    let mut utxos = HashMap::new();
    utxos.insert(
        OutPoint {
            txid: confirmed,
            vout: 0,
        },
        coin(1_000_000, p2pkh(1)),
    );
    // Parent signals BIP125. Child and grandchild do not.
    let parent = tx(
        vec![tx_in(confirmed, 0, 0xffff_fffd, vec![], vec![])],
        vec![tx_out(990_000, p2pkh(2))],
    );
    let parent_id = admit(&state, parent, &utxos).await;
    utxos.insert(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        coin(990_000, p2pkh(2)),
    );
    let child = tx(
        vec![tx_in(parent_id, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(900_000, p2pkh(3))],
    );
    let child_id = admit(&state, child, &utxos).await;
    utxos.insert(
        OutPoint {
            txid: child_id,
            vout: 0,
        },
        coin(900_000, p2pkh(3)),
    );
    let grand = tx(
        vec![tx_in(child_id, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(800_000, p2pkh(4))],
    );
    let grand_id = admit(&state, grand, &utxos).await;

    // Live tip moves; admission height must not.
    state.write().await.best_height = 55;

    let raw = pool_map(&rpc).await;
    let ids = [parent_id, child_id, grand_id];
    for id in &ids {
        let from_pool = &raw[&id.to_hex()];
        let from_entry = one_entry(&rpc, &id.to_hex()).await;
        assert_eq!(
            from_pool, &from_entry,
            "getrawmempool and getmempoolentry diverge for {}",
            id.to_hex()
        );
        assert_entry_shape(from_pool);
        assert_eq!(from_pool["height"].as_u64(), Some(40), "admission height");
        assert_eq!(from_pool["unbroadcast"], false);
        assert_eq!(from_pool["bip125-replaceable"], true);
    }
    assert_eq!(strings(&raw[&parent_id.to_hex()]["depends"]), Vec::<String>::new());
    assert_eq!(
        strings(&raw[&parent_id.to_hex()]["spentby"]),
        vec![child_id.to_hex()]
    );
    assert_eq!(
        strings(&raw[&child_id.to_hex()]["depends"]),
        vec![parent_id.to_hex()]
    );
    assert_eq!(
        strings(&raw[&child_id.to_hex()]["spentby"]),
        vec![grand_id.to_hex()]
    );
    assert_eq!(
        strings(&raw[&grand_id.to_hex()]["depends"]),
        vec![child_id.to_hex()]
    );
    assert_eq!(strings(&raw[&grand_id.to_hex()]["spentby"]), Vec::<String>::new());

    // Chain is one chunk: grandchild's fee pulls the parents in.
    let chunk_fee = 10_000 + 90_000 + 100_000;
    for id in &ids {
        assert_eq!(sats(&raw[&id.to_hex()]["fees"]["chunk"]), chunk_fee);
    }
    let chunk_weight: u64 = ids
        .iter()
        .map(|id| raw[&id.to_hex()]["weight"].as_u64().unwrap())
        .sum();
    for id in &ids {
        assert_eq!(raw[&id.to_hex()]["chunkweight"].as_u64(), Some(chunk_weight));
    }

    let ancestors = parse_raw(
        &rpc.get_mempool_ancestors(grand_id.to_hex(), Some(true))
            .await
            .unwrap(),
    );
    assert!(ancestors.get(&parent_id.to_hex()).is_some());
    assert_eq!(
        strings(&ancestors[&parent_id.to_hex()]["spentby"]),
        vec![child_id.to_hex()]
    );
    assert_eq!(ancestors[&child_id.to_hex()]["bip125-replaceable"], true);
    let descendants = parse_raw(
        &rpc.get_mempool_descendants(parent_id.to_hex(), Some(true))
            .await
            .unwrap(),
    );
    assert_eq!(
        strings(&descendants[&grand_id.to_hex()]["depends"]),
        vec![child_id.to_hex()]
    );
}

#[tokio::test]
async fn verbose_two_children_spentby_sorted_by_internal_txid() {
    let (rpc, state) = fixture().await;
    let confirmed = Hash256::from_bytes([0x61; 32]);
    let mut utxos = HashMap::new();
    utxos.insert(
        OutPoint {
            txid: confirmed,
            vout: 0,
        },
        coin(3_000_000, p2pkh(1)),
    );

    let mut chosen: Option<(Hash256, Hash256, Hash256)> = None;
    for marker in 0u8..64 {
        let parent = tx(
            vec![tx_in(confirmed, 0, 0xffff_ffff, vec![], vec![])],
            vec![
                tx_out(1_000_000, p2pkh(marker)),
                tx_out(1_000_000, p2pkh(marker.wrapping_add(1))),
                tx_out(900_000, p2pkh(0xfe)),
            ],
        );
        let parent_id = parent.txid();
        let child_a = tx(
            vec![tx_in(parent_id, 0, 0xffff_ffff, vec![], vec![])],
            vec![tx_out(900_000, p2pkh(0x10))],
        );
        let child_b = tx(
            vec![tx_in(parent_id, 1, 0xffff_ffff, vec![], vec![])],
            vec![tx_out(500_000, p2pkh(0x11))],
        );
        if orders_differ(child_a.txid(), child_b.txid()) {
            chosen = Some((parent_id, child_a.txid(), child_b.txid()));
            let pid = admit(&state, parent, &utxos).await;
            assert_eq!(pid, parent_id);
            utxos.insert(
                OutPoint { txid: pid, vout: 0 },
                coin(1_000_000, p2pkh(marker)),
            );
            utxos.insert(
                OutPoint { txid: pid, vout: 1 },
                coin(1_000_000, p2pkh(marker.wrapping_add(1))),
            );
            admit(&state, child_a, &utxos).await;
            admit(&state, child_b, &utxos).await;
            break;
        }
    }
    let (parent_id, a, b) = chosen.expect("txid pair whose hex order differs from uint256 order");
    let raw = pool_map(&rpc).await;
    let spentby = strings(&raw[&parent_id.to_hex()]["spentby"]);
    assert_eq!(spentby, internal_sorted(&[a, b]));
    assert_ne!(
        spentby,
        hex_sorted(&[a, b]),
        "spentby follows uint256 order, not display-hex order"
    );
    // High-fee child pulls the parent into its chunk; the low-fee child is its own.
    let high = if sats(&raw[&a.to_hex()]["fees"]["base"]) > sats(&raw[&b.to_hex()]["fees"]["base"])
    {
        a
    } else {
        b
    };
    let low = if high == a { b } else { a };
    let package = sats(&raw[&parent_id.to_hex()]["fees"]["base"]) + sats(&raw[&high.to_hex()]["fees"]["base"]);
    assert_eq!(sats(&raw[&parent_id.to_hex()]["fees"]["chunk"]), package);
    assert_eq!(sats(&raw[&high.to_hex()]["fees"]["chunk"]), package);
    assert_eq!(
        sats(&raw[&low.to_hex()]["fees"]["chunk"]),
        sats(&raw[&low.to_hex()]["fees"]["base"])
    );
    assert_ne!(
        raw[&parent_id.to_hex()]["chunkweight"],
        raw[&low.to_hex()]["chunkweight"]
    );
}

/// Both children pay enough that the whole cluster is one chunk.
#[tokio::test]
async fn verbose_two_high_fee_children_share_one_chunk() {
    let (rpc, state) = fixture().await;
    let confirmed = Hash256::from_bytes([0x71; 32]);
    let mut utxos = HashMap::new();
    utxos.insert(
        OutPoint {
            txid: confirmed,
            vout: 0,
        },
        coin(3_000_000, p2pkh(1)),
    );
    let parent = tx(
        vec![tx_in(confirmed, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(1_400_000, p2pkh(2)), tx_out(1_400_000, p2pkh(3))],
    );
    let parent_id = admit(&state, parent, &utxos).await;
    utxos.insert(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        coin(1_400_000, p2pkh(2)),
    );
    utxos.insert(
        OutPoint {
            txid: parent_id,
            vout: 1,
        },
        coin(1_400_000, p2pkh(3)),
    );
    let c1 = tx(
        vec![tx_in(parent_id, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(1_200_000, p2pkh(4))],
    );
    let c2 = tx(
        vec![tx_in(parent_id, 1, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(1_200_000, p2pkh(5))],
    );
    let c1_id = admit(&state, c1, &utxos).await;
    let c2_id = admit(&state, c2, &utxos).await;
    let raw = pool_map(&rpc).await;
    // fees: parent 200_000, each child 200_000.
    let total = 600_000;
    for id in [parent_id, c1_id, c2_id] {
        assert_eq!(sats(&raw[&id.to_hex()]["fees"]["chunk"]), total);
    }
    let weight: u64 = [parent_id, c1_id, c2_id]
        .iter()
        .map(|id| raw[&id.to_hex()]["weight"].as_u64().unwrap())
        .sum();
    assert_eq!(raw[&parent_id.to_hex()]["chunkweight"].as_u64(), Some(weight));
}

/// A tx that spends two mempool parents lists both, in display-hex order.
#[tokio::test]
async fn verbose_two_parents_depends_sorted_by_display_hex() {
    let (rpc, state) = fixture().await;
    let mut utxos = HashMap::new();
    let mut chosen = None;
    for marker in 0u8..64 {
        let ca = Hash256::from_bytes([0x80, marker, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let cb = Hash256::from_bytes([0x80, marker, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let pa = tx(
            vec![tx_in(ca, 0, 0xffff_ffff, vec![], vec![])],
            vec![tx_out(500_000, p2pkh(marker))],
        );
        let pb = tx(
            vec![tx_in(cb, 0, 0xffff_ffff, vec![], vec![])],
            vec![tx_out(500_000, p2pkh(marker.wrapping_add(7)))],
        );
        if !orders_differ(pa.txid(), pb.txid()) {
            continue;
        }
        chosen = Some((ca, cb, pa, pb));
        break;
    }
    let (ca, cb, pa, pb) = chosen.expect("parent pair with distinct sort orders");
    utxos.insert(OutPoint { txid: ca, vout: 0 }, coin(600_000, p2pkh(1)));
    utxos.insert(OutPoint { txid: cb, vout: 0 }, coin(600_000, p2pkh(2)));
    let pa_id = admit(&state, pa, &utxos).await;
    let pb_id = admit(&state, pb, &utxos).await;
    utxos.insert(OutPoint { txid: pa_id, vout: 0 }, coin(500_000, p2pkh(3)));
    utxos.insert(OutPoint { txid: pb_id, vout: 0 }, coin(500_000, p2pkh(4)));
    let child = tx(
        vec![
            tx_in(pa_id, 0, 0xffff_ffff, vec![], vec![]),
            tx_in(pb_id, 0, 0xffff_ffff, vec![], vec![]),
        ],
        vec![tx_out(900_000, p2pkh(5))],
    );
    let child_id = admit(&state, child, &utxos).await;
    let raw = pool_map(&rpc).await;
    let depends = strings(&raw[&child_id.to_hex()]["depends"]);
    assert_eq!(depends, hex_sorted(&[pa_id, pb_id]));
    assert_ne!(depends, internal_sorted(&[pa_id, pb_id]));
    assert_eq!(strings(&raw[&pa_id.to_hex()]["spentby"]), vec![child_id.to_hex()]);
    assert_eq!(strings(&raw[&pb_id.to_hex()]["spentby"]), vec![child_id.to_hex()]);
}

/// Full-RBF is the default, but `bip125-replaceable` stays the opt-in signal
/// (self or an unconfirmed ancestor). A final tx with final ancestors is false.
#[tokio::test]
async fn verbose_bip125_is_opt_in_under_full_rbf() {
    let (rpc, state) = fixture().await;
    let mut utxos = HashMap::new();
    let signaled_prev = Hash256::from_bytes([0x91; 32]);
    let final_prev = Hash256::from_bytes([0x92; 32]);
    utxos.insert(
        OutPoint {
            txid: signaled_prev,
            vout: 0,
        },
        coin(1_000_000, p2pkh(1)),
    );
    utxos.insert(
        OutPoint {
            txid: final_prev,
            vout: 0,
        },
        coin(1_000_000, p2pkh(2)),
    );
    let signaled = tx(
        vec![tx_in(signaled_prev, 0, 0xffff_fffd, vec![], vec![])],
        vec![tx_out(900_000, p2pkh(3))],
    );
    let final_tx = tx(
        vec![tx_in(final_prev, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(900_000, p2pkh(4))],
    );
    let signaled_id = admit(&state, signaled, &utxos).await;
    let final_id = admit(&state, final_tx, &utxos).await;
    let raw = pool_map(&rpc).await;
    assert_eq!(raw[&signaled_id.to_hex()]["bip125-replaceable"], true);
    assert_eq!(raw[&final_id.to_hex()]["bip125-replaceable"], false);
    assert_eq!(
        one_entry(&rpc, &final_id.to_hex()).await["bip125-replaceable"],
        false
    );
}

/// `sendrawtransaction` on a node with no peers stays unbroadcast, and the
/// count matches. A direct mempool admission (the p2p path) does not.
#[tokio::test]
async fn verbose_sendrawtransaction_stays_unbroadcast_without_peers() {
    let (rpc, state) = fixture().await;
    state.write().await.best_height = 40;

    let prev = Hash256::from_bytes([0xa1; 32]);
    let spk = p2pkh(7);
    {
        let db = state.read().await.db.clone();
        let store = BlockStore::new(&db);
        store
            .put_utxo(
                &OutPoint { txid: prev, vout: 0 },
                &StoreCoin {
                    height: 1,
                    is_coinbase: false,
                    value: 1_000_000,
                    script_pubkey: spk.clone(),
                },
            )
            .unwrap();
    }
    let local = tx(
        vec![tx_in(prev, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(900_000, p2pkh(8))],
    );
    let hex_tx = hex::encode(local.serialize());
    let txid = rpc
        .send_raw_transaction(hex_tx, Some(0.0), None)
        .await
        .expect("sendrawtransaction");
    state.write().await.best_height = 55;

    let entry = one_entry(&rpc, &txid).await;
    assert_eq!(entry["unbroadcast"], true);
    assert_eq!(entry["height"].as_u64(), Some(40));
    let info = rpc.get_mempool_info().await.unwrap();
    assert_eq!(info.unbroadcastcount, 1);

    // Peer-accepted tx: not in the unbroadcast set.
    let other_prev = Hash256::from_bytes([0xa2; 32]);
    let mut utxos = HashMap::new();
    utxos.insert(
        OutPoint {
            txid: other_prev,
            vout: 0,
        },
        coin(1_000_000, p2pkh(9)),
    );
    let peer_tx = tx(
        vec![tx_in(other_prev, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(900_000, p2pkh(10))],
    );
    let peer_id = admit(&state, peer_tx, &utxos).await;
    let peer_entry = one_entry(&rpc, &peer_id.to_hex()).await;
    assert_eq!(peer_entry["unbroadcast"], false);
    let info = rpc.get_mempool_info().await.unwrap();
    assert_eq!(info.unbroadcastcount, 1);
}

/// A tx mined and then re-added by invalidateblock takes the post-disconnect
/// tip as its admission height, and a later tip move does not rewrite it.
#[tokio::test]
async fn verbose_reorg_refill_height_is_readmission_height() {
    let (rpc, state) = fixture().await;
    let prev = Hash256::from_bytes([0xb1; 32]);
    let mut utxos = HashMap::new();
    utxos.insert(OutPoint { txid: prev, vout: 0 }, coin(1_000_000, p2pkh(1)));
    {
        let mut s = state.write().await;
        s.mempool.notify_new_tip(40, 0);
        s.best_height = 40;
    }
    let spend = tx(
        vec![tx_in(prev, 0, 0xffff_ffff, vec![], vec![])],
        vec![tx_out(900_000, p2pkh(2))],
    );
    let id = admit(&state, spend.clone(), &utxos).await;
    {
        let mut s = state.write().await;
        s.mempool.remove_transaction(&id, false);
        // Disconnect one block: tip is now 39, then the tx is re-added.
        s.mempool.notify_new_tip(39, 0);
        s.best_height = 39;
        let n = s.mempool.readd_disconnected_blocks(
            [std::slice::from_ref(&spend)],
            &|op| utxos.get(op).cloned(),
        );
        assert_eq!(n, 1, "refill accepted the disconnected tx");
        s.best_height = 70;
    }
    let entry = one_entry(&rpc, &id.to_hex()).await;
    assert_eq!(entry["height"].as_u64(), Some(39));
    assert_eq!(entry["unbroadcast"], false, "reorg refill is not a local broadcast");
    assert_eq!(
        pool_map(&rpc).await[&id.to_hex()]["height"].as_u64(),
        Some(39)
    );
}
