//! `submitpackage` result shape against Bitcoin Core v31.1 `rpc/mempool.cpp`.
//!
//! Rejected `tx-results` entries carry `error` and omit `vsize` / `fees`.
//! An already-in-mempool member keeps `vsize` and `fees.base` and omits
//! `effective-feerate` / `effective-includes`. A non-standard child does not
//! evict a parent that was valid on its own (`rpc_packages.py`).

use crate::server::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_consensus::ChainParams;
use rustoshi_crypto::{
    ecdsa_sign, hash160, p2wpkh_script_code, public_key_from_private, segwit_v0_sighash,
    serialize_der_signature, serialize_pubkey_compressed, SecretKey,
};
use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::{BlockStore, ChainDb};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bitcoin Core v31.1 `rpc/mempool.cpp` `submitpackage` pushKV order.
const TOP_KEYS: &[&str] = &["package_msg", "tx-results", "replaced-transactions"];
const TX_ACCEPTED: &[&str] = &["txid", "vsize", "fees"];
const TX_REJECTED: &[&str] = &["txid", "error"];
const TX_OTHER_WTXID: &[&str] = &["txid", "other-wtxid"];
const FEES_VALID: &[&str] = &["base", "effective-feerate", "effective-includes"];
const FEES_MEMPOOL: &[&str] = &["base"];

fn p2sh_true() -> Vec<u8> {
    let h = rustoshi_crypto::hash160(&[0x51]);
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&h.0);
    s.push(0x87);
    s
}

fn spend(prev: OutPoint, value: u64, fee: u64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![0x01, 0x51],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: value - fee,
            script_pubkey: p2sh_true(),
        }],
        lock_time: 0,
    }
}

fn hex_tx(tx: &Transaction) -> String {
    let mut buf = Vec::new();
    tx.encode(&mut buf).unwrap();
    hex::encode(buf)
}

fn server() -> (Arc<RwLock<RpcState>>, RpcServerImpl) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let db = Arc::new(ChainDb::open(&path).unwrap());
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let peer_state = Arc::new(RwLock::new(PeerState::default()));
    let server = RpcServerImpl::new(state.clone(), peer_state);
    (state, server)
}

async fn call(
    state: &Arc<RwLock<RpcState>>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));
    let module = server.into_rpc();
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "pkg",
        "method": method,
        "params": params,
    })
    .to_string();
    let (resp, _) = module.raw_json_request(&req, 1).await.expect("dispatch");
    serde_json::from_str(&resp).expect("json response")
}

fn result(resp: serde_json::Value) -> serde_json::Value {
    assert!(
        resp.get("error").map(|e| e.is_null()).unwrap_or(true),
        "expected success, got {resp}"
    );
    resp["result"].clone()
}

struct Funded {
    state: Arc<RwLock<RpcState>>,
    parent: Transaction,
    child: Transaction,
}

async fn funded(parent_fee: u64, child_fee: u64) -> Funded {
    let (state, _server) = server();
    let prev = OutPoint {
        txid: Hash256::from([0x11u8; 32]),
        vout: 0,
    };
    let value = 1_000_000u64;
    {
        let mut st = state.write().await;
        BlockStore::new(&st.db)
            .put_utxo(
                &prev,
                &rustoshi_storage::CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value,
                    script_pubkey: p2sh_true(),
                },
            )
            .unwrap();
        st.mempool.notify_new_tip(200, 1_700_000_000);
    }
    let parent = spend(prev, value, parent_fee);
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        value - parent_fee,
        child_fee,
    );
    Funded {
        state,
        parent,
        child,
    }
}

fn entry<'a>(res: &'a serde_json::Value, wtxid: &str) -> &'a serde_json::Value {
    res["tx-results"]
        .get(wtxid)
        .unwrap_or_else(|| panic!("missing {wtxid} in {res}"))
}

fn object_keys(v: &serde_json::Value) -> Vec<String> {
    v.as_object()
        .unwrap_or_else(|| panic!("expected object, got {v}"))
        .keys()
        .cloned()
        .collect()
}

fn assert_keys(v: &serde_json::Value, expected: &[&str], what: &str) {
    let got = object_keys(v);
    assert_eq!(
        got,
        expected
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
        "{what}: {v}"
    );
}

fn assert_top(res: &serde_json::Value) {
    assert_keys(res, TOP_KEYS, "submitpackage result");
    assert!(res["replaced-transactions"].is_array(), "{res}");
}

fn assert_tx_order(res: &serde_json::Value, wtxids: &[&str]) {
    assert_eq!(
        object_keys(&res["tx-results"]),
        wtxids.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        "tx-results key order: {res}"
    );
}

/// Bad-version child: parent result keeps vsize/fees and has no error; the
/// child has `error` and no vsize/fees. Parent remains in the mempool.
#[tokio::test]
async fn submitpackage_partial_version_child_result_shape() {
    let f = funded(10_000, 10_000).await;
    let mut child = f.child.clone();
    child.version = 0x7fff_ffff;
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed");

    let parent = entry(&res, &f.parent.wtxid().to_hex());
    assert!(parent.get("error").is_none(), "{parent}");
    assert!(parent.get("vsize").is_some(), "{parent}");
    assert!(parent["fees"].get("base").is_some(), "{parent}");

    let child_res = entry(&res, &child.wtxid().to_hex());
    assert_eq!(child_res["error"], "version");
    assert!(child_res.get("vsize").is_none(), "{child_res}");
    assert!(child_res.get("fees").is_none(), "{child_res}");

    let pool = result(call(&f.state, "getrawmempool", serde_json::json!([false])).await);
    let txids: Vec<String> = serde_json::from_value(pool).unwrap();
    assert!(txids.contains(&f.parent.txid().to_hex()));
    assert!(!txids.contains(&child.txid().to_hex()));
}

/// Resubmitting a tx that is already in the mempool omits effective-feerate.
#[tokio::test]
async fn submitpackage_already_in_mempool_omits_effective_feerate() {
    let f = funded(10_000, 10_000).await;
    let first = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent)]]),
        )
        .await,
    );
    assert_eq!(first["package_msg"], "success");

    let second = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&f.child)]]),
        )
        .await,
    );
    assert_eq!(second["package_msg"], "success");
    let parent = entry(&second, &f.parent.wtxid().to_hex());
    assert!(parent.get("error").is_none(), "{parent}");
    assert!(parent.get("vsize").is_some(), "{parent}");
    assert!(parent["fees"].get("base").is_some(), "{parent}");
    assert!(
        parent["fees"].get("effective-feerate").is_none(),
        "MEMPOOL_ENTRY omits effective-feerate: {parent}"
    );
    assert!(
        parent["fees"].get("effective-includes").is_none(),
        "MEMPOOL_ENTRY omits effective-includes: {parent}"
    );
}

/// Valid CPFP: both results report one package feerate and both wtxids.
#[tokio::test]
async fn submitpackage_valid_cpfp_effective_feerate_is_package_rate() {
    let f = funded(1, 20_000).await;
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&f.child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "success");
    let parent = entry(&res, &f.parent.wtxid().to_hex());
    let child = entry(&res, &f.child.wtxid().to_hex());
    assert_eq!(
        parent["fees"]["effective-feerate"],
        child["fees"]["effective-feerate"]
    );
    let includes = serde_json::json!([f.parent.wtxid().to_hex(), f.child.wtxid().to_hex()]);
    assert_eq!(parent["fees"]["effective-includes"], includes);
    assert_eq!(child["fees"]["effective-includes"], includes);

    let pool = result(call(&f.state, "getrawmempool", serde_json::json!([false])).await);
    let txids: Vec<String> = serde_json::from_value(pool).unwrap();
    assert!(txids.contains(&f.parent.txid().to_hex()));
    assert!(txids.contains(&f.child.txid().to_hex()));
}

const SIGHASH_ALL: u32 = 1;
const IN_VALUE: u64 = 1_000_000;

struct Signer {
    sk: SecretKey,
    pk: [u8; 33],
    h160: [u8; 20],
}

fn signer(seed: u8) -> Signer {
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = serialize_pubkey_compressed(&public_key_from_private(&sk));
    let h160 = *hash160(&pk).as_bytes();
    Signer { sk, pk, h160 }
}

fn p2wpkh_spk(k: &Signer) -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&k.h160);
    v
}

/// 1-in/1-out P2WPKH. `corrupt` flips one byte of strict-DER `r` so CHECKSIG
/// fails NULLFAIL while the witness stays well-formed.
fn signed_spend(
    prev: OutPoint,
    in_value: u64,
    fee: u64,
    who: &Signer,
    dest: &Signer,
    corrupt: bool,
) -> Transaction {
    let mut tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: in_value - fee,
            script_pubkey: p2wpkh_spk(dest),
        }],
        lock_time: 0,
    };
    let script_code = p2wpkh_script_code(&who.h160);
    let sighash = segwit_v0_sighash(&tx, 0, &script_code, in_value, SIGHASH_ALL);
    let mut der = serialize_der_signature(&ecdsa_sign(&who.sk, &sighash));
    if corrupt {
        let rlen = der[3] as usize;
        der[4 + rlen - 1] ^= 0x01;
    }
    der.push(SIGHASH_ALL as u8);
    tx.inputs[0].witness = vec![der, who.pk.to_vec()];
    tx
}

struct Signed {
    state: Arc<RwLock<RpcState>>,
    parent: Transaction,
    child: Transaction,
}

async fn signed_pkg(
    parent_fee: u64,
    child_fee: u64,
    corrupt_parent: bool,
    corrupt_child: bool,
) -> Signed {
    let alice = signer(0x11);
    let bob = signer(0x22);
    let (state, _server) = server();
    let prev = OutPoint {
        txid: Hash256::from([0x42u8; 32]),
        vout: 0,
    };
    {
        let mut st = state.write().await;
        BlockStore::new(&st.db)
            .put_utxo(
                &prev,
                &rustoshi_storage::CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value: IN_VALUE,
                    script_pubkey: p2wpkh_spk(&alice),
                },
            )
            .unwrap();
        st.mempool.notify_new_tip(200, 1_700_000_000);
    }
    let parent = signed_spend(prev, IN_VALUE, parent_fee, &alice, &bob, corrupt_parent);
    let child = signed_spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        IN_VALUE - parent_fee,
        child_fee,
        &bob,
        &bob,
        corrupt_child,
    );
    Signed {
        state,
        parent,
        child,
    }
}

async fn submit_pair(
    state: &Arc<RwLock<RpcState>>,
    parent: &Transaction,
    child: &Transaction,
) -> serde_json::Value {
    result(
        call(
            state,
            "submitpackage",
            serde_json::json!([[hex_tx(parent), hex_tx(child)]]),
        )
        .await,
    )
}

/// Valid CPFP: top-level keys and each accepted entry match Core.
#[tokio::test]
async fn submitpackage_valid_cpfp_result_keys_match_core() {
    let f = funded(1, 20_000).await;
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&f.child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "success");
    assert_top(&res);
    let pw = f.parent.wtxid().to_hex();
    let cw = f.child.wtxid().to_hex();
    assert_tx_order(&res, &[&pw, &cw]);
    for w in [&pw, &cw] {
        let e = entry(&res, w);
        assert_keys(e, TX_ACCEPTED, "valid cpfp entry");
        assert_keys(&e["fees"], FEES_VALID, "valid cpfp fees");
        assert!(e["vsize"].is_number(), "{e}");
        assert!(e["fees"]["base"].is_number(), "{e}");
        assert!(e["fees"]["effective-feerate"].is_number(), "{e}");
        assert!(e["fees"]["effective-includes"].is_array(), "{e}");
    }
}

/// Already-in-mempool member: `fees` is `base` only. The new child is VALID.
#[tokio::test]
async fn submitpackage_already_in_mempool_result_keys_match_core() {
    let f = funded(10_000, 10_000).await;
    let _first = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent)]]),
        )
        .await,
    );
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&f.child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "success");
    assert_top(&res);
    let pw = f.parent.wtxid().to_hex();
    let cw = f.child.wtxid().to_hex();
    assert_tx_order(&res, &[&pw, &cw]);
    let parent = entry(&res, &pw);
    assert_keys(parent, TX_ACCEPTED, "mempool entry");
    assert_keys(&parent["fees"], FEES_MEMPOOL, "mempool fees");
    let child = entry(&res, &cw);
    assert_keys(child, TX_ACCEPTED, "new child");
    assert_keys(&child["fees"], FEES_VALID, "new child fees");
}

/// Invalid-signature child: parent stays VALID; child is `txid` + `error`.
#[tokio::test]
async fn submitpackage_invalid_sig_child_result_keys_match_core() {
    let s = signed_pkg(10_000, 10_000, false, true).await;
    let res = submit_pair(&s.state, &s.parent, &s.child).await;
    assert_eq!(res["package_msg"], "transaction failed");
    assert_top(&res);
    let pw = s.parent.wtxid().to_hex();
    let cw = s.child.wtxid().to_hex();
    assert_tx_order(&res, &[&pw, &cw]);
    let parent = entry(&res, &pw);
    assert_keys(parent, TX_ACCEPTED, "valid parent");
    assert_keys(&parent["fees"], FEES_VALID, "valid parent fees");
    let child = entry(&res, &cw);
    assert_keys(child, TX_REJECTED, "invalid-sig child");
    assert!(
        child["error"]
            .as_str()
            .unwrap_or("")
            .contains("Signature must be zero"),
        "{child}"
    );
}

/// Invalid-signature parent: both entries are `txid` + `error`.
#[tokio::test]
async fn submitpackage_invalid_sig_parent_result_keys_match_core() {
    let s = signed_pkg(10_000, 10_000, true, false).await;
    let res = submit_pair(&s.state, &s.parent, &s.child).await;
    assert_eq!(res["package_msg"], "transaction failed");
    assert_top(&res);
    let pw = s.parent.wtxid().to_hex();
    let cw = s.child.wtxid().to_hex();
    assert_tx_order(&res, &[&pw, &cw]);
    assert_keys(entry(&res, &pw), TX_REJECTED, "invalid-sig parent");
    assert_keys(entry(&res, &cw), TX_REJECTED, "child of invalid parent");
}

/// Below-min-fee parent plus a bad-sig child: both entries are `txid` + `error`.
#[tokio::test]
async fn submitpackage_cpfp_bad_sig_child_result_keys_match_core() {
    let s = signed_pkg(1, 20_000, false, true).await;
    let res = submit_pair(&s.state, &s.parent, &s.child).await;
    assert_eq!(res["package_msg"], "transaction failed");
    assert_top(&res);
    let pw = s.parent.wtxid().to_hex();
    let cw = s.child.wtxid().to_hex();
    assert_tx_order(&res, &[&pw, &cw]);
    assert_keys(entry(&res, &pw), TX_REJECTED, "cpfp parent");
    assert_keys(entry(&res, &cw), TX_REJECTED, "cpfp bad-sig child");
}

/// Non-standard child version: parent keeps vsize/fees; child is `txid` + `error`.
#[tokio::test]
async fn submitpackage_bad_version_child_result_keys_match_core() {
    let f = funded(10_000, 10_000).await;
    let mut child = f.child.clone();
    child.version = 0x7fff_ffff;
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed");
    assert_top(&res);
    let pw = f.parent.wtxid().to_hex();
    let cw = child.wtxid().to_hex();
    assert_tx_order(&res, &[&pw, &cw]);
    let parent = entry(&res, &pw);
    assert_keys(parent, TX_ACCEPTED, "individually valid parent");
    assert_keys(&parent["fees"], FEES_VALID, "parent fees");
    assert_keys(entry(&res, &cw), TX_REJECTED, "bad-version child");
}

/// Same txid, different witness already in the mempool: `txid` + `other-wtxid`.
#[tokio::test]
async fn submitpackage_other_wtxid_result_keys_match_core() {
    let f = funded(10_000, 10_000).await;
    let first = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent)]]),
        )
        .await,
    );
    assert_eq!(first["package_msg"], "success");
    let mem_wtxid = f.parent.wtxid().to_hex();

    let mut malleated = f.parent.clone();
    malleated.inputs[0].witness = vec![vec![0x00]];
    assert_eq!(malleated.txid(), f.parent.txid());
    let submitted = malleated.wtxid().to_hex();
    assert_ne!(submitted, mem_wtxid);

    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&malleated)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "success");
    assert_top(&res);
    assert_tx_order(&res, &[&submitted]);
    let e = entry(&res, &submitted);
    assert_keys(e, TX_OTHER_WTXID, "different witness");
    assert_eq!(e["txid"], f.parent.txid().to_hex());
    assert_eq!(e["other-wtxid"], mem_wtxid);
}

fn mempool_txids(pool: &serde_json::Value) -> Vec<String> {
    serde_json::from_value(pool.clone()).unwrap()
}

async fn mempool(state: &Arc<RwLock<RpcState>>) -> Vec<String> {
    let pool = result(call(state, "getrawmempool", serde_json::json!([false])).await);
    mempool_txids(&pool)
}

/// Core `CFeeRate(fee, vsize).GetFeePerK` is `EvaluateFeeDown(1000)`:
/// `(fee * 1000) / vsize` (truncation toward zero). `ValueFromAmount` is that
/// many satoshis printed as 8-decimal BTC.
fn trunc_sat_per_kvb(fee: u64, vsize: usize) -> u64 {
    fee.saturating_mul(1000) / vsize as u64
}

fn round_sat_per_kvb(fee: u64, vsize: usize) -> u64 {
    fee.saturating_mul(1000).saturating_add(vsize as u64 / 2) / vsize as u64
}

/// Solo effective-feerate matches Core truncation, which differs from rounding
/// whenever the remainder is at least half a sat/kvB.
#[tokio::test]
async fn submitpackage_solo_effective_feerate_truncates_like_core() {
    let probe = signed_pkg(10_000, 1_000, false, false).await;
    let vsize = probe.parent.vsize();
    let mut fee = 10_000u64;
    while trunc_sat_per_kvb(fee, vsize) == round_sat_per_kvb(fee, vsize) {
        fee += 1;
        assert!(fee < 20_000, "vsize {vsize} never separates trunc from round");
    }
    let s = signed_pkg(fee, 1_000, false, false).await;
    let res = result(
        call(
            &s.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&s.parent)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "success");
    let e = entry(&res, &s.parent.wtxid().to_hex());
    assert_keys(e, TX_ACCEPTED, "solo");
    let got = e["fees"]["effective-feerate"].as_f64().unwrap();
    let trunc = trunc_sat_per_kvb(fee, s.parent.vsize()) as f64 / 100_000_000.0;
    let round = round_sat_per_kvb(fee, s.parent.vsize()) as f64 / 100_000_000.0;
    assert!(
        (got - trunc).abs() < 1e-12,
        "effective-feerate {got} != Core GetFeePerK {trunc} (round would be {round})"
    );
    assert!(
        (got - round).abs() > 1e-12,
        "effective-feerate collapsed to the rounded value {round}"
    );
    let includes = e["fees"]["effective-includes"].as_array().unwrap();
    assert_eq!(includes.len(), 1);
    assert_eq!(includes[0], s.parent.wtxid().to_hex());
}

/// Core checks maxfeerate before submission. The tx is not admitted, the
/// entry is INVALID (`txid` + `error` = "max feerate exceeded"), and
/// `package_msg` is "transaction failed".
#[tokio::test]
async fn submitpackage_maxfeerate_rejected_before_admission() {
    let s = signed_pkg(10_000, 10_000, false, false).await;
    let res = result(
        call(
            &s.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&s.parent)], "0.00001000"]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed");
    assert_top(&res);
    assert_eq!(res["replaced-transactions"].as_array().unwrap().len(), 0);
    let e = entry(&res, &s.parent.wtxid().to_hex());
    assert_keys(e, TX_REJECTED, "maxfeerate");
    assert_eq!(e["error"], "max feerate exceeded");
    let ids = mempool(&s.state).await;
    assert!(
        !ids.contains(&s.parent.txid().to_hex()),
        "maxfeerate reject must not admit the tx, mempool={ids:?}"
    );
}

/// `tx-results[].error` is `TxValidationState::ToString()`:
/// `mempool min fee not met, {fee} < {GetMinFee().GetFee(vsize)}`.
#[tokio::test]
async fn submitpackage_mempool_min_fee_error_matches_core() {
    let fee = 10_000u64;
    let s = signed_pkg(fee, 1_000, false, false).await;
    let min_kvb = 5_000_000u64;
    {
        let mut st = s.state.write().await;
        st.mempool.set_rolling_min_fee_sat_kvb(min_kvb);
    }
    let vsize = s.parent.vsize();
    let required = (min_kvb * vsize as u64 + 999) / 1000;
    let expect = format!("mempool min fee not met, {fee} < {required}");
    let res = result(
        call(
            &s.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&s.parent)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed");
    assert_top(&res);
    let e = entry(&res, &s.parent.wtxid().to_hex());
    assert_keys(e, TX_REJECTED, "mempool min fee");
    assert_eq!(e["error"], expect, "vsize={vsize} result={e}");
    let ids = mempool(&s.state).await;
    assert!(
        !ids.contains(&s.parent.txid().to_hex()),
        "below mempool min fee must not be admitted, mempool={ids:?}"
    );
}

struct Replacement {
    state: Arc<RwLock<RpcState>>,
    original: Transaction,
    parent: Transaction,
    child: Transaction,
}

async fn replacement_pkg(orig_fee: u64, parent_fee: u64, child_fee: u64, corrupt_child: bool) -> Replacement {
    let alice = signer(0x11);
    let bob = signer(0x22);
    let carol = signer(0x33);
    let (state, _server) = server();
    let prev = OutPoint {
        txid: Hash256::from([0x77u8; 32]),
        vout: 0,
    };
    {
        let mut st = state.write().await;
        BlockStore::new(&st.db)
            .put_utxo(
                &prev,
                &rustoshi_storage::CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value: IN_VALUE,
                    script_pubkey: p2wpkh_spk(&alice),
                },
            )
            .unwrap();
        st.mempool.notify_new_tip(200, 1_700_000_000);
    }
    let original = signed_spend(prev.clone(), IN_VALUE, orig_fee, &alice, &bob, false);
    let parent = signed_spend(prev, IN_VALUE, parent_fee, &alice, &carol, false);
    let child = signed_spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        IN_VALUE - parent_fee,
        child_fee,
        &carol,
        &carol,
        corrupt_child,
    );
    Replacement {
        state,
        original,
        parent,
        child,
    }
}

/// Package RBF success lists the replaced txid.
#[tokio::test]
async fn submitpackage_rbf_success_lists_replaced_txids() {
    let r = replacement_pkg(10_000, 50_000, 5_000, false).await;
    let first = result(
        call(
            &r.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&r.original)]]),
        )
        .await,
    );
    assert_eq!(first["package_msg"], "success", "{first}");
    let res = result(
        call(
            &r.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&r.parent), hex_tx(&r.child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "success", "{res}");
    assert_top(&res);
    let replaced = res["replaced-transactions"].as_array().unwrap();
    assert_eq!(
        replaced,
        &vec![serde_json::Value::String(r.original.txid().to_hex())],
        "{res}"
    );
    let ids = mempool(&r.state).await;
    assert!(!ids.contains(&r.original.txid().to_hex()), "{ids:?}");
    assert!(ids.contains(&r.parent.txid().to_hex()), "{ids:?}");
    assert!(ids.contains(&r.child.txid().to_hex()), "{ids:?}");
}

/// A package that would evict and then fails must leave the original in
/// place, with `replaced-transactions` empty. The parent clears RBF on its
/// own fee but not the rolling mempool floor, so it is package-only; the
/// child then fails script checks.
#[tokio::test]
async fn submitpackage_failed_package_does_not_keep_evictions() {
    let r = replacement_pkg(10_000, 50_000, 20_000, true).await;
    let first = result(
        call(
            &r.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&r.original)]]),
        )
        .await,
    );
    assert_eq!(first["package_msg"], "success", "{first}");
    {
        let mut st = r.state.write().await;
        st.mempool.set_rolling_min_fee_sat_kvb(5_000_000);
    }
    let res = result(
        call(
            &r.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&r.parent), hex_tx(&r.child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed", "{res}");
    assert_top(&res);
    assert_eq!(
        res["replaced-transactions"].as_array().unwrap().len(),
        0,
        "{res}"
    );
    let ids = mempool(&r.state).await;
    assert!(
        ids.contains(&r.original.txid().to_hex()),
        "original must survive a failed package, mempool={ids:?} result={res}"
    );
    assert!(!ids.contains(&r.parent.txid().to_hex()), "{ids:?} {res}");
    assert!(!ids.contains(&r.child.txid().to_hex()), "{ids:?} {res}");
}

const TOPOLOGY_MSG: &str = "package topology disallowed. not child-with-parents or parents depend on each other.";
const TOO_MANY_MSG: &str = "Array must contain between 1 and 25 transactions.";

fn rpc_err(resp: &serde_json::Value) -> (i64, String) {
    let err = &resp["error"];
    assert!(
        !err.is_null(),
        "expected JSON-RPC error, got result {}",
        resp["result"]
    );
    (
        err["code"].as_i64().unwrap_or(0),
        err["message"].as_str().unwrap_or("").to_string(),
    )
}

fn lone_spend(prev: OutPoint) -> Transaction {
    spend(prev, 50_000, 1_000)
}

/// Parent weight plus a one-input child exceeds `MAX_PACKAGE_WEIGHT` (404_000).
fn overweight_tree() -> (Transaction, Transaction) {
    let prev = OutPoint {
        txid: Hash256::from([0x41u8; 32]),
        vout: 0,
    };
    let mut n = 12_000usize;
    loop {
        let parent = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: prev.clone(),
                script_sig: vec![],
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![
                TxOut {
                    value: 1_000,
                    script_pubkey: vec![],
                };
                n
            ],
            lock_time: 0,
        };
        let child = spend(
            OutPoint {
                txid: parent.txid(),
                vout: 0,
            },
            1_000,
            100,
        );
        if parent.weight() + child.weight()
            > rustoshi_consensus::mempool::MAX_PACKAGE_WEIGHT as usize
        {
            return (parent, child);
        }
        n += 500;
        assert!(n < 20_000, "could not build an overweight package");
    }
}

fn assert_package_not_validated(res: &serde_json::Value, msg: &str, txs: &[&Transaction]) {
    assert_eq!(res["package_msg"], msg, "{res}");
    assert_top(res);
    assert_eq!(res["replaced-transactions"].as_array().unwrap().len(), 0);
    // tx-results is an object keyed by wtxid. A repeated wtxid overwrites,
    // the same way Core's UniValue object does.
    let map = res["tx-results"].as_object().unwrap();
    let mut seen = std::collections::HashSet::new();
    for tx in txs {
        let wtxid = tx.wtxid().to_hex();
        let e = entry(res, &wtxid);
        assert_keys(e, TX_REJECTED, msg);
        assert_eq!(e["txid"], tx.txid().to_hex());
        assert_eq!(e["error"], "package-not-validated", "{e}");
        seen.insert(wtxid);
    }
    assert_eq!(map.len(), seen.len(), "{res}");
}

fn assert_tma_package_error(rows: &serde_json::Value, msg: &str, txs: &[&Transaction]) {
    let arr = rows.as_array().expect("testmempoolaccept array");
    assert_eq!(arr.len(), txs.len(), "{rows}");
    for (row, tx) in arr.iter().zip(txs) {
        assert_keys(row, &["txid", "wtxid", "package-error"], msg);
        assert_eq!(row["txid"], tx.txid().to_hex());
        assert_eq!(row["wtxid"], tx.wtxid().to_hex());
        assert_eq!(row["package-error"], msg, "{row}");
        assert!(row.get("allowed").is_none(), "no allowed with package-error: {row}");
    }
}

/// Not child-with-parents is an RPC error, not a `package-error:` result.
#[tokio::test]
async fn submitpackage_unrelated_topology_is_rpc_error() {
    let (state, _) = server();
    let a = lone_spend(OutPoint {
        txid: Hash256::from([0x11u8; 32]),
        vout: 0,
    });
    let b = lone_spend(OutPoint {
        txid: Hash256::from([0x22u8; 32]),
        vout: 0,
    });
    let resp = call(
        &state,
        "submitpackage",
        serde_json::json!([[hex_tx(&a), hex_tx(&b)]]),
    )
    .await;
    let (code, message) = rpc_err(&resp);
    assert_eq!(code, -25, "{resp}");
    assert_eq!(message, TOPOLOGY_MSG, "{resp}");
}

/// Two copies of one tx are not a child-with-parents tree. Core's submitpackage
/// rejects that in the RPC, before IsWellFormedPackage.
#[tokio::test]
async fn submitpackage_duplicate_txs_are_rpc_error() {
    let (state, _) = server();
    let a = lone_spend(OutPoint {
        txid: Hash256::from([0x33u8; 32]),
        vout: 0,
    });
    let resp = call(
        &state,
        "submitpackage",
        serde_json::json!([[hex_tx(&a), hex_tx(&a)]]),
    )
    .await;
    let (code, message) = rpc_err(&resp);
    assert_eq!(code, -25, "{resp}");
    assert_eq!(message, TOPOLOGY_MSG, "{resp}");
}

/// More than 25 txs is -8 on both RPCs, before any per-tx result.
#[tokio::test]
async fn submitpackage_too_many_txs_is_rpc_error() {
    let (state, _) = server();
    let a = lone_spend(OutPoint {
        txid: Hash256::from([0x44u8; 32]),
        vout: 0,
    });
    let hexes = vec![hex_tx(&a); 26];
    let resp = call(&state, "submitpackage", serde_json::json!([hexes])).await;
    let (code, message) = rpc_err(&resp);
    assert_eq!(code, -8, "{resp}");
    assert_eq!(message, TOO_MANY_MSG, "{resp}");
}

#[tokio::test]
async fn testmempoolaccept_too_many_txs_is_rpc_error() {
    let (state, _) = server();
    let a = lone_spend(OutPoint {
        txid: Hash256::from([0x55u8; 32]),
        vout: 0,
    });
    let hexes = vec![hex_tx(&a); 26];
    let resp = call(&state, "testmempoolaccept", serde_json::json!([hexes])).await;
    let (code, message) = rpc_err(&resp);
    assert_eq!(code, -8, "{resp}");
    assert_eq!(message, TOO_MANY_MSG, "{resp}");
}

/// A child-with-parents package over `MAX_PACKAGE_WEIGHT` is a result:
/// `package_msg` is the policy token and every tx is `package-not-validated`.
#[tokio::test]
async fn submitpackage_package_too_large_emits_package_not_validated() {
    let (state, _) = server();
    let (parent, child) = overweight_tree();
    let res = result(
        call(
            &state,
            "submitpackage",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_package_not_validated(&res, "package-too-large", &[&parent, &child]);
}

#[tokio::test]
async fn testmempoolaccept_package_too_large_has_package_error_only() {
    let (state, _) = server();
    let (parent, child) = overweight_tree();
    let res = result(
        call(
            &state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_tma_package_error(&res, "package-too-large", &[&parent, &child]);
}

/// Duplicate txids that still form a child-with-parents tree pass the RPC
/// topology gate and come back as `package-contains-duplicates`.
#[tokio::test]
async fn submitpackage_duplicate_parents_emit_package_not_validated() {
    let (state, _) = server();
    let parent = lone_spend(OutPoint {
        txid: Hash256::from([0x66u8; 32]),
        vout: 0,
    });
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        49_000,
        1_000,
    );
    let res = result(
        call(
            &state,
            "submitpackage",
            serde_json::json!([[hex_tx(&parent), hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_package_not_validated(
        &res,
        "package-contains-duplicates",
        &[&parent, &parent, &child],
    );
}

#[tokio::test]
async fn testmempoolaccept_duplicate_txs_have_package_error_only() {
    let (state, _) = server();
    let a = lone_spend(OutPoint {
        txid: Hash256::from([0x77u8; 32]),
        vout: 0,
    });
    let res = result(
        call(
            &state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&a), hex_tx(&a)]]),
        )
        .await,
    );
    assert_tma_package_error(&res, "package-contains-duplicates", &[&a, &a]);
}

/// Child listed before its parent: testmempoolaccept reports `package-not-sorted`.
/// submitpackage hits the topology RPC error because the last tx is not the child.
#[tokio::test]
async fn testmempoolaccept_unsorted_package_has_package_error_only() {
    let (state, _) = server();
    let parent = lone_spend(OutPoint {
        txid: Hash256::from([0x88u8; 32]),
        vout: 0,
    });
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        49_000,
        1_000,
    );
    let res = result(
        call(
            &state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&child), hex_tx(&parent)]]),
        )
        .await,
    );
    assert_tma_package_error(&res, "package-not-sorted", &[&child, &parent]);
}

#[tokio::test]
async fn submitpackage_unsorted_is_topology_rpc_error() {
    let (state, _) = server();
    let parent = lone_spend(OutPoint {
        txid: Hash256::from([0x99u8; 32]),
        vout: 0,
    });
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        49_000,
        1_000,
    );
    let resp = call(
        &state,
        "submitpackage",
        serde_json::json!([[hex_tx(&child), hex_tx(&parent)]]),
    )
    .await;
    let (code, message) = rpc_err(&resp);
    assert_eq!(code, -25, "{resp}");
    assert_eq!(message, TOPOLOGY_MSG, "{resp}");
}

/// Two parents spending one prevout, child spending both: still a tree, so
/// submitpackage returns `conflict-in-package` and `package-not-validated`.
#[tokio::test]
async fn submitpackage_conflict_emits_package_not_validated() {
    let (state, _) = server();
    let prev = OutPoint {
        txid: Hash256::from([0xaau8; 32]),
        vout: 0,
    };
    let p1 = lone_spend(prev.clone());
    let p2 = spend(prev, 50_000, 2_000);
    let child = Transaction {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: p1.txid(),
                    vout: 0,
                },
                script_sig: vec![0x01, 0x51],
                sequence: 0xffff_ffff,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint {
                    txid: p2.txid(),
                    vout: 0,
                },
                script_sig: vec![0x01, 0x51],
                sequence: 0xffff_ffff,
                witness: vec![],
            },
        ],
        outputs: vec![TxOut {
            value: 1_000,
            script_pubkey: p2sh_true(),
        }],
        lock_time: 0,
    };
    let res = result(
        call(
            &state,
            "submitpackage",
            serde_json::json!([[hex_tx(&p1), hex_tx(&p2), hex_tx(&child)]]),
        )
        .await,
    );
    assert_package_not_validated(&res, "conflict-in-package", &[&p1, &p2, &child]);
}

/// Core `IsWellFormedPackage` rejects `package-too-large` before
/// `package-contains-duplicates`. A repeated parent that is also overweight
/// is still a child-with-parents tree, so this is a result, not an RPC error.
#[tokio::test]
async fn submitpackage_overweight_duplicate_is_package_too_large() {
    let (state, _) = server();
    let (parent, child) = overweight_tree();
    let res = result(
        call(
            &state,
            "submitpackage",
            serde_json::json!([[hex_tx(&parent), hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_package_not_validated(
        &res,
        "package-too-large",
        &[&parent, &parent, &child],
    );
}

#[tokio::test]
async fn testmempoolaccept_overweight_duplicate_is_package_too_large() {
    let (state, _) = server();
    let (parent, child) = overweight_tree();
    let res = result(
        call(
            &state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&parent), hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_tma_package_error(
        &res,
        "package-too-large",
        &[&parent, &parent, &child],
    );
}

/// 60-byte tx: version 1, one zero prevout, empty scriptSig, one 1-sat
/// empty scriptPubKey. Base size is 60, under Core's 65-byte floor, but
/// `IsStandardTx` reports `scriptpubkey` before that floor (validation.cpp
/// PreChecks: IsStandardTx, then MIN_STANDARD_TX_NONWITNESS_SIZE).
fn tiny_empty_scriptpubkey() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    }
}

/// Standard NULL_DATA under 65 bytes. IsStandardTx accepts it, so the size
/// floor that follows is `tx-size-small`.
fn tiny_op_return() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    }
}

fn dust_parent(prev: OutPoint, value: u64, fee: u64) -> Transaction {
    let dust = 1u64;
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![0x01, 0x51],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![
            TxOut {
                value: value - dust - fee,
                script_pubkey: p2sh_true(),
            },
            TxOut {
                value: dust,
                script_pubkey: p2sh_true(),
            },
        ],
        lock_time: 0,
    }
}

fn spend_outputs(inputs: Vec<(OutPoint, u64)>, fee: u64) -> Transaction {
    let sum: u64 = inputs.iter().map(|(_, v)| *v).sum();
    Transaction {
        version: 2,
        inputs: inputs
            .into_iter()
            .map(|(prev, _)| TxIn {
                previous_output: prev,
                script_sig: vec![0x01, 0x51],
                sequence: 0xffff_ffff,
                witness: vec![],
            })
            .collect(),
        outputs: vec![TxOut {
            value: sum - fee,
            script_pubkey: p2sh_true(),
        }],
        lock_time: 0,
    }
}

/// `CFeeRate::GetFee` for a sat/kvB rate.
fn required_relay_fee(vsize: usize) -> u64 {
    (100u64 * vsize as u64 + 999) / 1000
}

fn missing_ephemeral_spends(tx: &Transaction) -> String {
    format!(
        "missing-ephemeral-spends, tx {} (wtxid={}) did not spend parent's ephemeral dust",
        tx.txid(),
        tx.wtxid()
    )
}

const DUST_FEE_MSG: &str = "dust, tx with dust output must be 0-fee";

/// KB-104: empty scriptPubKey is `scriptpubkey`, not `tx-size-small`.
#[tokio::test]
async fn submitpackage_60byte_empty_scriptpubkey_is_scriptpubkey() {
    let tx = tiny_empty_scriptpubkey();
    assert_eq!(tx.base_size(), 60, "fixture must be the 60-byte Core case");
    let (state, _) = server();
    let res = result(
        call(&state, "submitpackage", serde_json::json!([[hex_tx(&tx)]])).await,
    );
    assert_top(&res);
    assert_eq!(res["package_msg"], "transaction failed", "{res}");
    assert_eq!(res["replaced-transactions"].as_array().unwrap().len(), 0);
    let row = entry(&res, &tx.wtxid().to_hex());
    assert_keys(row, TX_REJECTED, "60-byte submitpackage");
    assert_eq!(row["txid"], tx.txid().to_hex());
    assert_eq!(row["error"], "scriptpubkey", "{row}");
    assert_ne!(res["package_msg"], "partial failure");
}

#[tokio::test]
async fn testmempoolaccept_60byte_empty_scriptpubkey_is_scriptpubkey() {
    let tx = tiny_empty_scriptpubkey();
    assert_eq!(tx.base_size(), 60);
    let (state, _) = server();
    let res = result(
        call(
            &state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&tx)]]),
        )
        .await,
    );
    let row = &res.as_array().unwrap()[0];
    assert_keys(
        row,
        &["txid", "wtxid", "allowed", "reject-reason", "reject-details"],
        "60-byte testmempoolaccept",
    );
    assert_eq!(row["allowed"], false);
    assert_eq!(row["reject-reason"], "scriptpubkey", "{row}");
    assert_eq!(row["reject-details"], "scriptpubkey", "{row}");
}

/// A standard tiny OP_RETURN still hits the size floor after IsStandardTx.
#[tokio::test]
async fn testmempoolaccept_tiny_op_return_is_tx_size_small() {
    let tx = tiny_op_return();
    assert!(tx.base_size() < 65, "got {}", tx.base_size());
    let (state, _) = server();
    let res = result(
        call(
            &state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&tx)]]),
        )
        .await,
    );
    let row = &res.as_array().unwrap()[0];
    assert_eq!(row["reject-reason"], "tx-size-small", "{row}");
    assert_eq!(row["reject-details"], "tx-size-small", "{row}");
    assert_eq!(row["allowed"], false);
}

/// KB-105: one dust output and a nonzero fee is PreCheckEphemeralTx.
/// submitpackage records the individual results: parent ToString `dust`,
/// child `bad-txns-inputs-missingorspent`, package_msg `transaction failed`.
#[tokio::test]
async fn submitpackage_ephemeral_nonzero_fee_is_dust_tostring() {
    let f = funded(10_000, 10_000).await;
    let parent = dust_parent(
        OutPoint {
            txid: Hash256::from([0x11u8; 32]),
            vout: 0,
        },
        1_000_000,
        5_000,
    );
    let change = 1_000_000 - 1 - 5_000;
    let child = spend_outputs(
        vec![
            (
                OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
                change,
            ),
            (
                OutPoint {
                    txid: parent.txid(),
                    vout: 1,
                },
                1,
            ),
        ],
        5_000,
    );
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_top(&res);
    assert_eq!(res["package_msg"], "transaction failed", "{res}");
    assert_ne!(res["package_msg"], "partial failure");
    assert_eq!(res["replaced-transactions"].as_array().unwrap().len(), 0);
    let parent_row = entry(&res, &parent.wtxid().to_hex());
    assert_keys(parent_row, TX_REJECTED, "dust parent");
    assert_eq!(parent_row["error"], DUST_FEE_MSG, "{parent_row}");
    let child_row = entry(&res, &child.wtxid().to_hex());
    assert_keys(child_row, TX_REJECTED, "dust child");
    assert_eq!(child_row["error"], "bad-txns-inputs-missingorspent", "{child_row}");
    let st = f.state.read().await;
    assert!(!st.mempool.contains(&parent.txid()));
    assert!(!st.mempool.contains(&child.txid()));
}

#[tokio::test]
async fn testmempoolaccept_ephemeral_nonzero_fee_dust_details() {
    let f = funded(10_000, 10_000).await;
    let parent = dust_parent(
        OutPoint {
            txid: Hash256::from([0x11u8; 32]),
            vout: 0,
        },
        1_000_000,
        5_000,
    );
    let change = 1_000_000 - 1 - 5_000;
    let child = spend_outputs(
        vec![
            (
                OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
                change,
            ),
            (
                OutPoint {
                    txid: parent.txid(),
                    vout: 1,
                },
                1,
            ),
        ],
        5_000,
    );
    let res = result(
        call(
            &f.state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    let rows = res.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_keys(
        &rows[0],
        &["txid", "wtxid", "allowed", "reject-reason", "reject-details"],
        "nonzero-fee dust parent",
    );
    assert_eq!(rows[0]["allowed"], false);
    assert_eq!(rows[0]["reject-reason"], "dust", "{rows:?}");
    assert_eq!(rows[0]["reject-details"], DUST_FEE_MSG, "{rows:?}");
    assert!(rows[0].get("package-error").is_none(), "{rows:?}");
    assert_keys(&rows[1], &["txid", "wtxid"], "unfinished child");
    assert_eq!(rows[1]["txid"], child.txid().to_hex());
    assert_eq!(rows[1]["wtxid"], child.wtxid().to_hex());
}

/// KB-105: 0-fee dust parent whose child spends only the non-dust output.
/// submitpackage package_msg is `unspent-dust`. The parent keeps its
/// individual min-relay ToString. The child is `missing-ephemeral-spends`.
#[tokio::test]
async fn submitpackage_unspent_dust_package_msg_is_unspent_dust() {
    let f = funded(10_000, 10_000).await;
    let parent = dust_parent(
        OutPoint {
            txid: Hash256::from([0x11u8; 32]),
            vout: 0,
        },
        1_000_000,
        0,
    );
    let change = 1_000_000 - 1;
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        change,
        5_000,
    );
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_top(&res);
    assert_eq!(res["package_msg"], "unspent-dust", "{res}");
    assert_ne!(res["package_msg"], "partial failure");
    assert_eq!(res["replaced-transactions"].as_array().unwrap().len(), 0);
    let required = required_relay_fee(parent.vsize());
    let parent_row = entry(&res, &parent.wtxid().to_hex());
    assert_keys(parent_row, TX_REJECTED, "0-fee dust parent");
    assert_eq!(
        parent_row["error"],
        format!("min relay fee not met, 0 < {required}"),
        "{parent_row}"
    );
    let child_row = entry(&res, &child.wtxid().to_hex());
    assert_keys(child_row, TX_REJECTED, "unspent child");
    assert_eq!(child_row["error"], missing_ephemeral_spends(&child), "{child_row}");
    let st = f.state.read().await;
    assert!(!st.mempool.contains(&parent.txid()));
    assert!(!st.mempool.contains(&child.txid()));
}

/// testmempoolaccept uses AcceptMultipleTransactions (package_feerates off),
/// so the 0-fee parent fails CheckFeeRate and the child stays unfinished.
/// `unspent-dust` is submitpackage only.
#[tokio::test]
async fn testmempoolaccept_unspent_dust_parent_is_min_relay() {
    let f = funded(10_000, 10_000).await;
    let parent = dust_parent(
        OutPoint {
            txid: Hash256::from([0x11u8; 32]),
            vout: 0,
        },
        1_000_000,
        0,
    );
    let change = 1_000_000 - 1;
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        change,
        5_000,
    );
    let res = result(
        call(
            &f.state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    let rows = res.as_array().unwrap();
    let required = required_relay_fee(parent.vsize());
    assert_keys(
        &rows[0],
        &["txid", "wtxid", "allowed", "reject-reason", "reject-details"],
        "0-fee dust parent",
    );
    assert_eq!(rows[0]["allowed"], false);
    assert_eq!(rows[0]["reject-reason"], "min relay fee not met", "{rows:?}");
    assert_eq!(
        rows[0]["reject-details"],
        format!("min relay fee not met, 0 < {required}"),
        "{rows:?}"
    );
    assert!(rows[0].get("package-error").is_none(), "{rows:?}");
    assert_keys(&rows[1], &["txid", "wtxid"], "unfinished child");
}

/// Fill a 63-tx cluster, then a 2-tx child-with-parent that would make it 65.
async fn cluster_of_63() -> (Arc<RwLock<RpcState>>, Transaction, Transaction) {
    let (state, _) = server();
    let prev0 = OutPoint {
        txid: Hash256::from([0x5cu8; 32]),
        vout: 0,
    };
    let mut value = 100_000_000u64;
    {
        let mut st = state.write().await;
        BlockStore::new(&st.db)
            .put_utxo(
                &prev0,
                &rustoshi_storage::CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value,
                    script_pubkey: p2sh_true(),
                },
            )
            .unwrap();
        st.mempool.notify_new_tip(200, 1_700_000_000);
    }
    let mut prev = prev0;
    for _ in 0..63 {
        let tx = spend(prev, value, 1_000);
        let res = result(
            call(&state, "submitpackage", serde_json::json!([[hex_tx(&tx)]])).await,
        );
        assert_eq!(res["package_msg"], "success", "{res}");
        prev = OutPoint {
            txid: tx.txid(),
            vout: 0,
        };
        value -= 1_000;
    }
    let parent = spend(prev, value, 1_000);
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        value - 1_000,
        1_000,
    );
    (state, parent, child)
}

/// KB-107: multi-tx testmempoolaccept cluster failure is PCKG_POLICY with an
/// empty tx-result map. Every row is package-error and has no `allowed`.
#[tokio::test]
async fn testmempoolaccept_too_large_cluster_has_package_error_and_no_allowed() {
    let (state, parent, child) = cluster_of_63().await;
    let res = result(
        call(
            &state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_tma_package_error(&res, "too-large-cluster", &[&parent, &child]);
}

/// submitpackage tries the parent alone (it fits at 64) and rejects the child.
#[tokio::test]
async fn submitpackage_too_large_cluster_child_is_transaction_failed() {
    let (state, parent, child) = cluster_of_63().await;
    let res = result(
        call(
            &state,
            "submitpackage",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_top(&res);
    assert_eq!(res["package_msg"], "transaction failed", "{res}");
    assert_ne!(res["package_msg"], "partial failure");
    let parent_row = entry(&res, &parent.wtxid().to_hex());
    assert!(parent_row.get("error").is_none(), "{parent_row}");
    assert!(parent_row.get("vsize").is_some(), "{parent_row}");
    let child_row = entry(&res, &child.wtxid().to_hex());
    assert_keys(child_row, TX_REJECTED, "cluster child");
    assert_eq!(child_row["error"], "too-large-cluster", "{child_row}");
    let st = state.read().await;
    assert!(st.mempool.contains(&parent.txid()));
    assert!(!st.mempool.contains(&child.txid()));
}

fn relay_fee(vsize: usize) -> u64 {
    100u64.saturating_mul(vsize as u64).saturating_add(999) / 1000
}

/// Aggregate CheckFeeRate: package_msg is `transaction failed`, and only the
/// last tx carries the package fee/vsize ToString.
#[tokio::test]
async fn submitpackage_low_package_fee_last_tx_is_checkfeerate() {
    let f = funded(1, 1).await;
    let parent_req = relay_fee(f.parent.vsize());
    let pkg_req = relay_fee(f.parent.vsize() + f.child.vsize());
    assert!(1 < parent_req && 2 < pkg_req);
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&f.child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed", "{res}");
    let parent_row = entry(&res, &f.parent.wtxid().to_hex());
    let child_row = entry(&res, &f.child.wtxid().to_hex());
    assert_eq!(
        parent_row["error"],
        format!("min relay fee not met, 1 < {parent_req}")
    );
    assert_eq!(
        child_row["error"],
        format!("min relay fee not met, 2 < {pkg_req}")
    );
}

/// Fee-sufficient v3 parent + version=2 child. submitpackage admits the
/// parent and the child's error is the SingleTRUCChecks ToString.
#[tokio::test]
async fn submitpackage_truc_child_error_includes_debug() {
    let f = funded(10_000, 10_000).await;
    let mut parent = f.parent.clone();
    parent.version = 3;
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        1_000_000 - 10_000,
        10_000,
    );
    let debug = format!(
        "non-version=3 tx {} (wtxid={}) cannot spend from version=3 tx {} (wtxid={})",
        child.txid(),
        child.wtxid(),
        parent.txid(),
        parent.wtxid()
    );
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed", "{res}");
    assert_eq!(
        entry(&res, &child.wtxid().to_hex())["error"],
        format!("TRUC-violation, {debug}")
    );
    let st = f.state.read().await;
    assert!(st.mempool.contains(&parent.txid()));
}

/// testmempoolaccept does not admit the parent, so PackageTRUCChecks is the
/// package-error on every entry and `allowed` is omitted.
#[tokio::test]
async fn testmempoolaccept_truc_package_error_includes_debug() {
    let f = funded(10_000, 10_000).await;
    let mut parent = f.parent.clone();
    parent.version = 3;
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        1_000_000 - 10_000,
        10_000,
    );
    let debug = format!(
        "non-version=3 tx {} (wtxid={}) cannot spend from version=3 tx {} (wtxid={})",
        child.txid(),
        child.wtxid(),
        parent.txid(),
        parent.wtxid()
    );
    let res = result(
        call(
            &f.state,
            "testmempoolaccept",
            serde_json::json!([[hex_tx(&parent), hex_tx(&child)]]),
        )
        .await,
    );
    let rows = res.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["package-error"], format!("TRUC-violation, {debug}"), "{row}");
        assert!(row.get("allowed").is_none(), "{row}");
    }
}

/// sendrawtransaction of a nonzero-fee dust tx is RPC -26 and Core's ToString,
/// not the bare `dust` token.
#[tokio::test]
async fn sendrawtransaction_dust_returns_tostring_and_code() {
    let f = funded(10_000, 10_000).await;
    let parent = dust_parent(
        OutPoint {
            txid: Hash256::from([0x11u8; 32]),
            vout: 0,
        },
        1_000_000,
        5_000,
    );
    let resp = call(
        &f.state,
        "sendrawtransaction",
        serde_json::json!([hex_tx(&parent)]),
    )
    .await;
    let (code, message) = rpc_err(&resp);
    assert_eq!(code, -26, "{resp}");
    assert_eq!(message, DUST_FEE_MSG, "{resp}");
}

/// `sendtoaddress` broadcasts through `broadcast_signed_tx`. A 1-sat output
/// is dust with a nonzero wallet fee, so the RPC must return the same -26
/// and PreCheckEphemeralTx string as `sendrawtransaction`.
#[tokio::test]
async fn sendtoaddress_dust_matches_sendraw_reject() {
    use crate::wallet::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
    use rustoshi_crypto::address::{Address, Network};
    use rustoshi_wallet::{CreateWalletOptions, WalletManager, WalletUtxo};

    let (state, _server) = server();
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager
        .create_wallet("dust", CreateWalletOptions::default())
        .unwrap();
    let utxo = {
        let arc = manager.get_wallet("dust").unwrap();
        let mut wallet = arc.lock().unwrap();
        wallet.set_chain_height(200);
        let addr = wallet.get_new_address().unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();
        let spk = Address::from_string(&addr, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey();
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::from([0xb2; 32]),
                vout: 0,
            },
            value: 100_000,
            script_pubkey: spk,
            derivation_path: path,
            confirmations: 10,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        };
        wallet.add_utxo(utxo.clone());
        utxo
    };
    {
        let mut st = state.write().await;
        BlockStore::new(&st.db)
            .put_utxo(
                &utxo.outpoint,
                &rustoshi_storage::CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value: utxo.value,
                    script_pubkey: utxo.script_pubkey.clone(),
                },
            )
            .unwrap();
        st.mempool.notify_new_tip(200, 1_700_000_000);
    }
    let mut wallet_state = WalletRpcState::new(manager, dir.keep());
    wallet_state.node = Some(state);
    let rpc = WalletRpcImpl::new(Arc::new(RwLock::new(wallet_state)));
    let err = rpc
        .send_to_address(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            0.00000001,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("dust sendtoaddress must be rejected");
    assert_eq!(err.code(), -26, "{err:?}");
    assert_eq!(err.message(), DUST_FEE_MSG, "{err:?}");
}
