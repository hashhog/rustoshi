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
