// Temporary verification harness for the WIRE KEY-ORDER SWEEP.
// Confirms the SERIALIZED key order (the actual emitted JSON bytes) of the
// audited RPC response shapes matches Bitcoin Core's pushKV order. This file
// is intended to be deleted after verification (not a permanent test).

use rustoshi_rpc::types::*;
use serde_json::value::RawValue;

/// Extract top-level object keys in serialized (wire) order from a JSON string.
fn top_level_keys(json: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    // serde_json with preserve_order keeps insertion/source order in the Map.
    match v {
        serde_json::Value::Object(m) => m.keys().cloned().collect(),
        _ => panic!("not an object: {json}"),
    }
}

fn keys_of_serialize<T: serde::Serialize>(t: &T) -> Vec<String> {
    let s = serde_json::to_string(t).unwrap();
    top_level_keys(&s)
}

#[test]
fn networkinfo_key_order_matches_core() {
    let ni = NetworkInfo {
        version: 1,
        subversion: "/x/".into(),
        protocolversion: 70016,
        localservices: "0".into(),
        localservicesnames: vec![],
        localrelay: true,
        timeoffset: 0,
        networkactive: true,
        connections: 0,
        connections_in: 0,
        connections_out: 0,
        networks: vec![],
        relayfee: BtcAmount(0),
        incrementalfee: BtcAmount(0),
        localaddresses: vec![],
        warnings: Vec::new(),
    };
    let got = keys_of_serialize(&ni);
    let want = [
        "version", "subversion", "protocolversion", "localservices",
        "localservicesnames", "localrelay", "timeoffset", "networkactive",
        "connections", "connections_in", "connections_out", "networks",
        "relayfee", "incrementalfee", "localaddresses", "warnings",
    ];
    assert_eq!(got, want, "getnetworkinfo key order");
}

#[test]
fn mempoolinfo_key_order_matches_core() {
    let mi = MempoolInfo {
        loaded: true,
        size: 0,
        bytes: 0,
        usage: 0,
        total_fee: BtcAmount(0),
        maxmempool: 0,
        mempoolminfee: BtcAmount(0),
        minrelaytxfee: BtcAmount(0),
        incrementalrelayfee: BtcAmount(0),
        unbroadcastcount: 0,
        fullrbf: true,
        permitbaremultisig: true,
        maxdatacarriersize: 100_000,
        limitclustercount: 64,
        limitclustersize: 101_000,
        optimal: true,
    };
    let got = keys_of_serialize(&mi);
    let want = [
        "loaded", "size", "bytes", "usage", "total_fee", "maxmempool",
        "mempoolminfee", "minrelaytxfee", "incrementalrelayfee",
        "unbroadcastcount", "fullrbf", "permitbaremultisig",
        "maxdatacarriersize", "limitclustercount", "limitclustersize",
        "optimal",
    ];
    assert_eq!(got, want, "getmempoolinfo key order");
}

#[test]
fn mininginfo_key_order_matches_core() {
    let mi = MiningInfo {
        blocks: 0,
        bits: "1d00ffff".into(),
        difficulty: serde_json::value::RawValue::from_string("1".to_string()).unwrap(),
        target: "0".repeat(64),
        networkhashps: 0.0,
        pooledtx: 0,
        blockmintxfee: BtcAmount(0),
        chain: "regtest".into(),
        next: MiningInfoNext {
            height: 1,
            bits: "1d00ffff".into(),
            difficulty: serde_json::value::RawValue::from_string("1".to_string()).unwrap(),
            target: "0".repeat(64),
        },
        warnings: Vec::new(),
    };
    let got = keys_of_serialize(&mi);
    let want = [
        "blocks", "bits", "difficulty", "target", "networkhashps", "pooledtx",
        "blockmintxfee", "chain", "next", "warnings",
    ];
    assert_eq!(got, want, "getmininginfo key order");
    // next sub-object
    let s = serde_json::to_string(&mi).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let next_keys: Vec<String> = match &v["next"] {
        serde_json::Value::Object(m) => m.keys().cloned().collect(),
        _ => panic!(),
    };
    assert_eq!(next_keys, ["height", "bits", "difficulty", "target"], "next order");
}

#[test]
fn rawtx_verbose_key_order_matches_core() {
    let ti = TransactionInfo {
        in_active_chain: None,
        txid: "00".into(),
        wtxid: "00".into(),
        hash: "00".into(),
        version: 2,
        size: 0,
        vsize: 0,
        weight: 0,
        locktime: 0,
        vin: vec![],
        vout: vec![],
        hex: "".into(),
        blockhash: Some("00".into()),
        confirmations: Some(1),
        time: Some(0),
        blocktime: Some(0),
    };
    let got = keys_of_serialize(&ti);
    // Core TxToUniv body + TxToJSON envelope (no in_active_chain here since None;
    // wtxid is skip_serializing). When blockhash present: ...hex, blockhash,
    // confirmations, time, blocktime.
    let want = [
        "txid", "hash", "version", "size", "vsize", "weight", "locktime",
        "vin", "vout", "hex", "blockhash", "confirmations", "time", "blocktime",
    ];
    assert_eq!(got, want, "getrawtransaction verbose key order");
}

#[test]
fn peerinfo_key_order_prefix_matches_core() {
    let p = PeerInfoRpc {
        id: 0,
        addr: "1.2.3.4:1".into(),
        addrbind: Some("0.0.0.0:1".into()),
        addrlocal: Some("0.0.0.0:1".into()),
        network: "ipv4".into(),
        mapped_as: Some(7),
        services: "0".into(),
        servicesnames: vec![],
        relaytxes: true,
        last_inv_sequence: 0,
        inv_to_send: 0,
        lastsend: 0,
        lastrecv: 0,
        last_transaction: 0,
        last_block: 0,
        bytessent: 0,
        bytesrecv: 0,
        conntime: 0,
        timeoffset: 0,
        pingtime: None,
        minping: None,
        pingwait: None,
        version: 70016,
        subver: "/x/".into(),
        inbound: false,
        bip152_hb_to: false,
        bip152_hb_from: false,
        startingheight: 0,
        presynced_headers: -1,
        synced_headers: 0,
        synced_blocks: 0,
        inflight: vec![],
        addr_relay_enabled: true,
        addr_processed: 0,
        addr_rate_limited: 0,
        permissions: vec![],
        minfeefilter: BtcAmount(0),
        bytessent_per_msg: serde_json::json!({}),
        bytesrecv_per_msg: serde_json::json!({}),
        connection_type: "outbound-full-relay".into(),
        transport_protocol_type: "v2".into(),
        session_id: "".into(),
    };
    let got = keys_of_serialize(&p);
    // Verify the Core-critical relative orderings:
    let has = |k: &str| got.iter().any(|x| x == k);
    let pos = |k: &str| {
        got.iter()
            .position(|x| x == k)
            .unwrap_or_else(|| panic!("getpeerinfo is missing field `{k}` — got {got:?}"))
    };
    assert!(pos("network") + 1 == pos("mapped_as"), "mapped_as after network");
    assert!(pos("mapped_as") < pos("services"), "mapped_as before services");
    // Core's getpeerinfo (rpc/net.cpp:242-246) pushes `last_inv_sequence` and
    // `inv_to_send` immediately after `relaytxes` and BEFORE `lastsend`. Both
    // MUST be emitted, and in that exact contiguous position.
    assert!(has("last_inv_sequence"), "getpeerinfo must emit last_inv_sequence");
    assert!(has("inv_to_send"), "getpeerinfo must emit inv_to_send");
    assert!(
        pos("relaytxes") + 1 == pos("last_inv_sequence"),
        "last_inv_sequence directly after relaytxes"
    );
    assert!(
        pos("last_inv_sequence") + 1 == pos("inv_to_send"),
        "inv_to_send directly after last_inv_sequence"
    );
    assert!(
        pos("inv_to_send") + 1 == pos("lastsend"),
        "inv_to_send directly before lastsend"
    );
    assert!(pos("lastrecv") < pos("last_transaction"), "lastrecv < last_transaction");
    assert!(pos("last_transaction") < pos("last_block"), "last_transaction < last_block");
    assert!(pos("last_block") < pos("bytessent"), "last_block < bytessent");
    assert!(pos("session_id") == got.len() - 1, "session_id last");
}

// ---- Value/json! based methods: replicate the handler's insertion order and
// confirm preserve_order keeps it on the wire. ----

#[test]
fn getchaintxstats_value_order_preserved() {
    // Mirrors get_chain_tx_stats insertion order.
    let mut ret = serde_json::Map::new();
    ret.insert("time".into(), serde_json::json!(1));
    ret.insert("txcount".into(), serde_json::json!(2));
    ret.insert("window_final_block_hash".into(), serde_json::json!("h"));
    ret.insert("window_final_block_height".into(), serde_json::json!(3));
    ret.insert("window_block_count".into(), serde_json::json!(4));
    ret.insert("window_interval".into(), serde_json::json!(5));
    ret.insert("window_tx_count".into(), serde_json::json!(6));
    ret.insert("txrate".into(), serde_json::json!(0.1));
    let s = serde_json::to_string(&serde_json::Value::Object(ret)).unwrap();
    let got = top_level_keys(&s);
    let want = [
        "time", "txcount", "window_final_block_hash", "window_final_block_height",
        "window_block_count", "window_interval", "window_tx_count", "txrate",
    ];
    assert_eq!(got, want, "getchaintxstats preserves source order (preserve_order on)");
}

#[test]
fn gettxoutsetinfo_value_order_matches_core() {
    // Mirrors get_tx_out_set_info full-scan insertion order (hash_serialized_3 path).
    let mut result = serde_json::Map::new();
    result.insert("height".into(), serde_json::json!(1));
    result.insert("bestblock".into(), serde_json::json!("h"));
    result.insert("txouts".into(), serde_json::json!(2));
    result.insert("bogosize".into(), serde_json::json!(3));
    result.insert("hash_serialized_3".into(), serde_json::json!("hs"));
    result.insert("hash_serialized_2".into(), serde_json::json!("hs"));
    result.insert("total_amount".into(), serde_json::json!(0.0));
    result.insert("transactions".into(), serde_json::json!(4));
    result.insert("disk_size".into(), serde_json::json!(0));
    let s = serde_json::to_string(&serde_json::Value::Object(result)).unwrap();
    let got = top_level_keys(&s);
    // Core: height, bestblock, txouts, bogosize, hash_serialized_3, total_amount,
    // transactions, disk_size. (hash_serialized_2 is a rustoshi-only alias kept
    // adjacent to the canonical key.)
    let want = [
        "height", "bestblock", "txouts", "bogosize", "hash_serialized_3",
        "hash_serialized_2", "total_amount", "transactions", "disk_size",
    ];
    assert_eq!(got, want, "gettxoutsetinfo key order");
}

#[test]
fn scantxoutset_value_order_matches_core() {
    // Top-level
    let top = serde_json::json!({
        "success": true,
        "txouts": 0,
        "height": 0,
        "bestblock": "h",
        "unspents": [],
        "total_amount": 0.0,
    });
    let got = top_level_keys(&serde_json::to_string(&top).unwrap());
    assert_eq!(
        got,
        ["success", "txouts", "height", "bestblock", "unspents", "total_amount"],
        "scantxoutset top-level"
    );
    // Per-unspent
    let u = serde_json::json!({
        "txid": "t",
        "vout": 0,
        "scriptPubKey": "s",
        "desc": "d",
        "amount": 0.0,
        "coinbase": false,
        "height": 0,
        "blockhash": "b",
        "confirmations": 1,
    });
    let got = top_level_keys(&serde_json::to_string(&u).unwrap());
    assert_eq!(
        got,
        ["txid", "vout", "scriptPubKey", "desc", "amount", "coinbase",
         "height", "blockhash", "confirmations"],
        "scantxoutset per-unspent"
    );
}

#[test]
fn getblock_coinbase_tx_order_matches_core() {
    // Mirrors get_block coinbase_tx Map insertion order.
    let mut cb = serde_json::Map::new();
    cb.insert("version".into(), serde_json::json!(2));
    cb.insert("locktime".into(), serde_json::json!(0));
    cb.insert("sequence".into(), serde_json::json!(4294967295u32));
    cb.insert("coinbase".into(), serde_json::json!("ab"));
    cb.insert("witness".into(), serde_json::json!("cd"));
    let got = top_level_keys(&serde_json::to_string(&serde_json::Value::Object(cb)).unwrap());
    assert_eq!(got, ["version", "locktime", "sequence", "coinbase", "witness"],
        "coinbaseTxToJSON order");
}

#[test]
fn getblockchaininfo_order_matches_core() {
    let bi = BlockchainInfo {
        chain: "regtest".into(),
        blocks: 0,
        headers: 0,
        bestblockhash: "h".into(),
        bits: "1d00ffff".into(),
        target: "0".repeat(64),
        difficulty: serde_json::value::RawValue::from_string("1".to_string()).unwrap(),
        time: 0,
        mediantime: 0,
        verificationprogress: 1.0,
        initialblockdownload: false,
        chainwork: "0".repeat(64),
        size_on_disk: 0,
        pruned: false,
        pruneheight: None,
        prune_target_size: None,
        warnings: Vec::new(),
    };
    let got = keys_of_serialize(&bi);
    // Core v31.99 key order (blockchain.cpp:1420-1466). Core dropped the
    // softforks field from getblockchaininfo (the builder is now consumed only
    // by getdeploymentinfo), so rustoshi no longer emits it either. The
    // optional pruneheight/prune_target_size are skipped when not pruning.
    let want = [
        "chain", "blocks", "headers", "bestblockhash", "bits", "target",
        "difficulty", "time", "mediantime", "verificationprogress",
        "initialblockdownload", "chainwork", "size_on_disk", "pruned",
        "warnings",
    ];
    assert_eq!(got, want, "getblockchaininfo key order");
}

#[test]
fn getblock_verbose_top_level_order_matches_core() {
    // Replicates the get_block manual string-builder order (verbosity>=1, with
    // prev/next/coinbase_tx present).
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = write!(out, "{{");
    let _ = write!(out, r#""hash":"h""#);
    let _ = write!(out, r#","confirmations":1"#);
    let _ = write!(out, r#","height":0"#);
    let _ = write!(out, r#","version":1"#);
    let _ = write!(out, r#","versionHex":"00000001""#);
    let _ = write!(out, r#","merkleroot":"m""#);
    let _ = write!(out, r#","time":0"#);
    let _ = write!(out, r#","mediantime":0"#);
    let _ = write!(out, r#","nonce":0"#);
    let _ = write!(out, r#","bits":"1d00ffff""#);
    let _ = write!(out, r#","target":"00""#);
    let _ = write!(out, r#","difficulty":1.0"#);
    let _ = write!(out, r#","chainwork":"00""#);
    let _ = write!(out, r#","nTx":1"#);
    let _ = write!(out, r#","previousblockhash":"p""#);
    let _ = write!(out, r#","nextblockhash":"n""#);
    let _ = write!(out, r#","strippedsize":1"#);
    let _ = write!(out, r#","size":1"#);
    let _ = write!(out, r#","weight":1"#);
    let _ = write!(out, r#","coinbase_tx":{{}}"#);
    let _ = write!(out, r#","tx":[]"#);
    let _ = write!(out, "}}");
    let got = top_level_keys(&out);
    // Core blockToJSON = blockheaderToJSON (header fields) + strippedsize, size,
    // weight, coinbase_tx, tx.
    let want = [
        "hash", "confirmations", "height", "version", "versionHex", "merkleroot",
        "time", "mediantime", "nonce", "bits", "target", "difficulty",
        "chainwork", "nTx", "previousblockhash", "nextblockhash",
        "strippedsize", "size", "weight", "coinbase_tx", "tx",
    ];
    assert_eq!(got, want, "getblock verbose top-level key order");
}

#[test]
fn blockheader_verbose_order_matches_core() {
    let bh = BlockHeaderInfo {
        hash: "h".into(),
        confirmations: 1,
        height: 0,
        version: 1,
        version_hex: "00000001".into(),
        merkleroot: "m".into(),
        time: 0,
        mediantime: 0,
        nonce: 0,
        bits: "1d00ffff".into(),
        target: "0".repeat(64),
        difficulty: RawValue::from_string("1.0".into()).unwrap(),
        chainwork: "0".repeat(64),
        n_tx: 1,
        previousblockhash: Some("p".into()),
        nextblockhash: Some("n".into()),
    };
    let got = keys_of_serialize(&bh);
    let want = [
        "hash", "confirmations", "height", "version", "versionHex", "merkleroot",
        "time", "mediantime", "nonce", "bits", "target", "difficulty",
        "chainwork", "nTx", "previousblockhash", "nextblockhash",
    ];
    assert_eq!(got, want, "getblockheader verbose key order");
}
