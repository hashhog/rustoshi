//! `listdescriptors` — RPC functional test (Core
//! `bitcoin-core/src/wallet/rpc/backup.cpp::listdescriptors`).
//!
//! Drives the descriptor store end-to-end with NO node and NO regtest:
//!
//!   1. Create a WATCH-ONLY wallet (`disable_private_keys=true`) — exactly
//!      what rustoshi's imported-descriptor store is.
//!   2. `importdescriptors` two PUBLIC (xpub / pubkey) descriptors: one RANGED
//!      (`wpkh(tpub.../0/*)`) and one NON-ranged (`pkh(<pubkey>)`), each with a
//!      DISTINCT numeric `timestamp`. These persist into the wallet DB
//!      (descriptor, label, timestamp, range_end) — the authoritative store
//!      `listdescriptors` reads.
//!   3. Call `listdescriptors` (default `private=false`) and assert the full
//!      Core response shape:
//!        - `{ wallet_name, descriptors: [...] }`.
//!        - each `desc` carries a CORRECT trailing `#checksum` — recomputed
//!          independently with `descriptor_checksum` and compared (proves the
//!          checksum is real, not fabricated).
//!        - `timestamp` round-trips the imported value.
//!        - `active=false` and `internal` OMITTED (watch-only imports are never
//!          active ScriptPubKeyMans; `internal` is "defined only for active
//!          descriptors").
//!        - the RANGED descriptor emits `range=[0,end]` + `next`/`next_index`;
//!          the NON-ranged descriptor omits all three.
//!        - the array is SORTED by descriptor string (backup.cpp:541-543).
//!   4. `listdescriptors true` -> `-4`
//!      "Can't get private descriptor string for watch-only wallets".

use std::sync::Arc;

use rustoshi_crypto::address::Network;
use rustoshi_rpc::{ImportDescriptorRequest, WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_wallet::{
    descriptor_checksum, encode_xpub, ExtendedPrivKey, WalletManager,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::sync::RwLock;

/// Build a watch-only WalletRpcState + a targeted RPC handle on a fresh
/// tempdir. The wallet is created with `disable_private_keys=true`, so
/// `private_keys_enabled` is false on the in-memory wallet — the precondition
/// for importing PUBLIC descriptors (and for the `private=true` -> -4 path).
fn watch_only_rpc(wallet_name: &str) -> WalletRpcImpl {
    let dir = tempdir().expect("unique tempdir");
    let manager = WalletManager::new(dir.path(), Network::Testnet).expect("manager");
    let state = Arc::new(RwLock::new(WalletRpcState::new(
        manager,
        dir.path().to_path_buf(),
    )));
    // Keep the tempdir alive for the whole process by leaking it; tests are
    // short-lived and this avoids the dir being removed out from under the DB.
    std::mem::forget(dir);

    WalletRpcImpl::with_target_wallet(state, wallet_name.to_string())
}

/// A real, parseable testnet xpub (BIP-32 test-vector master key, testnet
/// version bytes) for the ranged descriptor.
fn test_tpub() -> String {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::from_seed(&seed).unwrap();
    let xpub = master.to_public();
    encode_xpub(&xpub, Network::Testnet)
}

/// Append the canonical BIP-380 checksum to a descriptor body (independent of
/// the implementation under test).
fn with_checksum(body: &str) -> String {
    let cs = descriptor_checksum(body).expect("descriptor body must be checksummable");
    format!("{}#{}", body, cs)
}

#[tokio::test]
async fn listdescriptors_core_shape_checksum_sort_and_private_error() {
    let rpc = watch_only_rpc("listdesc-wo");
    rpc.create_wallet(
        "listdesc-wo".to_string(),
        /* disable_private_keys */ Some(true),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("create watch-only wallet");

    // --- Two PUBLIC descriptors, distinct timestamps. ---
    // Ranged: wpkh(tpub.../0/*) -> IsRange == true.
    let ranged_body = format!("wpkh({}/0/*)", test_tpub());
    let ranged_desc = with_checksum(&ranged_body);
    // Non-ranged: pkh(<compressed pubkey>) -> IsRange == false, solvable.
    let nonranged_body =
        "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)".to_string();
    let nonranged_desc = with_checksum(&nonranged_body);

    let ranged_ts: u64 = 1_700_000_000;
    let nonranged_ts: u64 = 1_600_000_000;
    let ranged_range_end: u32 = 49; // import range [0,49] -> inclusive end 49.

    let requests = vec![
        ImportDescriptorRequest {
            desc: ranged_desc.clone(),
            active: false,
            range: Some(json!([0, ranged_range_end])),
            timestamp: json!(ranged_ts),
            internal: false,
            label: None,
        },
        ImportDescriptorRequest {
            desc: nonranged_desc.clone(),
            active: false,
            range: None,
            timestamp: json!(nonranged_ts),
            internal: false,
            label: Some(String::new()),
        },
    ];

    let import_results = rpc
        .import_descriptors(requests)
        .await
        .expect("importdescriptors must not top-level error");
    assert_eq!(import_results.len(), 2, "one result per request");
    for (i, r) in import_results.iter().enumerate() {
        assert!(
            r.success,
            "import #{i} should succeed, got error: {:?}",
            r.error
        );
    }

    // --- listdescriptors (private=false). ---
    let resp = rpc
        .list_descriptors(None)
        .await
        .expect("listdescriptors must succeed");
    let obj = resp.as_object().expect("response is an object");

    assert_eq!(
        obj.get("wallet_name").and_then(|v| v.as_str()),
        Some("listdesc-wo"),
        "wallet_name field"
    );

    let descriptors = obj
        .get("descriptors")
        .and_then(|v| v.as_array())
        .expect("descriptors array");
    assert_eq!(descriptors.len(), 2, "exactly the two imported descriptors");

    // Sort order: array MUST be sorted ascending by the descriptor string.
    let descs: Vec<&str> = descriptors
        .iter()
        .map(|e| e.get("desc").and_then(|v| v.as_str()).expect("desc string"))
        .collect();
    let mut sorted = descs.clone();
    sorted.sort_unstable();
    assert_eq!(descs, sorted, "descriptors must be sorted by desc string");

    // Per-entry shape assertions, keyed by the descriptor BODY so we don't
    // depend on which sorts first.
    let mut saw_ranged = false;
    let mut saw_nonranged = false;
    for entry in descriptors {
        let e = entry.as_object().expect("entry is an object");

        // desc: carries a trailing #checksum, and that checksum is CORRECT
        // (recomputed independently from the body).
        let desc = e.get("desc").and_then(|v| v.as_str()).unwrap();
        let (body, checksum) = desc.rsplit_once('#').expect("desc has #checksum");
        assert_eq!(
            checksum.len(),
            8,
            "BIP-380 checksum is 8 chars: {desc}"
        );
        let expected = descriptor_checksum(body).expect("body checksummable");
        assert_eq!(
            checksum, expected,
            "emitted checksum must equal the recomputed BIP-380 checksum for {body}"
        );

        // active is always false (watch-only imports) and internal is omitted.
        assert_eq!(
            e.get("active").and_then(|v| v.as_bool()),
            Some(false),
            "active must be false for watch-only imports"
        );
        assert!(
            !e.contains_key("internal"),
            "internal is defined only for active descriptors -> must be omitted"
        );

        let ts = e
            .get("timestamp")
            .and_then(|v| v.as_u64())
            .expect("timestamp is an integer");

        if body == ranged_body {
            saw_ranged = true;
            assert_eq!(ts, ranged_ts, "ranged timestamp round-trips");
            // Ranged -> range/next/next_index present.
            let range = e
                .get("range")
                .and_then(|v| v.as_array())
                .expect("ranged descriptor has range");
            assert_eq!(range.len(), 2, "range is [begin,end]");
            assert_eq!(range[0].as_u64(), Some(0), "range begin is 0");
            assert_eq!(
                range[1].as_u64(),
                Some(ranged_range_end as u64),
                "range end is the inclusive last index"
            );
            assert_eq!(e.get("next").and_then(|v| v.as_u64()), Some(0), "next");
            assert_eq!(
                e.get("next_index").and_then(|v| v.as_u64()),
                Some(0),
                "next_index"
            );
        } else if body == nonranged_body {
            saw_nonranged = true;
            assert_eq!(ts, nonranged_ts, "non-ranged timestamp round-trips");
            // Non-ranged -> range/next/next_index all OMITTED.
            assert!(!e.contains_key("range"), "non-ranged: range omitted");
            assert!(!e.contains_key("next"), "non-ranged: next omitted");
            assert!(
                !e.contains_key("next_index"),
                "non-ranged: next_index omitted"
            );
        } else {
            panic!("unexpected descriptor body in response: {body}");
        }
    }
    assert!(saw_ranged, "ranged descriptor present in output");
    assert!(saw_nonranged, "non-ranged descriptor present in output");

    // --- listdescriptors true -> -4 for a watch-only wallet. ---
    let err = rpc
        .list_descriptors(Some(true))
        .await
        .expect_err("private=true on a watch-only wallet must error");
    assert_eq!(
        err.code(),
        -4,
        "private=true -> RPC_WALLET_ERROR (-4), got: {}",
        err.message()
    );
    assert!(
        err.message()
            .contains("Can't get private descriptor string for watch-only wallets"),
        "private=true error message must match Core, got: {}",
        err.message()
    );
}
