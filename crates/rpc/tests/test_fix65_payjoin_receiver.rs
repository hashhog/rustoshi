//! BIP-78 PayJoin receiver — end-to-end HTTP tests (W119 / FIX-65).
//!
//! Each test brings the REST listener up on an ephemeral port with a
//! pre-funded WalletManager wired into [`RestState::wallet_state`], drives
//! a real TCP+HTTP/1.1 request through it, and asserts the response.
//!
//! Covers the five FIX-65 acceptance cases laid out in the brief:
//!  1. Happy path: PSBT augmented with receiver input + signed witness.
//!  2. `version-unsupported` (HTTP 415) for `v=2`.
//!  3. `original-psbt-rejected` (HTTP 400) for garbage body.
//!  4. `not-enough-money` (HTTP 422) for an empty wallet.
//!  5. `unavailable` (HTTP 503) for a locked wallet.

use std::sync::Arc;
use std::time::Duration;

use rustoshi_consensus::ChainParams;
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::{start_rest_server_with_wallet, RestConfig, RpcState, WalletRpcState};
use rustoshi_storage::ChainDb;
use rustoshi_wallet::{CreateWalletOptions, Psbt, WalletManager, WalletUtxo};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

/// Build a 1-in/1-out Original PSBT paying `receiver_address` `recv_value`
/// satoshis. The sender input carries a witness_utxo so the receiver-side
/// validation step accepts it.
fn make_original_psbt(receiver_address: &str, network: Network, recv_value: u64) -> Psbt {
    let recv_spk = Address::from_string(receiver_address, Some(network))
        .expect("parse receiver address")
        .to_script_pubkey();

    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0xa1; 32]),
                vout: 7,
            },
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: recv_value,
            script_pubkey: recv_spk,
        }],
        lock_time: 0,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt build");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: recv_value + 10_000,
        script_pubkey: {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&[0x33; 20]);
            s
        },
    });
    psbt
}

/// Build a WalletRpcState + populate it with a single wallet whose
/// receive address is funded with one P2WPKH UTXO of `utxo_value`
/// satoshis. Returns `(state, receiver_address, wallet_name)`.
///
/// `passphrase` is `Some(_)` for the encrypted-wallet path (the
/// `unavailable` test re-locks afterwards). The encrypted-wallet
/// session is left unlocked by default per `WalletManager::create_wallet`'s
/// contract.
fn setup_funded_wallet(
    utxo_value: u64,
    passphrase: Option<&str>,
) -> (Arc<RwLock<WalletRpcState>>, String, String) {
    let dir = tempdir().expect("tempdir");
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).expect("manager");
    let wallet_name = "fix65-test".to_string();
    manager
        .create_wallet(
            &wallet_name,
            CreateWalletOptions {
                passphrase: passphrase.map(|s| s.to_string()),
                ..Default::default()
            },
        )
        .expect("create wallet");

    // Generate one address and fund it.
    let recv_addr = {
        let arc = manager.get_wallet(&wallet_name).expect("loaded");
        let mut w = arc.lock().expect("wallet lock");
        w.set_chain_height(200);
        let addr = w.get_new_address().expect("new addr");
        let path = w.get_derivation_path(&addr).expect("path").clone();
        let spk = Address::from_string(&addr, Some(Network::Regtest))
            .expect("parse addr")
            .to_script_pubkey();
        w.add_utxo(WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::from_bytes([0xb1; 32]),
                vout: 0,
            },
            value: utxo_value,
            script_pubkey: spk,
            derivation_path: path,
            confirmations: 10,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        });
        addr
    };

    // Move WalletRpcState ownership of the tempdir by leaking it — the
    // process exits at test end so resource reclamation is irrelevant
    // and we avoid making the test fixture struct visible.
    let temp_path = dir.keep();
    let state = Arc::new(RwLock::new(WalletRpcState::new(manager, temp_path)));
    (state, recv_addr, wallet_name)
}

/// Build a regtest RpcState. The REST listener needs it for unrelated
/// routes; the PayJoin handler itself only consumes `wallet_state`.
fn dummy_rpc_state() -> Arc<RwLock<RpcState>> {
    let tmp = tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
    // Leak the tempdir so the RocksDB store outlives the function (the
    // listener task holds the Arc).
    std::mem::forget(tmp);
    let params = ChainParams::regtest();
    Arc::new(RwLock::new(RpcState::new(db, params)))
}

/// Spin up the REST listener on an ephemeral port and drive a single
/// HTTP/1.1 POST request to `/payjoin?<query>` with `body` as the
/// payload. Returns `(status_line, body_bytes)`.
async fn send_payjoin_request(
    wallet_state: Option<Arc<RwLock<WalletRpcState>>>,
    query: &str,
    body: &[u8],
) -> (String, Vec<u8>) {
    let rpc_state = dummy_rpc_state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let bound = listener.local_addr().expect("local_addr");
    drop(listener); // free port for start_rest_server_with_wallet's own bind

    let cfg = RestConfig {
        bind_address: bound.to_string(),
    };
    let _handle = start_rest_server_with_wallet(cfg, rpc_state, wallet_state)
        .await
        .expect("rest server");
    // Tiny grace period for the listener task to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = TcpStream::connect(bound).await.expect("connect");
    let path = if query.is_empty() {
        "/payjoin".to_string()
    } else {
        format!("/payjoin?{query}")
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        path = path,
        len = body.len(),
    );
    sock.write_all(request.as_bytes()).await.expect("write head");
    sock.write_all(body).await.expect("write body");
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await.expect("read");

    // Split status line + headers + body.
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response had no header terminator");
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let body_bytes = buf[head_end + 4..].to_vec();
    let status_line = head.lines().next().unwrap_or("").to_string();
    (status_line, body_bytes)
}

// ---------------------------------------------------------------------
// 1. Happy path — full receiver round-trip.
// ---------------------------------------------------------------------
#[tokio::test]
async fn payjoin_round_trip_returns_modified_psbt() {
    let (wallet_state, recv_addr, _name) = setup_funded_wallet(500_000, None);

    let psbt = make_original_psbt(&recv_addr, Network::Regtest, 50_000);
    let body = psbt.to_base64();
    let (status, response_body) = send_payjoin_request(
        Some(wallet_state),
        "v=1&maxadditionalfeecontribution=1000",
        body.as_bytes(),
    )
    .await;

    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected 200 OK, got: {status}\nbody: {}",
        String::from_utf8_lossy(&response_body)
    );

    let returned_b64 = String::from_utf8(response_body).expect("body utf-8");
    // The chunked-or-not body may include a leading hex-size when transfer-
    // encoding is chunked. Strip any non-base64 prefix/suffix by walking
    // the leading and trailing base64-character runs.
    let trimmed = trim_to_base64(&returned_b64);
    let parsed = Psbt::from_base64(&trimmed).expect("parse returned PSBT");

    // Modified PSBT must have one MORE input than the original (the
    // receiver's contributed UTXO).
    assert_eq!(parsed.unsigned_tx.inputs.len(), 2);
    assert_eq!(parsed.inputs.len(), 2);

    // Receiver output's value increased.
    let recv_spk = Address::from_string(&recv_addr, Some(Network::Regtest))
        .unwrap()
        .to_script_pubkey();
    let recv_output = parsed
        .unsigned_tx
        .outputs
        .iter()
        .find(|o| o.script_pubkey == recv_spk)
        .expect("recv output preserved");
    assert!(
        recv_output.value > 50_000,
        "receiver output value must increase; got {}",
        recv_output.value
    );

    // The receiver-added input (last) must be signed — final_script_witness
    // is the BIP-78 receiver-foundation contract.
    assert!(
        parsed.inputs[1].final_script_witness.is_some(),
        "receiver-added input must be signed"
    );
}

// ---------------------------------------------------------------------
// 2. version-unsupported — `v=2` returns 415 + JSON.
// ---------------------------------------------------------------------
#[tokio::test]
async fn payjoin_version_two_returns_415_json() {
    // Funded wallet so the only thing that can reject is the version.
    let (wallet_state, _addr, _name) = setup_funded_wallet(500_000, None);
    let (status, body) = send_payjoin_request(
        Some(wallet_state),
        "v=2",
        b"anything", // body is irrelevant; version is checked first
    )
    .await;
    assert!(
        status.starts_with("HTTP/1.1 415"),
        "expected 415, got: {status}\nbody: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value =
        serde_json::from_slice(extract_json_body(&body).as_bytes()).expect("json parse");
    assert_eq!(json["errorCode"].as_str(), Some("version-unsupported"));
    assert!(json["message"].is_string());
}

// ---------------------------------------------------------------------
// 3. original-psbt-rejected — garbage body returns 400 + JSON.
// ---------------------------------------------------------------------
#[tokio::test]
async fn payjoin_garbage_body_returns_400_json() {
    let (wallet_state, _addr, _name) = setup_funded_wallet(500_000, None);
    let (status, body) = send_payjoin_request(
        Some(wallet_state),
        "v=1",
        b"definitely not a psbt at all",
    )
    .await;
    assert!(
        status.starts_with("HTTP/1.1 400"),
        "expected 400, got: {status}\nbody: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value =
        serde_json::from_slice(extract_json_body(&body).as_bytes()).expect("json parse");
    assert_eq!(json["errorCode"].as_str(), Some("original-psbt-rejected"));
}

// ---------------------------------------------------------------------
// 4. not-enough-money — empty wallet returns 422 + JSON.
// ---------------------------------------------------------------------
#[tokio::test]
async fn payjoin_empty_wallet_returns_422_json() {
    // Set up a wallet with NO funding; one address is generated so that
    // the Original PSBT's output still pays a wallet-owned address (we
    // want to fail on coin-selection, not on "not paying me").
    let dir = tempdir().expect("tempdir");
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).expect("manager");
    manager
        .create_wallet("empty", CreateWalletOptions::default())
        .expect("create");
    let recv_addr = {
        let arc = manager.get_wallet("empty").unwrap();
        let mut w = arc.lock().unwrap();
        w.set_chain_height(200);
        w.get_new_address().expect("addr")
    };
    let temp_path = dir.keep();
    let wallet_state = Arc::new(RwLock::new(WalletRpcState::new(manager, temp_path)));

    let psbt = make_original_psbt(&recv_addr, Network::Regtest, 50_000);
    let body = psbt.to_base64();

    let (status, response_body) = send_payjoin_request(
        Some(wallet_state),
        "v=1",
        body.as_bytes(),
    )
    .await;
    assert!(
        status.starts_with("HTTP/1.1 422"),
        "expected 422, got: {status}\nbody: {}",
        String::from_utf8_lossy(&response_body)
    );
    let json: serde_json::Value =
        serde_json::from_slice(extract_json_body(&response_body).as_bytes())
            .expect("json parse");
    assert_eq!(json["errorCode"].as_str(), Some("not-enough-money"));
}

// ---------------------------------------------------------------------
// 5. unavailable — locked wallet returns 503 + JSON.
// ---------------------------------------------------------------------
#[tokio::test]
async fn payjoin_locked_wallet_returns_503_json() {
    let (wallet_state, recv_addr, wallet_name) =
        setup_funded_wallet(500_000, Some("the-passphrase"));
    // Lock it so the require_unlocked gate fires.
    {
        let mut guard = wallet_state.write().await;
        guard
            .wallet_manager
            .lock_wallet(&wallet_name)
            .expect("lock wallet");
    }

    let psbt = make_original_psbt(&recv_addr, Network::Regtest, 50_000);
    let body = psbt.to_base64();
    let (status, response_body) = send_payjoin_request(
        Some(wallet_state),
        "v=1",
        body.as_bytes(),
    )
    .await;
    assert!(
        status.starts_with("HTTP/1.1 503"),
        "expected 503, got: {status}\nbody: {}",
        String::from_utf8_lossy(&response_body)
    );
    let json: serde_json::Value =
        serde_json::from_slice(extract_json_body(&response_body).as_bytes())
            .expect("json parse");
    assert_eq!(json["errorCode"].as_str(), Some("unavailable"));
}

// ---------------------------------------------------------------------
// Test-side helpers
// ---------------------------------------------------------------------

/// Strip any leading/trailing whitespace + any chunked-transfer-encoding
/// hex prefix/suffix lines from a response body so the residue is the
/// raw base64 PSBT.
fn trim_to_base64(s: &str) -> String {
    // Base64 alphabet (+ '=' pad). Anything outside it is treated as
    // framing noise.
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=';
    s.chars().filter(|c| is_b64(*c)).collect()
}

/// Pull the JSON body out of a raw HTTP response body that may include
/// chunked transfer-encoding framing. axum/hyper 0.7 may send a small
/// JSON in a single chunk: `<hex-len>\r\n<json>\r\n0\r\n\r\n`. We just
/// scan for the first `{` and last `}` since JSON objects are
/// substring-unique in this context (the framing is pure ASCII digits
/// and CRLFs).
fn extract_json_body(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    let start = s.find('{').unwrap_or(0);
    let end = s.rfind('}').unwrap_or(s.len() - 1);
    s[start..=end].to_string()
}
