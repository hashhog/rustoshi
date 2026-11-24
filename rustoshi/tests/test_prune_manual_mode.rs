//! `--prune=1` is Core's MANUAL prune mode: the node never deletes block data
//! on its own; only the `pruneblockchain` RPC does.
//!
//! Core (`bitcoin-core/src/init.cpp`, `-prune` help text: "-prune=1 allows
//! manual pruning via RPC"): `node/blockmanager_args.cpp` maps `-prune=1` to
//! `BlockManager::PRUNE_TARGET_MANUAL` (`UINT64_MAX`, `blockstorage.h`), so
//! the automatic `FindFilesToPrune` pass can never find usage above the
//! target and deletes nothing. Data goes only through `PruneBlockFilesManual`,
//! which only `pruneblockchain` reaches.
//!
//! rustoshi gated the reorg-retention sweep in the P2P connect loop on
//! "any prune mode" (`PruneCoordConfig::is_prune_mode`), so a `--prune=1`
//! node still dropped every block body + undo below `tip - 288` on each
//! flush, exactly like `--prune=550`.
//!
//! Each test drives two real regtest binaries: a miner (archive) and a
//! `--prune=1` node that syncs from it over P2P (`--connect`), because the
//! retention sweep lives in the P2P block-connect loop, not in the RPC
//! mining path. Run with
//! `cargo test -p rustoshi --test test_prune_manual_mode`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// BIP-173 regtest P2WPKH test vector; any valid regtest address works.
const MINE_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// Core regtest `nPruneAfterHeight` is 1000: `pruneblockchain` refuses a
/// shorter chain ("Blockchain is too short for pruning.").
const FIRST_SYNC: u32 = 1100;
/// Blocks mined on top of `FIRST_SYNC` (and again after `pruneblockchain`).
const EXTRA: u32 = 40;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    child: Child,
    rpc_port: u16,
    p2p_port: u16,
    log_path: std::path::PathBuf,
}

impl Node {
    fn start(datadir: &Path, extra: &[String]) -> Node {
        std::fs::create_dir_all(datadir).unwrap();
        let rpc_port = free_port();
        let p2p_port = free_port();
        let log_path = datadir.join("stdout.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_rustoshi"))
            .arg("--network=regtest")
            .arg(format!("--datadir={}", datadir.display()))
            .arg(format!("--rpcbind=127.0.0.1:{rpc_port}"))
            .arg("--rpcuser=test")
            .arg("--rpcpassword=test")
            .arg(format!("--port={p2p_port}"))
            .arg("--metrics-port=0")
            .arg("--nodnsseed")
            .arg("--nofixedseeds")
            .args(extra)
            .env_remove("HASHHOG_UNSAFE_SNAPSHOT_HEIGHT")
            .env_remove("HASHHOG_CAMPAIGN_ASSUMEUTXO")
            .env_remove("HASHHOG_REGTEST_ASSUMEUTXO")
            .env("NO_COLOR", "1")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn rustoshi");
        let node = Node {
            child,
            rpc_port,
            p2p_port,
            log_path,
        };
        node.wait_rpc();
        node
    }

    fn log_tail(&self) -> String {
        let s = std::fs::read_to_string(&self.log_path).unwrap_or_default();
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }

    /// One JSON-RPC call over a fresh HTTP/1.1 connection. Returns the
    /// `result` on success and the `error` object as `Err`.
    fn call(&self, method: &str, params: Value) -> Result<Value, Value> {
        let body =
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut s = TcpStream::connect(("127.0.0.1", self.rpc_port))
            .map_err(|e| json!({"transport": e.to_string()}))?;
        s.set_read_timeout(Some(Duration::from_secs(300))).unwrap();
        // "test:test"
        let req = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        s.write_all(req.as_bytes())
            .map_err(|e| json!({"transport": e.to_string()}))?;
        let mut reader = BufReader::new(s);
        let mut content_length: Option<usize> = None;
        loop {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| json!({"transport": e.to_string()}))?;
            if n == 0 || line == "\r\n" {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().ok();
            }
        }
        let mut buf = Vec::new();
        match content_length {
            Some(n) => {
                buf.resize(n, 0);
                reader
                    .read_exact(&mut buf)
                    .map_err(|e| json!({"transport": e.to_string()}))?;
            }
            None => {
                reader
                    .read_to_end(&mut buf)
                    .map_err(|e| json!({"transport": e.to_string()}))?;
            }
        }
        let v: Value = serde_json::from_slice(&buf)
            .map_err(|e| json!({"transport": format!("bad json: {e}")}))?;
        match v.get("error") {
            Some(e) if !e.is_null() => Err(e.clone()),
            _ => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
        }
    }

    fn wait_rpc(&self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if self.call("getblockcount", json!([])).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("RPC never came up; log tail:\n{}", self.log_tail());
    }

    fn height(&self) -> u32 {
        self.call("getblockcount", json!([]))
            .expect("getblockcount")
            .as_u64()
            .unwrap() as u32
    }

    fn mine(&self, n: u32) {
        let mut left = n;
        while left > 0 {
            let k = left.min(100);
            self.call("generatetoaddress", json!([k, MINE_ADDR]))
                .unwrap_or_else(|e| panic!("generatetoaddress: {e}"));
            left -= k;
        }
    }

    fn wait_height(&self, h: u32) {
        let deadline = Instant::now() + Duration::from_secs(600);
        while Instant::now() < deadline {
            if self.height() >= h {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!(
            "node stuck at {} waiting for {}; log tail:\n{}",
            self.height(),
            h,
            self.log_tail()
        );
    }

    /// Heights in `1..=tip` whose block body this node can no longer serve.
    fn missing_blocks(&self) -> Vec<u32> {
        let tip = self.height();
        let mut missing = Vec::new();
        for h in 1..=tip {
            let hash = self.call("getblockhash", json!([h])).expect("getblockhash");
            if self.call("getblock", json!([hash, 0])).is_err() {
                missing.push(h);
            }
        }
        missing
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.call("stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // The test's own child on a scratch regtest datadir.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A `--prune=1` node connects to the miner before any block exists and
/// follows the miner's block announcements over P2P while the miner mines
/// `FIRST_SYNC + EXTRA` blocks. Each announced block reaches the header tip
/// and flushes on its own, which is when the retention sweep runs. Returns
/// both nodes (miner first) once the pruned node is at the miner's tip.
///
/// The pruned node is started first on purpose: a rustoshi node advertises
/// the `start_height` it had at boot in its `version` message, so a peer that
/// joins after RPC mining would see height 0 and never pick it as a sync
/// peer. That is unrelated to pruning and not what these tests pin.
fn miner_and_manual_pruned(tmp: &Path) -> (Node, Node) {
    miner_and_pruned(tmp, "--prune=1")
}

fn miner_and_pruned(tmp: &Path, prune_arg: &str) -> (Node, Node) {
    let miner = Node::start(&tmp.join("miner"), &[]);
    let pruned = Node::start(
        &tmp.join("pruned"),
        &[
            prune_arg.to_string(),
            format!("--connect=127.0.0.1:{}", miner.p2p_port),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while pruned
        .call("getconnectioncount", json!([]))
        .ok()
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        == 0
    {
        assert!(
            Instant::now() < deadline,
            "pruned node never connected; log:\n{}",
            pruned.log_tail()
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    let total = FIRST_SYNC + EXTRA;
    while miner.height() < total {
        miner.mine((total - miner.height()).min(100));
        pruned.wait_height(miner.height());
    }
    assert_eq!(miner.height(), total);
    assert_eq!(pruned.height(), total);
    (miner, pruned)
}

/// Core: `-prune=1` never prunes automatically. After syncing
/// FIRST_SYNC + EXTRA blocks (well past `MIN_BLOCKS_TO_KEEP` = 288) the
/// `--prune=1` node must still serve every block. Failed before this fix:
/// heights 2..=851 were gone ("deleted 850 blocks on its own").
#[test]
fn prune_manual_mode_never_prunes_automatically() {
    let tmp = tempfile::tempdir().unwrap();
    let (_miner, pruned) = miner_and_manual_pruned(tmp.path());

    let info = pruned.call("getblockchaininfo", json!([])).unwrap();
    assert_eq!(
        info["pruned"],
        json!(true),
        "--prune=1 is a prune mode: {info}"
    );

    let missing = pruned.missing_blocks();
    assert!(
        missing.is_empty(),
        "--prune=1 deleted {} blocks on its own (first {:?}, last {:?}); \
         Core's manual mode only prunes through pruneblockchain",
        missing.len(),
        missing.first(),
        missing.last()
    );
    assert_eq!(
        info["pruneheight"],
        json!(0),
        "nothing pruned yet, pruneheight must stay 0: {info}"
    );
}

/// Core: under `-prune=1`, `pruneblockchain <h>` deletes block data up to
/// `h` and nothing above it, and the node keeps that floor afterwards (no
/// automatic pruning follows it up the chain). Failed before this fix:
/// blocks up to `tip - 289` were already gone before the RPC was called.
///
/// `target` stays below 299, the highest regtest assumeutxo height in
/// chainparams: rustoshi's `pruneblockchain` clamps to that height even when
/// no snapshot is loaded (Core's `GetPruneRange` does not). That is a
/// separate divergence, left out of this test on purpose.
#[test]
fn prune_manual_mode_pruneblockchain_prunes_to_requested_height() {
    let tmp = tempfile::tempdir().unwrap();
    let (miner, pruned) = miner_and_manual_pruned(tmp.path());

    let target = 250u32;
    let got = pruned
        .call("pruneblockchain", json!([target]))
        .unwrap_or_else(|e| panic!("pruneblockchain: {e}"));
    assert_eq!(
        got,
        json!(target),
        "pruneblockchain returns the last pruned height"
    );

    let missing = pruned.missing_blocks();
    let expected: Vec<u32> = (1..=target).collect();
    assert_eq!(
        missing.first(),
        Some(&1),
        "blocks from height 1 must be pruned"
    );
    assert_eq!(
        missing.len(),
        expected.len(),
        "exactly heights 1..={target} must be pruned (last missing {:?})",
        missing.last()
    );
    assert_eq!(missing, expected);

    let info = pruned.call("getblockchaininfo", json!([])).unwrap();
    assert_eq!(info["pruneheight"], json!(target + 1), "{info}");

    // More blocks after the manual prune: the floor stays where the operator
    // put it.
    miner.mine(EXTRA);
    pruned.wait_height(miner.height());
    assert_eq!(pruned.missing_blocks(), expected);
}

/// Control: the size-target mode (`--prune=550`) still prunes on its own, so
/// the fix gates the sweep on the mode and does not switch it off. Also shows
/// the harness can see an automatic prune. Passes before and after the fix.
///
/// This pins rustoshi's CURRENT size-mode behaviour, not Core's: rustoshi's
/// retention sweep ignores the byte target and keeps only the last 288
/// blocks, while Core would delete nothing on ~1,140 tiny regtest blocks
/// (far below 550 MiB). If size mode is made to honour the target, update
/// this control to build a chain above the target instead.
#[test]
fn prune_size_mode_still_prunes_automatically() {
    let tmp = tempfile::tempdir().unwrap();
    let (_miner, pruned) = miner_and_pruned(tmp.path(), "--prune=550");
    let missing = pruned.missing_blocks();
    let tip = pruned.height();
    assert!(
        !missing.is_empty(),
        "--prune=550 must prune below tip - 288 on its own"
    );
    assert!(
        missing.iter().all(|&h| h < tip - 288),
        "size mode must keep the last 288 blocks (missing up to {:?}, tip {tip})",
        missing.last()
    );
}
