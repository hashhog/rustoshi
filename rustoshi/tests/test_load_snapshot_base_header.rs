//! `--load-snapshot` must refuse a snapshot whose base header is unknown.
//!
//! Core's `ActivateSnapshot` (validation.cpp:5611-5615) returns "The base
//! block header (...) must appear in the headers chain" before it reads a
//! coin. rustoshi's CLI path used to ingest the coins and write the base's
//! block index entry with `prev_hash = ZERO` and `bits = 0` instead.
//!
//! This drives the real binary on a fresh regtest datadir, so the snapshot
//! targets Core's built-in regtest entry at height 299 while the datadir has
//! no headers at all.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Hash256, OutPoint, TxOut};
use rustoshi_storage::block_store::BlockStore;
use rustoshi_storage::{ChainDb, Coin, SnapshotMetadata, SnapshotWriter, CF_UTXO};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn cli_load_snapshot_refuses_unknown_base_header_and_writes_nothing() {
    let params = ChainParams::regtest();
    let entry = params
        .assumeutxo_data
        .iter()
        .find(|e| e.height == 299)
        .expect("Core's regtest assumeutxo entry at 299")
        .clone();
    assert!(
        entry.base_tail_headers.is_empty(),
        "regtest entries carry no header band"
    );

    let tmp = tempfile::tempdir().unwrap();
    let datadir = tmp.path().join("node");
    let snap = tmp.path().join("snap.dat");
    {
        let meta = SnapshotMetadata::new(entry.blockhash, 1, params.network_magic);
        let mut buf = Vec::new();
        let mut w = SnapshotWriter::new(&mut buf, &meta).unwrap();
        let op = OutPoint {
            txid: Hash256([0x42; 32]),
            vout: 0,
        };
        let coin = Coin {
            tx_out: TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x51],
            },
            height: 1,
            is_coinbase: true,
        };
        w.write_coin(&op, &coin).unwrap();
        let _ = w.finish().unwrap();
        std::fs::write(&snap, &buf).unwrap();
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustoshi"))
        .arg("--network=regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcbind=127.0.0.1:{}", free_port()))
        .arg("--rpcuser=test")
        .arg("--rpcpassword=test")
        .arg(format!("--port={}", free_port()))
        .arg("--nodnsseed")
        .arg("--nofixedseeds")
        .arg("--maxconnections=0")
        .arg(format!("--load-snapshot={}", snap.display()))
        .env_remove("HASHHOG_UNSAFE_SNAPSHOT_HEIGHT")
        .env_remove("HASHHOG_CAMPAIGN_ASSUMEUTXO")
        .env_remove("HASHHOG_REGTEST_ASSUMEUTXO")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustoshi");

    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut out = String::new();
    let mut err = String::new();
    let _ = child.stdout.take().unwrap().read_to_string(&mut out);
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    let log = format!("{out}\n{err}");

    let status =
        status.unwrap_or_else(|| panic!("node kept running after --load-snapshot:\n{log}"));
    assert!(!status.success(), "load must fail, node exited 0:\n{log}");
    let want = format!(
        "Unable to load UTXO snapshot: The base block header ({}) must appear in the headers \
         chain. Make sure all headers are syncing, and call loadtxoutset again",
        entry.blockhash.to_hex()
    );
    assert!(
        log.contains(&want),
        "missing Core's error {want:?} in:\n{log}"
    );

    // Nothing written: no coins, no base index entry, tip still genesis, no
    // snapshot base marker.
    let netdir = datadir.join("regtest");
    let db = ChainDb::open(&netdir.join("chainstate")).expect("reopen chainstate");
    let coins = db.iter_cf(CF_UTXO).map(|it| it.count()).unwrap_or(0);
    assert_eq!(coins, 0, "refused load wrote {coins} coins");
    let store = BlockStore::new(&db);
    assert!(
        store.get_block_index(&entry.blockhash).unwrap().is_none(),
        "refused load wrote a base block index entry"
    );
    assert!(
        store.get_hash_by_height(299).unwrap().is_none(),
        "refused load wrote a height index entry at the base"
    );
    assert_ne!(
        store.get_best_block_hash().unwrap(),
        Some(entry.blockhash),
        "refused load moved the tip to the base"
    );
    assert!(
        rustoshi_storage::read_snapshot_blockhash(&netdir)
            .unwrap()
            .is_none(),
        "refused load wrote the snapshot base marker"
    );
}
