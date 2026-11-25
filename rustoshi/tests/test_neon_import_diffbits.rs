//! Neon audit (2026-11-24) finding 13, block-import half, and its interplay
//! with finding 11.
//!
//! Core's `-loadblock` import runs every block through `AcceptBlock` ->
//! `ContextualCheckBlockHeader`, whose first gate is
//! `nBits == GetNextWorkRequired(...)` ("bad-diffbits", validation.cpp).
//! rustoshi's `--import-blocks` paths called `process_block` directly, which
//! passes `expected_bits = None`, so an imported block with valid PoW against
//! a wrong, easier nBits was connected.
//!
//! Finding 11 (in this PR) makes `check_proof_of_work` accept nBits
//! `0x21007fff` on regtest, as Core's SetCompact does. Without the import
//! gate, a regtest block 1 with that nBits would then import. Core refuses
//! it (bad-diffbits), and so did master, only because master's PoW check
//! wrongly refused it (high-hash). The gate keeps the import path closed.
//!
//! The behavioural tests run the real binary: `--import-blocks -` on a fresh
//! regtest datadir with one framed block on stdin, then read the best height
//! stored in the datadir.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Block, BlockHeader, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::block_store::BlockStore;
use rustoshi_storage::ChainDb;

const MAIN_RS: &str = include_str!("../src/main.rs");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Regtest block 1 on the real regtest genesis, mined against `bits`
/// (the hash meets the target `bits` declares).
fn block1(bits: u32) -> Block {
    let params = ChainParams::regtest();
    let cb = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
            // BIP-34 height 1 = OP_1, then filler to reach the 2-byte minimum.
            script_sig: vec![0x51, 0x00],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 50 * 100_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };
    let mut b = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: params.genesis_hash,
            merkle_root: Hash256::ZERO,
            timestamp: params.genesis_block.header.timestamp + 600,
            bits,
            nonce: 0,
        },
        transactions: vec![cb],
    };
    b.header.merkle_root = b.compute_merkle_root();
    // Compare the hash with the target `bits` declares, computed here so the
    // test does not depend on the target decoder under test.
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x7f_ffff;
    let mut target = [0u8; 32]; // big-endian
    for (k, byte) in [(mant >> 16) as u8, (mant >> 8) as u8, mant as u8].iter().enumerate() {
        let pos = 32 + k;
        if pos >= exp && pos - exp < 32 {
            target[pos - exp] = *byte;
        }
    }
    loop {
        let mut h = *b.block_hash().as_bytes();
        h.reverse();
        if h <= target {
            return b;
        }
        b.header.nonce += 1;
    }
}

fn import_one(block: &Block) -> (u32, String) {
    let tmp = tempfile::tempdir().unwrap();
    let datadir = tmp.path().join("node");
    std::fs::create_dir_all(&datadir).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustoshi"))
        .arg("--network=regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcbind=127.0.0.1:{}", free_port()))
        .arg("--rpcuser=test")
        .arg("--rpcpassword=test")
        .arg(format!("--port={}", free_port()))
        .arg("--metrics-port=0")
        .arg("--nodnsseed")
        .arg("--nofixedseeds")
        .arg("--maxconnections=0")
        .arg("--import-blocks=-")
        .env_remove("HASHHOG_UNSAFE_SNAPSHOT_HEIGHT")
        .env_remove("HASHHOG_CAMPAIGN_ASSUMEUTXO")
        .env_remove("HASHHOG_REGTEST_ASSUMEUTXO")
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustoshi");
    {
        let raw = block.serialize();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&1u32.to_le_bytes()).unwrap();
        stdin.write_all(&(raw.len() as u32).to_le_bytes()).unwrap();
        stdin.write_all(&raw).unwrap();
        // drop closes stdin: end of the import stream
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("rustoshi --import-blocks did not exit within 120 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let db = ChainDb::open(&datadir.join("regtest").join("chainstate")).unwrap();
    let height = BlockStore::new(&db).get_best_height().unwrap().unwrap_or(0);
    (height, log)
}

#[test]
fn neon_f13_import_refuses_block_with_wrong_nbits() {
    // 0x2000ffff is below the regtest powLimit and the block meets it, but
    // GetNextWorkRequired for regtest block 1 is 0x207fffff: Core bad-diffbits.
    let (height, log) = import_one(&block1(0x2000_ffff));
    assert_eq!(height, 0, "the wrong-nBits block must not be connected; log:\n{log}");
}

#[test]
fn neon_f11_import_refuses_nsize33_nbits() {
    // 0x21007fff passes Core's (and, with F11, rustoshi's) PoW check on
    // regtest; it is still not 0x207fffff, so Core refuses it bad-diffbits.
    let (height, log) = import_one(&block1(0x2100_7fff));
    assert_eq!(height, 0, "an nBits-33 block 1 must not be connected; log:\n{log}");
}

#[test]
fn neon_f13_control_import_connects_block_with_required_nbits() {
    let (height, log) = import_one(&block1(0x207f_ffff));
    assert_eq!(height, 1, "a valid block 1 must still import; log:\n{log}");
}

#[test]
fn neon_f13_blk_file_import_runs_the_diffbits_gate() {
    // The blk*.dat path takes its hashes from the header chain; pin that it
    // runs the same connect-time gate as the stdin path above.
    let start = MAIN_RS.find("fn run_import_from_blk_files(").expect("blk import fn");
    let end = MAIN_RS[start..].find("fn run_import_from_stdin(").expect("stdin import fn") + start;
    assert!(
        MAIN_RS[start..end].contains("check_connect_diffbits("),
        "run_import_from_blk_files must call check_connect_diffbits before process_block"
    );
}
