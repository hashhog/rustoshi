//! State-machine sweep (sm-sweep-rustoshi), gap B-1: boot tip derivation.
//!
//! At startup `async_main` re-derives the chain tip height from the height
//! index (`rustoshi/src/main.rs`, "Try to find the actual height by looking up
//! the best hash in the height index"). The backward scan is capped at
//! `min(stored_height, 1_000_000)` and the "cumulative counter bug" binary
//! search uses `hi = 1_000_000`, so a real tip above height 1,000,000 can never
//! be found. Boot then persists a wrong height with `set_best_block` and builds
//! `ChainState` on it; the next block's BIP34 height check runs against that
//! wrong height.
//!
//! Core takes the tip height from the coins tip's block-index entry
//! (`Chainstate::LoadChainTip`, validation.cpp) and never guesses or caps it.
//!
//! Mainnet is about 25k blocks below 1,000,000 (Nov 2026), so this fires on
//! every restart from then on.
//!
//! The test drives the real binary on a regtest datadir prepared with a
//! height index and a tip, waits for the boot log line `Chain tip: <hash>
//! (height N)`, stops the child, and reads back the persisted tip.
//!
//! Fixed by sm-fix-rustoshi-boot-tip-height: boot now takes the height from
//! the tip's block-index entry, so the test runs by default. Run with
//! `cargo test -p rustoshi --test sm_sweep_boot_tip_height`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use rustoshi_consensus::ChainParams;
use rustoshi_primitives::Hash256;
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus, BlockStore};
use rustoshi_storage::ChainDb;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn fake_hash(h: u32) -> Hash256 {
    let mut b = [0x5au8; 32];
    b[..4].copy_from_slice(&h.to_le_bytes());
    Hash256(b)
}

/// Prepare a regtest datadir whose height index holds `lo..=tip` and whose
/// stored best block is (`fake_hash(tip)`, `tip`). Boot the binary until it
/// logs its chain tip, then stop it. Returns (height in the boot log line,
/// height persisted in CF_META after boot).
fn boot_with_tip(lo: u32, tip: u32) -> (u32, u32) {
    boot_with(lo, tip, tip, true)
}

/// Like `boot_with_tip`, but the stored best-block height is `stored` (which
/// may differ from the tip's real height `tip`), and the tip's block-index
/// entry is written only when `with_index_entry` is set.
fn boot_with(lo: u32, tip: u32, stored: u32, with_index_entry: bool) -> (u32, u32) {
    let (logged, persisted, log) = boot_raw(lo, tip, stored, with_index_entry, false);
    let logged = logged.unwrap_or_else(|| panic!("no `Chain tip:` boot line in:\n{log}"));
    (logged, persisted)
}

/// Prepare and boot as `boot_with`; with `corrupt_index_entry` the tip's
/// block-index entry is replaced by undecodable bytes. Returns (height in the
/// boot log line if one was printed, height persisted after boot, boot log).
fn boot_raw(
    lo: u32,
    tip: u32,
    stored: u32,
    with_index_entry: bool,
    corrupt_index_entry: bool,
) -> (Option<u32>, u32, String) {
    let params = ChainParams::regtest();
    let tmp = tempfile::tempdir().unwrap();
    let datadir = tmp.path().join("node");
    let chainstate = datadir.join("regtest").join("chainstate");
    std::fs::create_dir_all(&chainstate).unwrap();
    {
        let db = ChainDb::open(&chainstate).unwrap();
        let store = BlockStore::new(&db);
        store.init_genesis(&params).unwrap();
        for h in lo..=tip {
            store.put_height_index(h, &fake_hash(h)).unwrap();
        }
        // The tip has a block-index entry at its real height, as on a real
        // datadir: that is what Core's LoadChainTip reads the height from.
        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_SCRIPTS);
        status.set(BlockStatus::HAVE_DATA);
        if with_index_entry {
            store
                .put_block_index(
                    &fake_hash(tip),
                    &BlockIndexEntry {
                        height: tip,
                        status,
                        n_tx: 1,
                        timestamp: 1_700_000_000,
                        bits: 0x207f_ffff,
                        nonce: 0,
                        version: 0x2000_0000,
                        prev_hash: fake_hash(tip - 1),
                        chain_work: [0u8; 32],
                    },
                )
                .unwrap();
        }
        if corrupt_index_entry {
            db.put_cf(
                rustoshi_storage::CF_BLOCK_INDEX,
                fake_hash(tip).as_bytes(),
                &[0xff, 0xff, 0xff],
            )
            .unwrap();
        }
        store.set_best_block(&fake_hash(tip), stored).unwrap();
    }

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
        .env_remove("HASHHOG_UNSAFE_SNAPSHOT_HEIGHT")
        .env_remove("HASHHOG_CAMPAIGN_ASSUMEUTXO")
        .env_remove("HASHHOG_REGTEST_ASSUMEUTXO")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustoshi");

    let (tx, rx) = mpsc::channel::<String>();
    for pipe in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut log = String::new();
    let mut logged: Option<u32> = None;
    while let Ok(line) = rx.recv_timeout(Duration::from_secs(60)) {
        log.push_str(&line);
        log.push('\n');
        if let Some(i) = line.find("Chain tip: ") {
            let rest = &line[i..];
            let h = rest
                .split("(height ")
                .nth(1)
                .and_then(|s| s.split(')').next())
                .and_then(|s| s.trim().parse::<u32>().ok());
            logged = h;
            break;
        }
    }
    // This is the test's own child process on a scratch regtest datadir.
    let _ = child.kill();
    let _ = child.wait();

    let db = ChainDb::open(&chainstate).expect("reopen chainstate");
    let persisted = BlockStore::new(&db).get_best_height().unwrap().unwrap();
    (logged, persisted, log)
}

/// Control: below the 1,000,000 cap the boot scan finds the tip, so the
/// harness reaches the derivation and parses its result. Passes on master.
#[test]
fn boot_tip_height_below_one_million_is_kept() {
    let (logged, persisted) = boot_with_tip(990_000, 999_999);
    assert_eq!(logged, 999_999);
    assert_eq!(persisted, 999_999);
}

/// The gap: a tip above 1,000,000 is re-derived to a wrong height and that
/// wrong height is written back to disk. Failed before
/// sm-fix-rustoshi-boot-tip-height.
#[test]
fn boot_tip_height_above_one_million_is_kept() {
    let (logged, persisted) = boot_with_tip(995_000, 1_000_005);
    assert_eq!(
        logged, 1_000_005,
        "boot derived the wrong tip height (Core LoadChainTip uses the tip's index entry)"
    );
    assert_eq!(persisted, 1_000_005, "boot persisted the wrong tip height");
}

/// The stored height is a stale counter (the "cumulative counter" case the
/// legacy scan guessed at) and disagrees with the tip's block-index entry.
/// Boot must take the entry's height, not guess from the height index.
#[test]
fn boot_tip_height_comes_from_block_index_not_stored_counter() {
    let (logged, persisted) = boot_with(995_000, 1_000_005, 3_000_000, true);
    assert_eq!(
        logged, 1_000_005,
        "boot must use the tip's block-index height"
    );
    assert_eq!(
        persisted, 1_000_005,
        "boot must persist the tip's block-index height"
    );
}

/// Control for the kept fallback: a tip with no block-index entry is still
/// found by the legacy height-index scan below 1,000,000.
#[test]
fn boot_tip_without_index_entry_keeps_legacy_scan() {
    let (logged, persisted) = boot_with(490_000, 500_000, 500_000, false);
    assert_eq!(logged, 500_000);
    assert_eq!(persisted, 500_000);
}

/// A tip whose block-index entry cannot be read must not be treated as "no
/// entry": that would run the capped legacy scan and write a wrong height to
/// disk. Boot must stop before choosing a tip and leave the stored height alone.
#[test]
fn boot_tip_corrupt_index_entry_is_not_guessed() {
    let (logged, persisted, log) = boot_raw(995_000, 1_000_005, 1_000_005, false, true);
    assert_eq!(
        logged, None,
        "boot guessed a tip height past an unreadable block-index entry:\n{log}"
    );
    assert_eq!(
        persisted, 1_000_005,
        "boot overwrote the stored tip height past an unreadable block-index entry"
    );
}
