//! Neon audit (2026-11-24) finding 8, the P2P header half in `main.rs`.
//!
//! Core `ContextualCheckBlockHeader` (validation.cpp) refuses a header at a
//! difficulty-adjustment height whose time is more than MAX_TIMEWARP (600 s)
//! before `pindexPrev->GetBlockTime()` when BIP-94 is enforced (testnet4).
//! The header-sync closure built the gate's `prev_entry` with
//! `timestamp: 0`, so `block_time < 0 - 600` could never fire. The closure
//! is inline in `main()` (it needs the live HeaderSync and BlockStore), so
//! this pins its source, as `test_header_path_diffbits_wiring.rs` does for
//! the diffbits gate. The same gate with the real parent time is exercised
//! behaviourally through the side-branch store and submitheader in
//! `crates/rpc/tests/test_neon_accept_findings.rs`.
//!
//! Fails on master 93365362; passes with the fix.

const MAIN_RS: &str = include_str!("../src/main.rs");

#[test]
fn neon_f8_p2p_header_closure_passes_the_real_parent_timestamp() {
    let start = MAIN_RS
        .find("let need_more = header_sync.process_headers(")
        .expect("header-sync closure");
    let end = MAIN_RS[start..]
        .find("store_validated_header(&block_store, header, height)")
        .expect("closure end")
        + start;
    let closure = &MAIN_RS[start..end];
    assert!(
        !closure.contains("timestamp: 0,"),
        "the BIP-94 timewarp gate's prev_entry must not use a 0 parent timestamp"
    );
    assert!(
        closure.contains("timestamp: parent_timestamp,"),
        "prev_entry must carry the parent's timestamp"
    );
    assert!(
        closure.contains("parent_timestamp_for_connect("),
        "the header closure must read the stored parent header's timestamp"
    );
}
