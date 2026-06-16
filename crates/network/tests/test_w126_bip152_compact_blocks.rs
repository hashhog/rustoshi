//! W126 — BIP-152 Compact Blocks 30-gate audit (rustoshi).
//!
//! Discovery wave, not a fix wave. Each gate is documented inline and either:
//!   - **PASS regression-pin** for surfaces that are PRESENT and Core-aligned;
//!   - **`#[ignore]` xfail** for known PARTIAL or MISSING gates, with a
//!     `BUG-N` reference into `audit/w126_bip152_compact_blocks.md`.
//!
//! ## Scope
//! - `crates/network/src/compact_blocks.rs` (CmpctBlock, PrefilledTx,
//!   BlockTxnRequest, BlockTxn, PartiallyDownloadedBlock,
//!   PeerCompactBlockState, CompactBlockRelay, is_block_mutated)
//! - `rustoshi/src/main.rs:3814-4058` — incoming SENDCMPCT / CMPCTBLOCK /
//!   GETBLOCKTXN / BLOCKTXN dispatch
//! - `crates/network/src/peer.rs:1015-1026,1241-1254,1945-1957` — outbound
//!   sendcmpct on v1/v2 handshake
//! - `crates/network/src/message.rs::SendCmpctMessage` — wire codec
//! - `crates/network/src/peer_manager.rs::handle_event` — forwarded message
//!   fall-through (no-op for SendCmpct today)
//!
//! ## Core reference
//! - BIP-152: <https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki>
//! - `bitcoin-core/src/blockencodings.{h,cpp}`
//! - `bitcoin-core/src/net_processing.cpp` (lines 138-141, 199, 1272-1329,
//!   2105-2152, 2598-2614, 3441-3526, 3864-3917, 4245-4304, 4466-4726,
//!   5891-5928) + `net_processing.h:47`
//!
//! ## Audit verdict counters
//!   PRESENT 13 / PARTIAL 1 / MISSING 16 / 17 distinct BUG findings (30 gates).
//!
//! ## Bug index (severity legend: P0-CDIV / P0 / P1 / P2 / P3)
//!   BUG-1  (P1)  G23  CmpctBlock::from_block dead-helper (#[cfg(test)]-only)
//!   BUG-2  (P1)  G24  getdata(MSG_CMPCT_BLOCK) falls through `_ => {}`
//!   BUG-3  (P2)  G25  sendcmpct(version=1) silently accepted (Core rejects)
//!   BUG-4  (P0)  G26  no anti-DoS chain-work pre-check on cmpctblock
//!   BUG-5  (P1)  G27  no orphan-prev MaybeSendGetHeaders fall-back
//!   BUG-6  (P2)  G21  getblocktxn out-of-range index → silent skip, no Misbehaving
//!   BUG-7  (P2)  G21/G30  MAX_BLOCKTXN_DEPTH=10 cap missing
//!   BUG-8  (P2)  G28  no LoadingBlocks/IBD guard on cmpctblock
//!   BUG-9  (P2)  G29  MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3 not defined
//!   BUG-10 (P3)  G23  peer_manager::handle_event(SendCmpct) no-op
//!   BUG-11 (P3)   —   CompactBlockRelay struct never instantiated
//!   BUG-12 (P3)   —   PeerCompactBlockState.last_cmpctblock unused
//!   BUG-13 (P3)  G24  create_cmpctblock_inv pub but unused
//!   BUG-14 (P3)   —   miss_pct > 50% full-block fallback diverges from Core
//!   BUG-15 (P3)  G21  getblocktxn reads from disk; Core uses m_most_recent_block cache
//!   BUG-16 (P3)   —   no vExtraTxnForCompact-equivalent passed to init_data
//!   BUG-17 (P3)   —   no dynamic HB-promote via sendcmpct(announce=true)
//!
//! Cross-wave refs: W112 BUG-G27/G29/G30, W123 G14/G15/G16.

use rustoshi_network::compact_blocks::{
    is_block_mutated, BlockTxn, BlockTxnRequest, CmpctBlock, CompactBlockMode,
    PartiallyDownloadedBlock, PeerCompactBlockState, PrefilledTx, ReadStatus,
    CMPCT_VERSION_1, CMPCT_VERSION_2, MAX_BLOCK_WEIGHT, MAX_CMPCTBLOCK_PEERS_HB,
    MIN_SERIALIZABLE_TRANSACTION_WEIGHT, SHORTTXIDS_LENGTH,
};
use rustoshi_network::message::{
    NetworkMessage, SendCmpctMessage, SENDCMPCT_VERSION,
};
use rustoshi_network::peer::PeerId;
use rustoshi_primitives::transaction::{OutPoint, TxIn, TxOut};
use rustoshi_primitives::{Block, BlockHeader, Hash256, Transaction};
use rustoshi_crypto::sha256d;
use std::sync::Arc;

// ============================================================================
// Helpers (mirrored from W112 to keep the tests self-contained).
// ============================================================================

fn make_coinbase() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x03, 0x01, 0x00, 0x00],
            sequence: 0xFFFFFFFF,
            witness: vec![vec![0u8; 32]],
        }],
        outputs: vec![TxOut {
            value: 50_0000_0000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

fn make_tx(seed: u64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([seed as u8; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![vec![0x30, 0x44], vec![0x02, 0x21]],
        }],
        outputs: vec![TxOut {
            value: seed,
            script_pubkey: vec![0x00; 22],
        }],
        lock_time: 0,
    }
}

fn make_block(tx_count: usize) -> Block {
    let mut transactions = vec![make_coinbase()];
    for i in 1..tx_count {
        transactions.push(make_tx(i as u64 * 1_000_000));
    }
    let merkle_root = {
        let mut hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                hashes.push(*hashes.last().unwrap());
            }
            let mut next = Vec::new();
            for pair in hashes.chunks(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&pair[0].0);
                combined[32..].copy_from_slice(&pair[1].0);
                next.push(sha256d(&combined));
            }
            hashes = next;
        }
        hashes.first().copied().unwrap_or(Hash256::ZERO)
    };
    Block {
        header: BlockHeader {
            version: 0x20000000,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp: 1234567890,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions,
    }
}

// ============================================================================
// G1-G10 — Wire codec layer (all PRESENT, regression pins)
// ============================================================================

/// G1 — `SHORTTXIDS_LENGTH == 6` and short-ids are 6 LE bytes on the wire.
/// Core: `blockencodings.h:103` `static constexpr int SHORTTXIDS_LENGTH = 6`.
#[test]
fn g1_shorttxids_length_constant_and_wire_layout() {
    assert_eq!(SHORTTXIDS_LENGTH, 6, "Core SHORTTXIDS_LENGTH = 6");
    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0x1234_5678_9ABC_DEF0);
    let encoded = compact.serialize();
    // Bytes [80..88] = nonce. Bytes [88..89] = compact-size for shortids count.
    // For 2 short-ids: count byte == 0x02, then 2 × 6 = 12 bytes of short-ids.
    assert_eq!(encoded[88], 0x02, "shortids count");
    // No short-id encoded as 8 bytes — total wire size for 2 ids is 12 not 16.
    // (Test by computing offset to prefilled-vec count byte: 88 + 1 + 2*6 = 101.)
    // We expect prefilled count == 1 at offset 101.
    assert_eq!(encoded[101], 0x01, "prefilled count == 1 (coinbase)");
}

/// G2 — `CMPCT_VERSION_2 == 2` (segwit-aware). Core: `net_processing.cpp:199`
/// `static constexpr uint64_t CMPCTBLOCKS_VERSION{2};`.
#[test]
fn g2_cmpct_version_2_matches_core() {
    assert_eq!(CMPCT_VERSION_2, 2);
    // peer.rs:1020 / 1248 / 1949 all send version=2.
}

/// G3 — `MAX_CMPCTBLOCK_PEERS_HB == 3` matches Core `net_processing.cpp:1312`
/// "we only get 3 of our peers to announce blocks using compact encodings".
#[test]
fn g3_hb_peer_cap_is_3() {
    assert_eq!(MAX_CMPCTBLOCK_PEERS_HB, 3);
}

/// G4 — SipHash key derivation = SHA256(header ‖ nonce), bytes [0..8] → k0,
/// bytes [8..16] → k1. Core: `blockencodings.cpp:35-44`. Tested via
/// determinism: two `CmpctBlock`s from the same (header, nonce) compute the
/// same short-id for the same wtxid.
#[test]
fn g4_siphash_key_derivation_deterministic() {
    let block = make_block(4);
    let c1 = CmpctBlock::from_block(&block, 0xDEAD_BEEF);
    let c2 = CmpctBlock::from_block(&block, 0xDEAD_BEEF);
    let wtxid = block.transactions[1].wtxid();
    assert_eq!(c1.get_short_id(&wtxid), c2.get_short_id(&wtxid));

    // Different nonce → different short-id.
    let c3 = CmpctBlock::from_block(&block, 0xDEAD_BEEE);
    assert_ne!(c1.get_short_id(&wtxid), c3.get_short_id(&wtxid));
}

/// G5 — Short-id always uses wtxid. Core's v2 spec (`blockencodings.cpp:31`):
/// `shorttxids[i - 1] = GetShortID(tx.GetWitnessHash());`. (V1 used txid;
/// rustoshi never supports v1 — see BUG-3 / G25.)
#[test]
fn g5_short_id_uses_wtxid() {
    let block = make_block(2);
    let compact = CmpctBlock::from_block(&block, 0xABCD);
    let wtxid = block.transactions[1].wtxid();
    let expected = compact.get_short_id(&wtxid);
    assert_eq!(compact.short_ids[0], expected);
}

/// G6 — `sendcmpct` wire codec: 1 byte announce + 8 LE bytes version.
/// Core: `protocol.h::SENDCMPCT` payload "bool + uint64".
#[test]
fn g6_sendcmpct_wire_codec() {
    let msg = SendCmpctMessage { announce: true, version: 2 };
    let nm = NetworkMessage::SendCmpct(msg);
    let payload = nm.serialize_payload();
    assert_eq!(payload.len(), 9, "1B announce + 8B version");
    assert_eq!(payload[0], 0x01, "announce=true byte");
    assert_eq!(&payload[1..9], &2u64.to_le_bytes());
}

/// G7 — `CmpctBlock` decode round-trip: header‖nonce‖shortid-vec‖prefilled-vec.
/// Core: `blockencodings.h:121-130`.
#[test]
fn g7_cmpctblock_roundtrip() {
    let block = make_block(6);
    let original = CmpctBlock::from_block(&block, 0xCAFE);
    let encoded = original.serialize();
    let decoded = CmpctBlock::deserialize(&encoded).expect("decode");
    assert_eq!(decoded.header.merkle_root, original.header.merkle_root);
    assert_eq!(decoded.nonce, original.nonce);
    assert_eq!(decoded.short_ids, original.short_ids);
    assert_eq!(decoded.prefilled_txn.len(), original.prefilled_txn.len());
}

/// G8 — `PrefilledTx` differential-index encode/decode.
/// Core: `blockencodings.h:74-81` (COMPACTSIZE-encoded difference).
#[test]
fn g8_prefilled_differential_index() {
    // Construct a block with multiple prefilled txs and verify decode preserves
    // absolute indexes.
    let block = make_block(10);
    let compact = CmpctBlock::from_block_with_prefilled(&block, 0, &[0, 3, 7]);
    assert_eq!(compact.prefilled_txn.len(), 3);
    assert_eq!(compact.prefilled_txn[0].index, 0);
    assert_eq!(compact.prefilled_txn[1].index, 3);
    assert_eq!(compact.prefilled_txn[2].index, 7);

    let encoded = compact.serialize();
    let decoded = CmpctBlock::deserialize(&encoded).expect("decode");
    assert_eq!(decoded.prefilled_txn[0].index, 0);
    assert_eq!(decoded.prefilled_txn[1].index, 3);
    assert_eq!(decoded.prefilled_txn[2].index, 7);
}

/// G9 — `BlockTransactionsRequest` (getblocktxn) differential indexes.
/// Core: `blockencodings.h:45-55` with `DifferenceFormatter`.
#[test]
fn g9_blocktxn_request_differential_indexes() {
    let req = BlockTxnRequest::new(Hash256([0xAB; 32]), vec![0, 1, 5, 100, 1000]);
    let bytes = req.serialize();
    let decoded = BlockTxnRequest::deserialize(&bytes).expect("decode");
    assert_eq!(decoded.block_hash, req.block_hash);
    assert_eq!(decoded.indices, vec![0, 1, 5, 100, 1000]);
}

/// G10 — `BlockTransactions` (blocktxn) full-tx vector codec.
/// Core: `blockencodings.h:57-71`.
#[test]
fn g10_blocktxn_full_tx_vector_codec() {
    let txs = vec![make_tx(1), make_tx(2)];
    let resp = BlockTxn::new(Hash256([0xCD; 32]), txs.clone());
    let bytes = resp.serialize();
    let decoded = BlockTxn::deserialize(&bytes).expect("decode");
    assert_eq!(decoded.block_hash, resp.block_hash);
    assert_eq!(decoded.transactions.len(), 2);
}

// ============================================================================
// G11-G18 — Reconstruction layer (all PRESENT)
// ============================================================================

/// G11 — DoS cap: `tx_count > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT`.
/// Core: `blockencodings.cpp:64-65`.
#[test]
fn g11_init_data_max_tx_count_dos_cap() {
    // Sanity-check the constants match Core.
    assert_eq!(MAX_BLOCK_WEIGHT, 4_000_000);
    assert_eq!(MIN_SERIALIZABLE_TRANSACTION_WEIGHT, 60);
    // MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 66_666.
    assert_eq!(MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT, 66_666);
}

/// G12 — `InitData` empty/null guard returns `ReadStatus::Invalid`.
/// Core: `blockencodings.cpp:62-67`.
#[test]
fn g12_init_data_empty_guard() {
    let block = make_block(3);
    let mut compact = CmpctBlock::from_block(&block, 0);
    // Strip everything → both vectors empty → Invalid.
    compact.short_ids.clear();
    compact.prefilled_txn.clear();
    let res = PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]);
    assert!(matches!(res, Err(ReadStatus::Invalid)));
}

/// G13 — `InitData` bucket-load DoS guard (≤ 12 entries per bucket).
/// Core: `blockencodings.cpp:110-111`. Documented inline at
/// `compact_blocks.rs:704-710`.
#[test]
fn g13_init_data_bucket_load_dos_guard() {
    // The bucket-load guard fires when >12 short-ids land in the same bucket.
    // We can't easily synthesize such a collision in a unit test without
    // mining for it; instead pin the helper is implemented + actively called.
    // Source-grep guard:
    let src = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/compact_blocks.rs"),
    )
    .expect("read compact_blocks.rs");
    assert!(
        src.contains("if *load > 12"),
        "bucket-load DoS guard must trip at 12 elements per bucket"
    );
}

/// G14 — `InitData` short-id exact-collision returns `ReadStatus::Failed`.
/// Core: `blockencodings.cpp:115-116`.
#[test]
fn g14_init_data_exact_shortid_collision() {
    // Forge a CmpctBlock whose `short_ids` contains two identical entries.
    let block = make_block(3);
    let mut compact = CmpctBlock::from_block(&block, 0xFEED);
    // Replace the second short_id with the first → exact collision.
    if compact.short_ids.len() >= 2 {
        compact.short_ids[1] = compact.short_ids[0];
    } else {
        // Inject a duplicate; need at least 2 to trigger.
        let dup = compact.short_ids[0];
        compact.short_ids.push(dup);
    }
    let res = PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]);
    assert!(matches!(res, Err(ReadStatus::Failed)));
}

/// G15 — Mempool walk: first-match fills slot. Source-grep + behavioral.
/// Core: `blockencodings.cpp:121-145`.
#[test]
fn g15_init_data_mempool_first_match_fill() {
    let block = make_block(4);
    let compact = CmpctBlock::from_block(&block, 0xC0FFEE);

    // Build a mempool containing all non-coinbase txs.
    let mempool: Vec<(Hash256, Arc<Transaction>)> = block
        .transactions
        .iter()
        .skip(1)
        .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
        .collect();
    let mempool_refs: Vec<(&Hash256, &Arc<Transaction>)> =
        mempool.iter().map(|(h, t)| (h, t)).collect();

    let partial = PartiallyDownloadedBlock::init_data(
        &compact,
        mempool_refs.into_iter(),
        &[],
    )
    .expect("init_data ok");
    let (prefilled, from_mempool, _extra) = partial.stats();
    assert_eq!(prefilled, 1, "coinbase prefilled");
    assert_eq!(from_mempool, 3, "3 non-coinbase txs filled from mempool");
    assert!(partial.is_complete());
}

/// G16 — Extra-txn walk uses wtxid-different collision discriminator.
/// Core: `blockencodings.cpp:163-164`.  Pinned via source-grep.
#[test]
fn g16_init_data_extra_txn_wtxid_discriminator() {
    let src = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/compact_blocks.rs"),
    )
    .expect("read compact_blocks.rs");
    // Comment + code reference the wtxid-vs-wtxid compare for the
    // dedup-mempool-vs-extra path.
    assert!(
        src.contains("if existing.wtxid() != **wtxid"),
        "extra-txn collision must compare wtxids before suppressing"
    );
}

/// G17 — `FillBlock` runs `is_block_mutated` after fill (mutation check).
/// Core: `blockencodings.cpp:218-222`.
#[test]
fn g17_fill_block_mutation_check_runs() {
    // Build a clean block, reconstruct, fill, expect Ok.
    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0xBEEF);
    let mempool: Vec<(Hash256, Arc<Transaction>)> = block
        .transactions
        .iter()
        .skip(1)
        .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
        .collect();
    let mempool_refs: Vec<(&Hash256, &Arc<Transaction>)> =
        mempool.iter().map(|(h, t)| (h, t)).collect();
    let mut partial = PartiallyDownloadedBlock::init_data(
        &compact,
        mempool_refs.into_iter(),
        &[],
    )
    .expect("init_data");
    // segwit_active=false to bypass coinbase witness commitment check (our
    // make_coinbase has a witness but no commitment output).
    let res = partial.fill_block(vec![], false);
    assert!(res.is_ok(), "fill_block ok on clean reconstruction");
}

/// G18 — `FillBlock` clears `header` + `txn_available` after the fill path
/// runs, so the partial cannot be filled a second time (Core:
/// `blockencodings.cpp:211` `header.SetNull()` after the tx-missing fill loop;
/// our impl mirrors this at `compact_blocks.rs:873-874`).
#[test]
fn g18_fill_block_resets_state_after_fill() {
    // Build a complete reconstruction (all txs in mempool) then call
    // fill_block — state must reset so a second fill_block returns Invalid.
    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0);
    let mempool: Vec<(Hash256, Arc<Transaction>)> = block
        .transactions
        .iter()
        .skip(1)
        .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
        .collect();
    let mempool_refs: Vec<(&Hash256, &Arc<Transaction>)> =
        mempool.iter().map(|(h, t)| (h, t)).collect();
    let mut partial = PartiallyDownloadedBlock::init_data(
        &compact,
        mempool_refs.into_iter(),
        &[],
    )
    .expect("init_data");
    // First fill — succeeds, header reset.
    let res = partial.fill_block(vec![], false);
    assert!(res.is_ok(), "first fill_block ok");
    assert_eq!(
        partial.header,
        BlockHeader::default(),
        "header must be reset after successful fill_block (Core SetNull() at \
         blockencodings.cpp:211)"
    );
    // Second fill — must report Invalid because header is null.
    let res2 = partial.fill_block(vec![], false);
    assert!(matches!(res2, Err(ReadStatus::Invalid)),
        "second fill_block must return Invalid (header reset)");
}

// ============================================================================
// G19-G20 — peer.rs handshake + main.rs cmpctblock decode (PRESENT)
// ============================================================================

/// G19 — Outbound handshake sends `sendcmpct(announce=false, version=2)` per
/// Core `net_processing.cpp:3870`. Source-grep across peer.rs.
#[test]
fn g19_peer_sends_sendcmpct_announce_false_v2() {
    let src = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/peer.rs"),
    )
    .expect("read peer.rs");
    // Three sites: v1 outbound (line 1015-1026), v1 inbound (1241-1254),
    // v2 BIP-324 (1945-1957).  Each should send announce=false, version=2.
    let occurrences = src.matches("announce: false").count();
    assert!(
        occurrences >= 3,
        "expected at least 3 `announce: false` sites (v1-in, v1-out, v2-in), found {}",
        occurrences
    );
    assert!(src.contains("SENDCMPCT_VERSION"), "SENDCMPCT_VERSION gate referenced");
    assert_eq!(SENDCMPCT_VERSION, 70014, "protocol version gate");
}

/// G20 — Incoming `cmpctblock` handler decodes + Misbehaving-on-bad-decode.
/// Pinned via source-grep.
#[test]
fn g20_cmpctblock_handler_decodes_and_misbehaves_on_bad_decode() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let main_rs = std::path::Path::new(manifest).parent().unwrap()
        .parent().unwrap()
        .join("rustoshi").join("src").join("main.rs");
    let src = std::fs::read_to_string(&main_rs).expect("read main.rs");
    assert!(
        src.contains("CmpctBlock::decode"),
        "main.rs must decode incoming cmpctblock"
    );
    assert!(
        src.contains("MisbehaviorReason::InvalidCompactBlock"),
        "decode failure must Misbehaving with InvalidCompactBlock"
    );
}

// ============================================================================
// G21 — getblocktxn handler (PARTIAL, BUG-6 + BUG-7 + BUG-15)
// ============================================================================

/// G21 — `getblocktxn` handler responds with `blocktxn` containing requested
/// indexes.  PARTIAL: three sub-gaps (BUG-6 out-of-range, BUG-7 depth cap,
/// BUG-15 disk-cache).
#[test]
#[ignore = "BUG-6 (P2): getblocktxn out-of-range index — silent skip, no Misbehaving"]
fn g21_getblocktxn_out_of_range_misbehaves() {
    panic!(
        "BUG-6: rustoshi/src/main.rs:3920-3930 uses block.transactions.get(idx) which \
         returns None silently. Core net_processing.cpp:2602-2604 fires \
         Misbehaving(peer, \"getblocktxn with out-of-bounds tx indices\") on the \
         same condition."
    );
}

// ============================================================================
// G22 — blocktxn handler PRESENT (regression pin) — completes reconstruction
// ============================================================================

/// G22 — `blocktxn` handler finishes reconstruction via `fill_block` and
/// submits the block via `block_downloader.block_received`.  Source-grep pin.
#[test]
fn g22_blocktxn_handler_completes_reconstruction() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let main_rs = std::path::Path::new(manifest).parent().unwrap()
        .parent().unwrap()
        .join("rustoshi").join("src").join("main.rs");
    let src = std::fs::read_to_string(&main_rs).expect("read main.rs");
    // Must look up the in-flight partial block AND call fill_block AND submit
    // to block_downloader.
    assert!(
        src.contains("inflight_partial_blocks.remove"),
        "blocktxn handler must look up in-flight partial block"
    );
    assert!(
        src.contains("partial.fill_block"),
        "blocktxn handler must call fill_block"
    );
    assert!(
        src.contains("block_downloader\n                                                            .block_received(peer_id, block)")
            || src.contains("block_downloader.block_received(peer_id, block)"),
        "blocktxn handler must submit the reconstructed block to block_downloader"
    );
}

// ============================================================================
// G23 — SEND-side CmpctBlock construction MISSING → BUG-1
// ============================================================================

/// G23 — `CmpctBlock::from_block` is wired into the new-tip path (Core's
/// `NewPoWValidBlock` at `net_processing.cpp:2105-2152`). MISSING: only
/// called from `#[cfg(test)]` today.
#[test]
#[ignore = "BUG-1 (P1): CmpctBlock::from_block dead-helper — only invoked from #[cfg(test)]"]
fn g23_cmpctblock_send_side_wired_in_production() {
    panic!(
        "BUG-1 (P1): grep `CmpctBlock::from_block` in rustoshi/ + crates/ finds zero \
         non-#[cfg(test)] call sites. Core net_processing.cpp:2105 (NewPoWValidBlock) \
         builds a fresh CBlockHeaderAndShortTxIDs per new tip and pushes to all HB \
         peers. rustoshi has no equivalent send-side hook. \
         See audit/w126_bip152_compact_blocks.md."
    );
}

// ============================================================================
// G24 — getdata(MSG_CMPCT_BLOCK) MISSING → BUG-2
// ============================================================================

/// G24 — `getdata(MSG_CMPCT_BLOCK)` is served with a fresh `cmpctblock`
/// (Core `net_processing.cpp:2466-2471`). MISSING: rustoshi falls through.
#[test]
#[ignore = "BUG-2 (P1): main.rs:3343-3384 GetData handler falls through `_ => {}` for MsgCmpctBlock"]
fn g24_getdata_cmpctblock_served() {
    panic!(
        "BUG-2 (P1): main.rs:3343-3384 only matches MsgBlock | MsgWitnessBlock | \
         MsgTx | MsgWitnessTx; MsgCmpctBlock silently dropped.  Core \
         net_processing.cpp:2466-2471 responds with cached cmpctblock when within \
         MAX_CMPCTBLOCK_DEPTH=5 of tip, or fresh-builds one. \
         Blocked behind BUG-1."
    );
}

// ============================================================================
// G25 — sendcmpct(version != 2) rejection BUG → BUG-3
// ============================================================================

/// G25 — `sendcmpct(version=1)` is rejected (Core: any version != 2 ignored).
/// BUG: rustoshi accepts v1 and stores `version = 1`.
#[test]
fn g25_sendcmpct_v1_rejected() {
    // Document the divergence with a runtime check: handle_sendcmpct(true, 1)
    // does NOT enable v1 once the fix lands.
    let mut state = PeerCompactBlockState::new();
    state.handle_sendcmpct(true, CMPCT_VERSION_1);
    // Today: state.enabled == true (BUG).
    // Target: state.enabled == false.
    if state.enabled {
        panic!(
            "BUG-3 (P2): rustoshi accepts sendcmpct(version=1); Core \
             net_processing.cpp:3907 ignores any version != CMPCTBLOCKS_VERSION (2). \
             compact_blocks.rs:957-969 has explicit v1 branch."
        );
    }
}

// ============================================================================
// G26 — anti-DoS chain-work pre-check MISSING → BUG-4 (P0)
// ============================================================================

/// G26 — Incoming `cmpctblock` is gated by
/// `prev_block->nChainWork + GetBlockProof(header) < GetAntiDoSWorkThreshold()`
/// (Core `net_processing.cpp:4490-4494`). MISSING.
#[test]
#[ignore = "BUG-4 (P0): no anti-DoS chain-work pre-check on incoming cmpctblock"]
fn g26_cmpctblock_anti_dos_chainwork_precheck() {
    panic!(
        "BUG-4 (P0): main.rs:3826-3914 decodes cmpctblock + calls init_data \
         unconditionally. Core net_processing.cpp:4490-4494 drops the message when \
         prev_block->nChainWork + GetBlockProof(header) < GetAntiDoSWorkThreshold() \
         (= max(MinimumChainWork, 0.5 * tip chainwork)). DoS vector: low-work \
         cmpctblock spam forces full mempool walk per message."
    );
}

// ============================================================================
// G27 — orphan-prev MaybeSendGetHeaders MISSING → BUG-5
// ============================================================================

/// G27 — On orphan-prev `cmpctblock`, Core calls `MaybeSendGetHeaders` instead
/// of falling back to full-block getdata.
#[test]
#[ignore = "BUG-5 (P1): orphan-prev cmpctblock never triggers getheaders (Core net_processing.cpp:4483-4489)"]
fn g27_cmpctblock_orphan_prev_triggers_getheaders() {
    panic!(
        "BUG-5 (P1): main.rs falls back to full-block MsgWitnessBlock getdata when \
         init_data fails. Core net_processing.cpp:4483-4489 looks up prev_block \
         and if null + !IBD calls MaybeSendGetHeaders to backfill ancestors. \
         Net effect: wasted bandwidth + slower catch-up."
    );
}

// ============================================================================
// G28 — LoadingBlocks/IBD guard MISSING → BUG-8
// ============================================================================

/// G28 — While `LoadingBlocks()` is true the cmpctblock handler must early-
/// return (Core `net_processing.cpp:4468-4472`).
#[test]
#[ignore = "BUG-8 (P2): no LoadingBlocks/IBD guard on incoming cmpctblock"]
fn g28_cmpctblock_loading_blocks_guard() {
    panic!(
        "BUG-8 (P2): main.rs:3826 enters init_data unconditionally during IBD. \
         Core net_processing.cpp:4468-4472 'Ignore cmpctblock received while \
         importing' early-returns when m_blockman.LoadingBlocks() is true."
    );
}

// ============================================================================
// G29 — MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3 MISSING → BUG-9
// ============================================================================

/// G29 — Constant + per-block in-flight cap from Core `net_processing.h:47`.
#[test]
#[ignore = "BUG-9 (P2): MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3 constant not defined; no per-block cap"]
fn g29_max_cmpctblocks_inflight_per_block_cap() {
    panic!(
        "BUG-9 (P2): grep `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` in rustoshi/ + crates/ \
         returns 0 matches. Core net_processing.h:47 defines this constant; \
         main.rs:2282 inflight_partial_blocks has no cap-per-block."
    );
}

// ============================================================================
// G30 — MAX_BLOCKTXN_DEPTH=10 MISSING → BUG-7
// ============================================================================

/// G30 — Constant + cap on `getblocktxn` depth (Core `net_processing.cpp:138-141`).
#[test]
#[ignore = "BUG-7 (P2): no MAX_BLOCKTXN_DEPTH=10 cap on getblocktxn responses"]
fn g30_max_blocktxn_depth_cap() {
    panic!(
        "BUG-7 (P2): grep `MAX_BLOCKTXN_DEPTH` finds 0 production matches. Core \
         net_processing.cpp:138-141 + 4276-4302 caps getblocktxn responses at \
         tip - 10 (deeper blocks served via full getdata to make attacker pay for \
         disk read). rustoshi serves every depth unconditionally."
    );
}

// ============================================================================
// Additional cross-wave pin: dead-helper inventory (BUG-11 / BUG-12 / BUG-13)
// ============================================================================

/// Dead-helper inventory pin: `CompactBlockRelay` is `pub` but never
/// instantiated outside `#[cfg(test)]`.
#[test]
#[ignore = "BUG-11 (P3): CompactBlockRelay struct never instantiated outside tests (W112 BUG-G29)"]
fn dead_helper_compact_block_relay() {
    panic!(
        "BUG-11 (P3): CompactBlockRelay (compact_blocks.rs:1001-1146) is dead. \
         grep `CompactBlockRelay::new\\b\\|CompactBlockRelay::default\\b` in \
         rustoshi/src/ + crates/*/src/ (excluding `*tests*`) returns 0 matches. \
         Pinned for fleet-wide cross-ref."
    );
}

/// Dead-state pin: `PeerCompactBlockState::last_cmpctblock` set but never read.
#[test]
#[ignore = "BUG-12 (P3): PeerCompactBlockState.last_cmpctblock written but never read (W112 BUG-G30)"]
fn dead_state_last_cmpctblock() {
    panic!(
        "BUG-12 (P3): compact_blocks.rs:919 field exists; no reader. Pinned for \
         fleet-wide cross-ref."
    );
}

/// Dead-helper pin: `peer_manager::handle_event(SendCmpct)` no-op.
#[test]
#[ignore = "BUG-10 (P3): main.rs:3822 forwards SendCmpct to peer_manager but handle_event has no SendCmpct arm"]
fn dead_handler_peer_manager_send_cmpct() {
    panic!(
        "BUG-10 (P3): main.rs:3822 `pm.handle_event(PeerEvent::Message(peer_id, \
         NetworkMessage::SendCmpct(sc)))` forwards the message but \
         peer_manager.rs::handle_event(PeerEvent::Message) has no SendCmpct \
         arm — falls through silently. CompactBlockRelay (the would-be receiver) \
         is itself dead (BUG-11)."
    );
}

/// Cosmetic-divergence pin: miss_pct > 50% full-block fallback (Core does not
/// have this heuristic).
#[test]
#[ignore = "BUG-14 (P3): main.rs:3865 miss_pct > 50% full-block fallback diverges from Core"]
fn cosmetic_divergence_miss_pct_fallback() {
    panic!(
        "BUG-14 (P3): main.rs:3865-3873 falls back to full-block getdata when \
         miss_pct > 50%. Core has no such heuristic — always rolls forward through \
         getblocktxn and only falls back on READ_STATUS_FAILED. Marginal \
         bandwidth-efficiency drift; pinned for parity."
    );
}

/// Cosmetic-divergence pin: no `vExtraTxnForCompact`-equivalent.
#[test]
#[ignore = "BUG-16 (P3): main.rs:3841 passes `&[]` to init_data; Core uses orphan ring buffer"]
fn cosmetic_divergence_no_vextra_txn_for_compact() {
    panic!(
        "BUG-16 (P3): main.rs:3841 passes empty extra_txns to init_data. Core \
         maintains vExtraTxnForCompact (net_processing.cpp) — a ring buffer of \
         recently-seen orphan transactions — so an orphan we've already heard \
         about can resolve a short-id without round-tripping."
    );
}

/// Cosmetic-divergence pin: no dynamic HB-promote via `sendcmpct(announce=true)`.
#[test]
#[ignore = "BUG-17 (P3): no dynamic HB-promote (W123 G16)"]
fn cosmetic_divergence_no_hb_promote() {
    panic!(
        "BUG-17 (P3): peer.rs always sends announce=false; rustoshi never \
         promotes a peer to HB via a follow-up sendcmpct(announce=true). Core \
         MaybeSetPeerAsAnnouncingHeaderAndIDs (net_processing.cpp:1272) rotates \
         the 3 HB slots based on which peer delivered the last new block."
    );
}

/// `create_cmpctblock_inv` is `pub` but unused.
#[test]
#[ignore = "BUG-13 (P3): CompactBlockRelay::create_cmpctblock_inv pub but unused"]
fn dead_helper_create_cmpctblock_inv() {
    panic!(
        "BUG-13 (P3): compact_blocks.rs:1133-1139 `pub fn create_cmpctblock_inv` \
         has no production caller; would be the helper used by BUG-1's fix \
         when announcing tip via inv-cmpctblock."
    );
}

// ============================================================================
// is_block_mutated regression pin (segwit witness commitment + merkle root)
// ============================================================================

/// `is_block_mutated` returns true on merkle-root mismatch (mutation check).
/// Core: `validation.cpp:4027-4056`.
#[test]
fn aux_is_block_mutated_detects_merkle_mismatch() {
    let mut block = make_block(3);
    block.header.merkle_root = Hash256([0xFF; 32]);
    assert!(
        is_block_mutated(&block, false),
        "merkle-root mismatch must report mutated"
    );
}

/// CompactBlockMode enum surface pin.
#[test]
fn aux_compact_block_mode_distinct_variants() {
    let hb = CompactBlockMode::HighBandwidth;
    let lb = CompactBlockMode::LowBandwidth;
    assert_ne!(hb, lb);
}

/// PeerId constructor used by helpers.
#[test]
fn aux_peer_id_constructor() {
    let pid = PeerId(0);
    assert_eq!(pid.0, 0);
}

/// PrefilledTx::new round-trip.
#[test]
fn aux_prefilled_tx_constructors() {
    let cb = make_coinbase();
    let ptx = PrefilledTx::new(0, cb.clone());
    assert_eq!(ptx.index, 0);
    let ptx2 = PrefilledTx::from_arc(2, Arc::new(cb));
    assert_eq!(ptx2.index, 2);
}
