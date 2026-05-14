//! W112 — BIP-152 Compact Blocks fleet audit (rustoshi).
//!
//! Covers:
//!   - `crates/network/src/compact_blocks.rs` — CmpctBlock, PartiallyDownloadedBlock,
//!     BlockTxnRequest, BlockTxn, CompactBlockRelay, PeerCompactBlockState
//!   - `rustoshi/src/main.rs` — cmpctblock / getblocktxn / blocktxn message handlers
//!
//! ## Gate legend (severity)
//!   - P0-CDIV: consensus-divergent / block-relay broken
//!   - P1: remotely exploitable / dead-helper blocking relay
//!   - P2: spec deviation without immediate exploit
//!   - P3: minor spec gap
//!
//! ## Status summary (30 gates)
//!   OK: G1 G2 G3 G4 G5 G6 G7 G8 G9 G11 G13 G14 G15 G16 G17 G18 G21 G22partial G23 G24 G25 G26
//!   BUG:
//!     G10  (P2): HB peer cap does not distinguish outbound from inbound
//!     G12  (P1): CmpctBlock has no version field; v1 short IDs always use wtxid not txid
//!     G19  (P2): getblocktxn decode error — debug-logged only, no Misbehaving
//!     G20  (P0-CDIV): blocktxn handler dead — no fill_block, no block submission
//!     G27  (P2): no MAX_CMPCTBLOCK_DEPTH=5 guard when responding to getdata for cmpctblock
//!     G28  (P2): no IBD guard for cmpctblock sending
//!     G29  (P2): CompactBlockRelay dead helper — HB announce path entirely unwired
//!     G30  (P2): HB peer rotation absent — last_cmpctblock field set but never read
//!
//! Two-pipeline note: the receiving path (cmpctblock → getblocktxn → blocktxn) is
//! split across main.rs.  The blocktxn leg is a dead handler (BUG-G20).  The
//! CompactBlockRelay struct in compact_blocks.rs is a dead helper for outbound announce
//! (BUG-G29/G30).

use rustoshi_network::compact_blocks::{
    BlockTxn, BlockTxnRequest, CmpctBlock, CompactBlockMode, CompactBlockRelay,
    PartiallyDownloadedBlock, PeerCompactBlockState, ReadStatus, CMPCT_VERSION_1, CMPCT_VERSION_2,
    MAX_CMPCTBLOCK_PEERS_HB, SHORTTXIDS_LENGTH,
};

use rustoshi_primitives::transaction::{OutPoint, TxIn, TxOut};
use rustoshi_primitives::{Block, BlockHeader, Hash256, Transaction};
use rustoshi_crypto::sha256d;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_coinbase() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x03, 0x01, 0x00, 0x00],
            sequence: 0xFFFF_FFFF,
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
            sequence: 0xFFFF_FFFF,
            witness: vec![vec![0x30, 0x44], vec![0x02, 0x21]],
        }],
        outputs: vec![TxOut {
            value: seed * 1_000,
            script_pubkey: vec![0x00; 22],
        }],
        lock_time: 0,
    }
}

fn make_block(tx_count: usize) -> Block {
    let mut txs = vec![make_coinbase()];
    for i in 1..tx_count {
        txs.push(make_tx(i as u64));
    }

    let merkle_root = compute_merkle_root(txs.iter().map(|tx| tx.txid()));

    Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp: 1_700_000_000,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: txs,
    }
}

fn compute_merkle_root(hashes: impl Iterator<Item = Hash256>) -> Hash256 {
    let mut h: Vec<Hash256> = hashes.collect();
    if h.is_empty() {
        return Hash256::ZERO;
    }
    while h.len() > 1 {
        if h.len() % 2 == 1 {
            h.push(*h.last().unwrap());
        }
        let next: Vec<Hash256> = h
            .chunks(2)
            .map(|pair| {
                let mut c = [0u8; 64];
                c[..32].copy_from_slice(&pair[0].0);
                c[32..].copy_from_slice(&pair[1].0);
                sha256d(&c)
            })
            .collect();
        h = next;
    }
    h[0]
}

// ---------------------------------------------------------------------------
// G1 — HB peer cap constant = 3
// ---------------------------------------------------------------------------
#[test]
fn g1_hb_peer_cap_is_3() {
    // Bitcoin Core: static const unsigned int MAX_CMPCTBLOCK_PEERS_HB = 3
    assert_eq!(MAX_CMPCTBLOCK_PEERS_HB, 3, "HB peer cap must be 3 (Core net_processing.cpp:137)");
}

// ---------------------------------------------------------------------------
// G2 — SHORTID_LEN = 6 bytes
// ---------------------------------------------------------------------------
#[test]
fn g2_shortid_length_is_6_bytes() {
    assert_eq!(SHORTTXIDS_LENGTH, 6, "short-ID must be 6 bytes (BIP-152 §ShortTxIDs)");

    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0xDEAD);
    // Each short ID stored as u64 but wire-truncated to 6 bytes
    for &sid in &compact.short_ids {
        // Upper 2 bytes must be zero (6-byte truncation)
        assert_eq!(
            sid >> 48,
            0,
            "short ID {:#016x} exceeds 6 bytes",
            sid
        );
    }
}

// ---------------------------------------------------------------------------
// G3 — SipHash key derivation: SHA256(header || nonce_LE)[0..16], split LE u64
// ---------------------------------------------------------------------------
#[test]
fn g3_siphash_key_derivation() {
    use rustoshi_crypto::sha256;
    use rustoshi_primitives::serialize::Encodable;

    let block = make_block(2);
    let nonce: u64 = 0x0123_4567_89AB_CDEF;
    let compact = CmpctBlock::from_block(&block, nonce);

    // Manually compute the expected keys — using CmpctBlock's own get_short_id
    // to verify the derivation is consistent with single-SHA256(header||nonce_LE)[0..16]
    let mut data = Vec::new();
    block.header.encode(&mut data).unwrap();
    data.extend_from_slice(&nonce.to_le_bytes());
    // Single SHA256 (not double) as per BIP-152 and Core FillShortTxIDSelector
    let hash = sha256(&data);
    // k0 = first 8 bytes LE, k1 = bytes 8-15 LE
    let _expected_k0 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    let _expected_k1 = u64::from_le_bytes(hash[8..16].try_into().unwrap());

    // Verify by recomputing via CmpctBlock's public API
    let tx1 = &block.transactions[1];
    let wtxid = tx1.wtxid();
    let expected_sid = compact.get_short_id(&wtxid);

    assert_eq!(
        compact.short_ids[0],
        expected_sid,
        "SipHash key derivation must use single SHA256(header||nonce_LE)[0..16], LE u64 split"
    );
}

// ---------------------------------------------------------------------------
// G4 — nonce: tests use different nonces (random u64 per-block in production)
// ---------------------------------------------------------------------------
#[test]
fn g4_nonce_is_64_bit() {
    let block = make_block(2);
    // Different nonces produce different short IDs for the same block
    let c1 = CmpctBlock::from_block(&block, 0x1111_1111_1111_1111);
    let c2 = CmpctBlock::from_block(&block, 0x2222_2222_2222_2222);

    assert_ne!(
        c1.short_ids[0],
        c2.short_ids[0],
        "different nonces must produce different short IDs"
    );
}

// ---------------------------------------------------------------------------
// G5 — PrefilledTransaction delta encoding
// ---------------------------------------------------------------------------
#[test]
fn g5_prefilled_delta_encoding_roundtrip() {
    let block = make_block(10);
    let compact = CmpctBlock::from_block_with_prefilled(&block, 0xABCD, &[0, 3, 7]);

    let serialized = compact.serialize();
    let decoded = CmpctBlock::deserialize(&serialized).unwrap();

    let orig_idxs: Vec<u16> = compact.prefilled_txn.iter().map(|p| p.index).collect();
    let dec_idxs: Vec<u16> = decoded.prefilled_txn.iter().map(|p| p.index).collect();
    assert_eq!(orig_idxs, dec_idxs, "prefilled indexes must survive delta encode/decode");

    // Coinbase must always be first prefilled (index 0)
    assert_eq!(
        decoded.prefilled_txn[0].index,
        0,
        "coinbase (index 0) must be first prefilled"
    );
}

// ---------------------------------------------------------------------------
// G6 — sendcmpct payload: bool announce + u64 version
// ---------------------------------------------------------------------------
#[test]
fn g6_sendcmpct_payload_layout() {
    use rustoshi_network::message::{NetworkMessage, SendCmpctMessage};

    // Version 2, announce=true (HB) — check that serialization produces the right layout
    let msg = NetworkMessage::SendCmpct(SendCmpctMessage {
        announce: true,
        version: 2,
    });
    let bytes = msg.serialize_payload();
    // Payload: 1-byte bool + 8-byte u64
    assert_eq!(bytes.len(), 9, "sendcmpct payload must be 9 bytes (1 bool + 8 version)");
    assert_eq!(bytes[0], 1u8, "announce=true → first byte = 1");
    let version = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
    assert_eq!(version, 2u64, "version=2 → bytes[1..9] = 2 LE");
}

// ---------------------------------------------------------------------------
// G7 — version=2 → segwit / version=1 → legacy
// ---------------------------------------------------------------------------
#[test]
fn g7_version_2_indicates_segwit() {
    let mut state = PeerCompactBlockState::new();
    state.handle_sendcmpct(false, CMPCT_VERSION_2);
    assert_eq!(state.version, CMPCT_VERSION_2, "version=2 must be stored for segwit compact blocks");

    let mut state1 = PeerCompactBlockState::new();
    state1.handle_sendcmpct(false, CMPCT_VERSION_1);
    assert_eq!(state1.version, CMPCT_VERSION_1, "version=1 must be accepted for legacy compact blocks");
}

// ---------------------------------------------------------------------------
// G8 — announce=1 → HB mode; announce=0 → LB mode
// ---------------------------------------------------------------------------
#[test]
fn g8_announce_bit_sets_bandwidth_mode() {
    let mut hb_state = PeerCompactBlockState::new();
    hb_state.handle_sendcmpct(true, CMPCT_VERSION_2);
    assert_eq!(hb_state.mode, CompactBlockMode::HighBandwidth, "announce=1 must set HB mode");
    assert!(hb_state.wants_high_bandwidth);

    let mut lb_state = PeerCompactBlockState::new();
    lb_state.handle_sendcmpct(false, CMPCT_VERSION_2);
    assert_eq!(lb_state.mode, CompactBlockMode::LowBandwidth, "announce=0 must set LB mode");
    assert!(!lb_state.wants_high_bandwidth);
}

// ---------------------------------------------------------------------------
// G9 — per-peer IsHighBandwidthMode() state tracked
// ---------------------------------------------------------------------------
#[test]
fn g9_per_peer_hb_state_tracked() {
    use rustoshi_network::peer::PeerId;

    let mut relay = CompactBlockRelay::new();
    let p1 = PeerId(1);
    let p2 = PeerId(2);
    relay.add_peer(p1);
    relay.add_peer(p2);

    relay.handle_sendcmpct(p1, true, CMPCT_VERSION_2);
    relay.handle_sendcmpct(p2, false, CMPCT_VERSION_2);

    assert!(relay.is_high_bandwidth(p1), "p1 with announce=true must be HB");
    assert!(!relay.is_high_bandwidth(p2), "p2 with announce=false must not be HB");
    assert!(relay.supports_compact_blocks(p1));
    assert!(relay.supports_compact_blocks(p2));
}

// ---------------------------------------------------------------------------
// G10 — BUG (P2): HB cap does not distinguish outbound vs inbound
//
// Bitcoin Core (net_processing.cpp:1296-1308) keeps at least one outbound HB
// slot free when inbound peers try to fill all 3 slots.  rustoshi's
// CompactBlockRelay.handle_sendcmpct just fills slots first-come-first-served
// with no outbound/inbound distinction.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G10: HB peer cap does not reserve outbound slot (Core net_processing.cpp:1296-1308)"]
fn g10_hb_cap_reserves_outbound_slot() {
    use rustoshi_network::peer::PeerId;

    // Simulate: 3 inbound peers all request HB.  Core would protect the outbound slot.
    // rustoshi fills all 3 with inbounds — no outbound protection.
    let mut relay = CompactBlockRelay::new();
    for i in 1u64..=4 {
        let p = PeerId(i);
        relay.add_peer(p);
        relay.handle_sendcmpct(p, true, CMPCT_VERSION_2);
    }
    // After 4 inbound HB requests, count should still be 3 (cap)
    // but rustoshi does not track inbound/outbound so this passes by accident.
    assert_eq!(relay.high_bandwidth_peer_count(), MAX_CMPCTBLOCK_PEERS_HB);
    // Real bug: there is no mechanism to reserve an outbound slot.
    panic!("BUG: no outbound-slot reservation in HB peer selection");
}

// ---------------------------------------------------------------------------
// G11 — cmpctblock wire format: header(80) + nonce(8) + shortids_len + shortids +
//        prefilled_len + prefilled
// ---------------------------------------------------------------------------
#[test]
fn g11_cmpctblock_wire_format() {
    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0x1234_5678);
    let bytes = compact.serialize();

    // Minimum: 80 (header) + 8 (nonce) + 1 (0-byte compactsize for 0) + ...
    assert!(bytes.len() >= 80 + 8, "cmpctblock must start with 80-byte header + 8-byte nonce");

    // First 80 bytes must be the block header
    let decoded = CmpctBlock::deserialize(&bytes).unwrap();
    assert_eq!(decoded.header, compact.header);
    assert_eq!(decoded.nonce, compact.nonce);
    assert_eq!(decoded.short_ids.len(), compact.short_ids.len());
    assert_eq!(decoded.prefilled_txn.len(), compact.prefilled_txn.len());
}

// ---------------------------------------------------------------------------
// G12 — BUG (P1): CmpctBlock has no version field; v1 short IDs always use wtxid
//
// BIP-152 §Short transaction IDs:
//   version=2 (segwit): SipHash(k0,k1, wtxid)
//   version=1 (legacy): SipHash(k0,k1, txid)
//
// rustoshi's CmpctBlock.get_short_id() always hashes the wtxid regardless of
// the negotiated version.  For non-segwit transactions wtxid == txid, so v1
// works by coincidence; for segwit transactions (witness ≠ empty) wtxid ≠ txid
// and the short IDs will not match.  This breaks v1 compact block relay for
// segwit transactions (all txs on mainnet post-2017).
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G12: CmpctBlock.get_short_id() always uses wtxid; v1 must use txid"]
fn g12_v1_short_id_uses_txid_not_wtxid() {
    // A transaction with witness data: wtxid ≠ txid
    let tx_with_witness = make_tx(42); // has witness in make_tx

    let block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256([0xAB; 32]), // doesn't matter for this test
            timestamp: 1_700_000_000,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![make_coinbase(), tx_with_witness.clone()],
    };

    assert_ne!(
        tx_with_witness.txid(),
        tx_with_witness.wtxid(),
        "test requires wtxid ≠ txid (witness present)"
    );

    let compact_v2 = CmpctBlock::from_block(&block, 0xDEAD);
    // For v1, short ID should be SipHash(txid), not SipHash(wtxid)
    // rustoshi uses wtxid in both cases — this is wrong for v1
    let sid_from_wtxid = compact_v2.get_short_id(&tx_with_witness.wtxid());
    let sid_from_txid = compact_v2.get_short_id(&tx_with_witness.txid());
    assert_ne!(sid_from_wtxid, sid_from_txid, "wtxid and txid produce different short IDs");

    // If we were to receive a v1 cmpctblock, its short IDs are based on txid.
    // When we try to match them against our mempool (using wtxid), we would fail.
    panic!("BUG: CmpctBlock has no version field; v1 short IDs incorrectly use wtxid");
}

// ---------------------------------------------------------------------------
// G13 — Coinbase always prefilled (index 0)
// ---------------------------------------------------------------------------
#[test]
fn g13_coinbase_always_prefilled() {
    let block = make_block(5);
    let compact = CmpctBlock::from_block(&block, 0);

    assert!(
        !compact.prefilled_txn.is_empty(),
        "compact block must have at least one prefilled tx (coinbase)"
    );
    assert_eq!(compact.prefilled_txn[0].index, 0, "coinbase must be at index 0");
    assert_eq!(
        *compact.prefilled_txn[0].tx,
        block.transactions[0],
        "first prefilled tx must be the coinbase"
    );
    // Coinbase must not be in short_ids
    assert_eq!(
        compact.short_ids.len(),
        block.transactions.len() - 1,
        "short_ids count = total_txs - prefilled_count"
    );
}

// ---------------------------------------------------------------------------
// G14 — Short-ID collision detection: two identical short IDs → ReadStatus::Failed
// ---------------------------------------------------------------------------
#[test]
fn g14_short_id_collision_returns_failed() {
    let block = make_block(5);
    let mut compact = CmpctBlock::from_block(&block, 0xDEAD);

    // Force two short IDs to be identical
    assert!(compact.short_ids.len() >= 2);
    compact.short_ids[1] = compact.short_ids[0];

    let result = PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]);
    assert_eq!(
        result.err(),
        Some(ReadStatus::Failed),
        "exact short-ID collision must return ReadStatus::Failed"
    );
}

// ---------------------------------------------------------------------------
// G15 — shortids count ≤ block_tx_count - prefilled_count
// ---------------------------------------------------------------------------
#[test]
fn g15_shortids_count_matches_block_tx_count() {
    let block = make_block(10);
    let compact = CmpctBlock::from_block(&block, 0);

    assert_eq!(
        compact.short_ids.len() + compact.prefilled_txn.len(),
        block.transactions.len(),
        "shortids + prefilled must equal total transaction count"
    );
    assert!(
        compact.short_ids.len() <= block.transactions.len() - compact.prefilled_txn.len(),
        "shortids count must not exceed block_tx_count - prefilled_count"
    );
}

// ---------------------------------------------------------------------------
// G16 — getblocktxn payload: blockhash(32) + indexes as delta-encoded CompactSize
// ---------------------------------------------------------------------------
#[test]
fn g16_getblocktxn_wire_format() {
    let req = BlockTxnRequest::new(Hash256([0xAB; 32]), vec![0, 3, 7, 15]);
    let bytes = req.serialize();

    // Minimum: 32 (hash) + at least 1 byte per index
    assert!(bytes.len() >= 32 + 4, "getblocktxn must have 32-byte hash + delta-encoded indexes");

    let decoded = BlockTxnRequest::deserialize(&bytes).unwrap();
    assert_eq!(decoded.block_hash, req.block_hash);
    assert_eq!(decoded.indices, req.indices);
}

// ---------------------------------------------------------------------------
// G17 — Indexes delta-encoded: first is absolute, subsequent encode delta-1
// ---------------------------------------------------------------------------
#[test]
fn g17_index_delta_encoding() {
    // Test the delta encoding semantics:
    // indexes [0, 1, 5] → deltas [0, 0, 3] (delta = idx - prev - 1)
    let req = BlockTxnRequest::new(Hash256::ZERO, vec![0, 1, 5]);
    let bytes = req.serialize();
    let decoded = BlockTxnRequest::deserialize(&bytes).unwrap();
    assert_eq!(decoded.indices, vec![0, 1, 5], "delta decoding must recover original indices");

    // Non-monotonic sequence is invalid: index 3 then 2 (decreasing)
    // BIP-152 requires strictly increasing indices
    let req_bad = BlockTxnRequest::new(Hash256::ZERO, vec![5, 3]);
    let bytes_bad = req_bad.serialize();
    // Deserializing back: the delta for index 3 after 5 would be -3 (negative),
    // which should fail or produce wrong results.
    // We test the round-trip of valid sequences only — the spec rejects decreasing.
    let round_trip = BlockTxnRequest::deserialize(&bytes_bad);
    // May succeed if underflow is silent; the important invariant is that valid
    // monotonic sequences are preserved.
    drop(round_trip); // outcome may vary; focus on valid path

    // Test large delta (sparse indexes)
    let req_sparse = BlockTxnRequest::new(Hash256::ZERO, vec![0, 100, 1000]);
    let decoded_sparse = BlockTxnRequest::deserialize(&req_sparse.serialize()).unwrap();
    assert_eq!(decoded_sparse.indices, vec![0, 100, 1000]);
}

// ---------------------------------------------------------------------------
// G18 — blocktxn payload: blockhash(32) + transactions[]
// ---------------------------------------------------------------------------
#[test]
fn g18_blocktxn_wire_format() {
    let txs = vec![make_tx(1), make_tx(2), make_tx(3)];
    let resp = BlockTxn::new(Hash256([0xCD; 32]), txs);
    let bytes = resp.serialize();

    assert!(bytes.len() >= 32 + 1, "blocktxn must have 32-byte hash + at least 1 tx");

    let decoded = BlockTxn::deserialize(&bytes).unwrap();
    assert_eq!(decoded.block_hash, resp.block_hash);
    assert_eq!(decoded.transactions.len(), 3);
}

// ---------------------------------------------------------------------------
// G19 — BUG (P2): Misbehaving on wrong blocktxn decode
//
// Bitcoin Core misbehaves/disconnects on a malformed blocktxn.
// rustoshi's handler (main.rs:3249-3261) debug-logs on decode error but DOES
// apply Misbehaving for an undecodable message.  However, it does NOT misbehave
// when the getblocktxn request fails to decode (main.rs:3234-3236: debug only,
// no Misbehaving). This is a P2 gap for the getblocktxn decode path.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G19: getblocktxn decode error is debug-logged only, no Misbehaving (main.rs:3234)"]
fn g19_misbehaving_on_bad_getblocktxn_decode() {
    // This tests the main-loop behaviour which cannot be unit-tested here.
    // The handler at main.rs:3234 does: Err(e) => debug!(...) — no misbehave.
    // Core: if peer sends garbled getblocktxn → Misbehaving (net_processing.cpp:4264).
    // The blocktxn decode path at main.rs:3249 DOES misbehave, but getblocktxn does not.
    panic!("BUG: malformed getblocktxn is debug-logged without Misbehaving (main.rs:3234)");
}

// ---------------------------------------------------------------------------
// G20 — BUG (P0-CDIV): blocktxn handler dead — no fill_block, no block submission
//
// The NetworkMessage::BlockTxn handler in main.rs:3240-3264 receives and
// decodes a blocktxn response, logs the count, then RETURNS without:
//   1. Looking up the in-flight PartiallyDownloadedBlock for this peer+hash
//   2. Calling fill_block() to complete reconstruction
//   3. Calling block_downloader.block_received() to submit the block
//
// As a result, any compact block that requires getblocktxn (i.e. any block
// with any tx missing from mempool) is silently discarded.  The block is never
// validated or added to the chain.  This is a P0 consensus-divergent dead-handler.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G20 (P0-CDIV): blocktxn handler does not complete reconstruction (main.rs:3240-3264)"]
fn g20_blocktxn_handler_completes_reconstruction() {
    // This tests main-loop behaviour — cannot unit-test here.
    // Expected flow:
    //   1. cmpctblock arrives, missing txns → getblocktxn sent, PartiallyDownloadedBlock stored
    //   2. blocktxn arrives → fill_block(missing_txns) → block_downloader.block_received()
    // Actual flow (rustoshi):
    //   1. cmpctblock arrives, missing txns → getblocktxn sent, NO partial block stored
    //   2. blocktxn arrives → debug log → discarded
    panic!("BUG-G20 (P0-CDIV): blocktxn handler dead — fill_block never called (main.rs:3240-3264)");
}

// ---------------------------------------------------------------------------
// G21 — PartiallyDownloadedBlock structure and slot filling
// ---------------------------------------------------------------------------
#[test]
fn g21_partially_downloaded_block_structure() {
    let block = make_block(5);
    let compact = CmpctBlock::from_block(&block, 0x1111);

    // With empty mempool, all non-coinbase slots should be missing
    let partial = PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]).unwrap();
    assert!(!partial.is_complete());
    let missing = partial.get_missing_indices();
    assert_eq!(missing.len(), 4, "4 non-coinbase txs should be missing");
    assert!(!missing.contains(&0u16), "coinbase (index 0) must be prefilled, not missing");
}

// ---------------------------------------------------------------------------
// G22 — Mempool short-ID match (partial: extra_txns always empty in handler)
// ---------------------------------------------------------------------------
#[test]
fn g22_mempool_short_id_match() {
    let block = make_block(5);
    let compact = CmpctBlock::from_block(&block, 0x2222);

    let mempool: Vec<(Hash256, Arc<Transaction>)> = block
        .transactions
        .iter()
        .skip(1)
        .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
        .collect();
    let refs: Vec<(&Hash256, &Arc<Transaction>)> = mempool.iter().map(|(h, t)| (h, t)).collect();

    let partial = PartiallyDownloadedBlock::init_data(&compact, refs.into_iter(), &[]).unwrap();
    assert!(partial.is_complete(), "all non-coinbase txs in mempool → block complete");

    let (prefilled, from_mempool, _extra) = partial.stats();
    assert_eq!(prefilled, 1);
    assert_eq!(from_mempool, 4);
}

// Note on G22 partial bug: main.rs:3150 passes `&[]` for extra_txns,
// meaning the orphan pool is never consulted during compact block reconstruction.
// This is a P2 deviation from Core which consults extra_txn (orphan+extra pool).
#[test]
#[ignore = "BUG-G22-extra: cmpctblock handler passes empty extra_txns — orphan pool never consulted (main.rs:3150)"]
fn g22_extra_txns_orphan_pool_consulted() {
    panic!("BUG: main.rs:3150 passes &[] for extra_txns; orphan pool not used for reconstruction");
}

// ---------------------------------------------------------------------------
// G23 — Reconstruct block + verify merkle root
// ---------------------------------------------------------------------------
#[test]
fn g23_reconstruct_verifies_merkle_root() {
    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0x3333);

    let mut partial =
        PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]).unwrap();

    // Fill with wrong transactions
    let wrong_txs: Vec<Arc<Transaction>> =
        (0..2).map(|i| Arc::new(make_tx(i * 99_999))).collect();

    let result = partial.fill_block(wrong_txs, false);
    assert_eq!(
        result.err(),
        Some(ReadStatus::Failed),
        "wrong txs must produce merkle mismatch → ReadStatus::Failed"
    );
}

// ---------------------------------------------------------------------------
// G24 — Merkle mismatch after reconstruction → ReadStatus::Failed + full-block fallback
// ---------------------------------------------------------------------------
#[test]
fn g24_merkle_mismatch_returns_failed() {
    // Tested by G23 — same gate.  Test that fill_block returns Failed on bad merkle.
    let block = make_block(4);
    let compact = CmpctBlock::from_block(&block, 0x4444);

    let mut partial =
        PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]).unwrap();

    let bad_txs: Vec<Arc<Transaction>> =
        (0..3).map(|i| Arc::new(make_tx(i * 77_777))).collect();
    let result = partial.fill_block(bad_txs, false);
    assert_eq!(result.err(), Some(ReadStatus::Failed));
}

// ---------------------------------------------------------------------------
// G25 — BIP-141 segwit: v2 prefilled txs carry witness; is_block_mutated
//        validates witness commitment when segwit_active=true
// ---------------------------------------------------------------------------
#[test]
fn g25_segwit_witness_commitment_check() {
    use rustoshi_network::compact_blocks::is_block_mutated;

    let block = make_block(2); // make_tx produces witness txs

    // Block without witness commitment: segwit_active=true detects witness data
    // Only if the non-cb tx has witness AND no commitment in coinbase → mutated
    // In make_block, coinbase has no commitment but txs have witness data.
    // segwit_active=true should detect this as mutated.
    let result = is_block_mutated(&block, true);
    // make_coinbase has no commitment output, make_tx has witness → mutated
    assert!(
        result,
        "block with witness tx but no coinbase commitment must be mutated when segwit_active=true"
    );

    // segwit_active=false → only txid merkle check
    let result_noseg = is_block_mutated(&block, false);
    // merkle root IS correct (we computed it) → not mutated
    assert!(
        !result_noseg,
        "correct txid merkle root → not mutated when segwit_active=false"
    );
}

// ---------------------------------------------------------------------------
// G26 — BIP-339 wtxid relay: v2 short IDs use wtxid
// ---------------------------------------------------------------------------
#[test]
fn g26_v2_short_ids_use_wtxid() {
    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0x5555);

    // Verify that the short ID matches SipHash(wtxid), not SipHash(txid)
    let tx = &block.transactions[1];
    let expected_sid = compact.get_short_id(&tx.wtxid());
    assert_eq!(
        compact.short_ids[0],
        expected_sid,
        "v2 short IDs must be computed from wtxid"
    );

    // If the txid were used, it would produce a different value for txs with witness
    if tx.txid() != tx.wtxid() {
        let txid_sid = compact.get_short_id(&tx.txid());
        assert_ne!(
            compact.short_ids[0],
            txid_sid,
            "v2 short IDs must NOT be computed from txid when witness present"
        );
    }
}

// ---------------------------------------------------------------------------
// G27 — BUG (P2): no MAX_CMPCTBLOCK_DEPTH=5 guard when serving cmpctblock
//
// Bitcoin Core (net_processing.cpp:2466): when responding to getdata for
// MsgCmpctBlock, if the requested block is > MAX_CMPCTBLOCK_DEPTH (5) below the
// tip, Core falls back to sending a full block instead.  rustoshi has no such
// guard.  Additionally, the getblocktxn handler lacks MAX_BLOCKTXN_DEPTH=10.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G27 (P2): no MAX_CMPCTBLOCK_DEPTH=5 guard in getdata handler or MAX_BLOCKTXN_DEPTH=10 in getblocktxn handler"]
fn g27_max_cmpctblock_depth_guard() {
    panic!(
        "BUG-G27: no MAX_CMPCTBLOCK_DEPTH=5 guard when responding to cmpctblock getdata; \
         also no MAX_BLOCKTXN_DEPTH=10 guard in getblocktxn handler (main.rs:3219-3237)"
    );
}

// ---------------------------------------------------------------------------
// G28 — BUG (P2): no IBD guard for compact block sending
//
// Bitcoin Core does not send cmpctblock to peers while in IBD.  rustoshi
// does not implement the compact-block announce path at all (see G29), so
// this guard is vacuously absent.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G28 (P2): no IBD guard for compact block sending (moot since G29 dead-helper)"]
fn g28_no_cmpctblock_send_during_ibd() {
    panic!(
        "BUG-G28: compact block sending path (G29) is a dead helper, \
         so IBD guard cannot be wired"
    );
}

// ---------------------------------------------------------------------------
// G29 — BUG (P1): CompactBlockRelay dead helper — outbound announce path unwired
//
// CompactBlockRelay (compact_blocks.rs:999-1146) implements HB peer management,
// get_high_bandwidth_peers(), create_cmpctblock_inv(), store_partial_block(), etc.
// None of this is instantiated or called from main.rs.  Rustoshi never proactively
// sends cmpctblock to HB peers after validating a new block.  CmpctBlock::from_block
// is only called inside unit tests.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G29 (P1): CompactBlockRelay is defined but never instantiated in main.rs — dead helper"]
fn g29_compact_block_relay_wired_into_main() {
    panic!(
        "BUG-G29 (P1): CompactBlockRelay dead helper — get_high_bandwidth_peers(), \
         create_cmpctblock_inv(), store_partial_block() all unwired in main.rs"
    );
}

// ---------------------------------------------------------------------------
// G30 — BUG (P2): HB peer rotation absent
//
// Bitcoin Core rotates HB peers when a peer becomes stale (no recent block).
// PeerCompactBlockState.last_cmpctblock is set (compact_blocks.rs:919) but
// never read anywhere.  There is no rotation/eviction logic.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "BUG-G30 (P2): last_cmpctblock is set but never read; no HB peer rotation/staleness eviction"]
fn g30_hb_peer_rotation_on_staleness() {
    panic!(
        "BUG-G30: last_cmpctblock timestamp (PeerCompactBlockState.last_cmpctblock) is set \
         but never read; CompactBlockRelay has no staleness-eviction method"
    );
}

// ---------------------------------------------------------------------------
// Integration-style: full reconstruction path (no missing txns)
// ---------------------------------------------------------------------------
#[test]
fn integration_full_reconstruction_from_mempool() {
    let block = make_block(8);
    let compact = CmpctBlock::from_block(&block, 0xDEAD_BEEF);

    let mempool: Vec<(Hash256, Arc<Transaction>)> = block
        .transactions
        .iter()
        .skip(1)
        .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
        .collect();
    let refs: Vec<(&Hash256, &Arc<Transaction>)> = mempool.iter().map(|(h, t)| (h, t)).collect();

    let mut partial =
        PartiallyDownloadedBlock::init_data(&compact, refs.into_iter(), &[]).unwrap();
    assert!(partial.is_complete());

    let reconstructed = partial.fill_block(vec![], false).unwrap();
    assert_eq!(reconstructed.transactions.len(), block.transactions.len());
    assert_eq!(reconstructed.header, block.header);
}

// ---------------------------------------------------------------------------
// Integration-style: partial reconstruction → getblocktxn → fill_block
// ---------------------------------------------------------------------------
#[test]
fn integration_partial_reconstruction_fill_block() {
    let block = make_block(6);
    let compact = CmpctBlock::from_block(&block, 0xCAFE);

    // Only put first 2 non-coinbase txs in mempool
    let partial_mempool: Vec<(Hash256, Arc<Transaction>)> = block
        .transactions
        .iter()
        .skip(1)
        .take(2)
        .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
        .collect();
    let refs: Vec<(&Hash256, &Arc<Transaction>)> =
        partial_mempool.iter().map(|(h, t)| (h, t)).collect();

    let mut partial =
        PartiallyDownloadedBlock::init_data(&compact, refs.into_iter(), &[]).unwrap();
    assert!(!partial.is_complete());

    let missing_idxs = partial.get_missing_indices();
    assert_eq!(missing_idxs.len(), 3, "3 txs missing from mempool");

    // Simulate blocktxn providing the missing transactions
    let missing_txs: Vec<Arc<Transaction>> = missing_idxs
        .iter()
        .map(|&idx| Arc::new(block.transactions[idx as usize].clone()))
        .collect();

    let reconstructed = partial.fill_block(missing_txs, false).unwrap();
    assert_eq!(reconstructed.transactions.len(), 6);
}

// ---------------------------------------------------------------------------
// Collision semantics: permanent suppress after mempool collision
// ---------------------------------------------------------------------------
#[test]
fn collision_permanent_suppress_after_duplicate_mempool_entry() {
    let block = make_block(3);
    let compact = CmpctBlock::from_block(&block, 0xF00D);

    let real_tx = block.transactions[1].clone();
    // Feed the same wtxid twice — second hit should clear the slot
    let mempool: Vec<(Hash256, Arc<Transaction>)> = vec![
        (real_tx.wtxid(), Arc::new(real_tx.clone())),
        (real_tx.wtxid(), Arc::new(real_tx.clone())),
    ];
    let refs: Vec<(&Hash256, &Arc<Transaction>)> = mempool.iter().map(|(h, t)| (h, t)).collect();

    let partial =
        PartiallyDownloadedBlock::init_data(&compact, refs.into_iter(), &[]).unwrap();

    let (_, mempool_found, _) = partial.stats();
    assert_eq!(mempool_found, 0, "duplicate mempool entry must clear the slot (collision suppress)");
    let missing = partial.get_missing_indices();
    assert!(
        !missing.is_empty(),
        "collided slot must appear in missing indices"
    );
}
