//! Security audit 2026-10-28 (`audits/security/rustoshi-2026-10-28.md` in the
//! meta-repo), findings C1 and C2: BIP152 wire decoding.
//!
//! - C1: a `cmpctblock` whose prefilled-tx count is u64::MAX overflowed
//!   `short_ids_len + prefilled_len` and panicked the process.
//! - C2: differential indexes were read `as i32`, so a diff of 0xFFFFFFFF
//!   decoded as -1 and pinned the index: one `getblocktxn` could request the
//!   same transaction ~66k times.
//!
//! Core reference: `bitcoin-core/src/blockencodings.h` (`DifferenceFormatter`,
//! `HeaderAndShortIDs` "indexes overflowed 16 bits").

use rustoshi_network::{BlockTxnRequest, CmpctBlock, PartiallyDownloadedBlock, PrefilledTx};
use rustoshi_primitives::serialize::{write_compact_size, Encodable};
use rustoshi_primitives::transaction::{OutPoint, TxIn, TxOut};
use rustoshi_primitives::{Block, BlockHeader, Hash256, Transaction};

fn coinbase() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x03, 0x01, 0x00, 0x00],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_0000_0000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

fn spend(seed: u8) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([seed; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: seed as u64,
            script_pubkey: vec![0x00; 22],
        }],
        lock_time: 0,
    }
}

fn header() -> BlockHeader {
    BlockHeader {
        version: 0x20000000,
        prev_block_hash: Hash256([7; 32]),
        merkle_root: Hash256([9; 32]),
        timestamp: 1_700_000_000,
        bits: 0x207fffff,
        nonce: 1,
    }
}

/// header || nonce || short_ids(count, 6 bytes each)
fn cmpct_prefix(short_ids: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    header().encode(&mut buf).unwrap();
    buf.extend_from_slice(&0u64.to_le_bytes());
    write_compact_size(&mut buf, short_ids as u64).unwrap();
    buf.extend(std::iter::repeat(0xAB).take(short_ids * 6));
    buf
}

/// C1, the audit's exact ~104-byte message: one short ID, then a prefilled
/// count of u64::MAX (0xFF + eight 0xFF). Must be a decode error, not a panic.
#[test]
fn c1_cmpctblock_prefilled_len_u64_max_is_rejected_not_panic() {
    let mut msg = cmpct_prefix(1);
    msg.push(0xFF);
    msg.extend_from_slice(&[0xFF; 8]);
    let res = std::panic::catch_unwind(|| CmpctBlock::deserialize(&msg).is_err());
    assert_eq!(
        res.ok(),
        Some(true),
        "decode must return Err, not panic or accept"
    );
}

/// C1: same overflow with zero short IDs and a near-max prefilled count; the
/// bound must hold before any addition or allocation.
#[test]
fn c1_cmpctblock_prefilled_len_huge_is_rejected() {
    let mut msg = cmpct_prefix(0);
    msg.push(0xFF);
    msg.extend_from_slice(&(u64::MAX - 1).to_le_bytes());
    let res = std::panic::catch_unwind(|| CmpctBlock::deserialize(&msg).is_err());
    assert_eq!(res.ok(), Some(true));
}

/// Core: `BlockTxCount() > std::numeric_limits<uint16_t>::max()` throws
/// "indexes overflowed 16 bits". 65,536 short IDs + 0 prefilled is one over.
#[test]
fn c1_cmpctblock_tx_count_above_u16_is_rejected() {
    let mut msg = cmpct_prefix(65_536);
    write_compact_size(&mut msg, 0).unwrap();
    assert!(CmpctBlock::deserialize(&msg).is_err());

    // 65,535 is exactly at the limit and decodes.
    let mut ok = cmpct_prefix(65_535);
    write_compact_size(&mut ok, 0).unwrap();
    assert_eq!(
        CmpctBlock::deserialize(&ok).unwrap().block_tx_count(),
        65_535
    );
}

/// C2, the audit's request: first diff k, then diffs of 0xFE FFFFFFFF. The old
/// decoder read each as -1 and produced [k, k, k, ...].
#[test]
fn c2_getblocktxn_repeated_index_is_rejected() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x11; 32]);
    write_compact_size(&mut msg, 1000).unwrap();
    write_compact_size(&mut msg, 3).unwrap();
    for _ in 1..1000 {
        msg.push(0xFE);
        msg.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    let res = BlockTxnRequest::deserialize(&msg);
    assert!(
        res.is_err(),
        "repeated-index getblocktxn must not decode (got {:?} indices)",
        res.map(|r| r.indices.len()).ok()
    );
}

/// C2: Core's DifferenceFormatter keeps the running index within u16; one
/// past it is "differential value overflow".
#[test]
fn c2_getblocktxn_index_past_u16_is_rejected() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x11; 32]);
    write_compact_size(&mut msg, 2).unwrap();
    write_compact_size(&mut msg, 65_535).unwrap(); // index 65535: allowed
    write_compact_size(&mut msg, 0).unwrap(); // index 65536: overflow
    assert!(BlockTxnRequest::deserialize(&msg).is_err());

    let mut at_limit = Vec::new();
    at_limit.extend_from_slice(&[0x11; 32]);
    write_compact_size(&mut at_limit, 1).unwrap();
    write_compact_size(&mut at_limit, 65_535).unwrap();
    assert_eq!(
        BlockTxnRequest::deserialize(&at_limit).unwrap().indices,
        vec![65_535]
    );
}

/// C2: a diff that does not fit in 32 bits must not wrap back into range.
#[test]
fn c2_getblocktxn_u64_diff_is_rejected() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x11; 32]);
    write_compact_size(&mut msg, 1).unwrap();
    write_compact_size(&mut msg, (1u64 << 32) + 5).unwrap();
    assert!(BlockTxnRequest::deserialize(&msg).is_err());
}

/// C2, prefilled side: the same `as i32` read on cmpctblock prefilled indexes.
#[test]
fn c2_cmpctblock_repeated_prefilled_index_is_rejected() {
    let mut msg = cmpct_prefix(0);
    write_compact_size(&mut msg, 2).unwrap();
    write_compact_size(&mut msg, 0).unwrap();
    coinbase().encode(&mut msg).unwrap();
    msg.push(0xFE);
    msg.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    spend(1).encode(&mut msg).unwrap();
    assert!(CmpctBlock::deserialize(&msg).is_err());
}

/// The strict decoder still round-trips honest messages.
#[test]
fn c2_honest_messages_round_trip() {
    let req = BlockTxnRequest::new(Hash256([3; 32]), vec![0, 1, 2, 7, 100, 65_535]);
    assert_eq!(BlockTxnRequest::deserialize(&req.serialize()).unwrap(), req);

    let block = Block {
        header: header(),
        transactions: vec![coinbase(), spend(1), spend(2), spend(3)],
    };
    let cb = CmpctBlock::from_block_with_prefilled(&block, 42, &[2, 3]);
    let back = CmpctBlock::deserialize(&cb.serialize()).unwrap();
    let idx: Vec<u16> = back
        .prefilled_txn
        .iter()
        .map(|p: &PrefilledTx| p.index)
        .collect();
    assert_eq!(idx, vec![0, 2, 3]);
    assert_eq!(back.short_ids, cb.short_ids);
}
