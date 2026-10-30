//! Security audit 2026-10-28, finding H1: compact-block reconstruction reads
//! the mempool by reference. `init_data_with` is new API, so this lives apart
//! from `test_sec_compact_blocks.rs` (which also compiles on the base commit).

use rustoshi_network::{CmpctBlock, PartiallyDownloadedBlock};
use rustoshi_primitives::transaction::{OutPoint, TxIn, TxOut};
use rustoshi_primitives::{Block, BlockHeader, Hash256, Transaction};
use std::sync::Arc;

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

/// H1: `init_data_with` takes borrowed mempool transactions and clones only
/// the ones it matches, with the same result as the Arc-based `init_data`.
#[test]
fn h1_init_data_with_borrowed_mempool_matches_init_data() {
    let block = Block {
        header: header(),
        transactions: vec![coinbase(), spend(1), spend(2), spend(3)],
    };
    let cb = CmpctBlock::from_block(&block, 99);
    // Mempool holds txs 1 and 3 plus an unrelated one; tx 2 is missing.
    let pool = [spend(1), spend(3), spend(200)];
    let wtxids: Vec<Hash256> = pool.iter().map(|t| t.wtxid()).collect();

    let borrowed =
        PartiallyDownloadedBlock::init_data_with(&cb, wtxids.iter().zip(pool.iter()), &[]).unwrap();
    let arcs: Vec<Arc<Transaction>> = pool.iter().cloned().map(Arc::new).collect();
    let owned =
        PartiallyDownloadedBlock::init_data(&cb, wtxids.iter().zip(arcs.iter()), &[]).unwrap();

    assert_eq!(borrowed.get_missing_indices(), vec![2]);
    assert_eq!(borrowed.get_missing_indices(), owned.get_missing_indices());
    assert_eq!(borrowed.stats(), owned.stats());
}
