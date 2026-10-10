//! Core v31.1 `CTxMemPool::DynamicMemoryUsage` on x86_64-linux.
//!
//! Expected values were measured on a local Bitcoin Core v31.1 regtest
//! (`getmempoolinfo` `usage`) for a fresh pool, then checked against the
//! `memusage::MallocUsage` decomposition of the v31.1 types.

use rustoshi_consensus::mempool::{AtmpOptions, Mempool, MempoolConfig};
use rustoshi_consensus::CoinEntry;
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::HashMap;

fn fresh_pool() -> Mempool {
    Mempool::new(MempoolConfig {
        verify_scripts: false,
        ..Default::default()
    })
}

fn admit_opts() -> AtmpOptions {
    AtmpOptions {
        require_standard: false,
        skip_script_checks: true,
        ..Default::default()
    }
}

fn p2wpkh_spk() -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[0x11u8; 20]);
    s
}

fn witness_71_33() -> Vec<Vec<u8>> {
    let mut sig = vec![0x30, 0x44];
    sig.resize(71, 0x11);
    let mut pk = vec![0x02];
    pk.resize(33, 0x22);
    vec![sig, pk]
}

fn coin(value: u64) -> CoinEntry {
    CoinEntry {
        height: 1,
        is_coinbase: false,
        value,
        script_pubkey: p2wpkh_spk(),
    }
}

fn admit(mp: &mut Mempool, tx: Transaction, utxos: &HashMap<OutPoint, CoinEntry>) {
    mp.add_transaction_with_options(tx, &|op| utxos.get(op).cloned(), admit_opts())
        .expect("admit");
}

/// 1 input, empty scriptSig, witness 71 + 33, one 22-byte output.
fn replay_shaped_tx(prev: OutPoint, value_in: u64, fee: u64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: witness_71_33(),
        }],
        outputs: vec![TxOut {
            value: value_in - fee,
            script_pubkey: p2wpkh_spk(),
        }],
        lock_time: 0,
    }
}

fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: Hash256::from([byte; 32]),
        vout,
    }
}

#[test]
fn empty_pool_usage_is_zero() {
    assert_eq!(fresh_pool().dynamic_memory_usage(), 0);
}

#[test]
fn fresh_p2wpkh_spend_usage_matches_core_1176() {
    let mut mp = fresh_pool();
    let prev = outpoint(0xab, 0);
    let value_in = 50_000_000;
    let tx = replay_shaped_tx(prev.clone(), value_in, 1_000_000);
    let mut utxos = HashMap::new();
    utxos.insert(prev, coin(value_in));
    admit(&mut mp, tx, &utxos);
    assert_eq!(mp.size(), 1);
    assert_eq!(
        mp.dynamic_memory_usage(),
        1176,
        "Core v31.1 DynamicMemoryUsage for the replayed 1-in/1-out spend"
    );
}

#[test]
fn removing_the_only_tx_keeps_randomized_capacity() {
    let mut mp = fresh_pool();
    let prev = outpoint(0xab, 0);
    let value_in = 50_000_000;
    let tx = replay_shaped_tx(prev.clone(), value_in, 1_000_000);
    let txid = tx.txid();
    let mut utxos = HashMap::new();
    utxos.insert(prev, coin(value_in));
    admit(&mut mp, tx, &utxos);
    mp.remove_transaction(&txid, false);
    assert_eq!(mp.size(), 0);
    // clear() kept a capacity-1 vector: MallocUsage(40) == 64.
    assert_eq!(mp.dynamic_memory_usage(), 64);
}

#[test]
fn two_in_two_out_usage_matches_core_1624() {
    let mut mp = fresh_pool();
    let a = outpoint(0x01, 0);
    let b = outpoint(0x02, 0);
    let value_in = 50_000_000;
    let fee = 1_000_000;
    let tx = Transaction {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: a.clone(),
                script_sig: vec![],
                sequence: 0xffff_fffd,
                witness: witness_71_33(),
            },
            TxIn {
                previous_output: b.clone(),
                script_sig: vec![],
                sequence: 0xffff_fffd,
                witness: witness_71_33(),
            },
        ],
        outputs: vec![
            TxOut {
                value: (value_in * 2 - fee) / 2,
                script_pubkey: p2wpkh_spk(),
            },
            TxOut {
                value: (value_in * 2 - fee) / 2,
                script_pubkey: p2wpkh_spk(),
            },
        ],
        lock_time: 0,
    };
    let mut utxos = HashMap::new();
    utxos.insert(a, coin(value_in));
    utxos.insert(b, coin(value_in));
    admit(&mut mp, tx, &utxos);
    assert_eq!(mp.dynamic_memory_usage(), 1624);
}

#[test]
fn parent_child_two_chunks_matches_core_2456() {
    // Parent fee above the child fee, equal sizes: Core keeps two chunks.
    let usage = parent_child_usage(200_000, 100_000);
    assert_eq!(usage, 2456);
}

#[test]
fn parent_child_one_chunk_matches_core_2392() {
    // Child fee above the parent fee: CPFP merges them into one chunk.
    let usage = parent_child_usage(20_000, 200_000);
    assert_eq!(usage, 2392);
}

fn parent_child_usage(parent_fee: u64, child_fee: u64) -> usize {
    let mut mp = fresh_pool();
    let prev = outpoint(0x11, 0);
    let value_in = 50_000_000;
    let parent = replay_shaped_tx(prev.clone(), value_in, parent_fee);
    let child_prev = OutPoint {
        txid: parent.txid(),
        vout: 0,
    };
    let child = replay_shaped_tx(child_prev, value_in - parent_fee, child_fee);
    let mut utxos = HashMap::new();
    utxos.insert(prev, coin(value_in));
    admit(&mut mp, parent, &utxos);
    admit(&mut mp, child, &utxos);
    assert_eq!(mp.size(), 2);
    mp.dynamic_memory_usage()
}

#[test]
fn witness_heavy_standard_shape_matches_core_1272() {
    // Two 80-byte items plus the 3-byte script OP_DROP OP_DROP OP_TRUE.
    // 80 is the standard P2WSH stack-item limit; both items share the
    // MallocUsage bucket of a 71-byte signature, and the extra stack slot
    // is what moves 1176 to 1272.
    let mut mp = fresh_pool();
    let prev = outpoint(0x44, 0);
    let value_in = 50_000_000;
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev.clone(),
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![vec![0x11; 80], vec![0x22; 80], vec![0x75, 0x75, 0x51]],
        }],
        outputs: vec![TxOut {
            value: value_in - 100_000,
            script_pubkey: p2wpkh_spk(),
        }],
        lock_time: 0,
    };
    let mut utxos = HashMap::new();
    utxos.insert(prev, coin(value_in));
    admit(&mut mp, tx, &utxos);
    assert_eq!(mp.dynamic_memory_usage(), 1272);
}

#[test]
fn script_pubkey_past_prevector_matches_core_1240() {
    // 37-byte bare 1-of-1 multisig. prevector<36> spills, MallocUsage(37) == 64.
    let mut spk = vec![0x51, 0x21, 0x02];
    spk.extend(std::iter::repeat(0xab).take(32));
    spk.extend_from_slice(&[0x51, 0xae]);
    assert_eq!(spk.len(), 37);
    let mut mp = fresh_pool();
    let prev = outpoint(0x55, 0);
    let value_in = 50_000_000;
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev.clone(),
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: witness_71_33(),
        }],
        outputs: vec![TxOut {
            value: value_in - 100_000,
            script_pubkey: spk,
        }],
        lock_time: 0,
    };
    let mut utxos = HashMap::new();
    utxos.insert(prev, coin(value_in));
    admit(&mut mp, tx, &utxos);
    assert_eq!(mp.dynamic_memory_usage(), 1240);
}

#[test]
fn map_deltas_node_is_96_until_cleared() {
    let mut mp = fresh_pool();
    let txid = Hash256::from([0xcd; 32]);
    mp.prioritise_transaction(&txid, 1);
    assert_eq!(mp.dynamic_memory_usage(), 96);
    mp.clear_prioritisation(&txid);
    assert_eq!(mp.dynamic_memory_usage(), 0);
}

#[test]
fn removing_a_two_tx_pool_leaves_capacity_two() {
    let mut mp = fresh_pool();
    let value_in = 50_000_000;
    let mut utxos = HashMap::new();
    let mut txids = Vec::new();
    for (i, byte) in [0x61u8, 0x62].into_iter().enumerate() {
        let prev = outpoint(byte, 0);
        utxos.insert(prev.clone(), coin(value_in));
        let tx = replay_shaped_tx(prev, value_in, 50_000 + i as u64);
        txids.push(tx.txid());
        admit(&mut mp, tx, &utxos);
    }
    assert_eq!(mp.size(), 2);
    mp.remove_transaction(&txids[0], false);
    mp.remove_transaction(&txids[1], false);
    assert_eq!(mp.size(), 0);
    // After the pop to one element, size*2 == capacity, so no shrink;
    // clear() then keeps that capacity-2 allocation: MallocUsage(80) == 96.
    assert_eq!(mp.dynamic_memory_usage(), 96);
}

#[test]
fn single_tx_while_randomized_cap_is_two_is_1208() {
    let mut mp = fresh_pool();
    let value_in = 50_000_000;
    let mut utxos = HashMap::new();
    let prev_p = outpoint(0x71, 0);
    utxos.insert(prev_p.clone(), coin(value_in));
    let parent = replay_shaped_tx(prev_p, value_in, 200_000);
    let child_prev = OutPoint {
        txid: parent.txid(),
        vout: 0,
    };
    let parent_txid = parent.txid();
    let child = replay_shaped_tx(child_prev, value_in - 200_000, 100_000);
    let child_txid = child.txid();
    admit(&mut mp, parent, &utxos);
    admit(&mut mp, child, &utxos);
    mp.remove_transaction(&child_txid, false);
    assert_eq!(mp.size(), 1);
    assert!(mp.get(&parent_txid).is_some());
    // Fresh 1176 uses a capacity-1 vector (64). Capacity stayed 2 (96).
    assert_eq!(mp.dynamic_memory_usage(), 1208);
}
