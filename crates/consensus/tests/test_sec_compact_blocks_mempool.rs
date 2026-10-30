//! Security audit 2026-10-28, finding H1: compact-block reconstruction used
//! to deep-clone and re-hash the whole mempool per `cmpctblock`.
//! `Mempool::iter_by_wtxid` yields every entry by reference with its cached
//! wtxid; this pins that it covers the pool exactly and the wtxids are right
//! (including for witness transactions, where wtxid != txid).

use rustoshi_consensus::mempool::{AtmpOptions, Mempool, MempoolConfig};
use rustoshi_consensus::CoinEntry;
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::{HashMap, HashSet};

fn p2wpkh_spk() -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[0x11u8; 20]);
    s
}

fn spend(prev: OutPoint) -> Transaction {
    let mut sig = vec![0x30, 0x44];
    sig.resize(71, 0x11);
    let mut pk = vec![0x02];
    pk.resize(33, 0x22);
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![sig, pk],
        }],
        outputs: vec![TxOut {
            value: 90_000,
            script_pubkey: p2wpkh_spk(),
        }],
        lock_time: 0,
    }
}

#[test]
fn h1_iter_by_wtxid_covers_pool_with_cached_wtxids() {
    let mut mp = Mempool::new(MempoolConfig {
        verify_scripts: false,
        ..Default::default()
    });
    let mut utxos = HashMap::new();
    let mut txs = Vec::new();
    for b in 1..=5u8 {
        let op = OutPoint {
            txid: Hash256::from([b; 32]),
            vout: 0,
        };
        utxos.insert(
            op.clone(),
            CoinEntry {
                height: 1,
                is_coinbase: false,
                value: 100_000,
                script_pubkey: p2wpkh_spk(),
            },
        );
        txs.push(spend(op));
    }
    for tx in &txs {
        mp.add_transaction_with_options(
            tx.clone(),
            &|op| utxos.get(op).cloned(),
            AtmpOptions {
                require_standard: false,
                skip_script_checks: true,
                ..Default::default()
            },
        )
        .expect("admit");
    }

    let seen: Vec<(Hash256, Hash256)> =
        mp.iter_by_wtxid().map(|(w, tx)| (*w, tx.wtxid())).collect();
    assert_eq!(seen.len(), txs.len());
    for (cached, computed) in &seen {
        assert_eq!(cached, computed, "cached wtxid must be the tx's wtxid");
    }
    let expected: HashSet<Hash256> = txs.iter().map(|t| t.wtxid()).collect();
    let got: HashSet<Hash256> = seen.iter().map(|(w, _)| *w).collect();
    assert_eq!(got, expected);
    assert!(
        txs.iter().all(|t| t.wtxid() != t.txid()),
        "witness txs exercised"
    );
}
