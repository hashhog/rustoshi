//! cffix-rustoshi-witness-malleation-before-weight: the historical-backfill
//! body check (`HistoricalBackfill::check_body`, run before a body is stored)
//! calls `check_block` then `contextual_check_block`. With the weight check
//! moved into `contextual_check_block`, after the witness commitment (Core
//! ContextualCheckBlock, src/validation.cpp:4169-4181), this path must:
//!
//! * still refuse a block that commits to its witness and is overweight
//!   (bad-blk-weight) — the weight check did not fall out of this path;
//! * refuse a witness-padded copy of an honest block as BLOCK_MUTATED
//!   (bad-witness-nonce-size), the reason Core gives, not as a weight verdict.
//!
//! The padded-copy test fails on master 7a703cbc by name (WeightExceeded).

use rustoshi_consensus::params::{ChainParams, MAX_BLOCK_WEIGHT};
use rustoshi_consensus::pow::check_proof_of_work;
use rustoshi_consensus::ValidationError;
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::HistoricalBackfill;
use sha2::{Digest, Sha256};

const HEIGHT: u32 = 1000;
const FILLER: usize = 996_000;
const PAD: usize = 40_000;

fn coinbase(nonce: Vec<u8>, commitment: [u8; 32]) -> Transaction {
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend_from_slice(&commitment);
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: 0xffff_ffff },
            // BIP-34 height 1000.
            script_sig: vec![0x02, 0xe8, 0x03, 0x00],
            sequence: 0xffff_ffff,
            witness: vec![nonce],
        }],
        outputs: vec![
            TxOut { value: 0, script_pubkey: vec![0u8; FILLER] },
            TxOut { value: 0, script_pubkey: spk },
        ],
        lock_time: 0,
    }
}

fn block_with_commitment(others: Vec<Transaction>, params: &ChainParams) -> Block {
    let nonce = vec![0u8; 32];
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: Hash256([0x22; 32]),
            merkle_root: Hash256::ZERO,
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: std::iter::once(coinbase(nonce.clone(), [0u8; 32])).chain(others).collect(),
    };
    let root = block.compute_witness_root();
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(root.as_bytes());
    preimage.extend_from_slice(&nonce);
    let commitment: [u8; 32] = Sha256::digest(Sha256::digest(&preimage)).into();
    block.transactions[0] = coinbase(nonce, commitment);
    block.header.merkle_root = block.compute_merkle_root();
    while !check_proof_of_work(&block.header.block_hash().0, block.header.bits, params) {
        block.header.nonce += 1;
    }
    block
}

fn spend_with_witness(witness: Vec<Vec<u8>>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0x11; 32]), vout: 0 },
            script_sig: vec![],
            sequence: 0xffff_fffe,
            witness,
        }],
        outputs: vec![TxOut { value: 1_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

fn weight(block: &Block) -> u64 {
    81 * 4 + block.transactions.iter().map(|t| t.weight() as u64).sum::<u64>()
}

#[test]
fn cffix_backfill_padded_copy_is_mutated_not_weight() {
    let params = ChainParams::regtest();
    let honest = block_with_commitment(vec![], &params);
    HistoricalBackfill::check_body(&honest, HEIGHT, &params).expect("honest body passes");
    let mut padded = honest.clone();
    padded.transactions[0].inputs[0].witness = vec![vec![0u8; 32 + PAD]];
    assert_eq!(padded.block_hash(), honest.block_hash());
    assert!(weight(&padded) > MAX_BLOCK_WEIGHT);
    let err = HistoricalBackfill::check_body(&padded, HEIGHT, &params)
        .expect_err("padded copy must not be stored");
    assert!(
        matches!(err, ValidationError::BadWitnessNonceSize),
        "backfill refused the padded copy as {err:?}; Core order gives bad-witness-nonce-size"
    );
}

#[test]
fn cffix_control_backfill_committed_overweight_is_refused() {
    let params = ChainParams::regtest();
    let heavy =
        block_with_commitment(vec![spend_with_witness(vec![vec![0x51], vec![0u8; PAD]])], &params);
    assert!(weight(&heavy) > MAX_BLOCK_WEIGHT);
    let err = HistoricalBackfill::check_body(&heavy, HEIGHT, &params)
        .expect_err("overweight body must not be stored");
    assert!(matches!(err, ValidationError::WeightExceeded(_)), "{err:?}");
    assert!(err.is_invalid_block_verdict());
}
