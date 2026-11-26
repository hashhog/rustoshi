//! cffix-rustoshi-witness-malleation-before-weight: the witness-inclusive
//! block-weight check must run AFTER the witness malleation check, so a
//! witness-padded copy of an honest block is refused as BLOCK_MUTATED (never
//! marked) and not as a weight VERDICT (marked).
//!
//! Witness bytes are not covered by the txid, the merkle root or the header
//! hash. A peer that pads the witness of an honest block keeps the block hash
//! unchanged. In Core v31.1, `CheckBlock` has no witness-inclusive weight
//! check (only the stripped-size `bad-blk-length` gate,
//! src/validation.cpp:3940-3948). `ContextualCheckBlock`
//! (src/validation.cpp:4169-4181) runs `CheckWitnessMalleation` first, which
//! returns BLOCK_MUTATED (bad-witness-nonce-size / bad-witness-merkle-match /
//! unexpected-witness), and only then `GetBlockWeight(block) >
//! MAX_BLOCK_WEIGHT` -> bad-blk-weight (BLOCK_CONSENSUS). `InvalidBlockFound`
//! never marks a BLOCK_MUTATED result failed (validation.cpp:1991).
//!
//! On master rustoshi ran the weight check at the end of `check_block`, which
//! every path runs before `contextual_check_block`. `WeightExceeded` is a
//! verdict (`is_invalid_block_verdict`), and the P2P connect loop marks the
//! hash FAILED_VALIDITY on a verdict, so one padded relay of the next block
//! split the node off the chain.
//!
//! The non-control tests fail on master 7a703cbc by name. The controls pass on
//! both: honest blocks connect, and a block whose commitment is valid but
//! which is genuinely overweight is still `WeightExceeded` and still a
//! verdict, on every path (the set of rejected blocks does not change).
//!
//! The `secscan2_*` tests are the proof tests from the security scan that
//! found this; the `cffix_*` tests add the reorg path and more controls.

use std::collections::HashMap;

use rustoshi_consensus::chain_state::{ChainState, UtxoCache};
use rustoshi_consensus::params::{ChainParams, MAX_BLOCK_WEIGHT};
use rustoshi_consensus::pow::check_proof_of_work;
use rustoshi_consensus::validation::{
    check_block, contextual_check_block, BlockIndexEntry, CoinEntry, StubChainContext,
    UndoData, ValidationError,
};
use rustoshi_crypto::sha256d;
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};

const HEIGHT: u32 = 1000;
/// Size of the zero-filled coinbase output script that brings the honest
/// block's stripped weight close to the limit (a large but valid block).
const FILLER: usize = 996_000;
/// Extra witness bytes the attacker adds. Small next to the 4 MB P2P
/// message cap.
const PAD: usize = 40_000;
/// Parent of every test block (the chain tip at HEIGHT - 1).
const PARENT: Hash256 = Hash256([0x22; 32]);

fn coinbase(marker: u8, nonce_item: Vec<Vec<u8>>, commitment: Option<[u8; 32]>) -> Transaction {
    let mut outputs = vec![TxOut {
        value: 0,
        script_pubkey: vec![0u8; FILLER],
    }];
    if let Some(c) = commitment {
        let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        spk.extend_from_slice(&c);
        outputs.push(TxOut {
            value: 0,
            script_pubkey: spk,
        });
    }
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0xffff_ffff,
            },
            // BIP-34 height 1000 = push 2 bytes e8 03, then a marker byte so
            // sibling blocks at the same height get different hashes.
            script_sig: vec![0x02, 0xe8, 0x03, marker],
            sequence: 0xffff_ffff,
            witness: nonce_item,
        }],
        outputs,
        lock_time: 0,
    }
}

fn spend_with_witness(witness: Vec<Vec<u8>>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0x11; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_fffe,
            witness,
        }],
        outputs: vec![TxOut {
            value: 1_000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

/// A block on `PARENT` whose coinbase commits to the witness root of
/// `others` (a valid BIP-141 commitment with a 32-byte reserved value).
fn block_marked(marker: u8, others: Vec<Transaction>, params: &ChainParams) -> Block {
    let nonce = vec![0u8; 32];
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: PARENT,
            merkle_root: Hash256::ZERO,
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: std::iter::once(coinbase(marker, vec![nonce.clone()], Some([0u8; 32])))
            .chain(others)
            .collect(),
    };
    let root = block.compute_witness_root();
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(root.as_bytes());
    preimage[32..].copy_from_slice(&nonce);
    block.transactions[0] = coinbase(marker, vec![nonce], Some(sha256d(&preimage).0));
    block.header.merkle_root = block.compute_merkle_root();
    while !check_proof_of_work(&block.header.block_hash().0, block.header.bits, params) {
        block.header.nonce += 1;
    }
    block
}

fn block_with_commitment(others: Vec<Transaction>, params: &ChainParams) -> Block {
    block_marked(0x00, others, params)
}

/// The padded copy: the coinbase witness reserved value grown past 32 bytes.
fn pad_coinbase_witness(honest: &Block) -> Block {
    let mut padded = honest.clone();
    padded.transactions[0].inputs[0].witness = vec![vec![0u8; 32 + PAD]];
    padded
}

/// A block that commits to its own witness and is still over the limit.
fn committed_overweight(marker: u8, params: &ChainParams) -> Block {
    block_marked(
        marker,
        vec![spend_with_witness(vec![vec![0x51], vec![0u8; PAD]])],
        params,
    )
}

fn weight(block: &Block) -> u64 {
    // header + 1-byte tx count, both non-witness.
    81 * 4 + block.transactions.iter().map(|t| t.weight() as u64).sum::<u64>()
}

/// The decision rustoshi's `process_block` reaches before ConnectBlock:
/// `check_block` then `contextual_check_block` (chain_state.rs).
fn decide(block: &Block, params: &ChainParams) -> Result<(), ValidationError> {
    check_block(block, params)?;
    contextual_check_block(block, HEIGHT, &StubChainContext, params)
}

fn assert_mutated_not_verdict(honest: &Block, padded: &Block, expected: ValidationError) {
    let params = ChainParams::regtest();
    assert_eq!(honest.block_hash(), padded.block_hash(), "padding must not change the hash");
    assert!(weight(honest) <= MAX_BLOCK_WEIGHT, "honest block must be within weight");
    assert!(weight(padded) > MAX_BLOCK_WEIGHT, "padded copy must exceed weight");
    let err = decide(padded, &params).expect_err("padded copy must be refused");
    assert!(
        !err.is_invalid_block_verdict(),
        "witness-padded copy of an honest block was refused as a VERDICT ({err:?}); \
         Core refuses it as BLOCK_MUTATED ({expected:?}) and never marks the hash failed"
    );
    assert_eq!(
        std::mem::discriminant(&err),
        std::mem::discriminant(&expected),
        "got {err:?}, Core order gives {expected:?}"
    );
}

fn utxo() -> UtxoCache<impl Fn(&OutPoint) -> Option<CoinEntry>> {
    UtxoCache::new(|_: &OutPoint| -> Option<CoinEntry> { None }, 1_000)
}

// ---------------------------------------------------------------------------
// CheckBlock + ContextualCheckBlock order (process_block's decision)
// ---------------------------------------------------------------------------

/// Padding the coinbase witness (Core: bad-witness-nonce-size, BLOCK_MUTATED).
#[test]
fn secscan2_padded_coinbase_witness_is_mutated_not_verdict() {
    let params = ChainParams::regtest();
    let honest = block_with_commitment(vec![], &params);
    let padded = pad_coinbase_witness(&honest);
    assert_mutated_not_verdict(&honest, &padded, ValidationError::BadWitnessNonceSize);
}

/// Adding a witness item to a non-coinbase input (Core:
/// bad-witness-merkle-match, BLOCK_MUTATED).
#[test]
fn secscan2_padded_tx_witness_is_mutated_not_verdict() {
    let params = ChainParams::regtest();
    let honest = block_with_commitment(vec![spend_with_witness(vec![vec![0x51]])], &params);
    let mut padded = honest.clone();
    padded.transactions[1].inputs[0].witness.push(vec![0u8; PAD]);
    assert_mutated_not_verdict(&honest, &padded, ValidationError::BadWitnessCommitment);
}

/// Control (passes on master): the honest blocks are valid.
#[test]
fn secscan2_control_honest_blocks_pass() {
    let params = ChainParams::regtest();
    let a = block_with_commitment(vec![], &params);
    let b = block_with_commitment(vec![spend_with_witness(vec![vec![0x51]])], &params);
    decide(&a, &params).expect("honest coinbase-only block");
    decide(&b, &params).expect("honest block with a witness spend");
}

/// Control (passes on master, must still pass after the fix): a block whose
/// witness commitment is VALID but which is genuinely over the weight limit
/// is a verdict, as in Core (bad-blk-weight, BLOCK_CONSENSUS). A fix that
/// stopped treating every WeightExceeded as a verdict, or dropped the weight
/// check, would fail here.
#[test]
fn secscan2_control_committed_overweight_is_verdict() {
    let params = ChainParams::regtest();
    let heavy = committed_overweight(0x00, &params);
    assert!(weight(&heavy) > MAX_BLOCK_WEIGHT);
    let err = decide(&heavy, &params).expect_err("overweight block");
    assert!(matches!(err, ValidationError::WeightExceeded(_)), "{err:?}");
    assert!(err.is_invalid_block_verdict());
}

/// Control: the stripped-size gate (Core CheckBlock `bad-blk-length`) stays
/// in `check_block`. It reads no witness data, so it may run before the
/// malleation check, and a block over it is still a verdict.
#[test]
fn cffix_control_stripped_size_gate_stays_in_check_block() {
    let params = ChainParams::regtest();
    let mut fat = block_with_commitment(vec![], &params);
    // 1,000,001 stripped bytes in one output: stripped size × 4 > 4M.
    fat.transactions[0].outputs[0].script_pubkey = vec![0u8; 1_000_001];
    fat.header.merkle_root = fat.compute_merkle_root();
    let err = check_block(&fat, &params).expect_err("stripped size over the limit");
    // bad-txns-oversize (per-tx, stripped) or bad-blk-length: both run in
    // check_block, before any witness data is looked at.
    assert!(
        matches!(
            err,
            ValidationError::BlockLengthTooLarge(_) | ValidationError::TxValidation(_)
        ),
        "{err:?}"
    );
    assert!(err.is_invalid_block_verdict());
}

// ---------------------------------------------------------------------------
// ChainState::process_block (tip-extending connect: P2P loop, submitblock,
// blk-file and stdin import all call it)
// ---------------------------------------------------------------------------

/// The production entry point: the padded copy must not come back from
/// `ChainState::process_block` as a verdict, and the honest block with the
/// same hash must then still connect.
#[test]
fn secscan2_process_block_padded_copy_then_honest_connects() {
    let params = ChainParams::regtest();
    let honest = block_with_commitment(vec![], &params);
    let padded = pad_coinbase_witness(&honest);

    let mut cs = ChainState::new(PARENT, HEIGHT - 1, params.clone());
    let mut utxo = utxo();
    let err = cs
        .process_block(&padded, &mut utxo, 0, true, 0, true, 0)
        .expect_err("padded copy must be refused");
    assert!(
        !err.is_invalid_block_verdict(),
        "process_block refused the witness-padded copy as a VERDICT ({err:?}); the P2P \
         connect loop would mark hash {} FAILED_VALIDITY and drop the honest block",
        honest.block_hash().to_hex()
    );
    cs.process_block(&honest, &mut utxo, 0, true, 0, true, 0)
        .expect("honest block with the same hash connects");
    assert_eq!(cs.tip_hash(), honest.block_hash());
}

/// Control: `process_block` still refuses a committed overweight block as a
/// WeightExceeded verdict (the weight check did not fall out of this path).
#[test]
fn cffix_control_process_block_committed_overweight_is_verdict() {
    let params = ChainParams::regtest();
    let heavy = committed_overweight(0x00, &params);
    let mut cs = ChainState::new(PARENT, HEIGHT - 1, params);
    let mut utxo = utxo();
    let err = cs
        .process_block(&heavy, &mut utxo, 0, true, 0, true, 0)
        .expect_err("overweight block must be refused");
    assert!(matches!(err, ValidationError::WeightExceeded(_)), "{err:?}");
    assert!(err.is_invalid_block_verdict());
    assert_eq!(cs.tip_hash(), PARENT, "tip must not move");
}

// ---------------------------------------------------------------------------
// ChainState::reorganize (the reorg connect path runs the same two checks)
// ---------------------------------------------------------------------------

/// Active chain PARENT -> A (height HEIGHT); reorganize to the side block
/// `b` (also on PARENT). Returns the reorg result and the chain state.
fn reorg_to(b: &Block) -> (Result<usize, ValidationError>, ChainState) {
    let params = ChainParams::regtest();
    let a = block_marked(0xA1, vec![], &params);
    let mut cs = ChainState::new(PARENT, HEIGHT - 1, params);
    let mut utxo = utxo();
    let (undo_a, _) = cs
        .process_block(&a, &mut utxo, 0, true, 0, true, 0)
        .expect("active block A connects");
    let (ah, bh) = (a.block_hash(), b.block_hash());
    assert_ne!(ah, bh);

    let entry = |height: u32, prev: Hash256| BlockIndexEntry {
        height,
        timestamp: 1_700_000_000,
        bits: 0x207f_ffff,
        prev_hash: prev,
        chain_work: [0u8; 32],
    };
    let index: HashMap<Hash256, BlockIndexEntry> = [
        (PARENT, entry(HEIGHT - 1, Hash256::ZERO)),
        (ah, entry(HEIGHT, PARENT)),
        (bh, entry(HEIGHT, PARENT)),
    ]
    .into_iter()
    .collect();
    // The connect half of the reorg walks the parent's ancestors for the
    // median time past; give it a parent body whose walk ends there.
    let parent = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1_699_999_000,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: vec![],
    };
    let blocks: HashMap<Hash256, Block> =
        [(PARENT, parent), (ah, a), (bh, b.clone())].into_iter().collect();
    let undos: HashMap<Hash256, UndoData> = [(ah, undo_a)].into_iter().collect();

    let r = cs
        .reorganize(
            bh,
            &|h: &Hash256| blocks.get(h).cloned(),
            &|h: &Hash256| undos.get(h).cloned(),
            &|h: &Hash256| index.get(h).cloned(),
            &mut utxo,
        )
        .map(|(n, _)| n);
    (r, cs)
}

/// The reorg path: a padded copy of the side-branch block is BLOCK_MUTATED,
/// not a verdict (the caller would otherwise mark it and its descendants
/// failed), and the honest block with the same hash reorganizes in.
#[test]
fn cffix_reorg_padded_side_block_is_mutated_then_honest_reorgs() {
    let params = ChainParams::regtest();
    let honest_b = block_marked(0xB1, vec![], &params);
    let padded_b = pad_coinbase_witness(&honest_b);
    assert_eq!(honest_b.block_hash(), padded_b.block_hash());

    let (r, _) = reorg_to(&padded_b);
    let err = r.expect_err("padded side block must not connect");
    assert!(
        matches!(err, ValidationError::BadWitnessNonceSize),
        "reorg refused the padded copy as {err:?}; Core order gives BadWitnessNonceSize"
    );
    assert!(!err.is_invalid_block_verdict(), "{err:?}");

    let (r, cs) = reorg_to(&honest_b);
    r.expect("honest side block with the same hash reorganizes in");
    assert_eq!(cs.tip_hash(), honest_b.block_hash());
}

/// Control: the reorg path still refuses a committed overweight block as a
/// WeightExceeded verdict.
#[test]
fn cffix_control_reorg_committed_overweight_is_verdict() {
    let params = ChainParams::regtest();
    let heavy = committed_overweight(0xB2, &params);
    let (r, _) = reorg_to(&heavy);
    let err = r.expect_err("overweight side block must not connect");
    assert!(matches!(err, ValidationError::WeightExceeded(_)), "{err:?}");
    assert!(err.is_invalid_block_verdict());
}
