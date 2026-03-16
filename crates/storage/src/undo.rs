//! Undo data for block disconnection during reorganizations.
//!
//! This module provides the data structures needed to reverse a block's
//! effects on the UTXO set during chain reorganizations.
//!
//! # Structure
//!
//! Following Bitcoin Core's design (`undo.h`):
//!
//! - `TxUndo`: Undo data for a single transaction. Contains the previous outputs
//!   (coins) that were spent by the transaction's inputs.
//!
//! - `BlockUndo`: Undo data for an entire block. Contains a `TxUndo` for each
//!   non-coinbase transaction in the block.
//!
//! # Usage
//!
//! During `connect_block`, before consuming each UTXO, save it into the
//! appropriate `TxUndo`. After connecting the block, persist the `BlockUndo`
//! to storage.
//!
//! During `disconnect_block`, read the `BlockUndo` from storage and restore
//! each spent coin to the UTXO set (in reverse order).
//!
//! # Serialization
//!
//! Bitcoin Core uses a compact format with varint-encoded height/coinbase flags
//! and script compression. This implementation uses serde for simplicity, which
//! is less space-efficient but easier to debug.

use crate::block_store::CoinEntry;
use serde::{Deserialize, Serialize};

/// Undo data for a single transaction.
///
/// Contains the coins (previous outputs) that were spent by this transaction's
/// inputs. The coins are stored in the same order as the transaction's inputs.
///
/// # Invariants
///
/// - `prev_outputs.len()` equals the number of inputs in the transaction.
/// - Each entry corresponds to the coin that was spent by the input at the
///   same index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxUndo {
    /// The coins spent by this transaction's inputs, in input order.
    pub prev_outputs: Vec<CoinEntry>,
}

impl TxUndo {
    /// Create a new empty TxUndo.
    pub fn new() -> Self {
        Self {
            prev_outputs: Vec::new(),
        }
    }

    /// Create a TxUndo with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            prev_outputs: Vec::with_capacity(capacity),
        }
    }

    /// Add a spent coin to this undo.
    pub fn add_spent_coin(&mut self, coin: CoinEntry) {
        self.prev_outputs.push(coin);
    }

    /// Get the number of spent coins.
    pub fn len(&self) -> usize {
        self.prev_outputs.len()
    }

    /// Check if this undo is empty.
    pub fn is_empty(&self) -> bool {
        self.prev_outputs.is_empty()
    }

    /// Iterate over spent coins in forward order.
    pub fn iter(&self) -> impl Iterator<Item = &CoinEntry> {
        self.prev_outputs.iter()
    }

    /// Iterate over spent coins in reverse order (for disconnection).
    pub fn iter_rev(&self) -> impl Iterator<Item = &CoinEntry> {
        self.prev_outputs.iter().rev()
    }
}

/// Undo data for an entire block.
///
/// Contains a `TxUndo` for each non-coinbase transaction in the block.
/// The coinbase transaction has no inputs to spend, so it has no undo data.
///
/// # Invariants
///
/// - `tx_undo.len()` equals `block.transactions.len() - 1` (excludes coinbase).
/// - Each entry corresponds to the transaction at index `i + 1` in the block.
///
/// # Example
///
/// For a block with transactions `[coinbase, tx1, tx2, tx3]`:
/// - `tx_undo[0]` contains undo data for `tx1`
/// - `tx_undo[1]` contains undo data for `tx2`
/// - `tx_undo[2]` contains undo data for `tx3`
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockUndo {
    /// Undo data for each non-coinbase transaction, in block order.
    pub tx_undo: Vec<TxUndo>,
}

impl BlockUndo {
    /// Create a new empty BlockUndo.
    pub fn new() -> Self {
        Self {
            tx_undo: Vec::new(),
        }
    }

    /// Create a BlockUndo with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `num_txs` - The number of transactions in the block (including coinbase).
    ///   Capacity will be `num_txs - 1` for non-coinbase transactions.
    pub fn with_capacity(num_txs: usize) -> Self {
        let capacity = num_txs.saturating_sub(1);
        Self {
            tx_undo: Vec::with_capacity(capacity),
        }
    }

    /// Add undo data for a transaction.
    pub fn add_tx_undo(&mut self, undo: TxUndo) {
        self.tx_undo.push(undo);
    }

    /// Get the number of transaction undos.
    pub fn len(&self) -> usize {
        self.tx_undo.len()
    }

    /// Check if this undo is empty.
    pub fn is_empty(&self) -> bool {
        self.tx_undo.is_empty()
    }

    /// Iterate over transaction undos in forward order.
    pub fn iter(&self) -> impl Iterator<Item = &TxUndo> {
        self.tx_undo.iter()
    }

    /// Iterate over transaction undos in reverse order (for disconnection).
    pub fn iter_rev(&self) -> impl Iterator<Item = &TxUndo> {
        self.tx_undo.iter().rev()
    }

    /// Get the total number of spent coins across all transactions.
    pub fn total_spent_coins(&self) -> usize {
        self.tx_undo.iter().map(|tx| tx.len()).sum()
    }

    /// Convert from flat spent coins list to structured BlockUndo.
    ///
    /// This is useful for converting from the existing `UndoData` format
    /// to the structured `BlockUndo` format.
    ///
    /// # Arguments
    ///
    /// * `spent_coins` - All spent coins in order.
    /// * `input_counts` - The number of inputs for each non-coinbase transaction.
    ///
    /// # Panics
    ///
    /// Panics if `spent_coins.len()` doesn't equal `input_counts.iter().sum()`.
    pub fn from_flat(spent_coins: &[CoinEntry], input_counts: &[usize]) -> Self {
        let total: usize = input_counts.iter().sum();
        assert_eq!(
            spent_coins.len(),
            total,
            "spent coins count mismatch: {} != {}",
            spent_coins.len(),
            total
        );

        let mut block_undo = BlockUndo::with_capacity(input_counts.len() + 1);
        let mut offset = 0;

        for &count in input_counts {
            let mut tx_undo = TxUndo::with_capacity(count);
            for coin in &spent_coins[offset..offset + count] {
                tx_undo.add_spent_coin(coin.clone());
            }
            block_undo.add_tx_undo(tx_undo);
            offset += count;
        }

        block_undo
    }

    /// Convert to flat spent coins list.
    ///
    /// This flattens the structured undo data into a single vector of spent
    /// coins, maintaining the original order.
    pub fn to_flat(&self) -> Vec<CoinEntry> {
        let mut coins = Vec::with_capacity(self.total_spent_coins());
        for tx_undo in &self.tx_undo {
            coins.extend(tx_undo.prev_outputs.iter().cloned());
        }
        coins
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coin(height: u32, value: u64, is_coinbase: bool) -> CoinEntry {
        CoinEntry {
            height,
            is_coinbase,
            value,
            script_pubkey: vec![0x51], // OP_1
        }
    }

    // =========================
    // TxUndo tests
    // =========================

    #[test]
    fn tx_undo_new_is_empty() {
        let undo = TxUndo::new();
        assert!(undo.is_empty());
        assert_eq!(undo.len(), 0);
    }

    #[test]
    fn tx_undo_add_and_iterate() {
        let mut undo = TxUndo::new();
        undo.add_spent_coin(make_coin(100, 50_000_000, true));
        undo.add_spent_coin(make_coin(200, 25_000_000, false));

        assert_eq!(undo.len(), 2);
        assert!(!undo.is_empty());

        let coins: Vec<_> = undo.iter().collect();
        assert_eq!(coins.len(), 2);
        assert_eq!(coins[0].height, 100);
        assert_eq!(coins[1].height, 200);
    }

    #[test]
    fn tx_undo_iterate_reverse() {
        let mut undo = TxUndo::new();
        undo.add_spent_coin(make_coin(1, 100, false));
        undo.add_spent_coin(make_coin(2, 200, false));
        undo.add_spent_coin(make_coin(3, 300, false));

        let heights: Vec<_> = undo.iter_rev().map(|c| c.height).collect();
        assert_eq!(heights, vec![3, 2, 1]);
    }

    #[test]
    fn tx_undo_with_capacity() {
        let undo = TxUndo::with_capacity(10);
        assert!(undo.is_empty());
        assert_eq!(undo.prev_outputs.capacity(), 10);
    }

    // =========================
    // BlockUndo tests
    // =========================

    #[test]
    fn block_undo_new_is_empty() {
        let undo = BlockUndo::new();
        assert!(undo.is_empty());
        assert_eq!(undo.len(), 0);
        assert_eq!(undo.total_spent_coins(), 0);
    }

    #[test]
    fn block_undo_with_capacity() {
        // Block with 5 transactions (1 coinbase + 4 regular)
        let undo = BlockUndo::with_capacity(5);
        assert!(undo.is_empty());
        assert_eq!(undo.tx_undo.capacity(), 4);
    }

    #[test]
    fn block_undo_add_and_iterate() {
        let mut block_undo = BlockUndo::new();

        let mut tx1_undo = TxUndo::new();
        tx1_undo.add_spent_coin(make_coin(100, 1000, false));
        tx1_undo.add_spent_coin(make_coin(101, 2000, false));

        let mut tx2_undo = TxUndo::new();
        tx2_undo.add_spent_coin(make_coin(200, 3000, true));

        block_undo.add_tx_undo(tx1_undo);
        block_undo.add_tx_undo(tx2_undo);

        assert_eq!(block_undo.len(), 2);
        assert_eq!(block_undo.total_spent_coins(), 3);

        let tx_undos: Vec<_> = block_undo.iter().collect();
        assert_eq!(tx_undos[0].len(), 2);
        assert_eq!(tx_undos[1].len(), 1);
    }

    #[test]
    fn block_undo_iterate_reverse() {
        let mut block_undo = BlockUndo::new();

        let mut tx1_undo = TxUndo::new();
        tx1_undo.add_spent_coin(make_coin(1, 100, false));
        block_undo.add_tx_undo(tx1_undo);

        let mut tx2_undo = TxUndo::new();
        tx2_undo.add_spent_coin(make_coin(2, 200, false));
        block_undo.add_tx_undo(tx2_undo);

        let mut tx3_undo = TxUndo::new();
        tx3_undo.add_spent_coin(make_coin(3, 300, false));
        block_undo.add_tx_undo(tx3_undo);

        // Iterate in reverse order
        let heights: Vec<_> = block_undo
            .iter_rev()
            .flat_map(|tx| tx.iter().map(|c| c.height))
            .collect();
        assert_eq!(heights, vec![3, 2, 1]);
    }

    #[test]
    fn block_undo_from_flat() {
        let spent_coins = vec![
            make_coin(1, 100, false),
            make_coin(2, 200, false),
            make_coin(3, 300, false),
            make_coin(4, 400, false),
            make_coin(5, 500, false),
        ];

        // tx1 has 2 inputs, tx2 has 1 input, tx3 has 2 inputs
        let input_counts = vec![2, 1, 2];

        let block_undo = BlockUndo::from_flat(&spent_coins, &input_counts);

        assert_eq!(block_undo.len(), 3);
        assert_eq!(block_undo.tx_undo[0].len(), 2);
        assert_eq!(block_undo.tx_undo[1].len(), 1);
        assert_eq!(block_undo.tx_undo[2].len(), 2);

        // Verify the coins are in the right places
        assert_eq!(block_undo.tx_undo[0].prev_outputs[0].height, 1);
        assert_eq!(block_undo.tx_undo[0].prev_outputs[1].height, 2);
        assert_eq!(block_undo.tx_undo[1].prev_outputs[0].height, 3);
        assert_eq!(block_undo.tx_undo[2].prev_outputs[0].height, 4);
        assert_eq!(block_undo.tx_undo[2].prev_outputs[1].height, 5);
    }

    #[test]
    fn block_undo_to_flat() {
        let mut block_undo = BlockUndo::new();

        let mut tx1_undo = TxUndo::new();
        tx1_undo.add_spent_coin(make_coin(1, 100, false));
        tx1_undo.add_spent_coin(make_coin(2, 200, false));
        block_undo.add_tx_undo(tx1_undo);

        let mut tx2_undo = TxUndo::new();
        tx2_undo.add_spent_coin(make_coin(3, 300, false));
        block_undo.add_tx_undo(tx2_undo);

        let flat = block_undo.to_flat();

        assert_eq!(flat.len(), 3);
        assert_eq!(flat[0].height, 1);
        assert_eq!(flat[1].height, 2);
        assert_eq!(flat[2].height, 3);
    }

    #[test]
    fn block_undo_roundtrip_flat() {
        let original_coins = vec![
            make_coin(100, 1000, true),
            make_coin(200, 2000, false),
            make_coin(300, 3000, false),
        ];
        let input_counts = vec![1, 2];

        let block_undo = BlockUndo::from_flat(&original_coins, &input_counts);
        let roundtrip = block_undo.to_flat();

        assert_eq!(original_coins, roundtrip);
    }

    #[test]
    #[should_panic(expected = "spent coins count mismatch")]
    fn block_undo_from_flat_panics_on_mismatch() {
        let spent_coins = vec![make_coin(1, 100, false), make_coin(2, 200, false)];
        let input_counts = vec![3]; // Says 3 but only 2 coins provided

        BlockUndo::from_flat(&spent_coins, &input_counts);
    }

    #[test]
    fn block_undo_empty_from_flat() {
        let block_undo = BlockUndo::from_flat(&[], &[]);
        assert!(block_undo.is_empty());
        assert_eq!(block_undo.to_flat(), Vec::<CoinEntry>::new());
    }

    // =========================
    // Serialization tests
    // =========================

    #[test]
    fn tx_undo_serialization_roundtrip() {
        let mut undo = TxUndo::new();
        undo.add_spent_coin(make_coin(100, 50_000_000, true));
        undo.add_spent_coin(make_coin(200, 25_000_000, false));

        let json = serde_json::to_string(&undo).unwrap();
        let deserialized: TxUndo = serde_json::from_str(&json).unwrap();

        assert_eq!(undo, deserialized);
    }

    #[test]
    fn block_undo_serialization_roundtrip() {
        let mut block_undo = BlockUndo::new();

        let mut tx1_undo = TxUndo::new();
        tx1_undo.add_spent_coin(make_coin(100, 1000, false));
        tx1_undo.add_spent_coin(make_coin(101, 2000, false));
        block_undo.add_tx_undo(tx1_undo);

        let mut tx2_undo = TxUndo::new();
        tx2_undo.add_spent_coin(make_coin(200, 3000, true));
        block_undo.add_tx_undo(tx2_undo);

        let json = serde_json::to_string(&block_undo).unwrap();
        let deserialized: BlockUndo = serde_json::from_str(&json).unwrap();

        assert_eq!(block_undo, deserialized);
    }
}
