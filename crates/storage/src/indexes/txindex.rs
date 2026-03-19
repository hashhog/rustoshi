//! Transaction Index.
//!
//! This module implements the txindex, which maps transaction IDs to their
//! location on disk. This enables fast transaction lookups by txid without
//! scanning the entire blockchain.
//!
//! # Structure
//!
//! For each transaction, we store:
//! - Block hash containing the transaction
//! - Byte offset within the serialized block
//! - Length of the serialized transaction
//!
//! # References
//!
//! - Bitcoin Core: `src/index/txindex.cpp`

use crate::columns::CF_TX_INDEX;
use crate::db::{ChainDb, StorageError};
use rustoshi_primitives::Hash256;
use serde::{Deserialize, Serialize};

/// Transaction index entry stored in the database.
///
/// This contains all the information needed to locate and read a transaction
/// from block storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxLocation {
    /// Hash of the block containing this transaction.
    pub block_hash: Hash256,
    /// Block height (for convenience).
    pub height: u32,
    /// Byte offset of the transaction within the serialized block.
    pub tx_offset: u32,
    /// Length of the serialized transaction in bytes.
    pub tx_length: u32,
    /// Position of this transaction within the block (0 = coinbase).
    pub tx_index: u32,
}

impl TxLocation {
    /// Create a new transaction location entry.
    pub fn new(
        block_hash: Hash256,
        height: u32,
        tx_offset: u32,
        tx_length: u32,
        tx_index: u32,
    ) -> Self {
        Self {
            block_hash,
            height,
            tx_offset,
            tx_length,
            tx_index,
        }
    }

    /// Check if this is a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        self.tx_index == 0
    }
}

/// Transaction index errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxIndexError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("transaction not found")]
    NotFound,
}

impl From<StorageError> for TxIndexError {
    fn from(e: StorageError) -> Self {
        TxIndexError::Storage(e.to_string())
    }
}

/// Transaction index providing storage and retrieval of transaction locations.
pub struct TxIndex<'a> {
    db: &'a ChainDb,
}

impl<'a> TxIndex<'a> {
    /// Create a new transaction index wrapping the given database.
    pub fn new(db: &'a ChainDb) -> Self {
        Self { db }
    }

    /// Store a transaction location.
    pub fn put(&self, txid: &Hash256, location: &TxLocation) -> Result<(), TxIndexError> {
        let data =
            serde_json::to_vec(location).map_err(|e| TxIndexError::Storage(e.to_string()))?;
        self.db.put_cf(CF_TX_INDEX, txid.as_bytes(), &data)?;
        Ok(())
    }

    /// Retrieve a transaction location by txid.
    pub fn get(&self, txid: &Hash256) -> Result<Option<TxLocation>, TxIndexError> {
        match self.db.get_cf(CF_TX_INDEX, txid.as_bytes())? {
            Some(data) => {
                let location: TxLocation = serde_json::from_slice(&data)
                    .map_err(|e| TxIndexError::Storage(e.to_string()))?;
                Ok(Some(location))
            }
            None => Ok(None),
        }
    }

    /// Delete a transaction from the index.
    pub fn delete(&self, txid: &Hash256) -> Result<(), TxIndexError> {
        self.db.delete_cf(CF_TX_INDEX, txid.as_bytes())?;
        Ok(())
    }

    /// Check if a transaction is indexed.
    pub fn contains(&self, txid: &Hash256) -> Result<bool, TxIndexError> {
        Ok(self.db.contains_key(CF_TX_INDEX, txid.as_bytes())?)
    }

    /// Index all transactions in a block.
    ///
    /// This is a convenience method for indexing an entire block at once.
    /// It calculates offsets based on transaction serialization sizes.
    pub fn index_block(
        &self,
        block_hash: Hash256,
        height: u32,
        txids: &[Hash256],
        tx_sizes: &[u32],
    ) -> Result<(), TxIndexError> {
        if txids.len() != tx_sizes.len() {
            return Err(TxIndexError::Storage(
                "txids and tx_sizes length mismatch".to_string(),
            ));
        }

        // Block header is 80 bytes, plus varint for tx count
        let mut offset = 80u32 + varint_size(txids.len() as u64);

        for (i, (txid, &size)) in txids.iter().zip(tx_sizes.iter()).enumerate() {
            let location = TxLocation::new(block_hash, height, offset, size, i as u32);
            self.put(txid, &location)?;
            offset += size;
        }

        Ok(())
    }

    /// Remove all transactions in a block from the index.
    ///
    /// This is used during block disconnection (reorg handling).
    pub fn disconnect_block(&self, txids: &[Hash256]) -> Result<(), TxIndexError> {
        for txid in txids {
            self.delete(txid)?;
        }
        Ok(())
    }
}

/// Calculate the size of a varint-encoded value.
fn varint_size(value: u64) -> u32 {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffffffff {
        5
    } else {
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_location_new() {
        let block_hash = Hash256::ZERO;
        let location = TxLocation::new(block_hash, 100, 80, 250, 0);

        assert_eq!(location.block_hash, block_hash);
        assert_eq!(location.height, 100);
        assert_eq!(location.tx_offset, 80);
        assert_eq!(location.tx_length, 250);
        assert_eq!(location.tx_index, 0);
        assert!(location.is_coinbase());
    }

    #[test]
    fn test_tx_location_not_coinbase() {
        let location = TxLocation::new(Hash256::ZERO, 100, 330, 250, 1);
        assert!(!location.is_coinbase());
    }

    #[test]
    fn test_tx_location_serialization() {
        let block_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        let location = TxLocation::new(block_hash, 100, 80, 250, 0);

        let json = serde_json::to_string(&location).unwrap();
        let restored: TxLocation = serde_json::from_str(&json).unwrap();

        assert_eq!(location, restored);
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(252), 1);
        assert_eq!(varint_size(253), 3);
        assert_eq!(varint_size(0xffff), 3);
        assert_eq!(varint_size(0x10000), 5);
        assert_eq!(varint_size(0xffffffff), 5);
        assert_eq!(varint_size(0x100000000), 9);
    }
}
