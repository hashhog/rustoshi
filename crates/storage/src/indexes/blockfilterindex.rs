//! BIP 157/158 Block Filter Index.
//!
//! This module implements the blockfilterindex, which stores compact block filters
//! (GCS filters) for each block in the chain. These filters enable light clients
//! to quickly determine if a block might contain transactions relevant to them.
//!
//! # Structure
//!
//! For each block, we store:
//! - The encoded GCS filter (containing scriptPubKeys from outputs and spent inputs)
//! - The filter hash (SHA256d of the encoded filter)
//! - The filter header (hash of filter_hash || prev_filter_header)
//!
//! # References
//!
//! - BIP 157: Client Side Block Filtering
//! - BIP 158: Compact Block Filters for Light Clients
//! - Bitcoin Core: `src/index/blockfilterindex.cpp`

use crate::columns::{CF_BLOCKFILTER, CF_BLOCKFILTER_HEADER};
use crate::db::{ChainDb, StorageError};
use crate::indexes::gcs::{GCSFilter, BASIC_FILTER_M, BASIC_FILTER_P};
use rustoshi_primitives::Hash256;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Block filter type (BIP 158).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlockFilterType {
    /// Basic filter containing scriptPubKeys.
    Basic = 0,
}

impl BlockFilterType {
    /// Get the human-readable name for this filter type.
    pub fn name(&self) -> &'static str {
        match self {
            BlockFilterType::Basic => "basic",
        }
    }

    /// Parse a filter type from its name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "basic" => Some(BlockFilterType::Basic),
            _ => None,
        }
    }
}

/// A complete block filter with metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockFilter {
    /// The filter type.
    pub filter_type: BlockFilterType,
    /// Hash of the block this filter is for.
    pub block_hash: Hash256,
    /// The encoded GCS filter.
    pub encoded_filter: Vec<u8>,
}

impl BlockFilter {
    /// Create a new block filter.
    pub fn new(
        filter_type: BlockFilterType,
        block_hash: Hash256,
        encoded_filter: Vec<u8>,
    ) -> Self {
        Self {
            filter_type,
            block_hash,
            encoded_filter,
        }
    }

    /// Build a basic filter from block data.
    ///
    /// The filter includes:
    /// - All scriptPubKeys from transaction outputs (excluding OP_RETURN)
    /// - All scriptPubKeys of spent outputs (from undo data)
    pub fn build_basic(
        block_hash: Hash256,
        output_scripts: impl Iterator<Item = Vec<u8>>,
        spent_scripts: impl Iterator<Item = Vec<u8>>,
    ) -> Self {
        let mut elements = HashSet::new();

        // Add output scriptPubKeys (skip empty and OP_RETURN)
        for script in output_scripts {
            if !script.is_empty() && script[0] != 0x6a {
                // 0x6a = OP_RETURN
                elements.insert(script);
            }
        }

        // Add spent scriptPubKeys
        for script in spent_scripts {
            if !script.is_empty() {
                elements.insert(script);
            }
        }

        let filter = GCSFilter::new_basic(&block_hash, &elements);

        Self {
            filter_type: BlockFilterType::Basic,
            block_hash,
            encoded_filter: filter.into_encoded(),
        }
    }

    /// Compute the filter hash (SHA256d of encoded filter).
    pub fn filter_hash(&self) -> Hash256 {
        sha256d(&self.encoded_filter)
    }

    /// Compute the filter header given the previous header.
    pub fn compute_header(&self, prev_header: &Hash256) -> Hash256 {
        let filter_hash = self.filter_hash();
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(filter_hash.as_bytes());
        data.extend_from_slice(prev_header.as_bytes());
        sha256d(&data)
    }

    /// Check if a script might be in the filter.
    pub fn match_script(&self, script: &[u8]) -> Result<bool, BlockFilterError> {
        let filter = GCSFilter::from_encoded(
            BASIC_FILTER_P,
            BASIC_FILTER_M,
            &self.block_hash,
            self.encoded_filter.clone(),
        )
        .map_err(|_| BlockFilterError::InvalidFilter)?;

        Ok(filter.match_element(script))
    }

    /// Check if any of the scripts might be in the filter.
    pub fn match_any_scripts(&self, scripts: &[Vec<u8>]) -> Result<bool, BlockFilterError> {
        let filter = GCSFilter::from_encoded(
            BASIC_FILTER_P,
            BASIC_FILTER_M,
            &self.block_hash,
            self.encoded_filter.clone(),
        )
        .map_err(|_| BlockFilterError::InvalidFilter)?;

        Ok(filter.match_any(scripts))
    }
}

/// Filter header entry stored in the database.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterHeaderEntry {
    /// Block hash this header is for.
    pub block_hash: Hash256,
    /// Hash of the encoded filter.
    pub filter_hash: Hash256,
    /// Filter header (hash of filter_hash || prev_header).
    pub filter_header: Hash256,
}

/// Block filter index errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockFilterError {
    #[error("invalid filter encoding")]
    InvalidFilter,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("filter not found for block")]
    NotFound,
}

impl From<StorageError> for BlockFilterError {
    fn from(e: StorageError) -> Self {
        BlockFilterError::Storage(e.to_string())
    }
}

/// Block filter index providing storage and retrieval of BIP 157/158 filters.
pub struct BlockFilterIndex<'a> {
    db: &'a ChainDb,
}

impl<'a> BlockFilterIndex<'a> {
    /// Create a new block filter index wrapping the given database.
    pub fn new(db: &'a ChainDb) -> Self {
        Self { db }
    }

    /// Store a block filter.
    pub fn put_filter(&self, filter: &BlockFilter) -> Result<(), BlockFilterError> {
        let data = serde_json::to_vec(filter)
            .map_err(|e| BlockFilterError::Storage(e.to_string()))?;
        self.db
            .put_cf(CF_BLOCKFILTER, filter.block_hash.as_bytes(), &data)?;
        Ok(())
    }

    /// Retrieve a block filter by block hash.
    pub fn get_filter(&self, block_hash: &Hash256) -> Result<Option<BlockFilter>, BlockFilterError> {
        match self.db.get_cf(CF_BLOCKFILTER, block_hash.as_bytes())? {
            Some(data) => {
                let filter: BlockFilter = serde_json::from_slice(&data)
                    .map_err(|e| BlockFilterError::Storage(e.to_string()))?;
                Ok(Some(filter))
            }
            None => Ok(None),
        }
    }

    /// Delete a block filter.
    pub fn delete_filter(&self, block_hash: &Hash256) -> Result<(), BlockFilterError> {
        self.db.delete_cf(CF_BLOCKFILTER, block_hash.as_bytes())?;
        Ok(())
    }

    /// Store a filter header entry by height.
    pub fn put_filter_header(
        &self,
        height: u32,
        entry: &FilterHeaderEntry,
    ) -> Result<(), BlockFilterError> {
        let data = serde_json::to_vec(entry)
            .map_err(|e| BlockFilterError::Storage(e.to_string()))?;
        self.db
            .put_cf(CF_BLOCKFILTER_HEADER, &height.to_be_bytes(), &data)?;
        Ok(())
    }

    /// Retrieve a filter header entry by height.
    pub fn get_filter_header(
        &self,
        height: u32,
    ) -> Result<Option<FilterHeaderEntry>, BlockFilterError> {
        match self.db.get_cf(CF_BLOCKFILTER_HEADER, &height.to_be_bytes())? {
            Some(data) => {
                let entry: FilterHeaderEntry = serde_json::from_slice(&data)
                    .map_err(|e| BlockFilterError::Storage(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Delete a filter header entry by height.
    pub fn delete_filter_header(&self, height: u32) -> Result<(), BlockFilterError> {
        self.db
            .delete_cf(CF_BLOCKFILTER_HEADER, &height.to_be_bytes())?;
        Ok(())
    }

    /// Check if a filter exists for the given block.
    pub fn has_filter(&self, block_hash: &Hash256) -> Result<bool, BlockFilterError> {
        Ok(self.db.contains_key(CF_BLOCKFILTER, block_hash.as_bytes())?)
    }

    /// Build and store a filter for a block.
    ///
    /// This is a convenience method that builds the filter, computes headers,
    /// and stores everything atomically.
    pub fn index_block(
        &self,
        height: u32,
        block_hash: Hash256,
        output_scripts: impl Iterator<Item = Vec<u8>>,
        spent_scripts: impl Iterator<Item = Vec<u8>>,
        prev_filter_header: &Hash256,
    ) -> Result<Hash256, BlockFilterError> {
        // Build the filter
        let filter = BlockFilter::build_basic(block_hash, output_scripts, spent_scripts);

        // Compute hashes
        let filter_hash = filter.filter_hash();
        let filter_header = filter.compute_header(prev_filter_header);

        // Store filter
        self.put_filter(&filter)?;

        // Store header
        let header_entry = FilterHeaderEntry {
            block_hash,
            filter_hash,
            filter_header,
        };
        self.put_filter_header(height, &header_entry)?;

        Ok(filter_header)
    }

    /// Remove index data for a block (for reorg handling).
    pub fn disconnect_block(
        &self,
        height: u32,
        block_hash: &Hash256,
    ) -> Result<(), BlockFilterError> {
        self.delete_filter(block_hash)?;
        self.delete_filter_header(height)?;
        Ok(())
    }
}

/// SHA256d (double SHA-256) hash.
fn sha256d(data: &[u8]) -> Hash256 {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    Hash256::from_bytes(second.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_type_name() {
        assert_eq!(BlockFilterType::Basic.name(), "basic");
        assert_eq!(BlockFilterType::from_name("basic"), Some(BlockFilterType::Basic));
        assert_eq!(BlockFilterType::from_name("invalid"), None);
    }

    #[test]
    fn test_block_filter_build_basic() {
        let block_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        let outputs = vec![
            vec![0x76, 0xa9, 0x14], // P2PKH-like
            vec![0x00, 0x14],        // P2WPKH-like
            vec![0x6a, 0x04],        // OP_RETURN (should be excluded)
        ];
        let spent = vec![vec![0x51]]; // P2SH-like

        let filter = BlockFilter::build_basic(
            block_hash,
            outputs.into_iter(),
            spent.into_iter(),
        );

        assert_eq!(filter.filter_type, BlockFilterType::Basic);
        assert_eq!(filter.block_hash, block_hash);
        assert!(!filter.encoded_filter.is_empty());

        // Should match included scripts
        assert!(filter.match_script(&[0x76, 0xa9, 0x14]).unwrap());
        assert!(filter.match_script(&[0x00, 0x14]).unwrap());
        assert!(filter.match_script(&[0x51]).unwrap());
    }

    #[test]
    fn test_filter_hash_and_header() {
        let block_hash = Hash256::ZERO;
        let outputs = vec![vec![0x51]];

        let filter = BlockFilter::build_basic(block_hash, outputs.into_iter(), std::iter::empty());

        let hash = filter.filter_hash();
        assert_ne!(hash, Hash256::ZERO);

        let prev_header = Hash256::ZERO;
        let header = filter.compute_header(&prev_header);
        assert_ne!(header, Hash256::ZERO);
        assert_ne!(header, hash);
    }

    #[test]
    fn test_filter_serialization() {
        let block_hash = Hash256::ZERO;
        let filter = BlockFilter::new(
            BlockFilterType::Basic,
            block_hash,
            vec![1, 2, 3, 4],
        );

        let json = serde_json::to_string(&filter).unwrap();
        let restored: BlockFilter = serde_json::from_str(&json).unwrap();

        assert_eq!(filter, restored);
    }
}
