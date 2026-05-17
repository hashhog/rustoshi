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
use rustoshi_consensus::validation::UndoData;
use rustoshi_primitives::{Block, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// BIP-157 checkpoint interval — see `bitcoin-core/src/index/blockfilterindex.h:31`:
///   `static constexpr int CFCHECKPT_INTERVAL = 1000;`
///
/// Walked by `ProcessGetCFCheckPt`: for every `(i+1) * CFCHECKPT_INTERVAL`
/// height up to `stop_index.nHeight / CFCHECKPT_INTERVAL`, the handler
/// returns the filter header at that exact height.  FIX-82 / W121 BUG-18.
pub const CFCHECKPT_INTERVAL: u32 = 1000;

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

    // ---------------- RANGE QUERY API (FIX-82) ----------------
    //
    // Mirrors Core's `BlockFilterIndex::LookupFilterRange` /
    // `LookupFilterHashRange` / `LookupFilterHeader` (index/blockfilterindex.cpp).
    // The P2P handlers in `main.rs` use these to assemble `cfilter`,
    // `cfheaders`, and `cfcheckpt` responses without doing one full block
    // load per height.

    /// Look up the filter header entry stored at the given block hash.
    ///
    /// Core: `BlockFilterIndex::LookupFilterHeader(const CBlockIndex*, uint256&)`.
    /// We index headers by *height* (not block hash) on disk for efficient
    /// range walks, so the caller must supply the height alongside the hash
    /// — typically resolved via `BlockStore::get_hash_by_height` for the
    /// active chain or via a stop-hash ancestor walk for non-active hashes.
    pub fn lookup_filter_header_at_height(
        &self,
        height: u32,
    ) -> Result<Option<Hash256>, BlockFilterError> {
        Ok(self
            .get_filter_header(height)?
            .map(|entry| entry.filter_header))
    }

    /// Look up the filter hashes for a contiguous height range
    /// `[start_height ..= stop_height]` on the active chain.
    ///
    /// `hash_lookup` is a callback that resolves height → block hash for the
    /// active chain (typically `BlockStore::get_hash_by_height`).  Returns
    /// the per-height filter_hash sequence so the caller can build a
    /// `cfheaders` body.  If any height is missing (e.g. the index is
    /// lagging), returns `Ok(None)` so the caller can defensively skip
    /// emitting a partial response — matches Core's
    /// `LookupFilterHashRange` returning false.
    pub fn lookup_filter_hash_range<F>(
        &self,
        start_height: u32,
        stop_height: u32,
        mut hash_lookup: F,
    ) -> Result<Option<Vec<Hash256>>, BlockFilterError>
    where
        F: FnMut(u32) -> Option<Hash256>,
    {
        if start_height > stop_height {
            return Ok(Some(Vec::new()));
        }
        let mut out = Vec::with_capacity((stop_height - start_height + 1) as usize);
        for h in start_height..=stop_height {
            let entry = match self.get_filter_header(h)? {
                Some(e) => e,
                None => return Ok(None),
            };
            // Defensively confirm the indexed block hash matches the active
            // chain's height index. If it doesn't, a reorg happened mid-walk
            // and we should not serve a stale chain to the peer.
            if let Some(active) = hash_lookup(h) {
                if entry.block_hash != active {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
            out.push(entry.filter_hash);
        }
        Ok(Some(out))
    }

    /// Look up the full filters for a contiguous height range
    /// `[start_height ..= stop_height]` on the active chain.
    ///
    /// Mirrors Core's `BlockFilterIndex::LookupFilterRange`.  Internally
    /// resolves each height to a block hash via `hash_lookup` (typically
    /// `BlockStore::get_hash_by_height`) then fetches the per-block filter
    /// row from CF_BLOCKFILTER. Returns `Ok(None)` if any filter or hash is
    /// missing (defensive: matches Core's bool return).
    pub fn lookup_filter_range<F>(
        &self,
        start_height: u32,
        stop_height: u32,
        mut hash_lookup: F,
    ) -> Result<Option<Vec<BlockFilter>>, BlockFilterError>
    where
        F: FnMut(u32) -> Option<Hash256>,
    {
        if start_height > stop_height {
            return Ok(Some(Vec::new()));
        }
        let mut out = Vec::with_capacity((stop_height - start_height + 1) as usize);
        for h in start_height..=stop_height {
            let hash = match hash_lookup(h) {
                Some(h) => h,
                None => return Ok(None),
            };
            let filter = match self.get_filter(&hash)? {
                Some(f) => f,
                None => return Ok(None),
            };
            out.push(filter);
        }
        Ok(Some(out))
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

    /// Connect a block to the filter index.
    ///
    /// Higher-level wrapper around [`index_block`] that:
    ///   - Extracts output scriptPubKeys from the block's transactions
    ///     (skipping OP_RETURN outputs, which `BlockFilter::build_basic`
    ///     also filters internally).
    ///   - Extracts spent scriptPubKeys from the `UndoData` returned by
    ///     `process_block`.
    ///   - Looks up the previous filter header from the index at `height-1`
    ///     (or uses `Hash256::ZERO` at genesis, height == 0).
    ///   - Calls `index_block` to persist the new filter + header.
    ///
    /// This is the canonical "BlockConnected" callback that mirrors Core's
    /// `BlockFilterIndex::CustomAppend` (index/blockfilterindex.cpp:250).
    /// Production code paths that call `ChainState::process_block` should
    /// invoke this immediately after a successful block connect.
    ///
    /// Returns the filter header for the connected block.
    pub fn connect_block(
        &self,
        height: u32,
        block: &Block,
        undo: &UndoData,
    ) -> Result<Hash256, BlockFilterError> {
        let block_hash = block.block_hash();

        // Look up the previous filter header. At genesis (height == 0) the
        // BIP-157 chain head is `Hash256::ZERO`; for any later height we
        // expect the index to already contain the prev entry (Core's
        // m_last_header invariant — see blockfilterindex.cpp:255).
        let prev_filter_header = if height == 0 {
            Hash256::ZERO
        } else {
            match self.get_filter_header(height - 1)? {
                Some(entry) => entry.filter_header,
                None => {
                    // Index lagging the chain (e.g. operator enabled
                    // -blockfilterindex mid-sync): start a new chain from
                    // ZERO so the filter still records, even though the
                    // resulting header chain will not match Core's until a
                    // backfill walks the gap.
                    tracing::warn!(
                        "BlockFilterIndex: missing prev filter header at height {} \
                         (block {}), starting new header chain from ZERO — full \
                         reindex required for header-chain Core parity",
                        height - 1,
                        block_hash,
                    );
                    Hash256::ZERO
                }
            }
        };

        // Output scripts (BlockFilter::build_basic skips OP_RETURN itself,
        // but we still collect every output here — dedupe happens in the
        // GCS construction via std::set semantics).
        let output_scripts = block
            .transactions
            .iter()
            .flat_map(|tx| tx.outputs.iter().map(|o| o.script_pubkey.clone()));

        // Spent scripts (from UndoData; coinbase has no spent inputs).
        let spent_scripts = undo
            .spent_coins
            .iter()
            .map(|c| c.script_pubkey.clone());

        self.index_block(
            height,
            block_hash,
            output_scripts,
            spent_scripts,
            &prev_filter_header,
        )
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
