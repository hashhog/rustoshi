//! Chain management operations for invalidating, reconsidering, and prioritizing blocks.
//!
//! This module implements the logic for:
//! - `invalidateblock`: Mark a block and all descendants as invalid
//! - `reconsiderblock`: Remove invalidity status from a block and related blocks
//! - `preciousblock`: Mark a block as precious for chain selection tie-breaking
//!
//! Reference: Bitcoin Core's validation.cpp (InvalidateBlock, ReconsiderBlock, PreciousBlock)

use rustoshi_primitives::Hash256;
use std::collections::HashMap;

/// Block status flags (matching storage::BlockStatus).
pub mod block_status {
    /// Block failed validation.
    pub const FAILED_VALIDITY: u32 = 32;
    /// Descendant of a failed block.
    pub const FAILED_CHILD: u32 = 64;
    /// Block has valid transactions.
    pub const VALID_TRANSACTIONS: u32 = 3;
    /// Block has full data.
    pub const HAVE_DATA: u32 = 8;
}

/// Error type for chain management operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChainManagementError {
    /// The specified block was not found.
    #[error("block not found: {0}")]
    BlockNotFound(String),

    /// Cannot invalidate the genesis block.
    #[error("cannot invalidate genesis block")]
    CannotInvalidateGenesis,

    /// Block disconnection failed.
    #[error("failed to disconnect block: {0}")]
    DisconnectFailed(String),

    /// Storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Chain state inconsistency.
    #[error("chain state inconsistency: {0}")]
    ChainStateError(String),
}

/// Metadata about a block for chain management.
#[derive(Clone, Debug)]
pub struct BlockMeta {
    /// Block hash.
    pub hash: Hash256,
    /// Block height.
    pub height: u32,
    /// Previous block hash.
    pub prev_hash: Hash256,
    /// Block status flags.
    pub status: u32,
    /// Total chain work (for comparison).
    pub chain_work: [u8; 32],
}

impl BlockMeta {
    /// Check if this block has failed validation.
    pub fn is_invalid(&self) -> bool {
        (self.status & block_status::FAILED_VALIDITY) != 0
            || (self.status & block_status::FAILED_CHILD) != 0
    }

    /// Check if this block has valid transactions.
    pub fn has_valid_transactions(&self) -> bool {
        (self.status & block_status::VALID_TRANSACTIONS) != 0
    }

    /// Check if this block has data.
    pub fn has_data(&self) -> bool {
        (self.status & block_status::HAVE_DATA) != 0
    }
}

/// Chain management state for tracking precious blocks.
#[derive(Debug, Default)]
pub struct ChainManagerState {
    /// Last chain work when precious block was called.
    /// Used to detect if the chain has grown since the last call.
    pub last_precious_chainwork: [u8; 32],

    /// Sequence ID counter for precious blocks (counts down).
    /// Lower sequence IDs are preferred in tie-breaking.
    pub block_reverse_sequence_id: i32,

    /// Sequence ID assignments for blocks.
    pub sequence_ids: HashMap<Hash256, i32>,
}

impl ChainManagerState {
    /// Create a new chain manager state.
    pub fn new() -> Self {
        Self {
            last_precious_chainwork: [0u8; 32],
            block_reverse_sequence_id: -1,
            sequence_ids: HashMap::new(),
        }
    }

    /// Get the sequence ID for a block, if any.
    pub fn get_sequence_id(&self, hash: &Hash256) -> Option<i32> {
        self.sequence_ids.get(hash).copied()
    }

    /// Assign a precious sequence ID to a block.
    ///
    /// Returns the assigned sequence ID.
    pub fn assign_precious_sequence(
        &mut self,
        hash: Hash256,
        current_tip_work: &[u8; 32],
    ) -> i32 {
        // If chain has grown since last call, reset the counter
        if compare_chain_work(current_tip_work, &self.last_precious_chainwork).is_gt() {
            self.block_reverse_sequence_id = -1;
        }
        self.last_precious_chainwork = *current_tip_work;

        // Assign the current sequence ID
        let seq_id = self.block_reverse_sequence_id;
        self.sequence_ids.insert(hash, seq_id);

        // Decrement for next call (unless at minimum)
        if self.block_reverse_sequence_id > i32::MIN {
            self.block_reverse_sequence_id -= 1;
        }

        seq_id
    }
}

/// Compare two 256-bit chain work values (big-endian).
///
/// Returns `Ordering::Greater` if `a > b`, `Ordering::Less` if `a < b`,
/// or `Ordering::Equal` if they are the same.
pub fn compare_chain_work(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    // Big-endian comparison: compare from most significant byte
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Check if `potential_ancestor` is an ancestor of `block` in the chain.
///
/// Uses the block index to walk back from `block` to verify ancestry.
pub fn is_ancestor<F>(
    potential_ancestor_hash: &Hash256,
    potential_ancestor_height: u32,
    block_hash: &Hash256,
    block_height: u32,
    get_block_meta: &F,
) -> bool
where
    F: Fn(&Hash256) -> Option<BlockMeta>,
{
    // If ancestor is higher than block, it can't be an ancestor
    if potential_ancestor_height > block_height {
        return false;
    }

    // Walk back from block to ancestor height
    let mut current_hash = *block_hash;
    let mut current_height = block_height;

    while current_height > potential_ancestor_height {
        match get_block_meta(&current_hash) {
            Some(meta) => {
                current_hash = meta.prev_hash;
                current_height = meta.height.saturating_sub(1);
            }
            None => return false,
        }
    }

    // Check if we arrived at the potential ancestor
    current_hash == *potential_ancestor_hash
}

/// Get the ancestor of a block at a specific height.
///
/// Returns `None` if the height is greater than the block's height or
/// if there's a break in the chain.
pub fn get_ancestor<F>(
    block_hash: &Hash256,
    block_height: u32,
    target_height: u32,
    get_block_meta: &F,
) -> Option<Hash256>
where
    F: Fn(&Hash256) -> Option<BlockMeta>,
{
    if target_height > block_height {
        return None;
    }

    let mut current_hash = *block_hash;
    let mut current_height = block_height;

    while current_height > target_height {
        match get_block_meta(&current_hash) {
            Some(meta) => {
                current_hash = meta.prev_hash;
                current_height = current_height.saturating_sub(1);
            }
            None => return None,
        }
    }

    Some(current_hash)
}

/// Check if a block is an ancestor OR descendant of the target block.
///
/// This is used by reconsider_block to find all related invalid blocks.
pub fn is_ancestor_or_descendant<F>(
    block_hash: &Hash256,
    block_height: u32,
    target_hash: &Hash256,
    target_height: u32,
    get_block_meta: &F,
) -> bool
where
    F: Fn(&Hash256) -> Option<BlockMeta>,
{
    // Check if target is ancestor of block
    if is_ancestor(target_hash, target_height, block_hash, block_height, get_block_meta) {
        return true;
    }

    // Check if block is ancestor of target
    if is_ancestor(block_hash, block_height, target_hash, target_height, get_block_meta) {
        return true;
    }

    false
}

/// Find all descendants of a block in the block index.
///
/// This is used by invalidate_block to mark all descendants as failed.
pub fn find_descendants<F, I>(
    ancestor_hash: &Hash256,
    ancestor_height: u32,
    all_blocks: I,
    get_block_meta: &F,
) -> Vec<Hash256>
where
    F: Fn(&Hash256) -> Option<BlockMeta>,
    I: Iterator<Item = Hash256>,
{
    let mut descendants = Vec::new();

    for hash in all_blocks {
        if hash == *ancestor_hash {
            continue;
        }

        if let Some(meta) = get_block_meta(&hash) {
            if meta.height > ancestor_height
                && is_ancestor(ancestor_hash, ancestor_height, &hash, meta.height, get_block_meta)
            {
                descendants.push(hash);
            }
        }
    }

    descendants
}

/// Result of invalidating a block.
#[derive(Debug)]
pub struct InvalidateBlockResult {
    /// Blocks that were disconnected from the active chain.
    pub disconnected_blocks: Vec<Hash256>,
    /// Blocks that were marked as invalid (including descendants).
    pub invalidated_blocks: Vec<Hash256>,
    /// The new chain tip after invalidation.
    pub new_tip: Hash256,
    /// Height of the new tip.
    pub new_tip_height: u32,
}

/// Result of reconsidering a block.
#[derive(Debug)]
pub struct ReconsiderBlockResult {
    /// Blocks that had their invalid status cleared.
    pub reconsidered_blocks: Vec<Hash256>,
    /// Whether a reorg occurred to include the reconsidered block.
    pub reorg_occurred: bool,
    /// The new chain tip after reconsideration.
    pub new_tip: Hash256,
    /// Height of the new tip.
    pub new_tip_height: u32,
}

/// Result of marking a block as precious.
#[derive(Debug)]
pub struct PreciousBlockResult {
    /// The sequence ID assigned to the block.
    pub sequence_id: i32,
    /// Whether a reorg occurred due to the precious designation.
    pub reorg_occurred: bool,
    /// The new chain tip after the operation.
    pub new_tip: Hash256,
    /// Height of the new tip.
    pub new_tip_height: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(byte: u8) -> Hash256 {
        Hash256([byte; 32])
    }

    #[test]
    fn test_compare_chain_work() {
        let low = [0u8; 32];
        let high = {
            let mut h = [0u8; 32];
            h[31] = 1;
            h
        };
        let higher = {
            let mut h = [0u8; 32];
            h[0] = 1;
            h
        };

        assert_eq!(compare_chain_work(&low, &low), std::cmp::Ordering::Equal);
        assert_eq!(compare_chain_work(&low, &high), std::cmp::Ordering::Less);
        assert_eq!(compare_chain_work(&high, &low), std::cmp::Ordering::Greater);
        assert_eq!(
            compare_chain_work(&higher, &high),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_is_ancestor() {
        // Build a simple chain: A -> B -> C
        let hash_a = make_hash(0);
        let hash_b = make_hash(1);
        let hash_c = make_hash(2);

        let blocks: HashMap<Hash256, BlockMeta> = [
            (
                hash_a,
                BlockMeta {
                    hash: hash_a,
                    height: 0,
                    prev_hash: Hash256::ZERO,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_b,
                BlockMeta {
                    hash: hash_b,
                    height: 1,
                    prev_hash: hash_a,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_c,
                BlockMeta {
                    hash: hash_c,
                    height: 2,
                    prev_hash: hash_b,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
        ]
        .into_iter()
        .collect();

        let get_meta = |h: &Hash256| blocks.get(h).cloned();

        // A is ancestor of C
        assert!(is_ancestor(&hash_a, 0, &hash_c, 2, &get_meta));
        // B is ancestor of C
        assert!(is_ancestor(&hash_b, 1, &hash_c, 2, &get_meta));
        // A is ancestor of B
        assert!(is_ancestor(&hash_a, 0, &hash_b, 1, &get_meta));
        // C is NOT ancestor of A (wrong direction)
        assert!(!is_ancestor(&hash_c, 2, &hash_a, 0, &get_meta));
        // A is NOT ancestor of itself (same block doesn't count)
        // Actually, let's check - same block at same height...
        // Walking back 0 steps from A at height 0 gives us A, which equals A
        assert!(is_ancestor(&hash_a, 0, &hash_a, 0, &get_meta));
    }

    #[test]
    fn test_find_descendants() {
        // Build a forking chain:
        //     A
        //    / \
        //   B   C
        //   |
        //   D
        let hash_a = make_hash(0);
        let hash_b = make_hash(1);
        let hash_c = make_hash(2);
        let hash_d = make_hash(3);

        let blocks: HashMap<Hash256, BlockMeta> = [
            (
                hash_a,
                BlockMeta {
                    hash: hash_a,
                    height: 0,
                    prev_hash: Hash256::ZERO,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_b,
                BlockMeta {
                    hash: hash_b,
                    height: 1,
                    prev_hash: hash_a,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_c,
                BlockMeta {
                    hash: hash_c,
                    height: 1,
                    prev_hash: hash_a,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_d,
                BlockMeta {
                    hash: hash_d,
                    height: 2,
                    prev_hash: hash_b,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
        ]
        .into_iter()
        .collect();

        let get_meta = |h: &Hash256| blocks.get(h).cloned();
        let all_blocks = blocks.keys().cloned();

        // Descendants of A should be B, C, D
        let descendants = find_descendants(&hash_a, 0, all_blocks.clone(), &get_meta);
        assert_eq!(descendants.len(), 3);
        assert!(descendants.contains(&hash_b));
        assert!(descendants.contains(&hash_c));
        assert!(descendants.contains(&hash_d));

        // Descendants of B should be D only
        let descendants = find_descendants(&hash_b, 1, all_blocks.clone(), &get_meta);
        assert_eq!(descendants.len(), 1);
        assert!(descendants.contains(&hash_d));

        // Descendants of C should be empty
        let descendants = find_descendants(&hash_c, 1, all_blocks.clone(), &get_meta);
        assert!(descendants.is_empty());
    }

    #[test]
    fn test_chain_manager_state_precious() {
        let mut state = ChainManagerState::new();
        let hash_a = make_hash(1);
        let hash_b = make_hash(2);

        let work1 = [0u8; 32];
        let mut work2 = [0u8; 32];
        work2[31] = 1;

        // First precious call
        let seq1 = state.assign_precious_sequence(hash_a, &work1);
        assert_eq!(seq1, -1);

        // Second precious call (same work)
        let seq2 = state.assign_precious_sequence(hash_b, &work1);
        assert_eq!(seq2, -2);

        // Third call with higher work - should reset counter
        let mut work3 = [0u8; 32];
        work3[30] = 1;
        let seq3 = state.assign_precious_sequence(hash_a, &work3);
        assert_eq!(seq3, -1);

        // Check we can retrieve sequence IDs
        assert_eq!(state.get_sequence_id(&hash_a), Some(-1));
        assert_eq!(state.get_sequence_id(&hash_b), Some(-2));
    }

    #[test]
    fn test_is_ancestor_or_descendant() {
        // Chain: A -> B -> C
        // Note: hash_a must NOT be Hash256::ZERO to avoid false positive matches
        let hash_a = make_hash(1);
        let hash_b = make_hash(2);
        let hash_c = make_hash(3);
        let hash_d = make_hash(4); // Unrelated

        // D's prev_hash is Hash256::ZERO (unrelated chain rooted at genesis/zero)
        // hash_a must not equal Hash256::ZERO to avoid false positive in is_ancestor check
        let blocks: HashMap<Hash256, BlockMeta> = [
            (
                hash_a,
                BlockMeta {
                    hash: hash_a,
                    height: 0,
                    prev_hash: Hash256::ZERO,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_b,
                BlockMeta {
                    hash: hash_b,
                    height: 1,
                    prev_hash: hash_a,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_c,
                BlockMeta {
                    hash: hash_c,
                    height: 2,
                    prev_hash: hash_b,
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
            (
                hash_d,
                BlockMeta {
                    hash: hash_d,
                    height: 1,
                    prev_hash: Hash256::ZERO, // Unrelated chain
                    status: 0,
                    chain_work: [0u8; 32],
                },
            ),
        ]
        .into_iter()
        .collect();

        let get_meta = |h: &Hash256| blocks.get(h).cloned();

        // A and C are related (A is ancestor of C)
        assert!(is_ancestor_or_descendant(&hash_a, 0, &hash_c, 2, &get_meta));
        assert!(is_ancestor_or_descendant(&hash_c, 2, &hash_a, 0, &get_meta));

        // B and C are related
        assert!(is_ancestor_or_descendant(&hash_b, 1, &hash_c, 2, &get_meta));

        // D is not related to anyone
        assert!(!is_ancestor_or_descendant(&hash_d, 1, &hash_a, 0, &get_meta));
        assert!(!is_ancestor_or_descendant(&hash_d, 1, &hash_c, 2, &get_meta));
    }
}
