//! P2P `headers` filter for blocks that failed validation.
//!
//! Core `AcceptBlockHeader` rejects a header whose hash or parent is
//! `BLOCK_FAILED_MASK` (`bad-prevblk`) and does not store it. The session set
//! is an O(1) cache of those hashes; the block index is the source of truth
//! after a restart.

use rustoshi_primitives::{BlockHeader, Hash256};
use std::collections::{HashMap, HashSet};

/// Drop headers that are themselves failed, or that descend from a failed
/// block. A dropped child is remembered so a later header in the same batch
/// (or a later batch) whose parent is that child is dropped too.
///
/// `index_invalid` reports whether the on-disk block index has
/// `FAILED_VALIDITY` or `FAILED_CHILD`. It is consulted even when the session
/// set is empty — that set is wiped by process restart.
pub fn filter_incoming_headers(
    headers: Vec<BlockHeader>,
    invalid_block_hashes: &mut HashSet<Hash256>,
    failed_child_parent: &mut HashMap<Hash256, Hash256>,
    index_invalid: impl Fn(&Hash256) -> bool,
) -> Vec<BlockHeader> {
    let mut kept = Vec::with_capacity(headers.len());
    for h in headers {
        let hh = h.block_hash();
        // The header itself already failed (session cache or the on-disk index).
        if invalid_block_hashes.contains(&hh) || index_invalid(&hh) {
            continue;
        }
        // Parent failed: Core AcceptBlockHeader returns bad-prevblk and does
        // not store the header. Remember the child so a grandchild in this
        // batch, whose parent was never indexed, is rejected too.
        if invalid_block_hashes.contains(&h.prev_block_hash) || index_invalid(&h.prev_block_hash)
        {
            invalid_block_hashes.insert(hh);
            if failed_child_parent.len() < 100_000 {
                failed_child_parent.insert(hh, h.prev_block_hash);
            }
            continue;
        }
        kept.push(h);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::BlockHeader;

    fn header_on(prev: Hash256, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::from([0xab; 32]),
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce,
        }
    }

    /// After restart the session set is empty. A header whose parent is
    /// `BLOCK_FAILED_VALID` on disk must still be rejected, and remembered so
    /// a grandchild in the same batch is rejected too.
    #[test]
    fn empty_session_still_rejects_child_of_index_failed_block() {
        let failed = Hash256::from([0x11; 32]);
        let child = header_on(failed, 1);
        let grandchild = header_on(child.block_hash(), 2);
        let mut session = HashSet::new();
        let mut failed_children = HashMap::new();
        let kept = filter_incoming_headers(
            vec![child.clone(), grandchild.clone()],
            &mut session,
            &mut failed_children,
            |hash| *hash == failed,
        );
        assert!(
            kept.is_empty(),
            "headers descending from a failed block must be dropped, kept {}",
            kept.len()
        );
        assert!(session.contains(&child.block_hash()));
        assert!(session.contains(&grandchild.block_hash()));
        assert_eq!(failed_children.get(&child.block_hash()), Some(&failed));
    }
}
