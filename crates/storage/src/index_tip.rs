//! Per-index "built through" markers for the optional indexes (ARCH-2 R-1).
//!
//! Bitcoin Core runs each optional index (txindex, blockfilterindex) as a
//! separate `BaseIndex` with its own best-block locator
//! (`bitcoin-core/src/index/base.cpp:90` `WriteBestBlock`). An index that is
//! disabled is never written (`DEFAULT_TXINDEX{false}`,
//! `DEFAULT_BLOCKFILTERINDEX "0"`), and enabling it later makes it sync from
//! its own locator, reporting `synced:false` until it reaches the tip
//! (`index/base.cpp:145`, `rpc/rawtransaction.cpp:308-326`).
//!
//! rustoshi used to write `CF_TX_INDEX` and `CF_BLOCKFILTER{,_HEADER}` on
//! every connect regardless of the operator's flags. Now the rows are written
//! only when the index is enabled, and each index keeps a marker in `CF_META`
//! recording the last block it has *contiguously* indexed:
//!
//! * `idx_tip/tx`, `idx_tip/blockfilter` — 36 bytes: height (u32 LE) ‖ block
//!   hash, or 0 bytes meaning "nothing indexed yet".
//! * The marker advances only from its parent (`height-1`, `prev_hash`) to
//!   the block being indexed (or stays put on an idempotent re-index). A block
//!   indexed after a gap writes its rows but does NOT advance the marker, so
//!   the marker can never claim coverage the index does not have. A disabled
//!   index's marker therefore freezes where the operator turned it off.
//! * An index is synced iff it is enabled and its marker is the active tip
//!   (hash checked against the active chain, so a reorg below the marker is
//!   seen as a gap, like Core's locator fork-point check).
//!
//! Additive (no `CURRENT_DB_VERSION` bump): an older binary ignores the keys.
//! The rollback hazard is the reverse — an older binary on a datadir that ran
//! with an index OFF sees a gap it cannot detect (DEPLOY-NOTE).

use crate::block_store::{BlockStore, TxIndexEntry};
use crate::columns::{CF_META, CF_TX_INDEX};
use crate::db::StorageError;
use rocksdb::WriteBatch;
use rustoshi_primitives::{Block, Hash256};

/// Meta key: txindex built-through marker.
pub const META_INDEX_TIP_TX: &[u8] = b"idx_tip/tx";
/// Meta key: basic block filter index built-through marker.
pub const META_INDEX_TIP_BLOCKFILTER: &[u8] = b"idx_tip/blockfilter";

/// The optional indexes that carry a built-through marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionalIndex {
    /// `-txindex`
    Tx,
    /// `-blockfilterindex=basic`
    BlockFilter,
}

impl OptionalIndex {
    fn key(self) -> &'static [u8] {
        match self {
            OptionalIndex::Tx => META_INDEX_TIP_TX,
            OptionalIndex::BlockFilter => META_INDEX_TIP_BLOCKFILTER,
        }
    }

    /// Short name for logs.
    pub fn name(self) -> &'static str {
        match self {
            OptionalIndex::Tx => "txindex",
            OptionalIndex::BlockFilter => "blockfilterindex",
        }
    }
}

/// A stored built-through marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexTip {
    /// The index holds nothing yet (fresh datadir with the index off).
    Empty,
    /// Every block from genesis through `(height, hash)` on that block's
    /// chain is indexed.
    At { height: u32, hash: Hash256 },
}

impl IndexTip {
    fn encode(self) -> Vec<u8> {
        match self {
            IndexTip::Empty => Vec::new(),
            IndexTip::At { height, hash } => {
                let mut v = Vec::with_capacity(36);
                v.extend_from_slice(&height.to_le_bytes());
                v.extend_from_slice(hash.as_bytes());
                v
            }
        }
    }

    fn decode(b: &[u8]) -> Result<Self, StorageError> {
        match b.len() {
            0 => Ok(IndexTip::Empty),
            36 => {
                let mut h = [0u8; 4];
                h.copy_from_slice(&b[..4]);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&b[4..]);
                Ok(IndexTip::At { height: u32::from_le_bytes(h), hash: Hash256(hash) })
            }
            n => Err(StorageError::Corruption(format!("index tip marker is {} bytes", n))),
        }
    }

    /// Height of the marker; `None` for [`IndexTip::Empty`].
    pub fn height(self) -> Option<u32> {
        match self {
            IndexTip::Empty => None,
            IndexTip::At { height, .. } => Some(height),
        }
    }
}

/// Whether indexing block `(height, hash)` with parent `prev_hash` advances a
/// marker currently at `cur`. Pure; the contiguity rule described in the
/// module docs.
pub fn index_tip_advances(cur: Option<IndexTip>, height: u32, hash: Hash256, prev_hash: Hash256) -> bool {
    match cur {
        Some(IndexTip::At { height: h, hash: x }) => {
            (height > 0 && h == height - 1 && x == prev_hash) || (h == height && x == hash)
        }
        Some(IndexTip::Empty) => height == 0,
        // No marker at all: boot migration has not run (unit tests, tools).
        // Do not invent coverage.
        None => false,
    }
}

impl<'a> BlockStore<'a> {
    /// Read an index's built-through marker. `Ok(None)` = no key (a datadir
    /// written before markers existed, or a store opened without the boot
    /// migration).
    pub fn get_index_tip(&self, kind: OptionalIndex) -> Result<Option<IndexTip>, StorageError> {
        match self.db().get_cf(CF_META, kind.key())? {
            Some(b) => Ok(Some(IndexTip::decode(&b)?)),
            None => Ok(None),
        }
    }

    /// Write an index's marker immediately.
    pub fn set_index_tip(&self, kind: OptionalIndex, tip: IndexTip) -> Result<(), StorageError> {
        self.db().put_cf(CF_META, kind.key(), &tip.encode())
    }

    /// Stage an index's marker into `batch`.
    pub fn batch_set_index_tip(
        &self,
        batch: &mut WriteBatch,
        kind: OptionalIndex,
        tip: IndexTip,
    ) -> Result<(), StorageError> {
        let cf = self.db().cf_handle(CF_META).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_META))
        })?;
        batch.put_cf(cf, kind.key(), tip.encode());
        Ok(())
    }

    /// Advance `kind`'s marker to `(height, hash)` if it is contiguous with
    /// the current marker. Returns whether it advanced.
    pub fn advance_index_tip(
        &self,
        kind: OptionalIndex,
        height: u32,
        hash: Hash256,
        prev_hash: Hash256,
    ) -> Result<bool, StorageError> {
        let cur = self.get_index_tip(kind)?;
        if index_tip_advances(cur, height, hash, prev_hash) {
            if cur != Some(IndexTip::At { height, hash }) {
                self.set_index_tip(kind, IndexTip::At { height, hash })?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Write the txindex rows of one connected block and, when contiguous,
    /// advance the txindex marker — one atomic batch (one write per block
    /// instead of one `put_cf` per transaction). Callers invoke this only when
    /// `-txindex` is on. A failed write latches AbortNode (gate 6) through
    /// [`crate::db::ChainDb::write_batch`], as every other chainstate write.
    pub fn write_tx_index_block(
        &self,
        block: &Block,
        hash: Hash256,
        height: u32,
    ) -> Result<bool, StorageError> {
        let mut batch = self.new_batch();
        let cf = self.db().cf_handle(CF_TX_INDEX).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_TX_INDEX))
        })?;
        for tx in &block.transactions {
            let entry = TxIndexEntry { block_hash: hash, tx_offset: 0, tx_length: 0 };
            batch.put_cf(cf, tx.txid().as_bytes(), crate::block_store::format_v2::encode_tx_index_entry(&entry));
        }
        let advanced = index_tip_advances(
            self.get_index_tip(OptionalIndex::Tx)?,
            height,
            hash,
            block.header.prev_block_hash,
        );
        if advanced {
            self.batch_set_index_tip(&mut batch, OptionalIndex::Tx, IndexTip::At { height, hash })?;
        }
        self.write_batch(batch)?;
        Ok(advanced)
    }

    /// `(synced, best_block_height)` of an ENABLED index against the active
    /// tip `(tip_height, tip_hash)`, for `getindexinfo` and the
    /// "still being indexed" RPC messages. Synced iff the marker is the tip
    /// itself (or is past `tip_height` on the active chain, when a connect
    /// has advanced it before the caller's view of the tip). A marker whose
    /// hash is off the active chain is a gap (reorg below it while off).
    pub fn index_sync_state(
        &self,
        kind: OptionalIndex,
        tip_height: u32,
        tip_hash: &Hash256,
    ) -> Result<(bool, u32), StorageError> {
        match self.get_index_tip(kind)? {
            None | Some(IndexTip::Empty) => Ok((false, 0)),
            Some(IndexTip::At { height, hash }) => {
                let on_chain = if height == tip_height {
                    hash == *tip_hash
                } else {
                    self.get_hash_by_height(height)? == Some(hash)
                };
                Ok((on_chain && height >= tip_height, height))
            }
        }
    }

    /// Whether `(height, hash)` is covered by `kind`'s marker: at or below
    /// the marker height and on the marker's chain. Used to refuse a
    /// block-filter read past a gap (headers there chain from ZERO).
    pub fn index_covers(
        &self,
        kind: OptionalIndex,
        height: u32,
        hash: &Hash256,
    ) -> Result<bool, StorageError> {
        match self.get_index_tip(kind)? {
            None | Some(IndexTip::Empty) => Ok(false),
            Some(IndexTip::At { height: mh, hash: mhash }) => {
                if height > mh {
                    return Ok(false);
                }
                // The marker's own block must still be on the active chain,
                // and so must the queried block.
                Ok(self.get_hash_by_height(mh)? == Some(mhash)
                    && self.get_hash_by_height(height)? == Some(*hash))
            }
        }
    }

    /// One-time boot migration for datadirs written before markers existed.
    ///
    /// Every rustoshi binary before R-1 wrote both indexes on every connect,
    /// so a datadir with a chain but no marker is taken to be indexed through
    /// its stored tip — whatever the flags say now (a disabled index then
    /// freezes there, and turning it back on later reports the gap). A fresh
    /// datadir (tip at genesis or absent) starts the txindex at genesis, which
    /// Core never indexes (`index/txindex.cpp:76`), and the filter index at
    /// genesis only if its genesis filter was written. A datadir whose chain
    /// came from an assumeutxo snapshot (`snapshot_based`) never had the
    /// blocks below the snapshot base connected, so neither index covers them:
    /// both start [`IndexTip::Empty`] (enabling one then honestly reports
    /// synced:false instead of claiming coverage from genesis). Returns what
    /// was written per index.
    pub fn migrate_index_tips(
        &self,
        genesis_hash: Hash256,
        genesis_filter_indexed: bool,
        snapshot_based: bool,
    ) -> Result<Vec<(OptionalIndex, IndexTip)>, StorageError> {
        let tip = match (self.get_best_height()?, self.get_best_block_hash()?) {
            (Some(h), Some(hash)) if h > 0 => Some((h, hash)),
            _ => None,
        };
        let mut out = Vec::new();
        for kind in [OptionalIndex::Tx, OptionalIndex::BlockFilter] {
            if self.get_index_tip(kind)?.is_some() {
                continue;
            }
            let t = match (tip, kind) {
                (Some(_), _) if snapshot_based => IndexTip::Empty,
                (Some((height, hash)), _) => IndexTip::At { height, hash },
                (None, OptionalIndex::Tx) => IndexTip::At { height: 0, hash: genesis_hash },
                (None, OptionalIndex::BlockFilter) if genesis_filter_indexed => {
                    IndexTip::At { height: 0, hash: genesis_hash }
                }
                (None, OptionalIndex::BlockFilter) => IndexTip::Empty,
            };
            self.set_index_tip(kind, t)?;
            out.push((kind, t));
        }
        Ok(out)
    }

    /// Reorg bookkeeping for an ENABLED index: if the marker sits on the
    /// active chain above `fork_height`, stage it back to
    /// `(fork_height, fork_hash)` (the rows above were deleted in the same
    /// batch); a later contiguous connect moves it forward again. A marker at
    /// or below the fork point, or already off-chain, is left alone.
    pub fn batch_rewind_index_tip(
        &self,
        batch: &mut WriteBatch,
        kind: OptionalIndex,
        fork_height: u32,
        fork_hash: Hash256,
    ) -> Result<bool, StorageError> {
        if let Some(IndexTip::At { height, hash }) = self.get_index_tip(kind)? {
            if height > fork_height && self.get_hash_by_height(height)? == Some(hash) {
                self.batch_set_index_tip(
                    batch,
                    kind,
                    IndexTip::At { height: fork_height, hash: fork_hash },
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ChainDb;
    use rustoshi_primitives::{BlockHeader, OutPoint, Transaction, TxIn, TxOut};
    use tempfile::tempdir;

    fn h(n: u8) -> Hash256 {
        Hash256([n; 32])
    }

    #[test]
    fn marker_roundtrip_and_contiguity() {
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        assert_eq!(store.get_index_tip(OptionalIndex::Tx).unwrap(), None);
        store.set_index_tip(OptionalIndex::Tx, IndexTip::At { height: 5, hash: h(5) }).unwrap();
        assert_eq!(
            store.get_index_tip(OptionalIndex::Tx).unwrap(),
            Some(IndexTip::At { height: 5, hash: h(5) })
        );
        // gap: 7 on top of 5 does not advance
        assert!(!store.advance_index_tip(OptionalIndex::Tx, 7, h(7), h(6)).unwrap());
        // wrong parent at 6 does not advance
        assert!(!store.advance_index_tip(OptionalIndex::Tx, 6, h(6), h(99)).unwrap());
        // contiguous child advances, then idempotent re-index stays
        assert!(store.advance_index_tip(OptionalIndex::Tx, 6, h(6), h(5)).unwrap());
        assert!(store.advance_index_tip(OptionalIndex::Tx, 6, h(6), h(5)).unwrap());
        assert_eq!(store.get_index_tip(OptionalIndex::Tx).unwrap().unwrap().height(), Some(6));
        // the other index is independent
        assert_eq!(store.get_index_tip(OptionalIndex::BlockFilter).unwrap(), None);
        store.set_index_tip(OptionalIndex::BlockFilter, IndexTip::Empty).unwrap();
        assert_eq!(store.get_index_tip(OptionalIndex::BlockFilter).unwrap(), Some(IndexTip::Empty));
        assert!(!index_tip_advances(Some(IndexTip::Empty), 1, h(1), h(0)));
        assert!(index_tip_advances(Some(IndexTip::Empty), 0, h(0), Hash256::ZERO));
        assert!(!index_tip_advances(None, 6, h(6), h(5)));
    }

    #[test]
    fn migration_legacy_vs_fresh() {
        // legacy datadir: chain at 100, no markers -> both indexed through 100
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        store.set_best_block(&h(100), 100).unwrap();
        let w = store.migrate_index_tips(h(0), false, false).unwrap();
        assert_eq!(w.len(), 2);
        for k in [OptionalIndex::Tx, OptionalIndex::BlockFilter] {
            assert_eq!(store.get_index_tip(k).unwrap(), Some(IndexTip::At { height: 100, hash: h(100) }));
        }
        // runs once: a later boot leaves markers alone
        store.set_best_block(&h(200), 200).unwrap();
        assert!(store.migrate_index_tips(h(0), false, false).unwrap().is_empty());
        assert_eq!(store.get_index_tip(OptionalIndex::Tx).unwrap().unwrap().height(), Some(100));

        // fresh datadir with the filter index off
        let dir2 = tempdir().unwrap();
        let db2 = ChainDb::open(dir2.path()).unwrap();
        let s2 = BlockStore::new(&db2);
        s2.migrate_index_tips(h(0), false, false).unwrap();
        assert_eq!(s2.get_index_tip(OptionalIndex::Tx).unwrap(), Some(IndexTip::At { height: 0, hash: h(0) }));
        assert_eq!(s2.get_index_tip(OptionalIndex::BlockFilter).unwrap(), Some(IndexTip::Empty));

        // legacy datadir whose chain came from a snapshot: nothing below the
        // base was ever indexed, so neither index claims coverage
        let dir3 = tempdir().unwrap();
        let db3 = ChainDb::open(dir3.path()).unwrap();
        let s3 = BlockStore::new(&db3);
        s3.set_best_block(&h(100), 100).unwrap();
        s3.migrate_index_tips(h(0), false, true).unwrap();
        for k in [OptionalIndex::Tx, OptionalIndex::BlockFilter] {
            assert_eq!(s3.get_index_tip(k).unwrap(), Some(IndexTip::Empty));
        }
    }

    fn block_on(prev: Hash256, tag: u8) -> Block {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
                script_sig: vec![tag, 0x51],
                sequence: u32::MAX,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50, script_pubkey: vec![0x51] }],
            lock_time: 0,
        };
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: prev,
                merkle_root: tx.txid(),
                timestamp: tag as u32,
                bits: 0x207fffff,
                nonce: tag as u32,
            },
            transactions: vec![tx],
        }
    }

    #[test]
    fn tx_index_block_batch_and_sync_state() {
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        store.set_index_tip(OptionalIndex::Tx, IndexTip::At { height: 0, hash: h(0) }).unwrap();
        let b1 = block_on(h(0), 1);
        let b1h = b1.block_hash();
        store.put_height_index(1, &b1h).unwrap();
        assert!(store.write_tx_index_block(&b1, b1h, 1).unwrap());
        assert_eq!(
            store.get_tx_index(&b1.transactions[0].txid()).unwrap().unwrap().block_hash,
            b1h
        );
        assert_eq!(store.index_sync_state(OptionalIndex::Tx, 1, &b1h).unwrap(), (true, 1));
        // tip moved on without the index (index off for block 2): not synced
        let b2 = block_on(b1h, 2);
        store.put_height_index(2, &b2.block_hash()).unwrap();
        assert_eq!(store.index_sync_state(OptionalIndex::Tx, 2, &b2.block_hash()).unwrap(), (false, 1));
        // block 3 indexed after the gap: rows written, marker does not move
        let b3 = block_on(b2.block_hash(), 3);
        assert!(!store.write_tx_index_block(&b3, b3.block_hash(), 3).unwrap());
        assert!(store.get_tx_index(&b3.transactions[0].txid()).unwrap().is_some());
        assert_eq!(store.get_index_tip(OptionalIndex::Tx).unwrap().unwrap().height(), Some(1));
        assert!(store.index_covers(OptionalIndex::Tx, 1, &b1h).unwrap());
        assert!(!store.index_covers(OptionalIndex::Tx, 2, &b2.block_hash()).unwrap());
        // reorg replaces block 1 below the marker: marker is off-chain -> gap
        store.put_height_index(1, &h(42)).unwrap();
        assert_eq!(store.index_sync_state(OptionalIndex::Tx, 1, &h(42)).unwrap(), (false, 1));
    }

    #[test]
    fn rewind_on_disconnect() {
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        store.put_height_index(9, &h(9)).unwrap();
        store.put_height_index(10, &h(10)).unwrap();
        store.set_index_tip(OptionalIndex::Tx, IndexTip::At { height: 10, hash: h(10) }).unwrap();
        let mut batch = store.new_batch();
        assert!(store.batch_rewind_index_tip(&mut batch, OptionalIndex::Tx, 9, h(9)).unwrap());
        store.write_batch(batch).unwrap();
        assert_eq!(store.get_index_tip(OptionalIndex::Tx).unwrap(), Some(IndexTip::At { height: 9, hash: h(9) }));
        // a marker below the fork point is left alone
        let mut batch = store.new_batch();
        assert!(!store.batch_rewind_index_tip(&mut batch, OptionalIndex::Tx, 9, h(9)).unwrap());
    }
}
