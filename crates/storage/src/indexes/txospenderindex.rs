//! Transaction-Output Spender Index.
//!
//! This module implements the txospenderindex, which maps a SPENT outpoint to
//! the transaction that spent it on-chain. For every input of every
//! non-coinbase transaction in a connected block it records a single key
//! mapping the spent outpoint -> the spending transaction's txid (plus the hash
//! of the block that confirmed the spend). It is the data source for the
//! confirmed-spend path of the `gettxspendingprevout` RPC.
//!
//! # Relationship to Bitcoin Core
//!
//! This mirrors Bitcoin Core's `TxoSpenderIndex`
//! (`bitcoin-core/src/index/txospenderindex.{h,cpp}`). Core stores the spending
//! tx's on-disk LOCATION (`CDiskTxPos`) keyed by a per-DB-salted
//! `siphash(outpoint)` and reads the tx back from the block files on lookup (a
//! flat-file optimisation that also lets it disambiguate siphash collisions and
//! serve the full spending tx). rustoshi stores the spending txid + block hash
//! directly under the exact spent outpoint — the simpler, faithful equivalent
//! the Core source comment explicitly allows ("a from-scratch implementation
//! may legitimately store outpoint -> spending-txid directly"). No salt and no
//! separate undo data are needed: the disconnect path (`revert_block`)
//! RE-DERIVES the exact same keys from the disconnected block's own inputs and
//! erases them, exactly like Core's `CustomRemove(BuildSpenderPositions(block))`.
//!
//! Default-off, gated by `-txospenderindex`, matching Core's
//! `DEFAULT_TXOSPENDERINDEX{false}`. This follows the same connect/disconnect
//! plumbing as the rustoshi coinstatsindex (`write_coinstats_index` /
//! `coinstats_disconnect_above`) and the blockbrew pilot
//! (`internal/storage/txospenderindex.go`, commit 77647fc).
//!
//! # References
//!
//! - Bitcoin Core: `src/index/txospenderindex.cpp`
//! - blockbrew pilot: `internal/storage/txospenderindex.go`

use crate::columns::CF_TXOSPENDER;
use crate::db::{ChainDb, StorageError};
use rustoshi_primitives::{Hash256, OutPoint};

/// State pointer key inside the index's own column family.
///
/// 5 bytes, so it can never collide with a 36-byte outpoint key
/// (`txid[32] + vout[4]`). Stores the index's best-block height (4 bytes BE) +
/// best-block hash (32 bytes), mirroring blockbrew's `TxoSpenderStateKey` and
/// Core's persisted best-block pointer (`BaseIndex::m_best_block_index`).
const TXOSPENDER_STATE_KEY: &[u8] = b"state";

/// Build the per-spend KV key for a spent outpoint:
/// `txid[32]` ++ `vout (4 bytes, big-endian)`.
///
/// Big-endian on the index keeps on-disk ordering grouped by outpoint txid,
/// matching the `CF_UTXO` key convention in `columns.rs` (txid + vout BE).
fn make_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.vout.to_be_bytes());
    key
}

/// Serialise the (spending txid, spending block hash) value: 64 bytes.
fn make_value(spending_txid: &Hash256, block_hash: &Hash256) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(spending_txid.as_bytes());
    buf[32..].copy_from_slice(block_hash.as_bytes());
    buf
}

/// The decoded value of a spender-index entry: which transaction spent the
/// queried outpoint, and the block it was confirmed in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxoSpender {
    /// The txid of the transaction that spent the outpoint.
    pub spending_txid: Hash256,
    /// The hash of the block that confirmed the spend.
    pub block_hash: Hash256,
}

fn deserialize_spender(data: &[u8]) -> Result<TxoSpender, TxoSpenderError> {
    if data.len() < 64 {
        return Err(TxoSpenderError::Storage(
            "txospenderindex value too short".to_string(),
        ));
    }
    let mut spending_txid = [0u8; 32];
    let mut block_hash = [0u8; 32];
    spending_txid.copy_from_slice(&data[..32]);
    block_hash.copy_from_slice(&data[32..64]);
    Ok(TxoSpender {
        spending_txid: Hash256(spending_txid),
        block_hash: Hash256(block_hash),
    })
}

/// Txo spender index errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxoSpenderError {
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<StorageError> for TxoSpenderError {
    fn from(e: StorageError) -> Self {
        TxoSpenderError::Storage(e.to_string())
    }
}

/// Transaction-output spender index providing storage, lookup, and reorg-safe
/// connect/disconnect maintenance of spent-outpoint -> spending-txid mappings.
pub struct TxoSpenderIndex<'a> {
    db: &'a ChainDb,
}

impl<'a> TxoSpenderIndex<'a> {
    /// Create a new txo spender index wrapping the given database.
    pub fn new(db: &'a ChainDb) -> Self {
        Self { db }
    }

    /// Look up the on-chain transaction that spends the given outpoint.
    ///
    /// Returns `Ok(Some(TxoSpender))` if a confirmed spend is recorded,
    /// `Ok(None)` if the outpoint is unspent on-chain, or `Err` on a DB /
    /// deserialization error. Mirrors Core's `TxoSpenderIndex::FindSpender`
    /// (which returns `std::nullopt` when unspent).
    pub fn find_spender(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<TxoSpender>, TxoSpenderError> {
        match self.db.get_cf(CF_TXOSPENDER, &make_key(outpoint))? {
            Some(data) => Ok(Some(deserialize_spender(&data)?)),
            None => Ok(None),
        }
    }

    /// Index every spend in a newly connected block: for each input of each
    /// non-coinbase transaction, write (spent outpoint -> spending txid ||
    /// block hash), then advance the persisted best-block pointer. All writes
    /// land in a single atomic RocksDB batch.
    ///
    /// Like Core's `CustomAppend(BuildSpenderPositions(block))`, every key is a
    /// pure function of the block's own inputs — no separate undo data is kept.
    /// The genesis block (height 0) has only the coinbase (null prevout), so it
    /// writes no spend keys, exactly as txindex/coinstatsindex skip it.
    pub fn write_block(
        &self,
        block: &rustoshi_primitives::Block,
        height: u32,
        block_hash: Hash256,
    ) -> Result<(), TxoSpenderError> {
        let mut batch = self.db.new_batch();
        let cf = self
            .db
            .cf_handle(CF_TXOSPENDER)
            .ok_or_else(|| TxoSpenderError::Storage("missing CF_TXOSPENDER".to_string()))?;

        for tx in &block.transactions {
            if tx.is_coinbase() {
                continue; // coinbase: null prevout, no real spend
            }
            let spending_txid = tx.txid();
            let value = make_value(&spending_txid, &block_hash);
            for input in &tx.inputs {
                batch.put_cf(cf, make_key(&input.previous_output), value);
            }
        }

        // Advance the best-block pointer in the same atomic batch.
        batch.put_cf(cf, TXOSPENDER_STATE_KEY, encode_state(height, &block_hash));

        self.db.write_batch(batch)?;
        Ok(())
    }

    /// Erase every spend recorded for a disconnected block. The keys are
    /// RE-DERIVED from the block's own inputs (no undo data needed), mirroring
    /// Core's `CustomRemove(BuildSpenderPositions(block))`. This is the
    /// reorg-safe undo. The caller passes the new best-block pointer
    /// (`prev_height` / `prev_hash` of the disconnected block) so the index's
    /// state pointer stays in lockstep with the chainstate after the rewind.
    pub fn revert_block(
        &self,
        block: &rustoshi_primitives::Block,
        prev_height: u32,
        prev_hash: Hash256,
    ) -> Result<(), TxoSpenderError> {
        let mut batch = self.db.new_batch();
        let cf = self
            .db
            .cf_handle(CF_TXOSPENDER)
            .ok_or_else(|| TxoSpenderError::Storage("missing CF_TXOSPENDER".to_string()))?;

        for tx in &block.transactions {
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.inputs {
                batch.delete_cf(cf, make_key(&input.previous_output));
            }
        }

        batch.put_cf(cf, TXOSPENDER_STATE_KEY, encode_state(prev_height, &prev_hash));

        self.db.write_batch(batch)?;
        Ok(())
    }

    /// Return the index's persisted best-block (height, hash), or `None` if the
    /// index has never been written. Used by `gettxspendingprevout` to decide
    /// whether the index is synced to the tip before consulting it (Core's
    /// `BlockUntilSyncedToCurrentChain`).
    pub fn best_block(&self) -> Result<Option<(u32, Hash256)>, TxoSpenderError> {
        match self.db.get_cf(CF_TXOSPENDER, TXOSPENDER_STATE_KEY)? {
            Some(data) => Ok(Some(decode_state(&data)?)),
            None => Ok(None),
        }
    }

    /// Best-block height, or `None` if never written.
    pub fn best_height(&self) -> Result<Option<u32>, TxoSpenderError> {
        Ok(self.best_block()?.map(|(h, _)| h))
    }
}

/// Encode the index state pointer: height (4 bytes BE) ++ block hash (32 bytes).
fn encode_state(height: u32, block_hash: &Hash256) -> [u8; 36] {
    let mut buf = [0u8; 36];
    buf[..4].copy_from_slice(&height.to_be_bytes());
    buf[4..].copy_from_slice(block_hash.as_bytes());
    buf
}

fn decode_state(data: &[u8]) -> Result<(u32, Hash256), TxoSpenderError> {
    if data.len() < 36 {
        return Err(TxoSpenderError::Storage(
            "txospenderindex state too short".to_string(),
        ));
    }
    let mut h = [0u8; 4];
    h.copy_from_slice(&data[..4]);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[4..36]);
    Ok((u32::from_be_bytes(h), Hash256(hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_key_layout() {
        let txid = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let op = OutPoint { txid, vout: 7 };
        let key = make_key(&op);
        assert_eq!(key.len(), 36);
        assert_eq!(&key[..32], txid.as_bytes());
        assert_eq!(&key[32..], &7u32.to_be_bytes());
    }

    #[test]
    fn test_value_roundtrip() {
        let spending = Hash256::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let bh = Hash256::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let v = make_value(&spending, &bh);
        let s = deserialize_spender(&v).unwrap();
        assert_eq!(s.spending_txid, spending);
        assert_eq!(s.block_hash, bh);
    }

    #[test]
    fn test_state_roundtrip() {
        let bh = Hash256::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        let enc = encode_state(123_456, &bh);
        let (h, hash) = decode_state(&enc).unwrap();
        assert_eq!(h, 123_456);
        assert_eq!(hash, bh);
    }

    #[test]
    fn test_short_value_errors() {
        assert!(deserialize_spender(&[0u8; 10]).is_err());
        assert!(decode_state(&[0u8; 10]).is_err());
    }
}
