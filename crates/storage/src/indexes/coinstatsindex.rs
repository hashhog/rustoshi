//! Coin Statistics Index.
//!
//! This module implements the coinstatsindex, which tracks per-block statistics
//! about the UTXO set, including:
//!
//! - Total number of UTXOs
//! - Total value in satoshis
//! - MuHash of the UTXO set (for consistency verification)
//! - Total block subsidy
//! - Various unspendable output categories
//!
//! # Use Cases
//!
//! - `gettxoutsetinfo` RPC for UTXO set statistics
//! - Chain state verification via MuHash comparison
//! - Supply auditing
//!
//! # References
//!
//! - Bitcoin Core: `src/index/coinstatsindex.cpp`

use crate::columns::CF_COINSTATS;
use crate::db::{ChainDb, StorageError};
use crate::indexes::muhash::MuHash3072;
use rustoshi_primitives::Hash256;
use serde::{Deserialize, Serialize};

/// UTXO set statistics at a specific block height.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinStatsEntry {
    /// Block height.
    pub height: u32,
    /// Block hash.
    pub block_hash: Hash256,
    /// Total number of UTXOs.
    pub utxo_count: u64,
    /// Total value of all UTXOs in satoshis.
    pub total_amount: u64,
    /// Estimated serialized size of the UTXO set (bogosize).
    pub bogo_size: u64,
    /// Total block subsidy up to this height.
    pub total_subsidy: u64,
    /// Total value of prevouts spent (cumulative).
    pub total_prevout_spent_amount: u64,
    /// Total value of new outputs (excluding coinbase).
    pub total_new_outputs_ex_coinbase: u64,
    /// Total value of coinbase outputs.
    pub total_coinbase_amount: u64,
    /// Unspendable: genesis block reward.
    pub unspendables_genesis: u64,
    /// Unspendable: BIP30 duplicate coinbase.
    pub unspendables_bip30: u64,
    /// Unspendable: OP_RETURN and provably unspendable scripts.
    pub unspendables_scripts: u64,
    /// Unspendable: unclaimed block rewards.
    pub unspendables_unclaimed: u64,
    /// MuHash of the UTXO set (serialized as Vec<u8> for serde compatibility).
    pub muhash: Vec<u8>,
}

impl Default for CoinStatsEntry {
    fn default() -> Self {
        Self {
            height: 0,
            block_hash: Hash256::ZERO,
            utxo_count: 0,
            total_amount: 0,
            bogo_size: 0,
            total_subsidy: 0,
            total_prevout_spent_amount: 0,
            total_new_outputs_ex_coinbase: 0,
            total_coinbase_amount: 0,
            unspendables_genesis: 0,
            unspendables_bip30: 0,
            unspendables_scripts: 0,
            unspendables_unclaimed: 0,
            muhash: vec![0u8; 768],
        }
    }
}

impl CoinStatsEntry {
    /// Create a new entry for the genesis block.
    pub fn genesis(block_hash: Hash256, genesis_subsidy: u64) -> Self {
        Self {
            height: 0,
            block_hash,
            total_subsidy: genesis_subsidy,
            // Genesis block reward is unspendable (Bitcoin Core quirk)
            unspendables_genesis: genesis_subsidy,
            ..Default::default()
        }
    }

    /// Get the MuHash accumulator from the stored bytes.
    pub fn get_muhash(&self) -> MuHash3072 {
        if self.muhash.len() == 768 {
            let mut arr = [0u8; 768];
            arr.copy_from_slice(&self.muhash);
            MuHash3072::from_bytes(&arr)
        } else {
            MuHash3072::new()
        }
    }

    /// Store a MuHash accumulator's state.
    pub fn set_muhash(&mut self, muhash: &MuHash3072) {
        self.muhash = muhash.to_bytes().to_vec();
    }

    /// Compute the total unspendable amount.
    pub fn total_unspendable(&self) -> u64 {
        self.unspendables_genesis
            + self.unspendables_bip30
            + self.unspendables_scripts
            + self.unspendables_unclaimed
    }

    /// Compute the circulating supply (total mined - unspendable).
    pub fn circulating_supply(&self) -> u64 {
        self.total_subsidy.saturating_sub(self.total_unspendable())
    }
}

/// Coin statistics index errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoinStatsError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("stats not found for height {0}")]
    NotFound(u32),
    #[error("invalid muhash state")]
    InvalidMuHash,
}

impl From<StorageError> for CoinStatsError {
    fn from(e: StorageError) -> Self {
        CoinStatsError::Storage(e.to_string())
    }
}

/// Coin statistics index providing storage and retrieval of UTXO set statistics.
pub struct CoinStatsIndex<'a> {
    db: &'a ChainDb,
}

impl<'a> CoinStatsIndex<'a> {
    /// Create a new coin stats index wrapping the given database.
    pub fn new(db: &'a ChainDb) -> Self {
        Self { db }
    }

    /// Store a coin stats entry.
    pub fn put_stats(&self, entry: &CoinStatsEntry) -> Result<(), CoinStatsError> {
        let data =
            serde_json::to_vec(entry).map_err(|e| CoinStatsError::Storage(e.to_string()))?;
        self.db
            .put_cf(CF_COINSTATS, &entry.height.to_be_bytes(), &data)?;
        Ok(())
    }

    /// Retrieve a coin stats entry by height.
    pub fn get_stats(&self, height: u32) -> Result<Option<CoinStatsEntry>, CoinStatsError> {
        match self.db.get_cf(CF_COINSTATS, &height.to_be_bytes())? {
            Some(data) => {
                let entry: CoinStatsEntry = serde_json::from_slice(&data)
                    .map_err(|e| CoinStatsError::Storage(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Delete a coin stats entry.
    pub fn delete_stats(&self, height: u32) -> Result<(), CoinStatsError> {
        self.db.delete_cf(CF_COINSTATS, &height.to_be_bytes())?;
        Ok(())
    }

    /// Check if stats exist for the given height.
    pub fn has_stats(&self, height: u32) -> Result<bool, CoinStatsError> {
        Ok(self.db.contains_key(CF_COINSTATS, &height.to_be_bytes())?)
    }

    /// Get the latest indexed height.
    ///
    /// This performs a reverse iteration to find the highest indexed height.
    pub fn get_best_height(&self) -> Result<Option<u32>, CoinStatsError> {
        // Simple approach: try common heights in reverse
        // In production, we'd store this as metadata
        for height in (0..=10_000_000).rev() {
            if self.has_stats(height)? {
                return Ok(Some(height));
            }
            if height == 0 {
                break;
            }
        }
        Ok(None)
    }
}

/// Compute the "bogosize" of a UTXO (estimated serialized size).
///
/// Following Bitcoin Core's formula:
/// bogosize = 32 + 4 + 1 + nScriptPubKey + 4 + 1
///          = 50 + nScriptPubKey (for compressed height/coinbase)
///
/// This is an approximation for the UTXO database storage cost.
pub fn get_bogo_size(script_pubkey_len: usize) -> u64 {
    // Size of serialized outpoint (txid + vout)
    const OUTPOINT_SIZE: u64 = 36;
    // Compressed height + coinbase flag + value
    const METADATA_SIZE: u64 = 14;

    OUTPOINT_SIZE + METADATA_SIZE + (script_pubkey_len as u64)
}

/// Serialize a coin for MuHash.
///
/// The serialization format matches Bitcoin Core:
/// - outpoint (txid + vout)
/// - code (height * 2 + coinbase flag)
/// - value (compressed)
/// - scriptPubKey
pub fn serialize_coin_for_muhash(
    txid: &Hash256,
    vout: u32,
    height: u32,
    is_coinbase: bool,
    value: u64,
    script_pubkey: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(36 + 10 + 10 + script_pubkey.len());

    // Outpoint
    data.extend_from_slice(txid.as_bytes());
    data.extend_from_slice(&vout.to_le_bytes());

    // Code: height * 2 + coinbase
    let code = (height as u64) * 2 + (is_coinbase as u64);
    write_varint(&mut data, code);

    // Value (compressed using varint)
    write_varint(&mut data, compress_amount(value));

    // ScriptPubKey
    data.extend_from_slice(script_pubkey);

    data
}

/// Compress a satoshi amount for serialization.
///
/// This uses Bitcoin Core's amount compression scheme.
fn compress_amount(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }

    let mut e = 0;
    let mut n = n;

    while n % 10 == 0 && e < 9 {
        n /= 10;
        e += 1;
    }

    if e < 9 {
        let d = n % 10;
        n /= 10;
        return 1 + (n * 9 + d - 1) * 10 + e;
    } else {
        return 1 + (n - 1) * 10 + 9;
    }
}

/// Write a varint to a buffer.
fn write_varint(buf: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

/// Block subsidy calculation (50 BTC halving every 210,000 blocks).
pub fn get_block_subsidy(height: u32) -> u64 {
    const INITIAL_SUBSIDY: u64 = 50 * 100_000_000; // 50 BTC in satoshis
    const HALVING_INTERVAL: u32 = 210_000;

    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }

    INITIAL_SUBSIDY >> halvings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_subsidy() {
        // Block 0 (genesis)
        assert_eq!(get_block_subsidy(0), 5_000_000_000);

        // Just before first halving
        assert_eq!(get_block_subsidy(209_999), 5_000_000_000);

        // First halving
        assert_eq!(get_block_subsidy(210_000), 2_500_000_000);

        // Second halving
        assert_eq!(get_block_subsidy(420_000), 1_250_000_000);

        // Third halving
        assert_eq!(get_block_subsidy(630_000), 625_000_000);

        // Far future (64+ halvings = 0)
        assert_eq!(get_block_subsidy(210_000 * 64), 0);
    }

    #[test]
    fn test_coin_stats_entry_default() {
        let entry = CoinStatsEntry::default();
        assert_eq!(entry.height, 0);
        assert_eq!(entry.utxo_count, 0);
        assert_eq!(entry.total_amount, 0);
        assert_eq!(entry.total_unspendable(), 0);
    }

    #[test]
    fn test_coin_stats_entry_genesis() {
        let block_hash = Hash256::ZERO;
        let subsidy = 5_000_000_000u64;
        let entry = CoinStatsEntry::genesis(block_hash, subsidy);

        assert_eq!(entry.height, 0);
        assert_eq!(entry.total_subsidy, subsidy);
        assert_eq!(entry.unspendables_genesis, subsidy);
        assert_eq!(entry.total_unspendable(), subsidy);
        assert_eq!(entry.circulating_supply(), 0);
    }

    #[test]
    fn test_bogo_size() {
        // P2PKH script (25 bytes)
        assert_eq!(get_bogo_size(25), 50 + 25);

        // P2WPKH script (22 bytes)
        assert_eq!(get_bogo_size(22), 50 + 22);

        // P2TR script (34 bytes)
        assert_eq!(get_bogo_size(34), 50 + 34);
    }

    #[test]
    fn test_compress_amount() {
        // 0 -> 0
        assert_eq!(compress_amount(0), 0);

        // 1 satoshi
        assert_ne!(compress_amount(1), 0);

        // 1 BTC = 100_000_000 satoshis
        assert_ne!(compress_amount(100_000_000), 0);
    }

    #[test]
    fn test_serialize_coin_for_muhash() {
        let txid = Hash256::ZERO;
        let vout = 0;
        let height = 100;
        let is_coinbase = false;
        let value = 50_000_000;
        let script = vec![0x76, 0xa9, 0x14]; // P2PKH prefix

        let serialized = serialize_coin_for_muhash(&txid, vout, height, is_coinbase, value, &script);

        // Should contain txid (32) + vout (4) + varint + varint + script
        assert!(serialized.len() >= 36 + 2 + script.len());
    }

    #[test]
    fn test_coin_stats_muhash_roundtrip() {
        let mut muhash = MuHash3072::new();
        muhash.insert(b"test coin 1");
        muhash.insert(b"test coin 2");

        let mut entry = CoinStatsEntry::default();
        entry.set_muhash(&muhash);

        let restored = entry.get_muhash();
        let original_hash = muhash.clone_for_finalize().finalize();
        let restored_hash = restored.clone_for_finalize().finalize();

        assert_eq!(original_hash, restored_hash);
    }

    #[test]
    fn test_coin_stats_entry_serialization() {
        let mut entry = CoinStatsEntry::default();
        entry.height = 100;
        entry.utxo_count = 50_000;
        entry.total_amount = 1_000_000_000_000;
        entry.block_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        let json = serde_json::to_string(&entry).unwrap();
        let restored: CoinStatsEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.height, restored.height);
        assert_eq!(entry.utxo_count, restored.utxo_count);
        assert_eq!(entry.total_amount, restored.total_amount);
        assert_eq!(entry.block_hash, restored.block_hash);
    }

    #[test]
    fn test_varint_encoding() {
        let test_cases = [0u64, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX as u64];

        for &value in &test_cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, value);
            assert!(!buf.is_empty());
        }
    }
}
