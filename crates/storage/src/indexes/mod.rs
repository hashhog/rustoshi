//! Block indexes for accelerated lookups.
//!
//! This module contains optional indexes that improve query performance:
//!
//! - **txindex**: Map txid -> block location for fast transaction lookups
//! - **blockfilterindex**: BIP 157/158 compact block filters for light clients
//! - **coinstatsindex**: Per-block UTXO set statistics
//!
//! # Architecture
//!
//! Each index is stored in its own column family and can be enabled independently.
//! Indexes are populated during block connection and updated during disconnection
//! (reorgs).
//!
//! # Usage
//!
//! ```ignore
//! use rustoshi_storage::indexes::{TxIndex, BlockFilterIndex, CoinStatsIndex};
//!
//! let tx_index = TxIndex::new(&db);
//! let filter_index = BlockFilterIndex::new(&db);
//! let stats_index = CoinStatsIndex::new(&db);
//! ```

pub mod blockfilterindex;
pub mod coinstatsindex;
pub mod gcs;
pub mod muhash;
pub mod txindex;

// Re-exports for convenience
pub use blockfilterindex::{BlockFilter, BlockFilterError, BlockFilterIndex, BlockFilterType, FilterHeaderEntry};
pub use coinstatsindex::{CoinStatsEntry, CoinStatsError, CoinStatsIndex, get_block_subsidy, get_bogo_size, serialize_coin_for_muhash};
pub use gcs::{GCSFilter, GCSError, BASIC_FILTER_M, BASIC_FILTER_P};
pub use muhash::{MuHash3072, Num3072};
pub use txindex::{TxIndex, TxIndexError, TxLocation};
