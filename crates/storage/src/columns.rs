//! Column family definitions for the RocksDB database.
//!
//! Each column family provides a logical namespace for a specific type of data,
//! while sharing a single WAL (write-ahead log) for atomic cross-family writes.

/// Block headers indexed by block hash.
/// Key: block_hash (32 bytes)
/// Value: serialized BlockHeader (80 bytes)
pub const CF_HEADERS: &str = "headers";

/// Full blocks indexed by block hash.
/// Key: block_hash (32 bytes)
/// Value: serialized Block
pub const CF_BLOCKS: &str = "blocks";

/// Block index entries indexed by block hash.
/// Key: block_hash (32 bytes)
/// Value: serialized BlockIndexEntry (height, status, metadata)
pub const CF_BLOCK_INDEX: &str = "block_index";

/// Mapping from height to block hash for the active chain.
/// Key: height (4 bytes, big-endian for sorted iteration)
/// Value: block_hash (32 bytes)
pub const CF_HEIGHT_INDEX: &str = "height_index";

/// UTXO set indexed by outpoint.
/// Key: txid (32 bytes) + vout (4 bytes, big-endian)
/// Value: serialized CoinEntry (height, is_coinbase, value, scriptPubKey)
pub const CF_UTXO: &str = "utxo";

/// Transaction index for looking up transactions by txid.
/// Key: txid (32 bytes)
/// Value: serialized TxIndexEntry (block_hash, offset, length)
pub const CF_TX_INDEX: &str = "tx_index";

/// Chain metadata (best block, chain work, etc.).
/// Key: string identifier
/// Value: varies by key type
pub const CF_META: &str = "meta";

/// Undo data for block disconnection during reorganizations.
/// Key: block_hash (32 bytes)
/// Value: serialized UndoData (spent coins needed to reverse the block)
pub const CF_UNDO: &str = "undo";

/// BIP157 compact block filters indexed by block hash.
/// Key: block_hash (32 bytes)
/// Value: serialized BlockFilter (type, encoded GCS filter)
pub const CF_BLOCKFILTER: &str = "blockfilter";

/// BIP157 block filter headers indexed by height.
/// Key: height (4 bytes, big-endian)
/// Value: block_hash (32 bytes) + filter_hash (32 bytes) + filter_header (32 bytes)
pub const CF_BLOCKFILTER_HEADER: &str = "blockfilter_header";

/// Coin statistics per block indexed by height.
/// Key: height (4 bytes, big-endian)
/// Value: serialized CoinStatsEntry (muhash, utxo_count, total_amount, etc.)
pub const CF_COINSTATS: &str = "coinstats";

/// List of all column families for database initialization.
pub const ALL_COLUMN_FAMILIES: &[&str] = &[
    CF_HEADERS,
    CF_BLOCKS,
    CF_BLOCK_INDEX,
    CF_HEIGHT_INDEX,
    CF_UTXO,
    CF_TX_INDEX,
    CF_META,
    CF_UNDO,
    CF_BLOCKFILTER,
    CF_BLOCKFILTER_HEADER,
    CF_COINSTATS,
];
