//! SQLite-based wallet persistence.
//!
//! This module provides persistent storage for wallet data using SQLite:
//! - Wallet metadata (network, address type, etc.)
//! - Generated addresses and derivation paths
//! - UTXOs (spent and unspent)
//! - Transaction history
//!
//! Reference: Bitcoin Core's `wallet/walletdb.cpp`

use std::path::Path;

use rusqlite::{params, Connection, Result as SqliteResult};

use crate::wallet::{AddressType, WalletUtxo};
use crate::hd::WalletError;
use rustoshi_crypto::address::Network;
use rustoshi_primitives::{Hash256, OutPoint};

/// SQLite wallet database.
pub struct WalletDb {
    /// SQLite connection.
    conn: Connection,
}

/// A saved address record.
#[derive(Debug, Clone)]
pub struct SavedAddress {
    /// The address string.
    pub address: String,
    /// Derivation path as string (e.g., "m/84'/0'/0'/0/0").
    pub derivation_path: String,
    /// Whether this is a change address.
    pub is_change: bool,
    /// Address index in the chain.
    pub index: u32,
}

/// A saved UTXO record.
#[derive(Debug, Clone)]
pub struct SavedUtxo {
    /// Transaction ID.
    pub txid: Hash256,
    /// Output index.
    pub vout: u32,
    /// Value in satoshis.
    pub value: u64,
    /// ScriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
    /// Derivation path string.
    pub derivation_path: String,
    /// Block height where the UTXO was created.
    pub height: Option<u32>,
    /// Number of confirmations.
    pub confirmations: u32,
    /// Whether this UTXO has been spent.
    pub spent: bool,
    /// Transaction that spent this UTXO.
    pub spent_by: Option<Hash256>,
    /// Whether this UTXO is from a coinbase transaction.
    pub is_coinbase: bool,
}

/// A label record for addresses or transactions.
#[derive(Debug, Clone)]
pub struct LabelRecord {
    /// The address or transaction ID being labeled.
    pub target: String,
    /// The label text.
    pub label: String,
}

/// Wallet metadata.
#[derive(Debug, Clone)]
pub struct WalletMeta {
    /// Wallet name.
    pub name: String,
    /// Network (mainnet, testnet, regtest).
    pub network: Network,
    /// Address type.
    pub address_type: AddressType,
    /// Next receiving address index.
    pub next_receive_index: u32,
    /// Next change address index.
    pub next_change_index: u32,
    /// Birthday (earliest block height of interest).
    pub birthday: u32,
}

impl WalletDb {
    /// Open or create a wallet database.
    pub fn open(path: &Path) -> Result<Self, WalletError> {
        let conn = Connection::open(path)
            .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Create an in-memory wallet database (for testing).
    pub fn in_memory() -> Result<Self, WalletError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Initialize the database schema.
    fn init_schema(&self) -> Result<(), WalletError> {
        self.conn.execute_batch(
            r#"
            -- Wallet metadata
            CREATE TABLE IF NOT EXISTS wallet_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Generated addresses
            CREATE TABLE IF NOT EXISTS addresses (
                address TEXT PRIMARY KEY,
                derivation_path TEXT NOT NULL,
                is_change INTEGER NOT NULL,
                address_index INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            -- UTXOs
            CREATE TABLE IF NOT EXISTS utxos (
                txid BLOB NOT NULL,
                vout INTEGER NOT NULL,
                value INTEGER NOT NULL,
                script_pubkey BLOB NOT NULL,
                derivation_path TEXT NOT NULL,
                height INTEGER,
                confirmations INTEGER NOT NULL DEFAULT 0,
                is_change INTEGER NOT NULL DEFAULT 0,
                is_coinbase INTEGER NOT NULL DEFAULT 0,
                spent INTEGER NOT NULL DEFAULT 0,
                spent_by BLOB,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (txid, vout)
            );

            -- Transaction history
            CREATE TABLE IF NOT EXISTS transactions (
                txid BLOB PRIMARY KEY,
                raw_tx BLOB NOT NULL,
                height INTEGER,
                timestamp INTEGER,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            -- Labels for addresses and transactions
            CREATE TABLE IF NOT EXISTS labels (
                target TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                label_type TEXT NOT NULL DEFAULT 'address',
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            -- Indices for performance
            CREATE INDEX IF NOT EXISTS idx_utxos_spent ON utxos(spent);
            CREATE INDEX IF NOT EXISTS idx_utxos_height ON utxos(height);
            CREATE INDEX IF NOT EXISTS idx_utxos_coinbase ON utxos(is_coinbase);
            CREATE INDEX IF NOT EXISTS idx_addresses_change ON addresses(is_change);
            CREATE INDEX IF NOT EXISTS idx_labels_type ON labels(label_type);
            "#
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        Ok(())
    }

    /// Set a wallet metadata value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), WalletError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Get a wallet metadata value.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, WalletError> {
        let result: SqliteResult<String> = self.conn.query_row(
            "SELECT value FROM wallet_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WalletError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    /// Save wallet metadata.
    pub fn save_wallet_meta(&self, meta: &WalletMeta) -> Result<(), WalletError> {
        self.set_meta("name", &meta.name)?;
        self.set_meta("network", &network_to_string(meta.network))?;
        self.set_meta("address_type", &address_type_to_string(meta.address_type))?;
        self.set_meta("next_receive_index", &meta.next_receive_index.to_string())?;
        self.set_meta("next_change_index", &meta.next_change_index.to_string())?;
        self.set_meta("birthday", &meta.birthday.to_string())?;
        Ok(())
    }

    /// Load wallet metadata.
    pub fn load_wallet_meta(&self) -> Result<Option<WalletMeta>, WalletError> {
        let name = match self.get_meta("name")? {
            Some(n) => n,
            None => return Ok(None),
        };

        let network = self.get_meta("network")?
            .map(|s| string_to_network(&s))
            .unwrap_or(Network::Testnet);

        let address_type = self.get_meta("address_type")?
            .map(|s| string_to_address_type(&s))
            .unwrap_or(AddressType::P2WPKH);

        let next_receive_index = self.get_meta("next_receive_index")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let next_change_index = self.get_meta("next_change_index")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let birthday = self.get_meta("birthday")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(Some(WalletMeta {
            name,
            network,
            address_type,
            next_receive_index,
            next_change_index,
            birthday,
        }))
    }

    /// Save an address.
    pub fn save_address(&self, address: &str, derivation_path: &str, is_change: bool, index: u32) -> Result<(), WalletError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO addresses (address, derivation_path, is_change, address_index) VALUES (?1, ?2, ?3, ?4)",
            params![address, derivation_path, is_change as i32, index],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Get an address by string.
    pub fn get_address(&self, address: &str) -> Result<Option<SavedAddress>, WalletError> {
        let result: SqliteResult<SavedAddress> = self.conn.query_row(
            "SELECT address, derivation_path, is_change, address_index FROM addresses WHERE address = ?1",
            params![address],
            |row| {
                Ok(SavedAddress {
                    address: row.get(0)?,
                    derivation_path: row.get(1)?,
                    is_change: row.get::<_, i32>(2)? != 0,
                    index: row.get(3)?,
                })
            },
        );

        match result {
            Ok(addr) => Ok(Some(addr)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WalletError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    /// List all addresses.
    pub fn list_addresses(&self, is_change: Option<bool>) -> Result<Vec<SavedAddress>, WalletError> {
        let sql = match is_change {
            Some(_) => "SELECT address, derivation_path, is_change, address_index FROM addresses WHERE is_change = ?1 ORDER BY address_index",
            None => "SELECT address, derivation_path, is_change, address_index FROM addresses ORDER BY is_change, address_index",
        };

        let mut stmt = self.conn.prepare(sql)
            .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let row_mapper = |row: &rusqlite::Row| -> rusqlite::Result<SavedAddress> {
            Ok(SavedAddress {
                address: row.get(0)?,
                derivation_path: row.get(1)?,
                is_change: row.get::<_, i32>(2)? != 0,
                index: row.get(3)?,
            })
        };

        let rows_iter = match is_change {
            Some(change) => stmt.query_map(params![change as i32], row_mapper),
            None => stmt.query_map([], row_mapper),
        }.map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let mut result = Vec::new();
        for row in rows_iter {
            result.push(row.map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?);
        }
        Ok(result)
    }

    /// Save a UTXO.
    pub fn save_utxo(&self, utxo: &WalletUtxo) -> Result<(), WalletError> {
        let derivation_path = format_derivation_path(&utxo.derivation_path);

        self.conn.execute(
            r#"INSERT OR REPLACE INTO utxos
               (txid, vout, value, script_pubkey, derivation_path, height, confirmations, is_change, is_coinbase, spent)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)"#,
            params![
                utxo.outpoint.txid.0.as_slice(),
                utxo.outpoint.vout,
                utxo.value as i64,
                &utxo.script_pubkey,
                derivation_path,
                utxo.height,
                utxo.confirmations,
                utxo.is_change as i32,
                utxo.is_coinbase as i32,
            ],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Mark a UTXO as spent.
    pub fn mark_spent(&self, txid: &Hash256, vout: u32, spent_by: &Hash256) -> Result<(), WalletError> {
        self.conn.execute(
            "UPDATE utxos SET spent = 1, spent_by = ?3 WHERE txid = ?1 AND vout = ?2",
            params![txid.0.as_slice(), vout, spent_by.0.as_slice()],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Get unspent UTXOs.
    pub fn get_unspent(&self, min_confirmations: u32) -> Result<Vec<WalletUtxo>, WalletError> {
        let mut stmt = self.conn.prepare(
            r#"SELECT txid, vout, value, script_pubkey, derivation_path, confirmations, is_change, is_coinbase, height
               FROM utxos WHERE spent = 0 AND confirmations >= ?1"#
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let rows = stmt.query_map(params![min_confirmations], |row| {
            let txid_bytes: Vec<u8> = row.get(0)?;
            let mut txid_arr = [0u8; 32];
            txid_arr.copy_from_slice(&txid_bytes);

            let derivation_path_str: String = row.get(4)?;
            let derivation_path = parse_derivation_path_simple(&derivation_path_str);

            Ok(WalletUtxo {
                outpoint: OutPoint {
                    txid: Hash256(txid_arr),
                    vout: row.get(1)?,
                },
                value: row.get::<_, i64>(2)? as u64,
                script_pubkey: row.get(3)?,
                derivation_path,
                confirmations: row.get(5)?,
                is_change: row.get::<_, i32>(6)? != 0,
                is_coinbase: row.get::<_, i32>(7)? != 0,
                height: row.get(8)?,
            })
        }).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let utxos: Result<Vec<_>, _> = rows.collect();
        utxos.map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))
    }

    /// Get all UTXOs (including spent).
    pub fn get_all_utxos(&self) -> Result<Vec<SavedUtxo>, WalletError> {
        let mut stmt = self.conn.prepare(
            r#"SELECT txid, vout, value, script_pubkey, derivation_path, height, confirmations, spent, spent_by, is_coinbase
               FROM utxos"#
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let rows = stmt.query_map([], |row| {
            let txid_bytes: Vec<u8> = row.get(0)?;
            let mut txid_arr = [0u8; 32];
            txid_arr.copy_from_slice(&txid_bytes);

            let spent_by_bytes: Option<Vec<u8>> = row.get(8)?;
            let spent_by = spent_by_bytes.map(|b| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Hash256(arr)
            });

            Ok(SavedUtxo {
                txid: Hash256(txid_arr),
                vout: row.get(1)?,
                value: row.get::<_, i64>(2)? as u64,
                script_pubkey: row.get(3)?,
                derivation_path: row.get(4)?,
                height: row.get(5)?,
                confirmations: row.get(6)?,
                spent: row.get::<_, i32>(7)? != 0,
                spent_by,
                is_coinbase: row.get::<_, i32>(9)? != 0,
            })
        }).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let utxos: Result<Vec<_>, _> = rows.collect();
        utxos.map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))
    }

    /// Update UTXO confirmations.
    pub fn update_confirmations(&self, txid: &Hash256, vout: u32, confirmations: u32) -> Result<(), WalletError> {
        self.conn.execute(
            "UPDATE utxos SET confirmations = ?3 WHERE txid = ?1 AND vout = ?2",
            params![txid.0.as_slice(), vout, confirmations],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Get the wallet balance.
    pub fn get_balance(&self) -> Result<u64, WalletError> {
        let result: SqliteResult<i64> = self.conn.query_row(
            "SELECT COALESCE(SUM(value), 0) FROM utxos WHERE spent = 0",
            [],
            |row| row.get(0),
        );

        result
            .map(|v| v as u64)
            .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))
    }

    /// Get confirmed balance.
    pub fn get_confirmed_balance(&self, min_confirmations: u32) -> Result<u64, WalletError> {
        let result: SqliteResult<i64> = self.conn.query_row(
            "SELECT COALESCE(SUM(value), 0) FROM utxos WHERE spent = 0 AND confirmations >= ?1",
            params![min_confirmations],
            |row| row.get(0),
        );

        result
            .map(|v| v as u64)
            .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))
    }

    /// Save a transaction.
    pub fn save_transaction(&self, txid: &Hash256, raw_tx: &[u8], height: Option<u32>) -> Result<(), WalletError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO transactions (txid, raw_tx, height) VALUES (?1, ?2, ?3)",
            params![txid.0.as_slice(), raw_tx, height],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Get a transaction by ID.
    pub fn get_transaction(&self, txid: &Hash256) -> Result<Option<Vec<u8>>, WalletError> {
        let result: SqliteResult<Vec<u8>> = self.conn.query_row(
            "SELECT raw_tx FROM transactions WHERE txid = ?1",
            params![txid.0.as_slice()],
            |row| row.get(0),
        );

        match result {
            Ok(tx) => Ok(Some(tx)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WalletError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    // ========================================================================
    // Label Management
    // ========================================================================

    /// Set a label for an address.
    pub fn set_label(&self, address: &str, label: &str) -> Result<(), WalletError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO labels (target, label, label_type) VALUES (?1, ?2, 'address')",
            params![address, label],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Get the label for an address.
    pub fn get_label(&self, address: &str) -> Result<Option<String>, WalletError> {
        let result: SqliteResult<String> = self.conn.query_row(
            "SELECT label FROM labels WHERE target = ?1",
            params![address],
            |row| row.get(0),
        );

        match result {
            Ok(label) => Ok(Some(label)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WalletError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    /// Set a label for a transaction.
    pub fn set_tx_label(&self, txid: &Hash256, label: &str) -> Result<(), WalletError> {
        let txid_hex = txid.to_hex();
        self.conn.execute(
            "INSERT OR REPLACE INTO labels (target, label, label_type) VALUES (?1, ?2, 'tx')",
            params![txid_hex, label],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Get the label for a transaction.
    pub fn get_tx_label(&self, txid: &Hash256) -> Result<Option<String>, WalletError> {
        let txid_hex = txid.to_hex();
        let result: SqliteResult<String> = self.conn.query_row(
            "SELECT label FROM labels WHERE target = ?1 AND label_type = 'tx'",
            params![txid_hex],
            |row| row.get(0),
        );

        match result {
            Ok(label) => Ok(Some(label)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WalletError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    /// Delete a label.
    pub fn delete_label(&self, target: &str) -> Result<bool, WalletError> {
        let rows_affected = self.conn.execute(
            "DELETE FROM labels WHERE target = ?1",
            params![target],
        ).map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
        Ok(rows_affected > 0)
    }

    /// List all labels (optionally filtered by type).
    pub fn list_labels(&self, label_type: Option<&str>) -> Result<Vec<LabelRecord>, WalletError> {
        let sql = match label_type {
            Some(_) => "SELECT target, label FROM labels WHERE label_type = ?1 ORDER BY target",
            None => "SELECT target, label FROM labels ORDER BY target",
        };

        let mut stmt = self.conn.prepare(sql)
            .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let row_mapper = |row: &rusqlite::Row| -> rusqlite::Result<LabelRecord> {
            Ok(LabelRecord {
                target: row.get(0)?,
                label: row.get(1)?,
            })
        };

        let rows_iter = match label_type {
            Some(t) => stmt.query_map(params![t], row_mapper),
            None => stmt.query_map([], row_mapper),
        }.map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;

        let mut result = Vec::new();
        for row in rows_iter {
            result.push(row.map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?);
        }
        Ok(result)
    }

    /// List all address labels.
    pub fn list_address_labels(&self) -> Result<Vec<LabelRecord>, WalletError> {
        self.list_labels(Some("address"))
    }

    /// List all transaction labels.
    pub fn list_tx_labels(&self) -> Result<Vec<LabelRecord>, WalletError> {
        self.list_labels(Some("tx"))
    }
}

// Helper functions

fn network_to_string(network: Network) -> String {
    match network {
        Network::Mainnet => "mainnet".to_string(),
        Network::Testnet => "testnet".to_string(),
        Network::Regtest => "regtest".to_string(),
    }
}

fn string_to_network(s: &str) -> Network {
    match s {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => Network::Testnet,
    }
}

fn address_type_to_string(addr_type: AddressType) -> String {
    match addr_type {
        AddressType::P2PKH => "p2pkh".to_string(),
        AddressType::P2shP2wpkh => "p2sh-p2wpkh".to_string(),
        AddressType::P2WPKH => "p2wpkh".to_string(),
        AddressType::P2TR => "p2tr".to_string(),
    }
}

fn string_to_address_type(s: &str) -> AddressType {
    match s {
        "p2pkh" | "legacy" => AddressType::P2PKH,
        "p2sh-p2wpkh" | "p2sh-segwit" => AddressType::P2shP2wpkh,
        "p2wpkh" | "bech32" => AddressType::P2WPKH,
        "p2tr" | "bech32m" | "taproot" => AddressType::P2TR,
        _ => AddressType::P2WPKH,
    }
}

fn format_derivation_path(path: &[u32]) -> String {
    use crate::hd::HARDENED_FLAG;

    let mut result = String::from("m");
    for &index in path {
        if index >= HARDENED_FLAG {
            result.push_str(&format!("/{}'", index & !HARDENED_FLAG));
        } else {
            result.push_str(&format!("/{}", index));
        }
    }
    result
}

fn parse_derivation_path_simple(s: &str) -> Vec<u32> {
    use crate::hd::HARDENED_FLAG;

    let s = s.trim();
    let s = s.strip_prefix("m/").unwrap_or(s);

    s.split('/')
        .filter(|seg| !seg.is_empty())
        .filter_map(|seg| {
            let (num_str, hardened) = if seg.ends_with('\'') || seg.ends_with('h') {
                (&seg[..seg.len()-1], true)
            } else {
                (seg, false)
            };

            num_str.parse::<u32>().ok().map(|n| {
                if hardened { n | HARDENED_FLAG } else { n }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_db() {
        let db = WalletDb::in_memory().unwrap();

        // Save and load meta
        let meta = WalletMeta {
            name: "test".to_string(),
            network: Network::Testnet,
            address_type: AddressType::P2WPKH,
            next_receive_index: 5,
            next_change_index: 2,
            birthday: 100000,
        };
        db.save_wallet_meta(&meta).unwrap();

        let loaded = db.load_wallet_meta().unwrap().unwrap();
        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.network, Network::Testnet);
        assert_eq!(loaded.next_receive_index, 5);
    }

    #[test]
    fn test_save_address() {
        let db = WalletDb::in_memory().unwrap();

        db.save_address("tb1qtest123", "m/84'/1'/0'/0/0", false, 0).unwrap();
        db.save_address("tb1qchange1", "m/84'/1'/0'/1/0", true, 0).unwrap();

        let addr = db.get_address("tb1qtest123").unwrap().unwrap();
        assert_eq!(addr.derivation_path, "m/84'/1'/0'/0/0");
        assert!(!addr.is_change);

        let change_addrs = db.list_addresses(Some(true)).unwrap();
        assert_eq!(change_addrs.len(), 1);
    }

    #[test]
    fn test_save_utxo() {
        let db = WalletDb::in_memory().unwrap();

        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            value: 100_000,
            script_pubkey: vec![0x00, 0x14],
            derivation_path: vec![0x80000054, 0x80000001, 0x80000000, 0, 0],
            confirmations: 6,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        };

        db.save_utxo(&utxo).unwrap();

        let unspent = db.get_unspent(1).unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].value, 100_000);
        assert!(!unspent[0].is_coinbase);
        assert_eq!(unspent[0].height, Some(100));

        let balance = db.get_balance().unwrap();
        assert_eq!(balance, 100_000);
    }

    #[test]
    fn test_save_coinbase_utxo() {
        let db = WalletDb::in_memory().unwrap();

        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            value: 5_000_000_000, // 50 BTC coinbase
            script_pubkey: vec![0x00, 0x14],
            derivation_path: vec![0x80000054, 0x80000001, 0x80000000, 0, 0],
            confirmations: 100,
            is_change: false,
            is_coinbase: true,
            height: Some(50),
        };

        db.save_utxo(&utxo).unwrap();

        let unspent = db.get_unspent(1).unwrap();
        assert_eq!(unspent.len(), 1);
        assert!(unspent[0].is_coinbase);
        assert_eq!(unspent[0].height, Some(50));
    }

    #[test]
    fn test_mark_spent() {
        let db = WalletDb::in_memory().unwrap();

        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            value: 100_000,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 6,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        };

        db.save_utxo(&utxo).unwrap();
        assert_eq!(db.get_balance().unwrap(), 100_000);

        let spending_txid = Hash256([1u8; 32]);
        db.mark_spent(&Hash256::ZERO, 0, &spending_txid).unwrap();

        assert_eq!(db.get_balance().unwrap(), 0);
    }

    #[test]
    fn test_derivation_path_format() {
        let path = vec![0x80000054, 0x80000001, 0x80000000, 0, 5];
        let formatted = format_derivation_path(&path);
        assert_eq!(formatted, "m/84'/1'/0'/0/5");

        let parsed = parse_derivation_path_simple(&formatted);
        assert_eq!(parsed, path);
    }

    #[test]
    fn test_set_label() {
        let db = WalletDb::in_memory().unwrap();

        // Set a label for an address
        db.set_label("tb1qtest123", "My savings").unwrap();

        // Retrieve the label
        let label = db.get_label("tb1qtest123").unwrap();
        assert_eq!(label, Some("My savings".to_string()));

        // Non-existent label
        let no_label = db.get_label("tb1qunknown").unwrap();
        assert_eq!(no_label, None);
    }

    #[test]
    fn test_update_label() {
        let db = WalletDb::in_memory().unwrap();

        db.set_label("tb1qtest123", "Old label").unwrap();
        db.set_label("tb1qtest123", "New label").unwrap();

        let label = db.get_label("tb1qtest123").unwrap();
        assert_eq!(label, Some("New label".to_string()));
    }

    #[test]
    fn test_delete_label() {
        let db = WalletDb::in_memory().unwrap();

        db.set_label("tb1qtest123", "My savings").unwrap();
        assert!(db.get_label("tb1qtest123").unwrap().is_some());

        let deleted = db.delete_label("tb1qtest123").unwrap();
        assert!(deleted);

        assert!(db.get_label("tb1qtest123").unwrap().is_none());

        // Deleting non-existent label returns false
        let deleted_again = db.delete_label("tb1qtest123").unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn test_list_labels() {
        let db = WalletDb::in_memory().unwrap();

        db.set_label("tb1qaddr1", "Label A").unwrap();
        db.set_label("tb1qaddr2", "Label B").unwrap();
        db.set_tx_label(&Hash256::ZERO, "TX Label").unwrap();

        // List all labels
        let all_labels = db.list_labels(None).unwrap();
        assert_eq!(all_labels.len(), 3);

        // List only address labels
        let addr_labels = db.list_address_labels().unwrap();
        assert_eq!(addr_labels.len(), 2);

        // List only tx labels
        let tx_labels = db.list_tx_labels().unwrap();
        assert_eq!(tx_labels.len(), 1);
        assert_eq!(tx_labels[0].label, "TX Label");
    }

    #[test]
    fn test_tx_label() {
        let db = WalletDb::in_memory().unwrap();

        let txid = Hash256([42u8; 32]);
        db.set_tx_label(&txid, "Payment to Alice").unwrap();

        let label = db.get_tx_label(&txid).unwrap();
        assert_eq!(label, Some("Payment to Alice".to_string()));
    }
}
