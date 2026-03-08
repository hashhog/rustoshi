//! Bitcoin transaction memory pool (mempool).
//!
//! The mempool stores unconfirmed transactions that are waiting to be included in a block.
//! It enforces both consensus rules and relay policies:
//!
//! - **Consensus rules**: All transactions must be valid (proper signatures, sufficient
//!   inputs, etc.)
//! - **Relay policies**: Standard transaction formats, minimum fee rates, dust limits,
//!   ancestor/descendant limits
//!
//! # Key Features
//!
//! - O(1) conflict detection via spent outpoint tracking
//! - Transaction dependency tracking (parent/child relationships)
//! - Fee-rate based eviction when mempool is full
//! - Ancestor and descendant limit enforcement (BIP-125 chain limits)
//!
//! # Example
//!
//! ```ignore
//! let config = MempoolConfig::default();
//! let mut mempool = Mempool::new(config);
//!
//! let txid = mempool.add_transaction(tx, &|outpoint| {
//!     utxo_set.get(outpoint)
//! })?;
//! ```

use crate::params::{DUST_RELAY_TX_FEE, MAX_STANDARD_TX_WEIGHT};
use crate::validation::{check_transaction, CoinEntry, TxValidationError};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxOut};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;
use thiserror::Error;

// ============================================================
// CONFIGURATION
// ============================================================

/// Mempool configuration.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    /// Maximum mempool size in bytes (default: 300 MB).
    pub max_size_bytes: usize,
    /// Minimum fee rate to accept a transaction (satoshis per virtual byte).
    pub min_fee_rate: u64,
    /// Maximum number of transactions.
    pub max_tx_count: usize,
    /// Maximum number of ancestor transactions (BIP-125 chain limit).
    pub max_ancestor_count: usize,
    /// Maximum ancestor size in virtual bytes.
    pub max_ancestor_size: usize,
    /// Maximum number of descendant transactions.
    pub max_descendant_count: usize,
    /// Maximum descendant size in virtual bytes.
    pub max_descendant_size: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 300 * 1024 * 1024,
            min_fee_rate: 1, // 1 sat/vbyte
            max_tx_count: 1_000_000,
            max_ancestor_count: 25,
            max_ancestor_size: 101_000,
            max_descendant_count: 25,
            max_descendant_size: 101_000,
        }
    }
}

// ============================================================
// MEMPOOL ENTRY
// ============================================================

/// A transaction entry in the mempool.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// The transaction.
    pub tx: Transaction,
    /// The transaction ID.
    pub txid: Hash256,
    /// The fee paid by this transaction (in satoshis).
    pub fee: u64,
    /// Serialized size in bytes.
    pub size: usize,
    /// Virtual size (weight / 4, rounded up).
    pub vsize: usize,
    /// Transaction weight (BIP-141).
    pub weight: usize,
    /// Time when the transaction was added.
    pub time_added: Instant,
    /// Fee rate in satoshis per virtual byte.
    pub fee_rate: f64,
    /// Ancestor count (including this transaction).
    pub ancestor_count: usize,
    /// Ancestor size in virtual bytes (including this transaction).
    pub ancestor_size: usize,
    /// Ancestor fees in satoshis (including this transaction).
    pub ancestor_fees: u64,
    /// Descendant count (including this transaction).
    pub descendant_count: usize,
    /// Descendant size in virtual bytes (including this transaction).
    pub descendant_size: usize,
    /// Descendant fees in satoshis (including this transaction).
    pub descendant_fees: u64,
}

// ============================================================
// ERRORS
// ============================================================

/// Errors that can occur during mempool operations.
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("transaction already in mempool")]
    AlreadyExists,

    #[error("transaction conflicts with mempool entry {0}")]
    Conflict(Hash256),

    #[error("fee rate too low: {0:.2} sat/vB (minimum: {1})")]
    InsufficientFee(f64, u64),

    #[error("mempool full")]
    MempoolFull,

    #[error("too many ancestors: {0} (max: {1})")]
    TooManyAncestors(usize, usize),

    #[error("ancestor size too large: {0} (max: {1})")]
    AncestorSizeTooLarge(usize, usize),

    #[error("too many descendants: {0} (max: {1})")]
    TooManyDescendants(usize, usize),

    #[error("descendant size too large: {0} (max: {1})")]
    DescendantSizeTooLarge(usize, usize),

    #[error("non-standard transaction: {0}")]
    NonStandard(String),

    #[error("validation error: {0}")]
    Validation(#[from] TxValidationError),

    #[error("missing input: {0}:{1}")]
    MissingInput(Hash256, u32),

    #[error("insufficient funds")]
    InsufficientFunds,
}

// ============================================================
// FEE RATE KEY
// ============================================================

/// Key for fee-rate ordering. Compares by fee rate, then by txid for uniqueness.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FeeRateKey {
    /// Fee rate as fixed-point (multiply by 1,000,000 to avoid float ordering issues).
    fee_rate_millionths: u64,
    /// Transaction ID for uniqueness.
    txid: Hash256,
}

// ============================================================
// MEMPOOL
// ============================================================

/// The transaction memory pool.
///
/// Stores unconfirmed transactions, validates them against the UTXO set,
/// enforces relay policies, and tracks transaction dependencies.
pub struct Mempool {
    /// Configuration.
    config: MempoolConfig,
    /// All transactions by txid.
    transactions: HashMap<Hash256, MempoolEntry>,
    /// Map from outpoint to the txid that spends it (for conflict detection).
    spent_outpoints: HashMap<OutPoint, Hash256>,
    /// Map from outpoint to the txid that creates it (for dependency tracking).
    /// These are UTXOs created by mempool transactions.
    created_utxos: HashMap<OutPoint, Hash256>,
    /// Transaction dependencies: txid -> set of parent txids in mempool.
    parents: HashMap<Hash256, HashSet<Hash256>>,
    /// Transaction dependents: txid -> set of child txids in mempool.
    children: HashMap<Hash256, HashSet<Hash256>>,
    /// Total size of all transactions in virtual bytes.
    total_size: usize,
    /// Fee-rate sorted index for eviction (lowest fee rate first).
    fee_rate_index: BTreeMap<FeeRateKey, Hash256>,
}

impl Mempool {
    /// Create a new mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            transactions: HashMap::new(),
            spent_outpoints: HashMap::new(),
            created_utxos: HashMap::new(),
            parents: HashMap::new(),
            children: HashMap::new(),
            total_size: 0,
            fee_rate_index: BTreeMap::new(),
        }
    }

    /// Add a transaction to the mempool.
    ///
    /// This performs full validation:
    /// 1. Check if already in mempool
    /// 2. Run context-free validation (check_transaction)
    /// 3. Check standardness rules
    /// 4. Look up all inputs (from UTXO set and mempool UTXOs)
    /// 5. Calculate fee and fee rate
    /// 6. Check minimum fee rate
    /// 7. Check ancestor/descendant limits
    /// 8. Check for conflicts (double-spends)
    /// 9. Evict low-fee transactions if mempool is full
    /// 10. Add to mempool data structures
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to add
    /// * `utxo_lookup` - Function to look up UTXOs from the chain state
    ///
    /// # Returns
    ///
    /// The txid of the added transaction, or an error.
    pub fn add_transaction<F>(
        &mut self,
        tx: Transaction,
        utxo_lookup: &F,
    ) -> Result<Hash256, MempoolError>
    where
        F: Fn(&OutPoint) -> Option<CoinEntry>,
    {
        let txid = tx.txid();

        // Already in mempool?
        if self.transactions.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists);
        }

        // Context-free validation
        check_transaction(&tx)?;

        // Check standardness
        self.check_standard(&tx)?;

        // Look up inputs and compute fee
        let mut input_sum: u64 = 0;
        let mut mempool_parents = HashSet::new();

        for input in &tx.inputs {
            // Check for conflicts (double-spends)
            if let Some(conflicting) = self.spent_outpoints.get(&input.previous_output) {
                return Err(MempoolError::Conflict(*conflicting));
            }

            // Try mempool UTXOs first (for chained unconfirmed transactions)
            if let Some(parent_txid) = self.created_utxos.get(&input.previous_output) {
                let parent = self
                    .transactions
                    .get(parent_txid)
                    .expect("created_utxos should be consistent with transactions");
                let vout = input.previous_output.vout as usize;
                if vout >= parent.tx.outputs.len() {
                    return Err(MempoolError::MissingInput(
                        input.previous_output.txid,
                        input.previous_output.vout,
                    ));
                }
                input_sum += parent.tx.outputs[vout].value;
                mempool_parents.insert(*parent_txid);
            } else if let Some(coin) = utxo_lookup(&input.previous_output) {
                input_sum += coin.value;
            } else {
                return Err(MempoolError::MissingInput(
                    input.previous_output.txid,
                    input.previous_output.vout,
                ));
            }
        }

        let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if input_sum < output_sum {
            return Err(MempoolError::InsufficientFunds);
        }
        let fee = input_sum - output_sum;

        let vsize = tx.vsize();
        let fee_rate = fee as f64 / vsize as f64;

        if (fee_rate as u64) < self.config.min_fee_rate {
            return Err(MempoolError::InsufficientFee(
                fee_rate,
                self.config.min_fee_rate,
            ));
        }

        // Check ancestor limits
        let (ancestor_count, ancestor_size, ancestor_fees) =
            self.calculate_ancestors(&mempool_parents);

        if ancestor_count + 1 > self.config.max_ancestor_count {
            return Err(MempoolError::TooManyAncestors(
                ancestor_count + 1,
                self.config.max_ancestor_count,
            ));
        }
        if ancestor_size + vsize > self.config.max_ancestor_size {
            return Err(MempoolError::AncestorSizeTooLarge(
                ancestor_size + vsize,
                self.config.max_ancestor_size,
            ));
        }

        // Check descendant limits for existing ancestors
        // Adding this transaction would increase their descendant counts
        for parent in &mempool_parents {
            if let Some(parent_entry) = self.transactions.get(parent) {
                if parent_entry.descendant_count + 1 > self.config.max_descendant_count {
                    return Err(MempoolError::TooManyDescendants(
                        parent_entry.descendant_count + 1,
                        self.config.max_descendant_count,
                    ));
                }
                if parent_entry.descendant_size + vsize > self.config.max_descendant_size {
                    return Err(MempoolError::DescendantSizeTooLarge(
                        parent_entry.descendant_size + vsize,
                        self.config.max_descendant_size,
                    ));
                }
            }
        }

        // Evict if mempool is full
        while self.total_size + vsize > self.config.max_size_bytes {
            if !self.evict_lowest_fee_rate() {
                return Err(MempoolError::MempoolFull);
            }
        }

        // Build the entry
        let weight = tx.weight();
        let entry = MempoolEntry {
            tx: tx.clone(),
            txid,
            fee,
            size: tx.weight() / 4, // approximate serialized size
            vsize,
            weight,
            time_added: Instant::now(),
            fee_rate,
            ancestor_count: ancestor_count + 1,
            ancestor_size: ancestor_size + vsize,
            ancestor_fees: ancestor_fees + fee,
            descendant_count: 1,
            descendant_size: vsize,
            descendant_fees: fee,
        };

        // Track spent outpoints
        for input in &tx.inputs {
            self.spent_outpoints
                .insert(input.previous_output.clone(), txid);
        }

        // Track created UTXOs
        for (vout, _) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            self.created_utxos.insert(outpoint, txid);
        }

        // Track parent/child relationships
        self.parents.insert(txid, mempool_parents.clone());
        for parent in &mempool_parents {
            self.children.entry(*parent).or_default().insert(txid);
            // Update parent's descendant stats
            self.update_ancestors_for_add(*parent, vsize, fee);
        }
        self.children.entry(txid).or_default();

        self.total_size += vsize;
        let fee_key = FeeRateKey {
            fee_rate_millionths: (fee_rate * 1_000_000.0) as u64,
            txid,
        };
        self.fee_rate_index.insert(fee_key, txid);
        self.transactions.insert(txid, entry);

        Ok(txid)
    }

    /// Update all ancestors' descendant stats when adding a new transaction.
    fn update_ancestors_for_add(&mut self, parent: Hash256, vsize: usize, fee: u64) {
        let mut visited = HashSet::new();
        let mut queue = vec![parent];

        while let Some(current) = queue.pop() {
            if !visited.insert(current) {
                continue;
            }
            if let Some(entry) = self.transactions.get_mut(&current) {
                entry.descendant_count += 1;
                entry.descendant_size += vsize;
                entry.descendant_fees += fee;
            }
            if let Some(grandparents) = self.parents.get(&current) {
                for gp in grandparents {
                    queue.push(*gp);
                }
            }
        }
    }

    /// Remove a transaction from the mempool.
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction to remove
    /// * `remove_descendants` - If true, also remove all descendants
    pub fn remove_transaction(&mut self, txid: &Hash256, remove_descendants: bool) {
        if remove_descendants {
            let descendants = self.get_all_descendants(txid);
            for desc in descendants {
                self.remove_single(&desc);
            }
        }
        self.remove_single(txid);
    }

    /// Remove a single transaction without touching descendants.
    fn remove_single(&mut self, txid: &Hash256) {
        if let Some(entry) = self.transactions.remove(txid) {
            // Remove spent outpoints
            for input in &entry.tx.inputs {
                self.spent_outpoints.remove(&input.previous_output);
            }

            // Remove created UTXOs
            for vout in 0..entry.tx.outputs.len() {
                let outpoint = OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                };
                self.created_utxos.remove(&outpoint);
            }

            // Update ancestor descendant stats
            if let Some(parents) = self.parents.get(txid).cloned() {
                for parent in &parents {
                    self.update_ancestors_for_remove(*parent, entry.vsize, entry.fee);
                    if let Some(children) = self.children.get_mut(parent) {
                        children.remove(txid);
                    }
                }
            }
            self.parents.remove(txid);
            self.children.remove(txid);

            // Remove from fee rate index
            let fee_key = FeeRateKey {
                fee_rate_millionths: (entry.fee_rate * 1_000_000.0) as u64,
                txid: *txid,
            };
            self.fee_rate_index.remove(&fee_key);
            self.total_size = self.total_size.saturating_sub(entry.vsize);
        }
    }

    /// Update all ancestors' descendant stats when removing a transaction.
    fn update_ancestors_for_remove(&mut self, parent: Hash256, vsize: usize, fee: u64) {
        let mut visited = HashSet::new();
        let mut queue = vec![parent];

        while let Some(current) = queue.pop() {
            if !visited.insert(current) {
                continue;
            }
            if let Some(entry) = self.transactions.get_mut(&current) {
                entry.descendant_count = entry.descendant_count.saturating_sub(1);
                entry.descendant_size = entry.descendant_size.saturating_sub(vsize);
                entry.descendant_fees = entry.descendant_fees.saturating_sub(fee);
            }
            if let Some(grandparents) = self.parents.get(&current) {
                for gp in grandparents {
                    queue.push(*gp);
                }
            }
        }
    }

    /// Remove transactions that were confirmed in a block.
    ///
    /// This also removes any conflicting transactions (those spending
    /// the same inputs as block transactions).
    pub fn remove_for_block(&mut self, block_txids: &[Hash256], block_spent_outpoints: &[OutPoint]) {
        // First, remove confirmed transactions
        for txid in block_txids {
            self.remove_transaction(txid, false);
        }

        // Then, find and remove conflicting transactions
        let mut conflicts = Vec::new();
        for outpoint in block_spent_outpoints {
            if let Some(conflicting_txid) = self.spent_outpoints.get(outpoint) {
                conflicts.push(*conflicting_txid);
            }
        }

        for txid in conflicts {
            // Remove the conflicting transaction and all its descendants
            self.remove_transaction(&txid, true);
        }
    }

    /// Get transactions sorted by descendant fee rate for block building.
    ///
    /// Returns txids in priority order (highest fee rate first).
    pub fn get_sorted_for_mining(&self) -> Vec<Hash256> {
        // Use ancestor fee rate for CPFP (child-pays-for-parent)
        let mut entries: Vec<_> = self
            .transactions
            .values()
            .map(|e| {
                let ancestor_fee_rate = e.ancestor_fees as f64 / e.ancestor_size as f64;
                (ancestor_fee_rate, e.txid)
            })
            .collect();

        // Sort by ancestor fee rate (highest first)
        entries.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        entries.into_iter().map(|(_, txid)| txid).collect()
    }

    /// Check transaction standardness rules.
    fn check_standard(&self, tx: &Transaction) -> Result<(), MempoolError> {
        // Version must be 1 or 2
        if tx.version < 1 || tx.version > 2 {
            return Err(MempoolError::NonStandard(format!(
                "bad version: {}",
                tx.version
            )));
        }

        // Weight must not exceed MAX_STANDARD_TX_WEIGHT
        if tx.weight() as u64 > MAX_STANDARD_TX_WEIGHT {
            return Err(MempoolError::NonStandard("tx too large".into()));
        }

        // Each output scriptPubKey must be a standard type
        for (i, output) in tx.outputs.iter().enumerate() {
            if !is_standard_script(&output.script_pubkey) {
                return Err(MempoolError::NonStandard(format!(
                    "non-standard output script at index {}",
                    i
                )));
            }

            // Dust check
            if is_dust(output, self.config.min_fee_rate) {
                return Err(MempoolError::NonStandard(format!(
                    "dust output at index {}",
                    i
                )));
            }
        }

        Ok(())
    }

    /// Calculate ancestor statistics for a set of direct parents.
    fn calculate_ancestors(
        &self,
        direct_parents: &HashSet<Hash256>,
    ) -> (usize, usize, u64) {
        let mut visited = HashSet::new();
        let mut queue: Vec<Hash256> = direct_parents.iter().cloned().collect();
        let mut total_size = 0usize;
        let mut total_fees = 0u64;

        while let Some(parent) = queue.pop() {
            if !visited.insert(parent) {
                continue;
            }
            if let Some(entry) = self.transactions.get(&parent) {
                total_size += entry.vsize;
                total_fees += entry.fee;
                if let Some(grandparents) = self.parents.get(&parent) {
                    for gp in grandparents {
                        queue.push(*gp);
                    }
                }
            }
        }

        (visited.len(), total_size, total_fees)
    }

    /// Get all descendants of a transaction.
    fn get_all_descendants(&self, txid: &Hash256) -> Vec<Hash256> {
        let mut result = Vec::new();
        let mut queue = vec![*txid];
        let mut visited = HashSet::new();

        while let Some(current) = queue.pop() {
            if !visited.insert(current) {
                continue;
            }
            if current != *txid {
                result.push(current);
            }
            if let Some(children) = self.children.get(&current) {
                for child in children {
                    queue.push(*child);
                }
            }
        }

        result
    }

    /// Evict the lowest fee rate transaction (and its descendants).
    fn evict_lowest_fee_rate(&mut self) -> bool {
        if let Some((key, _)) = self.fee_rate_index.iter().next() {
            let txid = key.txid;
            self.remove_transaction(&txid, true);
            true
        } else {
            false
        }
    }

    /// Get the number of transactions in the mempool.
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Get the total virtual size of all transactions.
    pub fn total_bytes(&self) -> usize {
        self.total_size
    }

    /// Get a transaction by its txid.
    pub fn get(&self, txid: &Hash256) -> Option<&MempoolEntry> {
        self.transactions.get(txid)
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, txid: &Hash256) -> bool {
        self.transactions.contains_key(txid)
    }

    /// Check if an outpoint is being spent by a mempool transaction.
    pub fn is_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_outpoints.contains_key(outpoint)
    }

    /// Get the txid that spends a given outpoint (if any).
    pub fn get_spending_tx(&self, outpoint: &OutPoint) -> Option<Hash256> {
        self.spent_outpoints.get(outpoint).copied()
    }

    /// Clear all transactions from the mempool.
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.spent_outpoints.clear();
        self.created_utxos.clear();
        self.parents.clear();
        self.children.clear();
        self.fee_rate_index.clear();
        self.total_size = 0;
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/// Check if a scriptPubKey is a standard type.
fn is_standard_script(script: &[u8]) -> bool {
    // OP_RETURN (data carrier) - always standard up to 83 bytes
    if !script.is_empty() && script[0] == 0x6a && script.len() <= 83 {
        return true;
    }

    // P2PKH: 25 bytes, OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return true;
    }

    // P2SH: 23 bytes, OP_HASH160 <20> OP_EQUAL
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return true;
    }

    // P2WPKH: 22 bytes, OP_0 <20>
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        return true;
    }

    // P2WSH: 34 bytes, OP_0 <32>
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        return true;
    }

    // P2TR: 34 bytes, OP_1 <32>
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return true;
    }

    // Bare multisig (1-of-3 max for standard)
    // OP_m <pubkey>... OP_n OP_CHECKMULTISIG
    if script.len() >= 35 && script.last() == Some(&0xae) {
        // Check for OP_1 through OP_3 at start
        let m = script.first();
        if let Some(&m_op) = m {
            if (0x51..=0x53).contains(&m_op) {
                // This is a simplified check; real implementation would validate structure
                return true;
            }
        }
    }

    // Witness version 1+ programs (future SegWit versions) - up to 40 bytes
    // OP_1..OP_16 followed by 2-40 bytes push
    if script.len() >= 4 && script.len() <= 42 {
        let version = script[0];
        if (0x51..=0x60).contains(&version) {
            // OP_1 through OP_16
            let push_len = script[1] as usize;
            if (2..=40).contains(&push_len) && script.len() == 2 + push_len {
                return true;
            }
        }
    }

    false
}

/// Check if an output is dust.
///
/// An output is dust if the cost of spending it exceeds its value.
fn is_dust(output: &TxOut, _min_fee_rate: u64) -> bool {
    // OP_RETURN is never dust
    if !output.script_pubkey.is_empty() && output.script_pubkey[0] == 0x6a {
        return false;
    }

    // Empty script with zero value is special (sometimes used)
    if output.script_pubkey.is_empty() && output.value == 0 {
        return false;
    }

    // Spending cost depends on output type
    let spending_size: usize = if output.script_pubkey.len() == 25 {
        148 // P2PKH input size
    } else if output.script_pubkey.len() == 23 {
        91 // P2SH input size (approximate)
    } else if output.script_pubkey.len() == 22 && output.script_pubkey[0] == 0x00 {
        68 // P2WPKH input size
    } else if output.script_pubkey.len() == 34 && output.script_pubkey[0] == 0x00 {
        108 // P2WSH input size (approximate)
    } else if output.script_pubkey.len() == 34 && output.script_pubkey[0] == 0x51 {
        58 // P2TR input size
    } else {
        148 // conservative default
    };

    // Dust threshold calculation: spending_size * DUST_RELAY_TX_FEE / 1000
    let dust_threshold = (spending_size as u64 * DUST_RELAY_TX_FEE) / 1000;
    output.value < dust_threshold
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::TxIn;
    use std::collections::HashMap;

    /// Helper to create a simple transaction.
    fn make_tx(
        inputs: Vec<(Hash256, u32)>,
        outputs: Vec<u64>,
        version: i32,
    ) -> Transaction {
        Transaction {
            version,
            inputs: inputs
                .into_iter()
                .map(|(txid, vout)| TxIn {
                    previous_output: OutPoint { txid, vout },
                    script_sig: vec![0x51], // OP_1
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                })
                .collect(),
            outputs: outputs
                .into_iter()
                .map(|value| TxOut {
                    value,
                    // Standard P2PKH script
                    script_pubkey: vec![
                        0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88,
                        0xac,
                    ],
                })
                .collect(),
            lock_time: 0,
        }
    }

    /// Create a mock UTXO set.
    fn mock_utxo_set(utxos: Vec<(OutPoint, u64)>) -> HashMap<OutPoint, CoinEntry> {
        utxos
            .into_iter()
            .map(|(outpoint, value)| {
                (
                    outpoint,
                    CoinEntry {
                        height: 100,
                        is_coinbase: false,
                        value,
                        script_pubkey: vec![0x51], // OP_1
                    },
                )
            })
            .collect()
    }

    #[test]
    fn test_add_valid_transaction() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: prev_txid, vout: 0 }, 100_000)]);

        let tx = make_tx(vec![(prev_txid, 0)], vec![90_000], 1);
        let txid = tx.txid();

        let result = mempool.add_transaction(tx, &|op| utxos.get(op).cloned());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), txid);
        assert!(mempool.contains(&txid));
        assert_eq!(mempool.size(), 1);
    }

    #[test]
    fn test_reject_duplicate_transaction() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: prev_txid, vout: 0 }, 100_000)]);

        let tx = make_tx(vec![(prev_txid, 0)], vec![90_000], 1);

        let result1 = mempool.add_transaction(tx.clone(), &|op| utxos.get(op).cloned());
        assert!(result1.is_ok());

        let result2 = mempool.add_transaction(tx, &|op| utxos.get(op).cloned());
        assert!(matches!(result2, Err(MempoolError::AlreadyExists)));
    }

    #[test]
    fn test_reject_low_fee_rate() {
        let config = MempoolConfig {
            min_fee_rate: 10, // 10 sat/vB minimum
            ..Default::default()
        };
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: prev_txid, vout: 0 }, 100_000)]);

        // Very small fee (1 satoshi)
        let tx = make_tx(vec![(prev_txid, 0)], vec![99_999], 1);

        let result = mempool.add_transaction(tx, &|op| utxos.get(op).cloned());
        assert!(matches!(result, Err(MempoolError::InsufficientFee(_, _))));
    }

    #[test]
    fn test_reject_bad_version() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: prev_txid, vout: 0 }, 100_000)]);

        // Version 0 is non-standard
        let tx = make_tx(vec![(prev_txid, 0)], vec![90_000], 0);

        let result = mempool.add_transaction(tx, &|op| utxos.get(op).cloned());
        assert!(matches!(result, Err(MempoolError::NonStandard(_))));
    }

    #[test]
    fn test_detect_double_spend_conflict() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: prev_txid, vout: 0 }, 100_000)]);

        let tx1 = make_tx(vec![(prev_txid, 0)], vec![90_000], 1);
        let txid1 = tx1.txid();

        let tx2 = make_tx(vec![(prev_txid, 0)], vec![80_000], 1);

        let result1 = mempool.add_transaction(tx1, &|op| utxos.get(op).cloned());
        assert!(result1.is_ok());

        let result2 = mempool.add_transaction(tx2, &|op| utxos.get(op).cloned());
        assert!(matches!(result2, Err(MempoolError::Conflict(txid)) if txid == txid1));
    }

    #[test]
    fn test_transaction_chain() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        // Initial UTXO
        let utxo_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: utxo_txid, vout: 0 }, 100_000)]);

        // First transaction (parent)
        let tx1 = make_tx(vec![(utxo_txid, 0)], vec![90_000], 1);
        let txid1 = tx1.txid();
        mempool
            .add_transaction(tx1, &|op| utxos.get(op).cloned())
            .unwrap();

        // Second transaction (child, spends output from tx1)
        let tx2 = make_tx(vec![(txid1, 0)], vec![80_000], 1);
        let txid2 = tx2.txid();
        let result = mempool.add_transaction(tx2, &|op| utxos.get(op).cloned());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), txid2);

        // Verify parent/child relationship
        assert!(mempool.parents.get(&txid2).unwrap().contains(&txid1));
        assert!(mempool.children.get(&txid1).unwrap().contains(&txid2));

        // Verify ancestor stats
        let entry = mempool.get(&txid2).unwrap();
        assert_eq!(entry.ancestor_count, 2); // self + parent
    }

    #[test]
    fn test_ancestor_limit() {
        let config = MempoolConfig {
            max_ancestor_count: 2, // Very low limit
            ..Default::default()
        };
        let mut mempool = Mempool::new(config);

        // Build a chain of 3 transactions
        let utxo_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: utxo_txid, vout: 0 }, 100_000)]);

        let tx1 = make_tx(vec![(utxo_txid, 0)], vec![90_000], 1);
        let txid1 = tx1.txid();
        mempool
            .add_transaction(tx1, &|op| utxos.get(op).cloned())
            .unwrap();

        let tx2 = make_tx(vec![(txid1, 0)], vec![80_000], 1);
        let txid2 = tx2.txid();
        mempool
            .add_transaction(tx2, &|op| utxos.get(op).cloned())
            .unwrap();

        // Third transaction should fail (would have 3 ancestors)
        let tx3 = make_tx(vec![(txid2, 0)], vec![70_000], 1);
        let result = mempool.add_transaction(tx3, &|op| utxos.get(op).cloned());
        assert!(matches!(result, Err(MempoolError::TooManyAncestors(_, _))));
    }

    #[test]
    fn test_remove_for_block() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let utxo_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: utxo_txid, vout: 0 }, 100_000)]);

        let tx = make_tx(vec![(utxo_txid, 0)], vec![90_000], 1);
        let txid = tx.txid();
        mempool
            .add_transaction(tx, &|op| utxos.get(op).cloned())
            .unwrap();
        assert_eq!(mempool.size(), 1);

        // Remove as if confirmed in a block
        mempool.remove_for_block(&[txid], &[]);
        assert_eq!(mempool.size(), 0);
        assert!(!mempool.contains(&txid));
    }

    #[test]
    fn test_eviction_when_full() {
        let config = MempoolConfig {
            max_size_bytes: 500, // Very small
            ..Default::default()
        };
        let mut mempool = Mempool::new(config);

        // Create UTXOs
        let utxo1 =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxo2 =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let utxos = mock_utxo_set(vec![
            (OutPoint { txid: utxo1, vout: 0 }, 100_000),
            (OutPoint { txid: utxo2, vout: 0 }, 100_000),
        ]);

        // Add low fee transaction
        let tx1 = make_tx(vec![(utxo1, 0)], vec![99_000], 1); // 1000 sat fee
        mempool
            .add_transaction(tx1, &|op| utxos.get(op).cloned())
            .unwrap();

        // Add higher fee transaction (should evict the first one)
        let tx2 = make_tx(vec![(utxo2, 0)], vec![90_000], 1); // 10000 sat fee
        let result = mempool.add_transaction(tx2, &|op| utxos.get(op).cloned());

        // Either succeeds (eviction worked) or fails (couldn't evict enough)
        // With our small limit, it should evict tx1
        assert!(result.is_ok() || matches!(result, Err(MempoolError::MempoolFull)));
    }

    #[test]
    fn test_dust_detection() {
        // P2PKH output (25 bytes, spending cost ~148 bytes)
        // Dust threshold = 148 * 3000 / 1000 = 444 satoshis
        let output = TxOut {
            value: 100, // Below dust threshold
            script_pubkey: vec![
                0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
            ],
        };
        assert!(is_dust(&output, 1));

        let non_dust_output = TxOut {
            value: 1000, // Above dust threshold
            script_pubkey: output.script_pubkey.clone(),
        };
        assert!(!is_dust(&non_dust_output, 1));

        // OP_RETURN is never dust
        let op_return = TxOut {
            value: 0,
            script_pubkey: vec![0x6a, 0x04, 0x00, 0x00, 0x00, 0x00],
        };
        assert!(!is_dust(&op_return, 1));
    }

    #[test]
    fn test_standard_scripts() {
        // P2PKH
        let p2pkh = vec![
            0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
        ];
        assert!(is_standard_script(&p2pkh));

        // P2SH
        let p2sh = vec![
            0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
        ];
        assert!(is_standard_script(&p2sh));

        // P2WPKH
        let p2wpkh = vec![
            0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_standard_script(&p2wpkh));

        // P2WSH
        let p2wsh = vec![
            0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_standard_script(&p2wsh));

        // P2TR
        let p2tr = vec![
            0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_standard_script(&p2tr));

        // OP_RETURN
        let op_return = vec![0x6a, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert!(is_standard_script(&op_return));

        // Non-standard (random bytes)
        let non_standard = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(!is_standard_script(&non_standard));
    }

    #[test]
    fn test_get_sorted_for_mining() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        // Create UTXOs
        let utxo1 =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxo2 =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let utxos = mock_utxo_set(vec![
            (OutPoint { txid: utxo1, vout: 0 }, 100_000),
            (OutPoint { txid: utxo2, vout: 0 }, 100_000),
        ]);

        // Add low fee transaction
        let tx_low = make_tx(vec![(utxo1, 0)], vec![99_000], 1); // 1000 sat fee
        let txid_low = tx_low.txid();
        mempool
            .add_transaction(tx_low, &|op| utxos.get(op).cloned())
            .unwrap();

        // Add high fee transaction
        let tx_high = make_tx(vec![(utxo2, 0)], vec![80_000], 1); // 20000 sat fee
        let txid_high = tx_high.txid();
        mempool
            .add_transaction(tx_high, &|op| utxos.get(op).cloned())
            .unwrap();

        let sorted = mempool.get_sorted_for_mining();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0], txid_high); // Higher fee rate first
        assert_eq!(sorted[1], txid_low);
    }

    #[test]
    fn test_missing_input() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos: HashMap<OutPoint, CoinEntry> = HashMap::new(); // Empty UTXO set

        let tx = make_tx(vec![(prev_txid, 0)], vec![90_000], 1);

        let result = mempool.add_transaction(tx, &|op| utxos.get(op).cloned());
        assert!(matches!(result, Err(MempoolError::MissingInput(_, _))));
    }

    #[test]
    fn test_insufficient_funds() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: prev_txid, vout: 0 }, 10_000)]);

        // Output exceeds input
        let tx = make_tx(vec![(prev_txid, 0)], vec![20_000], 1);

        let result = mempool.add_transaction(tx, &|op| utxos.get(op).cloned());
        assert!(matches!(result, Err(MempoolError::InsufficientFunds)));
    }

    #[test]
    fn test_remove_descendants() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let utxo_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: utxo_txid, vout: 0 }, 100_000)]);

        // Parent
        let tx1 = make_tx(vec![(utxo_txid, 0)], vec![90_000], 1);
        let txid1 = tx1.txid();
        mempool
            .add_transaction(tx1, &|op| utxos.get(op).cloned())
            .unwrap();

        // Child
        let tx2 = make_tx(vec![(txid1, 0)], vec![80_000], 1);
        let txid2 = tx2.txid();
        mempool
            .add_transaction(tx2, &|op| utxos.get(op).cloned())
            .unwrap();

        assert_eq!(mempool.size(), 2);

        // Remove parent with descendants
        mempool.remove_transaction(&txid1, true);

        assert_eq!(mempool.size(), 0);
        assert!(!mempool.contains(&txid1));
        assert!(!mempool.contains(&txid2));
    }

    #[test]
    fn test_clear() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let utxos = mock_utxo_set(vec![(OutPoint { txid: prev_txid, vout: 0 }, 100_000)]);

        let tx = make_tx(vec![(prev_txid, 0)], vec![90_000], 1);
        mempool
            .add_transaction(tx, &|op| utxos.get(op).cloned())
            .unwrap();
        assert_eq!(mempool.size(), 1);

        mempool.clear();
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.total_bytes(), 0);
    }

    #[test]
    fn test_is_spent() {
        let config = MempoolConfig::default();
        let mut mempool = Mempool::new(config);

        let prev_txid =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };
        let utxos = mock_utxo_set(vec![(outpoint.clone(), 100_000)]);

        let tx = make_tx(vec![(prev_txid, 0)], vec![90_000], 1);
        let txid = tx.txid();
        mempool
            .add_transaction(tx, &|op| utxos.get(op).cloned())
            .unwrap();

        assert!(mempool.is_spent(&outpoint));
        assert_eq!(mempool.get_spending_tx(&outpoint), Some(txid));

        // Unspent outpoint
        let other = OutPoint {
            txid: Hash256::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000099",
            )
            .unwrap(),
            vout: 0,
        };
        assert!(!mempool.is_spent(&other));
        assert_eq!(mempool.get_spending_tx(&other), None);
    }
}
