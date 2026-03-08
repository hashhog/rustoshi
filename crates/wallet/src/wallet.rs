//! HD Wallet implementation with address generation and transaction building.
//!
//! This module implements a BIP-84 compatible HD wallet supporting:
//! - Native SegWit (P2WPKH) addresses (BIP-84)
//! - Legacy (P2PKH) addresses (BIP-44)
//! - UTXO tracking
//! - Transaction creation and signing

use std::collections::HashMap;

use rustoshi_crypto::{
    address::{Address, Network},
    hash160, p2wpkh_script_code, segwit_v0_sighash, legacy_sighash,
};
use rustoshi_primitives::{OutPoint, Transaction, TxIn, TxOut};
use secp256k1::{Message, Secp256k1};

use crate::hd::{ExtendedPrivKey, WalletError, HARDENED_FLAG};

/// BIP-84 purpose for native SegWit (P2WPKH).
const BIP84_PURPOSE: u32 = 84 | HARDENED_FLAG;

/// BIP-44 purpose for legacy addresses (P2PKH).
const BIP44_PURPOSE: u32 = 44 | HARDENED_FLAG;

/// BIP-84/44 coin type for Bitcoin mainnet (0').
const COIN_MAINNET: u32 = HARDENED_FLAG;

/// BIP-84/44 coin type for Bitcoin testnet (1').
const COIN_TESTNET: u32 = 1 | HARDENED_FLAG;

/// Minimum output value to avoid dust (546 satoshis for P2WPKH).
const DUST_LIMIT: u64 = 546;

/// Default RBF sequence number (enables Replace-By-Fee, BIP-125).
const RBF_SEQUENCE: u32 = 0xFFFFFFFD;

/// Address type to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AddressType {
    /// Native SegWit (BIP-84, P2WPKH). Starts with bc1q (mainnet) or tb1q (testnet).
    #[default]
    P2WPKH,
    /// Legacy (BIP-44, P2PKH). Starts with 1 (mainnet) or m/n (testnet).
    P2PKH,
    /// Wrapped SegWit (BIP-49, P2SH-P2WPKH). Starts with 3 (mainnet) or 2 (testnet).
    P2shP2wpkh,
}

/// A UTXO owned by the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletUtxo {
    /// The outpoint (txid:vout) identifying this UTXO.
    pub outpoint: OutPoint,
    /// Value in satoshis.
    pub value: u64,
    /// The scriptPubKey of this output.
    pub script_pubkey: Vec<u8>,
    /// Derivation path used to derive the key controlling this UTXO.
    pub derivation_path: Vec<u32>,
    /// Number of confirmations.
    pub confirmations: u32,
    /// Whether this is a change address.
    pub is_change: bool,
}

/// The HD wallet.
pub struct Wallet {
    /// Master extended private key.
    master_key: ExtendedPrivKey,
    /// Network (for address encoding).
    network: Network,
    /// Generated addresses and their derivation paths.
    addresses: HashMap<String, Vec<u32>>,
    /// Known UTXOs owned by the wallet.
    utxos: HashMap<OutPoint, WalletUtxo>,
    /// Next unused receiving address index.
    next_receive_index: u32,
    /// Next unused change address index.
    next_change_index: u32,
    /// Account number (default: 0).
    account: u32,
    /// Address type to generate.
    address_type: AddressType,
    /// Lookahead window for address scanning (gap limit).
    gap_limit: u32,
}

impl Wallet {
    /// Create a new wallet from a seed.
    ///
    /// The seed should be 16-64 bytes. BIP-39 mnemonic phrases produce a 64-byte seed.
    ///
    /// # Arguments
    /// * `seed` - The seed bytes (16-64 bytes)
    /// * `network` - The Bitcoin network (Mainnet, Testnet, Regtest)
    /// * `address_type` - The type of addresses to generate
    ///
    /// # Errors
    /// Returns an error if the seed is invalid.
    pub fn from_seed(
        seed: &[u8],
        network: Network,
        address_type: AddressType,
    ) -> Result<Self, WalletError> {
        let master = ExtendedPrivKey::from_seed(seed)?;
        Ok(Self {
            master_key: master,
            network,
            addresses: HashMap::new(),
            utxos: HashMap::new(),
            next_receive_index: 0,
            next_change_index: 0,
            account: 0,
            address_type,
            gap_limit: 20,
        })
    }

    /// Get a new receiving address.
    ///
    /// Each call generates a fresh address at the next index in the derivation chain.
    pub fn get_new_address(&mut self) -> Result<String, WalletError> {
        let path = self.derivation_path(false, self.next_receive_index);
        let address = self.derive_address(&path)?;
        self.addresses.insert(address.clone(), path);
        self.next_receive_index += 1;
        Ok(address)
    }

    /// Get a new change address.
    ///
    /// Change addresses use a different derivation path branch than receiving addresses.
    pub fn get_change_address(&mut self) -> Result<String, WalletError> {
        let path = self.derivation_path(true, self.next_change_index);
        let address = self.derive_address(&path)?;
        self.addresses.insert(address.clone(), path);
        self.next_change_index += 1;
        Ok(address)
    }

    /// Peek at the next receiving address without consuming it.
    pub fn peek_address(&self) -> Result<String, WalletError> {
        let path = self.derivation_path(false, self.next_receive_index);
        self.derive_address(&path)
    }

    /// Get an address at a specific index.
    ///
    /// # Arguments
    /// * `is_change` - Whether this is a change address
    /// * `index` - The address index
    pub fn get_address_at(&mut self, is_change: bool, index: u32) -> Result<String, WalletError> {
        let path = self.derivation_path(is_change, index);
        let address = self.derive_address(&path)?;
        self.addresses.insert(address.clone(), path);
        Ok(address)
    }

    /// Build the derivation path for an address.
    ///
    /// BIP-84 (P2WPKH): m/84'/coin'/account'/change/index
    /// BIP-44 (P2PKH): m/44'/coin'/account'/change/index
    fn derivation_path(&self, is_change: bool, index: u32) -> Vec<u32> {
        let purpose = match self.address_type {
            AddressType::P2WPKH | AddressType::P2shP2wpkh => BIP84_PURPOSE,
            AddressType::P2PKH => BIP44_PURPOSE,
        };
        let coin = match self.network {
            Network::Mainnet => COIN_MAINNET,
            Network::Testnet | Network::Regtest => COIN_TESTNET,
        };
        vec![
            purpose,
            coin,
            self.account | HARDENED_FLAG,
            if is_change { 1 } else { 0 },
            index,
        ]
    }

    /// Derive an address from a derivation path.
    fn derive_address(&self, path: &[u32]) -> Result<String, WalletError> {
        let child_key = self.master_key.derive_path(path)?;
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &child_key.secret_key);
        let compressed: [u8; 33] = pubkey.serialize();

        let addr = match self.address_type {
            AddressType::P2WPKH => Address::p2wpkh_from_pubkey(&compressed, self.network),
            AddressType::P2PKH => Address::p2pkh_from_pubkey(&compressed, self.network),
            AddressType::P2shP2wpkh => {
                // P2SH-P2WPKH: the redeemScript is OP_0 <20-byte-pubkey-hash>
                // and the scriptPubKey is P2SH of that redeemScript
                let pubkey_hash = hash160(&compressed);
                let mut redeem_script = vec![0x00, 0x14]; // OP_0 OP_PUSHBYTES_20
                redeem_script.extend_from_slice(&pubkey_hash.0);
                let script_hash = hash160(&redeem_script);
                Address::P2SH {
                    hash: script_hash,
                    network: self.network,
                }
            }
        };

        Ok(addr.encode())
    }

    /// Get the private key for a derivation path (for signing).
    fn get_private_key(&self, path: &[u32]) -> Result<secp256k1::SecretKey, WalletError> {
        let child = self.master_key.derive_path(path)?;
        Ok(child.secret_key)
    }

    /// Add a UTXO owned by the wallet.
    pub fn add_utxo(&mut self, utxo: WalletUtxo) {
        self.utxos.insert(utxo.outpoint.clone(), utxo);
    }

    /// Remove a UTXO (when it is spent).
    pub fn remove_utxo(&mut self, outpoint: &OutPoint) {
        self.utxos.remove(outpoint);
    }

    /// Get a UTXO by outpoint.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<&WalletUtxo> {
        self.utxos.get(outpoint)
    }

    /// Get the wallet balance in satoshis (all UTXOs).
    pub fn balance(&self) -> u64 {
        self.utxos.values().map(|u| u.value).sum()
    }

    /// Get confirmed balance (confirmations >= 1).
    pub fn confirmed_balance(&self) -> u64 {
        self.utxos
            .values()
            .filter(|u| u.confirmations >= 1)
            .map(|u| u.value)
            .sum()
    }

    /// Get unconfirmed balance (confirmations == 0).
    pub fn unconfirmed_balance(&self) -> u64 {
        self.utxos
            .values()
            .filter(|u| u.confirmations == 0)
            .map(|u| u.value)
            .sum()
    }

    /// Build and sign a transaction.
    ///
    /// # Steps
    /// 1. Select UTXOs to cover the output amount + estimated fee
    /// 2. Create transaction inputs from selected UTXOs
    /// 3. Create outputs: recipient(s) + change (if needed)
    /// 4. Estimate fee based on transaction size and fee rate
    /// 5. Sign all inputs
    /// 6. Return the signed transaction
    ///
    /// # Arguments
    /// * `recipients` - List of (address, amount) pairs
    /// * `fee_rate` - Fee rate in satoshis per virtual byte
    ///
    /// # Errors
    /// Returns an error if:
    /// - Insufficient confirmed funds
    /// - Invalid recipient address
    /// - Signing fails
    pub fn create_transaction(
        &mut self,
        recipients: Vec<(String, u64)>,
        fee_rate: f64,
    ) -> Result<Transaction, WalletError> {
        let total_output: u64 = recipients.iter().map(|(_, v)| *v).sum();

        // Select UTXOs (largest-first strategy)
        let mut selected_utxos: Vec<WalletUtxo> = Vec::new();
        let mut selected_value: u64 = 0;

        let mut sorted_utxos: Vec<&WalletUtxo> = self
            .utxos
            .values()
            .filter(|u| u.confirmations >= 1)
            .collect();
        sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));

        for utxo in sorted_utxos {
            selected_utxos.push(utxo.clone());
            selected_value += utxo.value;

            // Estimate size to compute fee
            let estimated_size = estimate_tx_vsize(
                selected_utxos.len(),
                recipients.len() + 1, // +1 for potential change
                self.address_type,
            );
            let estimated_fee = (estimated_size as f64 * fee_rate).ceil() as u64;

            if selected_value >= total_output + estimated_fee {
                break;
            }
        }

        // Calculate final fee
        let estimated_size = estimate_tx_vsize(
            selected_utxos.len(),
            recipients.len() + 1,
            self.address_type,
        );
        let fee = (estimated_size as f64 * fee_rate).ceil() as u64;

        if selected_value < total_output + fee {
            return Err(WalletError::InsufficientFunds {
                have: selected_value,
                need: total_output + fee,
            });
        }

        // Build inputs
        let inputs: Vec<TxIn> = selected_utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: utxo.outpoint.clone(),
                script_sig: vec![], // Empty for SegWit
                sequence: RBF_SEQUENCE,
                witness: vec![],
            })
            .collect();

        // Build outputs
        let mut outputs: Vec<TxOut> = Vec::new();
        for (addr_str, value) in &recipients {
            let addr = Address::from_string(addr_str, Some(self.network))
                .map_err(|_| WalletError::InvalidAddress(addr_str.clone()))?;
            outputs.push(TxOut {
                value: *value,
                script_pubkey: addr.to_script_pubkey(),
            });
        }

        // Change output
        let change = selected_value - total_output - fee;
        if change > DUST_LIMIT {
            let change_addr = self.get_change_address()?;
            let change_addr_obj = Address::from_string(&change_addr, Some(self.network))
                .map_err(|_| WalletError::InvalidAddress(change_addr.clone()))?;
            outputs.push(TxOut {
                value: change,
                script_pubkey: change_addr_obj.to_script_pubkey(),
            });
        }

        let mut tx = Transaction {
            version: 2,
            inputs,
            outputs,
            lock_time: 0,
        };

        // Sign inputs
        let secp = Secp256k1::new();
        for (i, utxo) in selected_utxos.iter().enumerate() {
            let private_key = self.get_private_key(&utxo.derivation_path)?;

            match self.address_type {
                AddressType::P2WPKH => {
                    self.sign_p2wpkh_input(&mut tx, i, utxo, &private_key, &secp)?;
                }
                AddressType::P2PKH => {
                    self.sign_p2pkh_input(&mut tx, i, utxo, &private_key, &secp)?;
                }
                AddressType::P2shP2wpkh => {
                    self.sign_p2sh_p2wpkh_input(&mut tx, i, utxo, &private_key, &secp)?;
                }
            }
        }

        Ok(tx)
    }

    /// Sign a P2WPKH input (native SegWit).
    fn sign_p2wpkh_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        utxo: &WalletUtxo,
        private_key: &secp256k1::SecretKey,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<(), WalletError> {
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, private_key);
        let pubkey_hash = hash160(&pubkey.serialize());

        // Script code for P2WPKH: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        let script_code = p2wpkh_script_code(&pubkey_hash.0);

        let sighash = segwit_v0_sighash(tx, input_index, &script_code, utxo.value, 0x01);

        let msg = Message::from_digest(sighash.0);
        let sig = secp.sign_ecdsa(&msg, private_key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        tx.inputs[input_index].witness = vec![sig_bytes, pubkey.serialize().to_vec()];

        Ok(())
    }

    /// Sign a P2PKH input (legacy).
    fn sign_p2pkh_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        utxo: &WalletUtxo,
        private_key: &secp256k1::SecretKey,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<(), WalletError> {
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, private_key);

        let sighash = legacy_sighash(tx, input_index, &utxo.script_pubkey, 0x01);

        let msg = Message::from_digest(sighash.0);
        let sig = secp.sign_ecdsa(&msg, private_key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        // script_sig: <sig> <pubkey>
        let mut script_sig = Vec::new();
        script_sig.push(sig_bytes.len() as u8);
        script_sig.extend_from_slice(&sig_bytes);
        let pk_bytes = pubkey.serialize();
        script_sig.push(pk_bytes.len() as u8);
        script_sig.extend_from_slice(&pk_bytes);

        tx.inputs[input_index].script_sig = script_sig;

        Ok(())
    }

    /// Sign a P2SH-P2WPKH input (wrapped SegWit).
    fn sign_p2sh_p2wpkh_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        utxo: &WalletUtxo,
        private_key: &secp256k1::SecretKey,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<(), WalletError> {
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, private_key);
        let pubkey_hash = hash160(&pubkey.serialize());

        // The redeemScript is the P2WPKH scriptPubKey: OP_0 <20-byte-pubkey-hash>
        let mut redeem_script = vec![0x00, 0x14];
        redeem_script.extend_from_slice(&pubkey_hash.0);

        // Script code for signing (same as P2WPKH)
        let script_code = p2wpkh_script_code(&pubkey_hash.0);

        let sighash = segwit_v0_sighash(tx, input_index, &script_code, utxo.value, 0x01);

        let msg = Message::from_digest(sighash.0);
        let sig = secp.sign_ecdsa(&msg, private_key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        // scriptSig contains the redeemScript push
        let mut script_sig = Vec::new();
        script_sig.push(redeem_script.len() as u8);
        script_sig.extend_from_slice(&redeem_script);

        tx.inputs[input_index].script_sig = script_sig;
        tx.inputs[input_index].witness = vec![sig_bytes, pubkey.serialize().to_vec()];

        Ok(())
    }

    /// Check if an address belongs to this wallet.
    pub fn is_mine(&self, address: &str) -> bool {
        self.addresses.contains_key(address)
    }

    /// Get the derivation path for an address.
    pub fn get_derivation_path(&self, address: &str) -> Option<&Vec<u32>> {
        self.addresses.get(address)
    }

    /// Get all addresses generated by this wallet.
    pub fn list_addresses(&self) -> Vec<&String> {
        self.addresses.keys().collect()
    }

    /// Get all UTXOs.
    pub fn list_utxos(&self) -> Vec<&WalletUtxo> {
        self.utxos.values().collect()
    }

    /// Get the network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get the address type.
    pub fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Get the gap limit.
    pub fn gap_limit(&self) -> u32 {
        self.gap_limit
    }

    /// Set the gap limit.
    pub fn set_gap_limit(&mut self, gap_limit: u32) {
        self.gap_limit = gap_limit;
    }

    /// Get the account number.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Set the account number.
    pub fn set_account(&mut self, account: u32) {
        self.account = account;
    }

    /// Generate addresses up to the gap limit for scanning.
    ///
    /// Returns all generated addresses for both receiving and change chains.
    pub fn generate_lookahead_addresses(&mut self) -> Result<Vec<String>, WalletError> {
        let mut addresses = Vec::new();

        // Generate receiving addresses
        for i in 0..self.gap_limit {
            let addr = self.get_address_at(false, i)?;
            addresses.push(addr);
        }

        // Generate change addresses
        for i in 0..self.gap_limit {
            let addr = self.get_address_at(true, i)?;
            addresses.push(addr);
        }

        Ok(addresses)
    }

    /// Update UTXO confirmation count.
    pub fn update_confirmations(&mut self, outpoint: &OutPoint, confirmations: u32) {
        if let Some(utxo) = self.utxos.get_mut(outpoint) {
            utxo.confirmations = confirmations;
        }
    }
}

/// Estimate the virtual size (vsize) of a transaction.
///
/// vsize = (weight + 3) / 4
/// weight = base_size * 3 + total_size
fn estimate_tx_vsize(num_inputs: usize, num_outputs: usize, addr_type: AddressType) -> usize {
    match addr_type {
        AddressType::P2WPKH => {
            // P2WPKH:
            // - Overhead: 10 bytes (version 4, locktime 4, marker 1, flag 1)
            // - Input overhead: 32 (txid) + 4 (vout) + 1 (scriptSig len) + 4 (sequence) = 41 bytes
            // - Witness per input: ~107 bytes (1 count + 72 sig + 1 push + 33 pubkey)
            // - Output: 8 (value) + 1 (len) + 22 (P2WPKH script) = 31 bytes
            //
            // weight = (10 + 41*inputs + 31*outputs) * 4 + 107*inputs
            // vsize = weight / 4
            //
            // Simplified: ~68 vbytes per input, ~31 per output, ~11 overhead
            11 + num_inputs * 68 + num_outputs * 31
        }
        AddressType::P2PKH => {
            // P2PKH (legacy, no witness):
            // - Overhead: 10 bytes
            // - Input: 32 + 4 + 1 + 107 (scriptSig) + 4 = ~148 bytes
            // - Output: 8 + 1 + 25 (P2PKH script) = 34 bytes
            10 + num_inputs * 148 + num_outputs * 34
        }
        AddressType::P2shP2wpkh => {
            // P2SH-P2WPKH (wrapped SegWit):
            // - Input scriptSig: 23 bytes (push of 22-byte redeemScript)
            // - Plus witness data
            // ~91 vbytes per input, ~32 per output
            11 + num_inputs * 91 + num_outputs * 32
        }
    }
}

/// Calculate the actual vsize of a signed transaction.
pub fn calculate_vsize(tx: &Transaction) -> usize {
    tx.vsize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> Vec<u8> {
        // BIP-39 test mnemonic "abandon" x12
        // Seed: 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
        hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap()
    }

    #[test]
    fn create_wallet() {
        let seed = test_seed();
        let wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

        assert_eq!(wallet.network(), Network::Mainnet);
        assert_eq!(wallet.address_type(), AddressType::P2WPKH);
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn generate_p2wpkh_addresses_mainnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

        let addr1 = wallet.get_new_address().unwrap();
        let addr2 = wallet.get_new_address().unwrap();

        // Addresses should start with bc1q for mainnet P2WPKH
        assert!(addr1.starts_with("bc1q"), "Address should start with bc1q: {}", addr1);
        assert!(addr2.starts_with("bc1q"), "Address should start with bc1q: {}", addr2);

        // Addresses should be different
        assert_ne!(addr1, addr2);

        // Addresses should be tracked
        assert!(wallet.is_mine(&addr1));
        assert!(wallet.is_mine(&addr2));
    }

    #[test]
    fn generate_p2wpkh_addresses_testnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        let addr = wallet.get_new_address().unwrap();

        // Testnet P2WPKH addresses start with tb1q
        assert!(addr.starts_with("tb1q"), "Address should start with tb1q: {}", addr);
    }

    #[test]
    fn generate_p2pkh_addresses_mainnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2PKH).unwrap();

        let addr = wallet.get_new_address().unwrap();

        // Mainnet P2PKH addresses start with 1
        assert!(addr.starts_with('1'), "Address should start with 1: {}", addr);
    }

    #[test]
    fn generate_p2pkh_addresses_testnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2PKH).unwrap();

        let addr = wallet.get_new_address().unwrap();

        // Testnet P2PKH addresses start with m or n
        assert!(
            addr.starts_with('m') || addr.starts_with('n'),
            "Address should start with m or n: {}",
            addr
        );
    }

    #[test]
    fn derivation_path_mainnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

        let addr = wallet.get_new_address().unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap();

        // BIP-84 mainnet: m/84'/0'/0'/0/0
        assert_eq!(
            path,
            &vec![
                84 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0,
                0
            ]
        );
    }

    #[test]
    fn derivation_path_testnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        let addr = wallet.get_new_address().unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap();

        // BIP-84 testnet: m/84'/1'/0'/0/0
        assert_eq!(
            path,
            &vec![
                84 | HARDENED_FLAG,
                1 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0,
                0
            ]
        );
    }

    #[test]
    fn change_address_path() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2WPKH).unwrap();

        let addr = wallet.get_change_address().unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap();

        // Change addresses use index 1 in the path: m/84'/0'/0'/1/0
        assert_eq!(
            path,
            &vec![
                84 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                1,
                0
            ]
        );
    }

    #[test]
    fn balance_calculation() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        // Add some UTXOs
        let utxo1 = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0,
            },
            value: 100_000,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 6,
            is_change: false,
        };

        let utxo2 = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 1,
            },
            value: 50_000,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 0,
            is_change: false,
        };

        wallet.add_utxo(utxo1);
        wallet.add_utxo(utxo2);

        assert_eq!(wallet.balance(), 150_000);
        assert_eq!(wallet.confirmed_balance(), 100_000);
        assert_eq!(wallet.unconfirmed_balance(), 50_000);
    }

    #[test]
    fn insufficient_funds() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        // Try to create a transaction with no UTXOs
        let result = wallet.create_transaction(
            vec![("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(), 10_000)],
            1.0,
        );

        assert!(matches!(
            result,
            Err(WalletError::InsufficientFunds { have: 0, .. })
        ));
    }

    #[test]
    fn create_simple_transaction() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        // Generate an address and add a UTXO
        let addr = wallet.get_new_address().unwrap();
        let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();

        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0,
            },
            value: 100_000,
            script_pubkey: addr_obj.to_script_pubkey(),
            derivation_path: path,
            confirmations: 6,
            is_change: false,
        };
        wallet.add_utxo(utxo);

        // Create a transaction
        let tx = wallet
            .create_transaction(
                vec![("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(), 50_000)],
                1.0,
            )
            .unwrap();

        // Verify transaction structure
        assert_eq!(tx.version, 2);
        assert_eq!(tx.inputs.len(), 1);
        assert!(tx.outputs.len() >= 1); // At least the recipient

        // Input should have witness data (P2WPKH)
        assert_eq!(tx.inputs[0].witness.len(), 2); // [signature, pubkey]
        assert!(tx.inputs[0].script_sig.is_empty()); // No scriptSig for native SegWit

        // Verify RBF sequence
        assert_eq!(tx.inputs[0].sequence, RBF_SEQUENCE);
    }

    #[test]
    fn change_output_created() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        let addr = wallet.get_new_address().unwrap();
        let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();

        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0,
            },
            value: 100_000,
            script_pubkey: addr_obj.to_script_pubkey(),
            derivation_path: path,
            confirmations: 6,
            is_change: false,
        };
        wallet.add_utxo(utxo);

        // Send only 10,000 sats (should create change output)
        let tx = wallet
            .create_transaction(
                vec![("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(), 10_000)],
                1.0,
            )
            .unwrap();

        // Should have 2 outputs: recipient + change
        assert_eq!(tx.outputs.len(), 2);

        // Change output should be > dust limit
        let change_output = &tx.outputs[1];
        assert!(change_output.value > DUST_LIMIT);
    }

    #[test]
    fn dust_change_absorbed() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        let addr = wallet.get_new_address().unwrap();
        let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();

        // UTXO with exact amount + small fee (leaving dust as change)
        // Fee estimate: 11 + 68*1 + 31*2 = 141 vbytes at 1 sat/vbyte = 141 sats
        // For change to be dust (< 546), we need: UTXO - 10000 - fee < 546
        // So UTXO < 10000 + 141 + 546 = 10687
        // Use 10600 to leave 459 sats change (dust)
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0,
            },
            value: 10_600, // 10000 output + ~141 fee + ~459 dust change
            script_pubkey: addr_obj.to_script_pubkey(),
            derivation_path: path,
            confirmations: 6,
            is_change: false,
        };
        wallet.add_utxo(utxo);

        let tx = wallet
            .create_transaction(
                vec![("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(), 10_000)],
                1.0,
            )
            .unwrap();

        // Should have only 1 output (no change because it would be dust)
        // Change would be: 10600 - 10000 - 141 = 459 sats < 546 (dust)
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn lookahead_addresses() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        wallet.set_gap_limit(5);
        let addresses = wallet.generate_lookahead_addresses().unwrap();

        // Should generate gap_limit * 2 addresses (receiving + change)
        assert_eq!(addresses.len(), 10);

        // All should be tracked
        for addr in &addresses {
            assert!(wallet.is_mine(addr));
        }
    }

    #[test]
    fn vsize_estimation() {
        // P2WPKH transaction with 1 input and 2 outputs
        let vsize = estimate_tx_vsize(1, 2, AddressType::P2WPKH);
        // Should be around 110-115 vbytes
        assert!(vsize >= 100 && vsize <= 150, "Unexpected vsize: {}", vsize);

        // P2PKH transaction (legacy) should be larger
        let legacy_vsize = estimate_tx_vsize(1, 2, AddressType::P2PKH);
        assert!(legacy_vsize > vsize, "Legacy should be larger than SegWit");
    }

    #[test]
    fn p2sh_p2wpkh_address() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2shP2wpkh).unwrap();

        let addr = wallet.get_new_address().unwrap();

        // P2SH addresses start with 3 on mainnet
        assert!(addr.starts_with('3'), "P2SH address should start with 3: {}", addr);
    }

    #[test]
    fn remove_utxo() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        let outpoint = OutPoint {
            txid: rustoshi_primitives::Hash256::ZERO,
            vout: 0,
        };

        let utxo = WalletUtxo {
            outpoint: outpoint.clone(),
            value: 100_000,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 6,
            is_change: false,
        };

        wallet.add_utxo(utxo);
        assert_eq!(wallet.balance(), 100_000);

        wallet.remove_utxo(&outpoint);
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn update_confirmations() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        let outpoint = OutPoint {
            txid: rustoshi_primitives::Hash256::ZERO,
            vout: 0,
        };

        let utxo = WalletUtxo {
            outpoint: outpoint.clone(),
            value: 100_000,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 0,
            is_change: false,
        };

        wallet.add_utxo(utxo);
        assert_eq!(wallet.confirmed_balance(), 0);

        wallet.update_confirmations(&outpoint, 1);
        assert_eq!(wallet.confirmed_balance(), 100_000);
    }
}
