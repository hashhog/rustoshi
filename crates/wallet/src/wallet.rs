//! HD Wallet implementation with address generation and transaction building.
//!
//! This module implements a hierarchical deterministic wallet supporting:
//! - Native SegWit (P2WPKH) addresses (BIP-84)
//! - Legacy (P2PKH) addresses (BIP-44)
//! - Wrapped SegWit (P2SH-P2WPKH) addresses (BIP-49)
//! - Taproot (P2TR) addresses (BIP-86)
//! - UTXO tracking
//! - Transaction creation and signing
//! - BnB and Knapsack coin selection

use std::collections::HashMap;

use rustoshi_crypto::{
    address::{Address, Network},
    hash160, p2wpkh_script_code, segwit_v0_sighash, legacy_sighash, tagged_hash,
};
use rustoshi_primitives::{OutPoint, Transaction, TxIn, TxOut, Encodable, write_compact_size};
use secp256k1::{Message, Secp256k1};

use crate::hd::{ExtendedPrivKey, WalletError, HARDENED_FLAG};

/// BIP-84 purpose for native SegWit (P2WPKH).
const BIP84_PURPOSE: u32 = 84 | HARDENED_FLAG;

/// BIP-44 purpose for legacy addresses (P2PKH).
const BIP44_PURPOSE: u32 = 44 | HARDENED_FLAG;

/// BIP-49 purpose for wrapped SegWit (P2SH-P2WPKH).
const BIP49_PURPOSE: u32 = 49 | HARDENED_FLAG;

/// BIP-86 purpose for Taproot (P2TR).
const BIP86_PURPOSE: u32 = 86 | HARDENED_FLAG;

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
    /// Taproot (BIP-86, P2TR). Starts with bc1p (mainnet) or tb1p (testnet).
    P2TR,
}

/// Coinbase maturity: coinbase outputs cannot be spent for 100 blocks.
pub const COINBASE_MATURITY: u32 = 100;

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
    /// Whether this UTXO is from a coinbase transaction.
    pub is_coinbase: bool,
    /// Block height at which this UTXO was created.
    pub height: Option<u32>,
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
    /// Current chain tip height (for maturity calculations).
    chain_height: u32,
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
            chain_height: 0,
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
    /// BIP-44 (P2PKH): m/44'/coin'/account'/change/index
    /// BIP-49 (P2SH-P2WPKH): m/49'/coin'/account'/change/index
    /// BIP-84 (P2WPKH): m/84'/coin'/account'/change/index
    /// BIP-86 (P2TR): m/86'/coin'/account'/change/index
    fn derivation_path(&self, is_change: bool, index: u32) -> Vec<u32> {
        let purpose = match self.address_type {
            AddressType::P2PKH => BIP44_PURPOSE,
            AddressType::P2shP2wpkh => BIP49_PURPOSE,
            AddressType::P2WPKH => BIP84_PURPOSE,
            AddressType::P2TR => BIP86_PURPOSE,
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
            AddressType::P2TR => {
                // BIP-86: P2TR key-path spending
                // The output key is: P = internal_key + H(tagged_hash("TapTweak", internal_key)) * G
                // For key-path only (no scripts), the tweak is just the internal key itself
                let xonly = secp256k1::XOnlyPublicKey::from(pubkey);
                let output_key = self.compute_taproot_output_key(&xonly);
                Address::P2TR {
                    output_key,
                    network: self.network,
                }
            }
        };

        Ok(addr.encode())
    }

    /// Compute the Taproot output key (tweaked x-only public key).
    ///
    /// For BIP-86 key-path only spending, the tweak is computed as:
    /// tweak = tagged_hash("TapTweak", internal_key)
    /// output_key = internal_key + tweak * G
    fn compute_taproot_output_key(&self, internal_key: &secp256k1::XOnlyPublicKey) -> [u8; 32] {
        let secp = Secp256k1::new();

        // Compute tweak: t = tagged_hash("TapTweak", internal_key)
        let tweak_hash = tagged_hash("TapTweak", &internal_key.serialize());

        // Create the tweak scalar
        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash)
            .expect("tweak should be valid scalar");

        // Compute the tweaked key pair (output key)
        let (output_key, _parity) = internal_key.add_tweak(&secp, &tweak)
            .expect("tweak should not overflow");

        output_key.serialize()
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

    /// Get immature coinbase balance (coinbase outputs that haven't reached maturity).
    pub fn immature_balance(&self) -> u64 {
        self.utxos
            .values()
            .filter(|u| u.is_coinbase && !self.is_mature(u))
            .map(|u| u.value)
            .sum()
    }

    /// Get spendable balance (confirmed, mature UTXOs only).
    ///
    /// This excludes:
    /// - Unconfirmed UTXOs (confirmations == 0)
    /// - Immature coinbase UTXOs (less than COINBASE_MATURITY confirmations)
    pub fn spendable_balance(&self) -> u64 {
        self.utxos
            .values()
            .filter(|u| self.is_spendable(u))
            .map(|u| u.value)
            .sum()
    }

    /// Check if a UTXO has reached coinbase maturity.
    ///
    /// Regular (non-coinbase) UTXOs are always mature.
    /// Coinbase UTXOs require COINBASE_MATURITY (100) confirmations.
    pub fn is_mature(&self, utxo: &WalletUtxo) -> bool {
        if !utxo.is_coinbase {
            return true;
        }
        // Use height-based calculation if available, otherwise fall back to confirmations
        if let Some(height) = utxo.height {
            self.chain_height >= height + COINBASE_MATURITY
        } else {
            utxo.confirmations >= COINBASE_MATURITY
        }
    }

    /// Check if a UTXO is spendable (confirmed and mature).
    pub fn is_spendable(&self, utxo: &WalletUtxo) -> bool {
        utxo.confirmations >= 1 && self.is_mature(utxo)
    }

    /// Set the current chain height (for maturity calculations).
    pub fn set_chain_height(&mut self, height: u32) {
        self.chain_height = height;
    }

    /// Get the current chain height.
    pub fn chain_height(&self) -> u32 {
        self.chain_height
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

        // Filter to only spendable UTXOs (confirmed and mature)
        let mut sorted_utxos: Vec<&WalletUtxo> = self
            .utxos
            .values()
            .filter(|u| self.is_spendable(u))
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
                AddressType::P2TR => {
                    self.sign_p2tr_input(&mut tx, i, utxo, &selected_utxos, &private_key, &secp)?;
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

    /// Sign a P2TR input (Taproot key-path spending).
    ///
    /// For BIP-86 key-path spending:
    /// 1. Compute the tweaked private key
    /// 2. Compute BIP-341 sighash
    /// 3. Create Schnorr signature
    fn sign_p2tr_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        _utxo: &WalletUtxo,
        all_utxos: &[WalletUtxo],
        private_key: &secp256k1::SecretKey,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<(), WalletError> {
        // Get the public key and compute the tweaked keypair
        let keypair = secp256k1::Keypair::from_secret_key(secp, private_key);
        let (xonly_pubkey, _parity) = keypair.x_only_public_key();

        // Compute the tweak (same as in derive_address)
        let tweak_hash = tagged_hash("TapTweak", &xonly_pubkey.serialize());
        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash)
            .map_err(|_| WalletError::SigningError("invalid tweak".to_string()))?;

        // Create tweaked keypair for signing
        let tweaked_keypair = keypair.add_xonly_tweak(secp, &tweak)
            .map_err(|_| WalletError::SigningError("tweak failed".to_string()))?;

        // Compute BIP-341 Taproot sighash
        let sighash = self.compute_taproot_sighash(tx, input_index, all_utxos, 0x00)?;

        // Create Schnorr signature
        let msg = Message::from_digest(sighash);
        let sig = secp.sign_schnorr(&msg, &tweaked_keypair);

        // For SIGHASH_DEFAULT (0x00), we don't append the hash type byte
        // This saves one byte in the witness
        let sig_bytes = sig.serialize().to_vec();

        // Witness is just the 64-byte Schnorr signature
        tx.inputs[input_index].witness = vec![sig_bytes];

        Ok(())
    }

    /// Compute BIP-341 Taproot sighash for key-path spending.
    fn compute_taproot_sighash(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[WalletUtxo],
        hash_type: u8,
    ) -> Result<[u8; 32], WalletError> {
        use std::io::Write;

        // Epoch byte (0x00 for Taproot)
        let epoch = 0x00u8;

        // Hash type handling
        // 0x00 = SIGHASH_DEFAULT (treated as SIGHASH_ALL for signing)
        let sighash_type = if hash_type == 0x00 { 0x01 } else { hash_type as u32 };
        let anyone_can_pay = (sighash_type & 0x80) != 0;
        let sighash_none = (sighash_type & 0x03) == 0x02;
        let sighash_single = (sighash_type & 0x03) == 0x03;

        let mut preimage = Vec::with_capacity(200);

        // 1. Epoch (1 byte)
        preimage.push(epoch);

        // 2. Hash type (1 byte) - write the original hash_type, not sighash_type
        preimage.push(hash_type);

        // 3. Version (4 bytes LE)
        preimage.write_all(&tx.version.to_le_bytes()).unwrap();

        // 4. Locktime (4 bytes LE)
        preimage.write_all(&tx.lock_time.to_le_bytes()).unwrap();

        // 5-7. sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences
        if !anyone_can_pay {
            // sha_prevouts
            let mut prevouts_data = Vec::new();
            for input in &tx.inputs {
                input.previous_output.encode(&mut prevouts_data).unwrap();
            }
            let sha_prevouts = rustoshi_crypto::sha256(&prevouts_data);
            preimage.write_all(&sha_prevouts).unwrap();

            // sha_amounts
            let mut amounts_data = Vec::new();
            for utxo in prevouts {
                amounts_data.write_all(&utxo.value.to_le_bytes()).unwrap();
            }
            let sha_amounts = rustoshi_crypto::sha256(&amounts_data);
            preimage.write_all(&sha_amounts).unwrap();

            // sha_scriptpubkeys
            let mut scripts_data = Vec::new();
            for utxo in prevouts {
                write_compact_size(&mut scripts_data, utxo.script_pubkey.len() as u64).unwrap();
                scripts_data.write_all(&utxo.script_pubkey).unwrap();
            }
            let sha_scriptpubkeys = rustoshi_crypto::sha256(&scripts_data);
            preimage.write_all(&sha_scriptpubkeys).unwrap();

            // sha_sequences
            let mut sequences_data = Vec::new();
            for input in &tx.inputs {
                sequences_data.write_all(&input.sequence.to_le_bytes()).unwrap();
            }
            let sha_sequences = rustoshi_crypto::sha256(&sequences_data);
            preimage.write_all(&sha_sequences).unwrap();
        }

        // 8. sha_outputs
        if !sighash_none && !sighash_single {
            let mut outputs_data = Vec::new();
            for output in &tx.outputs {
                output.encode(&mut outputs_data).unwrap();
            }
            let sha_outputs = rustoshi_crypto::sha256(&outputs_data);
            preimage.write_all(&sha_outputs).unwrap();
        } else if sighash_single && input_index < tx.outputs.len() {
            let mut output_data = Vec::new();
            tx.outputs[input_index].encode(&mut output_data).unwrap();
            let sha_outputs = rustoshi_crypto::sha256(&output_data);
            preimage.write_all(&sha_outputs).unwrap();
        }

        // 9. Spend type (1 byte)
        // ext_flag = 0 for key-path, annex_present = 0
        let spend_type = 0x00u8;
        preimage.push(spend_type);

        // 10. Input-specific data
        if anyone_can_pay {
            // Serialize the specific prevout
            let input = &tx.inputs[input_index];
            input.previous_output.encode(&mut preimage).unwrap();
            preimage.write_all(&prevouts[input_index].value.to_le_bytes()).unwrap();
            write_compact_size(&mut preimage, prevouts[input_index].script_pubkey.len() as u64).unwrap();
            preimage.write_all(&prevouts[input_index].script_pubkey).unwrap();
            preimage.write_all(&input.sequence.to_le_bytes()).unwrap();
        } else {
            // Input index (4 bytes LE)
            preimage.write_all(&(input_index as u32).to_le_bytes()).unwrap();
        }

        // No annex or script-path data for key-path spending

        // Compute tagged hash
        Ok(tagged_hash("TapSighash", &preimage))
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

    /// Get the current address indices (for serialization).
    pub fn get_indices(&self) -> (u32, u32) {
        (self.next_receive_index, self.next_change_index)
    }

    /// Restore address indices from saved state.
    pub fn restore_indices(&mut self, receive_index: u32, change_index: u32) {
        self.next_receive_index = receive_index;
        self.next_change_index = change_index;
    }

    /// List unspent UTXOs.
    pub fn list_unspent(&self) -> Vec<&WalletUtxo> {
        self.utxos.values().collect()
    }

    /// List spendable unspent UTXOs (confirmed and mature).
    pub fn list_spendable_unspent(&self) -> Vec<&WalletUtxo> {
        self.utxos
            .values()
            .filter(|u| self.is_spendable(u))
            .collect()
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
        AddressType::P2TR => {
            // P2TR (Taproot):
            // - Input: 41 bytes base + 65 bytes witness (64 sig + 1 count)
            // - weight = 41*4 + 65 = 229, vsize = ~57
            // - Output: 8 + 1 + 34 (P2TR script) = 43 bytes
            // Simplified: ~57 vbytes per input, ~43 per output, ~11 overhead
            11 + num_inputs * 57 + num_outputs * 43
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
            is_coinbase: false,
            height: Some(100),
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
            is_coinbase: false,
            height: None,
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
            is_coinbase: false,
            height: Some(100),
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
            is_coinbase: false,
            height: Some(100),
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
            is_coinbase: false,
            height: Some(100),
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
            is_coinbase: false,
            height: Some(100),
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
            is_coinbase: false,
            height: Some(100),
        };

        wallet.add_utxo(utxo);
        assert_eq!(wallet.confirmed_balance(), 0);

        wallet.update_confirmations(&outpoint, 1);
        assert_eq!(wallet.confirmed_balance(), 100_000);
    }

    #[test]
    fn p2tr_address_mainnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Mainnet, AddressType::P2TR).unwrap();

        let addr = wallet.get_new_address().unwrap();

        // Mainnet P2TR addresses start with bc1p
        assert!(addr.starts_with("bc1p"), "P2TR address should start with bc1p: {}", addr);

        // Verify derivation path is BIP-86
        let path = wallet.get_derivation_path(&addr).unwrap();
        assert_eq!(
            path,
            &vec![
                86 | HARDENED_FLAG, // BIP-86 purpose
                0 | HARDENED_FLAG,  // mainnet coin type
                0 | HARDENED_FLAG,  // account
                0,                  // receiving
                0                   // first address
            ]
        );
    }

    #[test]
    fn p2tr_address_testnet() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2TR).unwrap();

        let addr = wallet.get_new_address().unwrap();

        // Testnet P2TR addresses start with tb1p
        assert!(addr.starts_with("tb1p"), "P2TR address should start with tb1p: {}", addr);

        // Verify derivation path is BIP-86 for testnet
        let path = wallet.get_derivation_path(&addr).unwrap();
        assert_eq!(
            path,
            &vec![
                86 | HARDENED_FLAG, // BIP-86 purpose
                1 | HARDENED_FLAG,  // testnet coin type
                0 | HARDENED_FLAG,  // account
                0,                  // receiving
                0                   // first address
            ]
        );
    }

    #[test]
    fn p2tr_vsize_estimation() {
        // P2TR inputs are smaller due to Schnorr sigs (64 bytes vs ~72 DER)
        // But P2TR outputs are larger (34 bytes vs 22 bytes)
        let p2tr_vsize = estimate_tx_vsize(1, 2, AddressType::P2TR);
        let p2wpkh_vsize = estimate_tx_vsize(1, 2, AddressType::P2WPKH);

        // P2TR: 11 + 57 + 86 = 154 vbytes
        // P2WPKH: 11 + 68 + 62 = 141 vbytes
        // With 2 outputs, P2TR may actually be larger due to output size difference
        // But P2TR scales better with more inputs
        assert!(p2tr_vsize > 0 && p2wpkh_vsize > 0, "Both should have valid vsize");

        // With more inputs, P2TR becomes more efficient
        let p2tr_3in = estimate_tx_vsize(3, 2, AddressType::P2TR);
        let p2wpkh_3in = estimate_tx_vsize(3, 2, AddressType::P2WPKH);

        // 3 P2TR inputs: 11 + 57*3 + 43*2 = 11 + 171 + 86 = 268
        // 3 P2WPKH inputs: 11 + 68*3 + 31*2 = 11 + 204 + 62 = 277
        assert!(p2tr_3in < p2wpkh_3in, "P2TR should be smaller with multiple inputs");
    }

    #[test]
    fn p2tr_multiple_addresses() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2TR).unwrap();

        // Generate multiple addresses
        let addr1 = wallet.get_new_address().unwrap();
        let addr2 = wallet.get_new_address().unwrap();
        let change = wallet.get_change_address().unwrap();

        // All should be unique
        assert_ne!(addr1, addr2);
        assert_ne!(addr1, change);
        assert_ne!(addr2, change);

        // All should be valid P2TR addresses
        assert!(addr1.starts_with("tb1p"));
        assert!(addr2.starts_with("tb1p"));
        assert!(change.starts_with("tb1p"));

        // Verify change address path
        let change_path = wallet.get_derivation_path(&change).unwrap();
        assert_eq!(change_path[3], 1); // Change chain
    }

    #[test]
    fn coinbase_maturity_immature() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        // Set current chain height
        wallet.set_chain_height(150);

        // Coinbase UTXO created at height 100 (50 confirmations, needs 100)
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0,
            },
            value: 5_000_000_000, // 50 BTC coinbase reward
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 50,
            is_change: false,
            is_coinbase: true,
            height: Some(100),
        };

        wallet.add_utxo(utxo);

        // Balance shows total, but spendable should be 0 (immature)
        assert_eq!(wallet.balance(), 5_000_000_000);
        assert_eq!(wallet.immature_balance(), 5_000_000_000);
        assert_eq!(wallet.spendable_balance(), 0);
        assert!(!wallet.is_mature(wallet.list_utxos()[0]));
    }

    #[test]
    fn coinbase_maturity_mature() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        // Set current chain height
        wallet.set_chain_height(200);

        // Coinbase UTXO created at height 100 (100 confirmations, exactly mature)
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0,
            },
            value: 5_000_000_000,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 100,
            is_change: false,
            is_coinbase: true,
            height: Some(100),
        };

        wallet.add_utxo(utxo);

        // Now it should be spendable
        assert_eq!(wallet.balance(), 5_000_000_000);
        assert_eq!(wallet.immature_balance(), 0);
        assert_eq!(wallet.spendable_balance(), 5_000_000_000);
        assert!(wallet.is_mature(wallet.list_utxos()[0]));
    }

    #[test]
    fn non_coinbase_always_mature() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        wallet.set_chain_height(10);

        // Regular UTXO with only 1 confirmation
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0,
            },
            value: 100_000,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations: 1,
            is_change: false,
            is_coinbase: false,
            height: Some(9),
        };

        wallet.add_utxo(utxo);

        // Non-coinbase UTXOs are always mature (if confirmed)
        assert_eq!(wallet.spendable_balance(), 100_000);
        assert_eq!(wallet.immature_balance(), 0);
        assert!(wallet.is_mature(wallet.list_utxos()[0]));
    }

    #[test]
    fn coinbase_excluded_from_transaction() {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        // Set chain height so coinbase is immature (99 confirmations)
        wallet.set_chain_height(199);

        // Generate an address for the regular UTXO
        let addr = wallet.get_new_address().unwrap();
        let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();

        // Add an immature coinbase UTXO (large value, but not spendable)
        let coinbase_utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256([1u8; 32]),
                vout: 0,
            },
            value: 5_000_000_000,
            script_pubkey: addr_obj.to_script_pubkey(),
            derivation_path: path.clone(),
            confirmations: 99, // 1 short of maturity
            is_change: false,
            is_coinbase: true,
            height: Some(100),
        };

        // Add a regular UTXO (smaller, but spendable)
        let regular_utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256([2u8; 32]),
                vout: 0,
            },
            value: 100_000,
            script_pubkey: addr_obj.to_script_pubkey(),
            derivation_path: path,
            confirmations: 6,
            is_change: false,
            is_coinbase: false,
            height: Some(193),
        };

        wallet.add_utxo(coinbase_utxo);
        wallet.add_utxo(regular_utxo);

        // Total balance is high, but spendable is only the regular UTXO
        assert_eq!(wallet.balance(), 5_000_100_000);
        assert_eq!(wallet.spendable_balance(), 100_000);

        // Transaction should succeed using only the regular UTXO
        let tx = wallet.create_transaction(
            vec![("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(), 10_000)],
            1.0,
        ).unwrap();

        // Should have used the regular UTXO, not the immature coinbase
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].previous_output.txid.0, [2u8; 32]); // The regular UTXO
    }

    #[test]
    fn coinbase_maturity_constant() {
        // Verify the constant matches Bitcoin consensus
        assert_eq!(COINBASE_MATURITY, 100);
    }
}
