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

use std::collections::{HashMap, HashSet};

use rand::thread_rng;
use rustoshi_crypto::{
    address::{Address, Network},
    hash160, p2wpkh_script_code, segwit_v0_sighash, legacy_sighash, secp_ctx, sha256,
    taproot::{compute_taproot_sighash as crypto_compute_taproot_sighash, TaprootPrevouts,
              SIGHASH_DEFAULT},
};
use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use secp256k1::{Message, Secp256k1};

use crate::coin_selection::{select_coins, CoinSelectionParams};
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

/// Sentinel derivation path stored on UTXOs / index entries that belong to an
/// *imported* (non-HD) key rather than a seed-derived path. It is never a valid
/// BIP-32 path (`u32::MAX` as the single element), so `scan_block_at` can route
/// the address lookup through [`Wallet::imported_keys`] instead of attempting an
/// HD derivation. Mirrors the way Core distinguishes imported scripts in the
/// legacy keychain (`mapKeys` vs. HD `mapHdPubKeys`).
const IMPORTED_PATH: &[u32] = &[u32::MAX];

/// Sentinel derivation path for scriptPubKeys watched via an imported output
/// descriptor (`importdescriptors` on a watch-only wallet). Like
/// [`IMPORTED_PATH`] it is never a valid BIP-32 path; `scan_block_at` routes
/// the address lookup through [`Wallet::watched_scripts`] (decoding the
/// address straight from the script) instead of attempting HD derivation.
/// Mirrors Core's `DescriptorScriptPubKeyMan` set-of-scripts ownership.
const WATCHED_PATH: &[u32] = &[u32::MAX - 1];

/// A scriptPubKey registered through `importdescriptors` (watch-only or
/// pubkey-descriptor import). Mirrors the per-script view of Core's
/// `DescriptorScriptPubKeyMan::GetScriptPubKeys()`.
#[derive(Clone, Debug)]
pub struct WatchedScript {
    /// The canonical descriptor (with checksum) this script came from —
    /// reported as `parent_desc` by `getaddressinfo`.
    pub descriptor: String,
    /// User label supplied at import time (empty when none).
    pub label: String,
    /// Whether the descriptor is solvable (false for `addr()` / `raw()`,
    /// matching Core's `IsSolvable`).
    pub solvable: bool,
    /// The serialized public key controlling this script, when the
    /// descriptor exposes one (single-key descriptors). Used by
    /// `getaddressinfo`'s `pubkey` field.
    pub pubkey: Option<Vec<u8>>,
}

/// A private key imported into the wallet out-of-band (via `importprivkey`),
/// outside the HD seed derivation. Mirrors the subset of Core's legacy
/// `CKey` + `mapAddressBook` bookkeeping that `importprivkey` populates.
#[derive(Clone, Debug)]
pub struct ImportedKey {
    /// The secp256k1 secret key controlling the imported scriptPubKeys.
    pub secret_key: secp256k1::SecretKey,
    /// The primary address (the wallet's configured address type) the key
    /// controls, used to label credits in transaction history.
    pub address: String,
    /// Optional user label supplied at import time (Core's `strLabel`).
    pub label: String,
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
    /// Outpoints temporarily marked unspendable by `lockunspent`.
    ///
    /// Mirrors Bitcoin Core's per-wallet `setLockedCoins` (see
    /// `bitcoin-core/src/wallet/wallet.h::LockCoin/UnlockCoin`). Locked
    /// outputs are excluded from automatic coin selection but can still be
    /// spent by explicit user input. This is in-memory only — equivalent to
    /// Core's `persistent=false` default. Persistent (DB-backed) locks can
    /// be added later without breaking the surface.
    locked_coins: HashSet<OutPoint>,
    /// Outgoing transactions the wallet created but that may still be
    /// unconfirmed.
    ///
    /// FIX-61 (W118 BUG-2 / BUG-3): `bumpfee`/`psbtbumpfee` need to locate
    /// the original transaction by txid in order to (a) verify it signals
    /// BIP-125 RBF and (b) re-build a replacement with a higher fee. Core
    /// keeps every wallet-created tx in `CWallet::mapWallet` with a chain
    /// position; we keep a much narrower book — just the raw `Transaction`
    /// plus the spent prevouts (mirrored from `selected_utxos` at
    /// build-time) — keyed by txid, indexed in send order. Entries are
    /// removed once a confirmation is recorded for the txid.
    ///
    /// Mirrors Core's `mapWallet` for the outgoing-tx-tracking subset.
    /// Reference: `bitcoin-core/src/wallet/feebumper.cpp::PreconditionChecks`.
    sent_txs: HashMap<Hash256, SentTx>,
    /// Wallet transaction history, in block-connect order (oldest first).
    ///
    /// One [`TxHistoryEntry`] per wallet-relevant transaction observed by
    /// [`Self::scan_block`] (a tx that credits a wallet-owned output and/or
    /// debits a wallet-owned coin). This is the backing store for
    /// `listtransactions` / `gettransaction`, mirroring the subset of Core's
    /// `CWallet::mapWallet` those RPCs read (see
    /// `bitcoin-core/src/wallet/rpc/transactions.cpp`). Confirmations and the
    /// coinbase `generate`/`immature` distinction are NOT frozen here — they
    /// are recomputed against the live `chain_height` at read time so a
    /// maturing coinbase or a deepening confirmation count is always current.
    history: Vec<TxHistoryEntry>,
    /// Private keys imported out-of-band via `importprivkey`, keyed by every
    /// standard single-key scriptPubKey the imported key controls (P2WPKH,
    /// P2PKH, P2SH-P2WPKH) so a block / rescan scan credits funds paid to ANY
    /// of those scripts. The seed-derived keychain is unaffected. Mirrors the
    /// imported subset of Core's legacy keychain that `importprivkey` writes.
    imported_keys: HashMap<Vec<u8>, ImportedKey>,
    /// ScriptPubKeys watched via `importdescriptors`, keyed by raw script.
    /// These participate in `build_script_index` (so block scans credit
    /// funds paid to them) but carry no signing capability. Mirrors Core's
    /// `DescriptorScriptPubKeyMan` script set for watch-only descriptors.
    watched_scripts: HashMap<Vec<u8>, WatchedScript>,
    /// Whether this wallet holds private keys (Core's
    /// `WALLET_FLAG_DISABLE_PRIVATE_KEYS`, inverted). When `false`:
    /// - no HD scripts are derived or indexed (Core sets up no SPKMs for
    ///   such wallets — wallet.cpp:3104-3105), so the placeholder zero seed
    ///   the in-memory object is built from can never mint spendable-looking
    ///   addresses (the old behaviour was a fund-theft hazard: the all-zero
    ///   seed is publicly known);
    /// - key generation and signing refuse with an explicit error.
    private_keys_enabled: bool,
}

/// A per-output or per-input line item in a wallet transaction's `details[]`.
///
/// Mirrors one element of Core's `COutputEntry`/`details` array
/// (`wallet/rpc/transactions.cpp` `ListTransactions`).
#[derive(Clone, Debug)]
pub struct TxDetail {
    /// The address this credit/debit involves (the wallet's own address for a
    /// receive/generate, the recipient address for a send). `None` for
    /// non-standard scripts that don't decode to an address.
    pub address: Option<String>,
    /// "send" | "receive" | "generate" | "immature".
    pub category: String,
    /// Amount in satoshis. NEGATIVE for the `send` category, positive otherwise.
    pub amount_sats: i64,
    /// The output index this line item refers to.
    pub vout: u32,
    /// Fee in satoshis (NEGATIVE), present only on `send` line items.
    pub fee_sats: Option<i64>,
}

/// A wallet-relevant transaction recorded at block-connect time.
///
/// Records the immutable facts of the transaction (its identity, the block it
/// confirmed in, the net effect on the wallet, the per-output/input details,
/// and the raw bytes) so `listtransactions` / `gettransaction` can reproduce
/// Core's response shape without re-scanning the chain.
#[derive(Clone, Debug)]
pub struct TxHistoryEntry {
    /// The transaction id (internal byte order; reverse for the RPC `txid`).
    pub txid: Hash256,
    /// Whether this transaction is a coinbase (drives generate/immature).
    pub is_coinbase: bool,
    /// Total satoshis this tx credited to wallet-owned outputs.
    pub credit_sats: u64,
    /// Total satoshis this tx debited from wallet-owned coins (value of the
    /// wallet UTXOs it spent).
    pub debit_sats: u64,
    /// Fee in satoshis, present only when the wallet spent into this tx
    /// (`debit_sats > 0`): sum(wallet inputs) - sum(all outputs).
    pub fee_sats: Option<u64>,
    /// Block height the tx confirmed at.
    pub block_height: u32,
    /// Block hash the tx confirmed in (internal byte order).
    pub block_hash: Hash256,
    /// Block timestamp (Unix seconds).
    pub block_time: u64,
    /// Per-output (receive/generate) + per-spend (send) line items.
    pub details: Vec<TxDetail>,
    /// Raw transaction bytes (full witness serialization) for the `hex` field.
    pub raw_tx: Vec<u8>,
}

/// A wallet-originated transaction the wallet remembers after `create_transaction`.
///
/// Held by [`Wallet::sent_txs`] keyed by txid so [`Wallet::bump_fee`] /
/// [`Wallet::psbt_bump_fee`] can re-build a replacement.
#[derive(Clone, Debug)]
pub struct SentTx {
    /// The signed transaction as broadcast.
    pub tx: Transaction,
    /// The wallet UTXOs that were consumed by this transaction. Indexed in
    /// the same order as `tx.inputs` so that `bump_fee` can reuse them
    /// directly (preserving derivation paths + values for re-signing).
    pub spent_utxos: Vec<WalletUtxo>,
    /// Fee paid (computed as sum(in) - sum(out) at creation time).
    pub fee_sats: u64,
    /// The vsize of the original signed transaction. Used to compute the
    /// minimum bump per BIP-125 rule 4 + rule 6.
    pub vsize: usize,
    /// Whether the transaction is still in mempool (or assumed-mempool).
    /// We do not track confirmations directly; consumers call
    /// [`Wallet::mark_sent_tx_confirmed`] when a block confirms it.
    pub confirmed: bool,
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
            locked_coins: HashSet::new(),
            sent_txs: HashMap::new(),
            history: Vec::new(),
            imported_keys: HashMap::new(),
            watched_scripts: HashMap::new(),
            private_keys_enabled: true,
        })
    }

    /// Whether this wallet holds private keys (the inverse of Core's
    /// `WALLET_FLAG_DISABLE_PRIVATE_KEYS`).
    pub fn private_keys_enabled(&self) -> bool {
        self.private_keys_enabled
    }

    /// Mark this wallet as private-key-less (`createwallet
    /// disable_private_keys=true`). Disables HD derivation/indexing, key
    /// generation, and signing.
    pub fn set_private_keys_enabled(&mut self, enabled: bool) {
        self.private_keys_enabled = enabled;
    }

    /// Create a new wallet from a BIP-39 mnemonic phrase.
    ///
    /// The mnemonic is validated (word count, wordlist membership, checksum)
    /// before being passed through PBKDF2-HMAC-SHA512(2048 iters, salt =
    /// "mnemonic" || passphrase) to produce a 64-byte BIP-39 seed, which is
    /// then fed into BIP-32 master-key derivation via [`Self::from_seed`].
    ///
    /// This is the high-level entry point most callers should use; it lets
    /// rustoshi interop with mnemonics produced by Sparrow, Electrum, Trezor,
    /// Ledger, and BIP-39 paper backups.
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic words (12/15/18/21/24, lowercase, English wordlist)
    /// * `passphrase` - Optional BIP-39 passphrase (pass `""` for none). Stretches the
    ///   seed but is NOT recoverable from the mnemonic — losing it loses the wallet.
    /// * `network` - Bitcoin network for address encoding
    /// * `address_type` - Address type to generate
    ///
    /// # Errors
    /// - [`WalletError::InvalidPath`] wrapping the BIP-39 reason if the mnemonic
    ///   is structurally invalid (bad word count, unknown word, checksum mismatch).
    /// - Other [`WalletError`] variants from [`Self::from_seed`].
    ///
    /// # Example
    /// ```rust,ignore
    /// use rustoshi_wallet::{Wallet, AddressType};
    /// use rustoshi_crypto::address::Network;
    ///
    /// let words = ["abandon"; 11];
    /// let mut mnemonic: Vec<&str> = words.to_vec();
    /// mnemonic.push("about");
    /// let wallet = Wallet::from_mnemonic(&mnemonic, "", Network::Mainnet, AddressType::P2TR)?;
    /// ```
    pub fn from_mnemonic(
        mnemonic: &[&str],
        passphrase: &str,
        network: Network,
        address_type: AddressType,
    ) -> Result<Self, WalletError> {
        // Strict validation: rejects word-count/unknown-word/checksum issues
        // before we waste 2048 iterations of PBKDF2.
        crate::bip39::validate_mnemonic(mnemonic)
            .map_err(|e| WalletError::InvalidPath(format!("invalid BIP-39 mnemonic: {}", e)))?;
        let seed = crate::bip39::mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed(&seed, network, address_type)
    }

    /// Get a new receiving address.
    ///
    /// Each call generates a fresh address at the next index in the derivation chain.
    pub fn get_new_address(&mut self) -> Result<String, WalletError> {
        if !self.private_keys_enabled {
            // Core: getnewaddress on a disable_private_keys wallet -> -4
            // "Error: This wallet has no available keys" (addresses.cpp:47).
            // The placeholder zero seed must never mint addresses.
            return Err(WalletError::SigningError(
                "This wallet has no available keys".into(),
            ));
        }
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
        if !self.private_keys_enabled {
            return Err(WalletError::SigningError(
                "This wallet has no available keys".into(),
            ));
        }
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
        let secp = secp_ctx();
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, &child_key.secret_key);
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
    ///
    /// W27-C P1: delegates to the canonical helper in
    /// `rustoshi-crypto::taproot` so all 3 BIP-86 tweak sites
    /// (this, `sign_p2tr_input`, `descriptor::make_p2tr_script`)
    /// share one source of truth.
    fn compute_taproot_output_key(&self, internal_key: &secp256k1::XOnlyPublicKey) -> [u8; 32] {
        let (output_key, _parity) =
            rustoshi_crypto::taproot::compute_taproot_output_key(internal_key, None)
                .expect("BIP-86 tweak should not overflow on a valid x-only key");
        output_key
    }

    /// Get the private key for a derivation path (for signing).
    fn get_private_key(&self, path: &[u32]) -> Result<secp256k1::SecretKey, WalletError> {
        let child = self.master_key.derive_path(path)?;
        Ok(child.secret_key)
    }

    /// Derive the compressed public key + BIP32 key-origin (master
    /// fingerprint + path) for a wallet-owned derivation path.
    ///
    /// Used by the PSBT Updater role (`walletprocesspsbt`) to attach genuine
    /// `PSBT_IN_BIP32_DERIVATION` records for inputs the wallet can sign.
    /// Reuses the same HD engine (`ExtendedPrivKey::derive_path`) the signer
    /// uses, so the pubkey is the exact one that will sign the input.
    pub fn pubkey_and_origin(
        &self,
        path: &[u32],
    ) -> Result<([u8; 33], crate::psbt::KeyOrigin), WalletError> {
        let secp = secp_ctx();
        let child = self.master_key.derive_path(path)?;
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, &child.secret_key);
        let origin = crate::psbt::KeyOrigin::new(self.master_key.fingerprint(), path.to_vec());
        Ok((pubkey.serialize(), origin))
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

        // Collect spendable UTXOs (confirmed, mature, unlocked). Mirror
        // Core's AvailableCoins which excludes setLockedCoins from automatic
        // coin selection (bitcoin-core/src/wallet/spend.cpp).
        let available_utxos: Vec<WalletUtxo> = self
            .utxos
            .values()
            .filter(|u| self.is_spendable(u) && !self.locked_coins.contains(&u.outpoint))
            .cloned()
            .collect();

        // Per-input vsize for the wallet's address type (used by coin_selection
        // to compute effective-value and fee per UTXO).
        let input_vsize = input_vsize_for(self.address_type);

        // Bootstrap fee estimate: assume 1 input + N+1 outputs (N recipients + change)
        // so the module has a concrete starting target. It will refine this via
        // effective-value filtering; a slight undercount here is fine because we
        // recompute the final fee below using the actual selected input count.
        let bootstrap_fee = {
            let est_sz = estimate_tx_vsize(1, recipients.len() + 1, self.address_type);
            (est_sz as f64 * fee_rate).ceil() as u64
        };

        // Per-output cost of adding the change output (vsize * feerate).
        let change_output_vsize = output_vsize_for(self.address_type);
        let change_cost_weight = change_output_vsize * 4; // stored as weight in CoinSelectionParams

        let params = CoinSelectionParams {
            target_value: total_output + bootstrap_fee,
            fee_rate,
            change_cost: change_cost_weight as u64,
            change_spend_cost: input_vsize as u64, // future spend of change at long_term_fee_rate
            long_term_fee_rate: 10.0 / 1000.0, // 10 sat/kvB = 0.01 sat/vbyte (Core default)
            min_change: DUST_LIMIT,
            input_weight: input_vsize * 4,
        };

        let mut rng = thread_rng();
        let selection = select_coins(&available_utxos, &params, &mut rng)
            .ok_or(WalletError::InsufficientFunds {
                have: available_utxos.iter().map(|u| u.value).sum(),
                need: total_output + bootstrap_fee,
            })?;

        let selected_utxos = selection.selected;
        let selected_value: u64 = selected_utxos.iter().map(|u| u.value).sum();

        // Recompute the final fee with the actual input count selected. We
        // check for change first to decide whether to include it in the vsize
        // estimate. cost_of_change from the module gives the creation+spend cost;
        // absorb change into fee when it wouldn't be economic to create the output.
        let cost_of_change = params.cost_of_change();

        // Tentative fee without change output
        let fee_no_change = {
            let sz = estimate_tx_vsize(selected_utxos.len(), recipients.len(), self.address_type);
            (sz as f64 * fee_rate).ceil() as u64
        };
        // Tentative fee with change output
        let fee_with_change = {
            let sz = estimate_tx_vsize(selected_utxos.len(), recipients.len() + 1, self.address_type);
            (sz as f64 * fee_rate).ceil() as u64
        };

        // Decide whether to create a change output.
        // Core: add change when selected_value > total_output + fee + cost_of_change
        // (i.e., change is large enough to be worth creating).
        // We also suppress dust regardless (change < DUST_LIMIT).
        let change_candidate = selected_value.saturating_sub(total_output + fee_with_change);
        let add_change = change_candidate > DUST_LIMIT && change_candidate > cost_of_change;

        let (fee, change_amount): (u64, u64) = if add_change {
            (fee_with_change, change_candidate)
        } else {
            // Absorb the remainder into fee (no change output)
            (fee_no_change, 0)
        };

        // Sanity check: we actually have enough funds after refining the fee.
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

        // Change output (only when economic, per cost_of_change check above)
        if add_change {
            let change_addr = self.get_change_address()?;
            let change_addr_obj = Address::from_string(&change_addr, Some(self.network))
                .map_err(|_| WalletError::InvalidAddress(change_addr.clone()))?;
            outputs.push(TxOut {
                value: change_amount,
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
        let secp = secp_ctx();
        for (i, utxo) in selected_utxos.iter().enumerate() {
            let private_key = self.get_private_key(&utxo.derivation_path)?;

            match self.address_type {
                AddressType::P2WPKH => {
                    self.sign_p2wpkh_input(&mut tx, i, utxo, &private_key, secp)?;
                }
                AddressType::P2PKH => {
                    self.sign_p2pkh_input(&mut tx, i, utxo, &private_key, secp)?;
                }
                AddressType::P2shP2wpkh => {
                    self.sign_p2sh_p2wpkh_input(&mut tx, i, utxo, &private_key, secp)?;
                }
                AddressType::P2TR => {
                    self.sign_p2tr_input(&mut tx, i, utxo, &selected_utxos, &private_key, secp)?;
                }
            }
        }

        // FIX-61 (W118 BUG-2 / BUG-3): record the outgoing tx so a later
        // `bumpfee` / `psbtbumpfee` can find it by txid. We store the
        // signed Transaction, the WalletUtxos it consumed (in input order),
        // the resolved fee, and the vsize for BIP-125-rule-4 bump
        // calculations. Mirrors Core's `CWallet::AddToWallet` for outgoing
        // tx entries.
        let txid = tx.txid();
        let total_in: u64 = selected_utxos.iter().map(|u| u.value).sum();
        let total_out: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let computed_fee = total_in.saturating_sub(total_out);
        let vsize = tx.vsize();
        self.sent_txs.insert(
            txid,
            SentTx {
                tx: tx.clone(),
                spent_utxos: selected_utxos.clone(),
                fee_sats: computed_fee,
                vsize,
                confirmed: false,
            },
        );

        Ok(tx)
    }

    /// Look up an outgoing transaction by txid.
    ///
    /// Returns the recorded [`SentTx`] (signed transaction + spent UTXOs +
    /// fee) if [`Wallet::create_transaction`] previously created it.
    ///
    /// Used by [`Wallet::bump_fee`] / [`Wallet::psbt_bump_fee`] to locate
    /// the original tx for fee-bump replacement.
    pub fn get_sent_tx(&self, txid: &Hash256) -> Option<&SentTx> {
        self.sent_txs.get(txid)
    }

    /// Mark an outgoing transaction as confirmed.
    ///
    /// After confirmation a tx is no longer eligible for fee bumping (per
    /// Core's `feebumper.cpp::PreconditionChecks`, which refuses to bump a
    /// confirmed tx). Callers in the node validation path should invoke
    /// this when a block containing the txid lands.
    pub fn mark_sent_tx_confirmed(&mut self, txid: &Hash256) {
        if let Some(entry) = self.sent_txs.get_mut(txid) {
            entry.confirmed = true;
        }
    }

    /// Forget an outgoing transaction. Used by tests + by long-running
    /// nodes that prune old entries.
    pub fn forget_sent_tx(&mut self, txid: &Hash256) {
        self.sent_txs.remove(txid);
    }

    /// FIX-61 (W118 BUG-2): bump the fee on a previously-sent outgoing tx
    /// (BIP-125 replace-by-fee).
    ///
    /// Minimal-viable implementation per the W118 audit closure plan:
    ///
    /// 1. Locate the original tx by `txid` in [`Wallet::sent_txs`].
    /// 2. Validate it is **unconfirmed** (per Core's PreconditionChecks).
    /// 3. Validate at least one input signals BIP-125 RBF (sequence
    ///    ≤ `0xFFFFFFFD`; per BIP-125 rule "Opt-in").
    /// 4. Locate the change output owned by the wallet ([`is_mine`]). We
    ///    pick the largest wallet-owned output as the change candidate so
    ///    a degenerate recipient-also-mine case does not collapse the
    ///    transaction.
    /// 5. Compute `new_fee = orig_fee + bump_delta`, where `bump_delta =
    ///    ceil(vsize * incremental_fee_rate)` and `incremental_fee_rate`
    ///    defaults to 1 sat/vB (Core's `DEFAULT_INCREMENTAL_RELAY_FEE`).
    ///    `fee_rate_override` (sat/vB) lets the caller pin a higher rate
    ///    explicitly; in that case `new_fee = max(ceil(vsize * fee_rate),
    ///    orig_fee + bump_delta)` so BIP-125 rule 4 still holds.
    /// 6. Reduce the change-output value by `(new_fee - orig_fee)`. If
    ///    the change drops below the dust threshold, refuse with a clear
    ///    error rather than silently destroying funds.
    /// 7. Re-build the transaction with the same inputs / outputs /
    ///    sequences (with the change value reduced) and re-sign.
    /// 8. Return the replacement [`Transaction`] (still in memory; the
    ///    RPC layer will broadcast it).
    ///
    /// # Limitations (intentional for the minimal viable cut)
    ///
    /// - **Requires an existing change output owned by the wallet.** No
    ///   input-adding path, no change-removal path. If `(orig_fee + delta)
    ///   ≥ change_value`, the bump fails with a clear error.
    /// - **Incremental-only bump.** Full Core fee-target inference
    ///   (`conf_target`/`estimate_mode`) is deferred. The caller may pass
    ///   an explicit absolute `fee_rate_override` to bump beyond the
    ///   minimum.
    /// - **Same-script-type signing.** Re-signs through the same per-
    ///   AddressType helper as [`create_transaction`]. Mixed-script
    ///   sends (rare in this wallet) re-use the same path.
    ///
    /// Reference: `bitcoin-core/src/wallet/feebumper.cpp` (Core's full
    /// implementation includes input adding, change removal, and full fee
    /// estimation — all of which are deferred here).
    pub fn bump_fee(
        &mut self,
        txid: &Hash256,
        fee_rate_override: Option<f64>,
    ) -> Result<Transaction, WalletError> {
        let (new_tx, _new_fee, _orig_fee) = self.build_bumped_tx(txid, fee_rate_override, true)?;
        Ok(new_tx)
    }

    /// FIX-61 (W118 BUG-3): same as [`bump_fee`] but returns the
    /// replacement transaction as an unsigned [`Psbt`] (Creator+Updater
    /// roles only — signing is left to a separate role).
    ///
    /// The PSBT contains the same inputs and outputs as the would-be
    /// bumped tx; sequences preserve BIP-125 opt-in; no witnesses or
    /// scriptSigs are set. Mirrors Core's `psbtbumpfee` shape.
    pub fn psbt_bump_fee(
        &mut self,
        txid: &Hash256,
        fee_rate_override: Option<f64>,
    ) -> Result<crate::psbt::Psbt, WalletError> {
        let (new_tx, _new_fee, _orig_fee) =
            self.build_bumped_tx(txid, fee_rate_override, false)?;
        crate::psbt::Psbt::from_unsigned_tx(new_tx).map_err(|e| {
            WalletError::SigningError(format!("PSBT build failed: {}", e))
        })
    }

    /// Shared bump-fee core. Returns `(replacement_tx, new_fee, orig_fee)`.
    ///
    /// When `sign` is `true`, the returned tx is signed in-place (suitable
    /// for `bumpfee`). When `false`, witnesses/scriptSigs are left empty
    /// (suitable for wrapping in a PSBT).
    fn build_bumped_tx(
        &mut self,
        txid: &Hash256,
        fee_rate_override: Option<f64>,
        sign: bool,
    ) -> Result<(Transaction, u64, u64), WalletError> {
        // ---- locate + validate the original tx --------------------------
        let entry = self.sent_txs.get(txid).cloned().ok_or_else(|| {
            WalletError::SigningError(format!(
                "bumpfee: txid {} not found in wallet outgoing-tx record",
                hex::encode(txid.0)
            ))
        })?;
        if entry.confirmed {
            return Err(WalletError::SigningError(
                "bumpfee: transaction already confirmed; cannot replace".to_string(),
            ));
        }
        let signals_rbf = entry
            .tx
            .inputs
            .iter()
            .any(|i| i.sequence <= 0xFFFF_FFFD);
        if !signals_rbf {
            return Err(WalletError::SigningError(
                "bumpfee: transaction does not signal BIP-125 RBF \
                 (no input has sequence <= 0xfffffffd); cannot replace"
                    .to_string(),
            ));
        }
        // ---- find the change output (largest wallet-owned output) -------
        let mut change_idx_opt: Option<usize> = None;
        let mut change_value: u64 = 0;
        for (idx, out) in entry.tx.outputs.iter().enumerate() {
            // Decode the scriptPubKey back to an address string so we can
            // check is_mine against the wallet's known addresses. If the
            // address fails to decode we just skip — non-recognised
            // outputs are recipients by definition.
            let addr_str = match address_from_script(&out.script_pubkey, self.network) {
                Some(s) => s,
                None => continue,
            };
            if self.is_mine(&addr_str) && out.value > change_value {
                change_idx_opt = Some(idx);
                change_value = out.value;
            }
        }
        let change_idx = change_idx_opt.ok_or_else(|| {
            WalletError::SigningError(
                "bumpfee: no wallet-owned change output found on transaction; \
                 cannot reduce a non-change output (would destroy recipient funds)"
                    .to_string(),
            )
        })?;

        // ---- compute the fee bump --------------------------------------
        const INCREMENTAL_FEE_RATE: f64 = 1.0; // sat/vB; Core DEFAULT_INCREMENTAL_RELAY_FEE
        let incremental_delta = (entry.vsize as f64 * INCREMENTAL_FEE_RATE).ceil() as u64;
        // Floor: orig_fee + 1 sat/vB * vsize  (BIP-125 rule 4 + Core rule 6).
        let min_new_fee = entry.fee_sats.saturating_add(incremental_delta.max(1));
        // If caller specifies an explicit rate, target that rate but never
        // dip below the BIP-125 floor.
        let new_fee = if let Some(rate) = fee_rate_override {
            if rate <= 0.0 {
                return Err(WalletError::SigningError(
                    "bumpfee: fee_rate must be > 0".to_string(),
                ));
            }
            let target_fee = (entry.vsize as f64 * rate).ceil() as u64;
            target_fee.max(min_new_fee)
        } else {
            min_new_fee
        };
        let delta = new_fee.checked_sub(entry.fee_sats).ok_or_else(|| {
            WalletError::SigningError(
                "bumpfee: new fee not greater than original (no bump needed)".to_string(),
            )
        })?;
        if delta == 0 {
            return Err(WalletError::SigningError(
                "bumpfee: new fee equals original fee; no bump needed".to_string(),
            ));
        }
        if delta >= change_value {
            return Err(WalletError::SigningError(format!(
                "bumpfee: fee bump delta ({} sats) exceeds change output value ({} sats); \
                 cannot bump without adding inputs (not yet supported)",
                delta, change_value
            )));
        }
        let new_change_value = change_value - delta;
        if new_change_value < DUST_LIMIT {
            return Err(WalletError::SigningError(format!(
                "bumpfee: change output would drop below dust threshold ({} < {}); \
                 cannot bump without removing change (not yet supported)",
                new_change_value, DUST_LIMIT
            )));
        }

        // ---- build the replacement tx -----------------------------------
        // Same inputs (with original sequences — BIP-125 opt-in preserved).
        // Same outputs but with reduced change. No script_sig / witness
        // populated yet — we re-sign below.
        let inputs: Vec<TxIn> = entry
            .tx
            .inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.previous_output.clone(),
                script_sig: vec![],
                sequence: i.sequence,
                witness: vec![],
            })
            .collect();
        let outputs: Vec<TxOut> = entry
            .tx
            .outputs
            .iter()
            .enumerate()
            .map(|(idx, o)| TxOut {
                value: if idx == change_idx { new_change_value } else { o.value },
                script_pubkey: o.script_pubkey.clone(),
            })
            .collect();
        let mut new_tx = Transaction {
            version: entry.tx.version,
            inputs,
            outputs,
            lock_time: entry.tx.lock_time,
        };

        if sign {
            let secp = secp_ctx();
            for (i, utxo) in entry.spent_utxos.iter().enumerate() {
                let private_key = self.get_private_key(&utxo.derivation_path)?;
                match self.address_type {
                    AddressType::P2WPKH => {
                        self.sign_p2wpkh_input(&mut new_tx, i, utxo, &private_key, secp)?
                    }
                    AddressType::P2PKH => {
                        self.sign_p2pkh_input(&mut new_tx, i, utxo, &private_key, secp)?
                    }
                    AddressType::P2shP2wpkh => {
                        self.sign_p2sh_p2wpkh_input(&mut new_tx, i, utxo, &private_key, secp)?
                    }
                    AddressType::P2TR => self.sign_p2tr_input(
                        &mut new_tx,
                        i,
                        utxo,
                        &entry.spent_utxos,
                        &private_key,
                        secp,
                    )?,
                }
            }
            // Record the replacement so a follow-up bump can find it.
            let new_txid = new_tx.txid();
            let new_vsize = new_tx.vsize();
            self.sent_txs.insert(
                new_txid,
                SentTx {
                    tx: new_tx.clone(),
                    spent_utxos: entry.spent_utxos.clone(),
                    fee_sats: new_fee,
                    vsize: new_vsize,
                    confirmed: false,
                },
            );
        }

        Ok((new_tx, new_fee, entry.fee_sats))
    }

    /// Sign a single input of an externally-built transaction with a wallet UTXO.
    ///
    /// Used by the `signrawtransactionwithwallet` RPC. Looks up the UTXO that
    /// `tx.inputs[input_index]` spends in the wallet's UTXO store, derives the
    /// matching private key, detects the script type from the UTXO's
    /// `script_pubkey`, and dispatches to the appropriate sighash + signing
    /// helper. On success, the input's `script_sig` and/or `witness` are
    /// populated in place.
    ///
    /// `all_prev_utxos` MUST be in the same order as `tx.inputs` and is used
    /// for BIP-341 Taproot multi-input sighash. Pass an empty slice if no
    /// taproot inputs are present (the function falls back to the per-input
    /// utxo for non-taproot scripts).
    ///
    /// Returns `Err(SigningError)` if no wallet UTXO matches the input's
    /// `previous_output`, or if the script type is unsupported (P2WSH, bare
    /// multisig, OP_RETURN, etc. — these would need PSBT-style handling).
    /// Reference: `bitcoin-core/src/wallet/rpc/spend.cpp::signrawtransactionwithwallet`.
    pub fn sign_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        all_prev_utxos: &[WalletUtxo],
    ) -> Result<(), WalletError> {
        if !self.private_keys_enabled {
            // Core: SendMoney/signing on a disable_private_keys wallet -> -4
            // "Error: Private keys are disabled for this wallet"
            // (spend.cpp:177-178). The zero placeholder seed must never sign.
            return Err(WalletError::SigningError(
                "Private keys are disabled for this wallet".into(),
            ));
        }
        if input_index >= tx.inputs.len() {
            return Err(WalletError::SigningError(format!(
                "input_index {} out of range ({} inputs)",
                input_index,
                tx.inputs.len()
            )));
        }

        // Look up the UTXO this input is spending in the wallet.
        let outpoint = tx.inputs[input_index].previous_output.clone();
        let utxo = self
            .utxos
            .get(&outpoint)
            .ok_or_else(|| {
                WalletError::SigningError(format!(
                    "UTXO {:?}:{} not in wallet",
                    outpoint.txid, outpoint.vout
                ))
            })?
            .clone();

        // Get the private key for this UTXO's derivation path.
        let private_key = self.get_private_key(&utxo.derivation_path)?;
        let secp = secp_ctx();

        // Detect script type from the actual scriptPubKey bytes, NOT
        // self.address_type — the wallet may have UTXOs of different script
        // types if it was reconfigured, and a "real" signrawtransaction must
        // honor the prevout's script.
        let spk = &utxo.script_pubkey;
        if is_p2wpkh_spk(spk) {
            self.sign_p2wpkh_input(tx, input_index, &utxo, &private_key, secp)?;
        } else if is_p2wsh_spk(spk) {
            // P2WSH cannot be signed from a single-key wallet UTXO — the
            // signer needs the witness_script and (for multisig) multiple
            // private keys. Callers must drive this through PSBT (where
            // witness_script + key-origin info live) and use
            // `sign_p2wsh_input` directly.
            return Err(WalletError::SigningError(format!(
                "input {} is P2WSH; sign via PSBT or call sign_p2wsh_input \
                 directly with the witness script and signing keys",
                input_index
            )));
        } else if is_p2pkh_spk(spk) {
            self.sign_p2pkh_input(tx, input_index, &utxo, &private_key, secp)?;
        } else if is_p2sh_spk(spk) {
            // We only know how to sign P2SH-P2WPKH (BIP-49 wrapped segwit).
            // The redeem script for a wallet-owned P2SH is reconstructed in
            // sign_p2sh_p2wpkh_input from the public key derived at the UTXO's
            // path, so this is correct provided the wallet stored the UTXO as
            // BIP-49. Wallets that hold P2SH-P2WSH UTXOs must drive signing
            // through PSBT (witness_script lives there).
            self.sign_p2sh_p2wpkh_input(tx, input_index, &utxo, &private_key, secp)?;
        } else if is_p2tr_spk(spk) {
            // Taproot key-path. all_prev_utxos must cover every input for the
            // BIP-341 sighash; if caller passed an empty slice, fall back to a
            // single-element slice (works for single-input txs).
            let prevouts: &[WalletUtxo] = if all_prev_utxos.is_empty() {
                std::slice::from_ref(&utxo)
            } else {
                all_prev_utxos
            };
            self.sign_p2tr_input(tx, input_index, &utxo, prevouts, &private_key, secp)?;
        } else {
            return Err(WalletError::SigningError(format!(
                "unsupported scriptPubKey type for input {} (len={}, first byte=0x{:02x})",
                input_index,
                spk.len(),
                spk.first().copied().unwrap_or(0)
            )));
        }

        Ok(())
    }

    /// Sign one input with an EXPLICITLY supplied private key + prevout, instead
    /// of an HD-derived wallet key.
    ///
    /// This is the engine `signrawtransactionwithkey` drives: the temporary
    /// keystore is the caller's WIF keys (not the wallet HD tree), and the
    /// prevout comes from the caller's `prevtxs` array, so `sign_input`'s
    /// `get_private_key(&utxo.derivation_path)` lookup is bypassed. The actual
    /// sighash + ECDSA/Schnorr signing is delegated to the SAME per-script
    /// signers `sign_input` uses (`sign_p2wpkh_input` / `sign_p2pkh_input` /
    /// `sign_p2sh_p2wpkh_input` / `sign_p2tr_input`) — NO sighash or signing is
    /// reimplemented here; only the key SOURCE differs.
    ///
    /// `prevout` is the UTXO being spent (its `script_pubkey` selects the script
    /// type and its `value` feeds the BIP-143 / BIP-341 sighash). `all_prevouts`
    /// must cover every input in spend order for the Taproot (BIP-341) sighash;
    /// for non-Taproot inputs it is unused.
    ///
    /// Reference: `bitcoin-core/src/script/sign.cpp::ProduceSignature` driven
    /// from `rpc/rawtransaction.cpp::SignTransaction` with a `FillableSigningProvider`
    /// keystore built from the provided keys.
    pub fn sign_input_with_key(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        prevout: &WalletUtxo,
        all_prevouts: &[WalletUtxo],
        private_key: &secp256k1::SecretKey,
    ) -> Result<(), WalletError> {
        if input_index >= tx.inputs.len() {
            return Err(WalletError::SigningError(format!(
                "input_index {} out of range ({} inputs)",
                input_index,
                tx.inputs.len()
            )));
        }
        let secp = secp_ctx();
        let spk = &prevout.script_pubkey;
        if is_p2wpkh_spk(spk) {
            self.sign_p2wpkh_input(tx, input_index, prevout, private_key, secp)?;
        } else if is_p2pkh_spk(spk) {
            self.sign_p2pkh_input(tx, input_index, prevout, private_key, secp)?;
        } else if is_p2sh_spk(spk) {
            // Only P2SH-P2WPKH (BIP-49 wrapped segwit) is reconstructible from a
            // single key; the redeem script is rebuilt inside the signer and the
            // P2SH commitment is checked there.
            self.sign_p2sh_p2wpkh_input(tx, input_index, prevout, private_key, secp)?;
        } else if is_p2tr_spk(spk) {
            let prevouts: &[WalletUtxo] = if all_prevouts.is_empty() {
                std::slice::from_ref(prevout)
            } else {
                all_prevouts
            };
            self.sign_p2tr_input(tx, input_index, prevout, prevouts, private_key, secp)?;
        } else if is_p2wsh_spk(spk) {
            return Err(WalletError::SigningError(format!(
                "input {} is P2WSH; sign via PSBT / signrawtransactionwithwallet \
                 with the witness script (multisig is not single-key signable)",
                input_index
            )));
        } else {
            return Err(WalletError::SigningError(format!(
                "unsupported scriptPubKey type for input {} (len={}, first byte=0x{:02x})",
                input_index,
                spk.len(),
                spk.first().copied().unwrap_or(0)
            )));
        }
        Ok(())
    }

    /// The standard single-key scriptPubKeys a raw secp256k1 key controls on a
    /// given network: P2WPKH, P2PKH, P2SH-P2WPKH and key-path P2TR (BIP-86).
    /// Exactly the set `import_private_key` registers — exposed for the
    /// temporary keystore `KeySigner` builds without mutating wallet state.
    fn script_pubkeys_for_key(
        secret_key: &secp256k1::SecretKey,
        network: Network,
    ) -> Vec<Vec<u8>> {
        let secp = secp_ctx();
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, secret_key);
        let pubkey_hash = hash160(&pubkey.serialize());

        let mut out = Vec::with_capacity(4);
        out.push(Address::P2WPKH { hash: pubkey_hash, network }.to_script_pubkey());
        out.push(Address::P2PKH { hash: pubkey_hash, network }.to_script_pubkey());
        // P2SH-P2WPKH: scriptPubKey = P2SH(redeem = OP_0 <20-byte pubkey hash>).
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&pubkey_hash.0);
        out.push(Address::P2SH { hash: hash160(&redeem), network }.to_script_pubkey());
        // Key-path P2TR (BIP-86): scriptPubKey commits to the tweaked output key.
        let xonly = secp256k1::XOnlyPublicKey::from(pubkey);
        if let Ok((output_key, _parity)) =
            rustoshi_crypto::taproot::compute_taproot_output_key(&xonly, None)
        {
            out.push(Address::P2TR { output_key, network }.to_script_pubkey());
        }
        out
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

        // Defense-in-depth (W31): the redeem_script is reconstructed from
        // *our* private key, so this check is always tautologically true on
        // the safe path. But a future refactor that lets the caller supply
        // a redeem_script would silently turn this into the same confused-
        // deputy bug as `sign_psbt_input` had pre-W31. Verify the P2SH
        // commitment now and have the assertion fail loud if anything
        // changes.
        rustoshi_crypto::verify_p2sh_commitment(&redeem_script, &utxo.script_pubkey).map_err(
            |e| {
                WalletError::SigningError(format!(
                    "P2SH-P2WPKH commitment verification failed: {}",
                    e
                ))
            },
        )?;

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

    /// Sign a P2WSH input (BIP-143 segwit-v0 with arbitrary witness script).
    ///
    /// Computes the BIP-143 segwit-v0 sighash with `witness_script` as
    /// scriptCode, signs once per supplied key, and assembles the witness:
    ///
    /// - **CHECKMULTISIG (M-of-N):** witness =
    ///   `[<empty>, sig1, ..., sigM, witness_script]`. The leading empty push
    ///   is the legacy `OP_CHECKMULTISIG` off-by-one stack pad and is required
    ///   for any multisig witness script. Signatures are appended in the order
    ///   `sign_keys` are supplied, which the caller must order to match the
    ///   pubkey order in the witness script (Core enforces this in
    ///   `script/sign.cpp::SignStep`).
    /// - **Single-key CHECKSIG:** witness = `[sig, witness_script]`.
    ///
    /// `value` is the prevout amount (committed in the BIP-143 preimage).
    /// `hash_type` is the sighash byte (e.g. 0x01 = SIGHASH_ALL).
    ///
    /// Reference: `bitcoin-core/src/script/sign.cpp::ProduceSignature` +
    /// `wallet/scriptpubkeyman.cpp::SignTransaction`.
    pub fn sign_p2wsh_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        witness_script: &[u8],
        value: u64,
        sign_keys: &[secp256k1::SecretKey],
        hash_type: u8,
    ) -> Result<(), WalletError> {
        if input_index >= tx.inputs.len() {
            return Err(WalletError::SigningError(format!(
                "input_index {} out of range ({} inputs)",
                input_index,
                tx.inputs.len()
            )));
        }
        if sign_keys.is_empty() {
            return Err(WalletError::SigningError(
                "sign_p2wsh_input requires at least one signing key".to_string(),
            ));
        }

        let secp = secp_ctx();
        let sighash = segwit_v0_sighash(
            tx,
            input_index,
            witness_script,
            value,
            hash_type as u32,
        );
        let msg = Message::from_digest(sighash.0);

        let sigs: Vec<Vec<u8>> = sign_keys
            .iter()
            .map(|sk| {
                let sig = secp.sign_ecdsa(&msg, sk);
                let mut out = sig.serialize_der().to_vec();
                out.push(hash_type);
                out
            })
            .collect();

        let mut witness: Vec<Vec<u8>> = Vec::with_capacity(sigs.len() + 2);
        if is_multisig_witness_script(witness_script) {
            // CHECKMULTISIG bug-compat: leading empty stack item.
            witness.push(Vec::new());
            witness.extend(sigs);
        } else {
            // Single-CHECKSIG: caller is responsible for any prefix items
            // (e.g. pubkey for OP_DUP OP_HASH160 ... CHECKSIG) but for the
            // common bare-CHECKSIG-on-pubkey shape that's just <sig>.
            witness.extend(sigs);
        }
        witness.push(witness_script.to_vec());

        tx.inputs[input_index].witness = witness;
        tx.inputs[input_index].script_sig = Vec::new();
        Ok(())
    }

    /// Sign a P2SH-P2WSH input (legacy P2SH wrapping a P2WSH inner script).
    ///
    /// The outer P2SH commits to `redeem_script = OP_0 <SHA256(witness_script)>`.
    /// The witness is computed exactly as in [`Self::sign_p2wsh_input`]; the
    /// scriptSig is set to a single push of the redeem script (the only thing
    /// the legacy P2SH consensus check looks at — it then unwraps the redeem
    /// script as if it were the scriptPubKey).
    ///
    /// `prevout_spk` is the 23-byte P2SH scriptPubKey of the UTXO being
    /// spent. We verify that `HASH160(redeem_script) == prevout_spk[2..22]`
    /// before signing; without that check a caller that hands us a
    /// `witness_script` unrelated to the prevout can extract a valid
    /// SIGHASH_ALL signature and steal funds (the
    /// hotbuns/W30-rustoshi-PSBT bug class). See
    /// `rustoshi_crypto::p2sh::verify_p2sh_commitment`.
    ///
    /// Reference: BIP-141 §"Backward compatibility" + `script/interpreter.cpp::EvalScript`
    /// (the P2SH unwrap branch when the redeem script is a witness program).
    pub fn sign_p2sh_p2wsh_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        witness_script: &[u8],
        value: u64,
        sign_keys: &[secp256k1::SecretKey],
        hash_type: u8,
        prevout_spk: &[u8],
    ) -> Result<(), WalletError> {
        // Build the outer P2SH redeem script: OP_0 <0x20> <SHA256(witness_script)>.
        let ws_hash = sha256(witness_script);
        let mut redeem_script = Vec::with_capacity(34);
        redeem_script.push(0x00); // OP_0
        redeem_script.push(0x20); // push 32 bytes
        redeem_script.extend_from_slice(&ws_hash);

        // W31: verify the P2SH commitment BEFORE producing any signature.
        // If the caller-supplied witness_script doesn't actually unlock the
        // prevout, signing it would just hand an attacker a SIGHASH_ALL
        // signature for an unrelated script.
        rustoshi_crypto::verify_p2sh_commitment(&redeem_script, prevout_spk).map_err(|e| {
            WalletError::SigningError(format!(
                "P2SH-P2WSH commitment verification failed: {}",
                e
            ))
        })?;

        // Inner P2WSH witness assembly (sets tx.inputs[idx].witness).
        self.sign_p2wsh_input(tx, input_index, witness_script, value, sign_keys, hash_type)?;

        // scriptSig is a single push of the 34-byte redeem script.
        let mut script_sig = Vec::with_capacity(35);
        script_sig.push(redeem_script.len() as u8);
        script_sig.extend_from_slice(&redeem_script);
        tx.inputs[input_index].script_sig = script_sig;
        Ok(())
    }

    /// Sign one PSBT input by populating `partial_sigs` for every supplied key
    /// whose pubkey appears in the input's `witness_script`.
    ///
    /// Drives the BIP-174 Signer role for P2WSH and P2SH-P2WSH inputs:
    /// reads `psbt.inputs[idx].witness_utxo` for the spent value, computes the
    /// BIP-143 segwit-v0 sighash with `witness_script` as scriptCode, signs
    /// once per matching key, and writes `(pubkey -> der_sig||hashtype)` into
    /// `partial_sigs`. The finalizer (`Psbt::finalize_input`) then assembles
    /// the witness in script-pubkey order with the CHECKMULTISIG pad.
    ///
    /// `hash_type` is the sighash byte (e.g. 0x01 = SIGHASH_ALL). Returns the
    /// number of signatures added (0 if none of the keys' pubkeys appear in
    /// the witness script — caller's choice whether that's an error).
    pub fn sign_psbt_input(
        &self,
        psbt: &mut crate::psbt::Psbt,
        input_index: usize,
        sign_keys: &[secp256k1::SecretKey],
        hash_type: u8,
    ) -> Result<usize, WalletError> {
        if input_index >= psbt.inputs.len() {
            return Err(WalletError::SigningError(format!(
                "input_index {} out of range ({} inputs)",
                input_index,
                psbt.inputs.len()
            )));
        }
        let witness_script = psbt.inputs[input_index]
            .witness_script
            .clone()
            .ok_or_else(|| {
                WalletError::SigningError(
                    "PSBT input is missing witness_script (only P2WSH / P2SH-P2WSH \
                     are wired through this signer)"
                        .to_string(),
                )
            })?;
        let witness_utxo = psbt.inputs[input_index]
            .witness_utxo
            .as_ref()
            .ok_or_else(|| {
                WalletError::SigningError(
                    "PSBT input is missing witness_utxo (P2WSH segwit-v0 sighash \
                     requires the prevout amount)"
                        .to_string(),
                )
            })?;

        // ============================================================
        // W41 — A2 (CVE-2020-14199 amount-oracle defense).
        //
        // BIP-143 segwit-v0 commits to the spent amount in the sighash
        // ("hashOutputs" + per-input value). A hostile PSBT can pair a
        // truthful `non_witness_utxo` (full prev tx, hash-checked at
        // deserialize) with a TAMPERED `witness_utxo` whose `value` /
        // `script_pubkey` differ. If we sighash on `witness_utxo.value`
        // alone, we sign for an amount the on-chain prevtx never paid;
        // the resulting signature can be replayed by the attacker
        // against the real (smaller) prevout to lift fees. Same
        // confused-deputy class as the W31 commitment bug — different
        // field.
        //
        // Mitigation: when both UTXO views are present, require they
        // agree on the spent output. Bitcoin Core's
        // `PSBTInput::IsSane`-aware paths read non_witness_utxo first
        // and fall through to witness_utxo only when non_witness is
        // missing; we enforce mutual consistency on the same intent.
        if let Some(ref nw) = psbt.inputs[input_index].non_witness_utxo {
            let vout = psbt.unsigned_tx.inputs[input_index].previous_output.vout as usize;
            if vout >= nw.outputs.len() {
                return Err(WalletError::SigningError(
                    "PSBT non_witness_utxo prevout vout out of range \
                     (W41 amount-oracle defense)"
                        .to_string(),
                ));
            }
            if nw.outputs[vout].value != witness_utxo.value
                || nw.outputs[vout].script_pubkey != witness_utxo.script_pubkey
            {
                return Err(crate::psbt::PsbtError::WitnessUtxoMismatch.into());
            }
        }

        let value = witness_utxo.value;
        let prevout_spk = witness_utxo.script_pubkey.clone();

        // ============================================================
        // W31 PRIMARY FIX — verify the caller-supplied witness_script is
        // actually committed to by the prevout's scriptPubKey BEFORE
        // signing.
        //
        // Threat model: a malicious PSBT can hand us any witness_script
        // whose multisig pubkey set happens to include one of our keys.
        // Without this check, `sign_psbt_input` produces a valid
        // SIGHASH_ALL signature against an unrelated script — the
        // attacker then drops that sig into a transaction the user never
        // approved and broadcasts. This is the same hotbuns
        // confused-deputy bug class found in the 2026-04 wallet audit
        // and called out in the W30-rustoshi audit
        // (`tasks/a4313ea8dbcf71339`).
        //
        // Two valid commitments here:
        //  - P2WSH:      prevout_spk = OP_0 PUSH32 <SHA256(witness_script)>
        //  - P2SH-P2WSH: prevout_spk = OP_HASH160 PUSH20
        //                <HASH160(OP_0 PUSH32 SHA256(witness_script))>
        //                OP_EQUAL
        // Anything else, refuse to sign.
        if rustoshi_crypto::is_p2wsh(&prevout_spk) {
            rustoshi_crypto::verify_p2wsh_commitment(&witness_script, &prevout_spk)
                .map_err(|e| {
                    WalletError::SigningError(format!(
                        "PSBT P2WSH commitment verification failed: {}",
                        e
                    ))
                })?;
        } else if rustoshi_crypto::is_p2sh(&prevout_spk) {
            // For P2SH-P2WSH the redeem_script committed to in the
            // outer P2SH is the inner P2WSH scriptPubKey shape, i.e.
            // OP_0 PUSH32 SHA256(witness_script).
            let ws_hash = sha256(&witness_script);
            let mut redeem_script = Vec::with_capacity(34);
            redeem_script.push(0x00); // OP_0
            redeem_script.push(0x20); // PUSH32
            redeem_script.extend_from_slice(&ws_hash);
            rustoshi_crypto::verify_p2sh_commitment(&redeem_script, &prevout_spk).map_err(
                |e| {
                    WalletError::SigningError(format!(
                        "PSBT P2SH-P2WSH commitment verification failed: {}",
                        e
                    ))
                },
            )?;
        } else {
            return Err(WalletError::SigningError(
                "PSBT witness_utxo.script_pubkey is neither P2WSH nor P2SH-P2WSH; \
                 refusing to sign caller-supplied witness_script (W31 commitment check)"
                    .to_string(),
            ));
        }

        // Collect script pubkeys (33-byte compressed only — Core forbids
        // uncompressed in segwit-v0 via WITNESS_PUBKEYTYPE).
        let script_pks: Vec<[u8; 33]> = {
            let mut out = Vec::new();
            let mut i = 1usize;
            if witness_script.len() >= 4 {
                let end = witness_script.len().saturating_sub(2);
                while i < end {
                    let push_len = witness_script[i] as usize;
                    if push_len != 33 && push_len != 65 {
                        break;
                    }
                    i += 1;
                    if i + push_len > end {
                        break;
                    }
                    if push_len == 33 {
                        let mut pk = [0u8; 33];
                        pk.copy_from_slice(&witness_script[i..i + 33]);
                        out.push(pk);
                    }
                    i += push_len;
                }
            }
            out
        };

        // Compute the BIP-143 sighash once — same digest signs for all
        // matching keys.
        let secp = secp_ctx();
        let sighash = segwit_v0_sighash(
            &psbt.unsigned_tx,
            input_index,
            &witness_script,
            value,
            hash_type as u32,
        );
        let msg = Message::from_digest(sighash.0);

        let mut added = 0usize;
        for sk in sign_keys {
            let pk = secp256k1::PublicKey::from_secret_key(secp, sk);
            let pk_bytes: [u8; 33] = pk.serialize();
            if !script_pks.iter().any(|p| p == &pk_bytes) {
                continue; // key not in this script
            }
            let sig = secp.sign_ecdsa(&msg, sk);
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(hash_type);
            psbt.add_partial_sig(input_index, pk_bytes, sig_bytes)
                .map_err(|e| {
                    WalletError::SigningError(format!("PSBT add_partial_sig: {:?}", e))
                })?;
            added += 1;
        }
        Ok(added)
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

        // Compute the tweak via the canonical BIP-86 helper (W27-C P1
        // dedup — same call shape as `derive_address` and the
        // descriptor builder).
        let tweak_hash = rustoshi_crypto::taproot::compute_taproot_tweak_hash(
            &xonly_pubkey.serialize(),
            None,
        );
        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash)
            .map_err(|_| WalletError::SigningError("invalid tweak".to_string()))?;

        // Create tweaked keypair for signing
        let tweaked_keypair = keypair.add_xonly_tweak(secp, &tweak)
            .map_err(|_| WalletError::SigningError("tweak failed".to_string()))?;

        // Compute BIP-341 Taproot sighash via the canonical helper in
        // `rustoshi-crypto::taproot` (W27-C P0-1). The wallet used to
        // ship its own copy that diverged on SIGHASH_SINGLE (it placed
        // the single-output digest at field 9 instead of after fields
        // 11+12 per BIP-341), so any tx the wallet signed under
        // SIGHASH_SINGLE was rejected by the consensus layer. Going
        // through the same helper consensus uses guarantees parity.
        let amounts: Vec<u64> = all_utxos.iter().map(|u| u.value).collect();
        let scripts_owned: Vec<&[u8]> =
            all_utxos.iter().map(|u| u.script_pubkey.as_slice()).collect();
        let prevouts = TaprootPrevouts {
            amounts: &amounts,
            scripts: &scripts_owned,
        };

        let sighash = crypto_compute_taproot_sighash(
            tx,
            input_index,
            prevouts,
            SIGHASH_DEFAULT,
            None, // annex (none from this wallet path)
            None, // script_path (key-path only)
        )
        .map_err(|e| WalletError::SigningError(format!("taproot sighash: {:?}", e)))?;

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

    /// Check if an address belongs to this wallet.
    pub fn is_mine(&self, address: &str) -> bool {
        if self.addresses.contains_key(address)
            || self
                .imported_keys
                .values()
                .any(|k| k.address == address)
        {
            return true;
        }
        // Watched (descriptor-imported) scripts: decode the address to its
        // scriptPubKey and probe the watch set.
        if !self.watched_scripts.is_empty() {
            if let Ok(addr) = Address::from_string(address, Some(self.network)) {
                return self.watched_scripts.contains_key(&addr.to_script_pubkey());
            }
        }
        false
    }

    /// Check if a raw scriptPubKey belongs to this wallet (HD addresses incl.
    /// gap-limit lookahead, imported keys, and watched descriptor scripts) —
    /// the script-level `IsMine` used by `getaddressinfo`.
    pub fn is_mine_script(&self, script_pubkey: &[u8]) -> bool {
        self.build_script_index().contains_key(script_pubkey)
    }

    /// Look up the watched-descriptor entry for a scriptPubKey, when the
    /// script was registered via `importdescriptors`.
    pub fn watched_script(&self, script_pubkey: &[u8]) -> Option<&WatchedScript> {
        self.watched_scripts.get(script_pubkey)
    }

    /// Register a scriptPubKey as watched (descriptor import). Idempotent:
    /// re-importing refreshes the stored descriptor/label.
    pub fn register_watched_script(&mut self, script_pubkey: Vec<u8>, entry: WatchedScript) {
        self.watched_scripts.insert(script_pubkey, entry);
    }

    /// Number of distinct watched scripts.
    pub fn watched_script_count(&self) -> usize {
        self.watched_scripts.len()
    }

    /// The set of UNIQUE descriptor strings (with checksum) registered via
    /// `importdescriptors`, deduplicated across the per-position scripts a
    /// single descriptor controls. Used by `listdescriptors` as the in-memory
    /// fallback when no persisted `descriptors` rows are available (the
    /// in-memory `watched_scripts` table does not retain per-descriptor
    /// timestamp / range_end).
    pub fn watched_descriptor_strings(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        for ws in self.watched_scripts.values() {
            seen.insert(ws.descriptor.clone());
        }
        seen.into_iter().collect()
    }

    /// Register every scriptPubKey a parsed descriptor controls (positions
    /// `0..=range_end` for ranged descriptors, position 0 otherwise) into the
    /// watched-script set, so block scans / rescans credit funds paid to
    /// them. `canonical` is the descriptor string with checksum (stored for
    /// `getaddressinfo.parent_desc`). Returns the number of scripts
    /// registered. Mirrors the script-registration half of Core's
    /// `ProcessDescriptorImport` (wallet/rpc/backup.cpp:141-300).
    pub fn register_descriptor(
        &mut self,
        canonical: &str,
        parsed: &crate::descriptor::Descriptor,
        label: &str,
        range_end: u32,
    ) -> Result<usize, WalletError> {
        use crate::descriptor::{Descriptor, DescriptorInfo};

        let info = DescriptorInfo::from_descriptor(parsed);
        let positions: std::ops::RangeInclusive<u32> = if parsed.is_range() {
            0..=range_end
        } else {
            0..=0
        };

        let mut registered = 0usize;
        for pos in positions {
            let scripts = parsed
                .derive_scripts(pos, self.network)
                .map_err(|e| WalletError::InvalidPath(e.to_string()))?;
            // Best-effort pubkey for single-key descriptors (getaddressinfo).
            let pubkey: Option<Vec<u8>> = match parsed {
                Descriptor::Pk(k) | Descriptor::Pkh(k) | Descriptor::Wpkh(k) => {
                    k.get_pubkey(pos).ok().map(|p| p.serialize().to_vec())
                }
                _ => None,
            };
            for spk in scripts {
                self.register_watched_script(
                    spk,
                    WatchedScript {
                        descriptor: canonical.to_string(),
                        label: label.to_string(),
                        solvable: info.is_solvable,
                        pubkey: pubkey.clone(),
                    },
                );
                registered += 1;
            }
        }
        Ok(registered)
    }

    /// Import a raw secp256k1 private key into the wallet (Core's
    /// `importprivkey`). Registers every standard single-key scriptPubKey the
    /// key controls — P2WPKH (the wallet's default + most-common), P2PKH, and
    /// P2SH-P2WPKH — so a subsequent block / rescan scan credits funds paid to
    /// ANY of those scripts, matching Core's behaviour of adding the key to the
    /// keychain and watching all its `IsMine` scripts.
    ///
    /// The "primary" returned address uses the wallet's configured
    /// `address_type` (so it round-trips with `getnewaddress`-shaped output).
    /// The imported key is independent of the HD seed; `sethdseed` /
    /// recovery never re-derives it. Idempotent: re-importing the same key
    /// just refreshes the label.
    ///
    /// Returns the primary address controlled by the imported key.
    pub fn import_private_key(
        &mut self,
        secret_key: secp256k1::SecretKey,
        label: String,
    ) -> Result<String, WalletError> {
        let secp = secp_ctx();
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, &secret_key);
        let compressed: [u8; 33] = pubkey.serialize();
        let pubkey_hash = hash160(&compressed);

        // The three standard single-key scriptPubKeys the key controls.
        let p2wpkh = Address::P2WPKH { hash: pubkey_hash, network: self.network };
        let p2pkh = Address::P2PKH { hash: pubkey_hash, network: self.network };
        // P2SH-P2WPKH: scriptPubKey = P2SH(redeem = OP_0 <20-byte pubkey hash>).
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&pubkey_hash.0);
        let p2sh_p2wpkh = Address::P2SH { hash: hash160(&redeem), network: self.network };

        // The primary address mirrors the wallet's configured address type.
        let primary = match self.address_type {
            AddressType::P2WPKH => p2wpkh.encode(),
            AddressType::P2PKH => p2pkh.encode(),
            AddressType::P2shP2wpkh => p2sh_p2wpkh.encode(),
            // Taproot is a tweaked key, not a hash160 script; for an imported
            // raw key we expose the key-path P2TR address as primary.
            AddressType::P2TR => {
                let xonly = secp256k1::XOnlyPublicKey::from(pubkey);
                let output_key = self.compute_taproot_output_key(&xonly);
                Address::P2TR { output_key, network: self.network }.encode()
            }
        };

        let entry = ImportedKey {
            secret_key,
            address: primary.clone(),
            label,
        };

        // Register all standard single-key scripts so funds to any are found.
        for addr in [&p2wpkh, &p2pkh, &p2sh_p2wpkh] {
            self.imported_keys
                .insert(addr.to_script_pubkey(), entry.clone());
        }
        if self.address_type == AddressType::P2TR {
            let xonly = secp256k1::XOnlyPublicKey::from(pubkey);
            let output_key = self.compute_taproot_output_key(&xonly);
            self.imported_keys.insert(
                Address::P2TR { output_key, network: self.network }.to_script_pubkey(),
                entry.clone(),
            );
        }

        Ok(primary)
    }

    /// Number of distinct imported keys (counted by primary address).
    pub fn imported_key_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for k in self.imported_keys.values() {
            seen.insert(k.address.clone());
        }
        seen.len()
    }

    /// Derive the scriptPubKey controlled by a derivation path.
    ///
    /// Re-derives the address for `path` (using the wallet's configured
    /// address type) and encodes it to the on-chain scriptPubKey bytes, so a
    /// block scan can match wallet-owned outputs by raw script comparison.
    fn script_pubkey_for_path(&self, path: &[u32]) -> Result<Vec<u8>, WalletError> {
        let addr_str = self.derive_address(path)?;
        let addr = Address::from_string(&addr_str, Some(self.network))
            .map_err(|_| WalletError::InvalidAddress(addr_str))?;
        Ok(addr.to_script_pubkey())
    }

    /// Build a `scriptPubKey -> (derivation_path, is_change)` ownership index.
    ///
    /// Covers (a) every address already generated by the wallet
    /// (`getnewaddress`, change addresses recorded by `create_transaction`)
    /// and (b) a forward gap-limit lookahead on BOTH the receive and change
    /// chains, mirroring Core's `CWallet` keypool lookahead. This lets a block
    /// scan recognise coinbase rewards paid to a freshly-handed-out address and
    /// change paid to a not-yet-issued change index.
    ///
    /// Pure (no `&mut self`): the lookahead addresses are recomputed on demand
    /// and not persisted into `self.addresses`, so scanning never advances the
    /// keypool cursor.
    fn build_script_index(&self) -> HashMap<Vec<u8>, (Vec<u32>, bool)> {
        let mut index: HashMap<Vec<u8>, (Vec<u32>, bool)> = HashMap::new();

        // HD-derived scripts exist ONLY when the wallet holds private keys.
        // A disable_private_keys wallet has no SPKMs in Core
        // (wallet.cpp:3104-3105); indexing the placeholder zero seed's
        // derivations here would credit funds to publicly-derivable keys.
        if self.private_keys_enabled {
            // (a) every already-generated address (path tells us the chain
            //     branch).
            for (_addr, path) in self.addresses.iter() {
                if let Ok(spk) = self.script_pubkey_for_path(path) {
                    // change branch is index [3] == 1 in the BIP-44/49/84/86 path.
                    let is_change = path.get(3).copied() == Some(1);
                    index.insert(spk, (path.clone(), is_change));
                }
            }

            // (b) forward lookahead on receive + change chains (gap limit).
            let look = self.gap_limit;
            for is_change in [false, true] {
                let start = if is_change { self.next_change_index } else { self.next_receive_index };
                for i in start..start.saturating_add(look) {
                    let path = self.derivation_path(is_change, i);
                    if let Ok(spk) = self.script_pubkey_for_path(&path) {
                        index.entry(spk).or_insert((path, is_change));
                    }
                }
            }
        }

        // (c) every imported (non-HD) key's scriptPubKeys. They carry the
        // sentinel IMPORTED_PATH so the credit-address lookup routes through
        // `imported_keys` rather than HD derivation. Imported funds are never
        // "change". A seed-derived script always wins (it was inserted first),
        // so an overlap never relabels a wallet's own HD output as imported.
        for spk in self.imported_keys.keys() {
            index
                .entry(spk.clone())
                .or_insert((IMPORTED_PATH.to_vec(), false));
        }

        // (d) watched descriptor scripts (importdescriptors). Never "change";
        // carry the WATCHED_PATH sentinel so address lookups decode straight
        // from the script.
        for spk in self.watched_scripts.keys() {
            index
                .entry(spk.clone())
                .or_insert((WATCHED_PATH.to_vec(), false));
        }

        index
    }

    /// Resolve the human-readable address that *owns* a wallet scriptPubKey,
    /// given the `(path, _)` recorded in the ownership index. For HD paths this
    /// re-derives the address; for the [`IMPORTED_PATH`] sentinel it looks the
    /// address up in [`Self::imported_keys`]. Used to label credits in history.
    fn owned_script_address(&self, spk: &[u8], path: &[u32]) -> Option<String> {
        if path == IMPORTED_PATH {
            self.imported_keys.get(spk).map(|k| k.address.clone())
        } else if path == WATCHED_PATH {
            // Watched descriptor scripts have no derivation; decode the
            // address straight from the scriptPubKey.
            Address::from_script_pubkey(spk, self.network).map(|a| a.encode())
        } else {
            self.derive_address(path).ok()
        }
    }

    /// Scan a connected block for wallet activity (Core's `CWallet::blockConnected`).
    ///
    /// Credits outputs paying a wallet-owned scriptPubKey (flagging coinbase),
    /// then debits any UTXO consumed by an input in the block. Operates in
    /// block order. `height` is the height at which this block connects (used
    /// for coinbase-maturity accounting); the wallet's chain height is also
    /// advanced to `height`. Idempotent w.r.t. re-credit (same outpoint just
    /// refreshes), and debits remove spent coins so the ledger never
    /// over-counts.
    ///
    /// Returns the number of (credits, debits) applied.
    ///
    /// Back-compat shim: equivalent to [`Self::scan_block_at`] with a zero
    /// block hash + zero block time. Callers that have the connecting block's
    /// hash and timestamp should prefer `scan_block_at` so transaction-history
    /// entries carry the real `blockhash` / `blocktime`.
    pub fn scan_block(&mut self, txs: &[Transaction], height: u32) -> (usize, usize) {
        self.scan_block_at(txs, height, Hash256::ZERO, 0)
    }

    /// Scan a connected block, recording wallet UTXO + transaction-history
    /// changes (Core's `CWallet::blockConnected`).
    ///
    /// In addition to crediting wallet-owned outputs (flagging coinbase) and
    /// debiting consumed wallet coins, this records one [`TxHistoryEntry`] per
    /// wallet-relevant transaction so `listtransactions` / `gettransaction` can
    /// report the wallet's own receive/send/coinbase activity. `block_hash` and
    /// `block_time` are the connecting block's identity + timestamp (used only
    /// for the history `blockhash` / `blocktime` fields).
    ///
    /// Returns the number of (credits, debits) applied.
    pub fn scan_block_at(
        &mut self,
        txs: &[Transaction],
        height: u32,
        block_hash: Hash256,
        block_time: u64,
    ) -> (usize, usize) {
        let index = self.build_script_index();
        let mut credits = 0usize;
        let mut debits = 0usize;

        for tx in txs {
            let is_cb = tx.is_coinbase();
            let txid = tx.txid();

            // --- Credit wallet-owned outputs (build the receive/generate
            //     details as we go). ----------------------------------------
            let mut credit_sats: u64 = 0;
            // Per-output: (vout, value, is_change, owned-address).
            let mut credit_outs: Vec<(u32, u64, bool, Option<String>)> = Vec::new();
            for (vout, out) in tx.outputs.iter().enumerate() {
                if let Some((path, is_change)) = index.get(&out.script_pubkey) {
                    let outpoint = OutPoint { txid, vout: vout as u32 };
                    self.utxos.insert(
                        outpoint.clone(),
                        WalletUtxo {
                            outpoint,
                            value: out.value,
                            script_pubkey: out.script_pubkey.clone(),
                            derivation_path: path.clone(),
                            confirmations: 1,
                            is_change: *is_change,
                            is_coinbase: is_cb,
                            height: Some(height),
                        },
                    );
                    credit_sats = credit_sats.saturating_add(out.value);
                    let addr = self.owned_script_address(&out.script_pubkey, path);
                    credit_outs.push((vout as u32, out.value, *is_change, addr));
                    credits += 1;
                }
            }

            // --- Debit wallet UTXOs spent by this tx's inputs. The spent
            //     value drives the fee + the `send` detail set. Capture value
            //     BEFORE removing the coin. (Coinbase has no real inputs.) ---
            let mut debit_sats: u64 = 0;
            if !is_cb {
                for input in &tx.inputs {
                    if let Some(spent) = self.utxos.remove(&input.previous_output) {
                        debit_sats = debit_sats.saturating_add(spent.value);
                        debits += 1;
                    }
                }
            }

            // --- Record transaction history if the tx touched the wallet. ---
            if credit_sats > 0 || debit_sats > 0 {
                let mut details: Vec<TxDetail> = Vec::new();

                // When the wallet funded this tx (debit > 0) it is a SEND: per
                // Core's CachedTxGetAmounts, EVERY non-change output becomes a
                // "send" line item (amount NEGATIVE), with the fee attached.
                // fee = sum(wallet inputs) - sum(all outputs).
                let fee_sats: Option<u64> = if debit_sats > 0 {
                    let value_out: u64 =
                        tx.outputs.iter().map(|o| o.value).sum();
                    Some(debit_sats.saturating_sub(value_out))
                } else {
                    None
                };

                if debit_sats > 0 {
                    let neg_fee = fee_sats.map(|f| -(f as i64));
                    for (vout, out) in tx.outputs.iter().enumerate() {
                        // Skip wallet change outputs (Core excludes change from
                        // listSent unless include_change).
                        let is_change = index
                            .get(&out.script_pubkey)
                            .map(|(_, c)| *c)
                            .unwrap_or(false);
                        if is_change {
                            continue;
                        }
                        let addr = Address::from_script_pubkey(
                            &out.script_pubkey,
                            self.network,
                        )
                        .map(|a| a.encode());
                        details.push(TxDetail {
                            address: addr,
                            category: "send".to_string(),
                            amount_sats: -(out.value as i64),
                            vout: vout as u32,
                            fee_sats: neg_fee,
                        });
                    }
                }

                // Receive / generate line items for wallet-owned outputs.
                for (vout, value, _is_change, addr) in &credit_outs {
                    let category = if is_cb { "generate" } else { "receive" };
                    details.push(TxDetail {
                        address: addr.clone(),
                        category: category.to_string(),
                        amount_sats: *value as i64,
                        vout: *vout,
                        fee_sats: None,
                    });
                }

                let entry = TxHistoryEntry {
                    txid,
                    is_coinbase: is_cb,
                    credit_sats,
                    debit_sats,
                    fee_sats,
                    block_height: height,
                    block_hash,
                    block_time,
                    details,
                    raw_tx: tx.serialize(),
                };
                // De-dup on re-scan of the same block: replace any existing
                // entry for this txid rather than appending a duplicate.
                if let Some(slot) =
                    self.history.iter_mut().find(|e| e.txid == txid)
                {
                    *slot = entry;
                } else {
                    self.history.push(entry);
                }
            }

            // Drop any sent-tx bookkeeping the moment its txid confirms.
            if let Some(entry) = self.sent_txs.get_mut(&txid) {
                entry.confirmed = true;
            }
        }

        // Advance chain height + refresh confirmation counts for maturity.
        self.set_chain_height(height);
        self.refresh_confirmations(height);

        (credits, debits)
    }

    /// Reverse a block's wallet credits/debits (Core's `CWallet::blockDisconnected`).
    ///
    /// Symmetric to [`Self::scan_block`]: removes UTXOs this block created and
    /// restores UTXOs this block spent (best-effort — a restored coin keeps the
    /// value/script the input referenced if known). Keeps the ledger from
    /// over-counting after a reorg. `new_tip_height` is the height the chain
    /// rewinds *to*.
    pub fn unscan_block(&mut self, txs: &[Transaction], spent: &[WalletUtxo], new_tip_height: u32) {
        for tx in txs {
            let txid = tx.txid();
            for vout in 0..tx.outputs.len() {
                let outpoint = OutPoint { txid, vout: vout as u32 };
                self.utxos.remove(&outpoint);
            }
            // Drop any transaction-history entry this disconnected tx created,
            // mirroring the UTXO un-credit so listtransactions/gettransaction
            // never report a tx that the reorg orphaned.
            self.history.retain(|e| e.txid != txid);
        }
        // Restore previously-spent wallet coins recorded by the caller.
        for u in spent {
            self.utxos.entry(u.outpoint.clone()).or_insert_with(|| u.clone());
        }
        self.set_chain_height(new_tip_height);
        self.refresh_confirmations(new_tip_height);
    }

    /// Transaction-history entries in block-connect order (oldest first).
    ///
    /// Backing store for `listtransactions` / `gettransaction`. Confirmations
    /// and the coinbase generate/immature distinction are NOT stored here; the
    /// RPC layer recomputes them against [`Self::chain_height`] at read time
    /// via [`Self::history_confirmations`] / [`Self::history_category`].
    pub fn history(&self) -> &[TxHistoryEntry] {
        &self.history
    }

    /// Find a single history entry by txid (internal byte order).
    pub fn history_entry(&self, txid: &Hash256) -> Option<&TxHistoryEntry> {
        self.history.iter().find(|e| &e.txid == txid)
    }

    /// Confirmations for a history entry against the current chain tip.
    ///
    /// `confirmations = chain_height - block_height + 1` (1 at the block it
    /// confirmed in), saturating at 0.
    pub fn history_confirmations(&self, entry: &TxHistoryEntry) -> u32 {
        self.chain_height
            .saturating_sub(entry.block_height)
            .saturating_add(1)
    }

    /// The effective receive category for a coinbase entry at the current tip:
    /// "generate" once mature (>= COINBASE_MATURITY confs), else "immature".
    /// Non-coinbase receives are always "receive". Returns `None` for entries
    /// that have no receive line item (pure sends).
    pub fn history_coinbase_is_mature(&self, entry: &TxHistoryEntry) -> bool {
        self.chain_height >= entry.block_height + COINBASE_MATURITY
    }

    /// Recompute every UTXO's confirmation count against the current tip.
    ///
    /// `confirmations = chain_height - utxo_height + 1` (1 confirmation at the
    /// block it was mined in). Coinbase maturity is enforced separately by
    /// [`Self::is_mature`] using the stored height + chain height.
    fn refresh_confirmations(&mut self, tip_height: u32) {
        for u in self.utxos.values_mut() {
            if let Some(h) = u.height {
                u.confirmations = tip_height.saturating_sub(h).saturating_add(1);
            }
        }
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

    // ------------------------------------------------------------------------
    // Coin locking (mirrors Core's `LockCoin` / `UnlockCoin` / `IsLockedCoin`,
    // `ListLockedCoins`, `UnlockAllCoins` in `bitcoin-core/src/wallet/wallet.cpp`).
    //
    // Locked coins are skipped by `list_spendable_unspent_unlocked` (used by
    // automatic coin selection). They remain visible to `listunspent` so an
    // operator can see them.
    // ------------------------------------------------------------------------

    /// Mark an outpoint locked (excluded from coin selection until unlocked).
    /// Returns `true` if the lock was newly inserted, `false` if it was
    /// already locked.
    pub fn lock_coin(&mut self, outpoint: &OutPoint) -> bool {
        self.locked_coins.insert(outpoint.clone())
    }

    /// Unmark an outpoint as locked. Returns `true` if a lock was removed,
    /// `false` if it was not locked.
    pub fn unlock_coin(&mut self, outpoint: &OutPoint) -> bool {
        self.locked_coins.remove(outpoint)
    }

    /// Whether an outpoint is currently locked.
    pub fn is_locked_coin(&self, outpoint: &OutPoint) -> bool {
        self.locked_coins.contains(outpoint)
    }

    /// Iterate over all locked outpoints.
    pub fn locked_coins(&self) -> impl Iterator<Item = &OutPoint> {
        self.locked_coins.iter()
    }

    /// Clear all locks. Mirrors Core's `UnlockAllCoins`.
    pub fn unlock_all_coins(&mut self) {
        self.locked_coins.clear();
    }

    /// List spendable unspent UTXOs that are not locked. Used by automatic
    /// coin selection (Core's `AvailableCoins` skips `setLockedCoins`).
    pub fn list_spendable_unspent_unlocked(&self) -> Vec<&WalletUtxo> {
        self.utxos
            .values()
            .filter(|u| self.is_spendable(u) && !self.locked_coins.contains(&u.outpoint))
            .collect()
    }

    // ------------------------------------------------------------------------
    // Key lookup for `signmessage` (Core takes a P2PKH address and looks up
    // the matching key — `bitcoin-core/src/wallet/rpc/signmessage.cpp:54-60`).
    // We expose two variants:
    //   - `private_key_for_pkh` — looks up a P2PKH hash160 directly
    //   - `private_key_for_address` — parses any P2PKH/P2WPKH/P2SH-P2WPKH
    //     address generated by this wallet and returns the matching key.
    // ------------------------------------------------------------------------

    /// Find the secp256k1 private key whose pubkey hashes to `pkh`, by
    /// scanning addresses generated so far. Returns `None` if no generated
    /// address matches. This mirrors Core's `pwallet->GetKey(pkh, key)` in
    /// signmessage.cpp.
    ///
    /// We only consider keys that hash to `pkh` under SHA256+RIPEMD160 of the
    /// 33-byte compressed serialization (Core's default since 0.7.x).
    pub fn private_key_for_pkh(
        &self,
        pkh: &rustoshi_primitives::Hash160,
    ) -> Option<secp256k1::SecretKey> {
        let secp = secp_ctx();
        for path in self.addresses.values() {
            let child = self.master_key.derive_path(path).ok()?;
            let pubkey = secp256k1::PublicKey::from_secret_key(secp, &child.secret_key);
            let hash = hash160(&pubkey.serialize());
            if &hash == pkh {
                return Some(child.secret_key);
            }
        }
        None
    }

    /// Find the secp256k1 private key controlling a wallet address. Accepts
    /// any address shape this wallet emits (P2PKH, P2WPKH, P2SH-P2WPKH);
    /// returns `None` for addresses the wallet does not own or for shapes we
    /// can't sign messages with (P2WSH, P2TR — see signmessage Core notes).
    ///
    /// Used by the Core-shaped `signmessage` RPC.
    pub fn private_key_for_address(&self, address: &str) -> Option<secp256k1::SecretKey> {
        // Fast path: if we generated this address, derive directly from the
        // stored derivation path. This skips a full re-scan of `addresses`.
        if let Some(path) = self.addresses.get(address) {
            return self.master_key.derive_path(path).ok().map(|c| c.secret_key);
        }
        None
    }

    /// Export the WIF (compressed) for a wallet-owned address — the inverse of
    /// importing a WIF into the key-based signer. Returns `None` for addresses
    /// the wallet does not control. Used by callers/tests that need to drive
    /// `signrawtransactionwithkey` with a key the wallet generated, without
    /// handling raw `secp256k1` material themselves.
    pub fn wif_for_address(&self, address: &str) -> Option<String> {
        self.private_key_for_address(address)
            .map(|sk| encode_wif(&sk, self.network))
    }
}

/// A temporary, walletless keystore that signs raw-transaction inputs from
/// EXPLICIT WIF private keys — the engine behind the `signrawtransactionwithkey`
/// RPC. Mirrors Core's `FillableSigningProvider` built inside
/// `rpc/rawtransaction.cpp::SignTransaction`: every WIF key registers the
/// standard single-key scriptPubKeys it controls (`scriptPubKey -> SecretKey`),
/// and each input whose prevout scriptPubKey matches a registered key is signed
/// through the SAME BIP-143/BIP-341 sighash + ECDSA/Schnorr engine the wallet
/// signer uses (`Wallet::sign_input_with_key` -> the per-script signers). No
/// sighash or signature code is duplicated here.
///
/// This type lives in the wallet crate so all `secp256k1` handling stays here;
/// the RPC layer drives it opaquely.
pub struct KeySigner {
    /// scriptPubKey (raw bytes) -> secret key that controls it.
    keystore: HashMap<Vec<u8>, secp256k1::SecretKey>,
    /// Stateless host for the per-script signers (HD tree never consulted).
    signer: Wallet,
}

impl KeySigner {
    /// Build the temporary keystore from WIF-encoded private keys. Each WIF is
    /// validated against `network` (Core `DecodeSecret`); an invalid WIF is a
    /// hard error (Core throws RPC_INVALID_ADDRESS_OR_KEY for a bad key).
    pub fn from_wifs(wifs: &[String], network: Network) -> Result<Self, WalletError> {
        let mut keystore: HashMap<Vec<u8>, secp256k1::SecretKey> = HashMap::new();
        for wif in wifs {
            let (sk, _compressed) = decode_wif(wif, network)?;
            for spk in Wallet::script_pubkeys_for_key(&sk, network) {
                keystore.insert(spk, sk);
            }
        }
        // A throwaway wallet hosts the (stateless) per-script signers; its HD
        // tree is never used — every signing key comes from `keystore`. The
        // fixed dummy seed only satisfies `from_seed`'s constructor.
        let signer = Wallet::from_seed(&[0u8; 32], network, AddressType::P2WPKH)?;
        Ok(Self { keystore, signer })
    }

    /// Whether a provided key controls this scriptPubKey (i.e. the input is
    /// signable by this keystore).
    pub fn can_sign(&self, script_pubkey: &[u8]) -> bool {
        self.keystore.contains_key(script_pubkey)
    }

    /// Sign one input with the keystore's matching key. `prevout` is the UTXO
    /// being spent; `all_prevouts` covers every input in spend order (required
    /// for the BIP-341 Taproot sighash). Returns an error if no key matches or
    /// the script type is not single-key signable.
    pub fn sign_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        prevout: &WalletUtxo,
        all_prevouts: &[WalletUtxo],
    ) -> Result<(), WalletError> {
        let sk = self
            .keystore
            .get(&prevout.script_pubkey)
            .copied()
            .ok_or_else(|| {
                WalletError::SigningError(
                    "no provided private key controls this input's scriptPubKey".to_string(),
                )
            })?;
        self.signer
            .sign_input_with_key(tx, input_index, prevout, all_prevouts, &sk)
    }
}

/// The WIF (Wallet Import Format) version byte for the secret key on a given
/// network. Mirrors Core's `base58Prefixes[SECRET_KEY]`
/// (`kernel/chainparams.cpp`): 0x80 on mainnet, 0xEF on testnet/regtest.
fn wif_secret_prefix(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x80,
        Network::Testnet | Network::Regtest => 0xEF,
    }
}

/// Decode a Bitcoin WIF private key (base58check). Returns the secp256k1
/// secret key and whether it encodes a compressed public key. Mirrors Core's
/// `DecodeSecret` (`key_io.cpp`): the payload is `[version] + 32-byte key`,
/// optionally followed by a `0x01` compression flag. The version byte is
/// validated against the active network so a mainnet WIF can't be imported
/// into a regtest wallet (Core's `pubKeyPrefix`/`secretKeyPrefix` check).
pub fn decode_wif(
    wif: &str,
    network: Network,
) -> Result<(secp256k1::SecretKey, bool), WalletError> {
    let data = rustoshi_crypto::base58check_decode(wif.trim())
        .map_err(|_| WalletError::InvalidAddress(format!("invalid WIF base58check: {}", wif)))?;
    if data.is_empty() || data[0] != wif_secret_prefix(network) {
        return Err(WalletError::InvalidAddress(
            "WIF version byte does not match the active network".to_string(),
        ));
    }
    let (key_bytes, compressed) = match data.len() {
        // version(1) + key(32)
        33 => (&data[1..33], false),
        // version(1) + key(32) + compression flag(1 == 0x01)
        34 if data[33] == 0x01 => (&data[1..33], true),
        _ => {
            return Err(WalletError::InvalidAddress(
                "invalid WIF length / compression flag".to_string(),
            ))
        }
    };
    let secret = secp256k1::SecretKey::from_slice(key_bytes)
        .map_err(|_| WalletError::InvalidAddress("WIF encodes an out-of-range key".to_string()))?;
    Ok((secret, compressed))
}

/// Encode a secp256k1 secret key as a (compressed-pubkey) WIF for the given
/// network — the inverse of [`decode_wif`]. Provided so callers / tests can
/// round-trip imported keys; not used by the wallet itself.
pub fn encode_wif(secret_key: &secp256k1::SecretKey, network: Network) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(wif_secret_prefix(network));
    payload.extend_from_slice(&secret_key[..]);
    payload.push(0x01); // compressed-pubkey flag
    rustoshi_crypto::base58check_encode(&payload)
}

// ----------------------------------------------------------------------------
// Local scriptPubKey type detection (mirrors rustoshi-consensus helpers; we
// duplicate them here to avoid a wallet → consensus dependency cycle, since
// only the byte-pattern check is needed for wallet-owned UTXO signing).
// ----------------------------------------------------------------------------

/// P2PKH: OP_DUP OP_HASH160 <20> 20 bytes OP_EQUALVERIFY OP_CHECKSIG (25 bytes).
fn is_p2pkh_spk(spk: &[u8]) -> bool {
    spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
}

/// P2SH: OP_HASH160 <20> 20 bytes OP_EQUAL (23 bytes).
fn is_p2sh_spk(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

/// P2WPKH: OP_0 <20> 20 bytes (22 bytes).
fn is_p2wpkh_spk(spk: &[u8]) -> bool {
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

/// P2WSH: OP_0 <32> 32 bytes (34 bytes).
fn is_p2wsh_spk(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20
}

/// P2TR: OP_1 <32> 32 bytes (34 bytes).
fn is_p2tr_spk(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

/// Detect a bare CHECKMULTISIG witness/redeem script of the form
/// `<M> <pk1> ... <pkN> <N> OP_CHECKMULTISIG` where M and N are encoded as
/// OP_1..OP_16 (0x51..0x60). Returns true only for the simple shape Core
/// recognises in `solver()` (`bitcoin-core/src/script/solver.cpp::MatchMultisig`).
///
/// Used by the P2WSH signer to decide whether to prepend the empty CHECKMULTISIG
/// off-by-one stack pad and how many sig stack slots to fill.
fn is_multisig_witness_script(script: &[u8]) -> bool {
    if script.len() < 4 {
        return false;
    }
    if *script.last().unwrap() != 0xae {
        // OP_CHECKMULTISIG
        return false;
    }
    // Last byte before OP_CHECKMULTISIG must be OP_1..OP_16 (the N count).
    let n_op = script[script.len() - 2];
    if !(0x51..=0x60).contains(&n_op) {
        return false;
    }
    // First byte must be OP_1..OP_16 (the M count).
    let m_op = script[0];
    if !(0x51..=0x60).contains(&m_op) {
        return false;
    }
    let m = (m_op - 0x50) as usize;
    let n = (n_op - 0x50) as usize;
    if m == 0 || m > n || n > 20 {
        return false;
    }
    // Walk N pubkey pushes between [1 .. len-2). Each push starts with the
    // length (compressed=33 → 0x21, uncompressed=65 → 0x41).
    let mut i = 1usize;
    let end = script.len() - 2;
    let mut keys_seen = 0usize;
    while i < end {
        let push_len = script[i] as usize;
        if push_len != 33 && push_len != 65 {
            return false;
        }
        i += 1;
        if i + push_len > end {
            return false;
        }
        i += push_len;
        keys_seen += 1;
    }
    keys_seen == n
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

/// Return the per-input vsize (in vbytes) for the given address type.
///
/// These numbers match the per-input coefficients in `estimate_tx_vsize` and
/// are used to populate `CoinSelectionParams::input_weight` so the module can
/// compute effective-value correctly.
fn input_vsize_for(addr_type: AddressType) -> usize {
    match addr_type {
        AddressType::P2WPKH => 68,
        AddressType::P2PKH => 148,
        AddressType::P2shP2wpkh => 91,
        AddressType::P2TR => 57,
    }
}

/// Return the per-output vsize (in vbytes) for a change output of the given type.
///
/// Used to compute the `change_cost` for `CoinSelectionParams::cost_of_change`.
fn output_vsize_for(addr_type: AddressType) -> usize {
    match addr_type {
        AddressType::P2WPKH => 31,
        AddressType::P2PKH => 34,
        AddressType::P2shP2wpkh => 32,
        AddressType::P2TR => 43,
    }
}

/// Decode a scriptPubKey back into the corresponding address string.
///
/// FIX-61 helper: [`Wallet::bump_fee`] needs to detect which output of a
/// previously-sent transaction is the wallet's change output. The wallet
/// tracks addresses (as encoded strings) but not raw `scriptPubKey` bytes,
/// so we re-decode each output's scriptPubKey into the same string form
/// that `addresses` uses and dispatch on prefix.
///
/// Returns `None` for unrecognised script shapes (bare multisig,
/// OP_RETURN, non-standard) — these are never wallet-owned and so are
/// definitionally not change outputs in a wallet-built tx.
fn address_from_script(script_pubkey: &[u8], network: Network) -> Option<String> {
    use rustoshi_primitives::Hash160;
    match script_pubkey {
        // P2PKH: OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
        [0x76, 0xa9, 0x14, rest @ ..] if rest.len() == 22 && rest[20] == 0x88 && rest[21] == 0xac => {
            let mut h = [0u8; 20];
            h.copy_from_slice(&rest[..20]);
            Some(
                Address::P2PKH {
                    hash: Hash160::from_bytes(h),
                    network,
                }
                .encode(),
            )
        }
        // P2SH: OP_HASH160 <20> OP_EQUAL
        [0xa9, 0x14, rest @ ..] if rest.len() == 21 && rest[20] == 0x87 => {
            let mut h = [0u8; 20];
            h.copy_from_slice(&rest[..20]);
            Some(
                Address::P2SH {
                    hash: Hash160::from_bytes(h),
                    network,
                }
                .encode(),
            )
        }
        // P2WPKH: OP_0 OP_PUSHBYTES_20 <20>
        [0x00, 0x14, rest @ ..] if rest.len() == 20 => {
            let mut h = [0u8; 20];
            h.copy_from_slice(rest);
            Some(
                Address::P2WPKH {
                    hash: Hash160::from_bytes(h),
                    network,
                }
                .encode(),
            )
        }
        // P2WSH: OP_0 OP_PUSHBYTES_32 <32>
        [0x00, 0x20, rest @ ..] if rest.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(rest);
            Some(
                Address::P2WSH {
                    hash: rustoshi_primitives::Hash256(h),
                    network,
                }
                .encode(),
            )
        }
        // P2TR: OP_1 OP_PUSHBYTES_32 <32>
        [0x51, 0x20, rest @ ..] if rest.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(rest);
            Some(
                Address::P2TR {
                    output_key: h,
                    network,
                }
                .encode(),
            )
        }
        _ => None,
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

    /// End-to-end integration: BIP-39 mnemonic -> seed -> BIP-32 master ->
    /// BIP-86 first receive address.
    ///
    /// Uses the canonical BIP-86 test vector (BIP-86 §"Test vectors"):
    ///   mnemonic: "abandon abandon ... abandon about"
    ///   passphrase: ""
    ///   m/86'/0'/0'/0/0 -> bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
    ///
    /// This proves that:
    ///   1. mnemonic_to_seed produces the right 64-byte seed (PBKDF2 wired correctly)
    ///   2. ExtendedPrivKey::from_seed accepts it (BIP-32 link works)
    ///   3. The resulting key derives the canonical first BIP-86 address
    ///
    /// If any of those is wrong this test breaks loudly. This is the
    /// load-bearing wave-21 integration check.
    #[test]
    fn from_mnemonic_bip86_first_address_matches_canonical_vector() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic: Vec<&str> = mnemonic_str.split_whitespace().collect();

        let mut wallet =
            Wallet::from_mnemonic(&mnemonic, "", Network::Mainnet, AddressType::P2TR).unwrap();

        // First receive address at m/86'/0'/0'/0/0.
        let addr0 = wallet.get_new_address().unwrap();
        assert_eq!(
            addr0,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "BIP-86 first receive address must match the canonical test vector"
        );
    }

    /// Cross-check: passing the well-known TREZOR vector-1 mnemonic with
    /// passphrase "TREZOR" through `from_mnemonic` produces a wallet whose
    /// internal seed corresponds to BIP-39 vector seed `c55257c3...` (we
    /// can't read the seed back out, but we *can* observe that the wallet
    /// constructs without error and the same seed bytes build via from_seed).
    #[test]
    fn from_mnemonic_with_trezor_passphrase_constructs_cleanly() {
        let mnemonic: Vec<&str> = "legal winner thank year wave sausage worth useful legal winner thank yellow"
            .split_whitespace()
            .collect();
        // Should NOT panic — covers checksum + PBKDF2 + BIP-32 master derivation.
        let _wallet =
            Wallet::from_mnemonic(&mnemonic, "TREZOR", Network::Mainnet, AddressType::P2TR)
                .unwrap();
    }

    #[test]
    fn from_mnemonic_rejects_bad_checksum() {
        // 12 valid words but the checksum is broken (final word should be "about").
        let bad: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            .split_whitespace()
            .collect();
        match Wallet::from_mnemonic(&bad, "", Network::Mainnet, AddressType::P2TR) {
            Err(e) => {
                let msg = format!("{}", e);
                assert!(msg.contains("invalid BIP-39 mnemonic"), "got: {}", msg);
            }
            Ok(_) => panic!("expected from_mnemonic to reject bad-checksum mnemonic"),
        }
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

    // ------------------------------------------------------------------
    // sign_input — `signrawtransactionwithwallet` lying-RPC P0 closure
    // (CORE-PARITY-AUDIT/_lying-rpc-cross-impl-2026-05-05.md)
    // ------------------------------------------------------------------

    /// Build a wallet + a single owned P2WPKH UTXO, plus a tx spending it to a
    /// dummy address. Returns (wallet, tx, utxo) ready for sign_input.
    fn build_p2wpkh_signing_fixture() -> (Wallet, Transaction, WalletUtxo) {
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();
        let addr = wallet.get_new_address().unwrap();
        let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();

        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256([0x11u8; 32]),
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
        wallet.add_utxo(utxo.clone());

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: utxo.outpoint.clone(),
                script_sig: vec![],
                sequence: 0xFFFFFFFD,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 90_000,
                script_pubkey: Address::from_string(
                    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                    Some(Network::Testnet),
                )
                .unwrap()
                .to_script_pubkey(),
            }],
            lock_time: 0,
        };

        (wallet, tx, utxo)
    }

    #[test]
    fn sign_input_p2wpkh_actually_signs() {
        // Regression test for the lying-RPC bug: pre-fix
        // signrawtransactionwithwallet returned complete=true with the input's
        // witness still empty. After the fix, sign_input must populate the
        // witness with a real (sig, pubkey) pair.
        let (wallet, mut tx, utxo) = build_p2wpkh_signing_fixture();

        // Pre-condition: witness empty.
        assert!(tx.inputs[0].witness.is_empty());

        wallet
            .sign_input(&mut tx, 0, &[utxo])
            .expect("P2WPKH sign should succeed");

        // Post-condition: witness has 2 stack items (DER-sig+hashtype, 33-byte
        // compressed pubkey). This is the byte-level proof that we actually
        // signed and didn't return the input untouched.
        assert_eq!(
            tx.inputs[0].witness.len(),
            2,
            "P2WPKH witness must have 2 stack items"
        );
        let sig = &tx.inputs[0].witness[0];
        assert!(sig.len() >= 71 && sig.len() <= 73, "DER sig length sane");
        assert_eq!(*sig.last().unwrap(), 0x01, "sighash byte is SIGHASH_ALL");
        let pk = &tx.inputs[0].witness[1];
        assert_eq!(pk.len(), 33, "compressed pubkey is 33 bytes");
        assert!(
            pk[0] == 0x02 || pk[0] == 0x03,
            "compressed pubkey prefix is 0x02 or 0x03"
        );
    }

    #[test]
    fn sign_input_unknown_utxo_errors() {
        // Honest-error contract: if the input's prevout is not in the wallet,
        // sign_input must return Err — never a silent success.
        let seed = test_seed();
        let wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2WPKH).unwrap();

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: rustoshi_primitives::Hash256([0xdeu8; 32]),
                    vout: 7,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFD,
                witness: vec![],
            }],
            outputs: vec![],
            lock_time: 0,
        };

        let result = wallet.sign_input(&mut tx, 0, &[]);
        assert!(result.is_err(), "must error on unknown UTXO");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not in wallet"),
            "error message must mention not-in-wallet, got: {}",
            err
        );

        // Critical: tx unchanged.
        assert!(tx.inputs[0].witness.is_empty());
        assert!(tx.inputs[0].script_sig.is_empty());
    }

    #[test]
    fn sign_input_p2pkh_actually_signs() {
        // Same byte-level proof for the legacy code path, ensuring the
        // dispatch actually selected sign_p2pkh_input rather than no-oping.
        let seed = test_seed();
        let mut wallet = Wallet::from_seed(&seed, Network::Testnet, AddressType::P2PKH).unwrap();
        let addr = wallet.get_new_address().unwrap();
        let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();

        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: rustoshi_primitives::Hash256([0x22u8; 32]),
                vout: 1,
            },
            value: 50_000,
            script_pubkey: addr_obj.to_script_pubkey(),
            derivation_path: path,
            confirmations: 6,
            is_change: false,
            is_coinbase: false,
            height: Some(200),
        };
        wallet.add_utxo(utxo.clone());

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: utxo.outpoint.clone(),
                script_sig: vec![],
                sequence: 0xFFFFFFFD,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 40_000,
                script_pubkey: Address::from_string(
                    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                    Some(Network::Testnet),
                )
                .unwrap()
                .to_script_pubkey(),
            }],
            lock_time: 0,
        };

        wallet
            .sign_input(&mut tx, 0, &[utxo])
            .expect("P2PKH sign should succeed");

        // P2PKH: scriptSig populated, witness empty.
        assert!(
            !tx.inputs[0].script_sig.is_empty(),
            "P2PKH scriptSig must be populated"
        );
        assert!(
            tx.inputs[0].witness.is_empty(),
            "P2PKH leaves witness empty"
        );
        // scriptSig shape: <push sig+hashtype> <push pubkey> — at least 71+33+2 bytes.
        assert!(
            tx.inputs[0].script_sig.len() > 100,
            "P2PKH scriptSig should be ~107 bytes, got {}",
            tx.inputs[0].script_sig.len()
        );
    }

    // -----------------------------------------------------------------------
    // Coin-locking — `lockunspent`/`listlockunspent` plumbing on the wallet.
    // -----------------------------------------------------------------------

    #[test]
    fn lock_coin_unlock_cycle_and_selection_skip() {
        // Lock-then-unlock state mutates correctly, and `create_transaction`
        // skips locked coins so a wallet with one locked UTXO refuses to
        // auto-fund a transaction.
        let mut wallet = Wallet::from_seed(&[0u8; 32], Network::Testnet, AddressType::P2WPKH).unwrap();
        let addr = wallet.get_new_address().unwrap();
        let addr_obj = Address::from_string(&addr, Some(Network::Testnet)).unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();
        let outpoint = OutPoint {
            txid: rustoshi_primitives::Hash256([0x99u8; 32]),
            vout: 0,
        };
        wallet.add_utxo(WalletUtxo {
            outpoint: outpoint.clone(),
            value: 100_000,
            script_pubkey: addr_obj.to_script_pubkey(),
            derivation_path: path,
            confirmations: 6,
            is_change: false,
            is_coinbase: false,
            height: Some(1),
        });

        // Initially nothing locked.
        assert!(!wallet.is_locked_coin(&outpoint));
        assert_eq!(wallet.locked_coins().count(), 0);

        // Lock: returns true the first time, false thereafter.
        assert!(wallet.lock_coin(&outpoint));
        assert!(!wallet.lock_coin(&outpoint), "second lock is a no-op");
        assert!(wallet.is_locked_coin(&outpoint));
        assert_eq!(wallet.locked_coins().count(), 1);

        // create_transaction must now refuse to spend (nothing else available).
        let dummy_recipient = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();
        let res = wallet.create_transaction(vec![(dummy_recipient, 50_000)], 1.0);
        assert!(
            matches!(res, Err(WalletError::InsufficientFunds { .. })),
            "auto-funding must skip locked UTXOs; got {:?}",
            res
        );
        // list_spendable_unspent_unlocked must also return empty.
        assert!(wallet.list_spendable_unspent_unlocked().is_empty());

        // Unlock: returns true on first call, false thereafter.
        assert!(wallet.unlock_coin(&outpoint));
        assert!(!wallet.unlock_coin(&outpoint), "second unlock is a no-op");
        assert!(!wallet.is_locked_coin(&outpoint));

        // Unlock-all is idempotent.
        wallet.lock_coin(&outpoint);
        wallet.unlock_all_coins();
        assert!(!wallet.is_locked_coin(&outpoint));
    }

    #[test]
    fn private_key_for_address_returns_signing_key() {
        // Generated address must yield a derivable secret, and an unknown
        // address (e.g. someone else's bech32) must return None.
        let mut wallet = Wallet::from_seed(&[0u8; 32], Network::Testnet, AddressType::P2WPKH).unwrap();
        let addr = wallet.get_new_address().unwrap();

        let secret = wallet.private_key_for_address(&addr);
        assert!(secret.is_some(), "wallet must derive a key for its own address");

        let other = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();
        // Only None if the address really wasn't generated. We didn't mint
        // it, so this must miss.
        let s2 = wallet.private_key_for_address(&other);
        assert!(s2.is_none(), "unknown address must not return a key");
    }

    // ------------------------------------------------------------------
    // Phase-2 segwit-v0 P2WSH + P2SH-P2WSH signers (W29-B)
    // (CORE-PARITY-AUDIT/_design-per-impl-wallet-phase2-segwit-v0-2026-05-08.md)
    // ------------------------------------------------------------------

    /// Build a deterministic K-of-N CHECKMULTISIG witness script:
    /// `<M> <pk1> ... <pkN> <N> OP_CHECKMULTISIG`. Pubkeys are 33-byte
    /// compressed.
    fn build_multisig_script(m: u8, pubkeys: &[[u8; 33]]) -> Vec<u8> {
        assert!(m >= 1 && m as usize <= pubkeys.len());
        assert!(pubkeys.len() <= 16);
        let mut script = Vec::with_capacity(2 + pubkeys.len() * 34);
        script.push(0x50 + m); // OP_M
        for pk in pubkeys {
            script.push(33);
            script.extend_from_slice(pk);
        }
        script.push(0x50 + pubkeys.len() as u8); // OP_N
        script.push(0xae); // OP_CHECKMULTISIG
        script
    }

    /// Build an unsigned 1-input/1-output spending transaction for a P2WSH
    /// (or P2SH-P2WSH) prevout. Returns the unsigned tx.
    fn build_unsigned_p2wsh_tx(prev_txid: [u8; 32], prev_vout: u32) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: rustoshi_primitives::Hash256(prev_txid),
                    vout: prev_vout,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFD,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 90_000,
                script_pubkey: Address::from_string(
                    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                    Some(Network::Testnet),
                )
                .unwrap()
                .to_script_pubkey(),
            }],
            lock_time: 0,
        }
    }

    /// Verify a CHECKMULTISIG-shaped witness using the embedded signatures.
    /// Confirms each `<sig>` after the empty pad is a valid ECDSA over the
    /// BIP-143 sighash with `witness_script` as scriptCode for the matching
    /// pubkey in script-pubkey order.
    fn verify_multisig_witness_p2wsh(
        tx: &Transaction,
        input_index: usize,
        witness_script: &[u8],
        value: u64,
    ) {
        let witness = &tx.inputs[input_index].witness;
        assert!(
            witness.len() >= 3,
            "P2WSH multisig witness needs >= 3 stack items (pad + sig + script)"
        );
        assert!(
            witness[0].is_empty(),
            "first witness item must be the CHECKMULTISIG empty pad"
        );
        assert_eq!(
            witness.last().unwrap().as_slice(),
            witness_script,
            "last witness item must be the witness_script"
        );

        // Recompute sighash and walk pubkeys in order, matching against sigs.
        let sighash = segwit_v0_sighash(tx, input_index, witness_script, value, 0x01);
        let msg = Message::from_digest(sighash.0);
        let secp = secp_ctx();

        let sigs: &[Vec<u8>] = &witness[1..witness.len() - 1];

        // Walk pubkeys embedded in the script.
        let mut script_pks: Vec<[u8; 33]> = Vec::new();
        let mut i = 1usize;
        let end = witness_script.len() - 2;
        while i < end {
            let push_len = witness_script[i] as usize;
            i += 1;
            if push_len == 33 {
                let mut pk = [0u8; 33];
                pk.copy_from_slice(&witness_script[i..i + 33]);
                script_pks.push(pk);
            }
            i += push_len;
        }

        // Match each sig against the next-in-order pubkey that verifies.
        let mut sig_idx = 0;
        let mut pk_idx = 0;
        while sig_idx < sigs.len() && pk_idx < script_pks.len() {
            let sig = &sigs[sig_idx];
            assert!(*sig.last().unwrap() == 0x01, "sighash byte = SIGHASH_ALL");
            let der = &sig[..sig.len() - 1];
            let parsed_sig = secp256k1::ecdsa::Signature::from_der(der)
                .expect("DER-encoded signature");
            let parsed_pk = secp256k1::PublicKey::from_slice(&script_pks[pk_idx])
                .expect("compressed pubkey");
            if secp.verify_ecdsa(&msg, &parsed_sig, &parsed_pk).is_ok() {
                sig_idx += 1;
            }
            pk_idx += 1;
        }
        assert_eq!(
            sig_idx,
            sigs.len(),
            "every signature in the witness must verify against an in-order pubkey"
        );
    }

    /// Test 1 (Wave 28 design-doc gate vector #1): native 2-of-3 P2WSH
    /// multisig sign + verify against the BIP-143 segwit-v0 sighash.
    #[test]
    fn sign_p2wsh_2_of_3_multisig_verifies() {
        // Three deterministic signing keys. Using small distinct scalars so
        // the test is fully deterministic and doesn't depend on rng.
        let secp = Secp256k1::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let sk3 = secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
        let pk1: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk1).serialize();
        let pk2: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk2).serialize();
        let pk3: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk3).serialize();

        let witness_script = build_multisig_script(2, &[pk1, pk2, pk3]);
        // 2-of-3 P2WSH script length is 1+34*3+1+1 = 105 bytes.
        assert_eq!(witness_script.len(), 105);
        // Sanity: detector recognises this shape.
        assert!(is_multisig_witness_script(&witness_script));

        // The wallet object isn't strictly needed for sign_p2wsh_input
        // (the keys come from the caller), but we instantiate one to mirror
        // how a real signer pipeline would look.
        let wallet =
            Wallet::from_seed(&test_seed(), Network::Testnet, AddressType::P2WPKH).unwrap();
        let mut tx = build_unsigned_p2wsh_tx([0xab; 32], 0);
        let value: u64 = 100_000;

        // Sign with keys 1 and 3 (skip the middle key on purpose to exercise
        // partial-multisig — Core honors any M-of-N order at verify time).
        wallet
            .sign_p2wsh_input(&mut tx, 0, &witness_script, value, &[sk1, sk3], 0x01)
            .expect("P2WSH 2-of-3 sign should succeed");

        // Witness must be [empty, sig_sk1, sig_sk3, witness_script].
        let witness = &tx.inputs[0].witness;
        assert_eq!(
            witness.len(),
            4,
            "2-of-3 P2WSH witness = [pad, sig1, sig2, script]"
        );
        assert!(witness[0].is_empty(), "leading CHECKMULTISIG empty pad");
        assert_eq!(witness[3], witness_script);

        // Both signatures must verify — and they verify against pk1 + pk3,
        // not pk2 (which we didn't sign with).
        verify_multisig_witness_p2wsh(&tx, 0, &witness_script, value);

        // scriptSig must be empty for native P2WSH.
        assert!(
            tx.inputs[0].script_sig.is_empty(),
            "native P2WSH scriptSig must be empty"
        );
    }

    /// Test 2 (Wave 28 design-doc gate vector #2): P2SH-P2WSH 2-of-2 multisig
    /// wrap. Witness must match the inner P2WSH; scriptSig must be a single
    /// push of the redeem script `OP_0 <sha256(witness_script)>`.
    #[test]
    fn sign_p2sh_p2wsh_2_of_2_wrap_verifies() {
        let secp = Secp256k1::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[8u8; 32]).unwrap();
        let pk1: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk1).serialize();
        let pk2: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk2).serialize();

        let witness_script = build_multisig_script(2, &[pk1, pk2]);
        // 2-of-2 P2WSH script length is 1+34*2+1+1 = 71 bytes.
        assert_eq!(witness_script.len(), 71);

        let wallet =
            Wallet::from_seed(&test_seed(), Network::Testnet, AddressType::P2WPKH).unwrap();
        let mut tx = build_unsigned_p2wsh_tx([0xcd; 32], 1);
        let value: u64 = 200_000;

        // Build the canonical P2SH-P2WSH prevout scriptPubKey:
        //   OP_HASH160 PUSH20 <HASH160(OP_0 PUSH32 SHA256(witness_script))> OP_EQUAL
        let ws_hash = sha256(&witness_script);
        let mut redeem = Vec::with_capacity(34);
        redeem.push(0x00);
        redeem.push(0x20);
        redeem.extend_from_slice(&ws_hash);
        let redeem_h160 = hash160(&redeem);
        let mut prevout_spk = Vec::with_capacity(23);
        prevout_spk.push(0xa9);
        prevout_spk.push(0x14);
        prevout_spk.extend_from_slice(&redeem_h160.0);
        prevout_spk.push(0x87);

        wallet
            .sign_p2sh_p2wsh_input(
                &mut tx,
                0,
                &witness_script,
                value,
                &[sk1, sk2],
                0x01,
                &prevout_spk,
            )
            .expect("P2SH-P2WSH 2-of-2 sign should succeed");

        // Witness identical shape to native P2WSH.
        verify_multisig_witness_p2wsh(&tx, 0, &witness_script, value);
        assert_eq!(tx.inputs[0].witness.len(), 4);

        // scriptSig: one push of OP_0 <sha256(witness_script)>. That's
        // 1 (length-prefix=34) + 34 (redeem_script) = 35 bytes.
        let script_sig = &tx.inputs[0].script_sig;
        assert_eq!(
            script_sig.len(),
            35,
            "P2SH-P2WSH scriptSig is 35 bytes (push of 34-byte redeem)"
        );
        assert_eq!(script_sig[0], 34, "first byte = 0x22 push of 34");
        assert_eq!(script_sig[1], 0x00, "redeem byte 0 = OP_0");
        assert_eq!(script_sig[2], 0x20, "redeem byte 1 = push 32");
        // Bytes 3..35 = SHA256(witness_script).
        let expected_hash = sha256(&witness_script);
        assert_eq!(&script_sig[3..35], &expected_hash[..]);
    }

    /// Test 3 (Wave 28 parallel-impl-drift sentinel, mirrors W27-D blockbrew
    /// pattern): PSBT-vs-raw-tx round-trip. Build the same 2-of-2 P2WSH spend
    /// two ways — directly via `sign_p2wsh_input` on a Transaction, and as a
    /// PSBT signed via `sign_psbt_input` + `finalize_input` + `extract_tx` —
    /// and assert the two extracted transactions are byte-identical.
    #[test]
    fn p2wsh_psbt_roundtrip_matches_raw_signer() {
        let secp = Secp256k1::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[0x21; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let pk1: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk1).serialize();
        let pk2: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk2).serialize();
        let witness_script = build_multisig_script(2, &[pk1, pk2]);
        let value: u64 = 150_000;
        let prev_txid = [0xefu8; 32];
        let prev_vout = 2u32;

        let wallet =
            Wallet::from_seed(&test_seed(), Network::Testnet, AddressType::P2WPKH).unwrap();

        // Path A: raw-tx signing directly.
        let mut tx_raw = build_unsigned_p2wsh_tx(prev_txid, prev_vout);
        wallet
            .sign_p2wsh_input(&mut tx_raw, 0, &witness_script, value, &[sk1, sk2], 0x01)
            .expect("raw P2WSH sign");

        // Path B: PSBT signing through the BIP-174 Signer + Finalizer +
        // Extractor roles.
        let unsigned_b = build_unsigned_p2wsh_tx(prev_txid, prev_vout);
        let mut psbt = crate::psbt::Psbt::from_unsigned_tx(unsigned_b).unwrap();
        // Build the witness UTXO: the actual P2WSH scriptPubKey is
        // OP_0 <sha256(witness_script)>.
        let ws_hash = sha256(&witness_script);
        let mut p2wsh_spk = Vec::with_capacity(34);
        p2wsh_spk.push(0x00);
        p2wsh_spk.push(0x20);
        p2wsh_spk.extend_from_slice(&ws_hash);
        psbt.set_witness_utxo(
            0,
            TxOut {
                value,
                script_pubkey: p2wsh_spk,
            },
        )
        .unwrap();
        psbt.set_input_witness_script(0, witness_script.clone())
            .unwrap();

        // Sign with both keys.
        let n1 = wallet
            .sign_psbt_input(&mut psbt, 0, &[sk1], 0x01)
            .expect("PSBT sign sk1");
        let n2 = wallet
            .sign_psbt_input(&mut psbt, 0, &[sk2], 0x01)
            .expect("PSBT sign sk2");
        assert_eq!(n1, 1, "sk1 signed exactly once");
        assert_eq!(n2, 1, "sk2 signed exactly once");
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);

        psbt.finalize_input(0).expect("finalize");
        let tx_psbt = psbt.extract_tx().expect("extract");

        // Byte-identity. ECDSA signing is deterministic in libsecp256k1
        // (RFC 6979) so the two paths must agree exactly.
        assert_eq!(
            tx_raw.inputs[0].witness, tx_psbt.inputs[0].witness,
            "PSBT witness must match raw-tx witness byte-for-byte"
        );
        assert_eq!(
            tx_raw.inputs[0].script_sig, tx_psbt.inputs[0].script_sig,
            "P2WSH scriptSig is empty on both paths"
        );

        // Sanity: both verify.
        verify_multisig_witness_p2wsh(&tx_psbt, 0, &witness_script, value);
        verify_multisig_witness_p2wsh(&tx_raw, 0, &witness_script, value);
    }

    // ====================================================================
    // W31 — P2SH/P2WSH commitment-check tests
    //
    // Threat: PSBT path consumes caller-supplied witness_script. Without a
    // commitment check, an attacker substitutes a witness_script that
    // happens to embed our pubkey, gets us to sign with SIGHASH_ALL, and
    // walks off with the signature for an unrelated prevout. These tests
    // assert that we (a) still sign happily on a correctly-built PSBT,
    // and (b) refuse loudly when the witness_script doesn't commit to the
    // prevout's scriptPubKey.
    // ====================================================================

    /// W31 positive: a correctly-built P2SH-P2WSH PSBT with a matching
    /// witness_script must sign successfully (no regression on the
    /// happy path).
    #[test]
    fn w31_psbt_p2sh_p2wsh_correct_commitment_signs_ok() {
        let secp = Secp256k1::new();
        let sk1 = secp256k1::SecretKey::from_slice(&[0x31; 32]).unwrap();
        let sk2 = secp256k1::SecretKey::from_slice(&[0x32; 32]).unwrap();
        let pk1: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk1).serialize();
        let pk2: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk2).serialize();

        let witness_script = build_multisig_script(2, &[pk1, pk2]);
        let value: u64 = 333_000;

        // Canonical P2SH-P2WSH scriptPubKey:
        //   OP_HASH160 PUSH20 HASH160(OP_0 PUSH32 SHA256(ws)) OP_EQUAL.
        let ws_hash = sha256(&witness_script);
        let mut redeem = Vec::with_capacity(34);
        redeem.push(0x00);
        redeem.push(0x20);
        redeem.extend_from_slice(&ws_hash);
        let redeem_h160 = hash160(&redeem);
        let mut p2sh_spk = Vec::with_capacity(23);
        p2sh_spk.push(0xa9);
        p2sh_spk.push(0x14);
        p2sh_spk.extend_from_slice(&redeem_h160.0);
        p2sh_spk.push(0x87);

        let wallet =
            Wallet::from_seed(&test_seed(), Network::Testnet, AddressType::P2WPKH).unwrap();
        let unsigned = build_unsigned_p2wsh_tx([0xa1; 32], 0);
        let mut psbt = crate::psbt::Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.set_witness_utxo(
            0,
            TxOut {
                value,
                script_pubkey: p2sh_spk,
            },
        )
        .unwrap();
        psbt.set_input_witness_script(0, witness_script.clone())
            .unwrap();

        let n1 = wallet
            .sign_psbt_input(&mut psbt, 0, &[sk1], 0x01)
            .expect("PSBT P2SH-P2WSH must sign on a matching commitment");
        let n2 = wallet
            .sign_psbt_input(&mut psbt, 0, &[sk2], 0x01)
            .expect("PSBT P2SH-P2WSH must sign on a matching commitment");
        assert_eq!(n1, 1);
        assert_eq!(n2, 1);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);
    }

    /// W31 negative — P2SH-P2WSH: a PSBT whose `witness_utxo.script_pubkey`
    /// is P2SH-shaped but doesn't commit to the supplied `witness_script`
    /// must be REFUSED, not signed. This is the genuinely-vulnerable path.
    #[test]
    fn w31_psbt_p2sh_p2wsh_forged_witness_script_rejected() {
        let secp = Secp256k1::new();
        let sk_atk = secp256k1::SecretKey::from_slice(&[0x33; 32]).unwrap();
        let sk_us = secp256k1::SecretKey::from_slice(&[0x34; 32]).unwrap();
        let pk_atk: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk_atk).serialize();
        let pk_us: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk_us).serialize();

        // The "real" prevout is a P2SH-P2WSH on a multisig of (atk, atk):
        let real_witness_script = build_multisig_script(1, &[pk_atk, pk_atk]);
        let real_ws_hash = sha256(&real_witness_script);
        let mut real_redeem = vec![0x00, 0x20];
        real_redeem.extend_from_slice(&real_ws_hash);
        let real_redeem_h160 = hash160(&real_redeem);
        let mut real_p2sh_spk = Vec::with_capacity(23);
        real_p2sh_spk.push(0xa9);
        real_p2sh_spk.push(0x14);
        real_p2sh_spk.extend_from_slice(&real_redeem_h160.0);
        real_p2sh_spk.push(0x87);

        // Attacker hands us a forged witness_script that includes OUR
        // pubkey (so the sign-key match fires). It does not commit to
        // real_p2sh_spk.
        let forged_witness_script = build_multisig_script(1, &[pk_us, pk_atk]);

        let wallet =
            Wallet::from_seed(&test_seed(), Network::Testnet, AddressType::P2WPKH).unwrap();
        let unsigned = build_unsigned_p2wsh_tx([0xa2; 32], 0);
        let mut psbt = crate::psbt::Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.set_witness_utxo(
            0,
            TxOut {
                value: 100_000,
                script_pubkey: real_p2sh_spk,
            },
        )
        .unwrap();
        psbt.set_input_witness_script(0, forged_witness_script)
            .unwrap();

        // Pre-W31 this would have succeeded and produced a valid sig.
        // Post-W31 it MUST fail on the commitment check.
        let res = wallet.sign_psbt_input(&mut psbt, 0, &[sk_us], 0x01);
        let err = res.expect_err("forged witness_script must be rejected");
        match err {
            WalletError::SigningError(msg) => {
                assert!(
                    msg.contains("P2SH-P2WSH commitment verification failed"),
                    "expected commitment-failure error, got: {}",
                    msg
                );
            }
            other => panic!("expected SigningError, got {:?}", other),
        }
        // Critically: no partial_sig must have been written.
        assert!(
            psbt.inputs[0].partial_sigs.is_empty(),
            "no signature should leak when the commitment check rejects"
        );
    }

    /// W31 negative — bare P2WSH: same threat, simpler shape. Forged
    /// `witness_script` whose SHA256 doesn't equal the witness program in
    /// the prevout's P2WSH scriptPubKey must be refused.
    #[test]
    fn w31_psbt_p2wsh_forged_witness_script_rejected() {
        let secp = Secp256k1::new();
        let sk_atk = secp256k1::SecretKey::from_slice(&[0x35; 32]).unwrap();
        let sk_us = secp256k1::SecretKey::from_slice(&[0x36; 32]).unwrap();
        let pk_atk: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk_atk).serialize();
        let pk_us: [u8; 33] = secp256k1::PublicKey::from_secret_key(&secp, &sk_us).serialize();

        // Real prevout: P2WSH committed to a 1-of-2 (atk, atk) script.
        let real_ws = build_multisig_script(1, &[pk_atk, pk_atk]);
        let real_ws_hash = sha256(&real_ws);
        let mut real_p2wsh_spk = Vec::with_capacity(34);
        real_p2wsh_spk.push(0x00);
        real_p2wsh_spk.push(0x20);
        real_p2wsh_spk.extend_from_slice(&real_ws_hash);

        // Attacker substitutes a witness_script that names US instead.
        let forged_ws = build_multisig_script(1, &[pk_us, pk_atk]);

        let wallet =
            Wallet::from_seed(&test_seed(), Network::Testnet, AddressType::P2WPKH).unwrap();
        let unsigned = build_unsigned_p2wsh_tx([0xa3; 32], 0);
        let mut psbt = crate::psbt::Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.set_witness_utxo(
            0,
            TxOut {
                value: 100_000,
                script_pubkey: real_p2wsh_spk,
            },
        )
        .unwrap();
        psbt.set_input_witness_script(0, forged_ws).unwrap();

        let res = wallet.sign_psbt_input(&mut psbt, 0, &[sk_us], 0x01);
        let err = res.expect_err("forged P2WSH witness_script must be rejected");
        match err {
            WalletError::SigningError(msg) => {
                assert!(
                    msg.contains("P2WSH commitment verification failed"),
                    "expected commitment-failure error, got: {}",
                    msg
                );
            }
            other => panic!("expected SigningError, got {:?}", other),
        }
        assert!(
            psbt.inputs[0].partial_sigs.is_empty(),
            "no signature should leak when the commitment check rejects"
        );
    }

    #[test]
    fn wif_round_trips_and_network_guards() {
        let sk = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
        // encode -> decode round-trips the key + compressed flag.
        let wif = encode_wif(&sk, Network::Regtest);
        let (decoded, compressed) = decode_wif(&wif, Network::Regtest).unwrap();
        assert_eq!(decoded[..], sk[..]);
        assert!(compressed, "encode_wif emits the compressed flag");
        // The regtest WIF must NOT decode under mainnet (version-byte guard).
        assert!(
            decode_wif(&wif, Network::Mainnet).is_err(),
            "regtest WIF must be rejected on mainnet (Core's secretKeyPrefix check)"
        );
        // Garbage is rejected.
        assert!(decode_wif("not-a-wif", Network::Regtest).is_err());
    }

    #[test]
    fn import_private_key_registers_scripts_and_scan_credits() {
        let mut wallet =
            Wallet::from_seed(&test_seed(), Network::Regtest, AddressType::P2WPKH).unwrap();

        // A foreign key NOT derived from the seed.
        let sk = secp256k1::SecretKey::from_slice(&[0x7e; 32]).unwrap();
        let addr = wallet
            .import_private_key(sk, "ext".to_string())
            .expect("import should succeed");
        assert!(wallet.is_mine(&addr), "imported address must be is_mine");
        assert_eq!(wallet.imported_key_count(), 1);

        // The P2WPKH scriptPubKey for the imported key (default address type).
        let secp = secp_ctx();
        let pk = secp256k1::PublicKey::from_secret_key(secp, &sk);
        let spk = Address::P2WPKH {
            hash: hash160(&pk.serialize()),
            network: Network::Regtest,
        }
        .to_script_pubkey();

        // A block paying that script must credit the wallet via the SAME scan
        // path rescanblockchain uses (Wallet::scan_block_at).
        let funding = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([0x11; 32]), vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 12_345_000, script_pubkey: spk }],
            lock_time: 0,
        };
        let (credits, _debits) =
            wallet.scan_block_at(&[funding], 5, Hash256([0x22; 32]), 1_700_000_000);
        assert_eq!(credits, 1, "scan must credit the imported-key output");
        assert_eq!(wallet.balance(), 12_345_000);

        // The credited output is labelled with the imported address (history).
        assert!(
            wallet.history().iter().any(|e| e
                .details
                .iter()
                .any(|d| d.address.as_deref() == Some(addr.as_str()))),
            "imported credit must be labelled with the imported address"
        );
    }
}
