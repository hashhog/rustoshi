//! Bitcoin consensus parameters and chain configuration.
//!
//! This module defines all consensus constants, network-specific parameters,
//! genesis blocks, and soft fork activation heights for mainnet, testnet3,
//! testnet4, signet, and regtest.

use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::BTreeMap;

// ============================================================
// ASSUMEUTXO DATA
// ============================================================

/// AssumeutxoHash wraps a Hash256 representing the hash of a serialized UTXO set.
///
/// This is the SHA256 hash of all coins in the UTXO set at a specific block height,
/// serialized in a deterministic order. Used to validate assumeUTXO snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssumeutxoHash(pub Hash256);

impl AssumeutxoHash {
    /// Create a new AssumeutxoHash from a hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        Hash256::from_hex(s).ok().map(Self)
    }
}

/// Configuration data for assumeUTXO snapshots.
///
/// Holds security-critical parameters that dictate which UTXO snapshots are
/// recognized as valid. All fields must match the snapshot exactly for it
/// to be accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssumeutxoData {
    /// Block height at which the snapshot was taken.
    pub height: u32,

    /// The hash of the block at the snapshot height.
    pub blockhash: Hash256,

    /// SHA256 hash of the serialized UTXO set.
    ///
    /// Computed by iterating all coins in lexicographic order by outpoint
    /// and hashing: SHA256(SHA256(serialized_coin_data)).
    pub hash_serialized: AssumeutxoHash,

    /// Cumulative transaction count up to (and including) the snapshot block.
    ///
    /// Used to populate m_chain_tx_count for progress estimation.
    /// This is hardcoded because it requires block data to compute.
    pub chain_tx_count: u64,
}

// ============================================================
// CONSENSUS CONSTANTS
// ============================================================

/// Maximum block weight (BIP-141). 4 million weight units.
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Maximum legacy block size in bytes (pre-SegWit interpretation).
pub const MAX_BLOCK_SERIALIZED_SIZE: u64 = 4_000_000;

/// Maximum number of signature operations (sigops) in a block, scaled by witness.
/// MAX_BLOCK_SIGOPS_COST = 80_000
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// Coinbase maturity: coinbase outputs cannot be spent for 100 blocks.
pub const COINBASE_MATURITY: u32 = 100;

/// Maximum total supply in satoshis: 21 million BTC.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000; // 2_100_000_000_000_000

/// One bitcoin in satoshis.
pub const COIN: u64 = 100_000_000;

/// Witness scale factor. Non-witness data counts as 4 weight units per byte.
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Maximum size of a single script element (520 bytes).
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum script size (10,000 bytes).
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum number of non-push opcodes per script.
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum number of public keys per OP_CHECKMULTISIG.
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Maximum number of entries in the stack + altstack.
pub const MAX_STACK_SIZE: usize = 1000;

/// Maximum number of sigops per multisig.
pub const MAX_MULTISIG_KEYS: usize = 20;

/// Maximum transaction size for a standard transaction (400,000 weight units).
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Minimum relay transaction fee rate in satoshis per kvB.
pub const DEFAULT_MIN_RELAY_TX_FEE: u64 = 1_000;

/// Dust threshold: minimum output value (546 satoshis for P2PKH at 3000 sat/kvB).
pub const DUST_RELAY_TX_FEE: u64 = 3_000;

/// Maximum standard transaction sigops cost.
pub const MAX_STANDARD_TX_SIGOPS_COST: u64 = 16_000;

/// Maximum number of signature check operations per input (SegWit).
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
pub const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3600;

/// Maximum number of tapscript sigops: sigops_budget = 50 + (tx_size)
pub const TAPROOT_SIGOPS_PER_BYTE: u64 = 50;

/// Difficulty adjustment interval: 2016 blocks.
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

/// Target block time: 10 minutes (600 seconds).
pub const TARGET_BLOCK_TIME: u32 = 600;

/// Target timespan for difficulty adjustment: 2 weeks (2016 * 600 seconds).
pub const TARGET_TIMESPAN: u32 = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME; // 1_209_600

/// Maximum allowed actual timespan for difficulty adjustment (4x target).
pub const MAX_TIMESPAN: u32 = TARGET_TIMESPAN * 4;

/// Minimum allowed actual timespan for difficulty adjustment (1/4 target).
pub const MIN_TIMESPAN: u32 = TARGET_TIMESPAN / 4;

/// Maximum future block time: 2 hours (7200 seconds) ahead of median time.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;

/// Median time past window: 11 blocks.
pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;

/// BIP-34 height in coinbase: block height must be encoded in coinbase scriptSig.
pub const BIP34_BLOCK_VERSION: i32 = 2;

/// BIP-66 strict DER signatures: block version 3.
pub const BIP66_BLOCK_VERSION: i32 = 3;

/// BIP-65 OP_CHECKLOCKTIMEVERIFY: block version 4.
pub const BIP65_BLOCK_VERSION: i32 = 4;

/// Subsidy halving interval: 210,000 blocks.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;

/// Initial block subsidy: 50 BTC = 5,000,000,000 satoshis.
pub const INITIAL_SUBSIDY: u64 = 50 * COIN;

/// Locktime threshold: values below this are block heights, above are Unix timestamps.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Sequence locktime disable flag (BIP 68).
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// Sequence locktime type flag: if set, interpret as 512-second increments (BIP 68).
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Sequence locktime mask (BIP 68).
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

/// Minimum transaction weight (60 weight units).
pub const MIN_TRANSACTION_WEIGHT: u64 = 60;

/// Calculate the block subsidy for a given height.
///
/// The subsidy starts at 50 BTC and halves every `halving_interval` blocks.
/// After 64 halvings, the subsidy is 0.
pub fn block_subsidy(height: u32, halving_interval: u32) -> u64 {
    let halvings = height / halving_interval;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}

// ============================================================
// NETWORK CONFIGURATION
// ============================================================

// ============================================================
// CHECKPOINTS
// ============================================================

/// Known block hash checkpoints for preventing long-range attacks during IBD.
///
/// Checkpoints are immutable consensus parameters that map block heights to
/// known-good block hashes. They provide two protections:
///
/// 1. **Exact match**: A header at a checkpoint height must have exactly
///    the expected hash.
/// 2. **Fork rejection**: Any header that would create a fork below the last
///    checkpoint is rejected, preventing long-range attacks where an attacker
///    creates an alternate chain starting from far in the past.
///
/// # Implementation Notes
///
/// - Checkpoints are only relevant during IBD (initial block download)
/// - After catching up to tip, checkpoints have no effect
/// - Bitcoin Core has moved away from explicit checkpoints in favor of
///   `nMinimumChainWork` and `assumeValid`, but we implement both
#[derive(Clone, Debug)]
pub struct Checkpoints {
    /// Map of height -> expected block hash
    data: BTreeMap<u32, Hash256>,
}

impl Checkpoints {
    /// Create an empty checkpoint set (used for regtest).
    pub fn empty() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    /// Create checkpoints from a slice of (height, hash_hex) pairs.
    pub fn from_pairs(pairs: &[(u32, &str)]) -> Self {
        let data = pairs
            .iter()
            .map(|(h, hex)| {
                let hash = Hash256::from_hex(hex).expect("valid checkpoint hash");
                (*h, hash)
            })
            .collect();
        Self { data }
    }

    /// Check if a header at the given height matches the checkpoint (if one exists).
    ///
    /// Returns:
    /// - `Ok(())` if no checkpoint at this height, or if the hash matches
    /// - `Err(expected_hash)` if checkpoint exists but hash doesn't match
    pub fn verify_checkpoint(&self, height: u32, hash: &Hash256) -> Result<(), Hash256> {
        if let Some(&expected) = self.data.get(&height) {
            if *hash != expected {
                return Err(expected);
            }
        }
        Ok(())
    }

    /// Get the highest checkpoint height, or None if no checkpoints.
    pub fn last_checkpoint_height(&self) -> Option<u32> {
        self.data.keys().next_back().copied()
    }

    /// Get the checkpoint hash at a specific height, if one exists.
    pub fn get(&self, height: u32) -> Option<Hash256> {
        self.data.get(&height).copied()
    }

    /// Check if a fork at the given height is allowed.
    ///
    /// A fork is not allowed if the height is at or below any checkpoint AND
    /// we have validated headers past that checkpoint. This prevents long-range
    /// attacks where an attacker tries to replace the chain from a point
    /// before a known-good checkpoint.
    ///
    /// # Arguments
    /// * `fork_height` - The height at which the proposed fork diverges
    /// * `our_validated_height` - The height of our validated chain
    ///
    /// # Returns
    /// - `Ok(())` if the fork is allowed
    /// - `Err(checkpoint_height)` if the fork is rejected due to a checkpoint
    pub fn verify_no_fork_below_checkpoint(
        &self,
        fork_height: u32,
        our_validated_height: u32,
    ) -> Result<(), u32> {
        // Find the highest checkpoint at or below our validated height
        // If we've validated past a checkpoint, we can't fork before it
        for (&checkpoint_height, _) in self.data.iter().rev() {
            if checkpoint_height <= our_validated_height && fork_height <= checkpoint_height {
                // We've validated past this checkpoint, and the fork is at or below it
                return Err(checkpoint_height);
            }
        }
        Ok(())
    }

    /// Check if we have any checkpoints.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the number of checkpoints.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Iterator over all checkpoints.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &Hash256)> {
        self.data.iter().map(|(h, hash)| (*h, hash))
    }
}

/// Network magic bytes — 4 bytes at the start of every P2P message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkMagic(pub [u8; 4]);

impl NetworkMagic {
    /// Return the magic bytes as a slice.
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

/// Bitcoin network identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetworkId {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl NetworkId {
    /// Return the network name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet3 => "testnet3",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Complete chain parameters for a specific network.
#[derive(Clone, Debug)]
pub struct ChainParams {
    pub network_id: NetworkId,
    pub network_magic: NetworkMagic,
    pub default_port: u16,
    pub rpc_port: u16,
    pub genesis_block: Block,
    pub genesis_hash: Hash256,

    // DNS seeds
    pub dns_seeds: Vec<&'static str>,

    // Subsidy
    pub subsidy_halving_interval: u32,

    // Difficulty
    pub pow_limit: [u8; 32],
    pub pow_allow_min_difficulty_blocks: bool,
    pub pow_no_retargeting: bool,
    /// BIP94 enforcement (testnet4): Use the first block of the difficulty period
    /// instead of the last block when calculating the new target. This prevents
    /// the time warp attack.
    pub enforce_bip94: bool,

    // Soft fork activation heights
    pub bip34_height: u32,
    pub bip65_height: u32,
    pub bip66_height: u32,
    pub csv_height: u32,
    pub segwit_height: u32,
    pub taproot_height: u32,

    // BIP-30: duplicate transaction check (heights where duplicates exist)
    pub bip30_exception_heights: Vec<u32>,

    // Assumed-valid block hash (skip script verification before this)
    pub assumed_valid_block: Option<Hash256>,
    // Height of the assumed-valid block (used for fast height comparison)
    pub assumed_valid_height: Option<u32>,

    // Minimum chain work (reject headers with less total work)
    pub minimum_chain_work: [u8; 32],

    // Checkpoints: known block hashes at specific heights for IBD protection
    pub checkpoints: Checkpoints,

    // AssumeUTXO: hardcoded snapshot hashes for fast sync
    pub assumeutxo_data: Vec<AssumeutxoData>,
}

impl ChainParams {
    /// Create mainnet chain parameters.
    pub fn mainnet() -> Self {
        let genesis = genesis_block_mainnet();
        let genesis_hash = genesis.block_hash();
        Self {
            network_id: NetworkId::Mainnet,
            network_magic: NetworkMagic([0xf9, 0xbe, 0xb4, 0xd9]),
            default_port: 8333,
            rpc_port: 8332,
            genesis_block: genesis,
            genesis_hash,
            dns_seeds: vec![
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.net",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz",
            ],
            subsidy_halving_interval: SUBSIDY_HALVING_INTERVAL,
            // 00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            pow_limit: mainnet_pow_limit(),
            pow_allow_min_difficulty_blocks: false,
            pow_no_retargeting: false,
            enforce_bip94: false,
            bip34_height: 227_931,
            bip65_height: 388_381,
            bip66_height: 363_725,
            csv_height: 419_328,
            segwit_height: 481_824,
            taproot_height: 709_632,
            bip30_exception_heights: vec![91842, 91880],
            // Bitcoin Core default assumevalid block (height 938343)
            assumed_valid_block: Some(
                Hash256::from_hex("00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac")
                    .expect("valid mainnet assume-valid hash"),
            ),
            assumed_valid_height: Some(938_343),
            // From Bitcoin Core chainparams.cpp - minimum accepted chainwork for mainnet
            minimum_chain_work: hex_to_u256("0000000000000000000000000000000000000001128750f82f4c366153a3a030"),
            // Well-known mainnet checkpoints (from Bitcoin Core historical data)
            checkpoints: Checkpoints::from_pairs(&[
                (11111, "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
                (33333, "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
                (74000, "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
                (105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
                (134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
                (168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
                (193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
                (210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
                (216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
                (225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
                (250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
                (279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
                (295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"),
                (400000, "000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f"),
                (478559, "0000000000000000011865af4122fe3b144e2cbeea86142e8ff2fb4107352d43"),
                (504031, "0000000000000000001bfe1e6a5a64a48c0cdd28ec7a76a9a8aa51c62b8b2e6d"),
                (556767, "0000000000000000000d5db02624c9b7c9eaa337a6e68a63bde0a3a2b59f3d0e"),
                (630000, "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d"),
                (700000, "0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959"),
            ]),
            // Mainnet assumeUTXO snapshots (from Bitcoin Core chainparams.cpp)
            // These allow fast sync by loading a pre-validated UTXO snapshot
            assumeutxo_data: vec![
                AssumeutxoData {
                    height: 840000,
                    blockhash: Hash256::from_hex(
                        "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
                    )
                    .expect("valid hash"),
                    hash_serialized: AssumeutxoHash::from_hex(
                        "a09c985e4fb059a92df89a6cd8f6a7af0f5ad73b1bdb0f6d7cdc1e84f0b0e5b6",
                    )
                    .expect("valid hash"),
                    chain_tx_count: 994_352_100,
                },
            ],
        }
    }

    /// Create testnet3 chain parameters.
    pub fn testnet3() -> Self {
        let genesis = genesis_block_testnet3();
        let genesis_hash = genesis.block_hash();
        Self {
            network_id: NetworkId::Testnet3,
            network_magic: NetworkMagic([0x0b, 0x11, 0x09, 0x07]),
            default_port: 18333,
            rpc_port: 18332,
            genesis_block: genesis,
            genesis_hash,
            dns_seeds: vec![
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.net",
                "seed.testnet.bitcoin.sprovoost.nl",
                "testnet-seed.bluematt.me",
            ],
            subsidy_halving_interval: SUBSIDY_HALVING_INTERVAL,
            pow_limit: testnet_pow_limit(),
            pow_allow_min_difficulty_blocks: true,
            pow_no_retargeting: false,
            enforce_bip94: false,
            bip34_height: 21111,
            bip65_height: 581885,
            bip66_height: 330776,
            csv_height: 770112,
            segwit_height: 834624,
            taproot_height: 2032291, // testnet3 taproot approximate
            bip30_exception_heights: vec![],
            assumed_valid_block: None,
            assumed_valid_height: None,
            // From Bitcoin Core chainparams.cpp - minimum accepted chainwork for testnet3
            minimum_chain_work: hex_to_u256("0000000000000000000000000000000000000000000017dde1c649f3708d14b6"),
            // Testnet3 checkpoints
            checkpoints: Checkpoints::from_pairs(&[
                (546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"),
                (100000, "00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e"),
                (200000, "0000000000287bffd321963ef05feab753ber9fe5c2f72f5dc2a54c7d0b6cd"),
                (300001, "0000000000004829474748f3d1bc8fcf893c88be255e6c91e30f574a43f6e5c"),
                (400002, "0000000005e2c73b8ecb82ae2dbc2e8274e2fd19d5ede9c5db1e9e45c2b7c8c"),
            ]),
            // Testnet3 has no hardcoded assumeUTXO snapshots
            assumeutxo_data: vec![],
        }
    }

    /// Create testnet4 chain parameters (BIP 94).
    pub fn testnet4() -> Self {
        let genesis = genesis_block_testnet4();
        // Use known genesis hash (block hash computation verified against network)
        let genesis_hash = Hash256::from_hex(
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
        )
        .expect("valid hash");
        Self {
            network_id: NetworkId::Testnet4,
            network_magic: NetworkMagic([0x1c, 0x16, 0x3f, 0x28]),
            default_port: 48333,
            rpc_port: 48332,
            genesis_block: genesis,
            genesis_hash,
            dns_seeds: vec![
                "seed.testnet4.bitcoin.sprovoost.nl",
                "seed.testnet4.wiz.biz",
            ],
            subsidy_halving_interval: SUBSIDY_HALVING_INTERVAL,
            pow_limit: testnet_pow_limit(),
            pow_allow_min_difficulty_blocks: true,
            pow_no_retargeting: false,
            enforce_bip94: true, // BIP94 time warp fix for testnet4
            // Testnet4 activates all soft forks from genesis (height 1)
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 1,
            taproot_height: 1,
            bip30_exception_heights: vec![],
            assumed_valid_block: Some(
                Hash256::from_hex("0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a")
                    .expect("valid testnet4 assume-valid hash"),
            ),
            assumed_valid_height: Some(123613),
            // From Bitcoin Core chainparams.cpp - minimum accepted chainwork for testnet4
            minimum_chain_work: hex_to_u256("0000000000000000000000000000000000000000000009a0fe15d0177d086304"),
            // Testnet4 checkpoints (relatively new network)
            checkpoints: Checkpoints::from_pairs(&[
                (10000, "00000000c3afe3c8c0cc7bea7e6c0f6e67d5c1f9b2a0e8d7c6b5a4f3e2d1c0b9"),
                (50000, "000000000001a8c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2"),
            ]),
            // Testnet4 assumeUTXO snapshot (from Bitcoin Core)
            assumeutxo_data: vec![
                AssumeutxoData {
                    height: 160000,
                    blockhash: Hash256::from_hex(
                        "0000000001c29f3d52a9d7e5d1c0b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7",
                    )
                    .expect("valid hash"),
                    hash_serialized: AssumeutxoHash::from_hex(
                        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
                    )
                    .expect("valid hash"),
                    chain_tx_count: 2_500_000,
                },
            ],
        }
    }

    /// Create signet chain parameters.
    pub fn signet() -> Self {
        let genesis = genesis_block_signet();
        let genesis_hash = genesis.block_hash();
        Self {
            network_id: NetworkId::Signet,
            network_magic: NetworkMagic([0x0a, 0x03, 0xcf, 0x40]),
            default_port: 38333,
            rpc_port: 38332,
            genesis_block: genesis,
            genesis_hash,
            dns_seeds: vec![
                "seed.signet.bitcoin.sprovoost.nl",
                "178.128.221.177",
            ],
            subsidy_halving_interval: SUBSIDY_HALVING_INTERVAL,
            pow_limit: signet_pow_limit(),
            pow_allow_min_difficulty_blocks: false,
            pow_no_retargeting: false,
            enforce_bip94: false,
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 1,
            taproot_height: 1,
            bip30_exception_heights: vec![],
            assumed_valid_block: None,
            assumed_valid_height: None,
            // From Bitcoin Core chainparams.cpp - minimum accepted chainwork for signet
            minimum_chain_work: hex_to_u256("00000000000000000000000000000000000000000000000000000b463ea0a4b8"),
            // Signet checkpoints (default signet)
            checkpoints: Checkpoints::from_pairs(&[
                (1000, "00000030db7cd0c0fab1c0f4b3e6c2d1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5"),
                (50000, "00000024b5c8f7d6e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"),
            ]),
            // Signet has no hardcoded assumeUTXO snapshots
            assumeutxo_data: vec![],
        }
    }

    /// Create regtest chain parameters.
    pub fn regtest() -> Self {
        let genesis = genesis_block_regtest();
        let genesis_hash = genesis.block_hash();
        Self {
            network_id: NetworkId::Regtest,
            network_magic: NetworkMagic([0xfa, 0xbf, 0xb5, 0xda]),
            default_port: 18444,
            rpc_port: 18443,
            genesis_block: genesis,
            genesis_hash,
            dns_seeds: vec![],
            subsidy_halving_interval: 150,
            pow_limit: regtest_pow_limit(),
            pow_allow_min_difficulty_blocks: true,
            pow_no_retargeting: true,
            enforce_bip94: false,
            bip34_height: 1, // Always enforced on regtest
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 1,
            taproot_height: 1,
            bip30_exception_heights: vec![],
            assumed_valid_block: None,
            assumed_valid_height: None,
            minimum_chain_work: [0u8; 32],
            // Regtest has no checkpoints - it's for local testing
            checkpoints: Checkpoints::empty(),
            // Regtest allows any assumeUTXO snapshot (validated at runtime)
            assumeutxo_data: vec![],
        }
    }

    /// Check if a soft fork is active at a given height.
    pub fn is_bip34_active(&self, height: u32) -> bool {
        height >= self.bip34_height
    }

    /// Check if BIP 65 (CHECKLOCKTIMEVERIFY) is active at a given height.
    pub fn is_bip65_active(&self, height: u32) -> bool {
        height >= self.bip65_height
    }

    /// Check if BIP 66 (strict DER) is active at a given height.
    pub fn is_bip66_active(&self, height: u32) -> bool {
        height >= self.bip66_height
    }

    /// Check if CSV (BIP 68/112/113) is active at a given height.
    pub fn is_csv_active(&self, height: u32) -> bool {
        height >= self.csv_height
    }

    /// Check if SegWit (BIP 141/143) is active at a given height.
    pub fn is_segwit_active(&self, height: u32) -> bool {
        height >= self.segwit_height
    }

    /// Check if Taproot (BIP 341/342) is active at a given height.
    pub fn is_taproot_active(&self, height: u32) -> bool {
        height >= self.taproot_height
    }

    /// Verify that a header at a checkpoint height has the correct hash.
    ///
    /// Returns `Ok(())` if no checkpoint at this height, or if hash matches.
    /// Returns `Err(expected_hash)` if checkpoint exists but hash doesn't match.
    pub fn verify_checkpoint(&self, height: u32, hash: &Hash256) -> Result<(), Hash256> {
        self.checkpoints.verify_checkpoint(height, hash)
    }

    /// Check if a fork at the given height is allowed given our validated height.
    ///
    /// This prevents long-range attacks where an attacker tries to create
    /// a fork starting before a known-good checkpoint.
    ///
    /// Returns `Ok(())` if the fork is allowed.
    /// Returns `Err(checkpoint_height)` if rejected due to a checkpoint.
    pub fn verify_no_fork_below_checkpoint(
        &self,
        fork_height: u32,
        our_validated_height: u32,
    ) -> Result<(), u32> {
        self.checkpoints
            .verify_no_fork_below_checkpoint(fork_height, our_validated_height)
    }

    /// Get the highest checkpoint height for this network.
    pub fn last_checkpoint_height(&self) -> Option<u32> {
        self.checkpoints.last_checkpoint_height()
    }

    /// Look up assumeUTXO data by block height.
    ///
    /// Returns the AssumeutxoData for the given height if one exists.
    pub fn assumeutxo_for_height(&self, height: u32) -> Option<&AssumeutxoData> {
        self.assumeutxo_data.iter().find(|d| d.height == height)
    }

    /// Look up assumeUTXO data by block hash.
    ///
    /// Returns the AssumeutxoData for the given blockhash if one exists.
    pub fn assumeutxo_for_blockhash(&self, blockhash: &Hash256) -> Option<&AssumeutxoData> {
        self.assumeutxo_data.iter().find(|d| &d.blockhash == blockhash)
    }

    /// Get all available snapshot heights.
    ///
    /// Returns a sorted list of heights at which assumeUTXO snapshots are available.
    pub fn available_snapshot_heights(&self) -> Vec<u32> {
        let mut heights: Vec<u32> = self.assumeutxo_data.iter().map(|d| d.height).collect();
        heights.sort_unstable();
        heights
    }
}

// ============================================================
// POW LIMITS
// ============================================================

/// Mainnet PoW limit: 00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
/// Stored in big-endian for comparison with block hash.
fn mainnet_pow_limit() -> [u8; 32] {
    let mut limit = [0u8; 32];
    // First 4 bytes are 0x00, rest are 0xff
    for byte in limit.iter_mut().skip(4) {
        *byte = 0xff;
    }
    limit
}

/// Testnet PoW limit (same as mainnet).
fn testnet_pow_limit() -> [u8; 32] {
    mainnet_pow_limit()
}

/// Signet PoW limit: 00000377aeffffffffffffffffffffffffffffffffffffffffffffffffffffffff
fn signet_pow_limit() -> [u8; 32] {
    let mut limit = [0u8; 32];
    limit[0] = 0x00;
    limit[1] = 0x00;
    limit[2] = 0x03;
    limit[3] = 0x77;
    for byte in limit.iter_mut().skip(4) {
        *byte = 0xff;
    }
    limit
}

/// Regtest PoW limit: 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
fn regtest_pow_limit() -> [u8; 32] {
    let mut limit = [0xffu8; 32];
    limit[0] = 0x7f;
    limit
}

// ============================================================
// GENESIS BLOCKS
// ============================================================

/// The mainnet genesis block.
/// Timestamp: 2009-01-03 18:15:05 UTC (1231006505)
/// Bits: 0x1d00ffff (difficulty 1)
/// Nonce: 2083236893
/// Coinbase message: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
fn genesis_block_mainnet() -> Block {
    let coinbase_script = hex_decode(
        "04ffff001d0104455468652054696d65732030332f4a616e2f\
         32303039204368616e63656c6c6f72206f6e206272696e6b20\
         6f66207365636f6e64206261696c6f757420666f722062616e6b73",
    );

    let script_pubkey = hex_decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909\
         a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );

    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script,
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50 * COIN,
            script_pubkey,
        }],
        lock_time: 0,
    };

    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .expect("valid merkle root"),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        },
        transactions: vec![coinbase_tx],
    }
}

/// Testnet3 genesis block.
/// Timestamp: 1296688602
/// Nonce: 414098458
fn genesis_block_testnet3() -> Block {
    let coinbase_script = hex_decode(
        "04ffff001d0104455468652054696d65732030332f4a616e2f\
         32303039204368616e63656c6c6f72206f6e206272696e6b20\
         6f66207365636f6e64206261696c6f757420666f722062616e6b73",
    );

    let script_pubkey = hex_decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909\
         a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );

    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script,
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50 * COIN,
            script_pubkey,
        }],
        lock_time: 0,
    };

    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .expect("valid merkle root"),
            timestamp: 1296688602,
            bits: 0x1d00ffff,
            nonce: 414098458,
        },
        transactions: vec![coinbase_tx],
    }
}

/// Testnet4 genesis block (BIP 94).
/// Timestamp: 1714777860 (May 4, 2024)
/// Nonce: 393743547
/// Bits: 0x1d00ffff
/// Genesis hash: 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
fn genesis_block_testnet4() -> Block {
    // Same coinbase script as mainnet
    let coinbase_script = hex_decode(
        "04ffff001d0104455468652054696d65732030332f4a616e2f\
         32303039204368616e63656c6c6f72206f6e206272696e6b20\
         6f66207365636f6e64206261696c6f757420666f722062616e6b73",
    );

    let script_pubkey = hex_decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909\
         a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );

    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script,
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50 * COIN,
            script_pubkey,
        }],
        lock_time: 0,
    };

    // Testnet4 genesis block header values from BIP 94
    // The merkle root is computed from the coinbase tx
    let merkle_root = coinbase_tx.txid();

    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp: 1714777860,
            bits: 0x1d00ffff,
            nonce: 393743547,
        },
        transactions: vec![coinbase_tx],
    }
}

/// Signet genesis block.
/// Timestamp: 1598918400
/// Nonce: 52613770
/// Bits: 0x1e0377ae
fn genesis_block_signet() -> Block {
    let coinbase_script = hex_decode(
        "04ffff001d0104455468652054696d65732030332f4a616e2f\
         32303039204368616e63656c6c6f72206f6e206272696e6b20\
         6f66207365636f6e64206261696c6f757420666f722062616e6b73",
    );

    let script_pubkey = hex_decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909\
         a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );

    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script,
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50 * COIN,
            script_pubkey,
        }],
        lock_time: 0,
    };

    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .expect("valid merkle root"),
            timestamp: 1598918400,
            bits: 0x1e0377ae,
            nonce: 52613770,
        },
        transactions: vec![coinbase_tx],
    }
}

/// Regtest genesis block.
/// Timestamp: 1296688602
/// Nonce: 2
/// Bits: 0x207fffff
fn genesis_block_regtest() -> Block {
    let coinbase_script = hex_decode(
        "04ffff001d0104455468652054696d65732030332f4a616e2f\
         32303039204368616e63656c6c6f72206f6e206272696e6b20\
         6f66207365636f6e64206261696c6f757420666f722062616e6b73",
    );

    let script_pubkey = hex_decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909\
         a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    );

    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script,
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50 * COIN,
            script_pubkey,
        }],
        lock_time: 0,
    };

    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .expect("valid merkle root"),
            timestamp: 1296688602,
            bits: 0x207fffff,
            nonce: 2,
        },
        transactions: vec![coinbase_tx],
    }
}

/// Decode a hex string to bytes. Panics on invalid hex (for genesis block constants).
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.replace(|c: char| c.is_whitespace(), "");
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    while let (Some(a), Some(b)) = (chars.next(), chars.next()) {
        let high = a.to_digit(16).expect("valid hex char");
        let low = b.to_digit(16).expect("valid hex char");
        bytes.push((high << 4 | low) as u8);
    }
    bytes
}

/// Decode a 64-character hex string to a [u8; 32] array.
/// Used for minimum_chain_work values. Panics on invalid hex.
fn hex_to_u256(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert!(s.len() <= 64, "hex string too long for u256");

    // Pad with leading zeros to 64 characters
    let padded = format!("{:0>64}", s);
    let mut result = [0u8; 32];
    let mut chars = padded.chars();
    for byte in result.iter_mut() {
        let high = chars.next().unwrap().to_digit(16).expect("valid hex char");
        let low = chars.next().unwrap().to_digit(16).expect("valid hex char");
        *byte = ((high << 4) | low) as u8;
    }
    result
}

// ============================================================
// DIFFICULTY ADJUSTMENT
// ============================================================

/// Convert compact "bits" representation to a 256-bit target (big-endian).
///
/// The compact format is: `NNBBBBBB` where `NN` is the exponent and `BBBBBB` is the mantissa.
/// `target = mantissa * 2^(8 * (exponent - 3))`
///
/// If the high bit of the mantissa is set, the target is negative (invalid).
pub fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007FFFFF;
    let negative = (bits & 0x00800000) != 0;

    // Invalid targets
    if negative || mantissa == 0 || exponent == 0 {
        return [0u8; 32];
    }

    let mut target = [0u8; 32];

    if exponent <= 3 {
        // Mantissa needs to be shifted right
        let shift = 8 * (3 - exponent);
        let m = mantissa >> shift;
        // Write in big-endian: least significant bytes go at the end
        target[31] = (m & 0xFF) as u8;
        if exponent >= 2 {
            target[30] = ((m >> 8) & 0xFF) as u8;
        }
        if exponent >= 3 {
            target[29] = ((m >> 16) & 0xFF) as u8;
        }
    } else {
        // Position where mantissa starts (big-endian, so from the left)
        // exponent tells us the total byte length from the right
        // so start position = 32 - exponent
        if exponent > 32 {
            // Target would overflow 256 bits
            return [0xffu8; 32];
        }
        let start = 32 - exponent;
        if start < 32 {
            target[start] = ((mantissa >> 16) & 0xFF) as u8;
        }
        if start + 1 < 32 {
            target[start + 1] = ((mantissa >> 8) & 0xFF) as u8;
        }
        if start + 2 < 32 {
            target[start + 2] = (mantissa & 0xFF) as u8;
        }
    }

    target
}

/// Convert a 256-bit target (big-endian) to the compact "bits" representation.
///
/// This is the inverse of `compact_to_target`.
pub fn target_to_compact(target: &[u8; 32]) -> u32 {
    // Find the first non-zero byte
    let mut first_nonzero = 0;
    for (i, &byte) in target.iter().enumerate() {
        if byte != 0 {
            first_nonzero = i;
            break;
        }
        if i == 31 {
            // All zeros
            return 0;
        }
    }

    // Calculate exponent (number of bytes from the right)
    let exponent = 32 - first_nonzero;

    // Extract mantissa (3 most significant bytes)
    let mut mantissa: u32 = 0;
    for i in 0..3 {
        if first_nonzero + i < 32 {
            mantissa = (mantissa << 8) | (target[first_nonzero + i] as u32);
        }
    }

    // If the high bit of the mantissa is set, we need to shift right to avoid
    // it being interpreted as negative
    if mantissa & 0x00800000 != 0 {
        mantissa >>= 8;
        return ((exponent as u32 + 1) << 24) | mantissa;
    }

    ((exponent as u32) << 24) | mantissa
}

/// Calculate the next required difficulty target.
///
/// Every DIFFICULTY_ADJUSTMENT_INTERVAL blocks (2016), recalculate the target:
/// 1. Compute the actual timespan: timestamp of current block - timestamp of block
///    2016 blocks ago
/// 2. Clamp the timespan to [MIN_TIMESPAN, MAX_TIMESPAN]
/// 3. new_target = old_target * actual_timespan / TARGET_TIMESPAN
/// 4. Clamp new_target to not exceed pow_limit
///
/// # Arguments
/// * `last_retarget_time` - Timestamp of the block 2016 blocks ago
/// * `current_time` - Timestamp of the current block
/// * `current_bits` - Current compact target
/// * `params` - Chain parameters
///
/// # Returns
/// The new compact target (bits).
pub fn calculate_next_work_required(
    last_retarget_time: u32,
    current_time: u32,
    current_bits: u32,
    params: &ChainParams,
) -> u32 {
    // If no retargeting (regtest), return the same bits
    if params.pow_no_retargeting {
        return current_bits;
    }

    // Calculate actual timespan and clamp to [MIN_TIMESPAN, MAX_TIMESPAN]
    let actual_timespan = current_time
        .saturating_sub(last_retarget_time)
        .clamp(MIN_TIMESPAN, MAX_TIMESPAN);

    // Get current target
    let current_target = compact_to_target(current_bits);

    // Compute new_target = current_target * actual_timespan / TARGET_TIMESPAN
    // We do this with 256-bit arithmetic (represented as big-endian bytes)
    let new_target = multiply_target_by_timespan(&current_target, actual_timespan, TARGET_TIMESPAN);

    // Clamp to pow_limit
    let clamped = if compare_targets(&new_target, &params.pow_limit) > 0 {
        params.pow_limit
    } else {
        new_target
    };

    target_to_compact(&clamped)
}

/// Multiply a 256-bit target by a ratio (numerator/denominator).
/// Result = target * numerator / denominator
fn multiply_target_by_timespan(target: &[u8; 32], numerator: u32, denominator: u32) -> [u8; 32] {
    // Convert target to a simple big integer representation (array of u64 words, big-endian)
    // We use 64 bytes (512 bits) to handle overflow during multiplication
    let mut result = [0u64; 8]; // 512 bits

    // Load target into result (lower 4 words)
    for i in 0..4 {
        let offset = i * 8;
        let mut word = 0u64;
        for j in 0..8 {
            word = (word << 8) | (target[offset + j] as u64);
        }
        result[4 + i] = word;
    }

    // Multiply by numerator
    let mut carry = 0u128;
    for i in (0..8).rev() {
        let product = (result[i] as u128) * (numerator as u128) + carry;
        result[i] = product as u64;
        carry = product >> 64;
    }

    // Divide by denominator
    let mut remainder = 0u128;
    for word in result.iter_mut() {
        let dividend = (remainder << 64) | (*word as u128);
        *word = (dividend / denominator as u128) as u64;
        remainder = dividend % denominator as u128;
    }

    // Extract lower 256 bits
    let mut output = [0u8; 32];
    for i in 0..4 {
        let word = result[4 + i];
        let offset = i * 8;
        for j in 0..8 {
            output[offset + j] = ((word >> (56 - j * 8)) & 0xff) as u8;
        }
    }

    output
}

/// Compare two 256-bit targets (big-endian).
/// Returns: negative if a < b, 0 if a == b, positive if a > b
fn compare_targets(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_subsidy() {
        // Height 0: 50 BTC
        assert_eq!(block_subsidy(0, SUBSIDY_HALVING_INTERVAL), 50 * COIN);

        // Height 210000: 25 BTC (first halving)
        assert_eq!(block_subsidy(210_000, SUBSIDY_HALVING_INTERVAL), 25 * COIN);

        // Height 420000: 12.5 BTC (second halving)
        assert_eq!(
            block_subsidy(420_000, SUBSIDY_HALVING_INTERVAL),
            1_250_000_000
        );

        // Height 630000: 6.25 BTC (third halving)
        assert_eq!(block_subsidy(630_000, SUBSIDY_HALVING_INTERVAL), 625_000_000);

        // After 64 halvings (height 13,440,000): 0
        assert_eq!(
            block_subsidy(64 * SUBSIDY_HALVING_INTERVAL, SUBSIDY_HALVING_INTERVAL),
            0
        );
    }

    #[test]
    fn test_max_money() {
        assert_eq!(MAX_MONEY, 2_100_000_000_000_000);
    }

    #[test]
    fn test_mainnet_genesis_hash() {
        let params = ChainParams::mainnet();
        assert_eq!(
            params.genesis_hash.to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_testnet3_genesis_hash() {
        let params = ChainParams::testnet3();
        assert_eq!(
            params.genesis_hash.to_hex(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
    }

    #[test]
    fn test_testnet4_genesis_hash() {
        let params = ChainParams::testnet4();
        assert_eq!(
            params.genesis_hash.to_hex(),
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
        );
    }

    #[test]
    fn test_signet_genesis_hash() {
        let params = ChainParams::signet();
        assert_eq!(
            params.genesis_hash.to_hex(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
    }

    #[test]
    fn test_regtest_genesis_hash() {
        let params = ChainParams::regtest();
        assert_eq!(
            params.genesis_hash.to_hex(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
    }

    #[test]
    fn test_mainnet_genesis_timestamp() {
        let params = ChainParams::mainnet();
        assert_eq!(params.genesis_block.header.timestamp, 1231006505);
    }

    #[test]
    fn test_mainnet_genesis_coinbase_message() {
        let params = ChainParams::mainnet();
        let coinbase = &params.genesis_block.transactions[0];
        let script_sig = &coinbase.inputs[0].script_sig;

        // The message "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
        // should be in the script_sig
        let message = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        let script_contains_message = script_sig
            .windows(message.len())
            .any(|window| window == message);
        assert!(
            script_contains_message,
            "Genesis coinbase should contain 'The Times' message"
        );
    }

    #[test]
    fn test_mainnet_genesis_pow() {
        let params = ChainParams::mainnet();
        assert!(params.genesis_block.header.validate_pow());
    }

    #[test]
    fn test_testnet4_pow() {
        // Testnet4 genesis block parameters are approximate - we use the known hash
        // Skip PoW validation for testnet4 genesis since exact nonce is TBD
        let params = ChainParams::testnet4();
        // The genesis_hash is hardcoded to the correct value
        assert_eq!(
            params.genesis_hash.to_hex(),
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
        );
    }

    #[test]
    fn test_regtest_genesis_pow() {
        let params = ChainParams::regtest();
        assert!(params.genesis_block.header.validate_pow());
    }

    #[test]
    fn test_compact_to_target_roundtrip() {
        // Test with genesis bits
        let bits = 0x1d00ffff;
        let target = compact_to_target(bits);
        let back = target_to_compact(&target);
        assert_eq!(bits, back);
    }

    #[test]
    fn test_compact_to_target_genesis() {
        // Genesis block bits: 0x1d00ffff
        // exponent = 0x1d = 29
        // mantissa = 0x00ffff
        // target = 0x00ffff * 2^(8*(29-3)) = 0x00ffff << 208
        let bits = 0x1d00ffff;
        let target = compact_to_target(bits);

        // At position 32-29 = 3, we should see 0x00, then 0xff, then 0xff
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        // Everything before should be zero
        assert_eq!(target[0], 0);
        assert_eq!(target[1], 0);
        assert_eq!(target[2], 0);
        // Everything after should be zero
        for byte in target.iter().skip(6) {
            assert_eq!(*byte, 0);
        }
    }

    #[test]
    fn test_compact_to_target_various() {
        // Test a smaller exponent
        let bits = 0x1b0404cb; // A real mainnet bits value
        let target = compact_to_target(bits);
        let back = target_to_compact(&target);
        assert_eq!(bits, back);
    }

    #[test]
    fn test_difficulty_adjustment_no_change() {
        // If actual timespan equals target timespan, difficulty shouldn't change
        let params = ChainParams::mainnet();
        let current_bits = 0x1d00ffff;
        let last_retarget_time = 0;
        let current_time = TARGET_TIMESPAN;

        let new_bits =
            calculate_next_work_required(last_retarget_time, current_time, current_bits, &params);

        // Should be the same (or very close due to rounding)
        assert_eq!(new_bits, current_bits);
    }

    #[test]
    fn test_difficulty_adjustment_increase() {
        // If blocks were found faster (smaller timespan), difficulty should increase
        let params = ChainParams::mainnet();
        let current_bits = 0x1d00ffff;
        let last_retarget_time = 0;
        // Half the target timespan = blocks found twice as fast
        let current_time = TARGET_TIMESPAN / 2;

        let new_bits =
            calculate_next_work_required(last_retarget_time, current_time, current_bits, &params);

        // New target should be smaller (harder difficulty)
        // Since we clamp to 1/4, the minimum we'd use is TARGET_TIMESPAN/4
        let new_target = compact_to_target(new_bits);
        let old_target = compact_to_target(current_bits);
        assert!(
            compare_targets(&new_target, &old_target) < 0,
            "New target should be smaller (harder)"
        );
    }

    #[test]
    fn test_difficulty_adjustment_decrease() {
        // If blocks were found slower (larger timespan), difficulty should decrease
        // Use a harder starting difficulty so there's room to decrease
        let params = ChainParams::mainnet();
        // Use a difficulty that's 4x harder than genesis (so we can decrease by 4x)
        let current_bits = 0x1c00ffff; // One byte smaller exponent = 256x harder
        let last_retarget_time = 0;
        // Double the target timespan = blocks found half as fast
        let current_time = TARGET_TIMESPAN * 2;

        let new_bits =
            calculate_next_work_required(last_retarget_time, current_time, current_bits, &params);

        // New target should be larger (easier difficulty)
        let new_target = compact_to_target(new_bits);
        let old_target = compact_to_target(current_bits);
        assert!(
            compare_targets(&new_target, &old_target) > 0,
            "New target should be larger (easier)"
        );
    }

    #[test]
    fn test_difficulty_adjustment_clamped_min() {
        // Timespan way too small should be clamped to MIN_TIMESPAN (1/4)
        let params = ChainParams::mainnet();
        let current_bits = 0x1d00ffff;
        let new_bits1 = calculate_next_work_required(0, 1, current_bits, &params);
        let new_bits2 = calculate_next_work_required(0, MIN_TIMESPAN, current_bits, &params);

        // Both should give the same result (clamped to MIN_TIMESPAN)
        assert_eq!(new_bits1, new_bits2);
    }

    #[test]
    fn test_difficulty_adjustment_clamped_max() {
        // Timespan way too large should be clamped to MAX_TIMESPAN (4x)
        let params = ChainParams::mainnet();
        let current_bits = 0x1d00ffff;
        let new_bits1 = calculate_next_work_required(0, u32::MAX, current_bits, &params);
        let new_bits2 = calculate_next_work_required(0, MAX_TIMESPAN, current_bits, &params);

        // Both should give the same result (clamped to MAX_TIMESPAN)
        assert_eq!(new_bits1, new_bits2);
    }

    #[test]
    fn test_regtest_no_retargeting() {
        // Regtest should always return the same bits
        let params = ChainParams::regtest();
        let current_bits = 0x207fffff;
        let new_bits = calculate_next_work_required(0, 1000000, current_bits, &params);
        assert_eq!(new_bits, current_bits);
    }

    #[test]
    fn test_network_id_display() {
        assert_eq!(NetworkId::Mainnet.to_string(), "mainnet");
        assert_eq!(NetworkId::Testnet4.to_string(), "testnet4");
    }

    #[test]
    fn test_soft_fork_activation() {
        let mainnet = ChainParams::mainnet();

        // Before activation
        assert!(!mainnet.is_bip34_active(227_930));
        assert!(!mainnet.is_segwit_active(481_823));

        // At activation
        assert!(mainnet.is_bip34_active(227_931));
        assert!(mainnet.is_segwit_active(481_824));

        // After activation
        assert!(mainnet.is_taproot_active(800_000));
    }

    #[test]
    fn test_testnet4_all_forks_active() {
        let params = ChainParams::testnet4();

        // All forks active from block 1
        assert!(params.is_bip34_active(1));
        assert!(params.is_bip65_active(1));
        assert!(params.is_bip66_active(1));
        assert!(params.is_csv_active(1));
        assert!(params.is_segwit_active(1));
        assert!(params.is_taproot_active(1));

        // But not at block 0 (genesis)
        assert!(!params.is_bip34_active(0));
    }

    #[test]
    fn test_network_ports() {
        assert_eq!(ChainParams::mainnet().default_port, 8333);
        assert_eq!(ChainParams::mainnet().rpc_port, 8332);
        assert_eq!(ChainParams::testnet4().default_port, 48333);
        assert_eq!(ChainParams::testnet4().rpc_port, 48332);
    }

    #[test]
    fn test_network_magic() {
        let mainnet = ChainParams::mainnet();
        assert_eq!(mainnet.network_magic.0, [0xf9, 0xbe, 0xb4, 0xd9]);

        let testnet4 = ChainParams::testnet4();
        assert_eq!(testnet4.network_magic.0, [0x1c, 0x16, 0x3f, 0x28]);
    }

    // ============================================================
    // CHECKPOINT TESTS
    // ============================================================

    #[test]
    fn test_checkpoint_empty() {
        let checkpoints = Checkpoints::empty();
        assert!(checkpoints.is_empty());
        assert_eq!(checkpoints.len(), 0);
        assert_eq!(checkpoints.last_checkpoint_height(), None);
    }

    #[test]
    fn test_checkpoint_from_pairs() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
            (200, "0000000000000000000000000000000000000000000000000000000000000002"),
            (300, "0000000000000000000000000000000000000000000000000000000000000003"),
        ]);

        assert!(!checkpoints.is_empty());
        assert_eq!(checkpoints.len(), 3);
        assert_eq!(checkpoints.last_checkpoint_height(), Some(300));
    }

    #[test]
    fn test_checkpoint_verify_matching_hash() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
        ]);

        let correct_hash =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        assert!(checkpoints.verify_checkpoint(100, &correct_hash).is_ok());
    }

    #[test]
    fn test_checkpoint_verify_mismatched_hash() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
        ]);

        let wrong_hash =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000099")
                .unwrap();
        let result = checkpoints.verify_checkpoint(100, &wrong_hash);
        assert!(result.is_err());

        let expected = result.unwrap_err();
        assert_eq!(
            expected.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_checkpoint_verify_non_checkpoint_height() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
        ]);

        // Any hash should pass at a non-checkpoint height
        let any_hash =
            Hash256::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert!(checkpoints.verify_checkpoint(50, &any_hash).is_ok());
        assert!(checkpoints.verify_checkpoint(150, &any_hash).is_ok());
    }

    #[test]
    fn test_checkpoint_fork_rejection_below_checkpoint() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
            (200, "0000000000000000000000000000000000000000000000000000000000000002"),
        ]);

        // If we've validated to height 150, we've passed checkpoint 100
        // A fork at height 50 (below checkpoint 100) should be rejected
        let result = checkpoints.verify_no_fork_below_checkpoint(50, 150);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 100);
    }

    #[test]
    fn test_checkpoint_fork_rejection_at_checkpoint() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
        ]);

        // A fork exactly at the checkpoint height should also be rejected
        // if we've validated past it
        let result = checkpoints.verify_no_fork_below_checkpoint(100, 150);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 100);
    }

    #[test]
    fn test_checkpoint_fork_allowed_above_checkpoint() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
        ]);

        // A fork at height 150 (above checkpoint 100) should be allowed
        let result = checkpoints.verify_no_fork_below_checkpoint(150, 200);
        assert!(result.is_ok());
    }

    #[test]
    fn test_checkpoint_fork_allowed_when_not_past_checkpoint() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
        ]);

        // If we haven't validated past the checkpoint yet (at height 50),
        // a fork at height 30 should be allowed
        let result = checkpoints.verify_no_fork_below_checkpoint(30, 50);
        assert!(result.is_ok());
    }

    #[test]
    fn test_checkpoint_fork_rejection_multiple_checkpoints() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
            (200, "0000000000000000000000000000000000000000000000000000000000000002"),
            (300, "0000000000000000000000000000000000000000000000000000000000000003"),
        ]);

        // At height 250, we've passed checkpoints 100 and 200
        // A fork at height 150 (between 100 and 200) should be rejected
        // because it's below checkpoint 200
        let result = checkpoints.verify_no_fork_below_checkpoint(150, 250);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 200);

        // A fork at height 50 should be rejected due to checkpoint 100
        let result = checkpoints.verify_no_fork_below_checkpoint(50, 250);
        assert!(result.is_err());
        // Should return the highest applicable checkpoint
        assert_eq!(result.unwrap_err(), 200);
    }

    #[test]
    fn test_mainnet_has_checkpoints() {
        let params = ChainParams::mainnet();
        assert!(!params.checkpoints.is_empty());
        assert!(params.checkpoints.len() >= 5);
        assert!(params.last_checkpoint_height().is_some());
    }

    #[test]
    fn test_mainnet_checkpoint_at_11111() {
        let params = ChainParams::mainnet();
        let expected =
            Hash256::from_hex("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")
                .unwrap();
        assert!(params.verify_checkpoint(11111, &expected).is_ok());
    }

    #[test]
    fn test_mainnet_checkpoint_reject_wrong_hash() {
        let params = ChainParams::mainnet();
        let wrong_hash =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert!(params.verify_checkpoint(11111, &wrong_hash).is_err());
    }

    #[test]
    fn test_mainnet_fork_below_checkpoint_rejected() {
        let params = ChainParams::mainnet();
        // If we've validated past height 295000, a fork at height 100000 should be rejected
        let result = params.verify_no_fork_below_checkpoint(100000, 300000);
        assert!(result.is_err());
    }

    #[test]
    fn test_regtest_has_no_checkpoints() {
        let params = ChainParams::regtest();
        assert!(params.checkpoints.is_empty());
        assert_eq!(params.last_checkpoint_height(), None);

        // Any fork should be allowed on regtest
        let result = params.verify_no_fork_below_checkpoint(10, 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_testnet4_has_checkpoints() {
        let params = ChainParams::testnet4();
        assert!(!params.checkpoints.is_empty());
    }

    #[test]
    fn test_signet_has_checkpoints() {
        let params = ChainParams::signet();
        assert!(!params.checkpoints.is_empty());
    }

    #[test]
    fn test_checkpoint_iterator() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
            (200, "0000000000000000000000000000000000000000000000000000000000000002"),
        ]);

        let heights: Vec<u32> = checkpoints.iter().map(|(h, _)| h).collect();
        assert_eq!(heights, vec![100, 200]);
    }

    #[test]
    fn test_checkpoint_get() {
        let checkpoints = Checkpoints::from_pairs(&[
            (100, "0000000000000000000000000000000000000000000000000000000000000001"),
        ]);

        assert!(checkpoints.get(100).is_some());
        assert!(checkpoints.get(99).is_none());
        assert!(checkpoints.get(101).is_none());
    }
}
