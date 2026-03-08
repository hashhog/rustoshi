//! Bitcoin address types and encoding.
//!
//! Supports all major Bitcoin address formats:
//! - P2PKH: Legacy pay-to-public-key-hash (Base58Check, starts with '1' or 'm'/'n')
//! - P2SH: Pay-to-script-hash (Base58Check, starts with '3' or '2')
//! - P2WPKH: SegWit v0 pay-to-witness-public-key-hash (Bech32, starts with 'bc1q' or 'tb1q')
//! - P2WSH: SegWit v0 pay-to-witness-script-hash (Bech32, starts with 'bc1q' or 'tb1q')
//! - P2TR: Taproot pay-to-taproot (Bech32m, starts with 'bc1p' or 'tb1p')

use rustoshi_primitives::{Hash160, Hash256};

use crate::base58::{base58check_decode, base58check_encode, Base58Error};
use crate::bech32::{decode_segwit_address, encode_segwit_address, Bech32Error};
use crate::hashes::hash160;

/// Bitcoin network type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin mainnet.
    Mainnet,
    /// Bitcoin testnet (testnet3, testnet4, signet all use same address format).
    Testnet,
    /// Bitcoin regtest (local testing).
    Regtest,
}

impl Network {
    /// Get the Base58Check version byte for P2PKH addresses.
    pub fn p2pkh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Regtest => 0x6F,
        }
    }

    /// Get the Base58Check version byte for P2SH addresses.
    pub fn p2sh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet | Network::Regtest => 0xC4,
        }
    }

    /// Get the Bech32 human-readable part (HRP).
    pub fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
            Network::Regtest => "bcrt",
        }
    }

    /// Determine network from a Base58Check version byte.
    fn from_version_byte(version: u8) -> Option<(Self, bool)> {
        // Returns (network, is_p2sh)
        match version {
            0x00 => Some((Network::Mainnet, false)), // mainnet P2PKH
            0x05 => Some((Network::Mainnet, true)),  // mainnet P2SH
            0x6F => Some((Network::Testnet, false)), // testnet P2PKH (also regtest)
            0xC4 => Some((Network::Testnet, true)),  // testnet P2SH (also regtest)
            _ => None,
        }
    }

    /// Determine network from a Bech32 HRP.
    fn from_hrp(hrp: &str) -> Option<Self> {
        match hrp {
            "bc" => Some(Network::Mainnet),
            "tb" => Some(Network::Testnet),
            "bcrt" => Some(Network::Regtest),
            _ => None,
        }
    }
}

/// A Bitcoin address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// Pay-to-Public-Key-Hash (legacy).
    P2PKH {
        /// The HASH160 of the public key.
        hash: Hash160,
        /// The network this address is for.
        network: Network,
    },
    /// Pay-to-Script-Hash.
    P2SH {
        /// The HASH160 of the redeem script.
        hash: Hash160,
        /// The network this address is for.
        network: Network,
    },
    /// Pay-to-Witness-Public-Key-Hash (SegWit v0).
    P2WPKH {
        /// The HASH160 of the public key.
        hash: Hash160,
        /// The network this address is for.
        network: Network,
    },
    /// Pay-to-Witness-Script-Hash (SegWit v0).
    P2WSH {
        /// The SHA256 of the witness script.
        hash: Hash256,
        /// The network this address is for.
        network: Network,
    },
    /// Pay-to-Taproot (SegWit v1).
    P2TR {
        /// The 32-byte x-only public key (tweaked).
        output_key: [u8; 32],
        /// The network this address is for.
        network: Network,
    },
}

/// Error type for address parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// Base58 decoding error.
    #[error("base58 error: {0}")]
    Base58(#[from] Base58Error),
    /// Bech32 decoding error.
    #[error("bech32 error: {0}")]
    Bech32(#[from] Bech32Error),
    /// Invalid address length.
    #[error("invalid address length: {0}")]
    InvalidLength(usize),
    /// Unknown version byte.
    #[error("unknown version byte: {0}")]
    UnknownVersion(u8),
    /// Network mismatch.
    #[error("network mismatch: expected {expected:?}, got {got:?}")]
    NetworkMismatch { expected: Network, got: Network },
    /// Invalid witness version for address type.
    #[error("invalid witness version: {0}")]
    InvalidWitnessVersion(u8),
    /// Empty input.
    #[error("empty address string")]
    EmptyInput,
}

impl Address {
    /// Encode the address to its string representation.
    pub fn encode(&self) -> String {
        match self {
            Address::P2PKH { hash, network } => {
                let mut payload = vec![network.p2pkh_version()];
                payload.extend_from_slice(&hash.0);
                base58check_encode(&payload)
            }
            Address::P2SH { hash, network } => {
                let mut payload = vec![network.p2sh_version()];
                payload.extend_from_slice(&hash.0);
                base58check_encode(&payload)
            }
            Address::P2WPKH { hash, network } => {
                encode_segwit_address(network.bech32_hrp(), 0, &hash.0)
                    .expect("P2WPKH encoding should never fail")
            }
            Address::P2WSH { hash, network } => {
                encode_segwit_address(network.bech32_hrp(), 0, &hash.0)
                    .expect("P2WSH encoding should never fail")
            }
            Address::P2TR {
                output_key,
                network,
            } => encode_segwit_address(network.bech32_hrp(), 1, output_key)
                .expect("P2TR encoding should never fail"),
        }
    }

    /// Parse an address from its string representation.
    ///
    /// If `expected_network` is provided, the address must match that network.
    pub fn from_string(s: &str, expected_network: Option<Network>) -> Result<Self, AddressError> {
        if s.is_empty() {
            return Err(AddressError::EmptyInput);
        }

        // Try Bech32/Bech32m first (if it starts with a known HRP)
        let lower = s.to_ascii_lowercase();
        if lower.starts_with("bc1")
            || lower.starts_with("tb1")
            || lower.starts_with("bcrt1")
        {
            return Self::parse_segwit(s, expected_network);
        }

        // Otherwise try Base58Check
        Self::parse_base58(s, expected_network)
    }

    /// Parse a Base58Check address.
    fn parse_base58(s: &str, expected_network: Option<Network>) -> Result<Self, AddressError> {
        let data = base58check_decode(s)?;

        if data.len() != 21 {
            return Err(AddressError::InvalidLength(data.len()));
        }

        let version = data[0];
        let (network, is_p2sh) =
            Network::from_version_byte(version).ok_or(AddressError::UnknownVersion(version))?;

        // Check network if expected
        if let Some(expected) = expected_network {
            // Regtest and Testnet use the same version bytes
            let matches = match (expected, network) {
                (Network::Regtest, Network::Testnet) => true,
                (Network::Testnet, Network::Regtest) => true,
                (a, b) => a == b,
            };
            if !matches {
                return Err(AddressError::NetworkMismatch {
                    expected,
                    got: network,
                });
            }
        }

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&data[1..21]);
        let hash = Hash160::from_bytes(hash_bytes);

        if is_p2sh {
            Ok(Address::P2SH { hash, network })
        } else {
            Ok(Address::P2PKH { hash, network })
        }
    }

    /// Parse a SegWit (Bech32/Bech32m) address.
    fn parse_segwit(s: &str, expected_network: Option<Network>) -> Result<Self, AddressError> {
        let (hrp, version, program) = decode_segwit_address(s)?;

        let network = Network::from_hrp(&hrp)
            .ok_or(Bech32Error::InvalidHrp)?;

        // Check network if expected
        if let Some(expected) = expected_network {
            if expected != network {
                return Err(AddressError::NetworkMismatch {
                    expected,
                    got: network,
                });
            }
        }

        match version {
            0 => {
                // SegWit v0: P2WPKH (20 bytes) or P2WSH (32 bytes)
                match program.len() {
                    20 => {
                        let mut hash_bytes = [0u8; 20];
                        hash_bytes.copy_from_slice(&program);
                        Ok(Address::P2WPKH {
                            hash: Hash160::from_bytes(hash_bytes),
                            network,
                        })
                    }
                    32 => {
                        let mut hash_bytes = [0u8; 32];
                        hash_bytes.copy_from_slice(&program);
                        Ok(Address::P2WSH {
                            hash: Hash256::from_bytes(hash_bytes),
                            network,
                        })
                    }
                    len => Err(AddressError::InvalidLength(len)),
                }
            }
            1 => {
                // SegWit v1: P2TR (32 bytes)
                if program.len() != 32 {
                    return Err(AddressError::InvalidLength(program.len()));
                }
                let mut output_key = [0u8; 32];
                output_key.copy_from_slice(&program);
                Ok(Address::P2TR {
                    output_key,
                    network,
                })
            }
            v => Err(AddressError::InvalidWitnessVersion(v)),
        }
    }

    /// Derive a P2PKH address from a compressed public key.
    pub fn p2pkh_from_pubkey(pubkey: &[u8; 33], network: Network) -> Self {
        Address::P2PKH {
            hash: hash160(pubkey),
            network,
        }
    }

    /// Derive a P2WPKH address from a compressed public key.
    pub fn p2wpkh_from_pubkey(pubkey: &[u8; 33], network: Network) -> Self {
        Address::P2WPKH {
            hash: hash160(pubkey),
            network,
        }
    }

    /// Get the network for this address.
    pub fn network(&self) -> Network {
        match self {
            Address::P2PKH { network, .. }
            | Address::P2SH { network, .. }
            | Address::P2WPKH { network, .. }
            | Address::P2WSH { network, .. }
            | Address::P2TR { network, .. } => *network,
        }
    }

    /// Get the scriptPubKey for this address.
    ///
    /// This is the script that must be satisfied to spend funds sent to this address.
    pub fn to_script_pubkey(&self) -> Vec<u8> {
        match self {
            Address::P2PKH { hash, .. } => {
                // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                let mut script = vec![0x76, 0xa9, 0x14];
                script.extend_from_slice(&hash.0);
                script.extend_from_slice(&[0x88, 0xac]);
                script
            }
            Address::P2SH { hash, .. } => {
                // OP_HASH160 <20 bytes> OP_EQUAL
                let mut script = vec![0xa9, 0x14];
                script.extend_from_slice(&hash.0);
                script.push(0x87);
                script
            }
            Address::P2WPKH { hash, .. } => {
                // OP_0 <20 bytes>
                let mut script = vec![0x00, 0x14];
                script.extend_from_slice(&hash.0);
                script
            }
            Address::P2WSH { hash, .. } => {
                // OP_0 <32 bytes>
                let mut script = vec![0x00, 0x20];
                script.extend_from_slice(&hash.0);
                script
            }
            Address::P2TR { output_key, .. } => {
                // OP_1 <32 bytes>
                let mut script = vec![0x51, 0x20];
                script.extend_from_slice(output_key);
                script
            }
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satoshi_address() {
        // Satoshi's genesis block address
        let hash = Hash160::from_hex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let addr = Address::P2PKH {
            hash,
            network: Network::Mainnet,
        };

        assert_eq!(addr.to_string(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

        // Round-trip
        let parsed = Address::from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn p2sh_address() {
        // Known P2SH address
        let hash = Hash160::from_hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        let addr = Address::P2SH {
            hash,
            network: Network::Mainnet,
        };

        assert_eq!(addr.to_string(), "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");

        // Round-trip
        let parsed = Address::from_string("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", None).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn p2wpkh_address() {
        // Known P2WPKH address
        let hash = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = Address::P2WPKH {
            hash,
            network: Network::Mainnet,
        };

        assert_eq!(addr.to_string(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

        // Round-trip
        let parsed =
            Address::from_string("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", None).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn p2wsh_address() {
        // Known P2WSH address
        let hash = Hash256::from_bytes(
            hex::decode("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let addr = Address::P2WSH {
            hash,
            network: Network::Mainnet,
        };

        assert_eq!(
            addr.to_string(),
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        );

        // Round-trip
        let parsed = Address::from_string(
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            None,
        )
        .unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn p2tr_address() {
        // P2TR address with output key a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
        let output_key: [u8; 32] =
            hex::decode("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
                .unwrap()
                .try_into()
                .unwrap();
        let addr = Address::P2TR {
            output_key,
            network: Network::Mainnet,
        };

        assert_eq!(
            addr.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );

        // Round-trip
        let parsed = Address::from_string(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            None,
        )
        .unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn testnet_p2pkh() {
        let hash = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = Address::P2PKH {
            hash,
            network: Network::Testnet,
        };

        // Testnet P2PKH starts with 'm' or 'n'
        let encoded = addr.to_string();
        assert!(encoded.starts_with('m') || encoded.starts_with('n'));

        // Round-trip
        let parsed = Address::from_string(&encoded, Some(Network::Testnet)).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn testnet_p2sh() {
        let hash = Hash160::from_hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        let addr = Address::P2SH {
            hash,
            network: Network::Testnet,
        };

        // Testnet P2SH starts with '2'
        let encoded = addr.to_string();
        assert!(encoded.starts_with('2'));

        // Round-trip
        let parsed = Address::from_string(&encoded, Some(Network::Testnet)).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn testnet_segwit() {
        let hash = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = Address::P2WPKH {
            hash,
            network: Network::Testnet,
        };

        // Testnet Bech32 starts with 'tb1'
        let encoded = addr.to_string();
        assert!(encoded.starts_with("tb1q"));

        // Round-trip
        let parsed = Address::from_string(&encoded, Some(Network::Testnet)).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn regtest_segwit() {
        let hash = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = Address::P2WPKH {
            hash,
            network: Network::Regtest,
        };

        // Regtest Bech32 starts with 'bcrt1'
        let encoded = addr.to_string();
        assert!(encoded.starts_with("bcrt1q"));

        // Round-trip
        let parsed = Address::from_string(&encoded, Some(Network::Regtest)).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn p2pkh_from_pubkey() {
        // Generator point compressed public key
        let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey: [u8; 33] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();

        let addr = Address::p2pkh_from_pubkey(&pubkey, Network::Mainnet);

        // The hash160 should be 751e76e8199196d454941c45d1b3a323f1433bd6
        if let Address::P2PKH { hash, network } = &addr {
            assert_eq!(hash.to_hex(), "751e76e8199196d454941c45d1b3a323f1433bd6");
            assert_eq!(*network, Network::Mainnet);
        } else {
            panic!("Expected P2PKH address");
        }
    }

    #[test]
    fn p2wpkh_from_pubkey() {
        // Generator point compressed public key
        let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey: [u8; 33] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();

        let addr = Address::p2wpkh_from_pubkey(&pubkey, Network::Mainnet);

        assert_eq!(addr.to_string(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn script_pubkey_p2pkh() {
        let hash = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = Address::P2PKH {
            hash,
            network: Network::Mainnet,
        };

        let script = addr.to_script_pubkey();
        assert_eq!(
            hex::encode(&script),
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        );
    }

    #[test]
    fn script_pubkey_p2sh() {
        let hash = Hash160::from_hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        let addr = Address::P2SH {
            hash,
            network: Network::Mainnet,
        };

        let script = addr.to_script_pubkey();
        assert_eq!(
            hex::encode(&script),
            "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87"
        );
    }

    #[test]
    fn script_pubkey_p2wpkh() {
        let hash = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = Address::P2WPKH {
            hash,
            network: Network::Mainnet,
        };

        let script = addr.to_script_pubkey();
        assert_eq!(
            hex::encode(&script),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn script_pubkey_p2wsh() {
        let hash = Hash256::from_bytes(
            hex::decode("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let addr = Address::P2WSH {
            hash,
            network: Network::Mainnet,
        };

        let script = addr.to_script_pubkey();
        assert_eq!(
            hex::encode(&script),
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
        );
    }

    #[test]
    fn script_pubkey_p2tr() {
        let output_key: [u8; 32] =
            hex::decode("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
                .unwrap()
                .try_into()
                .unwrap();
        let addr = Address::P2TR {
            output_key,
            network: Network::Mainnet,
        };

        let script = addr.to_script_pubkey();
        assert_eq!(
            hex::encode(&script),
            "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
    }

    #[test]
    fn network_mismatch_base58() {
        // Try to parse a mainnet address with testnet expected
        let result = Address::from_string(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            Some(Network::Testnet),
        );

        assert!(matches!(result, Err(AddressError::NetworkMismatch { .. })));
    }

    #[test]
    fn network_mismatch_segwit() {
        // Try to parse a mainnet address with testnet expected
        let result = Address::from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Some(Network::Testnet),
        );

        assert!(matches!(result, Err(AddressError::NetworkMismatch { .. })));
    }

    #[test]
    fn invalid_base58_checksum() {
        let result = Address::from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", None);
        assert!(matches!(result, Err(AddressError::Base58(_))));
    }

    #[test]
    fn invalid_bech32_checksum() {
        let result = Address::from_string("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", None);
        assert!(matches!(result, Err(AddressError::Bech32(_))));
    }

    #[test]
    fn empty_input() {
        let result = Address::from_string("", None);
        assert!(matches!(result, Err(AddressError::EmptyInput)));
    }

    #[test]
    fn display_trait() {
        let hash = Hash160::from_hex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let addr = Address::P2PKH {
            hash,
            network: Network::Mainnet,
        };

        assert_eq!(
            format!("{}", addr),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        );
    }

    #[test]
    fn network_getter() {
        let hash = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();

        let p2pkh = Address::P2PKH {
            hash,
            network: Network::Mainnet,
        };
        assert_eq!(p2pkh.network(), Network::Mainnet);

        let p2wpkh = Address::P2WPKH {
            hash,
            network: Network::Testnet,
        };
        assert_eq!(p2wpkh.network(), Network::Testnet);
    }

    #[test]
    fn uppercase_bech32() {
        // Bech32 addresses can be all uppercase
        let parsed =
            Address::from_string("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", None).unwrap();

        if let Address::P2WPKH { hash, network } = &parsed {
            assert_eq!(hash.to_hex(), "751e76e8199196d454941c45d1b3a323f1433bd6");
            assert_eq!(*network, Network::Mainnet);
        } else {
            panic!("Expected P2WPKH address");
        }
    }
}
