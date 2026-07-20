//! `HASHHOG_CAMPAIGN_ASSUMEUTXO` — campaign-only assumeutxo allowlist.
//!
//! hashhog-only mechanism (NOT in Bitcoin Core). Full spec:
//! `receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md` (meta-repo). Unblocks the M2
//! boundary campaign, which boots each impl with "mainnet params" and
//! fast-forwards a UTXO snapshot to a boundary height without permanently
//! widening any of the 10 impls' production trust tables.
//!
//! Contract:
//!   - Env var `HASHHOG_CAMPAIGN_ASSUMEUTXO=<absolute path to JSON>`.
//!   - Read at most once per process (the caller, `main.rs`, calls this
//!     exactly once at startup, right after network-params selection). When
//!     unset or empty: a single `env::var` call returns "not found" and this
//!     module does nothing else -- no file I/O, no table mutation. Bit-
//!     identical to a build without this feature.
//!   - When set: parse the file (array of `{height, blockhash,
//!     hash_serialized, m_chain_tx_count}` + optional `base_mtp` +
//!     optional `base_tail_headers`), validate, and return the entries for
//!     the caller to append to the *running* network's
//!     `ChainParams::assumeutxo_data`.
//!   - On any collision with a built-in entry (same height OR same block
//!     hash) or a duplicate within the campaign file itself: refuse (return
//!     `Err`) -- campaign data may never override a production hash. The
//!     caller turns this into a loud, fatal startup error.
//!
//! `base_tail_headers` (optional): a JSON array of hex-encoded 80-byte
//! block headers (Core wire order: version|prev|merkle|time|bits|nonce),
//! covering the band immediately BEFORE and INCLUDING the snapshot base, in
//! ascending height order. Fixes M2-RUST-MTP / M2-RUST-POW-PANIC
//! (receipts/PORTER-WAVE-NODE-BUGS.md): without real pre-base headers, the
//! MTP walk for blocks in [base+1, base+11] sees a too-small partial window
//! (false `time-too-old` rejects on legitimate blocks), and the retarget
//! ancestor walk at the very next difficulty-adjustment boundary can find no
//! ancestor at all (`AssumeutxoData::base_tail_headers` doc comment has the
//! full writeup; `2016 + 11 = 2027` headers is the recommended count, but
//! any length is accepted). Each header is validated to (a) parse as an
//! 80-byte header, (b) chain to the next (each header's `prev_block_hash`
//! must equal the previous header's hash), and (c) have its LAST header's
//! hash equal the entry's `blockhash`. A campaign entry with no
//! `base_tail_headers` key behaves exactly as before this field existed.
//!
//! SECURITY: this module implements only the parse/validate/merge mechanics.
//! The actual guard against production (mainnet P2P) use is external:
//! `tools/start_mainnet.sh` refuses to launch any node with this env var set
//! (launcher guard, mandatory + uniform). See the spec's "Security note".
//!
//! All hex fields are DISPLAY order (as Core's `kernel/chainparams.cpp`
//! prints / `uint256{"..."}` parses), matching every other `AssumeutxoData`
//! literal in `params.rs` -- `Hash256::from_hex` / `AssumeutxoHash::from_hex`
//! already do the display->internal byte reversal, so no extra conversion is
//! needed here.

use crate::params::{AssumeutxoData, AssumeutxoHash, ChainParams};
use rustoshi_primitives::{BlockHeader, Decodable, Hash256};
use serde::Deserialize;

/// Name of the environment variable this module reads.
pub const ENV_VAR: &str = "HASHHOG_CAMPAIGN_ASSUMEUTXO";

/// Bound on accepted campaign entries. The M2 boundary campaign fixture is
/// ~17-20 entries; this leaves generous headroom while still refusing a
/// runaway/garbage file.
pub const MAX_ENTRIES: usize = 256;

/// Raw on-disk shape of one campaign entry (before hex parsing).
#[derive(Debug, Deserialize)]
struct RawEntry {
    height: u32,
    blockhash: String,
    hash_serialized: String,
    m_chain_tx_count: u64,
    /// Optional: base_mtp (mainnet post-snapshot BIP-113 proxy). See
    /// `AssumeutxoData::base_mtp`'s doc comment -- without it the first
    /// post-snapshot block can wedge the chain at `bad-txns-nonfinal`.
    #[serde(default)]
    base_mtp: Option<u32>,
    /// Optional: real headers for the band ending at (and including) the
    /// snapshot base, ascending height order, each an 80-byte Core-wire-order
    /// header as hex. See `AssumeutxoData::base_tail_headers`'s doc comment.
    #[serde(default)]
    base_tail_headers: Option<Vec<String>>,
    // `base_header` (singular) / `chainwork` are accepted by the shared
    // cross-impl JSON schema for OTHER impls (e.g. ouroboros) but rustoshi's
    // `AssumeutxoData` carries no field for either -- `#[serde(default)]`-free
    // `RawEntry` simply ignores unknown JSON keys (serde_json's default
    // behavior), which is the correct "parsed-and-ignored" treatment here.
}

/// Everything that can go wrong loading a campaign file. The `Display` impl
/// is what ends up in the fatal startup message.
#[derive(Debug, thiserror::Error)]
pub enum CampaignAssumeutxoError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to parse {path} as JSON: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },

    #[error("campaign file {path} is empty (zero entries)")]
    Empty { path: String },

    #[error("campaign file {path} has {count} entries, exceeding the {max} limit")]
    TooManyEntries {
        path: String,
        count: usize,
        max: usize,
    },

    #[error("entry {index}: height must be > 0")]
    InvalidHeight { index: usize },

    #[error("entry {index}: invalid blockhash {value:?}: {reason}")]
    InvalidBlockhash {
        index: usize,
        value: String,
        reason: String,
    },

    #[error("entry {index}: invalid hash_serialized {value:?}: {reason}")]
    InvalidHashSerialized {
        index: usize,
        value: String,
        reason: String,
    },

    #[error(
        "entry {index} (height {height}) collides with a built-in assumeutxo entry -- \
         campaign data may never override a production hash"
    )]
    CollidesWithBuiltin { index: usize, height: u32 },

    #[error(
        "entry {index} (height {height}) duplicates an earlier entry in the same campaign file"
    )]
    DuplicateInFile { index: usize, height: u32 },

    #[error(
        "entry {index}: base_tail_headers[{header_index}] is not valid hex / not an \
         80-byte header: {reason}"
    )]
    InvalidTailHeader {
        index: usize,
        header_index: usize,
        reason: String,
    },

    #[error(
        "entry {index}: base_tail_headers does not chain -- header {header_index}'s \
         prev_block_hash does not equal header {prev_index}'s hash"
    )]
    TailHeadersDoNotChain {
        index: usize,
        header_index: usize,
        prev_index: usize,
    },

    #[error(
        "entry {index}: base_tail_headers' last header hash does not equal the entry's \
         blockhash -- the tail must end exactly at the snapshot base"
    )]
    TailHeadersWrongFinalHash { index: usize },
}

/// A successfully loaded and validated campaign table.
pub struct LoadedCampaign {
    /// The path the entries were read from (for the startup banner).
    pub path: String,
    /// The validated entries, ready to append to `ChainParams::assumeutxo_data`.
    pub entries: Vec<AssumeutxoData>,
}

/// Read `HASHHOG_CAMPAIGN_ASSUMEUTXO` (if set) and merge its entries into
/// `params.assumeutxo_data`.
///
/// Returns `Ok(None)` when the env var is unset or empty -- after the single
/// `env::var` call, nothing else runs. This is the "bit-identical to before
/// this feature existed" path that keeps the flag mainnet-inert by default.
///
/// Returns `Ok(Some(loaded))` on a successful load, having already appended
/// `loaded.entries` to `params.assumeutxo_data`.
///
/// Returns `Err(_)` on any malformed entry or a collision with a built-in
/// entry / duplicate within the file. The caller (`main.rs`) is expected to
/// treat this as fatal (loud message + non-zero exit) -- campaign data must
/// never silently coexist with a bad or colliding entry.
pub fn load_and_merge(
    params: &mut ChainParams,
) -> Result<Option<LoadedCampaign>, CampaignAssumeutxoError> {
    let path = match std::env::var(ENV_VAR) {
        Ok(p) if !p.is_empty() => p,
        _ => return Ok(None),
    };

    let entries = load_from_path(&path, &params.assumeutxo_data)?;
    params.assumeutxo_data.extend(entries.iter().cloned());
    Ok(Some(LoadedCampaign { path, entries }))
}

/// Parse and validate a campaign file at `path` against `builtin` (the
/// selected network's own `assumeutxo_data`, consulted only for collision
/// detection -- never mutated). Does not touch `params`; callers merge the
/// returned `Vec` themselves. Exposed separately from [`load_and_merge`] so
/// tests can exercise it without touching the process environment.
pub fn load_from_path(
    path: &str,
    builtin: &[AssumeutxoData],
) -> Result<Vec<AssumeutxoData>, CampaignAssumeutxoError> {
    let content = std::fs::read_to_string(path).map_err(|source| CampaignAssumeutxoError::Io {
        path: path.to_string(),
        source,
    })?;

    let raw: Vec<RawEntry> =
        serde_json::from_str(&content).map_err(|source| CampaignAssumeutxoError::Json {
            path: path.to_string(),
            source,
        })?;

    if raw.is_empty() {
        return Err(CampaignAssumeutxoError::Empty {
            path: path.to_string(),
        });
    }
    if raw.len() > MAX_ENTRIES {
        return Err(CampaignAssumeutxoError::TooManyEntries {
            path: path.to_string(),
            count: raw.len(),
            max: MAX_ENTRIES,
        });
    }

    let mut staged: Vec<AssumeutxoData> = Vec::with_capacity(raw.len());
    for (index, r) in raw.into_iter().enumerate() {
        if r.height == 0 {
            return Err(CampaignAssumeutxoError::InvalidHeight { index });
        }

        let blockhash = Hash256::from_hex(&r.blockhash).map_err(|e| {
            CampaignAssumeutxoError::InvalidBlockhash {
                index,
                value: r.blockhash.clone(),
                reason: format!("{e:?}"),
            }
        })?;

        let hash_serialized =
            AssumeutxoHash::from_hex(&r.hash_serialized).ok_or_else(|| {
                CampaignAssumeutxoError::InvalidHashSerialized {
                    index,
                    value: r.hash_serialized.clone(),
                    reason: "expected 32-byte hex".to_string(),
                }
            })?;

        // Refuse collisions with a built-in (production) entry: same height
        // OR same block hash. Campaign data may never override a production
        // hash.
        if builtin
            .iter()
            .any(|b| b.height == r.height || b.blockhash == blockhash)
        {
            return Err(CampaignAssumeutxoError::CollidesWithBuiltin {
                index,
                height: r.height,
            });
        }
        // Refuse duplicates within the campaign file itself.
        if staged
            .iter()
            .any(|s| s.height == r.height || s.blockhash == blockhash)
        {
            return Err(CampaignAssumeutxoError::DuplicateInFile {
                index,
                height: r.height,
            });
        }

        let base_tail_headers = match &r.base_tail_headers {
            None => Vec::new(),
            Some(hexes) => parse_base_tail_headers(index, hexes, &blockhash)?,
        };

        staged.push(AssumeutxoData {
            height: r.height,
            blockhash,
            hash_serialized,
            chain_tx_count: r.m_chain_tx_count,
            base_mtp: r.base_mtp,
            base_tail_headers,
        });
    }

    Ok(staged)
}

/// Parse and validate an entry's `base_tail_headers` hex list.
///
/// Each string must decode to exactly 80 bytes and parse as a `BlockHeader`
/// (`InvalidTailHeader` otherwise). The decoded headers -- assumed to be
/// supplied in ascending height order -- must chain (each header's
/// `prev_block_hash` equals the PREVIOUS header's hash;
/// `TailHeadersDoNotChain` otherwise), and the LAST header's hash must equal
/// `expected_base_hash` (`TailHeadersWrongFinalHash` otherwise) -- the tail
/// must end exactly at the snapshot base so the persisted band lines up with
/// the snapshot's own `blockhash`.
///
/// An empty `hexes` list parses to an empty `Vec` without error (nothing to
/// chain-check); the caller only invokes this when the JSON key was present,
/// so an explicit `"base_tail_headers": []` is accepted as a (pointless but
/// harmless) no-op, matching the field's overall optional/empty-default
/// semantics.
fn parse_base_tail_headers(
    index: usize,
    hexes: &[String],
    expected_base_hash: &Hash256,
) -> Result<Vec<BlockHeader>, CampaignAssumeutxoError> {
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(hexes.len());
    for (header_index, hex_str) in hexes.iter().enumerate() {
        let bytes = hex::decode(hex_str).map_err(|e| CampaignAssumeutxoError::InvalidTailHeader {
            index,
            header_index,
            reason: format!("invalid hex: {e}"),
        })?;
        if bytes.len() != BlockHeader::SIZE {
            return Err(CampaignAssumeutxoError::InvalidTailHeader {
                index,
                header_index,
                reason: format!(
                    "expected {} bytes (80-byte header), got {}",
                    BlockHeader::SIZE,
                    bytes.len()
                ),
            });
        }
        let header = BlockHeader::deserialize(&bytes).map_err(|e| {
            CampaignAssumeutxoError::InvalidTailHeader {
                index,
                header_index,
                reason: format!("header decode failed: {e}"),
            }
        })?;
        headers.push(header);
    }

    // Chain check: header[i].prev_block_hash == header[i-1].block_hash().
    for i in 1..headers.len() {
        if headers[i].prev_block_hash != headers[i - 1].block_hash() {
            return Err(CampaignAssumeutxoError::TailHeadersDoNotChain {
                index,
                header_index: i,
                prev_index: i - 1,
            });
        }
    }

    // Final-hash check: the LAST header must be the snapshot base itself.
    if let Some(last) = headers.last() {
        if last.block_hash() != *expected_base_hash {
            return Err(CampaignAssumeutxoError::TailHeadersWrongFinalHash { index });
        }
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::Encodable;

    fn write_json(dir: &std::path::Path, name: &str, content: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write fixture");
        path.to_string_lossy().to_string()
    }

    #[test]
    fn accepts_a_valid_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 481823,
                   "blockhash": "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80",
                   "hash_serialized": "25429c30cfa0b6051106c29d15b188d746d8e7ecd184bf34fae1cebe2ea447f4",
                   "m_chain_tx_count": 249036369 } ]"#,
        );

        let got = load_from_path(&path, &[]).expect("valid campaign file");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].height, 481_823);
        assert_eq!(got[0].chain_tx_count, 249_036_369);
        assert_eq!(
            got[0].blockhash,
            Hash256::from_hex(
                "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80"
            )
            .unwrap()
        );
        assert_eq!(got[0].base_mtp, None);
    }

    #[test]
    fn accepts_optional_base_mtp() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 481823,
                   "blockhash": "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80",
                   "hash_serialized": "25429c30cfa0b6051106c29d15b188d746d8e7ecd184bf34fae1cebe2ea447f4",
                   "m_chain_tx_count": 249036369,
                   "base_mtp": 1503536364 } ]"#,
        );

        let got = load_from_path(&path, &[]).expect("valid campaign file");
        assert_eq!(got[0].base_mtp, Some(1_503_536_364));
    }

    #[test]
    fn refuses_collision_with_builtin_same_height() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 840000,
                   "blockhash": "1111111111111111111111111111111111111111111111111111111111111111",
                   "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
                   "m_chain_tx_count": 1 } ]"#,
        );

        let builtin = vec![AssumeutxoData {
            height: 840_000,
            blockhash: Hash256::from_hex(
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
            )
            .unwrap(),
            hash_serialized: AssumeutxoHash::from_hex(
                "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
            )
            .unwrap(),
            chain_tx_count: 1,
            base_mtp: None,
            base_tail_headers: Vec::new(),
        }];

        let err = load_from_path(&path, &builtin).expect_err("must collide on height");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::CollidesWithBuiltin { .. }
        ));
    }

    #[test]
    fn refuses_collision_with_builtin_same_blockhash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 999999,
                   "blockhash": "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
                   "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
                   "m_chain_tx_count": 1 } ]"#,
        );

        let params = ChainParams::mainnet();
        let err = load_from_path(&path, &params.assumeutxo_data)
            .expect_err("must collide on blockhash");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::CollidesWithBuiltin { .. }
        ));
    }

    #[test]
    fn refuses_duplicate_height_within_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 500000,
                   "blockhash": "1111111111111111111111111111111111111111111111111111111111111111",
                   "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
                   "m_chain_tx_count": 1 },
                 { "height": 500000,
                   "blockhash": "3333333333333333333333333333333333333333333333333333333333333333",
                   "hash_serialized": "4444444444444444444444444444444444444444444444444444444444444444",
                   "m_chain_tx_count": 2 } ]"#,
        );

        let err = load_from_path(&path, &[]).expect_err("must reject in-file duplicate");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::DuplicateInFile { .. }
        ));
    }

    #[test]
    fn rejects_non_positive_height() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 0,
                   "blockhash": "1111111111111111111111111111111111111111111111111111111111111111",
                   "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
                   "m_chain_tx_count": 1 } ]"#,
        );

        let err = load_from_path(&path, &[]).expect_err("height 0 must be rejected");
        assert!(matches!(err, CampaignAssumeutxoError::InvalidHeight { .. }));
    }

    #[test]
    fn rejects_invalid_length_blockhash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 500000,
                   "blockhash": "abcd",
                   "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
                   "m_chain_tx_count": 1 } ]"#,
        );

        let err = load_from_path(&path, &[]).expect_err("short blockhash must be rejected");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::InvalidBlockhash { .. }
        ));
    }

    #[test]
    fn rejects_empty_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(tmp.path(), "campaign.json", "[]");

        let err = load_from_path(&path, &[]).expect_err("empty array must be rejected");
        assert!(matches!(err, CampaignAssumeutxoError::Empty { .. }));
    }

    #[test]
    fn rejects_malformed_json() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(tmp.path(), "campaign.json", "{ not json ]");

        let err = load_from_path(&path, &[]).expect_err("malformed JSON must be rejected");
        assert!(matches!(err, CampaignAssumeutxoError::Json { .. }));
    }

    #[test]
    fn rejects_missing_file() {
        let err = load_from_path("/nonexistent/path/campaign.json", &[])
            .expect_err("missing file must be rejected");
        assert!(matches!(err, CampaignAssumeutxoError::Io { .. }));
    }

    /// Unset env var: `load_and_merge` must be a strict no-op (no mutation,
    /// `Ok(None)`), matching the "bit-identical to before this feature
    /// existed" contract.
    #[test]
    fn load_and_merge_is_noop_when_env_unset() {
        // SAFETY: test-only removal of a var this test doesn't otherwise use;
        // guarded by not running assumeutxo campaign tests in parallel with
        // anything that sets this var (none in this crate do).
        std::env::remove_var(ENV_VAR);
        let mut params = ChainParams::mainnet();
        let before = params.assumeutxo_data.clone();

        let result = load_and_merge(&mut params).expect("unset env must not error");
        assert!(result.is_none());
        assert_eq!(params.assumeutxo_data, before);
    }

    // ============================================================
    // base_tail_headers: M2-RUST-MTP / M2-RUST-POW-PANIC
    // ============================================================

    /// Build a synthetic, internally-consistent chain of `n` headers
    /// (genesis-less -- an arbitrary all-zero `prev_block_hash` root), each
    /// linking to the previous via `prev_block_hash == prior.block_hash()`.
    /// Returns the headers in ascending order (oldest first).
    fn build_test_header_chain(n: usize, start_time: u32) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(n);
        let mut prev_hash = Hash256::ZERO;
        for i in 0..n {
            let header = BlockHeader {
                version: 1,
                prev_block_hash: prev_hash,
                merkle_root: Hash256::from_bytes([i as u8; 32]),
                timestamp: start_time + i as u32 * 600,
                bits: 0x1d00ffff,
                nonce: i as u32,
            };
            prev_hash = header.block_hash();
            headers.push(header);
        }
        headers
    }

    fn header_hex(h: &BlockHeader) -> String {
        hex::encode(h.serialize())
    }

    #[test]
    fn accepts_a_valid_chained_tail_header_band() {
        let chain = build_test_header_chain(5, 1_000_000);
        let base_hash = chain.last().unwrap().block_hash();
        let hexes: Vec<String> = chain.iter().map(header_hex).collect();

        let got = parse_base_tail_headers(0, &hexes, &base_hash)
            .expect("a genuinely chained band ending at the base hash must be accepted");
        assert_eq!(got.len(), 5);
        assert_eq!(got.last().unwrap().block_hash(), base_hash);
        // Round-trips byte-for-byte through hex encode/decode.
        assert_eq!(got, chain);
    }

    #[test]
    fn accepts_a_valid_chained_tail_header_band_via_load_from_path() {
        // End-to-end through the JSON campaign-file path (not just the
        // parse helper directly), proving `RawEntry`/`load_from_path` wire
        // `base_tail_headers` through correctly.
        let chain = build_test_header_chain(3, 1_000_000);
        let base_hash = chain.last().unwrap().block_hash();
        let hexes: Vec<String> = chain.iter().map(header_hex).collect();
        let hexes_json = serde_json::to_string(&hexes).unwrap();

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            &format!(
                r#"[ {{ "height": 500000,
                       "blockhash": "{}",
                       "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
                       "m_chain_tx_count": 1,
                       "base_tail_headers": {} }} ]"#,
                base_hash.to_hex(),
                hexes_json,
            ),
        );

        let got = load_from_path(&path, &[]).expect("valid tail-header band must be accepted");
        assert_eq!(got[0].base_tail_headers.len(), 3);
        assert_eq!(got[0].base_tail_headers, chain);
    }

    #[test]
    fn refuses_a_broken_chain_link() {
        let mut chain = build_test_header_chain(4, 1_000_000);
        // Corrupt header[2]'s prev_block_hash so it no longer points at
        // header[1]'s real hash.
        chain[2].prev_block_hash = Hash256::from_bytes([0xEE; 32]);
        let base_hash = chain.last().unwrap().block_hash();
        let hexes: Vec<String> = chain.iter().map(header_hex).collect();

        let err = parse_base_tail_headers(0, &hexes, &base_hash)
            .expect_err("a broken prev_block_hash link must be refused");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::TailHeadersDoNotChain {
                header_index: 2,
                prev_index: 1,
                ..
            }
        ));
    }

    #[test]
    fn refuses_a_wrong_final_hash() {
        let chain = build_test_header_chain(4, 1_000_000);
        let hexes: Vec<String> = chain.iter().map(header_hex).collect();
        // The chain is internally consistent, but doesn't end at the
        // (unrelated) expected base hash -- must be refused.
        let wrong_base_hash = Hash256::from_bytes([0xAB; 32]);

        let err = parse_base_tail_headers(0, &hexes, &wrong_base_hash)
            .expect_err("a tail band not ending at the entry's blockhash must be refused");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::TailHeadersWrongFinalHash { index: 0 }
        ));
    }

    #[test]
    fn refuses_invalid_hex_in_tail_headers() {
        let base_hash = Hash256::from_bytes([0xAB; 32]);
        let err = parse_base_tail_headers(0, &["not-hex".to_string()], &base_hash)
            .expect_err("non-hex tail header must be refused");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::InvalidTailHeader { header_index: 0, .. }
        ));
    }

    #[test]
    fn refuses_wrong_length_tail_header() {
        let base_hash = Hash256::from_bytes([0xAB; 32]);
        // Valid hex, but only 4 bytes -- not an 80-byte header.
        let err = parse_base_tail_headers(0, &["deadbeef".to_string()], &base_hash)
            .expect_err("a too-short tail header must be refused");
        assert!(matches!(
            err,
            CampaignAssumeutxoError::InvalidTailHeader { header_index: 0, .. }
        ));
    }

    #[test]
    fn missing_base_tail_headers_key_defaults_to_empty_unchanged_behavior() {
        // No `base_tail_headers` key at all: mainnet-inert, byte-identical
        // to before this field existed.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_json(
            tmp.path(),
            "campaign.json",
            r#"[ { "height": 481823,
                   "blockhash": "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80",
                   "hash_serialized": "25429c30cfa0b6051106c29d15b188d746d8e7ecd184bf34fae1cebe2ea447f4",
                   "m_chain_tx_count": 249036369 } ]"#,
        );
        let got = load_from_path(&path, &[]).expect("valid campaign file");
        assert!(got[0].base_tail_headers.is_empty());
    }
}
