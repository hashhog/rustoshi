//! Built-in assumeUTXO base-tail header bands.
//!
//! Bitcoin Core never needs this data. `ActivateSnapshot` refuses to activate a
//! snapshot whose base header is not already linked into the headers chain --
//! *"The base block header must appear in the headers chain. Make sure all
//! headers are syncing, and call loadtxoutset again"*
//! (`bitcoin-core/src/validation.cpp:5611-5624`). So in Core the base block's
//! `CBlockIndex` always has a real `pprev` chain, `GetAncestor` can never fail,
//! and `ContextualCheckBlockHeader` can open with `assert(pindexPrev != nullptr)`
//! (validation.cpp:4083).
//!
//! rustoshi's `--load-snapshot` boot materializes NO pre-base headers. Until
//! 2026-08-09 every built-in `AssumeutxoData` shipped `base_tail_headers:
//! Vec::new()`, so snapshot activation wrote the base's `CF_BLOCK_INDEX` entry
//! with a placeholder `bits: 0` and no `CF_HEADERS` at all. The bad-diffbits
//! gate then hit `degrade_at_snapshot_base`'s `None` arm and **skipped
//! entirely** -- not for one header, but for the whole first retarget period
//! above the base, because every retarget ancestor in that window lies below
//! the base. That is the fail-open this module closes.
//!
//! Each band is 2027 real mainnet headers ending at (and including) the base,
//! ascending. 2027 = 2016 (the next retarget boundary's `nHeightFirst`
//! ancestor) + 11 (the median-time-past window), per the contract documented on
//! `AssumeutxoData::base_tail_headers`.
//!
//! The bytes were extracted from a fully-synced Bitcoin Core at
//! `getblockheader(hash, false)` and verified at extraction time: every
//! header's `prev_block_hash` equals the double-SHA256 of its predecessor, and
//! the last header hashes to the entry's declared `blockhash`. Both invariants
//! are re-checked here at load time and again in the tests below -- baked data
//! that is wrong is a build defect, and this is consensus-critical input, so a
//! failure panics rather than degrading to "no tail" (which would silently
//! restore the fail-open).

use rustoshi_primitives::{BlockHeader, Decodable, Hash256};
use std::sync::OnceLock;

/// Number of headers baked per band: 2016 retarget window + 11 MTP window.
pub const TAIL_LEN: usize = 2027;

const RAW_840000: &[u8] = include_bytes!("assumeutxo_tails/mainnet_840000.bin");
const RAW_880000: &[u8] = include_bytes!("assumeutxo_tails/mainnet_880000.bin");
const RAW_910000: &[u8] = include_bytes!("assumeutxo_tails/mainnet_910000.bin");
const RAW_935000: &[u8] = include_bytes!("assumeutxo_tails/mainnet_935000.bin");
const RAW_944183: &[u8] = include_bytes!("assumeutxo_tails/mainnet_944183.bin");

/// `(height, raw bytes, expected base blockhash hex)` for every baked band.
///
/// The hex here must match the `blockhash` on the corresponding
/// `AssumeutxoData` in `params.rs`; `verify_bands_match_params` asserts it.
const BANDS: &[(u32, &[u8], &str)] = &[
    (
        840_000,
        RAW_840000,
        "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
    ),
    (
        880_000,
        RAW_880000,
        "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
    ),
    (
        910_000,
        RAW_910000,
        "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
    ),
    (
        935_000,
        RAW_935000,
        "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
    ),
    (
        944_183,
        RAW_944183,
        "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817",
    ),
];

/// Decode one band and enforce both structural invariants.
///
/// Panics on any violation. See the module docs: silently returning an empty
/// band would hand the caller the exact `None` arm this data exists to remove.
fn decode_band(height: u32, raw: &'static [u8], expected_base_hex: &str) -> Vec<BlockHeader> {
    assert_eq!(
        raw.len(),
        TAIL_LEN * BlockHeader::SIZE,
        "assumeutxo tail band for height {height} is {} bytes, expected {} \
         ({TAIL_LEN} headers x {} bytes)",
        raw.len(),
        TAIL_LEN * BlockHeader::SIZE,
        BlockHeader::SIZE,
    );

    let mut headers = Vec::with_capacity(TAIL_LEN);
    for i in 0..TAIL_LEN {
        let start = i * BlockHeader::SIZE;
        let bytes = &raw[start..start + BlockHeader::SIZE];
        let header = BlockHeader::deserialize(bytes).unwrap_or_else(|e| {
            panic!("assumeutxo tail band {height}: header {i} failed to decode: {e}")
        });
        headers.push(header);
    }

    // Invariant 1 -- the band is a real chain, not an unordered bag.
    for i in 1..headers.len() {
        assert_eq!(
            headers[i].prev_block_hash,
            headers[i - 1].block_hash(),
            "assumeutxo tail band {height}: header {i} does not chain onto header {}",
            i - 1,
        );
    }

    // Invariant 2 -- the band actually ends at the base it claims to.
    let expected_base = Hash256::from_hex(expected_base_hex)
        .unwrap_or_else(|_| panic!("assumeutxo tail band {height}: bad expected-base hex"));
    let last = headers
        .last()
        .expect("TAIL_LEN > 0 checked by the length assert above");
    assert_eq!(
        last.block_hash(),
        expected_base,
        "assumeutxo tail band {height}: last header does not hash to the declared base",
    );

    headers
}

/// All baked mainnet bands, decoded and verified once.
fn bands() -> &'static [(u32, Vec<BlockHeader>)] {
    static DECODED: OnceLock<Vec<(u32, Vec<BlockHeader>)>> = OnceLock::new();
    DECODED.get_or_init(|| {
        BANDS
            .iter()
            .map(|(height, raw, base_hex)| (*height, decode_band(*height, raw, base_hex)))
            .collect()
    })
}

/// The baked tail band ending at the mainnet snapshot base at `height`, or an
/// empty slice when no band is baked for it.
///
/// An empty return is NOT a licence to skip the difficulty gate -- see
/// `rustoshi_storage::header_context::degrade_at_snapshot_base`, which now
/// refuses rather than skipping.
pub fn mainnet_tail(height: u32) -> &'static [BlockHeader] {
    bands()
        .iter()
        .find(|(h, _)| *h == height)
        .map(|(_, headers)| headers.as_slice())
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ChainParams;

    #[test]
    fn every_band_decodes_and_chains() {
        // decode_band panics on violation; touching each band exercises both
        // invariants for all five.
        for (height, _, _) in BANDS {
            let tail = mainnet_tail(*height);
            assert_eq!(tail.len(), TAIL_LEN, "height {height}");
        }
    }

    #[test]
    fn bands_cover_the_retarget_and_mtp_windows() {
        // 2016 back for GetNextWorkRequired's nHeightFirst ancestor, 11 for MTP.
        assert!(TAIL_LEN >= 2016 + 11);
    }

    #[test]
    fn verify_bands_match_params() {
        // The band's final header must be the very block each AssumeutxoData
        // entry names. If someone edits a blockhash in params.rs without
        // re-extracting the band, this fails.
        let params = ChainParams::mainnet();
        for entry in &params.assumeutxo_data {
            let tail = mainnet_tail(entry.height);
            assert!(
                !tail.is_empty(),
                "mainnet assumeutxo entry at height {} has no baked tail band -- \
                 the bad-diffbits gate would refuse every header above it",
                entry.height,
            );
            assert_eq!(
                tail.last().unwrap().block_hash(),
                entry.blockhash,
                "baked tail for height {} does not end at the entry's blockhash",
                entry.height,
            );
            assert_eq!(tail.len(), TAIL_LEN);
        }
    }

    #[test]
    fn params_entries_carry_their_tails() {
        // The wiring itself: params.rs must actually hand the band through.
        let params = ChainParams::mainnet();
        assert!(!params.assumeutxo_data.is_empty());
        for entry in &params.assumeutxo_data {
            assert_eq!(
                entry.base_tail_headers.len(),
                TAIL_LEN,
                "assumeutxo entry at height {} still ships an empty tail",
                entry.height,
            );
            assert_eq!(
                entry.base_tail_headers.last().unwrap().block_hash(),
                entry.blockhash,
            );
        }
    }

    #[test]
    fn unknown_height_returns_empty() {
        assert!(mainnet_tail(1).is_empty());
        assert!(mainnet_tail(999_999).is_empty());
    }
}
