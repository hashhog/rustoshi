//! Store-backed, fail-closed BIP-68 coin median-time-past lookups.
//!
//! Bitcoin Core `consensus/tx_verify.cpp` `CalculateSequenceLocks` measures a
//! time-based relative lock from
//! `block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast()` —
//! the median of the 11 header timestamps ending at `coin_height - 1`. Core
//! always holds every header (assumeUTXO activation requires the full header
//! chain, validation.cpp ActivateSnapshot), so that window is never short
//! except at genesis.
//!
//! rustoshi's `--load-snapshot` boot holds only a 2027-header band below the
//! base (plus whatever historical backfill has fetched), so a coin created
//! near the bottom of the band, or below it, has a partial or absent window.
//! Two wrong answers were possible and both are closed here:
//!
//! * partial window: medianing the headers that happen to be stored gives a
//!   LATER coin time than Core (the missing headers are the older ones), so a
//!   valid block is rejected (hotbuns 942168, camlcoin 932256);
//! * absent header -> 0: the coin is treated as created at the epoch, so every
//!   time lock is satisfied and an invalid block is accepted.
//!
//! [`StoreSeqLockCtx::try_get_mtp_at_height`] instead returns `Err(height)` for
//! the first missing height, which block connection surfaces as
//! `ValidationError::MissingAncestorHeader` — "cannot decide", never an
//! invalid verdict.

use rustoshi_consensus::params::MEDIAN_TIME_PAST_WINDOW;
use rustoshi_consensus::SequenceLockContext;
use rustoshi_primitives::Hash256;

use crate::block_store::BlockStore;

/// `SequenceLockContext` over the persistent header store.
///
/// Heights resolve through `CF_HEIGHT_INDEX` (the best-header chain, which
/// below the block being connected is that block's ancestry); the 11-header
/// window is then walked by `prev_block_hash`, so the window is hash-linked
/// even if the index were stale above `height`.
pub struct StoreSeqLockCtx<'a> {
    store: &'a BlockStore<'a>,
}

impl<'a> StoreSeqLockCtx<'a> {
    pub fn new(store: &'a BlockStore<'a>) -> Self {
        Self { store }
    }
}

impl<'a> SequenceLockContext for StoreSeqLockCtx<'a> {
    /// Infallible form, kept only for callers that do not use the fallible
    /// path. On a missing window it returns `u32::MAX`, which makes any
    /// time-based lock UNSATISFIABLE (fail closed), never satisfied.
    fn get_mtp_at_height(&self, height: u32) -> u32 {
        self.try_get_mtp_at_height(height).unwrap_or(u32::MAX)
    }

    fn try_get_mtp_at_height(&self, height: u32) -> Result<u32, u32> {
        let mut current = match self.store.get_hash_by_height(height) {
            Ok(Some(h)) => h,
            _ => return Err(height),
        };
        let mut timestamps: Vec<u32> = Vec::with_capacity(MEDIAN_TIME_PAST_WINDOW);
        let mut h = height;
        loop {
            let header = match self.store.get_header(&current) {
                Ok(Some(hdr)) => hdr,
                _ => return Err(h),
            };
            timestamps.push(header.timestamp);
            if timestamps.len() == MEDIAN_TIME_PAST_WINDOW
                || header.prev_block_hash == Hash256::ZERO
            {
                // Full window, or Core's genuine short window at genesis.
                break;
            }
            current = header.prev_block_hash;
            h -= 1;
        }
        timestamps.sort_unstable();
        Ok(timestamps[timestamps.len() / 2])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ChainDb;
    use rustoshi_consensus::{check_sequence_locks, try_calculate_sequence_locks, ValidationError};
    use rustoshi_primitives::{BlockHeader, Decodable, OutPoint, Transaction, TxIn, TxOut};

    /// Raw mainnet headers 927966..=927979 from Bitcoin Core
    /// `getblockheader <hash> false` (2026-10-03).
    const HEADERS: &[&str] = &[
        // 927966
        "004000204ba148820ae8ae424419370d27243639025fe9590c4101000000000000000000f57c7275a92fb9b654f7c6db9fce851774f32f70f05bf759ddab874b0027efdeeafa3f693ae601175a3570a6",
        // 927967
        "00e0ff26cb8c74b118a48b2ab2b08bbed7b0d8ec8f4bc0c0328b01000000000000000000d0925f4e48d6b1464a4fec3c2cfcdda327a4db44b9bab9df7e2ef02b6fce06f8affc3f693ae60117848eba75",
        // 927968
        "0040d5271527afa32e96e40aa83462077ad71f57edd46e12d70801000000000000000000d86ef389e4383912c696812dd30f9bbe49649ca5466a250ca09e617edd77e2f98aff3f693ae60117c3d0e67d",
        // 927969
        "00604c2275d46a68ab50f7972eb3e5c2d7121a6a93b112b9563b010000000000000000009424d434c17c89aebb9fdf35e0d9fea4c944ac151e23f684e3e21e0fbd728082000140693ae601179c972b33",
        // 927970
        "00a00420536dd03c2356179c3860de85d61ba09176f91446d00e00000000000000000000858da5a3a3416716d22280fc858e15f63ae335f46132cb7de766b8c57304f654a40140693ae60117065b07ec",
        // 927971
        "00407b21362deed34a89d70b1460117c7bf96c6b8a6581c39988010000000000000000001f93a5b2993179f782dff30c44a9b1c48743dd4e8f1f3e44a9224aaffea194a1a70340693ae601178a07a026",
        // 927972
        "00e0ff3f4b8d1d54d193eb8fb1efdc2f43055fe02aa85546c5d4000000000000000000007b72dd234a9e33fab697246f56964b24cad845977f80cc644bbfc55a01ce8b138b0540693ae601176f958fbd",
        // 927973
        "000000347086fc0b3552d57b65f88909cee8c70c77b2ac654ab8010000000000000000004cb9fd96801049bf956e76469e46616332901546a94de61dd72a58fe345782d5e00740693ae60117a644a6a2",
        // 927974
        "004002209143c555c0a28dbd521c97aa7e03e64c93ad992669ea00000000000000000000432180db8e60bc066319e02bc8dc77883628e0c39f27e186e8456424494e7e9ad01540693ae60117e4a986da",
        // 927975
        "0000de258c3aac1daba1c1f547119026c083b9be506d0bfeea37000000000000000000008c266bcf17ebc8a9ff79d1db7b356e6828d24169725674800236440232d2d6d84f1640693ae601172f34e592",
        // 927976
        "0040aa25ea9af58f5967beb933e6e70f566c5fbbf17c80ed9f8601000000000000000000efd6c731cf9c490798b13bebfdac28aa16e570e4427efa55f9a8cfb86dde71ceaf1840693ae601175a9e160f",
        // 927977
        "000000346445d1e4c1a1ccb99e4ef033fee46c65cf584797e5f400000000000000000000b39c9cf6d8869991620571af2267451233d53f91eaaa8a408c34d1ddf4ba6f70471a40693ae60117275721b5",
        // 927978
        "00c0052052cad98b346a025552f94313ccc6afc599a592b58c9b010000000000000000005f512e2208b459e61d540d343c7376b985f9b78430195346392dfd4255cef1d3071c40693ae601177bf79c5f",
        // 927979
        "00000038943433b9297428816fa8dcbfef2987185251b5b7f87601000000000000000000f1a752f53f5eea33e72322f4ab4c9c2a9e93648832ac4b10672df690e33cab37d31f40693ae601171884465a",
    ];
    const FIRST: u32 = 927_966;

    fn store_with(db: &ChainDb, from: u32) -> BlockStore<'_> {
        let store = BlockStore::new(db);
        for (i, hex_hdr) in HEADERS.iter().enumerate() {
            let height = FIRST + i as u32;
            if height < from {
                continue;
            }
            let bytes = hex::decode(hex_hdr).unwrap();
            let hdr = BlockHeader::deserialize(&bytes).unwrap();
            let hash = hdr.block_hash();
            store.put_header(&hash, &hdr).unwrap();
            store.put_height_index(height, &hash).unwrap();
        }
        store
    }

    /// The camlcoin-932256 transaction shape: v2, one input spending a coin
    /// created at 927979, nSequence = TYPE_FLAG | 5063 (5063*512 s).
    fn lock_tx() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([1u8; 32]), vout: 0 },
                script_sig: vec![],
                sequence: 0x0040_13c7,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1, script_pubkey: vec![0x51] }],
            lock_time: 0,
        }
    }

    // Core: getblockheader(927978).mediantime / getblockheader(932255).mediantime
    const CORE_MTP_927978: u32 = 1_765_804_000;
    const CORE_MTP_932255: i64 = 1_768_398_550;

    #[test]
    fn full_window_matches_core_mtp() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = store_with(&db, FIRST);
        let ctx = StoreSeqLockCtx::new(&store);
        assert_eq!(ctx.try_get_mtp_at_height(927_978), Ok(CORE_MTP_927978));
    }

    /// Valid mainnet block 932256: with the full window the lock is met
    /// exactly as in Core (required 1768396255 < block prev-MTP 1768398550).
    #[test]
    fn mainnet_932256_lock_is_met_with_full_window() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = store_with(&db, FIRST);
        let ctx = StoreSeqLockCtx::new(&store);
        let locks = try_calculate_sequence_locks(&lock_tx(), &[927_979], &ctx, true).unwrap();
        assert_eq!(locks.min_time, CORE_MTP_927978 as i64 + 5063 * 512 - 1);
        assert!(check_sequence_locks(&locks, 932_256, CORE_MTP_932255));
    }

    /// A snapshot band starting at 927974 (snapshot 930000 - 2026) leaves the
    /// coin-MTP window 927968..=927978 partial. The old partial-window walk
    /// gave a later coin time and REJECTED valid block 932256; this must
    /// instead fail closed with MissingAncestorHeader (no verdict).
    #[test]
    fn mainnet_932256_partial_band_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = store_with(&db, 927_974);
        let ctx = StoreSeqLockCtx::new(&store);
        assert_eq!(ctx.try_get_mtp_at_height(927_978), Err(927_973));
        match try_calculate_sequence_locks(&lock_tx(), &[927_979], &ctx, true) {
            Err(ValidationError::MissingAncestorHeader(927_973)) => {}
            other => panic!("expected MissingAncestorHeader(927973), got {other:?}"),
        }
        // The infallible lookup must fail closed too (unsatisfiable), never 0.
        assert_eq!(ctx.get_mtp_at_height(927_978), u32::MAX);
    }

    /// Coin entirely below the band: absent height must not read as time 0.
    #[test]
    fn absent_height_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();
        let store = store_with(&db, 927_974);
        let ctx = StoreSeqLockCtx::new(&store);
        assert_eq!(ctx.try_get_mtp_at_height(900_000), Err(900_000));
    }
}
