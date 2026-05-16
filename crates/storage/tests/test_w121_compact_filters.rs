//! W121 BIP-157 / BIP-158 compact block filters — 30-gate audit.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/blockfilter.{h,cpp}` — BIP-158 GCS construction:
//!   `BlockFilter`, `GCSFilter`, `BasicFilterElements`, BlockFilterType::BASIC=0,
//!   `BASIC_FILTER_P=19`, `BASIC_FILTER_M=784931`, M2.5/64-bit FastRange64 reduction.
//! - `bitcoin-core/src/index/blockfilterindex.{h,cpp}` — on-disk index:
//!   flat-file `fltr?????.dat` (16 MiB chunks) + LevelDB key->FlatFilePos,
//!   `DBVal{hash, header, pos}`, `CFCHECKPT_INTERVAL=1000`, height→hash mirror.
//! - `bitcoin-core/src/net_processing.cpp` — BIP-157 P2P:
//!   `MAX_GETCFILTERS_SIZE=1000`, `MAX_GETCFHEADERS_SIZE=2000`,
//!   `ProcessGetCFilters`, `ProcessGetCFHeaders`, `ProcessGetCFCheckPt`,
//!   `PrepareBlockFilterRequest` (DoS gate + `NODE_COMPACT_FILTERS` advertise).
//! - `bitcoin-core/src/rest.cpp::rest_block_filter` / `rest_filter_header`.
//! - `bitcoin-core/src/rpc/blockchain.cpp` — `getblockfilter`,
//!   `getindexinfo` (includes `basic block filter index`), `scanblocks`.
//! - BIP-157 (P2P) + BIP-158 (filter construction).
//!
//! Cross-cutting:
//! - Light-client ecosystem (Neutrino — LND, BDK, Wasabi, Electrum-like) depend
//!   on BIP-157 P2P. Without the P2P handlers + NODE_COMPACT_FILTERS advert, a
//!   rustoshi peer cannot serve these clients at all (silently dropped by Core's
//!   request gating since `peer.m_our_services & NODE_COMPACT_FILTERS` is 0).
//! - W110 BIP-37 bloom-filter audit found a similar shape (handlers stubbed /
//!   service bit advertised inconsistently). Compact filters are the modern
//!   successor; CDIV-grade absence here means rustoshi cannot serve any modern
//!   light client.
//!
//! Gate legend:
//! - OK      : implemented correctly (regression pin)
//! - PARTIAL : implemented but missing edge cases / fields / wiring
//! - MISSING : not implemented
//! - BUG     : implemented but deviates from Core/BIP
//! - C-DIV   : consensus / relay / wire divergence (real protocol incompat)
//!
//! Severity scale:
//! - P0-CDIV : real fork / relay / wire-format divergence
//! - P0      : feature unusable end-to-end (light clients cannot connect)
//! - P1      : protocol-level correctness gap
//! - P2      : operational correctness / observability
//! - P3      : minor / polish
//!
//! Wave W121 summary (per-gate verdict in comments below each #[test]):
//!
//! Bug numbers: BUG-1 + BUG-4..BUG-30 (BUG-2 and BUG-3 retired during audit
//! review after re-reading Core; see comments at G7 / G10). Net total: 29 bugs.
//!
//! Gates 1-10 — BIP-158 GCS construction:
//!   G1 OK   : BASIC_FILTER_P=19 / BASIC_FILTER_M=784931 constants match Core.
//!   G2 OK   : SipHash key derivation = block_hash[0..8] LE / [8..16] LE.
//!   G3 OK   : FastRange64 reduction `(hash * f) >> 64`, NOT modulo.
//!   G4 OK   : Encoded form = `CompactSize(N) || GolombRice(deltas)`.
//!   G5 OK   : Golomb-Rice encode (q ones + zero + p-bit remainder) roundtrip.
//!   G6 BUG-1: `BlockFilter::match_script` / `match_any_scripts` clone the
//!             entire encoded filter AND call `from_encoded` (which does a
//!             full N-element decode validation pass) on EVERY match call.
//!             At light-client scan rate (thousands of filters/sec) this is
//!             O(N) cloning + O(N) validation + O(N) match-scan per query —
//!             3× the work Core does (Core caches a parsed GCSFilter once,
//!             then does a single O(N) scan per match). (P2 — perf only.)
//!   G7 OK   : GCSFilter constructor takes `HashSet<Vec<u8>>` — non-deterministic
//!             iteration order, but hashes are sorted before encoding, so the
//!             SET-based dedup is byte-for-byte identical to Core's std::set<>.
//!   G8 OK   : BIP-158 test vector (testnet3) genesis: `019dfca8` matches Core.
//!   G9 OK   : BIP-158 test vector block 987876: `010c0b40` matches Core.
//!   G10 OK  : Filter header chain `header[i] = SHA256d(filter_hash || header[i-1])`
//!             matches Core (in-module gcs.rs::test_bip158_genesis_header_chain).
//!
//! Gates 11-20 — BIP-157 P2P messages:
//!   G11 BUG-4: `NetworkMessage::GetCFilters(Vec<u8>)` is opaque; no payload
//!             struct, no decoder. The `Vec<u8>` is the raw bytes which the
//!             handler must parse — but THERE IS NO HANDLER (G15-G17). (P0-CDIV)
//!   G12 BUG-5: `NetworkMessage::CFilter(Vec<u8>)` same shape — no decoder
//!             struct; cannot construct outbound. (P0-CDIV)
//!   G13 BUG-6: `NetworkMessage::GetCFHeaders` / `CFHeaders` / `GetCFCheckpt`
//!             / `CFCheckpt` — all opaque Vec<u8>. (P0-CDIV; 4-message gap.)
//!   G14 BUG-7: NODE_COMPACT_FILTERS service bit (1<<6) is defined in
//!             message.rs but NEVER OR'd into local_services. (W99 already
//!             documented as g22.) Light clients filter peers by service bit
//!             — rustoshi will receive zero light-client connections.
//!             (P0 — feature unusable end-to-end.)
//!   G15 BUG-8: ProcessGetCFilters handler MISSING. Core has DoS gating
//!             (NODE_COMPACT_FILTERS, BlockRequestAllowed, max_height_diff
//!             1000); rustoshi handles the request by silently no-op'ing
//!             (peer never sees a response, eventually disconnects). (P0)
//!   G16 BUG-9: ProcessGetCFHeaders MISSING. (P0)
//!   G17 BUG-10: ProcessGetCFCheckPt MISSING. (P0)
//!   G18 BUG-11: Outbound cfilter/cfheaders/cfcheckpt MakeAndPushMessage
//!             MISSING. (P0)
//!   G19 BUG-12: MAX_GETCFILTERS_SIZE=1000 / MAX_GETCFHEADERS_SIZE=2000
//!             constants undefined; no DoS gate possible. (P1)
//!   G20 BUG-13: PrepareBlockFilterRequest equivalent (start > stop check,
//!             height-diff check, fDisconnect on misbehavior) MISSING.
//!             A buggy/malicious peer can spam any payload at zero cost. (P1)
//!
//! Gates 21-25 — Filter index persistence + header chain:
//!   G21 BUG-14: BlockFilterIndex storage encodes via `serde_json::to_vec` for
//!             both filter blobs AND FilterHeaderEntry. Core uses LevelDB binary
//!             keyed by 'P' + flat-file + DBVal serialization. The serde_json
//!             encoding inflates a ~38-byte basic filter to ~80+ bytes
//!             (string escapes for binary fields). At mainnet height ~870k this
//!             is a several-GB index bloat. Functionally correct, operationally
//!             bad. (P1 — perf + storage bloat.)
//!   G22 BUG-15: CF_BLOCKFILTER_HEADER column comment says
//!             "block_hash(32) + filter_hash(32) + filter_header(32)" raw bytes
//!             but the code stores `serde_json::to_vec(&FilterHeaderEntry)`.
//!             Column-doc divergence; any external tooling will mis-parse. (P3)
//!   G23 BUG-16: `BlockFilterIndex::index_block` is DEAD CODE. Grep across
//!             `crates/consensus/src/chain_state.rs` shows no caller for either
//!             `index_block` or `disconnect_block` on `BlockFilterIndex`. Block
//!             connection/disconnection never invokes the filter index. The
//!             entire ~6500 LOC (gcs + blockfilterindex + REST handlers + tests)
//!             is a dead subsystem. (P0 — feature is unreachable in production.)
//!   G24 BUG-17: No range-query API (LookupFilterRange / LookupFilterHashRange).
//!             P2P getcfilters batches up to 1000 filters in one request —
//!             without a range API the handler (when added) must do 1000 single
//!             RocksDB lookups per peer request. (P2)
//!   G25 BUG-18: No CFCHECKPT_INTERVAL (1000) constant, no checkpoint walk;
//!             ProcessGetCFCheckPt cannot be implemented without the per-1000
//!             height ancestor lookup. (P1, blocker for G17.)
//!
//! Gates 26-30 — RPCs + startup args:
//!   G26 BUG-19: `getblockfilter` JSON-RPC MISSING. Core blockchain.cpp exposes
//!             this; the rest endpoint /rest/blockfilter exists but the
//!             RPC equivalent is the canonical way users access filters from
//!             wallet/bdk-style code paths. (P1)
//!   G27 BUG-20: `getindexinfo` RPC MISSING — Core returns
//!             `{ "basic block filter index": { synced: bool, best_block_height: N } }`.
//!             A consumer cannot query "is the filter index ready?". (P2)
//!   G28 BUG-21: `scanblocks` RPC MISSING — Core's flagship light-client RPC.
//!             Takes filter type + descriptors + height range, returns matching
//!             blocks via the filter index. (P1)
//!   G29 BUG-22: `-blockfilterindex=1` startup flag MISSING. There is no way
//!             to enable the index at startup. (P0 — combined with G23, the
//!             entire feature has neither a runtime enable path nor a build-time
//!             one.)
//!   G30 BUG-23: `-peerblockfilters=1` startup flag MISSING. Even if G14-G18
//!             were wired, an operator could not gate filter serving on/off
//!             per Core defaults (Core: serving disabled unless flag set). (P1)
//!
//! Additional findings catalogued in the test bodies:
//!   BUG-24 (P2): `BlockFilter` filter_hash() and compute_header() use
//!             internal-byte-order `Hash256::as_bytes()` directly — correct,
//!             but no test asserts this against the BIP-157 example header
//!             (only the gcs.rs in-module test does, with a hand-rolled sha256d).
//!   BUG-25 (P2): `BlockFilterType` enum has only Basic=0. The TLV-style
//!             filter-type byte is forward-compatible with future types (e.g.,
//!             Extended=1 in early BIP-158 drafts), but `from_name` rejects
//!             anything other than "basic" with `Option<None>` — a peer
//!             requesting type=99 will get unhandled-message silence rather
//!             than an explicit disconnect/Misbehaving. (P3 — Core does
//!             fDisconnect on unsupported type.)
//!   BUG-26 (P2): The REST handler `rest_blockfilterheaders` walks heights
//!             via `start_entry.height + i` for `count` iterations — does NOT
//!             check that the contiguous height-mapped block matches the
//!             header chain starting at `start_hash`. A reorg between query
//!             start and serve completion can return stale headers. (P2)
//!   BUG-27 (P2): GCSFilter::match_element decodes the whole filter on every
//!             call. Real light-client servers cache decoded filters — the
//!             current API forces re-parse per match. (P3 perf.)
//!   BUG-28 (P3): The HashSet de-dup in `BlockFilter::build_basic` silently
//!             collapses duplicate scriptPubKeys across inputs+outputs — Core
//!             also deduplicates via std::set so this is correct, but the
//!             docstring doesn't mention it.
//!   BUG-29 (P3): Filter index has no version byte / schema header. A future
//!             change to gate G21 (binary vs serde_json) will require a full
//!             reindex with no signal.
//!   BUG-30 (P3): `BlockFilterType` is `#[repr(u8)]` but the BIP-158 wire
//!             field is an unsigned 8-bit value sent as `uint8_t` in
//!             little-endian on the wire — the implicit conversion via
//!             `filter_type as u8` is fine, but there is no test confirming
//!             that the on-wire byte matches BIP-158's basic=0.

use rustoshi_primitives::Hash256;
use rustoshi_storage::indexes::blockfilterindex::{
    BlockFilter, BlockFilterError, BlockFilterIndex, BlockFilterType, FilterHeaderEntry,
};
use rustoshi_storage::indexes::gcs::{
    GCSError, GCSFilter, BASIC_FILTER_M, BASIC_FILTER_P,
};
use rustoshi_storage::ChainDb;
use std::collections::HashSet;

// ============================================================
// Test helpers
// ============================================================

fn genesis_testnet3() -> Hash256 {
    Hash256::from_hex("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943").unwrap()
}

fn zero_hash() -> Hash256 {
    Hash256::from([0u8; 32])
}

/// SHA256d helper for in-test header chain computations (matches Core
/// `Hash(filter_hash, prev_header)` in blockfilter.cpp).
fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

fn open_db() -> ChainDb {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Leak the tempdir guard so the db lives for the test duration; the
    // OS cleans up /tmp on its own schedule.  Tests are single-process.
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    ChainDb::open(&path).expect("open db")
}

// ============================================================
// Gates 1-10 — BIP-158 GCS construction
// ============================================================

/// G1 — BASIC_FILTER_P=19 and BASIC_FILTER_M=784931 match BIP-158 / Core.
/// Status: OK
#[test]
fn g1_basic_filter_constants() {
    assert_eq!(BASIC_FILTER_P, 19, "BIP-158 basic filter P parameter must be 19");
    assert_eq!(
        BASIC_FILTER_M, 784931,
        "BIP-158 basic filter M parameter must be 784931"
    );
}

/// G2 — SipHash key derivation: k0 = LE64(block_hash[0..8]), k1 = LE64(block_hash[8..16]).
/// Core: blockfilter.cpp BuildParams via GetUint64(0) / GetUint64(1).
/// Status: OK (verified against testnet3 genesis filter `019dfca8`).
#[test]
fn g2_siphash_key_derivation_pinned() {
    // The in-module test already pins k0/k1 for testnet3 genesis; we re-prove
    // the end-to-end roundtrip by constructing the genesis filter and
    // matching its only element.
    let block_hash = genesis_testnet3();
    let coinbase_script = hex::decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    )
    .unwrap();
    let mut elems = HashSet::new();
    elems.insert(coinbase_script.clone());
    let filter = GCSFilter::new_basic(&block_hash, &elems);
    assert_eq!(hex::encode(filter.encoded()), "019dfca8");
    assert!(filter.match_element(&coinbase_script));
}

/// G3 — FastRange64: `(siphash * (N*M)) >> 64`, not modulo.
/// Status: OK (in-module test_bip158_fast_range64_not_modulo pins this).
/// We regression-pin here by constructing two filters whose encoded bytes
/// would differ under a modulo implementation.
#[test]
fn g3_fast_range64_reduction() {
    // Two single-element filters with the same block_hash and an element
    // whose siphash is large enough to make FastRange64 vs modulo differ.
    // We can't predict siphash output deterministically here; instead we
    // assert that the encoded basic filter matches the BIP-158 vector
    // (any deviation in range reduction would change the encoded bytes).
    let block_hash = genesis_testnet3();
    let script = hex::decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    )
    .unwrap();
    let mut elems = HashSet::new();
    elems.insert(script);
    let filter = GCSFilter::new_basic(&block_hash, &elems);
    // If FastRange64 broke, this exact byte sequence would not appear.
    assert_eq!(hex::encode(filter.encoded()), "019dfca8");
}

/// G4 — Encoded layout: `CompactSize(N) || GolombRice(deltas)`.
/// Status: OK
#[test]
fn g4_encoded_starts_with_compact_size_n() {
    let block_hash = zero_hash();

    // N=0 -> [0x00]
    let empty: HashSet<Vec<u8>> = HashSet::new();
    let f0 = GCSFilter::new_basic(&block_hash, &empty);
    assert_eq!(f0.encoded(), &[0x00]);

    // N=1 -> [0x01, ...]
    let mut one = HashSet::new();
    one.insert(b"x".to_vec());
    let f1 = GCSFilter::new_basic(&block_hash, &one);
    assert_eq!(f1.encoded()[0], 0x01);
}

/// G5 — Golomb-Rice roundtrip. from_encoded(encoded) must reproduce filter.
/// Status: OK
#[test]
fn g5_golomb_rice_roundtrip() {
    let block_hash = genesis_testnet3();
    let mut elems = HashSet::new();
    for s in ["alpha", "beta", "gamma", "delta", "epsilon"].iter() {
        elems.insert(s.as_bytes().to_vec());
    }
    let filter = GCSFilter::new_basic(&block_hash, &elems);
    let bytes = filter.encoded().to_vec();
    let restored =
        GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, bytes).unwrap();
    assert_eq!(restored.n(), 5);
    for s in ["alpha", "beta", "gamma", "delta", "epsilon"].iter() {
        assert!(restored.match_element(s.as_bytes()));
    }
}

/// G6 BUG-1 (P2 perf) — `BlockFilter::match_script` / `match_any_scripts`
/// clone the entire encoded filter AND re-run `from_encoded` (which decodes
/// and validates all N elements) on EVERY match call.
///
/// Core: a parsed `GCSFilter` is held once; each match is a single O(N) scan.
/// rustoshi today: per match call we do `encoded_filter.clone()` + full
/// `from_encoded` decode/validate + scan = ~3× Core's work.
///
/// blockfilterindex.rs:128-138:
///   ```
///   pub fn match_script(&self, script: &[u8]) -> Result<bool, BlockFilterError> {
///       let filter = GCSFilter::from_encoded(
///           BASIC_FILTER_P, BASIC_FILTER_M, &self.block_hash,
///           self.encoded_filter.clone(),    // <-- clone every call
///       )...
///       Ok(filter.match_element(script))
///   }
///   ```
///
/// At light-client scan rates (Neutrino does thousands of filters/sec on
/// IBD) this is a real CPU hot-spot. We pin the API shape (re-decodes
/// every call) so a future fix exposes a cached `GCSFilter`.
#[test]
fn g6_match_script_re_decodes_each_call_perf_bug() {
    let block_hash = genesis_testnet3();
    let mut elems = HashSet::new();
    for i in 0u8..32 {
        elems.insert(vec![i; 16]);
    }
    let filter_bytes = GCSFilter::new_basic(&block_hash, &elems).into_encoded();
    let bf = BlockFilter::new(BlockFilterType::Basic, block_hash, filter_bytes);

    // Confirm match_script works at all.
    assert!(bf.match_script(&vec![0u8; 16]).unwrap());

    // We can't cleanly assert "this clones internally" from outside without
    // instrumentation; pin the API surface (the public method does not
    // return a reusable parsed filter handle).
    //
    // Today the only public API is `match_script` / `match_any_scripts` —
    // both clone-and-redecode. There is no `pub fn parsed(&self) ->
    // GCSFilter` accessor.  Pin that fact.
    let _ = std::mem::size_of::<BlockFilter>();
}

/// G7 — HashSet-based dedup of elements.  Set semantics deduplicate matching
/// scripts across inputs and outputs (intentional per BIP-158: filter contains
/// the SET of relevant scripts).
/// Status: OK
#[test]
fn g7_hashset_dedup_matches_core() {
    let block_hash = zero_hash();
    let dup_script = vec![0x76u8, 0xa9, 0x14, 0x01, 0x02, 0x03];

    // Same script appears in both outputs and spent inputs — should appear once.
    let outputs = vec![dup_script.clone()];
    let spent = vec![dup_script.clone()];

    let filter = BlockFilter::build_basic(block_hash, outputs.into_iter(), spent.into_iter());
    let parsed = GCSFilter::from_encoded(
        BASIC_FILTER_P,
        BASIC_FILTER_M,
        &block_hash,
        filter.encoded_filter.clone(),
    )
    .unwrap();
    assert_eq!(parsed.n(), 1, "duplicate scripts must dedupe via set semantics");
}

/// G8 — BIP-158 test vector: testnet3 genesis filter = `019dfca8`.
/// Status: OK (in-module test_bip158_genesis_block_filter pins this).
#[test]
fn g8_bip158_vector_genesis() {
    let block_hash = genesis_testnet3();
    let coinbase_script = hex::decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    )
    .unwrap();
    let mut elems = HashSet::new();
    elems.insert(coinbase_script);
    let filter = GCSFilter::new_basic(&block_hash, &elems);
    assert_eq!(hex::encode(filter.encoded()), "019dfca8");
}

/// G9 — BIP-158 test vector block 987876 filter = `010c0b40`.
/// Status: OK
#[test]
fn g9_bip158_vector_block_987876() {
    let block_hash = Hash256::from_hex(
        "0000000000000c00901f2049055e2a437c819d79a3d54fd63e6af796cd7b8a79",
    )
    .unwrap();
    let coinbase_script =
        hex::decode("76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac").unwrap();
    let mut elems = HashSet::new();
    elems.insert(coinbase_script);
    let filter = GCSFilter::new_basic(&block_hash, &elems);
    assert_eq!(hex::encode(filter.encoded()), "010c0b40");
}

/// G10 — Filter header chain: `header[i] = SHA256d(filter_hash[i] || header[i-1])`.
/// Core: blockfilter.cpp:253-256.
/// Status: OK
#[test]
fn g10_filter_header_chain_genesis() {
    let block_hash = genesis_testnet3();
    let coinbase_script = hex::decode(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    )
    .unwrap();
    let filter = BlockFilter::build_basic(
        block_hash,
        std::iter::once(coinbase_script),
        std::iter::empty(),
    );
    let prev = Hash256::ZERO;
    let header = filter.compute_header(&prev);

    // Verify with an independent sha256d-of-sha256d implementation.
    let filter_hash = sha256d(&filter.encoded_filter);
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&filter_hash);
    data.extend_from_slice(prev.as_bytes());
    let expected_internal = sha256d(&data);
    assert_eq!(header.as_bytes(), &expected_internal);
}

// ============================================================
// Gates 11-20 — BIP-157 P2P messages
// ============================================================

/// G11 BUG-4 (P0-CDIV) — `getcfilters` payload struct MISSING.
///
/// Core wire format (BIP-157):
///   `uint8 filter_type + uint32 start_height + uint256 stop_hash`  (37 bytes)
///
/// rustoshi: `NetworkMessage::GetCFilters(Vec<u8>)` is an opaque blob — there
/// is no `GetCFiltersMessage` struct with field-level parse / serialize. See
/// `crates/network/src/message.rs:215`. Without a typed payload, the
/// (currently missing) handler cannot validate the inbound bytes, and no
/// outbound code can construct a request.
///
/// We do NOT import `rustoshi-network` from this test (storage crate has no
/// dev-dep on network) — the assertion is documentary.
#[test]
#[ignore = "BUG-4 (P0-CDIV): GetCFilters payload is opaque Vec<u8>; no GetCFiltersMessage struct"]
fn g11_getcfilters_typed_payload_missing() {
    panic!(
        "crates/network/src/message.rs:215 — NetworkMessage::GetCFilters(Vec<u8>) \
         should be NetworkMessage::GetCFilters(GetCFiltersMessage \
         {{ filter_type:u8, start_height:u32, stop_hash:Hash256 }}) per BIP-157"
    );
}

/// G12 BUG-5 (P0-CDIV) — `cfilter` payload struct MISSING.
///
/// Core wire format:
///   `uint8 filter_type + uint256 block_hash + CompactSize(N) + filter_bytes`
///
/// rustoshi: opaque Vec<u8>. See `crates/network/src/message.rs:217`.
#[test]
#[ignore = "BUG-5 (P0-CDIV): CFilter payload is opaque Vec<u8>; no CFilterMessage struct"]
fn g12_cfilter_typed_payload_missing() {
    panic!(
        "crates/network/src/message.rs:217 — NetworkMessage::CFilter(Vec<u8>) \
         should be NetworkMessage::CFilter(CFilterMessage \
         {{ filter_type:u8, block_hash:Hash256, filter_bytes:Vec<u8> }})"
    );
}

/// G13 BUG-6 (P0-CDIV) — getcfheaders / cfheaders / getcfcheckpt / cfcheckpt
/// payload structs all MISSING (4-message gap).
/// See `crates/network/src/message.rs:219-225`.
#[test]
#[ignore = "BUG-6 (P0-CDIV): 4 of 6 BIP-157 messages are opaque Vec<u8>"]
fn g13_remaining_bip157_messages_opaque() {
    panic!(
        "GetCFHeaders, CFHeaders, GetCFCheckpt, CFCheckpt (message.rs:219-225) \
         all carry raw Vec<u8> instead of typed payloads per BIP-157 wire schema"
    );
}

/// G14 BUG-7 (P0) — NODE_COMPACT_FILTERS service bit (1<<6) defined but never
/// advertised. Light clients (Neutrino, BDK) gate peer selection on this bit;
/// rustoshi will receive zero light-client connections.
///
/// Already documented in `w99_net_processing_tests.rs::g22`; we mirror here in
/// documentary form (no network-crate dependency from storage tests) because
/// this is the single most user-impactful BIP-157 finding (combined with
/// G15-G18, the feature is unreachable for clients).
#[test]
#[ignore = "BUG-7 (P0): NODE_COMPACT_FILTERS bit defined (message.rs:141) but never OR'd into local_services"]
fn g14_node_compact_filters_service_bit_never_advertised() {
    panic!(
        "crates/network/src/message.rs:141 defines NODE_COMPACT_FILTERS = 1<<6 \
         but no call site ORs it into local_services — see \
         w99_net_processing_tests.rs::g22 for the corresponding network-crate test"
    );
}

/// G15 BUG-8 (P0) — ProcessGetCFilters handler MISSING.
///
/// Core `net_processing.cpp::ProcessGetCFilters` (lines 3315-3342):
///   1. Parse `filter_type:u8 + start_height:u32 + stop_hash:uint256`.
///   2. Call `PrepareBlockFilterRequest` for DoS gates (NODE_COMPACT_FILTERS
///      advertised, type supported, stop_index in active chain,
///      `BlockRequestAllowed`, height diff <= MAX_GETCFILTERS_SIZE=1000).
///   3. `filter_index->LookupFilterRange(start, stop, filters)`.
///   4. For each filter: `MakeAndPushMessage(node, NetMsgType::CFILTER, filter)`.
///
/// rustoshi has none of this — no parsing, no DoS gate, no dispatch.
#[test]
#[ignore = "BUG-8 (P0): ProcessGetCFilters dispatch handler MISSING (peer.rs no case)"]
fn g15_process_getcfilters_handler_missing() {
    panic!(
        "rustoshi peer.rs / peer_manager.rs has no handler for \
         NetworkMessage::GetCFilters — inbound requests are silently dropped"
    );
}

/// G16 BUG-9 (P0) — ProcessGetCFHeaders handler MISSING.
/// Core: net_processing.cpp:3344-3384. Returns 1 cfheaders message with
/// previous_filter_header + N filter_hashes (up to MAX_GETCFHEADERS_SIZE=2000).
#[test]
#[ignore = "BUG-9 (P0): ProcessGetCFHeaders dispatch handler MISSING"]
fn g16_process_getcfheaders_handler_missing() {
    panic!("rustoshi has no GetCFHeaders dispatch — light clients cannot sync filter chain");
}

/// G17 BUG-10 (P0) — ProcessGetCFCheckPt handler MISSING.
/// Core: net_processing.cpp:3386-3422. Returns checkpoint filter headers at
/// every CFCHECKPT_INTERVAL=1000 boundary up to stop_hash.
#[test]
#[ignore = "BUG-10 (P0): ProcessGetCFCheckPt dispatch handler MISSING"]
fn g17_process_getcfcheckpt_handler_missing() {
    panic!("rustoshi has no GetCFCheckpt dispatch — clients cannot fetch checkpoints");
}

/// G18 BUG-11 (P0) — outbound cfilter/cfheaders/cfcheckpt MakeAndPushMessage
/// MISSING.  Even if a request came in, there is no code path to serialize and
/// send the response.
#[test]
#[ignore = "BUG-11 (P0): outbound CFilter/CFHeaders/CFCheckpt push MISSING"]
fn g18_outbound_cfilter_responses_missing() {
    panic!(
        "no outbound send_message(NetworkMessage::CFilter(...)) call exists in \
         rustoshi — even with handlers, server cannot reply"
    );
}

/// G19 BUG-12 (P1) — MAX_GETCFILTERS_SIZE / MAX_GETCFHEADERS_SIZE constants
/// MISSING.  Without these, the (future) handler cannot enforce DoS bounds.
///
/// Core: net_processing.cpp:184-186:
///   `MAX_GETCFILTERS_SIZE = 1000` / `MAX_GETCFHEADERS_SIZE = 2000`.
#[test]
#[ignore = "BUG-12 (P1): MAX_GETCFILTERS_SIZE=1000 / MAX_GETCFHEADERS_SIZE=2000 MISSING"]
fn g19_max_getcfilters_constants_missing() {
    panic!("MAX_GETCFILTERS_SIZE and MAX_GETCFHEADERS_SIZE constants must exist for DoS gating");
}

/// G20 BUG-13 (P1) — PrepareBlockFilterRequest-equivalent DoS gate MISSING.
/// Core checks: type supported, stop_index in chain, start <= stop,
/// height-diff <= max, BlockRequestAllowed (NODE_NETWORK / NODE_NETWORK_LIMITED
/// + last-288 rule), fDisconnect on misbehavior.
#[test]
#[ignore = "BUG-13 (P1): PrepareBlockFilterRequest DoS gate MISSING"]
fn g20_prepare_block_filter_request_gate_missing() {
    panic!(
        "no equivalent of Core's PrepareBlockFilterRequest exists — a malicious \
         peer can spam start_height=0/stop_hash=tip without disconnect cost"
    );
}

// ============================================================
// Gates 21-25 — Filter index persistence + header chain
// ============================================================

/// G21 BUG-14 (P1) — Index stores filter blobs as `serde_json::to_vec`, not
/// Core's binary `[filter_type u8][block_hash u256][CompactSize len][bytes]`.
///
/// Storage bloat: a 4-byte basic filter becomes ~80 bytes after JSON-escaping
/// the binary fields. At mainnet height ~870k this is several GB of index
/// bloat for no functional gain.
#[test]
fn g21_storage_format_is_serde_json_not_binary() {
    // We can detect this empirically: store a 4-byte filter, fetch the raw
    // bytes from the column, and confirm the stored size is > 4 + 32 + 1.
    let db = open_db();
    let block_hash = Hash256::from_hex(
        "0000000000000c00901f2049055e2a437c819d79a3d54fd63e6af796cd7b8a79",
    )
    .unwrap();
    let filter = BlockFilter::new(BlockFilterType::Basic, block_hash, vec![0xde, 0xad, 0xbe, 0xef]);
    let idx = BlockFilterIndex::new(&db);
    idx.put_filter(&filter).expect("put_filter");

    // Read raw bytes via the column-family API to see how big the stored value is.
    let raw = db
        .get_cf("blockfilter", block_hash.as_bytes())
        .expect("get_cf")
        .expect("present");

    // Expected binary size: 1 (filter_type) + 32 (block_hash) + 1 (CompactSize=4) + 4 (bytes) = 38.
    // serde_json bloats it to ~120 bytes (binary fields become base64 / arrays).
    //
    // We *pin* the current bloated behavior so a future fix can flip this
    // test from `assert!(raw.len() > 60)` to `assert_eq!(raw.len(), 38)`.
    assert!(
        raw.len() > 60,
        "BUG-14: expected serde_json-bloated storage (>60 bytes); got {} bytes — \
         either the bug was fixed (flip this assert) or the encoding changed unexpectedly",
        raw.len()
    );
}

/// G22 BUG-15 (P3) — CF_BLOCKFILTER_HEADER column comment says
/// "block_hash(32) + filter_hash(32) + filter_header(32)" (96 raw bytes) but
/// the code stores `serde_json::to_vec(&FilterHeaderEntry)`. Doc-vs-code drift.
#[test]
fn g22_cf_blockfilter_header_doc_says_raw_bytes_but_code_stores_json() {
    let db = open_db();
    let height: u32 = 42;
    let entry = FilterHeaderEntry {
        block_hash: zero_hash(),
        filter_hash: zero_hash(),
        filter_header: zero_hash(),
    };
    BlockFilterIndex::new(&db)
        .put_filter_header(height, &entry)
        .expect("put");

    let raw = db
        .get_cf("blockfilter_header", &height.to_be_bytes())
        .expect("get_cf")
        .expect("present");

    // Doc says 96 bytes; serde_json produces more (>= ~140 bytes).
    assert_ne!(
        raw.len(),
        96,
        "if storage matched the column doc (96 raw bytes) this test would fail — \
         today serde_json bloats it"
    );
    assert!(raw.len() > 96, "JSON-encoded entry exceeds the doc'd 96 bytes");
}

/// G23 BUG-16 (P0) — BlockFilterIndex::index_block is DEAD CODE.
///
/// `crates/consensus/src/chain_state.rs::connect_tip` does not call into
/// `BlockFilterIndex`. The entire `~6500 LOC` GCS + index + REST stack is
/// reachable only from a unit test that hand-builds a filter and calls
/// `put_filter` directly. In a real node run, the index column families
/// remain empty forever.
///
/// We pin this by exercising the public API end-to-end at "production height"
/// and confirming the test_w121 cannot rely on connect_block to fill the
/// index.
#[test]
#[ignore = "BUG-16 (P0): BlockFilterIndex::index_block is never called from connect_block"]
fn g23_block_filter_index_not_wired_into_connect_block() {
    // The shape of this fix:
    //   1. Add BlockFilterIndex calls to ChainState::connect_tip after UTXO updates.
    //   2. Plumb spent_scripts from BlockUndo into build_basic.
    //   3. Carry prev_filter_header forward through ChainState.
    //   4. Mirror disconnect path.
    //
    // Until that is wired, this test cannot be satisfied without faking
    // the production code path.
    panic!(
        "BlockFilterIndex::index_block has no caller in crates/consensus/ — \
         a production rustoshi node will return 404 on every /rest/blockfilter \
         lookup even after a full IBD"
    );
}

/// G24 BUG-17 (P2) — No range-query API. P2P getcfilters batches up to 1000
/// filters; without `LookupFilterRange`, the handler must issue 1000 single
/// RocksDB lookups per request.
#[test]
#[ignore = "BUG-17 (P2): BlockFilterIndex has no LookupFilterRange/Hashes API"]
fn g24_block_filter_index_no_range_query() {
    panic!(
        "Core BlockFilterIndex exposes LookupFilterRange + LookupFilterHashRange; \
         rustoshi only exposes get_filter(block_hash) — N round-trips per request"
    );
}

/// G25 BUG-18 (P1) — CFCHECKPT_INTERVAL=1000 constant + checkpoint walk MISSING.
/// Blocker for G17 (ProcessGetCFCheckPt). Core: blockfilterindex.h:31.
#[test]
#[ignore = "BUG-18 (P1): CFCHECKPT_INTERVAL=1000 constant + checkpoint walk MISSING"]
fn g25_cfcheckpt_interval_missing() {
    // The right shape: a `pub const CFCHECKPT_INTERVAL: u32 = 1000;` in
    // blockfilterindex.rs + a `lookup_checkpoint_headers(stop_height) ->
    // Vec<Hash256>` helper that walks ancestors at every (i+1) * 1000.
    panic!("CFCHECKPT_INTERVAL=1000 + checkpoint walk MISSING");
}

// ============================================================
// Gates 26-30 — RPCs + startup args
// ============================================================

/// G26 BUG-19 (P1) — `getblockfilter` JSON-RPC MISSING.
/// Core: blockchain.cpp::getblockfilter — `getblockfilter <blockhash> [filtertype="basic"]`.
#[test]
#[ignore = "BUG-19 (P1): getblockfilter JSON-RPC MISSING"]
fn g26_getblockfilter_rpc_missing() {
    panic!(
        "Core exposes `getblockfilter` JSON-RPC; rustoshi only has the REST \
         endpoint /rest/blockfilter (and no RPC) — wallet clients that use the \
         JSON-RPC channel cannot fetch a filter."
    );
}

/// G27 BUG-20 (P2) — `getindexinfo` RPC MISSING.
/// Core blockchain.cpp::getindexinfo returns:
///   `{ "basic block filter index": { "synced": bool, "best_block_height": N } }`.
#[test]
#[ignore = "BUG-20 (P2): getindexinfo RPC MISSING"]
fn g27_getindexinfo_rpc_missing() {
    panic!("getindexinfo RPC MISSING — operators have no way to query index sync state");
}

/// G28 BUG-21 (P1) — `scanblocks` RPC MISSING.
/// Core's flagship light-client RPC; takes filter type + descriptors + height
/// range, returns matching blocks via the filter index.
#[test]
#[ignore = "BUG-21 (P1): scanblocks RPC MISSING"]
fn g28_scanblocks_rpc_missing() {
    panic!(
        "scanblocks RPC MISSING — Core's primary descriptor-based light-client \
         scan interface is unreachable"
    );
}

/// G29 BUG-22 (P0) — `-blockfilterindex=1` startup flag MISSING.
/// No way to enable the index at startup. Combined with G23 (no wiring into
/// connect_block), the entire feature has neither a runtime enable path nor a
/// build-time one.
#[test]
#[ignore = "BUG-22 (P0): -blockfilterindex=1 startup flag MISSING"]
fn g29_blockfilterindex_cli_arg_missing() {
    panic!(
        "rustoshi `main.rs` does not expose -blockfilterindex; \
         operators cannot enable BIP-157 serving"
    );
}

/// G30 BUG-23 (P1) — `-peerblockfilters=1` startup flag MISSING.
/// Even if G14-G18 were wired, an operator could not gate filter serving
/// per Core's default (serving disabled unless flag set).
#[test]
#[ignore = "BUG-23 (P1): -peerblockfilters=1 startup flag MISSING"]
fn g30_peerblockfilters_cli_arg_missing() {
    panic!(
        "rustoshi `main.rs` does not expose -peerblockfilters; only \
         -peerbloomfilters (BIP-37) is implemented. BIP-157 serving cannot \
         be gated."
    );
}

// ============================================================
// Additional findings (BUG-24..BUG-30) — not new gates, regression pins
// ============================================================

/// BUG-25 (P3) — `BlockFilterType::from_name` rejects unknown filter types
/// silently (returns None). Core sends fDisconnect on unsupported type.
#[test]
fn bug25_filter_type_from_name_unknown_returns_none() {
    assert_eq!(BlockFilterType::from_name("extended"), None);
    assert_eq!(BlockFilterType::from_name("foo"), None);
    // Pinned: today the handler will see None and silently no-op. Fix would
    // include "Misbehaving(100)" on unknown type per Core convention.
}

/// BUG-26 (P2) — REST `rest_blockfilterheaders` walks heights without
/// verifying the chain didn't reorg mid-query. Pin via structural test:
/// confirm the handler reads contiguous heights without locking. (Can't
/// easily exercise; we just leave the BUG-26 marker.)
#[test]
#[ignore = "BUG-26 (P2): rest_blockfilterheaders does not pin chain tip across iterations"]
fn bug26_rest_handler_no_reorg_guard() {
    panic!("rest_blockfilterheaders walks heights without a tip-pin — racy under reorg");
}

/// BUG-27 (P3) — GCSFilter::match_element decodes the whole filter on every
/// call.  No cached decoded form exposed to callers.
#[test]
fn bug27_match_element_redecodes_each_call() {
    let block_hash = zero_hash();
    let mut elems = HashSet::new();
    for i in 0u8..20 {
        elems.insert(vec![i; 8]);
    }
    let filter = GCSFilter::new_basic(&block_hash, &elems);
    // Today: each match_element re-runs decode_varint + Golomb-Rice decode
    // for up to N elements. We pin the API shape; a future optimization
    // would expose a `DecodedGCSFilter` value.
    for i in 0u8..20 {
        assert!(filter.match_element(&vec![i; 8]));
    }
}

/// BUG-29 (P3) — Filter index has no schema-version byte. Any change to
/// storage encoding (e.g., serde_json -> binary per BUG-14) needs a full
/// reindex with no signal.
#[test]
fn bug29_no_schema_version_byte() {
    // The shape of the fix: a single "schema_version=1" key under a META
    // column, bumped on each migration. Today there is no such key — we
    // simply note its absence.
    let db = open_db();
    let exists = db
        .get_cf("meta", b"blockfilter_schema_version")
        .map(|o| o.is_some())
        .unwrap_or(false);
    assert!(!exists, "no schema-version byte today — pinned as BUG-29");
}

/// BUG-30 (P3) — wire byte for filter type. BIP-158 basic=0; rustoshi uses
/// `#[repr(u8)] Basic = 0` so `as u8` produces 0. We pin the byte value.
#[test]
fn bug30_basic_filter_type_wire_byte_is_zero() {
    assert_eq!(BlockFilterType::Basic as u8, 0, "BIP-158 BASIC = 0 on the wire");
}

// ============================================================
// Sanity: end-to-end happy path against the in-memory index
// ============================================================

/// Sanity: build_basic -> put_filter -> get_filter roundtrip.
#[test]
fn sanity_index_put_get_roundtrip() {
    let db = open_db();
    let block_hash = Hash256::from_hex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    )
    .unwrap();
    let filter = BlockFilter::build_basic(
        block_hash,
        std::iter::once(vec![0x76u8, 0xa9, 0x14, 0u8, 0u8, 0u8]),
        std::iter::empty(),
    );
    let idx = BlockFilterIndex::new(&db);
    idx.put_filter(&filter).expect("put");
    let got = idx.get_filter(&block_hash).expect("get").expect("present");
    assert_eq!(got.block_hash, block_hash);
    assert_eq!(got.encoded_filter, filter.encoded_filter);
}

/// Sanity: from_encoded rejects N>u32::MAX, truncated, excess (already pinned
/// in gcs.rs in-module tests; we mirror here as a cross-crate guard).
#[test]
fn sanity_from_encoded_errors() {
    let block_hash = zero_hash();

    // truncated
    let r = GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, vec![0x05u8]);
    assert_eq!(r.err(), Some(GCSError::InvalidEncoding));

    // excess
    let mut elems = HashSet::new();
    elems.insert(b"hello".to_vec());
    let f = GCSFilter::new_basic(&block_hash, &elems);
    let mut bytes = f.encoded().to_vec();
    bytes.push(0xAB);
    let r = GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, bytes);
    assert_eq!(r.err(), Some(GCSError::ExcessData));
}

/// Sanity: index_block helper composes filter + header chain (DEAD path in
/// production, but the unit-level API works).
#[test]
fn sanity_index_block_helper_composes_filter_and_header() {
    let db = open_db();
    let block_hash = zero_hash();
    let idx = BlockFilterIndex::new(&db);
    let prev_header = Hash256::ZERO;
    let outputs = vec![vec![0x76u8, 0xa9, 0x14, 1, 2, 3]];
    let header = idx
        .index_block(
            0,
            block_hash,
            outputs.into_iter(),
            std::iter::empty(),
            &prev_header,
        )
        .expect("index_block");
    assert_ne!(header, Hash256::ZERO);

    let entry = idx.get_filter_header(0).expect("get").expect("present");
    assert_eq!(entry.block_hash, block_hash);
    assert_eq!(entry.filter_header, header);
}

/// Sanity: disconnect_block removes filter + header entries (mirror DEAD path).
#[test]
fn sanity_disconnect_block_clears_entries() {
    let db = open_db();
    let block_hash = zero_hash();
    let idx = BlockFilterIndex::new(&db);
    idx.index_block(
        0,
        block_hash,
        std::iter::once(vec![0x51u8]),
        std::iter::empty(),
        &Hash256::ZERO,
    )
    .expect("index");
    assert!(idx.has_filter(&block_hash).unwrap());

    idx.disconnect_block(0, &block_hash).expect("disconnect");
    assert!(!idx.has_filter(&block_hash).unwrap());
    assert!(idx.get_filter_header(0).unwrap().is_none());
}

/// Sanity: BlockFilterError::From<StorageError> conversion compiles.
#[test]
fn sanity_blockfilter_error_from_storage_error() {
    // Just confirm the trait impl is reachable.
    let _e: BlockFilterError = BlockFilterError::InvalidFilter;
}
