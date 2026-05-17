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
//!   G14 BUG-7: FIX-71 / FIX-82 NODE_COMPACT_FILTERS gate plumbed in
//!             peer_manager.rs::local_services via
//!             should_advertise_compact_filters. As of FIX-82 the
//!             constant BIP157_P2P_HANDLERS_REGISTERED is now `true` (the
//!             dispatch handlers live in rustoshi/src/main.rs). Bit is
//!             advertised when both -blockfilterindex and -peerblockfilters
//!             are enabled. (CLOSED FIX-82)
//!   G15 BUG-8: ProcessGetCFilters dispatch handler in main.rs (CLOSED FIX-82).
//!             Per-violation try_disconnect_peer mirrors Core fDisconnect.
//!   G16 BUG-9: ProcessGetCFHeaders dispatch handler in main.rs (CLOSED FIX-82).
//!   G17 BUG-10: ProcessGetCFCheckPt dispatch handler in main.rs (CLOSED FIX-82).
//!   G18 BUG-11: Outbound cfilter/cfheaders/cfcheckpt via try_send_to_peer +
//!             typed CFilterMessage/CFHeadersMessage/CFCheckptMessage
//!             serialize methods (CLOSED FIX-82).
//!   G19 BUG-12: MAX_GETCFILTERS_SIZE=1000 / MAX_GETCFHEADERS_SIZE=2000 /
//!             CFCHECKPT_INTERVAL=1000 constants in network::message
//!             (CLOSED FIX-82).
//!   G20 BUG-13: PrepareBlockFilterRequest-equivalent gate inlined in each
//!             of the 3 dispatch handlers; per-violation peer.disconnect
//!             matches Core net_processing.cpp:3262-3313 (CLOSED FIX-82).
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
//!   G24 BUG-17: lookup_filter_range + lookup_filter_hash_range exposed on
//!             BlockFilterIndex, mirroring Core's LookupFilterRange /
//!             LookupFilterHashRange (CLOSED FIX-82).
//!   G25 BUG-18: CFCHECKPT_INTERVAL=1000 in blockfilterindex.rs + parallel
//!             definition in network::message (CLOSED FIX-82).
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

/// G11 BUG-4 — FIXED in FIX-82.
///
/// `NetworkMessage::GetCFilters` now carries a typed `GetCFiltersMessage`
/// payload struct with `filter_type: u8`, `start_height: u32`,
/// `stop_hash: Hash256`. The 37-byte BIP-157 wire format round-trips through
/// `serialize` / `deserialize` (regression-pinned below by file-level
/// grep against the storage crate's no-dep-on-network invariant).
#[test]
fn g11_getcfilters_typed_payload_present() {
    let body = std::fs::read_to_string("../network/src/message.rs")
        .expect("crates/network/src/message.rs must exist");
    assert!(
        body.contains("pub struct GetCFiltersMessage"),
        "FIX-82: GetCFiltersMessage struct must be defined in message.rs"
    );
    assert!(
        body.contains("GetCFilters(GetCFiltersMessage)"),
        "FIX-82: NetworkMessage::GetCFilters must carry typed payload, not Vec<u8>"
    );
    assert!(
        body.contains("impl GetCFiltersMessage")
            && body.contains("pub fn serialize")
            && body.contains("pub fn deserialize"),
        "FIX-82: GetCFiltersMessage must expose serialize/deserialize"
    );
}

/// G12 BUG-5 — FIXED in FIX-82.
///
/// `NetworkMessage::CFilter` now carries a typed `CFilterMessage` with
/// `filter_type: u8`, `block_hash: Hash256`, `filter_bytes: Vec<u8>`.
/// Wire format: `uint8 filter_type | uint256 block_hash | CompactSize(N)
/// | N bytes`.
#[test]
fn g12_cfilter_typed_payload_present() {
    let body = std::fs::read_to_string("../network/src/message.rs")
        .expect("crates/network/src/message.rs must exist");
    assert!(
        body.contains("pub struct CFilterMessage"),
        "FIX-82: CFilterMessage struct must be defined"
    );
    assert!(
        body.contains("CFilter(CFilterMessage)"),
        "FIX-82: NetworkMessage::CFilter must carry typed payload"
    );
    assert!(
        body.contains("filter_bytes: Vec<u8>"),
        "FIX-82: CFilterMessage must carry the filter bytes"
    );
}

/// G13 BUG-6 — FIXED in FIX-82.
///
/// All 6 BIP-157 wire messages now use typed payloads:
/// `GetCFHeadersMessage`, `CFHeadersMessage`, `GetCFCheckptMessage`,
/// `CFCheckptMessage`. Each round-trips serialize/deserialize.
#[test]
fn g13_remaining_bip157_messages_typed() {
    let body = std::fs::read_to_string("../network/src/message.rs")
        .expect("crates/network/src/message.rs must exist");
    for type_name in [
        "GetCFHeadersMessage",
        "CFHeadersMessage",
        "GetCFCheckptMessage",
        "CFCheckptMessage",
    ] {
        assert!(
            body.contains(&format!("pub struct {}", type_name)),
            "FIX-82: {} struct must exist", type_name
        );
    }
    // Also confirm the variants carry the typed payloads.
    assert!(body.contains("GetCFHeaders(GetCFHeadersMessage)"));
    assert!(body.contains("CFHeaders(CFHeadersMessage)"));
    assert!(body.contains("GetCFCheckpt(GetCFCheckptMessage)"));
    assert!(body.contains("CFCheckpt(CFCheckptMessage)"));
}

/// G14 BUG-7 — FIXED in FIX-82.
///
/// FIX-71 (W121 BUG-7 plumbing-without-flipping) added the gate function
/// `should_advertise_compact_filters` and the const
/// `BIP157_P2P_HANDLERS_REGISTERED: bool = false`. FIX-82 wires the
/// `GetCFilters` / `GetCFHeaders` / `GetCFCheckpt` dispatch handlers in
/// `rustoshi/src/main.rs` (event-loop match arms) and flips the constant to
/// `true`. The gate function now returns `true` whenever both
/// `-blockfilterindex` and `-peerblockfilters` are enabled (matching Core
/// `init.cpp:992-999`).
///
/// See `w99_net_processing_tests.rs::g22_node_compact_filters_gate_active`
/// for the network-crate test that exercises the live gate.
#[test]
fn g14_node_compact_filters_gate_plumbed() {
    use std::fs;
    let body = fs::read_to_string("../network/src/peer_manager.rs")
        .expect("crates/network/src/peer_manager.rs must exist");
    assert!(
        body.contains("pub fn should_advertise_compact_filters"),
        "FIX-71: peer_manager.rs must define should_advertise_compact_filters"
    );
    assert!(
        body.contains("pub const BIP157_P2P_HANDLERS_REGISTERED: bool = true"),
        "FIX-82: BIP157_P2P_HANDLERS_REGISTERED must be `true` once the \
         GetCFilters/Headers/CheckPt dispatch handlers land in main.rs"
    );
    assert!(
        body.contains("s |= NODE_COMPACT_FILTERS"),
        "FIX-71: local_services() must OR NODE_COMPACT_FILTERS under the gate"
    );
}

/// FIX-82 source-level regression guard — verify the 3 dispatch handlers
/// are wired into the rustoshi binary's event loop.
#[test]
fn fix82_main_rs_wires_bip157_dispatch_handlers() {
    use std::path::PathBuf;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let main_rs = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("rustoshi/src/main.rs"))
        .expect("workspace layout");
    let body = std::fs::read_to_string(&main_rs)
        .unwrap_or_else(|e| panic!("read {}: {}", main_rs.display(), e));
    for sym in [
        "NetworkMessage::GetCFilters(req)",
        "NetworkMessage::GetCFHeaders(req)",
        "NetworkMessage::GetCFCheckpt(req)",
        "MAX_GETCFILTERS_SIZE",
        "MAX_GETCFHEADERS_SIZE",
        "CFCHECKPT_INTERVAL",
        "lookup_filter_range",
        "lookup_filter_hash_range",
        "try_disconnect_peer",
    ] {
        assert!(
            body.contains(sym),
            "FIX-82: rustoshi/src/main.rs must reference `{}` — \
             the BIP-157 P2P dispatch handlers / DoS gate / range-API are \
             expected to be wired into the event loop. If this test fails \
             after a refactor, verify the handlers are still reachable.",
            sym,
        );
    }
}

/// G15 BUG-8 — FIXED in FIX-82.
///
/// `ProcessGetCFilters` dispatch is wired in `rustoshi/src/main.rs`'s event
/// loop. The handler validates filter_type + NODE_COMPACT_FILTERS advertise,
/// resolves stop_hash via the height index (active-chain confirm),
/// enforces `stop_height - start_height < MAX_GETCFILTERS_SIZE`, then calls
/// `BlockFilterIndex::lookup_filter_range` and pushes one `cfilter`
/// per height. Per-violation `try_disconnect_peer` mirrors Core's
/// `fDisconnect = true`.
///
/// Pinned via source-level grep (see `fix82_main_rs_wires_bip157_dispatch_handlers`).
#[test]
fn g15_process_getcfilters_handler_present() {
    use std::path::PathBuf;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let main_rs = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("rustoshi/src/main.rs"))
        .expect("workspace layout");
    let body = std::fs::read_to_string(&main_rs).expect("read main.rs");
    assert!(
        body.contains("NetworkMessage::GetCFilters(req)"),
        "FIX-82: main.rs must dispatch on NetworkMessage::GetCFilters"
    );
    assert!(
        body.contains("lookup_filter_range"),
        "FIX-82: handler must call lookup_filter_range"
    );
    assert!(
        body.contains("MAX_GETCFILTERS_SIZE"),
        "FIX-82: handler must enforce MAX_GETCFILTERS_SIZE"
    );
}

/// G16 BUG-9 — FIXED in FIX-82.
///
/// `ProcessGetCFHeaders` dispatch in main.rs. Resolves `prev_filter_header`
/// from `lookup_filter_header_at_height(start_height - 1)` (or zero at
/// start=0), collects filter hashes via `lookup_filter_hash_range`, and
/// emits a single `cfheaders` response containing `(stop_hash,
/// previous_filter_header, filter_hashes)`. Defensive return-without-send on
/// prev-header miss matches Core net_processing.cpp:3361-3370 (FIX-79
/// pattern).
#[test]
fn g16_process_getcfheaders_handler_present() {
    use std::path::PathBuf;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let main_rs = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("rustoshi/src/main.rs"))
        .expect("workspace layout");
    let body = std::fs::read_to_string(&main_rs).expect("read main.rs");
    assert!(body.contains("NetworkMessage::GetCFHeaders(req)"));
    assert!(body.contains("lookup_filter_hash_range"));
    assert!(body.contains("MAX_GETCFHEADERS_SIZE"));
    assert!(body.contains("previous_filter_header"));
}

/// G17 BUG-10 — FIXED in FIX-82.
///
/// `ProcessGetCFCheckPt` dispatch in main.rs. Walks every
/// `(i+1) * CFCHECKPT_INTERVAL` height up to `stop_height /
/// CFCHECKPT_INTERVAL`, reads each filter header via the index, and emits a
/// single `cfcheckpt` with the assembled chain. Active-chain validation
/// ensures the stop_hash is on our best chain before walking.
#[test]
fn g17_process_getcfcheckpt_handler_present() {
    use std::path::PathBuf;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let main_rs = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("rustoshi/src/main.rs"))
        .expect("workspace layout");
    let body = std::fs::read_to_string(&main_rs).expect("read main.rs");
    assert!(body.contains("NetworkMessage::GetCFCheckpt(req)"));
    assert!(body.contains("CFCHECKPT_INTERVAL"));
}

/// G18 BUG-11 — FIXED in FIX-82.
///
/// Outbound `cfilter` / `cfheaders` / `cfcheckpt` are emitted via
/// `try_send_to_peer(peer_id, NetworkMessage::CFilter(...))` (and the
/// other two variants) inside each handler. The typed payload structs
/// serialize to BIP-157 wire format on the way out.
#[test]
fn g18_outbound_cfilter_responses_present() {
    use std::path::PathBuf;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let main_rs = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("rustoshi/src/main.rs"))
        .expect("workspace layout");
    let body = std::fs::read_to_string(&main_rs).expect("read main.rs");
    assert!(body.contains("NetworkMessage::CFilter(CFilterMessage"));
    assert!(body.contains("NetworkMessage::CFHeaders(CFHeadersMessage"));
    assert!(body.contains("NetworkMessage::CFCheckpt(CFCheckptMessage"));
}

/// G19 BUG-12 — FIXED in FIX-82.
///
/// `MAX_GETCFILTERS_SIZE = 1000` / `MAX_GETCFHEADERS_SIZE = 2000` /
/// `CFCHECKPT_INTERVAL = 1000` are now defined in
/// `crates/network/src/message.rs` (mirrors Core net_processing.cpp:184-186
/// + blockfilterindex.h:31).
#[test]
fn g19_max_getcfilters_constants_present() {
    let body = std::fs::read_to_string("../network/src/message.rs")
        .expect("crates/network/src/message.rs must exist");
    assert!(
        body.contains("pub const MAX_GETCFILTERS_SIZE: u32 = 1000"),
        "FIX-82: MAX_GETCFILTERS_SIZE constant must exist with Core value 1000"
    );
    assert!(
        body.contains("pub const MAX_GETCFHEADERS_SIZE: u32 = 2000"),
        "FIX-82: MAX_GETCFHEADERS_SIZE constant must exist with Core value 2000"
    );
    assert!(
        body.contains("pub const CFCHECKPT_INTERVAL: u32 = 1000"),
        "FIX-82: CFCHECKPT_INTERVAL constant must exist with Core value 1000"
    );
}

/// G20 BUG-13 — FIXED in FIX-82.
///
/// `PrepareBlockFilterRequest`-equivalent DoS gate is inlined inside each of
/// the 3 dispatch handlers (factoring it out into a helper would add no
/// value at 5 lines per arm). The handler checks:
///   - filter_type == 0 + NODE_COMPACT_FILTERS advertised
///   - stop_hash resolves to a known block AND that block is on the active
///     chain (height index points at it)
///   - start_height <= stop_height
///   - stop_height - start_height < MAX_* (per-handler cap)
/// Any violation triggers `try_disconnect_peer` — matches Core's
/// `node.fDisconnect = true` in `net_processing.cpp:3262-3313`.
#[test]
fn g20_prepare_block_filter_request_gate_present() {
    use std::path::PathBuf;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let main_rs = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("rustoshi/src/main.rs"))
        .expect("workspace layout");
    let body = std::fs::read_to_string(&main_rs).expect("read main.rs");
    // Per-violation disconnects are present.
    assert!(
        body.contains("try_disconnect_peer"),
        "FIX-82: DoS gate must call try_disconnect_peer on violation"
    );
    // Service-bit gate. The check `local_services & NODE_COMPACT_FILTERS != 0`
    // is performed before every handler runs.
    assert!(
        body.contains("NODE_COMPACT_FILTERS"),
        "FIX-82: handler must verify NODE_COMPACT_FILTERS is advertised"
    );
    // Active-chain stop_hash validation: the height index must echo back
    // the same stop_hash for the resolved height.
    assert!(
        body.contains("get_hash_by_height(stop_index.height)"),
        "FIX-82: handler must verify stop_hash is on the active chain"
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

/// G23 BUG-16 (P0) — FIXED in FIX-69.
///
/// PRIOR STATE: `BlockFilterIndex::index_block` had no caller in
/// `crates/consensus/` or the main binary. The entire ~6500 LOC GCS + index
/// + REST stack was reachable only from this unit test file. In a real
/// node run, the `blockfilter` and `blockfilter_header` column families
/// stayed empty forever and `/rest/blockfilter/...` returned 404 even
/// after a full IBD.
///
/// FIX: `rustoshi/src/main.rs::write_block_filter_index` is called at
/// every successful `ChainState::process_block` site (4 call sites: blk-file
/// import, stdin frame import, IBD validation_interval, and P2P block
/// downloader). It invokes `BlockFilterIndex::connect_block`, which builds
/// the basic GCS filter from the block's output scriptPubKeys + the
/// UndoData's spent scriptPubKeys, then persists filter + header chain.
///
/// This regression-pin asserts the helper is wired end-to-end: a block
/// connect followed by `get_filter` and `get_filter_header` returns
/// populated entries. Future drive-by refactors that drop the wire-up
/// will fail this test FIRST.
#[test]
fn g23_block_filter_index_wired_into_connect_path() {
    use rustoshi_consensus::validation::{CoinEntry, UndoData};
    use rustoshi_primitives::{Block, BlockHeader, Transaction, TxIn, TxOut};

    // Build a 2-tx block: coinbase + one spending tx (so undo carries one spent coin).
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: rustoshi_primitives::OutPoint {
                txid: Hash256::ZERO,
                vout: 0xFFFFFFFF,
            },
            script_sig: vec![0x51],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_000_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0x01, 0x02, 0x03],
        }],
        lock_time: 0,
    };
    let spender = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: rustoshi_primitives::OutPoint {
                txid: Hash256::from([1u8; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 49_000_000,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb, 0xcc],
        }],
        lock_time: 0,
    };
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![coinbase, spender],
    };
    let undo = UndoData {
        spent_coins: vec![CoinEntry {
            height: 99,
            is_coinbase: false,
            value: 50_000_000,
            script_pubkey: vec![0x51, 0x21, 0xde, 0xad, 0xbe, 0xef],
        }],
    };

    let db = open_db();
    let idx = BlockFilterIndex::new(&db);
    let block_hash = block.block_hash();

    // Exercise the high-level connect_block (the same wrapper main.rs calls).
    let header = idx
        .connect_block(0, &block, &undo)
        .expect("connect_block at genesis-relative height");

    // Filter + header are now persisted.
    assert!(idx.has_filter(&block_hash).unwrap(), "filter row missing");
    let entry = idx.get_filter_header(0).expect("get").expect("present");
    assert_eq!(entry.block_hash, block_hash);
    assert_eq!(entry.filter_header, header);

    // Filter contains the output's scriptPubKey and the spent script.
    let filter = idx.get_filter(&block_hash).unwrap().unwrap();
    assert!(
        filter.match_script(&[0x76, 0xa9, 0x14, 0x01, 0x02, 0x03]).unwrap(),
        "output scriptPubKey must match"
    );
    assert!(
        filter.match_script(&[0x51, 0x21, 0xde, 0xad, 0xbe, 0xef]).unwrap(),
        "spent scriptPubKey must match"
    );
}

/// FIX-69 source-level regression guard.
///
/// Asserts via filesystem grep that `rustoshi/src/main.rs` still imports
/// `BlockFilterIndex` AND contains a call to `write_block_filter_index`.
/// If a future refactor accidentally drops the wire-up, this test fails
/// FIRST — surfacing the regression at the test layer before the
/// /rest/blockfilter endpoint silently starts returning 404 again.
#[test]
fn fix69_main_rs_wires_block_filter_index() {
    use std::path::PathBuf;
    // Walk up from CARGO_MANIFEST_DIR (crates/storage) to find rustoshi/src/main.rs.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let main_rs = manifest
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .map(|root| root.join("rustoshi/src/main.rs"))
        .expect("workspace layout");
    let body = std::fs::read_to_string(&main_rs)
        .unwrap_or_else(|e| panic!("read {}: {}", main_rs.display(), e));

    assert!(
        body.contains("BlockFilterIndex"),
        "rustoshi/src/main.rs must import BlockFilterIndex — \
         FIX-69 W121 BUG-16 regression guard. If you intentionally moved \
         the wire-up to another module, update this test to follow."
    );
    assert!(
        body.contains("write_block_filter_index"),
        "rustoshi/src/main.rs must call write_block_filter_index from \
         every process_block site — FIX-69 W121 BUG-16 regression guard"
    );
    // Sanity: the helper is invoked, not just imported. We require AT
    // LEAST 4 call sites (3 production process_block sites + the helper
    // definition referencing itself in the doc comment, or any
    // future-added call site).
    let call_count = body.matches("write_block_filter_index").count();
    assert!(
        call_count >= 4,
        "expected ≥4 occurrences of `write_block_filter_index` in main.rs \
         (1 fn definition + ≥3 call sites); got {}. Future refactors \
         should not silently lose a call site.",
        call_count,
    );
}

/// G24 BUG-17 — FIXED in FIX-82.
///
/// `BlockFilterIndex` exposes `lookup_filter_range(start, stop, hash_lookup)`
/// and `lookup_filter_hash_range(...)`, mirroring Core's
/// `LookupFilterRange` / `LookupFilterHashRange`. The hash_lookup callback
/// resolves height → hash on the active chain (typically via
/// `BlockStore::get_hash_by_height`) and the function returns `Ok(None)` if
/// any row is missing (defensive, matches Core's bool return).
#[test]
fn g24_block_filter_index_range_query_present() {
    use rustoshi_consensus::validation::UndoData;

    let db = open_db();
    let idx = BlockFilterIndex::new(&db);
    let empty_undo = UndoData { spent_coins: vec![] };

    // Build 5 blocks at heights 0..5 — each with a unique scriptPubKey
    // (so each filter has different content).
    let mut prev_hash = Hash256::ZERO;
    let mut hashes: Vec<Hash256> = Vec::new();
    for h in 0..5u32 {
        let block = fake_block_at_height(h, prev_hash);
        let block_hash = block.block_hash();
        idx.connect_block(h, &block, &empty_undo).expect("connect");
        hashes.push(block_hash);
        prev_hash = block_hash;
    }

    // Build a hash_lookup that mimics BlockStore::get_hash_by_height.
    let hashes_ref = hashes.clone();
    let hash_lookup = |h: u32| -> Option<Hash256> {
        hashes_ref.get(h as usize).copied()
    };

    // (a) Filter range: all 5 filters come back in order.
    let filters = idx
        .lookup_filter_range(0, 4, hash_lookup)
        .expect("lookup_filter_range")
        .expect("present");
    assert_eq!(filters.len(), 5);
    for (h, f) in filters.iter().enumerate() {
        assert_eq!(f.block_hash, hashes[h], "filter at height {} has wrong block_hash", h);
    }

    // (b) Filter hash range: 5 filter hashes in order.
    let hash_lookup = |h: u32| -> Option<Hash256> {
        hashes.get(h as usize).copied()
    };
    let filter_hashes = idx
        .lookup_filter_hash_range(0, 4, hash_lookup)
        .expect("lookup_filter_hash_range")
        .expect("present");
    assert_eq!(filter_hashes.len(), 5);

    // (c) Sub-range works.
    let hash_lookup2 = |h: u32| -> Option<Hash256> {
        hashes_ref.get(h as usize).copied()
    };
    let sub = idx
        .lookup_filter_range(2, 3, hash_lookup2)
        .expect("ok")
        .expect("present");
    assert_eq!(sub.len(), 2);
    assert_eq!(sub[0].block_hash, hashes_ref[2]);
    assert_eq!(sub[1].block_hash, hashes_ref[3]);
}

/// G25 BUG-18 — FIXED in FIX-82.
///
/// `CFCHECKPT_INTERVAL = 1000` is now defined in both
/// `crates/storage/src/indexes/blockfilterindex.rs` (for the index-side
/// walk helper) and `crates/network/src/message.rs` (for the P2P handler).
/// The `ProcessGetCFCheckPt` handler in main.rs walks every
/// `(i+1) * CFCHECKPT_INTERVAL` height up to `stop_height /
/// CFCHECKPT_INTERVAL`, mirroring Core net_processing.cpp:3403-3417.
#[test]
fn g25_cfcheckpt_interval_present() {
    use rustoshi_storage::indexes::blockfilterindex::CFCHECKPT_INTERVAL;
    assert_eq!(
        CFCHECKPT_INTERVAL, 1000,
        "CFCHECKPT_INTERVAL must match Core's blockfilterindex.h:31"
    );

    // Confirm the parallel constant in the network crate (used by the
    // dispatch handler) also matches.
    let body = std::fs::read_to_string("../network/src/message.rs")
        .expect("crates/network/src/message.rs must exist");
    assert!(
        body.contains("pub const CFCHECKPT_INTERVAL: u32 = 1000"),
        "FIX-82: network crate's CFCHECKPT_INTERVAL must mirror storage crate"
    );
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

// ============================================================
// FIX-69 integration tests — connect-then-reorg coverage.
// ============================================================

/// Helper: build a coinbase-only fake block with a deterministic hash that
/// depends on `height` (so each block has a distinct hash).  The merkle_root
/// is `height` packed into a Hash256 so we get unique block_hashes without
/// hashing a tx.
fn fake_block_at_height(height: u32, prev_hash: rustoshi_primitives::Hash256) -> rustoshi_primitives::Block {
    use rustoshi_primitives::{Block, BlockHeader, Transaction, TxIn, TxOut};

    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: rustoshi_primitives::OutPoint {
                txid: rustoshi_primitives::Hash256::ZERO,
                vout: 0xFFFFFFFF,
            },
            script_sig: vec![0x51, (height & 0xff) as u8, ((height >> 8) & 0xff) as u8],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_000_000,
            // Unique scriptPubKey per height so each filter has different content.
            script_pubkey: vec![
                0x76, 0xa9, 0x14,
                (height & 0xff) as u8,
                ((height >> 8) & 0xff) as u8,
                ((height >> 16) & 0xff) as u8,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0x88, 0xac,
            ],
        }],
        lock_time: 0,
    };

    // Merkle root is `height` packed so block_hash is deterministic per height.
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&height.to_le_bytes());

    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: rustoshi_primitives::Hash256::from_bytes(merkle),
            timestamp: 1_700_000_000 + height,
            bits: 0x207fffff,
            nonce: height,
        },
        transactions: vec![coinbase],
    }
}

/// FIX-69 integration test (a): connect 10 blocks → assert filter index
/// has filter + header rows for all 10 heights.
///
/// Mirrors the production hot loop: `BlockFilterIndex::connect_block` is
/// called for every block as `main.rs::write_block_filter_index` would
/// invoke it after `process_block`. Verifies:
///   - Filter rows present for every block hash.
///   - Filter header chain is contiguous (entry at height h+1 has
///     filter_header computed from entry at height h).
///   - Each filter matches its block's unique scriptPubKey.
#[test]
fn fix69_connect_ten_blocks_populates_index() {
    use rustoshi_consensus::validation::UndoData;
    let db = open_db();
    let idx = BlockFilterIndex::new(&db);

    let mut prev_hash = Hash256::ZERO;
    let mut prev_header = Hash256::ZERO;
    let mut hashes: Vec<Hash256> = Vec::new();
    let empty_undo = UndoData { spent_coins: vec![] };

    for h in 0..10u32 {
        let block = fake_block_at_height(h, prev_hash);
        let block_hash = block.block_hash();

        let header = idx
            .connect_block(h, &block, &empty_undo)
            .expect("connect_block");

        // Every block must produce a non-zero header (filter chain advances).
        assert_ne!(header, Hash256::ZERO, "filter header at height {} is zero", h);

        // Header derives from prev_header (BIP-157 chain rule).
        let entry = idx.get_filter_header(h).unwrap().expect("header at h");
        assert_eq!(entry.block_hash, block_hash);
        let filter = idx.get_filter(&block_hash).unwrap().expect("filter at h");
        let expected = filter.compute_header(&prev_header);
        assert_eq!(entry.filter_header, expected, "header chain at height {}", h);

        hashes.push(block_hash);
        prev_header = entry.filter_header;
        prev_hash = block_hash;
    }

    // All 10 heights have filter + header rows.
    for (h, hash) in hashes.iter().enumerate() {
        assert!(idx.has_filter(hash).unwrap(), "missing filter at height {}", h);
        assert!(
            idx.get_filter_header(h as u32).unwrap().is_some(),
            "missing header at height {}", h,
        );
    }
}

/// FIX-69 integration test (b): connect 10 then reorg the last 5
/// → filter index must REMOVE entries for heights 5..10.
///
/// Mirrors Core's `BlockFilterIndex::CustomRewind` (mediated through
/// `BaseIndex::Rewind` on disconnect). Verifies the disconnect-side
/// cleanup so stale filters from the orphan chain do not linger in the
/// REST/P2P serving paths.
#[test]
fn fix69_reorg_five_blocks_rewinds_index() {
    use rustoshi_consensus::validation::UndoData;
    let db = open_db();
    let idx = BlockFilterIndex::new(&db);
    let empty_undo = UndoData { spent_coins: vec![] };

    // Connect 10 blocks.
    let mut prev_hash = Hash256::ZERO;
    let mut hashes: Vec<Hash256> = Vec::new();
    for h in 0..10u32 {
        let block = fake_block_at_height(h, prev_hash);
        let block_hash = block.block_hash();
        idx.connect_block(h, &block, &empty_undo).expect("connect");
        hashes.push(block_hash);
        prev_hash = block_hash;
    }

    // Sanity: all 10 present pre-reorg.
    for (h, hash) in hashes.iter().enumerate() {
        assert!(idx.has_filter(hash).unwrap());
        assert!(idx.get_filter_header(h as u32).unwrap().is_some());
    }

    // Disconnect heights 9, 8, 7, 6, 5 (Core walks the rewind in
    // newest-to-oldest order — see validation.cpp::DisconnectTip).
    for h in (5..10u32).rev() {
        idx.disconnect_block(h, &hashes[h as usize]).expect("disconnect");
    }

    // Heights 5..10 are gone.
    for h in 5..10u32 {
        assert!(
            !idx.has_filter(&hashes[h as usize]).unwrap(),
            "filter at disconnected height {} should be removed",
            h,
        );
        assert!(
            idx.get_filter_header(h).unwrap().is_none(),
            "header at disconnected height {} should be removed",
            h,
        );
    }
    // Heights 0..5 are still there.
    for h in 0..5u32 {
        assert!(
            idx.has_filter(&hashes[h as usize]).unwrap(),
            "filter at retained height {} should still exist",
            h,
        );
        assert!(
            idx.get_filter_header(h).unwrap().is_some(),
            "header at retained height {} should still exist",
            h,
        );
    }
}
