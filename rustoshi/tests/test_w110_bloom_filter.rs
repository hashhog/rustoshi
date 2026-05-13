//! W110 — BIP-37 bloom filter 30-gate audit.
//!
//! ## What this tests
//! Bitcoin's BIP-37 SPV bloom filter subsystem: `CBloomFilter` struct,
//! `filterload`/`filteradd`/`filterclear` P2P message handling,
//! `merkleblock` construction, `IsWithinSizeConstraints`, `NODE_BLOOM`,
//! and BIP-111 `-peerbloomfilters` configuration gate.
//!
//! ## Subsystem status: MISSING ENTIRELY (with partial G30 PASS)
//!
//! rustoshi has NO `CBloomFilter` implementation. There is no:
//!   - `bloom.rs` or equivalent module
//!   - `MurmurHash3` function for BIP-37 purposes
//!   - `MAX_BLOOM_FILTER_SIZE` / `MAX_HASH_FUNCS` / `LN2SQUARED` constants
//!   - Per-peer bloom filter state in `PeerInfo` or `PeerHandle`
//!   - `filterload`/`filteradd`/`filterclear` message handlers
//!   - `IsWithinSizeConstraints` validation
//!   - `IsRelevantAndUpdate` function
//!
//! The P2P wire messages (`FilterLoad`, `FilterAdd`, `FilterClear`,
//! `MerkleBlock`) are parsed into `NetworkMessage` variants but every
//! handler falls through the `_ =>` catch-all in `main.rs`, which
//! forwards them to `peer_manager.handle_event`, which also silently
//! ignores them.
//!
//! ## Gate summary (30 gates)
//!   - PASS : G30 (NODE_BLOOM constant correct; -peerbloomfilters default=false)
//!   - PARTIAL PASS: (wire messages are parsed into correct variants)
//!   - MISSING ENTIRELY / BUG: G1-G29
//!
//! ## Bug index
//!   BUG-1  G1  MAX_BLOOM_FILTER_SIZE constant absent
//!   BUG-2  G2  MAX_HASH_FUNCS constant absent
//!   BUG-3  G3  LN2SQUARED constant absent
//!   BUG-4  G4  CBloomFilter constructor / sizing formula absent
//!   BUG-5  G5  nHashFuncs computation absent
//!   BUG-6  G6  MurmurHash3 32-bit for bloom absent
//!   BUG-7  G7  per-bit hash schedule (nTweak + i*0xFBA4C795) absent
//!   BUG-8  G8  bit index = hash % (vData.size()*8) absent
//!   BUG-9  G9  insert / contains operations absent
//!   BUG-10 G10 isFull/isEmpty short-circuit absent
//!   BUG-11 G11 BLOOM_UPDATE_NONE = 0 constant absent
//!   BUG-12 G12 BLOOM_UPDATE_ALL = 1 constant absent
//!   BUG-13 G13 BLOOM_UPDATE_P2PUBKEY_ONLY = 2 constant absent
//!   BUG-14 G14 BLOOM_UPDATE_MASK = 3 constant absent
//!   BUG-15 G15 nFlags & BLOOM_UPDATE_MASK dispatch absent
//!   BUG-16 G16 txid match absent
//!   BUG-17 G17 output scriptPubKey pushdata match absent
//!   BUG-18 G18 P2PKH/P2SH/P2PK/multisig match types absent
//!   BUG-19 G19 input outpoint match absent
//!   BUG-20 G20 scriptSig data item match absent
//!   BUG-21 G21 BLOOM_UPDATE_ALL outpoint insertion absent
//!   BUG-22 G22 BLOOM_UPDATE_P2PUBKEY_ONLY outpoint insertion absent
//!   BUG-23 G23 BLOOM_UPDATE_NONE no-mutation absent
//!   BUG-24 G24 outpoint serialization (32-byte LE hash + 4-byte LE index) absent
//!   BUG-25 G25 filterload handler absent — messages silently discarded
//!   BUG-26 G26 filteradd handler absent — messages silently discarded
//!   BUG-27 G27 filterclear handler absent — messages silently discarded
//!   BUG-28 G28 merkleblock construction from filter absent
//!   BUG-29 G29 IsWithinSizeConstraints validation absent — DoS vector
//!              (oversized filterload not rejected, peer not disconnected)
//!   (G30 PASS — NODE_BLOOM bit correct; -peerbloomfilters default=false)
//!   BUG-30 (BUG-25 detail) filterload/filteradd/filterclear fall through
//!              _ => catch-all in main.rs and are silently ignored
//!   BUG-31     No per-peer bloom filter state in PeerInfo/PeerHandle
//!   BUG-32     fRelay=false in version message not honoured for bloom peers
//!              (no filter to apply means relay behaviour is unaffected)
//!
//! ## Dead-helper note
//! `eviction.rs` carries a `bloom_filter: bool` field on `EvictionCandidate`
//! but `peer_manager.rs:2088` always hard-codes it to `false`
//! ("bloom_filter - we don't track this currently"), confirming the filter
//! state is never actually set. This is a dead-helper / stub in the
//! eviction path (25-wave streak maintained).
//!
//! ## Severity
//! All G1-G29 are P2 or higher:
//!   - G29 (BUG-29): P1 — a remote peer sending a MAX-size filterload
//!     (36000 bytes) with nHashFuncs=255 will be accepted without validation;
//!     each subsequent tx broadcast would trigger 255 MurmurHash3 calls *if*
//!     the filter were wired. Currently moot because no matching runs, but
//!     a future partial implementation without this guard is a DoS vector.
//!   - G25-G27 (BUG-25/26/27): P2 — any peer that sends filterload will
//!     get its messages silently dropped; if NODE_BLOOM is advertised (via
//!     -peerbloomfilters=true) we are lying about our capability.
//!   - G1-G24, G28: P3 — entire subsystem absent; SPV clients cannot use
//!     this node for bloom-filter-based sync.

use rustoshi_network::message::NetworkMessage;
use rustoshi_network::message::NODE_BLOOM;

// ─────────────────────────────────────────────────────────────────────────────
// G1: MAX_BLOOM_FILTER_SIZE = 36000 bytes
// Status: BUG-1 — MISSING ENTIRELY
// Core ref: bloom.h:17 `static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-1: MAX_BLOOM_FILTER_SIZE constant is absent — define it as 36000 in a bloom module"]
fn g1_max_bloom_filter_size_constant() {
    // When implemented:
    // use rustoshi_network::bloom::MAX_BLOOM_FILTER_SIZE;
    // assert_eq!(MAX_BLOOM_FILTER_SIZE, 36000u32);
    todo!("define MAX_BLOOM_FILTER_SIZE = 36000 in bloom module")
}

// ─────────────────────────────────────────────────────────────────────────────
// G2: MAX_HASH_FUNCS = 50
// Status: BUG-2 — MISSING ENTIRELY
// Core ref: bloom.h:18 `static constexpr unsigned int MAX_HASH_FUNCS = 50`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-2: MAX_HASH_FUNCS constant is absent — define it as 50 in a bloom module"]
fn g2_max_hash_funcs_constant() {
    // When implemented:
    // use rustoshi_network::bloom::MAX_HASH_FUNCS;
    // assert_eq!(MAX_HASH_FUNCS, 50u32);
    todo!("define MAX_HASH_FUNCS = 50 in bloom module")
}

// ─────────────────────────────────────────────────────────────────────────────
// G3: LN2SQUARED constant with full precision
// Status: BUG-3 — MISSING ENTIRELY
// Core ref: bloom.cpp:23
//   `static constexpr double LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-3: LN2SQUARED constant is absent — define with full double precision"]
fn g3_ln2squared_constant() {
    // When implemented:
    // use rustoshi_network::bloom::LN2SQUARED;
    // assert!((LN2SQUARED - 0.4804530139182014f64).abs() < 1e-15);
    todo!("define LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455 in bloom module")
}

// ─────────────────────────────────────────────────────────────────────────────
// G4: Constructor sizing formula
// Status: BUG-4 — MISSING ENTIRELY
// Core ref: bloom.cpp:32
//   vData(min((-1/LN2SQUARED * nElements * log(nFPRate)), MAX_BLOOM_FILTER_SIZE*8) / 8)
//
// For nElements=10000, nFPRate=0.001 the expected vData size is 17980 bytes.
// For nElements=1, nFPRate=0.0001 the expected size is at most 36000 bytes.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-4: CBloomFilter struct is absent — implement constructor with correct sizing formula"]
fn g4_constructor_sizing_formula() {
    // When implemented:
    // use rustoshi_network::bloom::CBloomFilter;
    // let f = CBloomFilter::new(10000, 0.001, 0, 0);
    // // Expected: (-1/LN2SQUARED * 10000 * ln(0.001)) / 8 ≈ 17980 bytes
    // assert_eq!(f.vdata_len(), 17980, "sizing formula must match Core");
    //
    // // Clamping: absurdly large nElements must not exceed 36000 bytes
    // let big = CBloomFilter::new(1_000_000, 0.001, 0, 0);
    // assert!(big.vdata_len() <= 36000);
    todo!("implement CBloomFilter with correct sizing formula")
}

// ─────────────────────────────────────────────────────────────────────────────
// G5: nHashFuncs computation
// Status: BUG-5 — MISSING ENTIRELY
// Core ref: bloom.cpp:38
//   nHashFuncs(min((uint)(vData.size() * 8 / nElements * LN2), MAX_HASH_FUNCS))
// where LN2 = 0.6931471805599453
//
// For nElements=10000, vData.size()=17980: nHashFuncs = floor(17980*8/10000*LN2) = 9
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-5: nHashFuncs computation absent — must match Core formula using LN2"]
fn g5_nhashfuncs_computation() {
    // When implemented:
    // use rustoshi_network::bloom::CBloomFilter;
    // let f = CBloomFilter::new(10000, 0.001, 0, 0);
    // // Core: floor(17980*8/10000 * 0.693...) = 9
    // assert_eq!(f.n_hash_funcs(), 9, "nHashFuncs must match Core's LN2-based formula");
    //
    // // nHashFuncs must never exceed MAX_HASH_FUNCS=50
    // let dense = CBloomFilter::new(1, 0.00000001, 0, 0);
    // assert!(dense.n_hash_funcs() <= 50);
    todo!("implement nHashFuncs = min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G6: Hash function is MurmurHash3 32-bit
// Status: BUG-6 — MISSING ENTIRELY
// Core ref: bloom.cpp:47
//   `return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8)`
//
// Known test vector from Core's bloom_tests.cpp:
//   MurmurHash3(seed=0, data=b"\x00") = 0x514E28B7
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-6: MurmurHash3 32-bit for bloom filter is absent — not SHA256, not FNV"]
fn g6_murmurhash3_32bit() {
    // When implemented:
    // use rustoshi_network::bloom::murmurhash3_32;
    // // Known vector: murmurhash3(seed=0, data=[0x00]) = 0x514E28B7
    // assert_eq!(murmurhash3_32(0, &[0x00u8]), 0x514E28B7u32, "MurmurHash3 vector mismatch");
    // // Second known vector: murmurhash3(seed=0, data=[]) = 0x00000000
    // assert_eq!(murmurhash3_32(0, &[]), 0x00000000u32, "empty-data MurmurHash3 must be 0");
    todo!("implement MurmurHash3 32-bit (Bitcoin Core's util/strencodings.h implementation)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G7: Per-bit hash uses nTweak + i*0xFBA4C795 schedule
// Status: BUG-7 — MISSING ENTIRELY
// Core ref: bloom.cpp:47
//   `MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash)`
//
// The constant 0xFBA4C795 "guarantees a reasonable bit difference between
// nHashNum values" (comment in Core source).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-7: per-bit hash schedule (nTweak + i*0xFBA4C795) is absent"]
fn g7_per_bit_hash_schedule() {
    // When implemented, verify that for hash i and nTweak:
    // seed_i = (i as u32).wrapping_mul(0xFBA4C795u32).wrapping_add(nTweak)
    // bit_index = MurmurHash3(seed_i, data) % (vdata_bytes * 8)
    todo!("verify seed schedule uses nHashNum * 0xFBA4C795 + nTweak")
}

// ─────────────────────────────────────────────────────────────────────────────
// G8: Bit index = hash % (vData.size() * 8)
// Status: BUG-8 — MISSING ENTIRELY
// Core ref: bloom.cpp:47
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-8: bit index computation absent — must use % (vData.size()*8)"]
fn g8_bit_index_modulo() {
    // The bit position must be reduced modulo the total bit count of vData,
    // NOT modulo the byte count, and NOT allowed to overflow.
    todo!("verify bit_index = murmurhash3(seed, data) % (vdata_len_bytes * 8)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G9: insert sets bit; contains AND of bits across all hash funcs
// Status: BUG-9 — MISSING ENTIRELY
// Core ref: bloom.cpp:50-81
//   insert: `vData[nIndex >> 3] |= (1 << (7 & nIndex))`
//   contains: returns false as soon as any bit is clear
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-9: insert/contains operations absent — implement set-bit and check-all-bits"]
fn g9_insert_contains_round_trip() {
    // When implemented:
    // use rustoshi_network::bloom::CBloomFilter;
    // let mut f = CBloomFilter::new(100, 0.001, 0, 0);
    // let key = b"hello";
    // assert!(!f.contains(key), "should not contain key before insert");
    // f.insert(key);
    // assert!(f.contains(key), "should contain key after insert");
    //
    // // Different key must not match (extremely unlikely for random data)
    // assert!(!f.contains(b"world_zzzzzzzzz"), "unrelated key should not match");
    todo!("implement insert (set bit) and contains (AND all hash bits)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G10: isFull/isEmpty short-circuit
// Status: BUG-10 — MISSING ENTIRELY
// Core ref: bloom.cpp:69-70, 100
//   contains: if vData.empty() return true  (CVE-2013-5700: empty = match-all)
//   insert:   if vData.empty() return       (avoid divide-by-zero)
//   IsRelevantAndUpdate: if vData.empty() return true
//
// A filter with vData.size()==0 is a "match-all" filter.
// A filter that is all-ones is "full" (returns true for everything).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-10: isFull/isEmpty short-circuit absent — CVE-2013-5700 guard missing"]
fn g10_is_full_is_empty_short_circuit() {
    // Empty vData (zero-size filter) must match everything — "match-all" semantic
    // This is NOT a bug condition to reject; it is the defined behavior (CVE-2013-5700 fix).
    //
    // When implemented:
    // use rustoshi_network::bloom::CBloomFilter;
    // let empty_filter = CBloomFilter::from_raw(vec![], 0, 0, 0);
    // assert!(empty_filter.contains(b"anything"),
    //     "empty vData must be match-all per Core CVE-2013-5700 fix");
    //
    // A full filter (all bits set) must also match everything
    // let full_filter = CBloomFilter::from_raw(vec![0xFFu8; 10], 3, 0, 0);
    // assert!(full_filter.is_full(), "all-ones filter must report is_full");
    // assert!(full_filter.contains(b"anything"));
    todo!("implement isEmpty/isFull short-circuits per Core CVE-2013-5700 guard")
}

// ─────────────────────────────────────────────────────────────────────────────
// G11: BLOOM_UPDATE_NONE = 0
// Status: BUG-11 — MISSING ENTIRELY
// Core ref: bloom.h:26
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-11: BLOOM_UPDATE_NONE = 0 constant absent"]
fn g11_bloom_update_none_constant() {
    // When implemented:
    // use rustoshi_network::bloom::BLOOM_UPDATE_NONE;
    // assert_eq!(BLOOM_UPDATE_NONE, 0u8);
    todo!("define BLOOM_UPDATE_NONE = 0")
}

// ─────────────────────────────────────────────────────────────────────────────
// G12: BLOOM_UPDATE_ALL = 1
// Status: BUG-12 — MISSING ENTIRELY
// Core ref: bloom.h:27
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-12: BLOOM_UPDATE_ALL = 1 constant absent"]
fn g12_bloom_update_all_constant() {
    // When implemented:
    // use rustoshi_network::bloom::BLOOM_UPDATE_ALL;
    // assert_eq!(BLOOM_UPDATE_ALL, 1u8);
    todo!("define BLOOM_UPDATE_ALL = 1")
}

// ─────────────────────────────────────────────────────────────────────────────
// G13: BLOOM_UPDATE_P2PUBKEY_ONLY = 2
// Status: BUG-13 — MISSING ENTIRELY
// Core ref: bloom.h:29
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-13: BLOOM_UPDATE_P2PUBKEY_ONLY = 2 constant absent"]
fn g13_bloom_update_p2pubkey_only_constant() {
    // When implemented:
    // use rustoshi_network::bloom::BLOOM_UPDATE_P2PUBKEY_ONLY;
    // assert_eq!(BLOOM_UPDATE_P2PUBKEY_ONLY, 2u8);
    todo!("define BLOOM_UPDATE_P2PUBKEY_ONLY = 2")
}

// ─────────────────────────────────────────────────────────────────────────────
// G14: BLOOM_UPDATE_MASK = 3
// Status: BUG-14 — MISSING ENTIRELY
// Core ref: bloom.h:30
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-14: BLOOM_UPDATE_MASK = 3 constant absent"]
fn g14_bloom_update_mask_constant() {
    // When implemented:
    // use rustoshi_network::bloom::BLOOM_UPDATE_MASK;
    // assert_eq!(BLOOM_UPDATE_MASK, 3u8);
    // // MASK must equal ALL | P2PUBKEY_ONLY = 1 | 2
    // assert_eq!(BLOOM_UPDATE_MASK, BLOOM_UPDATE_ALL | BLOOM_UPDATE_P2PUBKEY_ONLY);
    todo!("define BLOOM_UPDATE_MASK = 3 (bits 0 and 1 of nFlags)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G15: nFlags & BLOOM_UPDATE_MASK applied (not raw nFlags ==)
// Status: BUG-15 — MISSING ENTIRELY
// Core ref: bloom.cpp:123
//   `if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)`
//   `else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY)`
//
// The upper 6 bits of nFlags are reserved. Using raw nFlags == without the
// mask would cause incorrect dispatch if any reserved bit is set.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-15: nFlags & BLOOM_UPDATE_MASK dispatch absent — must mask before comparing"]
fn g15_nflags_update_mask_dispatch() {
    // When implemented, verify that a filter created with nFlags = 0b00000101
    // (BLOOM_UPDATE_ALL=1 plus a reserved bit=4) dispatches as BLOOM_UPDATE_ALL,
    // not as an unknown value:
    // use rustoshi_network::bloom::{CBloomFilter, BLOOM_UPDATE_MASK, BLOOM_UPDATE_ALL};
    // let f = CBloomFilter::from_raw(vec![0u8; 10], 1, 0, 0b00000101u8);
    // assert_eq!(f.n_flags() & BLOOM_UPDATE_MASK, BLOOM_UPDATE_ALL,
    //     "reserved bits must not affect update-flag dispatch");
    todo!("apply BLOOM_UPDATE_MASK before comparing nFlags in update dispatch")
}

// ─────────────────────────────────────────────────────────────────────────────
// G16: Tx matches by txid
// Status: BUG-16 — MISSING ENTIRELY
// Core ref: bloom.cpp:103
//   `if (contains(hash.ToUint256())) fFound = true`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-16: txid match in IsRelevantAndUpdate absent — must check filter.contains(txid)"]
fn g16_txid_match() {
    // When implemented, create a filter that contains a known txid and verify
    // IsRelevantAndUpdate returns true for a tx with that txid.
    todo!("implement IsRelevantAndUpdate: check filter.contains(tx.txid())")
}

// ─────────────────────────────────────────────────────────────────────────────
// G17: Output scriptPubKey pushdata items matched
// Status: BUG-17 — MISSING ENTIRELY
// Core ref: bloom.cpp:113-135
//   Iterates scriptPubKey opcodes, for any data push of size != 0, calls contains(data)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-17: output scriptPubKey pushdata match absent — must iterate output scripts"]
fn g17_output_scriptpubkey_pushdata_match() {
    // When implemented, create a filter containing a 20-byte pubkey hash and
    // verify a tx with a matching P2PKH output is found.
    todo!("implement IsRelevantAndUpdate: iterate output scriptPubKey data pushes")
}

// ─────────────────────────────────────────────────────────────────────────────
// G18: Match types: P2PKH, P2SH, P2PK, multisig
// Status: BUG-18 — MISSING ENTIRELY
// Core ref: bloom.cpp:127-132 (Solver call for update-flag dispatch)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-18: P2PKH/P2SH/P2PK/multisig match types absent in IsRelevantAndUpdate"]
fn g18_output_script_match_types() {
    // Match types to cover in tests once implemented:
    //   P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    //   P2PK:  <33-or-65-byte-pubkey> OP_CHECKSIG
    //   P2SH:  OP_HASH160 <20-byte-hash> OP_EQUAL
    //   multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
    todo!("implement match for all 4 output script types per Core bloom.cpp Solver logic")
}

// ─────────────────────────────────────────────────────────────────────────────
// G19: Input outpoint match
// Status: BUG-19 — MISSING ENTIRELY
// Core ref: bloom.cpp:144
//   `if (contains(txin.prevout)) return true`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-19: input outpoint match absent — must check filter.contains(prevout) for each input"]
fn g19_input_outpoint_match() {
    // When implemented, insert an outpoint (txid+vout serialized) into a filter
    // and verify a tx spending that outpoint is detected.
    todo!("implement IsRelevantAndUpdate: check filter.contains(txin.prevout) for each input")
}

// ─────────────────────────────────────────────────────────────────────────────
// G20: scriptSig data items matched
// Status: BUG-20 — MISSING ENTIRELY
// Core ref: bloom.cpp:148-157
//   Iterates scriptSig opcodes, for any data push of size != 0, calls contains(data)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-20: scriptSig data item match absent — must iterate input scriptSig pushes"]
fn g20_input_scriptsig_data_match() {
    // When implemented, insert a signature or pubkey into a filter and verify
    // a tx spending with that data in its scriptSig is detected.
    todo!("implement IsRelevantAndUpdate: check filter.contains(push_data) for each scriptSig item")
}

// ─────────────────────────────────────────────────────────────────────────────
// G21: BLOOM_UPDATE_ALL — every matched output's outpoint inserted
// Status: BUG-21 — MISSING ENTIRELY
// Core ref: bloom.cpp:123-124
//   `if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL) insert(COutPoint(hash, i))`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-21: BLOOM_UPDATE_ALL outpoint auto-insertion absent in IsRelevantAndUpdate"]
fn g21_bloom_update_all_inserts_outpoints() {
    // When implemented, after a P2PKH output matches BLOOM_UPDATE_ALL, the
    // outpoint (txid:vout_index) should be auto-inserted so the spending tx
    // is also caught without a round-trip filter update from the client.
    todo!("implement BLOOM_UPDATE_ALL: insert(outpoint) for every matched output")
}

// ─────────────────────────────────────────────────────────────────────────────
// G22: BLOOM_UPDATE_P2PUBKEY_ONLY — only P2PK and multisig outpoints inserted
// Status: BUG-22 — MISSING ENTIRELY
// Core ref: bloom.cpp:125-132
//   Uses Solver to determine TxoutType::PUBKEY or TxoutType::MULTISIG
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-22: BLOOM_UPDATE_P2PUBKEY_ONLY outpoint insertion absent"]
fn g22_bloom_update_p2pubkey_only_inserts_p2pk_multisig() {
    // Under P2PUBKEY_ONLY mode, matched P2PKH outputs must NOT auto-insert their
    // outpoints, but matched P2PK/multisig outputs MUST.
    todo!("implement BLOOM_UPDATE_P2PUBKEY_ONLY: insert outpoint only for P2PK/multisig")
}

// ─────────────────────────────────────────────────────────────────────────────
// G23: BLOOM_UPDATE_NONE — filter never mutated by match
// Status: BUG-23 — MISSING ENTIRELY
// Core ref: bloom.cpp (absence of insert() call in the NONE path)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-23: BLOOM_UPDATE_NONE must never mutate the filter during IsRelevantAndUpdate"]
fn g23_bloom_update_none_no_mutation() {
    // Under BLOOM_UPDATE_NONE, matching must not auto-insert any outpoints.
    // The filter byte array must be identical before and after a match.
    todo!("verify BLOOM_UPDATE_NONE never calls insert() inside IsRelevantAndUpdate")
}

// ─────────────────────────────────────────────────────────────────────────────
// G24: Outpoint serialization: 32-byte LE hash + 4-byte LE index
// Status: BUG-24 — MISSING ENTIRELY
// Core ref: bloom.cpp:63-66
//   `DataStream stream{}; stream << outpoint; insert(MakeUCharSpan(stream))`
//   COutPoint serializes as: txid (32 bytes, little-endian) + n (4 bytes, LE)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-24: outpoint serialization for bloom insert must be 32-byte LE txid + 4-byte LE index"]
fn g24_outpoint_serialization_for_bloom() {
    // When implemented:
    // let txid = [0xabu8; 32];
    // let vout: u32 = 3;
    // let mut expected = txid.to_vec();
    // expected.extend_from_slice(&vout.to_le_bytes());
    // assert_eq!(expected.len(), 36, "outpoint must serialize to exactly 36 bytes");
    //
    // use rustoshi_network::bloom::CBloomFilter;
    // let mut f = CBloomFilter::new(100, 0.001, 0, 1); // BLOOM_UPDATE_ALL
    // f.insert_outpoint(&txid, vout);
    // assert!(f.contains_outpoint(&txid, vout));
    todo!("implement outpoint serialization as 32-byte LE txid + 4-byte LE index for bloom insert/contains")
}

// ─────────────────────────────────────────────────────────────────────────────
// G25: filterload handler
// Status: BUG-25 — HANDLER ABSENT (messages silently discarded)
// Core ref: net_processing.cpp (NetMsgType::FILTERLOAD handler)
//   - Deserializes vData + nHashFuncs + nTweak + nFlags
//   - Calls IsWithinSizeConstraints() BEFORE accepting
//   - Sets per-peer filter
//   - Sets fRelay accordingly
//
// Current behavior: NetworkMessage::FilterLoad(raw_bytes) falls through
// the `_ =>` branch in main.rs:3267 and is forwarded to peer_manager
// handle_event, which has no match arm for it — silently dropped.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-25: filterload handler absent — FilterLoad messages are silently discarded in _ => catch-all"]
fn g25_filterload_handler_absent() {
    // When implemented:
    // 1. Build a valid filterload payload (vData + nHashFuncs + nTweak + nFlags)
    // 2. Feed it to the peer message handler
    // 3. Verify the per-peer filter is set
    // 4. Verify subsequent tx relay honours the filter
    todo!("implement filterload handler: deserialize, validate via IsWithinSizeConstraints, set per-peer filter")
}

// ─────────────────────────────────────────────────────────────────────────────
// G26: filteradd handler
// Status: BUG-26 — HANDLER ABSENT (messages silently discarded)
// Core ref: net_processing.cpp (NetMsgType::FILTERADD handler)
//   - Data item must be <= 520 bytes
//   - If oversized, disconnect peer
//   - Add item to existing per-peer filter via insert()
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-26: filteradd handler absent — FilterAdd messages are silently discarded in _ => catch-all"]
fn g26_filteradd_handler_absent() {
    // When implemented:
    // 1. Send filteradd with a valid data item (<= 520 bytes)
    // 2. Verify the item is added to the peer's existing filter
    // 3. Send filteradd with a 521-byte item — peer should be disconnected
    todo!("implement filteradd handler: validate size <= 520 bytes, insert into per-peer filter, disconnect on oversize")
}

// ─────────────────────────────────────────────────────────────────────────────
// G27: filterclear handler
// Status: BUG-27 — HANDLER ABSENT (messages silently discarded)
// Core ref: net_processing.cpp (NetMsgType::FILTERCLEAR handler)
//   - Clear the per-peer filter (set to NULL)
//   - Resume full relay to this peer
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-27: filterclear handler absent — FilterClear messages are silently discarded in _ => catch-all"]
fn g27_filterclear_handler_absent() {
    // When implemented:
    // 1. Set a per-peer filter via filterload
    // 2. Send filterclear
    // 3. Verify the per-peer filter is cleared (NULL)
    // 4. Verify the peer reverts to full tx relay
    todo!("implement filterclear handler: clear per-peer filter, resume full relay")
}

// ─────────────────────────────────────────────────────────────────────────────
// G28: merkleblock construction from filter
// Status: BUG-28 — MISSING ENTIRELY
// Core ref: merkleblock.h/cpp (CMerkleBlock constructor)
//   Given a CBlock and a CBloomFilter, construct a PartialMerkleTree of
//   only the txids that match the filter (via IsRelevantAndUpdate).
//   The merkleblock wire format: header (80 bytes) + CPartialMerkleTree
//   (nTransactions + hash list + flag bits).
//
// NOTE: The RPC `gettxoutproof` command has a SEPARATE PartialMerkleTree
// implementation in crates/rpc/src/server.rs (build_partial_merkle_tree_bytes),
// which is a TWO-PIPELINE risk. That helper is NOT wired to bloom filter
// matching — it takes a pre-selected set of txids. A full bloom-filter
// merkleblock needs to call IsRelevantAndUpdate on each tx and feed the
// resulting match list into the PartialMerkleTree builder.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-28: merkleblock construction from bloom filter absent — two-pipeline risk with RPC helper"]
fn g28_merkleblock_construction_from_filter() {
    // When implemented, given a block with 3 txs where tx[1] matches the filter:
    // - merkleblock should include tx[1]'s txid in the matched set
    // - PartialMerkleTree should prove tx[1] is in the block
    // - header bytes must match the block's 80-byte serialized header
    // - nTransactions field must equal total tx count in block (not matched count)
    //
    // TWO-PIPELINE RISK: crates/rpc/src/server.rs already has
    // build_partial_merkle_tree_bytes() — the bloom-filter variant must
    // reuse that helper rather than implement a separate tree builder.
    todo!("implement CMerkleBlock: call IsRelevantAndUpdate per tx, build PartialMerkleTree from matched set")
}

// ─────────────────────────────────────────────────────────────────────────────
// G29: IsWithinSizeConstraints — DoS guard
// Status: BUG-29 (P1) — MISSING ENTIRELY; peer not disconnected on oversize filterload
// Core ref: bloom.cpp:90-93
//   `return vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS`
// Core net_processing.cpp: if (!filter.IsWithinSizeConstraints()) { Misbehaving(..., 100) }
//
// Impact: A remote peer can send a filterload with vData.size() = 0xFFFF (65535)
// and nHashFuncs = 255. Without this guard, the node would allocate unlimited
// memory per peer and perform 255 MurmurHash3 calls per tx broadcast.
// Currently moot because there's no matching code, but BUG-29 must be fixed
// before any partial bloom implementation goes live.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-29 (P1): IsWithinSizeConstraints absent — oversized filterload must disconnect peer"]
fn g29_is_within_size_constraints_dos_guard() {
    // When implemented, a filterload with vData.size() = 36001 bytes must be
    // rejected and the sending peer disconnected (100-point misbehaving ban).
    //
    // Test case 1: valid filter (within limits)
    // let payload_ok = build_filterload_payload(36000_bytes_vdata, nhashfuncs=50, tweak=0, flags=0);
    // assert!(handle_filterload(payload_ok).is_ok(), "max-valid filter must be accepted");
    //
    // Test case 2: oversized vData
    // let payload_too_big = build_filterload_payload(36001_bytes_vdata, nhashfuncs=50, tweak=0, flags=0);
    // assert!(handle_filterload(payload_too_big).is_err(), "oversized vData must be rejected");
    //
    // Test case 3: too many hash funcs
    // let payload_too_many_hashes = build_filterload_payload(100_bytes_vdata, nhashfuncs=51, tweak=0, flags=0);
    // assert!(handle_filterload(payload_too_many_hashes).is_err(), "nHashFuncs > 50 must be rejected");
    todo!("implement IsWithinSizeConstraints and enforce it in filterload handler with peer disconnect on violation")
}

// ─────────────────────────────────────────────────────────────────────────────
// G30: NODE_BLOOM service flag and BIP-111 gate
// Status: PASS
// Core ref: protocol.h (NODE_BLOOM = 1 << 2)
//
// NODE_BLOOM is correctly defined as (1 << 2) = 4 in message.rs:137.
// peer_bloom_filters defaults to false (matching Core's
// DEFAULT_PEERBLOOMFILTERS=false in net_processing.h:44).
// When peer_bloom_filters=true, NODE_BLOOM is included in advertised services.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g30_node_bloom_constant_is_bit_2() {
    // NODE_BLOOM must be exactly (1 << 2) = 4 per BIP-111
    assert_eq!(NODE_BLOOM, 1u64 << 2,
        "NODE_BLOOM must be bit 2 per BIP-111 (not bit 0, not bit 1)");
    assert_eq!(NODE_BLOOM, 4u64,
        "NODE_BLOOM = 4 matches Bitcoin Core protocol.h");
}

#[test]
fn g30_node_bloom_default_disabled() {
    use rustoshi_network::PeerManagerConfig;
    let config = PeerManagerConfig::default();
    assert!(!config.peer_bloom_filters,
        "-peerbloomfilters must default to false matching Core's DEFAULT_PEERBLOOMFILTERS=false");
}

#[test]
fn g30_node_bloom_enabled_via_config() {
    use rustoshi_network::PeerManagerConfig;
    let mut config = PeerManagerConfig::default();
    config.peer_bloom_filters = true;
    assert!(config.peer_bloom_filters,
        "NODE_BLOOM must be advertised when peer_bloom_filters=true");
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-30: filterload/filteradd/filterclear fall through _ => catch-all
// Status: BUG — confirmed architectural gap
// Evidence:
//   main.rs:3267 `_ => { ... pm.handle_event(PeerEvent::Message(peer_id, msg)).await; }`
//   peer_manager.rs:1605 PeerEvent::Message match — no FilterLoad/FilterAdd/FilterClear arms
//
// BUG-25/26/27 document the specific missing handlers; this test documents
// the fall-through path that silently swallows them.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g30b_filterload_message_parses_into_correct_variant() {
    // The wire deserializer correctly maps "filterload" → FilterLoad(bytes).
    // This is a PASS on the parsing side — the bug is in the handler.
    // Build a minimal filterload payload: vData(1 byte) + nHashFuncs(4) + nTweak(4) + nFlags(1)
    // CompactSize(1) = 0x01, vData = [0x00], nHashFuncs = 1 (LE32), nTweak = 0 (LE32), nFlags = 0
    let payload: &[u8] = &[
        0x01, 0x00, // CompactSize(1) + 1 byte of vData
        0x01, 0x00, 0x00, 0x00, // nHashFuncs = 1 (LE32)
        0x00, 0x00, 0x00, 0x00, // nTweak = 0 (LE32)
        0x00, // nFlags = 0
    ];

    let result = NetworkMessage::deserialize("filterload", payload);
    assert!(result.is_ok(), "filterload must parse without error");
    match result.unwrap() {
        NetworkMessage::FilterLoad(bytes) => {
            assert_eq!(bytes, payload, "FilterLoad must preserve raw payload bytes");
        }
        other => panic!("Expected FilterLoad variant, got {:?}", other),
    }
}

#[test]
fn g30c_filterclear_message_parses_correctly() {
    use rustoshi_network::message::NetworkMessage;
    let result = NetworkMessage::deserialize("filterclear", &[]);
    assert!(result.is_ok(), "filterclear must parse without error");
    assert!(matches!(result.unwrap(), NetworkMessage::FilterClear),
        "filterclear must map to FilterClear variant");
}

#[test]
fn g30d_filteradd_message_parses_correctly() {
    use rustoshi_network::message::NetworkMessage;
    // filteradd payload: CompactSize(data_len) + data
    let data = b"\xab\xcd\xef";
    let mut payload = vec![data.len() as u8];
    payload.extend_from_slice(data);
    let result = NetworkMessage::deserialize("filteradd", &payload);
    assert!(result.is_ok(), "filteradd must parse without error");
    match result.unwrap() {
        NetworkMessage::FilterAdd(bytes) => {
            assert_eq!(bytes, payload.as_slice(),
                "FilterAdd must preserve raw payload bytes for later handler use");
        }
        other => panic!("Expected FilterAdd variant, got {:?}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-31: No per-peer bloom filter state in PeerInfo
// Status: BUG — dead-stub in eviction.rs
//
// eviction.rs:60 has `pub bloom_filter: bool` on EvictionCandidate, but
// peer_manager.rs:2088 always passes `false` for it:
//   `false, // bloom_filter - we don't track this currently`
//
// This means:
//   1. No per-peer CBloomFilter is stored anywhere
//   2. The eviction "protect peers with bloom filters" path never activates
//   3. Peers that legitimately set a filter get no eviction protection
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-31: per-peer bloom filter state absent — eviction.rs bloom_filter field is always false"]
fn g_bug31_per_peer_filter_state_missing() {
    // When implemented, PeerInfo or PeerHandle must carry an Option<CBloomFilter>
    // that is set on filterload and cleared on filterclear.
    // The EvictionCandidate::bloom_filter field in eviction.rs must be populated
    // from this actual state rather than hardcoded to false.
    todo!("add Option<CBloomFilter> to PeerInfo/PeerHandle; wire to eviction candidate bloom_filter field")
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-32: fRelay=false in version message not honoured for bloom filter peers
//
// Core behaviour: if a peer's version message has relay=false AND the peer
// subsequently sends filterload, the node should switch to bloom-filtered
// relay for that peer (this is BIP-37's "partial relay" semantics).
//
// Current state: relay=false peers simply get no tx relay (main.rs version
// handling), which is correct for non-BIP-37 peers. But because there is no
// bloom filter system, a peer that sets relay=false then sends filterload
// cannot recover its tx relay — the filterload is silently dropped and the
// peer remains in no-relay mode.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-32: fRelay=false peer cannot recover tx relay via filterload (bloom subsystem absent)"]
fn g_bug32_frelay_false_bloom_filter_relay_recovery() {
    // When implemented, a peer that connected with relay=false should be able
    // to use filterload to opt into filtered tx relay. This requires:
    //   1. Per-peer bloom filter state (BUG-31)
    //   2. filterload handler (BUG-25)
    //   3. Logic to resume tx relay (filtered) after filterload received from relay=false peer
    todo!("implement relay recovery path: relay=false peer can opt into filtered relay via filterload")
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural test: wire message commands are registered
// This is a PASS — verifying the command-to-variant mapping is present.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g_structural_bloom_message_commands_registered() {
    use rustoshi_network::message::NetworkMessage;
    // Verify all BIP-37 messages have the correct command strings
    assert_eq!(NetworkMessage::FilterLoad(vec![]).command(), "filterload");
    assert_eq!(NetworkMessage::FilterAdd(vec![]).command(), "filteradd");
    assert_eq!(NetworkMessage::FilterClear.command(), "filterclear");
    assert_eq!(NetworkMessage::MerkleBlock(vec![]).command(), "merkleblock");
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural test: NODE_BLOOM is distinct from other service bits
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g_structural_node_bloom_bit_distinct() {
    use rustoshi_network::message::{NODE_NETWORK, NODE_WITNESS, NODE_BLOOM, NODE_NETWORK_LIMITED};
    // NODE_BLOOM must not alias any other service bit
    assert_ne!(NODE_BLOOM, NODE_NETWORK,  "NODE_BLOOM must not equal NODE_NETWORK");
    assert_ne!(NODE_BLOOM, NODE_WITNESS,  "NODE_BLOOM must not equal NODE_WITNESS");
    assert_ne!(NODE_BLOOM, NODE_NETWORK_LIMITED, "NODE_BLOOM must not equal NODE_NETWORK_LIMITED");
    // AND of NODE_BLOOM with other bits must be zero (non-overlapping)
    assert_eq!(NODE_BLOOM & NODE_NETWORK,  0, "NODE_BLOOM must not share bits with NODE_NETWORK");
    assert_eq!(NODE_BLOOM & NODE_WITNESS,  0, "NODE_BLOOM must not share bits with NODE_WITNESS");
}
