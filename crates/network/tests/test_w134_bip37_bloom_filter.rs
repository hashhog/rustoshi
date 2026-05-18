//! W134 — BIP-37 Bloom Filter (legacy SPV) 30-gate audit (rustoshi).
//!
//! Discovery wave, not a fix wave. See `audit/w134_bip37_bloom_filter.md` for
//! the prose summary, 24 BUG findings, severity rollup, and recommended
//! Option-A-vs-B closure path. Each gate is documented inline and either:
//!   - **PASS** regression-pin for a Core-aligned surface, or
//!   - **`#[ignore]` xfail** for a known PARTIAL/MISSING gate with a
//!     `BUG-N` reference into the audit doc.
//!
//! ## Subsystem stance
//! rustoshi does NOT serve BIP-37 by default (correct — matches Core
//! `DEFAULT_PEERBLOOMFILTERS=false` since 0.19+). However:
//!   - The `-peerbloomfilters=true` CLI gate flips NODE_BLOOM into the
//!     advertised services WITHOUT any handlers being wired — **P0-CDIV
//!     advertise-without-fulfil (BUG-1, G2)**.
//!   - `getdata MSG_FILTERED_BLOCK` from a peer is silently dropped
//!     (main.rs:3343-3384 `_ => {}`) — **P1 (BUG-2, G3)**.
//!   - `IsWithinSizeConstraints` is absent — **P1 DoS guard (BUG-3, G4)**.
//!
//! ## Cross-wave context
//! W110 (`rustoshi/tests/test_w110_bloom_filter.rs`) audited the same
//! subsystem from the "CBloomFilter implementation absent" angle and
//! catalogued 32 BUGs. W134 re-frames with the explicit deprecation lens
//! (Core removed serving by default in 0.19+) and adds the
//! advertise-without-fulfil P0-CDIV plus the getdata-MsgFilteredBlock-drop
//! finding. The 30 W134 gates therefore include 6 PASS regression-pins,
//! 2 PARTIAL pins, and 22 MISSING xfails (24 distinct BUGs).
//!
//! Core references:
//!   - `bitcoin-core/src/common/bloom.{h,cpp}`
//!   - `bitcoin-core/src/merkleblock.{h,cpp}`
//!   - `bitcoin-core/src/net_processing.cpp:4963-5033` (FILTERLOAD/FILTERADD/
//!     FILTERCLEAR handlers), `:2438-2460` (MSG_FILTERED_BLOCK getdata),
//!     `:4853-4855` (mempool NODE_BLOOM gate)
//!   - `bitcoin-core/src/init.cpp:1104-1105` + `net_processing.h:44`
//!     (`DEFAULT_PEERBLOOMFILTERS = false`)
//!   - `bitcoin-core/src/protocol.h:317` (`NODE_BLOOM = (1 << 2)`)

use rustoshi_consensus::params::ChainParams;
use rustoshi_network::eviction::EvictionCandidate;
use rustoshi_network::message::{
    InvType, NetworkMessage, NODE_BLOOM, NODE_NETWORK, NODE_NETWORK_LIMITED, NODE_WITNESS,
};
use rustoshi_network::netgroup::{NetGroup, NetworkType};
use rustoshi_network::peer::PeerId;
use rustoshi_network::peer_manager::{PeerManager, PeerManagerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// G1 — NODE_BLOOM service bit value
// Status: PASS
// Core ref: bitcoin-core/src/protocol.h:317 `NODE_BLOOM = (1 << 2)`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g1_node_bloom_is_bit_2() {
    assert_eq!(NODE_BLOOM, 1u64 << 2, "NODE_BLOOM must be bit 2 per BIP-111");
    assert_eq!(NODE_BLOOM, 4u64, "NODE_BLOOM = 4 matches protocol.h");

    // Distinct from siblings (no bit-aliasing)
    assert_ne!(NODE_BLOOM, NODE_NETWORK);
    assert_ne!(NODE_BLOOM, NODE_WITNESS);
    assert_ne!(NODE_BLOOM, NODE_NETWORK_LIMITED);
    assert_eq!(NODE_BLOOM & NODE_NETWORK, 0);
    assert_eq!(NODE_BLOOM & NODE_WITNESS, 0);
    assert_eq!(NODE_BLOOM & NODE_NETWORK_LIMITED, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// G2 — InvType::MsgFilteredBlock + MsgWitnessFilteredBlock constants
// Status: PARTIAL (constant defined; getdata service path missing — see G3/BUG-2)
// Core ref: bitcoin-core/src/protocol.h:483 (MSG_FILTERED_BLOCK = 3)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g2_inv_type_msg_filtered_block_constants() {
    assert_eq!(InvType::from_u32(3), InvType::MsgFilteredBlock);
    assert_eq!(InvType::from_u32(0x40000003), InvType::MsgWitnessFilteredBlock);
}

// ─────────────────────────────────────────────────────────────────────────────
// G3 — getdata MSG_FILTERED_BLOCK service path
// Status: BUG-2 (P1) — MISSING. main.rs:3343-3384 dispatches MsgBlock /
// MsgWitnessBlock / MsgTx / MsgWitnessTx; MsgFilteredBlock hits `_ => {}`.
// Core ref: bitcoin-core/src/net_processing.cpp:2438-2460 — Core constructs
// CMerkleBlock from the per-peer filter and sends merkleblock + matched txs.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-2 (P1): getdata MSG_FILTERED_BLOCK is silently dropped in \
            main.rs:3343-3384 _ => {} catch-all. Core sends merkleblock + \
            matched TX messages (net_processing.cpp:2438-2460). When \
            peer_bloom_filters=true is advertised, peers expect this path."]
fn g3_getdata_msg_filtered_block_serves_merkleblock() {
    todo!("wire getdata MsgFilteredBlock → build CMerkleBlock(block, filter) \
          and send merkleblock + matched tx messages")
}

// ─────────────────────────────────────────────────────────────────────────────
// G4 — IsWithinSizeConstraints (DoS guard)
// Status: BUG-3 (P1) — MISSING. Must reject vData.size() > 36000 or
// nHashFuncs > 50 BEFORE installing the filter; Core misbehaves the peer.
// Core ref: bitcoin-core/src/common/bloom.cpp:90-93 + net_processing.cpp:4972-4975
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-3 (P1): IsWithinSizeConstraints absent — must reject \
            vData.size()>36000 or nHashFuncs>50 and Misbehaving(100) the peer \
            BEFORE installing the filter (CVE-class DoS at first wiring)"]
fn g4_is_within_size_constraints_dos_guard() {
    todo!("implement IsWithinSizeConstraints + enforce in filterload handler \
          + Misbehaving(100) + peer disconnect on violation")
}

// ─────────────────────────────────────────────────────────────────────────────
// G5 — MAX_BLOOM_FILTER_SIZE = 36000 constant
// Status: BUG-4 (P2) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.h:17
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-4 (P2): MAX_BLOOM_FILTER_SIZE = 36000 constant absent — \
            define in a bloom module (no rustoshi-network::bloom module exists)"]
fn g5_max_bloom_filter_size_constant_absent() {
    // When implemented:
    //   use rustoshi_network::bloom::MAX_BLOOM_FILTER_SIZE;
    //   assert_eq!(MAX_BLOOM_FILTER_SIZE, 36000u32);
    todo!("define MAX_BLOOM_FILTER_SIZE = 36000 in a bloom module")
}

// ─────────────────────────────────────────────────────────────────────────────
// G6 — MAX_HASH_FUNCS = 50 constant
// Status: BUG-5 (P2) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.h:18
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-5 (P2): MAX_HASH_FUNCS = 50 constant absent"]
fn g6_max_hash_funcs_constant_absent() {
    todo!("define MAX_HASH_FUNCS = 50 in a bloom module")
}

// ─────────────────────────────────────────────────────────────────────────────
// G7 — LN2SQUARED constant for sizing formula
// Status: BUG-6 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:23
//   LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-6 (P3): LN2SQUARED constant absent — full double precision \
            required for Core-byte-identical sizing"]
fn g7_ln2squared_constant_absent() {
    todo!("define LN2SQUARED with Core's full precision")
}

// ─────────────────────────────────────────────────────────────────────────────
// G8 — CBloomFilter constructor + sizing formula
// Status: BUG-7 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:32
//   vData.size() = min((-1/LN2SQUARED * nElements * log(nFPRate)),
//                      MAX_BLOOM_FILTER_SIZE*8) / 8
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-7 (P3): CBloomFilter sizing formula absent — no constructor"]
fn g8_cbloomfilter_sizing_formula_absent() {
    // Reference: for nElements=10000, nFPRate=0.001 → vData.size() ≈ 17980 bytes
    todo!("implement CBloomFilter::new with min(-1/LN2SQUARED*N*log(p), 36000*8)/8")
}

// ─────────────────────────────────────────────────────────────────────────────
// G9 — nHashFuncs computation
// Status: BUG-8 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:38
//   nHashFuncs = min((uint)(vData.size()*8/nElements*LN2), MAX_HASH_FUNCS)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-8 (P3): nHashFuncs computation absent"]
fn g9_nhashfuncs_computation_absent() {
    // Reference: for nElements=10000, vData.size()=17980 → nHashFuncs = 9
    todo!("implement nHashFuncs = min(vData.size()*8/nElements*LN2, 50)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G10 — MurmurHash3 32-bit (Bitcoin variant)
// Status: BUG-9 (P3) — MISSING.
// Core ref: bitcoin-core/src/hash.cpp (MurmurHash3)
// NB: rustoshi-network depends on `siphasher` 1.0 for compact-block short
// IDs, but SipHash != MurmurHash3. BIP-37 mandates MurmurHash3 specifically.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-9 (P3): MurmurHash3 32-bit absent (siphasher exists but is a \
            DIFFERENT hash family; BIP-37 specifically requires MurmurHash3)"]
fn g10_murmurhash3_32bit_absent() {
    // When implemented, known vectors:
    //   MurmurHash3(seed=0, data=[])       = 0x00000000
    //   MurmurHash3(seed=0, data=[0x00])   = 0x514E28B7
    todo!("implement MurmurHash3 32-bit per Bitcoin Core hash.cpp")
}

// ─────────────────────────────────────────────────────────────────────────────
// G11 — Per-bit hash seed schedule (nHashNum * 0xFBA4C795 + nTweak)
// Status: BUG-10 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:47
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-10 (P3): per-bit hash seed schedule (i*0xFBA4C795 + nTweak) absent"]
fn g11_per_bit_hash_seed_schedule_absent() {
    todo!("verify seed = (i as u32).wrapping_mul(0xFBA4C795) + nTweak")
}

// ─────────────────────────────────────────────────────────────────────────────
// G12 — bit_index = MurmurHash3(seed, data) % (vData.size() * 8)
// Status: BUG-11 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:47
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-11 (P3): bit-index mod (vData.size()*8) absent"]
fn g12_bit_index_modulo_absent() {
    todo!("verify bit_index = hash % (vData.size() * 8) — NOT % byte_count")
}

// ─────────────────────────────────────────────────────────────────────────────
// G13 — insert sets bit; contains is AND-of-bits across all hash funcs
// Status: BUG-12 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:50-81
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-12 (P3): insert (set bit) + contains (AND all hash bits) absent"]
fn g13_insert_contains_absent() {
    todo!("implement insert: vData[idx>>3] |= 1<<(7&idx); contains: false on any unset")
}

// ─────────────────────────────────────────────────────────────────────────────
// G14 — CVE-2013-5700 empty-vData ⇒ match-all + insert no-op
// Status: BUG-13 (P3) — MISSING.
// Core ref: bloom.cpp:52-53 (insert), :71-72 (contains), :100-101 (IsRelevantAndUpdate)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-13 (P3): CVE-2013-5700 short-circuit absent — empty vData must \
            be match-all in contains AND IsRelevantAndUpdate, no-op in insert"]
fn g14_cve_2013_5700_empty_vdata_short_circuit_absent() {
    todo!("implement: if vData.empty() then contains->true, insert->noop, IsRel->true")
}

// ─────────────────────────────────────────────────────────────────────────────
// G15-G18 — BLOOM_UPDATE_NONE=0, _ALL=1, _P2PUBKEY_ONLY=2, _MASK=3
// Status: BUG-14 (P3) — all 4 constants MISSING. Tracked as a single BUG
// to keep counts tight; W110 split them into BUG-11/12/13/14.
// Core ref: bitcoin-core/src/common/bloom.h:24-31
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-14 (P3): BLOOM_UPDATE_NONE/ALL/P2PUBKEY_ONLY/MASK constants absent"]
fn g15_to_g18_bloom_update_flag_constants_absent() {
    todo!("define BLOOM_UPDATE_NONE=0, _ALL=1, _P2PUBKEY_ONLY=2, _MASK=3")
}

// ─────────────────────────────────────────────────────────────────────────────
// G19 — `nFlags & BLOOM_UPDATE_MASK` dispatch (NOT raw `nFlags ==`)
// Status: BUG-15 (P3) — MISSING. Reserved upper bits of nFlags must be
// masked before comparing.
// Core ref: bitcoin-core/src/common/bloom.cpp:123-132
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-15 (P3): nFlags & BLOOM_UPDATE_MASK dispatch absent — reserved \
            upper-6-bits must be masked before comparing to ALL or P2PUBKEY_ONLY"]
fn g19_nflags_mask_dispatch_absent() {
    todo!("verify (nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL/P2PUBKEY_ONLY")
}

// ─────────────────────────────────────────────────────────────────────────────
// G20 — IsRelevantAndUpdate txid match
// Status: BUG-16 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:103
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-16 (P3): IsRelevantAndUpdate txid match absent"]
fn g20_isrelevantandupdate_txid_match_absent() {
    todo!("implement: if (contains(tx.hash().to_uint256())) fFound = true;")
}

// ─────────────────────────────────────────────────────────────────────────────
// G21 — IsRelevantAndUpdate output scriptPubKey pushdata match
// Status: BUG-17 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:113-135
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-17 (P3): IsRelevantAndUpdate output-script pushdata match absent"]
fn g21_output_scriptpubkey_match_absent() {
    todo!("iterate scriptPubKey opcodes; for each pushdata of size>0 call contains(data)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G22 — IsRelevantAndUpdate input outpoint match
// Status: BUG-18 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:144
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-18 (P3): IsRelevantAndUpdate input outpoint match absent"]
fn g22_input_outpoint_match_absent() {
    todo!("for each txin: if (contains(txin.prevout)) return true;")
}

// ─────────────────────────────────────────────────────────────────────────────
// G23 — IsRelevantAndUpdate scriptSig pushdata match
// Status: BUG-19 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:148-157
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-19 (P3): IsRelevantAndUpdate scriptSig pushdata match absent"]
fn g23_input_scriptsig_match_absent() {
    todo!("iterate scriptSig opcodes; for each pushdata of size>0 call contains(data)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G24 — BLOOM_UPDATE_ALL inserts outpoints of matched outputs
// Status: BUG-20 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:123-124
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-20 (P3): BLOOM_UPDATE_ALL outpoint auto-insertion absent"]
fn g24_bloom_update_all_inserts_outpoints_absent() {
    todo!("if (nFlags & MASK) == ALL: insert(COutPoint(tx.hash, i)) for matched outputs")
}

// ─────────────────────────────────────────────────────────────────────────────
// G25 — BLOOM_UPDATE_P2PUBKEY_ONLY inserts only P2PK/multisig outpoints
// Status: BUG-21 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:125-132 (uses Solver())
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-21 (P3): BLOOM_UPDATE_P2PUBKEY_ONLY outpoint insertion absent"]
fn g25_bloom_update_p2pubkey_only_inserts_p2pk_multisig_absent() {
    todo!("if (nFlags & MASK) == P2PUBKEY_ONLY: Solver() → only PUBKEY/MULTISIG → insert outpoint")
}

// ─────────────────────────────────────────────────────────────────────────────
// G26 — Outpoint serialization (32-byte LE txid + 4-byte LE index) for bloom
// Status: BUG-22 (P3) — MISSING.
// Core ref: bitcoin-core/src/common/bloom.cpp:62-67
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-22 (P3): outpoint→bloom serialization absent (must be 32-byte \
            LE txid + 4-byte LE index = 36 bytes via DataStream)"]
fn g26_outpoint_bloom_serialization_absent() {
    todo!("serialize outpoint as 32-byte LE txid + 4-byte LE index for insert/contains")
}

// ─────────────────────────────────────────────────────────────────────────────
// G27 — CMerkleBlock(block, filter) constructor / PartialMerkleTree from
// IsRelevantAndUpdate match list
// Status: BUG-23 (P3) — MISSING. Two-pipeline risk: an RPC-side helper
// `build_partial_merkle_tree_bytes` exists in `crates/rpc/src/server.rs:8738`
// for `gettxoutproof`, but it takes a pre-selected match list. Any
// wire-side bloom-driven CMerkleBlock MUST reuse that PMT traversal, not
// re-implement it.
// Core ref: bitcoin-core/src/merkleblock.{h,cpp}
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-23 (P3): CMerkleBlock(block, filter) constructor absent — \
            two-pipeline risk with crates/rpc/src/server.rs:8738 PMT helper"]
fn g27_cmerkleblock_from_filter_absent() {
    todo!("call IsRelevantAndUpdate per tx; feed matched set into PMT traversal \
          (reuse build_partial_merkle_tree_bytes, do NOT duplicate)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G28 — Eviction-protection field for bloom-filtered peers
// Status: BUG-24 (P2) — DOUBLY DEAD HELPER.
//   (a) peer_manager.rs:2500 hard-codes `false` ("bloom_filter - we don't
//       track this currently"), AND
//   (b) select_node_to_evict (eviction.rs:80-180) never reads the field
//       even when it would be true.
// Core ref: bitcoin-core/src/node/eviction.cpp — peers with bloom filter
// loaded are protected from random eviction.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[ignore = "BUG-24 (P2): EvictionCandidate.bloom_filter is doubly dead — never \
            set true (peer_manager.rs:2500 hard-codes false) AND never read in \
            select_node_to_evict (eviction.rs:80-180)"]
fn g28_eviction_candidate_bloom_filter_doubly_dead() {
    // When wired:
    //   - peer_manager.rs:2500 must set candidate.bloom_filter from
    //     per-peer Option<CBloomFilter> presence.
    //   - select_node_to_evict must protect peers with bloom_filter=true
    //     (mirrors Core's bloom-filtered-peer eviction protection).
    todo!("wire bloom_filter from per-peer state AND consult it in eviction")
}

// ─────────────────────────────────────────────────────────────────────────────
// G29 — DEFAULT_PEERBLOOMFILTERS = false (Core-parity default)
// Status: PASS
// Core ref: bitcoin-core/src/net_processing.h:44
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g29_peer_bloom_filters_default_false() {
    let cfg = PeerManagerConfig::default();
    assert!(
        !cfg.peer_bloom_filters,
        "peer_bloom_filters MUST default to false to match Core's DEFAULT_PEERBLOOMFILTERS"
    );

    let cfg_testnet4 = PeerManagerConfig::testnet4();
    assert!(
        !cfg_testnet4.peer_bloom_filters,
        "testnet4 preset MUST inherit the false default"
    );

    let params = ChainParams::testnet4();
    let mgr = PeerManager::new(cfg_testnet4, params);
    assert!(!mgr.peer_bloom_filters_enabled());

    // local_services() MUST NOT include NODE_BLOOM by default
    assert_eq!(
        mgr.local_services() & NODE_BLOOM,
        0,
        "NODE_BLOOM MUST NOT be advertised by default — matches Core init.cpp"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// G30 — BIP-35 mempool gate consults NODE_BLOOM
// Status: PASS — this is the one BIP-37-dependent feature that IS correctly
// gated. main.rs:3735-3789 reads `pm.peer_bloom_filters_enabled()` and
// disconnects the peer if NODE_BLOOM is not advertised.
// Core ref: bitcoin-core/src/net_processing.cpp:4853-4855
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn g30_bip35_mempool_gate_consults_node_bloom() {
    // We can verify the gate function shape here; the live disconnect
    // behaviour is exercised in main.rs and not unit-testable from this
    // crate. PASS regression-pin: the public method exists and the default
    // config returns false.
    let cfg = PeerManagerConfig::default();
    let mgr = PeerManager::new(cfg, ChainParams::testnet4());
    assert!(
        !mgr.peer_bloom_filters_enabled(),
        "with default config the BIP-35 mempool gate MUST disconnect peers"
    );

    let mut cfg_on = PeerManagerConfig::default();
    cfg_on.peer_bloom_filters = true;
    let mgr_on = PeerManager::new(cfg_on, ChainParams::testnet4());
    assert!(
        mgr_on.peer_bloom_filters_enabled(),
        "BIP-35 mempool gate MUST permit mempool requests when -peerbloomfilters=true"
    );
    assert!(
        mgr_on.local_services() & NODE_BLOOM != 0,
        "NODE_BLOOM MUST be advertised when -peerbloomfilters=true"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-1 / G2 P0-CDIV — NODE_BLOOM advertise-without-fulfil
//
// This is the headline W134 finding: if an operator sets
// `-peerbloomfilters=true`, NODE_BLOOM is added to local_services() and
// the outbound version message — but NO filterload/filteradd/filterclear
// handlers are wired. A peer connecting via this advertised capability will
// send filterload, expect filtered tx relay + merkleblock, and receive
// nothing (its messages fall through `_ => { pm.handle_event(...) }` in
// main.rs:4061-4066 and the PeerEvent::Message handler in
// peer_manager.rs:2017-2160 has no FilterLoad/FilterAdd/FilterClear arms).
//
// We pin this as a behavioural regression test: when -peerbloomfilters=true,
// the bit IS advertised today (and that is the bug-compat fault — we
// should NOT advertise until handlers land). The xfail documents the
// expected post-fix behaviour: either Option A (strip the gate so the bit
// is unreachable) or Option B (gate via BIP37_P2P_HANDLERS_REGISTERED).
// See audit doc for closure paths.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn bug1_node_bloom_advertised_when_peerbloomfilters_true_today() {
    // PIN current (buggy) behaviour: bit is set even though handlers are absent.
    let mut cfg = PeerManagerConfig::default();
    cfg.peer_bloom_filters = true;
    let mgr = PeerManager::new(cfg, ChainParams::testnet4());

    assert_ne!(
        mgr.local_services() & NODE_BLOOM,
        0,
        "PIN: NODE_BLOOM is currently advertised when -peerbloomfilters=true \
         — this is the P0-CDIV advertise-without-fulfil bug (BUG-1, G2). \
         Closure: Option A (strip gate) or Option B (BIP37_P2P_HANDLERS_REGISTERED gate)."
    );
}

#[test]
#[ignore = "BUG-1 (P0-CDIV): NODE_BLOOM is advertised when -peerbloomfilters=true \
            but no filterload/filteradd/filterclear handlers are wired \
            (main.rs:4061 _ => catch-all + peer_manager.rs:2017-2160 has no \
            FilterLoad/FilterAdd/FilterClear arms). Either remove the gate \
            (Option A) or plumb BIP37_P2P_HANDLERS_REGISTERED:bool = false \
            (Option B mirroring FIX-71/FIX-82 BIP-157 plumb-gate pattern)."]
fn bug1_node_bloom_gate_must_require_handlers_registered() {
    // When closed via Option B:
    //   pub const BIP37_P2P_HANDLERS_REGISTERED: bool = false;  // until wired
    //   local_services() should OR NODE_BLOOM only when
    //   peer_bloom_filters && BIP37_P2P_HANDLERS_REGISTERED.
    //
    // Expected post-fix:
    //   let mut cfg = PeerManagerConfig::default();
    //   cfg.peer_bloom_filters = true;
    //   let mgr = PeerManager::new(cfg, ChainParams::testnet4());
    //   assert_eq!(mgr.local_services() & NODE_BLOOM, 0,
    //       "until handlers land, gate must keep the bit unset");
    todo!("close BUG-1 via Option A (strip gate) or Option B (plumb-gate-then-flip)")
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-level pin: filterload / filteradd / filterclear / merkleblock messages
// deserialize into the correct NetworkMessage variants. This is a PARTIAL
// pass — the wire path is intact; the bug is in the HANDLER (see BUG-1, BUG-30).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn structural_filterload_message_parses_into_correct_variant() {
    // Minimal filterload payload: CompactSize(1) + 1 byte vData + nHashFuncs(4)
    // + nTweak(4) + nFlags(1)
    let payload: &[u8] = &[
        0x01, 0x00, // CompactSize(1) + 1 byte of vData
        0x01, 0x00, 0x00, 0x00, // nHashFuncs = 1 (LE32)
        0x00, 0x00, 0x00, 0x00, // nTweak = 0 (LE32)
        0x00, // nFlags = 0
    ];

    let result = NetworkMessage::deserialize("filterload", payload).expect("filterload must parse");
    match result {
        NetworkMessage::FilterLoad(bytes) => {
            assert_eq!(bytes, payload, "FilterLoad must preserve raw payload bytes");
        }
        other => panic!("expected FilterLoad variant, got {:?}", other),
    }
}

#[test]
fn structural_filterclear_message_parses_correctly() {
    let result = NetworkMessage::deserialize("filterclear", &[]).expect("filterclear must parse");
    assert!(
        matches!(result, NetworkMessage::FilterClear),
        "filterclear must map to FilterClear variant"
    );
}

#[test]
fn structural_filteradd_message_parses_correctly() {
    // filteradd payload: CompactSize(data_len) + data
    let data = b"\xab\xcd\xef";
    let mut payload = vec![data.len() as u8];
    payload.extend_from_slice(data);
    let result = NetworkMessage::deserialize("filteradd", &payload).expect("filteradd must parse");
    match result {
        NetworkMessage::FilterAdd(bytes) => {
            assert_eq!(
                bytes,
                payload.as_slice(),
                "FilterAdd must preserve raw payload bytes"
            );
        }
        other => panic!("expected FilterAdd variant, got {:?}", other),
    }
}

#[test]
fn structural_bloom_message_commands_round_trip() {
    assert_eq!(NetworkMessage::FilterLoad(vec![]).command(), "filterload");
    assert_eq!(NetworkMessage::FilterAdd(vec![]).command(), "filteradd");
    assert_eq!(NetworkMessage::FilterClear.command(), "filterclear");
    assert_eq!(NetworkMessage::MerkleBlock(vec![]).command(), "merkleblock");
}

// ─────────────────────────────────────────────────────────────────────────────
// Pin BUG-24: EvictionCandidate.bloom_filter exists as a pub field — but
// (a) is never set true and (b) is never read. This pin documents that the
// field type and visibility are unchanged from W110 so future fix-wave
// regression tests can target it. The xfail above (G28) tracks the actual
// bug closure.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn structural_eviction_candidate_bloom_filter_field_pub() {
    // Confirm the struct still has a `bloom_filter: bool` field exposed publicly.
    // The compile-time visibility check is implicit; we exercise the path by
    // constructing a value with the field set true and reading it back.
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::Instant;

    let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let c = EvictionCandidate {
        peer_id: PeerId(1),
        addr,
        keyed_netgroup: 0,
        netgroup: NetGroup::new(vec![]),
        is_local: true,
        network: NetworkType::Ipv4,
        connected_time: Instant::now(),
        min_ping_time: Some(Duration::from_millis(10)),
        last_block_time: None,
        last_tx_time: None,
        relevant_services: true,
        relay_txs: true,
        bloom_filter: true, // <-- pin: field is settable
        prefer_evict: false,
        noban: false,
    };
    assert!(
        c.bloom_filter,
        "field is pub and settable — but call site peer_manager.rs:2500 \
         hard-codes false (BUG-24 part a) and select_node_to_evict never \
         reads it (BUG-24 part b)"
    );
}
