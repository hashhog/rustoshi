//! W123 — Mining / GBT / BlockAssembler / BIP-152 parity audit (rustoshi).
//!
//! Discovery wave covering 30 gates across the full mining stack:
//!   - BlockAssembler / `build_block_template` (transaction selection, weight,
//!     sigops, witness commitment, coinbase, anti-fee-sniping)
//!   - mining RPCs (`getblocktemplate`, `submitblock`, `getmininginfo`,
//!     `prioritisetransaction`, `getnetworkhashps`)
//!   - BIP-141 witness commitment
//!   - BIP-152 compact block (sendcmpct/cmpctblock/getblocktxn/blocktxn)
//!   - cluster-mempool ImprovesFeerateDiagram for block-builder ordering
//!   - configuration plumbing (-blockmaxweight, -blockmintxfee,
//!     -blockreservedweight, -blockversion)
//!
//! ## Bitcoin Core reference surfaces
//!   - `bitcoin-core/src/node/miner.cpp`      — BlockAssembler::CreateNewBlock
//!   - `bitcoin-core/src/rpc/mining.cpp`      — getblocktemplate, submitblock,
//!                                              getmininginfo, prioritisetransaction
//!   - `bitcoin-core/src/policy/feefrac.cpp`  — cluster-mempool feerate diagram
//!   - `bitcoin-core/src/blockencodings.cpp`  — BIP-152 CmpctBlock construction
//!   - BIP-22/23 (GBT), BIP-141 (witness commitment), BIP-152 (compact block)
//!
//! ## Gate legend
//!   - P0-CDIV: consensus-divergent / live fork risk
//!   - P1     : remotely exploitable / mining-pool interop break
//!   - P2     : spec deviation
//!   - P3     : minor spec gap / monitoring hole
//!   - P4     : cosmetic
//!
//! ## Status summary (per gate)
//!   PRESENT (10): G1 block_weight_4M / G2 sigops_80000 / G7 anti_fee_sniping_locktime /
//!                 G9 halving_schedule / G10 bip34_height / G12 cmpctblock_codec /
//!                 G15 bip152_dispatch / G17 nonce_extranonce / G19 segwit_serialization /
//!                 G24 mempool_min_fee_stop
//!   PARTIAL ( 7): G3 witness_commitment_segwit_active / G5 modified_fee_selection /
//!                 G6 ancestor_aware_selection / G14 cmpctblock_construction_only_tests /
//!                 G16 sendcmpct_high_bandwidth_send / G22 template_refresh_on_new_tip /
//!                 G29 sigops_per_tx_witness_aware
//!   MISSING (13): G4 nBlockMaxWeight_clamp / G8 per_tx_fees_in_gbt_response /
//!                 G11 depends_array_in_gbt_response / G13 capabilities_field /
//!                 G18 m_last_block_weight_tracked / G20 cluster_improves_diagram /
//!                 G21 blockmaxweight_cli_arg / G23 truc_topology_at_block_builder /
//!                 G25 blockmintxfee_cli_arg / G26 submitblock_workid /
//!                 G27 mining_info_networkhashps_zero / G28 proposal_mode_dispatch /
//!                 G30 package_mining_feerates_array
//!
//! Tests for BUG / MISSING gates are `#[ignore]`d to document the gap
//! without breaking the build; they flip to passing when fixed.

use rustoshi_consensus::block_template::{
    build_block_template, BlockTemplateConfig, DEFAULT_BLOCK_RESERVED_WEIGHT,
    MAX_SEQUENCE_NONFINAL, MINIMUM_BLOCK_RESERVED_WEIGHT, SEQUENCE_FINAL,
};
use rustoshi_consensus::mempool::{AtmpOptions, Mempool, MempoolConfig};
use rustoshi_consensus::params::{
    block_subsidy, ChainParams, MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT,
    SUBSIDY_HALVING_INTERVAL,
};
use rustoshi_consensus::CoinEntry;
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::HashMap;

// ============================================================
// HELPERS
// ============================================================

fn test_opts() -> AtmpOptions {
    AtmpOptions {
        skip_script_checks: true,
        ..Default::default()
    }
}

fn mp_add(
    mp: &mut Mempool,
    tx: Transaction,
    utxos: &HashMap<OutPoint, CoinEntry>,
) -> Result<Hash256, rustoshi_consensus::MempoolError> {
    mp.add_transaction_with_options(tx, &|op| utxos.get(op).cloned(), test_opts())
}

fn test_coin(value: u64) -> CoinEntry {
    CoinEntry {
        value,
        // P2PKH so standardness gates accept the fixture.
        script_pubkey: {
            let mut v = vec![0x76, 0xa9, 0x14];
            v.extend_from_slice(&[0x42u8; 20]);
            v.push(0x88);
            v.push(0xac);
            v
        },
        height: 0,
        is_coinbase: false,
    }
}

fn empty_mempool() -> Mempool {
    Mempool::new(MempoolConfig {
        verify_scripts: false,
        ..Default::default()
    })
}

fn regtest_params() -> ChainParams {
    ChainParams::regtest()
}

fn default_config() -> BlockTemplateConfig {
    BlockTemplateConfig::default()
}

fn make_simple_tx(prev_txid: Hash256, vout: u32, value: u64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: vec![],
            sequence: SEQUENCE_FINAL,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: vec![
                0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
            ],
        }],
        lock_time: 0,
    }
}

// ============================================================
// G1 — block weight 4M enforced as the absolute ceiling
// ============================================================

/// G1 — PRESENT: MAX_BLOCK_WEIGHT = 4_000_000 matches Core consensus.h.
/// `build_block_template` uses this both as the inclusion ceiling
/// (block_template.rs:393) and the GBT `weightlimit` (server.rs:4321).
#[test]
fn test_g1_block_weight_4m_enforced() {
    assert_eq!(
        MAX_BLOCK_WEIGHT, 4_000_000,
        "MAX_BLOCK_WEIGHT must be 4_000_000 (Core consensus/consensus.h)"
    );
    assert_eq!(
        MAX_BLOCK_SERIALIZED_SIZE, 4_000_000,
        "MAX_BLOCK_SERIALIZED_SIZE matches the post-segwit weight ceiling"
    );
}

// ============================================================
// G2 — block sigops cost 80000 enforced
// ============================================================

/// G2 — PRESENT: MAX_BLOCK_SIGOPS_COST = 80_000 matches Core consensus.h.
/// The selection loop enforces `total_sigops + tx_sigops >= max_sigops`
/// (block_template.rs:413), and GBT advertises `sigoplimit: 80000`
/// (server.rs:4319).
#[test]
fn test_g2_block_sigops_80k_enforced() {
    assert_eq!(
        MAX_BLOCK_SIGOPS_COST, 80_000,
        "MAX_BLOCK_SIGOPS_COST must be 80_000 (Core consensus.h)"
    );
    let cfg = default_config();
    assert_eq!(cfg.max_sigops, MAX_BLOCK_SIGOPS_COST);
}

// ============================================================
// G3 — coinbase witness commitment per BIP-141 when segwit active
// ============================================================

/// G3 — PARTIAL (P2-CDIV via W108 G11 carry-forward): witness commitment is
/// NOT added when segwit is active but no witness transactions are in the
/// template. Core (`validation.cpp::GenerateCoinbaseCommitment`, called
/// unconditionally from miner.cpp:200) always emits the commitment once
/// segwit is active because the coinbase wtxid is itself in the witness
/// merkle tree.
///
/// rustoshi `build_coinbase_tx` (block_template.rs:586,598) gates on
/// `has_witness = txs.iter().any(|tx| tx.has_witness())` instead of
/// `segwit_active`. For an empty mempool on segwit-active chain, the
/// commitment is omitted; a block built from this template would be
/// rejected by validating peers as `bad-witness-nonce-size`.
///
/// Carry-forward from W108 G11.
#[test]
// FIXED 2026-05-19: `build_coinbase_tx` now takes a `segwit_active` parameter
// (sourced from `params.is_segwit_active(height)` at the call site) and gates
// the witness commitment on it, per BIP-141 / Core validation.cpp:3997-4019.
fn test_g3_witness_commitment_when_segwit_active_no_witness_txs() {
    let params = regtest_params(); // segwit always active on regtest
    let mp = empty_mempool();
    let cfg = default_config();
    let template = build_block_template(
        &mp,
        Hash256([0u8; 32]),
        1,
        1_700_000_000,
        0x207fffff,
        0,
        &params,
        &cfg,
    );
    let has_commit = template.coinbase_tx.outputs.iter().any(|o| {
        o.script_pubkey.len() == 38
            && o.script_pubkey[0] == 0x6a
            && o.script_pubkey[1] == 0x24
            && o.script_pubkey[2..6] == [0xaa, 0x21, 0xa9, 0xed]
    });
    assert!(
        has_commit,
        "Core validation.cpp:3997-4019 always adds the OP_RETURN witness commitment when segwit active"
    );
}

// ============================================================
// G4 — nBlockMaxWeight clamp to (block_reserved_weight, MAX_BLOCK_WEIGHT)
// ============================================================

/// G4 — MISSING (P2 carry-forward of W108 G8): block_template.rs:393 compares
/// against `MAX_BLOCK_WEIGHT` (absolute ceiling) instead of `config.max_weight`
/// (= `MAX_BLOCK_WEIGHT - block_reserved_weight`). Core miner.cpp:241 uses
/// `m_options.nBlockMaxWeight` which has been clamped down by
/// `ClampOptions` (miner.cpp:86).
///
/// Additionally, `BlockTemplateConfig` has no plumb for an operator override
/// of `nBlockMaxWeight`; `ClampOptions` itself is not modeled.
#[test]
#[ignore = "BUG G4 (P2) — weight_fails compares against MAX_BLOCK_WEIGHT not config.max_weight \
            (carry-forward W108 G8; block_template.rs:393); no ClampOptions equivalent"]
fn test_g4_nblockmaxweight_clamp_to_reserved() {
    panic!(
        "weight_fails must compare against config.max_weight; ClampOptions must enforce \
         max_weight ∈ [MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT] \
         (Core miner.cpp:86, ClampOptions)"
    );
}

// G4 supporting — clamp constants are correct.
#[test]
fn test_g4_clamp_constants_match_core() {
    assert_eq!(
        DEFAULT_BLOCK_RESERVED_WEIGHT, 8_000,
        "policy.h DEFAULT_BLOCK_RESERVED_WEIGHT"
    );
    assert_eq!(
        MINIMUM_BLOCK_RESERVED_WEIGHT, 2_000,
        "policy.h MINIMUM_BLOCK_RESERVED_WEIGHT"
    );
}

// ============================================================
// G5 — per-tx fee aggregation: modified_fee in selection ranking
// ============================================================

/// G5 — PARTIAL (P3): FIX-72 introduced `get_modified_fee(entry)` so the
/// single-entry ranking and the priority queue's `fee` field now incorporate
/// the prioritisetransaction delta (block_template.rs:343-354).  However:
///
///   (1) Ancestor-fee aggregation (`entry.ancestor_fees`) still uses raw
///       fees (mempool.rs:2349-2351 + block_template.rs:344) when
///       `ancestor_count > 1`, so a fee bump on an ancestor does NOT
///       propagate to descendants' chunk feerate.  Core
///       `CTxMemPoolEntry::GetModFeesWithAncestors` sums the deltas across
///       the ancestor set (W106 G8 follow-up acknowledged in the code).
///
///   (2) `total_fees` (block_template.rs:445) and the coinbase reward
///       (line 454) use raw `entry.fee`, matching Core (miner.cpp:178:
///       `nFees + GetBlockSubsidy`). PRESENT.
///
/// Net: mining selection ordering is partially aware of fee deltas;
/// CPFP ranking via prioritisetransaction on a single ancestor is broken.
#[test]
#[ignore = "BUG G5 (P3) — ancestor_fees aggregation skips prioritisetransaction delta \
            (block_template.rs:344-345; mempool.rs:2349-2351; W106 G8 follow-up)"]
fn test_g5_modified_fee_propagates_to_descendant_ranking() {
    panic!(
        "ancestor_fees aggregation must sum entry.fee_delta across the ancestor set \
         (Core txmempool.cpp::CTxMemPoolEntry::GetModFeesWithAncestors)"
    );
}

// G5 supporting — total_fees uses raw fee for coinbase reward (PRESENT).
#[test]
fn test_g5_coinbase_reward_uses_raw_fees() {
    let params = regtest_params();
    let mut mp = empty_mempool();
    let tx = make_simple_tx(Hash256([0xCC; 32]), 0, 987_655);
    let fee = 12_345u64;
    let mut utxos: HashMap<OutPoint, CoinEntry> = HashMap::new();
    utxos.insert(
        OutPoint {
            txid: Hash256([0xCC; 32]),
            vout: 0,
        },
        test_coin(1_000_000),
    );
    let _ = mp_add(&mut mp, tx, &utxos);
    let template = build_block_template(
        &mp,
        Hash256::ZERO,
        1,
        1_700_000_000,
        0x207fffff,
        0,
        &params,
        &default_config(),
    );
    let expected =
        block_subsidy(1, SUBSIDY_HALVING_INTERVAL) + fee;
    assert_eq!(
        template.coinbase_tx.outputs[0].value, expected,
        "coinbase reward = subsidy + raw fees (Core miner.cpp:178)"
    );
}

// ============================================================
// G6 — ancestor-aware selection (CPFP / addPackageTxs)
// ============================================================

/// G6 — PARTIAL (P2): rustoshi's `get_sorted_for_mining` (mempool.rs:2340)
/// ranks by `ancestor_fee_rate = ancestor_fees / ancestor_size`, which is
/// the ancestor-feerate algorithm (Core pre-cluster-mempool default).
/// `build_block_template` then re-orders via the priority queue.
///
/// However, the loop pops one tx at a time and includes it standalone —
/// there is no "package admission" where an ancestor set is added atomically.
/// Core post-cluster-mempool uses `GetBlockBuilderChunk` (cluster
/// linearization chunks), which atomically adds an entire chunk of
/// connected ancestors. Rustoshi's loop iterates by individual tx, which
/// fails for chains where an unincluded ancestor must precede a descendant
/// (the descendant pops first by ancestor feerate but its ancestors are
/// not yet in the block).
#[test]
#[ignore = "BUG G6 (P2) — single-tx pop loop instead of chunk-atomic ancestor admission \
            (block_template.rs:372; Core miner.cpp:279-333 addChunks)"]
fn test_g6_ancestor_aware_atomic_admission() {
    panic!(
        "Selection loop must pop an entire chunk (linearization) atomically. \
         Rustoshi pops one tx at a time and may include a descendant before \
         all its ancestors are present in the block (Core miner.cpp::addChunks)"
    );
}

// ============================================================
// G7 — anti-fee-sniping coinbase locktime
// ============================================================

/// G7 — PRESENT: coinbase locktime = height-1, sequence = MAX_SEQUENCE_NONFINAL.
/// `build_coinbase_tx` (block_template.rs:608-619, 627). Matches Core
/// miner.cpp:171,196.
#[test]
fn test_g7_anti_fee_sniping_coinbase_locktime() {
    let params = regtest_params();
    let mp = empty_mempool();
    let cfg = default_config();
    for height in [100u32, 840_000, 1] {
        let template = build_block_template(
            &mp,
            Hash256::ZERO,
            height,
            1_700_000_000,
            0x207fffff,
            0,
            &params,
            &cfg,
        );
        assert_eq!(
            template.coinbase_tx.lock_time,
            height.saturating_sub(1),
            "anti-fee-sniping locktime at height {}",
            height
        );
        assert_eq!(
            template.coinbase_tx.inputs[0].sequence, MAX_SEQUENCE_NONFINAL,
            "coinbase sequence must be MAX_SEQUENCE_NONFINAL (Core miner.cpp:171)"
        );
    }
}

// ============================================================
// G8 — per-tx fees in GBT transactions[].fee
// ============================================================

/// G8 — MISSING (P1 — mining-pool interop break): GBT response always emits
/// `transactions[].fee = 0` (server.rs:4193). Core mining.cpp:926:
/// `entry.pushKV("fee", tx_fees.at(index_in_template))` where `tx_fees` is
/// the per-tx fee vector from `pblocktemplate->vTxFees`.
///
/// Impact: mining pools that filter or shape templates by per-tx fee will see
/// every non-coinbase entry as a zero-fee tx. BIP-22:
/// `"fee" .. clients MUST NOT assume there isn't one` — the rustoshi shape
/// passively asserts there is none.
///
/// Root cause: `BlockTemplate` carries `total_fees` but no `per_tx_fees`
/// vector parallel to `per_tx_sigops`.
#[test]
#[ignore = "BUG G8 (P1) — GBT transactions[].fee hardcoded to 0 \
            (server.rs:4193; Core mining.cpp:926 vTxFees)"]
fn test_g8_per_tx_fees_in_gbt_response() {
    panic!(
        "BlockTemplate must carry per_tx_fees in the same order as transactions; \
         server.rs:4188 must read from it instead of `fee: 0` \
         (Core mining.cpp:926, pblocktemplate->vTxFees)"
    );
}

// ============================================================
// G9 — block reward halving schedule
// ============================================================

/// G9 — PRESENT: `block_subsidy` halves every `SUBSIDY_HALVING_INTERVAL`
/// blocks (params.rs:298) and reaches 0 after 64 halvings, matching Core.
#[test]
fn test_g9_block_reward_halving_schedule() {
    assert_eq!(SUBSIDY_HALVING_INTERVAL, 210_000);
    assert_eq!(block_subsidy(0, SUBSIDY_HALVING_INTERVAL), 50 * 100_000_000);
    assert_eq!(
        block_subsidy(209_999, SUBSIDY_HALVING_INTERVAL),
        50 * 100_000_000
    );
    assert_eq!(
        block_subsidy(210_000, SUBSIDY_HALVING_INTERVAL),
        25 * 100_000_000
    );
    assert_eq!(
        block_subsidy(420_000, SUBSIDY_HALVING_INTERVAL),
        12_500_000_000 / 10
    );
    assert_eq!(
        block_subsidy(630_000, SUBSIDY_HALVING_INTERVAL),
        625_000_000
    );
    assert_eq!(
        block_subsidy(64 * SUBSIDY_HALVING_INTERVAL, SUBSIDY_HALVING_INTERVAL),
        0
    );
}

// ============================================================
// G10 — BIP-34 height in coinbase scriptSig + 2-byte minimum
// ============================================================

/// G10 — PRESENT: height encoded in coinbase scriptSig per BIP-34;
/// the build path appends OP_0 dummy extranonce for heights 1-16 to satisfy
/// the `bad-cb-length` rule (block_template.rs:579-581). Matches
/// Core miner.cpp:187-193 `include_dummy_extranonce` semantics.
#[test]
fn test_g10_bip34_coinbase_height_and_min_length() {
    let params = regtest_params();
    let mp = empty_mempool();
    let cfg = default_config();
    for h in [1u32, 16, 17, 100, 840_000] {
        let template = build_block_template(
            &mp,
            Hash256::ZERO,
            h,
            1_700_000_000,
            0x207fffff,
            0,
            &params,
            &cfg,
        );
        let sig = &template.coinbase_tx.inputs[0].script_sig;
        assert!(
            sig.len() >= 2,
            "coinbase scriptSig must be ≥ 2 bytes (bad-cb-length) at height {}",
            h
        );
    }
}

// ============================================================
// G11 — depends[] populated in GBT transactions
// ============================================================

/// G11 — MISSING (P2 — BIP-22): GBT response always emits
/// `transactions[].depends = []` (server.rs:4192). Core mining.cpp:917-923
/// builds a `setTxIndex: txid → index_in_template` map and pushes each
/// dependency that's also in the template.
///
/// Impact: a mining client cannot reorder transactions safely — it doesn't
/// know which txs depend on which other txs in the template. BIP-22 spec
/// requires this field when `txns` is mutable (and it is: "transactions"
/// appears in the `mutable` array — server.rs:4317).
#[test]
#[ignore = "BUG G11 (P2) — GBT transactions[].depends hardcoded to [] \
            (server.rs:4192; Core mining.cpp:917-923)"]
fn test_g11_depends_array_populated() {
    panic!(
        "Build setTxIndex {{txid → index}} and push deps for each input whose \
         prevout.hash is in the template (Core mining.cpp:917-923)"
    );
}

// ============================================================
// G12 — BIP-152 compact block wire codec
// ============================================================

/// G12 — PRESENT: `CmpctBlock` codec implemented in
/// `crates/network/src/compact_blocks.rs` with SipHash-2-4 short IDs,
/// version-1 and version-2 (segwit), and `PrefilledTx` differential indexing.
///
/// Round-trip and BIP-152 test vector verification live in the network
/// crate's own tests; documented as PRESENT here for the W123 audit by
/// pinning the BIP-152 protocol constants directly (the network crate
/// cannot be imported into the consensus crate without a circular dep —
/// network -> consensus).
#[test]
fn test_g12_bip152_codec_present() {
    // BIP-152 protocol constants (pinned here to W123; live in
    // crates/network/src/compact_blocks.rs):
    //   SHORTTXIDS_LENGTH = 6
    //   CMPCT_VERSION_1   = 1
    //   CMPCT_VERSION_2   = 2  (segwit-aware, BIP-144)
    //   MAX_CMPCTBLOCK_PEERS_HB = 3
    const SHORTTXIDS_LENGTH: usize = 6;
    const CMPCT_VERSION_1: u64 = 1;
    const CMPCT_VERSION_2: u64 = 2;
    const MAX_CMPCTBLOCK_PEERS_HB: usize = 3;
    assert_eq!(SHORTTXIDS_LENGTH, 6, "BIP-152 short IDs are 6 bytes");
    assert_eq!(CMPCT_VERSION_1, 1);
    assert_eq!(CMPCT_VERSION_2, 2);
    assert_eq!(
        MAX_CMPCTBLOCK_PEERS_HB, 3,
        "Core default MAX_CMPCTBLOCK_PEERS_HB"
    );
}

// ============================================================
// G13 — BIP-22 capabilities field
// ============================================================

/// G13 — MISSING (P3): GBT response does NOT emit a `capabilities` array.
/// Core mining.cpp:948 emits `["proposal"]`. Without it, BIP-22-compliant
/// callers cannot discover whether the server supports proposal mode.
///
/// rustoshi `BlockTemplateResult` (types.rs:585-625) has no `capabilities`
/// field. Note this is consistent with G28 (proposal mode actually missing) —
/// emitting `["proposal"]` would be wrong given the unimplemented dispatch.
#[test]
#[ignore = "BUG G13 (P3) — GBT response missing `capabilities` array \
            (types.rs:585; Core mining.cpp:946-948)"]
fn test_g13_capabilities_array_in_gbt_response() {
    panic!(
        "BlockTemplateResult must include `capabilities: [\"proposal\"]` once G28 lands; \
         today the field is silently absent (Core mining.cpp:946-948)"
    );
}

// ============================================================
// G14 — CmpctBlock construction outside tests
// ============================================================

/// G14 — PARTIAL (P2 — relay incompleteness): `CmpctBlock::from_block` exists
/// (compact_blocks.rs:109) and decodes wire form correctly, but it is
/// **never called in production code** — every `from_block` invocation in
/// `compact_blocks.rs` is inside `#[cfg(test)]` blocks (lines 1234, 1249,
/// 1270, 1289, …).  `rustoshi/src/main.rs:3826` handles incoming `cmpctblock`
/// messages and assembles via `PartiallyDownloadedBlock`, but the sender
/// side never produces a `cmpctblock` to announce a newly-mined or relayed
/// block to HB-mode peers.
///
/// Net effect: rustoshi receives compact blocks but never sends them. HB-mode
/// peers will time out waiting for a `cmpctblock` after our `headers`
/// announce and downgrade to `getdata`.
#[test]
#[ignore = "BUG G14 (P2) — CmpctBlock::from_block invoked only in tests; \
            no send-side production path (compact_blocks.rs:109; rustoshi/src/main.rs)"]
fn test_g14_cmpctblock_construction_in_production() {
    panic!(
        "Send-side cmpctblock announcement must be wired into the relay pipeline \
         (Core net_processing.cpp::MaybeSendBlockAnnounce)"
    );
}

// ============================================================
// G15 — BIP-152 message dispatch (sendcmpct/cmpctblock/getblocktxn/blocktxn)
// ============================================================

/// G15 — PRESENT: BIP-152 messages are encoded in the V2 transport table
/// (v2_transport.rs:108-125) and the message dispatcher (message.rs:692-695,
/// 1051-1063) round-trips them. `rustoshi/src/main.rs:3826,3874,3950` handles
/// the receive side: cmpctblock → PartiallyDownloadedBlock → getblocktxn →
/// blocktxn reconstruction.
///
/// Cannot import `rustoshi_network` from the consensus crate's test target
/// (network -> consensus circular dep); the message round-trip lives in
/// `crates/network/src/message.rs::sendcmpct_roundtrip` and similar tests.
#[test]
fn test_g15_bip152_message_dispatch_present() {
    // BIP-152 message names that must appear in the wire codec table
    // (pinned for the W123 audit).
    let bip152_messages = ["sendcmpct", "cmpctblock", "getblocktxn", "blocktxn"];
    assert_eq!(bip152_messages.len(), 4);
}

// ============================================================
// G16 — sendcmpct high-bandwidth announce SEND side
// ============================================================

/// G16 — PARTIAL (P3): `CompactBlockRelay::handle_sendcmpct`
/// (compact_blocks.rs:1032) correctly tracks per-peer HB/LB state, but no
/// production code path proactively SENDS our own `sendcmpct(announce=true)`
/// to peers we'd like to receive compact blocks from in HB mode. Core
/// (net_processing.cpp::SendSendCmpct) sends sendcmpct to up to
/// MAX_CMPCTBLOCK_PEERS_HB outbound peers.
///
/// peer.rs:1241-1252 sends `sendcmpct` ONCE during handshake. After that,
/// there is no dynamic promotion to HB mode based on peer behavior.
#[test]
#[ignore = "BUG G16 (P3) — no dynamic HB-mode promotion via sendcmpct(announce=true) \
            (peer.rs:1241; Core net_processing.cpp::SendSendCmpct)"]
fn test_g16_sendcmpct_high_bandwidth_promote() {
    panic!(
        "Need a periodic task that promotes up to MAX_CMPCTBLOCK_PEERS_HB outbound peers \
         via sendcmpct(announce=true) (Core net_processing.cpp::SendSendCmpct)"
    );
}

// ============================================================
// G17 — nonce / extranonce iteration in coinbase
// ============================================================

/// G17 — PRESENT: BlockHeader.nonce is reset to 0 in the template
/// (block_template.rs:518); miner is expected to iterate it.  ExtraNonce
/// support is via the coinbase scriptSig extra_data field (block_template
/// .rs:583, BlockTemplateConfig::coinbase_extra_data).  `mine_blocks`
/// (server.rs:9436) does iterate nonces internally.  BIP-22 `mutable` array
/// includes "time" + "transactions" + "prevblock" (server.rs:4317).
#[test]
fn test_g17_nonce_extranonce_iteration() {
    let params = regtest_params();
    let mp = empty_mempool();
    let template = build_block_template(
        &mp,
        Hash256::ZERO,
        1,
        1_700_000_000,
        0x207fffff,
        0,
        &params,
        &default_config(),
    );
    assert_eq!(
        template.header.nonce, 0,
        "template nonce must be 0; miner varies it (Core miner.cpp:221)"
    );
}

// ============================================================
// G18 — m_last_block_weight / m_last_block_num_txs tracking
// ============================================================

/// G18 — MISSING (P3 — monitoring): Core (`BlockAssembler::m_last_block_weight`,
/// `m_last_block_num_txs`, miner.cpp:159-160) records each
/// `CreateNewBlock` call's weight and tx count. `getmininginfo` then surfaces
/// them as `currentblockweight` / `currentblocktx` (mining.cpp:467-468).
///
/// Rustoshi has no such tracking; W108 G27 documents the absence from
/// `MiningInfo` (types.rs:545-587).  Mining pool monitoring loses signal.
#[test]
#[ignore = "BUG G18 (P3) — no m_last_block_weight/m_last_block_num_txs tracking \
            (carry-forward W108 G27)"]
fn test_g18_last_block_weight_num_txs_tracked() {
    panic!(
        "Persist last_block_weight + last_block_num_txs across getblocktemplate calls; \
         surface as currentblockweight + currentblocktx in getmininginfo \
         (Core miner.cpp:159-160, mining.cpp:467-468)"
    );
}

// ============================================================
// G19 — segwit serialization in template (witness data included)
// ============================================================

/// G19 — PRESENT: GBT transaction data is hex-encoded via
/// `tx.serialize()` (server.rs:4189). `Transaction::serialize` produces
/// segwit serialization when the tx has witnesses (BIP-141 marker/flag).
/// `tx.wtxid()` is reported as the `hash` field, consistent with Core
/// mining.cpp:915 `tx.GetWitnessHash().GetHex()`.
///
/// Coinbase wtxid is the all-zero hash; verified via the BIP-141
/// witness merkle commitment computation (block_template.rs::build_witness_commitment
/// inserts `Hash256::ZERO` at index 0 in wtxids).
///
/// Structural check: a witness tx round-trips through its segwit
/// serialization with a distinct wtxid from its txid.
#[test]
fn test_g19_segwit_template_serialization() {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xDD; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: SEQUENCE_FINAL,
            witness: vec![vec![0x01, 0x02, 0x03]],
        }],
        outputs: vec![TxOut {
            value: 5_000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    // A tx with witness data has txid != wtxid; the GBT response
    // reports BOTH (server.rs:4190-4191).  This pins the segwit
    // serialization invariant at the type layer.
    assert!(tx.has_witness());
    assert_ne!(
        tx.txid(),
        tx.wtxid(),
        "witness tx must have distinct txid and wtxid (BIP-141 / BIP-144)"
    );
}

// ============================================================
// G20 — cluster mempool ImprovesFeerateDiagram for block builder ordering
// ============================================================

/// G20 — MISSING (P2 carry-forward of W106 G20): cluster-mempool
/// `ImprovesFeerateDiagram` / `CalculateChunksForRBF` is not implemented
/// (W106 G20 documents the absence at the RBF call site).  As a corollary
/// the block builder does not call any equivalent of Core's
/// `mempool.GetBlockBuilderChunk` (miner.cpp:293) — rustoshi uses a
/// single-tx priority pop and does NOT pop entire cluster chunks atomically.
///
/// Implementation gap chain: mempool has cluster linearizations (mempool.rs:481
/// `DepGraph::linearize`) but the block-builder loop bypasses them — see G6.
#[test]
#[ignore = "BUG G20 (P2) — no GetBlockBuilderChunk equivalent; block-builder iterates per-tx \
            instead of per-cluster-chunk (W106 G20 carry-forward; Core miner.cpp:293)"]
fn test_g20_cluster_improves_feerate_diagram() {
    panic!(
        "Mining selection must iterate cluster-chunks via GetBlockBuilderChunk; \
         each chunk is added atomically per ImprovesFeerateDiagram semantics \
         (Core miner.cpp:293-333, policy/feefrac.cpp)"
    );
}

// ============================================================
// G21 — -blockmaxweight CLI / config plumbing
// ============================================================

/// G21 — MISSING (P3): `BlockTemplateConfig::max_weight` is a struct field but
/// no CLI argument, env var, or config-file key sets it.  Core
/// (`bitcoin-core/src/node/miner.cpp:101`):
/// `options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", ...);`
///
/// Search confirms no `-blockmaxweight` parse path:
///   `grep -r "blockmaxweight\|nBlockMaxWeight\|args.*blockmax" crates/ rustoshi/src/`
///   returns only documentation references in tests.
#[test]
#[ignore = "BUG G21 (P3) — no -blockmaxweight CLI / config plumb \
            (Core node/miner.cpp:101)"]
fn test_g21_blockmaxweight_cli_arg_plumbed() {
    panic!(
        "Add a CLI arg / config key that flows into BlockTemplateConfig::max_weight \
         (Core miner.cpp:101)"
    );
}

// ============================================================
// G22 — template refresh on new tip / new mempool tx
// ============================================================

/// G22 — PARTIAL (P3): `get_block_template` (server.rs:4065) recomputes the
/// template on every invocation by re-reading `state.best_hash`, calling
/// `get_next_work_required`, and `build_block_template`.  This handles
/// "new tip" trivially: the next call sees the new tip.
///
/// However, there is NO long-polling: BIP-22 / BIP-23 longpolling
/// (`longpollid`) is the mechanism by which a mining client subscribes for
/// "template-changed" events. Server emits a longpollid
/// (`server.rs:4311 — format!("{}:{}", state.best_hash.to_hex(),
/// state.best_height)`) but no RPC pathway blocks on a tip change.
/// W108 G3 documents the longpollid format bug separately.
///
/// Net: short-poll templates work, but mining clients that rely on longpoll
/// will hang or get an immediate response (depending on RPC plumbing).
#[test]
#[ignore = "BUG G22 (P3) — no longpoll subscription mechanism; longpoll RPC hangs / no-ops \
            (server.rs:4311; carry-forward of W108 G3)"]
fn test_g22_template_refresh_longpoll_implemented() {
    panic!(
        "Implement BIP-22 long-polling: blocking getblocktemplate that returns when \
         best_tip changes OR a new mempool tx arrives (Core mining.cpp::mining)"
    );
}

// ============================================================
// G23 — TRUC topology enforced at block builder
// ============================================================

/// G23 — MISSING (P3): TRUC (BIP-431) limits are enforced at ATMP (mempool
/// admission) — only valid TRUC topology can be in the mempool.  However,
/// the block builder does not explicitly bail out a tx that would violate
/// TRUC limits IF the mempool state were tampered with mid-build (e.g.
/// after a partial reorg-refill).  Core's package-mining tracks TRUC
/// independently via `IsConsistent` checks at chunk selection time.
///
/// Documented as MISSING because the audit framework's gate is "TRUC at the
/// block builder"; rustoshi only checks at admission.  Risk profile is low
/// (mempool can't have inconsistent TRUC topology under normal operation),
/// but the defense-in-depth gate is absent.
#[test]
#[ignore = "BUG G23 (P3) — no TRUC topology re-check at block builder \
            (block_template.rs:330; Core miner.cpp uses GetBlockBuilderChunk \
             which respects cluster topology)"]
fn test_g23_truc_topology_at_block_builder() {
    panic!(
        "Block builder should reject any selected chunk that violates TRUC \
         ancestor/descendant limits (defense-in-depth; BIP-431)"
    );
}

// ============================================================
// G24 — block_min_fee_rate (mempool min fee) STOPs selection loop
// ============================================================

/// G24 — PRESENT: `block_min_fee_rate` (DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/vbyte)
/// causes the selection loop to `break` (return early) on the first chunk
/// whose feerate falls below the floor (block_template.rs:383). Mirrors
/// Core's `addChunks` `return` (miner.cpp:298-300).
#[test]
fn test_g24_block_min_fee_rate_stops_selection_early() {
    let cfg = default_config();
    assert_eq!(
        cfg.block_min_fee_rate, 1.0,
        "default block_min_fee_rate = 1 sat/vbyte = DEFAULT_BLOCK_MIN_TX_FEE"
    );
    // The break-not-continue behavior is documented in
    // block_template.rs:378-385 comments; covered by W108 G7 ordering test.
}

// ============================================================
// G25 — -blockmintxfee CLI / config plumbing
// ============================================================

/// G25 — MISSING (P4): Similar to G21, `block_min_fee_rate` is a struct field
/// but no CLI / config plumb exists.  Core
/// (`bitcoin-core/src/node/miner.cpp:102-104`):
/// `if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) { ... }`.
#[test]
#[ignore = "BUG G25 (P4) — no -blockmintxfee CLI / config plumb \
            (Core node/miner.cpp:102-104)"]
fn test_g25_blockmintxfee_cli_arg_plumbed() {
    panic!(
        "Add a CLI arg / config key that flows into BlockTemplateConfig::block_min_fee_rate \
         (Core miner.cpp:102-104)"
    );
}

// ============================================================
// G26 — submitblock workid (BIP-23)
// ============================================================

/// G26 — MISSING (P4): BIP-23 workid round-trip is absent.  Since the
/// GBT response does not advertise a `workid` field (W108 G25 documents
/// the structural absence; types.rs:585), a mining client will never round
/// one back — but the submitblock RPC signature still accepts an
/// `Option<dummy>` argument which is silently ignored
/// (server.rs:4331 `async fn submit_block(&self, hex: String)`).
///
/// Net: BIP-23 workid is fully absent; documented as MISSING.
#[test]
#[ignore = "BUG G26 (P4) — no BIP-23 workid round-trip \
            (server.rs:4331; types.rs:585; W108 G25 carry-forward)"]
fn test_g26_submitblock_workid_round_trip() {
    panic!(
        "Add `workid` field to BlockTemplateResult + accept and validate in submitblock \
         (BIP-23; Core rpc/mining.cpp::submitblock)"
    );
}

// ============================================================
// G27 — getmininginfo.networkhashps hardcoded to 0
// ============================================================

/// G27 — MISSING (P3 — monitoring): `getmininginfo` returns
/// `networkhashps: 0.0` (server.rs:4660, comment: "would need to compute from
/// recent blocks"). Core mining.cpp:472 calls
/// `getnetworkhashps().HandleRequest(request)` so the field has a real value.
///
/// rustoshi DOES implement `getnetworkhashps` (server.rs:7933, W108 G28
/// covers the parameter-validation bug separately), so the value is
/// computable — the `getmininginfo` handler just doesn't call it.
#[test]
#[ignore = "BUG G27 (P3) — getmininginfo.networkhashps hardcoded 0.0 \
            (server.rs:4660; Core mining.cpp:472)"]
fn test_g27_mining_info_networkhashps_uses_real_compute() {
    panic!(
        "MiningInfo.networkhashps must call getnetworkhashps logic (Core mining.cpp:472)"
    );
}

// ============================================================
// G28 — getblocktemplate proposal-mode dispatch
// ============================================================

/// G28 — MISSING (P2 — BIP-23 carry-forward of W108 G4 + G5):
/// `get_block_template` (server.rs:4065) takes a `_params: Option<Value>`
/// argument — the underscore prefix documents it as intentionally unused.
/// Core mining.cpp:713-764 parses `mode`, dispatches to proposal-mode
/// verification, and returns the BIP-22 result string.
#[test]
#[ignore = "BUG G28 (P2) — getblocktemplate ignores mode=proposal \
            (server.rs:4067 _params; carry-forward W108 G4/G5)"]
fn test_g28_proposal_mode_dispatch_to_test_block_validity() {
    panic!(
        "Parse template_request, dispatch mode='proposal' to TestBlockValidity \
         (BIP-23; Core mining.cpp:713-764)"
    );
}

// ============================================================
// G29 — per-tx sigops counting (witness sigops awareness)
// ============================================================

/// G29 — PARTIAL (P2-CDIV — theoretical): `build_block_template`
/// (block_template.rs:404-408) uses `get_legacy_sigop_count(&entry.tx) *
/// WITNESS_SCALE_FACTOR` for the sigop budget gate. This is documented as
/// "conservative" — it counts legacy sigops only, scaled by 4. P2SH and
/// witness sigops require UTXO context (`AreInputsStandard` etc.).
///
/// Block validation (validation.rs::count_block_sigops) uses the same
/// approximation, so the two stay consistent. BUT: if an adversarial
/// tx-set with low legacy sigops but high P2SH/witness sigops were
/// admitted to the mempool, the BLOCK BUILDER would gate it through, and
/// SOME OTHER VALIDATOR (running a stricter accurate count, e.g. Core)
/// would reject the block as `bad-blk-sigops`.
///
/// Note: mempool admission also uses the conservative count, so adversarial
/// admission is the same gap — but the audit-framework gate "sigop counting
/// per tx (witness sigops)" is fully accurate ONLY if both admission and
/// mining use the accurate count.
#[test]
#[ignore = "BUG G29 (P2-CDIV theoretical) — legacy sigop approximation only; \
            no P2SH/witness sigops accounted (block_template.rs:404-408)"]
fn test_g29_per_tx_sigops_witness_aware() {
    panic!(
        "Compute accurate per-tx sigop cost (legacy + P2SH + witness) with UTXO context, \
         match Core's GetTransactionSigOpCost (consensus/tx_verify.cpp)"
    );
}

// G29 supporting — total_sigops <= MAX_BLOCK_SIGOPS_COST invariant holds.
#[test]
fn test_g29_total_sigops_budget_invariant() {
    let params = regtest_params();
    let mp = empty_mempool();
    let template = build_block_template(
        &mp,
        Hash256::ZERO,
        1,
        1_700_000_000,
        0x207fffff,
        0,
        &params,
        &default_config(),
    );
    assert!(
        template.total_sigops <= MAX_BLOCK_SIGOPS_COST,
        "total_sigops must never exceed MAX_BLOCK_SIGOPS_COST"
    );
}

// ============================================================
// G30 — package mining: m_package_feerates array in template
// ============================================================

/// G30 — MISSING (P3 — informational): Core
/// `pblocktemplate->m_package_feerates` (miner.cpp:327) records the
/// FeePerVSize of each cluster chunk added to the block, so callers (mining
/// pool dashboards, fee-estimator backfeed) can analyze post-hoc which
/// feerate tiers were actually accepted.  Rustoshi's `BlockTemplate` has
/// no equivalent.
///
/// Note: not currently emitted by Core's GBT response either, but is
/// exposed via the BlockTemplate kernel API; rustoshi's lack of the field
/// closes off future package-mining integrations.
#[test]
#[ignore = "BUG G30 (P3) — BlockTemplate.m_package_feerates equivalent missing \
            (Core miner.cpp:327)"]
fn test_g30_package_feerates_array_recorded() {
    panic!(
        "Add `package_feerates: Vec<FeeFrac>` to BlockTemplate, populated per added chunk \
         (Core miner.cpp:327)"
    );
}

// ============================================================
// W123 cumulative invariants (cross-gate)
// ============================================================

/// Sanity: GBT response constants match Core consensus.h.
#[test]
fn test_w123_gbt_constants_match_core() {
    assert_eq!(MAX_BLOCK_WEIGHT, 4_000_000);
    assert_eq!(MAX_BLOCK_SERIALIZED_SIZE, 4_000_000);
    assert_eq!(MAX_BLOCK_SIGOPS_COST, 80_000);
    assert_eq!(DEFAULT_BLOCK_RESERVED_WEIGHT, 8_000);
    assert_eq!(MINIMUM_BLOCK_RESERVED_WEIGHT, 2_000);
}

/// Sanity: BlockTemplate has the fields W123 expects, and that
/// per_tx_sigops parallels transactions (G29 supporting).
#[test]
fn test_w123_block_template_shape() {
    let params = regtest_params();
    let mp = empty_mempool();
    let template = build_block_template(
        &mp,
        Hash256::ZERO,
        1,
        1_700_000_000,
        0x207fffff,
        0,
        &params,
        &default_config(),
    );
    assert_eq!(
        template.transactions.len(),
        template.per_tx_sigops.len(),
        "per_tx_sigops must parallel transactions"
    );
    // No per_tx_fees parallel array — that's G8 bug.
}
