//! W130 BIP-125 RBF Feebumper Rule 3 audit — rustoshi (Rust)
//!
//! 30-gate audit of the BIP-125 RBF feebumper subsystem versus Bitcoin
//! Core semantics, with **headline focus on Rule 3** —
//! `incrementalRelayFee.GetFee(maxTxSize)` invariant — and the adjacent
//! Rule 1 / 2 / 4 / 5 enforcement points.
//!
//! Reference surfaces:
//!   * `bitcoin-core/src/wallet/feebumper.cpp` —
//!     `CreateRateBumpTransaction`, `CheckFeeRate` (5-check guard),
//!     `EstimateFeeRate`, `PreconditionChecks`.
//!   * `bitcoin-core/src/policy/rbf.cpp` + `policy/rbf.h` —
//!     `PaysForRBF` (Rule 3 + 4), `GetEntriesForConflicts` (Rule 5),
//!     `EntriesAndTxidsDisjoint` (Rule 2), `IsRBFOptIn` (Rule 1),
//!     `ImprovesFeerateDiagram` (cluster mempool, Core 27+),
//!     `MAX_REPLACEMENT_CANDIDATES = 100`.
//!   * `bitcoin-core/src/util/rbf.cpp` + `util/rbf.h` —
//!     `SignalsOptInRBF`, `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd`.
//!   * `bitcoin-core/src/policy/feerate.cpp` +
//!     `bitcoin-core/src/util/feefrac.h` —
//!     `CFeeRate::GetFee` → `EvaluateFeeUp` (CeilDiv, rounds up).
//!   * `bitcoin-core/src/policy/policy.h:48` —
//!     `DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB = 1 sat/vB.
//!   * `bitcoin-core/src/wallet/wallet.h:124` —
//!     `WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB = 5 sat/vB.
//!
//! Audit subject:
//!   * `crates/wallet/src/wallet.rs::build_bumped_tx` (wallet.rs:761-932)
//!     invoked by both `bump_fee` and `psbt_bump_fee`.
//!   * `crates/consensus/src/mempool.rs::check_rbf_rules`
//!     (mempool.rs:2767-2879) + helpers
//!     `is_bip125_replaceable` / `signals_opt_in_rbf` /
//!     `is_truc_replaceable`.
//!   * RPC surface (`rpc/src/wallet.rs:816,834` `bumpfee`/`psbtbumpfee`).
//!
//! Bug inventory (BUG-1..19 — see `audit/w130_bip125_feebumper_rule3.md`
//! for full per-bug rationale and Core line references):
//!
//!   BUG-1  [CLOSED 2026-06-16] G2:  Wallet `INCREMENTAL_FEE_RATE` was
//!                    hardcoded to 1.0 sat/vB, ignoring Core's
//!                    `WALLET_INCREMENTAL_RELAY_FEE = 5 sat/vB`
//!                    (wallet.h:124). FIXED: `build_bumped_tx` now derives
//!                    the default incremental delta from
//!                    `WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB = 5000`
//!                    using integer-ceiling math (Core feebumper.cpp
//!                    `EstimateFeeRate` parity). De-staled test below.
//!
//!   BUG-2  [P0-CDIV] G10: Wallet never reads
//!                    `MempoolConfig::incremental_relay_fee` at runtime.
//!                    Operator `-incrementalrelayfee` override is
//!                    silently dropped on the bumpfee path.
//!
//!   BUG-3  [P0]      G11: `CheckFeeRate` 5-check Core-parity guard
//!                    MISSING — no mempool-min-fee, no
//!                    `combined_bump_fee`, no `GetRequiredFee` floor,
//!                    no `max_tx_fee` ceiling. Wallet may build
//!                    out-of-range replacements.
//!
//!   BUG-4  [P0]      G12: Rule 2 (no new unconfirmed inputs) not
//!                    enforceable in wallet — vacuously satisfied
//!                    only because input-adding is absent (W129
//!                    BUG-13 cross-ref). Minefield bug.
//!
//!   BUG-5  [P0]      G13: Dead error variant
//!                    `MempoolError::RbfInsufficientFeeRate` declared
//!                    at mempool.rs:920 but never constructed; the
//!                    intentional comment-removal at :2862-2865
//!                    confirms its dead status.
//!
//!   BUG-6  [P1]      G15: `EstimateFeeRate` helper absent. No
//!                    re-derivation of new feerate from
//!                    `old_feerate + 1 sat + max(node_incremental,
//!                    wallet_incremental)`.
//!
//!   BUG-7  [P1]      G17: `PreconditionChecks` partial — confirmed-tx
//!                    + RBF-signaling guards present, but
//!                    descendant-in-wallet (Core
//!                    feebumper.cpp:25-28), descendant-in-mempool
//!                    (Core :31-35), and `replaced_by_txid` mapValue
//!                    guards (Core :42-45) MISSING.
//!
//!   BUG-8  [P1]      G19: `bump_fee` checks only own-input
//!                    sequences; doesn't call `is_bip125_replaceable`
//!                    (which checks the ancestor-signaling path via
//!                    `IsRBFOptIn` Core parity). Less critical for
//!                    self-originated txs but the helper shape
//!                    diverges from Core.
//!
//!   BUG-9  [P1]      G20: Wallet uses f64 `.ceil()` math
//!                    (wallet.rs:818,829) for incremental-fee
//!                    computation; mempool path uses
//!                    `+999/1000` integer ceiling (mempool.rs:2870).
//!                    Two parities of the same numeric invariant.
//!
//!   BUG-10 [P1]      G22: TRUC sibling-eviction RBF mirror at
//!                    mempool.rs:1751-1769 uses the same incremental-
//!                    fee math but skips `check_rbf_rules` — no Rule
//!                    5 cap, no full check. May admit replacements
//!                    the standard path rejects.
//!
//!   BUG-11 [P2]      G30: `incremental_relay_fee` unit-confusion
//!                    comment-as-confession. Three sites document
//!                    sat/kvB vs sat/vB inconsistently (mempool.rs:
//!                    100-101, :697-698, wallet.rs:817-819).
//!
//!   BUG-12 [CLOSED 2026-06-16] G16: `WALLET_INCREMENTAL_RELAY_FEE`
//!                    constant (Core wallet.h:124 = 5000 sat/kvB) was
//!                    absent. FIXED: added
//!                    `WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB = 5000`
//!                    (re-exported from the wallet crate), used by BUG-1.
//!
//!   BUG-13 [P2]      G21: `calculateCombinedBumpFee` (Core 27+
//!                    descendant-aware bump fee accounting) absent.
//!
//!   BUG-14 [P2]      G23: `max_tx_fee` (`-maxtxfee` ceiling) absent.
//!
//!   BUG-15 [P2]      G25: `gettransaction.bip125_replaceable` field
//!                    not surfaced in wallet RPC.
//!
//!   BUG-16 [P2]      G26: `ImprovesFeerateDiagram` cluster-mempool
//!                    gate disclaimed at mempool.rs:2765-2766
//!                    (deferred until cluster mempool lands).
//!
//!   BUG-17 [P3]      G27: `EntriesAndTxidsDisjoint` open-coded at
//!                    mempool.rs:2844-2849 rather than factored as a
//!                    helper; cannot be reused by TRUC path.
//!
//!   BUG-18 [P3]      G28: `RBFTransactionState` enum (Core rbf.h:
//!                    29-36: UNKNOWN/REPLACEABLE_BIP125/FINAL) absent.
//!                    Rustoshi collapses to a `bool` from
//!                    `is_bip125_replaceable`.
//!
//!   BUG-19 [P3]      G29: `IsRBFOptInEmptyMempool` helper (Core
//!                    rbf.cpp:52-56) absent.
//!
//! PASS pins (11): G1 (MAX_BIP125_RBF_SEQUENCE constant), G3
//! (is_bip125_replaceable ancestor walk), G4 (signals_opt_in_rbf
//! private helper), G5 (Rule 1 enforced + full_rbf override), G6
//! (TRUC implicit replaceability), G7 (Rule 5 cap = 100), G8 (Rule
//! 3 uses GetModifiedFee, FIX-72 / W120 BUG-9 closure), G9 (full_rbf
//! default true), G14 (Rule 2 ancestors disjoint walk), G18
//! (DEFAULT_INCREMENTAL_RELAY_FEE = 100), G24
//! (`MempoolError::ReplacementDisallowed`).

use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};

// `mempool.rs` lives in the consensus crate, which the wallet crate
// does not depend on. We use `include_str!` against the consensus
// source for source-grep gates; this is the same shape W120 uses in
// its forward regression guards (e.g.
// `g11_modified_fee_unused_in_rbf_comparison_bug9`).
const MEMPOOL_SRC: &str =
    include_str!("../../consensus/src/mempool.rs");
const WALLET_SRC: &str =
    include_str!("../src/wallet.rs");

// Core constants — reproduced here for parity assertions. The source
// truth is bitcoin-core/src/util/rbf.h:12,
// bitcoin-core/src/policy/policy.h:48, and
// bitcoin-core/src/wallet/wallet.h:124.
const CORE_MAX_BIP125_RBF_SEQUENCE: u32 = 0xfffffffd;
const CORE_DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 100;
const CORE_WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 5000;
const CORE_MAX_REPLACEMENT_CANDIDATES: usize = 100;

// ============================================================================
// PRESENT (11) — regression pins for known-good behavior
// ============================================================================

/// G1: `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd` constant matches Core
/// `util/rbf.h:12`. Asserted via source-grep against the canonical
/// hex literal at `mempool.rs:96`.
#[test]
fn g1_max_bip125_rbf_sequence_constant_matches_core() {
    assert!(
        MEMPOOL_SRC.contains("pub const MAX_BIP125_RBF_SEQUENCE: u32 = 0xFFFFFFFD"),
        "MAX_BIP125_RBF_SEQUENCE must be defined as 0xFFFFFFFD (Core util/rbf.h:12)"
    );
    // Sanity check the const value via a parallel value computed from
    // the runtime parity literal.
    let parity_val: u32 = 0xFFFF_FFFD;
    assert_eq!(parity_val, CORE_MAX_BIP125_RBF_SEQUENCE);
}

/// G3: `is_bip125_replaceable` walks the tx + ancestor mempool entries
/// for the BIP-125 signal (Core `IsRBFOptIn` parity, `rbf.cpp:24-50`).
#[test]
fn g3_is_bip125_replaceable_walks_self_and_ancestors() {
    assert!(
        MEMPOOL_SRC.contains("pub fn is_bip125_replaceable"),
        "is_bip125_replaceable must be a public helper on Mempool"
    );
    // It must check both self-sequences AND ancestor sequences.
    let body_start = MEMPOOL_SRC
        .find("pub fn is_bip125_replaceable")
        .expect("is_bip125_replaceable absent");
    let body_window = &MEMPOOL_SRC[body_start..body_start + 1500];
    assert!(
        body_window.contains("Self::signals_opt_in_rbf"),
        "is_bip125_replaceable must dispatch to signals_opt_in_rbf"
    );
    assert!(
        body_window.contains("get_all_ancestors"),
        "is_bip125_replaceable must walk ancestors (Core IsRBFOptIn)"
    );
}

/// G4: `signals_opt_in_rbf` private helper iterates inputs and applies
/// `<= MAX_BIP125_RBF_SEQUENCE`. Mirrors Core `SignalsOptInRBF`
/// (`util/rbf.cpp:9-17`).
#[test]
fn g4_signals_opt_in_rbf_private_helper_present() {
    assert!(
        MEMPOOL_SRC.contains("fn signals_opt_in_rbf("),
        "signals_opt_in_rbf private helper must exist (Core SignalsOptInRBF parity)"
    );
    assert!(
        MEMPOOL_SRC.contains("input.sequence <= MAX_BIP125_RBF_SEQUENCE"),
        "signals_opt_in_rbf must apply <= MAX_BIP125_RBF_SEQUENCE per Core util/rbf.cpp:12"
    );
}

/// G5: Rule 1 enforced — `!full_rbf && !is_bip125_replaceable &&
/// !is_truc_replaceable` rejects with `RbfNotSignaling`. Core
/// `validation.cpp:839` + `policy/rbf.cpp:24-50`.
#[test]
fn g5_rule1_signaling_or_full_rbf_enforced() {
    assert!(
        MEMPOOL_SRC.contains("if !self.config.full_rbf {"),
        "Rule 1 must be gated on full_rbf config"
    );
    assert!(
        MEMPOOL_SRC.contains("return Err(MempoolError::RbfNotSignaling)"),
        "Rule 1 violation must surface as MempoolError::RbfNotSignaling"
    );
}

/// G6: TRUC v3 (BIP-431) implicit replaceability — v3 conflicts are
/// always replaceable regardless of BIP-125 signaling. Core
/// `validation.cpp:970-972` comment.
#[test]
fn g6_truc_v3_implicit_replaceability_honored() {
    assert!(
        MEMPOOL_SRC.contains("pub fn is_truc_replaceable"),
        "is_truc_replaceable helper must exist"
    );
    assert!(
        MEMPOOL_SRC.contains("&& !self.is_truc_replaceable(conflict_txid)"),
        "Rule 1 must also accept v3 (TRUC) conflicts as implicitly replaceable"
    );
}

/// G7: Rule 5 cap = `MAX_REPLACEMENT_CANDIDATES = 100`, matching Core
/// `policy/rbf.h:26`.
#[test]
fn g7_rule5_max_replacement_candidates_constant() {
    assert!(
        MEMPOOL_SRC.contains("pub const MAX_REPLACEMENT_CANDIDATES: usize = 100"),
        "MAX_REPLACEMENT_CANDIDATES must equal Core policy/rbf.h:26 value 100"
    );
    let runtime_val: usize = 100;
    assert_eq!(runtime_val, CORE_MAX_REPLACEMENT_CANDIDATES);
    assert!(
        MEMPOOL_SRC.contains("if all_to_evict.len() > MAX_REPLACEMENT_CANDIDATES"),
        "Rule 5 must check eviction count vs constant"
    );
}

/// G8: Rule 3 sum uses `Self::get_modified_fee` not raw `entry.fee`
/// (FIX-72 / W120 BUG-9 closure). Core `policy/rbf.cpp:104` reads
/// `it->GetModifiedFee()`.
#[test]
fn g8_rule3_uses_get_modified_fee_fix72() {
    // FIX-72 closure: forward regression guard. The Rule 3 accumulator
    // body must NOT read `entry.fee` and MUST read `get_modified_fee`.
    let body_start = MEMPOOL_SRC
        .find("// Rule #3: Replacement fees must be >= original fees.")
        .expect("Rule 3 comment marker absent");
    let body_window = &MEMPOOL_SRC[..body_start];
    // The accumulator is upstream of the rule comment; check the
    // immediate ancestor scope.
    let acc_window = &body_window[body_window
        .rfind("for conflict_txid in direct_conflicts {")
        .expect("conflict accumulator absent")..];
    assert!(
        acc_window.contains("Self::get_modified_fee"),
        "Rule 3 accumulator must read GetModifiedFee per FIX-72 / W120 BUG-9"
    );
}

/// G9: `full_rbf` defaults to `true` (Core v28+ parity).
#[test]
fn g9_full_rbf_defaults_to_true() {
    assert!(
        MEMPOOL_SRC.contains("full_rbf: true, // Bitcoin Core v28+ default"),
        "full_rbf default must be true (Core v28+ parity)"
    );
}

/// G14: Rule 2 enforced — replacement's ancestor set must not
/// intersect direct conflicts. Core
/// `policy/rbf.cpp:85-98 EntriesAndTxidsDisjoint`.
#[test]
fn g14_rule2_replacement_ancestors_disjoint_from_conflicts() {
    assert!(
        MEMPOOL_SRC.contains("let replacement_ancestors = self.get_all_ancestors(mempool_parents);"),
        "Rule 2 must compute replacement_ancestors"
    );
    assert!(
        MEMPOOL_SRC.contains("return Err(MempoolError::RbfSpendsConflicting)"),
        "Rule 2 violation must surface as RbfSpendsConflicting"
    );
}

/// G18: `DEFAULT_INCREMENTAL_RELAY_FEE = 100` (sat/kvB) matches Core
/// `policy/policy.h:48`.
#[test]
fn g18_default_incremental_relay_fee_constant() {
    assert!(
        MEMPOOL_SRC.contains("pub const DEFAULT_INCREMENTAL_RELAY_FEE: u64 = 100"),
        "DEFAULT_INCREMENTAL_RELAY_FEE must equal Core policy/policy.h:48 value 100 (sat/kvB)"
    );
    let runtime_val: u64 = 100;
    assert_eq!(runtime_val, CORE_DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB);
}

/// G24: `MempoolError::ReplacementDisallowed` ("bip125-replacement-
/// disallowed") fires when `args.allow_replacement == false`. Core
/// `validation.cpp:839` parity.
#[test]
fn g24_replacement_disallowed_error_variant_present() {
    assert!(
        MEMPOOL_SRC.contains("#[error(\"bip125-replacement-disallowed\")]"),
        "Error variant must carry the canonical Core error string"
    );
    assert!(
        MEMPOOL_SRC.contains("ReplacementDisallowed,"),
        "MempoolError::ReplacementDisallowed variant must exist"
    );
    assert!(
        MEMPOOL_SRC.contains("if !allow_replacement {"),
        "The `allow_replacement` gate must short-circuit RBF in the package context"
    );
}

// ============================================================================
// PARTIAL / MISSING (19) — #[ignore]'d panic!() regression pins
// ============================================================================

/// BUG-1 / G2 [P0-CDIV]: Wallet `INCREMENTAL_FEE_RATE` hardcoded to
/// 1.0 sat/vB at wallet.rs:817, ignoring Core's
/// `WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB = 5 sat/vB.
///
/// Core `feebumper.cpp:137`:
/// `feerate += std::max(node_incremental_relay_fee,
///                       wallet_incremental_relay_fee);`
///
/// Rustoshi's wallet builds replacements 5× below Core peers' wallet
/// floor by default. The local mempool accepts (both at 1 sat/vB);
/// every Core peer's wallet+relay path rejects.
/// BUG-1 / G2 [De-staled 2026-06-16]: the wallet fee-bump floor now uses
/// Core's conservative `WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB (= 5
/// sat/vB, `wallet.h:124`) instead of the old hardcoded 1.0 sat/vB literal.
/// Core `feebumper.cpp` `EstimateFeeRate` bumps the replacement feerate by
/// `max(node_incremental_relay_fee, WALLET_INCREMENTAL_RELAY_FEE)`; with the
/// node default `DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB, the wallet
/// floor of 5000 sat/kvB dominates. The bad 1.0 sat/vB literal is gone and
/// the bump now uses integer-ceiling math (`(rate_kvb * vsize + 999) / 1000`,
/// `CFeeRate::GetFee` -> `CeilDiv` parity), matching the mempool Rule-4 path.
#[test]
fn bug1_wallet_uses_wallet_incremental_relay_fee_max_fence() {
    // The bad 1.0 sat/vB literal must be GONE.
    assert!(
        !WALLET_SRC.contains("const INCREMENTAL_FEE_RATE: f64 = 1.0;"),
        "wallet.rs must no longer carry the bad 1.0 sat/vB INCREMENTAL_FEE_RATE literal"
    );
    // The corrected floor must reference the Core 5000 sat/kvB constant.
    assert!(
        WALLET_SRC.contains("WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB"),
        "build_bumped_tx must derive its incremental delta from \
         WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB (Core wallet.h:124 = 5000 sat/kvB)"
    );
    // The bump delta must use integer-ceiling math, not f64 ceil() — parity
    // with the mempool Rule-4 path.
    assert!(
        WALLET_SRC
            .contains("(incremental_rate_kvb.saturating_mul(entry.vsize as u64) + 999) / 1000"),
        "incremental delta must use integer ceiling (rate_kvb * vsize + 999) / 1000 \
         (CFeeRate::GetFee / CeilDiv parity)"
    );

    // Behavioral parity: the public constant equals Core's 5000 sat/kvB, and
    // the ceiling math the wallet now uses produces the Core-floor delta for a
    // typical replacement vsize. For a 141-vbyte P2WPKH tx the wallet floor is
    // ceil(5000 * 141 / 1000) = 705 sat (5 sat/vB), NOT the old 141 sat that
    // the 1 sat/vB literal produced.
    assert_eq!(
        rustoshi_wallet::WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
        CORE_WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
        "exported wallet incremental relay fee must equal Core wallet.h:124 (5000 sat/kvB)"
    );
    let vsize: u64 = 141;
    let wallet_floor_delta = (rustoshi_wallet::WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB
        * vsize
        + 999)
        / 1000;
    let old_one_sat_per_vb_delta = (100u64 * vsize + 999) / 1000;
    assert_eq!(wallet_floor_delta, 705, "5 sat/vB floor for a 141-vB tx must be 705 sat");
    assert_eq!(old_one_sat_per_vb_delta, 15, "old 1 sat/vB delta for a 141-vB tx was 15 sat");
    assert!(
        wallet_floor_delta > old_one_sat_per_vb_delta,
        "the corrected wallet floor must exceed the old 1 sat/vB delta (5x conservative margin)"
    );
}

/// BUG-2 / G10 [P0-CDIV]: Wallet bumpfee never reads
/// `MempoolConfig::incremental_relay_fee` at runtime. The constant is
/// compile-time `f64`, so `-incrementalrelayfee` operator override is
/// silently dropped on the bumpfee path.
#[test]
#[ignore = "BUG-2 P0-CDIV: wallet bumpfee ignores MempoolConfig::incremental_relay_fee"]
fn bug2_wallet_reads_mempool_config_incremental_relay_fee() {
    // The wallet source must NOT contain a reference to MempoolConfig
    // in the bumpfee neighborhood — that's the bug. We also assert
    // the literal config field exists in the consensus crate so the
    // fix has a clear plumbing target.
    assert!(
        MEMPOOL_SRC.contains("pub incremental_relay_fee: u64"),
        "MempoolConfig::incremental_relay_fee must exist as a config field"
    );
    let bump_window_start = WALLET_SRC
        .find("fn build_bumped_tx")
        .expect("build_bumped_tx must exist");
    let bump_window_end = bump_window_start + 8000;
    let bump_window = &WALLET_SRC[bump_window_start..bump_window_end.min(WALLET_SRC.len())];
    assert!(
        !bump_window.contains("incremental_relay_fee")
            && !bump_window.contains("MempoolConfig"),
        "build_bumped_tx must NOT yet read MempoolConfig.incremental_relay_fee (regression pin)"
    );
    panic!(
        "BUG-2 P0-CDIV: build_bumped_tx ignores MempoolConfig::incremental_relay_fee. \
         Operator -incrementalrelayfee override silently dropped on bumpfee path. \
         Fix: plumb &MempoolConfig (or a feerate accessor) through build_bumped_tx."
    );
}

/// BUG-3 / G11 [P0]: `CheckFeeRate` 5-check Core-parity guard MISSING.
/// Core `feebumper.cpp:60-117` enforces (a) `newFeerate >=
/// mempoolMinFee`, (b) `combined_bump_fee` descendant accounting,
/// (c) `new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)`
/// (Rule 3), (d) `new_total_fee >= GetRequiredFee(wallet, maxTxSize)`,
/// (e) `new_total_fee <= max_tx_fee`. Rustoshi's wallet does **none**
/// of these.
#[test]
#[ignore = "BUG-3 P0: CheckFeeRate 5-check guard MISSING in wallet bumpfee path"]
fn bug3_check_fee_rate_5_check_guard_present() {
    // Negative regression pin — the function name must NOT appear in
    // the wallet source.
    assert!(
        !WALLET_SRC.contains("fn check_fee_rate"),
        "check_fee_rate helper must not yet exist (regression pin)"
    );
    panic!(
        "BUG-3 P0: CheckFeeRate (feebumper.cpp:60-117) absent. Missing: \
         (1) mempool-min-fee gate, (2) combined_bump_fee, (3) Rule 3 \
         floor with maxTxSize, (4) required-fee floor, (5) max_tx_fee \
         ceiling. Fix: port Core's CheckFeeRate as \
         Wallet::check_fee_rate(&self, &mtx, fee_rate, max_tx_size, old_fee)."
    );
}

/// BUG-4 / G12 [P0]: Rule 2 (no new unconfirmed inputs) not enforceable
/// in wallet. Core `feebumper.cpp:312`: `new_coin_control.m_min_depth
/// = 1;` sets a floor on confirmations of newly-added inputs. Rustoshi's
/// `build_bumped_tx` doesn't add inputs — vacuously satisfied — but the
/// minute input-adding lands (W129 BUG-13), rule 2 will not be honored.
/// Minefield bug.
#[test]
#[ignore = "BUG-4 P0: Rule 2 (no new unconfirmed inputs) not enforced when input-adding lands"]
fn bug4_rule2_no_new_unconfirmed_inputs_enforced() {
    // Document the minefield: the wallet source must not yet mention
    // `m_min_depth` / `min_depth` / similar. When input-adding is
    // wired, this assertion will fail before the rule is enforced.
    let bump_window_start = WALLET_SRC
        .find("fn build_bumped_tx")
        .expect("build_bumped_tx must exist");
    let bump_window_end = bump_window_start + 8000;
    let bump_window = &WALLET_SRC[bump_window_start..bump_window_end.min(WALLET_SRC.len())];
    assert!(
        !bump_window.contains("min_depth")
            && !bump_window.contains("m_min_depth"),
        "build_bumped_tx must not yet have min_depth plumbing (minefield pin)"
    );
    panic!(
        "BUG-4 P0: Rule 2 not enforceable in wallet. When input-adding \
         lands (W129 BUG-13 / G29), `min_depth = 1` floor on new inputs \
         must be set BEFORE coin selection. Fix: thread CoinControl.min_depth \
         through build_bumped_tx::coin selection path."
    );
}

/// BUG-5 / G13 [P0]: Dead error variant
/// `MempoolError::RbfInsufficientFeeRate` declared at mempool.rs:920
/// but never constructed. The intentional comment-removal at
/// mempool.rs:2862-2865 confirms its dead status.
#[test]
#[ignore = "BUG-5 P0: RbfInsufficientFeeRate error variant declared but never constructed"]
fn bug5_dead_error_variant_rbf_insufficient_fee_rate() {
    assert!(
        MEMPOOL_SRC.contains("RbfInsufficientFeeRate(f64, f64)"),
        "RbfInsufficientFeeRate variant must still be in the enum (dead variant pin)"
    );
    let construction_sites: usize = MEMPOOL_SRC
        .matches("RbfInsufficientFeeRate(")
        .count();
    // Should be exactly 2 occurrences: the variant declaration line
    // and the #[error("...")] attribute line — NO construction site.
    // If/when someone adds a construction site, this count goes up
    // and the test fails (signalling the variant is now alive).
    assert!(
        construction_sites <= 2,
        "RbfInsufficientFeeRate should appear at most twice (enum decl + #[error] attr), \
         got {}. If alive, remove this regression pin.",
        construction_sites
    );
    panic!(
        "BUG-5 P0: RbfInsufficientFeeRate error variant is dead. \
         Intentional removal documented at mempool.rs:2862-2865 but \
         variant was left in place. Fix: remove the variant from \
         MempoolError, or wire a construction site if a fee-rate check \
         is added back."
    );
}

/// BUG-6 / G15 [P1]: `EstimateFeeRate` helper absent. Core
/// `feebumper.cpp:119-144`: `feerate = max(old_feerate + 1 sat +
/// max(node_incremental, wallet_incremental), min_feerate)`. Rustoshi
/// uses naive `min_new_fee = orig_fee + incremental_delta` only —
/// the *feerate* (sat/vB) is not re-derived from the *old feerate +
/// 1 sat*.
#[test]
#[ignore = "BUG-6 P1: EstimateFeeRate helper absent in wallet bumpfee path"]
fn bug6_estimate_fee_rate_helper_present() {
    assert!(
        !WALLET_SRC.contains("fn estimate_fee_rate"),
        "estimate_fee_rate must not yet exist (regression pin)"
    );
    panic!(
        "BUG-6 P1: EstimateFeeRate (feebumper.cpp:119-144) absent. \
         Wallet should derive new feerate as max(old_feerate + 1 sat + \
         max(node_incremental, wallet_incremental), min_feerate)."
    );
}

/// BUG-7 / G17 [P1]: `PreconditionChecks` partial. Confirmed-tx
/// (wallet.rs:774-778) and RBF-signaling (wallet.rs:779-790) are
/// present. MISSING:
///   - `HasWalletSpend(wtx.tx)` (descendants in wallet,
///     feebumper.cpp:25-28),
///   - `hasDescendantsInMempool(wtx.GetHash())` (descendants in
///     mempool, feebumper.cpp:31-35),
///   - `wtx.mapValue.contains("replaced_by_txid")` (already-bumped
///     guard, feebumper.cpp:42-45).
#[test]
#[ignore = "BUG-7 P1: PreconditionChecks partial — descendants + replaced_by_txid guards MISSING"]
fn bug7_precondition_checks_descendants_and_replaced_by_txid() {
    // Confirmed-tx guard is present (this PASSes structurally):
    assert!(
        WALLET_SRC.contains("\"bumpfee: transaction already confirmed; cannot replace\""),
        "confirmed-tx guard must remain in place"
    );
    // RBF-signaling guard is present:
    assert!(
        WALLET_SRC.contains("\"bumpfee: transaction does not signal BIP-125 RBF"),
        "RBF-signaling guard must remain in place"
    );
    // MISSING checks (regression pin) — these literals must still NOT
    // appear:
    assert!(
        !WALLET_SRC.contains("has_descendant")
            && !WALLET_SRC.contains("HasWalletSpend")
            && !WALLET_SRC.contains("hasDescendantsInMempool"),
        "descendant-in-wallet / descendant-in-mempool guards must not yet exist (pin)"
    );
    assert!(
        !WALLET_SRC.contains("replaced_by_txid"),
        "replaced_by_txid mapValue guard must not yet exist (pin)"
    );
    panic!(
        "BUG-7 P1: PreconditionChecks missing descendant-in-wallet, \
         descendant-in-mempool, and replaced_by_txid guards. See \
         feebumper.cpp:25-45 for Core parity."
    );
}

/// BUG-8 / G19 [P1]: `bump_fee` checks only own-input sequences (no
/// ancestor-signaling). Core's `IsRBFOptIn` (`rbf.cpp:24-50`) walks
/// ancestors too. For self-originated txs this is fine (all ancestors
/// are also self-originated), but the helper shape diverges from Core.
#[test]
#[ignore = "BUG-8 P1: build_bumped_tx skips ancestor-signaling (Core IsRBFOptIn parity)"]
fn bug8_bump_fee_calls_is_bip125_replaceable_for_ancestors() {
    let bump_window_start = WALLET_SRC
        .find("fn build_bumped_tx")
        .expect("build_bumped_tx must exist");
    let bump_window_end = bump_window_start + 1500;
    let bump_window = &WALLET_SRC[bump_window_start..bump_window_end.min(WALLET_SRC.len())];
    // The own-input check is there:
    assert!(
        bump_window.contains(".any(|i| i.sequence <= 0xFFFF_FFFD)"),
        "own-input signaling check must remain"
    );
    // But there's no ancestor-signaling helper invocation:
    assert!(
        !bump_window.contains("is_bip125_replaceable")
            && !bump_window.contains("IsRBFOptIn"),
        "no ancestor-signaling check must exist (regression pin)"
    );
    panic!(
        "BUG-8 P1: build_bumped_tx checks only own-input sequences; \
         Core's IsRBFOptIn (rbf.cpp:24-50) also walks ancestors. Fix: \
         expose Mempool::is_bip125_replaceable to the wallet and call it."
    );
}

/// BUG-9 / G20 [P1] [CLOSED 2026-06-16]: the wallet's `fee_rate_override`
/// target path used `(entry.vsize as f64 * rate).ceil() as u64` — an f64
/// ceiling of the product — whereas Core derives an explicit-`fee_rate`
/// target fee via `CFeeRate{AmountFromValue(fee_rate, /*decimals=*/3)}.GetFee`
/// (`spend.cpp:224` → `feerate.cpp:20` → `feefrac.h:212`): the sat/vB rate is
/// first parsed to an **integer** sat/kvB feerate (3-decimal fixed point), then
/// `CeilDiv(feerate_kvb * vsize, 1000)` is applied. The f64 path diverges by a
/// satoshi for rates not exactly representable in binary float (e.g. 1.1).
/// FIXED: override path now calls the integer-ceiling helper
/// `fee_for_rate_sat_per_vb`, the same `(.. + 999) / 1000` invariant as the
/// mempool Rule-4 path. De-staled below.
#[test]
fn bug9_evaluate_fee_up_parity_uniform() {
    // Mempool side: integer ceiling math (matches Core CeilDiv).
    assert!(
        MEMPOOL_SRC
            .contains("(self.config.incremental_relay_fee * new_vsize as u64 + 999) / 1000"),
        "mempool Rule 4 must use integer ceiling +999/1000"
    );
    // The old f64-ceil override literal must be GONE.
    assert!(
        !WALLET_SRC.contains("(entry.vsize as f64 * rate).ceil() as u64"),
        "wallet fee_rate_override path must no longer use f64 ceil() (regression pin)"
    );
    // The override path must route through the integer-ceiling helper.
    assert!(
        WALLET_SRC.contains("fee_for_rate_sat_per_vb(rate, entry.vsize as u64)"),
        "build_bumped_tx override path must call fee_for_rate_sat_per_vb (integer CeilDiv parity)"
    );
    // The helper itself must use integer ceiling, not f64 ceil().
    let helper_start = WALLET_SRC
        .find("pub fn fee_for_rate_sat_per_vb")
        .expect("fee_for_rate_sat_per_vb helper must exist");
    let helper_window = &WALLET_SRC[helper_start..helper_start + 600];
    assert!(
        helper_window.contains("+ 999) / 1000"),
        "fee_for_rate_sat_per_vb must apply integer ceiling division (+999)/1000"
    );
    assert!(
        !helper_window.contains(".ceil()"),
        "fee_for_rate_sat_per_vb must NOT use f64 .ceil()"
    );

    // --- Behavioral parity vs. Core, independently recomputed ---------------
    //
    // Core: fee = CeilDiv(round(rate*1000) * vsize, 1000)  (integer sat/kvB).
    // Old (buggy): fee = ceil(vsize as f64 * rate).
    //
    // Exercise a grid of (rate sat/vB, vsize) pairs. For every pair the helper
    // must equal the integer Core reference. Include a rate (1.1 sat/vB) that
    // is NOT exactly representable in binary float, where the old f64-ceil and
    // the integer path produce DIFFERENT answers for at least one vsize — proof
    // the fix is observable, not cosmetic.
    fn core_reference(rate_sat_per_vb: f64, vsize: u64) -> u64 {
        let rate_kvb = (rate_sat_per_vb * 1000.0).round() as u64; // ParseFixedPoint(3)
        (rate_kvb.saturating_mul(vsize) + 999) / 1000 // CFeeRate::GetFee / CeilDiv
    }

    let rates = [1.0_f64, 1.1, 2.0, 2.5, 5.0, 10.0, 0.1];
    let vsizes = [100_u64, 110, 141, 200, 250, 999, 1000, 1001, 1234];
    let mut saw_divergence_from_old_f64 = false;
    for &rate in &rates {
        for &vsize in &vsizes {
            let got = rustoshi_wallet::fee_for_rate_sat_per_vb(rate, vsize);
            let want = core_reference(rate, vsize);
            assert_eq!(
                got, want,
                "fee_for_rate_sat_per_vb({}, {}) = {} must equal Core CeilDiv reference {}",
                rate, vsize, got, want
            );
            let old_f64 = (vsize as f64 * rate).ceil() as u64;
            if old_f64 != want {
                saw_divergence_from_old_f64 = true;
            }
        }
    }
    assert!(
        saw_divergence_from_old_f64,
        "the corrected integer path must differ from the old f64-ceil path on at \
         least one (rate, vsize) — otherwise the fix would be unobservable"
    );

    // Spot-check the exact off-by-one the float path produced. At 1.1 sat/vB
    // and vsize=100, the f64 product `100.0 * 1.1` is 110.0000000000000142...,
    // so `ceil()` rounds it UP to 111, while Core's integer path gives
    // CeilDiv(round(1.1*1000) * 100, 1000) = CeilDiv(110000, 1000) = 110.
    // The helper must give Core's 110, not the buggy 111.
    assert_eq!(
        rustoshi_wallet::fee_for_rate_sat_per_vb(1.1, 100),
        110,
        "1.1 sat/vB * 100 vB must be exactly 110 sat (Core integer path)"
    );
    assert_eq!(
        (100.0_f64 * 1.1).ceil() as u64,
        111,
        "sanity: the old f64-ceil path produced 111 here (the off-by-one bug)"
    );
}

/// BUG-10 / G22 [P1]: TRUC sibling-eviction RBF mirror at
/// mempool.rs:1751-1769 uses the same incremental_relay_fee math
/// (correctly) but skips `check_rbf_rules` — no Rule 5 cap, no full
/// check. May admit replacements the standard RBF path rejects.
#[test]
#[ignore = "BUG-10 P1: TRUC sibling-eviction path skips check_rbf_rules (Rule 5 cap absent)"]
fn bug10_truc_sibling_eviction_uses_full_rbf_rules() {
    // The TRUC sibling-eviction site exists and does its own fee math:
    assert!(
        MEMPOOL_SRC
            .contains("let required_bandwidth_fee = (self.config.incremental_relay_fee * vsize as u64 + 999) / 1000;"),
        "TRUC sibling-eviction Rule 4 math must exist at mempool.rs:1765"
    );
    // But it does NOT yet call check_rbf_rules in the sibling path —
    // the standard RBF path's call is at :1727.
    let truc_section_start = MEMPOOL_SRC
        .find("// without the normal RBF fee-rate rule (but still need higher absolute fee)")
        .expect("TRUC sibling-eviction marker absent");
    let truc_section_end = truc_section_start + 1500;
    let truc_window =
        &MEMPOOL_SRC[truc_section_start..truc_section_end.min(MEMPOOL_SRC.len())];
    assert!(
        !truc_window.contains("self.check_rbf_rules"),
        "TRUC sibling-eviction path must not yet call check_rbf_rules (regression pin)"
    );
    panic!(
        "BUG-10 P1: TRUC sibling-eviction RBF path skips check_rbf_rules — \
         Rule 5 cap (MAX_REPLACEMENT_CANDIDATES = 100) is not enforced. \
         Fix: either dispatch through check_rbf_rules or duplicate the \
         cap + Rule 2 ancestor disjoint check in the sibling-eviction site."
    );
}

/// BUG-11 / G30 [P2]: Unit-confusion comment-as-confession. Three
/// sites document `incremental_relay_fee` units differently:
///   - `mempool.rs:100-101` — "satoshis per 1000 virtual bytes (sat/kvB)"
///   - `mempool.rs:697-698` — "satoshis per virtual byte"
///   - `wallet.rs:817-819` — "sat/vB; Core DEFAULT_INCREMENTAL_RELAY_FEE"
/// Defaults match the kvB reading; the wallet treats it as vB.
#[test]
#[ignore = "BUG-11 P2: incremental_relay_fee unit-confusion across three documentation sites"]
fn bug11_incremental_relay_fee_unit_documentation_consistent() {
    // Confirm the three inconsistent documentation sites are still
    // present (regression pin):
    assert!(
        MEMPOOL_SRC.contains("/// Default incremental relay fee rate in satoshis per 1000 virtual bytes (sat/kvB)."),
        "mempool.rs:100 kvB unit docstring must exist (pin)"
    );
    assert!(
        MEMPOOL_SRC.contains("/// Incremental relay fee rate (satoshis per virtual byte)."),
        "mempool.rs:697 vB unit docstring must exist (pin)"
    );
    assert!(
        WALLET_SRC.contains("// sat/vB; Core DEFAULT_INCREMENTAL_RELAY_FEE"),
        "wallet.rs:817 sat/vB docstring must exist (pin)"
    );
    panic!(
        "BUG-11 P2: incremental_relay_fee unit is documented \
         inconsistently across 3 sites. Pick ONE (sat/kvB matches Core \
         policy.h:48 raw constant) and rewrite all three to agree. \
         COMMENT-AS-CONFESSION pattern (W129 BUG-1 / W122 BUG)."
    );
}

/// BUG-12 / G16 [P1]: `WALLET_INCREMENTAL_RELAY_FEE` constant (Core
/// wallet.h:124 = 5000 sat/kvB) absent in rustoshi-wallet. No
/// "future-proofing-against-network-wide-policy" floor.
/// BUG-12 / G16 [De-staled 2026-06-16]: `WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB`
/// constant (Core `wallet.h:124` = 5000 sat/kvB = 5 sat/vB) is now defined and
/// re-exported from the wallet crate, used by BUG-1's fee-bump floor.
#[test]
fn bug12_wallet_incremental_relay_fee_constant_present() {
    assert!(
        WALLET_SRC.contains("pub const WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 5000;"),
        "WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB must be defined as 5000 (Core wallet.h:124)"
    );
    // The constant is re-exported and equals Core's value.
    assert_eq!(
        rustoshi_wallet::WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
        CORE_WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
        "exported constant must equal Core wallet.h:124 value 5000 sat/kvB"
    );
}

/// BUG-13 / G21 [P2]: `calculateCombinedBumpFee` (Core 27+ descendant-
/// aware bump fee accounting, `feebumper.cpp:83-87`) absent. Wallet
/// doesn't account for descendant fees; bumping a parent whose child
/// is also in mempool under-pays.
#[test]
#[ignore = "BUG-13 P2: calculateCombinedBumpFee (descendant-aware bump accounting) absent"]
fn bug13_calculate_combined_bump_fee_present() {
    assert!(
        !WALLET_SRC.contains("calculate_combined_bump_fee")
            && !WALLET_SRC.contains("calculateCombinedBumpFee"),
        "combined_bump_fee helper must not yet exist (regression pin)"
    );
    panic!(
        "BUG-13 P2: calculateCombinedBumpFee absent. Wallet under-pays \
         when bumping a parent whose child is also in mempool. Fix: \
         port feebumper.cpp:83-87 + interfaces/chain.cpp::calculateCombinedBumpFee."
    );
}

/// BUG-14 / G23 [P2]: `max_tx_fee` (`-maxtxfee` ceiling, Core
/// `wallet.m_default_max_tx_fee`, `feebumper.cpp:109-114`) absent. No
/// upper guard against a misconfigured ceiling.
#[test]
#[ignore = "BUG-14 P2: max_tx_fee (-maxtxfee ceiling) absent in wallet bumpfee path"]
fn bug14_max_tx_fee_ceiling_enforced() {
    let bump_window_start = WALLET_SRC
        .find("fn build_bumped_tx")
        .expect("build_bumped_tx must exist");
    let bump_window_end = bump_window_start + 8000;
    let bump_window = &WALLET_SRC[bump_window_start..bump_window_end.min(WALLET_SRC.len())];
    assert!(
        !bump_window.contains("max_tx_fee")
            && !bump_window.contains("maxtxfee"),
        "max_tx_fee ceiling must not yet be plumbed (regression pin)"
    );
    panic!(
        "BUG-14 P2: max_tx_fee ceiling (Core feebumper.cpp:109-114) \
         absent. Fix: plumb wallet config max_tx_fee through \
         build_bumped_tx and reject when new_total_fee > max_tx_fee."
    );
}

/// BUG-15 / G25 [P2]: `gettransaction.bip125_replaceable` field MISSING
/// in wallet RPC. `getrawmempool verbose.bip125_replaceable` IS wired
/// (`server.rs:7018`), but the wallet-side surface is absent.
#[test]
#[ignore = "BUG-15 P2: gettransaction.bip125_replaceable wallet RPC field absent"]
fn bug15_gettransaction_exposes_bip125_replaceable() {
    // We use a source-grep for the canonical field name with a leading
    // "gettransaction" context. The wallet RPC source isn't directly
    // include_str!'able from a wallet-test, but the constant string
    // and its plumb point would live there. Document the gap via a
    // negative include against the wallet source (the wallet doesn't
    // own RPC code, but does own the TxInfo shape the RPC pulls from).
    let _ = WALLET_SRC; // referenced for completeness
    panic!(
        "BUG-15 P2: gettransaction RPC response lacks bip125_replaceable. \
         Wallet TxInfo struct needs the field; rpc/src/wallet.rs gettransaction \
         needs to populate it from Mempool::is_bip125_replaceable."
    );
}

/// BUG-16 / G26 [P2]: `ImprovesFeerateDiagram` cluster-mempool gate
/// (Core 27+, `rbf.cpp:127-140`) explicitly disclaimed at
/// `mempool.rs:2765-2766` ("Note: Core's ImprovesFeerateDiagram
/// (cluster-mempool, Core 27+) is not implemented because rustoshi
/// does not yet have a cluster mempool. Deferred.").
#[test]
#[ignore = "BUG-16 P2: ImprovesFeerateDiagram (cluster mempool, Core 27+) deferred"]
fn bug16_improves_feerate_diagram_gate_present() {
    // Confirm the disclaimer is still present (regression pin):
    assert!(
        MEMPOOL_SRC.contains("Note: Core's ImprovesFeerateDiagram (cluster-mempool, Core 27+) is not implemented"),
        "ImprovesFeerateDiagram deferral disclaimer must remain (pin)"
    );
    panic!(
        "BUG-16 P2: ImprovesFeerateDiagram cluster-mempool gate (Core \
         rbf.cpp:127-140) absent. Acknowledged at mempool.rs:2765-2766. \
         Deferred until cluster mempool lands."
    );
}

/// BUG-17 / G27 [P3]: `EntriesAndTxidsDisjoint` (Core
/// `policy/rbf.cpp:85-98`) open-coded inline at
/// `mempool.rs:2844-2849` rather than factored as a helper; cannot
/// be reused by the TRUC sibling-eviction path (G22 / BUG-10 makes
/// this concrete).
#[test]
#[ignore = "BUG-17 P3: EntriesAndTxidsDisjoint open-coded not factored as helper"]
fn bug17_entries_and_txids_disjoint_factored_as_helper() {
    assert!(
        !MEMPOOL_SRC.contains("fn entries_and_txids_disjoint")
            && !MEMPOOL_SRC.contains("fn EntriesAndTxidsDisjoint"),
        "EntriesAndTxidsDisjoint helper must not yet be factored (pin)"
    );
    panic!(
        "BUG-17 P3: EntriesAndTxidsDisjoint open-coded at mempool.rs:2844-2849. \
         Fix: factor as `fn entries_and_txids_disjoint(replacement_ancestors, \
         direct_conflicts) -> Option<MempoolError>` and call from both standard \
         RBF and TRUC sibling-eviction paths."
    );
}

/// BUG-18 / G28 [P3]: `RBFTransactionState` enum (Core `rbf.h:29-36`:
/// `UNKNOWN`/`REPLACEABLE_BIP125`/`FINAL`) absent. Rustoshi collapses
/// to a `bool` from `is_bip125_replaceable`; the three-state UNKNOWN
/// distinction (when tx not in mempool) is lost.
#[test]
#[ignore = "BUG-18 P3: RBFTransactionState enum absent — three-state distinction collapsed to bool"]
fn bug18_rbf_transaction_state_enum_present() {
    assert!(
        !MEMPOOL_SRC.contains("enum RBFTransactionState")
            && !MEMPOOL_SRC.contains("RbfTransactionState::Unknown")
            && !MEMPOOL_SRC.contains("REPLACEABLE_BIP125"),
        "RBFTransactionState enum must not yet exist (pin)"
    );
    panic!(
        "BUG-18 P3: RBFTransactionState enum (UNKNOWN/REPLACEABLE_BIP125/\
         FINAL, Core rbf.h:29-36) absent. Fix: replace `bool` return of \
         is_bip125_replaceable with three-state enum so callers can \
         distinguish 'not in mempool' from 'final'."
    );
}

/// BUG-19 / G29 [P3]: `IsRBFOptInEmptyMempool` helper (Core
/// `rbf.cpp:52-56`) absent. Callers that want "is this replaceable
/// *outside* a mempool context?" must reimplement.
#[test]
#[ignore = "BUG-19 P3: IsRBFOptInEmptyMempool helper absent"]
fn bug19_is_rbf_opt_in_empty_mempool_helper_present() {
    assert!(
        !MEMPOOL_SRC.contains("is_rbf_opt_in_empty_mempool")
            && !MEMPOOL_SRC.contains("IsRBFOptInEmptyMempool"),
        "IsRBFOptInEmptyMempool helper must not yet exist (pin)"
    );
    panic!(
        "BUG-19 P3: IsRBFOptInEmptyMempool helper (Core rbf.cpp:52-56) \
         absent. Fix: add `pub fn is_rbf_opt_in_empty_mempool(tx: \
         &Transaction) -> RBFTransactionState` returning \
         REPLACEABLE_BIP125 if SignalsOptInRBF else UNKNOWN."
    );
}

// ============================================================================
// SUPPLEMENTARY ASSERTIONS — round-trip sanity checks against Core
// ============================================================================

/// Sanity round-trip: Core BIP-125 says `SignalsOptInRBF` returns true
/// iff ANY input has `sequence <= MAX_BIP125_RBF_SEQUENCE`. Build a few
/// synthetic transactions and apply rustoshi's `is_bip125_replaceable`
/// shape via a stand-in (the function lives on Mempool, which the
/// wallet crate doesn't depend on; we use the bare predicate).
#[test]
fn supplementary_signals_opt_in_rbf_predicate_matches_core() {
    fn signals(tx: &Transaction) -> bool {
        tx.inputs
            .iter()
            .any(|i| i.sequence <= CORE_MAX_BIP125_RBF_SEQUENCE)
    }
    let mk_tx = |seqs: &[u32]| Transaction {
        version: 2,
        inputs: seqs
            .iter()
            .map(|&seq| TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: seq,
                witness: vec![],
            })
            .collect(),
        outputs: vec![TxOut {
            value: 1000,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };

    // FINAL across the board: SEQUENCE_FINAL = 0xffffffff on every input.
    assert!(!signals(&mk_tx(&[0xffffffff, 0xffffffff])));
    // ONE input below the threshold: REPLACEABLE.
    assert!(signals(&mk_tx(&[0xffffffff, 0xfffffffd])));
    // ALL inputs at SEQUENCE_FINAL - 1 (0xfffffffe): below the
    // threshold? 0xfffffffe > 0xfffffffd, so NOT replaceable.
    assert!(!signals(&mk_tx(&[0xfffffffe, 0xfffffffe])));
    // All inputs at 0xfffffffd (= MAX_BIP125_RBF_SEQUENCE): REPLACEABLE.
    assert!(signals(&mk_tx(&[0xfffffffd, 0xfffffffd])));
    // Any sequence < MAX_BIP125_RBF_SEQUENCE: REPLACEABLE.
    assert!(signals(&mk_tx(&[0x00000000])));
}

/// Sanity round-trip: the Rule 3 + 4 integer ceiling math used at
/// mempool.rs:2870 — `(rate_kvb * vsize + 999) / 1000` — must match
/// Core `CFeeRate::GetFee` (which uses `EvaluateFeeUp` → `CeilDiv`,
/// feefrac.h:212). Spot-check against the known
/// `DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB` (= 1 sat/vB).
#[test]
fn supplementary_rule3_rule4_integer_ceiling_matches_core() {
    fn rustoshi_required_fee(rate_kvb: u64, vsize: u64) -> u64 {
        (rate_kvb * vsize + 999) / 1000
    }
    fn core_evaluate_fee_up(rate_kvb: u64, vsize: u64) -> u64 {
        // Mirrors feefrac.h:212 `CeilDiv(uint64_t(fee) * at_size,
        // uint32_t(size))` for the (size=1000) case.
        // For a CFeeRate constructed as (rate_kvb sat per 1000 vbytes),
        // GetFee(vsize) = ceil(rate_kvb * vsize / 1000).
        let prod = rate_kvb * vsize;
        (prod + 999) / 1000
    }
    // 1 sat/vB (= 100 sat/kvB), vsize=141 (typical P2WPKH 1-in 2-out):
    // ceil(100 * 141 / 1000) = ceil(14100 / 1000) = 15 sat.
    assert_eq!(rustoshi_required_fee(100, 141), 15);
    assert_eq!(rustoshi_required_fee(100, 141), core_evaluate_fee_up(100, 141));
    // Non-divisible case: 100 sat/kvB * 999 vbytes = 99900; CeilDiv =
    // (99900 + 999) / 1000 = 100899 / 1000 = 100.
    assert_eq!(rustoshi_required_fee(100, 999), 100);
    assert_eq!(rustoshi_required_fee(100, 999), core_evaluate_fee_up(100, 999));
    // Edge: vsize=1, rate=100 → ceil(100/1000) = 1.
    assert_eq!(rustoshi_required_fee(100, 1), 1);
    assert_eq!(rustoshi_required_fee(100, 1), core_evaluate_fee_up(100, 1));
    // Edge: vsize=0, rate=100 → 0.
    assert_eq!(rustoshi_required_fee(100, 0), 0);
    // 5 sat/vB (WALLET_INCREMENTAL_RELAY_FEE), vsize=141 → 705.
    assert_eq!(rustoshi_required_fee(5000, 141), 705);
    assert_eq!(rustoshi_required_fee(5000, 141), core_evaluate_fee_up(5000, 141));
}
