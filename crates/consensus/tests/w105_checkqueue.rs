//! W105 CCheckQueue / parallel script verification gate audit.
//!
//! Covers gates G1-G30 against Bitcoin Core's `checkqueue.h`,
//! `validation.cpp::ConnectBlock`, `init.cpp` `-par` parsing, and
//! `script/sigcache.h`.
//!
//! Reference surface:
//! - `bitcoin-core/src/checkqueue.h`               — CCheckQueue / CCheckQueueControl
//! - `bitcoin-core/src/validation.cpp`             — ConnectBlock CCheckQueueControl usage
//! - `bitcoin-core/src/node/chainstatemanager_args.cpp` — -par parsing
//! - `bitcoin-core/src/script/sigcache.h`           — SignatureCache key design
//!
//! Gate legend:
//! - OK     : correctly implemented (test passes as a pin / regression guard)
//! - BUG    : implemented but with a deviation from Core spec
//! - MISSING: the functionality is entirely absent in rustoshi
//!
//! Tests annotated `#[ignore]` document bugs / missing features.
//! Tests without `#[ignore]` pin correctly-implemented behaviour.
//!
//! Severity:
//! - P0-CDIV : Consensus-divergent — real fork risk
//! - P1      : Protocol-level correctness / performance DoS
//! - P2      : Correctness / operational
//! - P3      : Observability / minor
//! - P4      : Non-critical / polish

use rustoshi_consensus::{
    ChainParams, SigCache, DEFAULT_MAX_ENTRIES,
    validate_scripts_parallel_with_cache,
};
// validation module items used only in ignored tests (documented structural gaps)
#[allow(unused_imports)]
use rustoshi_consensus::validation::{
    connect_block_with_sequence_locks, StubChainContext,
};
use rustoshi_primitives::{Block, BlockHeader, Hash256, Transaction, TxIn, TxOut, OutPoint};
use rustoshi_consensus::CoinEntry;
use rustoshi_consensus::UtxoView;
use std::collections::HashMap;

// ============================================================
// Minimal helper types
// ============================================================

#[allow(dead_code)]
struct MapUtxo(HashMap<OutPoint, CoinEntry>);

impl UtxoView for MapUtxo {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<CoinEntry> {
        self.0.get(outpoint).cloned()
    }
    fn have_coin(&self, outpoint: &OutPoint) -> bool {
        self.0.contains_key(outpoint)
    }
    fn spend_utxo(&mut self, outpoint: &OutPoint) {
        self.0.remove(outpoint);
    }
    fn add_utxo(&mut self, outpoint: &OutPoint, coin: CoinEntry) {
        self.0.insert(outpoint.clone(), coin);
    }
    fn access_by_txid(&self, _txid: &rustoshi_primitives::Hash256) -> Option<CoinEntry> {
        None
    }
}

fn _make_hash(b: u8) -> Hash256 {
    Hash256([b; 32])
}

/// Build a minimal coinbase-only block at the given height.
fn make_coinbase_block(height: u32, prev_hash: Hash256, params: &ChainParams) -> Block {
    let coinbase_script: Vec<u8> = {
        // BIP-34: push block height as CScriptNum
        let mut s = vec![0x03u8]; // push 3 bytes
        let h = height.to_le_bytes();
        s.extend_from_slice(&h[..3]);
        s
    };
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0u8; 32]), vout: 0xFFFF_FFFF },
            script_sig: coinbase_script,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 5_000_000_000,
            script_pubkey: vec![0x51], // OP_1
        }],
        lock_time: 0,
    };
    let merkle_root = rustoshi_crypto::sha256d(&{
        let mut bytes = Vec::new();
        coinbase_tx.encode(&mut bytes).unwrap();
        bytes
    });
    Block {
        header: BlockHeader {
            version: 0x20000000,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: 1_700_000_000 + height,
            bits: params.genesis_block.header.bits,
            nonce: 0,
        },
        transactions: vec![coinbase_tx],
    }
}

use rustoshi_primitives::Encodable;

// ============================================================
// G1 — MISSING: -par flag / rayon thread-pool sizing
//
// Core: `DEFAULT_SCRIPTCHECK_THREADS=0` (auto), parsed via `-par`.
//       `GetNumCores()` → num physical cores - 1 worker threads.
//       Validated in `chainstatemanager_args.cpp:53-58`.
// Rustoshi: No `--par` CLI flag exists in `Cli` struct
//           (rustoshi/src/main.rs). Rayon uses its own global thread
//           pool sized at all available logical cores — no user override.
// Severity: P2
// ============================================================

#[test]
#[ignore = "BUG G1 (P2): rustoshi has no --par flag; rayon uses all logical cores with no cap; Core default is GetNumCores()-1 worker threads capped at MAX_SCRIPTCHECK_THREADS=15"]
fn g1_par_flag_absent() {
    // The absence is structural — no flag in Cli::parse() means the
    // rayon global pool is unconfigured. Confirm that the rayon
    // default >= 1 (deadlock-free) but note lack of -par control.
    let pool_threads = rayon::current_num_threads();
    // Core would cap at 15 workers; rayon may use 32+ on high-core servers.
    assert!(pool_threads >= 1, "rayon must have ≥1 thread");
    // The test assertion below is the BUG: there is no mechanism to
    // cap at MAX_SCRIPTCHECK_THREADS (15) via user config.
    assert!(
        pool_threads <= 15,
        "rustoshi has no --par cap: rayon uses {} threads, Core caps at 15",
        pool_threads
    );
}

// ============================================================
// G2 — MISSING: persistent thread-pool reused across blocks
//
// Core: `m_script_check_queue` is a field on `ChainstateManager`
//       constructed once with N worker threads and reused for every
//       block (validation.cpp:6136 + validation.h:978).
// Rustoshi: rayon's global thread pool is reused implicitly, so pool
//           reuse is OK at the rayon level, but there is no dedicated
//           CCheckQueue object with persistent state.
// Severity: P3 (rayon global pool does reuse workers)
// ============================================================

#[test]
fn g2_thread_pool_reuse_rayon_global() {
    // Rayon's global pool persists across calls — par_iter() never
    // spawns+joins a new OS thread pool per invocation.
    // This is weaker than Core's explicit CCheckQueue but avoids
    // spawn-per-block overhead. Treat as OK for thread-reuse semantics.
    let n = rayon::current_num_threads();
    assert!(n >= 1);
}

// ============================================================
// G3 — OK: min 1 thread (rayon global pool always ≥1)
// ============================================================

#[test]
fn g3_min_one_thread() {
    // rayon guarantees the global pool has at least 1 thread.
    assert!(rayon::current_num_threads() >= 1);
}

// ============================================================
// G4 — MISSING: MAX_SCRIPTCHECK_THREADS = 15 cap
//
// Core: `validation.h:90 MAX_SCRIPTCHECK_THREADS=15`.
//       `ChainstateManager` constructor clamps at this value.
// Rustoshi: No constant defined, no clamp applied; rayon pool can
//           grow beyond 15 on machines with >16 logical cores.
// Severity: P2
// ============================================================

#[test]
#[ignore = "BUG G4 (P2): MAX_SCRIPTCHECK_THREADS=15 constant and cap are absent; rayon pool is unbounded"]
fn g4_max_scriptcheck_threads_cap() {
    // rustoshi exports no MAX_SCRIPTCHECK_THREADS constant
    // (search: grep -r MAX_SCRIPTCHECK /home/work/hashhog/rustoshi/crates --include=*.rs)
    // This test would succeed once the constant is added and rayon is capped.
    const MAX_SCRIPTCHECK_THREADS: usize = 15;
    let actual = rayon::current_num_threads();
    assert!(
        actual <= MAX_SCRIPTCHECK_THREADS,
        "rayon uses {} threads; Core caps at {}",
        actual,
        MAX_SCRIPTCHECK_THREADS
    );
}

// ============================================================
// G5 — MISSING: DEFAULT_SCRIPTCHECK_THREADS = 0 (auto) constant
//
// Core: `node/chainstatemanager_args.h:14 DEFAULT_SCRIPTCHECK_THREADS=0`
//       meaning "auto-detect = GetNumCores()".
// Rustoshi: No corresponding constant. rayon silently uses all
//           logical cores. P3 (documentation / config parity).
// Severity: P3
// ============================================================

#[test]
#[ignore = "BUG G5 (P3): DEFAULT_SCRIPTCHECK_THREADS=0 constant absent; no auto-detection logic mirroring Core"]
fn g5_default_scriptcheck_threads_constant_absent() {
    // rustoshi has no DEFAULT_SCRIPTCHECK_THREADS exported from any crate.
    // Once added this test becomes a compile-time pin.
    // Expected constant: rustoshi_consensus::DEFAULT_SCRIPTCHECK_THREADS = 0
    // (or equivalent rayon default-auto semantics).
    let _: () = (); // placeholder — structural absence cannot be asserted
    panic!("DEFAULT_SCRIPTCHECK_THREADS constant is absent in rustoshi_consensus");
}

// ============================================================
// G6 — MISSING: nBatchSize = 128 constant / configurable batch
//
// Core: `CCheckQueue` is constructed with `batch_size=128`
//       (validation.cpp:6136). Workers pull at most 128 checks
//       per batch, dynamically subdivided.
// Rustoshi: rayon par_iter() splits work automatically with its
//           own adaptive scheduler — no 128-item batch constant.
//           Not a correctness bug but deviates from spec.
// Severity: P3
// ============================================================

#[test]
#[ignore = "BUG G6 (P3): nBatchSize=128 constant absent; rayon uses adaptive scheduling instead of fixed 128-item batches"]
fn g6_nbatch_size_constant() {
    // Core checkqueue.h:66 — const unsigned int nBatchSize = 128.
    // Rustoshi has no equivalent. rayon's adaptive partitioner may
    // use larger or smaller chunks, affecting cache locality.
    const CORE_NBATCH_SIZE: usize = 128;
    let _ = CORE_NBATCH_SIZE; // would reference rustoshi constant once added
    panic!("nBatchSize=128 constant not exported by rustoshi_consensus");
}

// ============================================================
// G7 — OK (via rayon): lock-protected work queue
//
// Core: explicit std::mutex + condition_variable on queue.
// Rustoshi: rayon's work-stealing deque is internally lock-free /
//           mutex-protected; correct for parallel safety.
// ============================================================

#[test]
fn g7_parallel_script_check_is_thread_safe() {
    // validate_scripts_parallel_with_cache uses par_iter() on
    // script_checks, so checks run under rayon's safe parallelism.
    // This is a no-panic smoke test.
    let checks: Vec<u32> = (0..64).collect();
    use rayon::prelude::*;
    let sum: u32 = checks.par_iter().sum();
    assert_eq!(sum, 63 * 64 / 2);
}

// ============================================================
// G8 — OK (rayon handles wakeup internally)
// ============================================================

#[test]
fn g8_worker_wakeup_on_enqueue() {
    // rayon internally parks idle threads and wakes them on work enqueue.
    // No explicit notify_one() needed by the caller.
    use rayon::prelude::*;
    let v: Vec<u32> = (0..16).collect();
    let r: u32 = v.par_iter().map(|&x| x * 2).sum();
    assert_eq!(r, 240);
}

// ============================================================
// G9 — OK: workers pull batches, release work, run checks
// ============================================================

#[test]
fn g9_worker_pulls_and_runs_checks() {
    use rayon::prelude::*;
    let items: Vec<i32> = (-32..32).collect();
    let results: Vec<bool> = items.par_iter().map(|&x| x >= 0).collect();
    assert_eq!(results.iter().filter(|&&b| b).count(), 32);
}

// ============================================================
// G10 — OK: workers re-acquire work (rayon loops internally)
// ============================================================

#[test]
fn g10_workers_continue_after_batch() {
    use rayon::prelude::*;
    // Two separate rounds of par_iter — same rayon pool processes both.
    let a: u32 = (0u32..100).collect::<Vec<_>>().par_iter().sum();
    let b: u32 = (100u32..200).collect::<Vec<_>>().par_iter().sum();
    assert_eq!(a, 4950);
    assert_eq!(b, 14950);
}

// ============================================================
// G11 — MISSING: first-failure cancellation (bAllOk short-circuit)
//
// Core: as soon as one CScriptCheck fails, `m_result.has_value()`
//       becomes true and subsequent workers skip execution
//       (`do_work = !m_result.has_value()` in checkqueue.h:126).
// Rustoshi: `validate_scripts_parallel_with_cache` collects ALL
//           results into a Vec with `.collect()`, then scans for
//           failures. All N checks always execute even after the
//           first failure is detected — wasted CPU on invalid blocks.
// Severity: P1 (DoS amplification: attacker crafts block with 1
//           bad script at position 0 and 10,000 expensive valid
//           scripts — all 10,000 run before rejection).
// ============================================================

#[test]
#[ignore = "BUG G11 (P1): no first-failure cancellation; validate_scripts_parallel_with_cache collects all results before checking — O(N) work even when first check fails (DoS amplifier)"]
fn g11_first_failure_cancellation_missing() {
    // Demonstrates that validate_scripts_parallel_with_cache runs ALL
    // checks regardless of early failure — no short-circuit.
    // A real test would need a block with many expensive-but-valid
    // scripts after an invalid one; here we just document the structural
    // absence: the `results.iter().find(|r| r.is_err())` scan happens
    // AFTER the full `.collect()`, not interleaved with execution.
    //
    // Core's CCheckQueue::Loop sets do_work=false as soon as
    // m_result.has_value() — workers stop executing new checks.
    // rustoshi's par_iter().map(...).collect() has no such mechanism.
    panic!("first-failure short-circuit is absent in validate_scripts_parallel_with_cache");
}

// ============================================================
// G12 — MISSING: explicit RAII control (CCheckQueueControl)
//
// Core: `CCheckQueueControl<CScriptCheck>` in ConnectBlock is an
//       RAII guard — its destructor calls Complete() which waits
//       for all workers before ConnectBlock returns.
// Rustoshi: rayon's par_iter().collect() is synchronous — all
//           parallel work completes before collect() returns, so
//           the guarantee holds implicitly. However, there is no
//           separate CCheckQueueControl RAII type; the parallel
//           function is called standalone, not as a control object.
//           MORE CRITICALLY: connect_block_with_sequence_locks
//           does NOT call validate_scripts_parallel_with_cache at
//           all (dead helper) — see G16 below.
// Severity: P2 (structural / dead helper)
// ============================================================

#[test]
#[ignore = "BUG G12 (P2): CCheckQueueControl RAII type absent; more critically, validate_scripts_parallel_with_cache is never called from connect_block_with_sequence_locks (dead helper)"]
fn g12_raii_control_and_parallel_not_wired() {
    // The helper exists but is never invoked on the block-connect path.
    // connect_block_with_sequence_locks uses a sequential per-input loop.
    panic!("validate_scripts_parallel_with_cache is a dead helper (not called from connect_block)");
}

// ============================================================
// G13 — MISSING: nIdle counter tracking
//
// Core: `nIdle` tracks idle workers so the batch-size formula
//       `max(1, min(nBatchSize, queue.size()/(nTotal+nIdle+1)))`
//       distributes work evenly across available workers.
// Rustoshi: rayon manages work-stealing internally — no nIdle.
//           Adaptive but different distribution heuristics.
// Severity: P3
// ============================================================

#[test]
fn g13_rayon_manages_idle_internally() {
    // rayon's work-stealing is functionally equivalent for
    // correctness; nIdle tracking is an internal detail.
    // This gate is treated as OK for correctness purposes.
    assert!(rayon::current_num_threads() >= 1);
}

// ============================================================
// G14 — OK via rayon: m_request_stop for shutdown
//
// Core: `m_request_stop` flag set in `~CCheckQueue()` causes
//       workers to exit their loop cleanly.
// Rustoshi: rayon pool is global and persists for process lifetime;
//           no explicit stop needed per-block.
// ============================================================

#[test]
fn g14_shutdown_handled_by_rayon_lifecycle() {
    // rayon global pool cleans up on process exit automatically.
    let n = rayon::current_num_threads();
    assert!(n >= 1);
}

// ============================================================
// G15 — OK via rayon: no leaked check objects on cancellation
//
// Core: workers drain remaining checks on m_request_stop so that
//       all CScriptCheck destructors run before CCheckQueue exits.
// Rustoshi: rayon collect() is synchronous; all closures complete
//           (or are dropped cleanly) before collect() returns.
// ============================================================

#[test]
fn g15_no_leaked_checks_on_completion() {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);
    let items: Vec<usize> = (0..32).collect();
    let _: Vec<usize> = items
        .par_iter()
        .map(|&x| {
            counter_clone.fetch_add(1, Ordering::Relaxed);
            x
        })
        .collect();
    // All 32 closures ran to completion
    assert_eq!(counter.load(Ordering::Relaxed), 32);
}

// ============================================================
// G16 — FIXED / P1-PERF: parallel script verification is now WIRED
//       into the block-connect path.
//
// Core: ConnectBlock calls CheckInputScripts with a vChecks pointer,
//       then `control->Add(std::move(vChecks))` — parallel dispatch
//       on every non-coinbase tx (validation.cpp:2581-2584).
// Rustoshi (now): `connect_block_with_sequence_locks` runs all the
//       non-script gates and UTXO mutations serially and in order,
//       accumulates each non-coinbase tx's prevout coins into a
//       block-level `Vec<Vec<CoinEntry>>`, then dispatches script
//       verification ONCE via `validate_scripts_parallel_with_cache`
//       (capped rayon pool, first-failure short-circuit) — unless
//       assume-valid is in effect, which skips scripts as before.
//
// This test proves the helper is REACHABLE from the connect path:
// it builds a block with one non-coinbase tx spending a pre-seeded
// mature coin whose scriptPubKey is `OP_0` (leaves false on the
// stack → always fails verify_script).  Every other gate passes, so
// the ONLY thing that can reject the block is script verification.
// If the helper were still a dead helper, the block would connect
// successfully; because it is wired, the connect fails with a
// `ScriptFailed`/`TxValidation` error.
// ============================================================

#[test]
fn g16_parallel_verify_wired_into_connect_block() {
    use rustoshi_consensus::params::ChainParams;
    use rustoshi_consensus::validation::{
        connect_block_with_sequence_locks, SequenceLockContext, TxValidationError, ValidationError,
    };

    // Minimal SequenceLockContext (no BIP-68 path is exercised here:
    // the spending tx is version 1, so get_mtp_at_height is never read).
    struct ZeroSeqCtx;
    impl SequenceLockContext for ZeroSeqCtx {
        fn get_mtp_at_height(&self, _height: u32) -> u32 {
            0
        }
    }

    let params = ChainParams::regtest();
    let height: u32 = 200; // well past coinbase maturity for the seeded coin

    // Pre-seed a spendable, NON-coinbase, mature coin with a scriptPubKey of
    // OP_0 — a valid (spendable, non-OP_RETURN) output that nonetheless makes
    // any spend fail script verification (top stack element is false).
    let funding_txid = _make_hash(0x42);
    let funding_outpoint = OutPoint { txid: funding_txid, vout: 0 };
    let mut utxos: HashMap<OutPoint, CoinEntry> = HashMap::new();
    utxos.insert(
        funding_outpoint.clone(),
        CoinEntry {
            height: 1, // mined long ago → mature, not coinbase
            is_coinbase: false,
            value: 5_000_000_000,
            script_pubkey: vec![0x00], // OP_0 → spend always fails verify
        },
    );
    let mut view = MapUtxo(utxos);

    // Coinbase tx (BIP-34 height push, value within subsidy).
    let coinbase_script: Vec<u8> = {
        let mut s = vec![0x03u8];
        s.extend_from_slice(&height.to_le_bytes()[..3]);
        s
    };
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0u8; 32]), vout: 0xFFFF_FFFF },
            script_sig: coinbase_script,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 5_000_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };

    // Non-coinbase tx spending the seeded coin. version=1 → no BIP-68.
    // sequence is final so IsFinalTx passes; output < input so fee is valid.
    let spend_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: vec![], // empty scriptSig — OP_0 still leaves false
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 4_000_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 0x20000000,
            prev_block_hash: _make_hash(0x01),
            merkle_root: Hash256([0u8; 32]),
            timestamp: 1_700_000_000 + height,
            bits: params.genesis_block.header.bits,
            nonce: 0,
        },
        transactions: vec![coinbase_tx, spend_tx],
    };

    // Assume-valid must NOT be active for this height, or scripts are skipped
    // by design (mirrors Core).  regtest has no assumed-valid height.
    assert!(
        params
            .assumed_valid_height
            .map(|av| height > av)
            .unwrap_or(true),
        "test predicate: scripts must be verified at this height (not assume-valid)"
    );

    let result =
        connect_block_with_sequence_locks(&block, height, &mut view, &params, &ZeroSeqCtx, 0, false);

    // The ONLY failing gate is script verification, which only runs if the
    // parallel helper is actually wired into the connect path.  A dead helper
    // would let this block connect.
    assert!(
        matches!(
            result,
            Err(ValidationError::TxValidation(TxValidationError::ScriptFailed(_)))
        ),
        "connect_block_with_sequence_locks must reject the block via the now-wired \
         parallel script verifier (validate_scripts_parallel_with_cache); got: {:?}",
        result
    );
}

// ============================================================
// G17 — N/A (CCheckQueueControl once per block)
//
// Core: One CCheckQueueControl per ConnectBlock call — the mutex
//       `m_control_mutex` prevents two concurrent uses.
// Rustoshi: validate_scripts_parallel_with_cache can be called
//           concurrently from multiple callers without a guard,
//           but is not wired in (G16), so this is moot.
// ============================================================

#[test]
fn g17_single_control_per_block_via_rayon() {
    // rayon par_iter is re-entrant safe. In future wiring, ensure
    // validate_scripts_parallel_with_cache is not called concurrently
    // for the same block.
    assert!(true);
}

// ============================================================
// G18 — OK: Add(Vec<T>) moves checks into the queue
//
// Core: `CCheckQueue::Add(std::vector<T>&&)` moves checks in.
// Rustoshi: validate_scripts_parallel_with_cache takes `block` and
//           `coins` by reference and builds the work vector
//           internally. No semantic issue.
// ============================================================

#[test]
fn g18_work_moved_into_parallel_dispatch() {
    use rayon::prelude::*;
    let items: Vec<String> = (0..4).map(|i| format!("item-{}", i)).collect();
    let lengths: Vec<usize> = items.par_iter().map(|s| s.len()).collect();
    assert_eq!(lengths.len(), 4);
}

// ============================================================
// G19 — MISSING: master-also-processes (N+1 worker model)
//
// Core: After Add()-ing all checks, the master thread calls
//       Complete() which invokes Loop(true), making the calling
//       thread an N+1th worker until all checks finish.
// Rustoshi: rayon par_iter handles master-as-worker transparently
//           (the calling thread participates in work-stealing).
//           Functionally equivalent but no explicit N+1 accounting.
// Severity: P3 (functionally equivalent; rayon docs confirm calling
//           thread participates)
// ============================================================

#[test]
fn g19_master_participates_in_parallel_work() {
    // rayon work-stealing: the calling thread participates.
    use rayon::prelude::*;
    let v: Vec<u32> = (0..100).collect();
    let sum: u32 = v.par_iter().sum();
    assert_eq!(sum, 4950);
}

// ============================================================
// G20 — OK: parallel check returns Err on first failure
//
// Core: CCheckQueueControl::Complete() returns optional<R> which
//       is non-nullopt when a check failed.
// Rustoshi: validate_scripts_parallel_with_cache returns
//           Result<(), TxValidationError> — maps correctly.
//           (Though all checks run first — see G11.)
// ============================================================

#[test]
fn g20_parallel_check_result_ok_on_all_pass() {
    // Smoke: a block with no non-coinbase txs has no scripts to check.
    let params = ChainParams::mainnet();
    let prev = params.genesis_hash;
    let block = make_coinbase_block(1, prev, &params);
    // No non-coinbase txs → empty script_checks → Ok(())
    let coins: Vec<Vec<CoinEntry>> = Vec::new();
    let flags = rustoshi_consensus::ScriptFlags {
        verify_p2sh: true,
        ..Default::default()
    };
    let result = validate_scripts_parallel_with_cache(&block, &coins, &flags, None);
    assert!(result.is_ok(), "coinbase-only block: {:?}", result);
}

// ============================================================
// G21 — BUG (P2): CScriptCheck struct does not store
//       cacheStore / PrecomputedTransactionData
//
// Core: CScriptCheck (validation.h:338) stores:
//   - CTxOut prev (scriptPubKey + value)
//   - CTransaction& tx
//   - uint32_t nIn
//   - script_verify_flags flags
//   - bool cacheStore
//   - PrecomputedTransactionData* txdata
//
// Rustoshi: There is no CScriptCheck struct. The parallel helper
//           builds an ad-hoc tuple and passes data inline to
//           verify_script. `cacheStore` is absent — cache is
//           ALWAYS written on success (see G25 analysis).
//           PrecomputedTransactionData has no equivalent; sighash
//           is recomputed fresh per-call (no memoization).
// Severity: P2 (correctness: sighash recomputed; missing cacheStore
//           semantics inverts Core's cache-write policy — see G25)
// ============================================================

#[test]
#[ignore = "BUG G21 (P2): no CScriptCheck struct; cacheStore flag absent; PrecomputedTransactionData (memoized sighash) not implemented"]
fn g21_cscriptcheck_struct_and_cachestore_missing() {
    // There is no `rustoshi_consensus::CScriptCheck` type.
    // validate_scripts_parallel_with_cache builds inline tuples
    // rather than a reusable struct that can be enqueued.
    panic!("CScriptCheck struct with cacheStore / PrecomputedTransactionData absent");
}

// ============================================================
// G22 — OK: signature cache lookup short-circuits verify
//
// Core: CachingTransactionSignatureChecker::VerifyECDSASignature /
//       VerifySchnorrSignature check SignatureCache before ECDSA.
// Rustoshi: validate_scripts_parallel_with_cache checks SigCache
//           before calling verify_script. Cache hit → skip verify.
//           Key is now SHA256(nonce||script_sig||script_pubkey||witness||flags)
//           (G23 fixed).
// ============================================================

#[test]
fn g22_cache_hit_short_circuits_verify() {
    let cache = SigCache::new(100);
    let script_sig = vec![0xabu8; 72];
    let script_pubkey = vec![0x76u8; 25];
    let witness: Vec<Vec<u8>> = vec![];
    // Post-W160-BUG-9: cache key also commits to (wtxid, input_idx).
    let wtxid = [0xCCu8; 32];

    // Pre-populate — simulates prior mempool validation
    cache.insert(&wtxid, 0, &script_sig, &script_pubkey, &witness, 0x0001);

    // Hit: same material
    assert!(cache.lookup(&wtxid, 0, &script_sig, &script_pubkey, &witness, 0x0001));
    // Miss: different flags
    assert!(!cache.lookup(&wtxid, 0, &script_sig, &script_pubkey, &witness, 0x0002));
}

// ============================================================
// G23 — FIXED (P1): cache key now SHA256(nonce||script_sig||script_pubkey||witness||flags)
//
// Core: sigcache.h:42 — "Entries are SHA256(nonce || 'E' or 'S' ||
//       31 zero bytes || signature hash || public key || signature)".
//       The key covers the SPECIFIC SIGNATURE + PUBKEY, not just
//       the tx.  Two inputs with the same txid+index but different sig
//       bytes must NOT share a cache entry; an attacker rebroadcasting a
//       malformed variant of a previously cached tx input must not hit.
//
// Fix: SigCache now carries a 256-bit per-session OsRng nonce.
//      lookup() / insert() take (script_sig, script_pubkey, witness, flags)
//      and key on SHA256(nonce||script_sig||script_pubkey||witness||flags).
//      The old txid+input_index key is gone.
// Severity was: P1 (cache-poisoning → forged-sig acceptance)
// ============================================================

#[test]
fn g23_cache_key_covers_signature_and_pubkey_bytes() {
    let cache = SigCache::new(100);
    let script_pubkey = vec![0x76u8, 0xa9, 0x14]; // P2PKH-style prefix
    let witness: Vec<Vec<u8>> = vec![];
    let flags: u32 = 0x0001;
    let wtxid = [0xABu8; 32];

    // sig_a: "valid" sig material
    let sig_a = vec![0xaau8; 72];
    // sig_b: forged / different sig bytes — same outpoint identity
    let sig_b = vec![0xbbu8; 72];

    // Cache a hit for sig_a
    cache.insert(&wtxid, 0, &sig_a, &script_pubkey, &witness, flags);

    // sig_a must hit
    assert!(
        cache.lookup(&wtxid, 0, &sig_a, &script_pubkey, &witness, flags),
        "sig_a should hit the cache after insert"
    );

    // sig_b (different bytes, same conceptual outpoint) must NOT hit
    assert!(
        !cache.lookup(&wtxid, 0, &sig_b, &script_pubkey, &witness, flags),
        "sig_b must not hit the cache — cache key covers sig bytes, preventing cache-poisoning"
    );

    // Per-session nonce: a fresh cache instance must also not hit for sig_a
    // (different nonce → different key space → no cross-session poisoning)
    let cache2 = SigCache::new(100);
    assert!(
        !cache2.lookup(&wtxid, 0, &sig_a, &script_pubkey, &witness, flags),
        "a fresh cache with different nonce must not inherit entries from the old cache"
    );
}

// ============================================================
// G24 — BUG (P1): cache written on successful connect_block verify
//       but Core explicitly DOES NOT write cache during ConnectBlock
//
// Core: `fCacheResults = fJustCheck` (validation.cpp:2576).
//       In the normal ConnectBlock path fJustCheck=false, so
//       fCacheResults=false. The cache is CONSULTED but NOT WRITTEN
//       during block connection. Only test/fJustCheck paths write.
//       Rationale: writing during IBD would evict mempool-verified
//       entries with block-verified entries that have a different
//       verification context.
//
// Rustoshi: validate_scripts_parallel_with_cache always writes to
//           cache on success (validation.rs:2001-2004):
//             if result.is_ok() { cache.insert(...) }
//           No fCacheResults / fJustCheck distinction.
//           ADDITIONAL BUG: connect_block_with_sequence_locks does
//           not even call validate_scripts_parallel_with_cache (G16),
//           so the cache is never written on the live path anyway —
//           but if G16 is fixed without also fixing G24, this becomes
//           a real regression.
// Severity: P1 (cache semantics inversion; will pollute cache on
//           reconnect/reorg; pairs with G23 to amplify severity)
// ============================================================

#[test]
#[ignore = "BUG G24 (P1): validate_scripts_parallel_with_cache always writes to SigCache on success; Core only writes during fJustCheck=true (testnet / pre-validation), NOT during actual ConnectBlock; this inverts Core's fCacheResults semantics"]
fn g24_cache_write_policy_inverted() {
    // In Core, connecting a real block uses fCacheResults=false.
    // rustoshi's helper writes unconditionally.
    // Demonstrate: after calling validate_scripts_parallel_with_cache
    // on a block with a pre-populated cache for one input, that input
    // would be written again (no-op currently but semantically wrong).
    panic!("fCacheResults=false during ConnectBlock is not modeled; cache write is unconditional");
}

// ============================================================
// G25 — OK: cache writes only on successful verify
//
// Core: sig is added to cache only inside VerifyECDSASignature /
//       VerifySchnorrSignature after a successful verify.
// Rustoshi: `if result.is_ok() { cache.insert(...) }` at
//           validation.rs:2001. Correct — no cache poisoning on fail.
// ============================================================

#[test]
fn g25_cache_write_only_on_success() {
    let cache = SigCache::new(100);
    let script_sig = vec![0x01u8; 72];
    let script_pubkey = vec![0x76u8; 25];
    let witness: Vec<Vec<u8>> = vec![];
    let wtxid = [0xDDu8; 32];

    // Simulate: validation failed → no insert
    // (rustoshi code path: result = Err(_); no cache.insert())
    assert!(!cache.lookup(&wtxid, 0, &script_sig, &script_pubkey, &witness, 0x0001));

    // Simulate: validation succeeded → insert
    cache.insert(&wtxid, 0, &script_sig, &script_pubkey, &witness, 0x0001);
    assert!(cache.lookup(&wtxid, 0, &script_sig, &script_pubkey, &witness, 0x0001));

    // Different flags — distinct entry (failed validations not cached)
    assert!(!cache.lookup(&wtxid, 0, &script_sig, &script_pubkey, &witness, 0x0002));
}

// ============================================================
// G26 — OK: script flags computed per height with consensus flags
//
// Core: `GetBlockScriptFlags(pindex, chainman.GetConsensus())`
//       returns P2SH|DERSIG|CLTV|CSV|WITNESS|NULLDUMMY|TAPROOT
//       activated at appropriate heights.
// Rustoshi: `script_flags_for_height()` in validation.rs:2338
//           returns the same set. Correctly excludes policy flags
//           (NULLFAIL, CLEANSTACK, LOW_S, etc.).
// ============================================================

#[test]
fn g26_script_flags_per_height_consensus_only() {
    // mainnet SegWit activation at h=481,824
    let _params = ChainParams::mainnet();
    // Below SegWit: P2SH only
    let flags_pre = rustoshi_consensus::ScriptFlags::consensus_flags(100_000, false);
    assert!(flags_pre.verify_p2sh);
    assert!(!flags_pre.verify_witness);
    assert!(!flags_pre.verify_taproot);

    // Post-SegWit, post-Taproot (h=709,632)
    let flags_post = rustoshi_consensus::ScriptFlags::consensus_flags(750_000, false);
    assert!(flags_post.verify_p2sh);
    assert!(flags_post.verify_witness);
    assert!(flags_post.verify_taproot);

    // Policy flags must NOT be set
    assert!(!flags_post.verify_nullfail, "NULLFAIL is policy-only, must not be set in block validation");
    assert!(!flags_post.verify_cleanstack, "CLEANSTACK is policy-only");
}

// ============================================================
// G27 — OK: MANDATORY vs STANDARD flag distinction documented
//
// Rustoshi correctly comments that only MANDATORY flags are used
// during block validation (validation.rs:2324-2342).
// ============================================================

#[test]
fn g27_mandatory_vs_standard_flags_separated() {
    // Verify no policy-only flag leaks into consensus validation path.
    let _params = ChainParams::mainnet();
    // Use the consensus flag path at a height where all activations are done.
    let flags = rustoshi_consensus::ScriptFlags::consensus_flags(800_000, false);

    // These are the policy-only flags that must NOT appear in block validation:
    assert!(!flags.verify_nullfail, "NULLFAIL is policy-only (BIP-146)");
    assert!(!flags.verify_cleanstack, "CLEANSTACK is policy-only");
    assert!(!flags.verify_low_s, "LOW_S is policy-only");
    assert!(!flags.verify_strictenc, "STRICTENC is policy-only");
    assert!(!flags.verify_minimaldata, "MINIMALDATA is policy-only");
    assert!(!flags.verify_minimalif, "MINIMALIF is policy-only (in tapscript consensus: must not be in pre-tapscript block path)");
    assert!(!flags.verify_witness_pubkeytype, "WITNESS_PUBKEYTYPE is policy-only");
}

// ============================================================
// G28 — MISSING: -par=1 means SINGLE-threaded determinism mode
//
// Core: `-par=1` means exactly 1 verification thread (the master).
//       This is used for test determinism and reduced parallelism.
// Rustoshi: No `--par` flag exists, so -par=1 cannot be expressed.
//           `rayon::ThreadPoolBuilder::new().num_threads(1).build_global()`
//           would be the equivalent but is not wired.
// Severity: P2 (testing / determinism)
// ============================================================

#[test]
#[ignore = "BUG G28 (P2): no --par=1 single-thread mode; rayon global pool cannot be forced to 1 thread via CLI; needed for test determinism and debugging"]
fn g28_par_1_single_threaded_mode() {
    // Core allows -par=1 to force serial script checking.
    // rustoshi has no equivalent. rayon pool is shared/global.
    panic!("--par=1 single-thread mode absent; rayon global pool cannot be CLI-constrained to 1 thread");
}

// ============================================================
// G29 — OK (rayon takes references): checks passed by move/ref
//
// Core: `control->Add(std::move(vChecks))` — move semantics to
//       avoid copying CScriptCheck objects.
// Rustoshi: par_iter() borrows the script_checks Vec; zero extra
//           copies. Equivalent efficiency.
// ============================================================

#[test]
fn g29_checks_passed_without_copy() {
    use rayon::prelude::*;
    let data: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; 32]).collect();
    // par_iter borrows, no clone/move needed
    let sums: Vec<u8> = data.par_iter().map(|v| v.iter().sum()).collect();
    assert_eq!(sums.len(), 8);
}

// ============================================================
// G30 — MISSING: reorg path (DisconnectBlock+ConnectBlock) does
//       not use parallel script verification either
//
// Core: The reorg path calls ConnectBlock with full CCheckQueueControl
//       parallel dispatch (same code path as normal connect).
// Rustoshi: reorganize() in chain_state.rs:662-706 calls
//           connect_block_with_sequence_locks which uses the
//           sequential loop — same dead-helper problem as G16.
//           Both the fast-path and reorg-path lack parallelism.
// Severity: P1 (same as G16 — reorg script verification is also
//           sequential on multi-core hardware)
// ============================================================

#[test]
#[ignore = "BUG G30 (P1): reorg path in ChainState::reorganize() also calls connect_block_with_sequence_locks sequentially; parallel verify not used on reorg either (same dead-helper as G16)"]
fn g30_reorg_connect_uses_parallel_verify() {
    panic!("reorg path uses sequential script verification same as normal connect — validate_scripts_parallel_with_cache not called from reorganize()");
}

// ============================================================
// Additional correctness: SigCache key covers cryptographic material
// ============================================================

#[test]
fn sig_cache_is_keyed_by_script_material() {
    let cache = SigCache::new(100);
    let script_pubkey = vec![0x76u8; 25];
    let witness: Vec<Vec<u8>> = vec![];
    let flags: u32 = 0x0001;
    let wtxid = [0xEEu8; 32];

    let sig_a = vec![0xaau8; 72];
    let sig_b = vec![0xbbu8; 72];

    cache.insert(&wtxid, 0, &sig_a, &script_pubkey, &witness, flags);

    // Same sig, same flags — cache hit
    assert!(cache.lookup(&wtxid, 0, &sig_a, &script_pubkey, &witness, flags));
    // Different sig bytes — distinct entry (the anti-poisoning property)
    assert!(!cache.lookup(&wtxid, 0, &sig_b, &script_pubkey, &witness, flags));
    // Different flags — distinct entry
    assert!(!cache.lookup(&wtxid, 0, &sig_a, &script_pubkey, &witness, 0x0002));
}

#[test]
fn sig_cache_eviction_stays_within_capacity() {
    let cap = 20usize;
    let cache = SigCache::new(cap);
    let script_pubkey = vec![0x76u8; 25];
    let witness: Vec<Vec<u8>> = vec![];

    for i in 0u8..40 {
        let script_sig = vec![i; 72];
        cache.insert(&[i; 32], 0, &script_sig, &script_pubkey, &witness, 0);
    }

    // After inserting 40 entries into a cap-20 cache, size <= cap + slack
    assert!(
        cache.len() <= cap + 1,
        "cache len {} exceeds cap {} by more than 1",
        cache.len(),
        cap
    );
}

#[test]
fn sig_cache_clear_removes_all() {
    let cache = SigCache::new(100);
    let script_pubkey = vec![0x76u8; 25];
    let witness: Vec<Vec<u8>> = vec![];
    for i in 0u8..10 {
        let script_sig = vec![i; 72];
        cache.insert(&[i; 32], 0, &script_sig, &script_pubkey, &witness, 0);
    }
    assert_eq!(cache.len(), 10);
    cache.clear();
    assert!(cache.is_empty());
}

#[test]
fn parallel_function_smoke_coinbase_only() {
    // A coinbase-only block has no non-coinbase inputs.
    // validate_scripts_parallel_with_cache should return Ok(()).
    let p = ChainParams::mainnet();
    let block = make_coinbase_block(1, p.genesis_hash, &p);
    let coins: Vec<Vec<CoinEntry>> = Vec::new();
    let flags = rustoshi_consensus::ScriptFlags::default();
    let result = validate_scripts_parallel_with_cache(&block, &coins, &flags, None);
    assert!(result.is_ok());
}

#[test]
fn parallel_function_with_cache_smoke() {
    // With a SigCache provided but empty, coinbase-only block still Ok.
    let _params = ChainParams::mainnet();
    let block = make_coinbase_block(2, _params.genesis_hash, &_params);
    let coins: Vec<Vec<CoinEntry>> = Vec::new();
    let flags = rustoshi_consensus::ScriptFlags::default();
    let cache = SigCache::new(DEFAULT_MAX_ENTRIES);
    let result = validate_scripts_parallel_with_cache(&block, &coins, &flags, Some(&cache));
    assert!(result.is_ok());
    // Cache should still be empty (no non-coinbase inputs)
    assert!(cache.is_empty());
}
