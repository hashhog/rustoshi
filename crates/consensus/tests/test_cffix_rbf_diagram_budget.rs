//! The RBF feerate-diagram check must not cost an unbounded linearization.
//!
//! `check_rbf_diagram` (Core `ImprovesFeerateDiagram`, policy/rbf.cpp:127)
//! relinearizes every cluster the replacement touches, and it runs BEFORE the
//! script checks. rustoshi's chunk search (`DepGraph::find_best_chunk`)
//! enumerated all 2^n subsets of a cluster of n <= 16 transactions with no
//! budget, so one replacement carrying an invalid signature bought ~2^17
//! subset evaluations against a 17-transaction cluster, got rejected without
//! penalty, left the cluster in place, and could repeat.
//!
//! Core bounds the same work: `TxGraph` keeps linearizations and improves them
//! under a cost budget (`ACCEPTABLE_COST = 75'000`, txmempool.h:54;
//! `Linearize(..., max_iterations, ...)`, cluster_linearize.h).
//!
//! The work is measured as heap allocations on the test thread, counted by a
//! global allocator in this test binary. The pre-fix search allocated one
//! `HashSet` per mask it scanned, so the count tracks masks without relying
//! on wall clock or on any hook in the crate (so the file builds on the
//! pre-fix tree and fails there on the assertion).

use rustoshi_consensus::mempool::{DepGraph, FeeFrac, Mempool, MempoolConfig, MempoolError};
use rustoshi_consensus::CoinEntry;
use rustoshi_crypto::{hash160, sighash::segwit_v0_sighash};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

struct CountingAlloc;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

// SAFETY: forwards every call to `System`; only adds a thread-local count.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Fallback for trees without `DepGraph::search_visits`: an inherent
/// associated fn takes precedence over this trait's, so where the search
/// counts its visits this default is never called. Without that counter the
/// visit bound cannot hold, so the default reports "unbounded".
#[allow(dead_code)] // unused exactly when the inherent counter exists
trait SearchVisitsFallback {
    fn search_visits() -> u64 {
        u64::MAX
    }
}
impl SearchVisitsFallback for DepGraph {}

/// Work done on this thread while running `f`: (heap allocations, chunk
/// search visits). Visits saturate at u64::MAX when the tree has no counter.
fn cost_of<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    let allocs0 = ALLOCS.with(|c| c.get());
    let visits0 = DepGraph::search_visits();
    let out = f();
    let allocs = ALLOCS.with(|c| c.get()) - allocs0;
    let visits = if visits0 == u64::MAX { u64::MAX } else { DepGraph::search_visits() - visits0 };
    (out, allocs, visits)
}

const SIGHASH_ALL: u32 = 1;
const RBF_SEQ: u32 = 0xFFFF_FFFD;
const IN_VALUE: u64 = 1_000_000;

/// Upper bound on heap allocations, and on chunk-search visits, for one
/// rejected submission and for one linearize() call. Core's ACCEPTABLE_COST
/// figure. The pre-fix search makes ~131,000 allocations here (one per mask).
const ALLOC_BUDGET: u64 = 75_000;
const VISIT_BUDGET: u64 = 75_000;
/// 17 txs: at most n chunks, each search visiting O(n) prefixes over n
/// positions. 17 * 17 * 4 leaves room over the measured ~1,000.
const CHAIN_VISIT_BOUND: u64 = 17 * 17 * 4;

struct Key {
    sk: SecretKey,
    pk: [u8; 33],
    h160: [u8; 20],
}

fn key(seed: u8) -> Key {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk).serialize();
    let h160 = *hash160(&pk).as_bytes();
    Key { sk, pk, h160 }
}

fn p2wpkh_spk(k: &Key) -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&k.h160);
    v
}

fn p2wpkh_script_code(k: &Key) -> Vec<u8> {
    let mut v = vec![0x76, 0xa9, 0x14];
    v.extend_from_slice(&k.h160);
    v.extend_from_slice(&[0x88, 0xac]);
    v
}

/// 1-in/1-out P2WPKH spend of `prev`, signed by `signer`; `corrupt` flips one
/// bit of the DER `r` so the signature is well-formed but does not verify.
fn signed_spend(prev: OutPoint, in_value: u64, fee: u64, signer: &Key, dest: &Key, corrupt: bool) -> Transaction {
    let mut tx = Transaction {
        version: 2,
        inputs: vec![TxIn { previous_output: prev, script_sig: vec![], sequence: RBF_SEQ, witness: vec![] }],
        outputs: vec![TxOut { value: in_value - fee, script_pubkey: p2wpkh_spk(dest) }],
        lock_time: 0,
    };
    let sighash = segwit_v0_sighash(&tx, 0, &p2wpkh_script_code(signer), in_value, SIGHASH_ALL);
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(sighash.as_bytes()).unwrap();
    let mut der = secp.sign_ecdsa(&msg, &signer.sk).serialize_der().to_vec();
    if corrupt {
        let rlen = der[3] as usize;
        der[4 + rlen - 1] ^= 0x01;
    }
    der.push(SIGHASH_ALL as u8);
    tx.inputs[0].witness = vec![der, signer.pk.to_vec()];
    tx
}

#[test]
fn rbf_diagram_cost_is_bounded() {
    let alice = key(0x11);
    let bob = key(0x22);
    let carol = key(0x33);
    let mut root = [0u8; 32];
    root[0] = 0xb7;
    let prev = OutPoint { txid: Hash256::from(root), vout: 0 };
    let mut utxos = HashMap::new();
    utxos.insert(
        prev.clone(),
        CoinEntry { height: 500, is_coinbase: false, value: IN_VALUE, script_pubkey: p2wpkh_spk(&alice) },
    );
    let lookup = |op: &OutPoint| utxos.get(op).cloned();
    let mut mp = Mempool::new(MempoolConfig::production());
    mp.notify_new_tip(1_000, 1_700_000_000);

    // 17-tx chain rooted on the confirmed coin, each tx paying less than its
    // parent (decreasing feerate), so every tx is its own chunk.
    let mut outpoint = prev.clone();
    let mut value = IN_VALUE;
    let mut signer = &alice;
    let mut chain = Vec::new();
    for k in 0..17u64 {
        let fee = 20_000 - 1_000 * k;
        let tx = signed_spend(outpoint.clone(), value, fee, signer, &bob, false);
        let txid = mp.add_transaction(tx, &lookup).unwrap_or_else(|e| panic!("chain tx {k}: {e:?}"));
        chain.push(txid);
        outpoint = OutPoint { txid, vout: 0 };
        value -= fee;
        signer = &bob;
    }
    assert_eq!(mp.size(), 17);

    // Replacement of the root with a fee that passes every RBF fee rule and
    // the diagram check, but an invalid signature.
    let attacker = signed_spend(prev.clone(), IN_VALUE, 600_000, &alice, &carol, true);
    let (r, allocs, visits) = cost_of(|| mp.add_transaction(attacker, &lookup));
    eprintln!("rejected replacement: {allocs} allocations, {visits} search visits");
    assert!(
        matches!(r, Err(MempoolError::PolicyScriptCheckFailed(_, _))),
        "bad-signature replacement must be refused at the script gate; got {:?}",
        r
    );
    assert!(
        allocs <= ALLOC_BUDGET,
        "rejected replacement cost {allocs} allocations (budget {ALLOC_BUDGET})"
    );
    assert!(
        visits <= VISIT_BUDGET,
        "rejected replacement cost {visits} chunk-search visits (budget {VISIT_BUDGET})"
    );
    // A chain's ancestor-closed subsets are its prefixes, so a search that
    // visits only closed sets is quadratic here, far inside the budget. A
    // budgeted 2^n mask scan would hit the budget instead; this pins the
    // pruning, not just the cap.
    assert!(
        visits <= CHAIN_VISIT_BOUND,
        "rejected replacement cost {visits} chunk-search visits; closed-set search on a chain needs <= {CHAIN_VISIT_BOUND}"
    );
    for txid in &chain {
        assert!(mp.contains(txid), "chain must survive a rejected replacement");
    }

    // Control: the same replacement with a valid signature is accepted, so the
    // fee/diagram path above was really exercised and the bound did not come
    // from an early refusal.
    let honest = signed_spend(prev.clone(), IN_VALUE, 600_000, &alice, &carol, false);
    let honest_txid = honest.txid();
    let (ok, allocs, visits) = cost_of(|| mp.add_transaction(honest, &lookup));
    assert_eq!(ok.ok(), Some(honest_txid));
    assert!(allocs <= ALLOC_BUDGET, "accepted replacement cost {allocs} allocations");
    assert!(visits <= VISIT_BUDGET, "accepted replacement cost {visits} search visits");
    assert_eq!(mp.size(), 1);
}

// ---------------------------------------------------------------------------
// Diagram results are unchanged: the bounded search returns the same
// linearization as the exhaustive 2^n mask scan it replaced, on every graph
// small enough to finish inside the budget.
// ---------------------------------------------------------------------------

fn h(i: usize, salt: u64) -> Hash256 {
    let mut b = [0u8; 32];
    let x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt;
    b[..8].copy_from_slice(&x.to_le_bytes());
    b[8] = i as u8;
    Hash256::from(b)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Random DAG on `n` nodes (edges only from lower to higher index), closed.
fn random_graph(rng: &mut Rng, n: usize, edge_pct: u64, salt: u64) -> DepGraph {
    let mut ancestors: Vec<HashSet<usize>> = (0..n).map(|i| std::iter::once(i).collect()).collect();
    for j in 0..n {
        for i in 0..j {
            if rng.next() % 100 < edge_pct {
                let a: Vec<usize> = ancestors[i].iter().copied().collect();
                ancestors[j].extend(a);
            }
        }
    }
    let mut descendants: Vec<HashSet<usize>> = (0..n).map(|i| std::iter::once(i).collect()).collect();
    for (i, ancs) in ancestors.iter().enumerate() {
        for &a in ancs {
            descendants[a].insert(i);
        }
    }
    let idx_to_txid: Vec<Hash256> = (0..n).map(|i| h(i, salt)).collect();
    let txid_to_idx = idx_to_txid.iter().enumerate().map(|(i, t)| (*t, i)).collect();
    // Few distinct fee/size values so equal-feerate ties are common.
    let feerates = (0..n)
        .map(|_| FeeFrac { fee: (rng.next() % 6) as i64 * 100, size: 100 + (rng.next() % 3) as i64 * 50 })
        .collect();
    DepGraph { txid_to_idx, idx_to_txid, feerates, ancestors, descendants }
}

/// The pre-fix chunk picker, verbatim in behaviour: ancestor-set heuristic,
/// then every mask in increasing order, keeping strictly better candidates.
fn reference_linearize(g: &DepGraph) -> Vec<(Vec<Hash256>, FeeFrac)> {
    let ff = |s: &HashSet<usize>| {
        let mut t = FeeFrac::default();
        for &i in s {
            t += g.feerates[i];
        }
        t
    };
    let max_txid = |s: &HashSet<usize>| s.iter().map(|&i| g.idx_to_txid[i]).max();
    let better = |c: &HashSet<usize>, cf: &FeeFrac, b: &HashSet<usize>, bf: &FeeFrac| {
        let lhs = (cf.fee as i128) * (bf.size as i128);
        let rhs = (bf.fee as i128) * (cf.size as i128);
        lhs.cmp(&rhs)
            .then_with(|| bf.size.cmp(&cf.size))
            .then_with(|| max_txid(b).cmp(&max_txid(c)))
            .is_gt()
    };
    let topo = |s: &HashSet<usize>| {
        let mut v: Vec<usize> = s.iter().copied().collect();
        v.sort_by_key(|&i| g.ancestors[i].iter().filter(|a| s.contains(a)).count());
        v.into_iter().map(|i| g.idx_to_txid[i]).collect::<Vec<_>>()
    };
    let mut remaining: HashSet<usize> = (0..g.idx_to_txid.len()).collect();
    let mut chunks: Vec<(Vec<Hash256>, FeeFrac)> = Vec::new();
    while !remaining.is_empty() {
        let mut best = HashSet::new();
        let mut best_ff = FeeFrac::default();
        for &i in &remaining {
            let c: HashSet<usize> = g.ancestors[i].iter().copied().filter(|a| remaining.contains(a)).collect();
            let cf = ff(&c);
            if best.is_empty() || better(&c, &cf, &best, &best_ff) {
                best = c;
                best_ff = cf;
            }
        }
        if remaining.len() <= 16 {
            let mut idxs: Vec<usize> = remaining.iter().copied().collect();
            idxs.sort_unstable();
            let n = idxs.len();
            for mask in 1u32..(1u32 << n) {
                let c: HashSet<usize> = (0..n).filter(|b| mask & (1 << b) != 0).map(|b| idxs[b]).collect();
                let closed = c
                    .iter()
                    .all(|&i| g.ancestors[i].iter().all(|a| !remaining.contains(a) || c.contains(a)));
                if !closed {
                    continue;
                }
                let cf = ff(&c);
                if better(&c, &cf, &best, &best_ff) {
                    best = c;
                    best_ff = cf;
                }
            }
        }
        let txids = topo(&best);
        for i in &best {
            remaining.remove(i);
        }
        if let Some(last) = chunks.last_mut() {
            let combined = FeeFrac { fee: last.1.fee + best_ff.fee, size: last.1.size + best_ff.size };
            if combined.is_better_than(&last.1) {
                last.0.extend(txids);
                last.1 = combined;
                continue;
            }
        }
        chunks.push((txids, best_ff));
    }
    chunks
}

#[test]
fn bounded_chunk_search_matches_exhaustive_scan() {
    let mut rng = Rng(0x5eed_cafe_f00d_1234);
    let mut cases = 0;
    for n in 1..=12usize {
        for edge_pct in [0u64, 15, 35, 70] {
            for rep in 0..6u64 {
                let salt = (n as u64) << 32 | edge_pct << 8 | rep;
                let g = random_graph(&mut rng, n, edge_pct, salt);
                // Order inside a chunk comes from HashSet iteration in
                // `topological_sort`; compare chunk membership, order and fees.
                let sorted = |v: Vec<(Vec<Hash256>, FeeFrac)>| {
                    v.into_iter()
                        .map(|(mut t, f)| {
                            t.sort();
                            (t, f)
                        })
                        .collect::<Vec<_>>()
                };
                let want = sorted(reference_linearize(&g));
                let got = sorted(g.linearize().into_iter().map(|c| (c.txids, c.feefrac)).collect());
                assert_eq!(got, want, "n={n} edge_pct={edge_pct} rep={rep}");
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 12 * 4 * 6);
}

/// A wide cluster -- one parent and 15 children -- has 2^15 + 1 ancestor-closed
/// subsets, so even a search that visits only closed sets would spend ~2^16
/// subset visits per chunk. The per-linearize budget caps it, and the fallback still
/// returns a complete, topologically valid linearization.
#[test]
fn wide_cluster_linearize_is_bounded_and_valid() {
    let n = 16usize;
    let mut ancestors: Vec<HashSet<usize>> = (0..n).map(|i| std::iter::once(i).collect()).collect();
    for anc in ancestors.iter_mut().skip(1) {
        anc.insert(0);
    }
    let mut descendants: Vec<HashSet<usize>> = (0..n).map(|i| std::iter::once(i).collect()).collect();
    descendants[0].extend(1..n);
    let idx_to_txid: Vec<Hash256> = (0..n).map(|i| h(i, 0x57a2)).collect();
    let txid_to_idx: HashMap<Hash256, usize> = idx_to_txid.iter().enumerate().map(|(i, t)| (*t, i)).collect();
    // The parent pays the highest feerate, so it is a chunk by itself and the
    // 15 children are left as an antichain for the next rounds: the
    // exhaustive scan then pays 2^16 + 2^15 + ... masks.
    let feerates: Vec<FeeFrac> = (0..n)
        .map(|i| if i == 0 { FeeFrac { fee: 100_000, size: 100 } } else { FeeFrac { fee: 100 * i as i64, size: 100 } })
        .collect();
    let g = DepGraph { txid_to_idx: txid_to_idx.clone(), idx_to_txid, feerates, ancestors, descendants };

    let (chunks, allocs, visits) = cost_of(|| g.linearize());
    eprintln!("wide-cluster linearize: {allocs} allocations, {visits} search visits");
    assert!(allocs <= ALLOC_BUDGET, "wide-cluster linearize cost {allocs} allocations (budget {ALLOC_BUDGET})");
    // Pruning to closed sets alone would visit ~2^16 + 2^15 + ... here; only
    // the per-call budget stops the search, and it stops it exactly there.
    assert_eq!(visits, VISIT_BUDGET, "wide-cluster linearize must stop at the search budget");

    // Every tx exactly once; no tx before any of its ancestors.
    let order: Vec<usize> = chunks.iter().flat_map(|c| c.txids.iter().map(|t| txid_to_idx[t])).collect();
    let mut seen = HashSet::new();
    for &i in &order {
        assert!(g.ancestors[i].iter().all(|a| *a == i || seen.contains(a)), "tx {i} placed before an ancestor");
        assert!(seen.insert(i), "tx {i} placed twice");
    }
    assert_eq!(seen.len(), n);
    let total = chunks.iter().fold(FeeFrac::default(), |acc, c| acc + c.feefrac);
    assert_eq!(total, g.set_feefrac(&(0..n).collect()));
}
