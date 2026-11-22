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
/// rejected submission against the 17-tx chain, and on allocations for one
/// linearize() call. Core's ACCEPTABLE_COST figure. The pre-fix search makes ~131,000 allocations here (one per mask).
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
// Diagram results are unchanged: the closed-set search returns the same
// linearization as the exhaustive 2^n mask scan it replaced.
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

/// Upper bound on chunk-search visits for one linearize() of any cluster:
/// exact search runs only while at most 16 transactions remain, and the
/// widest such cluster (one parent, 15 children) measures 229,357 visits.
const WIDE_VISIT_BOUND: u64 = 240_000;

/// One parent and 15 children; `parent_at` is the parent's index, the
/// children take the other indices in increasing order of `child_fees`.
fn star_graph(parent_fee: i64, child_fees: &[i64], parent_at: usize, salt: u64) -> DepGraph {
    let n = child_fees.len() + 1;
    let children: Vec<usize> = (0..n).filter(|&i| i != parent_at).collect();
    let mut ancestors: Vec<HashSet<usize>> = (0..n).map(|i| std::iter::once(i).collect()).collect();
    let mut descendants: Vec<HashSet<usize>> = (0..n).map(|i| std::iter::once(i).collect()).collect();
    let mut feerates = vec![FeeFrac::default(); n];
    feerates[parent_at] = FeeFrac { fee: parent_fee, size: 100 };
    for (k, &c) in children.iter().enumerate() {
        ancestors[c].insert(parent_at);
        descendants[parent_at].insert(c);
        feerates[c] = FeeFrac { fee: child_fees[k], size: 100 };
    }
    let idx_to_txid: Vec<Hash256> = (0..n).map(|i| h(i, salt)).collect();
    let txid_to_idx = idx_to_txid.iter().enumerate().map(|(i, t)| (*t, i)).collect();
    DepGraph { txid_to_idx, idx_to_txid, feerates, ancestors, descendants }
}

fn sorted_chunks(v: Vec<(Vec<Hash256>, FeeFrac)>) -> Vec<(Vec<Hash256>, FeeFrac)> {
    v.into_iter()
        .map(|(mut t, f)| {
            t.sort();
            (t, f)
        })
        .collect()
}

/// Every tx exactly once; no tx before any of its ancestors.
fn assert_topological(g: &DepGraph, chunks: &[rustoshi_consensus::mempool::Chunk]) {
    let n = g.idx_to_txid.len();
    let order: Vec<usize> = chunks.iter().flat_map(|c| c.txids.iter().map(|t| g.txid_to_idx[t])).collect();
    let mut seen = HashSet::new();
    for &i in &order {
        assert!(g.ancestors[i].iter().all(|a| *a == i || seen.contains(a)), "tx {i} placed before an ancestor");
        assert!(seen.insert(i), "tx {i} placed twice");
    }
    assert_eq!(seen.len(), n);
    let total = chunks.iter().fold(FeeFrac::default(), |acc, c| acc + c.feefrac);
    assert_eq!(total, g.set_feefrac(&(0..n).collect()));
}

/// A wide cluster -- one parent and 15 children -- has 2^15 + 1 ancestor-closed
/// subsets, and after the parent's chunk the 15 children are an antichain, so
/// the closed-set search visits 2^16 + 2^15 + ... subsets in all: more than
/// Core's 75,000 cost figure. It must still finish (a search cut short keeps
/// an index-order-dependent set) and return the exhaustive scan's answer,
/// within the shape's worst-case bound.
#[test]
fn wide_cluster_linearize_is_bounded_and_valid() {
    // The parent pays the highest feerate, so it is a chunk by itself and the
    // 15 children are left as an antichain for the next rounds.
    let child_fees: Vec<i64> = (1..16).map(|i| 100 * i as i64).collect();
    let g = star_graph(100_000, &child_fees, 0, 0x57a2);

    let t0 = std::time::Instant::now();
    let (chunks, allocs, visits) = cost_of(|| g.linearize());
    let elapsed = t0.elapsed();
    // Printed, not asserted: wall clock is not a stable bound on a shared box.
    eprintln!("wide-cluster linearize: {allocs} allocations, {visits} search visits, {elapsed:?}");
    assert!(allocs <= ALLOC_BUDGET, "wide-cluster linearize cost {allocs} allocations (budget {ALLOC_BUDGET})");
    assert!(visits > 75_000, "this shape must need more than a 75,000-visit budget; got {visits}");
    assert!(visits <= WIDE_VISIT_BOUND, "wide-cluster linearize cost {visits} visits (bound {WIDE_VISIT_BOUND})");
    assert_topological(&g, &chunks);
    let got = sorted_chunks(chunks.into_iter().map(|c| (c.txids, c.feefrac)).collect());
    assert_eq!(got, sorted_chunks(reference_linearize(&g)));
}

/// Warden's example on rustoshi#68: one parent (fee 1) and 15 children (fees
/// 10_000, 10_100, ..., 11_400), all size 100. The exact best chunk is the
/// parent plus every child except the 10_000-sat one: fee 150_501, size
/// 1_500. A search that stops early returns that only for some index orders
/// (with the parent last it finished; with the parent first and the children
/// in increasing-fee order it kept fee 149_201). The chunk must not depend on
/// where the parent sits.
#[test]
fn star_cluster_best_chunk_is_independent_of_index_order() {
    let child_fees: Vec<i64> = (0..15).map(|k| 10_000 + 100 * k).collect();
    let mut rng = Rng(0x0dd5_eed5_1234_5678);
    let mut orders: Vec<(usize, Vec<i64>)> = vec![(15, child_fees.clone()), (0, child_fees.clone())];
    // Decreasing-fee children, and shuffled ones, at every parent position.
    let mut rev = child_fees.clone();
    rev.reverse();
    orders.push((0, rev));
    for parent_at in 0..16 {
        let mut f = child_fees.clone();
        for i in (1..f.len()).rev() {
            f.swap(i, (rng.next() % (i as u64 + 1)) as usize);
        }
        orders.push((parent_at, f));
    }
    for (case, (parent_at, fees)) in orders.into_iter().enumerate() {
        let g = star_graph(1, &fees, parent_at, 0xbe57 + case as u64);
        let (chunks, _, visits) = cost_of(|| g.linearize());
        assert_topological(&g, &chunks);
        assert_eq!(
            chunks[0].feefrac,
            FeeFrac { fee: 150_501, size: 1_500 },
            "case {case} (parent at index {parent_at}, {visits} visits): first chunk is not the exact best chunk"
        );
        assert_eq!(chunks[0].txids.len(), 15, "case {case}: first chunk is parent + 14 children");
        let got = sorted_chunks(chunks.into_iter().map(|c| (c.txids, c.feefrac)).collect());
        assert_eq!(got, sorted_chunks(reference_linearize(&g)), "case {case}: linearization differs from the exhaustive scan");
    }
}

/// `DepGraph::from_cluster` must number a cluster's transactions the same way
/// every time. It used to take `HashSet` iteration order, which differs
/// between two sets holding the same txids (each draws its own hasher seed),
/// so two processes, or two builds in one process, searched the same cluster
/// in different index orders. Indices now follow txid order.
#[test]
fn from_cluster_assigns_indices_in_txid_order() {
    let txids: Vec<Hash256> = (0..16).map(|i| h(i, 0xf20c)).collect();
    let mut want = txids.clone();
    want.sort();
    let entries = HashMap::new();
    let parents = HashMap::new();
    for round in 0..8 {
        let set: HashSet<Hash256> = txids.iter().copied().collect();
        let g = DepGraph::from_cluster(&set, &entries, &parents);
        assert_eq!(g.idx_to_txid, want, "round {round}: indices not in txid order");
        for (i, t) in want.iter().enumerate() {
            assert_eq!(g.txid_to_idx[t], i);
        }
    }
}
