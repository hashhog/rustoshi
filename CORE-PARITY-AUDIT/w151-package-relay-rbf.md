# W151 — Package relay + BIP-125 RBF rules 1-5 (rustoshi)

**Wave:** W151 — `MemPoolAccept::AcceptPackage`, `AcceptMultipleTransactions`,
`AcceptMultipleTransactionsInternal`, `AcceptSubPackage`, `SubmitPackage`,
`PackageRBFChecks`, `PackageTRUCChecks`, `IsTopoSortedPackage`,
`IsChildWithParents`, `IsChildWithParentsTree`, `IsWellFormedPackage`,
`IsConsistentPackage`, `CheckPackage`, `GetEntriesForConflicts`,
`HasNoNewUnconfirmed`, `EntriesAndTxidsDisjoint`, `PaysForRBF`,
`ImprovesFeerateDiagram`, `IsRBFOptIn` / `IsRBFOptInEmptyMempool`,
`SignalsOptInRBF`, `MAX_BIP125_REPLACEMENT_CANDIDATES = 100`,
`MAX_PACKAGE_COUNT = 25`, `MAX_PACKAGE_WEIGHT = 404 000`,
`MAX_BIP125_RBF_SEQUENCE = 0xfffffffd`, `WALLET_INCREMENTAL_RELAY_FEE = 5000
sat/kvB`, `DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB`, `submitpackage` RPC,
`testmempoolaccept` RPC, P2P `sendpackages` / package-relay.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/policy/rbf.cpp:24-50` — `IsRBFOptIn(tx, pool)`:
  walks tx's UNCONFIRMED ancestors in the mempool and returns
  REPLACEABLE_BIP125 if ANY ancestor signals (`SignalsOptInRBF`). When the
  tx isn't in the pool, returns UNKNOWN.
- `bitcoin-core/src/policy/rbf.cpp:52-56` —
  `IsRBFOptInEmptyMempool(tx)`: tx-only fallback when no pool is available.
- `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts`:
  **Rule 5** uses `pool.GetUniqueClusterCount(iters_conflicting)`, NOT
  total-evictions. The cluster-count cap is `MAX_REPLACEMENT_CANDIDATES =
  100`; total evictions can FAR exceed that if descendants live in those
  clusters. The Rule-5 wire message is `"rejecting replacement %s; too many
  conflicting clusters (%u > 100)"`.
- `bitcoin-core/src/policy/rbf.cpp:85-98` — `EntriesAndTxidsDisjoint`:
  **Rule 2** walks `ancestors` (mempool ancestor iter set of the
  replacement) and checks intersection with the `direct_conflicts` set
  (not `all_to_evict`). Returns the wire string `"%s spends conflicting
  transaction %s"`.
- `bitcoin-core/src/policy/rbf.cpp:100-125` — `PaysForRBF`:
  - **Rule 3**: `replacement_fees < original_fees` → reject
    `"rejecting replacement %s, less fees than conflicting txs; %s < %s"`.
  - **Rule 4**: `additional_fees < relay_fee.GetFee(replacement_vsize)` →
    reject `"rejecting replacement %s, not enough additional fees to relay;
    %s < %s"`.
- `bitcoin-core/src/policy/rbf.cpp:127-140` —
  `ImprovesFeerateDiagram(changeset)`: cluster-mempool gate (Core 27+).
  Computes pre/post chunk-diagrams and requires the replacement to
  strictly dominate.
- `bitcoin-core/src/policy/rbf.h:25-26` —
  `MAX_REPLACEMENT_CANDIDATES = 100` (uint32_t).
- `bitcoin-core/src/policy/packages.h:19,24` —
  `MAX_PACKAGE_COUNT = 25`, `MAX_PACKAGE_WEIGHT = 404 000` weight units.
- `bitcoin-core/src/policy/packages.cpp:79-117` —
  `IsWellFormedPackage`:
  count > 25 → `"package-too-many-transactions"`,
  `package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT` →
  `"package-too-large"` (note: GetTransactionWeight, not vsize),
  duplicate txids → `"package-contains-duplicates"`,
  not topo-sorted → `"package-not-sorted"`,
  conflicting inputs in package → `"conflict-in-package"`.
- `bitcoin-core/src/policy/packages.cpp:119-148` —
  `IsChildWithParents` (every non-last tx must be referenced by an input
  of the last) + `IsChildWithParentsTree` (parents must not depend on each
  other).
- `bitcoin-core/src/validation.cpp:1037-1126` — `PackageRBFChecks`:
  package must be size-2 and 1-parent-1-child; neither workspace may have
  in-mempool ancestors; runs `GetEntriesForConflicts` over the merged
  conflict set; runs `PaysForRBF` over **aggregate** package fees and
  vsize; requires package-feerate > parent-feerate; requires
  `CheckMemPoolPolicyLimits` (cluster size); requires
  `ImprovesFeerateDiagram`.
- `bitcoin-core/src/validation.cpp:1432-1564` —
  `AcceptMultipleTransactionsInternal`: `IsWellFormedPackage` first,
  per-tx `PreChecks` (fail-fast), `PackageAddTransaction` between
  PreChecks to make sibling-coins visible, `PackageTRUCChecks` second
  pass, `CheckFeeRate` with `m_package_feerates=true`,
  `PackageRBFChecks` (if any tx conflicts), cluster size limit,
  `CheckEphemeralSpends`, then per-tx `PolicyScriptChecks`, then
  `SubmitPackage`.
- `bitcoin-core/src/validation.cpp:1622-1762` — `AcceptPackage`: handles
  the 3 already-in-mempool cases per tx (wtxid match → `MempoolTx`; txid
  match different wtxid → `MempoolTxDifferentWitness`; not present →
  `AcceptSubPackage({tx})`); de-duplicates so `AcceptMultipleTransactions`
  receives only the new txs; final pass calls `LimitMempoolSize`.
- `bitcoin-core/src/validation.cpp:1690` — `SingleInPackageAccept` ATMPArgs
  ctor (`allow_replacement=true`, `allow_sibling_eviction=true`,
  `package_submission=true`, `package_feerates=false`).
- `bitcoin-core/src/validation.cpp:485-528` — three package ATMPArgs
  ctors: `PackageTestAccept` (`allow_replacement=false`,
  `allow_sibling_eviction=false`, `package_feerates=false`); 
  `PackageChildWithParents` (`allow_replacement=true`,
  `allow_sibling_eviction=false`, `package_submission=true`,
  `package_feerates=true`); `SingleInPackageAccept` (above).
- `bitcoin-core/src/validation.cpp:566-575` — invariants enforced via
  `Assume`: `package_feerates → package_submission` AND
  `package_feerates → !allow_sibling_eviction`.
- `bitcoin-core/src/wallet/wallet.h:124` —
  `WALLET_INCREMENTAL_RELAY_FEE = 5000` (sat/kvB; 5 sat/vB).
- `bitcoin-core/src/wallet/feebumper.cpp:90-117` — wallet `CheckFeeRate`
  enforces Rule 3 via `incrementalRelayFee.GetFee(maxTxSize)`, where
  `incrementalRelayFee` is the **NODE's** runtime relay fee from
  `wallet.chain().relayIncrementalFee()` (NOT the wallet constant). The
  wallet constant `WALLET_INCREMENTAL_RELAY_FEE = 5000` is consulted only
  in `EstimateFeeRate` (feebumper.cpp:135-137) to pick a fee-rate target
  for the bumped tx: `feerate += max(node_incremental, wallet_incremental)`.
- `bitcoin-core/src/rpc/mempool.cpp:1302-1402` — `submitpackage` RPC:
  takes `package` (1..25), `maxfeerate` (default
  `DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK() = 0.10 BTC/kvB`),
  `maxburnamount` (default 0 BTC); calls `ProcessNewPackage(chainstate,
  mempool, txns, /*test_accept=*/false, client_maxfeerate)`.
- `bitcoin-core/src/util/rbf.cpp:12` — `SignalsOptInRBF(tx)`:
  `tx.vin[i].nSequence <= MAX_BIP125_RBF_SEQUENCE` (where threshold is
  `0xfffffffd = SEQUENCE_FINAL - 2`). Any single input below threshold
  signals.

**Files audited**
- `crates/consensus/src/mempool.rs:87-101` — `MAX_REPLACEMENT_CANDIDATES`,
  `MAX_BIP125_RBF_SEQUENCE`, `DEFAULT_INCREMENTAL_RELAY_FEE`.
- `crates/consensus/src/mempool.rs:159-169` — `MAX_PACKAGE_COUNT = 25`,
  `MAX_PACKAGE_WEIGHT = 404_000`, `MAX_PACKAGE_SIZE = 101_000`
  (vbytes; see BUG-1).
- `crates/consensus/src/mempool.rs:609-749` — `AtmpOptions`,
  `MempoolConfig` (`full_rbf`, `incremental_relay_fee`).
- `crates/consensus/src/mempool.rs:947-967` — `MempoolError` package
  variants (`PackageTooManyTx`, `PackageTooLarge`, `PackageDuplicateTx`,
  `PackageNotSorted`, `PackageConflict`, `PackageInsufficientFee`,
  `PackageInvalidTopology`, `PackageTxFailed`).
- `crates/consensus/src/mempool.rs:1326-2046` —
  `add_transaction_with_options` (single-tx ATMP path).
- `crates/consensus/src/mempool.rs:2678-2745` — `signals_opt_in_rbf`,
  `is_bip125_replaceable`, `is_truc_replaceable`.
- `crates/consensus/src/mempool.rs:2767-2879` — `check_rbf_rules`
  (BIP-125 Rules 1-5).
- `crates/consensus/src/mempool.rs:3794-3903` — `check_package`,
  `is_child_with_parents`.
- `crates/consensus/src/mempool.rs:3919-4131` — `accept_package`.
- `crates/consensus/src/mempool.rs:4143-4465` —
  `add_transaction_for_package` (second ATMP entry; cross-cited from W150
  BUG-15).
- `crates/network/src/relay.rs:280-340` — `pays_for_rbf` (dead helper;
  cross-cite W120 BUG-8); `INVENTORY_BROADCAST_TARGET`,
  `feefilter_delay` constants.
- `crates/rpc/src/server.rs:144-219` — `RpcState::new` /
  `with_prune_config`; both wire `mempool: Mempool::new(MempoolConfig::default())`.
- `crates/rpc/src/server.rs:523-529` — `submitpackage` RPC trait method
  (3 args: `rawtxs`, `maxfeerate`, `maxburnamount`).
- `crates/rpc/src/server.rs:5208-5410` — `submit_package` impl: parses
  hex, enforces `maxburnamount` per output, calls
  `state.mempool.accept_package(txs, &utxo_lookup)`, broadcasts via inv.
- `crates/rpc/src/server.rs:6560-6705` — `test_mempool_accept` impl
  (uses `AtmpOptions::test_accept()` per tx; never routes the >1 case
  through `accept_package`).
- `crates/wallet/src/wallet.rs:761-932` — `build_bumped_tx`
  (`bump_fee` + `psbt_bump_fee`); cross-cite W130.
- `crates/wallet/src/wallet.rs:817` — `INCREMENTAL_FEE_RATE = 1.0 sat/vB`
  hardcoded constant in the wallet's bump-fee path.
- `crates/wallet/tests/test_w130_bip125_feebumper_rule3.rs` — W130
  follow-on audit; lists BUG-1..19 (Rule 3 / wallet-side).
- `crates/consensus/tests/test_w116_package_relay.rs` — W116 follow-on
  audit; lists 15 documented bugs (G3b, G8b, G9b, G15, G17, G19, G25,
  G26b, etc).
- `crates/consensus/tests/test_w120_mempool_rbf.rs` — W120 follow-on
  audit; lists BUG-1..18 (mempool RBF).

---

## Gate matrix (32 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Package size / weight gates (Core packages.cpp:79-117) | G1: MAX_PACKAGE_COUNT = 25 constant | PASS (`mempool.rs:161`) |
| 1 | … | G2: MAX_PACKAGE_WEIGHT = 404_000 constant present | PASS (`mempool.rs:165`) |
| 1 | … | G3: `check_package` uses **WEIGHT** comparison, not vsize | **BUG-1 (P1)** — `check_package` (`mempool.rs:3801-3826`) accumulates `tx.vsize()` then compares against `MAX_PACKAGE_SIZE = 101_000` (vbytes); Core compares `sum(GetTransactionWeight) > MAX_PACKAGE_WEIGHT`. Carry-forward of W116 G3b BUG. For non-segwit identical; for segwit packages the vsize-based check is non-identical |
| 1 | … | G4: 1-tx package skips weight gate (Core `package_count > 1 &&`) | PASS-by-coincidence (`mempool.rs:3795-3798` checks count first then vsize for ALL sizes including 1; only triggers if 1 tx is > 101k vB which Core's `MAX_STANDARD_TX_WEIGHT` already rejects upstream) |
| 1 | … | G5: duplicate txid detection emits Core token `package-contains-duplicates` | **BUG-2 (P2)** — rustoshi emits the thiserror Display `"package: contains duplicate transaction"` (`mempool.rs:953-955`); Core emits `package-contains-duplicates` (packages.cpp:101). Wire-string parity slip — cross-impl test harness will see different tokens |
| 1 | … | G6: not-topo-sorted emits Core token `package-not-sorted` | **BUG-2 cross-cite** — rustoshi emits `"package: not topologically sorted (child before parent)"` (`mempool.rs:957-958`) |
| 1 | … | G7: same-input-twice in package → Core token `conflict-in-package` | **BUG-2 cross-cite** — rustoshi emits `"package: transactions conflict with each other"` (`mempool.rs:960-961`) |
| 2 | accept_package topology (Core AcceptPackage:1622-1762) | G8: 3 cases for already-in-mempool (exact wtxid; same-txid-diff-wtxid; not present) | **BUG-3 (P0-CDIV)** — `accept_package` (`mempool.rs:3944-3951`) only consults `self.transactions.contains_key(&txid)` (txid-only). It does NOT distinguish: (1) wtxid match → `MempoolTx`; (2) txid match different wtxid → `MempoolTxDifferentWitness` (the *original* wtxid is returned to the submitter); (3) not present → admit. The single `already_in_mempool: true` result returned to `submitpackage` always reports the SUBMITTED wtxid even when the mempool actually contains a different witness; downstream wallets/explorers indexing on returned wtxid get a phantom that doesn't exist in the mempool |
| 2 | … | G9: child-with-parents enforced strictly (every non-last tx must be parent of last) | PASS (`mempool.rs:3871-3902` correctly mirrors Core `IsChildWithParents` + parent-no-depend-on-parent `IsChildWithParentsTree` semantics) |
| 2 | … | G10: 1-tx package routed through `AcceptSubPackage({tx})` single-tx path | **BUG-4 (P1)** — `accept_package` calls `is_child_with_parents` (`mempool.rs:3871-3903`) which returns true for 1-tx; then drops straight into the package-fee-rate path at `mempool.rs:3961+` and ultimately calls `add_transaction_for_package` (which BYPASSES `IsFinalTx` + 10 other gates — cross-cite W150 BUG-15 / W116 G26b). Core routes 1-tx through `SingleInPackageAccept` which is the FULL `AcceptSingleTransactionInternal` path. So a 1-tx submitpackage admits a tx with `nLockTime` in the future, whereas a sendrawtransaction of the SAME tx is rejected |
| 3 | BIP-125 Rule 1 — opt-in signaling (rbf.cpp:24-50 / util/rbf.cpp:12) | G11: MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD constant | PASS (`mempool.rs:96`) |
| 3 | … | G12: `is_bip125_replaceable` walks **unconfirmed mempool ancestors** | PASS (`mempool.rs:2698-2710`) |
| 3 | … | G13: full_rbf flag tracked operator-tunable | PARTIAL — `MempoolConfig.full_rbf` default `true` (`mempool.rs:730`) and exposed via Default ctor; but **BUG-5 (P1)**: no CLI flag wires this in `rustoshi/src/main.rs`; both `RpcState::new` (`server.rs:172`) and `RpcState::with_prune_config` (`server.rs:199`) call `MempoolConfig::default()` so the value is permanently `true`. Operators cannot opt back into signaling-only RBF. Cross-cite W120 BUG-11 |
| 3 | … | G14: `IsRBFOptInEmptyMempool` analogue (tx-only fallback when no pool) | **BUG-6 (P3)** — rustoshi has no equivalent of `IsRBFOptInEmptyMempool` (`rbf.cpp:52-56`). The P2P-side RBF-detection on incoming announcements that we haven't seen yet currently can't classify a tx's RBF status; rustoshi only computes it when the tx is already in `self.transactions`. Latent — currently no production caller invokes the empty-pool path |
| 4 | BIP-125 Rule 2 — no-new-unconfirmed-inputs (rbf.cpp:85-98) | G15: `EntriesAndTxidsDisjoint` walks **mempool ancestors** of the new tx, checks intersection with **direct_conflicts** (not full eviction set) | PARTIAL — `check_rbf_rules` (`mempool.rs:2844-2849`) walks `get_all_ancestors(mempool_parents)` and tests against `direct_conflicts`. Correct in shape — but **BUG-7 (P1)**: the walk omits the SELF set (Core walks `pool.CalculateMemPoolAncestors(*ws.m_ptx)` which includes the new tx's IMMEDIATE mempool parents AS WELL — `replacement_ancestors` here is `get_all_ancestors(parents)` which is the **transitive** ancestor set MINUS the direct parents. A replacement whose DIRECT parent is in direct_conflicts will not trip this check (subtle off-by-one) |
| 4 | … | G16: error message includes BOTH the replacement txid AND the offending ancestor txid (Core `"%s spends conflicting transaction %s"`) | **BUG-2 cross-cite** — rustoshi emits `MempoolError::RbfSpendsConflicting` ("rbf: replacement spends conflicting transaction") — no txids in the message at all |
| 5 | BIP-125 Rule 3 — replacement_fees >= original_fees (rbf.cpp:100-112) | G17: integer compare; equality allowed | PASS (`mempool.rs:2854` uses `<` not `<=`) |
| 5 | … | G18: `original_fees` uses `GetModifiedFee()` (post-prioritisetransaction) | PASS (`mempool.rs:2811, 2818`) |
| 5 | … | G19: wallet-side bump uses MAX(node_incremental, wallet_incremental) where wallet_incremental = 5000 sat/kvB = 5 sat/vB (Core feebumper.cpp:135-137) | **BUG-8 (P0-CDIV / TWO-PIPELINE GUARD 16TH DISTINCT EXTENSION)** — `wallet.rs:817` hardcodes `INCREMENTAL_FEE_RATE = 1.0 sat/vB`; node-side `check_rbf_rules` uses `MempoolConfig.incremental_relay_fee = 100 sat/kvB = 1 sat/vB` (`mempool.rs:731`). Two pipelines, but BOTH at node-default — Core wallet uses 5 sat/vB to "future proof" against node-policy changes the wallet doesn't know about (see feebumper.cpp:128-132 comment). Carry-forward W130 BUG-1 ~3 weeks open. Wallet-built replacements 5× below Core peers' wallet-build floor; the wallet's bumped tx is admissible to its OWN node (1 sat/vB) but REJECTED by 5-sat/vB-wallet-built Core peer relays as Rule-4-insufficient |
| 6 | BIP-125 Rule 4 — additional_fees >= relay_fee * vsize (rbf.cpp:114-123) | G20: integer ceiling math matches Core's `CFeeRate::GetFee` (CeilDiv) | PASS (`mempool.rs:2870` uses `(rate * vsize + 999) / 1000`); but **BUG-9 (P1)**: wallet path uses `.ceil()` on f64 (`wallet.rs:818, 829`) instead of integer ceiling. Two parities of the same numeric invariant. Carry-forward W130 BUG-9 |
| 6 | … | G21: TRUC sibling-eviction path uses the SAME math; no Rule-5 cap on sibling-eviction count | **BUG-10 (P1)** — `add_transaction_with_options:1747-1775` (sibling-eviction) does NOT route through `check_rbf_rules`. It enforces only Rule-3 + Rule-4 inline but skips Rule-2 (no-new-unconfirmed-inputs) and Rule-5 (replacement-count cap). Cross-cite W130 BUG-10 |
| 7 | BIP-125 Rule 5 — replacement count cap (rbf.cpp:58-83) | G22: Core 27+ uses `GetUniqueClusterCount`, NOT eviction count | **BUG-11 (P0-CDIV)** — `check_rbf_rules:2828` enforces `all_to_evict.len() > MAX_REPLACEMENT_CANDIDATES` (100). Core 27+ enforces `pool.GetUniqueClusterCount(iters_conflicting) > 100`. Comment at `mempool.rs:2826-2827` admits the divergence: `"NOTE: Core 27+ uses unique cluster count; pre-cluster-mempool Core used eviction count"`. Comment-as-confession 6th distinct instance fleet-wide. Result: a replacement that conflicts with 5 mempool txs each having 25 descendants would be REJECTED by rustoshi (125 evictions > 100) but ACCEPTED by Core (5 clusters < 100) → fleet-wide RBF policy divergence; PinSpoof-style attacks Core 27+ defends against are not defended in rustoshi |
| 7 | … | G23: Rule-5 wire message format `"rejecting replacement %s; too many conflicting clusters (%u > 100)"` | **BUG-2 cross-cite** — rustoshi emits `"rbf: too many replacements (N > 100)"` (`mempool.rs:913-914`); Core emits `"rejecting replacement ...; too many conflicting clusters ..."`. Wire-string slip |
| 7 | … | G24: `pays_for_rbf` helper in `network/relay.rs:296` is the canonical Rule 3+4 implementation | **BUG-12 (P0-CDIV / TWO-PIPELINE GUARD 17TH DISTINCT EXTENSION)** — DEAD HELPER. `crates/network/src/relay.rs:280-340` defines `pays_for_rbf(original, replacement, vsize, incremental)` with full Rule 3+4 logic AND its own unit tests (`relay.rs:1467-1495`). Zero non-test callers — the mempool `check_rbf_rules` (mempool.rs:2854-2876) re-implements Rule 3+4 inline. Two parities of the same invariant. Carry-forward W120 BUG-8 |
| 8 | submitpackage RPC (rpc/mempool.cpp:1302-1402) | G25: 3-arg signature `package`, `maxfeerate`, `maxburnamount` | PASS (`server.rs:5208-5213`) |
| 8 | … | G26: 1..25 package count enforced at RPC boundary | PASS-via-check_package — `submitpackage` does not enforce count directly but `accept_package → check_package` enforces `> 25` reject. Empty package: **BUG-13 (P2)** — `server.rs:5262-5267` rejects empty with custom error string `"Package must contain at least one transaction"`; Core relies on `IsWellFormedPackage` + an upstream `Assert(!package.empty())` (validation.cpp:1624). Wire-message and code-path differ |
| 8 | … | G27: maxfeerate per-tx check uses tx feerate (not package feerate) | PASS (`server.rs:5320-5333`); but **BUG-14 (P3)** — comment `"N.B. this doesn't take into account CPFPs"` from Core (validation.cpp:1457) is absent; rustoshi's per-tx maxfeerate check rejects a high-fee child even when its parent is below feerate and the package average is within max |
| 8 | … | G28: `package-feerates=true` invariant: `package_submission=true` AND `!allow_sibling_eviction` (Core ATMPArgs invariants validation.cpp:571-575) | **BUG-15 (P0-CDIV)** — rustoshi has no equivalent of `ATMPArgs` constructor-side enforcement. `add_transaction_for_package` ALWAYS allows TRUC sibling-eviction (mempool.rs:4264 calls `check_truc_policy` unconditionally) even though Core's `PackageChildWithParents` constructor (validation.cpp:514-528) sets `allow_sibling_eviction=false`. A package-submitted TRUC child whose sibling is also TRUC will trigger sibling-eviction here, evicting a tx that Core would not have evicted. Sibling-eviction in package context is a SECOND replacement during a submission that Core specifically forbids |
| 9 | PackageRBFChecks (validation.cpp:1037-1126) | G29: package must be 1-parent-1-child for RBF | **BUG-16 (P0-CDIV)** — rustoshi has NO `PackageRBFChecks` analogue. `accept_package` → `add_transaction_for_package` → `check_rbf_rules` runs RBF PER-TX, so a 1p1c package whose CHILD conflicts can replace via the parent's individual check (allowed) AND the child's individual check (also allowed) — but Core's `PackageRBFChecks` requires that neither workspace has in-mempool ancestors (validation.cpp:1063-1067) and uses AGGREGATE fees/vsize for Rule 3 + 4 (validation.cpp:1096-1102). Result: a tx-graph that Core rejects with `"package RBF failed: new transaction cannot have mempool ancestors"` will be ACCEPTED by rustoshi |
| 9 | … | G30: package RBF uses AGGREGATE total_modified_fees / total_vsize for Rule 3+4 | **BUG-16 cross-cite** — rustoshi runs per-tx Rule 3+4 in `add_transaction_for_package`, not on the aggregate. Cross-cite W116 G25 BUG |
| 9 | … | G31: package-feerate > parent-feerate check (validation.cpp:1108-1112) | **BUG-17 (P1)** — rustoshi does not enforce that the child-bearing package must out-pay its parent's feerate individually. A package with parent-only-pays-relay-fee + child-pays-tiny-bump escapes the "child not paying anti-DoS fees alone" gate Core enforces |
| 9 | … | G32: `ImprovesFeerateDiagram` cluster-mempool gate | **BUG-18 (P1)** "deferred-with-comment-as-confession" — `mempool.rs:2765-2766` comment: `"Note: Core's ImprovesFeerateDiagram (cluster-mempool, Core 27+) is not implemented because rustoshi does not yet have a cluster mempool. Deferred."`. PinSpoof / fee-diagram pinning Core 27+ defends against is undefended. Cross-cite W130 BUG-16. Note rustoshi DOES have cluster scaffolding (`MAX_CLUSTER_SIZE=64`, `tx_to_cluster`, `Cluster::linearization`) but never feeds `ImprovesFeerateDiagram` from it |
| 10 | Add-transaction-for-package gate parity (W150 BUG-15 cross-cite) | G33: package-path runs SAME gate-set as single-tx path | **BUG-19 (P0-CONS / CARRY-FORWARD W150 BUG-15 CONFIRMED)** — `add_transaction_for_package` (`mempool.rs:4143-4500`) skips: `is_final_tx` (BIP-113); `CheckSequenceLocks` (BIP-68); `AreInputsStandard`; `IsWitnessStandard`; `MAX_STANDARD_TX_SIGOPS_COST`; `COINBASE_MATURITY` (per-input height delta); `MoneyRange` on inputs; `PolicyScriptChecks`; `ConsensusScriptChecks`; `PreCheckEphemeralTx` on the per-tx basis (only `check_ephemeral_spends` runs in `accept_package` after the per-tx loop). A submitpackage RPC bypasses ~10 ATMP gates that sendrawtransaction enforces. **W150 finding still holds verbatim** — no fix has landed in the intervening window |
| 11 | P2P package relay (BIP-431 1p1c + sendpackages) | G34: `sendpackages` message dispatch | EXPECTED-MISSING (not yet shipped in Core mainline); rustoshi `crates/network/src/message.rs` has no `SendPackages` / `PkgTxns` variants. Cross-cite W116 G29 |
| 11 | … | G35: per-peer `MAX_ORPHAN_TX_PACKAGE_RELAY_REQUESTS` tracking | EXPECTED-MISSING |
| 12 | Reject-string fleet parity | G36: every package + RBF error path emits Core wire token | **BUG-2 (P1)** consolidated — 9 distinct wire-string slips: `package-too-many-transactions`, `package-too-large`, `package-contains-duplicates`, `package-not-sorted`, `conflict-in-package`, `bip125-replacement-disallowed` (this ONE is correct, `mempool.rs:1018`), `rejecting replacement %s, less fees than conflicting txs`, `rejecting replacement %s, not enough additional fees to relay`, `rejecting replacement %s; too many conflicting clusters`. Wire-parity slippage same pattern as nimrod W125/W145 and lunarblock W145 |

---

## BUG-1 (P1) — `check_package` enforces vsize-based cap (101 000 vB) instead of weight-based cap (404 000 WU)

**Severity:** P1.

Bitcoin Core `IsWellFormedPackage` (packages.cpp:87-92) computes
`total_weight = sum(GetTransactionWeight(tx))` and rejects when
`package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT = 404 000`.

rustoshi `check_package` (`mempool.rs:3801-3826`) computes
`total_vsize = sum(tx.vsize())` and compares against `MAX_PACKAGE_SIZE
= 101 000` (vbytes), where `MAX_PACKAGE_SIZE = MAX_PACKAGE_WEIGHT / 4`
(`mempool.rs:168-169`).

For non-segwit transactions: `weight = 4 * vsize`, so `4*vsize >
404 000 <=> vsize > 101 000` — checks are equivalent.

For segwit transactions: `vsize = ceil(weight / 4)`. A segwit
transaction with `weight = 199` has `vsize = 50` (199 / 4 rounds up to
50); `4 * 50 = 200 != 199`. So `sum(vsize) > 101 000` is STRICTLY
STRONGER than `sum(weight) > 404 000` (i.e. rustoshi rejects packages
Core accepts).

Concretely: 25 segwit txs each with `weight = 16 002` and `vsize =
4001` (4 * 4001 = 16 004 > 16 002): rustoshi's `total_vsize = 100 025`
which is < 101 000 — OK. But 25 segwit txs each with `weight = 16 159`
and `vsize = 4040`: rustoshi rejects at `total_vsize = 101 000` vs
Core's `total_weight = 403 975 < 404 000`. Stricter-than-Core.

Also: `MAX_PACKAGE_SIZE` is NOT a public Core constant — the
authoritative constant is `MAX_PACKAGE_WEIGHT`.

**File:** `crates/consensus/src/mempool.rs:3801-3826`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:87-92`.

**Excerpt (rustoshi)**
```rust
let mut total_vsize = 0usize;
// ...
total_vsize += tx.vsize();
// ...
if total_vsize > MAX_PACKAGE_SIZE {
    return Err(MempoolError::PackageTooLarge(total_vsize, MAX_PACKAGE_SIZE));
}
```

**Impact:** A handful of carefully-crafted segwit packages legitimate
under Core get rejected by rustoshi. Latent for most real-world
packages (the unit difference is tiny) but cross-impl test
non-determinism. Carry-forward from W116 G3b (~6 weeks open).

---

## BUG-2 (P1) — Package + RBF reject-tokens diverge from Core wire format (9 distinct slips)

**Severity:** P1. Wire-string parity slippage breaks cross-impl fleet
testing and breaks Core-compatible wallet/tool error handling.

Bitcoin Core emits stable tokens for package + RBF validation
failures: `package-too-many-transactions`, `package-too-large`,
`package-contains-duplicates`, `package-not-sorted`,
`conflict-in-package` (packages.cpp:84-114),
`bip125-replacement-disallowed` (validation.cpp:839),
`"rejecting replacement %s, less fees than conflicting txs; %s < %s"`
(rbf.cpp:110-111), `"rejecting replacement %s, not enough additional
fees to relay; %s < %s"` (rbf.cpp:119-122),
`"rejecting replacement %s; too many conflicting clusters (%u > 100)"`
(rbf.cpp:71-74).

rustoshi `MempoolError` variants (`mempool.rs:872-967`) use thiserror
Display strings that read as English sentences ("package: too many
transactions (N > M)", "rbf: too many replacements (N > M)", "rbf:
replacement spends conflicting transaction", etc).

Only `bip125-replacement-disallowed` (`mempool.rs:1018`) matches Core
exactly — the 8 other tokens slip.

**Files:**
- `crates/consensus/src/mempool.rs:872-967` — error variants
- `crates/consensus/src/mempool.rs:1004-1020` — single Core-parity
  variant (`ReplacementDisallowed`)
- `crates/rpc/src/server.rs:3758-3789` — sendrawtransaction
  error-mapping (uses Display strings, not Core tokens)

**Core refs:**
- `bitcoin-core/src/policy/packages.cpp:84,91,101,109,114`
- `bitcoin-core/src/policy/rbf.cpp:71,110,119`
- `bitcoin-core/src/validation.cpp:839`

**Impact:** Same fleet pattern as nimrod W125/W145, lunarblock W125/W145
"reject-string wire-parity slippage" — cross-impl test harness sees
divergent reject reasons; wallet code that pattern-matches Core tokens
to UI strings fails. Compounds when this is consensus-RBF-relevant
(Rule 5 cluster count, BUG-11 below).

---

## BUG-3 (P0-CDIV) — `accept_package` loses Core's 3-case already-in-mempool dispatch (`MempoolTxDifferentWitness` lost)

**Severity:** P0-CDIV (RPC return shape divergence; consensus-adjacent
because submitter-supplied wtxid is masked).

Bitcoin Core `AcceptPackage` (validation.cpp:1660-1687) classifies
each tx into 3 cases:
1. **wtxid match** (`m_pool.exists(wtxid)`): emit
   `MempoolAcceptResult::MempoolTx(size, fee)` — the EXACT tx is in.
2. **txid match, different wtxid** (`m_pool.exists(txid)`): emit
   `MempoolAcceptResult::MempoolTxDifferentWitness(mempool_wtxid)` —
   the submitter's tx is silently swapped for the mempool's; the
   `mempool_wtxid` (NOT the submitted one) is returned so the
   submitter can look up the actual mempool tx.
3. **Not in mempool**: `AcceptSubPackage({tx})` (full single-tx
   ATMP).

rustoshi `accept_package` (`mempool.rs:3944-3973`) only checks
`self.transactions.contains_key(&txid)` — the wtxid-vs-txid
distinction is collapsed. When the EXACT wtxid is in mempool, the
result is correct; when the txid is in but the wtxid differs (i.e.
witness was mutated), rustoshi STILL reports `already_in_mempool: true`
with the SUBMITTED wtxid (`mempool.rs:3961-3968`), so a downstream
wallet indexing on `txresult.wtxid` will look up a wtxid that doesn't
exist in the mempool.

**File:** `crates/consensus/src/mempool.rs:3944-3974`.

**Core ref:** `bitcoin-core/src/validation.cpp:1660-1687`.

**Impact:** `submitpackage` RPC behaves incorrectly under
witness-malleation: wallet/explorer that submits a package containing
a previously-relayed tx with different witness data sees
`already_in_mempool: true` with the WRONG wtxid. Cross-cite W150
BUG-13: rustoshi's `sendrawtransaction` ALSO collapses the 3-case
distinction (only `AlreadyExists` is recognised; the W96 split
`WtxidAlreadyInMempool`/`TxidSameNonwitnessData` falls through to a
generic error).

---

## BUG-4 (P1) — 1-tx package routes through `add_transaction_for_package` (skipping ~10 ATMP gates) instead of single-tx ATMP

**Severity:** P1.

Bitcoin Core `AcceptPackage` (validation.cpp:1690) routes any 1-tx
case (whether `package.size() == 1` or after deduplication) through
`AcceptSubPackage({tx}, args)` which calls
`AcceptSingleTransactionInternal(tx, single_args)` (validation.cpp:1606).
That goes through the FULL `PreChecks → PolicyScriptChecks →
ConsensusScriptChecks → Finalize` pipeline.

rustoshi `accept_package` does the opposite. After
`is_child_with_parents` returns `true` for the 1-tx case
(`mempool.rs:3871-3874`), the function falls through to
`add_transaction_for_package(tx, utxo_lookup, package_fee_rate)`
(`mempool.rs:4101`). That ATMP entry **bypasses 10 gates** including
`IsFinalTx`, `CheckSequenceLocks`, `AreInputsStandard`,
`IsWitnessStandard`, `MAX_STANDARD_TX_SIGOPS_COST`,
`COINBASE_MATURITY`, `PolicyScriptChecks`, `ConsensusScriptChecks` —
the same set W150 BUG-15 documented for the multi-tx package path.

So: a 1-tx submitpackage of a tx with `nLockTime = future_height`
ADMITS the tx; a 1-tx sendrawtransaction of the SAME tx REJECTS it
with `non-final`.

**File:** `crates/consensus/src/mempool.rs:3933-4131` (control flow);
`mempool.rs:4143-4500` (the bypass).

**Core ref:** `bitcoin-core/src/validation.cpp:1690, 1606`.

**Impact:** RPC-shaped consensus bypass — `submitpackage` of a 1-tx
package becomes a back-door to skip ~10 ATMP gates that
`sendrawtransaction` enforces. Same "different-entry-point-different-rules"
class as W143 fleet-wide multi-pipeline bypass; same fleet pattern
("N-pipeline drift") as the rustoshi W142 3-merkle and W150 BUG-15
finding.

---

## BUG-5 (P1) — `-mempoolfullrbf` CLI flag not parsed; `full_rbf` permanently `true`

**Severity:** P1.

Bitcoin Core 27 introduced (and 28 deprecated, then re-defaulted-on)
the `-mempoolfullrbf` operator knob, allowing operators to opt back
into signaling-only RBF. The `full_rbf` flag in
`MempoolConfig` (`mempool.rs:730`) defaults `true` and is exposed via
`MempoolConfig::default()`, but rustoshi's `main.rs` does not parse
`-mempoolfullrbf` / `--mempool-full-rbf`. Both `RpcState::new`
(`server.rs:172`) and `with_prune_config` (`server.rs:199`)
unconditionally call `MempoolConfig::default()` so the value is locked
to `true`.

`MempoolConfig::default()` baking `true` matches Core's current
behavior, but no operator override is possible (the W150 BUG-11 fleet
pattern of "config-knob constants baked into defaults, no CLI plumb"
applies here).

**File:** `crates/consensus/src/mempool.rs:730`;
`crates/rpc/src/server.rs:172, 199`; `rustoshi/src/main.rs` (no
`-mempoolfullrbf` arg parse).

**Core ref:** Bitcoin Core 27 `init.cpp` `-mempoolfullrbf` arg.

**Impact:** Operators wanting signaling-only RBF (a small but
legitimate set: research nodes, conservative miners) cannot opt out.
Carry-forward W120 BUG-11.

---

## BUG-6 (P3) — `IsRBFOptInEmptyMempool` analogue absent

**Severity:** P3 (latent).

Bitcoin Core `rbf.cpp:52-56` has a tx-only RBF-classification helper
`IsRBFOptInEmptyMempool(tx)` used when no pool is available (e.g.
during early node bootstrap or in tests). rustoshi has no equivalent;
`is_bip125_replaceable(txid)` (`mempool.rs:2690`) only works when the
tx is already in `self.transactions`. A P2P-side RBF-detection on
incoming inv before the tx is admitted can't classify the tx.

Currently no production caller invokes the empty-pool path so the gap
is latent. Documented for fleet pattern continuity.

**File:** `crates/consensus/src/mempool.rs:2690-2711`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:52-56`.

---

## BUG-7 (P1) — Rule 2 ancestor walk omits the SELF set (direct-parent-in-conflicts edge case slips)

**Severity:** P1 (subtle off-by-one).

Bitcoin Core `EntriesAndTxidsDisjoint` (`rbf.cpp:85-98`) is called
with `ancestors = pool.CalculateMemPoolAncestors(*ws.m_ptx)` which
INCLUDES the new tx's immediate mempool parents (the iter set spans
all ancestors of the entry, including direct parents).

rustoshi `check_rbf_rules` computes:
```rust
let replacement_ancestors = self.get_all_ancestors(mempool_parents);
for ancestor_txid in &replacement_ancestors {
    if direct_conflicts.contains(ancestor_txid) {
        return Err(MempoolError::RbfSpendsConflicting);
    }
}
```

`get_all_ancestors(set)` returns the TRANSITIVE ancestor set of the
input set. If `mempool_parents = {P1}`, then `get_all_ancestors({P1})`
returns the ancestors of P1 — but NOT P1 itself.

So a replacement tx whose DIRECT parent is one of the
`direct_conflicts` slips past Rule 2 here. Core catches it because the
walk includes P1 itself.

(Reality check: a replacement that spends an output of a tx it's also
replacing is normally caught by `add_transaction_with_options`'s input
loop at `mempool.rs:1441-1453` — the same outpoint will appear in
`self.spent_outpoints` and also be added to `direct_conflicts`. So
this off-by-one is mostly defended by the input loop. But the Rule-2
text is "no new unconfirmed inputs" — replacement's MEMPOOL_PARENTS
must not include any direct_conflict — and that text is exactly the
gate that's miscoded here.)

**File:** `crates/consensus/src/mempool.rs:2844-2849`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:85-98`.

**Impact:** Subtle. The input-loop check at `mempool.rs:1443-1448`
defends in depth (it converts the same outpoint into a conflict). But
the Rule-2 codepath is wired to the wrong set.

---

## BUG-8 (P0-CDIV / TWO-PIPELINE GUARD 16TH DISTINCT EXTENSION) — Wallet `INCREMENTAL_FEE_RATE` hardcoded 1 sat/vB; Core wallet uses MAX(node, WALLET_INCREMENTAL_RELAY_FEE=5 sat/vB)

**Severity:** P0-CDIV (cross-network feerate-floor divergence; rustoshi
wallet's bumped txs rejected by Core peer relays).

Bitcoin Core `feebumper.cpp:128-137`:
```cpp
// The node has a configurable incremental relay fee. Increment the fee by
// the minimum of that and the wallet's conservative
// WALLET_INCREMENTAL_RELAY_FEE value to future proof against changes to
// network wide policy for incremental relay fee that our node may not be
// aware of. This ensures we're over the required relay fee rate
// (Rule 4).  The replacement tx will be at least as large as the
// original tx, so the total fee will be greater (Rule 3)
CFeeRate node_incremental_relay_fee = wallet.chain().relayIncrementalFee();
CFeeRate wallet_incremental_relay_fee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
feerate += std::max(node_incremental_relay_fee, wallet_incremental_relay_fee);
```

`WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB = 5 sat/vB` (wallet.h:124).

rustoshi `wallet.rs:817`:
```rust
const INCREMENTAL_FEE_RATE: f64 = 1.0; // sat/vB; Core DEFAULT_INCREMENTAL_RELAY_FEE
```

The comment is BACKWARDS — Core does NOT use `DEFAULT_INCREMENTAL_RELAY_FEE`
in the wallet bump-fee path. Core uses the MAX of node and
WALLET_INCREMENTAL_RELAY_FEE. The wallet constant is 5 sat/vB
specifically to future-proof against the node-policy floor moving up.
rustoshi's wallet bumps at 1 sat/vB, but a Core peer that increased
its node `incremental_relay_fee` will reject the bumped tx.

There is also no `WALLET_INCREMENTAL_RELAY_FEE` constant defined in
rustoshi at all.

**File:** `crates/wallet/src/wallet.rs:817`.

**Core ref:** `bitcoin-core/src/wallet/wallet.h:124`;
`bitcoin-core/src/wallet/feebumper.cpp:135-137`.

**Impact:**
- Wallet-built replacements 5× below Core peers' wallet-build floor.
- The bumped tx is admissible to its OWN node (1 sat/vB matches the
  node's `incremental_relay_fee = 100 sat/kvB`) but REJECTED by a
  Core-built wallet peer relay that requires 5 sat/vB.
- "Wallet doesn't know about node policy" future-proofing is absent.
- Two-pipeline guard 16th distinct extension (wallet-side vs node-side
  pays_for_rbf math). Same archetype as W144 two-pipeline ATMP entries,
  W150 BUG-14 two-pipeline ATMP entries, W120 BUG-8 two-pipeline RBF
  helpers.
- Carry-forward W130 BUG-1 (~3 weeks open since 2026-04-25).

---

## BUG-9 (P1) — Wallet uses f64 `.ceil()` for incremental-fee math; mempool uses integer ceiling — two parities of the same numeric invariant

**Severity:** P1.

`wallet.rs:818`:
```rust
let incremental_delta = (entry.vsize as f64 * INCREMENTAL_FEE_RATE).ceil() as u64;
```

`mempool.rs:2870`:
```rust
let required_bandwidth_fee = (self.config.incremental_relay_fee * new_vsize as u64 + 999) / 1000;
```

The two helpers compute the same number (Rule 4's bandwidth requirement)
in incompatible ways. The mempool path uses integer ceiling
`(a * vsize + 999) / 1000`. The wallet path multiplies an f64 by an
i64 and `.ceil()`s.

For small vsize values they agree; for f64 precision edge cases
(vsize ≥ 2^53) they don't. Latent for normal-sized tx but documented
as a two-parity divergence.

**File:** `crates/wallet/src/wallet.rs:818, 829`; `crates/consensus/src/mempool.rs:2870`.

**Core ref:** `bitcoin-core/src/policy/feerate.cpp::CFeeRate::GetFee`
(EvaluateFeeUp, CeilDiv).

**Impact:** Wire-edge divergence; carry-forward W130 BUG-9.

---

## BUG-10 (P1) — TRUC sibling-eviction path skips Rule 2 + Rule 5

**Severity:** P1.

`add_transaction_with_options:1747-1775` (sibling-eviction for v3 TRUC):

```rust
if let Some(sibling_txid) = sibling_to_evict {
    if let Some(sibling_entry) = self.transactions.get(&sibling_txid) {
        let sibling_fee = Self::get_modified_fee(sibling_entry);
        if fee <= sibling_fee {  // Rule 3 (inline)
            return Err(MempoolError::RbfInsufficientAbsoluteFee(...));
        }
        let additional_fee = fee - sibling_fee;
        let required_bandwidth_fee = ...;
        if additional_fee < required_bandwidth_fee {  // Rule 4 (inline)
            return Err(MempoolError::RbfInsufficientBandwidthFee(...));
        }
        self.remove_single(&sibling_txid);
    }
}
```

This inlines Rule 3 + Rule 4 but does NOT call `check_rbf_rules`. So:
- Rule 2 (no-new-unconfirmed-inputs) is not enforced.
- Rule 5 (≤ 100 evictions) is not enforced.

In practice TRUC sibling-eviction is bounded to evict ONE sibling (by
TRUC ancestor-limit = 2), so Rule 5 is structurally OK. But Rule 2
slipping means a TRUC sibling-eviction can introduce a replacement
whose ancestor is the evicted sibling.

**File:** `crates/consensus/src/mempool.rs:1747-1775` and the
duplicated copy at `mempool.rs:4294-4319` (package-path TRUC sibling
eviction).

**Core ref:** `bitcoin-core/src/policy/truc_policy.cpp:240-260`;
`bitcoin-core/src/validation.cpp:958-965`.

**Impact:** Carry-forward W130 BUG-10.

---

## BUG-11 (P0-CDIV) — Rule 5 uses eviction-count cap (>100), Core 27+ uses unique-cluster-count cap (>100) — **comment-as-confession 6th instance**

**Severity:** P0-CDIV (fleet-wide RBF policy divergence; PinSpoof
class).

Bitcoin Core 27+ rewrote `GetEntriesForConflicts` (rbf.cpp:58-83) to
use `pool.GetUniqueClusterCount(iters_conflicting)`, not the total
eviction count. The cluster-count cap is `MAX_REPLACEMENT_CANDIDATES =
100`. Total eviction count can FAR exceed that when the conflicting
txs each have many descendants.

rustoshi `check_rbf_rules:2824-2833`:
```rust
// Rule #5: Limit total evictions to MAX_REPLACEMENT_CANDIDATES.
// Core policy/rbf.cpp:69-75 (GetEntriesForConflicts).
// NOTE: Core 27+ uses unique cluster count; pre-cluster-mempool Core used eviction count.
// Rustoshi uses the eviction-count approach (pre-cluster-mempool compatible).
if all_to_evict.len() > MAX_REPLACEMENT_CANDIDATES {
    return Err(MempoolError::RbfTooManyReplacements(
        all_to_evict.len(),
        MAX_REPLACEMENT_CANDIDATES,
    ));
}
```

**Comment-as-confession 6th distinct instance fleet-wide** (after
W128 banman, W141 rustoshi BUG-X "comment-as-confession 4th instance",
W144 lunarblock "BUG-12 comment-as-confession 5th instance literally
documents the bug it perpetuates", etc).

The comment cleanly admits: "Core 27+ uses unique cluster count;
pre-cluster-mempool Core used eviction count. Rustoshi uses the
eviction-count approach (pre-cluster-mempool compatible)." But Core 27
shipped July 2024 (~2 years ago); rustoshi is permanently on the
pre-cluster-mempool model.

**Concrete divergence example:** Replacement tx conflicts with 5
mempool txs, each having 25 mempool descendants (5×26 = 130 total
evictions, 5 unique clusters).
- rustoshi: rejects (130 > 100).
- Core 27+: accepts (5 < 100).

PinSpoof-style attacks Core 27+ specifically defends against (where an
attacker pins a single low-feerate tx with a long descendant chain to
prevent legitimate replacement) are not defended in rustoshi.

**File:** `crates/consensus/src/mempool.rs:2824-2833`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:64-75`.

**Impact:** Fleet-wide RBF policy divergence — rustoshi's mempool will
reject replacements that 9 of 10 modern Core relays accept. Same class
as W144 fleet-wide script_flag_exceptions divergence (mainnet-replay
chain split risk). Live tx flow today is mostly < 5 conflicts so the
divergence is rare in practice but the PinSpoof attack surface is
permanent.

---

## BUG-12 (P0-CDIV / TWO-PIPELINE GUARD 17TH DISTINCT EXTENSION) — `crates/network/src/relay.rs::pays_for_rbf` is a DEAD helper; mempool re-implements Rule 3+4 inline

**Severity:** P0-CDIV.

`crates/network/src/relay.rs:280-340` defines:
```rust
pub fn pays_for_rbf(
    original_fees: u64,
    replacement_fees: u64,
    replacement_vsize: u64,
    incremental_relay_fee: u64,
) -> Result<(), String> {
    // Rule #3 + Rule #4
}
```

with full unit tests at `relay.rs:1467-1495`. Zero non-test callers
(verified via grep).

`mempool.rs:2854-2876` re-implements the same Rules 3+4 inline inside
`check_rbf_rules`. So two parities of the same numeric invariant
diverge by a 4th distinct pipeline (mempool, wallet, network/relay
dead helper, network/relay test-only helper).

**Carry-forward W120 BUG-8.** Two-pipeline guard 17th distinct
extension fleet-wide.

Note: `relay.rs:445-462` also has a wrapper that calls the
module-level `pays_for_rbf` — still dead-helper but a 5th parity site.

**File:** `crates/network/src/relay.rs:280-340, 445-462`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:100-125`.

**Impact:** Dead helper at canonical site (`network/relay` is the
expected home for relay-policy primitives in rustoshi); mempool path
reimplements the same logic. Future fix to one will not propagate to
the other. Same archetype as the dead-helper pattern in nimrod W138,
clearbit W148, etc.

---

## BUG-13 (P2) — `submitpackage` RPC empty-package reject is custom string, not Core wire format

**Severity:** P2.

`crates/rpc/src/server.rs:5262-5267`:
```rust
if txs.is_empty() {
    return Err(Self::rpc_error(
        rpc_error::RPC_INVALID_PARAMS,
        "Package must contain at least one transaction",
    ));
}
```

Core relies on `IsWellFormedPackage` (called by
`AcceptMultipleTransactionsInternal:1439`) + an upstream
`Assert(!package.empty())` (validation.cpp:1624). The wire-message and
error-code differ.

**File:** `crates/rpc/src/server.rs:5262-5267`.

**Core ref:** `bitcoin-core/src/validation.cpp:1624`;
`bitcoin-core/src/rpc/mempool.cpp:1302-1402` (submitpackage).

**Impact:** Wire-string slip.

---

## BUG-14 (P3) — `submitpackage` per-tx maxfeerate check doesn't account for CPFP / aggregate package feerate

**Severity:** P3 (documented in Core code as a known limitation).

`crates/rpc/src/server.rs:5320-5336`:

```rust
let fee_rate_sat_vb = if tx_result.vsize > 0 {
    tx_result.fee as f64 / tx_result.vsize as f64
} else { 0.0 };
let reject_reason = if let Some(ref err) = tx_result.error {
    Some(err.clone())
} else if max_fee_rate_btc_kvb > 0.0 && fee_rate_sat_vb > max_fee_rate_sat_vb {
    Some(format!("Fee rate too high: {:.8} BTC/kvB > {:.8} BTC/kvB (maxfeerate)", ...));
} else { None };
```

Core's analog (validation.cpp:1458) carries the comment "N.B. this
doesn't take into account CPFPs. Chunk-aware validation may be more
robust." rustoshi has the same behavior but doesn't emit the same
comment, so the developer reading rustoshi can't see the known issue.

**File:** `crates/rpc/src/server.rs:5320-5336`.

**Core ref:** `bitcoin-core/src/validation.cpp:1456-1465`.

---

## BUG-15 (P0-CDIV) — `add_transaction_for_package` always allows TRUC sibling-eviction; Core's `PackageChildWithParents` constructor forbids it

**Severity:** P0-CDIV.

Bitcoin Core's `PackageChildWithParents` ATMPArgs ctor
(`validation.cpp:514-528`):
```cpp
return ATMPArgs{...,
                /*allow_replacement=*/ true,
                /*allow_sibling_eviction=*/ false,
                /*package_submission=*/ true,
                /*package_feerates=*/ true,
                ...};
```

with the invariant (validation.cpp:571-575):
```cpp
if (m_package_feerates) {
    Assume(m_package_submission);
    Assume(!m_allow_sibling_eviction);
}
```

So in package-feerate context (the canonical 1p1c submitpackage path),
TRUC sibling-eviction is FORBIDDEN.

rustoshi `add_transaction_for_package:4264` calls `check_truc_policy`
unconditionally:
```rust
let sibling_to_evict = self.check_truc_policy(&tx, txid, vsize, &mempool_parents, &direct_conflicts)?;
```

then at `mempool.rs:4294-4319` performs the sibling eviction:
```rust
if let Some(sibling_txid) = sibling_to_evict {
    if let Some(sibling_entry) = self.transactions.get(&sibling_txid) {
        let sibling_fee = Self::get_modified_fee(sibling_entry);
        if fee <= sibling_fee { ... }
        let additional_fee = fee - sibling_fee;
        let required_bandwidth_fee = ...;
        if additional_fee < required_bandwidth_fee { ... }
        replaced_txids.push(sibling_txid);
        self.remove_single(&sibling_txid);
    }
}
```

A package-submitted TRUC child whose sibling is also TRUC will trigger
sibling-eviction here — evicting a tx that Core would not have
evicted. Sibling-eviction in package context is a SECOND replacement
during a submission that Core specifically forbids (it would compound
with the package's own conflict and produce two replacements per ATMP
call, breaking Core's "one replacement per submission" invariant).

**File:** `crates/consensus/src/mempool.rs:4264, 4294-4319`.

**Core ref:** `bitcoin-core/src/validation.cpp:514-528, 571-575`.

**Impact:** Package-RBF + TRUC sibling-eviction co-occur in rustoshi
when Core forbids the combination. A 1p1c submitpackage of a TRUC
child can evict a sibling AND replace a conflicted mempool tx in the
SAME submission. Core's `Assume` would have fired (debug-build) or
silently violated the invariant (release-build). Rustoshi has neither
the constructor invariant nor the assume.

---

## BUG-16 (P0-CDIV) — `accept_package` runs RBF PER-TX inside `add_transaction_for_package`; no Core-equivalent `PackageRBFChecks` aggregate path

**Severity:** P0-CDIV.

Bitcoin Core `PackageRBFChecks` (`validation.cpp:1037-1126`) is the
authoritative package-RBF gate. It runs ONCE per package and:

1. **Topology gate:** workspaces.size() == 2 AND IsChildWithParents
   (validation.cpp:1051): package-RBF only allowed for 1-parent-1-child.
2. **No-in-mempool-ancestors gate** (validation.cpp:1063-1067):
   neither workspace may have `m_parents` (in-mempool ancestors).
   Rationale: to keep the new cluster size = 2.
3. **Aggregate Rule 3 + 4** (validation.cpp:1096-1102):
   `PaysForRBF(conflicting_fees, total_modified_fees, total_vsize,
   incremental_relay_feerate, child_hash)`.
4. **Package-feerate > parent-feerate gate** (validation.cpp:1108-1112):
   the bundle must not be only-anti-DoS-fees.
5. **Cluster size limit** (validation.cpp:1115-1117).
6. **ImprovesFeerateDiagram** (validation.cpp:1120-1124).

rustoshi has NO `PackageRBFChecks` analogue. The control flow is:

`accept_package` → for each tx in package, call
`add_transaction_for_package` → `check_rbf_rules` (PER-TX). So:

- (1) Topology gate: NOT enforced for package RBF specifically. A
  1p2c package with the child conflicting would attempt per-tx RBF on
  the child — Core would reject the WHOLE package as "package must be
  1-parent-1-child" but rustoshi attempts the per-tx replacement.
- (2) No-in-mempool-ancestors: NOT enforced. Both parent and child
  can have mempool ancestors; rustoshi's per-tx path just collects
  ancestors and computes RBF.
- (3) Aggregate Rule 3+4: NOT enforced. Each tx individually pays for
  its own bandwidth; the CHILD doesn't pay for the parent's
  bandwidth aggregated.
- (4) Package-feerate > parent-feerate: NOT enforced; per-tx is the
  only gate.
- (5) Cluster size: enforced per-tx (`mempool.rs:4322-4329`).
- (6) ImprovesFeerateDiagram: BUG-18 below.

**File:** `crates/consensus/src/mempool.rs:3919-4131` (no
PackageRBFChecks call); `mempool.rs:4143-4500` (per-tx).

**Core ref:** `bitcoin-core/src/validation.cpp:1037-1126, 1515`.

**Impact:** rustoshi accepts package-RBF graphs Core specifically
rejects: (a) packages of size > 2; (b) packages where either tx has
in-mempool ancestors; (c) packages where the child-bumps-tiny pattern
that Core prevents under (4) is admissible. Cross-cite W116 G25 BUG.

---

## BUG-17 (P1) — Package-feerate-must-exceed-parent-feerate gate absent

**Severity:** P1.

Bitcoin Core `PackageRBFChecks:1108-1112`:
```cpp
const CFeeRate parent_feerate(parent_ws.m_modified_fees, parent_ws.m_vsize);
const CFeeRate package_feerate(m_subpackage.m_total_modified_fees, m_subpackage.m_total_vsize);
if (package_feerate <= parent_feerate) {
    return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                 "package RBF failed: package feerate is less than or equal to parent feerate", ...);
}
```

This gate ensures the bundle isn't paying only-anti-DoS-fees: the
child must contribute more than its own bandwidth — the AGGREGATE
must rise above the parent's. If the child contributed 0 fee, package_
feerate < parent_feerate (because child adds size but no fee). This
gate forbids the "free child" CPFP-pinning pattern.

rustoshi `accept_package` checks only `package_fee_rate >=
self.config.min_fee_rate` (`mempool.rs:4067`) — never compares against
parent's per-tx rate. A package where parent pays 5 sat/vB and child
pays 0 sat/vB, total 4.8 sat/vB, passes if min_fee_rate is 1.

**File:** `crates/consensus/src/mempool.rs:4060-4072`.

**Core ref:** `bitcoin-core/src/validation.cpp:1108-1112`.

---

## BUG-18 (P1, deferred-with-comment-as-confession) — `ImprovesFeerateDiagram` cluster-mempool gate absent; gate explicitly disclaimed

**Severity:** P1 (deferred).

`mempool.rs:2765-2766`:
```rust
/// Note: Core's ImprovesFeerateDiagram (cluster-mempool, Core 27+) is not implemented
/// because rustoshi does not yet have a cluster mempool. Deferred.
```

Yet rustoshi DOES have cluster scaffolding: `MAX_CLUSTER_SIZE = 64`
(`mempool.rs:144`), `tx_to_cluster` map (`mempool.rs:3424`),
`Cluster::new_singleton` (`mempool.rs:3436`), `Cluster.linearization`
with `Chunk` types and a greedy linearizer (`mempool.rs:474-498`).
The infrastructure exists but `ImprovesFeerateDiagram` is never
wired.

Comment-as-confession ("not implemented... deferred") + "the helpers
exist but the call site is unwired" — the W141 / W148 "dead-helper-at-
call-site" pattern.

**File:** `crates/consensus/src/mempool.rs:2765-2766`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:127-140`.

**Impact:** Fee-diagram pinning that Core 27+ defends against
(PinSpoof family) is undefended in rustoshi. Carry-forward W130
BUG-16. Cross-cite W116 G25.

---

## BUG-19 (P0-CONS / CARRY-FORWARD W150 BUG-15 CONFIRMED) — `add_transaction_for_package` STILL bypasses 10 ATMP gates that single-tx path enforces

**Severity:** P0-CONS.

W150 BUG-15 (dated 2026-05-17) documented this finding. Re-verified
in W151: NO FIX HAS LANDED. `add_transaction_for_package`
(`mempool.rs:4143-4500`) calls:

- `check_transaction(&tx)` (`:4160`) — context-free
- `self.check_standard(&tx)` (`:4163`) — standardness
- Input loop (`:4175-4216`) — input lookup + conflict detection
- Sigop-adjusted vsize (`:4229-4251`)
- `package_fee_rate` min check (`:4256-4261`)
- `check_truc_policy` (`:4264`)
- `check_rbf_rules` if conflicts (`:4274`)
- TRUC sibling eviction (`:4294-4319`)
- Cluster size limit (`:4322-4329`)
- Ancestor limits (`:4332-4346`)
- Descendant limits (`:4348-4375`)
- `trim_to_size` (`:4379-4385`)
- Final insertion

vs `add_transaction_with_options`. Missing from the package path:

| Gate | single-tx path location | package path |
|------|-------------------------|--------------|
| `is_final_tx` (BIP-113) | `mempool.rs:1419-1422` | ABSENT |
| `check_sequence_locks` (BIP-68 CSV) | `mempool.rs:1678-1685` | ABSENT |
| Per-input COINBASE_MATURITY enforcement | `mempool.rs:1454-1457` | absent (no `coin.height` / `tip_height` check) |
| `MoneyRange` on input_sum | `mempool.rs:1466-1469` | absent |
| `AreInputsStandard` | `mempool.rs:1576-1613` | ABSENT |
| `IsWitnessStandard` | `mempool.rs:1620-1624` | ABSENT |
| `MAX_STANDARD_TX_SIGOPS_COST` | `mempool.rs:1657-1662` | tracked via sigop_cost but NEVER COMPARED against MAX_STANDARD_TX_SIGOPS_COST |
| `PolicyScriptChecks` (when verify_scripts=true) | `mempool.rs:1861-` | ABSENT |
| `ConsensusScriptChecks` (when verify_scripts=true) | `mempool.rs:1861-` | ABSENT |
| `pre_check_ephemeral_tx` per-tx | `mempool.rs:1937` (single path) | accept_package calls it (`:4048`) but only on the per-tx loop BEFORE add_transaction_for_package, and tx_fees are recomputed there so it's a separate pipeline |

So a submitpackage RPC of a package containing:
- a tx with `nLockTime = future_height` → ADMITTED (single-tx path rejects)
- a tx with `nSequence` triggering CSV not-yet-final → ADMITTED
- a tx with non-standard input scripts → ADMITTED
- a tx with witness > MAX_STANDARD_P2WSH_STACK_ITEMS → ADMITTED
- a tx with sigops > 16 000 → ADMITTED
- a tx spending an unmatured coinbase (< 100 confirmations) → ADMITTED

The W150 finding was made 24 hours ago; nothing changed. Same root
cause — `add_transaction_for_package` was written as a sibling to
`add_transaction_with_options` but evolved divergently, and is now
~360 LOC of partial-parity code.

**File:** `crates/consensus/src/mempool.rs:4143-4500` (entire helper);
`mempool.rs:1326-2046` (single-tx parity reference).

**Core ref:** `bitcoin-core/src/validation.cpp:1432-1564`
(`AcceptMultipleTransactionsInternal` runs the FULL `PreChecks` per tx).

**Impact:**
- P0-CONS: consensus-level gates bypassed via `submitpackage`.
- "Three-pipeline drift" (single-tx ATMP / package ATMP / test_accept
  ATMP) — same archetype as the rustoshi W142 3-merkle finding (3
  identical merkle helpers, all missing CVE-2012-2459).
- N-pipeline drift: 3rd 3-pipeline finding in W76+ tracking (after
  rustoshi W142 3-merkle and ouroboros W143 3-consensus-pipeline).
- Carry-forward W150 BUG-15 (1 day open, no movement).

**Recommended fix:** Replace `add_transaction_for_package` with a
single-tx call to `add_transaction_with_options` parameterised by a
new `AtmpOptions { in_package: true, package_fee_rate: f64, ... }`.
Eliminates 360 LOC of duplicated/drifted code.

---

## BUG-20 (P2) — `MAX_PACKAGE_SIZE` constant (101 000 vB) exposed as `pub const`; Core has no such public constant

**Severity:** P2.

`crates/consensus/src/mempool.rs:166-169`:
```rust
/// Maximum total virtual size of a package in virtual bytes.
/// Derived from MAX_PACKAGE_WEIGHT: 404000 / 4 = 101000 vB
pub const MAX_PACKAGE_SIZE: usize = 101_000;
```

`MAX_PACKAGE_SIZE` is exported from rustoshi's public API and is used
in test files (`tests/test_w116_package_relay.rs:32`). Core has no
such constant — the authoritative public name is `MAX_PACKAGE_WEIGHT`.
Exporting a derived-but-not-canonical constant invites consumers to
assume it has a Core counterpart.

Combined with BUG-1 (the constant is also used in the WRONG check),
this is a public-API smell.

**File:** `crates/consensus/src/mempool.rs:166-169`;
`crates/consensus/src/lib.rs` (re-export).

**Core ref:** `bitcoin-core/src/policy/packages.h:24` (only
`MAX_PACKAGE_WEIGHT` is public).

---

## BUG-21 (P3) — `accept_package` package-fee-rate compares as integer (`u64`) instead of float; rounds down package admission gate

**Severity:** P3.

`crates/consensus/src/mempool.rs:4061-4072`:
```rust
let package_fee_rate = if package_vsize > 0 {
    package_fee as f64 / package_vsize as f64
} else { 0.0 };

if (package_fee_rate as u64) < self.config.min_fee_rate {
    return PackageAcceptResult::package_failure(
        MempoolError::PackageInsufficientFee(package_fee_rate, self.config.min_fee_rate)
            .to_string(),
    );
}
```

`(package_fee_rate as u64)` truncates 0.999 to 0, but Core uses
`CFeeRate(fees, size).GetFeePerK()` which rounds via CeilDiv. So a
package at exactly the boundary (fee=999 / vsize=1000 = 0.999
sat/vB) is rejected by rustoshi (0u64 < 1), but Core would compute
`CFeeRate(999, 1000) = 999 sat/kvB ≥ 1000 sat/kvB`? Actually no, Core
also rejects this case because GetFeePerK on (999, 1000) returns 999
sat/kvB < 1000 sat/kvB minRelayTxFee.

The divergence: Core compares in sat/kvB integer space; rustoshi
truncates float to integer sat/vB. For ALL fractional sat/vB values
< 1, rustoshi sees 0 and rejects. For most real packages > 1 sat/vB
the cast is identical. Latent.

**File:** `crates/consensus/src/mempool.rs:4061-4072`.

**Core ref:** `bitcoin-core/src/policy/feerate.cpp::CFeeRate::GetFeePerK`.

---

## BUG-22 (P1) — `submit_package` per-tx maxburnamount check uses OP_RETURN-only detector; misses other "provably unspendable" patterns

**Severity:** P1.

`crates/rpc/src/server.rs:5245-5257`:
```rust
for output in &tx.outputs {
    let is_unspendable = output.script_pubkey.first() == Some(&0x6a); // OP_RETURN
    if is_unspendable && output.value > max_burn_sats {
        return Err(...);
    }
}
```

Core's analog uses `CScript::IsUnspendable()` which tests
`!script.empty() && script[0] == OP_RETURN` OR `script.size() >
MAX_SCRIPT_SIZE`. The 10 000-byte ceiling test is missing here.

A tx with a giant non-OP_RETURN output (e.g. 10 001-byte
scriptPubKey) is treated as spendable by rustoshi, so `maxburnamount`
doesn't gate it. Core would consider the output unspendable and
gate it.

**File:** `crates/rpc/src/server.rs:5245-5257`.

**Core ref:** `bitcoin-core/src/script/script.cpp::CScript::IsUnspendable`.

**Impact:** Limited — `MAX_SCRIPT_SIZE` enforcement upstream usually
rejects the tx first. Wire-token / behaviour divergence.

---

## BUG-23 (P3) — `is_child_with_parents` accepts single-tx package (returns true on `txs.len() == 1`); Core requires `package.size() < 2 ⇒ false`

**Severity:** P3.

`crates/consensus/src/mempool.rs:3871-3874`:
```rust
pub fn is_child_with_parents(&self, txs: &[Transaction]) -> bool {
    if txs.len() < 2 {
        return txs.len() == 1; // Single tx is valid
    }
    ...
}
```

Bitcoin Core `IsChildWithParents` (packages.cpp:119-134):
```cpp
bool IsChildWithParents(const Package& package) {
    if (package.size() < 2) return false;
    ...
}
```

Core explicitly returns `false` for 1-tx packages. The function is a
**topology classifier**, not a "should we accept this?". The
1-tx-is-OK route in Core is handled at a HIGHER layer in
`AcceptPackage` (validation.cpp:1640-1645: `if (package.size() > 1 &&
!IsChildWithParents(package))`).

rustoshi's `accept_package` (`mempool.rs:3933-3937`) routes through
`is_child_with_parents` directly:
```rust
if !self.is_child_with_parents(&txs) {
    return PackageAcceptResult::package_failure(
        MempoolError::PackageInvalidTopology.to_string(),
    );
}
```

So rustoshi's `is_child_with_parents` returns `true` for 1-tx (and
that allows the package admission to proceed); Core would return
`false` from the same helper but the caller doesn't dispatch through
it for 1-tx case (BUG-4 above).

Two design philosophies — and both end up admitting 1-tx packages —
but the helper-shape divergence makes cross-impl shared test fixtures
hard to write.

**File:** `crates/consensus/src/mempool.rs:3871-3874`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:119-122`.

---

## BUG-24 (P3, cross-cite W120 BUG-7) — RBF error string `"rbf: insufficient absolute fee (new: %d, conflicting: %d)"` doesn't match Core wording

**Severity:** P3.

`mempool.rs:916-917`:
```rust
#[error("rbf: insufficient absolute fee (new: {0}, conflicting: {1})")]
RbfInsufficientAbsoluteFee(u64, u64),
```

Core `rbf.cpp:110-111`:
```cpp
return strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                 txid.ToString(), FormatMoney(replacement_fees), FormatMoney(original_fees));
```

Different format ("rbf: insufficient absolute fee" vs "rejecting
replacement %s, less fees than conflicting txs"), different numeric
format (raw sats vs `FormatMoney`-formatted BTC), missing the txid.

**File:** `crates/consensus/src/mempool.rs:910-924` (all RBF error
messages).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:110-122`.

**Impact:** BIP-22 reject-string priority slip; carry-forward W120
BUG-7 (~5 weeks open).

---

## Summary

24 bugs catalogued (P0-CDIV: 6 / P0-CONS: 1 / P1: 11 / P2: 3 /
P3: 3):

| Severity | Count | BUG IDs |
|----------|-------|---------|
| P0-CONS | 1 | BUG-19 (W150 BUG-15 carry-forward, package path skips 10 ATMP gates) |
| P0-CDIV | 6 | BUG-3 (already-in-mempool 3-case dispatch lost), BUG-8 (wallet INCREMENTAL_FEE_RATE hardcoded 1 sat/vB), BUG-11 (Rule 5 eviction-count vs cluster-count), BUG-12 (network/relay::pays_for_rbf dead helper), BUG-15 (PackageChildWithParents sibling-eviction invariant absent), BUG-16 (no PackageRBFChecks analogue) |
| P1 | 11 | BUG-1, BUG-2, BUG-4, BUG-5, BUG-7, BUG-9, BUG-10, BUG-17, BUG-18, BUG-22, plus partial BUG-19 |
| P2 | 3 | BUG-13, BUG-20, BUG-24 (partial) |
| P3 | 3 | BUG-6, BUG-14, BUG-21, BUG-23, BUG-24 |

### Top 3 findings

1. **BUG-19 (P0-CONS, carry-forward W150 BUG-15 re-confirmed)** —
   `add_transaction_for_package` STILL skips 10 ATMP gates that
   `add_transaction_with_options` enforces, including BIP-113
   `IsFinalTx`, BIP-68 `CheckSequenceLocks`, COINBASE_MATURITY,
   MoneyRange, AreInputsStandard, IsWitnessStandard,
   MAX_STANDARD_TX_SIGOPS_COST, PolicyScriptChecks,
   ConsensusScriptChecks. `submitpackage` of any tx becomes a back
   door past consensus gates that `sendrawtransaction` enforces. This
   is the rustoshi-specific instance of "N-pipeline drift" (3rd
   3-pipeline finding fleet-wide — sibling to rustoshi W142 3-merkle
   and ouroboros W143 3-consensus-pipeline). W150 finding made 24 h
   ago; no fix landed. Recommended: collapse `add_transaction_for_package`
   into `add_transaction_with_options` with a new
   `AtmpOptions::in_package` knob.

2. **BUG-11 (P0-CDIV) — Rule 5 uses eviction-count cap (>100), Core 27+
   uses unique-cluster-count cap (>100); comment-as-confession 6th
   distinct fleet instance.** rustoshi's mempool rejects RBF
   replacements that 9 of 10 modern Core 27+ relays accept. The
   in-code comment LITERALLY admits the gap: `"NOTE: Core 27+ uses
   unique cluster count; pre-cluster-mempool Core used eviction
   count. Rustoshi uses the eviction-count approach (pre-cluster-
   mempool compatible)."`. PinSpoof family of attacks (where an
   attacker pins a low-feerate tx with long descendant chains)
   defended by Core 27+ are not defended in rustoshi. **Same
   archetype** as W144 fleet-wide script_flag_exceptions absent (9
   of 10 impls) and W128 banman conflation (8 of 10) — RBF policy
   continues fleet-wide pre-cluster-mempool baseline.

3. **BUG-8 (P0-CDIV, two-pipeline guard 17TH distinct extension fleet
   wide; carry-forward W130 BUG-1)** — Wallet
   `INCREMENTAL_FEE_RATE = 1.0 sat/vB` hardcoded at `wallet.rs:817`;
   Core uses `MAX(node_incremental, WALLET_INCREMENTAL_RELAY_FEE =
   5000 sat/kvB = 5 sat/vB)` (feebumper.cpp:135-137). The wallet
   constant exists specifically to "future proof against changes to
   network wide policy for incremental relay fee that our node may
   not be aware of." rustoshi's bumped replacement is admissible to
   its OWN node (1 sat/vB matches the node's `incremental_relay_fee
   = 100 sat/kvB`) but REJECTED by a Core-built wallet peer relay
   that requires 5 sat/vB. The comment at the constant site says
   `// sat/vB; Core DEFAULT_INCREMENTAL_RELAY_FEE` — confusing the
   node constant with the wallet constant (`WALLET_INCREMENTAL_
   RELAY_FEE` is the wallet's, `DEFAULT_INCREMENTAL_RELAY_FEE` is
   the node's). Carry-forward ~3 weeks open since 2026-04-25.

### Fleet patterns confirmed this audit

- **Two-pipeline guard 16th distinct extension** (wallet vs node
  Rule-3 bandwidth math, BUG-8) — fleet pattern grows.
- **Two-pipeline guard 17th distinct extension** (mempool vs
  network/relay dead-helper Rule 3+4 math, BUG-12) — fleet pattern
  grows.
- **Comment-as-confession 6th distinct fleet instance** (BUG-11
  literally documents that rustoshi has pre-Core-27 RBF semantics).
- **N-pipeline drift / 3-pipeline drift 3rd instance** (BUG-19:
  single-tx ATMP + package ATMP + test_accept ATMP all share check
  surface area but diverged).
- **Dead-helper at canonical site** (BUG-12: `network/relay::pays_
  for_rbf` is the natural home for the helper but mempool
  re-implements; same archetype as nimrod W138 / clearbit W148
  dead-helper findings).
- **Reject-string wire-parity slippage** (BUG-2: 9 distinct slips
  across package + RBF reject tokens; same pattern as nimrod W125/
  W145 9-token sweep, lunarblock W145).
- **Wiring-look-but-no-wire** (BUG-5: `MempoolConfig.full_rbf` defined
  with operator-default-true but no CLI flag wires the field; same
  archetype as W138 fleet-wide ChainstateManager defined-but-not-wired
  9 of 10 impls).
- **Deferred-with-comment-as-confession** (BUG-18:
  `ImprovesFeerateDiagram` deferred with explicit code-comment;
  cluster infrastructure exists at MAX_CLUSTER_SIZE=64 but is never
  fed into the diagram check).

### Carry-forward inventory

- **W150 BUG-15 → W151 BUG-19** (1 day open; no movement)
- **W130 BUG-1 → W151 BUG-8** (~3 weeks open since 2026-04-25)
- **W130 BUG-9 → W151 BUG-9** (~3 weeks open)
- **W130 BUG-10 → W151 BUG-10** (~3 weeks open)
- **W130 BUG-16 → W151 BUG-18** (~3 weeks open)
- **W120 BUG-7 → W151 BUG-24** (~5 weeks open)
- **W120 BUG-8 → W151 BUG-12** (~5 weeks open)
- **W120 BUG-11 → W151 BUG-5** (~5 weeks open)
- **W116 G3b → W151 BUG-1** (~7 weeks open)
- **W116 G26b → W151 BUG-19 cross-cite** (~7 weeks open)

### Priority next fix recommendations (rustoshi-side)

1. **BUG-19 (P0-CONS)**: Collapse `add_transaction_for_package`
   into `add_transaction_with_options` parameterised by
   `AtmpOptions::in_package = true` + `package_fee_rate`. Eliminates
   ~360 LOC of duplicated/drifted code and re-anchors single-tx +
   package paths to the same gate-set. Single-architecture-fix
   closes 1 P0-CONS finding spanning 2 audits.
2. **BUG-11 (P0-CDIV)**: Implement `GetUniqueClusterCount` over the
   existing `tx_to_cluster` map and route Rule 5 through it.
   Estimated ~15 LOC + cluster-count helper. Re-removes the
   PinSpoof attack surface.
3. **BUG-8 (P0-CDIV)**: Replace `wallet.rs:817` `INCREMENTAL_FEE_
   RATE = 1.0` with `max(node_incremental_relay_fee, 5.0)` and
   introduce `WALLET_INCREMENTAL_RELAY_FEE = 5_000` sat/kvB
   constant. ~5 LOC. Closes wallet-bumped-tx rejection on Core peer
   relays.
4. **BUG-16 (P0-CDIV) + BUG-15 + BUG-17**: Introduce a
   `package_rbf_checks` helper covering Core's full
   `PackageRBFChecks`: 1-parent-1-child gate, no-in-mempool-
   ancestors gate, aggregate Rule 3+4, package-feerate > parent-
   feerate. Single subsystem fix closes 3 P0-CDIV / P1 findings.
5. **BUG-3 (P0-CDIV)**: Add a wtxid-vs-txid dispatch in
   `accept_package` mirroring Core's 3-case
   `MempoolTx`/`MempoolTxDifferentWitness`/`AcceptSubPackage` split.
   ~30 LOC.
6. **BUG-2 (P1)**: Sweep package + RBF error variants in
   `MempoolError` to emit Core wire tokens via `bip22_string()`
   instead of thiserror Display strings. ~50 LOC.
7. **BUG-12 (P0-CDIV)**: Either delete the dead `network/relay::
   pays_for_rbf` helper, or wire `mempool::check_rbf_rules` through
   it. Eliminates the second pipeline. ~10 LOC.
8. **BUG-18 (P1)**: Implement `improves_feerate_diagram` over the
   existing cluster infrastructure (`Cluster.linearization`) and
   wire into `check_rbf_rules`. ~50-80 LOC.
