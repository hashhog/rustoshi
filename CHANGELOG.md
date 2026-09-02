# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-rc1`:

- 8e21edee test(rpc): un-rot test_w125_error_parity — integer args became serde_json::Value in f4781114
- 55cbede2 docs: LICENSE, toolchain version (release hygiene)
- f4781114 fix(rpc): read integer arguments in the handler, not in the deserializer
- 575c92e4 fix(rpc): createpsbt accepts an empty inputs array, as Core does
- 8b7c15e2 fix(rpc): read integer arguments at Core's width, and honour the ones we read
- 6b9b0f92 fix(rpc): createrawtransaction and createpsbt ignored the `version` argument
- 5bffba4f fix(rpc): createrawtransaction rejects replaceable=true contradicted by its sequences
- 3f97b04a fix(rpc): createrawtransaction range-checks vout/sequence/locktime instead of truncating them
- abe51de7 test: connect-path intra-block tx chain leaves no phantom UTXO (#64)
- bf49fc5a fix: remove signet assumeutxo entry from testnet4 (#51) + BIP-324 long-form command validation + modern sendcmpct test
- 7930999a test(consensus): pin work-vs-length cross-cases on the header-tip rewind (#47/#49)
- 4b08ca1f fix(p2p): send_to_peer failures are loud + must_use; block dispatch requeues on dead channels (#74)
- dd338408 fix(p2p): headers_presync next_locator gets the real LocatorEntries walk
- d086a76a fix(consensus): interleave disconnect output-undo and input-restore per tx
- ba0731c8 fix(sync): fetch a losing fork's competing branch by hash
- fd8b6584 fix(sync): add a level-triggered block-download gap fill
- b5ef1034 build: enable runtime integer-overflow checks in the release profile
- ac5be0e9 feat(rpc): list 10 answered-but-unlisted methods in help (R5 help-parity)
- c9aa18c4 fix(consensus): run the CVE-2012-2459 mutation scan before the dup-txid scan (Core CheckBlock order) + bad-txns-duplicate token
- 776d2bd5 fix: bwmc R2 reason-code parity — emit Core CheckBlock reject tokens
- c7caa7e7 fix(assumeutxo): backfill baked base-tail bands on startup, not only at activation
- 4af56bda fix(consensus): enforce bad-diffbits by pointer, and close the snapshot-base fail-open
- 02652493 fix: surface chainstate corruption instead of silently wedging
- db23aec5 fix(rpc): answer prev-blk-not-found for an unknown parent, as Core does
- 994334d6 fix(p2p): bound peer sends — one blackholed peer wedged the whole node
- 2762fff3 fix(policy): Core v31 cluster mempool limits — weight units, >404000, >64
- 7ae238c8 refactor(consensus): delete ScriptFlags::consensus_flags, the hash-blind decoy
- 18872117 fix(consensus): unconditional P2SH|WITNESS|TAPROOT + Core's replace-then-OR
- 234dd60e fix(policy): track Core v31 relay-fee defaults (1000 -> 100 sat/kvB)
- bf2cd82c fix: P2P liveness watchdog — crash-only self-heal for async task hang
- 3efc01c1 test: fix process_block call sites for 7-arg signature (fixture rot)
- d32d51f3 docs: in-repo release wrapper (SECURITY.md + reproducible-build note) for v0.1.0-rc1

