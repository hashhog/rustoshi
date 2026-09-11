# Changelog

## v1.0.2 (unreleased)

Changes since `v1.0.1`:

- fix(rpc): T1 error/shape parity — gettxoutsetinfo -8, addnode -1, clearbanned extra-arg, getnettotals.uploadtarget, getnetworkhashps -3, getblocktemplate missing-segwit
- feat(net): `HASHHOG_BLOCKS_IN_FLIGHT_PER_PEER` — raise the per-peer in-flight block cap (default 16, max 128) for single-feeder syncs; A/B in progress, default unchanged (a74be105)
- fix: a campaign entry identical to Core's built-in assumeutxo anchor is a confirmation, not a collision — it is skipped, not staged (7d4d7972)

## v1.0.1 — 2026-09-07

Changes since `v1.0.0`:

- 5e1689a3 docs: say the cited paths are private before the claims that rest on them
- 1261e48b fix: SIGTERM was permanently lost while the node was syncing
- fd1197a7 fix: force-flush the chainstate before hashing the UTXO set
- edcf6016 fix: emit the assumevalid-disable banner where it can be seen
- 7f36021d feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot
