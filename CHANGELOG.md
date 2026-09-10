# Changelog

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

- fix(rpc): T1 error/shape parity — gettxoutsetinfo -8, addnode -1, clearbanned extra-arg, getnettotals.uploadtarget, getnetworkhashps -3, getblocktemplate missing-segwit
- 5e1689a3 docs: say the cited paths are private before the claims that rest on them
- 1261e48b fix: SIGTERM was permanently lost while the node was syncing
- fd1197a7 fix: force-flush the chainstate before hashing the UTXO set
- edcf6016 fix: emit the assumevalid-disable banner where it can be seen
- 7f36021d feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

