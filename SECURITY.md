# Security Policy — rustoshi

rustoshi is a from-scratch Bitcoin full-node implementation in Rust, part of the
[hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core. It is the lead flagship — the node with
the strongest correctness evidence in the fleet. Security is the entire purpose.

## Project maturity — read this first

rustoshi is released on the **tagged-validator** bar: a node you can build, run
*beside* Bitcoin Core in watchtower mode, and trust to track consensus. Its
correctness is unusually well-evidenced: an **`--assumevalid=0` genesis→tip
validation reaches the exact Core tip byte-for-byte**, trusting no checkpoint — the
strongest such proof in the fleet. P0 is proven: crash-recovery 3/3, deep-reorg 6/6
(incl. a 110-block reorg), clean differential guard, byte-exact with Core live, and
P2P DoS-hardened (getblocktxn-depth + accept-time inbound caps) with a signature cache.

**It is NOT yet fund-capable for general custody.** rustoshi is the fleet's *funding
target* and is closest to that bar, but it is not there. Do not custody funds on it
yet beyond an eyes-open canary. The intended trust model for this release is: run it
alongside Core with `consensus-diff` as a live divergence alarm.

There are no fund-grade guarantees. Run from a pinned commit.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v1.0.0` | Current release — best-effort; no security SLA |
| `v0.1.0-rc1` (pinned `e735ef1`) | Superseded validator RC — upgrade to `v1.0.0` |
| pre-release (`master`) | Best-effort |

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
wallet paths — a public report could put real Bitcoin nodes or funds at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (a diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix. We coordinate
a fix + disclosure timeline and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — rustoshi accepting a block/tx Core rejects, or vice-versa.
  This is the core concern; rustoshi carries 33+ receipted-and-fixed divergences with
  Core `file:line` citations (see `../CORE-PARITY-AUDIT/`).
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or block/tx
  decode paths (past examples: P2P-decoder OOM, BIP-157 overflow — both fixed).
- **Wallet funds-safety** — silent wrong-key signing, a spend the node reports valid
  that the network rejects, un-recoverable backups, fee miscalculation stranding funds.
- **Chainstate corruption on crash** (crash-recovery is 3/3; regressions are in scope).

## Custody caveats (not consensus, but real — for the fund track, not this validator tag)

- The **default `createwallet` is not exportable/backup-able** (`listdescriptors`/
  `dumpwallet` fail on it) — a funds trap. Use the seed (`sethdseed`) path for any
  canary funding; the seed you generate offline IS the backup. See the funding runbook.
- `signrawtransactionwithwallet` ignores `prevtxs` (no offline/hardware-wallet signing yet).

These gate fund-capability (P2), not the watchtower-validator tag.

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed; a live
watchtower (`../tools/watchtower.sh`) alarms on any rustoshi-vs-Core divergence.
