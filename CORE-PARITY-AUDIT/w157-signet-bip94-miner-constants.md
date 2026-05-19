# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (rustoshi)

**Wave:** W157 — `CheckSignetBlockSolution`, `SignetTxs::Create`,
`FetchAndClearCommitmentSection`, `SIGNET_HEADER=0xecc7daa2`,
`signet_blocks`, `signet_challenge` (Consensus::Params),
`-signetchallenge` CLI, `pchMessageStart` derived from challenge hash,
`MAX_TIMEWARP=600` (BIP-94, always-on for miners since Core v25),
`enforce_BIP94` (consensus param), `GetMinimumTime(pindexPrev, dai)`
miner-side clamp, `UpdateTime` retarget side-effect for testnet
min-difficulty, `ComputeBlockVersion` with chain context.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.cpp:28` — `static constexpr uint8_t
  SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};` — the 4-byte tag that
  marks the signet-solution push inside the witness-commitment script
  of the coinbase.
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection`:
  walks the witness-commitment scriptPubKey, finds the `SIGNET_HEADER`
  prefix in any push-data, extracts the trailing bytes as the
  `signet_solution`, and rewrites the script with the header+solution
  removed so the modified-merkle-root can be recomputed deterministically.
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create` — builds the
  spend/spent transaction pair used by `VerifyScript`. The `to_spend` tx
  has a single output paying `consensusParams.signet_challenge`; the
  `to_sign` tx parses `signet_solution` as (scriptSig, scriptWitness)
  and signs the block-header bytes (`nVersion || hashPrevBlock ||
  signet_merkle || nTime`).
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  bypasses for `block.GetHash() == hashGenesisBlock`; otherwise
  `VerifyScript(scriptSig, signet_challenge, witness,
  BLOCK_SCRIPT_VERIFY_FLAGS [P2SH|WITNESS|DERSIG|NULLDUMMY], sigcheck)`.
  Failure → `false` → caller emits `bad-signet-blksig`.
- `bitcoin-core/src/validation.cpp:3930-3933` —
  `if (consensusParams.signet_blocks && fCheckPOW &&
  !CheckSignetBlockSolution(block, consensusParams)) {
  return state.Invalid(BLOCK_CONSENSUS, "bad-signet-blksig", ...); }`
  — gates the call on `signet_blocks` AND `fCheckPOW`.
- `bitcoin-core/src/signet.h:30-39` — `SignetTxs` public/private API +
  documentation that the signet tx commits to everything in the block
  EXCEPT the modified merkle root (signet signature removed from CB) AND
  the nonce (so PoW is independent of the signet solution).
- `bitcoin-core/src/kernel/chainparams.cpp:451-453` — signet
  `consensus.signet_blocks = true; consensus.signet_challenge.assign(...);`
  population from operator-provided or default challenge.
- `bitcoin-core/src/kernel/chainparams.cpp:432-479` —
  `-signetchallenge=<hex>` operator override; default-signet challenge
  hash → `pchMessageStart` first-4-bytes (custom signet networks
  therefore have DIFFERENT P2P magic from default signet).
- `bitcoin-core/src/consensus/params.h:121, 140` —
  `bool enforce_BIP94;` and `std::vector<uint8_t> signet_challenge;` —
  the two consensus params W157 covers.
- `bitcoin-core/src/consensus/consensus.h:35` —
  `static constexpr int64_t MAX_TIMEWARP = 600;`
- `bitcoin-core/src/pow.cpp:67-76` — `CalculateNextWorkRequired`
  BIP-94 first-block branch: `if (params.enforce_BIP94) { bnNew.SetCompact(pindexFirst->nBits); }`
- `bitcoin-core/src/validation.cpp:4097-4105` — `ContextualCheckBlockHeader`
  BIP-94 receive-side gate: `if (consensusParams.enforce_BIP94 && nHeight %
  DifficultyAdjustmentInterval() == 0) { if (block.GetBlockTime() <
  pindexPrev->GetBlockTime() - MAX_TIMEWARP) state.Invalid(...,
  "bad-time-timewarp"); }`
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`:
  ```cpp
  int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
  const int height{pindexPrev->nHeight + 1};
  // Account for BIP94 timewarp rule on all networks. This makes future
  // activation safer.
  if (height % difficulty_adjustment_interval == 0) {
      min_time = std::max<int64_t>(min_time,
                                   pindexPrev->GetBlockTime() - MAX_TIMEWARP);
  }
  return min_time;
  ```
  Note: BIP-94 timewarp clamp fires REGARDLESS of `enforce_BIP94`
  flag on the miner side (Core v25+ as defense-in-depth).
- `bitcoin-core/src/node/miner.cpp:49-64` — `UpdateTime`:
  `pblock->nTime = max(GetMinimumTime(pindexPrev, dai), NodeClock::now)`,
  and re-runs `GetNextWorkRequired` if
  `fPowAllowMinDifficultyBlocks` (testnet min-diff reacts to
  timestamp).
- `bitcoin-core/src/rpc/mining.cpp:1004` — `result.pushKV("mintime",
  GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval()));` —
  GBT `mintime` is computed from `GetMinimumTime`, NOT raw `MTP+1`.

**Files audited**
- `crates/consensus/src/params.rs` — `NetworkId::Signet`,
  `ChainParams::signet()` (line 879-921), `signet_pow_limit()`
  (line 1064-1075), `genesis_block_signet()` (line 1232-1277),
  `MAX_TIMEWARP=600` const (line 213), `enforce_bip94` field
  (line 490).
- `crates/consensus/src/pow.rs` — `get_next_work_required` (line 52-87),
  `calculate_next_work_required` (line 128-159), BIP-94 base-bits branch
  (line 144-155), `check_proof_of_work` (line 625-643).
- `crates/consensus/src/validation.rs` — `check_block` (line 453-514),
  `contextual_check_block` (line 1079, called from production via
  `process_block`), `contextual_check_block_header` (line 914-986,
  test-only — NO production callers), `accept_block_header_chain_work`
  (line 1018, test-only).
- `crates/consensus/src/block_template.rs` — `build_block_template`
  (line 290-534), `compute_block_version` use (line 487-509),
  no MAX_TIMEWARP/min_time clamp anywhere.
- `crates/consensus/src/chain_state.rs` —
  `ChainState::process_block`/`process_block_inner` (line 395-509)
  calls `check_block` + `contextual_check_block` but NOT
  `CheckSignetBlockSolution` and NOT the timewarp-header check.
- `crates/consensus/src/versionbits.rs` —
  `compute_block_version` (line 504-520), `get_state_for` (line 285-443),
  `get_deployments` (line 536-639) maps `Signet` to all-always-active
  (line 623-629).
- `crates/rpc/src/server.rs` — `get_block_template` (line 4065-4329),
  `mintime` derivation (line 4316), `mine_single_block` (line 9384-9509,
  regtest-only).
- `crates/rpc/src/types.rs` — `BlockTemplateResult` (line 583-626),
  no `signet_challenge` field.
- `rustoshi/src/main.rs` — header processing in `Headers` message
  branch (line 2542-2612), hand-rolled time check (line 2547-2598),
  no BIP-94 gate, no nVersion gate.

---

## Gate matrix (38 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `CheckSignetBlockSolution` perimeter | G1: function exists in consensus crate | **BUG-1 (P0-CONS)** — function ENTIRELY ABSENT. Zero callsites, zero implementation. |
| 1 | … | G2: called from `check_block` / `connect_block` / `process_block` for signet | **BUG-1 cross-cite** |
| 1 | … | G3: genesis hash bypass before signature check | N/A (function absent) |
| 1 | … | G4: signet challenge VerifyScript with P2SH|WITNESS|DERSIG|NULLDUMMY | N/A (function absent) |
| 2 | `signet_challenge` consensus param | G5: `ChainParams::signet()` stores `signet_challenge: Vec<u8>` field | **BUG-2 (P0-CONS)** — `ChainParams` struct (params.rs:467-541) has NO `signet_challenge` field. No way to plumb a challenge into validation. |
| 2 | … | G6: `signet_blocks: bool` flag for "this network requires solution check" | **BUG-2 cross-cite** — no `signet_blocks` field either |
| 2 | … | G7: `-signetchallenge=<hex>` CLI override | **BUG-3 (P1)** — `parse_args` / `Args` in `rustoshi/src/main.rs` has no `signetchallenge` flag. Custom-signet operators cannot run rustoshi against their own signet network. |
| 3 | `SIGNET_HEADER=0xecc7daa2` constant | G8: tag defined as 4-byte constant | **BUG-4 (P0-CONS)** — no `SIGNET_HEADER` constant anywhere in the codebase. `grep ecc7daa2 .` → zero hits. |
| 3 | … | G9: `FetchAndClearCommitmentSection` helper | N/A (function family absent) |
| 4 | `pchMessageStart` derived from challenge hash | G10: signet network_magic computed from `sha256d(signet_challenge)[0..4]` | **BUG-5 (P1)** — `network_magic: NetworkMagic([0x0a, 0x03, 0xcf, 0x40])` HARDCODED (params.rs:885). Custom-signet operators would need a different magic but rustoshi has only the default-signet value. |
| 5 | `enforce_BIP94` consensus param | G11: per-network flag exists | PASS (`params.rs:490 enforce_bip94: bool`); testnet4 `true`, others `false` (params.rs:571, 754, 810, 898, 939 — matches Core lines 463, 78, 213, 309, 540) |
| 5 | … | G12: receive-side `ContextualCheckBlockHeader` BIP-94 gate fires on testnet4 retarget | **BUG-6 (P0-CONS)** — `contextual_check_block_header` defines the gate (validation.rs:940-948) but the function has ZERO production callsites. Header validation in `main.rs:2547-2598` hand-rolls a partial check that OMITS the BIP-94 gate entirely. `MAX_TIMEWARP` is consequently never enforced on incoming headers. |
| 5 | … | G13: receive-side gate inside `process_block` (body-validation) | **BUG-6 cross-cite** — `chain_state.rs:475-477` checks `prev_block_mtp > 0 && block.header.timestamp <= prev_block_mtp` but the BIP-94 `prev_time - MAX_TIMEWARP` rule is also missing here. |
| 6 | `CalculateNextWorkRequired` BIP-94 first-bits branch | G14: when `enforce_bip94` true, use first-of-period bits | PASS (`pow.rs:146-155`) |
| 7 | `GetMinimumTime` miner-side BIP-94 always-on | G15: `mintime` in GBT response clamps to `max(MTP+1, prev_time - MAX_TIMEWARP)` at retarget | **BUG-7 (P0-CDIV — cross-cite W154 BUG-12)** — `server.rs:4316` returns `mintime: (median_time_past + 1) as u32`. No MAX_TIMEWARP clamp. Core's `GetMinimumTime` (miner.cpp:36-47) clamps unconditionally regardless of `enforce_BIP94` flag. |
| 7 | … | G16: `build_block_template` clamps `timestamp` parameter to same min_time | **BUG-8 (P1)** — `build_block_template` (block_template.rs:290-534) accepts `timestamp: u32` from caller and writes it into the header (line 516). No internal clamp. |
| 7 | … | G17: `mine_single_block` uses `GetMinimumTime` | **BUG-9 (P1)** — `server.rs:9432`: `let timestamp = std::cmp::max(now, (median_time_past + 1) as u32);` — same MAX_TIMEWARP gap. (Mitigated: regtest-only path; mainnet GBT users hit BUG-7 instead.) |
| 8 | `UpdateTime` retarget-side-effect | G18: testnet `pow_allow_min_difficulty_blocks` re-runs `GetNextWorkRequired` after time bump | **BUG-10 (P1)** — `mine_single_block` (server.rs:9405-9411) reads `bits = prev_header.bits` directly. No `get_next_work_required` invocation. Echoes W154 BUG-1 (lunarblock) — regtest-only here (pow_no_retargeting=true makes it benign) but the SHAPE matches Core's pre-W154 bug class. |
| 9 | `ComputeBlockVersion` with chain context | G19: GBT version reflects STARTED/LOCKED_IN deployment bits at current height | **BUG-11 (P1 — cross-cite W154 BUG-13)** — `block_template.rs:487-509` calls `compute_block_version::<NoBlock>(None, &pairs, None)`. With `block=None`, `get_state_for` (versionbits.rs:285-302) returns `Defined` for non-trivial deployments and `Active` for Always-Active. `compute_block_version` only ORs bits for STARTED/LOCKED_IN — so the result is permanently `0x20000000`. |
| 10 | Signet `pow_limit` exact value | G20: `00000377ae000000000000000000000000000000000000000000000000000000` | **BUG-12 (P0-CONS)** — `signet_pow_limit()` (params.rs:1065-1075) sets `[0..4] = [0x00, 0x00, 0x03, 0x77]` and `[4..32] = 0xff` (skip 4 + 0xff fill). Core sets `[0..5] = [0x00, 0x00, 0x03, 0x77, 0xae]` and `[5..32] = 0x00`. Rustoshi's pow_limit is `0x0000037 7 FF...FF` (much higher = much weaker) — signet PoW difficulty floor is wrong by orders of magnitude. **Comment** (params.rs:1064) is also wrong (missing 0xae after 0x77). |
| 11 | Signet `pow_allow_min_difficulty_blocks` | G21: `false` (Core: chainparams.cpp:463) | PASS (`params.rs:896`) |
| 11 | … | G22: `pow_no_retargeting: false` | PASS (`params.rs:897`) |
| 11 | … | G23: `enforce_bip94: false` (Core: chainparams.cpp:464) | PASS (`params.rs:898`) — matches Core. Note Core's miner `GetMinimumTime` still applies MAX_TIMEWARP unconditionally; rustoshi does not (BUG-7). |
| 12 | Signet checkpoints | G24: NONE (Core has zero `checkpointData` for signet) | **BUG-13 (P1)** — `params.rs:914-917` defines TWO checkpoints with hashes `00000030db7cd0c0fab1c0f4b3e6c2d1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5` (h=1000) and `00000024b5c8f7d6e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0` (h=50000). These hashes are PATTERN-FABRICATED (sequential hex nibbles `0123...edcba9`). Core has no signet checkpoints. Any real-signet sync to height 1000 will fail with checkpoint mismatch. |
| 12 | … | G25: testnet4 checkpoints absent (Core has zero) | **BUG-14 (P1)** — same pattern. `params.rs:831-834`: h=10000 `00000000c3afe3c8c0cc7bea7e6c0f6e67d5c1f9b2a0e8d7c6b5a4f3e2d1c0b9`, h=50000 `000000000001a8c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2`. Sequential nibbles betray fabrication. |
| 12 | … | G26: signet/testnet4 default `assumed_valid_block` matches Core | **BUG-15 (P1)** — signet: rustoshi `assumed_valid_block: None`/`assumed_valid_height: None` (params.rs:909-910). Core sets `00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329` at h=293,175 (chainparams.cpp:436). Signet IBD is consequently much slower than Core (full script revalidation through tip). Companion to W149 BUG-7 (blockbrew). |
| 13 | Validation entry-point coverage | G27: `check_block` invokes `CheckSignetBlockSolution` for signet | **BUG-1 cross-cite** — not present |
| 13 | … | G28: `process_block` / `process_block_inner` invokes signet check | **BUG-1 cross-cite** |
| 13 | … | G29: header-sync pipeline invokes BIP-94 check | **BUG-6 cross-cite** |
| 13 | … | G30: `contextual_check_block_header` has at least one production callsite | **BUG-16 (P0-DEAD)** — function defined (validation.rs:914-986) with full body for MTP+TimeTooNew+BIP-94+nVersion-by-height gates; grep for callers outside `crates/consensus/src/validation.rs` test block returns zero. All gates inside it are dead. |
| 13 | … | G31: `accept_block_header_chain_work` has at least one production callsite | **BUG-17 (P1)** — function defined (validation.rs:1018) with `min_pow_checked` gate; only callers are `crates/storage/src/w109_block_index_gates.rs` (which is itself a documentation-only gate module, not the main wire-up path) and the `crates/consensus/tests/` suite. The header-sync pipeline in `main.rs:2542-2612` does NOT call it, so headers below `minimum_chain_work` are NOT rejected on the receive side. |
| 13 | … | G32: nVersion BIP-34/65/66 height-gate runs on every header | **BUG-18 (P0-CDIV)** — header-sync path in `main.rs:2547-2598` hand-rolls a partial BIP-113 check but OMITS the `nVersion < 2|3|4` height-gated rejection from `contextual_check_block_header` (validation.rs:977-983). Headers with the wrong nVersion are accepted in IBD; the divergence is caught later in `process_block`'s `contextual_check_block` — wasted work plus possible mid-IBD wedge if a malicious peer feeds 2000 such headers. |
| 13 | … | G33: timestamp 7200s future-drift gate runs on header AND body | PARTIAL — header path enforces (main.rs:2565-2575). Body path: `contextual_check_block_header` would but is dead; `process_block` checks `timestamp <= prev_block_mtp` only (chain_state.rs:475). Acceptable in practice (header already filtered) but defense-in-depth gap. |
| 13 | … | G34: `MTP+1` strict-greater enforced on submitblock path | PASS (`chain_state.rs:475-477`) |
| 13 | … | G35: signet `dns_seeds` valid | PASS (`params.rs:890-893`) |

---

## BUG-1 (P0-CONS) — `CheckSignetBlockSolution` entirely missing

**Severity:** P0-CONS (signet chain split at block 1; fleet-wide
pattern echoing W143 BUG-9 / W155 BUG-25 — confirmed for blockbrew,
hotbuns, and now rustoshi).

Bitcoin Core's `validation.cpp:3930-3933` gates every signet block with:
```cpp
if (consensusParams.signet_blocks && fCheckPOW &&
    !CheckSignetBlockSolution(block, consensusParams)) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                         "bad-signet-blksig",
                         "signet block signature validation failure");
}
```

`CheckSignetBlockSolution` (signet.cpp:126-153) extracts the signet
solution from the witness commitment, builds the spend/spent tx pair via
`SignetTxs::Create`, and runs `VerifyScript` with
`SCRIPT_VERIFY_P2SH|WITNESS|DERSIG|NULLDUMMY` against
`consensusParams.signet_challenge`. The genesis block is bypassed
(`block.GetHash() == hashGenesisBlock`).

Rustoshi has:
- **Zero** `CheckSignetBlockSolution` definition.
- **Zero** `signet_blocks` chain-param field.
- **Zero** `signet_challenge` chain-param field (params.rs `ChainParams`
  struct at 467-541 has no such field).
- **Zero** `SIGNET_HEADER` constant (`grep ecc7daa2 .` returns no
  hits across the repo).
- **Zero** `SignetTxs` / `FetchAndClearCommitmentSection` helpers.

Consequence on signet:
- `process_block` (chain_state.rs:424-509) runs `check_block` → which
  validates PoW against `params.pow_limit` and the merkle root, but
  performs NO signet-signature check.
- Any block whose hash is below the (broken-permissive — see BUG-12)
  `signet_pow_limit` is accepted regardless of who mined it, with or
  without the signet operator's signature. Rustoshi forks off signet at
  block 1 (the first non-genesis block where a real signet node would
  reject a non-signed competitor).
- Effective network split: rustoshi cannot follow real signet; rustoshi
  would also accept any attacker-mined fork.

This is the SAME pattern as W143 BUG-9 (blockbrew), W155 BUG-25
(hotbuns) — now fleet-wide ≥3 impls confirmed.

**File:** `crates/consensus/src/validation.rs` (no entry); `crates/consensus/src/params.rs:879-921`
(no `signet_blocks` / `signet_challenge` fields); whole `signet.cpp`
absent in `crates/consensus/src/`.

**Core ref:** `bitcoin-core/src/validation.cpp:3930-3933`;
`bitcoin-core/src/signet.cpp:126-153`.

**Impact:** rustoshi cannot follow real signet; chain forks at block 1;
accepts attacker-mined blocks.

---

## BUG-2 (P0-CONS) — `signet_challenge` / `signet_blocks` consensus-param fields absent

**Severity:** P0-CONS (companion to BUG-1; same chain-split blast
radius).

Bitcoin Core's `consensus/params.h:121,140`:
```cpp
bool enforce_BIP94;
// ... (other fields) ...
std::vector<uint8_t> signet_challenge;
```
plus `bool signet_blocks;` flag.

Rustoshi's `ChainParams` struct (`params.rs:467-541`) declares
`enforce_bip94: bool` (correctly, line 490), but is **missing both**
`signet_blocks: bool` and `signet_challenge: Vec<u8>`. The `signet()`
constructor (line 879-921) makes no attempt to populate either —
because the fields do not exist.

Without the param fields:
- `CheckSignetBlockSolution` could not even be implemented without a
  refactor of `ChainParams`.
- Custom-signet networks (operators running their own signet with a
  different challenge script) are doubly impossible.
- The `pchMessageStart` derivation (Core chainparams.cpp:476-479
  `h << consensus.signet_challenge; hash.first(4)`) cannot be wired —
  rustoshi hardcodes the default-signet magic instead (BUG-5).

**File:** `crates/consensus/src/params.rs:467-541` (`ChainParams`
struct), 879-921 (`signet()` constructor).

**Core ref:** `bitcoin-core/src/consensus/params.h:121, 140`.

**Impact:** architectural prerequisite to fixing BUG-1, BUG-3, BUG-4,
BUG-5.

---

## BUG-3 (P1) — `-signetchallenge` CLI override absent

**Severity:** P1 (operator-knob; mainnet-class operators not affected,
but anyone running a custom signet cannot use rustoshi).

Bitcoin Core's `kernel/chainparams.cpp:432-479` reads `-signetchallenge=<hex>`
from `options.challenge`, derives `pchMessageStart` from
`sha256d(challenge).first(4)`, and writes the challenge into
`consensus.signet_challenge`.

Rustoshi's `rustoshi/src/main.rs` (CLI parsing) has no
`signetchallenge` flag. `ChainParams::signet()` is invoked
unconditionally with the default-signet challenge implicit (and even
that is not stored anywhere — see BUG-2). Operators on a custom-signet
deployment cannot pass their challenge in.

**File:** `rustoshi/src/main.rs` (CLI struct, ~line 50-200);
`crates/consensus/src/params.rs:879-921` (signet constructor with no
override path).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:432-479`
(`-signetchallenge` argument handling).

**Impact:** custom-signet networks cannot run rustoshi; operator
ecosystem coverage gap.

---

## BUG-4 (P0-CONS) — `SIGNET_HEADER=0xecc7daa2` constant absent

**Severity:** P0-CONS (BUG-1 prerequisite — without this 4-byte tag
constant, the parser cannot locate the signet-solution push within the
witness-commitment scriptPubKey).

Bitcoin Core's `signet.cpp:28`:
```cpp
static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};
```

Rustoshi: zero hits for `0xecc7daa2`, `SIGNET_HEADER`, `ecc7daa2`
anywhere in the codebase (grep includes `.rs`, comments, tests, docs).

`FetchAndClearCommitmentSection` (signet.cpp:32-57) iterates
`witness_commitment.GetOp(pc, opcode, pushdata)` and matches the first
4 bytes of every push against `SIGNET_HEADER`. Without the constant,
the helper cannot be written; without the helper, the signet solution
cannot be extracted from a block coinbase; without extraction, the
signature cannot be verified.

**File:** absent across `crates/consensus/src/` (would normally live in
`signet.rs` or `crypto/src/signet.rs`).

**Core ref:** `bitcoin-core/src/signet.cpp:28`.

**Impact:** BUG-1 prerequisite; cannot be fixed independently.

---

## BUG-5 (P1) — Signet `network_magic` hardcoded; not derived from challenge hash

**Severity:** P1 (custom-signet networks cannot interop).

Bitcoin Core derives `pchMessageStart` from
`sha256d(consensus.signet_challenge).first(4)`
(`kernel/chainparams.cpp:476-479`). The default-signet challenge yields
`0x0a 0x03 0xcf 0x40` (matching what rustoshi hardcodes). But custom
signet networks have DIFFERENT magic bytes per their own challenge.

Rustoshi (`params.rs:885`):
```rust
network_magic: NetworkMagic([0x0a, 0x03, 0xcf, 0x40]),
```
This is the default-signet magic baked in. No derivation, no override.
A custom-signet operator running rustoshi would (a) not be able to set
`-signetchallenge` (BUG-3), and (b) even if rustoshi accepted such a
flag, its P2P layer would advertise the wrong magic to peers — peers
would reject the version handshake.

**File:** `crates/consensus/src/params.rs:885`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:476-479`.

**Impact:** custom-signet interop impossible. Default-signet is fine
because the magic happens to match the hardcoded value.

---

## BUG-6 (P0-CONS) — `contextual_check_block_header` is DEAD code; BIP-94 receive-side gate never fires

**Severity:** P0-CONS (testnet4 chain split at every retarget boundary
≥ height 2016 if a peer feeds a header with `nTime < prev.nTime - 600`).

Bitcoin Core's `ContextualCheckBlockHeader` (validation.cpp:4097-4105)
runs on EVERY header during `AcceptBlockHeader`. The BIP-94 gate inside
it fires on testnet4 when `enforce_BIP94 && height % 2016 == 0`.

Rustoshi's `contextual_check_block_header` (`validation.rs:914-986`)
contains the correct gate at lines 940-948 (verified against Core
4097-4105 line-for-line). But a grep for production callers reveals:

```
/home/work/hashhog/rustoshi/crates/consensus/src/lib.rs:62:
    connect_block_with_sequence_locks, contextual_check_block,
    contextual_check_block_header, ...                      # re-export only
/home/work/hashhog/rustoshi/crates/consensus/src/validation.rs:914:
    pub fn contextual_check_block_header(                   # definition
```
and **zero** other hits across `crates/`, `rustoshi/src/`, `crates/network/`,
`crates/rpc/`. Every other hit is inside the test block at line 4901+.

The header-sync wire-in at `rustoshi/src/main.rs:2547-2598` hand-rolls
a PARTIAL replacement that checks:
- `header.timestamp > now + MAX_FUTURE_BLOCK_TIME` (Core gate 3)
- `header.timestamp <= MTP` (Core gate 1)

…and OMITS gate 2 (BIP-94 timewarp). It also omits gates 4-6 (nVersion
by height — BUG-18).

`process_block` (chain_state.rs:475-477) re-checks gate 1 only:
```rust
if prev_block_mtp > 0 && block.header.timestamp <= prev_block_mtp {
    return Err(ValidationError::TimeTooOld);
}
```
No BIP-94 re-check there either.

Net result on testnet4: any peer can feed a block at height
multiple-of-2016 with `nTime < prev.nTime - 600`, and rustoshi accepts
it. Core rejects with `bad-time-timewarp`. Chain split candidate.

**File:** `crates/consensus/src/validation.rs:914-986` (definition,
dead); `rustoshi/src/main.rs:2547-2598` (partial replacement, missing
BIP-94); `crates/consensus/src/chain_state.rs:475-477` (also missing
BIP-94).

**Core ref:** `bitcoin-core/src/validation.cpp:4097-4105`.

**Excerpt (rustoshi, missing gate at chain_state):**
```rust
// chain_state.rs:475-477
if prev_block_mtp > 0 && block.header.timestamp <= prev_block_mtp {
    return Err(ValidationError::TimeTooOld);
}
// MISSING: BIP-94 gate
// if params.enforce_bip94 && new_height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
//     if (block.header.timestamp as i64) < (prev_block.timestamp as i64) - MAX_TIMEWARP {
//         return Err(ValidationError::TimeTimewarpAttack);
//     }
// }
```

**Impact:** testnet4 chain split at every retarget boundary (height
multiple-of-2016) if a malicious peer chooses to exercise the gap.
The error variant `ValidationError::TimeTimewarpAttack` (validation.rs:90)
is defined but never returned outside the test block.

---

## BUG-7 (P0-CDIV — cross-cite W154 BUG-12) — `mintime` GBT field skips BIP-94 timewarp clamp

**Severity:** P0-CDIV (already catalogued in W154 BUG-12; re-listed
here as the W157 perimeter touches the same code path for the signet/
miner aspect).

Bitcoin Core's `GetMinimumTime` (miner.cpp:36-47) ALWAYS clamps to
`max(MTP+1, prev_time - MAX_TIMEWARP)` at retarget boundaries
regardless of `enforce_BIP94`:
```cpp
int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
const int height{pindexPrev->nHeight + 1};
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time,
                                 pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
return min_time;
```
The inline Core comment is explicit: "Account for BIP94 timewarp rule
on all networks. This makes future activation safer."

Rustoshi (`server.rs:4316`):
```rust
mintime: (median_time_past + 1) as u32,
```
No retarget-boundary detection, no MAX_TIMEWARP clamp. On testnet4 at
height multiple-of-2016, rustoshi advertises a `mintime` lower than
Core's; a naive miner trusting that value would mine a block that
rustoshi accepts (no receive-side BIP-94 — see BUG-6) but Core rejects.

**File:** `crates/rpc/src/server.rs:4316`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`,
`bitcoin-core/src/rpc/mining.cpp:1004`.

**Impact:** GBT `mintime` field diverges from Core at retarget boundaries
on all networks; particularly impactful on testnet4 where Core enforces
receive-side and would reject the resulting block.

---

## BUG-8 (P1) — `build_block_template` accepts caller-supplied `timestamp` with no internal clamp

**Severity:** P1 (defense-in-depth gap; caller is responsible for
clamping but BUG-7 shows the caller drops the ball).

Bitcoin Core's `BlockAssembler::Create` calls `UpdateTime` which calls
`GetMinimumTime` and writes the clamped value into the header
(miner.cpp:49-64). The miner cannot pass a `timestamp` that violates
BIP-94.

Rustoshi's `build_block_template` signature (`block_template.rs:290-300`):
```rust
pub fn build_block_template(
    mempool: &Mempool,
    prev_hash: Hash256,
    height: u32,
    timestamp: u32,                // caller-supplied
    bits: u32,
    median_time_past: i64,
    params: &ChainParams,
    config: &BlockTemplateConfig,
) -> BlockTemplate
```
Line 516 writes `timestamp` directly into `BlockHeader.timestamp` with no
clamp:
```rust
let header = BlockHeader {
    version: block_version,
    prev_block_hash: prev_hash,
    merkle_root: computed_merkle_root,
    timestamp,           // raw caller value
    bits,
    nonce: 0,
};
```

The `is_final_tx(...)` call inside the loop (line 333, 434) uses
`median_time_past` not `timestamp`, so the lock-time filtering is
correct. But the resulting block's `nTime` field is whatever the caller
passed — including values that violate BIP-94. The two callers in the
repo (GBT at server.rs:4173 and mine_single_block at server.rs:9444)
BOTH pass un-clamped values.

**File:** `crates/consensus/src/block_template.rs:295, 516`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-64` (`UpdateTime`).

**Impact:** template assembler emits blocks with arbitrary `nTime`; no
defensive clamp. The fix point of "all blocks must pass receive-side
validation" is the only safety net, and BUG-6 shows it's compromised.

---

## BUG-9 (P1) — `mine_single_block` uses raw `now` with no GetMinimumTime clamp

**Severity:** P1 (regtest-only path; not customer-facing, but mirrors
the BUG-7 / BUG-8 pattern, and would matter the moment someone wires
`mine_single_block` into a testnet4 / signet fast-mining mode).

`server.rs:9430-9432`:
```rust
let median_time_past = if timestamps.is_empty() {
    now as i64
} else {
    timestamps.sort();
    timestamps[timestamps.len() / 2] as i64
};

// Timestamp must be strictly greater than MTP
let timestamp = std::cmp::max(now, (median_time_past + 1) as u32);
```
The `max(now, MTP+1)` half is correct; the BIP-94 half is missing. Note
also the `median_time_past` derivation uses the simple-median over
collected timestamps rather than `CBlockIndex::GetMedianTimePast` proper
(skips ancestor-walk and the 11-block window edge case where fewer
than 11 ancestors exist).

`mine_single_block` is only called from `generate_to_address` and
`generate_block` (both regtest-only, line 5533, 5568). regtest has
`pow_no_retargeting=true`, so the retarget-boundary case never fires in
practice. But the SHAPE is wrong, and the function is one network-flag
change away from miscompiling on testnet4.

**File:** `crates/rpc/src/server.rs:9405-9432`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-64`.

**Impact:** latent on regtest (`pow_no_retargeting=true`); active if
mine_single_block ever runs on a retargeting network.

---

## BUG-10 (P1) — `mine_single_block` reads parent `bits` directly; no `get_next_work_required`

**Severity:** P1 (cross-cite W154 BUG-1 for lunarblock pattern).

`server.rs:9405-9411`:
```rust
// Get the bits from the previous block (for regtest, it stays constant)
let bits = store
    .get_header(&prev_hash)
    .ok()
    .flatten()
    .map(|h| h.bits)
    .unwrap_or(0x207fffff); // Regtest default difficulty
```

On regtest with `pow_no_retargeting=true`, this is correct — Core
returns `pindexLast->nBits` unchanged. But the SHAPE is wrong: Core's
`GetNextWorkRequired` is the authoritative function; on a network where
`mine_single_block` was called with `pow_no_retargeting=false`, the
result would be wrong at every retarget boundary.

The GBT path (server.rs:4090-4162) DOES call `get_next_work_required`
correctly — so the GBT mainnet-style mining flow is fine. The
mine_single_block shortcut bypasses that and would mint blocks at the
wrong difficulty if extended to non-regtest networks.

**File:** `crates/rpc/src/server.rs:9405-9411`.

**Core ref:** `bitcoin-core/src/pow.cpp:14-48` (`GetNextWorkRequired`).

**Impact:** regtest-only today; latent foot-gun if generateblock ever
gains testnet support.

---

## BUG-11 (P1 — cross-cite W154 BUG-13) — `ComputeBlockVersion` in GBT always returns `0x20000000`

**Severity:** P1 (BIP-9 signaling broken; harmless on networks where
all deployments are always-active or buried, e.g. signet/testnet4/regtest;
matters on testnet3 and any future BIP-9 deployment on mainnet).

Bitcoin Core's `BlockAssembler::Create` (miner.cpp:140) calls
`m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev,
consensus_params)` — with the parent block index — to derive the version
that signals STARTED/LOCKED_IN deployments.

Rustoshi `build_block_template` (`block_template.rs:487-509`):
```rust
let block_version = config.block_version.unwrap_or_else(|| {
    struct NoBlock;
    impl VersionbitsBlockInfo for NoBlock { /* all `unreachable!()` */ }

    let deployments_map = get_deployments(params);
    let pairs: Vec<(&DeploymentId, &BIP9Deployment)> =
        deployments_map.iter().collect();
    // No prev-block chain context available without a full block index;
    // use the None overload which signals all STARTED/LOCKED_IN forks
    // based on params alone.  Callers with chain access should pass
    // block_version explicitly via BlockTemplateConfig::block_version.
    compute_block_version::<NoBlock>(None, &pairs, None)
});
```
With `block=None`, `get_state_for` (versionbits.rs:285-302) returns:
- `Active` for ALWAYS_ACTIVE deployments,
- `Failed` for NEVER_ACTIVE,
- `Defined` for everything else.

`compute_block_version` (versionbits.rs:504-520) only ORs in deployment
bits for `Started | LockedIn`. Therefore `block=None` ALWAYS returns
`0x20000000` (the `VERSIONBITS_TOP_BITS` baseline) regardless of params.

On testnet3 the consequence is non-trivial: any BIP-9 deployment in
STARTED or LOCKED_IN state should be signaled by miners running
rustoshi, but the GBT-derived version omits the bits.

The GBT caller (server.rs:4065) does not set `config.block_version`
explicitly, so the `NoBlock` path always fires.

**File:** `crates/consensus/src/block_template.rs:487-509`;
`crates/rpc/src/server.rs:4164-4178` (caller not setting
`block_version`).

**Core ref:** `bitcoin-core/src/node/miner.cpp:140`
(`m_versionbitscache.ComputeBlockVersion(pindexPrev, ...)`).

**Impact:** BIP-9 deployment signaling broken in GBT for any network
with active BIP-9 deployments (effectively testnet3 + future mainnet
forks).

---

## BUG-12 (P0-CONS) — `signet_pow_limit()` differs from Core by orders of magnitude

**Severity:** P0-CONS (signet PoW gate is dramatically weaker than
Core — accepts blocks Core rejects).

Bitcoin Core (`kernel/chainparams.cpp:467`):
```cpp
consensus.powLimit = uint256{
    "00000377ae000000000000000000000000000000000000000000000000000000"
};
```
That is 5 leading bytes `00 00 03 77 ae` followed by 27 zero bytes.

Rustoshi (`params.rs:1064-1075`):
```rust
/// Signet PoW limit: 00000377aeffffffffffffffffffffffffffffffffffffffffffffffffffffffff
fn signet_pow_limit() -> [u8; 32] {
    let mut limit = [0u8; 32];
    limit[0] = 0x00;
    limit[1] = 0x00;
    limit[2] = 0x03;
    limit[3] = 0x77;
    for byte in limit.iter_mut().skip(4) {
        *byte = 0xff;
    }
    limit
}
```
Effective value: `00 00 03 77 ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff` — that is, `0xae` is OMITTED
from byte 4 and every subsequent byte (4..32) is set to `0xff`.

The numeric ratio between the two limits:
- Core: `0x00000377 ae00000000000000000000000000000000000000000000000000000000`
- rustoshi: `0x00000377 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`
- rustoshi / Core ≈ `0xff00..00 / 0xae00..00` ≈ 1.5× by the most-significant
  byte alone, but the trailing-zero-vs-trailing-ff cascade adds another
  ~10^57 of effective permissiveness for hashes near the boundary.

The docstring comment ALSO contains the bug — it claims
`00000377aeffffffffffff...` (missing `ae` after `0377`).

Net effect: rustoshi's signet accepts blocks Core would reject as
`high-hash` / `bad-diffbits`. PoW is meaningfully weakened. Combined
with BUG-1 (no signet signature check), the signet consensus surface
is effectively unprotected.

**File:** `crates/consensus/src/params.rs:1064-1075`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:467`.

**Excerpt (correct shape):**
```rust
fn signet_pow_limit() -> [u8; 32] {
    let mut limit = [0u8; 32];
    limit[0] = 0x00;
    limit[1] = 0x00;
    limit[2] = 0x03;
    limit[3] = 0x77;
    limit[4] = 0xae;       // <-- MISSING
    // bytes 5..32 stay zero (they are the default)
    limit
}
```

**Impact:** signet PoW gate is broken; rustoshi accepts blocks no other
signet node would accept. Cross-cite BUG-1 — together they yield a
signet implementation that has neither correct PoW nor correct
signature checking.

---

## BUG-13 (P1) — Signet checkpoints are pattern-fabricated hashes

**Severity:** P1 (any real-signet sync past height 1000 will fail).

Bitcoin Core has ZERO checkpoints for signet (`kernel/chainparams.cpp:451+`
populates no `checkpointData`). Rustoshi defines two:

```rust
// crates/consensus/src/params.rs:914-917
checkpoints: Checkpoints::from_pairs(&[
    (1000, "00000030db7cd0c0fab1c0f4b3e6c2d1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5"),
    (50000, "00000024b5c8f7d6e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"),
]),
```
The hash bytes are pattern-fabricated:
- `db7cd0c0fab1c0f4b3e6c2d1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5` — sequential
  nibble pattern, betrays placeholder.
- `b5c8f7d6e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0` — same
  pattern, descending.

On a real signet IBD, when rustoshi reaches height 1000 it will compare
the actual block hash against the fabricated value, mismatch, and emit
a checkpoint-error. The node would refuse to advance past height 1000.

**File:** `crates/consensus/src/params.rs:914-917`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp` (no
checkpointData for signet).

**Impact:** rustoshi cannot sync real signet (would also fail BUG-1
+ BUG-12, but the checkpoint mismatch fires first).

---

## BUG-14 (P1) — Testnet4 checkpoints are pattern-fabricated hashes

**Severity:** P1 (any testnet4 sync past height 10000 will fail).

Same shape as BUG-13 for testnet4 (`params.rs:831-834`):
```rust
checkpoints: Checkpoints::from_pairs(&[
    (10000, "00000000c3afe3c8c0cc7bea7e6c0f6e67d5c1f9b2a0e8d7c6b5a4f3e2d1c0b9"),
    (50000, "000000000001a8c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2"),
]),
```
The nibble pattern `c3afe3c8c0cc7bea7e6c0f6e67d5c1f9b2a0e8d7c6b5a4f3e2d1c0b9`
and `a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2` are both
descending-hex sequences. Core has no testnet4 checkpoints either.

**File:** `crates/consensus/src/params.rs:831-834`.

**Impact:** testnet4 IBD wedges at height 10000; rustoshi cannot sync
real testnet4.

---

## BUG-15 (P1) — Signet `assumed_valid_block` / `assumed_valid_height` absent

**Severity:** P1 (slow signet IBD; cross-cite W149 BUG-7 for blockbrew).

Bitcoin Core sets (`kernel/chainparams.cpp:436`):
```cpp
consensus.defaultAssumeValid = uint256{
    "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329"
}; // height 293,175
```

Rustoshi (`params.rs:909-910`):
```rust
assumed_valid_block: None,
assumed_valid_height: None,
```
No assume-valid hash; every signet IBD revalidates every signature from
genesis to tip.

**File:** `crates/consensus/src/params.rs:909-910`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:436`.

**Impact:** signet IBD wall-clock is multiple hours longer than Core.

---

## BUG-16 (P0-DEAD) — `contextual_check_block_header` defined but has zero production callers

**Severity:** P0-DEAD (six gates inside the function are entirely dead).

Cross-cite BUG-6; this is the "function-definition-as-dead-code" framing
of the same gap. The function (`validation.rs:914-986`) implements:
- Gate 1: BIP-113 MTP+1 (`block_time <= mtp` → TimeTooOld)
- Gate 2: BIP-94 timewarp (`enforce_bip94` + retarget boundary)
- Gate 3: 7200s future-drift
- Gates 4-6: nVersion < 2|3|4 by BIP-34/65/66 height

All six gates are unreachable in production. The function appears in:
- The re-export at `lib.rs:62` (exported as a public API)
- The definition at `validation.rs:914`
- 32 internal-test callsites (validation.rs:4935-5343)

Zero production callers. The two header-validation paths (`main.rs:2547`
for the headers-sync wire, `chain_state.rs:475` for the body-validation
wire) both hand-roll partial subsets of the gates, with documented
omissions.

**File:** `crates/consensus/src/validation.rs:914-986`.

**Core ref:** `bitcoin-core/src/validation.cpp::ContextualCheckBlockHeader`
— always called from `AcceptBlockHeader`.

**Impact:** "two-pipeline guard" pattern (test-pipeline vs production-
pipeline diverge); fleet-wide pattern (W138/W140/W144 catalog 14+
instances across impls).

---

## BUG-17 (P1) — `accept_block_header_chain_work` not called from header-sync path

**Severity:** P1 (low-work header DoS-protection bypassed at the wire).

Bitcoin Core's `AcceptBlockHeader` (validation.cpp:4229-4231) rejects
headers whose accumulated chain work is below `MinimumChainWork()`
UNLESS `min_pow_checked=true` (the PRESYNC pipeline has already vetted
the chain).

Rustoshi defines `accept_block_header_chain_work` (`validation.rs:1018-1067`)
correctly. Production callers:
- `crates/storage/src/w109_block_index_gates.rs:713-721` — only inside a
  documentation-only gate-coverage module (the file is named `w109_*`,
  i.e. a wave-audit harness, not production).
- `crates/consensus/tests/w97_accept_block_gates.rs:253, 279` — test
  harness.

The actual header-sync wire-in at `main.rs:2542-2612` calls
`block_store.put_header(...)` then `block_store.put_height_index(...)`
directly, with no chain-work-gate invocation. Headers below
`minimum_chain_work` are accepted on the wire and stored. A malicious
peer can fill the header DB with low-work garbage during IBD.

**File:** `crates/consensus/src/validation.rs:1018-1067`;
`rustoshi/src/main.rs:2542-2612` (caller, missing the gate).

**Core ref:** `bitcoin-core/src/validation.cpp:4229-4231`.

**Impact:** low-work header flood not gated on the wire; DB bloat;
amplifies the `MinimumChainWork` cross-cite from W149 BUG-10
(blockbrew).

---

## BUG-18 (P0-CDIV) — Header-sync wire omits nVersion BIP-34/65/66 height-gated rejection

**Severity:** P0-CDIV (wasted IBD work; possible mid-IBD wedge if a peer
floods 2000 wrong-version headers).

Bitcoin Core's `contextual_check_block_header` (validation.cpp:4113-4118)
rejects headers with:
- `version < 2 && height >= BIP34Height`
- `version < 3 && height >= BIP66Height`
- `version < 4 && height >= BIP65Height`

Rustoshi's `contextual_check_block_header` (validation.rs:977-983) has
the gate; but as BUG-16 shows, the function is dead. The header-sync
wire-in at `main.rs:2547-2598` runs only the BIP-113 MTP check and the
7200s future-drift check; nVersion-by-height is omitted.

A peer can serve a 2000-header batch with nVersion=1 at height >= 388381
(mainnet BIP65) and rustoshi will (a) store every header in the DB and
(b) only catch the error when `process_block` tries to body-validate
each block, by which point the IBD state has wasted bandwidth and disk
on garbage.

**File:** `rustoshi/src/main.rs:2547-2598`;
`crates/consensus/src/validation.rs:977-983` (correct gate, dead).

**Core ref:** `bitcoin-core/src/validation.cpp:4113-4118`.

**Impact:** wasted IBD work; amplifies BUG-16 by another fleet-pattern
instance.

---

## BUG-19 (P1) — Signet `dns_seeds` includes a bare IP address

**Severity:** P1 (operational; not consensus).

Bitcoin Core's signet `vSeeds` (chainparams.cpp:447-449) is a single
DNS hostname: `seed.signet.bitcoin.sprovoost.nl`.

Rustoshi (`params.rs:890-893`):
```rust
dns_seeds: vec![
    "seed.signet.bitcoin.sprovoost.nl",
    "178.128.221.177",                  // <-- bare IP
],
```
The bare-IP entry is a static peer rather than a DNS seed. DNS-seed
resolution code (rustoshi/src/main.rs or crates/network/) generally
expects hostnames it can submit to `getaddrinfo`. A bare IP may resolve
"correctly" (returning the same address) on most resolvers, but the
semantics are wrong — and if the operator at 178.128.221.177 ever
goes down, the seed list silently degrades.

**File:** `crates/consensus/src/params.rs:892`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:447-449`.

**Impact:** brittle seed list; operator-grade gap.

---

## BUG-20 (P1) — `is_segwit_active` family is height-based; ignores BIP-9 STARTED/LOCKED_IN states

**Severity:** P1 (effective on networks where the deployment is
BIP-9-driven rather than height-buried; mainnet/testnet3 historical
behaviour).

Rustoshi (`params.rs:976-989`):
```rust
pub fn is_bip66_active(&self, height: u32) -> bool {
    height >= self.bip66_height
}
pub fn is_csv_active(&self, height: u32) -> bool {
    height >= self.csv_height
}
pub fn is_segwit_active(&self, height: u32) -> bool {
    height >= self.segwit_height
}
pub fn is_taproot_active(&self, height: u32) -> bool {
    height >= self.taproot_height
}
```
This works correctly post-activation on networks with hardcoded
activation heights (mainnet csv_height=419328, etc.). It MISSES the
LOCKED_IN-but-not-yet-ACTIVE window — Core's `DeploymentActiveAt` looks
up the actual versionbits state per parent block, which can transition
through DEFINED → STARTED → LOCKED_IN → ACTIVE across the period
boundary.

The GBT signaling logic in `server.rs:4253-4278` derives signaling via
`get_state_for` + threshold-state matching, but the consensus-side
"is this fork active" lookup uses the simple `height >=` form. On
testnet3 mainline, this is consequential only during the specific
locked-in window for each fork; post-activation the two pipelines
converge.

**File:** `crates/consensus/src/params.rs:976-989`.

**Core ref:** `bitcoin-core/src/deploymentstatus.h::DeploymentActiveAt`
(uses versionbits cache, not raw height).

**Impact:** consensus-vs-mining-signaling skew during the LOCKED_IN
window of any future BIP-9 deployment.

---

## BUG-21 (P1) — `compact_to_target` returns `[0xff; 32]` on exponent overflow; not Core's `{return {}, fOverflow=true}`

**Severity:** P1 (currently correctness-by-accident; type-contract leak).

Bitcoin Core's `arith_uint256::SetCompact(nBits, &fNegative, &fOverflow)`
sets `fOverflow=true` and returns 0 when the mantissa+exponent would
exceed 256 bits. `DeriveTarget` (pow.cpp:155) then checks
`fOverflow || bnTarget > UintToArith256(pow_limit)` and short-circuits.

Rustoshi (`params.rs:1395-1398`):
```rust
if exponent > 32 {
    // Target would overflow 256 bits
    return [0xffu8; 32];
}
```
This returns the max-256-bit target, which then COMPARES GREATER than
any pow_limit, so `check_proof_of_work` (pow.rs:633) returns false. The
end-to-end behaviour is correct, but the path is:
- "overflow" → "max target" → "max target > pow_limit" → "reject"

rather than:
- "overflow" → "explicit overflow flag" → "reject"

If a future change adds a code path that consumes the 32-byte target
WITHOUT comparing against pow_limit (e.g., a hex-encoder for RPC), it
will silently report `ffff...ff` as a legitimate target.

**File:** `crates/consensus/src/params.rs:1395-1398`;
`crates/consensus/src/pow.rs:625-643`.

**Core ref:** `bitcoin-core/src/pow.cpp:146-159` (`DeriveTarget`).

**Impact:** latent — current consumers happen to compare against
pow_limit; future code may not.

---

## BUG-22 (P1) — `process_block` validates `prev_block_mtp > 0` to gate the MTP check (regresses genesis-adjacent strictness)

**Severity:** P1 (small consensus surface; genesis-adjacent only).

`chain_state.rs:475-477`:
```rust
if prev_block_mtp > 0 && block.header.timestamp <= prev_block_mtp {
    return Err(ValidationError::TimeTooOld);
}
```
The `prev_block_mtp > 0` guard is intended to handle the "no parent
blocks" case (genesis + first few children) where MTP is conventionally
0 and the strict-greater check would reject every block with
`timestamp == 0` (which is impossible anyway, but the guard is
defensive).

Core's `CBlockIndex::GetMedianTimePast` returns `block.GetBlockTime()`
for blocks with fewer than 11 ancestors (not 0). Then the strict-greater
check is meaningful at every height. By returning 0 in the
genesis-adjacent case, rustoshi accepts a child with
`block.header.timestamp == 0` (impossible) AND a child with
`block.header.timestamp = parent.timestamp` (possible — and Core would
accept it too if the parent has < 11 ancestors).

Net divergence: rustoshi accepts `timestamp <= parent.timestamp` for
genesis + first 10 children; Core rejects `timestamp <= median-of-actual-
ancestors`. The intersection is small but not empty.

**File:** `crates/consensus/src/chain_state.rs:475-477`;
`compute_prev_block_mtp` definition (search for callsite around
`server.rs:4084`).

**Core ref:** `bitcoin-core/src/chain.h::CBlockIndex::GetMedianTimePast`.

**Impact:** small divergence on the first ~11 blocks; mostly cosmetic.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CONS:** 5 (BUG-1, BUG-2, BUG-4, BUG-6, BUG-12)
- **P0-CDIV:** 2 (BUG-7, BUG-18)
- **P0-DEAD:** 1 (BUG-16)
- **P1:** 14 (BUG-3, BUG-5, BUG-8, BUG-9, BUG-10, BUG-11, BUG-13,
  BUG-14, BUG-15, BUG-17, BUG-19, BUG-20, BUG-21, BUG-22)

5 + 2 + 1 + 14 = 22 ✓

**Fleet patterns confirmed (cross-cites)**:
- **Signet `CheckSignetBlockSolution` absent**: 3rd impl confirmed
  fleet-wide (after W143 BUG-9 blockbrew + W155 BUG-25 hotbuns).
  Cluster of P0-CONS findings: BUG-1 (function absent) + BUG-2
  (params absent) + BUG-4 (header constant absent) + BUG-12 (pow_limit
  wrong) — four-bug architectural gap.
- **BIP-94 MAX_TIMEWARP absent on miner side**: 4th+ impl confirmed
  fleet-wide (W154 BUG-7/BUG-11/BUG-12 camlcoin/beamchain/rustoshi
  echo). Rustoshi BUG-7 is the same code path as W154 BUG-11+12; W157
  refocuses on the validation-side companion gap (BUG-6 — dead
  `contextual_check_block_header`).
- **Two-pipeline guard 17th distinct extension** (BUG-16) — test-only
  function with full body, production wires hand-roll partial subsets.
  Rustoshi already had W76+ tracked instances; this is the first time
  the SAME function defines all gates AND none of them run in
  production.
- **`compute_block_version` always `0x20000000` in GBT** (BUG-11) — same
  shape as W154 BUG-13.
- **Comment-as-confession**: BUG-12 docstring lies (claims
  `00000377ae...ff` but implementation drops the `ae`); BUG-8 + BUG-11
  inline comments admit the gap (BUG-8: "caller is responsible";
  BUG-11: "the None overload which signals all STARTED/LOCKED_IN forks
  based on params alone" — except it doesn't, because get_state_for
  with `None` returns Defined never Started/LockedIn).
- **Pattern-fabricated chainparams data** (BUG-13 + BUG-14) — first
  rustoshi instance of fabricated-checkpoints fleet pattern.
- **Dead-data plumbing** (BUG-16, BUG-17, BUG-20) — 4th rustoshi
  instance tracked in W76+ catalog.
- **Genesis-adjacent edge case** (BUG-22) — small but echoes
  `IsBIP30Repeat`-shape blockbrew W149 BUG-12.

**Top three findings:**
1. **BUG-1 + BUG-2 + BUG-4 + BUG-12 cluster (P0-CONS, signet
   foundation)** — `CheckSignetBlockSolution` function does not exist,
   the consensus-param fields (`signet_blocks`, `signet_challenge`) do
   not exist, the `SIGNET_HEADER=0xecc7daa2` tag constant does not
   exist, AND the signet `pow_limit` differs from Core by orders of
   magnitude. Net effect: rustoshi has no signet implementation
   whatsoever beyond the network-name string. Forks off real signet at
   block 1. Accepts attacker-mined blocks freely. Cross-cite W143
   BUG-9 (blockbrew) + W155 BUG-25 (hotbuns); now ≥3 of 10 impls
   confirmed signet-broken at this severity.
2. **BUG-6 + BUG-16 + BUG-17 + BUG-18 cluster (P0-CONS + P0-DEAD +
   P0-CDIV)** — `contextual_check_block_header` defines all six BIP-113
   / BIP-94 / future-drift / nVersion-by-height gates but is entirely
   dead production code; the header-sync wire-in
   (`rustoshi/src/main.rs:2547-2598`) hand-rolls a partial subset that
   omits the BIP-94 timewarp gate AND the nVersion-by-height gate AND
   the `accept_block_header_chain_work` gate. Testnet4 chain split
   candidate at every retarget boundary (height multiple-of-2016) when
   a peer feeds `nTime < prev.nTime - 600`. Mainnet/testnet3
   nVersion-too-low headers are accepted into the DB.
3. **BUG-7 + BUG-8 + BUG-9 + BUG-10 + BUG-11 cluster (P0-CDIV + P1
   miner-side)** — the miner-template assembly path drops every Core
   defense-in-depth check on `nTime`/`nBits`/`nVersion`:
   `GetMinimumTime` BIP-94 clamp absent (BUG-7), `build_block_template`
   has no internal clamp (BUG-8), `mine_single_block` has neither
   timestamp clamp nor `get_next_work_required` invocation (BUG-9 +
   BUG-10), and the resulting `nVersion` is permanently `0x20000000`
   (BUG-11). The miner emits templates that BUG-6 then rubber-stamps on
   the receive side — the consensus surface is unprotected on both
   ends.
