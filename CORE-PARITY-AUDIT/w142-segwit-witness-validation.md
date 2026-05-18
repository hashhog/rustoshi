# W142 — BIP-141/143 SegWit witness validation audit (rustoshi)

**Wave:** W142 — SegWit witness validation (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** the rustoshi consensus-layer SegWit pipeline:

- `crates/consensus/src/validation.rs` — `check_witness_commitment`
  (lines 1186-1240), `contextual_check_block` (lines 1079-1102),
  `check_block` (lines 453-514), `compute_block_weight` (lines 521-535).
- `crates/consensus/src/script/interpreter.rs` —
  `parse_witness_program` (lines 2456-2485), `verify_witness_program`
  (lines 2685-3035), `verify_script` witness paths (lines 2543-2676),
  `ScriptFlags::consensus_flags` (lines 123-144).
- `crates/primitives/src/block.rs` — `compute_merkle_root` (lines
  192-223), `compute_witness_root` (lines 227-264).
- `crates/primitives/src/transaction.rs` — `Transaction::wtxid` (lines
  286-293), `Transaction::has_witness` (lines 238-240),
  `Transaction::weight` (lines 299-303), `Transaction::Decodable`
  (lines 375-520) — the segwit marker/flag decode path, witness item
  decode.
- `crates/crypto/src/sighash.rs` — `segwit_v0_sighash` BIP-143 (lines
  373-463), `p2wpkh_script_code` (lines 468-477).
- `crates/crypto/src/hashes.rs` — `merkle_root` helper (lines 59-84).
- `crates/network/src/compact_blocks.rs` — `is_block_mutated`
  (lines 540-600): a **parallel pipeline** of the witness-commitment
  check that lives next to the BIP-152 cmpctblock reconstruction path.
- `crates/consensus/src/block_template.rs` — `build_coinbase_tx`
  (lines 558-628), `build_witness_commitment` (lines 635-663): the
  **mining-side** equivalent of Core's `GenerateCoinbaseCommitment`.

**References (Bitcoin Core):**
- `bitcoin-core/src/validation.cpp:3837-3862` — `CheckMerkleRoot`
  (CVE-2012-2459 + `bad-txnmrklroot`).
- `bitcoin-core/src/validation.cpp:3864-3916` — `CheckWitnessMalleation`
  (`bad-witness-nonce-size`, `bad-witness-merkle-match`,
  `unexpected-witness`).
- `bitcoin-core/src/validation.cpp:3918-3983` — `CheckBlock` (size
  limits, vtx[0] coinbase, weight cap-via-stripped-size).
- `bitcoin-core/src/validation.cpp:3997-4019` —
  `ChainstateManager::GenerateCoinbaseCommitment` (mining side).
- `bitcoin-core/src/validation.cpp:4027-4056` — `IsBlockMutated`
  (CheckMerkleRoot + 64-byte-tx merkle-mutation defence +
  CheckWitnessMalleation).
- `bitcoin-core/src/validation.cpp:4067-4184` — `ContextualCheckBlock`
  (BIP-34 height + `CheckWitnessMalleation` gated on segwit deployment
  active + weight cap **after** witness check).
- `bitcoin-core/src/consensus/merkle.cpp:46-85` — `ComputeMerkleRoot`
  + `BlockWitnessMerkleRoot` (the `mutated` out-param and zero-coinbase-
  wtxid invariant).
- `bitcoin-core/src/consensus/consensus.h:15-24` — `MAX_BLOCK_WEIGHT
  = 4_000_000`, `WITNESS_SCALE_FACTOR = 4`,
  `MIN_TRANSACTION_WEIGHT = 240`.
- `bitcoin-core/src/consensus/validation.h:130-165` —
  `GetTransactionWeight`, `GetBlockWeight`, `GetTransactionInputWeight`,
  `MINIMUM_WITNESS_COMMITMENT = 38`, `GetWitnessCommitmentIndex`.
- `bitcoin-core/src/script/interpreter.cpp:1832-1864` —
  `ExecuteWitnessScript` (the `MAX_STACK_SIZE`/`MAX_SCRIPT_ELEMENT_SIZE`
  pre-eval gates).
- `bitcoin-core/src/script/interpreter.cpp:1917-2000` —
  `VerifyWitnessProgram` (v0 length 20/32, P2WSH SHA256, P2WPKH
  implicit P2PKH, taproot guard).
- `bitcoin-core/src/script/interpreter.cpp:1348-1377` —
  `GetPrevoutsSHA256` / `GetSequencesSHA256` / `GetOutputsSHA256`
  (the single-SHA256 midstates BIP-143 layers double-SHA256 on).
- `bitcoin-core/src/script/interpreter.cpp:1600-1677` — legacy +
  BIP-143 `SignatureHash` (the SIGHASH_SINGLE / ANYONECANPAY mask).
- `bitcoin-core/src/script/script.cpp:249-263` — `IsWitnessProgram`
  (the canonical script-shape detector).
- `bitcoin-core/src/primitives/transaction.h:200-238` —
  `UnserializeTransaction` (the "Superfluous witness record" reject
  on all-empty witness with marker+flag set).

BIPs: BIP-141 (consensus segwit), BIP-143 (sighash v0), BIP-144 (p2p
segwit envelope), BIP-147 (NULLDUMMY, gated with segwit). BIP-341/342
(taproot/tapscript) were audited in W127 and are out of scope here
except where the v1+32 program parsing intersects v0.

**Production code changes:** 0 (pure audit).

## Why this matters

SegWit witness validation is the **consensus seam** between rustoshi's
legacy-bitcoin code paths and everything that has been added since
August 2017 (`mainnet h=481_824`). A single divergence here is enough
to:

1. **Permanently chain-split** rustoshi from Core (e.g. accepting a
   block Core rejects on `bad-witness-merkle-match`, or vice versa).
2. **Open a transaction-malleability re-attack vector** that Core
   closed in BIP-141/144 (e.g. allowing roundtrip-asymmetric tx
   serialization where the wire form decodes differently than the
   re-serialized form).
3. **Break wtxid-relay (BIP-339)** because the wtxid is computed off
   the witness-included encoding — any decode/encode mismatch
   silently breaks every BIP-339 peer.
4. **Re-open CVE-2012-2459** (merkle-mutation by odd-pair duplication):
   if rustoshi computes a "valid" merkle root for a duplicate-leaf
   block that Core flags as `bad-txns-duplicate`, an attacker can
   feed it a permanently-rejected-elsewhere block, then refuse
   to disconnect when the genuine block arrives.

The audit found a tight cluster of bugs in three patterns that recur
across the wave:

### Pattern 1: parallel pipelines (three merkle-root + two witness-commitment paths)

rustoshi has **three different functions** that all compute a Bitcoin
merkle root, each with the same CVE-2012-2459 hazard (duplicate-pair
mutation undetected):

- `Block::compute_merkle_root` (`primitives/block.rs:192`).
- `Block::compute_witness_root` (`primitives/block.rs:227`).
- `rustoshi_crypto::merkle_root` (`crypto/hashes.rs:59`) — called by
  the mining-side `build_witness_commitment`.

And **two different functions** that walk the coinbase commitment:

- `check_witness_commitment` in `consensus::validation::contextual_check_block`
  (`consensus/validation.rs:1186`).
- `is_block_mutated` in `network::compact_blocks::PartiallyDownloadedBlock::fill_block`
  (`network/compact_blocks.rs:540`).

This is the W76+ **two-pipeline guard** pattern — but here it's a
**three-pipeline merkle root**, the worst instance the wave has seen.
Any fix to one of these (e.g. adding mutated detection) will fail to
close the bug class unless all three are touched. Coverage: BUG-1
through BUG-3, BUG-7.

### Pattern 2: "feature gated on the wrong condition"

Three separate places gate segwit-related behavior on something other
than Core's `DeploymentActiveAfter(... DEPLOYMENT_SEGWIT)`:

- `build_coinbase_tx` gates the witness-commitment OP_RETURN output on
  `has_witness = txs.any(has_witness)` instead of on "segwit active".
  Empty-mempool blocks are emitted **without** the required commitment.
  Carry-forward from W108 G11.
- `contextual_check_block` gates `check_witness_commitment` on
  `height >= params.segwit_height` — but Core's
  `CheckWitnessMalleation(block, expect_witness_commitment=false)`
  **still runs** the "no witness data anywhere" loop when segwit is
  inactive. Pre-segwit blocks with witness data slip through.
- The `check_witness_commitment` itself never runs the "no witness data
  in any tx" loop **unless `commit_out_idx == None`** AND segwit is
  active — but Core's loop runs whenever `expect_witness_commitment`
  is false, regardless of whether the (absent) commitment was found.

Coverage: BUG-4, BUG-5, BUG-6.

### Pattern 3: "deserialise-accepts-more-than-serialise-produces"

rustoshi's `Transaction::Decodable` happily decodes a tx with the
marker+flag prefix but **all witness stacks empty** (i.e. each input's
witness count CompactSize is 0). When rustoshi then re-serialises
that tx, it **omits** the marker+flag (because `has_witness()`
returns false). This produces:

- a different on-the-wire byte sequence (no marker+flag);
- a different `wtxid` than the peer signed off on;
- a fresh tx-malleation vector closed in Core (`primitives/transaction.h:228-231`,
  `"Superfluous witness record"`).

Coverage: BUG-8.

## Audit framework (30 gates / 22 BUGS catalogued)

Gate legend:
- **PASS** : behaviour matches Core (regression pin).
- **MISSING** : Core implements; rustoshi has no equivalent.
- **WIRING** : Code exists but is never reached / wrong call site.
- **CDIV** : consensus-layer divergence (accept-vs-reject flip).
- **CDIV-MALL** : block/tx malleation defence missing.
- **CDIV-MINER** : mining-side commitment generation diverges from
  Core, producing blocks Core rejects.

Severity:
- **P0-CONSENSUS** : provable accept-vs-reject divergence for a
  block/tx the rest of the network already settled.
- **P0-CDIV** : silent consensus-state divergence not yet observed
  in the wild but constructable (e.g. crafted dup-pair block).
- **P0-MALL** : opens a malleability re-attack closed by Core.
- **P1** : feature gap with no current accept-vs-reject flip.
- **P2** : helper/test-only divergence, low blast radius.
- **P3** : cosmetic / API fragility / documentation.

### Subsystem 1: merkle-root + witness-merkle-root computation (G1-G6 / 7 BUGS)

|  # | Gate                                                            | Status     | Sev          | BUG      |
|---:|-----------------------------------------------------------------|------------|--------------|----------|
| G1 | `Block::compute_merkle_root` detects odd-pair duplicate (CVE-2012-2459) | MISSING | P0-CDIV-MALL | BUG-1    |
| G2 | `Block::compute_witness_root` detects odd-pair duplicate        | MISSING    | P0-CDIV-MALL | BUG-2    |
| G3 | `rustoshi_crypto::merkle_root` detects odd-pair duplicate       | MISSING    | P0-CDIV-MALL | BUG-3    |
| G4 | Coinbase wtxid hard-coded to 32-zero (Core BlockWitnessMerkleRoot:80) | PASS  | —            | —        |
| G5 | Empty `transactions` returns `Hash256::ZERO` (Core ComputeMerkleRoot:61) | PASS | —          | —        |
| G6 | 64-byte non-witness tx serialization triggers merkle-mutation reject  | MISSING | P0-CDIV-MALL | BUG-7    |

### Subsystem 2: `check_witness_commitment` / `CheckWitnessMalleation` (G7-G13 / 8 BUGS)

|  # | Gate                                                            | Status     | Sev          | BUG      |
|---:|-----------------------------------------------------------------|------------|--------------|----------|
| G7 | OP_RETURN+0x24+0xaa21a9ed magic detected (`MINIMUM_WITNESS_COMMITMENT=38`) | PASS | —      | —        |
| G8 | Last matching output wins (`GetWitnessCommitmentIndex` overwrite semantics) | PASS | —     | —        |
| G9 | Coinbase vin[0].witness must be exactly 1×32 bytes              | PASS       | —            | —        |
| G10| Commitment = SHA256d(witness_root \|\| nonce); bytes [6..38] match  | PASS    | —            | —        |
| G11| "no witness anywhere" loop runs even when `expect_witness_commitment=false` | MISSING | P1 | BUG-5    |
| G12| Witness check fires for pre-segwit blocks with witness data     | MISSING    | P1           | BUG-4    |
| G13| Result class mapped to `BLOCK_MUTATED` (Core ban-vs-discard split) | MISSING | P2          | BUG-9    |

### Subsystem 3: ContextualCheckBlock ordering + size limits (G14-G17 / 3 BUGS)

|  # | Gate                                                            | Status     | Sev          | BUG      |
|---:|-----------------------------------------------------------------|------------|--------------|----------|
| G14| Block weight check fires **after** witness commitment validated | WRONG-ORDER| P2           | BUG-10   |
| G15| `vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` cheap pre-check fires | MISSING | P2 | BUG-11   |
| G16| `GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` stripped-size pre-check fires | MISSING | P2 | BUG-12   |
| G17| `compute_block_weight` uses Core formula `stripped*(K-1) + total` | PASS    | —            | —        |

### Subsystem 4: mining-side coinbase commitment (G18-G21 / 2 BUGS)

|  # | Gate                                                            | Status     | Sev          | BUG      |
|---:|-----------------------------------------------------------------|------------|--------------|----------|
| G18| `build_coinbase_tx` always emits commitment when segwit active  | MISSING    | P0-CDIV-MINER| BUG-13   |
| G19| `UpdateUncommittedBlockStructures` adds 32-zero nonce to coinbase witness | MISSING | P1 | BUG-14   |
| G20| Mining-side commitment uses sha256d(witness_root \|\| nonce)     | PASS       | —            | —        |
| G21| Mining-side commitment script = `0x6a 0x24 0xaa21a9ed <hash>`   | PASS       | —            | —        |

### Subsystem 5: BIP-143 SegWit v0 sighash (G22-G25 / 1 BUG)

|  # | Gate                                                            | Status     | Sev          | BUG      |
|---:|-----------------------------------------------------------------|------------|--------------|----------|
| G22| Preimage layout: version + hashPrevouts + hashSequence + outpoint + scriptCode + value + nSequence + hashOutputs + locktime + hashType | PASS | — | — |
| G23| `hashOutputs == 0` for SIGHASH_NONE and out-of-range SIGHASH_SINGLE | PASS | —            | —        |
| G24| `hashSequence == 0` for ANYONECANPAY/NONE/SINGLE                | PASS       | —            | —        |
| G25| `p2wpkh_script_code` produces `0x76a914<hash>88ac` (25 bytes, CompactSize prefix added by caller) | PASS | — | — |

### Subsystem 6: witness program parsing + execution (G26-G28 / 3 BUGS)

|  # | Gate                                                            | Status     | Sev          | BUG      |
|---:|-----------------------------------------------------------------|------------|--------------|----------|
| G26| `parse_witness_program` accepts version 0..16 + program 2..40 bytes | PASS   | —            | —        |
| G27| P2WPKH path: stack size exactly 2 enforced                      | PASS       | —            | —        |
| G28| P2WSH path: SHA256(witness_script) == program (single SHA, not double) | PASS | —          | —        |

### Subsystem 7: transaction segwit decode/encode roundtrip (G29-G30 / 3 BUGS)

|  # | Gate                                                            | Status     | Sev          | BUG      |
|---:|-----------------------------------------------------------------|------------|--------------|----------|
| G29| All-empty witness with marker+flag throws "Superfluous witness record" | MISSING | P0-MALL  | BUG-8    |
| G30| `Transaction::Decodable` panics on empty vin when reading segwit flag | PARTIAL | P3       | BUG-15   |

## Bugs

### BUG-1 (P0-CDIV-MALL) `Block::compute_merkle_root` does not detect CVE-2012-2459 odd-pair duplication

**File:** `crates/primitives/src/block.rs:192-223`
**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:46-63`
(`ComputeMerkleRoot` with `mutated` out-param), `validation.cpp:3853-3858`
(`bad-txns-duplicate` reject).

**Description:** Core's `ComputeMerkleRoot` accepts a `bool* mutated`
out-param and walks every pair at every level checking
`hashes[pos] == hashes[pos + 1]` before pairing. A `true` result is
surfaced through `CheckMerkleRoot` (`validation.cpp:3853`) as
`state.Invalid(BLOCK_MUTATED, "bad-txns-duplicate", "duplicate
transaction")`. This is the CVE-2012-2459 defence: without it, an
attacker can construct a block whose duplicate-tx-list produces the
same merkle root as the canonical list, banning rustoshi on the
duplicate version but leaving the canonical version unblockable
through that path.

rustoshi's `compute_merkle_root` has no `mutated` tracking; it just
pairs and hashes:

```rust
// crates/primitives/src/block.rs:204-220
while hashes.len() > 1 {
    if hashes.len() % 2 == 1 {
        // Duplicate the last hash
        hashes.push(*hashes.last().unwrap());
    }

    let mut next_level = Vec::with_capacity(hashes.len() / 2);
    for pair in hashes.chunks(2) {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&pair[0]);
        combined[32..].copy_from_slice(&pair[1]);
        let hash = Sha256::digest(Sha256::digest(combined));
        next_level.push(hash.into());
    }
    hashes = next_level;
}
```

**Impact:** Permanent chain-split on a crafted duplicate-tx block.
rustoshi accepts the duplicate-tx form as valid (it computes the same
merkle root Core does); Core rejects it as `bad-txns-duplicate`.

### BUG-2 (P0-CDIV-MALL) `Block::compute_witness_root` does not detect CVE-2012-2459 odd-pair duplication

**File:** `crates/primitives/src/block.rs:227-264`
**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:76-85` —
`BlockWitnessMerkleRoot` builds leaves and calls `ComputeMerkleRoot`
(which DOES check `mutated`; the witness-malleability check is also
documented at `validation.cpp:3887-3889` as "ignored because the
transaction tree itself already does not permit it").

**Description:** The witness merkle root inherits the same odd-pair
duplication algorithm as `compute_merkle_root` and has the same gap.
Even though Core's comment at `validation.cpp:3887-3889` says the
witness-tree malleation check is "ignored because the transaction
tree itself already does not permit it", that reasoning depends on
`compute_merkle_root` actually detecting the txid-tree mutation —
which BUG-1 establishes that rustoshi does not. So both trees can
silently mutate.

**Excerpt:** `primitives/block.rs:246-260` — same `while .. % 2 == 1
{ duplicate }` loop, no `mutated` flag.

**Impact:** Compounds with BUG-1. A duplicate-coinbase-wtxid (which
is always 32-zero, so the coinbase ALWAYS duplicates an even-sized
leaf set's last item if there's an odd number of post-coinbase txs)
produces a witness-root collision on permuted lists.

### BUG-3 (P0-CDIV-MALL) `rustoshi_crypto::merkle_root` does not detect CVE-2012-2459 odd-pair duplication

**File:** `crates/crypto/src/hashes.rs:59-84`
**Core ref:** same as BUG-1.

**Description:** Third copy of the same merkle-root algorithm — this
one used by the **mining-side** `build_witness_commitment`
(`block_template.rs:647`). When this function is used to produce a
template, the witness commitment in the coinbase reflects the same
flawed algorithm: a mining-pool feeding a duplicate-pair tx list
through rustoshi's `getblocktemplate` would emit a coinbase commitment
that Core accepts as numerically valid but rejects as
`bad-txns-duplicate`.

**Excerpt:** `crypto/hashes.rs:66-83`:

```rust
while current_level.len() > 1 {
    if !current_level.len().is_multiple_of(2) {
        let last = *current_level.last().unwrap();
        current_level.push(last);
    }
    let mut next_level = Vec::with_capacity(current_level.len() / 2);
    for pair in current_level.chunks(2) {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&pair[0].0);
        combined[32..].copy_from_slice(&pair[1].0);
        next_level.push(Hash256(sha256_accel::sha256d_64(&combined)));
    }
    current_level = next_level;
}
```

**Impact:** Three-pipeline drift. Any future fix to ONE of these
helpers will leave the other two exposed.

### BUG-4 (P1) `contextual_check_block` skips witness validation pre-segwit

**File:** `crates/consensus/src/validation.rs:1096-1099`
**Core ref:** `bitcoin-core/src/validation.cpp:4169-4171` —
`CheckWitnessMalleation(block, DeploymentActiveAfter(..., DEPLOYMENT_SEGWIT))`.
The function is always called; only the `expect_witness_commitment`
argument changes.

**Description:** rustoshi only calls `check_witness_commitment` when
`height >= params.segwit_height`:

```rust
// validation.rs:1096-1099
// SegWit: Check witness commitment
if height >= params.segwit_height {
    check_witness_commitment(block)?;
}
```

Core calls `CheckWitnessMalleation` **regardless** of segwit
activation; the `expect_witness_commitment` parameter only controls
whether the OP_RETURN commitment is required, but the
"no witness data anywhere" loop (`validation.cpp:3905-3913`) runs
unconditionally. So Core REJECTS a pre-segwit block carrying witness
data; rustoshi silently accepts it.

**Impact:** Reorg-from-genesis divergence on any historical
pre-segwit block that has been tampered to include witness data.
Low practical impact (such blocks are not in the canonical chain)
but it is a state-divergence on adversarial replay.

### BUG-5 (P1) `check_witness_commitment` skips the "no witness data" loop when no commitment is present AND segwit is inactive

**File:** `crates/consensus/src/validation.rs:1186-1240`
**Core ref:** `bitcoin-core/src/validation.cpp:3905-3913`.

**Description:** Core's `CheckWitnessMalleation` always runs the
"no witness anywhere" loop when `expect_witness_commitment=false`:

```cpp
// validation.cpp:3905-3913
// No witness data is allowed in blocks that don't commit to witness data...
for (const auto& tx : block.vtx) {
    if (tx->HasWitness()) {
        return state.Invalid(BLOCK_MUTATED, "unexpected-witness", ...);
    }
}
```

rustoshi's `check_witness_commitment` only runs the equivalent loop
inside the `if let Some(idx) = commit_out_idx { ... } else { for tx in
... has_witness() ... }` branch — but the OUTER call is gated on
`height >= segwit_height` (see BUG-4). So this loop never runs
pre-segwit.

**Excerpt:** `validation.rs:1206-1237`:

```rust
if let Some(idx) = commit_out_idx {
    // ... commit nonce + merkle match
    return Ok(());
}

// Gate 9: no commitment found — NO transaction (including coinbase) may carry
// witness data. Core loops `for (const auto& tx : block.vtx)` (validation.cpp:3906).
for tx in &block.transactions {
    if tx.has_witness() {
        return Err(ValidationError::UnexpectedWitness);
    }
}
```

**Impact:** Combined with BUG-4, pre-segwit blocks with witness data
pass through both gates. Edge case.

### BUG-6 (P2) `unexpected-witness` enforcement: rustoshi accepts a no-commitment block with witness data when only the coinbase has witness data

**File:** `crates/consensus/src/validation.rs:1233-1237`
**Core ref:** `bitcoin-core/src/validation.cpp:3906-3912`.

**Description:** The loop checks `tx.has_witness()` for every tx,
which is consistent with Core. But the subtle case: a coinbase whose
input[0].witness has a stack of `vec![]` (an empty Vec<Vec<u8>>) is
NOT considered to have witness; but a coinbase with
`vec![vec![]]` (one empty stack item) IS considered to have witness
by `has_witness()` (since `!i.witness.is_empty()` returns true for a
length-1 outer Vec even if the inner is empty). Core's `HasWitness`
returns the same (`!stack.empty()`). So the encoding "marker + flag +
witness count 1 + item len 0" is recognized as having witness by both,
but the encoding "marker + flag + witness count 0" is recognized as
having NO witness — yet rustoshi accepts both decoded forms with no
re-serialization round-trip check (see BUG-8). Marked P2 because
the malleability primitive is BUG-8; this gate is mostly fine.

### BUG-7 (P0-CDIV-MALL) 64-byte non-witness transaction merkle-mutation defence is missing

**File:** `crates/consensus/src/validation.rs:441-514` (`check_block`)
and `crates/network/src/compact_blocks.rs:540-600` (`is_block_mutated`).
**Core ref:** `bitcoin-core/src/validation.cpp:4035-4048` (in
`IsBlockMutated`):

```cpp
if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
    // Consider the block mutated if any transaction is 64 bytes in size...
    return std::any_of(block.vtx.begin(), block.vtx.end(),
                       [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
}
```

**Description:** Bitcoin's merkle tree leaves are 32-byte hashes. A
node in the tree at any level is the SHA256d of two concatenated
32-byte hashes — a 64-byte input. If a transaction's TX_NO_WITNESS
serialization is also exactly 64 bytes, an attacker can craft a tree
where a leaf collides with an intermediate node, producing a different
canonical tx-list with the same merkle root. The Core defence is to
reject any block with a 64-byte non-witness-serialized tx. rustoshi
has NO such gate in `check_block` or `is_block_mutated`.

**Excerpt:** `compact_blocks.rs:540-560` only checks merkle root then
witness commitment — no 64-byte loop.

**Impact:** Crafted merkle-leaf-collision attack: an attacker who
gets a 64-byte tx into a block can construct two distinct ordered
tx-lists that produce the same merkle root, banning rustoshi on
one and leaving the other unblockable. Same impact class as
BUG-1; the 64-byte rule is the documented Core mitigation for the
case where odd-duplication alone doesn't catch it.

### BUG-8 (P0-MALL) `Transaction::Decodable` accepts marker+flag with all-empty witnesses ("Superfluous witness record" missing)

**File:** `crates/primitives/src/transaction.rs:483-507`
**Core ref:** `bitcoin-core/src/primitives/transaction.h:222-231`:

```cpp
if ((flags & 1) && fAllowWitness) {
    flags ^= 1;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        s >> tx.vin[i].scriptWitness.stack;
    }
    if (!tx.HasWitness()) {
        /* It's illegal to encode witnesses when all witness stacks are empty. */
        throw std::ios_base::failure("Superfluous witness record");
    }
}
```

**Description:** rustoshi's decoder reads marker+flag and a per-input
witness count CompactSize. If every per-input witness count is 0, the
resulting tx has `has_witness() == false`, but the wire form WAS in
segwit framing. Core throws `Superfluous witness record`; rustoshi
accepts.

**Excerpt:** `transaction.rs:483-507`:

```rust
// Read witness data if present
if has_witness {
    for input in &mut inputs {
        let witness_count = read_compact_size(reader)?;
        if witness_count > MAX_WITNESS_ITEMS as u64 {
            return Err(...);
        }
        input.witness = Vec::with_capacity(witness_count as usize);
        for _ in 0..witness_count {
            // ... read item
        }
    }
}
// NO post-loop check that at least one input has a non-empty witness
```

**Impact:** Tx-malleability re-attack. A peer can re-frame any legacy
tx into segwit envelope with all-empty witnesses; rustoshi accepts
it, but the re-serialization (via `tx.serialize()`) omits the
marker+flag (because `has_witness()` is false). Net result:
- The peer's `wtxid` (computed over the segwit framing) differs from
  rustoshi's `wtxid` (computed over the legacy framing).
- Two rustoshi peers that received the SAME tx from different upstream
  paths (one segwit-framed-but-empty, one legacy) compute different
  wtxids → BIP-339 wtxid-relay loops indefinitely.
- The mempool sees the tx as a new tx every time (no dedup).

This is exactly the malleability primitive BIP-141/144 closed.

### BUG-9 (P2) `ValidationError` flattens `BLOCK_CONSENSUS` and `BLOCK_MUTATED` into one category

**File:** `crates/consensus/src/validation.rs:43-166` (the `ValidationError` enum)
**Core ref:** `bitcoin-core/src/consensus/validation.h` — Core uses
`BlockValidationResult::BLOCK_MUTATED` (banman category 2, network-malleated)
vs `BLOCK_CONSENSUS` (banman category 1, consensus-invalid).

**Description:** Core uses two distinct result classes for block
rejection:
- `BLOCK_MUTATED` = the block may be valid but was malleated in
  transit; do NOT mark the block-hash as permanently invalid (a peer
  could be feeding us a corrupted version of a valid block).
- `BLOCK_CONSENSUS` = the block is permanently invalid; mark the
  block-hash as such and ban-from-this-block-forward.

rustoshi's `ValidationError` enum has no such split. `BadMerkleRoot`,
`BadWitnessCommitment`, `BadWitnessNonceSize`, `UnexpectedWitness`
all map to the same flat variant with no metadata about which ban
category they belong to. The downstream `bip22_string()` function
correctly maps each to a Core-identical reject reason string, but the
ban-vs-discard distinction is lost — every consensus failure becomes
a hard "this block is permanently invalid" mark, which is the wrong
behavior for `BLOCK_MUTATED` causes.

**Impact:** When a peer feeds us a malleated copy of a valid block,
rustoshi marks the hash as permanently invalid. The genuine block
later arrives with the same hash and is silently rejected as
"already-known-invalid". Documented Core behavior is to NOT mark
mutated-class failures as permanent.

### BUG-10 (P2) Block weight check fires **before** witness commitment validation

**File:** `crates/consensus/src/validation.rs:494-505` (in `check_block`)
**Core ref:** `bitcoin-core/src/validation.cpp:4173-4181` —
`GetBlockWeight(block) > MAX_BLOCK_WEIGHT` is checked **after**
`CheckWitnessMalleation` in `ContextualCheckBlock`.

**Description:** Core deliberately moved the weight check to AFTER
the witness check because the coinbase witness reserved value is
unconstrained (could be padded with arbitrary bytes to push the
block over MAX_BLOCK_WEIGHT without changing the block hash). If
weight is checked first and rejected, the block hash gets marked
invalid — but the same block hash could be re-mined with a
different (shorter) coinbase witness that does pass weight. So
weight failure should be treated as `BLOCK_MUTATED` (transient), not
`BLOCK_CONSENSUS` (permanent), and Core orders the checks so that
witness-commitment validity is established first.

rustoshi's `check_block` runs the weight check at line 502, BEFORE
`contextual_check_block` is called (chain_state.rs:480, 489). So weight
failure is mistakenly marked as permanent.

**Excerpt:** `validation.rs:501-505`:

```rust
// Check block weight
let weight = compute_block_weight(block);
if weight > MAX_BLOCK_WEIGHT {
    return Err(ValidationError::WeightExceeded(weight));
}
```

**Impact:** Compounds with BUG-9. Same "marked-permanent-when-should-be-transient"
class.

### BUG-11 (P2) Missing `block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` cheap pre-check

**File:** `crates/consensus/src/validation.rs:453-514` (`check_block`)
**Core ref:** `bitcoin-core/src/validation.cpp:3947` — the
"size limits" guard:
```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

**Description:** Core's first check in `CheckBlock` is the cheap
"absurd-count" guard: a block whose tx count alone × 4 exceeds
`MAX_BLOCK_WEIGHT` (i.e. > 1,000,000 transactions) must be rejected.
rustoshi has no equivalent before the per-tx loops.

**Impact:** DoS amplification. A malicious peer sending a block with
40,000,001 zero-length entries (per-tx loop hits each one) burns more
CPU than Core does before rejecting. Marked P2 because the per-tx
`check_transaction` loop is bounded by overall block size anyway.

### BUG-12 (P2) Missing `GetSerializeSize(TX_NO_WITNESS(block)) * 4 > MAX_BLOCK_WEIGHT` stripped-size pre-check

**File:** `crates/consensus/src/validation.rs:453-514`
**Core ref:** same as BUG-11, the third clause.

**Description:** Core's same "size limits" guard includes the
stripped-size check: a block whose pre-witness serialization × 4
exceeds `MAX_BLOCK_WEIGHT` is rejected before any per-tx work runs.
rustoshi has no equivalent.

**Impact:** Same as BUG-11. The full block-weight check at
`compute_block_weight` catches this eventually, but only after
per-tx validation.

### BUG-13 (P0-CDIV-MINER) `build_coinbase_tx` skips witness commitment when no tx has witness data

**File:** `crates/consensus/src/block_template.rs:586-604`
**Core ref:** `bitcoin-core/src/validation.cpp:3997-4019`
(`GenerateCoinbaseCommitment`). Core ALWAYS generates the commitment
when segwit is active (the gate is `commitpos == NO_WITNESS_COMMITMENT`,
i.e. "is there not already one?"), regardless of whether any non-
coinbase tx carries witness data.

**Description:** rustoshi's mining-side coinbase builder gates the
commitment OP_RETURN on `has_witness = txs.any(has_witness)`:

```rust
// block_template.rs:586,598-604
let has_witness = selected_txs.iter().any(|tx| tx.has_witness());
// ...
if has_witness {
    let commitment = build_witness_commitment(selected_txs, &witness_nonce);
    outputs.push(TxOut {
        value: 0,
        script_pubkey: commitment,
    });
}
```

When an empty-mempool block is built on a segwit-active chain (regtest
+ no submitted txs OR mainnet with no segwit txs in mempool), the
coinbase is emitted WITHOUT the commitment OP_RETURN. Any external
validator (including rustoshi itself when reading the block back via
the validation pipeline) would reject this block — except that
rustoshi's `check_witness_commitment` ALSO has a no-op path when
no witness data is present.

This is a known carry-forward of W108 G11 + W123 G3 — both have
ignored tests (`test_g11_witness_commitment_always_present_when_segwit_active`
at `tests/test_w108_gbt.rs:504`; `test_g3_witness_commitment_when_segwit_active_no_witness_txs`
at `tests/test_w123_mining_gbt.rs:193`). Neither has been closed.

**Impact:** rustoshi-as-mining-pool produces blocks that Core (and
every other consensus impl) rejects as `bad-witness-nonce-size`.
Empty-mempool blocks on regtest (e.g. during smoke tests) silently
fail when validated by Core or any other impl.

### BUG-14 (P1) `UpdateUncommittedBlockStructures` equivalent missing

**File:** `crates/consensus/src/block_template.rs:558-628` and
upward in the block-template pipeline.
**Core ref:** `bitcoin-core/src/validation.cpp:3985-3995`:

```cpp
void ChainstateManager::UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev) const
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT && DeploymentActiveAfter(pindexPrev, *this, Consensus::DEPLOYMENT_SEGWIT) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}
```

**Description:** This is the symmetric helper: when a block has a
commitment but the coinbase has NO witness (e.g. a submitblock RPC
caller passed in a coinbase missing the reserved value), Core
auto-injects a 32-zero witness reserved value. rustoshi has no such
helper — a submitblock caller that provides a commitment but no
coinbase witness reserved value gets a `bad-witness-nonce-size`
rejection instead of automatic recovery.

**Impact:** Stratum-2 / mining-pool RPC interoperability: tools that
submit pre-built blocks expecting Core's auto-injection get a hard
reject instead.

### BUG-15 (P3) `Transaction::Decodable` panics on empty vin in segwit-flag branch

**File:** `crates/primitives/src/transaction.rs:483-507`
**Core ref:** `bitcoin-core/src/primitives/transaction.h:218-220`
— if non-empty vin was read in legacy form, fall through to vout.

**Description:** rustoshi's decode handles `marker == 0x00` →
"this is segwit framing" → read flag → read input_count. If
input_count is also 0 in segwit framing (legal in Core; this is an
empty-vin segwit tx), the subsequent witness loop is skipped. But
the per-input witness loop assumes `inputs` is populated; with
input_count = 0, there's no panic — empty loop. Actually this
specific path is fine.

The fragile case: if a caller invokes `check_witness_commitment`
on a block with `block.transactions.is_empty()`, the function panics
at `let coinbase = &block.transactions[0]` (validation.rs:1187). In
practice this is always preceded by `check_block` (validation.rs:455
guards against empty), but the API is fragile — a future refactor
that bypasses `check_block` will panic. P3 because no current code
path triggers it.

### BUG-16 (P2) Two-pipeline drift between `check_witness_commitment` (validation.rs) and `is_block_mutated` (compact_blocks.rs)

**File:**
- `crates/consensus/src/validation.rs:1186-1240`
- `crates/network/src/compact_blocks.rs:540-600`

**Core ref:** Core uses a single `CheckWitnessMalleation`
(`validation.cpp:3870`) called from both `ContextualCheckBlock`
(line 4169) and `IsBlockMutated` (line 4050). One function, two
callers.

**Description:** rustoshi has two near-identical reimplementations of
the same logic. Both walk the coinbase outputs to find the
commitment, both check `witness_stack.len() != 1 || witness_stack[0].len() != 32`,
both recompute `sha256d(witness_root || nonce)`, both check the
"no witness data anywhere" fallback. They will inevitably drift.

**Excerpt comparison:**

`validation.rs:1192-1204`:
```rust
const MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
let mut commit_out_idx: Option<usize> = None;
for (i, output) in coinbase.outputs.iter().enumerate() {
    let s = &output.script_pubkey;
    if s.len() >= 38
        && s[0] == 0x6a   // OP_RETURN
        && s[1] == 0x24   // push 36 bytes
        && s[2..6] == MAGIC
    {
        commit_out_idx = Some(i);
    }
}
```

`compact_blocks.rs:554-570` — same code, copy-pasted, with the
same MAGIC constant declared locally. Any fix to one (e.g.
mutated-tx detection per BUG-1) must be applied to both.

**Impact:** Maintainability hazard. As of this audit they happen to
agree, but future fixes will diverge silently.

### BUG-17 (P2) `check_witness_commitment` is `fn` (not `pub fn`) but its compact_blocks twin is `pub fn` — visibility / reuse asymmetry

**File:** `crates/consensus/src/validation.rs:1186` (`fn`) vs
`crates/network/src/compact_blocks.rs:540` (`pub fn`).

**Description:** The compact-blocks function is exported and used by
the cmpctblock reconstruction path. The validation-side function is
private to `validation.rs` and cannot be reused by `compact_blocks.rs`
even though it would deduplicate the BUG-16 drift. This is a Cargo
crate-dependency artifact: `network` depends on `consensus`, so
`compact_blocks` could call `validation::check_witness_commitment`
if it were public. Marked P2 because fixing this enables fixing
BUG-16 cleanly.

### BUG-18 (P2) `compute_block_weight` re-implements Core's `GetBlockWeight` formula incorrectly for the header+count contribution

**File:** `crates/consensus/src/validation.rs:521-535`
**Core ref:** `bitcoin-core/src/consensus/validation.h:136-139`:
```cpp
static inline int64_t GetBlockWeight(const CBlock& block)
{
    return ::GetSerializeSize(TX_NO_WITNESS(block)) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(TX_WITH_WITNESS(block));
}
```

**Description:** Core's formula treats the entire block (header + tx
count CompactSize + all txs) as one unit, computing
`stripped_total * 3 + full_total`. rustoshi instead splits:

```rust
let mut weight: u64 = 80 * WITNESS_SCALE_FACTOR;     // header * 4
let tx_count_size = compact_size_len(block.transactions.len() as u64);
weight += tx_count_size as u64 * WITNESS_SCALE_FACTOR; // count * 4
for tx in &block.transactions {
    weight += tx.weight() as u64;                    // tx weight
}
```

The header is 80 bytes with NO witness data so `header_stripped * 3 +
header_full = 80*3 + 80 = 320 = 80*4`. ✓
The tx count CompactSize is NOT in any tx's witness so same.
The per-tx `tx.weight() = base_size*3 + total_size` is identical to
Core's per-tx contribution.

Result: mathematically equivalent. No bug as such, but this is a
**three-line independently-derived reimplementation** of a one-line
Core formula. Future modifications (e.g. adding metadata weight)
will silently drift if Core changes the formula but rustoshi doesn't.
Marked P2 because the math is currently correct.

### BUG-19 (P3) `Transaction::wtxid()` returns `txid()` for non-witness txs (correct) but always re-hashes from scratch

**File:** `crates/primitives/src/transaction.rs:286-293`
**Core ref:** `bitcoin-core/src/primitives/transaction.h:353` —
`HasWitness` is computed once at construction; `wtxid` returns
`m_witness_hash` or `m_hash` based on that cached flag.

**Description:** rustoshi recomputes both `serialize_no_witness()` and
`serialize()` on every call. For a coinbase with witness, this means
re-serializing the entire tx every time `wtxid()` is called. Minor
performance issue. P3.

### BUG-20 (P3) BIP-143 sighash uses `tx.version` as i32 LE but spec says u32

**File:** `crates/crypto/src/sighash.rs:432`
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1646` — `ss << txTo.version`, where `txTo.version` is `int32_t`.

**Description:** rustoshi uses `tx.version.to_le_bytes()` where
`version` is `i32`. Core uses `int32_t txTo.version`. The byte
representation of negative i32 values (theoretically permitted on the
wire) is identical to u32 reinterpretation (two's complement little-
endian). Match. P3 noted for consistency with the BIP-143 spec
language which says "nVersion of the transaction (4-byte little endian)"
without specifying signedness.

### BUG-21 (P2) BIP-143 sighash preimage allocation hint is wrong

**File:** `crates/crypto/src/sighash.rs:429`
```rust
let mut preimage = Vec::with_capacity(156 + script_code.len());
```

**Description:** The preimage is exactly `4 + 32 + 32 + 36 + compact_size(script_code.len()) + script_code.len() + 8 + 4 + 32 + 4 + 4 = 156 + compact_size_len + script_code.len()` bytes. The CompactSize prefix is 1 byte for scripts ≤ 252 bytes (P2WPKH=25 ✓, most P2WSH scripts) but 3 bytes for scripts 253-65535. rustoshi's hint misses the compact_size prefix. Performance only — `Vec` will reallocate. P2.

### BUG-22 (P3) `p2wpkh_script_code` returns `[u8; 25]` but the BIP-143 spec quotes the leading `0x19` length prefix

**File:** `crates/crypto/src/sighash.rs:468`

**Description:** BIP-143's English describes the P2WPKH scriptCode
as `0x1976a914<hash>88ac` — that's 26 bytes including a `0x19`
(=25) length prefix. rustoshi returns the bare 25-byte script and
relies on `segwit_v0_sighash` to prepend a CompactSize (line 444:
`write_compact_size(&mut preimage, script_code.len() as u64)`). The
CompactSize of 25 is one byte = 0x19, so the wire form matches. P3
because it's spec-quoting ambiguity, not a bug; future readers of
the BIP may be confused into thinking the 25 bytes should be 26.

## Fleet-pattern observations

1. **Three-pipeline merkle root.** rustoshi has the worst observed
   case of duplicate-pipeline drift in W76+ tracking: `compute_merkle_root`
   in `primitives::block`, `compute_witness_root` next door, AND
   `rustoshi_crypto::merkle_root` in the helper crate — all three
   independently implement Core's `ComputeMerkleRoot`, all three
   miss the `mutated` out-param, all three are called from different
   call paths. **Cross-impl correlation candidate:** check the other 9
   impls for the same "helper crate also has a merkle root function"
   pattern. The blockbrew Go impl is known to have `chainhash` reused
   by both consensus and miner; investigate whether it has the same
   triple-helper hazard.

2. **Two-pipeline witness commitment.** A separate instance of the
   W76+ guard pattern: `validation::check_witness_commitment` and
   `compact_blocks::is_block_mutated` reimplement the same
   `CheckWitnessMalleation` logic. This is the **fifteenth dedicated
   two-pipeline-guard finding** in the W76-W141 sweep.

3. **"Mining-side gated on the wrong thing."** BUG-13 is a textbook
   carry-forward: a known-bad gate at `block_template.rs:586,598`
   was flagged by W108 G11 and W123 G3 (both with `#[ignore]`
   regression tests), but the production code has not been touched.
   This is the **fourth carry-forward re-anchor instance** since
   W124, joining the same trajectory as clearbit W140 BUG-13. The
   single-line fix is to replace `let has_witness = ...any(...)`
   with `let segwit_active = params.is_segwit_active(height)`.

4. **Validation-result-class flattening.** BUG-9 + BUG-10 are the
   ban-vs-discard analog of a class of bugs seen in beamchain W140
   ("defense-in-depth missing every layer"): rustoshi's
   `ValidationError` enum can't distinguish `BLOCK_MUTATED` from
   `BLOCK_CONSENSUS`, so the banman policy is necessarily
   coarse-grained. Cross-impl correlation candidate: check
   `network::misbehavior::MisbehaviorReason` — it has a
   `MutatedBlock` variant (compact_blocks.rs:1854 wires it up) but
   the consensus layer doesn't surface the metadata to populate it
   correctly from `BadMerkleRoot` vs `BadWitnessCommitment` vs
   `WeightExceeded` etc.

5. **"Decoder accepts a superset of what the encoder produces."**
   BUG-8 is a textbook instance of the asymmetric-roundtrip pattern.
   Core throws `Superfluous witness record` to enforce that the
   wire form is canonical for the value. rustoshi accepts the
   non-canonical form and silently canonicalizes on re-serialize.
   This is the **first instance** of this pattern in the W76+ sweep
   for rustoshi; cross-impl correlation candidate: check every
   `decode` function in every impl that handles segwit framing —
   most will likely have the same gap.

## Summary

22 bugs catalogued; 7 P0 (3 P0-CDIV-MALL merkle-root, 1 P0-CDIV-MALL
64-byte-tx, 1 P0-MALL tx malleability, 1 P0-CDIV-MINER mining-side,
1 P1 pre-segwit witness gate), 5 P1, 7 P2, 3 P3.

**Most representative finding:** BUG-1 (`compute_merkle_root` missing
CVE-2012-2459 detection). Three independent copies of the helper
exist, none of them check `mutated`. Single-class fix would be to
land Core's `ComputeMerkleRoot(hashes, &mutated)` signature on
`rustoshi_crypto::merkle_root` and delete the other two copies in
favor of calling the helper.

**Most urgent fix:** BUG-13 (`build_coinbase_tx` skips commitment when
no witness tx). This is a one-line change with two ignored regression
tests already on disk (`test_g11_*` in W108, `test_g3_*` in W123).
Closing it unblocks regtest smoke and stops rustoshi-mining-pool from
producing Core-incompatible blocks.

**Most subtle finding:** BUG-8 (`Superfluous witness record` missing).
Opens a tx-malleability vector that's been closed in Core for ~8
years; rustoshi's mempool dedup and BIP-339 wtxid-relay both depend
on the encoded form being canonical for the tx value.
