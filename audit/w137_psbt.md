# W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (rustoshi)

**Wave:** W137 — PSBT v0 (BIP-174) + PSBT v2 (BIP-370) + Taproot fields
(BIP-371) (DISCOVERY)
**Date:** 2026-05-17
**Audit subject:** the rustoshi wallet PSBT implementation:
- `crates/wallet/src/psbt.rs` (~3,862 LOC) —
  `Psbt`, `PsbtInput`, `PsbtOutput`, `KeyOrigin`, `ExtPubKey`, `Proprietary`,
  `encode_psbt_input`, `encode_psbt_output`, `decode_psbt_input`,
  `decode_psbt_output`, role analysis (`PsbtAnalysis`, `next_role`,
  `analyze`, `input_next_role`), finalizer (`finalize`, `finalize_input`,
  `build_p2wsh_witness`, `parse_multisig_script`), extractor
  (`extract_tx`), combiner (`merge`, `combine`).
- `crates/wallet/src/wallet.rs::sign_psbt_input` (lines 1280-1480) —
  the signer entry point used by the RPC layer.
- `crates/rpc/src/server.rs::createpsbt` (lines 5950-6077),
  `decodepsbt` (lines 6079-6440), `combinepsbt` (lines 6440-6465),
  `finalizepsbt` (lines 6467-6511), `analyzepsbt` (lines 6513-6554),
  `walletcreatefundedpsbt` (in `wallet.rs`).

**References (Bitcoin Core):**
- `bitcoin-core/src/psbt.h` (1,475 LOC) — `PartiallySignedTransaction`,
  `PSBTInput`, `PSBTOutput`, `PSBTProprietary`, `SerializeHDKeypaths`,
  `DeserializeHDKeypaths`, `SerializeToVector`/`UnserializeFromVector`,
  `DeserializeMuSig2ParticipantPubkeys`,
  `DeserializeMuSig2ParticipantDataIdentifier`, all 35
  `case PSBT_IN_*` / `case PSBT_OUT_*` / `case PSBT_GLOBAL_*` branches
  with their **DUPLICATE-KEY**, **KEY-SIZE**, **VALUE-SIZE**, **PUBKEY-VALID**
  checks. PSBT v0 high watermark: `PSBT_HIGHEST_VERSION = 0`.
- `bitcoin-core/src/psbt.cpp` (639 LOC) — `CombinePSBTs`, `FinalizePSBT`,
  `FinalizeAndExtractPSBT`, `SignPSBTInput`, `RemoveUnnecessaryTransactions`,
  `PSBTInputSigned`, `PSBTInputSignedAndVerified`, `CountPSBTUnsignedInputs`,
  `UpdatePSBTOutput`, `PrecomputePSBTData`, `PSBTRoleName`,
  `DecodeBase64PSBT`, `DecodeRawPSBT`.
- `bitcoin-core/src/node/psbt.cpp` — `AnalyzePSBT`.
- `bitcoin-core/src/rpc/rawtransaction.cpp` — `createpsbt`, `decodepsbt`,
  `analyzepsbt`, `combinepsbt`, `finalizepsbt`,
  `joinpsbts`, `utxoupdatepsbt`.
- `bitcoin-core/src/wallet/rpc/spend.cpp` — `walletcreatefundedpsbt`,
  `walletprocesspsbt`, `sendall`, `descriptorprocesspsbt`.
- BIPs **174**, **370**, **371**.

**Production code changes:** 0 (pure audit).
**Test file:** `crates/wallet/tests/test_w137_psbt.rs` — 30 gates,
PASS regression pins + `#[ignore]`-pinned BUG-N stubs.

## Why this matters

PSBT is the universal Bitcoin signing protocol: hardware wallets,
multi-sig coordinators, exchanges, and any cross-impl tooling
encode/decode it. Any cross-impl PSBT byte-divergence or
duplicate-key permissiveness becomes a real-world failure when:

1. **Hardware-wallet interop.** Trezor/Ledger/Coldcard hold the
   master keys and expect strict BIP-174 parsing. If rustoshi
   silently accepts a PSBT with duplicate `PSBT_IN_PARTIAL_SIG`
   keys (BUG-2), a malicious counterparty can stuff the PSBT with
   conflicting signatures and hope a downstream tool picks the
   "wrong" one. Core rejects this at psbt.h:535.
2. **CVE-2020-14199 amount-oracle defense.** A counterparty can
   ship a `witness_utxo` whose amount disagrees with the
   `non_witness_utxo`. rustoshi has W41-A2 defense, but only
   inside `sign_psbt_input` — not at deserialize time, so a
   downstream tool reading `psbt.inputs[i].witness_utxo.value`
   directly (e.g. fee accounting in `decodepsbt`) trusts the
   attacker amount. Audit coverage: BUG-3.
3. **PSBT v2 (BIP-370).** Newer hardware wallets (Coldcard Edge,
   newer Ledger firmware) and some exchanges have started
   emitting PSBT v2 with explicit input/output fields and no
   global `unsigned_tx`. rustoshi has NO support — it rejects
   any version > 0. This is **deliberate** for Core parity (Core
   itself rejects v2 — PSBT_HIGHEST_VERSION=0) but means rustoshi
   cannot import PSBTs from those tools. Coverage: BUG-15.
4. **BIP-371 Taproot fields.** `PSBT_OUT_TAP_TREE` and
   `PSBT_IN_TAP_LEAF_SCRIPT` carry trust-critical commitments. Core
   validates depth ≤ 128 and leaf_version pattern (`0xfe` mask).
   rustoshi does NEITHER, so a malicious counterparty can stuff a
   1000-deep tap_tree and either DoS the parsing path or pass
   garbage downstream. Coverage: BUG-5, BUG-6.
5. **`PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` round-trip.** rustoshi
   has the storage field (`PsbtOutput::musig2_participant_pubkeys`)
   AND the decoder, but NO encoder. A combiner-style workflow that
   reads → modifies → re-serializes will SILENTLY DROP the MuSig2
   participants on output. Critical for any MuSig2 coordinator.
   Coverage: BUG-7.

## 30-gate audit matrix

| Gate | Status  | Severity | Finding |
|------|---------|----------|---------|
| G1   | OK      | -        | PSBT_MAGIC_BYTES `0x70 0x73 0x62 0x74 0xFF` is byte-identical to Core (`psbt.h:28`); `Psbt::decode` rejects mismatched magic with `PsbtError::InvalidMagic` |
| G2   | OK      | -        | PSBT_SEPARATOR `0x00` correctly emitted at end of global / per-input / per-output maps (`encode`/`encode_psbt_input`/`encode_psbt_output`); decoder treats `key_len == 0` as separator |
| G3   | BUG     | P0-CDIV  | **PSBT_GLOBAL_UNSIGNED_TX is the ONLY required global field** but missing-separator detection is implicit (`key_len == 0` breaks the loop). Core has explicit `found_sep` tracking and throws `"Separator is missing at the end of the global map"` at `psbt.h:1354-1356` if EOF reached without separator. rustoshi silently OKs an EOF that happens mid-map — see BUG-1 |
| G4   | BUG     | P0-CDIV  | **No duplicate-key check on `PSBT_IN_PARTIAL_SIG`**. `decode_psbt_input` line 2120-2137 inserts into `input.partial_sigs` BTreeMap which silently overwrites on duplicate. Core explicitly checks `partial_sigs.contains(pubkey.GetID())` at `psbt.h:535-537` and throws "Duplicate Key, input partial signature for pubkey already provided" — see BUG-2 |
| G5   | BUG     | P0-CDIV  | **No `PSBT_IN_PARTIAL_SIG` signature-encoding validation**. Core calls `CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG \| SCRIPT_VERIFY_STRICTENC, nullptr)` at `psbt.h:544` and throws "Signature is not a valid encoding" if non-DER or invalid sighash byte. rustoshi accepts any byte sequence — see BUG-3 |
| G6   | BUG     | P0-CDIV  | **No pubkey validity check on `PSBT_IN_PARTIAL_SIG` keys**. Core constructs `CPubKey(key.begin() + 1, key.end())` and rejects via `pubkey.IsFullyValid()` at `psbt.h:532`. rustoshi just blindly copies 33 bytes into a `[u8; 33]` array. A garbage 33-byte string (e.g. all-zero or invalid curve point) passes — see BUG-4 |
| G7   | BUG     | P0-CDIV  | **No uncompressed pubkey support in `PSBT_IN_PARTIAL_SIG` decoder**. Core's `CPubKey::SIZE = 65` (uncompressed) is accepted at `psbt.h:527`. rustoshi accepts a 66-byte key (line 2122) but then errors with `InvalidPubkey` at line 2134 — `key.len() == 66` is the **uncompressed-pubkey case** which Core supports for legacy multi-sig — see BUG-12 |
| G8   | BUG     | P1       | **No duplicate-key check on `PSBT_IN_TAP_SCRIPT_SIG`**. `decode_psbt_input` line 2304-2320 lacks `key_lookup.insert(key.clone())` while Core enforces it at `psbt.h:708`. Same shape for `PSBT_IN_TAP_LEAF_SCRIPT` (line 2321-2343) vs Core `psbt.h:730`, and for `PSBT_IN_TAP_BIP32_DERIVATION` (line 2344-2367) vs Core `psbt.h:750` — see BUG-9 |
| G9   | OK      | -        | `PSBT_IN_NON_WITNESS_UTXO` duplicate-key check via `key_lookup.insert(key.clone())` (line 2095-2097) matches Core `psbt.h:507`. `PSBT_IN_WITNESS_UTXO` (line 2108-2110) same; `PSBT_IN_SIGHASH` (line 2139-2141) same; `PSBT_IN_REDEEMSCRIPT` (line 2160-2162) same; `PSBT_IN_WITNESSSCRIPT` (line 2173-2175) same; `PSBT_IN_SCRIPTSIG` (line 2205-2207) same; `PSBT_IN_SCRIPTWITNESS` (line 2218-2220) same; `PSBT_IN_TAP_KEY_SIG` (line 2289-2291) same; `PSBT_IN_TAP_INTERNAL_KEY` (line 2369-2371) same; `PSBT_IN_TAP_MERKLE_ROOT` (line 2390-2392) same |
| G10  | OK      | -        | W41 A1 defense at decode time: `non_witness_utxo.txid() != unsigned_tx.inputs[i].previous_output.txid` returns `PsbtError::UtxoHashMismatch` at lines 2048-2054. Mirrors Core's `PSBTInput::Unserialize` post-loop check at `psbt.h:1371-1378` |
| G11  | OK      | -        | W36 fix: BIP32_DERIVATION value is the raw fingerprint+path bytes (no inner CompactSize), correctly framed by outer `write_kv_pair`'s `WriteCompactSize`. Verified by `test_w36_bip174_no_inner_compactsize_on_bip32_values` |
| G12  | OK      | -        | W41 A1 defense at combiner time: `Psbt::merge` (lines 816-826) checks `nw.txid() != self.unsigned_tx.inputs[i].previous_output.txid` BEFORE adopting other's non_witness_utxo. Mirrors Core's `PSBTInput::Merge` immutability contract |
| G13  | OK      | -        | W49 fix: partial signature serialization order is `HASH160(pubkey)` (line 1649-1651). Mirrors Core's `std::map<CKeyID, SigPair>` order (`psbt.h:270`) for byte-identical combinepsbt output |
| G14  | BUG     | P0-CDIV  | **`PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` is decoded but NEVER ENCODED**. `PsbtOutput::musig2_participant_pubkeys` field exists (line 531), decoder is wired (line 2575-2603), but `encode_psbt_output` (lines 1800-1876) has NO `for ... musig2_participant_pubkeys` block. Round-trip on a PSBT carrying MuSig2 silently drops the participants. Compare to Core `psbt.h:948-957` — see BUG-7 |
| G15  | BUG     | P1       | **`PsbtOutput::merge` does NOT merge `musig2_participant_pubkeys`**. Line 555-584 lacks the field. Core's `PSBTOutput::Merge` at `psbt.cpp:317` does `m_musig2_participants.insert(other.m_musig2_participants.begin(), ...)`. Combine-style workflows lose MuSig2 — see BUG-8 |
| G16  | BUG     | P0-CDIV  | **`PSBT_OUT_TAP_TREE` lacks depth + leaf-version validation**. Decoder at lines 2536-2550 does NOT check `depth > TAPROOT_CONTROL_MAX_NODE_COUNT (128)` and does NOT check `(leaf_ver & ~TAPROOT_LEAF_MASK) != 0`. Core enforces both at `psbt.h:1053-1058` and rejects malformed trees. A malicious PSBT can stuff a depth=255 or leaf_ver=0xFF and pass — see BUG-5 |
| G17  | BUG     | P1       | **`PSBT_OUT_TAP_TREE` lacks `TaprootBuilder::IsComplete()` check**. Core builds a TaprootBuilder from the entries and rejects via "Output Taproot tree is malformed" at `psbt.h:1062-1064` if the tree shape is not a complete binary tree. rustoshi accepts any depth list — see BUG-6 |
| G18  | BUG     | P1       | **`PSBT_OUT_TAP_TREE` empty-value rejection missing**. Core throws "Output Taproot tree must not be empty" at `psbt.h:1042-1044`. rustoshi's loop `while (value_cursor.position() as usize) < value.len()` silently accepts an empty value (zero iterations) — see BUG-10 |
| G19  | MISSING | P1       | **`PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a`**, **`PSBT_IN_MUSIG2_PUB_NONCE = 0x1b`**, **`PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c`** — none of the per-input MuSig2 fields (BIP-327 PSBT integration) are defined in rustoshi. The corresponding fields exist on `PSBTInput` in Core (`psbt.h:284-289`). MuSig2 signers/coordinators cannot use rustoshi as a combiner — see BUG-11 |
| G20  | MISSING | P1       | **PSBT v2 (BIP-370) entirely absent**. rustoshi rejects `m_version > 0` (line 1988-1990 `PSBT_HIGHEST_VERSION = 0`). Core does the same — this matches Core parity but means the explicit-fields workflow used by newer hardware wallets is not supported. NOT a Core-divergence bug, but a feature gap — see BUG-15 |
| G21  | BUG     | P1       | **`PSBT_IN_TAP_KEY_SIG` value-length is checked at decode (lines 2299-2301: 64 ≤ len ≤ 65) but rustoshi does NOT verify the sighash byte matches the input's `sighash_type` field**. Core's `SignPSBTInput` (`psbt.cpp:468`) checks `m_tap_key_sig.back() != *sighash` for non-default sighashes and returns `PSBTError::SIGHASH_MISMATCH`. A signer producing PSBTs with mismatched sighash and tap_key_sig passes rustoshi's decoder — see BUG-13 |
| G22  | BUG     | P1       | **`PSBT_IN_SIGHASH` `value.len() < 4` check is wrong direction**. Lines 2149-2154 require AT LEAST 4 bytes but happily accept MORE bytes — only the first 4 are used. Core's `UnserializeFromVector(s, sighash)` (`psbt.h:559`) requires EXACTLY 4 bytes (the inner UnserializeFromVector CompactSize equals `sizeof(int) == 4`); excess data throws "Size of value was not the stated size" — see BUG-14 |
| G23  | OK      | -        | `finalizepsbt` extract path mirrors Core's `FinalizeAndExtractPSBT` at `psbt.cpp:567-581`: pulls `final_script_sig` + `final_script_witness` into the result tx. `extract_tx` at lines 1043-1062 implements this. `finalizepsbt` RPC returns `{psbt, hex, complete}` shape matching Core |
| G24  | OK      | -        | `combinepsbt` rejects empty psbts array (line 6441-6446) and incompatible PSBTs via `IncompatiblePsbts` if txids differ (lines 793-796). Mirrors Core's `CombinePSBTs` shape at `psbt.cpp:583-594` |
| G25  | OK      | -        | `analyzepsbt` next-role ordering: `min` over per-input verdicts with `creator(0) < updater(1) < signer(2) < finalizer(3) < extractor(4)`. Implemented via `role_rank` (lines 1318-1330). Matches Core's `AnalyzePSBT` at `node/psbt.cpp:91-95` (W47-W48 fix) |
| G26  | OK      | -        | W41 A2 defense (CVE-2020-14199): `sign_psbt_input` at `wallet.rs:1347-1359` rejects `witness_utxo != non_witness_utxo.outputs[vout]` with `WitnessUtxoMismatch`. Witness commitment verification (P2WSH/P2SH-P2WSH) at `wallet.rs:1371-1414` |
| G27  | BUG     | P2       | **W41 A2 defense is NOT applied at `decodepsbt` / `analyzepsbt` time**. The check is inside `sign_psbt_input` only. A `decodepsbt` consumer reading `psbt.inputs[i].witness_utxo.value` directly for fee display sees the attacker amount. Recommended: hoist the check into `Psbt::decode` post-loop (alongside the W41 A1 txid check at lines 2048-2054) — see BUG-16 |
| G28  | BUG     | P2       | **`finalize_input` P2WPKH/P2PKH paths do NOT clear producer fields**. Lines 914-919 (P2WPKH) and 921-935 (P2PKH) set `final_script_witness` / `final_script_sig` but do NOT clear `partial_sigs`, `redeem_script`, `bip32_derivation`, `sighash_type` like the legacy P2SH-multisig path does (line 1012-1016). Encoder skips them on output anyway, but in-memory PsbtInput is inconsistent — see BUG-17 |
| G29  | BUG     | P1       | **`createpsbt` does not support PSBT v2 input fields when v2 is supplied**. Since rustoshi rejects v > 0 globally, the v2-specific request shape (`{inputs: [{txid, vout, sequence, locktime, required_height_locktime, required_time_locktime}], outputs: [...]}`) is silently ignored — the `locktime` and `required_*_locktime` fields are not surfaced. Core also doesn't support v2, so this is parity-OK as a feature gap, but the API contract is silent — see BUG-15 |
| G30  | MISSING | P1       | **No `joinpsbts` RPC** (Core: `bitcoin-core/src/rpc/rawtransaction.cpp::joinpsbts`). Lets a user concatenate inputs/outputs of independent PSBTs. rustoshi only exposes `combinepsbt` (merge same-tx). **No `utxoupdatepsbt`** (Core: same file). **No `descriptorprocesspsbt`** (Core: wallet/rpc/spend.cpp). All are listed for completeness — see BUG-18 |

## Bugs catalogued

### BUG-1 — Global / input / output map missing-separator detection silent

**Severity:** P0-CDIV (consensus-relevant only in that a malformed PSBT
can be accepted where Core would reject; impact mostly hardware-wallet
interop / fuzzer-divergent)

**Where:** `crates/wallet/src/psbt.rs::decode` (line 1902-2013),
`decode_psbt_input` (line 2073-2428), `decode_psbt_output`
(line 2438-2622). The decode loops use `if key_len == 0 { break; }`
as the separator marker. If the reader hits EOF mid-map (e.g.
`read_compact_size` returns IO error or `read_exact` short-reads),
the loop propagates the IO error. But if a malicious PSBT just
omits the separator and ends with the last record's last byte, the
behavior depends on the next `read_compact_size` call: if there's
even one byte left, it'll try to read a key — if zero bytes, it'll
return an IO `UnexpectedEof` error.

**Core:** `psbt.h:1242-1356` (global), `psbt.h:482-868` (input),
`psbt.h:972-1129` (output). All three have a `bool found_sep = false`
flag set inside the `if (key.empty()) { found_sep = true; break; }`
path AND a post-loop check:
```cpp
if (!found_sep) {
    throw std::ios_base::failure("Separator is missing at the end of the global map");
}
```

**Symptom:** A PSBT that ends exactly after the last record's value
byte (no `0x00` separator before EOF) MAY be accepted by rustoshi
(if EOF is exactly at the last byte) but rejected by Core. Cross-impl
divergent parsing on truncated PSBTs.

**Fix:** Add `let mut found_sep = false;` before each loop; set
`found_sep = true;` in the separator break; after the loop, return
`PsbtError::MissingSeparator` if `!found_sep`.

### BUG-2 — `PSBT_IN_PARTIAL_SIG` accepts duplicate pubkey keys (silently overwrites)

**Severity:** P0-CDIV

**Where:** `crates/wallet/src/psbt.rs::decode_psbt_input` line 2120-2137.
```rust
PSBT_IN_PARTIAL_SIG => {
    // Key is type + pubkey (33 or 65 bytes)
    if key.len() != 34 && key.len() != 66 { ... }
    let mut pubkey = [0u8; 33];
    if key.len() == 34 { pubkey.copy_from_slice(&key[1..34]); }
    else { return Err(PsbtError::InvalidPubkey); }
    input.partial_sigs.insert(pubkey, value);  // <-- silently overwrites
}
```

**Core:** `psbt.h:535-537`:
```cpp
if (partial_sigs.contains(pubkey.GetID())) {
    throw std::ios_base::failure("Duplicate Key, input partial signature for pubkey already provided");
}
```

**Symptom:** A malicious PSBT can include the same pubkey twice with
different signatures. rustoshi keeps only the LAST one (BTreeMap insert
overwrite). Core rejects. The downstream finalizer then constructs a
witness using the attacker-chosen "winning" sig. Cross-impl mempool
divergence on any signed-tx broadcast.

**Fix:** Add a per-input `key_lookup` check shape like Core, or check
`input.partial_sigs.contains_key(&pubkey)` and return DuplicateKey.

### BUG-3 — `PSBT_IN_PARTIAL_SIG` accepts non-DER signatures

**Severity:** P0-CDIV

**Where:** `crates/wallet/src/psbt.rs::decode_psbt_input` line 2136
inserts `value` into `partial_sigs` without any validation.

**Core:** `psbt.h:543-546`:
```cpp
if (sig.empty() || !CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)) {
    throw std::ios_base::failure("Signature is not a valid encoding");
}
```

**Symptom:** A signer can hand rustoshi a partial_sig that fails Core's
CheckSignatureEncoding (non-DER, non-low-S, malformed sighash byte,
empty). rustoshi stores it silently; the finalizer builds a witness
that fails consensus on broadcast. Hard-to-debug "signed tx rejected
by mempool" UX. Cross-impl divergent.

**Fix:** Port `CheckSignatureEncoding`-equivalent (rustoshi already has
`rustoshi_consensus::script::interpreter::check_signature_encoding`)
into the PSBT decoder for PSBT_IN_PARTIAL_SIG values.

### BUG-4 — `PSBT_IN_PARTIAL_SIG` accepts invalid pubkey bytes

**Severity:** P0-CDIV

**Where:** Same call site as BUG-3. `pubkey.copy_from_slice(&key[1..34])`
takes 33 bytes verbatim into a `[u8; 33]` array. No `IsFullyValid()` check.

**Core:** `psbt.h:531-534`:
```cpp
CPubKey pubkey(key.begin() + 1, key.end());
if (!pubkey.IsFullyValid()) {
   throw std::ios_base::failure("Invalid pubkey");
}
```

**Symptom:** A 33-byte string starting with 0x02/0x03 but not a valid
secp256k1 point passes rustoshi's decoder. The downstream signer/
finalizer will produce a degenerate witness; the verifier rejects.
Cross-impl divergent at decode time.

**Fix:** Add `secp256k1::PublicKey::from_slice(&pubkey).is_ok()` (or
equivalent IsFullyValid) check before inserting.

### BUG-5 — `PSBT_OUT_TAP_TREE` accepts depth > 128 and bogus leaf_ver

**Severity:** P0-CDIV

**Where:** `crates/wallet/src/psbt.rs::decode_psbt_output` lines 2524-2550:
```rust
PSBT_OUT_TAP_TREE => {
    ...
    while (value_cursor.position() as usize) < value.len() {
        ... read depth, leaf_ver, script_len, script ...
        output.tap_tree.push((depth, leaf_ver, script));
    }
}
```
No `depth > 128` check. No `(leaf_ver & ~0xfe) != 0` check.

**Core:** `psbt.h:1053-1058`:
```cpp
if (depth > TAPROOT_CONTROL_MAX_NODE_COUNT) {
    throw std::ios_base::failure("Output Taproot tree has as leaf greater than Taproot maximum depth");
}
if ((leaf_ver & ~TAPROOT_LEAF_MASK) != 0) {
    throw std::ios_base::failure("Output Taproot tree has a leaf with an invalid leaf version");
}
```
where `TAPROOT_CONTROL_MAX_NODE_COUNT = 128` and `TAPROOT_LEAF_MASK = 0xfe`.

**Symptom:** A malicious counterparty's PSBT_OUT_TAP_TREE with depth=255
(invalid for BIP-341 tree depth) or leaf_ver=0x01 (invalid; only
even values matching `0xfe` mask allowed per BIP-341) passes rustoshi's
decoder. The downstream consumer attempts to derive the output key,
fails (depth-overflow / invalid leaf), and the user sees a confusing
mid-pipeline error instead of the Core-aligned "malformed at decode."
Cross-impl divergent.

**Fix:** Add both checks inside the loop. Match Core's wording.

### BUG-6 — `PSBT_OUT_TAP_TREE` accepts incomplete (non-tree-shaped) entry lists

**Severity:** P1

**Where:** Same loop as BUG-5. No `TaprootBuilder::IsComplete()` check
after parsing.

**Core:** `psbt.h:1062-1064`:
```cpp
if (!builder.IsComplete()) {
    throw std::ios_base::failure("Output Taproot tree is malformed");
}
```

**Symptom:** A PSBT_OUT_TAP_TREE listing `[(0, 0xc0, scriptA)]` (depth
0 but a single leaf — should be a path-of-depth-zero in a single-leaf
tree, OK) versus `[(1, 0xc0, scriptA)]` (depth 1 but no sibling — not
a complete binary tree, malformed) is rejected by Core but accepted by
rustoshi.

**Fix:** Port a TaprootBuilder analog or, simpler, a stack-based
"complete-binary-tree" validator: walk depths in order, maintaining a
stack; at each leaf, pop equal-depth siblings; at end, stack must be
empty (or single node at depth 0).

### BUG-7 — `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` decoded but never encoded

**Severity:** P0-CDIV

**Where:** `crates/wallet/src/psbt.rs::encode_psbt_output` lines 1800-1876.
The function writes `redeem_script`, `witness_script`, `bip32_derivation`,
`tap_internal_key`, `tap_tree`, `tap_bip32_derivation`, `proprietary`,
`unknown`. **It NEVER emits** `musig2_participant_pubkeys`. The decoder
at line 2575-2603 DOES read it and stores it.

**Core:** `psbt.h:948-957`:
```cpp
for (const auto& [agg_pubkey, part_pubs] : m_musig2_participants) {
    SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS), std::span{agg_pubkey});
    std::vector<unsigned char> value;
    VectorWriter s_value{value, 0};
    for (auto& pk : part_pubs) {
        s_value << std::span{pk};
    }
    s << value;
}
```

**Symptom:** A combiner-style workflow that does `decode → modify →
re-encode` SILENTLY DROPS the entire MuSig2 participant list. Critical
for any MuSig2 coordinator that uses rustoshi's combinepsbt RPC. Test:
encode a fixture with PSBT_OUT_MUSIG2 then deserialize → re-serialize
→ deserialize and assert the field round-trips. Currently FAILS.

**Fix:** Add the encoder block. Key = `[PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, agg_pubkey...]`,
value = concatenated 33-byte participant pubkeys.

### BUG-8 — `PsbtOutput::merge` does not merge MuSig2 participants

**Severity:** P1

**Where:** `crates/wallet/src/psbt.rs::PsbtOutput::merge` (line 555-584).
No `for (k, v) in &other.musig2_participant_pubkeys` block.

**Core:** `psbt.cpp:317`:
```cpp
m_musig2_participants.insert(output.m_musig2_participants.begin(), output.m_musig2_participants.end());
```

**Symptom:** Same data-loss as BUG-7 but at combinepsbt time. Two PSBTs
each contributing different MuSig2 participants on the same output:
after merge, only `self`'s participants are kept.

**Fix:** Mirror Core's insertion. Also extend `is_null` (line 542-552)
already does, that's fine. Also: `PsbtInput::merge` (line 397-501)
doesn't merge MuSig2 either, but rustoshi's `PsbtInput` doesn't even
have the field — see BUG-11 instead.

### BUG-9 — Missing duplicate-key checks on Taproot input fields

**Severity:** P1

**Where:**
- `PSBT_IN_TAP_SCRIPT_SIG` (line 2304-2320) — no key_lookup
- `PSBT_IN_TAP_LEAF_SCRIPT` (line 2321-2343) — no key_lookup
- `PSBT_IN_TAP_BIP32_DERIVATION` (line 2344-2367) — no key_lookup

**Core:** `psbt.h:708`, `psbt.h:730`, `psbt.h:750` all enforce
`if (!key_lookup.emplace(key).second) throw "Duplicate Key, ..."`.

**Symptom:** A PSBT with two PSBT_IN_TAP_SCRIPT_SIG entries having the
SAME (xonly, leaf_hash) pair: rustoshi's BTreeMap insert silently
overwrites. Same shape as BUG-2 but for Taproot signatures. Cross-impl
divergence in finalizer output.

**Fix:** Add per-input `key_lookup` set (BTreeSet<Vec<u8>>) at the
top of `decode_psbt_input` (rustoshi already has one initialized at
line 2070 — just USE it consistently for these three cases).

### BUG-10 — `PSBT_OUT_TAP_TREE` accepts empty value

**Severity:** P1

**Where:** `decode_psbt_output` line 2535-2550. The loop
`while (value_cursor.position() as usize) < value.len()` will
have ZERO iterations if `value.is_empty()`, producing an empty
`tap_tree` vector. No rejection.

**Core:** `psbt.h:1042-1044`:
```cpp
if (s_tree.empty()) {
    throw std::ios_base::failure("Output Taproot tree must not be empty");
}
```

**Fix:** Add `if value.is_empty() { return Err(...) }` before the loop.

### BUG-11 — MuSig2 input fields entirely missing

**Severity:** P1

**Where:** `crates/wallet/src/psbt.rs::PsbtInput` (line 302-367).
None of the BIP-327 input fields are defined:
- `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a`
- `PSBT_IN_MUSIG2_PUB_NONCE = 0x1b`
- `PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c`

**Core:** `psbt.h:284-289` defines all three on `PSBTInput`:
```cpp
std::map<CPubKey, std::vector<CPubKey>> m_musig2_participants;
std::map<std::pair<CPubKey, uint256>, std::map<CPubKey, std::vector<uint8_t>>> m_musig2_pubnonces;
std::map<std::pair<CPubKey, uint256>, std::map<CPubKey, uint256>> m_musig2_partial_sigs;
```

**Symptom:** rustoshi cannot serve as a MuSig2 signer or coordinator
on the INPUT side. PSBTs from external MuSig2 tooling that carry
these fields will be stored in `unknown` (line 2424-2427) — which
preserves them for round-trip, BUT no type-aware processing.

**Fix:** Add the three field types to `PsbtInput`, define decoder
cases mirroring Core's `psbt.h:791-836`, and emit them in
`encode_psbt_input`.

### BUG-12 — `PSBT_IN_PARTIAL_SIG` rejects uncompressed pubkeys

**Severity:** P0-CDIV

**Where:** `crates/wallet/src/psbt.rs::decode_psbt_input` line 2122-2134.
Although the size check at line 2122 accepts `34 || 66`, the
uncompressed-pubkey branch at line 2132-2134 returns `InvalidPubkey`.

**Core:** `psbt.h:527-549`:
```cpp
if (key.size() != CPubKey::SIZE + 1 && key.size() != CPubKey::COMPRESSED_SIZE + 1) {
    throw "...";
}
CPubKey pubkey(key.begin() + 1, key.end());  // accepts both 33 and 65
if (!pubkey.IsFullyValid()) throw "Invalid pubkey";
```
where `CPubKey::SIZE = 65` (uncompressed) and `CPubKey::COMPRESSED_SIZE = 33`.

**Symptom:** Legacy P2SH multisig PSBTs that include uncompressed
pubkeys (lawful per BIP-174) are rejected by rustoshi but accepted by
Core. Cross-impl divergent at decode.

**Fix:** Change `partial_sigs` storage to `BTreeMap<Vec<u8>, Vec<u8>>`
(variable-length pubkey) or add a parallel uncompressed-sig field.
Mirror Core's flexible CPubKey constructor.

### BUG-13 — `PSBT_IN_TAP_KEY_SIG` does not check sighash byte vs `sighash_type` field

**Severity:** P1

**Where:** `crates/wallet/src/psbt.rs::decode_psbt_input` lines 2288-2303.
The 64-or-65 byte length is checked, but if length==65 (non-default
sighash present), the sighash byte (sig[64]) is NOT compared against
`input.sighash_type`.

**Core:** `psbt.cpp:467-470` (inside `SignPSBTInput`):
```cpp
if (!input.m_tap_key_sig.empty() && (input.m_tap_key_sig.size() != 65 || input.m_tap_key_sig.back() != *sighash)) {
    return PSBTError::SIGHASH_MISMATCH;
}
```

**Symptom:** A signer can ship a tap_key_sig with sighash byte=0x83
(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY) while declaring
`sighash_type=0x01` (SIGHASH_ALL). rustoshi accepts both, then the
finalizer constructs a witness that fails consensus.

**Fix:** Cross-check at decode time (or at finalize/sign time) — Core
does it at sign time. Either is acceptable.

### BUG-14 — `PSBT_IN_SIGHASH` accepts > 4 byte values (only first 4 used)

**Severity:** P1

**Where:** `crates/wallet/src/psbt.rs::decode_psbt_input` lines 2149-2157:
```rust
if value.len() < 4 { return Err(...) }
let mut bytes = [0u8; 4];
bytes.copy_from_slice(&value[0..4]);
input.sighash_type = Some(u32::from_le_bytes(bytes));
```
Excess bytes (value.len() > 4) silently ignored.

**Core:** `psbt.h:559`:
```cpp
int sighash;
UnserializeFromVector(s, sighash);
```
where `UnserializeFromVector` throws if the inner-stated-size doesn't
match `sizeof(int) == 4` consumed.

Actually re-reading Core: the inner UnserializeFromVector reads a
CompactSize length first which must equal 4, then reads 4 bytes.
The outer SerializeToVector writes `[CompactSize(4)] [4 bytes]`, so
the on-wire value is 5 bytes (4 + 1 CompactSize byte). rustoshi reads
the OUTER value as exactly the 5 bytes (the outer write_kv_pair
framing), but then DOESN'T parse the inner CompactSize — it reads
the first 4 bytes of `value` directly. This means rustoshi's on-wire
PSBT_IN_SIGHASH is INCOMPATIBLE with Core's: Core writes 5 bytes
(`04 XX XX XX XX`), rustoshi writes 4 bytes (`XX XX XX XX`).

Wait — let me re-verify. rustoshi's encoder at line 1659-1664:
```rust
if let Some(sighash) = input.sighash_type {
    let key = vec![PSBT_IN_SIGHASH];
    let mut value = Vec::new();
    value.extend_from_slice(&sighash.to_le_bytes());
    len += write_kv_pair(writer, &key, &value)?;
}
```
This emits `<keylen=1> <type=0x03> <vallen=4> <4 LE bytes>`. So on-wire is `01 03 04 XX XX XX XX`.

Core emits via `SerializeToVector(s, CompactSizeWriter(PSBT_IN_SIGHASH))`
which writes `<vallen-of-key=1> <type=0x03>`, then
`SerializeToVector(s, *sighash_type)` which writes `<vallen=4> <4 LE>`.
Same as rustoshi.

So the on-wire IS the same: 4-byte u32 value. Then BIP-174 spec text
"The 32-bit unsigned integer specifying the sighash type..."
confirms 4 bytes exactly.

**Actual bug:** rustoshi accepts `value.len() > 4` (excess bytes
ignored). Core throws via UnserializeFromVector's strict equality.

**Symptom:** Cross-impl divergent decode on malformed sighash records.

**Fix:** Change `value.len() < 4` to `value.len() != 4`.

### BUG-15 — PSBT v2 (BIP-370) feature gap

**Severity:** P1 (parity with Core; missing feature for newer hardware)

**Where:** All of `crates/wallet/src/psbt.rs`. `PSBT_HIGHEST_VERSION = 0`
(line 52). Decoder rejects `m_version > 0` (line 1988-1990).

PSBT v2 (BIP-370) defines:
- `PSBT_GLOBAL_TX_VERSION = 0x02`
- `PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03`
- `PSBT_GLOBAL_INPUT_COUNT = 0x04`
- `PSBT_GLOBAL_OUTPUT_COUNT = 0x05`
- `PSBT_GLOBAL_TX_MODIFIABLE = 0x06`
- `PSBT_IN_PREVIOUS_TXID = 0x0e`
- `PSBT_IN_OUTPUT_INDEX = 0x0f`
- `PSBT_IN_SEQUENCE = 0x10`
- `PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11`
- `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12`
- `PSBT_OUT_AMOUNT = 0x03`
- `PSBT_OUT_SCRIPT = 0x04`

Plus: v2 omits PSBT_GLOBAL_UNSIGNED_TX entirely, and uses explicit
input/output count fields.

**Core:** Also doesn't implement v2 (`PSBT_HIGHEST_VERSION = 0` at
`psbt.h:80`). This is **PARITY**: rustoshi rejects v2 with the same
shape as Core.

**Symptom:** PSBTs from Coldcard Edge / newer Ledger firmware /
HWI v3.x with v2 output are rejected. Not a Core-divergence bug — but
a real-world feature gap.

**Fix:** Not in scope for a "Core parity" wave. Track as feature
request. The brief mentions "missing PSBT v2 (newer Core feature)"
but Core itself hasn't shipped v2 — so this is a fleet-wide gap
shared with Core.

### BUG-16 — W41 A2 amount-oracle defense not applied at decodepsbt time

**Severity:** P2 (signer-path is protected; decoder/analyze paths are not)

**Where:** The CVE-2020-14199 check at `Psbt::deserialize` lines
2048-2054 verifies non_witness_utxo TXID matches prevout TXID, but
does NOT verify `witness_utxo.amount == non_witness_utxo.outputs[vout].amount`
or scriptPubKey. That check is ONLY in `sign_psbt_input`
(`wallet.rs:1347-1359`).

**Symptom:** `decodepsbt` consumers (fee accounting display, block
explorers, fee-estimation libs) read the attacker's witness_utxo
amount directly. UI displays wrong fee. No signing happens, so no
consensus impact, but the trust surface is misleading.

**Fix:** Hoist the W41 A2 check from `sign_psbt_input` to
`Psbt::deserialize` post-loop, paired with the existing A1 txid
check.

### BUG-17 — `finalize_input` P2WPKH/P2PKH paths leave producer fields populated

**Severity:** P2

**Where:** `finalize_input` lines 914-919 (P2WPKH), 921-935 (P2PKH).
After setting `final_script_witness`/`final_script_sig`, the function
returns without clearing `partial_sigs`, `redeem_script`, `bip32_derivation`,
`sighash_type`. Compare to legacy P2SH-multisig path (line 1012-1016)
which clears all producer fields, per BIP-174 finalizer role:
"The Finalizer's role is constructing the scriptSig and scriptWitness
... it then deletes all data except the UTXO, scriptSig, and scriptWitness."

**Core:** `psbt.cpp:163-176` `PSBTInput::FromSignatureData`:
```cpp
if (sigdata.complete) {
    partial_sigs.clear();
    hd_keypaths.clear();
    redeem_script.clear();
    witness_script.clear();
    ...
}
```

**Symptom:** A finalized PSBT serialized round-trip works (encoder
skips producer fields when finals are set, line 1638), but an
introspection RPC (`decodepsbt` reading from a not-yet-saved in-memory
PSBT) reports stale producer fields. Cosmetic + spec-compliance.

**Fix:** Clear producer fields in P2WPKH/P2PKH paths to match the
legacy-multisig path.

### BUG-18 — Missing RPCs: `joinpsbts`, `utxoupdatepsbt`, `descriptorprocesspsbt`

**Severity:** P1 (RPC parity)

**Where:** `crates/rpc/src/server.rs`. The wallet RPC exposes
`createpsbt`, `decodepsbt`, `combinepsbt`, `finalizepsbt`,
`analyzepsbt`, `walletcreatefundedpsbt`. NOT exposed:
- `joinpsbts` — Concatenate multiple PSBTs' inputs/outputs into one.
- `utxoupdatepsbt` — Fill `witness_utxo`/`non_witness_utxo` from chain.
- `descriptorprocesspsbt` — Sign+finalize from descriptor.

**Core:** `bitcoin-core/src/rpc/rawtransaction.cpp::joinpsbts`,
`utxoupdatepsbt`, `bitcoin-core/src/wallet/rpc/spend.cpp::descriptorprocesspsbt`.

**Symptom:** Workflow gaps. `utxoupdatepsbt` in particular is the
standard "fill in inputs from on-chain data" RPC; without it, users
have to construct PSBTs with pre-populated UTXO info manually.

**Fix:** Add the three RPCs. `joinpsbts` is purely arithmetic
(concat inputs/outputs and validate no duplicate prevouts);
`utxoupdatepsbt` needs UTXO-set + tx lookups; `descriptorprocesspsbt`
needs descriptor-driven signing pipeline.

### BUG-19 — `Psbt::merge` skips out-of-bounds `other` inputs silently

**Severity:** P2

**Where:** `Psbt::merge` lines 816-827:
```rust
for (i, other_input) in other.inputs.iter().enumerate() {
    if i < self.inputs.len() {
        ... merge ...
    }
}
```
If `other.inputs.len() > self.inputs.len()`, the excess inputs are
silently dropped. Same for outputs (line 830-834).

**Core:** `psbt.cpp:30-32` returns false on differing tx hash, but
PSBTs sharing the same tx hash MUST have the same input/output count
by construction (the tx hash commits to vin/vout lengths). So the
case "same txid, different input count" can't happen unless one PSBT
is malformed. Core implicitly relies on this.

rustoshi's check at line 794 is `self.unsigned_tx.txid() == other.unsigned_tx.txid()`.
If txids match, vin/vout counts MUST match (txid commits to them).
So the `if i < self.inputs.len()` is dead-code defensive — but it
silently drops data instead of `assert` or `return Err`.

**Symptom:** No real-world impact (precondition guards make this
unreachable), but the silent-drop pattern is fragile. Future code
change to allow merge without txid check would expose data loss.

**Fix:** Replace `if i < self.inputs.len()` with
`assert_eq!(other.inputs.len(), self.inputs.len())` or
`return Err(PsbtError::IncompatiblePsbts)`.

### BUG-20 — `Psbt::deserialize` does NOT verify `unsigned_tx.vin.len() == inputs.len()` or `vout.len() == outputs.len()` upfront

**Severity:** P0-CDIV

**Where:** `Psbt::decode` lines 2020-2030 reads `num_inputs = unsigned_tx.inputs.len()` and loops `for _ in 0..num_inputs`. Same for outputs. So input/output counts are derived from `unsigned_tx` and cannot diverge. **However** if the stream runs out before `num_inputs` inputs are read, `decode_psbt_input` will return an IO error — but the error doesn't say "expected N inputs, got fewer" — it'll be an EOF on the inner read.

**Core:** `psbt.h:1365-1397`:
```cpp
while (!s.empty() && i < tx->vin.size()) {
    ... read input ...
}
if (inputs.size() != tx->vin.size()) {
    throw "Inputs provided does not match the number of inputs in transaction.";
}
```
Core has an explicit count-mismatch check at the end. rustoshi's count
is implicit via the loop bound, but if the stream has EXCESS bytes
after the inputs, those become outputs (rustoshi has no
"if extra bytes after outputs" check either). Actually rustoshi DOES
loop `for _ in 0..num_outputs` and outputs are bounded — but excess
data after the last output is silently discarded by the cursor on
return.

**Core:** `psbt.cpp:617-630` `DecodeRawPSBT`:
```cpp
SpanReader ss_data{tx_data};
try {
    ss_data >> psbt;
    if (!ss_data.empty()) {
        error = "extra data after PSBT";
        return false;
    }
}
```
Core has an explicit "extra data after PSBT" check.

**Symptom:** A PSBT with extra bytes appended after the legitimate
output map(s) is silently accepted by rustoshi but rejected by Core.
Cross-impl divergent decode on padded PSBTs (could be deliberate
fingerprinting).

**Fix:** After the output loop, check `cursor.position() == data.len()`.

### BUG-21 — `PSBT_IN_RIPEMD160` / `SHA256` / `HASH160` / `HASH256` preimages lack hash-vs-preimage verification

**Severity:** P1

**Where:** `decode_psbt_input` lines 2240-2287. The decoder accepts
arbitrary `(hash, preimage)` pairs without verifying `HASH(preimage) == hash`.

**Core:** Same — Core does NOT verify either. But Core's PSBT finalizer
re-checks at finalize time inside SignStep. rustoshi's finalizer does
NOT use the preimages at all (it's hash-locked-script-unaware) — so
preimages stored in the PSBT are useless for finalization.

**Symptom:** A counterparty's PSBT carries `sha256_preimages: {hashA → garbage}`.
rustoshi accepts it. Then finalize fails because rustoshi can't build
hash-locked-script witnesses. Confusing UX.

**Fix:** Either verify `HASH(preimage) == hash` at decode (defensive
strict mode) or extend the finalizer to consume preimages for
HASH160/HASH256/SHA256/RIPEMD160 preimage-protected scripts.

### BUG-22 — `Psbt::finalize` returns `Ok(())` even if no inputs were actually finalized

**Severity:** P2

**Where:** `Psbt::finalize` lines 1029-1034:
```rust
pub fn finalize(&mut self) -> Result<(), PsbtError> {
    for i in 0..self.inputs.len() {
        self.finalize_input(i)?;
    }
    Ok(())
}
```
Wait — `finalize_input` returns `Err(CannotFinalize)` for unfinalizable
inputs (line 1023-1025), so `?` propagates. The function only returns
`Ok(())` if ALL inputs were finalized.

Actually re-reading: `finalize_input` (line 874-1026) returns `Ok(())`
either if the input was already finalized (line 882-884) OR if a
finalization path succeeded. The only `Err` path is the catchall
"insufficient data or unsupported script type" at the end.

But the `finalizepsbt` RPC at line 6480 does
`let _finalize_result = psbt.finalize();` — discards the result —
then checks `psbt.is_finalized()`. So `_finalize_result = Err(...)`
on ANY single input failure aborts the entire chain, leaving SOME
inputs finalized and others not. The post-`finalize` PSBT may then
have a half-finalized state. The encoder will emit a partial PSBT.

**Core:** `FinalizePSBT` (`psbt.cpp:551-565`) iterates and tracks
`complete &= ...` per input — does NOT short-circuit on the first
failure:
```cpp
for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
    PSBTInput& input = psbtx.inputs.at(i);
    complete &= (SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, ...) == PSBTError::OK);
}
return complete;
```
Every input is attempted regardless of others.

**Symptom:** A PSBT with 5 inputs, where input 2 is malformed: rustoshi
finalizes input 0, input 1, then errors on input 2 and STOPS. Inputs
3, 4 are left unprocessed. Core would finalize 0, 1, 3, 4 and report
"complete: false."

**Fix:** Change `finalize` to accumulate per-input results instead of
propagating the first error. Match Core's "best-effort" semantics.

### BUG-23 — `PSBT_GLOBAL_PROPRIETARY` and per-input/output proprietary lack identifier-uniqueness validation

**Severity:** P2

**Where:** `decode` line 1993-2008, `decode_psbt_input` line 2410-2423,
`decode_psbt_output` line 2604-2617. All three blindly insert the
proprietary entry into a BTreeSet keyed by `key` (the raw key bytes).
A malicious PSBT can stuff duplicate proprietary entries with the
same identifier+subtype+subkeydata but different value — only the
LAST is kept.

**Core:** `psbt.h:846-848`:
```cpp
if (m_proprietary.contains(this_prop)) {
    throw std::ios_base::failure("Duplicate Key, proprietary key already found");
}
```
where `PSBTProprietary::operator==` compares by `key` field.

Actually rustoshi's BTreeSet insert returns the bool — but rustoshi
doesn't check it. So duplicates are silently kept-as-set-deduped, NOT
rejected. Same end-state (only one entry kept) but DIFFERENT error
semantics from Core.

**Symptom:** Cross-impl divergence on duplicate-proprietary PSBTs.

**Fix:** Check the BTreeSet `insert` return value; return DuplicateKey
on false.

### BUG-24 — Per-input `unknown` field can have raw `key.size() == 1` collision with reserved type bytes

**Severity:** P2

**Where:** `decode_psbt_input` line 2424-2427:
```rust
_ => {
    input.unknown.insert(key, value);
}
```
Any unrecognized `key_type` is stuffed into `unknown`. But this means
future BIP-174 reserved type bytes (e.g., a future
`PSBT_IN_FUTURE_FEATURE = 0x19`) that aren't yet implemented will be
treated as "unknown" — which is correct BIP-174 behavior for
forward-compatibility. But it also means a malformed PSBT with
`key.len() == 1` and `key_type = 0x19` (not yet allocated) silently
passes.

**Core:** `psbt.h:853-861` default branch does the same. So this
matches Core. Not a bug — listing here for completeness.

**Verdict:** No fix needed; documenting that the "unknown" pattern
is the BIP-174 escape hatch.

### BUG-25 — `decodepsbt` fee accounting can underflow on adversarial inputs

**Severity:** P2

**Where:** `decodepsbt` RPC implementation (server.rs:6079+) accumulates
`total_input_value` via `Option<u64>`. If any input lacks UTXO info,
the total stays None. But if `input.witness_utxo.value` is read from
an attacker-supplied (CVE-2020-14199 unverified — see BUG-16)
witness_utxo, the displayed total/fee is wrong.

**Symptom:** Combined with BUG-16, displayed fee is attacker-controlled.

**Fix:** Apply BUG-16's hoist of W41 A2 check to deserialize.

### BUG-26 — `finalizepsbt` RPC discards finalize() error and never reports WHICH input failed

**Severity:** P2

**Where:** server.rs:6480 `let _finalize_result = psbt.finalize();`
discards the per-input failure reason. The response shape is just
`{complete: false, psbt: ...}` with no indication of which input
couldn't be finalized.

**Core:** Returns the partial PSBT similarly. But the per-input
failure reason is available via `SignPSBTInput`'s `PSBTError` return.
A higher-level UI can call `analyzepsbt` for per-input next-role
verdicts.

**Symptom:** UX-only.

**Fix:** Cross-reference with BUG-22 (finalize semantics fix). Use
`analyzepsbt` for per-input verdicts in the same flow.

### BUG-27 — `analyzepsbt` does not report `estimated_vsize` or `fee_rate`

**Severity:** P2 (cosmetic — Core has these optional fields)

**Where:** server.rs `analyzepsbt` (lines 6513-6554) reports `inputs[]`
and `next`. Core's `AnalyzePSBT` (`node/psbt.cpp:88-130`) also reports:
- `estimated_vsize` — predicted virtual size of the final tx
- `estimated_feerate` — fee rate after finalization
- `fee` — calculated fee

**Core:** Returns those fields when the analyzer can dummy-sign all
inputs successfully.

**Symptom:** Wallet UIs displaying "estimated fee" from
`analyzepsbt` get less info from rustoshi than from Core.

**Fix:** Compute estimated_vsize from `tx.vsize` + per-input
dummy-witness size adjustments. fee = sum(input_utxo.value) -
sum(output.value), available only when all UTXOs known.

### BUG-28 — `Psbt::deserialize` `MAX_PSBT_SIZE` enforcement misses streaming case

**Severity:** P3

**Where:** `Psbt::deserialize` lines 1174-1180:
```rust
pub fn deserialize(data: &[u8]) -> Result<Self, PsbtError> {
    if data.len() > MAX_PSBT_SIZE {
        return Err(...);
    }
    let mut cursor = Cursor::new(data);
    Self::decode(&mut cursor)
}
```
`MAX_PSBT_SIZE = 100_000_000` (100 MB). The check is upfront, OK.
But `Psbt::decode<R: Read>` (line 1884) takes any Reader — a streaming
caller can bypass the size check.

**Core:** `psbt.h:77` defines `MAX_FILE_SIZE_PSBT = 100000000` but the
limit is enforced at the SpanReader/file-read level, not in the
parser. Same shape as rustoshi.

**Symptom:** A streaming caller (e.g. reading from a network socket)
can submit arbitrarily large PSBTs. Memory DoS surface.

**Fix:** Add a `LimitedReader` wrapper in `decode`, or document the
limit-enforcement contract.

### BUG-29 — `PSBT_OUT_BIP32_DERIVATION` lacks pubkey-validity check at decode

**Severity:** P0-CDIV

**Where:** `decode_psbt_output` lines 2485-2502. The 33-byte pubkey
is extracted from `key[1..34]` and used as a BTreeMap key without any
`IsFullyValid()` check.

**Core:** `psbt.h:153-159` (used for both input and output via
`DeserializeHDKeypaths`):
```cpp
CPubKey pubkey(key.begin() + 1, key.end());
if (!pubkey.IsFullyValid()) {
   throw std::ios_base::failure("Invalid pubkey");
}
```

**Symptom:** Same as BUG-4 but for output BIP32 derivation. A 33-byte
garbage string with valid prefix byte (0x02/0x03) passes rustoshi.

**Fix:** Check `secp256k1::PublicKey::from_slice(...)` before insertion
for both `PSBT_IN_BIP32_DERIVATION` (line 2185-2202) and
`PSBT_OUT_BIP32_DERIVATION` (line 2485-2501).

### BUG-30 — `PSBT_GLOBAL_XPUB` key-size check loose

**Severity:** P2

**Where:** `decode` lines 1945-1968. `if key.len() != 79` matches Core
(1 type byte + 78 xpub bytes). But: rustoshi accepts the 78 bytes as
raw xpub data without any internal-shape validation (depth field
sanity, chain code bytes — all just stored in a `[u8; 78]` array).

**Core:** `psbt.h:1289-1295`:
```cpp
CExtPubKey xpub;
xpub.DecodeWithVersion(&key.data()[1]);
if (!xpub.pubkey.IsFullyValid()) {
   throw "Invalid pubkey";
}
```
Core decodes the 78 bytes into a CExtPubKey AND validates the
embedded pubkey via IsFullyValid.

**Symptom:** A PSBT carrying a malformed PSBT_GLOBAL_XPUB (invalid
embedded pubkey in the xpub bytes) passes rustoshi's decoder but
fails Core's. Cross-impl divergent decode.

**Fix:** Parse the 78 bytes per BIP-32 layout, extract bytes 45..78
as the compressed pubkey, validate.

## Summary

**Total bugs catalogued: 30** (BUG-1 through BUG-30; BUG-24 documented
as non-bug for completeness).

**Severity breakdown:**
- **P0-CDIV (consensus / cross-impl decode divergence):** 11 — BUG-1,
  BUG-2, BUG-3, BUG-4, BUG-5, BUG-7, BUG-12, BUG-14, BUG-20, BUG-29,
  BUG-30. These are PSBT decoder permissiveness bugs where rustoshi
  silently accepts what Core rejects (or vice versa for BUG-12).
- **P1 (feature gap / API parity):** 12 — BUG-6, BUG-8, BUG-9, BUG-10,
  BUG-11, BUG-13, BUG-15, BUG-18, BUG-21, BUG-23, BUG-27 (P2 but
  promoted as visible).
- **P2-P3 (cosmetic / UX):** 7 — BUG-16, BUG-17, BUG-19, BUG-22,
  BUG-25, BUG-26, BUG-28.

**v0 vs v2 coverage:**
- **PSBT v0 (BIP-174):** 28 of 30 bugs apply. Comprehensive.
- **PSBT v2 (BIP-370):** 1 bug — BUG-15 — entire v2 path is absent
  (matches Core's PSBT_HIGHEST_VERSION=0 today). Not a Core-divergence
  but a real-world feature gap. **Not a fix priority** until Core
  ships v2.
- **BIP-371 Taproot fields:** 4 bugs — BUG-5 (depth check), BUG-6
  (tree completeness), BUG-9 (Taproot input dedup), BUG-10 (empty
  tap_tree). All applicable to v0 PSBTs carrying Taproot data.
- **MuSig2 (BIP-327 / PSBT integration):** 2 bugs — BUG-7 (output
  encoder missing), BUG-8 (merge missing), BUG-11 (input fields
  entirely absent).

**Cross-cutting patterns:**
1. **Decoder permissiveness:** rustoshi's decoder has fewer
   duplicate-key / sig-encoding / pubkey-validity checks than Core
   (BUG-2/3/4/9/12/14/29/30). Pattern: BTreeMap-insert-silently-overwrites
   in places where Core has explicit `if contains() throw "Duplicate"`.
2. **Decode-vs-sign defense asymmetry:** W41 A2 amount-oracle check
   is in `sign_psbt_input` only, not in `Psbt::deserialize`. Consumers
   reading PSBT data directly (decodepsbt fee display) bypass the
   defense (BUG-16, BUG-25).
3. **Round-trip dropped fields:** MuSig2 participant pubkeys decoded
   but never encoded (BUG-7) — the classic "well-engineered helper
   never wired" anti-pattern.
4. **Spec compliance gaps:** BIP-371 tap_tree validation missing
   (BUG-5, BUG-6, BUG-10) — the audit-friendly invariants are in
   Core but not in rustoshi.
5. **No PSBT v2:** parity with Core. Documented as feature gap, not
   bug, but tracked.

## Next steps

A future fix wave (FIX-86+) can land in tiers:
- **Tier-1 (decoder hardening):** BUG-2, BUG-3, BUG-4, BUG-5, BUG-6,
  BUG-9, BUG-10, BUG-29, BUG-30 — all in `decode_psbt_input` /
  `decode_psbt_output` / `decode`. ~150 LOC, mostly adding
  `key_lookup.insert(key.clone()).then(...)` and
  `secp256k1::PublicKey::from_slice` checks.
- **Tier-2 (MuSig2 + completeness):** BUG-7, BUG-8, BUG-11 — wire the
  output encoder, merge, and add input MuSig2 fields. ~200 LOC.
- **Tier-3 (defense hoist):** BUG-16 — move CVE-2020-14199 check to
  `Psbt::decode`. ~30 LOC.
- **Tier-4 (RPC parity):** BUG-18 — add `joinpsbts`, `utxoupdatepsbt`,
  `descriptorprocesspsbt`. ~600 LOC across server.rs.

These are NOT actioned in this wave (DISCOVERY only); the audit gates
in `crates/wallet/tests/test_w137_psbt.rs` flip on each BUG-N closure.

## Cross-impl context

Related waves and shared findings:
- **W36 (rustoshi)** — original BIP-174 byte-layout fix (no inner
  CompactSize on BIP32_DERIVATION values). Mirrored from nimrod W34-C.
  Closure pinned by existing tests `test_w36_*`.
- **W41 (rustoshi)** — A1 (non_witness_utxo txid sanity) + A2
  (witness/non-witness amount oracle, CVE-2020-14199). Closure pinned
  by existing tests `test_w41_*`. The A2 check is sign-path-only; this
  audit's BUG-16 / BUG-25 catalogue the decode-path gap.
- **W46 (rustoshi)** — legacy P2SH-multisig finalize. Closure pinned;
  this audit's BUG-17 catalogues the P2WPKH/P2PKH analog where
  producer fields are NOT cleared.
- **W47/W48 (rustoshi)** — analyzepsbt + missing-sigs reporting.
  Closure pinned; this audit's BUG-26 / BUG-27 catalogue the
  estimated_vsize / fee_rate completeness gap.
- **W49 (rustoshi)** — partial_sig HASH160-order emission. Closure
  pinned by existing serialization test.
- **W127 (rustoshi)** — Taproot / Schnorr / Tapscript discovery.
  Companion to this audit's BIP-371 PSBT-field findings (BUG-5/6/10).
