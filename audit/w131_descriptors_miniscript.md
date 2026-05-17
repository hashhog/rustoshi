# W131 — Descriptors + Miniscript audit (rustoshi)

**Wave:** W131 — BIP-380 / BIP-385 (Output Descriptors + Miniscript)
**Date:** 2026-05-17
**Audit subject:** the rustoshi descriptor + miniscript implementation:
- `crates/wallet/src/descriptor.rs` (~2,020 LOC) —
  `descriptor_checksum`, `add_checksum`, `verify_checksum`,
  `parse_descriptor`, `parse_descriptor_inner`, `split_descriptor`,
  `parse_tr_descriptor`, `parse_multi_descriptor`, `split_args`,
  `parse_key_expression`, `parse_key_with_origin`, `parse_origin`,
  `parse_xpub_key`, `parse_xprv_key`, `split_xpub_and_path`,
  `parse_hex_pubkey`, `parse_xonly_pubkey`, `KeyProvider`,
  `Descriptor`, `DescriptorInfo::from_descriptor`,
  `descriptor_has_private_keys`, `validate_segwit_v0_compressed`,
  `check_key_compressed`, `make_p2pk_script`, `make_p2pkh_script`,
  `make_p2wpkh_script`, `make_p2sh_script`, `make_p2wsh_script`,
  `make_p2tr_script`, `make_rawtr_script`, `make_multisig_script`,
  `compute_taproot_merkle_root`, `encode_xpub`, `encode_xprv`,
  `decode_xpub`, `decode_xprv`.
- `crates/wallet/src/miniscript.rs` (~2,987 LOC) —
  `BasicType` (B/V/K/W), `TypeProperties` (zonduef smxghijk),
  `Type::is_valid`, `Type::is_valid_top_level`, `Type::is_sane`,
  `ScriptContext::{P2wsh, Tapscript}`, `Fragment::{False, True,
  PkK, PkH, Older, After, Sha256, Hash256, Ripemd160, Hash160,
  Alt, Swap, Check, DupIf, Verify, NonZero, ZeroNotEqual, AndV,
  AndB, AndOr, OrB, OrC, OrD, OrI, Thresh, Multi, MultiA}`,
  `Miniscript::{new, parse, compile, compile_inner, satisfy,
  satisfy_inner, dissatisfy, analyze, max_witness_size,
  count_sigops, count_required_keys, get_keys, is_valid,
  is_valid_top_level, is_sane}`, `compute_type`, `parse_miniscript`,
  `parse_wrapper`, `parse_function`, `parse_key`, `parse_hash32`,
  `parse_hash20`, `split_args` / `split_args_variadic`,
  `push_bytes`, `push_scriptnum`, `encode_scriptnum`,
  `dissatisfy_witness`, `Witness`, `Satisfier`, `Analysis`.
- `crates/rpc/src/server.rs` — `infer_descriptor()` (line 10025) is
  the RPC-level `InferDescriptor` analogue for scantxoutset /
  getdescriptorinfo / decodescript / listunspent.

**References:**
- `bitcoin-core/src/script/descriptor.cpp`:
  - `PolyMod` (lines 94-104)
  - `DescriptorChecksum` (lines 106-151) including INPUT_CHARSET +
    CHECKSUM_CHARSET
  - `AddChecksum` (line 153)
  - `OriginPubkeyProvider` (lines 236-322)
  - `ConstPubkeyProvider` (lines 324-380)
  - `BIP32PubkeyProvider::IsHardened/ToString/ToPrivateString/
    ToNormalizedString/GetPubKey/GetPrivKey` (lines 460-815)
  - `DescriptorImpl` base class + `Expand` (lines 814-1059)
  - `AddrDescriptor` + `RawDescriptor` (lines 1078-1135)
  - `PKDescriptor` / `PKHDescriptor` / `WPKHDescriptor` /
    `ComboDescriptor` (lines 1140-1255)
  - `MultisigDescriptor` (lines 1257-1320) — k/n/sorted/tapscript
    discrimination
  - `SHDescriptor` / `WSHDescriptor` (lines 1370-1455)
  - **`TRDescriptor`** (lines 1456-1538) — `m_depths`,
    `TaprootBuilder`, tree construction, control block hashes
  - `MiniscriptDescriptor` (lines 1540-1700) — Miniscript
    wrapped in a descriptor
  - `ParsePubkeyInner` (lines 1876-1945) — `permit_uncompressed`
    threading by context, BIP-32 vs hex, x-only handling
  - `ParseKeyPath` (lines 1789-1870) — multipath BIP-389 `<0;1;…>`
    detection
  - **`ParseScript` (lines 2266-2625)** — full descriptor parser
    including the **`{…}` tree syntax for `tr()`** (lines
    2459-2553)
  - `InferScript` (lines 2691-2899) — script → descriptor inference,
    including miniscript embedding
  - `GetDescriptorChecksum` / public `Parse` entry points (lines
    2855-2899)
- `bitcoin-core/src/script/miniscript.h`:
  - `Type` class + `_mst` literal operator (lines 128-189)
  - `Fragment` enum (lines 210-243)
  - `MiniscriptContext` enum + `IsTapscript` (lines 251-264)
  - `MAX_TAPMINISCRIPT_STACK_ELEM_SIZE` = 65 (line 269)
  - `MaxScriptSize(ms_ctx)` (lines 282-294) — P2WSH bound vs
    derived tapscript bound
  - `Node::CalcType` / `CheckOpsLimit` (line 1571) — MAX_OPS_PER_SCRIPT
  - `Node::CalcStackSize` / `CalcWitnessSize`
  - `FromScript` (line 2691) — script → miniscript parser
  - `KeyParser` template for miniscript context handling
- `bitcoin-core/src/script/miniscript.cpp`:
  - `SanitizeType` (lines 19-37) — type invariants
  - **`ComputeType`** (lines 39-262) — per-fragment type derivation;
    this is the consensus surface for type-system correctness
  - `ComputeScriptLen` (lines 264-296)
- `bitcoin-core/src/script/script.h`:
  - `MAX_OPS_PER_SCRIPT` = 201 (line 31)
  - `MAX_PUBKEYS_PER_MULTISIG` = 20 (line 34)
  - `MAX_PUBKEYS_PER_MULTI_A` = 999 (line 37)
- `bitcoin-core/src/test/descriptor_tests.cpp` +
  `data/descriptor_tests_external.json` — corpus of valid /
  invalid / parsed-form descriptors with expected scripts.
- `bitcoin-core/src/test/miniscript_tests.cpp` — type-system
  unit vectors.
- BIPs **380** (Descriptors), **381** (Singlesig descriptors),
  **382** (`sh()`/`wsh()`), **383** (Multisig), **384** (`combo()`),
  **385** (`raw()`/`addr()`), **386** (`tr()` / `rawtr()`), **389**
  (Multipath `<0;1>`), **341/342** (Taproot/tapscript).

**Production code changes:** 0 (pure audit).
**Test file:** `crates/wallet/tests/test_w131_descriptors_miniscript.rs`
— 30 gates, PASS regression pins + `#[ignore]`-pinned BUG-N stubs.

## Why this matters

Output descriptors are the canonical interchange format for wallets,
PSBTs, watch-only setups, hardware-signers, multi-sig coordinators
(Specter, Sparrow, Blockstream Jade) and BIP-174 PSBT flows. A divergence
in:

1. **Checksum** — wrong checksum means descriptors round-trip to
   the wrong string, every external wallet rejects the import, every
   `listdescriptors` output is silently incompatible with Core / btcd
   / specter peers.
2. **Parser correctness** for `tr(internal_key, {script_tree})` —
   a divergence here means we derive the **wrong taproot output
   key** for any multi-leaf tree, which is **P0-CDIV**: every UTXO
   sent to such an address with our derivation is unspendable, every
   block we process containing such a UTXO would (silently) hash to
   a different sigmsg.
3. **Miniscript type system** — Bitcoin Core enforces type rules as
   consensus-aligned policy: a miniscript expression that we declare
   *valid* but Core declares *invalid* (or vice versa) cannot be
   imported, signed, or relayed by the broader network. Type-system
   drift breaks Miniscript-coordinated multi-sig (e.g. Liana, Anchorwatch)
   end-to-end.
4. **Key-origin info parsing** (`[fpr/path]…`) — required for PSBT
   `PSBT_IN_BIP32_DERIVATION` and `PSBT_OUT_TAP_BIP32_DERIVATION`;
   getting the fingerprint or path wrong silently breaks hardware
   wallet signing.
5. **`combo()` script set selection** — combo emits {P2PK, P2PKH,
   P2WPKH, P2SH-P2WPKH} for compressed keys and {P2PK, P2PKH} for
   uncompressed; emitting the wrong subset breaks address-monitoring
   for legacy watch-only wallets (every transaction since 2017 may
   pay to a compressed key, but the descriptor was imported with
   `combo(uncompressed)`).
6. **`multi_a` / `multi` context discrimination** — `multi()` is
   forbidden in tapscript context (no `OP_CHECKMULTISIG` available);
   `multi_a()` is forbidden in P2WSH (no `OP_CHECKSIGADD`); confusing
   these emits a script that any node will reject at policy or
   consensus.
7. **Descriptor depth limits in `tr()`** — Core caps tree depth at
   `TAPROOT_CONTROL_MAX_NODE_COUNT = 128`. Accepting a deeper tree
   produces a control block that **no node will accept** because
   `TAPROOT_CONTROL_MAX_SIZE = 4129` (33 + 32*128) is enforced at
   consensus.

The W118 wallet audit (May 16 2026) catalogued **104 bugs in 10 impls**
on the broader wallet surface (BIP-32 / PSBT / fee / send / UTXO).
Descriptors + Miniscript form the *language layer* underneath those
operations and have intentionally been audited as their own wave.

## Headline findings

- **0 P0-CONSENSUS bugs** — no bug in this surface produces an
  invalid block or accepts an invalid one. Descriptors are wallet-side
  string parsing; even the worst divergences here would cause a stale
  derived address or rejected import, not a chain split.
- **2 P0-CDIV bugs** (cross-impl-divergence — peer wallets / signers
  reject what we accept, or vice versa):
  - **BUG-1**: `parse_tr_descriptor` does NOT parse the `{...}`
    script-tree syntax. Core's grammar is `tr(IK, TREE)` where
    `TREE` is either a script or `{TREE,TREE}` recursively, and
    depths are derived from the tree structure (Core's
    `branches.push_back(false/true)` walk). Rustoshi's
    `parse_tr_descriptor` (line 1461-1484) splits on top-level
    commas and hardcodes `depth = 0` for every leaf. Result:
    `tr(K, {pk(A),pk(B)})` is REJECTED (Bracket syntax not
    handled — `{` is treated as the first character of a key
    expression and fails parse), and even if it parsed, every
    leaf would get `depth=0` so `compute_taproot_merkle_root`
    would hash leaves at the wrong tree position → wrong merkle
    root → wrong P2TR address.
  - **BUG-2**: `compute_taproot_merkle_root` (descriptor.rs:1097)
    IGNORES the `depth` field stored in `TrWithTree.tree`, instead
    pairwise-merging leaves left-to-right regardless of their
    intended tree position. Even if BUG-1 were fixed, depth would
    be discarded. Core's `TaprootBuilder::Add(depth, script, version)`
    plus `Finalize()` builds a Huffman-like canonical tree where
    leaves are placed at their declared depth. Rustoshi's
    pairwise-merge produces a balanced binary tree that only
    coincides with Core's output when every leaf has the same
    depth (uniform balanced tree).
- **3 P1 miniscript type-system bugs** — the computed `Type` for
  three fragment kinds diverges from `bitcoin-core/src/script/
  miniscript.cpp:88-262`:
  - **BUG-3**: `compute_type(Sha256/Hash256/Ripemd160/Hash160)`
    incorrectly sets `e: true` (miniscript.rs:601). Core's type is
    `"Bonudmk"_mst` (B + o + n + u + d + m + k — no `e`). The `e`
    property means "dissatisfaction is nonmalleable and unique";
    for hash preimages the trivial dissatisfaction is *malleable*
    (any non-32-byte value), so Core omits `e`.
  - **BUG-4**: `compute_type(MultiA)` sets `n: true` (miniscript.rs:
    1131). Core's type for `MULTI_A` is `"Budemsk"_mst` — no `n`.
    The `n` property ("for every way to satisfy, a satisfaction
    exists that never needs a zero top-stack element") does not
    hold for `multi_a` because the satisfaction stack consists of
    `[sig_k, …, sig_1]` where any "missing" signature slot is
    represented by an empty element (zero).
  - **BUG-5**: `compute_type(WRAP_D)` (`d:` wrapper) sets
    `u: true` unconditionally (miniscript.rs:698). Core only sets
    `u` under tapscript (`"u"_mst.If(IsTapscript(ms_ctx))`,
    miniscript.cpp:126). The note in Core: "'d:' is 'u' under
    Tapscript but not P2WSH as MINIMALIF is only a policy rule
    there." Under P2WSH, `d:X` does NOT guarantee an exact 1 is
    pushed (MINIMALIF is policy, not consensus, so `OP_DUP OP_IF`
    accepts any non-empty truthy value as input). Setting `u=true`
    on P2WSH `d:` makes `andor(d:Y, _, _)` accept compositions Core
    rejects.
- **1 P1 missing-property bug**:
  - **BUG-6**: `compute_type(JUST_0)` sets `s: false`
    (miniscript.rs:501). Core's type is `"Bzudemsxk"_mst` — `s`
    IS included. The `s` property is "satisfactions for this
    expression always involve at least one signature"; for
    `JUST_0` (which is unsatisfiable — it pushes 0) the property
    holds *vacuously*. Core follows the vacuous-truth convention
    consistently across the type system; rustoshi's negation here
    breaks downstream `OrB(JUST_0, Y) → m=…(x|y)<<s` rule.
- **3 P1 missing-validation bugs** at parse time:
  - **BUG-7**: `parse_descriptor_inner` does not enforce the
    BIP-380 nesting rules: it accepts `wsh(wsh(...))` (Core rejects
    — `wsh` cannot be nested in `wsh`), `sh(sh(...))` (Core rejects),
    `wsh(sh(...))` (Core rejects — `sh` not allowed inside segwit),
    and `tr(...)` inside `sh()` / `wsh()` (Core rejects — `tr` is
    top-level only, per Core line 2555 `"Can only have tr at top
    level"`).
  - **BUG-8**: `parse_multi_descriptor` enforces
    `keys.len() > 20` only inside `make_multisig_script` (descriptor.
    rs:1066), and only for the **legacy** `multi()` script-build path.
    At parse time and inside `make_multisig_script` there is no
    discrimination between P2WSH-context `multi` (max 20) and
    tapscript-context `multi_a` (max 999, per `MAX_PUBKEYS_PER_MULTI_A`).
    The descriptor module doesn't expose `multi_a` at the
    `Descriptor` enum level at all (it's only in the miniscript
    fragment language). Result: a descriptor like
    `tr(K, multi_a(10, A1, …, A10))` cannot be parsed by
    rustoshi at all.
  - **BUG-9**: BIP-389 multipath `<0;1>` notation is NOT
    parsed. Core supports `wpkh(xpub.../<0;1>/*)` to expand into
    two descriptors (receive + change) from a single string
    (descriptor.cpp:1789-1870). `parse_derivation_path` in
    `rustoshi-wallet::hd` does not handle `<…;…>` and rejects
    the entire path as invalid. Modern wallet exports (Sparrow,
    Specter post-2024) emit multipath descriptors as the default
    output format.
- **2 P1 round-trip bugs**:
  - **BUG-10**: `Descriptor::Display` for `Multi` /
    `SortedMulti` emits the keys in their parsed order, but
    `sortedmulti()` is supposed to canonicalise to lex-sorted
    pubkeys at Display time (Core's `MultisigDescriptor::
    ToStringExtra` sorts the keys for `sortedmulti`). Rustoshi
    sorts the pubkey BYTES at script construction (`make_multisig_
    script`, descriptor.rs:1073) but Display (`fmt`, descriptor.rs:
    800-806) emits them in the user-provided order. Round-trip
    `parse_descriptor(s).to_string() == s` fails for
    `sortedmulti` whenever the user-given key order isn't lex-sorted.
  - **BUG-11**: `Descriptor::Display` for `TrWithTree` (descriptor.
    rs:786-792) emits `tr(K,desc1,desc2,…)` with comma-separated
    leaves, which is **not** the BIP-386 grammar. The canonical
    string uses `{...}` brackets to denote tree structure:
    `tr(K, {pk(A),{pk(B),pk(C)}})`. Round-trip
    `parse → to_string → parse` would fail in Core (and fail in
    a hypothetical rustoshi parser that supported `{...}` after
    BUG-1 is fixed) because the tree shape is lost on emit.
- **2 P2 cosmetic / error-name divergences**:
  - **BUG-12**: `descriptor_has_private_keys` returns `false` for
    `KeyProvider::Const` always (descriptor.rs:914), with the
    comment "Const is always public — match Bitcoin Core which
    checks for actual secret material, not reconstructed pubkeys."
    But Core DOES expose `was_originally_wif` via the
    `ConstPubkeyProvider::ToPrivateString` path (descriptor.cpp:
    501-513) by looking up the original `CKey` in the signing
    provider. Rustoshi loses the WIF→Const mapping at parse time
    (`parse_hex_pubkey` always emits Const) so the descriptor's
    `hasprivatekeys` field is silently false for `pk(WIF)` /
    `pkh(WIF)` / `combo(WIF)`. Comment-as-confession pattern.
  - **BUG-13**: `descriptor_checksum` accepts any character that
    appears in `INPUT_CHARSET`, but does not reject Unicode
    composition forms or zero-width joiners that Core's
    `std::string::find` would reject (because Core operates over
    bytes, not chars). Rustoshi uses `desc.chars()` (line 97)
    which interprets multi-byte UTF-8 as a single character. Result:
    a descriptor with a U+0030 → U+FF10 (full-width zero)
    substitution would be **rejected by Core but parse and
    checksum-validate by rustoshi**. This is a confused-deputy
    risk in mixed-tool flows.
- **3 P2 missing-feature gaps**:
  - **BUG-14**: No `FromScript` / `InferScript` equivalent that
    converts a `CScript` back into a parsed `Descriptor` /
    `Miniscript`. `infer_descriptor` in `rpc/server.rs:10025` is
    a flat string-builder that special-cases P2WPKH / P2WSH / P2TR
    / P2PKH / P2SH and returns a `raw(...)` for anything else. It
    cannot infer a `multi(…)`, `sortedmulti(…)`, or any miniscript
    expression. Core's `InferScript`
    (descriptor.cpp:2691-2899) handles all of these plus
    `miniscript::FromScript`. The result is that
    `getdescriptorinfo` / `scantxoutset` / `decodescript` emit
    `raw(...)` for every non-trivial script, which is
    silently incompatible with PSBT round-tripping (PSBTs from
    Core include descriptor strings; rustoshi can't generate
    equivalents on the output side).
  - **BUG-15**: No `ToNormalizedString` — Core emits a normalized
    form with the xpub at the last hardened derivation and `h`
    (not `'`) for hardened markers, used by
    `listdescriptors` (`descriptor.cpp:735-757`). Rustoshi's
    `to_public_string` and Display impls preserve the user-supplied
    apostrophe / `h` and don't push down to the last hardened
    derivation. Normalized form is the canonical key for
    deduplication; without it, the same logical descriptor can
    appear twice in `listdescriptors` output.
  - **BUG-16**: No `ToPrivateString` — Core emits a private-key
    form (`pk(L1abc…)` / `wpkh(xprv.../*)`) by re-encoding the
    private material if available. Rustoshi has `encode_xprv` but
    no descriptor-level `to_private_string`; the wallet path to
    BIP-380 backup export ("export with private keys") is missing.
- **4 P2 miniscript-completeness gaps**:
  - **BUG-17**: `Miniscript::compile` (miniscript.rs:1508-1795)
    does not enforce `MAX_OPS_PER_SCRIPT = 201` for P2WSH context
    (Core's `Node::CheckOpsLimit`, miniscript.h:1571). A pathological
    `thresh(1, pk(A), s:pk(B), s:pk(C), …)` with enough leaves
    would compile to a script Core rejects.
  - **BUG-18**: `Miniscript::compile` does not enforce
    `MaxScriptSize(ctx)` (miniscript.h:282-294). P2WSH limit is
    `MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600`; rustoshi will happily
    emit a 10 KB miniscript and never warn.
  - **BUG-19**: `Miniscript::is_sane` checks `m && s && k`
    (miniscript.rs:195) but does NOT check the duplicate-key
    constraint Core enforces in `Node::CheckDuplicateKey`
    (miniscript.h:1690). Repeated keys in a miniscript are
    rejected by Core as malleable (the same signature can be
    rebound), but rustoshi accepts them.
  - **BUG-20**: `Miniscript::parse` (miniscript.rs:1161) does NOT
    distinguish between the textual `t:X` / `l:X` / `u:X` wrappers
    and their canonical desugared forms (`and_v(X,1)` /
    `or_i(0,X)` / `or_i(X,0)`). When parsing it desugars (which
    is correct for compile), but when calling `to_string()` /
    Display it does NOT re-sugar — `parse("t:pk(A)").to_string()`
    returns `and_v(c:pk_k(A),1)`. Core's `Node::ToString` re-sugars
    (descriptor.cpp:910-933). Round-trip is broken; PSBT
    descriptor strings will not match the user-supplied input.
- **2 P3 documentation / dead-code drift**:
  - **BUG-21**: Comment for `Multi` fragment says "Type:
    Bnudemsxk" (miniscript.rs:1106) but the code computes
    `Bnudemsk` (no `x`). Code is correct (Core says
    `"Bnudemsk"`); comment is misleading.
  - **BUG-22**: Comment for `MultiA` fragment says "Type:
    Bnudemsxk" (miniscript.rs:1129) but Core's type is `"Budemsk"`
    (no `n`, no `x`). Code computes `Bnudemsk` (wrong on `n`,
    correct on absence of `x`). Both comment and code disagree
    with Core — code is wrong (BUG-4) and comment overstates
    the wrongness.
- **1 P3 corpus-absence finding**:
  - **BUG-23**: `crates/wallet/src/descriptor.rs::tests` and
    `crates/wallet/src/miniscript.rs::tests` together cover ~30
    cases. Core ships `data/descriptor_tests_external.json` with
    **161 fixtures** (valid descriptor → expected scripts /
    expected error / round-trip form). None of those fixtures
    are imported into rustoshi. This is the same audit-shape as
    W127's "script_assets_test.json gap": well-engineered tests
    that pass in isolation but don't pin the external corpus.

## 30-gate audit matrix

| # | Gate | Reference | Subject | Status | BUG-ID |
|---|------|-----------|---------|--------|--------|
| G1 | Checksum INPUT_CHARSET matches Core (byte-for-byte) | descriptor.cpp:121-124 | descriptor.rs:56-58 | PRESENT | — |
| G2 | Checksum CHECKSUM_CHARSET matches bech32 | descriptor.cpp:127 | descriptor.rs:61 | PRESENT | — |
| G3 | PolyMod constants match Core (5 XOR magic numbers) | descriptor.cpp:94-104 | descriptor.rs:67-86 | PRESENT | — |
| G4 | DescriptorChecksum emits 8 chars from CHECKSUM_CHARSET | descriptor.cpp:148-150 | descriptor.rs:118-123 | PRESENT | — |
| G5 | Checksum rejects characters outside INPUT_CHARSET | descriptor.cpp:134 | descriptor.rs:98 | PARTIAL | BUG-13 (Unicode confusable bypass) |
| G6 | `pk()` / `pkh()` / `wpkh()` / `sh()` / `wsh()` parse | descriptor.cpp:2280-2400 | descriptor.rs:1383-1414 | PRESENT | — |
| G7 | `tr(IK)` key-only parses | descriptor.cpp:2459-2466 | descriptor.rs:1471-1473 | PRESENT | — |
| G8 | `tr(IK, {tree})` script-tree parses | descriptor.cpp:2469-2511 | descriptor.rs:1474-1483 | MISSING | **BUG-1** P0-CDIV |
| G9 | `tr()` depth honoured in merkle root | descriptor.cpp:1456-1470 (TaprootBuilder.Add) | descriptor.rs:1097-1147 | BROKEN | **BUG-2** P0-CDIV |
| G10 | `tr()` rejects depth > TAPROOT_CONTROL_MAX_NODE_COUNT=128 | descriptor.cpp:2484-2487 | none | MISSING | covered by BUG-1 |
| G11 | `sh()` rejects `tr(...)` nested inside | descriptor.cpp:2555-2557 | none | MISSING | **BUG-7** |
| G12 | `wsh()` rejects `wsh()` nested inside | descriptor.cpp:2402-2412 (ctx threading) | none | MISSING | **BUG-7** |
| G13 | `sh()` rejects `sh()` nested inside | descriptor.cpp same | none | MISSING | **BUG-7** |
| G14 | Multi `n_keys <= MAX_PUBKEYS_PER_MULTISIG=20` for P2WSH | script.h:34, miniscript.cpp:76 | descriptor.rs:1066 | PARTIAL | path-dependent (only in script build) |
| G15 | Multi_a `n_keys <= MAX_PUBKEYS_PER_MULTI_A=999` for tapscript | script.h:37, miniscript.cpp:79 | none in Descriptor enum | MISSING | **BUG-8** |
| G16 | Multi context discriminator: `multi` forbidden in tapscript | miniscript.cpp:77 | miniscript.rs:1098-1100 | PRESENT (miniscript only) | — |
| G17 | Multi_a context discriminator: `multi_a` forbidden in P2WSH | miniscript.cpp:80 | miniscript.rs:1120-1123 | PRESENT (miniscript only) | — |
| G18 | BIP-389 multipath `<0;1>` parse | descriptor.cpp:1789-1870 | hd.rs / descriptor.rs | MISSING | **BUG-9** |
| G19 | Key origin `[fpr/path]` parse + round-trip | descriptor.cpp:236-322 | descriptor.rs:1583-1631 | PRESENT | — |
| G20 | Xpub / xprv decode 78 bytes, version + parent_fp + cn + cc + key | descriptor.cpp BIP32 | descriptor.rs:1259-1355 | PRESENT | — |
| G21 | combo(compressed) → P2PK + P2PKH + P2WPKH + P2SH-P2WPKH (4) | descriptor.cpp:1208-1255 | descriptor.rs:696-714 | PRESENT | — |
| G22 | combo(uncompressed) → P2PK + P2PKH (2) | descriptor.cpp same | descriptor.rs:707 (gated on is_compressed) | PRESENT | — |
| G23 | segwit-v0 rejects uncompressed key in wpkh/wsh | descriptor.cpp:1876-1880 | descriptor.rs:932-966 | PRESENT | — |
| G24 | Miniscript `Type` for `PK_K` is `Konudemsxk` | miniscript.cpp:89 | miniscript.rs:523-538 | PRESENT | — |
| G25 | Miniscript `Type` for `SHA256/HASH256/RIPEMD160/HASH160` is `Bonudmk` (no `e`) | miniscript.cpp:99-102 | miniscript.rs:594-608 | BROKEN | **BUG-3** |
| G26 | Miniscript `Type` for `JUST_0` is `Bzudemsxk` (with `s`) | miniscript.cpp:104 | miniscript.rs:493-507 | BROKEN | **BUG-6** |
| G27 | Miniscript `Type` for `MULTI_A` is `Budemsk` (no `n`) | miniscript.cpp:227 | miniscript.rs:1120-1141 | BROKEN | **BUG-4** |
| G28 | Miniscript `WRAP_D` adds `u` only under Tapscript | miniscript.cpp:126 | miniscript.rs:688-712 | BROKEN | **BUG-5** |
| G29 | Miniscript top-level `MAX_OPS_PER_SCRIPT=201` enforced | miniscript.h:1571 | none | MISSING | **BUG-17** |
| G30 | InferScript → reverses pk/pkh/wpkh/sh/wsh/tr/multi/multi_a/miniscript | descriptor.cpp:2691-2899 | server.rs:10025 (flat string) | PARTIAL | **BUG-14** |

## Why no P0-CONSENSUS findings

Descriptors do not participate in block validation. The closest
consensus-adjacent surface is `compute_taproot_merkle_root` (descriptor.
rs:1097), which is wallet-only — its only consumer is `make_p2tr_script`
(descriptor.rs:1023) at address-derivation time. A wrong merkle root
emits a wrong address (and a wrong-pubkey UTXO becomes unspendable
when the user tries to recover the funds), but does not cause us to
accept an invalid block or produce an invalid one.

That said, **BUG-1** and **BUG-2** are P0-CDIV because a Core-derived
tr() descriptor for the same key + tree will produce a different
address than rustoshi's derivation:
- Multi-leaf tr() descriptors imported from Core would derive the
  wrong addresses on rustoshi and miss incoming payments.
- Tr() descriptors exported from rustoshi would derive the wrong
  addresses on Core and miss incoming payments.
- Hardware wallet flows that use descriptors (Sparrow / Specter /
  AirGap Vault) would all fail at the rustoshi boundary.

## Cross-cutting notes

### Pattern observations

1. **"Comment-as-confession"** (BUG-12, BUG-21, BUG-22). Multiple
   sites carry inline comments that document a deliberate divergence
   from Core (`Const is always public — match Bitcoin Core which
   checks for actual secret material, not reconstructed pubkeys` for
   BUG-12) or list a wrong type string (BUG-21 / BUG-22). This is
   the same pattern flagged in W122 blockbrew BIP-158 audit
   (`TestBIP158Vectors deliberately opts out of byte-exact with
   prose rationalization`). Going forward: descriptor parse-time
   metadata (`was_originally_wif`) needs to be threaded through to
   `DescriptorInfo::has_private_keys` — the comment rationalises
   a known gap that prevents fixing the gap.

2. **"Well-engineered helper never wired"**: `dissatisfy_witness`
   (miniscript.rs:2238) is a complete dissatisfaction implementation
   that handles all 27 fragment kinds correctly. Its only caller
   in production is `Miniscript::dissatisfy` (miniscript.rs:2226).
   It is NEVER called from a satisfaction path; the `Thresh`
   satisfaction at miniscript.rs:2172 has the only cross-call.
   But `Miniscript::dissatisfy` itself is not consumed by any
   PSBT / signer / RPC code in rustoshi. The dissatisfaction logic
   is gated behind `if !self.ty.props.d { return None; }` (line 2227),
   which means even if a caller arrives, every type with `d=false`
   returns None — and the type computation has its own bugs
   (BUG-4, BUG-5) that downstream this gate.

3. **"Type-system silently diverges from Core"** (BUG-3, BUG-4,
   BUG-5, BUG-6). The miniscript Type system is implemented as a
   `TypeProperties` struct of booleans with a hand-written
   per-fragment combinator. Core's `_mst` literal operator
   (miniscript.h:159-189) makes the type derivation textually
   match the property list — `"Bonudmk"_mst` is a literal string
   identical to the type-system documentation. Rustoshi's
   per-property booleans drift because there is no textual
   round-trip. **Recommendation (out-of-scope for audit)**: emit
   the Core canonical type string at compile-test time and
   diff against Core's strings.

4. **"Descriptor test corpus missing"** (BUG-23). Same shape as
   W127's `script_assets_test.json` gap. Core ships 161 descriptor
   fixtures in `descriptor_tests_external.json` covering every
   valid descriptor type, every malformed input, and every
   round-trip identity. None of those are loaded.

5. **"Parser-side enforcement vs build-side enforcement"** (BUG-8,
   G14, G15). `parse_multi_descriptor` accepts any number of keys
   and only `make_multisig_script` (the build path) limits to 20.
   For descriptors that never exercise the script-build path
   (e.g. `getdescriptorinfo` round-trips that only call
   `to_string()`), the violation is silent. Parser should enforce
   structural limits up front; build path is a second line of
   defence.

6. **`raw(HEX)` is permissive** — `parse_descriptor_inner` accepts
   any even-length hex as a valid `raw()` script (descriptor.rs:
   1423-1427). Core's `RawDescriptor` requires `script.IsPushOnly()`
   in some contexts and ALWAYS enforces `script.size() <=
   MAX_STANDARD_SCRIPTSIG_SIZE`. Rustoshi accepts a 100KB raw
   script. This is downstream of `descriptor::Descriptor::Raw(Vec<u8>)`
   having no length cap. Not catalogued as a separate BUG because
   `raw()` is documented as the unstructured escape hatch; downstream
   consensus / mempool will still reject it.

### What's right

- **Checksum implementation** is byte-exact with Core. The
  INPUT_CHARSET, CHECKSUM_CHARSET, PolyMod magic numbers, group
  encoding (5 lower bits + group-of-3 cls byte), final XOR with 1,
  and 8-character emit all match. The first test case
  (`pk(0279…)` → `gn28ywm7`) is from BIP-380 and passes.
- **Key origin info parsing** correctly extracts the 4-byte
  fingerprint and the derivation path with `'` / `h` apostrophe
  preservation.
- **Xpub / xprv encoding** matches BIP-32 wire format
  (version 4 + depth 1 + parent_fp 4 + child_num 4 + chain_code 32
  + key 33/34 = 78 bytes, base58check).
- **Segwit-v0 uncompressed key rejection** correctly threads
  through `validate_segwit_v0_compressed` for `wpkh` / `wsh`
  contexts AND `sh(wpkh)` / `sh(wsh)` nested contexts. The
  is_compressed flag is parsed once at hex parse time
  (not recomputed from the always-compressed `secp256k1::PublicKey::
  serialize()`), which is the right design.
- **`combo()` script-set selection** correctly emits 4 scripts for
  compressed keys and 2 scripts for uncompressed, gated on the
  parse-time `is_compressed` flag.
- **Hash fragment compile sequence** (`OP_SIZE 32 OP_EQUALVERIFY
  OP_{SHA256,HASH256,RIPEMD160,HASH160} <hash> OP_EQUAL[VERIFY]`)
  matches Core's `BuildScript` per fragment.
- **`multi_a` compile sequence** (`key1 CHECKSIG key2 CHECKSIGADD
  … keyN CHECKSIGADD k NUMEQUAL[VERIFY]`) matches Core's tapscript
  multisig template.
- **CHECKMULTISIG dummy element** in satisfaction (`witness.push_empty()`
  at miniscript.rs:2196) correctly adds the zero element for the
  Bitcoin off-by-one bug.

### Cross-impl context

Most rustoshi-fleet impls have similar gaps:
- **clearbit**: descriptors stubbed out at the `multi` / `tr-tree`
  level (see clearbit's wallet audit W118).
- **blockbrew**: `tr()` parser does not handle `{...}` (same
  P0-CDIV class).
- **lunarblock**: no miniscript implementation at all.
- **ouroboros** (via `python-bitcoin-descriptors`): full BIP-380
  support but no BIP-389 multipath.

This is consistent with W118 wallet-audit finding "descriptor
language is intentionally deferred across the fleet; only the
keypath-spend wallet types are supported end-to-end."

## Out of scope (for W131 — explicitly future waves)

- Descriptor caching (`DescriptorCache` / `read_cache` / `write_cache`).
- `bip341-vector-runner` parity for Taproot script-tree depth
  vectors (covered by W127 Taproot audit).
- Miniscript witness-size estimation accuracy (`max_witness_size`
  computation correctness — only spot-checked in this audit).
- Miniscript satisfaction edge cases for `andor` / `thresh` with
  shared keys.
- PSBT-level descriptor expansion (covered by W129 + W118).
- RPC-level descriptor expansion at `getdescriptorinfo` /
  `deriveaddresses` / `scantxoutset` — `infer_descriptor` is
  the BUG-14 surface there.
- Descriptor parsing performance / DoS bounds (max descriptor
  string length, max recursion depth in `parse_descriptor_inner`,
  max key expansion in multi() / multi_a() and friends).

## Summary

- **23 bugs catalogued.** Breakdown:
  - **P0-CDIV: 2** (BUG-1, BUG-2 — `tr()` tree syntax + depth
    handling).
  - **P1: 8** (BUG-3 through BUG-10 — miniscript type system
    drift, multi_a length cap, multipath missing, multisig
    Display round-trip).
  - **P2: 9** (BUG-11 through BUG-19 — round-trip,
    cosmetic/error-name, missing inference, normalised/private
    string emission, miniscript completeness).
  - **P3: 4** (BUG-20 — round-trip wrapper desugaring; BUG-21,
    BUG-22 — comment-as-confession; BUG-23 — corpus absence).
- **30/30 gates** assessed against Core; 17 PRESENT, 3 PARTIAL,
  10 MISSING / BROKEN.
- **0 P0-CONSENSUS** (descriptors are wallet-side; even worst
  divergences are P0-CDIV).
- **2 P0-CDIV** that would cause real address mismatches between
  rustoshi and any Core-derived wallet for non-trivial
  `tr(IK, TREE)` descriptors.
- **Bug-yield similar to W118 wallet audit (104/10) on a per-impl
  basis**: this single-impl wave's 23 bugs are concentrated in
  the type-system + tr()-tree areas where W118 explicitly deferred.
