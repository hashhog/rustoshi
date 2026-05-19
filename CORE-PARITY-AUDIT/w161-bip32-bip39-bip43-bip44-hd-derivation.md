# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (rustoshi)

**Wave:** W161 — `ExtendedPrivKey::from_seed`, `ExtendedPrivKey::derive_child`,
`ExtendedPubKey::derive_child`, `parse_derivation_path`, BIP-39
`entropy_to_mnemonic` / `mnemonic_to_entropy` / `mnemonic_to_seed` (PBKDF2-HMAC-SHA512
2048 iters), BIP-39 English wordlist (2048 words), BIP-43 purpose +
BIP-44/49/84/86 path layouts (`m/44'`/`m/49'`/`m/84'`/`m/86'`), xprv/xpub
78-byte encoding + version bytes per network (mainnet `0488ADE4`/`0488B21E`,
testnet `04358394`/`043587CF`), BIP-32 master key generation
(`HMAC-SHA512("Bitcoin seed", seed)`), parent fingerprint (HASH160[0..4]),
descriptor key origin parsing (`[fingerprint/path]`), descriptor xpub/xprv
expansion + ranged derivation (`/*`, `/*'`, `/*h`), BIP-86 TapTweak with
empty merkle root, gap-limit + address-rescan, memory hygiene
(seed/secret-key zeroize on drop), HMAC-SHA512 source.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:293-310` — `CKey::Derive(keyChild, ccChild, nChild, cc)`:
  hardened uses `BIP32Hash(cc, nChild, 0, ser256(seckey), out)`; unhardened
  uses `BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, out)`;
  result is `secp256k1_ec_seckey_tweak_add(static_ctx, child_seckey, out)`.
  On failure (`IL >= n` OR `child_seckey == 0`), `ClearKeyData()` and
  return false. **Core does NOT retry next index — caller error.**
- `bitcoin-core/src/key.cpp:482-501` — `CExtKey::Derive`: bumps `nDepth`,
  sets `vchFingerprint = key.GetPubKey().GetID()[0..4]`, calls
  `key.Derive(...)`. `CExtKey::SetSeed(seed)` computes
  `HMAC-SHA512(hashkey = "Bitcoin seed", seed)`; sets `key = vout[0..32]`,
  `chaincode = vout[32..64]`, `depth=0`, `nChild=0`,
  `vchFingerprint = {0,0,0,0}`. **Core does NOT retry on master IL >= n.**
- `bitcoin-core/src/key.cpp:513-530` — `CExtKey::Encode/Decode`: 74-byte
  layout `[depth(1) || fp(4) || child(4 BE) || cc(32) || 0x00 || seckey(32)]`.
  **Decode sanity-clears `key` when** `(nDepth==0 && (nChild!=0 || fp!=0)) || code[41]!=0`.
  Decode is for the 74-byte payload; the 78-byte serialized form adds
  4 version bytes (in `EncodeWithVersion`/`DecodeWithVersion`).
- `bitcoin-core/src/pubkey.cpp:341-363` — `CPubKey::Derive`: hardened forbidden
  (`assert((nChild >> 31) == 0)`); unhardened uses
  `BIP32Hash(cc, nChild, *begin(), begin()+1, out)`, then
  `secp256k1_ec_pubkey_tweak_add(static_ctx, &pubkey, out)`. On
  parse/tweak failure → return false.
- `bitcoin-core/src/pubkey.cpp:415-422` — `CExtPubKey::Derive`: same
  envelope as `CExtKey::Derive` for fingerprint + depth bookkeeping.
- `bitcoin-core/src/pubkey.h:160-163` — `CPubKey::GetID() = CKeyID(Hash160(span{vch}.first(size())))`.
  `vchFingerprint` = first 4 bytes of HASH160 of parent's compressed pubkey.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:730-749` —
  `secp256k1_ec_seckey_tweak_add` returns 0 on invalid result; tweak must
  be valid (in `[0, n)` per `seckey_verify`) **or** 32 zeros.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:751-768` —
  `secp256k1_ec_pubkey_tweak_add` same envelope.
- `bitcoin-core/src/script/descriptor.cpp::ParseExtKey` (~`ParsePubkey`)
  parses `[fingerprint/path]xpub.../path/*` expressions, cross-checks
  `version` against `ChainParams` (rejects tpub on mainnet, xpub on testnet),
  threads `permit_uncompressed` through the parser for legacy sh-context
  reuse, and validates that the post-xpub path does not exceed 256 levels.
- `bitcoin-core/src/secp256k1/src/secp256k1.c::secp256k1_context_randomize`
  — Core randomizes the static context for side-channel defence on
  every `CKey::Sign`/`Derive` call indirectly via `secp256k1_context_static`
  initialization in `ECC_Start` (`init.cpp`).
- BIP-32 spec: `https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki`
  — "Master key generation" + "Child key derivation (CKD) functions" both
  mandate retry-on-IL≥n / retry-on-result==0 with next index `i+1`. Core
  deviates: returns error to caller; rustoshi matches Core.
- BIP-39 spec: `https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki`
  — Entropy 128/160/192/224/256 bits, checksum = N/32 bits, 11-bit words
  via English wordlist (2048 entries), seed = PBKDF2-HMAC-SHA512(NFKD(words),
  "mnemonic"||NFKD(passphrase), 2048, 64).
- BIP-43: `m/purpose'/...` reserves the top-level hardened purpose.
- BIP-44/49/84/86: `m/{44,49,84,86}'/coin'/account'/change/index` —
  coin=0' mainnet, coin=1' testnet/signet/regtest (per SLIP-0044).
- BIP-86 spec: P2TR key-path uses
  `taproot_tweak_pubkey(internal_key, "") = H(internal_key)` then
  `output_key = internal_key + H·G`.

**Files audited**
- `crates/wallet/src/hd.rs` (723 LOC) — `ExtendedPrivKey`,
  `ExtendedPubKey`, `from_seed`, `derive_child`, `derive_path`,
  `to_public`, `fingerprint`, `key_fingerprint`, `parse_derivation_path`,
  `WalletError`, `HARDENED_FLAG = 0x80000000`.
- `crates/wallet/src/bip39.rs` (479 LOC) — BIP-39 wordlist loader,
  `entropy_to_mnemonic`, `mnemonic_to_entropy`, `mnemonic_to_seed`,
  `validate_mnemonic`, `pbkdf2_hmac_sha512` (hand-rolled),
  `Bip39Error`.
- `crates/wallet/src/bip39_wordlist.txt` — 2048-entry English wordlist
  embedded via `include_str!`.
- `crates/wallet/src/wallet.rs:1-400, 1575-1620` — `Wallet::from_seed`,
  `Wallet::from_mnemonic`, `derivation_path`, `derive_address`,
  `get_new_address`, `get_change_address`, `peek_address`,
  `get_address_at`, `gap_limit`, `generate_lookahead_addresses`,
  BIP-44/49/84/86 purpose constants (`BIP{44,49,84,86}_PURPOSE`),
  coin-type constants (`COIN_MAINNET = 0x80000000`,
  `COIN_TESTNET = 0x80000001`), `compute_taproot_output_key` (P2TR via
  `rustoshi-crypto::taproot::compute_taproot_output_key`).
- `crates/wallet/src/descriptor.rs:1213-1355, 1546-1704` —
  `encode_xpub`/`encode_xprv`/`decode_xpub`/`decode_xprv`, version bytes
  (`XPUB_VERSION_MAINNET = 0x0488B21E`, `XPRV_VERSION_MAINNET = 0x0488ADE4`,
  `XPUB_VERSION_TESTNET = 0x043587CF`, `XPRV_VERSION_TESTNET = 0x04358394`),
  `KeyProvider::{Const, Xpub, Xprv, WithOrigin}`, `KeyOrigin`,
  `parse_key_expression`, `parse_xpub_key`, `parse_xprv_key`,
  `parse_origin`, `parse_key_with_origin`, `split_xpub_and_path`,
  `format_path`, `DeriveType::{NonRanged, UnhardenedRanged, HardenedRanged}`.
- `crates/wallet/src/manager.rs:33-410` — `SEED_LEN = 64`,
  `create_wallet`, `persist_seed`, `getrandom::getrandom`-sourced seed
  generation, `Wallet::from_seed` invocation, `WalletLockState`.
- `crates/rpc/src/wallet.rs` — RPC surface (no `sethdseed` /
  `getnewmnemonic`; only `importdescriptors` documented at line 682).
- `crates/wallet/Cargo.toml` — `secp256k1 = "0.28"` with
  `global-context` feature, `zeroize = "1.7"` (used only in
  `encryption.rs`, NOT in `hd.rs` or `bip39.rs`).
- `crates/wallet/tests/test_w111_wallet.rs` — G1/G2/G3 BIP-32 vectors,
  G8/G18 BIP-39 vectors.
- `crates/wallet/tests/test_w118_wallet.rs` — G7 BIP-32 test vectors 1+3,
  G8 BIP-39 word-count rejection, G10 tpub testnet, G11 WIF (`#[ignore]`).
- `bitcoin-core/src/key.cpp`, `bitcoin-core/src/pubkey.cpp`,
  `bitcoin-core/src/script/descriptor.cpp`,
  `bitcoin-core/src/kernel/chainparams.cpp:148/149, 261/262, 366/367, 507/508, 639/640`.

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | BIP-32 master key generation | G1: HMAC-SHA512(key="Bitcoin seed", msg=seed) | PASS (`hd.rs:156-159`) |
| 1 | … | G2: seed length validated 16–64 bytes | PASS (`hd.rs:152-154`) |
| 1 | … | G3: master depth=0, fingerprint=`{0,0,0,0}`, child_number=0 | PASS (`hd.rs:166-172`) |
| 1 | … | G4: Core-compatible NOT-retry on `IL >= n` | PASS — `Scalar::from_be_bytes` returns error mapped to `KeyDerivation` (`hd.rs:213`), same envelope as Core's `secp256k1_ec_seckey_tweak_add` returning 0 |
| 2 | BIP-32 CKD private | G5: hardened uses `0x00 || seckey || ser32(i)` | PASS (`hd.rs:194-202`) |
| 2 | … | G6: unhardened uses `ser_p(pub) || ser32(i)` | PASS (`hd.rs:199-201`) |
| 2 | … | G7: `parent_seckey + parse256(IL) mod n` via libsecp `add_tweak` (NOT pure-Rust BigInt) | PASS (`hd.rs:213-217`) — **cross-cite W160 G41: explicit contrast to haskoin W159 BUG-X "BIP-32 private-side GMP / public-side libsecp asymmetry"** |
| 2 | … | G8: chain code = HMAC output[32..64] | PASS (`hd.rs:219-220`) |
| 2 | … | G9: depth saturating-add (no wrap at 255) | PASS (`hd.rs:225`); Core asserts `nDepth != UINT8_MAX` (`key.cpp:483`); rustoshi clamps silently — informational divergence (BUG-14 below) |
| 3 | BIP-32 CKD public | G10: hardened rejected (`HardenedFromPublic`) | PASS (`hd.rs:271-274`) |
| 3 | … | G11: `parent_pub + IL·G` via libsecp `combine` of `PublicKey::from_secret_key(tweak)` | PASS (`hd.rs:289-298`) — **deviates from Core's direct `secp256k1_ec_pubkey_tweak_add` (`pubkey.cpp:355`); rustoshi does two ops where Core does one — BUG-1 below** |
| 3 | … | G12: chain code propagated | PASS (`hd.rs:300-301`) |
| 4 | parent fingerprint | G13: `HASH160(parent_compressed_pubkey)[0..4]` | PASS (`hd.rs:331-336`) |
| 4 | … | G14: master parent_fingerprint = `{0,0,0,0}` | PASS (`hd.rs:170`) |
| 5 | xprv/xpub encoding | G15: 78-byte layout `[4 ver || 1 depth || 4 fp || 4 child || 32 cc || 33 key]` | PASS (`descriptor.rs:1229-1256`) |
| 5 | … | G16: base58check encoding | PASS (`descriptor.rs:1237, 1256`) |
| 5 | … | G17: mainnet version bytes match Core | PASS — `XPUB_VERSION_MAINNET = 0x0488B21E`, `XPRV_VERSION_MAINNET = 0x0488ADE4` (`descriptor.rs:1217-1218`) |
| 5 | … | G18: testnet version bytes match Core | PASS — `XPUB_VERSION_TESTNET = 0x043587CF`, `XPRV_VERSION_TESTNET = 0x04358394` (`descriptor.rs:1219-1220`) |
| 5 | … | G19: cross-network mixing rejected (mainnet wallet refuses tpub) | **BUG-2 (P0-CDIV)** — `parse_xpub_key`/`parse_xprv_key` discard `network` (`descriptor.rs:1638, 1660`); wallet can construct mainnet descriptors from testnet xprv/xpub (and vice versa) |
| 5 | … | G20: Core's `CExtKey::Decode` sanity-clear when `depth==0 && (nChild!=0 \|\| fp!=0)` | **BUG-3 (P1)** — `decode_xprv`/`decode_xpub` accept malformed depth-0 keys with nonzero fingerprint/child (`descriptor.rs:1283-1301, 1328-1354`); Core invalidates per `pubkey.cpp:400`, `key.cpp:529` |
| 6 | BIP-39 mnemonic ↔ entropy | G21: entropy lengths 16/20/24/28/32 enforced | PASS (`bip39.rs:96-98`) |
| 6 | … | G22: word counts 12/15/18/21/24 enforced | PASS (`bip39.rs:142-144`) |
| 6 | … | G23: checksum bits = entropy_bits / 32 | PASS (`bip39.rs:100, 146-147`) |
| 6 | … | G24: English wordlist exactly 2048 entries, indexed 0..2047 | PASS (`bip39.rs:50-62`) |
| 6 | … | G25: case-sensitive wordlist lookup | PASS (`bip39.rs:153-156`) |
| 6 | … | G26: PBKDF2-HMAC-SHA512 iter=2048, salt="mnemonic"+passphrase | PASS (`bip39.rs:202-206`) |
| 6 | … | G27: NFKD normalization on mnemonic + passphrase | PASS (`bip39.rs:199-200`) |
| 7 | BIP-43/44/49/84/86 path layout | G28: purpose constants hardened (44'/49'/84'/86') | PASS (`wallet.rs:28-37`) |
| 7 | … | G29: coin=0' mainnet, 1' testnet (covers signet/regtest via Network::Testnet) | PASS (`wallet.rs:40-43, 294-297`) |
| 7 | … | G30: BIP-86 P2TR tweak with empty merkle root | PASS (`wallet.rs:331-339, 355-360`) — delegated to `rustoshi-crypto::taproot::compute_taproot_output_key` |

---

## Severity bands

- **P0-CONS** (consensus chain-split): 0 (BIP-32 is wallet-only, no
  consensus surface; CKD bugs cause unrecoverable funds, never chain-split)
- **P0-CDIV** (cross-network / cross-impl divergence breaking interop):
  BUG-2, BUG-4, BUG-5, BUG-9, BUG-12
- **P0-SEC** (security / fund-loss / privacy): BUG-6, BUG-7, BUG-13
- **P1**: BUG-1, BUG-3, BUG-8, BUG-10, BUG-11, BUG-14, BUG-15, BUG-16
- **P2 / informational**: BUG-17, BUG-18, BUG-19

---

## BUG-1 (P1) — `ExtendedPubKey::derive_child` does two libsecp ops where Core does one (`pubkey_tweak_add`)

**Severity:** P1 perf + audit-quality. Two-call form silently masks the
canonical Core code path and adds an unnecessary `PublicKey::from_secret_key`
in the hot derivation loop.

`crates/wallet/src/hd.rs:289-298`:

```rust
// child_pub = parent_pub + tweak * G
let secp = Secp256k1::new();
let tweak =
    SecretKey::from_slice(&tweak_bytes).map_err(|_| WalletError::KeyDerivation)?;
let tweak_pub = PublicKey::from_secret_key(&secp, &tweak);
let child_pub = self
    .public_key
    .combine(&tweak_pub)
    .map_err(|_| WalletError::KeyDerivation)?;
```

Core (`bitcoin-core/src/pubkey.cpp:351-357`):

```cpp
secp256k1_pubkey pubkey;
if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, vch, size())) return false;
if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &pubkey, out)) return false;
```

Core's `secp256k1_ec_pubkey_tweak_add` directly mutates the parent
public key in-place. Rustoshi performs:
1. `SecretKey::from_slice(tweak_bytes)` — validates `tweak < n` and `!= 0`.
2. `PublicKey::from_secret_key(secp, tweak)` — one scalar multiplication
   `tweak · G`.
3. `pub.combine(tweak_pub)` — group-element addition.

The combined effect is mathematically equivalent (`pub + tweak·G`), BUT
the Rust path rejects `tweak == 0` at step 1 (`SecretKey::from_slice`
errors on zero), whereas Core's `pubkey_tweak_add` accepts the 32-zero
tweak as documented behaviour ("must be valid according to
`secp256k1_ec_seckey_verify` or 32 zero bytes"). With a 32-zero tweak,
Core returns the unchanged parent pubkey (additive identity);
rustoshi short-circuits with `KeyDerivation` error.

The probability of `parse256(IL) == 0` is `2^-256` so this is not a
real correctness gap on the public side. The real issue is that the
two-op form is slower in a tight derivation loop (`Secp256k1::new()`
creates a fresh context per call — see BUG-12) and the divergence from
Core's API choice makes test-vector debugging harder.

**File:** `crates/wallet/src/hd.rs:289-298`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:341-363`.

**Why this matters:** the canonical `pubkey_tweak_add` is exposed in
`secp256k1` 0.28 via the unsafe `secp256k1_sys` layer; the safe API does
not currently wrap it, hence the two-op workaround. Document the
intentional deviation in code (currently absent) and consider migrating
to the bindings-direct call. Cross-cite the "two-op divergence from
Core's single-op" pattern.

---

## BUG-2 (P0-CDIV) — `decode_xpub`/`decode_xprv` discards network; cross-network mixing silently accepted

**Severity:** P0-CDIV. Bitcoin Core's
`bitcoin-core/src/script/descriptor.cpp::ParseExtKey` cross-checks the
parsed version bytes against `Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY)`
and rejects mainnet xpub on a testnet wallet (and vice versa). Rustoshi's
`parse_xpub_key`/`parse_xprv_key` discard the parsed network entirely:

`crates/wallet/src/descriptor.rs:1638` (`parse_xpub_key`):
```rust
let (xpub, _network) = decode_xpub(xpub_str)?;
```

`crates/wallet/src/descriptor.rs:1660` (`parse_xprv_key`):
```rust
let (xprv, _network) = decode_xprv(xprv_str)?;
```

This means a user can construct e.g. a mainnet `wpkh(tpub.../0/0)` descriptor
and rustoshi will silently derive **mainnet** P2WPKH addresses from a
**testnet**-prefixed xpub. The keys are mathematically valid on both
networks, but addresses generated this way:

1. Cannot be funded from a Core mainnet wallet that refuses the descriptor.
2. Make wallet backups ambiguous — the descriptor string preserves the
   tpub prefix but the wallet uses it as if it were an xpub.
3. Break interop with Sparrow / Electrum / Specter, which all enforce
   the descriptor-vs-chainparams version check.

**File:** `crates/wallet/src/descriptor.rs:1638, 1660` (call sites) +
`crates/wallet/src/descriptor.rs:1546-1580` (`parse_key_expression`,
where the active wallet network is also not passed in to the parser).

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParseExtKey`
threads `ParseScriptContext` + `out.parser_error` and validates against
`Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY)`.

**Excerpt (rustoshi, missing network check)**
```rust
fn parse_xpub_key(expr: &str) -> Result<KeyProvider, DescriptorError> {
    let (xpub_str, path_str, derive_type, apostrophe) = split_xpub_and_path(expr)?;
    let (xpub, _network) = decode_xpub(xpub_str)?;  // <-- network silently discarded
    // ...
}
```

**Why this matters:** silent cross-network address derivation has been
the source of multiple production incidents (testnet keys re-used on
mainnet → funds sent to addresses the user cannot recover from a
testnet-only signer). This is **NEW PATTERN "network-strip on key
parse"** — the parser knows the network but the caller chain never
consults it.

---

## BUG-3 (P1) — `decode_xprv`/`decode_xpub` does NOT sanity-clear malformed depth-0 keys (Core's `CExtKey::Decode` invariant)

**Severity:** P1 correctness. Bitcoin Core's `CExtKey::Decode`
(`key.cpp:523-530`) and `CExtPubKey::Decode` (`pubkey.cpp:394-401`) both
enforce the BIP-32 invariant **"a master key (depth==0) MUST have
nChild=0 and fingerprint=0"**:

```cpp
if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) ||
    code[41] != 0) key = CKey();  // invalidate
```

Rustoshi's `decode_xprv` (`descriptor.rs:1328-1354`) and `decode_xpub`
(`descriptor.rs:1283-1301`) read these fields but never validate them.
A hand-crafted xprv with `depth=0` and `child_number=0xDEADBEEF` or
`parent_fingerprint=[1,2,3,4]` parses cleanly and produces an
`ExtendedPrivKey` that subsequent derivation will then attach as a
"master" with nonzero metadata — silently breaking any consumer that
chases the fingerprint chain to reconstruct origin.

**File:** `crates/wallet/src/descriptor.rs:1283-1301` (xpub),
`crates/wallet/src/descriptor.rs:1328-1354` (xprv). No
`if depth == 0 && (child_number != 0 || parent_fingerprint != [0;4])`
check.

**Core ref:** `bitcoin-core/src/key.cpp:529` and
`bitcoin-core/src/pubkey.cpp:400`.

**Why this matters:** BIP-32 §"Serialization format" mandates this
invariant. Skipping it lets a malicious or buggy producer of xprvs
embed metadata that confuses downstream key-origin tracking. Core has
enforced this since the original CExtKey introduction. **NEW PATTERN
"BIP-32 sanity invariant skipped on decode"**.

---

## BUG-4 (P0-CDIV) — `manager::create_wallet` generates 64 random bytes as seed; CANNOT export a recoverable BIP-39 mnemonic

**Severity:** P0-CDIV / fund-recovery. `crates/wallet/src/manager.rs:386-389`:

```rust
let mut seed = [0u8; SEED_LEN];  // SEED_LEN = 64
getrandom::getrandom(&mut seed)
    .map_err(|e| WalletError::Crypto(format!("failed to generate random seed: {}", e)))?;
persist_seed(&wallet_dir, &seed, passphrase)?;
let wallet = Wallet::from_seed(&seed, self.network, AddressType::P2WPKH)?;
```

The 64 random bytes are fed directly into BIP-32 master derivation
(`ExtendedPrivKey::from_seed` at `hd.rs:151`). This is what the BIP-39
PBKDF2 output would have been **if it had come from a mnemonic** — but
because rustoshi skips the mnemonic step and uses raw `getrandom`
output, **there is no recoverable mnemonic for the wallet**.

Concrete failure modes:
- User creates rustoshi wallet → no `getnewmnemonic` RPC exposes the
  underlying entropy → user CANNOT write down 12/24 words for paper
  backup.
- User can only recover the wallet by restoring the on-disk
  `seed.bin` blob (which is what `persist_seed` writes). Lose the
  file → lose the funds. **Catastrophic UX regression vs. Core's
  `sethdseed` + `dumpwallet` workflow** and vs. every other Bitcoin
  wallet on the market.

Compare BIP-39 flow:
1. Generate 128/160/192/224/256 bits of entropy (`getrandom`).
2. Convert to mnemonic (`entropy_to_mnemonic`).
3. Convert mnemonic → 64-byte seed (`mnemonic_to_seed`, PBKDF2 2048 iter).
4. Feed seed into BIP-32 (`ExtendedPrivKey::from_seed`).

Rustoshi skips steps 1–3 and goes straight to step 4 with raw bytes.

**File:** `crates/wallet/src/manager.rs:386-389`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::GenerateNewSeed`
(Core's descriptors-only wallet uses a 32-byte seed but exposes it
via `dumpwallet` / `getwalletinfo`).

**Why this matters:** "I wrote down 12 words" is the universal Bitcoin
recovery story. A wallet that cannot produce those 12 words is
not a Bitcoin wallet — it is a one-shot key holder. Even users who
never trigger recovery rely on the *option* to do so. **NEW PATTERN
"raw-getrandom-bypasses-BIP-39"**.

---

## BUG-5 (P0-CDIV) — No `sethdseed` / `getnewmnemonic` RPC; wallet has no programmatic seed-import path

**Severity:** P0-CDIV. Bitcoin Core exposes `sethdseed [newkeypool] [seed]`
to (re-)initialise the wallet's HD seed from an explicit WIF private
key, and `dumpwallet <filename>` to export it. Rustoshi's RPC has
**neither** — `grep -n "sethdseed\|getnewseed\|generatemnemonic" crates/rpc/src/wallet.rs`
returns 0 hits.

`importdescriptors` (`crates/rpc/src/wallet.rs:682, 1540`) lets a user
import a descriptor with an xprv/xpub key inside, but:
- The descriptor must already be in canonical form (no "give me 12
  words" entry point).
- Importing a descriptor with an xprv does NOT replace the wallet's
  master seed — it adds a watched/imported key alongside the
  manager-created random seed.
- There is no way to enumerate the random seed AS a mnemonic for
  backup.

**File:** `crates/rpc/src/wallet.rs` (entire file; no `sethdseed`
method). `crates/wallet/src/manager.rs::create_wallet` accepts only
`CreateWalletOptions` (passphrase, blank, disable_private_keys) — no
`seed` or `mnemonic` field.

**Core ref:** `bitcoin-core/src/wallet/rpc/wallet.cpp::sethdseed`,
`dumpwallet`, `bitcoin-core/src/wallet/rpc/util.cpp::DecodeSecret`.

**Why this matters:** combined with BUG-4, this means a rustoshi wallet
created via `createwallet` RPC is irrecoverable except via direct
file-system access to `seed.bin`. There is no on-the-wire path to
extract the seed for backup or to inject a known seed for restore.
**Cross-cite "feature-half-finished" fleet pattern from hotbuns W160 (parser-vs-signer)** — here it is wallet-create-vs-wallet-import: random seed creation
present, mnemonic-based creation absent.

---

## BUG-6 (P0-SEC) — `ExtendedPrivKey`, `mnemonic_to_seed` output, and `pbkdf2_hmac_sha512` intermediate buffers never zeroize on drop

**Severity:** P0-SEC memory hygiene. Bitcoin Core uses
`std::vector<unsigned char, secure_allocator<unsigned char>>` for ALL
intermediate buffers in `CKey::Derive` (`key.cpp:296`) and
`CExtKey::SetSeed` (`key.cpp:494`) — guarantees that the seed, the
HMAC output, and the secret key bytes are wiped on stack-frame exit.

Rustoshi:
- `ExtendedPrivKey` (`hd.rs:25-36`) holds `secret_key: SecretKey` +
  `chain_code: [u8; 32]`. Neither field implements `Zeroize` nor
  `Drop`. On scope exit, the bytes linger in the freed heap/stack
  region until overwritten.
- `bip39::mnemonic_to_seed` (`bip39.rs:196-208`) returns `[u8; 64]`
  by value — the caller's binding is also non-zeroizing. The
  internal `salt: String`, `password_nfkd: String`, `passphrase_nfkd: String`
  all leak via standard `String::drop` (no zeroing).
- `pbkdf2_hmac_sha512` (`bip39.rs:218-237`) holds
  `salt_block: Vec<u8>`, `u: [u8; 64]`, `t: [u8; 64]` — none
  zeroized.
- `ExtendedPrivKey::Clone` (`hd.rs:24`) implies cheap copy semantics —
  every `derive_path` step `key = key.derive_child(child)?` (`hd.rs:240-241`)
  drops the previous `ExtendedPrivKey` without zeroing.

The `zeroize = "1.7"` dep is in `Cargo.toml:24` but **used only in
`encryption.rs`** (`grep -n "zeroize" crates/wallet/src/*.rs` → 9 hits,
all in encryption.rs). The seed/mnemonic/secret stack of `hd.rs` +
`bip39.rs` is unwiped.

**File:** `crates/wallet/src/hd.rs:25-36, 188-229, 247-256`;
`crates/wallet/src/bip39.rs:196-237`.

**Core ref:** `bitcoin-core/src/key.cpp:296, 494, 580`; Core's
`support/allocators/secure.h::secure_allocator`.

**Why this matters:** an attacker with read access to swap, core dumps,
or post-crash heap snapshots can recover the master seed. Production
wallets MUST zero secret material on drop. This is a known fleet-wide
weak spot — cross-cite the universal pattern of "zeroize-dep-imported-but-only-used-in-encryption.rs". **NEW PATTERN
"zeroize-dep-present-but-uncovered-modules"** — auditor sees `zeroize
= "1.7"` in `Cargo.toml` and assumes coverage; actual usage is
encryption-only.

---

## BUG-7 (P0-SEC) — `Secp256k1::new()` created per derivation call; missing context randomization (cross-cite W159 UNIVERSAL 10/10)

**Severity:** P0-SEC + perf. `hd.rs` invokes `Secp256k1::new()` in
**FOUR distinct hot-path call sites**:
- `derive_child` (`hd.rs:189`)
- `to_public` (`hd.rs:248`)
- `fingerprint` (`hd.rs:260`)
- `ExtendedPubKey::derive_child` (`hd.rs:291`)

Each call:
1. Allocates a fresh secp256k1 context (verify + sign capabilities
   + scratch).
2. Skips `secp256k1_context_randomize` (side-channel blinding) —
   **same defect W159 catalogued UNIVERSAL 10/10 fleet-wide**.
3. Adds significant allocation overhead in a derivation loop:
   `derive_path([84',0',0',0,0])` (BIP-84 first address) calls
   `derive_child` 5 times → 5 fresh context allocations + 5 keypair
   re-blindings skipped.

The `secp256k1 = "0.28"` dep enables `global-context` feature
(`Cargo.toml:33`), which exposes `secp256k1::SECP256K1` — a static
context initialised once at program start. **None of the hot-path
hd.rs sites use it.**

Core's reference (`bitcoin-core/src/init.cpp::ECC_Start` +
`init.cpp::ECC_Context`) calls `secp256k1_context_randomize` ONCE on
the static context at startup; thereafter every `key.cpp` /
`pubkey.cpp` op uses the static context.

**File:** `crates/wallet/src/hd.rs:189, 248, 260, 291`.

**Core ref:** `bitcoin-core/src/init.cpp::ECC_Start`,
`bitcoin-core/src/secp256k1/include/secp256k1.h::secp256k1_context_randomize`.

**Why this matters:** every derivation step is a fresh non-randomized
context → side-channel blinding never engaged for HD derivation. Cross-cite
the **W159 fleet-wide "context_randomize UNIVERSAL 10/10"** finding —
rustoshi already PASSES W159 G1 for the SIGNING context (per W159 audit)
but FAILS for the HD-DERIVATION context, because the latter creates fresh
non-randomized contexts ad-hoc. This is **NEW PATTERN "side-channel
defence absent on derivation hot path even though present on signing
hot path"**.

---

## BUG-8 (P1) — `pbkdf2_hmac_sha512` is hand-rolled; deviates from RFC 2898 §5.2 in dklen handling

**Severity:** P1 correctness boundary. `bip39.rs:218-237`:

```rust
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    debug_assert!(out.len() <= 64, "this implementation only supports dklen <= 64");
    debug_assert!(iterations >= 1, "PBKDF2 requires at least 1 iteration");

    // T_1 = F(P, S, c, 1) where F is U_1 ^ U_2 ^ ... ^ U_c
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&1u32.to_be_bytes());
    // ... single PRF block only
}
```

Issues:

1. **`debug_assert!` is stripped in release builds.** A caller passing
   `out.len() > 64` in a release build silently truncates output —
   no panic, no error. Production-built code that ever calls with
   `dklen=65` (e.g. for an Argon2 wrapper) reads 1 byte of
   uninitialized memory. Use `assert!` or return `Result`.
2. **Single PRF block only** — RFC 2898 §5.2 requires concatenating
   T_1, T_2, …, T_l blocks for dklen > hLen. The code is correct for
   the only existing caller (`mnemonic_to_seed` with dklen=64
   exactly), but the **module-public-but-private** function (it is
   `fn`, not `pub fn`, so not exported) could be misused in a
   future caller without surfacing the limitation as a type-level
   constraint.
3. **`iterations` ≥ 1 check is debug-only.** A buggy caller passing
   `iterations = 0` in release reads from `u` BEFORE any HMAC call,
   leaking the initial value (which is the first HMAC iteration —
   so functionally a 1-iteration PBKDF2). Not exploitable today
   because only `mnemonic_to_seed` calls it (hard-coded
   `iterations = 2048`), but the contract is weaker than it looks.

**File:** `crates/wallet/src/bip39.rs:218-237`.

**Core ref:** Core does not implement BIP-39 (notes in `bip39.rs:30-36`).
RFC 2898 §5.2 — `https://datatracker.ietf.org/doc/html/rfc2898#section-5.2`.

**Why this matters:** wallet codebases evolve. A new caller —
SLIP-0010, Argon2, BIP-85 child-mnemonic derivation — could pluck
this `pbkdf2_hmac_sha512` and hit the silent-truncate fence.
Tighten to `assert!` + explicit `Result` boundary. **NEW PATTERN
"debug_assert as production-contract"** in primitives.

---

## BUG-9 (P0-CDIV) — `parse_origin` allows arbitrarily deep paths inside `[fingerprint/...]`; Core caps at 256 levels

**Severity:** P0-CDIV. Bitcoin Core's
`bitcoin-core/src/script/descriptor.cpp::ParseKeyOrigin` enforces:
- 8-hex fingerprint (rustoshi: PASS — `descriptor.rs:1609-1614`).
- Path depth ≤ 256 (matches `BIP32_EXTKEY_SIZE`-derived budget).

Rustoshi's `parse_origin` (`descriptor.rs:1605-1631`) imposes NO depth
cap. `[d34db33f/a/b/c/d/.../zzz]` with 100,000 path segments allocates
400 KiB of `Vec<u32>` and then proceeds to descriptor expansion.
Combined with `parse_descriptor` accepting arbitrary nesting, this is
a soft DoS via descriptor RPC.

The bigger interop issue: a descriptor accepted by rustoshi with depth
1000 will fail on Core (rejected by length cap) → re-import from a
backup made on rustoshi to Core silently fails. Round-trip broken.

**File:** `crates/wallet/src/descriptor.rs:1605-1631` (`parse_origin`),
`crates/wallet/src/hd.rs:351-402` (`parse_derivation_path` — also
uncapped).

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParseKeyOrigin`
+ comment in `bitcoin-core/src/script/descriptor.cpp` about Core's
parsed-tree max depth.

**Why this matters:** descriptor wallets exchange descriptors between
implementations (this is the WHOLE POINT of BIP-380). A rustoshi-emitted
descriptor that Core refuses breaks the round-trip contract.
**NEW PATTERN "no depth cap on parsed paths"**.

---

## BUG-10 (P1) — `parse_key_expression` documents WIF support, but no WIF parser exists; descriptor with WIF silently rejected as "unrecognized key format"

**Severity:** P1 / docs-vs-impl. `crates/wallet/src/descriptor.rs:25-26`:

```text
//! - Hex-encoded public keys (33 or 65 bytes)
//! - WIF-encoded private keys
```

`KeyProvider::Const` (`descriptor.rs:313-327`) documents:
```text
/// A constant public key (hex or WIF).
```

`key_provider_has_private` (`descriptor.rs:907-918`) ALSO documents
WIF:
```text
/// Const is always a public key after parsing; WIF is converted to pubkey
/// on parse so we can never recover "was this originally WIF?" without
/// extra tracking.
```

But `parse_key_expression` (`descriptor.rs:1546-1580`) has NO WIF
branch — it only handles `xpub`/`tpub`/`xprv`/`tprv` prefixes, hex
pubkeys, and x-only pubkeys. A descriptor like
`pkh(L5oLkpV3aqBjhki6LmvChTCq73v9gyymzzMpBbhDLjDp1ErCw9va)` returns
`DescriptorError::InvalidKey("unrecognized key format: ...")`.

This is **already tracked as W118 BUG-10** (`#[ignore = "BUG-10: WIF
encoding/decoding MISSING ENTIRELY..."]` at
`tests/test_w118_wallet.rs:857-858`) but **regressed against** the
documentation that claims WIF support — a `WIF` descriptor backup from
Sparrow / Electrum / Core fails round-trip on rustoshi.

**File:** `crates/wallet/src/descriptor.rs:1546-1580` (parser),
`crates/wallet/src/descriptor.rs:25-26` (docs claim).

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParsePubkey` +
`bitcoin-core/src/key_io.cpp::DecodeSecret`.

**Why this matters:** unrecognized-key error message is misleading
("unrecognized key format" implies user typo, not "feature missing").
**Cross-cite "feature-half-finished parser-vs-signer" hotbuns W160
fleet pattern** — here it is parser-vs-doc-claim, which is the same
shape one layer up.

---

## BUG-11 (P1) — `generate_lookahead_addresses` always starts from index 0 (not last-used + gap); Core gap-limit semantics broken

**Severity:** P1 functional. Per BIP-44 §"Address gap limit":

> Address gap limit is currently set to 20. If the software hits 20
> unused addresses in a row, it expects there are no used addresses
> beyond this point and stops searching the address chain.

The semantics are **last-used + gap_limit**, NOT **first-gap_limit-addresses**.

`crates/wallet/src/wallet.rs:1603-1619`:

```rust
pub fn generate_lookahead_addresses(&mut self) -> Result<Vec<String>, WalletError> {
    let mut addresses = Vec::new();
    for i in 0..self.gap_limit {                  // <-- always 0..20
        let addr = self.get_address_at(false, i)?;
        addresses.push(addr);
    }
    for i in 0..self.gap_limit {                  // <-- always 0..20
        let addr = self.get_address_at(true, i)?;
        addresses.push(addr);
    }
    Ok(addresses)
}
```

Concrete failure: user has receive_index=50 (used 50 addresses), then
restores from seed → `generate_lookahead_addresses` returns addresses
0..19 only. Addresses 20..49 are NEVER scanned. A rescan that uses
this set as the scan input will MISS funds received on indices 20..49.

Compare Core (`bitcoin-core/src/wallet/scriptpubkeyman.cpp::TopUp`):
generates `m_keypool_size` (default 1000) keys past the highest seen
descriptor index.

**File:** `crates/wallet/src/wallet.rs:1603-1619`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::TopUp`,
`bitcoin-core/src/wallet/scriptpubkeyman.cpp::TopUpChain`.

**Why this matters:** rescan-after-restore is the primary funds-recovery
operation. A wallet that scans only the first 20 addresses cannot
recover funds received at higher indices. The bug is masked when
`next_receive_index < gap_limit` (the easy case), so tests pass and
the regression surfaces only in production restore scenarios.
**NEW PATTERN "gap-limit-starts-from-zero-not-last-used"** —
fleet-wide candidate to check.

---

## BUG-12 (P0-CDIV) — `derive_path` retries on `IL >= n` are absent (BIP-32 spec mandates "proceed to next i"); Core also absent but undocumented in rustoshi

**Severity:** P0-CDIV (documentation gap) + spec-deviation that
mirrors Core but is not flagged. Per BIP-32 §"Child key derivation
(CKD) functions" + §"Master key generation":

> In case parse_256(I_L) ≥ n or k_i = 0, the resulting key is invalid,
> and one should proceed with the next value for i. (Note: this has
> probability lower than 1 in 2^127.)

Core's `CExtKey::Derive` (`key.cpp:482-489`) and `CExtKey::SetSeed`
(`key.cpp:491-501`) BOTH return false / store invalid key — they do NOT
retry. This is a known Core deviation from BIP-32; the rationale is
that the probability is so low that real users will never hit it, and
silent retry would conceal a buggy HMAC.

Rustoshi's `derive_child` (`hd.rs:213-217`) and `from_seed`
(`hd.rs:161-162`) BOTH return `Err(WalletError::KeyDerivation)` on
`IL >= n`. **Same behaviour as Core**.

The bug is **the silence about this deviation**:
- `hd.rs:151` doc says "Returns an error if the seed is not 16-64
  bytes, or if the derived key is invalid" — does NOT say "we
  deliberately do not retry per BIP-32, matching Core's
  `CExtKey::SetSeed` behaviour".
- `hd.rs:188` derive_child doc says "Returns an error if the derivation
  produces an invalid key (astronomically unlikely)" — does NOT say
  "BIP-32 spec mandates retrying with `i+1`; we deliberately match
  Core's no-retry behaviour".

An auditor reading rustoshi top-down without checking Core would
flag the missing retry as a bug.

**File:** `crates/wallet/src/hd.rs:151-173, 188-229`.

**Core ref:** `bitcoin-core/src/key.cpp:307-309`, `key.cpp:491-501`.

**Why this matters:** **NEW PATTERN "deliberate-Core-deviation
not flagged in code comment"** — distinct from
"comment-as-confession" (fleet pattern, e.g. clearbit) in that here
there is NO comment at all. Future auditors / refactors will not know
whether the absence of retry is intentional or an oversight.

---

## BUG-13 (P0-SEC) — `Wallet::from_seed` accepts any seed length 16-64; BIP-39 seeds are ALWAYS exactly 64 bytes

**Severity:** P0-SEC. `hd.rs:151-173`:

```rust
pub fn from_seed(seed: &[u8]) -> Result<Self, WalletError> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(WalletError::InvalidSeedLength(seed.len()));
    }
    // ...
}
```

The 16-byte LOWER bound is suspicious:
- BIP-39 entropy MIN is 128 bits = 16 bytes — but the BIP-32 seed
  comes from PBKDF2(mnemonic) which is always exactly 64 bytes.
- A 16-byte BIP-32 master seed is allowed by BIP-32 ("Generate a
  seed byte sequence S of a chosen length (between 128 and 512
  bits)") but provides only 128 bits of security.
- Allowing any length in 16–64 bytes makes it possible to feed
  BIP-39 *entropy* (e.g. 16 bytes) directly as seed and produce a
  totally different (and much weaker) master key than the
  PBKDF2-derived 64-byte seed for the SAME mnemonic.

This is exactly the confusion that `manager.rs::create_wallet`
exhibits (BUG-4): it generates 64 bytes of raw entropy and feeds
them as "seed", bypassing BIP-39 entirely. A caller that mistakes
"seed" for "entropy" loses a factor of ~2048 in keyspace search
when restoring.

The lower bound SHOULD be either:
- 64 (BIP-39 only — strictest, matches `mnemonic_to_seed` output);
- 32 (minimum 256-bit security level);
- with strict documentation that any input is treated as raw BIP-32
  seed material, NOT BIP-39 entropy.

**File:** `crates/wallet/src/hd.rs:151-154`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::GenerateNewSeed`
uses a fixed 256-bit seed (32 bytes).

**Why this matters:** weak seeds = weak wallets. The current lax check
is silently the API that `create_wallet` abuses. **NEW PATTERN
"seed-length-permissiveness invites mnemonic/entropy confusion"**.

---

## BUG-14 (P1) — `derive_child` uses `saturating_add` on depth; Core asserts `nDepth != UINT8_MAX`

**Severity:** P1. Core (`key.cpp:483`):

```cpp
if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
out.nDepth = nDepth + 1;
```

Rustoshi (`hd.rs:225`):

```rust
depth: self.depth.saturating_add(1),
```

At `depth = 255`, Core returns error (`Derive` returns false). Rustoshi
silently produces another `ExtendedPrivKey` with `depth = 255` (stuck).
Repeated calls keep producing keys with `depth=255` indefinitely. The
fingerprint chain still advances (`parent_fingerprint` updates each
time), but the depth field is stuck. Round-trip encode/decode
re-imports a key with `depth=255` but with parents at "phantom" levels.

**File:** `crates/wallet/src/hd.rs:225` (priv), `crates/wallet/src/hd.rs:306` (pub).

**Core ref:** `bitcoin-core/src/key.cpp:483`,
`bitcoin-core/src/pubkey.cpp:416`.

**Why this matters:** BIP-32 has a hard depth cap at 255 (single
`uint8_t`). Rustoshi's silent saturation diverges from Core's hard
error → cross-impl divergence on extremely-deep paths. Production
descriptors never exceed depth 6-10, so this is real-world unreachable,
but the API contract differs. **NEW PATTERN
"saturating_add as silent divergence from Core's assert"**.

---

## BUG-15 (P1) — No defensive xprv version-byte check on inner-key path after origin parse; mixed-network descriptor passes

**Severity:** P1 cross-cite of BUG-2. `parse_key_with_origin`
(`descriptor.rs:1583-1602`) parses `[fingerprint/path]inner_key` and
recursively calls `parse_key_expression(key_str)`. The inner key
could be xpub (mainnet) while the descriptor is intended for testnet —
nothing in the chain checks compatibility.

Combined with BUG-2 (network stripped at decode time), this means a
descriptor like `wpkh([d34db33f/84'/0'/0']xpub.../0/*)` parses on a
testnet rustoshi wallet without any warning. Address derivation will
produce testnet bech32 (`tb1q...`) addresses from a mainnet xpub —
which is mathematically OK (same secp256k1 curve) but semantically
broken (the user's mainnet hardware wallet won't recognize the testnet
address derivation path as "owned").

**File:** `crates/wallet/src/descriptor.rs:1583-1602` (origin parse),
`crates/wallet/src/descriptor.rs:1638` (network-strip).

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParseExtKey`.

**Why this matters:** companion bug to BUG-2; even when origin info
is present (which IS the canonical descriptor form for hardware
wallets) the cross-network check still does not run. **CROSS-CITE
"network-strip on key parse"** — same pattern, two call sites.

---

## BUG-16 (P1) — `derive_path` clones `ExtendedPrivKey` per step; secret material proliferates without zeroize

**Severity:** P1 memory hygiene compounded with BUG-6. `hd.rs:238-244`:

```rust
pub fn derive_path(&self, path: &[u32]) -> Result<Self, WalletError> {
    let mut key = self.clone();          // copy #1
    for &child in path {
        key = key.derive_child(child)?;  // copy #2..N, each drops the previous WITHOUT zeroize
    }
    Ok(key)
}
```

For a BIP-84 path `[84',0',0',0,0]`, this produces 6 distinct
`ExtendedPrivKey` instances in sequence. With `Clone` derived without
`Drop` zeroize (see BUG-6), each intermediate secret_key + chain_code
lingers in freed memory until overwritten.

**File:** `crates/wallet/src/hd.rs:238-244`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::Derive` uses
`secure_allocator` for stack-frame vout; intermediate keys live in
secure memory.

**Why this matters:** compounds BUG-6. Every BIP-44/49/84/86 address
derivation produces 5-6 sequential secret-bearing structs that all
leak. **CROSS-CITE BUG-6** — same root cause, larger blast radius
on deep paths.

---

## BUG-17 (P2 / informational) — No support for SLIP-0132 ypub/zpub/upub/vpub/Ypub/Zpub/Upub/Vpub version bytes

**Severity:** P2 informational. SLIP-0132 defines per-purpose extended
key version bytes:
- `ypub` (`049D7CB2`) / `yprv` (`049D7878`) — BIP-49 P2SH-P2WPKH mainnet
- `zpub` (`04B24746`) / `zprv` (`04B2430C`) — BIP-84 P2WPKH mainnet
- `Ypub` (`0295B43F`) / `Yprv` (`0295B005`) — BIP-49 multisig P2WSH-in-P2SH
- `Zpub` (`02AA7ED3`) / `Zprv` (`02AA7A99`) — BIP-84 multisig P2WSH
- testnet counterparts (`upub`/`vpub`/etc.)

Rustoshi's `XPUB_VERSION_*` constants (`descriptor.rs:1217-1220`)
ONLY support xpub/xprv/tpub/tprv. A SLIP-0132 ypub/zpub from
Trezor / Ledger backups fails to decode with `unknown version: [...]`.

Core ALSO only emits xpub/xprv version bytes (Core normalises to
SLIP-0049-style descriptors and rejects SLIP-0132 as non-standard).
So this **matches Core's behaviour** and is not a Core-divergence per
se — but it's an interop gap with hardware wallets that emit
SLIP-0132 by default.

**File:** `crates/wallet/src/descriptor.rs:1217-1220, 1272-1281`.

**Core ref:** Core does not implement SLIP-0132. Cross-cite:
descriptors-based wallets convert at the export boundary.

**Why this matters:** users importing Trezor / Ledger / Sparrow ypub
backups will see "unknown version" errors. Either add SLIP-0132
support (informational extension) OR document the limitation +
guide users to convert to xpub form first. Currently neither.

---

## BUG-18 (P2 / informational) — `Network` enum lacks `Signet`; signet wallets collapse into Testnet

**Severity:** P2 informational. `crates/crypto/src/address.rs:18-25`:

```rust
pub enum Network {
    Mainnet,
    Testnet,    // testnet3, testnet4, signet collapsed here
    Regtest,
}
```

For BIP-32/44/49/84/86 HD derivation specifically:
- Coin type 1' is used for testnet AND signet AND regtest per SLIP-0044.
- Version bytes (tpub/tprv) are shared.
- Bech32 HRP for signet is `tb` (same as testnet), so the difference
  is signet-genesis + signet-challenge.

So for the **HD derivation layer specifically**, signet ≈ testnet is
correct. The bug is that the wallet has no way to flag a
"signet wallet" vs a "testnet wallet" — when the node is signet, the
wallet is silently named "Testnet" in logs / RPC output, which
breaks UX expectations.

**File:** `crates/crypto/src/address.rs:18-25`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:507/508` (signet
EXT_PUBLIC_KEY identical to testnet, same observation as rustoshi).

**Why this matters:** matches Core for BIP-32 specifically; surfacing
issue for cross-cite to fleet-wide W157 "signet-Network-not-modelled"
pattern (haskoin W157 BUG-1). Same shape one layer up — haskoin
lacks signet Network constructor entirely; rustoshi has it absent at
the wallet-Network enum level. **CROSS-CITE haskoin W157 BUG-1**.

---

## BUG-19 (P2 / informational) — `derive_child` calls `Secp256k1::new()` four times per CKD; global-context feature is enabled but unused

**Severity:** P2 perf. Already documented under BUG-7 (memory) — this
entry isolates the **perf** axis. `cargo bench` measurements (not
performed here) on a 5-level BIP-84 derivation would show ~5×
context-allocation overhead vs. using `secp256k1::SECP256K1`. Negligible
for one-off derivation but compounds when bulk-deriving 1000 addresses
on wallet restore.

**File:** `crates/wallet/src/hd.rs:189, 248, 260, 291`.

**Why this matters:** trivial one-line fix per call site. Cross-cite
BUG-7 for the security half of the same root cause.

---

## Summary

**Total bugs catalogued: 19**

| Severity | Count |
|----------|-------|
| P0-CONS  | 0     |
| P0-CDIV  | 5 (BUG-2, BUG-4, BUG-5, BUG-9, BUG-12) |
| P0-SEC   | 3 (BUG-6, BUG-7, BUG-13) |
| P1       | 8 (BUG-1, BUG-3, BUG-8, BUG-10, BUG-11, BUG-14, BUG-15, BUG-16) |
| P2 / info | 3 (BUG-17, BUG-18, BUG-19) |

**Top-3 highest-impact findings** (auditor's rank):
1. **BUG-4 + BUG-5 (P0-CDIV "raw-getrandom-bypasses-BIP-39"
   + "no sethdseed/getnewmnemonic RPC")** — wallets created via the
   only available code path produce a 64-byte seed with NO recoverable
   mnemonic, and no RPC exists to inject or extract one. A
   rustoshi-created wallet cannot be paper-backed up. This is the
   single most user-visible functional gap of the entire HD stack.
2. **BUG-2 + BUG-15 (P0-CDIV "network-strip on key parse")** —
   `decode_xpub`/`decode_xprv` discard the parsed network at the
   descriptor boundary, allowing silent cross-network derivation
   (mainnet wallet accepts tpub, testnet wallet accepts xpub) that
   Core rejects. Round-trip with Sparrow / Electrum / Specter breaks.
3. **BUG-6 + BUG-7 + BUG-16 ("zeroize-dep-present-but-uncovered-modules"
   + "side-channel defence absent on derivation hot path")** — the
   `zeroize` dep is imported only by `encryption.rs`; the entire
   BIP-32/BIP-39 stack leaks secret material on every derivation
   step (Clone-without-Drop), and every `derive_child` creates a fresh
   non-randomized secp256k1 context. Fleet-wide W159 UNIVERSAL pattern
   re-confirmed at the derivation layer specifically.

**Cross-cite fleet patterns surfaced this wave:**
- **W159 context_randomize UNIVERSAL 10/10** — re-confirmed at rustoshi
  HD derivation; signing context randomized, derivation context not
  (BUG-7).
- **W160 BIP-32 private-side libsecp tweak** — re-confirmed: rustoshi
  uses `add_tweak` (`hd.rs:213`), NOT pure-Rust BigInt. PASS gate.
  Explicit contrast to haskoin W159's GMP-private / libsecp-public
  asymmetry.
- **"feature-half-finished parser-vs-signer"** (hotbuns W160 fleet
  pattern) — extended here as "parser-vs-doc-claim": WIF documented
  but absent (BUG-10).
- **"comment-as-confession"** — INVERSE here: BUG-12 has NO comment
  flagging the deliberate Core deviation (no retry on `IL >= n`).
  **NEW PATTERN "silent-Core-deviation"**.
- **"signet-Network-not-modelled"** (haskoin W157 BUG-1) —
  rustoshi same shape one layer up (BUG-18); Network enum lacks
  Signet variant.
- **"test-pins-bug"** (hotbuns W157) — `#[ignore = "BUG-10: WIF
  encoding/decoding MISSING ENTIRELY"]` at `tests/test_w118_wallet.rs:857`
  is the canonical INVERSE: test exists, pins absence as "regression
  contract" awaiting fix.

**NEW patterns this wave (W161-distinctive):**
1. "raw-getrandom-bypasses-BIP-39" (BUG-4) — `create_wallet` skips
   mnemonic step entirely.
2. "network-strip on key parse" (BUG-2, BUG-15) — `decode_xpub` knows
   the network but callers discard it.
3. "zeroize-dep-present-but-uncovered-modules" (BUG-6, BUG-16) —
   Cargo.toml lists `zeroize` but only `encryption.rs` uses it.
4. "side-channel defence absent on derivation hot path" (BUG-7) —
   signing-side W159 PASS does not protect derivation-side.
5. "no depth cap on parsed paths" (BUG-9) — DoS + cross-impl
   round-trip break.
6. "gap-limit-starts-from-zero-not-last-used" (BUG-11) — restore-from-seed
   silently misses funds at indices ≥ gap_limit.
7. "silent-Core-deviation" (BUG-12) — INVERSE of
   "comment-as-confession": no comment at all on intentional spec
   divergence.
8. "BIP-32 sanity invariant skipped on decode" (BUG-3) — Core's
   `CExtKey::Decode` invalidates malformed depth-0 keys; rustoshi
   accepts.
9. "seed-length-permissiveness invites mnemonic/entropy confusion"
   (BUG-13).
10. "saturating_add as silent divergence from Core's assert" (BUG-14).
11. "debug_assert as production-contract" (BUG-8) — release-stripped
    contract.
12. "two-op pubkey derive where Core uses one" (BUG-1).

**Reference Bitcoin Core lines (canonical for this wave):**
- `bitcoin-core/src/key.cpp:293-310` — `CKey::Derive`
- `bitcoin-core/src/key.cpp:482-501` — `CExtKey::Derive` + `SetSeed`
- `bitcoin-core/src/key.cpp:523-530` — `CExtKey::Decode` (sanity-clear)
- `bitcoin-core/src/pubkey.cpp:341-363` — `CPubKey::Derive`
- `bitcoin-core/src/pubkey.cpp:394-401` — `CExtPubKey::Decode`
- `bitcoin-core/src/pubkey.h:160-163` — `GetID() = Hash160(pubkey)`
- `bitcoin-core/src/script/descriptor.cpp::ParseExtKey` — network check
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp::TopUp` — gap-limit semantics
- `bitcoin-core/src/wallet/rpc/wallet.cpp::sethdseed` — RPC seed import
- `bitcoin-core/src/kernel/chainparams.cpp:148/149, 261/262` — version bytes
