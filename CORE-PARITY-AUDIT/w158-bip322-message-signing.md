# W158 — BIP-322 message signing (Legacy + Simple + Full virtual-tx modes) (rustoshi)

**Wave:** W158 — `MessageSign`, `MessageVerify`, `MessageHash`,
`MESSAGE_MAGIC = "Bitcoin Signed Message:\n"` (length-prefixed via
HashWriter `<<`), `SignCompact` / `RecoverCompact` (65-byte
`[header][r 32][s 32]` with header = `27 + recid + (fCompressed?4:0)`),
`signmessage` (wallet), `signmessagewithprivkey` (util),
`verifymessage` (util), `RegisterSignMessageRPCCommands`,
`SigningResult::{OK,PRIVATE_KEY_NOT_AVAILABLE,SIGNING_FAILED}`,
`MessageVerificationResult::{ERR_INVALID_ADDRESS, ERR_ADDRESS_NO_KEY,
ERR_MALFORMED_SIGNATURE, ERR_PUBKEY_NOT_RECOVERED, ERR_NOT_SIGNED,
OK}`, BIP-322 modes (Legacy / Simple / Full): virtual-tx `to_spend`
(1-input null-prevout sequence=0, 1-output value=0 with scriptSig
`OP_0 PUSH(sha256(tag||msg))` where tag=`"BIP0322-signed-message"`) +
virtual-tx `to_sign` (1-input prevOut=to_spend:0 sequence=0, 1-output
value=0 OP_RETURN, witness/scriptSig signs sighash of to_sign), BIP-143
sighash for segwit witness scripts, BIP-341 sighash for taproot
key-spend / script-path, NUMS-point fallback (`H = lift_x(0x50929b74...)`)
when there is no internal-key knowledge for a P2TR address.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/common/signmessage.cpp:24` —
  `const std::string MESSAGE_MAGIC = "Bitcoin Signed Message:\n";` (24
  bytes; serialized via `HashWriter << MESSAGE_MAGIC` which writes
  `CompactSize(24) || bytes` — i.e. `0x18` length prefix + 24 bytes).
- `bitcoin-core/src/common/signmessage.cpp:73-79` — `MessageHash`:
  `HashWriter{} << MESSAGE_MAGIC << message` → returns `SHA256d` of the
  serialized stream (`HashWriter::GetHash()`).
- `bitcoin-core/src/common/signmessage.cpp:26-55` — `MessageVerify`:
  parses address, rejects non-`PKHash` with `ERR_ADDRESS_NO_KEY`,
  decodes base64 → `ERR_MALFORMED_SIGNATURE`, calls
  `CPubKey::RecoverCompact(MessageHash(msg), sig)` → on fail
  `ERR_PUBKEY_NOT_RECOVERED`, compares `PKHash(pubkey)` to the parsed
  destination → on mismatch `ERR_NOT_SIGNED`, else `OK`. Critical:
  the address is parsed BEFORE the signature.
- `bitcoin-core/src/common/signmessage.cpp:57-71` — `MessageSign`:
  `privkey.SignCompact(MessageHash(message), bytes); signature =
  EncodeBase64(bytes)`. Returns false only if `SignCompact` returns
  false (zero-keydata; impossible from a valid `CKey`).
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact`: secp256k1
  RFC-6979 recoverable-ECDSA sign; serializes 64-byte compact `r||s`
  into bytes 1..64; header byte at index 0 = `27 + recid +
  (fCompressed ? 4 : 0)`. **Additional re-verification step
  (lines 263-269)**: recovers the pubkey from the freshly produced
  signature and asserts it equals the signing pubkey. This catches
  hardware-induced bitflips on the sig output buffer.
- `bitcoin-core/src/pubkey.cpp:300-318` — `CPubKey::RecoverCompact`:
  requires `vchSig.size() == COMPACT_SIGNATURE_SIZE` (65); decodes
  recid via `(vchSig[0] - 27) & 3` and compressed-flag via
  `((vchSig[0] - 27) & 4) != 0`. **Note**: Core does NOT reject
  headers > 34; it just masks. So header byte 35 is interpreted as
  `27 + 0 + uncompressed` (recid=0). This permissive behaviour is the
  fleet-baseline.
- `bitcoin-core/src/pubkey.cpp:294-297` — Core normalizes S (`secp256k1_ecdsa_signature_normalize`)
  for `Verify`, but `RecoverCompact` does NOT normalize — the signature
  bytes are passed verbatim. Both directions are compatible: a low-S
  and high-S signature for the same key+msg both recover.
- `bitcoin-core/src/rpc/signmessage.cpp:17-60` — `verifymessage` RPC:
  maps result enum to `RPC_INVALID_ADDRESS_OR_KEY` (-5) for
  `ERR_INVALID_ADDRESS`, `RPC_TYPE_ERROR` (-3) for `ERR_ADDRESS_NO_KEY`
  AND `ERR_MALFORMED_SIGNATURE`, returns `false` (not an error) for
  `ERR_PUBKEY_NOT_RECOVERED` and `ERR_NOT_SIGNED`, `true` for `OK`.
- `bitcoin-core/src/rpc/signmessage.cpp:62-101` — `signmessagewithprivkey`
  RPC: decodes WIF via `DecodeSecret(strPrivkey)`; returns
  `RPC_INVALID_ADDRESS_OR_KEY` for invalid privkey OR sign-fail; emits
  base64 of `MessageSign` output.
- `bitcoin-core/src/rpc/signmessage.cpp:103-112` —
  `RegisterSignMessageRPCCommands`: places BOTH `verifymessage` and
  `signmessagewithprivkey` under the `"util"` category. (NOT "wallet".)
- `bitcoin-core/src/wallet/rpc/signmessage.cpp:13-71` — `signmessage`
  (wallet): requires a loaded wallet (`GetWalletForJSONRPCRequest`
  returns `VNULL` if absent), takes `LOCK(cs_wallet)`, calls
  `EnsureWalletIsUnlocked(*pwallet)`, gates on `PKHash` (legacy P2PKH
  ONLY), then `pwallet->SignMessage(strMessage, *pkhash, signature)`.
  Returns `RPC_INVALID_ADDRESS_OR_KEY` for `SIGNING_FAILED` and
  `RPC_WALLET_ERROR` (-4) for `PRIVATE_KEY_NOT_AVAILABLE`. The wallet
  variant is registered separately by the wallet (NOT in the global
  table).
- `bitcoin-core/src/wallet/wallet.cpp:2254-2265` — `CWallet::SignMessage`:
  iterates the wallet's script-pubkey managers, finds one that
  `CanProvide` the `PKHash` destination, delegates to its `SignMessage`.
  Returns `PRIVATE_KEY_NOT_AVAILABLE` if no SPK manager owns the key.
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp:1291-1307` —
  `DescriptorScriptPubKeyMan::SignMessage`: `GetSigningProvider`, then
  `keys->GetKey(ToKeyID(pkhash), key)`, then `MessageSign(key, ...)`.
  Returns `PRIVATE_KEY_NOT_AVAILABLE` when GetKey fails (e.g. watch-only
  wallet, encrypted-locked wallet, or pkh not owned).
- BIP-322 — Generic signed message format (the "rest of the iceberg"
  beyond legacy BIP-137):
  - **Tag**: `"BIP0322-signed-message"` (the tagged hash of the message
    is `SHA256(tag || msg)` consumed as the scriptSig `OP_RETURN`
    commitment in `to_spend`).
  - **`to_spend` virtual tx**: nVersion=0, nLockTime=0, 1 input
    `{prev_txid=0x00..00, prev_vout=0xFFFFFFFF, sequence=0,
    scriptSig=OP_0 PUSH(sha256(tag||msg))}`, 1 output
    `{value=0, scriptPubKey=<address.scriptPubKey>}`. Effectively a
    coinbase-shaped commitment to the message.
  - **`to_sign` virtual tx**: nVersion=0, nLockTime=0, 1 input
    `{prev_txid=txid(to_spend), prev_vout=0, sequence=0, scriptSig
    and/or witness produced by signing}`, 1 output `{value=0,
    scriptPubKey=OP_RETURN}`. The sighash is computed against the
    `to_sign` tx using BIP-143 (segwit v0) or BIP-341 (taproot) with
    the prevout being `to_spend`'s sole output.
  - **Simple mode**: serialize ONLY `to_sign.witness` (varint
    witness-stack-count + each item with length prefix). Base64 of that.
    Only supported for witness programs.
  - **Full mode**: serialize the FULL `to_sign` tx (witness format).
    Base64 of that. Required when `to_sign` has multiple inputs (one
    P2WSH script-path with siblings) or non-trivial scriptSig (P2SH).
  - **Legacy (BIP-137)**: identical to today's `MessageSign` /
    `MessageVerify`; ECDSA-recoverable on `MessageHash(msg)`, base64
    encoded, P2PKH ONLY on verify side. Compatible with all wallets
    that ship Core 0.7.x+.
- BIP-340 NUMS-point — `H = lift_x(0x50929b74...)`. Used as the
  Taproot internal-key when proving "this address has no key-path
  spendability". BIP-322 uses NUMS for P2TR addresses where the signer
  doesn't know the internal key (script-path-only signing).

**Files audited**
- `crates/crypto/src/keys.rs` — `BITCOIN_SIGNED_MESSAGE_MAGIC`
  (line 18: hardcoded `b"\x18Bitcoin Signed Message:\n"` with manual
  0x18 length-prefix); `signed_message_hash` (line 25-32: manual
  `compact-size` for message length, then `sha256d`); `encode_compact_size`
  (line 34-47, fileprivate); `sign_message_compact` (line 58-75:
  recoverable ECDSA + manual recid→header byte mapping); `recover_message_pubkey`
  (line 83-105: rejects header outside `27..=34`, parses recid +
  compressed flag, returns `(PublicKey, bool)`).
- `crates/crypto/src/lib.rs:30-36` — re-exports
  `sign_message_compact`, `recover_message_pubkey`, `signed_message_hash`,
  `BITCOIN_SIGNED_MESSAGE_MAGIC`.
- `crates/rpc/src/server.rs:822-861` — RPC trait declarations:
  `verify_message` (`#[method(name = "verifymessage")]`), `sign_message`
  (`#[method(name = "signmessage")]`), `sign_message_with_privkey`
  (`#[method(name = "signmessagewithprivkey")]`).
- `crates/rpc/src/server.rs:7320-7378` — `verify_message` impl (parses
  signature FIRST then address, P2PKH-only, returns bool on bad sig).
- `crates/rpc/src/server.rs:7380-7420` — `sign_message` impl
  (wallet-shaped surface that **always returns -18 RPC_WALLET_NOT_FOUND**
  with hard-coded error code, because the `RpcServerImpl` does NOT hold
  a `WalletManager`).
- `crates/rpc/src/server.rs:7422-7437` — `sign_message_with_privkey`
  impl (`parse_signing_privkey` for hex/WIF, signs, base64-encodes).
- `crates/rpc/src/server.rs:9650-9687` — `parse_signing_privkey`
  helper (hex 64-char OR base58check WIF; returns
  `(SecretKey, compressed_flag)`).
- `crates/rpc/src/server.rs:7240-7274` — help command listing
  (categorises `signmessagewithprivkey` under BOTH `== Wallet ==` AND
  `== Util ==`; categorises `signmessage` under `== Wallet ==`,
  `verifymessage` under `== Util ==`).
- `crates/rpc/src/server.rs:7223-7233` — per-command help strings.
- `crates/rpc/src/server.rs:12298-12356` — `signmessage_verifymessage_roundtrip_compressed`
  test (round-trip via `sign_message_with_privkey` → `verify_message`).
- `crates/wallet/src/wallet.rs:1698-1744` — `private_key_for_pkh`
  (HD-scan by hash160) + `private_key_for_address` (path lookup).
  **These exist but have ZERO non-test production callers; the
  `RpcServerImpl::sign_message` path does NOT wire to a `WalletManager`.**
- `crates/rpc/src/wallet.rs` — wallet RPC module (`WalletManager` is
  held in `WalletRpcState`). Confirmed via grep: no `signmessage` /
  `verifymessage` / `sign_message` / `verify_message` methods.
- `crates/rpc/tests/test_w125_error_parity.rs:103-136` — error-parity
  audit; flags `BUG-16` (`RPC_TYPE_ERROR` -3 used at only 1 site,
  `signmessage` non-PKH at server.rs:7399) + `BUG-25` (hardcoded `-18`
  literal in `signmessage` at server.rs:7416).

---

## Gate matrix (28 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `MessageHash` parity | G1: magic prefix bytes = `"Bitcoin Signed Message:\n"` (24 bytes) | PASS (`keys.rs:18`) |
| 1 | … | G2: length-prefix byte `0x18` (compact-size of 24) precedes the magic | PASS (`keys.rs:18`, prefix manually folded) |
| 1 | … | G3: message length encoded as `CompactSize` (1/3/5/9 bytes per range) | PASS (`keys.rs:25-32`, `encode_compact_size` line 34-47) |
| 1 | … | G4: final hash is `sha256d` of the assembled buffer | PASS (`keys.rs:31`) |
| 2 | `signmessagewithprivkey` parity | G5: accepts WIF base58check (compressed/uncompressed) | PASS (`server.rs:9665-9686`) |
| 2 | … | G6: accepts 64-char raw hex private key | PARTIAL — accepted (`server.rs:9654-9663`), but **BUG-1 (P0-CDIV)** Core's `DecodeSecret` rejects hex; rustoshi accepts an input form Core does NOT |
| 2 | … | G7: signature is 65-byte compact-recoverable; header byte = `27 + recid + (fCompressed?4:0)` | PASS (`keys.rs:62-73`) |
| 2 | … | G8: post-sign re-verification step (Core key.cpp:263-269 corruption guard) | **BUG-2 (P1)** — rustoshi `sign_message_compact` does NOT re-recover and compare; Core does, as a hardware-bitflip belt-and-suspenders gate |
| 2 | … | G9: invalid hex/WIF returns `RPC_INVALID_ADDRESS_OR_KEY` (-5) | PASS (`server.rs:7430-7432`) |
| 3 | `verifymessage` parity | G10: parse-order is address FIRST then signature | **BUG-3 (P1)** — rustoshi `verify_message` parses signature BEFORE address (`server.rs:7339-7354`); Core (signmessage.cpp:31-43) parses address first. Diverges error precedence on inputs with BOTH garbage-base64 and bad-address |
| 3 | … | G11: bad base64 → `RPC_TYPE_ERROR` (-3) "Malformed base64 encoding" | **BUG-4 (P1)** — rustoshi emits `RPC_INVALID_PARAMS` (-32602) at `server.rs:7343` instead of Core's `RPC_TYPE_ERROR` (-3 from `signmessage.cpp:48-49`); message text matches |
| 3 | … | G12: P2PKH ONLY (legacy address) | PASS (`server.rs:7355-7363`) |
| 3 | … | G13: non-P2PKH → `RPC_TYPE_ERROR` (-3) "Address does not refer to key" | PARTIAL — code = correct (`server.rs:7358-7361`); message text diverges ("to a P2PKH key" vs Core's "to key") |
| 3 | … | G14: bad recovery / pubkey-mismatch → bool `false` (NOT error) | PASS (`server.rs:7367-7377`) |
| 3 | … | G15: empty address → `RPC_INVALID_ADDRESS_OR_KEY` (-5) | PASS (`server.rs:7331-7336`) — but message text "Invalid address" matches Core |
| 4 | `signmessage` (wallet) parity | G16: takes `(address, message)`; locks wallet; calls `EnsureWalletIsUnlocked` | **BUG-5 (P0-CDIV)** — rustoshi has NO wallet lookup at all; the method body unconditionally returns `RPC_WALLET_NOT_FOUND` (`server.rs:7415-7419`), so the entire `signmessage` flow is functionally dead |
| 4 | … | G17: address must be P2PKH; non-PKH → `RPC_TYPE_ERROR` | PARTIAL — code-path runs but result is masked by BUG-5 (always -18 before reaching the gate) |
| 4 | … | G18: key not in wallet → `RPC_WALLET_ERROR` (-4) (Core via `SigningResult::PRIVATE_KEY_NOT_AVAILABLE`) | **BUG-5 cross-cite** — always -18 regardless |
| 4 | … | G19: passphrase-locked wallet → `RPC_WALLET_UNLOCK_NEEDED` (-13) via `EnsureWalletIsUnlocked` | **BUG-5 cross-cite** |
| 5 | Recovery-header validation | G20: reject `vchSig.size() != 65` | PASS (`keys.rs:87-89`) |
| 5 | … | G21: accept Core's full 27..=34 header range (incl. uncompressed) | PASS (`keys.rs:90-94`) |
| 5 | … | G22: handle header BYTES outside 27..=34 as Core does (mask, not reject) | **BUG-6 (P1)** — rustoshi rejects header outside `27..=34` (`keys.rs:91`); Core (pubkey.cpp:303-304) MASKS via `(vchSig[0] - 27) & 3` and `& 4`, accepting arbitrary upper bits. Stricter than Core, divergence |
| 5 | … | G23: recoverable sig parse failure → return error to caller | PASS (`keys.rs:99-100`) |
| 6 | `RegisterSignMessageRPCCommands` namespacing | G24: `verifymessage` listed under `util` category | PASS (`server.rs:7271-7273`) |
| 6 | … | G25: `signmessagewithprivkey` listed under `util` category ONLY (not wallet) | **BUG-7 (P2)** — rustoshi help lists `signmessagewithprivkey` under BOTH `== Wallet ==` (`server.rs:7265`) AND `== Util ==` (`server.rs:7273`); Core registers under util only |
| 6 | … | G26: `signmessage` (wallet) listed under `wallet` category | PASS (`server.rs:7263-7266`) |
| 7 | BIP-322 Simple mode | G27: `to_spend` virtual-tx construction + `to_sign` virtual-tx construction + tagged hash with `"BIP0322-signed-message"` + Simple serialization (witness-only) | **BUG-8 (P0-CDIV)** — BIP-322 Simple mode does NOT EXIST in rustoshi. Zero grep hits for `BIP0322`/`bip322`/`to_spend`/`to_sign` anywhere in the crate tree. `verifymessage` rejects ALL P2WPKH/P2WSH/P2TR addresses with `RPC_TYPE_ERROR`. Wallets that ship BIP-322-only proofs (Sparrow, Trezor, Ledger post-2023) cannot use rustoshi to verify |
| 8 | BIP-322 Full mode | G28: Full-mode (multi-input or script-path) tx serialization + BIP-143 / BIP-341 sighash on virtual `to_sign` + NUMS-point fallback for P2TR script-path-only signing | **BUG-9 (P0-CDIV)** — Full mode entirely absent; cross-cite BUG-8 |

---

## BUG-1 (P0-CDIV) — `signmessagewithprivkey` accepts 64-char hex; Core only accepts WIF

**Severity:** P0-CDIV. Core's `signmessagewithprivkey` calls
`DecodeSecret(strPrivkey)` (`bitcoin-core/src/rpc/signmessage.cpp:87`),
which ONLY accepts Base58Check WIF. A 64-char hex string is NOT valid
input to Core's `DecodeSecret` (`key_io.cpp::DecodeSecret`).

rustoshi's `parse_signing_privkey` (`crates/rpc/src/server.rs:9650-9687`)
adds a non-Core hex form:

```rust
if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
    let bytes = hex::decode(input)...;
    ...
    return Ok((key, true));  // <-- ACCEPTS 64-CHAR HEX
}
```

A test at server.rs:12260-12265 asserts this hex acceptance is
deliberate. The doc-comment at server.rs:850-855 says rustoshi "Accepts
either a Base58Check WIF or a 64-char hex-encoded raw private key" —
this is **`comment-as-confession`**, the divergence is documented.

**Failure modes:**
- A cross-impl test that sends `signmessagewithprivkey "<64-char hex>"
  "msg"` succeeds on rustoshi and FAILS on Core (and likely every other
  hashhog impl that mirrors Core strictly), producing a false-positive
  in interop tests.
- A user pasting a raw hex privkey (e.g. exported by `dumpprivkey` in
  earlier days or by a hardware-wallet seed-derivation script) gets
  "it works" on rustoshi and "it doesn't" on Core, then ships scripts
  that depend on rustoshi's superset acceptance.
- Hex acceptance defaults `compressed = true` unconditionally (line
  9662). Core's WIF compressed flag is derived from the 0x01 suffix.
  An imported uncompressed key signed via hex → rustoshi will produce
  a compressed-flag header byte that Core can recover, but the P2PKH
  address derived from compressed pubkey hash160 does NOT match the
  address the operator expects (which was uncompressed). Verify
  silently fails with `ERR_NOT_SIGNED`.

**File:** `crates/rpc/src/server.rs:9650-9687`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:87` —
`CKey key = DecodeSecret(strPrivkey);` (WIF only).

**Impact:** silent interop divergence; default-to-compressed for
hex-imported keys breaks address derivation for legacy uncompressed
imports.

---

## BUG-2 (P1) — `sign_message_compact` skips Core's re-verification (corruption guard)

**Severity:** P1. Bitcoin Core's `CKey::SignCompact` at
`bitcoin-core/src/key.cpp:262-269` does a post-sign re-verify:

```cpp
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey epk, rpk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &epk, ...);
assert(ret);
ret = secp256k1_ecdsa_recover(secp256k1_context_static, &rpk, &rsig, hash.begin());
assert(ret);
ret = secp256k1_ec_pubkey_cmp(secp256k1_context_static, &epk, &rpk);
assert(ret == 0);
```

This catches three classes of corruption:
1. Bitflip on the `vchSig` output buffer between sign and serialise.
2. Bitflip during recid serialisation (`recoverable_signature_serialize_compact`).
3. Compiler / linker miscompile of the secp256k1 wrapper.

rustoshi's `sign_message_compact` (`crates/crypto/src/keys.rs:58-75`)
does NOT perform this gate. The signature bytes are returned directly
from `serialize_compact`, with the `assert!((0..=3).contains(&recid))`
the only sanity check.

**File:** `crates/crypto/src/keys.rs:58-75`.

**Core ref:** `bitcoin-core/src/key.cpp:262-269`.

**Impact:** zero functional impact in normal operation (the assert in
Core fires only on hardware fault). But Core's gate is the difference
between "produce a corrupt sig and ship it" and "abort". On a
long-running mining/signing process under cosmic-ray flip pressure
(ECC RAM gives this >10⁻¹⁵ but unsigned RAM gives ~10⁻⁷ per bit-day),
rustoshi will silently emit garbage signatures while Core would crash.

---

## BUG-3 (P1) — `verifymessage` parses signature BEFORE address (error precedence flipped)

**Severity:** P1. Bitcoin Core's `MessageVerify`
(`bitcoin-core/src/common/signmessage.cpp:31-43`):

```cpp
CTxDestination destination = DecodeDestination(address);
if (!IsValidDestination(destination)) return ERR_INVALID_ADDRESS;
if (std::get_if<PKHash>(&destination) == nullptr) return ERR_ADDRESS_NO_KEY;

auto signature_bytes = DecodeBase64(signature);
if (!signature_bytes) return ERR_MALFORMED_SIGNATURE;
```

Address is parsed first, then signature. A request with BOTH bad
address AND bad base64 returns `ERR_INVALID_ADDRESS` (→
RPC_INVALID_ADDRESS_OR_KEY).

rustoshi's `verify_message` at `crates/rpc/src/server.rs:7320-7377`
parses signature FIRST then address:

```rust
let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(signature.trim()) {
    Ok(b) => b,
    Err(_) => return Err(Self::rpc_error(rpc_error::RPC_INVALID_PARAMS, "Malformed base64 encoding")),
};

let parsed = Address::from_string(&address, None).map_err(|_| {
    Self::rpc_error(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, "Invalid address")
})?;
```

A request with BOTH bad address AND bad base64 returns
`RPC_INVALID_PARAMS` "Malformed base64 encoding" on rustoshi vs
`RPC_INVALID_ADDRESS_OR_KEY` "Invalid address" on Core.

**File:** `crates/rpc/src/server.rs:7339-7354`.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:31-43` (order is
load-bearing).

**Impact:** cross-impl divergence on error-message precedence; test
suites that assert on the error code returned by a deliberately-bad
request will see different results. Also pairs with BUG-4 (the error
CODE differs even if address-first ordering were restored).

---

## BUG-4 (P1) — `verifymessage` "Malformed base64" emits `-32602` not Core's `-3`

**Severity:** P1. Bitcoin Core's `verifymessage` RPC at
`bitcoin-core/src/rpc/signmessage.cpp:48-49`:

```cpp
case MessageVerificationResult::ERR_MALFORMED_SIGNATURE:
    throw JSONRPCError(RPC_TYPE_ERROR, "Malformed base64 encoding");
```

Code is `RPC_TYPE_ERROR = -3` (protocol.h:41).

rustoshi emits `RPC_INVALID_PARAMS = -32602` at
`crates/rpc/src/server.rs:7343`. Message text matches Core.

This is the same class as W125 BUG-16 (RPC_TYPE_ERROR is under-used in
rustoshi). The verify-message error pair is the most-cited example in
the W125 audit.

**File:** `crates/rpc/src/server.rs:7343`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:48-49`.

**Impact:** cross-impl test failures on negative-test cases. Operators
parsing the numeric code to route error handling treat -3 (parameter
shape) and -32602 (JSON-RPC malformed) differently.

---

## BUG-5 (P0-CDIV) — `signmessage` (wallet) is **completely dead** — always returns `RPC_WALLET_NOT_FOUND`

**Severity:** P0-CDIV ("**wiring-look-but-no-wire**" fleet pattern,
plus "**dead-helper-at-call-site**" — wallet primitives exist but no
caller wires them up).

rustoshi's `RpcServerImpl::sign_message`
(`crates/rpc/src/server.rs:7380-7420`):

```rust
async fn sign_message(&self, address: String, message: String) -> RpcResult<String> {
    if address.is_empty() { ... }
    let parsed = Address::from_string(&address, None).map_err(...)?;
    let _pkh = match parsed {
        Address::P2PKH { hash, .. } => hash,
        _ => return Err(Self::rpc_error(RPC_TYPE_ERROR, ...)),
    };

    // Look up the wallet's key for this address.
    //
    // The RPC server currently has no shared wallet keystore (the wallet
    // RPC module ships separately and isn't wired into the live router).
    // Until that is plumbed through, we surface an honest "no wallet
    // available" error ...
    let _ = message; // silence unused-warn until wallet wiring lands.
    Err(Self::rpc_error(
        -18, // RPC_WALLET_NOT_FOUND, matches Core's "no wallet" surface.
        "Method needs a loaded wallet (none available in this build). \
         Use signmessagewithprivkey for raw-key signing.",
    ))
}
```

The inline comment is a **`comment-as-confession`** (fleet pattern, Nth
distinct rustoshi instance) — it documents that the integration is not
done and points the caller at a different RPC.

Compounding factors:

1. **`RpcServerImpl` does NOT hold a `WalletManager`**. The struct
   (`server.rs:1029-1037`) has only `state`, `peer_state`, `zmq_notifier`.
   `WalletManager` lives in a separate `WalletRpcState`
   (`crates/rpc/src/wallet.rs:482`) used by the wallet RPC module
   that "ships separately and isn't wired into the live router."

2. **`Wallet::private_key_for_pkh` / `Wallet::private_key_for_address`**
   exist in `crates/wallet/src/wallet.rs:1714` / `1736` — they are
   precisely the primitives Core's
   `DescriptorScriptPubKeyMan::SignMessage` needs (key lookup by
   PKHash). They are exported (`pub fn`) and documented as "Used by
   the Core-shaped `signmessage` RPC" (`wallet.rs:1735`) — but they
   have **zero non-test production callers** (grep confirms only
   `crates/wallet/src/payjoin.rs:737` uses `private_key_for_address`,
   not for signmessage).

3. **`sign_message_compact` exists** (`crates/crypto/src/keys.rs:58`)
   and is wired into `signmessagewithprivkey`. It would also be the
   correct primitive to use after wallet lookup. The wiring stops at
   the wallet boundary.

4. **The error code `-18` is hard-coded** instead of using the named
   constant `wallet_error::RPC_WALLET_NOT_FOUND` (which equals -18).
   Numeric match, but flagged separately as W125 BUG-25 (P3).

5. **The error message is misleading**. Core's `signmessage` returns
   `RPC_WALLET_NOT_FOUND` (-18) only when there is genuinely no wallet
   loaded — i.e., `GetWalletForJSONRPCRequest(request)` returns
   `VNULL`. Rustoshi returns -18 even when wallets ARE loaded (via
   the separate wallet RPC namespace). An operator who has
   `loadwallet`-ed and then runs `signmessage` is told "no wallet
   loaded" — false.

**Failure modes:**
- Any client that calls `signmessage "<addr>" "<msg>"` (the Core-spec
  way to sign with the active wallet) gets a -18 error regardless of
  wallet state — and is then told to use `signmessagewithprivkey`,
  which requires the operator to have the raw key on hand.
- Hardware-wallet-style flows (operator address resident in wallet,
  raw key NOT exportable) can't sign messages at all.
- Cross-impl: every hashhog impl that wires `signmessage` properly
  (blockbrew, haskoin per parity matrix) succeeds where rustoshi fails.

**File:** `crates/rpc/src/server.rs:7380-7420`;
`crates/wallet/src/wallet.rs:1698-1744` (dead primitives).

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:14-69`,
`bitcoin-core/src/wallet/wallet.cpp:2254-2265`,
`bitcoin-core/src/wallet/scriptpubkeyman.cpp:1291-1307`.

**Impact:** `signmessage` is functionally dead. Operators must drop
to raw-key signing. The wallet primitives Core requires are present
but unused — a textbook **wiring-look-but-no-wire**.

---

## BUG-6 (P1) — `recover_message_pubkey` rejects header bytes outside `27..=34`; Core MASKS, not rejects

**Severity:** P1. Bitcoin Core's `CPubKey::RecoverCompact` at
`bitcoin-core/src/pubkey.cpp:300-318`:

```cpp
int recid = (vchSig[0] - 27) & 3;        // recid is bottom 2 bits
bool fComp = ((vchSig[0] - 27) & 4) != 0; // compressed bit is bit 2
```

A header byte of 35 → `(35-27) & 3 = 8 & 3 = 0` (recid=0) and
`(35-27) & 4 = 8 & 4 = 0` (uncompressed). Core interprets 35 the same
as 27 — it does NOT reject.

rustoshi's `recover_message_pubkey` (`crates/crypto/src/keys.rs:90-94`):

```rust
let header = sig_bytes[0];
if !(27..=34).contains(&header) {
    return Err(secp256k1::Error::InvalidSignature);
}
```

Strictly stricter than Core. A signature with header 35 (which Core
would accept and produce a pubkey for) returns `InvalidSignature` on
rustoshi.

This is the **stricter-than-Core** flavour of divergence: rustoshi
gives `false` (via the `match Err(_) => return Ok(false)` at
`server.rs:7367-7370`) on some inputs Core accepts. Real-world impact
is low (no signing path produces headers > 34), but stress-tests and
fuzzers that exercise the verify boundary will diverge.

**File:** `crates/crypto/src/keys.rs:90-94`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:303-304`.

**Impact:** fuzz divergence; some BIP-322 simple-mode signers might
emit non-standard headers (compressed flag in upper bits beyond 34)
in malicious payloads — rustoshi would safely reject while Core
would tolerate. This is one of the rare "stricter is fine" cases but
still a behavioural divergence.

---

## BUG-7 (P2) — Help listing duplicates `signmessagewithprivkey` under Wallet AND Util

**Severity:** P2. Bitcoin Core's `RegisterSignMessageRPCCommands`
(`bitcoin-core/src/rpc/signmessage.cpp:103-112`) places BOTH
`verifymessage` and `signmessagewithprivkey` under the "util" category
only:

```cpp
static const CRPCCommand commands[]{
    {"util", &verifymessage},
    {"util", &signmessagewithprivkey},
};
```

The wallet's `signmessage` is registered separately by the wallet
under "wallet".

rustoshi's `help` command listing (`crates/rpc/src/server.rs:7261-7274`)
puts `signmessagewithprivkey` under BOTH `== Wallet ==` (line 7265)
AND `== Util ==` (line 7273):

```rust
"== Wallet ==",
"createmultisig", "deriveaddresses", "getdescriptorinfo", "listlockunspent", "lockunspent",
"setlabel", "signmessage", "signmessagewithprivkey", "validateaddress",   // <-- here
"walletcreatefundedpsbt", "walletlock", "walletpassphrase",
"",
...
"== Util ==",
"estimaterawfee", "estimatesmartfee", "getindexinfo", "getnettotals", "help",
"signmessagewithprivkey", "stop", "uptime", "verifymessage",              // <-- AND here
```

Duplicate. Operator running `help` sees `signmessagewithprivkey` twice
under two different categories.

**File:** `crates/rpc/src/server.rs:7265, 7273`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:103-112`.

**Impact:** cosmetic; operator UX confusion. Tooling that scrapes
`help` to discover commands picks up the duplicate.

---

## BUG-8 (P0-CDIV) — BIP-322 Simple mode is **entirely absent**

**Severity:** P0-CDIV. Bitcoin Core ships BIP-322 verify-side support
since v25 (and signing-side via descriptor wallets in v26+). The Simple
mode allows P2WPKH / P2WSH / P2TR addresses to participate in
signed-message verification by constructing virtual `to_spend` /
`to_sign` transactions and verifying the witness.

rustoshi grep over the entire crate tree shows **zero hits** for any
of: `bip322`, `bip-322`, `BIP0322`, `to_spend`, `to_sign`,
`BIP0322-signed-message`. The BIP-322 standard is unimplemented.

The `verifymessage` impl at `crates/rpc/src/server.rs:7355-7363`
explicitly rejects all non-P2PKH addresses:

```rust
let expected_hash = match parsed {
    Address::P2PKH { hash, .. } => hash,
    _ => {
        return Err(Self::rpc_error(
            rpc_error::RPC_TYPE_ERROR,
            "Address does not refer to a P2PKH key",
        ))
    }
};
```

A user attempting to verify a Sparrow / Trezor / Ledger / mempool.space
generated BIP-322 signature for ANY native-segwit address (bc1q…) or
Taproot address (bc1p…) gets `RPC_TYPE_ERROR`. This matches Core's
PRE-v25 behaviour, but trails the current Core surface area by 2+
years.

**Components required for BIP-322 verify** (all missing in rustoshi):
1. **`to_spend` virtual-tx construction**: 1-input null-prevout
   (`0x00..00:0xFFFFFFFF`) sequence=0, scriptSig = `OP_0
   PUSH(sha256(tag||msg))` where tag = `"BIP0322-signed-message"`.
   1-output value=0 with `scriptPubKey = address.scriptPubKey`.
2. **`to_sign` virtual-tx construction**: 1-input prevOut=to_spend:0
   sequence=0, with the **witness parsed from the base64-decoded
   signature blob**. 1-output value=0 with `scriptPubKey = OP_RETURN`.
3. **Witness deserialization from Simple-mode blob** — varint
   stack-count + per-stack-item length-prefixed byte string.
4. **BIP-143 sighash dispatch** for P2WPKH/P2WSH using to_spend.outputs[0]
   as the prevout, to_sign as the tx-under-sign.
5. **BIP-341 sighash dispatch** for P2TR (key-spend AND script-path).
6. **`VerifyScript`** invocation with `STANDARD_SCRIPT_VERIFY_FLAGS`
   including WITNESS|TAPROOT.

**File:** `crates/rpc/src/server.rs:7320-7378` (rejects non-P2PKH);
fleet-wide absence (grep -r "bip322" returns nothing).

**Core ref:** BIP-322 spec; Core's `SignMessage`/`MessageVerify`
extension in v25+ (kept as separate code paths that wrap
`MessageSign`/`MessageVerify` and dispatch by address type).

**Impact:**
- All wallets/proofs that ship BIP-322-only signatures (modern
  hardware wallets, mempool.space's "Sign with Bitcoin" UI, Sparrow's
  message-signing tool with native-segwit account, Bitkit, etc.) cannot
  be verified against rustoshi. Operators must fall back to Core or
  another impl.
- Cross-impl: any sub-fleet bridge or proof-of-reserves tool that
  relies on BIP-322 silently breaks at the rustoshi boundary.
- Standard parity gap: rustoshi's claim of P2PKH-only verifymessage is
  ~10-year-stale BIP-137 surface, not 2026-era Bitcoin.

---

## BUG-9 (P0-CDIV) — BIP-322 Full mode (multi-input / script-path) is **entirely absent**

**Severity:** P0-CDIV (companion to BUG-8). BIP-322 Full mode requires
the complete `to_sign` tx serialization (not just the witness blob).
This is required for:

1. **Multi-input proofs of reserve** — exchanges signing across N UTXOs
   in one BIP-322 message to prove they hold all of them.
2. **Script-path Taproot signing** — P2TR addresses where the signer
   uses a script-leaf instead of the key-path. The control block + leaf
   script + script-witness stack must travel in the proof.
3. **P2SH-wrapped witness scripts** — scriptSig in to_sign is non-empty.
4. **MuSig2 aggregate signing** — multi-signer flow; Full-mode carries
   the partial signature exchange artefacts.

rustoshi has none of:

- A tx serialization path that takes a virtual-tx (value=0 inputs and
  outputs are unusual on the encode side and trigger several sanity
  checks in `Transaction::encode` flows).
- BIP-143 sighash dispatch wired into `verifymessage`.
- BIP-341 sighash dispatch wired into `verifymessage`.
- NUMS-point fallback (`H = lift_x(0x5092...)`) for P2TR
  script-path-only signing (where the signer has no internal-key
  knowledge).

Note `crates/crypto/src/taproot.rs::compute_taproot_sighash` exists and
is the primitive Full-mode needs, but it has zero callers in any
`verifymessage` / `signmessage` path. Same shape as BUG-5: primitive
exists, wiring absent.

**File:** entire crate tree (no BIP-322 module).

**Core ref:** BIP-322 spec; Sparrow's reference implementation
(`bitcoin-message-tool`); the `mempool/mempool` `verifymessage` library.

**Impact:**
- Proof-of-reserves attestations published in BIP-322 Full mode cannot
  be verified against rustoshi at all.
- Lightning / DLC / discrete-log-contract counterparty key proofs that
  use BIP-322 Full + script-path → silent rejection.
- Cross-impl interop: at least one upcoming exchange-reserves audit
  tool ships BIP-322 Full mode as the only supported format.

---

## BUG-10 (P1) — `verifymessage` error message for P2WPKH says "P2PKH key" not "key"

**Severity:** P1. Core's `MessageVerify` returns
`ERR_ADDRESS_NO_KEY` for any non-PKHash destination, which the RPC
maps to:

```cpp
case MessageVerificationResult::ERR_ADDRESS_NO_KEY:
    throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
```

— a generic "this address type can't be used for signed-messages"
message.

rustoshi's `verify_message` at `crates/rpc/src/server.rs:7358-7361`
emits "Address does not refer to a P2PKH key". The phrase "a P2PKH"
narrows what Core says into something more specific.

Pre-BIP-322 this would actually be informative, but post-BIP-322 it is
**misleading**: a user with a P2WPKH address SHOULD be able to sign
messages (via BIP-322 Simple) — the error message implies the address
shape is the problem, not the missing implementation. (Cross-cite BUG-8
/ BUG-9: the actual reason is "BIP-322 not implemented".)

**File:** `crates/rpc/src/server.rs:7360`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:47`.

**Impact:** misleading error UX; operator wastes time investigating
why "their P2PKH key" doesn't refer to a key when in fact they pasted
a P2WPKH and the system just doesn't support BIP-322.

---

## BUG-11 (P1) — `Wallet::private_key_for_pkh` and `_for_address` are dead code

**Severity:** P1 ("**dead-helper-at-call-site**" fleet pattern;
documented as "Used by the Core-shaped `signmessage` RPC" but unused).

`crates/wallet/src/wallet.rs:1698-1744` defines two helpers:

```rust
pub fn private_key_for_pkh(&self, pkh: &Hash160) -> Option<SecretKey> { ... }
pub fn private_key_for_address(&self, address: &str) -> Option<SecretKey> { ... }
```

Both are `pub fn`, both have doc comments explicitly stating they
mirror Core's `pwallet->GetKey(pkh, key)` from
`signmessage.cpp:54-60`, AND are "Used by the Core-shaped `signmessage`
RPC" (line 1735).

`grep -rn "private_key_for_pkh\|private_key_for_address" crates/`
produces:
- defs in `crates/wallet/src/wallet.rs:1714, 1736`
- a test in `crates/wallet/src/wallet.rs:2975-2987`
- one production caller in `crates/wallet/src/payjoin.rs:737` (uses
  `private_key_for_address` for PayJoin input signing, NOT signmessage)

The signmessage wiring is absent (BUG-5). The helpers were added in
anticipation but never connected. This is a textbook
**dead-helper-at-call-site** — function exists, exported, documented,
even tested, but no production caller of the intended path.

**File:** `crates/wallet/src/wallet.rs:1698-1744` (defs);
`crates/rpc/src/server.rs:7380-7420` (intended-but-absent caller).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp:1299` —
`if (!keys->GetKey(ToKeyID(pkhash), key))`.

**Impact:** dead code waiting to rot; if a future refactor renames the
helpers, no caller breaks, and the next operator to wire signmessage
either invents new helpers or hits the rename. Compaction risk.

---

## BUG-12 (P2) — No `EnsureWalletIsUnlocked` analogue; encrypted-wallet flow missing

**Severity:** P2. Bitcoin Core's `signmessage` (wallet)
calls `EnsureWalletIsUnlocked(*pwallet)` before signing
(`bitcoin-core/src/wallet/rpc/signmessage.cpp:44`). This raises
`RPC_WALLET_UNLOCK_NEEDED` (-13) "Error: Please enter the wallet
passphrase with walletpassphrase first" if the wallet is encrypted
and locked.

rustoshi has no wallet encryption (W125 BUG comments at server.rs:7287
and 7301 confirm: `walletpassphrase` and `walletlock` both return
`RPC_WALLET_WRONG_ENC_STATE` -15 unconditionally on the grounds that
"wallet encryption not implemented in this build"). Consequently:

1. There is no "unlock needed" path for `signmessage`.
2. The `RPC_WALLET_UNLOCK_NEEDED` constant is defined at
   `crates/rpc/src/wallet.rs:39` but never thrown anywhere.
3. If/when wallet encryption lands, the `signmessage` integration
   (BUG-5) needs to be updated to gate on the unlock state, OR it
   silently signs from a locked wallet (worse).

**File:** `crates/rpc/src/server.rs:7380-7420` (no unlock gate);
`crates/rpc/src/wallet.rs:39` (constant defined, unused).

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:44`,
`bitcoin-core/src/wallet/rpc/util.cpp::EnsureWalletIsUnlocked`.

**Impact:** future-bug surface. When BUG-5 is fixed, BUG-12 will need
attention or signing from a locked wallet becomes possible.

---

## BUG-13 (P2) — `MessageHash` re-encodes magic length-prefix as raw byte instead of via CompactSize round-trip

**Severity:** P2 (correctness-equivalent but representation-divergent).
Core writes the magic via `HashWriter << MESSAGE_MAGIC`. Operator `<<`
for a `std::string` calls `Serialize(stream, const std::string&)`,
which writes:

```cpp
WriteCompactSize(s, str.size());   // 1 byte for 24
s.write(MakeUCharSpan(str));        // 24 bytes
```

Core re-derives `CompactSize(24) = 0x18` at hash-time from the string
length, which would naturally extend if Core ever changed `MESSAGE_MAGIC`
(it doesn't, but it would).

rustoshi hardcodes the prefix byte AS PART OF THE MAGIC CONSTANT:

```rust
pub const BITCOIN_SIGNED_MESSAGE_MAGIC: &[u8] = b"\x18Bitcoin Signed Message:\n";
```

— the leading `\x18` is the compact-size of 24 baked into the literal.

Bit-for-bit identical hash output, but the magic constant exposed in
the public API (`crates/crypto/src/lib.rs:35`) **silently includes
the length byte**. A consumer who does
`buf.extend_from_slice(BITCOIN_SIGNED_MESSAGE_MAGIC); buf.extend_from_slice(message);`
without invoking `signed_message_hash` would compute a hash with a
DOUBLE length prefix (one from the constant, one they think they need
to add).

**File:** `crates/crypto/src/keys.rs:16-18`;
`crates/crypto/src/lib.rs:35` (re-export).

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:24,73-79` —
magic is 24 bytes, length is derived at serialize time.

**Impact:** API trap; one bad cross-impl recipe. Not a divergence in
output, just a divergence in the **shape of the publicly exposed
primitive**.

---

## BUG-14 (P2) — `signmessage` constants hardcoded `-18`; should use named constant

**Severity:** P2 (already flagged as W125 BUG-25 P3; restated here for
W158 completeness).

`crates/rpc/src/server.rs:7416`:

```rust
Err(Self::rpc_error(
    -18, // RPC_WALLET_NOT_FOUND, matches Core's "no wallet" surface.
    ...
))
```

The constant `wallet_error::RPC_WALLET_NOT_FOUND` is defined at
`crates/rpc/src/wallet.rs:47`. Using the literal `-18` instead is a
maintenance hazard: future refactor that changes the constant doesn't
propagate to this hardcoded site.

**File:** `crates/rpc/src/server.rs:7416`.

**Core ref:** `bitcoin-core/src/rpc/protocol.h::RPC_WALLET_NOT_FOUND`.

**Impact:** maintenance hazard; flagged.

---

## BUG-15 (P2) — `parse_signing_privkey` accepts WIF version byte for ANY network without validation

**Severity:** P2. `parse_signing_privkey` at
`crates/rpc/src/server.rs:9665-9686`:

```rust
let data = base58check_decode(input).map_err(|e| format!("Invalid WIF: {}", e))?;
if data.is_empty() { return Err("Empty WIF payload".to_string()); }
// First byte is the version (0x80 mainnet, 0xef testnet/regtest).
let payload = &data[1..];
```

The comment annotates `0x80 mainnet, 0xef testnet/regtest`, but the
code does NOT validate that the version byte matches the configured
network. A mainnet WIF (`0x80`) accepted on a regtest server signs
with the operator-supplied key — which is correct cryptographically,
but Core's `DecodeSecret` validates against the active chainparams
and rejects cross-network WIF (`key_io.cpp::DecodeSecret` uses
`PREFIXES[CChainParams::SECRET_KEY]`).

This means a slip-up where a mainnet WIF is fed to a testnet rustoshi
to "test the flow" gets a valid signature back, while the same call
to Core would error out. Operator slips a mainnet key into a debug
session and signs.

**File:** `crates/rpc/src/server.rs:9669-9670`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeSecret`.

**Impact:** operator-safety divergence. Cross-network WIF acceptance
makes a class of leak-by-accident possible that Core forbids.

---

## BUG-16 (P2) — No equivalent of Core's `SigningResult` enum (PRIVATE_KEY_NOT_AVAILABLE vs SIGNING_FAILED)

**Severity:** P2. Bitcoin Core has a small enum
(`bitcoin-core/src/common/signmessage.h:43-47`):

```cpp
enum class SigningResult {
    OK,
    PRIVATE_KEY_NOT_AVAILABLE,
    SIGNING_FAILED,
};
```

… and a stringifier `SigningResultString()`. The wallet's
`SignMessage` returns this enum, and the RPC layer dispatches:

- `SIGNING_FAILED` → `RPC_INVALID_ADDRESS_OR_KEY`
- `PRIVATE_KEY_NOT_AVAILABLE` → `RPC_WALLET_ERROR` (-4)

rustoshi has no such enum. The single `Err(...)` at server.rs:7415
collapses every signmessage failure into `RPC_WALLET_NOT_FOUND` (-18).
After BUG-5 is fixed and wallet wiring lands, the rich error mapping
must be re-derived — and the audit trail (W125 BUG-25) shows the
current code already doesn't honour the distinction.

**File:** `crates/rpc/src/server.rs:7415-7419`.

**Core ref:** `bitcoin-core/src/common/signmessage.h:43-47`,
`bitcoin-core/src/common/signmessage.cpp:81-92`.

**Impact:** future-bug surface; refactoring debt.

---

## BUG-17 (P2) — `MessageVerificationResult` enum equivalent missing; `verify_message` collapses 4 outcomes into 2 RPC shapes

**Severity:** P2. Core's
`MessageVerificationResult` enum (`signmessage.h:23-41`) has 6 values:

- `ERR_INVALID_ADDRESS` → -5 / "Invalid address"
- `ERR_ADDRESS_NO_KEY` → -3 / "Address does not refer to key"
- `ERR_MALFORMED_SIGNATURE` → -3 / "Malformed base64 encoding"
- `ERR_PUBKEY_NOT_RECOVERED` → bool `false`
- `ERR_NOT_SIGNED` → bool `false`
- `OK` → bool `true`

rustoshi's `verify_message` (`crates/rpc/src/server.rs:7320-7377`)
inlines the dispatch instead of having an enum. The dispatch is
broadly correct EXCEPT for the BUG-4 code mismatch on malformed
base64. But the lack of a structured enum means future-bug surface
when ERR_PUBKEY_NOT_RECOVERED gains a distinct telemetry need
(operator dashboards that want to count "actually-bad-sigs" vs
"address-mismatch" can't, because rustoshi returns the same `Ok(false)`
for both).

**File:** `crates/rpc/src/server.rs:7320-7377`.

**Core ref:** `bitcoin-core/src/common/signmessage.h:23-41`.

**Impact:** telemetry gap; cosmetic refactor target.

---

## BUG-18 (P2) — Test coverage gap: no test for header bytes 27–34, no fuzz on base64

**Severity:** P2. `crates/crypto/src/keys.rs:307-362` has tests for:
- magic-hash assembly
- compressed sign/recover roundtrip
- uncompressed sign/recover roundtrip
- header rejection at 26 / 35

But NOT:
- recid > 1 (only 0 and 1 ever observed in non-adversarial signing;
  recids 2 and 3 are valid but only fire when r-value exceeds curve
  order, ~1/2³² probability)
- specific header bytes 28, 29, 30, 32, 33 (each combination of
  compressed flag × recid)
- malformed base64 that decodes to a 64-byte or 66-byte sig (boundary
  conditions)
- s-value of zero or n (invalid)
- pubkey at infinity recovery

`crates/rpc/src/server.rs:12298-12356` has ONE end-to-end test:
`signmessage_verifymessage_roundtrip_compressed`. No uncompressed
roundtrip, no taproot-bech32m rejection assertion, no
"different signer's address" mismatch test, no high-S signature test.

**File:** `crates/crypto/src/keys.rs:307-362`,
`crates/rpc/src/server.rs:12298-12356`.

**Core ref:** `bitcoin-core/src/test/key_tests.cpp`,
`bitcoin-core/src/test/util_tests.cpp::message_tests`.

**Impact:** coverage gap; fuzzer regression candidate.

---

## BUG-19 (P3) — Trim whitespace on `signature` but NOT on `address` or `message`

**Severity:** P3. `verify_message` at `crates/rpc/src/server.rs:7339`:

```rust
let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(signature.trim()) {
```

The `.trim()` accepts signatures with leading/trailing whitespace. But
the `address` parsing at line 7352 uses `&address` without `.trim()`,
and the `message.as_bytes()` at line 7367 includes any whitespace
verbatim.

Inconsistency:
- Core: `DecodeBase64` and `DecodeDestination` both reject leading/
  trailing whitespace — strict on all three inputs.
- rustoshi: lenient on signature, strict on address/message. A
  copy-pasted signature with a trailing `\n` works; a copy-pasted
  address with a trailing space does NOT.

**File:** `crates/rpc/src/server.rs:7339, 7352, 7367`.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:31, 40`.

**Impact:** UX inconsistency; not a divergence with operational
consequences.

---

## BUG-20 (P3) — Comment at server.rs:7411-7413 confesses the dead-wire and directs at `signmessagewithprivkey`

**Severity:** P3 (already implicit in BUG-5; flagged separately as a
fleet `comment-as-confession` pattern instance).

`crates/rpc/src/server.rs:7411-7413`:

```rust
// privkey-based signing — that fallback was the lying-RPC behaviour
// the audit flagged. Operators wanting to sign without a loaded
// wallet should call `signmessagewithprivkey` instead.
```

This is the **Nth distinct rustoshi `comment-as-confession`**
(cumulative tracking: W141 BUG-Z, W144 BUG-12, etc.) — the comment
explicitly directs operators away from `signmessage` toward a
different RPC. Combined with the error message at line 7417-7418
which carries the same redirect, the implementation is **honest**
about being broken (which is the "honest-refusal" pattern Core's
"lying RPC" audit at `_lying-rpc-cross-impl-2026-05-05.md`
celebrates) — but the user-facing impact (BUG-5) remains.

**File:** `crates/rpc/src/server.rs:7411-7418`.

**Impact:** documentation-of-bug rather than fix-of-bug. The
honest-refusal stance prevents silent corruption but doesn't restore
the feature.

---

## Summary

**Bug count:** 20 (BUG-1 through BUG-20).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-1, BUG-5, BUG-8, BUG-9)
- **P1:** 5 (BUG-2, BUG-3, BUG-4, BUG-6, BUG-11)
- **P2:** 9 (BUG-7, BUG-10, BUG-12, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18)
- **P3:** 2 (BUG-19, BUG-20)

Total: 4 + 5 + 9 + 2 = 20.

**Fleet patterns confirmed:**
- **"wiring-look-but-no-wire"** (BUG-5) — `signmessage` RPC accepts the
  call, parses the address, gates on PKH, then hard-aborts with -18
  because `RpcServerImpl` doesn't hold a `WalletManager`. The wallet
  helpers exist (`Wallet::private_key_for_pkh`) and are documented as
  the intended caller, but the wiring stops at the crate boundary.
- **"dead-helper-at-call-site"** (BUG-5 + BUG-11) — `private_key_for_pkh`
  and `private_key_for_address` are `pub fn`, doc-commented as
  signmessage primitives, even tested, but have zero non-test production
  signmessage callers.
- **"comment-as-confession"** (BUG-5, BUG-20) — Nth rustoshi instance;
  inline comment directs operators at a different RPC, documenting
  rather than fixing the dead code.
- **"BIP-322 standard absent"** (BUG-8 + BUG-9) — fleet-baseline check;
  given the W134/W135/W156 pattern of BIP-spec gaps, rustoshi here
  trails by ~2 years on signed-message standardisation.
- **"error-code-precedence flipped"** (BUG-3) — verifymessage parses
  signature before address; Core parses address before signature.
- **"stricter-than-Core rejection"** (BUG-6) — recover-message-pubkey
  rejects header byte > 34; Core masks. One of the rare safer-but-
  divergent cases.
- **"-32602 used where Core uses -3"** (BUG-4) — same shape as W125
  BUG-16; the verifymessage malformed-base64 path is one of the
  most-cited instances.
- **"compressed-flag-baked-into-magic constant"** (BUG-13) — the public
  `BITCOIN_SIGNED_MESSAGE_MAGIC` includes the 0x18 length byte, which
  is an API trap for callers that don't go through `signed_message_hash`.
- **"hex-accepted-where-Core-only-takes-WIF"** (BUG-1) — superset
  acceptance; rustoshi reports compressed=true for hex defaults, which
  silently mis-derives addresses for legacy uncompressed imports.
- **"cross-network-WIF-not-validated"** (BUG-15) — mainnet WIF accepted
  on regtest server; Core's `DecodeSecret` rejects via chainparams.

**Top three findings:**
1. **BUG-5 (P0-CDIV) — `signmessage` is functionally dead.** The
   wallet variant of `signmessage` unconditionally returns -18
   "RPC_WALLET_NOT_FOUND" regardless of loaded-wallet state, because
   `RpcServerImpl` does not hold a `WalletManager`. The wallet
   primitives (`Wallet::private_key_for_pkh` /
   `Wallet::private_key_for_address`) exist and are documented as the
   intended callees, but no caller wires them in. Operators must
   fall back to raw-key signing via `signmessagewithprivkey`. Combined
   with BUG-20 (comment-as-confession), the dead-wire is honest but
   unfixed.
2. **BUG-8 + BUG-9 (P0-CDIV cluster) — BIP-322 standard absent
   entirely.** Zero grep hits for any BIP-322 artefact (`bip322`,
   `to_spend`, `to_sign`, `BIP0322-signed-message`). Both Simple
   mode (witness-only base64 for P2WPKH/P2WSH/P2TR) and Full mode
   (complete `to_sign` tx for multi-input / script-path) are
   unimplemented. The `verifymessage` impl explicitly rejects all
   non-P2PKH addresses with `RPC_TYPE_ERROR`. Wallets shipping
   BIP-322-only signatures (Sparrow, Trezor, Ledger, mempool.space,
   Bitkit) cannot be verified against rustoshi.
3. **BUG-1 (P0-CDIV) — `signmessagewithprivkey` accepts 64-char hex
   private keys.** Core's `DecodeSecret` requires WIF base58check;
   rustoshi adds a non-Core hex acceptance path that defaults
   `compressed=true` unconditionally. A user importing an uncompressed
   key via hex gets compressed-address derivation back, and the
   resulting signature looks fine but does not verify against the
   uncompressed address the user expected. Silent interop divergence.
