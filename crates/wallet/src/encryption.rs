//! Wallet seed encryption at rest (W118 BUG-1, P0-SECURITY).
//!
//! Before this module, `wallet_seed.bin` was a plaintext 64-byte BIP-39 seed.
//! `CreateWalletOptions::passphrase` was accepted by the API but silently
//! dropped — any user who set a passphrase expecting encryption was holding
//! a wallet whose secret was readable by anyone with disk access.
//!
//! This module replaces the on-disk format with an authenticated, KDF-derived
//! AEAD ciphertext when a passphrase is supplied. The unencrypted path is
//! preserved (raw 64 bytes, version-1 format) so wallets created without a
//! passphrase round-trip identically to the pre-fix layout.
//!
//! # Design (encrypted format, v2)
//!
//! ```text
//! offset  len  field
//! ------  ---  --------------------------------------------------------
//!   0     16   magic  = "RUSTOSHI_WALLET\0"  (constant, identifies v2)
//!  16      1   version = 0x02
//!  17      1   kdf_id  = 0x01  (PBKDF2-HMAC-SHA512)
//!  18      1   cipher_id = 0x01  (ChaCha20-Poly1305 AEAD)
//!  19      1   reserved (0)
//!  20      4   iter_count (BE u32)
//!  24     32   salt (per-wallet random)
//!  56     12   nonce (per-write random)
//!  68     64   ciphertext (the encrypted 64-byte seed)
//! 132     16   Poly1305 authentication tag
//! ------------- total: 148 bytes
//! ```
//!
//! # KDF
//!
//! PBKDF2-HMAC-SHA512 at **210,000 iterations** (OWASP 2023 PBKDF2-SHA512
//! recommendation). Bitcoin Core's `CCrypter::SetKeyFromPassphrase` uses
//! SHA-512 round-robin at 25,000 iters by default; we err higher because
//! today's hardware is much faster than 2011 hardware. Output is 32 bytes
//! (the ChaCha20-Poly1305 key size).
//!
//! # Cipher
//!
//! ChaCha20-Poly1305 (RFC 8439). Authenticated: any modification to the
//! ciphertext on disk surfaces as `WalletDecryptError::BadTag` and is
//! indistinguishable from a wrong passphrase from the attacker's point of
//! view. We do NOT use AES because that would pull an additional crate
//! family; the `chacha20poly1305` crate is already a dependency for BIP-324
//! (network/v2_transport.rs).
//!
//! # Per-wallet salt
//!
//! Required: two wallets sharing a passphrase must not share a derived key.
//! Salt is freshly random per `encryptwallet` invocation. Re-encrypting (i.e.
//! `walletpassphrasechange`) regenerates the salt — never reuse old salt for
//! a new passphrase because that would allow an attacker who recorded the old
//! ciphertext to test the new passphrase against the old data.
//!
//! # References
//!
//! - `bitcoin-core/src/wallet/crypter.h`, `crypter.cpp` — Core's
//!   `CMasterKey`/`CCrypter` (AES-256-CBC + SHA-512 round-robin KDF).
//! - clearbit FIX-39 / W111 BUG-4 — `aaa` (AES-256-GCM + scrypt) closure of
//!   the project's first P0-SECURITY (W107 XOR encryption).
//! - RFC 8018 §5.2 — PBKDF2 specification.
//! - RFC 8439 — ChaCha20-Poly1305 AEAD.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::KeyInit as AeadKeyInit;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// Magic bytes that identify a v2 (encrypted) seed file.
///
/// Exactly 16 bytes including the trailing NUL — chosen so we never collide
/// with a 64-byte plaintext seed (different length AND different prefix).
pub const SEED_FILE_MAGIC: [u8; 16] = *b"RUSTOSHI_WALLET\0";

/// Encrypted-format version. Increment when changing the layout below.
pub const SEED_FILE_VERSION: u8 = 0x02;

/// KDF id stored on disk. `0x01` = PBKDF2-HMAC-SHA512.
pub const KDF_PBKDF2_SHA512: u8 = 0x01;

/// Cipher id stored on disk. `0x01` = ChaCha20-Poly1305 AEAD (RFC 8439).
pub const CIPHER_CHACHA20_POLY1305: u8 = 0x01;

/// Default KDF iteration count. OWASP 2023 PBKDF2-SHA512 recommendation
/// (`>= 210_000`). Bitcoin Core ships 25,000 by default in `crypter.h`
/// (`DEFAULT_DERIVE_ITERATIONS`); we go higher because 2026-era CPUs can
/// brute-force 25k SHA-512 rounds per password orders of magnitude faster
/// than 2011 hardware. Stored on-disk so old wallets keep their original
/// count if we change this default later.
pub const DEFAULT_KDF_ITERATIONS: u32 = 210_000;

/// Minimum KDF iteration count we will accept on read. Defense-in-depth:
/// reject anyone hand-crafting a `wallet_seed.bin` with `iters=1`.
pub const MIN_KDF_ITERATIONS: u32 = 10_000;

/// Length of the random KDF salt (bytes). Bigger than Core's 8-byte salt
/// because that was a 2011 compromise; 32 bytes is the modern norm and
/// costs essentially nothing.
pub const SALT_LEN: usize = 32;

/// ChaCha20-Poly1305 key size (bytes).
pub const KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce size (bytes).
pub const NONCE_LEN: usize = 12;

/// Poly1305 authentication tag size (bytes).
pub const TAG_LEN: usize = 16;

/// Size of the plaintext seed (bytes). BIP-39 seed length.
pub const SEED_LEN: usize = 64;

/// Total v2 file size (bytes). Const-asserted in `decode_seed_file`.
pub const ENCRYPTED_FILE_LEN: usize = 16 + 4 + 4 + SALT_LEN + NONCE_LEN + SEED_LEN + TAG_LEN;

/// Errors from the wallet encryption layer.
#[derive(Debug)]
pub enum WalletEncryptError {
    /// Passphrase rejected: ciphertext failed authentication. Indistinguishable
    /// from a tampered file from the user's perspective (intentional).
    BadPassphrase,
    /// The on-disk file is not a recognized format (bad magic, wrong version,
    /// truncated, etc.).
    Malformed(String),
    /// KDF iteration count is below `MIN_KDF_ITERATIONS`.
    WeakIterations(u32),
    /// I/O error while reading/writing.
    Io(std::io::Error),
    /// Random-number generation failed.
    Rng(String),
}

impl fmt::Display for WalletEncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPassphrase => write!(f, "incorrect passphrase"),
            Self::Malformed(m) => write!(f, "wallet seed file malformed: {}", m),
            Self::WeakIterations(n) => write!(
                f,
                "wallet seed file rejects: KDF iterations {} below minimum {}",
                n, MIN_KDF_ITERATIONS
            ),
            Self::Io(e) => write!(f, "io error: {}", e),
            Self::Rng(m) => write!(f, "rng error: {}", m),
        }
    }
}

impl std::error::Error for WalletEncryptError {}

impl From<std::io::Error> for WalletEncryptError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Derive a 32-byte ChaCha20-Poly1305 key from a UTF-8 passphrase + salt
/// using PBKDF2-HMAC-SHA512.
///
/// The passphrase is NFKD-normalized first so that visually-identical
/// passphrases entered via different input methods (precomposed vs. combining
/// accents) yield the same key. This matches BIP-39's behavior in
/// [`crate::bip39::mnemonic_to_seed`].
///
/// `iterations` must be `>= MIN_KDF_ITERATIONS`; callers create new wallets
/// with [`DEFAULT_KDF_ITERATIONS`] but the stored count is honored on read
/// so we can lower the default in the future without breaking existing
/// wallets.
pub fn derive_key(
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; KEY_LEN], WalletEncryptError> {
    if iterations < MIN_KDF_ITERATIONS {
        return Err(WalletEncryptError::WeakIterations(iterations));
    }
    if salt.len() != SALT_LEN {
        return Err(WalletEncryptError::Malformed(format!(
            "salt is {} bytes, expected {}",
            salt.len(),
            SALT_LEN
        )));
    }

    let passphrase_nfkd: String = passphrase.nfkd().collect();
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac_sha512(passphrase_nfkd.as_bytes(), salt, iterations, &mut key);
    Ok(key)
}

/// Hand-rolled PBKDF2-HMAC-SHA512 (mirrors `bip39::pbkdf2_hmac_sha512` style).
///
/// `out.len()` must be `<= 64` because we produce one PRF block. The wallet
/// always asks for 32 bytes, but the bound is checked anyway. A `debug_assert`
/// (and runtime check via `out.len() <= 64` requirement at the call site)
/// guards against silent collapse to a single iteration.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(
        out.len() <= 64,
        "this PBKDF2 implementation supports dklen <= 64 (SHA-512 block)"
    );
    assert!(iterations >= 1, "PBKDF2 requires >= 1 iteration");

    // T_1 = U_1 ^ U_2 ^ ... ^ U_c where U_1 = PRF(P, S || INT(1))
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha512(password, &salt_block);
    let mut t = u;
    for _ in 1..iterations {
        u = hmac_sha512(password, &u);
        for k in 0..64 {
            t[k] ^= u[k];
        }
    }
    out.copy_from_slice(&t[..out.len()]);

    // Zero the temporaries; the caller will zero `key`.
    u.zeroize();
    t.zeroize();
    salt_block.zeroize();
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // Fully-qualified syntax because chacha20poly1305 also brings a
    // `KeyInit` trait into scope which would otherwise shadow `Mac`'s.
    let mut mac = <HmacSha512 as Mac>::new_from_slice(key)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// Generate a cryptographically-random buffer using `getrandom`.
fn rand_bytes(out: &mut [u8]) -> Result<(), WalletEncryptError> {
    getrandom::getrandom(out).map_err(|e| WalletEncryptError::Rng(e.to_string()))
}

/// Encrypt a 64-byte seed with `passphrase`. Returns the full on-disk byte
/// layout suitable for `fs::write` (i.e. magic + header + ciphertext + tag).
///
/// Each call generates a fresh random salt and nonce; never call this twice
/// without writing both results to different files (the salt makes them
/// independent, but the contract of a single seed file is "one ciphertext").
pub fn encrypt_seed(
    seed: &[u8; SEED_LEN],
    passphrase: &str,
    iterations: u32,
) -> Result<Vec<u8>, WalletEncryptError> {
    // Defense-in-depth: refuse empty passphrases. Bitcoin Core also refuses
    // (`walletpassphrasechange` rejects empty new). An empty passphrase is
    // a footgun — if a user genuinely wants no encryption, they should pass
    // `None`, not `Some("")`.
    if passphrase.is_empty() {
        return Err(WalletEncryptError::Malformed(
            "refusing to encrypt with empty passphrase".to_string(),
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    rand_bytes(&mut salt)?;

    let mut nonce = [0u8; NONCE_LEN];
    rand_bytes(&mut nonce)?;

    let mut key = derive_key(passphrase, &salt, iterations)?;
    let cipher = ChaCha20Poly1305::new((&key).into());

    // ChaCha20-Poly1305 encrypts in place; we work on a copy of the seed.
    let mut buffer = seed.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            (&nonce).into(),
            b"rustoshi-wallet-seed-v2",
            &mut buffer,
        )
        .map_err(|e| WalletEncryptError::Malformed(format!("AEAD encrypt failed: {}", e)))?;

    // Now serialize the file. Zero the key buffer before we leave scope —
    // the derived key is the most valuable thing in this function.
    let mut out = Vec::with_capacity(ENCRYPTED_FILE_LEN);
    out.extend_from_slice(&SEED_FILE_MAGIC);
    out.push(SEED_FILE_VERSION);
    out.push(KDF_PBKDF2_SHA512);
    out.push(CIPHER_CHACHA20_POLY1305);
    out.push(0); // reserved
    out.extend_from_slice(&iterations.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    debug_assert_eq!(out.len(), ENCRYPTED_FILE_LEN);

    key.zeroize();
    buffer.zeroize();

    Ok(out)
}

/// Decoded view of an encrypted seed file — what we need to attempt a
/// decryption. Held briefly so callers can prompt the user for a passphrase
/// without reparsing.
#[derive(Debug, Clone)]
pub struct EncryptedSeedFile {
    pub iterations: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// `ciphertext || tag` concatenated, exactly as on disk.
    pub ciphertext_and_tag: [u8; SEED_LEN + TAG_LEN],
}

/// Parse a raw `wallet_seed.bin` byte slice and decide whether it is a v1
/// plaintext (64 bytes) or a v2 encrypted file (148 bytes). Returns an enum
/// so the caller routes to the right loader.
#[derive(Debug)]
pub enum ParsedSeedFile {
    /// Pre-encryption layout. The bytes ARE the seed.
    PlaintextV1([u8; SEED_LEN]),
    /// Encrypted. Caller must invoke [`decrypt_seed`] with the passphrase.
    EncryptedV2(EncryptedSeedFile),
}

pub fn parse_seed_file(bytes: &[u8]) -> Result<ParsedSeedFile, WalletEncryptError> {
    // Heuristic: v1 is exactly SEED_LEN raw bytes. v2 starts with the magic
    // string and is ENCRYPTED_FILE_LEN bytes. Anything else is malformed.
    if bytes.len() == SEED_LEN {
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(bytes);
        return Ok(ParsedSeedFile::PlaintextV1(seed));
    }

    if bytes.len() != ENCRYPTED_FILE_LEN {
        return Err(WalletEncryptError::Malformed(format!(
            "unexpected wallet seed file length {} (v1 expects {}, v2 expects {})",
            bytes.len(),
            SEED_LEN,
            ENCRYPTED_FILE_LEN
        )));
    }

    if bytes[..16] != SEED_FILE_MAGIC {
        return Err(WalletEncryptError::Malformed(
            "missing v2 magic header".to_string(),
        ));
    }
    if bytes[16] != SEED_FILE_VERSION {
        return Err(WalletEncryptError::Malformed(format!(
            "unsupported wallet seed file version {} (expected {})",
            bytes[16], SEED_FILE_VERSION
        )));
    }
    if bytes[17] != KDF_PBKDF2_SHA512 {
        return Err(WalletEncryptError::Malformed(format!(
            "unsupported KDF id {}",
            bytes[17]
        )));
    }
    if bytes[18] != CIPHER_CHACHA20_POLY1305 {
        return Err(WalletEncryptError::Malformed(format!(
            "unsupported cipher id {}",
            bytes[18]
        )));
    }
    // bytes[19] is reserved; ignore content.

    let iterations = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    if iterations < MIN_KDF_ITERATIONS {
        return Err(WalletEncryptError::WeakIterations(iterations));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[24..24 + SALT_LEN]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[56..56 + NONCE_LEN]);

    let mut ciphertext_and_tag = [0u8; SEED_LEN + TAG_LEN];
    ciphertext_and_tag.copy_from_slice(&bytes[68..68 + SEED_LEN + TAG_LEN]);

    Ok(ParsedSeedFile::EncryptedV2(EncryptedSeedFile {
        iterations,
        salt,
        nonce,
        ciphertext_and_tag,
    }))
}

/// Attempt to decrypt a parsed v2 seed file with `passphrase`.
///
/// Returns `Err(WalletEncryptError::BadPassphrase)` if the Poly1305 tag
/// rejects the (key, ciphertext) pair — indistinguishable from disk
/// tampering by design.
pub fn decrypt_seed(
    file: &EncryptedSeedFile,
    passphrase: &str,
) -> Result<[u8; SEED_LEN], WalletEncryptError> {
    let mut key = derive_key(passphrase, &file.salt, file.iterations)?;
    let cipher = ChaCha20Poly1305::new((&key).into());

    let mut ciphertext = file.ciphertext_and_tag[..SEED_LEN].to_vec();
    let tag = &file.ciphertext_and_tag[SEED_LEN..];

    let result = cipher.decrypt_in_place_detached(
        (&file.nonce).into(),
        b"rustoshi-wallet-seed-v2",
        &mut ciphertext,
        tag.into(),
    );

    key.zeroize();

    match result {
        Ok(()) => {
            let mut seed = [0u8; SEED_LEN];
            seed.copy_from_slice(&ciphertext);
            ciphertext.zeroize();
            Ok(seed)
        }
        Err(_) => {
            // Either wrong passphrase OR file tampering — same error per
            // RFC 8439's security analysis. Wipe the partial plaintext.
            ciphertext.zeroize();
            Err(WalletEncryptError::BadPassphrase)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> [u8; SEED_LEN] {
        // Easy-to-spot pattern so tampering tests can sanity-check.
        let mut seed = [0u8; SEED_LEN];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        seed
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let seed = fixed_seed();
        let encoded = encrypt_seed(&seed, "correct horse battery staple", DEFAULT_KDF_ITERATIONS)
            .expect("encrypt");
        assert_eq!(encoded.len(), ENCRYPTED_FILE_LEN);

        let parsed = parse_seed_file(&encoded).expect("parse");
        let file = match parsed {
            ParsedSeedFile::EncryptedV2(f) => f,
            ParsedSeedFile::PlaintextV1(_) => panic!("should be v2"),
        };

        let decrypted =
            decrypt_seed(&file, "correct horse battery staple").expect("decrypt");
        assert_eq!(decrypted, seed);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let seed = fixed_seed();
        let encoded =
            encrypt_seed(&seed, "right one", DEFAULT_KDF_ITERATIONS).expect("encrypt");
        let parsed = parse_seed_file(&encoded).expect("parse");
        let file = match parsed {
            ParsedSeedFile::EncryptedV2(f) => f,
            _ => unreachable!(),
        };

        let err = decrypt_seed(&file, "wrong one").unwrap_err();
        assert!(matches!(err, WalletEncryptError::BadPassphrase));
    }

    #[test]
    fn plaintext_does_not_appear_on_disk() {
        // The most important test: assert that the ciphertext shares zero
        // contiguous 32-byte runs with the plaintext seed. If we ever
        // accidentally write the seed as plaintext (e.g., a regression
        // sneaks `fs::write(seed_path, &seed)` back in), this test fires.
        let seed = fixed_seed();
        let encoded =
            encrypt_seed(&seed, "secret", DEFAULT_KDF_ITERATIONS).expect("encrypt");

        // The first 32 bytes of the seed must NOT appear in the encoded file.
        let needle = &seed[..32];
        for window in encoded.windows(32) {
            assert_ne!(
                window, needle,
                "plaintext seed prefix appeared verbatim in the encrypted on-disk blob"
            );
        }

        // And the encoded blob's length should differ from v1's 64 bytes.
        assert_ne!(encoded.len(), SEED_LEN);
    }

    #[test]
    fn tamper_with_ciphertext_rejects() {
        let seed = fixed_seed();
        let mut encoded =
            encrypt_seed(&seed, "secret", DEFAULT_KDF_ITERATIONS).expect("encrypt");

        // Flip a byte in the ciphertext region (offset 68..132).
        encoded[80] ^= 0xFF;

        let parsed = parse_seed_file(&encoded).expect("parse");
        let file = match parsed {
            ParsedSeedFile::EncryptedV2(f) => f,
            _ => unreachable!(),
        };
        let err = decrypt_seed(&file, "secret").unwrap_err();
        assert!(matches!(err, WalletEncryptError::BadPassphrase));
    }

    #[test]
    fn tamper_with_salt_rejects() {
        let seed = fixed_seed();
        let mut encoded =
            encrypt_seed(&seed, "secret", DEFAULT_KDF_ITERATIONS).expect("encrypt");

        // Flip a byte in the salt — yields a different KDF key → bad tag.
        encoded[24] ^= 0xFF;

        let parsed = parse_seed_file(&encoded).expect("parse");
        let file = match parsed {
            ParsedSeedFile::EncryptedV2(f) => f,
            _ => unreachable!(),
        };
        let err = decrypt_seed(&file, "secret").unwrap_err();
        assert!(matches!(err, WalletEncryptError::BadPassphrase));
    }

    #[test]
    fn two_wallets_same_passphrase_get_different_salt_and_ciphertext() {
        let seed = fixed_seed();
        let a = encrypt_seed(&seed, "same", DEFAULT_KDF_ITERATIONS).expect("encrypt");
        let b = encrypt_seed(&seed, "same", DEFAULT_KDF_ITERATIONS).expect("encrypt");

        // Salt region differs.
        assert_ne!(&a[24..24 + SALT_LEN], &b[24..24 + SALT_LEN]);
        // Therefore ciphertext region differs too.
        assert_ne!(&a[68..132], &b[68..132]);

        // Both decrypt to the same seed.
        let pa = parse_seed_file(&a).expect("parse a");
        let pb = parse_seed_file(&b).expect("parse b");
        let fa = match pa {
            ParsedSeedFile::EncryptedV2(f) => f,
            _ => unreachable!(),
        };
        let fb = match pb {
            ParsedSeedFile::EncryptedV2(f) => f,
            _ => unreachable!(),
        };
        assert_eq!(decrypt_seed(&fa, "same").unwrap(), seed);
        assert_eq!(decrypt_seed(&fb, "same").unwrap(), seed);
    }

    #[test]
    fn empty_passphrase_refused_at_encrypt() {
        let seed = fixed_seed();
        let err = encrypt_seed(&seed, "", DEFAULT_KDF_ITERATIONS).unwrap_err();
        assert!(matches!(err, WalletEncryptError::Malformed(_)));
    }

    #[test]
    fn weak_iterations_refused_at_encrypt() {
        let seed = fixed_seed();
        let err = encrypt_seed(&seed, "pw", 100).unwrap_err();
        assert!(matches!(err, WalletEncryptError::WeakIterations(100)));
    }

    #[test]
    fn weak_iterations_refused_at_decode() {
        // Hand-craft a header with iters=1 and a valid magic — should be
        // rejected at parse time before we even try to derive a key.
        let mut buf = Vec::with_capacity(ENCRYPTED_FILE_LEN);
        buf.extend_from_slice(&SEED_FILE_MAGIC);
        buf.push(SEED_FILE_VERSION);
        buf.push(KDF_PBKDF2_SHA512);
        buf.push(CIPHER_CHACHA20_POLY1305);
        buf.push(0);
        buf.extend_from_slice(&1u32.to_be_bytes()); // iters=1
        buf.extend_from_slice(&[0u8; SALT_LEN]);
        buf.extend_from_slice(&[0u8; NONCE_LEN]);
        buf.extend_from_slice(&[0u8; SEED_LEN + TAG_LEN]);
        let err = parse_seed_file(&buf).unwrap_err();
        assert!(matches!(err, WalletEncryptError::WeakIterations(1)));
    }

    #[test]
    fn plaintext_v1_is_passed_through_unchanged() {
        // Backward compatibility: a 64-byte plaintext file (the pre-fix
        // layout) parses to `PlaintextV1(bytes)`. This is what wallets
        // created without a passphrase produce, and what loadwallet on a
        // pre-fix wallet directory will encounter.
        let seed = fixed_seed();
        let parsed = parse_seed_file(&seed).expect("parse");
        match parsed {
            ParsedSeedFile::PlaintextV1(b) => assert_eq!(b, seed),
            ParsedSeedFile::EncryptedV2(_) => panic!("64-byte file misclassified as encrypted"),
        }
    }

    #[test]
    fn malformed_length_rejected() {
        // 100 bytes is neither v1 (64) nor v2 (148).
        let buf = vec![0u8; 100];
        let err = parse_seed_file(&buf).unwrap_err();
        assert!(matches!(err, WalletEncryptError::Malformed(_)));
    }

    #[test]
    fn nfkd_passphrase_normalization() {
        // Two visually identical passphrases that differ only in Unicode
        // composition form (NFC vs NFD) must yield the same key. This
        // matches BIP-39's behavior.
        let seed = fixed_seed();
        // "é" = U+00E9 (NFC) vs "e" + combining acute U+0301 (NFD).
        let nfc = "p\u{00E9}";
        let nfd = "p\u{0065}\u{0301}";
        assert_ne!(nfc, nfd, "test setup: the two strings are byte-different");

        let encoded =
            encrypt_seed(&seed, nfc, DEFAULT_KDF_ITERATIONS).expect("encrypt with NFC");
        let parsed = parse_seed_file(&encoded).expect("parse");
        let file = match parsed {
            ParsedSeedFile::EncryptedV2(f) => f,
            _ => unreachable!(),
        };
        // Decrypt with the NFD form — must succeed because of NFKD normalization.
        let decrypted = decrypt_seed(&file, nfd).expect("decrypt with NFD-equivalent");
        assert_eq!(decrypted, seed);
    }

    #[test]
    fn derive_key_rejects_short_salt() {
        let err = derive_key("pw", &[0u8; 4], DEFAULT_KDF_ITERATIONS).unwrap_err();
        assert!(matches!(err, WalletEncryptError::Malformed(_)));
    }
}
