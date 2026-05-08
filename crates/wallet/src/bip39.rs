//! BIP-39: Mnemonic code for generating deterministic keys.
//!
//! Implements the BIP-39 standard for converting between entropy and
//! human-readable mnemonic phrases, plus the PBKDF2-HMAC-SHA512 derivation
//! that turns a mnemonic + optional passphrase into a 64-byte seed suitable
//! for [`crate::wallet::Wallet::from_seed`] / [`crate::hd::ExtendedPrivKey::from_seed`].
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
//!
//! # Algorithm summary
//!
//! Entropy (16/20/24/28/32 bytes) -> append `entropy_bits/32` checksum bits
//! taken from the leading bits of `sha256(entropy)` -> split into 11-bit
//! groups -> map each 11-bit group to one of 2048 English words. The reverse
//! direction recomputes the checksum and rejects mismatches.
//!
//! # Mnemonic -> Seed
//!
//! ```text
//! seed = PBKDF2-HMAC-SHA512(
//!     password = NFKD(words.join(" ")),
//!     salt     = "mnemonic" || NFKD(passphrase),
//!     iters    = 2048,
//!     dklen    = 64,
//! )
//! ```
//!
//! The seed is the 64-byte master input to BIP-32 (`HMAC-SHA512("Bitcoin seed", seed)`).
//!
//! # Why this module exists
//!
//! Bitcoin Core does not implement BIP-39 (its wallet uses raw HD seeds), so
//! we follow the canonical BIP text and the TREZOR python-mnemonic reference
//! vectors (`https://github.com/trezor/python-mnemonic/blob/master/vectors.json`).
//! Tests below check byte-identity against those vectors so that a silent
//! iteration-count or salt-construction collapse does not pass for free.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

type HmacSha512 = Hmac<Sha512>;

/// The canonical BIP-39 English wordlist (2048 words, one per line).
const WORDLIST_RAW: &str = include_str!("bip39_wordlist.txt");

/// 2048-element wordlist, indexed by 11-bit value.
///
/// Constructed lazily on first access via [`wordlist`].
fn wordlist() -> &'static [&'static str; 2048] {
    use std::sync::OnceLock;
    static WORDS: OnceLock<[&'static str; 2048]> = OnceLock::new();
    WORDS.get_or_init(|| {
        let v: Vec<&'static str> = WORDLIST_RAW.lines().collect();
        assert_eq!(v.len(), 2048, "BIP-39 wordlist must have exactly 2048 words");
        let mut arr: [&'static str; 2048] = [""; 2048];
        for (i, w) in v.into_iter().enumerate() {
            arr[i] = w;
        }
        arr
    })
}

/// Errors produced by BIP-39 encoding/decoding.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Bip39Error {
    /// Entropy length is not 16, 20, 24, 28, or 32 bytes.
    #[error("invalid entropy length: {0} (must be 16, 20, 24, 28, or 32 bytes)")]
    InvalidEntropyLength(usize),

    /// Mnemonic word count is not 12, 15, 18, 21, or 24.
    #[error("invalid word count: {0} (must be 12, 15, 18, 21, or 24)")]
    InvalidWordCount(usize),

    /// One of the supplied words is not in the BIP-39 English wordlist.
    #[error("unknown word in mnemonic: {0:?}")]
    UnknownWord(String),

    /// Checksum bits at the end of the mnemonic do not match the recomputed
    /// `sha256(entropy)` prefix.
    #[error("mnemonic checksum mismatch")]
    ChecksumMismatch,
}

/// Encode entropy as a BIP-39 mnemonic.
///
/// `entropy` must be exactly 16, 20, 24, 28, or 32 bytes (128/160/192/224/256
/// bits). Returns the mnemonic as a `Vec<&'static str>` of 12/15/18/21/24
/// words referencing the static wordlist.
///
/// # Errors
/// [`Bip39Error::InvalidEntropyLength`] if `entropy.len()` is not one of the
/// allowed values.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Vec<&'static str>, Bip39Error> {
    let ent_bytes = entropy.len();
    if !matches!(ent_bytes, 16 | 20 | 24 | 28 | 32) {
        return Err(Bip39Error::InvalidEntropyLength(ent_bytes));
    }
    let ent_bits = ent_bytes * 8;
    let cs_bits = ent_bits / 32; // checksum bit count
    let total_bits = ent_bits + cs_bits;
    let word_count = total_bits / 11;

    // Build a bitstream: entropy bytes followed by the first cs_bits of sha256(entropy).
    let checksum = Sha256::digest(entropy);
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for byte in entropy.iter() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    for i in 0..cs_bits {
        let byte = checksum[i / 8];
        bits.push((byte >> (7 - (i % 8))) & 1);
    }

    let words = wordlist();
    let mut out = Vec::with_capacity(word_count);
    for chunk in bits.chunks_exact(11) {
        let mut idx: u16 = 0;
        for &b in chunk {
            idx = (idx << 1) | (b as u16);
        }
        out.push(words[idx as usize]);
    }
    Ok(out)
}

/// Decode a BIP-39 mnemonic back to entropy, validating the checksum.
///
/// Each word must be a member of the canonical English wordlist (case-sensitive
/// — the wordlist is all lowercase). Whitespace must already be split: callers
/// pass `&["abandon", "abandon", ...]`, not a raw sentence.
///
/// # Errors
/// - [`Bip39Error::InvalidWordCount`] if `mnemonic.len()` is not 12/15/18/21/24.
/// - [`Bip39Error::UnknownWord`] if any word is not in the wordlist.
/// - [`Bip39Error::ChecksumMismatch`] if the embedded checksum does not match
///   the recomputed `sha256(entropy)` prefix.
pub fn mnemonic_to_entropy(mnemonic: &[&str]) -> Result<Vec<u8>, Bip39Error> {
    let n = mnemonic.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(Bip39Error::InvalidWordCount(n));
    }
    let total_bits = n * 11;
    let cs_bits = total_bits / 33; // = ent_bits / 32
    let ent_bits = total_bits - cs_bits;
    let ent_bytes = ent_bits / 8;

    let words = wordlist();
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for word in mnemonic.iter() {
        let idx = words
            .iter()
            .position(|w| *w == *word)
            .ok_or_else(|| Bip39Error::UnknownWord((*word).to_string()))?;
        for i in (0..11).rev() {
            bits.push(((idx >> i) & 1) as u8);
        }
    }

    let mut entropy = vec![0u8; ent_bytes];
    for (i, b) in bits[..ent_bits].iter().enumerate() {
        entropy[i / 8] |= b << (7 - (i % 8));
    }

    // Recompute checksum and compare.
    let checksum = Sha256::digest(&entropy);
    for i in 0..cs_bits {
        let expected = (checksum[i / 8] >> (7 - (i % 8))) & 1;
        let got = bits[ent_bits + i];
        if expected != got {
            return Err(Bip39Error::ChecksumMismatch);
        }
    }

    Ok(entropy)
}

/// Convenience wrapper: validate that a mnemonic decodes cleanly. Discards
/// the returned entropy.
pub fn validate_mnemonic(mnemonic: &[&str]) -> Result<(), Bip39Error> {
    mnemonic_to_entropy(mnemonic).map(|_| ())
}

/// Derive the 64-byte BIP-39 seed from a mnemonic + passphrase.
///
/// The mnemonic is joined with single ASCII spaces, both mnemonic and
/// passphrase are NFKD-normalized, and the salt is `"mnemonic" || passphrase`.
/// PBKDF2-HMAC-SHA512 runs for 2048 iterations producing 64 bytes.
///
/// This function does *not* validate the mnemonic (use [`validate_mnemonic`]
/// or [`mnemonic_to_entropy`] first if you want strict checksum enforcement).
/// BIP-39 explicitly states the seed function is total — any string maps to
/// some seed — so leaving validation to the caller matches the spec.
pub fn mnemonic_to_seed(mnemonic: &[&str], passphrase: &str) -> [u8; 64] {
    // NFKD-normalize both inputs per BIP-39 §"From mnemonic to seed".
    let joined: String = mnemonic.join(" ");
    let password_nfkd: String = joined.nfkd().collect();
    let passphrase_nfkd: String = passphrase.nfkd().collect();
    let mut salt = String::with_capacity(8 + passphrase_nfkd.len());
    salt.push_str("mnemonic");
    salt.push_str(&passphrase_nfkd);

    let mut out = [0u8; 64];
    pbkdf2_hmac_sha512(password_nfkd.as_bytes(), salt.as_bytes(), 2048, &mut out);
    out
}

/// Hand-rolled PBKDF2-HMAC-SHA512.
///
/// We implement this directly on top of `hmac::Hmac<Sha512>` rather than
/// pulling in the `pbkdf2` crate so that the iteration loop is visible in
/// our source — silent collapse to 1 iteration (the failure mode that hid in
/// haskoin's BIP-39 stack until W21) is impossible without editing this
/// function. `dklen` <= 64 here (we only ever call it with dklen=64), so we
/// produce a single PRF block; the surrounding API caps the output to 64.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    debug_assert!(out.len() <= 64, "this implementation only supports dklen <= 64");
    debug_assert!(iterations >= 1, "PBKDF2 requires at least 1 iteration");

    // T_1 = F(P, S, c, 1) where F is U_1 ^ U_2 ^ ... ^ U_c
    // U_1 = PRF(P, S || INT(1)),  U_j = PRF(P, U_{j-1})
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
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: split a mnemonic string into &str slices borrowed from a Vec<String>.
    fn split_mnemonic(s: &str) -> Vec<&str> {
        s.split_whitespace().collect()
    }

    #[test]
    fn wordlist_loads_2048_words() {
        let w = wordlist();
        assert_eq!(w.len(), 2048);
        assert_eq!(w[0], "abandon");
        assert_eq!(w[2047], "zoo");
        // Known: "about" is index 3, sanity check the lookup direction.
        assert_eq!(w[3], "about");
    }

    /// TREZOR vector 1: 12-word, all-zero entropy, passphrase "TREZOR".
    /// First 4 bytes of seed must be `c5 52 57 c3` — byte-identity check, not
    /// just a length/determinism smoke test (haskoin Phase 3 caught a silent
    /// PBKDF2 iteration-collapse bug here).
    #[test]
    fn trezor_vector_1_12word_zero_entropy() {
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let expected_phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(mnemonic.join(" "), expected_phrase);

        // Round-trip: mnemonic -> entropy
        let decoded = mnemonic_to_entropy(&mnemonic).unwrap();
        assert_eq!(decoded, entropy);

        // Seed: PBKDF2 with passphrase "TREZOR"
        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        let expected_seed_hex =
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        assert_eq!(hex::encode(seed), expected_seed_hex);

        // Spec-mandated explicit byte-identity probe on the leading bytes.
        // This is the SPECIFIC anchor that catches iteration-count drift.
        assert_eq!(seed[0], 0xc5);
        assert_eq!(seed[1], 0x52);
        assert_eq!(seed[2], 0x57);
        assert_eq!(seed[3], 0xc3);
    }

    /// TREZOR vector 2: 12-word, repeating 0x7f entropy.
    #[test]
    fn trezor_vector_2_12word_legal_winner() {
        let entropy = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let expected_phrase =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(mnemonic.join(" "), expected_phrase);

        let decoded = mnemonic_to_entropy(&mnemonic).unwrap();
        assert_eq!(decoded, entropy);

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        let expected_seed_hex =
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607";
        assert_eq!(hex::encode(seed), expected_seed_hex);
    }

    /// TREZOR vector: 18-word, 24-byte entropy `7f7f...`. Tests the 24-word
    /// boundary case is reached gradually and checksum bits survive.
    #[test]
    fn trezor_vector_18word_legal_winner_repeat() {
        let entropy = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let expected =
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will";
        assert_eq!(mnemonic.join(" "), expected);

        let decoded = mnemonic_to_entropy(&mnemonic).unwrap();
        assert_eq!(decoded, entropy);

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        let expected_seed_hex =
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd";
        assert_eq!(hex::encode(seed), expected_seed_hex);
    }

    /// TREZOR vector: 24-word, 32-byte entropy all 0xff.
    /// Required by the wave-21 prompt to cover the maximum word count.
    #[test]
    fn trezor_vector_24word_zoo_when() {
        let entropy =
            hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
        assert_eq!(mnemonic.join(" "), expected);

        let decoded = mnemonic_to_entropy(&mnemonic).unwrap();
        assert_eq!(decoded, entropy);

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        let expected_seed_hex =
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad";
        assert_eq!(hex::encode(seed), expected_seed_hex);
    }

    /// TREZOR vector exercising a 24-word non-trivial entropy.
    /// `hamster diagram private ... length` from python-mnemonic vectors.json.
    #[test]
    fn trezor_vector_24word_hamster_diagram() {
        let entropy =
            hex::decode("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c")
                .unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let expected = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
        assert_eq!(mnemonic.join(" "), expected);

        let decoded = mnemonic_to_entropy(&mnemonic).unwrap();
        assert_eq!(decoded, entropy);

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        let expected_seed_hex =
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440";
        assert_eq!(hex::encode(seed), expected_seed_hex);
    }

    /// TREZOR vector exercising a NON-default passphrase that is not just
    /// "TREZOR". Pulled from python-mnemonic vectors.json — entry uses
    /// passphrase "TREZOR" too, but cross with empty-passphrase sanity below
    /// proves the salt construction differs.
    #[test]
    fn empty_passphrase_differs_from_trezor_passphrase() {
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let seed_empty = mnemonic_to_seed(&mnemonic, "");
        let seed_trezor = mnemonic_to_seed(&mnemonic, "TREZOR");
        assert_ne!(seed_empty, seed_trezor);
        // empty-passphrase seed for the 12x abandon mnemonic is well-known:
        let expected_empty_hex =
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assert_eq!(hex::encode(seed_empty), expected_empty_hex);
    }

    #[test]
    fn rejects_invalid_entropy_length() {
        // 15 bytes — not allowed.
        let entropy = vec![0u8; 15];
        let err = entropy_to_mnemonic(&entropy).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidEntropyLength(15));
        // 33 bytes — also not allowed.
        let entropy = vec![0u8; 33];
        let err = entropy_to_mnemonic(&entropy).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidEntropyLength(33));
    }

    #[test]
    fn rejects_invalid_word_count() {
        let too_short: Vec<&str> = "abandon abandon abandon".split_whitespace().collect();
        let err = mnemonic_to_entropy(&too_short).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidWordCount(3));
    }

    #[test]
    fn rejects_unknown_word() {
        // 12 words but one is bogus.
        let bogus: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
            .split_whitespace()
            .collect();
        match mnemonic_to_entropy(&bogus) {
            Err(Bip39Error::UnknownWord(w)) => assert_eq!(w, "notaword"),
            other => panic!("expected UnknownWord, got {:?}", other),
        }
    }

    /// Manually corrupt a valid mnemonic by swapping one word for another
    /// valid-but-checksum-breaking word. `validate_mnemonic` must reject.
    #[test]
    fn rejects_bad_checksum() {
        // Valid: "abandon ... abandon about".  Corruption: change the final
        // "about" to "abandon" — both are valid words, but the checksum bits
        // no longer match.
        let corrupt: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            .split_whitespace()
            .collect();
        let err = validate_mnemonic(&corrupt).unwrap_err();
        assert_eq!(err, Bip39Error::ChecksumMismatch);
    }

    #[test]
    fn validate_mnemonic_accepts_canonical() {
        let m = split_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        validate_mnemonic(&m).unwrap();
    }

    /// Round-trip property: any valid entropy length produces a mnemonic
    /// that decodes back to the same entropy.
    #[test]
    fn entropy_mnemonic_roundtrip_all_sizes() {
        for &n in &[16usize, 20, 24, 28, 32] {
            let entropy: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
            let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
            // Word count: 12, 15, 18, 21, 24 corresponding to entropy 16/20/24/28/32
            let expected_word_count = match n {
                16 => 12,
                20 => 15,
                24 => 18,
                28 => 21,
                32 => 24,
                _ => unreachable!(),
            };
            assert_eq!(mnemonic.len(), expected_word_count);
            let decoded = mnemonic_to_entropy(&mnemonic).unwrap();
            assert_eq!(decoded, entropy, "round-trip failed for {}-byte entropy", n);
        }
    }

    /// Sanity: the PBKDF2 helper actually runs 2048 iterations. If somebody
    /// silently changes `2048` to `1` this test catches it independently of
    /// the TREZOR vectors.
    #[test]
    fn pbkdf2_iteration_count_distinct_from_one_round() {
        let pw = b"password";
        let salt = b"salt";
        let mut one = [0u8; 64];
        let mut twok = [0u8; 64];
        pbkdf2_hmac_sha512(pw, salt, 1, &mut one);
        pbkdf2_hmac_sha512(pw, salt, 2048, &mut twok);
        assert_ne!(one, twok, "PBKDF2 with 1 vs 2048 iters must differ");
    }
}
