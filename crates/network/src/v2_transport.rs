//! BIP324 v2 Transport Protocol
//!
//! Implements encrypted and authenticated P2P transport for Bitcoin.
//! Key features:
//! - ElligatorSwift encoding for public keys (censorship resistance)
//! - ECDH key exchange with ephemeral keys
//! - ChaCha20-Poly1305 AEAD encryption
//! - Forward-secure rekeying every 2^24 messages
//! - Short message IDs for bandwidth efficiency

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use lazy_static::lazy_static;
use rand::RngCore;
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use secp256k1::{All, Secp256k1, SecretKey};
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;

lazy_static! {
    /// Lazily-initialized full-capability secp256k1 context.
    ///
    /// `secp256k1` 0.28's `ElligatorSwift::new(seckey, rand)` invokes the C
    /// function `secp256k1_ellswift_create` with the static
    /// `context_no_precomp`, whose `ecmult_gen_ctx` is zero-initialized.
    /// The C implementation calls
    /// `ARG_CHECK(ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx))` (see
    /// `secp256k1-sys/.../modules/ellswift/main_impl.h:461`), which fires
    /// the illegal-argument callback (default: `abort()`) on the static
    /// context.  This was the panic blocking all 18 rustoshi pairs in the
    /// BIP324 interop matrix.
    ///
    /// The fix is to use `ElligatorSwift::from_seckey(&secp, sk, Some(rand))`
    /// with a context that actually has its signing-side (`ecmult_gen`)
    /// precomputation built.  `Secp256k1::new()` returns a `Secp256k1<All>`
    /// (created with `SECP256K1_START_SIGN | SECP256K1_START_VERIFY`),
    /// which has `ecmult_gen_ctx` built.  We cache it once and reuse for
    /// every handshake — building a context is expensive (it allocates and
    /// precomputes tables); the workspace already enables the `lowmemory`
    /// feature so the table is the smaller variant.
    static ref SECP_CTX: Secp256k1<All> = Secp256k1::new();
}

/// Errors that can occur during BIP324 operations.
#[derive(Debug, Error)]
pub enum Bip324Error {
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("cipher not initialized")]
    NotInitialized,
    #[error("invalid message length")]
    InvalidLength,
    #[error("handshake not complete")]
    HandshakeIncomplete,
    #[error("invalid garbage terminator")]
    InvalidGarbageTerminator,
    #[error("garbage too long")]
    GarbageTooLong,
    #[error("invalid message type")]
    InvalidMessageType,
}

/// Constants for BIP324.
pub mod constants {
    /// Length of session ID in bytes.
    pub const SESSION_ID_LEN: usize = 32;
    /// Length of garbage terminator in bytes.
    pub const GARBAGE_TERMINATOR_LEN: usize = 16;
    /// Rekey interval (2^24 operations, but BIP324 specifies 2^24 as the exponent).
    /// Note: Bitcoin Core uses 224 (0xE0) for testing, the spec says 2^24.
    /// We follow Bitcoin Core's constant for compatibility.
    pub const REKEY_INTERVAL: u32 = 224;
    /// Length of encrypted length field.
    pub const LENGTH_LEN: usize = 3;
    /// Length of header (ignore flag).
    pub const HEADER_LEN: usize = 1;
    /// Poly1305 tag length.
    pub const TAG_LEN: usize = 16;
    /// Total expansion when encrypting: LENGTH_LEN + HEADER_LEN + TAG_LEN.
    pub const EXPANSION: usize = LENGTH_LEN + HEADER_LEN + TAG_LEN;
    /// Ignore bit in header.
    pub const IGNORE_BIT: u8 = 0x80;
    /// Maximum garbage length.
    pub const MAX_GARBAGE_LEN: usize = 4095;
    /// ElligatorSwift public key length.
    pub const ELLSWIFT_PUBKEY_LEN: usize = 64;
    /// V1 prefix length for protocol detection.
    pub const V1_PREFIX_LEN: usize = 16;
    /// Maximum message contents length.
    pub const MAX_CONTENTS_LEN: usize = 1 + 12 + 4_000_000; // header + type + max payload
}

use constants::*;

/// Short message IDs as defined in BIP324.
/// Index 0 means long encoding (12 bytes follow).
const V2_MESSAGE_IDS: [&str; 33] = [
    "",           // 0: long encoding follows
    "addr",       // 1
    "block",      // 2
    "blocktxn",   // 3
    "cmpctblock", // 4
    "feefilter",  // 5
    "filteradd",  // 6
    "filterclear", // 7
    "filterload", // 8
    "getblocks",  // 9
    "getblocktxn", // 10
    "getdata",    // 11
    "getheaders", // 12
    "headers",    // 13
    "inv",        // 14
    "mempool",    // 15
    "merkleblock", // 16
    "notfound",   // 17
    "ping",       // 18
    "pong",       // 19
    "sendcmpct",  // 20
    "tx",         // 21
    "getcfilters", // 22
    "cfilter",    // 23
    "getcfheaders", // 24
    "cfheaders",  // 25
    "getcfcheckpt", // 26
    "cfcheckpt",  // 27
    "addrv2",     // 28
    "",           // 29: reserved
    "",           // 30: reserved
    "",           // 31: reserved
    "",           // 32: reserved
];

/// Map from message type string to short ID.
fn build_message_id_map() -> HashMap<&'static str, u8> {
    let mut map = HashMap::new();
    for (i, msg_type) in V2_MESSAGE_IDS.iter().enumerate().skip(1) {
        if !msg_type.is_empty() {
            map.insert(*msg_type, i as u8);
        }
    }
    map
}

lazy_static::lazy_static! {
    static ref V2_MESSAGE_MAP: HashMap<&'static str, u8> = build_message_id_map();
}

/// Get the short ID for a message type, if available.
pub fn get_short_id(message_type: &str) -> Option<u8> {
    V2_MESSAGE_MAP.get(message_type).copied()
}

/// Get the message type from a short ID.
pub fn get_message_type(short_id: u8) -> Option<&'static str> {
    if (short_id as usize) < V2_MESSAGE_IDS.len() {
        let msg = V2_MESSAGE_IDS[short_id as usize];
        if !msg.is_empty() {
            return Some(msg);
        }
    }
    None
}

/// The exact 12-byte v1 command field for a `version` message:
/// `b"version\0\0\0\0\0"`.  Used to disambiguate v1 from v2 on inbound.
pub const V1_VERSION_COMMAND: [u8; 12] = *b"version\0\0\0\0\0";

/// Classify the first 16 bytes of an inbound TCP stream.  Returns true
/// iff the bytes are the unambiguous start of a v1 VERSION message:
/// the network magic (4 bytes) followed by `"version\0\0\0\0\0"` (12
/// bytes).  In every other case (including a 64-byte ElligatorSwift
/// pubkey from a BIP-324 v2 initiator, since the magic match has
/// astronomically low probability for random bytes), returns false and
/// the caller should treat the stream as v2.
///
/// Bitcoin Core uses this exact heuristic — see BIP-324 §"Detecting
/// V1 vs V2".  The only downside is that v1 peers whose first message
/// is unexpectedly NOT `version` (a protocol violation) will be
/// misclassified as v2; the cipher handshake will fail and the peer
/// will be disconnected, which is fine.
pub fn looks_like_v1_version(bytes: &[u8], network_magic: &[u8; 4]) -> bool {
    if bytes.len() < V1_PREFIX_LEN {
        return false;
    }
    if &bytes[..4] != network_magic {
        return false;
    }
    bytes[4..16] == V1_VERSION_COMMAND
}

/// ElligatorSwift-encoded public key (64 bytes).
///
/// This encoding makes secp256k1 public keys indistinguishable from random bytes,
/// providing censorship resistance. Wraps the secp256k1 ElligatorSwift type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EllSwiftPubKey(pub [u8; ELLSWIFT_PUBKEY_LEN]);

impl EllSwiftPubKey {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Bip324Error> {
        if bytes.len() != ELLSWIFT_PUBKEY_LEN {
            return Err(Bip324Error::InvalidPublicKey);
        }
        let mut arr = [0u8; ELLSWIFT_PUBKEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; ELLSWIFT_PUBKEY_LEN] {
        &self.0
    }

    /// Convert to secp256k1's ElligatorSwift type.
    pub fn to_ellswift(&self) -> ElligatorSwift {
        ElligatorSwift::from_array(self.0)
    }

    /// Create from secp256k1's ElligatorSwift type.
    pub fn from_ellswift(es: ElligatorSwift) -> Self {
        Self(es.to_array())
    }
}

/// Generate an ElligatorSwift-encoded public key from a secret key.
///
/// The encoding uses 32 bytes of entropy to select one of the ~2^256 possible encodings.
///
/// Implementation note: We MUST use `ElligatorSwift::from_seckey(&secp, ...)`,
/// not `ElligatorSwift::new(...)`, because the latter calls the C function
/// with `secp256k1_context_no_precomp` (the static no-precomp context),
/// whose `ecmult_gen_ctx` is not built.  `secp256k1_ellswift_create` asserts
/// `ARG_CHECK(ecmult_gen_context_is_built)` and aborts via the default
/// illegal-argument callback when that assertion fails.  Using a context
/// constructed via `Secp256k1::new()` (which enables `SECP256K1_START_SIGN`)
/// satisfies that assertion.
pub fn ellswift_create(secret_key: &SecretKey, entropy: &[u8; 32]) -> EllSwiftPubKey {
    let es = ElligatorSwift::from_seckey(&*SECP_CTX, *secret_key, Some(*entropy));
    EllSwiftPubKey::from_ellswift(es)
}

/// Compute BIP324 ECDH shared secret.
///
/// This performs ECDH using ElligatorSwift-encoded public keys, producing a
/// 32-byte shared secret that is used to derive encryption keys.
///
/// The `initiator` flag determines the order of public keys in the XDH computation,
/// ensuring both parties derive the same secret.
pub fn compute_bip324_ecdh_secret(
    our_secret: &SecretKey,
    our_ellswift: &EllSwiftPubKey,
    their_ellswift: &EllSwiftPubKey,
    initiator: bool,
) -> [u8; 32] {
    // Convert to secp256k1's ElligatorSwift type
    let ours = our_ellswift.to_ellswift();
    let theirs = their_ellswift.to_ellswift();

    // Determine party based on initiator flag
    // Party A is the initiator, Party B is the responder
    // In shared_secret(), the first two args are (ell_a, ell_b) where A is initiator
    let (ell_a, ell_b, party) = if initiator {
        // We are the initiator (party A)
        (ours, theirs, ElligatorSwiftParty::A)
    } else {
        // We are the responder (party B)
        // Note: In ElligatorSwift::shared_secret, the first arg is always party A's pubkey
        (theirs, ours, ElligatorSwiftParty::B)
    };

    // Compute the BIP324 shared secret using the native implementation
    let shared = ElligatorSwift::shared_secret(ell_a, ell_b, *our_secret, party, None);
    shared.to_secret_bytes()
}

/// Forward-secure ChaCha20 stream cipher (BIP-324 length cipher).
///
/// Per BIP-324, the length cipher's keystream is CONTINUOUS within a rekey
/// epoch: each 3-byte length-prefix encryption consumes the next 3 bytes of
/// a single ChaCha20 keystream initialised at the start of the epoch.  The
/// per-epoch nonce is `[0, 0, 0, 0] || LE64(rekey_counter)` (constant within
/// an epoch), and the keystream is consumed monotonically.  After exactly
/// `rekey_interval` (= 224) `crypt()` calls, the next 32 bytes of keystream
/// become the new key, the rekey_counter increments, and the keystream
/// restarts at block 0 with the fresh epoch nonce.
///
/// A previous implementation built a fresh ChaCha20 cipher per `crypt()`
/// call with `chunk_counter` baked into the nonce — this produces a
/// different keystream for every packet starting at block 0, instead of
/// advancing through a single continuous stream.  The result diverges from
/// Bitcoin Core / ouroboros byte-for-byte starting at packet 2, silently
/// corrupting every encrypted length prefix beyond the first and breaking
/// real-peer interop.  See clearbit's identical fix in `cb04a1f`.
///
/// Reference:
/// - bitcoin-core/src/crypto/chacha20.cpp::FSChaCha20::Crypt (line 349)
///   — keeps a stateful `m_chacha20` and only re-seeks the nonce on rekey.
/// - ouroboros/src/ouroboros/transport_v2.py::FSChaCha20.crypt
///
/// Note: `FSChaCha20Poly1305` (the AEAD packet cipher) below is *not*
/// affected — it correctly builds a fresh AEAD per packet because each
/// AEAD packet uses a unique `(packet_counter, rekey_counter)` nonce, and
/// poly1305-key material is taken from block 0 with content from block 1+.
pub struct FSChaCha20 {
    /// Current epoch key.  Replaced on rekey.
    key: [u8; 32],
    /// Rekey threshold (number of `crypt()` calls per epoch).
    rekey_interval: u32,
    /// Number of `crypt()` calls so far in the current epoch.  Drives
    /// rekeying only — it does NOT participate in the nonce.
    chunk_counter: u32,
    /// Monotonic rekey counter.  Forms the high 8 bytes of the per-epoch
    /// nonce.  Bumped on rekey.
    rekey_counter: u64,
    /// Cached ChaCha20 keystream buffer for the current 64-byte block.
    /// Bytes are consumed from `[keystream_used..]`; when fully drained,
    /// `draw_block()` regenerates the next block of keystream from the
    /// stateful cipher.
    keystream_buf: [u8; 64],
    /// Number of bytes already consumed from `keystream_buf`.  Starts at
    /// 64 ("empty") so the first `crypt()` triggers a block draw.
    keystream_used: u8,
    /// Stateful ChaCha20 cipher for the current epoch.  Rebuilt on rekey
    /// with the fresh epoch key + epoch nonce (chunk counter starts at 0).
    /// We use `Option` because the cipher is rebuilt on rekey and lazily
    /// initialised on first use.
    cipher: Option<ChaCha20>,
}

impl FSChaCha20 {
    /// Create a new FSChaCha20 cipher.  The cipher state is initialised
    /// lazily on first `crypt()` call with epoch nonce
    /// `[0,0,0,0] || LE64(0)`.
    pub fn new(key: [u8; 32], rekey_interval: u32) -> Self {
        Self {
            key,
            rekey_interval,
            chunk_counter: 0,
            rekey_counter: 0,
            keystream_buf: [0u8; 64],
            keystream_used: 64, // start "empty" so first crypt draws a block
            cipher: None,
        }
    }

    /// Build the per-epoch nonce: `[0, 0, 0, 0] || LE64(rekey_counter)`.
    /// Constant within an epoch; bumped only on rekey.
    fn epoch_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        // First 4 bytes: zero (BIP-324 length-cipher convention).
        // Last 8 bytes: rekey_counter little-endian.
        nonce[4..12].copy_from_slice(&self.rekey_counter.to_le_bytes());
        nonce
    }

    /// Pull `out.len()` bytes of keystream into `out`, advancing the
    /// stateful cipher across as many 64-byte blocks as needed.
    fn draw_keystream(&mut self, out: &mut [u8]) {
        let mut written = 0usize;
        while written < out.len() {
            if self.keystream_used as usize >= 64 {
                // Refill: generate next 64 bytes of keystream from the
                // stateful epoch cipher.  This advances the cipher's
                // internal block counter by 1.
                self.refill_block();
            }
            let avail = 64 - self.keystream_used as usize;
            let need = out.len() - written;
            let take = avail.min(need);
            out[written..written + take].copy_from_slice(
                &self.keystream_buf[self.keystream_used as usize
                    ..self.keystream_used as usize + take],
            );
            self.keystream_used += take as u8;
            written += take;
        }
    }

    /// Refill `keystream_buf` with the next 64-byte ChaCha20 block from
    /// the stateful epoch cipher.  Initialises the cipher on first use.
    fn refill_block(&mut self) {
        if self.cipher.is_none() {
            let nonce = self.epoch_nonce();
            self.cipher = Some(ChaCha20::new((&self.key).into(), (&nonce).into()));
        }
        let cipher = self.cipher.as_mut().unwrap();
        // XOR a 64-byte zero block to extract the next 64 bytes of
        // keystream.  apply_keystream advances the cipher's internal
        // block counter, giving us continuous keystream within the epoch.
        self.keystream_buf = [0u8; 64];
        cipher.apply_keystream(&mut self.keystream_buf);
        self.keystream_used = 0;
    }

    /// Encrypt or decrypt data.  Each call consumes `input.len()` bytes
    /// from the current epoch's continuous keystream.  After
    /// `rekey_interval` calls, transparently rotates to a new key.
    pub fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());

        // Draw keystream into output, then XOR with input.
        self.draw_keystream(output);
        for (o, i) in output.iter_mut().zip(input.iter()) {
            *o ^= *i;
        }

        // Update chunk counter and possibly rekey.
        self.chunk_counter += 1;
        if self.chunk_counter == self.rekey_interval {
            self.rekey();
        }
    }

    /// Rotate to a new epoch.  Per BIP-324, the new key is the next 32
    /// bytes of keystream (block 7, 8, ... in the OLD epoch's keystream
    /// — but this differs from Bitcoin Core, which simply reads the next
    /// 32 bytes from the internal cipher state).  We follow Bitcoin
    /// Core's stateful model: pull 32 bytes from the *current* cipher's
    /// position as the new key, then advance the rekey counter and reset
    /// the cipher with the new epoch nonce.
    fn rekey(&mut self) {
        // Pull next 32 bytes of keystream as the new key (continuing the
        // current epoch's stream).
        let mut new_key = [0u8; 32];
        self.draw_keystream(&mut new_key);

        // Advance to new epoch.
        self.key = new_key;
        self.rekey_counter += 1;
        self.chunk_counter = 0;
        // Force fresh cipher init with new key + new epoch nonce on the
        // next draw.
        self.cipher = None;
        self.keystream_buf = [0u8; 64];
        self.keystream_used = 64;
    }
}

/// Forward-secure ChaCha20-Poly1305 AEAD.
///
/// Provides authenticated encryption with automatic rekeying for forward secrecy.
pub struct FSChaCha20Poly1305 {
    key: [u8; 32],
    rekey_interval: u32,
    packet_counter: u32,
    rekey_counter: u64,
}

impl FSChaCha20Poly1305 {
    /// Create a new FSChaCha20Poly1305 cipher.
    pub fn new(key: [u8; 32], rekey_interval: u32) -> Self {
        Self {
            key,
            rekey_interval,
            packet_counter: 0,
            rekey_counter: 0,
        }
    }

    /// Construct nonce from current counters.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.packet_counter.to_le_bytes());
        nonce[4..12].copy_from_slice(&self.rekey_counter.to_le_bytes());
        nonce
    }

    /// Encrypt with AEAD.
    ///
    /// `plain1` and `plain2` are concatenated as plaintext.
    /// `aad` is authenticated but not encrypted.
    /// `output` must have size = plain1.len() + plain2.len() + TAG_LEN.
    pub fn encrypt(&mut self, plain1: &[u8], plain2: &[u8], aad: &[u8], output: &mut [u8]) {
        assert_eq!(output.len(), plain1.len() + plain2.len() + TAG_LEN);

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = self.nonce();

        // Copy plaintext to output buffer
        output[..plain1.len()].copy_from_slice(plain1);
        output[plain1.len()..plain1.len() + plain2.len()].copy_from_slice(plain2);

        // Encrypt in place and append tag
        let tag = cipher
            .encrypt_in_place_detached(
                (&nonce).into(),
                aad,
                &mut output[..plain1.len() + plain2.len()],
            )
            .expect("encryption should not fail");

        output[plain1.len() + plain2.len()..].copy_from_slice(&tag);

        self.next_packet();
    }

    /// Decrypt with AEAD.
    ///
    /// Returns false if authentication fails.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        plain1: &mut [u8],
        plain2: &mut [u8],
    ) -> bool {
        if ciphertext.len() < TAG_LEN {
            return false;
        }

        let expected_plain_len = ciphertext.len() - TAG_LEN;
        if plain1.len() + plain2.len() != expected_plain_len {
            return false;
        }

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = self.nonce();

        // Split ciphertext into data and tag
        let (data, tag) = ciphertext.split_at(expected_plain_len);

        // Copy to output buffers
        plain1.copy_from_slice(&data[..plain1.len()]);
        plain2.copy_from_slice(&data[plain1.len()..]);

        // Create combined buffer for decryption
        let mut combined = vec![0u8; expected_plain_len];
        combined.copy_from_slice(data);

        // Decrypt in place
        let result = cipher.decrypt_in_place_detached(
            (&nonce).into(),
            aad,
            &mut combined,
            tag.into(),
        );

        if result.is_ok() {
            plain1.copy_from_slice(&combined[..plain1.len()]);
            plain2.copy_from_slice(&combined[plain1.len()..]);
            self.next_packet();
            true
        } else {
            false
        }
    }

    fn next_packet(&mut self) {
        self.packet_counter += 1;
        if self.packet_counter == self.rekey_interval {
            self.rekey();
        }
    }

    fn rekey(&mut self) {
        // Generate keystream with special nonce for rekeying
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        nonce[4..12].copy_from_slice(&self.rekey_counter.to_le_bytes());

        // Use ChaCha20 directly to generate keystream
        let mut cipher = ChaCha20::new((&self.key).into(), (&nonce).into());
        // Seek to block 1 (skip the Poly1305 key block)
        cipher.seek(64u32);

        let mut new_key = [0u8; 32];
        cipher.apply_keystream(&mut new_key);

        self.key = new_key;
        self.packet_counter = 0;
        self.rekey_counter += 1;
    }
}

/// BIP324 cipher for packet encryption/decryption.
///
/// Handles the full encryption lifecycle including key derivation from ECDH.
pub struct Bip324Cipher {
    /// Our secret key (cleared after initialization).
    secret_key: Option<SecretKey>,
    /// Our ElligatorSwift public key.
    our_pubkey: EllSwiftPubKey,
    /// Session ID (available after initialization).
    session_id: [u8; SESSION_ID_LEN],
    /// Send garbage terminator.
    send_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    /// Receive garbage terminator.
    recv_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    /// Send length cipher.
    send_l_cipher: Option<FSChaCha20>,
    /// Receive length cipher.
    recv_l_cipher: Option<FSChaCha20>,
    /// Send payload cipher.
    send_p_cipher: Option<FSChaCha20Poly1305>,
    /// Receive payload cipher.
    recv_p_cipher: Option<FSChaCha20Poly1305>,
}

impl Bip324Cipher {
    /// Create a new cipher with a specified key and entropy.
    ///
    /// The entropy is used for ElligatorSwift encoding.
    pub fn new(secret_key: SecretKey, entropy: [u8; 32]) -> Self {
        let our_pubkey = ellswift_create(&secret_key, &entropy);

        Self {
            secret_key: Some(secret_key),
            our_pubkey,
            session_id: [0u8; SESSION_ID_LEN],
            send_garbage_terminator: [0u8; GARBAGE_TERMINATOR_LEN],
            recv_garbage_terminator: [0u8; GARBAGE_TERMINATOR_LEN],
            send_l_cipher: None,
            recv_l_cipher: None,
            send_p_cipher: None,
            recv_p_cipher: None,
        }
    }

    /// Create a new cipher with a specified key and pre-computed pubkey (for testing).
    pub fn new_with_pubkey(secret_key: SecretKey, pubkey: EllSwiftPubKey) -> Self {
        Self {
            secret_key: Some(secret_key),
            our_pubkey: pubkey,
            session_id: [0u8; SESSION_ID_LEN],
            send_garbage_terminator: [0u8; GARBAGE_TERMINATOR_LEN],
            recv_garbage_terminator: [0u8; GARBAGE_TERMINATOR_LEN],
            send_l_cipher: None,
            recv_l_cipher: None,
            send_p_cipher: None,
            recv_p_cipher: None,
        }
    }

    /// Create a new cipher with random keys.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        rng.fill_bytes(&mut entropy);

        let secret_key = SecretKey::from_slice(&secret_bytes).expect("valid key");
        Self::new(secret_key, entropy)
    }

    /// Build a pair of post-handshake `Bip324Cipher`s with arbitrary
    /// matching keys, bypassing ECDH/ElligatorSwift entirely.
    ///
    /// **Test-only.**  This is a convenience for unit tests that need
    /// to verify wire-framing (encrypt/decrypt round-trip, re-key
    /// boundary, byte-by-byte feed) without invoking secp256k1 — useful
    /// in environments where the global secp context is not available
    /// (e.g. some sandboxed test runners).  Real peers still go through
    /// `initialize_for_initiator` / `initialize_for_responder`.
    ///
    /// Returns `(initiator, responder)`: each has its `send_*` keyed
    /// with the same bytes as the other's `recv_*`, so anything one
    /// encrypts the other decrypts (and vice versa).
    #[cfg(test)]
    pub fn pair_for_test() -> (Self, Self) {
        // Distinct, deterministic keys for each direction so a swap
        // bug (e.g. forgetting to flip send/recv on the responder
        // side) would surface as a tag-mismatch rather than passing
        // by accident.
        let init_l = [0xA1u8; 32];
        let init_p = [0xA2u8; 32];
        let resp_l = [0xB1u8; 32];
        let resp_p = [0xB2u8; 32];
        let send_term_init = [0xC1u8; GARBAGE_TERMINATOR_LEN];
        let recv_term_init = [0xC2u8; GARBAGE_TERMINATOR_LEN];
        let session_id = [0xDDu8; SESSION_ID_LEN];

        let make = |send_l: [u8; 32],
                    send_p: [u8; 32],
                    recv_l: [u8; 32],
                    recv_p: [u8; 32],
                    send_term: [u8; GARBAGE_TERMINATOR_LEN],
                    recv_term: [u8; GARBAGE_TERMINATOR_LEN]|
         -> Self {
            Self {
                secret_key: None,
                our_pubkey: EllSwiftPubKey([0u8; ELLSWIFT_PUBKEY_LEN]),
                session_id,
                send_garbage_terminator: send_term,
                recv_garbage_terminator: recv_term,
                send_l_cipher: Some(FSChaCha20::new(send_l, REKEY_INTERVAL)),
                recv_l_cipher: Some(FSChaCha20::new(recv_l, REKEY_INTERVAL)),
                send_p_cipher: Some(FSChaCha20Poly1305::new(send_p, REKEY_INTERVAL)),
                recv_p_cipher: Some(FSChaCha20Poly1305::new(recv_p, REKEY_INTERVAL)),
            }
        };

        let initiator = make(
            init_l,
            init_p,
            resp_l,
            resp_p,
            send_term_init,
            recv_term_init,
        );
        let responder = make(
            resp_l,
            resp_p,
            init_l,
            init_p,
            recv_term_init,
            send_term_init,
        );
        (initiator, responder)
    }

    /// Get our ElligatorSwift public key.
    pub fn our_pubkey(&self) -> &EllSwiftPubKey {
        &self.our_pubkey
    }

    /// Check if the cipher is initialized.
    pub fn is_initialized(&self) -> bool {
        self.send_l_cipher.is_some()
    }

    /// Convenience wrapper: initialize this cipher in responder (server)
    /// mode after receiving the peer's ElligatorSwift pubkey.  Equivalent
    /// to `self.initialize(their_pubkey, false, network_magic)`.  Used by
    /// the inbound BIP-324 v2 wiring in `peer_manager::run_inbound_peer`.
    pub fn initialize_for_responder(
        &mut self,
        their_pubkey: &EllSwiftPubKey,
        network_magic: &[u8; 4],
    ) {
        self.initialize(their_pubkey, false, network_magic);
    }

    /// Convenience wrapper: initialize this cipher in initiator (client)
    /// mode after receiving the peer's ElligatorSwift pubkey.  Equivalent
    /// to `self.initialize(their_pubkey, true, network_magic)`.
    pub fn initialize_for_initiator(
        &mut self,
        their_pubkey: &EllSwiftPubKey,
        network_magic: &[u8; 4],
    ) {
        self.initialize(their_pubkey, true, network_magic);
    }

    /// Initialize the cipher with the peer's public key.
    ///
    /// `initiator` should be true if we initiated the connection.
    /// `self_decrypt` is for testing only - swaps send/recv ciphers.
    pub fn initialize(
        &mut self,
        their_pubkey: &EllSwiftPubKey,
        initiator: bool,
        network_magic: &[u8; 4],
    ) {
        self.initialize_internal(their_pubkey, initiator, false, network_magic);
    }

    /// Initialize with self-decrypt mode for testing.
    pub fn initialize_self_decrypt(
        &mut self,
        their_pubkey: &EllSwiftPubKey,
        initiator: bool,
        network_magic: &[u8; 4],
    ) {
        self.initialize_internal(their_pubkey, initiator, true, network_magic);
    }

    fn initialize_internal(
        &mut self,
        their_pubkey: &EllSwiftPubKey,
        initiator: bool,
        self_decrypt: bool,
        network_magic: &[u8; 4],
    ) {
        let secret_key = self.secret_key.take().expect("already initialized");

        // Compute ECDH shared secret
        let ecdh_secret = compute_bip324_ecdh_secret(
            &secret_key,
            &self.our_pubkey,
            their_pubkey,
            initiator,
        );

        // Derive keys using HKDF
        let mut salt = b"bitcoin_v2_shared_secret".to_vec();
        salt.extend_from_slice(network_magic);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ecdh_secret);

        // Derive cipher keys
        let mut initiator_l_key = [0u8; 32];
        let mut initiator_p_key = [0u8; 32];
        let mut responder_l_key = [0u8; 32];
        let mut responder_p_key = [0u8; 32];
        let mut garbage_terminators = [0u8; 32];

        hkdf.expand(b"initiator_L", &mut initiator_l_key).unwrap();
        hkdf.expand(b"initiator_P", &mut initiator_p_key).unwrap();
        hkdf.expand(b"responder_L", &mut responder_l_key).unwrap();
        hkdf.expand(b"responder_P", &mut responder_p_key).unwrap();
        hkdf.expand(b"garbage_terminators", &mut garbage_terminators).unwrap();
        hkdf.expand(b"session_id", &mut self.session_id).unwrap();

        // Assign ciphers based on role
        let side = initiator != self_decrypt;

        if side {
            self.send_l_cipher = Some(FSChaCha20::new(initiator_l_key, REKEY_INTERVAL));
            self.send_p_cipher = Some(FSChaCha20Poly1305::new(initiator_p_key, REKEY_INTERVAL));
            self.recv_l_cipher = Some(FSChaCha20::new(responder_l_key, REKEY_INTERVAL));
            self.recv_p_cipher = Some(FSChaCha20Poly1305::new(responder_p_key, REKEY_INTERVAL));
        } else {
            self.send_l_cipher = Some(FSChaCha20::new(responder_l_key, REKEY_INTERVAL));
            self.send_p_cipher = Some(FSChaCha20Poly1305::new(responder_p_key, REKEY_INTERVAL));
            self.recv_l_cipher = Some(FSChaCha20::new(initiator_l_key, REKEY_INTERVAL));
            self.recv_p_cipher = Some(FSChaCha20Poly1305::new(initiator_p_key, REKEY_INTERVAL));
        }

        // Assign garbage terminators
        if initiator {
            self.send_garbage_terminator.copy_from_slice(&garbage_terminators[..16]);
            self.recv_garbage_terminator.copy_from_slice(&garbage_terminators[16..]);
        } else {
            self.recv_garbage_terminator.copy_from_slice(&garbage_terminators[..16]);
            self.send_garbage_terminator.copy_from_slice(&garbage_terminators[16..]);
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Get the send garbage terminator.
    pub fn send_garbage_terminator(&self) -> &[u8; GARBAGE_TERMINATOR_LEN] {
        &self.send_garbage_terminator
    }

    /// Get the receive garbage terminator.
    pub fn recv_garbage_terminator(&self) -> &[u8; GARBAGE_TERMINATOR_LEN] {
        &self.recv_garbage_terminator
    }

    /// Encrypt a packet.
    ///
    /// `contents` is the plaintext to encrypt.
    /// `aad` is additional authenticated data.
    /// `ignore` sets the ignore bit in the header.
    /// `output` must have size = contents.len() + EXPANSION.
    pub fn encrypt(
        &mut self,
        contents: &[u8],
        aad: &[u8],
        ignore: bool,
        output: &mut [u8],
    ) -> Result<(), Bip324Error> {
        if !self.is_initialized() {
            return Err(Bip324Error::NotInitialized);
        }

        if output.len() != contents.len() + EXPANSION {
            return Err(Bip324Error::InvalidLength);
        }

        // Encrypt length
        let len = contents.len() as u32;
        let len_bytes = [
            (len & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            ((len >> 16) & 0xFF) as u8,
        ];

        let mut encrypted_len = [0u8; LENGTH_LEN];
        self.send_l_cipher
            .as_mut()
            .unwrap()
            .crypt(&len_bytes, &mut encrypted_len);
        output[..LENGTH_LEN].copy_from_slice(&encrypted_len);

        // Encrypt header + contents with AEAD
        let header = [if ignore { IGNORE_BIT } else { 0 }];
        self.send_p_cipher.as_mut().unwrap().encrypt(
            &header,
            contents,
            aad,
            &mut output[LENGTH_LEN..],
        );

        Ok(())
    }

    /// Decrypt the length field from an encrypted packet.
    ///
    /// Returns the plaintext length.
    pub fn decrypt_length(&mut self, input: &[u8; LENGTH_LEN]) -> Result<u32, Bip324Error> {
        if !self.is_initialized() {
            return Err(Bip324Error::NotInitialized);
        }

        let mut decrypted = [0u8; LENGTH_LEN];
        self.recv_l_cipher.as_mut().unwrap().crypt(input, &mut decrypted);

        let len = (decrypted[0] as u32)
            | ((decrypted[1] as u32) << 8)
            | ((decrypted[2] as u32) << 16);

        Ok(len)
    }

    /// Decrypt a packet (after decrypting the length).
    ///
    /// `input` is the ciphertext without the length field.
    /// `contents` must have size = input.len() - HEADER_LEN - TAG_LEN.
    /// Returns the ignore flag.
    pub fn decrypt(
        &mut self,
        input: &[u8],
        aad: &[u8],
        contents: &mut [u8],
    ) -> Result<bool, Bip324Error> {
        if !self.is_initialized() {
            return Err(Bip324Error::NotInitialized);
        }

        if input.len() < HEADER_LEN + TAG_LEN {
            return Err(Bip324Error::InvalidLength);
        }

        let expected_contents_len = input.len() - HEADER_LEN - TAG_LEN;
        if contents.len() != expected_contents_len {
            return Err(Bip324Error::InvalidLength);
        }

        let mut header = [0u8; HEADER_LEN];

        if !self.recv_p_cipher.as_mut().unwrap().decrypt(
            input,
            aad,
            &mut header,
            contents,
        ) {
            return Err(Bip324Error::AuthenticationFailed);
        }

        let ignore = (header[0] & IGNORE_BIT) == IGNORE_BIT;
        Ok(ignore)
    }
}

/// Receiver state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// (Responder only) Detecting V1 vs V2.
    KeyMaybeV1,
    /// Receiving peer's public key.
    Key,
    /// Receiving garbage and garbage terminator.
    GarbageGarbTerm,
    /// Receiving version packet.
    Version,
    /// Receiving application packets.
    App,
    /// Application packet ready for retrieval.
    AppReady,
    /// Fell back to V1.
    V1,
}

/// Sender state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// (Responder only) Not sending until V1 vs V2 detected.
    MaybeV1,
    /// Awaiting peer's public key.
    AwaitingKey,
    /// Ready to send encrypted messages.
    Ready,
    /// Fell back to V1.
    V1,
}

/// V2 transport implementing the BIP324 state machine.
pub struct V2Transport {
    /// Node ID for logging.
    #[allow(dead_code)]
    node_id: u64,
    /// Whether we initiated the connection.
    initiator: bool,
    /// Network magic bytes.
    network_magic: [u8; 4],
    /// The BIP324 cipher.
    cipher: Bip324Cipher,
    /// Garbage to send.
    send_garbage: Vec<u8>,
    /// Current receive state.
    recv_state: RecvState,
    /// Current send state.
    send_state: SendState,
    /// Receive buffer.
    recv_buffer: Vec<u8>,
    /// Send buffer.
    #[allow(dead_code)]
    send_buffer: Vec<u8>,
    /// Expected packet length (after decrypting length).
    recv_len: Option<u32>,
    /// AAD for next decryption (garbage bytes).
    recv_aad: Vec<u8>,
    /// Whether handshake is complete.
    handshake_complete: bool,
}

impl V2Transport {
    /// Create a new V2 transport.
    pub fn new(node_id: u64, initiator: bool, network_magic: [u8; 4]) -> Self {
        let cipher = Bip324Cipher::random();
        let mut send_garbage = vec![0u8; rand::thread_rng().gen_range(0..=MAX_GARBAGE_LEN)];
        rand::thread_rng().fill_bytes(&mut send_garbage);

        let recv_state = if initiator {
            RecvState::Key
        } else {
            RecvState::KeyMaybeV1
        };

        let send_state = if initiator {
            SendState::AwaitingKey
        } else {
            SendState::MaybeV1
        };

        Self {
            node_id,
            initiator,
            network_magic,
            cipher,
            send_garbage,
            recv_state,
            send_state,
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            recv_len: None,
            recv_aad: Vec::new(),
            handshake_complete: false,
        }
    }

    /// Create a V2 transport with specified key and garbage (for testing).
    pub fn new_with_params(
        node_id: u64,
        initiator: bool,
        network_magic: [u8; 4],
        secret_key: SecretKey,
        entropy: [u8; 32],
        garbage: Vec<u8>,
    ) -> Self {
        let cipher = Bip324Cipher::new(secret_key, entropy);

        let recv_state = if initiator {
            RecvState::Key
        } else {
            RecvState::KeyMaybeV1
        };

        let send_state = if initiator {
            SendState::AwaitingKey
        } else {
            SendState::MaybeV1
        };

        Self {
            node_id,
            initiator,
            network_magic,
            cipher,
            send_garbage: garbage,
            recv_state,
            send_state,
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            recv_len: None,
            recv_aad: Vec::new(),
            handshake_complete: false,
        }
    }

    /// Get our public key to send to the peer.
    pub fn our_pubkey(&self) -> &EllSwiftPubKey {
        self.cipher.our_pubkey()
    }

    /// Get the handshake bytes to send (pubkey + garbage).
    pub fn get_handshake_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ELLSWIFT_PUBKEY_LEN + self.send_garbage.len());
        bytes.extend_from_slice(self.cipher.our_pubkey().as_bytes());
        bytes.extend_from_slice(&self.send_garbage);
        bytes
    }

    /// Check if handshake is complete.
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Get the session ID (only valid after handshake).
    pub fn session_id(&self) -> Option<&[u8; SESSION_ID_LEN]> {
        if self.handshake_complete {
            Some(self.cipher.session_id())
        } else {
            None
        }
    }

    /// Check if this should fall back to V1.
    pub fn should_fallback_v1(&self) -> bool {
        matches!(self.recv_state, RecvState::V1)
    }

    /// Receive bytes from the network.
    ///
    /// Returns the number of bytes consumed and any complete message.
    pub fn receive_bytes(&mut self, data: &[u8]) -> Result<(usize, Option<ReceivedMessage>), Bip324Error> {
        let mut consumed = 0;

        while consumed < data.len() {
            match self.recv_state {
                RecvState::KeyMaybeV1 => {
                    // Check for V1 magic
                    let needed = V1_PREFIX_LEN - self.recv_buffer.len();
                    let available = data.len() - consumed;
                    let to_copy = needed.min(available);

                    self.recv_buffer.extend_from_slice(&data[consumed..consumed + to_copy]);
                    consumed += to_copy;

                    if self.recv_buffer.len() >= V1_PREFIX_LEN {
                        // Check if this looks like V1 (magic + "version\0\0\0\0\0")
                        if self.recv_buffer[..4] == self.network_magic {
                            // Looks like V1, fall back
                            self.recv_state = RecvState::V1;
                            self.send_state = SendState::V1;
                            return Ok((consumed, None));
                        } else {
                            // Looks like V2, continue receiving key
                            self.recv_state = RecvState::Key;
                            self.send_state = SendState::AwaitingKey;
                        }
                    }
                }

                RecvState::Key => {
                    let needed = ELLSWIFT_PUBKEY_LEN - self.recv_buffer.len();
                    let available = data.len() - consumed;
                    let to_copy = needed.min(available);

                    self.recv_buffer.extend_from_slice(&data[consumed..consumed + to_copy]);
                    consumed += to_copy;

                    if self.recv_buffer.len() >= ELLSWIFT_PUBKEY_LEN {
                        // Got the peer's public key
                        let their_pubkey = EllSwiftPubKey::from_bytes(&self.recv_buffer[..ELLSWIFT_PUBKEY_LEN])?;

                        // Initialize cipher
                        self.cipher.initialize(&their_pubkey, self.initiator, &self.network_magic);

                        // Start looking for garbage terminator
                        self.recv_buffer.clear();
                        self.recv_state = RecvState::GarbageGarbTerm;
                        self.send_state = SendState::Ready;
                    }
                }

                RecvState::GarbageGarbTerm => {
                    // Look for garbage terminator
                    let terminator = self.cipher.recv_garbage_terminator();

                    while consumed < data.len() {
                        self.recv_buffer.push(data[consumed]);
                        consumed += 1;

                        if self.recv_buffer.len() > MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN {
                            return Err(Bip324Error::GarbageTooLong);
                        }

                        // Check if buffer ends with terminator
                        if self.recv_buffer.len() >= GARBAGE_TERMINATOR_LEN {
                            let suffix = &self.recv_buffer[self.recv_buffer.len() - GARBAGE_TERMINATOR_LEN..];
                            if suffix == terminator {
                                // Found terminator, save garbage as AAD
                                let garbage_len = self.recv_buffer.len() - GARBAGE_TERMINATOR_LEN;
                                self.recv_aad = self.recv_buffer[..garbage_len].to_vec();
                                self.recv_buffer.clear();
                                self.recv_state = RecvState::Version;
                                break;
                            }
                        }
                    }
                }

                RecvState::Version | RecvState::App => {
                    // Receive encrypted packet
                    if self.recv_len.is_none() {
                        // Need to receive length
                        let needed = LENGTH_LEN - self.recv_buffer.len();
                        let available = data.len() - consumed;
                        let to_copy = needed.min(available);

                        self.recv_buffer.extend_from_slice(&data[consumed..consumed + to_copy]);
                        consumed += to_copy;

                        if self.recv_buffer.len() >= LENGTH_LEN {
                            let len_bytes: [u8; LENGTH_LEN] = self.recv_buffer[..LENGTH_LEN].try_into().unwrap();
                            self.recv_len = Some(self.cipher.decrypt_length(&len_bytes)?);
                            self.recv_buffer.clear();
                        }
                    }

                    if let Some(len) = self.recv_len {
                        // Need to receive header + payload + tag
                        let total_len = HEADER_LEN + len as usize + TAG_LEN;
                        let needed = total_len - self.recv_buffer.len();
                        let available = data.len() - consumed;
                        let to_copy = needed.min(available);

                        self.recv_buffer.extend_from_slice(&data[consumed..consumed + to_copy]);
                        consumed += to_copy;

                        if self.recv_buffer.len() >= total_len {
                            // Decrypt packet
                            let mut contents = vec![0u8; len as usize];
                            let aad: &[u8] = if matches!(self.recv_state, RecvState::Version) {
                                &self.recv_aad
                            } else {
                                &[]
                            };

                            let ignore = self.cipher.decrypt(&self.recv_buffer, aad, &mut contents)?;

                            self.recv_buffer.clear();
                            self.recv_len = None;

                            if matches!(self.recv_state, RecvState::Version) {
                                // Version packet received, transition to App
                                self.recv_aad.clear();
                                self.recv_state = RecvState::App;
                                self.handshake_complete = true;
                            } else {
                                // Application message
                                self.recv_state = RecvState::AppReady;
                                return Ok((consumed, Some(ReceivedMessage { contents, ignore })));
                            }
                        }
                    }
                }

                RecvState::AppReady => {
                    // Message ready, caller should retrieve it
                    self.recv_state = RecvState::App;
                }

                RecvState::V1 => {
                    // V1 mode, pass through
                    return Ok((consumed, None));
                }
            }
        }

        Ok((consumed, None))
    }

    /// Encrypt and queue a message for sending.
    pub fn send_message(
        &mut self,
        message_type: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, Bip324Error> {
        if !self.handshake_complete {
            return Err(Bip324Error::HandshakeIncomplete);
        }

        // Encode message type
        let contents = encode_message_type_and_payload(message_type, payload);

        // Encrypt
        let mut output = vec![0u8; contents.len() + EXPANSION];
        self.cipher.encrypt(&contents, &[], false, &mut output)?;

        Ok(output)
    }

    /// Get the garbage terminator to send after the handshake.
    pub fn get_garbage_terminator(&self) -> &[u8; GARBAGE_TERMINATOR_LEN] {
        self.cipher.send_garbage_terminator()
    }

    /// Create an encrypted version packet.
    pub fn create_version_packet(&mut self) -> Result<Vec<u8>, Bip324Error> {
        // Version packet has empty contents per BIP324
        let contents: &[u8] = &[];
        let aad = &self.send_garbage;

        let mut output = vec![0u8; contents.len() + EXPANSION];
        self.cipher.encrypt(contents, aad, false, &mut output)?;

        Ok(output)
    }
}

/// A received message.
#[derive(Debug)]
pub struct ReceivedMessage {
    /// The message contents (type + payload).
    pub contents: Vec<u8>,
    /// Whether the ignore flag was set.
    pub ignore: bool,
}

impl ReceivedMessage {
    /// Decode the message type and payload.
    pub fn decode(&self) -> Result<(String, Vec<u8>), Bip324Error> {
        decode_message_type_and_payload(&self.contents)
    }
}

/// Encode a message type and payload for V2 transport.
pub fn encode_message_type_and_payload(message_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(1 + payload.len());

    if let Some(short_id) = get_short_id(message_type) {
        // Use short encoding
        result.push(short_id);
    } else {
        // Use long encoding
        result.push(0);
        let mut type_bytes = [0u8; 12];
        let bytes = message_type.as_bytes();
        let len = bytes.len().min(12);
        type_bytes[..len].copy_from_slice(&bytes[..len]);
        result.extend_from_slice(&type_bytes);
    }

    result.extend_from_slice(payload);
    result
}

/// Decode a message type and payload from V2 transport contents.
pub fn decode_message_type_and_payload(contents: &[u8]) -> Result<(String, Vec<u8>), Bip324Error> {
    if contents.is_empty() {
        return Err(Bip324Error::InvalidMessageType);
    }

    let first_byte = contents[0];

    if first_byte != 0 {
        // Short encoding
        if let Some(msg_type) = get_message_type(first_byte) {
            Ok((msg_type.to_string(), contents[1..].to_vec()))
        } else {
            Err(Bip324Error::InvalidMessageType)
        }
    } else {
        // Long encoding
        if contents.len() < 13 {
            return Err(Bip324Error::InvalidMessageType);
        }

        let type_bytes = &contents[1..13];
        let end = type_bytes.iter().position(|&b| b == 0).unwrap_or(12);
        let msg_type = String::from_utf8_lossy(&type_bytes[..end]).to_string();

        Ok((msg_type, contents[13..].to_vec()))
    }
}

/// Generate random garbage bytes for the handshake.
pub fn generate_garbage() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(0..=MAX_GARBAGE_LEN);
    let mut garbage = vec![0u8; len];
    rng.fill_bytes(&mut garbage);
    garbage
}

use rand::Rng;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_message_ids() {
        assert_eq!(get_short_id("addr"), Some(1));
        assert_eq!(get_short_id("block"), Some(2));
        assert_eq!(get_short_id("ping"), Some(18));
        assert_eq!(get_short_id("pong"), Some(19));
        assert_eq!(get_short_id("tx"), Some(21));
        assert_eq!(get_short_id("unknown"), None);

        assert_eq!(get_message_type(1), Some("addr"));
        assert_eq!(get_message_type(2), Some("block"));
        assert_eq!(get_message_type(18), Some("ping"));
        assert_eq!(get_message_type(0), None);
        assert_eq!(get_message_type(100), None);
    }

    #[test]
    fn test_message_encoding_short() {
        let encoded = encode_message_type_and_payload("ping", &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(encoded[0], 18); // Short ID for ping
        assert_eq!(&encoded[1..], &[1, 2, 3, 4, 5, 6, 7, 8]);

        let (msg_type, payload) = decode_message_type_and_payload(&encoded).unwrap();
        assert_eq!(msg_type, "ping");
        assert_eq!(payload, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_message_encoding_long() {
        let encoded = encode_message_type_and_payload("customtype", &[0xab, 0xcd]);
        assert_eq!(encoded[0], 0); // Long encoding marker
        assert_eq!(&encoded[1..11], b"customtype");
        assert_eq!(encoded[11], 0);
        assert_eq!(encoded[12], 0);
        assert_eq!(&encoded[13..], &[0xab, 0xcd]);

        let (msg_type, payload) = decode_message_type_and_payload(&encoded).unwrap();
        assert_eq!(msg_type, "customtype");
        assert_eq!(payload, vec![0xab, 0xcd]);
    }

    #[test]
    fn test_fs_chacha20() {
        let key = [0x42u8; 32];
        let mut cipher = FSChaCha20::new(key, REKEY_INTERVAL);

        let plaintext = [0u8; 32];
        let mut ciphertext = [0u8; 32];
        let mut decrypted = [0u8; 32];

        cipher.crypt(&plaintext, &mut ciphertext);

        // Reset cipher for decryption
        let mut cipher2 = FSChaCha20::new(key, REKEY_INTERVAL);
        cipher2.crypt(&ciphertext, &mut decrypted);

        assert_eq!(plaintext, decrypted);
    }

    /// Regression test for the BIP-324 length-cipher continuous-keystream
    /// requirement.  The previous implementation built a fresh ChaCha20
    /// per `crypt()` call with `chunk_counter` baked into the nonce, so
    /// every call started at block 0 of a different stream.  This test
    /// verifies that calling `crypt()` N times on 3-byte chunks produces
    /// the same ciphertext as calling `crypt()` once on a 3*N-byte chunk
    /// (i.e. the ciphertext is a contiguous slice of one keystream).
    ///
    /// If this test fails, real-peer interop is broken at packet 2 — see
    /// clearbit `cb04a1f`.
    #[test]
    fn test_fs_chacha20_continuous_keystream() {
        let key = [0x37u8; 32];

        // Reference: encrypt 30 zero bytes in one call.
        let mut ref_cipher = FSChaCha20::new(key, REKEY_INTERVAL);
        let mut reference = [0u8; 30];
        ref_cipher.crypt(&[0u8; 30], &mut reference);

        // Compare against 10 calls of 3 bytes each (the wire-format
        // length-prefix shape for 10 BIP-324 packets).
        let mut chunked = FSChaCha20::new(key, REKEY_INTERVAL);
        let mut out = [0u8; 30];
        for i in 0..10 {
            chunked.crypt(&[0u8; 3], &mut out[i * 3..(i + 1) * 3]);
        }

        assert_eq!(
            reference, out,
            "FSChaCha20 length cipher must produce a continuous keystream \
             across multiple crypt() calls within an epoch"
        );
    }

    /// Cross-impl byte-for-byte compatibility test: feed a known key and
    /// pull 30 bytes via 10 successive 3-byte crypt() calls, comparing
    /// against the keystream a plain ChaCha20 would emit at block 0 with
    /// the BIP-324 epoch nonce `[0,0,0,0] || LE64(0)`.
    #[test]
    fn test_fs_chacha20_matches_plain_chacha20() {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let key = [0xa5u8; 32];

        // Reference plain ChaCha20 with the BIP-324 epoch nonce.
        let nonce = [0u8; 12]; // [0,0,0,0] || LE64(0)
        let mut plain = chacha20::ChaCha20::new((&key).into(), (&nonce).into());
        let mut plain_keystream = [0u8; 30];
        plain.apply_keystream(&mut plain_keystream);

        // FSChaCha20 invoked in 3-byte chunks should produce the same
        // bytes (since input is zero, ciphertext == keystream).
        let mut fs = FSChaCha20::new(key, REKEY_INTERVAL);
        let mut fs_keystream = [0u8; 30];
        for i in 0..10 {
            fs.crypt(&[0u8; 3], &mut fs_keystream[i * 3..(i + 1) * 3]);
        }

        assert_eq!(plain_keystream, fs_keystream);
    }

    /// Wire-ordering round-trip: two packets, encrypted in order then
    /// decrypted in order using a single sender/receiver pair (the
    /// real-world use of a length cipher on a TCP stream).  Catches
    /// the same bug as `test_fs_chacha20_continuous_keystream` but
    /// from the symmetry direction — if encrypt and decrypt drift
    /// out of sync after packet 1, packet 2 will not round-trip.
    #[test]
    fn test_fs_chacha20_two_packet_wire_ordering() {
        let key = [0xc0u8; 32];

        let mut send = FSChaCha20::new(key, REKEY_INTERVAL);
        let mut recv = FSChaCha20::new(key, REKEY_INTERVAL);

        // Two distinct 3-byte plaintexts, encrypted in order.
        let pt1 = [0x01, 0x02, 0x03];
        let pt2 = [0xaa, 0xbb, 0xcc];

        let mut ct1 = [0u8; 3];
        let mut ct2 = [0u8; 3];
        send.crypt(&pt1, &mut ct1);
        send.crypt(&pt2, &mut ct2);

        // Decrypt in the same order.
        let mut rt1 = [0u8; 3];
        let mut rt2 = [0u8; 3];
        recv.crypt(&ct1, &mut rt1);
        recv.crypt(&ct2, &mut rt2);

        assert_eq!(rt1, pt1, "packet 1 must round-trip");
        assert_eq!(
            rt2, pt2,
            "packet 2 must round-trip; failure means encrypt/decrypt \
             cipher streams are not advancing in lockstep within an epoch"
        );
    }

    #[test]
    fn test_looks_like_v1_version_real_v1_prefix() {
        // Mainnet magic + b"version\0\0\0\0\0".
        let mainnet = [0xf9, 0xbe, 0xb4, 0xd9];
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&mainnet);
        bytes[4..16].copy_from_slice(b"version\0\0\0\0\0");
        assert!(looks_like_v1_version(&bytes, &mainnet));
    }

    #[test]
    fn test_looks_like_v1_version_v2_pubkey() {
        // The first 16 bytes of a 64-byte ellswift pubkey are
        // essentially random; the first 4 bytes match the network
        // magic only with probability ~1/2^32.
        let mainnet = [0xf9, 0xbe, 0xb4, 0xd9];
        let pubkey_prefix = [
            0xec, 0x0a, 0xdf, 0xf2, 0x57, 0xbb, 0xfe, 0x50, 0x0c, 0x18, 0x8c, 0x80, 0xb4, 0xfd,
            0xd6, 0x40,
        ];
        assert!(!looks_like_v1_version(&pubkey_prefix, &mainnet));
    }

    #[test]
    fn test_looks_like_v1_version_short_input() {
        // Anything shorter than 16 bytes can't be classified as v1.
        let mainnet = [0xf9, 0xbe, 0xb4, 0xd9];
        assert!(!looks_like_v1_version(&[], &mainnet));
        assert!(!looks_like_v1_version(&[0u8; 15], &mainnet));
    }

    #[test]
    fn test_looks_like_v1_version_magic_match_wrong_command() {
        // Magic matches but the v1 command is "inv" not "version" —
        // the spec only treats VERSION as the unambiguous v1 marker
        // because it's always the first message.
        let mainnet = [0xf9, 0xbe, 0xb4, 0xd9];
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&mainnet);
        bytes[4..16].copy_from_slice(b"inv\0\0\0\0\0\0\0\0\0");
        assert!(!looks_like_v1_version(&bytes, &mainnet));
    }

    #[test]
    fn test_looks_like_v1_version_wrong_magic() {
        // Even with "version" in bytes 4..16, a non-matching magic
        // prefix is not v1 (most likely v2 ellswift pubkey).
        let mainnet = [0xf9, 0xbe, 0xb4, 0xd9];
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        bytes[4..16].copy_from_slice(b"version\0\0\0\0\0");
        assert!(!looks_like_v1_version(&bytes, &mainnet));
    }

    #[test]
    fn test_fs_chacha20poly1305() {
        let key = [0x42u8; 32];
        let mut enc_cipher = FSChaCha20Poly1305::new(key, REKEY_INTERVAL);
        let mut dec_cipher = FSChaCha20Poly1305::new(key, REKEY_INTERVAL);

        let plaintext = b"Hello, BIP324!";
        let aad = b"additional data";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        enc_cipher.encrypt(&[], plaintext, aad, &mut ciphertext);

        let mut header = [0u8; 0];
        let mut decrypted = vec![0u8; plaintext.len()];

        assert!(dec_cipher.decrypt(&ciphertext, aad, &mut header, &mut decrypted));
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_ellswift_pubkey() {
        let bytes = [0x42u8; ELLSWIFT_PUBKEY_LEN];
        let pubkey = EllSwiftPubKey::from_bytes(&bytes).unwrap();
        assert_eq!(pubkey.as_bytes(), &bytes);

        assert!(EllSwiftPubKey::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_garbage_generation() {
        let garbage = generate_garbage();
        assert!(garbage.len() <= MAX_GARBAGE_LEN);
    }

    #[test]
    fn test_v2_message_ids_coverage() {
        // Test that all non-empty message IDs have valid short IDs
        for (i, msg) in V2_MESSAGE_IDS.iter().enumerate().skip(1) {
            if !msg.is_empty() {
                assert_eq!(get_short_id(msg), Some(i as u8));
            }
        }
    }

    #[test]
    fn test_ellswift_ecdh() {
        // Test vectors from BIP324/secp256k1
        // These test the ECDH shared secret computation using ElligatorSwift
        struct TestVector {
            our_secret: [u8; 32],
            ellswift_ours: [u8; 64],
            ellswift_theirs: [u8; 64],
            initiator: bool,
            expected_shared: [u8; 32],
        }

        let tests = [
            TestVector {
                our_secret: hex::decode("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7").unwrap().try_into().unwrap(),
                ellswift_ours: hex::decode("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap().try_into().unwrap(),
                ellswift_theirs: hex::decode("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap().try_into().unwrap(),
                initiator: true,
                expected_shared: hex::decode("c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592").unwrap().try_into().unwrap(),
            },
            TestVector {
                our_secret: hex::decode("1f9c581b35231838f0f17cf0c979835baccb7f3abbbb96ffcc318ab71e6e126f").unwrap().try_into().unwrap(),
                ellswift_ours: hex::decode("a1855e10e94e00baa23041d916e259f7044e491da6171269694763f018c7e63693d29575dcb464ac816baa1be353ba12e3876cba7628bd0bd8e755e721eb0140").unwrap().try_into().unwrap(),
                ellswift_theirs: hex::decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000").unwrap().try_into().unwrap(),
                initiator: false,
                expected_shared: hex::decode("a0138f564f74d0ad70bc337dacc9d0bf1d2349364caf1188a1e6e8ddb3b7b184").unwrap().try_into().unwrap(),
            },
        ];

        for test in tests {
            let secret = SecretKey::from_slice(&test.our_secret).unwrap();
            let ours = EllSwiftPubKey(test.ellswift_ours);
            let theirs = EllSwiftPubKey(test.ellswift_theirs);

            let shared = compute_bip324_ecdh_secret(&secret, &ours, &theirs, test.initiator);
            assert_eq!(shared, test.expected_shared, "ECDH shared secret mismatch");
        }
    }

    #[test]
    fn test_ellswift_create_roundtrip() {
        // Test that we can create an ElligatorSwift pubkey and use it for ECDH
        // Use valid secret keys from the test vectors
        let alice_secret = SecretKey::from_slice(
            &hex::decode("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7").unwrap()
        ).unwrap();
        let bob_secret = SecretKey::from_slice(
            &hex::decode("1f9c581b35231838f0f17cf0c979835baccb7f3abbbb96ffcc318ab71e6e126f").unwrap()
        ).unwrap();

        let alice_entropy = [0x11u8; 32];
        let bob_entropy = [0x22u8; 32];

        // Create ElligatorSwift pubkeys
        let alice_es = ellswift_create(&alice_secret, &alice_entropy);
        let bob_es = ellswift_create(&bob_secret, &bob_entropy);

        // Compute shared secrets from both sides
        let alice_shared = compute_bip324_ecdh_secret(&alice_secret, &alice_es, &bob_es, true);
        let bob_shared = compute_bip324_ecdh_secret(&bob_secret, &bob_es, &alice_es, false);

        // Both parties should derive the same shared secret
        assert_eq!(alice_shared, bob_shared, "ECDH shared secrets should match");
    }

    #[test]
    fn test_bip324_cipher_roundtrip() {
        // Test encryption/decryption roundtrip
        let alice_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let bob_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let alice_entropy = [0x11u8; 32];
        let bob_entropy = [0x22u8; 32];

        // Network magic (mainnet)
        let magic = [0xf9, 0xbe, 0xb4, 0xd9];

        // Create ciphers
        let mut alice = Bip324Cipher::new(alice_secret, alice_entropy);
        let mut bob = Bip324Cipher::new(bob_secret, bob_entropy);

        // Exchange public keys and initialize
        let alice_pubkey = alice.our_pubkey().clone();
        let bob_pubkey = bob.our_pubkey().clone();

        alice.initialize(&bob_pubkey, true, &magic);
        bob.initialize(&alice_pubkey, false, &magic);

        // Both should have the same session ID
        assert_eq!(alice.session_id(), bob.session_id());

        // Test packet encryption from Alice to Bob
        let plaintext = b"Hello, BIP324!";
        let mut ciphertext = vec![0u8; plaintext.len() + EXPANSION];

        alice.encrypt(plaintext, &[], false, &mut ciphertext).unwrap();

        // Decrypt the length
        let len = bob.decrypt_length(&ciphertext[..LENGTH_LEN].try_into().unwrap()).unwrap();
        assert_eq!(len as usize, plaintext.len());

        // Decrypt the contents
        let mut decrypted = vec![0u8; len as usize];
        let ignore = bob.decrypt(&ciphertext[LENGTH_LEN..], &[], &mut decrypted).unwrap();

        assert!(!ignore);
        assert_eq!(&decrypted[..], plaintext);

        // Test the other direction (Bob to Alice)
        let bob_message = b"Hello from Bob!";
        let mut bob_ciphertext = vec![0u8; bob_message.len() + EXPANSION];

        bob.encrypt(bob_message, &[], false, &mut bob_ciphertext).unwrap();

        let bob_len = alice.decrypt_length(&bob_ciphertext[..LENGTH_LEN].try_into().unwrap()).unwrap();
        let mut bob_decrypted = vec![0u8; bob_len as usize];
        alice.decrypt(&bob_ciphertext[LENGTH_LEN..], &[], &mut bob_decrypted).unwrap();

        assert_eq!(&bob_decrypted[..], bob_message);
    }

    #[test]
    fn test_bip324_garbage_terminators() {
        // Verify that initiator and responder get correct garbage terminators
        let alice_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let bob_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let alice_entropy = [0x11u8; 32];
        let bob_entropy = [0x22u8; 32];

        let magic = [0xf9, 0xbe, 0xb4, 0xd9];

        let mut alice = Bip324Cipher::new(alice_secret, alice_entropy);
        let mut bob = Bip324Cipher::new(bob_secret, bob_entropy);

        let alice_pubkey = alice.our_pubkey().clone();
        let bob_pubkey = bob.our_pubkey().clone();

        alice.initialize(&bob_pubkey, true, &magic);
        bob.initialize(&alice_pubkey, false, &magic);

        // Alice's send terminator should match Bob's receive terminator
        assert_eq!(
            alice.send_garbage_terminator(),
            bob.recv_garbage_terminator()
        );

        // Bob's send terminator should match Alice's receive terminator
        assert_eq!(
            bob.send_garbage_terminator(),
            alice.recv_garbage_terminator()
        );
    }

    #[test]
    fn test_bip324_ignore_flag() {
        let alice_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let bob_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let magic = [0xf9, 0xbe, 0xb4, 0xd9];

        let mut alice = Bip324Cipher::new(alice_secret, [0x11u8; 32]);
        let mut bob = Bip324Cipher::new(bob_secret, [0x22u8; 32]);

        let alice_pubkey = alice.our_pubkey().clone();
        let bob_pubkey = bob.our_pubkey().clone();

        alice.initialize(&bob_pubkey, true, &magic);
        bob.initialize(&alice_pubkey, false, &magic);

        // Send a message with ignore flag set
        let plaintext = b"Ignore me!";
        let mut ciphertext = vec![0u8; plaintext.len() + EXPANSION];

        alice.encrypt(plaintext, &[], true, &mut ciphertext).unwrap();

        let len = bob.decrypt_length(&ciphertext[..LENGTH_LEN].try_into().unwrap()).unwrap();
        let mut decrypted = vec![0u8; len as usize];
        let ignore = bob.decrypt(&ciphertext[LENGTH_LEN..], &[], &mut decrypted).unwrap();

        assert!(ignore, "Ignore flag should be set");
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_bip324_packet_test_vector_1() {
        // First test vector from Bitcoin Core bip324_tests.cpp
        // This tests the full cipher operation with known inputs
        let priv_ours = hex::decode("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7").unwrap();
        let ellswift_ours = hex::decode("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let ellswift_theirs = hex::decode("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let expected_session_id = hex::decode("ce72dffb015da62b0d0f5474cab8bc72605225b0cee3f62312ec680ec5f41ba5").unwrap();
        let expected_send_garbage = hex::decode("faef555dfcdb936425d84aba524758f3").unwrap();
        let expected_recv_garbage = hex::decode("02cb8ff24307a6e27de3b4e7ea3fa65b").unwrap();

        let secret_key = SecretKey::from_slice(&priv_ours).unwrap();
        let our_pubkey = EllSwiftPubKey::from_bytes(&ellswift_ours).unwrap();
        let their_pubkey = EllSwiftPubKey::from_bytes(&ellswift_theirs).unwrap();

        // Create cipher with pre-computed pubkey (for testing)
        let mut cipher = Bip324Cipher::new_with_pubkey(secret_key, our_pubkey);

        // Mainnet magic
        let magic = [0xf9, 0xbe, 0xb4, 0xd9];

        // Initialize
        cipher.initialize(&their_pubkey, true, &magic);

        // Verify session ID
        assert_eq!(cipher.session_id().as_slice(), expected_session_id.as_slice(), "Session ID mismatch");

        // Verify garbage terminators
        assert_eq!(cipher.send_garbage_terminator().as_slice(), expected_send_garbage.as_slice(), "Send garbage terminator mismatch");
        assert_eq!(cipher.recv_garbage_terminator().as_slice(), expected_recv_garbage.as_slice(), "Recv garbage terminator mismatch");
    }
}
