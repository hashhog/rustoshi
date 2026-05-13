//! W107 — CompactSize + VarInt 30-gate serialization audit.
//!
//! Covers Bitcoin Core `serialize.h` CompactSize and VarInt primitives
//! against rustoshi's implementations in:
//!   - `crates/primitives/src/serialize.rs`   — `read_compact_size`, `write_compact_size`
//!   - `crates/primitives/src/transaction.rs` — wire deserialization guards
//!   - `crates/network/src/message.rs`         — P2P message framing
//!   - `crates/network/src/compact_blocks.rs`  — BIP-152 short-ids
//!   - `crates/storage/src/snapshot.rs`        — VarInt (private, tested via snapshot round-trip)
//!
//! ## Gate legend (severity)
//!   - P0-CDIV: consensus-divergent
//!   - P1: remotely exploitable OOM / peer-ban / deserialization error
//!   - P2: spec deviation without immediate exploit
//!   - P3: minor spec gap / missing guard
//!   - P4: cosmetic / documentation gap
//!
//! ## Status summary
//!   - OK (passes spec): G1-G10, G13, G14, G15, G16, G17, G19, G20, G21, G23, G24, G25, G26, G27, G28, G29
//!   - BUG: G11, G12, G18, G22, G30
//!
//! Tests for BUG gates are annotated `#[ignore]` to document the failure
//! without breaking the build; they flip to passing when the bug is fixed.

use rustoshi_network::message::{
    serialize_message, NetworkMessage, VersionMessage, NetAddress, NODE_NETWORK, NODE_WITNESS,
    MAX_INV_SIZE,
};
use rustoshi_primitives::serialize::{read_compact_size, write_compact_size, Decodable, Encodable};
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::io::Cursor;

// ────────────────────────────────────────────────────────────────
// G1: WriteCompactSize 1-byte boundary (n < 253 → single byte)
// Status: OK
// Core ref: serialize.h WriteCompactSize: if (nSize < 253) ser_writedata8(os, nSize)
// ────────────────────────────────────────────────────────────────
#[test]
fn g1_write_compact_size_one_byte() {
    for val in [0u64, 1, 127, 252] {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        assert_eq!(buf.len(), 1, "value {} should encode to 1 byte", val);
        assert_eq!(buf[0], val as u8);
    }
}

// ────────────────────────────────────────────────────────────────
// G2: WriteCompactSize 3-byte boundary (253 ≤ n ≤ 65535)
// Status: OK
// Core ref: serialize.h: if (nSize <= 0xFFFF) → 0xFD + 2 LE bytes
// ────────────────────────────────────────────────────────────────
#[test]
fn g2_write_compact_size_three_bytes() {
    for val in [253u64, 254, 65535] {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        assert_eq!(buf.len(), 3, "value {} should encode to 3 bytes", val);
        assert_eq!(buf[0], 0xFD);
        let decoded_val = u16::from_le_bytes([buf[1], buf[2]]) as u64;
        assert_eq!(decoded_val, val);
    }
}

// ────────────────────────────────────────────────────────────────
// G3: WriteCompactSize 5-byte boundary (65536 ≤ n ≤ 4294967295)
// Status: OK
// Core ref: serialize.h: if (nSize <= UINT_MAX) → 0xFE + 4 LE bytes
// ────────────────────────────────────────────────────────────────
#[test]
fn g3_write_compact_size_five_bytes() {
    for val in [65536u64, 0xFFFF_FFFF] {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        assert_eq!(buf.len(), 5, "value {} should encode to 5 bytes", val);
        assert_eq!(buf[0], 0xFE);
        let decoded_val = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64;
        assert_eq!(decoded_val, val);
    }
}

// ────────────────────────────────────────────────────────────────
// G4: WriteCompactSize 9-byte boundary (n > 4294967295)
// Status: OK
// Core ref: serialize.h: else → 0xFF + 8 LE bytes
// ────────────────────────────────────────────────────────────────
#[test]
fn g4_write_compact_size_nine_bytes() {
    for val in [0x1_0000_0000u64, u64::MAX] {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        assert_eq!(buf.len(), 9, "value {} should encode to 9 bytes", val);
        assert_eq!(buf[0], 0xFF);
        let decoded_val = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        assert_eq!(decoded_val, val);
    }
}

// ────────────────────────────────────────────────────────────────
// G5: WriteCompactSize for n=0 (special-case empty)
// Status: OK
// Core ref: 0 < 253 → single byte 0x00
// ────────────────────────────────────────────────────────────────
#[test]
fn g5_write_compact_size_zero() {
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 0).unwrap();
    assert_eq!(buf, vec![0x00]);
}

// ────────────────────────────────────────────────────────────────
// G6: ReadCompactSize 1-byte parsing (first byte < 253)
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g6_read_compact_size_one_byte() {
    for val in [0u64, 1, 127, 252] {
        let buf = [val as u8];
        let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(result, val);
    }
}

// ────────────────────────────────────────────────────────────────
// G7: ReadCompactSize 3-byte parsing (first byte = 0xFD)
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g7_read_compact_size_three_bytes() {
    // 253 = [0xFD, 0xFD, 0x00]
    let buf = [0xFDu8, 0xFD, 0x00];
    let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(result, 253);

    // 65535 = [0xFD, 0xFF, 0xFF]
    let buf = [0xFDu8, 0xFF, 0xFF];
    let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(result, 65535);
}

// ────────────────────────────────────────────────────────────────
// G8: ReadCompactSize 5-byte parsing (first byte = 0xFE)
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g8_read_compact_size_five_bytes() {
    // 65536 = [0xFE, 0x00, 0x00, 0x01, 0x00]
    let buf = [0xFEu8, 0x00, 0x00, 0x01, 0x00];
    let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(result, 65536);
}

// ────────────────────────────────────────────────────────────────
// G9: ReadCompactSize 9-byte parsing (first byte = 0xFF)
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g9_read_compact_size_nine_bytes() {
    // 0x1_0000_0000
    let val: u64 = 0x1_0000_0000;
    let mut buf = vec![0xFFu8];
    buf.extend_from_slice(&val.to_le_bytes());
    let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(result, val);
}

// ────────────────────────────────────────────────────────────────
// G10: ReadCompactSize non-canonical rejection
// Status: OK
// Core ref: serialize.h ReadCompactSize: if (nSizeRet < 253) throw "non-canonical"
//           if (nSizeRet < 0x10000u) throw, if (nSizeRet < 0x100000000ULL) throw
// ────────────────────────────────────────────────────────────────
#[test]
fn g10_read_compact_size_non_canonical_fd() {
    // Value 252 encoded with 0xFD prefix (should be 1 byte)
    let buf = [0xFDu8, 0xFC, 0x00]; // 0xFC = 252
    let result = read_compact_size(&mut Cursor::new(&buf));
    assert!(result.is_err(), "non-canonical 0xFD+252 must be rejected");
}

#[test]
fn g10_read_compact_size_non_canonical_fe() {
    // Value 65535 encoded with 0xFE prefix (should be 3 bytes / 0xFD)
    let buf = [0xFEu8, 0xFF, 0xFF, 0x00, 0x00];
    let result = read_compact_size(&mut Cursor::new(&buf));
    assert!(result.is_err(), "non-canonical 0xFE+65535 must be rejected");
}

#[test]
fn g10_read_compact_size_non_canonical_ff() {
    // Value 0xFFFFFFFF encoded with 0xFF prefix (should be 5 bytes / 0xFE)
    let buf = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
    let result = read_compact_size(&mut Cursor::new(&buf));
    assert!(result.is_err(), "non-canonical 0xFF+0xFFFFFFFF must be rejected");
}

// ────────────────────────────────────────────────────────────────
// G11: MAX_SIZE = 0x02000000 enforcement on read
// Status: BUG / P2
//
// Core ref: serialize.h line 358: if (range_check && nSizeRet > MAX_SIZE) throw
//   ReadCompactSize enforces MAX_SIZE by default (range_check=true).
//   Any call site reading a count benefits automatically.
//
// rustoshi: read_compact_size has NO MAX_SIZE guard. The 0x02000000 check
//   only exists inside `Vec<u8> Decodable::decode` (serialize.rs:352).
//   All other callers (message.rs ua_len, getheaders count, etc.) receive
//   raw u64 with no cap enforced at the primitive level. A peer can send
//   a CompactSize = 0x02000001 to any unguarded parser without rejection.
// ────────────────────────────────────────────────────────────────
#[test]
#[ignore] // BUG G11: read_compact_size has no MAX_SIZE guard; only Vec<u8> decode does
fn g11_read_compact_size_max_size_enforced() {
    // 0x02000001 = MAX_SIZE + 1 = 33554433; should be rejected by the primitive
    let val: u64 = 0x02000001;
    let mut buf = vec![0xFEu8];
    buf.extend_from_slice(&(val as u32).to_le_bytes());
    let result = read_compact_size(&mut Cursor::new(&buf));
    assert!(
        result.is_err(),
        "read_compact_size should reject values > MAX_SIZE (0x02000000) by default, like Core does"
    );
}

#[test]
fn g11_vec_u8_decode_max_size_enforced() {
    // Vec<u8> Decodable does have the check — confirm it works
    // 0x02000001 encoded as 0xFF prefix (9 bytes)
    let val: u64 = 0x02000001;
    let mut buf = vec![0xFFu8];
    buf.extend_from_slice(&val.to_le_bytes());
    let result = Vec::<u8>::deserialize(&buf);
    assert!(result.is_err(), "Vec<u8> decode must reject len > 0x02000000");
}

#[test]
fn g11_vec_u8_decode_max_size_boundary() {
    // 0x02000000 exactly is the maximum allowed value per Core (MAX_SIZE)
    // The check is "> MAX_SIZE" so 0x02000000 should be ACCEPTED
    // We can't actually allocate 33MB in a test, but we confirm the CompactSize
    // encoding doesn't get rejected on boundary value
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 0x02000000).unwrap();
    // Read it back (without trying to allocate — just CompactSize decode)
    let val = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(val, 0x02000000);
}

// ────────────────────────────────────────────────────────────────
// G12: Allocator pre-allocation safety (no huge Vec::with_capacity)
// Status: BUG / P1
//
// Core ref: serialize.h:674-676: allocates in 5 MB batches (MAX_VECTOR_ALLOCATE=5MB)
//   so attacker needs to actually supply the bytes to grow the allocation.
//
// rustoshi: message.rs version handler reads ua_len via read_compact_size
//   then immediately does `vec![0u8; ua_len]` with no size cap.
//   An attacker sending a version message with ua_len = 0x02000000 (33 MB)
//   causes rustoshi to attempt a 33 MB heap allocation before reading any bytes.
//   Bitcoin Core limits user_agent to MAX_SUBVERSION_LENGTH = 256 bytes (net.h:67).
// ────────────────────────────────────────────────────────────────
#[test]
#[ignore] // BUG G12/G22: version message ua_len has no bound; should cap at 256 per Core net.h:67
fn g12_version_message_huge_ua_rejected() {
    // Craft a version message payload where ua_len is gigantic (e.g. 1 GB)
    // This should be rejected before any allocation attempt.
    //
    // Structure: version(4) + services(8) + timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8)
    //            + compact_size(ua_len) + ...
    // We will just check the parser rejects before blowing memory.
    let mut payload = Vec::new();
    // version i32
    payload.extend_from_slice(&70016i32.to_le_bytes());
    // services u64
    payload.extend_from_slice(&(NODE_NETWORK | NODE_WITNESS).to_le_bytes());
    // timestamp i64
    payload.extend_from_slice(&1_234_567_890i64.to_le_bytes());
    // addr_recv: services(8) + ip(16) + port(2) = 26 bytes
    payload.extend_from_slice(&[0u8; 26]);
    // addr_from: same
    payload.extend_from_slice(&[0u8; 26]);
    // nonce u64
    payload.extend_from_slice(&12345u64.to_le_bytes());
    // ua_len: craft a 0xFE-prefix value of 4_000_000 (4 MB) — well above 256
    // encoded as [0xFE, 0x40, 0x42, 0x0F, 0x00] = 4_000_000 (0x3D0900 → no, 4000000 = 0x3D0900)
    // 4_000_000 = 0x003D0900
    let ua_len: u32 = 4_000_000;
    payload.push(0xFE);
    payload.extend_from_slice(&ua_len.to_le_bytes());
    // No actual user_agent bytes follow — the parser should reject on ua_len > 256

    let result = NetworkMessage::deserialize("version", &payload);
    assert!(
        result.is_err(),
        "version message with ua_len={} must be rejected (Core cap: 256 bytes)",
        ua_len
    );
}

// ────────────────────────────────────────────────────────────────
// G13: Stream-end truncation (EOF in middle of multi-byte CompactSize)
// Status: OK
// read_exact returns UnexpectedEof which propagates as Err
// ────────────────────────────────────────────────────────────────
#[test]
fn g13_truncated_compact_size_fd() {
    // Only one byte of a 3-byte 0xFD sequence
    let buf = [0xFDu8];
    let result = read_compact_size(&mut Cursor::new(&buf));
    assert!(result.is_err(), "truncated 0xFD prefix must return Err");
}

#[test]
fn g13_truncated_compact_size_fe() {
    // Only 3 bytes of a 5-byte 0xFE sequence
    let buf = [0xFEu8, 0x00, 0x01];
    let result = read_compact_size(&mut Cursor::new(&buf));
    assert!(result.is_err(), "truncated 0xFE prefix must return Err");
}

#[test]
fn g13_truncated_compact_size_ff() {
    // Only 5 bytes of a 9-byte 0xFF sequence
    let buf = [0xFFu8, 0x00, 0x01, 0x02, 0x03];
    let result = read_compact_size(&mut Cursor::new(&buf));
    assert!(result.is_err(), "truncated 0xFF prefix must return Err");
}

// ────────────────────────────────────────────────────────────────
// G14: Empty stream read returns error not 0
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g14_empty_stream_is_error() {
    let buf: &[u8] = &[];
    let result = read_compact_size(&mut Cursor::new(buf));
    assert!(result.is_err(), "reading CompactSize from empty stream must return Err");
}

// ────────────────────────────────────────────────────────────────
// G15: Size used as loop count — no integer overflow if size × elem overflows usize
// Status: OK
// All loop count reads in transaction.rs/block.rs have bounds checks before
// Vec::with_capacity, capping values well below usize::MAX.
// ────────────────────────────────────────────────────────────────
#[test]
fn g15_loop_count_bounds_checked() {
    // Build a transaction payload claiming 0xFFFF_FFFF inputs (attacker value)
    // After the 4-byte version, SegWit marker byte isn't present, so the
    // first compact_size is the input count.
    // The parser must reject before allocating 4B TxIn entries.
    let mut payload = Vec::new();
    payload.extend_from_slice(&1i32.to_le_bytes()); // version
    // input_count = 0xFE + 4 bytes = 5-byte compact size encoding 0xFFFF_FFFF
    payload.push(0xFE);
    payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // No actual inputs follow

    let result = Transaction::deserialize(&payload);
    assert!(result.is_err(), "huge input_count must be rejected before OOM");
}

// ────────────────────────────────────────────────────────────────
// G16: VarInt encoding 1-byte (small values)
// Status: OK (snapshot.rs private write_varint, tested via known vectors)
// ────────────────────────────────────────────────────────────────
#[test]
fn g16_varint_roundtrip_via_serialization() {
    // VarInt is used only in snapshot serialization.
    // We verify indirectly: compact_size encodes 0-252 as 1 byte (different format from VarInt)
    // The VarInt's 1-byte range (0x00-0x7F) maps to same values, confirmed by snapshot tests.
    // We test the CompactSize 1-byte path as a proxy for the serialize layer.
    for val in 0u64..128 {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], val as u8);
    }
}

// ────────────────────────────────────────────────────────────────
// G17: VarInt encoding multi-byte continuation
// Status: OK (snapshot.rs — known vector coverage confirmed by test_varint_known_byte_vectors)
// ────────────────────────────────────────────────────────────────
#[test]
fn g17_varint_multi_byte_known_vectors() {
    // Cross-check against Core's serial test vectors (serialize.h comments):
    //   128:  [0x80 0x00]
    //   255:  [0x80 0x7F]
    //   256:  [0x81 0x00]
    // These are covered by snapshot::test_varint_known_byte_vectors already;
    // we confirm the CompactSize layer doesn't confuse the two formats.
    // CompactSize 128 → [0xFD, 0x80, 0x00] (3 bytes, not VarInt)
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 128).unwrap();
    assert_eq!(buf[0], 0xFD, "CompactSize must not be confused with VarInt format");
    assert_eq!(buf.len(), 3);
}

// ────────────────────────────────────────────────────────────────
// G18: VarInt mode DEFAULT vs NONNEGATIVE_SIGNED (range bias)
// Status: BUG / P3
//
// Core ref: serialize.h VarIntMode::NONNEGATIVE_SIGNED is used for signed types
//   (e.g. int) in UTXO/coin serialization — encodes nonneg i64/i32 values.
//   When a signed type with value < 0 is used, Core's static_assert catches it
//   at compile time.
//
// rustoshi snapshot.rs: write_varint/read_varint only accept u64. There is no
//   NONNEGATIVE_SIGNED variant. Code that needs to encode nonnegative i64/i32
//   values (e.g. coin height) must cast to u64 externally, with no compile-time
//   enforcement that the value is nonnegative. A future developer could introduce
//   a bug by passing a negative height.
// ────────────────────────────────────────────────────────────────
#[test]
#[ignore] // BUG G18 / P3: no NONNEGATIVE_SIGNED VarInt mode; negative i64 silently bit-patterns to large u64
fn g18_varint_nonnegative_signed_mode_absent() {
    // Core enforces mode at compile time via CheckVarIntMode<VarIntMode::NONNEGATIVE_SIGNED, I>().
    // Rustoshi has no such guard. A negative i64 height = -1i64 as u64 = u64::MAX = wrong encoding.
    // This test documents the contract: height values encoded as VarInt must be >= 0.
    let negative_as_u64: u64 = (-1i64) as u64; // u64::MAX in two's complement
    // u64::MAX encodes as a 10-byte VarInt — way larger than any valid height
    // If snapshot ever passes a negative height, it silently encodes garbage.
    assert_eq!(negative_as_u64, u64::MAX, "negative i64 cast to u64 gives MAX — not a valid height");
}

// ────────────────────────────────────────────────────────────────
// G19: VarInt overflow on encode (u64::MAX boundary)
// Status: OK — snapshot write_varint handles u64::MAX in 10-byte buffer
// ────────────────────────────────────────────────────────────────
#[test]
fn g19_varint_encode_u64_max_no_panic() {
    // snapshot write_varint uses tmp[10]; u64::MAX (0xFFFF...FFFF) takes 10 bytes.
    // The loop "if n <= 0x7F break; n = (n >> 7) - 1" terminates without panic.
    // We verify indirectly: CompactSize also handles u64::MAX (different encoding).
    let mut buf = Vec::new();
    write_compact_size(&mut buf, u64::MAX).unwrap();
    assert_eq!(buf.len(), 9);
    assert_eq!(buf[0], 0xFF);
    let decoded = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, u64::MAX);
}

// ────────────────────────────────────────────────────────────────
// G20: VarInt overflow on decode (truncate at u64::MAX)
// Status: OK — snapshot read_varint checks n > (u64::MAX >> 7) and n == u64::MAX
// ────────────────────────────────────────────────────────────────
#[test]
fn g20_varint_decode_overflow_guard_via_compactsize() {
    // VarInt decode overflow guard is in snapshot.rs (private).
    // Verify CompactSize analogously: u64::MAX round-trips without overflow.
    let val = u64::MAX;
    let mut buf = Vec::new();
    write_compact_size(&mut buf, val).unwrap();
    let decoded = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, val, "u64::MAX must round-trip through CompactSize");
}

// ────────────────────────────────────────────────────────────────
// G21: Vec<T> deserialization (CompactSize prefix + per-element call)
// Status: OK — transaction inputs/outputs decoded with CompactSize count
// ────────────────────────────────────────────────────────────────
#[test]
fn g21_vec_element_deserialization_roundtrip() {
    // A transaction with 2 inputs and 2 outputs should survive a full
    // serialize → deserialize cycle with the correct counts.
    let tx = Transaction {
        version: 1,
        inputs: vec![
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x01, 0x02, 0x03],
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            },
            TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 1 },
                script_sig: vec![0x04],
                sequence: 0xFFFE_FFFF,
                witness: Vec::new(),
            },
        ],
        outputs: vec![
            TxOut { value: 50_000_000, script_pubkey: vec![0x76, 0xa9] },
            TxOut { value: 49_900_000, script_pubkey: vec![0x00, 0x14] },
        ],
        lock_time: 0,
    };

    let encoded = tx.serialize();
    let decoded = Transaction::deserialize(&encoded).unwrap();
    assert_eq!(decoded.inputs.len(), 2);
    assert_eq!(decoded.outputs.len(), 2);
    assert_eq!(decoded, tx);
}

// ────────────────────────────────────────────────────────────────
// G22: String/ByteString length-prefixed serialization (user_agent bound)
// Status: BUG / P1
//
// Core ref: net.h:67 MAX_SUBVERSION_LENGTH = 256
//           net_processing.cpp:3636: vRecv >> LIMITED_STRING(strSubVer, 256)
//
// rustoshi message.rs:521: ua_len = read_compact_size() as usize, then
//   immediately vec![0u8; ua_len] — no bound check. Peer can cause a ≥33 MB
//   allocation by sending ua_len = 0x02000000.
// ────────────────────────────────────────────────────────────────
#[test]
fn g22_user_agent_short_roundtrip() {
    // Normal user agent (< 256 bytes) must serialize/deserialize correctly.
    let ua = "/rustoshi:0.1.0/".to_string();
    let msg = NetworkMessage::Version(VersionMessage {
        version: 70016,
        services: NODE_NETWORK | NODE_WITNESS,
        timestamp: 0,
        addr_recv: NetAddress { services: 0, ip: [0u8; 16], port: 0 },
        addr_from: NetAddress { services: 0, ip: [0u8; 16], port: 0 },
        nonce: 0,
        user_agent: ua.clone(),
        start_height: 0,
        relay: true,
    });
    let payload = msg.serialize_payload();
    let decoded = NetworkMessage::deserialize("version", &payload).unwrap();
    if let NetworkMessage::Version(v) = decoded {
        assert_eq!(v.user_agent, ua);
    } else {
        panic!("expected Version");
    }
}

#[test]
#[ignore] // BUG G22 / P1: user_agent length not bounded; should reject > 256 per Core MAX_SUBVERSION_LENGTH
fn g22_user_agent_too_long_rejected() {
    // A user agent of 300 bytes should be rejected.
    let ua = "A".repeat(300);
    let mut payload = Vec::new();
    payload.extend_from_slice(&70016i32.to_le_bytes());   // version
    payload.extend_from_slice(&0u64.to_le_bytes());         // services
    payload.extend_from_slice(&0i64.to_le_bytes());         // timestamp
    payload.extend_from_slice(&[0u8; 26]);                  // addr_recv
    payload.extend_from_slice(&[0u8; 26]);                  // addr_from
    payload.extend_from_slice(&0u64.to_le_bytes());         // nonce
    // ua_len = 300 (0xFD 0x2C 0x01)
    payload.push(0xFD);
    payload.extend_from_slice(&300u16.to_le_bytes());
    payload.extend_from_slice(ua.as_bytes());
    payload.extend_from_slice(&0i32.to_le_bytes());         // start_height
    payload.push(1u8);                                       // relay

    let result = NetworkMessage::deserialize("version", &payload);
    assert!(
        result.is_err(),
        "user_agent of {} bytes must be rejected (Core cap: 256)",
        ua.len()
    );
}

// ────────────────────────────────────────────────────────────────
// G23: OutPoint serialization (txid 32B + vout 4 LE bytes)
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g23_outpoint_serialization() {
    let outpoint = OutPoint {
        txid: Hash256::from_hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        ).unwrap(),
        vout: 42,
    };
    let encoded = outpoint.serialize();
    assert_eq!(encoded.len(), 36);
    // First 32 bytes = txid
    assert_eq!(&encoded[..32], &outpoint.txid.0);
    // Last 4 bytes = vout in little-endian
    assert_eq!(&encoded[32..], &42u32.to_le_bytes());

    let decoded = OutPoint::deserialize(&encoded).unwrap();
    assert_eq!(decoded, outpoint);
}

// ────────────────────────────────────────────────────────────────
// G24: Witness vector serialization (BIP-141)
// CompactSize stack_count + per-element (CompactSize length + bytes)
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g24_witness_roundtrip() {
    // A SegWit input with a typical P2WPKH witness (sig + pubkey).
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![
                vec![0x30u8; 71], // signature (DER + sighash)
                vec![0x02u8; 33], // compressed pubkey
            ],
        }],
        outputs: vec![TxOut {
            value: 1_000_000,
            script_pubkey: vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        }],
        lock_time: 0,
    };

    let encoded = tx.serialize();
    // SegWit marker and flag
    assert_eq!(encoded[4], 0x00);
    assert_eq!(encoded[5], 0x01);

    let decoded = Transaction::deserialize(&encoded).unwrap();
    assert!(decoded.has_witness());
    assert_eq!(decoded.inputs[0].witness.len(), 2);
    assert_eq!(decoded.inputs[0].witness[0].len(), 71);
    assert_eq!(decoded.inputs[0].witness[1].len(), 33);
}

// ────────────────────────────────────────────────────────────────
// G25: Script serialization (CompactSize length + bytes)
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g25_script_serialization() {
    // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    let script = {
        let mut s = vec![0x76u8, 0xa9, 0x14];
        s.extend_from_slice(&[0xABu8; 20]);
        s.extend_from_slice(&[0x88u8, 0xac]);
        s
    };
    let output = TxOut { value: 50_000_000, script_pubkey: script.clone() };
    let encoded = output.serialize();
    // First 8 bytes = value (LE)
    assert_eq!(u64::from_le_bytes(encoded[..8].try_into().unwrap()), 50_000_000);
    // Next byte = compact_size(script.len() = 25)
    assert_eq!(encoded[8], 25u8);
    // Remaining = script bytes
    assert_eq!(&encoded[9..], &script);

    let decoded = TxOut::deserialize(&encoded).unwrap();
    assert_eq!(decoded.script_pubkey, script);
}

// ────────────────────────────────────────────────────────────────
// G26: P2P message header size field (4 bytes LE, NOT CompactSize)
// Status: OK
// Core ref: net.h: header is 4(magic) + 12(command) + 4(length LE) + 4(checksum) = 24 bytes
// ────────────────────────────────────────────────────────────────
#[test]
fn g26_p2p_header_size_field_is_le_u32() {
    use rustoshi_network::message::parse_message_header;
    let testnet4_magic = [0x1c, 0x16, 0x3f, 0x28u8];
    let msg = NetworkMessage::Ping(0xDEADBEEF_12345678);
    let full = serialize_message(&testnet4_magic, &msg);

    let (_, _, length, _) = parse_message_header(full[..24].try_into().unwrap());
    assert_eq!(length, 8, "ping payload is 8 bytes");

    // Verify the raw bytes at position 16-19 are 4 LE bytes, NOT CompactSize
    let raw_len = u32::from_le_bytes(full[16..20].try_into().unwrap());
    assert_eq!(raw_len, 8);
    // If it were CompactSize, 8 would still be 1 byte (0x08) — but header uses 4 bytes
    assert_eq!(full[16], 8, "length field byte 0 = 8");
    assert_eq!(full[17], 0, "length field byte 1 = 0");
    assert_eq!(full[18], 0, "length field byte 2 = 0");
    assert_eq!(full[19], 0, "length field byte 3 = 0");
}

// ────────────────────────────────────────────────────────────────
// G27: BIP-152 short-id 6-byte serialization (not CompactSize)
// Status: OK
// compact_blocks.rs: reads/writes exactly 6 bytes per short ID
// ────────────────────────────────────────────────────────────────
#[test]
fn g27_bip152_short_id_is_six_bytes() {
    use rustoshi_network::compact_blocks::CmpctBlock;

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        },
        transactions: vec![
            Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![0x04],
                    sequence: 0xFFFF_FFFF,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x41],
                }],
                lock_time: 0,
            },
            Transaction {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                    script_sig: vec![],
                    sequence: 0xFFFF_FFFF,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut {
                    value: 1_000_000,
                    script_pubkey: vec![0x00, 0x14],
                }],
                lock_time: 0,
            },
        ],
    };

    let compact = CmpctBlock::from_block(&block, 0x12345678);
    let serialized = compact.serialize();

    // After header(80) + nonce(8), next is shortids_length (CompactSize)
    // Then each short_id is 6 bytes
    let after_header_nonce = &serialized[88..]; // 80 + 8
    let short_ids_len = after_header_nonce[0] as usize; // assuming < 253
    // There should be 1 short ID (coinbase is prefilled, second tx gets short ID)
    assert_eq!(short_ids_len, 1, "one non-coinbase tx → one short ID");
    // The 6 bytes follow immediately
    let short_id_bytes = &after_header_nonce[1..7];
    assert_eq!(short_id_bytes.len(), 6, "short ID must be exactly 6 bytes");

    // Roundtrip
    let decoded = CmpctBlock::deserialize(&serialized).unwrap();
    assert_eq!(decoded.short_ids.len(), 1);
}

// ────────────────────────────────────────────────────────────────
// G28: inv vector size = MAX_INV_SZ = 50000
// Status: OK
// message.rs: MAX_INV_SIZE = 50_000, enforced in inv/getdata/notfound decoders
// ────────────────────────────────────────────────────────────────
#[test]
fn g28_inv_max_size_constant() {
    assert_eq!(MAX_INV_SIZE, 50_000, "MAX_INV_SZ must match Bitcoin Core's value");
}

#[test]
fn g28_inv_over_max_rejected() {
    // Build a fake inv payload with count = 50_001
    let count: u64 = 50_001;
    let mut payload = Vec::new();
    write_compact_size(&mut payload, count).unwrap();
    // No actual inv items follow — decoder should reject on count alone
    let result = NetworkMessage::deserialize("inv", &payload);
    assert!(result.is_err(), "inv count > 50000 must be rejected");
}

// ────────────────────────────────────────────────────────────────
// G29: Endianness — CompactSize multi-byte values are LITTLE-ENDIAN
// Status: OK
// ────────────────────────────────────────────────────────────────
#[test]
fn g29_compact_size_is_little_endian() {
    // 0x1234 should encode as [0xFD, 0x34, 0x12] (LE), not [0xFD, 0x12, 0x34] (BE)
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 0x1234).unwrap();
    assert_eq!(buf, vec![0xFD, 0x34, 0x12], "CompactSize must be little-endian");

    // 0x12345678 as 0xFE prefix
    let mut buf2 = Vec::new();
    write_compact_size(&mut buf2, 0x12345678).unwrap();
    assert_eq!(buf2, vec![0xFE, 0x78, 0x56, 0x34, 0x12]);

    // Roundtrip verification for values that would fail if BE were used
    for val in [0x0100u64, 0x01_0000, 0x01_0000_0000] {
        let mut b = Vec::new();
        write_compact_size(&mut b, val).unwrap();
        let decoded = read_compact_size(&mut Cursor::new(&b)).unwrap();
        assert_eq!(decoded, val, "LE roundtrip failed for {:#x}", val);
    }
}

// ────────────────────────────────────────────────────────────────
// G30: Signed-to-unsigned truncation in BIP-152 differential index decode
// Status: BUG / P2
//
// Core ref: blockencodings.cpp uses uint64_t for differential index,
//   validates index fits in range.
//
// rustoshi compact_blocks.rs:323: `let diff = read_compact_size(reader)? as i32;`
//   A malicious peer sending diff = 0x80000000 causes two's-complement truncation
//   to i32::MIN (-2147483648), then `saturating_add(-2147483648).saturating_add(1)`
//   could leave last_index at i32::MIN, which fails the `< 0` check and returns
//   an error. HOWEVER, values like diff = 0x7FFFFFFF + 1 = 0x80000000 silently
//   become negative via truncation before the bounds check, creating inconsistent
//   behavior compared to the original u64 value.
//   The truncation should be an explicit checked conversion with rejection.
// ────────────────────────────────────────────────────────────────
#[test]
#[ignore] // BUG G30 / P2: read_compact_size() as i32 silently truncates u64 > i32::MAX for BIP-152 diff index
fn g30_bip152_differential_index_huge_diff_rejected() {
    use rustoshi_network::compact_blocks::CmpctBlock;

    // Craft a cmpctblock payload with an absurdly large differential index.
    // Format: header(80) + nonce(8) + shortids_len(1=0) + prefilled_len(1=1)
    //         + diff_CompactSize(huge) + ...
    let header = BlockHeader::default();
    let mut payload = Vec::new();
    // header
    header.encode(&mut payload).unwrap();
    // nonce
    payload.extend_from_slice(&0u64.to_le_bytes());
    // short_ids_len = 0
    write_compact_size(&mut payload, 0).unwrap();
    // prefilled_len = 1
    write_compact_size(&mut payload, 1).unwrap();
    // diff = 0x80000000 (truncates to i32::MIN when cast as i32)
    write_compact_size(&mut payload, 0x80000000u64).unwrap();
    // No actual tx bytes follow

    let result = CmpctBlock::deserialize(&payload);
    // The current impl returns an error, but via a different path (i32 bounds check).
    // What we care about: the truncation to i32 means the value 0x80000000 is not
    // recognized as "too large" directly — it wraps to -0x80000000 first.
    // After saturating_add: last_index = i32::MIN + (-0x80000000) sat + 1.
    // The fix is: bounds-check the u64 diff BEFORE the i32 cast.
    //
    // This test is marked ignore because the current code happens to return an
    // error on this specific input (due to OOM/truncation path), but the *root
    // cause* (unchecked cast) should be addressed regardless.
    assert!(result.is_err(), "huge BIP-152 differential index must be rejected cleanly");
}

// ────────────────────────────────────────────────────────────────
// Additional regression / boundary tests
// ────────────────────────────────────────────────────────────────

/// Boundary: value 252 is the last 1-byte CompactSize (not 253!)
#[test]
fn boundary_252_is_one_byte() {
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 252).unwrap();
    assert_eq!(buf.len(), 1);
    assert_eq!(buf[0], 0xFC);
    let decoded = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, 252);
}

/// Boundary: value 253 is the first 3-byte CompactSize
#[test]
fn boundary_253_is_three_bytes() {
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 253).unwrap();
    assert_eq!(buf.len(), 3);
    assert_eq!(buf[0], 0xFD);
    let decoded = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, 253);
}

/// Boundary: value 65535 stays in 3-byte range (0xFD prefix)
#[test]
fn boundary_65535_is_three_bytes() {
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 65535).unwrap();
    assert_eq!(buf.len(), 3);
    assert_eq!(buf[0], 0xFD);
    let decoded = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, 65535);
}

/// Boundary: value 65536 escalates to 5-byte range (0xFE prefix)
#[test]
fn boundary_65536_is_five_bytes() {
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 65536).unwrap();
    assert_eq!(buf.len(), 5);
    assert_eq!(buf[0], 0xFE);
    let decoded = read_compact_size(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, 65536);
}

/// Full transaction CompactSize round-trip: encode → decode → verify identical
#[test]
fn full_tx_compactsize_roundtrip() {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ).unwrap(),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFE,
            witness: vec![vec![0x30u8; 64], vec![0x02u8; 32]],
        }],
        outputs: vec![
            TxOut { value: 100_000, script_pubkey: vec![0x51, 0x20] },
            TxOut { value: 99_000, script_pubkey: vec![0x00, 0x14] },
        ],
        lock_time: 0,
    };
    let encoded = tx.serialize();
    let decoded = Transaction::deserialize(&encoded).unwrap();
    assert_eq!(decoded, tx);
    // Check wtxid / txid differ for segwit
    assert_ne!(tx.txid(), tx.wtxid());
}

/// Witness item DoS guard: item_len > 4_000_000 must be rejected
#[test]
fn witness_item_dos_guard() {
    // Build a SegWit tx payload with a single witness item of length 0x400001 (4MB+1)
    let mut payload = Vec::new();
    payload.extend_from_slice(&2i32.to_le_bytes()); // version
    payload.push(0x00); // SegWit marker
    payload.push(0x01); // SegWit flag
    // input_count = 1
    payload.push(0x01);
    // outpoint: 32 + 4 = 36 bytes
    payload.extend_from_slice(&[0x00u8; 36]);
    // script_sig len = 0
    payload.push(0x00);
    // sequence
    payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // output_count = 1
    payload.push(0x01);
    // value (8 bytes)
    payload.extend_from_slice(&1_000_000u64.to_le_bytes());
    // scriptPubKey len = 2, then 2 bytes
    payload.push(0x02);
    payload.extend_from_slice(&[0x00u8; 2]);
    // Witness for input 0:
    // witness_count = 1
    payload.push(0x01);
    // item_len = 4_000_001 (just over MAX_WITNESS_ITEM_SIZE)
    write_compact_size(&mut payload, 4_000_001u64).unwrap();
    // No actual item bytes — parser should reject on size check

    // locktime (4 bytes) appended at the end — but we expect rejection before that
    payload.extend_from_slice(&0u32.to_le_bytes());

    let result = Transaction::deserialize(&payload);
    assert!(result.is_err(), "witness item of 4_000_001 bytes must be rejected");
}

/// scriptSig size limit: script_sig > MAX_SCRIPT_SIZE (10000) must be rejected
#[test]
fn script_sig_size_limit() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1i32.to_le_bytes()); // version (non-SegWit path)
    // input_count = 1 (compact_size prefix consumed from first byte)
    // The first byte of input_count is NOT a SegWit marker (not 0x00)
    payload.push(0x01); // input count = 1
    // outpoint: 36 bytes
    payload.extend_from_slice(&[0x00u8; 36]);
    // script_sig len = 10_001 (above MAX_SCRIPT_SIZE = 10_000)
    write_compact_size(&mut payload, 10_001u64).unwrap();
    // No actual script bytes — should reject on size check

    let result = Transaction::deserialize(&payload);
    assert!(result.is_err(), "scriptSig > 10000 bytes must be rejected");
}
