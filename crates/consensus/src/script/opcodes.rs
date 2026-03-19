//! Bitcoin Script opcodes.
//!
//! This module defines all Bitcoin Script opcodes, including push operations,
//! flow control, stack manipulation, arithmetic, cryptographic operations,
//! and locktime checks.
//!
//! Note: Opcodes 0x01-0x4b are "push N bytes" where N is the opcode value.
//! These are handled specially by the interpreter.

// Bitcoin opcodes use a naming convention with OP_ prefix and underscores.
// This matches the convention used in Bitcoin Core and the BIPs.
#![allow(non_camel_case_types)]

/// All Bitcoin Script opcodes.
///
/// The opcodes are categorized as:
/// - Push value (0x00-0x60): Push data or small integers
/// - Flow control (0x61-0x6a): Conditionals, verify, return
/// - Stack (0x6b-0x7d): Stack manipulation
/// - Splice (0x7e-0x82): String operations (mostly disabled)
/// - Bitwise logic (0x83-0x8a): Bitwise operations (mostly disabled)
/// - Arithmetic (0x8b-0xa5): Numeric operations
/// - Crypto (0xa6-0xba): Hashing and signature verification
/// - Locktime (0xb0-0xb9): BIP-65/112 locktime checks and NOPs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // ==================== Push value ====================
    /// Push empty byte array (false)
    OP_0 = 0x00,
    // 0x01-0x4b: Push N bytes where N is the opcode value
    OP_PUSHBYTES_1 = 0x01,
    OP_PUSHBYTES_2 = 0x02,
    OP_PUSHBYTES_3 = 0x03,
    OP_PUSHBYTES_4 = 0x04,
    OP_PUSHBYTES_5 = 0x05,
    OP_PUSHBYTES_6 = 0x06,
    OP_PUSHBYTES_7 = 0x07,
    OP_PUSHBYTES_8 = 0x08,
    OP_PUSHBYTES_9 = 0x09,
    OP_PUSHBYTES_10 = 0x0a,
    OP_PUSHBYTES_11 = 0x0b,
    OP_PUSHBYTES_12 = 0x0c,
    OP_PUSHBYTES_13 = 0x0d,
    OP_PUSHBYTES_14 = 0x0e,
    OP_PUSHBYTES_15 = 0x0f,
    OP_PUSHBYTES_16 = 0x10,
    OP_PUSHBYTES_17 = 0x11,
    OP_PUSHBYTES_18 = 0x12,
    OP_PUSHBYTES_19 = 0x13,
    OP_PUSHBYTES_20 = 0x14,
    OP_PUSHBYTES_21 = 0x15,
    OP_PUSHBYTES_22 = 0x16,
    OP_PUSHBYTES_23 = 0x17,
    OP_PUSHBYTES_24 = 0x18,
    OP_PUSHBYTES_25 = 0x19,
    OP_PUSHBYTES_26 = 0x1a,
    OP_PUSHBYTES_27 = 0x1b,
    OP_PUSHBYTES_28 = 0x1c,
    OP_PUSHBYTES_29 = 0x1d,
    OP_PUSHBYTES_30 = 0x1e,
    OP_PUSHBYTES_31 = 0x1f,
    OP_PUSHBYTES_32 = 0x20,
    OP_PUSHBYTES_33 = 0x21,
    OP_PUSHBYTES_34 = 0x22,
    OP_PUSHBYTES_35 = 0x23,
    OP_PUSHBYTES_36 = 0x24,
    OP_PUSHBYTES_37 = 0x25,
    OP_PUSHBYTES_38 = 0x26,
    OP_PUSHBYTES_39 = 0x27,
    OP_PUSHBYTES_40 = 0x28,
    OP_PUSHBYTES_41 = 0x29,
    OP_PUSHBYTES_42 = 0x2a,
    OP_PUSHBYTES_43 = 0x2b,
    OP_PUSHBYTES_44 = 0x2c,
    OP_PUSHBYTES_45 = 0x2d,
    OP_PUSHBYTES_46 = 0x2e,
    OP_PUSHBYTES_47 = 0x2f,
    OP_PUSHBYTES_48 = 0x30,
    OP_PUSHBYTES_49 = 0x31,
    OP_PUSHBYTES_50 = 0x32,
    OP_PUSHBYTES_51 = 0x33,
    OP_PUSHBYTES_52 = 0x34,
    OP_PUSHBYTES_53 = 0x35,
    OP_PUSHBYTES_54 = 0x36,
    OP_PUSHBYTES_55 = 0x37,
    OP_PUSHBYTES_56 = 0x38,
    OP_PUSHBYTES_57 = 0x39,
    OP_PUSHBYTES_58 = 0x3a,
    OP_PUSHBYTES_59 = 0x3b,
    OP_PUSHBYTES_60 = 0x3c,
    OP_PUSHBYTES_61 = 0x3d,
    OP_PUSHBYTES_62 = 0x3e,
    OP_PUSHBYTES_63 = 0x3f,
    OP_PUSHBYTES_64 = 0x40,
    OP_PUSHBYTES_65 = 0x41,
    OP_PUSHBYTES_66 = 0x42,
    OP_PUSHBYTES_67 = 0x43,
    OP_PUSHBYTES_68 = 0x44,
    OP_PUSHBYTES_69 = 0x45,
    OP_PUSHBYTES_70 = 0x46,
    OP_PUSHBYTES_71 = 0x47,
    OP_PUSHBYTES_72 = 0x48,
    OP_PUSHBYTES_73 = 0x49,
    OP_PUSHBYTES_74 = 0x4a,
    OP_PUSHBYTES_75 = 0x4b,
    /// Next byte is length, then push that many bytes
    OP_PUSHDATA1 = 0x4c,
    /// Next 2 bytes (LE) are length, then push that many bytes
    OP_PUSHDATA2 = 0x4d,
    /// Next 4 bytes (LE) are length, then push that many bytes
    OP_PUSHDATA4 = 0x4e,
    /// Push -1
    OP_1NEGATE = 0x4f,
    /// Reserved (causes failure if executed)
    OP_RESERVED = 0x50,
    /// Push 1 (also called OP_TRUE)
    OP_1 = 0x51,
    /// Push 2
    OP_2 = 0x52,
    /// Push 3
    OP_3 = 0x53,
    /// Push 4
    OP_4 = 0x54,
    /// Push 5
    OP_5 = 0x55,
    /// Push 6
    OP_6 = 0x56,
    /// Push 7
    OP_7 = 0x57,
    /// Push 8
    OP_8 = 0x58,
    /// Push 9
    OP_9 = 0x59,
    /// Push 10
    OP_10 = 0x5a,
    /// Push 11
    OP_11 = 0x5b,
    /// Push 12
    OP_12 = 0x5c,
    /// Push 13
    OP_13 = 0x5d,
    /// Push 14
    OP_14 = 0x5e,
    /// Push 15
    OP_15 = 0x5f,
    /// Push 16
    OP_16 = 0x60,

    // ==================== Flow control ====================
    /// No operation
    OP_NOP = 0x61,
    /// Reserved (causes failure if executed). In tapscript: OP_SUCCESS
    OP_VER = 0x62,
    /// If top stack value is true, execute statements after
    OP_IF = 0x63,
    /// If top stack value is false, execute statements after
    OP_NOTIF = 0x64,
    /// Invalid opcode (causes failure immediately)
    OP_VERIF = 0x65,
    /// Invalid opcode (causes failure immediately)
    OP_VERNOTIF = 0x66,
    /// Execute statements if preceding IF/NOTIF was not executed
    OP_ELSE = 0x67,
    /// End IF/ELSE block
    OP_ENDIF = 0x68,
    /// Remove top element and fail if false
    OP_VERIFY = 0x69,
    /// Mark transaction as invalid (provably unspendable)
    OP_RETURN = 0x6a,

    // ==================== Stack ====================
    /// Move top element to alt stack
    OP_TOALTSTACK = 0x6b,
    /// Move top element from alt stack to main stack
    OP_FROMALTSTACK = 0x6c,
    /// Drop top 2 elements
    OP_2DROP = 0x6d,
    /// Duplicate top 2 elements
    OP_2DUP = 0x6e,
    /// Duplicate top 3 elements
    OP_3DUP = 0x6f,
    /// Copy 3rd and 4th items to top
    OP_2OVER = 0x70,
    /// Move 5th and 6th items to top
    OP_2ROT = 0x71,
    /// Swap top two pairs
    OP_2SWAP = 0x72,
    /// Duplicate top if nonzero
    OP_IFDUP = 0x73,
    /// Push stack depth
    OP_DEPTH = 0x74,
    /// Remove top element
    OP_DROP = 0x75,
    /// Duplicate top element
    OP_DUP = 0x76,
    /// Remove second element
    OP_NIP = 0x77,
    /// Copy second element to top
    OP_OVER = 0x78,
    /// Copy nth element to top (n is top stack value)
    OP_PICK = 0x79,
    /// Move nth element to top (n is top stack value)
    OP_ROLL = 0x7a,
    /// Rotate top 3 elements
    OP_ROT = 0x7b,
    /// Swap top 2 elements
    OP_SWAP = 0x7c,
    /// Copy top and insert before second
    OP_TUCK = 0x7d,

    // ==================== Splice (mostly disabled) ====================
    /// Concatenate two byte arrays (disabled)
    OP_CAT = 0x7e,
    /// Return substring (disabled)
    OP_SUBSTR = 0x7f,
    /// Keep left N bytes (disabled)
    OP_LEFT = 0x80,
    /// Keep right N bytes (disabled)
    OP_RIGHT = 0x81,
    /// Push string length
    OP_SIZE = 0x82,

    // ==================== Bitwise logic (mostly disabled) ====================
    /// Bitwise invert (disabled)
    OP_INVERT = 0x83,
    /// Bitwise AND (disabled)
    OP_AND = 0x84,
    /// Bitwise OR (disabled)
    OP_OR = 0x85,
    /// Bitwise XOR (disabled)
    OP_XOR = 0x86,
    /// Push 1 if byte arrays equal, 0 otherwise
    OP_EQUAL = 0x87,
    /// OP_EQUAL then OP_VERIFY
    OP_EQUALVERIFY = 0x88,
    /// Reserved (causes failure if executed). In tapscript: OP_SUCCESS
    OP_RESERVED1 = 0x89,
    /// Reserved (causes failure if executed). In tapscript: OP_SUCCESS
    OP_RESERVED2 = 0x8a,

    // ==================== Arithmetic ====================
    /// Add 1 to top element
    OP_1ADD = 0x8b,
    /// Subtract 1 from top element
    OP_1SUB = 0x8c,
    /// Multiply by 2 (disabled)
    OP_2MUL = 0x8d,
    /// Divide by 2 (disabled)
    OP_2DIV = 0x8e,
    /// Negate top element
    OP_NEGATE = 0x8f,
    /// Absolute value of top element
    OP_ABS = 0x90,
    /// Boolean NOT: 0 becomes 1, nonzero becomes 0
    OP_NOT = 0x91,
    /// Push 1 if top is nonzero, 0 otherwise
    OP_0NOTEQUAL = 0x92,
    /// Add top two elements
    OP_ADD = 0x93,
    /// Subtract: second minus top
    OP_SUB = 0x94,
    /// Multiply (disabled)
    OP_MUL = 0x95,
    /// Divide (disabled)
    OP_DIV = 0x96,
    /// Modulo (disabled)
    OP_MOD = 0x97,
    /// Left shift (disabled)
    OP_LSHIFT = 0x98,
    /// Right shift (disabled)
    OP_RSHIFT = 0x99,
    /// Boolean AND: push 1 if both nonzero
    OP_BOOLAND = 0x9a,
    /// Boolean OR: push 1 if either nonzero
    OP_BOOLOR = 0x9b,
    /// Push 1 if numbers equal
    OP_NUMEQUAL = 0x9c,
    /// OP_NUMEQUAL then OP_VERIFY
    OP_NUMEQUALVERIFY = 0x9d,
    /// Push 1 if numbers not equal
    OP_NUMNOTEQUAL = 0x9e,
    /// Push 1 if second < top
    OP_LESSTHAN = 0x9f,
    /// Push 1 if second > top
    OP_GREATERTHAN = 0xa0,
    /// Push 1 if second <= top
    OP_LESSTHANOREQUAL = 0xa1,
    /// Push 1 if second >= top
    OP_GREATERTHANOREQUAL = 0xa2,
    /// Push smaller of top two
    OP_MIN = 0xa3,
    /// Push larger of top two
    OP_MAX = 0xa4,
    /// Push 1 if x is within [min, max): min <= x < max
    OP_WITHIN = 0xa5,

    // ==================== Crypto ====================
    /// RIPEMD-160 hash of top element
    OP_RIPEMD160 = 0xa6,
    /// SHA-1 hash of top element
    OP_SHA1 = 0xa7,
    /// SHA-256 hash of top element
    OP_SHA256 = 0xa8,
    /// HASH160: RIPEMD-160(SHA-256(x))
    OP_HASH160 = 0xa9,
    /// HASH256: SHA-256(SHA-256(x)) (double SHA-256)
    OP_HASH256 = 0xaa,
    /// Mark code position for signature checking
    OP_CODESEPARATOR = 0xab,
    /// Verify signature against pubkey
    OP_CHECKSIG = 0xac,
    /// OP_CHECKSIG then OP_VERIFY
    OP_CHECKSIGVERIFY = 0xad,
    /// Verify m-of-n multisig
    OP_CHECKMULTISIG = 0xae,
    /// OP_CHECKMULTISIG then OP_VERIFY
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // ==================== Locktime / expansion ====================
    /// No operation (reserved for future soft-forks)
    OP_NOP1 = 0xb0,
    /// Check locktime (BIP-65)
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    /// Check sequence (BIP-112)
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    /// No operation (reserved)
    OP_NOP4 = 0xb3,
    /// No operation (reserved)
    OP_NOP5 = 0xb4,
    /// No operation (reserved)
    OP_NOP6 = 0xb5,
    /// No operation (reserved)
    OP_NOP7 = 0xb6,
    /// No operation (reserved)
    OP_NOP8 = 0xb7,
    /// No operation (reserved)
    OP_NOP9 = 0xb8,
    /// No operation (reserved)
    OP_NOP10 = 0xb9,

    // ==================== Tapscript ====================
    /// Tapscript signature check with accumulator (BIP-342)
    OP_CHECKSIGADD = 0xba,

    // ==================== Invalid ====================
    /// Invalid opcode (0xbb-0xfe are undefined, 0xff is explicitly invalid)
    OP_INVALIDOPCODE = 0xff,
}

impl Opcode {
    /// Create an opcode from a raw byte value.
    ///
    /// Unknown opcodes in the range 0xbb-0xfe are mapped to OP_INVALIDOPCODE.
    /// These would be OP_SUCCESS opcodes in tapscript context.
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            0x00 => Opcode::OP_0,
            0x01 => Opcode::OP_PUSHBYTES_1,
            0x02 => Opcode::OP_PUSHBYTES_2,
            0x03 => Opcode::OP_PUSHBYTES_3,
            0x04 => Opcode::OP_PUSHBYTES_4,
            0x05 => Opcode::OP_PUSHBYTES_5,
            0x06 => Opcode::OP_PUSHBYTES_6,
            0x07 => Opcode::OP_PUSHBYTES_7,
            0x08 => Opcode::OP_PUSHBYTES_8,
            0x09 => Opcode::OP_PUSHBYTES_9,
            0x0a => Opcode::OP_PUSHBYTES_10,
            0x0b => Opcode::OP_PUSHBYTES_11,
            0x0c => Opcode::OP_PUSHBYTES_12,
            0x0d => Opcode::OP_PUSHBYTES_13,
            0x0e => Opcode::OP_PUSHBYTES_14,
            0x0f => Opcode::OP_PUSHBYTES_15,
            0x10 => Opcode::OP_PUSHBYTES_16,
            0x11 => Opcode::OP_PUSHBYTES_17,
            0x12 => Opcode::OP_PUSHBYTES_18,
            0x13 => Opcode::OP_PUSHBYTES_19,
            0x14 => Opcode::OP_PUSHBYTES_20,
            0x15 => Opcode::OP_PUSHBYTES_21,
            0x16 => Opcode::OP_PUSHBYTES_22,
            0x17 => Opcode::OP_PUSHBYTES_23,
            0x18 => Opcode::OP_PUSHBYTES_24,
            0x19 => Opcode::OP_PUSHBYTES_25,
            0x1a => Opcode::OP_PUSHBYTES_26,
            0x1b => Opcode::OP_PUSHBYTES_27,
            0x1c => Opcode::OP_PUSHBYTES_28,
            0x1d => Opcode::OP_PUSHBYTES_29,
            0x1e => Opcode::OP_PUSHBYTES_30,
            0x1f => Opcode::OP_PUSHBYTES_31,
            0x20 => Opcode::OP_PUSHBYTES_32,
            0x21 => Opcode::OP_PUSHBYTES_33,
            0x22 => Opcode::OP_PUSHBYTES_34,
            0x23 => Opcode::OP_PUSHBYTES_35,
            0x24 => Opcode::OP_PUSHBYTES_36,
            0x25 => Opcode::OP_PUSHBYTES_37,
            0x26 => Opcode::OP_PUSHBYTES_38,
            0x27 => Opcode::OP_PUSHBYTES_39,
            0x28 => Opcode::OP_PUSHBYTES_40,
            0x29 => Opcode::OP_PUSHBYTES_41,
            0x2a => Opcode::OP_PUSHBYTES_42,
            0x2b => Opcode::OP_PUSHBYTES_43,
            0x2c => Opcode::OP_PUSHBYTES_44,
            0x2d => Opcode::OP_PUSHBYTES_45,
            0x2e => Opcode::OP_PUSHBYTES_46,
            0x2f => Opcode::OP_PUSHBYTES_47,
            0x30 => Opcode::OP_PUSHBYTES_48,
            0x31 => Opcode::OP_PUSHBYTES_49,
            0x32 => Opcode::OP_PUSHBYTES_50,
            0x33 => Opcode::OP_PUSHBYTES_51,
            0x34 => Opcode::OP_PUSHBYTES_52,
            0x35 => Opcode::OP_PUSHBYTES_53,
            0x36 => Opcode::OP_PUSHBYTES_54,
            0x37 => Opcode::OP_PUSHBYTES_55,
            0x38 => Opcode::OP_PUSHBYTES_56,
            0x39 => Opcode::OP_PUSHBYTES_57,
            0x3a => Opcode::OP_PUSHBYTES_58,
            0x3b => Opcode::OP_PUSHBYTES_59,
            0x3c => Opcode::OP_PUSHBYTES_60,
            0x3d => Opcode::OP_PUSHBYTES_61,
            0x3e => Opcode::OP_PUSHBYTES_62,
            0x3f => Opcode::OP_PUSHBYTES_63,
            0x40 => Opcode::OP_PUSHBYTES_64,
            0x41 => Opcode::OP_PUSHBYTES_65,
            0x42 => Opcode::OP_PUSHBYTES_66,
            0x43 => Opcode::OP_PUSHBYTES_67,
            0x44 => Opcode::OP_PUSHBYTES_68,
            0x45 => Opcode::OP_PUSHBYTES_69,
            0x46 => Opcode::OP_PUSHBYTES_70,
            0x47 => Opcode::OP_PUSHBYTES_71,
            0x48 => Opcode::OP_PUSHBYTES_72,
            0x49 => Opcode::OP_PUSHBYTES_73,
            0x4a => Opcode::OP_PUSHBYTES_74,
            0x4b => Opcode::OP_PUSHBYTES_75,
            0x4c => Opcode::OP_PUSHDATA1,
            0x4d => Opcode::OP_PUSHDATA2,
            0x4e => Opcode::OP_PUSHDATA4,
            0x4f => Opcode::OP_1NEGATE,
            0x50 => Opcode::OP_RESERVED,
            0x51 => Opcode::OP_1,
            0x52 => Opcode::OP_2,
            0x53 => Opcode::OP_3,
            0x54 => Opcode::OP_4,
            0x55 => Opcode::OP_5,
            0x56 => Opcode::OP_6,
            0x57 => Opcode::OP_7,
            0x58 => Opcode::OP_8,
            0x59 => Opcode::OP_9,
            0x5a => Opcode::OP_10,
            0x5b => Opcode::OP_11,
            0x5c => Opcode::OP_12,
            0x5d => Opcode::OP_13,
            0x5e => Opcode::OP_14,
            0x5f => Opcode::OP_15,
            0x60 => Opcode::OP_16,
            0x61 => Opcode::OP_NOP,
            0x62 => Opcode::OP_VER,
            0x63 => Opcode::OP_IF,
            0x64 => Opcode::OP_NOTIF,
            0x65 => Opcode::OP_VERIF,
            0x66 => Opcode::OP_VERNOTIF,
            0x67 => Opcode::OP_ELSE,
            0x68 => Opcode::OP_ENDIF,
            0x69 => Opcode::OP_VERIFY,
            0x6a => Opcode::OP_RETURN,
            0x6b => Opcode::OP_TOALTSTACK,
            0x6c => Opcode::OP_FROMALTSTACK,
            0x6d => Opcode::OP_2DROP,
            0x6e => Opcode::OP_2DUP,
            0x6f => Opcode::OP_3DUP,
            0x70 => Opcode::OP_2OVER,
            0x71 => Opcode::OP_2ROT,
            0x72 => Opcode::OP_2SWAP,
            0x73 => Opcode::OP_IFDUP,
            0x74 => Opcode::OP_DEPTH,
            0x75 => Opcode::OP_DROP,
            0x76 => Opcode::OP_DUP,
            0x77 => Opcode::OP_NIP,
            0x78 => Opcode::OP_OVER,
            0x79 => Opcode::OP_PICK,
            0x7a => Opcode::OP_ROLL,
            0x7b => Opcode::OP_ROT,
            0x7c => Opcode::OP_SWAP,
            0x7d => Opcode::OP_TUCK,
            0x7e => Opcode::OP_CAT,
            0x7f => Opcode::OP_SUBSTR,
            0x80 => Opcode::OP_LEFT,
            0x81 => Opcode::OP_RIGHT,
            0x82 => Opcode::OP_SIZE,
            0x83 => Opcode::OP_INVERT,
            0x84 => Opcode::OP_AND,
            0x85 => Opcode::OP_OR,
            0x86 => Opcode::OP_XOR,
            0x87 => Opcode::OP_EQUAL,
            0x88 => Opcode::OP_EQUALVERIFY,
            0x89 => Opcode::OP_RESERVED1,
            0x8a => Opcode::OP_RESERVED2,
            0x8b => Opcode::OP_1ADD,
            0x8c => Opcode::OP_1SUB,
            0x8d => Opcode::OP_2MUL,
            0x8e => Opcode::OP_2DIV,
            0x8f => Opcode::OP_NEGATE,
            0x90 => Opcode::OP_ABS,
            0x91 => Opcode::OP_NOT,
            0x92 => Opcode::OP_0NOTEQUAL,
            0x93 => Opcode::OP_ADD,
            0x94 => Opcode::OP_SUB,
            0x95 => Opcode::OP_MUL,
            0x96 => Opcode::OP_DIV,
            0x97 => Opcode::OP_MOD,
            0x98 => Opcode::OP_LSHIFT,
            0x99 => Opcode::OP_RSHIFT,
            0x9a => Opcode::OP_BOOLAND,
            0x9b => Opcode::OP_BOOLOR,
            0x9c => Opcode::OP_NUMEQUAL,
            0x9d => Opcode::OP_NUMEQUALVERIFY,
            0x9e => Opcode::OP_NUMNOTEQUAL,
            0x9f => Opcode::OP_LESSTHAN,
            0xa0 => Opcode::OP_GREATERTHAN,
            0xa1 => Opcode::OP_LESSTHANOREQUAL,
            0xa2 => Opcode::OP_GREATERTHANOREQUAL,
            0xa3 => Opcode::OP_MIN,
            0xa4 => Opcode::OP_MAX,
            0xa5 => Opcode::OP_WITHIN,
            0xa6 => Opcode::OP_RIPEMD160,
            0xa7 => Opcode::OP_SHA1,
            0xa8 => Opcode::OP_SHA256,
            0xa9 => Opcode::OP_HASH160,
            0xaa => Opcode::OP_HASH256,
            0xab => Opcode::OP_CODESEPARATOR,
            0xac => Opcode::OP_CHECKSIG,
            0xad => Opcode::OP_CHECKSIGVERIFY,
            0xae => Opcode::OP_CHECKMULTISIG,
            0xaf => Opcode::OP_CHECKMULTISIGVERIFY,
            0xb0 => Opcode::OP_NOP1,
            0xb1 => Opcode::OP_CHECKLOCKTIMEVERIFY,
            0xb2 => Opcode::OP_CHECKSEQUENCEVERIFY,
            0xb3 => Opcode::OP_NOP4,
            0xb4 => Opcode::OP_NOP5,
            0xb5 => Opcode::OP_NOP6,
            0xb6 => Opcode::OP_NOP7,
            0xb7 => Opcode::OP_NOP8,
            0xb8 => Opcode::OP_NOP9,
            0xb9 => Opcode::OP_NOP10,
            0xba => Opcode::OP_CHECKSIGADD,
            // 0xbb-0xfe are undefined (would be OP_SUCCESS in tapscript)
            // 0xff is explicitly invalid
            _ => Opcode::OP_INVALIDOPCODE,
        }
    }

    /// Returns true if this is a disabled opcode that must cause immediate failure.
    ///
    /// These opcodes were disabled early in Bitcoin's history due to security
    /// concerns or implementation complexity. They cause script failure even
    /// when in a non-executing branch.
    pub fn is_disabled(&self) -> bool {
        matches!(
            self,
            Opcode::OP_CAT
                | Opcode::OP_SUBSTR
                | Opcode::OP_LEFT
                | Opcode::OP_RIGHT
                | Opcode::OP_INVERT
                | Opcode::OP_AND
                | Opcode::OP_OR
                | Opcode::OP_XOR
                | Opcode::OP_2MUL
                | Opcode::OP_2DIV
                | Opcode::OP_MUL
                | Opcode::OP_DIV
                | Opcode::OP_MOD
                | Opcode::OP_LSHIFT
                | Opcode::OP_RSHIFT
        )
    }

    /// Returns true if this opcode is a push operation (0x00-0x60 or PUSHDATA).
    pub fn is_push(&self) -> bool {
        let byte = *self as u8;
        byte <= 0x60 || matches!(
            self,
            Opcode::OP_PUSHDATA1 | Opcode::OP_PUSHDATA2 | Opcode::OP_PUSHDATA4
        )
    }

    /// Returns true if this opcode is always invalid (even in non-executing branches).
    pub fn is_always_illegal(&self) -> bool {
        matches!(self, Opcode::OP_VERIF | Opcode::OP_VERNOTIF)
    }

    /// Returns true if this is an OP_SUCCESS opcode in tapscript context (BIP-342).
    ///
    /// In tapscript, these opcodes cause unconditional script success.
    /// Per BIP-342, the OP_SUCCESSx opcodes are:
    ///   0x50, 0x62, 0x7e-0x81, 0x83-0x86, 0x89-0x8a, 0x8d-0x8e,
    ///   0x95-0xb9, 0xbb-0xfe
    /// Note: 0xba (OP_CHECKSIGADD) is NOT OP_SUCCESS - it's a valid tapscript opcode.
    pub fn is_tapscript_success(&self) -> bool {
        let byte = *self as u8;
        matches!(
            self,
            Opcode::OP_RESERVED | Opcode::OP_VER | Opcode::OP_RESERVED1 | Opcode::OP_RESERVED2
        ) || (0x7e..=0x81).contains(&byte)  // OP_CAT through OP_RIGHT
            || (0x83..=0x86).contains(&byte)  // OP_INVERT through OP_XOR
            || matches!(self, Opcode::OP_2MUL | Opcode::OP_2DIV)  // 0x8d-0x8e
            || (0x95..=0xb9).contains(&byte)  // OP_MUL through OP_NOP10
            || (0xbb..=0xfe).contains(&byte)
    }

    /// Convert to raw byte value.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        Opcode::from_u8(byte)
    }
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> Self {
        op as u8
    }
}

impl std::fmt::Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_from_u8_round_trip() {
        // Test all known opcodes
        for byte in 0x00..=0xba {
            let op = Opcode::from_u8(byte);
            if op != Opcode::OP_INVALIDOPCODE {
                assert_eq!(op.to_u8(), byte, "Round-trip failed for byte 0x{:02x}", byte);
            }
        }
    }

    #[test]
    fn push_bytes_range() {
        // OP_PUSHBYTES_1 through OP_PUSHBYTES_75 should map correctly
        for n in 1..=75u8 {
            let op = Opcode::from_u8(n);
            assert!(op.is_push(), "OP_PUSHBYTES_{} should be a push opcode", n);
            assert_eq!(op.to_u8(), n);
        }
    }

    #[test]
    fn disabled_opcodes() {
        // All disabled opcodes should be identified
        assert!(Opcode::OP_CAT.is_disabled());
        assert!(Opcode::OP_SUBSTR.is_disabled());
        assert!(Opcode::OP_LEFT.is_disabled());
        assert!(Opcode::OP_RIGHT.is_disabled());
        assert!(Opcode::OP_INVERT.is_disabled());
        assert!(Opcode::OP_AND.is_disabled());
        assert!(Opcode::OP_OR.is_disabled());
        assert!(Opcode::OP_XOR.is_disabled());
        assert!(Opcode::OP_2MUL.is_disabled());
        assert!(Opcode::OP_2DIV.is_disabled());
        assert!(Opcode::OP_MUL.is_disabled());
        assert!(Opcode::OP_DIV.is_disabled());
        assert!(Opcode::OP_MOD.is_disabled());
        assert!(Opcode::OP_LSHIFT.is_disabled());
        assert!(Opcode::OP_RSHIFT.is_disabled());

        // Non-disabled opcodes
        assert!(!Opcode::OP_ADD.is_disabled());
        assert!(!Opcode::OP_SUB.is_disabled());
        assert!(!Opcode::OP_DUP.is_disabled());
    }

    #[test]
    fn small_integer_opcodes() {
        // OP_1 through OP_16 represent values 1-16
        assert_eq!(Opcode::OP_1 as u8, 0x51);
        assert_eq!(Opcode::OP_16 as u8, 0x60);

        for n in 1..=16u8 {
            let byte = 0x50 + n;
            let op = Opcode::from_u8(byte);
            assert!(op.is_push(), "OP_{} should be a push opcode", n);
        }
    }

    #[test]
    fn always_illegal_opcodes() {
        assert!(Opcode::OP_VERIF.is_always_illegal());
        assert!(Opcode::OP_VERNOTIF.is_always_illegal());
        assert!(!Opcode::OP_VER.is_always_illegal());
        assert!(!Opcode::OP_IF.is_always_illegal());
    }

    #[test]
    fn undefined_opcodes_map_to_invalid() {
        // 0xbb-0xfe (except recognized ones) should map to OP_INVALIDOPCODE
        for byte in 0xbb..=0xfe {
            let op = Opcode::from_u8(byte);
            assert_eq!(
                op,
                Opcode::OP_INVALIDOPCODE,
                "Byte 0x{:02x} should be OP_INVALIDOPCODE",
                byte
            );
        }
        // 0xff is explicitly invalid
        assert_eq!(Opcode::from_u8(0xff), Opcode::OP_INVALIDOPCODE);
    }
}
