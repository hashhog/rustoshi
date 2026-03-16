//! Miniscript: a structured representation of Bitcoin Script.
//!
//! Miniscript enables analysis, composition, and generic signing of Bitcoin
//! spending policies. It provides:
//!
//! - A type system ensuring script correctness
//! - Parsing of miniscript expressions
//! - Compilation to Bitcoin Script
//! - Witness satisfaction generation
//! - Analysis of script properties
//!
//! # Type System
//!
//! Each miniscript expression has a type (B, V, K, W) and properties
//! that determine how it can be composed with other expressions.
//!
//! # Example
//!
//! ```rust,ignore
//! use rustoshi_wallet::miniscript::{Miniscript, ScriptContext};
//!
//! // Parse a 2-of-3 threshold policy
//! let ms = Miniscript::parse("thresh(2,pk(A),pk(B),pk(C))")?;
//!
//! // Compile to Bitcoin Script
//! let script = ms.compile()?;
//!
//! // Compute witness for satisfaction
//! let witness = ms.satisfy(&available_sigs)?;
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

// =============================================================================
// Type System
// =============================================================================

/// The basic type of a miniscript expression.
///
/// Each expression has exactly one of these types, which determines
/// how it interacts with the stack and what operations can follow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BasicType {
    /// Base expression: consumes inputs, pushes 0 (false) or non-zero (true).
    /// Required at the top level of a script.
    B,
    /// Verify expression: consumes inputs, pushes nothing, aborts on failure.
    /// Cannot be dissatisfied (always succeeds or aborts).
    V,
    /// Key expression: pushes a public key for signature checking.
    /// Becomes B when followed by OP_CHECKSIG.
    K,
    /// Wrapped expression: takes input one below top, pushes result.
    /// Used for OP_SWAP compositions.
    W,
}

/// Type properties that characterize miniscript expression behavior.
///
/// These properties are used to validate composition rules and determine
/// satisfaction strategies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TypeProperties {
    // Stack consumption properties
    /// Zero-arg: always consumes exactly 0 stack elements
    pub z: bool,
    /// One-arg: always consumes exactly 1 stack element
    pub o: bool,
    /// Nonzero: satisfactions never need a zero top stack element
    pub n: bool,

    // Dissatisfaction and unit properties
    /// Dissatisfiable: a dissatisfaction exists
    pub d: bool,
    /// Unit: dissatisfaction pushes exactly empty vector
    pub u: bool,

    // Malleability properties
    /// Expression: dissatisfaction is non-malleable and unique
    pub e: bool,
    /// Forced: dissatisfactions always require a signature
    pub f: bool,
    /// Safe: satisfactions always require a signature
    pub s: bool,
    /// Non-malleable: non-malleable satisfaction exists
    pub m: bool,

    // Expensive verify property
    /// Last opcode is not EQUAL, CHECKSIG, or CHECKMULTISIG
    pub x: bool,

    // Timelock properties (for conflict detection)
    /// Contains relative time timelock (CSV with time flag)
    pub g: bool,
    /// Contains relative height timelock (CSV without time flag)
    pub h: bool,
    /// Contains absolute time timelock (CLTV >= 500000000)
    pub i: bool,
    /// Contains absolute height timelock (CLTV < 500000000)
    pub j: bool,
    /// All satisfactions don't mix heightlocks and timelocks
    pub k: bool,
}

/// Complete type information for a miniscript expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Type {
    /// The basic type (B, V, K, or W)
    pub base: BasicType,
    /// Additional type properties
    pub props: TypeProperties,
}

impl Type {
    /// Create a new type with the given base and properties.
    pub fn new(base: BasicType, props: TypeProperties) -> Self {
        Self { base, props }
    }

    /// Check if this type is valid (satisfies type system invariants).
    pub fn is_valid(&self) -> bool {
        let p = &self.props;

        // z conflicts with o
        if p.z && p.o {
            return false;
        }
        // n conflicts with z
        if p.n && p.z {
            return false;
        }
        // n conflicts with W
        if p.n && self.base == BasicType::W {
            return false;
        }
        // V conflicts with d (verify types can't be dissatisfied)
        if self.base == BasicType::V && p.d {
            return false;
        }
        // K implies u
        if self.base == BasicType::K && !p.u {
            return false;
        }
        // V conflicts with u
        if self.base == BasicType::V && p.u {
            return false;
        }
        // e conflicts with f
        if p.e && p.f {
            return false;
        }
        // e implies d
        if p.e && !p.d {
            return false;
        }
        // V conflicts with e
        if self.base == BasicType::V && p.e {
            return false;
        }
        // d conflicts with f
        if p.d && p.f {
            return false;
        }
        // V implies f
        if self.base == BasicType::V && !p.f {
            return false;
        }
        // K implies s
        if self.base == BasicType::K && !p.s {
            return false;
        }
        // z implies m
        if p.z && !p.m {
            return false;
        }
        // Timelock compatibility: k means no mixing
        if !p.k && ((p.g || p.h) && (p.i || p.j)) {
            // Has both relative and absolute, should have k=false
        }

        true
    }

    /// Check if this type is a valid top-level type.
    pub fn is_valid_top_level(&self) -> bool {
        self.is_valid() && self.base == BasicType::B
    }

    /// Check if this type represents a sane policy.
    ///
    /// A sane policy is valid, non-malleable, requires a signature,
    /// and has no timelock conflicts.
    pub fn is_sane(&self) -> bool {
        self.is_valid_top_level() && self.props.m && self.props.s && self.props.k
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.base)?;
        let p = &self.props;
        if p.z { write!(f, "z")?; }
        if p.o { write!(f, "o")?; }
        if p.n { write!(f, "n")?; }
        if p.d { write!(f, "d")?; }
        if p.u { write!(f, "u")?; }
        if p.e { write!(f, "e")?; }
        if p.f { write!(f, "f")?; }
        if p.s { write!(f, "s")?; }
        if p.m { write!(f, "m")?; }
        if p.x { write!(f, "x")?; }
        if p.k { write!(f, "k")?; }
        Ok(())
    }
}

// =============================================================================
// Script Context
// =============================================================================

/// The script execution context.
///
/// Different contexts have different rules for key sizes and available opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScriptContext {
    /// P2WSH context: 33-byte compressed keys, CHECKMULTISIG available
    P2wsh,
    /// Tapscript context: 32-byte x-only keys, CHECKSIGADD instead of CHECKMULTISIG
    Tapscript,
}

impl ScriptContext {
    /// Get the public key size for this context.
    pub fn pk_len(self) -> usize {
        match self {
            ScriptContext::P2wsh => 33,
            ScriptContext::Tapscript => 32,
        }
    }

    /// Get the signature size for this context (without sighash byte for tapscript default).
    pub fn sig_len(self) -> usize {
        match self {
            ScriptContext::P2wsh => 72, // DER signature + sighash byte
            ScriptContext::Tapscript => 64, // Schnorr signature (65 with non-default sighash)
        }
    }
}

// =============================================================================
// Miniscript Fragments (AST Nodes)
// =============================================================================

/// A miniscript fragment representing a spending condition.
///
/// Each fragment compiles to specific Bitcoin Script opcodes and has
/// associated type information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fragment<Pk: MiniscriptKey> {
    // === Leaf fragments ===
    /// Push 0 (false)
    False,
    /// Push 1 (true)
    True,

    /// Raw public key: `<key>`
    PkK(Pk),
    /// Public key hash: `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY`
    PkH(Pk),

    /// Relative timelock: `<n> OP_CHECKSEQUENCEVERIFY`
    Older(u32),
    /// Absolute timelock: `<n> OP_CHECKLOCKTIMEVERIFY`
    After(u32),

    /// SHA256 preimage: `OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL`
    Sha256([u8; 32]),
    /// HASH256 preimage: `OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL`
    Hash256([u8; 32]),
    /// RIPEMD160 preimage: `OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL`
    Ripemd160([u8; 20]),
    /// HASH160 preimage: `OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL`
    Hash160([u8; 20]),

    // === Wrapper fragments ===
    /// Alt stack wrapper: `OP_TOALTSTACK [X] OP_FROMALTSTACK`
    Alt(Box<Miniscript<Pk>>),
    /// Swap wrapper: `OP_SWAP [X]`
    Swap(Box<Miniscript<Pk>>),
    /// Check wrapper: `[X] OP_CHECKSIG`
    Check(Box<Miniscript<Pk>>),
    /// Dup-if wrapper: `OP_DUP OP_IF [X] OP_ENDIF`
    DupIf(Box<Miniscript<Pk>>),
    /// Verify wrapper: `[X] OP_VERIFY` or convert last opcode to VERIFY variant
    Verify(Box<Miniscript<Pk>>),
    /// Non-zero wrapper: `[X] OP_0NOTEQUAL`
    NonZero(Box<Miniscript<Pk>>),
    /// Zero-not-equal wrapper: `OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF`
    ZeroNotEqual(Box<Miniscript<Pk>>),

    // === Conjunctions ===
    /// AND with verify: `[X] [Y]` where X is V-type
    AndV(Box<Miniscript<Pk>>, Box<Miniscript<Pk>>),
    /// AND with boolean: `[X] [Y] OP_BOOLAND`
    AndB(Box<Miniscript<Pk>>, Box<Miniscript<Pk>>),
    /// Cascading AND: `[X] OP_NOTIF 0 OP_ELSE [Y] OP_ENDIF`
    AndOr(Box<Miniscript<Pk>>, Box<Miniscript<Pk>>, Box<Miniscript<Pk>>),

    // === Disjunctions ===
    /// OR with boolean: `[X] [Y] OP_BOOLOR`
    OrB(Box<Miniscript<Pk>>, Box<Miniscript<Pk>>),
    /// OR with cascade: `[X] OP_NOTIF [Y] OP_ENDIF`
    OrC(Box<Miniscript<Pk>>, Box<Miniscript<Pk>>),
    /// OR with dup: `[X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF`
    OrD(Box<Miniscript<Pk>>, Box<Miniscript<Pk>>),
    /// OR with if: `OP_IF [X] OP_ELSE [Y] OP_ENDIF`
    OrI(Box<Miniscript<Pk>>, Box<Miniscript<Pk>>),

    // === Thresholds ===
    /// K-of-N threshold: `[X1] [X2] OP_ADD ... [Xn] OP_ADD <k> OP_EQUAL`
    Thresh(usize, Vec<Miniscript<Pk>>),

    /// K-of-N multisig (P2WSH): `<k> <key1> ... <keyn> <n> OP_CHECKMULTISIG`
    Multi(usize, Vec<Pk>),

    /// K-of-N multisig (Tapscript): `<key1> OP_CHECKSIG <key2> OP_CHECKSIGADD ... <k> OP_NUMEQUAL`
    MultiA(usize, Vec<Pk>),
}

// =============================================================================
// Key Trait
// =============================================================================

/// Trait for public keys used in miniscript.
pub trait MiniscriptKey: Clone + Eq + std::hash::Hash + fmt::Debug + fmt::Display {
    /// The hash type for this key (for pkh).
    type Hash: Clone + Eq + std::hash::Hash + fmt::Debug;

    /// Get the hash of this key.
    fn to_pubkey_hash(&self) -> Self::Hash;

    /// Serialize this key for P2WSH context (33-byte compressed).
    fn serialize_p2wsh(&self) -> Vec<u8>;

    /// Serialize this key for Tapscript context (32-byte x-only).
    fn serialize_tapscript(&self) -> Vec<u8>;
}

/// A string-based key for parsing and display.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StrKey(pub String);

impl fmt::Display for StrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl MiniscriptKey for StrKey {
    type Hash = String;

    fn to_pubkey_hash(&self) -> Self::Hash {
        format!("hash({})", self.0)
    }

    fn serialize_p2wsh(&self) -> Vec<u8> {
        // For string keys, return placeholder
        vec![0x02; 33]
    }

    fn serialize_tapscript(&self) -> Vec<u8> {
        // For string keys, return placeholder
        vec![0x02; 32]
    }
}

// =============================================================================
// Miniscript Node
// =============================================================================

/// A miniscript expression with computed type information.
#[derive(Clone, Debug)]
pub struct Miniscript<Pk: MiniscriptKey> {
    /// The fragment at this node.
    pub fragment: Fragment<Pk>,
    /// The computed type of this expression.
    pub ty: Type,
    /// The script context (P2WSH or Tapscript).
    pub ctx: ScriptContext,
}

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    /// Create a new miniscript node, computing its type.
    pub fn new(fragment: Fragment<Pk>, ctx: ScriptContext) -> Result<Self, MiniscriptError> {
        let ty = compute_type(&fragment, ctx)?;
        Ok(Self { fragment, ty, ctx })
    }

    /// Check if this miniscript is valid.
    pub fn is_valid(&self) -> bool {
        self.ty.is_valid()
    }

    /// Check if this miniscript is valid as a top-level expression.
    pub fn is_valid_top_level(&self) -> bool {
        self.ty.is_valid_top_level()
    }

    /// Check if this miniscript represents a sane policy.
    pub fn is_sane(&self) -> bool {
        self.ty.is_sane()
    }
}

impl<Pk: MiniscriptKey> PartialEq for Miniscript<Pk> {
    fn eq(&self, other: &Self) -> bool {
        self.fragment == other.fragment && self.ctx == other.ctx
    }
}

impl<Pk: MiniscriptKey> Eq for Miniscript<Pk> {}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur when working with miniscript.
#[derive(Clone, Debug, thiserror::Error)]
pub enum MiniscriptError {
    /// Invalid type for composition.
    #[error("type error: {0}")]
    TypeError(String),

    /// Invalid syntax in expression.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Invalid threshold value.
    #[error("invalid threshold: k={k}, n={n}")]
    InvalidThreshold { k: usize, n: usize },

    /// Invalid timelock value.
    #[error("invalid timelock value: {0}")]
    InvalidTimelock(u32),

    /// Context mismatch.
    #[error("context error: {0}")]
    ContextError(String),

    /// Script exceeds size limits.
    #[error("script too large: {0} bytes")]
    ScriptTooLarge(usize),

    /// Satisfaction impossible.
    #[error("cannot satisfy: {0}")]
    Unsatisfiable(String),

    /// Timelock conflict in policy.
    #[error("timelock conflict: mixing height and time locks")]
    TimelockConflict,

    /// Invalid key.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid hash.
    #[error("invalid hash: {0}")]
    InvalidHash(String),

    /// Multi not allowed in tapscript.
    #[error("multi() not allowed in tapscript, use multi_a()")]
    MultiNotInTapscript,

    /// MultiA not allowed in P2WSH.
    #[error("multi_a() not allowed in P2WSH, use multi()")]
    MultiANotInP2wsh,
}

// =============================================================================
// Type Computation
// =============================================================================

/// Compute the type of a miniscript fragment.
fn compute_type<Pk: MiniscriptKey>(
    fragment: &Fragment<Pk>,
    ctx: ScriptContext,
) -> Result<Type, MiniscriptError> {
    use BasicType::*;
    use Fragment::*;

    let (base, props) = match fragment {
        False => {
            // Type: Bzudemsxk
            let props = TypeProperties {
                z: true,
                u: true,
                d: true,
                e: true,
                m: true,
                s: false,
                x: true,
                k: true,
                ..Default::default()
            };
            (B, props)
        }

        True => {
            // Type: Bzufmxk
            let props = TypeProperties {
                z: true,
                u: true,
                f: true,
                m: true,
                x: true,
                k: true,
                ..Default::default()
            };
            (B, props)
        }

        PkK(_) => {
            // Type: Konudemsxk
            let props = TypeProperties {
                o: true,
                n: true,
                u: true,
                d: true,
                e: true,
                m: true,
                s: true,
                x: true,
                k: true,
                ..Default::default()
            };
            (K, props)
        }

        PkH(_) => {
            // Type: Knudemsxk
            let props = TypeProperties {
                n: true,
                u: true,
                d: true,
                e: true,
                m: true,
                s: true,
                x: true,
                k: true,
                ..Default::default()
            };
            (K, props)
        }

        Older(n) => {
            if *n == 0 {
                return Err(MiniscriptError::InvalidTimelock(0));
            }
            // Type: Bzfmxk (with timelock properties)
            let is_time = (*n & (1 << 22)) != 0;
            let props = TypeProperties {
                z: true,
                f: true,
                m: true,
                x: true,
                g: is_time,  // relative time
                h: !is_time, // relative height
                k: true,
                ..Default::default()
            };
            (B, props)
        }

        After(n) => {
            if *n == 0 {
                return Err(MiniscriptError::InvalidTimelock(0));
            }
            // Type: Bzfmxk (with timelock properties)
            let is_time = *n >= 500_000_000;
            let props = TypeProperties {
                z: true,
                f: true,
                m: true,
                x: true,
                i: is_time,  // absolute time
                j: !is_time, // absolute height
                k: true,
                ..Default::default()
            };
            (B, props)
        }

        Sha256(_) | Hash256(_) | Ripemd160(_) | Hash160(_) => {
            // Type: Bonudems
            let props = TypeProperties {
                o: true,
                n: true,
                u: true,
                d: true,
                e: true,
                m: true,
                s: false,
                k: true,
                ..Default::default()
            };
            (B, props)
        }

        Alt(sub) => {
            // a:X - requires B type, produces W type
            if sub.ty.base != B {
                return Err(MiniscriptError::TypeError(
                    "alt wrapper requires B type".into(),
                ));
            }
            let x = &sub.ty.props;
            let props = TypeProperties {
                u: x.u,
                d: x.d,
                f: x.f,
                e: x.e,
                m: x.m,
                s: x.s,
                x: x.x,
                g: x.g,
                h: x.h,
                i: x.i,
                j: x.j,
                k: x.k,
                ..Default::default()
            };
            (W, props)
        }

        Swap(sub) => {
            // s:X - requires o type, produces W type
            if !sub.ty.props.o {
                return Err(MiniscriptError::TypeError(
                    "swap wrapper requires o property".into(),
                ));
            }
            let x = &sub.ty.props;
            let props = TypeProperties {
                u: x.u,
                d: x.d,
                f: x.f,
                e: x.e,
                m: x.m,
                s: x.s,
                x: x.x,
                g: x.g,
                h: x.h,
                i: x.i,
                j: x.j,
                k: x.k,
                ..Default::default()
            };
            (W, props)
        }

        Check(sub) => {
            // c:X - requires K type, produces B type
            if sub.ty.base != K {
                return Err(MiniscriptError::TypeError(
                    "check wrapper requires K type".into(),
                ));
            }
            let x = &sub.ty.props;
            let props = TypeProperties {
                o: x.o,
                n: x.n,
                u: true,
                d: x.d,
                e: x.e,
                m: x.m,
                s: true,
                k: x.k,
                g: x.g,
                h: x.h,
                i: x.i,
                j: x.j,
                ..Default::default()
            };
            (B, props)
        }

        DupIf(sub) => {
            // d:X - requires Vz type, produces B type
            if sub.ty.base != V {
                return Err(MiniscriptError::TypeError(
                    "dupif wrapper requires V type".into(),
                ));
            }
            let x = &sub.ty.props;
            let props = TypeProperties {
                o: x.z,
                u: true,
                d: true,
                e: x.z && x.f,
                m: x.m,
                s: x.s,
                x: true,
                g: x.g,
                h: x.h,
                i: x.i,
                j: x.j,
                k: x.k,
                ..Default::default()
            };
            (B, props)
        }

        Verify(sub) => {
            // v:X - requires B type, produces V type
            if sub.ty.base != B {
                return Err(MiniscriptError::TypeError(
                    "verify wrapper requires B type".into(),
                ));
            }
            let x = &sub.ty.props;
            let props = TypeProperties {
                z: x.z,
                o: x.o,
                n: x.n,
                f: true,
                m: x.m,
                s: x.s,
                g: x.g,
                h: x.h,
                i: x.i,
                j: x.j,
                k: x.k,
                ..Default::default()
            };
            (V, props)
        }

        NonZero(sub) => {
            // n:X - requires B type, produces B type with u
            if sub.ty.base != B {
                return Err(MiniscriptError::TypeError(
                    "nonzero wrapper requires B type".into(),
                ));
            }
            let x = &sub.ty.props;
            let props = TypeProperties {
                z: x.z,
                o: x.o,
                n: x.n,
                u: true,
                d: x.d,
                e: x.e,
                f: x.f,
                m: x.m,
                s: x.s,
                x: true,
                g: x.g,
                h: x.h,
                i: x.i,
                j: x.j,
                k: x.k,
            };
            (B, props)
        }

        ZeroNotEqual(sub) => {
            // j:X - requires Bno type, produces B type
            if sub.ty.base != B || !sub.ty.props.n || !sub.ty.props.o {
                return Err(MiniscriptError::TypeError(
                    "j wrapper requires Bno type".into(),
                ));
            }
            let x = &sub.ty.props;
            let props = TypeProperties {
                o: true,
                n: true,
                u: x.u,
                d: true,
                e: x.f && x.e,
                m: x.e && x.m,
                s: x.s,
                x: true,
                g: x.g,
                h: x.h,
                i: x.i,
                j: x.j,
                k: x.k,
                ..Default::default()
            };
            (B, props)
        }

        AndV(left, right) => {
            // and_v(X, Y) - requires V type for X
            if left.ty.base != V {
                return Err(MiniscriptError::TypeError(
                    "and_v requires V type for first argument".into(),
                ));
            }
            let x = &left.ty.props;
            let y = &right.ty.props;
            let base = right.ty.base;

            let props = TypeProperties {
                z: x.z && y.z,
                o: (x.z && y.o) || (x.o && y.z),
                n: x.n || (x.z && y.n),
                u: y.u,
                d: false, // and_v is never dissatisfiable
                f: true,
                m: x.m && y.m,
                s: x.s || y.s,
                x: y.x,
                g: x.g || y.g,
                h: x.h || y.h,
                i: x.i || y.i,
                j: x.j || y.j,
                k: x.k && y.k && !((x.g || y.g || x.h || y.h) && (x.i || y.i || x.j || y.j)
                    && ((x.g || y.g) != (x.i || y.i))),
                ..Default::default()
            };
            (base, props)
        }

        AndB(left, right) => {
            // and_b(X, Y) - requires B type for X, W type for Y
            if left.ty.base != B {
                return Err(MiniscriptError::TypeError(
                    "and_b requires B type for first argument".into(),
                ));
            }
            if right.ty.base != W {
                return Err(MiniscriptError::TypeError(
                    "and_b requires W type for second argument".into(),
                ));
            }
            let x = &left.ty.props;
            let y = &right.ty.props;

            let props = TypeProperties {
                z: x.z && y.z,
                o: (x.z && y.o) || (x.o && y.z),
                n: x.n || (x.z && y.n),
                u: true,
                d: x.d && y.d,
                e: x.e && y.e,
                m: x.m && y.m && (x.e || y.e || (x.d && y.d)),
                s: x.s || y.s,
                x: true,
                g: x.g || y.g,
                h: x.h || y.h,
                i: x.i || y.i,
                j: x.j || y.j,
                k: x.k && y.k,
                ..Default::default()
            };
            (B, props)
        }

        OrB(left, right) => {
            // or_b(X, Y) - requires Bd type for X, Wd type for Y
            if left.ty.base != B || !left.ty.props.d {
                return Err(MiniscriptError::TypeError(
                    "or_b requires Bd type for first argument".into(),
                ));
            }
            if right.ty.base != W || !right.ty.props.d {
                return Err(MiniscriptError::TypeError(
                    "or_b requires Wd type for second argument".into(),
                ));
            }
            let x = &left.ty.props;
            let y = &right.ty.props;

            let props = TypeProperties {
                z: x.z && y.z,
                o: (x.z && y.o) || (x.o && y.z),
                u: true,
                d: true,
                e: x.e && y.e,
                m: x.m && y.m && x.e && y.e,
                s: x.s && y.s,
                x: true,
                g: x.g || y.g,
                h: x.h || y.h,
                i: x.i || y.i,
                j: x.j || y.j,
                k: (x.k && y.k) && !((x.g || x.h) && (y.i || y.j)) && !((y.g || y.h) && (x.i || x.j)),
                ..Default::default()
            };
            (B, props)
        }

        OrC(left, right) => {
            // or_c(X, Y) - requires Bdu type for X, V type for Y
            if left.ty.base != B || !left.ty.props.d || !left.ty.props.u {
                return Err(MiniscriptError::TypeError(
                    "or_c requires Bdu type for first argument".into(),
                ));
            }
            if right.ty.base != V {
                return Err(MiniscriptError::TypeError(
                    "or_c requires V type for second argument".into(),
                ));
            }
            let x = &left.ty.props;
            let y = &right.ty.props;

            let props = TypeProperties {
                z: x.z && y.z,
                o: x.o && y.z,
                f: true,
                m: x.m && y.m && x.e,
                s: x.s || y.s,
                x: y.x,
                g: x.g || y.g,
                h: x.h || y.h,
                i: x.i || y.i,
                j: x.j || y.j,
                k: (x.k && y.k) && !((x.g || x.h) && (y.i || y.j)) && !((y.g || y.h) && (x.i || x.j)),
                ..Default::default()
            };
            (V, props)
        }

        OrD(left, right) => {
            // or_d(X, Y) - requires Bdu type for X, B type for Y
            if left.ty.base != B || !left.ty.props.d || !left.ty.props.u {
                return Err(MiniscriptError::TypeError(
                    "or_d requires Bdu type for first argument".into(),
                ));
            }
            if right.ty.base != B {
                return Err(MiniscriptError::TypeError(
                    "or_d requires B type for second argument".into(),
                ));
            }
            let x = &left.ty.props;
            let y = &right.ty.props;

            let props = TypeProperties {
                z: x.z && y.z,
                o: x.o && y.z,
                u: y.u,
                d: y.d,
                e: y.e,
                f: y.f,
                m: x.m && y.m && x.e,
                s: x.s || y.s,
                x: y.x,
                g: x.g || y.g,
                h: x.h || y.h,
                i: x.i || y.i,
                j: x.j || y.j,
                k: (x.k && y.k) && !((x.g || x.h) && (y.i || y.j)) && !((y.g || y.h) && (x.i || x.j)),
                ..Default::default()
            };
            (B, props)
        }

        OrI(left, right) => {
            // or_i(X, Y) - both must be same type
            if left.ty.base != right.ty.base {
                return Err(MiniscriptError::TypeError(
                    "or_i requires same type for both arguments".into(),
                ));
            }
            let x = &left.ty.props;
            let y = &right.ty.props;
            let base = left.ty.base;

            let props = TypeProperties {
                o: x.z && y.z,
                u: x.u && y.u,
                d: x.d || y.d,
                e: (x.e && y.f) || (x.f && y.e),
                f: x.f && y.f,
                m: x.m && y.m && (x.s || y.s),
                s: x.s && y.s,
                x: x.x || y.x,
                g: x.g || y.g,
                h: x.h || y.h,
                i: x.i || y.i,
                j: x.j || y.j,
                k: (x.k && y.k) && !((x.g || x.h) && (y.i || y.j)) && !((y.g || y.h) && (x.i || x.j)),
                ..Default::default()
            };
            (base, props)
        }

        AndOr(cond, if_true, if_false) => {
            // andor(X, Y, Z)
            if cond.ty.base != B || !cond.ty.props.d || !cond.ty.props.u {
                return Err(MiniscriptError::TypeError(
                    "andor requires Bdu type for condition".into(),
                ));
            }
            if if_true.ty.base != if_false.ty.base {
                return Err(MiniscriptError::TypeError(
                    "andor requires same type for both branches".into(),
                ));
            }
            let x = &cond.ty.props;
            let y = &if_true.ty.props;
            let z = &if_false.ty.props;
            let base = if_true.ty.base;

            let props = TypeProperties {
                z: x.z && y.z && z.z,
                o: x.z && y.z && z.o,
                u: y.u && z.u,
                d: z.d,
                e: z.e && (x.s || y.f),
                f: z.f && (x.s || y.f),
                m: x.m && y.m && z.m && x.e && (x.s || y.s || z.s),
                s: (x.s || y.s) && z.s,
                x: y.x || z.x,
                g: x.g || y.g || z.g,
                h: x.h || y.h || z.h,
                i: x.i || y.i || z.i,
                j: x.j || y.j || z.j,
                k: x.k && y.k && z.k,
                ..Default::default()
            };
            (base, props)
        }

        Thresh(k, subs) => {
            let n = subs.len();
            if *k == 0 || *k > n {
                return Err(MiniscriptError::InvalidThreshold { k: *k, n });
            }
            if n == 0 {
                return Err(MiniscriptError::InvalidThreshold { k: *k, n: 0 });
            }

            // First sub must be Bdu, rest must be Wdu
            if subs[0].ty.base != B || !subs[0].ty.props.d || !subs[0].ty.props.u {
                return Err(MiniscriptError::TypeError(
                    "thresh first argument requires Bdu type".into(),
                ));
            }
            for sub in &subs[1..] {
                if sub.ty.base != W || !sub.ty.props.d || !sub.ty.props.u {
                    return Err(MiniscriptError::TypeError(
                        "thresh arguments after first require Wdu type".into(),
                    ));
                }
            }

            let mut all_z = true;
            let mut all_m = true;
            let mut all_e = true;
            let mut any_s = false;
            let mut num_s = 0usize;
            let mut g = false;
            let mut h = false;
            let mut i = false;
            let mut j = false;
            let mut all_k = true;

            for sub in subs {
                all_z = all_z && sub.ty.props.z;
                all_m = all_m && sub.ty.props.m;
                all_e = all_e && sub.ty.props.e;
                if sub.ty.props.s {
                    any_s = true;
                    num_s += 1;
                }
                g = g || sub.ty.props.g;
                h = h || sub.ty.props.h;
                i = i || sub.ty.props.i;
                j = j || sub.ty.props.j;
                all_k = all_k && sub.ty.props.k;
            }

            let props = TypeProperties {
                z: all_z,
                o: all_z && n == *k,
                u: true,
                d: true,
                e: all_e,
                m: all_e && all_m && (num_s >= n - *k),
                s: any_s && *k == n,
                x: true,
                g,
                h,
                i,
                j,
                k: all_k && !((g || h) && (i || j)),
                ..Default::default()
            };
            (B, props)
        }

        Multi(k, keys) => {
            if ctx == ScriptContext::Tapscript {
                return Err(MiniscriptError::MultiNotInTapscript);
            }
            let n = keys.len();
            if *k == 0 || *k > n || n > 20 {
                return Err(MiniscriptError::InvalidThreshold { k: *k, n });
            }

            // Type: Bnudemsxk
            let props = TypeProperties {
                n: true,
                u: true,
                d: true,
                e: true,
                m: true,
                s: true,
                k: true,
                ..Default::default()
            };
            (B, props)
        }

        MultiA(k, keys) => {
            if ctx == ScriptContext::P2wsh {
                return Err(MiniscriptError::MultiANotInP2wsh);
            }
            let n = keys.len();
            if *k == 0 || *k > n {
                return Err(MiniscriptError::InvalidThreshold { k: *k, n });
            }

            // Type: Bnudemsxk
            let props = TypeProperties {
                n: true,
                u: true,
                d: true,
                e: true,
                m: true,
                s: true,
                k: true,
                ..Default::default()
            };
            (B, props)
        }
    };

    let ty = Type::new(base, props);
    if !ty.is_valid() {
        return Err(MiniscriptError::TypeError(format!(
            "computed type {} is invalid",
            ty
        )));
    }

    Ok(ty)
}

// =============================================================================
// Parsing
// =============================================================================

impl Miniscript<StrKey> {
    /// Parse a miniscript expression from a string.
    pub fn parse(s: &str, ctx: ScriptContext) -> Result<Self, MiniscriptError> {
        parse_miniscript(s.trim(), ctx)
    }
}

/// Parse a miniscript expression.
fn parse_miniscript(s: &str, ctx: ScriptContext) -> Result<Miniscript<StrKey>, MiniscriptError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(MiniscriptError::ParseError("empty expression".into()));
    }

    // Check for wrapper prefixes (a:, s:, c:, d:, v:, j:, n:, t:, l:, u:)
    if s.len() > 2 && s.chars().nth(1) == Some(':') {
        let prefix = s.chars().next().unwrap();
        let rest = &s[2..];
        return parse_wrapper(prefix, rest, ctx);
    }

    // Check for constants
    if s == "0" {
        return Miniscript::new(Fragment::False, ctx);
    }
    if s == "1" {
        return Miniscript::new(Fragment::True, ctx);
    }

    // Check for function-style expressions
    if let Some(open) = s.find('(') {
        if !s.ends_with(')') {
            return Err(MiniscriptError::ParseError("missing closing parenthesis".into()));
        }
        let func = &s[..open];
        let args = &s[open + 1..s.len() - 1];
        return parse_function(func, args, ctx);
    }

    Err(MiniscriptError::ParseError(format!("unrecognized expression: {}", s)))
}

/// Parse a wrapper expression (a:X, s:X, etc.).
fn parse_wrapper(
    prefix: char,
    rest: &str,
    ctx: ScriptContext,
) -> Result<Miniscript<StrKey>, MiniscriptError> {
    let inner = parse_miniscript(rest, ctx)?;

    match prefix {
        'a' => Miniscript::new(Fragment::Alt(Box::new(inner)), ctx),
        's' => Miniscript::new(Fragment::Swap(Box::new(inner)), ctx),
        'c' => Miniscript::new(Fragment::Check(Box::new(inner)), ctx),
        'd' => Miniscript::new(Fragment::DupIf(Box::new(inner)), ctx),
        'v' => Miniscript::new(Fragment::Verify(Box::new(inner)), ctx),
        'j' => Miniscript::new(Fragment::ZeroNotEqual(Box::new(inner)), ctx),
        'n' => Miniscript::new(Fragment::NonZero(Box::new(inner)), ctx),
        't' => {
            // t:X = and_v(X, 1)
            let true_node = Miniscript::new(Fragment::True, ctx)?;
            Miniscript::new(Fragment::AndV(Box::new(inner), Box::new(true_node)), ctx)
        }
        'l' => {
            // l:X = or_i(0, X)
            let false_node = Miniscript::new(Fragment::False, ctx)?;
            Miniscript::new(Fragment::OrI(Box::new(false_node), Box::new(inner)), ctx)
        }
        'u' => {
            // u:X = or_i(X, 0)
            let false_node = Miniscript::new(Fragment::False, ctx)?;
            Miniscript::new(Fragment::OrI(Box::new(inner), Box::new(false_node)), ctx)
        }
        _ => Err(MiniscriptError::ParseError(format!("unknown wrapper: {}", prefix))),
    }
}

/// Parse a function-style expression.
fn parse_function(
    func: &str,
    args: &str,
    ctx: ScriptContext,
) -> Result<Miniscript<StrKey>, MiniscriptError> {
    match func {
        "pk" => {
            // pk(KEY) = c:pk_k(KEY)
            let key = parse_key(args)?;
            let pk_k = Miniscript::new(Fragment::PkK(key), ctx)?;
            Miniscript::new(Fragment::Check(Box::new(pk_k)), ctx)
        }
        "pk_k" => {
            let key = parse_key(args)?;
            Miniscript::new(Fragment::PkK(key), ctx)
        }
        "pk_h" => {
            let key = parse_key(args)?;
            Miniscript::new(Fragment::PkH(key), ctx)
        }
        "pkh" => {
            // pkh(KEY) = c:pk_h(KEY)
            let key = parse_key(args)?;
            let pk_h = Miniscript::new(Fragment::PkH(key), ctx)?;
            Miniscript::new(Fragment::Check(Box::new(pk_h)), ctx)
        }
        "older" => {
            let n: u32 = args.parse().map_err(|_| {
                MiniscriptError::ParseError(format!("invalid number: {}", args))
            })?;
            Miniscript::new(Fragment::Older(n), ctx)
        }
        "after" => {
            let n: u32 = args.parse().map_err(|_| {
                MiniscriptError::ParseError(format!("invalid number: {}", args))
            })?;
            Miniscript::new(Fragment::After(n), ctx)
        }
        "sha256" => {
            let hash = parse_hash32(args)?;
            Miniscript::new(Fragment::Sha256(hash), ctx)
        }
        "hash256" => {
            let hash = parse_hash32(args)?;
            Miniscript::new(Fragment::Hash256(hash), ctx)
        }
        "ripemd160" => {
            let hash = parse_hash20(args)?;
            Miniscript::new(Fragment::Ripemd160(hash), ctx)
        }
        "hash160" => {
            let hash = parse_hash20(args)?;
            Miniscript::new(Fragment::Hash160(hash), ctx)
        }
        "and_v" => {
            let parts = split_args(args, 2)?;
            let left = parse_miniscript(&parts[0], ctx)?;
            let right = parse_miniscript(&parts[1], ctx)?;
            Miniscript::new(Fragment::AndV(Box::new(left), Box::new(right)), ctx)
        }
        "and_b" => {
            let parts = split_args(args, 2)?;
            let left = parse_miniscript(&parts[0], ctx)?;
            let right = parse_miniscript(&parts[1], ctx)?;
            Miniscript::new(Fragment::AndB(Box::new(left), Box::new(right)), ctx)
        }
        "or_b" => {
            let parts = split_args(args, 2)?;
            let left = parse_miniscript(&parts[0], ctx)?;
            let right = parse_miniscript(&parts[1], ctx)?;
            Miniscript::new(Fragment::OrB(Box::new(left), Box::new(right)), ctx)
        }
        "or_c" => {
            let parts = split_args(args, 2)?;
            let left = parse_miniscript(&parts[0], ctx)?;
            let right = parse_miniscript(&parts[1], ctx)?;
            Miniscript::new(Fragment::OrC(Box::new(left), Box::new(right)), ctx)
        }
        "or_d" => {
            let parts = split_args(args, 2)?;
            let left = parse_miniscript(&parts[0], ctx)?;
            let right = parse_miniscript(&parts[1], ctx)?;
            Miniscript::new(Fragment::OrD(Box::new(left), Box::new(right)), ctx)
        }
        "or_i" => {
            let parts = split_args(args, 2)?;
            let left = parse_miniscript(&parts[0], ctx)?;
            let right = parse_miniscript(&parts[1], ctx)?;
            Miniscript::new(Fragment::OrI(Box::new(left), Box::new(right)), ctx)
        }
        "andor" => {
            let parts = split_args(args, 3)?;
            let cond = parse_miniscript(&parts[0], ctx)?;
            let if_true = parse_miniscript(&parts[1], ctx)?;
            let if_false = parse_miniscript(&parts[2], ctx)?;
            Miniscript::new(
                Fragment::AndOr(Box::new(cond), Box::new(if_true), Box::new(if_false)),
                ctx,
            )
        }
        "thresh" => {
            let parts = split_args_variadic(args)?;
            if parts.len() < 2 {
                return Err(MiniscriptError::ParseError(
                    "thresh requires at least 2 arguments".into(),
                ));
            }
            let k: usize = parts[0].parse().map_err(|_| {
                MiniscriptError::ParseError(format!("invalid threshold: {}", parts[0]))
            })?;
            let subs: Result<Vec<_>, _> = parts[1..]
                .iter()
                .map(|s| parse_miniscript(s, ctx))
                .collect();
            Miniscript::new(Fragment::Thresh(k, subs?), ctx)
        }
        "multi" => {
            let parts = split_args_variadic(args)?;
            if parts.len() < 2 {
                return Err(MiniscriptError::ParseError(
                    "multi requires at least 2 arguments".into(),
                ));
            }
            let k: usize = parts[0].parse().map_err(|_| {
                MiniscriptError::ParseError(format!("invalid threshold: {}", parts[0]))
            })?;
            let keys: Vec<StrKey> = parts[1..].iter().map(|s| parse_key(s).unwrap()).collect();
            Miniscript::new(Fragment::Multi(k, keys), ctx)
        }
        "multi_a" => {
            let parts = split_args_variadic(args)?;
            if parts.len() < 2 {
                return Err(MiniscriptError::ParseError(
                    "multi_a requires at least 2 arguments".into(),
                ));
            }
            let k: usize = parts[0].parse().map_err(|_| {
                MiniscriptError::ParseError(format!("invalid threshold: {}", parts[0]))
            })?;
            let keys: Vec<StrKey> = parts[1..].iter().map(|s| parse_key(s).unwrap()).collect();
            Miniscript::new(Fragment::MultiA(k, keys), ctx)
        }
        _ => Err(MiniscriptError::ParseError(format!("unknown function: {}", func))),
    }
}

/// Parse a key expression.
fn parse_key(s: &str) -> Result<StrKey, MiniscriptError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(MiniscriptError::InvalidKey("empty key".into()));
    }
    Ok(StrKey(s.to_string()))
}

/// Parse a 32-byte hash.
fn parse_hash32(s: &str) -> Result<[u8; 32], MiniscriptError> {
    let s = s.trim();
    let bytes = hex::decode(s).map_err(|e| MiniscriptError::InvalidHash(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(MiniscriptError::InvalidHash(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a 20-byte hash.
fn parse_hash20(s: &str) -> Result<[u8; 20], MiniscriptError> {
    let s = s.trim();
    let bytes = hex::decode(s).map_err(|e| MiniscriptError::InvalidHash(e.to_string()))?;
    if bytes.len() != 20 {
        return Err(MiniscriptError::InvalidHash(format!(
            "expected 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Split arguments at depth-0 commas.
fn split_args(s: &str, expected: usize) -> Result<Vec<String>, MiniscriptError> {
    let parts = split_args_variadic(s)?;
    if parts.len() != expected {
        return Err(MiniscriptError::ParseError(format!(
            "expected {} arguments, got {}",
            expected,
            parts.len()
        )));
    }
    Ok(parts)
}

/// Split arguments at depth-0 commas, returning variable number of parts.
fn split_args_variadic(s: &str) -> Result<Vec<String>, MiniscriptError> {
    let mut result = Vec::new();
    let mut depth = 0;
    let mut start = 0;

    for (i, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                result.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }

    let last = s[start..].trim();
    if !last.is_empty() {
        result.push(last.to_string());
    }

    Ok(result)
}

// =============================================================================
// Script Compilation
// =============================================================================

// Opcode constants
const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;
const OP_TOALTSTACK: u8 = 0x6b;
const OP_FROMALTSTACK: u8 = 0x6c;
const OP_2DROP: u8 = 0x6d;
const OP_IFDUP: u8 = 0x73;
const OP_DUP: u8 = 0x76;
const OP_SWAP: u8 = 0x7c;
const OP_SIZE: u8 = 0x82;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_0NOTEQUAL: u8 = 0x92;
const OP_ADD: u8 = 0x93;
const OP_BOOLAND: u8 = 0x9a;
const OP_BOOLOR: u8 = 0x9b;
const OP_NUMEQUAL: u8 = 0x9c;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_RIPEMD160: u8 = 0xa6;
const OP_SHA256: u8 = 0xa8;
const OP_HASH160: u8 = 0xa9;
const OP_HASH256: u8 = 0xaa;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_CHECKSIGADD: u8 = 0xba;

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    /// Compile this miniscript to Bitcoin Script bytes.
    pub fn compile(&self) -> Result<Vec<u8>, MiniscriptError> {
        self.compile_inner(false)
    }

    /// Compile with an optional VERIFY suffix.
    fn compile_inner(&self, verify: bool) -> Result<Vec<u8>, MiniscriptError> {
        use Fragment::*;
        let mut script = Vec::new();

        match &self.fragment {
            False => {
                script.push(OP_0);
            }

            True => {
                script.push(OP_1);
            }

            PkK(pk) => {
                let pk_bytes = match self.ctx {
                    ScriptContext::P2wsh => pk.serialize_p2wsh(),
                    ScriptContext::Tapscript => pk.serialize_tapscript(),
                };
                push_bytes(&mut script, &pk_bytes);
            }

            PkH(pk) => {
                // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY
                script.push(OP_DUP);
                script.push(OP_HASH160);
                let pk_bytes = match self.ctx {
                    ScriptContext::P2wsh => pk.serialize_p2wsh(),
                    ScriptContext::Tapscript => pk.serialize_tapscript(),
                };
                let hash = rustoshi_crypto::hashes::hash160(&pk_bytes);
                push_bytes(&mut script, &hash.0);
                script.push(OP_EQUALVERIFY);
            }

            Older(n) => {
                push_scriptnum(&mut script, *n as i64);
                script.push(OP_CHECKSEQUENCEVERIFY);
            }

            After(n) => {
                push_scriptnum(&mut script, *n as i64);
                script.push(OP_CHECKLOCKTIMEVERIFY);
            }

            Sha256(hash) => {
                // OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL[VERIFY]
                script.push(OP_SIZE);
                push_scriptnum(&mut script, 32);
                script.push(OP_EQUALVERIFY);
                script.push(OP_SHA256);
                push_bytes(&mut script, hash);
                if verify {
                    script.push(OP_EQUALVERIFY);
                } else {
                    script.push(OP_EQUAL);
                }
            }

            Hash256(hash) => {
                script.push(OP_SIZE);
                push_scriptnum(&mut script, 32);
                script.push(OP_EQUALVERIFY);
                script.push(OP_HASH256);
                push_bytes(&mut script, hash);
                if verify {
                    script.push(OP_EQUALVERIFY);
                } else {
                    script.push(OP_EQUAL);
                }
            }

            Ripemd160(hash) => {
                script.push(OP_SIZE);
                push_scriptnum(&mut script, 32);
                script.push(OP_EQUALVERIFY);
                script.push(OP_RIPEMD160);
                push_bytes(&mut script, hash);
                if verify {
                    script.push(OP_EQUALVERIFY);
                } else {
                    script.push(OP_EQUAL);
                }
            }

            Hash160(hash) => {
                script.push(OP_SIZE);
                push_scriptnum(&mut script, 32);
                script.push(OP_EQUALVERIFY);
                script.push(OP_HASH160);
                push_bytes(&mut script, hash);
                if verify {
                    script.push(OP_EQUALVERIFY);
                } else {
                    script.push(OP_EQUAL);
                }
            }

            Alt(sub) => {
                // OP_TOALTSTACK [X] OP_FROMALTSTACK
                script.push(OP_TOALTSTACK);
                script.extend(sub.compile_inner(verify)?);
                script.push(OP_FROMALTSTACK);
            }

            Swap(sub) => {
                // OP_SWAP [X]
                script.push(OP_SWAP);
                script.extend(sub.compile_inner(verify)?);
            }

            Check(sub) => {
                // [X] OP_CHECKSIG[VERIFY]
                script.extend(sub.compile()?);
                if verify {
                    script.push(OP_CHECKSIGVERIFY);
                } else {
                    script.push(OP_CHECKSIG);
                }
            }

            DupIf(sub) => {
                // OP_DUP OP_IF [X] OP_ENDIF
                script.push(OP_DUP);
                script.push(OP_IF);
                script.extend(sub.compile()?);
                script.push(OP_ENDIF);
                if verify {
                    script.push(OP_VERIFY);
                }
            }

            Verify(sub) => {
                // Compile inner with verify=true if possible
                if sub.ty.props.x {
                    // Last opcode is expensive, need explicit VERIFY
                    script.extend(sub.compile()?);
                    script.push(OP_VERIFY);
                } else {
                    // Can use -VERIFY variant
                    script.extend(sub.compile_inner(true)?);
                }
            }

            NonZero(sub) => {
                // [X] OP_0NOTEQUAL
                script.extend(sub.compile()?);
                script.push(OP_0NOTEQUAL);
                if verify {
                    script.push(OP_VERIFY);
                }
            }

            ZeroNotEqual(sub) => {
                // OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
                script.push(OP_SIZE);
                script.push(OP_0NOTEQUAL);
                script.push(OP_IF);
                script.extend(sub.compile()?);
                script.push(OP_ENDIF);
                if verify {
                    script.push(OP_VERIFY);
                }
            }

            AndV(left, right) => {
                // [X] [Y]
                script.extend(left.compile()?);
                script.extend(right.compile_inner(verify)?);
            }

            AndB(left, right) => {
                // [X] [Y] OP_BOOLAND
                script.extend(left.compile()?);
                script.extend(right.compile()?);
                script.push(OP_BOOLAND);
                if verify {
                    script.push(OP_VERIFY);
                }
            }

            OrB(left, right) => {
                // [X] [Y] OP_BOOLOR
                script.extend(left.compile()?);
                script.extend(right.compile()?);
                script.push(OP_BOOLOR);
                if verify {
                    script.push(OP_VERIFY);
                }
            }

            OrC(left, right) => {
                // [X] OP_NOTIF [Y] OP_ENDIF
                script.extend(left.compile()?);
                script.push(OP_NOTIF);
                script.extend(right.compile()?);
                script.push(OP_ENDIF);
            }

            OrD(left, right) => {
                // [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
                script.extend(left.compile()?);
                script.push(OP_IFDUP);
                script.push(OP_NOTIF);
                script.extend(right.compile_inner(verify)?);
                script.push(OP_ENDIF);
            }

            OrI(left, right) => {
                // OP_IF [X] OP_ELSE [Y] OP_ENDIF
                script.push(OP_IF);
                script.extend(left.compile_inner(verify)?);
                script.push(OP_ELSE);
                script.extend(right.compile_inner(verify)?);
                script.push(OP_ENDIF);
            }

            AndOr(cond, if_true, if_false) => {
                // [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
                script.extend(cond.compile()?);
                script.push(OP_NOTIF);
                script.extend(if_false.compile_inner(verify)?);
                script.push(OP_ELSE);
                script.extend(if_true.compile_inner(verify)?);
                script.push(OP_ENDIF);
            }

            Thresh(k, subs) => {
                // [X1] [X2] OP_ADD ... [Xn] OP_ADD <k> OP_EQUAL[VERIFY]
                if subs.is_empty() {
                    return Err(MiniscriptError::InvalidThreshold { k: *k, n: 0 });
                }
                script.extend(subs[0].compile()?);
                for sub in &subs[1..] {
                    script.extend(sub.compile()?);
                    script.push(OP_ADD);
                }
                push_scriptnum(&mut script, *k as i64);
                if verify {
                    script.push(OP_EQUALVERIFY);
                } else {
                    script.push(OP_EQUAL);
                }
            }

            Multi(k, keys) => {
                // <k> <key1> ... <keyn> <n> OP_CHECKMULTISIG[VERIFY]
                push_scriptnum(&mut script, *k as i64);
                for key in keys {
                    let pk_bytes = key.serialize_p2wsh();
                    push_bytes(&mut script, &pk_bytes);
                }
                push_scriptnum(&mut script, keys.len() as i64);
                if verify {
                    script.push(OP_CHECKMULTISIGVERIFY);
                } else {
                    script.push(OP_CHECKMULTISIG);
                }
            }

            MultiA(k, keys) => {
                // <key1> OP_CHECKSIG <key2> OP_CHECKSIGADD ... <k> OP_NUMEQUAL[VERIFY]
                if keys.is_empty() {
                    return Err(MiniscriptError::InvalidThreshold { k: *k, n: 0 });
                }
                let pk_bytes = keys[0].serialize_tapscript();
                push_bytes(&mut script, &pk_bytes);
                script.push(OP_CHECKSIG);
                for key in &keys[1..] {
                    let pk_bytes = key.serialize_tapscript();
                    push_bytes(&mut script, &pk_bytes);
                    script.push(OP_CHECKSIGADD);
                }
                push_scriptnum(&mut script, *k as i64);
                if verify {
                    script.push(OP_NUMEQUALVERIFY);
                } else {
                    script.push(OP_NUMEQUAL);
                }
            }
        }

        Ok(script)
    }
}

/// Push bytes onto a script with minimal encoding.
fn push_bytes(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(OP_0);
    } else if len <= 75 {
        script.push(len as u8);
        script.extend_from_slice(data);
    } else if len <= 255 {
        script.push(OP_PUSHDATA1);
        script.push(len as u8);
        script.extend_from_slice(data);
    } else if len <= 65535 {
        script.push(OP_PUSHDATA2);
        script.extend_from_slice(&(len as u16).to_le_bytes());
        script.extend_from_slice(data);
    } else {
        // OP_PUSHDATA4 - very large pushes
        script.push(0x4e);
        script.extend_from_slice(&(len as u32).to_le_bytes());
        script.extend_from_slice(data);
    }
}

/// Push a script number onto the script.
fn push_scriptnum(script: &mut Vec<u8>, n: i64) {
    if n == 0 {
        script.push(OP_0);
    } else if n == -1 {
        script.push(OP_1NEGATE);
    } else if n >= 1 && n <= 16 {
        script.push(OP_1 - 1 + n as u8);
    } else {
        // Encode as bytes
        let bytes = encode_scriptnum(n);
        push_bytes(script, &bytes);
    }
}

/// Encode a number as script number bytes.
fn encode_scriptnum(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }

    let neg = n < 0;
    let mut abs = if neg { -n } else { n } as u64;
    let mut result = Vec::new();

    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    // If the high bit is set, add a sign byte
    if result.last().map_or(false, |&b| b & 0x80 != 0) {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *result.last_mut().unwrap() |= 0x80;
    }

    result
}

// =============================================================================
// Satisfaction
// =============================================================================

/// A satisfier provides signatures, preimages, and timelock information.
pub trait Satisfier<Pk: MiniscriptKey> {
    /// Get a signature for the given key.
    fn lookup_sig(&self, pk: &Pk) -> Option<Vec<u8>>;

    /// Get the preimage for a SHA256 hash.
    fn lookup_sha256(&self, hash: &[u8; 32]) -> Option<Vec<u8>>;

    /// Get the preimage for a HASH256 hash.
    fn lookup_hash256(&self, hash: &[u8; 32]) -> Option<Vec<u8>>;

    /// Get the preimage for a RIPEMD160 hash.
    fn lookup_ripemd160(&self, hash: &[u8; 20]) -> Option<Vec<u8>>;

    /// Get the preimage for a HASH160 hash.
    fn lookup_hash160(&self, hash: &[u8; 20]) -> Option<Vec<u8>>;

    /// Check if a relative timelock is satisfied.
    fn check_older(&self, sequence: u32) -> bool;

    /// Check if an absolute timelock is satisfied.
    fn check_after(&self, locktime: u32) -> bool;
}

/// A witness stack for satisfying a miniscript.
#[derive(Clone, Debug, Default)]
pub struct Witness {
    /// The witness elements (bottom to top).
    pub stack: Vec<Vec<u8>>,
}

impl Witness {
    /// Create an empty witness.
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    /// Push an element onto the witness stack.
    pub fn push(&mut self, element: Vec<u8>) {
        self.stack.push(element);
    }

    /// Push an empty element (for dissatisfaction).
    pub fn push_empty(&mut self) {
        self.stack.push(vec![]);
    }

    /// Get the total serialized size of the witness.
    pub fn size(&self) -> usize {
        let mut size = 0;
        for elem in &self.stack {
            size += 1 + elem.len(); // varint + data (simplified)
        }
        size
    }

    /// Check if this witness is available (all elements present).
    pub fn is_available(&self) -> bool {
        !self.stack.is_empty()
    }
}

/// Result of attempting satisfaction.
#[derive(Clone, Debug)]
pub enum SatisfactionResult {
    /// Satisfaction succeeded with the given witness.
    Satisfied(Witness),
    /// Satisfaction impossible.
    Unsatisfiable,
    /// Satisfaction possible but missing data.
    Incomplete,
}

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    /// Attempt to satisfy this miniscript with the given satisfier.
    pub fn satisfy<S: Satisfier<Pk>>(&self, satisfier: &S) -> SatisfactionResult {
        match self.satisfy_inner(satisfier) {
            Some(witness) => SatisfactionResult::Satisfied(witness),
            None => {
                // Check if it's impossible or just incomplete
                if self.ty.props.f {
                    // Forced satisfaction - needs signature we don't have
                    SatisfactionResult::Incomplete
                } else {
                    SatisfactionResult::Unsatisfiable
                }
            }
        }
    }

    /// Inner satisfaction logic.
    fn satisfy_inner<S: Satisfier<Pk>>(&self, satisfier: &S) -> Option<Witness> {
        use Fragment::*;

        match &self.fragment {
            False => {
                // Cannot satisfy False
                None
            }

            True => {
                // True needs no witness
                Some(Witness::new())
            }

            PkK(pk) => {
                // Need a signature
                if let Some(sig) = satisfier.lookup_sig(pk) {
                    let mut witness = Witness::new();
                    witness.push(sig);
                    Some(witness)
                } else {
                    None
                }
            }

            PkH(pk) => {
                // Need a signature and the public key
                if let Some(sig) = satisfier.lookup_sig(pk) {
                    let mut witness = Witness::new();
                    witness.push(sig);
                    let pk_bytes = match self.ctx {
                        ScriptContext::P2wsh => pk.serialize_p2wsh(),
                        ScriptContext::Tapscript => pk.serialize_tapscript(),
                    };
                    witness.push(pk_bytes);
                    Some(witness)
                } else {
                    None
                }
            }

            Older(n) => {
                if satisfier.check_older(*n) {
                    Some(Witness::new())
                } else {
                    None
                }
            }

            After(n) => {
                if satisfier.check_after(*n) {
                    Some(Witness::new())
                } else {
                    None
                }
            }

            Sha256(hash) => {
                if let Some(preimage) = satisfier.lookup_sha256(hash) {
                    let mut witness = Witness::new();
                    witness.push(preimage);
                    Some(witness)
                } else {
                    None
                }
            }

            Hash256(hash) => {
                if let Some(preimage) = satisfier.lookup_hash256(hash) {
                    let mut witness = Witness::new();
                    witness.push(preimage);
                    Some(witness)
                } else {
                    None
                }
            }

            Ripemd160(hash) => {
                if let Some(preimage) = satisfier.lookup_ripemd160(hash) {
                    let mut witness = Witness::new();
                    witness.push(preimage);
                    Some(witness)
                } else {
                    None
                }
            }

            Hash160(hash) => {
                if let Some(preimage) = satisfier.lookup_hash160(hash) {
                    let mut witness = Witness::new();
                    witness.push(preimage);
                    Some(witness)
                } else {
                    None
                }
            }

            Alt(sub) | Swap(sub) | NonZero(sub) | ZeroNotEqual(sub) => {
                sub.satisfy_inner(satisfier)
            }

            Check(sub) | Verify(sub) | DupIf(sub) => {
                sub.satisfy_inner(satisfier)
            }

            AndV(left, right) | AndB(left, right) => {
                // Need both to be satisfied
                let left_wit = left.satisfy_inner(satisfier)?;
                let right_wit = right.satisfy_inner(satisfier)?;
                let mut witness = right_wit;
                for elem in left_wit.stack.into_iter().rev() {
                    witness.stack.insert(0, elem);
                }
                Some(witness)
            }

            OrB(left, right) => {
                // Try left first (prefer left branch)
                if let Some(left_wit) = left.satisfy_inner(satisfier) {
                    let mut witness = Witness::new();
                    witness.push_empty(); // Dissatisfy right
                    for elem in left_wit.stack {
                        witness.stack.insert(0, elem);
                    }
                    Some(witness)
                } else if let Some(right_wit) = right.satisfy_inner(satisfier) {
                    let mut witness = right_wit;
                    witness.push_empty(); // Dissatisfy left
                    Some(witness)
                } else {
                    None
                }
            }

            OrC(left, right) => {
                // Try left first
                if let Some(wit) = left.satisfy_inner(satisfier) {
                    Some(wit)
                } else {
                    right.satisfy_inner(satisfier)
                }
            }

            OrD(left, right) => {
                // Try left first
                if let Some(wit) = left.satisfy_inner(satisfier) {
                    Some(wit)
                } else {
                    right.satisfy_inner(satisfier)
                }
            }

            OrI(left, right) => {
                // Try left first (use OP_IF path)
                if let Some(mut wit) = left.satisfy_inner(satisfier) {
                    wit.push(vec![1]); // True for IF branch
                    Some(wit)
                } else if let Some(mut wit) = right.satisfy_inner(satisfier) {
                    wit.push(vec![]); // False for ELSE branch
                    Some(wit)
                } else {
                    None
                }
            }

            AndOr(cond, if_true, if_false) => {
                // Try the true path first
                if let Some(cond_wit) = cond.satisfy_inner(satisfier) {
                    if let Some(true_wit) = if_true.satisfy_inner(satisfier) {
                        let mut witness = true_wit;
                        for elem in cond_wit.stack {
                            witness.stack.insert(0, elem);
                        }
                        return Some(witness);
                    }
                }
                // Fall back to the false path
                if let Some(false_wit) = if_false.satisfy_inner(satisfier) {
                    let mut witness = false_wit;
                    witness.push_empty(); // Dissatisfy condition
                    Some(witness)
                } else {
                    None
                }
            }

            Thresh(k, subs) => {
                // Find k satisfiable branches
                let mut satisfiable = Vec::new();
                for (i, sub) in subs.iter().enumerate() {
                    if let Some(wit) = sub.satisfy_inner(satisfier) {
                        satisfiable.push((i, wit));
                    }
                }

                if satisfiable.len() < *k {
                    return None;
                }

                // Take the first k satisfactions
                let mut witness = Witness::new();
                let mut satisfied_indices: HashSet<usize> = HashSet::new();
                for (idx, _) in satisfiable.iter().take(*k) {
                    satisfied_indices.insert(*idx);
                }

                // Build witness in reverse order
                for (i, sub) in subs.iter().enumerate().rev() {
                    if satisfied_indices.contains(&i) {
                        let (_, wit) = satisfiable.iter().find(|(idx, _)| *idx == i).unwrap();
                        for elem in &wit.stack {
                            witness.push(elem.clone());
                        }
                    } else {
                        // Dissatisfy this branch
                        dissatisfy_witness(sub, &mut witness);
                    }
                }

                Some(witness)
            }

            Multi(k, keys) => {
                // Collect available signatures
                let mut sigs = Vec::new();
                for key in keys {
                    if let Some(sig) = satisfier.lookup_sig(key) {
                        sigs.push(sig);
                        if sigs.len() == *k {
                            break;
                        }
                    }
                }

                if sigs.len() < *k {
                    return None;
                }

                let mut witness = Witness::new();
                witness.push_empty(); // Dummy for CHECKMULTISIG bug
                for sig in sigs {
                    witness.push(sig);
                }
                Some(witness)
            }

            MultiA(k, keys) => {
                // Collect signatures in order
                let mut witness = Witness::new();
                let mut count = 0;
                for key in keys.iter().rev() {
                    if let Some(sig) = satisfier.lookup_sig(key) {
                        witness.push(sig);
                        count += 1;
                    } else {
                        witness.push_empty();
                    }
                }

                if count < *k {
                    return None;
                }

                Some(witness)
            }
        }
    }

    /// Compute a dissatisfaction for this miniscript.
    pub fn dissatisfy(&self) -> Option<Witness> {
        if !self.ty.props.d {
            return None;
        }

        let mut witness = Witness::new();
        dissatisfy_witness(self, &mut witness);
        Some(witness)
    }
}

/// Add dissatisfaction elements to the witness.
fn dissatisfy_witness<Pk: MiniscriptKey>(ms: &Miniscript<Pk>, witness: &mut Witness) {
    use Fragment::*;

    match &ms.fragment {
        False | True => {}
        PkK(_) => witness.push_empty(),
        PkH(pk) => {
            witness.push_empty();
            let pk_bytes = match ms.ctx {
                ScriptContext::P2wsh => pk.serialize_p2wsh(),
                ScriptContext::Tapscript => pk.serialize_tapscript(),
            };
            witness.push(pk_bytes);
        }
        Older(_) | After(_) => {}
        Sha256(_) | Hash256(_) | Ripemd160(_) | Hash160(_) => {
            // Push invalid preimage (will fail size check)
            witness.push_empty();
        }
        Alt(sub) | Swap(sub) | Check(sub) | NonZero(sub) | ZeroNotEqual(sub) => {
            dissatisfy_witness(sub, witness);
        }
        DupIf(_) => witness.push_empty(),
        Verify(_) => {} // Cannot dissatisfy
        AndV(_, _) => {} // Cannot dissatisfy
        AndB(left, right) => {
            dissatisfy_witness(left, witness);
            dissatisfy_witness(right, witness);
        }
        OrB(left, right) => {
            dissatisfy_witness(left, witness);
            dissatisfy_witness(right, witness);
        }
        OrC(_, _) => {} // Cannot dissatisfy (verify type)
        OrD(left, right) => {
            dissatisfy_witness(left, witness);
            dissatisfy_witness(right, witness);
        }
        OrI(left, _) => {
            dissatisfy_witness(left, witness);
            witness.push(vec![1]); // Choose IF branch and dissatisfy
        }
        AndOr(_, _, if_false) => {
            dissatisfy_witness(if_false, witness);
            witness.push_empty(); // Dissatisfy condition
        }
        Thresh(_, subs) => {
            for sub in subs.iter().rev() {
                dissatisfy_witness(sub, witness);
            }
        }
        Multi(_, keys) => {
            witness.push_empty(); // Dummy
            for _ in keys {
                witness.push_empty();
            }
        }
        MultiA(_, keys) => {
            for _ in keys {
                witness.push_empty();
            }
        }
    }
}

// =============================================================================
// Analysis
// =============================================================================

/// Analysis results for a miniscript.
#[derive(Clone, Debug)]
pub struct Analysis {
    /// Maximum witness size in bytes.
    pub max_witness_size: usize,
    /// Number of signature operations.
    pub sigops: usize,
    /// Required keys for satisfaction.
    pub required_keys: usize,
    /// Whether there are timelock conflicts.
    pub has_timelock_conflict: bool,
    /// Script size in bytes.
    pub script_size: usize,
}

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    /// Analyze this miniscript.
    pub fn analyze(&self) -> Result<Analysis, MiniscriptError> {
        let script = self.compile()?;
        let script_size = script.len();
        let max_witness_size = self.max_witness_size();
        let sigops = self.count_sigops();
        let required_keys = self.count_required_keys();
        let has_timelock_conflict = !self.ty.props.k;

        Ok(Analysis {
            max_witness_size,
            sigops,
            required_keys,
            has_timelock_conflict,
            script_size,
        })
    }

    /// Compute maximum witness size.
    pub fn max_witness_size(&self) -> usize {
        use Fragment::*;

        match &self.fragment {
            False => 0,
            True => 0,
            PkK(_) => self.ctx.sig_len() + 1, // sig + push
            PkH(_) => self.ctx.sig_len() + 1 + self.ctx.pk_len() + 1, // sig + pk
            Older(_) | After(_) => 0,
            Sha256(_) | Hash256(_) => 33, // 32-byte preimage + push
            Ripemd160(_) | Hash160(_) => 33,
            Alt(sub) | Swap(sub) | Check(sub) | DupIf(sub) | Verify(sub) |
            NonZero(sub) | ZeroNotEqual(sub) => sub.max_witness_size(),
            AndV(l, r) | AndB(l, r) => l.max_witness_size() + r.max_witness_size(),
            OrB(l, r) | OrC(l, r) | OrD(l, r) | OrI(l, r) => {
                l.max_witness_size().max(r.max_witness_size()) + 1
            }
            AndOr(x, y, z) => {
                let true_path = x.max_witness_size() + y.max_witness_size();
                let false_path = z.max_witness_size() + 1;
                true_path.max(false_path)
            }
            Thresh(k, subs) => {
                let mut total = 0;
                let mut sizes: Vec<_> = subs.iter().map(|s| s.max_witness_size()).collect();
                sizes.sort_by(|a, b| b.cmp(a)); // Sort descending
                for size in sizes.iter().take(*k) {
                    total += size;
                }
                // Add dissatisfaction for remaining
                total + (subs.len() - k)
            }
            Multi(k, _) => {
                1 + *k * (self.ctx.sig_len() + 1) // dummy + k sigs
            }
            MultiA(_, keys) => {
                keys.len() * (self.ctx.sig_len() + 1)
            }
        }
    }

    /// Count signature operations.
    pub fn count_sigops(&self) -> usize {
        use Fragment::*;

        match &self.fragment {
            PkK(_) | PkH(_) => 0, // Counted when wrapped in c:
            Check(sub) => 1 + sub.count_sigops(),
            Multi(_, keys) => keys.len(),
            MultiA(_, keys) => keys.len(),
            Alt(sub) | Swap(sub) | DupIf(sub) | Verify(sub) |
            NonZero(sub) | ZeroNotEqual(sub) => sub.count_sigops(),
            AndV(l, r) | AndB(l, r) | OrB(l, r) | OrC(l, r) |
            OrD(l, r) | OrI(l, r) => l.count_sigops() + r.count_sigops(),
            AndOr(x, y, z) => x.count_sigops() + y.count_sigops() + z.count_sigops(),
            Thresh(_, subs) => subs.iter().map(|s| s.count_sigops()).sum(),
            _ => 0,
        }
    }

    /// Count required keys for satisfaction.
    pub fn count_required_keys(&self) -> usize {
        use Fragment::*;

        match &self.fragment {
            PkK(_) | PkH(_) => 1,
            Multi(k, _) | MultiA(k, _) => *k,
            Check(sub) => sub.count_required_keys(),
            Alt(sub) | Swap(sub) | DupIf(sub) | Verify(sub) |
            NonZero(sub) | ZeroNotEqual(sub) => sub.count_required_keys(),
            AndV(l, r) | AndB(l, r) => l.count_required_keys() + r.count_required_keys(),
            OrB(l, r) | OrC(l, r) | OrD(l, r) | OrI(l, r) => {
                l.count_required_keys().min(r.count_required_keys())
            }
            AndOr(x, y, z) => {
                let true_path = x.count_required_keys() + y.count_required_keys();
                let false_path = z.count_required_keys();
                true_path.min(false_path)
            }
            Thresh(k, subs) => {
                let mut counts: Vec<_> = subs.iter().map(|s| s.count_required_keys()).collect();
                counts.sort();
                counts.iter().take(*k).sum()
            }
            _ => 0,
        }
    }

    /// Get all public keys in this miniscript.
    pub fn get_keys(&self) -> Vec<&Pk> {
        use Fragment::*;
        let mut keys = Vec::new();

        match &self.fragment {
            PkK(pk) | PkH(pk) => keys.push(pk),
            Multi(_, pks) | MultiA(_, pks) => keys.extend(pks.iter()),
            Alt(sub) | Swap(sub) | Check(sub) | DupIf(sub) | Verify(sub) |
            NonZero(sub) | ZeroNotEqual(sub) => keys.extend(sub.get_keys()),
            AndV(l, r) | AndB(l, r) | OrB(l, r) | OrC(l, r) |
            OrD(l, r) | OrI(l, r) => {
                keys.extend(l.get_keys());
                keys.extend(r.get_keys());
            }
            AndOr(x, y, z) => {
                keys.extend(x.get_keys());
                keys.extend(y.get_keys());
                keys.extend(z.get_keys());
            }
            Thresh(_, subs) => {
                for sub in subs {
                    keys.extend(sub.get_keys());
                }
            }
            _ => {}
        }

        keys
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Miniscript<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fragment)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Fragment<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Fragment::*;
        match self {
            False => write!(f, "0"),
            True => write!(f, "1"),
            PkK(pk) => write!(f, "pk_k({})", pk),
            PkH(pk) => write!(f, "pk_h({})", pk),
            Older(n) => write!(f, "older({})", n),
            After(n) => write!(f, "after({})", n),
            Sha256(h) => write!(f, "sha256({})", hex::encode(h)),
            Hash256(h) => write!(f, "hash256({})", hex::encode(h)),
            Ripemd160(h) => write!(f, "ripemd160({})", hex::encode(h)),
            Hash160(h) => write!(f, "hash160({})", hex::encode(h)),
            Alt(sub) => write!(f, "a:{}", sub),
            Swap(sub) => write!(f, "s:{}", sub),
            Check(sub) => write!(f, "c:{}", sub),
            DupIf(sub) => write!(f, "d:{}", sub),
            Verify(sub) => write!(f, "v:{}", sub),
            NonZero(sub) => write!(f, "n:{}", sub),
            ZeroNotEqual(sub) => write!(f, "j:{}", sub),
            AndV(l, r) => write!(f, "and_v({},{})", l, r),
            AndB(l, r) => write!(f, "and_b({},{})", l, r),
            AndOr(x, y, z) => write!(f, "andor({},{},{})", x, y, z),
            OrB(l, r) => write!(f, "or_b({},{})", l, r),
            OrC(l, r) => write!(f, "or_c({},{})", l, r),
            OrD(l, r) => write!(f, "or_d({},{})", l, r),
            OrI(l, r) => write!(f, "or_i({},{})", l, r),
            Thresh(k, subs) => {
                write!(f, "thresh({}", k)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                write!(f, ")")
            }
            Multi(k, keys) => {
                write!(f, "multi({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            MultiA(k, keys) => {
                write!(f, "multi_a({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_properties_default() {
        let props = TypeProperties::default();
        assert!(!props.z);
        assert!(!props.o);
        assert!(!props.d);
    }

    #[test]
    fn test_basic_types() {
        // Test that basic fragment types are computed correctly
        let pk: Fragment<StrKey> = Fragment::PkK(StrKey("A".into()));
        let ty = compute_type(&pk, ScriptContext::P2wsh).unwrap();
        assert_eq!(ty.base, BasicType::K);
        assert!(ty.props.o);
        assert!(ty.props.s);
    }

    #[test]
    fn test_check_wrapper() {
        // c:pk_k(A) should produce B type
        let pk = Miniscript::new(
            Fragment::PkK(StrKey("A".into())),
            ScriptContext::P2wsh,
        ).unwrap();

        let checked = Miniscript::new(
            Fragment::Check(Box::new(pk)),
            ScriptContext::P2wsh,
        ).unwrap();

        assert_eq!(checked.ty.base, BasicType::B);
        assert!(checked.ty.props.s);
    }

    #[test]
    fn test_older_timelock() {
        let older: Fragment<StrKey> = Fragment::Older(144);
        let ty = compute_type(&older, ScriptContext::P2wsh).unwrap();
        assert_eq!(ty.base, BasicType::B);
        assert!(ty.props.z);
        assert!(ty.props.f);
        assert!(ty.props.h); // height-based relative
        assert!(!ty.props.g); // not time-based
    }

    #[test]
    fn test_after_timelock() {
        let after: Fragment<StrKey> = Fragment::After(500_000_001);
        let ty = compute_type(&after, ScriptContext::P2wsh).unwrap();
        assert_eq!(ty.base, BasicType::B);
        assert!(ty.props.i); // absolute time
        assert!(!ty.props.j); // not height
    }

    #[test]
    fn test_multi_context() {
        // multi() should fail in tapscript
        let multi: Fragment<StrKey> = Fragment::Multi(2, vec![
            StrKey("A".into()),
            StrKey("B".into()),
            StrKey("C".into()),
        ]);
        assert!(compute_type(&multi, ScriptContext::Tapscript).is_err());
        assert!(compute_type(&multi, ScriptContext::P2wsh).is_ok());
    }

    #[test]
    fn test_multi_a_context() {
        // multi_a() should fail in P2WSH
        let multi_a: Fragment<StrKey> = Fragment::MultiA(2, vec![
            StrKey("A".into()),
            StrKey("B".into()),
            StrKey("C".into()),
        ]);
        assert!(compute_type(&multi_a, ScriptContext::P2wsh).is_err());
        assert!(compute_type(&multi_a, ScriptContext::Tapscript).is_ok());
    }

    #[test]
    fn test_invalid_threshold() {
        // k=0 is invalid
        let thresh: Fragment<StrKey> = Fragment::Multi(0, vec![StrKey("A".into())]);
        assert!(matches!(
            compute_type(&thresh, ScriptContext::P2wsh),
            Err(MiniscriptError::InvalidThreshold { k: 0, .. })
        ));

        // k > n is invalid
        let thresh2: Fragment<StrKey> = Fragment::Multi(3, vec![
            StrKey("A".into()),
            StrKey("B".into()),
        ]);
        assert!(matches!(
            compute_type(&thresh2, ScriptContext::P2wsh),
            Err(MiniscriptError::InvalidThreshold { k: 3, n: 2 })
        ));
    }

    #[test]
    fn test_type_display() {
        let ty = Type::new(BasicType::B, TypeProperties {
            z: true,
            o: false,
            n: false,
            d: true,
            u: true,
            e: true,
            f: false,
            s: false,
            m: true,
            x: true,
            k: true,
            ..Default::default()
        });
        let s = ty.to_string();
        assert!(s.starts_with("B"));
        assert!(s.contains("z"));
        assert!(s.contains("d"));
    }

    #[test]
    fn test_fragment_display() {
        let pk: Fragment<StrKey> = Fragment::PkK(StrKey("Alice".into()));
        assert_eq!(pk.to_string(), "pk_k(Alice)");

        let older: Fragment<StrKey> = Fragment::Older(144);
        assert_eq!(older.to_string(), "older(144)");

        let sha256: Fragment<StrKey> = Fragment::Sha256([0u8; 32]);
        let s = sha256.to_string();
        assert!(s.starts_with("sha256("));
    }

    // =========================================================================
    // Parser tests
    // =========================================================================

    #[test]
    fn test_parse_pk() {
        let ms = Miniscript::parse("pk(A)", ScriptContext::P2wsh).unwrap();
        // pk(A) = c:pk_k(A)
        assert!(matches!(ms.fragment, Fragment::Check(_)));
        assert_eq!(ms.ty.base, BasicType::B);
    }

    #[test]
    fn test_parse_pkh() {
        let ms = Miniscript::parse("pkh(Alice)", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::Check(_)));
    }

    #[test]
    fn test_parse_older() {
        let ms = Miniscript::parse("older(144)", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::Older(144)));
    }

    #[test]
    fn test_parse_after() {
        let ms = Miniscript::parse("after(500000000)", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::After(500000000)));
    }

    #[test]
    fn test_parse_sha256() {
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let ms = Miniscript::parse(&format!("sha256({})", hash), ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::Sha256(_)));
    }

    #[test]
    fn test_parse_and_v() {
        let ms = Miniscript::parse("and_v(v:pk(A),pk(B))", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::AndV(_, _)));
    }

    #[test]
    fn test_parse_or_i() {
        let ms = Miniscript::parse("or_i(pk(A),pk(B))", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::OrI(_, _)));
    }

    #[test]
    fn test_parse_thresh() {
        let ms = Miniscript::parse(
            "thresh(2,pk(A),s:pk(B),s:pk(C))",
            ScriptContext::P2wsh
        ).unwrap();
        if let Fragment::Thresh(k, subs) = &ms.fragment {
            assert_eq!(*k, 2);
            assert_eq!(subs.len(), 3);
        } else {
            panic!("Expected Thresh");
        }
    }

    #[test]
    fn test_parse_multi() {
        let ms = Miniscript::parse("multi(2,A,B,C)", ScriptContext::P2wsh).unwrap();
        if let Fragment::Multi(k, keys) = &ms.fragment {
            assert_eq!(*k, 2);
            assert_eq!(keys.len(), 3);
        } else {
            panic!("Expected Multi");
        }
    }

    #[test]
    fn test_parse_wrappers() {
        // Test various wrappers
        let ms = Miniscript::parse("a:pk(A)", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::Alt(_)));

        let ms = Miniscript::parse("s:pk(A)", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::Swap(_)));

        let ms = Miniscript::parse("c:pk_k(A)", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::Check(_)));

        let ms = Miniscript::parse("n:pk(A)", ScriptContext::P2wsh).unwrap();
        assert!(matches!(ms.fragment, Fragment::NonZero(_)));
    }

    // =========================================================================
    // Compilation tests
    // =========================================================================

    #[test]
    fn test_compile_pk() {
        let ms = Miniscript::parse("pk(A)", ScriptContext::P2wsh).unwrap();
        let script = ms.compile().unwrap();
        // Should contain CHECKSIG
        assert!(script.contains(&OP_CHECKSIG));
    }

    #[test]
    fn test_compile_older() {
        let ms = Miniscript::parse("older(144)", ScriptContext::P2wsh).unwrap();
        let script = ms.compile().unwrap();
        assert!(script.contains(&OP_CHECKSEQUENCEVERIFY));
    }

    #[test]
    fn test_compile_after() {
        let ms = Miniscript::parse("after(500000)", ScriptContext::P2wsh).unwrap();
        let script = ms.compile().unwrap();
        assert!(script.contains(&OP_CHECKLOCKTIMEVERIFY));
    }

    #[test]
    fn test_compile_multi() {
        let ms = Miniscript::parse("multi(2,A,B,C)", ScriptContext::P2wsh).unwrap();
        let script = ms.compile().unwrap();
        assert!(script.contains(&OP_CHECKMULTISIG));
    }

    #[test]
    fn test_compile_multi_a() {
        let ms = Miniscript::parse("multi_a(2,A,B,C)", ScriptContext::Tapscript).unwrap();
        let script = ms.compile().unwrap();
        assert!(script.contains(&OP_CHECKSIGADD));
        assert!(script.contains(&OP_NUMEQUAL));
    }

    #[test]
    fn test_compile_or_i() {
        let ms = Miniscript::parse("or_i(pk(A),pk(B))", ScriptContext::P2wsh).unwrap();
        let script = ms.compile().unwrap();
        assert!(script.contains(&OP_IF));
        assert!(script.contains(&OP_ELSE));
        assert!(script.contains(&OP_ENDIF));
    }

    // =========================================================================
    // Satisfaction tests
    // =========================================================================

    struct TestSatisfier {
        sigs: HashMap<String, Vec<u8>>,
        preimages: HashMap<[u8; 32], Vec<u8>>,
        older_ok: bool,
        after_ok: bool,
    }

    impl TestSatisfier {
        fn new() -> Self {
            Self {
                sigs: HashMap::new(),
                preimages: HashMap::new(),
                older_ok: true,
                after_ok: true,
            }
        }

        fn with_sig(mut self, key: &str) -> Self {
            self.sigs.insert(key.to_string(), vec![0x30; 72]); // Dummy DER sig
            self
        }

        fn with_preimage(mut self, hash: [u8; 32], preimage: Vec<u8>) -> Self {
            self.preimages.insert(hash, preimage);
            self
        }
    }

    impl Satisfier<StrKey> for TestSatisfier {
        fn lookup_sig(&self, pk: &StrKey) -> Option<Vec<u8>> {
            self.sigs.get(&pk.0).cloned()
        }

        fn lookup_sha256(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
            self.preimages.get(hash).cloned()
        }

        fn lookup_hash256(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
            self.preimages.get(hash).cloned()
        }

        fn lookup_ripemd160(&self, _hash: &[u8; 20]) -> Option<Vec<u8>> {
            None
        }

        fn lookup_hash160(&self, _hash: &[u8; 20]) -> Option<Vec<u8>> {
            None
        }

        fn check_older(&self, _sequence: u32) -> bool {
            self.older_ok
        }

        fn check_after(&self, _locktime: u32) -> bool {
            self.after_ok
        }
    }

    #[test]
    fn test_satisfaction_pk() {
        let ms = Miniscript::parse("pk(A)", ScriptContext::P2wsh).unwrap();
        let satisfier = TestSatisfier::new().with_sig("A");

        match ms.satisfy(&satisfier) {
            SatisfactionResult::Satisfied(witness) => {
                assert_eq!(witness.stack.len(), 1);
            }
            _ => panic!("Expected satisfaction"),
        }
    }

    #[test]
    fn test_satisfaction_pk_missing() {
        let ms = Miniscript::parse("pk(A)", ScriptContext::P2wsh).unwrap();
        let satisfier = TestSatisfier::new(); // No signature

        match ms.satisfy(&satisfier) {
            SatisfactionResult::Satisfied(_) => panic!("Expected failure"),
            _ => {} // OK
        }
    }

    #[test]
    fn test_satisfaction_or_i() {
        let ms = Miniscript::parse("or_i(pk(A),pk(B))", ScriptContext::P2wsh).unwrap();

        // Satisfy with A
        let satisfier = TestSatisfier::new().with_sig("A");
        match ms.satisfy(&satisfier) {
            SatisfactionResult::Satisfied(witness) => {
                assert!(!witness.stack.is_empty());
            }
            _ => panic!("Expected satisfaction"),
        }

        // Satisfy with B
        let satisfier = TestSatisfier::new().with_sig("B");
        match ms.satisfy(&satisfier) {
            SatisfactionResult::Satisfied(witness) => {
                assert!(!witness.stack.is_empty());
            }
            _ => panic!("Expected satisfaction"),
        }
    }

    #[test]
    fn test_satisfaction_multi() {
        let ms = Miniscript::parse("multi(2,A,B,C)", ScriptContext::P2wsh).unwrap();

        // Need at least 2 signatures
        let satisfier = TestSatisfier::new().with_sig("A").with_sig("B");
        match ms.satisfy(&satisfier) {
            SatisfactionResult::Satisfied(witness) => {
                // dummy + 2 sigs
                assert_eq!(witness.stack.len(), 3);
            }
            _ => panic!("Expected satisfaction"),
        }

        // Only 1 signature - should fail
        let satisfier = TestSatisfier::new().with_sig("A");
        match ms.satisfy(&satisfier) {
            SatisfactionResult::Satisfied(_) => panic!("Expected failure"),
            _ => {} // OK
        }
    }

    // =========================================================================
    // Analysis tests
    // =========================================================================

    #[test]
    fn test_analysis_pk() {
        let ms = Miniscript::parse("pk(A)", ScriptContext::P2wsh).unwrap();
        let analysis = ms.analyze().unwrap();

        assert!(analysis.script_size > 0);
        assert_eq!(analysis.sigops, 1);
        assert_eq!(analysis.required_keys, 1);
        assert!(!analysis.has_timelock_conflict);
    }

    #[test]
    fn test_analysis_multi() {
        let ms = Miniscript::parse("multi(2,A,B,C)", ScriptContext::P2wsh).unwrap();
        let analysis = ms.analyze().unwrap();

        assert_eq!(analysis.sigops, 3); // All 3 keys count as sigops
        assert_eq!(analysis.required_keys, 2);
    }

    #[test]
    fn test_get_keys() {
        let ms = Miniscript::parse("thresh(2,pk(A),s:pk(B),s:pk(C))", ScriptContext::P2wsh).unwrap();
        let keys = ms.get_keys();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_type_check_valid_top_level() {
        // pk(A) is valid top-level
        let ms = Miniscript::parse("pk(A)", ScriptContext::P2wsh).unwrap();
        assert!(ms.is_valid_top_level());

        // pk_k(A) is NOT valid top-level (K type, not B)
        let pk_k = Miniscript::new(
            Fragment::PkK(StrKey("A".into())),
            ScriptContext::P2wsh
        ).unwrap();
        assert!(!pk_k.is_valid_top_level());
    }

    #[test]
    fn test_type_check_sane() {
        // pk(A) is sane (requires signature, non-malleable, no timelock conflicts)
        let ms = Miniscript::parse("pk(A)", ScriptContext::P2wsh).unwrap();
        assert!(ms.is_sane());

        // 1 (true) is NOT sane (doesn't require signature)
        let one = Miniscript::new(Fragment::<StrKey>::True, ScriptContext::P2wsh).unwrap();
        assert!(!one.is_sane());
    }
}
