//! Rustoshi primitives crate
//!
//! Foundational types used throughout the rustoshi node, including hash types,
//! binary serialization, transactions, and blocks.

pub mod block;
pub mod hash;
pub mod serialize;
pub mod transaction;

pub use block::{Block, BlockHeader};
pub use hash::{Hash160, Hash256, HexError};
pub use serialize::{
    compact_size_len, read_compact_size, write_compact_size, Decodable, Encodable,
};
pub use transaction::{OutPoint, Transaction, TxIn, TxOut};
