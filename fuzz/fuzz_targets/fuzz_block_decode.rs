//! Fuzz target: Block decoder.
//!
//! Feeds arbitrary bytes to `<Block as Decodable>::deserialize` (the exact
//! path used when decoding untrusted `block` P2P payloads). A healthy decoder
//! must return Ok or Err — never panic, abort (OOM), or hang.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustoshi_primitives::{Block, Decodable};

fuzz_target!(|data: &[u8]| {
    let _ = Block::deserialize(data);
});
