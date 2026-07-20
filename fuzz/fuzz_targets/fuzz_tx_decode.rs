//! Fuzz target: Transaction decoder (witness + legacy paths).
//!
//! First input byte selects the decode variant so a single corpus exercises
//! both `<Transaction as Decodable>::deserialize` (SegWit marker/flag path)
//! and `Transaction::decode_no_witness` (legacy serialization path).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustoshi_primitives::{Decodable, Transaction};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel & 1 == 0 {
        let _ = Transaction::deserialize(rest);
    } else {
        let mut cursor = Cursor::new(rest);
        let _ = Transaction::decode_no_witness(&mut cursor);
    }
});
