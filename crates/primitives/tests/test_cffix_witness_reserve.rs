//! cffix-rustoshi-event-lane-byte-budget: the witness-stack reservation made
//! while decoding a transaction must be bounded by the items actually present,
//! not by the attacker-chosen CompactSize count in front of them.
//!
//! Bitcoin Core reads a vector in chunks of at most `MAX_VECTOR_ALLOCATE`
//! (serialize.h) so a large count with little data behind it never reserves
//! more than it reads. rustoshi reserved `Vec::with_capacity(witness_count)`
//! with `witness_count` allowed up to 4,000,000: 3,999,933 x 24 B ~= 96 MB for
//! a frame that carries a handful of bytes.
//!
//! The allocator below counts the bytes requested on the current thread while
//! tracking is enabled (the cargo test harness runs tests on several threads,
//! so a process-wide counter would also see the other test's allocations).

use rustoshi_primitives::{Decodable, Transaction};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Cursor;

struct Counting;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

fn note_alloc(n: usize) {
    let _ = TRACK.try_with(|t| {
        if t.get() {
            let live = LIVE.with(|l| {
                let v = l.get() + n;
                l.set(v);
                v
            });
            PEAK.with(|p| p.set(p.get().max(live)));
        }
    });
}

fn note_free(n: usize) {
    let _ = TRACK.try_with(|t| {
        if t.get() {
            LIVE.with(|l| l.set(l.get().saturating_sub(n)));
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_free(layout.size());
        note_alloc(new_size);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Peak bytes live on this thread while `f` runs.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    LIVE.with(|l| l.set(0));
    PEAK.with(|p| p.set(0));
    TRACK.with(|t| t.set(true));
    let out = f();
    TRACK.with(|t| t.set(false));
    (out, PEAK.with(|p| p.get()))
}

/// The audit fixture: 1 input whose witness declares 3,999,933 items.
const FIXTURE_ITEMS: u32 = 3_999_933;

/// Serialize a segwit tx with one input, one empty output and a witness
/// stack that DECLARES `declared` items but carries only `present` empty
/// items (each one byte: a zero length) before the locktime.
fn witness_tx(declared: u32, present: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&2i32.to_le_bytes()); // version
    b.extend_from_slice(&[0x00, 0x01]); // segwit marker + flag
    b.push(1); // input count
    b.extend_from_slice(&[0x11; 32]); // prevout txid
    b.extend_from_slice(&0u32.to_le_bytes()); // prevout vout
    b.push(0); // empty scriptSig
    b.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    b.push(1); // output count
    b.extend_from_slice(&0u64.to_le_bytes()); // value
    b.push(0); // empty scriptPubKey
    b.push(0xfe); // witness item count (CompactSize, 4-byte form)
    b.extend_from_slice(&declared.to_le_bytes());
    b.extend(std::iter::repeat_n(0u8, present as usize)); // empty items
    if present == declared {
        b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    }
    b
}

/// The full fixture is exactly a max-size (4,000,000-byte) P2P message.
#[test]
fn witness_fixture_is_a_max_size_message() {
    assert_eq!(witness_tx(FIXTURE_ITEMS, FIXTURE_ITEMS).len(), 4_000_000);
}

/// A frame that declares 3,999,933 witness items but carries 16 must not
/// reserve room for 3,999,933 (master: 3,999,933 x 24 B = 95,998,392 B up
/// front, then the read fails). Bound: Core-style chunking reserves at most
/// one chunk (rustoshi's MAX_ALLOC_RESERVE = 16,384 elements = 393,216 B for
/// `Vec<u8>` elements), so 1 MiB is generous.
#[test]
fn decoded_witness_reservation_bounded() {
    let frame = witness_tx(FIXTURE_ITEMS, 16);
    let (res, peak) = peak_during(|| Transaction::decode(&mut Cursor::new(&frame)));
    assert!(res.is_err(), "truncated witness must not decode");
    assert!(
        peak <= 1 << 20,
        "decoding a {}-byte frame that declares {} witness items peaked at {} bytes \
         allocated; the reservation must be bounded by the items actually present",
        frame.len(),
        FIXTURE_ITEMS,
        peak
    );
}

/// The genuine 4 MB fixture still decodes in full, and its witness capacity
/// stays within the allocator's doubling growth of the items present.
#[test]
fn full_witness_fixture_still_decodes() {
    let frame = witness_tx(FIXTURE_ITEMS, FIXTURE_ITEMS);
    let tx = Transaction::decode(&mut Cursor::new(&frame)).expect("valid encoding");
    let w = &tx.inputs[0].witness;
    assert_eq!(w.len(), FIXTURE_ITEMS as usize);
    assert!(w.iter().all(|i| i.is_empty()));
    assert!(
        w.capacity() <= w.len().next_power_of_two(),
        "capacity {} exceeds doubling growth of {} items",
        w.capacity(),
        w.len()
    );
}
