//! PRODUCTION WIRING for the `bad-diffbits` header gate.
//!
//! Core, `validation.cpp::ContextualCheckBlockHeader` (bitcoin-core/src/
//! validation.cpp:4088) — the FIRST contextual header check:
//!
//! ```text
//! if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
//!     return state.Invalid(..., "bad-diffbits", "incorrect proof of work");
//! ```
//!
//! The correctness of the resolver itself is pinned mainnet- and
//! testnet4-shaped in
//! `crates/storage/tests/test_bad_diffbits_header_only_ancestors.rs`. This file
//! answers a different question, and it is the one that actually bit:
//! **does the production header path execute it at all?**
//!
//! The bug being fixed was not a wrong formula. It was a correct formula behind
//! a `get_height` short-circuit that returned `None` for every header-only
//! parent, folded into an `Option` the caller read as "no check". Everything
//! downstream — including the 2018-header ancestor walk — was dead code. A test
//! that only exercises the resolver would have passed before AND after.

use std::collections::HashSet;

use rustoshi_consensus::params::ChainParams;
use rustoshi_network::{HeaderSync, PeerId};
use rustoshi_primitives::{BlockHeader, Hash256};
use rustoshi_storage::header_context::{
    diffbits_gate_for_header, DiffBitsGate, HeaderCache,
};
use rustoshi_storage::{BlockStore, ChainDb};

const MAIN_RS: &str = include_str!("../src/main.rs");

// ---------------------------------------------------------------------------
// 1. Source-level wiring pin
// ---------------------------------------------------------------------------

/// The header-acceptance closure in `main.rs` MUST call the shared, fail-closed
/// gate — and must no longer contain the fail-open helper it replaced.
///
/// This is deliberately a source assertion: `main.rs` is a binary, its
/// `process_headers` closure is not importable, and the failure mode this
/// change exists to prevent is precisely "the fix landed but never executes".
#[test]
fn main_rs_header_path_calls_the_shared_diffbits_gate() {
    assert!(
        MAIN_RS.contains("diffbits_gate_for_header"),
        "the header-acceptance path must call rustoshi_storage::diffbits_gate_for_header"
    );
    assert!(
        !MAIN_RS.contains("compute_expected_bits_via_store"),
        "the fail-open local helper must be gone — it resolved the parent height via \
         BlockStore::get_height (CF_BLOCK_INDEX), which headers-first sync never \
         populates for a header-only parent, and returned None = 'skip the gate'"
    );
    assert!(
        MAIN_RS.contains("check_proof_of_work"),
        "the header path must run the params-aware PoW check (pow_limit ceiling), not \
         only BlockHeader::validate_pow_against_declared_target"
    );
    assert!(
        MAIN_RS.contains("check_connect_diffbits"),
        "the connect path must carry the independent bad-diffbits backstop"
    );
}

/// The `DegradedSnapshotBase` carve-out is the ONLY way a `None` can reach
/// `contextual_check_block_header` from the header path. Pin that the error arm
/// rejects rather than falling through.
#[test]
fn main_rs_header_path_rejects_on_gate_error() {
    // Two call sites exist: `check_connect_diffbits` (defined near the top of
    // main.rs) and the header-acceptance closure (far below it). `rfind` picks
    // the header-path one, which is the site this fix is about.
    let idx = MAIN_RS
        .rfind("diffbits_gate_for_header")
        .expect("gate call present");
    let window = &MAIN_RS[idx..(idx + 3000).min(MAIN_RS.len())];
    assert!(
        window.contains("return Err(reason)"),
        "an unresolvable retarget window must REJECT the header, never fall through"
    );
    // ...and the header path must hand the resolved value to
    // `contextual_check_block_header`, not drop it.
    assert!(
        window.contains("contextual_check_block_header"),
        "the resolved expected_bits must feed Core's contextual header gate"
    );

    // The connect-path backstop must likewise turn a gate failure into a
    // rejection rather than proceeding to connect.
    let cidx = MAIN_RS
        .find("fn check_connect_diffbits")
        .expect("connect backstop present");
    let cwindow = &MAIN_RS[cidx..(cidx + 2500).min(MAIN_RS.len())];
    assert!(
        cwindow.contains("bad-diffbits: nBits"),
        "the connect backstop must reject on a nBits mismatch"
    );
}

// ---------------------------------------------------------------------------
// 2. Behavioural wiring through the real HeaderSync
// ---------------------------------------------------------------------------

/// Faithful replica of the deleted `compute_expected_bits_via_store` prologue.
/// Used to prove the fixture really is in the state that used to disable the
/// gate.
fn legacy_would_skip(store: &BlockStore, parent_hash: &Hash256) -> bool {
    !matches!(store.get_height(parent_hash), Ok(Some(_)))
}

/// The `validate_and_store` closure `rustoshi/src/main.rs` installs, reproduced
/// here so it can be driven through the real `HeaderSync::process_headers`.
/// Keep in sync with `main.rs`; `main_rs_header_path_calls_the_shared_diffbits_gate`
/// above guards the call sites.
fn make_validate_and_store<'a>(
    store: &'a BlockStore<'a>,
    params: &'a ChainParams,
    cache: &'a std::cell::RefCell<HeaderCache>,
    observed: &'a std::cell::RefCell<Vec<Option<u32>>>,
) -> impl FnMut(&BlockHeader, u32) -> Result<(), String> + 'a {
    move |header: &BlockHeader, height: u32| {
        // Core CheckBlockHeader -> pow.cpp CheckProofOfWorkImpl/DeriveTarget.
        if !rustoshi_consensus::check_proof_of_work(
            header.block_hash().as_bytes(),
            header.bits,
            params,
        ) {
            return Err("high-hash".to_string());
        }
        // Core ContextualCheckBlockHeader gate 0 (validation.cpp:4088).
        let expected_bits = {
            let mut c = cache.borrow_mut();
            match diffbits_gate_for_header(
                store,
                &mut c,
                &header.prev_block_hash,
                header.bits,
                header.timestamp,
                height,
                Some(height.saturating_sub(1)),
                params,
            ) {
                Ok(DiffBitsGate::Required(b)) => Some(b),
                Ok(DiffBitsGate::DegradedSnapshotBase) => None,
                Err(reason) => return Err(reason),
            }
        };
        observed.borrow_mut().push(expected_bits);
        let prev_entry = rustoshi_consensus::BlockIndexEntry {
            height: 0,
            timestamp: 0,
            bits: 0,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        };
        rustoshi_consensus::contextual_check_block_header(
            header,
            height,
            &prev_entry,
            &rustoshi_consensus::StubChainContext,
            params,
            0,
            expected_bits,
        )
        .map_err(|e| e.bip22_string())?;
        store
            .put_header(&header.block_hash(), header)
            .map_err(|e| e.to_string())?;
        store
            .put_height_index(height, &header.block_hash())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Mine a header against its own declared target (regtest max target, so a
/// handful of nonces suffice).
fn mine(header: &mut BlockHeader, params: &ChainParams) {
    for nonce in 0..5_000_000u32 {
        header.nonce = nonce;
        if rustoshi_consensus::check_proof_of_work(
            header.block_hash().as_bytes(),
            header.bits,
            params,
        ) {
            return;
        }
    }
    panic!("failed to mine a regtest-difficulty header");
}

/// End-to-end through `HeaderSync::process_headers`: an off-schedule `nBits` is
/// rejected, and the honest chain is accepted.
///
/// **Network caveat (constraint 6).** This arm runs on regtest, and regtest sets
/// `pow_no_retargeting` — so it proves REACHABILITY (the gate executes and its
/// verdict is enforced), NOT the retarget math. Mining a testnet4- or
/// mainnet-difficulty header in a unit test is not feasible, and
/// `HeaderSync::process_headers` refuses a header that fails
/// `validate_pow_against_declared_target` before the closure ever runs. The
/// difficulty math is pinned mainnet/testnet4-shaped in
/// `crates/storage/tests/test_bad_diffbits_header_only_ancestors.rs`, and the
/// third test below re-pins it against a real `BlockStore` with header-only
/// ancestors.
#[test]
fn header_sync_rejects_off_schedule_nbits_and_gate_is_enforced() {
    let params = ChainParams::regtest();
    let dir = tempfile::tempdir().unwrap();
    let db = ChainDb::open(dir.path()).unwrap();
    let store = BlockStore::new(&db);
    store.init_genesis(&params).unwrap();

    let good_bits = rustoshi_consensus::params::target_to_compact(&params.pow_limit);
    let base_time = params.genesis_block.header.timestamp;

    // Build 5 honest headers on top of genesis, each within 20 minutes of its
    // parent so the min-difficulty short-circuit does not pre-empt the
    // walk-back arm.
    let mut honest = Vec::new();
    let mut prev = params.genesis_hash;
    for h in 1..=5u32 {
        let mut hdr = BlockHeader {
            version: 0x2000_0000u32 as i32,
            prev_block_hash: prev,
            merkle_root: Hash256([h as u8; 32]),
            timestamp: base_time + h * 600,
            bits: good_bits,
            nonce: 0,
        };
        mine(&mut hdr, &params);
        prev = hdr.block_hash();
        honest.push(hdr);
    }

    let cache = std::cell::RefCell::new(HeaderCache::default());
    let observed = std::cell::RefCell::new(Vec::new());
    let mut sync = HeaderSync::new(params.genesis_hash);
    // Seeded from the CONNECTED BLOCK TIP, exactly as main.rs does — this is
    // what makes the height hint pointer-derived and therefore trustworthy.
    sync.set_best_header(0, params.genesis_hash);
    let peer = PeerId(1);
    sync.register_peer(peer, 100);

    {
        let mut vas = make_validate_and_store(&store, &params, &cache, &observed);
        sync.process_headers(peer, honest.clone(), &mut vas, &|_| None, &|_| None)
            .expect("honest headers must be accepted");
    }

    // THE REGRESSION: the gate must have been ENFORCED on every header, i.e.
    // `Some(required)` — never the `None` that used to mean "skip".
    let obs = observed.borrow().clone();
    assert_eq!(obs.len(), 5, "every header must reach the gate");
    assert!(
        obs.iter().all(|o| *o == Some(good_bits)),
        "the gate must be ENFORCED on every header, got {obs:?}"
    );
    // ...and the parents really were header-only, i.e. the legacy resolver
    // would have skipped.
    assert!(
        legacy_would_skip(&store, &honest[3].block_hash()),
        "fixture must reproduce the header-only state that disabled the old gate"
    );

    // Now an off-schedule nBits on top of the accepted chain. It passes the
    // params-aware PoW check (its declared target is <= pow_limit and the hash
    // meets it) so the ONLY thing that can reject it is bad-diffbits.
    let mut evil = BlockHeader {
        version: 0x2000_0000u32 as i32,
        prev_block_hash: honest[4].block_hash(),
        merkle_root: Hash256([0xEE; 32]),
        timestamp: base_time + 6 * 600,
        bits: good_bits - 1, // slightly harder than mandated -> still off-schedule
        nonce: 0,
    };
    mine(&mut evil, &params);
    assert!(
        rustoshi_consensus::check_proof_of_work(
            evil.block_hash().as_bytes(),
            evil.bits,
            &params
        ),
        "the attack header must pass the PoW gate so bad-diffbits is what rejects it"
    );

    let err = {
        let mut vas = make_validate_and_store(&store, &params, &cache, &observed);
        sync.process_headers(peer, vec![evil.clone()], &mut vas, &|_| None, &|_| None)
            .expect_err("off-schedule nBits must be rejected")
    };
    assert_eq!(err, "bad-diffbits", "got {err}");
    assert!(
        store.get_header(&evil.block_hash()).unwrap().is_none(),
        "a rejected header must never be stored"
    );
}

// ---------------------------------------------------------------------------
// 3. Mainnet-shaped, real BlockStore, header-only ancestors
// ---------------------------------------------------------------------------

/// The storage state a node is actually in during IBD: headers far above the
/// connected block tip, so every retarget ancestor is header-only. Mainnet
/// parameters (real retargeting, no min-difficulty rule).
#[test]
fn mainnet_shaped_header_only_chain_enforces_and_rejects() {
    let params = ChainParams::mainnet();
    let bits = 0x1b04_864cu32;

    let dir = tempfile::tempdir().unwrap();
    let db = ChainDb::open(dir.path()).unwrap();
    let store = BlockStore::new(&db);
    store.init_genesis(&params).unwrap();

    // 200 header-only blocks. `put_header` + `put_height_index` ONLY — exactly
    // what header acceptance writes. No `put_block_index` anywhere.
    let mut chain: Vec<BlockHeader> = vec![params.genesis_block.header.clone()];
    let mut prev = params.genesis_hash;
    for h in 1..=200u32 {
        let hdr = BlockHeader {
            version: 0x2000_0000u32 as i32,
            prev_block_hash: prev,
            merkle_root: Hash256([h as u8; 32]),
            timestamp: 1_300_000_000 + h * 600,
            bits,
            nonce: h,
        };
        prev = hdr.block_hash();
        store.put_header(&prev, &hdr).unwrap();
        store.put_height_index(h, &prev).unwrap();
        chain.push(hdr);
    }

    let parent = chain[200].block_hash();
    assert!(
        legacy_would_skip(&store, &parent),
        "precondition: no CF_BLOCK_INDEX entry — the old resolver failed open here"
    );

    let mut cache = HeaderCache::default();
    let gate = diffbits_gate_for_header(
        &store,
        &mut cache,
        &parent,
        bits,
        chain[200].timestamp + 600,
        201,
        Some(200),
        &params,
    )
    .expect("must resolve by pointers");
    assert_eq!(
        gate,
        DiffBitsGate::Required(bits),
        "mainnet non-boundary: nBits must equal the parent's, and the gate must be ENFORCED"
    );

    // A difficulty-1 header on top is rejected by the gate's verdict.
    let attack = BlockHeader {
        version: 0x2000_0000u32 as i32,
        prev_block_hash: parent,
        merkle_root: Hash256([0xAA; 32]),
        timestamp: chain[200].timestamp + 600,
        bits: 0x1d00_ffff,
        nonce: 1,
    };
    let prev_entry = rustoshi_consensus::BlockIndexEntry {
        height: 0,
        timestamp: 0,
        bits: 0,
        prev_hash: Hash256::ZERO,
        chain_work: [0u8; 32],
    };
    let res = rustoshi_consensus::contextual_check_block_header(
        &attack,
        201,
        &prev_entry,
        &rustoshi_consensus::StubChainContext,
        &params,
        0,
        Some(bits),
    );
    assert_eq!(res.unwrap_err().bip22_string(), "bad-diffbits");

    // Distinctness sanity: the two values really do differ, so the assertion
    // above is not vacuous.
    let distinct: HashSet<u32> = [bits, 0x1d00_ffff].into_iter().collect();
    assert_eq!(distinct.len(), 2);
}
