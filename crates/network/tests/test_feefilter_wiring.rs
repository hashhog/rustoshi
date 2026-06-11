//! BIP-133 feefilter wiring tests (W136 BUG-1/4/5/6/8 closure).
//!
//! These exercise the `FeeFilterManager` cadence + gate logic that is now
//! wired into `PeerManager` (Connected → `add_peer`, Disconnected →
//! `remove_peer`, received FEEFILTER → `handle_feefilter`, maintenance tick →
//! `get_pending_feefilters`, outbound tx-INV → `should_relay_to_peer`).
//!
//! The tests drive the cadence deterministically through the injectable-clock
//! helpers (`add_peer_at`, `set_next_send_for_test`, `get_pending_feefilters_at`)
//! rather than sleeping or asserting on exact Poisson reschedule values, so they
//! are non-flaky despite the global-RNG jitter inside `poisson_next_send`.
//!
//! Run:
//!   cargo test -p rustoshi-network --test test_feefilter_wiring

use rustoshi_network::peer::PeerId;
use rustoshi_network::relay::{FeeFilterManager, FeeFilterRounder, DEFAULT_INCREMENTAL_RELAY_FEE, MAX_MONEY};
use std::time::{Duration, Instant};

// ─── Test 1: periodic broadcast fires when the timer elapses (not before) ───
//
// Core MaybeSendFeefilter only emits FEEFILTER when `current_time >
// m_next_send_feefilter`. Before the per-peer timer elapses, no message is
// produced; once it elapses, exactly one (peer, rate) pair is produced and the
// timer is rescheduled (so an immediately-following poll produces nothing more).
#[test]
fn periodic_broadcast_fires_only_when_timer_elapses() {
    let mut mgr = FeeFilterManager::default();
    let t0 = Instant::now();
    let peer = PeerId(1);

    // Eligible peer (supports feefilter, not block-only), anchored at t0.
    mgr.add_peer_at(t0, peer, /*supports_feefilter=*/ true, /*is_block_only=*/ false);

    // Pin the next-send deadline well into the future.
    let deadline = t0 + Duration::from_secs(600);
    assert!(mgr.set_next_send_for_test(peer, deadline));

    // BEFORE the deadline → no broadcast. Use a non-IBD, non-zero mempool min
    // fee so the would-be filter differs from the sent value (0). We pick a
    // value BELOW the first fee bucket (DEFAULT_INCREMENTAL_RELAY_FEE) so
    // FeeFilterRounder::round() is deterministic here: with no lower bucket it
    // returns the first bucket directly (no 50/50 straddle coin-flip), which the
    // floor at min_relay_fee then dominates. A straddling value (e.g. 5_000)
    // would make the manager's internal round() and the test's expected round()
    // draw the coin independently and disagree ~50% of the time.
    let mempool_min_fee = DEFAULT_INCREMENTAL_RELAY_FEE / 2;
    let before = deadline - Duration::from_secs(1);
    let pending_before = mgr.get_pending_feefilters_at(before, mempool_min_fee, false);
    assert!(
        pending_before.is_empty(),
        "no feefilter must be sent before the per-peer timer elapses, got {:?}",
        pending_before
    );

    // AT/AFTER the deadline → exactly one broadcast for this peer.
    let after = deadline + Duration::from_secs(1);
    let pending_after = mgr.get_pending_feefilters_at(after, mempool_min_fee, false);
    assert_eq!(
        pending_after.len(),
        1,
        "exactly one feefilter must fire once the timer elapses, got {:?}",
        pending_after
    );
    assert_eq!(pending_after[0].0, peer);

    // The value is the rounded mempool min fee, floored at the min-relay fee.
    // round(mempool_min_fee) is deterministic for a sub-first-bucket input
    // (see above), so this assertion is stable.
    let rounder = FeeFilterRounder::new(DEFAULT_INCREMENTAL_RELAY_FEE);
    let expected = rounder.round(mempool_min_fee).max(mgr.min_relay_fee());
    assert_eq!(
        pending_after[0].1, expected,
        "broadcast value must be round(mempool_min_fee) floored at min_relay_fee"
    );

    // A second poll at the same instant must NOT re-send: the timer was
    // rescheduled (poisson, ~10 min out) and the sent value now matches.
    let pending_again = mgr.get_pending_feefilters_at(after, mempool_min_fee, false);
    assert!(
        pending_again.is_empty(),
        "the send must reschedule the timer; a same-value re-poll fires nothing, got {:?}",
        pending_again
    );
}

// ─── Test 2: outbound INV gate — sub-feefilter suppressed, at/above passes ──
//
// Mirrors Core's tx-INV loop skip: `txinfo.fee < filterrate.GetFee(txinfo.vsize)`
// i.e. drop when tx feerate < peer's received minfeefilter. This is the exact
// predicate `relay_tx_inv` consults via `should_relay_to_peer`.
#[test]
fn outbound_inv_gate_drops_sub_feefilter_passes_at_or_above() {
    let mut mgr = FeeFilterManager::default();
    let peer = PeerId(7);
    mgr.add_peer(peer, true, false);

    // Peer advertises a minfeefilter of 10_000 sat/kvB.
    mgr.handle_feefilter(peer, 10_000);

    // A tx whose feerate is BELOW the peer's filter must be SUPPRESSED.
    assert!(
        !mgr.should_relay_to_peer(peer, 9_999),
        "tx feerate below peer feefilter must be suppressed"
    );
    assert!(
        !mgr.should_relay_to_peer(peer, 0),
        "zero-feerate tx must be suppressed for a peer with a positive filter"
    );

    // A tx AT or ABOVE the filter must PASS.
    assert!(
        mgr.should_relay_to_peer(peer, 10_000),
        "tx feerate equal to peer feefilter must pass (>=)"
    );
    assert!(
        mgr.should_relay_to_peer(peer, 50_000),
        "tx feerate above peer feefilter must pass"
    );

    // A peer that never sent a feefilter (filter defaults to 0) passes
    // everything — only genuinely sub-threshold INVs are dropped.
    let quiet_peer = PeerId(8);
    mgr.add_peer(quiet_peer, true, false);
    assert!(
        mgr.should_relay_to_peer(quiet_peer, 1),
        "peer with no advertised feefilter (filter=0) must pass all txs"
    );
    // Unknown peer also defaults to relay.
    assert!(
        mgr.should_relay_to_peer(PeerId(999), 1),
        "unknown peer defaults to relay"
    );
}

// ─── Test 3: block-relay-only peers get NO feefilter ────────────────────────
//
// Core skips MaybeSendFeefilter for IsBlockOnlyConn peers (they never announce
// txs to us). A block-relay-only peer must therefore never appear in the
// periodic broadcast set nor in the forced initial send.
#[test]
fn block_relay_only_peer_gets_no_feefilter() {
    let mut mgr = FeeFilterManager::default();
    let t0 = Instant::now();
    let block_only = PeerId(2);
    let full = PeerId(3);

    mgr.add_peer_at(t0, block_only, /*supports_feefilter=*/ true, /*is_block_only=*/ true);
    mgr.add_peer_at(t0, full, true, false);

    // Force both timers due.
    let due = t0 - Duration::from_secs(1);
    assert!(mgr.set_next_send_for_test(block_only, due));
    assert!(mgr.set_next_send_for_test(full, due));

    let pending = mgr.get_pending_feefilters_at(t0, /*mempool_min_fee=*/ 5_000, false);

    // The full-relay peer fires; the block-relay-only peer must NOT.
    assert!(
        pending.iter().any(|(p, _)| *p == full),
        "full-relay peer must receive a periodic feefilter, got {:?}",
        pending
    );
    assert!(
        !pending.iter().any(|(p, _)| *p == block_only),
        "block-relay-only peer must NOT receive any feefilter, got {:?}",
        pending
    );

    // The forced initial send must also skip the block-relay-only peer.
    assert_eq!(
        mgr.force_initial_send(block_only, false),
        None,
        "force_initial_send must return None for a block-relay-only peer"
    );
    assert!(
        mgr.force_initial_send(full, false).is_some(),
        "force_initial_send must produce a value for a full-relay peer"
    );

    // Pre-70013 peers (supports_feefilter=false) are likewise skipped.
    let legacy = PeerId(4);
    mgr.add_peer_at(t0, legacy, /*supports_feefilter=*/ false, false);
    assert!(mgr.set_next_send_for_test(legacy, due));
    let pending2 = mgr.get_pending_feefilters_at(t0, 5_000, false);
    assert!(
        !pending2.iter().any(|(p, _)| *p == legacy),
        "pre-70013 peer (no feefilter support) must NOT receive a feefilter"
    );
    assert_eq!(
        mgr.force_initial_send(legacy, false),
        None,
        "force_initial_send must return None for a pre-70013 peer"
    );
}

// ─── Test 4: IBD sends the MAX_MONEY filter ─────────────────────────────────
//
// During IBD, Core sets currentFilter = MAX_MONEY ("don't send me txs") because
// inbound tx-INVs are discarded while in IBD. The broadcast value must equal
// round(MAX_MONEY), and crucially must differ from the post-IBD filter.
#[test]
fn ibd_sends_max_money_filter() {
    let mut mgr = FeeFilterManager::default();
    let t0 = Instant::now();
    let peer = PeerId(5);
    mgr.add_peer_at(t0, peer, true, false);

    // Force the timer due and poll with is_ibd = true.
    let due = t0 - Duration::from_secs(1);
    assert!(mgr.set_next_send_for_test(peer, due));

    // mempool_min_fee is deliberately small; IBD must override it with MAX_MONEY.
    let pending = mgr.get_pending_feefilters_at(t0, /*mempool_min_fee=*/ 1_000, /*is_ibd=*/ true);
    assert_eq!(pending.len(), 1, "IBD peer must receive a feefilter, got {:?}", pending);
    assert_eq!(pending[0].0, peer);

    let rounder = FeeFilterRounder::new(DEFAULT_INCREMENTAL_RELAY_FEE);
    let max_money_rounded = rounder.round(MAX_MONEY);
    assert_eq!(
        pending[0].1, max_money_rounded,
        "during IBD the feefilter must be round(MAX_MONEY), not the mempool min fee"
    );

    // Sanity: the IBD filter is far above any normal mempool min fee, proving
    // it is the "don't send me txs" signal and not the real filter.
    assert!(
        pending[0].1 > 1_000_000,
        "round(MAX_MONEY) must be enormous (the suppression signal), got {}",
        pending[0].1
    );

    // The forced initial send during IBD must also yield round(MAX_MONEY).
    let fresh = PeerId(6);
    mgr.add_peer_at(t0, fresh, true, false);
    let initial = mgr
        .force_initial_send(fresh, /*is_ibd=*/ true)
        .expect("eligible peer must get an initial send");
    assert_eq!(
        initial, max_money_rounded,
        "force_initial_send during IBD must yield round(MAX_MONEY)"
    );
}
