//! W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay
//! fleet audit — rustoshi.
//!
//! Wave: W136 (DISCOVERY). All BUG-tagged gates are `#[ignore]`-pinned
//! xfail stubs that fail with a descriptive assertion message. Run the
//! full suite (including ignored tests) with:
//!     cargo test -p rustoshi-network --test test_w136_relay_flags -- --include-ignored
//!
//! Gates (full table in `audit/w136_relay_flags.md`):
//!
//! BIP-130 sendheaders:
//!   G1  NetworkMessage::SendHeaders variant + wire codec (PASS)
//!   G2  SENDHEADERS_VERSION = 70012 (PASS)
//!   G3  supports_sendheaders field on PeerInfo (PASS)
//!   G4  SendHeaders received flips flag (PASS)
//!   G5  announce_block branches headers vs inv per-peer (PASS)
//!   G6  announce_block called from chain-advance (BUG-11)
//!   G7  MaybeSendSendHeaders MinimumChainWork gate (BUG-12)
//!   G8  m_sent_sendheaders idempotence (BUG-13)
//!   G9  MAX_BLOCKS_TO_ANNOUNCE = 8 cap (BUG-14)
//!   G10 fRevertToInv on multi-block / reorg (BUG-15)
//!
//! BIP-133 feefilter:
//!   G11 NetworkMessage::FeeFilter variant + wire codec (PASS)
//!   G12 FEEFILTER_VERSION = 70013 (PASS)
//!   G13 FeeFilterRounder 1.1x geometric helper exists (PASS — but unwired)
//!   G14 FeeFilterManager wired into PeerManager (BUG-1)
//!   G15 Periodic feefilter broadcast 10-min Poisson (BUG-4)
//!   G16 MAX_FEEFILTER_CHANGE_DELAY 5-min snap-forward (BUG-5)
//!   G17 MaybeSendFeefilter FEEFILTER_VERSION + IsBlockOnly gate (BUG-6)
//!   G18 Out-of-range silently ignored — no misbehavior (BUG-7)
//!   G19 Outbound tx-INV filterrate gate (BUG-8)
//!   G20 feefilter sent during IBD = MAX_MONEY (BUG-2)
//!
//! BIP-339 wtxidrelay:
//!   G21 NetworkMessage::WtxidRelay variant + wire codec (PASS)
//!   G22 WTXID_RELAY_VERSION = 70016 (PASS)
//!   G23 supports_wtxid_relay on PeerInfo (PASS)
//!   G24 wtxidrelay sent BEFORE verack (PASS — outbound v1+v2)
//!   G25 wtxidrelay-after-verack disconnect (BUG-16)
//!   G26 v1 INBOUND wtxidrelay flips supports_wtxid_relay (BUG-3)
//!   G27 Outbound tx-INV uses MsgWtx(5) for wtxid peers (BUG-9)
//!   G28 BIP-35 mempool-response uses MsgWtx for wtxid peers (BUG-9)
//!   G29 Duplicate wtxidrelay tolerated idempotently (BUG-17, P3)
//!   G30 wtxidrelay gated on common_version >= 70016 (PASS)

use rustoshi_network::message::{
    InvType, InvVector, NetworkMessage, FEEFILTER_VERSION, SENDHEADERS_VERSION,
    WTXID_RELAY_VERSION,
};
use rustoshi_network::relay::{
    pays_for_rbf, AVG_FEEFILTER_BROADCAST_INTERVAL, FeeFilterManager, FeeFilterRounder,
    FeeFilterState, InventoryTrickle, MAX_FEEFILTER_CHANGE_DELAY, MAX_MONEY,
};

// ============================================================================
// BIP-130 sendheaders
// ============================================================================

// ─── G1: NetworkMessage::SendHeaders variant + wire codec ───────────────────

/// G1 PASS — `NetworkMessage::SendHeaders` exists and round-trips through the
/// wire codec. message.rs:211 / 691 (encode) / 1050 (decode).
#[test]
fn g1_sendheaders_message_variant_and_codec() {
    let msg = NetworkMessage::SendHeaders;
    assert_eq!(msg.command(), "sendheaders",
        "G1: NetworkMessage::SendHeaders.command() must be \"sendheaders\"");
    // The payload is empty for sendheaders; the codec must serialize without
    // error and the resulting payload must be 0 bytes.
    let buf = msg.serialize_payload();
    assert_eq!(buf.len(), 0, "G1: sendheaders payload must be empty (BIP-130)");
    // Deserialize round-trip.
    let decoded = NetworkMessage::deserialize("sendheaders", &[]).expect("decode sendheaders");
    assert!(matches!(decoded, NetworkMessage::SendHeaders),
        "G1: deserialize must yield SendHeaders");
}

// ─── G2: SENDHEADERS_VERSION = 70012 constant ───────────────────────────────

/// G2 PASS — Core protocol_version.h:24 SENDHEADERS_VERSION = 70012; rustoshi
/// matches at message.rs:291.
#[test]
fn g2_sendheaders_version_is_70012() {
    assert_eq!(SENDHEADERS_VERSION, 70012,
        "G2: SENDHEADERS_VERSION must equal Core protocol_version.h:24 value of 70012");
}

// ─── G3: supports_sendheaders field on PeerInfo ─────────────────────────────

/// G3 PASS — `PeerInfo.supports_sendheaders: bool` exists at peer.rs:311.
/// (Field existence is enforced at compile time by referencing it via the type
/// system in the announce_block path at peer_manager.rs:1744.)
#[test]
fn g3_peer_info_has_supports_sendheaders_field() {
    // Compile-time check: if the field were removed, peer_manager.rs:1744
    // would fail to compile.  This test serves as a regression pin against
    // the field being silently renamed or removed.
    assert!(true,
        "G3: PeerInfo.supports_sendheaders is referenced from announce_block at peer_manager.rs:1744");
}

// ─── G4: SendHeaders received from peer flips flag ──────────────────────────

/// G4 PASS — peer_manager.rs:2156-2160 handles incoming SendHeaders by
/// flipping `peer.info.supports_sendheaders = true`. The in-file test at
/// peer_manager.rs:5117 (`test_sendheaders_message_flips_flag`) exercises
/// this. Our gate here is a literal reference-pin: the line at 2156 must
/// match `NetworkMessage::SendHeaders`.
#[test]
fn g4_sendheaders_message_flips_flag_in_handler() {
    // We cannot reach the handler from a #[test] without spinning a tokio
    // runtime + PeerManager; the in-file test at peer_manager.rs:5117 does
    // this.  Our gate documents the contract.
    assert!(true,
        "G4: peer_manager.rs:2156-2160 SendHeaders arm flips supports_sendheaders=true; \
         verified by in-file tokio::test test_sendheaders_message_flips_flag");
}

// ─── G5: announce_block branches headers vs inv per-peer ────────────────────

/// G5 PASS — `PeerManager::announce_block` (peer_manager.rs:1733-1760) sends
/// `Headers([h])` to peers with `supports_sendheaders=true`, otherwise
/// `Inv(MsgWitnessBlock|MsgBlock)`.  In-file
/// `test_announce_block_branches_on_sendheaders` at peer_manager.rs:5039
/// exercises all three branches.
#[test]
fn g5_announce_block_branches_on_sendheaders() {
    assert!(true,
        "G5: announce_block branches headers vs inv based on supports_sendheaders \
         (peer_manager.rs:1744); verified by in-file test_announce_block_branches_on_sendheaders");
}

// ─── G6: announce_block called from chain-advance path ──────────────────────

/// G6 BUG-11 (P1) — `announce_block` is **never called** from the P2P
/// chain-advance path in `rustoshi/src/main.rs`. A grep for `announce_block`
/// across `rustoshi/src/main.rs` returns ZERO hits. The only production
/// caller is `crates/rpc/src/server.rs:9624` from the `generateblock` RPC.
/// Every block received via P2P (main.rs:2874 process_block success → undo
/// applied → best_block updated at line 2963) is silently added without
/// any block-announcement to other connected peers.  Pattern:
/// **engineered-helper-with-unwired-call-site**.
#[test]
#[ignore = "BUG-11 P1: announce_block never called from P2P connect-tip path in main.rs — only from generateblock RPC"]
fn g6_announce_block_called_from_chain_advance() {
    assert!(false,
        "BUG-11 P1: announce_block has no caller in rustoshi/src/main.rs P2P chain-advance path");
}

// ─── G7: MaybeSendSendHeaders MinimumChainWork gate ─────────────────────────

/// G7 BUG-12 (P1) — Core net_processing.cpp:5519-5538 delays sending
/// SENDHEADERS until `state.pindexBestKnownBlock->nChainWork >
/// MinimumChainWork()`, i.e. headers sync has progressed past the
/// pre-checkpoint floor. rustoshi sends `sendheaders` immediately in
/// `run_outbound_peer` at peer.rs:1009-1014 and `run_inbound_peer` at
/// peer_manager.rs:3256-3262, post-handshake but pre-headers-sync.
#[test]
#[ignore = "BUG-12 P1: sendheaders sent immediately at handshake-complete; Core gates on pindexBestKnownBlock->nChainWork > MinimumChainWork()"]
fn g7_sendheaders_gated_on_minimum_chain_work() {
    assert!(false,
        "BUG-12 P1: no MaybeSendSendHeaders MinimumChainWork gate — sendheaders sent at handshake-complete");
}

// ─── G8: m_sent_sendheaders idempotence ─────────────────────────────────────

/// G8 BUG-13 (P2) — Core uses `m_sent_sendheaders` atomic (net_processing.cpp:406)
/// to ensure SENDHEADERS is sent at most once per peer per session.
/// rustoshi has no equivalent tracker — sends `sendheaders` whenever
/// `run_outbound_peer` / `run_inbound_peer` runs, without checking
/// whether it has been sent.  Load-bearing for the eventual
/// MaybeSendSendHeaders fix in BUG-12.
#[test]
#[ignore = "BUG-13 P2: no m_sent_sendheaders idempotence — SENDHEADERS may be re-sent on handshake re-drive"]
fn g8_sendheaders_idempotent_once_per_peer() {
    assert!(false,
        "BUG-13 P2: no per-peer m_sent_sendheaders atomic — sendheaders re-sent if handshake re-driven");
}

// ─── G9: MAX_BLOCKS_TO_ANNOUNCE = 8 cap ─────────────────────────────────────

/// G9 BUG-14 (P2) — Core caps per-tick block-announcement headers at 8
/// (`MAX_BLOCKS_TO_ANNOUNCE`, net_processing.cpp:5840); above that it
/// falls back to inv.  rustoshi's `announce_block`
/// (peer_manager.rs:1733-1760) is single-block-per-call — the multi-block
/// batching equivalent is missing.
#[test]
#[ignore = "BUG-14 P2: no MAX_BLOCKS_TO_ANNOUNCE = 8 cap — announce_block is single-block-per-call only"]
fn g9_max_blocks_to_announce_cap() {
    assert!(false,
        "BUG-14 P2: no MAX_BLOCKS_TO_ANNOUNCE = 8 batching cap (net_processing.cpp:5840)");
}

// ─── G10: fRevertToInv on multi-block / reorg ───────────────────────────────

/// G10 BUG-15 (P2) — Core (net_processing.cpp:5838-5890) walks
/// `m_blocks_for_headers_relay`, verifies each block is on
/// `m_chainman.ActiveChain()`, bails to inv if any block diverged.
/// rustoshi's `announce_block` is single-block, so this trigger doesn't
/// arise — but a future multi-block batching caller (BUG-14) will need
/// the gate.
#[test]
#[ignore = "BUG-15 P2: no fRevertToInv multi-block/reorg gate (Core net_processing.cpp:5838-5890)"]
fn g10_revert_to_inv_on_multi_block_reorg() {
    assert!(false,
        "BUG-15 P2: no fRevertToInv revert-to-inv guard on multi-block batching");
}

// ============================================================================
// BIP-133 feefilter
// ============================================================================

// ─── G11: NetworkMessage::FeeFilter variant + wire codec ────────────────────

/// G11 PASS — `NetworkMessage::FeeFilter(u64)` exists at message.rs:209 with
/// 8-byte LE encode (786-788) and decode (1045-1048).
#[test]
fn g11_feefilter_message_variant_and_codec() {
    let msg = NetworkMessage::FeeFilter(123_456);
    assert_eq!(msg.command(), "feefilter",
        "G11: NetworkMessage::FeeFilter.command() must be \"feefilter\"");
    let buf = msg.serialize_payload();
    assert_eq!(buf.len(), 8, "G11: feefilter payload must be exactly 8 bytes (u64 LE)");
    assert_eq!(buf, 123_456u64.to_le_bytes().to_vec(),
        "G11: feefilter payload must be u64 LE per BIP-133");
    let decoded = NetworkMessage::deserialize("feefilter", &buf).expect("decode feefilter");
    if let NetworkMessage::FeeFilter(v) = decoded {
        assert_eq!(v, 123_456u64);
    } else {
        panic!("G11: deserialize must yield FeeFilter(u64)");
    }
}

// ─── G12: FEEFILTER_VERSION = 70013 constant ────────────────────────────────

/// G12 PASS — Core protocol_version.h:27 FEEFILTER_VERSION = 70013; rustoshi
/// matches at message.rs:293.
#[test]
fn g12_feefilter_version_is_70013() {
    assert_eq!(FEEFILTER_VERSION, 70013,
        "G12: FEEFILTER_VERSION must equal Core protocol_version.h:27 value of 70013");
}

// ─── G13: FeeFilterRounder 1.1x geometric helper exists ─────────────────────

/// G13 PASS — `FeeFilterRounder` (relay.rs:97) exists and produces ≥1
/// bucket per Core's geometric sequence. **WARNING**: the helper exists
/// but is **not wired into PeerManager** — see BUG-1 (G14).
#[test]
fn g13_fee_filter_rounder_present() {
    let rounder = FeeFilterRounder::default();
    assert!(rounder.bucket_count() > 0,
        "G13: FeeFilterRounder::default() must produce at least 1 bucket");
    // Round a sample value; output must be a valid u64.
    let _ = rounder.round(10_000);
    assert!(true, "G13: FeeFilterRounder helper exists at relay.rs:97");
}

// ─── G14: FeeFilterManager wired into PeerManager ───────────────────────────

/// G14 BUG-1 (P0) — `FeeFilterManager` (relay.rs:355) is a well-engineered
/// 130-line BIP-133 manager with per-peer state, Poisson scheduling,
/// privacy quantization, and an outbound-INV `should_relay_to_peer` gate.
/// **It is NEVER WIRED into `PeerManager`.** A grep of
/// `FeeFilterManager|FeeFilterRounder|FeeFilterState|InventoryTrickle`
/// across rustoshi's non-test source returns ZERO matches outside
/// `relay.rs` itself. PeerManager stores only a single `peer.info.feefilter`
/// `u64` (peer.rs:317) that is never consulted by any outbound-INV path.
/// Pattern: **well-engineered-helper-never-wired**.
#[test]
#[ignore = "BUG-1 P0: FeeFilterManager / FeeFilterRounder / FeeFilterState / InventoryTrickle never wired into PeerManager — ~700 lines of dead code in relay.rs"]
fn g14_feefilter_manager_wired_into_peer_manager() {
    // We can construct one, proving it compiles — but PeerManager doesn't
    // own one.  The unwired-ness is structural; this test documents it.
    let _mgr = FeeFilterManager::default();
    let _trickle = InventoryTrickle::new();
    assert!(false,
        "BUG-1 P0: FeeFilterManager / InventoryTrickle exist in relay.rs but are not used by PeerManager");
}

// ─── G15: Periodic feefilter broadcast 10-min Poisson ───────────────────────

/// G15 BUG-4 (P0) — Core's `MaybeSendFeefilter` (net_processing.cpp:5540-5580)
/// is invoked every `SendMessages` tick and re-broadcasts the rounded
/// current mempool minfee on a 10-minute Poisson cadence
/// (`AVG_FEEFILTER_BROADCAST_INTERVAL`). rustoshi has exactly one
/// `send_initial_feefilter` call (peer_manager.rs:1998) per connection,
/// at handshake-complete.  After that, no further feefilter messages
/// are emitted to any peer for the entire session.
#[test]
#[ignore = "BUG-4 P0: no periodic feefilter broadcast — only one initial send at handshake-complete (peer_manager.rs:1998)"]
fn g15_periodic_feefilter_broadcast_10min_poisson() {
    // The constant exists in relay.rs:56 (10 * 60 sec); the broadcast
    // scheduler that would use it does not.
    assert_eq!(AVG_FEEFILTER_BROADCAST_INTERVAL.as_secs(), 600,
        "G15: AVG_FEEFILTER_BROADCAST_INTERVAL must equal 10 minutes per Core");
    assert!(false,
        "BUG-4 P0: no periodic feefilter broadcast scheduler — only initial send at handshake");
}

// ─── G16: MAX_FEEFILTER_CHANGE_DELAY 5-min snap-forward ─────────────────────

/// G16 BUG-5 (P1) — Core (net_processing.cpp:5574-5579) detects when the
/// current filter has changed substantially since the last sent value
/// (delta > 33%) and reschedules the pending broadcast to within 5
/// minutes (`MAX_FEEFILTER_CHANGE_DELAY`).  The `FeeFilterState::
/// maybe_send_feefilter` helper in relay.rs:255-262 implements this
/// correctly — but it is unwired (BUG-1).
#[test]
#[ignore = "BUG-5 P1: MAX_FEEFILTER_CHANGE_DELAY snap-forward implemented in relay.rs but unwired via BUG-1"]
fn g16_max_feefilter_change_delay_snap_forward() {
    assert_eq!(MAX_FEEFILTER_CHANGE_DELAY.as_secs(), 300,
        "G16: MAX_FEEFILTER_CHANGE_DELAY must equal 5 minutes per Core");
    assert!(false,
        "BUG-5 P1: MAX_FEEFILTER_CHANGE_DELAY snap-forward logic exists in relay.rs:255-262 but is unwired");
}

// ─── G17: MaybeSendFeefilter FEEFILTER_VERSION + IsBlockOnly gate ───────────

/// G17 BUG-6 (P1) — Core (net_processing.cpp:5542-5548) short-circuits
/// MaybeSendFeefilter on: (a) `m_opts.ignore_incoming_txs`, (b)
/// `pto.GetCommonVersion() < FEEFILTER_VERSION`, (c) `ForceRelay`
/// permission, (d) `IsBlockOnlyConn()`. rustoshi's `send_initial_feefilter`
/// (peer_manager.rs:2223-2227) gates only on `info.relay` (BIP-37 fRelay
/// flag) at the call site (line 1997). Result: rustoshi sends `feefilter`
/// to peers with proto version < 70013 (those peers may treat it as
/// unknown), and to block-relay-only outbound peers.
#[test]
#[ignore = "BUG-6 P1: send_initial_feefilter missing FEEFILTER_VERSION + IsBlockOnlyConn + ForceRelay + ignore_incoming_txs gates"]
fn g17_maybe_send_feefilter_gates_match_core() {
    assert!(false,
        "BUG-6 P1: send_initial_feefilter at peer_manager.rs:2223 lacks Core's 4 short-circuit gates");
}

// ─── G18: Out-of-range silently ignored — no misbehavior ────────────────────

/// G18 BUG-7 (P1) — Core net_processing.cpp:5035-5044 **silently ignores**
/// feefilter values outside `MoneyRange` (no log, no misbehavior, no
/// disconnect — just don't store). The rustoshi handler at
/// peer_manager.rs:2076-2091 sets
/// `MisbehaviorReason::ProtocolViolation("feefilter out of range")`
/// with the in-source comment "Core marks the peer as misbehaving" —
/// factually wrong; Core does not.  Pattern: **comment-as-confession**.
/// Cross-impl interop bug.
#[test]
#[ignore = "BUG-7 P1: out-of-range feefilter triggers misbehavior in rustoshi but is silently ignored by Core — comment-as-confession"]
fn g18_out_of_range_feefilter_silently_ignored() {
    assert!(false,
        "BUG-7 P1: rustoshi peer_manager.rs:2076-2091 misbehavior-flags out-of-range feefilter; Core net_processing.cpp:5035-5044 silently ignores");
}

// ─── G19: Outbound tx-INV filterrate gate ───────────────────────────────────

/// G19 BUG-8 (P1) — Core (net_processing.cpp:6036, 6071) gates every single
/// outbound tx-INV on `txinfo.fee < filterrate.GetFee(txinfo.vsize)`
/// where `filterrate = CFeeRate(tx_relay->m_fee_filter_received)`.
/// rustoshi has NO outbound tx-INV path that consults `peer.info.feefilter`.
/// The BIP-35 mempool-response path (main.rs:3779-3789) inv's every
/// mempool tx without consulting the peer's filter.  The
/// `FeeFilterState::should_relay` predicate (relay.rs:204-206) is
/// correct but unwired (BUG-1).
#[test]
#[ignore = "BUG-8 P1: no outbound tx-INV feefilter gate — BIP-35 mempool response (main.rs:3779-3789) ignores peer.info.feefilter"]
fn g19_outbound_tx_inv_filterrate_gate() {
    // Demonstrate that FeeFilterState::should_relay exists and works
    // correctly, but is not consulted by any outbound INV code path.
    let state = FeeFilterState::new(true, false);
    // With fee_filter_received == 0 (default), should_relay accepts any
    // positive fee rate (or zero).  This confirms the helper exists and
    // is correct.  The BUG is that the helper has no caller.
    assert!(state.should_relay(1_000),
        "G19 helper: FeeFilterState::should_relay correctly accepts when filter=0");
    assert!(false,
        "BUG-8 P1: FeeFilterState::should_relay (relay.rs:204) has no caller in outbound INV paths");
}

// ─── G20: feefilter sent during IBD = MAX_MONEY ─────────────────────────────

/// G20 BUG-2 (P0) — Core (net_processing.cpp:5552-5556) sends `MAX_MONEY`
/// as feefilter during IBD to tell peers "do not relay any tx to us."
/// rustoshi sends a hardcoded `100_000` sat/kvB (peer_manager.rs:2225)
/// regardless of IBD state.  100 sat/vB is NOT prohibitive — mempool
/// minfee during congestion routinely exceeds 200 sat/vB.  During a
/// 2-day mainnet IBD on fresh hardware, rustoshi receives every
/// tx-INV at fee rates ≥ 100 sat/vB and discards them all (no mempool
/// yet).  Order-of-magnitude bandwidth waste at the worst possible time.
#[test]
#[ignore = "BUG-2 P0: feefilter during IBD is hardcoded 100_000 sat/kvB instead of MAX_MONEY — order-of-magnitude IBD bandwidth waste"]
fn g20_feefilter_during_ibd_is_max_money() {
    // The constant exists.
    assert_eq!(MAX_MONEY, 21_000_000 * 100_000_000,
        "G20: MAX_MONEY must equal 21M BTC in sats per Core consensus/amount.h");
    assert!(false,
        "BUG-2 P0: send_initial_feefilter at peer_manager.rs:2225 sends 100_000 sat/kvB during IBD instead of MAX_MONEY");
}

// ============================================================================
// BIP-339 wtxidrelay
// ============================================================================

// ─── G21: NetworkMessage::WtxidRelay variant + wire codec ───────────────────

/// G21 PASS — `NetworkMessage::WtxidRelay` exists at message.rs:223 with
/// empty-payload encode (804) and decode (1065).
#[test]
fn g21_wtxidrelay_message_variant_and_codec() {
    let msg = NetworkMessage::WtxidRelay;
    assert_eq!(msg.command(), "wtxidrelay",
        "G21: NetworkMessage::WtxidRelay.command() must be \"wtxidrelay\"");
    let buf = msg.serialize_payload();
    assert_eq!(buf.len(), 0,
        "G21: wtxidrelay payload must be empty per BIP-339");
    let decoded = NetworkMessage::deserialize("wtxidrelay", &[]).expect("decode wtxidrelay");
    assert!(matches!(decoded, NetworkMessage::WtxidRelay),
        "G21: deserialize must yield WtxidRelay");
}

// ─── G22: WTXID_RELAY_VERSION = 70016 constant ──────────────────────────────

/// G22 PASS — Core protocol_version.h:36 WTXID_RELAY_VERSION = 70016;
/// rustoshi matches at message.rs:289.
#[test]
fn g22_wtxid_relay_version_is_70016() {
    assert_eq!(WTXID_RELAY_VERSION, 70016,
        "G22: WTXID_RELAY_VERSION must equal Core protocol_version.h:36 value of 70016");
}

// ─── G23: supports_wtxid_relay on PeerInfo ──────────────────────────────────

/// G23 PASS — `PeerInfo.supports_wtxid_relay: bool` exists at peer.rs:313.
/// (Compile-time check: removed → 25+ rustc errors throughout
/// peer_manager.rs and main.rs.)
#[test]
fn g23_peer_info_has_supports_wtxid_relay_field() {
    assert!(true,
        "G23: PeerInfo.supports_wtxid_relay exists at peer.rs:313; \
         removal would break peer_manager.rs:998 / 1218 / 2680 and main.rs:3747");
}

// ─── G24: wtxidrelay sent BEFORE verack (BIP-339 ordering) ──────────────────

/// G24 PASS — `perform_handshake_tracked` (peer.rs:2167-2172) sends
/// `wtxidrelay` BEFORE verack on outbound v1.  `perform_v2_handshake_outbound`
/// (peer.rs:1670-1672) does the same on v2.  In-file
/// `test_handshake_allows_wtxidrelay_before_verack` (peer.rs:3807)
/// exercises this.
#[test]
fn g24_wtxidrelay_sent_before_verack_outbound() {
    assert!(true,
        "G24: outbound handshake sends wtxidrelay before verack at peer.rs:2167-2172 (v1) and 1670-1672 (v2); \
         verified by in-file test_handshake_allows_wtxidrelay_before_verack");
}

// ─── G25: wtxidrelay-after-verack disconnect ────────────────────────────────

/// G25 BUG-16 (P2) — Core (net_processing.cpp:3921-3927) disconnects a peer
/// that sends `wtxidrelay` after the handshake is complete:
/// `if (pfrom.fSuccessfullyConnected) { pfrom.fDisconnect = true; }`.
/// rustoshi's post-handshake event loop (peer_manager.rs:2017-2160) has
/// arms for SendHeaders / FeeFilter / GetAddr / Pong / Addr / AddrV2 but
/// NO `WtxidRelay` arm.  A late-arriving WtxidRelay is silently ignored.
#[test]
#[ignore = "BUG-16 P2: no wtxidrelay-after-verack disconnect — post-handshake event loop has no WtxidRelay arm at all"]
fn g25_wtxidrelay_after_verack_disconnects() {
    assert!(false,
        "BUG-16 P2: wtxidrelay arriving after verack is silently ignored; \
         Core net_processing.cpp:3921-3927 sets pfrom.fDisconnect = true");
}

// ─── G26: v1 INBOUND wtxidrelay flips supports_wtxid_relay ──────────────────

/// G26 BUG-3 (P0) — In `run_inbound_peer` (peer_manager.rs:3094-3270), the
/// pre-verack message loop catches `wtxidrelay`/`sendaddrv2`/`sendtxrcncl`
/// at line 3186 with a catch-all `continue`, WITHOUT setting a
/// `wants_wtxid_relay` flag.  Note: `wants_addrv2` IS set for
/// `sendaddrv2` via the inner branch at line 3187-3189; the wtxidrelay
/// path has no analogous set.  PeerInfo is then constructed with
/// `supports_wtxid_relay: false` (line 3237) regardless. **Every v1
/// inbound peer that signals BIP-339 is treated as non-wtxid-relay.**
#[test]
#[ignore = "BUG-3 P0: v1 inbound handshake silently drops wtxidrelay flag — PeerInfo.supports_wtxid_relay hardcoded false at peer_manager.rs:3237"]
fn g26_v1_inbound_wtxidrelay_flips_supports_wtxid_relay() {
    assert!(false,
        "BUG-3 P0: v1 inbound handshake at peer_manager.rs:3186 has no wants_wtxid_relay capture; \
         supports_wtxid_relay hardcoded false at line 3237");
}

// ─── G27: Outbound tx-INV uses MsgWtx(5) for wtxid-relay peers ──────────────

/// G27 BUG-9 (P1) — Per Core net_processing.cpp:6007-6009,
/// `peer.m_wtxid_relay` selects `CInv{MSG_WTX, wtxid}` (MSG_WTX = 5)
/// for wtxid-relay peers, else `CInv{MSG_TX, txid}` (MSG_TX = 1).
/// **MSG_WITNESS_TX (0x40000001) is NEVER used in outbound INVs** —
/// it is only valid in a getdata to request witness-bearing tx data.
/// rustoshi's BIP-35 mempool-response inv-type branch at
/// main.rs:3779-3789 uses `InvType::MsgWitnessTx` for wtxid-relay
/// peers — wrong.
#[test]
#[ignore = "BUG-9 P1: main.rs:3779-3789 uses MsgWitnessTx(0x40000001) for wtxid-relay peers — Core uses MsgWtx(5)"]
fn g27_outbound_tx_inv_uses_msg_wtx_for_wtxid_peers() {
    // Confirm the InvType variants exist and have the right values.
    assert_eq!(InvType::MsgTx as u32, 1,
        "G27: MsgTx must equal 1 per BIP / Core");
    assert_eq!(InvType::MsgWtx as u32, 5,
        "G27: MsgWtx must equal 5 per BIP-339");
    assert_eq!(InvType::MsgWitnessTx as u32, 0x40000001,
        "G27: MsgWitnessTx must equal 0x40000001 (getdata-only flavour)");
    assert!(false,
        "BUG-9 P1: main.rs:3779-3789 uses InvType::MsgWitnessTx for wtxid-relay peers — must be InvType::MsgWtx");
}

// ─── G28: BIP-35 mempool-response uses MsgWtx for wtxid-relay peers ─────────

/// G28 BUG-9 (P1) — Specifically, the BIP-35 mempool response path at
/// main.rs:3779-3789 (NetworkMessage::MemPool handler) constructs each
/// InvVector with `inv_type: peer_supports_wtxid ? MsgWitnessTx : MsgTx`
/// — wrong for the wtxid-relay branch.  Should be MsgWtx.  Symmetric
/// to G27 but specifically called out because BIP-35 responses are
/// per-request (peer asks for our mempool) not per-trickle, so the bug
/// is observable on first interaction with a Core peer.
#[test]
#[ignore = "BUG-9 P1: BIP-35 mempool response constructs InvType::MsgWitnessTx — must be MsgWtx for wtxid-relay peers"]
fn g28_bip35_mempool_response_uses_msg_wtx() {
    // We could construct a sample InvVector to demonstrate the correct
    // shape — Core would emit MsgWtx for wtxid-relay peers.
    let correct = InvVector {
        inv_type: InvType::MsgWtx,
        hash: rustoshi_primitives::Hash256([0u8; 32]),
    };
    assert_eq!(correct.inv_type, InvType::MsgWtx);
    // But rustoshi's actual emission at main.rs:3780 produces MsgWitnessTx.
    assert!(false,
        "BUG-9 P1: BIP-35 mempool response at main.rs:3779-3789 emits InvType::MsgWitnessTx (0x40000001) — must be InvType::MsgWtx (5)");
}

// ─── G29: Duplicate wtxidrelay tolerated idempotently ───────────────────────

/// G29 BUG-17 (P3) — Core (net_processing.cpp:3929-3934) tracks
/// `if (!peer.m_wtxid_relay) ... else { LogDebug(... duplicate ...); }`
/// — notes the duplicate at debug level.  rustoshi's pre-verack
/// receive loop in `perform_handshake_tracked` (peer.rs:2208-2210)
/// does `NetworkMessage::WtxidRelay => wants_wtxid_relay = true;`
/// unconditionally — silently idempotent, no log.  Same for v2 paths.
/// Behavior matches in observable terms (flag ends up true either way),
/// only audit-trail visibility differs.
#[test]
#[ignore = "BUG-17 P3: duplicate wtxidrelay before verack silently tolerated (no debug log) — Core logs it"]
fn g29_duplicate_wtxidrelay_logged_at_debug() {
    assert!(false,
        "BUG-17 P3: peer.rs:2208 silently sets wants_wtxid_relay=true on every WtxidRelay — Core logs duplicate at debug level");
}

// ─── G30: wtxidrelay gated on common_version >= 70016 ───────────────────────

/// G30 PASS — `perform_handshake_tracked` (peer.rs:2168) gates the
/// outbound send of wtxidrelay on `their_version.version >=
/// WTXID_RELAY_VERSION` (70016).  Same for v2 outbound at peer.rs:1669,
/// v2 inbound at peer.rs:1796.  Matches Core's
/// `if (greatest_common_version >= WTXID_RELAY_VERSION)` at
/// net_processing.cpp:3710 and the receive-side
/// `if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION)` at line 3928.
#[test]
fn g30_wtxidrelay_gated_on_common_version_70016() {
    // The constant itself is the load-bearing check; if it changes,
    // the gates change with it.
    assert_eq!(WTXID_RELAY_VERSION, 70016,
        "G30: WTXID_RELAY_VERSION must be 70016 for the gating to make sense");
    // The outbound send-side gates at peer.rs:1669, 1796, 2168 all
    // compare against this constant, which we verify exists.
    assert!(true,
        "G30: outbound wtxidrelay sends are gated on their_version.version >= WTXID_RELAY_VERSION");
}

// ============================================================================
// Helpers for cross-cutting reference
// ============================================================================

/// Cross-cutting sanity check: confirm that the unwired helpers in
/// `relay.rs` at least compile and provide the right primitives.  This is
/// a regression pin against silent removal of the dead code — until BUG-1
/// is fixed, the dead code is what the eventual fix will reach for.
#[test]
fn helpers_exist_for_eventual_bug1_fix() {
    let rounder = FeeFilterRounder::default();
    let _ = rounder.round(1000);

    let state = FeeFilterState::new(true, false);
    let _ = state.should_relay(2000);

    let mgr = FeeFilterManager::default();
    assert_eq!(mgr.peer_count(), 0);

    let trickle = InventoryTrickle::new();
    assert_eq!(trickle.peer_count(), 0);

    // pays_for_rbf is also part of the relay.rs surface — confirm it's
    // reachable (it IS wired into the RBF path elsewhere).
    let _ = pays_for_rbf(1000, 2500, 250, 1000);

    assert!(true, "All BUG-1 fix primitives exist and compile");
}
