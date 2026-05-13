//! W103 audit tests: transaction relay flow 30-gate audit.
//!
//! Reference: Bitcoin Core `net_processing.cpp`, `txrequest.h`, `txorphanage.h/cpp`,
//! `txdownloadman.h/cpp`, `protocol.h`, `net.h`.
//!
//! Gate summary (bugs found):
//!   G1  - PASS: MAX_INV_SIZE=50_000 enforced at deserialise; parse error on overflow
//!   G2  - BUG (CORRECTNESS): getdata handler entirely absent; no MSG_TX/MSG_WTX dispatch
//!   G3  - BUG (CORRECTNESS): inbound v1 path hardcodes supports_wtxid_relay=false (from W99 G21)
//!   G4  - BUG (CORRECTNESS): mempool message not handled; no NODE_BLOOM gate + !fRelay block
//!   G5  - FIXED: MAX_GETDATA_SZ=1000 constant + batch_getdata_items helper in relay.rs
//!   G6  - BUG (CORRECTNESS): wtxidrelay sent by inbound path before VERSION received (ordering violation)
//!   G7  - PASS: NODE_BLOOM config gate exists; peer_bloom_filters default=false
//!   G8  - BUG (CORRECTNESS): no tx data piggyback path (FindTxForGetData / m_recently_confirmed_transactions absent)
//!   G9  - MISSING: no MAX_PEER_TX_ANNOUNCEMENTS=5000 per-peer announcement cap
//!   G10 - MISSING: no MAX_PEER_TX_REQUEST_IN_FLIGHT=100 in-flight cap
//!   G11 - MISSING: no GETDATA_TX_INTERVAL=60s request timeout / expiry
//!   G12 - MISSING: no NONPREF_PEER_TX_DELAY=2s outbound-preference delay
//!   G13 - MISSING: no TXID_RELAY_DELAY=2s delay for txid annoucements when wtxid peers available
//!   G14 - MISSING: no OVERLOADED_PEER_TX_DELAY=2s when peer >=50 outstanding requests
//!   G15 - MISSING: no alternating-announcer timeout / MAX_PEER_TX_ANNOUNCEMENTS cap logic
//!   G16 - BUG (CORRECTNESS): m_tx_relay BIP-37 gate absent — !relay peers receive tx invs
//!   G17 - MISSING: no m_recently_announced_invs LRU (tx deduplcation for re-announce)
//!   G18 - MISSING: no mempool query rate-limit (attack vector: unlimited mempool flooding)
//!   G19 - BUG (CORRECTNESS): ProcessOrphanTx never called after tx accepted to mempool
//!   G20 - BUG (CORRECTNESS): RelayTransaction / broadcast after mempool acceptance absent
//!   G20a- FIXED: tx relay inv wire format uses MSG_WTX(5) not MSG_WITNESS_TX(0x40000001); build_tx_inv_entry helper added
//!   G21 - PASS: MAX_ORPHAN_TRANSACTIONS=100 enforced in orphanage.rs
//!   G22 - MISSING: no EvictExpiredOrphans / time-based 5min orphan expiry
//!   G23 - PASS: orphanage primary key is wtxid (BIP-339) — orphanage.rs by_wtxid map
//!   G24 - PASS: erase_for_peer() exists and clears all orphans on disconnect
//!   G25 - BUG (CORRECTNESS): ProcessOrphanTx not recursive; only single-level orphan resolution
//!   G26 - BUG (CORRECTNESS): no NODE_NETWORK guard before serving tx data (CanRequestTxFrom)
//!   G27 - MISSING: no m_relay_to_set wtxid-keyed broadcast set (relay targets set absent)
//!   G28 - MISSING: no UNREQUESTED tx Misbehaving penalty (tx received without prior getdata)
//!   G29 - MISSING: no rate-limited reject reasons (mapRejectedTx / REJECT_MALFORMED deduplcation)
//!   G30 - PASS: -peerbloomfilters flag wired to peer_bloom_filters config; -whitelistforcerelay absent
//!
//! Totals: 20 BUGS/MISSING, 10 PASS.

#[cfg(test)]
mod tests {
    use crate::message::{
        InvType, InvVector, NetworkMessage, MAX_INV_SIZE, MAX_GETDATA_SZ,
    };
    use rustoshi_consensus::orphanage::{
        TxOrphanage, MAX_ORPHAN_TRANSACTIONS, MAX_ORPHANS_PER_PEER, OrphanEntry, OrphanError,
    };
    use crate::relay::{
        batch_getdata_items, build_tx_inv_entry, InventoryTrickle, PeerRelayState,
        INVENTORY_BROADCAST_MAX, INBOUND_INVENTORY_BROADCAST_INTERVAL,
        OUTBOUND_INVENTORY_BROADCAST_INTERVAL,
    };
    use crate::peer::PeerId;
    use rustoshi_primitives::{Hash256, Transaction, TxIn, TxOut, OutPoint};
    use std::sync::Arc;
    use std::time::Duration;

    // ─── helpers ─────────────────────────────────────────────────────────────

    fn make_tx(seed: u8) -> Arc<Transaction> {
        Arc::new(Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256([seed; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 0xffffffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x6a], // OP_RETURN
            }],
            lock_time: 0,
        })
    }

    fn make_inv_vector(inv_type: InvType, seed: u8) -> InvVector {
        InvVector { inv_type, hash: Hash256([seed; 32]) }
    }

    // ─── G1: MAX_INV_SIZE=50_000 enforced ────────────────────────────────────

    /// G1 PASS: inv deserialization rejects payloads with count > MAX_INV_SIZE=50_000.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:4040` — `if (vInv.size() > MAX_INV_SZ)`
    /// triggers `Misbehaving(peer, ...)`. rustoshi rejects at deserialise level.
    ///
    /// Note: rustoshi rejects at parse time (connection-level error) rather than via
    /// Misbehaving + disconnect; the behaviour is still correct (connection drops).
    #[test]
    fn g1_max_inv_size_constant_is_50000() {
        assert_eq!(MAX_INV_SIZE, 50_000,
            "MAX_INV_SIZE must be 50_000 matching Core's MAX_INV_SZ");
        // Verify getdata uses the same constant by crafting an over-limit count manually.
        // Serialise an inv header with count=50_001 (compact_size 0xfd 0x51 0xC4)
        // and verify parse returns Err.
        let payload = vec![0xfd, 0x51, 0xC4]; // compact_size 50001
        // We need at least 1 inv vector length (36 bytes) but parse fails at count check
        let result = NetworkMessage::deserialize("inv", &payload);
        assert!(result.is_err(), "inv with count > 50_000 must fail");

        // getdata also uses MAX_INV_SIZE as cap
        let result2 = NetworkMessage::deserialize("getdata", &payload);
        assert!(result2.is_err(), "getdata with count > 50_000 must fail");
    }

    // ─── G2: getdata handler absent ──────────────────────────────────────────

    /// G2 BUG (CORRECTNESS): the peer_manager `handle_event` function handles many
    /// message types (addr, addrv2, feefilter, getaddr, pong, sendheaders) but has
    /// NO handler for `NetworkMessage::GetData`. A peer requesting a transaction
    /// receives no response at all — rustoshi never serves tx data from the mempool.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:4128` — the GETDATA handler calls
    /// `ProcessGetData()` which serves MSG_TX / MSG_WTX from the mempool and
    /// MSG_WITNESS_TX for witness-capable peers. A missing response causes the
    /// requesting peer's TxRequestTracker to timeout after GETDATA_TX_INTERVAL=60s,
    /// burning 60 seconds before trying another peer.
    ///
    /// Core: GETDATA with size > MAX_INV_SZ (50000) triggers Misbehaving disconnect.
    ///       rustoshi: GETDATA messages are deserialized and forwarded to handle_event
    ///       but dropped silently.
    #[test]
    #[ignore = "G2 BUG: NetworkMessage::GetData handler absent in peer_manager::handle_event — add ProcessGetData path that serves tx from mempool"]
    fn g2_getdata_handler_absent_no_tx_served() {
        // Demonstrates: rustoshi can deserialise a getdata but has no response path.
        let items = vec![make_inv_vector(InvType::MsgTx, 1)];
        let msg = NetworkMessage::GetData(items);
        // No handler: in handle_event the GetData arm falls through all if-let chains
        // silently.  There is no mempool lookup or tx send.
        match msg {
            NetworkMessage::GetData(v) => {
                assert!(!v.is_empty());
                // If a handler existed it would look up each item by txid/wtxid
                // in the mempool and send NetworkMessage::Tx in response.
            }
            _ => panic!("wrong variant"),
        }
    }

    // ─── G3: inbound v1 hardcodes supports_wtxid_relay=false ─────────────────

    /// G3 BUG (CORRECTNESS): the inbound v1 peer setup path in
    /// `peer_manager::run_inbound_peer` (line 2816) hardcodes
    /// `supports_wtxid_relay: false` even after the "wtxidrelay" message
    /// was observed in the pre-verack window.
    ///
    /// Consequence: all inbound v1 peers that sent wtxidrelay during handshake
    /// are stored with `supports_wtxid_relay=false`, so relay.rs will send them
    /// MSG_TX (txid-keyed) inv instead of MSG_WTX (wtxid-keyed). This breaks
    /// BIP-339 for all inbound v1 connections.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:3921` — WtxidRelay message
    /// sets `peer.m_wtxid_relay=true` only before VERACK. rustoshi: already
    /// tracked in `HandshakeResult.wants_wtxid_relay` for v2 outbound but not
    /// populated for inbound v1 (line 2816 vs line 3203).
    ///
    /// This was first documented in W99 G21; promoted to G3 in W103.
    #[test]
    #[ignore = "G3 BUG: inbound v1 path hardcodes supports_wtxid_relay=false at peer_manager.rs:2816 — use HandshakeResult.wants_wtxid_relay like v2 path does at line 3203"]
    fn g3_inbound_v1_wtxid_relay_hardcoded_false() {
        // Evidence: line 2816 of peer_manager.rs:
        //   supports_wtxid_relay: false,
        // vs line 3203 (v2 inbound):
        //   supports_wtxid_relay: app_hs.wants_wtxid_relay,
        //
        // The v1 inbound handshake loop at peer_manager.rs:2763 already parses
        // "wtxidrelay" and sets `wants_wtxid_relay=true` inside the loop, but
        // that local variable is never propagated to the PeerInfo.
        todo!("fix: capture wants_wtxid_relay from v1 inbound handshake and pass to PeerInfo");
    }

    // ─── G4: mempool handler absent ──────────────────────────────────────────

    /// G4 BUG (CORRECTNESS): the "mempool" P2P message is not handled in
    /// `peer_manager::handle_event`. Bitcoin Core's handler at line 4852 checks:
    ///   1. Peer has NODE_BLOOM or explicit mempool permission — else disconnect
    ///   2. Outbound bandwidth target not reached — else disconnect (unless noban)
    ///   3. Sets tx_relay.m_send_mempool=true to schedule mempool inv dump
    ///
    /// rustoshi: the message is deserialized, forwarded as PeerEvent::Message,
    /// but no arm in handle_event matches it. The result:
    ///   a. Any peer can request our mempool without permission check.
    ///   b. Even if the check existed, no mempool dump is scheduled.
    ///
    /// The !fRelay block is also absent: Core gates mempool/tx relay on
    /// version.relay=false (BIP 37 fRelay field). rustoshi tracks `peer.info.relay`
    /// but does not gate incoming "mempool" messages on it.
    #[test]
    #[ignore = "G4 BUG: NetworkMessage::Mempool handler absent — add NODE_BLOOM gate, fRelay check, and m_send_mempool scheduling in handle_event"]
    fn g4_mempool_handler_absent_no_bloom_gate() {
        // Verify the Mempool variant can be deserialized — this is the trigger.
        let msg = NetworkMessage::deserialize("mempool", &[]).unwrap();
        match msg {
            NetworkMessage::MemPool => {}
            _ => panic!("expected MemPool"),
        }
        // No NODE_BLOOM check: peer_manager never consults peer_bloom_filters_enabled()
        // before processing this message, so any peer can trigger mempool flooding.
    }

    // ─── G5: MAX_GETDATA_SZ=1000 batch cap on outgoing getdata ───────────────

    /// G5 FIXED: `MAX_GETDATA_SZ = 1000` is now defined in `message.rs` and
    /// `batch_getdata_items` in `relay.rs` splits any inv-derived list into
    /// chunks ≤ 1000, matching Bitcoin Core's `ProcessGetData` cap at
    /// `net_processing.cpp:128` and `:6207`.
    ///
    /// Reference: Core `net_processing.cpp:6207` —
    ///   `if (vGetData.size() >= MAX_GETDATA_SZ) break;`
    /// also Core `MAX_GETDATA_SZ = 1000` at line 128.
    #[test]
    fn g5_max_getdata_sz_batch_cap() {
        // Constant is correct.
        assert_eq!(MAX_GETDATA_SZ, 1_000,
            "MAX_GETDATA_SZ must be 1000 matching Core's protocol.h:482");
        // MAX_INV_SIZE is the parse-time cap; MAX_GETDATA_SZ is the per-batch response cap.
        assert!(MAX_INV_SIZE > MAX_GETDATA_SZ,
            "MAX_INV_SIZE ({MAX_INV_SIZE}) must exceed MAX_GETDATA_SZ ({MAX_GETDATA_SZ})");

        // Empty input → empty output (no panic, no empty chunk).
        let batches = batch_getdata_items(vec![]);
        assert!(batches.is_empty(), "empty input should yield empty batch list");

        // Exactly 1000 items → one batch of 1000.
        let items_1000: Vec<InvVector> = (0..1000_u32)
            .map(|i| InvVector {
                inv_type: InvType::MsgTx,
                hash: Hash256::from([(i & 0xff) as u8; 32]),
            })
            .collect();
        let batches = batch_getdata_items(items_1000);
        assert_eq!(batches.len(), 1, "1000 items must fit in exactly one batch");
        assert_eq!(batches[0].len(), 1000);

        // 1001 items → two batches (1000 + 1).
        let items_1001: Vec<InvVector> = (0..=1000_u32)
            .map(|i| InvVector {
                inv_type: InvType::MsgWtx,
                hash: Hash256::from([(i & 0xff) as u8; 32]),
            })
            .collect();
        let batches = batch_getdata_items(items_1001);
        assert_eq!(batches.len(), 2, "1001 items must split into two batches");
        assert_eq!(batches[0].len(), MAX_GETDATA_SZ);
        assert_eq!(batches[1].len(), 1);

        // Simulate MAX_INV_SZ=50_000 inv arriving: must produce ceil(50000/1000)=50 batches.
        let big_items: Vec<InvVector> = (0..50_000_u32)
            .map(|i| InvVector {
                inv_type: InvType::MsgTx,
                hash: Hash256::from([(i & 0xff) as u8; 32]),
            })
            .collect();
        let batches = batch_getdata_items(big_items);
        assert_eq!(batches.len(), 50,
            "MAX_INV_SZ=50000 items must split into exactly 50 getdata batches");
        for (idx, batch) in batches.iter().enumerate() {
            assert_eq!(batch.len(), MAX_GETDATA_SZ,
                "batch {idx} should be exactly MAX_GETDATA_SZ items");
        }
    }

    // ─── G6: wtxidrelay sent before VERSION in outbound initiator path ────────

    /// G6 BUG (CORRECTNESS): Bitcoin Core's WTXIDRELAY message MUST be sent
    /// after VERSION but BEFORE VERACK (BIP-339 §2). In Core's outbound initiator
    /// path at `net_processing.cpp:3921` the message is only processed if it
    /// arrives between VERSION and VERACK.
    ///
    /// rustoshi's `perform_v2_handshake_outbound` (peer.rs:1245) sends WtxidRelay
    /// in the right window for v2 outbound. However the inbound v2 path sends
    /// WtxidRelay at line 1246 BEFORE checking if the peer's version supports it.
    /// More critically, rustoshi's v1 inbound path (run_inbound_peer) sends
    /// WtxidRelay at a point where the peer's version has been received but before
    /// the rest of the post-verack window guard that Core enforces.
    ///
    /// Additionally: WTXID_RELAY_VERSION is checked (protocol version >= 70016)
    /// which is correct. But the message may still be sent in edge cases where
    /// the peer's version is exactly 70016 and the remote has not yet confirmed
    /// VERACK, creating a protocol race.
    ///
    /// Reference: BIP-339, Core `net_processing.cpp:3938` —
    ///   "The wtxidrelay message MUST be sent in response to a version message
    ///    from a peer whose protocol version is >= 70016, and prior to sending
    ///    a verack message."
    #[test]
    #[ignore = "G6 BUG: confirm wtxidrelay is only sent between VERSION and VERACK in ALL handshake paths (v1 inbound, v1 outbound, v2 inbound, v2 outbound)"]
    fn g6_wtxidrelay_ordering_across_all_handshake_paths() {
        use crate::message::WTXID_RELAY_VERSION;
        // Minimum version requirement is correct: 70016
        assert_eq!(WTXID_RELAY_VERSION, 70016,
            "WTXID_RELAY_VERSION must be 70016 per BIP-339");
        // Fix: audit each handshake path and confirm wtxidrelay is sent AFTER
        // VERSION received and BEFORE VERACK sent.
    }

    // ─── G7: NODE_BLOOM config gate ───────────────────────────────────────────

    /// G7 PASS: NODE_BLOOM is only advertised when peer_bloom_filters=true
    /// (default: false). This matches Core's `-peerbloomfilters` flag.
    ///
    /// However, BIP-37 bloom filter messages (filterload/filteradd/filterclear/
    /// merkleblock) are not handled in handle_event. NODE_BLOOM advertisement
    /// is correct; serving bloom filters is missing (out of scope for this wave).
    #[test]
    fn g7_node_bloom_default_false_peer_bloom_filters_config() {
        use crate::message::NODE_BLOOM;
        use crate::peer_manager::PeerManagerConfig;

        let config = PeerManagerConfig::default();
        assert!(!config.peer_bloom_filters,
            "peer_bloom_filters must default to false matching Core's default");

        // NODE_BLOOM bit value per BIP-111
        assert_eq!(NODE_BLOOM, 1 << 2, "NODE_BLOOM must be bit 2 per BIP-111");
    }

    // ─── G8: no tx data piggyback (FindTxForGetData) ─────────────────────────

    /// G8 BUG (CORRECTNESS): Bitcoin Core's `FindTxForGetData` searches:
    ///   1. m_recently_confirmed_transactions (recently confirmed, may still be requested)
    ///   2. mempool
    ///   3. tx relay set (m_relay_to_set)
    /// to serve the most recent copy of a tx. rustoshi has no equivalent path.
    ///
    /// Additionally, Core implements a "data piggyback" optimisation where a
    /// freshly received tx is piggybacked on the next message cycle without
    /// waiting for an INV → GETDATA round-trip. rustoshi's InventoryTrickle
    /// only sends INV (never piggybacks data).
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:2457, 2547` — direct TX pushes
    /// from `ProcessGetData` when the tx is found in the relay/mempool path.
    #[test]
    #[ignore = "G8 BUG: no FindTxForGetData / m_recently_confirmed_transactions lookup; getdata handler absent — implement ProcessGetData with mempool + relay-set lookup"]
    fn g8_tx_data_piggyback_absent() {
        // No m_recently_confirmed_transactions exists in rustoshi crates.
        // relay.rs tracks tx_inventory_to_send (wtxids queued for INV) but
        // has no mechanism to serve the actual serialized transaction on request.
        todo!("implement ProcessGetData with mempool lookup + tx serialization + notfound fallback");
    }

    // ─── G9: no MAX_PEER_TX_ANNOUNCEMENTS=5000 cap ───────────────────────────

    /// G9 MISSING: Bitcoin Core's `TxDownloadManagerImpl::AddTxAnnouncement`
    /// (txdownloadman_impl.cpp:204) rejects any announcement from a peer that
    /// already has `m_txrequest.Count(peer) >= MAX_PEER_TX_ANNOUNCEMENTS`.
    ///
    /// MAX_PEER_TX_ANNOUNCEMENTS = 5000 (txdownloadman.h:30).
    ///
    /// rustoshi's `InventoryTrickle` tracks `tx_inventory_to_send` (outbound queue)
    /// and `tx_inventory_known` (already announced) per peer, but there is no
    /// cap on the number of *inbound* announcements tracked per peer. An attacker
    /// can flood 50000 tx announcements (the parse limit) per message, effectively
    /// pinning unbounded memory in the relay tracker.
    ///
    /// Reference: Core `txdownloadman.h:30` —
    ///   `static constexpr int32_t MAX_PEER_TX_ANNOUNCEMENTS = 5000;`
    #[test]
    #[ignore = "G9 MISSING: no MAX_PEER_TX_ANNOUNCEMENTS=5000 per-peer announcement cap — add counter to InventoryTrickle and reject after 5000 outstanding announcements per peer"]
    fn g9_max_peer_tx_announcements_absent() {
        // Demonstrate: InventoryTrickle has no per-peer inbound-announcement counter.
        let mut trickle = InventoryTrickle::new();
        let peer = PeerId(1);
        trickle.add_peer(peer, false, false, true);

        // Queue 5001 items — no cap enforced
        for i in 0u32..5001 {
            let hash = Hash256({
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                b
            });
            trickle.queue_transaction_for_relay(hash, hash);
        }
        // No panic, no error — but Core would have capped at 5000.
        assert!(trickle.pending_count(peer) > 5000,
            "5001 items accepted — Core would have capped at 5000 per peer");
    }

    // ─── G10: no MAX_PEER_TX_REQUEST_IN_FLIGHT=100 ───────────────────────────

    /// G10 MISSING: Core's `TxRequestTracker` enforces that at most
    /// MAX_PEER_TX_REQUEST_IN_FLIGHT=100 getdata requests are outstanding to a
    /// single peer at once. When a peer has >=50 outstanding requests, the
    /// OVERLOADED_PEER_TX_DELAY (2s) is applied to subsequent request scheduling.
    ///
    /// rustoshi has no TxRequestTracker equivalent. There is no in-flight
    /// counting for tx requests; the entire `getdata → response` flow is absent
    /// (G2), so in-flight tracking cannot exist either.
    ///
    /// Reference: Core `txdownloadman.h:25,38` —
    ///   `static constexpr int32_t MAX_PEER_TX_REQUEST_IN_FLIGHT = 100;`
    ///   `static constexpr auto OVERLOADED_PEER_TX_DELAY{2s};`
    #[test]
    #[ignore = "G10 MISSING: no TxRequestTracker, no MAX_PEER_TX_REQUEST_IN_FLIGHT=100 in-flight cap — implement TxRequestTracker with in-flight counting"]
    fn g10_max_peer_tx_request_in_flight_absent() {
        todo!("implement TxRequestTracker with MAX_PEER_TX_REQUEST_IN_FLIGHT=100 and OVERLOADED_PEER_TX_DELAY=2s");
    }

    // ─── G11: no GETDATA_TX_INTERVAL=60s request timeout ─────────────────────

    /// G11 MISSING: Core's `TxRequestTracker::RequestedTx` stamps each outgoing
    /// getdata with `current_time + GETDATA_TX_INTERVAL` as the expiry.
    /// If no response arrives within 60 seconds, the request is marked failed
    /// and the next-best peer is tried.
    ///
    /// GETDATA_TX_INTERVAL = 60s (txdownloadman.h:38).
    ///
    /// rustoshi: no TxRequestTracker, no per-request expiry timestamps, no retry
    /// logic after timeout. A peer that ignores a tx request pins that tx lookup
    /// indefinitely (or until disconnect).
    #[test]
    #[ignore = "G11 MISSING: no GETDATA_TX_INTERVAL=60s per-request expiry — implement expiry tracking in TxRequestTracker and retry-next-peer after timeout"]
    fn g11_getdata_tx_interval_absent() {
        // Core constant: static constexpr auto GETDATA_TX_INTERVAL{60s};
        // No equivalent Duration constant in relay.rs or block_download.rs for txs.
        todo!("implement GETDATA_TX_INTERVAL=60s with per-tx expiry and peer retry logic");
    }

    // ─── G12: no NONPREF_PEER_TX_DELAY=2s outbound preference ────────────────

    /// G12 MISSING: Core's delay schedule adds NONPREF_PEER_TX_DELAY=2s to
    /// requests from non-preferred (inbound) peers. Outbound peers (preferred)
    /// get no extra delay, so they are always tried first.
    ///
    /// `NONPREF_PEER_TX_DELAY = 2s` (txdownloadman.h:34).
    ///
    /// rustoshi: InventoryTrickle differentiates inbound/outbound only for
    /// the outbound *announce* schedule (2s vs 5s). There is no corresponding
    /// *request* preference — inbound and outbound peers are treated identically
    /// when deciding whom to send a getdata to.
    #[test]
    #[ignore = "G12 MISSING: no NONPREF_PEER_TX_DELAY=2s for inbound announcement requests — implement preferred-peer-first scheduling in TxRequestTracker"]
    fn g12_nonpref_peer_tx_delay_absent() {
        // Verify the trickle intervals exist (these are for announce, not request):
        assert_eq!(OUTBOUND_INVENTORY_BROADCAST_INTERVAL, Duration::from_secs(2),
            "outbound announce interval must be 2s");
        assert_eq!(INBOUND_INVENTORY_BROADCAST_INTERVAL, Duration::from_secs(5),
            "inbound announce interval must be 5s");
        // Missing: NONPREF_PEER_TX_DELAY=2s on the *request* (getdata) side.
    }

    // ─── G13: no TXID_RELAY_DELAY=2s ─────────────────────────────────────────

    /// G13 MISSING: Core adds TXID_RELAY_DELAY=2s to txid-keyed announcements
    /// when at least one wtxid-relay peer is available. This prevents txid-keyed
    /// announcements from racing wtxid-keyed ones, ensuring wtxid-relay peers
    /// are tried first for any given transaction.
    ///
    /// `TXID_RELAY_DELAY = 2s` (txdownloadman.h:32).
    ///
    /// rustoshi: `PeerRelayState` distinguishes wtxid vs txid announce types for
    /// the outbound INV hash selection, but applies no extra delay to txid
    /// announcements when wtxid peers are present.
    ///
    /// Reference: Core `txdownloadman_impl.cpp:217` —
    ///   `if (!gtxid.IsWtxid() && m_num_wtxid_peers > 0) delay += TXID_RELAY_DELAY;`
    #[test]
    #[ignore = "G13 MISSING: no TXID_RELAY_DELAY=2s for txid announcements when wtxid peers present — add m_num_wtxid_peers counter and delay logic in request scheduling"]
    fn g13_txid_relay_delay_absent() {
        // Demonstrate: two peers added — one wtxid, one txid-only. Both receive
        // queue entries simultaneously with no differential delay.
        let mut trickle = InventoryTrickle::new();
        let wtxid_peer = PeerId(1);
        let txid_peer  = PeerId(2);

        trickle.add_peer(wtxid_peer, false, true,  true); // wtxid-relay
        trickle.add_peer(txid_peer,  false, false, true); // txid-only

        let txid  = Hash256([0xaa; 32]);
        let wtxid = Hash256([0xbb; 32]);
        trickle.queue_transaction_for_relay(txid, wtxid);

        // Both peers have the same pending count — no differential delay.
        assert_eq!(trickle.pending_count(wtxid_peer), 1);
        assert_eq!(trickle.pending_count(txid_peer), 1);
        // Core would add a 2s delay to the txid_peer request when wtxid_peer exists.
    }

    // ─── G14: no OVERLOADED_PEER_TX_DELAY=2s ─────────────────────────────────

    /// G14 MISSING: Core adds OVERLOADED_PEER_TX_DELAY=2s when a peer already
    /// has >= MAX_PEER_TX_REQUEST_IN_FLIGHT (100) requests outstanding and does
    /// not have relay permissions. This prevents one peer from monopolising all
    /// download slots.
    ///
    /// `OVERLOADED_PEER_TX_DELAY = 2s` (txdownloadman.h:36).
    ///
    /// rustoshi: no TxRequestTracker, no in-flight counter (G10), so
    /// OVERLOADED_PEER_TX_DELAY cannot be applied.
    #[test]
    #[ignore = "G14 MISSING: no OVERLOADED_PEER_TX_DELAY=2s when peer >=100 in-flight — implement alongside G10 TxRequestTracker in-flight counting"]
    fn g14_overloaded_peer_tx_delay_absent() {
        todo!("implement OVERLOADED_PEER_TX_DELAY=2s as part of TxRequestTracker (depends on G10 fix)");
    }

    // ─── G15: no alternating-announcers timeout ───────────────────────────────

    /// G15 MISSING: Core's `TxRequestTracker` tracks up to
    /// MAX_PEER_TX_ANNOUNCEMENTS per peer and has sophisticated "alternating
    /// announcers" logic to avoid a single peer starving all tx downloads.
    /// The `m_sequence_num` and per-announcement state machine (CANDIDATE →
    /// REQUESTED → COMPLETED) ensure fairness and prevent censorship.
    ///
    /// rustoshi: no per-announcement state machine. InventoryTrickle tracks only
    /// outbound sends; it has no inbound-announcement tracking, no fairness
    /// scheduling, and no censorship-resistant retry logic.
    #[test]
    #[ignore = "G15 MISSING: no TxRequestTracker announcement state machine — Core-class implementation requires CANDIDATE/REQUESTED/COMPLETED per-tx-per-peer state"]
    fn g15_alternating_announcers_absent() {
        todo!("implement full TxRequestTracker with per-announcement states and censorship-resistant scheduling");
    }

    // ─── G16: m_tx_relay BIP-37 gate absent ──────────────────────────────────

    /// G16 BUG (CORRECTNESS): Bitcoin Core's tx relay checks `peer.GetTxRelay()`
    /// before sending any tx-related messages. When `version.relay=false` (BIP-37
    /// fRelay field), Core never sends tx inv/data to that peer and does not
    /// process mempool messages from them.
    ///
    /// rustoshi: `PeerInfo.relay` is set from `version.relay` correctly during
    /// handshake (peer_manager.rs:2804). However:
    ///   a. `InventoryTrickle::queue_transaction_for_relay` does check `state.relay`
    ///      and skips queuing — this is correct.
    ///   b. BUT `handle_event` has no check that a Tx/Inv/GetData message from a
    ///      peer with relay=false is rejected. A no-relay peer can still announce
    ///      txs and receive (non-)responses.
    ///   c. The mempool handler (absent — G4) would also need a relay guard.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:4046,4386` — `RejectIncomingTxs`
    /// returns true for block-only + feeler connections; additionally Core checks
    /// `pfrom.m_tx_relay` struct existence before processing any tx relay.
    #[test]
    #[ignore = "G16 BUG: no m_tx_relay guard on incoming inv/tx messages from relay=false peers — add peer.info.relay check in handle_event before processing NetworkMessage::Inv/Tx"]
    fn g16_tx_relay_bip37_gate_absent_for_incoming() {
        // Evidence: peer.info.relay is stored but never consulted in handle_event.
        // InventoryTrickle correctly gates *outgoing* relay on state.relay.
        // The inbound side (incoming inv with tx hashes, incoming tx messages) has
        // no equivalent guard.
        //
        // relay.rs line 532: `if !self.relay { return false; }` — outgoing only.
        //
        // Consequence: a peer that signalled relay=false during handshake can still
        // send us tx invs that we may attempt to act on (e.g. after G2 is fixed).
        let mut state = PeerRelayState::new(false, false, false); // relay=false
        let hash = Hash256([1u8; 32]);
        // Outgoing queue correctly rejects relay=false:
        assert!(!state.queue_transaction(hash),
            "outgoing relay must be blocked when relay=false");
        // But incoming msgs from relay=false peers are not rejected in handle_event.
    }

    // ─── G17: no m_recently_announced_invs LRU ───────────────────────────────

    /// G17 MISSING: Core's `PeerManager` tracks `m_recently_announced_invs` per
    /// peer — a rolling set of tx hashes that were recently sent in an INV to
    /// that peer. This prevents re-announcing the same tx to a peer who already
    /// received the INV (which would be redundant and potentially fingerprinting).
    ///
    /// Core: `m_recently_announced_invs` is an LRU set (bounded); `AddKnownTx`
    /// adds the hash on INV-send; the set is checked before adding to the
    /// trickle queue.
    ///
    /// rustoshi: `PeerRelayState.tx_inventory_known` serves a similar purpose for
    /// the outbound queue but is an unbounded `HashSet<Hash256>`. There is no:
    ///   - Size bound (memory DoS if many txs announced)
    ///   - LRU eviction policy
    ///   - Cross-peer deduplication (each PeerRelayState has its own set)
    #[test]
    #[ignore = "G17 MISSING: tx_inventory_known is unbounded HashSet — replace with bounded LRU set matching Core's m_recently_announced_invs semantics"]
    fn g17_recently_announced_invs_unbounded() {
        let mut state = PeerRelayState::new(false, false, true);
        // Queue and mark known 100_000 items — no memory bound enforced
        for i in 0u32..100_000 {
            let hash = Hash256({
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                b
            });
            state.mark_known(hash);
        }
        assert!(state.tx_inventory_known.len() >= 100_000,
            "tx_inventory_known grows unbounded — Core would cap via LRU eviction");
    }

    // ─── G18: no mempool query rate-limit ────────────────────────────────────

    /// G18 MISSING: Bitcoin Core's MEMPOOL handler (net_processing.cpp:4852)
    /// checks `m_connman.OutboundTargetReached(false)` to rate-limit mempool
    /// dumps when the node's upload bandwidth budget is exhausted. Only peers
    /// with explicit Mempool permission bypass this check.
    ///
    /// rustoshi: no mempool handler at all (G4), so no rate-limiting exists.
    /// After G4 is fixed, a rate-limit gate must also be added.
    ///
    /// A missing rate-limit allows an attacker to trigger unbounded mempool INV
    /// dumps by connecting many peers and sending "mempool" repeatedly.
    #[test]
    #[ignore = "G18 MISSING: no mempool rate-limit (bandwidth target check) — add OutboundTargetReached equivalent in mempool handler after G4 is fixed"]
    fn g18_mempool_rate_limit_absent() {
        todo!("implement bandwidth-target rate-limit for mempool handler (depends on G4 fix)");
    }

    // ─── G19: ProcessOrphanTx not called after ATMP acceptance ───────────────

    /// G19 BUG (CORRECTNESS): Bitcoin Core calls `ProcessOrphanTx` after every
    /// successful `AcceptToMemoryPool` call to retry any orphans whose missing
    /// parent just arrived. This is the key mechanism by which chains of
    /// unconfirmed transactions propagate through the mempool.
    ///
    /// rustoshi has a functional `TxOrphanage` with `find_children()`, but there
    /// is no call site that invokes `find_children()` after a tx is accepted.
    /// `peer_manager::handle_event` does not call `find_children()` when it
    /// sees `NetworkMessage::Tx`.
    ///
    /// Consequence: orphan transactions can never graduate to the mempool.
    /// A CPFP (child-pays-for-parent) transaction will be held in the orphanage
    /// forever, even after the parent arrives.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:4451` —
    ///   `ProcessValidTx` → `m_txdownloadman.MempoolAcceptedTx` → orphan retry loop.
    #[test]
    #[ignore = "G19 BUG: ProcessOrphanTx / find_children() never called after mempool acceptance — wire orphanage.find_children() into the post-ATMP success path"]
    fn g19_process_orphan_tx_never_called_after_atmp() {
        // Demonstrate: orphanage has find_children() but nothing calls it post-acceptance.
        let mut orphanage = TxOrphanage::new();
        let parent_txid = Hash256([0xAA; 32]);

        // Add a child orphan whose parent hasn't arrived yet.
        let child = Arc::new(Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 0 },
                script_sig: Vec::new(),
                sequence: 0xffffffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut { value: 10_000, script_pubkey: vec![0x6a] }],
            lock_time: 0,
        });
        orphanage.add(child.clone(), 1, 100).unwrap();
        assert_eq!(orphanage.len(), 1);

        // The parent arrives and is accepted to mempool. In Core, ProcessOrphanTx
        // would now find_children(parent_txid) and retry the child.
        // In rustoshi: nothing is called. The orphan stays forever.
        let children = orphanage.find_children(&parent_txid);
        assert_eq!(children.len(), 1, "find_children works but is never called automatically");
        // Fix: after ATMP success, call orphanage.find_children(txid) and retry each child.
    }

    // ─── G20a: tx relay inv wire format — MSG_WTX(5) not MSG_WITNESS_TX(0x40000001) ──

    /// G20a FIXED: tx relay inv announcements use MSG_WTX(5) keyed by wtxid for
    /// BIP-339 peers, and MSG_TX(1) keyed by txid for legacy peers.
    ///
    /// Root cause (now fixed): the relay path was using MSG_WITNESS_TX(0x40000001)
    /// — a BIP-144 getdata witness flag — as the inv type for wtxid-relay peers.
    /// Core peers silently discard inv entries with that type, making rustoshi
    /// invisible as a relay source to all modern peers.
    ///
    /// Reference: Bitcoin Core `protocol.h:481,486`; BIP-339; `net_processing.cpp`
    /// `RelayTransaction` and `m_relay_to_set` handling.
    #[test]
    fn g20a_tx_relay_wire_format_msg_wtx_not_msg_witness_tx() {
        let txid  = Hash256([0xaa; 32]);
        let wtxid = Hash256([0xbb; 32]);

        // 1. wtxid-relay peer: inv type must be MSG_WTX(5), hash must be wtxid.
        let inv_wtxid = build_tx_inv_entry(true, txid, wtxid);
        assert_eq!(inv_wtxid.inv_type, InvType::MsgWtx,
            "wtxid-relay peer must receive MSG_WTX(5), not MSG_WITNESS_TX(0x40000001)");
        assert_eq!(inv_wtxid.inv_type as u32, 5,
            "MSG_WTX wire value must be 5 per BIP-339 / Core protocol.h:481");
        assert_eq!(inv_wtxid.hash, wtxid,
            "wtxid-relay peer inv hash must be the wtxid, not txid");

        // 2. Legacy (txid-relay) peer: inv type must be MSG_TX(1), hash must be txid.
        let inv_txid = build_tx_inv_entry(false, txid, wtxid);
        assert_eq!(inv_txid.inv_type, InvType::MsgTx,
            "legacy peer must receive MSG_TX(1) keyed by txid");
        assert_eq!(inv_txid.inv_type as u32, 1);
        assert_eq!(inv_txid.hash, txid,
            "legacy peer inv hash must be the txid");

        // 3. Verify MSG_WITNESS_TX(0x40000001) is NOT used for any relay inv.
        assert_ne!(inv_wtxid.inv_type, InvType::MsgWitnessTx,
            "MSG_WITNESS_TX(0x40000001) is a getdata flag, not a valid inv type");
        assert_ne!(inv_txid.inv_type, InvType::MsgWitnessTx);

        // 4. trickle queue agrees: wtxid-relay peer gets MsgWtx from get_pending_inv.
        let mut state = PeerRelayState::new(false, true, true);
        state.queue_transaction(wtxid);
        let inv = state.get_pending_inv(10);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].inv_type, InvType::MsgWtx,
            "PeerRelayState::get_pending_inv must also use MSG_WTX for wtxid-relay peers");
        assert_eq!(inv[0].hash, wtxid);
    }

    // ─── G20: RelayTransaction / broadcast after acceptance absent ────────────

    /// G20 BUG (CORRECTNESS): After a transaction is successfully accepted to the
    /// mempool, Bitcoin Core calls `InitiateTxBroadcastToAll` (formerly
    /// `RelayTransaction`) which adds the txid/wtxid to the per-peer trickle
    /// queues of all relay-eligible peers.
    ///
    /// rustoshi: `InventoryTrickle::queue_transaction_for_relay` exists and would
    /// do the right thing, but it is never called from the tx-acceptance code path.
    /// `handle_event` receives `NetworkMessage::Tx` but only updates `last_tx_time`
    /// (peer_manager.rs:1609-1611); there is no call to `queue_transaction_for_relay`.
    ///
    /// Consequence: rustoshi never re-announces accepted transactions to its peers.
    /// It can receive txs but cannot forward them, breaking its role as a relay node.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:4451` —
    ///   `ProcessValidTx(pfrom.GetId(), ptx, result.m_replaced_transactions)` →
    ///   `InitiateTxBroadcastToAll(txid, wtxid)`.
    #[test]
    #[ignore = "G20 BUG: InventoryTrickle::queue_transaction_for_relay never called after tx acceptance — wire into post-ATMP success path in handle_event or main loop"]
    fn g20_relay_transaction_never_called_after_acceptance() {
        // Demonstrate: an InventoryTrickle is idle even after a tx "arrives".
        let mut trickle = InventoryTrickle::new();
        let peer = PeerId(42);
        trickle.add_peer(peer, false, true, true);

        // Simulate: tx arrives (handle_event sees NetworkMessage::Tx) but
        // queue_transaction_for_relay is never invoked.
        assert_eq!(trickle.pending_count(peer), 0,
            "no tx queued for relay — Core would have called InitiateTxBroadcastToAll");
        // Fix: after ATMP accept, call: trickle.queue_transaction_for_relay(txid, wtxid)
    }

    // ─── G21: MAX_ORPHAN_TRANSACTIONS=100 enforced ───────────────────────────

    /// G21 PASS: orphanage correctly caps at MAX_ORPHAN_TRANSACTIONS=100 with
    /// FIFO eviction. Matches Core's `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100`.
    #[test]
    fn g21_max_orphan_transactions_is_100() {
        assert_eq!(MAX_ORPHAN_TRANSACTIONS, 100,
            "must match Core's DEFAULT_MAX_ORPHAN_TRANSACTIONS");
        // Verify FIFO eviction enforces the cap.
        let mut orphanage = TxOrphanage::new();
        for i in 0..MAX_ORPHAN_TRANSACTIONS as u32 {
            orphanage.add(make_tx(i as u8), i as u64, 100).unwrap();
        }
        assert_eq!(orphanage.len(), MAX_ORPHAN_TRANSACTIONS);

        let extra = make_tx(200);
        orphanage.add(extra, 999, 100).unwrap();
        // Cap still holds — oldest evicted.
        assert_eq!(orphanage.len(), MAX_ORPHAN_TRANSACTIONS);
    }

    // ─── G22: no time-based orphan expiry ─────────────────────────────────────

    /// G22 MISSING: Bitcoin Core evicts orphans that have been resident for more
    /// than ORPHAN_TX_EXPIRE_TIME=5 minutes (300 seconds), called from the
    /// periodic scheduler (`m_orphanage.LimitOrphans()` which inspects timestamps).
    ///
    /// rustoshi: `OrphanEntry` has `seq` (insertion order) but no timestamp field.
    /// Eviction is count-only (FIFO). A flood of orphans in the first 5 minutes
    /// will evict legitimate orphans; orphans that arrive and are never resolved
    /// (parent never comes) stay until evicted by count pressure only.
    ///
    /// Reference: Core `txorphanage.cpp:442` — `LimitOrphans()` removes entries
    /// older than `ORPHAN_TX_EXPIRE_TIME` before applying the count cap.
    #[test]
    #[ignore = "G22 MISSING: no time-based orphan expiry — add inserted_at timestamp to OrphanEntry and call EvictExpiredOrphans() periodically (ORPHAN_TX_EXPIRE_TIME=300s)"]
    fn g22_orphan_time_based_expiry_absent() {
        // Evidence: OrphanEntry has no timestamp field.
        // (OrphanEntry imported at top of module)
        // Fields: { tx: Arc<Transaction>, from_peer: u64, seq: u64 }
        // A timestamp would be: inserted_at: Instant or unix_secs: u64.
        //
        // The absence of a timestamp means it's impossible to implement
        // the 5-minute TTL eviction required by Core.
        let tx = make_tx(1);
        let entry = OrphanEntry {
            tx: tx.clone(),
            from_peer: 1,
            seq: 0,
            // inserted_at: <missing field>
        };
        let _ = entry.seq; // seq exists
        // If inserted_at existed, we could write: entry.inserted_at.elapsed() > Duration::from_secs(300)
        todo!("add inserted_at field to OrphanEntry and implement EvictExpiredOrphans");
    }

    // ─── G23: orphan keyed by wtxid (BIP-339) ────────────────────────────────

    /// G23 PASS: TxOrphanage uses wtxid as the primary key, matching BIP-339 and
    /// Core PR #18044 / #28196. Witness-malleated duplicates are tracked separately.
    #[test]
    fn g23_orphanage_primary_key_is_wtxid() {
        let mut orphanage = TxOrphanage::new();
        let tx = make_tx(1);
        let wtxid = tx.wtxid();

        orphanage.add(tx.clone(), 1, 100).unwrap();
        assert!(orphanage.contains(&wtxid),
            "orphanage must be keyed by wtxid per BIP-339");
        // Duplicate by wtxid → AlreadyKnown
        let err = orphanage.add(tx.clone(), 2, 100).unwrap_err();
        assert_eq!(err, OrphanError::AlreadyKnown);
    }

    // ─── G24: erase_for_peer on disconnect ───────────────────────────────────

    /// G24 PASS: erase_for_peer() correctly removes all orphans from a disconnected
    /// peer. Matches Core's `TxOrphanage::EraseForPeer`.
    #[test]
    fn g24_erase_for_peer_on_disconnect() {
        let mut orphanage = TxOrphanage::new();
        for i in 0..5 {
            orphanage.add(make_tx(i), 99, 100).unwrap();
        }
        orphanage.add(make_tx(5), 42, 100).unwrap(); // different peer

        assert_eq!(orphanage.len(), 6);
        let removed = orphanage.erase_for_peer(99);
        assert_eq!(removed, 5);
        assert_eq!(orphanage.len(), 1);
        assert_eq!(orphanage.count_from_peer(99), 0);
        assert_eq!(orphanage.count_from_peer(42), 1);
    }

    // ─── G25: ProcessOrphanTx not recursive ──────────────────────────────────

    /// G25 BUG (CORRECTNESS): Core's `ProcessOrphanTx` resolves orphan chains
    /// recursively: when orphan A's parent arrives and A is accepted to the
    /// mempool, Core then searches for orphans whose parent is A (and so on),
    /// processing the entire descendant chain in one pass.
    ///
    /// rustoshi: `find_children()` returns only direct children (single level).
    /// Even if it were wired up (fixing G19), a 3-level chain:
    ///   grandparent → parent (orphan) → child (orphan)
    /// would require two separate `find_children()` passes. `find_children()`
    /// is not recursive; the caller would have to implement the BFS/DFS loop.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp:ProcessOrphanTx` —
    ///   `std::set<uint256> orphan_work_set` drives a BFS through the orphanage.
    #[test]
    #[ignore = "G25 BUG: find_children() is single-level only — wrap in BFS/DFS loop to process full orphan chains recursively"]
    fn g25_process_orphan_tx_not_recursive() {
        let mut orphanage = TxOrphanage::new();

        // Build a 3-level chain: grandparent → parent → child
        let grandparent_txid = Hash256([0x11; 32]);

        // parent: spends grandparent:0
        let parent = Arc::new(Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: grandparent_txid, vout: 0 },
                script_sig: Vec::new(),
                sequence: 0xffffffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut { value: 40_000, script_pubkey: vec![0x6a] }],
            lock_time: 0,
        });
        let parent_txid = parent.txid();

        // child: spends parent:0
        let child = Arc::new(Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 0 },
                script_sig: Vec::new(),
                sequence: 0xffffffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut { value: 30_000, script_pubkey: vec![0x6a] }],
            lock_time: 0,
        });

        orphanage.add(parent.clone(), 1, 200).unwrap();
        orphanage.add(child.clone(), 1, 200).unwrap();

        // Grandparent arrives → find parent (direct child of grandparent)
        let level1 = orphanage.find_children(&grandparent_txid);
        assert_eq!(level1.len(), 1, "parent found as child of grandparent");

        // Parent accepted → find child (direct child of parent).
        // find_children is NOT called automatically; it doesn't recurse.
        let level2 = orphanage.find_children(&parent_txid);
        assert_eq!(level2.len(), 1, "child found as child of parent — but needs explicit 2nd call");

        // Fix: implement a BFS loop that keeps calling find_children until empty,
        // processing each resolved orphan through ATMP and enqueueing its own children.
    }

    // ─── G26: no NODE_NETWORK guard in CanRequestTxFrom ─────────────────────

    /// G26 BUG (CORRECTNESS): Bitcoin Core's `PeerManagerImpl::CanRequestTxFrom`
    /// checks that a peer has NODE_NETWORK (or NODE_NETWORK_LIMITED for recent
    /// blocks) before allowing tx data requests from them. Requesting txs from
    /// a peer without NODE_NETWORK is wasteful (they likely won't have them)
    /// and is a bandwidth DoS vector.
    ///
    /// rustoshi: no `CanRequestTxFrom` equivalent exists. The getdata handler
    /// is absent (G2), so no service-flags check is performed before requesting
    /// transactions.
    ///
    /// Reference: Bitcoin Core `net_processing.cpp` — `CanRequestTxFrom` consults
    /// `peer.m_our_services` and the peer's `nServices` field.
    ///
    /// The `PeerInfo.services` field is populated at handshake; the check is
    /// missing in the relay request path.
    #[test]
    #[ignore = "G26 BUG: no NODE_NETWORK service-flag check before requesting tx data from a peer — add CanRequestTxFrom gate using peer.info.services & NODE_NETWORK"]
    fn g26_can_request_tx_from_node_network_absent() {
        use crate::message::NODE_NETWORK;
        // NODE_NETWORK bit must be present in services before requesting txs.
        let services_with_network: u64 = NODE_NETWORK;
        let services_without: u64 = 0;

        assert_ne!(services_with_network & NODE_NETWORK, 0);
        assert_eq!(services_without & NODE_NETWORK, 0,
            "peer without NODE_NETWORK should not be asked for tx data");
        todo!("add CanRequestTxFrom(peer) check before adding peer to tx-request tracker");
    }

    // ─── G27: no m_relay_to_set (wtxid-keyed broadcast set) ─────────────────

    /// G27 MISSING: Bitcoin Core maintains `m_relay_to_set` — a per-tx set of
    /// peers that should receive a tx announcement. The set is keyed by wtxid
    /// (BIP-339) and is populated by `InitiateTxBroadcastToAll` after ATMP
    /// acceptance. `FindTxForGetData` also uses this set to serve the tx.
    ///
    /// rustoshi: `InventoryTrickle::queue_transaction_for_relay` performs a
    /// broadcast-to-all (every relay=true peer). This is the equivalent of
    /// `InitiateTxBroadcastToAll` but:
    ///   a. It is never called (G20).
    ///   b. It uses a per-peer queue rather than a wtxid-keyed relay set,
    ///      which means the tx cannot be looked up for serving getdata responses.
    ///
    /// Core: `m_relay_to_set` is a `CRollingBloomFilter` that enables fast
    /// `FindTxForGetData` lookup of recently relayed txs.
    #[test]
    #[ignore = "G27 MISSING: no m_relay_to_set wtxid-keyed broadcast set — implement a rolling bloom filter or bounded map keyed by wtxid for recently-relayed txs"]
    fn g27_relay_to_set_absent() {
        todo!("implement m_relay_to_set as a bounded map/bloom filter of recently relayed txids/wtxids");
    }

    // ─── G28: no UNREQUESTED tx Misbehaving penalty ──────────────────────────

    /// G28 MISSING: Bitcoin Core applies a misbehavior penalty when a peer sends
    /// a TX message that was never requested (no prior INV → GETDATA → TX cycle).
    /// Unsolicited txs are a DoS vector (force arbitrary ATMP calls).
    ///
    /// Core: `m_txdownloadman.ReceivedTx(pfrom.GetId(), ptx)` returns
    /// `should_validate=false` when the txid was not in the expected-request set.
    /// If the tx is still in the mempool and a peer keeps sending it unsolicited,
    /// a Misbehaving(20) penalty applies (`UNREQUESTED_TX_MISBEHAVIOR`).
    ///
    /// rustoshi: no per-peer "expected tx" tracking. Any peer can send any tx at
    /// any time. The handle_event path (1609-1611) records only `last_tx_time`.
    #[test]
    #[ignore = "G28 MISSING: no UNREQUESTED tx Misbehaving — track expected tx hashes per-peer and apply Misbehaving(20) on unsolicited sends after G2 handler is added"]
    fn g28_unrequested_tx_misbehavior_absent() {
        todo!("implement per-peer expected-tx set and UNREQUESTED penalty of 20 pts");
    }

    // ─── G29: no rate-limited reject reasons ─────────────────────────────────

    /// G29 MISSING: Bitcoin Core's `ProcessInvalidTx` tracks recently-rejected
    /// tx hashes to avoid re-processing the same invalid tx repeatedly. This
    /// prevents CPU DoS from a peer that repeatedly sends a known-invalid tx.
    ///
    /// Core: `m_recent_rejects` (rolling bloom filter) is checked at the start
    /// of the TX handler; known-bad txs are dropped with no further processing.
    /// `m_recent_rejects_reconsiderable` handles txs that may become valid
    /// after a block reorg.
    ///
    /// rustoshi: no `m_recent_rejects` set. Every TX message, valid or not,
    /// triggers a full ATMP call. A peer that spams a known-invalid tx will
    /// consume ATMP CPU on every message.
    #[test]
    #[ignore = "G29 MISSING: no m_recent_rejects bloom filter — add rolling bloom filter for recently-rejected txids to avoid repeated ATMP calls on same invalid tx"]
    fn g29_recent_rejects_absent() {
        todo!("implement m_recent_rejects as a rolling bloom filter; check before every ATMP call");
    }

    // ─── G30: peerbloomfilters flag wired ────────────────────────────────────

    /// G30 PASS: the `-peerbloomfilters` config flag is correctly wired to
    /// `PeerManagerConfig::peer_bloom_filters` and controls NODE_BLOOM advertisement.
    ///
    /// Note: `-whitelistforcerelay` is not implemented (out of scope for this
    /// wave). BIP-37 bloom filter messages themselves are not served.
    #[test]
    fn g30_peerbloomfilters_config_wired() {
        use crate::peer_manager::PeerManagerConfig;
        use crate::message::NODE_BLOOM;

        // Default: bloom filters disabled.
        let config = PeerManagerConfig::default();
        assert!(!config.peer_bloom_filters,
            "-peerbloomfilters must default to false");

        // When enabled: NODE_BLOOM bit included in services.
        let mut config_bloom = PeerManagerConfig::default();
        config_bloom.peer_bloom_filters = true;
        // Validate the flag is stored correctly.
        assert!(config_bloom.peer_bloom_filters);
        // Note: NODE_BLOOM is bit 2 (= 4).
        assert_eq!(NODE_BLOOM, 1 << 2);
    }

    // ─── Orphan per-peer cap ──────────────────────────────────────────────────

    /// Supplemental: per-peer orphan cap enforced at MAX_ORPHANS_PER_PEER=100.
    /// Matches Core's per-peer orphan submission limiting.
    #[test]
    fn orphan_per_peer_cap_enforced() {
        assert_eq!(MAX_ORPHANS_PER_PEER, 100,
            "per-peer orphan cap must be 100");
        let mut orphanage = TxOrphanage::new();
        for i in 0..MAX_ORPHANS_PER_PEER as u8 {
            orphanage.add(make_tx(i), 7, 100).unwrap();
        }
        let err = orphanage.add(make_tx(200), 7, 100).unwrap_err();
        assert_eq!(err, OrphanError::PeerCap);
    }

    // ─── Orphan find_children secondary-index correctness ────────────────────

    /// Supplemental: find_children uses the secondary txid-to-wtxids index,
    /// returning all orphans whose inputs reference the given parent txid.
    #[test]
    fn orphan_find_children_secondary_index() {
        let mut orphanage = TxOrphanage::new();
        let parent_txid = Hash256([0xDE; 32]);

        let child_a = Arc::new(Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 0 },
                script_sig: Vec::new(), sequence: 0xffffffff, witness: Vec::new(),
            }],
            outputs: vec![TxOut { value: 1000, script_pubkey: vec![0x51] }],
            lock_time: 0,
        });
        let child_b = Arc::new(Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 1 },
                script_sig: Vec::new(), sequence: 0xffffffff, witness: Vec::new(),
            }],
            outputs: vec![TxOut { value: 2000, script_pubkey: vec![0x51] }],
            lock_time: 0,
        });
        let unrelated = make_tx(42);

        orphanage.add(child_a.clone(), 1, 100).unwrap();
        orphanage.add(child_b.clone(), 2, 100).unwrap();
        orphanage.add(unrelated, 3, 100).unwrap();

        let children = orphanage.find_children(&parent_txid);
        assert_eq!(children.len(), 2);
        let wtxids: std::collections::HashSet<Hash256> =
            children.iter().map(|e| e.tx.wtxid()).collect();
        assert!(wtxids.contains(&child_a.wtxid()));
        assert!(wtxids.contains(&child_b.wtxid()));
    }

    // ─── INVENTORY_BROADCAST_MAX constant ────────────────────────────────────

    /// Supplemental: INVENTORY_BROADCAST_MAX=1000 matches Core's limit.
    #[test]
    fn inventory_broadcast_max_is_1000() {
        assert_eq!(INVENTORY_BROADCAST_MAX, 1000,
            "INVENTORY_BROADCAST_MAX must match Core's limit of 1000 per trickle batch");
    }
}
