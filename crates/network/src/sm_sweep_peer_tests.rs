//! State-machine sweep (sm-sweep-rustoshi), path d: peer connection states.
//!
//! Child module of `peer_manager` so it can reach the private peer table.
//! Every test here fails on master by design: the sweep confirms gaps, it
//! does not fix them. They are `#[ignore]`d so CI stays green; run with
//! `cargo test -p rustoshi-network sm_sweep -- --include-ignored`.
//! A test whose gap has been fixed drops its `#[ignore]` and runs normally
//! (D-1b: peers-rustoshi-outbound; D-1a: sm-fix-rustoshi-chain-sync-eviction).

use super::*;
use crate::stale_detection::{CHAIN_SYNC_TIMEOUT, HEADERS_RESPONSE_TIME};

/// Drive the chain-sync eviction machine (`check_for_stale_peers` ->
/// `StalePeerDetector::check_chain_sync`) through its three ticks, the way the
/// 45 s maintenance tick in `main.rs` does: arm the 20-minute timeout, fire it
/// (send getheaders, arm the 2-minute timeout), fire that (disconnect).
/// Each wait is replaced by backdating the timeout. Returns true if the peer
/// was evicted for chain-sync timeout on any tick.
async fn run_chain_sync_ticks(mgr: &mut PeerManager, peer: PeerId) -> bool {
    for _ in 0..3 {
        mgr.force_stale_check_due();
        let r = mgr.check_for_stale_peers(0).await;
        if r.chain_sync_failures.contains(&peer) {
            return true;
        }
        if let Some(s) = mgr.get_peer_stale_state_mut(peer) {
            if s.chain_sync.timeout.is_some() {
                s.chain_sync.timeout = Some(Instant::now() - Duration::from_secs(1));
            }
        }
    }
    false
}

fn mgr() -> (tempfile::TempDir, PeerManager) {
    let dir = tempfile::TempDir::new().unwrap();
    let config = PeerManagerConfig::testnet4().with_data_dir(dir.path().to_path_buf());
    (dir, PeerManager::new(config, ChainParams::testnet4()))
}

fn backdate_connect(mgr: &mut PeerManager, peer: PeerId) {
    let p = mgr.peers.get_mut(&peer).unwrap();
    p.connected_time = Instant::now() - Duration::from_secs(120);
}

/// Control for the tests below: a full-relay outbound peer whose known height
/// stays below our tip IS evicted after the three ticks. This is Core's
/// behaviour too (ConsiderEviction), and it proves the tick driver reaches the
/// disconnect arm. Passes on master.
#[tokio::test]
async fn sm_sweep_control_lagging_full_relay_peer_is_evicted() {
    let (_d, mut mgr) = mgr();
    mgr.update_tip_height(100);
    let peer = PeerId(7);
    let _rx = mgr.insert_test_outbound_peer_old(peer, "192.0.2.7:8333".parse().unwrap());
    mgr.get_peer_stale_state_mut(peer).unwrap().best_known_height = 50;
    assert!(run_chain_sync_ticks(&mut mgr, peer).await);
    // Sanity on the constants the ticks stand in for.
    assert!(CHAIN_SYNC_TIMEOUT > HEADERS_RESPONSE_TIME);
}

/// Gap D-1a: chain-sync eviction applies to MANUAL (`-connect`/`-addnode`)
/// and FEELER peers.
///
/// `check_for_stale_peers` treats every non-inbound peer as outbound
/// (`p.conn_type != ConnectionType::Inbound`). Core runs ConsiderEviction only
/// when `pto.IsOutboundOrBlockRelayConn()` (net_processing.cpp
/// `PeerManagerImpl::ConsiderEviction`), which is false for MANUAL and FEELER
/// (net.h `CNode::IsOutboundOrBlockRelayConn`). A `--connect`-pinned node
/// therefore drops its only configured peers every ~23 minutes.
#[tokio::test]
async fn sm_sweep_manual_and_feeler_peers_are_not_chain_sync_evicted() {
    for (i, ct) in [ConnectionType::Manual, ConnectionType::Feeler].into_iter().enumerate() {
        let (_d, mut mgr) = mgr();
        mgr.update_tip_height(100);
        let peer = PeerId(10 + i as u64);
        let _rx = mgr.insert_test_peer_with_flags(
            peer,
            format!("192.0.2.{}:8333", 10 + i).parse().unwrap(),
            ct,
            false,
        );
        backdate_connect(&mut mgr, peer);
        mgr.get_peer_stale_state_mut(peer).unwrap().best_known_height = 50;
        assert!(
            !run_chain_sync_ticks(&mut mgr, peer).await,
            "{ct:?} peer was disconnected for chain-sync timeout; Core exempts it \
             (IsOutboundOrBlockRelayConn is false)"
        );
    }
}

/// Control for D-1a: the exemption is not wider than Core's. A lagging
/// BLOCK-RELAY-ONLY outbound peer is still chain-sync evicted, because
/// `IsOutboundOrBlockRelayConn` is true for BLOCK_RELAY.
#[tokio::test]
async fn sm_sweep_control_lagging_block_relay_only_peer_is_evicted() {
    let (_d, mut mgr) = mgr();
    mgr.update_tip_height(100);
    let peer = PeerId(12);
    let _rx = mgr.insert_test_peer_with_flags(
        peer,
        "192.0.2.12:8333".parse().unwrap(),
        ConnectionType::BlockRelayOnly,
        false,
    );
    backdate_connect(&mut mgr, peer);
    mgr.get_peer_stale_state_mut(peer).unwrap().best_known_height = 50;
    assert!(
        run_chain_sync_ticks(&mut mgr, peer).await,
        "lagging block-relay-only peer was not chain-sync evicted; Core evicts it"
    );
}

/// D-1a reaches production: the dial paths for operator-named peers open
/// them as `Manual`, as Core does (`ConnectionType::MANUAL` for `-connect` in
/// net.cpp `ThreadOpenConnections` and for `addnode onetry` in rpc/net.cpp).
/// If they dialed `FullRelay`, the chain-sync exemption above would never
/// apply to a live `-connect` / `addnode` peer.
#[tokio::test]
async fn sm_sweep_connect_and_onetry_peers_dial_as_manual() {
    let onetry: SocketAddr = "192.0.2.20:8333".parse().unwrap();
    let pinned: SocketAddr = "192.0.2.21:8333".parse().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let mut config = PeerManagerConfig::testnet4().with_data_dir(dir.path().to_path_buf());
    config.connect_peers = vec![pinned];
    let mut mgr = PeerManager::new(config, ChainParams::testnet4());

    mgr.connect_to_peer(onetry).await;
    mgr.maintain_connect_peers().await;

    for addr in [onetry, pinned] {
        let ct = mgr
            .peers
            .values()
            .find(|p| p.info.addr == addr)
            .map(|p| p.conn_type)
            .unwrap_or_else(|| panic!("{addr} was not dialed"));
        assert_eq!(ct, ConnectionType::Manual, "{addr} dialed as {ct:?}, Core uses MANUAL");
    }
}

/// Gap D-1b: the per-peer best-known height that chain-sync eviction reads is
/// never advanced by the blocks a peer actually relays.
///
/// The only production writer is `handle_event(PeerEvent::Message(_, Block))`,
/// and it records the peer's handshake `start_height`, not the block's height
/// (`peer.stale_state.block_received(peer.info.start_height)`). On top of that,
/// `main.rs` handles `block`, `headers`, `inv` and `cmpctblock` itself and never
/// forwards them to the peer manager, so on the live node the value stays at 0.
/// Core advances `pindexBestKnownBlock` from every headers/block/inv a peer
/// sends (`UpdateBlockAvailability`), and a peer that delivered our tip is never
/// evicted by ConsiderEviction.
///
/// This test feeds the manager the only way it is fed today (a `block`
/// message through `handle_event`) for a peer that connected at our tip (100)
/// and then relayed the block that became our tip (101). The message payload
/// stands in for block 101: the peer manager has no block index, and today's
/// code ignores the payload and records `start_height`. A fix must feed the
/// relayed block's height (101) by whatever call it adds; it then changes
/// only the feed line, not the assertion.
#[tokio::test]
async fn sm_sweep_peer_relaying_our_tip_is_not_chain_sync_evicted() {
    let (_d, mut mgr) = mgr();
    let params = ChainParams::testnet4();
    mgr.update_tip_height(100);
    let peer = PeerId(20);
    let _rx = mgr.insert_test_outbound_peer_old(peer, "192.0.2.20:8333".parse().unwrap());
    // Handshake said 100 (our tip at connect time).
    mgr.peers.get_mut(&peer).unwrap().info.start_height = 100;
    // The peer relays block 101, which becomes our tip (payload stands in,
    // see the doc comment). Fed the way main.rs now feeds it: Core
    // UpdateBlockAvailability with the relayed block's indexed height.
    let relayed = params.genesis_block.block_hash();
    mgr.update_block_availability(peer, relayed, |h| (*h == relayed).then_some(101));
    mgr.update_tip_height(101);
    assert!(
        !run_chain_sync_ticks(&mut mgr, peer).await,
        "peer that relayed our tip block was evicted for chain-sync timeout \
         (best_known_height={})",
        mgr.get_peer_stale_state_mut(peer).map(|s| s.best_known_height).unwrap_or(-1)
    );
}

/// Gap D-4: NODE_NETWORK is advertised in prune mode.
///
/// `local_services` set NODE_NETWORK unconditionally (fixed by
/// sm-fix-rustoshi-prune-node-network). Core only adds it when
/// not pruning and with no historical (background) chainstate (init.cpp,
/// "Setting NODE_NETWORK in non-prune mode"); a pruned node advertises
/// NODE_NETWORK_LIMITED only, so peers do not ask it for blocks it deleted.
/// `test_node_network_limited_advertised_when_prune_on` was flipped with the
/// fix; it asserted the old behaviour.
#[test]
fn sm_sweep_prune_mode_does_not_advertise_node_network() {
    let mut config = PeerManagerConfig::testnet4();
    config.prune_mode = true;
    let mgr = PeerManager::new(config, ChainParams::testnet4());
    let services = mgr.local_services();
    assert_ne!(services & NODE_NETWORK_LIMITED, 0, "control: LIMITED is set");
    assert_eq!(
        services & NODE_NETWORK,
        0,
        "pruned node advertises NODE_NETWORK (Core: NODE_NETWORK_LIMITED only)"
    );
}
