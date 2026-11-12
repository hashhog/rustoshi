//! cffix-rustoshi-main-loop-send-await: the P2P main loop must never await a
//! single peer's bounded command channel.
//!
//! A peer that never reads leaves its writer parked in `write_all` for up to
//! `PEER_SEND_TIMEOUT` (120 s); its 32-slot command queue then fills. Every
//! `command_tx.send(..).await` the main loop makes to that peer used to park
//! the whole loop behind it. Core never blocks its message handler on one
//! peer: `ProcessMessages` returns early on `fPauseSend`
//! (net_processing.cpp:5157) and `fDisconnect` is a flag, not a queued send.
//!
//! These tests fill a peer's queue (its receiver is held but never polled)
//! and then drive the reply / disconnect paths under a 1 s timeout. On the
//! base commit each of them times out.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustoshi_consensus::params::ChainParams;
use rustoshi_network::{
    NetworkMessage, PeerCommand, PeerEvent, PeerId, PeerManager, PeerManagerConfig,
};

const LIMIT: Duration = Duration::from_secs(1);

fn manager() -> PeerManager {
    PeerManager::new(PeerManagerConfig::default(), ChainParams::regtest())
}

/// Seed shareable addresses so a getaddr has something to answer with
/// (Core's cap is floor(23% of the pool); 100 entries -> 23 sent).
fn seed_addrs(mgr: &mut PeerManager) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for i in 1..=100u32 {
        let addr: SocketAddr = format!("8.{}.{}.{}:8333", i / 50 + 1, i % 50 + 1, i)
            .parse()
            .unwrap();
        mgr.add_address_entry(addr, 1, now);
        mgr.addr_manager_mut().mark_success(&addr);
    }
}

/// Fill the peer's command queue until a non-blocking send is refused.
fn fill(mgr: &PeerManager, id: PeerId) -> usize {
    let mut n = 0;
    while mgr.try_send_to_peer(id, NetworkMessage::Ping(n as u64)) {
        n += 1;
        assert!(n < 10_000, "command channel never filled");
    }
    assert_eq!(mgr.send_capacity(id), 0);
    n
}

#[tokio::test]
async fn send_to_full_peer_channel_does_not_block() {
    let mut mgr = manager();
    seed_addrs(&mut mgr);

    // Positive control: with room in the queue the getaddr IS answered, so
    // the full-queue case below really reaches the reply send.
    let ctl = PeerId(1);
    let mut ctl_rx = mgr.insert_observable_peer(ctl, "9.9.9.1:8333".parse().unwrap());
    mgr.handle_event(PeerEvent::Message(ctl, NetworkMessage::GetAddr))
        .await;
    assert!(
        matches!(
            ctl_rx.try_recv(),
            Ok(PeerCommand::SendMessage(NetworkMessage::Addr(ref a))) if !a.is_empty()
        ),
        "control: getaddr on a peer with queue room must be answered"
    );

    // The stuck peer: receiver held (channel open) but never polled.
    let stuck = PeerId(2);
    let _stuck_rx = mgr.insert_observable_peer(stuck, "9.9.9.2:8333".parse().unwrap());
    let queued = fill(&mgr, stuck);
    assert!(queued > 0);

    let r = tokio::time::timeout(
        LIMIT,
        mgr.handle_event(PeerEvent::Message(stuck, NetworkMessage::GetAddr)),
    )
    .await;
    assert!(
        r.is_ok(),
        "getaddr reply to a peer with a full command queue blocked the main loop"
    );
}

#[tokio::test]
async fn disconnect_full_peer_does_not_block() {
    let mut mgr = manager();
    let stuck = PeerId(3);
    let mut rx = mgr.insert_observable_peer(stuck, "9.9.9.3:8333".parse().unwrap());
    let queued = fill(&mgr, stuck);

    let r = tokio::time::timeout(LIMIT, mgr.disconnect_peer(stuck)).await;
    assert!(r.is_ok(), "disconnect_peer on a full command queue blocked");

    // The disconnect is not lost: once the peer drains, it arrives.
    for _ in 0..queued {
        assert!(matches!(rx.recv().await, Some(PeerCommand::SendMessage(_))));
    }
    let next = tokio::time::timeout(LIMIT, rx.recv()).await;
    assert!(
        matches!(next, Ok(Some(PeerCommand::Disconnect))),
        "the deferred Disconnect must still be delivered, got {:?}",
        next
    );
}

#[tokio::test]
async fn ban_full_peer_does_not_block() {
    let mut mgr = manager();
    // Routable address: the discourage + disconnect branch.
    let stuck = PeerId(4);
    let _rx = mgr.insert_observable_peer(stuck, "9.9.9.4:8333".parse().unwrap());
    fill(&mgr, stuck);
    let r = tokio::time::timeout(LIMIT, mgr.ban_peer_with_reason(stuck, "test".to_string())).await;
    assert!(
        r.is_ok(),
        "ban_peer_with_reason (routable) on a full queue blocked"
    );

    // Local address: the disconnect-only branch.
    let local = PeerId(5);
    let _rx2 = mgr.insert_observable_peer(local, "127.0.0.1:18444".parse().unwrap());
    fill(&mgr, local);
    let r = tokio::time::timeout(LIMIT, mgr.ban_peer_with_reason(local, "test".to_string())).await;
    assert!(
        r.is_ok(),
        "ban_peer_with_reason (local) on a full queue blocked"
    );
}
