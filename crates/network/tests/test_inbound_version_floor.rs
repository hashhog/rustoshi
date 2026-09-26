//! Handshake acceptance parity with Bitcoin Core for low-version peers and
//! pre-verack feature messages.
//!
//! Core reference:
//!   - `node/protocol_version.h`: `MIN_PEER_PROTO_VERSION = 31800` — the only
//!     protocol-version floor Core applies (`net_processing.cpp` VERSION
//!     handler, "peer using obsolete version").
//!   - `net_processing.cpp` VERSION handler: `ExpectServicesFromConn() &&
//!     !HasAllDesirableServiceFlags(nServices)` disconnects *outbound* peers
//!     that do not offer NODE_WITNESS (+ NETWORK/NETWORK_LIMITED); inbound
//!     peers are never disconnected for their services.
//!   - `net_processing.cpp`: SENDHEADERS and SENDCMPCT handlers run ABOVE
//!     the `if (!pfrom.fSuccessfullyConnected)` guard, so they are applied
//!     even when received between VERSION and VERACK; every other
//!     non-negotiation message there is "Unsupported message \"%s\" prior
//!     to verack" — logged and IGNORED, not a disconnect.
//!   - Feature messages are gated on the common version: WTXIDRELAY
//!     (>= 70016), SENDADDRV2 (>= 70016), SENDHEADERS (>= 70012),
//!     SENDCMPCT (>= 70014).
//!
//! Evidence: on mainnet every inbound peer was dropped with
//! `ObsoleteVersion(70002)` (e.g. `/BTC-Nodes:2026-09-24/Sonar/`) or
//! `PreHandshakeMessage("sendheaders")`, all of which Core accepts.

use std::net::SocketAddr;
use std::time::Duration;

use rustoshi_network::message::{
    parse_message_header, serialize_message, NetAddress, NetworkMessage, SendCmpctMessage,
    VersionMessage, MESSAGE_HEADER_SIZE, NODE_NETWORK, NODE_WITNESS, PROTOCOL_VERSION,
};
use rustoshi_network::peer::{
    mark_v1_only, run_outbound_peer, DisconnectReason, PeerCommand, PeerEvent, PeerId,
};
use rustoshi_network::peer_manager::run_inbound_peer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // regtest

fn version_msg(version: i32, services: u64) -> VersionMessage {
    VersionMessage {
        version,
        services,
        timestamp: 1_700_000_000,
        addr_recv: NetAddress::from_ipv4([127, 0, 0, 1], 18444, 0),
        addr_from: NetAddress::from_ipv4([127, 0, 0, 1], 18444, services),
        nonce: 0x5eed_5eed_5eed_5eed,
        user_agent: "/test-peer:0.1/".to_string(),
        start_height: 0,
        relay: true,
    }
}

async fn send(stream: &mut TcpStream, msg: &NetworkMessage) {
    stream
        .write_all(&serialize_message(&MAGIC, msg))
        .await
        .unwrap();
    stream.flush().await.unwrap();
}

/// Read one message's command name (payload discarded). `None` on EOF,
/// error, or timeout.
async fn recv_cmd(stream: &mut TcpStream, wait: Duration) -> Option<String> {
    let mut header = [0u8; MESSAGE_HEADER_SIZE];
    match tokio::time::timeout(wait, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        _ => return None,
    }
    let (_, cmd, len, _) = parse_message_header(&header);
    let mut payload = vec![0u8; len as usize];
    if !payload.is_empty() {
        match tokio::time::timeout(wait, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            _ => return None,
        }
    }
    Some(cmd)
}

/// Collect every command the node sends us within `wait` of quiet.
async fn drain_cmds(stream: &mut TcpStream, wait: Duration) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(cmd) = recv_cmd(stream, wait).await {
        out.push(cmd);
    }
    out
}

/// Spawn rustoshi's inbound peer task on an accepted socket and return the
/// connected client side plus the event receiver.
async fn start_inbound() -> (
    TcpStream,
    mpsc::Receiver<PeerEvent>,
    mpsc::Sender<PeerCommand>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, peer_addr) = listener.accept().await.unwrap();
    let (event_tx, event_rx) = mpsc::channel(32);
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    tokio::spawn(async move {
        run_inbound_peer(
            PeerId(7),
            server,
            peer_addr,
            MAGIC,
            NODE_NETWORK | NODE_WITNESS,
            0,
            event_tx,
            cmd_rx,
        )
        .await;
    });
    (client, event_rx, cmd_tx)
}

async fn next_event(rx: &mut mpsc::Receiver<PeerEvent>) -> PeerEvent {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("no peer event within 5s")
        .expect("event channel closed")
}

/// Wait for Connected, skipping Misbehaving events; panics on Disconnected.
async fn expect_connected(rx: &mut mpsc::Receiver<PeerEvent>) -> rustoshi_network::peer::PeerInfo {
    loop {
        match next_event(rx).await {
            PeerEvent::Connected(_, info, _) => return info,
            PeerEvent::Disconnected(_, reason) => {
                panic!("peer was disconnected, Core would keep it: {:?}", reason)
            }
            _ => continue,
        }
    }
}

async fn expect_disconnected(rx: &mut mpsc::Receiver<PeerEvent>) -> DisconnectReason {
    loop {
        match next_event(rx).await {
            PeerEvent::Disconnected(_, reason) => return reason,
            PeerEvent::Connected(_, info, _) => {
                panic!(
                    "peer connected (version {}), expected a disconnect",
                    info.version
                )
            }
            _ => continue,
        }
    }
}

// ─── Inbound ──────────────────────────────────────────────────────────────

/// A VERSION(70002) inbound peer (the Sonar crawler case) completes the
/// handshake: Core's only version floor is MIN_PEER_PROTO_VERSION = 31800,
/// and inbound peers are not disconnected for missing services.
#[tokio::test]
async fn inbound_version_70002_handshake_completes() {
    let (mut client, mut events, _cmd) = start_inbound().await;
    send(
        &mut client,
        &NetworkMessage::Version(version_msg(70002, NODE_NETWORK)),
    )
    .await;

    // The node must answer with version + verack (no disconnect).
    let first = recv_cmd(&mut client, Duration::from_secs(5)).await;
    assert_eq!(
        first.as_deref(),
        Some("version"),
        "node must send its VERSION"
    );
    let mut got_verack = false;
    for _ in 0..4 {
        match recv_cmd(&mut client, Duration::from_secs(5))
            .await
            .as_deref()
        {
            Some("verack") => {
                got_verack = true;
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }
    assert!(got_verack, "node must send VERACK to a 70002 peer");
    send(&mut client, &NetworkMessage::Verack).await;

    let info = expect_connected(&mut events).await;
    assert_eq!(info.version, 70002);
    assert!(!info.supports_witness);
    assert!(!info.supports_sendheaders);

    // A 70002 peer must NOT be sent feature messages it cannot know
    // (sendheaders >= 70012, sendcmpct >= 70014, wtxidrelay/sendaddrv2 >= 70016).
    let after = drain_cmds(&mut client, Duration::from_millis(700)).await;
    for forbidden in [
        "sendheaders",
        "sendcmpct",
        "wtxidrelay",
        "sendaddrv2",
        "feefilter",
    ] {
        assert!(
            !after.iter().any(|c| c == forbidden),
            "sent {forbidden} to a 70002 peer: {after:?}"
        );
    }
}

/// Collect the `PeerEvent::Message` commands delivered after Connected
/// (the dispatcher sees these exactly like post-verack messages).
async fn messages_after_connect(rx: &mut mpsc::Receiver<PeerEvent>) -> Vec<NetworkMessage> {
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        match ev {
            PeerEvent::Message(_, m) => out.push(m),
            PeerEvent::Disconnected(_, r) => panic!("disconnected after connect: {r:?}"),
            _ => {}
        }
    }
    out
}

/// A pre-verack `sendheaders` does not disconnect, and — because Core's
/// SENDHEADERS handler runs before the fSuccessfullyConnected guard — the
/// preference is applied (delivered to the dispatcher after Connected).
/// A pre-verack `ping` is merely ignored (not delivered, no disconnect).
#[tokio::test]
async fn inbound_pre_verack_sendheaders_is_honored_not_disconnected() {
    let (mut client, mut events, _cmd) = start_inbound().await;
    send(
        &mut client,
        &NetworkMessage::Version(version_msg(PROTOCOL_VERSION, NODE_NETWORK | NODE_WITNESS)),
    )
    .await;
    send(&mut client, &NetworkMessage::SendHeaders).await;
    send(&mut client, &NetworkMessage::Ping(42)).await;
    send(&mut client, &NetworkMessage::Verack).await;
    let info = expect_connected(&mut events).await;
    assert_eq!(info.version, PROTOCOL_VERSION);
    let msgs = messages_after_connect(&mut events).await;
    assert!(
        msgs.iter()
            .any(|m| matches!(m, NetworkMessage::SendHeaders)),
        "pre-verack sendheaders preference was dropped: {msgs:?}"
    );
    assert!(
        !msgs.iter().any(|m| matches!(m, NetworkMessage::Ping(_))),
        "pre-verack ping must be ignored, not processed: {msgs:?}"
    );
}

/// A pre-verack `sendcmpct` is likewise applied (Core SENDCMPCT handler is
/// above the guard); the latest one wins.
#[tokio::test]
async fn inbound_pre_verack_sendcmpct_is_honored() {
    let (mut client, mut events, _cmd) = start_inbound().await;
    send(
        &mut client,
        &NetworkMessage::Version(version_msg(PROTOCOL_VERSION, NODE_NETWORK | NODE_WITNESS)),
    )
    .await;
    send(
        &mut client,
        &NetworkMessage::SendCmpct(SendCmpctMessage {
            announce: false,
            version: 2,
        }),
    )
    .await;
    send(
        &mut client,
        &NetworkMessage::SendCmpct(SendCmpctMessage {
            announce: true,
            version: 2,
        }),
    )
    .await;
    send(&mut client, &NetworkMessage::Verack).await;
    expect_connected(&mut events).await;
    let msgs = messages_after_connect(&mut events).await;
    let cmpct: Vec<_> = msgs
        .iter()
        .filter_map(|m| match m {
            NetworkMessage::SendCmpct(sc) => Some((sc.announce, sc.version)),
            _ => None,
        })
        .collect();
    assert_eq!(
        cmpct,
        vec![(true, 2)],
        "expected the latest pre-verack sendcmpct once"
    );
}

/// Floor control: a version below Core's MIN_PEER_PROTO_VERSION (31800) is
/// still refused (negative control for the relaxed floor).
#[tokio::test]
async fn inbound_version_below_31800_still_rejected() {
    let (mut client, mut events, _cmd) = start_inbound().await;
    send(
        &mut client,
        &NetworkMessage::Version(version_msg(31799, NODE_NETWORK)),
    )
    .await;
    match expect_disconnected(&mut events).await {
        DisconnectReason::ObsoleteVersion(v) => assert_eq!(v, 31799),
        other => panic!("expected ObsoleteVersion(31799), got {other:?}"),
    }
}

/// Exactly 31800 is accepted (boundary).
#[tokio::test]
async fn inbound_version_31800_accepted() {
    let (mut client, mut events, _cmd) = start_inbound().await;
    send(&mut client, &NetworkMessage::Version(version_msg(31800, 0))).await;
    send(&mut client, &NetworkMessage::Verack).await;
    let info = expect_connected(&mut events).await;
    assert_eq!(info.version, 31800);
}

// ─── Outbound ─────────────────────────────────────────────────────────────

/// Mock remote node for outbound tests: reads our VERSION, sends
/// `their_version` + optional extra messages + VERACK, then records the
/// commands we send for a short while.
async fn run_outbound(
    their: VersionMessage,
    extra_pre_verack: Vec<NetworkMessage>,
) -> (PeerEvent, Vec<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    mark_v1_only(addr);
    let (event_tx, mut event_rx) = mpsc::channel(32);
    let (_cmd_tx, cmd_rx) = mpsc::channel(32);

    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ours = recv_cmd(&mut s, Duration::from_secs(5)).await;
        send(&mut s, &NetworkMessage::Version(their)).await;
        for m in &extra_pre_verack {
            send(&mut s, m).await;
        }
        send(&mut s, &NetworkMessage::Verack).await;
        let cmds = drain_cmds(&mut s, Duration::from_millis(700)).await;
        (s, cmds)
    });

    let mut our = version_msg(PROTOCOL_VERSION, NODE_NETWORK | NODE_WITNESS);
    our.nonce = 0x0123_4567_89ab_cdef; // distinct from the mock's (self-connection check)
    tokio::spawn(async move {
        run_outbound_peer(PeerId(9), addr, MAGIC, our, event_tx, cmd_rx).await;
    });

    let mut ev = next_event(&mut event_rx).await;
    while let PeerEvent::Misbehaving(..) = ev {
        ev = next_event(&mut event_rx).await;
    }
    let (_s, cmds) = server.await.unwrap();
    let mut later = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(200), event_rx.recv()).await
    {
        if let PeerEvent::Message(_, m) = e {
            later.push(m.command().to_string());
        }
    }
    (
        ev,
        [
            cmds,
            later.into_iter().map(|c| format!("event:{c}")).collect(),
        ]
        .concat(),
    )
}

/// Outbound: Core requires the desirable services (NODE_WITNESS) of
/// outbound peers, so a non-witness outbound peer is still dropped — we
/// must never pick it for (witness) block download.
#[tokio::test]
async fn outbound_non_witness_peer_rejected() {
    let (ev, _) = run_outbound(version_msg(PROTOCOL_VERSION, NODE_NETWORK), vec![]).await;
    match ev {
        PeerEvent::Disconnected(_, reason) => {
            let s = format!("{reason:?}");
            assert!(s.contains("services"), "unexpected reason {s}");
        }
        other => panic!("non-witness outbound peer must be dropped, got {other:?}"),
    }
}

/// Outbound: below-floor version refused.
#[tokio::test]
async fn outbound_version_below_31800_rejected() {
    let (ev, _) = run_outbound(version_msg(31799, NODE_NETWORK | NODE_WITNESS), vec![]).await;
    match ev {
        PeerEvent::Disconnected(_, DisconnectReason::ObsoleteVersion(v)) => assert_eq!(v, 31799),
        other => panic!("expected ObsoleteVersion(31799), got {other:?}"),
    }
}

/// Outbound: a witness-capable 70012 peer is kept (Core has no 70015 floor),
/// and is only sent the feature messages its version understands:
/// sendheaders (>= 70012) yes; sendcmpct (70014), wtxidrelay/sendaddrv2
/// (70016) no.
#[tokio::test]
async fn outbound_version_70012_witness_peer_kept_and_feature_gated() {
    let (ev, cmds) = run_outbound(version_msg(70012, NODE_NETWORK | NODE_WITNESS), vec![]).await;
    match ev {
        PeerEvent::Connected(_, info, _) => assert_eq!(info.version, 70012),
        other => panic!("expected Connected, got {other:?}"),
    }
    assert!(cmds.iter().any(|c| c == "verack"), "{cmds:?}");
    assert!(cmds.iter().any(|c| c == "sendheaders"), "{cmds:?}");
    for forbidden in ["sendcmpct", "wtxidrelay", "sendaddrv2"] {
        assert!(
            !cmds.iter().any(|c| c == forbidden),
            "sent {forbidden}: {cmds:?}"
        );
    }
}

/// Outbound: a pre-verack `sendheaders` from the remote does not disconnect
/// and is applied (delivered to the dispatcher after Connected).
#[tokio::test]
async fn outbound_pre_verack_sendheaders_is_honored() {
    let (ev, cmds) = run_outbound(
        version_msg(PROTOCOL_VERSION, NODE_NETWORK | NODE_WITNESS),
        vec![NetworkMessage::SendHeaders],
    )
    .await;
    match ev {
        PeerEvent::Connected(_, info, _) => assert_eq!(info.version, PROTOCOL_VERSION),
        other => panic!("expected Connected, got {other:?}"),
    }
    assert!(
        cmds.iter().any(|c| c == "event:sendheaders"),
        "pre-verack sendheaders not applied: {cmds:?}"
    );
}
