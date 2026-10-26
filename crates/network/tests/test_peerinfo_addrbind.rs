//! `PeerInfo.addr_bind` / `addr_local` feed getpeerinfo `addrbind` / `addrlocal`.
//!
//! Core reference: rpc/net.cpp getpeerinfo pushes `addrbind` when
//! `stats.addrBind.IsValid()` (our end of the socket) and `addrlocal` when
//! `stats.addrLocal` is non-empty (the peer's VERSION addrMe).

use std::time::Duration;

use rustoshi_network::message::{
    parse_message_header, serialize_message, NetAddress, NetworkMessage, VersionMessage,
    MESSAGE_HEADER_SIZE, NODE_NETWORK, NODE_WITNESS, PROTOCOL_VERSION,
};
use rustoshi_network::peer::{mark_v1_only, run_outbound_peer, PeerEvent, PeerId};
use rustoshi_network::peer_manager::run_inbound_peer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

fn version(addr_recv: NetAddress) -> VersionMessage {
    VersionMessage {
        version: PROTOCOL_VERSION,
        services: NODE_NETWORK | NODE_WITNESS,
        timestamp: 1_700_000_000,
        addr_recv,
        addr_from: NetAddress::from_ipv4([127, 0, 0, 1], 18444, NODE_NETWORK),
        nonce: 0x1234_5678_9abc_def0,
        user_agent: "/addrbind-test:0.1/".to_string(),
        start_height: 0,
        relay: true,
    }
}

async fn send(s: &mut TcpStream, m: &NetworkMessage) {
    s.write_all(&serialize_message(&MAGIC, m)).await.unwrap();
    s.flush().await.unwrap();
}

async fn recv_cmd(s: &mut TcpStream) -> String {
    let mut h = [0u8; MESSAGE_HEADER_SIZE];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut h))
        .await
        .expect("header timeout")
        .unwrap();
    let (_, cmd, len, _) = parse_message_header(&h);
    let mut p = vec![0u8; len as usize];
    if len > 0 {
        s.read_exact(&mut p).await.unwrap();
    }
    cmd
}

async fn connected(rx: &mut mpsc::Receiver<PeerEvent>) -> rustoshi_network::peer::PeerInfo {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no event")
            .expect("closed");
        if let PeerEvent::Connected(_, info, _) = ev {
            return info;
        }
    }
}

/// Inbound: addrbind is our listening-side socket address, addrlocal the
/// peer's VERSION addr_recv.
#[tokio::test]
async fn inbound_peerinfo_has_addr_bind_and_addr_local() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let laddr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(laddr).await.unwrap();
    let (server, peer_addr) = listener.accept().await.unwrap();
    let (etx, mut erx) = mpsc::channel(32);
    let (_ctx, crx) = mpsc::channel(32);
    tokio::spawn(async move {
        run_inbound_peer(PeerId(1), server, peer_addr, MAGIC, NODE_NETWORK, 0, etx, crx).await;
    });
    send(
        &mut client,
        &NetworkMessage::Version(version(NetAddress::from_ipv4([203, 0, 113, 9], 18444, 0))),
    )
    .await;
    assert_eq!(recv_cmd(&mut client).await, "version");
    send(&mut client, &NetworkMessage::Verack).await;
    let info = connected(&mut erx).await;
    assert_eq!(info.addr_bind, Some(laddr), "addrbind = our socket end");
    assert_eq!(
        info.addr_local,
        Some("203.0.113.9:18444".parse().unwrap()),
        "addrlocal = peer's VERSION addr_recv"
    );
}

/// Outbound: addrbind is the ephemeral local port we connected from.
#[tokio::test]
async fn outbound_peerinfo_has_addr_bind() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    mark_v1_only(addr);
    let (etx, mut erx) = mpsc::channel(32);
    let (_ctx, crx) = mpsc::channel(32);
    let ours = version(NetAddress::from_ipv4([127, 0, 0, 1], addr.port(), 0));
    tokio::spawn(async move {
        run_outbound_peer(PeerId(2), addr, MAGIC, ours, etx, crx).await;
    });
    let (mut srv, client_end) = listener.accept().await.unwrap();
    assert_eq!(recv_cmd(&mut srv).await, "version");
    // A distinct nonce, or the outbound side drops it as a self-connection.
    let mut theirs = version(NetAddress::from_ipv4([198, 51, 100, 7], 5, 0));
    theirs.nonce = 0x0bad_cafe_0bad_cafe;
    send(&mut srv, &NetworkMessage::Version(theirs)).await;
    send(&mut srv, &NetworkMessage::Verack).await;
    let info = connected(&mut erx).await;
    // Our end of the socket is what the server saw as the peer address.
    assert_eq!(info.addr_bind, Some(client_end));
    assert_eq!(info.addr_local, Some("198.51.100.7:5".parse().unwrap()));
}
