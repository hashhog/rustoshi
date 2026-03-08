//! Bitcoin P2P peer connection handling.
//!
//! This module implements async TCP peer connections using tokio, including:
//! - TCP connection establishment with timeouts
//! - Version/verack handshake protocol
//! - Message framing (reading/writing length-prefixed messages)
//! - Ping/pong keepalive
//!
//! The design uses channels to separate I/O from business logic, preventing
//! blocking I/O from stalling the main event loop.

use crate::message::*;
use rustoshi_crypto::sha256d;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration, Instant};

/// Timeout for establishing TCP connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for completing the version/verack handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval between ping messages.
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

/// Timeout for pong response before disconnecting.
pub const PING_TIMEOUT: Duration = Duration::from_secs(20);

/// Timeout for inactivity (no messages received).
#[allow(dead_code)]
pub const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);

/// Peer connection state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Initial state, attempting TCP connection.
    Connecting,
    /// TCP connected, handshake not started.
    Connected,
    /// We sent version, waiting for version+verack.
    HandshakeSent,
    /// Handshake complete, ready for normal operation.
    Established,
    /// Initiating disconnection.
    Disconnecting,
    /// Connection closed.
    Disconnected,
}

/// Information about a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Protocol version negotiated.
    pub version: i32,
    /// Services advertised by peer.
    pub services: u64,
    /// User agent string.
    pub user_agent: String,
    /// Best block height known by peer.
    pub start_height: i32,
    /// Whether peer wants transaction relay.
    pub relay: bool,
    /// Whether this is an inbound connection.
    pub inbound: bool,
    /// Current connection state.
    pub state: PeerState,
    /// Time of last message sent.
    pub last_send: Instant,
    /// Time of last message received.
    pub last_recv: Instant,
    /// Outstanding ping nonce (if any).
    pub ping_nonce: Option<u64>,
    /// Last measured round-trip time.
    pub ping_time: Option<Duration>,
    /// Total bytes sent to this peer.
    pub bytes_sent: u64,
    /// Total bytes received from this peer.
    pub bytes_recv: u64,
    /// Whether peer supports SegWit (NODE_WITNESS).
    pub supports_witness: bool,
    /// Whether peer supports sendheaders (BIP 130).
    pub supports_sendheaders: bool,
    /// Whether peer supports wtxid relay (BIP 339).
    pub supports_wtxid_relay: bool,
    /// Minimum fee rate filter (BIP 133).
    pub feefilter: u64,
}

/// Unique identifier for a peer connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

/// Events sent from peer connection tasks to the main node logic.
#[derive(Debug)]
pub enum PeerEvent {
    /// Peer connection established (handshake complete).
    Connected(PeerId, PeerInfo),
    /// Message received from peer.
    Message(PeerId, NetworkMessage),
    /// Peer disconnected.
    Disconnected(PeerId, DisconnectReason),
}

/// Reason for peer disconnection.
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Connection or handshake timed out.
    Timeout,
    /// Protocol violation or invalid message.
    ProtocolError(String),
    /// Handshake failed.
    HandshakeFailed(String),
    /// We requested disconnection.
    PeerRequested,
    /// Remote closed connection.
    ConnectionClosed,
    /// I/O error.
    IoError(String),
}

/// Commands sent from the main node to peer connection tasks.
#[derive(Debug)]
pub enum PeerCommand {
    /// Send a message to the peer.
    SendMessage(NetworkMessage),
    /// Disconnect from the peer.
    Disconnect,
}

/// Internal state for tracking a pending read operation.
/// This prevents TCP stream desync when select! cancels a partial read.
struct PendingRead {
    /// Buffer for the current read operation.
    buffer: Vec<u8>,
    /// Number of bytes already read into buffer.
    bytes_read: usize,
    /// Total bytes expected.
    expected: usize,
    /// Current phase of reading.
    phase: ReadPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadPhase {
    /// Reading the 24-byte header.
    Header,
    /// Reading the payload (after header parsed).
    Payload,
}

impl PendingRead {
    fn new_header() -> Self {
        Self {
            buffer: vec![0u8; MESSAGE_HEADER_SIZE],
            bytes_read: 0,
            expected: MESSAGE_HEADER_SIZE,
            phase: ReadPhase::Header,
        }
    }

    fn new_payload(length: usize) -> Self {
        Self {
            buffer: vec![0u8; length],
            bytes_read: 0,
            expected: length,
            phase: ReadPhase::Payload,
        }
    }

    #[allow(dead_code)]
    fn remaining(&self) -> usize {
        self.expected - self.bytes_read
    }

    fn is_complete(&self) -> bool {
        self.bytes_read >= self.expected
    }
}

/// Run an outbound peer connection task.
///
/// This handles:
/// 1. TCP connection with timeout
/// 2. Version/verack handshake
/// 3. Post-handshake negotiation (sendheaders, wtxidrelay)
/// 4. Message read/write loop with ping/pong keepalive
///
/// # Arguments
/// * `peer_id` - Unique identifier for this peer
/// * `addr` - Remote socket address to connect to
/// * `magic` - Network magic bytes (mainnet, testnet4, etc.)
/// * `our_version` - Our version message to send
/// * `event_tx` - Channel to send events to the node
/// * `command_rx` - Channel to receive commands from the node
pub async fn run_outbound_peer(
    peer_id: PeerId,
    addr: SocketAddr,
    magic: [u8; 4],
    our_version: VersionMessage,
    event_tx: mpsc::Sender<PeerEvent>,
    command_rx: mpsc::Receiver<PeerCommand>,
) {
    // 1. Connect with timeout
    let stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::IoError(e.to_string()),
                ))
                .await;
            return;
        }
        Err(_) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(peer_id, DisconnectReason::Timeout))
                .await;
            return;
        }
    };

    // Use into_split() to separate read/write halves, preventing TCP desync
    // when select! cancels a pending read operation.
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // 2. Send our version message
    let version_msg = NetworkMessage::Version(our_version.clone());
    let data = serialize_message(&magic, &version_msg);
    if writer.write_all(&data).await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("failed to send version".to_string()),
            ))
            .await;
        return;
    }
    if writer.flush().await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("failed to flush version".to_string()),
            ))
            .await;
        return;
    }

    // 3. Perform handshake with timeout
    let handshake_result = timeout(
        HANDSHAKE_TIMEOUT,
        perform_handshake(&mut reader, &mut writer, &magic),
    )
    .await;

    let their_version = match handshake_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::HandshakeFailed(e.to_string()),
                ))
                .await;
            return;
        }
        Err(_) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(peer_id, DisconnectReason::Timeout))
                .await;
            return;
        }
    };

    // 4. Build peer info
    let peer_info = PeerInfo {
        addr,
        version: their_version.version,
        services: their_version.services,
        user_agent: their_version.user_agent.clone(),
        start_height: their_version.start_height,
        relay: their_version.relay,
        inbound: false,
        state: PeerState::Established,
        last_send: Instant::now(),
        last_recv: Instant::now(),
        ping_nonce: None,
        ping_time: None,
        bytes_sent: 0,
        bytes_recv: 0,
        supports_witness: their_version.services & NODE_WITNESS != 0,
        supports_sendheaders: their_version.version >= SENDHEADERS_VERSION,
        supports_wtxid_relay: false,
        feefilter: 0,
    };

    let _ = event_tx
        .send(PeerEvent::Connected(peer_id, peer_info))
        .await;

    // 5. Send post-handshake negotiation messages
    if their_version.version >= SENDHEADERS_VERSION {
        let msg = serialize_message(&magic, &NetworkMessage::SendHeaders);
        let _ = writer.write_all(&msg).await;
    }
    if their_version.version >= WTXID_RELAY_VERSION {
        let msg = serialize_message(&magic, &NetworkMessage::WtxidRelay);
        let _ = writer.write_all(&msg).await;
    }
    let _ = writer.flush().await;

    // 6. Main message loop
    run_message_loop(peer_id, &magic, reader, writer, event_tx, command_rx).await;
}

/// Perform the version/verack handshake.
async fn perform_handshake(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut BufWriter<OwnedWriteHalf>,
    magic: &[u8; 4],
) -> std::io::Result<VersionMessage> {
    // Read their version message
    let their_version_msg = read_message_simple(reader, magic).await?;
    let their_version = match their_version_msg {
        NetworkMessage::Version(v) => v,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected version message",
            ))
        }
    };

    // Send verack
    let verack_data = serialize_message(magic, &NetworkMessage::Verack);
    writer.write_all(&verack_data).await?;
    writer.flush().await?;

    // Read messages until we get verack (some peers send wtxidrelay/sendaddrv2 first)
    loop {
        let msg = read_message_simple(reader, magic).await?;
        match msg {
            NetworkMessage::Verack => break,
            // Buffer other pre-verack messages (wtxidrelay, sendaddrv2, etc.)
            // In a full implementation, we'd process these appropriately
            _ => continue,
        }
    }

    Ok(their_version)
}

/// Simple message reading for handshake phase (no select! cancellation concerns).
async fn read_message_simple(
    reader: &mut BufReader<OwnedReadHalf>,
    expected_magic: &[u8; 4],
) -> std::io::Result<NetworkMessage> {
    // Read 24-byte header
    let mut header_buf = [0u8; MESSAGE_HEADER_SIZE];
    reader.read_exact(&mut header_buf).await?;
    let (magic, command, length, checksum) = parse_message_header(&header_buf);

    // Validate magic
    if magic != *expected_magic {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad magic: {:?}", magic),
        ));
    }

    // Validate length
    if length as usize > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {} bytes", length),
        ));
    }

    // Read payload
    let mut payload = vec![0u8; length as usize];
    if !payload.is_empty() {
        reader.read_exact(&mut payload).await?;
    }

    // Validate checksum
    let computed_checksum = sha256d(&payload);
    if checksum != computed_checksum.0[..4] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checksum mismatch",
        ));
    }

    // Deserialize
    NetworkMessage::deserialize(&command, &payload)
}

/// Run the main message loop with ping/pong keepalive.
///
/// Uses a pinned read future to prevent TCP stream desync when select!
/// cancels the read branch.
async fn run_message_loop(
    peer_id: PeerId,
    magic: &[u8; 4],
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: BufWriter<OwnedWriteHalf>,
    event_tx: mpsc::Sender<PeerEvent>,
    mut command_rx: mpsc::Receiver<PeerCommand>,
) {
    let mut last_ping = Instant::now();
    let mut ping_nonce_pending: Option<(u64, Instant)> = None;

    // State machine for reading messages to handle select! cancellation
    let mut pending_read: Option<PendingRead> = None;
    let mut header_buf = [0u8; MESSAGE_HEADER_SIZE];
    let mut parsed_header: Option<(String, u32, [u8; 4])> = None;

    loop {
        // Initialize pending read if needed
        if pending_read.is_none() {
            pending_read = Some(PendingRead::new_header());
        }

        let read_state = pending_read.as_mut().unwrap();

        tokio::select! {
            biased;

            // Handle outgoing commands first (higher priority)
            cmd = command_rx.recv() => {
                match cmd {
                    Some(PeerCommand::SendMessage(msg)) => {
                        let data = serialize_message(magic, &msg);
                        if writer.write_all(&data).await.is_err() {
                            let _ = event_tx.send(PeerEvent::Disconnected(
                                peer_id, DisconnectReason::IoError("write failed".to_string())
                            )).await;
                            return;
                        }
                        if writer.flush().await.is_err() {
                            let _ = event_tx.send(PeerEvent::Disconnected(
                                peer_id, DisconnectReason::IoError("flush failed".to_string())
                            )).await;
                            return;
                        }
                    }
                    Some(PeerCommand::Disconnect) | None => {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::PeerRequested
                        )).await;
                        return;
                    }
                }
            }

            // Read next chunk of data
            result = reader.read(&mut read_state.buffer[read_state.bytes_read..]) => {
                match result {
                    Ok(0) => {
                        // EOF - connection closed
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::ConnectionClosed
                        )).await;
                        return;
                    }
                    Ok(n) => {
                        read_state.bytes_read += n;

                        // Check if current read phase is complete
                        if read_state.is_complete() {
                            match read_state.phase {
                                ReadPhase::Header => {
                                    // Parse header
                                    header_buf.copy_from_slice(&read_state.buffer);
                                    let (magic_bytes, command, length, checksum) = parse_message_header(&header_buf);

                                    // Validate magic
                                    if magic_bytes != *magic {
                                        let _ = event_tx.send(PeerEvent::Disconnected(
                                            peer_id, DisconnectReason::ProtocolError("bad magic".to_string())
                                        )).await;
                                        return;
                                    }

                                    // Validate length
                                    if length as usize > MAX_MESSAGE_SIZE {
                                        let _ = event_tx.send(PeerEvent::Disconnected(
                                            peer_id, DisconnectReason::ProtocolError("message too large".to_string())
                                        )).await;
                                        return;
                                    }

                                    if length == 0 {
                                        // Empty payload, process immediately
                                        let computed = sha256d(&[]);
                                        if checksum != computed.0[..4] {
                                            let _ = event_tx.send(PeerEvent::Disconnected(
                                                peer_id, DisconnectReason::ProtocolError("checksum mismatch".to_string())
                                            )).await;
                                            return;
                                        }

                                        match handle_message(peer_id, &command, &[], &mut writer, magic, &mut ping_nonce_pending, &event_tx).await {
                                            Ok(()) => {}
                                            Err(e) => {
                                                let _ = event_tx.send(PeerEvent::Disconnected(
                                                    peer_id, DisconnectReason::ProtocolError(e.to_string())
                                                )).await;
                                                return;
                                            }
                                        }
                                        pending_read = Some(PendingRead::new_header());
                                    } else {
                                        // Start reading payload
                                        parsed_header = Some((command, length, checksum));
                                        pending_read = Some(PendingRead::new_payload(length as usize));
                                    }
                                }
                                ReadPhase::Payload => {
                                    let (command, _length, checksum) = parsed_header.take().unwrap();
                                    let payload = &read_state.buffer;

                                    // Validate checksum
                                    let computed = sha256d(payload);
                                    if checksum != computed.0[..4] {
                                        let _ = event_tx.send(PeerEvent::Disconnected(
                                            peer_id, DisconnectReason::ProtocolError("checksum mismatch".to_string())
                                        )).await;
                                        return;
                                    }

                                    match handle_message(peer_id, &command, payload, &mut writer, magic, &mut ping_nonce_pending, &event_tx).await {
                                        Ok(()) => {}
                                        Err(e) => {
                                            let _ = event_tx.send(PeerEvent::Disconnected(
                                                peer_id, DisconnectReason::ProtocolError(e.to_string())
                                            )).await;
                                            return;
                                        }
                                    }

                                    pending_read = Some(PendingRead::new_header());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::IoError(e.to_string())
                        )).await;
                        return;
                    }
                }
            }

            // Periodic ping
            _ = tokio::time::sleep(PING_INTERVAL.saturating_sub(last_ping.elapsed())) => {
                if let Some((_, sent_at)) = &ping_nonce_pending {
                    if sent_at.elapsed() > PING_TIMEOUT {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::Timeout
                        )).await;
                        return;
                    }
                } else {
                    let nonce: u64 = rand::random();
                    let ping = serialize_message(magic, &NetworkMessage::Ping(nonce));
                    if writer.write_all(&ping).await.is_err() {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::IoError("ping write failed".to_string())
                        )).await;
                        return;
                    }
                    if writer.flush().await.is_err() {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::IoError("ping flush failed".to_string())
                        )).await;
                        return;
                    }
                    ping_nonce_pending = Some((nonce, Instant::now()));
                    last_ping = Instant::now();
                }
            }
        }
    }
}

/// Handle a received message, sending pong for ping and tracking pong RTT.
async fn handle_message(
    peer_id: PeerId,
    command: &str,
    payload: &[u8],
    writer: &mut BufWriter<OwnedWriteHalf>,
    magic: &[u8; 4],
    ping_nonce_pending: &mut Option<(u64, Instant)>,
    event_tx: &mpsc::Sender<PeerEvent>,
) -> std::io::Result<()> {
    let msg = NetworkMessage::deserialize(command, payload)?;

    match &msg {
        NetworkMessage::Ping(nonce) => {
            // Respond immediately with pong
            let pong = serialize_message(magic, &NetworkMessage::Pong(*nonce));
            writer.write_all(&pong).await?;
            writer.flush().await?;
        }
        NetworkMessage::Pong(nonce) => {
            // Check if this matches our pending ping
            if let Some((pending_nonce, sent_at)) = ping_nonce_pending {
                if nonce == pending_nonce {
                    let rtt = sent_at.elapsed();
                    tracing::debug!("Peer {:?} ping RTT: {:?}", peer_id, rtt);
                    *ping_nonce_pending = None;
                }
            }
        }
        _ => {}
    }

    // Forward all messages to the event handler
    let _ = event_tx.send(PeerEvent::Message(peer_id, msg)).await;

    Ok(())
}

/// Read a single P2P message from the stream.
///
/// This is a convenience function for testing. For production use, prefer
/// the state-machine approach in `run_message_loop` to handle select! cancellation.
pub async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    expected_magic: &[u8; 4],
) -> std::io::Result<NetworkMessage> {
    // Read 24-byte header
    let mut header_buf = [0u8; MESSAGE_HEADER_SIZE];
    reader.read_exact(&mut header_buf).await?;
    let (magic, command, length, checksum) = parse_message_header(&header_buf);

    // Validate magic
    if magic != *expected_magic {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad magic: {:?}", magic),
        ));
    }

    // Validate length
    if length as usize > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {} bytes", length),
        ));
    }

    // Read payload
    let mut payload = vec![0u8; length as usize];
    if !payload.is_empty() {
        reader.read_exact(&mut payload).await?;
    }

    // Validate checksum
    let computed_checksum = sha256d(&payload);
    if checksum != computed_checksum.0[..4] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checksum mismatch",
        ));
    }

    // Deserialize
    NetworkMessage::deserialize(&command, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    // Testnet4 magic bytes
    const TESTNET4_MAGIC: [u8; 4] = [0x1c, 0x16, 0x3f, 0x28];

    fn create_test_version() -> VersionMessage {
        VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK | NODE_WITNESS,
            timestamp: 1234567890,
            addr_recv: NetAddress::from_ipv4([127, 0, 0, 1], 48333, NODE_NETWORK),
            addr_from: NetAddress::from_ipv4([127, 0, 0, 1], 48333, NODE_NETWORK | NODE_WITNESS),
            nonce: 0x1234567890ABCDEF,
            user_agent: "/rustoshi:0.1.0/".to_string(),
            start_height: 50000,
            relay: true,
        }
    }

    #[test]
    fn test_peer_state_transitions() {
        // Test that states are distinct and can be compared
        assert_ne!(PeerState::Connecting, PeerState::Connected);
        assert_ne!(PeerState::HandshakeSent, PeerState::Established);
        assert_eq!(PeerState::Disconnected, PeerState::Disconnected);
    }

    #[test]
    fn test_peer_id_equality() {
        let id1 = PeerId(1);
        let id2 = PeerId(1);
        let id3 = PeerId(2);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_peer_info_construction() {
        let info = PeerInfo {
            addr: "127.0.0.1:48333".parse().unwrap(),
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK | NODE_WITNESS,
            user_agent: "/test/".to_string(),
            start_height: 100000,
            relay: true,
            inbound: false,
            state: PeerState::Established,
            last_send: Instant::now(),
            last_recv: Instant::now(),
            ping_nonce: None,
            ping_time: None,
            bytes_sent: 0,
            bytes_recv: 0,
            supports_witness: true,
            supports_sendheaders: true,
            supports_wtxid_relay: false,
            feefilter: 0,
        };

        assert_eq!(info.version, 70016);
        assert!(info.supports_witness);
        assert!(!info.inbound);
    }

    #[test]
    fn test_version_message_has_correct_fields() {
        let version = create_test_version();

        assert_eq!(version.version, PROTOCOL_VERSION);
        assert!(version.services & NODE_NETWORK != 0);
        assert!(version.services & NODE_WITNESS != 0);
        assert!(!version.user_agent.is_empty());
        assert!(version.relay);
    }

    #[tokio::test]
    async fn test_message_framing_roundtrip() {
        // Create a buffer and write multiple messages
        let mut buffer = Vec::new();

        let ping = NetworkMessage::Ping(0x1234567890ABCDEF);
        let verack = NetworkMessage::Verack;
        let pong = NetworkMessage::Pong(0xFEDCBA0987654321);

        buffer.extend_from_slice(&serialize_message(&TESTNET4_MAGIC, &ping));
        buffer.extend_from_slice(&serialize_message(&TESTNET4_MAGIC, &verack));
        buffer.extend_from_slice(&serialize_message(&TESTNET4_MAGIC, &pong));

        // Read them back
        let mut cursor = Cursor::new(buffer);

        let msg1 = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();
        if let NetworkMessage::Ping(n) = msg1 {
            assert_eq!(n, 0x1234567890ABCDEF);
        } else {
            panic!("expected Ping");
        }

        let msg2 = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();
        assert!(matches!(msg2, NetworkMessage::Verack));

        let msg3 = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();
        if let NetworkMessage::Pong(n) = msg3 {
            assert_eq!(n, 0xFEDCBA0987654321);
        } else {
            panic!("expected Pong");
        }
    }

    #[tokio::test]
    async fn test_bad_magic_rejection() {
        let msg = NetworkMessage::Verack;
        let data = serialize_message(&TESTNET4_MAGIC, &msg);

        let mut cursor = Cursor::new(data);

        // Try to read with wrong magic
        let wrong_magic = [0xFF, 0xFF, 0xFF, 0xFF];
        let result = read_message(&mut cursor, &wrong_magic).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }

    #[tokio::test]
    async fn test_checksum_mismatch_rejection() {
        let msg = NetworkMessage::Ping(42);
        let mut data = serialize_message(&TESTNET4_MAGIC, &msg);

        // Corrupt the checksum (bytes 20-23)
        data[20] ^= 0xFF;
        data[21] ^= 0xFF;

        let mut cursor = Cursor::new(data);
        let result = read_message(&mut cursor, &TESTNET4_MAGIC).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("checksum"));
    }

    #[tokio::test]
    async fn test_oversized_message_rejection() {
        // Craft a header claiming an oversized payload
        let mut header = [0u8; MESSAGE_HEADER_SIZE];
        header[0..4].copy_from_slice(&TESTNET4_MAGIC);
        header[4..8].copy_from_slice(b"test");
        // Set length to MAX_MESSAGE_SIZE + 1
        let bad_length = (MAX_MESSAGE_SIZE + 1) as u32;
        header[16..20].copy_from_slice(&bad_length.to_le_bytes());

        let mut cursor = Cursor::new(header.to_vec());
        let result = read_message(&mut cursor, &TESTNET4_MAGIC).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_ping_pong_nonce_echo() {
        let nonce: u64 = 0xDEADBEEFCAFEBABE;

        // Send ping
        let ping = NetworkMessage::Ping(nonce);
        let ping_data = serialize_message(&TESTNET4_MAGIC, &ping);

        // Expected pong with same nonce
        let pong = NetworkMessage::Pong(nonce);
        let expected_pong_data = serialize_message(&TESTNET4_MAGIC, &pong);

        // Verify ping round-trips correctly
        let mut cursor = Cursor::new(ping_data);
        let read_ping = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();

        if let NetworkMessage::Ping(n) = read_ping {
            assert_eq!(n, nonce);
            // In real code, we'd send Pong(n) back
            let pong_response = NetworkMessage::Pong(n);
            let pong_data = serialize_message(&TESTNET4_MAGIC, &pong_response);
            assert_eq!(pong_data, expected_pong_data);
        } else {
            panic!("expected Ping");
        }
    }

    #[tokio::test]
    async fn test_version_message_framing() {
        let version = create_test_version();
        let msg = NetworkMessage::Version(version.clone());
        let data = serialize_message(&TESTNET4_MAGIC, &msg);

        let mut cursor = Cursor::new(data);
        let read_msg = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();

        if let NetworkMessage::Version(v) = read_msg {
            assert_eq!(v.version, version.version);
            assert_eq!(v.services, version.services);
            assert_eq!(v.nonce, version.nonce);
            assert_eq!(v.user_agent, version.user_agent);
            assert_eq!(v.start_height, version.start_height);
        } else {
            panic!("expected Version");
        }
    }

    #[tokio::test]
    async fn test_empty_payload_message() {
        // Verack has empty payload
        let verack = NetworkMessage::Verack;
        let data = serialize_message(&TESTNET4_MAGIC, &verack);

        // Should be exactly 24 bytes (header only)
        assert_eq!(data.len(), MESSAGE_HEADER_SIZE);

        let mut cursor = Cursor::new(data);
        let read_msg = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();
        assert!(matches!(read_msg, NetworkMessage::Verack));
    }

    #[tokio::test]
    async fn test_handshake_sequence() {
        // This test simulates the handshake by writing and reading messages in sequence
        let mut buffer = Vec::new();

        // Simulate: we send version, they send version, they send verack
        let our_version = create_test_version();
        let their_version = VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            timestamp: 1234567890,
            addr_recv: NetAddress::from_ipv4([192, 168, 1, 1], 48333, 0),
            addr_from: NetAddress::from_ipv4([10, 0, 0, 1], 48333, NODE_NETWORK),
            nonce: 0xABCDEF0123456789,
            user_agent: "/Satoshi:25.0.0/".to_string(),
            start_height: 60000,
            relay: true,
        };

        // Their version message
        buffer.extend_from_slice(&serialize_message(
            &TESTNET4_MAGIC,
            &NetworkMessage::Version(their_version.clone()),
        ));
        // Their verack
        buffer.extend_from_slice(&serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Verack));

        let mut cursor = Cursor::new(buffer);

        // Read their version
        let msg1 = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();
        if let NetworkMessage::Version(v) = msg1 {
            assert_eq!(v.version, their_version.version);
            assert_eq!(v.user_agent, "/Satoshi:25.0.0/");
        } else {
            panic!("expected Version");
        }

        // Read their verack
        let msg2 = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();
        assert!(matches!(msg2, NetworkMessage::Verack));
    }

    #[tokio::test]
    async fn test_disconnect_reason_debug() {
        // Ensure DisconnectReason can be debug-printed (useful for logging)
        let reasons = [
            DisconnectReason::Timeout,
            DisconnectReason::ProtocolError("test".to_string()),
            DisconnectReason::HandshakeFailed("no version".to_string()),
            DisconnectReason::PeerRequested,
            DisconnectReason::ConnectionClosed,
            DisconnectReason::IoError("connection reset".to_string()),
        ];

        for reason in &reasons {
            let debug_str = format!("{:?}", reason);
            assert!(!debug_str.is_empty());
        }
    }

    #[tokio::test]
    async fn test_peer_event_variants() {
        let peer_id = PeerId(42);
        let peer_info = PeerInfo {
            addr: "127.0.0.1:48333".parse().unwrap(),
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            user_agent: "/test/".to_string(),
            start_height: 0,
            relay: true,
            inbound: false,
            state: PeerState::Established,
            last_send: Instant::now(),
            last_recv: Instant::now(),
            ping_nonce: None,
            ping_time: None,
            bytes_sent: 0,
            bytes_recv: 0,
            supports_witness: false,
            supports_sendheaders: true,
            supports_wtxid_relay: false,
            feefilter: 0,
        };

        let events = [
            PeerEvent::Connected(peer_id, peer_info),
            PeerEvent::Message(peer_id, NetworkMessage::Verack),
            PeerEvent::Disconnected(peer_id, DisconnectReason::Timeout),
        ];

        for event in &events {
            let debug_str = format!("{:?}", event);
            assert!(!debug_str.is_empty());
        }
    }

    #[tokio::test]
    async fn test_peer_command_variants() {
        let commands = [
            PeerCommand::SendMessage(NetworkMessage::Verack),
            PeerCommand::Disconnect,
        ];

        for cmd in &commands {
            let debug_str = format!("{:?}", cmd);
            assert!(!debug_str.is_empty());
        }
    }

    #[tokio::test]
    async fn test_connection_timeout() {
        // Try to connect to a non-routable IP with a very short timeout
        let peer_id = PeerId(1);
        // 10.255.255.1 is a non-routable IP that should timeout
        let addr: SocketAddr = "10.255.255.1:48333".parse().unwrap();

        let (event_tx, mut event_rx) = mpsc::channel(10);
        let (command_tx, command_rx) = mpsc::channel(10);

        let version = create_test_version();
        let magic = TESTNET4_MAGIC;

        // Spawn the peer task
        let handle = tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, version, event_tx, command_rx).await;
        });

        // Wait for disconnect event
        let event = tokio::time::timeout(Duration::from_secs(10), event_rx.recv())
            .await
            .expect("should receive event before timeout")
            .expect("channel should not be closed");

        match event {
            PeerEvent::Disconnected(id, reason) => {
                assert_eq!(id, peer_id);
                // Should be either Timeout or IoError depending on OS
                match reason {
                    DisconnectReason::Timeout | DisconnectReason::IoError(_) => {}
                    _ => panic!("unexpected disconnect reason: {:?}", reason),
                }
            }
            _ => panic!("expected Disconnected event"),
        }

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_with_mock_peer() {
        // Create a mock server that does the handshake
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let peer_id = PeerId(1);
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let (_command_tx, command_rx) = mpsc::channel(10);

        let our_version = create_test_version();
        let magic = TESTNET4_MAGIC;

        // Spawn the mock server
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read their version
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            stream.read_exact(&mut header).await.unwrap();
            let (_, _, length, _) = parse_message_header(&header);
            let mut payload = vec![0u8; length as usize];
            if !payload.is_empty() {
                stream.read_exact(&mut payload).await.unwrap();
            }

            // Send our version
            let server_version = VersionMessage {
                version: PROTOCOL_VERSION,
                services: NODE_NETWORK | NODE_WITNESS,
                timestamp: 1234567890,
                addr_recv: NetAddress::from_ipv4([127, 0, 0, 1], 48333, 0),
                addr_from: NetAddress::from_ipv4([127, 0, 0, 1], 48333, NODE_NETWORK),
                nonce: 0xDEADBEEF,
                user_agent: "/mock:1.0/".to_string(),
                start_height: 100,
                relay: true,
            };
            let version_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Version(server_version));
            stream.write_all(&version_msg).await.unwrap();

            // Send verack
            let verack_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Verack);
            stream.write_all(&verack_msg).await.unwrap();
            stream.flush().await.unwrap();

            // Read their verack
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            stream.read_exact(&mut header).await.unwrap();
        });

        // Spawn the client
        let client_handle = tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, our_version, event_tx, command_rx).await;
        });

        // Wait for connected event
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("channel should not be closed");

        match event {
            PeerEvent::Connected(id, info) => {
                assert_eq!(id, peer_id);
                assert_eq!(info.version, PROTOCOL_VERSION);
                assert_eq!(info.user_agent, "/mock:1.0/");
                assert_eq!(info.start_height, 100);
                assert!(info.supports_witness);
                assert!(!info.inbound);
                assert_eq!(info.state, PeerState::Established);
            }
            _ => panic!("expected Connected event, got {:?}", event),
        }

        // Clean up
        server_handle.await.unwrap();
        // Client will disconnect when server closes
    }

    #[tokio::test]
    async fn test_large_message_parsing() {
        // Test parsing a message with a large payload (like a block)
        let items: Vec<InvVector> = (0..1000)
            .map(|i| InvVector {
                inv_type: InvType::MsgTx,
                hash: rustoshi_primitives::Hash256([i as u8; 32]),
            })
            .collect();

        let msg = NetworkMessage::Inv(items);
        let data = serialize_message(&TESTNET4_MAGIC, &msg);

        // Should be substantial in size
        assert!(data.len() > 1000);

        let mut cursor = Cursor::new(data);
        let read_msg = read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();

        if let NetworkMessage::Inv(inv) = read_msg {
            assert_eq!(inv.len(), 1000);
        } else {
            panic!("expected Inv");
        }
    }

    #[test]
    fn test_pending_read_state_machine() {
        let mut state = PendingRead::new_header();
        assert_eq!(state.phase, ReadPhase::Header);
        assert_eq!(state.expected, MESSAGE_HEADER_SIZE);
        assert_eq!(state.bytes_read, 0);
        assert!(!state.is_complete());
        assert_eq!(state.remaining(), MESSAGE_HEADER_SIZE);

        // Simulate partial read
        state.bytes_read = 10;
        assert!(!state.is_complete());
        assert_eq!(state.remaining(), MESSAGE_HEADER_SIZE - 10);

        // Complete the read
        state.bytes_read = MESSAGE_HEADER_SIZE;
        assert!(state.is_complete());
        assert_eq!(state.remaining(), 0);

        // Transition to payload
        let payload_state = PendingRead::new_payload(1000);
        assert_eq!(payload_state.phase, ReadPhase::Payload);
        assert_eq!(payload_state.expected, 1000);
    }
}
