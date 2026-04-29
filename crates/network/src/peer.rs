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

use crate::message::{
    parse_message_header, serialize_message, NetworkMessage, SendCmpctMessage, VersionMessage,
    MAX_MESSAGE_SIZE, MESSAGE_HEADER_SIZE, MIN_WITNESS_PROTO_VERSION, NODE_WITNESS,
    SENDCMPCT_VERSION, SENDHEADERS_VERSION, WTXID_RELAY_VERSION,
};
use crate::v2_transport::{
    constants::{
        ELLSWIFT_PUBKEY_LEN, EXPANSION, GARBAGE_TERMINATOR_LEN, HEADER_LEN, LENGTH_LEN,
        MAX_GARBAGE_LEN, V1_PREFIX_LEN,
    },
    looks_like_v1_version, Bip324Cipher, EllSwiftPubKey,
};
use rustoshi_crypto::sha256d;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration, Instant};

/// Timeout for establishing TCP connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for completing the version/verack handshake.
/// Bitcoin Core uses 60 seconds for connection timeout.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// Clock-skew at handshake in seconds: peer_version_timestamp - our_unix_time.
    /// Matches Bitcoin Core CNode::nTimeOffset. Zero until VERSION received.
    pub time_offset: i64,
    /// Whether peer supports SegWit (NODE_WITNESS).
    pub supports_witness: bool,
    /// Whether peer supports sendheaders (BIP 130).
    pub supports_sendheaders: bool,
    /// Whether peer supports wtxid relay (BIP 339).
    pub supports_wtxid_relay: bool,
    /// Whether peer supports addrv2 (BIP 155).
    pub supports_addrv2: bool,
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
    /// Duplicate version message received.
    DuplicateVersion,
    /// Self-connection detected (matching nonce).
    SelfConnection,
    /// Pre-handshake message received (not version/verack).
    PreHandshakeMessage(String),
    /// Protocol version too old.
    ObsoleteVersion(i32),
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

/// Pre-allocated message reader for efficient message parsing.
///
/// Uses fixed-size header buffer and a reusable payload buffer to reduce
/// allocations during block download. This is particularly important during
/// IBD when millions of messages are processed.
///
/// # Performance Notes
/// - Header buffer is fixed at 24 bytes (MESSAGE_HEADER_SIZE)
/// - Payload buffer starts at 4 MB and grows as needed
/// - Buffer is reused across messages, avoiding repeated allocations
pub struct MessageReader {
    /// Fixed header buffer (24 bytes).
    header_buf: [u8; MESSAGE_HEADER_SIZE],
    /// Reusable payload buffer (grows as needed, never shrinks).
    payload_buf: Vec<u8>,
}

impl MessageReader {
    /// Create a new MessageReader with pre-allocated buffers.
    ///
    /// The payload buffer starts at 4 MB to handle full blocks without
    /// reallocation.
    pub fn new() -> Self {
        Self {
            header_buf: [0u8; MESSAGE_HEADER_SIZE],
            payload_buf: Vec::with_capacity(4 * 1024 * 1024), // 4 MB initial
        }
    }

    /// Read a single P2P message from the stream.
    ///
    /// Uses the pre-allocated buffers to avoid allocations. The payload buffer
    /// is resized as needed but never reallocated for smaller messages.
    ///
    /// # Arguments
    /// * `reader` - The async reader to read from
    /// * `expected_magic` - Network magic bytes to validate
    ///
    /// # Returns
    /// The deserialized NetworkMessage, or an error.
    pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin>(
        &mut self,
        reader: &mut R,
        expected_magic: &[u8; 4],
    ) -> std::io::Result<NetworkMessage> {
        // Read 24-byte header
        reader.read_exact(&mut self.header_buf).await?;
        let (magic, command, length, checksum) = parse_message_header(&self.header_buf);

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

        // Resize payload buffer (no realloc if already big enough)
        self.payload_buf.resize(length as usize, 0);

        // Read payload
        if !self.payload_buf.is_empty() {
            reader.read_exact(&mut self.payload_buf[..length as usize]).await?;
        }

        // Validate checksum
        let computed = sha256d(&self.payload_buf[..length as usize]);
        if checksum != computed.0[..4] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checksum mismatch",
            ));
        }

        // Deserialize
        NetworkMessage::deserialize(&command, &self.payload_buf[..length as usize])
    }
}

impl Default for MessageReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true iff outbound BIP-324 v2 negotiation is enabled.  Gated by
/// the `RUSTOSHI_BIP324_V2_OUTBOUND` environment variable (default OFF
/// pending live-fleet verification).  Set to `1` / `true` / `yes` / `on`
/// to enable; any other value or unset → outbound connections start
/// directly with v1 (matching prior behavior).
///
/// Mirrors `peer_manager::bip324_v2_inbound_enabled` for inbound.  Once
/// flipped to default-ON in a future commit, this flag will gate the
/// fall-back-to-v1 LRU cache path.  The cipher fix in `0de596e`
/// (continuous FSChaCha20 keystream) is required before real-peer v2
/// interop can succeed in either direction.
///
/// Reference: clearbit `Peer.bip324V2Enabled` (Zig).
pub fn bip324_v2_outbound_enabled() -> bool {
    match std::env::var("RUSTOSHI_BIP324_V2_OUTBOUND") {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

/// Maximum size of the per-process BIP-324 v2 outbound v1-only fall-back
/// LRU cache.  Mirrors clearbit's `V2_FALLBACK_CACHE_MAX = 4096`.  Once
/// full, a single arbitrary entry is evicted; reprobing v1-only peers
/// is cheap (one round-trip cost) so eviction policy isn't critical.
pub const V2_FALLBACK_CACHE_MAX: usize = 4096;

/// V2 handshake deadline (seconds).  Matches Bitcoin Core's
/// `peers.timeoutbal`-aligned handshake budget and clearbit's
/// `V2_HANDSHAKE_DEADLINE_MS = 30_000`.
pub const V2_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// Per-process LRU set of remote socket addresses that have been
/// observed to NOT speak BIP-324 v2 (either timed out or sent v1 magic
/// in response to our ellswift pubkey).  Once an address lands here,
/// subsequent outbound attempts skip the v2 probe and go straight to
/// v1.  Bounded by `V2_FALLBACK_CACHE_MAX`.
///
/// We use a process-wide `OnceLock<Mutex<HashSet>>` rather than threading
/// state through every `run_outbound_peer` call: the data structure is
/// hot only on connection setup (a few times per minute) and the lock
/// is held for microseconds.
fn v1_only_cache() -> &'static Mutex<HashSet<SocketAddr>> {
    static CACHE: OnceLock<Mutex<HashSet<SocketAddr>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Returns true if `addr` is in the v1-only fall-back set.
pub fn is_v1_only(addr: &SocketAddr) -> bool {
    v1_only_cache()
        .lock()
        .map(|set| set.contains(addr))
        .unwrap_or(false)
}

/// Mark `addr` as v1-only so future outbound attempts skip the v2 probe.
/// If the cache is full, evicts a single arbitrary entry (HashSet
/// iteration order is implementation-defined; Rust's hash-randomisation
/// makes this effectively a random eviction).
pub fn mark_v1_only(addr: SocketAddr) {
    if let Ok(mut set) = v1_only_cache().lock() {
        if set.len() >= V2_FALLBACK_CACHE_MAX {
            // Evict an arbitrary entry to bound memory.
            if let Some(victim) = set.iter().next().copied() {
                set.remove(&victim);
            }
        }
        set.insert(addr);
    }
}

/// Test-only helper: clear the v1-only cache.
#[cfg(test)]
pub fn clear_v1_only_cache() {
    if let Ok(mut set) = v1_only_cache().lock() {
        set.clear();
    }
}

/// Run an outbound peer connection task.
///
/// This handles:
/// 1. TCP connection with timeout
/// 2. (Optional) BIP-324 v2 cipher handshake (when
///    `RUSTOSHI_BIP324_V2_OUTBOUND=1` and the address is not v1-only)
/// 3. Version/verack handshake
/// 4. Post-handshake negotiation (sendheaders, wtxidrelay)
/// 5. Message read/write loop with ping/pong keepalive
///
/// On v2 path failure (timeout, peer responded with v1 magic, AEAD
/// decrypt failed, etc.), the v2 socket is abandoned (sending v2
/// garbage corrupts v1 framing on the remote, so the same socket
/// cannot be reused), the address is cached in the v1-only set, and
/// a fresh TCP connection is opened for the v1 handshake.
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
    // BIP-324 v2 outbound probe path.  When enabled and the address is
    // not in the v1-only LRU cache, attempt the v2 cipher handshake on a
    // dedicated socket first.  On any failure, mark v1-only, drop the
    // socket, and fall through to the v1 path on a fresh socket.
    if bip324_v2_outbound_enabled() && !is_v1_only(&addr) {
        match try_v2_outbound_handshake(addr, magic).await {
            Ok(()) => {
                // Cipher handshake completed.  The application-layer
                // version/verack pump over the encrypted v2 channel is
                // not yet plumbed (mirrors the inbound path's deferred
                // wrap of `run_message_loop`).  Disconnect cleanly so
                // the v1 path takes over on the next connection attempt
                // — and so live-test logs unambiguously record cipher-
                // handshake success without spurious app-traffic noise.
                //
                // FOLLOW-UP: dispatch `run_message_loop` through
                // `Bip324Cipher.encrypt`/`decrypt` for both directions
                // so the application protocol runs over the encrypted
                // channel end-to-end.
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::PeerRequested,
                    ))
                    .await;
                return;
            }
            Err(e) => {
                tracing::info!(
                    "peer {:?} ({}): BIP-324 v2 outbound handshake failed: {}; \
                     marking v1-only and reconnecting on a fresh socket",
                    peer_id,
                    addr,
                    e
                );
                mark_v1_only(addr);
                // Fall through to v1 path with a fresh TCP connection.
            }
        }
    }

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

    // 3. Perform handshake with timeout (60 seconds per Bitcoin Core)
    let our_nonce = our_version.nonce;
    let handshake_result = timeout(
        HANDSHAKE_TIMEOUT,
        perform_handshake(&mut reader, &mut writer, &magic, our_nonce),
    )
    .await;

    let hs_result = match handshake_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let reason = match e {
                HandshakeError::DuplicateVersion => DisconnectReason::DuplicateVersion,
                HandshakeError::SelfConnection => DisconnectReason::SelfConnection,
                HandshakeError::ObsoleteVersion(v) => DisconnectReason::ObsoleteVersion(v),
                HandshakeError::PreHandshakeMessage(cmd) => {
                    DisconnectReason::PreHandshakeMessage(cmd)
                }
                _ => DisconnectReason::HandshakeFailed(e.to_string()),
            };
            let _ = event_tx
                .send(PeerEvent::Disconnected(peer_id, reason))
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

    let their_version = &hs_result.version;

    // 4. Build peer info
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
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
        time_offset: their_version.timestamp - now_unix,
        supports_witness: their_version.services & NODE_WITNESS != 0,
        supports_sendheaders: their_version.version >= SENDHEADERS_VERSION,
        supports_wtxid_relay: hs_result.wants_wtxid_relay,
        supports_addrv2: hs_result.wants_addrv2,
        feefilter: 0,
    };

    let _ = event_tx
        .send(PeerEvent::Connected(peer_id, peer_info))
        .await;

    // 5. Send post-handshake feature negotiation messages
    // Note: BIP 155 (sendaddrv2) and BIP 339 (wtxidrelay) are sent BEFORE verack
    // in perform_handshake(). Only sendheaders is sent after verack.
    // BIP 130: sendheaders - request headers announcements instead of inv
    if their_version.version >= SENDHEADERS_VERSION {
        let msg = serialize_message(&magic, &NetworkMessage::SendHeaders);
        let _ = writer.write_all(&msg).await;
    }
    // BIP 152: sendcmpct - signal compact block relay support (version 2 = segwit)
    // announce=false means low-bandwidth mode (we receive inv/headers first)
    if their_version.version >= SENDCMPCT_VERSION {
        let msg = serialize_message(
            &magic,
            &NetworkMessage::SendCmpct(SendCmpctMessage {
                announce: false,
                version: 2,
            }),
        );
        let _ = writer.write_all(&msg).await;
    }
    let _ = writer.flush().await;

    // 6. Main message loop
    run_message_loop(peer_id, &magic, reader, writer, event_tx, command_rx).await;
}

/// Errors specific to the outbound BIP-324 v2 cipher handshake.
#[derive(Debug)]
pub enum V2OutboundError {
    /// TCP connection failed.
    ConnectFailed(String),
    /// Connection timed out.
    Timeout,
    /// Peer responded with v1 magic (i.e. is treating our 64-byte
    /// ellswift garbage as a v1 message header).  Caller MUST close
    /// the socket (sending v2 garbage is destructive on a v1 peer).
    V1MagicDetected,
    /// I/O error during the handshake.
    IoError(String),
    /// Cipher operation failed (encrypt / decrypt / length-decrypt).
    CipherError(String),
    /// Peer's pubkey or version packet was malformed / over-sized.
    ProtocolError(String),
}

impl std::fmt::Display for V2OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V2OutboundError::ConnectFailed(s) => write!(f, "v2 connect failed: {}", s),
            V2OutboundError::Timeout => write!(f, "v2 handshake timeout"),
            V2OutboundError::V1MagicDetected => write!(f, "v2 peer responded with v1 magic"),
            V2OutboundError::IoError(s) => write!(f, "v2 io error: {}", s),
            V2OutboundError::CipherError(s) => write!(f, "v2 cipher error: {}", s),
            V2OutboundError::ProtocolError(s) => write!(f, "v2 protocol error: {}", s),
        }
    }
}

/// Drive a BIP-324 v2 cipher handshake as the *initiator* against `addr`.
///
/// Mirrors the inbound responder flow in
/// `peer_manager::run_inbound_v2_peer` but with the order reversed and
/// with a v1-magic detection short-circuit: as the initiator we send
/// our pubkey + garbage first and observe the peer's reply, so we can
/// detect a v1-only peer (which will treat our ellswift bytes as a v1
/// version header and reply with its own v1 version) by inspecting the
/// first 16 bytes for the magic prefix.
///
/// Wire flow (initiator):
///   1. Open a fresh TCP connection.
///   2. Build a `Bip324Cipher::random()` and initialize it for
///      *initiator* mode against the peer's pubkey (not yet received —
///      we initialize lazily after step 4).
///   3. Send our 64-byte ellswift pubkey + garbage (0 bytes for now,
///      matching the responder side; randomising garbage is a
///      follow-up).
///   4. Read the first 16 bytes of the peer's reply.  If the bytes
///      look like a v1 VERSION header (`looks_like_v1_version`),
///      abandon — the peer is v1-only.  Otherwise treat as the
///      first 16 bytes of the peer's 64-byte ellswift pubkey.
///   5. Read the remaining 48 bytes of the peer's pubkey, initialise
///      the cipher in initiator mode, then send our garbage terminator
///      and an encrypted version packet (zero contents, our garbage
///      as AAD).
///   6. Scan the peer's stream for our `recv_garbage_terminator`
///      (capped at MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN), the
///      bytes preceding it are the AAD for decrypting the peer's
///      encrypted version packet.
///   7. Decrypt the encrypted length, then read header + payload + tag
///      and verify the AEAD.
///
/// On success, the cipher is in lockstep with the peer.  The function
/// returns `Ok(())` and drops the connection (the application-layer
/// version/verack pump over the encrypted channel is a follow-up; see
/// the call site in `run_outbound_peer`).
///
/// Bounded by `V2_HANDSHAKE_DEADLINE` (30 s).
async fn try_v2_outbound_handshake(
    addr: SocketAddr,
    magic: [u8; 4],
) -> Result<(), V2OutboundError> {
    // ----- Step 1: open a fresh TCP connection. -----
    let stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(V2OutboundError::ConnectFailed(e.to_string())),
        Err(_) => return Err(V2OutboundError::Timeout),
    };
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // ----- Step 2: build our cipher. -----
    let mut cipher = Bip324Cipher::random();
    let our_pubkey_bytes = *cipher.our_pubkey().as_bytes();

    // Random garbage is allowed in [0, MAX_GARBAGE_LEN].  We send 0
    // bytes for now to match the inbound responder side and minimise
    // failure surface during initial wiring; a future commit can
    // randomise.
    let our_garbage: Vec<u8> = Vec::new();

    // ----- Step 3: send our ellswift pubkey + garbage. -----
    if writer.write_all(&our_pubkey_bytes).await.is_err()
        || writer.write_all(&our_garbage).await.is_err()
        || writer.flush().await.is_err()
    {
        return Err(V2OutboundError::IoError(
            "failed to send pubkey + garbage".to_string(),
        ));
    }

    // ----- Step 4: read the peer's first 16 bytes; detect v1 magic. -----
    let mut prefix = [0u8; V1_PREFIX_LEN];
    match timeout(V2_HANDSHAKE_DEADLINE, reader.read_exact(&mut prefix)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(V2OutboundError::IoError(format!(
                "failed to read peer pubkey prefix: {}",
                e
            )))
        }
        Err(_) => return Err(V2OutboundError::Timeout),
    }
    if looks_like_v1_version(&prefix, &magic) {
        // Peer is v1 — we've already corrupted its framing by sending
        // 64+ bytes of v2 garbage, but that's the cost of probing.
        // Caller will reconnect on a fresh socket in v1 mode.
        return Err(V2OutboundError::V1MagicDetected);
    }

    // ----- Step 5: read the remaining 48 bytes of the peer's pubkey. -----
    let mut their_pubkey_bytes = [0u8; ELLSWIFT_PUBKEY_LEN];
    their_pubkey_bytes[..V1_PREFIX_LEN].copy_from_slice(&prefix);
    match timeout(
        V2_HANDSHAKE_DEADLINE,
        reader.read_exact(&mut their_pubkey_bytes[V1_PREFIX_LEN..]),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(V2OutboundError::IoError(format!(
                "failed to read peer pubkey tail: {}",
                e
            )))
        }
        Err(_) => return Err(V2OutboundError::Timeout),
    }
    let their_pubkey = EllSwiftPubKey::from_bytes(&their_pubkey_bytes)
        .map_err(|_| V2OutboundError::ProtocolError("invalid ellswift pubkey".to_string()))?;

    // Initialise the cipher in initiator mode now that we have the
    // peer's pubkey.  This consumes our secret key inside the cipher.
    cipher.initialize_for_initiator(&their_pubkey, &magic);

    // ----- Step 6: send garbage terminator + encrypted version packet. -----
    let our_garbage_term = *cipher.send_garbage_terminator();
    let mut version_packet = vec![0u8; EXPANSION]; // contents.len() == 0
    cipher
        .encrypt(&[], &our_garbage, false, &mut version_packet)
        .map_err(|e| V2OutboundError::CipherError(format!("encrypt version packet: {}", e)))?;
    if writer.write_all(&our_garbage_term).await.is_err()
        || writer.write_all(&version_packet).await.is_err()
        || writer.flush().await.is_err()
    {
        return Err(V2OutboundError::IoError(
            "failed to send terminator/version packet".to_string(),
        ));
    }

    // ----- Step 7: scan inbound for the peer's garbage terminator. -----
    let recv_garbage_term = *cipher.recv_garbage_terminator();
    let mut their_garbage: Vec<u8> = Vec::new();
    let scan_result = timeout(V2_HANDSHAKE_DEADLINE, async {
        loop {
            if their_garbage.len() > MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "garbage exceeds MAX_GARBAGE_LEN before terminator",
                ));
            }
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).await?;
            their_garbage.push(byte[0]);
            if their_garbage.len() >= GARBAGE_TERMINATOR_LEN {
                let tail_start = their_garbage.len() - GARBAGE_TERMINATOR_LEN;
                if their_garbage[tail_start..] == recv_garbage_term {
                    their_garbage.truncate(tail_start);
                    return Ok::<(), std::io::Error>(());
                }
            }
        }
    })
    .await;
    match scan_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(V2OutboundError::ProtocolError(format!(
                "garbage scan: {}",
                e
            )))
        }
        Err(_) => return Err(V2OutboundError::Timeout),
    }

    // ----- Step 8: decrypt the peer's encrypted length. -----
    let mut enc_len = [0u8; LENGTH_LEN];
    match timeout(V2_HANDSHAKE_DEADLINE, reader.read_exact(&mut enc_len)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(V2OutboundError::IoError(format!(
                "failed to read encrypted length: {}",
                e
            )))
        }
        Err(_) => return Err(V2OutboundError::Timeout),
    }
    let plain_len = cipher
        .decrypt_length(&enc_len)
        .map_err(|e| V2OutboundError::CipherError(format!("length decrypt: {}", e)))?
        as usize;
    if plain_len > MAX_MESSAGE_SIZE {
        return Err(V2OutboundError::ProtocolError(format!(
            "version packet too large: {} bytes",
            plain_len
        )));
    }

    // ----- Step 9: read + decrypt the peer's encrypted version packet. -----
    // 16 = TAG_LEN; we don't import it directly to keep the use list short.
    let total_aead = HEADER_LEN + plain_len + 16;
    let mut aead_buf = vec![0u8; total_aead];
    match timeout(V2_HANDSHAKE_DEADLINE, reader.read_exact(&mut aead_buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(V2OutboundError::IoError(format!(
                "failed to read encrypted version packet: {}",
                e
            )))
        }
        Err(_) => return Err(V2OutboundError::Timeout),
    }

    let mut contents = vec![0u8; plain_len];
    cipher
        .decrypt(&aead_buf, &their_garbage, &mut contents)
        .map_err(|e| V2OutboundError::CipherError(format!("version packet AEAD: {}", e)))?;

    // ----- Cipher handshake complete. -----
    tracing::info!(
        "outbound v2 ({}): BIP-324 v2 cipher handshake COMPLETE \
         (session_id={}, their_garbage={} bytes, version_packet={} bytes)",
        addr,
        hex::encode(cipher.session_id()),
        their_garbage.len(),
        plain_len,
    );

    Ok(())
}

/// Result of handshake validation.
#[derive(Debug)]
pub enum HandshakeError {
    /// Expected version message but got something else.
    ExpectedVersion(String),
    /// Received duplicate version message.
    DuplicateVersion,
    /// Self-connection detected (nonce matches our own).
    SelfConnection,
    /// Protocol version too old.
    ObsoleteVersion(i32),
    /// Pre-handshake message received (not version/verack).
    PreHandshakeMessage(String),
    /// I/O error during handshake.
    IoError(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::ExpectedVersion(cmd) => {
                write!(f, "expected version message, got {}", cmd)
            }
            HandshakeError::DuplicateVersion => write!(f, "duplicate version message"),
            HandshakeError::SelfConnection => write!(f, "self-connection detected"),
            HandshakeError::ObsoleteVersion(v) => write!(f, "obsolete protocol version: {}", v),
            HandshakeError::PreHandshakeMessage(cmd) => {
                write!(f, "pre-handshake message: {}", cmd)
            }
            HandshakeError::IoError(e) => write!(f, "io error: {}", e),
        }
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(e: std::io::Error) -> Self {
        HandshakeError::IoError(e)
    }
}

/// Misbehavior scores for handshake violations.
pub mod handshake_misbehavior {
    /// Pre-handshake message received (not version).
    pub const PRE_HANDSHAKE_MESSAGE: u32 = 10;
    /// Duplicate version message.
    pub const DUPLICATE_VERSION: u32 = 1;
}

/// Result of a successful handshake, including BIP negotiation flags.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// The peer's version message.
    pub version: VersionMessage,
    /// Whether the peer signaled wtxidrelay support (BIP 339).
    pub wants_wtxid_relay: bool,
    /// Whether the peer signaled addrv2 support (BIP 155).
    pub wants_addrv2: bool,
}

/// Perform the version/verack handshake with full validation.
///
/// This validates:
/// - First message must be version
/// - No duplicate version messages
/// - Self-connection detection via nonce
/// - Minimum protocol version (70015 for witness support)
/// - Only version/verack/wtxidrelay/sendaddrv2/sendtxrcncl allowed before handshake complete
///
/// The BIP negotiation flow is:
/// 1. Send/receive VERSION
/// 2. Send WTXIDRELAY, SENDADDRV2 (before VERACK per BIP 155)
/// 3. Send/receive VERACK
///
/// Returns HandshakeResult containing the peer's version and BIP negotiation flags.
async fn perform_handshake(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut BufWriter<OwnedWriteHalf>,
    magic: &[u8; 4],
    our_nonce: u64,
) -> Result<HandshakeResult, HandshakeError> {
    // Read their version message
    let their_version_msg = read_message_simple(reader, magic).await?;
    let their_version = match their_version_msg {
        NetworkMessage::Version(v) => v,
        other => {
            return Err(HandshakeError::ExpectedVersion(other.command().to_string()));
        }
    };

    // Check for self-connection (matching nonce)
    if their_version.nonce == our_nonce && our_nonce != 0 {
        return Err(HandshakeError::SelfConnection);
    }

    // Check minimum protocol version (70015 for witness support)
    if their_version.version < MIN_WITNESS_PROTO_VERSION {
        return Err(HandshakeError::ObsoleteVersion(their_version.version));
    }

    // Send BIP negotiation messages BEFORE verack (per BIP 155, BIP 339)
    // BIP 339: wtxidrelay - announce transactions by wtxid
    if their_version.version >= WTXID_RELAY_VERSION {
        let wtxid_msg = serialize_message(magic, &NetworkMessage::WtxidRelay);
        writer.write_all(&wtxid_msg).await?;
    }
    // BIP 155: sendaddrv2 - signal support for addrv2 messages
    // Send to all peers (protocol version >= 70016 is a courtesy, not a requirement)
    let addrv2_msg = serialize_message(magic, &NetworkMessage::SendAddrV2);
    writer.write_all(&addrv2_msg).await?;

    // Send verack
    let verack_data = serialize_message(magic, &NetworkMessage::Verack);
    writer.write_all(&verack_data).await?;
    writer.flush().await?;

    // Track whether we've received version (to detect duplicates)
    let mut version_received = true;

    // Track BIP negotiation messages received before verack
    let mut wants_wtxid_relay = false;
    let mut wants_addrv2 = false;

    // Read messages until we get verack
    // Only certain messages are allowed before handshake is complete:
    // - verack (completes handshake)
    // - wtxidrelay, sendaddrv2, sendtxrcncl (BIP negotiation, must be before verack)
    loop {
        let msg = read_message_simple(reader, magic).await?;
        match msg {
            NetworkMessage::Verack => break,
            NetworkMessage::Version(_) => {
                // Duplicate version message
                if version_received {
                    return Err(HandshakeError::DuplicateVersion);
                }
                version_received = true;
            }
            // BIP 339: wtxid relay negotiation
            NetworkMessage::WtxidRelay => {
                wants_wtxid_relay = true;
            }
            // BIP 155: addrv2 negotiation
            NetworkMessage::SendAddrV2 => {
                wants_addrv2 = true;
            }
            // Any other message before handshake is complete is a protocol violation
            other => {
                return Err(HandshakeError::PreHandshakeMessage(
                    other.command().to_string(),
                ));
            }
        }
    }

    Ok(HandshakeResult {
        version: their_version,
        wants_wtxid_relay,
        wants_addrv2,
    })
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
pub async fn run_message_loop(
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
    tracing::debug!("Forwarding {} message from peer {} to main loop", msg.command(), peer_id.0);
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
    use crate::message::{
        InvType, InvVector, NetAddress, NetworkMessage, VersionMessage,
        NODE_NETWORK, NODE_WITNESS, PROTOCOL_VERSION,
    };
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
            time_offset: 0,
            supports_witness: true,
            supports_sendheaders: true,
            supports_wtxid_relay: false,
            supports_addrv2: false,
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
        let _our_version = create_test_version();
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
            time_offset: 0,
            supports_witness: false,
            supports_sendheaders: true,
            supports_wtxid_relay: false,
            supports_addrv2: false,
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
        let (_command_tx, command_rx) = mpsc::channel(10);

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
        let _client_handle = tokio::spawn(async move {
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

    #[tokio::test]
    async fn test_message_reader_preallocated_buffer() {
        // Create a pre-allocated message reader
        let mut reader = MessageReader::new();

        // Initial capacity should be 4 MB
        assert!(reader.payload_buf.capacity() >= 4 * 1024 * 1024);

        // Create multiple messages of different sizes
        let messages = vec![
            NetworkMessage::Ping(0x1234567890ABCDEF),
            NetworkMessage::Verack,
            NetworkMessage::Inv(
                (0..100)
                    .map(|i| InvVector {
                        inv_type: InvType::MsgTx,
                        hash: rustoshi_primitives::Hash256([i as u8; 32]),
                    })
                    .collect(),
            ),
        ];

        for msg in messages {
            let data = serialize_message(&TESTNET4_MAGIC, &msg);
            let mut cursor = Cursor::new(data);

            let read_msg = reader.read_message(&mut cursor, &TESTNET4_MAGIC).await.unwrap();

            // Verify message was read correctly
            match (&msg, &read_msg) {
                (NetworkMessage::Ping(n1), NetworkMessage::Ping(n2)) => assert_eq!(n1, n2),
                (NetworkMessage::Verack, NetworkMessage::Verack) => {}
                (NetworkMessage::Inv(v1), NetworkMessage::Inv(v2)) => {
                    assert_eq!(v1.len(), v2.len());
                }
                _ => panic!("message type mismatch"),
            }
        }

        // Buffer should still have same capacity (reused, not reallocated)
        assert!(reader.payload_buf.capacity() >= 4 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_message_reader_bad_magic() {
        let mut reader = MessageReader::new();

        let msg = NetworkMessage::Verack;
        let data = serialize_message(&TESTNET4_MAGIC, &msg);
        let mut cursor = Cursor::new(data);

        // Try to read with wrong magic
        let wrong_magic = [0xFF, 0xFF, 0xFF, 0xFF];
        let result = reader.read_message(&mut cursor, &wrong_magic).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }

    #[tokio::test]
    async fn test_message_reader_checksum_mismatch() {
        let mut reader = MessageReader::new();

        let msg = NetworkMessage::Ping(42);
        let mut data = serialize_message(&TESTNET4_MAGIC, &msg);

        // Corrupt the checksum (bytes 20-23)
        data[20] ^= 0xFF;
        data[21] ^= 0xFF;

        let mut cursor = Cursor::new(data);
        let result = reader.read_message(&mut cursor, &TESTNET4_MAGIC).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("checksum"));
    }

    // ============================================================
    // PRE-HANDSHAKE VALIDATION TESTS
    // ============================================================

    #[tokio::test]
    async fn test_handshake_rejects_pre_handshake_ping() {
        // Test that a ping message sent before version is rejected
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let peer_id = PeerId(1);
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let (_command_tx, command_rx) = mpsc::channel(10);

        let our_version = create_test_version();
        let magic = TESTNET4_MAGIC;

        // Spawn a mock server that sends ping before version
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read client's version
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            stream.read_exact(&mut header).await.unwrap();
            let (_, _, length, _) = parse_message_header(&header);
            let mut payload = vec![0u8; length as usize];
            if !payload.is_empty() {
                stream.read_exact(&mut payload).await.unwrap();
            }

            // Send ping BEFORE version (protocol violation)
            let ping_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Ping(0x123456));
            stream.write_all(&ping_msg).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Spawn the client
        let client_handle = tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, our_version, event_tx, command_rx).await;
        });

        // Should get disconnected due to pre-handshake message
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("channel should not be closed");

        match event {
            PeerEvent::Disconnected(id, reason) => {
                assert_eq!(id, peer_id);
                match reason {
                    DisconnectReason::PreHandshakeMessage(cmd) => {
                        assert_eq!(cmd, "ping");
                    }
                    DisconnectReason::HandshakeFailed(msg) => {
                        assert!(msg.contains("ping") || msg.contains("version"));
                    }
                    _ => panic!("expected PreHandshakeMessage, got {:?}", reason),
                }
            }
            _ => panic!("expected Disconnected event"),
        }

        server_handle.await.unwrap();
        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_rejects_obsolete_protocol_version() {
        // Test that protocol version < 70015 is rejected
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let peer_id = PeerId(1);
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let (_command_tx, command_rx) = mpsc::channel(10);

        let our_version = create_test_version();
        let magic = TESTNET4_MAGIC;

        // Spawn a mock server that sends old protocol version
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read client's version
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            stream.read_exact(&mut header).await.unwrap();
            let (_, _, length, _) = parse_message_header(&header);
            let mut payload = vec![0u8; length as usize];
            if !payload.is_empty() {
                stream.read_exact(&mut payload).await.unwrap();
            }

            // Send version with obsolete protocol version (pre-witness)
            let old_version = VersionMessage {
                version: 70010, // Pre-SegWit version
                services: NODE_NETWORK,
                timestamp: 1234567890,
                addr_recv: NetAddress::from_ipv4([127, 0, 0, 1], 48333, 0),
                addr_from: NetAddress::from_ipv4([127, 0, 0, 1], 48333, NODE_NETWORK),
                nonce: 0xDEADBEEF,
                user_agent: "/old:1.0/".to_string(),
                start_height: 100,
                relay: true,
            };
            let version_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Version(old_version));
            stream.write_all(&version_msg).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Spawn the client
        let client_handle = tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, our_version, event_tx, command_rx).await;
        });

        // Should get disconnected due to obsolete version
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("channel should not be closed");

        match event {
            PeerEvent::Disconnected(id, reason) => {
                assert_eq!(id, peer_id);
                match reason {
                    DisconnectReason::ObsoleteVersion(v) => {
                        assert_eq!(v, 70010);
                    }
                    DisconnectReason::HandshakeFailed(msg) => {
                        assert!(msg.contains("70010") || msg.contains("obsolete"));
                    }
                    _ => panic!("expected ObsoleteVersion, got {:?}", reason),
                }
            }
            _ => panic!("expected Disconnected event"),
        }

        server_handle.await.unwrap();
        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_rejects_duplicate_version() {
        // Test that receiving two version messages is rejected
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let peer_id = PeerId(1);
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let (_command_tx, command_rx) = mpsc::channel(10);

        let our_version = create_test_version();
        let magic = TESTNET4_MAGIC;

        // Spawn a mock server that sends duplicate version
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read client's version
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            stream.read_exact(&mut header).await.unwrap();
            let (_, _, length, _) = parse_message_header(&header);
            let mut payload = vec![0u8; length as usize];
            if !payload.is_empty() {
                stream.read_exact(&mut payload).await.unwrap();
            }

            // Send first version
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
            let version_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Version(server_version.clone()));
            stream.write_all(&version_msg).await.unwrap();

            // Send DUPLICATE version (protocol violation)
            stream.write_all(&version_msg).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Spawn the client
        let client_handle = tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, our_version, event_tx, command_rx).await;
        });

        // Should get disconnected due to duplicate version
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("channel should not be closed");

        match event {
            PeerEvent::Disconnected(id, reason) => {
                assert_eq!(id, peer_id);
                match reason {
                    DisconnectReason::DuplicateVersion => {}
                    DisconnectReason::HandshakeFailed(msg) => {
                        assert!(msg.contains("duplicate"));
                    }
                    _ => panic!("expected DuplicateVersion, got {:?}", reason),
                }
            }
            _ => panic!("expected Disconnected event"),
        }

        server_handle.await.unwrap();
        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_rejects_self_connection() {
        // Test that self-connection (matching nonce) is rejected
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let peer_id = PeerId(1);
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let (_command_tx, command_rx) = mpsc::channel(10);

        // Use a specific nonce for our version
        let our_nonce = 0x1234567890ABCDEF_u64;
        let mut our_version = create_test_version();
        our_version.nonce = our_nonce;

        let magic = TESTNET4_MAGIC;

        // Spawn a mock server that echoes back the same nonce
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read client's version
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            stream.read_exact(&mut header).await.unwrap();
            let (_, _, length, _) = parse_message_header(&header);
            let mut payload = vec![0u8; length as usize];
            if !payload.is_empty() {
                stream.read_exact(&mut payload).await.unwrap();
            }

            // Parse the client's version to get their nonce
            let client_version = match NetworkMessage::deserialize("version", &payload) {
                Ok(NetworkMessage::Version(v)) => v,
                _ => panic!("expected version message"),
            };

            // Send version with SAME nonce (self-connection)
            let server_version = VersionMessage {
                version: PROTOCOL_VERSION,
                services: NODE_NETWORK | NODE_WITNESS,
                timestamp: 1234567890,
                addr_recv: NetAddress::from_ipv4([127, 0, 0, 1], 48333, 0),
                addr_from: NetAddress::from_ipv4([127, 0, 0, 1], 48333, NODE_NETWORK),
                nonce: client_version.nonce, // Echo back the same nonce
                user_agent: "/self:1.0/".to_string(),
                start_height: 100,
                relay: true,
            };
            let version_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Version(server_version));
            stream.write_all(&version_msg).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Spawn the client
        let client_handle = tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, our_version, event_tx, command_rx).await;
        });

        // Should get disconnected due to self-connection
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("channel should not be closed");

        match event {
            PeerEvent::Disconnected(id, reason) => {
                assert_eq!(id, peer_id);
                match reason {
                    DisconnectReason::SelfConnection => {}
                    DisconnectReason::HandshakeFailed(msg) => {
                        assert!(msg.contains("self") || msg.contains("nonce"));
                    }
                    _ => panic!("expected SelfConnection, got {:?}", reason),
                }
            }
            _ => panic!("expected Disconnected event"),
        }

        server_handle.await.unwrap();
        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_allows_wtxidrelay_before_verack() {
        // Test that wtxidrelay/sendaddrv2 messages are allowed before verack
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let peer_id = PeerId(1);
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let (_command_tx, command_rx) = mpsc::channel(10);

        let our_version = create_test_version();
        let magic = TESTNET4_MAGIC;

        // Spawn a mock server that sends wtxidrelay before verack
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read client's version
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            stream.read_exact(&mut header).await.unwrap();
            let (_, _, length, _) = parse_message_header(&header);
            let mut payload = vec![0u8; length as usize];
            if !payload.is_empty() {
                stream.read_exact(&mut payload).await.unwrap();
            }

            // Send version
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

            // Send wtxidrelay BEFORE verack (this is allowed per BIP 339)
            let wtxidrelay_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::WtxidRelay);
            stream.write_all(&wtxidrelay_msg).await.unwrap();

            // Send sendaddrv2 BEFORE verack (this is allowed per BIP 155)
            let sendaddrv2_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::SendAddrV2);
            stream.write_all(&sendaddrv2_msg).await.unwrap();

            // Send verack
            let verack_msg = serialize_message(&TESTNET4_MAGIC, &NetworkMessage::Verack);
            stream.write_all(&verack_msg).await.unwrap();
            stream.flush().await.unwrap();

            // Read their verack
            let mut header = [0u8; MESSAGE_HEADER_SIZE];
            let _ = stream.read_exact(&mut header).await;
        });

        // Spawn the client
        let _client_handle = tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, our_version, event_tx, command_rx).await;
        });

        // Should successfully connect (wtxidrelay/sendaddrv2 before verack is allowed)
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("channel should not be closed");

        match event {
            PeerEvent::Connected(id, info) => {
                assert_eq!(id, peer_id);
                assert_eq!(info.version, PROTOCOL_VERSION);
                assert_eq!(info.user_agent, "/mock:1.0/");
            }
            PeerEvent::Disconnected(id, reason) => {
                panic!("unexpected disconnect: id={}, reason={:?}", id.0, reason);
            }
            _ => panic!("expected Connected event, got {:?}", event),
        }

        server_handle.await.unwrap();
        // Client will disconnect when server closes
    }

    #[test]
    fn test_handshake_error_display() {
        // Test that HandshakeError has proper Display implementation
        let err = HandshakeError::ExpectedVersion("ping".to_string());
        assert!(err.to_string().contains("version"));
        assert!(err.to_string().contains("ping"));

        let err = HandshakeError::DuplicateVersion;
        assert!(err.to_string().contains("duplicate"));

        let err = HandshakeError::SelfConnection;
        assert!(err.to_string().contains("self"));

        let err = HandshakeError::ObsoleteVersion(70010);
        assert!(err.to_string().contains("70010"));

        let err = HandshakeError::PreHandshakeMessage("getdata".to_string());
        assert!(err.to_string().contains("getdata"));
    }

    #[test]
    fn test_handshake_misbehavior_scores() {
        // Test that misbehavior scores are correctly defined
        assert_eq!(handshake_misbehavior::PRE_HANDSHAKE_MESSAGE, 10);
        assert_eq!(handshake_misbehavior::DUPLICATE_VERSION, 1);
    }

    #[test]
    fn test_disconnect_reason_variants() {
        // Test new DisconnectReason variants
        let reason = DisconnectReason::DuplicateVersion;
        assert!(format!("{:?}", reason).contains("DuplicateVersion"));

        let reason = DisconnectReason::SelfConnection;
        assert!(format!("{:?}", reason).contains("SelfConnection"));

        let reason = DisconnectReason::PreHandshakeMessage("inv".to_string());
        assert!(format!("{:?}", reason).contains("inv"));

        let reason = DisconnectReason::ObsoleteVersion(70010);
        assert!(format!("{:?}", reason).contains("70010"));
    }

    // -------- BIP-324 v2 outbound state-machine tests --------

    /// The env-var gate must default to OFF.  Live-fleet flip happens
    /// by setting `RUSTOSHI_BIP324_V2_OUTBOUND=1` (or `true` / `yes` /
    /// `on`).  Anything else, including unset, returns false.
    #[test]
    fn test_bip324_v2_outbound_disabled_by_default() {
        // SAFETY: Cargo runs each test in its own process by default;
        // even if a user pre-set the env var, removing it here only
        // affects this test process.  We re-set it to its prior value
        // at the end on a best-effort basis (drops on panic, but the
        // process exits anyway).
        let prior = std::env::var("RUSTOSHI_BIP324_V2_OUTBOUND").ok();
        std::env::remove_var("RUSTOSHI_BIP324_V2_OUTBOUND");
        assert!(
            !bip324_v2_outbound_enabled(),
            "v2 outbound must be OFF when env var is unset"
        );
        std::env::set_var("RUSTOSHI_BIP324_V2_OUTBOUND", "0");
        assert!(
            !bip324_v2_outbound_enabled(),
            "v2 outbound must be OFF when env var is '0'"
        );
        std::env::set_var("RUSTOSHI_BIP324_V2_OUTBOUND", "no");
        assert!(
            !bip324_v2_outbound_enabled(),
            "v2 outbound must be OFF when env var is 'no'"
        );
        if let Some(v) = prior {
            std::env::set_var("RUSTOSHI_BIP324_V2_OUTBOUND", v);
        } else {
            std::env::remove_var("RUSTOSHI_BIP324_V2_OUTBOUND");
        }
    }

    /// All the canonical "ON" strings (1, true, yes, on) must enable
    /// the gate, case-insensitive.
    #[test]
    fn test_bip324_v2_outbound_enable_strings() {
        let prior = std::env::var("RUSTOSHI_BIP324_V2_OUTBOUND").ok();
        for v in ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"] {
            std::env::set_var("RUSTOSHI_BIP324_V2_OUTBOUND", v);
            assert!(
                bip324_v2_outbound_enabled(),
                "v2 outbound must be ON for env var = {:?}",
                v
            );
        }
        if let Some(v) = prior {
            std::env::set_var("RUSTOSHI_BIP324_V2_OUTBOUND", v);
        } else {
            std::env::remove_var("RUSTOSHI_BIP324_V2_OUTBOUND");
        }
    }

    /// `mark_v1_only` + `is_v1_only` round-trip — basic correctness.
    /// Note: the LRU cache is process-wide so this test must avoid
    /// addresses used by other tests.
    #[test]
    fn test_v1_only_cache_roundtrip() {
        let addr: SocketAddr = "203.0.113.42:8333".parse().unwrap();
        clear_v1_only_cache();
        assert!(!is_v1_only(&addr), "fresh cache must not contain addr");
        mark_v1_only(addr);
        assert!(is_v1_only(&addr), "marked addr must be in cache");
        let other: SocketAddr = "203.0.113.43:8333".parse().unwrap();
        assert!(!is_v1_only(&other), "unmarked addr must NOT be in cache");
        clear_v1_only_cache();
    }

    /// LRU cache must respect `V2_FALLBACK_CACHE_MAX`: inserting more
    /// than that many entries must NOT cause the cache to grow without
    /// bound — it caps at the max.
    #[test]
    fn test_v1_only_cache_lru_eviction() {
        clear_v1_only_cache();
        // Insert V2_FALLBACK_CACHE_MAX + 100 distinct addresses.
        for i in 0..(V2_FALLBACK_CACHE_MAX as u16 + 100) {
            // Use 198.51.100.0/16 reserved-for-documentation range.
            let oct_a = (i / 256) as u8;
            let oct_b = (i % 256) as u8;
            let addr: SocketAddr = format!("198.51.{}.{}:8333", oct_a, oct_b)
                .parse()
                .unwrap();
            mark_v1_only(addr);
        }
        // Cache size must be <= V2_FALLBACK_CACHE_MAX (we evict on
        // insert when at capacity).
        let size = v1_only_cache().lock().unwrap().len();
        assert!(
            size <= V2_FALLBACK_CACHE_MAX,
            "cache must respect cap; got {} > {}",
            size,
            V2_FALLBACK_CACHE_MAX
        );
        // And must be exactly capped (we inserted +100 over the cap).
        assert_eq!(
            size, V2_FALLBACK_CACHE_MAX,
            "cache must fill to exactly the cap"
        );
        clear_v1_only_cache();
    }

    /// V2OutboundError Display impl must include enough context for
    /// debugging (used in tracing logs).
    #[test]
    fn test_v2_outbound_error_display() {
        let err = V2OutboundError::ConnectFailed("refused".to_string());
        assert!(err.to_string().contains("refused"));

        let err = V2OutboundError::Timeout;
        assert!(err.to_string().contains("timeout"));

        let err = V2OutboundError::V1MagicDetected;
        assert!(err.to_string().contains("v1 magic"));

        let err = V2OutboundError::CipherError("tag mismatch".to_string());
        assert!(err.to_string().contains("tag mismatch"));

        let err = V2OutboundError::ProtocolError("oversized".to_string());
        assert!(err.to_string().contains("oversized"));
    }

    /// V1-magic detection: when a v1-only peer sees our 64-byte
    /// ellswift garbage on the wire, it tries to parse it as a v1
    /// message header and (typically) replies with its own version
    /// message starting with the network magic.  We must detect this
    /// in the first 16 bytes of the peer's reply via
    /// `looks_like_v1_version` and fall back.
    ///
    /// This test exercises the same classification logic used inside
    /// `try_v2_outbound_handshake` so we can verify the detection
    /// without needing live secp256k1 (the lowmemory feature aborts on
    /// `ElligatorSwift::new`, which would block any real handshake
    /// test).
    #[test]
    fn test_v1_magic_detection_in_outbound_reply() {
        // Mainnet magic + b"version\0\0\0\0\0".
        let mainnet = [0xf9, 0xbe, 0xb4, 0xd9];
        let mut v1_reply = [0u8; V1_PREFIX_LEN];
        v1_reply[..4].copy_from_slice(&mainnet);
        v1_reply[4..16].copy_from_slice(b"version\0\0\0\0\0");
        assert!(
            looks_like_v1_version(&v1_reply, &mainnet),
            "v1 peer reply must be classified as v1"
        );

        // Random-looking 16 bytes (i.e. start of an ellswift pubkey)
        // must NOT be classified as v1 with overwhelming probability.
        let v2_pubkey_prefix = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        assert!(
            !looks_like_v1_version(&v2_pubkey_prefix, &mainnet),
            "v2 peer reply (random pubkey prefix) must NOT be classified as v1"
        );

        // Magic match but wrong command (e.g. peer sent "addr" first
        // — protocol violation): not a v1 marker.  This matches
        // `looks_like_v1_version`'s contract: only the unambiguous v1
        // VERSION-message start is treated as v1.
        let mut wrong_cmd = [0u8; V1_PREFIX_LEN];
        wrong_cmd[..4].copy_from_slice(&mainnet);
        wrong_cmd[4..16].copy_from_slice(b"addr\0\0\0\0\0\0\0\0");
        assert!(
            !looks_like_v1_version(&wrong_cmd, &mainnet),
            "magic+wrong-command must NOT be classified as v1"
        );
    }

    /// V2 handshake deadline must match the documented 30s budget
    /// (mirrors clearbit's `V2_HANDSHAKE_DEADLINE_MS = 30_000`).
    #[test]
    fn test_v2_handshake_deadline_constant() {
        assert_eq!(V2_HANDSHAKE_DEADLINE, Duration::from_secs(30));
    }
}
