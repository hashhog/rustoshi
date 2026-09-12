//! ZeroMQ notification support for real-time block and transaction events.
//!
//! This module implements Bitcoin Core-compatible ZMQ notifications, publishing
//! events on the following topics:
//!
//! - `hashblock`: 32-byte block hash (reversed for display order)
//! - `hashtx`: 32-byte transaction ID (reversed for display order)
//! - `rawblock`: Full serialized block with witness data
//! - `rawtx`: Full serialized transaction with witness data
//! - `sequence`: Hash + event label for mempool/block lifecycle events
//!
//! # Message Format
//!
//! Each ZMQ message is multi-part:
//! - Frame 1: Topic string (e.g., "hashblock")
//! - Frame 2: Body (hash, raw data, or sequence event)
//! - Frame 3: Sequence number (4-byte little-endian u32)
//!
//! # Configuration
//!
//! Enable via CLI flags like `-zmqpubhashblock=tcp://127.0.0.1:28332`.
//! Multiple endpoints can publish to the same or different addresses.
//!
//! # Thread Safety
//!
//! ZMQ sockets are not Send/Sync, so this module uses a dedicated thread for
//! ZMQ operations. The `ZmqNotifier` wrapper communicates with this thread
//! via channels, making it safe to use from async Rust code.

use rustoshi_primitives::{Block, Encodable, Hash256, Transaction};
use std::collections::HashMap;
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors that can occur during ZMQ operations.
#[derive(Debug, Error)]
pub enum ZmqError {
    #[error("failed to create ZMQ context: {0}")]
    ContextCreation(String),

    #[error("failed to create ZMQ socket: {0}")]
    SocketCreation(String),

    #[error("failed to bind socket to {address}: {reason}")]
    BindFailed { address: String, reason: String },

    #[error("failed to set socket option: {0}")]
    SetOption(String),

    #[error("failed to send message: {0}")]
    SendFailed(String),

    #[error("invalid endpoint address: {0}")]
    InvalidAddress(String),

    #[error("worker thread error: {0}")]
    WorkerError(String),
}

// ============================================================
// TOPIC TYPES
// ============================================================

/// ZMQ notification topic types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZmqTopic {
    /// Publish block hash on new tip
    HashBlock,
    /// Publish transaction hash on mempool add
    HashTx,
    /// Publish raw serialized block
    RawBlock,
    /// Publish raw serialized transaction
    RawTx,
    /// Publish sequence events (mempool add/remove, block connect/disconnect)
    Sequence,
}

impl ZmqTopic {
    /// Get the topic string used in ZMQ messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            ZmqTopic::HashBlock => "hashblock",
            ZmqTopic::HashTx => "hashtx",
            ZmqTopic::RawBlock => "rawblock",
            ZmqTopic::RawTx => "rawtx",
            ZmqTopic::Sequence => "sequence",
        }
    }

    /// Parse a topic from a CLI argument name.
    pub fn from_arg(arg: &str) -> Option<Self> {
        match arg {
            "zmqpubhashblock" => Some(ZmqTopic::HashBlock),
            "zmqpubhashtx" => Some(ZmqTopic::HashTx),
            "zmqpubrawblock" => Some(ZmqTopic::RawBlock),
            "zmqpubrawtx" => Some(ZmqTopic::RawTx),
            "zmqpubsequence" => Some(ZmqTopic::Sequence),
            _ => None,
        }
    }
}

impl std::fmt::Display for ZmqTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================
// SEQUENCE EVENT LABELS
// ============================================================

/// Sequence notification event labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceLabel {
    /// Transaction added to mempool
    MempoolAcceptance,
    /// Transaction removed from mempool
    MempoolRemoval,
    /// Block connected to chain
    BlockConnect,
    /// Block disconnected from chain
    BlockDisconnect,
}

impl SequenceLabel {
    /// Get the single-byte label character.
    pub fn as_byte(&self) -> u8 {
        match self {
            SequenceLabel::MempoolAcceptance => b'A',
            SequenceLabel::MempoolRemoval => b'R',
            SequenceLabel::BlockConnect => b'C',
            SequenceLabel::BlockDisconnect => b'D',
        }
    }
}

// ============================================================
// NOTIFIER CONFIGURATION
// ============================================================

/// Configuration for a single ZMQ notification endpoint.
#[derive(Debug, Clone)]
pub struct ZmqNotifierConfig {
    /// Topic type
    pub topic: ZmqTopic,
    /// Endpoint address (e.g., "tcp://127.0.0.1:28332")
    pub address: String,
    /// High water mark for outbound messages (default: 1000)
    pub high_water_mark: i32,
}

impl ZmqNotifierConfig {
    /// Create a new notifier configuration.
    pub fn new(topic: ZmqTopic, address: String) -> Self {
        Self {
            topic,
            address,
            high_water_mark: 1000,
        }
    }

    /// Set the high water mark.
    pub fn with_hwm(mut self, hwm: i32) -> Self {
        self.high_water_mark = hwm;
        self
    }
}

// ============================================================
// ZMQ NOTIFICATION COMMANDS
// ============================================================

/// Commands sent to the ZMQ worker thread.
#[derive(Debug)]
enum ZmqCommand {
    /// Publish a block notification
    NotifyBlock {
        block_hash: Hash256,
        raw_block: Vec<u8>,
    },
    /// Publish a transaction notification
    NotifyTransaction { txid: Hash256, raw_tx: Vec<u8> },
    /// Publish block connect sequence event
    BlockConnect { block_hash: Hash256 },
    /// Publish block disconnect sequence event
    BlockDisconnect { block_hash: Hash256 },
    /// Publish tx acceptance sequence event
    TxAcceptance {
        txid: Hash256,
        mempool_sequence: u64,
    },
    /// Publish tx removal sequence event
    TxRemoval {
        txid: Hash256,
        mempool_sequence: u64,
    },
    /// Shutdown the worker thread
    Shutdown,
}

// ============================================================
// ZMQ NOTIFICATION INTERFACE (INTERNAL)
// ============================================================

/// Internal ZMQ notification publisher (runs on dedicated thread).
struct ZmqPublisher {
    /// ZMQ context
    #[allow(dead_code)]
    context: zmq::Context,
    /// Sockets by address (shared if same endpoint)
    sockets: HashMap<String, zmq::Socket>,
    /// Sequence numbers per topic
    sequences: HashMap<ZmqTopic, u32>,
    /// Active notifier configurations
    notifiers: Vec<ZmqNotifierConfig>,
}

impl ZmqPublisher {
    /// Create a new ZMQ publisher.
    fn new(configs: Vec<ZmqNotifierConfig>) -> Result<Self, ZmqError> {
        let context = zmq::Context::new();
        let mut sockets = HashMap::new();
        let mut sequences = HashMap::new();

        for config in &configs {
            // Initialize sequence counter for this topic
            sequences.entry(config.topic).or_insert(0);

            // Skip if we already have a socket for this address
            if sockets.contains_key(&config.address) {
                debug!(
                    "Reusing ZMQ socket for {} at {}",
                    config.topic, config.address
                );
                continue;
            }

            // Create and bind a new socket
            let socket = context
                .socket(zmq::PUB)
                .map_err(|e| ZmqError::SocketCreation(e.to_string()))?;

            // Set high water mark
            socket
                .set_sndhwm(config.high_water_mark)
                .map_err(|e| ZmqError::SetOption(format!("SNDHWM: {}", e)))?;

            // Enable TCP keepalive
            socket
                .set_tcp_keepalive(1)
                .map_err(|e| ZmqError::SetOption(format!("TCP_KEEPALIVE: {}", e)))?;

            // Bind to the address
            socket
                .bind(&config.address)
                .map_err(|e| ZmqError::BindFailed {
                    address: config.address.clone(),
                    reason: e.to_string(),
                })?;

            info!("ZMQ {} bound to {}", config.topic.as_str(), config.address);
            sockets.insert(config.address.clone(), socket);
        }

        Ok(Self {
            context,
            sockets,
            sequences,
            notifiers: configs,
        })
    }

    /// Send a multipart ZMQ message.
    fn send_multipart(&self, address: &str, topic: &str, body: &[u8], seq: u32) -> bool {
        let socket = match self.sockets.get(address) {
            Some(s) => s,
            None => {
                error!("No socket for address {}", address);
                return false;
            }
        };

        let seq_bytes = seq.to_le_bytes();

        // Send topic (with SNDMORE)
        if let Err(e) = socket.send(topic.as_bytes(), zmq::SNDMORE) {
            error!("Failed to send ZMQ topic: {}", e);
            return false;
        }

        // Send body (with SNDMORE)
        if let Err(e) = socket.send(body, zmq::SNDMORE) {
            error!("Failed to send ZMQ body: {}", e);
            return false;
        }

        // Send sequence number (final frame)
        if let Err(e) = socket.send(&seq_bytes[..], 0) {
            error!("Failed to send ZMQ sequence: {}", e);
            return false;
        }

        true
    }

    /// Get and increment the sequence number for a topic.
    fn next_sequence(&mut self, topic: ZmqTopic) -> u32 {
        let seq = self.sequences.entry(topic).or_insert(0);
        let current = *seq;
        *seq = seq.wrapping_add(1);
        current
    }

    /// Handle a notification command.
    fn handle_command(&mut self, cmd: ZmqCommand) {
        match cmd {
            ZmqCommand::NotifyBlock {
                block_hash,
                raw_block,
            } => {
                self.notify_block(&block_hash, &raw_block);
            }
            ZmqCommand::NotifyTransaction { txid, raw_tx } => {
                self.notify_transaction(&txid, &raw_tx);
            }
            ZmqCommand::BlockConnect { block_hash } => {
                self.send_sequence(&block_hash, SequenceLabel::BlockConnect, None);
            }
            ZmqCommand::BlockDisconnect { block_hash } => {
                self.send_sequence(&block_hash, SequenceLabel::BlockDisconnect, None);
            }
            ZmqCommand::TxAcceptance {
                txid,
                mempool_sequence,
            } => {
                self.send_sequence(
                    &txid,
                    SequenceLabel::MempoolAcceptance,
                    Some(mempool_sequence),
                );
            }
            ZmqCommand::TxRemoval {
                txid,
                mempool_sequence,
            } => {
                self.send_sequence(&txid, SequenceLabel::MempoolRemoval, Some(mempool_sequence));
            }
            ZmqCommand::Shutdown => {
                // Handled in run loop
            }
        }
    }

    fn notify_block(&mut self, block_hash: &Hash256, raw_block: &[u8]) {
        // Collect addresses for each topic to avoid borrow conflicts
        let hashblock_addrs: Vec<_> = self
            .notifiers
            .iter()
            .filter(|c| c.topic == ZmqTopic::HashBlock)
            .map(|c| c.address.clone())
            .collect();
        let rawblock_addrs: Vec<_> = self
            .notifiers
            .iter()
            .filter(|c| c.topic == ZmqTopic::RawBlock)
            .map(|c| c.address.clone())
            .collect();

        let hash_bytes = reverse_hash(block_hash);

        for address in hashblock_addrs {
            let seq = self.next_sequence(ZmqTopic::HashBlock);
            if self.send_multipart(&address, "hashblock", &hash_bytes, seq) {
                debug!("Published hashblock {} to {}", block_hash, address);
            }
        }

        for address in rawblock_addrs {
            let seq = self.next_sequence(ZmqTopic::RawBlock);
            if self.send_multipart(&address, "rawblock", raw_block, seq) {
                debug!(
                    "Published rawblock {} ({} bytes) to {}",
                    block_hash,
                    raw_block.len(),
                    address
                );
            }
        }
    }

    fn notify_transaction(&mut self, txid: &Hash256, raw_tx: &[u8]) {
        let hashtx_addrs: Vec<_> = self
            .notifiers
            .iter()
            .filter(|c| c.topic == ZmqTopic::HashTx)
            .map(|c| c.address.clone())
            .collect();
        let rawtx_addrs: Vec<_> = self
            .notifiers
            .iter()
            .filter(|c| c.topic == ZmqTopic::RawTx)
            .map(|c| c.address.clone())
            .collect();

        let hash_bytes = reverse_hash(txid);

        for address in hashtx_addrs {
            let seq = self.next_sequence(ZmqTopic::HashTx);
            if self.send_multipart(&address, "hashtx", &hash_bytes, seq) {
                debug!("Published hashtx {} to {}", txid, address);
            }
        }

        for address in rawtx_addrs {
            let seq = self.next_sequence(ZmqTopic::RawTx);
            if self.send_multipart(&address, "rawtx", raw_tx, seq) {
                debug!(
                    "Published rawtx {} ({} bytes) to {}",
                    txid,
                    raw_tx.len(),
                    address
                );
            }
        }
    }

    fn send_sequence(
        &mut self,
        hash: &Hash256,
        label: SequenceLabel,
        mempool_sequence: Option<u64>,
    ) {
        let sequence_addrs: Vec<_> = self
            .notifiers
            .iter()
            .filter(|c| c.topic == ZmqTopic::Sequence)
            .map(|c| c.address.clone())
            .collect();

        if sequence_addrs.is_empty() {
            return;
        }

        let body_len = 32 + 1 + if mempool_sequence.is_some() { 8 } else { 0 };
        let mut body = Vec::with_capacity(body_len);

        let hash_bytes = reverse_hash(hash);
        body.extend_from_slice(&hash_bytes);
        body.push(label.as_byte());

        if let Some(seq) = mempool_sequence {
            body.extend_from_slice(&seq.to_le_bytes());
        }

        for address in sequence_addrs {
            let seq = self.next_sequence(ZmqTopic::Sequence);
            if self.send_multipart(&address, "sequence", &body, seq) {
                debug!("Published sequence {} {:?} to {}", hash, label, address);
            }
        }
    }

    fn shutdown(&mut self) {
        info!("Shutting down ZMQ publisher");
        for (address, socket) in self.sockets.drain() {
            if let Err(e) = socket.set_linger(0) {
                warn!("Failed to set ZMQ linger on {}: {}", address, e);
            }
            debug!("Closed ZMQ socket at {}", address);
        }
    }
}

// ============================================================
// ZMQ NOTIFIER (THREAD-SAFE WRAPPER)
// ============================================================

/// Thread-safe ZMQ notifier.
///
/// Wraps the ZMQ publisher in a dedicated thread, communicating via channels.
/// This makes the notifier `Send + Sync` and safe to use from async code.
pub struct ZmqNotifier {
    /// Channel to send commands to the worker thread
    command_tx: Sender<ZmqCommand>,
    /// Worker thread handle
    worker_handle: Option<JoinHandle<()>>,
    /// Active notifier configurations (for RPC query)
    notifiers: Vec<ZmqNotifierConfig>,
}

impl ZmqNotifier {
    /// Create a new ZMQ notifier.
    ///
    /// Returns `None` if no notifiers are configured.
    pub fn create(configs: Vec<ZmqNotifierConfig>) -> Result<Option<Self>, ZmqError> {
        if configs.is_empty() {
            return Ok(None);
        }

        let notifiers = configs.clone();
        let (tx, rx) = mpsc::channel::<ZmqCommand>();

        // Spawn worker thread
        let handle = thread::Builder::new()
            .name("zmq-notifier".to_string())
            .spawn(move || {
                let mut publisher = match ZmqPublisher::new(configs) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to initialize ZMQ publisher: {}", e);
                        return;
                    }
                };

                loop {
                    match rx.recv() {
                        Ok(ZmqCommand::Shutdown) => {
                            publisher.shutdown();
                            break;
                        }
                        Ok(cmd) => {
                            publisher.handle_command(cmd);
                        }
                        Err(_) => {
                            // Channel closed, shutdown
                            publisher.shutdown();
                            break;
                        }
                    }
                }
            })
            .map_err(|e| ZmqError::WorkerError(e.to_string()))?;

        Ok(Some(Self {
            command_tx: tx,
            worker_handle: Some(handle),
            notifiers,
        }))
    }

    /// Get the list of active notifiers for RPC response.
    pub fn get_active_notifiers(&self) -> Vec<ZmqNotificationInfo> {
        self.notifiers
            .iter()
            .map(|config| ZmqNotificationInfo {
                notification_type: format!("pub{}", config.topic.as_str()),
                address: config.address.clone(),
                hwm: config.high_water_mark,
            })
            .collect()
    }

    /// Notify subscribers of a new block.
    pub fn notify_block(&self, block: &Block) {
        let block_hash = block.block_hash();
        let raw_block = block.serialize();
        let _ = self.command_tx.send(ZmqCommand::NotifyBlock {
            block_hash,
            raw_block,
        });
    }

    /// Notify subscribers of a transaction.
    pub fn notify_transaction(&self, tx: &Transaction) {
        let txid = tx.txid();
        let raw_tx = tx.serialize();
        let _ = self
            .command_tx
            .send(ZmqCommand::NotifyTransaction { txid, raw_tx });
    }

    /// Notify subscribers of block connection.
    pub fn notify_block_connect(&self, block_hash: &Hash256) {
        let _ = self.command_tx.send(ZmqCommand::BlockConnect {
            block_hash: *block_hash,
        });
    }

    /// Notify subscribers of block disconnection.
    pub fn notify_block_disconnect(&self, block_hash: &Hash256) {
        let _ = self.command_tx.send(ZmqCommand::BlockDisconnect {
            block_hash: *block_hash,
        });
    }

    /// Notify subscribers of mempool transaction acceptance.
    pub fn notify_tx_acceptance(&self, txid: &Hash256, mempool_sequence: u64) {
        let _ = self.command_tx.send(ZmqCommand::TxAcceptance {
            txid: *txid,
            mempool_sequence,
        });
    }

    /// Notify subscribers of mempool transaction removal.
    pub fn notify_tx_removal(&self, txid: &Hash256, mempool_sequence: u64) {
        let _ = self.command_tx.send(ZmqCommand::TxRemoval {
            txid: *txid,
            mempool_sequence,
        });
    }

    /// Shutdown the ZMQ notifier.
    pub fn shutdown(&mut self) {
        let _ = self.command_tx.send(ZmqCommand::Shutdown);
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ZmqNotifier {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/// Reverse hash bytes for display order (internal LE -> display BE).
fn reverse_hash(hash: &Hash256) -> [u8; 32] {
    let mut reversed = hash.0;
    reversed.reverse();
    reversed
}

// ============================================================
// RPC RESPONSE TYPES
// ============================================================

/// Information about an active ZMQ notifier for getzmqnotifications RPC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZmqNotificationInfo {
    /// Notification type (e.g., "pubhashblock")
    #[serde(rename = "type")]
    pub notification_type: String,
    /// Endpoint address
    pub address: String,
    /// High water mark
    pub hwm: i32,
}

// ============================================================
// THREAD-SAFE TYPE ALIAS
// ============================================================

/// Thread-safe wrapper for ZMQ notifications.
pub type SharedZmqNotifier = Arc<ZmqNotifier>;

/// Parse ZMQ configuration from CLI arguments.
///
/// Expected format: `--zmqpub<topic>=<address>`, e.g.:
/// - `--zmqpubhashblock=tcp://127.0.0.1:28332`
/// - `--zmqpubhashtx=tcp://127.0.0.1:28332`
/// - `--zmqpubrawblock=tcp://127.0.0.1:28333`
/// - `--zmqpubrawtx=tcp://127.0.0.1:28333`
/// - `--zmqpubsequence=tcp://127.0.0.1:28334`
pub fn parse_zmq_args(args: &[(String, String)]) -> Vec<ZmqNotifierConfig> {
    let mut configs = Vec::new();

    for (key, value) in args {
        if let Some(topic) = ZmqTopic::from_arg(key) {
            configs.push(ZmqNotifierConfig::new(topic, value.clone()));
        }
    }

    configs
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, Instant};

    /// ZMQ PUB/SUB over TCP is lossy across the handshake. Serialize the
    /// integration tests so a loaded `cargo test --workspace` does not drop
    /// the first message, and never skip-on-bind-fail (that masks a red run).
    static ZMQ_INTEGRATION: Mutex<()> = Mutex::new(());

    fn zmq_integration_lock() -> std::sync::MutexGuard<'static, ()> {
        ZMQ_INTEGRATION.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ephemeral_zmq_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("ephemeral bind")
            .local_addr()
            .expect("local_addr")
            .port()
    }

    /// Poll a SUB socket for a 3-frame notification until `deadline`.
    ///
    /// A single blocking `recv` after a fixed sleep loses the ZMQ slow-joiner
    /// race: if the PUB send lands before the SUB filter is on the socket,
    /// the message is dropped and the recv times out with `None`.
    fn recv_notification_until(
        socket: &zmq::Socket,
        deadline: Instant,
    ) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout_ms = remaining.as_millis().min(50) as i64;
            if timeout_ms == 0 {
                break;
            }
            match socket.poll(zmq::POLLIN, timeout_ms) {
                Ok(n) if n > 0 => {
                    let topic = socket.recv_bytes(0).ok()?;
                    let body = socket.recv_bytes(0).ok()?;
                    let seq = socket.recv_bytes(0).ok()?;
                    return Some((topic, body, seq));
                }
                _ => {}
            }
        }
        None
    }

    /// Bind an ephemeral PUB, wait until the SUB has connected and subscribed,
    /// then keep calling `publish` until the SUB observes a 3-frame notification
    /// or `wait` elapses. Republishing is required: a PUB send that beats the
    /// SUB filter is dropped (ZMQ slow-joiner).
    fn zmq_pubsub_roundtrip<F>(
        topic: ZmqTopic,
        wait: Duration,
        mut publish: F,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, ZmqNotifier)
    where
        F: FnMut(&ZmqNotifier),
    {
        let _guard = zmq_integration_lock();
        let address = format!("tcp://127.0.0.1:{}", ephemeral_zmq_port());
        let configs = vec![ZmqNotifierConfig::new(topic, address.clone())];
        let notifier = ZmqNotifier::create(configs)
            .unwrap_or_else(|e| panic!("zmq notifier: {e}"))
            .expect("Expected notifier");

        let topic_bytes = topic.as_str().as_bytes().to_vec();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let context = zmq::Context::new();
            let socket = context.socket(zmq::SUB).expect("sub socket");
            socket.set_linger(0).ok();
            socket.connect(&address).expect("sub connect");
            socket.set_subscribe(&topic_bytes).expect("subscribe");
            let _ = ready_tx.send(());
            recv_notification_until(&socket, Instant::now() + wait)
        });

        ready_rx.recv_timeout(wait).expect("subscriber connected");

        let deadline = Instant::now() + wait;
        while Instant::now() < deadline && !handle.is_finished() {
            publish(&notifier);
            thread::sleep(Duration::from_millis(20));
        }

        let (topic, body, seq) = handle
            .join()
            .expect("subscriber thread")
            .unwrap_or_else(|| panic!("timed out waiting for {} notification", topic.as_str()));
        (topic, body, seq, notifier)
    }

    #[test]
    fn test_topic_as_str() {
        assert_eq!(ZmqTopic::HashBlock.as_str(), "hashblock");
        assert_eq!(ZmqTopic::HashTx.as_str(), "hashtx");
        assert_eq!(ZmqTopic::RawBlock.as_str(), "rawblock");
        assert_eq!(ZmqTopic::RawTx.as_str(), "rawtx");
        assert_eq!(ZmqTopic::Sequence.as_str(), "sequence");
    }

    #[test]
    fn test_topic_from_arg() {
        assert_eq!(
            ZmqTopic::from_arg("zmqpubhashblock"),
            Some(ZmqTopic::HashBlock)
        );
        assert_eq!(ZmqTopic::from_arg("zmqpubhashtx"), Some(ZmqTopic::HashTx));
        assert_eq!(
            ZmqTopic::from_arg("zmqpubrawblock"),
            Some(ZmqTopic::RawBlock)
        );
        assert_eq!(ZmqTopic::from_arg("zmqpubrawtx"), Some(ZmqTopic::RawTx));
        assert_eq!(
            ZmqTopic::from_arg("zmqpubsequence"),
            Some(ZmqTopic::Sequence)
        );
        assert_eq!(ZmqTopic::from_arg("invalid"), None);
    }

    #[test]
    fn test_sequence_labels() {
        assert_eq!(SequenceLabel::MempoolAcceptance.as_byte(), b'A');
        assert_eq!(SequenceLabel::MempoolRemoval.as_byte(), b'R');
        assert_eq!(SequenceLabel::BlockConnect.as_byte(), b'C');
        assert_eq!(SequenceLabel::BlockDisconnect.as_byte(), b'D');
    }

    #[test]
    fn test_reverse_hash() {
        let hash =
            Hash256::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let reversed = reverse_hash(&hash);
        // The reversed bytes should start with 0x00 (the leading zeros of the hash display)
        assert_eq!(reversed[0], 0x00);
        assert_eq!(reversed[1], 0x00);
        assert_eq!(reversed[2], 0x00);
    }

    #[test]
    fn test_parse_zmq_args() {
        let args = vec![
            (
                "zmqpubhashblock".to_string(),
                "tcp://127.0.0.1:28332".to_string(),
            ),
            (
                "zmqpubhashtx".to_string(),
                "tcp://127.0.0.1:28332".to_string(),
            ),
            (
                "zmqpubrawblock".to_string(),
                "tcp://127.0.0.1:28333".to_string(),
            ),
            ("invalid".to_string(), "ignored".to_string()),
        ];

        let configs = parse_zmq_args(&args);
        assert_eq!(configs.len(), 3);
        assert_eq!(configs[0].topic, ZmqTopic::HashBlock);
        assert_eq!(configs[0].address, "tcp://127.0.0.1:28332");
        assert_eq!(configs[1].topic, ZmqTopic::HashTx);
        assert_eq!(configs[2].topic, ZmqTopic::RawBlock);
    }

    #[test]
    fn test_no_configs_returns_none() {
        let result = ZmqNotifier::create(vec![]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_zmq_notification_info_serialization() {
        let info = ZmqNotificationInfo {
            notification_type: "pubhashblock".to_string(),
            address: "tcp://127.0.0.1:28332".to_string(),
            hwm: 1000,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("pubhashblock"));
        assert!(json.contains("tcp://127.0.0.1:28332"));
        assert!(json.contains("1000"));
    }

    #[test]
    fn test_zmq_pub_sub_hashblock() {
        let block = create_test_block();
        let (topic, body, seq, mut notifier) =
            zmq_pubsub_roundtrip(ZmqTopic::HashBlock, Duration::from_secs(2), |n| {
                n.notify_block(&block)
            });

        assert_eq!(topic, b"hashblock");
        assert_eq!(body.len(), 32);
        assert_eq!(seq.len(), 4);

        notifier.shutdown();
    }

    #[test]
    fn test_zmq_pub_sub_sequence() {
        let block_hash =
            Hash256::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let (topic, body, seq, mut notifier) =
            zmq_pubsub_roundtrip(ZmqTopic::Sequence, Duration::from_secs(2), |n| {
                n.notify_block_connect(&block_hash)
            });

        assert_eq!(topic, b"sequence");
        // 32 bytes hash + 1 byte label (no mempool sequence for block events)
        assert_eq!(body.len(), 33);
        assert_eq!(body[32], b'C');
        assert_eq!(seq.len(), 4);

        notifier.shutdown();
    }

    #[test]
    fn test_zmq_sequence_mempool_acceptance() {
        let txid =
            Hash256::from_hex("7f6b3f6d7c8b9a0e1d2c3b4a5f6e7d8c9b0a1e2d3c4b5a6f7e8d9c0b1a2e3d4c")
                .unwrap();
        let (topic, body, seq, mut notifier) =
            zmq_pubsub_roundtrip(ZmqTopic::Sequence, Duration::from_secs(2), |n| {
                n.notify_tx_acceptance(&txid, 12345)
            });

        assert_eq!(topic, b"sequence");
        // 32 bytes hash + 1 byte label + 8 bytes mempool sequence
        assert_eq!(body.len(), 41);
        assert_eq!(body[32], b'A'); // Mempool Acceptance
        let mempool_seq = u64::from_le_bytes(body[33..41].try_into().unwrap());
        assert_eq!(mempool_seq, 12345);
        assert_eq!(seq.len(), 4);

        notifier.shutdown();
    }

    // Helper function to create a minimal test block
    fn create_test_block() -> Block {
        use rustoshi_primitives::{BlockHeader, OutPoint, TxIn, TxOut};

        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };

        // Create a minimal coinbase transaction
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0xffffffff,
                },
                script_sig: vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14], // Truncated P2PKH
            }],
            lock_time: 0,
        };

        Block {
            header,
            transactions: vec![coinbase_tx],
        }
    }

    #[test]
    fn test_zmq_pub_sub_rawtx() {
        let tx = create_test_tx();
        let expected_raw = tx.serialize();
        let (topic, body, seq, mut notifier) =
            zmq_pubsub_roundtrip(ZmqTopic::RawTx, Duration::from_secs(2), |n| {
                n.notify_transaction(&tx)
            });

        assert_eq!(topic, b"rawtx");
        assert_eq!(body, expected_raw);
        assert_eq!(seq.len(), 4);

        notifier.shutdown();
    }

    fn create_test_tx() -> Transaction {
        use rustoshi_primitives::{OutPoint, TxIn, TxOut};

        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: vec![0x00],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![
                    0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn test_get_active_notifiers() {
        let configs = vec![
            ZmqNotifierConfig::new(ZmqTopic::HashBlock, "tcp://127.0.0.1:28332".to_string()),
            ZmqNotifierConfig::new(ZmqTopic::HashTx, "tcp://127.0.0.1:28332".to_string()),
            ZmqNotifierConfig::new(ZmqTopic::Sequence, "tcp://127.0.0.1:28334".to_string()),
        ];

        // We can't easily create a notifier without binding ports, but we can test
        // the info structure directly
        let infos: Vec<ZmqNotificationInfo> = configs
            .iter()
            .map(|c| ZmqNotificationInfo {
                notification_type: format!("pub{}", c.topic.as_str()),
                address: c.address.clone(),
                hwm: c.high_water_mark,
            })
            .collect();

        assert_eq!(infos.len(), 3);
        assert_eq!(infos[0].notification_type, "pubhashblock");
        assert_eq!(infos[1].notification_type, "pubhashtx");
        assert_eq!(infos[2].notification_type, "pubsequence");
    }
}
