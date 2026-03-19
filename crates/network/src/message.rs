//! Bitcoin P2P protocol message types and serialization.
//!
//! This module implements the Bitcoin P2P message format:
//! - 24-byte message header (magic, command, length, checksum)
//! - Variable-length payload
//!
//! Each message type has its own payload format as defined by the Bitcoin protocol.

use rustoshi_crypto::sha256d;
use rustoshi_primitives::serialize::{read_compact_size, write_compact_size};
use rustoshi_primitives::{Block, BlockHeader, Decodable, Encodable, Hash256, Transaction};
use std::io::{Cursor, Read};

/// Size of the message header in bytes.
pub const MESSAGE_HEADER_SIZE: usize = 24;

/// Maximum message payload size (32 MB).
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Maximum number of inventory items in a single message.
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum number of headers in a single headers message.
pub const MAX_HEADERS: usize = 2000;

/// Maximum number of addresses in a single addr message.
pub const MAX_ADDR: usize = 1000;

/// Inventory type flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum InvType {
    /// Error/unknown type.
    Error = 0,
    /// Transaction.
    MsgTx = 1,
    /// Block.
    MsgBlock = 2,
    /// Filtered block (BIP 37).
    MsgFilteredBlock = 3,
    /// Compact block (BIP 152).
    MsgCmpctBlock = 4,
    /// Witness transaction (BIP 144).
    MsgWitnessTx = 0x40000001,
    /// Witness block (BIP 144).
    MsgWitnessBlock = 0x40000002,
    /// Witness filtered block.
    MsgWitnessFilteredBlock = 0x40000003,
}

impl InvType {
    /// Convert a u32 to InvType, returning Error for unknown values.
    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => InvType::Error,
            1 => InvType::MsgTx,
            2 => InvType::MsgBlock,
            3 => InvType::MsgFilteredBlock,
            4 => InvType::MsgCmpctBlock,
            0x40000001 => InvType::MsgWitnessTx,
            0x40000002 => InvType::MsgWitnessBlock,
            0x40000003 => InvType::MsgWitnessFilteredBlock,
            _ => InvType::Error,
        }
    }
}

/// An inventory vector (type + hash).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InvVector {
    /// The type of object being referenced.
    pub inv_type: InvType,
    /// The hash of the object.
    pub hash: Hash256,
}

/// A network address without timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetAddress {
    /// Service flags advertised by this node.
    pub services: u64,
    /// IPv6 address (or IPv4-mapped IPv6).
    pub ip: [u8; 16],
    /// Port number (big-endian in wire format).
    pub port: u16,
}

impl NetAddress {
    /// Create a NetAddress from an IPv4 address.
    pub fn from_ipv4(ip: [u8; 4], port: u16, services: u64) -> Self {
        let mut ip6 = [0u8; 16];
        // IPv4-mapped IPv6: ::ffff:x.x.x.x
        ip6[10] = 0xff;
        ip6[11] = 0xff;
        ip6[12..16].copy_from_slice(&ip);
        Self {
            services,
            ip: ip6,
            port,
        }
    }
}

/// A network address with timestamp (used in addr messages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimestampedNetAddress {
    /// Unix timestamp when this address was last seen.
    pub timestamp: u32,
    /// The network address.
    pub address: NetAddress,
}

// Service flags
/// This node can serve the full blockchain.
pub const NODE_NETWORK: u64 = 1;
/// This node supports SegWit (BIP 144).
pub const NODE_WITNESS: u64 = 1 << 3;
/// This node supports compact block filters (BIP 157).
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
/// This node supports limited blockchain serving (last 288 blocks).
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;

/// All P2P network messages.
#[derive(Clone, Debug)]
pub enum NetworkMessage {
    /// Version handshake message.
    Version(VersionMessage),
    /// Version acknowledgement.
    Verack,
    /// Ping with nonce.
    Ping(u64),
    /// Pong response with nonce.
    Pong(u64),
    /// Request headers.
    GetHeaders(GetHeadersMessage),
    /// Block headers response.
    Headers(Vec<BlockHeader>),
    /// Request blocks (deprecated, use getheaders).
    GetBlocks(GetBlocksMessage),
    /// Inventory announcement.
    Inv(Vec<InvVector>),
    /// Request specific objects.
    GetData(Vec<InvVector>),
    /// Full block data.
    Block(Block),
    /// Transaction data.
    Tx(Transaction),
    /// Peer addresses (legacy format).
    Addr(Vec<TimestampedNetAddress>),
    /// Peer addresses (BIP155 format with variable-length addresses).
    AddrV2(Vec<crate::addr::AddrV2Entry>),
    /// Request peer addresses.
    GetAddr,
    /// Objects not found.
    NotFound(Vec<InvVector>),
    /// Transaction or block rejection (deprecated).
    Reject(RejectMessage),
    /// Minimum fee rate filter (BIP 133).
    FeeFilter(u64),
    /// Request headers-first announcements (BIP 130).
    SendHeaders,
    /// Compact block relay (BIP 152).
    SendCmpct(SendCmpctMessage),
    /// Compact block (BIP 152).
    CmpctBlock(Vec<u8>),
    /// Request missing transactions for compact block (BIP 152).
    GetBlockTxn(Vec<u8>),
    /// Missing transactions for compact block (BIP 152).
    BlockTxn(Vec<u8>),
    /// Request mempool contents.
    MemPool,
    /// Announce transactions by wtxid (BIP 339).
    WtxidRelay,
    /// Use addrv2 format (BIP 155).
    SendAddrV2,
    /// Announce tx reconciliation support (BIP 330).
    SendTxRcncl(crate::erlay::SendTxRcncl),
    /// Request reconciliation (BIP 330 Erlay).
    ReqRecon(Vec<u8>),
    /// Sketch data for reconciliation (BIP 330 Erlay).
    Sketch(Vec<u8>),
    /// Report reconciliation differences (BIP 330 Erlay).
    ReconcilDiff(Vec<u8>),
    /// BIP 37 bloom filter: load filter.
    FilterLoad(Vec<u8>),
    /// BIP 37 bloom filter: add element.
    FilterAdd(Vec<u8>),
    /// BIP 37 bloom filter: clear filter (empty payload).
    FilterClear,
    /// BIP 37: filtered block (header + merkle match flags).
    MerkleBlock(Vec<u8>),
    /// BIP 157: request compact block filters.
    GetCFilters(Vec<u8>),
    /// BIP 157: compact block filter.
    CFilter(Vec<u8>),
    /// BIP 157: request compact block filter headers.
    GetCFHeaders(Vec<u8>),
    /// BIP 157: compact block filter headers.
    CFHeaders(Vec<u8>),
    /// BIP 157: request compact block filter checkpoints.
    GetCFCheckpt(Vec<u8>),
    /// BIP 157: compact block filter checkpoints.
    CFCheckpt(Vec<u8>),
    /// Unknown or unsupported message type.
    Unknown { command: String, payload: Vec<u8> },
}

/// Version message for protocol handshake.
#[derive(Clone, Debug)]
pub struct VersionMessage {
    /// Protocol version (e.g., 70016).
    pub version: i32,
    /// Services offered by this node.
    pub services: u64,
    /// Unix timestamp.
    pub timestamp: i64,
    /// Address of receiving node.
    pub addr_recv: NetAddress,
    /// Address of sending node.
    pub addr_from: NetAddress,
    /// Random nonce for self-connection detection.
    pub nonce: u64,
    /// User agent string (BIP 14).
    pub user_agent: String,
    /// Best block height known to sender.
    pub start_height: i32,
    /// Relay transactions (BIP 37).
    pub relay: bool,
}

/// Current protocol version.
pub const PROTOCOL_VERSION: i32 = 70016;
/// Minimum supported peer protocol version.
pub const MIN_PEER_PROTO_VERSION: i32 = 31800;
/// Minimum protocol version for witness support (post-SegWit).
/// We require SegWit support for all connections.
pub const MIN_WITNESS_PROTO_VERSION: i32 = 70015;
/// Protocol version that added wtxidrelay.
pub const WTXID_RELAY_VERSION: i32 = 70016;
/// Protocol version that added sendheaders.
pub const SENDHEADERS_VERSION: i32 = 70012;
/// Protocol version that added feefilter.
pub const FEEFILTER_VERSION: i32 = 70013;
/// Protocol version that added sendcmpct.
pub const SENDCMPCT_VERSION: i32 = 70014;

/// Request headers from a peer.
#[derive(Clone, Debug)]
pub struct GetHeadersMessage {
    /// Protocol version.
    pub version: u32,
    /// Block locator hashes (newest to oldest).
    pub locator_hashes: Vec<Hash256>,
    /// Stop hash (zero to get as many as possible).
    pub hash_stop: Hash256,
}

/// Request blocks from a peer (deprecated).
#[derive(Clone, Debug)]
pub struct GetBlocksMessage {
    /// Protocol version.
    pub version: u32,
    /// Block locator hashes (newest to oldest).
    pub locator_hashes: Vec<Hash256>,
    /// Stop hash (zero to get as many as possible).
    pub hash_stop: Hash256,
}

/// Rejection message (deprecated since protocol version 70002).
#[derive(Clone, Debug)]
pub struct RejectMessage {
    /// The message type being rejected.
    pub message: String,
    /// Rejection code.
    pub code: u8,
    /// Human-readable rejection reason.
    pub reason: String,
    /// Optional extra data (e.g., block/tx hash).
    pub data: Vec<u8>,
}

/// Compact block relay negotiation (BIP 152).
#[derive(Clone, Debug)]
pub struct SendCmpctMessage {
    /// Request high-bandwidth mode.
    pub announce: bool,
    /// Compact block version.
    pub version: u64,
}

impl NetworkMessage {
    /// Get the command name for this message.
    pub fn command(&self) -> &str {
        match self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::AddrV2(_) => "addrv2",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::Reject(_) => "reject",
            NetworkMessage::FeeFilter(_) => "feefilter",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::SendCmpct(_) => "sendcmpct",
            NetworkMessage::CmpctBlock(_) => "cmpctblock",
            NetworkMessage::GetBlockTxn(_) => "getblocktxn",
            NetworkMessage::BlockTxn(_) => "blocktxn",
            NetworkMessage::MemPool => "mempool",
            NetworkMessage::WtxidRelay => "wtxidrelay",
            NetworkMessage::SendAddrV2 => "sendaddrv2",
            NetworkMessage::SendTxRcncl(_) => "sendtxrcncl",
            NetworkMessage::ReqRecon(_) => "reqrecon",
            NetworkMessage::Sketch(_) => "sketch",
            NetworkMessage::ReconcilDiff(_) => "reconcildiff",
            NetworkMessage::FilterLoad(_) => "filterload",
            NetworkMessage::FilterAdd(_) => "filteradd",
            NetworkMessage::FilterClear => "filterclear",
            NetworkMessage::MerkleBlock(_) => "merkleblock",
            NetworkMessage::GetCFilters(_) => "getcfilters",
            NetworkMessage::CFilter(_) => "cfilter",
            NetworkMessage::GetCFHeaders(_) => "getcfheaders",
            NetworkMessage::CFHeaders(_) => "cfheaders",
            NetworkMessage::GetCFCheckpt(_) => "getcfcheckpt",
            NetworkMessage::CFCheckpt(_) => "cfcheckpt",
            NetworkMessage::Unknown { command, .. } => command,
        }
    }

    /// Serialize the message payload (without header).
    pub fn serialize_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            NetworkMessage::Version(v) => {
                buf.extend_from_slice(&v.version.to_le_bytes());
                buf.extend_from_slice(&v.services.to_le_bytes());
                buf.extend_from_slice(&v.timestamp.to_le_bytes());
                serialize_net_address(&mut buf, &v.addr_recv);
                serialize_net_address(&mut buf, &v.addr_from);
                buf.extend_from_slice(&v.nonce.to_le_bytes());
                write_compact_size(&mut buf, v.user_agent.len() as u64).unwrap();
                buf.extend_from_slice(v.user_agent.as_bytes());
                buf.extend_from_slice(&v.start_height.to_le_bytes());
                buf.push(if v.relay { 1 } else { 0 });
            }
            NetworkMessage::Verack => {}
            NetworkMessage::Ping(nonce) => buf.extend_from_slice(&nonce.to_le_bytes()),
            NetworkMessage::Pong(nonce) => buf.extend_from_slice(&nonce.to_le_bytes()),
            NetworkMessage::GetHeaders(msg) => {
                buf.extend_from_slice(&msg.version.to_le_bytes());
                write_compact_size(&mut buf, msg.locator_hashes.len() as u64).unwrap();
                for hash in &msg.locator_hashes {
                    buf.extend_from_slice(hash.as_bytes());
                }
                buf.extend_from_slice(msg.hash_stop.as_bytes());
            }
            NetworkMessage::GetBlocks(msg) => {
                buf.extend_from_slice(&msg.version.to_le_bytes());
                write_compact_size(&mut buf, msg.locator_hashes.len() as u64).unwrap();
                for hash in &msg.locator_hashes {
                    buf.extend_from_slice(hash.as_bytes());
                }
                buf.extend_from_slice(msg.hash_stop.as_bytes());
            }
            NetworkMessage::Headers(headers) => {
                write_compact_size(&mut buf, headers.len() as u64).unwrap();
                for header in headers {
                    header.encode(&mut buf).unwrap();
                    // Headers message includes a tx_count after each header (always 0)
                    write_compact_size(&mut buf, 0).unwrap();
                }
            }
            NetworkMessage::Inv(items)
            | NetworkMessage::GetData(items)
            | NetworkMessage::NotFound(items) => {
                write_compact_size(&mut buf, items.len() as u64).unwrap();
                for item in items {
                    buf.extend_from_slice(&(item.inv_type as u32).to_le_bytes());
                    buf.extend_from_slice(item.hash.as_bytes());
                }
            }
            NetworkMessage::Block(block) => {
                block.encode(&mut buf).unwrap();
            }
            NetworkMessage::Tx(tx) => {
                tx.encode(&mut buf).unwrap();
            }
            NetworkMessage::Addr(addrs) => {
                write_compact_size(&mut buf, addrs.len() as u64).unwrap();
                for addr in addrs {
                    buf.extend_from_slice(&addr.timestamp.to_le_bytes());
                    serialize_net_address(&mut buf, &addr.address);
                }
            }
            NetworkMessage::AddrV2(entries) => {
                buf = crate::addr::serialize_addrv2_message(entries);
            }
            NetworkMessage::GetAddr => {}
            NetworkMessage::FeeFilter(fee_rate) => {
                buf.extend_from_slice(&fee_rate.to_le_bytes());
            }
            NetworkMessage::SendHeaders => {}
            NetworkMessage::SendCmpct(msg) => {
                buf.push(if msg.announce { 1 } else { 0 });
                buf.extend_from_slice(&msg.version.to_le_bytes());
            }
            NetworkMessage::CmpctBlock(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::GetBlockTxn(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::BlockTxn(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::MemPool => {}
            NetworkMessage::WtxidRelay => {}
            NetworkMessage::SendAddrV2 => {}
            NetworkMessage::SendTxRcncl(msg) => {
                buf = msg.serialize();
            }
            NetworkMessage::ReqRecon(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::Sketch(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::ReconcilDiff(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::FilterLoad(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::FilterAdd(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::FilterClear => {}
            NetworkMessage::MerkleBlock(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::GetCFilters(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::CFilter(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::GetCFHeaders(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::CFHeaders(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::GetCFCheckpt(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::CFCheckpt(data) => {
                buf.extend_from_slice(data);
            }
            NetworkMessage::Reject(r) => {
                write_compact_size(&mut buf, r.message.len() as u64).unwrap();
                buf.extend_from_slice(r.message.as_bytes());
                buf.push(r.code);
                write_compact_size(&mut buf, r.reason.len() as u64).unwrap();
                buf.extend_from_slice(r.reason.as_bytes());
                buf.extend_from_slice(&r.data);
            }
            NetworkMessage::Unknown { payload, .. } => {
                buf.extend_from_slice(payload);
            }
        }
        buf
    }

    /// Deserialize a message from its command name and payload bytes.
    pub fn deserialize(command: &str, payload: &[u8]) -> std::io::Result<Self> {
        let mut cursor = Cursor::new(payload);
        match command {
            "version" => {
                let mut buf4 = [0u8; 4];
                let mut buf8 = [0u8; 8];
                cursor.read_exact(&mut buf4)?;
                let version = i32::from_le_bytes(buf4);
                cursor.read_exact(&mut buf8)?;
                let services = u64::from_le_bytes(buf8);
                cursor.read_exact(&mut buf8)?;
                let timestamp = i64::from_le_bytes(buf8);
                let addr_recv = deserialize_net_address(&mut cursor)?;
                let addr_from = deserialize_net_address(&mut cursor)?;
                cursor.read_exact(&mut buf8)?;
                let nonce = u64::from_le_bytes(buf8);
                let ua_len = read_compact_size(&mut cursor)? as usize;
                let mut ua_bytes = vec![0u8; ua_len];
                cursor.read_exact(&mut ua_bytes)?;
                let user_agent = String::from_utf8_lossy(&ua_bytes).into_owned();
                cursor.read_exact(&mut buf4)?;
                let start_height = i32::from_le_bytes(buf4);
                let relay = if cursor.position() < payload.len() as u64 {
                    let mut b = [0u8; 1];
                    cursor.read_exact(&mut b)?;
                    b[0] != 0
                } else {
                    true
                };
                Ok(NetworkMessage::Version(VersionMessage {
                    version,
                    services,
                    timestamp,
                    addr_recv,
                    addr_from,
                    nonce,
                    user_agent,
                    start_height,
                    relay,
                }))
            }
            "verack" => Ok(NetworkMessage::Verack),
            "ping" => {
                let mut buf = [0u8; 8];
                cursor.read_exact(&mut buf)?;
                Ok(NetworkMessage::Ping(u64::from_le_bytes(buf)))
            }
            "pong" => {
                let mut buf = [0u8; 8];
                cursor.read_exact(&mut buf)?;
                Ok(NetworkMessage::Pong(u64::from_le_bytes(buf)))
            }
            "getheaders" => {
                let mut buf4 = [0u8; 4];
                cursor.read_exact(&mut buf4)?;
                let version = u32::from_le_bytes(buf4);
                let count = read_compact_size(&mut cursor)? as usize;
                let mut locator_hashes = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut hash = [0u8; 32];
                    cursor.read_exact(&mut hash)?;
                    locator_hashes.push(Hash256(hash));
                }
                let mut stop = [0u8; 32];
                cursor.read_exact(&mut stop)?;
                Ok(NetworkMessage::GetHeaders(GetHeadersMessage {
                    version,
                    locator_hashes,
                    hash_stop: Hash256(stop),
                }))
            }
            "getblocks" => {
                let mut buf4 = [0u8; 4];
                cursor.read_exact(&mut buf4)?;
                let version = u32::from_le_bytes(buf4);
                let count = read_compact_size(&mut cursor)? as usize;
                let mut locator_hashes = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut hash = [0u8; 32];
                    cursor.read_exact(&mut hash)?;
                    locator_hashes.push(Hash256(hash));
                }
                let mut stop = [0u8; 32];
                cursor.read_exact(&mut stop)?;
                Ok(NetworkMessage::GetBlocks(GetBlocksMessage {
                    version,
                    locator_hashes,
                    hash_stop: Hash256(stop),
                }))
            }
            "headers" => {
                let count = read_compact_size(&mut cursor)? as usize;
                if count > MAX_HEADERS {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "too many headers",
                    ));
                }
                let mut headers = Vec::with_capacity(count);
                for _ in 0..count {
                    let header = BlockHeader::decode(&mut cursor)?;
                    // Read and discard the tx_count (always 0)
                    let _tx_count = read_compact_size(&mut cursor)?;
                    headers.push(header);
                }
                Ok(NetworkMessage::Headers(headers))
            }
            "inv" => {
                let count = read_compact_size(&mut cursor)? as usize;
                if count > MAX_INV_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "too many inv items",
                    ));
                }
                let items = deserialize_inv_vectors(&mut cursor, count)?;
                Ok(NetworkMessage::Inv(items))
            }
            "getdata" => {
                let count = read_compact_size(&mut cursor)? as usize;
                let items = deserialize_inv_vectors(&mut cursor, count)?;
                Ok(NetworkMessage::GetData(items))
            }
            "notfound" => {
                let count = read_compact_size(&mut cursor)? as usize;
                let items = deserialize_inv_vectors(&mut cursor, count)?;
                Ok(NetworkMessage::NotFound(items))
            }
            "block" => {
                let block = Block::decode(&mut cursor)?;
                Ok(NetworkMessage::Block(block))
            }
            "tx" => {
                let tx = Transaction::decode(&mut cursor)?;
                Ok(NetworkMessage::Tx(tx))
            }
            "addr" => {
                let count = read_compact_size(&mut cursor)? as usize;
                if count > MAX_ADDR {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "too many addrs",
                    ));
                }
                let mut addrs = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut buf4 = [0u8; 4];
                    cursor.read_exact(&mut buf4)?;
                    let timestamp = u32::from_le_bytes(buf4);
                    let address = deserialize_net_address(&mut cursor)?;
                    addrs.push(TimestampedNetAddress { timestamp, address });
                }
                Ok(NetworkMessage::Addr(addrs))
            }
            "getaddr" => Ok(NetworkMessage::GetAddr),
            "addrv2" => {
                let entries = crate::addr::deserialize_addrv2_message(payload)?;
                Ok(NetworkMessage::AddrV2(entries))
            }
            "feefilter" => {
                let mut buf = [0u8; 8];
                cursor.read_exact(&mut buf)?;
                Ok(NetworkMessage::FeeFilter(u64::from_le_bytes(buf)))
            }
            "sendheaders" => Ok(NetworkMessage::SendHeaders),
            "sendcmpct" => {
                let mut b = [0u8; 1];
                cursor.read_exact(&mut b)?;
                let mut buf = [0u8; 8];
                cursor.read_exact(&mut buf)?;
                Ok(NetworkMessage::SendCmpct(SendCmpctMessage {
                    announce: b[0] != 0,
                    version: u64::from_le_bytes(buf),
                }))
            }
            "cmpctblock" => Ok(NetworkMessage::CmpctBlock(payload.to_vec())),
            "getblocktxn" => Ok(NetworkMessage::GetBlockTxn(payload.to_vec())),
            "blocktxn" => Ok(NetworkMessage::BlockTxn(payload.to_vec())),
            "mempool" => Ok(NetworkMessage::MemPool),
            "wtxidrelay" => Ok(NetworkMessage::WtxidRelay),
            "sendaddrv2" => Ok(NetworkMessage::SendAddrV2),
            "sendtxrcncl" => {
                let msg = crate::erlay::SendTxRcncl::deserialize(payload)?;
                Ok(NetworkMessage::SendTxRcncl(msg))
            }
            // BIP 330 Erlay reconciliation round-trip messages
            "reqrecon" => Ok(NetworkMessage::ReqRecon(payload.to_vec())),
            "sketch" => Ok(NetworkMessage::Sketch(payload.to_vec())),
            "reconcildiff" => Ok(NetworkMessage::ReconcilDiff(payload.to_vec())),
            // BIP 37 bloom filter messages
            "filterload" => Ok(NetworkMessage::FilterLoad(payload.to_vec())),
            "filteradd" => Ok(NetworkMessage::FilterAdd(payload.to_vec())),
            "filterclear" => Ok(NetworkMessage::FilterClear),
            "merkleblock" => Ok(NetworkMessage::MerkleBlock(payload.to_vec())),
            // BIP 157/158 compact block filter messages
            "getcfilters" => Ok(NetworkMessage::GetCFilters(payload.to_vec())),
            "cfilter" => Ok(NetworkMessage::CFilter(payload.to_vec())),
            "getcfheaders" => Ok(NetworkMessage::GetCFHeaders(payload.to_vec())),
            "cfheaders" => Ok(NetworkMessage::CFHeaders(payload.to_vec())),
            "getcfcheckpt" => Ok(NetworkMessage::GetCFCheckpt(payload.to_vec())),
            "cfcheckpt" => Ok(NetworkMessage::CFCheckpt(payload.to_vec())),
            "reject" => {
                let msg_len = read_compact_size(&mut cursor)? as usize;
                let mut msg_bytes = vec![0u8; msg_len];
                cursor.read_exact(&mut msg_bytes)?;
                let message = String::from_utf8_lossy(&msg_bytes).into_owned();
                let mut code = [0u8; 1];
                cursor.read_exact(&mut code)?;
                let reason_len = read_compact_size(&mut cursor)? as usize;
                let mut reason_bytes = vec![0u8; reason_len];
                cursor.read_exact(&mut reason_bytes)?;
                let reason = String::from_utf8_lossy(&reason_bytes).into_owned();
                // Remaining bytes are extra data
                let pos = cursor.position() as usize;
                let data = payload[pos..].to_vec();
                Ok(NetworkMessage::Reject(RejectMessage {
                    message,
                    code: code[0],
                    reason,
                    data,
                }))
            }
            _ => Ok(NetworkMessage::Unknown {
                command: command.to_string(),
                payload: payload.to_vec(),
            }),
        }
    }
}

/// Serialize a full P2P message with header.
pub fn serialize_message(magic: &[u8; 4], msg: &NetworkMessage) -> Vec<u8> {
    let payload = msg.serialize_payload();
    let checksum = sha256d(&payload);
    let command = msg.command();

    let mut result = Vec::with_capacity(MESSAGE_HEADER_SIZE + payload.len());

    // Magic bytes (4 bytes)
    result.extend_from_slice(magic);

    // Command name (12 bytes, null-padded)
    let mut cmd_bytes = [0u8; 12];
    let cmd_slice = command.as_bytes();
    cmd_bytes[..cmd_slice.len().min(12)].copy_from_slice(&cmd_slice[..cmd_slice.len().min(12)]);
    result.extend_from_slice(&cmd_bytes);

    // Payload length (4 bytes, little-endian)
    result.extend_from_slice(&(payload.len() as u32).to_le_bytes());

    // Checksum (first 4 bytes of SHA256d of payload)
    result.extend_from_slice(&checksum.0[..4]);

    // Payload
    result.extend_from_slice(&payload);

    result
}

/// Parse a message header from 24 bytes.
/// Returns (magic, command, length, checksum).
pub fn parse_message_header(
    data: &[u8; MESSAGE_HEADER_SIZE],
) -> ([u8; 4], String, u32, [u8; 4]) {
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&data[0..4]);

    let command = String::from_utf8_lossy(&data[4..16])
        .trim_end_matches('\0')
        .to_string();

    let length = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&data[20..24]);

    (magic, command, length, checksum)
}

/// Verify a message checksum.
pub fn verify_checksum(payload: &[u8], expected: &[u8; 4]) -> bool {
    let actual = sha256d(payload);
    actual.0[..4] == *expected
}

// Helper functions for NetAddress serialization

fn serialize_net_address(buf: &mut Vec<u8>, addr: &NetAddress) {
    buf.extend_from_slice(&addr.services.to_le_bytes()); // 8 bytes
    buf.extend_from_slice(&addr.ip); // 16 bytes
    buf.extend_from_slice(&addr.port.to_be_bytes()); // 2 bytes big-endian (!)
}

fn deserialize_net_address<R: Read>(reader: &mut R) -> std::io::Result<NetAddress> {
    let mut buf8 = [0u8; 8];
    reader.read_exact(&mut buf8)?;
    let services = u64::from_le_bytes(buf8);

    let mut ip = [0u8; 16];
    reader.read_exact(&mut ip)?;

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf)?;
    let port = u16::from_be_bytes(port_buf); // big-endian (!)

    Ok(NetAddress { services, ip, port })
}

fn deserialize_inv_vectors<R: Read>(reader: &mut R, count: usize) -> std::io::Result<Vec<InvVector>> {
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let mut buf4 = [0u8; 4];
        reader.read_exact(&mut buf4)?;
        let inv_type = InvType::from_u32(u32::from_le_bytes(buf4));

        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;

        items.push(InvVector {
            inv_type,
            hash: Hash256(hash),
        });
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::transaction::{OutPoint, TxIn, TxOut};

    // Testnet4 magic bytes for testing
    const TESTNET4_MAGIC: [u8; 4] = [0x1c, 0x16, 0x3f, 0x28];

    #[test]
    fn version_message_roundtrip() {
        let version = VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK | NODE_WITNESS,
            timestamp: 1234567890,
            addr_recv: NetAddress::from_ipv4([127, 0, 0, 1], 8333, NODE_NETWORK),
            addr_from: NetAddress::from_ipv4([192, 168, 1, 1], 8333, NODE_NETWORK | NODE_WITNESS),
            nonce: 0xDEADBEEF12345678,
            user_agent: "/rustoshi:0.1.0/".to_string(),
            start_height: 750000,
            relay: true,
        };

        let msg = NetworkMessage::Version(version.clone());
        let payload = msg.serialize_payload();
        let decoded = NetworkMessage::deserialize("version", &payload).unwrap();

        if let NetworkMessage::Version(v) = decoded {
            assert_eq!(v.version, version.version);
            assert_eq!(v.services, version.services);
            assert_eq!(v.timestamp, version.timestamp);
            assert_eq!(v.nonce, version.nonce);
            assert_eq!(v.user_agent, version.user_agent);
            assert_eq!(v.start_height, version.start_height);
            assert_eq!(v.relay, version.relay);
            assert_eq!(v.addr_recv, version.addr_recv);
            assert_eq!(v.addr_from, version.addr_from);
        } else {
            panic!("expected Version message");
        }
    }

    #[test]
    fn verack_empty_payload_checksum() {
        let msg = NetworkMessage::Verack;
        let payload = msg.serialize_payload();
        assert!(payload.is_empty());

        // SHA256d of empty = 5df6e0e2...
        let checksum = sha256d(&payload);
        assert_eq!(&checksum.0[..4], &[0x5d, 0xf6, 0xe0, 0xe2]);

        // Full message serialization
        let full = serialize_message(&TESTNET4_MAGIC, &msg);
        assert_eq!(full.len(), MESSAGE_HEADER_SIZE);
        assert_eq!(&full[20..24], &[0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn ping_pong_roundtrip() {
        let nonce: u64 = 0x123456789ABCDEF0;

        let ping = NetworkMessage::Ping(nonce);
        let payload = ping.serialize_payload();
        assert_eq!(payload.len(), 8);

        let decoded = NetworkMessage::deserialize("ping", &payload).unwrap();
        if let NetworkMessage::Ping(n) = decoded {
            assert_eq!(n, nonce);
        } else {
            panic!("expected Ping");
        }

        let pong = NetworkMessage::Pong(nonce);
        let payload = pong.serialize_payload();
        let decoded = NetworkMessage::deserialize("pong", &payload).unwrap();
        if let NetworkMessage::Pong(n) = decoded {
            assert_eq!(n, nonce);
        } else {
            panic!("expected Pong");
        }
    }

    #[test]
    fn headers_message_roundtrip() {
        let headers = vec![
            BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::from_hex(
                    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                )
                .unwrap(),
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            BlockHeader {
                version: 1,
                prev_block_hash: Hash256::from_hex(
                    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                )
                .unwrap(),
                merkle_root: Hash256::ZERO,
                timestamp: 1231469665,
                bits: 0x1d00ffff,
                nonce: 1639830024,
            },
            BlockHeader {
                version: 1,
                prev_block_hash: Hash256::from_hex(
                    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
                )
                .unwrap(),
                merkle_root: Hash256::ZERO,
                timestamp: 1231469744,
                bits: 0x1d00ffff,
                nonce: 1844305925,
            },
        ];

        let msg = NetworkMessage::Headers(headers.clone());
        let payload = msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("headers", &payload).unwrap();
        if let NetworkMessage::Headers(h) = decoded {
            assert_eq!(h.len(), 3);
            assert_eq!(h[0], headers[0]);
            assert_eq!(h[1], headers[1]);
            assert_eq!(h[2], headers[2]);
        } else {
            panic!("expected Headers");
        }
    }

    #[test]
    fn inv_message_with_different_types() {
        let items = vec![
            InvVector {
                inv_type: InvType::MsgTx,
                hash: Hash256::from_hex(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
            },
            InvVector {
                inv_type: InvType::MsgBlock,
                hash: Hash256::from_hex(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
            },
            InvVector {
                inv_type: InvType::MsgWitnessTx,
                hash: Hash256::from_hex(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
            },
        ];

        let msg = NetworkMessage::Inv(items.clone());
        let payload = msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("inv", &payload).unwrap();
        if let NetworkMessage::Inv(inv) = decoded {
            assert_eq!(inv.len(), 3);
            assert_eq!(inv[0].inv_type, InvType::MsgTx);
            assert_eq!(inv[1].inv_type, InvType::MsgBlock);
            assert_eq!(inv[2].inv_type, InvType::MsgWitnessTx);
            assert_eq!(inv[0].hash, items[0].hash);
            assert_eq!(inv[1].hash, items[1].hash);
            assert_eq!(inv[2].hash, items[2].hash);
        } else {
            panic!("expected Inv");
        }
    }

    #[test]
    fn message_header_parsing() {
        let msg = NetworkMessage::Ping(0x1234567890ABCDEF);
        let full = serialize_message(&TESTNET4_MAGIC, &msg);

        let mut header_bytes = [0u8; MESSAGE_HEADER_SIZE];
        header_bytes.copy_from_slice(&full[..MESSAGE_HEADER_SIZE]);

        let (magic, command, length, checksum) = parse_message_header(&header_bytes);

        assert_eq!(magic, TESTNET4_MAGIC);
        assert_eq!(command, "ping");
        assert_eq!(length, 8);

        // Verify checksum
        let payload = &full[MESSAGE_HEADER_SIZE..];
        assert!(verify_checksum(payload, &checksum));
    }

    #[test]
    fn net_address_port_is_big_endian() {
        let addr = NetAddress::from_ipv4([10, 0, 0, 1], 8333, NODE_NETWORK);
        let mut buf = Vec::new();
        serialize_net_address(&mut buf, &addr);

        // Port 8333 = 0x208D
        // Big-endian: 0x20, 0x8D
        // Port is at bytes 24-25 (after 8 bytes services + 16 bytes IP)
        assert_eq!(buf[24], 0x20);
        assert_eq!(buf[25], 0x8D);

        // Verify roundtrip
        let mut cursor = Cursor::new(&buf);
        let decoded = deserialize_net_address(&mut cursor).unwrap();
        assert_eq!(decoded.port, 8333);
    }

    #[test]
    fn ipv4_mapped_ipv6() {
        let addr = NetAddress::from_ipv4([10, 0, 0, 1], 8333, 0);

        // IPv4-mapped IPv6: ::ffff:10.0.0.1
        // [0,0,0,0,0,0,0,0,0,0,0xff,0xff,10,0,0,1]
        assert_eq!(addr.ip[0..10], [0u8; 10]);
        assert_eq!(addr.ip[10], 0xff);
        assert_eq!(addr.ip[11], 0xff);
        assert_eq!(addr.ip[12], 10);
        assert_eq!(addr.ip[13], 0);
        assert_eq!(addr.ip[14], 0);
        assert_eq!(addr.ip[15], 1);
    }

    #[test]
    fn getheaders_message_roundtrip() {
        let msg = GetHeadersMessage {
            version: PROTOCOL_VERSION as u32,
            locator_hashes: vec![
                Hash256::from_hex(
                    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                )
                .unwrap(),
                Hash256::ZERO,
            ],
            hash_stop: Hash256::ZERO,
        };

        let network_msg = NetworkMessage::GetHeaders(msg.clone());
        let payload = network_msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("getheaders", &payload).unwrap();
        if let NetworkMessage::GetHeaders(gh) = decoded {
            assert_eq!(gh.version, msg.version);
            assert_eq!(gh.locator_hashes.len(), 2);
            assert_eq!(gh.locator_hashes[0], msg.locator_hashes[0]);
            assert_eq!(gh.hash_stop, msg.hash_stop);
        } else {
            panic!("expected GetHeaders");
        }
    }

    #[test]
    fn feefilter_roundtrip() {
        let fee_rate: u64 = 1000; // 1000 sat/kvB
        let msg = NetworkMessage::FeeFilter(fee_rate);
        let payload = msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("feefilter", &payload).unwrap();
        if let NetworkMessage::FeeFilter(f) = decoded {
            assert_eq!(f, fee_rate);
        } else {
            panic!("expected FeeFilter");
        }
    }

    #[test]
    fn sendcmpct_roundtrip() {
        let msg = SendCmpctMessage {
            announce: true,
            version: 2,
        };

        let network_msg = NetworkMessage::SendCmpct(msg.clone());
        let payload = network_msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("sendcmpct", &payload).unwrap();
        if let NetworkMessage::SendCmpct(sc) = decoded {
            assert_eq!(sc.announce, msg.announce);
            assert_eq!(sc.version, msg.version);
        } else {
            panic!("expected SendCmpct");
        }
    }

    #[test]
    fn addr_message_roundtrip() {
        let addrs = vec![
            TimestampedNetAddress {
                timestamp: 1700000000,
                address: NetAddress::from_ipv4([192, 168, 1, 1], 8333, NODE_NETWORK),
            },
            TimestampedNetAddress {
                timestamp: 1700000001,
                address: NetAddress::from_ipv4([10, 0, 0, 1], 48333, NODE_NETWORK | NODE_WITNESS),
            },
        ];

        let msg = NetworkMessage::Addr(addrs.clone());
        let payload = msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("addr", &payload).unwrap();
        if let NetworkMessage::Addr(a) = decoded {
            assert_eq!(a.len(), 2);
            assert_eq!(a[0].timestamp, addrs[0].timestamp);
            assert_eq!(a[0].address.port, 8333);
            assert_eq!(a[1].timestamp, addrs[1].timestamp);
            assert_eq!(a[1].address.port, 48333);
        } else {
            panic!("expected Addr");
        }
    }

    #[test]
    fn empty_payload_messages() {
        for (command, expected_msg) in [
            ("verack", NetworkMessage::Verack),
            ("getaddr", NetworkMessage::GetAddr),
            ("sendheaders", NetworkMessage::SendHeaders),
            ("mempool", NetworkMessage::MemPool),
            ("wtxidrelay", NetworkMessage::WtxidRelay),
            ("sendaddrv2", NetworkMessage::SendAddrV2),
        ] {
            let payload = expected_msg.serialize_payload();
            assert!(payload.is_empty(), "{} should have empty payload", command);

            let decoded = NetworkMessage::deserialize(command, &payload).unwrap();
            assert_eq!(decoded.command(), command);
        }
    }

    #[test]
    fn unknown_message_preserved() {
        let command = "foomessage";
        let payload = vec![1, 2, 3, 4, 5];

        let decoded = NetworkMessage::deserialize(command, &payload).unwrap();
        if let NetworkMessage::Unknown { command: c, payload: p } = decoded {
            assert_eq!(c, "foomessage");
            assert_eq!(p, vec![1, 2, 3, 4, 5]);
        } else {
            panic!("expected Unknown");
        }
    }

    #[test]
    fn block_message_roundtrip() {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![0x04, 0xff, 0xff, 0x00, 0x1d],
                    sequence: 0xFFFFFFFF,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x41],
                }],
                lock_time: 0,
            }],
        };

        let msg = NetworkMessage::Block(block.clone());
        let payload = msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("block", &payload).unwrap();
        if let NetworkMessage::Block(b) = decoded {
            assert_eq!(b.header, block.header);
            assert_eq!(b.transactions.len(), 1);
        } else {
            panic!("expected Block");
        }
    }

    #[test]
    fn tx_message_roundtrip() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_hex(
                        "1111111111111111111111111111111111111111111111111111111111111111",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0x30, 0x44], vec![0x02, 0x20]],
            }],
            outputs: vec![TxOut {
                value: 10_000_000,
                script_pubkey: vec![0x00, 0x14],
            }],
            lock_time: 0,
        };

        let msg = NetworkMessage::Tx(tx.clone());
        let payload = msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("tx", &payload).unwrap();
        if let NetworkMessage::Tx(t) = decoded {
            assert_eq!(t.version, tx.version);
            assert!(t.has_witness());
            assert_eq!(t.inputs[0].witness.len(), 2);
        } else {
            panic!("expected Tx");
        }
    }

    #[test]
    fn inv_type_from_u32() {
        assert_eq!(InvType::from_u32(0), InvType::Error);
        assert_eq!(InvType::from_u32(1), InvType::MsgTx);
        assert_eq!(InvType::from_u32(2), InvType::MsgBlock);
        assert_eq!(InvType::from_u32(3), InvType::MsgFilteredBlock);
        assert_eq!(InvType::from_u32(4), InvType::MsgCmpctBlock);
        assert_eq!(InvType::from_u32(0x40000001), InvType::MsgWitnessTx);
        assert_eq!(InvType::from_u32(0x40000002), InvType::MsgWitnessBlock);
        assert_eq!(InvType::from_u32(0x40000003), InvType::MsgWitnessFilteredBlock);
        assert_eq!(InvType::from_u32(999), InvType::Error);
    }

    #[test]
    fn getdata_notfound_roundtrip() {
        let items = vec![
            InvVector {
                inv_type: InvType::MsgWitnessBlock,
                hash: Hash256::from_hex(
                    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                )
                .unwrap(),
            },
        ];

        // Test getdata
        let msg = NetworkMessage::GetData(items.clone());
        let payload = msg.serialize_payload();
        let decoded = NetworkMessage::deserialize("getdata", &payload).unwrap();
        if let NetworkMessage::GetData(gd) = decoded {
            assert_eq!(gd.len(), 1);
            assert_eq!(gd[0].inv_type, InvType::MsgWitnessBlock);
        } else {
            panic!("expected GetData");
        }

        // Test notfound
        let msg = NetworkMessage::NotFound(items.clone());
        let payload = msg.serialize_payload();
        let decoded = NetworkMessage::deserialize("notfound", &payload).unwrap();
        if let NetworkMessage::NotFound(nf) = decoded {
            assert_eq!(nf.len(), 1);
            assert_eq!(nf[0].inv_type, InvType::MsgWitnessBlock);
        } else {
            panic!("expected NotFound");
        }
    }

    #[test]
    fn reject_message_roundtrip() {
        let reject = RejectMessage {
            message: "tx".to_string(),
            code: 0x10, // REJECT_INVALID
            reason: "bad-txns-inputs-missingorspent".to_string(),
            data: vec![0xab; 32], // txid
        };

        let msg = NetworkMessage::Reject(reject.clone());
        let payload = msg.serialize_payload();

        let decoded = NetworkMessage::deserialize("reject", &payload).unwrap();
        if let NetworkMessage::Reject(r) = decoded {
            assert_eq!(r.message, reject.message);
            assert_eq!(r.code, reject.code);
            assert_eq!(r.reason, reject.reason);
            assert_eq!(r.data, reject.data);
        } else {
            panic!("expected Reject");
        }
    }

    #[test]
    fn full_message_with_magic() {
        let msg = NetworkMessage::Verack;
        let full = serialize_message(&TESTNET4_MAGIC, &msg);

        // Total size = 24 bytes header + 0 bytes payload
        assert_eq!(full.len(), 24);

        // Check magic
        assert_eq!(&full[0..4], &TESTNET4_MAGIC);

        // Check command (verack\0\0\0\0\0\0)
        assert_eq!(&full[4..10], b"verack");
        assert_eq!(&full[10..16], &[0, 0, 0, 0, 0, 0]);

        // Check length = 0
        assert_eq!(&full[16..20], &[0, 0, 0, 0]);

        // Check checksum
        assert_eq!(&full[20..24], &[0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn command_name_correct() {
        assert_eq!(NetworkMessage::Version(VersionMessage {
            version: 70016,
            services: 0,
            timestamp: 0,
            addr_recv: NetAddress { services: 0, ip: [0; 16], port: 0 },
            addr_from: NetAddress { services: 0, ip: [0; 16], port: 0 },
            nonce: 0,
            user_agent: String::new(),
            start_height: 0,
            relay: true,
        }).command(), "version");
        assert_eq!(NetworkMessage::Verack.command(), "verack");
        assert_eq!(NetworkMessage::Ping(0).command(), "ping");
        assert_eq!(NetworkMessage::Pong(0).command(), "pong");
        assert_eq!(NetworkMessage::GetHeaders(GetHeadersMessage {
            version: 0,
            locator_hashes: vec![],
            hash_stop: Hash256::ZERO,
        }).command(), "getheaders");
        assert_eq!(NetworkMessage::Headers(vec![]).command(), "headers");
        assert_eq!(NetworkMessage::Inv(vec![]).command(), "inv");
        assert_eq!(NetworkMessage::GetData(vec![]).command(), "getdata");
        assert_eq!(NetworkMessage::GetAddr.command(), "getaddr");
        assert_eq!(NetworkMessage::SendHeaders.command(), "sendheaders");
        assert_eq!(NetworkMessage::MemPool.command(), "mempool");
        assert_eq!(NetworkMessage::WtxidRelay.command(), "wtxidrelay");
    }

    #[test]
    fn version_without_relay_field() {
        // Old version messages didn't have the relay field
        // We should handle this gracefully
        let version = VersionMessage {
            version: 60002,
            services: NODE_NETWORK,
            timestamp: 1234567890,
            addr_recv: NetAddress::from_ipv4([127, 0, 0, 1], 8333, NODE_NETWORK),
            addr_from: NetAddress::from_ipv4([127, 0, 0, 1], 8333, NODE_NETWORK),
            nonce: 12345,
            user_agent: "/test/".to_string(),
            start_height: 100,
            relay: true,
        };

        let msg = NetworkMessage::Version(version);
        let mut payload = msg.serialize_payload();

        // Remove the last byte (relay flag)
        payload.pop();

        // Should still parse, defaulting relay to true
        let decoded = NetworkMessage::deserialize("version", &payload).unwrap();
        if let NetworkMessage::Version(v) = decoded {
            assert_eq!(v.relay, true);
        } else {
            panic!("expected Version");
        }
    }

    #[test]
    fn addrv2_message_roundtrip() {
        use std::net::Ipv4Addr;

        let entries = vec![
            crate::addr::AddrV2Entry {
                timestamp: 1700000000,
                services: 1033,
                addr: crate::addr::NetworkAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                port: 8333,
            },
            crate::addr::AddrV2Entry {
                timestamp: 1700000001,
                services: 1,
                addr: crate::addr::NetworkAddr::TorV3([0x42; 32]),
                port: 9050,
            },
        ];

        let msg = NetworkMessage::AddrV2(entries.clone());
        assert_eq!(msg.command(), "addrv2");

        let payload = msg.serialize_payload();
        let decoded = NetworkMessage::deserialize("addrv2", &payload).unwrap();

        if let NetworkMessage::AddrV2(addrs) = decoded {
            assert_eq!(addrs.len(), 2);
            assert_eq!(addrs[0].timestamp, entries[0].timestamp);
            assert_eq!(addrs[0].port, 8333);
            assert_eq!(addrs[1].timestamp, entries[1].timestamp);
            assert_eq!(addrs[1].port, 9050);
            // Verify TorV3 address
            if let crate::addr::NetworkAddr::TorV3(pubkey) = &addrs[1].addr {
                assert_eq!(pubkey, &[0x42; 32]);
            } else {
                panic!("expected TorV3 address");
            }
        } else {
            panic!("expected AddrV2");
        }
    }

    #[test]
    fn addrv2_with_i2p_and_cjdns() {
        let entries = vec![
            crate::addr::AddrV2Entry {
                timestamp: 1700000000,
                services: 1,
                addr: crate::addr::NetworkAddr::I2P([0xab; 32]),
                port: 4567,
            },
            crate::addr::AddrV2Entry {
                timestamp: 1700000001,
                services: 1,
                addr: crate::addr::NetworkAddr::Cjdns([
                    0xfc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                ]),
                port: 8333,
            },
        ];

        let msg = NetworkMessage::AddrV2(entries);
        let payload = msg.serialize_payload();
        let decoded = NetworkMessage::deserialize("addrv2", &payload).unwrap();

        if let NetworkMessage::AddrV2(addrs) = decoded {
            assert_eq!(addrs.len(), 2);
            // Verify I2P address
            if let crate::addr::NetworkAddr::I2P(hash) = &addrs[0].addr {
                assert_eq!(hash, &[0xab; 32]);
            } else {
                panic!("expected I2P address");
            }
            // Verify CJDNS address
            if let crate::addr::NetworkAddr::Cjdns(addr) = &addrs[1].addr {
                assert_eq!(addr[0], 0xfc);
            } else {
                panic!("expected CJDNS address");
            }
        } else {
            panic!("expected AddrV2");
        }
    }
}
