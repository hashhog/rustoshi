//! Peer manager for maintaining Bitcoin P2P connections.
//!
//! This module implements:
//! - Connection pool management (target 8 outbound + 2 block-relay-only, up to 117 inbound)
//! - DNS seed resolution for initial peer discovery
//! - Address manager for tracking known peers
//! - Peer quality tracking (ban scores, response times, attempt counts)
//! - Misbehavior scoring and ban management
//! - Eclipse attack protections:
//!   - Network group diversity (no two outbound connections in same /16 or /32)
//!   - Anchor connections (persist 2 block-relay-only peers across restarts)
//!   - Inbound eviction protection (protect diverse, high-quality peers)
//!
//! The peer manager coordinates outbound connection attempts, accepts inbound
//! connections, and routes messages between peers and the node's message handler.

use crate::eviction::{select_node_to_evict, EvictionCandidate, EvictionCandidateBuilder};
use crate::message::{
    parse_message_header, serialize_message, NetAddress, NetworkMessage, TimestampedNetAddress,
    VersionMessage, FEEFILTER_VERSION, MAX_ADDR, MAX_MESSAGE_SIZE, MESSAGE_HEADER_SIZE,
    MIN_WITNESS_PROTO_VERSION, NODE_BLOOM, NODE_COMPACT_FILTERS, NODE_NETWORK,
    NODE_NETWORK_LIMITED, NODE_P2P_V2, NODE_WITNESS, PROTOCOL_VERSION, SENDHEADERS_VERSION,
};
use crate::misbehavior::{BanEntry, BanManager, MisbehaviorReason, MisbehaviorTracker};
use crate::netgroup::{ip_is_routable, NetGroup, NetGroupManager};
use crate::peer::{
    bip324_v2_outbound_enabled, run_outbound_peer, run_outbound_peer_with_proxy, DisconnectReason,
    PeerCommand, PeerEvent, PeerId, PeerInfo, PeerState,
};
use crate::proxy::ProxyConfig;
use crate::relay::FeeFilterManager;
use crate::stale_detection::{
    StalePeerDetector, StalePeerState, EXTRA_PEER_CHECK_INTERVAL, MINIMUM_CONNECT_TIME,
};
use crate::v2_transport::{
    constants::{
        ELLSWIFT_PUBKEY_LEN, EXPANSION, GARBAGE_TERMINATOR_LEN, HEADER_LEN, LENGTH_LEN,
        MAX_GARBAGE_LEN, V1_PREFIX_LEN,
    },
    looks_like_v1_version, Bip324Cipher, EllSwiftPubKey,
};
use rustoshi_consensus::{ChainParams, NetworkId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

/// Maximum number of block-relay-only anchor connections to persist.
pub const MAX_BLOCK_RELAY_ONLY_ANCHORS: usize = 2;

/// Whether BIP-157 P2P handlers are registered in the message-dispatch path.
///
/// FIX-71 gate flag (W121 BUG-7 / W99 G22): this is the third precondition for
/// advertising `NODE_COMPACT_FILTERS`. Mirrors Bitcoin Core's implicit
/// invariant that `ProcessGetCFilters` / `ProcessGetCFHeaders` /
/// `ProcessGetCFCheckPt` are always linked into `net_processing.cpp` when the
/// node binary is built (see `bitcoin-core/src/net_processing.cpp` 3315-3460).
///
/// FIX-82 (W121 BUG-7..BUG-13 closure): flipped to `true`. The dispatch
/// handlers now live in `rustoshi/src/main.rs` (event-loop match arms for
/// `NetworkMessage::GetCFilters` / `GetCFHeaders` / `GetCFCheckpt`),
/// invoking `BlockFilterIndex::lookup_filter_range` /
/// `lookup_filter_header_range` / per-checkpoint walks (mirrors Core's
/// `LookupFilterRange` / `LookupFilterHashRange` / `LookupFilterHeader`).
/// Per-violation `peer.disconnect()` mirrors Core's `node.fDisconnect=true`
/// inside `PrepareBlockFilterRequest` (net_processing.cpp:3262-3313).
///
/// The gate function `should_advertise_compact_filters` now OR-s the bit
/// into `local_services()` whenever `-blockfilterindex` and
/// `-peerblockfilters` are both enabled. See `BIP-157` and
/// `bitcoin-core/src/init.cpp:992-999`.
pub const BIP157_P2P_HANDLERS_REGISTERED: bool = true;

/// Decide whether to advertise `NODE_COMPACT_FILTERS` (bit 6, BIP-157) in the
/// outbound version handshake.
///
/// Mirrors Bitcoin Core's `init.cpp:992-999` gate, with one extra precondition
/// (handler-presence) made explicit so this can be wired safely before the
/// dispatch handlers land.
///
/// Returns `true` iff ALL of:
///   (a) `-blockfilterindex` is enabled (`block_filter_index_enabled = true`),
///       AND
///   (b) `-peerblockfilters` is enabled (`peer_block_filters = true`),
///       AND
///   (c) the BIP-157 P2P dispatch handlers are registered
///       (`BIP157_P2P_HANDLERS_REGISTERED = true`).
///
/// All three are required: a node that runs the index but cannot serve
/// requests would announce a service it does not fulfil; a node with
/// handlers but no index would error on every served request. Core enforces
/// (a)+(b) explicitly (init.cpp 994) and (c) is structurally trivial because
/// Core always links the handlers in the same binary; rustoshi must check
/// (c) until the handlers land.
///
/// As of FIX-82 the dispatch handlers are wired (see
/// `BIP157_P2P_HANDLERS_REGISTERED`), so this gate now returns `true`
/// whenever the operator enables both `-blockfilterindex` and
/// `-peerblockfilters` (matching Core's `init.cpp` behavior).
///
/// References:
///   - `bitcoin-core/src/protocol.h:323` — `NODE_COMPACT_FILTERS = (1 << 6)`
///   - `bitcoin-core/src/init.cpp:992-999` — gate computation
///   - BIP-157 — "Service Bits" section
pub fn should_advertise_compact_filters(
    block_filter_index_enabled: bool,
    peer_block_filters: bool,
) -> bool {
    block_filter_index_enabled && peer_block_filters && BIP157_P2P_HANDLERS_REGISTERED
}

/// Filename for anchor peer persistence.
pub const ANCHORS_DATABASE_FILENAME: &str = "anchors.dat";

/// Configuration for the peer manager.
#[derive(Clone, Debug)]
pub struct PeerManagerConfig {
    /// Target number of full-relay outbound connections (default: 8).
    pub max_outbound_full_relay: usize,
    /// Target number of block-relay-only outbound connections (default: 2).
    pub max_outbound_block_relay: usize,
    /// Maximum inbound connections (default: 117).
    pub max_inbound: usize,
    /// Maximum total connections (default: 125).
    pub max_total: usize,
    /// How long to ban misbehaving peers (default: 24h).
    pub ban_duration: Duration,
    /// Port to listen on for inbound connections.
    pub listen_port: u16,
    /// Whether to accept inbound connections.
    pub listen: bool,
    /// Whether to advertise NODE_BLOOM (BIP 37) and serve BIP 35 mempool requests.
    /// Bitcoin Core's `-peerbloomfilters` (default: false; see
    /// `bitcoin-core/src/net_processing.h:44 DEFAULT_PEERBLOOMFILTERS`).
    pub peer_bloom_filters: bool,
    /// Whether prune mode is enabled. When true the node serves only the most
    /// recent ~288 blocks, so it advertises NODE_NETWORK_LIMITED (BIP-159)
    /// *without* NODE_NETWORK. Note that NODE_NETWORK_LIMITED is advertised in
    /// BOTH prune and non-prune mode — Core seeds `g_local_services` with
    /// `NODE_NETWORK_LIMITED | NODE_WITNESS` unconditionally at
    /// `init.cpp:863` and only adds NODE_NETWORK in non-prune mode
    /// (`init.cpp:1950`). What prune mode actually toggles here is whether
    /// NODE_NETWORK is also present (full archive vs. limited).
    pub prune_mode: bool,
    /// Whether the BIP-157/158 BlockFilterIndex is enabled.
    ///
    /// Mirrors Bitcoin Core's `-blockfilterindex=basic` (default: disabled, per
    /// `bitcoin-core/src/index/blockfilterindex.h`). When false the index is
    /// never built and `NODE_COMPACT_FILTERS` MUST NOT be advertised even if
    /// `peer_block_filters` is set.
    ///
    /// FIX-71: this is one input to `should_advertise_compact_filters()`. Even
    /// when this is `true`, the gate keeps the bit unset until BIP-157 P2P
    /// handlers are registered (see `BIP157_P2P_HANDLERS_REGISTERED`).
    pub block_filter_index_enabled: bool,
    /// Whether to advertise NODE_COMPACT_FILTERS (BIP-157) and serve filter
    /// requests from peers.
    ///
    /// Mirrors Bitcoin Core's `-peerblockfilters` (default: disabled, per
    /// `bitcoin-core/src/init.cpp` line 993 `DEFAULT_PEERBLOCKFILTERS`).
    /// Core enforces that `-peerblockfilters` REQUIRES `-blockfilterindex`
    /// (init.cpp 994-996); the same precondition is enforced inside
    /// `should_advertise_compact_filters()`.
    pub peer_block_filters: bool,
    /// Data directory for persistent state (banlist, anchors.dat, etc.).
    pub data_dir: PathBuf,
    /// SOCKS5 proxy address for clearnet (IPv4/IPv6) outbound connections.
    ///
    /// Mirrors Bitcoin Core's `-proxy=<host:port>`. When `Some`, all clearnet
    /// connections go through this proxy. When `None`, clearnet uses direct
    /// `TcpStream::connect`. Tor v3 outbound also falls back to this proxy
    /// when `onion_proxy` is `None`.
    pub tor_proxy: Option<SocketAddr>,
    /// SOCKS5 proxy address dedicated to Tor v3 (.onion) outbound.
    ///
    /// Mirrors Bitcoin Core's `-onion=<host:port>`. When `Some`, takes
    /// precedence over `tor_proxy` for `NetworkAddr::TorV3` dispatch.
    /// When both are `None`, Tor outbound is unreachable.
    pub onion_proxy: Option<SocketAddr>,
    /// I2P SAM 3.1 bridge address for I2P outbound connections.
    ///
    /// Mirrors Bitcoin Core's `-i2psam=<host:port>`. When `Some`, I2P peers
    /// in `known_addrv2` become reachable via `I2pSession::connect`. When
    /// `None`, I2P outbound is unreachable.
    pub i2p_sam: Option<SocketAddr>,
    /// Whether CJDNS addresses are considered reachable.
    ///
    /// Mirrors Bitcoin Core's `-cjdnsreachable`. CJDNS uses native IPv6
    /// routing (fc00::/8 ULA range); enable only when the host actually
    /// has a working CJDNS interface.
    pub cjdns_reachable: bool,
    /// Phase B revalidation-harness offline mode. When true the node makes
    /// NO outbound connections — no anchors, no DNS seeds, no fallback
    /// peers — and (with `listen` false) accepts none. It advances only via
    /// the `submitblock` RPC. Set from `--maxconnections=0`. Mirrors Bitcoin
    /// Core's `-connect=0` + `-dnsseed=0` offline posture; see
    /// CORE-PARITY-AUDIT/_phase-b-revalidation-harness-plan-2026-05-21.md.
    pub offline: bool,
    /// Bitcoin Core `-connect=<ip:port>` (repeatable): pin to ONLY these
    /// peers. When non-empty the peer manager:
    ///   * does NOT resolve DNS seeds,
    ///   * does NOT load/dial anchors,
    ///   * does NOT auto-fill outbound slots from addrman,
    /// and instead dials exactly these addresses (re-dialing any that drop).
    /// Mirrors Core's `-connect` (which implies `-dnsseed=0` and disables
    /// the addrman auto-outbound loop) and clearbit's `connect_address`
    /// branch (peer.zig:7009 skips `dnsSeeds()`; peer.zig:7050 gates the
    /// outbound-fill loop on `connect_address == null`).
    pub connect_peers: Vec<SocketAddr>,
    /// Bitcoin Core `-nodnsseed` / `-dnsseed=0`: suppress DNS-seed
    /// resolution independently of `-connect`. Mirrors clearbit's
    /// `--nodnsseed` setting `dns_seed = false`. (When `connect_peers` is
    /// non-empty DNS seeding is already skipped; this flag is the standalone
    /// knob for the addrman-outbound case.)
    pub no_dns_seed: bool,
    /// Bitcoin Core `-fixedseeds=0`: disable the hardcoded fixed-seed
    /// bootstrap fallback. Default `false` (Core `DEFAULT_FIXEDSEEDS=true`),
    /// so the fallback is enabled out of the box. When `true` the node never
    /// injects `ChainParams::fixed_seeds` even with an empty address book —
    /// mirrors Core's `add_fixed_seeds = gArgs.GetBoolArg("-fixedseeds", ...)`
    /// gate (net.cpp:2568). See `maybe_add_fixed_seeds`.
    pub no_fixed_seeds: bool,
}

impl PeerManagerConfig {
    /// Total maximum outbound connections.
    pub fn max_outbound(&self) -> usize {
        self.max_outbound_full_relay + self.max_outbound_block_relay
    }

    /// Build a `ProxyConfig` from these fields, suitable for passing into
    /// `run_outbound_peer_with_proxy`.
    pub fn build_proxy_config(&self) -> ProxyConfig {
        let mut cfg = ProxyConfig::new();
        if let Some(p) = self.tor_proxy {
            cfg = cfg.with_socks5(p);
        }
        if let Some(p) = self.onion_proxy {
            cfg = cfg.with_onion_proxy(p);
        }
        if let Some(p) = self.i2p_sam {
            // No private-key persistence path here yet; sessions are transient.
            cfg = cfg.with_i2p_sam(p, None);
        }
        // Stream isolation is on by default for Tor when an onion proxy is set
        // (Bitcoin Core default since v0.22 / `proxyrandomize`).
        if self.onion_proxy.is_some() || self.tor_proxy.is_some() {
            cfg = cfg.with_stream_isolation();
        }
        cfg
    }

    /// Whether a given `NetworkAddr` is reachable under this configuration.
    ///
    /// IPv4/IPv6 are always reachable (direct or via `tor_proxy`).
    /// TorV3 is reachable iff `onion_proxy` or `tor_proxy` is set.
    /// I2P is reachable iff `i2p_sam` is set.
    /// CJDNS is reachable iff `cjdns_reachable` is true.
    pub fn is_reachable(&self, addr: &crate::addr::NetworkAddr) -> bool {
        match addr {
            crate::addr::NetworkAddr::Ipv4(_) | crate::addr::NetworkAddr::Ipv6(_) => true,
            crate::addr::NetworkAddr::TorV3(_) => {
                self.onion_proxy.is_some() || self.tor_proxy.is_some()
            }
            crate::addr::NetworkAddr::I2P(_) => self.i2p_sam.is_some(),
            crate::addr::NetworkAddr::Cjdns(_) => self.cjdns_reachable,
        }
    }
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            max_outbound_full_relay: 8,
            max_outbound_block_relay: 2,
            max_inbound: 117,
            max_total: 125,
            ban_duration: Duration::from_secs(24 * 60 * 60),
            listen_port: 8333,
            listen: true,
            peer_bloom_filters: false,
            prune_mode: false,
            block_filter_index_enabled: false,
            peer_block_filters: false,
            data_dir: PathBuf::from("."),
            tor_proxy: None,
            onion_proxy: None,
            i2p_sam: None,
            cjdns_reachable: false,
            offline: false,
            connect_peers: Vec::new(),
            no_dns_seed: false,
            // Core DEFAULT_FIXEDSEEDS = true → fallback enabled by default.
            no_fixed_seeds: false,
        }
    }
}

impl PeerManagerConfig {
    /// Create a config for testnet4.
    pub fn testnet4() -> Self {
        Self {
            listen_port: 48333,
            ..Default::default()
        }
    }

    /// Set the data directory.
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = data_dir;
        self
    }
}

// ============================================================
// ADDRESS MANAGER
// ============================================================

/// Source of a peer address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrSource {
    /// From DNS seed resolution.
    Dns,
    /// From an addr message from another peer.
    Peer(SocketAddr),
    /// Manually added (e.g., command line).
    Manual,
}

/// Feeler connection interval (Core net.h:61 FEELER_INTERVAL = 2min). Every
/// `FEELER_INTERVAL` the connection-open loop opens ONE short-lived feeler to a
/// NEW-table address, handshakes, promotes it NEW->TRIED, and disconnects.
pub const FEELER_INTERVAL: Duration = Duration::from_secs(120);

/// Maximum number of simultaneous feeler connections (Core net.h:75
/// MAX_FEELER_CONNECTIONS = 1).
pub const MAX_FEELER_CONNECTIONS: usize = 1;

/// Percentage of the addrman shared in a getaddr response (Core
/// MAX_PCT_ADDR_TO_SEND = 23, net_processing.cpp:188). The getaddr response is
/// capped at min(MAX_ADDR_TO_SEND, floor(23 * addrman_size / 100)) — primary
/// getaddr anti-DoS. Note: integer FLOOR, matching Core's `GetAddr_`.
pub const MAX_PCT_ADDR_TO_SEND: usize = 23;

/// Token-bucket constants for INBOUND addr rate-limiting (Core
/// net_processing.cpp:193-197). The bucket refills at MAX_ADDR_RATE_PER_SECOND
/// tokens/sec, capped at MAX_ADDR_PROCESSING_TOKEN_BUCKET; each processed
/// address costs one token, and addresses are dropped once the bucket runs dry.
pub const MAX_ADDR_RATE_PER_SECOND: f64 = 0.1;
/// Soft cap on the inbound-addr token bucket (Core MAX_ADDR_PROCESSING_TOKEN_BUCKET
/// = MAX_ADDR_TO_SEND = 1000).
pub const MAX_ADDR_PROCESSING_TOKEN_BUCKET: f64 = 1000.0;

/// Compute the getaddr 23%-cap over an addrman of `size` entries: the number of
/// addresses we are willing to return in a single getaddr response, i.e.
/// min(MAX_ADDR, floor(23 * size / 100)). Mirrors Core's `GetAddr_` cap
/// EXACTLY (addrman.cpp:799-805: `nNodes = max_pct * nNodes / 100`, integer
/// division = floor, then `nNodes = std::min(nNodes, max_addresses)`).
///
/// Integer FLOOR — NOT ceil, and NO `.max(1)` clamp: Core returns 0 when the
/// floor is 0 (e.g. size < 5 -> 23*size/100 == 0 -> share nothing). Rounding up
/// or forcing a minimum of 1 over-shares relative to Core and breaks the
/// anti-DoS contract on a small addrman.
pub fn getaddr_cap(size: usize) -> usize {
    // nNodes = max_pct * nNodes / 100  (integer floor, addrman.cpp:805)
    let n_nodes = size.saturating_mul(MAX_PCT_ADDR_TO_SEND) / 100;
    // nNodes = std::min(nNodes, max_addresses)  (max_addresses = MAX_ADDR)
    n_nodes.min(MAX_ADDR)
}

/// Current wall-clock time as unix seconds. Used to stamp the `time` of
/// addresses learned without an explicit timestamp (DNS seeds, manual peers).
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Clamp a peer-advertised address timestamp before storing it in the address
/// manager.  Mirrors Bitcoin Core `net_processing.cpp:5678-5680`:
///
/// ```cpp
/// if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_time + 10min)
///     addr.nTime = current_time - 5 * 24h;
/// ```
///
/// - Timestamps at or before 100 000 000 (pre-2001-03-09) are obviously bogus.
/// - Timestamps more than 10 minutes in the future are likely clock-drift or
///   manipulation.
/// Both cases are clamped to `now - 5 days` so the address stays discoverable
/// but ranks below freshly-seen peers in addrman selection.
pub(crate) fn clamp_addr_timestamp(ts: u32, now: u64) -> u64 {
    const STALE_THRESHOLD: u64 = 100_000_000; // <= this means pre-2001
    const FUTURE_TOLERANCE_SECS: u64 = 10 * 60; // 10 minutes
    const PENALTY_SECS: u64 = 5 * 24 * 60 * 60; // 5 days

    let ts64 = ts as u64;
    if ts64 <= STALE_THRESHOLD || ts64 > now.saturating_add(FUTURE_TOLERANCE_SECS) {
        now.saturating_sub(PENALTY_SECS)
    } else {
        ts64
    }
}

/// One row of the addrman dump returned by the `getnodeaddresses` RPC.
///
/// Mirrors the per-address object Bitcoin Core emits (rpc/net.cpp:958-965):
/// the raw `time`/`services`/`port` integers, the bare `address` literal
/// (no port), and the Core network-class string (`GetNetworkName`).
#[derive(Debug, Clone)]
pub struct NodeAddressEntry {
    /// Last-seen unix timestamp in seconds.
    pub time: u64,
    /// Raw services bitfield (emitted as an integer, not hex).
    pub services: u64,
    /// The address literal without the port (ip / `.onion` / `.b32.i2p`).
    pub address: String,
    /// The port number.
    pub port: u16,
    /// Core network-class string: ipv4 / ipv6 / onion / i2p / cjdns /
    /// not_publicly_routable / internal.
    pub network: String,
}

// ============================================================
// CORE-BUCKETED ADDRMAN (vvNew / vvTried)
//
// A faithful port of Bitcoin Core's CAddrMan (bitcoin-core/src/addrman.cpp +
// addrman_impl.h): two id-indexed bucket tables (NEW[1024][64] + TRIED[256][64])
// keyed off one per-manager 256-bit salt `nkey`, with the deterministic
// GetNewBucket / GetTriedBucket / GetBucketPosition placement, Add/Good/Select,
// IsTerrible eviction, and a versioned, corrupt-safe, bounded peers.dat-equiv.
//
// This is wired UNDER the existing public AddressManager API (add_*, mark_*,
// next_addr_to_try, get_addr_for_sharing) so the rest of the node is
// unaffected. The legacy `known_addrs` flat map is retained for the rich
// getnodeaddresses / addr-sharing metadata; the bucket table is the placement
// + anti-Sybil engine + persistence.
//
// NOTE: the cheap hash here is impl-internal (single SHA-256 truncated to the
// low 8 bytes, little-endian). peers.dat is a LOCAL file (never wire/RPC), so
// byte-identical Core bucket numbers are not required and not claimed; the
// golden test pins THIS impl's chosen hash.
// ============================================================

/// Number of new-address buckets (Core ADDRMAN_NEW_BUCKET_COUNT = 1 << 10).
pub const ADDRMAN_NEW_BUCKET_COUNT: usize = 1024;
/// Number of tried-address buckets (Core ADDRMAN_TRIED_BUCKET_COUNT = 1 << 8).
pub const ADDRMAN_TRIED_BUCKET_COUNT: usize = 256;
/// Positions per bucket (Core ADDRMAN_BUCKET_SIZE = 1 << 6).
pub const ADDRMAN_BUCKET_SIZE: usize = 64;
/// New buckets a single source group can reach (Core
/// ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP). Anti-Sybil cap.
pub const ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 64;
/// Tried buckets a single addr group can reach (Core
/// ADDRMAN_TRIED_BUCKETS_PER_GROUP). Anti-Sybil cap.
pub const ADDRMAN_TRIED_BUCKETS_PER_GROUP: u64 = 8;
/// Max new buckets one address may simultaneously occupy (Core
/// ADDRMAN_NEW_BUCKETS_PER_ADDRESS).
pub const ADDRMAN_NEW_BUCKETS_PER_ADDRESS: u32 = 8;
/// Addresses not seen in this long are terrible (Core ADDRMAN_HORIZON = 30 d).
pub const ADDRMAN_HORIZON_SECS: u64 = 30 * 24 * 60 * 60;
/// Tries after which a never-successful address is terrible (Core
/// ADDRMAN_RETRIES).
pub const ADDRMAN_RETRIES: u32 = 3;
/// Failed-attempt count after which a long-failing address is terrible (Core
/// ADDRMAN_MAX_FAILURES).
pub const ADDRMAN_MAX_FAILURES: u32 = 10;
/// Minimum time since last success before MAX_FAILURES applies (Core
/// ADDRMAN_MIN_FAIL = 7 d).
pub const ADDRMAN_MIN_FAIL_SECS: u64 = 7 * 24 * 60 * 60;

/// Hard slot ceiling: every id occupies at most one slot per table, and no
/// table can grow past its fixed bucket geometry. This is the bounded ceiling.
pub const ADDRMAN_CEILING: usize = ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE
    + ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE;

/// On-disk format version for the peers.dat-equiv. Bumping invalidates older
/// files (they load as an empty cold start, never a hard-down).
pub const ADDRMAN_DAT_VERSION: u32 = 1;
/// Filename for the bucketed addrman persistence (peers.dat-equiv).
pub const PEERS_DATABASE_FILENAME: &str = "peers.dat";

/// Integer node id (Core nid_type). `-1` is the empty-slot sentinel.
type NId = i64;

/// One address record held by the bucketed addrman. Mirrors Core AddrInfo's
/// bookkeeping fields (refcount, in_tried, attempt/success/seen times).
#[derive(Debug, Clone)]
pub struct AddrManEntry {
    /// The socket address (IPv4/IPv6 only in this pilot).
    pub addr: SocketAddr,
    /// Services bitfield.
    pub services: u64,
    /// Where we first heard about it (the source, for new-bucket grouping).
    pub source: IpAddr,
    /// Last-seen unix timestamp (seconds).
    pub time_unix: u64,
    /// Last-success unix timestamp (0 = never).
    pub last_success_unix: u64,
    /// Last-try unix timestamp (0 = never).
    pub last_try_unix: u64,
    /// Consecutive connection attempts.
    pub attempts: u32,
    /// How many new buckets reference this id (Core nRefCount). 0 once in tried.
    pub ref_count: u32,
    /// Whether this id currently lives in the tried table.
    pub in_tried: bool,
}

impl AddrManEntry {
    /// Core IsTerrible: should this entry be eviction-preferred? Ports the five
    /// Core conditions (addrman.cpp:49-72) using `now` as unix seconds.
    fn is_terrible(&self, now: u64) -> bool {
        // never remove things tried in the last minute
        if self.last_try_unix != 0 && now.saturating_sub(self.last_try_unix) <= 60 {
            return false;
        }
        // came in a flying DeLorean
        if self.time_unix > now + 10 * 60 {
            return true;
        }
        // not seen in recent history
        if now.saturating_sub(self.time_unix) > ADDRMAN_HORIZON_SECS {
            return true;
        }
        // tried N times and never a success
        if self.last_success_unix == 0 && self.attempts >= ADDRMAN_RETRIES {
            return true;
        }
        // N successive failures in the last week
        if self.last_success_unix != 0
            && now.saturating_sub(self.last_success_unix) > ADDRMAN_MIN_FAIL_SECS
            && self.attempts >= ADDRMAN_MAX_FAILURES
        {
            return true;
        }
        false
    }
}

/// Core-bucketed address manager: the NEW/TRIED tables + id maps + salt.
///
/// Heap-allocates the bucket tables (each is ~512 KB of i64) to avoid a
/// stack-overflow at construct (Core stores them in std::array members behind
/// the heap-allocated AddrManImpl).
#[derive(Debug)]
pub struct AddrManTable {
    /// 256-bit per-manager salt (Core nKey). Persisted; drives all placement.
    nkey: [u8; 32],
    /// NEW table: vv_new[bucket][pos] = id (or -1). Heap-boxed.
    vv_new: Box<[[NId; ADDRMAN_BUCKET_SIZE]]>,
    /// TRIED table: vv_tried[bucket][pos] = id (or -1). Heap-boxed.
    vv_tried: Box<[[NId; ADDRMAN_BUCKET_SIZE]]>,
    /// id -> entry (Core mapInfo).
    map_info: HashMap<NId, AddrManEntry>,
    /// addr -> id (Core mapAddr).
    map_addr: HashMap<SocketAddr, NId>,
    /// Next id to allocate (Core nIdCount).
    id_count: NId,
    /// Count of ids in the new table (Core nNew).
    n_new: usize,
    /// Count of ids in the tried table (Core nTried).
    n_tried: usize,
}

impl AddrManTable {
    /// Create an empty table with a random salt.
    pub fn new() -> Self {
        Self::with_nkey(rand::random())
    }

    /// Create an empty table with a fixed salt (deterministic; for tests +
    /// persistence restore).
    pub fn with_nkey(nkey: [u8; 32]) -> Self {
        Self {
            nkey,
            vv_new: vec![[-1; ADDRMAN_BUCKET_SIZE]; ADDRMAN_NEW_BUCKET_COUNT].into_boxed_slice(),
            vv_tried: vec![[-1; ADDRMAN_BUCKET_SIZE]; ADDRMAN_TRIED_BUCKET_COUNT]
                .into_boxed_slice(),
            map_info: HashMap::new(),
            map_addr: HashMap::new(),
            id_count: 0,
            n_new: 0,
            n_tried: 0,
        }
    }

    /// Number of addresses currently held (NEW + TRIED). Used by the task #12
    /// persistence test and as a cheap health/inspection counter.
    pub fn len(&self) -> usize {
        self.map_info.len()
    }

    /// True when the table holds no addresses.
    pub fn is_empty(&self) -> bool {
        self.map_info.is_empty()
    }

    /// Cheap hash (Core HashWriter::GetCheapHash analogue): single SHA-256 of
    /// the concatenated parts, low 8 bytes interpreted little-endian.
    fn cheap_hash(parts: &[&[u8]]) -> u64 {
        let mut buf: Vec<u8> = Vec::new();
        for p in parts {
            buf.extend_from_slice(p);
        }
        let h = rustoshi_crypto::sha256(&buf);
        u64::from_le_bytes(h[0..8].try_into().expect("sha256 yields >= 8 bytes"))
    }

    /// Stable key bytes for an address (Core CService::GetKey analogue):
    /// 16-byte IPv6 representation + 2-byte big-endian port.
    fn addr_key(addr: &SocketAddr) -> Vec<u8> {
        let mut v = Vec::with_capacity(18);
        let octets: [u8; 16] = match addr.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        v.extend_from_slice(&octets);
        v.extend_from_slice(&addr.port().to_be_bytes());
        v
    }

    /// Core AddrInfo::GetNewBucket. `src_group` / `addr_group` are the
    /// NetGroupManager group bytes for the address and its source.
    fn get_new_bucket(&self, addr_group: &[u8], src_group: &[u8]) -> usize {
        let hash1 = Self::cheap_hash(&[&self.nkey, addr_group, src_group]);
        let hash2 = Self::cheap_hash(&[
            &self.nkey,
            src_group,
            &(hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP).to_le_bytes(),
        ]);
        (hash2 % ADDRMAN_NEW_BUCKET_COUNT as u64) as usize
    }

    /// Core AddrInfo::GetTriedBucket. `addr_group` is the address's group bytes.
    fn get_tried_bucket(&self, addr: &SocketAddr, addr_group: &[u8]) -> usize {
        let hash1 = Self::cheap_hash(&[&self.nkey, &Self::addr_key(addr)]);
        let hash2 = Self::cheap_hash(&[
            &self.nkey,
            addr_group,
            &(hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP).to_le_bytes(),
        ]);
        (hash2 % ADDRMAN_TRIED_BUCKET_COUNT as u64) as usize
    }

    /// Core AddrInfo::GetBucketPosition.
    fn get_bucket_position(&self, f_new: bool, bucket: usize, addr: &SocketAddr) -> usize {
        let tag: [u8; 1] = [if f_new { b'N' } else { b'K' }];
        let hash1 = Self::cheap_hash(&[
            &self.nkey,
            &tag,
            &(bucket as u32).to_le_bytes(),
            &Self::addr_key(addr),
        ]);
        (hash1 % ADDRMAN_BUCKET_SIZE as u64) as usize
    }

    /// Look up the id for an address (Core Find).
    fn find(&self, addr: &SocketAddr) -> Option<NId> {
        self.map_addr.get(addr).copied()
    }

    /// Allocate a fresh entry (Core Create).
    fn create(&mut self, addr: SocketAddr, source: IpAddr, services: u64, time_unix: u64) -> NId {
        let id = self.id_count;
        self.id_count += 1;
        self.map_info.insert(
            id,
            AddrManEntry {
                addr,
                services,
                source,
                time_unix,
                last_success_unix: 0,
                last_try_unix: 0,
                attempts: 0,
                ref_count: 0,
                in_tried: false,
            },
        );
        self.map_addr.insert(addr, id);
        id
    }

    /// Delete a refcount-0, non-tried id entirely (Core Delete).
    fn delete(&mut self, id: NId) {
        if let Some(info) = self.map_info.get(&id) {
            if info.ref_count == 0 && !info.in_tried {
                let a = info.addr;
                self.map_addr.remove(&a);
                self.map_info.remove(&id);
            }
        }
    }

    /// Clear a new-table slot, decrementing the occupant refcount and deleting
    /// at 0 (Core ClearNew).
    fn clear_new(&mut self, bucket: usize, pos: usize) {
        let id = self.vv_new[bucket][pos];
        if id != -1 {
            if let Some(info) = self.map_info.get_mut(&id) {
                if info.ref_count > 0 {
                    info.ref_count -= 1;
                }
                let rc = info.ref_count;
                self.vv_new[bucket][pos] = -1;
                if rc == 0 {
                    self.n_new = self.n_new.saturating_sub(1);
                    self.delete(id);
                }
            } else {
                self.vv_new[bucket][pos] = -1;
            }
        }
    }

    /// The addr/src group bytes for an id, computed via the netgroup manager.
    fn groups(info: &AddrManEntry, ng: &NetGroupManager) -> (Vec<u8>, Vec<u8>) {
        let addr_group = ng.get_group(&info.addr.ip()).as_bytes().to_vec();
        let src_group = ng.get_group(&info.source).as_bytes().to_vec();
        (addr_group, src_group)
    }

    /// Core Add_/AddSingle: place a heard-about address in the NEW table.
    /// Returns true if a fresh slot insertion occurred. Non-routable addrs and
    /// the bounded-ceiling guard cause a `false` return.
    pub fn add(
        &mut self,
        addr: SocketAddr,
        source: IpAddr,
        services: u64,
        time_unix: u64,
        ng: &NetGroupManager,
    ) -> bool {
        if !ng.is_routable(&addr.ip()) {
            return false;
        }
        let now = now_unix_secs();

        let existing = self.find(&addr);
        let id = match existing {
            Some(id) => {
                // Refresh existing (Core AddSingle update path).
                if let Some(info) = self.map_info.get_mut(&id) {
                    if time_unix > info.time_unix {
                        info.time_unix = time_unix;
                    }
                    info.services |= services;
                    if info.in_tried {
                        return false;
                    }
                    if info.ref_count >= ADDRMAN_NEW_BUCKETS_PER_ADDRESS {
                        return false;
                    }
                    // stochastic multiplicity gate: 2^refcount harder each time.
                    if info.ref_count > 0 {
                        let factor = 1u32 << info.ref_count;
                        if rand::random::<u32>() % factor != 0 {
                            return false;
                        }
                    }
                }
                id
            }
            None => {
                // Bounded-ceiling guard: never allocate past the table capacity.
                if self.map_info.len() >= ADDRMAN_CEILING {
                    return false;
                }
                self.create(addr, source, services, time_unix)
            }
        };

        // Compute the placement.
        let (addr_group, src_group) = {
            let info = self.map_info.get(&id).expect("id just created/found");
            Self::groups(info, ng)
        };
        let bucket = self.get_new_bucket(&addr_group, &src_group);
        let pos = self.get_bucket_position(true, bucket, &addr);

        let occupant = self.vv_new[bucket][pos];
        let mut insert = occupant == -1;
        if occupant != id {
            if !insert {
                // Collision: overwrite iff occupant terrible, or occupant
                // multiply-referenced while the newcomer is fresh (Core rule).
                let occ_terrible_or_evictable = self
                    .map_info
                    .get(&occupant)
                    .map(|o| {
                        o.is_terrible(now)
                            || (o.ref_count > 1
                                && self.map_info.get(&id).map(|n| n.ref_count).unwrap_or(0) == 0)
                    })
                    .unwrap_or(true);
                insert = occ_terrible_or_evictable;
            }
            if insert {
                self.clear_new(bucket, pos);
                if let Some(info) = self.map_info.get_mut(&id) {
                    info.ref_count += 1;
                }
                self.vv_new[bucket][pos] = id;
                self.n_new += 1;
            } else if self.map_info.get(&id).map(|i| i.ref_count).unwrap_or(0) == 0 {
                // newly-created but not inserted -> drop it.
                self.delete(id);
            }
        }
        insert
    }

    /// Core Good_/MakeTried: promote an address from NEW to TRIED, evicting the
    /// existing tried occupant back to its NEW bucket on collision.
    pub fn good(&mut self, addr: &SocketAddr, now: u64, ng: &NetGroupManager) -> bool {
        let id = match self.find(addr) {
            Some(id) => id,
            None => return false,
        };
        // Update try/success bookkeeping (Core Good_).
        if let Some(info) = self.map_info.get_mut(&id) {
            info.last_success_unix = now;
            info.last_try_unix = now;
            info.attempts = 0;
            if info.in_tried {
                return false;
            }
            if info.ref_count == 0 {
                return false;
            }
        }

        // Remove the id from ALL its new buckets (Core MakeTried loop).
        let positions: Vec<(usize, usize)> = {
            let info = self.map_info.get(&id).expect("id present");
            let (addr_group, src_group) = Self::groups(info, ng);
            let start = self.get_new_bucket(&addr_group, &src_group);
            (0..ADDRMAN_NEW_BUCKET_COUNT)
                .map(|n| {
                    let b = (start + n) % ADDRMAN_NEW_BUCKET_COUNT;
                    let p = self.get_bucket_position(true, b, addr);
                    (b, p)
                })
                .collect()
        };
        for (b, p) in positions {
            if self.vv_new[b][p] == id {
                self.vv_new[b][p] = -1;
                if let Some(info) = self.map_info.get_mut(&id) {
                    if info.ref_count > 0 {
                        info.ref_count -= 1;
                    }
                    if info.ref_count == 0 {
                        break;
                    }
                }
            }
        }
        self.n_new = self.n_new.saturating_sub(1);
        if let Some(info) = self.map_info.get_mut(&id) {
            info.ref_count = 0;
        }

        // Compute the tried slot.
        let (k_bucket, k_pos) = {
            let info = self.map_info.get(&id).expect("id present");
            let (addr_group, _src) = Self::groups(info, ng);
            let kb = self.get_tried_bucket(addr, &addr_group);
            let kp = self.get_bucket_position(false, kb, addr);
            (kb, kp)
        };

        // On collision evict the existing tried occupant back to NEW.
        let evict = self.vv_tried[k_bucket][k_pos];
        if evict != -1 {
            // Pull it out of tried.
            self.vv_tried[k_bucket][k_pos] = -1;
            self.n_tried = self.n_tried.saturating_sub(1);
            if let Some(old) = self.map_info.get_mut(&evict) {
                old.in_tried = false;
            }
            // Recompute its new slot and place it back.
            let (ob, op) = {
                let old = self.map_info.get(&evict).expect("evict present");
                let (ag, sg) = Self::groups(old, ng);
                let b = self.get_new_bucket(&ag, &sg);
                let p = self.get_bucket_position(true, b, &old.addr);
                (b, p)
            };
            self.clear_new(ob, op);
            if let Some(old) = self.map_info.get_mut(&evict) {
                old.ref_count = 1;
            }
            self.vv_new[ob][op] = evict;
            self.n_new += 1;
        }

        // Place the promoted id into tried.
        self.vv_tried[k_bucket][k_pos] = id;
        self.n_tried += 1;
        if let Some(info) = self.map_info.get_mut(&id) {
            info.in_tried = true;
        }
        true
    }

    /// Core Attempt_: record a (possibly-failed) connection attempt.
    pub fn attempt(&mut self, addr: &SocketAddr, now: u64) {
        if let Some(&id) = self.map_addr.get(addr) {
            if let Some(info) = self.map_info.get_mut(&id) {
                info.last_try_unix = now;
                info.attempts += 1;
            }
        }
    }

    /// Core Select_ (simplified): 50/50 new-vs-tried when both are non-empty,
    /// then scan a random bucket from a random position and return the first
    /// occupant. Returns the chosen address.
    ///
    /// NOTE: the GetChance() * 1.2^miss probability bias is a named follow-up;
    /// this lands plain random-scan selection, which is bounded, deterministic
    /// per-RNG-draw, and faithful to the bucket geometry.
    pub fn select(&self, new_only: bool) -> Option<SocketAddr> {
        if self.map_info.is_empty() {
            return None;
        }
        if new_only && self.n_new == 0 {
            return None;
        }
        if self.n_new + self.n_tried == 0 {
            return None;
        }

        let mut rng = rand::thread_rng();
        use rand::Rng;

        let search_tried = if new_only || self.n_tried == 0 {
            false
        } else if self.n_new == 0 {
            true
        } else {
            rng.gen_bool(0.5)
        };

        let (table, bucket_count): (&Box<[[NId; ADDRMAN_BUCKET_SIZE]]>, usize) = if search_tried {
            (&self.vv_tried, ADDRMAN_TRIED_BUCKET_COUNT)
        } else {
            (&self.vv_new, ADDRMAN_NEW_BUCKET_COUNT)
        };

        // Pick a random starting bucket + position for selection bias, then
        // walk deterministically (wrapping) through every bucket. This is
        // bounded (at most bucket_count * BUCKET_SIZE slots) AND guaranteed to
        // return an occupant whenever one exists, unlike a pure rejection-
        // sample loop which can starve on a sparse table. Core's Select_ loops
        // forever on random buckets until it hits a non-empty one; this is the
        // bounded, liveness-safe analogue. (GetChance()*1.2^miss probability
        // bias is a named follow-up.)
        let start_bucket = rng.gen_range(0..bucket_count);
        let initial_pos = rng.gen_range(0..ADDRMAN_BUCKET_SIZE);
        for nb in 0..bucket_count {
            let bucket = (start_bucket + nb) % bucket_count;
            for i in 0..ADDRMAN_BUCKET_SIZE {
                let pos = (initial_pos + i) % ADDRMAN_BUCKET_SIZE;
                let id = table[bucket][pos];
                if id != -1 {
                    if let Some(info) = self.map_info.get(&id) {
                        return Some(info.addr);
                    }
                }
            }
        }
        None
    }

    /// Number of addresses currently in the NEW table.
    pub fn new_count(&self) -> usize {
        self.n_new
    }

    /// Number of addresses currently in the TRIED table.
    pub fn tried_count(&self) -> usize {
        self.n_tried
    }

    /// Total distinct ids tracked (bounded by ADDRMAN_CEILING).
    pub fn total_count(&self) -> usize {
        self.map_info.len()
    }

    /// Whether `addr` is in the TRIED table (test/inspection helper).
    pub fn is_in_tried(&self, addr: &SocketAddr) -> bool {
        self.map_addr
            .get(addr)
            .and_then(|id| self.map_info.get(id))
            .map(|i| i.in_tried)
            .unwrap_or(false)
    }

    /// Recompute the (bucket, pos) an address currently occupies in NEW (for
    /// determinism tests). Returns None if not in NEW.
    pub fn new_slot_of(&self, addr: &SocketAddr, ng: &NetGroupManager) -> Option<(usize, usize)> {
        let id = *self.map_addr.get(addr)?;
        let info = self.map_info.get(&id)?;
        if info.in_tried {
            return None;
        }
        let (ag, sg) = Self::groups(info, ng);
        let start = self.get_new_bucket(&ag, &sg);
        for n in 0..ADDRMAN_NEW_BUCKET_COUNT {
            let b = (start + n) % ADDRMAN_NEW_BUCKET_COUNT;
            let p = self.get_bucket_position(true, b, addr);
            if self.vv_new[b][p] == id {
                return Some((b, p));
            }
        }
        None
    }

    /// The (bucket, pos) an address occupies in TRIED. None if not in TRIED.
    pub fn tried_slot_of(&self, addr: &SocketAddr, ng: &NetGroupManager) -> Option<(usize, usize)> {
        let id = *self.map_addr.get(addr)?;
        let info = self.map_info.get(&id)?;
        if !info.in_tried {
            return None;
        }
        let (ag, _sg) = Self::groups(info, ng);
        let kb = self.get_tried_bucket(addr, &ag);
        let kp = self.get_bucket_position(false, kb, addr);
        Some((kb, kp))
    }

    /// The nkey salt bytes (test/persistence helper).
    pub fn nkey(&self) -> [u8; 32] {
        self.nkey
    }

    // --- Persistence (peers.dat-equiv) -------------------------------------

    /// Serialize to a versioned, line-oriented text format. Atomic-write is
    /// handled by `save`. Format:
    ///   line 0: "ADDRMAN <version> <nkey-hex>"
    ///   then one record per id:
    ///     "<n|t> <addr> <services> <source-ip> <time> <last_success> <last_try> <attempts> <ref_count>"
    /// New records carry their explicit (bucket,pos) restored on load via add();
    /// tried records are re-promoted via good() so placement is recomputed
    /// deterministically from the same nkey.
    fn serialize(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "ADDRMAN {} {}\n",
            ADDRMAN_DAT_VERSION,
            hex_encode(&self.nkey)
        ));
        for info in self.map_info.values() {
            let tag = if info.in_tried { 't' } else { 'n' };
            out.push_str(&format!(
                "{} {} {} {} {} {} {} {} {}\n",
                tag,
                info.addr,
                info.services,
                info.source,
                info.time_unix,
                info.last_success_unix,
                info.last_try_unix,
                info.attempts,
                info.ref_count,
            ));
        }
        out
    }

    /// Atomic save to `<data_dir>/peers.dat` (temp + rename). Best-effort;
    /// failures are logged, never fatal.
    pub fn save(&self, data_dir: &std::path::Path) {
        let path = data_dir.join(PEERS_DATABASE_FILENAME);
        let tmp = data_dir.join(format!("{}.tmp", PEERS_DATABASE_FILENAME));
        let result = (|| -> Result<(), std::io::Error> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            {
                let mut f = fs::File::create(&tmp)?;
                f.write_all(self.serialize().as_bytes())?;
                f.flush()?;
            }
            fs::rename(&tmp, &path)?;
            Ok(())
        })();
        if let Err(e) = result {
            tracing::warn!("Failed to write peers.dat to {}: {}", path.display(), e);
            let _ = fs::remove_file(&tmp);
        }
    }

    /// Load from `<data_dir>/peers.dat`, re-bucketing via add()/good() so
    /// placement is recomputed from the persisted nkey. Corrupt / truncated /
    /// wrong-version / missing files yield a graceful empty cold start (never a
    /// panic, never a hard-down). Bounded by ADDRMAN_CEILING.
    pub fn load(data_dir: &std::path::Path, ng: &NetGroupManager) -> Self {
        let path = data_dir.join(PEERS_DATABASE_FILENAME);
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Self::new(),
        };
        match Self::parse(&contents, ng) {
            Some(t) => t,
            None => {
                tracing::warn!(
                    "peers.dat at {} corrupt or unsupported; starting cold",
                    path.display()
                );
                Self::new()
            }
        }
    }

    /// Parse the serialized form. Returns None on any structural problem so the
    /// caller can cold-start. Separated from `load` for in-process tests.
    fn parse(contents: &str, ng: &NetGroupManager) -> Option<Self> {
        let mut lines = contents.lines();
        let header = lines.next()?;
        let mut hp = header.split_whitespace();
        if hp.next()? != "ADDRMAN" {
            return None;
        }
        let version: u32 = hp.next()?.parse().ok()?;
        if version != ADDRMAN_DAT_VERSION {
            return None;
        }
        let nkey = hex_decode_32(hp.next()?)?;

        let mut table = Self::with_nkey(nkey);
        // Two passes: place NEW first (via add), then promote TRIED (via good)
        // so a tried record always finds the id already present.
        let mut tried_addrs: Vec<SocketAddr> = Vec::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Bounded: stop ingesting past the ceiling.
            if table.map_info.len() >= ADDRMAN_CEILING {
                break;
            }
            let mut f = line.split_whitespace();
            let tag = f.next()?;
            let addr: SocketAddr = f.next()?.parse().ok()?;
            let services: u64 = f.next()?.parse().ok()?;
            let source: IpAddr = f.next()?.parse().ok()?;
            let time_unix: u64 = f.next()?.parse().ok()?;
            let last_success: u64 = f.next()?.parse().ok()?;
            let last_try: u64 = f.next()?.parse().ok()?;
            let attempts: u32 = f.next()?.parse().ok()?;
            let _ref_count: u32 = f.next().unwrap_or("0").parse().unwrap_or(0);

            // (Re)create via add() so the new-bucket placement is recomputed.
            table.add(addr, source, services, time_unix, ng);
            // Restore the attempt/success bookkeeping that add() does not carry.
            if let Some(&id) = table.map_addr.get(&addr) {
                if let Some(info) = table.map_info.get_mut(&id) {
                    info.last_success_unix = last_success;
                    info.last_try_unix = last_try;
                    info.attempts = attempts;
                }
            }
            if tag == "t" {
                tried_addrs.push(addr);
            }
        }
        // Second pass: promote the tried records.
        let now = now_unix_secs();
        for addr in tried_addrs {
            table.good(&addr, now, ng);
        }
        Some(table)
    }
}

impl Default for AddrManTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Lowercase hex encoding (no external dep).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decode a 64-char hex string into a 32-byte array. None on bad input.
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Metadata about a known peer address.
#[derive(Debug, Clone)]
pub struct AddrInfo {
    /// The socket address.
    pub addr: SocketAddr,
    /// Services advertised by this peer.
    pub services: u64,
    /// When this address was last seen (from addr message or connection),
    /// as an absolute unix timestamp in seconds. This is what
    /// `getnodeaddresses` reports as the `time` field (Core:
    /// `TicksSinceEpoch<seconds>(addr.nTime)`). Kept alongside `last_seen`
    /// (a monotonic `Instant`) because `Instant` cannot be converted to
    /// wall-clock time after the fact.
    pub time_unix: u64,
    /// When this address was last seen (from addr message or connection).
    pub last_seen: Instant,
    /// When we last attempted to connect.
    pub last_attempt: Option<Instant>,
    /// When we last successfully connected.
    pub last_success: Option<Instant>,
    /// Number of connection attempts.
    pub attempt_count: u32,
    /// Where we learned about this address.
    pub source: AddrSource,
}

/// Unique identifier for a BIP155 address (used as hash map key).
///
/// This allows storing addresses that don't map to SocketAddr
/// (TorV3, I2P, CJDNS).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddrV2Key {
    /// The network address.
    pub addr: crate::addr::NetworkAddr,
    /// Port number.
    pub port: u16,
}

impl AddrV2Key {
    /// Create from a NetworkAddr and port.
    pub fn new(addr: crate::addr::NetworkAddr, port: u16) -> Self {
        Self { addr, port }
    }

    /// Try to convert to SocketAddr (IPv4/IPv6 only).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.addr.to_socket_addr(self.port)
    }
}

/// Metadata about a known BIP155 address (supports all network types).
#[derive(Debug, Clone)]
pub struct AddrV2Info {
    /// The network address.
    pub addr: crate::addr::NetworkAddr,
    /// Port number.
    pub port: u16,
    /// Services advertised by this peer.
    pub services: u64,
    /// Unix timestamp when this address was last seen.
    pub timestamp: u32,
    /// When this address was last seen locally.
    pub last_seen: Instant,
    /// When we last attempted to connect.
    pub last_attempt: Option<Instant>,
    /// When we last successfully connected.
    pub last_success: Option<Instant>,
    /// Number of connection attempts.
    pub attempt_count: u32,
    /// Where we learned about this address.
    pub source: AddrSource,
}

impl AddrV2Info {
    /// Get the unique key for this address.
    pub fn key(&self) -> AddrV2Key {
        AddrV2Key {
            addr: self.addr.clone(),
            port: self.port,
        }
    }

    /// Try to convert to SocketAddr (IPv4/IPv6 only).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.addr.to_socket_addr(self.port)
    }

    /// Check if this is a privacy network address (Tor, I2P, CJDNS).
    pub fn is_privacy_network(&self) -> bool {
        matches!(
            self.addr,
            crate::addr::NetworkAddr::TorV3(_)
                | crate::addr::NetworkAddr::I2P(_)
                | crate::addr::NetworkAddr::Cjdns(_)
        )
    }

    /// Convert to an AddrV2Entry for sending.
    pub fn to_addrv2_entry(&self) -> crate::addr::AddrV2Entry {
        crate::addr::AddrV2Entry {
            timestamp: self.timestamp,
            services: self.services,
            addr: self.addr.clone(),
            port: self.port,
        }
    }
}

/// Address manager: tracks known peer addresses with metadata.
///
/// Supports both legacy SocketAddr-based addresses (IPv4/IPv6) and
/// BIP155 addresses (Tor v3, I2P, CJDNS).
#[derive(Debug)]
pub struct AddressManager {
    /// Known addresses with metadata (legacy format for IPv4/IPv6).
    known_addrs: HashMap<SocketAddr, AddrInfo>,
    /// BIP155 addresses (supports all network types including privacy networks).
    known_addrv2: HashMap<AddrV2Key, AddrV2Info>,
    /// Addresses to try next (prioritized queue).
    try_queue: VecDeque<SocketAddr>,
    /// Banned addresses with unban time.
    banned: HashMap<SocketAddr, Instant>,
    /// Currently connected addresses (to avoid duplicates).
    connected: HashSet<SocketAddr>,
    /// Network groups of currently connected outbound peers (for diversity).
    connected_outbound_netgroups: HashSet<Vec<u8>>,
    /// Core-bucketed addrman (NEW[1024][64] + TRIED[256][64]) driving anti-Sybil
    /// placement, Good/Add/Select, and peers.dat persistence. The legacy
    /// `known_addrs` map above is kept for rich getnodeaddresses / addr-sharing
    /// metadata; this table is the placement + bounded persistence engine.
    addrman: AddrManTable,
    /// A clone of the netgroup manager, captured lazily the first time a
    /// netgroup-aware public method runs. Lets the sourceless ingest paths
    /// (DNS / manual / addpeeraddress) bucket without changing their public
    /// signatures. None until first capture.
    bucket_ng: Option<Arc<NetGroupManager>>,
    /// Adds that arrived before `bucket_ng` was captured. Flushed into the
    /// bucketed addrman on first capture. Bounded by ADDRMAN_CEILING.
    pending_bucket_adds: Vec<(SocketAddr, IpAddr, u64, u64)>,
}

impl AddressManager {
    /// Create a new empty address manager.
    pub fn new() -> Self {
        Self {
            known_addrs: HashMap::new(),
            known_addrv2: HashMap::new(),
            try_queue: VecDeque::new(),
            banned: HashMap::new(),
            connected: HashSet::new(),
            connected_outbound_netgroups: HashSet::new(),
            addrman: AddrManTable::new(),
            bucket_ng: None,
            pending_bucket_adds: Vec::new(),
        }
    }

    /// Capture the netgroup manager (idempotent) and flush any adds that
    /// arrived before it was available, so the bucketed addrman stays in sync
    /// with the legacy store. Called from every netgroup-aware public method.
    fn bind_netgroup(&mut self, ng: &NetGroupManager) {
        if self.bucket_ng.is_none() {
            let arc = Arc::new(ng.clone());
            self.bucket_ng = Some(arc.clone());
            let pending = std::mem::take(&mut self.pending_bucket_adds);
            for (addr, source, services, time_unix) in pending {
                self.addrman.add(addr, source, services, time_unix, &arc);
            }
        }
    }

    /// Create an address manager whose bucketed addrman is loaded from
    /// `<data_dir>/peers.dat` (or cold-started if absent/corrupt). The salt and
    /// bucket placement survive the round-trip.
    pub fn with_persisted(data_dir: &std::path::Path, ng: &NetGroupManager) -> Self {
        let mut mgr = Self::new();
        mgr.addrman = AddrManTable::load(data_dir, ng);
        mgr.bucket_ng = Some(Arc::new(ng.clone()));
        mgr
    }

    /// Borrow the underlying bucketed addrman (read-only; for inspection,
    /// persistence, and tests).
    pub fn addrman(&self) -> &AddrManTable {
        &self.addrman
    }

    /// Borrow the legacy known_addrs map (for tests).
    #[cfg(test)]
    pub fn known_addrs(&self) -> &HashMap<SocketAddr, AddrInfo> {
        &self.known_addrs
    }

    /// Atomically persist the bucketed addrman to `<data_dir>/peers.dat`.
    pub fn save_addrman(&self, data_dir: &std::path::Path) {
        self.addrman.save(data_dir);
    }

    /// Add addresses discovered from DNS seeds.
    pub fn add_dns_addresses(&mut self, addrs: Vec<SocketAddr>) {
        for addr in addrs {
            if !self.known_addrs.contains_key(&addr) && !self.is_banned(&addr) {
                self.known_addrs.insert(
                    addr,
                    AddrInfo {
                        addr,
                        services: NODE_NETWORK | NODE_WITNESS,
                        time_unix: now_unix_secs(),
                        last_seen: Instant::now(),
                        last_attempt: None,
                        last_success: None,
                        attempt_count: 0,
                        source: AddrSource::Dns,
                    },
                );
                self.try_queue.push_back(addr);
                // Mirror into the bucketed addrman. DNS seeds are self-sourced
                // (no announcing peer), matching Core's CAddress source==addr.
                self.bucket_add(
                    addr,
                    addr.ip(),
                    NODE_NETWORK | NODE_WITNESS,
                    now_unix_secs(),
                );
            }
        }
    }

    /// Stage an address into the bucketed addrman (NEW table). Best-effort:
    /// requires the netgroup manager, so it is only invoked from paths that can
    /// supply one, or via the self-source convention for sourceless adds. When
    /// no netgroup manager has been bound yet, the add is deferred until a
    /// netgroup-aware path runs (the legacy `known_addrs` mirror still tracks
    /// it). See `bind_netgroup` / the netgroup-aware ingest paths.
    fn bucket_add(&mut self, addr: SocketAddr, source: IpAddr, services: u64, time_unix: u64) {
        if let Some(ng) = self.bucket_ng.clone() {
            self.addrman.add(addr, source, services, time_unix, &ng);
        } else {
            self.pending_bucket_adds
                .push((addr, source, services, time_unix));
        }
    }

    /// Add addresses from an addr message from a peer.
    pub fn add_peer_addresses(&mut self, addrs: &[TimestampedNetAddress], from: SocketAddr) {
        for taddr in addrs {
            if let Some(socket_addr) = net_address_to_socket_addr(&taddr.address) {
                // Reject non-routable addresses (RFC 1918, loopback, link-local,
                // multicast, reserved, etc.) — mirrors Core CNetAddr::IsRoutable().
                if !ip_is_routable(&socket_addr.ip()) {
                    continue;
                }
                if !self.is_banned(&socket_addr) {
                    // Clamp timestamp: mirrors Core net_processing.cpp:5678-5680.
                    // Pre-2001 (<=100_000_000) or >10 min future → 5 days ago.
                    let clamped_ts = clamp_addr_timestamp(taddr.timestamp, now_unix_secs());
                    let entry = self
                        .known_addrs
                        .entry(socket_addr)
                        .or_insert_with(|| AddrInfo {
                            addr: socket_addr,
                            services: taddr.address.services,
                            time_unix: clamped_ts,
                            last_seen: Instant::now(),
                            last_attempt: None,
                            last_success: None,
                            attempt_count: 0,
                            source: AddrSource::Peer(from),
                        });
                    entry.last_seen = Instant::now();
                    entry.time_unix = clamped_ts;
                    entry.services = taddr.address.services;
                    let services = taddr.address.services;
                    let ts = clamped_ts;

                    // Add to try queue if not already connected
                    if !self.connected.contains(&socket_addr) {
                        self.try_queue.push_back(socket_addr);
                    }
                    // Mirror into the bucketed addrman, keyed by the announcing
                    // peer's address as the source group (Core AddSingle source).
                    self.bucket_add(socket_addr, from.ip(), services, ts);
                }
            }
        }
    }

    /// Add a manually specified address.
    pub fn add_manual_address(&mut self, addr: SocketAddr) {
        self.known_addrs.entry(addr).or_insert_with(|| AddrInfo {
            addr,
            services: NODE_NETWORK | NODE_WITNESS,
            time_unix: now_unix_secs(),
            last_seen: Instant::now(),
            last_attempt: None,
            last_success: None,
            attempt_count: 0,
            source: AddrSource::Manual,
        });
        // Manual addresses go to the front of the queue
        self.try_queue.push_front(addr);
        // Manual peers are self-sourced in the bucketed addrman.
        self.bucket_add(
            addr,
            addr.ip(),
            NODE_NETWORK | NODE_WITNESS,
            now_unix_secs(),
        );
    }

    /// Get the next address to try connecting to with network group diversity.
    ///
    /// For IPv4/IPv6 outbound connections, this enforces that no two outbound
    /// connections share the same /16 (IPv4) or /32 (IPv6) network group.
    /// Privacy networks (Tor, I2P, CJDNS) are not subject to this restriction.
    ///
    /// Selection has two stages:
    ///  1. Fast path — drain the `try_queue` hint, which carries freshly
    ///     learned / preferred-order addresses (DNS seeds, `addr` messages,
    ///     manual peers).
    ///  2. Fallback — when the hint queue is empty, re-select from the
    ///     persistent `known_addrs` store, applying an attempt-count backoff.
    ///
    /// The fallback is what makes the AddrMan re-selectable: `try_queue` is a
    /// one-shot consume queue, so without stage 2 every address would be lost
    /// forever after one `pop_front()`. Once the queue drained (which happens
    /// within ~20 min of churn during IBD) `fill_outbound_connections` could
    /// never open another connection, and with 0 peers no new `addr` messages
    /// arrive to refill it — a permanent zero-peer deadlock (observed on
    /// mainnet 2026-05-19: rustoshi wedged 13+ h at h=948304, `peers=0`).
    /// Bitcoin Core's `AddrMan::Select_` is likewise a non-consuming read of
    /// the persistent new/tried tables — entries are never dropped on select.
    ///
    /// Returns None if no eligible address is available.
    pub fn next_addr_to_try(&mut self, netgroup_manager: &NetGroupManager) -> Option<SocketAddr> {
        // Capture the netgroup manager + flush any deferred bucket adds.
        self.bind_netgroup(netgroup_manager);
        // Stage 1: fast path over the preferred-order hint queue.
        while let Some(addr) = self.try_queue.pop_front() {
            if !self.is_addr_eligible(&addr, netgroup_manager) {
                continue;
            }

            // Update attempt metadata
            if let Some(info) = self.known_addrs.get_mut(&addr) {
                info.last_attempt = Some(Instant::now());
                info.attempt_count += 1;
            }

            return Some(addr);
        }

        // Stage 2: fallback re-selection from the persistent store. Pick the
        // eligible address whose connect attempt is most overdue (never tried,
        // or attempted longest ago) so we cycle fairly instead of hammering
        // one peer. This mirrors Core's AddrMan::Select_ reading the persistent
        // tables rather than consuming a queue.
        let now = Instant::now();
        let mut best: Option<SocketAddr> = None;
        // Larger key = more overdue. `u64::MAX` for never-attempted addresses.
        let mut best_key: u64 = 0;
        for (addr, info) in self.known_addrs.iter() {
            if !self.is_addr_eligible(addr, netgroup_manager) {
                continue;
            }
            let key = match info.last_attempt {
                None => u64::MAX,
                Some(last) => {
                    // Per-address backoff: an address attempted within the
                    // backoff window for its current failure streak is not
                    // yet retryable. Keeps us from spinning on a dead peer
                    // while still guaranteeing it becomes retryable later.
                    let since = now.saturating_duration_since(last);
                    if since < Self::retry_backoff(info.attempt_count) {
                        continue;
                    }
                    since.as_secs()
                }
            };
            if best.is_none() || key > best_key {
                best = Some(*addr);
                best_key = key;
            }
        }

        if let Some(addr) = best {
            if let Some(info) = self.known_addrs.get_mut(&addr) {
                info.last_attempt = Some(now);
                info.attempt_count += 1;
            }
        }
        best
    }

    /// Whether `addr` may be dialed right now: not banned, not already
    /// connected, and (for IPv4/IPv6) not sharing a netgroup with an
    /// existing outbound connection. Privacy-network addresses skip the
    /// netgroup check because they don't correlate with network topology.
    fn is_addr_eligible(&self, addr: &SocketAddr, netgroup_manager: &NetGroupManager) -> bool {
        if self.is_banned(addr) {
            return false;
        }
        if self.connected.contains(addr) {
            return false;
        }
        if !netgroup_manager.is_privacy_network(&addr.ip()) {
            let netgroup = netgroup_manager.get_group(&addr.ip());
            if self
                .connected_outbound_netgroups
                .contains(netgroup.as_bytes())
            {
                return false;
            }
        }
        true
    }

    /// Backoff window before a previously-attempted address is retryable
    /// again, growing with the consecutive failure count so dead peers are
    /// retried progressively less often. Capped at 1 h so even a long-failing
    /// address eventually re-enters the candidate pool (Core keeps terrible
    /// entries selectable too — `IsTerrible` only lowers their chance, never
    /// removes them). A freshly learned address (`attempt_count == 0`) has no
    /// backoff and is selected immediately.
    fn retry_backoff(attempt_count: u32) -> Duration {
        match attempt_count {
            0 => Duration::from_secs(0),
            1 => Duration::from_secs(60),
            2 => Duration::from_secs(5 * 60),
            3 => Duration::from_secs(15 * 60),
            _ => Duration::from_secs(60 * 60),
        }
    }

    /// Mark an address as successfully connected (outbound).
    pub fn mark_outbound_success(&mut self, addr: &SocketAddr, netgroup_manager: &NetGroupManager) {
        self.connected.insert(*addr);

        // Track netgroup for diversity enforcement (IPv4/IPv6 only)
        if !netgroup_manager.is_privacy_network(&addr.ip()) {
            let netgroup = netgroup_manager.get_group(&addr.ip());
            self.connected_outbound_netgroups
                .insert(netgroup.as_bytes().to_vec());
        }

        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }

        // Promote in the bucketed addrman (NEW -> TRIED), mirroring Core's
        // AddrMan::Good on a successful outbound connection.
        self.bind_netgroup(netgroup_manager);
        if let Some(ng) = self.bucket_ng.clone() {
            self.addrman.good(addr, now_unix_secs(), &ng);
        }
    }

    /// Select an address from the NEW table for a feeler probe (Core
    /// net.cpp:2809 `addrman.Select(/*newOnly=*/true, ...)`).
    ///
    /// Returns a NEW-table address that is not currently connected and not
    /// banned, or `None` when the NEW table is empty / yields only ineligible
    /// candidates. Feelers deliberately read from NEW (not TRIED): they probe
    /// freshly-learned addresses and, on a successful handshake, the caller
    /// promotes them NEW->TRIED via `mark_outbound_success` -> `addrman.good()`.
    ///
    /// NOTE: Core first tries `SelectTriedCollision()` (test-before-evict)
    /// before falling back to the NEW-table select. rustoshi's `AddrManTable`
    /// has no tried-collision queue yet, so this lands the NEW-only path (the
    /// eclipse-mitigation core); tried-collision test-before-evict is a named
    /// follow-up, exactly as `select()` deferred the GetChance bias.
    pub fn select_for_feeler(&self) -> Option<SocketAddr> {
        // A handful of attempts so a transiently-connected/banned pick does not
        // starve the probe; bounded so an all-ineligible NEW table no-ops.
        for _ in 0..8 {
            let addr = self.addrman.select(true)?;
            if self.connected.contains(&addr) {
                continue;
            }
            if self.is_banned(&addr) {
                continue;
            }
            return Some(addr);
        }
        None
    }

    /// Test-only: seed a routable address straight into the bucketed NEW table
    /// with the netgroup manager bound, so `select_for_feeler` / the 23%-cap
    /// have something to draw from without a live peer handshake. Mirrors a
    /// peer-announced address (source = the address itself).
    #[cfg(test)]
    pub(crate) fn test_seed_new(&mut self, addr: SocketAddr, ng: &NetGroupManager) {
        self.bind_netgroup(ng);
        self.known_addrs.entry(addr).or_insert_with(|| AddrInfo {
            addr,
            services: NODE_NETWORK | NODE_WITNESS,
            time_unix: now_unix_secs(),
            last_seen: Instant::now(),
            last_attempt: None,
            last_success: None,
            attempt_count: 0,
            source: AddrSource::Peer(addr),
        });
        self.bucket_add(addr, addr.ip(), NODE_NETWORK | NODE_WITNESS, now_unix_secs());
    }

    /// Test-only: mark a shareable entry (record a successful connect) so it is
    /// counted by `shareable_count` and returned by `get_addresses_for_sharing`,
    /// without a live handshake.
    #[cfg(test)]
    pub(crate) fn test_mark_shareable(&mut self, addr: SocketAddr) {
        if let Some(info) = self.known_addrs.get_mut(&addr) {
            info.last_success = Some(Instant::now());
        }
    }

    /// Record a (feeler) connection attempt against the bucketed addrman
    /// (Core `AddrMan::Attempt`). Bumps the address's attempt count + last-try
    /// time so a NEW entry that never answers ages toward "terrible" over time
    /// without being promoted. Best-effort: no-ops if the netgroup manager is
    /// not yet bound (the addrman cannot place an entry it never saw).
    pub fn attempt_addr(&mut self, addr: &SocketAddr) {
        self.addrman.attempt(addr, now_unix_secs());
    }

    /// Promote a feeler-probed address NEW->TRIED on a successful handshake
    /// (Core net.cpp:2816 `addrman.Good()` for feelers).
    ///
    /// Unlike `mark_outbound_success` this does NOT insert into `connected` or
    /// the outbound-netgroup diversity set: a feeler is a short-lived probe that
    /// disconnects immediately, and Core explicitly excludes feelers from
    /// netgroup-distinctness accounting (net.cpp:2831). It only refreshes the
    /// success bookkeeping and promotes the address in the bucketed addrman.
    /// On a feeler FAILURE this is never called, so TRIED is left unchanged.
    pub fn mark_feeler_success(&mut self, addr: &SocketAddr, netgroup_manager: &NetGroupManager) {
        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }
        self.bind_netgroup(netgroup_manager);
        if let Some(ng) = self.bucket_ng.clone() {
            self.addrman.good(addr, now_unix_secs(), &ng);
        }
    }

    /// Mark an address as successfully connected (inbound - no netgroup tracking).
    pub fn mark_inbound_success(&mut self, addr: &SocketAddr) {
        self.connected.insert(*addr);
        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }
    }

    /// Mark an address as successfully connected.
    ///
    /// DEPRECATED: Use mark_outbound_success or mark_inbound_success instead.
    pub fn mark_success(&mut self, addr: &SocketAddr) {
        self.connected.insert(*addr);
        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }
    }

    /// Mark an address as disconnected (outbound).
    pub fn mark_outbound_disconnected(
        &mut self,
        addr: &SocketAddr,
        netgroup_manager: &NetGroupManager,
    ) {
        self.connected.remove(addr);

        // Remove netgroup from tracking
        if !netgroup_manager.is_privacy_network(&addr.ip()) {
            let netgroup = netgroup_manager.get_group(&addr.ip());
            self.connected_outbound_netgroups
                .remove(netgroup.as_bytes());
        }
    }

    /// Mark an address as disconnected.
    pub fn mark_disconnected(&mut self, addr: &SocketAddr) {
        self.connected.remove(addr);
    }

    /// Check if a netgroup is already represented in our outbound connections.
    pub fn has_outbound_in_netgroup(&self, netgroup: &NetGroup) -> bool {
        self.connected_outbound_netgroups
            .contains(netgroup.as_bytes())
    }

    /// Get the number of unique netgroups in outbound connections.
    pub fn outbound_netgroup_count(&self) -> usize {
        self.connected_outbound_netgroups.len()
    }

    /// Ban an address for a specified duration.
    pub fn ban(&mut self, addr: &SocketAddr, duration: Duration) {
        self.banned.insert(*addr, Instant::now() + duration);
        self.connected.remove(addr);
    }

    /// Check if an address is currently banned.
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(unban_time) = self.banned.get(addr) {
            if Instant::now() < *unban_time {
                return true;
            }
        }
        false
    }

    /// Get addresses suitable for sharing with other peers.
    ///
    /// Returns addresses that have been successfully connected to recently.
    pub fn get_addresses_for_sharing(&self, count: usize) -> Vec<&AddrInfo> {
        self.known_addrs
            .values()
            .filter(|info| info.last_success.is_some())
            .take(count)
            .collect()
    }

    /// Number of addresses eligible to be shared in a getaddr response — the
    /// pool the 23%-cap (`getaddr_cap`) is computed over. Mirrors the filter in
    /// `get_addresses_for_sharing` / `get_addrv2_for_sharing` (entries with a
    /// recorded `last_success`). Counts both the legacy IPv4/IPv6 store and the
    /// BIP155 store so the cap reflects the union a peer could actually receive,
    /// analogous to Core computing the percentage over the whole addrman.
    pub fn shareable_count(&self) -> usize {
        let legacy = self
            .known_addrs
            .values()
            .filter(|i| i.last_success.is_some())
            .count();
        let v2 = self
            .known_addrv2
            .values()
            .filter(|i| i.last_success.is_some())
            .count();
        legacy + v2
    }

    /// Number of known addresses.
    pub fn known_count(&self) -> usize {
        self.known_addrs.len()
    }

    /// Number of addresses in the try queue.
    pub fn queue_size(&self) -> usize {
        self.try_queue.len()
    }

    /// Number of banned addresses.
    pub fn banned_count(&self) -> usize {
        self.banned.len()
    }

    /// Number of currently connected addresses.
    pub fn connected_count(&self) -> usize {
        self.connected.len()
    }

    /// Expire old bans (cleanup).
    pub fn expire_bans(&mut self) {
        let now = Instant::now();
        self.banned.retain(|_, unban_time| *unban_time > now);
    }

    // ============================================================
    // BIP155 ADDRV2 METHODS
    // ============================================================

    /// Add addresses from an addrv2 message from a peer.
    ///
    /// This handles all BIP155 address types including Tor v3, I2P, and CJDNS.
    /// IPv4/IPv6 addresses are also added to the legacy known_addrs for compatibility.
    pub fn add_addrv2_addresses(&mut self, entries: &[crate::addr::AddrV2Entry], from: SocketAddr) {
        let now = Instant::now();
        let now_unix = now_unix_secs();

        for entry in entries {
            let key = AddrV2Key::new(entry.addr.clone(), entry.port);

            // Clamp timestamp: mirrors Core net_processing.cpp:5678-5680.
            // Pre-2001 (<=100_000_000) or >10 min future → 5 days ago.
            let clamped_ts = clamp_addr_timestamp(entry.timestamp, now_unix);
            // AddrV2Info.timestamp is u32; safe to truncate — clamped_ts is
            // always >= (now - 5 days) which fits in u32 until year 2106.
            let clamped_ts_u32 = clamped_ts as u32;

            // For IPv4/IPv6, also add to legacy storage
            if let Some(socket_addr) = entry.to_socket_addr() {
                // Reject non-routable addresses — mirrors Core CNetAddr::IsRoutable().
                if !ip_is_routable(&socket_addr.ip()) {
                    continue;
                }
                if !self.is_banned(&socket_addr) {
                    let addr_entry =
                        self.known_addrs
                            .entry(socket_addr)
                            .or_insert_with(|| AddrInfo {
                                addr: socket_addr,
                                services: entry.services,
                                time_unix: clamped_ts,
                                last_seen: now,
                                last_attempt: None,
                                last_success: None,
                                attempt_count: 0,
                                source: AddrSource::Peer(from),
                            });
                    addr_entry.last_seen = now;
                    addr_entry.time_unix = clamped_ts;
                    addr_entry.services = entry.services;

                    // Add to try queue if not already connected
                    if !self.connected.contains(&socket_addr) {
                        self.try_queue.push_back(socket_addr);
                    }
                }
            }

            // Store in addrv2 storage
            let v2_entry = self.known_addrv2.entry(key).or_insert_with(|| AddrV2Info {
                addr: entry.addr.clone(),
                port: entry.port,
                services: entry.services,
                timestamp: clamped_ts_u32,
                last_seen: now,
                last_attempt: None,
                last_success: None,
                attempt_count: 0,
                source: AddrSource::Peer(from),
            });
            v2_entry.last_seen = now;
            v2_entry.services = entry.services;
            v2_entry.timestamp = clamped_ts_u32;
        }
    }

    /// Get addresses suitable for sharing via addrv2 format.
    ///
    /// Returns addresses that have been successfully connected to recently,
    /// including privacy network addresses.
    pub fn get_addrv2_for_sharing(&self, count: usize) -> Vec<crate::addr::AddrV2Entry> {
        self.known_addrv2
            .values()
            .filter(|info| info.last_success.is_some())
            .take(count)
            .map(|info| info.to_addrv2_entry())
            .collect()
    }

    /// Get addresses suitable for sharing via legacy addr format.
    ///
    /// Returns only IPv4/IPv6 addresses that can be encoded in legacy format.
    pub fn get_addr_for_sharing(&self, count: usize) -> Vec<TimestampedNetAddress> {
        self.known_addrs
            .values()
            .filter(|info| info.last_success.is_some())
            .take(count)
            .map(|info| {
                let services = info.services;
                TimestampedNetAddress {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32,
                    address: socket_addr_to_net_address(info.addr, services),
                }
            })
            .collect()
    }

    /// Number of known BIP155 addresses.
    pub fn known_addrv2_count(&self) -> usize {
        self.known_addrv2.len()
    }

    /// Number of privacy network addresses (Tor, I2P, CJDNS).
    pub fn privacy_network_count(&self) -> usize {
        self.known_addrv2
            .values()
            .filter(|info| info.is_privacy_network())
            .count()
    }

    /// Collect all IPv4/IPv6 addresses known to the address manager.
    ///
    /// Used by the ASMap health-check to compute per-ASN cardinality across the
    /// full set of known peers (not just connected peers).  Tor/I2P/CJDNS
    /// addresses are excluded because the ASMap only covers IPv4/IPv6.
    pub fn all_known_ips(&self) -> Vec<std::net::IpAddr> {
        self.known_addrs.keys().map(|sa| sa.ip()).collect()
    }

    // ============================================================
    // getnodeaddresses / addpeeraddress support
    // ============================================================

    /// Inject an IPv4/IPv6 address into the address manager (companion of the
    /// `addpeeraddress` RPC — Core net.cpp:972). Stamps the supplied unix
    /// `time` and `services`. Returns `false` if the address was already
    /// known (Core's `AddrMan::Add` returns false when nothing new was
    /// inserted), `true` if a fresh entry was created.
    ///
    /// Banned addresses are not added (return `false`). Privacy-network
    /// (Tor/I2P/CJDNS) injection is not supported through this path because
    /// it operates on the legacy `SocketAddr` store, matching what the
    /// testing-only RPC needs.
    pub fn add_address_entry(&mut self, addr: SocketAddr, services: u64, time: u64) -> bool {
        if self.is_banned(&addr) {
            return false;
        }
        if self.known_addrs.contains_key(&addr) {
            return false;
        }
        self.known_addrs.insert(
            addr,
            AddrInfo {
                addr,
                services,
                time_unix: time,
                last_seen: Instant::now(),
                last_attempt: None,
                last_success: None,
                attempt_count: 0,
                source: AddrSource::Manual,
            },
        );
        // Mirror into the bucketed addrman (self-sourced injection).
        self.bucket_add(addr, addr.ip(), services, time);
        true
    }

    /// Map a routable / non-routable IP to the Core network-class string,
    /// mirroring `CNetAddr::GetNetClass()` + `GetNetworkName()`
    /// (netaddress.cpp:674, netbase.cpp:114). Non-routable IPs (loopback,
    /// RFC1918, link-local, …) map to `not_publicly_routable`.
    fn ipv4_ipv6_network_name(ip: &std::net::IpAddr) -> &'static str {
        if !crate::netgroup::ip_is_routable(ip) {
            return "not_publicly_routable";
        }
        match ip {
            std::net::IpAddr::V4(_) => "ipv4",
            std::net::IpAddr::V6(_) => "ipv6",
        }
    }

    /// Dump known addresses for the `getnodeaddresses` RPC.
    ///
    /// Walks both the legacy IPv4/IPv6 store (`known_addrs`) and the BIP155
    /// store (`known_addrv2`, which carries Tor/I2P/CJDNS), maps each entry's
    /// network to the Core network-class string, and returns the combined
    /// list. The caller is responsible for shuffling, the `count` cap, and
    /// the optional network filter (matching Core's
    /// `GetAddressesUnsafe(count, max_pct, network)` contract; here we expose
    /// the raw rows and let the RPC layer apply count/filter/shuffle so the
    /// semantics live in one place).
    ///
    /// IPv4/IPv6 entries duplicated into both stores (BIP155 mirrors IPv4/IPv6
    /// into `known_addrs` too) are de-duplicated by preferring the legacy
    /// entry and only adding addrv2 entries for privacy networks.
    pub fn dump_addresses(&self) -> Vec<NodeAddressEntry> {
        let mut out: Vec<NodeAddressEntry> = Vec::new();

        // Legacy IPv4/IPv6 store.
        for info in self.known_addrs.values() {
            let ip = info.addr.ip();
            out.push(NodeAddressEntry {
                time: info.time_unix,
                services: info.services,
                address: ip.to_string(),
                port: info.addr.port(),
                network: Self::ipv4_ipv6_network_name(&ip).to_string(),
            });
        }

        // BIP155 store — only the privacy networks (IPv4/IPv6 are already
        // covered by the legacy store above to avoid duplicates).
        for info in self.known_addrv2.values() {
            let network = match &info.addr {
                crate::addr::NetworkAddr::TorV3(_) => "onion",
                crate::addr::NetworkAddr::I2P(_) => "i2p",
                crate::addr::NetworkAddr::Cjdns(_) => "cjdns",
                // IPv4/IPv6 already handled by the legacy store.
                _ => continue,
            };
            out.push(NodeAddressEntry {
                time: info.timestamp as u64,
                services: info.services,
                address: info.addr.to_address_string(),
                port: info.port,
                network: network.to_string(),
            });
        }

        out
    }
}

impl Default for AddressManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// ADDRESS CONVERSION HELPERS
// ============================================================

/// Convert a NetAddress to a SocketAddr.
pub fn net_address_to_socket_addr(addr: &NetAddress) -> Option<SocketAddr> {
    // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if addr.ip[0..10] == [0u8; 10] && addr.ip[10] == 0xff && addr.ip[11] == 0xff {
        let ip = std::net::Ipv4Addr::new(addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);
        Some(SocketAddr::new(std::net::IpAddr::V4(ip), addr.port))
    } else {
        let ip = std::net::Ipv6Addr::from(addr.ip);
        Some(SocketAddr::new(std::net::IpAddr::V6(ip), addr.port))
    }
}

/// Convert a SocketAddr to a NetAddress.
pub fn socket_addr_to_net_address(addr: SocketAddr, services: u64) -> NetAddress {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..16].copy_from_slice(&v4.octets());
            ip
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    };
    NetAddress {
        services,
        ip,
        port: addr.port(),
    }
}

// ============================================================
// DNS SEED RESOLUTION
// ============================================================

/// Resolve DNS seeds to socket addresses.
///
/// Returns all resolved addresses from all seeds.
pub async fn resolve_dns_seeds(seeds: &[&str], port: u16) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for seed in seeds {
        match tokio::net::lookup_host(format!("{}:{}", seed, port)).await {
            Ok(resolved) => {
                let resolved_addrs: Vec<_> = resolved.collect();
                tracing::info!(
                    "DNS seed {} resolved to {} addresses",
                    seed,
                    resolved_addrs.len()
                );
                addrs.extend(resolved_addrs);
            }
            Err(e) => {
                tracing::warn!("DNS seed {} failed: {}", seed, e);
            }
        }
    }
    addrs
}

/// Hardcoded fallback peers for testnet4.
///
/// DNS seeds are unreliable for testnet4, so we provide fallback addresses.
pub fn testnet4_fallback_peers() -> Vec<SocketAddr> {
    vec![
        // These are well-known testnet4 nodes
        // Add more fallback IPs as needed
    ]
}

/// Build a placeholder `SocketAddr` for a privacy-network peer's handle.
///
/// Privacy networks (Tor/I2P) have no IP; CJDNS has a real fc00::/8 IPv6.
/// Used as the `PeerInfo.addr` field for handle bookkeeping only — the
/// actual transport target is carried in the spawned task's
/// `OutboundTarget`.
fn target_for_handle(addr: &crate::addr::NetworkAddr, port: u16) -> SocketAddr {
    match addr {
        crate::addr::NetworkAddr::Ipv4(ip) => SocketAddr::new((*ip).into(), port),
        crate::addr::NetworkAddr::Ipv6(ip) => SocketAddr::new((*ip).into(), port),
        crate::addr::NetworkAddr::Cjdns(bytes) => {
            let ip = std::net::Ipv6Addr::from(*bytes);
            SocketAddr::new(ip.into(), port)
        }
        // Tor / I2P don't have a SocketAddr — use synthetic placeholder so
        // the existing log/RPC code paths keep functioning. Downstream
        // displays will show 0.0.0.0:<port>.
        crate::addr::NetworkAddr::TorV3(_) | crate::addr::NetworkAddr::I2P(_) => {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port)
        }
    }
}

// ============================================================
// PEER MANAGER
// ============================================================

/// Connection type for outbound connections.
///
/// Mirrors Bitcoin Core `net.h::ConnectionType`.  The `Manual` variant is used
/// for peers added via `addnode` RPC / `-addnode` CLI flag.  Core's
/// `MaybeDiscourageAndDisconnect` exempts Manual peers from the ban/discourage
/// path — they are never written to the ban-list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Full-relay connection (relays blocks and transactions).
    FullRelay,
    /// Block-relay-only connection (only relays blocks, not transactions).
    BlockRelayOnly,
    /// Inbound connection.
    Inbound,
    /// Manually configured connection (addnode / -addnode).
    /// Core: ConnectionType::MANUAL — never banned or discouraged.
    Manual,
    /// Short-lived feeler connection (Core: ConnectionType::FEELER).
    ///
    /// A feeler dials an address selected FROM THE NEW TABLE, completes the
    /// version handshake, promotes the address NEW->TRIED via addrman Good(),
    /// then disconnects. Feelers keep TRIED fresh (the primary eclipse-attack
    /// mitigation) and are bounded to MAX_FEELER_CONNECTIONS=1; they are
    /// excluded from the full-relay/block-relay outbound slot budgets and from
    /// netgroup-diversity accounting (Core net.cpp:2831).
    Feeler,
}

/// Result of checking for stale peers.
#[derive(Debug, Clone, Default)]
pub struct StalePeerCheckResult {
    /// Peers to disconnect due to ping timeout.
    pub ping_timeouts: Vec<PeerId>,
    /// Peers to disconnect due to chain sync failure.
    pub chain_sync_failures: Vec<PeerId>,
    /// Peers to send getheaders to (chain sync warning).
    pub send_getheaders_to: Vec<PeerId>,
    /// Whether our tip may be stale (need extra outbound peer).
    pub tip_may_be_stale: bool,
}

impl StalePeerCheckResult {
    /// Check if any action was taken.
    pub fn has_disconnects(&self) -> bool {
        !self.ping_timeouts.is_empty() || !self.chain_sync_failures.is_empty()
    }

    /// Get all peers that were disconnected.
    pub fn disconnected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.ping_timeouts
            .iter()
            .chain(self.chain_sync_failures.iter())
    }
}

/// One peer's RPC-visible state, as returned by
/// [`PeerManager::connected_peers_with_stats`].  Combines:
///
/// - the long-lived [`PeerInfo`] (addr, version, services, …),
/// - the live `Arc<PeerStats>` from the spawned peer task (bytes /
///   per-msg histograms / conn-time / last-send-recv),
/// - and a few scalars that the manager owns but `PeerInfo` doesn't
///   carry (connection type, min ping, last block / tx ages).
///
/// Designed to be cheap to assemble (one Arc clone per peer + cheap
/// scalar copies) so that `getpeerinfo` on a 100-peer fleet does not
/// hold the manager lock for long.
pub struct PeerInfoSnapshot {
    pub peer_id: PeerId,
    pub info: PeerInfo,
    pub stats: std::sync::Arc<crate::peer::PeerStats>,
    pub conn_type: ConnectionType,
    pub min_ping_time: Option<Duration>,
    pub last_block_time: Option<Duration>,
    pub last_tx_time: Option<Duration>,
}

/// Handle for a connected peer, held by the peer manager.
struct PeerHandle {
    /// Peer metadata.
    info: PeerInfo,
    /// Channel to send commands to the peer task.
    command_tx: mpsc::Sender<PeerCommand>,
    /// Connection type.
    conn_type: ConnectionType,
    /// NoBan permission flag.
    ///
    /// When true this peer is exempt from ban/discourage regardless of misbehavior
    /// score — mirroring Bitcoin Core's `NetPermissionFlags::NoBan` check in
    /// `MaybeDiscourageAndDisconnect` (net_processing.cpp:5083).  Set for
    /// whitelisted peers; currently always `false` for non-whitelisted peers.
    noban: bool,
    /// Time when connection was established.
    connected_time: Instant,
    /// Minimum observed ping time.
    min_ping_time: Option<Duration>,
    /// Last time we received a block from this peer.
    last_block_time: Option<Instant>,
    /// Last time we received a transaction from this peer.
    last_tx_time: Option<Instant>,
    /// Stale peer detection state.
    stale_state: StalePeerState,
    /// Live atomic counters for `getpeerinfo` accounting fields.
    /// Populated when the spawned peer task fires `PeerEvent::Connected`.
    /// Pre-handshake / Connecting handles get a fresh empty `PeerStats`
    /// so the RPC path always sees a well-formed value.
    stats: std::sync::Arc<crate::peer::PeerStats>,
    /// GETADDR anti-DoS: whether we have already answered a getaddr from this
    /// peer. Core net_processing.cpp:4833 (`peer.m_getaddr_recvd`) — only the
    /// FIRST getaddr per connection is answered; subsequent ones are ignored
    /// to discourage addr stamping / resource waste.
    getaddr_recvd: bool,
    /// INBOUND addr token bucket (Core `peer.m_addr_token_bucket`, init 1.0).
    /// Refilled by `elapsed * MAX_ADDR_RATE_PER_SECOND` (capped at
    /// MAX_ADDR_PROCESSING_TOKEN_BUCKET) on each addr message; each processed
    /// address consumes one token, and addresses are dropped once it runs dry.
    addr_token_bucket: f64,
    /// Timestamp of the last addr-bucket refill (Core `m_addr_token_timestamp`).
    addr_token_timestamp: Instant,
}

/// The peer manager coordinates all peer connections.
pub struct PeerManager {
    /// Configuration.
    config: PeerManagerConfig,
    /// Chain parameters (for network magic, DNS seeds, etc.).
    params: ChainParams,
    /// Connected peers indexed by PeerId.
    peers: HashMap<PeerId, PeerHandle>,
    /// Inbound peer command senders — kept alive until the peer is
    /// registered via Connected event in handle_event().
    #[allow(clippy::type_complexity)]
    inbound_cmd_txs: Option<Arc<std::sync::Mutex<HashMap<PeerId, mpsc::Sender<PeerCommand>>>>>,
    /// Address manager for peer discovery.
    addr_manager: AddressManager,
    /// Misbehavior tracker for all peers.
    misbehavior_tracker: MisbehaviorTracker,
    /// Ban manager for persistent bans.
    ban_manager: BanManager,
    /// Network group manager for diversity enforcement.
    netgroup_manager: NetGroupManager,
    /// Stale peer detector for timeout enforcement.
    stale_detector: StalePeerDetector,
    /// BIP-133 feefilter scheduling state (per-peer next-send timer +
    /// last-sent value + received filter). Owns the SEND-side cadence that
    /// `PeerInfo.feefilter` (the received scalar) does not track. Wired into
    /// the Connected/Disconnected/FeeFilter handlers and driven by
    /// `maybe_send_feefilters` from the main.rs maintenance tick.
    feefilter_manager: FeeFilterManager,
    /// Last-known IBD state, refreshed by main.rs each maintenance tick via
    /// `set_in_ibd`. Used by the handshake-time initial feefilter send (which
    /// has no IBD argument of its own) so a peer that connects during IBD is
    /// told MAX_MONEY ("don't send me txs"), matching Core's IBD branch.
    /// Defaults to `true`: at startup we are in IBD, the conservative signal.
    in_ibd: bool,
    /// Last time we ran the stale peer check.
    last_stale_check: Instant,
    /// Next peer ID to assign.
    next_peer_id: u64,
    /// Channel for receiving events from peer tasks.
    event_tx: mpsc::Sender<PeerEvent>,
    /// Receiver for peer events (Option so it can be taken for independent polling).
    event_rx: Option<mpsc::Receiver<PeerEvent>>,
    /// Our current best block height (for version messages).
    start_height: i32,
    /// Anchor connections loaded from disk.
    anchors: Vec<SocketAddr>,
    /// `-connect` mode: last time each pinned peer was dialed. Used to
    /// throttle reconnect attempts so a persistently-dead pin does not
    /// hot-loop the reactive Disconnected handler (which calls
    /// `fill_outbound_connections` → `maintain_connect_peers` on every
    /// drop). Empty / unused when `config.connect_peers` is empty.
    connect_attempt_at: HashMap<SocketAddr, Instant>,
    /// One-shot guard for the fixed-seed bootstrap fallback. Set to `true`
    /// the first time `maybe_add_fixed_seeds` fires so neither the immediate
    /// `start()` call nor any later maintenance-tick re-call re-injects the
    /// seeds (and re-bumps attempt counts) on a still-empty book. Mirrors
    /// Core's `add_fixed_seeds = false` after firing (net.cpp:2642). A plain
    /// bool suffices (no lock) because `start()` and the maintenance tick run
    /// on the same single-threaded manager task — unlike blockbrew's RWMutex.
    fixed_seeds_added: bool,
    /// Wall-clock anchor for the fixed-seed 60s grace window, captured once at
    /// the top of `start()` (mirrors Core's `auto start = GetTime()` at
    /// net.cpp:2562). `None` until `start()` runs; read by the maintenance-tick
    /// re-check in `fill_outbound_connections` so the grace clock is shared
    /// between the immediate call and the periodic call.
    start_instant: Option<Instant>,
}

/// Minimum interval between reconnect attempts to a single pinned `-connect`
/// peer. Bounds the reactive reconnect loop so a dead pin retries at a steady
/// cadence rather than spinning. (Core's net.cpp uses an exponential backoff
/// per address; this fixed floor is the minimal equivalent for the pinned
/// case.)
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(2);

impl PeerManager {
    /// Create a new peer manager with the given configuration and chain parameters.
    pub fn new(config: PeerManagerConfig, params: ChainParams) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1024);
        let ban_manager = BanManager::with_duration(config.data_dir.clone(), config.ban_duration);

        // Load anchor connections from disk
        let anchors = read_anchors(&config.data_dir);
        if !anchors.is_empty() {
            tracing::info!(
                "{} block-relay-only anchors loaded from {}",
                anchors.len(),
                config.data_dir.join(ANCHORS_DATABASE_FILENAME).display()
            );
        }

        Self {
            config,
            params,
            peers: HashMap::new(),
            inbound_cmd_txs: None,
            addr_manager: AddressManager::new(),
            misbehavior_tracker: MisbehaviorTracker::new(),
            ban_manager,
            netgroup_manager: NetGroupManager::new(),
            stale_detector: StalePeerDetector::new(),
            feefilter_manager: FeeFilterManager::default(),
            in_ibd: true,
            last_stale_check: Instant::now(),
            next_peer_id: 1,
            event_tx,
            event_rx: Some(event_rx),
            start_height: 0,
            anchors,
            connect_attempt_at: HashMap::new(),
            fixed_seeds_added: false,
            start_instant: None,
        }
    }

    /// Create a new peer manager with a pre-built NetGroupManager (e.g., with ASMap loaded).
    ///
    /// Use this constructor when an ASMap file has been loaded at startup so that
    /// AS-based IP bucketing (anti-eclipse) is active from the first connection.
    ///
    /// Core reference: `src/init.cpp` loads asmap then builds NetGroupManager and
    /// passes it into AddrMan; the equivalent here is passing the built manager in.
    pub fn new_with_netgroup(
        config: PeerManagerConfig,
        params: ChainParams,
        netgroup_manager: NetGroupManager,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1024);
        let ban_manager = BanManager::with_duration(config.data_dir.clone(), config.ban_duration);

        let anchors = read_anchors(&config.data_dir);
        if !anchors.is_empty() {
            tracing::info!(
                "{} block-relay-only anchors loaded from {}",
                anchors.len(),
                config.data_dir.join(ANCHORS_DATABASE_FILENAME).display()
            );
        }

        // task #12: load the persisted bucketed addrman from <data_dir>/peers.dat
        // (graceful cold-start if absent/corrupt) so the learned address table
        // survives restarts instead of starting empty. Mirrors Core CAddrMan
        // reading peers.dat at startup. The matching save is wired into the
        // daemon's periodic maintenance + graceful-shutdown path (main.rs).
        let addr_manager = AddressManager::with_persisted(&config.data_dir, &netgroup_manager);

        Self {
            config,
            params,
            peers: HashMap::new(),
            inbound_cmd_txs: None,
            addr_manager,
            misbehavior_tracker: MisbehaviorTracker::new(),
            ban_manager,
            netgroup_manager,
            stale_detector: StalePeerDetector::new(),
            feefilter_manager: FeeFilterManager::default(),
            in_ibd: true,
            last_stale_check: Instant::now(),
            next_peer_id: 1,
            event_tx,
            event_rx: Some(event_rx),
            start_height: 0,
            anchors,
            connect_attempt_at: HashMap::new(),
            fixed_seeds_added: false,
            start_instant: None,
        }
    }

    /// Create a peer manager for testnet4 with default configuration.
    pub fn testnet4() -> Self {
        Self::new(PeerManagerConfig::testnet4(), ChainParams::testnet4())
    }

    /// Set the current best block height (used in version messages).
    pub fn set_start_height(&mut self, height: i32) {
        self.start_height = height;
    }

    /// Service flags advertised by this node (NODE_NETWORK | NODE_WITNESS |
    /// NODE_NETWORK_LIMITED, plus NODE_BLOOM when `peer_bloom_filters` is
    /// enabled — Bitcoin Core's `g_local_services` after `init.cpp`'s
    /// `-peerbloomfilters` gate).
    ///
    /// NODE_NETWORK_LIMITED (BIP-159, bit 10) is advertised UNCONDITIONALLY,
    /// matching Core: `init.cpp:863` seeds `g_local_services` with
    /// `NODE_NETWORK_LIMITED | NODE_WITNESS` and `init.cpp:1950` adds
    /// `NODE_NETWORK` in non-prune mode. A full non-pruned node serves the
    /// whole chain, so it can always serve the recent-288-block window the bit
    /// promises. (It is NOT prune-gated — a prune node would advertise
    /// NODE_NETWORK_LIMITED *without* NODE_NETWORK, but the LIMITED bit itself
    /// is set in both cases.)
    ///
    /// NODE_COMPACT_FILTERS (BIP-157, bit 6) is gated through
    /// [`should_advertise_compact_filters`]; as of FIX-82 the gate returns
    /// `true` whenever `-blockfilterindex` and `-peerblockfilters` are both
    /// enabled, because the BIP-157 P2P handlers are now registered — see
    /// [`BIP157_P2P_HANDLERS_REGISTERED`] (FIX-82, W121 BUG-7..BUG-13).
    pub fn local_services(&self) -> u64 {
        // NODE_NETWORK_LIMITED (BIP-159, bit 10) is advertised UNCONDITIONALLY
        // for this full node. Bitcoin Core seeds `g_local_services` with
        // `NODE_NETWORK_LIMITED | NODE_WITNESS` at `init.cpp:863` and adds
        // `NODE_NETWORK` in non-prune mode (`init.cpp:1950`), so a full
        // non-pruned node always carries NODE_NETWORK_LIMITED — the bit means
        // "can serve >=288 recent blocks", which is trivially true when the
        // node serves the entire chain. It is NOT prune-only.
        let mut s = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED;
        if self.config.peer_bloom_filters {
            s |= NODE_BLOOM;
        }
        // FIX-82: BIP-157 compact-filter advertisement gate. Handlers are
        // registered in `main.rs`; bit advertised when both config flags
        // are set, matching Core's `init.cpp:992-999`.
        if should_advertise_compact_filters(
            self.config.block_filter_index_enabled,
            self.config.peer_block_filters,
        ) {
            s |= NODE_COMPACT_FILTERS;
        }
        // NODE_P2P_V2 (BIP-324 v2 encrypted transport, bit 11). rustoshi runs
        // default-on v2 transport on the wire (see `peer::bip324_v2_outbound_enabled`,
        // wired into `run_outbound_peer`/inbound v2 detection), so advertising the
        // capability is honest. Gated on the same toggle so
        // `RUSTOSHI_BIP324_V2_OUTBOUND=0` drops the bit, mirroring Core's
        // `-v2transport` gate at `bitcoin-core/src/init.cpp:987-989`.
        if bip324_v2_outbound_enabled() {
            s |= NODE_P2P_V2;
        }
        s
    }

    /// True if NODE_BLOOM is advertised in our outbound version messages.
    /// Required by BIP-35 to honor `mempool` requests from peers.
    pub fn peer_bloom_filters_enabled(&self) -> bool {
        self.config.peer_bloom_filters
    }

    /// Get a reference to the network group manager.
    pub fn netgroup_manager(&self) -> &NetGroupManager {
        &self.netgroup_manager
    }

    /// Run an ASMap health check over all known AddrMan entries.
    ///
    /// Collects all IPv4/IPv6 IPs from the AddressManager and calls
    /// `NetGroupManager::health_check()`.  Returns `None` when no ASMap is
    /// loaded.  The `top_n` parameter controls how many ASNs appear in the
    /// top-N list (default: 5 is a reasonable value for log lines).
    ///
    /// Called at startup (after asmap load) and every 3600 s by the main loop.
    pub fn asmap_health_check(&self, top_n: usize) -> Option<crate::netgroup::AsmapHealthStats> {
        let ips = self.addr_manager.all_known_ips();
        self.netgroup_manager.health_check(&ips, top_n)
    }

    /// Take the event receiver out of the peer manager.
    ///
    /// This allows the caller to poll events independently (e.g., in a `tokio::select!`)
    /// without holding a lock on the peer manager itself. Returns `None` if already taken.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<PeerEvent>> {
        self.event_rx.take()
    }

    /// Start the peer manager: resolve DNS seeds, begin connecting, and optionally
    /// start a TCP listener for inbound connections.
    pub async fn start(&mut self) {
        // Anchor for the fixed-seed 60s grace clock (Core net.cpp:2562
        // `auto start = GetTime()`). Captured once here and stored on the
        // manager so the later maintenance-tick re-check in
        // `fill_outbound_connections` shares the same grace window. Set even
        // on the offline / `-connect` early-returns below (harmless — the
        // fallback's enabled/`-connect` gates keep it from firing there).
        let start_instant = Instant::now();
        self.start_instant = Some(start_instant);

        // Start TCP listener for inbound connections if configured.
        // Phase B offline mode also suppresses the inbound listener, so the
        // shadow node accepts no peers at all (the `offline` early-return
        // below covers outbound).
        if self.config.listen && !self.config.offline {
            let listen_addr: SocketAddr = format!("0.0.0.0:{}", self.config.listen_port)
                .parse()
                .unwrap();
            match tokio::net::TcpListener::bind(listen_addr).await {
                Ok(listener) => {
                    tracing::info!("P2P listening on {}", listen_addr);
                    let event_tx = self.event_tx.clone();
                    let magic = self.params.network_magic.0;
                    let our_services = self.local_services();
                    let our_start_height = self.start_height;
                    // We need a shared counter for peer IDs for inbound peers.
                    // Use an AtomicU64 to generate unique IDs.
                    let next_id = Arc::new(std::sync::atomic::AtomicU64::new(
                        self.next_peer_id + 10000, // offset to avoid collision with outbound IDs
                    ));
                    // Shared map to keep command senders alive until the peer
                    // manager moves them into PeerHandle on Connected event.
                    let inbound_senders: Arc<
                        std::sync::Mutex<HashMap<PeerId, mpsc::Sender<PeerCommand>>>,
                    > = Arc::new(std::sync::Mutex::new(HashMap::new()));
                    self.inbound_cmd_txs = Some(inbound_senders.clone());
                    // Snapshot path of the on-disk banlist for the accept
                    // loop.  The listener task lives outside the manager's
                    // `&mut self`, so it cannot share the in-memory
                    // `BanManager`.  Re-reading the file on each accept()
                    // is cheap (rare event) and lets RPC `setban` /
                    // misbehavior-driven bans take effect on the next
                    // connection without extra plumbing.
                    let ban_path = self.config.data_dir.clone();
                    tokio::spawn(async move {
                        // Cheap, per-accept ban check: re-read the persisted
                        // banlist file on disk.  This means RPC `setban` /
                        // misbehavior-driven bans take effect on the next
                        // accept without needing extra plumbing.
                        loop {
                            match listener.accept().await {
                                Ok((stream, addr)) => {
                                    // Refuse banned addresses at accept time
                                    // so a banned peer can't burn handshake
                                    // bandwidth or refill connection slots.
                                    let banlist_file = ban_path.join("banlist.json");
                                    if banlist_file.exists() {
                                        let is_banned = match std::fs::File::open(&banlist_file) {
                                            Ok(f) => {
                                                match serde_json::from_reader::<_, serde_json::Value>(
                                                    f,
                                                ) {
                                                    Ok(v) => {
                                                        let now = std::time::SystemTime::now()
                                                            .duration_since(std::time::UNIX_EPOCH)
                                                            .map(|d| d.as_secs())
                                                            .unwrap_or(0);
                                                        v.get("entries")
                                                            .and_then(|e| e.as_object())
                                                            .map(|entries| {
                                                                entries.iter().any(
                                                                    |(ip_str, entry)| {
                                                                        if ip_str
                                                                            .parse::<IpAddr>()
                                                                            .map(|ip| {
                                                                                ip == addr.ip()
                                                                            })
                                                                            .unwrap_or(false)
                                                                        {
                                                                            entry
                                                                                .get("ban_until")
                                                                                .and_then(|u| {
                                                                                    u.as_u64()
                                                                                })
                                                                                .map(|until| {
                                                                                    until > now
                                                                                })
                                                                                .unwrap_or(false)
                                                                        } else {
                                                                            false
                                                                        }
                                                                    },
                                                                )
                                                            })
                                                            .unwrap_or(false)
                                                    }
                                                    Err(_) => false,
                                                }
                                            }
                                            Err(_) => false,
                                        };
                                        if is_banned {
                                            tracing::info!(
                                                "Rejecting inbound connection from banned address {}",
                                                addr
                                            );
                                            drop(stream);
                                            continue;
                                        }
                                    }

                                    let peer_id = PeerId(
                                        next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                                    );
                                    let event_tx = event_tx.clone();
                                    let (cmd_tx, cmd_rx) = mpsc::channel(32);
                                    // Store cmd_tx so it stays alive until the peer
                                    // manager registers the peer in its handle map.
                                    tracing::info!("Storing cmd_tx for inbound peer {}", peer_id.0);
                                    inbound_senders.lock().unwrap().insert(peer_id, cmd_tx);
                                    let senders_ref = inbound_senders.clone();
                                    tokio::spawn(async move {
                                        run_inbound_peer(
                                            peer_id,
                                            stream,
                                            addr,
                                            magic,
                                            our_services,
                                            our_start_height,
                                            event_tx,
                                            cmd_rx,
                                        )
                                        .await;
                                        // Clean up sender on disconnect
                                        senders_ref.lock().unwrap().remove(&peer_id);
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to accept inbound connection: {}", e);
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to bind P2P listener on {}: {}", listen_addr, e);
                }
            }
        }

        // Phase B offline mode (`--maxconnections=0`): make no outbound
        // connections at all — skip anchors, DNS seeds and fallback peers.
        // The node then advances only when the revalidation harness feeds it
        // real blocks via `submitblock`. Inbound is separately gated by
        // `listen` (the harness launches the shadow node without `--listen`).
        if self.config.offline {
            tracing::info!(
                "Offline mode (maxconnections=0): P2P disabled — no DNS \
                 seeds, no outbound peers. Node advances via submitblock only."
            );
            return;
        }

        // `-connect=<ip:port>` peer pinning (Bitcoin Core / clearbit semantics).
        // When the connect list is non-empty we connect to ONLY those peers:
        // no anchors, no DNS seeds, no fallback peers, and no addrman-driven
        // outbound fill. We dial exactly the pinned addresses here; dropped
        // pinned peers are re-dialed by `fill_outbound_connections` (which is
        // itself gated to the pinned-only path in connect mode), driven by the
        // reactive Disconnected handler and the periodic maintenance tick.
        // Mirrors clearbit peer.zig:7009 (connect branch skips dnsSeeds()) and
        // peer.zig:7050 (outbound-fill loop gated on connect_address == null).
        if !self.config.connect_peers.is_empty() {
            tracing::info!(
                "-connect set ({} peer(s)): pinning to those peers only — \
                 skipping DNS seeds, anchors, and addrman auto-outbound",
                self.config.connect_peers.len()
            );
            self.fill_outbound_connections().await;
            return;
        }

        // First, try to connect to anchor peers (block-relay-only)
        // These are persisted from previous sessions for eclipse attack resistance
        self.connect_to_anchors().await;

        // Resolve DNS seeds — suppressed by `-nodnsseed` / `-dnsseed=0`
        // (Core: no DNS lookups when dnsseed is disabled).
        let addrs = if self.config.no_dns_seed {
            tracing::info!(
                "DNS seeding disabled (-nodnsseed); relying on addrman / fallback peers"
            );
            Vec::new()
        } else {
            resolve_dns_seeds(&self.params.dns_seeds, self.params.default_port).await
        };

        if addrs.is_empty() {
            tracing::warn!("No addresses from DNS seeds, trying fallback peers");
            // Add fallback peers for testnet4
            if self.params.network_id == NetworkId::Testnet4 {
                for addr in testnet4_fallback_peers() {
                    self.addr_manager.add_manual_address(addr);
                }
            }
        }

        self.addr_manager.add_dns_addresses(addrs);

        tracing::info!(
            "Address manager initialized with {} known addresses",
            self.addr_manager.known_count()
        );

        // Last-resort fixed-seed bootstrap fallback (Core net.cpp:2607-2643 /
        // blockbrew 4417bac). Fires here immediately when the address book is
        // still empty AND DNS seeding is disabled (nothing to wait for — the
        // exact DNS-failure hang fix); otherwise it is a cheap no-op now and
        // the periodic re-check in `fill_outbound_connections` injects the
        // seeds once the 60s grace elapses with the book still empty. Sits
        // strictly downstream of anchors and DNS, and is skipped entirely on
        // the offline / `-connect` early-returns above.
        self.maybe_add_fixed_seeds(start_instant);

        // Fill outbound connections
        self.fill_outbound_connections().await;
    }

    /// Add a manual peer address (e.g., from command line).
    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.addr_manager.add_manual_address(addr);
    }

    /// Inject an address into the address manager (companion of the
    /// `addpeeraddress` RPC). Returns `true` if a fresh entry was created.
    pub fn add_address_entry(&mut self, addr: SocketAddr, services: u64, time: u64) -> bool {
        self.addr_manager.add_address_entry(addr, services, time)
    }

    /// Dump all known addresses for the `getnodeaddresses` RPC. The RPC layer
    /// applies the count cap, the optional network filter, and the shuffle.
    pub fn dump_addresses(&self) -> Vec<NodeAddressEntry> {
        self.addr_manager.dump_addresses()
    }

    /// Immediately initiate an outbound connection to a peer (for addnode "onetry").
    pub async fn connect_to_peer(&mut self, addr: SocketAddr) {
        self.connect_to_with_type(addr, ConnectionType::FullRelay)
            .await;
    }

    /// Connect to anchor peers (block-relay-only connections from previous session).
    async fn connect_to_anchors(&mut self) {
        // Take anchors and clear them (we only try each once on startup)
        let anchors = std::mem::take(&mut self.anchors);

        let block_relay_count = self.block_relay_only_count();
        let needed = self
            .config
            .max_outbound_block_relay
            .saturating_sub(block_relay_count);

        for addr in anchors.into_iter().take(needed) {
            // Skip if already connected or in same netgroup as existing outbound
            if self.addr_manager.connected.contains(&addr) {
                continue;
            }

            // Check netgroup diversity (IPv4/IPv6 only)
            if !self.netgroup_manager.is_privacy_network(&addr.ip()) {
                let netgroup = self.netgroup_manager.get_group(&addr.ip());
                if self.addr_manager.has_outbound_in_netgroup(&netgroup) {
                    tracing::debug!(
                        "Skipping anchor {} - already have outbound in netgroup",
                        addr
                    );
                    continue;
                }
            }

            tracing::info!("Attempting anchor connection to {}", addr);
            self.connect_to_with_type(addr, ConnectionType::BlockRelayOnly)
                .await;
        }
    }

    /// Try to maintain the target number of outbound connections.
    ///
    /// This enforces network group diversity: no two IPv4/IPv6 outbound connections
    /// may share the same /16 (IPv4) or /32 (IPv6) network group.
    pub async fn fill_outbound_connections(&mut self) {
        // `-connect` mode: dial ONLY the pinned peers, never the addrman.
        // This is the single chokepoint reached on startup, on the reactive
        // PeerEvent::Disconnected path, and on the periodic maintenance tick,
        // so gating it here suppresses all three auto-outbound sources at
        // once. Re-dials any pinned peer that is not currently connected or
        // connecting (so a dropped pin reconnects), and never touches DNS,
        // anchors, or `next_addr_to_try`. Mirrors clearbit peer.zig:7050.
        if !self.config.connect_peers.is_empty() {
            self.maintain_connect_peers().await;
            return;
        }

        // Periodic fixed-seed re-check (Core's per-500ms re-check at
        // net.cpp:2594-2607 / blockbrew's 5s fixedSeedsTicker). This is the
        // addrman-driven branch reached on the reactive Disconnected path and
        // the periodic maintenance tick, so an address book that is still
        // empty after the 60s grace (e.g. DNS was up but returned nothing)
        // gets the fixed seeds injected on the next tick. The one-shot guard
        // inside `maybe_add_fixed_seeds` makes this a cheap no-op once fired.
        // `start_instant` was captured at the top of `start()`; if `start()`
        // has not run yet it is `None` and we simply skip (no clock yet).
        if let Some(start) = self.start_instant {
            self.maybe_add_fixed_seeds(start);
        }

        // Count full-relay outbound connections
        let full_relay_count = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::FullRelay && p.info.state == PeerState::Established
            })
            .count();

        let full_relay_connecting = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::FullRelay && p.info.state == PeerState::Connecting
            })
            .count();

        // Count block-relay-only outbound connections
        let block_relay_count = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && p.info.state == PeerState::Established
            })
            .count();

        let block_relay_connecting = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && p.info.state == PeerState::Connecting
            })
            .count();

        // Fill full-relay connections first
        let full_relay_needed = self
            .config
            .max_outbound_full_relay
            .saturating_sub(full_relay_count + full_relay_connecting);

        for _ in 0..full_relay_needed {
            if let Some(addr) = self.addr_manager.next_addr_to_try(&self.netgroup_manager) {
                self.connect_to_with_type(addr, ConnectionType::FullRelay)
                    .await;
            } else {
                break;
            }
        }

        // Then fill block-relay-only connections
        let block_relay_needed = self
            .config
            .max_outbound_block_relay
            .saturating_sub(block_relay_count + block_relay_connecting);

        for _ in 0..block_relay_needed {
            if let Some(addr) = self.addr_manager.next_addr_to_try(&self.netgroup_manager) {
                self.connect_to_with_type(addr, ConnectionType::BlockRelayOnly)
                    .await;
            } else {
                break;
            }
        }
    }

    /// Whether the fixed-seed bootstrap fallback is enabled.
    ///
    /// Port of blockbrew 4417bac `fixedSeedsEnabled()` / Core's
    /// `-fixedseeds` (DEFAULT_FIXEDSEEDS=true) gate: on by default, off when
    /// `-nofixedseeds` is set OR when `-connect` peer pinning is active (Core
    /// makes no addrman-driven outbound, and so never adds fixed seeds, when
    /// `-connect` is given).
    fn fixed_seeds_enabled(&self) -> bool {
        !self.config.no_fixed_seeds && self.config.connect_peers.is_empty()
    }

    /// Whether DNS seeding is disabled for this node.
    ///
    /// Port of blockbrew 4417bac `dnsSeedingDisabled()` / Core's `!dnsseed`
    /// + `-connect` implication. When DNS is disabled there is nothing to
    /// wait for, so the fixed-seed fallback may fire immediately rather than
    /// after the 60s grace (Core net.cpp:2620 — fire now when `!dnsseed &&
    /// !use_seednodes`; we have no `-seednode`, so the DNS predicate suffices).
    fn dns_seeding_disabled(&self) -> bool {
        self.config.no_dns_seed || !self.config.connect_peers.is_empty()
    }

    /// Last-resort fixed-seed bootstrap fallback — faithful port of blockbrew
    /// 4417bac `maybeAddFixedSeeds` (peermgr.go:1061-1089) + Core
    /// `ThreadOpenConnections` (net.cpp:2607-2643).
    ///
    /// Injects ALL of `ChainParams::fixed_seeds` into the address book exactly
    /// once, returning `true` only on the firing call. Fires iff every gate
    /// holds:
    ///  1. ENABLED — fixed seeds enabled and not in `-connect` mode
    ///     (`fixed_seeds_enabled()`).
    ///  2. NETWORK-SCOPED — the active params carry a non-empty `fixed_seeds`
    ///     list. Only `ChainParams::mainnet()` populates it, so this is
    ///     mainnet-only by construction; we also assert `network_id == Mainnet`
    ///     belt-and-suspenders.
    ///  3. ONE-SHOT — `fixed_seeds_added` is still false (set true on fire so
    ///     the periodic re-call is a cheap no-op; Core sets `add_fixed_seeds =
    ///     false` after firing).
    ///  4. BOOK-EMPTY — `known_count() == 0` (Core's GetReachableEmptyNetworks
    ///     proxy for an IPv4-only seed set: an empty book == the one reachable
    ///     network has zero addrman addresses). A populated book blocks firing,
    ///     so a successful DNS resolve is never bypassed.
    ///  5. TIMING — 60s grace elapsed since `start` (Core net.cpp:2614) OR DNS
    ///     seeding disabled (fire immediately — the DNS-failure hang fix).
    ///
    /// On fire it injects each literal via the addrman's DNS/manual add path,
    /// which already dedups against `known_addrs` and rejects banned addresses
    /// (peer_manager.rs `add_dns_addresses`), so no seed is duplicated or
    /// un-banned.
    fn maybe_add_fixed_seeds(&mut self, start: Instant) -> bool {
        // (3) ONE-SHOT — cheapest check first.
        if self.fixed_seeds_added {
            return false;
        }
        // (1) ENABLED.
        if !self.fixed_seeds_enabled() {
            return false;
        }
        // (2) NETWORK-SCOPED — mainnet-only by construction.
        if self.params.fixed_seeds.is_empty() || self.params.network_id != NetworkId::Mainnet {
            return false;
        }
        // (4) BOOK-EMPTY — a populated book (DNS success / loaded peers.dat)
        // blocks firing, so the fallback never bypasses normal bootstrap.
        if self.addr_manager.known_count() != 0 {
            return false;
        }
        // (5) TIMING — 60s grace (Core net.cpp:2614), short-circuited only
        // when DNS seeding is disabled (nothing to wait for).
        let grace_elapsed = start.elapsed() > Duration::from_secs(60);
        if !grace_elapsed && !self.dns_seeding_disabled() {
            return false;
        }

        // Fire: set the one-shot guard BEFORE injecting (Core net.cpp:2642
        // sets `add_fixed_seeds = false`), then inject all reachable seeds.
        self.fixed_seeds_added = true;
        let mut added = 0usize;
        for literal in &self.params.fixed_seeds {
            match literal.parse::<SocketAddr>() {
                Ok(addr) => {
                    // Use the addrman add path that dedups + rejects banned
                    // (guards `!known_addrs.contains_key && !is_banned`).
                    self.addr_manager.add_dns_addresses(vec![addr]);
                    added += 1;
                }
                Err(e) => {
                    tracing::warn!("Skipping malformed fixed seed {:?}: {}", literal, e);
                }
            }
        }
        tracing::info!(
            "Added {} fixed seeds (book was empty; {}) — last-resort bootstrap fallback",
            added,
            if grace_elapsed {
                "60s grace elapsed"
            } else {
                "DNS seeding disabled"
            }
        );
        true
    }

    /// `-connect` mode: re-dial any pinned peer that is not currently
    /// connected or connecting. Used in place of the addrman-driven
    /// `fill_outbound_connections` when `config.connect_peers` is non-empty.
    ///
    /// Each pinned peer is dialed as a `FullRelay` outbound (Core treats
    /// `-connect` peers as manual full-relay connections). A pinned peer is
    /// considered "already handled" if there is an outbound `PeerHandle` to
    /// the same `SocketAddr` in `Connecting` or `Established` state; otherwise
    /// we open a fresh connection. This gives Core/clearbit reconnect
    /// behaviour without ever consulting DNS seeds, anchors, or addrman.
    async fn maintain_connect_peers(&mut self) {
        // Snapshot the pin list so we can mutably borrow `self` while dialing.
        let pins = self.config.connect_peers.clone();
        let now = Instant::now();
        for addr in pins {
            let already = self.peers.values().any(|p| {
                !p.info.inbound
                    && p.info.addr == addr
                    && matches!(p.info.state, PeerState::Connecting | PeerState::Established)
            });
            if already {
                continue;
            }
            // Throttle reconnects to a single pinned peer. The reactive
            // Disconnected handler calls into here on every drop; without this
            // floor a permanently-dead pin (e.g. wrong/closed port) would spin
            // a tight connect→refused→reconnect loop. A live pin is unaffected
            // (it stays Established and hits the `already` guard above).
            if let Some(last) = self.connect_attempt_at.get(&addr) {
                if now.duration_since(*last) < CONNECT_RETRY_INTERVAL {
                    continue;
                }
            }
            self.connect_attempt_at.insert(addr, now);
            tracing::info!("Connecting to pinned -connect peer {}", addr);
            self.connect_to_with_type(addr, ConnectionType::FullRelay)
                .await;
        }
    }

    /// Count the number of block-relay-only outbound connections.
    fn block_relay_only_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && matches!(p.info.state, PeerState::Established | PeerState::Connecting)
            })
            .count()
    }

    /// Count in-flight feeler connections (connecting OR established) so a new
    /// feeler is only opened when below MAX_FEELER_CONNECTIONS. A feeler that
    /// has completed its handshake is disconnected immediately, so this is
    /// normally 0 between probes.
    fn feeler_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::Feeler
                    && matches!(p.info.state, PeerState::Established | PeerState::Connecting)
            })
            .count()
    }

    /// Open at most one short-lived feeler connection (Core net.cpp
    /// ThreadOpenConnections FEELER branch). Selects a NEW-table address (the
    /// addresses a feeler exists to probe), dials it as a `Feeler` connection,
    /// and returns. On a successful handshake the `PeerEvent::Connected`
    /// handler promotes the address NEW->TRIED via `mark_feeler_success` and
    /// disconnects (mirrors blockbrew peermgr.go:1626); on failure nothing is
    /// promoted, so TRIED stays unchanged.
    ///
    /// Bounded to MAX_FEELER_CONNECTIONS=1 in-flight: feelers never consume the
    /// full-relay/block-relay outbound slot budgets (those counts filter on
    /// their own conn types in `fill_outbound_connections`). No-ops gracefully
    /// when `-connect` pinning is active (the addrman is intentionally unused)
    /// or when the NEW table yields no eligible candidate.
    pub async fn maybe_open_feeler(&mut self) {
        // `-connect` mode makes no addrman-driven outbound (Core / blockbrew
        // peermgr.go:1260) — the feeler probe is addrman-driven, so skip it.
        if !self.config.connect_peers.is_empty() {
            return;
        }
        if self.feeler_count() >= MAX_FEELER_CONNECTIONS {
            return;
        }
        // Record the attempt in addrman so a never-answering NEW entry ages out
        // (Core records SelectTriedCollision/Select attempts; blockbrew does
        // NOT MarkFailed feelers, only MarkSuccess — so we only `attempt()`,
        // never penalise beyond the normal attempt bookkeeping).
        let addr = match self.addr_manager.select_for_feeler() {
            Some(a) => a,
            None => return,
        };
        self.addr_manager.attempt_addr(&addr);
        tracing::debug!("Making feeler connection to {}", addr);
        self.connect_to_with_type(addr, ConnectionType::Feeler).await;
    }

    /// Refill a peer's inbound-addr token bucket and consume up to `requested`
    /// tokens, returning how many addresses may be admitted (Core ProcessAddrs
    /// token-bucket, net_processing.cpp:5644-5671).
    ///
    /// The bucket refills at `MAX_ADDR_RATE_PER_SECOND` tokens/sec since the
    /// last addr message, capped at `MAX_ADDR_PROCESSING_TOKEN_BUCKET`. Each
    /// admitted address costs one token; once the bucket drops below 1.0 the
    /// remaining addresses are dropped (we hold no Addr-permission peers, so all
    /// inbound traffic is rate-limited, matching Core's default). A peer with no
    /// handle (already disconnected) admits 0.
    fn take_addr_tokens(&mut self, id: PeerId, requested: usize) -> usize {
        let now = Instant::now();
        let peer = match self.peers.get_mut(&id) {
            Some(p) => p,
            None => return 0,
        };
        // Refill (skip when already at/above the soft cap, matching Core's
        // "don't increment if already full" guard).
        if peer.addr_token_bucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET {
            let elapsed = now
                .saturating_duration_since(peer.addr_token_timestamp)
                .as_secs_f64();
            let increment = elapsed.max(0.0) * MAX_ADDR_RATE_PER_SECOND;
            peer.addr_token_bucket =
                (peer.addr_token_bucket + increment).min(MAX_ADDR_PROCESSING_TOKEN_BUCKET);
        }
        peer.addr_token_timestamp = now;

        // Admit up to floor(bucket) addresses, bounded by the request size.
        let admit = (peer.addr_token_bucket.floor() as usize).min(requested);
        peer.addr_token_bucket -= admit as f64;
        admit
    }

    /// Grant a peer the post-getaddr token bonus (Core net_processing.cpp:3767:
    /// `peer.m_addr_token_bucket += MAX_ADDR_TO_SEND`). Called when WE send a
    /// getaddr to a peer so the (possibly large) addr response we asked for is
    /// not spuriously rate-limited by the inbound token-bucket.
    pub fn grant_getaddr_token_bonus(&mut self, id: PeerId) {
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.addr_token_bucket += MAX_ADDR_PROCESSING_TOKEN_BUCKET;
        }
    }

    /// Initiate an outbound connection to a peer.
    #[allow(dead_code)]
    async fn connect_to(&mut self, addr: SocketAddr) {
        self.connect_to_with_type(addr, ConnectionType::FullRelay)
            .await;
    }

    /// Initiate an outbound connection to a peer with a specific connection type.
    async fn connect_to_with_type(&mut self, addr: SocketAddr, conn_type: ConnectionType) {
        // Skip banned addresses
        if self.ban_manager.is_addr_banned(&addr) {
            tracing::debug!("Skipping banned address: {}", addr);
            return;
        }

        let peer_id = PeerId(self.next_peer_id);
        self.next_peer_id += 1;

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let event_tx = self.event_tx.clone();
        let magic = self.params.network_magic.0;

        // For block-relay-only AND feeler connections, set relay=false.
        // Feelers are short-lived probes that disconnect right after the
        // handshake and never participate in tx relay (Core treats FEELER like
        // BLOCK_RELAY for the version `fRelay=false` flag).
        let relay =
            conn_type != ConnectionType::BlockRelayOnly && conn_type != ConnectionType::Feeler;
        let our_version = self.build_version_message_with_relay(addr, relay);

        tracing::debug!(
            "Connecting to peer {} (id={}, type={:?})",
            addr,
            peer_id.0,
            conn_type
        );

        // W117 wiring: if any proxy is configured, route the clearnet connect
        // through the proxy dispatch path. Otherwise keep the legacy direct-
        // TCP path so the v2-by-default BIP-324 probe behaviour is preserved
        // bit-for-bit.
        let needs_proxy_dispatch = self.config.tor_proxy.is_some()
            || self.config.onion_proxy.is_some()
            || self.config.i2p_sam.is_some();

        if needs_proxy_dispatch {
            let proxy_config = self.config.build_proxy_config();
            let target = crate::peer::OutboundTarget::Clearnet(addr);
            tokio::spawn(async move {
                run_outbound_peer_with_proxy(
                    peer_id,
                    target,
                    magic,
                    our_version,
                    proxy_config,
                    event_tx,
                    cmd_rx,
                )
                .await;
            });
        } else {
            // Spawn the peer connection task (legacy direct-TCP path).
            tokio::spawn(async move {
                run_outbound_peer(peer_id, addr, magic, our_version, event_tx, cmd_rx).await;
            });
        }

        self.peers.insert(
            peer_id,
            PeerHandle {
                info: PeerInfo {
                    addr,
                    version: 0,
                    services: 0,
                    user_agent: String::new(),
                    start_height: 0,
                    relay,
                    inbound: false,
                    state: PeerState::Connecting,
                    last_send: Instant::now(),
                    last_recv: Instant::now(),
                    ping_nonce: None,
                    ping_time: None,
                    bytes_sent: 0,
                    bytes_recv: 0,
                    time_offset: 0,
                    supports_witness: false,
                    supports_sendheaders: false,
                    supports_wtxid_relay: false,
                    supports_addrv2: false,
                    feefilter: 0,
                },
                command_tx: cmd_tx,
                conn_type,
                noban: false,
                connected_time: Instant::now(),
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
                // Placeholder; replaced when PeerEvent::Connected fires.
                stats: std::sync::Arc::new(crate::peer::PeerStats::new()),
                getaddr_recvd: false,
                addr_token_bucket: 1.0,
                addr_token_timestamp: Instant::now(),
            },
        );
    }

    /// Initiate an outbound connection to a BIP155 address (any network type).
    ///
    /// Unlike [`Self::connect_to_with_type`] this dispatches through the
    /// proxy/SAM stack based on the `NetworkAddr` variant:
    /// - IPv4/IPv6 -> direct (or via `tor_proxy` if set)
    /// - TorV3     -> `onion_proxy` / `tor_proxy`
    /// - I2P       -> `i2p_sam`
    /// - Cjdns     -> direct (only when `cjdns_reachable`)
    ///
    /// Refuses to dispatch unreachable variants (logs and returns). This is
    /// the entry point that closes W117 BUG-2: Tor v3 / I2P / CJDNS peers
    /// learned via ADDRv2 can now actually be dialed.
    pub async fn connect_to_addrv2(
        &mut self,
        addr: crate::addr::NetworkAddr,
        port: u16,
        conn_type: ConnectionType,
    ) {
        // Reachability gate — analogous to Core's IsReachable() check in
        // `src/net.cpp::ConnectNode` before initiating an outbound socket.
        if !self.config.is_reachable(&addr) {
            tracing::debug!(
                "Skipping unreachable {:?} peer (no proxy / not enabled): {:?}:{}",
                addr.network_id(),
                addr,
                port
            );
            return;
        }

        // IPv4/IPv6 fall through to the legacy path so we don't regress the
        // BIP-324 v2 probe behaviour for clearnet.
        if let Some(sa) = addr.to_socket_addr(port) {
            self.connect_to_with_type(sa, conn_type).await;
            return;
        }

        // Privacy-network branch: build an OutboundTarget and spawn the
        // proxy-aware variant.
        let peer_id = PeerId(self.next_peer_id);
        self.next_peer_id += 1;

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let event_tx = self.event_tx.clone();
        let magic = self.params.network_magic.0;

        let relay = conn_type != ConnectionType::BlockRelayOnly;
        // Synthetic loopback for version-message addr_recv (we have no IP).
        let synthetic = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let our_version = self.build_version_message_with_relay(synthetic, relay);

        let target = crate::peer::OutboundTarget::from_network_addr(&addr, port);
        let proxy_config = self.config.build_proxy_config();

        tracing::info!(
            "Connecting to {:?} peer (id={}, type={:?})",
            addr.network_id(),
            peer_id.0,
            conn_type
        );

        tokio::spawn(async move {
            run_outbound_peer_with_proxy(
                peer_id,
                target,
                magic,
                our_version,
                proxy_config,
                event_tx,
                cmd_rx,
            )
            .await;
        });

        // Use the synthetic socket addr as the handle key. Privacy-network
        // peers have no canonical SocketAddr; downstream logic that needs
        // the BIP-155 address should be extended later (W117 BUG-7/8).
        self.peers.insert(
            peer_id,
            PeerHandle {
                info: PeerInfo {
                    addr: target_for_handle(&addr, port),
                    version: 0,
                    services: 0,
                    user_agent: String::new(),
                    start_height: 0,
                    relay,
                    inbound: false,
                    state: PeerState::Connecting,
                    last_send: Instant::now(),
                    last_recv: Instant::now(),
                    ping_nonce: None,
                    ping_time: None,
                    bytes_sent: 0,
                    bytes_recv: 0,
                    time_offset: 0,
                    supports_witness: false,
                    supports_sendheaders: false,
                    supports_wtxid_relay: false,
                    supports_addrv2: false,
                    feefilter: 0,
                },
                command_tx: cmd_tx,
                conn_type,
                noban: false,
                connected_time: Instant::now(),
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
                stats: std::sync::Arc::new(crate::peer::PeerStats::new()),
                getaddr_recvd: false,
                addr_token_bucket: 1.0,
                addr_token_timestamp: Instant::now(),
            },
        );
    }

    /// Build a version message for outgoing connections.
    #[allow(dead_code)]
    fn build_version_message(&self, addr: SocketAddr) -> VersionMessage {
        self.build_version_message_with_relay(addr, true)
    }

    /// Build a version message for outgoing connections with relay flag.
    fn build_version_message_with_relay(&self, addr: SocketAddr, relay: bool) -> VersionMessage {
        let our_services = self.local_services();
        VersionMessage {
            version: PROTOCOL_VERSION,
            services: our_services,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            addr_recv: socket_addr_to_net_address(addr, 0),
            addr_from: socket_addr_to_net_address("0.0.0.0:0".parse().unwrap(), our_services),
            nonce: rand::random(),
            user_agent: "/Rustoshi:0.1.0/".to_string(),
            start_height: self.start_height,
            relay,
        }
    }

    /// Send a message to a specific peer.
    /// Uses blocking send to ensure critical messages (getheaders, getdata)
    /// are not dropped. For bulk responses (headers serving), use
    /// try_send_to_peer instead.
    pub async fn send_to_peer(&self, peer_id: PeerId, msg: NetworkMessage) -> bool {
        if let Some(peer) = self.peers.get(&peer_id) {
            peer.command_tx
                .send(PeerCommand::SendMessage(msg))
                .await
                .is_ok()
        } else {
            false
        }
    }

    /// Try to send a message without blocking. Drops the message if the
    /// peer's send buffer is full. Use for non-critical bulk responses.
    pub fn try_send_to_peer(&self, peer_id: PeerId, msg: NetworkMessage) -> bool {
        if let Some(peer) = self.peers.get(&peer_id) {
            peer.command_tx
                .try_send(PeerCommand::SendMessage(msg))
                .is_ok()
        } else {
            false
        }
    }

    /// Broadcast a message to all established peers.
    pub async fn broadcast(&self, msg: NetworkMessage) {
        for peer in self.peers.values() {
            if peer.info.state == PeerState::Established {
                let _ = peer
                    .command_tx
                    .send(PeerCommand::SendMessage(msg.clone()))
                    .await;
            }
        }
    }

    /// Announce a newly connected block to all established peers, honoring
    /// BIP-130: peers that have sent us `sendheaders` receive a `headers`
    /// message containing the new block header; everyone else receives an
    /// `inv` of MSG_BLOCK (or MSG_WITNESS_BLOCK for witness-aware peers).
    ///
    /// Reference: Bitcoin Core `net_processing.cpp::PeerManagerImpl::SendMessages`
    /// (the per-peer block-announcement loop honoring `m_prefers_headers`).
    /// Camlcoin's `peer_manager.ml::announce_block` (2026-05-06) is the
    /// fleet's canonical implementation of this branch.
    pub async fn announce_block(
        &self,
        header: rustoshi_primitives::BlockHeader,
        block_hash: rustoshi_primitives::Hash256,
    ) {
        let headers_msg = NetworkMessage::Headers(vec![header]);
        for peer in self.peers.values() {
            if peer.info.state != PeerState::Established {
                continue;
            }

            let msg = if peer.info.supports_sendheaders {
                headers_msg.clone()
            } else {
                let inv_type = if peer.info.supports_witness {
                    crate::message::InvType::MsgWitnessBlock
                } else {
                    crate::message::InvType::MsgBlock
                };
                NetworkMessage::Inv(vec![crate::message::InvVector {
                    inv_type,
                    hash: block_hash,
                }])
            };

            let _ = peer.command_tx.send(PeerCommand::SendMessage(msg)).await;
        }
    }

    /// Disconnect from a specific peer.
    pub async fn disconnect_peer(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.peers.get(&peer_id) {
            let _ = peer.command_tx.send(PeerCommand::Disconnect).await;
        }
    }

    /// Try to disconnect a peer non-blockingly via the peer's command channel.
    ///
    /// Mirrors Bitcoin Core's `node.fDisconnect = true` flag, which is checked
    /// by `SocketHandler` on the next event-loop tick.  Returns `true` if the
    /// `PeerCommand::Disconnect` was enqueued, `false` if the peer was already
    /// gone or the channel was full.
    ///
    /// Use this from sync code paths (e.g. event-loop match arms that hold
    /// `&PeerManager` via `peer_state.read()`) when an `await` on
    /// `disconnect_peer` would require upgrading to `&mut self`.
    /// (FIX-82 / W121 BIP-157 dispatch handlers use this for the per-violation
    /// disconnect that matches Core's `PrepareBlockFilterRequest` failure paths.)
    pub fn try_disconnect_peer(&self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get(&peer_id) {
            peer.command_tx.try_send(PeerCommand::Disconnect).is_ok()
        } else {
            false
        }
    }

    /// Ban a peer for misbehavior.
    pub async fn ban_peer(&mut self, peer_id: PeerId) {
        self.ban_peer_with_reason(peer_id, "manual ban".to_string())
            .await;
    }

    /// Ban a peer with a specific reason.
    ///
    /// Mirrors Bitcoin Core `MaybeDiscourageAndDisconnect` (net_processing.cpp:5083):
    ///
    /// * **NoBan** (`noban == true`) → no-op: whitelisted peers are never
    ///   written to the ban/discourage list and are not disconnected.
    /// * **Manual** (`ConnectionType::Manual`) → no-op: manually-configured
    ///   peers (addnode/-addnode) are never banned; Core returns `false`
    ///   immediately for `IsManualConn()`.
    /// * **Local address** (loopback / link-local / site-local) → disconnect
    ///   only, no discourage: avoids polluting the ban-list with local addrs.
    /// * **All other peers** → write to discourage/ban-list AND disconnect.
    pub async fn ban_peer_with_reason(&mut self, peer_id: PeerId, reason: String) {
        let peer = match self.peers.get(&peer_id) {
            Some(p) => p,
            None => return,
        };

        // NoBan permission → never ban, never disconnect (Core parity).
        if peer.noban {
            tracing::debug!(
                "Peer {} has NoBan permission, skipping ban (reason: {})",
                peer_id.0,
                reason
            );
            return;
        }

        // Manual connection → never ban, never disconnect (Core parity).
        if peer.conn_type == ConnectionType::Manual {
            tracing::debug!(
                "Peer {} is a manual connection, skipping ban (reason: {})",
                peer_id.0,
                reason
            );
            return;
        }

        let addr = peer.info.addr;
        let is_local = addr.ip().is_loopback()
            || matches!(addr.ip(),
                std::net::IpAddr::V4(v4) if v4.is_link_local() || v4.is_private()
            );

        if is_local {
            // Local address: disconnect only, do NOT write to the ban/discourage
            // list (Core: "don't pollute Discourage list with local addrs").
            tracing::debug!(
                "Peer {} has local address {}, disconnecting without ban (reason: {})",
                peer_id.0,
                addr,
                reason
            );
            let _ = peer.command_tx.send(PeerCommand::Disconnect).await;
        } else {
            // Regular inbound/outbound: discourage + disconnect.
            self.addr_manager.ban(&addr, self.config.ban_duration);
            self.ban_manager
                .ban_addr(addr, self.config.ban_duration, reason);
            let _ = self.peers[&peer_id]
                .command_tx
                .send(PeerCommand::Disconnect)
                .await;
        }
    }

    /// Record misbehavior for a peer. Always returns true (single-event model).
    ///
    /// Per Core PR #25974 (2022): any Misbehaving call immediately discourages
    /// the peer — no score accumulation to a threshold required.
    pub async fn misbehaving(&mut self, peer_id: PeerId, reason: MisbehaviorReason) -> bool {
        let should_ban = self
            .misbehavior_tracker
            .misbehaving(peer_id, reason.clone());

        if should_ban {
            self.ban_peer_with_reason(peer_id, reason.to_string()).await;
        }

        should_ban
    }

    /// Record misbehavior with a custom score and message. Always returns true (single-event model).
    ///
    /// Per Core PR #25974 (2022): any Misbehaving call immediately discourages the peer.
    pub async fn misbehaving_with_score(
        &mut self,
        peer_id: PeerId,
        howmuch: u32,
        message: &str,
    ) -> bool {
        let should_ban = self
            .misbehavior_tracker
            .misbehaving_with_score(peer_id, howmuch, message);

        if should_ban {
            self.ban_peer_with_reason(peer_id, message.to_string())
                .await;
        }

        should_ban
    }

    /// Get the misbehavior score for a peer.
    pub fn get_misbehavior_score(&self, peer_id: PeerId) -> u32 {
        self.misbehavior_tracker.get_score(peer_id)
    }

    /// Check if an IP address is banned.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.ban_manager.is_banned(ip)
    }

    /// Check if a socket address is banned.
    pub fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        self.ban_manager.is_addr_banned(addr)
    }

    /// Ban an IP address directly (e.g., via RPC).
    pub fn ban_ip(&mut self, ip: IpAddr, duration: Duration, reason: String) {
        self.ban_manager.ban(ip, duration, reason);
    }

    /// Unban an IP address. Returns true if the IP was previously banned.
    pub fn unban(&mut self, ip: &IpAddr) -> bool {
        self.ban_manager.unban(ip)
    }

    /// Get all banned addresses.
    pub fn list_banned(&self) -> Vec<(IpAddr, &BanEntry)> {
        self.ban_manager.get_banned()
    }

    /// Clear all bans.
    pub fn clear_banned(&mut self) {
        self.ban_manager.clear();
    }

    /// Get the next peer event.
    ///
    /// This should be called in a loop to process incoming events.
    pub async fn next_event(&mut self) -> Option<PeerEvent> {
        if let Some(ref mut rx) = self.event_rx {
            rx.recv().await
        } else {
            // event_rx was taken; use a pending future that never resolves
            std::future::pending().await
        }
    }

    /// Get the event sender for spawning new peer tasks.
    pub fn event_sender(&self) -> mpsc::Sender<PeerEvent> {
        self.event_tx.clone()
    }

    /// Handle a peer event internally.
    ///
    /// Returns the event for external processing if needed.
    pub async fn handle_event(&mut self, event: PeerEvent) -> Option<PeerEvent> {
        match &event {
            PeerEvent::Connected(id, info, stats) => {
                tracing::info!(
                    "Peer {} connected: {} ({})",
                    id.0,
                    info.addr,
                    info.user_agent
                );

                // For inbound peers, create a PeerHandle from the shared
                // command sender stored by the listener task.
                if !self.peers.contains_key(id) {
                    tracing::info!(
                        "Peer {} not in peers map, checking inbound_cmd_txs (is_some={})",
                        id.0,
                        self.inbound_cmd_txs.is_some()
                    );
                    if let Some(ref inbound_map) = self.inbound_cmd_txs {
                        if let Some(cmd_tx) = inbound_map.lock().unwrap().remove(id) {
                            self.peers.insert(
                                *id,
                                PeerHandle {
                                    info: info.clone(),
                                    command_tx: cmd_tx,
                                    conn_type: ConnectionType::Inbound,
                                    noban: false,
                                    connected_time: Instant::now(),
                                    min_ping_time: None,
                                    last_block_time: None,
                                    last_tx_time: None,
                                    stale_state: StalePeerState::new(),
                                    stats: std::sync::Arc::clone(stats),
                                    getaddr_recvd: false,
                                    addr_token_bucket: 1.0,
                                    addr_token_timestamp: Instant::now(),
                                },
                            );
                            self.addr_manager.mark_inbound_success(&info.addr);
                        }
                    }
                }

                // Feeler: a successful handshake promotes the probed address
                // NEW->TRIED, then we disconnect immediately (Core net.cpp:2816
                // Good() + blockbrew peermgr.go:1626 MarkSuccess+Disconnect).
                // A feeler is NOT inserted into `connected`/netgroup diversity
                // (it is short-lived), so we use `mark_feeler_success` not
                // `mark_outbound_success`. On a feeler FAILURE this branch never
                // runs, so TRIED is left unchanged — the falsification guard.
                let is_feeler = self
                    .peers
                    .get(id)
                    .map(|p| p.conn_type == ConnectionType::Feeler)
                    .unwrap_or(false);
                if is_feeler {
                    self.addr_manager
                        .mark_feeler_success(&info.addr, &self.netgroup_manager);
                    tracing::debug!(
                        "Feeler to {} handshook; promoted NEW->TRIED, disconnecting",
                        info.addr
                    );
                    // Tear the probe down by enqueuing Disconnect on the peer's
                    // command channel; the peer task then fires
                    // PeerEvent::Disconnected, which removes the handle and
                    // frees the single feeler slot for the next probe. We do
                    // NOT remove the handle here so the standard Disconnected
                    // cleanup path (feefilter/misbehavior bookkeeping) still
                    // runs exactly once.
                    self.disconnect_peer(*id).await;
                    return Some(event);
                }

                // Track netgroup for outbound connections
                if let Some(peer) = self.peers.get(id) {
                    if peer.conn_type != ConnectionType::Inbound {
                        self.addr_manager
                            .mark_outbound_success(&info.addr, &self.netgroup_manager);
                    }
                }

                if let Some(peer) = self.peers.get_mut(id) {
                    peer.info = info.clone();
                    peer.connected_time = Instant::now();
                    // Replace placeholder stats Arc with the live one
                    // produced by the spawned peer task. From here on
                    // every write/read updates these counters.
                    peer.stats = std::sync::Arc::clone(stats);
                }

                // BIP-133: register this peer with the feefilter manager so the
                // SEND-side cadence (per-peer next-send timer, last-sent value,
                // periodic re-broadcast) tracks it from now on. Gates mirror
                // Core's MaybeSendFeefilter short-circuits:
                //   - supports_feefilter = common version >= FEEFILTER_VERSION
                //     (70013); pre-70013 peers may treat FEEFILTER as unknown.
                //   - is_block_only = block-relay-only conn type. Core skips
                //     these (IsBlockOnlyConn) because they never announce txs to
                //     us, so we never need to advertise our filter to them.
                //     NOTE: this is the connection TYPE, distinct from the
                //     BIP-37 fRelay flag (`info.relay`).
                let conn_type = self
                    .peers
                    .get(id)
                    .map(|p| p.conn_type)
                    .unwrap_or(ConnectionType::Inbound);
                let supports_feefilter = info.version >= FEEFILTER_VERSION;
                let is_block_only = conn_type == ConnectionType::BlockRelayOnly;
                self.feefilter_manager
                    .add_peer(*id, supports_feefilter, is_block_only);

                // Early initial send (preserves the prior handshake-time
                // feefilter so a peer gets a filter without waiting for the
                // first maintenance tick), now routed through the manager so it
                // records the sent value + reschedules — no duplicate re-send.
                // Eligibility (version/block-only) is enforced inside
                // force_initial_send; the BIP-37 fRelay flag is an additional
                // gate (a peer that asked for no tx relay needs no filter).
                if info.relay {
                    if let Some(rate) = self.feefilter_manager.force_initial_send(*id, self.in_ibd)
                    {
                        let _ = self
                            .send_to_peer(*id, NetworkMessage::FeeFilter(rate))
                            .await;
                    }
                }
            }
            PeerEvent::Disconnected(id, reason) => {
                tracing::info!("Peer {} disconnected: {:?}", id.0, reason);
                if let Some(peer) = self.peers.remove(id) {
                    // Remove netgroup tracking for outbound connections
                    if peer.conn_type != ConnectionType::Inbound {
                        self.addr_manager
                            .mark_outbound_disconnected(&peer.info.addr, &self.netgroup_manager);
                    } else {
                        self.addr_manager.mark_disconnected(&peer.info.addr);
                    }
                }
                // Clean up misbehavior tracking for this peer
                self.misbehavior_tracker.remove_peer(*id);
                // Drop the per-peer BIP-133 feefilter scheduling state.
                self.feefilter_manager.remove_peer(*id);
                // Try to replace the connection
                self.fill_outbound_connections().await;
            }
            PeerEvent::Message(id, msg) => {
                // Update last_recv timestamp
                if let Some(peer) = self.peers.get_mut(id) {
                    peer.info.last_recv = Instant::now();

                    // Track block/tx times for eviction logic
                    match msg {
                        NetworkMessage::Block(_) => {
                            peer.last_block_time = Some(Instant::now());
                            // Update stale detection state with block height
                            // Use the peer's start_height as approximation
                            peer.stale_state.block_received(peer.info.start_height);
                        }
                        NetworkMessage::Tx(_) => {
                            peer.last_tx_time = Some(Instant::now());
                            peer.stale_state.tx_received();
                        }
                        NetworkMessage::Headers(headers) => {
                            // Update best known height from headers
                            // The actual height tracking is done elsewhere;
                            // here we just note we received headers
                            if !headers.is_empty() {
                                // Headers received; height will be updated by header sync
                            }
                        }
                        _ => {}
                    }
                }

                // Handle addr messages internally
                if let NetworkMessage::Addr(addrs) = msg {
                    if addrs.len() > MAX_ADDR {
                        // Bitcoin Core: 20-pt addr-format misbehavior.
                        let _ = self
                            .misbehavior_tracker
                            .misbehaving(*id, MisbehaviorReason::InvalidAddr);
                    } else {
                        // INBOUND addr token-bucket (Core ProcessAddrs,
                        // net_processing.cpp:5644-5671): refill by elapsed*0.1
                        // capped at 1000, then admit at most `tokens` addresses,
                        // dropping the rest. We have no Addr-permission peers, so
                        // all inbound addr traffic is rate-limited (Core default).
                        let admit = self.take_addr_tokens(*id, addrs.len());
                        if admit < addrs.len() {
                            tracing::debug!(
                                "addr rate-limit: dropped {} of {} addrs from peer {}",
                                addrs.len() - admit,
                                addrs.len(),
                                id.0
                            );
                        }
                        let admitted = &addrs[..admit];
                        if let Some(peer) = self.peers.get(id) {
                            self.addr_manager
                                .add_peer_addresses(admitted, peer.info.addr);
                        }
                        // BIP155: Relay a random subset of new addresses to 2 other peers
                        self.relay_addresses_to_peers(*id).await;
                    }
                }

                // Handle addrv2 messages (BIP155)
                if let NetworkMessage::AddrV2(entries) = msg {
                    if entries.len() > MAX_ADDR {
                        // Bitcoin Core: 20-pt addr-format misbehavior.
                        let _ = self
                            .misbehavior_tracker
                            .misbehaving(*id, MisbehaviorReason::InvalidAddr);
                    } else {
                        // Same inbound token-bucket as legacy addr above.
                        let admit = self.take_addr_tokens(*id, entries.len());
                        if admit < entries.len() {
                            tracing::debug!(
                                "addrv2 rate-limit: dropped {} of {} addrs from peer {}",
                                entries.len() - admit,
                                entries.len(),
                                id.0
                            );
                        }
                        let admitted = &entries[..admit];
                        self.addr_manager.add_addrv2_addresses(
                            admitted,
                            self.peers
                                .get(id)
                                .map(|p| p.info.addr)
                                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                        );
                        // Relay to 2 other peers
                        self.relay_addresses_to_peers(*id).await;
                    }
                }

                // Handle feefilter messages (BIP133)
                if let NetworkMessage::FeeFilter(fee_rate) = msg {
                    // Validate: must be within money range (max 21M BTC in sats).
                    // Out-of-range values are a protocol violation; Core
                    // marks the peer as misbehaving.
                    if *fee_rate > 2_100_000_000_000_000 {
                        let _ = self.misbehavior_tracker.misbehaving(
                            *id,
                            MisbehaviorReason::ProtocolViolation(
                                "feefilter out of range".to_string(),
                            ),
                        );
                    } else {
                        if let Some(peer) = self.peers.get_mut(id) {
                            peer.info.feefilter = *fee_rate;
                        }
                        // Mirror the received filter into the manager so the
                        // outbound tx-INV gate (should_relay_to_peer) consults
                        // the same value. Both stores stay in sync; the INV gate
                        // can use either.
                        self.feefilter_manager.handle_feefilter(*id, *fee_rate);
                    }
                }

                // Handle getaddr messages
                if let NetworkMessage::GetAddr = msg {
                    // GETADDR-once anti-DoS (Core net_processing.cpp:4833): only
                    // the FIRST getaddr per connection is answered; subsequent
                    // ones are ignored. We set the per-peer flag here and bail
                    // early on repeats (the flag is reset only when the peer
                    // reconnects and gets a fresh PeerHandle).
                    let already = self
                        .peers
                        .get(id)
                        .map(|p| p.getaddr_recvd)
                        .unwrap_or(true);
                    if already {
                        tracing::debug!("Ignoring repeated getaddr from peer {}", id.0);
                    } else {
                        if let Some(peer) = self.peers.get_mut(id) {
                            peer.getaddr_recvd = true;
                        }
                        // 23%-cap (Core MAX_PCT_ADDR_TO_SEND): cap the response
                        // to min(MAX_ADDR, ceil(0.23 * addrman_size)). Computed
                        // over the shareable pool size; gated to THIS getaddr
                        // call site so the getnodeaddresses RPC dump path stays
                        // uncapped (byte-exact, a closed northstar axis).
                        let cap = getaddr_cap(self.addr_manager.shareable_count());
                        // Send addrv2 if peer supports it, otherwise legacy addr
                        let peer_supports_addrv2 = self
                            .peers
                            .get(id)
                            .map(|p| p.info.supports_addrv2)
                            .unwrap_or(false);
                        if peer_supports_addrv2 {
                            let entries = self.addr_manager.get_addrv2_for_sharing(cap);
                            if !entries.is_empty() {
                                let _ = self
                                    .send_to_peer(*id, NetworkMessage::AddrV2(entries))
                                    .await;
                            }
                        } else {
                            let addrs = self.addr_manager.get_addresses_for_sharing(cap);
                            let timestamped_addrs: Vec<TimestampedNetAddress> = addrs
                                .into_iter()
                                .map(|info| TimestampedNetAddress {
                                    timestamp: info
                                        .last_seen
                                        .elapsed()
                                        .as_secs()
                                        .saturating_sub(info.last_seen.elapsed().as_secs())
                                        as u32,
                                    address: socket_addr_to_net_address(info.addr, info.services),
                                })
                                .collect();
                            if !timestamped_addrs.is_empty() {
                                let _ = self
                                    .send_to_peer(*id, NetworkMessage::Addr(timestamped_addrs))
                                    .await;
                            }
                        }
                    }
                }

                // Handle pong to track ping times
                if let NetworkMessage::Pong(nonce) = msg {
                    if let Some(peer) = self.peers.get_mut(id) {
                        if let Some(ping_nonce) = peer.info.ping_nonce {
                            if *nonce == ping_nonce {
                                let ping_time = peer.info.last_send.elapsed();
                                peer.info.ping_time = Some(ping_time);

                                // Track minimum ping time for eviction
                                match peer.min_ping_time {
                                    Some(min) if ping_time < min => {
                                        peer.min_ping_time = Some(ping_time);
                                    }
                                    None => {
                                        peer.min_ping_time = Some(ping_time);
                                    }
                                    _ => {}
                                }

                                peer.info.ping_nonce = None;

                                // Update stale detection state
                                peer.stale_state.pong_received();
                            }
                        }
                    }
                }

                // BIP-130: peer requests headers-style block announcements.
                // Track the flag so announce_block() can branch on it; without
                // this hook the flag stays false on inbound peers and Pattern A
                // (HSync findings doc, 2026-05-06) goes unfixed.
                if let NetworkMessage::SendHeaders = msg {
                    if let Some(peer) = self.peers.get_mut(id) {
                        peer.info.supports_sendheaders = true;
                    }
                }
            }
            PeerEvent::Misbehaving(id, reason) => {
                // Forward to the misbehavior tracker + ban manager.  A peer
                // hitting the 100-point threshold is added to the persistent
                // banlist and will be refused on the next accept().
                let reason = reason.clone();
                self.misbehaving(*id, reason).await;
            }
        }

        Some(event)
    }

    /// Relay addresses to up to 2 random peers (excluding the source).
    /// This implements Bitcoin Core's RelayAddress behavior.
    async fn relay_addresses_to_peers(&mut self, source_id: PeerId) {
        use rand::seq::SliceRandom;
        let candidates: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(pid, peer)| {
                **pid != source_id
                    && peer.conn_type != ConnectionType::BlockRelayOnly
                    && peer.info.state == PeerState::Established
            })
            .map(|(pid, _)| *pid)
            .collect();
        let mut rng = rand::thread_rng();
        let targets: Vec<PeerId> = candidates
            .choose_multiple(&mut rng, std::cmp::min(2, candidates.len()))
            .cloned()
            .collect();
        for target_id in targets {
            let target_supports_addrv2 = self
                .peers
                .get(&target_id)
                .map(|p| p.info.supports_addrv2)
                .unwrap_or(false);
            if target_supports_addrv2 {
                let entries = self.addr_manager.get_addrv2_for_sharing(10);
                if !entries.is_empty() {
                    let _ = self
                        .send_to_peer(target_id, NetworkMessage::AddrV2(entries))
                        .await;
                }
            } else {
                let addrs = self.addr_manager.get_addresses_for_sharing(10);
                let timestamped: Vec<TimestampedNetAddress> = addrs
                    .into_iter()
                    .map(|info| TimestampedNetAddress {
                        timestamp: 0,
                        address: socket_addr_to_net_address(info.addr, info.services),
                    })
                    .collect();
                if !timestamped.is_empty() {
                    let _ = self
                        .send_to_peer(target_id, NetworkMessage::Addr(timestamped))
                        .await;
                }
            }
        }
    }

    /// Send initial feefilter to a peer (BIP133).
    /// Without mempool, we set a high fee rate (100 sat/vbyte = 100000 sat/kvB)
    /// to discourage transaction relay.
    ///
    /// Legacy entry point retained for API compatibility; the live handshake
    /// path now goes through `FeeFilterManager::force_initial_send` so the
    /// periodic cadence stays consistent.
    pub async fn send_initial_feefilter(&mut self, peer_id: PeerId) {
        // 100 sat/vbyte = 100,000 sat/kvB (sat per 1000 virtual bytes)
        let fee_rate: u64 = 100_000;
        let _ = self
            .send_to_peer(peer_id, NetworkMessage::FeeFilter(fee_rate))
            .await;
    }

    /// Record the current IBD state for the handshake-time initial feefilter.
    ///
    /// Called by the main.rs maintenance tick before `maybe_send_feefilters`.
    /// Only affects the value chosen by `force_initial_send` for peers that
    /// connect later; the periodic path always passes the live `is_ibd`.
    pub fn set_in_ibd(&mut self, in_ibd: bool) {
        self.in_ibd = in_ibd;
    }

    /// BIP-133 periodic feefilter re-broadcast (Core `MaybeSendFeefilter`,
    /// invoked every SendMessages tick — here, every maintenance tick).
    ///
    /// Computes the set of peers whose per-peer `next_send_feefilter` timer has
    /// elapsed (or whose filter changed substantially enough to snap the
    /// broadcast forward) and pushes the rounded, min-relay-floored current
    /// filter to each. During IBD the filter is `MAX_MONEY` ("don't send me
    /// txs"); on the IBD→active transition any peer still holding the
    /// MAX_MONEY filter is force-updated. Eligibility (version >= 70013,
    /// not block-relay-only) is enforced per-peer inside the manager.
    ///
    /// `mempool_min_fee` is the node's current dynamic mempool minimum fee in
    /// sat/kvB (Core: `m_mempool.GetMinFee().GetFeePerK()`).
    pub async fn maybe_send_feefilters(&mut self, mempool_min_fee: u64, is_ibd: bool) {
        self.in_ibd = is_ibd;
        let pending = self
            .feefilter_manager
            .get_pending_feefilters(mempool_min_fee, is_ibd);
        for (peer_id, fee_rate) in pending {
            let _ = self
                .send_to_peer(peer_id, NetworkMessage::FeeFilter(fee_rate))
                .await;
        }
    }

    /// Announce a transaction INV to peers, gated by each peer's received
    /// feefilter (BIP-133 outbound tx-INV gate).
    ///
    /// Mirrors Core's SendMessages tx-INV loop (net_processing.cpp:6000/6036),
    /// which skips any tx whose feerate is below the peer's advertised
    /// `m_fee_filter_received`. A peer that never sent a feefilter (or is
    /// pre-70013) has a received filter of 0, so every tx passes — only
    /// genuinely sub-threshold INVs are dropped.
    ///
    /// `tx_fee_rate` is the transaction's feerate in sat/kvB, to match the u64
    /// feefilter units exactly.
    pub async fn relay_tx_inv(&self, inv: Vec<crate::message::InvVector>, tx_fee_rate: u64) {
        for (&peer_id, peer) in self.peers.iter() {
            if peer.info.state != PeerState::Established {
                continue;
            }
            // Consult the per-peer received filter. Use the manager's view
            // (kept in sync with PeerInfo.feefilter on every received
            // FEEFILTER); unknown peers default to relay (returns true).
            if !self
                .feefilter_manager
                .should_relay_to_peer(peer_id, tx_fee_rate)
            {
                continue;
            }
            let _ = peer
                .command_tx
                .send(PeerCommand::SendMessage(NetworkMessage::Inv(inv.clone())))
                .await;
        }
    }

    /// Update our tip height for stale peer detection.
    ///
    /// Call this when a new block is connected to our chain.
    pub fn update_tip_height(&mut self, height: u32) {
        self.stale_detector.update_tip(height);
        self.start_height = height as i32;
    }

    /// Check for stale peers and take appropriate action.
    ///
    /// This implements Bitcoin Core's CheckForStaleTipAndEvictPeers() logic:
    /// - Check every EXTRA_PEER_CHECK_INTERVAL (45 seconds)
    /// - Detect ping timeouts (20 minutes)
    /// - Detect chain sync failures (20 min + 2 min response time)
    /// - Evict stale peers, preferring inbound over outbound
    ///
    /// Returns lists of peers to disconnect.
    pub async fn check_for_stale_peers(&mut self, blocks_in_flight: usize) -> StalePeerCheckResult {
        let now = Instant::now();

        // Only check every EXTRA_PEER_CHECK_INTERVAL
        if now.duration_since(self.last_stale_check) < EXTRA_PEER_CHECK_INTERVAL {
            return StalePeerCheckResult::default();
        }
        self.last_stale_check = now;

        let mut result = StalePeerCheckResult::default();

        // Check if our tip may be stale
        if self.stale_detector.tip_may_be_stale(blocks_in_flight) {
            result.tip_may_be_stale = true;
            self.stale_detector.set_try_extra_outbound(true);
            tracing::info!(
                "Potential stale tip detected (last tip update: {} seconds ago)",
                self.stale_detector.our_tip_height()
            );
        } else {
            self.stale_detector.set_try_extra_outbound(false);
        }

        // Collect peers to check (avoid borrowing issues)
        let peer_ids: Vec<(PeerId, bool, bool)> = self
            .peers
            .iter()
            .filter(|(_, p)| p.info.state == PeerState::Established)
            .map(|(id, p)| {
                let is_outbound = p.conn_type != ConnectionType::Inbound;
                let is_protected = p.stale_state.chain_sync.protected;
                (*id, is_outbound, is_protected)
            })
            .collect();

        // Check each peer
        for (peer_id, is_outbound, is_protected) in peer_ids {
            // Check ping timeout
            if let Some(peer) = self.peers.get(&peer_id) {
                if peer.stale_state.is_ping_timed_out() {
                    tracing::info!(
                        "Peer {} disconnecting due to ping timeout (>20 minutes)",
                        peer_id.0
                    );
                    result.ping_timeouts.push(peer_id);
                    continue;
                }
            }

            // Check minimum connect time before considering for eviction
            if let Some(peer) = self.peers.get(&peer_id) {
                if peer.connected_time.elapsed() < MINIMUM_CONNECT_TIME {
                    continue;
                }
            }

            // Check chain sync timeout for outbound peers
            if is_outbound {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    let action = self.stale_detector.check_chain_sync(
                        &mut peer.stale_state,
                        true,
                        is_protected,
                    );

                    match action {
                        Some(true) => {
                            // Send getheaders
                            result.send_getheaders_to.push(peer_id);
                        }
                        Some(false) => {
                            // Disconnect
                            tracing::info!(
                                "Peer {} disconnecting due to chain sync timeout",
                                peer_id.0
                            );
                            result.chain_sync_failures.push(peer_id);
                        }
                        None => {}
                    }
                }
            }
        }

        // Disconnect ping timeout peers
        for peer_id in &result.ping_timeouts {
            self.disconnect_peer(*peer_id).await;
        }

        // Disconnect chain sync failure peers
        for peer_id in &result.chain_sync_failures {
            self.disconnect_peer(*peer_id).await;
        }

        result
    }

    /// Evict one extra outbound peer if we have too many.
    ///
    /// This is called periodically to maintain the target number of connections.
    /// We prefer to evict:
    /// 1. Block-relay-only peers over full-relay peers
    /// 2. Peers that haven't announced a block recently
    /// 3. Peers with longer connect times (newer peers get a chance)
    pub async fn evict_extra_outbound_peer(&mut self) -> Option<PeerId> {
        let full_relay_count = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::FullRelay && p.info.state == PeerState::Established
            })
            .count();

        let block_relay_count = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && p.info.state == PeerState::Established
            })
            .count();

        // Check if we have excess block-relay-only peers
        if block_relay_count > self.config.max_outbound_block_relay {
            // Find the youngest block-relay-only peer to evict
            // (unless it recently sent us a block)
            let evict_candidate = self
                .peers
                .iter()
                .filter(|(_, p)| {
                    p.conn_type == ConnectionType::BlockRelayOnly
                        && p.info.state == PeerState::Established
                        && p.connected_time.elapsed() >= MINIMUM_CONNECT_TIME
                        // Don't evict if peer recently sent a block
                        && p.last_block_time
                            .is_none_or(|t| t.elapsed() > Duration::from_secs(60))
                })
                .max_by_key(|(_, p)| p.connected_time) // Youngest = most recent connected_time
                .map(|(id, _)| *id);

            if let Some(peer_id) = evict_candidate {
                tracing::info!(
                    "Evicting extra block-relay-only peer {} (excess: {} > {})",
                    peer_id.0,
                    block_relay_count,
                    self.config.max_outbound_block_relay
                );
                self.disconnect_peer(peer_id).await;
                return Some(peer_id);
            }
        }

        // Check if we have excess full-relay peers
        if full_relay_count > self.config.max_outbound_full_relay {
            // Find the peer that least recently announced a new block
            let evict_candidate = self
                .peers
                .iter()
                .filter(|(_, p)| {
                    p.conn_type == ConnectionType::FullRelay
                        && p.info.state == PeerState::Established
                        && p.connected_time.elapsed() >= MINIMUM_CONNECT_TIME
                        && !p.stale_state.chain_sync.protected
                })
                .min_by_key(|(_, p)| {
                    // Prefer to evict peers with oldest last_block_time
                    p.last_block_time
                        .map_or(0, |t| (Instant::now() - t).as_secs())
                })
                .map(|(id, _)| *id);

            if let Some(peer_id) = evict_candidate {
                tracing::info!(
                    "Evicting extra full-relay peer {} (excess: {} > {})",
                    peer_id.0,
                    full_relay_count,
                    self.config.max_outbound_full_relay
                );
                self.disconnect_peer(peer_id).await;
                return Some(peer_id);
            }
        }

        None
    }

    /// Check if we should try to add an extra outbound peer.
    pub fn should_try_extra_outbound(&self) -> bool {
        self.stale_detector.should_try_extra_outbound()
    }

    /// Get the stale peer detector (for testing).
    #[cfg(test)]
    pub fn stale_detector(&self) -> &StalePeerDetector {
        &self.stale_detector
    }

    /// Get a mutable reference to a peer's stale state (for testing).
    #[cfg(test)]
    pub fn get_peer_stale_state_mut(&mut self, peer_id: PeerId) -> Option<&mut StalePeerState> {
        self.peers.get_mut(&peer_id).map(|p| &mut p.stale_state)
    }

    /// Persist the bucketed addrman to `<data_dir>/peers.dat` (task #12).
    ///
    /// Delegates to the inner `AddressManager`; called from the daemon's
    /// periodic maintenance tick and graceful-shutdown path so the learned
    /// address table survives restarts. Mirrors Core's periodic
    /// `DumpPeerAddresses` + the shutdown dump. Best-effort (never fatal).
    pub fn save_addrman(&self, data_dir: &std::path::Path) {
        self.addr_manager.save_addrman(data_dir);
    }

    /// Save anchor connections to disk.
    ///
    /// Called before shutdown to persist block-relay-only connections
    /// for eclipse attack resistance.
    pub fn save_anchors(&self) {
        let anchors: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && p.info.state == PeerState::Established
            })
            .take(MAX_BLOCK_RELAY_ONLY_ANCHORS)
            .map(|p| p.info.addr)
            .collect();

        if !anchors.is_empty() {
            dump_anchors(&self.config.data_dir, &anchors);
            tracing::info!(
                "Saved {} anchor connections to {}",
                anchors.len(),
                self.config
                    .data_dir
                    .join(ANCHORS_DATABASE_FILENAME)
                    .display()
            );
        }
    }

    /// Select an inbound peer to evict when slots are full.
    ///
    /// Returns None if no peer should be evicted (all protected).
    pub fn select_inbound_to_evict(&self) -> Option<PeerId> {
        let builder = EvictionCandidateBuilder::new(&self.netgroup_manager);

        let candidates: Vec<EvictionCandidate> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                p.conn_type == ConnectionType::Inbound && p.info.state == PeerState::Established
            })
            .map(|(id, p)| {
                builder.build(
                    *id,
                    p.info.addr,
                    p.connected_time,
                    p.min_ping_time,
                    p.last_block_time,
                    p.last_tx_time,
                    (p.info.services & NODE_NETWORK != 0) && (p.info.services & NODE_WITNESS != 0),
                    p.info.relay,
                    false, // bloom_filter - we don't track this currently
                    false, // prefer_evict
                    false, // noban
                )
            })
            .collect();

        select_node_to_evict(candidates)
    }

    /// Get list of connected peers.
    pub fn connected_peers(&self) -> Vec<(PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .filter(|(_, h)| h.info.state == PeerState::Established)
            .map(|(id, h)| (*id, &h.info))
            .collect()
    }

    /// Snapshot of every established peer's stats handle, plus a few
    /// peer_manager-side scalars that aren't covered by [`PeerStats`]
    /// itself (connection type, min ping, last block/tx times).
    /// Used by the RPC `getpeerinfo` handler to populate the wire
    /// fields with live atomically-updated values rather than the
    /// hard-coded zeros that shipped before W11.
    pub fn connected_peers_with_stats(&self) -> Vec<PeerInfoSnapshot> {
        let now = Instant::now();
        self.peers
            .iter()
            .filter(|(_, h)| h.info.state == PeerState::Established)
            .map(|(id, h)| PeerInfoSnapshot {
                peer_id: *id,
                info: h.info.clone(),
                stats: std::sync::Arc::clone(&h.stats),
                conn_type: h.conn_type,
                min_ping_time: h.min_ping_time,
                last_block_time: h.last_block_time.map(|t| now.saturating_duration_since(t)),
                last_tx_time: h.last_tx_time.map(|t| now.saturating_duration_since(t)),
            })
            .collect()
    }

    /// Get list of all peers (including connecting).
    pub fn all_peers(&self) -> Vec<(PeerId, &PeerInfo)> {
        self.peers.iter().map(|(id, h)| (*id, &h.info)).collect()
    }

    /// Get the number of established connections.
    pub fn peer_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.info.state == PeerState::Established)
            .count()
    }

    /// Get the number of outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| !p.info.inbound && p.info.state == PeerState::Established)
            .count()
    }

    /// Get the number of inbound connections.
    pub fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.info.inbound && p.info.state == PeerState::Established)
            .count()
    }

    /// Get information about a specific peer.
    pub fn get_peer_info(&self, peer_id: PeerId) -> Option<&PeerInfo> {
        self.peers.get(&peer_id).map(|h| &h.info)
    }

    /// Get a reference to the address manager.
    pub fn addr_manager(&self) -> &AddressManager {
        &self.addr_manager
    }

    /// Get a mutable reference to the address manager.
    pub fn addr_manager_mut(&mut self) -> &mut AddressManager {
        &mut self.addr_manager
    }

    /// Test-only: insert an outbound full-relay peer with a back-dated
    /// `connected_time` so MINIMUM_CONNECT_TIME does not protect it from
    /// the stalled-peer eviction path.  Used by the maintenance-tick
    /// integration test (`test_check_for_stale_peers_disconnects_zombie`).
    #[cfg(test)]
    pub(crate) fn insert_test_outbound_peer_old(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
    ) -> mpsc::Receiver<PeerCommand> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let old_connected = Instant::now() - Duration::from_secs(120);
        self.peers.insert(
            peer_id,
            PeerHandle {
                info: PeerInfo {
                    addr,
                    version: PROTOCOL_VERSION,
                    services: 0,
                    user_agent: String::new(),
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
                    supports_sendheaders: false,
                    supports_wtxid_relay: false,
                    supports_addrv2: false,
                    feefilter: 0,
                },
                command_tx: cmd_tx,
                conn_type: ConnectionType::FullRelay,
                noban: false,
                connected_time: old_connected,
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
                stats: std::sync::Arc::new(crate::peer::PeerStats::new()),
                getaddr_recvd: false,
                addr_token_bucket: 1.0,
                addr_token_timestamp: Instant::now(),
            },
        );
        cmd_rx
    }

    /// Test-only: force the stale-detector's `last_stale_check` clock back
    /// in time so the next `check_for_stale_peers` call passes the
    /// EXTRA_PEER_CHECK_INTERVAL gate without sleeping.
    #[cfg(test)]
    pub(crate) fn force_stale_check_due(&mut self) {
        self.last_stale_check = Instant::now() - Duration::from_secs(60);
    }

    /// Test-only: directly insert a peer into the peers map.  Returns the
    /// receiver side of the command channel so the test can observe what
    /// `send_to_peer` / `broadcast` / `announce_block` would deliver.
    #[cfg(test)]
    pub(crate) fn insert_test_peer(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
        supports_sendheaders: bool,
        supports_witness: bool,
    ) -> mpsc::Receiver<PeerCommand> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        self.peers.insert(
            peer_id,
            PeerHandle {
                info: PeerInfo {
                    addr,
                    version: PROTOCOL_VERSION,
                    services: 0,
                    user_agent: String::new(),
                    start_height: 0,
                    relay: true,
                    inbound: true,
                    state: PeerState::Established,
                    last_send: Instant::now(),
                    last_recv: Instant::now(),
                    ping_nonce: None,
                    ping_time: None,
                    bytes_sent: 0,
                    bytes_recv: 0,
                    time_offset: 0,
                    supports_witness,
                    supports_sendheaders,
                    supports_wtxid_relay: false,
                    supports_addrv2: false,
                    feefilter: 0,
                },
                command_tx: cmd_tx,
                conn_type: ConnectionType::Inbound,
                noban: false,
                connected_time: Instant::now(),
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
                stats: std::sync::Arc::new(crate::peer::PeerStats::new()),
                getaddr_recvd: false,
                addr_token_bucket: 1.0,
                addr_token_timestamp: Instant::now(),
            },
        );
        cmd_rx
    }

    /// Test-support seam (cross-crate): insert an ESTABLISHED peer with the
    /// given id/addr and hand back the receiver of its command channel so a
    /// caller can observe exactly what `send_to_peer` / `broadcast` would
    /// deliver to it. Unlike [`insert_test_peer`] this is `pub` (not
    /// `#[cfg(test)]`) so downstream crates — notably `rustoshi-rpc`'s
    /// `getblockfrompeer` test — can build a `PeerManager` with a fake peer
    /// without a live TCP connection. `#[doc(hidden)]`: not part of the public
    /// API contract, test-support only.
    #[doc(hidden)]
    pub fn insert_observable_peer(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
    ) -> mpsc::Receiver<PeerCommand> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        self.peers.insert(
            peer_id,
            PeerHandle {
                info: PeerInfo {
                    addr,
                    version: PROTOCOL_VERSION,
                    services: 0,
                    user_agent: String::new(),
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
                    supports_witness: true,
                    supports_sendheaders: false,
                    supports_wtxid_relay: false,
                    supports_addrv2: false,
                    feefilter: 0,
                },
                command_tx: cmd_tx,
                conn_type: ConnectionType::FullRelay,
                noban: false,
                connected_time: Instant::now(),
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
                stats: std::sync::Arc::new(crate::peer::PeerStats::new()),
                getaddr_recvd: false,
                addr_token_bucket: 1.0,
                addr_token_timestamp: Instant::now(),
            },
        );
        cmd_rx
    }

    /// Test-only: insert a `Feeler` peer handle in the `Connecting` state and
    /// hand back a clone of its `PeerInfo` (so a test can build a matching
    /// `PeerEvent::Connected`) plus the command-channel receiver (so the test
    /// can observe the post-handshake `Disconnect`). Mirrors what
    /// `connect_to_with_type(addr, Feeler)` would have inserted.
    #[cfg(test)]
    pub(crate) fn insert_test_feeler_peer(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
    ) -> (PeerInfo, mpsc::Receiver<PeerCommand>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let info = PeerInfo {
            addr,
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK | NODE_WITNESS,
            user_agent: String::new(),
            start_height: 0,
            relay: false,
            inbound: false,
            state: PeerState::Connecting,
            last_send: Instant::now(),
            last_recv: Instant::now(),
            ping_nonce: None,
            ping_time: None,
            bytes_sent: 0,
            bytes_recv: 0,
            time_offset: 0,
            supports_witness: false,
            supports_sendheaders: false,
            supports_wtxid_relay: false,
            supports_addrv2: false,
            feefilter: 0,
        };
        self.peers.insert(
            peer_id,
            PeerHandle {
                info: info.clone(),
                command_tx: cmd_tx,
                conn_type: ConnectionType::Feeler,
                noban: false,
                connected_time: Instant::now(),
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
                stats: std::sync::Arc::new(crate::peer::PeerStats::new()),
                getaddr_recvd: false,
                addr_token_bucket: 1.0,
                addr_token_timestamp: Instant::now(),
            },
        );
        (info, cmd_rx)
    }

    /// Test-only: insert a peer with specific connection type and noban flag.
    /// Used by W99 G2 unit tests to exercise the ban-exemption logic without
    /// a live async runtime.
    #[cfg(test)]
    pub(crate) fn insert_test_peer_with_flags(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
        conn_type: ConnectionType,
        noban: bool,
    ) -> mpsc::Receiver<PeerCommand> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        self.peers.insert(
            peer_id,
            PeerHandle {
                info: PeerInfo {
                    addr,
                    version: PROTOCOL_VERSION,
                    services: 0,
                    user_agent: String::new(),
                    start_height: 0,
                    relay: true,
                    inbound: conn_type == ConnectionType::Inbound,
                    state: PeerState::Established,
                    last_send: Instant::now(),
                    last_recv: Instant::now(),
                    ping_nonce: None,
                    ping_time: None,
                    bytes_sent: 0,
                    bytes_recv: 0,
                    time_offset: 0,
                    supports_witness: false,
                    supports_sendheaders: false,
                    supports_wtxid_relay: false,
                    supports_addrv2: false,
                    feefilter: 0,
                },
                command_tx: cmd_tx,
                conn_type,
                noban,
                connected_time: Instant::now(),
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
                stats: std::sync::Arc::new(crate::peer::PeerStats::new()),
                getaddr_recvd: false,
                addr_token_bucket: 1.0,
                addr_token_timestamp: Instant::now(),
            },
        );
        cmd_rx
    }
}

// ============================================================
// INBOUND CONNECTION HANDLING
// ============================================================

/// Returns true iff inbound BIP-324 v2 negotiation is enabled.  Gated by
/// the `RUSTOSHI_BIP324_V2_INBOUND` environment variable (default ON since
/// the live two-rustoshi handshake completed end-to-end on the W90 fleet
/// (`ef3bb91` ellswift signing-context fix + `766304a` app-frame transport)
/// and the Phase C interop matrix shows rustoshi → ouroboros v2/v2.  Set
/// to `0` / `false` / `no` / `off` to refuse v2 inbound (peers that send
/// the v2 ellswift will disconnect with `bad magic`, same as the prior
/// default-OFF behaviour).
///
/// Flipped in lock-step with `peer::bip324_v2_outbound_enabled` because
/// the underlying transport + cipher are shared.  Bitcoin Core defaults
/// `-v2transport=1` since v26 (2024); we match that policy.
pub fn bip324_v2_inbound_enabled() -> bool {
    match std::env::var("RUSTOSHI_BIP324_V2_INBOUND") {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "no" || v == "off")
        }
        Err(_) => true,
    }
}

/// Run an inbound peer connection task.
///
/// Similar to run_outbound_peer but for connections initiated by remote peers.
/// Enforces pre-handshake message validation:
/// - First message must be version
/// - Minimum protocol version (70015 for witness)
/// - Self-connection detection via nonce
/// - Duplicate version rejection
/// - Pre-handshake message rejection
#[allow(clippy::too_many_arguments)]
pub async fn run_inbound_peer(
    peer_id: PeerId,
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    magic: [u8; 4],
    our_services: u64,
    our_start_height: i32,
    event_tx: mpsc::Sender<PeerEvent>,
    command_rx: mpsc::Receiver<PeerCommand>,
) {
    use tokio::time::timeout;

    // Split the stream
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // Generate our nonce for self-connection detection
    let our_nonce: u64 = rand::random();

    // Apply 60-second handshake timeout (Bitcoin Core default)
    let handshake_timeout = Duration::from_secs(60);

    // BIP-324 v2 detection: peek the first V1_PREFIX_LEN (=16) bytes so
    // we can classify the wire as v1 or v2.  The two leading-byte
    // patterns are unambiguous:
    //   - v1: [4-byte magic][b"version\0\0\0\0\0"]      → looks_like_v1_version() == true
    //   - v2: [first 16 bytes of 64-byte ellswift pubkey] → essentially
    //         random (1/2^32 chance of magic-collision per BIP-324).
    //
    // We pick which path to take based on the result.  If the bytes
    // look like v2 BUT inbound v2 negotiation is disabled (default
    // until live-verified), we fall through to the v1 path which will
    // disconnect with `bad magic`, matching prior behavior.
    let mut prefix_buf = [0u8; V1_PREFIX_LEN];
    let read_result = timeout(handshake_timeout, reader.read_exact(&mut prefix_buf)).await;
    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::IoError(format!("failed to read version header: {}", e)),
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
    }

    // BIP-324 classification.
    let is_v1 = looks_like_v1_version(&prefix_buf, &magic);
    if !is_v1 && bip324_v2_inbound_enabled() {
        // Hand off to the v2 inbound path.  prefix_buf holds the first
        // 16 bytes of the peer's 64-byte ellswift pubkey; the remaining
        // 48 bytes plus the rest of the BIP-324 handshake will be
        // pulled by run_inbound_v2_peer.
        tracing::info!(
            "peer {:?} ({}): BIP-324 v2 detected on inbound, driving cipher handshake",
            peer_id,
            addr
        );
        run_inbound_v2_peer(
            peer_id,
            reader,
            writer,
            addr,
            magic,
            our_services,
            our_start_height,
            our_nonce,
            prefix_buf,
            handshake_timeout,
            event_tx,
            command_rx,
        )
        .await;
        return;
    }

    // V1 path: we have the first 16 bytes; read the remaining
    // MESSAGE_HEADER_SIZE - 16 = 8 bytes (length + checksum fields) to
    // complete the v1 message header.
    let mut header_buf = [0u8; MESSAGE_HEADER_SIZE];
    header_buf[..V1_PREFIX_LEN].copy_from_slice(&prefix_buf);
    let read_result = timeout(
        handshake_timeout,
        reader.read_exact(&mut header_buf[V1_PREFIX_LEN..]),
    )
    .await;
    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::IoError(format!("failed to read version header tail: {}", e)),
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
    }

    let (msg_magic, command, length, checksum) = parse_message_header(&header_buf);
    if msg_magic != magic {
        let _ = event_tx
            .send(PeerEvent::Misbehaving(
                peer_id,
                MisbehaviorReason::ProtocolViolation("bad magic".to_string()),
            ))
            .await;
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ProtocolError("bad magic".to_string()),
            ))
            .await;
        return;
    }

    // First message MUST be version (pre-handshake validation)
    if command != "version" {
        let _ = event_tx
            .send(PeerEvent::Misbehaving(
                peer_id,
                MisbehaviorReason::ProtocolViolation(format!("pre-handshake message: {}", command)),
            ))
            .await;
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::PreHandshakeMessage(command.clone()),
            ))
            .await;
        return;
    }

    // Validate length
    if length as usize > MAX_MESSAGE_SIZE {
        let _ = event_tx
            .send(PeerEvent::Misbehaving(
                peer_id,
                MisbehaviorReason::MessageTooLarge,
            ))
            .await;
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ProtocolError("message too large".to_string()),
            ))
            .await;
        return;
    }

    let mut payload = vec![0u8; length as usize];
    if !payload.is_empty() {
        match timeout(handshake_timeout, reader.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::IoError(format!("failed to read version payload: {}", e)),
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
        }
    }

    // Validate checksum
    let computed = rustoshi_crypto::sha256d(&payload);
    if checksum != computed.0[..4] {
        let _ = event_tx
            .send(PeerEvent::Misbehaving(
                peer_id,
                MisbehaviorReason::ProtocolViolation("checksum mismatch".to_string()),
            ))
            .await;
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ProtocolError("checksum mismatch".to_string()),
            ))
            .await;
        return;
    }

    let their_version = match NetworkMessage::deserialize("version", &payload) {
        Ok(NetworkMessage::Version(v)) => v,
        _ => {
            let _ = event_tx
                .send(PeerEvent::Misbehaving(
                    peer_id,
                    MisbehaviorReason::ProtocolViolation("invalid version message".to_string()),
                ))
                .await;
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::HandshakeFailed("invalid version message".to_string()),
                ))
                .await;
            return;
        }
    };

    // Check minimum protocol version (70015 for witness support)
    if their_version.version < MIN_WITNESS_PROTO_VERSION {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ObsoleteVersion(their_version.version),
            ))
            .await;
        return;
    }

    // Check for self-connection (matching nonce)
    if their_version.nonce == our_nonce && our_nonce != 0 {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::SelfConnection,
            ))
            .await;
        return;
    }

    // Send our version
    let our_version = VersionMessage {
        version: PROTOCOL_VERSION,
        services: our_services,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        addr_recv: socket_addr_to_net_address(addr, their_version.services),
        addr_from: socket_addr_to_net_address("0.0.0.0:0".parse().unwrap(), our_services),
        nonce: our_nonce,
        user_agent: "/Rustoshi:0.1.0/".to_string(),
        start_height: our_start_height,
        relay: true,
    };

    let version_msg = serialize_message(&magic, &NetworkMessage::Version(our_version));
    if writer.write_all(&version_msg).await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("failed to send version".to_string()),
            ))
            .await;
        return;
    }

    // Send verack
    let verack_msg = serialize_message(&magic, &NetworkMessage::Verack);
    if writer.write_all(&verack_msg).await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("failed to send verack".to_string()),
            ))
            .await;
        return;
    }

    if writer.flush().await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("flush failed".to_string()),
            ))
            .await;
        return;
    }

    // Track whether we've received version (for duplicate detection)
    let mut version_received = true;
    let mut handshake_complete = false;
    let mut wants_addrv2 = false;

    // Wait for their verack (with pre-handshake message validation)
    while !handshake_complete {
        let read_result = timeout(handshake_timeout, reader.read_exact(&mut header_buf)).await;

        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::IoError("failed to read message header".to_string()),
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
        }

        let (_, cmd, len, chk) = parse_message_header(&header_buf);

        // Read payload if any
        let mut msg_payload = vec![0u8; len as usize];
        if !msg_payload.is_empty() {
            match timeout(handshake_timeout, reader.read_exact(&mut msg_payload)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => {
                    let _ = event_tx
                        .send(PeerEvent::Disconnected(
                            peer_id,
                            DisconnectReason::IoError("failed to read message payload".to_string()),
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
            }

            // Validate checksum
            let computed = rustoshi_crypto::sha256d(&msg_payload);
            if chk != computed.0[..4] {
                let _ = event_tx
                    .send(PeerEvent::Misbehaving(
                        peer_id,
                        MisbehaviorReason::ProtocolViolation("checksum mismatch".to_string()),
                    ))
                    .await;
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::ProtocolError("checksum mismatch".to_string()),
                    ))
                    .await;
                return;
            }
        }

        match cmd.as_str() {
            "verack" => {
                handshake_complete = true;
            }
            "version" => {
                // Duplicate version message — Bitcoin Core 1-pt misbehavior.
                if version_received {
                    let _ = event_tx
                        .send(PeerEvent::Misbehaving(
                            peer_id,
                            MisbehaviorReason::ProtocolViolation("duplicate version".to_string()),
                        ))
                        .await;
                    let _ = event_tx
                        .send(PeerEvent::Disconnected(
                            peer_id,
                            DisconnectReason::DuplicateVersion,
                        ))
                        .await;
                    return;
                }
                version_received = true;
            }
            // Pre-verack negotiation messages are allowed
            "wtxidrelay" | "sendaddrv2" | "sendtxrcncl" => {
                if cmd == "sendaddrv2" {
                    wants_addrv2 = true;
                }
                continue;
            }
            // Any other message before handshake is complete is a protocol violation
            _ => {
                let _ = event_tx
                    .send(PeerEvent::Misbehaving(
                        peer_id,
                        MisbehaviorReason::ProtocolViolation(format!(
                            "pre-handshake message after version: {}",
                            cmd
                        )),
                    ))
                    .await;
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::PreHandshakeMessage(cmd),
                    ))
                    .await;
                return;
            }
        }
    }

    // Connection established
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let peer_info = PeerInfo {
        addr,
        version: their_version.version,
        services: their_version.services,
        user_agent: their_version.user_agent,
        start_height: their_version.start_height,
        relay: their_version.relay,
        inbound: true,
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
        supports_wtxid_relay: false,
        supports_addrv2: wants_addrv2,
        feefilter: 0,
    };

    // Per-peer atomic counters; populated for the entire post-handshake
    // session.  Pre-handshake bytes are not retroactively credited but
    // that's negligible (tens of bytes vs MB-scale block traffic).
    let stats = std::sync::Arc::new(crate::peer::PeerStats::new());
    stats.mark_connected();

    let _ = event_tx
        .send(PeerEvent::Connected(
            peer_id,
            peer_info,
            std::sync::Arc::clone(&stats),
        ))
        .await;

    // BIP 130: sendheaders - request headers announcements instead of inv
    if their_version.version >= SENDHEADERS_VERSION {
        let msg = serialize_message(&magic, &NetworkMessage::SendHeaders);
        if writer.write_all(&msg).await.is_ok() {
            stats.record_send("sendheaders", msg.len() as u64);
        }
    }
    let _ = writer.flush().await;

    // Full message loop — same as outbound peers
    crate::peer::run_message_loop_tracked(
        peer_id, &magic, reader, writer, event_tx, command_rx, stats,
    )
    .await;
}

/// Drive a BIP-324 v2 inbound handshake to cipher-handshake-complete.
///
/// On entry, `prefix` holds the first `V1_PREFIX_LEN` (=16) bytes of the
/// peer's 64-byte ElligatorSwift pubkey, already drained from the
/// reader.  This function:
///
/// 1. Reads the remaining 48 bytes of the peer's ellswift pubkey.
/// 2. Initializes a fresh `Bip324Cipher` in responder mode.
/// 3. Sends our own 64-byte ellswift pubkey + a random garbage payload.
/// 4. Sends our 16-byte garbage terminator followed by an encrypted
///    BIP-324 "version packet" (zero-byte contents, garbage as AAD).
/// 5. Scans the inbound stream byte-by-byte for the peer's garbage
///    terminator (capped at `MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN`
///    bytes); the bytes preceding the terminator are the peer's
///    garbage and become the AAD for decrypting their version packet.
/// 6. Decrypts the peer's encrypted length prefix (3 bytes) via the
///    length cipher, then reads `header + len + tag` bytes and
///    decrypts the version packet to confirm AEAD integrity.
///
/// On success, the cipher handshake is complete: both sides have
/// derived the same session ID, and the AEAD packet ciphers are
/// synchronised.  At that point we emit a tracing log so live tests
/// can confirm interop, then *cleanly disconnect*.  Wrapping the
/// existing `run_message_loop` to dispatch messages over V2Transport
/// (encrypt outgoing / decrypt incoming) is deliberately deferred
/// to a follow-up commit to keep this change reviewable: the cipher
/// fix + handshake plumbing is what unblocks real-peer interop;
/// the application-frame wrapper is mechanical from there.
///
/// Reference:
/// - clearbit `cb04a1f` — equivalent Zig implementation, live-verified
///   against Bitcoin Core 28.x mainnet peers.
/// - ouroboros `_negotiate_v2` — full Python BIP-324 wire flow.
/// - BIP-324 §"Wire format" — packet layout + handshake order.
#[allow(clippy::too_many_arguments)]
async fn run_inbound_v2_peer(
    peer_id: PeerId,
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    addr: SocketAddr,
    magic: [u8; 4],
    our_services: u64,
    our_start_height: i32,
    _our_nonce: u64,
    prefix: [u8; V1_PREFIX_LEN],
    handshake_timeout: Duration,
    event_tx: mpsc::Sender<PeerEvent>,
    _command_rx: mpsc::Receiver<PeerCommand>,
) {
    use tokio::time::timeout;
    // ----- Step 1: complete the peer's 64-byte ellswift pubkey. -----
    let mut their_pubkey_bytes = [0u8; ELLSWIFT_PUBKEY_LEN];
    their_pubkey_bytes[..V1_PREFIX_LEN].copy_from_slice(&prefix);
    let read_result = timeout(
        handshake_timeout,
        reader.read_exact(&mut their_pubkey_bytes[V1_PREFIX_LEN..]),
    )
    .await;
    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::IoError(format!(
                        "v2 handshake: failed to read ellswift pubkey: {}",
                        e
                    )),
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
    }
    let their_pubkey = match EllSwiftPubKey::from_bytes(&their_pubkey_bytes) {
        Ok(p) => p,
        Err(_) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::HandshakeFailed(
                        "v2 handshake: invalid ellswift pubkey".to_string(),
                    ),
                ))
                .await;
            return;
        }
    };

    // ----- Step 2: build our random ellswift keypair + garbage. -----
    let mut cipher = Bip324Cipher::random();
    cipher.initialize_for_responder(&their_pubkey, &magic);

    // Random garbage of 0..=MAX_GARBAGE_LEN bytes (Bitcoin Core sends 0
    // by default; clearbit/ouroboros include it for traffic analysis
    // resistance).  We send 0 bytes for now to minimise the failure
    // surface during initial wiring; a future commit can randomise it.
    let our_garbage: Vec<u8> = Vec::new();

    // ----- Step 3: send our pubkey + garbage. -----
    let our_pubkey_bytes = *cipher.our_pubkey().as_bytes();
    if writer.write_all(&our_pubkey_bytes).await.is_err()
        || writer.write_all(&our_garbage).await.is_err()
    {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError(
                    "v2 handshake: failed to send pubkey + garbage".to_string(),
                ),
            ))
            .await;
        return;
    }

    // ----- Step 4: send garbage terminator + encrypted version packet. -----
    // The version packet has zero-byte contents per BIP-324; our
    // garbage is the AAD so the peer can authenticate it received our
    // garbage unchanged.
    let our_garbage_term = *cipher.send_garbage_terminator();
    let mut version_packet = vec![0u8; EXPANSION]; // contents.len()==0, so EXPANSION = LENGTH_LEN+HEADER_LEN+TAG_LEN
    if let Err(e) = cipher.encrypt(&[], &our_garbage, false, &mut version_packet) {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::HandshakeFailed(format!(
                    "v2 handshake: failed to encrypt version packet: {}",
                    e
                )),
            ))
            .await;
        return;
    }
    if writer.write_all(&our_garbage_term).await.is_err()
        || writer.write_all(&version_packet).await.is_err()
        || writer.flush().await.is_err()
    {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError(
                    "v2 handshake: failed to send terminator/version packet".to_string(),
                ),
            ))
            .await;
        return;
    }

    // ----- Step 5: scan inbound for the peer's garbage terminator. -----
    let recv_garbage_term = *cipher.recv_garbage_terminator();
    let mut their_garbage: Vec<u8> = Vec::new();
    let scan_result = timeout(handshake_timeout, async {
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
            // Only check once we have at least GARBAGE_TERMINATOR_LEN bytes.
            if their_garbage.len() >= GARBAGE_TERMINATOR_LEN {
                let tail_start = their_garbage.len() - GARBAGE_TERMINATOR_LEN;
                if their_garbage[tail_start..] == recv_garbage_term {
                    // Strip the terminator so the remaining bytes are
                    // pure garbage (used as AAD for decrypting the
                    // version packet).
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
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::HandshakeFailed(format!(
                        "v2 handshake: garbage scan failed: {}",
                        e
                    )),
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
    }

    // ----- Step 6: decrypt the peer's version packet. -----
    let mut enc_len = [0u8; LENGTH_LEN];
    if timeout(handshake_timeout, reader.read_exact(&mut enc_len))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError(
                    "v2 handshake: failed to read encrypted length".to_string(),
                ),
            ))
            .await;
        return;
    }
    let plain_len = match cipher.decrypt_length(&enc_len) {
        Ok(n) => n as usize,
        Err(e) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::HandshakeFailed(format!(
                        "v2 handshake: length decrypt failed: {}",
                        e
                    )),
                ))
                .await;
            return;
        }
    };
    if plain_len > MAX_MESSAGE_SIZE {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ProtocolError(
                    "v2 handshake: version packet too large".to_string(),
                ),
            ))
            .await;
        return;
    }

    let total_aead = HEADER_LEN + plain_len + 16; // 16 = TAG_LEN; constant inlined to avoid pulling another import
    let mut aead_buf = vec![0u8; total_aead];
    if timeout(handshake_timeout, reader.read_exact(&mut aead_buf))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError(
                    "v2 handshake: failed to read encrypted version packet".to_string(),
                ),
            ))
            .await;
        return;
    }

    let mut contents = vec![0u8; plain_len];
    if let Err(e) = cipher.decrypt(&aead_buf, &their_garbage, &mut contents) {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::HandshakeFailed(format!(
                    "v2 handshake: version packet AEAD decrypt failed: {}",
                    e
                )),
            ))
            .await;
        return;
    }

    // ----- Cipher handshake complete. -----
    tracing::info!(
        "peer {:?} ({}): BIP-324 v2 cipher handshake COMPLETE \
         (session_id={}, their_garbage={} bytes, version_packet={} bytes)",
        peer_id,
        addr,
        hex::encode(cipher.session_id()),
        their_garbage.len(),
        plain_len,
    );

    // ----- Application-layer version/verack over the cipher. -----
    //
    // BIP-324 §"Wire format": after both sides have decrypted the empty
    // version packet exchanged during the cipher handshake (which exists
    // only to AEAD-authenticate the garbage), the application protocol
    // resumes exactly as in v1 — a peer-initiated VERSION followed by
    // SENDADDRV2 / WTXIDRELAY / VERACK in either direction — except
    // every message is now framed through `Bip324Cipher.encrypt` /
    // `decrypt`.  As the responder we wait for the peer's VERSION first.
    let app_hs = match timeout(
        handshake_timeout,
        crate::peer::perform_v2_handshake_inbound(
            &mut cipher,
            &mut reader,
            &mut writer,
            &magic,
            our_services,
            our_start_height,
            _our_nonce,
            addr,
        ),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(reason)) => {
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

    let their_version = app_hs.version;
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
        inbound: true,
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
        supports_wtxid_relay: app_hs.wants_wtxid_relay,
        supports_addrv2: app_hs.wants_addrv2,
        feefilter: 0,
    };

    let stats = std::sync::Arc::new(crate::peer::PeerStats::new());
    stats.mark_connected();

    let _ = event_tx
        .send(PeerEvent::Connected(
            peer_id,
            peer_info,
            std::sync::Arc::clone(&stats),
        ))
        .await;

    tracing::info!(
        "peer {:?} ({}): BIP-324 v2 application handshake COMPLETE \
         (ua=\"{}\", version={})",
        peer_id,
        addr,
        their_version.user_agent,
        their_version.version,
    );

    // ----- Main v2 message loop over the cipher. -----
    crate::peer::run_message_loop_v2_tracked(
        peer_id,
        &magic,
        cipher,
        reader,
        writer,
        event_tx,
        _command_rx,
        stats,
    )
    .await;
}

// ============================================================
// ANCHOR CONNECTION PERSISTENCE
// ============================================================

/// Read anchor connections from disk.
///
/// Anchors are block-relay-only peers persisted across restarts to provide
/// eclipse attack resistance. The file is deleted after reading to prevent
/// stale data from being used on subsequent restarts without new anchors.
pub fn read_anchors(data_dir: &std::path::Path) -> Vec<SocketAddr> {
    let path = data_dir.join(ANCHORS_DATABASE_FILENAME);

    if !path.exists() {
        return Vec::new();
    }

    let result = (|| -> Result<Vec<SocketAddr>, std::io::Error> {
        let mut file = fs::File::open(&path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut anchors = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(addr) = line.parse::<SocketAddr>() {
                anchors.push(addr);
            }
        }

        // Delete the file after reading (matches Bitcoin Core behavior)
        // This prevents stale anchors from being used on multiple restarts
        let _ = fs::remove_file(&path);

        Ok(anchors)
    })();

    match result {
        Ok(anchors) => {
            if !anchors.is_empty() {
                tracing::debug!("Read {} anchors from {}", anchors.len(), path.display());
            }
            anchors
        }
        Err(e) => {
            tracing::warn!("Failed to read anchors from {}: {}", path.display(), e);
            Vec::new()
        }
    }
}

/// Write anchor connections to disk.
///
/// Persists block-relay-only peer addresses for use on next startup.
pub fn dump_anchors(data_dir: &std::path::Path, anchors: &[SocketAddr]) {
    let path = data_dir.join(ANCHORS_DATABASE_FILENAME);

    let result = (|| -> Result<(), std::io::Error> {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(&path)?;
        writeln!(file, "# Anchor connections for eclipse attack resistance")?;
        writeln!(
            file,
            "# These block-relay-only peers will be reconnected on startup"
        )?;
        writeln!(file, "# This file is automatically deleted after reading")?;

        for addr in anchors.iter().take(MAX_BLOCK_RELAY_ONLY_ANCHORS) {
            writeln!(file, "{}", addr)?;
        }

        Ok(())
    })();

    if let Err(e) = result {
        tracing::warn!("Failed to write anchors to {}: {}", path.display(), e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_config_default() {
        let config = PeerManagerConfig::default();
        assert_eq!(config.max_outbound_full_relay, 8);
        assert_eq!(config.max_inbound, 117);
        assert_eq!(config.max_total, 125);
        assert_eq!(config.ban_duration, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.listen_port, 8333);
        assert!(config.listen);
    }

    #[test]
    fn test_peer_manager_config_testnet4() {
        let config = PeerManagerConfig::testnet4();
        assert_eq!(config.listen_port, 48333);
        assert_eq!(config.max_outbound(), 10); // 8 full-relay + 2 block-relay-only
    }

    // ----- W117 BUG-2 proxy / reachability wiring -----

    #[test]
    fn w117_default_config_has_no_proxy() {
        let cfg = PeerManagerConfig::default();
        assert!(cfg.tor_proxy.is_none());
        assert!(cfg.onion_proxy.is_none());
        assert!(cfg.i2p_sam.is_none());
        assert!(!cfg.cjdns_reachable);
    }

    #[test]
    fn w117_is_reachable_clearnet_always_true() {
        let cfg = PeerManagerConfig::default();
        assert!(
            cfg.is_reachable(&crate::addr::NetworkAddr::Ipv4(std::net::Ipv4Addr::new(
                8, 8, 8, 8
            )))
        );
        assert!(cfg.is_reachable(&crate::addr::NetworkAddr::Ipv6(
            "2001:db8::1".parse().unwrap()
        )));
    }

    #[test]
    fn w117_is_reachable_tor_requires_proxy() {
        let mut cfg = PeerManagerConfig::default();
        let tor = crate::addr::NetworkAddr::TorV3([0x42; 32]);
        assert!(!cfg.is_reachable(&tor));

        cfg.onion_proxy = Some("127.0.0.1:9050".parse().unwrap());
        assert!(cfg.is_reachable(&tor));

        cfg.onion_proxy = None;
        cfg.tor_proxy = Some("127.0.0.1:1080".parse().unwrap());
        assert!(cfg.is_reachable(&tor));
    }

    #[test]
    fn w117_is_reachable_i2p_requires_sam() {
        let mut cfg = PeerManagerConfig::default();
        let i2p = crate::addr::NetworkAddr::I2P([0xab; 32]);
        assert!(!cfg.is_reachable(&i2p));

        cfg.i2p_sam = Some("127.0.0.1:7656".parse().unwrap());
        assert!(cfg.is_reachable(&i2p));
    }

    #[test]
    fn w117_is_reachable_cjdns_requires_flag() {
        let mut cfg = PeerManagerConfig::default();
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfc;
        let cjdns = crate::addr::NetworkAddr::Cjdns(bytes);
        assert!(!cfg.is_reachable(&cjdns));

        cfg.cjdns_reachable = true;
        assert!(cfg.is_reachable(&cjdns));
    }

    #[test]
    fn w117_build_proxy_config_propagates_fields() {
        let cfg = PeerManagerConfig {
            tor_proxy: Some("127.0.0.1:1080".parse().unwrap()),
            onion_proxy: Some("127.0.0.1:9050".parse().unwrap()),
            i2p_sam: Some("127.0.0.1:7656".parse().unwrap()),
            cjdns_reachable: true,
            ..Default::default()
        };
        let pc = cfg.build_proxy_config();
        assert_eq!(
            pc.socks5_proxy,
            Some("127.0.0.1:1080".parse().unwrap()),
            "tor_proxy must populate ProxyConfig.socks5_proxy"
        );
        assert_eq!(
            pc.onion_proxy,
            Some("127.0.0.1:9050".parse().unwrap()),
            "onion_proxy must propagate"
        );
        assert_eq!(
            pc.i2p_sam,
            Some("127.0.0.1:7656".parse().unwrap()),
            "i2p_sam must propagate"
        );
        // Stream isolation is on by default whenever a Tor/clearnet proxy is set.
        assert!(pc.tor_stream_isolation);
    }

    #[test]
    fn w117_target_for_handle_resolves_per_variant() {
        // IPv4 → real socket addr
        let sa = target_for_handle(
            &crate::addr::NetworkAddr::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            8333,
        );
        assert!(matches!(sa.ip(), IpAddr::V4(_)));
        assert_eq!(sa.port(), 8333);

        // CJDNS → real IPv6
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfc;
        let sa = target_for_handle(&crate::addr::NetworkAddr::Cjdns(bytes), 8333);
        assert!(matches!(sa.ip(), IpAddr::V6(_)));
        assert_eq!(sa.port(), 8333);

        // Tor / I2P → unspecified placeholder
        let sa = target_for_handle(&crate::addr::NetworkAddr::TorV3([0u8; 32]), 8333);
        assert!(sa.ip().is_unspecified());
        let sa = target_for_handle(&crate::addr::NetworkAddr::I2P([0u8; 32]), 8333);
        assert!(sa.ip().is_unspecified());
    }

    #[tokio::test]
    async fn w117_connect_to_addrv2_skips_unreachable_tor() {
        // Without an onion/tor proxy, calling connect_to_addrv2 on a Tor v3
        // peer must be a no-op (no peer handle inserted, no panic, no spawn).
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);
        let before = mgr.peers.len();

        mgr.connect_to_addrv2(
            crate::addr::NetworkAddr::TorV3([0x42; 32]),
            8333,
            ConnectionType::FullRelay,
        )
        .await;

        assert_eq!(mgr.peers.len(), before, "no handle should be inserted");
    }

    #[tokio::test]
    async fn w117_connect_to_addrv2_skips_unreachable_i2p() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);
        let before = mgr.peers.len();

        mgr.connect_to_addrv2(
            crate::addr::NetworkAddr::I2P([0xab; 32]),
            8333,
            ConnectionType::FullRelay,
        )
        .await;

        assert_eq!(mgr.peers.len(), before, "no handle should be inserted");
    }

    #[test]
    fn test_address_manager_add_dns_addresses() {
        let mut mgr = AddressManager::new();
        let addrs = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "192.168.1.2:8333".parse().unwrap(),
            "192.168.1.3:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs);

        assert_eq!(mgr.known_count(), 3);
        assert_eq!(mgr.queue_size(), 3);
    }

    #[test]
    fn test_address_manager_next_addr_to_try() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        // Use different /16 subnets to avoid netgroup diversity blocking
        let addrs: Vec<SocketAddr> = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "10.0.0.1:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        let first = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(first, Some(addrs[0]));

        let second = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(second, Some(addrs[1]));

        let third = mgr.next_addr_to_try(&netgroup_mgr);
        assert!(third.is_none());
    }

    #[test]
    fn test_address_manager_ban() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        assert!(!mgr.is_banned(&addr));
        mgr.ban(&addr, Duration::from_secs(3600));
        assert!(mgr.is_banned(&addr));

        // Banned address should be skipped
        assert!(mgr.next_addr_to_try(&netgroup_mgr).is_none());
    }

    #[test]
    fn test_address_manager_mark_success() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        // Get the address (this increments attempt_count)
        let _ = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(mgr.known_addrs.get(&addr).unwrap().attempt_count, 1);

        // Mark as successful
        mgr.mark_success(&addr);
        assert_eq!(mgr.known_addrs.get(&addr).unwrap().attempt_count, 0);
        assert!(mgr.known_addrs.get(&addr).unwrap().last_success.is_some());
        assert!(mgr.connected.contains(&addr));
    }

    #[test]
    fn test_address_manager_mark_disconnected() {
        let mut mgr = AddressManager::new();
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);
        mgr.mark_success(&addr);

        assert!(mgr.connected.contains(&addr));
        mgr.mark_disconnected(&addr);
        assert!(!mgr.connected.contains(&addr));
    }

    #[test]
    fn test_address_manager_connected_addresses_skipped() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        // Mark as connected
        mgr.mark_success(&addr);

        // Re-add to queue
        mgr.try_queue.push_back(addr);

        // Should skip connected address
        assert!(mgr.next_addr_to_try(&netgroup_mgr).is_none());
    }

    #[test]
    fn test_address_manager_manual_address_priority() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        // Use different /16 subnets
        let dns_addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let manual_addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();

        mgr.add_dns_addresses(vec![dns_addr]);
        mgr.add_manual_address(manual_addr);

        // Manual address should be tried first
        assert_eq!(mgr.next_addr_to_try(&netgroup_mgr), Some(manual_addr));
        assert_eq!(mgr.next_addr_to_try(&netgroup_mgr), Some(dns_addr));
    }

    #[test]
    fn test_netgroup_diversity_enforcement() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        // Add addresses in the same /16 subnet
        let addrs: Vec<SocketAddr> = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "192.168.1.2:8333".parse().unwrap(),
            "192.168.1.3:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        // First address should succeed
        let first = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(first, Some(addrs[0]));

        // Mark the first as connected (this adds netgroup to tracking)
        mgr.mark_outbound_success(&addrs[0], &netgroup_mgr);

        // Other addresses in same /16 should be skipped
        let second = mgr.next_addr_to_try(&netgroup_mgr);
        assert!(second.is_none()); // All remaining are same netgroup
    }

    #[test]
    fn test_netgroup_diversity_allows_different_groups() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        // Add addresses in different /16 subnets (publicly routable — RFC 1918
        // ranges are now all Unroutable and would share the same netgroup).
        let addrs: Vec<SocketAddr> = vec![
            "1.2.3.4:8333".parse().unwrap(),    // 1.2.0.0/16
            "5.6.7.8:8333".parse().unwrap(),    // 5.6.0.0/16
            "9.10.11.12:8333".parse().unwrap(), // 9.10.0.0/16
        ];
        mgr.add_dns_addresses(addrs.clone());

        // All should be allowed since they're in different netgroups
        for expected in &addrs {
            let addr = mgr.next_addr_to_try(&netgroup_mgr);
            assert_eq!(addr, Some(*expected));
            mgr.mark_outbound_success(expected, &netgroup_mgr);
        }
    }

    // ── Regression: AddrMan re-selection after try_queue drain ──────────────
    //
    // Mainnet incident 2026-05-19: rustoshi wedged 13+ h at h=948304 with
    // `peers=0`. Root cause: `try_queue` is a one-shot consume queue, so once
    // it drained (every connect attempt `pop_front`s and never re-queues) the
    // node could open no further outbound connections, and with 0 peers no
    // `addr` messages arrived to refill the queue — a permanent deadlock.
    // `next_addr_to_try` must fall back to re-selecting from the persistent
    // `known_addrs` store, like Core's non-consuming `AddrMan::Select_`.

    /// After the try_queue is fully drained, a known, non-connected,
    /// netgroup-free address is still re-selectable from the persistent store.
    #[test]
    fn test_addr_reselectable_after_queue_drain() {
        let mut mgr = AddressManager::new();
        let ng = NetGroupManager::with_key(12345);
        // One publicly-routable address (RFC1918 ranges collapse to the same
        // Unroutable netgroup, which would mask the re-selection behaviour).
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        // Stage-1 fast path drains the queue.
        assert_eq!(mgr.next_addr_to_try(&ng), Some(addr));
        assert_eq!(mgr.queue_size(), 0, "queue must be drained");

        // The address was attempted but never connected: a fresh attempt is
        // gated by the failure backoff, so an immediate re-select is None …
        assert!(
            mgr.next_addr_to_try(&ng).is_none(),
            "address within retry backoff must not be re-selected yet"
        );

        // … but once the backoff has elapsed, stage-2 re-selects it from the
        // persistent store. Simulate elapsed time by ageing last_attempt.
        let info = mgr.known_addrs.get_mut(&addr).unwrap();
        info.last_attempt = Some(Instant::now() - Duration::from_secs(3600));
        assert_eq!(
            mgr.next_addr_to_try(&ng),
            Some(addr),
            "address must be re-selectable from the persistent store after backoff"
        );
    }

    /// The pre-fix failure mode: connect to every known address, disconnect
    /// them all, and confirm the AddrMan can still hand back a candidate.
    /// Before the fix this returned None forever (zero-peer deadlock).
    #[test]
    fn test_addr_not_starved_after_connect_disconnect_cycle() {
        let mut mgr = AddressManager::new();
        let ng = NetGroupManager::with_key(12345);
        // Distinct /16s so netgroup diversity never blocks the candidates.
        let addrs: Vec<SocketAddr> = vec![
            "1.2.3.4:8333".parse().unwrap(),
            "5.6.7.8:8333".parse().unwrap(),
            "9.10.11.12:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        // Connect to all of them (drains the queue), then disconnect all.
        for _ in &addrs {
            let picked = mgr.next_addr_to_try(&ng).expect("queue has addresses");
            mgr.mark_outbound_success(&picked, &ng);
        }
        for a in &addrs {
            mgr.mark_outbound_disconnected(a, &ng);
        }
        assert_eq!(mgr.queue_size(), 0, "queue drained by the connect cycle");
        assert_eq!(mgr.connected_count(), 0, "all peers disconnected");

        // Age last_attempt past the backoff window to model the 45s
        // maintenance tick firing well after the disconnects.
        for a in &addrs {
            mgr.known_addrs.get_mut(a).unwrap().last_attempt =
                Some(Instant::now() - Duration::from_secs(3600));
        }

        // The AddrMan must still produce a connectable candidate — this is
        // exactly what fill_outbound_connections needs to escape peers=0.
        let recovered = mgr.next_addr_to_try(&ng);
        assert!(
            recovered.is_some(),
            "AddrMan starved: no candidate after connect/disconnect cycle (zero-peer deadlock)"
        );
        assert!(addrs.contains(&recovered.unwrap()));
    }

    /// Banned and currently-connected addresses are still excluded by the
    /// stage-2 fallback, not just the stage-1 queue path.
    #[test]
    fn test_addr_fallback_excludes_banned_and_connected() {
        let mut mgr = AddressManager::new();
        let ng = NetGroupManager::with_key(12345);
        let banned: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let connected: SocketAddr = "5.6.7.8:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![banned, connected]);

        // Drain the queue, then make one banned and one connected.
        let _ = mgr.next_addr_to_try(&ng);
        let _ = mgr.next_addr_to_try(&ng);
        mgr.ban(&banned, Duration::from_secs(3600));
        mgr.mark_outbound_success(&connected, &ng);

        // Age last_attempt so backoff would otherwise allow re-selection.
        for a in [banned, connected] {
            mgr.known_addrs.get_mut(&a).unwrap().last_attempt =
                Some(Instant::now() - Duration::from_secs(3600));
        }

        // Neither is eligible: banned is excluded, connected is excluded.
        assert!(
            mgr.next_addr_to_try(&ng).is_none(),
            "stage-2 fallback must exclude banned and connected addresses"
        );
    }

    #[test]
    fn test_address_manager_get_addresses_for_sharing() {
        let mut mgr = AddressManager::new();
        let addrs = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "192.168.1.2:8333".parse().unwrap(),
            "192.168.1.3:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        // No successful connections yet
        assert!(mgr.get_addresses_for_sharing(10).is_empty());

        // Mark one as successful
        mgr.mark_success(&addrs[0]);
        let shared = mgr.get_addresses_for_sharing(10);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].addr, addrs[0]);
    }

    #[test]
    fn test_net_address_to_socket_addr_ipv4() {
        let net_addr = NetAddress::from_ipv4([192, 168, 1, 1], 8333, NODE_NETWORK);
        let socket_addr = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, "192.168.1.1:8333".parse().unwrap());
    }

    #[test]
    fn test_net_address_to_socket_addr_ipv6() {
        let net_addr = NetAddress {
            services: NODE_NETWORK,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 8333,
        };
        let socket_addr = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, "[::1]:8333".parse().unwrap());
    }

    #[test]
    fn test_socket_addr_to_net_address_roundtrip_ipv4() {
        let socket_addr: SocketAddr = "10.0.0.1:48333".parse().unwrap();
        let net_addr = socket_addr_to_net_address(socket_addr, NODE_NETWORK | NODE_WITNESS);
        let back = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, back);
        assert_eq!(net_addr.services, NODE_NETWORK | NODE_WITNESS);
        assert_eq!(net_addr.port, 48333);
    }

    #[test]
    fn test_socket_addr_to_net_address_roundtrip_ipv6() {
        let socket_addr: SocketAddr = "[2001:db8::1]:8333".parse().unwrap();
        let net_addr = socket_addr_to_net_address(socket_addr, NODE_NETWORK);
        let back = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, back);
    }

    #[test]
    fn test_peer_manager_build_version_message() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        let version = mgr.build_version_message(addr);

        assert_eq!(version.version, PROTOCOL_VERSION);
        assert!(version.services & NODE_NETWORK != 0);
        assert!(version.services & NODE_WITNESS != 0);
        assert_eq!(version.user_agent, "/Rustoshi:0.1.0/");
        assert_eq!(version.start_height, 0);
        assert!(version.relay);
    }

    /// BIP 35 / NODE_BLOOM: by default `peer_bloom_filters=false` (matching
    /// Bitcoin Core's `DEFAULT_PEERBLOOMFILTERS=false` in `net_processing.h:44`),
    /// so our outbound version messages (and `local_services()`) must NOT
    /// include the NODE_BLOOM bit.
    #[test]
    fn test_node_bloom_disabled_by_default() {
        let config = PeerManagerConfig::testnet4();
        assert!(
            !config.peer_bloom_filters,
            "peer_bloom_filters default should be false (Core parity)"
        );

        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        assert!(!mgr.peer_bloom_filters_enabled());
        let services = mgr.local_services();
        assert_eq!(
            services & NODE_BLOOM,
            0,
            "NODE_BLOOM must NOT be advertised by default"
        );
        assert!(services & NODE_NETWORK != 0);
        assert!(services & NODE_WITNESS != 0);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        let version = mgr.build_version_message(addr);
        assert_eq!(
            version.services & NODE_BLOOM,
            0,
            "outbound version message must NOT include NODE_BLOOM by default"
        );
        assert_eq!(
            version.addr_from.services & NODE_BLOOM,
            0,
            "addr_from in version must NOT include NODE_BLOOM by default"
        );
    }

    /// When `-peerbloomfilters=true`, the operator opts INTO BIP 35 + BIP 37.
    /// NODE_BLOOM must appear on the wire and the gate in the MEMPOOL handler
    /// must allow the request.
    #[test]
    fn test_node_bloom_enabled_via_config() {
        let mut config = PeerManagerConfig::testnet4();
        config.peer_bloom_filters = true;
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        assert!(mgr.peer_bloom_filters_enabled());
        let services = mgr.local_services();
        assert!(
            services & NODE_BLOOM != 0,
            "NODE_BLOOM must be set when explicitly enabled"
        );
        assert!(services & NODE_NETWORK != 0);
        assert!(services & NODE_WITNESS != 0);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        let version = mgr.build_version_message(addr);
        assert!(version.services & NODE_BLOOM != 0);
        assert!(version.addr_from.services & NODE_BLOOM != 0);
    }

    /// BIP-159: NODE_NETWORK_LIMITED (1 << 10) MUST be advertised even when
    /// prune mode is off. Core seeds `g_local_services` with
    /// `NODE_NETWORK_LIMITED | NODE_WITNESS` unconditionally (`init.cpp:863`)
    /// and adds NODE_NETWORK in non-prune mode (`init.cpp:1950`), so a full
    /// non-pruned node advertises NODE_NETWORK | NODE_WITNESS |
    /// NODE_NETWORK_LIMITED. (Regression test: previously this asserted the
    /// bit was OMITTED when prune was off, which under-advertised vs. Core.)
    #[test]
    fn test_node_network_limited_advertised_by_default() {
        let config = PeerManagerConfig::testnet4();
        assert!(!config.prune_mode);
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        let services = mgr.local_services();
        assert!(
            services & NODE_NETWORK_LIMITED != 0,
            "NODE_NETWORK_LIMITED must be advertised unconditionally for a full node (Core init.cpp:863)"
        );
        // Non-pruned full node also keeps NODE_NETWORK set.
        assert!(services & NODE_NETWORK != 0);
        assert!(services & NODE_WITNESS != 0);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        let version = mgr.build_version_message(addr);
        assert!(version.services & NODE_NETWORK_LIMITED != 0);
        assert!(version.addr_from.services & NODE_NETWORK_LIMITED != 0);
    }

    /// Full-node honest service-flag set: a default (non-pruned, v2-default-on)
    /// rustoshi node must advertise exactly
    /// `0xC09 = NODE_NETWORK(0x1) | NODE_WITNESS(0x8) |
    ///          NODE_NETWORK_LIMITED(0x400) | NODE_P2P_V2(0x800)`.
    /// NODE_BLOOM and NODE_COMPACT_FILTERS are config-gated off by default, so
    /// they must be absent. Mirrors Core's `g_local_services` for a full node
    /// with `-v2transport` on (`init.cpp:863`/`989`/`1950`).
    #[test]
    fn test_local_services_full_node_is_0xc09() {
        // v2 outbound defaults ON; ensure no env override is in effect so the
        // P2P_V2 bit is present, matching the default production config.
        let prior = std::env::var("RUSTOSHI_BIP324_V2_OUTBOUND").ok();
        std::env::remove_var("RUSTOSHI_BIP324_V2_OUTBOUND");

        let config = PeerManagerConfig::testnet4();
        assert!(!config.prune_mode, "default must be non-pruned");
        assert!(!config.peer_bloom_filters, "NODE_BLOOM must default off");
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        let services = mgr.local_services();
        let expected = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2;
        assert_eq!(
            services, expected,
            "full-node local_services() must be exactly 0xC09 \
             (NETWORK|WITNESS|NETWORK_LIMITED|P2P_V2); got {:#x}",
            services
        );
        // Spell out the individual honest bits for clarity.
        assert!(services & NODE_NETWORK != 0, "NODE_NETWORK (full node)");
        assert!(services & NODE_WITNESS != 0, "NODE_WITNESS (witness node)");
        assert!(
            services & NODE_NETWORK_LIMITED != 0,
            "NODE_NETWORK_LIMITED (unconditional, Core init.cpp:863)"
        );
        assert!(
            services & NODE_P2P_V2 != 0,
            "NODE_P2P_V2 (BIP-324 v2 default-on, genuinely implemented)"
        );
        // Honesty: bits we do NOT genuinely support by default stay off.
        assert_eq!(services & NODE_BLOOM, 0, "NODE_BLOOM off by default");
        assert_eq!(
            services & NODE_COMPACT_FILTERS,
            0,
            "NODE_COMPACT_FILTERS off by default"
        );

        // Restore the env var to whatever it was before the test.
        if let Some(v) = prior {
            std::env::set_var("RUSTOSHI_BIP324_V2_OUTBOUND", v);
        }
    }

    /// BIP-159: when prune mode is enabled the version handshake must
    /// advertise NODE_NETWORK_LIMITED so peers don't request pre-prune-horizon
    /// blocks. Core also advertises NODE_NETWORK alongside it (the node still
    /// has the recent-288 archive), so we keep NODE_NETWORK set as well.
    #[test]
    fn test_node_network_limited_advertised_when_prune_on() {
        let mut config = PeerManagerConfig::testnet4();
        config.prune_mode = true;
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        let services = mgr.local_services();
        assert!(
            services & NODE_NETWORK_LIMITED != 0,
            "NODE_NETWORK_LIMITED must be advertised when prune_mode=true"
        );
        // Core keeps NODE_NETWORK set in the auto-prune case too.
        assert!(services & NODE_NETWORK != 0);
        assert!(services & NODE_WITNESS != 0);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        let version = mgr.build_version_message(addr);
        assert!(version.services & NODE_NETWORK_LIMITED != 0);
        assert!(version.addr_from.services & NODE_NETWORK_LIMITED != 0);
    }

    #[test]
    fn test_address_manager_expire_bans() {
        let mut mgr = AddressManager::new();
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();

        // Ban with zero duration (already expired)
        mgr.banned
            .insert(addr, Instant::now() - Duration::from_secs(1));
        assert_eq!(mgr.banned_count(), 1);

        mgr.expire_bans();
        assert_eq!(mgr.banned_count(), 0);
    }

    #[test]
    fn test_address_manager_add_peer_addresses() {
        let mut mgr = AddressManager::new();
        // Use a routable source address (not RFC 1918 — those are filtered by
        // the W104 IsRoutable fix).
        let from: SocketAddr = "8.8.8.8:8333".parse().unwrap();

        let addrs = vec![
            TimestampedNetAddress {
                timestamp: 1700000000,
                address: NetAddress::from_ipv4([1, 2, 3, 4], 8333, NODE_NETWORK),
            },
            TimestampedNetAddress {
                timestamp: 1700000001,
                address: NetAddress::from_ipv4([5, 6, 7, 8], 8333, NODE_NETWORK | NODE_WITNESS),
            },
        ];

        mgr.add_peer_addresses(&addrs, from);

        assert_eq!(mgr.known_count(), 2);
        let info = mgr
            .known_addrs
            .get(&"1.2.3.4:8333".parse().unwrap())
            .unwrap();
        assert_eq!(info.source, AddrSource::Peer(from));
    }

    #[tokio::test]
    async fn test_peer_manager_creation() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        assert_eq!(mgr.peer_count(), 0);
        assert_eq!(mgr.outbound_count(), 0);
        assert_eq!(mgr.inbound_count(), 0);
    }

    #[tokio::test]
    async fn test_peer_manager_add_peer() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        mgr.add_peer(addr);

        assert_eq!(mgr.addr_manager.known_count(), 1);
        assert_eq!(mgr.addr_manager.queue_size(), 1);
    }

    #[tokio::test]
    async fn test_peer_manager_set_start_height() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        mgr.set_start_height(100000);
        let version = mgr.build_version_message("192.168.1.1:8333".parse().unwrap());
        assert_eq!(version.start_height, 100000);
    }

    #[tokio::test]
    async fn test_dns_seed_resolution_timeout() {
        // Test that DNS resolution handles failures gracefully
        let addrs = resolve_dns_seeds(&["nonexistent.invalid.domain"], 8333).await;
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn test_peer_manager_misbehavior_tracking() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(1);

        // Initial score should be 0
        assert_eq!(mgr.get_misbehavior_score(peer_id), 0);

        // Single-event (Core PR #25974): first Misbehaving call discourages immediately.
        let banned = mgr
            .misbehaving(peer_id, MisbehaviorReason::InvalidTransaction)
            .await;
        assert!(banned, "single-event: first call must return true");
        assert_eq!(mgr.get_misbehavior_score(peer_id), 10);

        // Subsequent calls accumulate score for log context.
        mgr.misbehaving(peer_id, MisbehaviorReason::InvalidTransaction)
            .await;
        mgr.misbehaving(peer_id, MisbehaviorReason::InvalidTransaction)
            .await;
        assert_eq!(mgr.get_misbehavior_score(peer_id), 30);
    }

    #[tokio::test]
    async fn test_peer_manager_misbehavior_instant_ban() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(1);

        // Invalid block header = 100 points = instant ban
        let banned = mgr
            .misbehaving(peer_id, MisbehaviorReason::InvalidBlockHeader)
            .await;
        assert!(banned);
        assert_eq!(mgr.get_misbehavior_score(peer_id), 100);
    }

    #[tokio::test]
    async fn test_peer_manager_ban_and_unban() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

        assert!(!mgr.is_banned(&ip));

        mgr.ban_ip(ip, Duration::from_secs(3600), "test ban".to_string());
        assert!(mgr.is_banned(&ip));

        assert!(mgr.unban(&ip));
        assert!(!mgr.is_banned(&ip));
    }

    #[tokio::test]
    async fn test_peer_manager_list_banned() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: std::net::IpAddr = "192.168.1.2".parse().unwrap();

        mgr.ban_ip(ip1, Duration::from_secs(3600), "test1".to_string());
        mgr.ban_ip(ip2, Duration::from_secs(3600), "test2".to_string());

        let banned = mgr.list_banned();
        assert_eq!(banned.len(), 2);
    }

    #[tokio::test]
    async fn test_peer_manager_misbehaving_with_score() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(1);

        // Single-event (Core PR #25974): first call discourages immediately.
        let banned = mgr
            .misbehaving_with_score(peer_id, 50, "custom violation")
            .await;
        assert!(
            banned,
            "single-event: first misbehaving_with_score must return true"
        );
        assert_eq!(mgr.get_misbehavior_score(peer_id), 50);

        // Subsequent calls accumulate score for log context.
        let banned = mgr
            .misbehaving_with_score(peer_id, 50, "another violation")
            .await;
        assert!(banned);
        assert_eq!(mgr.get_misbehavior_score(peer_id), 100);
    }

    /// `PeerEvent::Misbehaving` flowing through `handle_event` must
    /// discourage immediately on the first call — single-event model (Core PR #25974).
    #[tokio::test]
    async fn test_handle_event_misbehaving_wires_into_tracker_and_ban() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(42);

        // Single-event (Core PR #25974): first PeerEvent::Misbehaving discourages immediately.
        assert_eq!(mgr.get_misbehavior_score(peer_id), 0);
        mgr.handle_event(PeerEvent::Misbehaving(
            peer_id,
            MisbehaviorReason::UnsolicitedMessage,
        ))
        .await;
        assert_eq!(
            mgr.get_misbehavior_score(peer_id),
            20,
            "score accumulated to 20 (for logging)"
        );

        // Subsequent calls keep accumulating score for log context.
        for _ in 0..4 {
            mgr.handle_event(PeerEvent::Misbehaving(
                peer_id,
                MisbehaviorReason::UnsolicitedMessage,
            ))
            .await;
        }
        assert_eq!(mgr.get_misbehavior_score(peer_id), 100);
    }

    /// `PeerEvent::Misbehaving` carrying an instant-ban reason
    /// (InvalidBlockHeader = 100 pts) should ban on the very first hit.
    #[tokio::test]
    async fn test_handle_event_misbehaving_instant_ban_on_threshold() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(7);
        mgr.handle_event(PeerEvent::Misbehaving(
            peer_id,
            MisbehaviorReason::InvalidBlockHeader,
        ))
        .await;

        assert_eq!(mgr.get_misbehavior_score(peer_id), 100);
        // Banlist is the source-of-truth that's checked at accept time.
        // We can't easily ban a peer without a registered PeerHandle, but
        // we can confirm that the tracker hit threshold (the actual ban
        // call only fires when the peer is registered + has a known
        // SocketAddr; the score path here is what matters for the
        // production wire-up).
    }

    #[test]
    fn test_anchor_persistence() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        let anchors: Vec<SocketAddr> = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "10.0.0.1:8333".parse().unwrap(),
        ];

        // Write anchors
        dump_anchors(&data_dir, &anchors);

        // Read them back
        let loaded = read_anchors(&data_dir);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&anchors[0]));
        assert!(loaded.contains(&anchors[1]));

        // File should be deleted after reading
        let anchor_path = data_dir.join(ANCHORS_DATABASE_FILENAME);
        assert!(!anchor_path.exists());
    }

    #[test]
    fn test_anchor_limits() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        // Try to write more than MAX_BLOCK_RELAY_ONLY_ANCHORS
        let anchors: Vec<SocketAddr> = (0..10)
            .map(|i| format!("192.168.{}.1:8333", i).parse().unwrap())
            .collect();

        dump_anchors(&data_dir, &anchors);

        let loaded = read_anchors(&data_dir);
        // Should only have MAX_BLOCK_RELAY_ONLY_ANCHORS (2)
        assert_eq!(loaded.len(), MAX_BLOCK_RELAY_ONLY_ANCHORS);
    }

    #[test]
    fn test_read_anchors_nonexistent() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        // Reading from non-existent file should return empty vec
        let loaded = read_anchors(&data_dir);
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_outbound_netgroup_tracking() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        // Use publicly routable addresses — RFC 1918 (192.168/16, 10/8) are now
        // all classified as Unroutable and would share a single netgroup.
        let addr1: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let addr2: SocketAddr = "1.2.4.5:8333".parse().unwrap(); // Same /16 (1.2.0.0/16)
        let addr3: SocketAddr = "5.6.7.8:8333".parse().unwrap(); // Different /16

        // Initially no outbound netgroups
        assert_eq!(mgr.outbound_netgroup_count(), 0);

        // Mark first as connected
        mgr.mark_outbound_success(&addr1, &netgroup_mgr);
        assert_eq!(mgr.outbound_netgroup_count(), 1);

        // Second address is in same netgroup
        let netgroup = netgroup_mgr.get_group(&addr2.ip());
        assert!(mgr.has_outbound_in_netgroup(&netgroup));

        // Third address is in different netgroup
        let netgroup3 = netgroup_mgr.get_group(&addr3.ip());
        assert!(!mgr.has_outbound_in_netgroup(&netgroup3));

        // Mark third as connected
        mgr.mark_outbound_success(&addr3, &netgroup_mgr);
        assert_eq!(mgr.outbound_netgroup_count(), 2);

        // Disconnect first
        mgr.mark_outbound_disconnected(&addr1, &netgroup_mgr);
        assert_eq!(mgr.outbound_netgroup_count(), 1);

        // Now second address netgroup should be available
        assert!(!mgr.has_outbound_in_netgroup(&netgroup));
    }

    #[test]
    fn test_eclipse_attack_scenario() {
        // Simulate an eclipse attack: attacker floods us with addresses in same /16
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        // Attacker controls addresses in 192.168.x.x
        let attacker_addrs: Vec<SocketAddr> = (1..=100)
            .map(|i| format!("192.168.1.{}:8333", i % 256).parse().unwrap())
            .collect();

        // Add one legitimate address in different /16
        let legitimate_addr: SocketAddr = "8.8.8.8:8333".parse().unwrap();

        mgr.add_dns_addresses(attacker_addrs);
        mgr.add_dns_addresses(vec![legitimate_addr]);

        // First connection to attacker
        let first = mgr.next_addr_to_try(&netgroup_mgr).unwrap();
        mgr.mark_outbound_success(&first, &netgroup_mgr);

        // All other attacker addresses should be skipped (same netgroup)
        // Next should be the legitimate one
        let second = mgr.next_addr_to_try(&netgroup_mgr).unwrap();
        assert_eq!(second, legitimate_addr);
    }

    // ============================================================
    // STALE PEER EVICTION TESTS
    // ============================================================

    #[test]
    fn test_stale_peer_check_result_default() {
        let result = StalePeerCheckResult::default();
        assert!(result.ping_timeouts.is_empty());
        assert!(result.chain_sync_failures.is_empty());
        assert!(result.send_getheaders_to.is_empty());
        assert!(!result.tip_may_be_stale);
        assert!(!result.has_disconnects());
    }

    #[test]
    fn test_stale_peer_check_result_has_disconnects() {
        let mut result = StalePeerCheckResult::default();
        assert!(!result.has_disconnects());

        result.ping_timeouts.push(PeerId(1));
        assert!(result.has_disconnects());

        let mut result2 = StalePeerCheckResult::default();
        result2.chain_sync_failures.push(PeerId(2));
        assert!(result2.has_disconnects());
    }

    #[test]
    fn test_stale_peer_check_result_disconnected_peers() {
        let mut result = StalePeerCheckResult::default();
        result.ping_timeouts.push(PeerId(1));
        result.chain_sync_failures.push(PeerId(2));
        result.chain_sync_failures.push(PeerId(3));

        let disconnected: Vec<_> = result.disconnected_peers().collect();
        assert_eq!(disconnected.len(), 3);
        assert!(disconnected.contains(&&PeerId(1)));
        assert!(disconnected.contains(&&PeerId(2)));
        assert!(disconnected.contains(&&PeerId(3)));
    }

    #[tokio::test]
    async fn test_stale_peer_update_tip_height() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        assert_eq!(mgr.start_height, 0);
        assert_eq!(mgr.stale_detector().our_tip_height(), 0);

        mgr.update_tip_height(100000);

        assert_eq!(mgr.start_height, 100000);
        assert_eq!(mgr.stale_detector().our_tip_height(), 100000);
    }

    #[tokio::test]
    async fn test_stale_peer_should_try_extra_outbound() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        // Initially should not try extra outbound
        assert!(!mgr.should_try_extra_outbound());
    }

    /// Regression: a zombie outbound peer (TCP alive but not advancing the
    /// chain) must be evicted by the maintenance-tick path that calls
    /// `check_for_stale_peers`.  Pre-2026-05-07, this routine existed but
    /// was never invoked outside tests; rustoshi mainnet froze for 6+
    /// hours at h=948271 with one such zombie peer.
    ///
    /// The test drives the same call sequence that the main loop's
    /// 45-second maintenance tick now performs:
    ///   1. update_tip_height(our_tip)
    ///   2. check_for_stale_peers(blocks_in_flight=0)
    /// and asserts the stalled peer is evicted (PeerCommand::Disconnect
    /// arrives on its command channel).
    #[tokio::test]
    async fn test_check_for_stale_peers_disconnects_zombie() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        // Our tip is at height 100; peer is way behind at 50 with the
        // chain-sync timeout already past.  Mirrors a peer that
        // completed the version handshake and then went silent at the
        // application layer.
        mgr.update_tip_height(100);

        let peer_id = PeerId(42);
        let mut rx = mgr.insert_test_outbound_peer_old(peer_id, "192.0.2.42:8333".parse().unwrap());

        // Pre-arm the stalled-peer state: peer is behind, timeout has
        // fired, getheaders was already sent (so the next tick should
        // disconnect rather than just send another getheaders).
        if let Some(state) = mgr.get_peer_stale_state_mut(peer_id) {
            state.best_known_height = 50;
            state.chain_sync.set_timeout(100, Duration::from_millis(1));
            state.chain_sync.sent_getheaders = true;
            // Backdate the timeout so is_timed_out() returns true now.
            state.chain_sync.timeout = Some(Instant::now() - Duration::from_secs(1));
        }

        // Skip the EXTRA_PEER_CHECK_INTERVAL gate so we run synchronously.
        mgr.force_stale_check_due();

        let result = mgr.check_for_stale_peers(0).await;
        assert!(
            result.chain_sync_failures.contains(&peer_id),
            "stalled outbound peer must appear in chain_sync_failures, got {:?}",
            result.chain_sync_failures
        );

        // The peer's command channel must receive a Disconnect.
        let cmd = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for Disconnect command");
        assert!(matches!(cmd, Some(PeerCommand::Disconnect)));
    }

    #[test]
    fn test_stale_peer_state_initialization() {
        let state = StalePeerState::new();
        assert_eq!(state.best_known_height, 0);
        assert!(state.last_block_time.is_none());
        assert!(state.last_tx_time.is_none());
        assert!(state.ping_start.is_none());
        assert!(!state.ping_nonce_sent);
        assert!(state.last_getheaders_time.is_none());
        assert!(state.chain_sync.timeout.is_none());
    }

    #[test]
    fn test_stale_peer_ping_timeout_detection() {
        use crate::stale_detection::PING_TIMEOUT_INTERVAL;

        let mut state = StalePeerState::new();

        // No ping sent - not timed out
        assert!(!state.is_ping_timed_out());

        // Send ping
        state.ping_sent();
        assert!(state.ping_nonce_sent);
        assert!(state.ping_start.is_some());

        // Just sent - not timed out
        assert!(!state.is_ping_timed_out());

        // Simulate timeout by setting ping_start in the past
        state.ping_start = Some(Instant::now() - PING_TIMEOUT_INTERVAL - Duration::from_secs(1));
        assert!(state.is_ping_timed_out());

        // Receive pong - should clear
        state.pong_received();
        assert!(!state.ping_nonce_sent);
        assert!(!state.is_ping_timed_out());
    }

    #[test]
    fn test_stale_peer_block_tracking() {
        let mut state = StalePeerState::new();

        state.block_received(100);
        assert_eq!(state.best_known_height, 100);
        assert!(state.last_block_time.is_some());

        // Higher block should update
        state.block_received(200);
        assert_eq!(state.best_known_height, 200);

        // Lower block should not reduce best_known_height
        state.block_received(150);
        assert_eq!(state.best_known_height, 200);
    }

    #[test]
    fn test_stale_peer_headers_timeout_detection() {
        use crate::stale_detection::HEADERS_RESPONSE_TIME;

        let mut state = StalePeerState::new();

        // No getheaders sent - not timed out
        assert!(!state.is_headers_timed_out());

        // Send getheaders
        state.getheaders_sent();
        assert!(state.chain_sync.sent_getheaders);
        assert!(state.last_getheaders_time.is_some());

        // Just sent - not timed out
        assert!(!state.is_headers_timed_out());

        // Simulate timeout
        state.last_getheaders_time =
            Some(Instant::now() - HEADERS_RESPONSE_TIME - Duration::from_secs(1));
        assert!(state.is_headers_timed_out());
    }

    #[test]
    fn test_stale_peer_detector_tip_stale() {
        let mut detector = StalePeerDetector::new();

        // With blocks in flight - never stale
        assert!(!detector.tip_may_be_stale(1));

        // Just updated tip - not stale
        detector.update_tip(100);
        assert!(!detector.tip_may_be_stale(0));

        // Simulate old tip by setting last_tip_update in the past
        // (We can't easily do this without modifying the struct, so we'll test the logic)
    }

    #[test]
    fn test_stale_peer_detector_protection() {
        use crate::stale_detection::MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT;

        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut states: Vec<StalePeerState> = (0..5)
            .map(|_| {
                let mut s = StalePeerState::new();
                s.best_known_height = 100; // At tip
                s
            })
            .collect();

        // Protect up to max
        for i in 0..MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT {
            assert!(detector.try_protect_peer(&mut states[i]));
            assert!(states[i].chain_sync.protected);
        }

        assert_eq!(
            detector.protected_count(),
            MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT
        );

        // Can't protect more
        assert!(!detector.try_protect_peer(&mut states[4]));
        assert!(!states[4].chain_sync.protected);

        // Unprotect one
        detector.unprotect_peer(&mut states[0]);
        assert!(!states[0].chain_sync.protected);
        assert_eq!(
            detector.protected_count(),
            MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT - 1
        );

        // Now can protect the last one
        assert!(detector.try_protect_peer(&mut states[4]));
    }

    #[test]
    fn test_stale_peer_detector_protection_requires_good_height() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Too far behind (> 6 blocks)

        // Can't protect peer with bad height
        assert!(!detector.try_protect_peer(&mut state));
        assert!(!state.chain_sync.protected);

        // Close to tip - can protect
        state.best_known_height = 95;
        assert!(detector.try_protect_peer(&mut state));
    }

    #[test]
    fn test_stale_peer_chain_sync_timeout_sets_timeout() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // First check should set timeout
        let action = detector.check_chain_sync(&mut state, true, false);
        assert!(action.is_none()); // No immediate action
        assert!(state.chain_sync.timeout.is_some());
        assert_eq!(state.chain_sync.work_header_height, Some(100));
        assert!(!state.chain_sync.sent_getheaders);
    }

    #[test]
    fn test_stale_peer_chain_sync_catches_up() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // Set timeout
        detector.check_chain_sync(&mut state, true, false);
        assert!(state.chain_sync.timeout.is_some());

        // Peer catches up
        state.best_known_height = 100;
        let action = detector.check_chain_sync(&mut state, true, false);
        assert!(action.is_none());
        assert!(state.chain_sync.timeout.is_none()); // Cleared
    }

    #[test]
    fn test_stale_peer_chain_sync_inbound_ignored() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // Inbound peers are not subject to chain sync checks
        let action = detector.check_chain_sync(&mut state, false, false);
        assert!(action.is_none());
        assert!(state.chain_sync.timeout.is_none()); // No timeout set
    }

    #[tokio::test]
    async fn test_evict_extra_outbound_peer_no_excess() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        // No peers - nothing to evict
        let evicted = mgr.evict_extra_outbound_peer().await;
        assert!(evicted.is_none());
    }

    #[test]
    fn test_minimum_connect_time_constant() {
        // Verify MINIMUM_CONNECT_TIME matches Bitcoin Core
        assert_eq!(MINIMUM_CONNECT_TIME, Duration::from_secs(30));
    }

    #[test]
    fn test_ping_timeout_interval_constant() {
        use crate::stale_detection::PING_TIMEOUT_INTERVAL;
        // Verify PING_TIMEOUT_INTERVAL matches Bitcoin Core's TIMEOUT_INTERVAL
        assert_eq!(PING_TIMEOUT_INTERVAL, Duration::from_secs(20 * 60));
    }

    #[test]
    fn test_extra_peer_check_interval_constant() {
        // Verify check interval is 45 seconds per Bitcoin Core
        assert_eq!(EXTRA_PEER_CHECK_INTERVAL, Duration::from_secs(45));
    }

    /// `RUSTOSHI_BIP324_V2_INBOUND` defaults ON (matches Bitcoin Core ≥26
    /// `-v2transport=1`); operators set the var to `0` / `false` / `no` /
    /// `off` to opt out.  Mirrors `peer::test_bip324_v2_outbound_default_on`.
    #[test]
    fn test_bip324_v2_inbound_default_on() {
        let _g = crate::v2_test_lock::lock();
        let prior = std::env::var("RUSTOSHI_BIP324_V2_INBOUND").ok();
        std::env::remove_var("RUSTOSHI_BIP324_V2_INBOUND");
        assert!(
            bip324_v2_inbound_enabled(),
            "v2 inbound must default ON when env var is unset"
        );
        for off in ["0", "false", "False", "FALSE", "no", "NO", "off", "OFF"] {
            std::env::set_var("RUSTOSHI_BIP324_V2_INBOUND", off);
            assert!(
                !bip324_v2_inbound_enabled(),
                "v2 inbound must be OFF when env var is {:?}",
                off
            );
        }
        for on in ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"] {
            std::env::set_var("RUSTOSHI_BIP324_V2_INBOUND", on);
            assert!(
                bip324_v2_inbound_enabled(),
                "v2 inbound must be ON for env var = {:?}",
                on
            );
        }
        if let Some(v) = prior {
            std::env::set_var("RUSTOSHI_BIP324_V2_INBOUND", v);
        } else {
            std::env::remove_var("RUSTOSHI_BIP324_V2_INBOUND");
        }
    }

    /// BIP-130: a peer that has sent us `sendheaders` must receive a
    /// `headers` message at block-announce time; peers that have not
    /// must continue to receive an `inv(MSG_BLOCK)` (or
    /// `inv(MSG_WITNESS_BLOCK)` for witness-aware peers).
    ///
    /// HSync wave Pattern A — `_header-sync-dos-cross-impl-audit-2026-05-06-part1.md`.
    /// Reference impl: camlcoin `peer_manager.ml::announce_block`.
    #[tokio::test]
    async fn test_announce_block_branches_on_sendheaders() {
        use rustoshi_primitives::{BlockHeader, Hash256};

        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        // Peer A: sent sendheaders, no witness.   -> expect Headers
        // Peer B: no sendheaders, witness peer.   -> expect Inv(MsgWitnessBlock)
        // Peer C: no sendheaders, no witness.     -> expect Inv(MsgBlock)
        let mut rx_a = mgr.insert_test_peer(
            PeerId(1),
            "192.0.2.1:8333".parse().unwrap(),
            true,  // supports_sendheaders
            false, // supports_witness
        );
        let mut rx_b =
            mgr.insert_test_peer(PeerId(2), "192.0.2.2:8333".parse().unwrap(), false, true);
        let mut rx_c =
            mgr.insert_test_peer(PeerId(3), "192.0.2.3:8333".parse().unwrap(), false, false);

        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256([1u8; 32]),
            merkle_root: Hash256([2u8; 32]),
            timestamp: 1_700_000_000,
            bits: 0x1d00ffff,
            nonce: 42,
        };
        let block_hash = Hash256([0xab; 32]);

        mgr.announce_block(header.clone(), block_hash).await;

        // Peer A receives a Headers message containing exactly our header.
        match rx_a.recv().await.expect("peer A should receive a message") {
            PeerCommand::SendMessage(NetworkMessage::Headers(hs)) => {
                assert_eq!(hs.len(), 1);
                assert_eq!(hs[0].nonce, header.nonce);
                assert_eq!(hs[0].timestamp, header.timestamp);
            }
            other => panic!("peer A expected Headers, got {:?}", other),
        }

        // Peer B receives Inv with MsgWitnessBlock.
        match rx_b.recv().await.expect("peer B should receive a message") {
            PeerCommand::SendMessage(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv.len(), 1);
                assert_eq!(inv[0].inv_type, crate::message::InvType::MsgWitnessBlock);
                assert_eq!(inv[0].hash, block_hash);
            }
            other => panic!("peer B expected Inv, got {:?}", other),
        }

        // Peer C receives Inv with plain MsgBlock.
        match rx_c.recv().await.expect("peer C should receive a message") {
            PeerCommand::SendMessage(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv.len(), 1);
                assert_eq!(inv[0].inv_type, crate::message::InvType::MsgBlock);
                assert_eq!(inv[0].hash, block_hash);
            }
            other => panic!("peer C expected Inv, got {:?}", other),
        }
    }

    /// Receiving a `sendheaders` message from a peer must flip the
    /// `supports_sendheaders` flag, so the next `announce_block` call uses
    /// the headers branch for that peer.  Without this hook the flag stays
    /// at its handshake-time value (always `false` for inbound peers in the
    /// current code path) and Pattern A is unfixed.
    #[tokio::test]
    async fn test_sendheaders_message_flips_flag() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(7);
        let _rx = mgr.insert_test_peer(
            peer_id,
            "192.0.2.7:8333".parse().unwrap(),
            false, // initial supports_sendheaders
            false,
        );
        assert!(!mgr.peers.get(&peer_id).unwrap().info.supports_sendheaders);

        let event = PeerEvent::Message(peer_id, NetworkMessage::SendHeaders);
        mgr.handle_event(event).await;

        assert!(
            mgr.peers.get(&peer_id).unwrap().info.supports_sendheaders,
            "supports_sendheaders must be set after a SendHeaders message"
        );
    }

    // ============================================================
    // Fixed-seed bootstrap fallback (Core net.cpp:2607-2643 parity)
    // ============================================================

    /// Build a mainnet PeerManager for the fixed-seed tests, with the address
    /// book guaranteed empty (fresh `AddressManager`, no DNS, no anchors).
    fn fixedseed_mainnet_mgr(no_fixed_seeds: bool, no_dns_seed: bool) -> PeerManager {
        let config = PeerManagerConfig {
            no_fixed_seeds,
            no_dns_seed,
            // No listener bind in these tests (we never call start()).
            listen: false,
            ..Default::default()
        };
        PeerManager::new(config, ChainParams::mainnet())
    }

    #[test]
    fn fixedseed_list_is_40_routable_ipv4_8333() {
        let params = ChainParams::mainnet();
        assert_eq!(
            params.fixed_seeds.len(),
            40,
            "mainnet must carry exactly 40 fixed seeds"
        );
        for lit in &params.fixed_seeds {
            let sa: SocketAddr = lit
                .parse()
                .unwrap_or_else(|e| panic!("fixed seed {lit:?} must parse: {e}"));
            assert_eq!(sa.port(), 8333, "fixed seed {lit} must be :8333");
            match sa.ip() {
                IpAddr::V4(v4) => assert!(
                    ip_is_routable(&IpAddr::V4(v4)),
                    "fixed seed {lit} must be a routable IPv4"
                ),
                IpAddr::V6(_) => panic!("fixed seed {lit} must be IPv4, got IPv6"),
            }
        }
        // First and last anchors of the verbatim blockbrew/nimrod list.
        assert_eq!(
            params.fixed_seeds.first().copied(),
            Some("2.121.116.198:8333")
        );
        assert_eq!(params.fixed_seeds.last().copied(), Some("77.38.72.37:8333"));
    }

    #[test]
    fn fixedseed_non_mainnet_lists_are_empty() {
        // Network-scoped by construction: only mainnet populates fixed_seeds.
        assert!(ChainParams::testnet3().fixed_seeds.is_empty());
        assert!(ChainParams::testnet4().fixed_seeds.is_empty());
        assert!(ChainParams::signet().fixed_seeds.is_empty());
        assert!(ChainParams::regtest().fixed_seeds.is_empty());
    }

    #[test]
    fn fixedseed_fires_on_empty_book_when_dns_disabled() {
        // enabled + empty book + DNS disabled → fires immediately (grace not
        // required). This is the DNS-failure hang fix.
        let mut mgr =
            fixedseed_mainnet_mgr(/*no_fixed_seeds=*/ false, /*no_dns_seed=*/ true);
        assert_eq!(mgr.addr_manager.known_count(), 0, "book starts empty");
        let now = Instant::now(); // 0s elapsed — grace NOT elapsed
        let fired = mgr.maybe_add_fixed_seeds(now);
        assert!(
            fired,
            "must fire on empty book with DNS disabled (no grace wait)"
        );
        assert_eq!(
            mgr.addr_manager.known_count(),
            40,
            "all 40 fixed seeds injected into the book"
        );
        assert!(mgr.fixed_seeds_added, "one-shot guard set after firing");
    }

    #[test]
    fn fixedseed_fires_on_empty_book_after_60s_grace() {
        // enabled + empty book + DNS *enabled* → only fires once the 60s grace
        // has elapsed. Simulate elapsed time via a back-dated start Instant.
        let mut mgr = fixedseed_mainnet_mgr(false, /*no_dns_seed=*/ false);
        // Before grace: a fresh `now` => 0s elapsed, DNS enabled => no fire.
        assert!(
            !mgr.maybe_add_fixed_seeds(Instant::now()),
            "must NOT fire before the 60s grace when DNS is enabled"
        );
        assert_eq!(mgr.addr_manager.known_count(), 0, "no seeds yet");
        assert!(!mgr.fixed_seeds_added, "guard not set — did not fire");
        // After grace: back-date start by 61s so start.elapsed() > 60s.
        let stale_start = Instant::now() - Duration::from_secs(61);
        assert!(
            mgr.maybe_add_fixed_seeds(stale_start),
            "must fire once 60s grace has elapsed on an empty book"
        );
        assert_eq!(
            mgr.addr_manager.known_count(),
            40,
            "seeds injected after grace"
        );
    }

    #[test]
    fn fixedseed_does_not_fire_on_nonempty_book() {
        // A populated book (e.g. successful DNS / loaded peers.dat) blocks the
        // fallback so normal bootstrap is never bypassed.
        let mut mgr = fixedseed_mainnet_mgr(false, /*no_dns_seed=*/ true);
        mgr.addr_manager
            .add_dns_addresses(vec!["198.51.100.7:8333".parse().unwrap()]);
        assert_eq!(mgr.addr_manager.known_count(), 1, "book non-empty");
        // Even DNS-disabled + a back-dated start must NOT fire on a non-empty book.
        let stale_start = Instant::now() - Duration::from_secs(120);
        let fired = mgr.maybe_add_fixed_seeds(stale_start);
        assert!(!fired, "must NOT fire when the book is non-empty");
        assert_eq!(
            mgr.addr_manager.known_count(),
            1,
            "no fixed seeds added — book unchanged"
        );
        assert!(!mgr.fixed_seeds_added, "guard stays unset — never fired");
    }

    #[test]
    fn fixedseed_does_not_fire_when_disabled() {
        // -nofixedseeds disables the fallback even on an empty book + DNS off.
        let mut mgr =
            fixedseed_mainnet_mgr(/*no_fixed_seeds=*/ true, /*no_dns_seed=*/ true);
        let stale_start = Instant::now() - Duration::from_secs(120);
        let fired = mgr.maybe_add_fixed_seeds(stale_start);
        assert!(!fired, "must NOT fire when -nofixedseeds is set");
        assert_eq!(
            mgr.addr_manager.known_count(),
            0,
            "no seeds added when disabled"
        );
    }

    #[test]
    fn fixedseed_does_not_fire_in_connect_mode() {
        // -connect pinning disables addrman-driven outbound AND the fallback.
        let config = PeerManagerConfig {
            connect_peers: vec!["192.0.2.50:8333".parse().unwrap()],
            listen: false,
            ..Default::default()
        };
        let mut mgr = PeerManager::new(config, ChainParams::mainnet());
        let stale_start = Instant::now() - Duration::from_secs(120);
        assert!(
            !mgr.maybe_add_fixed_seeds(stale_start),
            "must NOT fire in -connect mode (fixed_seeds_enabled() is false)"
        );
        assert_eq!(
            mgr.addr_manager.known_count(),
            0,
            "no seeds in -connect mode"
        );
    }

    #[test]
    fn fixedseed_does_not_fire_on_non_mainnet() {
        // Network-scoped: testnet4 has an empty fixed_seeds list, so the
        // fallback is a no-op even with the book empty + DNS disabled.
        let config = PeerManagerConfig {
            no_dns_seed: true,
            listen: false,
            ..Default::default()
        };
        let mut mgr = PeerManager::new(config, ChainParams::testnet4());
        let stale_start = Instant::now() - Duration::from_secs(120);
        assert!(
            !mgr.maybe_add_fixed_seeds(stale_start),
            "must NOT fire on testnet4 (empty fixed_seeds, non-Mainnet network_id)"
        );
        assert_eq!(mgr.addr_manager.known_count(), 0, "no seeds on testnet4");
    }

    #[test]
    fn fixedseed_is_one_shot() {
        // The first fire injects 40 seeds; a second call is a cheap no-op even
        // though the book would be re-emptied — guarding against re-injection /
        // attempt-count re-bumping on every maintenance tick.
        let mut mgr = fixedseed_mainnet_mgr(false, /*no_dns_seed=*/ true);
        let now = Instant::now();
        assert!(mgr.maybe_add_fixed_seeds(now), "first call fires");
        assert_eq!(mgr.addr_manager.known_count(), 40);
        // Forcibly empty the book to prove the one-shot guard (not book-empty)
        // is what blocks the re-fire.
        mgr.addr_manager = AddressManager::new();
        assert_eq!(mgr.addr_manager.known_count(), 0, "book re-emptied");
        let stale_start = Instant::now() - Duration::from_secs(120);
        assert!(
            !mgr.maybe_add_fixed_seeds(stale_start),
            "second call must be a no-op once fixed_seeds_added is set"
        );
        assert_eq!(
            mgr.addr_manager.known_count(),
            0,
            "no re-injection after the one-shot guard fired"
        );
    }

    // ========================================================================
    // P2P anti-eclipse hardening — FEELER + getaddr anti-DoS proof tests
    // (Core net.cpp ThreadOpenConnections FEELER + net_processing.cpp getaddr
    // guards + addr token-bucket). In-process; no daemon/regtest slot needed.
    // ========================================================================

    /// getaddr_cap honors min(MAX_ADDR, floor(23 * size / 100)) — Core's
    /// `GetAddr_` cap (addrman.cpp:805 `nNodes = max_pct * nNodes / 100`, integer
    /// FLOOR). Uses distinguishing sizes where 23*N is NOT a multiple of 100 so
    /// floor != ceil and the floor-vs-(ceil/max-1) regression cannot pass:
    ///   - size=10 -> 230/100 = 2 (floor), NOT 3 (ceil)
    ///   - size=4  -> 92/100  = 0 (floor), NOT 1 (the old `.max(1)` clamp)
    ///   - size=1  -> 23/100  = 0 (floor), NOT 1
    #[test]
    fn feeler_getaddr_cap_formula() {
        assert_eq!(getaddr_cap(0), 0, "empty addrman shares nothing");
        // FLOOR, no min-1 clamp: 23*1/100 = 0 (Core shares nothing on a 1-entry
        // addrman). The old ceil/max(1) wrongly returned 1.
        assert_eq!(getaddr_cap(1), 0, "23*1/100 floors to 0 — Core shares nothing");
        assert_eq!(getaddr_cap(4), 0, "23*4/100 = 92/100 floors to 0, NOT 1");
        // DISTINGUISHING: 23*10/100 = 230/100 = 2 (floor) vs 3 (ceil).
        assert_eq!(getaddr_cap(10), 2, "23*10/100 floors to 2, NOT 3 (ceil)");
        // 23*100/100 = 23 (floor == ceil here).
        assert_eq!(getaddr_cap(100), 23);
        // 23*1000/100 = 230 (floor == ceil here).
        assert_eq!(getaddr_cap(1000), 230);
        // 23*100000/100 = 23000 -> clamped to MAX_ADDR (1000).
        assert_eq!(getaddr_cap(100_000), MAX_ADDR);
    }

    /// FEELER (AddressManager level): a probed NEW-table address is promoted
    /// NEW->TRIED on handshake SUCCESS, and NOT promoted on failure.
    /// Falsification: pre-impl there was no feeler at all, so TRIED was never
    /// refreshed by probing — this proves the promote path exists and is gated
    /// on success.
    #[test]
    fn feeler_promotes_new_to_tried_on_success_only() {
        let ng = NetGroupManager::new();
        let mut mgr = AddressManager::new();

        let probed: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let unprobed: SocketAddr = "5.6.7.8:8333".parse().unwrap();
        mgr.test_seed_new(probed, &ng);
        mgr.test_seed_new(unprobed, &ng);

        assert_eq!(mgr.addrman().tried_count(), 0, "nothing tried yet");
        assert!(!mgr.addrman().is_in_tried(&probed));
        assert!(!mgr.addrman().is_in_tried(&unprobed));

        // select_for_feeler draws from the NEW table.
        let selected = mgr.select_for_feeler();
        assert!(selected.is_some(), "NEW table must yield a feeler candidate");

        // SUCCESS: handshake completed -> promote NEW->TRIED.
        mgr.mark_feeler_success(&probed, &ng);
        assert!(
            mgr.addrman().is_in_tried(&probed),
            "successful feeler must promote NEW->TRIED"
        );
        assert_eq!(mgr.addrman().tried_count(), 1, "tried went 0 -> 1");

        // FAILURE (never marked): the unprobed addr stays in NEW.
        assert!(
            !mgr.addrman().is_in_tried(&unprobed),
            "an un-handshook feeler candidate must NOT be promoted"
        );
        assert_eq!(mgr.addrman().tried_count(), 1, "no spurious promotion");
    }

    /// select_for_feeler no-ops gracefully on an empty NEW table (must not dial
    /// an invalid address — Core breaks out of the select loop).
    #[test]
    fn feeler_select_empty_new_table_is_none() {
        let mut mgr = AddressManager::new();
        assert!(mgr.select_for_feeler().is_none());
        // After binding a netgroup but with no NEW entries, still None.
        let ng = NetGroupManager::new();
        mgr.bind_netgroup(&ng);
        assert!(mgr.select_for_feeler().is_none());
    }

    /// FEELER (end-to-end wiring): the PeerEvent::Connected handler routes a
    /// Feeler peer through mark_feeler_success (NEW->TRIED promote) and then
    /// enqueues a Disconnect on the peer's command channel.
    #[tokio::test]
    async fn feeler_connected_handler_promotes_and_disconnects() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let addr: SocketAddr = "9.9.9.9:8333".parse().unwrap();
        let ng = mgr.netgroup_manager.clone();
        mgr.addr_manager.test_seed_new(addr, &ng);
        assert!(!mgr.addr_manager.addrman().is_in_tried(&addr));

        let pid = PeerId(77);
        let (info, mut cmd_rx) = mgr.insert_test_feeler_peer(pid, addr);

        let stats = std::sync::Arc::new(crate::peer::PeerStats::new());
        mgr.handle_event(PeerEvent::Connected(pid, info, stats))
            .await;

        // Promoted NEW->TRIED on handshake success.
        assert!(
            mgr.addr_manager.addrman().is_in_tried(&addr),
            "feeler Connected must promote the probed addr NEW->TRIED"
        );
        // Disconnect enqueued on the feeler's command channel.
        match cmd_rx.try_recv() {
            Ok(PeerCommand::Disconnect) => {}
            other => panic!("expected Disconnect on feeler channel, got {:?}", other),
        }
    }

    /// GETADDR-once: a 2nd getaddr from the same peer is ignored (no addr sent),
    /// while the 1st is answered. Falsification: pre-impl answered EVERY getaddr.
    #[tokio::test]
    async fn getaddr_answered_once_per_peer() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        // Seed enough shareable addresses that the 23%-FLOOR cap is non-zero so
        // the first getaddr produces a non-empty response. Core's getaddr cap is
        // floor(23 * N / 100) (addrman.cpp:805); a single address floors to 0
        // (23*1/100 = 0 -> Core shares nothing), so seed 100 (-> cap 23).
        let ng = mgr.netgroup_manager.clone();
        for i in 0..100u32 {
            let octets = i.to_be_bytes();
            let addr: SocketAddr =
                format!("8.{}.{}.{}:8333", octets[1], octets[2], octets[3].max(1))
                    .parse()
                    .unwrap();
            mgr.addr_manager.test_seed_new(addr, &ng);
            mgr.addr_manager.test_mark_shareable(addr);
        }

        // Insert an inbound peer (legacy addr path; supports_addrv2=false).
        let pid = PeerId(11);
        let mut cmd_rx = mgr.insert_test_peer(pid, "2.2.2.2:8333".parse().unwrap(), false, false);

        // 1st getaddr -> answered (an Addr message is sent).
        mgr.handle_event(PeerEvent::Message(pid, NetworkMessage::GetAddr))
            .await;
        let first = cmd_rx.try_recv();
        assert!(
            matches!(first, Ok(PeerCommand::SendMessage(NetworkMessage::Addr(_)))),
            "first getaddr must be answered with an Addr, got {:?}",
            first
        );
        // getaddr_recvd flag set.
        assert!(
            mgr.peers.get(&pid).map(|p| p.getaddr_recvd).unwrap_or(false),
            "getaddr_recvd must be set after first getaddr"
        );

        // 2nd getaddr -> ignored (nothing sent).
        mgr.handle_event(PeerEvent::Message(pid, NetworkMessage::GetAddr))
            .await;
        assert!(
            cmd_rx.try_recv().is_err(),
            "second getaddr from the same peer must be ignored (no message)"
        );
    }

    /// 23%-cap: the getaddr response length honors min(MAX_ADDR, floor(23*N/100)).
    #[tokio::test]
    async fn getaddr_response_honors_23pct_cap() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        // Seed 100 distinct shareable addresses -> cap = floor(23*100/100) = 23.
        let ng = mgr.netgroup_manager.clone();
        for i in 0..100u32 {
            let octets = i.to_be_bytes();
            // Build a routable, distinct public IP (avoid RFC1918 ranges).
            let addr: SocketAddr =
                format!("100.{}.{}.{}:8333", octets[1], octets[2], octets[3].max(1))
                    .parse()
                    .unwrap();
            mgr.addr_manager.test_seed_new(addr, &ng);
            mgr.addr_manager.test_mark_shareable(addr);
        }
        let pool = mgr.addr_manager.shareable_count();
        assert!(pool > 0, "must have a shareable pool");
        let cap = getaddr_cap(pool);

        let pid = PeerId(22);
        let mut cmd_rx = mgr.insert_test_peer(pid, "3.3.3.3:8333".parse().unwrap(), false, false);
        mgr.handle_event(PeerEvent::Message(pid, NetworkMessage::GetAddr))
            .await;

        match cmd_rx.try_recv() {
            Ok(PeerCommand::SendMessage(NetworkMessage::Addr(addrs))) => {
                assert!(
                    addrs.len() <= cap,
                    "getaddr response ({}) must honor the 23% cap ({})",
                    addrs.len(),
                    cap
                );
                assert!(addrs.len() <= MAX_ADDR, "and never exceed MAX_ADDR");
            }
            other => panic!("expected an Addr response, got {:?}", other),
        }
    }

    /// TOKEN-BUCKET: inbound addrs beyond the per-peer bucket are dropped. A
    /// fresh peer starts with 1.0 token, so a single addr message carrying many
    /// addresses admits exactly 1 and drops the rest.
    #[tokio::test]
    async fn inbound_addr_token_bucket_drops_excess() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let pid = PeerId(33);
        let _cmd_rx = mgr.insert_test_peer(pid, "4.4.4.4:8333".parse().unwrap(), false, false);

        // 10 routable addresses in one addr message; fresh bucket = 1.0 token.
        let mut taddrs = Vec::new();
        for i in 0..10u32 {
            let addr: SocketAddr = format!("101.0.0.{}:8333", i + 1).parse().unwrap();
            taddrs.push(TimestampedNetAddress {
                timestamp: now_unix_secs() as u32,
                address: socket_addr_to_net_address(addr, NODE_NETWORK | NODE_WITNESS),
            });
        }
        let before = mgr.addr_manager.known_count();
        mgr.handle_event(PeerEvent::Message(pid, NetworkMessage::Addr(taddrs)))
            .await;
        let admitted = mgr.addr_manager.known_count() - before;
        assert_eq!(
            admitted, 1,
            "fresh 1.0-token bucket must admit exactly 1 of 10 addrs, dropping the excess"
        );

        // The bucket is now drained; an immediate second message admits 0.
        let mut more = Vec::new();
        for i in 0..5u32 {
            let addr: SocketAddr = format!("102.0.0.{}:8333", i + 1).parse().unwrap();
            more.push(TimestampedNetAddress {
                timestamp: now_unix_secs() as u32,
                address: socket_addr_to_net_address(addr, NODE_NETWORK | NODE_WITNESS),
            });
        }
        let before2 = mgr.addr_manager.known_count();
        mgr.handle_event(PeerEvent::Message(pid, NetworkMessage::Addr(more)))
            .await;
        assert_eq!(
            mgr.addr_manager.known_count(),
            before2,
            "drained bucket must drop all addrs in the immediate next message"
        );
    }
}
