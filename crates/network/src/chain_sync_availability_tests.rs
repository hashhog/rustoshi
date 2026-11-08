//! Chain-sync eviction must see what a peer announces (peers-rustoshi-outbound).
//!
//! Child module of `peer_manager` so it can reach the private peer table.
//!
//! Mainnet 2026-11-07/08 (rustoshi pin e5e72f42): every outbound peer that
//! survived its first minute was disconnected "due to chain sync timeout"
//! 23-25 minutes after it connected (412 times in 24 h), and the node never
//! held 8 full-relay outbound peers. The best-known height that
//! `check_chain_sync` (Core `ConsiderEviction`) reads was never advanced by
//! the headers, block invs and compact blocks the peer relayed, and the
//! getheaders the check asks for was never sent. Core feeds every
//! announcement to `UpdateBlockAvailability` and sends
//! `getheaders(GetLocator(m_work_header->pprev))` before it disconnects
//! (bitcoin-core/src/net_processing.cpp).

use super::*;
use crate::message::{InvType, InvVector};
use rustoshi_primitives::{BlockHeader, Hash256};

fn mgr() -> (tempfile::TempDir, PeerManager) {
    let dir = tempfile::TempDir::new().unwrap();
    let config = PeerManagerConfig::testnet4().with_data_dir(dir.path().to_path_buf());
    (dir, PeerManager::new(config, ChainParams::testnet4()))
}

/// Deterministic stand-in for the block at `height` in our index.
fn hash_at(height: u32) -> Hash256 {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&height.to_le_bytes());
    b[31] = 0xab;
    Hash256(b)
}

/// Index lookup over heights 0..=`tip`; anything else is unknown.
fn index_up_to(tip: u32) -> impl Fn(&Hash256) -> Option<u32> {
    move |h: &Hash256| (0..=tip).find(|&n| hash_at(n) == *h)
}

/// One maintenance tick (main.rs order): resolve availability, run the
/// stale check, send any chain-sync getheaders. Returns (evicted, getheaders
/// queued).
async fn tick(mgr: &mut PeerManager, peer: PeerId, index_tip: u32) -> (bool, usize) {
    mgr.force_stale_check_due();
    mgr.process_block_availability(index_up_to(index_tip));
    let r = mgr.check_for_stale_peers(0).await;
    let sent = mgr.send_chain_sync_getheaders(&r.send_getheaders_to, |h| {
        if h <= index_tip { Some(hash_at(h)) } else { None }
    });
    (r.chain_sync_failures.contains(&peer), sent)
}

/// Expire whatever chain-sync timeout is armed, standing in for the wait.
fn expire(mgr: &mut PeerManager, peer: PeerId) {
    if let Some(s) = mgr.get_peer_stale_state_mut(peer) {
        if s.chain_sync.timeout.is_some() {
            s.chain_sync.timeout = Some(Instant::now() - Duration::from_secs(1));
        }
    }
}

/// Run the arm / getheaders / disconnect sequence. Returns true if evicted.
async fn run_ticks(mgr: &mut PeerManager, peer: PeerId, index_tip: u32) -> bool {
    for _ in 0..3 {
        if tick(mgr, peer, index_tip).await.0 {
            return true;
        }
        expire(mgr, peer);
    }
    false
}

/// A peer that announced our tip block (as the last header of a `headers`
/// message, the way Core peers announce with sendheaders) keeps its slot.
/// Mainnet: these peers were dropped at ~23 min.
#[tokio::test]
async fn peer_that_announced_our_tip_is_not_chain_sync_evicted() {
    let (_d, mut mgr) = mgr();
    mgr.update_tip_height(100);
    let peer = PeerId(1);
    let _rx = mgr.insert_test_outbound_peer_old(peer, "192.0.2.1:8333".parse().unwrap());
    for hash in announced_block_hashes(&NetworkMessage::Inv(vec![InvVector {
        inv_type: InvType::MsgBlock,
        hash: hash_at(100),
    }])) {
        mgr.update_block_availability(peer, hash, index_up_to(100));
    }
    assert!(
        !run_ticks(&mut mgr, peer, 100).await,
        "peer that announced our tip was evicted for chain-sync timeout"
    );
}

/// The announcement arrives before its header is indexed (a new tip). Core
/// keeps it as hashLastUnknownBlock and ProcessBlockAvailability resolves it
/// once the header lands; the peer then counts as caught up.
#[tokio::test]
async fn unknown_announcement_counts_once_its_header_is_indexed() {
    let (_d, mut mgr) = mgr();
    mgr.update_tip_height(100);
    let peer = PeerId(2);
    let _rx = mgr.insert_test_outbound_peer_old(peer, "192.0.2.2:8333".parse().unwrap());
    // Index only reaches 99 when block 100 is announced.
    mgr.update_block_availability(peer, hash_at(100), index_up_to(99));
    // Ticks run with the header for 100 now indexed.
    assert!(
        !run_ticks(&mut mgr, peer, 100).await,
        "announcement of block 100 was never resolved after its header landed"
    );
}

/// A peer that is in sync but has announced nothing since it connected (no
/// block for 20 minutes). Core sends getheaders from the benchmark tip's
/// parent; the peer answers with that tip header and keeps its slot.
#[tokio::test]
async fn silent_in_sync_peer_answers_chain_sync_getheaders_and_stays() {
    let (_d, mut mgr) = mgr();
    mgr.update_tip_height(100);
    let peer = PeerId(3);
    let mut rx = mgr.insert_test_outbound_peer_old(peer, "192.0.2.3:8333".parse().unwrap());

    // Tick 1 arms the 20-minute timeout.
    assert_eq!(tick(&mut mgr, peer, 100).await, (false, 0));
    expire(&mut mgr, peer);
    // Tick 2: timeout fired, getheaders must actually go out.
    assert_eq!(tick(&mut mgr, peer, 100).await, (false, 1), "chain-sync getheaders not sent");
    let locator = match rx.try_recv() {
        Ok(PeerCommand::SendMessage(NetworkMessage::GetHeaders(gh))) => gh.locator_hashes,
        other => panic!("expected getheaders, got {other:?}"),
    };
    // Core GetLocator(m_work_header->pprev): starts at 99, ends at genesis.
    assert_eq!(locator.first(), Some(&hash_at(99)));
    assert_eq!(locator.last(), Some(&hash_at(0)));

    // The peer answers with header 100 (the one it has beyond the locator).
    let mut h = ChainParams::testnet4().genesis_block.header.clone();
    h.nonce = 1;
    let reply = NetworkMessage::Headers(vec![h.clone()]);
    // Its hash is not ours (test index), so feed the real announcement path
    // with the reply and resolve it as block 100.
    let announced = announced_block_hashes(&reply);
    assert_eq!(announced, vec![h.block_hash()]);
    let reply_hash = announced[0];
    mgr.update_block_availability(peer, reply_hash, |x| (*x == reply_hash).then_some(100));

    // Tick 3 (after the 2-minute deadline): caught up, not evicted.
    expire(&mut mgr, peer);
    assert!(!tick(&mut mgr, peer, 100).await.0, "peer evicted after answering getheaders");
}

/// Control: a peer whose announcements stay behind our tip, and one that
/// only announced a block we never indexed, are still evicted after the
/// getheaders round. The fix must not exempt peers that do not show a chain
/// at least as tall as ours.
#[tokio::test]
async fn lagging_or_unknown_announcer_is_still_evicted() {
    // Behind: announced block 50 while our tip is 100.
    let (_d, mut mgr1) = mgr();
    mgr1.update_tip_height(100);
    let lag = PeerId(4);
    let _r1 = mgr1.insert_test_outbound_peer_old(lag, "192.0.2.4:8333".parse().unwrap());
    mgr1.update_block_availability(lag, hash_at(50), index_up_to(100));
    assert!(run_ticks(&mut mgr1, lag, 100).await, "lagging peer was not evicted");

    // Unknown: announced a hash that never enters our index.
    let (_d2, mut mgr2) = mgr();
    mgr2.update_tip_height(100);
    let unk = PeerId(5);
    let _r2 = mgr2.insert_test_outbound_peer_old(unk, "198.51.100.5:8333".parse().unwrap());
    mgr2.update_block_availability(unk, Hash256([0xee; 32]), index_up_to(100));
    assert!(run_ticks(&mut mgr2, unk, 100).await, "peer announcing only an unindexed block kept its slot");
}

/// The extraction mirrors Core's three UpdateBlockAvailability call sites
/// and ignores everything else.
#[test]
fn announced_block_hashes_matches_core_call_sites() {
    let g: BlockHeader = ChainParams::testnet4().genesis_block.header.clone();
    let mut g2 = g.clone();
    g2.nonce ^= 1;
    // headers: the LAST header only.
    assert_eq!(
        announced_block_hashes(&NetworkMessage::Headers(vec![g.clone(), g2.clone()])),
        vec![g2.block_hash()]
    );
    assert!(announced_block_hashes(&NetworkMessage::Headers(vec![])).is_empty());
    // inv: MSG_BLOCK items only (Core `IsMsgBlk()` is `type == MSG_BLOCK`),
    // in order; not txs, and not the witness-block getdata flag.
    let inv = NetworkMessage::Inv(vec![
        InvVector { inv_type: InvType::MsgTx, hash: hash_at(1) },
        InvVector { inv_type: InvType::MsgBlock, hash: hash_at(2) },
        InvVector { inv_type: InvType::MsgWitnessBlock, hash: hash_at(3) },
        InvVector { inv_type: InvType::MsgWtx, hash: hash_at(4) },
        InvVector { inv_type: InvType::MsgBlock, hash: hash_at(5) },
    ]);
    assert_eq!(announced_block_hashes(&inv), vec![hash_at(2), hash_at(5)]);
    // cmpctblock: the header at the front of the payload.
    let mut payload = Vec::new();
    rustoshi_primitives::serialize::Encodable::encode(&g, &mut payload).unwrap();
    payload.extend_from_slice(&[0u8; 9]);
    assert_eq!(
        announced_block_hashes(&NetworkMessage::CmpctBlock(payload)),
        vec![g.block_hash()]
    );
    assert!(announced_block_hashes(&NetworkMessage::CmpctBlock(vec![0u8; 10])).is_empty());
    assert!(announced_block_hashes(&NetworkMessage::Ping(1)).is_empty());
}
