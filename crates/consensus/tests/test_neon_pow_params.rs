//! Neon audit (2026-11-24) chain-parameter and PoW findings 7, 9, 10, 11, 12,
//! checked against Bitcoin Core v31.1 (`kernel/chainparams.cpp`,
//! `arith_uint256.cpp`, `pow.cpp`, `chain.cpp`).
//!
//! Every non-control test fails on rustoshi master 93365362 and passes with
//! the fix. Controls pin what must not move.

use rustoshi_consensus::{
    check_proof_of_work, compact_to_target, get_block_proof, get_next_work_required,
    target_to_compact, BlockIndex, ChainParams,
};
use rustoshi_primitives::{BlockHeader, Hash256};

fn be(hex_str: &str) -> [u8; 32] {
    let v = hex::decode(hex_str).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Big-endian 256-bit value `m << (8 * shift_bytes)`.
fn shl_bytes(m: &[u8], shift_bytes: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let end = 32 - shift_bytes;
    out[end - m.len()..end].copy_from_slice(m);
    out
}

fn small(v: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&v.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// F7: signet powLimit
// ---------------------------------------------------------------------------

#[test]
fn neon_f7_signet_pow_limit_is_core_value() {
    let p = ChainParams::signet();
    assert_eq!(
        p.pow_limit,
        be("00000377ae000000000000000000000000000000000000000000000000000000")
    );
    assert_eq!(target_to_compact(&p.pow_limit), 0x1e0377ae);
}

#[test]
fn neon_f7_signet_nbits_above_limit_fails_pow() {
    // 0x1e0377af..=0x1e0377ff are above Core's signet powLimit (high-hash).
    let p = ChainParams::signet();
    let zero_hash = [0u8; 32];
    assert!(!check_proof_of_work(&zero_hash, 0x1e0377af, &p));
    assert!(!check_proof_of_work(&zero_hash, 0x1e0377ff, &p));
}

#[test]
fn neon_f7_control_signet_genesis_bits_pass_pow() {
    let p = ChainParams::signet();
    assert_eq!(p.genesis_block.header.bits, 0x1e0377ae);
    assert!(check_proof_of_work(p.genesis_hash.as_bytes(), 0x1e0377ae, &p));
}

// ---------------------------------------------------------------------------
// F9: testnet4 genesis block
// ---------------------------------------------------------------------------

#[test]
fn neon_f9_testnet4_genesis_block_hashes_to_genesis_hash() {
    let p = ChainParams::testnet4();
    assert_eq!(
        p.genesis_block.header.merkle_root,
        Hash256::from_hex("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e").unwrap()
    );
    assert_eq!(p.genesis_block.block_hash(), p.genesis_hash);
    assert_eq!(
        p.genesis_hash,
        Hash256::from_hex("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043").unwrap()
    );
}

#[test]
fn neon_f9_testnet4_genesis_coinbase_is_bip94() {
    let p = ChainParams::testnet4();
    let cb = &p.genesis_block.transactions[0];
    let msg = b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
    let ss = &cb.inputs[0].script_sig;
    assert!(ss.windows(msg.len()).any(|w| w == msg), "testnet4 genesis message missing");
    let mut spk = vec![33u8];
    spk.extend([0u8; 33]);
    spk.push(0xac);
    assert_eq!(cb.outputs[0].script_pubkey, spk);
}

#[test]
fn neon_f9_control_other_networks_genesis_hash_matches_block() {
    for p in [
        ChainParams::mainnet(),
        ChainParams::testnet3(),
        ChainParams::signet(),
        ChainParams::regtest(),
    ] {
        assert_eq!(p.genesis_block.block_hash(), p.genesis_hash, "{:?}", p.network_id);
    }
}

// ---------------------------------------------------------------------------
// F10: target_to_compact for targets below 2^24 (GetCompact left shift)
// ---------------------------------------------------------------------------

#[test]
fn neon_f10_target_to_compact_small_targets_match_getcompact() {
    // Core arith_uint256::GetCompact: nSize <= 3 shifts the value LEFT.
    assert_eq!(target_to_compact(&small(1)), 0x0101_0000);
    assert_eq!(target_to_compact(&small(0x0123)), 0x0201_2300);
    assert_eq!(target_to_compact(&small(0x80)), 0x0200_8000);
    assert_eq!(target_to_compact(&small(0x8000)), 0x0300_8000);
    assert_eq!(target_to_compact(&small(0x7f_ffff)), 0x037f_ffff);
}

#[test]
fn neon_f10_target_to_compact_small_targets_round_trip() {
    for v in [1u32, 2, 0x7f, 0x80, 0xff, 0x100, 0x0123, 0x7fff, 0x8000, 0xffff, 0x12_3456] {
        let t = small(v);
        assert_eq!(compact_to_target(target_to_compact(&t)), t, "target {v:#x}");
    }
}

#[test]
fn neon_f10_control_pow_limit_compacts() {
    assert_eq!(target_to_compact(&ChainParams::mainnet().pow_limit), 0x1d00ffff);
    assert_eq!(target_to_compact(&ChainParams::testnet4().pow_limit), 0x1d00ffff);
    assert_eq!(target_to_compact(&ChainParams::regtest().pow_limit), 0x207fffff);
    assert_eq!(target_to_compact(&[0u8; 32]), 0);
}

// ---------------------------------------------------------------------------
// F11: SetCompact nSize 33 / 34 are not overflows
// ---------------------------------------------------------------------------

#[test]
fn neon_f11_compact_to_target_nsize_33_34_fit() {
    assert_eq!(compact_to_target(0x2100_7fff), shl_bytes(&[0x7f, 0xff], 30));
    assert_eq!(compact_to_target(0x2200_007f), shl_bytes(&[0x7f], 31));
    assert_eq!(compact_to_target(0x2100_0001), shl_bytes(&[0x01], 30));
}

#[test]
fn neon_f11_compact_to_target_overflow_boundaries() {
    // fOverflow = nWord != 0 && (nSize > 34 || (nWord > 0xff && nSize > 33)
    //                             || (nWord > 0xffff && nSize > 32))
    let ovf = [0xffu8; 32];
    assert_eq!(compact_to_target(0x2101_0000), ovf);
    assert_eq!(compact_to_target(0x2200_0100), ovf);
    assert_eq!(compact_to_target(0x2300_0001), ovf);
    assert_eq!(compact_to_target(0xff00_0001), ovf);
    assert_ne!(compact_to_target(0x2100_ffff), ovf);
    assert_ne!(compact_to_target(0x2200_00ff), ovf);
}

#[test]
fn neon_f11_regtest_pow_accepts_nsize_33_target_below_limit() {
    // 0x21007fff = 0x7fff << 240 <= regtest powLimit (0x7fff..ff): Core
    // CheckProofOfWork passes for a hash below it (zero hash here).
    let p = ChainParams::regtest();
    assert!(check_proof_of_work(&[0u8; 32], 0x2100_7fff, &p));
    assert!(check_proof_of_work(&[0u8; 32], 0x2200_007f, &p));
    let header = BlockHeader { bits: 0x2100_7fff, ..Default::default() };
    assert_eq!(header.target(), shl_bytes(&[0x7f, 0xff], 30));
}

#[test]
fn neon_f11_block_proof_of_nsize_33_target() {
    // GetBlockProof = 2^256 / (target + 1); target = 0x7fff << 240 -> 2.
    let mut two = [0u8; 32];
    two[31] = 2;
    assert_eq!(get_block_proof(0x2100_7fff).0, two);
}

#[test]
fn neon_f11_control_overflow_and_limit_rejections() {
    let p = ChainParams::regtest();
    // Overflow: high-hash. Above powLimit (0xffff << 240): high-hash.
    assert!(!check_proof_of_work(&[0u8; 32], 0x2101_0000, &p));
    assert!(!check_proof_of_work(&[0u8; 32], 0x2100_ffff, &p));
    assert_eq!(get_block_proof(0x2101_0000).0, [0u8; 32]);
    let header = BlockHeader { bits: 0x2101_0000, ..Default::default() };
    assert_eq!(header.target(), [0u8; 32]);
    assert!(check_proof_of_work(&[0u8; 32], 0x207f_ffff, &p));
}

// ---------------------------------------------------------------------------
// F12: GetNextWorkRequired min-difficulty test in 64-bit arithmetic
// ---------------------------------------------------------------------------

struct Node {
    height: u32,
    timestamp: u32,
    bits: u32,
    prev: Option<Box<Node>>,
}

impl BlockIndex for Node {
    fn height(&self) -> u32 {
        self.height
    }
    fn timestamp(&self) -> u32 {
        self.timestamp
    }
    fn bits(&self) -> u32 {
        self.bits
    }
    fn prev(&self) -> Option<&Self> {
        self.prev.as_deref()
    }
    fn ancestor(&self, height: u32) -> Option<&Self> {
        let mut cur = self;
        while cur.height > height {
            cur = cur.prev.as_deref()?;
        }
        (cur.height == height).then_some(cur)
    }
}

/// Heights 2014..=2018 on testnet4 (min-difficulty rules), every block at
/// `bits`, the tip at `tip_ts`.
fn short_chain(tip_ts: u32, bits: u32) -> Node {
    let mut node: Option<Box<Node>> = None;
    for (i, h) in (2014..=2018u32).enumerate() {
        node = Some(Box::new(Node {
            height: h,
            timestamp: tip_ts - (4 - i as u32) * 600,
            bits,
            prev: node,
        }));
    }
    *node.unwrap()
}

#[test]
fn neon_f12_min_difficulty_test_does_not_overflow_near_u32_max() {
    // Parent timestamp 0xfffffc00: parent + 1200 does not fit in u32.
    // Core (int64): 0xfffffdf4 > 0xfffffc00 + 1200 is false -> no
    // min-difficulty, so the harder parent bits are required.
    let p = ChainParams::testnet4();
    let hard = 0x1c00_ffff;
    let tip = short_chain(0xffff_fc00, hard);
    assert_eq!(get_next_work_required(&tip, 0xffff_fdf4, &p).unwrap(), hard);
    assert_eq!(get_next_work_required(&tip, u32::MAX, &p).unwrap(), hard);
}

#[test]
fn neon_f12_control_min_difficulty_rule_at_normal_times() {
    let p = ChainParams::testnet4();
    let hard = 0x1c00_ffff;
    let tip = short_chain(1_750_000_000, hard);
    assert_eq!(get_next_work_required(&tip, 1_750_000_000 + 1200, &p).unwrap(), hard);
    assert_eq!(
        get_next_work_required(&tip, 1_750_000_000 + 1201, &p).unwrap(),
        target_to_compact(&p.pow_limit)
    );
}
