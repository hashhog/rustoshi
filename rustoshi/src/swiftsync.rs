//! `rustoshi swiftsync-pass` -- a fully-validating SwiftSync batch pass.
//!
//! Hashhog meta-repo design: `receipts/swiftsync-design-2026-10-05.md`
//! (§1.2 protocol P, §2 soundness, §2.4 controls, §3 "How nodes consume it"),
//! ratified as TRUST-ANCHOR "SwiftSync-verified" (2026-10-05). Draft BIP 457.
//!
//! The pass validates a height range of the chain WITHOUT a UTXO set. Spent
//! coins come from Bitcoin Core's undo data (`undo.pack`, untrusted); which
//! outputs survive comes from a hints file (untrusted). Both are bound to this
//! node's own parse of the chain by a salted 256-bit additive hash aggregate:
//!
//! ```text
//!   Agg_in  = Σ  H(salt ‖ code ‖ amount ‖ script ‖ prevout)   over every input
//!   Agg_out = Σ  H(salt ‖ code ‖ amount ‖ script ‖ outpoint)  over every created,
//!             spendable, NOT-hinted output
//! ```
//!
//! Hinted outputs are written to a spill (TxOutSer records); the meta-repo
//! close tool (`tools/swiftsync-close.py`) requires `Agg_in == Agg_out`,
//! `scripts_run == Σinputs` and that the spill's `hash_serialized_3` equals the
//! commitment (C(958794) for the full chain).
//!
//! # Path identity -- the production connect, with supplied coins
//!
//! Every block goes through EXACTLY the calls rustoshi's IBD makes for a block
//! (`rustoshi/src/main.rs`, the connect loop):
//!
//! 1. the connect-path `bad-diffbits` backstop
//!    (`rustoshi_storage::diffbits_gate_for_header`, as `check_connect_diffbits`);
//! 2. `ChainState::process_block_with_seq_ctx(block, view, prev_mtp,
//!    f_requested=true, now, seq_ctx, skip_scripts=false, prev_timestamp)`,
//!    which runs `check_block` (PoW, merkle/mutation, size, tx checks),
//!    the MTP gate, `contextual_check_block_header`, `contextual_check_block`
//!    (BIP34, witness commitment) and `connect_block_with_sequence_locks`
//!    (BIP30 probe, IsFinal/BIP113, maturity, MoneyRange, sigops, BIP68, fees,
//!    subsidy and the parallel script checks with the height's flags).
//!
//! The only differences from production are where the inputs come from:
//! the `UtxoView` is a per-block map holding this block's undo coins (instead
//! of the chainstate), and the MTP/timestamp/diffbits context comes from the
//! header chain read out of the blk files (instead of the block store).
//! `skip_scripts` is the literal `false`: assumevalid is never consulted.
//!
//! # The three mandatory soundness extensions (TRUST-ANCHOR ruling 1)
//!
//! * **P-ORD**: a supplied coin's height must be `< h`, or `== h` with the
//!   prevout created by an EARLIER tx of this block with identical data.
//! * **completeness**: every height of the range processed exactly once.
//! * **BIP30**: the coinbase outputs of 91722 and 91812 (overwritten by 91880
//!   and 91842) are unspendable, and coinbase txids below BIP34 (227,931) must
//!   be unique (91842/91880 exempt). Within one pass that is checked here; the
//!   txids are also written out so `tools/swiftsync-combine.py` can check
//!   uniqueness ACROSS parallel ranges.
//!
//! # Parallel ranges compose
//!
//! A pass over `[from, to]` with hints describing the set at `H >= to`
//! produces partial aggregates, a partial spill and its coinbase-txid list.
//! Passes that share one salt (`--salt-file`) and tile `[0, H]` exactly add up
//! (aggregates mod 2^256) to the whole-chain pass. A range with
//! `--start-snapshot` (the set at `from-1`) is instead STANDALONE: the start
//! set's coins are treated as created outputs (hinted -> spill, else Agg_out),
//! so the range closes on its own commitment at `to`.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Cursor, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use rustoshi_consensus::validation::install_on_script_check_pool;
use rustoshi_consensus::{
    init_script_check_threads, read_script_checks_total, ChainParams, ChainState, CoinEntry,
    SequenceLockContext, UtxoView,
};
use rustoshi_primitives::{Block, BlockHeader, Decodable, Hash256, OutPoint};
use rustoshi_storage::{
    diffbits_gate_for_header, read_core_txin_undo, DiffBitsGate, HeaderCache, HeaderMeta,
    HeaderProvider, IndexedBlock, SnapshotReader, StorageError,
};

/// Mainnet coinbases whose outputs were OVERWRITTEN by the duplicate coinbases
/// of 91880 / 91842 (BIP30); Core's set holds only the later coin, so these
/// outputs are unspendable [extension c]. Mainnet only.
const BIP30_OVERWRITTEN_MAINNET: [u32; 2] = [91_722, 91_812];
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Arguments of `rustoshi swiftsync-pass`.
#[derive(clap::Args, Debug, Clone)]
pub struct PassArgs {
    /// Chain: `mainnet` (default) or `regtest` (the control fixtures of
    /// tools/swiftsync-fixture.py).
    #[arg(long, default_value = "mainnet")]
    pub network: String,
    /// Generator pack dir (blocks.idx, undo.idx, undo.pack[, hints.*, MANIFEST.json]).
    #[arg(long)]
    pub pack: PathBuf,
    /// Core blocks dir holding blk*.dat (read-only). Default: MANIFEST sources.core_blocks.
    #[arg(long)]
    pub blocks: Option<PathBuf>,
    /// Hints dir (hints.idx + hints.pack) describing the unspent set at its height H.
    /// Default: --pack.
    #[arg(long)]
    pub hints: Option<PathBuf>,
    /// First height of the range (inclusive).
    #[arg(long = "from")]
    pub from: u32,
    /// Last height of the range (inclusive).
    #[arg(long = "to")]
    pub to: u32,
    /// Output dir: result.json, spill/, bip30-coinbase.bin.
    #[arg(long)]
    pub out: PathBuf,
    /// Script-check pool size (= worker threads; rustoshi's `--par` semantics, max 16).
    #[arg(long, default_value_t = 8)]
    pub threads: i32,
    /// 32-byte hex salt file shared by composing ranges. Default: fresh random salt.
    #[arg(long)]
    pub salt_file: Option<PathBuf>,
    /// Core snapshot of the set at `from-1`: makes the range standalone.
    #[arg(long)]
    pub start_snapshot: Option<PathBuf>,
    /// Negative controls, comma-separated (see CONTROLS in --help of the meta tools).
    #[arg(long, default_value = "")]
    pub control: String,
    /// Replace the raw bytes of block H with a scratch file: `H=PATH` (control use).
    #[arg(long = "block-file")]
    pub block_file: Vec<String>,
    /// Number of errors kept verbatim in result.json.
    #[arg(long, default_value_t = 200)]
    pub max_errors: usize,
}

// ------------------------------------------------------------------------
// controls (in-memory mutations; nothing on disk is modified)
// ------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct Controls {
    /// (field, height, coin-class): flip one field of one undo coin.
    field: Option<(String, u32, String)>,
    hint_drop: Option<u32>,
    hint_add: Option<u32>,
    drop_block: Option<u32>,
    dup_block: Option<u32>,
    forge_order: Option<u32>,
    no_pord: bool,
    bip30_spendable: bool,
    bip30_noexempt: bool,
    drop_coin: Option<u32>,
}

fn parse_controls(s: &str) -> Result<Controls, String> {
    let mut c = Controls::default();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        let (name, arg) = match part.split_once('@') {
            Some((n, a)) => (n, Some(a.parse::<u32>().map_err(|e| format!("{part}: {e}"))?)),
            None => (part, None),
        };
        let need = |a: Option<u32>| a.ok_or_else(|| format!("{name} needs @HEIGHT"));
        if let Some(rest) = name.strip_prefix("field:") {
            // field:<amount|script|height|coinbase|vout>[/<p2pkh|p2wpkh|p2pk>]
            let (f, class) = match rest.split_once('/') {
                Some((f, cl)) => (f.to_string(), cl.to_string()),
                None => (rest.to_string(), "p2pkh".to_string()),
            };
            if !["amount", "script", "height", "coinbase", "vout"].contains(&f.as_str()) {
                return Err(format!("unknown field {f}"));
            }
            if !["p2pkh", "p2wpkh", "p2pk"].contains(&class.as_str()) {
                return Err(format!("unknown coin class {class}"));
            }
            c.field = Some((f, need(arg)?, class));
            continue;
        }
        match name {
            "hint-drop" => c.hint_drop = Some(need(arg)?),
            "hint-add" => c.hint_add = Some(need(arg)?),
            "drop-block" => c.drop_block = Some(need(arg)?),
            "dup-block" => c.dup_block = Some(need(arg)?),
            "forge-order" => c.forge_order = Some(need(arg)?),
            "drop-coin" => c.drop_coin = Some(need(arg)?),
            "no-pord" => c.no_pord = true,
            "bip30-spendable" => c.bip30_spendable = true,
            "bip30-noexempt" => c.bip30_noexempt = true,
            _ => return Err(format!("unknown control {name}")),
        }
    }
    Ok(c)
}

// ------------------------------------------------------------------------
// pack readers
// ------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct BEnt {
    hash: [u8; 32],
    blk_file: u32,
    blk_pos: u32,
    blk_size: u32,
}

struct Pack {
    h: u32,
    xor: [u8; 8],
    base: [u8; 32],
    ents: Vec<BEnt>,
    undo_from: u32,
    undo_idx: Vec<(u64, u32, u32)>,
    undo: File,
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl Pack {
    fn open(dir: &Path) -> Result<Self, String> {
        let b = std::fs::read(dir.join("blocks.idx")).map_err(|e| format!("blocks.idx: {e}"))?;
        if &b[..8] != b"HHSSB1\0\0" {
            return Err("bad blocks.idx magic".into());
        }
        let h = u32_at(&b, 12);
        let mut xor = [0u8; 8];
        xor.copy_from_slice(&b[16..24]);
        let mut base = [0u8; 32];
        base.copy_from_slice(&b[24..56]);
        if b.len() != 64 + 64 * (h as usize + 1) {
            return Err("blocks.idx size".into());
        }
        let ents = (0..=h as usize)
            .map(|i| {
                let o = 64 + 64 * i;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&b[o..o + 32]);
                BEnt {
                    hash,
                    blk_file: u32_at(&b, o + 32),
                    blk_pos: u32_at(&b, o + 36),
                    blk_size: u32_at(&b, o + 40),
                }
            })
            .collect();
        let u = std::fs::read(dir.join("undo.idx")).map_err(|e| format!("undo.idx: {e}"))?;
        if &u[..8] != b"HHSSU1\0\0" {
            return Err("bad undo.idx magic".into());
        }
        if u32_at(&u, 12) != h {
            return Err("undo.idx height != blocks.idx height".into());
        }
        let undo_from = u32_at(&u, 16);
        let n = (u.len() - 32) / 16;
        let undo_idx = (0..n)
            .map(|i| {
                let o = 32 + 16 * i;
                (u64_at(&u, o), u32_at(&u, o + 8), u32_at(&u, o + 12))
            })
            .collect();
        let undo = File::open(dir.join("undo.pack")).map_err(|e| format!("undo.pack: {e}"))?;
        Ok(Pack { h, xor, base, ents, undo_from, undo_idx, undo })
    }

    fn undo_entry(&self, h: u32) -> Option<(u64, u32, u32)> {
        if h < self.undo_from {
            return None;
        }
        self.undo_idx.get((h - self.undo_from) as usize).copied()
    }
}

struct Hints {
    h: u32,
    starts: Vec<u64>,
    file: File,
}

impl Hints {
    fn open(dir: &Path) -> Result<Self, String> {
        let b = std::fs::read(dir.join("hints.idx")).map_err(|e| format!("hints.idx: {e}"))?;
        if &b[..8] != b"HHSSH1\0\0" {
            return Err("bad hints.idx magic".into());
        }
        let h = u32_at(&b, 12);
        let starts = (0..h as usize + 2).map(|i| u64_at(&b, 32 + 8 * i)).collect();
        let file = File::open(dir.join("hints.pack")).map_err(|e| format!("hints.pack: {e}"))?;
        Ok(Hints { h, starts, file })
    }

    fn count_range(&self, a: u32, b: u32) -> u64 {
        let b = b.min(self.h);
        if a > b {
            return 0;
        }
        self.starts[b as usize + 1] - self.starts[a as usize]
    }

    fn at(&self, h: u32) -> Result<Vec<(Hash256, u32)>, String> {
        if h > self.h {
            return Ok(Vec::new());
        }
        let (s, e) = (self.starts[h as usize], self.starts[h as usize + 1]);
        let mut raw = vec![0u8; ((e - s) * 36) as usize];
        self.file
            .read_exact_at(&mut raw, s * 36)
            .map_err(|e| format!("hints.pack read: {e}"))?;
        Ok(raw
            .chunks_exact(36)
            .map(|r| (Hash256(r[..32].try_into().unwrap()), u32_at(r, 32)))
            .collect())
    }
}

/// Per-thread blk-file reader (read-only; de-XORs with Core's xor.dat key).
struct BlkReader {
    dir: PathBuf,
    xor: [u8; 8],
    files: HashMap<u32, File>,
}

impl BlkReader {
    fn new(dir: &Path, xor: [u8; 8]) -> Self {
        BlkReader { dir: dir.to_path_buf(), xor, files: HashMap::new() }
    }

    fn read(&mut self, file: u32, pos: u32, len: usize) -> Result<Vec<u8>, String> {
        if !self.files.contains_key(&file) {
            if self.files.len() >= 64 {
                self.files.clear();
            }
            let p = self.dir.join(format!("blk{file:05}.dat"));
            let f = File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            self.files.insert(file, f);
        }
        let mut buf = vec![0u8; len];
        self.files[&file]
            .read_exact_at(&mut buf, pos as u64)
            .map_err(|e| format!("blk{file:05}.dat@{pos}: {e}"))?;
        if self.xor != [0u8; 8] {
            for (i, b) in buf.iter_mut().enumerate() {
                *b ^= self.xor[(pos as usize + i) % 8];
            }
        }
        Ok(buf)
    }
}

// ------------------------------------------------------------------------
// header chain (phase 0): MTP oracle + diffbits provider
// ------------------------------------------------------------------------

struct HeaderChain {
    headers: Vec<BlockHeader>,
    hashes: Vec<Hash256>,
    by_hash: HashMap<Hash256, u32>,
    mtp: Vec<u32>,
}

impl HeaderProvider for HeaderChain {
    fn header_meta(&self, hash: &Hash256) -> Result<Option<HeaderMeta>, StorageError> {
        Ok(self.by_hash.get(hash).map(|&h| {
            let hd = &self.headers[h as usize];
            HeaderMeta { bits: hd.bits, timestamp: hd.timestamp, prev_hash: hd.prev_block_hash }
        }))
    }
    fn indexed_block(&self, hash: &Hash256) -> Result<Option<IndexedBlock>, StorageError> {
        Ok(self
            .by_hash
            .get(hash)
            .map(|&h| IndexedBlock { height: h, bits: self.headers[h as usize].bits }))
    }
}

/// BIP-68 MTP oracle over the header chain (Core `GetMedianTimePast`, partial
/// window at genesis -- the same median `StoreSeqLockCtx` computes).
struct MtpCtx<'a>(&'a [u32]);

impl SequenceLockContext for MtpCtx<'_> {
    fn get_mtp_at_height(&self, height: u32) -> u32 {
        self.try_get_mtp_at_height(height).unwrap_or(u32::MAX)
    }
    fn try_get_mtp_at_height(&self, height: u32) -> Result<u32, u32> {
        self.0.get(height as usize).copied().ok_or(height)
    }
}

// ------------------------------------------------------------------------
// supplied-coin view
// ------------------------------------------------------------------------

/// The `UtxoView` handed to the production connect: this block's undo coins
/// created BELOW h, keyed by the block's own prevouts. In-block creations are
/// added/spent by `connect_block` itself, exactly as on the chainstate.
struct SuppliedView {
    map: HashMap<OutPoint, CoinEntry>,
}

impl UtxoView for SuppliedView {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<CoinEntry> {
        self.map.get(outpoint).cloned()
    }
    fn add_utxo(&mut self, outpoint: &OutPoint, coin: CoinEntry) {
        self.map.insert(outpoint.clone(), coin);
    }
    fn spend_utxo(&mut self, outpoint: &OutPoint) {
        self.map.remove(outpoint);
    }
    fn have_coin(&self, outpoint: &OutPoint) -> bool {
        self.map.contains_key(outpoint)
    }
}

// ------------------------------------------------------------------------
// aggregate
// ------------------------------------------------------------------------

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Agg([u64; 4]); // little-endian limbs, mod 2^256

impl Agg {
    fn add_digest(&mut self, d: &[u8; 32]) {
        let mut carry = 0u128;
        for i in 0..4 {
            let limb = u64::from_le_bytes(d[8 * i..8 * i + 8].try_into().unwrap());
            let s = self.0[i] as u128 + limb as u128 + carry;
            self.0[i] = s as u64;
            carry = s >> 64;
        }
    }
    fn add(&mut self, o: &Agg) {
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.0[i] as u128 + o.0[i] as u128 + carry;
            self.0[i] = s as u64;
            carry = s >> 64;
        }
    }
    fn hex(&self) -> String {
        format!("{:016x}{:016x}{:016x}{:016x}", self.0[3], self.0[2], self.0[1], self.0[0])
    }
    fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }
}

fn compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// `H(c) = SHA256(salt ‖ code u32 ‖ amount i64 ‖ CompactSize(len) ‖ script ‖ txid ‖ vout u32)`,
/// `code = height*2 + coinbase` -- every Coin field plus the outpoint (design §1.2;
/// byte-identical to tools/swiftsync-refval.py so a revealed salt can be re-checked).
fn coin_hash(salt: &[u8; 32], code: u32, amount: u64, script: &[u8], txid: &Hash256, vout: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(code.to_le_bytes());
    h.update((amount as i64).to_le_bytes());
    let mut cs = Vec::with_capacity(9);
    compact_size(&mut cs, script.len() as u64);
    h.update(&cs);
    h.update(script);
    h.update(txid.0);
    h.update(vout.to_le_bytes());
    h.finalize().into()
}

/// TxOutSer record (kernel/coinstats.cpp), the spill format swiftsync-close.py reads.
fn txoutser(out: &mut Vec<u8>, txid: &Hash256, vout: u32, code: u32, amount: u64, script: &[u8]) {
    out.extend_from_slice(&txid.0);
    out.extend_from_slice(&vout.to_le_bytes());
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&(amount as i64).to_le_bytes());
    compact_size(out, script.len() as u64);
    out.extend_from_slice(script);
}

fn is_unspendable(script: &[u8]) -> bool {
    // Core CScript::IsUnspendable (script.h): OP_RETURN start, or > MAX_SCRIPT_SIZE.
    (!script.is_empty() && script[0] == 0x6a) || script.len() > MAX_SCRIPT_SIZE
}

// ------------------------------------------------------------------------
// per-block state
// ------------------------------------------------------------------------

#[derive(Default)]
struct Partial {
    agg_in: Agg,
    agg_out: Agg,
    blocks: u64,
    txs: u64,
    inputs: u64,
    inputs_connected: u64,
    outputs: u64,
    hinted: u64,
    agg_out_terms: u64,
    skipped: u64,
    same_block: u64,
}

impl Partial {
    fn merge(&mut self, o: &Partial) {
        self.agg_in.add(&o.agg_in);
        self.agg_out.add(&o.agg_out);
        self.blocks += o.blocks;
        self.txs += o.txs;
        self.inputs += o.inputs;
        self.inputs_connected += o.inputs_connected;
        self.outputs += o.outputs;
        self.hinted += o.hinted;
        self.agg_out_terms += o.agg_out_terms;
        self.skipped += o.skipped;
        self.same_block += o.same_block;
    }
}

struct Errors {
    list: Mutex<Vec<(String, u32, String)>>,
    count: AtomicU64,
    max: usize,
}

impl Errors {
    fn push(&self, kind: &str, h: u32, msg: String) {
        self.count.fetch_add(1, Ordering::Relaxed);
        let mut l = self.list.lock().unwrap();
        if l.len() < self.max {
            l.push((kind.to_string(), h, msg));
        }
    }
}

struct Ctx<'a> {
    params: &'a ChainParams,
    pack: &'a Pack,
    hints: &'a Hints,
    hc: &'a HeaderChain,
    salt: [u8; 32],
    ctl: Controls,
    relabel: HashMap<u32, u32>,
    overrides: HashMap<u32, PathBuf>,
    errors: Errors,
    applied: Mutex<Vec<String>>,
    spills: Vec<Mutex<BufWriter<File>>>,
    coinbases: Mutex<Vec<(Hash256, u32)>>,
    now: u64,
    /// BIP34 activation height (`params.bip34_height`): BIP30 coinbase-txid
    /// uniqueness is checked below it.
    bip34_height: u32,
    /// BIP30 exception heights (`params.bip30_exception_blocks`: 91842, 91880).
    bip30_exempt: Vec<u32>,
    /// Heights whose coinbase outputs are unspendable (overwritten), mainnet only.
    bip30_overwritten: Vec<u32>,
}

impl Ctx<'_> {
    fn phys(&self, h: u32) -> u32 {
        *self.relabel.get(&h).unwrap_or(&h)
    }
}

struct UndoCoin {
    height: u32,
    coinbase: bool,
    value: u64,
    script: Vec<u8>,
}

fn parse_undo(raw: &[u8]) -> Result<Vec<Vec<UndoCoin>>, String> {
    let mut cur = Cursor::new(raw);
    let n = rustoshi_primitives::serialize::read_compact_size(&mut cur).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let m = rustoshi_primitives::serialize::read_compact_size(&mut cur).map_err(|e| e.to_string())?;
        let mut coins = Vec::with_capacity(m as usize);
        for _ in 0..m {
            let (height, coinbase, value, script) =
                read_core_txin_undo(&mut cur).map_err(|e| e.to_string())?;
            coins.push(UndoCoin { height, coinbase, value, script });
        }
        out.push(coins);
    }
    if cur.position() as usize != raw.len() {
        return Err(format!("{} trailing bytes", raw.len() - cur.position() as usize));
    }
    Ok(out)
}

/// Validate one height. `h` is the LABEL height (what the pass believes).
fn process_height(ctx: &Ctx, cs: &mut ChainState, rd: &mut BlkReader, h: u32, part: &mut Partial) {
    let err = |kind: &str, msg: String| ctx.errors.push(kind, h, msg);
    let ph = ctx.phys(h);
    let ent = ctx.pack.ents[ph as usize];

    // -- block bytes, parsed by the node's own decoder
    let raw = match ctx.overrides.get(&h) {
        Some(p) => match std::fs::read(p) {
            Ok(b) => {
                ctx.applied.lock().unwrap().push(format!("block-file h={h} from {}", p.display()));
                b
            }
            Err(e) => return err("io", format!("{}: {e}", p.display())),
        },
        None => match rd.read(ent.blk_file, ent.blk_pos, ent.blk_size as usize) {
            Ok(b) => b,
            Err(e) => return err("io", e),
        },
    };
    let mut cur = Cursor::new(&raw[..]);
    let block = match Block::decode(&mut cur) {
        Ok(b) => b,
        Err(e) => return err("parse", format!("block decode: {e}")),
    };
    if cur.position() as usize != raw.len() {
        return err("parse", "trailing bytes after block".into());
    }
    // Header binds to the chain: hash == blocks.idx[h] == phase-0 header chain.
    let bhash = block.block_hash();
    if bhash.0 != ctx.pack.ents[h as usize].hash || bhash != ctx.hc.hashes[h as usize] {
        err("header", format!("block hash {bhash} != blocks.idx[{h}]"));
    }
    part.blocks += 1;
    part.txs += block.transactions.len() as u64;
    let txids: Vec<Hash256> = block.transactions.iter().map(|t| t.txid()).collect();

    if h == 0 {
        // Genesis: no inputs, its output is unspendable (never in the set).
        if bhash != ctx.params.genesis_hash {
            err("header", "genesis hash mismatch".into());
        }
        for tx in &block.transactions {
            part.outputs += tx.outputs.len() as u64;
            part.skipped += tx.outputs.len() as u64;
        }
        return;
    }

    // -- undo coins (untrusted), node's own Core coin decoder
    let (uoff, ulen, unin) = match ctx.pack.undo_entry(ph) {
        Some(e) => e,
        None => return err("undo", format!("no undo.idx entry for {ph}")),
    };
    let mut uraw = vec![0u8; ulen as usize];
    if let Err(e) = ctx.pack.undo.read_exact_at(&mut uraw, uoff) {
        return err("io", format!("undo.pack: {e}"));
    }
    let mut undo = match parse_undo(&uraw) {
        Ok(u) => u,
        Err(e) => return err("undo-parse", e),
    };
    if undo.len() + 1 != block.transactions.len() {
        return err("undo-count", format!("{} CTxUndo for {} txs", undo.len(), block.transactions.len() - 1));
    }
    let mut nin = 0u64;
    for (i, tu) in undo.iter().enumerate() {
        let want = block.transactions[i + 1].inputs.len();
        nin += tu.len() as u64;
        if tu.len() != want {
            return err("undo-count", format!("tx {} has {want} inputs, {} undo coins", i + 1, tu.len()));
        }
    }
    if nin != unin as u64 {
        err("undo-count", format!("undo.idx n_inputs {unin} != coins {nin}"));
    }

    // -- controls on the supplied coins
    if !ctx.relabel.is_empty() {
        for tu in undo.iter_mut() {
            for c in tu.iter_mut() {
                if let Some(&r) = ctx.relabel.get(&c.height) {
                    c.height = r;
                }
            }
        }
    }
    let mut vout_flip: Option<(usize, usize)> = None;
    if let Some((f, fh, class)) = &ctx.ctl.field {
        if *fh == h {
            'outer: for (i, tu) in undo.iter_mut().enumerate() {
                for (j, c) in tu.iter_mut().enumerate() {
                    let s = &c.script;
                    let class_ok = match class.as_str() {
                        "p2pkh" => s.len() == 25 && s[..3] == [0x76, 0xa9, 0x14],
                        "p2wpkh" => s.len() == 22 && s[..2] == [0x00, 0x14],
                        "p2pk" => (s.len() == 35 && s[0] == 33) || (s.len() == 67 && s[0] == 65),
                        _ => false,
                    };
                    if c.coinbase || !class_ok || c.height >= h || h - c.height <= 100 {
                        continue;
                    }
                    match f.as_str() {
                        "amount" => c.value += 1,
                        "script" => {
                            // P2PKH: last pubkey-hash byte; P2PK: a pubkey byte
                            // (the signature then checks against another key).
                            let k = if class == "p2pk" { 10 } else { s.len() - 3 };
                            c.script[k] ^= 1;
                        }
                        "height" => c.height -= 1,
                        "coinbase" => c.coinbase = !c.coinbase,
                        "vout" => vout_flip = Some((i + 1, j)),
                        _ => {}
                    }
                    ctx.applied.lock().unwrap().push(format!(
                        "field:{f}/{class} h={h} tx={} in={j} coin_height={} value={}",
                        i + 1,
                        c.height,
                        c.value
                    ));
                    break 'outer;
                }
            }
        }
    }
    if ctx.ctl.drop_coin == Some(h) {
        if let Some(tu) = undo.iter_mut().find(|tu| !tu.is_empty()) {
            tu.pop();
            ctx.applied.lock().unwrap().push(format!("drop-coin h={h}"));
        }
    }
    for (i, tu) in undo.iter().enumerate() {
        if tu.len() != block.transactions[i + 1].inputs.len() {
            return err("undo-count", format!("tx {} inputs != undo coins", i + 1));
        }
    }

    // -- P-ORD [extension a] + the supplied view
    let mut view = SuppliedView { map: HashMap::with_capacity(nin as usize) };
    let mut same_block: Vec<(usize, usize)> = Vec::new();
    let mut pord_fail = false;
    for (i, tu) in undo.iter().enumerate() {
        let tx = &block.transactions[i + 1];
        for (j, c) in tu.iter().enumerate() {
            let op = &tx.inputs[j].previous_output;
            if c.height == h {
                same_block.push((i + 1, j));
                // Not supplied: connect_block must find it among this block's
                // own earlier outputs (its in-block add_utxo), or reject.
                if ctx.ctl.no_pord {
                    view.map.insert(op.clone(), CoinEntry { height: c.height, is_coinbase: c.coinbase, value: c.value, script_pubkey: c.script.clone() });
                }
            } else {
                if c.height > h && !ctx.ctl.no_pord {
                    err("P-ORD", format!("tx {} in {j} spends a coin created at {} > {h}", i + 1, c.height));
                    pord_fail = true;
                }
                view.map.insert(
                    op.clone(),
                    CoinEntry { height: c.height, is_coinbase: c.coinbase, value: c.value, script_pubkey: c.script.clone() },
                );
            }
        }
    }

    // A P-ORD failure has already failed the pass. The block is still run
    // through the connect and both aggregates (with the future coin supplied,
    // as `no-pord` would) so the record shows WHICH checks see the forgery:
    // the aggregate balances on a truthful out-of-order spend, only P-ORD
    // catches it (design §2 case H).
    let _ = pord_fail;

    // -- connect-path bad-diffbits backstop (main.rs::check_connect_diffbits)
    let parent = ctx.hc.hashes[(h - 1) as usize];
    let mut hcache = HeaderCache::new(256);
    match diffbits_gate_for_header(ctx.hc, &mut hcache, &parent, block.header.bits, block.header.timestamp, h, None, ctx.params) {
        Ok(DiffBitsGate::Required(want)) if want == block.header.bits => {}
        Ok(DiffBitsGate::Required(want)) => {
            err("node:bad-diffbits", format!("nBits {:#010x} != required {want:#010x}", block.header.bits))
        }
        Ok(DiffBitsGate::DegradedSnapshotBase) => err("node:bad-diffbits", "degraded gate on a full header chain".into()),
        Err(e) => err("node:bad-diffbits", e),
    }

    // -- THE production connect (ChainState::process_block_with_seq_ctx)
    cs.set_tip(parent, h - 1);
    let prev_mtp = ctx.hc.mtp[(h - 1) as usize];
    let prev_ts = ctx.hc.headers[(h - 1) as usize].timestamp;
    let seq = MtpCtx(&ctx.hc.mtp);
    match cs.process_block_with_seq_ctx(&block, &mut view, prev_mtp, true, ctx.now, &seq, false, prev_ts) {
        Ok(_) => part.inputs_connected += nin,
        Err(e) => err("node", format!("{e} [{e:?}]")),
    }

    // -- P-ORD, same-block half: created by an EARLIER tx with identical data
    if !ctx.ctl.no_pord && !same_block.is_empty() {
        let pos: HashMap<&Hash256, usize> = txids.iter().enumerate().map(|(k, t)| (t, k)).collect();
        for &(i, j) in &same_block {
            part.same_block += 1;
            let op = &block.transactions[i].inputs[j].previous_output;
            let c = &undo[i - 1][j];
            match pos.get(&op.txid) {
                Some(&k) if k < i => {
                    let outs = &block.transactions[k].outputs;
                    let ok = (op.vout as usize) < outs.len()
                        && outs[op.vout as usize].value == c.value
                        && outs[op.vout as usize].script_pubkey == c.script
                        && c.coinbase == (k == 0);
                    if !ok {
                        err("P-ORD", format!("tx {i} in {j}: same-block coin data != created output"));
                    }
                }
                _ => err("P-ORD", format!("tx {i} in {j}: coin height == h but prevout not created earlier in block")),
            }
        }
    }

    // -- Agg_in over every input (supplied coin, prevout from the BLOCK)
    for (i, tu) in undo.iter().enumerate() {
        let tx = &block.transactions[i + 1];
        for (j, c) in tu.iter().enumerate() {
            let op = &tx.inputs[j].previous_output;
            let mut vout = op.vout;
            if vout_flip == Some((i + 1, j)) {
                vout ^= 1;
            }
            let code = c.height.wrapping_mul(2).wrapping_add(c.coinbase as u32);
            part.agg_in.add_digest(&coin_hash(&ctx.salt, code, c.value, &c.script, &op.txid, vout));
            part.inputs += 1;
        }
    }

    // -- outputs: unspendable skip / hinted -> spill / else Agg_out
    let mut hint_list = match ctx.hints.at(ph) {
        Ok(l) => l,
        Err(e) => return err("hints", e),
    };
    if ctx.ctl.hint_drop == Some(h) && !hint_list.is_empty() {
        let d = hint_list.remove(0);
        ctx.applied.lock().unwrap().push(format!("hint-drop {}:{} h={h}", d.0, d.1));
    }
    let mut hset: HashSet<(Hash256, u32)> = hint_list.iter().cloned().collect();
    if hset.len() != hint_list.len() {
        err("hints", "duplicate hint".into());
    }
    if ctx.ctl.hint_add == Some(h) {
        'add: for (k, tx) in block.transactions.iter().enumerate().skip(1).chain(block.transactions.iter().enumerate().take(1)) {
            for (v, o) in tx.outputs.iter().enumerate() {
                if !hset.contains(&(txids[k], v as u32)) && !is_unspendable(&o.script_pubkey) {
                    hset.insert((txids[k], v as u32));
                    ctx.applied.lock().unwrap().push(format!("hint-add {}:{v} h={h}", txids[k]));
                    break 'add;
                }
            }
        }
    }
    let tidx = rayon::current_thread_index().unwrap_or(ctx.spills.len() - 1).min(ctx.spills.len() - 1);
    let mut spill = Vec::new();
    let mut hits = 0usize;
    for (k, tx) in block.transactions.iter().enumerate() {
        for (v, o) in tx.outputs.iter().enumerate() {
            part.outputs += 1;
            let overwritten = k == 0 && ctx.bip30_overwritten.contains(&h) && !ctx.ctl.bip30_spendable;
            if overwritten || is_unspendable(&o.script_pubkey) {
                part.skipped += 1;
                continue;
            }
            let code = h * 2 + (k == 0) as u32;
            if hset.contains(&(txids[k], v as u32)) {
                hits += 1;
                part.hinted += 1;
                txoutser(&mut spill, &txids[k], v as u32, code, o.value, &o.script_pubkey);
            } else {
                part.agg_out_terms += 1;
                part.agg_out.add_digest(&coin_hash(&ctx.salt, code, o.value, &o.script_pubkey, &txids[k], v as u32));
            }
        }
    }
    if hits != hset.len() {
        err("hint-count", format!("hint hits {hits} != |hints[{h}]| {}", hset.len()));
    }
    if !spill.is_empty() {
        if let Err(e) = ctx.spills[tidx].lock().unwrap().write_all(&spill) {
            err("io", format!("spill write: {e}"));
        }
    }
    // -- BIP30 coinbase-txid cache [extension c]
    if h < ctx.bip34_height && (ctx.ctl.bip30_noexempt || !ctx.bip30_exempt.contains(&h)) {
        ctx.coinbases.lock().unwrap().push((txids[0], h));
    }
}

// ------------------------------------------------------------------------
// start set (standalone ranges)
// ------------------------------------------------------------------------

struct StartSetResult {
    coins: u64,
    survivors: u64,
    spent_in_range: u64,
    hints_below_from: u64,
    agg_out: Agg,
}

fn process_start_set(ctx: &Ctx, path: &Path, from: u32, spill_dir: &Path) -> Result<StartSetResult, String> {
    // Hints for heights < from: the survivors of S(from-1) at the hints height.
    let mut keys: Vec<(Hash256, u32)> = Vec::with_capacity(ctx.hints.count_range(0, from - 1) as usize);
    for h in 0..from.min(ctx.hints.h + 1) {
        keys.extend(ctx.hints.at(h)?);
    }
    // Any total order works: membership is by binary search, never by
    // relying on the snapshot's own coin order.
    keys.sort_unstable();
    let mut matched = vec![false; keys.len()];
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut rdr = SnapshotReader::open(f, &ctx.params.network_magic)
        .map_err(|e| format!("start snapshot: {e}"))?
        .with_base_height(from - 1);
    if rdr.metadata().base_blockhash != ctx.hc.hashes[(from - 1) as usize] {
        return Err(format!(
            "start snapshot base {} != header chain [{}] {}",
            rdr.metadata().base_blockhash,
            from - 1,
            ctx.hc.hashes[(from - 1) as usize]
        ));
    }
    let mut out = BufWriter::new(File::create(spill_dir.join("startset-survivors.bin")).map_err(|e| e.to_string())?);
    let mut r = StartSetResult { coins: 0, survivors: 0, spent_in_range: 0, hints_below_from: keys.len() as u64, agg_out: Agg::default() };
    let mut rec = Vec::new();
    while let Some((op, coin)) = rdr.read_coin().map_err(|e| format!("start snapshot coin: {e}"))? {
        r.coins += 1;
        let code = coin.height * 2 + coin.is_coinbase as u32;
        let found = keys.binary_search(&(op.txid, op.vout)).ok();
        match found {
            Some(i) => {
                if matched[i] {
                    return Err(format!("start set: duplicate coin {}:{}", op.txid, op.vout));
                }
                matched[i] = true;
                r.survivors += 1;
                rec.clear();
                txoutser(&mut rec, &op.txid, op.vout, code, coin.tx_out.value, &coin.tx_out.script_pubkey);
                out.write_all(&rec).map_err(|e| e.to_string())?;
            }
            None => {
                r.spent_in_range += 1;
                r.agg_out.add_digest(&coin_hash(&ctx.salt, code, coin.tx_out.value, &coin.tx_out.script_pubkey, &op.txid, op.vout));
            }
        }
    }
    rdr.verify_complete().map_err(|e| format!("start snapshot: {e}"))?;
    out.flush().map_err(|e| e.to_string())?;
    if rdr.coins_read() != rdr.coins_total() {
        return Err("start snapshot: short".into());
    }
    let unmatched = matched.iter().filter(|m| !**m).count();
    if unmatched != 0 {
        return Err(format!("start set: {unmatched} hints below --from are not coins of S(from-1)"));
    }
    Ok(r)
}

// ------------------------------------------------------------------------
// driver
// ------------------------------------------------------------------------

fn vm_hwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

fn exe_sha256() -> String {
    std::fs::read("/proc/self/exe").map(|b| hex::encode(Sha256::digest(&b))).unwrap_or_default()
}

fn read_salt(p: &Option<PathBuf>) -> Result<[u8; 32], String> {
    let mut salt = [0u8; 32];
    match p {
        Some(p) => {
            let s = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let b = hex::decode(s.trim()).map_err(|e| format!("salt: {e}"))?;
            if b.len() != 32 {
                return Err("salt must be 32 bytes hex".into());
            }
            salt.copy_from_slice(&b);
        }
        None => {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut salt);
        }
    }
    Ok(salt)
}

/// Entry point. Returns the process exit code (0 = PASS).
pub fn run(a: PassArgs) -> i32 {
    match run_inner(a) {
        Ok(pass) => {
            if pass {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("swiftsync-pass: FATAL: {e}");
            2
        }
    }
}

fn run_inner(a: PassArgs) -> Result<bool, String> {
    let t0 = Instant::now();
    let params = match a.network.as_str() {
        "mainnet" => ChainParams::mainnet(),
        "regtest" => ChainParams::regtest(),
        n => return Err(format!("--network {n}: only mainnet and regtest are supported")),
    };
    let ctl = parse_controls(&a.control)?;
    let pack = Pack::open(&a.pack)?;
    let hints = Hints::open(a.hints.as_deref().unwrap_or(&a.pack))?;
    if a.to > pack.h || a.from > a.to {
        return Err(format!("bad range {}..{} (pack H={})", a.from, a.to, pack.h));
    }
    if a.to > hints.h {
        return Err(format!("hints describe height {} < --to {}", hints.h, a.to));
    }
    let blocks_dir = match &a.blocks {
        Some(b) => b.clone(),
        None => {
            let m: serde_json::Value = serde_json::from_slice(
                &std::fs::read(a.pack.join("MANIFEST.json")).map_err(|e| format!("MANIFEST.json: {e}"))?,
            )
            .map_err(|e| e.to_string())?;
            PathBuf::from(m["sources"]["core_blocks"].as_str().ok_or("MANIFEST sources.core_blocks")?)
        }
    };
    let salt = read_salt(&a.salt_file)?;
    let threads = init_script_check_threads(a.threads.clamp(1, 16));
    std::fs::create_dir_all(a.out.join("spill")).map_err(|e| e.to_string())?;
    for e in std::fs::read_dir(a.out.join("spill")).map_err(|e| e.to_string())? {
        let _ = std::fs::remove_file(e.map_err(|e| e.to_string())?.path());
    }
    let mut relabel = HashMap::new();
    if let Some(k) = ctl.forge_order {
        relabel.insert(k, k + 1);
        relabel.insert(k + 1, k);
    }
    let mut overrides = HashMap::new();
    for s in &a.block_file {
        let (h, p) = s.split_once('=').ok_or("--block-file H=PATH")?;
        overrides.insert(h.parse::<u32>().map_err(|e| e.to_string())?, PathBuf::from(p));
    }
    eprintln!(
        "swiftsync-pass: range {}..{} hints@{} threads={} control={:?} pack={}",
        a.from, a.to, hints.h, threads, a.control, a.pack.display()
    );

    // ---- phase 0: header chain 0..=to (node header checks: linkage, PoW;
    // the contextual header gates run per block inside process_block).
    let tp = Instant::now();
    let n = a.to as usize + 1;
    let hdrs: Vec<Result<BlockHeader, String>> = install_on_script_check_pool(|| {
        (0..n)
            .into_par_iter()
            .map_init(
                || BlkReader::new(&blocks_dir, pack.xor),
                |rd, h| {
                    let e = pack.ents[*relabel.get(&(h as u32)).unwrap_or(&(h as u32)) as usize];
                    let raw = rd.read(e.blk_file, e.blk_pos, 80)?;
                    BlockHeader::deserialize(&raw).map_err(|e| e.to_string())
                },
            )
            .collect()
    });
    let mut headers = Vec::with_capacity(n);
    for (h, r) in hdrs.into_iter().enumerate() {
        headers.push(r.map_err(|e| format!("header {h}: {e}"))?);
    }
    let hashes: Vec<Hash256> = install_on_script_check_pool(|| headers.par_iter().map(|h| h.block_hash()).collect());
    let mut hdr_errors: Vec<String> = Vec::new();
    if hashes[0] != params.genesis_hash {
        hdr_errors.push("header 0 is not the mainnet genesis".into());
    }
    for h in 0..n {
        if hashes[h].0 != pack.ents[h].hash {
            hdr_errors.push(format!("header {h}: hash != blocks.idx"));
        }
        if h > 0 && headers[h].prev_block_hash != hashes[h - 1] {
            hdr_errors.push(format!("header {h}: hashPrev != hash[{}] (linkage)", h - 1));
        }
        if !rustoshi_consensus::pow::check_proof_of_work(&hashes[h].0, headers[h].bits, &params) {
            hdr_errors.push(format!("header {h}: PoW"));
        }
        if hdr_errors.len() > 20 {
            break;
        }
    }
    if a.to == pack.h && hashes[a.to as usize].0 != pack.base {
        hdr_errors.push("tip != pack base hash".into());
    }
    let by_hash: HashMap<Hash256, u32> = hashes.iter().enumerate().map(|(h, x)| (*x, h as u32)).collect();
    let mut mtp = Vec::with_capacity(n);
    for h in 0..n {
        let lo = h.saturating_sub(10);
        let mut w: Vec<u32> = headers[lo..=h].iter().map(|x| x.timestamp).collect();
        w.sort_unstable();
        mtp.push(w[w.len() / 2]);
    }
    let hc = HeaderChain { headers, hashes, by_hash, mtp };
    let phase0_s = tp.elapsed().as_secs_f64();
    eprintln!("swiftsync-pass: phase 0: {n} headers in {phase0_s:.1}s, {} header errors", hdr_errors.len());

    let nspill = threads + 1;
    let mut spills = Vec::with_capacity(nspill);
    for t in 0..nspill {
        let f = File::create(a.out.join("spill").join(format!("r{:07}-{:07}-t{t:02}.bin", a.from, a.to)))
            .map_err(|e| e.to_string())?;
        spills.push(Mutex::new(BufWriter::with_capacity(1 << 20, f)));
    }
    let ctx = Ctx {
        params: &params,
        pack: &pack,
        hints: &hints,
        hc: &hc,
        salt,
        ctl: ctl.clone(),
        relabel,
        overrides,
        errors: Errors { list: Mutex::new(Vec::new()), count: AtomicU64::new(0), max: a.max_errors },
        applied: Mutex::new(Vec::new()),
        spills,
        coinbases: Mutex::new(Vec::new()),
        now: rustoshi_consensus::current_time_secs(),
        bip34_height: params.bip34_height,
        bip30_exempt: params.bip30_exception_blocks.iter().map(|(h, _)| *h).collect(),
        bip30_overwritten: if a.network == "mainnet" { BIP30_OVERWRITTEN_MAINNET.to_vec() } else { Vec::new() },
    };
    for e in &hdr_errors {
        ctx.errors.push("header-chain", 0, e.clone());
    }

    // ---- phase 1: every height of the range, out of order, on the pool
    let mut heights: Vec<u32> = (a.from..=a.to).collect();
    if let Some(d) = ctl.drop_block {
        heights.retain(|&h| h != d);
        ctx.applied.lock().unwrap().push(format!("drop-block {d}"));
    }
    if let Some(d) = ctl.dup_block {
        heights.push(d);
        ctx.applied.lock().unwrap().push(format!("dup-block {d}"));
    }
    let seen: Vec<AtomicU8> = (a.from..=a.to).map(|_| AtomicU8::new(0)).collect();
    let done = AtomicU64::new(0);
    let total = heights.len() as u64;
    let tp1 = Instant::now();
    let stop_progress = AtomicBool::new(false);
    let script_base = read_script_checks_total();
    let part = std::thread::scope(|s| {
        s.spawn(|| {
            let mut last = Instant::now();
            while !stop_progress.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if last.elapsed().as_secs() >= 60 {
                    last = Instant::now();
                    let d = done.load(Ordering::Relaxed);
                    eprintln!(
                        "swiftsync-pass: {d}/{total} blocks, {:.0}s, scripts {} , rss {} MiB, errors {}",
                        tp1.elapsed().as_secs_f64(),
                        read_script_checks_total() - script_base,
                        vm_hwm_kb() / 1024,
                        ctx.errors.count.load(Ordering::Relaxed)
                    );
                }
            }
        });
        let r = install_on_script_check_pool(|| {
            heights
                .par_iter()
                .with_max_len(4)
                .fold(
                    || (Partial::default(), None::<(ChainState, BlkReader)>),
                    |(mut p, st), &h| {
                        let (mut cs, mut rd) = st.unwrap_or_else(|| {
                            (ChainState::new(params.genesis_hash, 0, params.clone()), BlkReader::new(&blocks_dir, pack.xor))
                        });
                        seen[(h - a.from) as usize].fetch_add(1, Ordering::Relaxed);
                        process_height(&ctx, &mut cs, &mut rd, h, &mut p);
                        done.fetch_add(1, Ordering::Relaxed);
                        (p, Some((cs, rd)))
                    },
                )
                .map(|(p, _)| p)
                .reduce(Partial::default, |mut x, y| {
                    x.merge(&y);
                    x
                })
        });
        stop_progress.store(true, Ordering::Relaxed);
        r
    });
    let phase1_s = tp1.elapsed().as_secs_f64();
    for s in &ctx.spills {
        s.lock().unwrap().flush().map_err(|e| format!("spill flush: {e}"))?;
    }
    let scripts_run = read_script_checks_total() - script_base;
    let mut agg_out = part.agg_out;

    // ---- start set (standalone range)
    let mut start_json = serde_json::Value::Null;
    if a.from > 0 {
        if let Some(p) = &a.start_snapshot {
            match process_start_set(&ctx, p, a.from, &a.out.join("spill")) {
                Ok(r) => {
                    agg_out.add(&r.agg_out);
                    start_json = serde_json::json!({
                        "snapshot": p.display().to_string(), "coins": r.coins, "survivors": r.survivors,
                        "spent_in_range": r.spent_in_range, "hints_below_from": r.hints_below_from,
                    });
                }
                Err(e) => ctx.errors.push("startset", a.from, e),
            }
        }
    }

    // ---- completeness [extension b]
    let missing: Vec<u32> = (a.from..=a.to).filter(|h| seen[(h - a.from) as usize].load(Ordering::Relaxed) == 0).collect();
    let dups: Vec<u32> = (a.from..=a.to).filter(|h| seen[(h - a.from) as usize].load(Ordering::Relaxed) > 1).collect();
    if !missing.is_empty() {
        ctx.errors.push("completeness", missing[0], format!("{} heights never processed, first {:?}", missing.len(), &missing[..missing.len().min(5)]));
    }
    if !dups.is_empty() {
        ctx.errors.push("completeness", dups[0], format!("{} heights processed twice: {:?}", dups.len(), &dups[..dups.len().min(5)]));
    }
    // ---- BIP30 coinbase-txid uniqueness [extension c]
    let mut cbs = ctx.coinbases.lock().unwrap().clone();
    cbs.sort();
    for w in cbs.windows(2) {
        if w[0].0 == w[1].0 {
            ctx.errors.push("BIP30", w[1].1, format!("duplicate coinbase txid {} at {} and {}", w[0].0, w[0].1, w[1].1));
        }
    }
    {
        let mut f = BufWriter::new(File::create(a.out.join("bip30-coinbase.bin")).map_err(|e| e.to_string())?);
        for (t, h) in &cbs {
            f.write_all(&t.0).and_then(|_| f.write_all(&h.to_le_bytes())).map_err(|e| e.to_string())?;
        }
    }

    // ---- verdict
    let expected_inputs: u64 = (a.from.max(1)..=a.to).map(|h| pack.undo_entry(h).map(|e| e.2 as u64).unwrap_or(0)).sum();
    let standalone = a.from == 0 || a.start_snapshot.is_some();
    let complete_to_hints = a.to == hints.h;
    let errs = ctx.errors.list.lock().unwrap().clone();
    let n_errors = ctx.errors.count.load(Ordering::Relaxed);
    let mut fired: Vec<String> = errs.iter().map(|e| e.0.clone()).collect();
    fired.sort();
    fired.dedup();
    let agg_equal = part.agg_in == agg_out;
    if standalone && complete_to_hints {
        if !agg_equal {
            fired.push("aggregate".into());
        }
        if part.agg_in.is_zero() || agg_out.is_zero() {
            fired.push("aggregate-zero".into());
        }
    }
    // Script-count denominator: every input consumed from U was dispatched to
    // the node's script checker (rustoshi counts at dispatch, before the
    // verdict, so a failing block still counts its inputs), and the inputs
    // consumed equal Σ n_inputs of undo.idx over the range.
    if scripts_run != part.inputs || (part.inputs != expected_inputs && ctl.drop_block.is_none() && ctl.dup_block.is_none()) {
        fired.push("script-count".into());
    }
    let applied = ctx.applied.lock().unwrap().clone();
    let verdict = if fired.is_empty() { "PASS" } else { "FAIL" };
    let res = serde_json::json!({
        "tool": "rustoshi swiftsync-pass",
        "node": "rustoshi",
        "network": a.network,
        "exe_sha256": exe_sha256(),
        "validation_path": "main.rs connect loop: rustoshi_storage::diffbits_gate_for_header + ChainState::process_block_with_seq_ctx(f_requested=true, skip_scripts=false) -> check_block, contextual_check_block_header, contextual_check_block, connect_block_with_sequence_locks",
        "range": [a.from, a.to],
        "hints_height": hints.h,
        "hints_dir": a.hints.as_ref().unwrap_or(&a.pack).display().to_string(),
        "standalone": standalone,
        "composes": !standalone,
        "control": if a.control.is_empty() { serde_json::Value::Null } else { a.control.clone().into() },
        "block_file": a.block_file,
        "control_applied": applied,
        "salt": hex::encode(salt),
        "agg_in": part.agg_in.hex(),
        "agg_out": agg_out.hex(),
        "agg_out_blocks_only": part.agg_out.hex(),
        "agg_equal": agg_equal,
        "scripts_run": scripts_run,
        "scripts_counter": "rustoshi_consensus::read_script_checks_total (inputs dispatched to the script checker)",
        "inputs": part.inputs,
        "inputs_connected": part.inputs_connected,
        "expected_inputs_undo_idx": expected_inputs,
        "missing_heights": missing.len(),
        "duplicate_heights": dups.len(),
        "start_set": start_json,
        "stats": {
            "blocks": part.blocks, "txs": part.txs, "outputs": part.outputs, "hinted": part.hinted,
            "agg_out_terms": part.agg_out_terms, "skipped": part.skipped, "same_block": part.same_block,
            "bip30_coinbases": cbs.len(), "hints_in_range": hints.count_range(a.from, a.to),
        },
        "fired": fired,
        "errors": errs.iter().map(|(k, h, m)| format!("{k} @{h}: {m}")).collect::<Vec<_>>(),
        "n_errors": n_errors,
        "threads": threads,
        "timing_s": { "phase0_headers": phase0_s, "phase1_blocks": phase1_s, "total": t0.elapsed().as_secs_f64() },
        "throughput": {
            "blocks_per_s": part.blocks as f64 / phase1_s.max(1e-9),
            "inputs_per_s": part.inputs as f64 / phase1_s.max(1e-9),
        },
        "rss_peak_kib": vm_hwm_kb(),
        "verdict": verdict,
    });
    let js = serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?;
    std::fs::write(a.out.join("result.json"), &js).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({"range": [a.from, a.to], "verdict": verdict, "fired": res["fired"], "agg_equal": agg_equal,
            "scripts_run": scripts_run, "inputs": part.inputs, "expected_inputs_undo_idx": expected_inputs,
            "n_errors": n_errors, "first_error": errs.first().map(|e| format!("{} @{}: {}", e.0, e.1, e.2)),
            "elapsed_s": t0.elapsed().as_secs_f64()})
    );
    Ok(verdict == "PASS")
}
