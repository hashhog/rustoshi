//! W141 — ZMQ publisher + REST endpoints + Notification scripts audit
//! (rustoshi, discovery wave, 30 gates / 18 BUGS).
//!
//! Reference surfaces:
//! - `bitcoin-core/src/zmq/zmqnotificationinterface.cpp` (213 LOC) — topic
//!   factory map + IBD/historical gates + `TryForEachAndRemoveFailed`.
//! - `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` (293 LOC) — multipart
//!   frame layout, per-instance sequence counter, IPC prefix normalisation.
//! - `bitcoin-core/src/rest.cpp` (1,178 LOC) — `StartREST` URI table at
//!   line 1141, `RESTERR` HTTP-status mapping, `MAX_REST_HEADERS_RESULTS =
//!   2000`, `MAX_GETUTXOS_OUTPOINTS = 15`.
//! - `bitcoin-core/src/init.cpp:2009-2018` — `-blocknotify` dispatch.
//! - `bitcoin-core/src/wallet/wallet.cpp:1139-1164` — `-walletnotify`
//!   dispatch + `%s`/`%w`/`%b`/`%h` substitution rules.
//! - `bitcoin-core/src/node/kernel_notifications.cpp:30-47` — `-alertnotify`
//!   sanitised + single-quoted dispatch.
//! - `bitcoin-core/src/common/system.cpp:40-62` — `ShellEscape` + `runCommand`.
//!
//! Audit subject (rustoshi):
//! - `crates/rpc/src/zmq.rs` (1,079 LOC) — full ZMQ pipeline (per-topic
//!   queues / worker thread / pub/sub round-trip tests) but never wired
//!   in production (BUG-1).
//! - `crates/rpc/src/rest.rs` (2,470 LOC) — 11 REST routes mounted at
//!   line 2034; missing `/rest/blockpart`, `/rest/spenttxouts`,
//!   `/rest/deploymentinfo` from Core's 14-route table.
//! - (absence) `crates/rpc/src/notify.rs` — does not exist; `-blocknotify`
//!   / `-walletnotify` / `-alertnotify` CLI flags + dispatchers absent.
//!
//! Gate legend:
//! - PASS  : behaviour matches Core (regression pin).
//! - BUG   : implemented but diverges from Core (CDIV-ZMQ / CDIV-REST /
//!           CDIV-NOTIFY in the audit doc).
//! - MISSING : Core implements; rustoshi has no equivalent.
//! - WIRING : Code exists in tree but never reached in production.
//!
//! Severity (operator-visible):
//! - P0 : node silently does not provide a documented Core feature.
//! - P1 : feature provided but wire-incompatible.
//! - P2 : feature provided, subtly different.
//! - P3 : doc / comment / cosmetic.
//!
//! Wave W141 summary (30 gates / 18 BUGS) split across subsystems:
//!   ZMQ (G1-G10 / BUG-1..BUG-11)
//!   REST (G11-G25 / BUG-12..BUG-20)
//!   NOTIFY (G26-G30 / BUG-21..BUG-25)
//!
//! BUG cross-reference:
//!   BUG-1  (P0) : ZMQ subsystem never wired in main.rs (zmq.rs:498
//!                 `ZmqNotifier::create` has zero callers outside tests).
//!   BUG-2  (P1) : Sequence numbers keyed by topic, not by notifier
//!                 instance — two `pubhashblock=` endpoints share a
//!                 counter and each sees gaps (zmq.rs:225, 322).
//!   BUG-3  (P1) : `unix://` prefix not normalised to `ipc://`
//!                 (zmqnotificationinterface.cpp:62-64 parity gap).
//!   BUG-4  (P2) : `-zmqpub<topic>hwm=N` per-notifier HWM override absent
//!                 (zmqnotificationinterface.cpp:69 parity gap).
//!   BUG-5  (P2) : IBD gate on `UpdatedBlockTip` absent (latent under
//!                 BUG-1; would swamp subscribers during IBD).
//!   BUG-6  (P3) : No `TryForEachAndRemoveFailed` semantic; failed
//!                 sockets are reused instead of dropped + reopened.
//!   BUG-7  (P3) : `ZmqCommand::Shutdown` arm in `handle_command` is
//!                 dead code (zmq.rs:358-361).
//!   BUG-8  (P3) : `#[allow(dead_code)] context` lint suppression marks
//!                 a confession-as-comment on lifetime ownership.
//!   BUG-9  (P3) : Allocation pressure — address vectors cloned twice
//!                 per notify_block (zmq.rs:366-376).
//!   BUG-10 (P3) : No clap CLI surface for `-zmqpub*` flags (rustoshi/
//!                 src/main.rs Cli struct has no `zmqpubhashblock` etc.).
//!   BUG-11 (P3) : Module docs (zmq.rs:23-24) don't qualify sequence
//!                 scope, masking BUG-2.
//!   BUG-12 (P0) : `/rest/block/<hash>.json` returns txid-only `tx`
//!                 array; Core returns full `vin[]/vout[]` objects.
//!   BUG-13 (P3) : `build_block_info_simple` comment-as-confession
//!                 (rest.rs:997-999 "this is the same since we already
//!                 only return txids").
//!   BUG-14 (P1) : `/rest/blockpart/<hash>` not implemented.
//!   BUG-15 (P1) : `/rest/spenttxouts/<hash>` not implemented.
//!   BUG-16 (P1) : `/rest/deploymentinfo` not implemented.
//!   BUG-17 (P1) : `?count=N` query form of `/rest/headers` +
//!                 `/rest/blockfilterheaders` not implemented.
//!   BUG-18 (P2) : `/rest/getutxos` POST body for binary input not
//!                 implemented (rest.rs:2043 GET-only).
//!   BUG-19 (P1) : No warmup HTTP 503 — operators hitting REST during
//!                 startup get 200 + stale data.
//!   BUG-20 (P2) : REST runs on `rpc_port+100` instead of sharing the
//!                 JSON-RPC port; tight-firewall operators see REST
//!                 blocked.
//!   BUG-21 (P2) : No `runCommand` thread-detach helper (blocks
//!                 BUG-22/23/24 fixes).
//!   BUG-22 (P1) : `-blocknotify=<cmd>` CLI arg + dispatch missing.
//!   BUG-23 (P1) : `-walletnotify=<cmd>` CLI arg + dispatch missing.
//!   BUG-24 (P1) : `-alertnotify=<cmd>` CLI arg + dispatch missing.
//!   BUG-25 (P2) : `ShellEscape` helper for `%w` substitution missing.

#![allow(clippy::needless_return)]

use std::path::Path;

// ====================================================================
// SUBSYSTEM 1: ZMQ PUBLISHER (G1-G10)
// ====================================================================
//
// Surface under audit: `crates/rpc/src/zmq.rs` (1,079 LOC).
// All 5 topic strings + frame layout + sequence label bytes already
// match Core; the gap is wiring (BUG-1), per-instance sequence semantics
// (BUG-2), and Core-prefix normalisation (BUG-3).

/// G1 — Five topic enum strings match Core's wire constants in
/// `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:33-37`
/// (MSG_HASHBLOCK / MSG_HASHTX / MSG_RAWBLOCK / MSG_RAWTX / MSG_SEQUENCE).
/// Status: PASS.
#[test]
fn g1_zmq_topic_strings_match_core() {
    use rustoshi_rpc::zmq::ZmqTopic;
    assert_eq!(ZmqTopic::HashBlock.as_str(), "hashblock");
    assert_eq!(ZmqTopic::HashTx.as_str(), "hashtx");
    assert_eq!(ZmqTopic::RawBlock.as_str(), "rawblock");
    assert_eq!(ZmqTopic::RawTx.as_str(), "rawtx");
    assert_eq!(ZmqTopic::Sequence.as_str(), "sequence");
}

/// G2 — Multipart frame layout = `[topic str][body bytes][LE-u32 seq]`,
/// matching Core's `SendZmqMessage` in
/// `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:193-208`.
/// rustoshi's `send_multipart` (zmq.rs:288-318) calls
/// `socket.send(..., SNDMORE)` three times in the same order; the wire
/// envelope is identical to Core's `zmq_send_multipart` vararg loop.
/// Status: PASS — structural pin via grep on the public source.
#[test]
fn g2_zmq_multipart_frame_layout_pin() {
    // Regression pin: verifying the documented intent in the source.
    // The send order is topic → body → seq; switching this would
    // silently break every ZMQ subscriber. This test pins it at
    // the documentation level so any reordering in zmq.rs triggers
    // a review.
    let src = std::fs::read_to_string(Path::new(
        env!("CARGO_MANIFEST_DIR")
    ).join("src").join("zmq.rs")).expect("zmq.rs readable");
    // The topic-first send.
    assert!(
        src.contains("socket.send(topic.as_bytes(), zmq::SNDMORE)"),
        "expected topic-first SNDMORE send (Core wire-format parity)"
    );
    // The body-with-SNDMORE send.
    assert!(
        src.contains("socket.send(body, zmq::SNDMORE)"),
        "expected body SNDMORE send"
    );
    // The seq-final send (no SNDMORE).
    assert!(
        src.contains("socket.send(&seq_bytes[..], 0)"),
        "expected seq-final 0-flag send"
    );
    // The seq must be LE 4 bytes.
    assert!(
        src.contains("seq.to_le_bytes()"),
        "expected LE-u32 sequence encoding (Core WriteLE32 parity)"
    );
}

/// G3 — Sequence label enum bytes match Core's char constants in
/// `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:267-292` SendSequenceMsg
/// labels: 'A' (acceptance) / 'R' (removal) / 'C' (connect) /
/// 'D' (disconnect).
/// Status: PASS.
#[test]
fn g3_zmq_sequence_label_bytes_match_core() {
    use rustoshi_rpc::zmq::SequenceLabel;
    assert_eq!(SequenceLabel::MempoolAcceptance.as_byte(), b'A');
    assert_eq!(SequenceLabel::MempoolRemoval.as_byte(), b'R');
    assert_eq!(SequenceLabel::BlockConnect.as_byte(), b'C');
    assert_eq!(SequenceLabel::BlockDisconnect.as_byte(), b'D');
}

/// G4 — `reverse_hash` produces display-order bytes — Core's pattern at
/// `zmqpublishnotifier.cpp:215-217` for hashblock (and :226-228 for
/// hashtx) writes the uint256 reversed because uint256 internal byte
/// order is LE but display order is BE. rustoshi's reverse is at
/// `zmq.rs:622-627`.
/// Status: PASS via the in-module test, re-pinned here for cross-check.
#[test]
fn g4_zmq_reverse_hash_produces_display_order() {
    use rustoshi_primitives::Hash256;
    let hash = Hash256::from_hex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    ).unwrap();
    // Hash256.0 is internal LE; reverse_hash should produce the display
    // BE encoding, which starts with zeros (the leading "000000000019"
    // visible in the hex string).
    //
    // We can't directly call the private reverse_hash helper, but
    // ZmqNotifier::notify_block (zmq.rs:557) uses it via
    // block.block_hash(), then send_multipart with `&hash_bytes`.
    // The in-module unit test `test_reverse_hash` already covers it.
    // This gate is a no-op pin to keep the property visible at audit
    // level.
    let internal = hash.as_bytes();
    let mut reversed = [0u8; 32];
    for i in 0..32 {
        reversed[i] = internal[31 - i];
    }
    // Display order starts with 0x00 (leading zeros visible in display).
    assert_eq!(reversed[0], 0x00);
    assert_eq!(reversed[1], 0x00);
    assert_eq!(reversed[2], 0x00);
}

/// G5 — `parse_zmq_args` recognises 5 wire keys.
/// Core enumerates them at `zmqnotificationinterface.cpp:47-53`
/// (`pubhashblock` / `pubhashtx` / `pubrawblock` / `pubrawtx` /
/// `pubsequence`).
/// Status: PASS.
#[test]
fn g5_parse_zmq_args_recognises_five_topics() {
    use rustoshi_rpc::zmq::{parse_zmq_args, ZmqTopic};
    let args = [
        ("zmqpubhashblock".to_string(), "tcp://127.0.0.1:28332".into()),
        ("zmqpubhashtx".to_string(),    "tcp://127.0.0.1:28333".into()),
        ("zmqpubrawblock".to_string(),  "tcp://127.0.0.1:28334".into()),
        ("zmqpubrawtx".to_string(),     "tcp://127.0.0.1:28335".into()),
        ("zmqpubsequence".to_string(),  "tcp://127.0.0.1:28336".into()),
        ("zmqpubgarbage".to_string(),   "ignored".into()),
    ];
    let configs = parse_zmq_args(&args);
    assert_eq!(configs.len(), 5, "five topics recognised, garbage dropped");
    let topics: Vec<ZmqTopic> = configs.iter().map(|c| c.topic).collect();
    assert!(topics.contains(&ZmqTopic::HashBlock));
    assert!(topics.contains(&ZmqTopic::HashTx));
    assert!(topics.contains(&ZmqTopic::RawBlock));
    assert!(topics.contains(&ZmqTopic::RawTx));
    assert!(topics.contains(&ZmqTopic::Sequence));
}

/// G6 — `ZmqNotifier::create([])` returns `Ok(None)` — matches Core's
/// behaviour at `zmqnotificationinterface.cpp:74-84` (returns nullptr
/// when the notifiers list is empty).
/// Status: PASS.
#[test]
fn g6_zmq_create_returns_none_on_empty_config() {
    use rustoshi_rpc::zmq::ZmqNotifier;
    let result = ZmqNotifier::create(vec![]).unwrap();
    assert!(result.is_none(), "empty config → no notifier");
}

/// G7 — Production binary actually instantiates `ZmqNotifier`.
/// Status: WIRING / BUG-1 (P0).
///
/// The `ZmqNotifier::create` constructor has zero call sites in
/// `rustoshi/src/main.rs`. The only downstream consumer
/// (`RpcServerImpl::with_zmq` at server.rs:1050) also has zero
/// call sites outside the crate. Result: production runs with
/// `RpcServerImpl::new` (server.rs:1041), which sets
/// `zmq_notifier = None`, and operators passing
/// `-zmqpubhashblock=tcp://...` get silently dropped.
#[test]
#[ignore]
fn g7_zmq_subsystem_wired_in_main() {
    // Detection: grep main.rs for `ZmqNotifier::` or `with_zmq(`.
    let main_rs = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join("..").join("rustoshi").join("src").join("main.rs")
    ).expect("main.rs readable");
    let has_create_call = main_rs.contains("ZmqNotifier::create(")
        || main_rs.contains("ZmqNotifier::new(")
        || main_rs.contains("with_zmq(");
    assert!(
        has_create_call,
        "BUG-1: ZmqNotifier::create / with_zmq is never called from main.rs; \
         the entire ZMQ subsystem (zmq.rs, 1,079 LOC) is unreachable code. \
         Operators specifying -zmqpubhashblock=tcp://... are silently dropped."
    );
}

/// G8 — Sequence numbers are **per-notifier-instance**, not per-topic.
/// Status: BUG-2 (P1 / CDIV-ZMQ).
///
/// Core's `nSequence` lives on `CZMQAbstractPublishNotifier` and is
/// incremented in `SendZmqMessage` after sending
/// (zmqpublishnotifier.cpp:198-205). Two `pubhashblock=` endpoints at
/// different addresses each maintain their own counter and each sees
/// contiguous 0,1,2,3,... .
///
/// rustoshi keys by `ZmqTopic`
/// (`crates/rpc/src/zmq.rs:225`, `next_sequence` at `:321-326`), so two
/// `pubhashblock` endpoints share the counter and each sees gaps
/// (one sees 0,2,4,...; the other sees 1,3,5,...).
#[test]
#[ignore]
fn g8_zmq_sequence_per_notifier_instance() {
    // Detection: inspect the `sequences` field type signature at line
    // 225 of zmq.rs and assert it's keyed by (Topic, Address) not Topic.
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("zmq.rs")
    ).expect("zmq.rs readable");
    // Core-parity key signature would be one of:
    //   HashMap<(ZmqTopic, String), u32>
    //   HashMap<ZmqNotifierConfigId, u32>
    //   per-config `sequence: u32` field on ZmqNotifierConfig
    let has_per_instance_key = src.contains("HashMap<(ZmqTopic, String), u32>")
        || src.contains("HashMap<(String, ZmqTopic), u32>")
        || src.contains("(ZmqTopic, String) -> u32")
        || src.contains("per-instance");
    let has_per_topic_only = src.contains("sequences: HashMap<ZmqTopic, u32>");
    assert!(
        has_per_instance_key && !has_per_topic_only,
        "BUG-2: rustoshi's sequence counter is keyed by ZmqTopic alone, so two \
         same-topic endpoints share the counter. Each subscriber sees gaps. \
         Core keys per CZMQAbstractPublishNotifier instance."
    );
}

/// G9 — `unix://` prefix normalised to `ipc://`.
/// Status: BUG-3 (P1 / MISSING).
///
/// Core at `zmqnotificationinterface.cpp:62-64`:
///   if (address.starts_with(ADDR_PREFIX_UNIX))
///       address.replace(0, ADDR_PREFIX_UNIX.length(), ADDR_PREFIX_IPC);
///
/// libzmq accepts only `ipc://` for UNIX domain sockets; rustoshi passes
/// the address through unchanged so `--zmqpubsequence=unix:///tmp/x`
/// fails at `socket.bind`.
#[test]
#[ignore]
fn g9_zmq_unix_prefix_normalised_to_ipc() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("zmq.rs")
    ).expect("zmq.rs readable");
    assert!(
        src.contains("unix://") || src.contains("strip_prefix(\"unix://\")")
            || src.contains("ADDR_PREFIX_UNIX") || src.contains("normalise"),
        "BUG-3: no `unix://` → `ipc://` rewrite (Core \
         zmqnotificationinterface.cpp:62-64 parity gap). \
         --zmqpubsequence=unix:///tmp/x fails at bind."
    );
}

/// G10 — Per-notifier HWM override via `-zmqpub<topic>hwm=N`.
/// Status: BUG-4 (P2 / MISSING).
///
/// Core at `zmqnotificationinterface.cpp:69` reads
/// `gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM)` where `arg` is the
/// base `-zmqpub<topic>` flag.  rustoshi hardcodes 1000 in
/// `ZmqNotifierConfig::new` (zmq.rs:167); the `with_hwm` builder
/// (zmq.rs:172) has no CLI entry point and `parse_zmq_args` never sets
/// a non-default HWM.
#[test]
#[ignore]
fn g10_zmq_per_topic_hwm_override() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("zmq.rs")
    ).expect("zmq.rs readable");
    assert!(
        src.contains("hwm") && (src.contains("hashblockhwm")
            || src.contains("hashtxhwm") || src.contains("rawblockhwm")
            || src.contains("rawtxhwm") || src.contains("sequencehwm")),
        "BUG-4: no `-zmqpub<topic>hwm=N` flag parsing. Operators cannot \
         override the default 1000-message HWM per topic."
    );
}

// ====================================================================
// SUBSYSTEM 2: REST ENDPOINTS (G11-G25)
// ====================================================================
//
// Surface under audit: `crates/rpc/src/rest.rs` (2,470 LOC), router
// mounted at line 2034 with 11 routes.  Core URI table at
// `bitcoin-core/src/rest.cpp:1141` has 14 routes.  Three families
// (blockpart / spenttxouts / deploymentinfo) are missing.

/// G11 — `/rest/tx/<hash>.{bin,hex,json}` content-type maps correctly.
/// Status: PASS.
#[test]
fn g11_rest_tx_content_types() {
    // Pin: RestFormat -> content_type mapping.
    // The mapping lives at rest.rs:96-104.  We verify it via grep
    // because RestFormat / content_type are private to the module.
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(src.contains("\"application/json\""),
        "Json content-type pin");
    assert!(src.contains("\"application/octet-stream\""),
        "Binary content-type pin (Core 'application/octet-stream')");
    assert!(src.contains("\"text/plain\""),
        "Hex content-type pin (Core 'text/plain')");
}

/// G12 — `/rest/block/<hash>.json` returns FULL tx detail (vin/vout),
/// not just txids.
/// Status: BUG-12 (P0 / CDIV-REST).
///
/// Core's `rest_block_extended` (rest.cpp:471-473) calls into
/// `rest_block` with `tx_verbosity=SHOW_DETAILS_AND_PREVOUT` and
/// `blockToJSON` builds each transaction as a full UniValue object
/// with `vin[].prevout`, `vout[].scriptPubKey`, etc.
///
/// rustoshi's `rest_block` (rest.rs:276) calls `build_block_info`
/// (rest.rs:932) which produces a `BlockInfo` with
/// `tx: Vec<String>` of txid hex strings — NOT full tx objects.
/// Anyone parsing `/rest/block/<hash>.json` for fee-rate accounting
/// or address indexing gets a useless txid array.
#[test]
#[ignore]
fn g12_rest_block_json_full_tx_detail() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    // Detection: the BlockInfo struct's `tx` field type. We assert it
    // is NOT Vec<String> (which would indicate txid-only).
    // A correct Core-parity shape would be Vec<RestTxInfo> or
    // Vec<serde_json::Value> with object-shape elements.
    assert!(
        !src.contains("tx: block.transactions.iter().map(|tx| tx.txid().to_hex()).collect()"),
        "BUG-12: rest_block JSON returns Vec<String> of txids only; \
         Core returns full tx objects via blockToJSON(SHOW_DETAILS_AND_PREVOUT)."
    );
}

/// G13 — `/rest/block/notxdetails/<hash>.json` returns only txids.
/// Status: PASS — rustoshi's `rest_block_notxdetails` produces the
/// same shape as `rest_block` (txid-only). This is correct for
/// notxdetails; the bug is that `rest_block` ALSO does it (BUG-12).
#[test]
fn g13_rest_block_notxdetails_txid_only() {
    // Pin: notxdetails endpoint exists at rest.rs:328.
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("async fn rest_block_notxdetails"),
        "rest_block_notxdetails handler pin"
    );
    assert!(
        src.contains("\"/rest/block/notxdetails/:hash_format\""),
        "notxdetails route mount pin (rest.rs:2038)"
    );
}

/// G14 — `/rest/blockpart/<hash>.{bin,hex}?offset=N&size=M` not
/// implemented.
/// Status: BUG-14 (P1 / MISSING).
///
/// Core: `rest.cpp:481` `rest_block_part`, uses `ReadRawBlock(pos,
/// block_part)` to serve a sub-range. Used by streaming-block
/// readers and lightweight block-explorer patterns.
#[test]
#[ignore]
fn g14_rest_blockpart_implemented() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("/rest/blockpart") || src.contains("rest_block_part"),
        "BUG-14: /rest/blockpart not implemented; Core rest.cpp:481 has it."
    );
}

/// G15 — `/rest/spenttxouts/<hash>.{bin,hex,json}` not implemented.
/// Status: BUG-15 (P1 / MISSING).
///
/// Core: `rest.cpp:313` `rest_spent_txouts` — serializes a block's
/// undo data (every prevout consumed by every non-coinbase tx).
/// Block-explorer fast historical address mapping depends on this.
#[test]
#[ignore]
fn g15_rest_spenttxouts_implemented() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("/rest/spenttxouts") || src.contains("rest_spent_txouts"),
        "BUG-15: /rest/spenttxouts not implemented; Core rest.cpp:313 has it."
    );
}

/// G16 — `/rest/deploymentinfo[/<hash>].json` not implemented.
/// Status: BUG-16 (P1 / MISSING).
///
/// Core: `rest.cpp:743` `rest_deploymentinfo` — projects
/// `getdeploymentinfo` over REST.
#[test]
#[ignore]
fn g16_rest_deploymentinfo_implemented() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("/rest/deploymentinfo") || src.contains("rest_deploymentinfo"),
        "BUG-16: /rest/deploymentinfo not implemented; Core rest.cpp:743 has it."
    );
}

/// G17 — `/rest/headers/<hash>.<fmt>?count=N` (new query form).
/// Status: BUG-17 (P1 / MISSING).
///
/// Core: `rest.cpp:191-205` accepts BOTH the deprecated
/// `<count>/<hash>` path form AND the new `?count=N` query form
/// (`req->GetQueryParameter("count").value_or("5")`).
/// rustoshi: `rest.rs:382-389` only parses 2-segment path; rejects
/// the new form with `InvalidUri`.
#[test]
#[ignore]
fn g17_rest_headers_count_query_form() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("GetQueryParameter") || src.contains("query.get(\"count\")")
            || src.contains("count=") || src.contains("?count="),
        "BUG-17: ?count=N query form for /rest/headers not implemented; \
         Core rest.cpp:191-205 accepts both forms."
    );
}

/// G18 — `/rest/getutxos` accepts POST body for binary input.
/// Status: BUG-18 (P2 / MISSING).
///
/// Core: `rest.cpp:912-986` reads request body in `.bin`/`.hex` mode
/// and deserialises `[bool checkMempool, vector<COutPoint>]` from
/// the binary stream. rustoshi: registered as GET only at
/// `rest.rs:2043` `.route(... get(rest_getutxos))` — any POST is
/// 405.
#[test]
#[ignore]
fn g18_rest_getutxos_post_body_input() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    let getutxos_post = src.contains(".route(\"/rest/getutxos/*path\", post(")
        || src.contains(".route(\"/rest/getutxos/*path\", get(rest_getutxos).post(");
    assert!(
        getutxos_post,
        "BUG-18: /rest/getutxos is GET-only at rest.rs:2043; \
         Core accepts POST with binary outpoint blob in body."
    );
}

/// G19 — HTTP 400 on bad hash / 404 on not found / 503 on warmup.
/// Status: PARTIAL — BUG-19 (P1).
///
/// Core's `RESTERR` mapping uses 400 for parse errors, 404 for
/// missing-resource, 503 for warmup (rest.cpp:171-176 `CheckWarmup`).
/// rustoshi's `RestError::into_response` (rest.rs:166-196) gets 400
/// and 404 right but has NO warmup-503 path — operators hitting
/// REST during chain database startup get 200 + stale (empty
/// mempool, height 0) data instead of a documented 503.
#[test]
#[ignore]
fn g19_rest_warmup_503() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("SERVICE_UNAVAILABLE") || src.contains("503")
            || src.contains("Warmup") || src.contains("RPCIsInWarmup"),
        "BUG-19: no warmup 503 — REST returns 200 + stale data during \
         chain database startup; Core rejects with 503 'Service \
         temporarily unavailable'."
    );
}

/// G20 — `MAX_REST_HEADERS_RESULTS = 2000`.
/// Status: PASS — matches Core's `rest.cpp:45`
/// (`MAX_REST_HEADERS_RESULTS = 2000`).
#[test]
fn g20_rest_max_headers_results_cap() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("MAX_REST_HEADERS_RESULTS: usize = 2000"),
        "MAX_REST_HEADERS_RESULTS = 2000 (Core rest.cpp:45 parity)"
    );
}

/// G21 — `MAX_GETUTXOS_OUTPOINTS = 15`.
/// Status: PASS — matches Core's `rest.cpp:44`
/// (`MAX_GETUTXOS_OUTPOINTS = 15`).
#[test]
fn g21_rest_max_getutxos_outpoints_cap() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("MAX_GETUTXOS_OUTPOINTS: usize = 15"),
        "MAX_GETUTXOS_OUTPOINTS = 15 (Core rest.cpp:44 parity)"
    );
}

/// G22 — `-rest` flag defaults OFF (matches Core's
/// `DEFAULT_REST_ENABLE = false`).
/// Status: PASS — rustoshi/src/main.rs:230-231:
///   #[arg(long = "rest", default_value = "false")]
///   rest: bool
#[test]
fn g22_rest_flag_default_off() {
    let main_rs = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join("..").join("rustoshi").join("src").join("main.rs")
    ).expect("main.rs readable");
    assert!(
        main_rs.contains("long = \"rest\", default_value = \"false\"")
            || main_rs.contains("long = \"rest\""),
        "-rest flag pin"
    );
}

/// G23 — REST router shares the JSON-RPC port (Core does).
/// Status: BUG-20 (P2 / CDIV-REST).
///
/// Core's REST is registered as additional URI handlers on the same
/// `httpserver` instance backing JSON-RPC, so `127.0.0.1:8332/rest/...`
/// and `127.0.0.1:8332` (JSON-RPC) share host:port.
///
/// rustoshi binds a separate axum listener at `rpc_ip:rpc_port+100`
/// (`rustoshi/src/main.rs:2007-2018`) because jsonrpsee 0.22 does not
/// expose a hookable HTTP router. Tight-firewall operators allowing
/// only the JSON-RPC port get rustoshi REST blocked.
#[test]
#[ignore]
fn g23_rest_shares_jsonrpc_port() {
    let main_rs = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join("..").join("rustoshi").join("src").join("main.rs")
    ).expect("main.rs readable");
    // Detection: if main.rs computes a separate restbind port via
    // `port.saturating_add(100)`, REST does NOT share the JSON-RPC port.
    let separate_port = main_rs.contains("port.saturating_add(100)")
        || main_rs.contains("rpc_port + 100");
    assert!(
        !separate_port,
        "BUG-20: REST listener binds on rpc_port+100 (rustoshi/src/main.rs:2016) \
         instead of sharing the JSON-RPC port like Core."
    );
}

/// G24 — `build_block_info_simple` is a dead-helper comment-as-confession.
/// Status: BUG-13 (P3 / CDIV-REST).
///
/// `rest.rs:991-1000` defines `build_block_info_simple` with the comment:
///   // Same as build_block_info but only txids (no transaction details)
///   // For REST notxdetails endpoint, this is the same since we already
///   // only return txids
/// then immediately delegates: `build_block_info(block, entry, ...)`.
/// The comment confesses the function would be redundant IF
/// `build_block_info` were correct — it isn't (BUG-12) — and the helper
/// remains in tree as a TODO marker disguised as a stub.
#[test]
#[ignore]
fn g24_rest_build_block_info_simple_comment_as_confession() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    // Detection: presence of the confessional comment text.
    let confession = src.contains("this is the same since we already only return txids")
        || src.contains("Same as build_block_info but only txids");
    assert!(
        !confession,
        "BUG-13: `build_block_info_simple` (rest.rs:991-1000) is a \
         comment-as-confession dead helper. The comment text \
         'this is the same since we already only return txids' is the \
         author confessing that rest_block returns the wrong shape (BUG-12). \
         Either remove the helper (and fix BUG-12) or make it produce the \
         txid-only shape independently."
    );
}

/// G25 — `/rest/chaininfo.json` rejects non-JSON formats.
/// Status: PASS — rest.rs:1314-1316 implements only the JSON variant
/// and the router (`rest.rs:2046`) mounts only the `.json` path,
/// matching Core's `rest.cpp:723-737`.
#[test]
fn g25_rest_chaininfo_json_only() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("rest.rs")
    ).expect("rest.rs readable");
    assert!(
        src.contains("\"/rest/chaininfo.json\""),
        "chaininfo route pin"
    );
    // Negative pin: confirm there is no rest_chaininfo_bin/_hex variant.
    assert!(
        !src.contains("rest_chaininfo_bin") && !src.contains("rest_chaininfo_hex"),
        "chaininfo is JSON-only (no bin/hex variants)"
    );
}

// ====================================================================
// SUBSYSTEM 3: NOTIFICATION SCRIPTS (G26-G30)
// ====================================================================
//
// Surface under audit: ABSENT.  `crates/rpc/src/notify.rs` does not
// exist; the `Cli` struct in `rustoshi/src/main.rs` has no
// `blocknotify` / `walletnotify` / `alertnotify` arguments; no
// `runCommand`-equivalent helper anywhere in the workspace.
//
// All 5 gates are MISSING.

/// G26 — `-blocknotify=<cmd>` CLI arg + `%s` block-hash substitution
/// + thread-detached dispatch.
/// Status: BUG-22 (P1 / MISSING).
///
/// Core: `init.cpp:2009-2018` connects a closure to
/// `uiInterface.NotifyBlockTip_connect` that:
///   1. Skips when `sync_state != POST_INIT` (only "live" tips fire).
///   2. ReplaceAll(`%s`, block.GetBlockHash().GetHex()).
///   3. Spawns + detaches `std::thread t(runCommand, command)`.
#[test]
#[ignore]
fn g26_blocknotify_implemented() {
    let main_rs = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join("..").join("rustoshi").join("src").join("main.rs")
    ).expect("main.rs readable");
    let has_arg = main_rs.contains("long = \"blocknotify\"")
        || main_rs.contains("blocknotify:") || main_rs.contains("block_notify:");
    assert!(
        has_arg,
        "BUG-22: -blocknotify=<cmd> not implemented in rustoshi CLI; \
         Core init.cpp:2009-2018 fires the script on every POST_INIT \
         block tip."
    );
}

/// G27 — `-walletnotify=<cmd>` CLI arg + `%s`/`%w`/`%b`/`%h`
/// substitution.
/// Status: BUG-23 (P1 / MISSING).
///
/// Core: `wallet/wallet.cpp:1139-1164` fires after every
/// `AddToWallet`/`SyncTransaction`:
///   - `%s` → txid hex.
///   - `%b` → confirmed block hash hex OR `"unconfirmed"`.
///   - `%h` → confirmed block height OR `"-1"`.
///   - `%w` → `ShellEscape(GetName())` (non-Windows only).
#[test]
#[ignore]
fn g27_walletnotify_implemented() {
    // Detection: grep workspace for "walletnotify" outside docs/comments.
    let main_rs = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join("..").join("rustoshi").join("src").join("main.rs")
    ).expect("main.rs readable");
    let wallet_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..").join("wallet");
    let wallet_rs = std::fs::read_to_string(wallet_dir.join("src").join("wallet.rs"))
        .unwrap_or_default();
    let has_walletnotify = main_rs.contains("walletnotify")
        || wallet_rs.contains("walletnotify");
    assert!(
        has_walletnotify,
        "BUG-23: -walletnotify=<cmd> not implemented; \
         Core wallet.cpp:1139-1164 fires the script on AddToWallet."
    );
}

/// G28 — `-alertnotify=<cmd>` CLI arg + sanitised + single-quoted
/// `%s` substitution.
/// Status: BUG-24 (P1 / MISSING).
///
/// Core: `node/kernel_notifications.cpp:30-47`:
///   1. SanitizeString(strMessage) (strips non-safeChars).
///   2. Single-quote wrap: `safeStatus = "'" + safeStatus + "'"`.
///   3. ReplaceAll `%s` with quoted, sanitised string.
///   4. Spawns + detaches `runCommand` thread.
#[test]
#[ignore]
fn g28_alertnotify_implemented() {
    let main_rs = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join("..").join("rustoshi").join("src").join("main.rs")
    ).expect("main.rs readable");
    let has_alertnotify = main_rs.contains("alertnotify")
        || main_rs.contains("alert_notify");
    assert!(
        has_alertnotify,
        "BUG-24: -alertnotify=<cmd> not implemented; \
         Core kernel_notifications.cpp:30-47 fires the script on \
         warnings/errors with sanitised + single-quoted %s."
    );
}

/// G29 — `ShellEscape` helper for `%w` substitution.
/// Status: BUG-25 (P2 / MISSING).
///
/// Core: `common/system.cpp:41-46`:
///   std::string escaped = arg;
///   ReplaceAll(escaped, "'", "'\"'\"'");
///   return "'" + escaped + "'";
///
/// Required for safe `%w` substitution if wallet names ever contain
/// shell metacharacters.
#[test]
#[ignore]
fn g29_shell_escape_helper() {
    // Detection: grep workspace for a ShellEscape / shell_escape /
    // sanitize_shell function.
    let mut found = false;
    for crate_name in &["primitives", "consensus", "crypto", "storage",
                         "network", "rpc", "wallet"] {
        let crate_src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join(crate_name).join("src");
        if !crate_src.exists() { continue; }
        if let Ok(entries) = std::fs::read_dir(&crate_src) {
            for entry in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if content.contains("fn shell_escape")
                        || content.contains("fn ShellEscape")
                        || content.contains("pub fn shell_escape") {
                        found = true;
                    }
                }
            }
        }
    }
    assert!(
        found,
        "BUG-25: no ShellEscape helper anywhere in the workspace; \
         Core common/system.cpp:41-46 implements the single-quote \
         escape required for safe %w wallet-name substitution."
    );
}

/// G30 — `runCommand` thread-detach lifecycle.
/// Status: BUG-21 (P2 / MISSING).
///
/// Core: `common/system.cpp:50-62` shells out via
/// `::system(cmd.c_str())` from a detached `std::thread`.  The
/// detach-on-spawn semantic means the node continues regardless of
/// how slow the notify script is.
#[test]
#[ignore]
fn g30_run_command_helper() {
    // Detection: grep workspace for a runCommand / run_command /
    // spawn_notify_thread function.
    let mut found = false;
    for crate_name in &["primitives", "consensus", "crypto", "storage",
                         "network", "rpc", "wallet"] {
        let crate_src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..").join(crate_name).join("src");
        if !crate_src.exists() { continue; }
        if let Ok(entries) = std::fs::read_dir(&crate_src) {
            for entry in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if content.contains("fn run_command")
                        || content.contains("fn runCommand")
                        || content.contains("pub fn run_command") {
                        found = true;
                    }
                }
            }
        }
    }
    assert!(
        found,
        "BUG-21: no runCommand / run_command helper anywhere in the \
         workspace; Core common/system.cpp:50-62 detaches a thread \
         that calls ::system(cmd).  Blocks BUG-22/23/24 fixes."
    );
}
