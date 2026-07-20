//! Fuzz target: P2P network message decoder.
//!
//! First input byte selects a command from the full dispatch table of
//! `NetworkMessage::deserialize` (message.rs), the rest is the untrusted
//! payload. Covers every match arm including the BIP-157 cfilter/cfheaders/
//! cfcheckpt sub-decoders. Must never panic, OOM-abort, or hang.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustoshi_network::NetworkMessage;

/// Every command NetworkMessage::deserialize dispatches on.
const COMMANDS: &[&str] = &[
    "version",
    "verack",
    "ping",
    "pong",
    "getheaders",
    "getblocks",
    "headers",
    "inv",
    "getdata",
    "notfound",
    "block",
    "tx",
    "addr",
    "getaddr",
    "addrv2",
    "feefilter",
    "sendheaders",
    "sendcmpct",
    "cmpctblock",
    "getblocktxn",
    "blocktxn",
    "mempool",
    "wtxidrelay",
    "sendaddrv2",
    "sendtxrcncl",
    "reqrecon",
    "sketch",
    "reconcildiff",
    "filterload",
    "filteradd",
    "filterclear",
    "merkleblock",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "reject",
    "unknown-cmd", // exercise the fallthrough arm
];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, payload)) = data.split_first() else {
        return;
    };
    let command = COMMANDS[sel as usize % COMMANDS.len()];
    let _ = NetworkMessage::deserialize(command, payload);
});
