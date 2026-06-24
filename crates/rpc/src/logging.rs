//! Live, runtime-mutable debug-logging category control.
//!
//! This is the backing state for the `logging` RPC (Bitcoin Core
//! `rpc/node.cpp::logging` + `logging.cpp`). Core keeps an in-memory
//! per-category enable bitmask (`BCLog::Logger::m_categories`) that the
//! `logging` RPC mutates *in place* so toggling a category takes effect
//! immediately with no restart. rustoshi's logger is `tracing` +
//! `tracing_subscriber::EnvFilter`; the live equivalent of Core's bitmask is
//! the process-global active-category set held here, which the running
//! `EnvFilter` is rebuilt from on every toggle.
//!
//! # The snapshot trap (and how this avoids it)
//!
//! A naïve port builds the `EnvFilter` once at startup and never touches it —
//! the `logging` RPC then returns a `{category: bool}` map that is a *cosmetic*
//! bitmask, disconnected from what the logger actually emits. Toggling a
//! category would flip the reported bool but never start or stop a single log
//! line. The contract here is that the toggle MUST mutate the live filter the
//! logger consults per-record.
//!
//! rustoshi achieves this with a `tracing_subscriber::reload::Layer` wrapping
//! the `EnvFilter`. The reload handle lives in the binary crate (which owns the
//! subscriber); it is registered here at startup behind the [`LiveLogControl`]
//! trait object. Every enable/disable rebuilds the active set, then calls
//! `apply()`, which rebuilds the `EnvFilter` from the active set and *reloads*
//! it into the running subscriber — so the very next `tracing` event is gated
//! by the new set. No restart, no snapshot.
//!
//! The rpc crate deliberately does NOT depend on `tracing-subscriber`: the
//! reload-handle machinery is entirely behind [`LiveLogControl`] in the binary
//! crate. This module owns only the category registry, the active set, and the
//! Core-faithful name/token semantics.

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock, RwLock};

/// The canonical set of debug-logging categories rustoshi exposes.
///
/// These are the Core `-debug=<cat>` category NAMES that rustoshi actually
/// recognizes and maps onto real `tracing` target directives (see
/// `rustoshi::ops::map_debug_category`). The names legitimately differ from
/// Core's full 28-29-category set — rustoshi is a from-scratch node with its
/// own subsystem decomposition — but each name here is wired to a real logger,
/// so enabling it genuinely starts that subsystem's DEBUG output (no cosmetic
/// bits). They are stored sorted (a `BTreeSet`) so the RPC emits them in
/// ascending alphabetical key order, matching Core's `std::map` iteration.
///
/// Source of truth: the distinct, non-special tokens in
/// `rustoshi::ops::map_debug_category`. Kept in sync by the
/// `logging_categories_match_ops_mapping` test in `rustoshi/src/ops.rs`.
pub const LOG_CATEGORIES: &[&str] = &[
    "addrman",
    "bench",
    "blockstorage",
    "coindb",
    "crypto",
    "estimatefee",
    "http",
    "i2p",
    "ipc",
    "leveldb",
    "lock",
    "mempool",
    "mempoolrej",
    "net",
    "p2p",
    "proxy",
    "prune",
    "qt",
    "reindex",
    "rpc",
    "selectcoins",
    "tor",
    "validation",
    "wallet",
    "zmq",
];

/// Core's special input-only tokens that expand to the FULL category mask
/// (`logging.cpp`: `"all"`, `"1"`, and the empty string `""`). Accepted as
/// inputs in either slot; in the include slot they enable everything, in the
/// exclude slot they clear everything ("none" effect). NEVER emitted as output
/// keys.
pub const ALL_TOKENS: &[&str] = &["all", "1", ""];

/// Returns `true` if `name` is a real, recognized category (not a special
/// token).
pub fn is_known_category(name: &str) -> bool {
    LOG_CATEGORIES.contains(&name)
}

/// Returns `true` if `name` is one of Core's special ALL tokens (`all`/`1`/`""`).
pub fn is_all_token(name: &str) -> bool {
    ALL_TOKENS.contains(&name)
}

/// The process-global live active-category set — the rustoshi analogue of
/// Core's `BCLog::Logger::m_categories` bitmask. Mutated by the `logging` RPC;
/// read when (re)building the running `EnvFilter`.
fn active_set() -> &'static RwLock<BTreeSet<String>> {
    static ACTIVE: OnceLock<RwLock<BTreeSet<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| RwLock::new(BTreeSet::new()))
}

/// Hook the binary crate installs at startup so category toggles can rebuild
/// and hot-reload the running `tracing` `EnvFilter`. Implemented in
/// `rustoshi::ops` over a `tracing_subscriber::reload::Handle`.
pub trait LiveLogControl: Send + Sync {
    /// Rebuild the running `EnvFilter` from the current active-category set and
    /// reload it into the live subscriber, so the change takes effect on the
    /// next emitted event (no restart). `active` is the sorted active set.
    fn apply(&self, active: &BTreeSet<String>);
}

fn control() -> &'static Mutex<Option<Box<dyn LiveLogControl>>> {
    static CONTROL: OnceLock<Mutex<Option<Box<dyn LiveLogControl>>>> = OnceLock::new();
    CONTROL.get_or_init(|| Mutex::new(None))
}

/// Install the live-log-control hook (called once at startup from the binary
/// crate after the `tracing` subscriber is built). Also seeds the active set
/// from the `-debug` startup flags so the `logging` RPC reports & toggles
/// relative to the startup configuration.
pub fn install_control(ctrl: Box<dyn LiveLogControl>, startup_categories: &[String]) {
    {
        let mut set = active_set().write().unwrap();
        set.clear();
        for c in startup_categories {
            if is_known_category(c) {
                set.insert(c.clone());
            }
        }
    }
    *control().lock().unwrap() = Some(ctrl);
    // Apply the seeded set so the live filter and the reported map agree from
    // the first `logging` call (no-op if the EnvFilter already encodes these).
    apply_active();
}

/// Push the current active set into the live subscriber via the installed hook.
/// A no-op (other than updating the reported map) when no hook is installed —
/// e.g. in unit tests that exercise the registry without a real subscriber.
fn apply_active() {
    let snapshot = { active_set().read().unwrap().clone() };
    if let Some(ctrl) = control().lock().unwrap().as_ref() {
        ctrl.apply(&snapshot);
    }
}

/// Return a copy of the currently-active categories (sorted).
pub fn get_active_categories() -> BTreeSet<String> {
    active_set().read().unwrap().clone()
}

/// Enable one category (or every category for an ALL token), then hot-reload
/// the live filter. Mirrors Core `EnableCategory`.
pub fn enable_category(name: &str) {
    {
        let mut set = active_set().write().unwrap();
        if is_all_token(name) {
            set.clear();
            for c in LOG_CATEGORIES {
                set.insert((*c).to_string());
            }
        } else {
            set.insert(name.to_string());
        }
    }
    apply_active();
}

/// Disable one category (or every category for an ALL token), then hot-reload
/// the live filter. Mirrors Core `DisableCategory` (`DisableCategory("all")`
/// clears the whole mask — how `logging [], ["all"]` disables everything).
pub fn disable_category(name: &str) {
    {
        let mut set = active_set().write().unwrap();
        if is_all_token(name) {
            set.clear();
        } else {
            set.remove(name);
        }
    }
    apply_active();
}

/// Build the `{category: bool}` map the `logging` RPC returns: one key per real
/// category in [`LOG_CATEGORIES`], value = whether it is currently active,
/// emitted in ascending alphabetical order (the slice is pre-sorted; we use a
/// `BTreeMap` so the wire order is alphabetical regardless of `serde_json`
/// settings). The special tokens `all`/`1`/`""` are never keys.
pub fn categories_map() -> serde_json::Value {
    let active = get_active_categories();
    // BTreeMap guarantees alphabetical key order on serialization, independent
    // of the crate's `preserve_order` feature.
    let mut map = std::collections::BTreeMap::new();
    for cat in LOG_CATEGORIES {
        map.insert((*cat).to_string(), active.contains(*cat));
    }
    serde_json::to_value(map).expect("category map serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The active-category set is process-global, so the state-mutating tests
    // must not run concurrently or they race each other's enable/disable. A
    // shared mutex serializes them (and a clean-slate reset at entry).
    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn reset_all() {
        for c in LOG_CATEGORIES {
            disable_category(c);
        }
    }

    #[test]
    fn categories_are_sorted_and_unique() {
        let mut sorted = LOG_CATEGORIES.to_vec();
        sorted.sort_unstable();
        assert_eq!(LOG_CATEGORIES, sorted.as_slice(), "must be alphabetical");
        let unique: BTreeSet<_> = LOG_CATEGORIES.iter().collect();
        assert_eq!(unique.len(), LOG_CATEGORIES.len(), "no duplicates");
    }

    #[test]
    fn map_is_alphabetical_and_full() {
        let _g = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        // No control installed in unit tests; start from a clean slate.
        reset_all();
        let v = categories_map();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), LOG_CATEGORIES.len());
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "keys alphabetical");
        for (_k, val) in obj {
            assert!(val.is_boolean());
        }
    }

    #[test]
    fn enable_then_disable_roundtrip() {
        let _g = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        enable_category("net");
        assert!(get_active_categories().contains("net"));
        assert_eq!(categories_map()["net"], serde_json::Value::Bool(true));
        disable_category("net");
        assert!(!get_active_categories().contains("net"));
        assert_eq!(categories_map()["net"], serde_json::Value::Bool(false));
    }

    #[test]
    fn all_token_enables_and_clears_everything() {
        let _g = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        enable_category("all");
        let active = get_active_categories();
        assert_eq!(active.len(), LOG_CATEGORIES.len());
        disable_category("all");
        assert!(get_active_categories().is_empty());
    }

    #[test]
    fn special_tokens_recognized() {
        assert!(is_all_token("all"));
        assert!(is_all_token("1"));
        assert!(is_all_token(""));
        assert!(!is_all_token("net"));
        assert!(is_known_category("net"));
        assert!(!is_known_category("bogus_xyz"));
    }
}
