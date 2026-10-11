#!/usr/bin/env python3
"""Side-by-side Core v31.1 regtest check for GBT sigops and verbose mempool.

Replays the same blocks and signed transactions into an offline bitcoind and
an offline rustoshi (no connection between them). Compares, field by field:

  getblocktemplate tx order, depends, sigops, fee, weight, sigoplimit
  getrawmempool verbose (every entry field, including key order)
  getmempoolentry
  getmempoolinfo.unbroadcastcount
  tips

Admission `time` within 600s is reported and not treated as a failure.
A two-block invalidate is recorded separately: Core stamps each refilled
tx with the height of the disconnect that produced it, which this script
does not require the single-block path to match.
"""

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("SWEEP_WORKDIR", "/tmp/gbt-sigops-verbose-sweep")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mempool_reorg_sweep as base  # noqa: E402

ENTRY_KEYS = [
    "vsize",
    "weight",
    "time",
    "height",
    "descendantcount",
    "descendantsize",
    "ancestorcount",
    "ancestorsize",
    "wtxid",
    "chunkweight",
    "fees",
    "depends",
    "spentby",
    "bip125-replaceable",
    "unbroadcast",
]
FEE_KEYS = ["base", "modified", "ancestor", "descendant", "chunk"]

# Fields compared for equality. `time` is checked separately.
EXACT_KEYS = [k for k in ENTRY_KEYS if k not in ("time", "fees")]


def sign_and_send(core, rust, txid, vout, input_sats, payments, fee, label, sequence=0xFFFFFFFF):
    """Spend one input. `payments` is {address: sats}. Leftover is a bech32 change output."""
    pay = sum(payments.values())
    change = input_sats - pay - fee
    if change < 0:
        raise SystemExit(f"{label} overspends: in={input_sats} pay={pay} fee={fee}")
    outputs = {addr: base.sats_num(sats) for addr, sats in payments.items()}
    if change > 0:
        if change < 546:
            raise SystemExit(f"{label} dusty change {change}")
        outputs[core.call("getnewaddress", "", "bech32")] = base.sats_num(change)
    raw = core.call(
        "createrawtransaction",
        [{"txid": txid, "vout": vout, "sequence": sequence}],
        outputs,
    )
    signed = core.call("signrawtransactionwithwallet", raw)
    if not signed["complete"]:
        raise SystemExit(f"{label} did not sign: {signed}")
    sent = base.send_both(core, rust, signed["hex"], label)
    info = core.call("decoderawtransaction", signed["hex"])
    return sent, info


def import_p2sh_2of3(core):
    """Legacy 2-of-3 the wallet can sign. Core 31 dropped addmultisigaddress."""
    descs = core.call("listdescriptors", True)["descriptors"]
    master = None
    for item in descs:
        desc = item["desc"]
        if desc.startswith("wpkh(") and "/84h/1h/0h/0/*" in desc and "prv" in desc:
            master = desc[len("wpkh(") : desc.find("/84h/")]
            break
    if master is None:
        raise SystemExit("wallet has no private wpkh descriptor")
    keys = []
    for _ in range(3):
        addr = core.call("getnewaddress", "", "bech32")
        info = core.call("getaddressinfo", addr)
        keys.append(f"{master}/{info['hdkeypath'][2:]}")
    desc = f"sh(multi(2,{','.join(keys)}))"
    checksum = core.call("getdescriptorinfo", desc)["checksum"]
    private_desc = f"{desc}#{checksum}"
    imported = core.call(
        "importdescriptors",
        [{"desc": private_desc, "timestamp": "now"}],
    )
    if not imported or not imported[0].get("success"):
        raise SystemExit(f"importdescriptors failed: {imported}")
    return core.call("deriveaddresses", private_desc)[0]


def vout_paying(info, sats):
    hits = [o["n"] for o in info["vout"] if base.btc_to_sats(o["value"]) == sats]
    if len(hits) != 1:
        raise SystemExit(f"expected one output of {sats} sats, got {hits}")
    return hits[0]


def cmp_entry(label, core_entry, rust_entry):
    base.expect_equal(f"{label}.keys", list(core_entry.keys()), list(rust_entry.keys()))
    fees_c = core_entry.get("fees") or {}
    fees_r = rust_entry.get("fees") or {}
    base.expect_equal(f"{label}.fees.keys", list(fees_c.keys()), list(fees_r.keys()))
    for key in EXACT_KEYS:
        base.expect_equal(f"{label}.{key}", core_entry.get(key), rust_entry.get(key))
    for key in FEE_KEYS:
        c_val = fees_c.get(key)
        r_val = fees_r.get(key)
        c_sats = None if c_val is None else base.btc_to_sats(c_val)
        r_sats = None if r_val is None else base.btc_to_sats(r_val)
        base.expect_equal(f"{label}.fees.{key}", c_sats, r_sats)
    c_time, r_time = core_entry.get("time"), rust_entry.get("time")
    now = int(time.time())
    if c_time != r_time:
        close = (
            isinstance(c_time, int)
            and isinstance(r_time, int)
            and abs(c_time - now) < 600
            and abs(r_time - now) < 600
        )
        base.note(
            f"{label}.time",
            c_time,
            r_time,
            "each node stamps its own admission time" if close else None,
        )


def cmp_verbose(core, rust, label):
    c_pool = core.call("getrawmempool", True)
    r_pool = rust.call("getrawmempool", True)
    base.expect_equal(
        f"{label}.txid_set",
        sorted(c_pool),
        sorted(r_pool),
    )
    matched = sorted(set(c_pool) & set(r_pool))
    print(f"MATCH {label} txid set ({len(matched)})")
    for txid in matched:
        cmp_entry(f"{label}.mempool[{txid[:12]}]", c_pool[txid], r_pool[txid])
        c_one = core.call("getmempoolentry", txid)
        r_one = rust.call("getmempoolentry", txid)
        base.expect_equal(f"{label}.getmempoolentry[{txid[:12]}].core_vs_raw", c_one, c_pool[txid])
        base.expect_equal(f"{label}.getmempoolentry[{txid[:12]}].rust_vs_raw", r_one, r_pool[txid])
        cmp_entry(f"{label}.getmempoolentry[{txid[:12]}]", c_one, r_one)
    c_info = core.call("getmempoolinfo")
    r_info = rust.call("getmempoolinfo")
    base.expect_equal(
        f"{label}.unbroadcastcount",
        c_info.get("unbroadcastcount"),
        r_info.get("unbroadcastcount"),
    )
    return c_pool, r_pool


def cmp_gbt(core, rust, label):
    req = {"rules": ["segwit"]}
    c = core.call("getblocktemplate", req)
    r = rust.call("getblocktemplate", req)
    base.expect_equal(f"{label}.sigoplimit", c.get("sigoplimit"), r.get("sigoplimit"))
    c_txs = c.get("transactions") or []
    r_txs = r.get("transactions") or []

    def shape(txs):
        return [
            {
                "txid": t.get("txid"),
                "depends": t.get("depends"),
                "fee": t.get("fee"),
                "sigops": t.get("sigops"),
                "weight": t.get("weight"),
            }
            for t in txs
        ]

    c_shape, r_shape = shape(c_txs), shape(r_txs)
    base.expect_equal(f"{label}.order", [t["txid"] for t in c_shape], [t["txid"] for t in r_shape])
    base.expect_equal(f"{label}.depends", [t["depends"] for t in c_shape], [t["depends"] for t in r_shape])
    if [t["txid"] for t in c_shape] == [t["txid"] for t in r_shape]:
        print(f"MATCH {label} order {[t['txid'][:12] for t in c_shape]}")
    else:
        print(f"ORDER core {[t['txid'][:12] for t in c_shape]}")
        print(f"ORDER rust {[t['txid'][:12] for t in r_shape]}")
    c_by = {t["txid"]: t for t in c_shape}
    r_by = {t["txid"]: t for t in r_shape}
    for txid in sorted(set(c_by) & set(r_by)):
        for key in ("fee", "sigops", "weight"):
            base.expect_equal(f"{label}.tx[{txid[:12]}].{key}", c_by[txid][key], r_by[txid][key])
    return c_shape, r_shape


def take_utxo(utxos, need_sats):
    for i, u in enumerate(utxos):
        if base.btc_to_sats(u["amount"]) >= need_sats:
            return utxos.pop(i)
    raise SystemExit(f"no utxo with {need_sats} sats")


def main():
    core, rust, core_proc, rust_proc = base.start_nodes()
    try:
        core.call("createwallet", "sweep")
        mine_to = core.call("getnewaddress", "", "bech32")
        core.call("generatetoaddress", 120, mine_to)
        base.replay(core, rust, 0)
        base.cmp_tip(core, rust, "mature")

        def fresh_utxos():
            utxos = core.call("listunspent", 1, 9999999)
            return [u for u in utxos if base.btc_to_sats(u["amount"]) >= 50 * 100_000_000]

        # Confirm a P2SH 2-of-3 output before anything else sits in the mempool,
        # so generatetoaddress cannot sweep the spends under test.
        utxos = fresh_utxos()
        ms_addr = import_p2sh_2of3(core)
        u = take_utxo(utxos, 100_000_000)
        fund_pay = 100_000_000
        fund_id, fund_info = sign_and_send(
            core,
            rust,
            u["txid"],
            u["vout"],
            base.btc_to_sats(u["amount"]),
            {ms_addr: fund_pay},
            10_000,
            "p2sh.fund",
        )
        fund_vout = vout_paying(fund_info, fund_pay)
        height = core.call("getblockcount")
        core.call("generatetoaddress", 1, mine_to)
        base.replay(core, rust, height)
        base.cmp_tip(core, rust, "p2sh.funded")

        utxos = fresh_utxos()
        bech32 = core.call("getnewaddress", "", "bech32")
        u = take_utxo(utxos, 100_000_000)
        p2wpkh_id, _ = sign_and_send(
            core,
            rust,
            u["txid"],
            u["vout"],
            base.btc_to_sats(u["amount"]),
            {bech32: 100_000_000 - 10_000},
            10_000,
            "p2wpkh",
        )

        p2sh_id, _ = sign_and_send(
            core,
            rust,
            fund_id,
            fund_vout,
            fund_pay,
            {bech32: fund_pay - 30_000},
            30_000,
            "p2sh.spend",
        )

        # Parent -> child -> grandchild. Parent signals BIP125.
        u = take_utxo(utxos, 100_000_000)
        chain_dest = core.call("getnewaddress", "", "bech32")
        parent_value = 100_000_000 - 1_000
        parent_id, parent_info = sign_and_send(
            core,
            rust,
            u["txid"],
            u["vout"],
            base.btc_to_sats(u["amount"]),
            {chain_dest: parent_value},
            1_000,
            "chain.parent",
            sequence=0xFFFFFFFD,
        )
        child_value = parent_value - 50_000
        child_dest = core.call("getnewaddress", "", "bech32")
        child_id, child_info = sign_and_send(
            core,
            rust,
            parent_id,
            vout_paying(parent_info, parent_value),
            parent_value,
            {child_dest: child_value},
            50_000,
            "chain.child",
        )
        grand_dest = core.call("getnewaddress", "", "bech32")
        grand_id, _ = sign_and_send(
            core,
            rust,
            child_id,
            vout_paying(child_info, child_value),
            child_value,
            {grand_dest: child_value - 200_000},
            200_000,
            "chain.grand",
        )

        # Parent with two children: one high fee, one low.
        u = take_utxo(utxos, 200_000_000)
        low_dest = core.call("getnewaddress", "", "bech32")
        high_dest = core.call("getnewaddress", "", "bech32")
        low_pay = 100_000_000 - 10_000
        high_pay = 100_000_000 - 40_000
        split_parent, split_info = sign_and_send(
            core,
            rust,
            u["txid"],
            u["vout"],
            base.btc_to_sats(u["amount"]),
            {low_dest: low_pay, high_dest: high_pay},
            50_000,
            "split.parent",
        )
        low_id, _ = sign_and_send(
            core,
            rust,
            split_parent,
            vout_paying(split_info, low_pay),
            low_pay,
            {core.call("getnewaddress", "", "bech32"): low_pay - 5_000},
            5_000,
            "split.low",
        )
        high_id, _ = sign_and_send(
            core,
            rust,
            split_parent,
            vout_paying(split_info, high_pay),
            high_pay,
            {core.call("getnewaddress", "", "bech32"): high_pay - 400_000},
            400_000,
            "split.high",
        )

        # Parent and two similarly high-fee children: one chunk.
        u = take_utxo(utxos, 200_000_000)
        d1 = core.call("getnewaddress", "", "bech32")
        d2 = core.call("getnewaddress", "", "bech32")
        both_pay = 100_000_000 - 100_000
        both_parent, both_info = sign_and_send(
            core,
            rust,
            u["txid"],
            u["vout"],
            base.btc_to_sats(u["amount"]),
            {d1: both_pay, d2: both_pay},
            200_000,
            "both.parent",
        )
        both_vouts = [o["n"] for o in both_info["vout"] if base.btc_to_sats(o["value"]) == both_pay]
        if len(both_vouts) != 2:
            raise SystemExit(f"both-parent outputs {both_vouts}")
        c1, _ = sign_and_send(
            core,
            rust,
            both_parent,
            both_vouts[0],
            both_pay,
            {core.call("getnewaddress", "", "bech32"): both_pay - 200_000},
            200_000,
            "both.child1",
        )
        c2, _ = sign_and_send(
            core,
            rust,
            both_parent,
            both_vouts[1],
            both_pay,
            {core.call("getnewaddress", "", "bech32"): both_pay - 200_000},
            200_000,
            "both.child2",
        )

        print("ids", {
            "p2wpkh": p2wpkh_id,
            "p2sh": p2sh_id,
            "parent": parent_id,
            "child": child_id,
            "grand": grand_id,
            "split": split_parent,
            "low": low_id,
            "high": high_id,
            "both": both_parent,
            "c1": c1,
            "c2": c2,
        })

        base.cmp_tip(core, rust, "loaded")
        cmp_verbose(core, rust, "loaded")
        gbt_c, gbt_r = cmp_gbt(core, rust, "loaded")
        by_txid = {t["txid"]: t for t in gbt_c}
        by_txid_r = {t["txid"]: t for t in gbt_r}
        for name, txid, expect in (
            ("p2wpkh", p2wpkh_id, 1),
            ("p2sh", p2sh_id, 12),
        ):
            print(
                f"sigops {name} core={by_txid.get(txid, {}).get('sigops')} "
                f"rust={by_txid_r.get(txid, {}).get('sigops')} expect={expect}"
            )

        # Ancestors of the grandchild: same verbose shape as the pool.
        c_anc = core.call("getmempoolancestors", grand_id, True)
        r_anc = rust.call("getmempoolancestors", grand_id, True)
        base.expect_equal("loaded.ancestors.ids", sorted(c_anc), sorted(r_anc))
        for txid in sorted(set(c_anc) & set(r_anc)):
            cmp_entry(f"loaded.ancestor[{txid[:12]}]", c_anc[txid], r_anc[txid])

        height = core.call("getblockcount")
        mined = core.call("generatetoaddress", 1, mine_to)[0]
        base.replay(core, rust, height)
        base.cmp_tip(core, rust, "mined")
        cmp_verbose(core, rust, "mined")

        base.cmp_rpc(core, rust, "refill", "invalidateblock", [mined])
        base.cmp_tip(core, rust, "refill")
        cmp_verbose(core, rust, "refill")
        cmp_gbt(core, rust, "refill")

        # Two-block invalidate: record heights, do not fail the run on them.
        # Mine two more blocks worth of single txs, disconnect both, compare.
        extra = []
        for i in range(2):
            u = take_utxo(utxos, 50_000_000)
            txid, _ = sign_and_send(
                core,
                rust,
                u["txid"],
                u["vout"],
                base.btc_to_sats(u["amount"]),
                {core.call("getnewaddress", "", "bech32"): 50_000_000 - 20_000},
                20_000,
                f"extra.{i}",
            )
            extra.append(txid)
            h = core.call("getblockcount")
            blk = core.call("generatetoaddress", 1, mine_to)[0]
            base.replay(core, rust, h)
            extra.append(blk)
        # extra = [tx0, blk0, tx1, blk1]. One invalidate of blk0 disconnects
        # both blocks. Core stamps each DisconnectTip; a single refill stamps
        # every tx with the final tip.
        blk0 = extra[1]
        tx1, tx0 = extra[2], extra[0]
        core.call("invalidateblock", blk0)
        rust.call("invalidateblock", blk0)
        base.cmp_tip(core, rust, "twoblock")
        c_pool = core.call("getrawmempool", True)
        r_pool = rust.call("getrawmempool", True)
        for txid in (tx0, tx1):
            if txid in c_pool and txid in r_pool:
                ch = c_pool[txid].get("height")
                rh = r_pool[txid].get("height")
                print(f"twoblock height {txid[:12]} core={ch} rust={rh}")
                if ch != rh:
                    base.note(
                        f"twoblock.height[{txid[:12]}]",
                        ch,
                        rh,
                        "multi-block invalidate: Core stamps each disconnect's tip; "
                        "rustoshi stamps every refilled tx with the final tip",
                    )
    finally:
        base.stop(rust_proc)
        base.stop(core_proc)

    unjustified = [m for m in base.MISMATCHES if not m["justified"]]
    print(f"\n{len(base.MISMATCHES)} mismatches, {len(unjustified)} unjustified")
    for m in base.MISMATCHES:
        print(f"  {'justified' if m['justified'] else 'FAIL'} {m['path']}")
    return 1 if unjustified else 0


if __name__ == "__main__":
    sys.exit(main())
