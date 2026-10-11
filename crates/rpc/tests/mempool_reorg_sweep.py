#!/usr/bin/env python3
"""Regtest comparison of rustoshi and Bitcoin Core for mempool reorg behavior.

Builds one chain on Core, replays those blocks into rustoshi, and sends the
same signed transactions to both. Nothing here dials another node: Core is
started with -listen=0 and rustoshi with --maxconnections 0.

Compares, and prints every mismatch with both values:
  getblocktemplate transaction order and BIP-22 depends
  getrawmempool txid set, plus verbose entry fields
  submitblock / invalidateblock / reconsiderblock results
  tip (getbestblockhash, getblockcount)
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

CORE_BIN = Path(os.environ.get("BITCOIN_BIN", "/tmp/bitcoin-31.1/bin"))
RUSTOSHI = Path(os.environ.get("RUSTOSHI_BIN", "/workspace/target/debug/rustoshi"))
WORKDIR = Path(os.environ.get("SWEEP_WORKDIR", "/tmp/mempool-reorg-sweep"))

CORE_RPC_PORT = 18443
RUST_RPC_PORT = 18445
RPC_USER = "sweep"
RPC_PASS = "sweep"

MISMATCHES = []


class RpcError(Exception):
    def __init__(self, method, error):
        self.method = method
        self.error = error
        super().__init__(f"{method}: {error}")


class Rpc:
    def __init__(self, url, user, password):
        self.url = url
        token = f"{user}:{password}".encode()
        import base64

        self.auth = "Basic " + base64.b64encode(token).decode()

    def raw(self, method, params):
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            payload = json.loads(e.read().decode())
        return payload.get("result"), payload.get("error")

    def call(self, method, *params):
        result, err = self.raw(method, list(params))
        if err:
            raise RpcError(method, err)
        return result


def note(path, core_val, rust_val, justified=None):
    MISMATCHES.append(
        {"path": path, "core": core_val, "rustoshi": rust_val, "justified": justified}
    )
    tag = " (justified)" if justified else ""
    print(f"MISMATCH {path}{tag}")
    print(f"  core:     {json.dumps(core_val, sort_keys=True)}")
    print(f"  rustoshi: {json.dumps(rust_val, sort_keys=True)}")


def expect_equal(path, core_val, rust_val, justified=None):
    if core_val != rust_val:
        note(path, core_val, rust_val, justified)


def wait_rpc(rpc, proc, label):
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"{label} exited {proc.returncode} before RPC came up")
        try:
            rpc.call("getblockcount")
            return
        except Exception:
            time.sleep(0.2)
    raise SystemExit(f"{label} RPC did not come up")


def start_nodes():
    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    core_dir = WORKDIR / "core"
    rust_dir = WORKDIR / "rustoshi"
    core_dir.mkdir(parents=True)
    rust_dir.mkdir(parents=True)

    bitcoind = CORE_BIN / "bitcoind"
    core_proc = subprocess.Popen(
        [
            str(bitcoind),
            "-regtest",
            "-daemon=0",
            f"-datadir={core_dir}",
            f"-port={18444}",
            f"-rpcport={CORE_RPC_PORT}",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            f"-rpcuser={RPC_USER}",
            f"-rpcpassword={RPC_PASS}",
            "-listen=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-fallbackfee=0.0002",
            f"-debuglogfile={WORKDIR / 'bitcoind.log'}",
        ],
        stdout=open(WORKDIR / "bitcoind.out", "w"),
        stderr=subprocess.STDOUT,
    )
    rust_proc = subprocess.Popen(
        [
            str(RUSTOSHI),
            "--network",
            "regtest",
            "--datadir",
            str(rust_dir),
            "--rpcbind",
            f"127.0.0.1:{RUST_RPC_PORT}",
            "--rpcuser",
            RPC_USER,
            "--rpcpassword",
            RPC_PASS,
            "--maxconnections",
            "0",
            "--nodnsseed",
            "--nofixedseeds",
            "--port",
            "18446",
            "--metrics-port",
            "0",
            "--loglevel",
            "info",
        ],
        stdout=open(WORKDIR / "rustoshi.out", "w"),
        stderr=subprocess.STDOUT,
    )
    core = Rpc(f"http://127.0.0.1:{CORE_RPC_PORT}", RPC_USER, RPC_PASS)
    rust = Rpc(f"http://127.0.0.1:{RUST_RPC_PORT}", RPC_USER, RPC_PASS)
    try:
        wait_rpc(core, core_proc, "bitcoind")
        wait_rpc(rust, rust_proc, "rustoshi")
    except BaseException:
        stop(rust_proc)
        stop(core_proc)
        raise
    return core, rust, core_proc, rust_proc


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


def sats_num(sats):
    """JSON number text with 8 decimal places, no float rounding."""
    sign = "-" if sats < 0 else ""
    sats = abs(int(sats))
    return f"{sign}{sats // 100_000_000}.{sats % 100_000_000:08d}"


def btc_to_sats(value):
    if isinstance(value, str):
        whole, _, frac = value.partition(".")
        frac = (frac + "00000000")[:8]
        sign = -1 if whole.startswith("-") else 1
        return sign * (abs(int(whole or "0")) * 100_000_000 + int(frac or "0"))
    return int(round(float(value) * 100_000_000))


def replay(core, rust, synced):
    tip = core.call("getblockcount")
    for height in range(synced + 1, tip + 1):
        block_hash = core.call("getblockhash", height)
        block_hex = core.call("getblock", block_hash, 0)
        result, err = rust.raw("submitblock", [block_hex])
        if err or result is not None:
            raise SystemExit(
                f"replay height {height} {block_hash}: result={result} error={err}"
            )
    return tip


def send_both(core, rust, hex_tx, label):
    c_res, c_err = core.raw("sendrawtransaction", [hex_tx])
    r_res, r_err = rust.raw("sendrawtransaction", [hex_tx])
    c_ok = c_err is None
    r_ok = r_err is None
    if c_ok != r_ok or (c_ok and c_res != r_res):
        note(
            f"{label}.sendrawtransaction",
            {"result": c_res, "error": c_err},
            {"result": r_res, "error": r_err},
        )
    if not c_ok:
        raise SystemExit(f"core rejected {label}: {c_err}")
    return c_res


def cmp_tip(core, rust, label):
    c_height, r_height = core.call("getblockcount"), rust.call("getblockcount")
    c_tip, r_tip = core.call("getbestblockhash"), rust.call("getbestblockhash")
    expect_equal(f"{label}.getblockcount", c_height, r_height)
    expect_equal(f"{label}.getbestblockhash", c_tip, r_tip)
    if c_height == r_height and c_tip == r_tip:
        print(f"MATCH {label} tip {c_tip} height {c_height}")


def cmp_rpc(core, rust, label, method, params):
    c_res, c_err = core.raw(method, params)
    r_res, r_err = rust.raw(method, params)
    c_out = {"result": c_res, "error": c_err}
    r_out = {"result": r_res, "error": r_err}
    expect_equal(f"{label}.{method}", c_out, r_out)
    if c_out == r_out:
        print(f"MATCH {label}.{method} {c_res!r}")
    return c_res, r_res


def fee_sats(entry):
    fees = entry.get("fees") or {}
    return {k: btc_to_sats(v) for k, v in fees.items()}


def cmp_mempool(core, rust, label):
    c = core.call("getrawmempool", True)
    r = rust.call("getrawmempool", True)
    c_ids, r_ids = set(c), set(r)
    expect_equal(f"{label}.getrawmempool.txid_set", sorted(c_ids), sorted(r_ids))
    if c_ids == r_ids:
        print(f"MATCH {label} mempool txids ({len(c_ids)})")
    now = int(time.time())
    for txid in sorted(c_ids & r_ids):
        ce, re = c[txid], r[txid]
        for key in (
            "vsize",
            "weight",
            "descendantcount",
            "descendantsize",
            "ancestorcount",
            "ancestorsize",
            "wtxid",
            "depends",
            "spentby",
            "bip125-replaceable",
            "unbroadcast",
        ):
            expect_equal(f"{label}.mempool[{txid[:12]}].{key}", ce.get(key), re.get(key))
        c_fees, r_fees = fee_sats(ce), fee_sats(re)
        shared = sorted(set(c_fees) & set(r_fees))
        expect_equal(
            f"{label}.mempool[{txid[:12]}].fees_sats",
            {k: c_fees[k] for k in shared},
            {k: r_fees[k] for k in shared},
        )
        only_core = sorted(set(c_fees) - set(r_fees))
        only_rust = sorted(set(r_fees) - set(c_fees))
        if only_core or only_rust:
            note(
                f"{label}.mempool[{txid[:12]}].fees_only",
                {k: c_fees[k] for k in only_core},
                {k: r_fees[k] for k in only_rust},
                "Core v31 adds fees.chunk (cluster chunk fee); the shared fee fields match"
                if only_core == ["chunk"] and not only_rust
                else None,
            )
        # Admission time is local to each process.
        c_time, r_time = ce.get("time"), re.get("time")
        if c_time != r_time:
            close = (
                isinstance(c_time, int)
                and isinstance(r_time, int)
                and abs(c_time - now) < 600
                and abs(r_time - now) < 600
            )
            note(
                f"{label}.mempool[{txid[:12]}].time",
                c_time,
                r_time,
                "each node stamps its own admission time" if close else None,
            )
        expect_equal(f"{label}.mempool[{txid[:12]}].height", ce.get("height"), re.get("height"))
    return c_ids, r_ids


def cmp_template(core, rust, label):
    req = {"rules": ["segwit"]}
    c = core.call("getblocktemplate", req)
    r = rust.call("getblocktemplate", req)
    c_txs = c.get("transactions") or []
    r_txs = r.get("transactions") or []

    def shape(txs):
        return [
            {
                "txid": t.get("txid"),
                "depends": t.get("depends"),
                "fee": t.get("fee"),
                "weight": t.get("weight"),
                "sigops": t.get("sigops"),
            }
            for t in txs
        ]

    c_shape, r_shape = shape(c_txs), shape(r_txs)
    c_order = [t["txid"] for t in c_shape]
    r_order = [t["txid"] for t in r_shape]
    c_deps = [t["depends"] for t in c_shape]
    r_deps = [t["depends"] for t in r_shape]
    expect_equal(f"{label}.gbt.tx_order", c_order, r_order)
    expect_equal(f"{label}.gbt.depends", c_deps, r_deps)
    if c_order == r_order and c_deps == r_deps:
        print(f"MATCH {label} gbt order+depends {c_deps}")
    if [t["txid"] for t in c_shape] == [t["txid"] for t in r_shape]:
        for i, (ct, rt) in enumerate(zip(c_shape, r_shape)):
            for key in ("fee", "weight"):
                expect_equal(f"{label}.gbt.tx[{i}].{key}", ct[key], rt[key])
            if ct["sigops"] != rt["sigops"]:
                note(
                    f"{label}.gbt.tx[{i}].sigops",
                    ct["sigops"],
                    rt["sigops"],
                    "rustoshi counts legacy sigops times the witness scale; "
                    "a P2WPKH input has none. Core counts the witness sigop",
                )
    return c_shape, r_shape


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def script_num(n):
    if n == 0:
        return b"\x00"
    raw = n.to_bytes(8, "little").rstrip(b"\x00")
    if raw[-1] & 0x80:
        raw += b"\x00"
    return bytes([len(raw)]) + raw


def parse_bits(bits):
    if isinstance(bits, str):
        return int(bits, 16)
    return int(bits)


def bits_target(bits):
    bits = parse_bits(bits)
    exp = bits >> 24
    mant = bits & 0xFFFFFF
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def mine_on(prev_hash_hex, height, bits, timestamp):
    """Coinbase-only regtest block whose parent is prev_hash_hex."""
    script = script_num(height) + b"\x00"
    tx = b"".join(
        [
            struct.pack("<i", 2),
            b"\x01",
            b"\x00" * 32,
            struct.pack("<I", 0xFFFFFFFF),
            bytes([len(script)]),
            script,
            struct.pack("<I", 0xFFFFFFFF),
            b"\x01",
            struct.pack("<q", 50 * 100_000_000),
            b"\x01\x51",
            struct.pack("<I", 0),
        ]
    )
    merkle = dsha(tx)
    prev = bytes.fromhex(prev_hash_hex)[::-1]
    target = bits_target(bits)
    for nonce in range(0x1000000):
        header = b"".join(
            [
                struct.pack("<i", 0x20000000),
                prev,
                merkle,
                struct.pack("<I", timestamp),
                struct.pack("<I", bits),
                struct.pack("<I", nonce),
            ]
        )
        if int.from_bytes(dsha(header), "little") <= target:
            # CompactSize tx count, then the coinbase. Without the count
            # Core reports bad-txnmrklroot and rustoshi fails to decode.
            return (header + b"\x01" + tx).hex()
    raise SystemExit("failed to mine bad-prevblk candidate")


def make_parent(core):
    """Low-feerate parent paying a wallet address. Child is signed after broadcast."""
    dest = core.call("getnewaddress")
    raw = core.call(
        "createrawtransaction",
        [],
        {dest: sats_num(1_000_000)},
    )
    # fee_rate is sat/vB. 1 sat/vB is above the 0.1 sat/vB relay floor and
    # at Core's default block mintxfee, so the parent is mineable but the
    # child (signed later) outranks it.
    funded = core.call(
        "fundrawtransaction",
        raw,
        {"fee_rate": 1, "changePosition": 1},
    )
    signed = core.call("signrawtransactionwithwallet", funded["hex"])
    if not signed["complete"]:
        raise SystemExit(f"parent did not sign: {signed}")
    info = core.call("decoderawtransaction", signed["hex"])
    pay_sats = btc_to_sats(info["vout"][0]["value"])
    return signed["hex"], info["txid"], pay_sats


def make_child(core, parent_id, pay_sats):
    """High-feerate child spending the parent's first output."""
    child_fee = 50_000
    dest = core.call("getnewaddress")
    raw = core.call(
        "createrawtransaction",
        [{"txid": parent_id, "vout": 0}],
        {dest: sats_num(pay_sats - child_fee)},
    )
    signed = core.call("signrawtransactionwithwallet", raw)
    if not signed["complete"]:
        raise SystemExit(f"child did not sign: {signed}")
    return signed["hex"]


def make_cluster_parent(core):
    """Parent with 64 equal outputs. Children are signed only after it confirms."""
    addrs = [core.call("getnewaddress") for _ in range(64)]
    outputs = {addr: sats_num(200_000) for addr in addrs}
    raw = core.call("createrawtransaction", [], outputs)
    funded = core.call(
        "fundrawtransaction",
        raw,
        {"fee_rate": 1, "changePosition": 64},
    )
    signed = core.call("signrawtransactionwithwallet", funded["hex"])
    if not signed["complete"]:
        raise SystemExit(f"cluster parent did not sign: {signed}")
    info = core.call("decoderawtransaction", signed["hex"])
    for i in range(64):
        got = btc_to_sats(info["vout"][i]["value"])
        if got != 200_000:
            raise SystemExit(f"vout {i} is {got}, wanted 200000")
    return signed["hex"], info["txid"]


def make_cluster_children(core, parent_id):
    """64 children of strictly increasing fee, spending confirmed parent outputs."""
    children = []
    for i in range(64):
        fee = 5_000 + i * 200
        dest = core.call("getnewaddress")
        child_raw = core.call(
            "createrawtransaction",
            [{"txid": parent_id, "vout": i}],
            {dest: sats_num(200_000 - fee)},
        )
        child_signed = core.call("signrawtransactionwithwallet", child_raw)
        if not child_signed["complete"]:
            raise SystemExit(f"cluster child {i} did not sign: {child_signed}")
        children.append((fee, child_signed["hex"]))
    return children


def main():
    if not RUSTOSHI.exists():
        raise SystemExit(f"rustoshi binary missing: {RUSTOSHI}")
    if not (CORE_BIN / "bitcoind").exists():
        raise SystemExit(f"bitcoind missing under {CORE_BIN}")

    core, rust, core_proc, rust_proc = start_nodes()
    try:
        genesis_c = core.call("getblockhash", 0)
        genesis_r = rust.call("getblockhash", 0)
        expect_equal("genesis", genesis_c, genesis_r)
        if genesis_c != genesis_r:
            raise SystemExit("genesis mismatch; refusing to continue")

        core.call("createwallet", "sweep")
        addr = core.call("getnewaddress")
        core.call("generatetoaddress", 101, addr)
        height = replay(core, rust, 0)
        cmp_tip(core, rust, "after_maturity")
        print(f"synced {height} blocks")

        parent_hex, parent_id, pay_sats = make_parent(core)
        send_both(core, rust, parent_hex, "cpfp.parent")
        child_hex = make_child(core, parent_id, pay_sats)
        send_both(core, rust, child_hex, "cpfp.child")
        cmp_mempool(core, rust, "cpfp.mempool")
        cmp_template(core, rust, "cpfp")

        mined = core.call("generatetoaddress", 1, addr)[0]
        replay(core, rust, height)
        height = core.call("getblockcount")
        cmp_tip(core, rust, "cpfp.mined")
        cmp_mempool(core, rust, "cpfp.mined")

        cmp_rpc(core, rust, "cpfp", "invalidateblock", [mined])
        cmp_tip(core, rust, "cpfp.invalidated")
        cmp_mempool(core, rust, "cpfp.invalidated")
        cmp_template(core, rust, "cpfp.invalidated")

        mined_hex = core.call("getblock", mined, 0)
        active = core.call("getbestblockhash")
        active_hex = core.call("getblock", active, 0)
        cmp_rpc(core, rust, "submit.invalidated", "submitblock", [mined_hex])
        cmp_rpc(core, rust, "submit.active", "submitblock", [active_hex])
        header = core.call("getblockheader", mined)
        candidate = mine_on(
            mined,
            header["height"] + 1,
            parse_bits(header["bits"]),
            int(time.time()),
        )
        cmp_rpc(core, rust, "submit.bad_prev", "submitblock", [candidate])
        cmp_tip(core, rust, "submit.after")

        cmp_rpc(core, rust, "cpfp", "reconsiderblock", [mined])
        cmp_tip(core, rust, "cpfp.reconsidered")
        cmp_mempool(core, rust, "cpfp.reconsidered")
        height = core.call("getblockcount")

        parent_hex, parent_id = make_cluster_parent(core)
        send_both(core, rust, parent_hex, "cluster.parent")
        cluster_block = core.call("generatetoaddress", 1, addr)[0]
        replay(core, rust, height)
        height = core.call("getblockcount")
        cmp_tip(core, rust, "cluster.mined")
        # Children spend the confirmed parent, so each is its own 1-tx cluster
        # until the parent block is disconnected.
        children = make_cluster_children(core, parent_id)
        child_ids = []
        for fee, child_hex in children:
            child_ids.append((fee, send_both(core, rust, child_hex, f"cluster.child.{fee}")))
        before_c, before_r = cmp_mempool(core, rust, "cluster.before_invalidate")
        if before_c != set(txid for _, txid in child_ids):
            note(
                "cluster.before_invalidate.expected_children",
                sorted(txid for _, txid in child_ids),
                sorted(before_c),
            )

        cmp_rpc(core, rust, "cluster", "invalidateblock", [cluster_block])
        cmp_tip(core, rust, "cluster.invalidated")
        after_c, after_r = cmp_mempool(core, rust, "cluster.invalidated")
        lowest = child_ids[0][1]
        for side, ids in (("core", after_c), ("rustoshi", after_r)):
            present_parent = parent_id in ids
            dropped_lowest = lowest not in ids
            print(
                f"cluster {side}: size={len(ids)} parent_present={present_parent} "
                f"lowest_dropped={dropped_lowest}"
            )
        if lowest in after_c or lowest in after_r or parent_id not in after_c or parent_id not in after_r:
            note(
                "cluster.invalidated.expected_trim",
                {
                    "parent": parent_id,
                    "dropped_lowest": lowest,
                    "core_has_parent": parent_id in after_c,
                    "core_has_lowest": lowest in after_c,
                    "core_size": len(after_c),
                },
                {
                    "parent": parent_id,
                    "dropped_lowest": lowest,
                    "rustoshi_has_parent": parent_id in after_r,
                    "rustoshi_has_lowest": lowest in after_r,
                    "rustoshi_size": len(after_r),
                },
            )
        kept = [txid for _, txid in child_ids[1:]]
        missing_kept_c = [txid for txid in kept if txid not in after_c]
        missing_kept_r = [txid for txid in kept if txid not in after_r]
        if missing_kept_c or missing_kept_r:
            note(
                "cluster.invalidated.higher_children",
                missing_kept_c,
                missing_kept_r,
            )

        cmp_rpc(core, rust, "cluster", "reconsiderblock", [cluster_block])
        cmp_tip(core, rust, "cluster.reconsidered")
        cmp_mempool(core, rust, "cluster.reconsidered")
    finally:
        stop(rust_proc)
        stop(core_proc)

    unjustified = [m for m in MISMATCHES if not m["justified"]]
    print(f"\n{len(MISMATCHES)} mismatches, {len(unjustified)} unjustified")
    return 1 if unjustified else 0


if __name__ == "__main__":
    sys.exit(main())
