#!/usr/bin/env python3
"""Replay one regtest chain against Bitcoin Core v31.1 and rustoshi.

Both nodes stay offline (no DNS, no fixed seeds, no listen). Blocks are
mined once on a throwaway Core wallet and submitted as the same hex to a
fresh Core node and a fresh rustoshi. Compared, field by field:

  * submitblock: valid (null), duplicate, duplicate-invalid, bad-prevblk,
    inconclusive, and a context-free CheckBlock failure on a failed parent
  * invalidateblock / reconsiderblock results
  * getchaintips (height, hash, branchlen, status)
  * getbestblockhash
  * getblockchaininfo, every field (headers, verificationprogress,
    size_on_disk included)
  * getrawmempool after invalidate and after reconsider, including time,
    bip125-replaceable, fees.chunk, and chunkweight
  * submitheader of a header whose parent was invalidated (bad-prevblk,
    header not stored)

Usage:
  invalidated_submit_sweep.py --bitcoind PATH --bitcoin-cli PATH --rustoshi PATH
      [--tarball PATH --sha256sums PATH]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Floats Core emits with setFloat / setprecision. Compared as f64.
INFO_FLOATS = {"difficulty", "verificationprogress"}


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def script_num(height: int) -> bytes:
    if height == 0:
        return b"\x00"
    if height <= 16:
        return bytes([0x50 + height])
    h = height
    le = bytearray()
    while h:
        le.append(h & 0xFF)
        h >>= 8
    if le[-1] & 0x80:
        le.append(0)
    return bytes([len(le)]) + bytes(le)


def coinbase(height: int, extra: bytes = b"\x01\xc5") -> bytes:
    script = script_num(height) + extra
    tx = struct.pack("<i", 2)
    tx += compact_size(1)
    tx += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF)
    tx += compact_size(len(script)) + script + struct.pack("<I", 0xFFFFFFFF)
    tx += compact_size(1)
    tx += struct.pack("<q", 50 * 100_000_000) + compact_size(1) + b"\x51"
    tx += struct.pack("<I", 0)
    return tx


def solve(prefix76: bytes) -> bytes:
    # Compact 0x207fffff: mantissa 0x7fffff, exponent 0x20.
    target = 0x7FFFFF << (8 * (0x20 - 3))
    for nonce in range(1 << 24):
        hdr = prefix76 + struct.pack("<I", nonce)
        if int.from_bytes(sha256d(hdr), "little") <= target:
            return hdr
    raise RuntimeError("regtest PoW search failed")


def make_block(prev_hex: str, cb_height: int, timestamp: int, extra: bytes = b"\x01\xc5") -> str:
    tx = coinbase(cb_height, extra)
    merkle = sha256d(tx)
    prev = bytes.fromhex(prev_hex)[::-1]
    prefix = struct.pack("<i", 0x20000000) + prev + merkle + struct.pack("<II", timestamp, 0x207FFFFF)
    hdr = solve(prefix)
    return (hdr + compact_size(1) + tx).hex()


def mutated_block(prev_hex: str, timestamp: int) -> str:
    """Valid PoW header whose merkle root does not match the coinbase."""
    tx = coinbase(1, b"\x02\xc5")
    merkle = sha256d(coinbase(2))
    prev = bytes.fromhex(prev_hex)[::-1]
    prefix = struct.pack("<i", 0x20000000) + prev + merkle + struct.pack("<II", timestamp, 0x207FFFFF)
    hdr = solve(prefix)
    return (hdr + compact_size(1) + tx).hex()


class Rpc:
    def __init__(self, url: str, cookie_paths: list[str]):
        self.url = url
        self.cookie_paths = cookie_paths

    def _auth(self) -> str:
        for path in self.cookie_paths:
            if os.path.exists(path):
                return open(path).read().strip()
        raise RuntimeError(f"no cookie in {self.cookie_paths}")

    def call(self, method: str, params: list | None = None):
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params or []}
        ).encode()
        token = base64.b64encode(self._auth().encode()).decode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {token}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            payload = json.loads(e.read().decode())
        if payload.get("error"):
            err = payload["error"]
            return {"_rpc_error": {"code": err.get("code"), "message": err.get("message")}}
        return payload.get("result")


def wait_rpc(rpc: Rpc, proc: subprocess.Popen | None, log_path: str, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            tail = open(log_path).read()[-2000:]
            raise RuntimeError(f"node exited {proc.returncode}\n{tail}")
        try:
            rpc.call("getblockcount")
            return
        except Exception as e:  # noqa: BLE001 — startup race
            last = str(e)
            time.sleep(0.25)
    tail = open(log_path).read()[-2000:] if os.path.exists(log_path) else ""
    raise RuntimeError(f"RPC never came up ({last})\n{tail}")


def stop_proc(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


class Node:
    def __init__(self, name: str, proc: subprocess.Popen | None, rpc: Rpc, datadir: str, log_path: str):
        self.name = name
        self.proc = proc
        self.rpc = rpc
        self.datadir = datadir
        self.log_path = log_path

    def stop(self) -> None:
        if self.name == "core":
            try:
                self.rpc.call("stop")
            except Exception:
                pass
            if self.proc is not None:
                try:
                    self.proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    stop_proc(self.proc)
        else:
            stop_proc(self.proc)


def start_core(bitcoind: str, datadir: str, rpc_port: int, p2p_port: int) -> Node:
    os.makedirs(datadir, exist_ok=True)
    log_path = os.path.join(datadir, "debug.log")
    proc = subprocess.Popen(
        [
            bitcoind,
            "-regtest",
            f"-datadir={datadir}",
            "-listen=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            f"-port={p2p_port}",
            f"-rpcport={rpc_port}",
            "-rpcbind=127.0.0.1",
            "-fallbackfee=0.0002",
        ],
        stdout=open(log_path, "ab"),
        stderr=subprocess.STDOUT,
    )
    rpc = Rpc(
        f"http://127.0.0.1:{rpc_port}/",
        [os.path.join(datadir, "regtest", ".cookie")],
    )
    wait_rpc(rpc, proc, os.path.join(datadir, "regtest", "debug.log"))
    return Node("core", proc, rpc, datadir, log_path)


def start_rustoshi(binary: str, datadir: str, rpc_port: int, p2p_port: int) -> Node:
    os.makedirs(datadir, exist_ok=True)
    log_path = os.path.join(datadir, "node.log")
    proc = subprocess.Popen(
        [
            binary,
            "--network=regtest",
            f"--datadir={datadir}",
            "--nodnsseed",
            "--nofixedseeds",
            f"--port={p2p_port}",
            f"--rpcbind=127.0.0.1:{rpc_port}",
        ],
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
    )
    rpc = Rpc(
        f"http://127.0.0.1:{rpc_port}/",
        [os.path.join(datadir, ".cookie"), os.path.join(datadir, "regtest", ".cookie")],
    )
    wait_rpc(rpc, proc, log_path)
    return Node("rustoshi", proc, rpc, datadir, log_path)


def cli(bitcoin_cli: str, datadir: str, rpc_port: int, *args: str) -> str:
    return subprocess.check_output(
        [bitcoin_cli, "-regtest", f"-datadir={datadir}", f"-rpcport={rpc_port}", *args],
        text=True,
    ).strip()


def build_chain(bitcoind: str, bitcoin_cli: str, work: str) -> dict:
    """Mine 101 + a confirming block on a throwaway Core, plus the raw spend."""
    datadir = os.path.join(work, "builder")
    node = start_core(bitcoind, datadir, 18601, 18602)
    try:
        cli(bitcoin_cli, datadir, 18601, "createwallet", "builder")
        addr = cli(bitcoin_cli, datadir, 18601, "getnewaddress")
        hashes = json.loads(cli(bitcoin_cli, datadir, 18601, "generatetoaddress", "101", addr))
        cb = json.loads(cli(bitcoin_cli, datadir, 18601, "getblock", hashes[0]))["tx"][0]
        raw = cli(
            bitcoin_cli,
            datadir,
            18601,
            "createrawtransaction",
            json.dumps([{"txid": cb, "vout": 0}]),
            json.dumps([{addr: 49.99}]),
        )
        signed = json.loads(cli(bitcoin_cli, datadir, 18601, "signrawtransactionwithwallet", raw))
        if not signed.get("complete"):
            raise RuntimeError(f"sign failed: {signed}")
        tx_hex = signed["hex"]
        txid = cli(bitcoin_cli, datadir, 18601, "sendrawtransaction", tx_hex)
        conf = json.loads(cli(bitcoin_cli, datadir, 18601, "generatetoaddress", "1", addr))
        hashes.append(conf[0])
        blocks = [cli(bitcoin_cli, datadir, 18601, "getblock", h, "0") for h in hashes]
        return {"blocks": blocks, "hashes": hashes, "tx_hex": tx_hex, "txid": txid}
    finally:
        node.stop()
        shutil.rmtree(datadir, ignore_errors=True)


def header_hash(header_hex: str) -> str:
    return sha256d(bytes.fromhex(header_hex))[::-1].hex()


def snapshot(rpc: Rpc, blocks: list[str], mock_time: int) -> dict:
    """One full pass. `blocks` is height 1..102; the last confirms a non-coinbase spend."""
    out: dict = {"steps": []}
    # Same mock clock on both nodes so mempool `time` is not a race.
    rec_clock = rpc.call("setmocktime", [mock_time])
    if isinstance(rec_clock, dict) and "_rpc_error" in rec_clock:
        raise RuntimeError(f"setmocktime failed: {rec_clock}")

    def rec(name: str, value) -> None:
        out["steps"].append({"name": name, "value": value})

    def submit(name: str, hexdata: str) -> None:
        rec(name, rpc.call("submitblock", [hexdata]))

    def chain_view(tag: str) -> None:
        rec(f"{tag}:getbestblockhash", rpc.call("getbestblockhash"))
        rec(f"{tag}:getblockcount", rpc.call("getblockcount"))
        rec(f"{tag}:getblockchaininfo", rpc.call("getblockchaininfo"))
        rec(f"{tag}:getchaintips", rpc.call("getchaintips"))
        rec(f"{tag}:getrawmempool", rpc.call("getrawmempool", [True]))

    for i, hx in enumerate(blocks, start=1):
        submit(f"valid:{i}", hx)
    chain_view("after-valid")
    submit("duplicate", blocks[0])

    # Sibling of block 1. Valid, but lighter than the tip: Core "inconclusive".
    genesis = rpc.call("getblockhash", [0])
    side = make_block(genesis, 1, 1_700_000_000, extra=b"\x11\xc5")
    submit("inconclusive", side)
    submit("inconclusive-resubmit", side)
    chain_view("after-side")

    # Disconnect the confirming tip. Its non-coinbase tx must return to the mempool.
    tip_hex = blocks[-1]
    tip_hash = rpc.call("getbestblockhash")
    rec("invalidate-tip", rpc.call("invalidateblock", [tip_hash]))
    chain_view("after-invalidate-tip")
    # Header whose parent is the invalidated tip. Core: RPC -25 bad-prevblk,
    # and the header is not added to the index.
    failed_parent = rpc.call("getblock", [tip_hash])
    if not isinstance(failed_parent, dict) or "time" not in failed_parent:
        raise RuntimeError(f"getblock {tip_hash} missing time: {failed_parent}")
    failed_header_block = make_block(
        tip_hash, 1, int(failed_parent["time"]) + 1, extra=b"\x31\xc5"
    )
    failed_header = failed_header_block[:160]
    rec("submitheader-failed-parent", rpc.call("submitheader", [failed_header]))
    rec(
        "submitheader-failed-parent:getblockheader",
        rpc.call("getblockheader", [header_hash(failed_header)]),
    )
    submit("duplicate-invalid-tip", tip_hex)
    rec("reconsider-tip", rpc.call("reconsiderblock", [tip_hash]))
    chain_view("after-reconsider-tip")

    # Block 100 and everything above it (101, 102) are failed. 102 is a
    # descendant, so a new block on 102 is the BLOCK_FAILED_CHILD case.
    h100 = rpc.call("getblockhash", [100])
    h102 = rpc.call("getbestblockhash")
    rec("invalidate-100", rpc.call("invalidateblock", [h100]))
    chain_view("after-invalidate-100")
    submit("duplicate-invalid-100", chain_block_hex(rpc, h100))
    submit("duplicate-invalid-descendant", chain_block_hex(rpc, h102))

    now = int(time.time()) + 10_000
    submit("bad-prevblk-child", make_block(h100, 1, now))
    submit("bad-prevblk-grandchild", make_block(h102, 1, now + 600))
    submit("bad-txnmrklroot-on-failed", mutated_block(h100, now + 1200))
    # The child that should become the tip is built only after reconsider.
    # nTime must clear MTP and stay inside MAX_FUTURE_BLOCK_TIME (7200s);
    # the parent's own timestamp + 1 does both. A clock-based stamp past
    # that window is "time-too-new" on both nodes and never extends the tip.
    parent_hdr = rpc.call("getblock", [h102])
    if not isinstance(parent_hdr, dict) or "time" not in parent_hdr:
        raise RuntimeError(f"getblock {h102} missing time: {parent_hdr}")
    valid_child = make_block(h102, 103, int(parent_hdr["time"]) + 1, extra=b"\x21\xc5")
    submit("bad-prevblk-valid-child", valid_child)
    rec("reconsider-100", rpc.call("reconsiderblock", [h100]))
    chain_view("after-reconsider-100")
    submit("accept-child", valid_child)
    chain_view("after-accept-child")
    return out


def chain_block_hex(rpc: Rpc, blockhash: str) -> str:
    blk = rpc.call("getblock", [blockhash, 0])
    if isinstance(blk, dict) and "_rpc_error" in blk:
        raise RuntimeError(f"getblock {blockhash}: {blk}")
    return blk


def norm_difficulty(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return value


def canonical_tips(tips):
    if not isinstance(tips, list):
        return tips
    return sorted(tips, key=lambda t: (t.get("height", -1), t.get("hash", ""), t.get("status", "")))


def canonical_mempool(pool):
    if not isinstance(pool, dict):
        return pool
    return {txid: pool[txid] for txid in sorted(pool)}


def floats_close(a, b) -> bool:
    fa, fb = norm_difficulty(a), norm_difficulty(b)
    if isinstance(fa, float) and isinstance(fb, float):
        return abs(fa - fb) <= max(1e-12, 1e-9 * max(abs(fa), abs(fb)))
    return a == b


def values_equal(name: str, a, b) -> bool:
    if name.endswith(":getchaintips"):
        return canonical_tips(a) == canonical_tips(b)
    if name.endswith(":getrawmempool"):
        return canonical_mempool(a) == canonical_mempool(b)
    if name.endswith(":getblockchaininfo"):
        if not isinstance(a, dict) or not isinstance(b, dict):
            return a == b
        if set(a) != set(b):
            return False
        for k, av in a.items():
            bv = b[k]
            if k in INFO_FLOATS:
                if not floats_close(av, bv):
                    return False
            elif av != bv:
                return False
        return True
    return a == b


def dump(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def compare(core: dict, rust: dict) -> list[dict]:
    rows = []
    by_r = {s["name"]: s["value"] for s in rust["steps"]}
    for step in core["steps"]:
        name = step["name"]
        cv = step["value"]
        rv = by_r.get(name, {"_missing": True})
        rows.append(
            {
                "name": name,
                "match": values_equal(name, cv, rv),
                "core": cv,
                "rustoshi": rv,
            }
        )
    return rows


def verify_tarball(tarball: str, sums: str) -> str:
    wanted = None
    base = os.path.basename(tarball)
    for line in open(sums):
        parts = line.split()
        if len(parts) >= 2 and parts[-1] == base:
            wanted = parts[0]
            break
    if wanted is None:
        raise SystemExit(f"{base} not listed in {sums}")
    h = hashlib.sha256()
    with open(tarball, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got != wanted:
        raise SystemExit(f"SHA256 mismatch for {base}\n  got  {got}\n  want {wanted}")
    return got


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--bitcoin-cli", required=True)
    ap.add_argument("--rustoshi", required=True)
    ap.add_argument("--tarball")
    ap.add_argument("--sha256sums")
    ap.add_argument("--work", default="/tmp/invalidated-submit-sweep")
    args = ap.parse_args()

    if args.tarball or args.sha256sums:
        if not (args.tarball and args.sha256sums):
            raise SystemExit("pass both --tarball and --sha256sums")
        digest = verify_tarball(args.tarball, args.sha256sums)
        print(f"SHA256 {os.path.basename(args.tarball)} {digest} OK")

    ver = subprocess.check_output([args.bitcoind, "-version"], text=True).splitlines()[0]
    print(f"bitcoind: {ver}")
    if "v31.1" not in ver:
        raise SystemExit(f"expected Bitcoin Core v31.1, got {ver}")

    if os.path.exists(args.work):
        shutil.rmtree(args.work)
    os.makedirs(args.work)

    print("mining shared chain on a throwaway Core...")
    built = build_chain(args.bitcoind, args.bitcoin_cli, args.work)
    print(f"chain blocks={len(built['blocks'])} spend={built['txid']}")

    nodes = []
    try:
        core = start_core(args.bitcoind, os.path.join(args.work, "core"), 18611, 18612)
        nodes.append(core)
        rust = start_rustoshi(args.rustoshi, os.path.join(args.work, "rustoshi"), 18621, 18622)
        nodes.append(rust)
        print("replaying on core...")
        mock_time = int(time.time())
        core_obs = snapshot(core.rpc, built["blocks"], mock_time)
        print("replaying on rustoshi...")
        rust_obs = snapshot(rust.rpc, built["blocks"], mock_time)
    finally:
        for n in nodes:
            n.stop()

    rows = compare(core_obs, rust_obs)
    matched = [r for r in rows if r["match"]]
    mismatched = [r for r in rows if not r["match"]]
    print(f"\nmatched {len(matched)}  mismatched {len(mismatched)}")
    for r in mismatched:
        print(f"\nMISMATCH {r['name']}")
        print(f"  core:     {dump(r['core'])[:2000]}")
        print(f"  rustoshi: {dump(r['rustoshi'])[:2000]}")
    report = os.path.join(args.work, "report.json")
    with open(report, "w") as f:
        json.dump({"matched": [r["name"] for r in matched], "rows": rows}, f)
    print(f"\nreport {report}")
    return 1 if mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
