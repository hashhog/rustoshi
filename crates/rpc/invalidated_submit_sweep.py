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
  * coinbase maturity at tip 99 (reject) and tip 100 (accept), via
    testmempoolaccept, sendrawtransaction, and a mined block
  * REST /rest/mempool/contents.json and /rest/mempool/info.json
  * a heavier side branch whose tip fails ConnectBlock (bad-cb-amount),
    then the same getchaintips / getbestblockhash after a restart

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


def coinbase(height: int, extra: bytes = b"\x01\xc5", value: int = 50 * 100_000_000) -> bytes:
    script = script_num(height) + extra
    tx = struct.pack("<i", 2)
    tx += compact_size(1)
    tx += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF)
    tx += compact_size(len(script)) + script + struct.pack("<I", 0xFFFFFFFF)
    tx += compact_size(1)
    tx += struct.pack("<q", value) + compact_size(1) + b"\x51"
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


def make_block(
    prev_hex: str,
    cb_height: int,
    timestamp: int,
    extra: bytes = b"\x01\xc5",
    value: int = 50 * 100_000_000,
) -> str:
    tx = coinbase(cb_height, extra, value)
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


def merkle_root(leaves: list[bytes]) -> bytes:
    level = list(leaves)
    if not level:
        return b"\x00" * 32
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def coinbase_with_commitment(height: int, value: int, extra: bytes, commitment: bytes) -> tuple[bytes, bytes]:
    """Coinbase that commits to a witness merkle root.

    Returns (non-witness serialization for the txid, full serialization
    including the 32-byte witness nonce). The commitment output is
    OP_RETURN 0x24 aa21a9ed || SHA256d(witness_root || nonce).
    """
    script = script_num(height) + extra
    pay = b"\x51"
    commit = bytes([0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED]) + commitment
    vin = b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF)
    vin += compact_size(len(script)) + script + struct.pack("<I", 0xFFFFFFFF)
    vout = struct.pack("<q", value) + compact_size(len(pay)) + pay
    vout += struct.pack("<q", 0) + compact_size(len(commit)) + commit
    base = struct.pack("<i", 2) + compact_size(1) + vin + compact_size(2) + vout + struct.pack("<I", 0)
    witness = b"\x01\x20" + (b"\x00" * 32)
    full = (
        struct.pack("<i", 2)
        + b"\x00\x01"
        + compact_size(1)
        + vin
        + compact_size(2)
        + vout
        + witness
        + struct.pack("<I", 0)
    )
    return base, full


def block_spending(
    prev_hex: str,
    height: int,
    timestamp: int,
    spend_hex: str,
    txid_hex: str,
    wtxid_hex: str,
    extra: bytes,
) -> str:
    """Tip-extending block that pays a 50 BTC coinbase and includes `spend_hex`.

    The coinbase claims the subsidy only (fees may go unclaimed). The
    witness commitment uses a 32-zero nonce, matching BIP141.
    """
    txid = bytes.fromhex(txid_hex)[::-1]
    wtxid = bytes.fromhex(wtxid_hex)[::-1]
    witness_root = merkle_root([b"\x00" * 32, wtxid])
    commitment = sha256d(witness_root + (b"\x00" * 32))
    cb_base, cb_full = coinbase_with_commitment(height, 50 * 100_000_000, extra, commitment)
    root = merkle_root([sha256d(cb_base), txid])
    prev = bytes.fromhex(prev_hex)[::-1]
    prefix = struct.pack("<i", 0x20000000) + prev + root + struct.pack("<II", timestamp, 0x207FFFFF)
    hdr = solve(prefix)
    return (hdr + compact_size(2) + cb_full + bytes.fromhex(spend_hex)).hex()


def rest_get(base: str, path: str):
    req = urllib.request.Request(base + path)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return {"_http_error": e.code, "body": body[:500]}


def wait_rest(base: str, proc: subprocess.Popen, log_path: str, timeout: int = 30) -> None:
    deadline = time.time() + timeout
    last = ""
    url = base + "/rest/mempool/info.json"
    while time.time() < deadline:
        if proc.poll() is not None:
            tail = open(log_path).read()[-2000:]
            raise RuntimeError(f"node exited {proc.returncode} before REST came up\n{tail}")
        try:
            rest_get(base, "/rest/mempool/info.json")
            return
        except Exception as e:  # noqa: BLE001 — startup race
            last = str(e)
            time.sleep(0.25)
    tail = open(log_path).read()[-2000:] if os.path.exists(log_path) else ""
    raise RuntimeError(f"REST never came up at {url} ({last})\n{tail}")


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
    def __init__(
        self,
        name: str,
        proc: subprocess.Popen | None,
        rpc: Rpc,
        datadir: str,
        log_path: str,
        rest_base: str,
    ):
        self.name = name
        self.proc = proc
        self.rpc = rpc
        self.datadir = datadir
        self.log_path = log_path
        self.rest_base = rest_base

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
            "-rpcallowip=127.0.0.1",
            "-fallbackfee=0.0002",
            "-rest",
        ],
        stdout=open(log_path, "ab"),
        stderr=subprocess.STDOUT,
    )
    rpc = Rpc(
        f"http://127.0.0.1:{rpc_port}/",
        [os.path.join(datadir, "regtest", ".cookie")],
    )
    rest_base = f"http://127.0.0.1:{rpc_port}"
    core_log = os.path.join(datadir, "regtest", "debug.log")
    wait_rpc(rpc, proc, core_log)
    wait_rest(rest_base, proc, core_log)
    return Node("core", proc, rpc, datadir, log_path, rest_base)


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
            "--rest",
            f"--restbind=127.0.0.1:{rpc_port + 100}",
        ],
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
    )
    rpc = Rpc(
        f"http://127.0.0.1:{rpc_port}/",
        [os.path.join(datadir, ".cookie"), os.path.join(datadir, "regtest", ".cookie")],
    )
    rest_base = f"http://127.0.0.1:{rpc_port + 100}"
    wait_rpc(rpc, proc, log_path)
    wait_rest(rest_base, proc, log_path)
    return Node("rustoshi", proc, rpc, datadir, log_path, rest_base)


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
        decoded = json.loads(cli(bitcoin_cli, datadir, 18601, "decoderawtransaction", tx_hex))
        txid = decoded["txid"]
        wtxid = decoded["hash"]
        if txid == wtxid:
            raise RuntimeError("spend has no witness; the mined-block path needs a segwit commitment")
        # Broadcast so the confirming block actually includes the spend.
        sent = cli(bitcoin_cli, datadir, 18601, "sendrawtransaction", tx_hex)
        if sent != txid:
            raise RuntimeError(f"sendrawtransaction returned {sent}, want {txid}")
        conf = json.loads(cli(bitcoin_cli, datadir, 18601, "generatetoaddress", "1", addr))
        hashes.append(conf[0])
        blocks = [cli(bitcoin_cli, datadir, 18601, "getblock", h, "0") for h in hashes]
        return {
            "blocks": blocks,
            "hashes": hashes,
            "tx_hex": tx_hex,
            "txid": txid,
            "wtxid": wtxid,
        }
    finally:
        node.stop()
        shutil.rmtree(datadir, ignore_errors=True)


def header_hash(header_hex: str) -> str:
    return sha256d(bytes.fromhex(header_hex))[::-1].hex()


def block_time(rpc: Rpc, blockhash: str) -> int:
    hdr = rpc.call("getblock", [blockhash])
    if not isinstance(hdr, dict) or "time" not in hdr:
        raise RuntimeError(f"getblock {blockhash} missing time: {hdr}")
    return int(hdr["time"])


def snapshot(rpc: Rpc, blocks: list[str], mock_time: int, rest_base: str, spend: dict) -> dict:
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

    if len(blocks) != 102:
        raise RuntimeError(f"expected 102 blocks (heights 1..102), got {len(blocks)}")

    # Heights 1..99. A height-1 coinbase is still immature here: Core's
    # mempool nSpendHeight is tip+1 (age 99) and ConnectBlock's spend height
    # is the block height (100 - 1 = 99). Both must reject.
    for i, hx in enumerate(blocks[:99], start=1):
        submit(f"valid:{i}", hx)
    tip99 = rpc.call("getbestblockhash")
    rec("tip99:testmempoolaccept", rpc.call("testmempoolaccept", [[spend["hex"]]]))
    rec("tip99:sendrawtransaction", rpc.call("sendrawtransaction", [spend["hex"]]))
    premature = block_spending(
        tip99,
        100,
        block_time(rpc, tip99) + 1,
        spend["hex"],
        spend["txid"],
        spend["wtxid"],
        extra=b"\x51\xc5",
    )
    submit("tip99:premature-block", premature)

    # Height 100. Age is now 100 on both the mempool (tip+1) and a block
    # mined at height 101. Accept the spend, then diff REST while it sits
    # in the mempool.
    submit("valid:100", blocks[99])
    rec("tip100:testmempoolaccept", rpc.call("testmempoolaccept", [[spend["hex"]]]))
    rec("tip100:sendrawtransaction", rpc.call("sendrawtransaction", [spend["hex"]]))
    rec("tip100:rest-contents", rest_get(rest_base, "/rest/mempool/contents.json"))
    rec("tip100:rest-info", rest_get(rest_base, "/rest/mempool/info.json"))
    tip100 = rpc.call("getbestblockhash")
    mature = block_spending(
        tip100,
        101,
        block_time(rpc, tip100) + 1,
        spend["hex"],
        spend["txid"],
        spend["wtxid"],
        extra=b"\x52\xc5",
    )
    submit("tip100:mature-block", mature)
    mature_hash = header_hash(mature[:160])
    rec("tip100:mature-block:getbestblockhash", rpc.call("getbestblockhash"))
    # Drop the mature block so the shared canonical chain can continue.
    # The spend re-enters the mempool and block 102 confirms it again.
    rec("invalidate-mature-block", rpc.call("invalidateblock", [mature_hash]))

    for i, hx in enumerate(blocks[100:], start=101):
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

    # Heavier side branch whose tip fails ConnectBlock (coinbase pays 51 BTC).
    # The sibling has equal work, so it stays off the active chain; the child
    # has more work and is attempted. Core marks that child BLOCK_FAILED_VALID
    # and does not move the tip. A restart must still report the same tip.
    tip = rpc.call("getbestblockhash")
    tip_info = rpc.call("getblock", [tip])
    if not isinstance(tip_info, dict) or "previousblockhash" not in tip_info:
        raise RuntimeError(f"getblock {tip} missing previousblockhash: {tip_info}")
    sibling = make_block(
        tip_info["previousblockhash"],
        int(tip_info["height"]),
        int(tip_info["time"]) + 1,
        extra=b"\x61\xc5",
    )
    submit("failed-connect:sibling", sibling)
    sibling_hash = header_hash(sibling[:160])
    bad = make_block(
        sibling_hash,
        int(tip_info["height"]) + 1,
        int(tip_info["time"]) + 2,
        extra=b"\x62\xc5",
        value=51 * 100_000_000,
    )
    submit("failed-connect:bad-cb-amount", bad)
    chain_view("after-failed-connect")
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


# Fee rates and totals. Same 8-decimal JSON numbers on both sides, compared
# with a tolerance so a trailing-zero spelling cannot fail the diff.
INFO_FEE_FIELDS = {"total_fee", "mempoolminfee", "minrelaytxfee", "incrementalrelayfee"}


def dicts_equal(a, b, float_keys: set[str]) -> bool:
    if not isinstance(a, dict) or not isinstance(b, dict):
        return a == b
    if set(a) != set(b):
        return False
    for k, av in a.items():
        bv = b[k]
        if k in float_keys:
            if not floats_close(av, bv):
                return False
        elif av != bv:
            return False
    return True


def values_equal(name: str, a, b) -> bool:
    if name.endswith(":getchaintips"):
        return canonical_tips(a) == canonical_tips(b)
    if name.endswith(":getrawmempool") or name.endswith("rest-contents"):
        return canonical_mempool(a) == canonical_mempool(b)
    if name.endswith(":getblockchaininfo"):
        return dicts_equal(a, b, INFO_FLOATS)
    if name.endswith("rest-info"):
        return dicts_equal(a, b, INFO_FEE_FIELDS)
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
        spend = {"hex": built["tx_hex"], "txid": built["txid"], "wtxid": built["wtxid"]}
        core_obs = snapshot(core.rpc, built["blocks"], mock_time, core.rest_base, spend)
        print("replaying on rustoshi...")
        rust_obs = snapshot(rust.rpc, built["blocks"], mock_time, rust.rest_base, spend)
        print("restarting both nodes on the same datadirs...")
        core.stop()
        core = start_core(args.bitcoind, core.datadir, 18611, 18612)
        nodes[0] = core
        rust.stop()
        rust = start_rustoshi(args.rustoshi, rust.datadir, 18621, 18622)
        nodes[1] = rust
        for obs, node in ((core_obs, core), (rust_obs, rust)):
            for method in ("getbestblockhash", "getblockcount", "getchaintips"):
                obs["steps"].append({"name": f"restart:{method}", "value": node.rpc.call(method)})
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
