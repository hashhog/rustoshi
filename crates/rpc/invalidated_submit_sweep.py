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
  * getmempoolinfo and REST info `usage` for an empty pool, the matured
    spend, a 2-in/2-out, a parent+child chain, and a witness-heavy tx
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
import socket
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


def start_core(
    bitcoind: str,
    datadir: str,
    rpc_port: int,
    p2p_port: int,
    listen: bool = False,
    maxmempool_mb: int | None = None,
) -> Node:
    os.makedirs(datadir, exist_ok=True)
    log_path = os.path.join(datadir, "debug.log")
    proc = subprocess.Popen(
        [
            bitcoind,
            "-regtest",
            f"-datadir={datadir}",
            "-listen=1" if listen else "-listen=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            f"-port={p2p_port}",
            f"-rpcport={rpc_port}",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-fallbackfee=0.0002",
            "-rest",
        ]
        + ([f"-maxmempool={maxmempool_mb}"] if maxmempool_mb is not None else []),
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


def start_rustoshi(
    binary: str,
    datadir: str,
    rpc_port: int,
    p2p_port: int,
    maxmempool_mb: int | None = None,
) -> Node:
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
        ]
        + ([f"--maxmempool={maxmempool_mb}"] if maxmempool_mb is not None else []),
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

        def coinbase_txid(index: int) -> str:
            blk = json.loads(cli(bitcoin_cli, datadir, 18601, "getblock", hashes[index]))
            return blk["tx"][0]

        def sign(raw: str) -> str:
            signed = json.loads(
                cli(bitcoin_cli, datadir, 18601, "signrawtransactionwithwallet", raw)
            )
            if not signed.get("complete"):
                raise RuntimeError(f"sign failed: {signed}")
            return signed["hex"]

        addr2 = cli(bitcoin_cli, datadir, 18601, "getnewaddress")
        # Two mature coinbases (heights 2 and 3). Distinct outputs so
        # createrawtransaction accepts the pair. Fee 0.001 BTC.
        two_raw = cli(
            bitcoin_cli,
            datadir,
            18601,
            "createrawtransaction",
            json.dumps(
                [
                    {"txid": coinbase_txid(1), "vout": 0},
                    {"txid": coinbase_txid(2), "vout": 0},
                ]
            ),
            json.dumps([{addr: "49.99950000"}, {addr2: "49.99950000"}]),
        )
        two_hex = sign(two_raw)
        two_dec = json.loads(cli(bitcoin_cli, datadir, 18601, "decoderawtransaction", two_hex))

        # Parent fee 0.002 BTC, child fee 0.001 BTC, both P2WPKH. Parent
        # feerate stays above the child's, so Core keeps two chunks.
        parent_raw = cli(
            bitcoin_cli,
            datadir,
            18601,
            "createrawtransaction",
            json.dumps([{"txid": coinbase_txid(4), "vout": 0}]),
            json.dumps([{addr: "49.99800000"}]),
        )
        parent_hex = sign(parent_raw)
        parent_dec = json.loads(
            cli(bitcoin_cli, datadir, 18601, "decoderawtransaction", parent_hex)
        )
        parent_txid = parent_dec["txid"]
        # The builder's tip is only 102, so this coinbase is still immature
        # there and cannot be broadcast. Hand the parent output to the
        # signer instead; the replay nodes mine far enough first.
        parent_out = parent_dec["vout"][0]
        child_raw = cli(
            bitcoin_cli,
            datadir,
            18601,
            "createrawtransaction",
            json.dumps([{"txid": parent_txid, "vout": 0}]),
            json.dumps([{addr2: "49.99700000"}]),
        )
        child_signed = json.loads(
            cli(
                bitcoin_cli,
                datadir,
                18601,
                "signrawtransactionwithwallet",
                child_raw,
                json.dumps(
                    [
                        {
                            "txid": parent_txid,
                            "vout": 0,
                            "scriptPubKey": parent_out["scriptPubKey"]["hex"],
                            "amount": "49.99800000",
                        }
                    ]
                ),
            )
        )
        if not child_signed.get("complete"):
            raise RuntimeError(f"child sign failed: {child_signed}")
        child_hex = child_signed["hex"]

        # Funding pays a P2WSH of OP_DROP OP_DROP OP_TRUE. The spend's
        # witness is [80, 80, 3], which is standard (stack items ≤ 80).
        decoded_script = json.loads(cli(bitcoin_cli, datadir, 18601, "decodescript", "755175"))
        p2wsh_addr = decoded_script["segwit"]["address"]
        fund_raw = cli(
            bitcoin_cli,
            datadir,
            18601,
            "createrawtransaction",
            json.dumps([{"txid": coinbase_txid(3), "vout": 0}]),
            json.dumps([{p2wsh_addr: "49.99900000"}]),
        )
        fund_hex = sign(fund_raw)
        fund_dec = json.loads(cli(bitcoin_cli, datadir, 18601, "decoderawtransaction", fund_hex))
        heavy_hex = witness_heavy_spend(fund_dec["txid"], 4_999_900_000 - 100_000)
        heavy_dec = json.loads(cli(bitcoin_cli, datadir, 18601, "decoderawtransaction", heavy_hex))

        return {
            "blocks": blocks,
            "hashes": hashes,
            "tx_hex": tx_hex,
            "txid": txid,
            "wtxid": wtxid,
            "two_hex": two_hex,
            "two_txid": two_dec["txid"],
            "two_wtxid": two_dec["hash"],
            "parent_hex": parent_hex,
            "child_hex": child_hex,
            "fund_hex": fund_hex,
            "fund_txid": fund_dec["txid"],
            "fund_wtxid": fund_dec["hash"],
            "heavy_hex": heavy_hex,
            "heavy_txid": heavy_dec["txid"],
            "heavy_wtxid": heavy_dec["hash"],
        }
    finally:
        node.stop()
        shutil.rmtree(datadir, ignore_errors=True)


def witness_heavy_spend(funding_txid: str, value_out: int) -> str:
    """P2WSH spend of script `OP_DROP OP_DROP OP_TRUE` with two 80-byte items.

    The funding output must pay `SHA256(755175)`. No signature: the script
    pushes true after dropping both items.
    """
    txid_le = bytes.fromhex(funding_txid)[::-1]
    vin = txid_le + struct.pack("<I", 0) + compact_size(0) + struct.pack("<I", 0xFFFFFFFD)
    spk = b"\x00\x14" + (b"\x11" * 20)
    vout = struct.pack("<q", value_out) + compact_size(len(spk)) + spk
    items = [b"\x11" * 80, b"\x22" * 80, bytes.fromhex("755175")]
    witness = compact_size(len(items))
    for item in items:
        witness += compact_size(len(item)) + item
    raw = (
        struct.pack("<i", 2)
        + b"\x00\x01"
        + compact_size(1)
        + vin
        + compact_size(1)
        + vout
        + witness
        + struct.pack("<I", 0)
    )
    return raw.hex()


def header_hash(header_hex: str) -> str:
    return sha256d(bytes.fromhex(header_hex))[::-1].hex()


def block_time(rpc: Rpc, blockhash: str) -> int:
    hdr = rpc.call("getblock", [blockhash])
    if not isinstance(hdr, dict) or "time" not in hdr:
        raise RuntimeError(f"getblock {blockhash} missing time: {hdr}")
    return int(hdr["time"])


P2WSH_SCRIPT = bytes.fromhex("755175")
P2WSH_SPK = b"\x00\x20" + hashlib.sha256(P2WSH_SCRIPT).digest()
REGTEST_MAGIC = bytes.fromhex("fabfb5da")
# Inputs per spend, and how many such spends to push past -maxmempool=5.
PRESSURE_INPUTS = 800
PRESSURE_TXS = 14
PRESSURE_VALUE = 20_000


def fanout_block(prev_hex: str, height: int, timestamp: int, n_out: int, value_each: int, extra: bytes) -> tuple[str, str]:
    """Coinbase block whose outputs are P2WSH(OP_DROP OP_DROP OP_TRUE)."""
    script = script_num(height) + extra
    vin = b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF)
    vin += compact_size(len(script)) + script + struct.pack("<I", 0xFFFFFFFF)
    spk = P2WSH_SPK
    vout = b"".join(
        struct.pack("<q", value_each) + compact_size(len(spk)) + spk for _ in range(n_out)
    )
    tx = (
        struct.pack("<i", 2)
        + compact_size(1)
        + vin
        + compact_size(n_out)
        + vout
        + struct.pack("<I", 0)
    )
    merkle = sha256d(tx)
    prev = bytes.fromhex(prev_hex)[::-1]
    prefix = struct.pack("<i", 0x20000000) + prev + merkle + struct.pack("<II", timestamp, 0x207FFFFF)
    hdr = solve(prefix)
    return (hdr + compact_size(1) + tx).hex(), sha256d(tx)[::-1].hex()


def big_p2wsh_spend(outpoints: list[tuple[str, int]], fee: int, value_each: int) -> str:
    """Standard P2WSH spend: witness [80, 80, OP_DROP OP_DROP OP_TRUE]."""
    n = len(outpoints)
    pay = n * value_each - fee
    spk = b"\x00\x14" + (b"\x11" * 20)
    vin = b""
    for txid, vout in outpoints:
        vin += bytes.fromhex(txid)[::-1]
        vin += struct.pack("<I", vout) + compact_size(0) + struct.pack("<I", 0xFFFFFFFD)
    vout_bytes = struct.pack("<q", pay) + compact_size(len(spk)) + spk
    items = [b"\x11" * 80, b"\x22" * 80, P2WSH_SCRIPT]
    witness = b""
    for _ in range(n):
        witness += compact_size(len(items))
        for item in items:
            witness += compact_size(len(item)) + item
    raw = (
        struct.pack("<i", 2)
        + b"\x00\x01"
        + compact_size(n)
        + vin
        + compact_size(1)
        + vout_bytes
        + witness
        + struct.pack("<I", 0)
    )
    return raw.hex()


def block_subsidy(height: int) -> int:
    """Regtest subsidy: 50 BTC, halved every 150 blocks."""
    halvings = height // 150
    if halvings >= 64:
        return 0
    return (50 * 100_000_000) >> halvings


def mine_empty(rpc: Rpc, n: int, extra: bytes) -> None:
    for i in range(n):
        tip = rpc.call("getbestblockhash")
        info = rpc.call("getblock", [tip])
        height = int(info["height"]) + 1
        blk = make_block(
            tip,
            height,
            int(info["time"]) + 1,
            extra=extra + bytes([i & 0xFF]),
            value=block_subsidy(height),
        )
        result = rpc.call("submitblock", [blk])
        if result not in (None,):
            raise RuntimeError(f"empty block {i} rejected: {result}")


def mempool_pressure(rpc: Rpc, rec, mock_time: int, rest_base: str) -> None:
    """Fill past -maxmempool, then decay the rolling fee across one block.

    Both nodes are started with -maxmempool=5 (5_000_000 bytes). The spends
    are independent, so each is its own chunk: TrimToSize drops the cheapest
    ones. After a connected block, 12h+11s of mock time halves the bumped
    feerate when dynamic usage stays at or above half the limit.
    """
    tip = rpc.call("getbestblockhash")
    info = rpc.call("getblock", [tip])
    n_out = PRESSURE_INPUTS * PRESSURE_TXS
    blk, txid = fanout_block(
        tip,
        int(info["height"]) + 1,
        int(info["time"]) + 1,
        n_out,
        PRESSURE_VALUE,
        b"\x81\xc5",
    )
    result = rpc.call("submitblock", [blk])
    if result is not None:
        raise RuntimeError(f"fanout block rejected: {result}")
    # Coinbase maturity is 100. Mempool spend height is tip+1, so 99
    # descendants make the outputs spendable. Mine 100.
    mine_empty(rpc, 100, b"\x82")

    sent: list[str] = []
    for i in range(PRESSURE_TXS):
        outpoints = [(txid, v) for v in range(i * PRESSURE_INPUTS, (i + 1) * PRESSURE_INPUTS)]
        fee = 20_000 + i * 5_000
        raw = big_p2wsh_spend(outpoints, fee, PRESSURE_VALUE)
        accepted = rpc.call("sendrawtransaction", [raw])
        rec(f"pressure:send:{i}", accepted)
        if isinstance(accepted, str):
            sent.append(accepted)
    pool = rpc.call("getrawmempool", [False])
    if not isinstance(pool, list):
        raise RuntimeError(f"getrawmempool after pressure: {pool}")
    evicted = [txid for txid in sent if txid not in pool]
    if not evicted:
        info = rpc.call("getmempoolinfo")
        raise RuntimeError(f"pressure phase evicted nothing; mempoolinfo={info} sent={len(sent)}")
    rec("pressure:getrawmempool", pool)
    rec("pressure:getmempoolinfo", rpc.call("getmempoolinfo"))
    rec("pressure:rest-info", rest_get(rest_base, "/rest/mempool/info.json"))

    # Arm rolling-fee decay (Core removeForBlock stamps lastRollingFeeUpdate).
    tip = rpc.call("getbestblockhash")
    info = rpc.call("getblock", [tip])
    height = int(info["height"]) + 1
    blk = make_block(
        tip,
        height,
        int(info["time"]) + 1,
        extra=b"\x83\xc5",
        value=block_subsidy(height),
    )
    result = rpc.call("submitblock", [blk])
    if result is not None:
        raise RuntimeError(f"decay block rejected: {result}")
    later = mock_time + 43_200 + 11
    rec_clock = rpc.call("setmocktime", [later])
    if isinstance(rec_clock, dict) and "_rpc_error" in rec_clock:
        raise RuntimeError(f"setmocktime decay failed: {rec_clock}")
    rec("pressure-decay:getmempoolinfo", rpc.call("getmempoolinfo"))
    rec("pressure-decay:getrawmempool", rpc.call("getrawmempool", [False]))


def submit_heavier_headers(rpc: Rpc, rec) -> None:
    """Headers-only chain with more work than the active tip."""
    tip = rpc.call("getbestblockhash")
    info = rpc.call("getblock", [tip])
    h1 = make_block(tip, int(info["height"]) + 1, int(info["time"]) + 1, extra=b"\x91\xc5")
    rec("headers-only:submit:1", rpc.call("submitheader", [h1[:160]]))
    h1_hash = header_hash(h1[:160])
    h2 = make_block(h1_hash, int(info["height"]) + 2, int(info["time"]) + 2, extra=b"\x92\xc5")
    rec("headers-only:submit:2", rpc.call("submitheader", [h2[:160]]))
    rec("headers-only:getblockchaininfo", rpc.call("getblockchaininfo"))
    rec("headers-only:getchaintips", rpc.call("getchaintips"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("peer closed the connection")
        buf += chunk
    return buf


def _p2p_msg(command: str, payload: bytes = b"") -> bytes:
    cmd = command.encode().ljust(12, b"\x00")
    return REGTEST_MAGIC + cmd + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def _read_p2p(sock: socket.socket) -> tuple[str, bytes]:
    hdr = _recv_exact(sock, 24)
    if hdr[:4] != REGTEST_MAGIC:
        raise RuntimeError(f"bad magic {hdr[:4].hex()}")
    command = hdr[4:16].split(b"\x00", 1)[0].decode()
    length = struct.unpack("<I", hdr[16:20])[0]
    checksum = hdr[20:24]
    payload = _recv_exact(sock, length) if length else b""
    if sha256d(payload)[:4] != checksum:
        raise RuntimeError(f"bad checksum on {command}")
    return command, payload


def push_headers(host: str, port: int, headers: list[bytes], height: int) -> None:
    """Inbound-style handshake, then one `headers` message. Regtest only."""
    addr = struct.pack("<Q", 1) + b"\x00" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", port)
    ua = b"/sweep:0.0.1/"
    version = (
        struct.pack("<i", 70016)
        + struct.pack("<Q", 1)
        + struct.pack("<q", int(time.time()))
        + addr
        + addr
        + struct.pack("<Q", 0x1234_5678_90AB_CDEF)
        + compact_size(len(ua))
        + ua
        + struct.pack("<i", height)
        + b"\x01"
    )
    # One header per `headers` message. Core rejects a batch whose headers
    # do not form a single chain ("non-continuous headers sequence") before
    # it looks at proof-of-work or the failed-parent filter, so the valid
    # tip extension and the BLOCK_FAILED_VALID child cannot share a message.
    payloads = []
    for header in headers:
        if len(header) != 80:
            raise RuntimeError(f"header is {len(header)} bytes")
        payloads.append(compact_size(1) + header + compact_size(0))
    sock = socket.create_connection((host, port), timeout=5)
    try:
        sock.sendall(_p2p_msg("version", version))
        verack_sent = False
        deadline = time.time() + 5
        while time.time() < deadline:
            sock.settimeout(max(0.2, deadline - time.time()))
            command, body = _read_p2p(sock)
            if command == "version" and not verack_sent:
                sock.sendall(_p2p_msg("verack"))
                verack_sent = True
            elif command == "verack":
                break
            elif command == "ping":
                sock.sendall(_p2p_msg("pong", body))
        else:
            raise RuntimeError(f"no verack from {host}:{port}")
        for payload in payloads:
            sock.sendall(_p2p_msg("headers", payload))
        # Core disconnects the peer after the invalid header. That close is
        # the rejection, not a failed send.
        sock.settimeout(0.5)
        try:
            while True:
                command, body = _read_p2p(sock)
                if command == "ping":
                    sock.sendall(_p2p_msg("pong", body))
        except (socket.timeout, RuntimeError):
            pass
    finally:
        sock.close()


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

    def rec_usage(tag: str) -> None:
        rec(f"{tag}:getmempoolinfo", rpc.call("getmempoolinfo"))
        rec(f"{tag}:rest-info", rest_get(rest_base, "/rest/mempool/info.json"))

    if len(blocks) != 102:
        raise RuntimeError(f"expected 102 blocks (heights 1..102), got {len(blocks)}")

    # Fresh pool: Core reports usage 0 (no txns_randomized allocation yet).
    rec_usage("usage-empty")

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
    rec("tip100:getmempoolinfo", rpc.call("getmempoolinfo"))
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

    # The matured spend was admitted and removed (only ever one tx at a
    # time), so the pool is empty but txns_randomized still holds its
    # capacity. Then one shape at a time: confirm the single-tx shapes so
    # the parent+child measurement is not mixed with them. Confirming
    # blocks are deterministic and identical on both nodes; restart only
    # compares tips.
    rec_usage("usage-drained")

    def mine_one(name: str, tx_hex: str, txid: str, wtxid: str, height: int, extra: bytes) -> None:
        tip = rpc.call("getbestblockhash")
        if not isinstance(tip, str):
            raise RuntimeError(f"{name}: no tip before mining: {tip}")
        blk = block_spending(
            tip,
            height,
            block_time(rpc, tip) + 1,
            tx_hex,
            txid,
            wtxid,
            extra,
        )
        submit(name, blk)

    def must_send(name: str, tx_hex: str) -> None:
        result = rpc.call("sendrawtransaction", [tx_hex])
        rec(name, result)
        if not isinstance(result, str):
            raise RuntimeError(f"{name} rejected: {result}")

    must_send("usage-2in2out:send", spend["two_hex"])
    rec_usage("usage-2in2out")
    mine_one(
        "usage-2in2out:mine",
        spend["two_hex"],
        spend["two_txid"],
        spend["two_wtxid"],
        104,
        b"\x71\xc5",
    )

    must_send("usage-fund:send", spend["fund_hex"])
    mine_one(
        "usage-fund:mine",
        spend["fund_hex"],
        spend["fund_txid"],
        spend["fund_wtxid"],
        105,
        b"\x72\xc5",
    )
    must_send("usage-heavy:send", spend["heavy_hex"])
    rec_usage("usage-heavy")
    mine_one(
        "usage-heavy:mine",
        spend["heavy_hex"],
        spend["heavy_txid"],
        spend["heavy_wtxid"],
        106,
        b"\x73\xc5",
    )

    must_send("usage-chain:parent", spend["parent_hex"])
    must_send("usage-chain:child", spend["child_hex"])
    rec_usage("usage-chain")

    # -maxmempool=5 on both nodes. Independent max-standard spends fill past
    # the dynamic-usage limit; the cheapest chunks are evicted. A following
    # block plus 12h of mock time decays mempoolminfee. `optimal` is part of
    # the getmempoolinfo object (Core DoWork(0)).
    mempool_pressure(rpc, rec, mock_time, rest_base)
    # Heavier headers-only chain, persisted so a restart still reports it.
    submit_heavier_headers(rpc, rec)
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
    if name.endswith("rest-info") or name.endswith(":getmempoolinfo"):
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
        # -maxmempool=5 so TrimToSize / GetMinFee run on DynamicMemoryUsage.
        # Core listens so the post-restart header is delivered over P2P.
        core = start_core(
            args.bitcoind,
            os.path.join(args.work, "core"),
            18611,
            18612,
            listen=True,
            maxmempool_mb=5,
        )
        nodes.append(core)
        rust = start_rustoshi(
            args.rustoshi,
            os.path.join(args.work, "rustoshi"),
            18621,
            18622,
            maxmempool_mb=5,
        )
        nodes.append(rust)
        print("replaying on core...")
        mock_time = int(time.time())
        spend = {
            "hex": built["tx_hex"],
            "txid": built["txid"],
            "wtxid": built["wtxid"],
            "two_hex": built["two_hex"],
            "two_txid": built["two_txid"],
            "two_wtxid": built["two_wtxid"],
            "parent_hex": built["parent_hex"],
            "child_hex": built["child_hex"],
            "fund_hex": built["fund_hex"],
            "fund_txid": built["fund_txid"],
            "fund_wtxid": built["fund_wtxid"],
            "heavy_hex": built["heavy_hex"],
            "heavy_txid": built["heavy_txid"],
            "heavy_wtxid": built["heavy_wtxid"],
        }
        core_obs = snapshot(core.rpc, built["blocks"], mock_time, core.rest_base, spend)
        print("replaying on rustoshi...")
        rust_obs = snapshot(rust.rpc, built["blocks"], mock_time, rust.rest_base, spend)
        print("restarting both nodes on the same datadirs...")
        core.stop()
        core = start_core(
            args.bitcoind, core.datadir, 18611, 18612, listen=True, maxmempool_mb=5
        )
        nodes[0] = core
        rust.stop()
        rust = start_rustoshi(
            args.rustoshi, rust.datadir, 18621, 18622, maxmempool_mb=5
        )
        nodes[1] = rust
        for obs, node in ((core_obs, core), (rust_obs, rust)):
            for method in (
                "getbestblockhash",
                "getblockcount",
                "getchaintips",
                "getblockchaininfo",
            ):
                obs["steps"].append({"name": f"restart:{method}", "value": node.rpc.call(method)})

        # Header descending from the BLOCK_FAILED_VALID side tip, plus one
        # valid header on the active tip, both over P2P. Core rejects the
        # descendant (it is not stored). The valid header shows the message
        # was processed.
        tips = core.rpc.call("getchaintips")
        invalid = [t for t in tips if isinstance(t, dict) and t.get("status") == "invalid"]
        if not invalid:
            raise RuntimeError(f"no invalid chain tip to extend: {tips}")
        failed = max(invalid, key=lambda t: int(t["height"]))
        failed_info = core.rpc.call("getblockheader", [failed["hash"]])
        active = core.rpc.call("getbestblockhash")
        active_info = core.rpc.call("getblock", [active])
        bad_child = make_block(
            failed["hash"],
            int(failed["height"]) + 1,
            int(failed_info["time"]) + 1,
            extra=b"\xa1\xc5",
        )
        good = make_block(
            active,
            int(active_info["height"]) + 1,
            int(active_info["time"]) + 1,
            extra=b"\xa2\xc5",
        )
        bad_hash = header_hash(bad_child[:160])
        good_hash = header_hash(good[:160])
        headers = [bytes.fromhex(good[:160]), bytes.fromhex(bad_child[:160])]
        print("feeding headers over P2P...")
        push_headers("127.0.0.1", 18612, headers, int(active_info["height"]))
        push_headers("127.0.0.1", 18622, headers, int(active_info["height"]))
        deadline = time.time() + 10
        while time.time() < deadline:
            core_hdr = core.rpc.call("getblockheader", [good_hash])
            rust_hdr = rust.rpc.call("getblockheader", [good_hash])
            if isinstance(core_hdr, dict) and "hash" in core_hdr and isinstance(rust_hdr, dict) and "hash" in rust_hdr:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError(
                f"valid P2P header was not stored; core={core.rpc.call('getblockheader', [good_hash])} "
                f"rust={rust.rpc.call('getblockheader', [good_hash])}"
            )
        for obs, node in ((core_obs, core), (rust_obs, rust)):
            obs["steps"].append(
                {"name": "p2p-header:getchaintips", "value": node.rpc.call("getchaintips")}
            )
            obs["steps"].append(
                {
                    "name": "p2p-header:getblockheader-valid",
                    "value": node.rpc.call("getblockheader", [good_hash]),
                }
            )
            obs["steps"].append(
                {
                    "name": "p2p-header:getblockheader-failed-child",
                    "value": node.rpc.call("getblockheader", [bad_hash]),
                }
            )
            obs["steps"].append(
                {
                    "name": "p2p-header:getblockchaininfo",
                    "value": node.rpc.call("getblockchaininfo"),
                }
            )
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
