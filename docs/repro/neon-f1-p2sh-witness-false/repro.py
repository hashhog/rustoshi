#!/usr/bin/env python3
"""Neon audit finding 1: a P2SH-wrapped witness program whose program bytes
cast to false, spent with an empty witness, under block consensus.

Core v31.1 VerifyScript evaluates the redeemScript first and requires a true
top element (EVAL_FALSE otherwise) before it looks for a witness program.

The script starts a Core v31.1 regtest node and a rustoshi regtest node, each
on its own scratch datadir with no peers, and submits the same blocks to both:

  blocks 1..100  coinbase 1 pays two P2SH outputs:
                   out 0: redeemScript OP_1 <0x0001>  (true program: control)
                   out 1: redeemScript OP_1 <0x0000>  (zero program: the case)
  block 101      spends out 0 (control: both nodes must accept)
  block 102      spends out 1 (Core rejects; the question is rustoshi)

Usage: repro.py --bitcoind <v31.1 bitcoind> --rustoshi <rustoshi binary>
                --workdir <scratch dir> [--label <text>]
Only the Python standard library is used.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def cs(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def push(data):
    assert len(data) < 0x4C
    return bytes([len(data)]) + data


def script_num_push(n):
    """CScript() << n, as Core serialises the BIP-34 height."""
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    v = n.to_bytes((n.bit_length() + 7) // 8, "little")
    if v[-1] & 0x80:
        v += b"\x00"
    return push(v)


def tx_ser(inputs, outputs, version=2, locktime=0):
    out = version.to_bytes(4, "little") + cs(len(inputs))
    for txid, vout, script_sig in inputs:
        out += txid + vout.to_bytes(4, "little") + cs(len(script_sig)) + script_sig + b"\xff\xff\xff\xff"
    out += cs(len(outputs))
    for value, spk in outputs:
        out += value.to_bytes(8, "little") + cs(len(spk)) + spk
    return out + locktime.to_bytes(4, "little")


def coinbase(height, outputs):
    ss = script_num_push(height) + b"\x04neon"
    return tx_ser([(b"\x00" * 32, 0xFFFFFFFF, ss)], outputs, version=1)


def merkle(txids):
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def block(prev_hash_le, ts, txs):
    root = merkle([sha256d(t) for t in txs])
    target = 0x7FFFFF << (8 * (0x20 - 3))
    nonce = 0
    while True:
        hdr = (0x20000000).to_bytes(4, "little") + prev_hash_le + root + ts.to_bytes(4, "little") + \
            (0x207FFFFF).to_bytes(4, "little") + nonce.to_bytes(4, "little")
        h = sha256d(hdr)
        if int.from_bytes(h, "little") <= target:
            return (hdr + cs(len(txs)) + b"".join(txs)).hex(), h
        nonce += 1


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Node:
    def __init__(self, name, argv, rpcport):
        self.name, self.rpcport = name, rpcport
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 90
        while True:
            try:
                self.call("getblockcount")
                return
            except Exception:
                if time.time() > deadline or self.proc.poll() is not None:
                    raise RuntimeError(f"{name} did not start")
                time.sleep(0.5)

    def call(self, method, *params):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpcport}/",
            data=json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode(),
            headers={"Authorization": "Basic " + base64.b64encode(b"test:test").decode(),
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read())
        if body.get("error"):
            raise RuntimeError(body["error"])
        return body["result"]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(timeout=30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--rustoshi", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    shutil.rmtree(a.workdir, ignore_errors=True)
    os.makedirs(a.workdir)

    redeem_true = bytes([0x51, 0x02, 0x00, 0x01])
    redeem_zero = bytes([0x51, 0x02, 0x00, 0x00])
    p2sh = lambda r: bytes([0xA9, 0x14]) + hash160(r) + bytes([0x87])

    cport, cp2p = free_port(), free_port()
    core_dir = os.path.join(a.workdir, "core")
    os.makedirs(core_dir)
    rport, rp2p = free_port(), free_port()
    rdir = os.path.join(a.workdir, "rustoshi")
    os.makedirs(rdir)
    nodes = []
    try:
        nodes.append(Node("core", [a.bitcoind, "-regtest", f"-datadir={core_dir}", f"-rpcport={cport}",
                                   f"-port={cp2p}", "-listen=0", "-connect=0", "-rpcuser=test",
                                   "-rpcpassword=test", "-server=1", "-printtoconsole=0"], cport))
        nodes.append(Node("rustoshi", [a.rustoshi, "--network=regtest", f"--datadir={rdir}",
                                       f"--rpcbind=127.0.0.1:{rport}", "--rpcuser=test", "--rpcpassword=test",
                                       f"--port={rp2p}", "--nodnsseed", "--nofixedseeds",
                                       "--maxconnections=0", "--metrics-port=0"], rport))
        core = nodes[0]
        genesis = bytes.fromhex(core.call("getblockhash", 0))[::-1]
        base_ts = int(time.time()) - 110 * 60

        blocks = []
        prev = genesis
        cb1 = coinbase(1, [(25 * 10**8, p2sh(redeem_true)), (25 * 10**8, p2sh(redeem_zero))])
        cb1_txid = sha256d(cb1)
        for h in range(1, 101):
            txs = [cb1] if h == 1 else [coinbase(h, [(50 * 10**8, b"\x51")])]
            hx, prev = block(prev, base_ts + h * 60, txs)
            blocks.append(hx)

        def spend(vout, redeem):
            return tx_ser([(cb1_txid, vout, push(redeem))], [(25 * 10**8 - 10_000, b"\x51")])

        ctl_hex, ctl_hash = block(prev, base_ts + 101 * 60, [coinbase(101, [(50 * 10**8, b"\x51")]), spend(0, redeem_true)])
        case_hex, _ = block(ctl_hash, base_ts + 102 * 60, [coinbase(102, [(50 * 10**8, b"\x51")]), spend(1, redeem_zero)])

        print(f"# {a.label}")
        for n in nodes:
            for hx in blocks:
                r = n.call("submitblock", hx)
                if r is not None:
                    raise RuntimeError(f"{n.name} refused setup block: {r}")
            ctl = n.call("submitblock", ctl_hex)
            case = n.call("submitblock", case_hex)
            print(f"{n.name:9s} control block 101 (OP_1 <0x0001>): {json.dumps(ctl)}")
            print(f"{n.name:9s} case    block 102 (OP_1 <0x0000>): {json.dumps(case)}")
            print(f"{n.name:9s} getblockcount: {n.call('getblockcount')}")
        heights = [n.call("getblockcount") for n in nodes]
        print("RESULT:", "AGREE" if heights[0] == heights[1] else "SPLIT", f"core={heights[0]} rustoshi={heights[1]}")
    finally:
        for n in nodes:
            n.stop()


if __name__ == "__main__":
    sys.exit(main())
