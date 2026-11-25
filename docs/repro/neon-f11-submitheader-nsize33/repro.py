#!/usr/bin/env python3
"""Neon audit finding 11: Core's SetCompact does not treat nSize 33/34 as an
overflow when the mantissa's high bytes are zero. nBits 0x21007fff is the
target 0x7fff << 240, which is below the regtest powLimit, so Core's
CheckProofOfWork passes and submitheader then refuses the header at the next
gate (bad-diffbits: regtest block 1 must use 0x207fffff).

The script starts a Core v31.1 regtest node and a rustoshi regtest node on
scratch datadirs with no peers and submits the same headers to both:
  case:    nBits 0x21007fff, hash <= 0x7fff << 240   (Core: bad-diffbits)
  control: nBits 0x2100ffff (target above powLimit)  (Core: high-hash)

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


def tx_ser_witness(inputs, outputs, witnesses, version=2, locktime=0):
    base = tx_ser(inputs, outputs, version, locktime)
    body = base[4:-4]
    wit = b""
    for stack in witnesses:
        wit += cs(len(stack)) + b"".join(cs(len(i)) + i for i in stack)
    return base[:4] + b"\x00\x01" + body + wit + base[-4:]


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


def header(prev_le, ts, bits):
    target_exp, mant = bits >> 24, bits & 0x7FFFFF
    target = mant << (8 * (target_exp - 3))
    nonce = 0
    while True:
        hdr = (4).to_bytes(4, "little") + prev_le + b"\x11" * 32 + ts.to_bytes(4, "little") + \
            bits.to_bytes(4, "little") + nonce.to_bytes(4, "little")
        if int.from_bytes(sha256d(hdr), "little") <= target:
            return hdr.hex()
        nonce += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--rustoshi", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    shutil.rmtree(a.workdir, ignore_errors=True)
    os.makedirs(a.workdir)
    cport, cp2p, rport, rp2p = free_port(), free_port(), free_port(), free_port()
    core_dir, rdir = os.path.join(a.workdir, "core"), os.path.join(a.workdir, "rustoshi")
    os.makedirs(core_dir)
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
        g = nodes[0].call("getblockheader", nodes[0].call("getblockhash", 0))
        prev, ts = bytes.fromhex(g["hash"])[::-1], g["time"] + 600
        cases = [("case    nBits 0x21007fff", header(prev, ts, 0x21007FFF)),
                 ("control nBits 0x2100ffff", header(prev, ts + 1, 0x2100FFFF))]
        print(f"# {a.label}")
        answers = {}
        for n in nodes:
            for label, hx in cases:
                try:
                    res = json.dumps(n.call("submitheader", hx))
                except RuntimeError as e:
                    res = "error: " + str(e.args[0].get("message"))
                answers.setdefault(label, []).append(res)
                print(f"{n.name:9s} {label}: submitheader -> {res}")
        for label, (c, r) in answers.items():
            print("RESULT:", label, "AGREE" if c == r else "DIFFER")
    finally:
        for n in nodes:
            n.stop()


if __name__ == "__main__":
    sys.exit(main())
