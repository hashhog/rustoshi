#!/usr/bin/env python3
"""Regtest check: does rustoshi follow a tip that Bitcoin Core mines?

Two processes, P2P only: Bitcoin Core (the miner) and rustoshi. Core mines
blocks one at a time; rustoshi learns of each block only through Core's
announcement (headers, cmpctblock, or inv, whichever Core picks for that
peer). After every block rustoshi must report Core's best hash within
--follow-timeout seconds.

Mainnet 2026-10-30: rustoshi 30574478 matched Core at 973839 and then never
accepted the header for 973840 (blocks = headers = 973839 for 10+ min with 18
peers announcing it). Nothing in the Core regtest ratchet delivered a block by
P2P announcement only, so it passed.

Scenarios (each a fresh pair of datadirs):
  outbound   rustoshi --connect=Core   (rustoshi dials Core)
  inbound    Core addnode rustoshi     (Core dials rustoshi)
  mempool    as outbound, with wallet txs in every block, so cmpctblock
             reconstruction needs Core's mempool relay or getblocktxn

Usage: follow_tip_regtest.py --bin RUSTOSHI --bitcoind BITCOIND --workdir DIR
       [--only NAME] [--blocks N] [--follow-timeout S]
Exit 0 if every scenario PASSes, 1 otherwise. Python 3 standard library only.
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Proc:
    def __init__(self, name, argv, workdir, rpc_port, user, password, wallet=None):
        self.name = name
        self.rpc_port = rpc_port
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.wallet = wallet
        self.logpath = os.path.join(workdir, f"{name}.log")
        self.log = open(self.logpath, "wb")
        self.proc = subprocess.Popen(argv, stdout=self.log, stderr=subprocess.STDOUT,
                                     start_new_session=True)

    def call(self, method, params=None, timeout=30, wallet=None):
        path = f"/wallet/{wallet}" if wallet else "/"
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpc_port}{path}",
            data=json.dumps({"jsonrpc": "1.0", "id": 1, "method": method,
                             "params": params or []}).encode(),
            headers={"Authorization": f"Basic {self.auth}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read())
        if body.get("error"):
            raise RuntimeError(f"{self.name} {method}: {body['error']}")
        return body["result"]

    def wait_rpc(self, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited rc={self.proc.returncode}")
            try:
                self.call("getblockcount", timeout=5)
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError(f"{self.name} RPC never came up")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.close()


def start_core(bitcoind, workdir):
    d = os.path.join(workdir, "core")
    os.makedirs(d)
    p2p, rpc = free_port(), free_port()
    core = Proc("core", [bitcoind, "-regtest", f"-datadir={d}", f"-port={p2p}",
                         f"-bind=127.0.0.1:{p2p}", f"-rpcport={rpc}", "-rpcuser=u",
                         "-rpcpassword=p", "-listen=1", "-dnsseed=0", "-fixedseeds=0",
                         "-printtoconsole=1", "-debug=net", "-debug=cmpctblock",
                         "-fallbackfee=0.0002", "-txindex=0"],
                workdir, rpc, "u", "p")
    core.p2p = p2p
    core.wait_rpc()
    return core


def start_rustoshi(binary, workdir, connect=None, fresh=True):
    d = os.path.join(workdir, "rustoshi")
    os.makedirs(d, exist_ok=not fresh)
    p2p, rpc = free_port(), free_port()
    argv = [binary, "--network=regtest", f"--datadir={d}", f"--port={p2p}",
            f"--rpcbind=127.0.0.1:{rpc}", "--rpcuser=u", "--rpcpassword=p",
            "--metrics-port=0", "--nodnsseed", "--nofixedseeds", "--loglevel=debug"]
    if connect:
        argv.append(f"--connect={connect}")
    node = Proc("rustoshi" if fresh else "rustoshi-restart", argv, workdir, rpc, "u", "p")
    node.p2p = p2p
    node.wait_rpc()
    return node


MAGIC = bytes.fromhex("fabfb5da")


def _sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _frame(cmd, payload=b""):
    return (MAGIC + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload))
            + _sha256d(payload)[:4] + payload)


class LaggingPeer(threading.Thread):
    """A listening fake peer that claims a far-ahead start_height but answers
    every getheaders with an empty headers message: the shape of mainnet
    peer 2 on 2026-10-30 (a Knots node that kept answering rustoshi's locator
    with a stale batch, never with anything above rustoshi's tip)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.getheaders = 0
        self.stop_flag = False

    def run(self):
        self.srv.settimeout(0.5)
        while not self.stop_flag:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, s):
        buf = b""
        s.settimeout(0.5)
        while not self.stop_flag:
            try:
                d = s.recv(1 << 16)
            except socket.timeout:
                continue
            except OSError:
                return
            if not d:
                return
            buf += d
            while len(buf) >= 24:
                ln = struct.unpack("<I", buf[16:20])[0]
                if len(buf) < 24 + ln:
                    break
                cmd = buf[4:16].rstrip(b"\0").decode()
                payload = buf[24:24 + ln]
                buf = buf[24 + ln:]
                if cmd == "version":
                    addr = (struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff"
                            + bytes([127, 0, 0, 1]) + struct.pack(">H", 0))
                    ua = b"/lagging-peer:0/"
                    ver = (struct.pack("<iQq", 70016, 9, int(time.time())) + addr + addr
                           + struct.pack("<Q", 0x5eed) + bytes([len(ua)]) + ua
                           + struct.pack("<i", 1_000_000) + b"\x01")
                    s.sendall(_frame("version", ver) + _frame("verack"))
                elif cmd == "ping":
                    s.sendall(_frame("pong", payload))
                elif cmd == "getheaders":
                    self.getheaders += 1
                    s.sendall(_frame("headers", b"\x00"))

    def stop(self):
        self.stop_flag = True
        self.srv.close()


def run_restart(args, workdir):
    """A block is found while rustoshi is down. It restarts with a sync peer
    that never serves anything above its tip, then an honest peer (Core)
    connects. Core's initial getheaders goes to every peer once the header
    tip is within 24h of now (net_processing.cpp SendMessages, fSyncStarted),
    so Core learns the missed block from the honest peer at once."""
    os.makedirs(workdir)
    core = start_core(args.bitcoind, workdir)
    node = None
    lag = LaggingPeer()
    lag.start()
    try:
        core.call("createwallet", ["w"])
        addr = core.call("getnewaddress", wallet="w")
        core.call("generatetoaddress", [110, addr], timeout=120)
        node = start_rustoshi(args.bin, workdir, f"127.0.0.1:{core.p2p}")
        if wait_hash(node, core.call("getbestblockhash"), 120) is None:
            return False, "initial sync never reached Core's tip"
        node.stop()
        # The block rustoshi misses while it is down.
        missed = core.call("generatetoaddress", [1, addr])[0]
        node = start_rustoshi(args.bin, workdir, f"127.0.0.1:{lag.port}", fresh=False)
        end = time.time() + 30
        while lag.getheaders == 0 and time.time() < end:
            time.sleep(0.2)
        if lag.getheaders == 0:
            return False, "rustoshi never sent getheaders to the lagging peer"
        core.call("addnode", [f"127.0.0.1:{node.p2p}", "onetry"])
        end = time.time() + 30
        while not core.call("getpeerinfo") and time.time() < end:
            time.sleep(0.2)
        if not core.call("getpeerinfo"):
            return False, "Core never connected to rustoshi"
        took = wait_hash(node, missed, args.follow_timeout)
        if took is None:
            info = node.call("getblockchaininfo")
            return False, (f"block {missed[:16]} mined while rustoshi was down not "
                           f"followed in {args.follow_timeout}s after Core connected: "
                           f"rustoshi blocks={info['blocks']} headers={info['headers']} "
                           f"vs Core {core.call('getblockcount')} "
                           f"(lagging peer got {lag.getheaders} getheaders)")
        return True, f"missed block followed {took:.2f}s after Core connected"
    finally:
        lag.stop()
        if node:
            node.stop()
        core.stop()


def wait_hash(node, want, timeout):
    """Seconds until node's best hash == want, or None on timeout."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if node.call("getbestblockhash", timeout=10) == want:
                return time.time() - t0
        except Exception:
            pass
        time.sleep(0.2)
    return None


def run(args, name, workdir):
    os.makedirs(workdir)
    core = start_core(args.bitcoind, workdir)
    node = None
    try:
        core.call("createwallet", ["w"])
        addr = core.call("getnewaddress", wallet="w")
        # Some history before rustoshi joins, plus mature coinbases for txs.
        core.call("generatetoaddress", [110, addr], timeout=120)
        connect = f"127.0.0.1:{core.p2p}" if name in ("outbound", "mempool") else None
        node = start_rustoshi(args.bin, workdir, connect)
        if name == "inbound":
            core.call("addnode", [f"127.0.0.1:{node.p2p}", "onetry"])
        lag = wait_hash(node, core.call("getbestblockhash"), 120)
        if lag is None:
            return False, (f"initial sync never reached Core's tip "
                           f"(rustoshi {node.call('getblockcount')} vs Core 110)")
        times = []
        for i in range(args.blocks):
            if name == "mempool":
                for _ in range(3):
                    core.call("sendtoaddress", [addr, 0.1], wallet="w")
                time.sleep(1.0)  # let Core relay the txs before the block
            h = core.call("generatetoaddress", [1, addr])[0]
            took = wait_hash(node, h, args.follow_timeout)
            if took is None:
                info = node.call("getblockchaininfo")
                return False, (f"block {i + 1}/{args.blocks} ({h[:16]}) not followed in "
                               f"{args.follow_timeout}s: rustoshi blocks={info['blocks']} "
                               f"headers={info['headers']} vs Core "
                               f"{core.call('getblockcount')}")
            times.append(took)
        return True, (f"{args.blocks}/{args.blocks} blocks followed, "
                      f"max {max(times):.2f}s, mean {sum(times) / len(times):.2f}s")
    finally:
        if node:
            node.stop()
        core.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--only")
    ap.add_argument("--blocks", type=int, default=5)
    ap.add_argument("--follow-timeout", type=float, default=15.0)
    args = ap.parse_args()
    names = ["outbound", "inbound", "mempool", "restart_lagging_sync_peer"]
    if args.only:
        names = [args.only]
    ok_all = True
    for name in names:
        wd = os.path.join(args.workdir, name)
        try:
            if name == "restart_lagging_sync_peer":
                ok, detail = run_restart(args, wd)
            else:
                ok, detail = run(args, name, wd)
        except Exception as e:
            ok, detail = False, f"error: {e}"
        ok_all &= ok
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
