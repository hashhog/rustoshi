#!/usr/bin/env python3
"""Regtest sweep: rustoshi `submitpackage` vs Bitcoin Core v31.1.

Offline. No peers. Three packages on a shared chain, then
invalidateblock/reconsiderblock of the tip.

  1. valid CPFP (1-parent-1-child, parent below min relay)
  2. parent pays its own fee; child signature is a non-empty but invalid
     ECDSA sig (NULLFAIL)
  3. parent signature is invalid; child spends that parent

Core v31.1 (`validation.cpp` ProcessNewPackage / AcceptPackage /
PolicyScriptChecks + ConsensusScriptChecks, `rpc/mempool.cpp` submitpackage)
rejects (2) and (3) with
`mempool-script-verify-flag-failed (Signature must be zero for failed
CHECK(MULTI)SIG operation), input 0 of <txid> (wtxid <wtxid>), spending
<prev>:<n>` and `package_msg` `transaction failed`. A parent that was
individually valid stays in the mempool; a child of a rejected parent is
`bad-txns-inputs-missingorspent`.

rustoshi regtest builds the mempool with `verify_scripts = false`
(`mempool_config_for_network`). There is no CLI flag to flip it.
`submitpackage` passes `AtmpOptions { force_script_checks: true }`.

Usage:
  BITCOIND=... BITCOIN_CLI=... RUSTOSHI=target/debug/rustoshi \\
    CORE_RPC_PORT=18445 RUST_RPC_PORT=18443 \\
    CORE_P2P_PORT=18446 RUST_P2P_PORT=18447 \\
    python3 crates/rpc/tests/submitpackage_script_sweep.py

Port defaults match a single local regtest pair. Set the four variables
when another job already holds those ports.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path

BITCOIND = os.environ.get(
    "BITCOIND", "/tmp/bitcoincore/bitcoin-31.1/bin/bitcoind"
)
BITCOIN_CLI = os.environ.get(
    "BITCOIN_CLI", "/tmp/bitcoincore/bitcoin-31.1/bin/bitcoin-cli"
)
RUSTOSHI = os.environ.get("RUSTOSHI", "target/debug/rustoshi")
WORKDIR = Path(os.environ.get("SWEEP_WORKDIR", "/tmp/submitpackage-sweep"))


def _env_port(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise SystemExit(f"FATAL: {name}={raw} is not an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit(f"FATAL: {name}={port} is out of range")
    return port


CORE_RPC_PORT = _env_port("CORE_RPC_PORT", 18445)
RUST_RPC_PORT = _env_port("RUST_RPC_PORT", 18443)
CORE_P2P_PORT = _env_port("CORE_P2P_PORT", 18446)
RUST_P2P_PORT = _env_port("RUST_P2P_PORT", 18447)
CHAIN_BLOCKS = 110


def log(msg: str) -> None:
    print(msg, flush=True)


def die(msg: str) -> None:
    log(f"FATAL: {msg}")
    sys.exit(2)


class Node:
    def __init__(self, name: str, proc: subprocess.Popen | None = None):
        self.name = name
        self.proc = proc

    def rpc(self, method: str, params: list | None = None):
        raise NotImplementedError


class CoreNode(Node):
    def __init__(self, datadir: Path):
        super().__init__("core")
        self.datadir = datadir

    def cli(self, *args: str) -> str:
        cmd = [
            BITCOIN_CLI,
            "-regtest",
            f"-datadir={self.datadir}",
            f"-rpcport={CORE_RPC_PORT}",
            *args,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(
                f"bitcoin-cli {' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}"
            )
        return r.stdout.strip()

    def cli_json(self, *args: str):
        # bitcoin-cli prints a top-level string result bare (no JSON quotes)
        # and everything else as JSON.
        out = self.cli(*args)
        if out == "" or out == "null":
            return None
        try:
            return json.loads(out, parse_float=Decimal)
        except json.JSONDecodeError:
            return out

    def _post(self, method: str, params: list | None = None) -> dict:
        # HTTP, not bitcoin-cli. A package over MAX_PACKAGE_WEIGHT is >128KiB
        # of hex, which this environment rejects as E2BIG on exec.
        cookie_path = self.datadir / "regtest" / ".cookie"
        user, _, secret = cookie_path.read_text().strip().partition(":")
        token = base64.b64encode(f"{user}:{secret}".encode()).decode()
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params or []}
        ).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{CORE_RPC_PORT}/",
            data=body,
            headers={
                "Authorization": f"Basic {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode(), parse_float=Decimal)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            try:
                return json.loads(detail, parse_float=Decimal)
            except json.JSONDecodeError as err:
                raise RuntimeError(
                    f"bitcoind {method} HTTP {e.code}: {detail}"
                ) from err

    def rpc(self, method: str, params: list | None = None):
        payload = self._post(method, params)
        if payload.get("error"):
            raise RuntimeError(f"bitcoind {method}: {payload['error']}")
        return payload.get("result")

    def rpc_outcome(self, method: str, params: list | None = None):
        """Result JSON, or Core's JSONRPCError code and message."""
        payload = self._post(method, params)
        if payload.get("error"):
            err = payload["error"]
            return {
                "ok": False,
                "code": err.get("code"),
                "message": err.get("message"),
            }
        return {"ok": True, "result": payload.get("result")}

    def wallet_outcome(self, method: str, params: list | None = None):
        """Wallet RPC on /wallet/sweep. Root `/` has no wallet selected."""
        cookie_path = self.datadir / "regtest" / ".cookie"
        user, _, secret = cookie_path.read_text().strip().partition(":")
        token = base64.b64encode(f"{user}:{secret}".encode()).decode()
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params or []}
        ).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{CORE_RPC_PORT}/wallet/sweep",
            data=body,
            headers={
                "Authorization": f"Basic {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read().decode(), parse_float=Decimal)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            try:
                payload = json.loads(detail, parse_float=Decimal)
            except json.JSONDecodeError:
                return {"ok": False, "code": None, "message": detail}
        if payload.get("error"):
            err = payload["error"]
            return {
                "ok": False,
                "code": err.get("code"),
                "message": err.get("message"),
            }
        return {"ok": True, "result": payload.get("result")}


class RustNode(Node):
    def __init__(self, url: str, cookie: str):
        super().__init__("rustoshi")
        self.url = url
        user, _, secret = cookie.partition(":")
        token = base64.b64encode(f"{user}:{secret}".encode()).decode()
        self.auth = f"Basic {token}"

    def rpc(self, method: str, params: list | None = None):
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params or []}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Authorization": self.auth,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read().decode(), parse_float=Decimal)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            raise RuntimeError(f"rustoshi {method} HTTP {e.code}: {detail}") from e
        if payload.get("error"):
            err = payload["error"]
            raise RuntimeError(f"rustoshi {method}: {err}")
        return payload.get("result")

    def rpc_outcome(self, method: str, params: list | None = None):
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params or []}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Authorization": self.auth,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read().decode(), parse_float=Decimal)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            try:
                payload = json.loads(detail)
            except json.JSONDecodeError:
                return {"ok": False, "code": None, "message": detail}
        if payload.get("error"):
            err = payload["error"]
            return {
                "ok": False,
                "code": err.get("code"),
                "message": err.get("message"),
            }
        return {"ok": True, "result": payload.get("result")}


def wait_rpc(node: Node, seconds: int = 60) -> None:
    deadline = time.time() + seconds
    last = "not started"
    while time.time() < deadline:
        try:
            node.rpc("getblockcount")
            return
        except Exception as e:  # noqa: BLE001
            last = str(e)
            time.sleep(0.25)
    die(f"{node.name} RPC did not come up: {last}")


def start_core(datadir: Path, *extra: str) -> None:
    datadir.mkdir(parents=True, exist_ok=True)
    cmd = [
        BITCOIND,
        "-regtest",
        f"-datadir={datadir}",
        "-listen=0",
        "-dnsseed=0",
        "-fixedseeds=0",
        f"-port={CORE_P2P_PORT}",
        f"-rpcport={CORE_RPC_PORT}",
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
        # A later restart (acceptnonstdtxn) must not reload the mempool this
        # process saves on shutdown.
        "-persistmempool=0",
        *extra,
        "-daemon",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"bitcoind failed to start: {r.stderr or r.stdout}")


def stop_core(datadir: Path) -> None:
    subprocess.run(
        [
            BITCOIN_CLI,
            "-regtest",
            f"-datadir={datadir}",
            f"-rpcport={CORE_RPC_PORT}",
            "stop",
        ],
        capture_output=True,
        text=True,
    )
    # Wait until the process releases the datadir.
    for _ in range(80):
        if not (datadir / "regtest" / "bitcoind.pid").exists():
            return
        time.sleep(0.25)


def start_rustoshi(datadir: Path, log_path: Path, *extra: str) -> subprocess.Popen:
    datadir.mkdir(parents=True, exist_ok=True)
    log_f = open(log_path, "w")
    cmd = [
        RUSTOSHI,
        "--network",
        "regtest",
        "--datadir",
        str(datadir),
        "--rpcbind",
        f"127.0.0.1:{RUST_RPC_PORT}",
        "--maxconnections",
        "0",
        "--nodnsseed",
        "--nofixedseeds",
        "--port",
        str(RUST_P2P_PORT),
        *extra,
    ]
    proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT)
    return proc


def stop_rustoshi(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def btc(sats: int) -> str:
    return f"{Decimal(sats) / Decimal(100_000_000):.8f}"


def sats_of(amount) -> int:
    return int((Decimal(str(amount)) * Decimal(100_000_000)).to_integral_value())


def with_version(raw_hex: str, version: int) -> str:
    raw = bytearray.fromhex(raw_hex)
    raw[0:4] = (version & 0xFFFFFFFF).to_bytes(4, "little")
    return raw.hex()


def corrupt_witness_sig(raw_hex: str, sig_hex: str) -> str:
    """Flip the low bit of the last byte of DER r. Stays strict-DER so
    CHECKSIG fails and NULLFAIL fires (Core SCRIPT_ERR_SIG_NULLFAIL)."""
    sig = bytes.fromhex(sig_hex)
    if not sig or sig[0] != 0x30:
        die(f"witness item is not DER: {sig_hex}")
    # 30 len 02 rlen r ...
    if sig[2] != 0x02:
        die(f"DER r marker missing: {sig_hex}")
    rlen = sig[3]
    r_last = 4 + rlen - 1
    flipped = bytearray(sig)
    flipped[r_last] ^= 0x01
    new_sig = flipped.hex()
    if sig_hex not in raw_hex:
        die("signature bytes not found in raw tx")
    return raw_hex.replace(sig_hex, new_sig, 1)


def make_signed(
    core: CoreNode,
    prev_txid: str,
    prev_vout: int,
    prev_sats: int,
    prev_spk: str,
    fee_sats: int,
    dest: str,
) -> dict:
    out_sats = prev_sats - fee_sats
    if out_sats <= 0:
        die(f"fee {fee_sats} exceeds input {prev_sats}")
    raw = core.cli(
        "createrawtransaction",
        json.dumps([{"txid": prev_txid, "vout": prev_vout}]),
        json.dumps([{dest: btc(out_sats)}]),
    )
    # Descriptor wallets in Core v31 have no dumpprivkey. The wallet holds
    # the key for `dest`, including an output of a tx that is not yet
    # broadcast, as long as the prevout is supplied.
    signed = core.cli_json(
        "-rpcwallet=sweep",
        "signrawtransactionwithwallet",
        raw,
        json.dumps(
            [
                {
                    "txid": prev_txid,
                    "vout": prev_vout,
                    "scriptPubKey": prev_spk,
                    "amount": btc(prev_sats),
                }
            ]
        ),
    )
    if not signed.get("complete"):
        die(f"signrawtransactionwithwallet incomplete: {signed}")
    decoded = core.cli_json("decoderawtransaction", signed["hex"])
    witness = decoded["vin"][0].get("txinwitness") or []
    return {
        "hex": signed["hex"],
        "txid": decoded["txid"],
        "wtxid": decoded["hash"],
        "vsize": int(decoded["vsize"]),
        "witness": witness,
        "out_sats": out_sats,
        "spk": decoded["vout"][0]["scriptPubKey"]["hex"],
    }


def _num(v):
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, Decimal)):
        return Decimal(v)
    return None


def compare_json(core, rust, path: str) -> list[dict]:
    """Entire JSON value: key set, key order, and values. No ignored extras."""
    mismatches = []

    def add(field: str, c, r):
        mismatches.append(
            {"field": field, "core": c, "rustoshi": r, "out_of_scope": None}
        )

    cn, rn = _num(core), _num(rust)
    if cn is not None and rn is not None:
        if cn != rn:
            add(path, core, rust)
        return mismatches

    if isinstance(core, dict) or isinstance(rust, dict):
        if not isinstance(core, dict) or not isinstance(rust, dict):
            add(path, core, rust)
            return mismatches
        ck, rk = list(core), list(rust)
        if ck != rk:
            add(f"{path} keys", ck, rk)
        for key in ck:
            if key in rust:
                mismatches.extend(compare_json(core[key], rust[key], f"{path}.{key}"))
        return mismatches

    if isinstance(core, list) or isinstance(rust, list):
        if not isinstance(core, list) or not isinstance(rust, list):
            add(path, core, rust)
            return mismatches
        if len(core) != len(rust):
            add(f"{path} len", len(core), len(rust))
        for i, (c, r) in enumerate(zip(core, rust)):
            mismatches.extend(compare_json(c, r, f"{path}[{i}]"))
        return mismatches

    if core != rust:
        add(path, core, rust)
    return mismatches


def compare_submit(core_res: dict, rust_res: dict) -> list[dict]:
    return compare_json(core_res, rust_res, "submitpackage")


def compare_outcome(core_out: dict, rust_out: dict, path: str) -> list[dict]:
    """RPC error (code + message) or the entire result JSON."""
    if core_out.get("ok") != rust_out.get("ok"):
        return [
            {
                "field": f"{path} ok",
                "core": core_out,
                "rustoshi": rust_out,
                "out_of_scope": None,
            }
        ]
    if not core_out.get("ok"):
        c = {"code": core_out.get("code"), "message": core_out.get("message")}
        r = {"code": rust_out.get("code"), "message": rust_out.get("message")}
        if c != r:
            return [
                {
                    "field": path,
                    "core": c,
                    "rustoshi": r,
                    "out_of_scope": None,
                }
            ]
        return []
    return compare_json(core_out.get("result"), rust_out.get("result"), path)


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def raw_tx(
    inputs: list[tuple[bytes, int, bytes]],
    outputs: list[tuple[int, bytes]],
    version: int = 2,
    locktime: int = 0,
) -> bytes:
    """Non-witness tx. `inputs` are (prevout txid in internal order, vout, scriptSig)."""
    raw = (version & 0xFFFFFFFF).to_bytes(4, "little")
    raw += _compact_size(len(inputs))
    for txid_le, vout, script in inputs:
        raw += txid_le
        raw += int(vout).to_bytes(4, "little")
        raw += _compact_size(len(script)) + script
        raw += (0xFFFFFFFF).to_bytes(4, "little")
    raw += _compact_size(len(outputs))
    for value, spk in outputs:
        raw += int(value).to_bytes(8, "little")
        raw += _compact_size(len(spk)) + spk
    raw += (locktime & 0xFFFFFFFF).to_bytes(4, "little")
    return raw


def txid_internal(raw: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def fake_spend(prev_byte: int, script_sig: bytes = b"", n_outputs: int = 1, value: int = 1000) -> bytes:
    prev = bytes([prev_byte]) * 32
    return raw_tx([(prev, 0, script_sig)], [(value, b"")] * n_outputs)


def mempool_txids(node: Node) -> list[str]:
    raw = node.rpc("getrawmempool", [False])
    if isinstance(raw, dict):
        return sorted(raw.keys())
    return sorted(raw or [])


def main() -> int:
    if not Path(BITCOIND).exists():
        die(f"bitcoind missing: {BITCOIND}")
    if not Path(RUSTOSHI).exists():
        die(f"rustoshi missing: {RUSTOSHI}")

    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    core_dir = WORKDIR / "core"
    rust_dir = WORKDIR / "rustoshi"
    core_dir.mkdir(parents=True)
    rust_dir.mkdir(parents=True)

    log(f"bitcoind: {subprocess.check_output([BITCOIND, '-version'], text=True).splitlines()[0]}")
    log("starting bitcoind (regtest, -listen=0 -dnsseed=0 -fixedseeds=0)")
    start_core(core_dir)
    core = CoreNode(core_dir)
    wait_rpc(core)
    core.cli("createwallet", "sweep")
    dest = core.cli_json("-rpcwallet=sweep", "getnewaddress", "", "bech32")
    info = core.cli_json("-rpcwallet=sweep", "getaddressinfo", dest)
    spk = info["scriptPubKey"]
    log(f"mining {CHAIN_BLOCKS} regtest blocks to {dest}")
    core.cli("-rpcwallet=sweep", "generatetoaddress", str(CHAIN_BLOCKS), dest)
    height = core.rpc("getblockcount")
    tip = core.rpc("getbestblockhash")
    genesis = core.rpc("getblockhash", [0])
    log(f"core height={height} tip={tip} genesis={genesis}")

    utxos = core.cli_json("-rpcwallet=sweep", "listunspent", "100", "9999999")
    utxos = [u for u in utxos if u.get("spendable")]
    if len(utxos) < 10:
        die(f"need 10 mature coinbases, have {len(utxos)}")
    utxos = utxos[:10]
    for u in utxos:
        log(f"utxo {u['txid']}:{u['vout']} {u['amount']} conf={u['confirmations']}")

    log(
        "starting rustoshi (--maxconnections 0 --nodnsseed --nofixedseeds, "
        f"--port {RUST_P2P_PORT}). --listen is a switch that cannot be set false "
        "(default true); maxconnections 0 is the offline gate"
    )
    rust_log = WORKDIR / "rustoshi.log"
    rust_proc = start_rustoshi(rust_dir, rust_log)
    cookie_path = rust_dir / ".cookie"
    deadline = time.time() + 60
    while time.time() < deadline and not cookie_path.exists():
        if rust_proc.poll() is not None:
            die(f"rustoshi exited {rust_proc.returncode}: {rust_log.read_text()[-2000:]}")
        time.sleep(0.25)
    if not cookie_path.exists():
        die(f"no cookie file; log:\n{rust_log.read_text()[-2000:]}")
    rust = RustNode(f"http://127.0.0.1:{RUST_RPC_PORT}", cookie_path.read_text().strip())
    wait_rpc(rust, 90)
    rust_genesis = rust.rpc("getblockhash", [0])
    log(f"rustoshi genesis={rust_genesis}")
    if rust_genesis != genesis:
        die("genesis mismatch")

    for h in range(1, CHAIN_BLOCKS + 1):
        bh = core.rpc("getblockhash", [h])
        raw = core.cli_json("getblock", bh, "0")
        result = rust.rpc("submitblock", [raw])
        if result not in (None, ""):
            die(f"submitblock height {h} ({bh}): {result}")
        if h % 20 == 0:
            log(f"  submitted through height {h}")
    rust_height = rust.rpc("getblockcount")
    rust_tip = rust.rpc("getbestblockhash")
    log(f"rustoshi height={rust_height} tip={rust_tip}")
    if rust_height != height or rust_tip != tip:
        die(f"chain diverged before packages: core {height}/{tip} rustoshi {rust_height}/{rust_tip}")

    # Script-verification setting. No CLI switch; regtest mempool config is
    # verify_scripts=false. submitpackage forces the checks.
    log(
        "script verification: regtest MempoolConfig.verify_scripts=false "
        "(mempool_config_for_network); no CLI flag; submitpackage "
        "AtmpOptions.force_script_checks=true"
    )

    cases = []

    def run_case(name: str, parent_hex: str, child_hex: str, parent_txid: str, child_txid: str):
        log(f"=== {name} ===")
        before_c = set(mempool_txids(core))
        before_r = set(mempool_txids(rust))
        c_tma = core.rpc("testmempoolaccept", [[parent_hex, child_hex]])
        r_tma = rust.rpc("testmempoolaccept", [[parent_hex, child_hex]])
        log("core testmempoolaccept: " + json.dumps(c_tma, sort_keys=True, default=str))
        log("rustoshi testmempoolaccept: " + json.dumps(r_tma, sort_keys=True, default=str))
        tma_mismatches = compare_json(c_tma, r_tma, "testmempoolaccept")
        for m in tma_mismatches:
            log(f"  MISMATCH {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
        c_res = core.rpc("submitpackage", [[parent_hex, child_hex]])
        r_res = rust.rpc("submitpackage", [[parent_hex, child_hex]])
        log("core submitpackage: " + json.dumps(c_res, sort_keys=True, default=str))
        log("rustoshi submitpackage: " + json.dumps(r_res, sort_keys=True, default=str))
        mismatches = tma_mismatches + compare_submit(c_res, r_res)
        after_c = mempool_txids(core)
        after_r = mempool_txids(rust)
        if after_c != after_r:
            mismatches.append(
                {
                    "field": "getrawmempool",
                    "core": after_c,
                    "rustoshi": after_r,
                    "out_of_scope": None,
                }
            )
        # Membership of this package's txids, called out even when the full
        # mempool lists match.
        for label, txid in (("parent", parent_txid), ("child", child_txid)):
            c_in = txid in after_c
            r_in = txid in after_r
            log(f"  {label} {txid} in mempool core={c_in} rustoshi={r_in}")
            if c_in != r_in:
                mismatches.append(
                    {
                        "field": f"mempool_contains_{label}",
                        "core": c_in,
                        "rustoshi": r_in,
                        "out_of_scope": None,
                    }
                )
            if c_in and r_in:
                c_entry = core.rpc("getmempoolentry", [txid])
                r_entry = rust.rpc("getmempoolentry", [txid])
                c_unb = c_entry.get("unbroadcast") if isinstance(c_entry, dict) else None
                r_unb = r_entry.get("unbroadcast") if isinstance(r_entry, dict) else None
                log(f"  {label} unbroadcast core={c_unb} rustoshi={r_unb}")
                if c_unb != r_unb:
                    mismatches.append(
                        {
                            "field": f"unbroadcast_{label}",
                            "core": c_unb,
                            "rustoshi": r_unb,
                            "out_of_scope": None,
                        }
                    )
        added_c = sorted(set(after_c) - before_c)
        added_r = sorted(set(after_r) - before_r)
        if added_c != added_r:
            mismatches.append(
                {
                    "field": "mempool_added",
                    "core": added_c,
                    "rustoshi": added_r,
                    "out_of_scope": None,
                }
            )
        for m in mismatches:
            tag = "OUT_OF_SCOPE" if m["out_of_scope"] else "MISMATCH"
            log(f"  {tag} {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
            if m["out_of_scope"]:
                log(f"    why: {m['out_of_scope']}")
        cases.append(
            {
                "name": name,
                "core": c_res,
                "rustoshi": r_res,
                "mempool_core": after_c,
                "mempool_rustoshi": after_r,
                "mismatches": mismatches,
            }
        )

    # 1. CPFP. Parent fee 1 sat (below 100 sat/kvB). Child fee 20_000 sat.
    u = utxos[0]
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 1, dest
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 20_000, dest
    )
    cpfp_parent = parent
    run_case("valid-cpfp", parent["hex"], child["hex"], parent["txid"], child["txid"])
    # Same package again: both members are already in the mempool (MEMPOOL_ENTRY).
    run_case(
        "already-in-mempool",
        parent["hex"],
        child["hex"],
        parent["txid"],
        child["txid"],
    )

    # Same txid as the CPFP parent, different witness. Core returns other-wtxid
    # and leaves the mempool tx alone.
    log("=== other-wtxid ===")
    malleated_hex = corrupt_witness_sig(cpfp_parent["hex"], cpfp_parent["witness"][0])
    malleated = core.cli_json("decoderawtransaction", malleated_hex)
    if malleated["txid"] != cpfp_parent["txid"]:
        die("witness malleation changed txid")
    if malleated["hash"] == cpfp_parent["wtxid"]:
        die("witness malleation did not change wtxid")
    before_c = mempool_txids(core)
    before_r = mempool_txids(rust)
    c_tma = core.rpc("testmempoolaccept", [[malleated_hex]])
    r_tma = rust.rpc("testmempoolaccept", [[malleated_hex]])
    log("core testmempoolaccept: " + json.dumps(c_tma, sort_keys=True, default=str))
    log("rustoshi testmempoolaccept: " + json.dumps(r_tma, sort_keys=True, default=str))
    ow_mismatches = compare_json(c_tma, r_tma, "testmempoolaccept")
    c_res = core.rpc("submitpackage", [[malleated_hex]])
    r_res = rust.rpc("submitpackage", [[malleated_hex]])
    log("core submitpackage: " + json.dumps(c_res, sort_keys=True, default=str))
    log("rustoshi submitpackage: " + json.dumps(r_res, sort_keys=True, default=str))
    ow_mismatches.extend(compare_submit(c_res, r_res))
    if mempool_txids(core) != before_c or mempool_txids(rust) != before_r:
        ow_mismatches.append(
            {
                "field": "mempool_changed",
                "core": mempool_txids(core) != before_c,
                "rustoshi": mempool_txids(rust) != before_r,
                "out_of_scope": None,
            }
        )
    if mempool_txids(core) != mempool_txids(rust):
        ow_mismatches.append(
            {
                "field": "getrawmempool",
                "core": mempool_txids(core),
                "rustoshi": mempool_txids(rust),
                "out_of_scope": None,
            }
        )
    for m in ow_mismatches:
        tag = "OUT_OF_SCOPE" if m["out_of_scope"] else "MISMATCH"
        log(f"  {tag} {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
    cases.append(
        {
            "name": "other-wtxid",
            "core": c_res,
            "rustoshi": r_res,
            "mempool_core": mempool_txids(core),
            "mempool_rustoshi": mempool_txids(rust),
            "mismatches": ow_mismatches,
        }
    )

    # 2. Invalid-signature child. Parent fee 10_000 sat so it is individually valid.
    u = utxos[1]
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 10_000, dest
    )
    bad_child_hex = corrupt_witness_sig(child["hex"], child["witness"][0])
    bad_child = core.cli_json("decoderawtransaction", bad_child_hex)
    run_case(
        "invalid-sig-child",
        parent["hex"],
        bad_child_hex,
        parent["txid"],
        bad_child["txid"],
    )

    # 3. Invalid-signature parent.
    u = utxos[2]
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest
    )
    bad_parent_hex = corrupt_witness_sig(parent["hex"], parent["witness"][0])
    bad_parent = core.cli_json("decoderawtransaction", bad_parent_hex)
    # Child spends the corrupted parent. txid is unchanged by a witness-only
    # mutation, so the signed child still refers to it.
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 10_000, dest
    )
    run_case(
        "invalid-sig-parent",
        bad_parent_hex,
        child["hex"],
        bad_parent["txid"],
        child["txid"],
    )

    # 4. CPFP parent + invalid-signature child. Core submits nothing.
    u = utxos[3]
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 1, dest
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 20_000, dest
    )
    bad_child_hex = corrupt_witness_sig(child["hex"], child["witness"][0])
    bad_child = core.cli_json("decoderawtransaction", bad_child_hex)
    run_case(
        "cpfp-invalid-sig-child",
        parent["hex"],
        bad_child_hex,
        parent["txid"],
        bad_child["txid"],
    )

    # 5. Non-standard child version. Parent pays its own fee and is relayed.
    u = utxos[4]
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 10_000, dest
    )
    bad_ver_hex = with_version(child["hex"], 0xFFFFFFFF)
    bad_ver = core.cli_json("decoderawtransaction", bad_ver_hex)
    run_case(
        "bad-version-child",
        parent["hex"],
        bad_ver_hex,
        parent["txid"],
        bad_ver["txid"],
    )

    def admit_both(name: str, hex_tx: str) -> None:
        """submitpackage one tx on both nodes and require the results to match."""
        log(f"=== admit {name} ===")
        c_res = core.rpc("submitpackage", [[hex_tx]])
        r_res = rust.rpc("submitpackage", [[hex_tx]])
        log("core submitpackage: " + json.dumps(c_res, sort_keys=True, default=str))
        log("rustoshi submitpackage: " + json.dumps(r_res, sort_keys=True, default=str))
        mismatches = compare_submit(c_res, r_res)
        if mempool_txids(core) != mempool_txids(rust):
            mismatches.append(
                {
                    "field": "getrawmempool",
                    "core": mempool_txids(core),
                    "rustoshi": mempool_txids(rust),
                    "out_of_scope": None,
                }
            )
        for m in mismatches:
            tag = "OUT_OF_SCOPE" if m["out_of_scope"] else "MISMATCH"
            log(f"  {tag} {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
        cases.append(
            {
                "name": name,
                "core": c_res,
                "rustoshi": r_res,
                "mempool_core": mempool_txids(core),
                "mempool_rustoshi": mempool_txids(rust),
                "mismatches": mismatches,
            }
        )

    # 6. Package RBF success. The replacement parent spends the same confirmed
    # output as `original` and pays a higher fee; the child spends the parent.
    # Core lists the replaced txid in replaced-transactions.
    u = utxos[5]
    original = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest
    )
    admit_both("package-rbf-original", original["hex"])
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 50_000, dest
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 5_000, dest
    )
    run_case(
        "package-rbf-success",
        parent["hex"],
        child["hex"],
        parent["txid"],
        child["txid"],
    )
    if original["txid"] in mempool_txids(core) or original["txid"] in mempool_txids(rust):
        log(
            f"MISMATCH package-rbf-success left original {original['txid']} in a mempool"
        )
        cases[-1]["mismatches"].append(
            {
                "field": "original_still_present",
                "core": original["txid"] in mempool_txids(core),
                "rustoshi": original["txid"] in mempool_txids(rust),
                "out_of_scope": None,
            }
        )

    # 7. The replacement itself fails script checks. Core never reaches
    # FinalizeSubpackage, so the original stays and replaced-transactions is
    # empty. A child of the rejected parent is missing-inputs.
    u = utxos[6]
    original = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest
    )
    admit_both("package-rbf-badsig-original", original["hex"])
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 50_000, dest
    )
    bad_parent_hex = corrupt_witness_sig(parent["hex"], parent["witness"][0])
    bad_parent = core.cli_json("decoderawtransaction", bad_parent_hex)
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 5_000, dest
    )
    run_case(
        "package-rbf-badsig",
        bad_parent_hex,
        child["hex"],
        bad_parent["txid"],
        child["txid"],
    )
    orig_c = original["txid"] in mempool_txids(core)
    orig_r = original["txid"] in mempool_txids(rust)
    log(f"  original still in mempool core={orig_c} rustoshi={orig_r}")
    if not orig_c or not orig_r:
        cases[-1]["mismatches"].append(
            {
                "field": "original_evicted",
                "core": orig_c,
                "rustoshi": orig_r,
                "out_of_scope": None,
            }
        )

    # 8. Individually valid RBF parent, bad-sig child. Core finalizes the
    # parent (and its eviction) before the child is script-checked, so the
    # original is gone and replaced-transactions lists it.
    u = utxos[7]
    original = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest
    )
    admit_both("package-rbf-badchild-original", original["hex"])
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 50_000, dest
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 5_000, dest
    )
    bad_child_hex = corrupt_witness_sig(child["hex"], child["witness"][0])
    bad_child = core.cli_json("decoderawtransaction", bad_child_hex)
    run_case(
        "package-rbf-bad-child",
        parent["hex"],
        bad_child_hex,
        parent["txid"],
        bad_child["txid"],
    )

    def run_solo(name: str, hex_tx: str, txid: str, maxfeerate: str | None = None):
        """One-tx submitpackage (and testmempoolaccept). Optional maxfeerate."""
        log(f"=== {name} ===")
        before_c = set(mempool_txids(core))
        before_r = set(mempool_txids(rust))
        tma_params: list = [[hex_tx]]
        sp_params: list = [[hex_tx]]
        if maxfeerate is not None:
            # testmempoolaccept takes a JSON number. submitpackage takes
            # Core's amount string (8 decimal places).
            tma_params.append(float(maxfeerate))
            sp_params.append(maxfeerate)
        c_tma = core.rpc("testmempoolaccept", tma_params)
        r_tma = rust.rpc("testmempoolaccept", tma_params)
        log("core testmempoolaccept: " + json.dumps(c_tma, sort_keys=True, default=str))
        log("rustoshi testmempoolaccept: " + json.dumps(r_tma, sort_keys=True, default=str))
        mismatches = compare_json(c_tma, r_tma, "testmempoolaccept")
        c_res = core.rpc("submitpackage", sp_params)
        r_res = rust.rpc("submitpackage", sp_params)
        log("core submitpackage: " + json.dumps(c_res, sort_keys=True, default=str))
        log("rustoshi submitpackage: " + json.dumps(r_res, sort_keys=True, default=str))
        mismatches.extend(compare_submit(c_res, r_res))
        after_c = mempool_txids(core)
        after_r = mempool_txids(rust)
        if after_c != after_r:
            mismatches.append(
                {
                    "field": "getrawmempool",
                    "core": after_c,
                    "rustoshi": after_r,
                    "out_of_scope": None,
                }
            )
        c_in = txid in after_c
        r_in = txid in after_r
        log(f"  tx {txid} in mempool core={c_in} rustoshi={r_in}")
        if c_in != r_in:
            mismatches.append(
                {
                    "field": "mempool_contains",
                    "core": c_in,
                    "rustoshi": r_in,
                    "out_of_scope": None,
                }
            )
        added_c = sorted(set(after_c) - before_c)
        added_r = sorted(set(after_r) - before_r)
        if added_c != added_r:
            mismatches.append(
                {
                    "field": "mempool_added",
                    "core": added_c,
                    "rustoshi": added_r,
                    "out_of_scope": None,
                }
            )
        for m in mismatches:
            tag = "OUT_OF_SCOPE" if m["out_of_scope"] else "MISMATCH"
            log(f"  {tag} {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
        cases.append(
            {
                "name": name,
                "core": c_res,
                "rustoshi": r_res,
                "mempool_core": after_c,
                "mempool_rustoshi": after_r,
                "mismatches": mismatches,
            }
        )

    # 9. Solo effective-feerate. CFeeRate::GetFeePerK truncates
    # (fee * 1000) / vsize. Pick a fee where that differs from rounding.
    u = utxos[8]
    fee = 10_000
    solo = None
    for _ in range(80):
        solo = make_signed(
            core, u["txid"], u["vout"], sats_of(u["amount"]), spk, fee, dest
        )
        vsize = solo["vsize"]
        trunc = (fee * 1000) // vsize
        rnd = (fee * 1000 + vsize // 2) // vsize
        if trunc != rnd:
            log(f"solo feerate fee={fee} vsize={vsize} trunc_sat_kvb={trunc} round_sat_kvb={rnd}")
            break
        fee += 1
    else:
        die("could not find a solo fee whose GetFeePerK truncates differently from rounding")
    run_solo("solo-effective-feerate", solo["hex"], solo["txid"])

    # 10. maxfeerate is checked before submission. 0.00001000 BTC/kvB is
    # 1000 sat/kvB; this tx's fee is far above that. Core's error is
    # "max feerate exceeded" (empty debug message), package_msg
    # "transaction failed", and the tx is not admitted.
    u = utxos[9]
    hot = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest
    )
    run_solo("maxfeerate", hot["hex"], hot["txid"], "0.00001000")

    def run_policy(name: str, hexes: list[str], allow_admit: bool = False):
        """submitpackage and testmempoolaccept, including JSON-RPC errors.

        Topology and the 1..=25 size gate are RPC errors (code + message).
        IsWellFormedPackage failures are results. `allow_admit` is for a
        package whose individually valid parents stay in the mempool on both
        nodes (too-large-cluster: the parent fits, the child does not).
        """
        log(f"=== {name} ===")
        before_c = mempool_txids(core)
        before_r = mempool_txids(rust)
        c_tma = core.rpc_outcome("testmempoolaccept", [hexes])
        r_tma = rust.rpc_outcome("testmempoolaccept", [hexes])
        log("core testmempoolaccept: " + json.dumps(c_tma, sort_keys=True, default=str))
        log("rustoshi testmempoolaccept: " + json.dumps(r_tma, sort_keys=True, default=str))
        mismatches = compare_outcome(c_tma, r_tma, "testmempoolaccept")
        c_res = core.rpc_outcome("submitpackage", [hexes])
        r_res = rust.rpc_outcome("submitpackage", [hexes])
        log("core submitpackage: " + json.dumps(c_res, sort_keys=True, default=str))
        log("rustoshi submitpackage: " + json.dumps(r_res, sort_keys=True, default=str))
        mismatches.extend(compare_outcome(c_res, r_res, "submitpackage"))
        after_c = mempool_txids(core)
        after_r = mempool_txids(rust)
        if allow_admit:
            if after_c != after_r:
                mismatches.append(
                    {
                        "field": "getrawmempool",
                        "core": after_c,
                        "rustoshi": after_r,
                        "out_of_scope": None,
                    }
                )
        elif after_c != before_c or after_r != before_r or after_c != after_r:
            mismatches.append(
                {
                    "field": "mempool_changed",
                    "core": after_c,
                    "rustoshi": after_r,
                    "out_of_scope": None,
                }
            )
        for m in mismatches:
            tag = "OUT_OF_SCOPE" if m["out_of_scope"] else "MISMATCH"
            log(f"  {tag} {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
        cases.append(
            {
                "name": name,
                "core": c_res,
                "rustoshi": r_res,
                "mempool_core": after_c,
                "mempool_rustoshi": after_r,
                "mismatches": mismatches,
            }
        )

    # Two individually valid spends are not a child-with-parents tree.
    # submitpackage is the topology RPC error. testmempoolaccept has no tree
    # gate and validates each tx (allowed, with fees).
    free = [
        u
        for u in utxos
        if core.rpc("gettxout", [u["txid"], int(u["vout"])]) is not None
    ]
    if len(free) < 2:
        die(f"need 2 unspent coinbases for the topology case, have {len(free)}")
    topo_a = make_signed(
        core, free[0]["txid"], free[0]["vout"], sats_of(free[0]["amount"]), spk, 10_000, dest
    )
    topo_b = make_signed(
        core, free[1]["txid"], free[1]["vout"], sats_of(free[1]["amount"]), spk, 10_000, dest
    )
    run_policy("topology-unrelated", [topo_a["hex"], topo_b["hex"]])

    dup = fake_spend(0x33).hex()
    run_policy("duplicate-tx", [dup, dup])

    tiny = fake_spend(0x44).hex()
    run_policy("too-many-txs", [tiny] * 26)
    run_policy("empty-package", [])

    # Child-with-parents whose total weight exceeds 404_000. Parent alone is
    # already over the limit (non-witness weight = 4 * serialized size).
    n_out = 12_000
    parent_raw = fake_spend(0x55, n_outputs=n_out, value=1_000)
    child_raw = raw_tx([(txid_internal(parent_raw), 0, b"")], [(100, b"")])
    weight = 4 * (len(parent_raw) + len(child_raw))
    if weight <= 404_000:
        die(f"policy package weight {weight} did not exceed 404000")
    log(f"overweight package bytes parent={len(parent_raw)} child={len(child_raw)} weight={weight}")
    parent_hex = parent_raw.hex()
    child_hex = child_raw.hex()
    # Confirm Core can decode them. A decode failure would hide the policy token.
    core.rpc("decoderawtransaction", [parent_hex])
    core.rpc("decoderawtransaction", [child_hex])
    run_policy("package-too-large", [parent_hex, child_hex])
    run_policy("package-too-large-duplicate", [parent_hex, parent_hex, child_hex])

    # Last tx is not the child, so submitpackage is the topology RPC error.
    # testmempoolaccept has no tree gate and reports package-not-sorted.
    # Use a small tree: the overweight pair would be package-too-large first.
    sort_parent = fake_spend(0x88, value=50_000)
    sort_child = raw_tx([(txid_internal(sort_parent), 0, b"")], [(1_000, b"")])
    run_policy("unsorted", [sort_child.hex(), sort_parent.hex()])

    # Two parents spend one prevout; the child spends both. Still a tree.
    p1 = fake_spend(0x66, script_sig=b"", value=50_000)
    p2 = fake_spend(0x66, script_sig=b"\x51", value=40_000)
    conflict_child = raw_tx(
        [
            (txid_internal(p1), 0, b""),
            (txid_internal(p2), 0, b""),
        ],
        [(1_000, b"")],
    )
    run_policy("conflict-in-package", [p1.hex(), p2.hex(), conflict_child.hex()])

    # Duplicate parents that still form a tree: package-contains-duplicates,
    # not the topology RPC error. Distinct from duplicate-tx ([tx, tx]).
    tree_parent = fake_spend(0x77, value=50_000)
    tree_child = raw_tx([(txid_internal(tree_parent), 0, b"")], [(1_000, b"")])
    run_policy(
        "duplicate-parents",
        [tree_parent.hex(), tree_parent.hex(), tree_child.hex()],
    )

    # KB-104: 60-byte empty scriptPubKey. IsStandardTx returns scriptpubkey
    # before the 65-byte floor. A 61-byte OP_RETURN is standard and hits
    # tx-size-small.
    empty_spk = (1).to_bytes(4, "little")
    empty_spk += bytes([1]) + bytes(32) + (0).to_bytes(4, "little")
    empty_spk += bytes([0]) + (0xFFFFFFFF).to_bytes(4, "little")
    empty_spk += bytes([1]) + (1).to_bytes(8, "little") + bytes([0])
    empty_spk += (0).to_bytes(4, "little")
    if len(empty_spk) != 60:
        die(f"60-byte fixture is {len(empty_spk)} bytes")
    core.rpc("decoderawtransaction", [empty_spk.hex()])
    run_policy("empty-scriptpubkey-60", [empty_spk.hex()])

    op_ret = (1).to_bytes(4, "little")
    op_ret += bytes([1]) + bytes(32) + (0).to_bytes(4, "little")
    op_ret += bytes([0]) + (0xFFFFFFFF).to_bytes(4, "little")
    op_ret += bytes([1]) + (0).to_bytes(8, "little") + bytes([1, 0x6A])
    op_ret += (0).to_bytes(4, "little")
    if len(op_ret) >= 65:
        die(f"OP_RETURN fixture is {len(op_ret)} bytes")
    run_policy("op-return-tx-size-small", [op_ret.hex()])

    def spendable_coin():
        coins = core.cli_json("-rpcwallet=sweep", "listunspent", "100", "9999999")
        for coin in coins:
            if core.rpc("gettxout", [coin["txid"], int(coin["vout"])]) is not None:
                return coin
        die("no confirmed spendable coin left for dust/cluster cases")

    def sign_raw(raw: str, prevs: list[dict]) -> dict:
        encoded_prevs = []
        for prev in prevs:
            item = dict(prev)
            amount = item.get("amount")
            if isinstance(amount, Decimal):
                item["amount"] = f"{amount:.8f}"
            encoded_prevs.append(item)
        signed = core.cli_json(
            "-rpcwallet=sweep",
            "signrawtransactionwithwallet",
            raw,
            json.dumps(encoded_prevs),
        )
        if not signed.get("complete"):
            die(f"signrawtransactionwithwallet incomplete: {signed}")
        decoded = core.cli_json("decoderawtransaction", signed["hex"])
        return {"hex": signed["hex"], "decoded": decoded}

    dust_addr = core.cli_json("-rpcwallet=sweep", "getnewaddress", "", "bech32")
    coin = spendable_coin()
    coin_sats = sats_of(coin["amount"])
    coin_spk = core.cli_json(
        "-rpcwallet=sweep", "getaddressinfo", coin["address"]
    )["scriptPubKey"]
    # One 1-sat output (dust) and a change output. Fee is nonzero, so Core
    # PreCheckEphemeralTx rejects the parent before the child is finished.
    change = coin_sats - 1 - 5_000
    parent_raw = core.cli(
        "createrawtransaction",
        json.dumps([{"txid": coin["txid"], "vout": int(coin["vout"])}]),
        json.dumps({dest: btc(change), dust_addr: btc(1)}),
    )
    dust_parent = sign_raw(
        parent_raw,
        [
            {
                "txid": coin["txid"],
                "vout": int(coin["vout"]),
                "scriptPubKey": coin_spk,
                "amount": btc(coin_sats),
            }
        ],
    )
    parent_dec = dust_parent["decoded"]
    prevs = []
    for vout in parent_dec["vout"]:
        prevs.append(
            {
                "txid": parent_dec["txid"],
                "vout": vout["n"],
                "scriptPubKey": vout["scriptPubKey"]["hex"],
                "amount": vout["value"],
            }
        )
    child_out = change + 1 - 5_000
    child_raw = core.cli(
        "createrawtransaction",
        json.dumps(
            [
                {"txid": parent_dec["txid"], "vout": v["n"]}
                for v in parent_dec["vout"]
            ]
        ),
        json.dumps({dest: btc(child_out)}),
    )
    dust_child = sign_raw(child_raw, prevs)
    run_policy(
        "ephemeral-dust-nonzero-fee",
        [dust_parent["hex"], dust_child["hex"]],
    )

    # 0-fee dust parent; child spends only the non-dust output.
    # submitpackage package_msg is unspent-dust. testmempoolaccept stops at
    # the parent's min-relay failure and leaves the child unfinished.
    zero_change = coin_sats - 1
    zero_raw = core.cli(
        "createrawtransaction",
        json.dumps([{"txid": coin["txid"], "vout": int(coin["vout"])}]),
        json.dumps({dest: btc(zero_change), dust_addr: btc(1)}),
    )
    zero_parent = sign_raw(
        zero_raw,
        [
            {
                "txid": coin["txid"],
                "vout": int(coin["vout"]),
                "scriptPubKey": coin_spk,
                "amount": btc(coin_sats),
            }
        ],
    )
    zero_dec = zero_parent["decoded"]
    change_vout = next(v for v in zero_dec["vout"] if sats_of(v["value"]) != 1)
    sweep_raw = core.cli(
        "createrawtransaction",
        json.dumps([{"txid": zero_dec["txid"], "vout": change_vout["n"]}]),
        json.dumps({dest: btc(sats_of(change_vout["value"]) - 5_000)}),
    )
    sweep_child = sign_raw(
        sweep_raw,
        [
            {
                "txid": zero_dec["txid"],
                "vout": change_vout["n"],
                "scriptPubKey": change_vout["scriptPubKey"]["hex"],
                "amount": change_vout["value"],
            }
        ],
    )
    run_policy(
        "ephemeral-unspent-dust",
        [zero_parent["hex"], sweep_child["hex"]],
    )

    # KB-107: 63-tx cluster, then a 2-tx package. testmempoolaccept is
    # package-error too-large-cluster with no allowed. submitpackage admits
    # the parent (cluster 64) and rejects the child.
    cluster_coin = spendable_coin()
    prev_txid = cluster_coin["txid"]
    prev_vout = int(cluster_coin["vout"])
    prev_sats = sats_of(cluster_coin["amount"])
    prev_spk = core.cli_json(
        "-rpcwallet=sweep", "getaddressinfo", cluster_coin["address"]
    )["scriptPubKey"]
    for i in range(63):
        step = make_signed(
            core, prev_txid, prev_vout, prev_sats, prev_spk, 10_000, dest
        )
        admit_both(f"cluster-fill-{i}", step["hex"])
        prev_txid = step["txid"]
        prev_vout = 0
        prev_sats = step["out_sats"]
        prev_spk = step["spk"]
    cluster_parent = make_signed(
        core, prev_txid, prev_vout, prev_sats, prev_spk, 10_000, dest
    )
    cluster_child = make_signed(
        core,
        cluster_parent["txid"],
        0,
        cluster_parent["out_sats"],
        cluster_parent["spk"],
        10_000,
        dest,
    )
    run_policy(
        "too-large-cluster",
        [cluster_parent["hex"], cluster_child["hex"]],
        allow_admit=True,
    )

    # Seven Core v31.1 paths. testmempoolaccept, sendrawtransaction, and
    # submitpackage are compared whole. getrawmempool verbose is compared for
    # the package txids that landed; time / chunkweight / fees.chunk / depends
    # / spentby / bip125-replaceable / unbroadcast / time are out of scope:
    # they are fixed on PR #7 and are not compared into the exit code.
    spk_bytes = bytes.fromhex(spk)
    # OP_1 PUSH2 4e73. 0x02 is the push length; 0x20 would be a 32-byte push.
    p2a_script = bytes.fromhex("51024e73")

    def spendable_coins() -> list[dict]:
        # minconf 1: outputs of txs just mined out of the mempool are spendable.
        # Immature coinbases stay hidden. gettxout drops anything still in the mempool.
        coins = core.cli_json("-rpcwallet=sweep", "listunspent", "1", "9999999")
        live = []
        for coin in coins:
            if core.rpc("gettxout", [coin["txid"], int(coin["vout"])]) is not None:
                live.append(coin)
        return live

    def sync_generated(n: int) -> None:
        """Mine on Core and submit the same blocks to rustoshi so tips stay equal."""
        hashes = core.cli_json("-rpcwallet=sweep", "generatetoaddress", str(n), dest)
        if isinstance(hashes, str):
            hashes = [hashes]
        for bh in hashes:
            raw = core.cli_json("getblock", bh, "0")
            result = rust.rpc("submitblock", [raw])
            if result not in (None, ""):
                die(f"submitblock {bh}: {result}")
        c_hash = core.rpc("getbestblockhash")
        r_hash = rust.rpc("getbestblockhash")
        if c_hash != r_hash or core.rpc("getblockcount") != rust.rpc("getblockcount"):
            die(f"tip diverged after generate: core={c_hash} rustoshi={r_hash}")
        log(
            f"advanced to height {core.rpc('getblockcount')} "
            f"mempool core={len(mempool_txids(core))} rustoshi={len(mempool_txids(rust))}"
        )

    def coin_prev(coin: dict) -> dict:
        return {
            "txid": coin["txid"],
            "vout": int(coin["vout"]),
            "scriptPubKey": coin["scriptPubKey"],
            "amount": btc(sats_of(coin["amount"])),
        }

    def signed_outputs(
        coin: dict,
        outputs: list[tuple[int, bytes]],
        version: int = 2,
        locktime: int = 0,
    ) -> dict:
        txid_le = bytes.fromhex(coin["txid"])[::-1]
        raw = raw_tx(
            [(txid_le, int(coin["vout"]), b"")],
            outputs,
            version=version,
            locktime=locktime,
        ).hex()
        return sign_raw(raw, [coin_prev(coin)])

    def signed_child(parent: dict, fee_sats: int, version: int = 2, extra_inputs: list[dict] | None = None) -> dict:
        """Spend every parent output, plus any extra prevouts, paying `dest`."""
        dec = parent["decoded"]
        inputs = []
        prevs = []
        total = 0
        for vout in dec["vout"]:
            inputs.append((bytes.fromhex(dec["txid"])[::-1], vout["n"], b""))
            prevs.append(
                {
                    "txid": dec["txid"],
                    "vout": vout["n"],
                    "scriptPubKey": vout["scriptPubKey"]["hex"],
                    "amount": btc(sats_of(vout["value"])),
                }
            )
            total += sats_of(vout["value"])
        for extra in extra_inputs or []:
            inputs.append(
                (bytes.fromhex(extra["txid"])[::-1], int(extra["vout"]), b"")
            )
            prevs.append(
                {
                    "txid": extra["txid"],
                    "vout": int(extra["vout"]),
                    "scriptPubKey": extra["scriptPubKey"],
                    "amount": btc(sats_of(extra["amount"])),
                }
            )
            total += sats_of(extra["amount"])
        out_sats = total - fee_sats
        if out_sats <= 0:
            die(f"child fee {fee_sats} exceeds inputs {total}")
        raw = raw_tx(inputs, [(out_sats, spk_bytes)], version=version).hex()
        return sign_raw(raw, prevs)

    def strip_verbose_entry(entry: dict) -> dict:
        kept = {
            key: entry[key]
            for key in entry
            if key
            not in (
                "time",
                "chunkweight",
                "depends",
                "spentby",
                "bip125-replaceable",
                "unbroadcast",
            )
        }
        fees = dict(kept.get("fees") or {})
        fees.pop("chunk", None)
        kept["fees"] = fees
        return kept

    def compare_verbose(core_map, rust_map, focus: list[str]) -> list[dict]:
        mismatches = []
        if not isinstance(core_map, dict) or not isinstance(rust_map, dict):
            return [
                {
                    "field": "getrawmempool type",
                    "core": core_map,
                    "rustoshi": rust_map,
                    "out_of_scope": None,
                }
            ]
        c_ids, r_ids = list(core_map), list(rust_map)
        if set(c_ids) != set(r_ids):
            mismatches.append(
                {
                    "field": "getrawmempool txids",
                    "core": sorted(set(c_ids) - set(r_ids)),
                    "rustoshi": sorted(set(r_ids) - set(c_ids)),
                    "out_of_scope": None,
                }
            )
        if c_ids != r_ids and set(c_ids) == set(r_ids):
            mismatches.append(
                {
                    "field": "getrawmempool key order",
                    "core": len(c_ids),
                    "rustoshi": len(r_ids),
                    "out_of_scope": (
                        "Core MempoolToJSON walks entryAll (rpc/mempool.cpp:579); "
                        "rustoshi walks get_sorted_for_mining (crates/rpc/src/server.rs:9091)"
                    ),
                }
            )
        residual = {
            "time": 0,
            "chunkweight": 0,
            "fees.chunk": 0,
            "depends": 0,
            "spentby": 0,
            "bip125-replaceable": 0,
            "unbroadcast": 0,
        }
        present = [txid for txid in focus if txid in core_map or txid in rust_map]
        for txid in present:
            if txid not in core_map or txid not in rust_map:
                mismatches.append(
                    {
                        "field": f"getrawmempool.{txid}",
                        "core": txid in core_map,
                        "rustoshi": txid in rust_map,
                        "out_of_scope": None,
                    }
                )
                continue
            c_ent, r_ent = core_map[txid], rust_map[txid]
            if c_ent.get("time") != r_ent.get("time"):
                residual["time"] += 1
            if "chunkweight" in c_ent and "chunkweight" not in r_ent:
                residual["chunkweight"] += 1
            elif c_ent.get("chunkweight") != r_ent.get("chunkweight"):
                mismatches.append(
                    {
                        "field": f"getrawmempool.{txid}.chunkweight",
                        "core": c_ent.get("chunkweight"),
                        "rustoshi": r_ent.get("chunkweight"),
                        "out_of_scope": None,
                    }
                )
            c_fees = c_ent.get("fees") if isinstance(c_ent.get("fees"), dict) else {}
            r_fees = r_ent.get("fees") if isinstance(r_ent.get("fees"), dict) else {}
            if "chunk" in c_fees and "chunk" not in r_fees:
                residual["fees.chunk"] += 1
            elif c_fees.get("chunk") != r_fees.get("chunk"):
                mismatches.append(
                    {
                        "field": f"getrawmempool.{txid}.fees.chunk",
                        "core": c_fees.get("chunk"),
                        "rustoshi": r_fees.get("chunk"),
                        "out_of_scope": None,
                    }
                )
            for key in ("depends", "spentby", "bip125-replaceable", "unbroadcast"):
                if c_ent.get(key) != r_ent.get(key):
                    residual[key] += 1
            mismatches.extend(
                compare_json(
                    strip_verbose_entry(c_ent),
                    strip_verbose_entry(r_ent),
                    f"getrawmempool.{txid}",
                )
            )
        hit = {key: count for key, count in residual.items() if count}
        if hit:
            mismatches.append(
                {
                    "field": "getrawmempool verbose residuals",
                    "core": hit,
                    "rustoshi": "differs on the focused entries",
                    "out_of_scope": (
                        "time is the local Unix second the tx entered; "
                        "chunkweight is Core entryToJSON (rpc/mempool.cpp:525), "
                        "omitted by rustoshi MempoolEntry (crates/rpc/src/types.rs:723); "
                        "fees.chunk is Core rpc/mempool.cpp:532, omitted by MempoolFees "
                        "(crates/rpc/src/types.rs:696); depends, spentby, and "
                        "bip125-replaceable are empty/false in get_raw_mempool "
                        "(crates/rpc/src/server.rs:9130-9132); unbroadcast is "
                        "hardcoded false (server.rs:9197) because rustoshi keeps "
                        "no unbroadcast set, while Core's sendrawtransaction marks "
                        "the tx via AddUnbroadcastTx"
                    ),
                }
            )
        return mismatches

    def package_txids(hexes: list[str]) -> list[str]:
        return [core.rpc("decoderawtransaction", [hx])["txid"] for hx in hexes]

    def run_reached(name: str, hexes: list[str], sendraw: list[str] | None = None) -> None:
        log(f"=== {name} ===")
        mismatches: list[dict] = []
        before = set(mempool_txids(core))
        c_tma = core.rpc_outcome("testmempoolaccept", [hexes])
        r_tma = rust.rpc_outcome("testmempoolaccept", [hexes])
        log("core testmempoolaccept: " + json.dumps(c_tma, default=str)[:2500])
        log("rustoshi testmempoolaccept: " + json.dumps(r_tma, default=str)[:2500])
        mismatches.extend(compare_outcome(c_tma, r_tma, "testmempoolaccept"))
        for i, hx in enumerate(sendraw or []):
            c_sr = core.rpc_outcome("sendrawtransaction", [hx])
            r_sr = rust.rpc_outcome("sendrawtransaction", [hx])
            log(f"core sendrawtransaction[{i}]: " + json.dumps(c_sr, default=str)[:1500])
            log(f"rustoshi sendrawtransaction[{i}]: " + json.dumps(r_sr, default=str)[:1500])
            mismatches.extend(compare_outcome(c_sr, r_sr, f"sendrawtransaction[{i}]"))
        c_res = core.rpc_outcome("submitpackage", [hexes])
        r_res = rust.rpc_outcome("submitpackage", [hexes])
        log("core submitpackage: " + json.dumps(c_res, default=str)[:2500])
        log("rustoshi submitpackage: " + json.dumps(r_res, default=str)[:2500])
        mismatches.extend(compare_outcome(c_res, r_res, "submitpackage"))
        c_tip = {
            "height": core.rpc("getblockcount"),
            "hash": core.rpc("getbestblockhash"),
        }
        r_tip = {
            "height": rust.rpc("getblockcount"),
            "hash": rust.rpc("getbestblockhash"),
        }
        log(f"  tip core={c_tip} rustoshi={r_tip}")
        if c_tip != r_tip:
            mismatches.append(
                {
                    "field": "tip",
                    "core": c_tip,
                    "rustoshi": r_tip,
                    "out_of_scope": None,
                }
            )
        focus = package_txids(hexes)
        added = sorted(set(mempool_txids(core)) - before)
        c_mem = core.rpc("getrawmempool", [True])
        r_mem = rust.rpc("getrawmempool", [True])
        mismatches.extend(compare_verbose(c_mem, r_mem, focus + added))
        for m in mismatches:
            shown = m["core"]
            if isinstance(shown, (dict, list)) and len(json.dumps(shown, default=str)) > 400:
                shown = json.dumps(shown, default=str)[:400] + "…"
            tag = "OUT_OF_SCOPE" if m["out_of_scope"] else "MISMATCH"
            log(f"  {tag} {m['field']}: core={shown!r} rustoshi={m['rustoshi']!r}")
            if m["out_of_scope"]:
                log(f"    why: {m['out_of_scope']}")
        cases.append(
            {
                "name": name,
                "core": c_res,
                "rustoshi": r_res,
                "mismatches": mismatches,
            }
        )

    # The first 110 blocks only mature ~11 coinbases, and the cases above
    # spend those in the mempool. One block confirms them into ordinary outputs.
    sync_generated(1)
    if mempool_txids(core) != mempool_txids(rust):
        die(
            "mempools diverged after the confirming block: "
            f"core={mempool_txids(core)} rustoshi={mempool_txids(rust)}"
        )
    live = spendable_coins()
    if len(live) < 4:
        die(f"need 4 spendable coins for the seven Core paths, have {len(live)}")
    reject_coin, rbf_parent_coin, rbf_low_coin, truc_coin = live[:4]
    for label, coin in (
        ("reject", reject_coin),
        ("rbf-parent", rbf_parent_coin),
        ("rbf-low", rbf_low_coin),
        ("truc", truc_coin),
    ):
        log(
            f"path coin {label} {coin['txid']}:{coin['vout']} {coin['amount']}"
        )

    # 1. Positive sub-threshold P2A is dust. 0-value P2A with a 0 fee stays
    # ephemeral and fails the relay floor instead of the dust rule.
    reject_sats = sats_of(reject_coin["amount"])
    p2a_pos = signed_outputs(
        reject_coin,
        [(reject_sats - 10_000 - 1, spk_bytes), (1, p2a_script)],
    )
    run_reached("p2a-positive-dust", [p2a_pos["hex"]], sendraw=[p2a_pos["hex"]])
    p2a_zero = signed_outputs(
        reject_coin,
        [(reject_sats, spk_bytes), (0, p2a_script)],
    )
    run_reached("p2a-zero-ephemeral", [p2a_zero["hex"]], sendraw=[p2a_zero["hex"]])

    # 2. Both package members are below min relay. package_msg is
    # `transaction failed`; only the child carries the package CheckFeeRate string.
    low_parent = signed_outputs(reject_coin, [(reject_sats - 1, spk_bytes)])
    low_child = signed_child(low_parent, 1)
    run_reached(
        "package-fee-checkfeerate",
        [low_parent["hex"], low_child["hex"]],
        sendraw=[low_parent["hex"], low_child["hex"]],
    )

    # 6. sendrawtransaction of a nonzero-fee dust parent: code -26 and the
    # full PreCheckEphemeralTx string, not the bare `dust` token.
    dust_pos = signed_outputs(
        reject_coin,
        [(reject_sats - 5_000 - 1, spk_bytes), (1, spk_bytes)],
    )
    run_reached("sendraw-dust-tostring", [dust_pos["hex"]], sendraw=[dust_pos["hex"]])

    # 7. 0-base-fee dust plus a prioritisetransaction delta is still dust.
    dust_zero = signed_outputs(
        reject_coin,
        [(reject_sats - 1, spk_bytes), (1, spk_bytes)],
    )
    dust_txid = dust_zero["decoded"]["txid"]
    c_pri = core.rpc_outcome("prioritisetransaction", [dust_txid, 0, 1000])
    r_pri = rust.rpc_outcome("prioritisetransaction", [dust_txid, 0, 1000])
    log("core prioritisetransaction: " + json.dumps(c_pri, default=str))
    log("rustoshi prioritisetransaction: " + json.dumps(r_pri, default=str))
    pri_mismatch = compare_outcome(c_pri, r_pri, "prioritisetransaction")
    if pri_mismatch:
        cases.append(
            {
                "name": "prioritisetransaction-dust-delta",
                "core": c_pri,
                "rustoshi": r_pri,
                "mismatches": pri_mismatch,
            }
        )
        for m in pri_mismatch:
            log(f"  MISMATCH {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
    run_reached(
        "ephemeral-dust-priority-delta",
        [dust_zero["hex"]],
        sendraw=[dust_zero["hex"]],
    )

    # 5. Replacement spends a mempool parent that already has a spender.
    # Package fee clears the relay floor so Core reaches PackageRBFChecks.
    rbf_p = signed_outputs(
        rbf_parent_coin,
        [(sats_of(rbf_parent_coin["amount"]) - 10_000, spk_bytes)],
    )
    admit_both("package-rbf-ancestor-parent", rbf_p["hex"])
    rbf_m = signed_child(rbf_p, 10_000)
    admit_both("package-rbf-ancestor-spender", rbf_m["hex"])
    rbf_a = signed_outputs(
        rbf_low_coin,
        [(sats_of(rbf_low_coin["amount"]) - 1, spk_bytes)],
    )
    a_out = sats_of(rbf_a["decoded"]["vout"][0]["value"])
    p_out = sats_of(rbf_p["decoded"]["vout"][0]["value"])
    rbf_fee = 50_000
    rbf_r_raw = raw_tx(
        [
            (bytes.fromhex(rbf_a["decoded"]["txid"])[::-1], 0, b""),
            (bytes.fromhex(rbf_p["decoded"]["txid"])[::-1], 0, b""),
        ],
        [(a_out + p_out - rbf_fee, spk_bytes)],
    ).hex()
    rbf_r = sign_raw(
        rbf_r_raw,
        [
            {
                "txid": rbf_a["decoded"]["txid"],
                "vout": 0,
                "scriptPubKey": rbf_a["decoded"]["vout"][0]["scriptPubKey"]["hex"],
                "amount": btc(a_out),
            },
            {
                "txid": rbf_p["decoded"]["txid"],
                "vout": 0,
                "scriptPubKey": rbf_p["decoded"]["vout"][0]["scriptPubKey"]["hex"],
                "amount": btc(p_out),
            },
        ],
    )
    run_reached(
        "package-rbf-mempool-ancestor",
        [rbf_a["hex"], rbf_r["hex"]],
        sendraw=[rbf_a["hex"], rbf_r["hex"]],
    )

    # 3. Fee-sufficient v3 parent + non-v3 child. testmempoolaccept is
    # package-error with the debug suffix; submitpackage admits the parent.
    truc_parent = signed_outputs(
        truc_coin,
        [(sats_of(truc_coin["amount"]) - 10_000, spk_bytes)],
        version=3,
    )
    if truc_parent["decoded"]["version"] != 3:
        die(f"TRUC parent version is {truc_parent['decoded']['version']}")
    truc_child = signed_child(truc_parent, 10_000)
    run_reached(
        "truc-package-error",
        [truc_parent["hex"], truc_child["hex"]],
        sendraw=[truc_child["hex"]],
    )

    def fresh_coin() -> dict:
        coins = spendable_coins()
        if not coins:
            sync_generated(1)
            coins = spendable_coins()
        if not coins:
            die("no confirmed spendable coin")
        return coins[0]

    def sign_partial(raw: str, prevs: list[dict]) -> dict:
        """Sign what the wallet can. A P2A input stays unsigned."""
        encoded_prevs = []
        for prev in prevs:
            item = dict(prev)
            amount = item.get("amount")
            if isinstance(amount, Decimal):
                item["amount"] = f"{amount:.8f}"
            encoded_prevs.append(item)
        signed = core.cli_json(
            "-rpcwallet=sweep",
            "signrawtransactionwithwallet",
            raw,
            json.dumps(encoded_prevs),
        )
        decoded = core.cli_json("decoderawtransaction", signed["hex"])
        by_vout = {int(prev["vout"]): prev for prev in encoded_prevs}
        for vin in decoded["vin"]:
            prev = by_vout[int(vin["vout"])]
            witness = vin.get("txinwitness") or []
            script_sig = (vin.get("scriptSig") or {}).get("hex") or ""
            if prev["scriptPubKey"] == p2a_script.hex():
                if witness or script_sig:
                    die(f"P2A input must have a null witness and empty scriptSig: {vin}")
            elif not witness:
                die(f"signrawtransactionwithwallet left a non-anchor input unsigned: {signed}")
        return {"hex": signed["hex"], "decoded": decoded}

    # 0-fee 0-value P2A, spent by the child. Ephemeral dust: the package is
    # accepted and the anchor is not left unspent. Solo sendraw of the parent
    # fails the relay floor (PreCheckEphemeralTx allows the 0 fee).
    anchor_coin = fresh_coin()
    anchor_parent = signed_outputs(
        anchor_coin,
        [(sats_of(anchor_coin["amount"]), spk_bytes), (0, p2a_script)],
    )
    anchor_dec = anchor_parent["decoded"]
    change_vout = next(v for v in anchor_dec["vout"] if sats_of(v["value"]) > 0)
    anchor_vout = next(
        v for v in anchor_dec["vout"] if v["scriptPubKey"]["hex"] == p2a_script.hex()
    )
    anchor_child_value = sats_of(change_vout["value"]) - 10_000
    anchor_child_raw = raw_tx(
        [
            (bytes.fromhex(anchor_dec["txid"])[::-1], change_vout["n"], b""),
            (bytes.fromhex(anchor_dec["txid"])[::-1], anchor_vout["n"], b""),
        ],
        [(anchor_child_value, spk_bytes)],
    ).hex()
    anchor_child = sign_partial(
        anchor_child_raw,
        [
            {
                "txid": anchor_dec["txid"],
                "vout": change_vout["n"],
                "scriptPubKey": change_vout["scriptPubKey"]["hex"],
                "amount": btc(sats_of(change_vout["value"])),
            },
            {
                "txid": anchor_dec["txid"],
                "vout": anchor_vout["n"],
                "scriptPubKey": anchor_vout["scriptPubKey"]["hex"],
                "amount": btc(0),
            },
        ],
    )
    run_reached(
        "p2a-zero-spent-by-child",
        [anchor_parent["hex"], anchor_child["hex"]],
        sendraw=[anchor_parent["hex"]],
    )

    # Wallet CreateTransaction pre-checks. Dust (including 0) is rejected
    # before fee estimation, so it matches on a node with no -fallbackfee.
    # `send` takes an explicit fee_rate, which is how insufficient funds and
    # the no-input-fee sentence are reached on both nodes.
    log("=== wallet CreateTransaction pre-checks ===")
    rust.rpc("createwallet", ["sweep"])
    rust_addr = rust.rpc("getnewaddress", ["", "bech32"])
    rust_info = rust.rpc("getaddressinfo", [rust_addr])
    rust_spk = bytes.fromhex(rust_info["scriptPubKey"])
    fund_coin = fresh_coin()
    fund_sats = sats_of(fund_coin["amount"])
    fund_pay = min(100_000_000, fund_sats // 2)
    fund_tx = signed_outputs(
        fund_coin,
        [(fund_pay, rust_spk), (fund_sats - fund_pay - 10_000, spk_bytes)],
    )
    admit_both("fund-rustoshi-wallet", fund_tx["hex"])
    sync_generated(1)
    log("rustoshi rescan: " + json.dumps(rust.rpc("rescanblockchain", []), default=str))
    rust_unspent = rust.rpc("listunspent", [1, 9999999])
    log("rustoshi listunspent: " + json.dumps(rust_unspent, default=str)[:1500])
    if not rust_unspent:
        die("rustoshi wallet saw no coins after rescanblockchain")
    core_addr = core.cli_json("-rpcwallet=sweep", "getnewaddress", "", "bech32")
    rust_addr = rust.rpc("getnewaddress", ["", "bech32"])

    def record_wallet(name: str, method: str, core_params: list, rust_params: list) -> None:
        log(f"=== {name} ===")
        c_out = core.wallet_outcome(method, core_params)
        r_out = rust.rpc_outcome(method, rust_params)
        log("core: " + json.dumps(c_out, default=str))
        log("rustoshi: " + json.dumps(r_out, default=str))
        mismatches = compare_outcome(c_out, r_out, method)
        for item in mismatches:
            log(
                f"  MISMATCH {item['field']}: "
                f"core={item['core']!r} rustoshi={item['rustoshi']!r}"
            )
        cases.append(
            {
                "name": name,
                "core": c_out,
                "rustoshi": r_out,
                "mismatches": mismatches,
            }
        )

    record_wallet(
        "sendtoaddress-1sat",
        "sendtoaddress",
        [core_addr, "0.00000001"],
        [rust_addr, "0.00000001"],
    )
    record_wallet(
        "sendtoaddress-zero",
        "sendtoaddress",
        [core_addr, "0"],
        [rust_addr, "0"],
    )
    record_wallet(
        "sendtoaddress-negative",
        "sendtoaddress",
        [core_addr, "-0.00000001"],
        [rust_addr, "-0.00000001"],
    )
    record_wallet(
        "send-1sat",
        "send",
        [[{core_addr: "0.00000001"}], None, "unset", 1],
        [[{rust_addr: "0.00000001"}], None, "unset", 1],
    )
    record_wallet(
        "send-zero",
        "send",
        [[{core_addr: "0"}], None, "unset", 1],
        [[{rust_addr: "0"}], None, "unset", 1],
    )
    record_wallet(
        "send-negative",
        "send",
        [[{core_addr: "-0.00000001"}], None, "unset", 1],
        [[{rust_addr: "-0.00000001"}], None, "unset", 1],
    )
    record_wallet(
        "send-insufficient",
        "send",
        [[{core_addr: "1000000"}], None, "unset", 1],
        [[{rust_addr: "1000000"}], None, "unset", 1],
    )
    c_bal = core.wallet_outcome("getbalance", [])
    r_bal = rust.rpc_outcome("getbalance", [])
    log(f"wallet balance core={c_bal} rustoshi={r_bal}")
    if not c_bal.get("ok") or not r_bal.get("ok"):
        die(f"getbalance failed core={c_bal} rustoshi={r_bal}")
    record_wallet(
        "send-exact-balance-fee5",
        "send",
        [[{core_addr: str(c_bal["result"])}], None, "unset", 5],
        [[{rust_addr: str(r_bal["result"])}], None, "unset", 5],
    )
    record_wallet(
        "send-exact-balance-fee1",
        "send",
        [[{core_addr: str(c_bal["result"])}], None, "unset", 1],
        [[{rust_addr: str(r_bal["result"])}], None, "unset", 1],
    )

    def restart_nodes(log_name: str, core_extra: list[str], rust_extra: list[str]) -> None:
        nonlocal rust_proc, rust
        log(f"=== restart {log_name} core={core_extra} rustoshi={rust_extra} ===")
        stop_rustoshi(rust_proc)
        rust_proc = None
        stop_core(core_dir)
        for stale in (
            core_dir / "regtest" / "mempool.dat",
            rust_dir / "mempool.dat",
            rust_dir / "regtest" / "mempool.dat",
            rust_dir / ".cookie",
            rust_dir / "regtest" / ".cookie",
        ):
            stale.unlink(missing_ok=True)
        # -walletbroadcast=0: otherwise the wallet resubmits the pre-restart
        # mempool txs and Core's pool is not empty.
        start_core(core_dir, *core_extra)
        wait_rpc(core)
        wallets = core.rpc("listwallets")
        if "sweep" not in wallets:
            core.rpc("loadwallet", ["sweep"])
        log_path = WORKDIR / log_name
        rust_proc = start_rustoshi(rust_dir, log_path, *rust_extra)
        cookie_path = rust_dir / ".cookie"
        deadline = time.time() + 90
        while time.time() < deadline and not cookie_path.exists():
            if rust_proc.poll() is not None:
                die(
                    "rustoshi exited "
                    f"{rust_proc.returncode}: "
                    f"{log_path.read_text()[-2000:]}"
                )
            time.sleep(0.25)
        if not cookie_path.exists():
            die(f"no cookie after restart: {log_path.read_text()[-2000:]}")
        rust = RustNode(
            f"http://127.0.0.1:{RUST_RPC_PORT}",
            cookie_path.read_text().strip(),
        )
        wait_rpc(rust, 90)
        c_tip = {"height": core.rpc("getblockcount"), "hash": core.rpc("getbestblockhash")}
        r_tip = {"height": rust.rpc("getblockcount"), "hash": rust.rpc("getbestblockhash")}
        log(f"after restart tip core={c_tip} rustoshi={r_tip}")
        if c_tip != r_tip:
            die(f"tips diverged after restart: core={c_tip} rustoshi={r_tip}")
        if mempool_txids(core) or mempool_txids(rust):
            die(
                "mempools not empty after restart: "
                f"core={mempool_txids(core)} rustoshi={mempool_txids(rust)}"
            )

    def null_data(payload: int) -> bytes:
        if payload <= 75:
            body = bytes([payload]) + bytes(payload)
        elif payload <= 255:
            body = bytes([0x4C, payload]) + bytes(payload)
        else:
            body = b"\x4d" + payload.to_bytes(2, "little") + bytes(payload)
        return bytes([0x6A]) + body

    def get_fee(rate: int, vsize: int) -> int:
        return (rate * vsize + 999) // 1000

    def floor_sat_kvb(fee: int, vsize: int) -> int:
        return math.floor(fee / vsize * 1000)

    def signed_padded(coin: dict, fee: int, pad: int) -> dict:
        sats = sats_of(coin["amount"])
        if fee <= 0 or fee >= sats:
            die(f"pad fee {fee} does not fit coin {sats}")
        return signed_outputs(
            coin,
            [(sats - fee, spk_bytes), (0, null_data(pad))],
        )

    # Package CheckFeeRate uses modified fees. Parent fee is 1 sat. A +1
    # prioritisetransaction delta clears a package that is one sat under
    # GetFee. A -1 delta rejects a package whose base fee meets GetFee.
    def child_spending(parent: dict, fee: int) -> dict:
        change = next(v for v in parent["decoded"]["vout"] if sats_of(v["value"]) > 0)
        change_value = sats_of(change["value"])
        if fee <= 0 or fee >= change_value:
            die(f"child fee {fee} does not fit {change_value}")
        return sign_raw(
            raw_tx(
                [(bytes.fromhex(parent["decoded"]["txid"])[::-1], change["n"], b"")],
                [(change_value - fee, spk_bytes)],
            ).hex(),
            [
                {
                    "txid": parent["decoded"]["txid"],
                    "vout": change["n"],
                    "scriptPubKey": change["scriptPubKey"]["hex"],
                    "amount": btc(change_value),
                }
            ],
        )

    def prioritise(txid: str, delta: int) -> None:
        c_pri = core.rpc_outcome("prioritisetransaction", [txid, 0, delta])
        r_pri = rust.rpc_outcome("prioritisetransaction", [txid, 0, delta])
        log(f"prioritise {txid} {delta}: core={c_pri} rustoshi={r_pri}")
        mismatches = compare_outcome(c_pri, r_pri, "prioritisetransaction")
        if mismatches:
            cases.append(
                {
                    "name": f"prioritisetransaction-{txid}-{delta}",
                    "core": c_pri,
                    "rustoshi": r_pri,
                    "mismatches": mismatches,
                }
            )

    def modified_fee_package(child_fee_below_req: int, delta: int, name: str) -> None:
        coin = fresh_coin()
        parent = signed_outputs(coin, [(sats_of(coin["amount"]) - 1, spk_bytes)])
        parent_v = int(parent["decoded"]["vsize"])
        change_value = sats_of(coin["amount"]) - 1
        # A DER signature's length moves with the fee, so a probe at fee 1
        # does not fix the child's vsize. Search for a fee that is exactly
        # GetFee(package vsize) minus the requested shortfall at that vsize.
        found = None
        for fee in range(1, 80):
            if fee >= change_value:
                break
            trial = child_spending(parent, fee)
            pkg_v = parent_v + int(trial["decoded"]["vsize"])
            pkg_req = get_fee(100, pkg_v)
            if fee == pkg_req - child_fee_below_req:
                found = (trial, pkg_v, pkg_req, fee)
                break
        if found is None:
            die(f"{name} found no child fee whose vsize satisfies GetFee")
        child, pkg_v, pkg_req, child_fee = found
        log(
            f"{name} parent_vsize={parent['decoded']['vsize']} "
            f"pkg_vsize={pkg_v} pkg_req={pkg_req} child_fee={child_fee} "
            f"base={1 + child_fee} delta={delta}"
        )
        prioritise(parent["decoded"]["txid"], delta)
        run_reached(name, [parent["hex"], child["hex"]], sendraw=[parent["hex"]])

    modified_fee_package(2, 1, "package-modified-fee-positive")
    modified_fee_package(1, -1, "package-modified-fee-negative")

    # Package RBF. Expectations come from the Core node this sweep is
    # talking to. A construction that does not reach the path it names
    # is a sweep bug and stops the run.
    def relay_sats(vsize: int) -> int:
        return (100 * vsize + 999) // 1000

    def tx_vsize(tx: dict) -> int:
        return int(tx["decoded"]["vsize"])

    def package_msg_of(obj) -> str:
        if not isinstance(obj, dict):
            return "n/a"
        if "package_msg" in obj:
            return str(obj["package_msg"])
        inner = obj.get("result")
        if isinstance(inner, dict) and "package_msg" in inner:
            return str(inner["package_msg"])
        if obj.get("ok") is False:
            return f"error {obj.get('code')}: {obj.get('message')}"
        return "n/a"

    def outcome_result(obj) -> dict | None:
        if not isinstance(obj, dict) or not obj.get("ok"):
            return None
        inner = obj.get("result")
        return inner if isinstance(inner, dict) else None

    def require_core_path(name: str, outcome: dict, needle: str) -> None:
        msg = package_msg_of(outcome)
        if needle not in msg:
            die(f"{name}: Core package_msg {msg!r} does not contain {needle!r}")

    def fit_vsize(build, target: int) -> dict:
        """`build(payload, locktime)` signs one tx.

        payload None is the unpadded tx. The smallest OP_RETURN output is 11
        vbytes, so a 1-vbyte gap (a 70-byte DER sig) cannot be closed that way.
        Locktime is ignored when every sequence is 0xffffffff, but it changes
        the sighash and therefore the signature length.
        """
        bare = build(None, 0)
        if tx_vsize(bare) == target:
            return bare
        gap = target - tx_vsize(bare)
        if gap >= 11:
            for payload in range(0, 80):
                trial = build(payload, 0)
                if tx_vsize(trial) == target:
                    return trial
        for locktime in range(0, 400):
            trial = build(None, locktime)
            if tx_vsize(trial) == target:
                return trial
        die(
            f"vsize {tx_vsize(bare)} cannot be brought to {target} "
            f"(last tried {tx_vsize(trial)})"
        )

    def spend_exact(coin: dict, fee: int, target: int, version: int = 2) -> dict:
        sats = sats_of(coin["amount"])

        def build(payload, locktime):
            outputs = [(sats - fee, spk_bytes)]
            if payload is not None:
                outputs.append((0, null_data(payload)))
            return signed_outputs(coin, outputs, version=version, locktime=locktime)

        return fit_vsize(build, target)

    def child_exact(parent: dict, fee: int, target: int, version: int = 2) -> dict:
        change = next(v for v in parent["decoded"]["vout"] if sats_of(v["value"]) > 0)
        change_value = sats_of(change["value"])
        prev = {
            "txid": parent["decoded"]["txid"],
            "vout": change["n"],
            "scriptPubKey": change["scriptPubKey"]["hex"],
            "amount": btc(change_value),
        }

        def build(payload, locktime):
            outputs = [(change_value - fee, spk_bytes)]
            if payload is not None:
                outputs.append((0, null_data(payload)))
            raw = raw_tx(
                [(bytes.fromhex(parent["decoded"]["txid"])[::-1], change["n"], b"")],
                outputs,
                version=version,
                locktime=locktime,
            ).hex()
            return sign_raw(raw, [prev])

        return fit_vsize(build, target)

    def make_child(
        parent: dict,
        fee: int,
        version: int = 2,
        extra_coins: list[dict] | None = None,
        extra_outputs: list[tuple[int, bytes]] | None = None,
    ) -> dict:
        dec = parent["decoded"]
        inputs = []
        prevs = []
        total = 0
        for vout in dec["vout"]:
            spk_hex = vout["scriptPubKey"]["hex"]
            if spk_hex.startswith("6a"):
                continue
            inputs.append((bytes.fromhex(dec["txid"])[::-1], vout["n"], b""))
            amount = sats_of(vout["value"])
            prevs.append(
                {
                    "txid": dec["txid"],
                    "vout": vout["n"],
                    "scriptPubKey": spk_hex,
                    "amount": btc(amount),
                }
            )
            total += amount
        for extra in extra_coins or []:
            amount = sats_of(extra["amount"])
            inputs.append(
                (bytes.fromhex(extra["txid"])[::-1], int(extra["vout"]), b"")
            )
            prevs.append(
                {
                    "txid": extra["txid"],
                    "vout": int(extra["vout"]),
                    "scriptPubKey": extra["scriptPubKey"],
                    "amount": btc(amount),
                }
            )
            total += amount
        if fee <= 0 or fee >= total:
            die(f"child fee {fee} does not fit inputs {total}")
        outputs = [(total - fee, spk_bytes)]
        outputs.extend(extra_outputs or [])
        raw = raw_tx(inputs, outputs, version=version).hex()
        return sign_raw(raw, prevs)

    def spend_coins(coins: list[dict], fee: int, version: int = 2) -> dict:
        inputs = []
        prevs = []
        total = 0
        for coin in coins:
            amount = sats_of(coin["amount"])
            inputs.append(
                (bytes.fromhex(coin["txid"])[::-1], int(coin["vout"]), b"")
            )
            prevs.append(
                {
                    "txid": coin["txid"],
                    "vout": int(coin["vout"]),
                    "scriptPubKey": coin["scriptPubKey"],
                    "amount": btc(amount),
                }
            )
            total += amount
        if fee <= 0 or fee >= total:
            die(f"multi fee {fee} does not fit inputs {total}")
        raw = raw_tx(inputs, [(total - fee, spk_bytes)], version=version).hex()
        return sign_raw(raw, prevs)

    def must_match_submit(name: str, hex_tx: str) -> None:
        c_res = core.rpc_outcome("submitpackage", [[hex_tx]])
        r_res = rust.rpc_outcome("submitpackage", [[hex_tx]])
        mismatches = compare_outcome(c_res, r_res, "submitpackage")
        if mempool_txids(core) != mempool_txids(rust):
            mismatches.append(
                {
                    "field": "getrawmempool",
                    "core": mempool_txids(core),
                    "rustoshi": mempool_txids(rust),
                    "out_of_scope": None,
                }
            )
        if not c_res.get("ok") or package_msg_of(c_res) != "success":
            die(f"{name}: Core rejected setup tx: {package_msg_of(c_res)}")
        if mismatches:
            cases.append(
                {
                    "name": name,
                    "core": c_res,
                    "rustoshi": r_res,
                    "mismatches": mismatches,
                }
            )
            die(f"{name}: rustoshi diverged while admitting a package RBF input")

    def run_package_rbf(name: str, hexes: list[str], focus_extra: list[str] | None = None) -> dict:
        log(f"=== {name} ===")
        mismatches: list[dict] = []
        c_res = core.rpc_outcome("submitpackage", [hexes])
        r_res = rust.rpc_outcome("submitpackage", [hexes])
        log("core submitpackage: " + json.dumps(c_res, default=str)[:4000])
        log("rustoshi submitpackage: " + json.dumps(r_res, default=str)[:4000])
        mismatches.extend(compare_outcome(c_res, r_res, "submitpackage"))
        focus = package_txids(hexes) + (focus_extra or [])
        c_mem = core.rpc("getrawmempool", [True])
        r_mem = rust.rpc("getrawmempool", [True])
        log(
            f"  mempool size core={len(c_mem) if isinstance(c_mem, dict) else c_mem} "
            f"rustoshi={len(r_mem) if isinstance(r_mem, dict) else r_mem}"
        )
        mismatches.extend(compare_verbose(c_mem, r_mem, focus))
        for m in mismatches:
            shown = m["core"]
            if isinstance(shown, (dict, list)) and len(json.dumps(shown, default=str)) > 400:
                shown = json.dumps(shown, default=str)[:400] + "…"
            tag = "OUT_OF_SCOPE" if m["out_of_scope"] else "MISMATCH"
            log(f"  {tag} {m['field']}: core={shown!r} rustoshi={m['rustoshi']!r}")
            if m["out_of_scope"]:
                log(f"    why: {m['out_of_scope']}")
        cases.append(
            {
                "name": name,
                "core": c_res,
                "rustoshi": r_res,
                "mismatches": mismatches,
            }
        )
        return c_res

    def coin_at_least(min_sats: int) -> dict:
        coins = [c for c in spendable_coins() if sats_of(c["amount"]) > min_sats]
        if not coins:
            sync_generated(1)
            coins = [c for c in spendable_coins() if sats_of(c["amount"]) > min_sats]
        if not coins:
            die(f"no confirmed coin above {min_sats} sats")
        return max(coins, key=lambda c: sats_of(c["amount"]))

    def one_conflict_package(original_fee: int, parent_fee: int, child_fee: int, version: int = 2):
        coin = coin_at_least(parent_fee + child_fee + 1000)
        original = spend_exact(coin, original_fee, 110, version=version)
        must_match_submit(f"package-rbf-setup-{original['decoded']['txid'][:8]}", original["hex"])
        parent = spend_exact(coin, parent_fee, 110, version=version)
        child = child_exact(parent, child_fee, 110, version=version)
        assert tx_vsize(parent) == 110 and tx_vsize(child) == 110
        return original, parent, child

    # (a) Parent alone is one sat short of the conflict plus incremental
    # relay. The child funds the replacement. vsize 110+110, fees
    # 10001+50000 → effective feerate 272731 sat/kvB.
    original, parent, child = one_conflict_package(10_000, 10_001, 50_000)
    log(
        f"package-rbf-child-pays vsizes parent={tx_vsize(parent)} "
        f"child={tx_vsize(child)} original={tx_vsize(original)}"
    )
    child_pays = run_package_rbf(
        "package-rbf-child-pays",
        [parent["hex"], child["hex"]],
        [original["decoded"]["txid"]],
    )
    require_core_path("package-rbf-child-pays", child_pays, "success")
    child_pays_body = outcome_result(child_pays)
    if child_pays_body is None:
        die("package-rbf-child-pays: Core submitpackage was not ok")
    if child_pays_body.get("replaced-transactions") != [original["decoded"]["txid"]]:
        die(
            "package-rbf-child-pays: Core replaced-transactions "
            f"{child_pays_body.get('replaced-transactions')!r}"
        )
    for entry in (child_pays_body.get("tx-results") or {}).values():
        rate = (entry.get("fees") or {}).get("effective-feerate")
        if rate != Decimal("0.00272731"):
            die(f"package-rbf-child-pays: Core effective-feerate {rate!r}")

    # (b) Child fee does not cover incremental relay against the conflict.
    original, parent, _child = one_conflict_package(10_000, 10_001, 10)
    # one_conflict_package already built a 10-sat child at vsize 110.
    # Rebuild is unnecessary: that child is the anti-DoS shape.
    anti = run_package_rbf(
        "package-rbf-anti-dos",
        [parent["hex"], _child["hex"]],
        [original["decoded"]["txid"]],
    )
    require_core_path("package-rbf-anti-dos", anti, "insufficient anti-DoS fees")

    # (c) Anti-DoS passes and the package feerate is still <= the parent.
    # Search the child fee against the signed vsizes. Core's CFeeRate <=
    # is a cross-multiply, and PaysForRBF uses ceiling GetFee.
    feerate_coin_original, feerate_parent, _ignored = one_conflict_package(10_000, 10_001, 21)
    # The pinned 21-sat child may or may not land on the right side of
    # GetFee once the signature length is known. Search below.
    del _ignored

    def parent_feerate_ok(parent_tx, child_tx, fee):
        pv = tx_vsize(parent_tx)
        cv = tx_vsize(child_tx)
        total_fee = 10_001 + fee
        total_v = pv + cv
        additional = total_fee - 10_000
        if additional < relay_sats(total_v):
            return False
        return total_fee * pv <= 10_001 * total_v

    # one_conflict_package already admitted an original. Find the child
    # on that same parent instead of spending another coin.
    feerate_child = None
    change_room = sats_of(
        next(v["value"] for v in feerate_parent["decoded"]["vout"] if sats_of(v["value"]) > 0)
    )
    for fee in range(1, min(change_room, 20_000)):
        trial = make_child(feerate_parent, fee)
        if parent_feerate_ok(feerate_parent, trial, fee):
            feerate_child = trial
            log(
                f"package-rbf-feerate-le-parent child_fee={fee} "
                f"vsize={tx_vsize(feerate_parent)}+{tx_vsize(trial)}"
            )
            break
    if feerate_child is None:
        die("no child fee with package feerate <= parent and anti-DoS paid")
    feerate_res = run_package_rbf(
        "package-rbf-feerate-le-parent",
        [feerate_parent["hex"], feerate_child["hex"]],
        [feerate_coin_original["decoded"]["txid"]],
    )
    require_core_path(
        "package-rbf-feerate-le-parent",
        feerate_res,
        "package feerate is less than or equal to parent feerate",
    )

    # (f) Absolute package fee beats the conflict, package feerate beats
    # the parent, and the chunk diagram does not.
    diagram_original, diagram_parent, _ignored = one_conflict_package(50_000, 10_001, 45_000)
    del _ignored
    diagram_child = None
    for fee in (45_000, 40_000, 30_000, 20_000, 60_000):
        trial = make_child(diagram_parent, fee)
        pv = tx_vsize(diagram_parent)
        cv = tx_vsize(trial)
        ov = tx_vsize(diagram_original)
        total_fee = 10_001 + fee
        total_v = pv + cv
        additional = total_fee - 50_000
        if additional < relay_sats(total_v):
            continue
        if total_fee * pv <= 10_001 * total_v:
            continue
        # Higher total fee, lower feerate than the conflict: CompareChunks
        # is unordered, which PackageRBFChecks rejects.
        if total_fee > 50_000 and total_fee * ov < 50_000 * total_v:
            diagram_child = trial
            log(
                f"package-rbf-feerate-diagram child_fee={fee} "
                f"vsize original={ov} package={total_v}"
            )
            break
    if diagram_child is None:
        die("no child fee that fails only the feerate diagram")
    diagram_res = run_package_rbf(
        "package-rbf-feerate-diagram",
        [diagram_parent["hex"], diagram_child["hex"]],
        [diagram_original["decoded"]["txid"]],
    )
    require_core_path(
        "package-rbf-feerate-diagram",
        diagram_res,
        "insufficient feerate: does not improve feerate diagram",
    )

    # (g) 1p1c package RBF whose child is over TRUC_CHILD_MAX_VSIZE.
    # The non-TRUC package clears parent feerate, anti-DoS, and the
    # diagram, so Core accepts it. The v3 package dies in
    # PackageTRUCChecks before those checks. Same fee shape, two coins.
    def oversized_child(parent: dict, version: int) -> tuple[dict, int]:
        payload_hit = None
        for payload in range(900, 1600, 20):
            probe = make_child(
                parent,
                50_000,
                version=version,
                extra_outputs=[(0, null_data(payload))],
            )
            size = tx_vsize(probe)
            if 1000 < size <= 10_000:
                payload_hit = payload
                break
        if payload_hit is None:
            die(f"version {version} child never landed in (1000, 10000] vbytes")
        # Second pass uses the signed size. fee * parent_vsize must beat
        # parent_fee * package_vsize, with margin for a 1-byte signature.
        pv = tx_vsize(parent)
        cv = tx_vsize(probe)
        fee = (10_001 * cv) // pv + 20_000
        child = make_child(
            parent,
            fee,
            version=version,
            extra_outputs=[(0, null_data(payload_hit))],
        )
        cv = tx_vsize(child)
        total_fee = 10_001 + fee
        total_v = pv + cv
        if not (1000 < cv <= 10_000):
            die(f"version {version} child vsize {cv} left the TRUC child window")
        if total_fee * pv <= 10_001 * total_v:
            die(
                f"version {version} package feerate does not beat the parent "
                f"({total_fee}/{total_v} vs 10001/{pv})"
            )
        if total_fee * 110 <= 10_000 * total_v:
            die(
                f"version {version} package feerate does not beat the conflict "
                f"({total_fee}/{total_v})"
            )
        log(f"version {version} oversized child fee={fee} vsize={cv} payload={payload_hit}")
        return child, fee

    def conflict_110(version: int):
        # The oversized child fee is about parent_fee * child_vsize / parent_vsize.
        coin = coin_at_least(2_000_000)
        original = spend_exact(coin, 10_000, 110, version=version)
        must_match_submit(
            f"package-rbf-v{version}-original-{original['decoded']['txid'][:8]}",
            original["hex"],
        )
        parent = spend_exact(coin, 10_001, 110, version=version)
        return original, parent

    plain_original, plain_parent = conflict_110(2)
    plain_child, _plain_fee = oversized_child(plain_parent, 2)
    plain_res = run_package_rbf(
        "package-rbf-large-child",
        [plain_parent["hex"], plain_child["hex"]],
        [plain_original["decoded"]["txid"]],
    )
    require_core_path("package-rbf-large-child", plain_res, "success")
    truc_original, truc_parent = conflict_110(3)
    truc_child, _truc_fee = oversized_child(truc_parent, 3)
    truc_res = run_package_rbf(
        "package-rbf-truc",
        [truc_parent["hex"], truc_child["hex"]],
        [truc_original["decoded"]["txid"]],
    )
    if package_msg_of(truc_res) == package_msg_of(plain_res):
        die(
            "TRUC package RBF package_msg matches the non-TRUC control "
            f"({package_msg_of(truc_res)!r}); Core did not treat v3 differently"
        )
    require_core_path("package-rbf-truc", truc_res, "TRUC-violation")

    # (d) 60 clusters on the parent and 41 on the child. Each side is
    # under GetEntriesForConflicts' limit of 100; the union is not.
    # One confirmed fan-out creates the coins. Independent mempool
    # spends are the clusters the package conflicts with.
    if mempool_txids(core) != mempool_txids(rust):
        die(
            "mempools diverged before the cluster fan-out: "
            f"core={len(mempool_txids(core))} rustoshi={len(mempool_txids(rust))}"
        )
    sync_generated(1)
    fan_coin = max(spendable_coins(), key=lambda c: sats_of(c["amount"]))
    fan_sats = sats_of(fan_coin["amount"])
    cluster_n = 101
    each = 100_000
    fan_fee = 10_000
    if fan_sats <= each * cluster_n + fan_fee:
        die(f"fan-out coin {fan_sats} cannot fund {cluster_n} outputs")
    fan_outputs = [(each, spk_bytes)] * cluster_n
    fan_outputs.append((fan_sats - each * cluster_n - fan_fee, spk_bytes))
    fan_tx = signed_outputs(fan_coin, fan_outputs)
    must_match_submit("package-rbf-cluster-fanout", fan_tx["hex"])
    sync_generated(1)
    fan_coins = []
    for vout in fan_tx["decoded"]["vout"]:
        if sats_of(vout["value"]) != each:
            continue
        fan_coins.append(
            {
                "txid": fan_tx["decoded"]["txid"],
                "vout": vout["n"],
                "scriptPubKey": vout["scriptPubKey"]["hex"],
                "amount": vout["value"],
            }
        )
    if len(fan_coins) != cluster_n:
        die(f"fan-out produced {len(fan_coins)} coins, want {cluster_n}")
    conflict_ids = []
    for i, coin in enumerate(fan_coins):
        conflict = signed_outputs(coin, [(each - 1_000, spk_bytes)])
        must_match_submit(f"package-rbf-cluster-conflict-{i}", conflict["hex"])
        conflict_ids.append(conflict["decoded"]["txid"])
        if i % 25 == 24:
            log(f"  admitted {i + 1} conflicting clusters")
    parent_coins = fan_coins[:60]
    child_coins = fan_coins[60:]
    cluster_parent = spend_coins(parent_coins, 10_001)
    cluster_child = make_child(cluster_parent, 50_000, extra_coins=child_coins)
    log(
        f"package-rbf-too-many-clusters parent_inputs={len(parent_coins)} "
        f"child_extra={len(child_coins)} "
        f"parent_vsize={tx_vsize(cluster_parent)} child_vsize={tx_vsize(cluster_child)}"
    )
    cluster_res = run_package_rbf(
        "package-rbf-too-many-clusters",
        [cluster_parent["hex"], cluster_child["hex"]],
        conflict_ids,
    )
    require_core_path(
        "package-rbf-too-many-clusters",
        cluster_res,
        "too many conflicting clusters",
    )

    # Rate 1005 sat/kvB is the smallest rate whose CFeeRate::GetFee(vsize)
    # disagrees with floor(fee/vsize*1000). vsize 200, fee 201 floors to 1004.
    # The rolling floor has no RPC on either node; the unit test covers it.
    restart_nodes(
        "rustoshi-feerate.log",
        ["-minrelaytxfee=0.00001005", "-walletbroadcast=0"],
        ["--minrelaytxfee=0.00001005"],
    )
    boundary_coin = fresh_coin()
    boundary = None
    base_v = int(signed_padded(boundary_coin, 201, 0)["decoded"]["vsize"])
    for target in (200, 400, 600):
        guess = max(0, target - base_v)
        for pad in range(max(0, guess - 8), guess + 48):
            probe_v = int(signed_padded(boundary_coin, 201, pad)["decoded"]["vsize"])
            if probe_v not in (200, 400, 600):
                continue
            fee = get_fee(1005, probe_v)
            exact = signed_padded(boundary_coin, fee, pad)
            low = signed_padded(boundary_coin, fee - 1, pad)
            exact_v = int(exact["decoded"]["vsize"])
            low_v = int(low["decoded"]["vsize"])
            if exact_v != probe_v or low_v != probe_v:
                continue
            if floor_sat_kvb(fee, exact_v) >= 1005:
                continue
            boundary = (exact, low, exact_v, fee, pad)
            break
        if boundary:
            break
    if boundary is None:
        die("no vsize where floor(fee*1000/vsize) disagrees with GetFee")
    exact_tx, low_tx, exact_v, exact_fee, exact_pad = boundary
    log(
        f"fee boundary vsize={exact_v} fee={exact_fee} "
        f"floor={floor_sat_kvb(exact_fee, exact_v)} pad={exact_pad} "
        f"getfee={get_fee(1005, exact_v)}"
    )
    # One sat under first: it must be rejected, so the coin is still free
    # for the GetFee-sized tx that both nodes accept.
    run_reached(
        "fee-one-sat-under-getfee",
        [low_tx["hex"]],
        sendraw=[low_tx["hex"]],
    )
    run_reached(
        "fee-getfee-boundary",
        [exact_tx["hex"]],
        sendraw=[exact_tx["hex"]],
    )

    package_coin = fresh_coin()
    package_hit = None
    parent_base = int(signed_padded(package_coin, 1, 0)["decoded"]["vsize"])
    for target in (400, 600, 200):
        guess = max(0, target - parent_base - 140)
        for pad in range(guess, guess + 80):
            parent = signed_padded(package_coin, 1, pad)
            change = next(
                v for v in parent["decoded"]["vout"] if sats_of(v["value"]) > 0
            )
            change_value = sats_of(change["value"])
            child_probe = sign_raw(
                raw_tx(
                    [(bytes.fromhex(parent["decoded"]["txid"])[::-1], change["n"], b"")],
                    [(change_value - 1, spk_bytes)],
                ).hex(),
                [
                    {
                        "txid": parent["decoded"]["txid"],
                        "vout": change["n"],
                        "scriptPubKey": change["scriptPubKey"]["hex"],
                        "amount": btc(change_value),
                    }
                ],
            )
            combined = int(parent["decoded"]["vsize"]) + int(child_probe["decoded"]["vsize"])
            if combined not in (200, 400, 600):
                continue
            fee = get_fee(1005, combined)
            if fee <= 2 or change_value <= fee:
                continue
            child = sign_raw(
                raw_tx(
                    [(bytes.fromhex(parent["decoded"]["txid"])[::-1], change["n"], b"")],
                    [(change_value - (fee - 1), spk_bytes)],
                ).hex(),
                [
                    {
                        "txid": parent["decoded"]["txid"],
                        "vout": change["n"],
                        "scriptPubKey": change["scriptPubKey"]["hex"],
                        "amount": btc(change_value),
                    }
                ],
            )
            combined2 = int(parent["decoded"]["vsize"]) + int(child["decoded"]["vsize"])
            if combined2 != combined or floor_sat_kvb(fee, combined2) >= 1005:
                continue
            package_hit = (parent, child, combined2, fee, pad)
            break
        if package_hit:
            break
    if package_hit is None:
        die("no package vsize where floor(fee*1000/vsize) disagrees with GetFee")
    pkg_parent, pkg_child, pkg_v, pkg_fee, pkg_pad = package_hit
    log(
        f"package fee boundary vsize={pkg_v} fee={pkg_fee} "
        f"floor={floor_sat_kvb(pkg_fee, pkg_v)} pad={pkg_pad}"
    )
    run_reached(
        "package-fee-getfee-boundary",
        [pkg_parent["hex"], pkg_child["hex"]],
        sendraw=[pkg_parent["hex"]],
    )

    # 4. require_standard off. A >=65-byte nonstandard output is accepted;
    # the 65-byte floor still rejects the undersized OP_RETURN. Empty
    # scriptPubKeys are nonstandard, so IsDust is not reached while
    # standardness is on (IsStandardTx returns scriptpubkey first).
    restart_nodes(
        "rustoshi-nonstd.log",
        ["-acceptnonstdtxn=1", "-walletbroadcast=0"],
        ["--acceptnonstdtxn"],
    )

    nonstd_script = bytes([0x51]) + bytes([0x61]) * 20
    nonstd_coin = spendable_coins()[0]
    nonstd_parent = signed_outputs(
        nonstd_coin,
        [(sats_of(nonstd_coin["amount"]) - 10_000, nonstd_script)],
    )
    nonstd_value = sats_of(nonstd_parent["decoded"]["vout"][0]["value"])
    # Empty scriptSig. OP_TRUE then OP_NOPs leaves a single true stack item.
    nonstd_child_raw = raw_tx(
        [(bytes.fromhex(nonstd_parent["decoded"]["txid"])[::-1], 0, b"")],
        [(nonstd_value - 1_000, spk_bytes)],
    ).hex()
    nonstd_child = {"hex": nonstd_child_raw, "decoded": core.rpc("decoderawtransaction", [nonstd_child_raw])}
    run_reached(
        "acceptnonstdtxn-package",
        [nonstd_parent["hex"], nonstd_child["hex"]],
    )
    run_reached("tx-size-small-still", [op_ret.hex()], sendraw=[op_ret.hex()])

    def nonwitness_size(tx_hex: str, decoded: dict) -> int:
        raw = bytes.fromhex(tx_hex)
        if len(raw) >= 6 and raw[4] == 0x00:
            size = int(decoded["size"])
            weight = int(decoded["weight"])
            return (weight - size + 2) // 3
        return len(raw)

    def empty_spk_tx(coin: dict, empty_value: int, fee: int) -> dict:
        sats = sats_of(coin["amount"])
        change = sats - empty_value - fee
        if change <= 0:
            die(f"empty-spk change {change} for value {empty_value} fee {fee}")
        signed = signed_outputs(coin, [(change, spk_bytes), (empty_value, b"")])
        base = nonwitness_size(signed["hex"], signed["decoded"])
        if base < 65:
            die(f"empty-spk tx base size {base} is below the 65-byte floor")
        return signed

    # Empty script is spendable. GetDustThreshold sizes it as 9 + 148 = 157,
    # and CFeeRate(3000).GetFee(157) is 471, so 0 and 1 are both dust. With
    # acceptnonstdtxn, IsStandard and PreCheckEphemeralTx are skipped, so a
    # fee that clears min relay is accepted and a 0 fee is min-relay.
    zero_fee_coin = fresh_coin()
    empty_zero_fee = empty_spk_tx(zero_fee_coin, 0, 0)
    run_reached(
        "empty-spk-zero-value-zero-fee",
        [empty_zero_fee["hex"]],
        sendraw=[empty_zero_fee["hex"]],
    )
    paid_zero = empty_spk_tx(fresh_coin(), 0, 10_000)
    run_reached(
        "empty-spk-zero-value-with-fee",
        [paid_zero["hex"]],
        sendraw=[paid_zero["hex"]],
    )
    paid_one = empty_spk_tx(fresh_coin(), 1, 10_000)
    run_reached(
        "empty-spk-positive-value",
        [paid_one["hex"]],
        sendraw=[paid_one["hex"]],
    )

    # require_standard is off, so Core skips CheckEphemeralSpends. The child
    # spends the value output and leaves the 0-value empty output unspent.
    unspent_parent = empty_spk_tx(fresh_coin(), 0, 10_000)
    unspent_change = next(
        v for v in unspent_parent["decoded"]["vout"] if sats_of(v["value"]) > 0
    )
    unspent_empty = next(
        v for v in unspent_parent["decoded"]["vout"] if sats_of(v["value"]) == 0
    )
    if unspent_empty["scriptPubKey"]["hex"] != "":
        die(f"expected an empty scriptPubKey, got {unspent_empty}")
    unspent_value = sats_of(unspent_change["value"])
    unspent_child = sign_raw(
        raw_tx(
            [
                (
                    bytes.fromhex(unspent_parent["decoded"]["txid"])[::-1],
                    unspent_change["n"],
                    b"",
                )
            ],
            [(unspent_value - 1_000, spk_bytes)],
        ).hex(),
        [
            {
                "txid": unspent_parent["decoded"]["txid"],
                "vout": unspent_change["n"],
                "scriptPubKey": unspent_change["scriptPubKey"]["hex"],
                "amount": btc(unspent_value),
            }
        ],
    )
    run_reached(
        "acceptnonstd-unspent-empty-output",
        [unspent_parent["hex"], unspent_child["hex"]],
    )

    # invalidateblock / reconsiderblock of the current tip.
    log("=== invalidateblock / reconsiderblock ===")
    tip = core.rpc("getbestblockhash")
    rust_tip = rust.rpc("getbestblockhash")
    header = core.rpc("getblockheader", [tip])
    parent_hash = header["previousblockhash"]
    parent_height = header["height"] - 1
    log(f"tip={tip} parent={parent_hash} height={header['height']}")
    if rust_tip != tip:
        log(f"MISMATCH tips already differ before invalidate: core={tip} rustoshi={rust_tip}")

    core.rpc("invalidateblock", [tip])
    rust.rpc("invalidateblock", [tip])
    c_after_inv = {
        "height": core.rpc("getblockcount"),
        "hash": core.rpc("getbestblockhash"),
    }
    r_after_inv = {
        "height": rust.rpc("getblockcount"),
        "hash": rust.rpc("getbestblockhash"),
    }
    log(f"after invalidate core={c_after_inv} rustoshi={r_after_inv}")
    core.rpc("reconsiderblock", [tip])
    rust.rpc("reconsiderblock", [tip])
    c_after_re = {
        "height": core.rpc("getblockcount"),
        "hash": core.rpc("getbestblockhash"),
    }
    r_after_re = {
        "height": rust.rpc("getblockcount"),
        "hash": rust.rpc("getbestblockhash"),
    }
    log(f"after reconsider core={c_after_re} rustoshi={r_after_re}")
    reconsider = {
        "invalidated": tip,
        "expected_parent": parent_hash,
        "expected_parent_height": parent_height,
        "after_invalidate": {"core": c_after_inv, "rustoshi": r_after_inv},
        "after_reconsider": {"core": c_after_re, "rustoshi": r_after_re},
    }
    if c_after_inv != r_after_inv:
        log(
            "MISMATCH after invalidateblock: "
            f"core={c_after_inv} rustoshi={r_after_inv}"
        )
    if c_after_re != r_after_re:
        log(
            "MISMATCH after reconsiderblock: "
            f"core={c_after_re} rustoshi={r_after_re}"
        )
        log(
            "  why: this branch is master reconsider_block (clears FAILED flags, "
            "does not ActivateBestChain). PR #7 invalidated-submit adds "
            "activate_best_chain_after_reconsider. Not fixed on this branch."
        )

    if c_after_re != r_after_re:
        log(
            "OUT_OF_SCOPE reconsiderblock tip: "
            f"core={c_after_re} rustoshi={r_after_re}. "
            "PR #7 invalidated-submit restores the tip. Not fixed on this branch."
        )

    report = {
        "cases": cases,
        "reconsider": reconsider,
    }
    out = WORKDIR / "report.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    log(f"wrote {out}")

    in_scope = []
    out_of_scope = []
    for case in cases:
        for m in case["mismatches"]:
            entry = (case["name"], m)
            if m.get("out_of_scope"):
                out_of_scope.append(entry)
            else:
                in_scope.append(entry)
    if c_after_inv != r_after_inv:
        in_scope.append(
            (
                "invalidateblock",
                {"field": "after_invalidate", "core": c_after_inv, "rustoshi": r_after_inv},
            )
        )
    if c_after_re != r_after_re:
        out_of_scope.append(
            (
                "reconsiderblock",
                {
                    "field": "after_reconsider",
                    "core": c_after_re,
                    "rustoshi": r_after_re,
                    "out_of_scope": (
                        "PR #7 invalidated-submit calls activate_best_chain_after_reconsider. "
                        "This branch only clears FAILED flags."
                    ),
                },
            )
        )
    log(f"in-scope mismatches: {len(in_scope)}")
    for name, m in in_scope:
        log(f"  {name} {m.get('field')}: core={m.get('core')!r} rustoshi={m.get('rustoshi')!r}")
    log(f"out of scope (PR #7 verbose mempool / reconsiderblock): {len(out_of_scope)}")
    for name, m in out_of_scope:
        why = m.get("out_of_scope")
        log(f"  {name} {m.get('field')}: {why}")

    in_scope_names = {name for name, _m in in_scope}
    log("=== summary ===")
    log(f"{'case':<44} {'status':<9} core package_msg")
    log(f"{'':<44} {'':<9} rustoshi package_msg")
    n_mismatch = 0
    for case in cases:
        c_msg = package_msg_of(case["core"]).replace("\n", " ")
        r_msg = package_msg_of(case["rustoshi"]).replace("\n", " ")
        status = "mismatch" if case["name"] in in_scope_names else "match"
        if status == "mismatch":
            n_mismatch += 1
        log(f"{case['name']:<44} {status:<9} {c_msg}")
        log(f"{'':<44} {'':<9} {r_msg}")
    if c_after_inv != r_after_inv or c_after_re != r_after_re:
        inv_status = "mismatch" if c_after_inv != r_after_inv else "match"
        re_status = "mismatch" if "reconsiderblock" in in_scope_names else "match"
        log(f"{'invalidateblock':<44} {inv_status:<9} n/a")
        log(f"{'':<44} {'':<9} n/a")
        log(f"{'reconsiderblock':<44} {re_status:<9} n/a")
        log(f"{'':<44} {'':<9} n/a")
    log(
        f"summary: {len(cases)} cases, {n_mismatch} mismatch, "
        f"{len(cases) - n_mismatch} match, in-scope={len(in_scope)}"
    )

    stop_rustoshi(rust_proc)
    stop_core(core_dir)
    return 1 if in_scope else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log(f"FATAL: {e}")
        # Best-effort cleanup so a rerun can take the ports.
        subprocess.run(["pkill", "-f", f"datadir={WORKDIR / 'core'}"], check=False)
        subprocess.run(["pkill", "-f", str(WORKDIR / "rustoshi")], check=False)
        raise
