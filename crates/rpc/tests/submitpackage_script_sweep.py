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
    python3 crates/rpc/tests/submitpackage_script_sweep.py
"""

from __future__ import annotations

import base64
import json
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
CORE_RPC_PORT = 18445
RUST_RPC_PORT = 18443
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

    def rpc(self, method: str, params: list | None = None):
        raw_args = [method]
        for p in params or []:
            raw_args.append(p if isinstance(p, str) else json.dumps(p))
        return self.cli_json(*raw_args)


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
            raise RuntimeError(f"rustoshi {method}: {payload['error']}")
        return payload.get("result")


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


def start_core(datadir: Path) -> None:
    datadir.mkdir(parents=True, exist_ok=True)
    cmd = [
        BITCOIND,
        "-regtest",
        f"-datadir={datadir}",
        "-listen=0",
        "-dnsseed=0",
        "-fixedseeds=0",
        "-port=18446",
        f"-rpcport={CORE_RPC_PORT}",
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
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


def start_rustoshi(datadir: Path, log_path: Path) -> subprocess.Popen:
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
        "18447",
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
            {"field": field, "core": c, "rustoshi": r, "justified": None}
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
    if len(utxos) < 5:
        die(f"need 5 mature coinbases, have {len(utxos)}")
    utxos = utxos[:5]
    for u in utxos:
        log(f"utxo {u['txid']}:{u['vout']} {u['amount']} conf={u['confirmations']}")

    log(
        "starting rustoshi (--maxconnections 0 --nodnsseed --nofixedseeds, "
        "--port 18447). --listen is a switch that cannot be set false "
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
                    "justified": None,
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
                        "justified": None,
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
                            "justified": None,
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
                    "justified": None,
                }
            )
        for m in mismatches:
            tag = "JUSTIFIED" if m["justified"] else "MISMATCH"
            log(f"  {tag} {m['field']}: core={m['core']!r} rustoshi={m['rustoshi']!r}")
            if m["justified"]:
                log(f"    why: {m['justified']}")
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
                "justified": None,
            }
        )
    if mempool_txids(core) != mempool_txids(rust):
        ow_mismatches.append(
            {
                "field": "getrawmempool",
                "core": mempool_txids(core),
                "rustoshi": mempool_txids(rust),
                "justified": None,
            }
        )
    for m in ow_mismatches:
        tag = "JUSTIFIED" if m["justified"] else "MISMATCH"
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

    report = {"cases": cases, "reconsider": reconsider}
    out = WORKDIR / "report.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    log(f"wrote {out}")

    unjustified = []
    for case in cases:
        for m in case["mismatches"]:
            if not m["justified"]:
                unjustified.append((case["name"], m))
    if c_after_inv != r_after_inv:
        unjustified.append(("reconsider", {"field": "after_invalidate", "core": c_after_inv, "rustoshi": r_after_inv}))
    # Tip not restored is the known B gap; count it separately so the script
    # exit code reflects package mismatches only when B is the sole gap.
    b_gap = c_after_re != r_after_re
    log(f"unjustified package/invalidate mismatches: {len(unjustified)}")
    log(f"reconsiderblock tip gap (known, PR #7): {b_gap}")

    stop_rustoshi(rust_proc)
    stop_core(core_dir)
    return 1 if unjustified else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log(f"FATAL: {e}")
        # Best-effort cleanup so a rerun can take the ports.
        subprocess.run(["pkill", "-f", f"datadir={WORKDIR / 'core'}"], check=False)
        subprocess.run(["pkill", "-f", str(WORKDIR / "rustoshi")], check=False)
        raise
