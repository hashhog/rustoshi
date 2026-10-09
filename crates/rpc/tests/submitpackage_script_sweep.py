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

# Fields Core v31.1 submitpackage does not return. A difference that is only
# one of these being present on rustoshi is recorded, not treated as a
# value mismatch.
RUSTOSHI_EXTRA_TOP = {"package_feerate"}
RUSTOSHI_EXTRA_TX = {"allowed", "reject_reason", "wtxid"}


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
        out = self.cli(*args)
        if out == "":
            return None
        return json.loads(out, parse_float=Decimal)

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
        "--listen",
        "false",
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
    priv: str,
) -> dict:
    out_sats = prev_sats - fee_sats
    if out_sats <= 0:
        die(f"fee {fee_sats} exceeds input {prev_sats}")
    raw = core.cli(
        "createrawtransaction",
        json.dumps([{"txid": prev_txid, "vout": prev_vout}]),
        json.dumps([{dest: btc(out_sats)}]),
    )
    signed = core.cli_json(
        "signrawtransactionwithkey",
        raw,
        json.dumps([priv]),
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
        die(f"signrawtransactionwithkey incomplete: {signed}")
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


def norm_amount(v):
    if v is None:
        return None
    return f"{Decimal(str(v)):.8f}"


def compare_submit(core_res: dict, rust_res: dict) -> list[dict]:
    mismatches = []

    def add(field: str, c, r, justified: str | None = None):
        mismatches.append(
            {
                "field": field,
                "core": c,
                "rustoshi": r,
                "justified": justified,
            }
        )

    if core_res.get("package_msg") != rust_res.get("package_msg"):
        add("package_msg", core_res.get("package_msg"), rust_res.get("package_msg"))

    c_rep = core_res.get("replaced-transactions")
    r_rep = rust_res.get("replaced-transactions")
    if c_rep != r_rep:
        add("replaced-transactions", c_rep, r_rep)

    for key in sorted(set(rust_res) - set(core_res)):
        if key in RUSTOSHI_EXTRA_TOP:
            add(
                key,
                None,
                rust_res.get(key),
                "Core v31.1 submitpackage does not return this field",
            )
        else:
            add(key, None, rust_res.get(key))
    for key in sorted(set(core_res) - set(rust_res)):
        if key in ("package_msg", "tx-results", "replaced-transactions"):
            continue
        add(key, core_res.get(key), None)

    c_tx = core_res.get("tx-results") or {}
    r_tx = rust_res.get("tx-results") or {}
    for wtxid in sorted(set(c_tx) | set(r_tx)):
        c = c_tx.get(wtxid)
        r = r_tx.get(wtxid)
        prefix = f"tx-results[{wtxid[:12]}]"
        if c is None or r is None:
            add(prefix, c, r)
            continue
        if c.get("txid") != r.get("txid"):
            add(f"{prefix}.txid", c.get("txid"), r.get("txid"))
        if c.get("error") != r.get("error"):
            add(f"{prefix}.error", c.get("error"), r.get("error"))
        if c.get("vsize") != r.get("vsize"):
            add(f"{prefix}.vsize", c.get("vsize"), r.get("vsize"))
        c_fees = c.get("fees") or {}
        r_fees = r.get("fees") or {}
        if (c.get("fees") is None) != (r.get("fees") is None):
            add(f"{prefix}.fees", c.get("fees"), r.get("fees"))
        else:
            if norm_amount(c_fees.get("base")) != norm_amount(r_fees.get("base")):
                add(f"{prefix}.fees.base", c_fees.get("base"), r_fees.get("base"))
            c_eff = norm_amount(c_fees.get("effective-feerate"))
            r_eff = norm_amount(r_fees.get("effective-feerate"))
            if c_eff != r_eff:
                add(
                    f"{prefix}.fees.effective-feerate",
                    c_fees.get("effective-feerate"),
                    r_fees.get("effective-feerate"),
                    "rustoshi reports this tx's own feerate; Core v31.1 "
                    "AcceptPackage reports the package feerate "
                    "(effective-feerate / effective-includes)",
                )
            c_inc = c_fees.get("effective-includes")
            r_inc = r_fees.get("effective-includes")
            if c_inc != r_inc:
                add(
                    f"{prefix}.fees.effective-includes",
                    c_inc,
                    r_inc,
                    "Core lists every wtxid in the package fee calculation; "
                    "rustoshi lists only this tx",
                )
        for key in sorted(set(r) - set(c)):
            if key in RUSTOSHI_EXTRA_TX:
                add(
                    f"{prefix}.{key}",
                    None,
                    r.get(key),
                    "Core v31.1 submitpackage tx-results omit this field",
                )
            else:
                add(f"{prefix}.{key}", None, r.get(key))
        for key in sorted(set(c) - set(r)):
            if key in ("txid", "error", "vsize", "fees", "other-wtxid"):
                continue
            add(f"{prefix}.{key}", c.get(key), None)
    return mismatches


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
    priv = core.cli_json("-rpcwallet=sweep", "dumpprivkey", dest)
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
    if len(utxos) < 3:
        die(f"need 3 mature coinbases, have {len(utxos)}")
    utxos = utxos[:3]
    for u in utxos:
        log(f"utxo {u['txid']}:{u['vout']} {u['amount']} conf={u['confirmations']}")

    log("starting rustoshi (--maxconnections 0 --nodnsseed --nofixedseeds --listen false)")
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
        c_res = core.rpc("submitpackage", [[parent_hex, child_hex]])
        r_res = rust.rpc("submitpackage", [[parent_hex, child_hex]])
        log("core submitpackage: " + json.dumps(c_res, sort_keys=True, default=str))
        log("rustoshi submitpackage: " + json.dumps(r_res, sort_keys=True, default=str))
        mismatches = compare_submit(c_res, r_res)
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
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 1, dest, priv
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 20_000, dest, priv
    )
    run_case("valid-cpfp", parent["hex"], child["hex"], parent["txid"], child["txid"])

    # 2. Invalid-signature child. Parent fee 10_000 sat so it is individually valid.
    u = utxos[1]
    parent = make_signed(
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest, priv
    )
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 10_000, dest, priv
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
        core, u["txid"], u["vout"], sats_of(u["amount"]), spk, 10_000, dest, priv
    )
    bad_parent_hex = corrupt_witness_sig(parent["hex"], parent["witness"][0])
    bad_parent = core.cli_json("decoderawtransaction", bad_parent_hex)
    # Child spends the corrupted parent. txid is unchanged by a witness-only
    # mutation, so the signed child still refers to it.
    child = make_signed(
        core, parent["txid"], 0, parent["out_sats"], parent["spk"], 10_000, dest, priv
    )
    run_case(
        "invalid-sig-parent",
        bad_parent_hex,
        child["hex"],
        bad_parent["txid"],
        child["txid"],
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
