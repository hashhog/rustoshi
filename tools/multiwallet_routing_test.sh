#!/usr/bin/env bash
# multiwallet_routing_test.sh — regression test for /wallet/<name> URL routing.
#
# Usage: multiwallet_routing_test.sh <rustoshi-binary>
#
# Sequence (mirrors Core wallet/rpc/util.cpp:54-86 GetWalletForJSONRPCRequest):
#   createwallet w1; createwallet w2 (2 wallets loaded)
#   1. POST getwalletinfo to /wallet/w1 -> result.walletname == "w1"
#   2. POST getwalletinfo to /wallet/w2 -> result.walletname == "w2"
#   3. POST getwalletinfo to bare /     -> error -19 with Core's exact message
#   4. POST getwalletinfo to /wallet/nope -> error -18 "Requested wallet does
#      not exist or is not loaded"
#   5. unloadwallet w2; bare getwalletinfo -> routes to w1 (1 wallet loaded)
#   6. unloadwallet w1; bare getwalletinfo -> -18 "No wallet is loaded. ..."
# Exit 0 iff all checks pass. Scratch: /tmp/hashhog-mwroute-$$, self-cleans.
set -uo pipefail

BIN="${1:?usage: $0 <rustoshi-binary>}"
DATADIR="/tmp/hashhog-mwroute-$$"
RPC_PORT=41461
P2P_PORT=41462
NODE_PID=""
FAILS=0

log() { echo "[mwroute] $*" >&2; }
check() { # check <name> <ok:0/1> <detail>
    if [[ "$2" == 1 ]]; then log "PASS $1 $3"; else log "FAIL $1 $3"; FAILS=$((FAILS+1)); fi
}
cleanup() {
    local ec=$?
    [[ -n "$NODE_PID" ]] && kill "$NODE_PID" 2>/dev/null
    for _ in $(seq 1 15); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 1; done
    kill -9 "$NODE_PID" 2>/dev/null || true
    rm -rf "$DATADIR"
    return $ec
}
trap cleanup EXIT INT TERM

rm -rf "$DATADIR"; mkdir -p "$DATADIR"
"$BIN" --network=regtest --datadir="$DATADIR" \
    --port="$P2P_PORT" --rpcbind="127.0.0.1:$RPC_PORT" >"$DATADIR/node.log" 2>&1 &
NODE_PID=$!

rpc() { # rpc <path> <method> [params]
    local path=$1 method=$2 params="${3:-[]}" auth=""
    for c in "$DATADIR/.cookie" "$DATADIR/regtest/.cookie"; do
        [[ -f "$c" ]] && { auth="-u $(cat "$c")"; break; }
    done
    # shellcheck disable=SC2086
    curl -s --max-time 20 $auth \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "http://127.0.0.1:$RPC_PORT$path" 2>/dev/null
}

up=0
deadline=$(( $(date +%s) + 30 ))
while (( $(date +%s) < deadline )); do
    rpc / getblockcount | grep -q '"result"' && { up=1; break; }
    kill -0 "$NODE_PID" 2>/dev/null || { echo "MWROUTE: FAIL node died (see $DATADIR/node.log)"; exit 1; }
    sleep 1
done
[[ $up == 1 ]] || { echo "MWROUTE: FAIL rpc never came up"; exit 1; }

rpc / createwallet '["w1"]' >/dev/null
rpc / createwallet '["w2"]' >/dev/null
nwallets=$(rpc / listwallets | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["result"]))' 2>/dev/null)
[[ "$nwallets" == 2 ]] || { echo "MWROUTE: FAIL setup (loaded wallets=$nwallets, want 2)"; exit 1; }

# 1+2: /wallet/<name> must pin the wallet.
for w in w1 w2; do
    out=$(rpc "/wallet/$w" getwalletinfo)
    name=$(echo "$out" | python3 -c 'import json,sys
r=json.load(sys.stdin)
print((r.get("result") or {}).get("walletname",""))' 2>/dev/null)
    check "pin-$w" "$([[ "$name" == "$w" ]] && echo 1 || echo 0)" "walletname='$name' raw=$(echo "$out" | head -c 200)"
done

# 3: bare endpoint with 2 wallets -> -19 + Core's exact message.
out=$(rpc / getwalletinfo)
ok=$(echo "$out" | python3 -c 'import json,sys
r=json.load(sys.stdin); e=r.get("error") or {}
want="Multiple wallets are loaded. Please select which wallet to use by requesting the RPC through the /wallet/<walletname> URI path."
print(1 if e.get("code")==-19 and e.get("message")==want else 0)' 2>/dev/null)
check "bare-ambiguous-19" "${ok:-0}" "raw=$(echo "$out" | head -c 250)"

# 4: /wallet/<unknown> -> -18 exact message.
out=$(rpc /wallet/nope getwalletinfo)
ok=$(echo "$out" | python3 -c 'import json,sys
r=json.load(sys.stdin); e=r.get("error") or {}
print(1 if e.get("code")==-18 and e.get("message")=="Requested wallet does not exist or is not loaded" else 0)' 2>/dev/null)
check "unknown-18" "${ok:-0}" "raw=$(echo "$out" | head -c 250)"

# 5: unload w2 -> bare endpoint routes to the single remaining wallet.
rpc / unloadwallet '["w2"]' >/dev/null
out=$(rpc / getwalletinfo)
name=$(echo "$out" | python3 -c 'import json,sys
r=json.load(sys.stdin)
print((r.get("result") or {}).get("walletname",""))' 2>/dev/null)
check "bare-single-routes" "$([[ "$name" == w1 ]] && echo 1 || echo 0)" "walletname='$name' raw=$(echo "$out" | head -c 200)"

# 6: unload w1 -> bare endpoint with 0 wallets -> -18 exact long message.
rpc / unloadwallet '["w1"]' >/dev/null
out=$(rpc / getwalletinfo)
ok=$(echo "$out" | python3 -c 'import json,sys
r=json.load(sys.stdin); e=r.get("error") or {}
want="No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet. (Note: A default wallet is no longer automatically created)"
print(1 if e.get("code")==-18 and e.get("message")==want else 0)' 2>/dev/null)
check "bare-none-18" "${ok:-0}" "raw=$(echo "$out" | head -c 250)"

if [[ $FAILS -eq 0 ]]; then echo "MWROUTE: PASS (6/6)"; exit 0; fi
echo "MWROUTE: FAIL ($FAILS check(s) failed)"
exit 1
