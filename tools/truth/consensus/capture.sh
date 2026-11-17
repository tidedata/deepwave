#!/usr/bin/env bash
# Mysten localnet consensus capture for deepwave's consensus-localnet suite (docs/VALIDATOR-STATUS.md,
# conformance). Four unchanged Mysten sui-node 1.83.1 validators and one full node on loopback, keys
# from Mysten's own `sui genesis`, a short epoch, transaction load (owned transfers, read-only and
# mutable shared objects, randomness, staking), for $EPOCHS epochs. Then the validators stop and
# dump/run.sh writes every epoch's consensus store as text. Nothing touches testnet or mainnet: the
# generated configs are checked for non-loopback addresses (only the full node's JSON-RPC is moved
# from 0.0.0.0 to 127.0.0.1) and nothing reads a real key. Test machine only.
#
#   capture.sh genesis | start | load | wait | stop | jobs | dump | all
# Env: CAP_DIR (/tmp/val-truth/capture), SUI_BIN (/opt/sui-1.83.1),
#      EPOCH_MS (120000), EPOCHS (6: run until this epoch starts, then stop), CAP_CPU (200%),
#      LOAD_WORKERS (10), RPC_PORT (19400, the full node's HTTP port moved off 0.0.0.0:9000).
# Each epoch's consensus committee, protocol version and epoch start time are taken from sui-node's
# own log lines at consensus start (`Starting consensus validator authority ...`, `Consensus
# committee: Committee { ... }`) by committees.py: that is the Context Mysten's core ran with.
set -euo pipefail
CAP_DIR=${CAP_DIR:-/tmp/val-truth/capture}
SUI_BIN=${SUI_BIN:-/opt/sui-1.83.1}
EPOCH_MS=${EPOCH_MS:-120000}
EPOCHS=${EPOCHS:-6}
CAP_CPU=${CAP_CPU:-200%}
RPC_PORT=${RPC_PORT:-19400}
HERE=$(cd "$(dirname "$0")" && pwd)
cfg=$CAP_DIR/config
die() { echo "capture: $*" >&2; exit 1; }
validator_yamls() { ls "$cfg"/*.yaml | grep -v -E '/(network|fullnode|client)\.yaml$'; }
unit() { echo "zcap-$1"; }
run_unit() { # name, cmd...
  local name=$1; shift
  systemd-run --user --quiet --collect --unit="$(unit "$name")" -p CPUQuota="$CAP_CPU" -p MemoryMax=12G \
    -p Nice=10 -p IOSchedulingClass=idle --working-directory="$CAP_DIR" \
    -E RUST_LOG="${RUST_LOG:-info,sui_core=warn,consensus_core=info}" -E RUST_BACKTRACE=1 \
    bash -c 'exec "$@" >> "'"$CAP_DIR"'/logs/'"$name"'.log" 2>&1' _ "$@"
}
# highest epoch whose consensus started on every validator (-1: none yet)
cur_epoch() {
  local m=""
  for y in $(validator_yamls); do
    local l="$CAP_DIR/logs/$(basename "$y" .yaml).log" e
    e=$(grep -o 'Consensus committee: Committee { epoch: [0-9]*' "$l" 2>/dev/null | tail -1 | grep -o '[0-9]*$' || true)
    [ -n "$e" ] || { echo -1; return; }
    if [ -z "$m" ] || [ "$e" -lt "$m" ]; then m=$e; fi
  done
  echo "${m:--1}"
}

case "${1:-}" in
  genesis)
    rm -rf "$CAP_DIR"; mkdir -p "$cfg" "$CAP_DIR/logs" "$CAP_DIR/epochs"
    "$SUI_BIN/sui" genesis --working-dir "$cfg" --committee-size 4 --epoch-duration-ms "$EPOCH_MS" -f
    # keep every epoch's consensus store; JSON-RPC of the full node on loopback only
    for y in $(validator_yamls); do sed -i 's/^  db-retention-epochs: ~$/  db-retention-epochs: 1000/' "$y"; done
    sed -i "s/^json-rpc-address: \"0.0.0.0:9000\"/json-rpc-address: \"127.0.0.1:$RPC_PORT\"/" "$cfg/fullnode.yaml"
    sed -i "s#rpc: \"http://127.0.0.1:9000\"#rpc: \"http://127.0.0.1:$RPC_PORT\"#" "$cfg/client.yaml"
    if grep -oh -E '/(ip4|ip6|dns|dns4|dns6)/[^/ "]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' $(validator_yamls) "$cfg/fullnode.yaml" \
        | grep -v -E '^(/ip4/)?(127\.0\.0\.1)(:[0-9]+)?$|^/dns/localhost$' | grep -q .; then
      die "a non-local address in the generated configs"; fi
    grep -q "db-retention-epochs: 1000" "$(validator_yamls | head -1)" || die "retention not set"
    ;;
  start)
    mkdir -p "$CAP_DIR/logs"
    for y in $(validator_yamls); do run_unit "$(basename "$y" .yaml)" "$SUI_BIN/sui-node" --config-path "$y"; done
    run_unit fullnode "$SUI_BIN/sui-node" --config-path "$cfg/fullnode.yaml"
    for _ in $(seq 120); do [ "$(cur_epoch)" != -1 ] && break; sleep 2; done
    echo "epoch $(cur_epoch)"
    ;;
  load)
    systemd-run --user --quiet --collect --unit="$(unit load)" -p CPUQuota=200% -p Nice=10 --working-directory="$CAP_DIR" \
      python3 -I "$HERE/load.py" "$SUI_BIN/sui" "$cfg/client.yaml" "$CAP_DIR" "${LOAD_WORKERS:-10}"
    ;;
  wait) # until epoch $EPOCHS has started on every validator
    last=-1
    while :; do
      e=$(cur_epoch)
      [ "$e" != "$last" ] && { echo "$(date +%T) epoch $e $(tail -1 "$CAP_DIR/load.stats" 2>/dev/null)"; last=$e; }
      [ "$e" -ge "$EPOCHS" ] 2>/dev/null && break
      sleep 5
    done
    ;;
  stop)
    touch "$CAP_DIR/stop-load"; sleep 5
    for u in $(systemctl --user list-units --plain --no-legend "zcap-*" | awk '{print $1}'); do systemctl --user stop "$u" || true; done
    ;;
  jobs) # one dump job per epoch present in every validator's consensus store
    out=$CAP_DIR/vectors; mkdir -p "$out"; : > "$CAP_DIR/dump.jobs"
    dbs=$(for y in $(validator_yamls); do awk '/^consensus-config:/{c=1} c && /db-path:/{print $2; exit}' "$y"; done)
    for e in $(ls $(echo "$dbs" | head -1) | sort -n); do
      line="$out/epoch-$e.vec"
      for d in $dbs; do [ -d "$d/$e" ] || continue 2; line="$line $(basename "$(dirname "$d/x")")=$d/$e"; done
      echo "$line" >> "$CAP_DIR/dump.jobs"
    done
    cat "$CAP_DIR/dump.jobs"
    ;;
  dump)
    "$HERE/dump/run.sh" "$CAP_DIR/dump.jobs"
    python3 -I "$HERE/committees.py" "$CAP_DIR/vectors" "$CAP_DIR"/logs/127.*.log
    ;;
  all)
    "$0" genesis; "$0" start; "$0" load; "$0" wait; "$0" stop; "$0" jobs; "$0" dump
    ;;
  *) sed -n '2,15p' "$0"; exit 2;;
esac
