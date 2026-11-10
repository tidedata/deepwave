#!/bin/bash
# Runner: a fresh deepwave from the tip (public bucket, no S3) serving for a few minutes, asked
# GetEpoch protocol_config; compared with sui-node 1.83.1's capture (serve vector). Exit 0: equal.
#   e2e-protocfg.sh [RELEASE]                check against the vector, then stop
#   E2E_SERVE_SECS=N E2E_PORT=P e2e-protocfg.sh   also keep serving on 127.0.0.1:P for N s (a Mac
#                                            tunnel then runs zui-shadow against sui-node)
set -uo pipefail
cd "$(dirname "$0")/../../.."
./zig build node -Doptimize=ReleaseFast -Dcpu=native --summary none || exit 2
have_node=1; command -v node >/dev/null || { have_node=0; echo "no node.js on this box: serve only"; }
DIR=$(mktemp -d); PORT=${E2E_PORT:-$((20000 + RANDOM % 20000))}
REL=${1:-}
./zig-out/bin/deepwave run --dir "$DIR" --source http --no-s3-fallback --from tip \
  --genesis "$ZUI_CORPUS/vectors/bls-cert/upstream/genesis.blob" --epochs "$ZUI_CORPUS/epochs.jsonl" \
  --trust-dir "$ZUI_CORPUS/chk" --serve "127.0.0.1:$PORT" --status-every 30 ${REL:+--rpc-release $REL} > "$DIR/node.log" 2>&1 &
pid=$!
rc=4
for i in $(seq 1 40); do
  sleep 10
  kill -0 $pid 2>/dev/null || { echo "deepwave exited"; tail -20 "$DIR/node.log"; break; }
  if [ $have_node = 0 ]; then
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && [ $i -ge 6 ]; then rc=0; break; fi
    continue
  fi
  out=$(node tools/truth/epoch-pkg/e2e-protocfg.mjs "http://127.0.0.1:$PORT" src/serve/vectors/protocfg/getepoch-1305-sui-node-1.83.1.bin 2>&1); rc=$?
  echo "t=$((i * 10))s $out"
  [ $rc -eq 0 ] || [ $rc -eq 1 ] && break
done
if [ -n "${E2E_SERVE_SECS:-}" ] && kill -0 $pid 2>/dev/null; then
  echo "SERVING 127.0.0.1:$PORT for $E2E_SERVE_SECS s"
  end=$((SECONDS + E2E_SERVE_SECS))
  while [ $SECONDS -lt $end ] && kill -0 $pid 2>/dev/null; do sleep 5; done
fi
kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null
grep -m3 -E "serving|verified" "$DIR/node.log" || true
rm -rf "$DIR"
exit $rc
