#!/usr/bin/env bash
# Manual HTTP/2 interop against curl (not run in CI): starts the Zig test server for one
# connection and calls it with curl's HTTP/2 prior-knowledge mode.
set -euo pipefail
cd "$(dirname "$0")/../../.."
PORT=${PORT:-18080}
ZUI_H2_INTEROP_PORT=$PORT ./zig build test -Dlane=serve >/tmp/zui-h2-interop.log 2>&1 &
SRV=$!
sleep 15
printf '\0\0\0\0\3abc' | curl --http2-prior-knowledge -s -D - -o - \
  -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @- "http://127.0.0.1:$PORT/t/Echo" | xxd | head
wait $SRV || true
