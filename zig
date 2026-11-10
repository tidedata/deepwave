#!/usr/bin/env bash
# Pinned-zig wrapper: ./zig build test-conformance -Dsuite=bcs
ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT/tools/env.sh"
[ -x "$ZUI_ZIG" ] || "$ROOT/tools/bootstrap.sh" >&2
exec "$ZUI_ZIG" "$@"
