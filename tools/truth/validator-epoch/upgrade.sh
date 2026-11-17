#!/usr/bin/env bash
# Protocol upgrade vectors (G4/G3) at both releases, into OUT (default the repo's
# src/validator/epoch/testdata/upgrade):
#   tools/truth/validator-epoch/upgrade.sh MAINNET_OBJECTS.jsonl [OUT]
# 1.84 first (MAX 142, its own target dir: the 1.83.1 binaries in the shared one stay), then
# 1.83.1 (MAX 141) with the 1.84 upgrade's packages as the "chain-ahead" store. tools/sui is
# pointed at each tree in turn and restored to the 1.83.1 pin at the end.
#   SUI184 (default /data/parity-src/v184), SUI1831 (default /data/sui-1.83.1)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
source "$ROOT/tools/env.sh"
OBJS="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT="${2:-$ROOT/src/validator/epoch/testdata/upgrade}"
mkdir -p "$OUT"
SUI184=${SUI184:-/data/parity-src/v184}
SUI1831=${SUI1831:-/data/sui-1.83.1}
T184=${T184:-$ZUI_CACHE/target-pa-g4-184}
trap 'ln -sfn "$SUI1831" "$ROOT/tools/sui"' EXIT
cd "$HERE"
ln -sfn "$SUI184" "$ROOT/tools/sui"
CARGO_TARGET_DIR="$T184" cargo build --release 2>&1 | grep -v "^ *Compiling" | tail -40
"$T184/release/zui-valepoch-truth" upgrade "$OUT/v142" "$OBJS"
ln -sfn "$SUI1831" "$ROOT/tools/sui"
cargo build --release 2>&1 | grep -v "^ *Compiling" | tail -40
"$CARGO_TARGET_DIR/release/zui-valepoch-truth" upgrade "$OUT/v141" "$OBJS" "$OUT/v142/upgraded-objects-v142.jsonl"
ls -la "$OUT"/*
