#!/usr/bin/env bash
# Builds the truth tool into the shared target dir and writes the vectors.
#   tools/truth/validator-epoch/run.sh [OUT_DIR]       default $ZUI_CORPUS/vectors/validator-epoch
# Then, in the deepwave checkout:   ./zig build validator && ./zig-out/bin/deepwave-validator vectors-check OUT_DIR
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/../../env.sh"
OUT="${1:-$ZUI_CORPUS/vectors/validator-epoch}"
cd "$HERE"
cargo build --release
"$CARGO_TARGET_DIR/release/zui-valepoch-truth" dump "$OUT"
