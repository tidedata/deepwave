#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/../../env.sh"
OUT="${1:-$ZUI_CORPUS/vectors/protocol-config}"
cd "$HERE"
cargo build --release
"$CARGO_TARGET_DIR/release/zui-pc-truth" dump "$OUT" "$ZUI_SUI_SRC/crates/sui-protocol-config/src/snapshots"
