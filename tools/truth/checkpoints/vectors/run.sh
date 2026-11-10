#!/usr/bin/env bash
# Prints the checkpoint wire vectors pinned in src/validator/checkpoints/rust_vectors.zig, from
# Mysten's sui-types at mainnet-v1.83.1 (contents V1/V2, summaries, BLS signatures of generated
# keys, the CheckpointSignatureV2 ConsensusTransaction, the strong quorum certificate, roaring
# bitmaps). Generated keys only; never talks to a network.
#
#   SUI_SRC=$ZUI_SUI_SRC OUT=/tmp/ckpt-vectors.txt ./run.sh
#
# Works on a git worktree of $SUI_SRC (the checkout stays clean); the test module is a child of
# messages_checkpoint.rs so it can build CheckpointContentsV2 with fixed digests. On macOS,
# source tools/env.sh first (SDKROOT).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
SUI_SRC="${SUI_SRC:-$HOME/src/sui-1.83.1}"
OUT="${OUT:?set OUT to the vectors file to write}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/zui-ckpt-vectors.XXXXXX")}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/zui/target-swarm}"

git -C "$SUI_SRC" worktree add --detach "$WORK/sui" HEAD >/dev/null
trap 'git -C "$SUI_SRC" worktree remove --force "$WORK/sui" >/dev/null 2>&1 || true' EXIT
cp "$here/zui_ckpt_vectors.rs" "$WORK/sui/crates/sui-types/src/zui_ckpt_vectors.rs"
printf '\n#[cfg(test)]\n#[path = "zui_ckpt_vectors.rs"]\nmod zui_ckpt_vectors;\n' >> "$WORK/sui/crates/sui-types/src/messages_checkpoint.rs"
( cd "$WORK/sui" && ZUI_VECTORS_OUT="$OUT" cargo test -p sui-types --lib zui_ckpt_vectors -- --nocapture --test-threads=1 )
test -s "$OUT" && echo "wrote $OUT ($(wc -l < "$OUT") lines)"
