#!/usr/bin/env bash
# Builds and runs the randomness/JWK truth tool (src/main.rs) with Mysten's own Cargo.lock: the
# source is dropped in as an example of the `sui-types` crate inside a scratch git worktree of the
# sui checkout (mainnet-v1.83.1), so the checkout stays clean and every dependency (fastcrypto,
# fastcrypto-tbls, fastcrypto-zkp da61cd46) is the pinned one. Never talks to a network.
#
#   OUT_DIR=$ZUI_CORPUS/vectors ./run.sh          # writes $OUT_DIR/dkg/fastcrypto.jsonl and
#                                                 #        $OUT_DIR/jwk/fastcrypto.jsonl
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
SUI_SRC="${SUI_SRC:-$HOME/src/sui-1.83.1}"
OUT_DIR="${OUT_DIR:?set OUT_DIR to the vectors directory: the suites read ZUI_CORPUS/vectors/dkg and /jwk}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/zui-randomness-truth.XXXXXX")}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/zui/target-swarm}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
CARGO="${CARGO:-$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}"

git -C "$SUI_SRC" worktree add --detach "$WORK/sui" HEAD >/dev/null
trap 'git -C "$SUI_SRC" worktree remove --force "$WORK/sui" >/dev/null 2>&1 || true' EXIT
mkdir -p "$WORK/sui/crates/sui-types/examples" "$OUT_DIR/dkg" "$OUT_DIR/jwk"
cp "$here/src/main.rs" "$WORK/sui/crates/sui-types/examples/zui_truth_randomness.rs"
cd "$WORK/sui"
"$CARGO" build --release -p sui-types --example zui_truth_randomness
bin="$CARGO_TARGET_DIR/release/examples/zui_truth_randomness"
"$bin" dkg "$OUT_DIR/dkg/fastcrypto.jsonl"
"$bin" jwk "$OUT_DIR/jwk/fastcrypto.jsonl"
for f in dkg jwk; do echo "wrote $OUT_DIR/$f/fastcrypto.jsonl ($(wc -l < "$OUT_DIR/$f/fastcrypto.jsonl") lines)"; done
