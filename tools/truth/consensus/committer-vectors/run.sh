#!/usr/bin/env bash
# Produces tools/truth/consensus/committer-vectors output: consensus vectors (replay, verify, bcs,
# swap, elect) from Mysten's consensus-core at mainnet-v1.83.1. Builds Rust in the shared target
# dir. Never talks to a network.
#
#   SUI_SRC=$ZUI_SUI_SRC OUT=$ZUI_CORPUS/consensus/replay.vec ./run.sh
#
# Then: ZUI_CORPUS=... zig-out/bin/deepwave-conformance-consensus --suite val-consensus-core --jobs 1
#
# It works on a scratch git worktree of $SUI_SRC so the checkout stays clean, and removes it on exit.
# Last run (2026-11-09): 35929 blocks, 3266 commits and 3254 finalized commits in 16 scenarios,
# 3280 elect, 2825 swap, 36 verify, 16 bcs items; all equal in deepwave.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
SUI_SRC="${SUI_SRC:-$HOME/src/sui-1.83.1}"
OUT="${OUT:?set OUT to the vectors file to write}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/zui-consensus-vectors.XXXXXX")}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/zui/target-swarm}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
# Validators run release builds, which do not check integer overflow. The byzvotes7 scenario feeds
# the CommitFinalizer out-of-range reject indices, where a metrics subtraction wraps in release
# and panics with overflow checks on, so the test profile turns them off too.
export CARGO_PROFILE_TEST_OVERFLOW_CHECKS=false
# macOS: the CommandLineTools default SDK (27.0) does not link (tools/env.sh pins the same).
if [ "$(uname -s)" = Darwin ] && [ -z "${SDKROOT:-}" ] && [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk ]; then
  export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
fi
heavy=()
[ -x "$root/tools/heavy.sh" ] && heavy=("$root/tools/heavy.sh" build --)

git -C "$SUI_SRC" worktree add --detach "$WORK/sui" HEAD >/dev/null
trap 'git -C "$SUI_SRC" worktree remove --force "$WORK/sui" >/dev/null 2>&1 || true' EXIT
cp "$here/zui_consensus_vectors.rs" "$WORK/sui/consensus/core/src/zui_consensus_vectors.rs"
# Register the test module once.
if ! grep -q zui_consensus_vectors "$WORK/sui/consensus/core/src/lib.rs"; then
  printf '\n#[cfg(test)]\nmod zui_consensus_vectors;\n' >> "$WORK/sui/consensus/core/src/lib.rs"
fi
mkdir -p "$(dirname "$OUT")"
( cd "$WORK/sui" && ZUI_VECTORS_OUT="$OUT" ${heavy[@]+"${heavy[@]}"} cargo test -p consensus-core --lib zui_consensus_vectors -- --nocapture --test-threads=1 )
test -s "$OUT" && echo "wrote $OUT ($(wc -l < "$OUT") lines)"
