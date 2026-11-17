#!/usr/bin/env bash
# Shared-object version assignment vectors from Mysten's sui-core at mainnet-v1.83.1
# (zui_version_vectors.rs, format in its header). Builds sui-core's test binary in a scratch git
# worktree of $SUI_SRC (the checkout stays clean). Test machine only. Never talks to a network.
#
#   SUI_SRC=/data/sui-1.83.1 CARGO_TARGET_DIR=... OUT=.../versions.txt tools/truth/authority/versions/run.sh
# A WORK you pass is kept (the worktree is reused, so a rerun rebuilds incrementally); remove it with
# `git -C $SUI_SRC worktree remove --force $WORK/sui`.
# deepwave side: the conformance suite `authority-versions` (src/validator/authority/versions_conformance.zig)
# reads $ZUI_CORPUS/vectors/authority/versions.txt.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
SUI_SRC="${SUI_SRC:-/data/sui-1.83.1}"
OUT="${OUT:?set OUT to the vectors file to write}"
keep=1
[ -n "${WORK:-}" ] || { WORK="$(mktemp -d "${TMPDIR:-/tmp}/zui-version-vectors.XXXXXX")"; keep=0; }
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to the shared target dir}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
[ -d "$WORK/sui" ] || git -C "$SUI_SRC" worktree add --detach "$WORK/sui" HEAD >/dev/null
[ "$keep" = 1 ] || trap 'git -C "$SUI_SRC" worktree remove --force "$WORK/sui" >/dev/null 2>&1 || true' EXIT
d="$WORK/sui/crates/sui-core/src/authority"
git -C "$WORK/sui" checkout -q -- crates/sui-core/src/authority/shared_object_version_manager.rs
cp "$here/zui_version_vectors.rs" "$d/zui_version_vectors.rs"
printf '\n#[cfg(test)]\n#[path = "zui_version_vectors.rs"]\nmod zui_version_vectors;\n' >> "$d/shared_object_version_manager.rs"
mkdir -p "$(dirname "$OUT")"
( cd "$WORK/sui" && ZUI_VECTORS_OUT="$OUT" cargo test -p sui-core --lib zui_version_vectors -- --nocapture --test-threads=1 )
test -s "$OUT" && echo "wrote $OUT ($(wc -l < "$OUT") lines)"
