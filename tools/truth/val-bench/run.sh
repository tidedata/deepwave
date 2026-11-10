#!/usr/bin/env bash
# Mysten side of the validator speed bench (docs/VALIDATOR-SPEED.md). Test machine only; no network.
#
#   tools/truth/val-bench/run.sh setup              scratch worktree of $SUI_SRC at $WORK/sui
#   tools/truth/val-bench/run.sh consensus          stages 3 and 4: consensus-core test module
#   tools/truth/val-bench/run.sh build              stages 1, 5 and 6: release binary zui-val-bench
#   tools/truth/val-bench/run.sh bin <args...>      run it (4-core scope, nice)
#   tools/truth/val-bench/run.sh clean              remove the worktree
#
# The worktree is a detached git worktree of the sui 1.83.1 checkout
# ($SUI_SRC). Its files are backdated so cargo reuses the release
# artifacts already in the shared target dir; only the bench crate and the consensus-core test
# build compile. cargo runs at -j6 inside a 600% CPU scope at nice 10, idle I/O class.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
SUI_SRC="${SUI_SRC:-$HOME/src/sui-1.83.1}"
WORK="${WORK:-${TMPDIR:-/tmp}/zui-val-bench}"
OUT="${ZUI_VALBENCH_OUT:-${ZUI_CORPUS:?set ZUI_CORPUS}}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/zui/target-swarm}" CARGO_BUILD_JOBS=6
wt="$WORK/sui"
old="2025-01-01 00:00:00"

scope() { systemd-run --user --scope -q -p CPUQuota=600% -p MemoryMax=${REMOTE_RUN_MEM:-48G} -p MemorySwapMax=0 nice -n 10 ionice -c3 "$@"; }

setup() {
  mkdir -p "$WORK"
  if [ ! -d "$wt" ]; then
    git -C "$SUI_SRC" worktree add --detach "$wt" HEAD >/dev/null
    find "$wt" -path "$wt/.git" -prune -o -exec touch -h -d "$old" {} +
  fi
  # consensus-core test module (lib.rs keeps its old mtime: the module is cfg(test) only)
  cp "$here/consensus/zui_val_bench.rs" "$wt/consensus/core/src/zui_val_bench.rs"
  if ! grep -q zui_val_bench "$wt/consensus/core/src/lib.rs"; then
    printf '\n#[cfg(test)]\nmod zui_val_bench;\n' >> "$wt/consensus/core/src/lib.rs"
    touch -d "$old" "$wt/consensus/core/src/lib.rs"
  fi
  # consensus-core's criterion bench is not built (its dev-dependency is not in the offline
  # registry and the bench is not needed); the lib's dependency set is unchanged
  ct="$wt/consensus/core/Cargo.toml"
  if grep -q '^criterion.workspace' "$ct"; then
    sed -i '/^criterion.workspace = true$/d; /^\[\[bench\]\]$/,/^harness = false$/d' "$ct"
    touch -d "$old" "$ct"
  fi
  # the bench crate as a workspace member
  mkdir -p "$wt/crates/zui-val-bench/src"
  cp "$here/bin/Cargo.toml" "$wt/crates/zui-val-bench/Cargo.toml"
  cp "$here"/bin/src/*.rs "$wt/crates/zui-val-bench/src/"
  if ! grep -q '"crates/zui-val-bench"' "$wt/Cargo.toml"; then
    sed -i 's|^members = \[|members = [\n    "crates/zui-val-bench",|' "$wt/Cargo.toml"
    touch -d "$old" "$wt/Cargo.toml"
  fi
}

case "${1:-}" in
  setup) setup ;;
  consensus)
    setup
    cd "$wt"
    # not --offline: consensus-core's test dev-dependencies (rstest and its few small crates) are
    # not in the local registry; with the lock file in place cargo fetches only those
    ZUI_VALBENCH_OUT="$OUT" scope cargo test --release -p consensus-core --lib zui_val_bench -- --nocapture --test-threads=1
    ;;
  build)
    setup
    cd "$wt"
    scope cargo build --release --offline -p zui-val-bench
    ;;
  bin)
    shift
    scope "$CARGO_TARGET_DIR/release/zui-val-bench" "$@"
    ;;
  clean)
    git -C "$SUI_SRC" worktree remove --force "$wt" 2>/dev/null || rm -rf "$wt"
    ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
