#!/usr/bin/env bash
# Dumps sui-node consensus stores into the text format of zui_consensus_dump.rs, for deepwave's
# `consensus-localnet` suite. Mysten consensus-core at mainnet-v1.83.1, built in a scratch git
# worktree of $SUI_SRC (the checkout stays clean; WORK is kept so a rerun reuses the build).
# Test machine only (Rust builds run on a test machine). Run with the validators stopped.
#
#   SUI_SRC=/data/sui-1.83.1 CARGO_TARGET_DIR=... tools/truth/consensus/dump/run.sh JOBS_FILE
# JOBS_FILE: one line per epoch: `<out file> <label>=<consensus db-path>/<epoch> ...`
# (tools/truth/consensus/capture.sh writes it).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
SUI_SRC="${SUI_SRC:-/data/sui-1.83.1}"
jobs="$(cd "$(dirname "${1:?usage: run.sh JOBS_FILE}")" && pwd)/$(basename "$1")"
WORK="${WORK:-${TMPDIR:-/tmp}/zui-consensus-dump}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to the shared target dir}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
mkdir -p "$WORK"
[ -d "$WORK/sui" ] || git -C "$SUI_SRC" worktree add --detach "$WORK/sui" HEAD >/dev/null
cp "$here/zui_consensus_dump.rs" "$WORK/sui/consensus/core/src/storage/zui_consensus_dump.rs"
f="$WORK/sui/consensus/core/src/storage/rocksdb_store.rs"
grep -q zui_consensus_dump "$f" || printf '\n#[cfg(test)]\n#[path = "zui_consensus_dump.rs"]\nmod zui_consensus_dump;\n' >> "$f"
( cd "$WORK/sui" && ZUI_DUMP_JOBS="$jobs" \
    cargo test -p consensus-core --lib zui_consensus_dump -- --ignored --nocapture --test-threads=1 )
# Remove the worktree with: git -C "$SUI_SRC" worktree remove --force "$WORK/sui"
