#!/usr/bin/env bash
# Capture for val-authority: the consensus capture (localnet under load) then the authority
# tables of every validator. Loopback only. See README.md.
set -euo pipefail
out=${1:?usage: capture.sh <out dir>}
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
# 1. localnet + consensus vectors (stops the localnet cleanly)
"$root/tools/truth/consensus/capture.sh" "$out"
# 2. authority tables
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/zui/target-swarm}"   # shared
sui_src="${ZUI_SUI_SRC:-$root/tools/sui}"
dump="$here/dump"
cargo run --release --manifest-path "$dump/Cargo.toml" -- \
  --sui-src "$sui_src" --localnet "$out/localnet" --out "$out/vectors/authority"
echo "authority vectors in $out/vectors/authority"
