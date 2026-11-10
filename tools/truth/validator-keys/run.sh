#!/usr/bin/env bash
# Rust truth for the validator keys, validator.yaml and epoch messages (mainnet-v1.83.1).
# Never talks to a network; generated keys only. macOS or Linux.
#
#   OUT=$ZUI_CORPUS/vectors/validator-keys [ZUI_YAML_DIR=<dir of deepwave validator-*.yaml>] ./run.sh
#
# Works on a scratch git worktree of $SUI_SRC: drops zui_compat.rs into
# crates/sui-swarm-config/tests and adds sui-keys and prost as its dev-dependencies, then runs
# `cargo test --release -p sui-swarm-config --test zui_compat`. Writes into OUT:
#   keys.jsonl, bad-keys.jsonl, keys/      sui-keys key files for 8 seeds, accept/reject cases
#   mysten-validator-<i>.yaml (+ .jsonl)   ConfigBuilder validator configs as `sui genesis` saves them
#   validator-epoch/                       the files `deepwave-validator vectors-check DIR` reads
#                                          (the generator of tools/truth/validator-epoch, in-workspace)
#   zui-yaml.jsonl                         with ZUI_YAML_DIR: NodeConfig parse of each deepwave yaml
#                                          (the test fails if any does not load)
# deepwave pins: src/validator/keys/testdata/, src/validator/epoch/protocol-digests.txt.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../../env.sh"
# Under a build wrapper the /usr/bin/python3 xcrun shim exports SDKROOT=<default SDK 27.0> before
# env.sh runs, and env.sh keeps an existing SDKROOT: pin the SDK that links (see env.sh).
if [ "$(uname -s)" = Darwin ] && [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk ]; then
  export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
fi
SUI_SRC="${SUI_SRC:-$ZUI_SUI_SRC}"
OUT="${OUT:?set OUT to the output directory}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/deepwave-validator-keys.XXXXXX")}"
git -C "$SUI_SRC" worktree add --detach "$WORK/sui" HEAD >/dev/null
trap 'git -C "$SUI_SRC" worktree remove --force "$WORK/sui" >/dev/null 2>&1 || true' EXIT
cfg="$WORK/sui/crates/sui-swarm-config"
cp "$here/zui_compat.rs" "$cfg/tests/zui_compat.rs"
if ! grep -q '^sui-keys.workspace' "$cfg/Cargo.toml"; then
  sed -i.bak 's/^tempfile.workspace = true$/tempfile.workspace = true\
sui-keys.workspace = true\
prost.workspace = true/' "$cfg/Cargo.toml"
fi
mkdir -p "$OUT"
echo "validator-keys truth: SDKROOT=${SDKROOT:-unset} CARGO_TARGET_DIR=$CARGO_TARGET_DIR" >&2
( cd "$WORK/sui" && ZUI_COMPAT_OUT="$OUT" cargo test --release -p sui-swarm-config --test zui_compat -- --nocapture --test-threads=1 )
echo "wrote $OUT"
