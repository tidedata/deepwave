#!/usr/bin/env bash
# Regenerate src/protocol/gen_types.zig and gen_data.zig from Mysten's real configs, then prove
# them. Run from anywhere; needs tools/sui (tools/setup-sui.sh), the shared cargo target dir and $ZUI_CORPUS.
#   1. tools/truth/protocol-config builds against sui-protocol-config and dumps every (chain, version)
#   2. gen.zig turns dump.jsonl + lib.rs into the Zig types and per-version deltas
#   3. the suites compare the result with insta's YAML of the real configs
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
source "$ROOT/tools/env.sh"
cd "$ROOT"
V="$ZUI_CORPUS/vectors/protocol-config"
tools/truth/protocol-config/run.sh "$V"
./zig run src/protocol/gen/gen.zig -- tools/sui/crates/sui-protocol-config/src/lib.rs "$V/dump.jsonl" src/protocol
./zig fmt src/protocol
./zig build test -Dlane=protocol
./zig build test-conformance -Dsuite=protocol-config
git diff --stat -- src/protocol/gen_types.zig src/protocol/gen_data.zig
