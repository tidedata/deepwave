#!/usr/bin/env bash
# Interop of deepwave consensus_net with Mysten's own consensus network stack at mainnet-v1.83.1
# (TonicManager, TonicValidatorClient, sui-tls; rustls, hyper/h2, tonic, zstd): both directions,
# every ConsensusService RPC, on loopback with generated keys. Never talks to a real network.
#
#   tools/truth/consensus-net/interop/run.sh            (from the deepwave worktree; macOS or Linux)
#
# Drops zui_interop.rs into a scratch git worktree of $SUI_SRC as a consensus-core unit test,
# builds the consensus-core test binary in the shared target dir, then runs the zig test
# "tonic interop" (src/consensus/net/interop.zig), which starts the deepwave side and runs the Rust
# test as a child. The test binary is run directly: zig caches test runs and does not key them
# on the environment.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
SUI_SRC="${SUI_SRC:-$HOME/src/sui-1.83.1}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/zui-consensus-interop.XXXXXX")}"
source "$root/tools/env.sh"   # CARGO_TARGET_DIR (shared), SDKROOT on the Mac, ZUI_ZIG

git -C "$SUI_SRC" worktree add --detach "$WORK/sui" HEAD >/dev/null
trap 'git -C "$SUI_SRC" worktree remove --force "$WORK/sui" >/dev/null 2>&1 || true' EXIT
cp "$here/zui_interop.rs" "$WORK/sui/consensus/core/src/network/zui_interop.rs"
printf '\n#[cfg(all(test, not(msim)))]\nmod zui_interop;\n' >> "$WORK/sui/consensus/core/src/network/mod.rs"
bin="$(cd "$WORK/sui" && CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test -p consensus-core --lib --no-run --message-format=json \
  | python3 -c 'import json,sys
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("executable") and m.get("target",{}).get("name")=="consensus_core": print(m["executable"])' | tail -1)"
test -x "$bin"
cp "$bin" "$WORK/consensus-core-test"

cd "$root"
"$ZUI_ZIG" build test -Dlane=consensus_net -j4 >/dev/null 2>&1 || true   # compile (and the regular run)
tbin="$(ls -t "$ZIG_LOCAL_CACHE_DIR"/o/*/test-consensus_net | head -1)"
mkdir -p "$WORK/x"
ZUI_CONSENSUS_INTEROP_BIN="$WORK/consensus-core-test" ZUI_CONSENSUS_INTEROP_DIR="$WORK/x" "$tbin"
grep -E "^INTEROP" "$WORK/x/rust.log"
grep -q "INTEROP PASS" "$WORK/x/rust.log" && echo "consensus-net interop: PASS"
