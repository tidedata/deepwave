#!/usr/bin/env bash
# Mysten localnet capture for the validator lanes (README.md here). Skeleton: the build and
# localnet steps are written; the dump step needs tools/truth/consensus/dump (val-consensus-core).
# Loopback only. Refuses to run if the generated network config names a non-loopback address.
set -euo pipefail
out=${1:?usage: capture.sh <out dir>}
MINUTES=${MINUTES:-20}
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
sui_src="${ZUI_SUI_SRC:-$root/tools/sui}"
[ -d "$sui_src/crates/sui" ] || { echo "capture: Mysten source missing at $sui_src (tools/setup-sui.sh)" >&2; exit 2; }
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/zui/target-swarm}"   # shared
mkdir -p "$out"
cargo build --release --manifest-path "$sui_src/Cargo.toml" -p sui --bin sui
sui="$CARGO_TARGET_DIR/release/sui"
cfg="$out/localnet"
rm -rf "$cfg"
"$sui" genesis --working-dir "$cfg" --committee-size 4 --with-faucet --force
if grep -Eo '/(ip4|dns)/[^/]+' "$cfg"/*.yaml | grep -Ev '/ip4/127\.|/dns/localhost' ; then
  echo "capture: non-loopback address in the generated config, refusing" >&2; exit 2
fi
"$sui" start --network.config "$cfg" > "$out/localnet.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true' EXIT
sleep 30
# Load: transfers and shared-object calls through the faucet-funded addresses (to write: a small
# loop with `sui client` against the localnet's RPC, including soft bundles and randomness calls).
sleep "$((MINUTES * 60))"
kill -INT $pid; wait $pid || true
trap - EXIT
dump="$here/dump"
[ -f "$dump/Cargo.toml" ] || { echo "capture: localnet data in $cfg; dump tool not written yet" >&2; exit 3; }
cargo run --release --manifest-path "$dump/Cargo.toml" -- --localnet "$cfg" --out "$out/vectors"
