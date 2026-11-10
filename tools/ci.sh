#!/usr/bin/env bash
# Regression gate: unit tests, then every suite in tools/ci-suites.txt on the full corpus.
#   tools/ci.sh            unit tests and every CI suite (needs $ZUI_CORPUS, see docs/testing.md)
#   tools/ci.sh --quick    unit tests and the corpus integrity suites only
# Deterministic: the summary lines do not depend on -Djobs or scheduling.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
./zig build test --summary none
if [ "${1:-}" = "--quick" ]; then suites="corpus,corpus-chain"
else suites="$(grep -Ev '^[[:space:]]*(#|$)' tools/ci-suites.txt | awk '{print $1}' | paste -sd, -)"; fi
# The lean suites run the proofs' oracles: rebuild the proofs and the Rust checker first, so no
# suite runs a stale binary.
case ",$suites," in *,lean-*)
  ./zig build lean --summary none
  # shellcheck source=/dev/null
  source tools/env.sh
  tools/setup-sui.sh >/dev/null
  cargo build --release --quiet --manifest-path tools/truth/lean/Cargo.toml ;;
esac
./zig build test-conformance -Dsuite="$suites" -Doptimize=fast
