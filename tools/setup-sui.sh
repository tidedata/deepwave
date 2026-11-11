#!/usr/bin/env bash
# Links the Mysten mainnet-v1.83.1 source tree at tools/sui so every Rust truth tool resolves
# sui-types & co. by the same relative path from any checkout or worktree. Idempotent.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/tools/env.sh"
[ -d "$ZUI_SUI_SRC/crates/sui-types" ] || { echo "missing Mysten source at $ZUI_SUI_SRC" >&2; exit 1; }
rev="$(git -C "$ZUI_SUI_SRC" rev-parse --short=8 HEAD 2>/dev/null || echo unknown)"
[ "$rev" = 6a567faf ] || echo "warning: $ZUI_SUI_SRC is at $rev, expected 6a567faf (mainnet-v1.83.1)" >&2
ln -sfn "$ZUI_SUI_SRC" "$ROOT/tools/sui"
echo "tools/sui -> $ZUI_SUI_SRC ($rev)"
