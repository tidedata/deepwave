#!/usr/bin/env bash
# Installs the pinned Zig toolchain into the shared deepwave cache (one copy for every
# checkout and worktree). Idempotent. Usage: tools/bootstrap.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/tools/env.sh"

ver="$ZUI_ZIG_VERSION"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  plat=aarch64-macos; sha=75f1bc7a1e9852f17ec9a0c1895f767c4ec56d46bc8a834920eece1d0359dd8d ;;
  Linux-x86_64)  plat=x86_64-linux;  sha=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a ;;
  *) echo "unsupported host $(uname -s)-$(uname -m); add its sha256 from ziglang.org/download/index.json" >&2; exit 1 ;;
esac
dest="$ZUI_CACHE/zig-$ver"
if [ -x "$dest/zig" ]; then echo "zig $ver already at $dest"; exit 0; fi
mkdir -p "$ZUI_CACHE"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
url="https://ziglang.org/download/$ver/zig-$plat-$ver.tar.xz"
echo "fetching $url"
curl -fL --retry 3 -o "$tmp/zig.tar.xz" "$url"
got="$(shasum -a 256 "$tmp/zig.tar.xz" | cut -d' ' -f1)"
[ "$got" = "$sha" ] || { echo "sha256 mismatch: $got != $sha" >&2; exit 1; }
tar -C "$tmp" -xJf "$tmp/zig.tar.xz"
mv "$tmp/zig-$plat-$ver" "$dest"
echo "installed zig $("$dest/zig" version) at $dest"
