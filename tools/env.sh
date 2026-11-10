# Shared build environment. Source it, or use ./zig, which sources it.
# One cache root per machine: every checkout shares the Zig global cache and the cargo target dir.
export ZUI_ZIG_VERSION=0.17.1
export ZUI_CACHE="${ZUI_CACHE:-$HOME/.cache/zui}"
export ZIG_GLOBAL_CACHE_DIR="$ZUI_CACHE/zig-global"
# Zig's local cache is per checkout ($ZUI_CACHE/zig-local-wt/<checkout dir name>), so parallel
# builds in different checkouts do not queue on one manifest lock. ZUI_LOCAL_CACHE overrides it.
if [ -n "${BASH_SOURCE:-}" ]; then _zui_env="${BASH_SOURCE[0]}"
elif [ -n "${ZSH_VERSION:-}" ]; then eval '_zui_env="${(%):-%x}"'
else _zui_env="$PWD/tools/env.sh"; fi
_zui_root="$(cd "$(dirname "$_zui_env")/.." && pwd)"
export ZIG_LOCAL_CACHE_DIR="${ZUI_LOCAL_CACHE:-$ZUI_CACHE/zig-local-wt/$(basename "$_zui_root")}"
unset _zui_env _zui_root
# The shared cargo target dir for the Rust ground-truth tools (tools/truth, tools/dumper).
export CARGO_TARGET_DIR="${ZUI_CARGO_TARGET:-$ZUI_CACHE/target-swarm}"
export ZUI_ZIG="$ZUI_CACHE/zig-$ZUI_ZIG_VERSION/zig"
# Mysten's sui source at mainnet-v1.83.1 (commit 6a567faf), the source of truth for tools/truth.
# tools/setup-sui.sh links it at tools/sui.
export ZUI_SUI_SRC="${ZUI_SUI_SRC:-$HOME/src/sui-1.83.1}"
# macOS: the CommandLineTools default SDK (27.0) ships .tbd files the bundled ld cannot parse
# ("unknown architecture arm64e.x1"); pin the newest SDK that links.
if [ "$(uname -s)" = Darwin ] && [ -z "${SDKROOT:-}" ] && [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk ]; then
  export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
fi
# Conformance corpus (real mainnet data and truth made by Mysten's code; not in git). See docs/testing.md.
export ZUI_CORPUS="${ZUI_CORPUS:-$HOME/zui-corpus}"
export ZUI_DUMPER="$CARGO_TARGET_DIR/release/zui-dumper"
case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) if [ -d "$HOME/.cargo/bin" ]; then export PATH="$HOME/.cargo/bin:$PATH"; fi ;; esac
