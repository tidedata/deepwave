#!/usr/bin/env bash
# Regenerate everything the `hash` suite needs under $ZUI_CORPUS/vectors/hash/:
#   upstream/            official NIST / Keccak team / BLAKE2 / Wycheproof / RFC files (+ SOURCES.txt)
#   synthetic.tsv.zst    fastcrypto truth over generated inputs (lengths, HMAC, HKDF)
#   corpus-blobs.tsv.zst every chk blob hashed by all seven hashers (needs the chk corpus)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
source "$ROOT/tools/env.sh"
here="$ROOT/tools/truth/crypto-hash"
(cd "$here" && cargo build --release)
T="$CARGO_TARGET_DIR/release/zui-truth-hash"
mkdir -p "$ZUI_CORPUS/vectors/hash"
"$here/fetch-upstream.sh"
"$T" gen "$ZUI_CORPUS/vectors/hash"
"$T" blobs "$ZUI_CORPUS/chk" "$ZUI_CORPUS/vectors/hash/corpus-blobs.tsv.zst"
