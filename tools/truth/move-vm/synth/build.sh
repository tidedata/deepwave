#!/usr/bin/env bash
# Compiles the synthetic Move packages the move-vm truth tool runs next to the mainnet corpus.
# zvm (v1, storage = runtime 0x5a7e..01), zvm2 (an upgrade of zvm: the same modules plus
# `up`, storage 0x5a7e..02), zdep (0x5a7e..03, depends on zvm2), zbig (0x5a7e..04, types at the
# 128-node JIT limit) and zbd (0x5a7e..08, depends on zbig). Output: out/<pkg>/*.mv.
# Needs the `sui` CLI (any recent version; only the bytecode is used).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
rm -rf work out && mkdir -p work out/zvm out/zvm2 out/zdep out/zbig out/zbd
cp -R zvm work/zvm && rm -rf work/zvm/build
cp -R zvm work/zvm2 && rm -rf work/zvm2/build && cp up/sources/*.move work/zvm2/sources/
cp -R dep work/zdep
(cd work/zvm && sui move build --silence-warnings >/dev/null)
(cd work/zvm2 && sui move build --silence-warnings >/dev/null)
sed -i.bak 's#\.\./work/zvm2#../zvm2#' work/zdep/Move.toml
(cd work/zdep && sui move build --silence-warnings >/dev/null)
cp -R big work/zbig && rm -rf work/zbig/build
cp -R bdep work/zbd && rm -rf work/zbd/build
(cd work/zbig && sui move build --silence-warnings >/dev/null)
(cd work/zbd && sui move build --silence-warnings >/dev/null)
cp work/zbig/build/zbig/bytecode_modules/*.mv out/zbig/
cp work/zbd/build/zbd/bytecode_modules/*.mv out/zbd/
cp work/zvm/build/zvm/bytecode_modules/*.mv out/zvm/
cp work/zvm2/build/zvm/bytecode_modules/*.mv out/zvm2/
cp work/zdep/build/zdep/bytecode_modules/*.mv out/zdep/
rm -rf work zvm/build
ls out/*
