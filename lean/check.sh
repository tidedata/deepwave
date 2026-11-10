#!/usr/bin/env bash
# Owned by the lean lane (ARCHITECTURE.md section 6, CONTRACTS.md section 5.11).
# Builds every spec, proof and the zui-spec oracle, and fails on any sorry/admit or on any
# axiom beyond Lean's three standard ones in the headline theorems.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.elan/bin:$PATH"
if ! command -v lake >/dev/null; then
  echo "lake not found: install elan (https://github.com/leanprover/elan), toolchain is pinned in lean/lean-toolchain" >&2
  exit 1
fi
if grep -rnE '\b(sorry|admit)\b' --include='*.lean' Zui Main.lean; then
  echo "proofs contain sorry/admit" >&2
  exit 1
fi
lake build
# Every headline theorem must rest only on propext, Classical.choice and Quot.sound.
out="$(lake env lean AxiomCheck.lean 2>&1)"
echo "$out"
if echo "$out" | grep -E "depends on axioms" | grep -vE "^'[^']+' depends on axioms: \[(propext|Classical\.choice|Quot\.sound)(, (propext|Classical\.choice|Quot\.sound))*\]$" | grep -q .; then
  echo "a headline theorem depends on a non-standard axiom (sorryAx, native_decide, ...)" >&2
  exit 1
fi
if echo "$out" | grep -q "sorryAx"; then echo "sorryAx found" >&2; exit 1; fi
echo "lean: ok"
