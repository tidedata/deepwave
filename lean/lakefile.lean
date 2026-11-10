import Lake
open Lake DSL

/-! zui Lean 4 specs and proofs (ARCHITECTURE.md section 6, CONTRACTS.md section 5.11).
No Mathlib or other dependencies: core Lean only, so `lake build` needs nothing but the
pinned toolchain. -/

package zui where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib Zui

@[default_target]
lean_exe «zui-spec» where
  root := `Main
  supportInterpreter := false
