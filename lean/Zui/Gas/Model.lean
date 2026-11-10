/-!
# Sui gas: the executable model

A model of gas charging as sui-types 1.83.1 implements it for the gas model live on mainnet
(`gas_model_version` 15, protocol 138 to 141: `gas_model/gas_v3.rs`), on top of the Move meter
`gas_model/tables.rs` (`GasStatus`) with the cost tables of `gas_predicates.rs`, and the shared
storage accounting of `gas_common.rs`.

Integers are `Nat`; every place where Rust uses checked or saturating `u64` arithmetic is
modelled explicitly against `u64Max`. Two unchecked spots in `tables.rs` (`charge_bytes`'s
product and the sum in `GasCost::total_internal`) are plain `Nat` here: they wrap in a Rust
release build only far outside protocol limits.

Gas model versions below 15 (`gas_v2.rs`: bucket, stepped and half-digit rounding, the
budget-charging OOG path) are not modelled yet.
-/

namespace Zui.Gas

def u64Max : Nat := 2 ^ 64 - 1

/-- The protocol-config values gas charging reads (`zui-lean-truth gas-config`). -/
structure Config where
  pv : Nat
  gasModelVersion : Nat
  maxGasComputationBucket : Nat
  maxGasPrice : Nat
  objReadPerByte : Nat
  pkgReadPerKb : Option Nat
  publishPerByte : Nat
  storagePerByte : Nat
  storageGasPrice : Nat
  rebateRate : Nat
  abortFactor : Option Nat
  deriving Repr, Inhabited

/-! ## Cost tables (`tables.rs`, `cost_table_for_version`) -/

/-- Tiers as (start, multiplier), ascending. -/
structure CostTable where
  instr : List (Nat × Nat)
  height : List (Nat × Nat)
  size : List (Nat × Nat)

def costTableV5 : CostTable where
  instr := [(0, 1), (20000, 2), (50000, 10), (100000, 50), (200000, 100), (10000000, 1000)]
  height := [(0, 1), (1000, 2), (10000, 10)]
  size := [(0, 1), (100000, 2), (500000, 5), (1000000, 100), (100000000, 1000)]

def costTableV4 : CostTable where
  instr := [(0, 1), (20000, 2), (50000, 10), (100000, 50), (200000, 100)]
  height := [(0, 1), (1000, 2), (10000, 10)]
  size := [(0, 1), (100000, 2), (500000, 5), (1000000, 100)]

/-- `cost_table_for_version` for gas models 6 and up (only 15 is exercised). -/
def costTableFor (gm : Nat) : CostTable :=
  if gm ≥ 8 then costTableV5 else costTableV4

/-- `get_current_and_future_tier`: the multiplier of the last tier starting at or below
`cur` (default 1), and the start of the first tier strictly above `cur`. -/
def tierMult (tiers : List (Nat × Nat)) (cur : Nat) : Nat :=
  tiers.foldl (fun m t => if t.1 ≤ cur then t.2 else m) 1

def nextTier (tiers : List (Nat × Nat)) (cur : Nat) : Option Nat :=
  (tiers.find? (fun t => t.1 > cur)).map (·.1)

/-! ## The Move meter (`GasStatus`) -/

structure Meter where
  table : CostTable
  gasLeft : Nat
  initial : Nat
  hCur : Nat
  hNext : Option Nat
  hMult : Nat
  sCur : Nat
  sNext : Option Nat
  sMult : Nat
  instr : Nat
  iNext : Option Nat
  iMult : Nat

/-- VM status codes the meter can raise. -/
inductive VmErr where
  | outOfGas | arithmeticOverflow | pcOverflow
  deriving Repr, DecidableEq

def VmErr.name : VmErr → String
  | .outOfGas => "OUT_OF_GAS"
  | .arithmeticOverflow => "ARITHMETIC_OVERFLOW"
  | .pcOverflow => "PC_OVERFLOW"

def Meter.new (t : CostTable) (budget price : Nat) : Meter :=
  let left := budget / price * 1000
  { table := t, gasLeft := left, initial := left,
    hCur := 0, hNext := nextTier t.height 0, hMult := tierMult t.height 0,
    sCur := 0, sNext := nextTier t.size 0, sMult := tierMult t.size 0,
    instr := 0, iNext := nextTier t.instr 0, iMult := tierMult t.instr 0 }

/-- `deduct_gas`: on failure the meter is left with no gas. -/
def Meter.deduct (m : Meter) (amount : Nat) : Meter × Option VmErr :=
  if amount ≤ m.gasLeft then ({ m with gasLeft := m.gasLeft - amount }, none)
  else ({ m with gasLeft := 0 }, some .outOfGas)

def Meter.pushStack (m : Meter) (pushes : Nat) : Option Meter :=
  let h := m.hCur + pushes
  if h > u64Max then none else
  let m := { m with hCur := h }
  match m.hNext with
  | some nxt => if h > nxt then some { m with hMult := tierMult m.table.height h,
                                              hNext := nextTier m.table.height h } else some m
  | none => some m

def Meter.addInstr (m : Meter) (n : Nat) : Option Meter :=
  let c := m.instr + n
  if c > u64Max then none else
  let m := { m with instr := c }
  match m.iNext with
  | some nxt => if c > nxt then some { m with iMult := tierMult m.table.instr c,
                                              iNext := nextTier m.table.instr c } else some m
  | none => some m

def Meter.addSize (m : Meter) (n : Nat) : Option Meter :=
  let s := m.sCur + n
  if s > u64Max then none else
  let m := { m with sCur := s }
  match m.sNext with
  | some nxt => if s > nxt then some { m with sMult := tierMult m.table.size s,
                                              sNext := nextTier m.table.size s } else some m
  | none => some m

/-- `GasStatus::charge(num_instructions, pushes, pops, incr_size, _)`. -/
def Meter.charge (m : Meter) (instrs pushes pops incr : Nat) : Meter × Option VmErr :=
  match m.pushStack pushes with
  | none => (m, some .arithmeticOverflow)
  | some m =>
    match m.addInstr instrs with
    | none => (m, some .pcOverflow)
    | some m =>
      match m.addSize incr with
      | none => (m, some .arithmeticOverflow)
      | some m =>
        let a := m.iMult * instrs
        let b := m.sMult * incr
        let c := m.hMult * pushes
        if a > u64Max ∨ b > u64Max ∨ c > u64Max then (m, some .arithmeticOverflow) else
        match m.deduct (a + b + c) with
        | (m, some e) => (m, some e)
        | (m, none) => ({ m with hCur := m.hCur - pops }, none)

/-- `gas_used_pre_gas_price`: internal units used, rounded down to gas units. -/
def Meter.used (m : Meter) : Nat := (m.initial - m.gasLeft) / 1000

/-! ## Rounding and rebates (`gas_common.rs`) -/

def ilog10 (n : Nat) : Nat := if n < 10 then 0 else ilog10 (n / 10) + 1

def ceilDiv (a b : Nat) : Nat := (a + b - 1) / b

/-- `half_digits_rounding`. -/
def halfDigits (n : Nat) : Nat :=
  if n < 1000 then 1000 else
  let base := 10 ^ (ilog10 n / 2)
  min (ceilDiv n base * base) u64Max

/-- `sender_rebate`: the rebate at `rate` basis points, rounded half up. -/
def senderRebate (rebate rate : Nat) : Nat :=
  min ((rebate * rate + 5000) / 10000) u64Max

/-- `package_read_internal_gas`. -/
def pkgReadGas (size perKb : Nat) : Nat := min (ceilDiv (size * perKb) 1024) u64Max

/-! ## `SuiGasStatus` v3 -/

structure Status where
  cfg : Config
  meter : Meter
  budget : Nat
  userPrice : Nat
  rgp : Nat
  effPrice : Nat
  storageCost : Nat
  storageRebate : Nat
  force : Bool

/-- `ExecutionErrorKind`s the status raises. -/
inductive ExErr where
  | insufficientGas | invariantViolation
  deriving Repr, DecidableEq

def ExErr.name : ExErr → String
  | .insufficientGas => "InsufficientGas"
  | .invariantViolation => "InvariantViolation"

inductive NewErr where
  | underRgp | tooHigh
  deriving Repr, DecidableEq

def NewErr.name : NewErr → String
  | .underRgp => "GasPriceUnderRGP"
  | .tooHigh => "GasPriceTooHigh"

/-- `SuiGasStatus::new` for gas model 15. -/
def Status.new (c : Config) (budget price rgp : Nat) : Except NewErr Status :=
  if price < rgp then .error .underRgp
  else if c.gasModelVersion ≥ 4 ∧ price ≥ c.maxGasPrice then .error .tooHigh
  else
    let maxComp := c.maxGasComputationBucket * price
    let compBudget := if budget > maxComp then maxComp else budget
    .ok { cfg := c, meter := Meter.new (costTableFor c.gasModelVersion) compBudget price,
          budget, userPrice := price, rgp, effPrice := price,
          storageCost := 0, storageRebate := 0, force := false }

def Status.uncapped (s : Status) : Nat :=
  if s.force then s.budget else min (halfDigits s.meter.used * s.effPrice) u64Max

def Status.senderRebate (s : Status) : Nat := Zui.Gas.senderRebate s.storageRebate s.cfg.rebateRate

def Status.netStorage (s : Status) : Nat := s.storageCost - s.senderRebate

def Status.computation (s : Status) : Nat := min s.uncapped (s.budget - s.netStorage)

/-- `summary()`: computation, storage cost, storage rebate, non-refundable fee. -/
def Status.summary (s : Status) : Nat × Nat × Nat × Nat :=
  (s.computation, s.storageCost, s.senderRebate, s.storageRebate - s.senderRebate)

def Status.chargeBytes (s : Status) (size perByte : Nat) : Status × Option ExErr :=
  match s.meter.deduct (size * perByte) with
  | (m, none) => ({ s with meter := m }, none)
  | (m, some _) => ({ s with meter := m }, some .insufficientGas)

def Status.chargeRead (s : Status) (size : Nat) := s.chargeBytes size s.cfg.objReadPerByte
def Status.chargePublish (s : Status) (size : Nat) := s.chargeBytes size s.cfg.publishPerByte

def Status.chargePackageRead (s : Status) (size : Nat) : Status × Option ExErr :=
  match s.cfg.pkgReadPerKb with
  | none => s.chargeRead size
  | some perKb =>
    match s.meter.deduct (pkgReadGas size perKb) with
    | (m, none) => ({ s with meter := m }, none)
    | (m, some _) => ({ s with meter := m }, some .insufficientGas)

/-- `track_storage_mutation` (metered): the new object's storage cost, or `none` on u64
overflow; the cost total is updated before the rebate total is checked, as in Rust. -/
def Status.trackMutation (s : Status) (newSize rebate : Nat) : Status × Option Nat :=
  let a := newSize * s.cfg.storagePerByte
  if a > u64Max then (s, none) else
  let cost := a * s.cfg.storageGasPrice
  if cost > u64Max then (s, none) else
  let tc := s.storageCost + cost
  if tc > u64Max then (s, none) else
  let s := { s with storageCost := tc }
  let tr := s.storageRebate + rebate
  if tr > u64Max then (s, none) else
  ({ s with storageRebate := tr }, some cost)

/-- `bucketize_computation(Some aborted)`. -/
def Status.bucketize (s : Status) (aborted : Bool) : Status × Option ExErr :=
  let eff : Except ExErr Nat :=
    match s.cfg.abortFactor with
    | some f => if aborted then
        (if f * s.rgp > u64Max then .error .invariantViolation else .ok (min s.userPrice (f * s.rgp)))
      else .ok s.userPrice
    | none => .ok s.userPrice
  match eff with
  | .error e => (s, some e)
  | .ok p =>
    let s := { s with effPrice := p }
    if s.uncapped ≥ s.budget then (s, some .insufficientGas) else (s, none)

/-- `charge_storage_and_rebate`. -/
def Status.chargeStorage (s : Status) : Option ExErr :=
  if s.netStorage > s.budget - s.uncapped then some .insufficientGas else none

/-- `adjust_computation_on_out_of_gas`. -/
def Status.outOfGas (s : Status) : Status :=
  { s with storageCost := 0, storageRebate := 0, force := true }

/-- `reset_storage_cost_and_rebate`. -/
def Status.reset (s : Status) : Status := { s with storageCost := 0, storageRebate := 0 }

end Zui.Gas
