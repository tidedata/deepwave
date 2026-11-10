import Lean.Data.Json
import Zui.Gas.Model
import Zui.Bcs.Gen

/-!
# Gas vector export

A gas vector is an op script run against one `SuiGasStatus`: the model's results are stored in
`expect`, and `zui-lean-truth gas-check` replays the script on sui-types' `SuiGasStatus` with
`ProtocolConfig::get_for_version(pv, Mainnet)`, comparing every op's result, the summary, the
gas used and the internal gas left. The vector also carries the config row the model used;
the checker requires it to equal Rust's.
-/

namespace Zui.Gas
open Lean Zui.Bcs

/-- One op: name and numeric arguments, as in the vector JSON. -/
abbrev Op := String × List Nat

def natOrNone (j : Json) (k : String) : Except String (Option Nat) :=
  match j.getObjVal? k with
  | .ok .null => .ok none
  | .ok v => (some ·) <$> v.getNat?
  | .error e => .error e

def parseConfig (j : Json) : Except String Config := do
  let n := fun k => do (← j.getObjVal? k).getNat?
  return { pv := ← n "pv", gasModelVersion := ← n "gas_model_version",
           maxGasComputationBucket := ← n "max_gas_computation_bucket",
           maxGasPrice := ← n "max_gas_price",
           objReadPerByte := ← n "obj_access_cost_read_per_byte",
           pkgReadPerKb := ← natOrNone j "obj_access_cost_read_per_package_kb",
           publishPerByte := ← n "package_publish_cost_per_byte",
           storagePerByte := ← n "obj_data_cost_refundable",
           storageGasPrice := ← n "storage_gas_price",
           rebateRate := ← n "storage_rebate_rate",
           abortFactor := ← natOrNone j "max_gas_price_rgp_factor_for_aborted_transactions" }

def runOp (s : Status) : Op → Status × String
  | ("charge", [i, pu, po, inc, _]) =>
    let (m, e) := s.meter.charge i pu po inc
    ({ s with meter := m }, match e with | none => "ok" | some e => e.name)
  | ("deduct", [n]) =>
    let (m, e) := s.meter.deduct n
    ({ s with meter := m }, match e with | none => "ok" | some e => e.name)
  | ("read", [n]) => let (s, e) := s.chargeRead n; (s, match e with | none => "ok" | some e => e.name)
  | ("pkgread", [n]) => let (s, e) := s.chargePackageRead n; (s, match e with | none => "ok" | some e => e.name)
  | ("publish", [n]) => let (s, e) := s.chargePublish n; (s, match e with | none => "ok" | some e => e.name)
  | ("mutate", [sz, rb]) => let (s, c) := s.trackMutation sz rb; (s, match c with | none => "none" | some c => toString c)
  | ("bucketize", [a]) => let (s, e) := s.bucketize (a == 1); (s, match e with | none => "ok" | some e => e.name)
  | ("storage", []) => (s, match s.chargeStorage with | none => "ok" | some e => e.name)
  | ("oog", []) => (s.outOfGas, "ok")
  | ("reset", []) => (s.reset, "ok")
  | (n, _) => (s, "bad-op:" ++ n)

def resultJson (c : Config) (budget price rgp : Nat) (ops : List Op) : String :=
  match Status.new c budget price rgp with
  | .error e => "{\"new\":\"" ++ e.name ++ "\"}"
  | .ok s0 =>
    let (s, res) := ops.foldl (fun (s, acc) op => let (s', r) := runOp s op; (s', acc.push r)) (s0, #[])
    let (a, b, c', d) := s.summary
    "{\"res\":[" ++ ",".intercalate (res.toList.map fun r => "\"" ++ r ++ "\"") ++ "],\"summary\":[" ++
      s!"{a},{b},{c'},{d}],\"used\":{s.meter.used},\"left\":{s.meter.gasLeft}" ++ "}"

def opJson (op : Op) : String :=
  "[\"" ++ op.1 ++ "\"" ++ String.join (op.2.map fun n => "," ++ toString n) ++ "]"

/-- A random script: Move charges (some crossing tiers), reads, publishes, mutations, then
usually the executor's closing sequence. -/
def genScript : G (List Op) := do
  let n ← rand 24
  let mut ops := #[]
  let mut height := 0
  for _ in [0:n] do
    match ← rand 10 with
    | 0 | 1 | 2 =>
      let big ← rand 8
      let i ← if big == 0 then rand 60000 else rand 50
      let pu ← rand (if big == 1 then 5000 else 4)
      let po ← rand (height + pu + 1)
      let inc ← if big == 2 then rand 300000 else rand 64
      height := height + pu - po
      ops := ops.push ("charge", [i, pu, po, inc, 0])
    | 3 => ops := ops.push ("deduct", [← rand (if (← rand 4) == 0 then 50000000000 else 2000000)])
    | 4 => ops := ops.push ("read", [← rand 300000])
    | 5 => ops := ops.push ("pkgread", [← rand 300000])
    | 6 => ops := ops.push ("publish", [← rand 120000])
    | 7 | 8 => ops := ops.push ("mutate", [← rand 200000, ← rand 2000000000])
    | _ => ops := ops.push ("bucketize", [← rand 2])
  match ← rand 4 with
  | 0 => pure ()
  | _ =>
    ops := ops.push ("bucketize", [← rand 2])
    ops := ops.push ("storage", [])
    if (← rand 3) == 0 then
      ops := ops.push ("reset", [])
      ops := ops.push ("mutate", [← rand 1000, ← rand 100000])
      ops := ops.push ("storage", [])
    if (← rand 3) == 0 then ops := ops.push ("oog", [])
  return ops.toList

def genVector (cfgs : Array (Config × String)) (i : Nat) : G String := do
  let (c, raw) := cfgs[← rand cfgs.size]!
  let rgp ← pick [1, 750, 1000, (← rand 5000) + 1]
  let price ← match ← rand 10 with
    | 0 => rand rgp
    | 1 => pure c.maxGasPrice
    | 2 => pure (c.maxGasPrice - 1)
    | _ => pure (rgp + (← rand (rgp * 3)))
  let budget ← match ← rand 6 with
    | 0 => pure (1000 * rgp)
    | 1 => pure 50000000000000
    | 2 => rand 100000
    | _ => rand 5000000000
  let ops ← genScript
  return "{\"id\":\"gas/" ++ toString i ++ "\",\"pv\":" ++ toString c.pv ++ ",\"cfg\":" ++ raw ++
    ",\"budget\":" ++ toString budget ++ ",\"price\":" ++ toString price ++ ",\"rgp\":" ++ toString rgp ++
    ",\"ops\":[" ++ ",".intercalate (ops.map opJson) ++ "],\"expect\":" ++
    resultJson c budget price rgp ops ++ "}"

end Zui.Gas
