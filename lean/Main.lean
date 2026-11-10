import Zui

/-!
# zui-spec: the executable oracles (CONTRACTS.md section 5.11)

  zui-spec bcs-gen <registry.json> <out.jsonl> [seed] [fuzz]   export BCS vectors with the model's verdicts
  zui-spec bcs <registry.json> <vectors.jsonl>                re-check vectors: verdict, and encode(decode(b)) == b
  zui-spec bcs-chk <registry.json> <Type> <file>...           decode whole corpus blobs (0x01 tag + BCS) as <Type>
  zui-spec gas-gen <gas-config.json> <out.jsonl> [seed] [n]    export gas op scripts with the model's results
  zui-spec gas <vectors.jsonl>                                re-check gas vectors against the model
  zui-spec store-gen <dir> [seed] [n]                         write n example traces from the store model
  zui-spec store-trace <trace.jsonl>...                       check storage traces against the store model

Every command prints one JSON summary line last, with "done" true only when items > 0 and
nothing failed.
-/

open Zui Zui.Bcs Lean

def loadRegistry (path : String) : IO (Std.HashMap String Container) := do
  let text ← IO.FS.readFile path
  let j ← IO.ofExcept (Json.parse text)
  IO.ofExcept (parseRegistryJson j)

def summary (name : String) (items failed : Nat) (extra : String := "") : String :=
  "{\"check\":\"" ++ name ++ "\",\"items\":" ++ toString items ++ ",\"failed\":" ++ toString failed ++
    extra ++ ",\"done\":" ++ (if items > 0 && failed == 0 then "true" else "false") ++ "}"

def cmdBcsGen (reg out : String) (seed fuzz : Nat) : IO UInt32 := do
  let base ← loadRegistry reg
  let vs := allVectors base seed.toUInt64 fuzz
  let h ← IO.FS.Handle.mk out .write
  let mut n := 0
  for v in vs do
    h.putStrLn (v.line base)
    n := n + 1
  h.flush
  IO.println (summary "lean-bcs-gen" n 0)
  return 0

def cmdBcs (reg path : String) : IO UInt32 := do
  let base ← loadRegistry reg
  let lines := (← IO.FS.readFile path).splitOn "\n" |>.filter (· ≠ "")
  let mut items := 0
  let mut failed := 0
  for line in lines do
    let j ← IO.ofExcept (Json.parse line)
    let id ← IO.ofExcept (j.getObjValAs? String "id")
    let fmt ← IO.ofExcept (parseFmt (← IO.ofExcept (j.getObjVal? "fmt")))
    let types ← match j.getObjVal? "types" with
      | .ok t => IO.ofExcept (parseRegistryJson t)
      | .error _ => pure {}
    let some bytes := ofHex (← IO.ofExcept (j.getObjValAs? String "hex"))
      | throw (IO.userError s!"bad hex in {id}")
    let expect ← IO.ofExcept (j.getObjValAs? String "expect")
    let R := Registry.ofMaps base types
    let (got, reenc) := match decodeFull R fmt bytes with
      | .ok v => ("ok", encode v == bytes)
      | .error e => (e.name, true)
    items := items + 1
    if got != expect || !reenc then
      failed := failed + 1
      if failed ≤ 50 then IO.println s!"FAIL {id} expect={expect} lean={got} reencode={reenc}"
  IO.println (summary "lean-bcs" items failed)
  return if failed == 0 && items > 0 then 0 else 1

def cmdBcsChk (reg ty : String) (files : List String) : IO UInt32 := do
  let base ← loadRegistry reg
  let R := Registry.ofMaps base {}
  let mut items := 0
  let mut failed := 0
  let mut bytesTotal := 0
  let t0 ← IO.monoNanosNow
  for f in files do
    let raw ← IO.FS.readBinFile f
    let bs := raw.toList
    items := items + 1
    bytesTotal := bytesTotal + raw.size
    match bs with
    | 0x01 :: body =>
      match decodeFull R (.ref ty) body with
      | .ok v =>
        if encode v != body then
          failed := failed + 1
          IO.println s!"FAIL {f} re-encode differs"
      | .error e =>
        failed := failed + 1
        IO.println s!"FAIL {f} {e.name}"
    | _ =>
      failed := failed + 1
      IO.println s!"FAIL {f} blob tag is not 0x01"
  let t1 ← IO.monoNanosNow
  IO.println (summary "lean-bcs-chk" items failed
    s!",\"bytes\":{bytesTotal},\"ns\":{t1 - t0}")
  return if failed == 0 && items > 0 then 0 else 1

def loadGasConfigs (path : String) : IO (Array (Gas.Config × String)) := do
  let j ← IO.ofExcept (Json.parse (← IO.FS.readFile path))
  let arr ← IO.ofExcept j.getArr?
  let mut out := #[]
  for e in arr do
    let c ← IO.ofExcept (Gas.parseConfig e)
    -- gas model 15 (gas_v3) is what the model covers: protocol 138 and later
    if c.gasModelVersion == 15 then out := out.push (c, e.compress)
  return out

def cmdGasGen (cfgPath out : String) (seed n : Nat) : IO UInt32 := do
  let cfgs ← loadGasConfigs cfgPath
  let h ← IO.FS.Handle.mk out .write
  let gen : Bcs.G (Array String) := do
    let mut acc := #[]
    for i in [0:n] do acc := acc.push (← Gas.genVector cfgs i)
    return acc
  let lines := (gen.run ⟨seed.toUInt64⟩).1
  for l in lines do h.putStrLn l
  h.flush
  IO.println (summary "lean-gas-gen" lines.size 0 s!",\"configs\":{cfgs.size}")
  return 0

def cmdGas (path : String) : IO UInt32 := do
  let lines := (← IO.FS.readFile path).splitOn "\n" |>.filter (· ≠ "")
  let mut items := 0
  let mut failed := 0
  for line in lines do
    let j ← IO.ofExcept (Json.parse line)
    let c ← IO.ofExcept (Gas.parseConfig (← IO.ofExcept (j.getObjVal? "cfg")))
    let n := fun k => IO.ofExcept (do (← j.getObjVal? k).getNat?)
    let ops ← IO.ofExcept (do
      (← (← j.getObjVal? "ops").getArr?).toList.mapM fun o => do
        let a ← o.getArr?
        let name ← a[0]!.getStr?
        let args ← (a.toList.drop 1).mapM (·.getNat?)
        pure (name, args))
    let got ← IO.ofExcept (Json.parse (Gas.resultJson c (← n "budget") (← n "price") (← n "rgp") ops))
    let expect ← IO.ofExcept (j.getObjVal? "expect")
    items := items + 1
    if got.compress != expect.compress then
      failed := failed + 1
      if failed ≤ 20 then IO.println s!"FAIL {(j.getObjValAs? String "id").toOption} {got.compress}"
  IO.println (summary "lean-gas" items failed)
  return if failed == 0 && items > 0 then 0 else 1

def cmdStoreTrace (files : List String) : IO UInt32 := do
  let mut items := 0
  let mut failed := 0
  let mut events := 0
  for f in files do
    let lines := (← IO.FS.readFile f).splitOn "\n" |>.filter (· ≠ "")
    let c ← IO.ofExcept (lines.foldlM Store.Checker.step {})
    items := items + 1
    events := events + c.events
    if c.failed > 0 then
      failed := failed + 1
      for m in c.msgs do IO.println s!"FAIL {f} {m}"
  IO.println (summary "lean-store" items failed s!",\"events\":{events}")
  return if failed == 0 && items > 0 then 0 else 1

def cmdStoreGen (dir : String) (seed n : Nat) : IO UInt32 := do
  IO.FS.createDirAll dir
  let gen : Bcs.G (Array (Array String)) := do
    let mut acc := #[]
    for _ in [0:n] do acc := acc.push (← Store.genTrace ((← Bcs.rand 400) + 1))
    return acc
  let traces := (gen.run ⟨seed.toUInt64⟩).1
  let mut i := 0
  for t in traces do
    IO.FS.writeFile s!"{dir}/trace-{i}.jsonl" (String.join (t.toList.map (· ++ "\n")))
    i := i + 1
  IO.println (summary "lean-store-gen" traces.size 0)
  return 0

def main (args : List String) : IO UInt32 := do
  match args with
  | ["bcs-gen", reg, out] => cmdBcsGen reg out 1 20000
  | ["bcs-gen", reg, out, seed, fuzz] => cmdBcsGen reg out seed.toNat! fuzz.toNat!
  | ["bcs", reg, path] => cmdBcs reg path
  | "bcs-chk" :: reg :: ty :: files => cmdBcsChk reg ty files
  | ["gas-gen", cfg, out] => cmdGasGen cfg out 1 20000
  | ["gas-gen", cfg, out, seed, n] => cmdGasGen cfg out seed.toNat! n.toNat!
  | ["gas", path] => cmdGas path
  | ["store-gen", dir] => cmdStoreGen dir 1 1000
  | ["store-gen", dir, seed, n] => cmdStoreGen dir seed.toNat! n.toNat!
  | "store-trace" :: files@(_ :: _) => cmdStoreTrace files
  | _ =>
    IO.eprintln "usage: zui-spec bcs-gen|bcs|bcs-chk|gas-gen|gas|store-gen|store-trace ... (see lean/README.md)"
    return 2
