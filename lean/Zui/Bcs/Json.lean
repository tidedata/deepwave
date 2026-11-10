import Lean.Data.Json
import Std.Data.HashMap
import Zui.Bcs.Basic

/-!
# Registry I/O for the oracle

Reads a serde-reflection registry as JSON (`zui-lean-truth registry` converts
`spec/sui-format-1.83.1.yaml.snap`) into the model's `Fmt`/`Container`, and prints formats back
as serde-reflection JSON so the Rust checker can rebuild the same format. Not part of the
proofs: these functions only build inputs for the proved decoder.
-/

namespace Zui.Bcs
open Lean

/-- The single key of a one-entry JSON object. -/
def singleKey (j : Json) : Except String (String × Json) :=
  match j with
  | .obj kvs =>
    match kvs.foldl (fun acc k v => (k, v) :: acc) [] with
    | [kv] => .ok kv
    | _ => .error s!"expected a one-key object, got {j.compress}"
  | _ => .error s!"expected an object, got {j.compress}"

partial def parseFmt (j : Json) : Except String Fmt := do
  match j with
  | .str "UNIT" => pure .unit
  | .str "BOOL" => pure .bool
  | .str "U8" => pure (.uint 1)
  | .str "U16" => pure (.uint 2)
  | .str "U32" => pure (.uint 4)
  | .str "U64" => pure (.uint 8)
  | .str "U128" => pure (.uint 16)
  | .str "U256" => pure (.uint 32)
  | .str "STR" => pure .str
  | .str "BYTES" => pure .bytes
  | .str s => throw s!"unsupported format {s}"
  | _ =>
    let (k, v) ← singleKey j
    match k with
    | "TYPENAME" => return .ref (← v.getStr?)
    | "OPTION" => return .option (← parseFmt v)
    | "SEQ" => return .seq (← parseFmt v)
    | "MAP" => return .map (← parseFmt (← v.getObjVal? "KEY")) (← parseFmt (← v.getObjVal? "VALUE"))
    | "TUPLE" => return .tuple (← (← v.getArr?).toList.mapM parseFmt)
    | "TUPLEARRAY" =>
      return .array (← parseFmt (← v.getObjVal? "CONTENT")) (← (← v.getObjVal? "SIZE").getNat?)
    | _ => throw s!"unsupported format {k}"

/-- `[{"name": fmt}, ...]` -> the field formats in order. -/
def parseNamedList (j : Json) : Except String (List Fmt) := do
  (← j.getArr?).toList.mapM fun e => do
    let (_, f) ← singleKey e
    parseFmt f

def parseVariant (j : Json) : Except String Fmt := do
  match j with
  | .str "UNIT" => pure .unit
  | _ =>
    let (k, v) ← singleKey j
    match k with
    | "NEWTYPE" => parseFmt v
    | "TUPLE" => return .tuple (← (← v.getArr?).toList.mapM parseFmt)
    | "STRUCT" => return .tuple (← parseNamedList v)
    | _ => throw s!"unsupported variant format {k}"

def parseContainer (j : Json) : Except String Container := do
  match j with
  | .str "UNITSTRUCT" => pure (.struct [])
  | _ =>
    let (k, v) ← singleKey j
    match k with
    | "NEWTYPESTRUCT" => return .struct [← parseFmt v]
    | "TUPLESTRUCT" => return .struct (← (← v.getArr?).toList.mapM parseFmt)
    | "STRUCT" => return .struct (← parseNamedList v)
    | "ENUM" =>
      match v with
      | .obj kvs =>
        let entries := kvs.foldl (fun acc k e => (k, e) :: acc) []
        let mut indexed : Array (Nat × Fmt) := #[]
        for (ik, e) in entries do
          let some i := ik.toNat? | throw s!"bad variant index {ik}"
          let (_, vf) ← singleKey e
          indexed := indexed.push (i, ← parseVariant vf)
        let sorted := indexed.qsort (fun a b => a.1 < b.1)
        for h : n in [0:sorted.size] do
          if sorted[n].1 != n then throw "variant indices are not 0..n-1"
        return .enum (sorted.toList.map (·.2))
      | _ => throw "ENUM expects an object"
    | _ => throw s!"unsupported container {k}"

def parseRegistryJson (j : Json) : Except String (Std.HashMap String Container) := do
  match j with
  | .obj kvs =>
    let entries := kvs.foldl (fun acc k e => (k, e) :: acc) []
    let mut m : Std.HashMap String Container := {}
    for (name, c) in entries do
      m := m.insert name (← parseContainer c)
    return m
  | _ => throw "registry must be an object"

def Registry.ofMaps (base extra : Std.HashMap String Container) : Registry :=
  ⟨fun n => match extra.get? n with
    | Option.some c => Option.some c
    | Option.none => base.get? n⟩

/-! ## Printing (serde-reflection JSON) -/

def jsonStr (s : String) : String := (Json.str s).compress

partial def Fmt.toJson : Fmt → String
  | .unit => "\"UNIT\""
  | .bool => "\"BOOL\""
  | .uint 1 => "\"U8\""
  | .uint 2 => "\"U16\""
  | .uint 4 => "\"U32\""
  | .uint 8 => "\"U64\""
  | .uint 16 => "\"U128\""
  | .uint w => s!"\"U{8 * w}\""
  | .str => "\"STR\""
  | .bytes => "\"BYTES\""
  | .option f => "{\"OPTION\":" ++ f.toJson ++ "}"
  | .seq f => "{\"SEQ\":" ++ f.toJson ++ "}"
  | .map k v => "{\"MAP\":{\"KEY\":" ++ k.toJson ++ ",\"VALUE\":" ++ v.toJson ++ "}}"
  | .tuple fs => "{\"TUPLE\":[" ++ ",".intercalate (fs.map Fmt.toJson) ++ "]}"
  | .array f n => "{\"TUPLEARRAY\":{\"CONTENT\":" ++ f.toJson ++ ",\"SIZE\":" ++ toString n ++ "}}"
  | .ref n => "{\"TYPENAME\":" ++ jsonStr n ++ "}"

def variantToJson : Fmt → String
  | .unit => "\"UNIT\""
  | .tuple fs => "{\"TUPLE\":[" ++ ",".intercalate (fs.map Fmt.toJson) ++ "]}"
  | f => "{\"NEWTYPE\":" ++ f.toJson ++ "}"

def Container.toJson : Container → String
  | .struct fs =>
    let named := (List.range fs.length).zip fs |>.map fun (i, f) => "{\"f" ++ toString i ++ "\":" ++ f.toJson ++ "}"
    "{\"STRUCT\":[" ++ ",".intercalate named ++ "]}"
  | .enum vs =>
    let named := (List.range vs.length).zip vs |>.map fun (i, f) =>
      "\"" ++ toString i ++ "\":{\"V" ++ toString i ++ "\":" ++ variantToJson f ++ "}"
    "{\"ENUM\":{" ++ ",".intercalate named ++ "}}"

def typesToJson (ts : List (String × Container)) : String :=
  "{" ++ ",".intercalate (ts.map fun (n, c) => jsonStr n ++ ":" ++ c.toJson) ++ "}"

/-! ## Hex -/

def hexDigit (n : Nat) : Char := "0123456789abcdef".toList[n % 16]!

def toHex (bs : Bytes) : String :=
  String.ofList (bs.foldr (fun b acc => hexDigit (b.toNat / 16) :: hexDigit (b.toNat % 16) :: acc) [])

def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def ofHex (s : String) : Option Bytes :=
  let rec go : List Char → Option Bytes
    | [] => some []
    | a :: b :: r => do
      let x ← hexVal a
      let y ← hexVal b
      let rest ← go r
      pure (UInt8.ofNat (x * 16 + y) :: rest)
    | _ => none
  go s.toList

end Zui.Bcs
