import Lean.Data.Json
import Zui.Store.Theorems
import Zui.Bcs.Gen

/-!
# Store trace oracle

A storage trace is NDJSON, one event per line, in the order the implementation did them:

  {"op":"commit","writes":[[key,version,value],...]}   one checkpoint's group (sequence implicit)
  {"op":"ack"}                                         every commit so far is durable
  {"op":"read","state":[[key,version,value],...]}      the live index, no crash
  {"op":"recover","k":n,"state":[[key,version,value],...]}
                                                       after a crash and reopen: n checkpoints
                                                       recovered, and the live index

`state` lists every key that has an entry, sorted by key, with its newest (version, value).
The checker holds the history `G` and checks each `recover` against `recover_crash`: the
acknowledged count `≤ n ≤` the started count, and the state equals `stateAt G n`. After a
recover the history is `G.take n` (later commits continue from there). A `read` must equal
the state after every commit so far.
-/

namespace Zui.Store
open Lean Zui.Bcs

/-- The model state on the keys written in `G.take j`, sorted. -/
def stateList (G : List Group) (j : Nat) : List (Nat × Nat × Nat) :=
  let gs := G.take j
  let keys := (gs.flatMap fun g => g.writes.map (·.1)).mergeSort (· ≤ ·) |>.eraseDups
  let st := stateAt G j
  keys.filterMap fun k => (st k).map fun (v, x) => (k, v, x)

def stateJson (l : List (Nat × Nat × Nat)) : String :=
  "[" ++ ",".intercalate (l.map fun (k, v, x) => s!"[{k},{v},{x}]") ++ "]"

def parseTriples (j : Json) : Except String (List (Nat × Nat × Nat)) := do
  (← j.getArr?).toList.mapM fun t => do
    let a ← t.getArr?
    if a.size != 3 then throw "expected [key,version,value]"
    pure (← a[0]!.getNat?, ← a[1]!.getNat?, ← a[2]!.getNat?)

structure Checker where
  hist : Array Group := #[]
  acked : Nat := 0
  events : Nat := 0
  failed : Nat := 0
  msgs : Array String := #[]

def Checker.fail (c : Checker) (m : String) : Checker :=
  { c with failed := c.failed + 1, msgs := if c.msgs.size < 20 then c.msgs.push m else c.msgs }

def Checker.step (c : Checker) (line : String) : Except String Checker := do
  let j ← Json.parse line
  let op ← j.getObjValAs? String "op"
  let c := { c with events := c.events + 1 }
  match op with
  | "commit" =>
    let ws ← parseTriples (← j.getObjVal? "writes")
    pure { c with hist := c.hist.push { seq := c.hist.size, writes := ws } }
  | "ack" => pure { c with acked := c.hist.size }
  | "read" =>
    let got ← parseTriples (← j.getObjVal? "state")
    let want := stateList c.hist.toList c.hist.size
    pure (if got == want then c else c.fail s!"event {c.events}: read state differs from the model")
  | "recover" =>
    let k ← (← j.getObjVal? "k").getNat?
    let got ← parseTriples (← j.getObjVal? "state")
    if k < c.acked then
      return c.fail s!"event {c.events}: recovered {k} < acknowledged {c.acked}"
    if k > c.hist.size then
      return c.fail s!"event {c.events}: recovered {k} > started {c.hist.size}"
    let want := stateList c.hist.toList k
    let c := if got == want then c else c.fail s!"event {c.events}: state after recovering {k} differs from stateAt"
    pure { c with hist := c.hist.extract 0 k, acked := k }
  | o => throw s!"unknown op {o}"

/-! ## Example traces, from the model itself (fixtures for implementations and a self-test) -/

def randWrites (keys : Nat) (ver : Nat) : G (List Write) := do
  let n ← rand 6
  let mut ws := #[]
  for _ in [0:n] do
    let k ← rand keys
    -- mostly increasing versions, sometimes a stale or tied one
    let v ← match ← rand 8 with
      | 0 => rand (ver + 1)
      | _ => pure ver
    ws := ws.push (k, v, ← rand 1000)
  return ws.toList

/-- One trace: commits, acks, reads, crashes. A crash keeps the acked prefix and a garbage tail
(each unsynced group intact, dropped or junk, with occasional junk after); recovery runs the
model's `recoverIndex` from a random snapshot `a ≤ j ≤ acked`. -/
def genTrace (steps : Nat) : G (Array String) := do
  let keys := (← rand 40) + 1
  let mut hist : Array Group := #[]
  let mut acked := 0
  let mut out := #[]
  let mut ver := 1
  for _ in [0:steps] do
    match ← rand 10 with
    | 0 | 1 | 2 | 3 =>
      let ws ← randWrites keys ver
      ver := ver + 1
      hist := hist.push { seq := hist.size, writes := ws }
      out := out.push ("{\"op\":\"commit\",\"writes\":" ++ stateJson ws ++ "}")
    | 4 | 5 =>
      acked := hist.size
      out := out.push "{\"op\":\"ack\"}"
    | 6 =>
      out := out.push ("{\"op\":\"read\",\"state\":" ++ stateJson (stateList hist.toList hist.size) ++ "}")
    | _ =>
      let G := hist.toList
      let mut tail : Array Entry := #[]
      for g in G.drop acked do
        match ← rand 4 with
        | 0 => tail := tail.push .junk
        | 1 => pure ()
        | _ => tail := tail.push (.grp g)
      if (← rand 3) == 0 then tail := tail.push .junk
      if (← rand 3) == 0 && G.length > 0 then tail := tail.push (.grp G[← rand G.length]!)
      let log := crashLog G acked tail.toList
      let k := (recoverLog log).length
      let jj ← rand (acked + 1)
      let a ← rand (jj + 1)
      let st := recoverIndex (stateAt G jj) a log
      let keysAll := (G.flatMap fun g => g.writes.map (·.1)).mergeSort (· ≤ ·) |>.eraseDups
      let l := keysAll.filterMap fun key => (st key).map fun (v, x) => (key, v, x)
      out := out.push ("{\"op\":\"recover\",\"k\":" ++ toString k ++ ",\"state\":" ++ stateJson l ++ "}")
      hist := hist.extract 0 k
      acked := k
  return out

end Zui.Store
