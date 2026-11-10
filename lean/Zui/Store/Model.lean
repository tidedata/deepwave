/-!
# Store: the crash-recovery protocol

A model of zui's storage protocol (ARCHITECTURE.md section 8; `src/store/store.zig`):

* the log is a sequence of **commit groups**, one per checkpoint, each hash-chained to the one
  before (a group is valid only where the chain expects it);
* `commit` appends a group and makes it durable with one sync, then acknowledges it; in
  catch-up several groups may be appended before one sync;
* a **crash** keeps every synced entry and, of the unsynced ones, any subset of whole groups
  where each lost group is either missing or torn into junk (sector-level tearing, lost writes,
  reordering inside the unsynced tail), followed possibly by stale junk;
* **recovery** scans from the start and keeps the longest run of valid, chained groups,
  truncating the rest;
* the derived **index** maps each object to its newest (version, value); it is snapshotted with
  the log position it covers, and recovery replays the log after the snapshot. Updates take the
  higher version, so replaying groups the snapshot already holds changes nothing.

Keys, versions and values are `Nat`: the protocol does not look inside them.
-/

namespace Zui.Store

abbrev Key := Nat
abbrev Val := Nat

/-- One write: object key, version, value (a tombstone is just another value). -/
abbrev Write := Key × Nat × Val

structure Group where
  seq : Nat
  writes : List Write
  deriving Repr, DecidableEq, Inhabited

inductive Entry where
  | grp (g : Group)
  | junk
  deriving Repr, DecidableEq, Inhabited

/-- Recovery scan: the longest run of groups with consecutive sequence numbers from `next`
(the hash chain makes a group valid only in its own place). -/
def scan (next : Nat) : List Entry → List Group
  | [] => []
  | .junk :: _ => []
  | .grp g :: rest => if g.seq = next then g :: scan (next + 1) rest else []

def recoverLog (log : List Entry) : List Group := scan 0 log

/-- What a crash may leave after the synced prefix of history `G`: any entries at all, as long
as each is junk (torn, zeroed, misdirected, rotted bytes) or some group of `G` (an unsynced group
that survived, possibly out of order, or a stale copy). The hash chain is the assumption that
nothing else passes validation: a valid group in place `i` is `G[i]`. -/
def Garbage (G : List Group) (tail : List Entry) : Prop :=
  ∀ e ∈ tail, e = .junk ∨ ∃ g ∈ G, e = .grp g

/-- `G` is a history: group `i` carries sequence number `i`. -/
def History (G : List Group) : Prop := ∀ (i : Nat) (h : i < G.length), G[i].seq = i

/-- The on-disk log after a crash: the first `s` groups (synced before the crash) intact, then
whatever the crash left. -/
def crashLog (G : List Group) (s : Nat) (tail : List Entry) : List Entry :=
  (G.take s).map .grp ++ tail

/-! ## The index -/

abbrev State := Key → Option (Nat × Val)

def State.empty : State := fun _ => none

/-- The newer of two entries by version; on equal versions the first is kept. -/
def merge : Option (Nat × Val) → Option (Nat × Val) → Option (Nat × Val)
  | none, b => b
  | a, none => a
  | some (v, x), some (w, y) => if w > v then some (w, y) else some (v, x)

def applyWrite (s : State) (w : Write) : State :=
  fun k => if k = w.1 then merge (s k) (some w.2) else s k

def applyGroup (s : State) (g : Group) : State := g.writes.foldl applyWrite s

def replay (s : State) (gs : List Group) : State := gs.foldl applyGroup s

/-- The state after the first `j` checkpoints. -/
def stateAt (G : List Group) (j : Nat) : State := replay State.empty (G.take j)

/-- Recovery from an index snapshot covering the first `a` groups: load it, replay the
recovered log after position `a`. -/
def recoverIndex (snap : State) (a : Nat) (log : List Entry) : State :=
  replay snap ((recoverLog log).drop a)

end Zui.Store
