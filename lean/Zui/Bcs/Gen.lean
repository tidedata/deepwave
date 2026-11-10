import Zui.Bcs.Json

/-!
# BCS vector export

Builds the `lean-bcs` vectors: edge cases chosen from the model's own case splits (every
error the decoder can raise, at and around every limit) plus seeded random values of every
type in the Sui registry, encoded by the model and then mutated. Each vector carries the
proved decoder's verdict; `zui-lean-truth bcs-check` must agree on every one.
-/

namespace Zui.Bcs

/-- splitmix64. -/
structure Rng where
  s : UInt64

def Rng.next (r : Rng) : UInt64 × Rng :=
  let s := r.s + 0x9e3779b97f4a7c15
  let z := s
  let z := (z ^^^ (z >>> 30)) * 0xbf58476d1ce4e5b9
  let z := (z ^^^ (z >>> 27)) * 0x94d049bb133111eb
  (z ^^^ (z >>> 31), ⟨s⟩)

abbrev G := StateM Rng

def rand (n : Nat) : G Nat := do
  let r ← get
  let (x, r') := r.next
  set r'
  return if n == 0 then 0 else x.toNat % n

def randByte : G UInt8 := do return UInt8.ofNat (← rand 256)
def randBytes (n : Nat) : G Bytes := (List.range n).mapM fun _ => randByte
def pick {α} [Inhabited α] (xs : List α) : G α := do return xs[← rand xs.length]!

/-- One vector line. -/
structure Vec where
  id : String
  types : List (String × Container) := []
  fmt : Fmt
  bytes : Bytes

def verdict (base : Std.HashMap String Container) (v : Vec) : String :=
  let R := Registry.ofMaps base (Std.HashMap.ofList v.types)
  match decodeFull R v.fmt v.bytes with
  | .ok _ => "ok"
  | .error e => e.name

def Vec.line (base : Std.HashMap String Container) (v : Vec) : String :=
  let types := if v.types.isEmpty then "" else ",\"types\":" ++ typesToJson v.types
  "{\"id\":" ++ jsonStr v.id ++ types ++ ",\"fmt\":" ++ v.fmt.toJson ++ ",\"hex\":\"" ++
    toHex v.bytes ++ "\",\"expect\":\"" ++ verdict base v ++ "\"}"

/-! ## Edge cases -/

def ulebAlphabet : List UInt8 := [0x00, 0x01, 0x02, 0x07, 0x08, 0x0f, 0x10, 0x7f, 0x80, 0x81, 0x8f, 0xf0, 0xff]

/-- All byte strings of length `k` over `alpha`. -/
def strings (alpha : List UInt8) : Nat → List Bytes
  | 0 => [[]]
  | k + 1 => (strings alpha k).flatMap fun s => alpha.map (· :: s)

def edgeUleb : G (List Vec) := do
  let mut out := #[]
  -- lengths of BYTES, over every 1..4-byte prefix from the alphabet, then 3 payload bytes
  for k in [1:5] do
    for p in strings ulebAlphabet k do
      out := out.push { id := s!"uleb-len/{toHex p}", fmt := .bytes, bytes := p ++ [0xaa, 0xbb, 0xcc] }
      out := out.push { id := s!"uleb-len-bare/{toHex p}", fmt := .bytes, bytes := p }
  -- 5 and 6 byte prefixes: sampled
  for i in [0:6000] do
    let k := 5 + (← rand 2)
    let p ← (List.range k).mapM fun _ => pick ulebAlphabet
    out := out.push { id := s!"uleb-len5/{i}/{toHex p}", fmt := .bytes, bytes := p ++ [0xaa] }
  -- exact boundaries
  for n in [0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456,
            2147483646, 2147483647, 2147483648, 4294967295] do
    out := out.push { id := s!"uleb-len-exact/{n}", fmt := .bytes, bytes := uleb n }
    out := out.push { id := s!"uleb-seq-exact/{n}", fmt := .seq (.uint 1), bytes := uleb n ++ [1, 2] }
    out := out.push { id := s!"uleb-str-exact/{n}", fmt := .str, bytes := uleb n ++ [0x41] }
    out := out.push { id := s!"uleb-map-exact/{n}", fmt := .map (.uint 1) (.uint 1), bytes := uleb n ++ [1, 2] }
  -- uleb(2^32) and beyond, non-minimal forms of small values
  for p in [[0x80, 0x80, 0x80, 0x80, 0x10], [0xff, 0xff, 0xff, 0xff, 0x0f], [0xff, 0xff, 0xff, 0xff, 0x1f],
            [0x80, 0x00], [0x81, 0x00], [0xff, 0x00], [0x80, 0x80, 0x00], [0x80, 0x80, 0x80, 0x80, 0x00],
            [0x80, 0x80, 0x80, 0x80, 0x80, 0x01], [0xff, 0xff, 0xff, 0xff, 0x07]] do
    out := out.push { id := s!"uleb-odd/{toHex p}", fmt := .bytes, bytes := p }
  -- variant indices of a 3-variant enum
  let e : Container := .enum [.unit, .uint 1, .tuple [.uint 1, .uint 2]]
  for k in [1:4] do
    for p in strings ulebAlphabet k do
      out := out.push { id := s!"uleb-variant/{toHex p}", types := [("E", e)], fmt := .ref "E",
                        bytes := p ++ [0x01, 0x02, 0x03] }
      out := out.push { id := s!"uleb-variant-exact/{toHex p}", types := [("E", e)], fmt := .ref "E", bytes := p }
  return out.toList

def edgeTags : List Vec := Id.run do
  let mut out := #[]
  for b in List.range 256 do
    let x := UInt8.ofNat b
    out := out.push { id := s!"bool/{b}", fmt := .bool, bytes := [x] }
    out := out.push { id := s!"bool-trail/{b}", fmt := .bool, bytes := [x, 0] }
    out := out.push { id := s!"option/{b}", fmt := .option (.uint 1), bytes := [x, 5] }
    out := out.push { id := s!"option-bare/{b}", fmt := .option (.uint 1), bytes := [x] }
    out := out.push { id := s!"option-unit/{b}", fmt := .option .unit, bytes := [x] }
  out := out.push { id := "bool/empty", fmt := .bool, bytes := [] }
  out := out.push { id := "option/empty", fmt := .option .bool, bytes := [] }
  out := out.push { id := "unit/empty", fmt := .unit, bytes := [] }
  out := out.push { id := "unit/trail", fmt := .unit, bytes := [0] }
  return out.toList

def edgeInts : G (List Vec) := do
  let mut out := #[]
  for w in [1, 2, 4, 8, 16] do
    for n in List.range (w + 3) do
      for i in [0:4] do
        let bs ← randBytes n
        out := out.push { id := s!"uint{8 * w}/{n}/{i}", fmt := .uint w, bytes := bs }
    out := out.push { id := s!"uint{8 * w}/max", fmt := .uint w, bytes := List.replicate w 0xff }
    out := out.push { id := s!"array{w}/short", fmt := .array (.uint 1) w, bytes := List.replicate (w - 1) 7 }
    out := out.push { id := s!"array{w}/exact", fmt := .array (.uint 1) w, bytes := List.replicate w 7 }
  out := out.push { id := "array32-of-u16/short", fmt := .array (.uint 2) 32, bytes := List.replicate 63 1 }
  out := out.push { id := "array0", fmt := .array (.uint 8) 0, bytes := [] }
  out := out.push { id := "tuple0-trail", fmt := .tuple [], bytes := [1] }
  return out.toList

def utf8Edge : List Bytes :=
  [[0x00], [0x7f], [0x80], [0xbf], [0xc0, 0x80], [0xc1, 0xbf], [0xc2, 0x80], [0xdf, 0xbf], [0xc2],
   [0xe0, 0x80, 0x80], [0xe0, 0x9f, 0xbf], [0xe0, 0xa0, 0x80], [0xe1, 0x80, 0x80], [0xec, 0xbf, 0xbf],
   [0xed, 0x80, 0x80], [0xed, 0x9f, 0xbf], [0xed, 0xa0, 0x80], [0xed, 0xbf, 0xbf], [0xee, 0x80, 0x80],
   [0xef, 0xbf, 0xbf], [0xef, 0xbf], [0xf0, 0x80, 0x80, 0x80], [0xf0, 0x8f, 0xbf, 0xbf],
   [0xf0, 0x90, 0x80, 0x80], [0xf3, 0xbf, 0xbf, 0xbf], [0xf4, 0x80, 0x80, 0x80], [0xf4, 0x8f, 0xbf, 0xbf],
   [0xf4, 0x90, 0x80, 0x80], [0xf5, 0x80, 0x80, 0x80], [0xf8, 0x88, 0x80, 0x80, 0x80], [0xff], [0xfe],
   [0xf0, 0x90, 0x80], [0xe2, 0x82, 0xac, 0x41], [0x41, 0xe2, 0x82]]

def edgeUtf8 : G (List Vec) := do
  let mut out := #[]
  for s in utf8Edge do
    out := out.push { id := s!"utf8-edge/{toHex s}", fmt := .str, bytes := uleb s.length ++ s }
  for b in List.range 256 do
    out := out.push { id := s!"utf8-1/{b}", fmt := .str, bytes := [1, UInt8.ofNat b] }
  for a in List.range 256 do
    for b in List.range 256 do
      out := out.push { id := s!"utf8-2/{a}/{b}", fmt := .str, bytes := [2, UInt8.ofNat a, UInt8.ofNat b] }
  -- 3- and 4-byte strings: lead byte from the multi-byte ranges, the rest near the borders
  let cont : List UInt8 := [0x00, 0x41, 0x7f, 0x80, 0x81, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xff]
  for lead in List.range 0x20 do
    for c in cont do
      for d in cont do
        let l := UInt8.ofNat (0xe0 + lead)
        out := out.push { id := s!"utf8-3/{toHex [l, c, d]}", fmt := .str, bytes := [3, l, c, d] }
  for lead in List.range 0x10 do
    for i in [0:200] do
      let l := UInt8.ofNat (0xf0 + lead)
      let c ← pick cont
      let d ← pick cont
      let e ← pick cont
      out := out.push { id := s!"utf8-4/{i}/{toHex [l, c, d, e]}", fmt := .str, bytes := [4, l, c, d, e] }
  return out.toList

/-- `L` is a linked list of named enums: `n` ones then a zero enter `n + 1` containers.
`W` wraps the recursion in an option and a sequence, which do not count. `N` adds a newtype
struct per level, so each level enters two containers. -/
def depthTypes : List (String × Container) :=
  [("L", .enum [.unit, .ref "L"]),
   ("W", .enum [.unit, .option (.seq (.ref "W"))]),
   ("N", .struct [.ref "M"]),
   ("M", .enum [.unit, .ref "N"])]

def edgeDepth : List Vec := Id.run do
  let mut out := #[]
  for n in [0, 1, 2, 248, 249, 250, 251, 497, 498, 499, 500, 501, 502, 600] do
    out := out.push { id := s!"depth-L/{n}", types := depthTypes, fmt := .ref "L",
                      bytes := List.replicate n 1 ++ [0] }
    out := out.push { id := s!"depth-W/{n}", types := depthTypes, fmt := .ref "W",
                      bytes := (List.replicate n [1, 1, 1]).flatten ++ [0] }
    out := out.push { id := s!"depth-N/{n}", types := depthTypes, fmt := .ref "N",
                      bytes := List.replicate n 1 ++ [0] }
    -- unterminated chains: depth error or Eof, whichever Rust meets first
    out := out.push { id := s!"depth-L-open/{n}", types := depthTypes, fmt := .ref "L",
                      bytes := List.replicate n 1 }
    -- a sequence of the chain does not add depth
    out := out.push { id := s!"depth-seqL/{n}", types := depthTypes, fmt := .seq (.ref "L"),
                      bytes := [2] ++ List.replicate n 1 ++ [0, 0] }
  return out.toList

def edgeMaps : G (List Vec) := do
  let mut out := #[]
  let keys : List UInt8 := [0, 1, 2]
  for k1 in keys do
    for k2 in keys do
      for k3 in keys do
        out := out.push { id := s!"map-u8/{k1}{k2}{k3}", fmt := .map (.uint 1) (.uint 1),
                          bytes := [3, k1, 9, k2, 9, k3, 9] }
  -- u16 keys: byte order differs from numeric order
  for (a, b) in [((1 : Nat), (256 : Nat)), (256, 1), (255, 256), (256, 255), (1, 1), (0, 65535), (65535, 0)] do
    out := out.push { id := s!"map-u16/{a}-{b}", fmt := .map (.uint 2) .unit,
                      bytes := [2] ++ leBytes 2 a ++ leBytes 2 b }
  -- byte-string keys: encoded with a length prefix, so "b" < "aa"
  let ks : List Bytes := [[], [0x61], [0x62], [0x61, 0x61], [0x61, 0x62], [0x00], [0xff]]
  for a in ks do
    for b in ks do
      out := out.push { id := s!"map-bytes/{toHex a}-{toHex b}", fmt := .map .bytes (.uint 1),
                        bytes := [2] ++ uleb a.length ++ a ++ [7] ++ uleb b.length ++ b ++ [7] }
  -- a bad key after a good one; a bad value; empty and truncated maps
  out := out.push { id := "map/key-error", fmt := .map .bool .unit, bytes := [2, 0, 2] }
  out := out.push { id := "map/value-error", fmt := .map (.uint 1) .bool, bytes := [2, 0, 1, 1, 2] }
  out := out.push { id := "map/empty", fmt := .map (.uint 1) .bool, bytes := [0] }
  out := out.push { id := "map/short", fmt := .map (.uint 1) .bool, bytes := [2, 0, 1] }
  -- unsorted keys whose value is malformed: the order check comes first
  out := out.push { id := "map/order-before-value", fmt := .map (.uint 1) .bool, bytes := [2, 5, 1, 4, 9] }
  -- random maps of small keys
  for i in [0:2000] do
    let n ← rand 5
    let mut bs : Bytes := uleb n
    for _ in [0:n] do
      bs := bs ++ [← pick [0, 1, 2, 3], ← pick [0, 1, 2]]
    out := out.push { id := s!"map-rand/{i}", fmt := .map (.uint 1) .bool, bytes := bs }
  return out.toList

/-! ## Random well-formed values of registry types -/

def asciiOrMulti : G Bytes := do
  match ← rand 6 with
  | 0 => pure [0xe2, 0x82, 0xac]
  | 1 => pure [0xc3, 0xa9]
  | 2 => pure [0xf0, 0x9f, 0x98, 0x80]
  | _ => pure [UInt8.ofNat (0x20 + (← rand 95))]

partial def genVal (R : Registry) (fuel : Nat) (f : Fmt) : G Value := do
  match f with
  | .unit => pure .unit
  | .bool => return .bool ((← rand 2) == 1)
  | .uint w =>
    match ← rand 4 with
    | 0 => pure (.uint w 0)
    | 1 => pure (.uint w (2 ^ (8 * w) - 1))
    | _ => return .uint w (leVal (← randBytes w))
  | .str =>
    let n ← rand (if fuel == 0 then 2 else 6)
    let parts ← (List.range n).mapM fun _ => asciiOrMulti
    return .str parts.flatten
  | .bytes => return .bytes (← randBytes (← rand 40))
  | .option g =>
    if fuel == 0 || (← rand 2) == 0 then pure .none else return .some (← genVal R (fuel - 1) g)
  | .seq g =>
    let n ← if fuel == 0 then pure 0 else rand (match g with | .uint 1 => 40 | _ => 4)
    return .seq (← (List.range n).mapM fun _ => genVal R (fuel - 1) g)
  | .map kf vf =>
    let n ← if fuel == 0 then pure 0 else rand 4
    let kvs ← (List.range n).mapM fun _ => do
      return (← genVal R (fuel - 1) kf, ← genVal R (fuel - 1) vf)
    -- canonical order: sort by encoded key, drop duplicates (what bcs's serializer does)
    let sorted := kvs.toArray.qsort (fun a b => lexLt (encode a.1) (encode b.1)) |>.toList
    let dedup := sorted.foldr (fun kv acc => match acc with
      | [] => [kv]
      | kv' :: _ => if encode kv.1 == encode kv'.1 then acc else kv :: acc) []
    return .map dedup
  | .tuple fs => return .tuple (← fs.mapM (genVal R fuel))
  | .array g n => return .tuple (← (List.range n).mapM fun _ => genVal R fuel g)
  | .ref name =>
    match R.lookup name with
    | Option.none => pure .unit
    | Option.some (.struct fs) => return .tuple (← fs.mapM (genVal R (fuel - 1)))
    | Option.some (.enum vs) =>
      let i ← if fuel == 0 then pure 0 else rand vs.length
      return .variant i (← genVal R (fuel - 1) vs[i]!)

def mutate (bs : Bytes) : G (String × Bytes) := do
  let n := bs.length
  match ← rand 5 with
  | 0 =>
    if n == 0 then return ("append", [← randByte])
    let i ← rand n
    let b ← randByte
    return (s!"set{i}", bs.set i b)
  | 1 => return ("truncate", bs.take (← rand (n + 1)))
  | 2 => return ("append", bs ++ [← randByte])
  | 3 =>
    let i ← rand (n + 1)
    return (s!"insert{i}", bs.take i ++ [← randByte] ++ bs.drop i)
  | _ =>
    if n == 0 then return ("append", [← randByte])
    let i ← rand n
    return (s!"delete{i}", bs.take i ++ bs.drop (i + 1))

def fuzzSui (base : Std.HashMap String Container) (count : Nat) : G (List Vec) := do
  let R := Registry.ofMaps base {}
  let names := base.toList.map (·.1) |>.toArray.qsort (· < ·) |>.toList
  let mut out := #[]
  for i in [0:count] do
    let name := names[i % names.length]!
    let v ← genVal R 6 (.ref name)
    let bs := encode v
    out := out.push { id := s!"sui/{name}/{i}", fmt := .ref name, bytes := bs }
    for j in [0:4] do
      let (how, m) ← mutate bs
      out := out.push { id := s!"sui-mut/{name}/{i}/{j}/{how}", fmt := .ref name, bytes := m }
  return out.toList

/-- Every vector, deterministic for a seed. -/
def allVectors (base : Std.HashMap String Container) (seed : UInt64) (fuzz : Nat) : List Vec :=
  let gen : G (List Vec) := do
    let a ← edgeUleb
    let b ← edgeInts
    let c ← edgeUtf8
    let d ← edgeMaps
    let e ← fuzzSui base fuzz
    return a ++ edgeTags ++ b ++ c ++ edgeDepth ++ d ++ e
  (gen.run ⟨seed⟩).1

end Zui.Bcs
