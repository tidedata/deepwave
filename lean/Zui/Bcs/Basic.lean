/-!
# BCS: the executable model

A model of BCS as crates.io `bcs` 0.1.6 implements it (the version Mysten's sui 1.83.1
`Cargo.lock` pins), driven by a serde-reflection registry such as
`spec/sui-format-1.83.1.yaml.snap`.

The decoder below follows `bcs::de` step for step, including the order in which errors are
detected, so its verdicts can be diffed against the Rust crate (`tools/truth/lean`):

* fixed-width integers are little endian; a short input is `Eof`;
* `bool` accepts only 0 and 1 (`ExpectedBoolean`), an option tag only 0 and 1 (`ExpectedOption`);
* ULEB128 is read as `parse_u32_from_uleb128`: at most five bytes, the last digit non-zero
  unless it is the only one (`NonCanonicalUleb128Encoding`), the value below 2^32
  (`IntegerOverflowDuringUleb128Decoding`);
* lengths are at most `2^31 - 1` (`ExceededMaxLen`);
* every named container (struct, newtype struct, tuple struct, unit struct, enum) is entered
  with the remaining depth checked first (`ExceededContainerDepthLimit`, limit 500); sequences,
  options, tuples, arrays and maps do not count;
* map keys are compared as raw encoded bytes and must strictly increase (`NonCanonicalMap`),
  checked after the key is decoded and before the value;
* strings must be valid UTF-8 exactly as `std::str::from_utf8` defines it (`Utf8`);
* a variant index past the last variant is serde's `invalid_value` (`Custom`);
* a whole-input decode rejects trailing bytes (`RemainingInput`).

Bytes are `List UInt8`: the same functions are what the theorems talk about and what the
`zui-spec` oracle runs, so the oracle is the proved function itself.
-/

namespace Zui.Bcs

abbrev Bytes := List UInt8

/-- `bcs::Error` variants that decoding can produce, plus `unknownType` for a registry that
does not define a referenced name (a broken registry, never a Rust outcome). -/
inductive Err where
  | eof
  | exceededMaxLen
  | depthLimit
  | expectedBool
  | expectedOption
  | nonCanonicalMap
  | unknownVariant
  | remainingInput
  | utf8
  | nonCanonicalUleb
  | ulebOverflow
  | unknownType (name : String)
  deriving Repr, DecidableEq, Inhabited

/-- Name of the error as the Rust checker prints it (`bcs::Error` variant name). -/
def Err.name : Err → String
  | .eof => "Eof"
  | .exceededMaxLen => "ExceededMaxLen"
  | .depthLimit => "ExceededContainerDepthLimit"
  | .expectedBool => "ExpectedBoolean"
  | .expectedOption => "ExpectedOption"
  | .nonCanonicalMap => "NonCanonicalMap"
  | .unknownVariant => "Custom"
  | .remainingInput => "RemainingInput"
  | .utf8 => "Utf8"
  | .nonCanonicalUleb => "NonCanonicalUleb128Encoding"
  | .ulebOverflow => "IntegerOverflowDuringUleb128Decoding"
  | .unknownType n => "UnknownType:" ++ n

/-- Anonymous formats (serde-reflection `Format`). `uint w` is an unsigned integer of `w`
bytes (U8 = 1 ... U128 = 16, U256 = 32). `ref` is `TYPENAME`. -/
inductive Fmt where
  | unit
  | bool
  | uint (w : Nat)
  | str
  | bytes
  | option (f : Fmt)
  | seq (f : Fmt)
  | map (k v : Fmt)
  | tuple (fs : List Fmt)
  | array (f : Fmt) (n : Nat)
  | ref (name : String)
  deriving Repr, Inhabited

/-- Named containers (serde-reflection `ContainerFormat`), reduced to their byte shape:
a struct of any kind is the concatenation of its fields (`UNITSTRUCT` = no fields,
`NEWTYPESTRUCT f` = `[f]`); an enum is a ULEB128 variant index followed by the variant's
payload (`UNIT` = `Fmt.unit`, `NEWTYPE f` = `f`, `TUPLE`/`STRUCT` = `Fmt.tuple`). -/
inductive Container where
  | struct (fs : List Fmt)
  | enum (vs : List Fmt)
  deriving Repr, Inhabited

/-- A registry is any lookup from type names to containers. -/
structure Registry where
  lookup : String → Option Container

/-- Values. Structs, tuples and fixed arrays are all `tuple` (no length prefix). -/
inductive Value where
  | unit
  | bool (b : Bool)
  | uint (w : Nat) (n : Nat)
  | str (bs : Bytes)
  | bytes (bs : Bytes)
  | none
  | some (v : Value)
  | seq (vs : List Value)
  | map (kvs : List (Value × Value))
  | tuple (vs : List Value)
  | variant (i : Nat) (v : Value)
  deriving Repr, Inhabited

/-- `bcs::MAX_SEQUENCE_LENGTH`. -/
def maxSeqLen : Nat := 2 ^ 31 - 1
/-- `bcs::MAX_CONTAINER_DEPTH`. -/
def maxDepth : Nat := 500

/-! ## Encoding -/

/-- Little-endian `w`-byte encoding of `n` (the low `8w` bits). -/
def leBytes : Nat → Nat → Bytes
  | 0, _ => []
  | w + 1, n => UInt8.ofNat (n % 256) :: leBytes w (n / 256)

/-- Little-endian value of a byte string. -/
def leVal : Bytes → Nat
  | [] => 0
  | b :: bs => b.toNat + 256 * leVal bs

/-- Minimal ULEB128 (`output_u32_as_uleb128`). -/
def uleb (n : Nat) : Bytes :=
  if h : n < 128 then [UInt8.ofNat n]
  else UInt8.ofNat (n % 128 + 128) :: uleb (n / 128)
termination_by n
decreasing_by omega

mutual
/-- BCS encoding of a value (the format is implicit in the value's shape). -/
def encode : Value → Bytes
  | .unit => []
  | .bool b => [if b then 1 else 0]
  | .uint w n => leBytes w n
  | .str bs => uleb bs.length ++ bs
  | .bytes bs => uleb bs.length ++ bs
  | .none => [0]
  | .some v => 1 :: encode v
  | .seq vs => uleb vs.length ++ encodeList vs
  | .map kvs => uleb kvs.length ++ encodePairs kvs
  | .tuple vs => encodeList vs
  | .variant i v => uleb i ++ encode v

def encodeList : List Value → Bytes
  | [] => []
  | v :: vs => encode v ++ encodeList vs

def encodePairs : List (Value × Value) → Bytes
  | [] => []
  | (k, v) :: kvs => encode k ++ encode v ++ encodePairs kvs
end

/-! ## UTF-8 (Unicode 15, table 3-7: what `std::str::from_utf8` accepts) -/

/-- Is `b` a continuation byte in `[lo, hi]`? -/
@[inline] def inRange (b : UInt8) (lo hi : UInt8) : Bool := lo ≤ b && b ≤ hi

/-- Well-formed UTF-8 byte sequences, exactly table 3-7: no overlongs, no surrogates,
nothing above U+10FFFF. -/
def validUtf8 : Bytes → Bool
  | [] => true
  | b :: bs =>
    if b < 0x80 then validUtf8 bs
    else if inRange b 0xC2 0xDF then
      match bs with
      | c :: r => inRange c 0x80 0xBF && validUtf8 r
      | _ => false
    else if b == 0xE0 then
      match bs with
      | c :: d :: r => inRange c 0xA0 0xBF && inRange d 0x80 0xBF && validUtf8 r
      | _ => false
    else if inRange b 0xE1 0xEC || inRange b 0xEE 0xEF then
      match bs with
      | c :: d :: r => inRange c 0x80 0xBF && inRange d 0x80 0xBF && validUtf8 r
      | _ => false
    else if b == 0xED then
      match bs with
      | c :: d :: r => inRange c 0x80 0x9F && inRange d 0x80 0xBF && validUtf8 r
      | _ => false
    else if b == 0xF0 then
      match bs with
      | c :: d :: e :: r =>
        inRange c 0x90 0xBF && inRange d 0x80 0xBF && inRange e 0x80 0xBF && validUtf8 r
      | _ => false
    else if inRange b 0xF1 0xF3 then
      match bs with
      | c :: d :: e :: r =>
        inRange c 0x80 0xBF && inRange d 0x80 0xBF && inRange e 0x80 0xBF && validUtf8 r
      | _ => false
    else if b == 0xF4 then
      match bs with
      | c :: d :: e :: r =>
        inRange c 0x80 0x8F && inRange d 0x80 0xBF && inRange e 0x80 0xBF && validUtf8 r
      | _ => false
    else false

/-! ## Byte order of map keys (`<[u8] as Ord>`) -/

def lexLt : Bytes → Bytes → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => a < b || (a == b && lexLt as bs)

/-- Is `k` strictly after the previous key (if any)? -/
def prevLt : Option Bytes → Bytes → Bool
  | Option.none, _ => true
  | Option.some p, k => lexLt p k

/-- Map entries in canonical order: encoded keys strictly increasing. -/
def keysSorted : Option Bytes → List (Value × Value) → Bool
  | _, [] => true
  | prev, (k, _) :: rest => prevLt prev (encode k) && keysSorted (Option.some (encode k)) rest

/-! ## Decoding -/

/-- `parse_u32_from_uleb128`, with `k` loop iterations left, the current shift and the value
so far. -/
def ulebGo : Nat → Nat → Nat → Bytes → Except Err (Nat × Bytes)
  | 0, _, _, _ => .error .ulebOverflow
  | _ + 1, _, _, [] => .error .eof
  | k + 1, shift, acc, b :: rest =>
    let digit := b.toNat % 128
    let acc' := acc + digit * 2 ^ shift
    if b.toNat < 128 then
      if shift > 0 ∧ digit = 0 then .error .nonCanonicalUleb
      else if acc' < 2 ^ 32 then .ok (acc', rest) else .error .ulebOverflow
    else ulebGo k (shift + 7) acc' rest

def readUleb32 (bs : Bytes) : Except Err (Nat × Bytes) := ulebGo 5 0 0 bs

/-- `take n` and `drop n` in one pass, or `none` if the input is shorter than `n`
(tail recursive, no length computation, so the oracle stays linear in the input). -/
def takeGo : Nat → Bytes → Bytes → Option (Bytes × Bytes)
  | 0, acc, bs => some (acc.reverse, bs)
  | _ + 1, _, [] => none
  | n + 1, acc, b :: bs => takeGo n (b :: acc) bs

def takeN (n : Nat) (bs : Bytes) : Option (Bytes × Bytes) := takeGo n [] bs

/-- `parse_length`. -/
def readLen (bs : Bytes) : Except Err (Nat × Bytes) :=
  match readUleb32 bs with
  | .error e => .error e
  | .ok (n, r) => if n > maxSeqLen then .error .exceededMaxLen else .ok (n, r)

/-- `parse_bytes`: a length, then that many bytes. -/
def readBytes (bs : Bytes) : Except Err (Bytes × Bytes) :=
  match readLen bs with
  | .error e => .error e
  | .ok (n, r) =>
    match takeN n r with
    | Option.none => .error .eof
    | Option.some (s, r') => .ok (s, r')

mutual
/-- Decode a value of format `f` with `d` named containers of depth left. -/
def dec (R : Registry) (d : Nat) (f : Fmt) (bs : Bytes) : Except Err (Value × Bytes) :=
  match f with
  | .unit => .ok (.unit, bs)
  | .bool =>
    match bs with
    | [] => .error .eof
    | b :: r => if b = 0 then .ok (.bool false, r)
                else if b = 1 then .ok (.bool true, r) else .error .expectedBool
  | .uint w =>
    match takeN w bs with
    | Option.none => .error .eof
    | Option.some (t, r) => .ok (.uint w (leVal t), r)
  | .str =>
    match readBytes bs with
    | .error e => .error e
    | .ok (s, r) => if validUtf8 s then .ok (.str s, r) else .error .utf8
  | .bytes =>
    match readBytes bs with
    | .error e => .error e
    | .ok (s, r) => .ok (.bytes s, r)
  | .option g =>
    match bs with
    | [] => .error .eof
    | b :: r =>
      if b = 0 then .ok (.none, r)
      else if b = 1 then
        match dec R d g r with
        | .error e => .error e
        | .ok (v, r') => .ok (.some v, r')
      else .error .expectedOption
  | .seq g =>
    match readLen bs with
    | .error e => .error e
    | .ok (n, r) =>
      match decMany R d g n [] r with
      | .error e => .error e
      | .ok (vs, r') => .ok (.seq vs, r')
  | .map kf vf =>
    match readLen bs with
    | .error e => .error e
    | .ok (n, r) =>
      match decMap R d kf vf n Option.none [] r with
      | .error e => .error e
      | .ok (kvs, r') => .ok (.map kvs, r')
  | .tuple fs =>
    match decList R d fs bs with
    | .error e => .error e
    | .ok (vs, r) => .ok (.tuple vs, r)
  | .array g n =>
    match decMany R d g n [] bs with
    | .error e => .error e
    | .ok (vs, r) => .ok (.tuple vs, r)
  | .ref name =>
    match R.lookup name with
    | Option.none => .error (.unknownType name)
    | Option.some c =>
      match d with
      | 0 => .error .depthLimit
      | d' + 1 =>
        match c with
        | .struct fs =>
          match decList R d' fs bs with
          | .error e => .error e
          | .ok (vs, r) => .ok (.tuple vs, r)
        | .enum vfs =>
          match readUleb32 bs with
          | .error e => .error e
          | .ok (i, r) =>
            match vfs[i]? with
            | Option.none => .error .unknownVariant
            | Option.some g =>
              match dec R d' g r with
              | .error e => .error e
              | .ok (v, r') => .ok (.variant i v, r')
termination_by (d, 2 * sizeOf f, 0)

/-- `n` more items of format `f`; `acc` holds the items so far, last first. -/
def decMany (R : Registry) (d : Nat) (f : Fmt) (n : Nat) (acc : List Value) (bs : Bytes) :
    Except Err (List Value × Bytes) :=
  match n with
  | 0 => .ok (acc.reverse, bs)
  | n + 1 =>
    match dec R d f bs with
    | .error e => .error e
    | .ok (v, r) => decMany R d f n (v :: acc) r
termination_by (d, 2 * sizeOf f, n + 1)

/-- The fields of a tuple or struct, in order. -/
def decList (R : Registry) (d : Nat) (fs : List Fmt) (bs : Bytes) :
    Except Err (List Value × Bytes) :=
  match fs with
  | [] => .ok ([], bs)
  | f :: fs =>
    match dec R d f bs with
    | .error e => .error e
    | .ok (v, r) =>
      match decList R d fs r with
      | .error e => .error e
      | .ok (vs, r') => .ok (v :: vs, r')
termination_by (d, 2 * sizeOf fs, 0)

/-- `n` more map entries; `prev` is the previous key's raw bytes. -/
def decMap (R : Registry) (d : Nat) (kf vf : Fmt) (n : Nat) (prev : Option Bytes)
    (acc : List (Value × Value)) (bs : Bytes) : Except Err (List (Value × Value) × Bytes) :=
  match n with
  | 0 => .ok (acc.reverse, bs)
  | n + 1 =>
    match dec R d kf bs with
    | .error e => .error e
    | .ok (k, r1) =>
      -- Rust compares the raw key slice; `dec_consumed` proves it is exactly `encode k`.
      let kb := encode k
      if prevLt prev kb then
        match dec R d vf r1 with
        | .error e => .error e
        | .ok (v, r2) => decMap R d kf vf n (Option.some kb) ((k, v) :: acc) r2
      else .error .nonCanonicalMap
termination_by (d, 2 * sizeOf kf + 2 * sizeOf vf + 1, n + 1)
end

/-- `bcs::from_bytes`: decode the whole input at the full depth limit. -/
def decodeFull (R : Registry) (f : Fmt) (bs : Bytes) : Except Err Value :=
  match dec R maxDepth f bs with
  | .error e => .error e
  | .ok (v, r) => if r = [] then .ok v else .error .remainingInput

end Zui.Bcs
