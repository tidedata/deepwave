import Zui.Bcs.Uleb

/-!
# BCS round trip: `decode (encode v) = v`

`WT R d f v` says that `v` is a well-formed value of format `f` under registry `R` that fits
in `d` levels of named containers: integers in range, lengths at most `2^31 - 1`, strings valid
UTF-8, map keys in strictly increasing byte order, variant indices naming a variant.

`dec_encode`: every well-formed value decodes from its encoding, leaving any following bytes
untouched. With `decodeFull` this is `decodeFull R f (encode v) = ok v` at depth 500.
-/

namespace Zui.Bcs

/-- Well-formed values. -/
inductive WT (R : Registry) : Nat → Fmt → Value → Prop
  | unit {d} : WT R d .unit .unit
  | bool {d b} : WT R d .bool (.bool b)
  | uint {d w n} : n < 2 ^ (8 * w) → WT R d (.uint w) (.uint w n)
  | str {d bs} : bs.length ≤ maxSeqLen → validUtf8 bs = true → WT R d .str (.str bs)
  | bytes {d bs} : bs.length ≤ maxSeqLen → WT R d .bytes (.bytes bs)
  | none {d f} : WT R d (.option f) .none
  | some {d f v} : WT R d f v → WT R d (.option f) (.some v)
  | seq {d f vs} : vs.length ≤ maxSeqLen → (∀ v ∈ vs, WT R d f v) → WT R d (.seq f) (.seq vs)
  | array {d f n vs} : vs.length = n → (∀ v ∈ vs, WT R d f v) →
      WT R d (.array f n) (.tuple vs)
  | map {d kf vf kvs} : kvs.length ≤ maxSeqLen → keysSorted Option.none kvs = true →
      (∀ p ∈ kvs, WT R d kf p.1) → (∀ p ∈ kvs, WT R d vf p.2) →
      WT R d (.map kf vf) (.map kvs)
  | tuple {d fs vs} : vs.length = fs.length → (∀ p ∈ List.zip fs vs, WT R d p.1 p.2) →
      WT R d (.tuple fs) (.tuple vs)
  | struct {d name fs vs} : R.lookup name = Option.some (.struct fs) →
      vs.length = fs.length → (∀ p ∈ List.zip fs vs, WT R d p.1 p.2) →
      WT R (d + 1) (.ref name) (.tuple vs)
  | variant {d name vfs i g v} : R.lookup name = Option.some (.enum vfs) →
      vfs[i]? = Option.some g → i < 2 ^ 32 → WT R d g v →
      WT R (d + 1) (.ref name) (.variant i v)

/-! ## Primitive lemmas -/

theorem leBytes_length (w n : Nat) : (leBytes w n).length = w := by
  induction w generalizing n with
  | zero => rfl
  | succ w ih => simp [leBytes, ih]

theorem leVal_leBytes : ∀ (w n : Nat), n < 2 ^ (8 * w) → leVal (leBytes w n) = n := by
  intro w
  induction w with
  | zero => intro n h; simp at h; simp [leBytes, leVal, h]
  | succ w ih =>
    intro n h
    have hp : 2 ^ (8 * (w + 1)) = 2 ^ (8 * w) * 256 := by
      rw [show 8 * (w + 1) = 8 * w + 8 by omega, Nat.pow_add]
    have hdiv : n / 256 < 2 ^ (8 * w) := by
      rw [Nat.div_lt_iff_lt_mul (by decide)]; omega
    simp only [leBytes, leVal, ih _ hdiv]
    have : (UInt8.ofNat (n % 256)).toNat = n % 256 := by simp
    rw [this]; omega

theorem leVal_lt : ∀ (bs : Bytes), leVal bs < 2 ^ (8 * bs.length) := by
  intro bs
  induction bs with
  | nil => simp [leVal]
  | cons b bs ih =>
    have hb := UInt8.toNat_lt b
    have hp : 2 ^ (8 * (bs.length + 1)) = 2 ^ (8 * bs.length) * 256 := by
      rw [show 8 * (bs.length + 1) = 8 * bs.length + 8 by omega, Nat.pow_add]
    simp only [leVal, List.length_cons, hp]
    omega

theorem takeGo_append : ∀ (l acc rest : Bytes),
    takeGo l.length acc (l ++ rest) = some (acc.reverse ++ l, rest) := by
  intro l
  induction l with
  | nil => intro acc rest; simp [takeGo]
  | cons b l ih => intro acc rest; simp [takeGo, ih]

theorem takeN_append {l : Bytes} {n : Nat} (h : l.length = n) (rest : Bytes) :
    takeN n (l ++ rest) = some (l, rest) := by
  subst h; simp [takeN, takeGo_append]

theorem takeGo_some : ∀ (n : Nat) (acc bs t r : Bytes), takeGo n acc bs = some (t, r) →
    ∃ t', t = acc.reverse ++ t' ∧ bs = t' ++ r ∧ t'.length = n := by
  intro n
  induction n with
  | zero => intro acc bs t r h; simp [takeGo] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨[], by simp, rfl, rfl⟩
  | succ n ih =>
    intro acc bs t r h
    match bs with
    | [] => simp [takeGo] at h
    | b :: bs =>
      simp only [takeGo] at h
      obtain ⟨t', ht, hbs, hl⟩ := ih _ _ _ _ h
      exact ⟨b :: t', by simp [ht], by simp [hbs], by simp [hl]⟩

theorem takeN_some {n : Nat} {bs t r : Bytes} (h : takeN n bs = some (t, r)) :
    bs = t ++ r ∧ t.length = n := by
  obtain ⟨t', ht, hbs, hl⟩ := takeGo_some n [] bs t r h
  simp at ht; subst ht; exact ⟨hbs, hl⟩

theorem maxSeqLen_lt : maxSeqLen < 2 ^ 32 := by decide

theorem readLen_uleb {n : Nat} (h : n ≤ maxSeqLen) (rest : Bytes) :
    readLen (uleb n ++ rest) = .ok (n, rest) := by
  have h32 : n < 2 ^ 32 := Nat.lt_of_le_of_lt h maxSeqLen_lt
  simp only [readLen, readUleb32_uleb h32 rest]
  have : ¬ n > maxSeqLen := by omega
  simp [this]

theorem readBytes_enc {bs : Bytes} (h : bs.length ≤ maxSeqLen) (rest : Bytes) :
    readBytes (uleb bs.length ++ bs ++ rest) = .ok (bs, rest) := by
  simp only [readBytes, List.append_assoc, readLen_uleb h, takeN_append rfl]

theorem take_consumed (a b : Bytes) : (a ++ b).take ((a ++ b).length - b.length) = a := by
  simp

/-! ## Round trip -/

theorem decMany_encode (R : Registry) (d : Nat) (f : Fmt) : ∀ (vs acc : List Value) (rest : Bytes),
    (∀ v ∈ vs, ∀ rest, dec R d f (encode v ++ rest) = .ok (v, rest)) →
    decMany R d f vs.length acc (encodeList vs ++ rest) = .ok (acc.reverse ++ vs, rest) := by
  intro vs
  induction vs with
  | nil => intro acc rest _; simp [decMany, encodeList]
  | cons v vs ih =>
    intro acc rest h
    simp only [List.length_cons, encodeList, List.append_assoc]
    rw [decMany]
    simp only [h v (by simp) (encodeList vs ++ rest)]
    rw [ih (v :: acc) rest (fun x hx => h x (by simp [hx]))]
    simp

theorem decList_encode (R : Registry) (d : Nat) : ∀ (fs : List Fmt) (vs : List Value) (rest : Bytes),
    vs.length = fs.length →
    (∀ p ∈ List.zip fs vs, ∀ rest, dec R d p.1 (encode p.2 ++ rest) = .ok (p.2, rest)) →
    decList R d fs (encodeList vs ++ rest) = .ok (vs, rest) := by
  intro fs
  induction fs with
  | nil =>
    intro vs rest hl _
    match vs, hl with
    | [], _ => simp [decList, encodeList]
  | cons f fs ih =>
    intro vs rest hl h
    match vs, hl with
    | v :: vs, hl =>
      simp only [encodeList, List.append_assoc]
      rw [decList]
      simp only [h (f, v) (by simp) (encodeList vs ++ rest)]
      rw [ih vs rest (by simpa using hl) (fun p hp => h p (by simp [hp]))]

theorem decMap_encode (R : Registry) (d : Nat) (kf vf : Fmt) :
    ∀ (kvs : List (Value × Value)) (prev : Option Bytes) (acc : List (Value × Value)) (rest : Bytes),
    keysSorted prev kvs = true →
    (∀ p ∈ kvs, ∀ rest, dec R d kf (encode p.1 ++ rest) = .ok (p.1, rest)) →
    (∀ p ∈ kvs, ∀ rest, dec R d vf (encode p.2 ++ rest) = .ok (p.2, rest)) →
    decMap R d kf vf kvs.length prev acc (encodePairs kvs ++ rest) = .ok (acc.reverse ++ kvs, rest) := by
  intro kvs
  induction kvs with
  | nil => intro prev acc rest _ _ _; simp [decMap, encodePairs]
  | cons kv kvs ih =>
    obtain ⟨k, v⟩ := kv
    intro prev acc rest hs hk hv
    simp only [keysSorted, Bool.and_eq_true] at hs
    obtain ⟨hprev, hs⟩ := hs
    simp only [List.length_cons, encodePairs, List.append_assoc]
    rw [decMap]
    simp only [hk (k, v) (by simp) (encode v ++ (encodePairs kvs ++ rest))]
    simp only [hprev, ite_true]
    simp only [hv (k, v) (by simp) (encodePairs kvs ++ rest)]
    rw [ih (Option.some (encode k)) ((k, v) :: acc) rest hs
      (fun p hp => hk p (by simp [hp])) (fun p hp => hv p (by simp [hp]))]
    simp

/-- **Round trip.** A well-formed value decodes from its own encoding, and the bytes after it
are left as they were. -/
theorem dec_encode {R : Registry} {d : Nat} {f : Fmt} {v : Value} (h : WT R d f v) :
    ∀ rest, dec R d f (encode v ++ rest) = .ok (v, rest) := by
  induction h with
  | unit => intro rest; simp [dec, encode]
  | @bool d b =>
    intro rest
    cases b <;> simp [dec, encode]
  | @uint d w n hn =>
    intro rest
    simp only [dec, encode, takeN_append (leBytes_length w n), leVal_leBytes w n hn]
  | str hl hu =>
    intro rest
    simp only [dec, encode, readBytes_enc hl, hu, ite_true]
  | bytes hl =>
    intro rest
    simp only [dec, encode, readBytes_enc hl]
  | none => intro rest; simp [dec, encode]
  | some _ ih =>
    intro rest
    simp only [dec, encode, List.cons_append]
    simp [ih rest]
  | @seq d f vs hl _ ih =>
    intro rest
    simp only [dec, encode, List.append_assoc, readLen_uleb hl]
    have := decMany_encode R d f vs [] rest ih
    simp only [List.reverse_nil, List.nil_append] at this
    simp [this]
  | @array d f n vs hl _ ih =>
    intro rest
    subst hl
    simp only [dec, encode]
    have := decMany_encode R d f vs [] rest ih
    simp only [List.reverse_nil, List.nil_append] at this
    simp [this]
  | @map d kf vf kvs hl hs _ _ ihk ihv =>
    intro rest
    simp only [dec, encode, List.append_assoc, readLen_uleb hl]
    have := decMap_encode R d kf vf kvs Option.none [] rest hs ihk ihv
    simp only [List.reverse_nil, List.nil_append] at this
    simp [this]
  | @tuple d fs vs hl _ ih =>
    intro rest
    simp only [dec, encode]
    simp [decList_encode R d fs vs rest hl ih]
  | @struct d name fs vs hlook hl _ ih =>
    intro rest
    simp only [dec, encode, hlook]
    simp [decList_encode R d fs vs rest hl ih]
  | @variant d name vfs i g v hlook hi hi32 _ ih =>
    intro rest
    simp only [dec, encode, hlook, List.append_assoc, readUleb32_uleb hi32, hi]
    simp [ih rest]

/-- Round trip for a whole input: `bcs::from_bytes(&bcs::to_bytes(v)) == v`. -/
theorem decodeFull_encode {R : Registry} {f : Fmt} {v : Value} (h : WT R maxDepth f v) :
    decodeFull R f (encode v) = .ok v := by
  have := dec_encode h []
  simp only [List.append_nil] at this
  simp [decodeFull, this]

end Zui.Bcs
