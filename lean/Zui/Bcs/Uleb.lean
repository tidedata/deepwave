import Zui.Bcs.Basic

/-!
# ULEB128: round trip and minimality

`readUleb32` (the model of `bcs`'s `parse_u32_from_uleb128`) accepts exactly the minimal
encodings `uleb n` of the values `n < 2^32`, and nothing else:

* `readUleb32_uleb`: `readUleb32 (uleb n ++ rest) = ok (n, rest)` for every `n < 2^32`;
* `readUleb32_canonical`: if `readUleb32 bs = ok (n, rest)` then `bs = uleb n ++ rest` and
  `n < 2^32`. So a non-minimal encoding (a trailing zero digit) is never accepted, and the
  encoding of a length or variant index is unique.
-/

namespace Zui.Bcs

theorem uleb_small {n : Nat} (h : n < 128) : uleb n = [UInt8.ofNat n] := by
  rw [uleb]; simp [h]

theorem uleb_big {n : Nat} (h : ¬ n < 128) :
    uleb n = UInt8.ofNat (n % 128 + 128) :: uleb (n / 128) := by
  rw [uleb]; simp [h]

theorem uleb_ne_nil (n : Nat) : uleb n ≠ [] := by
  by_cases h : n < 128
  · simp [uleb_small h]
  · simp [uleb_big h]

/-- The heart of the round trip: reading `uleb n` with shift `shift` and `k` iterations left,
where `shift + 7k = 35` (the loop runs over shifts 0, 7, ..., 28). -/
theorem ulebGo_uleb (n : Nat) : ∀ (k shift acc : Nat) (rest : Bytes),
    shift + 7 * k = 35 → (shift > 0 → n > 0) → acc + n * 2 ^ shift < 2 ^ 32 →
    ulebGo k shift acc (uleb n ++ rest) = .ok (acc + n * 2 ^ shift, rest) := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
  intro k shift acc rest hk hpos hlt
  have hP : 2 ^ shift > 0 := Nat.pow_pos (by decide)
  by_cases hn : n < 128
  · rw [uleb_small hn]
    match k, hk with
    | 0, hk =>
      -- shift = 35, so n * 2^35 < 2^32 forces n = 0, but shift > 0 forces n > 0
      have : shift = 35 := by omega
      subst this
      have := hpos (by decide)
      have : n * 2 ^ 35 ≥ 2 ^ 35 := Nat.le_mul_of_pos_left _ this
      have : (2 : Nat) ^ 35 ≥ 2 ^ 32 := Nat.pow_le_pow_right (by decide) (by decide)
      omega
    | k + 1, _ =>
      have hb : (UInt8.ofNat n).toNat = n := by
        simp; omega
      simp only [List.singleton_append, ulebGo, hb]
      have h1 : n % 128 = n := Nat.mod_eq_of_lt hn
      simp only [h1, hn, ite_true]
      have : ¬ (shift > 0 ∧ n = 0) := by
        intro ⟨a, b⟩; have := hpos a; omega
      simp [this, hlt]
  · rw [uleb_big hn]
    have hb : (UInt8.ofNat (n % 128 + 128)).toNat = n % 128 + 128 := by
      simp; omega
    match k, hk with
    | 0, hk =>
      have : shift = 35 := by omega
      subst this
      have : n * 2 ^ 35 ≥ 2 ^ 35 := Nat.le_mul_of_pos_left _ (by omega)
      have : (2 : Nat) ^ 35 ≥ 2 ^ 32 := Nat.pow_le_pow_right (by decide) (by decide)
      omega
    | 1, hk =>
      have : shift = 28 := by omega
      subst this
      have : n * 2 ^ 28 ≥ 128 * 2 ^ 28 := Nat.mul_le_mul_right _ (by omega)
      have : (128 : Nat) * 2 ^ 28 = 2 ^ 35 := by decide
      have : (2 : Nat) ^ 35 ≥ 2 ^ 32 := Nat.pow_le_pow_right (by decide) (by decide)
      omega
    | k + 2, hk =>
      simp only [List.cons_append, ulebGo, hb]
      have hge : ¬ (n % 128 + 128 < 128) := by omega
      have hmod : (n % 128 + 128) % 128 = n % 128 := by omega
      simp only [hge, ite_false, hmod]
      have hpow : 2 ^ (shift + 7) = 2 ^ shift * 128 := by rw [Nat.pow_add]
      have hsplit : acc + n % 128 * 2 ^ shift + n / 128 * 2 ^ (shift + 7)
          = acc + n * 2 ^ shift := by
        rw [hpow]
        have := Nat.mod_add_div n 128
        generalize 2 ^ shift = P at *
        generalize n % 128 = a at *
        generalize n / 128 = b at *
        subst this
        grind
      have := ih (n / 128) (by omega) (k + 1) (shift + 7) (acc + n % 128 * 2 ^ shift) rest
        (by omega) (fun _ => by omega) (by rw [hsplit]; exact hlt)
      rw [this, hsplit]

theorem uleb_length_le (n : Nat) (h : n < 2 ^ 32) : (uleb n).length ≤ 5 := by
  have h1 : ∀ m, (uleb m).length ≤ 1 ∨ m ≥ 128 := by
    intro m; by_cases hm : m < 128
    · left; simp [uleb_small hm]
    · right; omega
  -- unfold four times: 2^32 / 128^4 < 128
  by_cases a : n < 128
  · simp [uleb_small a]
  rw [uleb_big a]; simp only [List.length_cons]
  by_cases b : n / 128 < 128
  · simp [uleb_small b]
  rw [uleb_big b]; simp only [List.length_cons]
  by_cases c : n / 128 / 128 < 128
  · simp [uleb_small c]
  rw [uleb_big c]; simp only [List.length_cons]
  by_cases d : n / 128 / 128 / 128 < 128
  · simp [uleb_small d]
  rw [uleb_big d]; simp only [List.length_cons]
  have e : n / 128 / 128 / 128 / 128 < 128 := by omega
  simp [uleb_small e]

/-- Round trip: the minimal encoding of any `n < 2^32` reads back as `n`. -/
theorem readUleb32_uleb {n : Nat} (h : n < 2 ^ 32) (rest : Bytes) :
    readUleb32 (uleb n ++ rest) = .ok (n, rest) := by
  have := ulebGo_uleb n 5 0 0 rest (by decide) (fun h => absurd h (by decide)) (by simpa using h)
  simpa [readUleb32] using this

/-- Canonicity, generalised over the loop state. -/
theorem ulebGo_canonical : ∀ (k shift acc : Nat) (bs rest : Bytes) (v : Nat),
    ulebGo k shift acc bs = .ok (v, rest) →
    ∃ m, bs = uleb m ++ rest ∧ v = acc + m * 2 ^ shift ∧ (shift > 0 → m > 0) ∧ v < 2 ^ 32 := by
  intro k
  induction k with
  | zero => intro shift acc bs rest v h; simp [ulebGo] at h
  | succ k ih =>
    intro shift acc bs rest v h
    match bs with
    | [] => simp [ulebGo] at h
    | b :: r =>
      have hb := UInt8.toNat_lt b
      simp only [ulebGo] at h
      by_cases hsmall : b.toNat < 128
      · simp only [hsmall, ite_true] at h
        by_cases hz : shift > 0 ∧ b.toNat % 128 = 0
        · simp [hz] at h
        · simp only [hz, ite_false] at h
          by_cases hlt : acc + b.toNat % 128 * 2 ^ shift < 2 ^ 32
          · simp only [hlt, ite_true, Except.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨hv, hr⟩ := h
            have hm : b.toNat % 128 = b.toNat := Nat.mod_eq_of_lt hsmall
            refine ⟨b.toNat, ?_, ?_, ?_, ?_⟩
            · rw [uleb_small hsmall, UInt8.ofNat_toNat, hr]; rfl
            · rw [← hv, hm]
            · intro hs; omega
            · omega
          · simp [hlt] at h
      · simp only [hsmall, ite_false] at h
        obtain ⟨m', hr, hv, hpos, hvlt⟩ := ih _ _ r rest v h
        have hm'pos := hpos (by omega)
        refine ⟨b.toNat % 128 + 128 * m', ?_, ?_, ?_, hvlt⟩
        · have hbig : ¬ (b.toNat % 128 + 128 * m' < 128) := by omega
          rw [uleb_big hbig]
          have e1 : (b.toNat % 128 + 128 * m') % 128 + 128 = b.toNat := by omega
          have e2 : (b.toNat % 128 + 128 * m') / 128 = m' := by omega
          rw [e1, e2, UInt8.ofNat_toNat, hr]; rfl
        · rw [hv]
          have hpow : 2 ^ (shift + 7) = 2 ^ shift * 128 := by rw [Nat.pow_add]
          rw [hpow]
          generalize 2 ^ shift = P
          generalize b.toNat % 128 = a
          grind
        · intro _; omega

/-- Canonicity: the only encodings `readUleb32` accepts are the minimal ones, of values
below `2^32`. -/
theorem readUleb32_canonical {bs rest : Bytes} {n : Nat} (h : readUleb32 bs = .ok (n, rest)) :
    bs = uleb n ++ rest ∧ n < 2 ^ 32 := by
  obtain ⟨m, hbs, hv, _, hlt⟩ := ulebGo_canonical 5 0 0 bs rest n h
  simp at hv
  subst hv
  exact ⟨hbs, hlt⟩

/-- Minimality: `uleb n` uses the fewest base-128 digits, i.e. its last byte is non-zero
unless `n = 0`. Stated as: every byte but the last has the high bit set, and the last byte
is `n`'s top digit. -/
theorem uleb_last_nonzero (n : Nat) (h : n > 0) : (uleb n).getLast (uleb_ne_nil n) ≠ 0 := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
  by_cases hn : n < 128
  · simp only [uleb_small hn, List.getLast_singleton]
    intro h0
    have : (UInt8.ofNat n).toNat = n := by simp; omega
    rw [h0] at this; simp at this; omega
  · simp only [uleb_big hn]
    rw [List.getLast_cons (uleb_ne_nil _)]
    exact ih (n / 128) (by omega) (by omega)

end Zui.Bcs
