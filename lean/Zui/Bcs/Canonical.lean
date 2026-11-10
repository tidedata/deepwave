import Zui.Bcs.Roundtrip

/-!
# BCS canonicity: every accepted input is the encoding of what it decodes to

`dec_canonical`: if `dec R d f bs = ok (v, rest)` then `bs = encode v ++ rest` and `v` is
well formed (`WT R d f v`). With the round trip this makes BCS a bijection between well-formed
values and accepted inputs:

* `decodeFull_iff`: `decodeFull R f bs = ok v ↔ WT R maxDepth f v ∧ bs = encode v`;
* `encoding_unique`: two inputs that decode to the same value are the same bytes.

So the decoder admits no alternative encodings: no non-minimal ULEB128, no unsorted or
duplicate map keys, no bool or option tag other than 0 and 1, no trailing bytes.
-/

set_option linter.unusedSimpArgs false

namespace Zui.Bcs

theorem readLen_canonical {bs r : Bytes} {n : Nat} (h : readLen bs = .ok (n, r)) :
    bs = uleb n ++ r ∧ n ≤ maxSeqLen := by
  unfold readLen at h
  cases hu : readUleb32 bs with
  | error e => simp [hu] at h
  | ok p =>
    obtain ⟨m, r0⟩ := p
    simp only [hu] at h
    by_cases hm : m > maxSeqLen
    · simp [hm] at h
    · simp only [hm, ite_false, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨(readUleb32_canonical hu).1, by omega⟩

theorem readBytes_canonical {bs s r : Bytes} (h : readBytes bs = .ok (s, r)) :
    bs = uleb s.length ++ s ++ r ∧ s.length ≤ maxSeqLen := by
  unfold readBytes at h
  cases hl : readLen bs with
  | error e => simp [hl] at h
  | ok p =>
    obtain ⟨n, r0⟩ := p
    simp only [hl] at h
    obtain ⟨hbs, hn⟩ := readLen_canonical hl
    cases ht : takeN n r0 with
    | none => simp [ht] at h
    | some q =>
      obtain ⟨s', r'⟩ := q
      simp only [ht, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨hr0, hlen⟩ := takeN_some ht
      rw [hlen]
      exact ⟨by rw [hbs, hr0, List.append_assoc], hn⟩

theorem leBytes_leVal : ∀ (t : Bytes), leBytes t.length (leVal t) = t := by
  intro t
  induction t with
  | nil => rfl
  | cons b t ih =>
    have hb := UInt8.toNat_lt b
    simp only [List.length_cons, leBytes, leVal]
    have e1 : (b.toNat + 256 * leVal t) % 256 = b.toNat := by omega
    have e2 : (b.toNat + 256 * leVal t) / 256 = leVal t := by omega
    rw [e1, e2, UInt8.ofNat_toNat, ih]

mutual
theorem dec_canonical (R : Registry) (d : Nat) (f : Fmt) (bs : Bytes) (v : Value) (rest : Bytes)
    (h : dec R d f bs = .ok (v, rest)) : bs = encode v ++ rest ∧ WT R d f v := by
  match f with
  | .unit =>
    simp only [dec, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, .unit⟩
  | .bool =>
    match bs with
    | [] => simp [dec] at h
    | b :: r =>
      simp only [dec] at h
      by_cases h0 : b = 0
      · simp only [h0, ite_true, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨by simp [encode, h0], .bool⟩
      · by_cases h1 : b = 1
        · simp [h0, h1] at h
          obtain ⟨rfl, rfl⟩ := h
          exact ⟨by simp [encode, h1], .bool⟩
        · simp [h0, h1] at h
  | .uint w =>
    simp only [dec] at h
    cases ht : takeN w bs with
    | none => simp [ht] at h
    | some q =>
      obtain ⟨t, r⟩ := q
      simp only [ht, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨hbs, hlen⟩ := takeN_some ht
      refine ⟨?_, .uint ?_⟩
      · simp only [encode]
        have := leBytes_leVal t
        rw [hlen] at this
        rw [this, hbs]
      · have := leVal_lt t
        rw [hlen] at this
        exact this
  | .str =>
    simp only [dec] at h
    cases hb : readBytes bs with
    | error e => simp [hb] at h
    | ok p =>
      obtain ⟨s, r⟩ := p
      simp only [hb] at h
      by_cases hu : validUtf8 s = true
      · simp only [hu, ite_true, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hbs, hl⟩ := readBytes_canonical hb
        exact ⟨by simp [encode, hbs], .str hl hu⟩
      · simp [hu] at h
  | .bytes =>
    simp only [dec] at h
    cases hb : readBytes bs with
    | error e => simp [hb] at h
    | ok p =>
      obtain ⟨s, r⟩ := p
      simp only [hb, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨hbs, hl⟩ := readBytes_canonical hb
      exact ⟨by simp [encode, hbs], .bytes hl⟩
  | .option g =>
    match bs with
    | [] => simp [dec] at h
    | b :: r =>
      simp only [dec] at h
      by_cases h0 : b = 0
      · simp only [h0, ite_true, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨by simp [encode, h0], .none⟩
      · by_cases h1 : b = 1
        · simp only [h0, h1, ite_false, ite_true] at h
          cases hg : dec R d g r with
          | error e => simp [hg] at h
          | ok p =>
            obtain ⟨v', r'⟩ := p
            simp only [hg, Except.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            obtain ⟨hr, hw⟩ := dec_canonical R d g r _ _ hg
            exact ⟨by simp [encode, h1, hr], .some hw⟩
        · simp [h0, h1] at h
  | .seq g =>
    simp only [dec] at h
    cases hl : readLen bs with
    | error e => simp [hl] at h
    | ok p =>
      obtain ⟨n, r⟩ := p
      simp only [hl] at h
      cases hm : decMany R d g n [] r with
      | error e => simp [hm] at h
      | ok q =>
        obtain ⟨vs, r'⟩ := q
        simp only [hm, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hbs, hn⟩ := readLen_canonical hl
        obtain ⟨ws, hvs, hlen, hr, hw⟩ := decMany_canonical R d g n [] r _ _ hm
        simp only [List.reverse_nil, List.nil_append] at hvs
        subst hvs
        refine ⟨?_, .seq (by omega) hw⟩
        simp [encode, hbs, hr, hlen]
  | .map kf vf =>
    simp only [dec] at h
    cases hl : readLen bs with
    | error e => simp [hl] at h
    | ok p =>
      obtain ⟨n, r⟩ := p
      simp only [hl] at h
      cases hm : decMap R d kf vf n Option.none [] r with
      | error e => simp [hm] at h
      | ok q =>
        obtain ⟨kvs, r'⟩ := q
        simp only [hm, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hbs, hn⟩ := readLen_canonical hl
        obtain ⟨ws, hvs, hlen, hr, hs, hk, hv⟩ :=
          decMap_canonical R d kf vf n Option.none [] r _ _ hm
        simp only [List.reverse_nil, List.nil_append] at hvs
        subst hvs
        refine ⟨?_, .map (by omega) hs hk hv⟩
        simp [encode, hbs, hr, hlen]
  | .tuple fs =>
    simp only [dec] at h
    cases hm : decList R d fs bs with
    | error e => simp [hm] at h
    | ok q =>
      obtain ⟨vs, r⟩ := q
      simp only [hm, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨hr, hlen, hw⟩ := decList_canonical R d fs bs _ _ hm
      exact ⟨by simp [encode, hr], .tuple hlen hw⟩
  | .array g n =>
    simp only [dec] at h
    cases hm : decMany R d g n [] bs with
    | error e => simp [hm] at h
    | ok q =>
      obtain ⟨vs, r⟩ := q
      simp only [hm, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨ws, hvs, hlen, hr, hw⟩ := decMany_canonical R d g n [] bs _ _ hm
      simp only [List.reverse_nil, List.nil_append] at hvs
      subst hvs
      exact ⟨by simp [encode, hr], .array hlen hw⟩
  | .ref name =>
    simp only [dec] at h
    cases hlook : R.lookup name with
    | none => simp [hlook] at h
    | some c =>
      simp only [hlook] at h
      match hd : d with
      | 0 => simp at h
      | d' + 1 =>
        try simp only at h
        match c with
        | .struct fs =>
          try simp only at h
          cases hm : decList R d' fs bs with
          | error e => simp [hm] at h
          | ok q =>
            obtain ⟨vs, r⟩ := q
            simp only [hm, Except.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            obtain ⟨hr, hlen, hw⟩ := decList_canonical R d' fs bs _ _ hm
            exact ⟨by simp [encode, hr], .struct hlook hlen hw⟩
        | .enum vfs =>
          try simp only at h
          cases hu : readUleb32 bs with
          | error e => simp [hu] at h
          | ok p =>
            obtain ⟨i, r⟩ := p
            simp only [hu] at h
            cases hi : vfs[i]? with
            | none => simp [hi] at h
            | some g =>
              simp only [hi] at h
              cases hg : dec R d' g r with
              | error e => simp [hg] at h
              | ok q =>
                obtain ⟨v', r'⟩ := q
                simp only [hg, Except.ok.injEq, Prod.mk.injEq] at h
                obtain ⟨rfl, rfl⟩ := h
                obtain ⟨hbs, hi32⟩ := readUleb32_canonical hu
                obtain ⟨hr, hw⟩ := dec_canonical R d' g r _ _ hg
                exact ⟨by simp [encode, hbs, hr], .variant hlook hi hi32 hw⟩
termination_by (d, 2 * sizeOf f, 0)

theorem decMany_canonical (R : Registry) (d : Nat) (f : Fmt) (n : Nat) (acc : List Value)
    (bs : Bytes) (vs : List Value) (rest : Bytes) (h : decMany R d f n acc bs = .ok (vs, rest)) :
    ∃ ws, vs = acc.reverse ++ ws ∧ ws.length = n ∧ bs = encodeList ws ++ rest ∧
      ∀ w ∈ ws, WT R d f w := by
  match n with
  | 0 =>
    simp only [decMany, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨[], by simp, rfl, by simp [encodeList], by simp⟩
  | n + 1 =>
    simp only [decMany] at h
    cases hg : dec R d f bs with
    | error e => simp [hg] at h
    | ok p =>
      obtain ⟨v, r⟩ := p
      simp only [hg] at h
      obtain ⟨hbs, hw⟩ := dec_canonical R d f bs v r hg
      obtain ⟨ws, hvs, hlen, hr, hws⟩ := decMany_canonical R d f n (v :: acc) r vs rest h
      refine ⟨v :: ws, by simp [hvs], by simp [hlen], by simp [encodeList, hbs, hr], ?_⟩
      intro w hw'
      simp only [List.mem_cons] at hw'
      rcases hw' with rfl | hw'
      · exact hw
      · exact hws w hw'
termination_by (d, 2 * sizeOf f, n + 1)

theorem decList_canonical (R : Registry) (d : Nat) (fs : List Fmt) (bs : Bytes)
    (vs : List Value) (rest : Bytes) (h : decList R d fs bs = .ok (vs, rest)) :
    bs = encodeList vs ++ rest ∧ vs.length = fs.length ∧
      ∀ p ∈ List.zip fs vs, WT R d p.1 p.2 := by
  match fs with
  | [] =>
    simp only [decList, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨by simp [encodeList], rfl, by simp⟩
  | f :: fs =>
    simp only [decList] at h
    cases hg : dec R d f bs with
    | error e => simp [hg] at h
    | ok p =>
      obtain ⟨v, r⟩ := p
      simp only [hg] at h
      cases hl : decList R d fs r with
      | error e => simp [hl] at h
      | ok q =>
        obtain ⟨vs', r'⟩ := q
        simp only [hl, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hbs, hw⟩ := dec_canonical R d f bs v r hg
        obtain ⟨hr, hlen, hws⟩ := decList_canonical R d fs r _ _ hl
        refine ⟨by simp [encodeList, hbs, hr], by simp [hlen], ?_⟩
        intro p hp
        simp only [List.zip_cons_cons, List.mem_cons] at hp
        rcases hp with rfl | hp
        · exact hw
        · exact hws p hp
termination_by (d, 2 * sizeOf fs, 0)

theorem decMap_canonical (R : Registry) (d : Nat) (kf vf : Fmt) (n : Nat) (prev : Option Bytes)
    (acc : List (Value × Value)) (bs : Bytes) (kvs : List (Value × Value)) (rest : Bytes)
    (h : decMap R d kf vf n prev acc bs = .ok (kvs, rest)) :
    ∃ ws, kvs = acc.reverse ++ ws ∧ ws.length = n ∧ bs = encodePairs ws ++ rest ∧
      keysSorted prev ws = true ∧ (∀ p ∈ ws, WT R d kf p.1) ∧ (∀ p ∈ ws, WT R d vf p.2) := by
  match n with
  | 0 =>
    simp only [decMap, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨[], by simp, rfl, by simp [encodePairs], by simp [keysSorted], by simp, by simp⟩
  | n + 1 =>
    simp only [decMap] at h
    cases hk : dec R d kf bs with
    | error e => simp [hk] at h
    | ok p =>
      obtain ⟨k, r1⟩ := p
      simp only [hk] at h
      obtain ⟨hbs, hwk⟩ := dec_canonical R d kf bs k r1 hk
      by_cases hc : prevLt prev (encode k) = true
      · simp only [hc, ite_true] at h
        cases hv : dec R d vf r1 with
        | error e => simp [hv] at h
        | ok q =>
          obtain ⟨v, r2⟩ := q
          simp only [hv] at h
          obtain ⟨hr1, hwv⟩ := dec_canonical R d vf r1 v r2 hv
          obtain ⟨ws, hkvs, hlen, hr2, hs, hks, hvs⟩ :=
            decMap_canonical R d kf vf n (Option.some (encode k)) ((k, v) :: acc) r2 kvs rest h
          refine ⟨(k, v) :: ws, by simp [hkvs], by simp [hlen],
            by simp [encodePairs, hbs, hr1, hr2], ?_, ?_, ?_⟩
          · simp only [keysSorted, Bool.and_eq_true]; exact ⟨hc, hs⟩
          · intro p hp; simp only [List.mem_cons] at hp
            rcases hp with rfl | hp
            · exact hwk
            · exact hks p hp
          · intro p hp; simp only [List.mem_cons] at hp
            rcases hp with rfl | hp
            · exact hwv
            · exact hvs p hp
      · simp [hc] at h
termination_by (d, 2 * sizeOf kf + 2 * sizeOf vf + 1, n + 1)
end

/-- The key bytes `decMap` compares are exactly the bytes the key was decoded from, as Rust's
`next_key_seed` slices them. -/
theorem dec_consumed {R : Registry} {d : Nat} {f : Fmt} {bs r : Bytes} {v : Value}
    (h : dec R d f bs = .ok (v, r)) : bs.take (bs.length - r.length) = encode v := by
  rw [(dec_canonical R d f bs v r h).1]; exact take_consumed _ _

/-- **Canonicity and round trip together**: whole-input decoding accepts exactly the
encodings of well-formed values. -/
theorem decodeFull_iff (R : Registry) (f : Fmt) (bs : Bytes) (v : Value) :
    decodeFull R f bs = .ok v ↔ WT R maxDepth f v ∧ bs = encode v := by
  constructor
  · intro h
    unfold decodeFull at h
    cases hd : dec R maxDepth f bs with
    | error e => simp [hd] at h
    | ok p =>
      obtain ⟨v', r⟩ := p
      simp only [hd] at h
      by_cases hr : r = []
      · simp only [hr, ite_true, Except.ok.injEq] at h
        subst h; subst hr
        obtain ⟨hbs, hw⟩ := dec_canonical R maxDepth f bs v' [] hd
        exact ⟨hw, by simpa using hbs⟩
      · simp [hr] at h
  · rintro ⟨hw, rfl⟩
    exact decodeFull_encode hw

/-- **Unique encoding.** Two inputs that decode to the same value are byte-identical. -/
theorem encoding_unique {R : Registry} {f : Fmt} {b1 b2 : Bytes} {v : Value}
    (h1 : decodeFull R f b1 = .ok v) (h2 : decodeFull R f b2 = .ok v) : b1 = b2 := by
  rw [((decodeFull_iff R f b1 v).1 h1).2, ((decodeFull_iff R f b2 v).1 h2).2]

/-- Re-encoding what was decoded gives back the input exactly (the `bcs` suite invariant
`encode(decode(b)) == b`). -/
theorem encode_decodeFull {R : Registry} {f : Fmt} {bs : Bytes} {v : Value}
    (h : decodeFull R f bs = .ok v) : encode v = bs :=
  ((decodeFull_iff R f bs v).1 h).2.symm

end Zui.Bcs
