import Zui.Store.Model

/-!
# Store: crash-recovery theorems

* `recover_crash`: after any crash, recovery yields exactly the first `k` checkpoints of the
  history for some `k` with `acked ≤ k ≤ started`: no acknowledged checkpoint is lost and no
  checkpoint is partially visible (the recovered log is whole groups of the history, and the
  index is `stateAt G k`, the state after exactly `k` whole checkpoints).
* The index part holds from any snapshot: one taken after `j` checkpoints, while `meta` names a
  replay position `a ≤ j` (the snapshot was written but `meta` still points at an older one, or
  points at it exactly). Replaying groups the snapshot already holds changes nothing
  (`replay_absorbed`), because updates keep the higher version.
* `recover_idem`: recovering the recovered log again gives the same result (a crash during or
  right after recovery is just another crash with `s = k`).
-/

namespace Zui.Store

/-! ## The log scan -/

theorem scan_history {G : List Group} (hG : History G) :
    ∀ (m n : Nat) (tail : List Entry), n + m ≤ G.length →
      scan n (((G.drop n).take m).map .grp ++ tail) = (G.drop n).take m ++ scan (n + m) tail := by
  intro m
  induction m with
  | zero => intro n tail _; simp
  | succ m ih =>
    intro n tail h
    have hn : n < G.length := by omega
    rw [List.drop_eq_getElem_cons hn]
    simp only [List.take_succ_cons, List.map_cons, List.cons_append, scan, hG n hn, ite_true]
    rw [ih (n + 1) tail (by omega), Nat.add_assoc, Nat.add_comm 1 m]

theorem scan_garbage {G : List Group} (hG : History G) :
    ∀ (tail : List Entry) (n : Nat), Garbage G tail → ∃ j, scan n tail = (G.drop n).take j := by
  intro tail
  induction tail with
  | nil => intro n _; exact ⟨0, by simp [scan]⟩
  | cons e rest ih =>
    intro n hg
    have hrest : Garbage G rest := fun e' he' => hg e' (List.mem_cons_of_mem _ he')
    rcases hg e List.mem_cons_self with rfl | ⟨g, hgG, rfl⟩
    · exact ⟨0, by simp [scan]⟩
    · simp only [scan]
      by_cases hs : g.seq = n
      · simp only [hs, ite_true]
        obtain ⟨i, hi, hgi⟩ := List.getElem_of_mem hgG
        have hin : i = n := by rw [← hs, ← hgi, hG i hi]
        subst hin
        obtain ⟨j, hj⟩ := ih (i + 1) hrest
        refine ⟨j + 1, ?_⟩
        rw [hj, List.drop_eq_getElem_cons hi, List.take_succ_cons, hgi]
      · simp only [hs, ite_false]
        exact ⟨0, by simp⟩

/-- The recovered log is a prefix of the history that contains every synced group. -/
theorem recoverLog_crash {G : List Group} (hG : History G) {s : Nat} (hs : s ≤ G.length)
    {tail : List Entry} (hg : Garbage G tail) :
    ∃ k, s ≤ k ∧ k ≤ G.length ∧ recoverLog (crashLog G s tail) = G.take k := by
  have h0 := scan_history hG s 0 tail (by omega)
  simp only [List.drop_zero, Nat.zero_add] at h0
  obtain ⟨j, hj⟩ := scan_garbage hG tail s hg
  refine ⟨min (s + j) G.length, by omega, by omega, ?_⟩
  simp only [recoverLog, crashLog, h0, hj]
  rw [← List.take_add, List.take_eq_take_iff]
  omega

/-! ## The index -/

/-- `s` already holds `w` or something newer for its key. -/
def Absorbs (s : State) (w : Write) : Prop := ∃ v x, s w.1 = some (v, x) ∧ w.2.1 ≤ v

theorem absorbs_write (s : State) (w : Write) : Absorbs (applyWrite s w) w := by
  obtain ⟨k, v, x⟩ := w
  simp only [Absorbs, applyWrite, ite_true]
  cases h : s k with
  | none => exact ⟨v, x, by simp [merge], Nat.le_refl _⟩
  | some p =>
    obtain ⟨v', x'⟩ := p
    by_cases hv : v > v'
    · exact ⟨v, x, by simp [merge, hv], Nat.le_refl _⟩
    · exact ⟨v', x', by simp [merge, hv], by omega⟩

theorem absorbs_mono {s : State} {w : Write} (h : Absorbs s w) (u : Write) :
    Absorbs (applyWrite s u) w := by
  obtain ⟨v, x, hs, hle⟩ := h
  obtain ⟨k, vu, xu⟩ := u
  simp only [Absorbs, applyWrite]
  by_cases hk : w.1 = k
  · simp only [hk, ite_true]
    rw [hk] at hs
    rw [hs]
    by_cases hv : vu > v
    · exact ⟨vu, xu, by simp [merge, hv], by omega⟩
    · exact ⟨v, x, by simp [merge, hv], hle⟩
  · simp only [hk, ite_false]
    exact ⟨v, x, hs, hle⟩

theorem applyWrite_absorbed {s : State} {w : Write} (h : Absorbs s w) : applyWrite s w = s := by
  obtain ⟨v, x, hs, hle⟩ := h
  funext k
  simp only [applyWrite]
  by_cases hk : k = w.1
  · subst hk
    have : ¬ w.2.1 > v := by omega
    simp [hs, merge, this]
  · simp [hk]

theorem absorbs_writes {s : State} {w : Write} (h : Absorbs s w) :
    ∀ ws : List Write, Absorbs (ws.foldl applyWrite s) w := by
  intro ws
  induction ws generalizing s with
  | nil => exact h
  | cons u ws ih => exact ih (absorbs_mono h u)

theorem absorbs_replay {s : State} {w : Write} (h : Absorbs s w) :
    ∀ gs : List Group, Absorbs (replay s gs) w := by
  intro gs
  induction gs generalizing s with
  | nil => exact h
  | cons g gs ih => exact ih (absorbs_writes h g.writes)

theorem writes_absorbed (s : State) :
    ∀ (ws : List Write), ∀ w ∈ ws, Absorbs (ws.foldl applyWrite s) w := by
  intro ws
  induction ws generalizing s with
  | nil => intro w hw; cases hw
  | cons u ws ih =>
    intro w hw
    rcases List.mem_cons.mp hw with rfl | hw
    · exact absorbs_writes (absorbs_write s w) ws
    · exact ih (applyWrite s u) w hw

/-- Every write of every replayed group is absorbed by the result. -/
theorem replay_absorbs (s : State) :
    ∀ (gs : List Group), ∀ g ∈ gs, ∀ w ∈ g.writes, Absorbs (replay s gs) w := by
  intro gs
  induction gs generalizing s with
  | nil => intro g hg; cases hg
  | cons g' gs ih =>
    intro g hg w hw
    rcases List.mem_cons.mp hg with rfl | hg
    · exact absorbs_replay (writes_absorbed s g.writes w hw) gs
    · exact ih (applyGroup s g') g hg w hw

theorem foldl_absorbed {s : State} :
    ∀ (ws : List Write), (∀ w ∈ ws, Absorbs s w) → ws.foldl applyWrite s = s := by
  intro ws h
  induction ws with
  | nil => rfl
  | cons u ws ih =>
    simp only [List.foldl_cons, applyWrite_absorbed (h u List.mem_cons_self)]
    exact ih fun w hw => h w (List.mem_cons_of_mem _ hw)

/-- Replaying groups whose writes the state already absorbed changes nothing. -/
theorem replay_absorbed {s : State} :
    ∀ (gs : List Group), (∀ g ∈ gs, ∀ w ∈ g.writes, Absorbs s w) → replay s gs = s := by
  intro gs h
  induction gs with
  | nil => rfl
  | cons g gs ih =>
    simp only [replay, List.foldl_cons, applyGroup]
    rw [foldl_absorbed g.writes (h g List.mem_cons_self)]
    exact ih fun g' hg' => h g' (List.mem_cons_of_mem _ hg')

/-- Idempotence: replaying again any groups already replayed changes nothing. -/
theorem replay_idem (s : State) (gs : List Group) {gs' : List Group}
    (h : ∀ g ∈ gs', g ∈ gs) : replay (replay s gs) gs' = replay s gs :=
  replay_absorbed gs' fun g hg w hw => replay_absorbs s gs g (h g hg) w hw

/-- Replay from a snapshot after `j` checkpoints, starting at any older position `a`, lands on
the state after `k`. -/
theorem replay_from_snapshot (G : List Group) {a j k : Nat} (haj : a ≤ j) (hjk : j ≤ k)
    (hj : j ≤ G.length) :
    replay (stateAt G j) ((G.take k).drop a) = stateAt G k := by
  have hlen : ((G.take k).take j).length = j := by simp; omega
  have htj : (G.take k).take j = G.take j := by rw [List.take_take]; congr 1; omega
  have split : (G.take k).drop a = (G.take j).drop a ++ (G.take k).drop j := by
    conv => lhs; rw [← List.take_append_drop j (G.take k)]
    rw [List.drop_append_of_le_length (by omega), htj]
  rw [split, replay, List.foldl_append]
  have hsub : ∀ g ∈ (G.take j).drop a, g ∈ G.take j := fun g hg => List.mem_of_mem_drop hg
  have := replay_idem State.empty (G.take j) hsub
  simp only [stateAt, replay] at this ⊢
  rw [this, ← List.foldl_append, ← htj, List.take_append_drop]

/-! ## Recovery -/

/-- **Crash recovery.** Any crash of a store whose first `s` checkpoints were synced
(acknowledged), recovered from an index snapshot taken after `j ≤ s` checkpoints with `meta`
naming replay position `a ≤ j`, recovers the log as the first `k` checkpoints and the index as
the state after exactly those `k`, for one `k` with `s ≤ k ≤ |G|`. -/
theorem recover_crash {G : List Group} (hG : History G) {s : Nat} (hs : s ≤ G.length)
    {tail : List Entry} (hg : Garbage G tail) :
    ∃ k, s ≤ k ∧ k ≤ G.length ∧ recoverLog (crashLog G s tail) = G.take k ∧
      ∀ a j, a ≤ j → j ≤ s →
        recoverIndex (stateAt G j) a (crashLog G s tail) = stateAt G k := by
  obtain ⟨k, hsk, hkl, hr⟩ := recoverLog_crash hG hs hg
  refine ⟨k, hsk, hkl, hr, fun a j haj hjs => ?_⟩
  simp only [recoverIndex, hr]
  exact replay_from_snapshot G haj (by omega) (by omega)

/-- Recovering the recovered (truncated) log again changes nothing. -/
theorem recover_idem {G : List Group} (hG : History G) {k : Nat} (hk : k ≤ G.length) :
    recoverLog ((G.take k).map .grp) = G.take k := by
  have h := scan_history hG k 0 [] (by omega)
  simpa [recoverLog, scan] using h

end Zui.Store
