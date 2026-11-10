import Zui.Gas.Model

/-!
# Gas theorems

For the live gas model (15, `gas_v3.rs`):

* `senderRebate_le`, `rebate_split`: the sender rebate never exceeds the storage rebate it is
  taken from (so never more than the storage previously paid for those objects), and rebate =
  sender rebate + non-refundable fee exactly.
* `computation_le_budget`: the reported computation cost never exceeds the budget.
* `charge_le_budget`: once `charge_storage_and_rebate` has accepted the storage, the net charge
  computation + storage cost - sender rebate never exceeds the budget.
* `outOfGas_summary`: after the out-of-gas adjustment the summary is exactly
  (budget, 0, 0, 0).
* `deduct_le`, `charge_gasLeft_le`, `used_le`: the meter only ever spends, and gas used never
  exceeds the computation budget.
* `le_halfDigits`: half-digit rounding never rounds down.
* `chargeList_batch`: **batching licence for the Move VM.** Charging a run of instructions one
  by one, and charging their summed counts in one `charge` call, give the same verdict
  (success or OUT_OF_GAS) and the same gas left, whenever the run crosses no tier boundary and
  stays inside u64 (on success the counters agree too). So the VM may charge a basic block once,
  after checking at block entry that no tier boundary is in reach.
-/

namespace Zui.Gas

/-! ## Rebates -/

theorem senderRebate_le (r rate : Nat) (h : rate ≤ 10000) : senderRebate r rate ≤ r := by
  unfold senderRebate
  have h1 : r * rate ≤ r * 10000 := Nat.mul_le_mul_left r h
  have h2 : (r * rate + 5000) / 10000 ≤ (r * 10000 + 5000) / 10000 := Nat.div_le_div_right (by omega)
  have h3 : (r * 10000 + 5000) / 10000 = r := by omega
  exact Nat.le_trans (Nat.min_le_left _ _) (by omega)

theorem rebate_split (s : Status) (h : s.cfg.rebateRate ≤ 10000) :
    s.storageRebate = s.senderRebate + (s.storageRebate - s.senderRebate) := by
  have := senderRebate_le s.storageRebate s.cfg.rebateRate h
  unfold Status.senderRebate; omega

/-! ## Budget bounds -/

theorem computation_le_budget (s : Status) : s.computation ≤ s.budget := by
  unfold Status.computation
  exact Nat.le_trans (Nat.min_le_right _ _) (Nat.sub_le _ _)

theorem charge_le_budget_of_net (s : Status) (h : s.netStorage ≤ s.budget) :
    s.computation + s.storageCost ≤ s.budget + s.senderRebate := by
  unfold Status.computation Status.netStorage at *
  have := Nat.min_le_right s.uncapped (s.budget - (s.storageCost - s.senderRebate))
  omega

theorem chargeStorage_net (s : Status) (h : s.chargeStorage = none) : s.netStorage ≤ s.budget := by
  unfold Status.chargeStorage at h
  by_cases hc : s.netStorage > s.budget - s.uncapped
  · simp [hc] at h
  · omega

/-- **Charges never exceed the budget.** -/
theorem charge_le_budget (s : Status) (h : s.chargeStorage = none) :
    s.computation + s.storageCost ≤ s.budget + s.senderRebate :=
  charge_le_budget_of_net s (chargeStorage_net s h)

theorem outOfGas_summary (s : Status) : s.outOfGas.summary = (s.budget, 0, 0, 0) := by
  simp [Status.summary, Status.outOfGas, Status.computation, Status.uncapped,
    Status.netStorage, Status.senderRebate, senderRebate, u64Max]

/-! ## The meter only spends -/

theorem deduct_le (m : Meter) (a : Nat) : (m.deduct a).1.gasLeft ≤ m.gasLeft := by
  unfold Meter.deduct; split <;> simp

theorem pushStack_gasLeft {m m' : Meter} {p : Nat} (h : m.pushStack p = some m') : m'.gasLeft = m.gasLeft := by
  unfold Meter.pushStack at h
  dsimp only at h
  by_cases h1 : m.hCur + p > u64Max
  · simp [h1] at h
  · rw [if_neg h1] at h
    cases hn : m.hNext with
    | none => rw [hn] at h; simp at h; rw [← h]
    | some n =>
      rw [hn] at h
      dsimp only at h
      split at h <;> (simp at h; rw [← h])

theorem addInstr_gasLeft {m m' : Meter} {p : Nat} (h : m.addInstr p = some m') : m'.gasLeft = m.gasLeft := by
  unfold Meter.addInstr at h
  dsimp only at h
  by_cases h1 : m.instr + p > u64Max
  · simp [h1] at h
  · rw [if_neg h1] at h
    cases hn : m.iNext with
    | none => rw [hn] at h; simp at h; rw [← h]
    | some n =>
      rw [hn] at h
      dsimp only at h
      split at h <;> (simp at h; rw [← h])

theorem addSize_gasLeft {m m' : Meter} {p : Nat} (h : m.addSize p = some m') : m'.gasLeft = m.gasLeft := by
  unfold Meter.addSize at h
  dsimp only at h
  by_cases h1 : m.sCur + p > u64Max
  · simp [h1] at h
  · rw [if_neg h1] at h
    cases hn : m.sNext with
    | none => rw [hn] at h; simp at h; rw [← h]
    | some n =>
      rw [hn] at h
      dsimp only at h
      split at h <;> (simp at h; rw [← h])

theorem charge_gasLeft_le (m : Meter) (i pu po inc : Nat) :
    (m.charge i pu po inc).1.gasLeft ≤ m.gasLeft := by
  unfold Meter.charge
  cases h1 : m.pushStack pu with
  | none => simp
  | some m1 =>
    have e1 := pushStack_gasLeft h1
    simp only
    cases h2 : m1.addInstr i with
    | none => simp only; omega
    | some m2 =>
      have e2 := addInstr_gasLeft h2
      simp only
      cases h3 : m2.addSize inc with
      | none => simp only; omega
      | some m3 =>
        have e3 := addSize_gasLeft h3
        simp only
        have := deduct_le m3 (m3.iMult * i + m3.sMult * inc + m3.hMult * pu)
        split
        · simp only; omega
        · cases hd : m3.deduct (m3.iMult * i + m3.sMult * inc + m3.hMult * pu) with
          | mk md e =>
            rw [hd] at this
            cases e <;> dsimp only at this ⊢ <;> omega

theorem used_le (m : Meter) : m.used ≤ m.initial / 1000 := by
  unfold Meter.used; exact Nat.div_le_div_right (Nat.sub_le _ _)

/-! ## Rounding -/

theorem le_ceilDiv_mul (n b : Nat) (hb : b > 0) : n ≤ ceilDiv n b * b := by
  unfold ceilDiv
  have h1 := Nat.div_add_mod (n + b - 1) b
  have h2 := Nat.mod_lt (n + b - 1) hb
  rw [Nat.mul_comm]
  omega

theorem le_halfDigits (n : Nat) (h : n ≤ u64Max) : n ≤ halfDigits n := by
  unfold halfDigits
  split
  · omega
  · have hb : 10 ^ (ilog10 n / 2) > 0 := Nat.pow_pos (by decide)
    have := le_ceilDiv_mul n _ hb
    exact Nat.le_min.2 ⟨this, h⟩

/-! ## Batching -/

/-- One instruction's counts: (instructions, pushes, pops, size increase). -/
abbrev Step := Nat × Nat × Nat × Nat

def Meter.chargeList (m : Meter) : List Step → Meter × Option VmErr
  | [] => (m, none)
  | (i, pu, po, inc) :: ops =>
    match m.charge i pu po inc with
    | (m', none) => m'.chargeList ops
    | r => r

def sumI : List Step → Nat
  | [] => 0
  | (i, _, _, _) :: ops => i + sumI ops
def sumPU : List Step → Nat
  | [] => 0
  | (_, pu, _, _) :: ops => pu + sumPU ops
def sumPO : List Step → Nat
  | [] => 0
  | (_, _, po, _) :: ops => po + sumPO ops
def sumINC : List Step → Nat
  | [] => 0
  | (_, _, _, inc) :: ops => inc + sumINC ops

/-- No tier boundary is reached and nothing leaves u64 when adding these totals. -/
def Quiet (m : Meter) (I PU INC : Nat) : Prop :=
  (∀ n, m.iNext = some n → m.instr + I ≤ n) ∧
  (∀ n, m.hNext = some n → m.hCur + PU ≤ n) ∧
  (∀ n, m.sNext = some n → m.sCur + INC ≤ n) ∧
  m.instr + I ≤ u64Max ∧ m.hCur + PU ≤ u64Max ∧ m.sCur + INC ≤ u64Max ∧
  m.iMult * I ≤ u64Max ∧ m.sMult * INC ≤ u64Max ∧ m.hMult * PU ≤ u64Max

/-- Every pop is covered by the stack height at that point (no saturation). -/
def PopsOk : Nat → List Step → Prop
  | _, [] => True
  | h, (_, pu, po, _) :: ops => po ≤ h + pu ∧ PopsOk (h + pu - po) ops

def Meter.cost (m : Meter) (i pu inc : Nat) : Nat := m.iMult * i + m.sMult * inc + m.hMult * pu

/-- The meter after a successful quiet charge of these totals. -/
def Meter.after (m : Meter) (I PU PO INC : Nat) : Meter :=
  { m with hCur := m.hCur + PU - PO, instr := m.instr + I, sCur := m.sCur + INC,
           gasLeft := m.gasLeft - m.cost I PU INC }

theorem pushStack_quiet (m : Meter) (p : Nat) (h64 : m.hCur + p ≤ u64Max)
    (hn : ∀ n, m.hNext = some n → m.hCur + p ≤ n) :
    m.pushStack p = some { m with hCur := m.hCur + p } := by
  unfold Meter.pushStack
  dsimp only
  rw [if_neg (by omega)]
  cases h : m.hNext with
  | none => rfl
  | some n => have := hn n h; dsimp only; rw [if_neg (by omega)]

theorem addInstr_quiet (m : Meter) (p : Nat) (h64 : m.instr + p ≤ u64Max)
    (hn : ∀ n, m.iNext = some n → m.instr + p ≤ n) :
    m.addInstr p = some { m with instr := m.instr + p } := by
  unfold Meter.addInstr
  dsimp only
  rw [if_neg (by omega)]
  cases h : m.iNext with
  | none => rfl
  | some n => have := hn n h; dsimp only; rw [if_neg (by omega)]

theorem addSize_quiet (m : Meter) (p : Nat) (h64 : m.sCur + p ≤ u64Max)
    (hn : ∀ n, m.sNext = some n → m.sCur + p ≤ n) :
    m.addSize p = some { m with sCur := m.sCur + p } := by
  unfold Meter.addSize
  dsimp only
  rw [if_neg (by omega)]
  cases h : m.sNext with
  | none => rfl
  | some n => have := hn n h; dsimp only; rw [if_neg (by omega)]

/-- Under `Quiet`, `charge` is plain arithmetic. -/
theorem charge_quiet (m : Meter) (i pu po inc : Nat) (hq : Quiet m i pu inc) :
    m.charge i pu po inc =
      if m.cost i pu inc ≤ m.gasLeft then (m.after i pu po inc, none)
      else ({ m with hCur := m.hCur + pu, instr := m.instr + i, sCur := m.sCur + inc, gasLeft := 0 },
            some .outOfGas) := by
  obtain ⟨hi, hh, hs, hi64, hh64, hs64, hmi, hms, hmh⟩ := hq
  unfold Meter.charge
  rw [pushStack_quiet m pu hh64 hh]
  dsimp only
  rw [addInstr_quiet { m with hCur := m.hCur + pu } i hi64 hi]
  dsimp only
  rw [addSize_quiet { m with hCur := m.hCur + pu, instr := m.instr + i } inc hs64 hs]
  dsimp only
  rw [if_neg (by omega)]
  unfold Meter.deduct Meter.after Meter.cost
  by_cases hc : m.iMult * i + m.sMult * inc + m.hMult * pu ≤ m.gasLeft
  · rw [if_pos hc, if_pos hc]
  · rw [if_neg hc, if_neg hc]

theorem quiet_step {m : Meter} {i pu inc I PU INC : Nat} (hq : Quiet m (i + I) (pu + PU) (inc + INC)) :
    Quiet m i pu inc := by
  obtain ⟨hi, hh, hs, a, b, c, d, e, f⟩ := hq
  refine ⟨fun n h => by have := hi n h; omega, fun n h => by have := hh n h; omega,
    fun n h => by have := hs n h; omega, by omega, by omega, by omega, ?_, ?_, ?_⟩
  · exact Nat.le_trans (Nat.mul_le_mul_left _ (by omega)) d
  · exact Nat.le_trans (Nat.mul_le_mul_left _ (by omega)) e
  · exact Nat.le_trans (Nat.mul_le_mul_left _ (by omega)) f

theorem popsOk_sum : ∀ (ops : List Step) (h : Nat), PopsOk h ops → sumPO ops ≤ h + sumPU ops := by
  intro ops
  induction ops with
  | nil => intro h _; simp [sumPO]
  | cons op ops ih =>
    obtain ⟨i, pu, po, inc⟩ := op
    intro h hp
    simp only [PopsOk] at hp
    have := ih _ hp.2
    simp only [sumPO, sumPU]; omega

/-- A quiet run charged step by step: arithmetic on success, OUT_OF_GAS with nothing left on
failure. -/
theorem chargeList_quiet : ∀ (ops : List Step) (m : Meter),
    Quiet m (sumI ops) (sumPU ops) (sumINC ops) → PopsOk m.hCur ops →
    (m.cost (sumI ops) (sumPU ops) (sumINC ops) ≤ m.gasLeft →
      m.chargeList ops = (m.after (sumI ops) (sumPU ops) (sumPO ops) (sumINC ops), none)) ∧
    (¬ m.cost (sumI ops) (sumPU ops) (sumINC ops) ≤ m.gasLeft →
      (m.chargeList ops).2 = some .outOfGas ∧ (m.chargeList ops).1.gasLeft = 0) := by
  intro ops
  induction ops with
  | nil =>
    intro m _ _
    refine ⟨fun _ => ?_, fun h => ?_⟩
    · obtain ⟨⟩ := m; simp [Meter.chargeList, Meter.after, sumI, sumPU, sumPO, sumINC, Meter.cost]
    · simp [sumI, sumPU, sumINC, Meter.cost] at h
  | cons op ops ih =>
    obtain ⟨i, pu, po, inc⟩ := op
    intro m hq hp
    simp only [sumI, sumPU, sumPO, sumINC] at hq ⊢
    simp only [PopsOk] at hp
    obtain ⟨hpo, hp⟩ := hp
    have hq1 := quiet_step hq
    have hcost : m.cost (i + sumI ops) (pu + sumPU ops) (inc + sumINC ops) =
        m.cost i pu inc + m.cost (sumI ops) (sumPU ops) (sumINC ops) := by
      simp only [Meter.cost, Nat.mul_add]; omega
    rw [hcost]
    simp only [Meter.chargeList]
    rw [charge_quiet m i pu po inc hq1]
    by_cases h1 : m.cost i pu inc ≤ m.gasLeft
    · rw [if_pos h1]
      dsimp only
      have hq' : Quiet (m.after i pu po inc) (sumI ops) (sumPU ops) (sumINC ops) := by
        unfold Meter.after
        obtain ⟨a, b, c, d, e, f, g, h, k⟩ := hq
        refine ⟨fun n hn => by have := a n hn; dsimp only at *; omega,
          fun n hn => by have := b n hn; dsimp only at *; omega,
          fun n hn => by have := c n hn; dsimp only at *; omega,
          by dsimp only; omega, by dsimp only; omega, by dsimp only; omega, ?_, ?_, ?_⟩
        · exact Nat.le_trans (Nat.mul_le_mul_left _ (by omega)) g
        · exact Nat.le_trans (Nat.mul_le_mul_left _ (by omega)) h
        · exact Nat.le_trans (Nat.mul_le_mul_left _ (by omega)) k
      obtain ⟨ok, bad⟩ := ih _ hq' hp
      have hrest := popsOk_sum ops _ hp
      try dsimp only at hrest
      refine ⟨fun h2 => ?_, fun h2 => ?_⟩
      · rw [ok (by unfold Meter.after Meter.cost at *; dsimp only at *; omega)]
        obtain ⟨⟩ := m
        unfold Meter.after Meter.cost at *
        dsimp only at *
        simp only [Prod.mk.injEq, Meter.mk.injEq, and_true, true_and, Nat.mul_add]
        omega
      · exact bad (by unfold Meter.after Meter.cost at *; dsimp only at *; omega)
    · rw [if_neg h1]
      refine ⟨fun h2 => absurd (by omega) h1, fun _ => ⟨rfl, rfl⟩⟩

/-- **Batching licence.** -/
theorem chargeList_batch (ops : List Step) (m : Meter)
    (hq : Quiet m (sumI ops) (sumPU ops) (sumINC ops)) (hp : PopsOk m.hCur ops) :
    (m.chargeList ops).2 = (m.charge (sumI ops) (sumPU ops) (sumPO ops) (sumINC ops)).2 ∧
    (m.chargeList ops).1.gasLeft = (m.charge (sumI ops) (sumPU ops) (sumPO ops) (sumINC ops)).1.gasLeft ∧
    ((m.chargeList ops).2 = none →
      (m.chargeList ops).1 = (m.charge (sumI ops) (sumPU ops) (sumPO ops) (sumINC ops)).1) := by
  obtain ⟨ok, bad⟩ := chargeList_quiet ops m hq hp
  rw [charge_quiet m _ _ _ _ hq]
  by_cases h : m.cost (sumI ops) (sumPU ops) (sumINC ops) ≤ m.gasLeft
  · rw [if_pos h, ok h]
    exact ⟨rfl, rfl, fun _ => rfl⟩
  · rw [if_neg h]
    obtain ⟨e1, e2⟩ := bad h
    exact ⟨e1, e2, fun hn => by rw [e1] at hn; cases hn⟩

end Zui.Gas
