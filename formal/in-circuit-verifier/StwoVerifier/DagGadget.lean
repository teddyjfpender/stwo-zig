/-
**The composition-polynomial gadget as the recorded DAG** (scope B).

`harness/airdump.zig` records the in-circuit `computeCompositionPolynomial`
(the 11-component evaluator table plus the composition accumulator) as
one arithmetic DAG (`CircuitAirData.nodes`) and its `eq` side
conditions. `dagG` emits one gate per node — `const`, `add`, `sub`,
`mul`, `inv` — reading atoms straight from the input registers, then one
`eq` gate per side condition. `dagG_sound`: every node register holds
the spec value `CircuitAir.evalNodes` assigns it, and the side
conditions hold (`eqConditionsHold`). `compositionG_sound` adds the
final `denom_inverse` and product: the output register is
`CircuitAir.composition`.

Trusted: that the Zig emitter's gates for this phase are exactly the
recorded DAG (the recording is a replay of the same emitter through a
recording context; `lake exe aircheck` checks values differentially).
-/
import StwoVerifier.CircuitAirEval
import StwoVerifier.CircleGadgets
import StwoVerifier.PowGadget

namespace StwoVerifier.Gadgets

attribute [local irreducible] CircuitAirData.nodes CircuitAirData.eqs

open StwoVerifier StwoVerifier.Gates CircuitAir CircuitAirData

/-- The constant of a `const` node. -/
def constVal (a : ℕ) : QM31 :=
  let c := consts.getD a (0, 0, 0, 0)
  QM31.fromM31s (c.1 : Nat) (c.2.1 : Nat) (c.2.2.1 : Nat) (c.2.2.2 : Nat)

/-- One node's gates and register. Atoms emit nothing. -/
def nodeG (zero : ℕ) (inRegs : Array ℕ) (regs : Array ℕ) (nd : ℕ × ℕ × ℕ) (n : ℕ) :
    List Op × ℕ × ℕ :=
  match nd with
  | (0, a, _) => ([.const n (constVal a)], n, n + 1)
  | (1, a, _) => ([], inRegs.getD a zero, n)
  | (2, a, b) => ([.add n (regs.getD a zero) (regs.getD b zero)], n, n + 1)
  | (3, a, b) => ([.sub n (regs.getD a zero) (regs.getD b zero)], n, n + 1)
  | (4, a, b) => ([.mul n (regs.getD a zero) (regs.getD b zero)], n, n + 1)
  | (_, a, _) => ([.inv n (regs.getD a zero)], n, n + 1)

/-- The node walk: registers in node order. -/
def dagWalk (zero : ℕ) (inRegs : Array ℕ) :
    List (ℕ × ℕ × ℕ) → Array ℕ → ℕ → Out (Array ℕ)
  | [], regs, n => ⟨[], regs, n⟩
  | nd :: rest, regs, n =>
    let s := nodeG zero inRegs regs nd n
    let r := dagWalk zero inRegs rest (regs.push s.2.1) s.2.2
    ⟨s.1 ++ r.ops, r.res, r.next⟩

theorem qinv_of_ne {x : QM31} (hx : x ≠ 0) : qinv x = x⁻¹ := by
  unfold qinv; rw [inv?_of_ne hx]; rfl

/-- Registers track values: one `getD`-level invariant. -/
def Tracks (ρ : ℕ → QM31) (zero : ℕ) (regs : Array ℕ) (vals : Array QM31) : Prop :=
  regs.size = vals.size ∧ ∀ k, ρ (regs.getD k zero) = vals.getD k QM31.zero

theorem tracks_push {ρ : ℕ → QM31} {zero : ℕ} {regs : Array ℕ} {vals : Array QM31}
    (ht : Tracks ρ zero regs vals) (r : ℕ) (v : QM31) (hv : ρ r = v) :
    Tracks ρ zero (regs.push r) (vals.push v) := by
  obtain ⟨hs, hk⟩ := ht
  refine ⟨by simp [hs], fun k => ?_⟩
  rw [Array.getD_eq_getD_getElem?, Array.getD_eq_getD_getElem?, Array.getElem?_push,
    Array.getElem?_push]
  by_cases hk' : k = regs.size
  · rw [if_pos hk', if_pos (by rw [hk', hs])]
    exact hv
  · rw [if_neg hk', if_neg (by rw [← hs]; exact hk')]
    have := hk k
    rwa [Array.getD_eq_getD_getElem?, Array.getD_eq_getD_getElem?] at this

theorem nodeG_sound {ρ : ℕ → QM31} {zero : ℕ} {inRegs regs : Array ℕ}
    {inputs vals : Array QM31} (hzero : ρ zero = 0)
    (hin : ∀ a, ρ (inRegs.getD a zero) = inputs.getD a QM31.zero)
    (ht : Tracks ρ zero regs vals) (nd : ℕ × ℕ × ℕ) (n : ℕ)
    (h : AllHold ρ (nodeG zero inRegs regs nd n).1) :
    ρ (nodeG zero inRegs regs nd n).2.1 = dagStep inputs vals nd := by
  obtain ⟨t, a, b⟩ := nd
  have hr : ∀ k, ρ (regs.getD k zero) = vals.getD k QM31.zero := ht.2
  match t with
  | 0 =>
    have := h _ List.mem_cons_self
    exact this
  | 1 => exact hin a
  | 2 =>
    have : ρ n = _ := h _ List.mem_cons_self
    show ρ n = _
    rw [this, hr, hr]; rfl
  | 3 =>
    have : ρ n = _ := h _ List.mem_cons_self
    show ρ n = _
    rw [this, hr, hr]; rfl
  | 4 =>
    have : ρ n = _ := h _ List.mem_cons_self
    show ρ n = _
    rw [this, hr, hr]; rfl
  | t + 5 =>
    have hinv : ρ (regs.getD a zero) * ρ n = QM31.one := h _ List.mem_cons_self
    show ρ n = qinv (vals.getD a QM31.zero)
    have hne : ρ (regs.getD a zero) ≠ 0 := by
      intro h0; rw [h0, zero_mul] at hinv; exact absurd hinv (by decide)
    rw [← hr, qinv_of_ne hne]
    exact eq_inv_of_mul_eq_one_right hinv

theorem dagWalk_sound {ρ : ℕ → QM31} {zero : ℕ} {inRegs : Array ℕ}
    {inputs : Array QM31} (hzero : ρ zero = 0)
    (hin : ∀ a, ρ (inRegs.getD a zero) = inputs.getD a QM31.zero) :
    ∀ (nds : List (ℕ × ℕ × ℕ)) (regs : Array ℕ) (vals : Array QM31) (n : ℕ),
      Tracks ρ zero regs vals → AllHold ρ (dagWalk zero inRegs nds regs n).ops →
      Tracks ρ zero (dagWalk zero inRegs nds regs n).res
        (nds.foldl (fun vs nd => vs.push (dagStep inputs vs nd)) vals) := by
  intro nds
  induction nds with
  | nil => intro regs vals n ht _; exact ht
  | cons nd rest ih =>
    intro regs vals n ht h
    rw [show (dagWalk zero inRegs (nd :: rest) regs n).ops =
      (nodeG zero inRegs regs nd n).1 ++
        (dagWalk zero inRegs rest (regs.push (nodeG zero inRegs regs nd n).2.1)
          (nodeG zero inRegs regs nd n).2.2).ops from rfl, allHold_append] at h
    obtain ⟨h1, h2⟩ := h
    have hv := nodeG_sound hzero hin ht nd n h1
    exact ih _ _ _ (tracks_push ht _ _ hv) h2

/-- The DAG gadget: the node walk, then the recorded `eq` gates. -/
def dagG (zero : ℕ) (inRegs : Array ℕ) (n : ℕ) : Out (Array ℕ) :=
  let w := dagWalk zero inRegs nodes.toList #[] n
  ⟨w.ops ++ eqs.toList.map (fun p => .eq (w.res.getD p.1 zero) (w.res.getD p.2 zero)),
   w.res, w.next⟩

theorem evalNodes_eq (inputs : Array QM31) :
    evalNodes inputs
      = nodes.toList.foldl (fun vs nd => vs.push (dagStep inputs vs nd)) #[] := by
  unfold evalNodes
  rw [← Array.foldl_toList]
  rfl

/-- **The DAG gadget computes the spec DAG**: node registers carry
`evalNodes`, and the recorded side conditions hold. -/
theorem dagG_sound {ρ : ℕ → QM31} {zero : ℕ} {inRegs : Array ℕ} {inputs : Array QM31}
    {n : ℕ} (hzero : ρ zero = 0)
    (hin : ∀ a, ρ (inRegs.getD a zero) = inputs.getD a QM31.zero)
    (h : AllHold ρ (dagG zero inRegs n).ops) :
    (∀ k, ρ ((dagG zero inRegs n).res.getD k zero) = (evalNodes inputs).getD k QM31.zero) ∧
    eqConditionsHold inputs = true := by
  unfold dagG at h
  rw [allHold_append] at h
  obtain ⟨hw, he⟩ := h
  have ht := dagWalk_sound hzero hin nodes.toList #[] #[] n ⟨rfl, fun k => by
    simp [hzero]⟩ hw
  rw [evalNodes_eq]
  refine ⟨ht.2, ?_⟩
  unfold eqConditionsHold
  simp only [Array.all_eq_true]
  intro i hi
  have hg := he _ (List.mem_map.mpr ⟨eqs[i], Array.getElem_mem_toList hi, rfl⟩)
  simp only [Holds] at hg
  rw [ht.2, ht.2] at hg
  rw [evalNodes_eq]
  simpa [QM31.eql, Array.getD_eq_getD_getElem?] using hg

/-- `vanishing` is the iterated `doubleX`. -/
theorem vanishing_eq (x : QM31) : ∀ k, vanishing x k = CPoint.doubleX^[k] x
  | 0 => rfl
  | k + 1 => by
    rw [Function.iterate_succ_apply', ← vanishing_eq x k]
    rfl

/-- **The composition gadget**: the DAG, the vanishing inverse at the
point's `x`, and the product is `CircuitAir.composition`. -/
noncomputable def compositionG (zero one : ℕ) (inRegs : Array ℕ) (ptX : ℕ) (logTrace : ℕ)
    (n : ℕ) : Out ℕ :=
  let d := dagG zero inRegs n
  let di := denomInverse one ptX logTrace d.next
  ⟨d.ops ++ di.ops ++ [.mul di.next (d.res.getD output zero) di.res], di.next, di.next + 1⟩

theorem compositionG_sound {ρ : ℕ → QM31} {zero one : ℕ} {inRegs : Array ℕ}
    {inputs : Array QM31} {ptX logTrace n : ℕ} (hzero : ρ zero = 0) (hone : ρ one = 1)
    (hin : ∀ a, ρ (inRegs.getD a zero) = inputs.getD a QM31.zero)
    (hx : ρ ptX = inputs.getD atomPtX QM31.zero)
    (h : AllHold ρ (compositionG zero one inRegs ptX logTrace n).ops) :
    eqConditionsHold inputs = true ∧
    ρ (compositionG zero one inRegs ptX logTrace n).res = composition inputs logTrace := by
  unfold compositionG at h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hd, hdi⟩, hm⟩ := h
  obtain ⟨hvals, heqs⟩ := dagG_sound hzero hin hd
  refine ⟨heqs, ?_⟩
  have hm' := hm _ List.mem_cons_self
  simp only [Holds] at hm'
  have hinv := denomInverse_sound hone hdi
  have hne : CPoint.doubleX^[logTrace - 1] (ρ ptX) ≠ 0 := by
    intro h0; rw [h0, zero_mul] at hinv; exact absurd hinv (by decide)
  show ρ (denomInverse one ptX logTrace (dagG zero inRegs n).next).next = _
  rw [hm', hvals, eq_inv_of_mul_eq_one_right hinv]
  unfold composition constraintSum
  rw [vanishing_eq, ← hx, qinv_of_ne hne]

end StwoVerifier.Gadgets
