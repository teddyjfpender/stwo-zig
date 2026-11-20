/-
**Scope A, first gadgets: in-circuit circle arithmetic**
(`src/frontends/circuit/stark_verifier/circle.zig`, stwo-zig `4afa09dbf`).

Each emitter mirrors the Zig function's builder calls over plain QM31
wires, in emission order, against a register `one` holding the interned
constant 1 (the builder's var 1). The soundness theorems say: whenever an
assignment satisfies every emitted gate (and pins `one`), the output
registers hold the spec's function of the input registers — the same
`CPoint` functions the differentially-validated verifier spec runs on.

`double_point` is sound only on the circle: its x-coordinate uses
`2x² − 1`, which equals the group law's `x² − y²` exactly when
`x² + y² = 1`. The hypothesis is explicit in `doublePoint_sound`; callers
must establish it (the verifier only doubles points known on-circle).
-/
import StwoVerifier.Gates
import StwoVerifier.Circle
import StwoVerifier.Algebra

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- A point as two registers. -/
structure PointReg where
  x : ℕ
  y : ℕ
  deriving Repr

/-- The QM31 point an assignment gives a register pair. -/
def PointReg.val (ρ : ℕ → QM31) (p : PointReg) : PointQ := ⟨ρ p.x, ρ p.y⟩

/-! ### `double_x`: `2x² − 1` -/

/-- `doubleX`: `sqr = x·x`, `twice = sqr + sqr`, `out = twice − one`. -/
def doubleX (one x n : ℕ) : Out ℕ :=
  ⟨[.mul n x x, .add (n + 1) n n, .sub (n + 2) (n + 1) one], n + 2, n + 3⟩

theorem doubleX_sound {ρ : ℕ → QM31} {one x n : ℕ}
    (hone : ρ one = 1) (h : AllHold ρ (doubleX one x n).ops) :
    ρ (doubleX one x n).res = CPoint.doubleX (ρ x) := by
  rw [show (doubleX one x n).ops =
    .mul n x x :: .add (n + 1) n n :: [.sub (n + 2) (n + 1) one] from rfl,
    allHold_cons, allHold_cons, allHold_cons] at h
  obtain ⟨h1, h2, h3, -⟩ := h
  simp only [Holds] at h1 h2 h3
  show ρ (n + 2) = _
  rw [h3, h2, h1, hone]
  rfl

/-! ### `add_points`: the circle group law -/

/-- `addPoints`: the six builder calls of `add_points`, in order. -/
def addPoints (p0 p1 : PointReg) (n : ℕ) : Out PointReg :=
  ⟨[.mul n p0.x p1.x,
    .mul (n + 1) p0.y p1.y,
    .sub (n + 2) n (n + 1),
    .mul (n + 3) p0.x p1.y,
    .mul (n + 4) p0.y p1.x,
    .add (n + 5) (n + 3) (n + 4)],
   ⟨n + 2, n + 5⟩, n + 6⟩

theorem addPoints_sound {ρ : ℕ → QM31} {p0 p1 : PointReg} {n : ℕ}
    (h : AllHold ρ (addPoints p0 p1 n).ops) :
    ((addPoints p0 p1 n).res).val ρ = CPoint.add (p0.val ρ) (p1.val ρ) := by
  rw [show (addPoints p0 p1 n).ops =
    .mul n p0.x p1.x :: .mul (n + 1) p0.y p1.y :: .sub (n + 2) n (n + 1) ::
    .mul (n + 3) p0.x p1.y :: .mul (n + 4) p0.y p1.x ::
    [.add (n + 5) (n + 3) (n + 4)] from rfl,
    allHold_cons, allHold_cons, allHold_cons, allHold_cons, allHold_cons,
    allHold_cons] at h
  obtain ⟨h1, h2, h3, h4, h5, h6, -⟩ := h
  simp only [Holds] at h1 h2 h3 h4 h5 h6
  show CPoint.mk (ρ (n + 2)) (ρ (n + 5)) = _
  rw [h3, h6, h1, h2, h4, h5]
  rfl

/-! ### `double_point` (on-circle points) -/

/-- `doublePoint`: `xy = x·y`, `new_y = xy + xy`, then `doubleX x`. -/
def doublePoint (one : ℕ) (p : PointReg) (n : ℕ) : Out PointReg :=
  let dx := doubleX one p.x (n + 2)
  ⟨.mul n p.x p.y :: .add (n + 1) n n :: dx.ops, ⟨dx.res, n + 1⟩, dx.next⟩

/-- `double_point` computes the group-law doubling for points **on the
circle**: `x² + y² = 1` makes `2x² − 1 = x² − y²`. -/
theorem doublePoint_sound {ρ : ℕ → QM31} {one : ℕ} {p : PointReg} {n : ℕ}
    (hone : ρ one = 1)
    (hcircle : ρ p.x * ρ p.x + ρ p.y * ρ p.y = 1)
    (h : AllHold ρ (doublePoint one p n).ops) :
    ((doublePoint one p n).res).val ρ = CPoint.double (p.val ρ) := by
  rw [show (doublePoint one p n).ops =
    .mul n p.x p.y :: .add (n + 1) n n :: (doubleX one p.x (n + 2)).ops from rfl,
    allHold_cons, allHold_cons] at h
  obtain ⟨h1, h2, hdx⟩ := h
  simp only [Holds] at h1 h2
  have hx := doubleX_sound hone hdx
  show CPoint.mk (ρ (doubleX one p.x (n + 2)).res) (ρ (n + 1)) = _
  rw [hx, h2, h1]
  show CPoint.mk _ _ = CPoint.mk
    (ρ p.x * ρ p.x - ρ p.y * ρ p.y) (ρ p.x * ρ p.y + ρ p.y * ρ p.x)
  have hxeq : CPoint.doubleX (ρ p.x) = ρ p.x * ρ p.x - ρ p.y * ρ p.y := by
    show ρ p.x * ρ p.x + ρ p.x * ρ p.x - 1 = _
    linear_combination hcircle
  have hyeq : ρ p.x * ρ p.y + ρ p.x * ρ p.y = ρ p.x * ρ p.y + ρ p.y * ρ p.x := by
    ring
  rw [hxeq, hyeq]

/-! ### `coset_vanishing_poly` and `denom_inverse` -/

/-- `cosetVanishingPoly`: `doubleX` iterated `log_trace_size − 1` times. -/
def cosetVanishing (one x : ℕ) : Nat → Nat → Out ℕ
  | 0, n => ⟨[], x, n⟩
  | k + 1, n =>
    let prev := cosetVanishing one x k n
    let dx := doubleX one prev.res prev.next
    ⟨prev.ops ++ dx.ops, dx.res, dx.next⟩

theorem cosetVanishing_sound {ρ : ℕ → QM31} {one x : ℕ}
    (hone : ρ one = 1) :
    ∀ k n, AllHold ρ (cosetVanishing one x k n).ops →
      ρ (cosetVanishing one x k n).res = CPoint.doubleX^[k] (ρ x) := by
  intro k
  induction k with
  | zero => intro n _; simp [cosetVanishing]
  | succ k ih =>
    intro n h
    rw [show (cosetVanishing one x (k + 1) n).ops =
      (cosetVanishing one x k n).ops ++
        (doubleX one (cosetVanishing one x k n).res
          (cosetVanishing one x k n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hprev, hdx⟩ := h
    show ρ (doubleX one (cosetVanishing one x k n).res
      (cosetVanishing one x k n).next).res = _
    rw [doubleX_sound hone hdx, ih n hprev,
      Function.iterate_succ_apply' CPoint.doubleX k (ρ x)]

/-- `denomInverse`: the vanishing polynomial then an `inv` gate (a guessed
register `o` with the constraint `v · o = 1`). -/
def denomInverse (one x : ℕ) (logTraceSize : Nat) (n : ℕ) : Out ℕ :=
  let v := cosetVanishing one x (logTraceSize - 1) n
  ⟨v.ops ++ [.inv v.next v.res], v.next, v.next + 1⟩

/-- `denom_inverse` soundness: the output register holds a two-sided
inverse of the iterated `doubleX` of the input — in particular that value
is nonzero, and any other register satisfying the same product law equals
this one (`QM31.inv_unique`). -/
theorem denomInverse_sound {ρ : ℕ → QM31} {one x : ℕ} {logTraceSize n : ℕ}
    (hone : ρ one = 1)
    (h : AllHold ρ (denomInverse one x logTraceSize n).ops) :
    CPoint.doubleX^[logTraceSize - 1] (ρ x) *
      ρ (denomInverse one x logTraceSize n).res = 1 := by
  rw [show (denomInverse one x logTraceSize n).ops =
    (cosetVanishing one x (logTraceSize - 1) n).ops ++
      [.inv (cosetVanishing one x (logTraceSize - 1) n).next
        (cosetVanishing one x (logTraceSize - 1) n).res] from rfl,
    allHold_append, allHold_cons] at h
  obtain ⟨hv, hinv, -⟩ := h
  simp only [Holds] at hinv
  have := cosetVanishing_sound hone (logTraceSize - 1) n hv
  show CPoint.doubleX^[logTraceSize - 1] (ρ x) *
    ρ (cosetVanishing one x (logTraceSize - 1) n).next = 1
  rw [← this]
  simpa using hinv

end StwoVerifier.Gadgets
