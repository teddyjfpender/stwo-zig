/-
**Scope A / deliverable 4, first piece: the FRI fold**
(`src/frontends/circuit/stark_verifier/fri.zig` `fold_coset`, stwo-zig
`4afa09dbf`), at the pinned profile's `fold_step = 1`.

One fold is `(even + odd) + α·((even − odd)·t)` with the twiddle `t` a
gate-proven inverse (`simd.inv`: a guess constrained by `t·x = 1`). With
the QM31 field structure, the constraint pins `t = x⁻¹`, and the folded
value is exactly the spec's `Fri.foldLinePair even odd α x` — the same
formula the differentially-validated verifier runs for both the
circle-to-line layer (`x = p.y`) and every inner line layer.
-/
import StwoVerifier.Gates
import StwoVerifier.Fri
import StwoVerifier.FieldTower
import StwoVerifier.DeepIdentity
import StwoVerifier.SpecLemmas
import StwoVerifier.SimdGadgets

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- The base-field embedding as a ring homomorphism. -/
def baseHom : F →+* QM31 where
  toFun := QM31.fromBase
  map_one' := rfl
  map_mul' a b := by
    unfold QM31.fromBase CM31.fromBase
    refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
      simp [QM31.mul_c0, QM31.mul_c1] <;> ext <;> simp
  map_zero' := rfl
  map_add' a b := by
    unfold QM31.fromBase CM31.fromBase
    ext <;> simp

theorem fromBase_inv (x : F) : QM31.fromBase x⁻¹ = (QM31.fromBase x)⁻¹ :=
  map_inv₀ baseHom x

theorem fromBase_ne_zero {x : F} (hx : x ≠ 0) : QM31.fromBase x ≠ 0 := by
  intro h
  exact hx (by
    have := congrArg (fun q : QM31 => q.c0.a) h
    simpa [QM31.fromBase, CM31.fromBase] using this)

/-- One `fold_coset` round at fold step 1:
`g = even + odd`, `h = (even − odd)·t`, `out = g + α·h`. -/
def foldCoset1 (even odd twiddle alpha n : ℕ) : Out ℕ :=
  ⟨[.add n even odd,
    .sub (n + 1) even odd,
    .mul (n + 2) (n + 1) twiddle,
    .mul (n + 3) alpha (n + 2),
    .add (n + 4) n (n + 3)],
   n + 4, n + 5⟩

/-- **Fold soundness.** If the gates hold and the twiddle is gate-proven
to invert the base-field point coordinate `x` (the `t·x = 1` constraint
`simd.inv` emits), the output register holds the spec's
`Fri.foldLinePair even odd α x`. -/
theorem foldCoset1_sound {ρ : ℕ → QM31} {even odd twiddle alpha n : ℕ} {x : F}
    (htw : ρ twiddle * QM31.fromBase x = 1)
    (h : AllHold ρ (foldCoset1 even odd twiddle alpha n).ops) :
    Fri.foldLinePair (ρ even) (ρ odd) (ρ alpha) x
      = .ok (ρ (foldCoset1 even odd twiddle alpha n).res) := by
  rw [show (foldCoset1 even odd twiddle alpha n).ops =
    .add n even odd :: .sub (n + 1) even odd :: .mul (n + 2) (n + 1) twiddle ::
    .mul (n + 3) alpha (n + 2) :: [.add (n + 4) n (n + 3)] from rfl,
    allHold_cons, allHold_cons, allHold_cons, allHold_cons, allHold_cons] at h
  obtain ⟨h1, h2, h3, h4, h5, -⟩ := h
  simp only [Holds] at h1 h2 h3 h4 h5
  have hx : x ≠ 0 := by
    intro h0
    rw [h0] at htw
    simp [show QM31.fromBase 0 = 0 from rfl] at htw
  have htinv : ρ twiddle = (QM31.fromBase x)⁻¹ :=
    eq_inv_of_mul_eq_one_left htw
  unfold Fri.foldLinePair
  rw [if_neg hx]
  show Except.ok _ = Except.ok _
  congr 1
  show _ = ρ (n + 4)
  rw [h5, h1, h4, h3, h2, htinv]
  rw [show (ρ even - ρ odd).mulM31 x⁻¹
    = (ρ even - ρ odd) * QM31.fromBase x⁻¹ from by
      unfold QM31.mulM31 QM31.fromBase
      refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
        simp [QM31.mul_c0, QM31.mul_c1, CM31.mulM31, CM31.fromBase] <;>
        ext <;> simp [CM31.mul_a, CM31.mul_b]]
  rw [fromBase_inv]
  try ring

/-- The decommit's closing battery: one `eq` gate pinning each query's
fully folded value to the last-layer constant register. -/
def lastLayerEqs (coeff : ℕ) (vals : List ℕ) (n : ℕ) : Out Unit :=
  ⟨vals.map fun v => .eq v coeff, (), n⟩

theorem lastLayerEqs_sound {ρ : ℕ → QM31} {coeff n : ℕ} {vals : List ℕ}
    (h : AllHold ρ (lastLayerEqs coeff vals n).ops) :
    ∀ v ∈ vals, ρ v = ρ coeff := by
  intro v hv
  have hop : Op.eq v coeff ∈ (lastLayerEqs coeff vals n).ops :=
    List.mem_map.mpr ⟨v, hv, rfl⟩
  exact h _ hop

/-- **The battery is the spec's last-layer check.** At the pinned
last-layer degree bound 0, with the constant register pinned to the
committed polynomial's single coefficient, the `eq` gates holding is
exactly `Fri.lastLayerCheck` succeeding on the register values. -/
theorem lastLayerEqs_spec {ρ : ℕ → QM31} {coeff n : ℕ} {vals : List ℕ}
    (c : Fri.Committed) (c0 : QM31) (hpoly : c.lastLayerPoly = [c0])
    (hc : ρ coeff = c0) (positions : List Nat)
    (hlen : positions.length = vals.length)
    (h : AllHold ρ (lastLayerEqs coeff vals n).ops) :
    Fri.lastLayerCheck c positions (vals.map ρ) = .ok () := by
  rw [SpecLemmas.lastLayerCheck_const c c0 hpoly positions _
    (by rw [List.length_map, hlen])]
  intro e he
  obtain ⟨v, hv, rfl⟩ := List.mem_map.mp he
  rw [lastLayerEqs_sound h v hv, hc]

/-- The `c`-th unit lane vector (`builder/simd.zig` `unit_vecs`). -/
def unitVec : Nat → QM31
  | 0 => QM31.fromM31s 1 0 0 0
  | 1 => QM31.fromM31s 0 1 0 0
  | 2 => QM31.fromM31s 0 0 1 0
  | _ => QM31.fromM31s 0 0 0 1

theorem unitVec_ne_zero (c : Nat) (hc : c < 4) : unitVec c ≠ 0 := by
  interval_cases c <;> intro h
  · have h1 : (1 : F) = 0 := congrArg CM31.a (congrArg QM31.c0 h)
    exact absurd h1 (by norm_num)
  · have h1 : (1 : F) = 0 := congrArg CM31.b (congrArg QM31.c0 h)
    exact absurd h1 (by norm_num)
  · have h1 : (1 : F) = 0 := congrArg CM31.a (congrArg QM31.c1 h)
    exact absurd h1 (by norm_num)
  · have h1 : (1 : F) = 0 := congrArg CM31.b (congrArg QM31.c1 h)
    exact absurd h1 (by norm_num)

/-- `pmul` with a unit vector picks out one lane:
`x .* e_c = fromBase (coord x c) · e_c`. -/
theorem pmul_unitVec (x : QM31) (c : Nat) (hc : c < 4) :
    Gates.pmulQ x (unitVec c) = QM31.fromBase (coord x c) * unitVec c := by
  interval_cases c <;>
    (refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
      simp [Gates.pmulQ, unitVec, coord, QM31.fromBase, CM31.fromBase,
        QM31.fromM31s, QM31.mul_c0, QM31.mul_c1, QM31.R] <;>
      ext <;> simp [CM31.mul_a, CM31.mul_b] <;> ring)

/-- `unpack_idx` (`builder/simd.zig`): one lane of a SIMD wire as a
scalar register — pointwise-multiply by the unit vector, then divide the
lane back into base position by the interned inverse. -/
noncomputable def unpackIdx (w : ℕ) (c : Nat) (n : ℕ) : Out ℕ :=
  if c = 0 then
    ⟨[.const n (unitVec 0), .pmul (n + 1) w n], n + 1, n + 2⟩
  else
    ⟨[.const n (unitVec c), .pmul (n + 1) w n,
      .const (n + 2) (unitVec c)⁻¹, .mul (n + 3) (n + 1) (n + 2)],
     n + 3, n + 4⟩

/-- The unpacked register holds the base-field lift of the lane. -/
theorem unpackIdx_sound {ρ : ℕ → QM31} {w c n : ℕ} (hc : c < 4)
    (h : AllHold ρ (unpackIdx w c n).ops) :
    ρ (unpackIdx w c n).res = QM31.fromBase (coord (ρ w) c) := by
  by_cases h0 : c = 0
  · subst h0
    rw [show (unpackIdx w 0 n).ops
      = .const n (unitVec 0) :: [.pmul (n + 1) w n] from rfl,
      allHold_cons, allHold_cons] at h
    obtain ⟨h1, h2, -⟩ := h
    simp only [Holds] at h1 h2
    show ρ (n + 1) = _
    rw [h2, h1, pmul_unitVec _ 0 (by omega),
      show unitVec 0 = 1 from rfl, mul_one]
  · rw [show (unpackIdx w c n).ops
      = .const n (unitVec c) :: .pmul (n + 1) w n ::
        .const (n + 2) (unitVec c)⁻¹ :: [.mul (n + 3) (n + 1) (n + 2)] from by
          simp [unpackIdx, h0],
      allHold_cons, allHold_cons, allHold_cons, allHold_cons] at h
    obtain ⟨h1, h2, h3, h4, -⟩ := h
    simp only [Holds] at h1 h2 h3 h4
    have hres : (unpackIdx w c n).res = n + 3 := by simp [unpackIdx, h0]
    rw [hres, h4, h2, h3, h1, pmul_unitVec _ c hc, mul_assoc,
      mul_inv_cancel₀ (unitVec_ne_zero c hc), mul_one]

end StwoVerifier.Gadgets
