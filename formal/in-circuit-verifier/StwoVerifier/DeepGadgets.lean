/-
**`compute_fri_input`'s per-point accumulation**
(`src/frontends/circuit/stark_verifier/oods.zig` `OodsPointAuxiliary`,
stwo-zig `4afa09dbf`): the line coefficients `d = im P.y`, `e = im P.x`,
`f = d·P.x − e·P.y`, and the response accumulators
`a = Σ α'ᵢ·im Vᵢ`, `v = Σ α'ᵢ·Vᵢ`, `b = d·v − a·P.y`, with the per-column
coefficients `cᵢ = d·α'ᵢ`.

The soundness lemmas state each register as the corresponding sum over
the response list — exactly the shapes `Deep.num_identity_batched` and
`Deep.den_identity` consume. The remaining `compute_fri_input` work is
the per-query quotient loop and the grouping walk.

`imMask` is the interned constant `(0,0,1,1)` (`ops.im`'s coefficient),
pinned by hypothesis like the builder's interned `one`.
-/
import StwoVerifier.Gates
import StwoVerifier.DeepIdentity

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- `OodsPointAuxiliary.init`: `d`, `e`, `f` from the point's wires. -/
def auxInit (imMask px py n : ℕ) : Out (ℕ × ℕ × ℕ) :=
  ⟨[.pmul n py imMask,
    .pmul (n + 1) px imMask,
    .mul (n + 2) n px,
    .mul (n + 3) (n + 1) py,
    .sub (n + 4) (n + 2) (n + 3)],
   (n, n + 1, n + 4), n + 5⟩

theorem auxInit_sound {ρ : ℕ → QM31} {imMask px py n : ℕ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1)
    (h : AllHold ρ (auxInit imMask px py n).ops) :
    ρ (auxInit imMask px py n).res.1 = Deep.imQ (ρ py) ∧
    ρ (auxInit imMask px py n).res.2.1 = Deep.imQ (ρ px) ∧
    ρ (auxInit imMask px py n).res.2.2
      = Deep.imQ (ρ py) * ρ px - Deep.imQ (ρ px) * ρ py := by
  rw [show (auxInit imMask px py n).ops =
    .pmul n py imMask :: .pmul (n + 1) px imMask :: .mul (n + 2) n px ::
    .mul (n + 3) (n + 1) py :: [.sub (n + 4) (n + 2) (n + 3)] from rfl,
    allHold_cons, allHold_cons, allHold_cons, allHold_cons, allHold_cons] at h
  obtain ⟨h1, h2, h3, h4, h5, -⟩ := h
  simp only [Holds] at h1 h2 h3 h4 h5
  have hd : ρ n = Deep.imQ (ρ py) := by
    rw [h1, hmask]; rfl
  have he : ρ (n + 1) = Deep.imQ (ρ px) := by
    rw [h2, hmask]; rfl
  refine ⟨hd, he, ?_⟩
  show ρ (n + 4) = _
  rw [h5, h3, h4, hd, he]

/-- One `accumulate` step: `c = d·α'`, `a += α'·im V`, `v += α'·V`. The
`c` register is recorded; the new `a`/`v` registers are returned. -/
def auxAccum (imMask d alphaPow value aReg vReg n : ℕ) : Out (ℕ × ℕ × ℕ) :=
  ⟨[.mul n d alphaPow,
    .pmul (n + 1) value imMask,
    .mul (n + 2) alphaPow (n + 1),
    .add (n + 3) aReg (n + 2),
    .mul (n + 4) alphaPow value,
    .add (n + 5) vReg (n + 4)],
   (n, n + 3, n + 5), n + 6⟩

theorem auxAccum_sound {ρ : ℕ → QM31} {imMask d alphaPow value aReg vReg n : ℕ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1)
    (h : AllHold ρ (auxAccum imMask d alphaPow value aReg vReg n).ops) :
    ρ (auxAccum imMask d alphaPow value aReg vReg n).res.1
      = ρ d * ρ alphaPow ∧
    ρ (auxAccum imMask d alphaPow value aReg vReg n).res.2.1
      = ρ aReg + ρ alphaPow * Deep.imQ (ρ value) ∧
    ρ (auxAccum imMask d alphaPow value aReg vReg n).res.2.2
      = ρ vReg + ρ alphaPow * ρ value := by
  rw [show (auxAccum imMask d alphaPow value aReg vReg n).ops =
    .mul n d alphaPow :: .pmul (n + 1) value imMask ::
    .mul (n + 2) alphaPow (n + 1) :: .add (n + 3) aReg (n + 2) ::
    .mul (n + 4) alphaPow value :: [.add (n + 5) vReg (n + 4)] from rfl,
    allHold_cons, allHold_cons, allHold_cons, allHold_cons, allHold_cons,
    allHold_cons] at h
  obtain ⟨h1, h2, h3, h4, h5, h6, -⟩ := h
  simp only [Holds] at h1 h2 h3 h4 h5 h6
  refine ⟨h1, ?_, ?_⟩
  · show ρ (n + 3) = _
    rw [h4, h3, h2, hmask]
    rfl
  · show ρ (n + 5) = _
    rw [h6, h5]

/-- `finalize`: `b = d·v − a·P.y`. -/
def auxFinalize (d vSum aSum py n : ℕ) : Out ℕ :=
  ⟨[.mul n d vSum, .mul (n + 1) aSum py, .sub (n + 2) n (n + 1)],
   n + 2, n + 3⟩

theorem auxFinalize_sound {ρ : ℕ → QM31} {d vSum aSum py n : ℕ}
    (h : AllHold ρ (auxFinalize d vSum aSum py n).ops) :
    ρ (auxFinalize d vSum aSum py n).res
      = ρ d * ρ vSum - ρ aSum * ρ py := by
  rw [show (auxFinalize d vSum aSum py n).ops =
    .mul n d vSum :: .mul (n + 1) aSum py :: [.sub (n + 2) n (n + 1)] from rfl,
    allHold_cons, allHold_cons, allHold_cons] at h
  obtain ⟨h1, h2, h3, -⟩ := h
  simp only [Holds] at h1 h2 h3
  show ρ (n + 2) = _
  rw [h3, h1, h2]

/-- The numerator subtraction chain: `num − Σ cᵢ·valᵢ`. -/
def subCoeffs : List (ℕ × ℕ) → ℕ → ℕ → Out ℕ
  | [], num, n => ⟨[], num, n⟩
  | (coeff, value) :: rest, num, n =>
    let tail := subCoeffs rest (n + 1) (n + 2)
    ⟨.mul n coeff value :: .sub (n + 1) num n :: tail.ops, tail.res, tail.next⟩

theorem subCoeffs_sound {ρ : ℕ → QM31} :
    ∀ (cvs : List (ℕ × ℕ)) (num n : ℕ),
      AllHold ρ (subCoeffs cvs num n).ops →
      ρ (subCoeffs cvs num n).res
        = ρ num - (cvs.map fun (c, v) => ρ c * ρ v).sum := by
  intro cvs
  induction cvs with
  | nil => intro num n _; simp [subCoeffs]
  | cons cv rest ih =>
    intro num n h
    obtain ⟨coeff, value⟩ := cv
    rw [show (subCoeffs ((coeff, value) :: rest) num n).ops =
      .mul n coeff value :: .sub (n + 1) num n ::
        (subCoeffs rest (n + 1) (n + 2)).ops from rfl,
      allHold_cons, allHold_cons] at h
    obtain ⟨h1, h2, hrest⟩ := h
    simp only [Holds] at h1 h2
    show ρ (subCoeffs rest (n + 1) (n + 2)).res = _
    rw [ih (n + 1) (n + 2) hrest, h2, h1]
    simp only [List.map_cons, List.sum_cons]
    ring

/-- The per-point per-query quotient:
`num = a·q_y + b − Σ cᵢ·valᵢ`, `den = d·q_x − (e·q_y + f)`,
`quot = num / den` (a `div` gate: a guess with `quot·den = num`). -/
def deepQuery (aSum b d e f qx qy : ℕ) (cvs : List (ℕ × ℕ)) (n : ℕ) : Out ℕ :=
  let num0ops : List Op := [.mul n aSum qy, .add (n + 1) n b]
  let num := subCoeffs cvs (n + 1) (n + 2)
  let m := num.next
  ⟨num0ops ++ num.ops ++
    [.mul m d qx, .mul (m + 1) e qy, .add (m + 2) (m + 1) f,
     .sub (m + 3) m (m + 2),
     .guess (m + 4), .mul (m + 5) (m + 4) (m + 3), .eq (m + 5) num.res],
   m + 4, m + 6⟩

/-- The quotient gate law: the output register satisfies
`quot · den = num` with the stated numerator and denominator values. -/
theorem deepQuery_sound {ρ : ℕ → QM31} {aSum b d e f qx qy : ℕ}
    {cvs : List (ℕ × ℕ)} {n : ℕ}
    (h : AllHold ρ (deepQuery aSum b d e f qx qy cvs n).ops) :
    ρ (deepQuery aSum b d e f qx qy cvs n).res *
        (ρ d * ρ qx - (ρ e * ρ qy + ρ f))
      = ρ aSum * ρ qy + ρ b - (cvs.map fun (c, v) => ρ c * ρ v).sum := by
  unfold deepQuery at h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hnum0, hnum⟩, h7⟩ := h
  rw [allHold_cons, allHold_cons, allHold_cons, allHold_cons, allHold_cons,
    allHold_cons, allHold_cons] at h7
  obtain ⟨hm1, hm2, hm3, hm4, hg, hm5, heq, -⟩ := h7
  rw [allHold_cons, allHold_cons] at hnum0
  obtain ⟨h1, h2, -⟩ := hnum0
  simp only [Holds] at h1 h2 hm1 hm2 hm3 hm4 hm5 heq
  have hnumval := subCoeffs_sound cvs (n + 1) (n + 2) hnum
  show ρ ((subCoeffs cvs (n + 1) (n + 2)).next + 4) * _ = _
  rw [← hm1, ← hm2, ← hm3, ← hm4, ← hm5, heq, hnumval, h2, h1]

/-- The alpha-power chain: starting from the interned `−2u`, multiply by
`α` once per further response. Returns the power registers in order. -/
def alphaChain (start alpha : ℕ) : Nat → ℕ → Out (List ℕ)
  | 0, n => ⟨[], [], n⟩
  | k + 1, n =>
    let rest := alphaChain n alpha k (n + 1)
    ⟨.mul n start alpha :: rest.ops, start :: rest.res, rest.next⟩

theorem alphaChain_sound {ρ : ℕ → QM31} {alpha : ℕ} :
    ∀ (k : Nat) (start n : ℕ),
      AllHold ρ (alphaChain start alpha k n).ops →
      ∀ i, i < k →
        ρ ((alphaChain start alpha k n).res.getD i 0)
          = ρ start * ρ alpha ^ i := by
  intro k
  induction k with
  | zero => intro start n _ i hi; omega
  | succ k ih =>
    intro start n h i hi
    rw [show (alphaChain start alpha (k + 1) n).ops =
      .mul n start alpha :: (alphaChain n alpha k (n + 1)).ops from rfl,
      allHold_cons] at h
    obtain ⟨h1, hrest⟩ := h
    simp only [Holds] at h1
    cases i with
    | zero =>
      show ρ start = ρ start * ρ alpha ^ 0
      rw [pow_zero, mul_one]
    | succ i =>
      show ρ ((alphaChain n alpha k (n + 1)).res.getD i 0) = _
      rw [ih n (n + 1) hrest i (by omega), h1, pow_succ]
      ring

/-- Wiring the alpha chain into the capstone: a response list whose
coefficient registers are the chain's outputs satisfies the capstone's
alpha hypothesis with `rsAlpha = [a0, a0·α, a0·α², …]`, where the
interned start register carries `−2u·a0`. -/
theorem chain_alphas {ρ : ℕ → QM31} {start alpha : ℕ} {a0 : QM31}
    {k m : ℕ} {rsReg : List (ℕ × ℕ)}
    (hstart : ρ start = (-2 : QM31) * Deep.uu * a0)
    (hfst : rsReg.map Prod.fst = (alphaChain start alpha k m).res)
    (hlen : rsReg.length = k)
    (hch : AllHold ρ (alphaChain start alpha k m).ops) :
    ∀ i, i < rsReg.length →
      ρ (rsReg.getD i (0, 0)).1
        = (-2 : QM31) * Deep.uu *
            (((List.range k).map fun j => a0 * ρ alpha ^ j).getD i 0) := by
  intro i hi
  have h1 : (rsReg.getD i (0, 0)).1
      = (alphaChain start alpha k m).res.getD i 0 := by
    rw [← hfst]
    conv_rhs => rw [List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_eq_getElem hi]
    conv_lhs => rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]
    rfl
  have h2 : ((List.range k).map fun j => a0 * ρ alpha ^ j).getD i 0
      = a0 * ρ alpha ^ i := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_eq_getElem (by simpa using (hlen ▸ hi))]
    simp
  rw [h1, alphaChain_sound k start m hch i (hlen ▸ hi), hstart, h2]
  ring

/-- The accumulate walk over one point's responses
(`(α'ᵢ, Vᵢ)` register pairs): threads the `a`/`v` registers and records
each response's coefficient register. -/
def auxAccumList (imMask d : ℕ) :
    List (ℕ × ℕ) → ℕ → ℕ → ℕ → Out (List ℕ × ℕ × ℕ)
  | [], aReg, vReg, n => ⟨[], ([], aReg, vReg), n⟩
  | (alphaPow, value) :: rest, aReg, vReg, n =>
    let st := auxAccum imMask d alphaPow value aReg vReg n
    let r := auxAccumList imMask d rest st.res.2.1 st.res.2.2 st.next
    ⟨st.ops ++ r.ops, (st.res.1 :: r.res.1, r.res.2), r.next⟩

/-- Walk soundness: the final `a`/`v` registers hold the initial values
plus the response sums, and coefficient `i` holds `d·α'ᵢ`. -/
theorem auxAccumList_sound {ρ : ℕ → QM31} {imMask d : ℕ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) :
    ∀ (rs : List (ℕ × ℕ)) (aReg vReg n : ℕ),
      AllHold ρ (auxAccumList imMask d rs aReg vReg n).ops →
      (auxAccumList imMask d rs aReg vReg n).res.1.length = rs.length ∧
      (∀ i, i < rs.length →
        ρ ((auxAccumList imMask d rs aReg vReg n).res.1.getD i 0)
          = ρ d * ρ ((rs.getD i (0, 0)).1)) ∧
      ρ (auxAccumList imMask d rs aReg vReg n).res.2.1
        = ρ aReg + (rs.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum ∧
      ρ (auxAccumList imMask d rs aReg vReg n).res.2.2
        = ρ vReg + (rs.map fun (a, v) => ρ a * ρ v).sum := by
  intro rs
  induction rs with
  | nil =>
    intro aReg vReg n _
    refine ⟨rfl, fun i hi => by simp at hi, ?_, ?_⟩
    · show ρ aReg = ρ aReg + ([] : List QM31).sum
      simp
    · show ρ vReg = ρ vReg + ([] : List QM31).sum
      simp
  | cons r rest ih =>
    intro aReg vReg n h
    obtain ⟨alphaPow, value⟩ := r
    rw [show (auxAccumList imMask d ((alphaPow, value) :: rest) aReg vReg n).ops =
      (auxAccum imMask d alphaPow value aReg vReg n).ops ++
        (auxAccumList imMask d rest
          (auxAccum imMask d alphaPow value aReg vReg n).res.2.1
          (auxAccum imMask d alphaPow value aReg vReg n).res.2.2
          (auxAccum imMask d alphaPow value aReg vReg n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hstep, hrest⟩ := h
    obtain ⟨hc, ha, hv⟩ := auxAccum_sound hmask hstep
    obtain ⟨ihlen, ihc, iha, ihv⟩ := ih _ _ _ hrest
    refine ⟨?_, ?_, ?_, ?_⟩
    · show _ + 1 = _ + 1
      rw [ihlen]
    · intro i hi
      cases i with
      | zero => exact hc
      | succ i =>
        show ρ ((auxAccumList imMask d rest _ _ _).res.1.getD i 0) = _
        exact ihc i (by simpa using hi)
    · show ρ (auxAccumList imMask d rest _ _ _).res.2.1 = _
      rw [iha, ha]
      simp only [List.map_cons, List.sum_cons]
      ring
    · show ρ (auxAccumList imMask d rest _ _ _).res.2.2 = _
      rw [ihv, hv]
      simp only [List.map_cons, List.sum_cons]
      ring

/-- Pointwise-equal maps over a list have equal sums (getD form). -/
theorem map_sum_congr_getD {α : Type} [Inhabited α] (l : List α)
    (f g : α → QM31)
    (h : ∀ i, i < l.length → f (l.getD i default) = g (l.getD i default)) :
    (l.map f).sum = (l.map g).sum := by
  induction l with
  | nil => rfl
  | cons a rest ih =>
    simp only [List.map_cons, List.sum_cons]
    have h0 := h 0 (by simp)
    simp only [List.getD_cons_zero] at h0
    rw [h0]
    congr 1
    refine ih fun i hi => ?_
    have := h (i + 1) (by simpa using hi)
    simpa using this

instance : Inhabited (ℕ × ℕ) := ⟨(0, 0)⟩

/-- A mapped sum as a range-indexed sum (getD form). -/
theorem map_sum_eq_range {α : Type} [Inhabited α] (l : List α) (f : α → QM31) :
    (l.map f).sum = ∑ i ∈ Finset.range l.length, f (l.getD i default) := by
  induction l with
  | nil => simp
  | cons a rest ih =>
    simp only [List.map_cons, List.sum_cons, List.length_cons]
    rw [Finset.sum_range_succ' (fun i => f ((a :: rest).getD i default)) rest.length]
    simp only [List.getD_cons_succ, List.getD_cons_zero]
    rw [ih]
    ring

/-- A zipped mapped sum as a range-indexed sum over the common length. -/
theorem zip_map_sum_eq_range {α β : Type} [Inhabited α] [Inhabited β]
    (A : List α) (B : List β) (f : α → β → QM31) (hlen : A.length = B.length) :
    ((A.zip B).map fun (a, b) => f a b).sum
      = ∑ i ∈ Finset.range A.length,
          f (A.getD i default) (B.getD i default) := by
  rw [map_sum_eq_range, List.length_zip, hlen, Nat.min_self]
  refine Finset.sum_congr rfl fun i hi => ?_
  have hiB := Finset.mem_range.mp hi
  have hiA : i < A.length := by omega
  have hz : (A.zip B).getD i default = (A.getD i default, B.getD i default) := by
    rw [List.getD_eq_getElem?_getD,
      show (A.zip B)[i]? = some (A[i], B[i]) from
        List.getElem?_zip_eq_some.2 ⟨List.getElem?_eq_getElem hiA,
          List.getElem?_eq_getElem hiB⟩]
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiA,
      List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiB]
    rfl
  rw [hz]

theorem range_map_sum (n : ℕ) (f : ℕ → QM31) :
    ((List.range n).map f).sum = ∑ i ∈ Finset.range n, f i := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [List.range_succ, List.map_append, List.sum_append,
      Finset.sum_range_succ, ih]
    simp

/-- One group, one query: `d/e/f` from the point, the accumulate walk over
the responses (from the zero register), `b`, and the query quotient. -/
def processGroupQuery (imMask zero px py : ℕ) (rsReg : List (ℕ × ℕ))
    (valRegs : List ℕ) (qx qy : ℕ) (n : ℕ) : Out ℕ :=
  let ini := auxInit imMask px py n
  let walk := auxAccumList imMask ini.res.1 rsReg zero zero ini.next
  let fin := auxFinalize ini.res.1 walk.res.2.2 walk.res.2.1 py walk.next
  let q := deepQuery walk.res.2.1 fin.res ini.res.1 ini.res.2.1 ini.res.2.2
    qx qy (walk.res.1.zip valRegs) fin.next
  ⟨ini.ops ++ walk.ops ++ fin.ops ++ q.ops, q.res, q.next⟩

set_option maxHeartbeats 1600000 in
/-- **The per-group quotient is the spec's batch term.** With the point,
query and response registers pinned to their spec values (`α'ᵢ = −2u·αᵢ`
as the alpha chain provides), and the spec denominator nonzero, the
`div`-gate output is the spec batch numerator times the inverse CM31
denominator — the exact summand of `Quotients.friAnswers`' row value. -/
theorem processGroupQuery_sound {ρ : ℕ → QM31}
    {imMask zero px py qx qy n : ℕ}
    {rsReg : List (ℕ × ℕ)} {valRegs : List ℕ}
    {P : PointQ} {xq yq : F} {rsAlpha : List QM31} {vals : List F}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) (hzero : ρ zero = 0)
    (hpx : ρ px = P.x) (hpy : ρ py = P.y)
    (hqx : ρ qx = QM31.fromBase xq) (hqy : ρ qy = QM31.fromBase yq)
    (hlenV : valRegs.length = rsReg.length)
    (halpha : ∀ i, i < rsReg.length →
      ρ (rsReg.getD i (0, 0)).1 = (-2 : QM31) * Deep.uu * rsAlpha.getD i 0)
    (hvals : ∀ i, i < rsReg.length →
      ρ (valRegs.getD i 0) = QM31.fromBase (vals.getD i 0))
    (h : AllHold ρ (processGroupQuery imMask zero px py rsReg valRegs qx qy n).ops)
    (hden : Quotients.denominator P ⟨xq, yq⟩ ≠ 0) :
    ρ (processGroupQuery imMask zero px py rsReg valRegs qx qy n).res
      = ((((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r =>
          r.1 * (P.y.complexConjugate - P.y) * r.2.2
            - (r.1 * (r.2.1.complexConjugate - r.2.1) * QM31.fromBase yq
              + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
                - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum).mulCM31
          (Quotients.denominator P ⟨xq, yq⟩)⁻¹ := by
  unfold processGroupQuery at h
  rw [allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨hini, hwalk⟩, hfin⟩, hq⟩ := h
  obtain ⟨hd, he, hf⟩ := auxInit_sound hmask hini
  obtain ⟨hwlen, hwc, hwa, hwv⟩ := auxAccumList_sound hmask rsReg zero zero _ hwalk
  have hb := auxFinalize_sound hfin
  have hql := deepQuery_sound hq
  -- The denominator register value is `−u·embed(den)`.
  have hdenreg : ρ (auxInit imMask px py n).res.1 * ρ qx
      - (ρ (auxInit imMask px py n).res.2.1 * ρ qy + ρ (auxInit imMask px py n).res.2.2)
      = -Deep.uu * Deep.embed (Quotients.denominator P ⟨xq, yq⟩) := by
    rw [hd, he, hf, hpx, hpy, hqx, hqy]
    exact Deep.den_identity P xq yq
  -- The three register sums, instantiated to spec data over the triple list.
  have hsumA : (rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum
      = (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r => ((-2 : QM31) * Deep.uu * r.1) * Deep.imQ r.2.1).sum := by
    rw [map_sum_eq_range, List.map_map, range_map_sum]
    refine Finset.sum_congr rfl fun i hi => ?_
    have hi' := Finset.mem_range.mp hi
    show ρ (rsReg.getD i (0, 0)).1 * Deep.imQ (ρ (rsReg.getD i (0, 0)).2)
      = ((-2 : QM31) * Deep.uu * rsAlpha.getD i 0) * Deep.imQ (ρ (rsReg.getD i (0, 0)).2)
    rw [halpha i hi']
  have hsumV : (rsReg.map fun (a, v) => ρ a * ρ v).sum
      = (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r => ((-2 : QM31) * Deep.uu * r.1) * r.2.1).sum := by
    rw [map_sum_eq_range, List.map_map, range_map_sum]
    refine Finset.sum_congr rfl fun i hi => ?_
    have hi' := Finset.mem_range.mp hi
    show ρ (rsReg.getD i (0, 0)).1 * ρ (rsReg.getD i (0, 0)).2
      = ((-2 : QM31) * Deep.uu * rsAlpha.getD i 0) * ρ (rsReg.getD i (0, 0)).2
    rw [halpha i hi']
  have hsumC : (((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1.zip valRegs).map
        fun (c, v) => ρ c * ρ v).sum
      = (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r => Deep.imQ P.y * ((-2 : QM31) * Deep.uu * r.1) * r.2.2).sum := by
    rw [map_sum_eq_range, List.length_zip, hwlen, hlenV, Nat.min_self,
      List.map_map, range_map_sum]
    refine Finset.sum_congr rfl fun i hi => ?_
    have hi' := Finset.mem_range.mp hi
    have hiA : i < (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1.length := by rw [hwlen]; exact hi'
    have hiB : i < valRegs.length := by rw [hlenV]; exact hi'
    have hz : ((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1.zip valRegs).getD i default
        = ((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1.getD i 0, valRegs.getD i 0) := by
      rw [List.getD_eq_getElem?_getD,
        show ((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1.zip valRegs)[i]?
            = some ((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1[i], valRegs[i]) from
          List.getElem?_zip_eq_some.2 ⟨List.getElem?_eq_getElem hiA,
            List.getElem?_eq_getElem hiB⟩]
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiA,
        List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiB]
      rfl
    rw [hz]
    show ρ ((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1.getD i 0) * ρ (valRegs.getD i 0)
      = Deep.imQ P.y * ((-2 : QM31) * Deep.uu * rsAlpha.getD i 0)
          * QM31.fromBase (vals.getD i 0)
    rw [hwc i hi', hvals i hi', halpha i hi', hd, hpy]
  -- Assemble the numerator: the batched identity.
  have hnum : ρ (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.2.1 * ρ qy
      + ρ (auxFinalize (auxInit imMask px py n).res.1 (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.2.2 (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.2.1 py (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).next).res
      - (((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero (auxInit imMask px py n).next).res.1.zip valRegs).map
          fun (c, v) => ρ c * ρ v).sum
      = -Deep.uu * (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r =>
          r.1 * (P.y.complexConjugate - P.y) * r.2.2
            - (r.1 * (r.2.1.complexConjugate - r.2.1) * QM31.fromBase yq
              + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
                - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum := by
    rw [hb, hwa, hwv, hzero, zero_add, zero_add, hsumA, hsumV, hsumC,
      hd, hpy, hqy]
    exact Deep.num_identity_batched P (QM31.fromBase yq) ((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0)))
  -- The div gate pins the quotient.
  have hdenne : (-Deep.uu * Deep.embed (Quotients.denominator P ⟨xq, yq⟩)) ≠ 0 :=
    mul_ne_zero (neg_ne_zero.mpr Deep.uu_ne_zero) (Deep.embed_ne_zero hden)
  have hquot := hql
  rw [hdenreg] at hquot
  rw [hnum] at hquot
  have hfinal : ρ (processGroupQuery imMask zero px py rsReg valRegs qx qy n).res
      = (-Deep.uu * (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r =>
          r.1 * (P.y.complexConjugate - P.y) * r.2.2
            - (r.1 * (r.2.1.complexConjugate - r.2.1) * QM31.fromBase yq
              + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
                - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum)
        / (-Deep.uu * Deep.embed (Quotients.denominator P ⟨xq, yq⟩)) :=
    (eq_div_iff hdenne).mpr hquot
  rw [hfinal, mul_div_mul_left _ _ (neg_ne_zero.mpr Deep.uu_ne_zero),
    div_eq_mul_inv, ← Deep.embed_inv, ← Deep.mulCM31_eq]

/-- The denominator guard: multiply all denominator registers into one
product register, then a single `inv` gate. -/
def prodChain (first : ℕ) : List ℕ → ℕ → Out ℕ
  | [], n => ⟨[], first, n⟩
  | r :: rest, n =>
    let t := prodChain n rest (n + 1)
    ⟨.mul n first r :: t.ops, t.res, t.next⟩

theorem prodChain_sound {ρ : ℕ → QM31} :
    ∀ (rs : List ℕ) (first n : ℕ),
      AllHold ρ (prodChain first rs n).ops →
      ρ (prodChain first rs n).res = ρ first * (rs.map ρ).prod := by
  intro rs
  induction rs with
  | nil => intro first n _; simp [prodChain]
  | cons r rest ih =>
    intro first n h
    rw [show (prodChain first (r :: rest) n).ops
      = .mul n first r :: (prodChain n rest (n + 1)).ops from rfl,
      allHold_cons] at h
    obtain ⟨h1, hrest⟩ := h
    simp only [Holds] at h1
    show ρ (prodChain n rest (n + 1)).res = _
    rw [ih n (n + 1) hrest, h1]
    simp only [List.map_cons, List.prod_cons]
    ring

/-- An `inv` gate's input is nonzero. -/
theorem inv_gate_ne_zero {ρ : ℕ → QM31} {o x : ℕ}
    (h : Holds ρ (.inv o x)) : ρ x ≠ 0 := by
  simp only [Holds] at h
  exact left_ne_zero_of_mul_eq_one h

/-- The guard's force: with the `inv` gate on the chained product, every
chained register is nonzero. -/
theorem prodChain_all_ne_zero {ρ : ℕ → QM31} {rs : List ℕ}
    {first n o : ℕ}
    (hchain : AllHold ρ (prodChain first rs n).ops)
    (hinv : Holds ρ (.inv o (prodChain first rs n).res)) :
    ρ first ≠ 0 ∧ ∀ r ∈ rs, ρ r ≠ 0 := by
  have hne : ρ (prodChain first rs n).res ≠ 0 := inv_gate_ne_zero hinv
  rw [prodChain_sound rs first n hchain] at hne
  refine ⟨left_ne_zero_of_mul hne, fun r hr hzero => ?_⟩
  apply right_ne_zero_of_mul hne
  exact List.prod_eq_zero (List.mem_map.mpr ⟨r, hr, hzero⟩)

/-- Discharging the capstone's denominator hypothesis: a denominator
register carrying `−u·embed(den)` (as `den_identity` provides) that the
guard proves nonzero forces the spec denominator nonzero. -/
theorem den_nonzero_of_reg {ρ : ℕ → QM31} {reg : ℕ} {den : CM31}
    (hreg : ρ reg = -Deep.uu * Deep.embed den) (hne : ρ reg ≠ 0) :
    den ≠ 0 := by
  rintro rfl
  rw [hreg, Deep.embed_zero, mul_zero] at hne
  exact hne rfl

end StwoVerifier.Gadgets
