/-
**The query-selection gadget**
(`src/frontends/circuit/stark_verifier/select_queries.zig` and the SIMD
point arithmetic of `stark_verifier/circle.zig`, stwo-zig `4afa09dbf`).

`select_queries` extracts 31 bits from each drawn lane, then builds the
evaluation-domain point of each query: starting from the generator of the
subgroup of size `2^(log+1)` (the canonic-coset shift), it conditionally
adds the size-`2^i` subgroup generator for each index bit `i ≥ 1`, and
negates `y` when bit 0 is set. `selectPoint_sound` proves the built lane
point is `toPoint` of exactly that index arithmetic; combined with
`extractBits31_sound` the bits are the canonical digits of the drawn
value, so the point is a function of the *canonical* query index.
-/
import StwoVerifier.SimdGadgets
import StwoVerifier.CircleGroup

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- Lane-wise `add` (`Simd::add`). -/
def simdAdd (a b : SimdReg) (n : ℕ) : Out SimdReg :=
  let w := lanewise2 .add a.data b.data n
  ⟨w.ops, ⟨w.res, a.len⟩, w.next⟩

theorem simdAdd_covers {a b : SimdReg} {n : ℕ} (ha : a.Covers)
    (hb : a.len ≤ 4 * b.data.length) : (simdAdd a b n).res.Covers := by
  show a.len ≤ 4 * (lanewise2 Op.add a.data b.data n).res.length
  rw [lanewise2_length]
  have h1 : a.len ≤ 4 * a.data.length := ha
  omega

theorem simdAdd_lane {ρ : ℕ → QM31} {a b : SimdReg} {n : ℕ}
    (ha : a.Covers) (hb : a.len ≤ 4 * b.data.length)
    (h : AllHold ρ (simdAdd a b n).ops) (j : ℕ) (hj : j < a.len) :
    SimdReg.lane ρ (simdAdd a b n).res j
      = SimdReg.lane ρ a j + SimdReg.lane ρ b j := by
  have hc4 : j % 4 < 4 := Nat.mod_lt _ (by norm_num)
  have hk : j / 4 < (lanewise2 Op.add a.data b.data n).res.length := by
    rw [lanewise2_length]
    unfold SimdReg.Covers at ha
    omega
  have hwire : ρ ((simdAdd a b n).res.data.getD (j / 4) 0)
      = ρ (a.data.getD (j / 4) 0) + ρ (b.data.getD (j / 4) 0) :=
    lanewise2_sound (· + ·) .add (fun _ _ _ _ h => h) a.data b.data n h (j / 4) hk
  unfold SimdReg.lane
  rw [hwire, coord_add _ _ _ hc4]

/-! Result-shape helpers: the emitted wire counts, stated so `omega` can
consume them. -/

theorem simdSub_data_len (a b : SimdReg) (n : ℕ) :
    (simdSub a b n).res.data.length = min a.data.length b.data.length :=
  lanewise2_length .sub a.data b.data n

theorem simdMul_data_len (a b : SimdReg) (n : ℕ) :
    (simdMul a b n).res.data.length = min a.data.length b.data.length :=
  lanewise2_length .pmul a.data b.data n

theorem simdAdd_data_len (a b : SimdReg) (n : ℕ) :
    (simdAdd a b n).res.data.length = min a.data.length b.data.length :=
  lanewise2_length .add a.data b.data n

/-- `simd.select`: `if_zero + selector ⊙ (if_one − if_zero)`. -/
def simdSelect (sel ifZero ifOne : SimdReg) (n : ℕ) : Out SimdReg :=
  let diff := simdSub ifOne ifZero n
  let scaled := simdMul sel diff.res diff.next
  let out := simdAdd ifZero scaled.res scaled.next
  ⟨diff.ops ++ scaled.ops ++ out.ops, out.res, out.next⟩

/-- Shape bundle for `simdSelect`: everything the lane lemma needs. -/
structure SelShape (sel ifZero ifOne : SimdReg) : Prop where
  covSel : sel.Covers
  covZero : ifZero.Covers
  covOne : ifOne.Covers
  lenZero : ifZero.len = sel.len
  lenOne : ifOne.len = sel.len
  dataZero : sel.len ≤ 4 * ifZero.data.length
  dataOne : sel.len ≤ 4 * ifOne.data.length

theorem simdSelect_covers {sel ifZero ifOne : SimdReg} {n : ℕ}
    (hs : SelShape sel ifZero ifOne) : (simdSelect sel ifZero ifOne n).res.Covers := by
  obtain ⟨hcs, hcz, hco, hlz, hlo, hdz, hdo⟩ := hs
  show ifZero.len ≤ 4 * (simdAdd ifZero (simdMul sel (simdSub ifOne ifZero n).res
    (simdSub ifOne ifZero n).next).res (simdMul sel (simdSub ifOne ifZero n).res
    (simdSub ifOne ifZero n).next).next).res.data.length
  rw [simdAdd_data_len, simdMul_data_len, simdSub_data_len]
  have h1 : sel.len ≤ 4 * sel.data.length := hcs
  omega

theorem simdSelect_lane {ρ : ℕ → QM31} {sel ifZero ifOne : SimdReg} {n : ℕ}
    (hs : SelShape sel ifZero ifOne)
    (h : AllHold ρ (simdSelect sel ifZero ifOne n).ops) (j : ℕ) (hj : j < sel.len) :
    SimdReg.lane ρ (simdSelect sel ifZero ifOne n).res j
      = SimdReg.lane ρ ifZero j + SimdReg.lane ρ sel j *
          (SimdReg.lane ρ ifOne j - SimdReg.lane ρ ifZero j) := by
  obtain ⟨hcs, hcz, hco, hlz, hlo, hdz, hdo⟩ := hs
  unfold simdSelect at h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hdiff, hscaled⟩, hadd⟩ := h
  have h1 : sel.len ≤ 4 * sel.data.length := hcs
  have hdlane := simdSub_lane hco (by rw [hlo]; exact hdz) hdiff j (by omega)
  have hdiffdata : sel.len ≤ 4 * (simdSub ifOne ifZero n).res.data.length := by
    rw [simdSub_data_len]; omega
  have hslane := simdMul_lane hcs hdiffdata hscaled j hj
  have hscaleddata : ifZero.len ≤ 4 * (simdMul sel (simdSub ifOne ifZero n).res
      (simdSub ifOne ifZero n).next).res.data.length := by
    rw [simdMul_data_len, simdSub_data_len]; omega
  have halane := simdAdd_lane hcz hscaleddata hadd j (by omega)
  refine halane.trans ?_
  rw [hslane, hdlane]

/-- A bit-valued selector picks one branch. -/
theorem simdSelect_lane_bit {ρ : ℕ → QM31} {sel ifZero ifOne : SimdReg} {n : ℕ}
    (hs : SelShape sel ifZero ifOne)
    (h : AllHold ρ (simdSelect sel ifZero ifOne n).ops) (j : ℕ) (hj : j < sel.len)
    (hbit : SimdReg.lane ρ sel j = 0 ∨ SimdReg.lane ρ sel j = 1) :
    SimdReg.lane ρ (simdSelect sel ifZero ifOne n).res j
      = if SimdReg.lane ρ sel j = 0 then SimdReg.lane ρ ifZero j
        else SimdReg.lane ρ ifOne j := by
  rw [simdSelect_lane hs h j hj]
  rcases hbit with hb | hb
  · rw [hb, if_pos rfl]; ring
  · rw [hb, if_neg (by norm_num)]; ring

/-! ### SIMD circle points -/

/-- A SIMD point: one lane point per query. -/
structure PointSimd where
  x : SimdReg
  y : SimdReg

/-- The lane point. -/
def PointSimd.lane (ρ : ℕ → QM31) (p : PointSimd) (j : ℕ) : PointF :=
  ⟨SimdReg.lane ρ p.x j, SimdReg.lane ρ p.y j⟩

/-- Well-shaped: both halves have `len` lanes, covered, with equal wire
counts `count`. -/
structure PointSimd.Shape (p : PointSimd) (len count : ℕ) : Prop where
  lenX : p.x.len = len
  lenY : p.y.len = len
  dataX : p.x.data.length = count
  dataY : p.y.data.length = count
  hcount : len ≤ 4 * count

/-- `generator_point_simd`: both coordinates of the size-`2^log` subgroup
generator, splat as constants. -/
def genPointSimd (logSize count len n : ℕ) : Out PointSimd :=
  let gp := (subgroupGen logSize : PIdx).toPoint
  let xs := constSplat gp.x count len n
  let ys := constSplat gp.y count len xs.next
  ⟨xs.ops ++ ys.ops, ⟨xs.res, ys.res⟩, ys.next⟩

theorem genPointSimd_shape {logSize count len n : ℕ} (h : len ≤ 4 * count) :
    (genPointSimd logSize count len n).res.Shape len count :=
  ⟨rfl, rfl, by simp [genPointSimd, constSplat], by simp [genPointSimd, constSplat], h⟩

theorem genPointSimd_lane {ρ : ℕ → QM31} {logSize count len n : ℕ}
    (h : AllHold ρ (genPointSimd logSize count len n).ops) (j : ℕ)
    (hj : j / 4 < count) :
    PointSimd.lane ρ (genPointSimd logSize count len n).res j
      = (subgroupGen logSize : PIdx).toPoint := by
  unfold genPointSimd at h
  rw [allHold_append] at h
  obtain ⟨hx, hy⟩ := h
  exact CPoint.ext' (constSplat_lane hx j hj) (constSplat_lane hy j hj)

/-- `add_points_simd`: the four products, then the two coordinates. -/
def addPointsSimd (p0 p1 : PointSimd) (n : ℕ) : Out PointSimd :=
  let x0x1 := simdMul p0.x p1.x n
  let x0y1 := simdMul p0.x p1.y x0x1.next
  let y0x1 := simdMul p0.y p1.x x0y1.next
  let y0y1 := simdMul p0.y p1.y y0x1.next
  let x := simdSub x0x1.res y0y1.res y0y1.next
  let y := simdAdd x0y1.res y0x1.res x.next
  ⟨x0x1.ops ++ x0y1.ops ++ y0x1.ops ++ y0y1.ops ++ x.ops ++ y.ops,
   ⟨x.res, y.res⟩, y.next⟩

theorem addPointsSimd_shape {p0 p1 : PointSimd} {len count n : ℕ}
    (h0 : p0.Shape len count) (h1 : p1.Shape len count) :
    (addPointsSimd p0 p1 n).res.Shape len count := by
  obtain ⟨l0x, l0y, d0x, d0y, hc⟩ := h0
  obtain ⟨l1x, l1y, d1x, d1y, -⟩ := h1
  refine ⟨l0x, l0x, ?_, ?_, hc⟩
  · show (simdSub (simdMul p0.x p1.x n).res _ _).res.data.length = count
    rw [simdSub_data_len, simdMul_data_len, simdMul_data_len]
    omega
  · show (simdAdd (simdMul p0.x p1.y _).res _ _).res.data.length = count
    rw [simdAdd_data_len, simdMul_data_len, simdMul_data_len]
    omega

theorem addPointsSimd_lane {ρ : ℕ → QM31} {p0 p1 : PointSimd} {len count n : ℕ}
    (h0 : p0.Shape len count) (h1 : p1.Shape len count)
    (h : AllHold ρ (addPointsSimd p0 p1 n).ops) (j : ℕ) (hj : j < len) :
    PointSimd.lane ρ (addPointsSimd p0 p1 n).res j
      = (PointSimd.lane ρ p0 j).add (PointSimd.lane ρ p1 j) := by
  obtain ⟨l0x, l0y, d0x, d0y, hc⟩ := h0
  obtain ⟨l1x, l1y, d1x, d1y, -⟩ := h1
  unfold addPointsSimd at h
  rw [allHold_append, allHold_append, allHold_append, allHold_append,
    allHold_append] at h
  obtain ⟨⟨⟨⟨⟨hxx, hxy⟩, hyx⟩, hyy⟩, hx⟩, hy⟩ := h
  have c0x : p0.x.Covers := by show p0.x.len ≤ 4 * p0.x.data.length; omega
  have c0y : p0.y.Covers := by show p0.y.len ≤ 4 * p0.y.data.length; omega
  have lxx := simdMul_lane c0x (by rw [l0x]; omega) hxx j (by omega)
  have lxy := simdMul_lane c0x (by rw [l0x]; omega) hxy j (by omega)
  have lyx := simdMul_lane c0y (by rw [l0y]; omega) hyx j (by omega)
  have lyy := simdMul_lane c0y (by rw [l0y]; omega) hyy j (by omega)
  have cxx : (simdMul p0.x p1.x n).res.Covers := by
    show p0.x.len ≤ 4 * (simdMul p0.x p1.x n).res.data.length
    rw [simdMul_data_len]; omega
  have cxy : (simdMul p0.x p1.y (simdMul p0.x p1.x n).next).res.Covers := by
    show p0.x.len ≤ 4 * (simdMul p0.x p1.y (simdMul p0.x p1.x n).next).res.data.length
    rw [simdMul_data_len]; omega
  have lx := simdSub_lane cxx (by
      show p0.x.len ≤ 4 * (simdMul p0.y p1.y _).res.data.length
      rw [simdMul_data_len]; omega) hx j (by
      show j < p0.x.len; omega)
  have ly := simdAdd_lane cxy (by
      show p0.x.len ≤ 4 * (simdMul p0.y p1.x _).res.data.length
      rw [simdMul_data_len]; omega) hy j (by
      show j < p0.x.len; omega)
  refine CPoint.ext' ?_ ?_
  · exact lx.trans (by rw [lxx, lyy]; rfl)
  · exact ly.trans (by rw [lxy, lyx]; rfl)

/-- `sub_points_simd`: the four products, then `x₀x₁ + y₀y₁` and
`y₀x₁ − x₀y₁` — addition with the conjugate. -/
def subPointsSimd (p0 p1 : PointSimd) (n : ℕ) : Out PointSimd :=
  let x0x1 := simdMul p0.x p1.x n
  let x0y1 := simdMul p0.x p1.y x0x1.next
  let y0x1 := simdMul p0.y p1.x x0y1.next
  let y0y1 := simdMul p0.y p1.y y0x1.next
  let x := simdAdd x0x1.res y0y1.res y0y1.next
  let y := simdSub y0x1.res x0y1.res x.next
  ⟨x0x1.ops ++ x0y1.ops ++ y0x1.ops ++ y0y1.ops ++ x.ops ++ y.ops,
   ⟨x.res, y.res⟩, y.next⟩

theorem subPointsSimd_shape {p0 p1 : PointSimd} {len count n : ℕ}
    (h0 : p0.Shape len count) (h1 : p1.Shape len count) :
    (subPointsSimd p0 p1 n).res.Shape len count := by
  obtain ⟨l0x, l0y, d0x, d0y, hc⟩ := h0
  obtain ⟨l1x, l1y, d1x, d1y, -⟩ := h1
  refine ⟨l0x, l0y, ?_, ?_, hc⟩
  · show (simdAdd (simdMul p0.x p1.x n).res _ _).res.data.length = count
    rw [simdAdd_data_len, simdMul_data_len, simdMul_data_len]
    omega
  · show (simdSub (simdMul p0.y p1.x _).res _ _).res.data.length = count
    rw [simdSub_data_len, simdMul_data_len, simdMul_data_len]
    omega

theorem subPointsSimd_lane {ρ : ℕ → QM31} {p0 p1 : PointSimd} {len count n : ℕ}
    (h0 : p0.Shape len count) (h1 : p1.Shape len count)
    (h : AllHold ρ (subPointsSimd p0 p1 n).ops) (j : ℕ) (hj : j < len) :
    PointSimd.lane ρ (subPointsSimd p0 p1 n).res j
      = (PointSimd.lane ρ p0 j).add (PointSimd.lane ρ p1 j).conjugate := by
  obtain ⟨l0x, l0y, d0x, d0y, hc⟩ := h0
  obtain ⟨l1x, l1y, d1x, d1y, -⟩ := h1
  unfold subPointsSimd at h
  rw [allHold_append, allHold_append, allHold_append, allHold_append,
    allHold_append] at h
  obtain ⟨⟨⟨⟨⟨hxx, hxy⟩, hyx⟩, hyy⟩, hx⟩, hy⟩ := h
  have c0x : p0.x.Covers := by show p0.x.len ≤ 4 * p0.x.data.length; omega
  have c0y : p0.y.Covers := by show p0.y.len ≤ 4 * p0.y.data.length; omega
  have lxx := simdMul_lane c0x (by rw [l0x]; omega) hxx j (by omega)
  have lxy := simdMul_lane c0x (by rw [l0x]; omega) hxy j (by omega)
  have lyx := simdMul_lane c0y (by rw [l0y]; omega) hyx j (by omega)
  have lyy := simdMul_lane c0y (by rw [l0y]; omega) hyy j (by omega)
  have cxx : (simdMul p0.x p1.x n).res.Covers := by
    show p0.x.len ≤ 4 * (simdMul p0.x p1.x n).res.data.length
    rw [simdMul_data_len]; omega
  have cyx : (simdMul p0.y p1.x (simdMul p0.x p1.y
      (simdMul p0.x p1.x n).next).next).res.Covers := by
    show p0.y.len ≤ 4 * _
    rw [simdMul_data_len]; omega
  have lx := simdAdd_lane cxx (by
      show p0.x.len ≤ 4 * (simdMul p0.y p1.y _).res.data.length
      rw [simdMul_data_len]; omega) hx j (by
      show j < p0.x.len; omega)
  have ly := simdSub_lane cyx (by
      show p0.y.len ≤ 4 * (simdMul p0.x p1.y _).res.data.length
      rw [simdMul_data_len]; omega) hy j (by
      show j < p0.y.len; omega)
  refine CPoint.ext' ?_ ?_
  · refine lx.trans ?_
    rw [lxx, lyy]
    unfold CPoint.add CPoint.conjugate PointSimd.lane
    simp only
    ring
  · refine ly.trans ?_
    rw [lyx, lxy]
    unfold CPoint.add CPoint.conjugate PointSimd.lane
    simp only
    ring

/-! ### The query-point loop

`select_queries` starts from the size-`2^(log+1)` subgroup generator and,
for each index bit `i ∈ [1, log)`, conditionally adds the size-`2^i`
subgroup generator. Lane-wise this is
`point + Σ bitᵢ · gen(i)` in the circle group, i.e. the generator power of
the accumulated index. -/

/-- A bit vector's shape. -/
structure BitShape (b : SimdReg) (len count : ℕ) : Prop where
  lenEq : b.len = len
  dataEq : b.data.length = count

/-- One loop iteration: generator `i`, conditional add. -/
def loopStep (bit : SimdReg) (i count len : ℕ) (point : PointSimd) (n : ℕ) :
    Out PointSimd :=
  let gen := genPointSimd i count len n
  let pib := addPointsSimd point gen.res gen.next
  let sx := simdSelect bit point.x pib.res.x pib.next
  let sy := simdSelect bit point.y pib.res.y sx.next
  ⟨gen.ops ++ pib.ops ++ sx.ops ++ sy.ops, ⟨sx.res, sy.res⟩, sy.next⟩

theorem simdSelect_data_len (sel ifZero ifOne : SimdReg) (n : ℕ) :
    (simdSelect sel ifZero ifOne n).res.data.length
      = min ifZero.data.length (min sel.data.length
          (min ifOne.data.length ifZero.data.length)) := by
  show (simdAdd ifZero (simdMul sel (simdSub ifOne ifZero n).res
    (simdSub ifOne ifZero n).next).res _).res.data.length = _
  rw [simdAdd_data_len, simdMul_data_len, simdSub_data_len]

theorem simdSelect_len (sel ifZero ifOne : SimdReg) (n : ℕ) :
    (simdSelect sel ifZero ifOne n).res.len = ifZero.len := rfl

theorem loopStep_shape {bit : SimdReg} {i count len n : ℕ} {point : PointSimd}
    (hb : BitShape bit len count) (hp : point.Shape len count) :
    (loopStep bit i count len point n).res.Shape len count := by
  obtain ⟨hblen, hbdata⟩ := hb
  have hps := hp
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  have hpib : (addPointsSimd point (genPointSimd i count len n).res
      (genPointSimd i count len n).next).res.Shape len count :=
    addPointsSimd_shape hps (genPointSimd_shape (by omega))
  obtain ⟨plx, ply, pdx, pdy, -⟩ := hpib
  refine ⟨by show point.x.len = len; exact hlx,
    by show point.y.len = len; exact hly, ?_, ?_, hc⟩
  · rw [show (loopStep bit i count len point n).res.x
      = (simdSelect bit point.x (addPointsSimd point
          (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x
          (addPointsSimd point (genPointSimd i count len n).res
            (genPointSimd i count len n).next).next).res from rfl,
      simdSelect_data_len]
    omega
  · rw [show (loopStep bit i count len point n).res.y
      = (simdSelect bit point.y (addPointsSimd point
          (genPointSimd i count len n).res (genPointSimd i count len n).next).res.y
          (simdSelect bit point.x (addPointsSimd point
            (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x
            (addPointsSimd point (genPointSimd i count len n).res
              (genPointSimd i count len n).next).next).next).res from rfl,
      simdSelect_data_len]
    omega

/-- One iteration's lane: add the generator exactly when the bit is set. -/
theorem loopStep_lane {ρ : ℕ → QM31} {bit : SimdReg} {i count len n : ℕ}
    {point : PointSimd}
    (hb : BitShape bit len count) (hp : point.Shape len count)
    (h : AllHold ρ (loopStep bit i count len point n).ops)
    (j : ℕ) (hj : j < len)
    (hbit : SimdReg.lane ρ bit j = 0 ∨ SimdReg.lane ρ bit j = 1) :
    PointSimd.lane ρ (loopStep bit i count len point n).res j
      = if SimdReg.lane ρ bit j = 0 then PointSimd.lane ρ point j
        else (PointSimd.lane ρ point j).add ((subgroupGen i : PIdx).toPoint) := by
  obtain ⟨hblen, hbdata⟩ := hb
  have hps := hp
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  unfold loopStep at h
  rw [allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨hgen, hpib⟩, hsx⟩, hsy⟩ := h
  have hgshape : (genPointSimd i count len n).res.Shape len count :=
    genPointSimd_shape (by omega)
  have hpibshape : (addPointsSimd point (genPointSimd i count len n).res
      (genPointSimd i count len n).next).res.Shape len count :=
    addPointsSimd_shape hps hgshape
  obtain ⟨plx, ply, pdx, pdy, -⟩ := hpibshape
  have hj4 : j / 4 < count := by omega
  have hgenlane := genPointSimd_lane hgen j hj4
  have hpiblane := addPointsSimd_lane hps hgshape hpib j hj
  have hselx : SelShape bit point.x (addPointsSimd point
      (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x :=
    ⟨by show bit.len ≤ 4 * bit.data.length; omega,
     by show point.x.len ≤ 4 * point.x.data.length; omega,
     by show _ ≤ 4 * _; omega,
     by omega, by omega, by omega, by omega⟩
  have hsely : SelShape bit point.y (addPointsSimd point
      (genPointSimd i count len n).res (genPointSimd i count len n).next).res.y :=
    ⟨by show bit.len ≤ 4 * bit.data.length; omega,
     by show point.y.len ≤ 4 * point.y.data.length; omega,
     by show _ ≤ 4 * _; omega,
     by omega, by omega, by omega, by omega⟩
  have hlx' := simdSelect_lane_bit hselx hsx j (by omega) hbit
  have hly' := simdSelect_lane_bit hsely hsy j (by omega) hbit
  have hxeq : SimdReg.lane ρ (loopStep bit i count len point n).res.x j
      = _ := hlx'
  have hyeq : SimdReg.lane ρ (loopStep bit i count len point n).res.y j
      = _ := hly'
  rcases hbit with hb0 | hb1
  · rw [if_pos hb0]
    refine CPoint.ext' ?_ ?_
    · show SimdReg.lane ρ (loopStep bit i count len point n).res.x j = _
      rw [hxeq, if_pos hb0]
      rfl
    · show SimdReg.lane ρ (loopStep bit i count len point n).res.y j = _
      rw [hyeq, if_pos hb0]
      rfl
  · rw [if_neg (by rw [hb1]; norm_num)]
    have hxne : ¬ SimdReg.lane ρ bit j = 0 := by rw [hb1]; norm_num
    have hpibx : (PointSimd.lane ρ (addPointsSimd point (genPointSimd i count len n).res
        (genPointSimd i count len n).next).res j).x
        = ((PointSimd.lane ρ point j).add ((subgroupGen i : PIdx).toPoint)).x := by
      rw [hpiblane, hgenlane]
    have hpiby : (PointSimd.lane ρ (addPointsSimd point (genPointSimd i count len n).res
        (genPointSimd i count len n).next).res j).y
        = ((PointSimd.lane ρ point j).add ((subgroupGen i : PIdx).toPoint)).y := by
      rw [hpiblane, hgenlane]
    refine CPoint.ext' ?_ ?_
    · show SimdReg.lane ρ (loopStep bit i count len point n).res.x j = _
      rw [hxeq, if_neg hxne]
      exact hpibx
    · show SimdReg.lane ρ (loopStep bit i count len point n).res.y j = _
      rw [hyeq, if_neg hxne]
      exact hpiby

/-- `toPoint` of a small index needs no reduction. -/
theorem toPoint_subgroupGen {i : ℕ} (hi : 1 ≤ i) (hi31 : i ≤ 31) :
    (subgroupGen i : PIdx).toPoint = M31_CIRCLE_GEN.smul (subgroupGen i) := by
  unfold PIdx.toPoint PIdx.reduce subgroupGen circleOrder
  congr 1
  apply Nat.mod_eq_of_lt
  have : (31 : ℕ) - i < 31 := by omega
  exact Nat.pow_lt_pow_right (by norm_num) this

/-- The lane bit as a natural. -/
def bitNat (ρ : ℕ → QM31) (b : SimdReg) (j : ℕ) : ℕ :=
  if SimdReg.lane ρ b j = 0 then 0 else 1

/-- The whole conditional-add loop over a list of bit vectors. -/
def buildLoop (count len : ℕ) : List SimdReg → ℕ → PointSimd → ℕ → Out PointSimd
  | [], _, point, n => ⟨[], point, n⟩
  | bit :: rest, startIdx, point, n =>
    let st := loopStep bit startIdx count len point n
    let r := buildLoop count len rest (startIdx + 1) st.res st.next
    ⟨st.ops ++ r.ops, r.res, r.next⟩

/-- Loop soundness: the output lane point is the input lane point plus the
generator powers of the set bits. -/
theorem buildLoop_lane {ρ : ℕ → QM31} {count len : ℕ} :
    ∀ (bits : List SimdReg) (startIdx : ℕ) (point : PointSimd) (n : ℕ),
      1 ≤ startIdx → startIdx + bits.length ≤ 31 →
      (∀ b ∈ bits, BitShape b len count) →
      point.Shape len count →
      AllHold ρ (buildLoop count len bits startIdx point n).ops →
      (buildLoop count len bits startIdx point n).res.Shape len count ∧
      ∀ j, j < len →
        (∀ b ∈ bits, SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1) →
        PointSimd.lane ρ (buildLoop count len bits startIdx point n).res j
          = (PointSimd.lane ρ point j).add
              (M31_CIRCLE_GEN.smul (∑ t ∈ Finset.range bits.length,
                bitNat ρ (bits.getD t dummySimd) j * subgroupGen (startIdx + t))) := by
  intro bits
  induction bits with
  | nil =>
    intro startIdx point n _ _ _ hp _
    refine ⟨hp, fun j hj _ => ?_⟩
    show PointSimd.lane ρ point j = _
    simp only [List.length_nil, Finset.range_zero, Finset.sum_empty, ← CPoint.mul_def]
    rw [show CPoint.smul M31_CIRCLE_GEN 0 = (1 : PointF) from by
      rw [CPoint.smul_eq_pow, pow_zero], mul_one]
  | cons bit rest ih =>
    intro startIdx point n hstart hbound hshapes hp h
    rw [show (buildLoop count len (bit :: rest) startIdx point n).ops
      = (loopStep bit startIdx count len point n).ops ++
        (buildLoop count len rest (startIdx + 1)
          (loopStep bit startIdx count len point n).res
          (loopStep bit startIdx count len point n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hstep, hrest⟩ := h
    have hbshape := hshapes bit List.mem_cons_self
    have hstepshape : (loopStep bit startIdx count len point n).res.Shape len count :=
      loopStep_shape hbshape hp
    obtain ⟨ihshape, ihlane⟩ := ih (startIdx + 1)
      (loopStep bit startIdx count len point n).res
      (loopStep bit startIdx count len point n).next
      (by omega) (by simp at hbound ⊢; omega)
      (fun b hb => hshapes b (List.mem_cons_of_mem _ hb)) hstepshape hrest
    refine ⟨ihshape, fun j hj hbits => ?_⟩
    have hbit := hbits bit List.mem_cons_self
    have hsteplane := loopStep_lane hbshape hp hstep j hj hbit
    rw [show (buildLoop count len (bit :: rest) startIdx point n).res
      = (buildLoop count len rest (startIdx + 1)
          (loopStep bit startIdx count len point n).res
          (loopStep bit startIdx count len point n).next).res from rfl,
      ihlane j hj (fun b hb => hbits b (List.mem_cons_of_mem _ hb)), hsteplane]
    -- Fold the conditional add into the sum.
    have hsum : ∑ t ∈ Finset.range (bit :: rest).length,
        bitNat ρ ((bit :: rest).getD t dummySimd) j * subgroupGen (startIdx + t)
        = bitNat ρ bit j * subgroupGen startIdx +
          ∑ t ∈ Finset.range rest.length,
            bitNat ρ (rest.getD t dummySimd) j * subgroupGen (startIdx + 1 + t) := by
      rw [List.length_cons, Finset.sum_range_succ']
      simp only [List.getD_cons_succ, List.getD_cons_zero, Nat.add_zero]
      rw [Nat.add_comm]
      congr 1
      exact Finset.sum_congr rfl fun t _ => by
        congr 2
        omega
    rw [hsum, CPoint.smul_add_idx]
    simp only [← CPoint.mul_def]
    rcases hbit with hb0 | hb1
    · rw [if_pos hb0,
        show bitNat ρ bit j = 0 from by unfold bitNat; rw [if_pos hb0],
        Nat.zero_mul,
        show CPoint.smul M31_CIRCLE_GEN 0 = (1 : PointF) from by
          rw [CPoint.smul_eq_pow, pow_zero], one_mul]
    · have hne : ¬ SimdReg.lane ρ bit j = 0 := by rw [hb1]; norm_num
      rw [if_neg hne,
        show bitNat ρ bit j = 1 from by unfold bitNat; rw [if_neg hne],
        Nat.one_mul, toPoint_subgroupGen hstart (by
          simp only [List.length_cons] at hbound; omega),
        mul_assoc]

/-! ### `Simd::inv` -/

/-- `simd.inv`: guessed inverse wires, `res ⊙ a`, and `Simd::eq` against a
constant-splat one. Proves every lane of `a` nonzero. -/
def simdInv (zero : ℕ) (a : SimdReg) (n : ℕ) : Out SimdReg :=
  let g := guessWires a.data.length a.len n
  let prod := simdMul g.res a g.next
  let ones := constSplat 1 a.data.length a.len prod.next
  let eqo := simdEq zero prod.res ones.res ones.next
  ⟨g.ops ++ prod.ops ++ ones.ops ++ eqo.ops, g.res, eqo.next⟩

theorem simdInv_covers {zero : ℕ} {a : SimdReg} {n : ℕ} (ha : a.Covers) :
    (simdInv zero a n).res.Covers :=
  guessWires_covers ha

/-- Lane soundness: the guessed wire inverts the lane. -/
theorem simdInv_lane {ρ : ℕ → QM31} {zero : ℕ} {a : SimdReg} {n : ℕ}
    (hzero : ρ zero = 0) (ha : a.Covers)
    (h : AllHold ρ (simdInv zero a n).ops) (j : ℕ) (hj : j < a.len) :
    SimdReg.lane ρ (simdInv zero a n).res j * SimdReg.lane ρ a j = 1 := by
  unfold simdInv at h
  rw [allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨_, hprod⟩, hones⟩, heqo⟩ := h
  have hg : (guessWires a.data.length a.len n).res.Covers := guessWires_covers ha
  have hgdata : (guessWires a.data.length a.len n).res.data.length
      = a.data.length := by simp [guessWires]
  have hpcov : (simdMul (guessWires a.data.length a.len n).res a
      (guessWires a.data.length a.len n).next).res.Covers := by
    show a.len ≤ 4 * _
    rw [simdMul_data_len, hgdata]
    have h4 : a.len ≤ 4 * a.data.length := ha
    omega
  have hj4 : j / 4 < a.data.length := by
    have h4 : a.len ≤ 4 * a.data.length := ha
    omega
  have honeslane : SimdReg.lane ρ (constSplat 1 a.data.length a.len
      (simdMul (guessWires a.data.length a.len n).res a
        (guessWires a.data.length a.len n).next).next).res j = 1 :=
    constSplat_lane hones j hj4
  have honesdata : (constSplat 1 a.data.length a.len
      (simdMul (guessWires a.data.length a.len n).res a
        (guessWires a.data.length a.len n).next).next).res.data.length
      = a.data.length := by simp [constSplat]
  have heqlane := simdEq_sound hzero (by exact hpcov) (by
    show a.len ≤ 4 * _
    rw [honesdata]
    exact ha) heqo j hj
  have hmlane := simdMul_lane hg (by
    show (guessWires a.data.length a.len n).res.len ≤ 4 * a.data.length
    exact ha) hprod j hj
  rw [hmlane] at heqlane
  show SimdReg.lane ρ (guessWires a.data.length a.len n).res j
    * SimdReg.lane ρ a j = 1
  exact heqlane.trans honeslane

/-! ### Shapes of the extraction outputs -/

theorem rounds_shapes {zero invTwo : ℕ} :
    ∀ (k : Nat) (value : SimdReg) (n : ℕ),
      (∀ b ∈ (rounds zero invTwo value k n).res.1,
        b.len = value.len ∧ b.data.length = value.data.length) ∧
      (rounds zero invTwo value k n).res.2.len = value.len ∧
      (rounds zero invTwo value k n).res.2.data.length = value.data.length := by
  intro k
  induction k with
  | zero =>
    intro value n
    exact ⟨by simp [rounds], rfl, rfl⟩
  | succ k ih =>
    intro value n
    set lsb := guessLsb zero value n with hlsbdef
    set sub := simdSub value lsb.res lsb.next with hsubdef
    set half := simdScalarMul sub.res invTwo sub.next with hhalfdef
    have hlsbdata : lsb.res.data.length = value.data.length := by
      simp [hlsbdef, guessLsb, guessWires]
    have hsubdata : sub.res.data.length = value.data.length := by
      show (lanewise2 Op.sub value.data lsb.res.data lsb.next).res.length = _
      rw [lanewise2_length, hlsbdata]
      omega
    have hhalfdata : half.res.data.length = value.data.length := by
      show (lanewise2 (fun o x y => Op.mul o x y) sub.res.data
        (sub.res.data.map fun _ => invTwo) sub.next).res.length = _
      rw [lanewise2_length, List.length_map, hsubdata]
      omega
    obtain ⟨ihbits, ihfinlen, ihfindata⟩ := ih half.res half.next
    refine ⟨?_, ?_, ?_⟩
    · intro b hb
      rw [show (rounds zero invTwo value (k + 1) n).res.1
        = lsb.res :: (rounds zero invTwo half.res k half.next).res.1 from rfl] at hb
      rcases List.mem_cons.mp hb with rfl | hb
      · exact ⟨rfl, hlsbdata⟩
      · obtain ⟨hl, hd⟩ := ihbits b hb
        exact ⟨hl, by rw [hd, hhalfdata]⟩
    · show (rounds zero invTwo half.res k half.next).res.2.len = value.len
      rw [ihfinlen]
      rfl
    · show (rounds zero invTwo half.res k half.next).res.2.data.length = _
      rw [ihfindata, hhalfdata]

theorem rounds_len {zero invTwo : ℕ} :
    ∀ (k : Nat) (value : SimdReg) (n : ℕ),
      (rounds zero invTwo value k n).res.1.length = k := by
  intro k
  induction k with
  | zero => intro value n; rfl
  | succ k ih =>
    intro value n
    show (_ :: _).length = k + 1
    rw [List.length_cons, ih]

/-! ### The full query-point gadget -/

/-- `select_queries`' point construction for one `log_domain_size = L`:
extract 31 bits, build the point from bits `1..L−1` starting at the
size-`2^(L+1)` generator, then negate `y` when bit 0 is set. -/
def selectQueriesPoint (zero : ℕ) (input : SimdReg) (L : ℕ) (n : ℕ) :
    Out (List SimdReg × PointSimd) :=
  let count := input.data.length
  let len := input.len
  let eb := extractBits31 zero input n
  let point0 := genPointSimd (L + 1) count len eb.next
  let loopBits := (eb.res.drop 1).take (L - 1)
  let lp := buildLoop count len loopBits 1 point0.res point0.next
  let zs := constSplat 0 count len lp.next
  let ny := simdSub zs.res lp.res.y zs.next
  let ysel := simdSelect (eb.res.getD 0 dummySimd) lp.res.y ny.res ny.next
  ⟨eb.ops ++ point0.ops ++ lp.ops ++ zs.ops ++ ny.ops ++ ysel.ops,
   (eb.res, ⟨lp.res.x, ysel.res⟩), ysel.next⟩

/-- The accumulated index of the built point: the canonic shift plus the
set bits' subgroup generators. -/
def queryIndex (bN : ℕ → ℕ) (L : ℕ) : ℕ :=
  subgroupGen (L + 1) + ∑ t ∈ Finset.range (L - 1), bN (t + 1) * subgroupGen (t + 1)

set_option maxHeartbeats 1600000 in
/-- **Soundness of the query-point gadget.** If every emitted gate holds,
then per lane: the 31 extracted bits are the binary digits of the drawn
value's canonical representative, and the built point is the generator
power of `queryIndex` of those bits — conjugated exactly when bit 0 is
set. (`2 ≤ L ≤ 30` as in every deployed configuration.) -/
theorem selectQueriesPoint_sound {ρ : ℕ → QM31} {zero : ℕ} {input : SimdReg}
    {L n : ℕ} (hL2 : 2 ≤ L) (hL30 : L ≤ 30)
    (hzero : ρ zero = 0) (hcov : input.Covers)
    (h : AllHold ρ (selectQueriesPoint zero input L n).ops)
    (j : ℕ) (hj : j < input.len) :
    BitDecomp.natOf (fun i => SimdReg.lane ρ
        ((selectQueriesPoint zero input L n).res.1.getD i dummySimd) j) 31
      = (SimdReg.lane ρ input j).val ∧
    PointSimd.lane ρ (selectQueriesPoint zero input L n).res.2 j
      = (let base := M31_CIRCLE_GEN.smul (queryIndex
          (fun i => bitNat ρ ((selectQueriesPoint zero input L n).res.1.getD i dummySimd) j) L)
         if SimdReg.lane ρ ((selectQueriesPoint zero input L n).res.1.getD 0 dummySimd) j = 0
         then base else base.conjugate) := by
  unfold selectQueriesPoint at h ⊢
  rw [allHold_append, allHold_append, allHold_append, allHold_append,
    allHold_append] at h
  obtain ⟨⟨⟨⟨⟨heb, hpoint0⟩, hlp⟩, hzs⟩, hny⟩, hysel⟩ := h
  set count := input.data.length with hcountdef
  set len := input.len with hlendef
  set eb := extractBits31 zero input n with hebdef
  obtain ⟨hbits31, hnat⟩ := extractBits31_sound hzero hcov heb j hj
  -- Shapes of the bit vectors.
  have hrshapes := rounds_shapes (zero := zero) (invTwo := n) 30 input (n + 1)
  obtain ⟨hbitsShapes, hfinlen, hfindata⟩ := hrshapes
  have hebshape : ∀ b ∈ eb.res, b.len = len ∧ b.data.length = count := by
    intro b hb
    rw [show eb.res = (rounds zero n input 30 (n + 1)).res.1
      ++ [(rounds zero n input 30 (n + 1)).res.2] from rfl] at hb
    rcases List.mem_append.mp hb with hb | hb
    · exact hbitsShapes b hb
    · rcases List.mem_singleton.mp hb with rfl
      exact ⟨hfinlen, hfindata⟩
  have heblen : eb.res.length = 31 := by
    rw [show eb.res = (rounds zero n input 30 (n + 1)).res.1
      ++ [(rounds zero n input 30 (n + 1)).res.2] from rfl,
      List.length_append, rounds_len, List.length_singleton]
  refine ⟨hnat, ?_⟩
  -- The loop bits are `eb.res[1 .. L-1]`.
  set point0 := genPointSimd (L + 1) count len eb.next with hp0def
  set loopBits := (eb.res.drop 1).take (L - 1) with hlbdef
  set lp := buildLoop count len loopBits 1 point0.res point0.next with hlpdef
  have hlblen : loopBits.length = L - 1 := by
    rw [hlbdef, List.length_take, List.length_drop, heblen]
    omega
  have hloopget : ∀ t, t < L - 1 →
      loopBits.getD t dummySimd = eb.res.getD (t + 1) dummySimd := by
    intro t ht
    rw [hlbdef, List.getD_eq_getElem?_getD, List.getElem?_take, if_pos ht,
      List.getElem?_drop, List.getD_eq_getElem?_getD,
      show 1 + t = t + 1 by omega]
  have hcnt : len ≤ 4 * count := hcov
  have hp0shape : point0.res.Shape len count := genPointSimd_shape hcnt
  have hlbshapes : ∀ b ∈ loopBits, BitShape b len count := by
    intro b hb
    have hb' : b ∈ eb.res := by
      rw [hlbdef] at hb
      exact List.mem_of_mem_drop (List.mem_of_mem_take hb)
    obtain ⟨hl, hd⟩ := hebshape b hb'
    exact ⟨hl, hd⟩
  have hlbbits : ∀ b ∈ loopBits, SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1 := by
    intro b hb
    obtain ⟨t, ht, rfl⟩ := List.getElem_of_mem hb
    have hbg : loopBits[t] = loopBits.getD t dummySimd := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem ht]
      rfl
    rw [hbg, hloopget t (by omega)]
    exact hbits31 (t + 1) (by rw [hlblen] at ht; omega)
  obtain ⟨hlpshape, hlplane⟩ := buildLoop_lane loopBits 1 point0.res point0.next
    (by norm_num) (by rw [hlblen]; omega) hlbshapes hp0shape hlp
  have hlpres := hlplane j hj hlbbits
  have hp0lane := genPointSimd_lane hpoint0 j (by
    have h4 : input.len ≤ 4 * input.data.length := hcov
    omega)
  -- The accumulated point is the generator power of `queryIndex`.
  have hbase : PointSimd.lane ρ lp.res j = M31_CIRCLE_GEN.smul
      (queryIndex (fun i => bitNat ρ (eb.res.getD i dummySimd) j) L) := by
    rw [hlpres, hp0lane, toPoint_subgroupGen (by omega) (by omega)]
    rw [show ∑ t ∈ Finset.range loopBits.length,
        bitNat ρ (loopBits.getD t dummySimd) j * subgroupGen (1 + t)
      = ∑ t ∈ Finset.range (L - 1),
        bitNat ρ (eb.res.getD (t + 1) dummySimd) j * subgroupGen (t + 1) from by
      rw [hlblen]
      exact Finset.sum_congr rfl fun t ht => by
        rw [hloopget t (Finset.mem_range.mp ht), show 1 + t = t + 1 by omega]]
    rw [← CPoint.smul_add_idx]
    rfl
  -- Shapes for the final select.
  obtain ⟨hlpx, hlpy, hlpdx, hlpdy, -⟩ := hlpshape
  set zs := constSplat 0 count len lp.next with hzsdef
  set ny := simdSub zs.res lp.res.y zs.next with hnydef
  have hzsdata : zs.res.data.length = count := by simp [hzsdef, constSplat]
  have hzscov : zs.res.Covers := by
    show len ≤ 4 * zs.res.data.length
    rw [hzsdata]; exact hcnt
  have hzslane : SimdReg.lane ρ zs.res j = 0 := constSplat_lane hzs j (by
    unfold SimdReg.Covers at hcov; omega)
  have hnylane := simdSub_lane hzscov (by
    show zs.res.len ≤ 4 * lp.res.y.data.length
    rw [show zs.res.len = len from rfl, hlpdy]; exact hcnt) hny j (by
    show j < zs.res.len; exact hj)
  have hnydata : ny.res.data.length = count := by
    rw [hnydef]
    show (lanewise2 Op.sub zs.res.data lp.res.y.data zs.next).res.length = count
    rw [lanewise2_length, hzsdata, hlpdy]
    omega
  have hbit0mem : eb.res.getD 0 dummySimd ∈ eb.res := by
    have : eb.res ≠ [] := by
      intro hnil; rw [hnil] at heblen; simp at heblen
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [heblen]; omega)]
    exact List.getElem_mem _
  obtain ⟨hb0len, hb0data⟩ := hebshape _ hbit0mem
  have hselshape : SelShape (eb.res.getD 0 dummySimd) lp.res.y ny.res :=
    ⟨by show _ ≤ 4 * _; rw [hb0len, hb0data]; exact hcnt,
     by show lp.res.y.len ≤ 4 * lp.res.y.data.length; rw [hlpy, hlpdy]; exact hcnt,
     by show ny.res.len ≤ 4 * ny.res.data.length
        rw [show ny.res.len = zs.res.len from rfl,
          show zs.res.len = len from rfl, hnydata]
        exact hcnt,
     by rw [hlpy, hb0len],
     by show zs.res.len = _; rw [show zs.res.len = len from rfl, hb0len],
     by rw [hb0len, hlpdy]; exact hcnt,
     by rw [hb0len, hnydata]; exact hcnt⟩
  have hb0bit := hbits31 0 (by norm_num)
  have hysel := simdSelect_lane_bit hselshape hysel j (by rw [hb0len]; exact hj) hb0bit
  -- Assemble.
  have hx : SimdReg.lane ρ lp.res.x j = (M31_CIRCLE_GEN.smul
      (queryIndex (fun i => bitNat ρ (eb.res.getD i dummySimd) j) L)).x :=
    congrArg CPoint.x hbase
  have hy : SimdReg.lane ρ lp.res.y j = (M31_CIRCLE_GEN.smul
      (queryIndex (fun i => bitNat ρ (eb.res.getD i dummySimd) j) L)).y :=
    congrArg CPoint.y hbase
  rcases hb0bit with hb0 | hb1
  · rw [if_pos hb0]
    refine CPoint.ext' hx ?_
    show SimdReg.lane ρ (simdSelect (eb.res.getD 0 dummySimd)
      lp.res.y ny.res ny.next).res j = _
    rw [hysel, if_pos hb0]
    exact hy
  · have hne : ¬ SimdReg.lane ρ (eb.res.getD 0 dummySimd) j = 0 := by
      rw [hb1]; norm_num
    rw [if_neg hne]
    refine CPoint.ext' hx ?_
    show SimdReg.lane ρ (simdSelect (eb.res.getD 0 dummySimd)
      lp.res.y ny.res ny.next).res j = _
    rw [hysel, if_neg hne, hnylane, hzslane]
    show (0 : F) - SimdReg.lane ρ lp.res.y j
      = -(M31_CIRCLE_GEN.smul (queryIndex
          (fun i => bitNat ρ (eb.res.getD i dummySimd) j) L)).y
    rw [hy]
    ring

/-! ### `translate_to_base_point` (FRI decommit)

Per index bit `i`, conditionally *subtract* the size-`2^(i+1)` subgroup
generator: lane-wise, add the conjugate generator power. The loop is the
conjugate twin of `buildLoop`. -/

def transStep (bit : SimdReg) (i count len : ℕ) (point : PointSimd) (n : ℕ) :
    Out PointSimd :=
  let gen := genPointSimd i count len n
  let pib := subPointsSimd point gen.res gen.next
  let sx := simdSelect bit point.x pib.res.x pib.next
  let sy := simdSelect bit point.y pib.res.y sx.next
  ⟨gen.ops ++ pib.ops ++ sx.ops ++ sy.ops, ⟨sx.res, sy.res⟩, sy.next⟩

theorem transStep_shape {bit : SimdReg} {i count len n : ℕ} {point : PointSimd}
    (hb : BitShape bit len count) (hp : point.Shape len count) :
    (transStep bit i count len point n).res.Shape len count := by
  obtain ⟨hblen, hbdata⟩ := hb
  have hps := hp
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  have hpib : (subPointsSimd point (genPointSimd i count len n).res
      (genPointSimd i count len n).next).res.Shape len count :=
    subPointsSimd_shape hps (genPointSimd_shape (by omega))
  obtain ⟨plx, ply, pdx, pdy, -⟩ := hpib
  refine ⟨by show point.x.len = len; exact hlx,
    by show point.y.len = len; exact hly, ?_, ?_, hc⟩
  · rw [show (transStep bit i count len point n).res.x
      = (simdSelect bit point.x (subPointsSimd point
          (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x
          (subPointsSimd point (genPointSimd i count len n).res
            (genPointSimd i count len n).next).next).res from rfl,
      simdSelect_data_len]
    omega
  · rw [show (transStep bit i count len point n).res.y
      = (simdSelect bit point.y (subPointsSimd point
          (genPointSimd i count len n).res (genPointSimd i count len n).next).res.y
          (simdSelect bit point.x (subPointsSimd point
            (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x
            (subPointsSimd point (genPointSimd i count len n).res
              (genPointSimd i count len n).next).next).next).res from rfl,
      simdSelect_data_len]
    omega

theorem transStep_lane {ρ : ℕ → QM31} {bit : SimdReg} {i count len n : ℕ}
    {point : PointSimd}
    (hb : BitShape bit len count) (hp : point.Shape len count)
    (h : AllHold ρ (transStep bit i count len point n).ops)
    (j : ℕ) (hj : j < len)
    (hbit : SimdReg.lane ρ bit j = 0 ∨ SimdReg.lane ρ bit j = 1) :
    PointSimd.lane ρ (transStep bit i count len point n).res j
      = if SimdReg.lane ρ bit j = 0 then PointSimd.lane ρ point j
        else (PointSimd.lane ρ point j).add ((subgroupGen i : PIdx).toPoint).conjugate := by
  obtain ⟨hblen, hbdata⟩ := hb
  have hps := hp
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  unfold transStep at h
  rw [allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨hgen, hpib⟩, hsx⟩, hsy⟩ := h
  have hgshape : (genPointSimd i count len n).res.Shape len count :=
    genPointSimd_shape (by omega)
  have hpibshape : (subPointsSimd point (genPointSimd i count len n).res
      (genPointSimd i count len n).next).res.Shape len count :=
    subPointsSimd_shape hps hgshape
  obtain ⟨plx, ply, pdx, pdy, -⟩ := hpibshape
  have hj4 : j / 4 < count := by omega
  have hgenlane := genPointSimd_lane hgen j hj4
  have hpiblane := subPointsSimd_lane hps hgshape hpib j hj
  have hselx : SelShape bit point.x (subPointsSimd point
      (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x :=
    ⟨by show bit.len ≤ 4 * bit.data.length; omega,
     by show point.x.len ≤ 4 * point.x.data.length; omega,
     by show _ ≤ 4 * _; omega,
     by omega, by omega, by omega, by omega⟩
  have hsely : SelShape bit point.y (subPointsSimd point
      (genPointSimd i count len n).res (genPointSimd i count len n).next).res.y :=
    ⟨by show bit.len ≤ 4 * bit.data.length; omega,
     by show point.y.len ≤ 4 * point.y.data.length; omega,
     by show _ ≤ 4 * _; omega,
     by omega, by omega, by omega, by omega⟩
  have hlx' := simdSelect_lane_bit hselx hsx j (by omega) hbit
  have hly' := simdSelect_lane_bit hsely hsy j (by omega) hbit
  rcases hbit with hb0 | hb1
  · rw [if_pos hb0]
    refine CPoint.ext' ?_ ?_
    · show SimdReg.lane ρ (simdSelect bit point.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).next).res j = _
      rw [hlx', if_pos hb0]
      rfl
    · show SimdReg.lane ρ (simdSelect bit point.y (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).res.y (simdSelect bit point.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).next).next).res j = _
      rw [hly', if_pos hb0]
      rfl
  · rw [if_neg (by rw [hb1]; norm_num)]
    have hne : ¬ SimdReg.lane ρ bit j = 0 := by rw [hb1]; norm_num
    have hpibx : (PointSimd.lane ρ (subPointsSimd point (genPointSimd i count len n).res
        (genPointSimd i count len n).next).res j).x
        = ((PointSimd.lane ρ point j).add ((subgroupGen i : PIdx).toPoint).conjugate).x := by
      rw [hpiblane, hgenlane]
    have hpiby : (PointSimd.lane ρ (subPointsSimd point (genPointSimd i count len n).res
        (genPointSimd i count len n).next).res j).y
        = ((PointSimd.lane ρ point j).add ((subgroupGen i : PIdx).toPoint).conjugate).y := by
      rw [hpiblane, hgenlane]
    refine CPoint.ext' ?_ ?_
    · show SimdReg.lane ρ (simdSelect bit point.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).next).res j = _
      rw [hlx', if_neg hne]
      exact hpibx
    · show SimdReg.lane ρ (simdSelect bit point.y (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).res.y (simdSelect bit point.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).res.x (subPointsSimd point (genPointSimd i count len n).res (genPointSimd i count len n).next).next).next).res j = _
      rw [hly', if_neg hne]
      exact hpiby

/-- `translate_to_base_point`: subtract `gen(startIdx + t)` for every set
bit `t`. -/
def transLoop (count len : ℕ) : List SimdReg → ℕ → PointSimd → ℕ → Out PointSimd
  | [], _, point, n => ⟨[], point, n⟩
  | bit :: rest, startIdx, point, n =>
    let st := transStep bit startIdx count len point n
    let r := transLoop count len rest (startIdx + 1) st.res st.next
    ⟨st.ops ++ r.ops, r.res, r.next⟩

theorem transLoop_lane {ρ : ℕ → QM31} {count len : ℕ} :
    ∀ (bits : List SimdReg) (startIdx : ℕ) (point : PointSimd) (n : ℕ),
      1 ≤ startIdx → startIdx + bits.length ≤ 31 →
      (∀ b ∈ bits, BitShape b len count) →
      point.Shape len count →
      AllHold ρ (transLoop count len bits startIdx point n).ops →
      (transLoop count len bits startIdx point n).res.Shape len count ∧
      ∀ j, j < len →
        (∀ b ∈ bits, SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1) →
        PointSimd.lane ρ (transLoop count len bits startIdx point n).res j
          = (PointSimd.lane ρ point j).add
              (M31_CIRCLE_GEN.smul (∑ t ∈ Finset.range bits.length,
                bitNat ρ (bits.getD t dummySimd) j * subgroupGen (startIdx + t))).conjugate := by
  intro bits
  induction bits with
  | nil =>
    intro startIdx point n _ _ _ hp _
    refine ⟨hp, fun j hj _ => ?_⟩
    show PointSimd.lane ρ point j = _
    simp only [List.length_nil, Finset.range_zero, Finset.sum_empty, ← CPoint.mul_def]
    rw [show CPoint.smul M31_CIRCLE_GEN 0 = (1 : PointF) from by
      rw [CPoint.smul_eq_pow, pow_zero], CPoint.conj_one, mul_one]
  | cons bit rest ih =>
    intro startIdx point n hstart hbound hshapes hp h
    rw [show (transLoop count len (bit :: rest) startIdx point n).ops =
      (transStep bit startIdx count len point n).ops ++
        (transLoop count len rest (startIdx + 1)
          (transStep bit startIdx count len point n).res
          (transStep bit startIdx count len point n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hstep, hrest⟩ := h
    have hbshape := hshapes bit List.mem_cons_self
    have hstepshape : (transStep bit startIdx count len point n).res.Shape len count :=
      transStep_shape hbshape hp
    obtain ⟨ihshape, ihlane⟩ := ih (startIdx + 1)
      (transStep bit startIdx count len point n).res
      (transStep bit startIdx count len point n).next
      (by omega) (by simp only [List.length_cons] at hbound; omega)
      (fun b hb => hshapes b (List.mem_cons_of_mem _ hb)) hstepshape hrest
    refine ⟨ihshape, fun j hj hbits => ?_⟩
    have hbit := hbits bit List.mem_cons_self
    have hsteplane := transStep_lane hbshape hp hstep j hj hbit
    rw [show (transLoop count len (bit :: rest) startIdx point n).res
      = (transLoop count len rest (startIdx + 1)
          (transStep bit startIdx count len point n).res
          (transStep bit startIdx count len point n).next).res from rfl,
      ihlane j hj (fun b hb => hbits b (List.mem_cons_of_mem _ hb)), hsteplane]
    have hsum : ∑ t ∈ Finset.range (bit :: rest).length,
        bitNat ρ ((bit :: rest).getD t dummySimd) j * subgroupGen (startIdx + t)
        = bitNat ρ bit j * subgroupGen startIdx +
          ∑ t ∈ Finset.range rest.length,
            bitNat ρ (rest.getD t dummySimd) j * subgroupGen (startIdx + 1 + t) := by
      rw [List.length_cons, Finset.sum_range_succ']
      simp only [List.getD_cons_succ, List.getD_cons_zero, Nat.add_zero]
      rw [Nat.add_comm]
      congr 1
      exact Finset.sum_congr rfl fun t _ => by
        congr 2
        omega
    rw [hsum, CPoint.smul_add_idx]
    rw [show (M31_CIRCLE_GEN.smul (bitNat ρ bit j * subgroupGen startIdx)).add
        (M31_CIRCLE_GEN.smul (∑ t ∈ Finset.range rest.length,
          bitNat ρ (rest.getD t dummySimd) j * subgroupGen (startIdx + 1 + t)))
      = M31_CIRCLE_GEN.smul (bitNat ρ bit j * subgroupGen startIdx)
        * M31_CIRCLE_GEN.smul (∑ t ∈ Finset.range rest.length,
          bitNat ρ (rest.getD t dummySimd) j * subgroupGen (startIdx + 1 + t)) from rfl,
      CPoint.conj_mul]
    simp only [← CPoint.mul_def]
    rcases hbit with hb0 | hb1
    · rw [if_pos hb0,
        show bitNat ρ bit j = 0 from by unfold bitNat; rw [if_pos hb0],
        Nat.zero_mul,
        show CPoint.smul M31_CIRCLE_GEN 0 = (1 : PointF) from by
          rw [CPoint.smul_eq_pow, pow_zero],
        CPoint.conj_one, one_mul]
    · have hne : ¬ SimdReg.lane ρ bit j = 0 := by rw [hb1]; norm_num
      rw [if_neg hne,
        show bitNat ρ bit j = 1 from by unfold bitNat; rw [if_neg hne],
        Nat.one_mul, toPoint_subgroupGen hstart (by
          simp only [List.length_cons] at hbound; omega),
        mul_assoc]

end StwoVerifier.Gadgets
