/-
**The decommit's base-point and twiddle chain at fold step 1**
(`src/frontends/circuit/stark_verifier/fri.zig`
`circle_translate_to_base_point` / `translate_to_base_point` /
`repeated_double_point_simd` / `compute_twiddles_from_base_point`,
stwo-zig `4afa09dbf`).

At the pinned fold step 1, every per-layer twiddle list is a single
`simd.inv`: of the base point's `y` for the circle-to-line layer, of
its `x` for the line layers (`compute_half_coset_points` at log size 1
is just the base point). The base point chain is: conjugate-select by
the query's bit 0, then per layer double (zero times before the first
line layer, once afterwards) and translate by the order-2 subgroup
generator when the layer's bit is set. This file proves the lane
semantics of each step; the chain walk discharges `Chain1`'s twiddle
hypotheses with the lane points' coordinates.
-/
import StwoVerifier.SelectQueriesBridge

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates StwoVerifier.Bridge

/-- `eval!(ctx, -(x))` on a `Simd`: `0 − x` lane-wise. -/
def negSimdG (count len : ℕ) (x : SimdReg) (n : ℕ) : Out SimdReg :=
  let z := constSplat 0 count len n
  let r := simdSub z.res x z.next
  ⟨z.ops ++ r.ops, r.res, r.next⟩

theorem negSimdG_shape (count len : ℕ) (x : SimdReg) (n : ℕ) :
    (negSimdG count len x n).res.len = len ∧
    (negSimdG count len x n).res.data.length = min count x.data.length := by
  constructor
  · rfl
  · show (lanewise2 Op.sub (List.replicate count n) x.data _).res.length = _
    rw [lanewise2_length]
    simp

theorem negSimdG_lane {ρ : ℕ → QM31} {count len : ℕ} {x : SimdReg} {n : ℕ}
    (hlen : len ≤ 4 * count) (hxd : len ≤ 4 * x.data.length)
    (h : AllHold ρ (negSimdG count len x n).ops) (j : ℕ) (hj : j < len) :
    SimdReg.lane ρ (negSimdG count len x n).res j = -SimdReg.lane ρ x j := by
  unfold negSimdG at h
  rw [allHold_append] at h
  obtain ⟨hz, hr⟩ := h
  have hzc : (constSplat 0 count len n).res.Covers := constSplat_covers hlen
  have hsub := simdSub_lane hzc (by show len ≤ 4 * x.data.length; exact hxd)
    hr j (by show j < len; exact hj)
  show SimdReg.lane ρ (simdSub (constSplat 0 count len n).res x
    (constSplat 0 count len n).next).res j = -SimdReg.lane ρ x j
  rw [hsub, constSplat_lane hz j (by omega)]
  ring

/-- `double_x_simd`: `2x² − 1` lane-wise. -/
def doubleXSimdG (count len : ℕ) (x : SimdReg) (n : ℕ) : Out SimdReg :=
  let sqr := simdMul x x n
  let twice := simdAdd sqr.res sqr.res sqr.next
  let one := constSplat 1 count len twice.next
  let r := simdSub twice.res one.res one.next
  ⟨sqr.ops ++ twice.ops ++ one.ops ++ r.ops, r.res, r.next⟩

theorem doubleXSimdG_lane {ρ : ℕ → QM31} {count len : ℕ} {x : SimdReg} {n : ℕ}
    (hxl : x.len = len) (hxd : x.data.length = count) (hlen : len ≤ 4 * count)
    (h : AllHold ρ (doubleXSimdG count len x n).ops) (j : ℕ) (hj : j < len) :
    SimdReg.lane ρ (doubleXSimdG count len x n).res j
      = CPoint.doubleX (SimdReg.lane ρ x j) := by
  unfold doubleXSimdG at h
  rw [allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨hsqr, htwice⟩, hone⟩, hr⟩ := h
  have hxc : x.Covers := by show x.len ≤ 4 * x.data.length; omega
  have hsqlane := simdMul_lane hxc (by show x.len ≤ 4 * x.data.length; omega)
    hsqr j (by omega)
  have hsqc : (simdMul x x n).res.Covers := simdMul_covers hxc hxc
  have hsqd : (simdMul x x n).res.data.length = count := by
    show (lanewise2 Op.pmul x.data x.data n).res.length = count
    rw [lanewise2_length]
    omega
  have htwlane := simdAdd_lane hsqc
    (by show (simdMul x x n).res.len ≤ 4 * (simdMul x x n).res.data.length
        exact hsqc)
    htwice j (by show j < x.len; omega)
  have htwc : (simdAdd (simdMul x x n).res (simdMul x x n).res
      (simdMul x x n).next).res.Covers := simdAdd_covers hsqc hsqc
  have htwd : (simdAdd (simdMul x x n).res (simdMul x x n).res
      (simdMul x x n).next).res.len = len := by
    show (simdMul x x n).res.len = len
    show x.len = len
    exact hxl
  have hrl := simdSub_lane htwc
    (by show (simdAdd _ _ _).res.len ≤ 4 * (List.replicate count _).length
        rw [htwd]
        simpa using hlen)
    hr j (by rw [htwd]; exact hj)
  show SimdReg.lane ρ (simdSub (simdAdd (simdMul x x n).res (simdMul x x n).res
    (simdMul x x n).next).res
    (constSplat 1 count len (simdAdd (simdMul x x n).res (simdMul x x n).res
      (simdMul x x n).next).next).res
    (constSplat 1 count len (simdAdd (simdMul x x n).res (simdMul x x n).res
      (simdMul x x n).next).next).next).res j = _
  rw [hrl, htwlane, hsqlane, constSplat_lane hone j (by omega)]
  unfold CPoint.doubleX
  ring

/-- `double_point_simd`: `(2x² − 1, 2xy)` lane-wise. -/
def doublePointSimdG (count len : ℕ) (p : PointSimd) (n : ℕ) : Out PointSimd :=
  let xy := simdMul p.x p.y n
  let ny := simdAdd xy.res xy.res xy.next
  let nx := doubleXSimdG count len p.x ny.next
  ⟨xy.ops ++ ny.ops ++ nx.ops, ⟨nx.res, ny.res⟩, nx.next⟩

theorem doublePointSimdG_shape {count len : ℕ} {p : PointSimd} {n : ℕ}
    (hp : p.Shape len count) :
    (doublePointSimdG count len p n).res.Shape len count := by
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  refine ⟨?_, ?_, ?_, ?_, hc⟩
  · show p.x.len = len
    exact hlx
  · show p.x.len = len
    exact hlx
  · simp only [doublePointSimdG, doubleXSimdG, simdSub_data_len,
      simdAdd_data_len, simdMul_data_len]
    show min (min (min p.x.data.length p.x.data.length)
      (min p.x.data.length p.x.data.length)) (List.replicate count _).length = _
    simp [hdx]
  · simp only [doublePointSimdG, simdAdd_data_len, simdMul_data_len]
    show min (min p.x.data.length p.y.data.length)
      (min p.x.data.length p.y.data.length) = _
    simp [hdx, hdy]

/-- The lane point doubles — on the circle, the spec's `CPoint.double`. -/
theorem doublePointSimdG_lane {ρ : ℕ → QM31} {count len : ℕ} {p : PointSimd}
    {n : ℕ} (hp : p.Shape len count)
    (h : AllHold ρ (doublePointSimdG count len p n).ops) (j : ℕ) (hj : j < len)
    (hcirc : OnCircle (PointSimd.lane ρ p j)) :
    PointSimd.lane ρ (doublePointSimdG count len p n).res j
      = (PointSimd.lane ρ p j).double := by
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  unfold doublePointSimdG at h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hxy, hny⟩, hnx⟩ := h
  have hxc : p.x.Covers := by show p.x.len ≤ 4 * p.x.data.length; omega
  have hxylane := simdMul_lane hxc (by show p.x.len ≤ 4 * p.y.data.length; omega)
    hxy j (by omega)
  have hxyc : (simdMul p.x p.y n).res.Covers := by
    show p.x.len ≤ 4 * (lanewise2 Op.pmul p.x.data p.y.data n).res.length
    rw [lanewise2_length]
    omega
  have hnylane := simdAdd_lane hxyc
    (by show (simdMul p.x p.y n).res.len ≤ 4 * _; exact hxyc)
    hny j (by show j < p.x.len; omega)
  have hnxlane := doubleXSimdG_lane hlx hdx hc hnx j hj
  unfold OnCircle at hcirc
  have hcirc' : SimdReg.lane ρ p.x j * SimdReg.lane ρ p.x j
      + SimdReg.lane ρ p.y j * SimdReg.lane ρ p.y j = 1 := hcirc
  refine CPoint.ext' ?_ ?_
  · show SimdReg.lane ρ (doubleXSimdG count len p.x _).res j = _
    rw [hnxlane]
    show CPoint.doubleX (SimdReg.lane ρ p.x j)
      = SimdReg.lane ρ p.x j * SimdReg.lane ρ p.x j
        - SimdReg.lane ρ p.y j * SimdReg.lane ρ p.y j
    unfold CPoint.doubleX
    linear_combination hcirc'
  · show SimdReg.lane ρ (simdAdd (simdMul p.x p.y n).res _ _).res j = _
    rw [hnylane, hxylane]
    show SimdReg.lane ρ p.x j * SimdReg.lane ρ p.y j
        + SimdReg.lane ρ p.x j * SimdReg.lane ρ p.y j
      = SimdReg.lane ρ p.x j * SimdReg.lane ρ p.y j
        + SimdReg.lane ρ p.y j * SimdReg.lane ρ p.x j
    ring

/-! ### On-circle closure -/

theorem onCircle_conj {p : PointF} (hp : OnCircle p) : OnCircle p.conjugate := by
  unfold OnCircle CPoint.conjugate at *
  show p.x * p.x + -p.y * -p.y = 1
  linear_combination hp

theorem onCircle_double {p : PointF} (hp : OnCircle p) : OnCircle p.double := by
  show OnCircle (p.add p)
  rw [← CPoint.mul_def]
  exact onCircle_mul hp hp

theorem onCircle_repeatedDouble {p : PointF} (hp : OnCircle p) :
    ∀ k, OnCircle (p.repeatedDouble k)
  | 0 => hp
  | k + 1 => onCircle_double (onCircle_repeatedDouble hp k)

theorem onCircle_smul {p : PointF} (hp : OnCircle p) (k : ℕ) :
    OnCircle (p.smul k) := by
  rw [CPoint.smul_eq_pow]
  exact onCircle_pow hp k

/-- Doubling first commutes with the repeated double. -/
theorem repeatedDouble_shift (p : PointF) :
    ∀ k, (p.double).repeatedDouble k = p.repeatedDouble (k + 1)
  | 0 => rfl
  | k + 1 => by
    show ((p.double).repeatedDouble k).double = (p.repeatedDouble (k + 1)).double
    rw [repeatedDouble_shift p k]

/-- `repeated_double_point_simd`. -/
def repDoubleSimdG (count len : ℕ) : ℕ → PointSimd → ℕ → Out PointSimd
  | 0, p, n => ⟨[], p, n⟩
  | k + 1, p, n =>
    let d := doublePointSimdG count len p n
    let r := repDoubleSimdG count len k d.res d.next
    ⟨d.ops ++ r.ops, r.res, r.next⟩

theorem repDoubleSimdG_sound {ρ : ℕ → QM31} {count len : ℕ} :
    ∀ (k : ℕ) (p : PointSimd) (n : ℕ),
      p.Shape len count →
      AllHold ρ (repDoubleSimdG count len k p n).ops →
      (repDoubleSimdG count len k p n).res.Shape len count ∧
      ∀ j, j < len → OnCircle (PointSimd.lane ρ p j) →
        PointSimd.lane ρ (repDoubleSimdG count len k p n).res j
          = (PointSimd.lane ρ p j).repeatedDouble k := by
  intro k
  induction k with
  | zero =>
    intro p n hp _
    exact ⟨hp, fun j hj _ => rfl⟩
  | succ k ih =>
    intro p n hp h
    rw [show (repDoubleSimdG count len (k + 1) p n).ops =
      (doublePointSimdG count len p n).ops ++
        (repDoubleSimdG count len k (doublePointSimdG count len p n).res
          (doublePointSimdG count len p n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hd, hr⟩ := h
    have hdshape := doublePointSimdG_shape (n := n) hp
    obtain ⟨ihshape, ihlane⟩ := ih (doublePointSimdG count len p n).res
      (doublePointSimdG count len p n).next hdshape hr
    refine ⟨ihshape, fun j hj hcirc => ?_⟩
    have hdlane := doublePointSimdG_lane hp hd j hj hcirc
    show PointSimd.lane ρ (repDoubleSimdG count len k
      (doublePointSimdG count len p n).res
      (doublePointSimdG count len p n).next).res j = _
    rw [ihlane j hj (by rw [hdlane]; exact onCircle_double hcirc), hdlane,
      repeatedDouble_shift]

/-- `circle_translate_to_base_point` with a single (fold-step-1) bit:
conjugate-select by the query's bit 0, no translation. -/
def circleBase1 (count len : ℕ) (bit0 : SimdReg) (p : PointSimd) (n : ℕ) :
    Out PointSimd :=
  let ng := negSimdG count len p.y n
  let sy := simdSelect bit0 p.y ng.res ng.next
  ⟨ng.ops ++ sy.ops, ⟨p.x, sy.res⟩, sy.next⟩

theorem circleBase1_shape {count len : ℕ} {bit0 : SimdReg} {p : PointSimd}
    {n : ℕ} (hb : BitShape bit0 len count) (hp : p.Shape len count) :
    (circleBase1 count len bit0 p n).res.Shape len count := by
  obtain ⟨hbl, hbd⟩ := hb
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  have hngdata : (negSimdG count len p.y n).res.data.length
      = min count p.y.data.length := (negSimdG_shape count len p.y n).2
  refine ⟨hlx, ?_, hdx, ?_, hc⟩
  · show p.y.len = len
    exact hly
  · show (simdSelect bit0 p.y (negSimdG count len p.y n).res
      (negSimdG count len p.y n).next).res.data.length = _
    rw [simdSelect_data_len, hngdata]
    omega

theorem circleBase1_lane {ρ : ℕ → QM31} {count len : ℕ} {bit0 : SimdReg}
    {p : PointSimd} {n : ℕ}
    (hb : BitShape bit0 len count) (hp : p.Shape len count)
    (h : AllHold ρ (circleBase1 count len bit0 p n).ops)
    (j : ℕ) (hj : j < len)
    (hbit : SimdReg.lane ρ bit0 j = 0 ∨ SimdReg.lane ρ bit0 j = 1) :
    PointSimd.lane ρ (circleBase1 count len bit0 p n).res j
      = if SimdReg.lane ρ bit0 j = 0 then PointSimd.lane ρ p j
        else (PointSimd.lane ρ p j).conjugate := by
  obtain ⟨hbl, hbd⟩ := hb
  obtain ⟨hlx, hly, hdx, hdy, hc⟩ := hp
  unfold circleBase1 at h
  rw [allHold_append] at h
  obtain ⟨hng, hsy⟩ := h
  have hngdata : (negSimdG count len p.y n).res.data.length
      = min count p.y.data.length := (negSimdG_shape count len p.y n).2
  have hsel : SelShape bit0 p.y (negSimdG count len p.y n).res :=
    ⟨by show bit0.len ≤ 4 * bit0.data.length; omega,
     by show p.y.len ≤ 4 * p.y.data.length; omega,
     by show (negSimdG count len p.y n).res.len
          ≤ 4 * (negSimdG count len p.y n).res.data.length
        rw [(negSimdG_shape count len p.y n).1, hngdata]
        omega,
     by rw [hly, hbl],
     by rw [(negSimdG_shape count len p.y n).1, hbl],
     by rw [hbl]; omega,
     by rw [hbl, hngdata]; omega⟩
  have hng_lane := negSimdG_lane hc (by omega) hng j hj
  have hsy_lane := simdSelect_lane_bit hsel hsy j (by rw [hbl]; exact hj) hbit
  rcases hbit with hb0 | hb1
  · rw [if_pos hb0]
    refine CPoint.ext' rfl ?_
    show SimdReg.lane ρ (simdSelect bit0 p.y (negSimdG count len p.y n).res
      (negSimdG count len p.y n).next).res j = _
    rw [hsy_lane, if_pos hb0]
    rfl
  · rw [if_neg (by rw [hb1]; norm_num)]
    refine CPoint.ext' rfl ?_
    show SimdReg.lane ρ (simdSelect bit0 p.y (negSimdG count len p.y n).res
      (negSimdG count len p.y n).next).res j = -(PointSimd.lane ρ p j).y
    rw [hsy_lane, if_neg (by rw [hb1]; norm_num), hng_lane]
    rfl

/-- The spec-side base-point sequence below the circle layer: per line
layer, double `d` times (zero before the first, once afterwards) and
translate by the order-2 subgroup generator when the bit is set. -/
def baseSeq (P : PointF) : ℕ → List ℕ → List PointF
  | _, [] => []
  | d, b :: rest =>
    ((P.repeatedDouble d).add
      ((M31_CIRCLE_GEN.smul (b * subgroupGen 1)).conjugate))
      :: baseSeq ((P.repeatedDouble d).add
        ((M31_CIRCLE_GEN.smul (b * subgroupGen 1)).conjugate)) 1 rest

/-- The inner-layer walk: per line layer, double, translate by the
layer's bit, and invert the base point's `x` (the fold-step-1 twiddle). -/
def innerChain (zero count len : ℕ) :
    List SimdReg → ℕ → PointSimd → ℕ → Out (List SimdReg)
  | [], _, _, n => ⟨[], [], n⟩
  | bit :: rest, d, base, n =>
    let q := repDoubleSimdG count len d base n
    let t := transLoop count len [bit] 1 q.res q.next
    let tw := simdInv zero t.res.x t.next
    let r := innerChain zero count len rest 1 t.res tw.next
    ⟨q.ops ++ t.ops ++ tw.ops ++ r.ops, tw.res :: r.res, r.next⟩

set_option maxHeartbeats 800000 in
/-- Each inner twiddle register inverts its base point's `x`. -/
theorem innerChain_sound {ρ : ℕ → QM31} {zero count len : ℕ}
    (hzero : ρ zero = 0) :
    ∀ (bits : List SimdReg) (d : ℕ) (base : PointSimd) (n : ℕ),
      base.Shape len count →
      (∀ b ∈ bits, BitShape b len count) →
      AllHold ρ (innerChain zero count len bits d base n).ops →
      (innerChain zero count len bits d base n).res.length = bits.length ∧
      ∀ j, j < len →
        (∀ b ∈ bits, SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1) →
        OnCircle (PointSimd.lane ρ base j) →
        ∀ l, l < bits.length →
          SimdReg.lane ρ ((innerChain zero count len bits d base n).res.getD
              l dummySimd) j
            * ((baseSeq (PointSimd.lane ρ base j) d
                (bits.map fun b => bitNat ρ b j)).getD l CPoint.zero).x = 1 := by
  intro bits
  induction bits with
  | nil =>
    intro d base n _ _ _
    exact ⟨rfl, fun j hj _ _ l hl => by simp at hl⟩
  | cons bit rest ih =>
    intro d base n hbase hshapes h
    rw [show (innerChain zero count len (bit :: rest) d base n).ops =
      (repDoubleSimdG count len d base n).ops ++
        (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).ops ++
        (simdInv zero (transLoop count len [bit] 1
          (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).res.x
          (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
            (repDoubleSimdG count len d base n).next).next).ops ++
        (innerChain zero count len rest 1
          (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
            (repDoubleSimdG count len d base n).next).res
          (simdInv zero (transLoop count len [bit] 1
            (repDoubleSimdG count len d base n).res
            (repDoubleSimdG count len d base n).next).res.x
            (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
              (repDoubleSimdG count len d base n).next).next).next).ops from rfl,
      allHold_append, allHold_append, allHold_append] at h
    obtain ⟨⟨⟨hq, ht⟩, htw⟩, hrest⟩ := h
    obtain ⟨hqshape, hqlane⟩ := repDoubleSimdG_sound d base n hbase hq
    obtain ⟨htshape, htlane⟩ := transLoop_lane [bit] 1
      (repDoubleSimdG count len d base n).res
      (repDoubleSimdG count len d base n).next
      (by omega) (by simp)
      (by intro b hb; rw [List.mem_singleton.mp hb]
          exact hshapes bit List.mem_cons_self)
      hqshape ht
    have htxcov : (transLoop count len [bit] 1
        (repDoubleSimdG count len d base n).res
        (repDoubleSimdG count len d base n).next).res.x.Covers := by
      obtain ⟨hlx, hly, hdx, hdy, hc⟩ := htshape
      show _ ≤ 4 * _
      omega
    obtain ⟨ihlen, ihval⟩ := ih 1
      (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
        (repDoubleSimdG count len d base n).next).res
      (simdInv zero (transLoop count len [bit] 1
        (repDoubleSimdG count len d base n).res
        (repDoubleSimdG count len d base n).next).res.x
        (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).next).next
      htshape (fun b hb => hshapes b (List.mem_cons_of_mem _ hb)) hrest
    refine ⟨?_, fun j hj hbits hcirc l hl => ?_⟩
    · show (innerChain zero count len rest 1
        (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).res
        (simdInv zero (transLoop count len [bit] 1
          (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).res.x
          (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
            (repDoubleSimdG count len d base n).next).next).next).res.length + 1
        = rest.length + 1
      rw [ihlen]
    have hbit := hbits bit List.mem_cons_self
    have hqcirc : OnCircle (PointSimd.lane ρ
        (repDoubleSimdG count len d base n).res j) := by
      rw [hqlane j hj hcirc]
      exact onCircle_repeatedDouble hcirc d
    -- The translated lane point, in `baseSeq` form.
    have hblane : PointSimd.lane ρ (transLoop count len [bit] 1
        (repDoubleSimdG count len d base n).res
        (repDoubleSimdG count len d base n).next).res j
        = ((PointSimd.lane ρ base j).repeatedDouble d).add
            ((M31_CIRCLE_GEN.smul (bitNat ρ bit j * subgroupGen 1)).conjugate) := by
      rw [htlane j hj (by intro b hb; rw [List.mem_singleton.mp hb]; exact hbit),
        hqlane j hj hcirc]
      simp
    have htcirc : OnCircle (PointSimd.lane ρ (transLoop count len [bit] 1
        (repDoubleSimdG count len d base n).res
        (repDoubleSimdG count len d base n).next).res j) := by
      rw [hblane, ← CPoint.mul_def]
      exact onCircle_mul (onCircle_repeatedDouble hcirc d)
        (onCircle_conj (onCircle_smul onCircle_gen _))
    cases l with
    | zero =>
      have hinv := simdInv_lane hzero htxcov htw j (by
        obtain ⟨hlx, -, -, -, -⟩ := htshape
        rw [hlx]
        exact hj)
      show SimdReg.lane ρ (simdInv zero (transLoop count len [bit] 1
        (repDoubleSimdG count len d base n).res
        (repDoubleSimdG count len d base n).next).res.x
        (transLoop count len [bit] 1 (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).next).res j * _ = 1
      have hx : SimdReg.lane ρ (transLoop count len [bit] 1
          (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).res.x j
          = ((baseSeq (PointSimd.lane ρ base j) d
              ((bit :: rest).map fun b => bitNat ρ b j)).getD 0 CPoint.zero).x := by
        show (PointSimd.lane ρ (transLoop count len [bit] 1
          (repDoubleSimdG count len d base n).res
          (repDoubleSimdG count len d base n).next).res j).x = _
        rw [hblane]
        rfl
      rw [← hx]
      exact hinv
    | succ l =>
      have hl' : l < rest.length := by simpa using hl
      have := ihval j hj (fun b hb => hbits b (List.mem_cons_of_mem _ hb))
        htcirc l hl'
      show SimdReg.lane ρ ((innerChain zero count len rest 1 _ _).res.getD
        l dummySimd) j * _ = 1
      rw [show ((baseSeq (PointSimd.lane ρ base j) d
          ((bit :: rest).map fun b => bitNat ρ b j)).getD (l + 1) CPoint.zero)
          = ((baseSeq (PointSimd.lane ρ (transLoop count len [bit] 1
              (repDoubleSimdG count len d base n).res
              (repDoubleSimdG count len d base n).next).res j) 1
              (rest.map fun b => bitNat ρ b j)).getD l CPoint.zero) from by
        rw [hblane]
        rfl]
      exact this

/-- The full fold-step-1 twiddle chain: conjugate-select the query
point by bit 0, invert its `y` (the circle layer's twiddle), then the
inner-layer walk starting with zero doubles. -/
def twiddleChain1 (zero count len : ℕ) (bit0 : SimdReg) (points : PointSimd)
    (bits : List SimdReg) (n : ℕ) : Out (List SimdReg) :=
  let b0 := circleBase1 count len bit0 points n
  let tw0 := simdInv zero b0.res.y b0.next
  let r := innerChain zero count len bits 0 b0.res tw0.next
  ⟨b0.ops ++ tw0.ops ++ r.ops, tw0.res :: r.res, r.next⟩

set_option maxHeartbeats 800000 in
/-- **Every twiddle register inverts its layer's fold coordinate**: the
conjugate-selected query point's `y` for the circle layer, then the
`baseSeq` points' `x`s for the line layers. -/
theorem twiddleChain1_sound {ρ : ℕ → QM31} {zero count len : ℕ}
    {bit0 : SimdReg} {points : PointSimd} {bits : List SimdReg} {n : ℕ}
    (hzero : ρ zero = 0)
    (hb0 : BitShape bit0 len count) (hp : points.Shape len count)
    (hshapes : ∀ b ∈ bits, BitShape b len count)
    (h : AllHold ρ (twiddleChain1 zero count len bit0 points bits n).ops) :
    (twiddleChain1 zero count len bit0 points bits n).res.length
      = bits.length + 1 ∧
    ∀ j, j < len →
      (SimdReg.lane ρ bit0 j = 0 ∨ SimdReg.lane ρ bit0 j = 1) →
      (∀ b ∈ bits, SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1) →
      OnCircle (PointSimd.lane ρ points j) →
      (SimdReg.lane ρ ((twiddleChain1 zero count len bit0 points bits n).res.getD
          0 dummySimd) j
        * (if SimdReg.lane ρ bit0 j = 0 then PointSimd.lane ρ points j
           else (PointSimd.lane ρ points j).conjugate).y = 1) ∧
      ∀ l, l < bits.length →
        SimdReg.lane ρ ((twiddleChain1 zero count len bit0 points bits n).res.getD
            (l + 1) dummySimd) j
          * ((baseSeq (if SimdReg.lane ρ bit0 j = 0 then PointSimd.lane ρ points j
              else (PointSimd.lane ρ points j).conjugate) 0
              (bits.map fun b => bitNat ρ b j)).getD l CPoint.zero).x = 1 := by
  unfold twiddleChain1 at h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hb0h, htw0⟩, hinner⟩ := h
  have hb0shape := circleBase1_shape (n := n) hb0 hp
  have hycov : (circleBase1 count len bit0 points n).res.y.Covers := by
    obtain ⟨-, hly, -, hdy, hc⟩ := hb0shape
    show _ ≤ 4 * _
    omega
  obtain ⟨ihlen, ihval⟩ := innerChain_sound hzero bits 0
    (circleBase1 count len bit0 points n).res
    (simdInv zero (circleBase1 count len bit0 points n).res.y
      (circleBase1 count len bit0 points n).next).next
    hb0shape hshapes hinner
  refine ⟨?_, fun j hj hbit0 hbits hcirc => ?_⟩
  · show (innerChain zero count len bits 0 _ _).res.length + 1 = bits.length + 1
    rw [ihlen]
  · have hb0lane := circleBase1_lane hb0 hp hb0h j hj hbit0
    have hb0circ : OnCircle (PointSimd.lane ρ
        (circleBase1 count len bit0 points n).res j) := by
      rw [hb0lane]
      rcases hbit0 with h0 | h1
      · rw [if_pos h0]; exact hcirc
      · rw [if_neg (by rw [h1]; norm_num)]
        exact onCircle_conj hcirc
    refine ⟨?_, fun l hl => ?_⟩
    · have hinv := simdInv_lane hzero hycov htw0 j (by
        obtain ⟨-, hly, -, -, -⟩ := hb0shape
        rw [hly]
        exact hj)
      show SimdReg.lane ρ (simdInv zero
        (circleBase1 count len bit0 points n).res.y
        (circleBase1 count len bit0 points n).next).res j * _ = 1
      have hy : SimdReg.lane ρ (circleBase1 count len bit0 points n).res.y j
          = (if SimdReg.lane ρ bit0 j = 0 then PointSimd.lane ρ points j
             else (PointSimd.lane ρ points j).conjugate).y := by
        show (PointSimd.lane ρ (circleBase1 count len bit0 points n).res j).y = _
        rw [hb0lane]
      rw [← hy]
      exact hinv
    · have := ihval j hj hbits hb0circ l hl
      show SimdReg.lane ρ ((innerChain zero count len bits 0 _ _).res.getD
        l dummySimd) j * _ = 1
      rw [show (baseSeq (if SimdReg.lane ρ bit0 j = 0
          then PointSimd.lane ρ points j
          else (PointSimd.lane ρ points j).conjugate) 0
          (bits.map fun b => bitNat ρ b j))
          = (baseSeq (PointSimd.lane ρ
              (circleBase1 count len bit0 points n).res j) 0
              (bits.map fun b => bitNat ρ b j)) from by rw [hb0lane]]
      exact this

/-! ### The circle layer's fold point -/

theorem conj_conj (p : PointF) : p.conjugate.conjugate = p := by
  unfold CPoint.conjugate
  refine CPoint.ext' rfl ?_
  show -(-p.y) = p.y
  ring

/-- **Un-conjugating by bit 0 lands on the even position's point**: the
decommit's circle base point is the spec's `foldCircleSubset` point of
the query's width-2 subset (its start = the position with bit 0
cleared). `queryIndex` does not involve bit 0, so both sides are the
same generator power. -/
theorem base0_eq_evenPoint {b : ℕ → ℕ} (hb : ∀ i, b i ≤ 1) {L : ℕ}
    (hL2 : 2 ≤ L) (hL30 : L ≤ 30) :
    (if b 0 = 0
     then (canonicDomain L).at'
       (bitReverseIndex (∑ i ∈ Finset.range L, b i * 2 ^ i) L)
     else ((canonicDomain L).at'
       (bitReverseIndex (∑ i ∈ Finset.range L, b i * 2 ^ i) L)).conjugate)
      = (canonicDomain L).at' (bitReverseIndex
          (∑ i ∈ Finset.range L, (if i = 0 then 0 else b i) * 2 ^ i) L) := by
  have hb' : ∀ i, (if i = 0 then 0 else b i) ≤ 1 := by
    intro i
    by_cases h0 : i = 0 <;> simp [h0, hb i]
  have hqi : queryIndex (fun i => if i = 0 then 0 else b i) L
      = queryIndex b L := by
    unfold queryIndex
    congr 1
  have hmain := Bridge.queryIndex_eq_domainPoint hb hL2 hL30
  have hmain' := Bridge.queryIndex_eq_domainPoint hb' hL2 hL30
  simp only [reduceIte] at hmain'
  rw [hqi] at hmain'
  by_cases h0 : b 0 = 0
  · rw [if_pos h0, ← hmain, if_pos h0, ← hmain']
  · rw [if_neg h0, ← hmain, if_neg h0, conj_conj, ← hmain']

end StwoVerifier.Gadgets
