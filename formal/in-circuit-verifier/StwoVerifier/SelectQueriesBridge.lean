/-
**From `queryIndex` to the spec's domain point.** The gadget builds
`gen^(queryIndex bits L)` (conjugated when bit 0 is set); the verifier
spec reads the query's domain point as
`(canonicDomain L).at' (bitReverseIndex pos L)` (`Quotients.friAnswers`).
This file proves the two agree: the gadget's bit weights `2^(31−i)` are
exactly the bit-reversed coset index of the canonic circle domain, and
the bit-0 conjugation is the domain's second (conjugate) half.

No gates here — pure index arithmetic on the circle group, plus the two
kernel-checked facts that the generator lies on the circle and has order
`2^31`.
-/
import StwoVerifier.SelectQueries

namespace StwoVerifier.Bridge

open StwoVerifier StwoVerifier.Gadgets Finset

/-! ### The circle: closure, conjugate inverse, generator order -/

/-- `x² + y² = 1`. -/
def OnCircle (p : PointF) : Prop := p.x * p.x + p.y * p.y = 1

theorem onCircle_gen : OnCircle M31_CIRCLE_GEN := by unfold OnCircle; decide

theorem gen_order : M31_CIRCLE_GEN.repeatedDouble 31 = CPoint.zero := by decide

theorem onCircle_mul {p q : PointF} (hp : OnCircle p) (hq : OnCircle q) :
    OnCircle (p * q) := by
  unfold OnCircle at *
  show (p.add q).x * (p.add q).x + (p.add q).y * (p.add q).y = 1
  unfold CPoint.add
  simp only
  linear_combination (q.x * q.x + q.y * q.y) * hp + hq

theorem onCircle_pow {p : PointF} (hp : OnCircle p) : ∀ n, OnCircle (p ^ n)
  | 0 => by
    rw [pow_zero, CPoint.one_def]
    unfold OnCircle CPoint.zero
    simp
  | n + 1 => by
    rw [pow_succ]
    exact onCircle_mul (onCircle_pow hp n) hp

/-- On the circle, the conjugate is the group inverse. -/
theorem mul_conjugate {p : PointF} (hp : OnCircle p) :
    p * p.conjugate = 1 := by
  unfold OnCircle at hp
  show p.add p.conjugate = CPoint.zero
  unfold CPoint.add CPoint.conjugate CPoint.zero
  refine CPoint.ext' ?_ ?_
  · show p.x * p.x - p.y * -p.y = 1
    linear_combination hp
  · show p.x * -p.y + p.y * p.x = 0
    ring

/-- Inverses are unique in the circle monoid. -/
theorem inv_unique {a b c : PointF} (hb : a * b = 1) (hc : a * c = 1) : b = c := by
  calc b = b * (a * c) := by rw [hc, mul_one]
    _ = (a * b) * c := by rw [← mul_assoc, mul_comm b a]
    _ = c := by rw [hb, one_mul]

/-- The generator's order divides `2³¹`: `gen^(2³¹) = 1`. -/
theorem gen_pow_order : M31_CIRCLE_GEN ^ (2 ^ 31) = 1 := by
  have h := gen_order
  rw [show M31_CIRCLE_GEN = M31_CIRCLE_GEN.smul 1 from by
      rw [CPoint.smul_eq_pow, pow_one]] at h
  rw [CPoint.repeatedDouble_eq_smul, CPoint.smul_eq_pow, one_mul] at h
  rw [h, CPoint.one_def]

theorem onCircle_toPoint (i : ℕ) : OnCircle (PIdx.toPoint i) := by
  unfold PIdx.toPoint
  rw [CPoint.smul_eq_pow]
  exact onCircle_pow onCircle_gen _

/-- `gen^·` only depends on the exponent mod the order. -/
theorem gen_pow_mod (x y : ℕ) (hxy : x % 2 ^ 31 = y % 2 ^ 31) :
    M31_CIRCLE_GEN ^ x = M31_CIRCLE_GEN ^ y := by
  rw [← Nat.div_add_mod x (2 ^ 31), ← Nat.div_add_mod y (2 ^ 31),
    pow_add, pow_add, pow_mul, pow_mul, gen_pow_order, one_pow, one_pow, hxy]

/-- `toPoint` is additive (the reductions cancel through the order). -/
theorem toPoint_add (a b : ℕ) :
    PIdx.toPoint (PIdx.add' a b) = PIdx.toPoint a * PIdx.toPoint b := by
  unfold PIdx.add' PIdx.toPoint PIdx.reduce circleOrder
  rw [CPoint.smul_eq_pow, CPoint.smul_eq_pow, CPoint.smul_eq_pow, ← pow_add]
  exact gen_pow_mod _ _ (by omega)

/-- `toPoint` of a negated index is the conjugate point. -/
theorem toPoint_neg (i : ℕ) :
    PIdx.toPoint (PIdx.neg' i) = (PIdx.toPoint i).conjugate := by
  have hinv : PIdx.toPoint i * PIdx.toPoint (PIdx.neg' i) = 1 := by
    rw [← toPoint_add]
    simp only [PIdx.add', PIdx.neg', PIdx.toPoint, PIdx.reduce, circleOrder]
    rw [CPoint.smul_eq_pow]
    have h0 : (i + ((2 : ℕ) ^ 31 - i % 2 ^ 31) % 2 ^ 31) % 2 ^ 31 % 2 ^ 31 = 0 := by
      omega
    rw [h0, pow_zero, CPoint.one_def]
  exact inv_unique hinv (mul_conjugate (onCircle_toPoint i))

/-! ### Digit extraction and bit reversal -/

/-- Digit `k` of a bit sum. -/
theorem digit_of_sum {b : ℕ → ℕ} (hb : ∀ i, b i ≤ 1) (L k : ℕ) (hk : k < L) :
    (∑ i ∈ range L, b i * 2 ^ i) / 2 ^ k % 2 = b k := by
  have hsplit : ∑ i ∈ range L, b i * 2 ^ i
      = (∑ i ∈ range k, b i * 2 ^ i) + b k * 2 ^ k
        + ∑ i ∈ Ico (k + 1) L, b i * 2 ^ i := by
    rw [← Finset.sum_range_succ]
    exact (Finset.sum_range_add_sum_Ico _ (by omega)).symm
  have hhi : ∑ i ∈ Ico (k + 1) L, b i * 2 ^ i
      = 2 ^ (k + 1) * ∑ j ∈ range (L - (k + 1)), b (k + 1 + j) * 2 ^ j := by
    rw [Finset.sum_Ico_eq_sum_range, Finset.mul_sum]
    exact Finset.sum_congr rfl fun j _ => by
      rw [pow_add]
      ring
  have hlow : (∑ i ∈ range k, b i * 2 ^ i) < 2 ^ k := by
    have hle : ∀ i ∈ range k, b i * 2 ^ i ≤ 1 * 2 ^ i := fun i _ =>
      Nat.mul_le_mul_right _ (hb i)
    have h1 := Finset.sum_le_sum hle
    have h2 : ∑ i ∈ range k, 1 * 2 ^ i = 2 ^ k - 1 := by
      simpa using BitDecomp.sum_two_pow k
    have h3 : (0 : ℕ) < 2 ^ k := Nat.two_pow_pos k
    omega
  rw [hsplit, hhi]
  set lo := ∑ i ∈ range k, b i * 2 ^ i
  set hi := ∑ j ∈ range (L - (k + 1)), b (k + 1 + j) * 2 ^ j
  have harr : lo + b k * 2 ^ k + 2 ^ (k + 1) * hi
      = lo + 2 ^ k * (b k + 2 * hi) := by ring
  rw [harr, Nat.add_mul_div_left _ _ (Nat.two_pow_pos k),
    Nat.div_eq_of_lt hlow]
  have := hb k
  omega

theorem foldl_add_range (f : ℕ → ℕ) :
    ∀ (n acc : ℕ), (List.range n).foldl (fun a k => a + f k) acc
      = acc + ∑ k ∈ range n, f k := by
  intro n
  induction n with
  | zero => intro acc; simp
  | succ n ih =>
    intro acc
    rw [List.range_succ, List.foldl_append, ih acc, Finset.sum_range_succ]
    simp [Nat.add_assoc]

/-- The spec's `bitReverseIndex` as a sum over digits. -/
theorem bitReverseIndex_eq_sum (pos L : ℕ) :
    bitReverseIndex pos L
      = ∑ k ∈ range L, (pos / 2 ^ k % 2) * 2 ^ (L - 1 - k) := by
  unfold bitReverseIndex
  rw [foldl_add_range (fun k => (pos / 2 ^ k % 2) * 2 ^ (L - 1 - k)) L 0]
  simp

/-! ### The bridge -/

/-- The reversed-bit coset offset: `Σ_{t<L−1} b(t+1)·2^(L−2−t)`. -/
def mRest (b : ℕ → ℕ) (L : ℕ) : ℕ :=
  ∑ t ∈ range (L - 1), b (t + 1) * 2 ^ (L - 2 - t)

theorem mRest_lt {b : ℕ → ℕ} (hb : ∀ i, b i ≤ 1) {L : ℕ} (hL2 : 2 ≤ L) :
    mRest b L < 2 ^ (L - 1) := by
  unfold mRest
  have hle : ∀ t ∈ range (L - 1), b (t + 1) * 2 ^ (L - 2 - t) ≤ 1 * 2 ^ (L - 2 - t) :=
    fun t _ => Nat.mul_le_mul_right _ (hb (t + 1))
  have h1 := Finset.sum_le_sum hle
  have h2 : ∑ t ∈ range (L - 1), 1 * 2 ^ (L - 2 - t) = 2 ^ (L - 1) - 1 := by
    simp only [one_mul]
    rw [show ∑ t ∈ range (L - 1), 2 ^ (L - 2 - t)
      = ∑ t ∈ range (L - 1), 2 ^ (L - 1 - 1 - t) from by
        exact Finset.sum_congr rfl fun t _ => by congr 1 <;> omega,
      Finset.sum_range_reflect (fun t => 2 ^ t) (L - 1)]
    exact BitDecomp.sum_two_pow (L - 1)
  have h3 : (0 : ℕ) < 2 ^ (L - 1) := Nat.two_pow_pos _
  omega

/-- The bit-reversed query position splits into the top bit and `mRest`. -/
theorem bitrev_split {b : ℕ → ℕ} (hb : ∀ i, b i ≤ 1) {L : ℕ} (hL2 : 2 ≤ L) :
    bitReverseIndex (∑ i ∈ range L, b i * 2 ^ i) L
      = b 0 * 2 ^ (L - 1) + mRest b L := by
  obtain ⟨M, rfl⟩ : ∃ M, L = M + 1 := ⟨L - 1, by omega⟩
  rw [bitReverseIndex_eq_sum,
    Finset.sum_congr rfl fun k hk => by
      rw [digit_of_sum hb (M + 1) k (Finset.mem_range.mp hk)]]
  rw [Finset.sum_range_succ' (fun k => b k * 2 ^ (M + 1 - 1 - k)) M]
  unfold mRest
  have hexp : ∀ t, b (t + 1) * 2 ^ (M + 1 - 1 - (t + 1))
      = b (t + 1) * 2 ^ (M + 1 - 2 - t) := fun t => by
    congr 2 <;> omega
  rw [Finset.sum_congr rfl fun t _ => hexp t]
  simp only [Nat.sub_zero, Nat.add_sub_cancel]
  omega

/-- 2 ≤ L ≤ 30: the coset index of the gadget's accumulated point. -/
theorem index_arith {b : ℕ → ℕ} {L : ℕ}
    (hL2 : 2 ≤ L) (hL30 : L ≤ 30) :
    subgroupGen (L + 1) + 2 ^ (32 - L) * mRest b L = queryIndex b L := by
  unfold queryIndex mRest subgroupGen M31_CIRCLE_LOG_ORDER
  congr 1
  rw [Finset.mul_sum]
  refine Finset.sum_congr rfl fun t ht => ?_
  have ht' := Finset.mem_range.mp ht
  rw [show 2 ^ (32 - L) * (b (t + 1) * 2 ^ (L - 2 - t))
    = b (t + 1) * (2 ^ (32 - L) * 2 ^ (L - 2 - t)) from by ring,
    ← pow_add, show 32 - L + (L - 2 - t) = 31 - (t + 1) from by omega]

theorem queryIndex_lt {b : ℕ → ℕ} (hb : ∀ i, b i ≤ 1) {L : ℕ}
    (hL2 : 2 ≤ L) (hL30 : L ≤ 30) : queryIndex b L < 2 ^ 31 := by
  rw [← index_arith (b := b) hL2 hL30]
  have hm := mRest_lt hb hL2
  have hmul : 2 ^ (32 - L) * mRest b L ≤ 2 ^ (32 - L) * (2 ^ (L - 1) - 1) :=
    Nat.mul_le_mul_left _ (by omega)
  have hpow : 2 ^ (32 - L) * 2 ^ (L - 1) = 2 ^ 31 := by
    rw [← pow_add]
    congr 1
    omega
  have hgen : subgroupGen (L + 1) = 2 ^ (30 - L) := by
    unfold subgroupGen M31_CIRCLE_LOG_ORDER
    congr 1
    omega
  have hgenlt : (2 : ℕ) ^ (30 - L) < 2 ^ (32 - L) :=
    Nat.pow_lt_pow_right (by norm_num) (by omega)
  have hdistrib : 2 ^ (32 - L) * (2 ^ (L - 1) - 1)
      = 2 ^ 31 - 2 ^ (32 - L) := by
    rw [Nat.mul_sub, hpow, Nat.mul_one]
  have hX : 2 ^ (32 - L) * mRest b L ≤ 2 ^ 31 - 2 ^ (32 - L) := by
    rw [← hdistrib]
    exact hmul
  have h32 : (2 : ℕ) ^ (32 - L) ≤ 2 ^ 31 :=
    Nat.pow_le_pow_right (by norm_num) (by omega)
  rw [hgen]
  omega

/-- **The bridge**: the gadget's point (`gen^queryIndex`, conjugated when
bit 0 is set) is the spec's domain point at the bit-reversed query
position — exactly the point `Quotients.friAnswers` evaluates at. -/
theorem queryIndex_eq_domainPoint {b : ℕ → ℕ} (hb : ∀ i, b i ≤ 1) {L : ℕ}
    (hL2 : 2 ≤ L) (hL30 : L ≤ 30) :
    (if b 0 = 0
     then M31_CIRCLE_GEN.smul (queryIndex b L)
     else (M31_CIRCLE_GEN.smul (queryIndex b L)).conjugate)
      = (canonicDomain L).at'
          (bitReverseIndex (∑ i ∈ range L, b i * 2 ^ i) L) := by
  rw [bitrev_split hb hL2]
  have hm := mRest_lt hb hL2
  have hq := queryIndex_lt hb hL2 hL30
  have hhalfsize : (canonicDomain L).halfCoset.size = 2 ^ (L - 1) := rfl
  have hstep : (canonicDomain L).halfCoset.stepSize = 2 ^ (32 - L) := by
    show subgroupGen (L - 1) = 2 ^ (32 - L)
    unfold subgroupGen M31_CIRCLE_LOG_ORDER
    congr 1
    omega
  have hinit : (canonicDomain L).halfCoset.initialIndex = subgroupGen (L + 1) := by
    show PIdx.reduce (subgroupGen ((L - 1) + 2)) = subgroupGen (L + 1)
    rw [show (L - 1) + 2 = L + 1 from by omega]
    unfold PIdx.reduce circleOrder subgroupGen M31_CIRCLE_LOG_ORDER
    apply Nat.mod_eq_of_lt
    exact Nat.pow_lt_pow_right (by norm_num) (by omega)
  have hidx : (canonicDomain L).halfCoset.indexAt (mRest b L) = queryIndex b L := by
    unfold Coset.indexAt PIdx.add' PIdx.mul'
    rw [hinit, hstep]
    have harith := index_arith (b := b) hL2 hL30
    have hfle : 2 ^ (32 - L) * mRest b L ≤ queryIndex b L :=
      Nat.le.intro (by rw [Nat.add_comm]; exact harith)
    have hmod : 2 ^ (32 - L) * mRest b L % circleOrder
        = 2 ^ (32 - L) * mRest b L := by
      apply Nat.mod_eq_of_lt
      unfold circleOrder
      omega
    rw [hmod, harith]
    apply Nat.mod_eq_of_lt
    unfold circleOrder
    exact hq
  by_cases h0 : b 0 = 0
  · rw [if_pos h0, h0]
    unfold CircleDomain.at' CircleDomain.indexAt
    rw [if_pos (by rw [hhalfsize]; omega)]
    rw [show (0 : ℕ) * 2 ^ (L - 1) + mRest b L = mRest b L from by omega, hidx]
    unfold PIdx.toPoint PIdx.reduce circleOrder
    rw [Nat.mod_eq_of_lt hq]
  · rw [if_neg h0]
    have hb0 : b 0 = 1 := by have := hb 0; omega
    rw [hb0]
    unfold CircleDomain.at' CircleDomain.indexAt
    rw [if_neg (by rw [hhalfsize]; omega)]
    rw [show 1 * 2 ^ (L - 1) + mRest b L - (canonicDomain L).halfCoset.size
      = mRest b L from by rw [hhalfsize]; omega, hidx, toPoint_neg]
    congr 1
    unfold PIdx.toPoint PIdx.reduce circleOrder
    rw [Nat.mod_eq_of_lt hq]

/-- **The exported query-selection theorem.** If `select_queries`' gates
hold, then per lane `j` with drawn word `q := (lane input j).val`: the
gadget's point is the spec's canonic-domain point at
`bitReverseIndex (q % 2^L) L` — precisely the domain point
`Quotients.friAnswers` evaluates for query position `q % 2^L` (the
native `drawQueries` mask). -/
theorem selectQueries_domainPoint {ρ : ℕ → QM31} {zero : ℕ}
    {input : Gadgets.SimdReg} {L n : ℕ} (hL2 : 2 ≤ L) (hL30 : L ≤ 30)
    (hzero : ρ zero = 0) (hcov : input.Covers)
    (h : Gates.AllHold ρ (Gadgets.selectQueriesPoint zero input L n).ops)
    (j : ℕ) (hj : j < input.len) :
    Gadgets.PointSimd.lane ρ (Gadgets.selectQueriesPoint zero input L n).res.2 j
      = (canonicDomain L).at'
          (bitReverseIndex ((SimdReg.lane ρ input j).val % 2 ^ L) L) := by
  obtain ⟨hnat, hpoint⟩ :=
    Gadgets.selectQueriesPoint_sound hL2 hL30 hzero hcov h j hj
  have hbits31 : ∀ i, i < 31 →
      SimdReg.lane ρ ((Gadgets.selectQueriesPoint zero input L n).res.1.getD i
        Gadgets.dummySimd) j = 0 ∨
      SimdReg.lane ρ ((Gadgets.selectQueriesPoint zero input L n).res.1.getD i
        Gadgets.dummySimd) j = 1 := by
    have hpre : Gates.AllHold ρ (Gadgets.extractBits31 zero input n).ops := by
      unfold Gadgets.selectQueriesPoint at h
      rw [Gates.allHold_append, Gates.allHold_append, Gates.allHold_append,
        Gates.allHold_append, Gates.allHold_append] at h
      exact h.1.1.1.1.1
    exact fun i hi => (Gadgets.extractBits31_sound hzero hcov hpre j hj).1 i hi
  have hbN01 : ∀ i, Gadgets.bitNat ρ
      ((Gadgets.selectQueriesPoint zero input L n).res.1.getD i Gadgets.dummySimd) j ≤ 1 := by
    intro i
    unfold Gadgets.bitNat
    split <;> omega
  -- `Σ_{i<L} bitNatᵢ·2^i = q % 2^L`: the truncated digits.
  have hq : (∑ i ∈ range L, Gadgets.bitNat ρ
        ((Gadgets.selectQueriesPoint zero input L n).res.1.getD i Gadgets.dummySimd) j
        * 2 ^ i)
      = (SimdReg.lane ρ input j).val % 2 ^ L := by
    have hmod := BitDecomp.natOf_mod (fun i => SimdReg.lane ρ
      ((Gadgets.selectQueriesPoint zero input L n).res.1.getD i Gadgets.dummySimd) j)
      31 L (by omega) hbits31
    have hLsum : BitDecomp.natOf (fun i => SimdReg.lane ρ
        ((Gadgets.selectQueriesPoint zero input L n).res.1.getD i Gadgets.dummySimd) j) L
        = ∑ i ∈ range L, Gadgets.bitNat ρ
          ((Gadgets.selectQueriesPoint zero input L n).res.1.getD i Gadgets.dummySimd) j
          * 2 ^ i := by
      unfold BitDecomp.natOf
      refine Finset.sum_congr rfl fun i hi => ?_
      have hi31 : i < 31 := by have := Finset.mem_range.mp hi; omega
      rw [BitDecomp.bitVal_eq (hbits31 i hi31)]
      rfl
    rw [← hLsum, hmod, hnat]
  rw [hpoint, ← hq, ← queryIndex_eq_domainPoint hbN01 hL2 hL30]
  by_cases hb0 : SimdReg.lane ρ ((Gadgets.selectQueriesPoint zero input L n).res.1.getD 0
      Gadgets.dummySimd) j = 0
  · rw [if_pos hb0, if_pos (by unfold Gadgets.bitNat; rw [if_pos hb0])]
  · rw [if_neg hb0, if_neg (by unfold Gadgets.bitNat; rw [if_neg hb0]; omega)]

end StwoVerifier.Bridge
