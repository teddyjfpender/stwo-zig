/-
**Statement-phase SIMD gadgets** of `stark_verifier/verify.zig`:
`extract_bits` at `k ≤ 30` bits (the range check), `simd.pow2`, and
`validate_and_compute_component_sizes`.

`extractBitsK_sound`: the `k` output lanes are bits and denote the input
lane's canonical value, so that value is below `2^k` — the range check
the statement phase relies on (no canonicity side constraint is needed
below 31 bits: `2^k ≤ 2^30 < P`).
`pow2G_sound`: with bit lanes `b`, the result lane is `2^(Σ bᵢ 2ⁱ)`.
`validateSizesG_sound`: component log sizes below `2^5`, never above the
trace log, and the size lanes are `2^log`.
-/
import StwoVerifier.SelectQueries
import StwoVerifier.FriGadgets

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates Finset

/-! ### `extract_bits` below 31 bits -/

/-- `extract_bits(input, k)`, `1 ≤ k ≤ 30`: the interned `2⁻¹`, `k − 1`
LSB rounds, the top residue asserted to be a bit. -/
def extractBitsK (zero : ℕ) (input : SimdReg) (k : ℕ) (n : ℕ) : Out (List SimdReg) :=
  let r := rounds zero n input (k - 1) (n + 1)
  let ab := assertBits zero r.res.2 r.next
  ⟨.const n (QM31.fromBase (2 : F)⁻¹) :: (r.ops ++ ab.ops), r.res.1 ++ [r.res.2], ab.next⟩

theorem extractBitsK_shapes (zero : ℕ) (input : SimdReg) (k n : ℕ) (hk : 1 ≤ k) :
    (extractBitsK zero input k n).res.length = k ∧
    ∀ b ∈ (extractBitsK zero input k n).res,
      b.len = input.len ∧ b.data.length = input.data.length := by
  obtain ⟨hb, hl, hd⟩ := rounds_shapes (zero := zero) (invTwo := n) (k - 1) input (n + 1)
  refine ⟨?_, ?_⟩
  · show ((rounds zero n input (k - 1) (n + 1)).res.1 ++ [_]).length = k
    rw [List.length_append, rounds_len, List.length_singleton]; omega
  · intro b hm
    rcases List.mem_append.mp hm with hm | hm
    · exact hb b hm
    · rw [List.mem_singleton.mp hm]; exact ⟨hl, hd⟩

theorem pow_two_lt_P {k : ℕ} (hk : k ≤ 30) : 2 ^ k < P := by
  have : 2 ^ k ≤ 2 ^ 30 := Nat.pow_le_pow_right (by norm_num) hk
  unfold P; omega

/-- **`extract_bits` at `k ≤ 30` bits** (per lane): bits, denoting the
input lane's canonical value. -/
theorem extractBitsK_sound {ρ : ℕ → QM31} {zero : ℕ} {input : SimdReg} {k n : ℕ}
    (hzero : ρ zero = 0) (hcov : input.Covers) (hk1 : 1 ≤ k) (hk : k ≤ 30)
    (h : AllHold ρ (extractBitsK zero input k n).ops) (j : ℕ) (hj : j < input.len) :
    (∀ i, i < k →
      SimdReg.lane ρ ((extractBitsK zero input k n).res.getD i dummySimd) j = 0 ∨
      SimdReg.lane ρ ((extractBitsK zero input k n).res.getD i dummySimd) j = 1) ∧
    BitDecomp.natOf
      (fun i => SimdReg.lane ρ ((extractBitsK zero input k n).res.getD i dummySimd) j) k
      = (SimdReg.lane ρ input j).val := by
  rw [show (extractBitsK zero input k n).ops =
    .const n (QM31.fromBase (2 : F)⁻¹) :: _ from rfl, allHold_cons] at h
  obtain ⟨hinv', h⟩ := h
  simp only [Holds] at hinv'
  rw [allHold_append] at h
  obtain ⟨hr, hab⟩ := h
  set r := rounds zero n input (k - 1) (n + 1) with hrdef
  obtain ⟨hrlen, hrcov, hrfinlen, hrlane⟩ :=
    rounds_sound hzero hinv' (k - 1) input (n + 1) hcov hr
  obtain ⟨hbitslow, hsumlow⟩ := hrlane j hj
  have htop := assertBits_sound hzero hrcov hab j (by rw [hrfinlen]; exact hj)
  have hreslist : (extractBitsK zero input k n).res = r.res.1 ++ [r.res.2] := rfl
  have hgetlow : ∀ i, i < k - 1 →
      (r.res.1 ++ [r.res.2]).getD i dummySimd = r.res.1.getD i dummySimd := by
    intro i hi
    rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
      List.getElem?_append_left (by rw [hrlen]; omega)]
  have hgettop : (r.res.1 ++ [r.res.2]).getD (k - 1) dummySimd = r.res.2 := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by rw [hrlen]), hrlen,
      Nat.sub_self]
    rfl
  have hbits : ∀ i, i < k →
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j = 0 ∨
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j = 1 := by
    intro i hi
    by_cases htk : i = k - 1
    · rw [htk, hgettop]; exact htop
    · rw [hgetlow i (by omega)]; exact hbitslow i (by omega)
  have hsum : SimdReg.lane ρ input j = ∑ i ∈ Finset.range k,
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j * 2 ^ i := by
    have hsplit := Finset.sum_range_succ (fun i =>
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j * 2 ^ i) (k - 1)
    rw [show k - 1 + 1 = k by omega] at hsplit
    rw [hsplit, hgettop, Finset.sum_congr rfl (fun i hi => by
        rw [hgetlow i (Finset.mem_range.mp hi)]), hsumlow]
    ring
  rw [hreslist]
  refine ⟨hbits, ?_⟩
  have hlt := BitDecomp.natOf_lt _ k hbits
  have hcast := BitDecomp.cast_natOf
    (fun i => SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j) k
  rw [← hsum] at hcast
  rw [← hcast, ZMod.val_cast_of_lt (lt_trans hlt (pow_two_lt_P hk))]

/-! ### `simd.pow2` -/

/-- The bit loop of `pow2`: square-and-select. (The emitter skips the last
squaring; the extra gate here defines a fresh register only.) -/
def pow2Loop : List SimdReg → SimdReg → ℕ → ℕ → Out SimdReg
  | [], res, _, n => ⟨[], res, n⟩
  | b :: bs, res, power, n =>
    let m := simdScalarMul res power n
    let s := simdSelect b res m.res m.next
    let rest := pow2Loop bs s.res s.next (s.next + 1)
    ⟨m.ops ++ s.ops ++ [.mul s.next power power] ++ rest.ops, rest.res, rest.next⟩

/-- `pow2`: `one`, the constant `2`, then the loop. -/
def pow2G (bits : List SimdReg) (count len n : ℕ) : Out SimdReg :=
  let one := constSplat 1 count len n
  let l := pow2Loop bits one.res (n + 1) (n + 2)
  ⟨one.ops ++ [.const (n + 1) (QM31.fromBase 2)] ++ l.ops, l.res, l.next⟩

theorem fromBase_mul' (a b : F) :
    QM31.fromBase a * QM31.fromBase b = QM31.fromBase (a * b) :=
  (map_mul baseHom a b).symm

theorem pow2Loop_sound {ρ : ℕ → QM31} {count len : ℕ} (j : ℕ) (hj : j < len)
    (hcl : len ≤ 4 * count) :
    ∀ (bits : List SimdReg) (res : SimdReg) (power n : ℕ) (e i : ℕ),
      (∀ b ∈ bits, BitShape b len count) →
      (∀ b ∈ bits, SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1) →
      res.len = len → res.data.length = count →
      SimdReg.lane ρ res j = 2 ^ e →
      ρ power = QM31.fromBase (2 ^ (2 ^ i)) →
      AllHold ρ (pow2Loop bits res power n).ops →
      (pow2Loop bits res power n).res.len = len ∧
      (pow2Loop bits res power n).res.data.length = count ∧
      SimdReg.lane ρ (pow2Loop bits res power n).res j
        = 2 ^ (e + ∑ t ∈ range bits.length,
            (SimdReg.lane ρ (bits.getD t dummySimd) j).val * 2 ^ (i + t)) := by
  intro bits
  induction bits with
  | nil =>
    intro res power n e i _ _ hrl hrd hres _ _
    exact ⟨hrl, hrd, by show SimdReg.lane ρ res j = _; simpa using hres⟩
  | cons b bs ih =>
    intro res power n e i hshape hbit hrl hrd hres hpow h
    set m := simdScalarMul res power n with hmdef
    set s := simdSelect b res m.res m.next with hsdef
    rw [show (pow2Loop (b :: bs) res power n).ops =
      m.ops ++ s.ops ++ [.mul s.next power power] ++
        (pow2Loop bs s.res s.next (s.next + 1)).ops from rfl,
      allHold_append, allHold_append, allHold_append] at h
    obtain ⟨⟨⟨hm, hs⟩, hsq⟩, hrest⟩ := h
    have hsq' : ρ s.next = ρ power * ρ power := hsq _ List.mem_cons_self
    have hbs := hshape b List.mem_cons_self
    have hrcov : res.Covers := by unfold SimdReg.Covers; rw [hrl, hrd]; exact hcl
    have hmdata : m.res.data.length = count := by
      show (lanewise2 (fun o x y => Op.mul o x y) res.data
        (res.data.map fun _ => power) n).res.length = count
      rw [lanewise2_length, List.length_map, hrd, Nat.min_self]
    have hsh : SelShape b res m.res :=
      ⟨by unfold SimdReg.Covers; rw [hbs.lenEq, hbs.dataEq]; exact hcl,
       hrcov, simdScalarMul_covers hrcov, by rw [hrl, hbs.lenEq],
       by show res.len = b.len; rw [hrl, hbs.lenEq],
       by rw [hbs.lenEq, hrd]; exact hcl, by rw [hbs.lenEq, hmdata]; exact hcl⟩
    have hslane := simdSelect_lane_bit hsh hs j (by rw [hbs.lenEq]; exact hj)
      (hbit b List.mem_cons_self)
    have hmlane := simdScalarMul_lane hrcov hpow hm j (by rw [hrl]; exact hj)
    have hsdata : s.res.data.length = count := by
      rw [hsdef, simdSelect_data_len, hrd, hbs.dataEq, hmdata]; simp
    have hpow' : ρ s.next = QM31.fromBase (2 ^ (2 ^ (i + 1))) := by
      rw [hsq', hpow, fromBase_mul', ← pow_add, ← two_mul, pow_succ]
      ring_nf
    -- The selected lane: `2^(e + b·2^i)`.
    have hsval : SimdReg.lane ρ s.res j
        = 2 ^ (e + (SimdReg.lane ρ b j).val * 2 ^ i) := by
      rw [hslane, hmlane, hres]
      rcases hbit b List.mem_cons_self with h0 | h1
      · rw [if_pos h0, h0]; simp
      · rw [if_neg (by rw [h1]; exact one_ne_zero), h1, BitDecomp.val_one, one_mul,
          pow_add, mul_comm]
    obtain ⟨hl, hd, hv⟩ := ih s.res s.next (s.next + 1)
      (e + (SimdReg.lane ρ b j).val * 2 ^ i) (i + 1)
      (fun b' hb' => hshape b' (List.mem_cons_of_mem _ hb'))
      (fun b' hb' => hbit b' (List.mem_cons_of_mem _ hb'))
      (by rw [hsdef, simdSelect_len, hrl]) hsdata hsval hpow' hrest
    refine ⟨hl, hd, ?_⟩
    show SimdReg.lane ρ (pow2Loop bs s.res s.next (s.next + 1)).res j = _
    rw [hv, List.length_cons, Finset.sum_range_succ']
    simp only [List.getD_cons_succ, List.getD_cons_zero, Nat.add_zero]
    congr 1
    rw [Finset.sum_congr rfl (fun t _ => by rw [show i + 1 + t = i + (t + 1) by omega])]
    ring

/-- **`pow2`**: the result lane is `2` to the bits' value. -/
theorem pow2G_sound {ρ : ℕ → QM31} {bits : List SimdReg} {count len n : ℕ}
    (hcl : len ≤ 4 * count)
    (hshape : ∀ b ∈ bits, BitShape b len count)
    (h : AllHold ρ (pow2G bits count len n).ops) (j : ℕ) (hj : j < len)
    (hbit : ∀ b ∈ bits, SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1) :
    (pow2G bits count len n).res.len = len ∧
    (pow2G bits count len n).res.data.length = count ∧
    SimdReg.lane ρ (pow2G bits count len n).res j
      = 2 ^ (∑ t ∈ range bits.length,
          (SimdReg.lane ρ (bits.getD t dummySimd) j).val * 2 ^ t) := by
  rw [show (pow2G bits count len n).ops =
    (constSplat 1 count len n).ops ++ [.const (n + 1) (QM31.fromBase 2)] ++
      (pow2Loop bits (constSplat 1 count len n).res (n + 1) (n + 2)).ops from rfl,
    allHold_append, allHold_append] at h
  obtain ⟨⟨hone, hc⟩, hl⟩ := h
  have hc' : ρ (n + 1) = QM31.fromBase 2 := hc _ List.mem_cons_self
  have hj4 : j / 4 < count := by omega
  have honelane := constSplat_lane hone j hj4
  obtain ⟨h1, h2, h3⟩ := pow2Loop_sound j hj hcl bits (constSplat 1 count len n).res
    (n + 1) (n + 2) 0 0 hshape hbit rfl (by simp [constSplat])
    (by rw [honelane, pow_zero]) (by rw [hc']; norm_num) hl
  refine ⟨h1, h2, ?_⟩
  show SimdReg.lane ρ (pow2Loop bits (constSplat 1 count len n).res (n + 1) (n + 2)).res j = _
  rw [h3, Nat.zero_add]
  simp

/-! ### `validate_and_compute_component_sizes` -/

/-- Log sizes and `log_trace − log` both 5-bit range-checked; the sizes
are `pow2` of the log-size bits. -/
def validateSizesG (zero : ℕ) (ls : SimdReg) (logTrace : ℕ) (n : ℕ) :
    Out (List SimdReg × SimdReg) :=
  let b5 := extractBitsK zero ls 5 n
  let lt := constSplat (logTrace : F) ls.data.length ls.len b5.next
  let diff := simdSub lt.res ls lt.next
  let d5 := extractBitsK zero diff.res 5 diff.next
  let sz := pow2G b5.res ls.data.length ls.len d5.next
  ⟨b5.ops ++ lt.ops ++ diff.ops ++ d5.ops ++ sz.ops, (b5.res, sz.res), sz.next⟩

/-- A field difference of two small naturals has a small value only if
the subtrahend is not larger. -/
theorem sub_val_small {a b : ℕ} (ha : a < 2 ^ 5) (hb : b < 2 ^ 5)
    (h : (((a : ℕ) : F) - ((b : ℕ) : F)).val < 2 ^ 5) : b ≤ a := by
  by_contra hlt
  push Not at hlt
  have hP : P = 2147483647 := rfl
  have hcast : (((a : ℕ) : F) - ((b : ℕ) : F)) = ((P - (b - a) : ℕ) : F) := by
    rw [Nat.cast_sub (by rw [hP]; omega), ZMod.natCast_self, zero_sub,
      Nat.cast_sub (le_of_lt hlt)]
    ring
  rw [hcast, ZMod.val_cast_of_lt (by rw [hP]; omega)] at h
  rw [hP] at h
  omega

set_option maxHeartbeats 800000 in
/-- **Component sizes**: every log-size lane is below `2^5` and at most
the trace log, and the size lane is `2^log`. -/
theorem validateSizesG_sound {ρ : ℕ → QM31} {zero : ℕ} {ls : SimdReg} {logTrace n : ℕ}
    (hzero : ρ zero = 0) (hcov : ls.Covers) (hlt : logTrace < 2 ^ 5)
    (h : AllHold ρ (validateSizesG zero ls logTrace n).ops) (j : ℕ) (hj : j < ls.len) :
    (SimdReg.lane ρ ls j).val < 2 ^ 5 ∧ (SimdReg.lane ρ ls j).val ≤ logTrace ∧
    (validateSizesG zero ls logTrace n).res.2.len = ls.len ∧
    (validateSizesG zero ls logTrace n).res.2.data.length = ls.data.length ∧
    SimdReg.lane ρ (validateSizesG zero ls logTrace n).res.2 j
      = 2 ^ (SimdReg.lane ρ ls j).val := by
  set b5 := extractBitsK zero ls 5 n with hb5
  set lt := constSplat (logTrace : F) ls.data.length ls.len b5.next with hltdef
  set diff := simdSub lt.res ls lt.next with hdiff
  set d5 := extractBitsK zero diff.res 5 diff.next with hd5
  rw [show (validateSizesG zero ls logTrace n).ops =
    b5.ops ++ lt.ops ++ diff.ops ++ d5.ops ++
      (pow2G b5.res ls.data.length ls.len d5.next).ops from rfl,
    allHold_append, allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨⟨hb, hl⟩, hd⟩, hd5'⟩, hp⟩ := h
  obtain ⟨hbits, hnat⟩ := extractBitsK_sound hzero hcov (by norm_num) (by norm_num) hb j hj
  have hval : (SimdReg.lane ρ ls j).val < 2 ^ 5 := by
    rw [← hnat]; exact BitDecomp.natOf_lt _ 5 hbits
  have hltcov : lt.res.Covers := constSplat_covers hcov
  have hdcov : diff.res.Covers := simdSub_covers hltcov hcov
  have hdlane := simdSub_lane hltcov hcov hd j hj
  have hltlane : SimdReg.lane ρ lt.res j = (logTrace : F) :=
    constSplat_lane hl j (by unfold SimdReg.Covers at hcov; omega)
  obtain ⟨-, hdnat⟩ := extractBitsK_sound hzero hdcov (by norm_num) (by norm_num) hd5' j hj
  have hdval : (SimdReg.lane ρ diff.res j).val < 2 ^ 5 := by
    obtain ⟨hdbits, -⟩ := extractBitsK_sound hzero hdcov (by norm_num) (by norm_num) hd5' j hj
    rw [← hdnat]; exact BitDecomp.natOf_lt _ 5 hdbits
  have hle : (SimdReg.lane ρ ls j).val ≤ logTrace := by
    rw [hdlane, hltlane] at hdval
    refine sub_val_small hlt hval ?_
    rwa [ZMod.natCast_val, ZMod.cast_id]
  obtain ⟨hshl, hshd⟩ := extractBitsK_shapes zero ls 5 n (by norm_num)
  obtain ⟨hpl, hpd, hpv⟩ := pow2G_sound (bits := b5.res) (count := ls.data.length)
    (len := ls.len) (n := d5.next) hcov
    (fun b hbm => ⟨(hshd b hbm).1, (hshd b hbm).2⟩) hp j hj
    (fun b hbm => by
      obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hbm
      have := hbits i (by rw [hshl] at hi; exact hi)
      rwa [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi] at this)
  refine ⟨hval, hle, hpl, hpd, ?_⟩
  show SimdReg.lane ρ (pow2G b5.res ls.data.length ls.len d5.next).res j = _
  rw [hpv, hshl, ← hnat]
  rfl

/-! ### One-hot size bits -/

theorem natOf_split (bits : ℕ → F) (t K : ℕ) (ht : t ≤ K) :
    BitDecomp.natOf bits K = BitDecomp.natOf bits t +
      2 ^ t * ∑ j ∈ range (K - t), (bits (t + j)).val * 2 ^ j := by
  unfold BitDecomp.natOf
  rw [← Finset.sum_range_add_sum_Ico _ ht, Finset.sum_Ico_eq_sum_range]
  congr 1
  rw [Finset.mul_sum]
  exact Finset.sum_congr rfl fun j _ => by rw [pow_add]; ring

/-- The `t`-th digit of a bit pattern's value is bit `t`. -/
theorem natOf_digit (bits : ℕ → F) (K t : ℕ) (ht : t < K)
    (hbits : ∀ i, i < K → bits i = 0 ∨ bits i = 1) :
    BitDecomp.natOf bits K / 2 ^ t % 2 = (bits t).val := by
  rw [natOf_split bits t K (le_of_lt ht)]
  have hlo := BitDecomp.natOf_lt bits t (fun i hi => hbits i (by omega))
  rw [Nat.add_mul_div_left _ _ (Nat.two_pow_pos t), Nat.div_eq_of_lt hlo, Nat.zero_add]
  obtain ⟨m, hm⟩ : ∃ m, K - t = m + 1 := ⟨K - t - 1, by omega⟩
  rw [hm, Finset.sum_range_succ']
  simp only [pow_zero, mul_one, Nat.add_zero]
  have hb := BitDecomp.bitVal_le (hbits t ht)
  rw [show (∑ i ∈ range m, (bits (t + (i + 1))).val * 2 ^ (i + 1))
      = 2 * ∑ i ∈ range m, (bits (t + (i + 1))).val * 2 ^ i from by
    rw [Finset.mul_sum]; exact Finset.sum_congr rfl fun i _ => by ring]
  omega

/-- Bits denoting `2^l` are one-hot at `l`. -/
theorem onehot_of_natOf (bits : ℕ → F) (K l : ℕ)
    (hbits : ∀ i, i < K → bits i = 0 ∨ bits i = 1)
    (hv : BitDecomp.natOf bits K = 2 ^ l) :
    ∀ t, t < K → bits t = if t = l then 1 else 0 := by
  intro t ht
  have hd := natOf_digit bits K t ht hbits
  rw [hv] at hd
  rcases hbits t ht with h0 | h1
  · rw [h0]
    by_cases htl : t = l
    · subst htl
      rw [h0, Nat.div_self (Nat.two_pow_pos t)] at hd
      simp at hd
    · rw [if_neg htl]
  · rw [h1, BitDecomp.val_one] at hd
    by_cases htl : t = l
    · rw [if_pos htl, h1]
    · exfalso
      rcases Nat.lt_or_gt_of_ne htl with hlt | hgt
      · rw [show l = t + (l - t) by omega, pow_add, Nat.mul_div_cancel_left _
          (Nat.two_pow_pos t)] at hd
        have : 2 ^ (l - t) % 2 = 0 := by
          rw [show l - t = (l - t - 1) + 1 by omega, pow_succ]; simp
        omega
      · rw [Nat.div_eq_of_lt (Nat.pow_lt_pow_right (by norm_num) hgt)] at hd
        simp at hd

end StwoVerifier.Gadgets
