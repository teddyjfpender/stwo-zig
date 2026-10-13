/-
**Shapes and bit facts of `select_queries`' outputs**, for the
decommit phases: 31 boolean bit vectors and a well-shaped point vector,
all over the input's lanes.
-/
import StwoVerifier.PhasePcs

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

set_option maxHeartbeats 1600000 in
theorem selectQueriesPoint_facts {ρ : ℕ → QM31} {zero : ℕ} {input : SimdReg} {L n : ℕ}
    (hL2 : 2 ≤ L) (hL30 : L ≤ 30) (hzero : ρ zero = 0) (hcov : input.Covers)
    (h : AllHold ρ (selectQueriesPoint zero input L n).ops) :
    (selectQueriesPoint zero input L n).res.1.length = 31 ∧
    (∀ b ∈ (selectQueriesPoint zero input L n).res.1, BitShape b input.len input.data.length) ∧
    (selectQueriesPoint zero input L n).res.2.Shape input.len input.data.length ∧
    ∀ j, j < input.len → ∀ i, i < 31 →
      SimdReg.lane ρ ((selectQueriesPoint zero input L n).res.1.getD i dummySimd) j = 0 ∨
      SimdReg.lane ρ ((selectQueriesPoint zero input L n).res.1.getD i dummySimd) j = 1 := by
  have h0 := h
  unfold selectQueriesPoint at h ⊢
  rw [allHold_append, allHold_append, allHold_append, allHold_append,
    allHold_append] at h
  obtain ⟨⟨⟨⟨⟨heb, hpoint0⟩, hlp⟩, hzs⟩, hny⟩, hysel⟩ := h
  set count := input.data.length with hcountdef
  set len := input.len with hlendef
  set eb := extractBits31 zero input n with hebdef
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
  set point0 := genPointSimd (L + 1) count len eb.next with hp0def
  set loopBits := (eb.res.drop 1).take (L - 1) with hlbdef
  set lp := buildLoop count len loopBits 1 point0.res point0.next with hlpdef
  have hlblen : loopBits.length = L - 1 := by
    rw [hlbdef, List.length_take, List.length_drop, heblen]
    omega
  have hcnt : len ≤ 4 * count := hcov
  have hp0shape : point0.res.Shape len count := genPointSimd_shape hcnt
  have hlbshapes : ∀ b ∈ loopBits, BitShape b len count := by
    intro b hb
    have hb' : b ∈ eb.res := by
      rw [hlbdef] at hb
      exact List.mem_of_mem_drop (List.mem_of_mem_take hb)
    obtain ⟨hl, hd⟩ := hebshape b hb'
    exact ⟨hl, hd⟩
  obtain ⟨hlpshape, -⟩ := buildLoop_lane loopBits 1 point0.res point0.next
    (by norm_num) (by rw [hlblen]; omega) hlbshapes hp0shape hlp
  obtain ⟨hlpx, hlpy, hlpdx, hlpdy, -⟩ := hlpshape
  have hbit0mem : eb.res.getD 0 dummySimd ∈ eb.res := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [heblen]; omega)]
    exact List.getElem_mem _
  obtain ⟨hb0len, hb0data⟩ := hebshape _ hbit0mem
  refine ⟨heblen, fun b hb => ⟨(hebshape b hb).1, (hebshape b hb).2⟩, ?_, fun j hj i hi =>
    (extractBits31_sound hzero hcov heb j hj).1 i hi⟩
  refine ⟨hlpx, ?_, hlpdx, ?_, hcnt⟩
  · rw [simdSelect_len]; exact hlpy
  · have hzs : (constSplat 0 count len lp.next).res.data.length = count := by
      simp [constSplat]
    rw [simdSelect_data_len, hlpdy, hb0data, simdSub_data_len, hzs, hlpdy]
    omega

set_option maxHeartbeats 4000000 in
/-- Phase 3's query bits and points: shapes and booleanness. -/
theorem phase3G_facts {ρ : ℕ → QM31} {zero one L nq powBits low high : ℕ}
    {friRoots : List (List ℕ)} {lastCoefs : List ℕ} {powNonce n : ℕ}
    (hzero : ρ zero = 0) (hL2 : 2 ≤ L) (hL30 : L ≤ 30)
    (hcov : (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.input.Covers)
    (h : AllHold ρ (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).ops) :
    (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.bits.length = 31 ∧
    (∀ b ∈ (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.bits,
      BitShape b nq (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.input.data.length) ∧
    (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.points.Shape nq
      (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.input.data.length ∧
    ∀ j, j < nq → ∀ i, i < 31 →
      SimdReg.lane ρ ((phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.bits.getD
        i dummySimd) j = 0 ∨
      SimdReg.lane ρ ((phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.bits.getD
        i dummySimd) j = 1 := by
  unfold phase3G at h hcov ⊢
  set DQ := drawTwoQm31sG low high 0 n with hDQdef
  rw [allHold_seq] at h
  rw [seq_res] at hcov ⊢
  obtain ⟨hDQ, h⟩ := h
  beta_reduce at h hcov ⊢
  set FL := friLoopG low high friRoots DQ.next with hFLdef
  rw [allHold_seq] at h
  rw [seq_res] at hcov ⊢
  obtain ⟨hFL, h⟩ := h
  beta_reduce at h hcov ⊢
  set ML := mixQm31sG FL.res.1.1 FL.res.1.2 lastCoefs FL.next with hMLdef
  rw [allHold_seq] at h
  rw [seq_res] at hcov ⊢
  obtain ⟨hML, h⟩ := h
  beta_reduce at h hcov ⊢
  set PW := powG zero one ML.res.1 ML.res.2 powNonce powBits ML.next with hPWdef
  rw [allHold_seq] at h
  rw [seq_res] at hcov ⊢
  obtain ⟨hPW, h⟩ := h
  beta_reduce at h hcov ⊢
  set QD := queryDrawsG PW.res.1 PW.res.2 ((nq + 7) / 8) 0 PW.next with hQDdef
  rw [allHold_seq] at h
  rw [seq_res] at hcov ⊢
  obtain ⟨hQD, h⟩ := h
  beta_reduce at h hcov ⊢
  set SQ := selectQueriesPoint zero ⟨QD.res.take ((nq + 3) / 4), nq⟩ L QD.next with hSQdef
  rw [allHold_seq] at h
  rw [seq_res] at hcov ⊢
  obtain ⟨hSQ, h⟩ := h
  beta_reduce at h hcov ⊢
  exact selectQueriesPoint_facts hL2 hL30 hzero hcov hSQ

theorem friLoopG_length : ∀ (low high : ℕ) (rs : List (List ℕ)) (n : ℕ),
    (friLoopG low high rs n).res.2.length = rs.length
  | _, _, [], _ => rfl
  | low, high, r :: rs, n => by
    show (friLoopG _ _ rs _).res.2.length + 1 = rs.length + 1
    rw [friLoopG_length]

theorem phase3G_alphas_length {zero one L nq powBits low high : ℕ}
    {friRoots : List (List ℕ)} {lastCoefs : List ℕ} {powNonce n : ℕ} :
    (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res.alphas.length
      = friRoots.length := by
  unfold phase3G
  rw [seq_res, seq_res, seq_res, seq_res, seq_res, seq_res]
  exact friLoopG_length _ _ _ _

end StwoVerifier.Gadgets
