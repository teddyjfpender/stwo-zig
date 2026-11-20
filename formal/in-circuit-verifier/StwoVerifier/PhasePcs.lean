/-
**Phase 3 of the in-circuit `verify`: the PCS transcript**
(`verify.zig` from the OODS-quotient coefficient draw through
`select_queries`).

`phase3G`: `draw_qm31` (the DEEP coefficient), `fri_commit`'s root/alpha
loop and last-layer mix, the FRI proof of work, the query-selection
draws and `select_queries`. `phase3G_sound`: the spec's DEEP draw, the
FRI transcript `friTr` with its last-layer mix, `verifyPowNonce`, and per
query lane the spec's drawn word, its canonical 31 bits, and the domain
point at the bit-reversed masked position.
-/
import StwoVerifier.PhaseTranscript
import StwoVerifier.SelectQueriesBridge

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates Finset

/-- The spec's batched word draw, word by word. -/
theorem drawWordBatches_getD (s : Channel.St) :
    ∀ (k j : ℕ), j < 8 * k →
      (Channel.drawWordBatches true k s).1.getD j 0 = dw ⟨s.digest, s.nDraws + j / 8⟩ (j % 8)
  | 0, j, hj => absurd hj (by omega)
  | k + 1, j, hj => by
    show ((Channel.drawU32s true s).1 ++ (Channel.drawWordBatches true k
      (Channel.drawU32s true s).2).1).getD j 0 = _
    have hlen : (Channel.drawU32s true s).1.length = 8 := by
      simp [Channel.drawU32s, Channel.digestWords]
    by_cases h8 : j < 8
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_left (by rw [hlen]; exact h8),
        show j / 8 = 0 by omega, Nat.add_zero, show j % 8 = j by omega]
      simp only [Channel.drawU32s, Channel.digestWords, List.getElem?_map,
        List.getElem?_range h8, Option.map_some, Option.getD_some]
      rfl
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by rw [hlen]; omega), hlen,
        ← List.getD_eq_getElem?_getD,
        drawWordBatches_getD (Channel.drawU32s true s).2 k (j - 8) (by omega)]
      simp only [Channel.drawU32s]
      rw [show s.nDraws + 1 + (j - 8) / 8 = s.nDraws + j / 8 by omega,
        show (j - 8) % 8 = j % 8 by omega]

/-- Phase-3 result registers. -/
structure P3Res where
  oq : ℕ
  alphas : List ℕ
  input : SimdReg
  bits : List SimdReg
  points : PointSimd

/-- **Phase 3**. -/
noncomputable def phase3G (zero one : ℕ) (L nq powBits : ℕ) (low high : ℕ)
    (friRoots : List (List ℕ)) (lastCoefs : List ℕ) (powNonce : ℕ) (n : ℕ) : Out P3Res :=
  (drawTwoQm31sG low high 0 n).seq fun dq n =>
  (friLoopG low high friRoots n).seq fun fl n =>
  (mixQm31sG fl.1.1 fl.1.2 lastCoefs n).seq fun ml n =>
  (powG zero one ml.1 ml.2 powNonce powBits n).seq fun pw n =>
  (queryDrawsG pw.1 pw.2 ((nq + 7) / 8) 0 n).seq fun qd n =>
  (selectQueriesPoint zero ⟨qd.take ((nq + 3) / 4), nq⟩ L n).seq fun sq n =>
  ⟨[], ⟨dq.1, fl.2, ⟨qd.take ((nq + 3) / 4), nq⟩, sq.1, sq.2⟩, n⟩

/-- What phase 3 establishes. -/
def P3Spec (ρ : ℕ → QM31) (s : Channel.St) (rootsB : List Channel.Bytes) (L nq powBits : ℕ)
    (lastCoefs : List ℕ) (powNonce : ℕ) (r : P3Res) : Prop :=
  let tr := friTr ⟨s.digest, 1⟩ rootsB
  let sM := Channel.mixFelts true tr.2 (lastCoefs.map ρ)
  let nonce := nonceNat (ρ powNonce)
  let sP := Channel.mixU64 true sM nonce
  Channel.drawSecureFelt true s = some (ρ r.oq, ⟨s.digest, 1⟩) ∧
  r.alphas.map ρ = tr.1 ∧
  Channel.verifyPowNonce true sM powBits nonce = true ∧
  r.input.len = nq ∧ r.input.Covers ∧
  (∀ j, j < nq → (SimdReg.lane ρ r.input j).val
    = (Channel.drawWordBatches true ((nq + 7) / 8) sP).1.getD j 0) ∧
  (∀ j, j < nq →
    BitDecomp.natOf (fun i => SimdReg.lane ρ (r.bits.getD i dummySimd) j) 31
      = (SimdReg.lane ρ r.input j).val) ∧
  (∀ j, j < nq → PointSimd.lane ρ r.points j
    = (canonicDomain L).at' (bitReverseIndex ((SimdReg.lane ρ r.input j).val % 2 ^ L) L))

set_option maxHeartbeats 16000000 in
theorem phase3G_sound {ρ : ℕ → QM31} {zero one L nq powBits low high : ℕ}
    {friRoots : List (List ℕ)} {lastCoefs : List ℕ} {powNonce n : ℕ}
    (s : Channel.St) (rootsB : List Channel.Bytes)
    (hzero : ρ zero = 0) (hone : ρ one = QM31.one)
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32) (hnd : s.nDraws = 0)
    (hrl : friRoots.length = rootsB.length)
    (hroots : ∀ i, i < rootsB.length → RootRegs ρ (friRoots.getD i []) (rootsB.getD i []))
    (hpb : powBits ≤ 30) (hL2 : 2 ≤ L) (hL30 : L ≤ 30) (hnqP : (nq + 7) / 8 < P)
    (h : AllHold ρ (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).ops) :
    P3Spec ρ s rootsB L nq powBits lastCoefs powNonce
      (phase3G zero one L nq powBits low high friRoots lastCoefs powNonce n).res := by
  unfold phase3G at h ⊢
  set DQ := drawTwoQm31sG low high 0 n with hDQdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hDQ, h⟩ := h
  beta_reduce at h ⊢
  set FL := friLoopG low high friRoots DQ.next with hFLdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hFL, h⟩ := h
  beta_reduce at h ⊢
  set ML := mixQm31sG FL.res.1.1 FL.res.1.2 lastCoefs FL.next with hMLdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hML, h⟩ := h
  beta_reduce at h ⊢
  set PW := powG zero one ML.res.1 ML.res.2 powNonce powBits ML.next with hPWdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hPW, h⟩ := h
  beta_reduce at h ⊢
  set QD := queryDrawsG PW.res.1 PW.res.2 ((nq + 7) / 8) 0 PW.next with hQDdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hQD, h⟩ := h
  beta_reduce at h ⊢
  set SQ := selectQueriesPoint zero ⟨QD.res.take ((nq + 3) / 4), nq⟩ L QD.next with hSQdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hSQ, h⟩ := h
  beta_reduce at h ⊢
  unfold P3Spec
  intro tr sM nonce sP
  show Channel.drawSecureFelt true s = some (ρ DQ.res.1, ⟨s.digest, 1⟩) ∧ _
  have hdq : AllHold ρ (drawTwoQm31sG low high s.nDraws n).ops := by rw [hnd]; exact hDQ
  have hdraw := drawQm31_sound (s := s) hd hdlen (by rw [hnd]; unfold P; norm_num) hdq
  rw [hnd] at hdraw
  obtain ⟨efl, efll, efla⟩ := friLoopG_sound rootsB friRoots low high DQ.next ⟨s.digest, 1⟩ hrl
    hroots hd hdlen hFL
  have eml := mixQm31sG_sound (s := tr.2) (xs := lastCoefs.map ρ) efl efll (by simp)
    (fun i hi => by
      rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map,
        List.getElem?_eq_getElem hi]; rfl) hML
  obtain ⟨hpow, epw⟩ := powG_sound hzero hone eml (chHash_true_length _) hpb hPW
  obtain ⟨hql, hqv⟩ := queryDrawsG_sound (s := sP) epw (chHash_true_length _) ((nq + 7) / 8) 0
    PW.next (by omega) hQD
  have hcov : (⟨QD.res.take ((nq + 3) / 4), nq⟩ : SimdReg).Covers := by
    show nq ≤ 4 * (QD.res.take ((nq + 3) / 4)).length
    rw [List.length_take, hql]; omega
  have hlane : ∀ j, j < nq → SimdReg.lane ρ ⟨QD.res.take ((nq + 3) / 4), nq⟩ j
      = ((dw ⟨sP.digest, j / 8⟩ (j % 8) : ℕ) : F) := by
    intro j hj
    unfold SimdReg.lane
    simp only
    rw [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos (by omega),
      ← List.getD_eq_getElem?_getD, hqv j (by omega), Nat.zero_add]
  refine ⟨hdraw, efla, hpow, rfl, hcov, fun j hj => ?_, fun j hj => ?_, fun j hj => ?_⟩
  · rw [hlane j hj, ZMod.val_cast_of_lt (dw_lt _ (Nat.mod_lt _ (by norm_num))),
      drawWordBatches_getD sP _ j (by omega), show sP.nDraws = 0 from rfl, Nat.zero_add]
  · exact (selectQueriesPoint_sound hL2 hL30 hzero hcov hSQ j hj).1
  · exact Bridge.selectQueries_domainPoint hL2 hL30 hzero hcov hSQ j hj

end StwoVerifier.Gadgets
