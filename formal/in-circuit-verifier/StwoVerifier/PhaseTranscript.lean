/-
**Phase 1 of the in-circuit `verify`: the statement transcript**
(`verify.zig` from `Channel.init` to `draw_point`, with
`CircuitStatement`'s circuit hash and packed log sizes).

`phase1G` strings together the proven channel, Blake2s, size and LogUp
gadgets in the emitter's order; `phase1G_sound` lifts their soundness to
the spec transcript `circuitAccepts`/`NativeAccepts` replay: every
channel state, the interaction and composition draws, the OODS point,
the public LogUp sum, the size checks and the size bits.
-/
import StwoVerifier.TranscriptGadgets
import StwoVerifier.LogupGadgets
import StwoVerifier.StatementGadgets
import StwoVerifier.GuessGadgets

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### Glue lemmas -/

theorem chDigest_zero {ρ : ℕ → QM31} {zero : ℕ} (hz : ρ zero = 0) :
    ChDigest ρ zero zero Channel.init.digest := by
  unfold ChDigest
  rw [hz]
  rfl

theorem wordAt_eq_leWord (b : Channel.Bytes) (k : ℕ) :
    BitVec.ofNat 32 (Channel.wordAt b k) = Blake2s.leWord b k := by
  unfold Channel.wordAt Blake2s.leWord
  norm_num

theorem digestWords_wordsBytes {ws : List Blake2s.Word} (h8 : ws.length = 8) :
    (Channel.digestWords (wordsBytes ws)).map (BitVec.ofNat 32) = ws := by
  refine List.ext_getElem (by simp [Channel.digestWords, h8]) fun k h1 h2 => ?_
  have hk : k < 8 := by simpa [Channel.digestWords] using h1
  simp only [Channel.digestWords, List.map_map, List.getElem_map, List.getElem_range,
    Function.comp_apply]
  rw [wordAt_eq_leWord, show wordsBytes ws = wordsBytes ws ++ [] by simp,
    leWord_wordsBytes ws [] (by omega), List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h2]
  rfl

/-- Word registers carrying a hash are the root registers of its bytes. -/
theorem rootRegs_words {ρ : ℕ → QM31} {regs : List ℕ} {ws : List Blake2s.Word}
    (hr : RegsWords ρ regs ws) (h8 : ws.length = 8) : RootRegs ρ regs (wordsBytes ws) :=
  ⟨by rw [wordsBytes_length, h8], by rw [digestWords_wordsBytes h8]; exact hr⟩

theorem val_mod32 (v : F) : v.val % 4294967296 = v.val :=
  Nat.mod_eq_of_lt (lt_of_lt_of_le (ZMod.val_lt v) (by unfold P; norm_num))

theorem feltWords_bytes : ∀ xs : List QM31,
    ((feltWords xs).map fun w => Channel.u32Le w.toNat).flatten
      = (xs.map Channel.qm31Bytes).flatten
  | [] => rfl
  | x :: rest => by
    have ih := feltWords_bytes rest
    unfold feltWords at ih ⊢
    rw [List.flatMap_cons, List.map_append, List.flatten_append, ih, List.map_cons,
      List.flatten_cons]
    congr 1
    simp [QM31.coords, Channel.qm31Bytes, Channel.feltBytes, val_mod32]

/-- Mixing a felt list's coordinate words is mixing the felts. -/
theorem mixU32s_feltWords (s : Channel.St) (xs : List QM31) :
    Channel.mixU32s true s ((feltWords xs).map BitVec.toNat) = Channel.mixFelts true s xs := by
  unfold Channel.mixU32s Channel.mixFelts
  rw [List.map_map, show (Channel.u32Le ∘ BitVec.toNat) = fun w : Blake2s.Word =>
    Channel.u32Le w.toNat from rfl, feltWords_bytes]

/-! ### The phase-1 emitter -/

/-- Packed component log sizes: four lanes per constant wire. -/
def packLogs (logSizes : List ℕ) (k : ℕ) : QM31 :=
  QM31.fromM31s ((logSizes.getD (4 * k) 0 : ℕ) : F) ((logSizes.getD (4 * k + 1) 0 : ℕ) : F)
    ((logSizes.getD (4 * k + 2) 0 : ℕ) : F) ((logSizes.getD (4 * k + 3) 0 : ℕ) : F)

/-! ### Sequencing -/

/-- Run `a`, then `f` on its result from its next register. -/
def _root_.StwoVerifier.Gates.Out.seq {α β : Type} (a : Out α) (f : α → ℕ → Out β) : Out β :=
  ⟨a.ops ++ (f a.res a.next).ops, (f a.res a.next).res, (f a.res a.next).next⟩

theorem allHold_seq {ρ : ℕ → QM31} {α β : Type} (a : Out α) (f : α → ℕ → Out β) :
    AllHold ρ (a.seq f).ops ↔ AllHold ρ a.ops ∧ AllHold ρ (f a.res a.next).ops :=
  allHold_append

theorem seq_res {α β : Type} (a : Out α) (f : α → ℕ → Out β) :
    (a.seq f).res = (f a.res a.next).res := rfl

/-- Constants at consecutive fresh registers. -/
def constsG (vs : List QM31) (n : ℕ) : Out (List ℕ) :=
  ⟨(List.range vs.length).map (fun i => .const (n + i) (vs.getD i 0)),
   (List.range vs.length).map (n + ·), n + vs.length⟩

theorem constsG_sound {ρ : ℕ → QM31} {vs : List QM31} {n : ℕ}
    (h : AllHold ρ (constsG vs n).ops) :
    (constsG vs n).res.length = vs.length ∧
    ∀ i, i < vs.length → ρ ((constsG vs n).res.getD i 0) = vs.getD i 0 := by
  refine ⟨by simp [constsG], fun i hi => ?_⟩
  have := h _ (List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩)
  simp only [Holds] at this
  rw [show (constsG vs n).res.getD i 0 = n + i by
    simp [constsG, List.getD_eq_getElem?_getD, hi]]
  exact this

/-- Phase-1 result registers. -/
structure P1Res where
  low : ℕ
  high : ℕ
  z : ℕ
  alpha : ℕ
  coeff : ℕ
  oods : PointReg
  logBits : List SimdReg
  sizes : SimdReg
  sizeBits : List SimdReg
  pub : ℕ

/-- **Phase 1**: `verify` up to the OODS point, with the statement's
circuit hash and packed log sizes (`CircuitStatement.init`). `cwords`
are the static config words, `cfg1`/`cfg2` the packed FRI config. -/
noncomputable def phase1G (zero one uW : ℕ) (logSizes : List ℕ) (logTrace : ℕ)
    (cfg1 cfg2 : QM31) (cwords : List ℕ) (salt : ℕ) (ppRoot outs traceRoot : List ℕ)
    (interNonce : ℕ) (claimed interRoot compRoot : List ℕ) (n : ℕ) : Out P1Res :=
  (mixQm31sG zero zero [salt] n).seq fun m1 n =>
  (constsG [cfg1, cfg2] n).seq fun cs n =>
  (mixQm31sG m1.1 m1.2 cs n).seq fun m2 n =>
  (mixCommitmentG m2.1 m2.2 ppRoot n).seq fun m3 n =>
  (constsG ((List.range 3).map fun i => packW (BitVec.ofNat 32 (cwords.getD i 0))) n).seq
    fun cw n =>
  (blake2sU32sG (cw ++ ppRoot) 44 n).seq fun hsh n =>
  (mixCommitmentG m3.1 m3.2 hsh n).seq fun m4 n =>
  (constsG ((List.range 3).map (packLogs logSizes)) n).seq fun lw n =>
  (validateSizesG zero ⟨lw, 11⟩ logTrace n).seq fun vs n =>
  (extractBitsK zero vs.2 (logTrace + 1) n).seq fun sb n =>
  (unpackFeltsG outs n).seq fun uo n =>
  (mixU32sG m4.1 m4.2 uo n).seq fun m5 n =>
  (mixCommitmentG m5.1 m5.2 traceRoot n).seq fun m6 n =>
  (powG zero one m6.1 m6.2 interNonce 20 n).seq fun pw n =>
  (drawTwoQm31sG pw.1 pw.2 0 n).seq fun d1 n =>
  (publicLogupG zero d1.1 d1.2 outs uW n).seq fun pl n =>
  (logupSumG zero pl claimed n).seq fun _ n =>
  (mixQm31sG pw.1 pw.2 claimed n).seq fun m8 n =>
  (mixCommitmentG m8.1 m8.2 interRoot n).seq fun m9 n =>
  (drawTwoQm31sG m9.1 m9.2 0 n).seq fun d2 n =>
  (mixCommitmentG m9.1 m9.2 compRoot n).seq fun m10 n =>
  (drawPointG m10.1 m10.2 0 n).seq fun dp n =>
  ⟨[], ⟨m10.1, m10.2, d1.1, d1.2, d2.1, dp, vs.1, vs.2, sb, pl⟩, n⟩

/-- What phase 1 establishes about its result registers. -/
def P1Spec (ρ : ℕ → QM31) (cfg1 cfg2 : QM31) (cwords : List ℕ) (salt : ℕ) (logSizes : List ℕ)
    (logTrace : ℕ) (interNonce : ℕ) (claimed : List ℕ)
    (ppW outW traceW interW compW : List Blake2s.Word) (r : P1Res) : Prop :=
    let cwW : List Blake2s.Word := (List.range 3).map fun i => BitVec.ofNat 32 (cwords.getD i 0)
    let s3 := Channel.mixRoot true (Channel.mixFelts true
      (Channel.mixFelts true Channel.init [ρ salt]) [cfg1, cfg2]) (wordsBytes ppW)
    let s5 := Channel.mixFelts true (Channel.mixRoot true s3
      (Blake2s.blake2s (wordsBytes (cwW ++ ppW)))) (outW.map packW)
    let s6 := Channel.mixRoot true s5 (wordsBytes traceW)
    let nonce := nonceNat (ρ interNonce)
    let s7 : Channel.St := ⟨(Channel.mixU64 true s6 nonce).digest, 1⟩
    let s9 := Channel.mixRoot true (Channel.mixFelts true s7 (claimed.map ρ)) (wordsBytes interW)
    let s11 := Channel.mixRoot true ⟨s9.digest, 1⟩ (wordsBytes compW)
    Channel.verifyPowNonce true s6 20 nonce = true ∧
    Channel.drawSecureFelts true 2 (Channel.mixU64 true s6 nonce)
      = some ([ρ r.z, ρ r.alpha], s7) ∧
    CircuitVerify.publicLogupSum (outW.map BitVec.toNat) (ρ r.z) (ρ r.alpha) = .ok (ρ r.pub) ∧
    ρ r.pub + (claimed.map ρ).foldl (· + ·) QM31.zero = QM31.zero ∧
    Channel.drawSecureFelt true s9 = some (ρ r.coeff, ⟨s9.digest, 1⟩) ∧
    (∃ t, Channel.drawSecureFelt true s11 = some (t, ⟨s11.digest, 1⟩) ∧
      securePointFromSeed t = some (r.oods.val ρ)) ∧
    ChDigest ρ r.low r.high s11.digest ∧
    (∀ j, j < 11 → (((logSizes.getD j 0 : ℕ) : F)).val < 2 ^ 5 ∧
      (((logSizes.getD j 0 : ℕ) : F)).val ≤ logTrace) ∧
    r.sizes.len = 11 ∧ r.sizes.data.length = 3 ∧
    (∀ j, j < 11 → SimdReg.lane ρ r.sizes j = 2 ^ (((logSizes.getD j 0 : ℕ) : F)).val) ∧
    r.sizeBits.length = logTrace + 1 ∧ (∀ b ∈ r.sizeBits, BitShape b 11 3) ∧
    (∀ j, j < 11 → ∀ t, t < logTrace + 1 →
      SimdReg.lane ρ (r.sizeBits.getD t dummySimd) j
        = if t = (((logSizes.getD j 0 : ℕ) : F)).val then 1 else 0)

set_option maxHeartbeats 16000000 in
/-- **Phase 1 soundness**: the gates replay the spec statement transcript. -/
theorem phase1G_sound {ρ : ℕ → QM31} {zero one uW : ℕ} {logSizes : List ℕ} {logTrace : ℕ}
    {cfg1 cfg2 : QM31} {cwords : List ℕ} {salt : ℕ} {ppRoot outs traceRoot : List ℕ}
    {interNonce : ℕ} {claimed interRoot compRoot : List ℕ} {n : ℕ}
    (ppW outW traceW interW compW : List Blake2s.Word)
    (hzero : ρ zero = 0) (hone : ρ one = QM31.one) (hu : ρ uW = QM31.fromM31s 0 0 1 0)
    (hlt : logTrace + 1 ≤ 30) (hlsl : logSizes.length = 11)
    (hpp : RegsWords ρ ppRoot ppW) (hpp8 : ppW.length = 8)
    (hout : RegsWords ρ outs outW) (hout8 : outW.length = 8)
    (htr : RegsWords ρ traceRoot traceW) (htr8 : traceW.length = 8)
    (hir : RegsWords ρ interRoot interW) (hir8 : interW.length = 8)
    (hcr : RegsWords ρ compRoot compW) (hcr8 : compW.length = 8)
    (h : AllHold ρ (phase1G zero one uW logSizes logTrace cfg1 cfg2 cwords salt ppRoot outs
      traceRoot interNonce claimed interRoot compRoot n).ops) :
    P1Spec ρ cfg1 cfg2 cwords salt logSizes logTrace interNonce claimed ppW outW traceW interW
      compW (phase1G zero one uW logSizes logTrace cfg1 cfg2 cwords salt ppRoot outs
        traceRoot interNonce claimed interRoot compRoot n).res := by
  unfold phase1G at h ⊢
  set M1 := mixQm31sG zero zero [salt] n with hM1def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM1, h⟩ := h
  beta_reduce at h ⊢
  set C1 := constsG [cfg1, cfg2] M1.next with hC1def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hC1, h⟩ := h
  beta_reduce at h ⊢
  set M2 := mixQm31sG M1.res.1 M1.res.2 C1.res C1.next with hM2def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM2, h⟩ := h
  beta_reduce at h ⊢
  set M3 := mixCommitmentG M2.res.1 M2.res.2 ppRoot M2.next with hM3def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM3, h⟩ := h
  beta_reduce at h ⊢
  set CW := constsG ((List.range 3).map fun i => packW (BitVec.ofNat 32 (cwords.getD i 0))) M3.next with hCWdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hCW, h⟩ := h
  beta_reduce at h ⊢
  set HS := blake2sU32sG (CW.res ++ ppRoot) 44 CW.next with hHSdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hHS, h⟩ := h
  beta_reduce at h ⊢
  set M4 := mixCommitmentG M3.res.1 M3.res.2 HS.res HS.next with hM4def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM4, h⟩ := h
  beta_reduce at h ⊢
  set LW := constsG ((List.range 3).map (packLogs logSizes)) M4.next with hLWdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hLW, h⟩ := h
  beta_reduce at h ⊢
  set VS := validateSizesG zero ⟨LW.res, 11⟩ logTrace LW.next with hVSdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hVS, h⟩ := h
  beta_reduce at h ⊢
  set SB := extractBitsK zero VS.res.2 (logTrace + 1) VS.next with hSBdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hSB, h⟩ := h
  beta_reduce at h ⊢
  set UO := unpackFeltsG outs SB.next with hUOdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hUO, h⟩ := h
  beta_reduce at h ⊢
  set M5 := mixU32sG M4.res.1 M4.res.2 UO.res UO.next with hM5def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM5, h⟩ := h
  beta_reduce at h ⊢
  set M6 := mixCommitmentG M5.res.1 M5.res.2 traceRoot M5.next with hM6def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM6, h⟩ := h
  beta_reduce at h ⊢
  set PW := powG zero one M6.res.1 M6.res.2 interNonce 20 M6.next with hPWdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hPW, h⟩ := h
  beta_reduce at h ⊢
  set D1 := drawTwoQm31sG PW.res.1 PW.res.2 0 PW.next with hD1def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hD1, h⟩ := h
  beta_reduce at h ⊢
  set PL := publicLogupG zero D1.res.1 D1.res.2 outs uW D1.next with hPLdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hPL, h⟩ := h
  beta_reduce at h ⊢
  set LS := logupSumG zero PL.res claimed PL.next with hLSdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hLS, h⟩ := h
  beta_reduce at h ⊢
  set M8 := mixQm31sG PW.res.1 PW.res.2 claimed LS.next with hM8def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM8, h⟩ := h
  beta_reduce at h ⊢
  set M9 := mixCommitmentG M8.res.1 M8.res.2 interRoot M8.next with hM9def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM9, h⟩ := h
  beta_reduce at h ⊢
  set D2 := drawTwoQm31sG M9.res.1 M9.res.2 0 M9.next with hD2def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hD2, h⟩ := h
  beta_reduce at h ⊢
  set M10 := mixCommitmentG M9.res.1 M9.res.2 compRoot D2.next with hM10def
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hM10, h⟩ := h
  beta_reduce at h ⊢
  set DP := drawPointG M10.res.1 M10.res.2 0 M10.next with hDPdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hDP, h⟩ := h
  beta_reduce at h ⊢
  unfold P1Spec
  intro cwW s3 s5 s6 nonce s7 s9 s11
  -- Salt and FRI config.
  have e1 := mixQm31sG_sound (s := Channel.init) (xs := [ρ salt]) (chDigest_zero hzero) rfl
    rfl (fun i hi => by simp at hi; subst hi; rfl) hM1
  obtain ⟨cl1, cv1⟩ := constsG_sound hC1
  have e2 := mixQm31sG_sound (xs := [cfg1, cfg2]) e1 (chHash_true_length _) cl1 cv1 hM2
  -- Preprocessed root.
  obtain ⟨rr32, rrr⟩ := rootRegs_words hpp hpp8
  have e3 := mixCommitmentG_sound e2 (chHash_true_length _) rr32 rrr hM3
  -- Circuit hash.
  obtain ⟨cwl, cwv⟩ := constsG_sound hCW
  have hcw : RegsWords ρ CW.res cwW := ⟨by rw [cwl]; simp [cwW], fun j hj => by
    rw [cwl] at hj
    rw [cwv j hj]
    simp only [cwW, List.length_map, List.length_range] at hj ⊢
    rw [getD_map' _ (0 : QM31) (List.range 3) j (by simpa using hj),
      getD_map' _ (0 : Blake2s.Word) (List.range 3) j (by simpa using hj)]
    try rfl⟩
  have hcat := regsWords_append hcw hpp
  have h44 : 44 = 4 * (cwW ++ ppW).length := by simp [cwW, hpp8]
  have hHS' : AllHold ρ (blake2sU32sG (CW.res ++ ppRoot) (4 * (cwW ++ ppW).length)
      CW.next).ops := by rw [← h44]; exact hHS
  obtain ⟨hw, hhw, hw8, hwb⟩ := blakeWords_sound hcat hHS'
  have hhw' : RegsWords ρ HS.res hw := by rw [hHSdef, h44]; exact hhw
  obtain ⟨hr32, hrr⟩ := rootRegs_words hhw' hw8
  have e4 := mixCommitmentG_sound e3 (chHash_true_length _) hr32 hrr hM4
  rw [hwb] at e4
  -- Sizes.
  obtain ⟨lwl, lwv⟩ := constsG_sound hLW
  have hlwc : (⟨LW.res, 11⟩ : SimdReg).Covers := by
    unfold SimdReg.Covers; rw [lwl]; simp
  have hsz := validateSizesG_sound hzero hlwc (by omega) hVS
  -- Output digest.
  have hof : ∀ i, i < outs.length → ρ (outs.getD i 0) = (outW.map packW).getD i 0 := by
    intro i hi
    rw [hout.val i hi, List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_eq_getElem (by rw [← hout.len]; exact hi)]
    rfl
  have huo := unpackFeltsG_sound outs (outW.map packW) SB.next (by rw [hout.len]; simp) hof hUO
  have huo' : RegsWords ρ UO.res (((feltWords (outW.map packW)).map BitVec.toNat).map
      (BitVec.ofNat 32)) := by
    rw [List.map_map, show (BitVec.ofNat 32 ∘ BitVec.toNat) = fun w : Blake2s.Word => w from
      funext fun w => BitVec.ofNat_toNat 32 w, List.map_id']
    exact huo
  have e5 := mixU32sG_sound e4 (chHash_true_length _)
    (fun w hw' => by obtain ⟨x, -, rfl⟩ := List.mem_map.mp hw'; exact x.isLt) huo'
    (by rw [List.length_map, ← huo.len]) hM5
  rw [mixU32s_feltWords] at e5
  -- Trace root and interaction proof of work.
  obtain ⟨tr32, trr⟩ := rootRegs_words htr htr8
  have e6 := mixCommitmentG_sound e5 (chHash_true_length _) tr32 trr hM6
  obtain ⟨hpow, e7⟩ := powG_sound hzero hone e6 (chHash_true_length _) (by norm_num) hPW
  -- Interaction elements.
  have hdraw1 := drawTwoQm31sG_sound (s := Channel.mixU64 true s6 nonce) e7
    (chHash_true_length _) (by show 0 < P; unfold P; norm_num) hD1
  -- LogUp.
  have hpub := publicLogupG_sound outW hzero hout.len (fun i hi => hout.val i hi) hu hPL
  have hsum := logupSumG_sound hzero hLS
  -- Claimed sums, interaction root, composition coefficient.
  have e8 := mixQm31sG_sound (s := s7) (xs := claimed.map ρ) e7 (chHash_true_length _)
    (by simp) (fun i hi => by
      rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map,
        List.getElem?_eq_getElem hi]
      rfl) hM8
  obtain ⟨ir32, irr⟩ := rootRegs_words hir hir8
  have e9 := mixCommitmentG_sound e8 (chHash_true_length _) ir32 irr hM9
  have hdraw2 := drawQm31_sound (s := s9) e9 (chHash_true_length _) (by show 0 < P; unfold P; norm_num) hD2
  obtain ⟨cr32, crr⟩ := rootRegs_words hcr hcr8
  have e10 := mixCommitmentG_sound (s := ⟨s9.digest, 1⟩) e9 (chHash_true_length _) cr32 crr hM10
  have hpt := drawPointG_sound (s := s11) e10 (chHash_true_length _) (by show 0 < P; unfold P; norm_num) hDP
  have hlaneAll : ∀ j, j < 11 → SimdReg.lane ρ ⟨LW.res, 11⟩ j
      = ((logSizes.getD j 0 : ℕ) : F) := by
    intro j hj
    unfold SimdReg.lane
    have hj4 : j / 4 < 3 := by omega
    rw [lwv (j / 4) (by simpa using hj4)]
    rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hj4]
    simp only [Option.map_some, Option.getD_some]
    obtain ⟨q, r, hr4, rfl⟩ : ∃ q r, r < 4 ∧ j = 4 * q + r :=
      ⟨j / 4, j % 4, Nat.mod_lt _ (by norm_num), (Nat.div_add_mod j 4).symm⟩
    rw [show (4 * q + r) / 4 = q by omega, show (4 * q + r) % 4 = r by omega]
    unfold packLogs
    interval_cases r <;> rfl
  obtain ⟨-, -, hszl, hszd, -⟩ := hsz 0 (by show 0 < 11; norm_num)
  have hszcov : VS.res.2.Covers := by
    unfold SimdReg.Covers; rw [hszl, hszd]; rw [lwl]; simp
  obtain ⟨sbl, sbsh⟩ := extractBitsK_shapes zero VS.res.2 (logTrace + 1) VS.next (by omega)
  refine ⟨hpow, hdraw1, hpub, hsum, hdraw2, hpt, e10, fun j hj => ?_, hszl, ?_, ?_, sbl,
    fun b hb => ⟨by rw [(sbsh b hb).1, hszl], by rw [(sbsh b hb).2, hszd, lwl]; simp⟩, ?_⟩
  rotate_left
  · rw [hszd, lwl]; simp
  · intro j hj
    obtain ⟨-, -, -, -, hv⟩ := hsz j (by show j < 11; exact hj)
    rw [hv, hlaneAll j hj]
  · intro j hj t ht
    obtain ⟨hb5, hble, -, -, hv⟩ := hsz j (by show j < 11; exact hj)
    rw [hlaneAll j hj] at hb5 hble hv
    obtain ⟨hbits, hnat⟩ := extractBitsK_sound hzero hszcov (by omega) hlt hSB j
      (by rw [hszl]; exact hj)
    have hpow2 : ((2 : F) ^ (((logSizes.getD j 0 : ℕ) : F)).val).val
        = 2 ^ (((logSizes.getD j 0 : ℕ) : F)).val := by
      rw [show (2 : F) ^ (((logSizes.getD j 0 : ℕ) : F)).val
          = ((2 ^ (((logSizes.getD j 0 : ℕ) : F)).val : ℕ) : F) by push_cast; rfl,
        ZMod.val_cast_of_lt (lt_of_le_of_lt (Nat.pow_le_pow_right (by norm_num) hble)
          (pow_two_lt_P (by omega)))]
    rw [hv, hpow2] at hnat
    exact onehot_of_natOf _ (logTrace + 1) _ hbits hnat t ht
  have hlane : SimdReg.lane ρ ⟨LW.res, 11⟩ j = ((logSizes.getD j 0 : ℕ) : F) := by
    unfold SimdReg.lane
    have hj4 : j / 4 < 3 := by omega
    rw [lwv (j / 4) (by simpa using hj4)]
    rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hj4]
    simp only [Option.map_some, Option.getD_some]
    obtain ⟨q, r, hr4, rfl⟩ : ∃ q r, r < 4 ∧ j = 4 * q + r :=
      ⟨j / 4, j % 4, Nat.mod_lt _ (by norm_num), (Nat.div_add_mod j 4).symm⟩
    rw [show (4 * q + r) / 4 = q by omega, show (4 * q + r) % 4 = r by omega]
    unfold packLogs
    interval_cases r <;> rfl
  obtain ⟨h1, h2, -⟩ := hsz j (by show j < 11; exact hj)
  rw [hlane] at h1 h2
  exact ⟨h1, h2⟩

end StwoVerifier.Gadgets
