/-
**Phase 5 of the in-circuit `verify`: the DEEP answers**
(`oods.zig` `collectOodsResponses` + `computeFriInput`).

`phase5G`: the period generators from the one-hot size bits, the
periodicity points `oods + 2^log·g`, the previous-row point
`oods + conj(g)`, the query points unpacked to scalars, and the composed
`compute_fri_input` over the emitter's response layout.
-/
import StwoVerifier.ResponseLayout
import StwoVerifier.PhaseTranscript
import StwoVerifier.CircuitAir
import StwoVerifier.FriWalk

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates Quotients

/-- The interaction OODS samples per column, from per-component
`(plain at_oods, cumulative (at_prev, at_oods))` registers. -/
def interAtOf (comps : List (List ℕ × List (ℕ × ℕ))) : List (ℕ × Option ℕ) :=
  comps.flatMap fun c => c.1.map (fun o => (o, none)) ++ c.2.map fun pv => (pv.2, some pv.1)

/-- The `interL` entries: per component its periodicity point, columns
and committed log size. -/
def interEntries (pers : List PointReg) (comps : List (List ℕ × List (ℕ × ℕ)))
    (logs : List ℕ) : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ) :=
  ((pers.zip comps).zip logs).map fun x => (x.1.1, x.1.2.1, x.1.2.2, x.2)

/-- **Phase 5**: the response points, the query scalars and the composed
`compute_fri_input`. Returns the per-query FRI input registers. -/
noncomputable def phase5G (zero one : ℕ) (g : PointF) (sizeBits : List SimdReg)
    (oods : PointReg) (points : PointSimd) (nq : ℕ) (oq : ℕ)
    (ppAt traceAt : List ℕ) (comps : List (List ℕ × List (ℕ × ℕ))) (compAt : List ℕ)
    (Ls : List ℕ) (valReg : ℕ → ℕ → ℕ) (n : ℕ) : Out (List ℕ) :=
  (periodGeneratorsG one g sizeBits n).seq fun gens n =>
  (addPointsList oods gens n).seq fun pers n =>
  (prevPointG g oods n).seq fun prev n =>
  (unpackFrom points.x nq 0 n).seq fun qx n =>
  (unpackFrom points.y nq 0 n).seq fun qy n =>
  (constsG [QM31.fromM31s 0 0 1 1] n).seq fun im n =>
  let rl := respLayout oods prev ppAt traceAt (interEntries pers comps Ls) compAt
  deepCompositeG (im.getD 0 0) zero oq (rl.map Prod.fst) (rl.map Prod.snd) (qx.zip qy) valReg n

/-! ### Helper facts -/

theorem onCircleQ_add {p q : PointQ} (hp : OnCircleQ p) (hq : OnCircleQ q) :
    OnCircleQ (p.add q) := by
  unfold OnCircleQ at *
  show (p.x * q.x - p.y * q.y) * (p.x * q.x - p.y * q.y)
    + (p.x * q.y + p.y * q.x) * (p.x * q.y + p.y * q.x) = 1
  have : (p.x * q.x - p.y * q.y) * (p.x * q.x - p.y * q.y)
      + (p.x * q.y + p.y * q.x) * (p.x * q.y + p.y * q.x)
      = (p.x * p.x + p.y * p.y) * (q.x * q.x + q.y * q.y) := by ring
  rw [this, hp, hq, one_mul]

/-- One-hot lanes as a list. -/
theorem onehot_list {bits : List SimdReg} {ρ : ℕ → QM31} {j K l : ℕ} (hlen : bits.length = K)
    (hl : l < K)
    (h : ∀ t, t < K → SimdReg.lane ρ (bits.getD t dummySimd) j = if t = l then 1 else 0) :
    bits.map (fun bb => SimdReg.lane ρ bb j)
      = List.replicate l 0 ++ 1 :: List.replicate (K - l - 1) 0 := by
  refine List.ext_getElem (by simp [hlen]; omega) fun t h1 h2 => ?_
  have ht : t < K := by simpa [hlen] using h1
  rw [List.getElem_map, ← List.getD_eq_getElem bits dummySimd (by omega), h t ht]
  by_cases htl : t < l
  · rw [if_neg (by omega), List.getElem_append_left (by simp; omega)]
    simp
  · rw [List.getElem_append_right (by simp; omega)]
    by_cases hte : t = l
    · subst hte; simp
    · rw [if_neg hte]
      obtain ⟨k, hk⟩ : ∃ k, t - l = k + 1 := ⟨t - l - 1, by omega⟩
      simp only [List.length_replicate, hk, List.getElem_cons_succ, List.getElem_replicate]

theorem singlesL_mem {pt : PointReg} :
    ∀ {vs : List ℕ} {fc : ℕ} {x : RespReg × ℕ}, x ∈ singlesL pt vs fc → x.1.px = pt.x ∧ x.1.py = pt.y
  | [], _, _, h => absurd h (by simp [singlesL])
  | v :: rest, fc, x, h => by
    rcases List.mem_cons.mp h with rfl | h
    · exact ⟨rfl, rfl⟩
    · exact singlesL_mem h

theorem doublesL_mem {oods prev period : PointReg} :
    ∀ {dv : List (ℕ × ℕ)} {fc : ℕ} {x : RespReg × ℕ}, x ∈ doublesL oods prev period dv fc →
      (x.1.px = oods.x ∧ x.1.py = oods.y) ∨ (x.1.px = prev.x ∧ x.1.py = prev.y) ∨
      (x.1.px = period.x ∧ x.1.py = period.y)
  | [], _, _, h => absurd h (by simp [doublesL])
  | (vp, vo) :: rest, fc, x, h => by
    simp only [doublesL, List.mem_cons] at h
    rcases h with rfl | rfl | rfl | h
    · exact Or.inr (Or.inr ⟨rfl, rfl⟩)
    · exact Or.inr (Or.inl ⟨rfl, rfl⟩)
    · exact Or.inl ⟨rfl, rfl⟩
    · exact doublesL_mem h

theorem interL_mem {oods prev : PointReg} :
    ∀ {ents : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ)} {fc : ℕ} {x : RespReg × ℕ},
      x ∈ interL oods prev ents fc →
      (x.1.px = oods.x ∧ x.1.py = oods.y) ∨ (x.1.px = prev.x ∧ x.1.py = prev.y) ∨
      ∃ e ∈ ents, x.1.px = e.1.x ∧ x.1.py = e.1.y
  | [], _, _, h => absurd h (by simp [interL])
  | (per, sv, dv, L) :: rest, fc, x, h => by
    simp only [interL, List.mem_append] at h
    rcases h with (h | h) | h
    · exact Or.inl (singlesL_mem h)
    · rcases doublesL_mem h with h | h | h
      · exact Or.inl h
      · exact Or.inr (Or.inl h)
      · exact Or.inr (Or.inr ⟨_, List.mem_cons_self, h⟩)
    · rcases interL_mem h with h | h | ⟨e, he, h⟩
      · exact Or.inl h
      · exact Or.inr (Or.inl h)
      · exact Or.inr (Or.inr ⟨e, List.mem_cons_of_mem _ he, h⟩)

theorem respLayout_mem {oods prev : PointReg} {ppAt traceAt compAt : List ℕ}
    {ents : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ)} {x : RespReg × ℕ}
    (h : x ∈ respLayout oods prev ppAt traceAt ents compAt) :
    (x.1.px = oods.x ∧ x.1.py = oods.y) ∨ (x.1.px = prev.x ∧ x.1.py = prev.y) ∨
      ∃ e ∈ ents, x.1.px = e.1.x ∧ x.1.py = e.1.y := by
  simp only [respLayout, List.mem_append] at h
  rcases h with ((h | h) | h) | h
  · exact Or.inl (singlesL_mem h)
  · exact Or.inl (singlesL_mem h)
  · exact interL_mem h
  · exact Or.inl (singlesL_mem h)

theorem interEntries_map (ρ : ℕ → QM31) :
    ∀ (pers : List PointReg) (comps : List (List ℕ × List (ℕ × ℕ))) (Ls : List ℕ),
      comps.length ≤ pers.length →
      (interEntries pers comps Ls).map (fun c => (c.2.1.map ρ, c.2.2.1.map fun d => (ρ d.1, ρ d.2),
        c.2.2.2))
        = (comps.zip Ls).map fun x => (x.1.1.map ρ, x.1.2.map fun d => (ρ d.1, ρ d.2), x.2)
  | _, [], _, _ => by simp [interEntries]
  | [], _ :: _, _, h => by simp at h
  | _ :: _, _ :: _, [], _ => by simp [interEntries]
  | p :: ps, c :: cs, L :: Ls, h => by
    have := interEntries_map ρ ps cs Ls (by simp at h; omega)
    simp only [interEntries, List.zip_cons_cons, List.map_cons] at this ⊢
    rw [this]

set_option maxHeartbeats 16000000 in
/-- **Phase 5**: the composed DEEP gadget computes the spec's `friAnswers`
at the raw query positions, for sample points/values/log sizes laid out
as the circuit statement's four trees. -/
theorem phase5G_sound {ρ : ℕ → QM31} {zero one : ℕ} {sizeBits : List SimdReg}
    {oods : PointReg} {points : PointSimd} {nq oq : ℕ} {ppAt traceAt compAt : List ℕ}
    {comps : List (List ℕ × List (ℕ × ℕ))} {Ls : List ℕ} {valReg : ℕ → ℕ → ℕ} {n : ℕ}
    (logTrace : ℕ) (logs : ℕ → ℕ) (P : PointQ)
    (cls : List (List ℕ)) (sp : List (List (List PointQ))) (sv : List (List (List QM31)))
    (ps : List ℕ) (queried : List (List (List F))) (batches : List SampleBatch)
    (ppLogs traceLogs compLogs : List ℕ)
    (hzero : ρ zero = 0) (hone : ρ one = 1)
    (hlT : 1 ≤ logTrace) (hlT29 : logTrace ≤ 29)
    (hsbl : sizeBits.length = logTrace + 1) (hsbs : ∀ b ∈ sizeBits, BitShape b 11 3)
    (hsb : ∀ j, j < 11 → ∀ t, t < logTrace + 1 →
      SimdReg.lane ρ (sizeBits.getD t dummySimd) j = if t = logs j then 1 else 0)
    (hlogs : ∀ j, j < 11 → logs j ≤ logTrace)
    (hP : oods.val ρ = P) (hPc : OnCircleQ P)
    (hcl : comps.length = 11) (hLs : Ls = (List.range 11).map (fun j => logs j + 1))
    (hps : ps.length = nq) (hposs : ∀ pos ∈ ps, pos < (canonicDomain (logTrace + 1)).size)
    (hpts : ∀ i, i < nq → PointSimd.lane ρ points i
      = (canonicDomain (logTrace + 1)).at' (bitReverseIndex (ps.getD i 0) (logTrace + 1)))
    (hbuild : buildSampleBatches sp sv cls (logTrace + 1) (ρ oq) = .ok batches)
    (htrees : sp.zip (sv.zip cls) =
      [(List.replicate (ppAt.map ρ).length [P], (ppAt.map ρ).map fun v => [v], ppLogs),
       (List.replicate (traceAt.map ρ).length [P], (traceAt.map ρ).map fun v => [v], traceLogs),
       (((comps.zip Ls).map fun x => (x.1.1.map ρ, x.1.2.map fun d => (ρ d.1, ρ d.2), x.2)).flatMap
          fun c => List.replicate c.1.length [P]
            ++ List.replicate c.2.1.length [P.add (PointF.intoQ (canonicStep logTrace).conjugate), P],
        ((comps.zip Ls).map fun x => (x.1.1.map ρ, x.1.2.map fun d => (ρ d.1, ρ d.2), x.2)).flatMap
          fun c => (c.1.map fun v => [v]) ++ c.2.1.map fun p => [p.1, p.2],
        ((comps.zip Ls).map fun x => (x.1.1.map ρ, x.1.2.map fun d => (ρ d.1, ρ d.2), x.2)).flatMap
          fun c => List.replicate c.1.length c.2.2 ++ List.replicate c.2.1.length c.2.2),
       (List.replicate (compAt.map ρ).length [P], (compAt.map ρ).map fun v => [v], compLogs)])
    (hppl : (ppAt.map ρ).length ≤ ppLogs.length) (htrl : (traceAt.map ρ).length ≤ traceLogs.length)
    (hcpl : (compAt.map ρ).length ≤ compLogs.length)
    (hcols : ∀ col ∈ queried.flatten, col.length = ps.length)
    (hrl : ∀ (pers : List PointReg) (prev : PointReg),
      let rl := respLayout oods prev ppAt traceAt (interEntries pers comps Ls) compAt
      (∀ j, j < rl.length → (rl.map Prod.snd).getD j 0 < queried.flatten.length) ∧
      (∀ j, j < rl.length → ∀ i, i < ps.length →
        ρ (valReg ((rl.map Prod.snd).getD j 0) i)
          = QM31.fromBase ((queried.flatten.getD ((rl.map Prod.snd).getD j 0) []).getD i 0)))
    (h : AllHold ρ (phase5G zero one (canonicStep logTrace) sizeBits oods points nq oq ppAt
      traceAt comps compAt Ls valReg n).ops) :
    Quotients.friAnswers cls sp sv (ρ oq) ps queried (logTrace + 1)
      = .ok ((phase5G zero one (canonicStep logTrace) sizeBits oods points nq oq ppAt
        traceAt comps compAt Ls valReg n).res.map ρ) ∧
    (∀ b ∈ batches, Deep.imQ b.point.y ≠ 0) ∧
    (∀ b ∈ batches, ∀ e ∈ b.entries, e.columnIndex < queried.flatten.length) ∧
    (∀ b ∈ batches, ∀ pos : ℕ, Quotients.denominator b.point
      ((canonicDomain (logTrace + 1)).at' (bitReverseIndex pos (logTrace + 1))) ≠ 0) := by
  obtain ⟨b0, rest, rfl⟩ : ∃ b0 rest, sizeBits = b0 :: rest := by
    cases sizeBits with
    | nil => simp at hsbl
    | cons b0 rest => exact ⟨b0, rest, rfl⟩
  unfold phase5G at h ⊢
  set GP := periodGeneratorsG one (canonicStep logTrace) (b0 :: rest) n with hGPdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hGP, h⟩ := h
  beta_reduce at h ⊢
  set AP := addPointsList oods GP.res GP.next with hAPdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hAP, h⟩ := h
  beta_reduce at h ⊢
  set PP := prevPointG (canonicStep logTrace) oods AP.next with hPPdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hPP, h⟩ := h
  beta_reduce at h ⊢
  set QX := unpackFrom points.x nq 0 PP.next with hQXdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hQX, h⟩ := h
  beta_reduce at h ⊢
  set QY := unpackFrom points.y nq 0 QX.next with hQYdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hQY, h⟩ := h
  beta_reduce at h ⊢
  set IM := constsG [QM31.fromM31s 0 0 1 1] QY.next with hIMdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hIM, h⟩ := h
  beta_reduce at h ⊢
  dsimp only at h ⊢
  -- The response points.
  have hg : Bridge.OnCircle (canonicStep logTrace) := Bridge.onCircle_toPoint _
  obtain ⟨gpl, -⟩ := periodGeneratorsG_sound hone (by norm_num) hg (hsbs b0 List.mem_cons_self)
    (fun b hb => hsbs b (List.mem_cons_of_mem _ hb)) hGP
  have hgen : ∀ i, i < 11 → (GP.res.getD i ⟨0, 0⟩).val ρ
      = PointF.intoQ ((canonicStep logTrace).repeatedDouble (logs i)) := by
    intro i hi
    exact periodGeneratorsG_getD_pow hone (by norm_num) hg (hsbs b0 List.mem_cons_self)
      (fun b hb => hsbs b (List.mem_cons_of_mem _ hb)) hGP hi
      (onehot_list hsbl (by have := hlogs i hi; omega) (hsb i hi))
  obtain ⟨apl, apv⟩ := addPointsList_sound GP.res GP.next hAP
  have hper : ∀ i, i < 11 → (AP.res.getD i ⟨0, 0⟩).val ρ
      = P.add (PointF.intoQ ((canonicStep (logTrace + 1)).repeatedDouble (logs i + 1))) := by
    intro i hi
    rw [apv i (by rw [gpl]; exact hi), hgen i hi, hP,
      canonicStep_double_shift hlT (by omega)]
  have hprev := prevPointG_sound hPP
  rw [hP] at hprev
  obtain ⟨qxl, qxv⟩ := unpackFrom_sound nq 0 PP.next hQX
  obtain ⟨qyl, qyv⟩ := unpackFrom_sound nq 0 QX.next hQY
  obtain ⟨iml, imv⟩ := constsG_sound hIM
  have him : ρ (IM.res.getD 0 0) = QM31.fromM31s 0 0 1 1 := imv 0 (by simp)
  obtain ⟨hfc, hval⟩ := hrl AP.res PP.res
  have hcg : Bridge.OnCircle (canonicStep (logTrace + 1)) := Bridge.onCircle_toPoint _
  have hperE : ∀ c ∈ interEntries AP.res comps Ls, c.1.val ρ
      = P.add (PointF.intoQ ((canonicStep (logTrace + 1)).repeatedDouble c.2.2.2)) := by
    intro c hc
    unfold interEntries at hc
    obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hc
    obtain ⟨i, hi, hxe⟩ := List.getElem_of_mem hx
    have hi' : i < 11 := by
      have := hi; simp [List.length_zip, hcl, hLs] at this; omega
    rw [← hxe]
    simp only [List.getElem_zip]
    rw [← List.getD_eq_getElem AP.res ⟨0, 0⟩ (by rw [apl, gpl]; exact hi'), hper i hi']
    subst hLs; simp
  refine deepComposite_spec cls sp sv (logTrace + 1) ps queried batches him hzero rfl hbuild
    ?_ ?_ hcols (fun j hj => hfc j (by simpa using hj)) hposs
    (by rw [List.length_zip, qxl, qyl, hps, min_self]) (fun i hi => ?_)
    (fun j hj i hi => hval j (by simpa using hj) i hi) h
  · rw [← rpairs_eq_respPairs, layout_pairs ρ (ρ oq) (canonicStep (logTrace + 1)) oods PP.res P
      (P.add (PointF.intoQ (canonicStep logTrace).conjugate)) hP hprev ppAt traceAt compAt
      (interEntries AP.res comps Ls) hperE,
      interEntries_map ρ AP.res comps Ls (by rw [apl, gpl, hcl]), htrees,
      Quotients.treesPairs_circuit _ _ _ _ _ _ _ _ _ _ _ hppl htrl hcpl]
    rfl
  · intro r hr
    obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hr
    rcases respLayout_mem hx with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨e, he, h1, h2⟩
    · rw [h1, h2, show (⟨ρ oods.x, ρ oods.y⟩ : PointQ) = oods.val ρ from rfl, hP]; exact hPc
    · rw [h1, h2, show (⟨ρ PP.res.x, ρ PP.res.y⟩ : PointQ) = PP.res.val ρ from rfl, hprev]
      exact onCircleQ_add hPc (intoQ_onCircle (onCircle_conj hg))
    · rw [h1, h2, show (⟨ρ e.1.x, ρ e.1.y⟩ : PointQ) = e.1.val ρ from rfl, hperE e he]
      exact onCircleQ_add hPc (intoQ_onCircle (onCircle_repeatedDouble hcg _))
  · have hil : i < nq := by rw [List.length_zip, qxl, qyl, min_self] at hi; exact hi
    rw [zip_getD QX.res QY.res i (by rw [qxl]; exact hil) (by rw [qyl]; exact hil)]
    have hp := hpts i hil
    rw [show (QX.res.getD i default) = QX.res.getD i 0 from rfl,
      show (QY.res.getD i default) = QY.res.getD i 0 from rfl,
      qxv i hil, qyv i hil, Nat.zero_add]
    exact ⟨by rw [show SimdReg.lane ρ points.x i = (PointSimd.lane ρ points i).x from rfl, hp],
      by rw [show SimdReg.lane ρ points.y i = (PointSimd.lane ρ points i).y from rfl, hp]⟩

end StwoVerifier.Gadgets
